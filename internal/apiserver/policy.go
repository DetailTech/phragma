package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/authz"
	"github.com/detailtech/oss-ngfw/internal/engines"
	"github.com/detailtech/oss-ngfw/internal/policy"
	"github.com/detailtech/oss-ngfw/internal/policydiff"
	"github.com/detailtech/oss-ngfw/internal/store"
)

// Pipeline renders a policy into per-engine artifacts.
type Pipeline func(*openngfwv1.Policy) (map[string][]byte, error)

// RuntimeReadinessCheck returns operator-visible runtime readiness blockers
// that must be acknowledged before a live policy apply proceeds. The target
// policy is the candidate or rollback policy about to be applied; running is
// the current committed policy, used for checks that only make sense after a
// feature is already live (for example flowtable runtime evidence).
type RuntimeReadinessCheck func(context.Context, *openngfwv1.Policy, *openngfwv1.Policy) ([]string, error)

type threatReplayAlertSource interface {
	ListAlerts(context.Context, *openngfwv1.ListAlertsRequest) (*openngfwv1.ListAlertsResponse, error)
}

type threatReplayStatusSource interface {
	GetStatus(context.Context, *openngfwv1.GetStatusRequest) (*openngfwv1.GetStatusResponse, error)
}

// PolicyServer implements openngfw.v1.PolicyService over the store and
// engine supervisor. All mutations are serialized; the commit path is
// candidate → validate → render → engine-validate → durable intent → apply
// → activate.
type PolicyServer struct {
	openngfwv1.UnimplementedPolicyServiceServer
	openngfwv1.UnimplementedThreatTuningServiceServer

	store  *store.Store
	sup    *engines.Supervisor
	render Pipeline

	// RuntimeReadiness, when set, is evaluated during commit/rollback so direct
	// API clients cannot bypass the same runtime warning acknowledgement shown
	// by CLI and WebUI clients.
	RuntimeReadiness RuntimeReadinessCheck

	// ThreatReplayAlerts and ThreatReplayStatus are optional read-only sources
	// used by ThreatTuningService replay checks. They are injected from controld
	// after the alert and system services are constructed.
	ThreatReplayAlerts threatReplayAlertSource
	ThreatReplayStatus threatReplayStatusSource

	// OnCommit, when set, runs after every successful commit/rollback
	// (e.g. to retrigger the intel updater, since a table replace
	// clears dynamic sets).
	OnCommit func()

	mu sync.Mutex
}

// NewPolicyServer wires the policy service.
func NewPolicyServer(st *store.Store, sup *engines.Supervisor, render Pipeline) *PolicyServer {
	return &PolicyServer{store: st, sup: sup, render: render}
}

func auditIdentity(ctx context.Context) store.ActorIdentity {
	if id, ok := authz.IdentityFromContext(ctx); ok {
		authSource := id.AuthSource
		if authSource == "" {
			authSource = "unknown"
		}
		return store.ActorIdentity{Name: id.Name, Role: id.Role.String(), AuthSource: authSource}
	}
	return store.ActorIdentity{Name: "local", Role: authz.RoleAdmin.String(), AuthSource: authz.AuthSourceDisabledLocal}
}

// GetPolicy returns the running, candidate, or a historical policy.
func (s *PolicyServer) GetPolicy(_ context.Context, req *openngfwv1.GetPolicyRequest) (*openngfwv1.GetPolicyResponse, error) {
	switch req.GetSource() {
	case openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE:
		p, ok, err := s.store.GetCandidate()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "read candidate: %v", err)
		}
		if !ok {
			return nil, status.Error(codes.NotFound, "no candidate policy is set")
		}
		return &openngfwv1.GetPolicyResponse{Policy: p}, nil
	case openngfwv1.PolicySource_POLICY_SOURCE_VERSION:
		p, err := s.store.GetVersion(req.GetVersion())
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "%v", err)
		}
		return &openngfwv1.GetPolicyResponse{Policy: p, Version: req.GetVersion()}, nil
	default: // running
		p, ver, err := s.store.GetRunning()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "read running policy: %v", err)
		}
		return &openngfwv1.GetPolicyResponse{Policy: p, Version: ver}, nil
	}
}

// GetCandidateStatus returns read-only candidate dirty-state and impact
// metadata for GUI, CLI, and automation review surfaces.
func (s *PolicyServer) GetCandidateStatus(_ context.Context, _ *openngfwv1.GetCandidateStatusRequest) (*openngfwv1.GetCandidateStatusResponse, error) {
	running, runningVersion, err := s.store.GetRunning()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read running policy: %v", err)
	}
	candidate, hasCandidate, err := s.store.GetCandidate()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read candidate: %v", err)
	}
	revision, err := s.store.CandidateRevision()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read candidate revision: %v", err)
	}
	if !hasCandidate {
		return &openngfwv1.GetCandidateStatusResponse{
			HasCandidate:      false,
			Dirty:             false,
			RunningVersion:    runningVersion,
			Impact:            policy.Impact(running, running),
			CandidateRevision: revision,
		}, nil
	}

	dirty := !proto.Equal(running, candidate)
	changes := candidateChangeSummaries(running, candidate)
	var changeCount uint32
	for _, change := range changes {
		changeCount += change.GetAdded() + change.GetModified() + change.GetRemoved()
	}
	return &openngfwv1.GetCandidateStatusResponse{
		HasCandidate:      true,
		Dirty:             dirty,
		RunningVersion:    runningVersion,
		ChangeCount:       changeCount,
		Changes:           changes,
		Impact:            policy.Impact(running, candidate),
		CandidateRevision: revision,
	}, nil
}

// ListNatRules returns source and destination NAT rules from the selected
// policy snapshot without mutating candidate state.
func (s *PolicyServer) ListNatRules(_ context.Context, req *openngfwv1.ListNatRulesRequest) (*openngfwv1.ListNatRulesResponse, error) {
	p, version, label, err := s.diffSnapshot(req.GetSource(), req.GetVersion(), "policy")
	if err != nil {
		return nil, err
	}
	return &openngfwv1.ListNatRulesResponse{
		SourceNat:      cloneSourceNatRules(p.GetNat().GetSource()),
		DestinationNat: cloneDestinationNatRules(p.GetNat().GetDestination()),
		Version:        version,
		Source:         label,
	}, nil
}

// UpsertCandidateSourceNat validates and stages one source NAT rule in the
// candidate workspace. Live running policy is unchanged until commit.
func (s *PolicyServer) UpsertCandidateSourceNat(ctx context.Context, req *openngfwv1.UpsertCandidateSourceNatRequest) (*openngfwv1.UpsertCandidateSourceNatResponse, error) {
	if req.GetRule() == nil {
		return nil, status.Error(codes.InvalidArgument, "source NAT rule is required")
	}
	comment, err := candidateNatAuditComment(req.GetComment(), req.GetReason())
	if err != nil {
		return nil, err
	}
	next, err := s.editableCandidatePolicyForMutation()
	if err != nil {
		return nil, err
	}
	if next.Nat == nil {
		next.Nat = &openngfwv1.Nat{}
	}
	rule := cloneSourceNat(req.GetRule())
	action, err := upsertSourceNat(next, rule, strings.TrimSpace(req.GetId()))
	if err != nil {
		return nil, err
	}
	result, err := s.storeCandidateNatMutation(ctx, next, strings.TrimSpace(req.GetExpectedCandidateRevision()), comment, "source", action, rule, nil)
	if err != nil {
		return nil, err
	}
	return result.upsertSourceResponse(), nil
}

// DeleteCandidateSourceNat validates and stages removal of one source NAT rule
// from the candidate workspace.
func (s *PolicyServer) DeleteCandidateSourceNat(ctx context.Context, req *openngfwv1.DeleteCandidateSourceNatRequest) (*openngfwv1.DeleteCandidateSourceNatResponse, error) {
	comment, err := candidateNatAuditComment(req.GetComment(), req.GetReason())
	if err != nil {
		return nil, err
	}
	next, err := s.editableCandidatePolicyForMutation()
	if err != nil {
		return nil, err
	}
	if next.Nat == nil {
		next.Nat = &openngfwv1.Nat{}
	}
	removed, err := deleteSourceNat(next, req.GetName(), strings.TrimSpace(req.GetId()))
	if err != nil {
		return nil, err
	}
	result, err := s.storeCandidateNatMutation(ctx, next, strings.TrimSpace(req.GetExpectedCandidateRevision()), comment, "source", "deleted", removed, nil)
	if err != nil {
		return nil, err
	}
	return result.deleteSourceResponse(), nil
}

// UpsertCandidateDestinationNat validates and stages one destination NAT rule
// in the candidate workspace. Live running policy is unchanged until commit.
func (s *PolicyServer) UpsertCandidateDestinationNat(ctx context.Context, req *openngfwv1.UpsertCandidateDestinationNatRequest) (*openngfwv1.UpsertCandidateDestinationNatResponse, error) {
	if req.GetRule() == nil {
		return nil, status.Error(codes.InvalidArgument, "destination NAT rule is required")
	}
	comment, err := candidateNatAuditComment(req.GetComment(), req.GetReason())
	if err != nil {
		return nil, err
	}
	next, err := s.editableCandidatePolicyForMutation()
	if err != nil {
		return nil, err
	}
	if next.Nat == nil {
		next.Nat = &openngfwv1.Nat{}
	}
	rule := cloneDestinationNat(req.GetRule())
	action, err := upsertDestinationNat(next, rule, strings.TrimSpace(req.GetId()))
	if err != nil {
		return nil, err
	}
	result, err := s.storeCandidateNatMutation(ctx, next, strings.TrimSpace(req.GetExpectedCandidateRevision()), comment, "destination", action, nil, rule)
	if err != nil {
		return nil, err
	}
	return result.upsertDestinationResponse(), nil
}

// DeleteCandidateDestinationNat validates and stages removal of one destination
// NAT rule from the candidate workspace.
func (s *PolicyServer) DeleteCandidateDestinationNat(ctx context.Context, req *openngfwv1.DeleteCandidateDestinationNatRequest) (*openngfwv1.DeleteCandidateDestinationNatResponse, error) {
	comment, err := candidateNatAuditComment(req.GetComment(), req.GetReason())
	if err != nil {
		return nil, err
	}
	next, err := s.editableCandidatePolicyForMutation()
	if err != nil {
		return nil, err
	}
	if next.Nat == nil {
		next.Nat = &openngfwv1.Nat{}
	}
	removed, err := deleteDestinationNat(next, req.GetName(), strings.TrimSpace(req.GetId()))
	if err != nil {
		return nil, err
	}
	result, err := s.storeCandidateNatMutation(ctx, next, strings.TrimSpace(req.GetExpectedCandidateRevision()), comment, "destination", "deleted", nil, removed)
	if err != nil {
		return nil, err
	}
	return result.deleteDestinationResponse(), nil
}

func (s *PolicyServer) editableCandidatePolicyForMutation() (*openngfwv1.Policy, error) {
	candidate, ok, err := s.store.GetCandidate()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read candidate: %v", err)
	}
	if ok {
		return proto.Clone(candidate).(*openngfwv1.Policy), nil
	}
	running, _, err := s.store.GetRunning()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read running policy: %v", err)
	}
	return proto.Clone(running).(*openngfwv1.Policy), nil
}

type candidateNatMutationResult struct {
	action            string
	natType           string
	sourceNat         *openngfwv1.SourceNat
	destinationNat    *openngfwv1.DestinationNat
	validation        *openngfwv1.ValidateResponse
	candidateStatus   *openngfwv1.GetCandidateStatusResponse
	candidateRevision string
}

func (r candidateNatMutationResult) upsertSourceResponse() *openngfwv1.UpsertCandidateSourceNatResponse {
	return &openngfwv1.UpsertCandidateSourceNatResponse{
		Action:            r.action,
		NatType:           r.natType,
		SourceNat:         cloneSourceNat(r.sourceNat),
		Validation:        r.validation,
		CandidateStatus:   r.candidateStatus,
		CandidateRevision: r.candidateRevision,
	}
}

func (r candidateNatMutationResult) deleteSourceResponse() *openngfwv1.DeleteCandidateSourceNatResponse {
	return &openngfwv1.DeleteCandidateSourceNatResponse{
		Action:            r.action,
		NatType:           r.natType,
		SourceNat:         cloneSourceNat(r.sourceNat),
		Validation:        r.validation,
		CandidateStatus:   r.candidateStatus,
		CandidateRevision: r.candidateRevision,
	}
}

func (r candidateNatMutationResult) upsertDestinationResponse() *openngfwv1.UpsertCandidateDestinationNatResponse {
	return &openngfwv1.UpsertCandidateDestinationNatResponse{
		Action:            r.action,
		NatType:           r.natType,
		DestinationNat:    cloneDestinationNat(r.destinationNat),
		Validation:        r.validation,
		CandidateStatus:   r.candidateStatus,
		CandidateRevision: r.candidateRevision,
	}
}

func (r candidateNatMutationResult) deleteDestinationResponse() *openngfwv1.DeleteCandidateDestinationNatResponse {
	return &openngfwv1.DeleteCandidateDestinationNatResponse{
		Action:            r.action,
		NatType:           r.natType,
		DestinationNat:    cloneDestinationNat(r.destinationNat),
		Validation:        r.validation,
		CandidateStatus:   r.candidateStatus,
		CandidateRevision: r.candidateRevision,
	}
}

func (s *PolicyServer) storeCandidateNatMutation(ctx context.Context, next *openngfwv1.Policy, expectedRevision, comment, natType, action string, sourceRule *openngfwv1.SourceNat, destinationRule *openngfwv1.DestinationNat) (candidateNatMutationResult, error) {
	if strings.TrimSpace(expectedRevision) == "" {
		return candidateNatMutationResult{}, status.Error(codes.InvalidArgument, "expected_candidate_revision is required")
	}
	validation, err := s.validatePolicy(ctx, next)
	if err != nil {
		return candidateNatMutationResult{}, err
	}
	if !validation.GetValid() {
		return candidateNatMutationResult{}, status.Errorf(codes.InvalidArgument, "candidate NAT mutation is invalid: %s", strings.Join(validation.GetErrors(), "; "))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	identity := auditIdentity(ctx)
	revision, err := s.store.SetCandidateWithAuditIfRevision(next, expectedRevision, store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role,
		AuthSource: identity.AuthSource,
		Action:     "mutate-candidate-nat",
		Detail:     fmt.Sprintf("%s NAT %s %q: %s", natType, action, natRuleName(sourceRule, destinationRule), comment),
	})
	if errors.Is(err, store.ErrCandidateRevisionConflict) {
		return candidateNatMutationResult{}, status.Error(codes.FailedPrecondition, "candidate changed since it was loaded; reload candidate NAT before staging")
	}
	if err != nil {
		return candidateNatMutationResult{}, status.Errorf(codes.Internal, "store candidate NAT mutation with audit: %v", err)
	}
	statusResp, err := s.candidateStatusFor(next)
	if err != nil {
		return candidateNatMutationResult{}, err
	}
	return candidateNatMutationResult{
		action:            action,
		natType:           natType,
		sourceNat:         cloneSourceNat(sourceRule),
		destinationNat:    cloneDestinationNat(destinationRule),
		validation:        validation,
		candidateStatus:   statusResp,
		candidateRevision: revision,
	}, nil
}

func candidateNatAuditComment(comment, reason string) (string, error) {
	comment = strings.TrimSpace(comment)
	reason = strings.TrimSpace(reason)
	switch {
	case comment != "" && reason != "":
		return comment + " (reason: " + reason + ")", nil
	case comment != "":
		return comment, nil
	case reason != "":
		return reason, nil
	default:
		return "", status.Error(codes.InvalidArgument, "comment or reason is required")
	}
}

func natRuleName(sourceRule *openngfwv1.SourceNat, destinationRule *openngfwv1.DestinationNat) string {
	if sourceRule != nil {
		return sourceRule.GetName()
	}
	if destinationRule != nil {
		return destinationRule.GetName()
	}
	return ""
}

func upsertSourceNat(p *openngfwv1.Policy, rule *openngfwv1.SourceNat, id string) (string, error) {
	if id != "" {
		if bodyID := strings.TrimSpace(rule.GetId()); bodyID != "" && bodyID != id {
			return "", status.Errorf(codes.InvalidArgument, "source NAT rule id %q does not match requested id %q", bodyID, id)
		}
		idx, err := resolveSourceNatIndexByID(p, id)
		if err != nil {
			return "", err
		}
		rule.Id = id
		p.Nat.Source[idx] = cloneSourceNat(rule)
		return "updated", nil
	}
	for i, existing := range p.GetNat().GetSource() {
		if existing.GetName() == rule.GetName() {
			p.Nat.Source[i] = cloneSourceNat(rule)
			return "updated", nil
		}
	}
	p.Nat.Source = append(p.Nat.Source, cloneSourceNat(rule))
	return "added", nil
}

func deleteSourceNat(p *openngfwv1.Policy, name, id string) (*openngfwv1.SourceNat, error) {
	if id != "" {
		idx, err := resolveSourceNatIndexByID(p, id)
		if err != nil {
			return nil, err
		}
		removed := cloneSourceNat(p.GetNat().GetSource()[idx])
		p.Nat.Source = append(p.Nat.Source[:idx], p.Nat.Source[idx+1:]...)
		return removed, nil
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	for i, existing := range p.GetNat().GetSource() {
		if existing.GetName() == name {
			removed := cloneSourceNat(existing)
			p.Nat.Source = append(p.Nat.Source[:i], p.Nat.Source[i+1:]...)
			return removed, nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "source NAT %q not found in candidate", name)
}

func upsertDestinationNat(p *openngfwv1.Policy, rule *openngfwv1.DestinationNat, id string) (string, error) {
	if id != "" {
		if bodyID := strings.TrimSpace(rule.GetId()); bodyID != "" && bodyID != id {
			return "", status.Errorf(codes.InvalidArgument, "destination NAT rule id %q does not match requested id %q", bodyID, id)
		}
		idx, err := resolveDestinationNatIndexByID(p, id)
		if err != nil {
			return "", err
		}
		rule.Id = id
		p.Nat.Destination[idx] = cloneDestinationNat(rule)
		return "updated", nil
	}
	for i, existing := range p.GetNat().GetDestination() {
		if existing.GetName() == rule.GetName() {
			p.Nat.Destination[i] = cloneDestinationNat(rule)
			return "updated", nil
		}
	}
	p.Nat.Destination = append(p.Nat.Destination, cloneDestinationNat(rule))
	return "added", nil
}

func deleteDestinationNat(p *openngfwv1.Policy, name, id string) (*openngfwv1.DestinationNat, error) {
	if id != "" {
		idx, err := resolveDestinationNatIndexByID(p, id)
		if err != nil {
			return nil, err
		}
		removed := cloneDestinationNat(p.GetNat().GetDestination()[idx])
		p.Nat.Destination = append(p.Nat.Destination[:idx], p.Nat.Destination[idx+1:]...)
		return removed, nil
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	for i, existing := range p.GetNat().GetDestination() {
		if existing.GetName() == name {
			removed := cloneDestinationNat(existing)
			p.Nat.Destination = append(p.Nat.Destination[:i], p.Nat.Destination[i+1:]...)
			return removed, nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "destination NAT %q not found in candidate", name)
}

func resolveSourceNatIndexByID(p *openngfwv1.Policy, id string) (int, error) {
	var matched int
	found := false
	for i, existing := range p.GetNat().GetSource() {
		if strings.TrimSpace(existing.GetId()) != id {
			continue
		}
		if found {
			return -1, status.Errorf(codes.FailedPrecondition, "source NAT id %q is ambiguous in candidate; reload candidate NAT and repair duplicate durable IDs before retrying", id)
		}
		matched = i
		found = true
	}
	if !found {
		return -1, status.Errorf(codes.NotFound, "source NAT id %q not found in candidate; reload candidate NAT and select a current durable ID", id)
	}
	return matched, nil
}

func resolveDestinationNatIndexByID(p *openngfwv1.Policy, id string) (int, error) {
	var matched int
	found := false
	for i, existing := range p.GetNat().GetDestination() {
		if strings.TrimSpace(existing.GetId()) != id {
			continue
		}
		if found {
			return -1, status.Errorf(codes.FailedPrecondition, "destination NAT id %q is ambiguous in candidate; reload candidate NAT and repair duplicate durable IDs before retrying", id)
		}
		matched = i
		found = true
	}
	if !found {
		return -1, status.Errorf(codes.NotFound, "destination NAT id %q not found in candidate; reload candidate NAT and select a current durable ID", id)
	}
	return matched, nil
}

func cloneSourceNatRules(rules []*openngfwv1.SourceNat) []*openngfwv1.SourceNat {
	out := make([]*openngfwv1.SourceNat, 0, len(rules))
	for _, rule := range rules {
		out = append(out, cloneSourceNat(rule))
	}
	return out
}

func cloneSourceNat(rule *openngfwv1.SourceNat) *openngfwv1.SourceNat {
	if rule == nil {
		return nil
	}
	return proto.Clone(rule).(*openngfwv1.SourceNat)
}

func cloneDestinationNatRules(rules []*openngfwv1.DestinationNat) []*openngfwv1.DestinationNat {
	out := make([]*openngfwv1.DestinationNat, 0, len(rules))
	for _, rule := range rules {
		out = append(out, cloneDestinationNat(rule))
	}
	return out
}

func cloneDestinationNat(rule *openngfwv1.DestinationNat) *openngfwv1.DestinationNat {
	if rule == nil {
		return nil
	}
	return proto.Clone(rule).(*openngfwv1.DestinationNat)
}

// ListObjectReferences returns reverse references from policy rules, host-input,
// zones, and NAT entries into named reusable policy objects.
func (s *PolicyServer) ListObjectReferences(_ context.Context, req *openngfwv1.ListObjectReferencesRequest) (*openngfwv1.ListObjectReferencesResponse, error) {
	if req.GetKind() == openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "kind is required")
	}
	p, version, err := s.policyForReferenceRequest(req)
	if err != nil {
		return nil, err
	}
	return &openngfwv1.ListObjectReferencesResponse{
		References: collectObjectReferences(p, req.GetKind(), strings.TrimSpace(req.GetName())),
		Version:    version,
	}, nil
}

// RenamePolicyObject renames one reusable object in the candidate and rewrites
// all candidate references to preserve referential integrity before commit.
func (s *PolicyServer) RenamePolicyObject(ctx context.Context, req *openngfwv1.RenamePolicyObjectRequest) (*openngfwv1.RenamePolicyObjectResponse, error) {
	if req.GetKind() == openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "kind is required")
	}
	oldName := strings.TrimSpace(req.GetOldName())
	newName := strings.TrimSpace(req.GetNewName())
	if oldName == "" {
		return nil, status.Error(codes.InvalidArgument, "old_name is required")
	}
	if newName == "" {
		return nil, status.Error(codes.InvalidArgument, "new_name is required")
	}
	if oldName == policy.Any || newName == policy.Any {
		return nil, status.Errorf(codes.InvalidArgument, "%q is reserved and cannot be renamed", policy.Any)
	}
	if oldName == newName {
		return nil, status.Error(codes.InvalidArgument, "old_name and new_name must be different")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	candidate, ok, err := s.store.GetCandidate()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read candidate: %v", err)
	}
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "no candidate policy is set")
	}
	next := proto.Clone(candidate).(*openngfwv1.Policy)
	rewritten := collectObjectReferences(next, req.GetKind(), oldName)
	if err := renamePolicyObjectDefinition(next, req.GetKind(), oldName, newName); err != nil {
		return nil, err
	}
	rewritePolicyObjectReferences(next, req.GetKind(), oldName, newName)
	if errs := policy.Validate(next); len(errs) > 0 {
		return nil, status.Errorf(codes.InvalidArgument, "renamed candidate is invalid: %s", strings.Join(errs, "; "))
	}

	identity := auditIdentity(ctx)
	detail := fmt.Sprintf("%s %q renamed to %q; %d references rewritten",
		policyObjectKindAuditLabel(req.GetKind()), oldName, newName, len(rewritten))
	if comment := strings.TrimSpace(req.GetComment()); comment != "" {
		detail += ": " + comment
	}
	if err := s.store.SetCandidateWithAudit(next, store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role,
		AuthSource: identity.AuthSource,
		Action:     "rename-policy-object",
		Detail:     detail,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "store renamed candidate with audit: %v", err)
	}
	statusResp, err := s.candidateStatusFor(next)
	if err != nil {
		return nil, err
	}
	return &openngfwv1.RenamePolicyObjectResponse{
		Kind:                req.GetKind(),
		OldName:             oldName,
		NewName:             newName,
		ObjectRenamed:       true,
		RewrittenReferences: renamedObjectReferences(rewritten, newName),
		CandidateStatus:     statusResp,
	}, nil
}

func (s *PolicyServer) candidateStatusFor(candidate *openngfwv1.Policy) (*openngfwv1.GetCandidateStatusResponse, error) {
	running, runningVersion, err := s.store.GetRunning()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read running policy: %v", err)
	}
	revision, err := s.store.CandidateRevision()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read candidate revision: %v", err)
	}
	dirty := !proto.Equal(running, candidate)
	changes := candidateChangeSummaries(running, candidate)
	var changeCount uint32
	for _, change := range changes {
		changeCount += change.GetAdded() + change.GetModified() + change.GetRemoved()
	}
	return &openngfwv1.GetCandidateStatusResponse{
		HasCandidate:      true,
		Dirty:             dirty,
		RunningVersion:    runningVersion,
		ChangeCount:       changeCount,
		Changes:           changes,
		Impact:            policy.Impact(running, candidate),
		CandidateRevision: revision,
	}, nil
}

// CreateChangeApproval records an approval for the exact candidate revision
// under review. RBAC requires admin for this RPC; commit consumes the approval.
func (s *PolicyServer) CreateChangeApproval(ctx context.Context, req *openngfwv1.CreateChangeApprovalRequest) (*openngfwv1.CreateChangeApprovalResponse, error) {
	comment, err := requiredAuditComment(req.GetComment(), "approval comment")
	if err != nil {
		return nil, err
	}
	revision := strings.TrimSpace(req.GetCandidateRevision())
	if revision == "" {
		return nil, status.Error(codes.InvalidArgument, "candidate_revision is required")
	}
	approval, err := s.store.CreateChangeApproval(revision, auditIdentity(ctx), comment, req.GetAckRisk(), req.GetAckRuntime())
	if errors.Is(err, store.ErrChangeApprovalRevisionMismatch) {
		return nil, status.Error(codes.FailedPrecondition, "candidate changed since approval review; reload candidate state before approving")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "record change approval: %v", err)
	}
	return &openngfwv1.CreateChangeApprovalResponse{Approval: changeApprovalProto(approval)}, nil
}

// ListChangeApprovals returns recent approval records, newest first.
func (s *PolicyServer) ListChangeApprovals(_ context.Context, req *openngfwv1.ListChangeApprovalsRequest) (*openngfwv1.ListChangeApprovalsResponse, error) {
	approvals, err := s.store.ListChangeApprovals(store.ChangeApprovalFilter{
		CandidateRevision: strings.TrimSpace(req.GetCandidateRevision()),
		IncludeConsumed:   req.GetIncludeConsumed(),
		Limit:             int(req.GetLimit()),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list change approvals: %v", err)
	}
	resp := &openngfwv1.ListChangeApprovalsResponse{}
	for _, approval := range approvals {
		resp.Approvals = append(resp.Approvals, changeApprovalProto(approval))
	}
	return resp, nil
}

// CreateBackupSnapshot persists an appliance-owned policy snapshot. Unlike
// browser export, this remains in the server store for validation and restore
// preview workflows.
func (s *PolicyServer) CreateBackupSnapshot(ctx context.Context, req *openngfwv1.CreateBackupSnapshotRequest) (*openngfwv1.CreateBackupSnapshotResponse, error) {
	source := req.GetSource()
	if source == openngfwv1.PolicySource_POLICY_SOURCE_UNSPECIFIED {
		source = openngfwv1.PolicySource_POLICY_SOURCE_RUNNING
	}
	p, sourceVersion, sourceLabel, err := s.diffSnapshot(source, req.GetVersion(), "snapshot")
	if err != nil {
		return nil, err
	}
	_, runningVersion, err := s.store.GetRunning()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read running policy: %v", err)
	}
	candidateRevision, err := s.store.CandidateRevision()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read candidate revision: %v", err)
	}
	identity := auditIdentity(ctx)
	comment := strings.TrimSpace(req.GetComment())
	snapshot, err := s.store.CreateBackupSnapshot(p, store.BackupSnapshot{
		Actor:             identity.Name,
		ActorRole:         identity.Role,
		AuthSource:        identity.AuthSource,
		Comment:           comment,
		Source:            sourceLabel,
		SourceVersion:     sourceVersion,
		RunningVersion:    runningVersion,
		CandidateRevision: candidateRevision,
	}, store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role,
		AuthSource: identity.AuthSource,
		Detail:     backupSnapshotAuditDetail(sourceLabel, sourceVersion, comment),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create backup snapshot: %v", err)
	}
	return &openngfwv1.CreateBackupSnapshotResponse{Snapshot: backupSnapshotProto(snapshot)}, nil
}

// ListBackupSnapshots returns appliance-owned snapshot metadata newest first.
func (s *PolicyServer) ListBackupSnapshots(_ context.Context, req *openngfwv1.ListBackupSnapshotsRequest) (*openngfwv1.ListBackupSnapshotsResponse, error) {
	snapshots, err := s.store.ListBackupSnapshots(int(req.GetLimit()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list backup snapshots: %v", err)
	}
	resp := &openngfwv1.ListBackupSnapshotsResponse{}
	for _, snapshot := range snapshots {
		resp.Snapshots = append(resp.Snapshots, backupSnapshotProto(snapshot))
	}
	return resp, nil
}

// GetBackupSnapshot returns a stored snapshot policy for inspection/export.
func (s *PolicyServer) GetBackupSnapshot(_ context.Context, req *openngfwv1.GetBackupSnapshotRequest) (*openngfwv1.GetBackupSnapshotResponse, error) {
	snapshot, p, err := s.store.GetBackupSnapshot(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}
	return &openngfwv1.GetBackupSnapshotResponse{Snapshot: backupSnapshotProto(snapshot), Policy: p}, nil
}

// ValidateBackupSnapshot validates a stored snapshot without mutating state.
func (s *PolicyServer) ValidateBackupSnapshot(ctx context.Context, req *openngfwv1.ValidateBackupSnapshotRequest) (*openngfwv1.ValidateBackupSnapshotResponse, error) {
	snapshot, p, err := s.store.GetBackupSnapshot(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}
	validation, err := s.validatePolicy(ctx, p)
	if err != nil {
		return nil, err
	}
	return &openngfwv1.ValidateBackupSnapshotResponse{Snapshot: backupSnapshotProto(snapshot), Validation: validation}, nil
}

// PreviewBackupSnapshotRestore previews restoration of a snapshot. If requested,
// it stages the snapshot into candidate only; live running policy is unchanged.
func (s *PolicyServer) PreviewBackupSnapshotRestore(ctx context.Context, req *openngfwv1.PreviewBackupSnapshotRestoreRequest) (*openngfwv1.PreviewBackupSnapshotRestoreResponse, error) {
	snapshot, p, err := s.store.GetBackupSnapshot(req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}
	validation, err := s.validatePolicy(ctx, p)
	if err != nil {
		return nil, err
	}
	running, runningVersion, err := s.store.GetRunning()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read running policy: %v", err)
	}
	lines, changed, err := policydiff.Lines(running, p)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "diff snapshot restore: %v", err)
	}
	resp := &openngfwv1.PreviewBackupSnapshotRestoreResponse{
		JobId:      "restore-preview-" + snapshot.ID,
		Snapshot:   backupSnapshotProto(snapshot),
		Validation: validation,
		Diff: &openngfwv1.DiffPolicyResponse{
			FromLabel:   fmt.Sprintf("running policy v%d", runningVersion),
			ToLabel:     "backup snapshot " + snapshot.ID,
			FromVersion: runningVersion,
			Changed:     changed,
			Lines:       lines,
		},
		Detail: "Restore preview only; running policy and engines are unchanged.",
	}
	if !req.GetStageCandidate() {
		return resp, nil
	}
	comment, err := requiredAuditComment(req.GetComment(), "restore preview comment")
	if err != nil {
		return nil, err
	}
	if !validation.GetValid() {
		return nil, status.Error(codes.FailedPrecondition, "snapshot validation failed; candidate was not staged")
	}
	identity := auditIdentity(ctx)
	revision, err := s.store.SetCandidateWithAuditIfRevision(proto.Clone(p).(*openngfwv1.Policy), strings.TrimSpace(req.GetExpectedCandidateRevision()), store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role,
		AuthSource: identity.AuthSource,
		Action:     "backup-snapshot-restore-stage",
		Detail:     fmt.Sprintf("snapshot %s staged as candidate: %s", snapshot.ID, comment),
	})
	if errors.Is(err, store.ErrCandidateRevisionConflict) {
		return nil, status.Error(codes.FailedPrecondition, "candidate changed since it was loaded; reload snapshot restore preview")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "stage backup snapshot candidate: %v", err)
	}
	resp.StagedCandidate = true
	resp.Detail = fmt.Sprintf("Snapshot %s staged as candidate revision %s. Commit is still required before live apply.", snapshot.ID, revision)
	statusResp, err := s.candidateStatusFor(p)
	if err != nil {
		return nil, err
	}
	resp.CandidateStatus = statusResp
	return resp, nil
}

type candidateChangeCounts struct {
	added    uint32
	modified uint32
	removed  uint32
}

type namedPolicyMessage interface {
	proto.Message
	GetName() string
}

func candidateChangeSummaries(running, candidate *openngfwv1.Policy) []*openngfwv1.CandidateChangeSummary {
	if running == nil {
		running = &openngfwv1.Policy{}
	}
	if candidate == nil {
		candidate = &openngfwv1.Policy{}
	}
	running, _ = policy.NormalizeRuleIDs(running)
	candidate, _ = policy.NormalizeRuleIDs(candidate)
	var out []*openngfwv1.CandidateChangeSummary
	out = appendCandidateChange(out, "rules", countRuleIdentityChanges(running.GetRules(), candidate.GetRules()))
	out = appendCandidateChange(out, "zones", countNamedPolicyChanges(running.GetZones(), candidate.GetZones(), false))
	out = appendCandidateChange(out, "addresses", countNamedPolicyChanges(running.GetAddresses(), candidate.GetAddresses(), false))
	out = appendCandidateChange(out, "services", countNamedPolicyChanges(running.GetServices(), candidate.GetServices(), false))
	out = appendCandidateChange(out, "applications", countNamedPolicyChanges(running.GetApplications(), candidate.GetApplications(), false))
	out = appendCandidateChange(out, "securityProfiles", countNamedPolicyChanges(running.GetSecurityProfiles(), candidate.GetSecurityProfiles(), false))
	out = appendCandidateChange(out, "qosProfiles", countNamedPolicyChanges(running.GetQosProfiles(), candidate.GetQosProfiles(), false))
	out = appendCandidateChange(out, "zoneProtectionProfiles", countNamedPolicyChanges(running.GetZoneProtectionProfiles(), candidate.GetZoneProtectionProfiles(), false))
	out = appendCandidateChange(out, "nat", countPolicyMessageChange(running.GetNat(), candidate.GetNat()))
	out = appendCandidateChange(out, "staticRoutes", countIndexedPolicyChanges(running.GetStaticRoutes(), candidate.GetStaticRoutes()))
	out = appendCandidateChange(out, "routing", countPolicyMessageChange(running.GetRouting(), candidate.GetRouting()))
	out = appendCandidateChange(out, "vpn", countPolicyMessageChange(running.GetVpn(), candidate.GetVpn()))
	out = appendCandidateChange(out, "network", countPolicyMessageChange(running.GetNetwork(), candidate.GetNetwork()))
	out = appendCandidateChange(out, "hostInput", countPolicyMessageChange(running.GetHostInput(), candidate.GetHostInput()))
	out = appendCandidateChange(out, "proxy", countPolicyMessageChange(running.GetProxy(), candidate.GetProxy()))
	out = appendCandidateChange(out, "ids", countPolicyMessageChange(running.GetIds(), candidate.GetIds()))
	out = appendCandidateChange(out, "intel", countPolicyMessageChange(running.GetIntel(), candidate.GetIntel()))
	out = appendCandidateChange(out, "telemetry", countPolicyMessageChange(running.GetTelemetry(), candidate.GetTelemetry()))
	return out
}

func countRuleIdentityChanges(before, after []*openngfwv1.Rule) candidateChangeCounts {
	oldMap := map[string]*openngfwv1.Rule{}
	newMap := map[string]*openngfwv1.Rule{}
	oldOrder := make([]string, 0, len(before))
	newOrder := make([]string, 0, len(after))
	for i, item := range before {
		key := policy.RuleIdentityKey(item, i)
		oldMap[key] = item
		oldOrder = append(oldOrder, key)
	}
	for i, item := range after {
		key := policy.RuleIdentityKey(item, i)
		newMap[key] = item
		newOrder = append(newOrder, key)
	}

	var counts candidateChangeCounts
	for key, afterItem := range newMap {
		beforeItem, ok := oldMap[key]
		if !ok {
			counts.added++
			continue
		}
		if !proto.Equal(beforeItem, afterItem) {
			counts.modified++
		}
	}
	for key := range oldMap {
		if _, ok := newMap[key]; !ok {
			counts.removed++
		}
	}
	if sameCandidateKeys(oldMap, newMap) && strings.Join(oldOrder, "\x00") != strings.Join(newOrder, "\x00") {
		counts.modified++
	}
	return counts
}

func appendCandidateChange(out []*openngfwv1.CandidateChangeSummary, section string, counts candidateChangeCounts) []*openngfwv1.CandidateChangeSummary {
	if counts.added+counts.modified+counts.removed == 0 {
		return out
	}
	return append(out, &openngfwv1.CandidateChangeSummary{
		Section:  section,
		Added:    counts.added,
		Modified: counts.modified,
		Removed:  counts.removed,
	})
}

func countNamedPolicyChanges[T namedPolicyMessage](before, after []T, trackOrder bool) candidateChangeCounts {
	oldMap := map[string]T{}
	newMap := map[string]T{}
	oldOrder := make([]string, 0, len(before))
	newOrder := make([]string, 0, len(after))
	for i, item := range before {
		key := candidateChangeKey(item.GetName(), i)
		oldMap[key] = item
		oldOrder = append(oldOrder, key)
	}
	for i, item := range after {
		key := candidateChangeKey(item.GetName(), i)
		newMap[key] = item
		newOrder = append(newOrder, key)
	}

	var counts candidateChangeCounts
	for key, afterItem := range newMap {
		beforeItem, ok := oldMap[key]
		if !ok {
			counts.added++
			continue
		}
		if !proto.Equal(beforeItem, afterItem) {
			counts.modified++
		}
	}
	for key := range oldMap {
		if _, ok := newMap[key]; !ok {
			counts.removed++
		}
	}
	if trackOrder && sameCandidateKeys(oldMap, newMap) && strings.Join(oldOrder, "\x00") != strings.Join(newOrder, "\x00") {
		counts.modified++
	}
	return counts
}

func countIndexedPolicyChanges[T proto.Message](before, after []T) candidateChangeCounts {
	var counts candidateChangeCounts
	minLen := len(before)
	if len(after) < minLen {
		minLen = len(after)
	}
	for i := 0; i < minLen; i++ {
		if !proto.Equal(before[i], after[i]) {
			counts.modified++
		}
	}
	if len(after) > len(before) {
		counts.added += uint32(len(after) - len(before))
	}
	if len(before) > len(after) {
		counts.removed += uint32(len(before) - len(after))
	}
	return counts
}

func countPolicyMessageChange(before, after proto.Message) candidateChangeCounts {
	if proto.Equal(before, after) {
		return candidateChangeCounts{}
	}
	return candidateChangeCounts{modified: 1}
}

func candidateChangeKey(name string, index int) string {
	if name != "" {
		return "name:" + name
	}
	return fmt.Sprintf("index:%d", index)
}

func sameCandidateKeys[T proto.Message](oldMap, newMap map[string]T) bool {
	if len(oldMap) != len(newMap) {
		return false
	}
	for key := range oldMap {
		if _, ok := newMap[key]; !ok {
			return false
		}
	}
	return true
}

// DiffPolicy returns the public policy diff used by GUI, CLI, and automation.
func (s *PolicyServer) DiffPolicy(_ context.Context, req *openngfwv1.DiffPolicyRequest) (*openngfwv1.DiffPolicyResponse, error) {
	fromPolicy, fromVersion, fromLabel, err := s.diffSnapshot(req.GetFromSource(), req.GetFromVersion(), "from")
	if err != nil {
		return nil, err
	}
	toSource := req.GetToSource()
	if toSource == openngfwv1.PolicySource_POLICY_SOURCE_UNSPECIFIED {
		toSource = openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE
	}
	toPolicy, toVersion, toLabel, err := s.diffSnapshot(toSource, req.GetToVersion(), "to")
	if err != nil {
		return nil, err
	}
	lines, changed, err := policydiff.Lines(fromPolicy, toPolicy)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "diff policy: %v", err)
	}
	return &openngfwv1.DiffPolicyResponse{
		FromLabel:   fromLabel,
		ToLabel:     toLabel,
		FromVersion: fromVersion,
		ToVersion:   toVersion,
		Changed:     changed,
		Lines:       lines,
	}, nil
}

func (s *PolicyServer) diffSnapshot(source openngfwv1.PolicySource, version uint64, side string) (*openngfwv1.Policy, uint64, string, error) {
	switch source {
	case openngfwv1.PolicySource_POLICY_SOURCE_UNSPECIFIED, openngfwv1.PolicySource_POLICY_SOURCE_RUNNING:
		p, runningVersion, err := s.store.GetRunning()
		if err != nil {
			return nil, 0, "", status.Errorf(codes.Internal, "read running policy: %v", err)
		}
		return p, runningVersion, fmt.Sprintf("running policy v%d", runningVersion), nil
	case openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE:
		p, ok, err := s.store.GetCandidate()
		if err != nil {
			return nil, 0, "", status.Errorf(codes.Internal, "read candidate: %v", err)
		}
		if !ok {
			return nil, 0, "", status.Error(codes.NotFound, "no candidate policy is set")
		}
		return p, 0, "candidate", nil
	case openngfwv1.PolicySource_POLICY_SOURCE_VERSION:
		if version == 0 {
			return nil, 0, "", status.Errorf(codes.InvalidArgument, "%s_version is required when %s_source is POLICY_SOURCE_VERSION", side, side)
		}
		p, err := s.store.GetVersion(version)
		if err != nil {
			return nil, 0, "", status.Errorf(codes.NotFound, "%v", err)
		}
		return p, version, fmt.Sprintf("version %d", version), nil
	default:
		return nil, 0, "", status.Errorf(codes.InvalidArgument, "%s_source is invalid", side)
	}
}

func (s *PolicyServer) policyForReferenceRequest(req *openngfwv1.ListObjectReferencesRequest) (*openngfwv1.Policy, uint64, error) {
	switch req.GetSource() {
	case openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE:
		p, ok, err := s.store.GetCandidate()
		if err != nil {
			return nil, 0, status.Errorf(codes.Internal, "read candidate: %v", err)
		}
		if !ok {
			return nil, 0, status.Error(codes.NotFound, "no candidate policy is set")
		}
		return p, 0, nil
	case openngfwv1.PolicySource_POLICY_SOURCE_VERSION:
		if req.GetVersion() == 0 {
			return nil, 0, status.Error(codes.InvalidArgument, "version is required when source is POLICY_SOURCE_VERSION")
		}
		p, err := s.store.GetVersion(req.GetVersion())
		if err != nil {
			return nil, 0, status.Errorf(codes.NotFound, "%v", err)
		}
		return p, req.GetVersion(), nil
	default: // running
		p, version, err := s.store.GetRunning()
		if err != nil {
			return nil, 0, status.Errorf(codes.Internal, "read running policy: %v", err)
		}
		return p, version, nil
	}
}

func collectObjectReferences(p *openngfwv1.Policy, kind openngfwv1.PolicyObjectKind, name string) []*openngfwv1.PolicyObjectReference {
	if p == nil {
		return nil
	}
	b := &objectReferenceBuilder{name: name}

	for i, rule := range p.GetRules() {
		switch kind {
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE:
			b.addManyForRule(rule, i, "from zone", rule.GetFromZones())
			b.addManyForRule(rule, i, "to zone", rule.GetToZones())
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS:
			b.addManyForRule(rule, i, "source address", rule.GetSourceAddresses())
			b.addManyForRule(rule, i, "destination address", rule.GetDestinationAddresses())
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SERVICE:
			b.addManyForRule(rule, i, "service", rule.GetServices())
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_APPLICATION:
			b.addManyForRule(rule, i, "application", rule.GetApplications())
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SECURITY_PROFILE:
			b.addManyForRule(rule, i, "security profile", rule.GetSecurityProfiles())
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_QOS_PROFILE:
			b.addForRule(rule, i, "QoS profile", rule.GetQosProfile())
		}
	}

	if kind == openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE_PROTECTION_PROFILE {
		for i, zone := range p.GetZones() {
			b.add("zone", zone.GetName(), "", i, "zone-protection profile", zone.GetZoneProtectionProfile(), zone.GetDescription())
		}
	}

	for i, rule := range p.GetHostInput().GetRules() {
		switch kind {
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE:
			b.addMany("host-input rule", rule.GetName(), strings.TrimSpace(rule.GetId()), i, "from zone", rule.GetFromZones(), rule.GetDescription())
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS:
			b.addMany("host-input rule", rule.GetName(), strings.TrimSpace(rule.GetId()), i, "source address", rule.GetSourceAddresses(), rule.GetDescription())
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SERVICE:
			b.addMany("host-input rule", rule.GetName(), strings.TrimSpace(rule.GetId()), i, "service", rule.GetServices(), rule.GetDescription())
		}
	}

	for i, rule := range p.GetNat().GetSource() {
		switch kind {
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE:
			b.add("source NAT", rule.GetName(), strings.TrimSpace(rule.GetId()), i, "to zone", rule.GetToZone(), "")
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS:
			b.add("source NAT", rule.GetName(), strings.TrimSpace(rule.GetId()), i, "source address", rule.GetSourceAddress(), "")
			b.add("source NAT", rule.GetName(), strings.TrimSpace(rule.GetId()), i, "translated address", rule.GetTranslatedAddress(), "")
		}
	}

	for i, rule := range p.GetNat().GetDestination() {
		switch kind {
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE:
			b.add("destination NAT", rule.GetName(), strings.TrimSpace(rule.GetId()), i, "from zone", rule.GetFromZone(), "")
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS:
			b.add("destination NAT", rule.GetName(), strings.TrimSpace(rule.GetId()), i, "destination address", rule.GetDestinationAddress(), "")
			b.add("destination NAT", rule.GetName(), strings.TrimSpace(rule.GetId()), i, "translated address", rule.GetTranslatedAddress(), "")
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SERVICE:
			b.add("destination NAT", rule.GetName(), strings.TrimSpace(rule.GetId()), i, "service", rule.GetService(), "")
		}
	}

	if kind == openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS {
		for i, exception := range p.GetIds().GetExceptions() {
			b.add("IDS exception", exception.GetName(), "", i, "source address", exception.GetSourceAddress(), exception.GetDescription())
			b.add("IDS exception", exception.GetName(), "", i, "destination address", exception.GetDestinationAddress(), exception.GetDescription())
		}
	}

	return b.refs
}

func renamePolicyObjectDefinition(p *openngfwv1.Policy, kind openngfwv1.PolicyObjectKind, oldName, newName string) error {
	switch kind {
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE:
		return renameNamedPolicyObject("zone", p.GetZones(), oldName, newName, func(z *openngfwv1.Zone, name string) { z.Name = name })
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS:
		return renameNamedPolicyObject("address", p.GetAddresses(), oldName, newName, func(a *openngfwv1.Address, name string) { a.Name = name })
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SERVICE:
		return renameNamedPolicyObject("service", p.GetServices(), oldName, newName, func(s *openngfwv1.Service, name string) { s.Name = name })
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_APPLICATION:
		return renameNamedPolicyObject("application", p.GetApplications(), oldName, newName, func(a *openngfwv1.Application, name string) { a.Name = name })
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SECURITY_PROFILE:
		return renameNamedPolicyObject("security profile", p.GetSecurityProfiles(), oldName, newName, func(sp *openngfwv1.SecurityProfile, name string) { sp.Name = name })
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_QOS_PROFILE:
		return renameNamedPolicyObject("QoS profile", p.GetQosProfiles(), oldName, newName, func(qp *openngfwv1.QosProfile, name string) { qp.Name = name })
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE_PROTECTION_PROFILE:
		return renameNamedPolicyObject("zone-protection profile", p.GetZoneProtectionProfiles(), oldName, newName, func(zp *openngfwv1.ZoneProtectionProfile, name string) { zp.Name = name })
	default:
		return status.Error(codes.InvalidArgument, "kind is invalid")
	}
}

func renameNamedPolicyObject[T interface{ GetName() string }](kind string, items []T, oldName, newName string, setName func(T, string)) error {
	found := false
	for _, item := range items {
		switch item.GetName() {
		case newName:
			return status.Errorf(codes.AlreadyExists, "%s %q already exists", kind, newName)
		case oldName:
			found = true
		}
	}
	if !found {
		return status.Errorf(codes.NotFound, "%s %q not found in candidate", kind, oldName)
	}
	for _, item := range items {
		if item.GetName() == oldName {
			setName(item, newName)
			return nil
		}
	}
	return nil
}

func rewritePolicyObjectReferences(p *openngfwv1.Policy, kind openngfwv1.PolicyObjectKind, oldName, newName string) {
	for _, rule := range p.GetRules() {
		switch kind {
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE:
			replaceStringRefs(rule.FromZones, oldName, newName)
			replaceStringRefs(rule.ToZones, oldName, newName)
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS:
			replaceStringRefs(rule.SourceAddresses, oldName, newName)
			replaceStringRefs(rule.DestinationAddresses, oldName, newName)
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SERVICE:
			replaceStringRefs(rule.Services, oldName, newName)
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_APPLICATION:
			replaceStringRefs(rule.Applications, oldName, newName)
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SECURITY_PROFILE:
			replaceStringRefs(rule.SecurityProfiles, oldName, newName)
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_QOS_PROFILE:
			rule.QosProfile = replaceStringRef(rule.GetQosProfile(), oldName, newName)
		}
	}
	if kind == openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE_PROTECTION_PROFILE {
		for _, zone := range p.GetZones() {
			zone.ZoneProtectionProfile = replaceStringRef(zone.GetZoneProtectionProfile(), oldName, newName)
		}
	}
	for _, rule := range p.GetHostInput().GetRules() {
		switch kind {
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE:
			replaceStringRefs(rule.FromZones, oldName, newName)
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS:
			replaceStringRefs(rule.SourceAddresses, oldName, newName)
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SERVICE:
			replaceStringRefs(rule.Services, oldName, newName)
		}
	}
	for _, rule := range p.GetNat().GetSource() {
		switch kind {
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE:
			rule.ToZone = replaceStringRef(rule.GetToZone(), oldName, newName)
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS:
			rule.SourceAddress = replaceStringRef(rule.GetSourceAddress(), oldName, newName)
			rule.TranslatedAddress = replaceStringRef(rule.GetTranslatedAddress(), oldName, newName)
		}
	}
	for _, rule := range p.GetNat().GetDestination() {
		switch kind {
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE:
			rule.FromZone = replaceStringRef(rule.GetFromZone(), oldName, newName)
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS:
			rule.DestinationAddress = replaceStringRef(rule.GetDestinationAddress(), oldName, newName)
			rule.TranslatedAddress = replaceStringRef(rule.GetTranslatedAddress(), oldName, newName)
		case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SERVICE:
			rule.Service = replaceStringRef(rule.GetService(), oldName, newName)
		}
	}
	if kind == openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS {
		for _, exception := range p.GetIds().GetExceptions() {
			exception.SourceAddress = replaceStringRef(exception.GetSourceAddress(), oldName, newName)
			exception.DestinationAddress = replaceStringRef(exception.GetDestinationAddress(), oldName, newName)
		}
	}
}

func replaceStringRefs(refs []string, oldName, newName string) {
	for i := range refs {
		refs[i] = replaceStringRef(refs[i], oldName, newName)
	}
}

func replaceStringRef(ref, oldName, newName string) string {
	if ref == oldName {
		return newName
	}
	return ref
}

func renamedObjectReferences(refs []*openngfwv1.PolicyObjectReference, newName string) []*openngfwv1.PolicyObjectReference {
	out := make([]*openngfwv1.PolicyObjectReference, 0, len(refs))
	for _, ref := range refs {
		if ref == nil {
			continue
		}
		cloned := proto.Clone(ref).(*openngfwv1.PolicyObjectReference)
		cloned.ObjectName = newName
		out = append(out, cloned)
	}
	return out
}

func policyObjectKindAuditLabel(kind openngfwv1.PolicyObjectKind) string {
	switch kind {
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE:
		return "zone"
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ADDRESS:
		return "address"
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SERVICE:
		return "service"
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_APPLICATION:
		return "application"
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_SECURITY_PROFILE:
		return "security profile"
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_QOS_PROFILE:
		return "QoS profile"
	case openngfwv1.PolicyObjectKind_POLICY_OBJECT_KIND_ZONE_PROTECTION_PROFILE:
		return "zone-protection profile"
	default:
		return "policy object"
	}
}

type objectReferenceBuilder struct {
	name string
	refs []*openngfwv1.PolicyObjectReference
}

func (b *objectReferenceBuilder) addMany(area, item, itemID string, index int, field string, objectNames []string, itemDescription string) {
	for _, objectName := range objectNames {
		b.add(area, item, itemID, index, field, objectName, itemDescription)
	}
}

func (b *objectReferenceBuilder) addForRule(rule *openngfwv1.Rule, index int, field, objectName string) {
	if rule == nil {
		b.add("security rule", "", "", index, field, objectName, "")
		return
	}
	b.add("security rule", rule.GetName(), strings.TrimSpace(rule.GetId()), index, field, objectName, rule.GetDescription())
}

func (b *objectReferenceBuilder) addManyForRule(rule *openngfwv1.Rule, index int, field string, objectNames []string) {
	for _, objectName := range objectNames {
		b.addForRule(rule, index, field, objectName)
	}
}

func (b *objectReferenceBuilder) add(area, item, itemID string, index int, field, objectName, itemDescription string) {
	objectName = strings.TrimSpace(objectName)
	if objectName == "" || objectName == "any" {
		return
	}
	if b.name != "" && objectName != b.name {
		return
	}
	if item == "" {
		item = fmt.Sprintf("#%d", index+1)
	}
	b.refs = append(b.refs, &openngfwv1.PolicyObjectReference{
		ObjectName: objectName,
		Area:       area,
		Item:       item,
		Index:      uint32(index),
		Field:      field,
		Detail:     referenceDetail(area, field, itemDescription),
		ItemId:     itemID,
	})
}

func referenceDetail(area, field, itemDescription string) string {
	switch {
	case area == "destination NAT" && field == "translated address":
		return "Traffic is translated to this address."
	case area == "source NAT" && field == "translated address":
		return "Egress traffic is translated to this address."
	case field == "from zone" || field == "to zone":
		return "Trust boundary match."
	case field == "application":
		return "Phragma App-ID policy match."
	case field == "security profile":
		return "Layered inspection profile attached to this rule."
	case field == "QoS profile":
		return "Traffic shaping intent attached to this rule."
	case field == "zone-protection profile":
		return "DoS protection intent attached to this zone."
	case field == "service":
		return "L4 protocol or port match."
	default:
		return itemDescription
	}
}

// SetCandidate replaces the candidate policy without applying it.
func (s *PolicyServer) SetCandidate(ctx context.Context, req *openngfwv1.SetCandidateRequest) (*openngfwv1.SetCandidateResponse, error) {
	if req.GetPolicy() == nil {
		return nil, status.Error(codes.InvalidArgument, "policy is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	identity := auditIdentity(ctx)
	revision, err := s.store.SetCandidateWithAuditIfRevision(req.GetPolicy(), strings.TrimSpace(req.GetExpectedCandidateRevision()), store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role,
		AuthSource: identity.AuthSource,
		Action:     "set-candidate",
		Detail:     fmt.Sprintf("%d zones, %d rules, %d applications, %d security profiles", len(req.GetPolicy().GetZones()), len(req.GetPolicy().GetRules()), len(req.GetPolicy().GetApplications()), len(req.GetPolicy().GetSecurityProfiles())),
	})
	if errors.Is(err, store.ErrCandidateRevisionConflict) {
		return nil, status.Error(codes.FailedPrecondition, "candidate changed since it was loaded; reload candidate state before staging")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "store candidate with audit: %v", err)
	}
	return &openngfwv1.SetCandidateResponse{CandidateRevision: revision}, nil
}

// Validate checks a policy end-to-end without touching engines. By default it
// validates the stored candidate; callers may also pass an unstaged policy for
// import/preflight workflows that must not mutate candidate state.
func (s *PolicyServer) Validate(ctx context.Context, req *openngfwv1.ValidateRequest) (*openngfwv1.ValidateResponse, error) {
	cand := req.GetPolicy()
	if cand == nil {
		var ok bool
		var err error
		cand, ok, err = s.store.GetCandidate()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "read candidate: %v", err)
		}
		if !ok {
			return nil, status.Error(codes.FailedPrecondition, "no candidate policy is set")
		}
	}
	return s.validatePolicy(ctx, cand)
}

func (s *PolicyServer) validatePolicy(ctx context.Context, cand *openngfwv1.Policy) (*openngfwv1.ValidateResponse, error) {
	cand, _ = policy.NormalizeRuleIDs(cand)
	running, _, err := s.store.GetRunning()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read running policy: %v", err)
	}
	impact := policy.Impact(running, cand)
	semanticFindings := policy.SemanticFindings(cand)
	annotateRuleOverlapFindings(cand, semanticFindings)
	if errs := policy.Validate(cand); len(errs) > 0 {
		findings := append(validationErrorFindings(errs), semanticFindings...)
		return validationResponse(false, errs, impact, nil, findings...), nil
	}
	// Renderability + engine syntax checks, still without touching state.
	artifacts, err := s.render(cand)
	if err != nil {
		errs := []string{err.Error()}
		findings := append(semanticFindings, &openngfwv1.ValidationFinding{
			Severity: openngfwv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR,
			Stage:    openngfwv1.ValidationStage_VALIDATION_STAGE_RENDER,
			Code:     "RENDER_ERROR",
			Message:  err.Error(),
		})
		return validationResponse(false, errs, impact, nil, findings...), nil
	}
	if err := s.sup.Validate(ctx, artifacts); err != nil {
		errs := []string{err.Error()}
		findings := append(semanticFindings, &openngfwv1.ValidationFinding{
			Severity: openngfwv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR,
			Stage:    openngfwv1.ValidationStage_VALIDATION_STAGE_ENGINE_VALIDATE,
			Code:     "ENGINE_VALIDATE_ERROR",
			Message:  err.Error(),
		})
		return validationResponse(false, errs, impact, artifacts, findings...), nil
	}
	return validationResponse(true, nil, impact, artifacts, semanticFindings...), nil
}

func backupSnapshotAuditDetail(sourceLabel string, sourceVersion uint64, comment string) string {
	detail := "snapshot from " + strings.TrimSpace(sourceLabel)
	if sourceVersion != 0 {
		detail += fmt.Sprintf(" (v%d)", sourceVersion)
	}
	if strings.TrimSpace(comment) != "" {
		detail += ": " + strings.TrimSpace(comment)
	}
	return detail
}

func backupSnapshotProto(snapshot store.BackupSnapshot) *openngfwv1.BackupSnapshot {
	out := &openngfwv1.BackupSnapshot{
		Id:                snapshot.ID,
		Actor:             snapshot.Actor,
		ActorRole:         snapshot.ActorRole,
		AuthSource:        snapshot.AuthSource,
		Comment:           snapshot.Comment,
		Source:            snapshot.Source,
		SourceVersion:     snapshot.SourceVersion,
		RunningVersion:    snapshot.RunningVersion,
		CandidateRevision: snapshot.CandidateRevision,
		PolicySha256:      snapshot.PolicySHA256,
		PolicySizeBytes:   snapshot.PolicySizeBytes,
	}
	if !snapshot.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(snapshot.CreatedAt)
	}
	return out
}

func validationResponse(valid bool, errors []string, impact *openngfwv1.ChangeImpact, artifacts map[string][]byte, findings ...*openngfwv1.ValidationFinding) *openngfwv1.ValidateResponse {
	resp := &openngfwv1.ValidateResponse{
		Valid:      valid,
		Errors:     errors,
		Impact:     impact,
		Findings:   append([]*openngfwv1.ValidationFinding{}, findings...),
		RenderPlan: renderPlan(artifacts),
	}
	resp.Findings = append(resp.Findings, impactFindings(impact)...)
	return resp
}

func validationErrorFindings(errors []string) []*openngfwv1.ValidationFinding {
	findings := make([]*openngfwv1.ValidationFinding, 0, len(errors))
	for _, msg := range errors {
		findings = append(findings, &openngfwv1.ValidationFinding{
			Severity: openngfwv1.ValidationSeverity_VALIDATION_SEVERITY_ERROR,
			Stage:    openngfwv1.ValidationStage_VALIDATION_STAGE_POLICY_MODEL,
			Code:     "POLICY_VALIDATION_ERROR",
			Message:  msg,
		})
	}
	return findings
}

const ruleOverlapFindingCap = 25

type ruleOverlapDetailEnvelope struct {
	Text      string                       `json:"text"`
	Peer      ruleOverlapPeerMetadata      `json:"peer"`
	Dimension []ruleOverlapDimensionResult `json:"dimensions"`
	Result    ruleOverlapResultMetadata    `json:"result"`
	Page      ruleOverlapPageMetadata      `json:"page"`
}

type ruleOverlapPeerMetadata struct {
	Index  int    `json:"index"`
	ID     string `json:"id,omitempty"`
	Name   string `json:"name"`
	Action string `json:"action,omitempty"`
}

type ruleOverlapDimensionResult struct {
	Key        string   `json:"key"`
	Label      string   `json:"label"`
	PeerValues []string `json:"peerValues,omitempty"`
	RuleValues []string `json:"ruleValues,omitempty"`
	Result     string   `json:"result"`
	Sample     string   `json:"sample,omitempty"`
}

type ruleOverlapResultMetadata struct {
	ID          string   `json:"id"`
	Index       int      `json:"index"`
	RuleIndex   int      `json:"ruleIndex"`
	RuleID      string   `json:"ruleId,omitempty"`
	RuleName    string   `json:"ruleName"`
	RuleAction  string   `json:"ruleAction,omitempty"`
	PeerIndex   int      `json:"peerIndex"`
	PeerID      string   `json:"peerId,omitempty"`
	PeerName    string   `json:"peerName"`
	PeerAction  string   `json:"peerAction,omitempty"`
	Outcome     string   `json:"outcome"`
	RiskLabels  []string `json:"riskLabels,omitempty"`
	FieldPath   string   `json:"fieldPath"`
	IdentityKey string   `json:"identityKey"`
}

type ruleOverlapPageMetadata struct {
	Offset       int    `json:"offset"`
	Limit        int    `json:"limit"`
	ResultIndex  int    `json:"resultIndex"`
	ResultCount  int    `json:"resultCount"`
	TotalResults int    `json:"totalResults"`
	Truncated    bool   `json:"truncated"`
	HasMore      bool   `json:"hasMore"`
	NextOffset   int    `json:"nextOffset,omitempty"`
	PageKey      string `json:"pageKey"`
}

type ruleOverlapPair struct {
	earlierIndex int
	laterIndex   int
	earlier      *openngfwv1.Rule
	later        *openngfwv1.Rule
}

func annotateRuleOverlapFindings(cand *openngfwv1.Policy, findings []*openngfwv1.ValidationFinding) {
	pairs := ruleOverlapPairs(cand.GetRules())
	if len(pairs) == 0 {
		return
	}
	resultCount := len(pairs)
	if resultCount > ruleOverlapFindingCap {
		resultCount = ruleOverlapFindingCap
	}
	nextPair := 0
	for _, finding := range findings {
		if finding.GetCode() != "POLICY_HYGIENE_RULE_OVERLAP" {
			continue
		}
		laterIndex, ok := ruleIndexFromFieldPath(finding.GetFieldPath())
		if !ok {
			continue
		}
		pairIndex := -1
		for i := nextPair; i < len(pairs) && i < ruleOverlapFindingCap; i++ {
			if pairs[i].laterIndex == laterIndex {
				pairIndex = i
				nextPair = i + 1
				break
			}
		}
		if pairIndex < 0 {
			continue
		}
		envelope := ruleOverlapDetail(pairs[pairIndex], pairIndex, resultCount, len(pairs), finding.GetFieldPath(), finding.GetDetail())
		encoded, err := json.Marshal(envelope)
		if err != nil {
			continue
		}
		finding.Detail = string(encoded)
	}
}

func ruleOverlapDetail(pair ruleOverlapPair, pairIndex, resultCount, totalResults int, fieldPath, fallback string) ruleOverlapDetailEnvelope {
	peerName := displayRuleName(pair.earlier, pair.earlierIndex)
	ruleName := displayRuleName(pair.later, pair.laterIndex)
	text := strings.TrimSpace(fallback)
	if text == "" {
		text = fmt.Sprintf("%s and %s can match some of the same traffic; first-match rule order decides the verdict.", peerName, ruleName)
	}
	identityKey := fmt.Sprintf("rules[%d]:peer[%d]:%s:%s", pair.laterIndex, pair.earlierIndex, pair.later.GetId(), pair.earlier.GetId())
	return ruleOverlapDetailEnvelope{
		Text: text,
		Peer: ruleOverlapPeerMetadata{
			Index:  pair.earlierIndex,
			ID:     pair.earlier.GetId(),
			Name:   peerName,
			Action: pair.earlier.GetAction().String(),
		},
		Dimension: ruleOverlapDimensions(pair.earlier, pair.later),
		Result: ruleOverlapResultMetadata{
			ID:          fmt.Sprintf("overlap-%03d-r%d-p%d", pairIndex+1, pair.laterIndex, pair.earlierIndex),
			Index:       pairIndex,
			RuleIndex:   pair.laterIndex,
			RuleID:      pair.later.GetId(),
			RuleName:    ruleName,
			RuleAction:  pair.later.GetAction().String(),
			PeerIndex:   pair.earlierIndex,
			PeerID:      pair.earlier.GetId(),
			PeerName:    peerName,
			PeerAction:  pair.earlier.GetAction().String(),
			Outcome:     "first-match-order-review",
			RiskLabels:  overlapRiskLabels(pair.earlier, pair.later),
			FieldPath:   fieldPath,
			IdentityKey: identityKey,
		},
		Page: ruleOverlapPageMetadata{
			Offset:       0,
			Limit:        ruleOverlapFindingCap,
			ResultIndex:  pairIndex,
			ResultCount:  resultCount,
			TotalResults: totalResults,
			Truncated:    totalResults > ruleOverlapFindingCap,
			HasMore:      totalResults > ruleOverlapFindingCap,
			NextOffset:   nextOverlapOffset(totalResults),
			PageKey:      "policy-hygiene-rule-overlap:v1",
		},
	}
}

func nextOverlapOffset(totalResults int) int {
	if totalResults <= ruleOverlapFindingCap {
		return 0
	}
	return ruleOverlapFindingCap
}

func ruleOverlapPairs(rules []*openngfwv1.Rule) []ruleOverlapPair {
	var out []ruleOverlapPair
	for i, earlier := range rules {
		if !apiRuleActive(earlier) {
			continue
		}
		for j := i + 1; j < len(rules); j++ {
			later := rules[j]
			if !apiRuleActive(later) || !apiRulesPartiallyOverlap(earlier, later) {
				continue
			}
			out = append(out, ruleOverlapPair{earlierIndex: i, laterIndex: j, earlier: earlier, later: later})
		}
	}
	return out
}

func ruleOverlapDimensions(earlier, later *openngfwv1.Rule) []ruleOverlapDimensionResult {
	dims := []struct {
		key, label string
		peer, rule []string
	}{
		{"from-zones", "From zones", earlier.GetFromZones(), later.GetFromZones()},
		{"to-zones", "To zones", earlier.GetToZones(), later.GetToZones()},
		{"source-addresses", "Source addresses", earlier.GetSourceAddresses(), later.GetSourceAddresses()},
		{"destination-addresses", "Destination addresses", earlier.GetDestinationAddresses(), later.GetDestinationAddresses()},
		{"services", "Services", earlier.GetServices(), later.GetServices()},
		{"applications", "Applications", earlier.GetApplications(), later.GetApplications()},
	}
	out := make([]ruleOverlapDimensionResult, 0, len(dims))
	for _, dim := range dims {
		if dim.key == "applications" && len(nonAnyValues(dim.peer)) == 0 && len(nonAnyValues(dim.rule)) == 0 {
			continue
		}
		result := "overlap"
		if apiCoversDim(dim.peer, dim.rule) {
			result = "peer-covers-rule"
		} else if apiCoversDim(dim.rule, dim.peer) {
			result = "rule-covers-peer"
		}
		out = append(out, ruleOverlapDimensionResult{
			Key:        dim.key,
			Label:      dim.label,
			PeerValues: copiedValues(dim.peer),
			RuleValues: copiedValues(dim.rule),
			Result:     result,
			Sample:     overlapSample(dim.peer, dim.rule),
		})
	}
	return out
}

func overlapRiskLabels(earlier, later *openngfwv1.Rule) []string {
	var labels []string
	if apiRuleAllows(earlier) && apiRuleBlocks(later) {
		labels = append(labels, "allow-before-deny")
	}
	if apiRuleBlocks(earlier) && apiRuleAllows(later) {
		labels = append(labels, "deny-before-allow")
	}
	if earlier.GetAction() != openngfwv1.Action_ACTION_UNSPECIFIED && earlier.GetAction() == later.GetAction() {
		labels = append(labels, "same-action")
	}
	if !earlier.GetLog() || !later.GetLog() {
		labels = append(labels, "log-gap")
	}
	if !proto.Equal(&openngfwv1.Policy{Rules: []*openngfwv1.Rule{{SecurityProfiles: earlier.GetSecurityProfiles()}}},
		&openngfwv1.Policy{Rules: []*openngfwv1.Rule{{SecurityProfiles: later.GetSecurityProfiles()}}}) {
		labels = append(labels, "profile-mismatch")
	}
	if !proto.Equal(&openngfwv1.Policy{Rules: []*openngfwv1.Rule{{Applications: earlier.GetApplications()}}},
		&openngfwv1.Policy{Rules: []*openngfwv1.Rule{{Applications: later.GetApplications()}}}) {
		labels = append(labels, "app-id-mismatch")
	}
	if len(labels) == 0 {
		labels = append(labels, "order-review")
	}
	return labels
}

func ruleIndexFromFieldPath(fieldPath string) (int, bool) {
	var idx int
	if _, err := fmt.Sscanf(fieldPath, "rules[%d]", &idx); err != nil {
		return 0, false
	}
	return idx, idx >= 0
}

func displayRuleName(rule *openngfwv1.Rule, index int) string {
	if rule.GetName() != "" {
		return rule.GetName()
	}
	return fmt.Sprintf("rule #%d", index+1)
}

func apiRuleActive(rule *openngfwv1.Rule) bool { return rule != nil && !rule.GetDisabled() }
func apiRuleAllows(rule *openngfwv1.Rule) bool {
	return rule != nil && rule.GetAction() == openngfwv1.Action_ACTION_ALLOW
}
func apiRuleBlocks(rule *openngfwv1.Rule) bool {
	return rule != nil && (rule.GetAction() == openngfwv1.Action_ACTION_DENY || rule.GetAction() == openngfwv1.Action_ACTION_REJECT)
}

func apiRulesPartiallyOverlap(a, b *openngfwv1.Rule) bool {
	if a == nil || b == nil {
		return false
	}
	if apiRuleCovers(a, b) || apiRuleCovers(b, a) {
		return false
	}
	return apiDimsOverlap(a.GetFromZones(), b.GetFromZones()) &&
		apiDimsOverlap(a.GetToZones(), b.GetToZones()) &&
		apiDimsOverlap(a.GetSourceAddresses(), b.GetSourceAddresses()) &&
		apiDimsOverlap(a.GetDestinationAddresses(), b.GetDestinationAddresses()) &&
		apiDimsOverlap(a.GetServices(), b.GetServices()) &&
		apiDimsOverlap(a.GetApplications(), b.GetApplications())
}

func apiRuleCovers(a, b *openngfwv1.Rule) bool {
	return apiCoversDim(a.GetFromZones(), b.GetFromZones()) &&
		apiCoversDim(a.GetToZones(), b.GetToZones()) &&
		apiCoversDim(a.GetSourceAddresses(), b.GetSourceAddresses()) &&
		apiCoversDim(a.GetDestinationAddresses(), b.GetDestinationAddresses()) &&
		apiCoversDim(a.GetServices(), b.GetServices()) &&
		apiCoversDim(a.GetApplications(), b.GetApplications())
}

func apiCoversDim(a, b []string) bool {
	if apiAnyToken(a) {
		return true
	}
	if apiAnyToken(b) {
		return false
	}
	seen := map[string]bool{}
	for _, x := range a {
		seen[x] = true
	}
	for _, x := range b {
		if !seen[x] {
			return false
		}
	}
	return true
}

func apiDimsOverlap(a, b []string) bool {
	if apiAnyToken(a) || apiAnyToken(b) {
		return true
	}
	seen := map[string]bool{}
	for _, x := range a {
		seen[x] = true
	}
	for _, x := range b {
		if seen[x] {
			return true
		}
	}
	return false
}

func apiAnyToken(xs []string) bool {
	if len(xs) == 0 {
		return true
	}
	for _, x := range xs {
		if x == policy.Any {
			return true
		}
	}
	return false
}

func copiedValues(xs []string) []string {
	if len(xs) == 0 {
		return []string{policy.Any}
	}
	return append([]string{}, xs...)
}

func nonAnyValues(xs []string) []string {
	var out []string
	for _, x := range xs {
		if x != "" && x != policy.Any {
			out = append(out, x)
		}
	}
	return out
}

func overlapSample(a, b []string) string {
	if apiAnyToken(a) && apiAnyToken(b) {
		return policy.Any
	}
	if apiAnyToken(a) {
		return firstNonEmptyPolicyValue(b)
	}
	if apiAnyToken(b) {
		return firstNonEmptyPolicyValue(a)
	}
	seen := map[string]bool{}
	for _, x := range a {
		seen[x] = true
	}
	for _, x := range b {
		if seen[x] {
			return x
		}
	}
	return "partial"
}

func firstNonEmptyPolicyValue(xs []string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return policy.Any
}

func impactFindings(impact *openngfwv1.ChangeImpact) []*openngfwv1.ValidationFinding {
	if impact == nil {
		return nil
	}
	var findings []*openngfwv1.ValidationFinding
	for _, item := range impact.GetItems() {
		if item.GetTitle() == "No material policy risk detected" {
			continue
		}
		severity := openngfwv1.ValidationSeverity_VALIDATION_SEVERITY_INFO
		if item.GetRisk() == openngfwv1.ChangeRisk_CHANGE_RISK_HIGH || item.GetRisk() == openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM {
			severity = openngfwv1.ValidationSeverity_VALIDATION_SEVERITY_WARNING
		}
		findings = append(findings, &openngfwv1.ValidationFinding{
			Severity: severity,
			Stage:    openngfwv1.ValidationStage_VALIDATION_STAGE_IMPACT,
			Code:     "POLICY_IMPACT_" + strings.ToUpper(riskCodeSuffix(item.GetRisk())),
			Message:  item.GetTitle(),
			Detail:   item.GetDetail(),
		})
	}
	return findings
}

func riskCodeSuffix(risk openngfwv1.ChangeRisk) string {
	switch risk {
	case openngfwv1.ChangeRisk_CHANGE_RISK_HIGH:
		return "high"
	case openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM:
		return "medium"
	case openngfwv1.ChangeRisk_CHANGE_RISK_LOW:
		return "low"
	default:
		return "unspecified"
	}
}

func renderPlan(artifacts map[string][]byte) *openngfwv1.RenderPlan {
	if len(artifacts) == 0 {
		return nil
	}
	keys := make([]string, 0, len(artifacts))
	for key := range artifacts {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	plan := &openngfwv1.RenderPlan{ArtifactCount: uint32(len(keys))}
	for _, key := range keys {
		size := uint64(len(artifacts[key]))
		plan.TotalBytes += size
		plan.Artifacts = append(plan.Artifacts, &openngfwv1.RenderArtifact{
			Engine:    key,
			Name:      key,
			SizeBytes: size,
		})
	}
	return plan
}

// Commit validates the candidate, records a durable apply intent, applies
// runtime engines, then activates the prepared version.
func (s *PolicyServer) Commit(ctx context.Context, req *openngfwv1.CommitRequest) (*openngfwv1.CommitResponse, error) {
	if req == nil {
		req = &openngfwv1.CommitRequest{}
	}
	if err := authz.RequireStepUp(ctx, "commit", req.GetStepUpToken()); err != nil {
		return nil, err
	}
	comment, err := requiredAuditComment(req.GetComment(), "commit comment")
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cand, ok, err := s.store.GetCandidate()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read candidate: %v", err)
	}
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "no candidate policy is set; nothing to commit")
	}
	candidateRevision, err := s.store.CandidateRevision()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read candidate revision: %v", err)
	}
	reviewedRevision := strings.TrimSpace(req.GetReviewedCandidateRevision())
	if reviewedRevision == "" {
		return nil, status.Error(codes.InvalidArgument, "reviewed_candidate_revision is required; reload candidate status, review validation/diff/runtime readiness, then commit the reviewed revision")
	}
	if reviewedRevision != candidateRevision {
		return nil, status.Error(codes.FailedPrecondition, "candidate changed since commit review; reload candidate status, review the current diff, and approve the new candidate revision before committing")
	}

	id, previousVersion, info, err := s.apply(ctx, cand, "commit", comment, req.GetAckRisk(), req.GetAckRuntime(), 0, strings.TrimSpace(req.GetApprovalId()), candidateRevision)
	if err != nil {
		return nil, err
	}
	return &openngfwv1.CommitResponse{Version: id, PreviousVersion: previousVersion, VersionInfo: versionInfoProto(info)}, nil
}

// Rollback re-applies a historical version as a new commit.
func (s *PolicyServer) Rollback(ctx context.Context, req *openngfwv1.RollbackRequest) (*openngfwv1.RollbackResponse, error) {
	if req == nil {
		req = &openngfwv1.RollbackRequest{}
	}
	if err := authz.RequireStepUp(ctx, "rollback", req.GetStepUpToken()); err != nil {
		return nil, err
	}
	comment, err := requiredAuditComment(req.GetComment(), "rollback audit comment")
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	target, err := s.store.GetVersion(req.GetVersion())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}
	id, previousVersion, info, err := s.apply(ctx, target, "rollback", comment, req.GetAckRisk(), req.GetAckRuntime(), req.GetVersion(), "", "")
	if err != nil {
		return nil, err
	}
	return &openngfwv1.RollbackResponse{Version: id, PreviousVersion: previousVersion, VersionInfo: versionInfoProto(info)}, nil
}

// ApplyReplicatedPolicy validates and applies a policy pulled from an HA peer
// through the same durable apply path used by commit and rollback.
func (s *PolicyServer) ApplyReplicatedPolicy(ctx context.Context, p *openngfwv1.Policy, comment string, ackRisk, ackRuntime bool, sourceVersion uint64) (uint64, uint64, store.VersionInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	running, runningVersion, err := s.store.GetRunning()
	if err != nil {
		return 0, 0, store.VersionInfo{}, status.Errorf(codes.Internal, "read running policy before HA policy pull: %v", err)
	}
	if candidate, ok, err := s.store.GetCandidate(); err != nil {
		return 0, 0, store.VersionInfo{}, status.Errorf(codes.Internal, "read candidate policy before HA policy pull: %v", err)
	} else if ok && !proto.Equal(candidate, running) {
		return 0, 0, store.VersionInfo{}, status.Error(codes.FailedPrecondition, "local candidate has staged changes; discard or commit them before HA policy pull")
	}
	if sourceVersion != 0 && sourceVersion <= runningVersion {
		return 0, 0, store.VersionInfo{}, status.Errorf(codes.FailedPrecondition, "HA peer policy version v%d is not newer than current local running version v%d", sourceVersion, runningVersion)
	}
	return s.apply(ctx, p, "ha-policy-pull", comment, ackRisk, ackRuntime, sourceVersion, "", "")
}

func requiredAuditComment(comment, label string) (string, error) {
	comment = strings.TrimSpace(comment)
	if comment == "" {
		return "", status.Errorf(codes.InvalidArgument, "%s is required", label)
	}
	return comment, nil
}

// apply is the shared commit path. Runtime engines are never touched until the
// target version and audit intent have committed to the durable store. The
// remaining two-phase risk is after engine apply succeeds: activation can still
// fail, leaving engines on the prepared version while the running pointer is
// stale. In that case the prepared version and intent audit remain durable
// reconciliation breadcrumbs, and a failure audit is attempted best-effort.
func (s *PolicyServer) apply(ctx context.Context, p *openngfwv1.Policy, action, comment string, ackRisk, ackRuntime bool, sourceVersion uint64, approvalID, candidateRevision string) (uint64, uint64, store.VersionInfo, error) {
	identity := auditIdentity(ctx)
	p, _ = policy.NormalizeRuleIDs(p)
	fail := func(stage string, version uint64, err error) (uint64, uint64, store.VersionInfo, error) {
		if version != 0 && stage == "apply" {
			_ = s.store.MarkVersionState(version, "apply_failed", err.Error())
		}
		if version != 0 && strings.HasPrefix(stage, "activate") {
			_ = s.store.MarkVersionState(version, "activation_failed", err.Error())
		}
		_ = s.store.AppendAudit(store.AuditEntry{
			Actor:      identity.Name,
			ActorRole:  identity.Role,
			AuthSource: identity.AuthSource,
			Action:     action + "-failed",
			Detail:     fmt.Sprintf("%s: %v", stage, err),
			Version:    version,
		})
		return 0, 0, store.VersionInfo{}, status.Errorf(codes.FailedPrecondition, "%s failed at %s: %v", action, stage, err)
	}

	if errs := policy.Validate(p); len(errs) > 0 {
		return fail("validation", 0, fmt.Errorf("%s", strings.Join(errs, "; ")))
	}
	artifacts, err := s.render(p)
	if err != nil {
		return fail("render", 0, err)
	}
	if err := s.sup.Validate(ctx, artifacts); err != nil {
		return fail("engine validation", 0, err)
	}

	prevPolicy, prevVersion, err := s.store.GetRunning()
	if err != nil {
		return fail("read running", 0, err)
	}
	if err := requireHighRiskAcknowledgement(action, policy.Impact(prevPolicy, p), ackRisk); err != nil {
		return fail("risk acknowledgement", 0, err)
	}
	if err := requireRuntimeAcknowledgement(ctx, action, s.RuntimeReadiness, p, prevPolicy, ackRuntime); err != nil {
		return fail("runtime acknowledgement", 0, err)
	}
	prevArtifacts, err := s.render(prevPolicy)
	if err != nil {
		return fail("render previous", 0, err)
	}
	if action == "commit" && strings.TrimSpace(approvalID) == "" {
		return fail("approval", 0, fmt.Errorf("change approval is required before commit"))
	}

	id, err := s.store.PreparePolicyApplyWithIdentityAndApproval(p, identity, action, comment, versionArtifacts(artifacts), sourceVersion, approvalID, candidateRevision)
	if action == "commit" {
		if errors.Is(err, store.ErrChangeApprovalNotFound) {
			return fail("approval", 0, fmt.Errorf("change approval %q was not found", approvalID))
		}
		if errors.Is(err, store.ErrChangeApprovalConsumed) {
			return fail("approval", 0, fmt.Errorf("change approval %q has already been consumed", approvalID))
		}
		if errors.Is(err, store.ErrChangeApprovalRevisionMismatch) {
			return fail("approval", 0, fmt.Errorf("change approval %q does not match the current candidate revision", approvalID))
		}
	}
	if err != nil {
		return fail("record intent", 0, err)
	}

	if err := s.sup.Apply(ctx, artifacts, prevArtifacts); err != nil {
		return fail("apply", id, fmt.Errorf("%w; prepared version %d left inactive; running remains previous version %d", err, id, prevVersion))
	}

	if err := s.store.ActivatePreparedVersion(id, identity, action, comment); err != nil {
		_, _, _, _ = fail("activate prepared version after engine apply", id, fmt.Errorf("%w; engines may be running prepared version %d while store running pointer remains previous version %d", err, id, prevVersion))
		return 0, 0, store.VersionInfo{}, status.Errorf(codes.Internal, "%s applied engines for prepared version %d but failed to activate the running store record: %v", action, id, err)
	}
	if s.OnCommit != nil {
		s.OnCommit()
	}
	info, err := s.store.GetVersionInfo(id)
	if err != nil {
		return 0, 0, store.VersionInfo{}, status.Errorf(codes.Internal, "read activated version metadata: %v", err)
	}
	return id, prevVersion, info, nil
}

func requireRuntimeAcknowledgement(ctx context.Context, action string, check RuntimeReadinessCheck, target, running *openngfwv1.Policy, ackRuntime bool) error {
	if check == nil {
		return nil
	}
	items, err := check(ctx, target, running)
	if err != nil {
		if ackRuntime {
			return nil
		}
		return fmt.Errorf("runtime readiness status unavailable requires ack_runtime before %s: %v", action, err)
	}
	if len(items) == 0 || ackRuntime {
		return nil
	}
	return fmt.Errorf("runtime readiness warnings require ack_runtime before %s: %s", action, strings.Join(items, "; "))
}

func requireHighRiskAcknowledgement(action string, impact *openngfwv1.ChangeImpact, ackRisk bool) error {
	if impact == nil || impact.GetRisk() != openngfwv1.ChangeRisk_CHANGE_RISK_HIGH || ackRisk {
		return nil
	}
	switch action {
	case "rollback":
		return fmt.Errorf("high-risk rollback impact requires ack_risk before rollback")
	default:
		return fmt.Errorf("high-risk policy impact requires ack_risk before commit")
	}
}

// ListVersions returns committed version metadata, newest first.
func (s *PolicyServer) ListVersions(_ context.Context, req *openngfwv1.ListVersionsRequest) (*openngfwv1.ListVersionsResponse, error) {
	infos, err := s.store.ListVersions(int(req.GetLimit()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	resp := &openngfwv1.ListVersionsResponse{}
	for _, vi := range infos {
		resp.Versions = append(resp.Versions, versionInfoProto(vi))
	}
	return resp, nil
}

func versionInfoProto(vi store.VersionInfo) *openngfwv1.VersionInfo {
	info := &openngfwv1.VersionInfo{
		Id:                vi.ID,
		Actor:             vi.Actor,
		Comment:           vi.Comment,
		ActorRole:         vi.ActorRole,
		AuthSource:        vi.AuthSource,
		Action:            vi.Action,
		SourceVersion:     vi.SourceVersion,
		State:             vi.State,
		ArtifactSetSha256: vi.ArtifactSetSHA256,
		LastKnownGood:     vi.LastKnownGood,
		StateDetail:       vi.StateDetail,
	}
	if !vi.CreatedAt.IsZero() {
		info.CreatedAt = timestamppb.New(vi.CreatedAt)
	}
	if !vi.ActivatedAt.IsZero() {
		info.ActivatedAt = timestamppb.New(vi.ActivatedAt)
	}
	for _, artifact := range vi.Artifacts {
		info.Artifacts = append(info.Artifacts, &openngfwv1.VersionArtifact{
			Engine:    artifact.Engine,
			Name:      artifact.Name,
			SizeBytes: artifact.SizeBytes,
			Sha256:    artifact.SHA256,
		})
	}
	return info
}

func changeApprovalProto(approval store.ChangeApproval) *openngfwv1.ChangeApproval {
	out := &openngfwv1.ChangeApproval{
		Id:                   approval.ID,
		CandidateRevision:    approval.CandidateRevision,
		Actor:                approval.Actor,
		ActorRole:            approval.ActorRole,
		AuthSource:           approval.AuthSource,
		Comment:              approval.Comment,
		AckRisk:              approval.AckRisk,
		AckRuntime:           approval.AckRuntime,
		Consumed:             approval.Consumed,
		ConsumedVersion:      approval.ConsumedVersion,
		ConsumedBy:           approval.ConsumedBy,
		ConsumedByRole:       approval.ConsumedByRole,
		ConsumedByAuthSource: approval.ConsumedByAuthSource,
	}
	if !approval.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(approval.CreatedAt)
	}
	if !approval.ConsumedAt.IsZero() {
		out.ConsumedAt = timestamppb.New(approval.ConsumedAt)
	}
	return out
}

func versionArtifacts(artifacts map[string][]byte) []store.VersionArtifact {
	if len(artifacts) == 0 {
		return nil
	}
	keys := make([]string, 0, len(artifacts))
	for key := range artifacts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]store.VersionArtifact, 0, len(keys))
	for _, key := range keys {
		sum := sha256.Sum256(artifacts[key])
		out = append(out, store.VersionArtifact{
			Engine:    key,
			Name:      key,
			SizeBytes: uint64(len(artifacts[key])),
			SHA256:    fmt.Sprintf("%x", sum[:]),
		})
	}
	return out
}

// ListAuditEntries returns the audit log, newest first.
func (s *PolicyServer) ListAuditEntries(_ context.Context, req *openngfwv1.ListAuditEntriesRequest) (*openngfwv1.ListAuditEntriesResponse, error) {
	since, err := optionalTimestamp(req.GetSince(), "since")
	if err != nil {
		return nil, err
	}
	until, err := optionalTimestamp(req.GetUntil(), "until")
	if err != nil {
		return nil, err
	}
	if !since.IsZero() && !until.IsZero() && since.After(until) {
		return nil, status.Error(codes.InvalidArgument, "since must be at or before until")
	}
	entries, err := s.store.ListAuditFiltered(store.AuditFilter{
		Limit:   int(req.GetLimit()),
		Actor:   req.GetActor(),
		Action:  req.GetAction(),
		Version: req.GetVersion(),
		Since:   since,
		Until:   until,
		Query:   req.GetQuery(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	resp := &openngfwv1.ListAuditEntriesResponse{}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, &openngfwv1.AuditEntry{
			Id: e.ID, Time: timestamppb.New(e.Time), Actor: e.Actor,
			ActorRole: e.ActorRole, AuthSource: e.AuthSource,
			Action: e.Action, Detail: e.Detail, Version: e.Version,
			PreviousHash: e.PreviousHash, EntryHash: e.EntryHash,
		})
	}
	return resp, nil
}

// VerifyAuditIntegrity validates the tamper-evident audit hash chain.
func (s *PolicyServer) VerifyAuditIntegrity(_ context.Context, _ *openngfwv1.VerifyAuditIntegrityRequest) (*openngfwv1.VerifyAuditIntegrityResponse, error) {
	report, err := s.store.AuditIntegrity()
	resp := &openngfwv1.VerifyAuditIntegrityResponse{
		Ok:              err == nil,
		EntryCount:      uint32(report.EntryCount),
		LatestEntryHash: report.LatestEntryHash,
		CheckedAt:       timestamppb.Now(),
	}
	if err != nil {
		resp.Detail = err.Error()
	} else if report.EntryCount == 0 {
		resp.Detail = "audit log is empty"
	} else {
		resp.Detail = "audit hash chain verified"
	}
	return resp, nil
}

func optionalTimestamp(ts *timestamppb.Timestamp, field string) (time.Time, error) {
	if ts == nil {
		return time.Time{}, nil
	}
	if err := ts.CheckValid(); err != nil {
		return time.Time{}, status.Errorf(codes.InvalidArgument, "%s timestamp is invalid: %v", field, err)
	}
	return ts.AsTime(), nil
}
