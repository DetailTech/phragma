package apiserver

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/authz"
	"github.com/detailtech/oss-ngfw/internal/engines"
	"github.com/detailtech/oss-ngfw/internal/policy"
	"github.com/detailtech/oss-ngfw/internal/store"
)

// Pipeline renders a policy into per-engine artifacts.
type Pipeline func(*openngfwv1.Policy) (map[string][]byte, error)

// PolicyServer implements openngfw.v1.PolicyService over the store and
// engine supervisor. All mutations are serialized; the commit path is
// candidate → validate → render → engine-validate → apply → record.
type PolicyServer struct {
	openngfwv1.UnimplementedPolicyServiceServer

	store  *store.Store
	sup    *engines.Supervisor
	render Pipeline

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

// actor identifies the caller for audit purposes: the authenticated
// user when auth is enabled, "local" otherwise.
func actor(ctx context.Context) string { return authz.Actor(ctx) }

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

// SetCandidate replaces the candidate policy without applying it.
func (s *PolicyServer) SetCandidate(ctx context.Context, req *openngfwv1.SetCandidateRequest) (*openngfwv1.SetCandidateResponse, error) {
	if req.GetPolicy() == nil {
		return nil, status.Error(codes.InvalidArgument, "policy is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store.SetCandidate(req.GetPolicy()); err != nil {
		return nil, status.Errorf(codes.Internal, "store candidate: %v", err)
	}
	if err := s.store.AppendAudit(store.AuditEntry{
		Actor: actor(ctx), Action: "set-candidate",
		Detail: fmt.Sprintf("%d zones, %d rules", len(req.GetPolicy().GetZones()), len(req.GetPolicy().GetRules())),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit: %v", err)
	}
	return &openngfwv1.SetCandidateResponse{}, nil
}

// Validate checks the candidate end-to-end without touching engines.
func (s *PolicyServer) Validate(ctx context.Context, _ *openngfwv1.ValidateRequest) (*openngfwv1.ValidateResponse, error) {
	cand, ok, err := s.store.GetCandidate()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read candidate: %v", err)
	}
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "no candidate policy is set")
	}
	if errs := policy.Validate(cand); len(errs) > 0 {
		return &openngfwv1.ValidateResponse{Valid: false, Errors: errs}, nil
	}
	// Renderability + engine syntax checks, still without touching state.
	artifacts, err := s.render(cand)
	if err != nil {
		return &openngfwv1.ValidateResponse{Valid: false, Errors: []string{err.Error()}}, nil
	}
	if err := s.sup.Validate(ctx, artifacts); err != nil {
		return &openngfwv1.ValidateResponse{Valid: false, Errors: []string{err.Error()}}, nil
	}
	return &openngfwv1.ValidateResponse{Valid: true}, nil
}

// Commit applies the candidate atomically and records a version.
func (s *PolicyServer) Commit(ctx context.Context, req *openngfwv1.CommitRequest) (*openngfwv1.CommitResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cand, ok, err := s.store.GetCandidate()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read candidate: %v", err)
	}
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "no candidate policy is set; nothing to commit")
	}

	id, err := s.apply(ctx, cand, "commit", req.GetComment())
	if err != nil {
		return nil, err
	}
	return &openngfwv1.CommitResponse{Version: id}, nil
}

// Rollback re-applies a historical version as a new commit.
func (s *PolicyServer) Rollback(ctx context.Context, req *openngfwv1.RollbackRequest) (*openngfwv1.RollbackResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	target, err := s.store.GetVersion(req.GetVersion())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}
	id, err := s.apply(ctx, target, "rollback", fmt.Sprintf("rollback to version %d", req.GetVersion()))
	if err != nil {
		return nil, err
	}
	return &openngfwv1.RollbackResponse{Version: id}, nil
}

// apply is the shared commit path. Every failure is audited and
// returned; nothing in this path fails silently.
func (s *PolicyServer) apply(ctx context.Context, p *openngfwv1.Policy, action, comment string) (uint64, error) {
	fail := func(stage string, err error) (uint64, error) {
		_ = s.store.AppendAudit(store.AuditEntry{
			Actor: actor(ctx), Action: action + "-failed",
			Detail: fmt.Sprintf("%s: %v", stage, err),
		})
		return 0, status.Errorf(codes.FailedPrecondition, "%s failed at %s: %v", action, stage, err)
	}

	if errs := policy.Validate(p); len(errs) > 0 {
		return fail("validation", fmt.Errorf("%s", strings.Join(errs, "; ")))
	}
	artifacts, err := s.render(p)
	if err != nil {
		return fail("render", err)
	}
	if err := s.sup.Validate(ctx, artifacts); err != nil {
		return fail("engine validation", err)
	}

	prevPolicy, _, err := s.store.GetRunning()
	if err != nil {
		return fail("read running", err)
	}
	prevArtifacts, err := s.render(prevPolicy)
	if err != nil {
		return fail("render previous", err)
	}

	if err := s.sup.Apply(ctx, artifacts, prevArtifacts); err != nil {
		return fail("apply", err)
	}

	id, err := s.store.CommitVersion(p, actor(ctx), comment)
	if err != nil {
		// Engines now run a config the store failed to record. Surface
		// loudly; the operator must re-commit or roll back by hand.
		return fail("record version (ENGINES UPDATED, STORE WRITE FAILED)", err)
	}
	if err := s.store.AppendAudit(store.AuditEntry{
		Actor: actor(ctx), Action: action, Detail: comment, Version: id,
	}); err != nil {
		return 0, status.Errorf(codes.Internal, "committed version %d but audit write failed: %v", id, err)
	}
	if s.OnCommit != nil {
		s.OnCommit()
	}
	return id, nil
}

// ListVersions returns committed version metadata, newest first.
func (s *PolicyServer) ListVersions(_ context.Context, req *openngfwv1.ListVersionsRequest) (*openngfwv1.ListVersionsResponse, error) {
	infos, err := s.store.ListVersions(int(req.GetLimit()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	resp := &openngfwv1.ListVersionsResponse{}
	for _, vi := range infos {
		resp.Versions = append(resp.Versions, &openngfwv1.VersionInfo{
			Id: vi.ID, CreatedAt: timestamppb.New(vi.CreatedAt), Actor: vi.Actor, Comment: vi.Comment,
		})
	}
	return resp, nil
}

// ListAuditEntries returns the audit log, newest first.
func (s *PolicyServer) ListAuditEntries(_ context.Context, req *openngfwv1.ListAuditEntriesRequest) (*openngfwv1.ListAuditEntriesResponse, error) {
	entries, err := s.store.ListAudit(int(req.GetLimit()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	resp := &openngfwv1.ListAuditEntriesResponse{}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, &openngfwv1.AuditEntry{
			Id: e.ID, Time: timestamppb.New(e.Time), Actor: e.Actor,
			Action: e.Action, Detail: e.Detail, Version: e.Version,
		})
	}
	return resp, nil
}
