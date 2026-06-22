package apiserver

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/store"
	"github.com/detailtech/oss-ngfw/internal/threatid"
)

var threatExceptionSHA256RE = regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)

// ListThreatExceptions returns the effective Threat-ID false-positive
// exception inventory without mutating policy state.
func (s *PolicyServer) ListThreatExceptions(ctx context.Context, req *openngfwv1.ListThreatExceptionsRequest) (*openngfwv1.ListThreatExceptionsResponse, error) {
	selected, source, version, err := s.threatExceptionPolicy(req.GetSource(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	running, _, err := s.store.GetRunning()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read running policy: %v", err)
	}
	records := threatExceptionRecords(selected.GetIds().GetExceptions(), running.GetIds().GetExceptions())
	statusResp, err := s.GetCandidateStatus(ctx, &openngfwv1.GetCandidateStatusRequest{})
	if err != nil {
		return nil, err
	}
	return &openngfwv1.ListThreatExceptionsResponse{
		Exceptions:      records,
		Source:          source,
		Version:         version,
		CandidateStatus: statusResp,
	}, nil
}

// StageThreatException stages one first-party Threat-ID false-positive
// exception into the candidate policy. It never applies engine state.
func (s *PolicyServer) StageThreatException(ctx context.Context, req *openngfwv1.StageThreatExceptionRequest) (*openngfwv1.StageThreatExceptionResponse, error) {
	reason := strings.TrimSpace(req.GetReason())
	if reason == "" {
		return nil, status.Error(codes.InvalidArgument, "reason is required")
	}
	sid, err := suricataSignatureID(req.GetEngineSignals())
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	candidate, err := s.stageThreatExceptionCandidate(req, sid, reason)
	if err != nil {
		return nil, err
	}
	validation, err := s.Validate(ctx, &openngfwv1.ValidateRequest{Policy: candidate.policy})
	if err != nil {
		return nil, err
	}
	if !validation.GetValid() {
		return &openngfwv1.StageThreatExceptionResponse{
			Exception:     candidate.exception,
			Address:       candidate.address,
			AddressReused: candidate.addressReused,
			Validation:    validation,
		}, nil
	}
	identity := auditIdentity(ctx)
	if err := s.store.SetCandidateWithAudit(candidate.policy, store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role,
		AuthSource: identity.AuthSource,
		Action:     "stage-threat-exception",
		Detail:     threatExceptionAuditDetail(candidate.exception, req.GetScope(), candidate.addressReused),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "store candidate with audit: %v", err)
	}

	statusResp, err := s.GetCandidateStatus(ctx, &openngfwv1.GetCandidateStatusRequest{})
	if err != nil {
		return nil, err
	}
	diff, err := s.DiffPolicy(ctx, &openngfwv1.DiffPolicyRequest{
		FromSource: openngfwv1.PolicySource_POLICY_SOURCE_RUNNING,
		ToSource:   openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE,
	})
	if err != nil {
		return nil, err
	}
	return &openngfwv1.StageThreatExceptionResponse{
		Exception:       candidate.exception,
		Address:         candidate.address,
		AddressReused:   candidate.addressReused,
		CandidateStatus: statusResp,
		Validation:      validation,
		Diff:            diff,
	}, nil
}

// UpdateThreatException stages a replacement for one existing exception. The
// replacement remains candidate-only until the normal commit path succeeds.
func (s *PolicyServer) UpdateThreatException(ctx context.Context, req *openngfwv1.UpdateThreatExceptionRequest) (*openngfwv1.UpdateThreatExceptionResponse, error) {
	reason, err := threatExceptionMutationReason(req.GetReason())
	if err != nil {
		return nil, err
	}
	replacement, err := normalizedThreatExceptionReplacement(req.GetName(), req.GetException(), reason)
	if err != nil {
		return nil, err
	}
	if isGlobalThreatException(replacement) && !replacement.GetDisabled() && !req.GetConfirmGlobal() {
		return nil, status.Error(codes.InvalidArgument, "confirm_global is required for active global threat exceptions")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	base, err := s.candidateOrRunningPolicy()
	if err != nil {
		return nil, err
	}
	if base.Ids == nil {
		base.Ids = &openngfwv1.Ids{}
	}
	idx, previous := findIDSExceptionByName(base.GetIds().GetExceptions(), req.GetName())
	if idx < 0 {
		return nil, status.Errorf(codes.NotFound, "threat exception %q not found", strings.TrimSpace(req.GetName()))
	}
	if replacement.GetName() != previous.GetName() && hasIDSExceptionName(base.GetIds().GetExceptions(), replacement.GetName()) {
		return nil, status.Errorf(codes.AlreadyExists, "threat exception %q already exists", replacement.GetName())
	}
	base.Ids.Exceptions[idx] = replacement

	result, err := s.storeThreatExceptionMutation(ctx, base, "update-threat-exception", threatExceptionLifecycleAuditDetail("update", previous, replacement, reason))
	if err != nil {
		return nil, err
	}
	return &openngfwv1.UpdateThreatExceptionResponse{
		Exception:         replacement,
		PreviousException: previous,
		CandidateStatus:   result.candidateStatus,
		Validation:        result.validation,
		Diff:              result.diff,
	}, nil
}

// SetThreatExceptionState stages an enable/disable lifecycle action.
func (s *PolicyServer) SetThreatExceptionState(ctx context.Context, req *openngfwv1.SetThreatExceptionStateRequest) (*openngfwv1.SetThreatExceptionStateResponse, error) {
	reason, err := threatExceptionMutationReason(req.GetReason())
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	base, err := s.candidateOrRunningPolicy()
	if err != nil {
		return nil, err
	}
	if base.Ids == nil {
		base.Ids = &openngfwv1.Ids{}
	}
	idx, previous := findIDSExceptionByName(base.GetIds().GetExceptions(), req.GetName())
	if idx < 0 {
		return nil, status.Errorf(codes.NotFound, "threat exception %q not found", strings.TrimSpace(req.GetName()))
	}
	updated := proto.Clone(previous).(*openngfwv1.IdsException)
	updated.Disabled = req.GetDisabled()
	if !updated.GetDisabled() && isGlobalThreatException(updated) && !req.GetConfirmGlobal() {
		return nil, status.Error(codes.InvalidArgument, "confirm_global is required to re-enable a global threat exception")
	}
	base.Ids.Exceptions[idx] = updated

	action := "enable"
	if updated.GetDisabled() {
		action = "disable"
	}
	result, err := s.storeThreatExceptionMutation(ctx, base, "set-threat-exception-state", threatExceptionLifecycleAuditDetail(action, previous, updated, reason))
	if err != nil {
		return nil, err
	}
	return &openngfwv1.SetThreatExceptionStateResponse{
		Exception:         updated,
		PreviousException: previous,
		CandidateStatus:   result.candidateStatus,
		Validation:        result.validation,
		Diff:              result.diff,
	}, nil
}

// RemoveThreatException stages removal of one exception from the candidate
// policy. The running suppression is unchanged until commit.
func (s *PolicyServer) RemoveThreatException(ctx context.Context, req *openngfwv1.RemoveThreatExceptionRequest) (*openngfwv1.RemoveThreatExceptionResponse, error) {
	reason, err := threatExceptionMutationReason(req.GetReason())
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	base, err := s.candidateOrRunningPolicy()
	if err != nil {
		return nil, err
	}
	if base.Ids == nil {
		base.Ids = &openngfwv1.Ids{}
	}
	idx, previous := findIDSExceptionByName(base.GetIds().GetExceptions(), req.GetName())
	if idx < 0 {
		return nil, status.Errorf(codes.NotFound, "threat exception %q not found", strings.TrimSpace(req.GetName()))
	}
	base.Ids.Exceptions = append(base.Ids.Exceptions[:idx], base.Ids.Exceptions[idx+1:]...)

	result, err := s.storeThreatExceptionMutation(ctx, base, "remove-threat-exception", threatExceptionLifecycleAuditDetail("remove", previous, nil, reason))
	if err != nil {
		return nil, err
	}
	return &openngfwv1.RemoveThreatExceptionResponse{
		PreviousException: previous,
		CandidateStatus:   result.candidateStatus,
		Validation:        result.validation,
		Diff:              result.diff,
	}, nil
}

// ReplayThreatEvidence runs bounded metadata-only Threat-ID replay checks. It
// compares expected signature/Threat-ID/verdict fields against the same
// classifier used by the alert API and includes current engine degraded-mode
// evidence from system status when available.
func (s *PolicyServer) ReplayThreatEvidence(ctx context.Context, req *openngfwv1.ReplayThreatEvidenceRequest) (*openngfwv1.ReplayThreatEvidenceResponse, error) {
	if req == nil {
		req = &openngfwv1.ReplayThreatEvidenceRequest{}
	}
	const maxReplaySamples = 25
	warnings := []string{
		"Threat-ID replay is metadata-only evidence; it does not execute packet payloads, malware samples, or certify IPS efficacy.",
	}
	samples := replaySamplesFromRequest(req.GetSamples())
	recentRequested := req.GetRecentAlerts() != nil || len(samples) == 0
	var recentCount uint32
	if recentRequested {
		recentSamples, recentWarnings, err := s.recentAlertReplaySamples(ctx, req.GetRecentAlerts(), maxReplaySamples-len(samples))
		if err != nil {
			return nil, err
		}
		samples = append(samples, recentSamples...)
		recentCount = uint32(len(recentSamples))
		warnings = append(warnings, recentWarnings...)
	}
	if len(samples) > maxReplaySamples {
		warnings = append(warnings, fmt.Sprintf("replay sample set was capped at %d records", maxReplaySamples))
		samples = samples[:maxReplaySamples]
	}

	engine, engineWarnings := s.threatReplayEngineEvidence(ctx)
	warnings = append(warnings, engineWarnings...)
	metadata := threatMetadataFromContentPackage(s.threatReplayContentDir())
	replay := threatid.Replay(samples, metadata)
	results := make([]*openngfwv1.ThreatReplayResult, 0, len(replay))
	for i, result := range replay {
		results = append(results, threatReplayResultProto(samples[i], result))
	}
	state, detail := threatReplayState(results, engine)
	return &openngfwv1.ReplayThreatEvidenceResponse{
		SchemaVersion:    "phragma.threat_id.replay.v1",
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		State:            state,
		Detail:           detail,
		Engine:           engine,
		Results:          results,
		Warnings:         warnings,
		SampleCount:      uint32(len(samples)),
		RecentAlertCount: recentCount,
	}, nil
}

type stagedThreatException struct {
	policy        *openngfwv1.Policy
	exception     *openngfwv1.IdsException
	address       *openngfwv1.Address
	addressReused bool
}

func replaySamplesFromRequest(in []*openngfwv1.ThreatReplaySample) []threatid.ReplaySample {
	out := make([]threatid.ReplaySample, 0, len(in))
	for i, sample := range in {
		if sample == nil {
			continue
		}
		id := strings.TrimSpace(sample.GetId())
		if id == "" {
			id = fmt.Sprintf("sample-%d", i+1)
		}
		out = append(out, threatid.ReplaySample{
			ID:          id,
			Source:      valueOrDefault(sample.GetSource(), "sample"),
			Signature:   sample.GetSignature(),
			SignatureID: sample.GetSignatureId(),
			Category:    sample.GetCategory(),
			Severity:    int(sample.GetSeverity()),
			Action:      sample.GetAction(),
			Expected: threatid.ReplayExpected{
				SignatureID: sample.GetExpected().GetSignatureId(),
				ThreatID:    sample.GetExpected().GetThreatId(),
				Verdict:     sample.GetExpected().GetVerdict(),
			},
		})
	}
	return out
}

func (s *PolicyServer) recentAlertReplaySamples(ctx context.Context, selector *openngfwv1.ThreatReplayRecentAlertSelector, remaining int) ([]threatid.ReplaySample, []string, error) {
	if remaining <= 0 {
		return nil, []string{"recent alert replay skipped because explicit samples reached the replay cap"}, nil
	}
	if s.ThreatReplayAlerts == nil {
		return nil, []string{"recent alert replay unavailable: alert evidence source is not wired"}, nil
	}
	limit := int(selector.GetLimit())
	if limit <= 0 {
		limit = 10
	}
	if limit > remaining {
		limit = remaining
	}
	resp, err := s.ThreatReplayAlerts.ListAlerts(ctx, &openngfwv1.ListAlertsRequest{
		Limit:          uint32(limit),
		Query:          selector.GetQuery(),
		SignatureId:    selector.GetSignatureId(),
		FlowId:         selector.GetFlowId(),
		Action:         selector.GetAction(),
		ThreatSeverity: selector.GetThreatSeverity(),
	})
	if err != nil {
		return nil, nil, status.Errorf(status.Code(err), "read recent alert evidence: %v", err)
	}
	out := make([]threatid.ReplaySample, 0, len(resp.GetAlerts()))
	for i, alert := range resp.GetAlerts() {
		out = append(out, threatid.ReplaySample{
			ID:          recentAlertReplayID(alert, i),
			Source:      "recent-alert",
			Signature:   alert.GetSignature(),
			SignatureID: alert.GetSignatureId(),
			Category:    alert.GetCategory(),
			Severity:    int(alert.GetSeverity()),
			Action:      alert.GetAction(),
			Expected: threatid.ReplayExpected{
				SignatureID: alert.GetSignatureId(),
				ThreatID:    alert.GetThreatId(),
				Verdict:     alert.GetAction(),
			},
		})
	}
	if len(out) == 0 {
		return nil, []string{"recent alert replay found no matching alert evidence"}, nil
	}
	return out, nil, nil
}

func recentAlertReplayID(alert *openngfwv1.Alert, idx int) string {
	if flow := strings.TrimSpace(alert.GetFlowId()); flow != "" {
		return "alert-flow-" + flow
	}
	if alert.GetSignatureId() > 0 {
		return fmt.Sprintf("alert-sid-%d-%d", alert.GetSignatureId(), idx+1)
	}
	return fmt.Sprintf("alert-%d", idx+1)
}

func (s *PolicyServer) threatReplayEngineEvidence(ctx context.Context) (*openngfwv1.ThreatReplayEngineEvidence, []string) {
	engine := &openngfwv1.ThreatReplayEngineEvidence{
		EngineName:      "suricata",
		EngineState:     "unknown",
		InspectionState: "unknown",
		EvidenceLabel:   "system status unavailable",
	}
	if s.ThreatReplayStatus == nil {
		return engine, []string{"engine degraded-mode evidence unavailable: system status source is not wired"}
	}
	statusResp, err := s.ThreatReplayStatus.GetStatus(ctx, &openngfwv1.GetStatusRequest{})
	if err != nil {
		return engine, []string{"engine degraded-mode evidence unavailable: " + err.Error()}
	}
	for _, candidate := range statusResp.GetEngines() {
		if strings.EqualFold(candidate.GetName(), "suricata") || strings.EqualFold(candidate.GetRole(), "inspection") {
			engine.EngineName = valueOrDefault(candidate.GetName(), "suricata")
			engine.EngineMode = candidate.GetMode()
			engine.EngineState = candidate.GetState()
			engine.EngineDetail = candidate.GetDetail()
			break
		}
	}
	inspection := statusResp.GetInspection()
	if inspection != nil {
		engine.InspectionState = inspection.GetState()
		engine.DegradedBehavior = inspection.GetDegradedBehavior()
		engine.EngineRequired = inspection.GetEngineRequired()
		engine.BypassPossible = inspection.GetBypassPossible()
		engine.BypassReason = inspection.GetBypassReason()
		if engine.EngineName == "" {
			engine.EngineName = valueOrDefault(inspection.GetEngineName(), "suricata")
		}
		if engine.EngineMode == "" {
			engine.EngineMode = inspection.GetEngineMode()
		}
		if engine.EngineState == "" {
			engine.EngineState = inspection.GetEngineState()
		}
	}
	engine.EvidenceLabel = "GET /v1/system/status inspection and engine posture"
	return engine, nil
}

func (s *PolicyServer) threatReplayContentDir() string {
	if alertSource, ok := s.ThreatReplayAlerts.(*AlertServer); ok {
		return alertSource.ContentDir
	}
	return ""
}

func threatReplayResultProto(sample threatid.ReplaySample, result threatid.ReplayResult) *openngfwv1.ThreatReplayResult {
	return &openngfwv1.ThreatReplayResult{
		SampleId:               result.SampleID,
		Source:                 result.Source,
		Expected:               threatReplayExpectationProto(result.Expected),
		ObservedSignature:      sample.Signature,
		ObservedSignatureId:    sample.SignatureID,
		ObservedThreatId:       result.Observed.ID,
		ObservedThreatName:     result.Observed.Name,
		ObservedThreatCategory: result.Observed.Category,
		ObservedThreatSeverity: result.Observed.Severity,
		ObservedConfidence:     result.Observed.Confidence,
		ObservedVerdict:        result.ObservedVerdict,
		SignatureMatched:       result.SignatureMatched,
		ThreatIdMatched:        result.ThreatIDMatched,
		VerdictMatched:         result.VerdictMatched,
		Passed:                 result.Passed,
		Evidence:               result.Evidence,
		Warnings:               result.Warnings,
	}
}

func threatReplayExpectationProto(expected threatid.ReplayExpected) *openngfwv1.ThreatReplayExpectation {
	return &openngfwv1.ThreatReplayExpectation{
		SignatureId: expected.SignatureID,
		ThreatId:    expected.ThreatID,
		Verdict:     expected.Verdict,
	}
}

func threatReplayState(results []*openngfwv1.ThreatReplayResult, engine *openngfwv1.ThreatReplayEngineEvidence) (string, string) {
	if len(results) == 0 {
		return "unavailable", "No Threat-ID replay samples or recent alert evidence were available."
	}
	for _, result := range results {
		if !result.GetPassed() {
			return "mismatched", "At least one replay result differs from expected signature, Threat-ID, or verdict evidence."
		}
	}
	if engine == nil {
		return "passed", "Replay comparison passed; engine availability evidence is unavailable."
	}
	engineState := strings.ToLower(engine.GetEngineState())
	inspectionState := strings.ToLower(engine.GetInspectionState())
	if engine.GetBypassPossible() || containsAnyText(engineState, "degraded", "failed", "missing", "unknown") || containsAnyText(inspectionState, "degraded", "failed", "unknown") {
		return "degraded", "Replay comparison passed, but current inspection engine posture needs operator review."
	}
	return "passed", "Replay comparison passed for the bounded evidence set."
}

func valueOrDefault(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func containsAnyText(s string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func (s *PolicyServer) stageThreatExceptionCandidate(req *openngfwv1.StageThreatExceptionRequest, sid int64, reason string) (*stagedThreatException, error) {
	base, err := s.candidateOrRunningPolicy()
	if err != nil {
		return nil, err
	}
	if base.Ids == nil {
		base.Ids = &openngfwv1.Ids{}
	}

	name := strings.TrimSpace(req.GetName())
	if name == "" {
		name = generatedThreatExceptionName(req, sid)
	}
	name = uniquePolicyObjectName(base.GetIds().GetExceptions(), name)

	ex := &openngfwv1.IdsException{
		Name:        name,
		SignatureId: sid,
		ThreatId:    strings.TrimSpace(req.GetThreatId()),
		Description: reason,
	}
	if err := applyThreatExceptionMetadata(ex, threatExceptionMetadataInput{
		Owner:         req.GetOwner(),
		TicketID:      req.GetTicketId(),
		ReviewDate:    req.GetReviewDate(),
		ExpiresAt:     req.GetExpiresAt(),
		PCAPSHA256:    req.GetPcapSha256(),
		RegressionRef: req.GetRegressionRef(),
	}); err != nil {
		return nil, err
	}
	var addr *openngfwv1.Address
	var reused bool
	switch req.GetScope() {
	case openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_SOURCE:
		addr, reused, err = ensureThreatAddress(base, req.GetSourceIp(), "threat-src-")
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "source_ip: %v", err)
		}
		ex.SourceAddress = addr.GetName()
	case openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_DESTINATION:
		addr, reused, err = ensureThreatAddress(base, req.GetDestinationIp(), "threat-dst-")
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "destination_ip: %v", err)
		}
		ex.DestinationAddress = addr.GetName()
	case openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_GLOBAL:
		if !req.GetConfirmGlobal() {
			return nil, status.Error(codes.InvalidArgument, "confirm_global is required for global threat exceptions")
		}
	default:
		return nil, status.Error(codes.InvalidArgument, "scope must be source, destination, or global")
	}
	if dup := matchingIDSException(base, sid, req.GetScope(), addr); dup != nil {
		return nil, status.Errorf(codes.AlreadyExists, "matching threat exception %q already exists", dup.GetName())
	}
	base.Ids.Exceptions = append(base.Ids.Exceptions, ex)
	return &stagedThreatException{policy: base, exception: ex, address: addr, addressReused: reused}, nil
}

func (s *PolicyServer) candidateOrRunningPolicy() (*openngfwv1.Policy, error) {
	if candidate, ok, err := s.store.GetCandidate(); err != nil {
		return nil, status.Errorf(codes.Internal, "read candidate: %v", err)
	} else if ok {
		return proto.Clone(candidate).(*openngfwv1.Policy), nil
	}
	running, _, err := s.store.GetRunning()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read running policy: %v", err)
	}
	return proto.Clone(running).(*openngfwv1.Policy), nil
}

func (s *PolicyServer) threatExceptionPolicy(source openngfwv1.PolicySource, version uint64) (*openngfwv1.Policy, openngfwv1.PolicySource, uint64, error) {
	switch source {
	case openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE:
		candidate, ok, err := s.store.GetCandidate()
		if err != nil {
			return nil, source, 0, status.Errorf(codes.Internal, "read candidate: %v", err)
		}
		if !ok {
			return nil, source, 0, status.Error(codes.NotFound, "no candidate policy is set")
		}
		return candidate, source, 0, nil
	case openngfwv1.PolicySource_POLICY_SOURCE_VERSION:
		if version == 0 {
			return nil, source, 0, status.Error(codes.InvalidArgument, "version is required for POLICY_SOURCE_VERSION")
		}
		p, err := s.store.GetVersion(version)
		if err != nil {
			return nil, source, version, status.Errorf(codes.NotFound, "%v", err)
		}
		return p, source, version, nil
	case openngfwv1.PolicySource_POLICY_SOURCE_RUNNING:
		running, runningVersion, err := s.store.GetRunning()
		if err != nil {
			return nil, source, 0, status.Errorf(codes.Internal, "read running policy: %v", err)
		}
		return running, source, runningVersion, nil
	default:
		if candidate, ok, err := s.store.GetCandidate(); err != nil {
			return nil, source, 0, status.Errorf(codes.Internal, "read candidate: %v", err)
		} else if ok {
			return candidate, openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE, 0, nil
		}
		running, runningVersion, err := s.store.GetRunning()
		if err != nil {
			return nil, source, 0, status.Errorf(codes.Internal, "read running policy: %v", err)
		}
		return running, openngfwv1.PolicySource_POLICY_SOURCE_RUNNING, runningVersion, nil
	}
}

type threatExceptionMutationResult struct {
	candidateStatus *openngfwv1.GetCandidateStatusResponse
	validation      *openngfwv1.ValidateResponse
	diff            *openngfwv1.DiffPolicyResponse
}

func (s *PolicyServer) storeThreatExceptionMutation(ctx context.Context, policy *openngfwv1.Policy, action, detail string) (*threatExceptionMutationResult, error) {
	validation, err := s.Validate(ctx, &openngfwv1.ValidateRequest{Policy: policy})
	if err != nil {
		return nil, err
	}
	if !validation.GetValid() {
		return &threatExceptionMutationResult{validation: validation}, nil
	}
	identity := auditIdentity(ctx)
	if err := s.store.SetCandidateWithAudit(policy, store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role,
		AuthSource: identity.AuthSource,
		Action:     action,
		Detail:     detail,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "store candidate with audit: %v", err)
	}
	statusResp, err := s.GetCandidateStatus(ctx, &openngfwv1.GetCandidateStatusRequest{})
	if err != nil {
		return nil, err
	}
	diff, err := s.DiffPolicy(ctx, &openngfwv1.DiffPolicyRequest{
		FromSource: openngfwv1.PolicySource_POLICY_SOURCE_RUNNING,
		ToSource:   openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE,
	})
	if err != nil {
		return nil, err
	}
	return &threatExceptionMutationResult{candidateStatus: statusResp, validation: validation, diff: diff}, nil
}

func suricataSignatureID(signals []*openngfwv1.ThreatEngineSignal) (int64, error) {
	var sid int64
	for _, sig := range signals {
		engine := strings.ToLower(strings.TrimSpace(sig.GetEngine()))
		kind := strings.ToLower(strings.TrimSpace(sig.GetKind()))
		if engine != "suricata" || (kind != "signature_id" && kind != "sid") {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimSpace(sig.GetValue()), 10, 64)
		if err != nil || value <= 0 {
			return 0, status.Errorf(codes.InvalidArgument, "suricata signature_id must be a positive integer")
		}
		if sid != 0 && sid != value {
			return 0, status.Error(codes.InvalidArgument, "conflicting suricata signature_id signals")
		}
		sid = value
	}
	if sid == 0 {
		return 0, status.Error(codes.InvalidArgument, "engine_signals must include suricata signature_id")
	}
	return sid, nil
}

func ensureThreatAddress(p *openngfwv1.Policy, ip, prefix string) (*openngfwv1.Address, bool, error) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil, false, fmt.Errorf("is required for selected scope")
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, false, fmt.Errorf("invalid IP %q", ip)
	}
	cidr := netip.PrefixFrom(addr, addr.BitLen()).String()
	for _, existing := range p.GetAddresses() {
		if existing.GetCidr() == cidr {
			return existing, true, nil
		}
	}
	name := uniquePolicyObjectName(p.GetAddresses(), cleanPolicyName(prefix+ip))
	created := &openngfwv1.Address{Name: name, Cidr: cidr, Description: "Auto-added from threat exception"}
	p.Addresses = append(p.Addresses, created)
	return created, false, nil
}

func matchingIDSException(p *openngfwv1.Policy, sid int64, scope openngfwv1.ThreatExceptionScope, addr *openngfwv1.Address) *openngfwv1.IdsException {
	for _, ex := range p.GetIds().GetExceptions() {
		if ex.GetDisabled() || ex.GetSignatureId() != sid {
			continue
		}
		switch scope {
		case openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_GLOBAL:
			if ex.GetSourceAddress() == "" && ex.GetDestinationAddress() == "" {
				return ex
			}
		case openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_SOURCE:
			if ex.GetSourceAddress() != "" && addressCIDR(p, ex.GetSourceAddress()) == addr.GetCidr() {
				return ex
			}
		case openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_DESTINATION:
			if ex.GetDestinationAddress() != "" && addressCIDR(p, ex.GetDestinationAddress()) == addr.GetCidr() {
				return ex
			}
		}
	}
	return nil
}

func addressCIDR(p *openngfwv1.Policy, name string) string {
	for _, addr := range p.GetAddresses() {
		if addr.GetName() == name {
			return addr.GetCidr()
		}
	}
	return ""
}

type namedPolicyObject interface {
	GetName() string
}

func uniquePolicyObjectName[T namedPolicyObject](items []T, base string) string {
	base = cleanPolicyName(base)
	if base == "" {
		base = "threat-exception"
	}
	names := map[string]bool{}
	for _, item := range items {
		names[item.GetName()] = true
	}
	if !names[base] {
		return base
	}
	for i := 2; i < 1000; i++ {
		suffix := fmt.Sprintf("-%d", i)
		candidate := base
		if len(candidate)+len(suffix) > 64 {
			candidate = candidate[:64-len(suffix)]
			candidate = strings.TrimRight(candidate, "-_")
		}
		candidate += suffix
		if !names[candidate] {
			return candidate
		}
	}
	return fmt.Sprintf("%s-%x", strings.TrimRight(base[:min(len(base), 55)], "-_"), sidNameEntropy(base))
}

func generatedThreatExceptionName(req *openngfwv1.StageThreatExceptionRequest, sid int64) string {
	switch req.GetScope() {
	case openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_SOURCE:
		return cleanPolicyName(fmt.Sprintf("fp-%d-source-%s", sid, req.GetSourceIp()))
	case openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_DESTINATION:
		return cleanPolicyName(fmt.Sprintf("fp-%d-destination-%s", sid, req.GetDestinationIp()))
	default:
		return cleanPolicyName(fmt.Sprintf("fp-%d-global", sid))
	}
}

func cleanPolicyName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastSep := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		sep := r == '-' || r == '_' || r == '.' || r == ':' || r == '/'
		switch {
		case ok:
			b.WriteRune(r)
			lastSep = false
		case sep && !lastSep:
			b.WriteByte('-')
			lastSep = true
		}
		if b.Len() >= 64 {
			break
		}
	}
	return strings.Trim(strings.TrimRight(b.String(), "-_"), "-_")
}

func sidNameEntropy(s string) uint32 {
	var h uint32 = 2166136261
	for _, c := range []byte(s) {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}

func threatExceptionAuditDetail(ex *openngfwv1.IdsException, scope openngfwv1.ThreatExceptionScope, addressReused bool) string {
	parts := []string{fmt.Sprintf("%s sid=%d", ex.GetName(), ex.GetSignatureId())}
	if ex.GetThreatId() != "" {
		parts = append(parts, "threat_id="+ex.GetThreatId())
	}
	appendThreatExceptionMetadataAudit(&parts, ex)
	parts = append(parts, "scope="+strings.ToLower(strings.TrimPrefix(scope.String(), "THREAT_EXCEPTION_SCOPE_")))
	if ex.GetSourceAddress() != "" {
		parts = append(parts, "source_address="+ex.GetSourceAddress())
	}
	if ex.GetDestinationAddress() != "" {
		parts = append(parts, "destination_address="+ex.GetDestinationAddress())
	}
	if addressReused {
		parts = append(parts, "address=reused")
	}
	return strings.Join(parts, " ")
}

func threatExceptionRecords(selected, running []*openngfwv1.IdsException) []*openngfwv1.ThreatExceptionRecord {
	records := make([]*openngfwv1.ThreatExceptionRecord, 0, len(selected))
	for _, ex := range selected {
		current := proto.Clone(ex).(*openngfwv1.IdsException)
		match := matchingIDSExceptionRecord(current, running)
		records = append(records, &openngfwv1.ThreatExceptionRecord{
			Exception:          current,
			Scope:              threatExceptionScopeFromPolicy(current),
			ScopeObject:        threatExceptionScopeObject(current),
			PresentInRunning:   match != nil,
			CandidateOnly:      match == nil,
			ChangedFromRunning: match != nil && !proto.Equal(current, match),
		})
	}
	sort.SliceStable(records, func(i, j int) bool {
		a, b := records[i].GetException(), records[j].GetException()
		if a.GetDisabled() != b.GetDisabled() {
			return !a.GetDisabled()
		}
		if a.GetSignatureId() != b.GetSignatureId() {
			return a.GetSignatureId() < b.GetSignatureId()
		}
		return a.GetName() < b.GetName()
	})
	return records
}

func matchingIDSExceptionRecord(ex *openngfwv1.IdsException, records []*openngfwv1.IdsException) *openngfwv1.IdsException {
	if ex.GetName() != "" {
		for _, candidate := range records {
			if candidate.GetName() == ex.GetName() {
				return candidate
			}
		}
	}
	for _, candidate := range records {
		if candidate.GetSignatureId() == ex.GetSignatureId() &&
			candidate.GetThreatId() == ex.GetThreatId() &&
			candidate.GetSourceAddress() == ex.GetSourceAddress() &&
			candidate.GetDestinationAddress() == ex.GetDestinationAddress() {
			return candidate
		}
	}
	return nil
}

func threatExceptionScopeFromPolicy(ex *openngfwv1.IdsException) openngfwv1.ThreatExceptionScope {
	if ex.GetSourceAddress() != "" {
		return openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_SOURCE
	}
	if ex.GetDestinationAddress() != "" {
		return openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_DESTINATION
	}
	return openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_GLOBAL
}

func threatExceptionScopeObject(ex *openngfwv1.IdsException) string {
	if ex.GetSourceAddress() != "" {
		return ex.GetSourceAddress()
	}
	return ex.GetDestinationAddress()
}

func findIDSExceptionByName(exceptions []*openngfwv1.IdsException, name string) (int, *openngfwv1.IdsException) {
	name = strings.TrimSpace(name)
	for i, ex := range exceptions {
		if ex.GetName() == name {
			return i, proto.Clone(ex).(*openngfwv1.IdsException)
		}
	}
	return -1, nil
}

func hasIDSExceptionName(exceptions []*openngfwv1.IdsException, name string) bool {
	for _, ex := range exceptions {
		if ex.GetName() == name {
			return true
		}
	}
	return false
}

func normalizedThreatExceptionReplacement(pathName string, ex *openngfwv1.IdsException, reason string) (*openngfwv1.IdsException, error) {
	if strings.TrimSpace(pathName) == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if ex == nil {
		return nil, status.Error(codes.InvalidArgument, "exception is required")
	}
	out := proto.Clone(ex).(*openngfwv1.IdsException)
	out.Name = strings.TrimSpace(defaultString(out.GetName(), pathName))
	out.ThreatId = strings.TrimSpace(out.GetThreatId())
	out.SourceAddress = strings.TrimSpace(out.GetSourceAddress())
	out.DestinationAddress = strings.TrimSpace(out.GetDestinationAddress())
	out.Description = strings.TrimSpace(out.GetDescription())
	if err := applyThreatExceptionMetadata(out, threatExceptionMetadataInput{
		Owner:         out.GetOwner(),
		TicketID:      out.GetTicketId(),
		ReviewDate:    out.GetReviewDate(),
		ExpiresAt:     out.GetExpiresAt(),
		PCAPSHA256:    out.GetPcapSha256(),
		RegressionRef: out.GetRegressionRef(),
	}); err != nil {
		return nil, err
	}
	if out.Description == "" {
		out.Description = reason
	}
	if out.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "exception name is required")
	}
	if out.GetSignatureId() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "signature_id must be set to a positive Suricata SID")
	}
	if out.GetSourceAddress() != "" && out.GetDestinationAddress() != "" {
		return nil, status.Error(codes.InvalidArgument, "source_address and destination_address are mutually exclusive")
	}
	return out, nil
}

type threatExceptionMetadataInput struct {
	Owner         string
	TicketID      string
	ReviewDate    string
	ExpiresAt     string
	PCAPSHA256    string
	RegressionRef string
}

func applyThreatExceptionMetadata(ex *openngfwv1.IdsException, input threatExceptionMetadataInput) error {
	ex.Owner = compactThreatExceptionText(input.Owner, 80)
	ex.TicketId = compactThreatExceptionText(input.TicketID, 80)
	ex.ReviewDate = compactThreatExceptionText(input.ReviewDate, 10)
	ex.ExpiresAt = compactThreatExceptionText(input.ExpiresAt, 10)
	ex.PcapSha256 = strings.ToLower(compactThreatExceptionText(input.PCAPSHA256, 64))
	ex.RegressionRef = compactThreatExceptionText(input.RegressionRef, 160)
	if ex.GetReviewDate() != "" {
		if err := validateThreatExceptionDate("review_date", ex.GetReviewDate()); err != nil {
			return err
		}
	}
	if ex.GetExpiresAt() != "" {
		if err := validateThreatExceptionDate("expires_at", ex.GetExpiresAt()); err != nil {
			return err
		}
	}
	if ex.GetPcapSha256() != "" && !threatExceptionSHA256RE.MatchString(ex.GetPcapSha256()) {
		return status.Error(codes.InvalidArgument, "pcap_sha256 must be a 64-character hex SHA-256")
	}
	return nil
}

func compactThreatExceptionText(value string, maxLen int) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if maxLen > 0 && len(value) > maxLen {
		value = strings.TrimSpace(value[:maxLen])
	}
	return value
}

func validateThreatExceptionDate(field, value string) error {
	if _, err := time.Parse("2006-01-02", value); err != nil {
		return status.Errorf(codes.InvalidArgument, "%s must use YYYY-MM-DD", field)
	}
	return nil
}

func threatExceptionMutationReason(reason string) (string, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "", status.Error(codes.InvalidArgument, "reason is required")
	}
	return reason, nil
}

func isGlobalThreatException(ex *openngfwv1.IdsException) bool {
	return ex.GetSourceAddress() == "" && ex.GetDestinationAddress() == ""
}

func threatExceptionLifecycleAuditDetail(action string, previous, next *openngfwv1.IdsException, reason string) string {
	subject := previous
	if next != nil {
		subject = next
	}
	if subject == nil {
		return fmt.Sprintf("%s reason=%s", action, compactAuditField(reason))
	}
	parts := []string{
		action,
		fmt.Sprintf("name=%s", compactAuditField(subject.GetName())),
		fmt.Sprintf("sid=%d", subject.GetSignatureId()),
		"scope=" + strings.ToLower(strings.TrimPrefix(threatExceptionScopeFromPolicy(subject).String(), "THREAT_EXCEPTION_SCOPE_")),
		"reason=" + compactAuditField(reason),
	}
	if previous != nil && next != nil && previous.GetName() != next.GetName() {
		parts = append(parts, "previous_name="+compactAuditField(previous.GetName()))
	}
	appendThreatExceptionMetadataAudit(&parts, subject)
	if next != nil && next.GetDisabled() {
		parts = append(parts, "state=disabled")
	} else if next != nil {
		parts = append(parts, "state=active")
	}
	return strings.Join(parts, " ")
}

func appendThreatExceptionMetadataAudit(parts *[]string, ex *openngfwv1.IdsException) {
	if ex.GetOwner() != "" {
		*parts = append(*parts, "owner="+compactAuditField(ex.GetOwner()))
	}
	if ex.GetTicketId() != "" {
		*parts = append(*parts, "ticket="+compactAuditField(ex.GetTicketId()))
	}
	if ex.GetReviewDate() != "" {
		*parts = append(*parts, "review_date="+compactAuditField(ex.GetReviewDate()))
	}
	if ex.GetExpiresAt() != "" {
		*parts = append(*parts, "expires_at="+compactAuditField(ex.GetExpiresAt()))
	}
	if ex.GetPcapSha256() != "" {
		*parts = append(*parts, "pcap_sha256="+compactAuditField(ex.GetPcapSha256()))
	}
	if ex.GetRegressionRef() != "" {
		*parts = append(*parts, "regression_ref="+compactAuditField(ex.GetRegressionRef()))
	}
}

func defaultString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value != "" {
		return value
	}
	return fallback
}
