package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/authz"
	"github.com/detailtech/oss-ngfw/internal/replayvalidation"
	"github.com/detailtech/oss-ngfw/internal/store"
)

// AutomationReplayValidationHandler validates browser-exported API/CLI
// automation runbooks and can execute the bounded audited candidate-safe slice
// when execute mode passes the same replay authority plan.
func (s *SystemService) AutomationReplayValidationHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/system/automation/replay:validate" {
			investigationJSONError(w, http.StatusNotFound, "NOT_FOUND", "automation replay validation route not found")
			return
		}
		if r.Method != http.MethodPost {
			investigationJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method is not allowed")
			return
		}
		s.handleValidateAutomationReplay(w, r)
	})
}

func (s *SystemService) handleValidateAutomationReplay(w http.ResponseWriter, r *http.Request) {
	identity, ok := s.automationReplayIdentity(w, r, authz.RoleOperator)
	if !ok {
		return
	}
	var req replayvalidation.Request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, replayvalidation.MaxRunbookBytes+65536)).Decode(&req); err != nil {
		investigationJSONError(w, http.StatusBadRequest, "INVALID_JSON", "request body must be JSON")
		return
	}
	state := s.automationReplayState(req.CandidateRevision)
	report := replayvalidation.Validate(req, state, time.Now().UTC())
	if strings.EqualFold(strings.TrimSpace(req.ExecutionMode), "execute") {
		report.ExecutionResult = s.executeAutomationReplay(r.Context(), identity, report)
	}
	status := http.StatusOK
	if report.Summary.Blocked {
		status = http.StatusOK
	}
	investigationWriteJSON(w, status, report)
}

func (s *SystemService) executeAutomationReplay(ctx context.Context, identity authz.Identity, report replayvalidation.Report) *replayvalidation.Result {
	started := time.Now().UTC()
	result := &replayvalidation.Result{
		SchemaVersion: replayvalidation.ResultSchema,
		Mode:          "execute",
		StartedAt:     started.Format(time.RFC3339Nano),
		Status:        "blocked",
		AuditRequired: true,
		Boundaries: []string{
			"executes only bounded candidate-safe replay steps with existing server validation coverage",
			"does not execute commit, rollback, host/runtime apply, packet capture start, HA actions, content lifecycle, shell, CLI, or unknown-route steps",
			"full production hardening for identity binding, signing, retention, least-privilege scope, and custody policy remains deferred",
		},
	}
	defer func() {
		result.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if result.Status == "" {
			result.Status = replayExecutionStatus(result.Results)
		}
	}()
	if report.ExecutionPlan == nil || !report.ExecutionPlan.AuthorityGranted {
		result.Results = append(result.Results, replayvalidation.StepResult{
			Action: "authority-check",
			Status: "blocked",
			Detail: "execute mode requires an authority-granted bounded replay plan",
		})
		return result
	}
	if s == nil || s.Store == nil {
		result.Results = append(result.Results, replayvalidation.StepResult{
			Action: "store-check",
			Status: "blocked",
			Detail: "candidate store is unavailable",
		})
		return result
	}
	if err := s.Store.AppendAudit(store.AuditEntry{
		Actor:      replayAuditActor(identity),
		ActorRole:  identity.Role.String(),
		AuthSource: identity.AuthSource,
		Action:     "automation-replay-execute-start",
		Detail:     fmt.Sprintf("steps=%d candidate_revision=%s unsigned=true bounded=true", len(report.Steps), report.State.CandidateRevision),
	}); err != nil {
		result.Results = append(result.Results, replayvalidation.StepResult{
			Action: "audit-start",
			Status: "blocked",
			Detail: fmt.Sprintf("record replay start audit: %v", err),
		})
		return result
	}
	for _, step := range report.Steps {
		result.Results = append(result.Results, s.executeAutomationReplayStep(ctx, identity, report.State, step))
	}
	result.Status = replayExecutionStatus(result.Results)
	_ = s.Store.AppendAudit(store.AuditEntry{
		Actor:      replayAuditActor(identity),
		ActorRole:  identity.Role.String(),
		AuthSource: identity.AuthSource,
		Action:     "automation-replay-execute-result",
		Detail:     fmt.Sprintf("status=%s steps=%d candidate_revision=%s bounded=true", result.Status, len(result.Results), report.State.CandidateRevision),
	})
	return result
}

func (s *SystemService) executeAutomationReplayStep(ctx context.Context, identity authz.Identity, state replayvalidation.State, step replayvalidation.Step) replayvalidation.StepResult {
	item := replayvalidation.StepResult{
		StepIndex:               step.Index,
		Action:                  "blocked",
		Status:                  "blocked",
		CandidateRevisionBefore: state.CandidateRevision,
	}
	if !step.KnownRoute || step.WouldApplyRunning || (step.WouldMutate && !step.WouldMutateCandidate) {
		item.Detail = "step is outside bounded replay execution scope"
		return item
	}
	if step.ReadOnly {
		item.Action = "observed"
		item.Status = "observed"
		item.Detail = fmt.Sprintf("%s %s validated for replay; no mutation executed", step.Method, step.Path)
		return item
	}
	if !step.WouldMutateCandidate || strings.Split(step.Path, "?")[0] != "/v1/candidate" || step.Method != http.MethodPut {
		item.Detail = "candidate workflow step is validated but not executable by this bounded replay slice"
		return item
	}
	req, err := replaySetCandidateRequest(step)
	if err != nil {
		item.Detail = err.Error()
		return item
	}
	if req.GetPolicy() == nil {
		item.Detail = "candidate replay body must include policy"
		return item
	}
	if s.Policy != nil {
		validation, err := s.Policy.validatePolicy(ctx, req.GetPolicy())
		if err != nil {
			item.Detail = fmt.Sprintf("candidate validation failed: %v", err)
			return item
		}
		if !validation.GetValid() {
			item.Detail = fmt.Sprintf("candidate validation rejected replay: %s", strings.Join(validation.GetErrors(), "; "))
			return item
		}
	}
	revision, err := s.Store.SetCandidateWithAuditIfRevision(req.GetPolicy(), strings.TrimSpace(req.GetExpectedCandidateRevision()), store.AuditEntry{
		Actor:      replayAuditActor(identity),
		ActorRole:  identity.Role.String(),
		AuthSource: identity.AuthSource,
		Action:     "automation-replay-set-candidate",
		Detail:     fmt.Sprintf("step=%d method=%s path=%s previous_candidate_revision=%s unsigned=true bounded=true", step.Index, step.Method, step.Path, state.CandidateRevision),
	})
	if errors.Is(err, store.ErrCandidateRevisionConflict) {
		item.Detail = "candidate changed since replay validation; reload candidate state before executing replay"
		return item
	}
	if err != nil {
		item.Detail = fmt.Sprintf("store candidate with replay audit: %v", err)
		return item
	}
	item.Action = "executed"
	item.Status = "applied"
	item.Mutation = "candidate"
	item.AuditAction = "automation-replay-set-candidate"
	item.CandidateRevisionAfter = revision
	item.Detail = "candidate policy replaced through audited bounded replay; running policy unchanged"
	return item
}

func replaySetCandidateRequest(step replayvalidation.Step) (*openngfwv1.SetCandidateRequest, error) {
	raw, err := json.Marshal(step.Body)
	if err != nil {
		return nil, fmt.Errorf("marshal candidate replay body: %w", err)
	}
	var req openngfwv1.SetCandidateRequest
	if err := protojson.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("candidate replay body must match SetCandidateRequest JSON: %w", err)
	}
	return &req, nil
}

func replayExecutionStatus(results []replayvalidation.StepResult) string {
	if len(results) == 0 {
		return "blocked"
	}
	status := "completed"
	for _, result := range results {
		if result.Status == "blocked" {
			return "blocked"
		}
		if result.Status != "applied" {
			status = "observed"
		}
	}
	return status
}

func replayAuditActor(identity authz.Identity) string {
	if strings.TrimSpace(identity.Name) != "" {
		return identity.Name
	}
	return "automation-replay"
}

func (s *SystemService) automationReplayState(expected string) replayvalidation.State {
	state := replayvalidation.State{
		ExpectedRevision:   expected,
		Source:             "store",
		CurrentStateLoaded: false,
	}
	if s == nil || s.Store == nil {
		state.Source = "unavailable"
		return state
	}
	running, version, err := s.Store.GetRunning()
	if err == nil {
		state.RunningVersion = version
	}
	candidate, hasCandidate, err := s.Store.GetCandidate()
	if err == nil {
		state.HasCandidate = hasCandidate
	}
	if revision, err := s.Store.CandidateRevision(); err == nil {
		state.CandidateRevision = revision
	}
	if running != nil && candidate != nil {
		state.CandidateDirty = !proto.Equal(running, candidate)
	}
	state.CurrentStateLoaded = true
	return state
}

func (s *SystemService) automationReplayIdentity(w http.ResponseWriter, r *http.Request, minRole authz.Role) (authz.Identity, bool) {
	if !s.Status.AuthEnabled {
		return authz.RequestIdentity(r.Context(), false), true
	}
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" {
		investigationJSONError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "missing bearer token")
		return authz.Identity{}, false
	}
	if s.Auth == nil {
		investigationJSONError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "authentication is not configured")
		return authz.Identity{}, false
	}
	id, ok := s.Auth.AuthenticateBearer(token)
	if !ok {
		investigationJSONError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "invalid bearer token")
		return authz.Identity{}, false
	}
	if id.Role < minRole {
		investigationJSONError(w, http.StatusForbidden, "FORBIDDEN", "role does not permit automation replay validation")
		return authz.Identity{}, false
	}
	return id, true
}
