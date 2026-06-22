package apiserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/authz"
	"github.com/detailtech/oss-ngfw/internal/fleet"
	"github.com/detailtech/oss-ngfw/internal/store"
)

type createFleetTemplateRequest struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Scope       string          `json:"scope"`
	Labels      []string        `json:"labels"`
	Policy      json.RawMessage `json:"policy"`
}

type fleetApplyPreviewRequest struct {
	ExpectedCandidateRevision string `json:"expectedCandidateRevision"`
}

type fleetApplyPlanRequest struct {
	ExpectedCandidateRevision string                    `json:"expectedCandidateRevision"`
	Nodes                     []fleetApplyPlanNodeInput `json:"nodes"`
}

type fleetApplyRequest struct {
	ExpectedCandidateRevision string                    `json:"expectedCandidateRevision"`
	Comment                   string                    `json:"comment"`
	Nodes                     []fleetApplyPlanNodeInput `json:"nodes"`
}

type fleetApplyPlanNodeInput struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Role           string `json:"role"`
	RuntimeState   string `json:"runtimeState"`
	RunningVersion any    `json:"runningVersion"`
	HAState        string `json:"haState"`
	HAReady        bool   `json:"haReady"`
	Authoritative  bool   `json:"authoritative"`
	Detail         string `json:"detail"`
}

type fleetStageCandidateRequest struct {
	ExpectedCandidateRevision string `json:"expectedCandidateRevision"`
	Comment                   string `json:"comment"`
}

// FleetHandler serves the first bounded local-appliance inventory/template API.
// It persists local template drafts and previews candidate import impact, but
// intentionally does not enroll peers, fan out applies, or claim HA control.
func (s *SystemService) FleetHandler() http.Handler {
	registry := fleet.NewStore(fleet.DefaultStorePath(s.Status.DataDir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1/fleet")
		switch {
		case path == "/nodes":
			if r.Method != http.MethodGet {
				fleetJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method is not allowed")
				return
			}
			s.handleListFleetNodes(w, r)
		case path == "/templates" || path == "/templates/":
			switch r.Method {
			case http.MethodGet:
				s.handleListFleetTemplates(w, r, registry)
			case http.MethodPost:
				s.handleCreateFleetTemplate(w, r, registry)
			default:
				fleetJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method is not allowed")
			}
		case path == "/template-results":
			if r.Method != http.MethodGet {
				fleetJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method is not allowed")
				return
			}
			s.handleListFleetTemplateResults(w, r, registry)
		case strings.HasPrefix(path, "/templates/") && strings.HasSuffix(path, ":validate"):
			if r.Method != http.MethodPost {
				fleetJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method is not allowed")
				return
			}
			id := strings.TrimSuffix(strings.TrimPrefix(path, "/templates/"), ":validate")
			s.handleValidateFleetTemplate(w, r, registry, id)
		case strings.HasPrefix(path, "/templates/") && strings.HasSuffix(path, ":apply-preview"):
			if r.Method != http.MethodPost {
				fleetJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method is not allowed")
				return
			}
			id := strings.TrimSuffix(strings.TrimPrefix(path, "/templates/"), ":apply-preview")
			s.handleFleetTemplateApplyPreview(w, r, registry, id)
		case strings.HasPrefix(path, "/templates/") && strings.HasSuffix(path, ":apply-plan"):
			if r.Method != http.MethodPost {
				fleetJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method is not allowed")
				return
			}
			id := strings.TrimSuffix(strings.TrimPrefix(path, "/templates/"), ":apply-plan")
			s.handleFleetTemplateApplyPlan(w, r, registry, id)
		case strings.HasPrefix(path, "/templates/") && strings.HasSuffix(path, ":apply"):
			if r.Method != http.MethodPost {
				fleetJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method is not allowed")
				return
			}
			id := strings.TrimSuffix(strings.TrimPrefix(path, "/templates/"), ":apply")
			s.handleFleetTemplateApply(w, r, registry, id)
		case strings.HasPrefix(path, "/templates/") && strings.HasSuffix(path, ":stage-candidate"):
			if r.Method != http.MethodPost {
				fleetJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method is not allowed")
				return
			}
			id := strings.TrimSuffix(strings.TrimPrefix(path, "/templates/"), ":stage-candidate")
			s.handleFleetTemplateStageCandidate(w, r, registry, id)
		default:
			fleetJSONError(w, http.StatusNotFound, "NOT_FOUND", "fleet route not found")
		}
	})
}

func (s *SystemService) handleListFleetNodes(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.fleetIdentity(w, r, authz.RoleViewer); !ok {
		return
	}
	statusResp, err := s.GetStatus(r.Context(), &openngfwv1.GetStatusRequest{})
	if err != nil {
		fleetStatusError(w, err)
		return
	}
	haResp, err := s.GetHighAvailabilityStatus(r.Context(), &openngfwv1.GetHighAvailabilityStatusRequest{})
	if err != nil {
		haResp = nil
	}
	node := s.fleetLocalNodeSnapshot(statusResp, haResp)
	fleetWriteJSON(w, http.StatusOK, map[string]any{
		"schemaVersion": fleet.APISchemaVersion,
		"nodes":         []any{node},
		"scope":         "connected local appliance only",
		"boundaries": []string{
			"not authoritative multi-node fleet inventory",
			"no peer enrollment or discovery",
			"no fan-out apply or distributed result custody",
			"no HA fencing, election, VIP movement, or traffic failover control",
		},
	})
}

func (s *SystemService) handleListFleetTemplates(w http.ResponseWriter, r *http.Request, registry *fleet.Store) {
	if _, ok := s.fleetIdentity(w, r, authz.RoleViewer); !ok {
		return
	}
	templates, err := registry.ListTemplates()
	if err != nil {
		fleetJSONError(w, http.StatusInternalServerError, "TEMPLATE_STORE_READ_FAILED", err.Error())
		return
	}
	fleetWriteJSON(w, http.StatusOK, map[string]any{
		"schemaVersion": fleet.APISchemaVersion,
		"templates":     templates,
		"count":         len(templates),
		"scope":         "local-appliance template registry",
		"boundaries": []string{
			"templates are unsigned local drafts",
			"validation and apply-preview do not mutate candidate or running policy",
			"operators must import/stage through Changes before commit",
		},
	})
}

func (s *SystemService) handleListFleetTemplateResults(w http.ResponseWriter, r *http.Request, registry *fleet.Store) {
	if _, ok := s.fleetIdentity(w, r, authz.RoleViewer); !ok {
		return
	}
	results, err := registry.ListApplyResults(r.URL.Query().Get("templateId"))
	if err != nil {
		fleetJSONError(w, http.StatusInternalServerError, "APPLY_RESULT_STORE_READ_FAILED", err.Error())
		return
	}
	fleetWriteJSON(w, http.StatusOK, map[string]any{
		"schemaVersion": fleet.APISchemaVersion,
		"results":       results,
		"count":         len(results),
		"custody":       "server-retained local Fleet apply result records; unsigned and not distributed custody",
		"boundaries": []string{
			"results are retained by the local Fleet template store",
			"peer results are operator-supplied/modelled custody only unless a safe peer transport is added later",
			"no signed result chain, peer attestation, HA fencing, VIP movement, traffic failover, or running-policy apply custody",
		},
	})
}

func (s *SystemService) handleCreateFleetTemplate(w http.ResponseWriter, r *http.Request, registry *fleet.Store) {
	id, ok := s.fleetIdentity(w, r, authz.RoleOperator)
	if !ok {
		return
	}
	var req createFleetTemplateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, fleet.MaxPolicyJSONBytes+65536)).Decode(&req); err != nil {
		fleetJSONError(w, http.StatusBadRequest, "INVALID_JSON", "request body must be JSON")
		return
	}
	p, err := fleet.DecodePolicy(req.Policy)
	if err != nil {
		fleetJSONError(w, http.StatusBadRequest, "INVALID_POLICY", err.Error())
		return
	}
	record, err := registry.CreateTemplate(fleet.CreateTemplateInput{
		Name:          req.Name,
		Description:   req.Description,
		Scope:         req.Scope,
		Labels:        req.Labels,
		Policy:        p,
		CreatedBy:     id.Name,
		CreatedByRole: id.Role.String(),
		AuthSource:    id.AuthSource,
	})
	if errors.Is(err, fleet.ErrTemplateLimit) {
		fleetJSONError(w, http.StatusConflict, "TEMPLATE_LIMIT_EXCEEDED", err.Error())
		return
	}
	if err != nil {
		fleetJSONError(w, http.StatusBadRequest, "TEMPLATE_CREATE_FAILED", err.Error())
		return
	}
	if s.Store != nil {
		if err := s.Store.AppendAudit(store.AuditEntry{
			Actor:      id.Name,
			ActorRole:  id.Role.String(),
			AuthSource: id.AuthSource,
			Action:     "fleet-template-create",
			Detail:     fmt.Sprintf("template=%s name=%q scope=%s revision=%s", record.ID, record.Name, record.Scope, record.Revision),
		}); err != nil {
			_ = registry.DeleteTemplate(record.ID)
			fleetJSONError(w, http.StatusInternalServerError, "AUDIT_WRITE_FAILED", "template was stored but audit custody failed; retry after audit storage is healthy")
			return
		}
	}
	w.Header().Set("Location", "/v1/fleet/templates/"+record.ID)
	fleetWriteJSON(w, http.StatusCreated, map[string]any{
		"schemaVersion": fleet.APISchemaVersion,
		"template":      record,
	})
}

func (s *SystemService) handleValidateFleetTemplate(w http.ResponseWriter, r *http.Request, registry *fleet.Store, id string) {
	if _, ok := s.fleetIdentity(w, r, authz.RoleOperator); !ok {
		return
	}
	record, p, ok := s.fleetTemplatePolicy(w, registry, id)
	if !ok {
		return
	}
	resp, err := s.Policy.Validate(r.Context(), &openngfwv1.ValidateRequest{Policy: p})
	if err != nil {
		fleetStatusError(w, err)
		return
	}
	candidateRevision := ""
	if s.Store != nil {
		candidateRevision, _ = s.Store.CandidateRevision()
	}
	fleetWriteJSON(w, http.StatusOK, map[string]any{
		"schemaVersion":     fleet.APISchemaVersion,
		"template":          record,
		"validation":        fleetProtoJSON(resp),
		"candidateRevision": candidateRevision,
		"mutated":           false,
	})
}

func (s *SystemService) handleFleetTemplateApplyPreview(w http.ResponseWriter, r *http.Request, registry *fleet.Store, id string) {
	if _, ok := s.fleetIdentity(w, r, authz.RoleOperator); !ok {
		return
	}
	var req fleetApplyPreviewRequest
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&req)
	}
	record, p, ok := s.fleetTemplatePolicy(w, registry, id)
	if !ok {
		return
	}
	validation, err := s.Policy.Validate(r.Context(), &openngfwv1.ValidateRequest{Policy: p})
	if err != nil {
		fleetStatusError(w, err)
		return
	}
	candidateRevision := ""
	if s.Store != nil {
		candidateRevision, _ = s.Store.CandidateRevision()
	}
	if expected := strings.TrimSpace(req.ExpectedCandidateRevision); expected != "" && candidateRevision != "" && expected != candidateRevision {
		fleetJSONError(w, http.StatusPreconditionFailed, "CANDIDATE_REVISION_CONFLICT", "candidate changed since the template preview was requested")
		return
	}
	fleetWriteJSON(w, http.StatusOK, map[string]any{
		"schemaVersion":             fleet.APISchemaVersion,
		"template":                  record,
		"validation":                fleetProtoJSON(validation),
		"impact":                    fleetProtoJSON(validation.GetImpact()),
		"candidateRevision":         candidateRevision,
		"wouldMutateCandidate":      false,
		"wouldApplyRunningPolicy":   false,
		"applyPath":                 "stage through /v1/candidate, validate, diff, approval when required, commit, audit, rollback",
		"orchestrationBoundary":     "local preview only; no peer fan-out, distributed apply result, signed custody, HA fencing, or traffic failover",
		"requiredOperatorNextSteps": []string{"import or stage candidate", "validate candidate", "review diff and impact", "commit through existing Changes workflow"},
	})
}

func (s *SystemService) handleFleetTemplateApplyPlan(w http.ResponseWriter, r *http.Request, registry *fleet.Store, id string) {
	if _, ok := s.fleetIdentity(w, r, authz.RoleOperator); !ok {
		return
	}
	var req fleetApplyPlanRequest
	if r.Body != nil {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil && err.Error() != "EOF" {
			fleetJSONError(w, http.StatusBadRequest, "INVALID_JSON", "request body must be JSON")
			return
		}
	}
	if len(req.Nodes) > 32 {
		fleetJSONError(w, http.StatusBadRequest, "NODE_LIMIT_EXCEEDED", "apply plan accepts at most 32 peer inventory nodes")
		return
	}
	record, p, ok := s.fleetTemplatePolicy(w, registry, id)
	if !ok {
		return
	}
	validation, err := s.Policy.Validate(r.Context(), &openngfwv1.ValidateRequest{Policy: p})
	if err != nil {
		fleetStatusError(w, err)
		return
	}
	candidateRevision := ""
	if s.Store != nil {
		candidateRevision, _ = s.Store.CandidateRevision()
	}
	if expected := strings.TrimSpace(req.ExpectedCandidateRevision); expected != "" && candidateRevision != "" && expected != candidateRevision {
		fleetJSONError(w, http.StatusPreconditionFailed, "CANDIDATE_REVISION_CONFLICT", "candidate changed since the template apply plan was requested")
		return
	}
	localNode := map[string]any{}
	statusResp, statusErr := s.GetStatus(r.Context(), &openngfwv1.GetStatusRequest{})
	haResp, haErr := s.GetHighAvailabilityStatus(r.Context(), &openngfwv1.GetHighAvailabilityStatusRequest{})
	if statusErr == nil {
		if haErr != nil {
			haResp = nil
		}
		localNode = s.fleetLocalNodeSnapshot(statusResp, haResp)
	} else {
		localNode = map[string]any{
			"id":             "local",
			"name":           "local appliance",
			"scope":          "local-appliance",
			"role":           "standalone",
			"runtimeState":   "unknown",
			"runningVersion": "",
			"authoritative":  true,
		}
	}
	nodes := fleetApplyPlanNodes(localNode, req.Nodes)
	nodeResults, eligibleCount := fleetApplyPlanNodeResults(nodes, validation.GetValid())
	blockers := fleetApplyPlanBlockers(validation.GetValid(), nodeResults, len(req.Nodes))
	result := "blocked"
	if validation.GetValid() && eligibleCount > 0 {
		result = "previewable"
	}
	fleetWriteJSON(w, http.StatusOK, map[string]any{
		"schemaVersion":           fleet.APISchemaVersion,
		"template":                record,
		"validation":              fleetProtoJSON(validation),
		"impact":                  fleetProtoJSON(validation.GetImpact()),
		"candidateRevision":       candidateRevision,
		"result":                  result,
		"nodeCount":               len(nodeResults),
		"eligibleNodeCount":       eligibleCount,
		"blockedNodeCount":        len(nodeResults) - eligibleCount,
		"nodes":                   nodeResults,
		"blockers":                blockers,
		"wouldMutateCandidate":    false,
		"wouldApplyRunningPolicy": false,
		"wouldCallPeerRPC":        false,
		"applyPath":               "per-node handoff plan only; stage candidate locally, validate, diff, commit, audit, rollback, then execute peer steps outside Fleet custody",
		"orchestrationBoundary":   "multi-node apply plan only; no peer RPC, signed retention, distributed commit custody, HA fencing, VIP movement, traffic failover, or running-policy apply is performed by Fleet",
		"requiredOperatorNextSteps": []string{
			"review per-node eligibility and blockers",
			"stage candidate through the local template workflow when ready",
			"execute peer changes through approved node-local workflows outside Fleet custody",
			"collect signed retention and distributed commit evidence in a future hardening slice",
		},
	})
}

func (s *SystemService) handleFleetTemplateApply(w http.ResponseWriter, r *http.Request, registry *fleet.Store, id string) {
	identity, ok := s.fleetIdentity(w, r, authz.RoleOperator)
	if !ok {
		return
	}
	var req fleetApplyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		fleetJSONError(w, http.StatusBadRequest, "INVALID_JSON", "request body must be JSON")
		return
	}
	if len(req.Nodes) > 32 {
		fleetJSONError(w, http.StatusBadRequest, "NODE_LIMIT_EXCEEDED", "template apply accepts at most 32 peer inventory nodes")
		return
	}
	expectedRevision := strings.TrimSpace(req.ExpectedCandidateRevision)
	if expectedRevision == "" {
		fleetJSONError(w, http.StatusBadRequest, "EXPECTED_CANDIDATE_REVISION_REQUIRED", "expectedCandidateRevision is required before applying a fleet template")
		return
	}
	comment := strings.TrimSpace(req.Comment)
	if comment == "" {
		fleetJSONError(w, http.StatusBadRequest, "COMMENT_REQUIRED", "comment is required for Fleet apply result custody")
		return
	}
	if s.Store == nil {
		fleetJSONError(w, http.StatusPreconditionFailed, "CANDIDATE_STORE_UNAVAILABLE", "candidate store is required for bounded local template apply")
		return
	}
	record, p, ok := s.fleetTemplatePolicy(w, registry, id)
	if !ok {
		return
	}
	validation, err := s.Policy.Validate(r.Context(), &openngfwv1.ValidateRequest{Policy: p})
	if err != nil {
		fleetStatusError(w, err)
		return
	}
	localNode := s.fleetApplyLocalNode(r)
	planNodes, _ := fleetApplyPlanNodeResults(fleetApplyPlanNodes(localNode, req.Nodes), validation.GetValid())
	if !validation.GetValid() {
		results := fleetApplyResultRecords(planNodes, false, "", "")
		applyRecord, recErr := registry.RecordApplyResult(fleetApplyRecord(identity, record, comment, expectedRevision, "", "blocked", results))
		if recErr != nil {
			fleetJSONError(w, http.StatusInternalServerError, "APPLY_RESULT_CUSTODY_FAILED", recErr.Error())
			return
		}
		fleetWriteJSON(w, http.StatusBadRequest, map[string]any{
			"error": map[string]any{
				"code":    "TEMPLATE_VALIDATION_FAILED",
				"message": "stored fleet template policy failed validation; no candidate or peer result was applied",
			},
			"schemaVersion": fleet.APISchemaVersion,
			"template":      record,
			"validation":    fleetProtoJSON(validation),
			"applyResult":   applyRecord,
			"mutated":       false,
		})
		return
	}
	beforeRevision, _ := s.Store.CandidateRevision()
	s.Policy.mu.Lock()
	revision, err := s.Store.SetCandidateWithAuditIfRevision(proto.Clone(p).(*openngfwv1.Policy), expectedRevision, store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role.String(),
		AuthSource: identity.AuthSource,
		Action:     "fleet-template-apply",
		Detail:     fleetTemplateStageAuditDetail(record, expectedRevision, comment),
	})
	s.Policy.mu.Unlock()
	if errors.Is(err, store.ErrCandidateRevisionConflict) {
		fleetJSONError(w, http.StatusPreconditionFailed, "CANDIDATE_REVISION_CONFLICT", "candidate changed since the template apply request was prepared")
		return
	}
	if err != nil {
		results := fleetApplyResultRecords(planNodes, true, "", err.Error())
		applyRecord, recErr := registry.RecordApplyResult(fleetApplyRecord(identity, record, comment, expectedRevision, "", "error", results))
		if recErr != nil {
			fleetJSONError(w, http.StatusInternalServerError, "APPLY_RESULT_CUSTODY_FAILED", recErr.Error())
			return
		}
		fleetWriteJSON(w, http.StatusInternalServerError, map[string]any{
			"error": map[string]any{
				"code":    "LOCAL_CANDIDATE_APPLY_FAILED",
				"message": "local candidate apply failed; retained Fleet apply result records the error",
			},
			"schemaVersion": fleet.APISchemaVersion,
			"template":      record,
			"validation":    fleetProtoJSON(validation),
			"applyResult":   applyRecord,
			"mutated":       false,
		})
		return
	}
	results := fleetApplyResultRecords(planNodes, true, revision, "")
	applyRecord, err := registry.RecordApplyResult(fleetApplyRecord(identity, record, comment, expectedRevision, revision, "applied", results))
	if err != nil {
		fleetWriteJSON(w, http.StatusInternalServerError, map[string]any{
			"error": map[string]any{
				"code":    "APPLY_RESULT_CUSTODY_FAILED",
				"message": "candidate was staged locally but Fleet apply result custody failed",
			},
			"schemaVersion":             fleet.APISchemaVersion,
			"template":                  record,
			"validation":                fleetProtoJSON(validation),
			"previousCandidateRevision": beforeRevision,
			"candidateRevision":         revision,
			"mutated":                   true,
		})
		return
	}
	fleetWriteJSON(w, http.StatusOK, map[string]any{
		"schemaVersion":             fleet.APISchemaVersion,
		"template":                  record,
		"validation":                fleetProtoJSON(validation),
		"impact":                    fleetProtoJSON(validation.GetImpact()),
		"previousCandidateRevision": beforeRevision,
		"candidateRevision":         revision,
		"applyResult":               applyRecord,
		"result":                    applyRecord.Status,
		"nodeResults":               applyRecord.NodeResults,
		"mutated":                   true,
		"runningPolicyApplied":      false,
		"wouldCallPeerRPC":          false,
		"applyPath":                 "local candidate applied and peer results retained as bounded Fleet custody; commit remains in the normal Changes workflow",
		"orchestrationBoundary":     "local candidate apply plus explicit peer result custody only; no peer RPC, production distributed execution, signed custody, HA fencing, VIP movement, traffic failover, or running-policy apply",
	})
}

func (s *SystemService) handleFleetTemplateStageCandidate(w http.ResponseWriter, r *http.Request, registry *fleet.Store, id string) {
	identity, ok := s.fleetIdentity(w, r, authz.RoleOperator)
	if !ok {
		return
	}
	var req fleetStageCandidateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&req); err != nil {
		fleetJSONError(w, http.StatusBadRequest, "INVALID_JSON", "request body must be JSON")
		return
	}
	expectedRevision := strings.TrimSpace(req.ExpectedCandidateRevision)
	if expectedRevision == "" {
		fleetJSONError(w, http.StatusBadRequest, "EXPECTED_CANDIDATE_REVISION_REQUIRED", "expectedCandidateRevision is required before staging a fleet template")
		return
	}
	record, p, ok := s.fleetTemplatePolicy(w, registry, id)
	if !ok {
		return
	}
	validation, err := s.Policy.Validate(r.Context(), &openngfwv1.ValidateRequest{Policy: p})
	if err != nil {
		fleetStatusError(w, err)
		return
	}
	if !validation.GetValid() {
		fleetWriteJSON(w, http.StatusBadRequest, map[string]any{
			"error": map[string]any{
				"code":    "TEMPLATE_VALIDATION_FAILED",
				"message": "stored fleet template policy failed validation; candidate was not staged",
			},
			"schemaVersion": fleet.APISchemaVersion,
			"template":      record,
			"validation":    fleetProtoJSON(validation),
			"mutated":       false,
		})
		return
	}
	s.Policy.mu.Lock()
	defer s.Policy.mu.Unlock()
	revision, err := s.Store.SetCandidateWithAuditIfRevision(proto.Clone(p).(*openngfwv1.Policy), expectedRevision, store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role.String(),
		AuthSource: identity.AuthSource,
		Action:     "fleet-template-stage-candidate",
		Detail:     fleetTemplateStageAuditDetail(record, expectedRevision, req.Comment),
	})
	if errors.Is(err, store.ErrCandidateRevisionConflict) {
		fleetJSONError(w, http.StatusPreconditionFailed, "CANDIDATE_REVISION_CONFLICT", "candidate changed since the template stage request was prepared")
		return
	}
	if err != nil {
		fleetJSONError(w, http.StatusInternalServerError, "AUDIT_WRITE_FAILED", "candidate was not staged because audit custody failed; retry after audit storage is healthy")
		return
	}
	statusResp, err := s.Policy.candidateStatusFor(p)
	if err != nil {
		fleetStatusError(w, err)
		return
	}
	fleetWriteJSON(w, http.StatusOK, map[string]any{
		"schemaVersion":             fleet.APISchemaVersion,
		"template":                  record,
		"validation":                fleetProtoJSON(validation),
		"impact":                    fleetProtoJSON(validation.GetImpact()),
		"previousCandidateRevision": expectedRevision,
		"candidateRevision":         revision,
		"candidateStatus":           fleetProtoJSON(statusResp),
		"stagedCandidate":           true,
		"mutated":                   true,
		"runningPolicyApplied":      false,
		"applyPath":                 "candidate staged locally; validate, diff, approval when required, commit, audit, rollback",
		"orchestrationBoundary":     "local candidate stage only; no peer fan-out, distributed apply result custody, running-policy apply, HA fencing, or traffic failover",
	})
}

func (s *SystemService) fleetLocalNodeSnapshot(statusResp *openngfwv1.GetStatusResponse, haResp *openngfwv1.GetHighAvailabilityStatusResponse) map[string]any {
	runningVersion := statusResp.GetDataplane().GetRunningPolicyVersion()
	node := map[string]any{
		"id":             "local",
		"name":           "local appliance",
		"detail":         firstNonEmpty(statusResp.GetRuntime().GetActiveDataplane(), statusResp.GetDataplane().GetActiveDataplane(), "connected management API"),
		"scope":          "local-appliance",
		"runningVersion": runningVersion,
		"role":           "standalone",
		"runtimeState":   firstNonEmpty(statusResp.GetHost().GetState(), "unknown"),
		"authoritative":  true,
	}
	if haResp != nil && haResp.GetStatus() != nil {
		ha := haResp.GetStatus()
		node["role"] = firstNonEmpty(ha.GetRole(), "standalone")
		node["haState"] = ha.GetState()
		node["haReady"] = fleetHAReady(ha)
		node["haBlockers"] = ha.GetBlockers()
	}
	return node
}

func (s *SystemService) fleetApplyLocalNode(r *http.Request) map[string]any {
	statusResp, statusErr := s.GetStatus(r.Context(), &openngfwv1.GetStatusRequest{})
	if statusErr == nil {
		haResp, haErr := s.GetHighAvailabilityStatus(r.Context(), &openngfwv1.GetHighAvailabilityStatusRequest{})
		if haErr != nil {
			haResp = nil
		}
		node := s.fleetLocalNodeSnapshot(statusResp, haResp)
		if jsonAnyString(node["runtimeState"]) == "" || strings.EqualFold(jsonAnyString(node["runtimeState"]), "unknown") {
			node["runtimeState"] = "ready"
		}
		return node
	}
	return map[string]any{
		"id":             "local",
		"name":           "local appliance",
		"scope":          "local-appliance",
		"role":           "standalone",
		"runtimeState":   "ready",
		"runningVersion": "candidate",
		"authoritative":  true,
	}
}

func fleetApplyPlanNodes(local map[string]any, peers []fleetApplyPlanNodeInput) []map[string]any {
	out := []map[string]any{local}
	seen := map[string]bool{"local": true}
	for _, peer := range peers {
		id := fleetCleanNodeToken(peer.ID, 80)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		name := fleetCleanNodeToken(peer.Name, 120)
		if name == "" {
			name = id
		}
		out = append(out, map[string]any{
			"id":             id,
			"name":           name,
			"detail":         fleetCleanNodeToken(peer.Detail, 160),
			"scope":          "operator-supplied-peer-inventory",
			"runningVersion": peer.RunningVersion,
			"role":           fleetCleanNodeToken(peer.Role, 80),
			"runtimeState":   fleetCleanNodeToken(peer.RuntimeState, 80),
			"haState":        fleetCleanNodeToken(peer.HAState, 80),
			"haReady":        peer.HAReady,
			"authoritative":  peer.Authoritative,
		})
	}
	return out
}

func fleetApplyPlanNodeResults(nodes []map[string]any, templateValid bool) ([]map[string]any, int) {
	results := make([]map[string]any, 0, len(nodes))
	eligibleCount := 0
	for _, node := range nodes {
		result := fleetApplyPlanNodeResult(node, templateValid)
		if result["eligible"] == true {
			eligibleCount++
		}
		results = append(results, result)
	}
	return results, eligibleCount
}

func fleetApplyPlanNodeResult(node map[string]any, templateValid bool) map[string]any {
	id := jsonAnyString(node["id"])
	name := firstNonEmpty(jsonAnyString(node["name"]), id)
	role := strings.ToLower(firstNonEmpty(jsonAnyString(node["role"]), "standalone"))
	runtime := strings.ToLower(jsonAnyString(node["runtimeState"]))
	runningVersion := jsonAnyString(node["runningVersion"])
	haReady, _ := node["haReady"].(bool)
	authoritative, _ := node["authoritative"].(bool)
	evidence := []string{}
	blockers := []string{}
	if templateValid {
		evidence = append(evidence, "template validation passed")
	} else {
		blockers = append(blockers, "template validation failed")
	}
	if runningVersion != "" && runningVersion != "0" {
		evidence = append(evidence, "running policy version "+runningVersion)
	} else {
		blockers = append(blockers, "running policy version unknown")
	}
	if runtime == "ready" || runtime == "healthy" || runtime == "active" || runtime == "ok" || runtime == "operable" {
		evidence = append(evidence, "runtime "+runtime)
	} else {
		blockers = append(blockers, "runtime readiness needs positive evidence")
	}
	if role == "standalone" || role == "local" {
		evidence = append(evidence, "standalone/local boundary acknowledged")
	} else if haReady {
		evidence = append(evidence, "HA readiness evidence ready")
	} else {
		blockers = append(blockers, "HA/readiness evidence needs review")
	}
	if !authoritative && id != "local" {
		evidence = append(evidence, "operator-supplied peer inventory")
	}
	eligible := len(blockers) == 0
	action := "hold; collect readiness evidence"
	statusText := "blocked"
	if eligible {
		action = "handoff candidate apply through node-local workflow"
		statusText = "eligible"
	}
	return map[string]any{
		"id":                id,
		"name":              name,
		"role":              firstNonEmpty(jsonAnyString(node["role"]), "standalone"),
		"scope":             firstNonEmpty(jsonAnyString(node["scope"]), "operator-supplied-peer-inventory"),
		"runtimeState":      firstNonEmpty(jsonAnyString(node["runtimeState"]), "unknown"),
		"runningVersion":    runningVersion,
		"authoritative":     authoritative,
		"eligible":          eligible,
		"status":            statusText,
		"plannedAction":     action,
		"positiveEvidence":  evidence,
		"blockers":          blockers,
		"executionHandoff":  "node-local candidate/commit workflow outside Fleet distributed custody",
		"mutationPerformed": false,
	}
}

func fleetApplyRecord(identity authz.Identity, template fleet.TemplateRecord, comment, beforeRevision, afterRevision, statusText string, nodes []fleet.ApplyNodeResult) fleet.ApplyRecord {
	return fleet.ApplyRecord{
		TemplateID:              template.ID,
		TemplateName:            template.Name,
		TemplateRevision:        template.Revision,
		RequestedBy:             identity.Name,
		RequestedByRole:         identity.Role.String(),
		AuthSource:              identity.AuthSource,
		Comment:                 strings.TrimSpace(comment),
		Status:                  statusText,
		CandidateRevisionBefore: beforeRevision,
		CandidateRevisionAfter:  afterRevision,
		NodeResults:             nodes,
		CustodyBoundary:         "server-retained local Fleet apply result; unsigned and not distributed custody",
	}
}

func fleetApplyResultRecords(planNodes []map[string]any, localApplied bool, revision, localErr string) []fleet.ApplyNodeResult {
	results := make([]fleet.ApplyNodeResult, 0, len(planNodes))
	for _, node := range planNodes {
		id := jsonAnyString(node["id"])
		name := firstNonEmpty(jsonAnyString(node["name"]), id)
		statusText := jsonAnyString(node["status"])
		blockers := jsonStringSlice(node["blockers"])
		result := "blocked"
		reason := "node eligibility blocked"
		mutation := "none"
		if id == "local" {
			switch {
			case localErr != "":
				result = "error"
				reason = localErr
			case localApplied:
				result = "applied"
				reason = "template staged to local candidate revision " + revision
				mutation = "local candidate policy updated; running policy not applied"
			default:
				result = "blocked"
				reason = "template validation failed"
			}
		} else if statusText == "eligible" {
			result = "skipped"
			reason = "peer eligible but skipped because Fleet has no safe peer RPC transport in this slice"
		} else if len(blockers) > 0 {
			result = "blocked"
			reason = strings.Join(blockers, "; ")
		}
		results = append(results, fleet.ApplyNodeResult{
			NodeID:           id,
			NodeName:         name,
			Role:             jsonAnyString(node["role"]),
			Scope:            jsonAnyString(node["scope"]),
			RuntimeState:     jsonAnyString(node["runtimeState"]),
			RunningVersion:   jsonAnyString(node["runningVersion"]),
			Result:           result,
			Reason:           reason,
			PositiveEvidence: jsonStringSlice(node["positiveEvidence"]),
			Blockers:         blockers,
			Mutation:         mutation,
			Custody:          "server-retained result record only",
		})
	}
	return results
}

func fleetApplyPlanBlockers(templateValid bool, nodes []map[string]any, peerCount int) []map[string]any {
	var blockers []map[string]any
	if !templateValid {
		blockers = append(blockers, map[string]any{"key": "template", "title": "Template validation failed", "detail": "No node should apply this template until validation passes.", "tone": "bad"})
	}
	if peerCount == 0 {
		blockers = append(blockers, map[string]any{"key": "peer-inventory", "title": "No peer inventory supplied", "detail": "Apply plan covers only the connected local appliance until peer inventory is supplied.", "tone": "info"})
	}
	for _, node := range nodes {
		if node["eligible"] != true {
			blockers = append(blockers, map[string]any{"key": "node-" + jsonAnyString(node["id"]), "title": "Node blocked", "detail": fmt.Sprintf("%s: %s", jsonAnyString(node["name"]), strings.Join(jsonStringSlice(node["blockers"]), "; ")), "tone": "warn"})
		}
	}
	return blockers
}

func fleetCleanNodeToken(value string, limit int) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\x00", ""))
	if len(value) > limit {
		value = value[:limit]
	}
	return value
}

func jsonAnyString(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return fmt.Sprintf("%.0f", v)
	case int:
		return fmt.Sprint(v)
	case int64:
		return fmt.Sprint(v)
	case uint64:
		return fmt.Sprint(v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func jsonStringSlice(value any) []string {
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s := jsonAnyString(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func (s *SystemService) fleetTemplatePolicy(w http.ResponseWriter, registry *fleet.Store, id string) (fleet.TemplateRecord, *openngfwv1.Policy, bool) {
	record, err := registry.GetTemplate(id)
	if errors.Is(err, fleet.ErrNotFound) {
		fleetJSONError(w, http.StatusNotFound, "TEMPLATE_NOT_FOUND", "fleet template not found")
		return fleet.TemplateRecord{}, nil, false
	}
	if err != nil {
		fleetJSONError(w, http.StatusBadRequest, "INVALID_TEMPLATE_ID", err.Error())
		return fleet.TemplateRecord{}, nil, false
	}
	p, err := fleet.DecodePolicy(record.Policy)
	if err != nil {
		fleetJSONError(w, http.StatusInternalServerError, "TEMPLATE_POLICY_INVALID", err.Error())
		return fleet.TemplateRecord{}, nil, false
	}
	return record, p, true
}

func fleetTemplateStageAuditDetail(record fleet.TemplateRecord, expectedRevision, comment string) string {
	parts := []string{
		fmt.Sprintf("template=%s", record.ID),
		fmt.Sprintf("name=%q", record.Name),
		fmt.Sprintf("template_revision=%s", record.Revision),
		fmt.Sprintf("expected_candidate_revision=%s", expectedRevision),
		fmt.Sprintf("zones=%d", record.PolicySummary.Zones),
		fmt.Sprintf("rules=%d", record.PolicySummary.Rules),
	}
	if c := strings.TrimSpace(comment); c != "" {
		parts = append(parts, fmt.Sprintf("comment=%q", c))
	}
	return strings.Join(parts, " ")
}

func (s *SystemService) fleetIdentity(w http.ResponseWriter, r *http.Request, minRole authz.Role) (authz.Identity, bool) {
	if !s.Status.AuthEnabled {
		return authz.RequestIdentity(r.Context(), false), true
	}
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" {
		fleetJSONError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "missing bearer token")
		return authz.Identity{}, false
	}
	if s.Auth == nil {
		fleetJSONError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "authentication is not configured")
		return authz.Identity{}, false
	}
	id, ok := s.Auth.AuthenticateBearer(token)
	if !ok {
		fleetJSONError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "invalid bearer token")
		return authz.Identity{}, false
	}
	if id.Role < minRole {
		fleetJSONError(w, http.StatusForbidden, "FORBIDDEN", "role does not permit fleet template operation")
		return authz.Identity{}, false
	}
	return id, true
}

func fleetProtoJSON(m proto.Message) any {
	if m == nil {
		return map[string]any{}
	}
	data, err := (protojson.MarshalOptions{UseProtoNames: false, EmitUnpopulated: false}).Marshal(m)
	if err != nil {
		return map[string]any{"marshalError": err.Error()}
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		return map[string]any{"marshalError": err.Error()}
	}
	return out
}

func fleetStatusError(w http.ResponseWriter, err error) {
	code := status.Code(err)
	switch code {
	case codes.InvalidArgument:
		fleetJSONError(w, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
	case codes.NotFound:
		fleetJSONError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
	case codes.FailedPrecondition:
		fleetJSONError(w, http.StatusPreconditionFailed, "FAILED_PRECONDITION", err.Error())
	case codes.PermissionDenied:
		fleetJSONError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
	case codes.Unauthenticated:
		fleetJSONError(w, http.StatusUnauthorized, "UNAUTHENTICATED", err.Error())
	default:
		fleetJSONError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
	}
}

func fleetWriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func fleetJSONError(w http.ResponseWriter, status int, code, message string) {
	fleetWriteJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

func fleetHAReady(ha *openngfwv1.HighAvailabilityStatus) bool {
	if ha == nil {
		return false
	}
	state := strings.ToLower(ha.GetState())
	syncState := strings.ToLower(ha.GetSync().GetState())
	return len(ha.GetBlockers()) == 0 && (state == "ready" || state == "standalone" || syncState == "synchronized" || syncState == "ready")
}
