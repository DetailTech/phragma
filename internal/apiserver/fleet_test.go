package apiserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/engines"
	"github.com/detailtech/oss-ngfw/internal/store"
)

func TestFleetHandlerCreatesListsValidatesAndPreviewsLocalTemplate(t *testing.T) {
	svc, cleanup := newFleetHandlerTestService(t)
	defer cleanup()
	handler := svc.FleetHandler()

	createResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates", map[string]any{
		"name":        "Branch Edge",
		"description": "Local branch appliance baseline",
		"scope":       "local-appliance",
		"labels":      []string{"Prod Edge", "prod-edge"},
		"policy":      fleetHandlerPolicyJSON(t),
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	location := createResp.Header().Get("Location")
	if !strings.HasPrefix(location, "/v1/fleet/templates/tmpl-branch-edge-") {
		t.Fatalf("Location = %q, want created template path", location)
	}
	createBody := decodeFleetBody(t, createResp)
	template := createBody["template"].(map[string]any)
	templateID := template["id"].(string)
	if template["createdBy"] != "local" || template["createdByRole"] != "admin" || template["authSource"] != "disabled-local" {
		t.Fatalf("template identity = %#v, want disabled-auth local admin", template)
	}
	summary := template["policySummary"].(map[string]any)
	if summary["rules"] != float64(1) || summary["zones"] != float64(2) || summary["securityProfiles"] != float64(1) {
		t.Fatalf("policySummary = %#v, want local policy counts", summary)
	}

	listResp := fleetTestRequest(t, handler, http.MethodGet, "/v1/fleet/templates", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", listResp.Code, listResp.Body.String())
	}
	listBody := decodeFleetBody(t, listResp)
	if listBody["scope"] != "local-appliance template registry" || listBody["count"] != float64(1) {
		t.Fatalf("list body = %#v, want local registry scope and one template", listBody)
	}
	assertFleetBoundaries(t, listBody["boundaries"], []string{
		"unsigned local drafts",
		"do not mutate candidate or running policy",
		"through Changes before commit",
	})

	validateResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates/"+templateID+":validate", map[string]any{})
	if validateResp.Code != http.StatusOK {
		t.Fatalf("validate status = %d body=%s", validateResp.Code, validateResp.Body.String())
	}
	validateBody := decodeFleetBody(t, validateResp)
	if validateBody["mutated"] != false {
		t.Fatalf("validate mutated = %#v, want false", validateBody["mutated"])
	}
	validation := validateBody["validation"].(map[string]any)
	if validation["valid"] != true {
		t.Fatalf("validation = %#v, want valid template policy", validation)
	}

	if err := svc.Store.SetCandidate(&openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "candidate"}}}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}
	candidateRevision, err := svc.Store.CandidateRevision()
	if err != nil {
		t.Fatalf("CandidateRevision: %v", err)
	}
	previewResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates/"+templateID+":apply-preview", map[string]any{
		"expectedCandidateRevision": candidateRevision,
	})
	if previewResp.Code != http.StatusOK {
		t.Fatalf("preview status = %d body=%s", previewResp.Code, previewResp.Body.String())
	}
	previewBody := decodeFleetBody(t, previewResp)
	if previewBody["candidateRevision"] != candidateRevision {
		t.Fatalf("candidateRevision = %#v, want %q", previewBody["candidateRevision"], candidateRevision)
	}
	if previewBody["wouldMutateCandidate"] != false || previewBody["wouldApplyRunningPolicy"] != false {
		t.Fatalf("preview mutation flags = %#v", previewBody)
	}
	if !strings.Contains(previewBody["orchestrationBoundary"].(string), "local preview only") {
		t.Fatalf("orchestrationBoundary = %q, want local preview boundary", previewBody["orchestrationBoundary"])
	}
	afterRevision, err := svc.Store.CandidateRevision()
	if err != nil {
		t.Fatalf("CandidateRevision after preview: %v", err)
	}
	if afterRevision != candidateRevision {
		t.Fatalf("preview changed candidate revision from %q to %q", candidateRevision, afterRevision)
	}
}

func TestFleetHandlerBuildsMultiNodeApplyPlanWithoutMutation(t *testing.T) {
	svc, cleanup := newFleetHandlerTestService(t)
	defer cleanup()
	handler := svc.FleetHandler()

	createResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates", map[string]any{
		"name":   "Apply Plan",
		"policy": fleetHandlerPolicyJSON(t),
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	templateID := decodeFleetBody(t, createResp)["template"].(map[string]any)["id"].(string)
	if err := svc.Store.SetCandidate(&openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "candidate"}}}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}
	candidateRevision, err := svc.Store.CandidateRevision()
	if err != nil {
		t.Fatalf("CandidateRevision: %v", err)
	}
	planResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates/"+templateID+":apply-plan", map[string]any{
		"expectedCandidateRevision": candidateRevision,
		"nodes": []map[string]any{
			{"id": "fw-peer-ready", "name": "fw-peer-ready", "role": "passive", "runtimeState": "ready", "runningVersion": 17, "haReady": true},
			{"id": "fw-peer-blocked", "name": "fw-peer-blocked", "role": "passive", "runtimeState": "degraded", "runningVersion": 0, "haReady": false},
		},
	})
	if planResp.Code != http.StatusOK {
		t.Fatalf("apply plan status = %d body=%s", planResp.Code, planResp.Body.String())
	}
	body := decodeFleetBody(t, planResp)
	if body["candidateRevision"] != candidateRevision {
		t.Fatalf("candidateRevision = %#v, want %q", body["candidateRevision"], candidateRevision)
	}
	if body["wouldMutateCandidate"] != false || body["wouldApplyRunningPolicy"] != false || body["wouldCallPeerRPC"] != false {
		t.Fatalf("apply plan mutation flags = %#v", body)
	}
	if body["nodeCount"] != float64(3) || body["eligibleNodeCount"] != float64(1) || body["blockedNodeCount"] != float64(2) {
		t.Fatalf("node counts = node:%#v eligible:%#v blocked:%#v", body["nodeCount"], body["eligibleNodeCount"], body["blockedNodeCount"])
	}
	nodes := body["nodes"].([]any)
	ready := nodes[1].(map[string]any)
	if ready["id"] != "fw-peer-ready" || ready["eligible"] != true || ready["executionHandoff"] == "" {
		t.Fatalf("ready peer result = %#v, want eligible handoff", ready)
	}
	blocked := nodes[2].(map[string]any)
	if blocked["eligible"] != false || !strings.Contains(strings.Join(fleetAnyStringList(blocked["blockers"]), ";"), "runtime readiness") {
		t.Fatalf("blocked peer result = %#v, want runtime blocker", blocked)
	}
	if !strings.Contains(body["orchestrationBoundary"].(string), "no peer RPC") {
		t.Fatalf("orchestrationBoundary = %q, want no peer RPC boundary", body["orchestrationBoundary"])
	}
	afterRevision, err := svc.Store.CandidateRevision()
	if err != nil {
		t.Fatalf("CandidateRevision after apply plan: %v", err)
	}
	if afterRevision != candidateRevision {
		t.Fatalf("apply plan changed candidate revision from %q to %q", candidateRevision, afterRevision)
	}
}

func TestFleetHandlerAppliesLocalCandidateAndRetainsPeerResults(t *testing.T) {
	svc, cleanup := newFleetHandlerTestService(t)
	defer cleanup()
	handler := svc.FleetHandler()

	createResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates", map[string]any{
		"name":   "Apply Result",
		"policy": fleetHandlerPolicyJSON(t),
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	templateID := decodeFleetBody(t, createResp)["template"].(map[string]any)["id"].(string)
	if err := svc.Store.SetCandidate(&openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "candidate"}}}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}
	candidateRevision, err := svc.Store.CandidateRevision()
	if err != nil {
		t.Fatalf("CandidateRevision: %v", err)
	}
	applyResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates/"+templateID+":apply", map[string]any{
		"expectedCandidateRevision": candidateRevision,
		"comment":                   "bounded apply test",
		"nodes": []map[string]any{
			{"id": "fw-peer-ready", "name": "fw-peer-ready", "role": "passive", "runtimeState": "ready", "runningVersion": 17, "haReady": true},
			{"id": "fw-peer-blocked", "name": "fw-peer-blocked", "role": "passive", "runtimeState": "degraded", "runningVersion": 0, "haReady": false},
		},
	})
	if applyResp.Code != http.StatusOK {
		t.Fatalf("apply status = %d body=%s", applyResp.Code, applyResp.Body.String())
	}
	body := decodeFleetBody(t, applyResp)
	if body["mutated"] != true || body["runningPolicyApplied"] != false || body["wouldCallPeerRPC"] != false {
		t.Fatalf("apply flags = %#v", body)
	}
	if body["candidateRevision"] == "" || body["candidateRevision"] == candidateRevision {
		t.Fatalf("candidateRevision = %#v, want new revision", body["candidateRevision"])
	}
	applyResult := body["applyResult"].(map[string]any)
	if applyResult["status"] != "applied" || !strings.Contains(applyResult["custodyBoundary"].(string), "unsigned") {
		t.Fatalf("applyResult = %#v, want applied unsigned custody", applyResult)
	}
	nodeResults := applyResult["nodeResults"].([]any)
	if len(nodeResults) != 3 {
		t.Fatalf("nodeResults len = %d, want 3", len(nodeResults))
	}
	got := map[string]string{}
	for _, raw := range nodeResults {
		node := raw.(map[string]any)
		got[node["nodeId"].(string)] = node["result"].(string)
	}
	if got["local"] != "applied" || got["fw-peer-ready"] != "skipped" || got["fw-peer-blocked"] != "blocked" {
		t.Fatalf("node result statuses = %#v", got)
	}
	resultsResp := fleetTestRequest(t, handler, http.MethodGet, "/v1/fleet/template-results?templateId="+templateID, nil)
	if resultsResp.Code != http.StatusOK {
		t.Fatalf("results status = %d body=%s", resultsResp.Code, resultsResp.Body.String())
	}
	resultsBody := decodeFleetBody(t, resultsResp)
	if resultsBody["count"] != float64(1) {
		t.Fatalf("results body = %#v, want one retained result", resultsBody)
	}
	retained := resultsBody["results"].([]any)[0].(map[string]any)
	if retained["id"] != applyResult["id"] || retained["templateId"] != templateID {
		t.Fatalf("retained result = %#v, want apply result id and template", retained)
	}
	audit, err := svc.Store.ListAuditFiltered(store.AuditFilter{Action: "fleet-template-apply", Limit: 1})
	if err != nil {
		t.Fatalf("ListAuditFiltered: %v", err)
	}
	if len(audit) != 1 || !strings.Contains(audit[0].Detail, "bounded apply test") {
		t.Fatalf("audit = %#v, want fleet apply custody comment", audit)
	}
}

func TestFleetHandlerRejectsStaleApplyPlan(t *testing.T) {
	svc, cleanup := newFleetHandlerTestService(t)
	defer cleanup()
	handler := svc.FleetHandler()

	createResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates", map[string]any{
		"name":   "Stale Plan",
		"policy": fleetHandlerPolicyJSON(t),
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	templateID := decodeFleetBody(t, createResp)["template"].(map[string]any)["id"].(string)
	if err := svc.Store.SetCandidate(&openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "candidate"}}}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}
	staleResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates/"+templateID+":apply-plan", map[string]any{
		"expectedCandidateRevision": "sha256:stale",
		"nodes":                     []map[string]any{{"id": "fw-peer-ready", "runtimeState": "ready", "runningVersion": 17, "haReady": true}},
	})
	if staleResp.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale apply plan status = %d body=%s", staleResp.Code, staleResp.Body.String())
	}
	assertFleetErrorCode(t, staleResp, "CANDIDATE_REVISION_CONFLICT")

	staleApplyResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates/"+templateID+":apply", map[string]any{
		"expectedCandidateRevision": "sha256:stale",
		"comment":                   "stale apply",
		"nodes":                     []map[string]any{{"id": "fw-peer-ready", "runtimeState": "ready", "runningVersion": 17, "haReady": true}},
	})
	if staleApplyResp.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale apply status = %d body=%s", staleApplyResp.Code, staleApplyResp.Body.String())
	}
	assertFleetErrorCode(t, staleApplyResp, "CANDIDATE_REVISION_CONFLICT")
}

func TestFleetHandlerRejectsBadTemplateRequestsAndStalePreview(t *testing.T) {
	svc, cleanup := newFleetHandlerTestService(t)
	defer cleanup()
	handler := svc.FleetHandler()

	badPolicyResp := fleetRawTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates", `{"name":"bad","policy":{"zones":`)
	if badPolicyResp.Code != http.StatusBadRequest {
		t.Fatalf("bad policy status = %d body=%s", badPolicyResp.Code, badPolicyResp.Body.String())
	}
	assertFleetErrorCode(t, badPolicyResp, "INVALID_JSON")

	createResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates", map[string]any{
		"name":   "Preview Conflict",
		"policy": fleetHandlerPolicyJSON(t),
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	templateID := decodeFleetBody(t, createResp)["template"].(map[string]any)["id"].(string)
	if err := svc.Store.SetCandidate(&openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "candidate"}}}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}
	staleResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates/"+templateID+":apply-preview", map[string]any{
		"expectedCandidateRevision": "sha256:stale",
	})
	if staleResp.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale preview status = %d body=%s", staleResp.Code, staleResp.Body.String())
	}
	assertFleetErrorCode(t, staleResp, "CANDIDATE_REVISION_CONFLICT")

	missingResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates/tmpl-missing00:validate", map[string]any{})
	if missingResp.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d body=%s", missingResp.Code, missingResp.Body.String())
	}
	assertFleetErrorCode(t, missingResp, "TEMPLATE_NOT_FOUND")

	invalidIDResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates/not-a-template:validate", map[string]any{})
	if invalidIDResp.Code != http.StatusBadRequest {
		t.Fatalf("invalid id status = %d body=%s", invalidIDResp.Code, invalidIDResp.Body.String())
	}
	assertFleetErrorCode(t, invalidIDResp, "INVALID_TEMPLATE_ID")
}

func TestFleetHandlerStagesTemplateCandidateWithRevisionGuardAndAudit(t *testing.T) {
	svc, cleanup := newFleetHandlerTestService(t)
	defer cleanup()
	handler := svc.FleetHandler()

	createResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates", map[string]any{
		"name":   "Stage Candidate",
		"policy": fleetHandlerPolicyJSON(t),
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	templateID := decodeFleetBody(t, createResp)["template"].(map[string]any)["id"].(string)

	if err := svc.Store.SetCandidate(&openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "candidate"}}}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}
	expectedRevision, err := svc.Store.CandidateRevision()
	if err != nil {
		t.Fatalf("CandidateRevision: %v", err)
	}
	stageResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates/"+templateID+":stage-candidate", map[string]any{
		"expectedCandidateRevision": expectedRevision,
		"comment":                   "stage from fleet template test",
	})
	if stageResp.Code != http.StatusOK {
		t.Fatalf("stage status = %d body=%s", stageResp.Code, stageResp.Body.String())
	}
	body := decodeFleetBody(t, stageResp)
	if body["stagedCandidate"] != true || body["runningPolicyApplied"] != false {
		t.Fatalf("stage flags = %#v, want candidate-only stage", body)
	}
	nextRevision := body["candidateRevision"].(string)
	if nextRevision == "" || nextRevision == expectedRevision {
		t.Fatalf("candidateRevision = %q, want new revision different from %q", nextRevision, expectedRevision)
	}
	if !strings.Contains(body["orchestrationBoundary"].(string), "no peer fan-out") {
		t.Fatalf("orchestrationBoundary = %q, want explicit local-only boundary", body["orchestrationBoundary"])
	}
	candidate, ok, err := svc.Store.GetCandidate()
	if err != nil || !ok {
		t.Fatalf("GetCandidate = ok %v err %v", ok, err)
	}
	firstRule := ""
	if len(candidate.GetRules()) > 0 {
		firstRule = candidate.GetRules()[0].GetName()
	}
	if len(candidate.GetZones()) != 2 || len(candidate.GetRules()) != 1 || firstRule != "allow-web" {
		t.Fatalf("candidate was not replaced by stored template policy: zones=%d rules=%d first_rule=%q", len(candidate.GetZones()), len(candidate.GetRules()), firstRule)
	}
	audit, err := svc.Store.ListAuditFiltered(store.AuditFilter{Action: "fleet-template-stage-candidate", Limit: 1})
	if err != nil {
		t.Fatalf("ListAuditFiltered: %v", err)
	}
	if len(audit) != 1 || !strings.Contains(audit[0].Detail, "template="+templateID) || !strings.Contains(audit[0].Detail, "stage from fleet template test") {
		t.Fatalf("stage audit = %#v, want template id and comment", audit)
	}
}

func TestFleetHandlerRejectsStaleTemplateStageCandidate(t *testing.T) {
	svc, cleanup := newFleetHandlerTestService(t)
	defer cleanup()
	handler := svc.FleetHandler()

	createResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates", map[string]any{
		"name":   "Stale Stage",
		"policy": fleetHandlerPolicyJSON(t),
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	templateID := decodeFleetBody(t, createResp)["template"].(map[string]any)["id"].(string)
	if err := svc.Store.SetCandidate(&openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "candidate"}}}); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}
	staleResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates/"+templateID+":stage-candidate", map[string]any{
		"expectedCandidateRevision": "sha256:stale",
	})
	if staleResp.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale stage status = %d body=%s", staleResp.Code, staleResp.Body.String())
	}
	assertFleetErrorCode(t, staleResp, "CANDIDATE_REVISION_CONFLICT")
	candidate, ok, err := svc.Store.GetCandidate()
	if err != nil || !ok {
		t.Fatalf("GetCandidate = ok %v err %v", ok, err)
	}
	if got := candidate.GetZones()[0].GetName(); got != "candidate" {
		t.Fatalf("candidate zone = %q, want original candidate after stale stage", got)
	}
}

func TestFleetHandlerRejectsInvalidTemplateStageCandidate(t *testing.T) {
	svc, cleanup := newFleetHandlerTestService(t)
	defer cleanup()
	handler := svc.FleetHandler()

	createResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates", map[string]any{
		"name":   "Invalid Stage",
		"policy": fleetInvalidTemplatePolicyJSON(t),
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	templateID := decodeFleetBody(t, createResp)["template"].(map[string]any)["id"].(string)
	expectedRevision, err := svc.Store.CandidateRevision()
	if err != nil {
		t.Fatalf("CandidateRevision: %v", err)
	}
	stageResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates/"+templateID+":stage-candidate", map[string]any{
		"expectedCandidateRevision": expectedRevision,
	})
	if stageResp.Code != http.StatusBadRequest {
		t.Fatalf("invalid stage status = %d body=%s", stageResp.Code, stageResp.Body.String())
	}
	assertFleetErrorCode(t, stageResp, "TEMPLATE_VALIDATION_FAILED")
	if _, ok, err := svc.Store.GetCandidate(); err != nil || ok {
		t.Fatalf("invalid template stage mutated candidate: ok=%v err=%v", ok, err)
	}
}

func TestFleetHandlerFailsClosedWhenStageCandidateAuditFails(t *testing.T) {
	svc, cleanup := newFleetHandlerTestService(t)
	defer cleanup()
	handler := svc.FleetHandler()

	createResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates", map[string]any{
		"name":   "Stage Audit Failure",
		"policy": fleetHandlerPolicyJSON(t),
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	templateID := decodeFleetBody(t, createResp)["template"].(map[string]any)["id"].(string)
	original := &openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "candidate"}}}
	if err := svc.Store.SetCandidate(original); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}
	expectedRevision, err := svc.Store.CandidateRevision()
	if err != nil {
		t.Fatalf("CandidateRevision: %v", err)
	}
	svc.Policy.render = func(*openngfwv1.Policy) (map[string][]byte, error) {
		if err := svc.Store.Close(); err != nil {
			t.Fatalf("close store during validation: %v", err)
		}
		return map[string][]byte{}, nil
	}
	stageResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates/"+templateID+":stage-candidate", map[string]any{
		"expectedCandidateRevision": expectedRevision,
	})
	if stageResp.Code != http.StatusInternalServerError {
		t.Fatalf("audit failure stage status = %d body=%s", stageResp.Code, stageResp.Body.String())
	}
	assertFleetErrorCode(t, stageResp, "AUDIT_WRITE_FAILED")
}

func TestFleetHandlerListsOnlyLocalNodeAndAuthGate(t *testing.T) {
	svc, cleanup := newFleetHandlerTestService(t)
	defer cleanup()
	handler := svc.FleetHandler()

	nodesResp := fleetTestRequest(t, handler, http.MethodGet, "/v1/fleet/nodes", nil)
	if nodesResp.Code != http.StatusOK {
		t.Fatalf("nodes status = %d body=%s", nodesResp.Code, nodesResp.Body.String())
	}
	nodesBody := decodeFleetBody(t, nodesResp)
	nodes := nodesBody["nodes"].([]any)
	if len(nodes) != 1 {
		t.Fatalf("nodes length = %d, want local-only inventory", len(nodes))
	}
	node := nodes[0].(map[string]any)
	if node["id"] != "local" || node["scope"] != "local-appliance" || node["authoritative"] != true {
		t.Fatalf("node = %#v, want authoritative local appliance", node)
	}
	assertFleetBoundaries(t, nodesBody["boundaries"], []string{
		"not authoritative multi-node fleet inventory",
		"no peer enrollment or discovery",
		"no fan-out apply",
		"no HA fencing",
	})

	svc.Status.AuthEnabled = true
	unauthResp := fleetTestRequest(t, handler, http.MethodGet, "/v1/fleet/templates", nil)
	if unauthResp.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status = %d body=%s", unauthResp.Code, unauthResp.Body.String())
	}
	assertFleetErrorCode(t, unauthResp, "UNAUTHENTICATED")
}

func TestFleetHandlerFailsClosedWhenTemplateAuditFails(t *testing.T) {
	svc, cleanup := newFleetHandlerTestService(t)
	defer cleanup()
	handler := svc.FleetHandler()
	if err := svc.Store.Close(); err != nil {
		t.Fatalf("close store before create: %v", err)
	}

	createResp := fleetTestRequest(t, handler, http.MethodPost, "/v1/fleet/templates", map[string]any{
		"name":   "Audit Failure",
		"policy": fleetHandlerPolicyJSON(t),
	})
	if createResp.Code != http.StatusInternalServerError {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	if got := createResp.Header().Get("Location"); got != "" {
		t.Fatalf("Location = %q, want no success location on audit failure", got)
	}
	body := decodeFleetBody(t, createResp)
	if _, ok := body["template"]; ok {
		t.Fatalf("audit failure response included success template body: %#v", body)
	}
	assertFleetErrorCode(t, createResp, "AUDIT_WRITE_FAILED")

	listResp := fleetTestRequest(t, handler, http.MethodGet, "/v1/fleet/templates", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", listResp.Code, listResp.Body.String())
	}
	listBody := decodeFleetBody(t, listResp)
	if listBody["count"] != float64(0) {
		t.Fatalf("templates persisted after audit failure: %#v", listBody)
	}
}

func newFleetHandlerTestService(t *testing.T) (*SystemService, func()) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	policy := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	svc := &SystemService{
		Store:  st,
		Policy: policy,
		Status: SystemStatusConfig{
			DataDir:         t.TempDir(),
			ActiveDataplane: "nftables",
		},
	}
	return svc, func() { _ = st.Close() }
}

func fleetTestRequest(t *testing.T, handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	return resp
}

func fleetRawTestRequest(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	return resp
}

func decodeFleetBody(t *testing.T, resp *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response JSON: %v body=%s", err, resp.Body.String())
	}
	return body
}

func assertFleetErrorCode(t *testing.T, resp *httptest.ResponseRecorder, want string) {
	t.Helper()
	body := decodeFleetBody(t, resp)
	errBody, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("error body = %#v, want error object", body)
	}
	if errBody["code"] != want {
		t.Fatalf("error code = %#v, want %q", errBody["code"], want)
	}
}

func assertFleetBoundaries(t *testing.T, raw any, wants []string) {
	t.Helper()
	values, ok := raw.([]any)
	if !ok {
		t.Fatalf("boundaries = %#v, want array", raw)
	}
	joined := ""
	for _, value := range values {
		joined += value.(string) + "\n"
	}
	for _, want := range wants {
		if !strings.Contains(joined, want) {
			t.Fatalf("boundaries %q missing %q", joined, want)
		}
	}
}

func fleetAnyStringList(value any) []string {
	raw, _ := value.([]any)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func fleetHandlerPolicyJSON(t *testing.T) json.RawMessage {
	t.Helper()
	raw, err := protojson.MarshalOptions{UseProtoNames: false}.Marshal(validReferencePolicy())
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	return raw
}

func fleetInvalidTemplatePolicyJSON(t *testing.T) json.RawMessage {
	t.Helper()
	raw, err := protojson.MarshalOptions{UseProtoNames: false}.Marshal(&openngfwv1.Policy{
		Rules: []*openngfwv1.Rule{{
			Name:      "bad-zone-ref",
			FromZones: []string{"missing"},
			Action:    openngfwv1.Action_ACTION_ALLOW,
		}},
	})
	if err != nil {
		t.Fatalf("marshal invalid policy: %v", err)
	}
	return raw
}
