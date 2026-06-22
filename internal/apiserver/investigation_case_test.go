package apiserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/detailtech/oss-ngfw/internal/store"
)

func TestInvestigationCaseHandlerCreatesListsGetsAppendsAndAudits(t *testing.T) {
	svc, cleanup := newInvestigationCaseTestService(t)
	defer cleanup()
	handler := svc.InvestigationCaseHandler()

	createResp := investigationCaseTestRequest(t, handler, http.MethodPost, "/v1/investigation/cases", map[string]any{
		"packet": map[string]any{
			"summary": map[string]any{
				"itemCount": 1,
				"rootCause": map[string]any{
					"title": "Threat evidence ready",
				},
			},
			"notes": "safe note with token=super-secret and /var/log/openngfw/eve.json",
		},
		"evidence": []map[string]any{{
			"kind":  "alert",
			"title": "Suspicious shell",
			"subject": map[string]any{
				"id": "alert-1",
			},
			"route": "#/threats?flowId=flow-1&token=super-secret",
		}},
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	location := createResp.Header().Get("Location")
	if !strings.HasPrefix(location, "/v1/investigation/cases/case-") {
		t.Fatalf("Location = %q, want created case path", location)
	}
	createBody := decodeInvestigationCaseBody(t, createResp)
	record := createBody["case"].(map[string]any)
	caseID := record["id"].(string)
	if record["title"] != "Threat evidence ready" || record["evidenceCount"] != float64(1) {
		t.Fatalf("created case = %#v, want title from packet and one evidence item", record)
	}
	rawCreate := createResp.Body.String()
	if strings.Contains(rawCreate, "super-secret") || strings.Contains(rawCreate, "/var/log/openngfw/eve.json") {
		t.Fatalf("created case leaked sensitive content: %s", rawCreate)
	}
	if !strings.Contains(rawCreate, "[redacted]") || !strings.Contains(rawCreate, "[server-local path redacted]") {
		t.Fatalf("created case did not include redaction markers: %s", rawCreate)
	}

	listResp := investigationCaseTestRequest(t, handler, http.MethodGet, "/v1/investigation/cases?state=open&limit=10", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", listResp.Code, listResp.Body.String())
	}
	listBody := decodeInvestigationCaseBody(t, listResp)
	cases := listBody["cases"].([]any)
	if len(cases) != 1 || cases[0].(map[string]any)["id"] != caseID {
		t.Fatalf("list cases = %#v, want created case %s", cases, caseID)
	}

	appendResp := investigationCaseTestRequest(t, handler, http.MethodPost, "/v1/investigation/cases/"+caseID+"/evidence", map[string]any{
		"evidence": []map[string]any{{
			"kind":  "flow",
			"title": "Flow tuple",
			"subject": map[string]any{
				"id": "flow-1",
			},
		}},
	})
	if appendResp.Code != http.StatusOK {
		t.Fatalf("append status = %d body=%s", appendResp.Code, appendResp.Body.String())
	}
	appendBody := decodeInvestigationCaseBody(t, appendResp)
	updated := appendBody["case"].(map[string]any)
	if updated["evidenceCount"] != float64(2) {
		t.Fatalf("updated evidenceCount = %#v, want 2", updated["evidenceCount"])
	}

	getResp := investigationCaseTestRequest(t, handler, http.MethodGet, "/v1/investigation/cases/"+caseID, nil)
	if getResp.Code != http.StatusOK {
		t.Fatalf("get status = %d body=%s", getResp.Code, getResp.Body.String())
	}
	getBody := decodeInvestigationCaseBody(t, getResp)
	gotCase := getBody["case"].(map[string]any)
	if gotCase["id"] != caseID || gotCase["evidenceCount"] != float64(2) {
		t.Fatalf("get case = %#v, want appended case %s", gotCase, caseID)
	}

	createAudit, err := svc.Store.ListAuditFiltered(store.AuditFilter{Action: "investigation-case-create", Limit: 1})
	if err != nil {
		t.Fatalf("list create audit: %v", err)
	}
	if len(createAudit) != 1 || !strings.Contains(createAudit[0].Detail, "case_id="+caseID) {
		t.Fatalf("create audit = %#v, want case id detail", createAudit)
	}
	appendAudit, err := svc.Store.ListAuditFiltered(store.AuditFilter{Action: "investigation-case-add-evidence", Limit: 1})
	if err != nil {
		t.Fatalf("list append audit: %v", err)
	}
	if len(appendAudit) != 1 || !strings.Contains(appendAudit[0].Detail, "evidence_count=2") {
		t.Fatalf("append audit = %#v, want evidence count detail", appendAudit)
	}
}

func TestInvestigationCaseHandlerRejectsInvalidCaseIDAndAuth(t *testing.T) {
	svc, cleanup := newInvestigationCaseTestService(t)
	defer cleanup()
	handler := svc.InvestigationCaseHandler()

	invalidResp := investigationCaseTestRequest(t, handler, http.MethodGet, "/v1/investigation/cases/not-a-case", nil)
	if invalidResp.Code != http.StatusBadRequest {
		t.Fatalf("invalid id status = %d body=%s", invalidResp.Code, invalidResp.Body.String())
	}
	assertInvestigationCaseErrorCode(t, invalidResp, "INVALID_CASE_ID")

	svc.Status.AuthEnabled = true
	unauthResp := investigationCaseTestRequest(t, handler, http.MethodPost, "/v1/investigation/cases", map[string]any{
		"packet": map[string]any{},
	})
	if unauthResp.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status = %d body=%s", unauthResp.Code, unauthResp.Body.String())
	}
	assertInvestigationCaseErrorCode(t, unauthResp, "UNAUTHENTICATED")
}

func TestInvestigationCaseHandlerRejectsEmptyEvidenceAppend(t *testing.T) {
	svc, cleanup := newInvestigationCaseTestService(t)
	defer cleanup()
	handler := svc.InvestigationCaseHandler()

	createResp := investigationCaseTestRequest(t, handler, http.MethodPost, "/v1/investigation/cases", map[string]any{
		"packet":   map[string]any{"summary": map[string]any{"itemCount": 1}},
		"evidence": []map[string]any{{"kind": "flow", "title": "Initial flow"}},
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	caseID := decodeInvestigationCaseBody(t, createResp)["case"].(map[string]any)["id"].(string)

	emptyResp := investigationCaseTestRequest(t, handler, http.MethodPost, "/v1/investigation/cases/"+caseID+"/evidence", map[string]any{
		"evidence": []map[string]any{},
	})
	if emptyResp.Code != http.StatusBadRequest {
		t.Fatalf("empty append status = %d body=%s", emptyResp.Code, emptyResp.Body.String())
	}
	assertInvestigationCaseErrorCode(t, emptyResp, "INVALID_EVIDENCE")

	getResp := investigationCaseTestRequest(t, handler, http.MethodGet, "/v1/investigation/cases/"+caseID, nil)
	if getResp.Code != http.StatusOK {
		t.Fatalf("get status = %d body=%s", getResp.Code, getResp.Body.String())
	}
	gotCase := decodeInvestigationCaseBody(t, getResp)["case"].(map[string]any)
	if gotCase["evidenceCount"] != float64(1) {
		t.Fatalf("empty append mutated evidence count: %#v", gotCase)
	}
	appendAudit, err := svc.Store.ListAuditFiltered(store.AuditFilter{Action: "investigation-case-add-evidence", Limit: 5})
	if err != nil {
		t.Fatalf("list append audit: %v", err)
	}
	if len(appendAudit) != 0 {
		t.Fatalf("empty append wrote audit entries: %#v", appendAudit)
	}
}

func TestInvestigationCaseHandlerRejectsEvidenceLimitOverflow(t *testing.T) {
	svc, cleanup := newInvestigationCaseTestService(t)
	defer cleanup()
	handler := svc.InvestigationCaseHandler()

	evidence := make([]map[string]any, 0, maxInvestigationEvidenceItems)
	for i := 0; i < maxInvestigationEvidenceItems; i++ {
		evidence = append(evidence, map[string]any{"kind": "flow", "title": "Initial flow", "subject": map[string]any{"id": i}})
	}
	createResp := investigationCaseTestRequest(t, handler, http.MethodPost, "/v1/investigation/cases", map[string]any{
		"packet":   map[string]any{"summary": map[string]any{"itemCount": maxInvestigationEvidenceItems}},
		"evidence": evidence,
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	caseID := decodeInvestigationCaseBody(t, createResp)["case"].(map[string]any)["id"].(string)

	overflowResp := investigationCaseTestRequest(t, handler, http.MethodPost, "/v1/investigation/cases/"+caseID+"/evidence", map[string]any{
		"evidence": []map[string]any{{"kind": "alert", "title": "Overflow alert"}},
	})
	if overflowResp.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("overflow status = %d body=%s", overflowResp.Code, overflowResp.Body.String())
	}
	assertInvestigationCaseErrorCode(t, overflowResp, "EVIDENCE_LIMIT_EXCEEDED")

	getResp := investigationCaseTestRequest(t, handler, http.MethodGet, "/v1/investigation/cases/"+caseID, nil)
	if getResp.Code != http.StatusOK {
		t.Fatalf("get status = %d body=%s", getResp.Code, getResp.Body.String())
	}
	gotCase := decodeInvestigationCaseBody(t, getResp)["case"].(map[string]any)
	if gotCase["evidenceCount"] != float64(maxInvestigationEvidenceItems) {
		t.Fatalf("overflow append mutated evidence count: %#v", gotCase)
	}
}

func TestInvestigationCaseHandlerPersistsBoundedTargetCustody(t *testing.T) {
	svc, cleanup := newInvestigationCaseTestService(t)
	defer cleanup()
	handler := svc.InvestigationCaseHandler()

	createResp := investigationCaseTestRequest(t, handler, http.MethodPost, "/v1/investigation/cases", map[string]any{
		"packet": map[string]any{"summary": map[string]any{"itemCount": 1}},
		"evidence": []map[string]any{{
			"kind":        "flow",
			"key":         strings.Repeat("k", 400),
			"title":       "/var/log/openngfw/eve.json token=super-secret " + strings.Repeat("Suspicious target ", 30),
			"pinnedAt":    "2026-06-18T12:00:01.000Z",
			"collectedAt": "2026-06-18T12:00:00.000Z",
			"subject": map[string]any{
				"id":    "flow-1",
				"label": "Flow evidence",
			},
			"source": map[string]any{
				"interface": "traffic",
				"route":     "#/traffic?flowId=flow-1&path=/var/log/openngfw/eve.json&token=super-secret",
			},
			"packet": map[string]any{
				"kind": "flow",
				"source": map[string]any{
					"interface": "traffic",
					"route":     "#/traffic?flowId=flow-1&token=super-secret",
				},
			},
		}},
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	record := decodeInvestigationCaseBody(t, createResp)["case"].(map[string]any)
	caseID := record["id"].(string)
	firstEvidence := record["evidence"].([]any)[0].(map[string]any)
	target := firstEvidence["target"].(map[string]any)
	if target["kind"] != "flow" || target["source"] != "traffic" || target["pinnedAt"] != "2026-06-18T12:00:01.000Z" || target["collectedAt"] != "2026-06-18T12:00:00.000Z" {
		t.Fatalf("target custody = %#v, want kind/source/timestamps", target)
	}
	if target["addedAt"] == "" {
		t.Fatalf("target addedAt missing: %#v", target)
	}
	if len(target["key"].(string)) > 240 || len(target["title"].(string)) > 240 || len(target["route"].(string)) > maxInvestigationTargetRoute {
		t.Fatalf("target custody not capped: %#v", target)
	}
	rawTarget, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("marshal target: %v", err)
	}
	if strings.Contains(string(rawTarget), "super-secret") || strings.Contains(string(rawTarget), "/var/log/openngfw/eve.json") {
		t.Fatalf("target custody leaked sensitive content: %s", rawTarget)
	}
	if !strings.Contains(string(rawTarget), "[redacted]") || !strings.Contains(string(rawTarget), "[server-local path redacted]") {
		t.Fatalf("target custody missing redaction markers: %s", rawTarget)
	}

	appendResp := investigationCaseTestRequest(t, handler, http.MethodPost, "/v1/investigation/cases/"+caseID+"/evidence", map[string]any{
		"evidence": []map[string]any{{
			"kind":  "alert",
			"key":   "alert:flow-1:#/threats?flowId=flow-1",
			"title": "Hydrated alert",
			"target": map[string]any{
				"kind":        "alert",
				"key":         "alert-target",
				"route":       "#/threats?flowId=flow-1&password=super-secret",
				"source":      "server-hydrated",
				"title":       "Hydrated source record",
				"pinnedAt":    "2026-06-18T12:05:01.000Z",
				"collectedAt": "2026-06-18T12:05:00.000Z",
			},
		}},
	})
	if appendResp.Code != http.StatusOK {
		t.Fatalf("append status = %d body=%s", appendResp.Code, appendResp.Body.String())
	}
	updated := decodeInvestigationCaseBody(t, appendResp)["case"].(map[string]any)
	evidence := updated["evidence"].([]any)
	appendedTarget := evidence[1].(map[string]any)["target"].(map[string]any)
	if appendedTarget["kind"] != "alert" || appendedTarget["key"] != "alert-target" || appendedTarget["source"] != "server-hydrated" {
		t.Fatalf("appended target custody = %#v, want hydrated target marker", appendedTarget)
	}
	if strings.Contains(appendedTarget["route"].(string), "super-secret") || !strings.Contains(appendedTarget["route"].(string), "[redacted]") {
		t.Fatalf("appended target route was not redacted: %#v", appendedTarget)
	}
}

func TestInvestigationCaseHandlerSynthesizesRetainedMultiFlowRecords(t *testing.T) {
	svc, cleanup := newInvestigationCaseTestService(t)
	defer cleanup()
	handler := svc.InvestigationCaseHandler()

	createResp := investigationCaseTestRequest(t, handler, http.MethodPost, "/v1/investigation/cases", map[string]any{
		"packet": map[string]any{"summary": map[string]any{"itemCount": 3}},
		"evidence": []map[string]any{
			{
				"kind":  "flow",
				"title": "Flow tuple",
				"target": map[string]any{
					"route": "#/traffic?flowId=flow-77",
				},
				"subject": map[string]any{
					"id": "flow-77",
					"tuple": map[string]any{
						"flowId":   "flow-77",
						"protocol": "TCP",
						"srcIp":    "10.0.1.20",
						"srcPort":  "51515",
						"destIp":   "10.0.2.20",
						"destPort": "443",
					},
				},
				"packet": map[string]any{"artifacts": map[string]any{"flow": map[string]any{
					"flowId":   "flow-77",
					"srcIp":    "10.0.1.20",
					"destIp":   "10.0.2.20",
					"destPort": "443",
				}}},
			},
			{
				"kind":  "alert",
				"title": "Threat alert",
				"target": map[string]any{
					"route": "#/threats?flowId=flow-77",
				},
				"subject": map[string]any{"id": "flow-77"},
				"packet": map[string]any{"artifacts": map[string]any{"alert": map[string]any{
					"flowId":      "flow-77",
					"signatureId": "9000001",
				}}},
			},
			{
				"kind":  "capture",
				"title": "Packet proof",
				"target": map[string]any{
					"route": "#/troubleshoot?flowId=flow-77&intent=capture",
				},
				"subject": map[string]any{"id": "flow-77"},
				"packet": map[string]any{"artifacts": map[string]any{
					"query": map[string]any{"flowId": "flow-77"},
					"capturePlan": map[string]any{
						"interface": "ens5",
						"srcIp":     "10.0.1.20",
						"destIp":    "10.0.2.20",
					},
				}},
			},
		},
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	record := decodeInvestigationCaseBody(t, createResp)["case"].(map[string]any)
	synthesis := record["synthesis"].(map[string]any)
	if synthesis["schemaVersion"] != investigationSynthesisSchema {
		t.Fatalf("synthesis schema = %#v", synthesis["schemaVersion"])
	}
	if synthesis["mutatesPolicy"] != false || synthesis["createsTicket"] != false {
		t.Fatalf("synthesis crossed mutation boundary: %#v", synthesis)
	}
	coverage := synthesis["coverage"].(map[string]any)
	if coverage["multiRecordGroups"] != float64(1) || coverage["captureProofRecords"] != float64(1) {
		t.Fatalf("coverage = %#v, want multi-record group with packet proof", coverage)
	}
	confidence := synthesis["confidence"].(map[string]any)
	if confidence["level"] != "high" {
		t.Fatalf("confidence = %#v, want high", confidence)
	}
	actions := synthesis["actions"].([]any)
	if len(actions) == 0 {
		t.Fatalf("actions = %#v, want candidate-safe owner actions", actions)
	}
	if !strings.Contains(createResp.Body.String(), "does not commit") {
		t.Fatalf("synthesis limitations missing no-mutation boundary: %s", createResp.Body.String())
	}

	listResp := investigationCaseTestRequest(t, handler, http.MethodGet, "/v1/investigation/cases?state=open", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", listResp.Code, listResp.Body.String())
	}
	listed := decodeInvestigationCaseBody(t, listResp)["cases"].([]any)[0].(map[string]any)
	if listed["synthesis"].(map[string]any)["schemaVersion"] != investigationSynthesisSchema {
		t.Fatalf("listed synthesis = %#v", listed["synthesis"])
	}
}

func TestInvestigationCaseHandlerPatchesLifecycleAndAudits(t *testing.T) {
	svc, cleanup := newInvestigationCaseTestService(t)
	defer cleanup()
	handler := svc.InvestigationCaseHandler()

	createResp := investigationCaseTestRequest(t, handler, http.MethodPost, "/v1/investigation/cases", map[string]any{
		"packet":   map[string]any{"summary": map[string]any{"itemCount": 1}},
		"evidence": []map[string]any{{"kind": "alert", "title": "Initial alert"}},
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	caseID := decodeInvestigationCaseBody(t, createResp)["case"].(map[string]any)["id"].(string)

	patchResp := investigationCaseTestRequest(t, handler, http.MethodPatch, "/v1/investigation/cases/"+caseID, map[string]any{
		"title":          "Resolved shell alert",
		"state":          "resolved",
		"resolutionNote": "operator reviewed token=super-secret and /var/log/openngfw/eve.json",
	})
	if patchResp.Code != http.StatusOK {
		t.Fatalf("patch status = %d body=%s", patchResp.Code, patchResp.Body.String())
	}
	patchBody := patchResp.Body.String()
	if strings.Contains(patchBody, "super-secret") || strings.Contains(patchBody, "/var/log/openngfw/eve.json") {
		t.Fatalf("patched case leaked sensitive content: %s", patchBody)
	}
	record := decodeInvestigationCaseBody(t, patchResp)["case"].(map[string]any)
	if record["title"] != "Resolved shell alert" || record["state"] != "resolved" {
		t.Fatalf("patched case = %#v, want resolved title/state", record)
	}
	if !strings.Contains(record["resolutionNote"].(string), "[redacted]") || !strings.Contains(record["resolutionNote"].(string), "[server-local path redacted]") {
		t.Fatalf("resolution note not redacted: %#v", record["resolutionNote"])
	}
	if record["resolvedAt"] == "" || record["resolvedBy"] == "" {
		t.Fatalf("resolved metadata missing: %#v", record)
	}

	listResp := investigationCaseTestRequest(t, handler, http.MethodGet, "/v1/investigation/cases?state=resolved", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("list resolved status = %d body=%s", listResp.Code, listResp.Body.String())
	}
	cases := decodeInvestigationCaseBody(t, listResp)["cases"].([]any)
	if len(cases) != 1 || cases[0].(map[string]any)["id"] != caseID {
		t.Fatalf("resolved cases = %#v, want %s", cases, caseID)
	}

	audit, err := svc.Store.ListAuditFiltered(store.AuditFilter{Action: "investigation-case-update", Limit: 1})
	if err != nil {
		t.Fatalf("list update audit: %v", err)
	}
	if len(audit) != 1 {
		t.Fatalf("update audit = %#v, want one entry", audit)
	}
	detail := audit[0].Detail
	for _, want := range []string{"case_id=" + caseID, "old_state=open", "new_state=resolved", "resolution_note_set=true"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("audit detail = %q, missing %q", detail, want)
		}
	}
	if strings.Contains(detail, "super-secret") || strings.Contains(detail, "var/log") || strings.Contains(detail, "operator reviewed") {
		t.Fatalf("audit detail leaked resolution note: %q", detail)
	}
}

func TestInvestigationCaseHandlerRejectsInvalidLifecyclePatch(t *testing.T) {
	svc, cleanup := newInvestigationCaseTestService(t)
	defer cleanup()
	handler := svc.InvestigationCaseHandler()

	createResp := investigationCaseTestRequest(t, handler, http.MethodPost, "/v1/investigation/cases", map[string]any{
		"packet":   map[string]any{"summary": map[string]any{"itemCount": 1}},
		"evidence": []map[string]any{{"kind": "flow", "title": "Initial flow"}},
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	caseID := decodeInvestigationCaseBody(t, createResp)["case"].(map[string]any)["id"].(string)

	invalidState := investigationCaseTestRequest(t, handler, http.MethodPatch, "/v1/investigation/cases/"+caseID, map[string]any{"state": "archived"})
	if invalidState.Code != http.StatusBadRequest {
		t.Fatalf("invalid state status = %d body=%s", invalidState.Code, invalidState.Body.String())
	}
	assertInvestigationCaseErrorCode(t, invalidState, "INVALID_CASE_STATE")

	missingNote := investigationCaseTestRequest(t, handler, http.MethodPatch, "/v1/investigation/cases/"+caseID, map[string]any{"state": "closed"})
	if missingNote.Code != http.StatusBadRequest {
		t.Fatalf("missing note status = %d body=%s", missingNote.Code, missingNote.Body.String())
	}
	assertInvestigationCaseErrorCode(t, missingNote, "INVALID_CASE_PATCH")

	emptyTitle := investigationCaseTestRequest(t, handler, http.MethodPatch, "/v1/investigation/cases/"+caseID, map[string]any{"title": "   "})
	if emptyTitle.Code != http.StatusBadRequest {
		t.Fatalf("empty title status = %d body=%s", emptyTitle.Code, emptyTitle.Body.String())
	}
	assertInvestigationCaseErrorCode(t, emptyTitle, "INVALID_CASE_PATCH")

	unknown := investigationCaseTestRequest(t, handler, http.MethodPatch, "/v1/investigation/cases/case-20260622T000000Z-ffffffff", map[string]any{"title": "Unknown"})
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown status = %d body=%s", unknown.Code, unknown.Body.String())
	}
	assertInvestigationCaseErrorCode(t, unknown, "CASE_NOT_FOUND")
}

func TestInvestigationCaseHandlerRollsBackCreateWhenAuditFails(t *testing.T) {
	svc, cleanup := newInvestigationCaseTestService(t)
	defer cleanup()
	handler := svc.InvestigationCaseHandler()
	if err := svc.Store.Close(); err != nil {
		t.Fatalf("close store before create: %v", err)
	}

	createResp := investigationCaseTestRequest(t, handler, http.MethodPost, "/v1/investigation/cases", map[string]any{
		"packet": map[string]any{
			"summary": map[string]any{"itemCount": 1},
		},
		"evidence": []map[string]any{{"kind": "flow", "title": "Flow tuple"}},
	})
	if createResp.Code != http.StatusInternalServerError {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	assertInvestigationCaseErrorCode(t, createResp, "CASE_AUDIT_FAILED")

	listResp := investigationCaseTestRequest(t, handler, http.MethodGet, "/v1/investigation/cases", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", listResp.Code, listResp.Body.String())
	}
	cases := decodeInvestigationCaseBody(t, listResp)["cases"].([]any)
	if len(cases) != 0 {
		t.Fatalf("case persisted after create audit failure: %#v", cases)
	}
}

func TestInvestigationCaseHandlerRollsBackAppendWhenAuditFails(t *testing.T) {
	svc, cleanup := newInvestigationCaseTestService(t)
	defer cleanup()
	handler := svc.InvestigationCaseHandler()

	createResp := investigationCaseTestRequest(t, handler, http.MethodPost, "/v1/investigation/cases", map[string]any{
		"packet":   map[string]any{"summary": map[string]any{"itemCount": 1}},
		"evidence": []map[string]any{{"kind": "alert", "title": "Initial alert"}},
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	caseID := decodeInvestigationCaseBody(t, createResp)["case"].(map[string]any)["id"].(string)
	if err := svc.Store.Close(); err != nil {
		t.Fatalf("close store before append: %v", err)
	}

	appendResp := investigationCaseTestRequest(t, handler, http.MethodPost, "/v1/investigation/cases/"+caseID+"/evidence", map[string]any{
		"evidence": []map[string]any{{"kind": "flow", "title": "Unaudited append"}},
	})
	if appendResp.Code != http.StatusInternalServerError {
		t.Fatalf("append status = %d body=%s", appendResp.Code, appendResp.Body.String())
	}
	assertInvestigationCaseErrorCode(t, appendResp, "CASE_AUDIT_FAILED")

	getResp := investigationCaseTestRequest(t, handler, http.MethodGet, "/v1/investigation/cases/"+caseID, nil)
	if getResp.Code != http.StatusOK {
		t.Fatalf("get status = %d body=%s", getResp.Code, getResp.Body.String())
	}
	gotCase := decodeInvestigationCaseBody(t, getResp)["case"].(map[string]any)
	if gotCase["evidenceCount"] != float64(1) {
		t.Fatalf("append persisted after audit failure: %#v", gotCase)
	}
}

func TestInvestigationCaseHandlerRollsBackPatchWhenAuditFails(t *testing.T) {
	svc, cleanup := newInvestigationCaseTestService(t)
	defer cleanup()
	handler := svc.InvestigationCaseHandler()

	createResp := investigationCaseTestRequest(t, handler, http.MethodPost, "/v1/investigation/cases", map[string]any{
		"packet":   map[string]any{"summary": map[string]any{"itemCount": 1}},
		"evidence": []map[string]any{{"kind": "alert", "title": "Initial alert"}},
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", createResp.Code, createResp.Body.String())
	}
	caseID := decodeInvestigationCaseBody(t, createResp)["case"].(map[string]any)["id"].(string)
	if err := svc.Store.Close(); err != nil {
		t.Fatalf("close store before patch: %v", err)
	}

	patchResp := investigationCaseTestRequest(t, handler, http.MethodPatch, "/v1/investigation/cases/"+caseID, map[string]any{
		"title":          "Unaudited closure",
		"state":          "closed",
		"resolutionNote": "reviewed",
	})
	if patchResp.Code != http.StatusInternalServerError {
		t.Fatalf("patch status = %d body=%s", patchResp.Code, patchResp.Body.String())
	}
	assertInvestigationCaseErrorCode(t, patchResp, "CASE_AUDIT_FAILED")

	getResp := investigationCaseTestRequest(t, handler, http.MethodGet, "/v1/investigation/cases/"+caseID, nil)
	if getResp.Code != http.StatusOK {
		t.Fatalf("get status = %d body=%s", getResp.Code, getResp.Body.String())
	}
	gotCase := decodeInvestigationCaseBody(t, getResp)["case"].(map[string]any)
	if gotCase["title"] == "Unaudited closure" || gotCase["state"] != "open" || gotCase["resolutionNote"] != nil {
		t.Fatalf("patch persisted after audit failure: %#v", gotCase)
	}
}

func newInvestigationCaseTestService(t *testing.T) (*SystemService, func()) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	svc := &SystemService{
		Store: st,
		Status: SystemStatusConfig{
			DataDir: t.TempDir(),
		},
	}
	return svc, func() { _ = st.Close() }
}

func investigationCaseTestRequest(t *testing.T, handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
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

func decodeInvestigationCaseBody(t *testing.T, resp *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response JSON: %v body=%s", err, resp.Body.String())
	}
	return body
}

func assertInvestigationCaseErrorCode(t *testing.T, resp *httptest.ResponseRecorder, want string) {
	t.Helper()
	body := decodeInvestigationCaseBody(t, resp)
	errBody, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("error body = %#v, want error object", body)
	}
	if errBody["code"] != want {
		t.Fatalf("error code = %#v, want %q", errBody["code"], want)
	}
}
