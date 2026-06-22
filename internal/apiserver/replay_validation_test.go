package apiserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/engines"
)

func TestAutomationReplayValidationHandlerReportsUnsafeMutation(t *testing.T) {
	svc := &SystemService{}
	body := []byte(`{"steps":[{"method":"POST","path":"/v1/commit","body":{"comment":"replay"}}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/system/automation/replay:validate", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	svc.AutomationReplayValidationHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var report struct {
		SchemaVersion string `json:"schemaVersion"`
		Summary       struct {
			Blocked                     bool `json:"blocked"`
			UnsafeMutationCount         int  `json:"unsafeMutationCount"`
			MissingAcknowledgementCount int  `json:"missingAcknowledgementCount"`
		} `json:"summary"`
		Boundaries []string `json:"boundaries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if report.SchemaVersion != "phragma.automation.replay-validation.v1" {
		t.Fatalf("schemaVersion = %q", report.SchemaVersion)
	}
	if !report.Summary.Blocked || report.Summary.UnsafeMutationCount != 1 || report.Summary.MissingAcknowledgementCount != 2 {
		t.Fatalf("unexpected summary: %+v", report.Summary)
	}
	if len(report.Boundaries) == 0 {
		t.Fatalf("response should include validation-only boundaries")
	}
}

func TestAutomationReplayValidationHandlerReturnsDryRunPlan(t *testing.T) {
	svc := &SystemService{}
	body := []byte(`{"executionMode":"dry-run","steps":[{"method":"GET","path":"/v1/candidate/status"},{"method":"POST","path":"/v1/commit","body":{"ackRisk":true,"ackRuntime":true}}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/system/automation/replay:validate", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	svc.AutomationReplayValidationHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var report struct {
		ExecutionPlan struct {
			SchemaVersion    string `json:"schemaVersion"`
			Mode             string `json:"mode"`
			DryRun           bool   `json:"dryRun"`
			AuthorityGranted bool   `json:"authorityGranted"`
			ReadOnlySteps    int    `json:"readOnlySteps"`
			BlockedSteps     int    `json:"blockedSteps"`
		} `json:"executionPlan"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if report.ExecutionPlan.SchemaVersion != "phragma.automation.replay-execution-plan.v1" {
		t.Fatalf("plan schema = %q", report.ExecutionPlan.SchemaVersion)
	}
	if report.ExecutionPlan.Mode != "dry-run" || !report.ExecutionPlan.DryRun || report.ExecutionPlan.AuthorityGranted {
		t.Fatalf("unexpected plan: %+v", report.ExecutionPlan)
	}
	if report.ExecutionPlan.ReadOnlySteps != 1 || report.ExecutionPlan.BlockedSteps != 1 {
		t.Fatalf("plan counts = readOnly %d blocked %d, want 1/1", report.ExecutionPlan.ReadOnlySteps, report.ExecutionPlan.BlockedSteps)
	}
}

func TestAutomationReplayValidationHandlerExecutesAuditedCandidateReplay(t *testing.T) {
	st := newSystemAuditStore(t)
	if err := st.SetCandidate(referencePolicyFixture()); err != nil {
		t.Fatalf("SetCandidate: %v", err)
	}
	revision, err := st.CandidateRevision()
	if err != nil {
		t.Fatalf("CandidateRevision: %v", err)
	}
	svc := &SystemService{
		Store: st,
		Policy: NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
			return map[string][]byte{"nftables": []byte("table inet filter {}")}, nil
		}),
	}
	stepBody, err := protojson.Marshal(&openngfwv1.SetCandidateRequest{
		Policy:                    validReferencePolicy(),
		ExpectedCandidateRevision: revision,
	})
	if err != nil {
		t.Fatalf("marshal replay step body: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"executionMode":     "execute",
		"candidateRevision": revision,
		"acknowledgements": map[string]bool{
			"ackReplayAuthority":     true,
			"ackReplayNoLiveApply":   true,
			"ackCandidateOnlyReplay": true,
			"ackCandidateRevision":   true,
		},
		"steps": []map[string]any{{
			"method": "PUT",
			"path":   "/v1/candidate",
			"body":   json.RawMessage(stepBody),
		}},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/system/automation/replay:validate", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	svc.AutomationReplayValidationHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var report struct {
		ExecutionPlan struct {
			Mode             string `json:"mode"`
			AuthorityGranted bool   `json:"authorityGranted"`
		} `json:"executionPlan"`
		ExecutionResult struct {
			SchemaVersion string `json:"schemaVersion"`
			Status        string `json:"status"`
			Results       []struct {
				Status                 string `json:"status"`
				Mutation               string `json:"mutation"`
				AuditAction            string `json:"auditAction"`
				CandidateRevisionAfter string `json:"candidateRevisionAfter"`
			} `json:"results"`
		} `json:"executionResult"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if report.ExecutionPlan.Mode != "execute" || !report.ExecutionPlan.AuthorityGranted {
		t.Fatalf("unexpected plan: %+v", report.ExecutionPlan)
	}
	if report.ExecutionResult.SchemaVersion != "phragma.automation.replay-execution-result.v1" || report.ExecutionResult.Status != "completed" {
		t.Fatalf("unexpected execution result: %+v", report.ExecutionResult)
	}
	if len(report.ExecutionResult.Results) != 1 || report.ExecutionResult.Results[0].Status != "applied" || report.ExecutionResult.Results[0].Mutation != "candidate" {
		t.Fatalf("unexpected step results: %+v", report.ExecutionResult.Results)
	}
	if report.ExecutionResult.Results[0].AuditAction != "automation-replay-set-candidate" || report.ExecutionResult.Results[0].CandidateRevisionAfter == "" {
		t.Fatalf("missing audit/revision result: %+v", report.ExecutionResult.Results[0])
	}
	entries, err := st.ListAudit(5)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	var found bool
	for _, entry := range entries {
		if entry.Action == "automation-replay-set-candidate" && strings.Contains(entry.Detail, "bounded=true") {
			found = true
		}
	}
	if !found {
		t.Fatalf("automation replay candidate audit not found in %#v", entries)
	}
}

func TestAutomationReplayValidationHandlerExecuteBlocksLiveApply(t *testing.T) {
	st := newSystemAuditStore(t)
	svc := &SystemService{Store: st}
	body := []byte(`{"executionMode":"execute","acknowledgements":{"ackReplayAuthority":true,"ackReplayNoLiveApply":true},"steps":[{"method":"POST","path":"/v1/commit","body":{"ackRisk":true,"ackRuntime":true}}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/system/automation/replay:validate", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	svc.AutomationReplayValidationHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var report struct {
		ExecutionPlan struct {
			AuthorityGranted bool `json:"authorityGranted"`
			BlockedSteps     int  `json:"blockedSteps"`
		} `json:"executionPlan"`
		ExecutionResult struct {
			Status  string `json:"status"`
			Results []struct {
				Action string `json:"action"`
				Status string `json:"status"`
				Detail string `json:"detail"`
			} `json:"results"`
		} `json:"executionResult"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if report.ExecutionPlan.AuthorityGranted || report.ExecutionPlan.BlockedSteps != 1 {
		t.Fatalf("unexpected plan: %+v", report.ExecutionPlan)
	}
	if report.ExecutionResult.Status != "blocked" || len(report.ExecutionResult.Results) != 1 || report.ExecutionResult.Results[0].Status != "blocked" {
		t.Fatalf("unexpected execution result: %+v", report.ExecutionResult)
	}
	if !strings.Contains(report.ExecutionResult.Results[0].Detail, "authority-granted") {
		t.Fatalf("unexpected block detail: %+v", report.ExecutionResult.Results[0])
	}
}
