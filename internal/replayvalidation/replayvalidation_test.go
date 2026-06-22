package replayvalidation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestValidateFlagsUnsafeCommitWithoutAcknowledgements(t *testing.T) {
	report := Validate(Request{
		Steps: []InputStep{{
			Type:   "api",
			Method: "POST",
			Path:   "/v1/commit",
			Body:   json.RawMessage(`{"comment":"replay"}`),
		}},
	}, State{HasCandidate: true, CandidateDirty: true, CandidateRevision: "sha256:current", CurrentStateLoaded: true}, fixedReplayTime())

	if !report.Summary.Blocked {
		t.Fatalf("report should be blocked")
	}
	if report.Summary.UnsafeMutationCount != 1 {
		t.Fatalf("unsafe count = %d, want 1", report.Summary.UnsafeMutationCount)
	}
	if report.Summary.MissingAcknowledgementCount != 2 {
		t.Fatalf("missing ack count = %d, want 2", report.Summary.MissingAcknowledgementCount)
	}
	if !report.Steps[0].WouldApplyRunning {
		t.Fatalf("commit should be classified as running mutation")
	}
}

func TestValidateNormalizesCurlAndRequiresCandidateRevision(t *testing.T) {
	report := Validate(Request{
		Runbook: `curl -sk -H "Authorization: Bearer ${PHRAGMA_TOKEN}" -H "Content-Type: application/json" -d '{"policy":{"rules":[]}}' -X PUT "${PHRAGMA_API_ORIGIN}/v1/candidate"`,
	}, State{HasCandidate: true, CandidateDirty: true, CandidateRevision: "sha256:current", CurrentStateLoaded: true}, fixedReplayTime())

	if len(report.Steps) != 1 {
		t.Fatalf("steps = %d, want 1", len(report.Steps))
	}
	step := report.Steps[0]
	if step.Method != "PUT" || step.Path != "/v1/candidate" {
		t.Fatalf("normalized step = %s %s", step.Method, step.Path)
	}
	if !step.WouldMutateCandidate {
		t.Fatalf("candidate PUT should mutate candidate")
	}
	if report.Summary.MissingRevisionCount != 1 {
		t.Fatalf("missing revision count = %d, want 1", report.Summary.MissingRevisionCount)
	}
}

func TestValidateAcceptsReadOnlyRunbook(t *testing.T) {
	report := Validate(Request{
		Steps: []InputStep{
			{Type: "api", Method: "GET", Path: "/v1/candidate/status"},
			{Type: "cli", Command: "ngfwctl policy diff"},
		},
	}, State{RunningVersion: 7, CandidateRevision: "sha256:current", CurrentStateLoaded: true}, fixedReplayTime())

	if report.Summary.Blocked {
		t.Fatalf("read-only report should not block: %+v", report.Issues)
	}
	if !report.Summary.ReplayAllowed {
		t.Fatalf("read-only report should be replay allowed")
	}
	if report.Summary.ExecutableStepCount != 2 {
		t.Fatalf("executable steps = %d, want 2", report.Summary.ExecutableStepCount)
	}
}

func TestDryRunPlanBlocksLiveApplyAndDoesNotGrantAuthority(t *testing.T) {
	report := Validate(Request{
		ExecutionMode: "dry-run",
		Steps: []InputStep{
			{Type: "api", Method: "GET", Path: "/v1/candidate/status"},
			{Type: "api", Method: "POST", Path: "/v1/commit", Body: json.RawMessage(`{"ackRisk":true,"ackRuntime":true}`)},
		},
	}, State{HasCandidate: true, CandidateDirty: true, CandidateRevision: "sha256:current", CurrentStateLoaded: true}, fixedReplayTime())

	if report.ExecutionPlan == nil {
		t.Fatalf("execution plan missing")
	}
	if report.ExecutionPlan.Mode != "dry-run" || !report.ExecutionPlan.DryRun || report.ExecutionPlan.AuthorityGranted {
		t.Fatalf("unexpected execution plan: %+v", report.ExecutionPlan)
	}
	if report.ExecutionPlan.ReadOnlySteps != 1 || report.ExecutionPlan.BlockedSteps != 1 {
		t.Fatalf("plan counts = readOnly %d blocked %d, want 1/1", report.ExecutionPlan.ReadOnlySteps, report.ExecutionPlan.BlockedSteps)
	}
	if report.Summary.LiveApplyBlockedCount != 1 {
		t.Fatalf("live apply blocked count = %d, want 1", report.Summary.LiveApplyBlockedCount)
	}
}

func TestApplyAuthorityRequiresReplayAcknowledgements(t *testing.T) {
	report := Validate(Request{
		ExecutionMode:     "apply-authority",
		CandidateRevision: "sha256:current",
		Acknowledgements: map[string]bool{
			"ackReplayAuthority":   true,
			"ackReplayNoLiveApply": true,
		},
		Steps: []InputStep{{
			Type:   "api",
			Method: "PUT",
			Path:   "/v1/candidate",
			Body:   json.RawMessage(`{"expectedCandidateRevision":"sha256:current","policy":{"rules":[]}}`),
		}},
	}, State{HasCandidate: true, CandidateDirty: true, CandidateRevision: "sha256:current", CurrentStateLoaded: true}, fixedReplayTime())

	if report.ExecutionPlan == nil {
		t.Fatalf("execution plan missing")
	}
	if report.ExecutionPlan.AuthorityGranted {
		t.Fatalf("authority should not be granted without candidate replay acknowledgements")
	}
	if got, want := report.ExecutionPlan.MissingAcks, []string{"ackCandidateOnlyReplay", "ackCandidateRevision"}; !sameStrings(got, want) {
		t.Fatalf("missing acks = %#v, want %#v", got, want)
	}
	if report.ExecutionPlan.CandidateOnlySteps != 1 || report.ExecutionPlan.BlockedSteps != 0 {
		t.Fatalf("plan counts = candidate %d blocked %d, want 1/0", report.ExecutionPlan.CandidateOnlySteps, report.ExecutionPlan.BlockedSteps)
	}
}

func TestApplyAuthorityGrantsCandidateOnlyWithAllAcksAndRevision(t *testing.T) {
	report := Validate(Request{
		ExecutionMode:     "apply-authority",
		CandidateRevision: "sha256:current",
		Acknowledgements: map[string]bool{
			"ackReplayAuthority":     true,
			"ackReplayNoLiveApply":   true,
			"ackCandidateOnlyReplay": true,
			"ackCandidateRevision":   true,
			"ackReadOnlyReplay":      true,
		},
		Steps: []InputStep{
			{Type: "api", Method: "GET", Path: "/v1/candidate/status"},
			{Type: "api", Method: "POST", Path: "/v1/candidate/validate", Body: json.RawMessage(`{}`)},
			{Type: "api", Method: "PUT", Path: "/v1/candidate", Body: json.RawMessage(`{"expectedCandidateRevision":"sha256:current","policy":{"rules":[]}}`)},
		},
	}, State{HasCandidate: true, CandidateDirty: true, CandidateRevision: "sha256:current", CurrentStateLoaded: true}, fixedReplayTime())

	if report.ExecutionPlan == nil || !report.ExecutionPlan.AuthorityGranted {
		t.Fatalf("authority should be granted for bounded read-only/candidate-only plan: %+v", report.ExecutionPlan)
	}
	if report.ExecutionPlan.ReadOnlySteps != 2 || report.ExecutionPlan.CandidateOnlySteps != 1 || report.ExecutionPlan.BlockedSteps != 0 {
		t.Fatalf("plan counts = readOnly %d candidate %d blocked %d, want 2/1/0", report.ExecutionPlan.ReadOnlySteps, report.ExecutionPlan.CandidateOnlySteps, report.ExecutionPlan.BlockedSteps)
	}
}

func TestExecutePlanUsesSameAuthorityAndMarksCandidateExecution(t *testing.T) {
	report := Validate(Request{
		ExecutionMode:     "execute",
		CandidateRevision: "sha256:current",
		Acknowledgements: map[string]bool{
			"ackReplayAuthority":     true,
			"ackReplayNoLiveApply":   true,
			"ackCandidateOnlyReplay": true,
			"ackCandidateRevision":   true,
			"ackReadOnlyReplay":      true,
		},
		Steps: []InputStep{
			{Type: "api", Method: "GET", Path: "/v1/candidate/status"},
			{Type: "api", Method: "PUT", Path: "/v1/candidate", Body: json.RawMessage(`{"expectedCandidateRevision":"sha256:current","policy":{"rules":[]}}`)},
		},
	}, State{HasCandidate: true, CandidateDirty: true, CandidateRevision: "sha256:current", CurrentStateLoaded: true}, fixedReplayTime())

	if report.ExecutionPlan == nil || !report.ExecutionPlan.AuthorityGranted {
		t.Fatalf("execute authority should be granted: %+v", report.ExecutionPlan)
	}
	if report.ExecutionPlan.Mode != "execute" || report.ExecutionPlan.DryRun {
		t.Fatalf("unexpected execute mode plan: %+v", report.ExecutionPlan)
	}
	if got := report.ExecutionPlan.Steps[0].Action; got != "read-only-observe" {
		t.Fatalf("read-only action = %q, want read-only-observe", got)
	}
	if got := report.ExecutionPlan.Steps[1].Action; got != "candidate-only-execute" {
		t.Fatalf("candidate action = %q, want candidate-only-execute", got)
	}
	joined := strings.Join(append(report.Boundaries, append(report.ExecutionPlan.Boundaries, report.Hardening...)...), "\n")
	for _, stale := range []string{
		"before execution exists",
		"caller-side executor",
	} {
		if strings.Contains(joined, stale) {
			t.Fatalf("replay report kept stale execution wording %q in:\n%s", stale, joined)
		}
	}
	if !strings.Contains(joined, "controld API executor is limited to read-only and candidate-safe replay steps") {
		t.Fatalf("replay boundaries do not describe bounded controld execute authority:\n%s", joined)
	}
	if !strings.Contains(joined, "before expanding beyond bounded candidate-safe execution") {
		t.Fatalf("replay hardening does not preserve expansion boundary:\n%s", joined)
	}
}

func TestExecutePlanStillBlocksLiveApply(t *testing.T) {
	report := Validate(Request{
		ExecutionMode: "execute",
		Acknowledgements: map[string]bool{
			"ackReplayAuthority":   true,
			"ackReplayNoLiveApply": true,
		},
		Steps: []InputStep{
			{Type: "api", Method: "POST", Path: "/v1/commit", Body: json.RawMessage(`{"ackRisk":true,"ackRuntime":true}`)},
		},
	}, State{HasCandidate: true, CandidateDirty: true, CandidateRevision: "sha256:current", CurrentStateLoaded: true}, fixedReplayTime())

	if report.ExecutionPlan == nil {
		t.Fatalf("execution plan missing")
	}
	if report.ExecutionPlan.AuthorityGranted {
		t.Fatalf("execute authority should not be granted for live apply")
	}
	if report.ExecutionPlan.BlockedSteps != 1 || report.Summary.LiveApplyBlockedCount != 1 {
		t.Fatalf("blocked counts = plan %d live %d, want 1/1", report.ExecutionPlan.BlockedSteps, report.Summary.LiveApplyBlockedCount)
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func fixedReplayTime() time.Time {
	return time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
}
