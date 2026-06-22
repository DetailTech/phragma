package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestActorWithRole(t *testing.T) {
	tests := []struct {
		actor string
		role  string
		want  string
	}{
		{actor: "alice", role: "admin", want: "alice/admin"},
		{actor: "bob", want: "bob"},
		{role: "operator", want: "-/operator"},
		{want: "-"},
	}
	for _, tt := range tests {
		if got := actorWithRole(tt.actor, tt.role); got != tt.want {
			t.Fatalf("actorWithRole(%q, %q) = %q, want %q", tt.actor, tt.role, got, tt.want)
		}
	}
}

func TestParseAuditTimeBound(t *testing.T) {
	rfc, err := parseAuditTimeBound("2026-06-17T12:30:00-04:00", false)
	if err != nil {
		t.Fatal(err)
	}
	if rfc != time.Date(2026, 6, 17, 16, 30, 0, 0, time.UTC) {
		t.Fatalf("RFC3339 parsed as %s", rfc)
	}

	start, err := parseAuditTimeBound("2026-06-17", false)
	if err != nil {
		t.Fatal(err)
	}
	if start != time.Date(2026, 6, 17, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("date start parsed as %s", start)
	}

	end, err := parseAuditTimeBound("2026-06-17", true)
	if err != nil {
		t.Fatal(err)
	}
	if end != time.Date(2026, 6, 17, 23, 59, 59, int(time.Second-time.Nanosecond), time.UTC) {
		t.Fatalf("date end parsed as %s", end)
	}

	if _, err := parseAuditTimeBound("06/17/2026", false); err == nil {
		t.Fatal("expected invalid date error")
	}
}

func TestAuditEntryLineShowsHashes(t *testing.T) {
	entry := &openngfwv1.AuditEntry{
		Id:        7,
		Time:      timestamppb.New(time.Date(2026, 6, 17, 12, 30, 0, 0, time.UTC)),
		Actor:     "alice",
		ActorRole: "admin",
		Action:    "commit",
		Detail:    "baseline",
		Version:   4,
		EntryHash: strings.Repeat("a", 64),
	}
	got := auditEntryLine(entry, true)
	for _, want := range []string{"alice/admin", "commit", "baseline", "version 4", "hash=aaaaaaaaaaaa", "prev=genesis"} {
		if !strings.Contains(got, want) {
			t.Fatalf("audit line %q missing %q", got, want)
		}
	}

	entry.PreviousHash = strings.Repeat("b", 64)
	got = auditEntryLine(entry, true)
	if !strings.Contains(got, "prev=bbbbbbbbbbbb") {
		t.Fatalf("audit line %q missing shortened previous hash", got)
	}
}

func TestAuditVerifyLine(t *testing.T) {
	resp := &openngfwv1.VerifyAuditIntegrityResponse{
		Ok:              true,
		EntryCount:      12,
		LatestEntryHash: strings.Repeat("c", 64),
		Detail:          "audit hash chain verified",
	}
	got := auditVerifyLine(resp)
	for _, want := range []string{"OK", "entries=12", "latest=cccccccccccc", "audit hash chain verified"} {
		if !strings.Contains(got, want) {
			t.Fatalf("verify line %q missing %q", got, want)
		}
	}
}

func TestHandleCommitPreflightRequiresAckForHighRisk(t *testing.T) {
	cmd, stdout, _ := preflightCommandForTest()
	resp := &openngfwv1.ValidateResponse{
		Valid: true,
		Impact: &openngfwv1.ChangeImpact{
			Risk: openngfwv1.ChangeRisk_CHANGE_RISK_HIGH,
			Items: []*openngfwv1.ChangeImpactItem{{
				Risk:   openngfwv1.ChangeRisk_CHANGE_RISK_HIGH,
				Title:  "Active broad allow rule",
				Detail: "allow-any permits any source to any destination/service.",
			}},
		},
	}

	err := handleCommitPreflight(cmd, resp, readyRuntimeForTest(), false, false)
	if err == nil || !strings.Contains(err.Error(), "--ack-risk") {
		t.Fatalf("expected --ack-risk error, got %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"candidate is valid", "impact: high", "Active broad allow rule"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in stdout %q", want, out)
		}
	}
}

func TestCommitCommandRequiresAuditCommentBeforeDial(t *testing.T) {
	server := "127.0.0.1:1"
	cmd := newCommitCommand(&server)

	err := cmd.RunE(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "commit comment is required") {
		t.Fatalf("expected missing comment error, got %v", err)
	}
}

func TestCommitCommandRejectsWhitespaceAuditCommentBeforeDial(t *testing.T) {
	server := "127.0.0.1:1"
	cmd := newCommitCommand(&server)
	if err := cmd.Flags().Set("message", "   "); err != nil {
		t.Fatal(err)
	}

	err := cmd.RunE(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "commit comment is required") {
		t.Fatalf("expected missing comment error, got %v", err)
	}
}

func TestNewCommitRequestIncludesApprovalIDAndReviewedRevision(t *testing.T) {
	req := newCommitRequest(" approved maintenance ", true, true, " approval-7 ", " sha256:reviewed ")
	if req.GetComment() != "approved maintenance" ||
		!req.GetAckRisk() ||
		!req.GetAckRuntime() ||
		req.GetApprovalId() != "approval-7" ||
		req.GetReviewedCandidateRevision() != "sha256:reviewed" {
		t.Fatalf("commit request = %+v", req)
	}
}

func TestCommitReviewedCandidateRevisionUsesCurrentStatus(t *testing.T) {
	client := &fakeCommitStatusClient{
		resp: &openngfwv1.GetCandidateStatusResponse{
			HasCandidate:      true,
			CandidateRevision: " sha256:current ",
		},
	}
	revision, err := commitReviewedCandidateRevision(context.Background(), client, "")
	if err != nil {
		t.Fatalf("commitReviewedCandidateRevision returned error: %v", err)
	}
	if revision != "sha256:current" {
		t.Fatalf("revision = %q, want sha256:current", revision)
	}
	if client.calls != 1 {
		t.Fatalf("status calls = %d, want 1", client.calls)
	}
}

func TestCommitReviewedCandidateRevisionUsesExplicitRevision(t *testing.T) {
	client := &fakeCommitStatusClient{}
	revision, err := commitReviewedCandidateRevision(context.Background(), client, " sha256:reviewed ")
	if err != nil {
		t.Fatalf("commitReviewedCandidateRevision returned error: %v", err)
	}
	if revision != "sha256:reviewed" {
		t.Fatalf("revision = %q, want sha256:reviewed", revision)
	}
	if client.calls != 0 {
		t.Fatalf("status calls = %d, want 0", client.calls)
	}
}

func TestCommitReviewedCandidateRevisionRequiresCandidate(t *testing.T) {
	_, err := commitReviewedCandidateRevision(context.Background(), &fakeCommitStatusClient{
		resp: &openngfwv1.GetCandidateStatusResponse{},
	}, "")
	if err == nil || !strings.Contains(err.Error(), "no candidate policy is set") {
		t.Fatalf("expected no candidate error, got %v", err)
	}
}

func TestCommitErrorExplainsStaleCandidateRecovery(t *testing.T) {
	err := commitError(grpcstatus.Error(codes.FailedPrecondition, "candidate changed since commit review"))
	if err == nil {
		t.Fatal("commitError returned nil")
	}
	msg := err.Error()
	for _, want := range []string{
		"candidate changed since commit review",
		"ngfwctl policy status",
		"ngfwctl policy diff",
		"--candidate-revision <revision>",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("stale commit error missing %q: %s", want, msg)
		}
	}
}

func TestHandleCommitPreflightAllowsAckedHighRisk(t *testing.T) {
	cmd, _, _ := preflightCommandForTest()
	resp := &openngfwv1.ValidateResponse{
		Valid:  true,
		Impact: &openngfwv1.ChangeImpact{Risk: openngfwv1.ChangeRisk_CHANGE_RISK_HIGH},
	}

	if err := handleCommitPreflight(cmd, resp, readyRuntimeForTest(), true, false); err != nil {
		t.Fatalf("handleCommitPreflight returned error: %v", err)
	}
}

func TestHandleCommitPreflightAllowsMediumRiskWithoutAck(t *testing.T) {
	cmd, _, _ := preflightCommandForTest()
	resp := &openngfwv1.ValidateResponse{
		Valid:  true,
		Impact: &openngfwv1.ChangeImpact{Risk: openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM},
	}

	if err := handleCommitPreflight(cmd, resp, readyRuntimeForTest(), false, false); err != nil {
		t.Fatalf("handleCommitPreflight returned error: %v", err)
	}
}

func TestHandleCommitPreflightRequiresAckForRuntimeWarnings(t *testing.T) {
	cmd, stdout, _ := preflightCommandForTest()
	resp := &openngfwv1.ValidateResponse{
		Valid:  true,
		Impact: &openngfwv1.ChangeImpact{Risk: openngfwv1.ChangeRisk_CHANGE_RISK_LOW},
	}
	runtime := cliRuntimePreflight(&openngfwv1.GetStatusResponse{
		Runtime: &openngfwv1.RuntimeStatus{DryRun: true, ActiveDataplane: "nftables"},
	}, nil, nil, nil)

	err := handleCommitPreflight(cmd, resp, runtime, false, false)
	if err == nil || !strings.Contains(err.Error(), "--ack-runtime") {
		t.Fatalf("expected --ack-runtime error, got %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"candidate is valid", "runtime: not-ready", "dry-run mode"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in stdout %q", want, out)
		}
	}
	if err := handleCommitPreflight(cmd, resp, runtime, false, true); err != nil {
		t.Fatalf("acked runtime should pass: %v", err)
	}
}

func TestHandleCommitPreflightRequiresAckForServerRuntimeReadiness(t *testing.T) {
	cmd, stdout, _ := preflightCommandForTest()
	resp := &openngfwv1.ValidateResponse{
		Valid:  true,
		Impact: &openngfwv1.ChangeImpact{Risk: openngfwv1.ChangeRisk_CHANGE_RISK_LOW},
	}
	runtime := cliRuntimePreflightFromResponse(&openngfwv1.CheckRuntimeReadinessResponse{
		Label:       "Runtime warnings need acknowledgement",
		RequiresAck: true,
		Items: []*openngfwv1.RuntimeReadinessItem{{
			Level:   "warning",
			Title:   "Threat-ID content is not production ready",
			Detail:  "Import verified Threat-ID content before Prevent mode.",
			Command: "ngfwctl intel content",
		}},
	})

	err := handleCommitPreflight(cmd, resp, runtime, false, false)
	if err == nil || !strings.Contains(err.Error(), "--ack-runtime") {
		t.Fatalf("expected --ack-runtime error, got %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"runtime: Runtime warnings need acknowledgement", "Threat-ID content is not production ready", "ngfwctl intel content"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in stdout %q", want, out)
		}
	}
	if err := handleCommitPreflight(cmd, resp, runtime, false, true); err != nil {
		t.Fatalf("acked runtime should pass: %v", err)
	}
}

func TestHandleCommitPreflightRejectsInvalidCandidate(t *testing.T) {
	cmd, stdout, stderr := preflightCommandForTest()
	resp := &openngfwv1.ValidateResponse{
		Valid:  false,
		Errors: []string{`rule "bad": unknown zone "dmz"`},
		Impact: &openngfwv1.ChangeImpact{
			Risk:  openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM,
			Items: []*openngfwv1.ChangeImpactItem{{Risk: openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, Title: "Rule match changed"}},
		},
	}

	err := handleCommitPreflight(cmd, resp, readyRuntimeForTest(), true, false)
	if err == nil || !strings.Contains(err.Error(), "candidate is invalid") {
		t.Fatalf("expected invalid candidate error, got %v", err)
	}
	if !strings.Contains(stderr.String(), `error: rule "bad": unknown zone "dmz"`) {
		t.Fatalf("missing validation error in stderr %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "impact: medium") {
		t.Fatalf("missing impact summary in stdout %q", stdout.String())
	}
}

func TestHandleRollbackPreflightRequiresAckForHighRisk(t *testing.T) {
	cmd, stdout, _ := preflightCommandForTest()
	resp := &openngfwv1.ValidateResponse{
		Valid: true,
		Impact: &openngfwv1.ChangeImpact{
			Risk: openngfwv1.ChangeRisk_CHANGE_RISK_HIGH,
			Items: []*openngfwv1.ChangeImpactItem{{
				Risk:   openngfwv1.ChangeRisk_CHANGE_RISK_HIGH,
				Title:  "Removed active blocking rule",
				Detail: "rollback target may expose previously denied traffic.",
			}},
		},
	}

	err := handleRollbackPreflight(cmd, resp, readyRuntimeForTest(), false, false)
	if err == nil || !strings.Contains(err.Error(), "--ack-risk") {
		t.Fatalf("expected --ack-risk error, got %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"rollback target is valid", "impact: high", "Removed active blocking rule"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in stdout %q", want, out)
		}
	}
}

func TestHandleRollbackPreflightRejectsInvalidTarget(t *testing.T) {
	cmd, stdout, stderr := preflightCommandForTest()
	resp := &openngfwv1.ValidateResponse{
		Valid:  false,
		Errors: []string{`rule "bad": unknown service "rdp"`},
		Impact: &openngfwv1.ChangeImpact{Risk: openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM},
	}

	err := handleRollbackPreflight(cmd, resp, readyRuntimeForTest(), true, false)
	if err == nil || !strings.Contains(err.Error(), "rollback target is invalid") {
		t.Fatalf("expected invalid rollback target error, got %v", err)
	}
	if !strings.Contains(stderr.String(), `error: rule "bad": unknown service "rdp"`) {
		t.Fatalf("missing validation error in stderr %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "impact: medium") {
		t.Fatalf("missing impact summary in stdout %q", stdout.String())
	}
}

func TestRollbackCommandRequiresAuditCommentBeforeDial(t *testing.T) {
	server := "127.0.0.1:1"
	cmd := newRollbackCommand(&server)

	err := cmd.RunE(cmd, []string{"1"})
	if err == nil || !strings.Contains(err.Error(), "rollback audit comment is required") {
		t.Fatalf("expected missing comment error, got %v", err)
	}
}

func TestHandleRollbackPreflightRequiresAckForRuntimeUnavailable(t *testing.T) {
	cmd, stdout, _ := preflightCommandForTest()
	resp := &openngfwv1.ValidateResponse{
		Valid:  true,
		Impact: &openngfwv1.ChangeImpact{Risk: openngfwv1.ChangeRisk_CHANGE_RISK_LOW},
	}
	runtime := cliRuntimePreflight(nil, errors.New("status endpoint unavailable"), nil, nil)

	err := handleRollbackPreflight(cmd, resp, runtime, false, false)
	if err == nil || !strings.Contains(err.Error(), "--ack-runtime") {
		t.Fatalf("expected --ack-runtime error, got %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"rollback target is valid", "runtime: unknown", "Runtime status unavailable"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in stdout %q", want, out)
		}
	}
	if err := handleRollbackPreflight(cmd, resp, runtime, false, true); err != nil {
		t.Fatalf("acked runtime should pass: %v", err)
	}
}

func TestCLIRuntimePreflightCapturesWarningsAndCapabilities(t *testing.T) {
	runtime := cliRuntimePreflight(&openngfwv1.GetStatusResponse{
		Runtime: &openngfwv1.RuntimeStatus{ActiveDataplane: "nftables"},
		Warnings: []*openngfwv1.StatusWarning{{
			Severity: "warning",
			Message:  "kernel tuning degraded",
			Action:   "run deploy/install.sh",
		}},
		Capabilities: []*openngfwv1.SystemCapability{{
			Name: "nftables", State: "degraded", Detail: "nft missing",
		}},
	}, nil, nil, nil)

	if !runtime.requiresAck || runtime.label != "warnings" {
		t.Fatalf("runtime = %#v, want warning ack", runtime)
	}
	for _, want := range []string{"kernel tuning degraded", "nftables is degraded"} {
		var found bool
		for _, item := range runtime.items {
			if item.title == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing runtime item %q in %#v", want, runtime.items)
		}
	}
}

func TestCLIRuntimePreflightIsPolicyAwareForFlowtable(t *testing.T) {
	standard := &openngfwv1.Policy{Zones: []*openngfwv1.Zone{{Name: "wan", Interfaces: []string{"eth0"}}}}
	flowtable := &openngfwv1.Policy{
		Zones:   []*openngfwv1.Zone{{Name: "wan", Interfaces: []string{"eth0"}}},
		Network: &openngfwv1.Network{EnableFlowOffload: true},
	}
	status := &openngfwv1.GetStatusResponse{
		Runtime: &openngfwv1.RuntimeStatus{ActiveDataplane: "nftables"},
		Dataplane: &openngfwv1.DataplaneStatus{
			Flowtable: &openngfwv1.FlowtableStatus{
				HostState:     "ready",
				HostDetail:    "host can apply flowtables",
				RuntimeState:  "inactive",
				RuntimeDetail: "runtime ruleset has no flowtable fast path",
			},
		},
	}

	newFlowtable := cliRuntimePreflight(status, nil, flowtable, standard)
	if newFlowtable.requiresAck {
		t.Fatalf("new flowtable candidate should not require live runtime evidence before commit: %#v", newFlowtable)
	}

	runningFlowtable := cliRuntimePreflight(status, nil, flowtable, flowtable)
	if !runningFlowtable.requiresAck || runningFlowtable.label != "not-ready" {
		t.Fatalf("running flowtable policy should require inactive runtime acknowledgement: %#v", runningFlowtable)
	}
	if !hasRuntimeItem(runningFlowtable.items, "nftables flowtable runtime is inactive") {
		t.Fatalf("missing flowtable runtime item in %#v", runningFlowtable.items)
	}

	status.GetDataplane().Flowtable.HostState = "simulation"
	status.GetDataplane().Flowtable.HostDetail = "nft command is missing"
	hostBlocked := cliRuntimePreflight(status, nil, flowtable, standard)
	if !hostBlocked.requiresAck || !hasRuntimeItem(hostBlocked.items, "nftables flowtable fast path is simulation") {
		t.Fatalf("flowtable target should require host readiness acknowledgement: %#v", hostBlocked)
	}
}

func TestCLIRuntimePreflightFromServerSendsTargetAndRunningPolicy(t *testing.T) {
	target := &openngfwv1.Policy{Network: &openngfwv1.Network{EnableFlowOffload: true}}
	running := &openngfwv1.Policy{Network: &openngfwv1.Network{EnableFlowOffload: false}}
	client := &fakeRuntimeReadinessClient{resp: &openngfwv1.CheckRuntimeReadinessResponse{
		Label:       "warnings",
		RequiresAck: true,
		Items:       []*openngfwv1.RuntimeReadinessItem{{Level: "critical", Title: "runtime blocked", Detail: "blocked detail"}},
	}}

	runtime := cliRuntimePreflightFromServer(context.Background(), client, "rollback", target, running)

	if client.req == nil {
		t.Fatal("CheckRuntimeReadiness was not called")
	}
	if client.req.GetOperation() != "rollback" {
		t.Fatalf("operation = %q, want rollback", client.req.GetOperation())
	}
	if client.req.GetTargetPolicy() != target || client.req.GetRunningPolicy() != running {
		t.Fatalf("preflight did not receive target/running policies: %#v", client.req)
	}
	if !runtime.requiresAck || runtime.label != "warnings" || !hasRuntimeItem(runtime.items, "runtime blocked") {
		t.Fatalf("runtime = %#v, want server warning result", runtime)
	}
	if client.getStatusCalled {
		t.Fatal("GetStatus fallback should not be called when server preflight succeeds")
	}
}

func TestCLIRuntimePreflightFromServerFallsBackWhenUnimplemented(t *testing.T) {
	target := &openngfwv1.Policy{Network: &openngfwv1.Network{EnableFlowOffload: true}}
	running := &openngfwv1.Policy{Network: &openngfwv1.Network{EnableFlowOffload: true}}
	client := &fakeRuntimeReadinessClient{
		err: grpcstatus.Error(codes.Unimplemented, "runtime readiness unavailable on legacy server"),
		statusResp: &openngfwv1.GetStatusResponse{
			Runtime: &openngfwv1.RuntimeStatus{ActiveDataplane: "nftables"},
			Dataplane: &openngfwv1.DataplaneStatus{Flowtable: &openngfwv1.FlowtableStatus{
				HostState:    "ready",
				RuntimeState: "inactive",
			}},
		},
	}

	runtime := cliRuntimePreflightFromServer(context.Background(), client, "commit", target, running)

	if !client.getStatusCalled {
		t.Fatal("GetStatus fallback was not called")
	}
	if !runtime.requiresAck || runtime.label != "not-ready" || !hasRuntimeItem(runtime.items, "nftables flowtable runtime is inactive") {
		t.Fatalf("runtime = %#v, want legacy status-derived flowtable warning", runtime)
	}
}

func TestCLIRuntimePreflightFromServerRequiresAckWhenUnavailable(t *testing.T) {
	client := &fakeRuntimeReadinessClient{err: errors.New("transport down")}

	runtime := cliRuntimePreflightFromServer(context.Background(), client, "commit", nil, nil)

	if !runtime.requiresAck || runtime.label != "unknown" || !hasRuntimeItem(runtime.items, "Runtime readiness preflight unavailable") {
		t.Fatalf("runtime = %#v, want unavailable warning", runtime)
	}
}

func readyRuntimeForTest() cliRuntimePreflightResult {
	return cliRuntimePreflight(&openngfwv1.GetStatusResponse{
		Runtime: &openngfwv1.RuntimeStatus{ActiveDataplane: "nftables"},
	}, nil, nil, nil)
}

func hasRuntimeItem(items []cliRuntimePreflightItem, title string) bool {
	for _, item := range items {
		if item.title == title {
			return true
		}
	}
	return false
}

func preflightCommandForTest() (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd := &cobra.Command{}
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	return cmd, stdout, stderr
}

type fakeCommitStatusClient struct {
	resp  *openngfwv1.GetCandidateStatusResponse
	err   error
	calls int
}

func (f *fakeCommitStatusClient) GetCandidateStatus(_ context.Context, _ *openngfwv1.GetCandidateStatusRequest, _ ...grpc.CallOption) (*openngfwv1.GetCandidateStatusResponse, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if f.resp != nil {
		return f.resp, nil
	}
	return &openngfwv1.GetCandidateStatusResponse{}, nil
}

type fakeRuntimeReadinessClient struct {
	resp            *openngfwv1.CheckRuntimeReadinessResponse
	err             error
	req             *openngfwv1.CheckRuntimeReadinessRequest
	statusResp      *openngfwv1.GetStatusResponse
	statusErr       error
	getStatusCalled bool
}

func (f *fakeRuntimeReadinessClient) CheckRuntimeReadiness(_ context.Context, req *openngfwv1.CheckRuntimeReadinessRequest, _ ...grpc.CallOption) (*openngfwv1.CheckRuntimeReadinessResponse, error) {
	f.req = req
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func (f *fakeRuntimeReadinessClient) GetStatus(context.Context, *openngfwv1.GetStatusRequest, ...grpc.CallOption) (*openngfwv1.GetStatusResponse, error) {
	f.getStatusCalled = true
	return f.statusResp, f.statusErr
}
