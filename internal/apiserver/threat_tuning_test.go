package apiserver

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/engines"
	"github.com/detailtech/oss-ngfw/internal/store"
)

func TestStageThreatExceptionBasesFromRunningAndAudits(t *testing.T) {
	st, srv := newThreatTuningTestServer(t, nil)
	if _, err := st.CommitVersion(validThreatTuningPolicy(), "tester", "baseline"); err != nil {
		t.Fatal(err)
	}

	resp, err := srv.StageThreatException(context.Background(), stageThreatRequest())
	if err != nil {
		t.Fatalf("StageThreatException: %v", err)
	}
	if resp.GetException().GetSignatureId() != 9000001 {
		t.Fatalf("signature = %d, want 9000001", resp.GetException().GetSignatureId())
	}
	if resp.GetException().GetOwner() != "secops-oncall" ||
		resp.GetException().GetTicketId() != "INC-2026-001" ||
		resp.GetException().GetReviewDate() != "2026-07-01" ||
		resp.GetException().GetExpiresAt() != "2026-08-01" ||
		resp.GetException().GetPcapSha256() != strings.Repeat("a", 64) ||
		resp.GetException().GetRegressionRef() != "evidence/fp-regression.json" {
		t.Fatalf("metadata = %#v", resp.GetException())
	}
	if resp.GetException().GetSourceAddress() == "" {
		t.Fatalf("expected source-scoped exception: %#v", resp.GetException())
	}
	if resp.GetAddress().GetCidr() != "10.0.1.10/32" || resp.GetAddressReused() {
		t.Fatalf("address = %#v reused=%v", resp.GetAddress(), resp.GetAddressReused())
	}
	if !resp.GetValidation().GetValid() {
		t.Fatalf("validation should be valid: %v", resp.GetValidation().GetErrors())
	}
	if !resp.GetCandidateStatus().GetDirty() || !resp.GetDiff().GetChanged() {
		t.Fatalf("missing candidate status/diff: status=%#v diff=%#v", resp.GetCandidateStatus(), resp.GetDiff())
	}

	candidate, ok, err := st.GetCandidate()
	if err != nil || !ok {
		t.Fatalf("candidate not stored: ok=%v err=%v", ok, err)
	}
	if len(candidate.GetIds().GetExceptions()) != 1 {
		t.Fatalf("exceptions = %#v", candidate.GetIds().GetExceptions())
	}
	audit, err := st.ListAuditFiltered(store.AuditFilter{Action: "stage-threat-exception", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(audit) != 1 || !strings.Contains(audit[0].Detail, "threat_id=phragma.test.web") ||
		!strings.Contains(audit[0].Detail, "scope=source") ||
		!strings.Contains(audit[0].Detail, "owner=secops-oncall") ||
		!strings.Contains(audit[0].Detail, "ticket=INC-2026-001") ||
		!strings.Contains(audit[0].Detail, "pcap_sha256="+strings.Repeat("a", 64)) {
		t.Fatalf("audit = %#v", audit)
	}
}

func TestStageThreatExceptionPreservesExistingCandidateAndReusesAddress(t *testing.T) {
	st, srv := newThreatTuningTestServer(t, nil)
	running := validThreatTuningPolicy()
	if _, err := st.CommitVersion(running, "tester", "baseline"); err != nil {
		t.Fatal(err)
	}
	candidate := validThreatTuningPolicy()
	candidate.Rules = append(candidate.Rules, &openngfwv1.Rule{
		Name: "deny-extra", FromZones: []string{"wan"}, ToZones: []string{"lan"},
		SourceAddresses: []string{"any"}, DestinationAddresses: []string{"web-server"},
		Services: []string{"https"}, Action: openngfwv1.Action_ACTION_DENY,
	})
	if err := st.SetCandidate(candidate); err != nil {
		t.Fatal(err)
	}

	req := stageThreatRequest()
	req.Scope = openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_DESTINATION
	req.SourceIp = ""
	req.DestinationIp = "10.0.2.10"
	resp, err := srv.StageThreatException(context.Background(), req)
	if err != nil {
		t.Fatalf("StageThreatException: %v", err)
	}
	if !resp.GetAddressReused() || resp.GetAddress().GetName() != "web-server" {
		t.Fatalf("expected web-server reuse, address=%#v reused=%v", resp.GetAddress(), resp.GetAddressReused())
	}
	got, _, err := st.GetCandidate()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GetRules()) != len(candidate.GetRules()) {
		t.Fatalf("existing candidate rule edit was not preserved")
	}
}

func TestStageThreatExceptionRejectsDuplicateAndGlobalWithoutConfirm(t *testing.T) {
	st, srv := newThreatTuningTestServer(t, nil)
	if _, err := st.CommitVersion(validThreatTuningPolicy(), "tester", "baseline"); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.StageThreatException(context.Background(), stageThreatRequest()); err != nil {
		t.Fatalf("first stage: %v", err)
	}
	_, err := srv.StageThreatException(context.Background(), stageThreatRequest())
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("duplicate error = %v, want AlreadyExists", err)
	}

	global := stageThreatRequest()
	global.Scope = openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_GLOBAL
	global.SourceIp = ""
	_, err = srv.StageThreatException(context.Background(), global)
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "confirm_global") {
		t.Fatalf("global error = %v, want confirm_global InvalidArgument", err)
	}
}

func TestStageThreatExceptionInvalidPolicyDoesNotStore(t *testing.T) {
	st, srv := newThreatTuningTestServer(t, nil)
	if _, err := st.CommitVersion(validThreatTuningPolicy(), "tester", "baseline"); err != nil {
		t.Fatal(err)
	}
	req := stageThreatRequest()
	req.ThreatId = "phragma.test\nbad"
	resp, err := srv.StageThreatException(context.Background(), req)
	if err != nil {
		t.Fatalf("StageThreatException should return validation response, got error: %v", err)
	}
	if resp.GetValidation().GetValid() {
		t.Fatalf("validation should be invalid")
	}
	if _, ok, err := st.GetCandidate(); err != nil || ok {
		t.Fatalf("invalid stage should not store candidate: ok=%v err=%v", ok, err)
	}
}

func TestStageThreatExceptionRejectsMissingInputs(t *testing.T) {
	_, srv := newThreatTuningTestServer(t, nil)
	cases := []struct {
		name string
		req  *openngfwv1.StageThreatExceptionRequest
	}{
		{name: "reason", req: func() *openngfwv1.StageThreatExceptionRequest { r := stageThreatRequest(); r.Reason = ""; return r }()},
		{name: "signature", req: func() *openngfwv1.StageThreatExceptionRequest {
			r := stageThreatRequest()
			r.EngineSignals = nil
			return r
		}()},
		{name: "source ip", req: func() *openngfwv1.StageThreatExceptionRequest { r := stageThreatRequest(); r.SourceIp = ""; return r }()},
		{name: "bad review date", req: func() *openngfwv1.StageThreatExceptionRequest {
			r := stageThreatRequest()
			r.ReviewDate = "07/01/2026"
			return r
		}()},
		{name: "bad pcap", req: func() *openngfwv1.StageThreatExceptionRequest {
			r := stageThreatRequest()
			r.PcapSha256 = "bad"
			return r
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := srv.StageThreatException(context.Background(), tc.req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("error = %v, want InvalidArgument", err)
			}
		})
	}
}

func TestStageThreatExceptionValidationFailureDoesNotOverwriteExistingCandidate(t *testing.T) {
	st, srv := newThreatTuningTestServer(t, nil)
	candidate := validThreatTuningPolicy()
	if err := st.SetCandidate(candidate); err != nil {
		t.Fatal(err)
	}
	req := stageThreatRequest()
	req.ThreatId = "bad\nid"
	resp, err := srv.StageThreatException(context.Background(), req)
	if err != nil {
		t.Fatalf("StageThreatException should return validation response, got error: %v", err)
	}
	if resp.GetValidation().GetValid() {
		t.Fatal("validation should be invalid")
	}
	got, ok, err := st.GetCandidate()
	if err != nil || !ok {
		t.Fatalf("candidate missing: ok=%v err=%v", ok, err)
	}
	if len(got.GetIds().GetExceptions()) != 0 {
		t.Fatalf("invalid stage mutated stored candidate: %#v", got.GetIds().GetExceptions())
	}
}

func TestListThreatExceptionsReportsEffectiveCandidateAndRunningState(t *testing.T) {
	st, srv := newThreatTuningTestServer(t, nil)
	running := validThreatTuningPolicy()
	running.GetIds().Exceptions = []*openngfwv1.IdsException{{
		Name: "fp-running", SignatureId: 9000001, ThreatId: "phragma.test.web", SourceAddress: "client-net", Description: "running reason",
	}}
	version, err := st.CommitVersion(running, "tester", "baseline")
	if err != nil {
		t.Fatal(err)
	}

	resp, err := srv.ListThreatExceptions(context.Background(), &openngfwv1.ListThreatExceptionsRequest{})
	if err != nil {
		t.Fatalf("ListThreatExceptions running: %v", err)
	}
	if resp.GetSource() != openngfwv1.PolicySource_POLICY_SOURCE_RUNNING || resp.GetVersion() != version {
		t.Fatalf("source/version = %s/%d, want running/%d", resp.GetSource(), resp.GetVersion(), version)
	}
	if len(resp.GetExceptions()) != 1 || !resp.GetExceptions()[0].GetPresentInRunning() || resp.GetExceptions()[0].GetCandidateOnly() {
		t.Fatalf("running records = %#v", resp.GetExceptions())
	}
	if resp.GetExceptions()[0].GetScope() != openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_SOURCE ||
		resp.GetExceptions()[0].GetScopeObject() != "client-net" {
		t.Fatalf("scope record = %#v", resp.GetExceptions()[0])
	}

	candidate := validThreatTuningPolicy()
	candidate.GetIds().Exceptions = []*openngfwv1.IdsException{
		{Name: "fp-running", SignatureId: 9000001, ThreatId: "phragma.test.web", SourceAddress: "client-net", Description: "updated reason"},
		{Name: "fp-new", SignatureId: 9000002, ThreatId: "phragma.test.two", DestinationAddress: "web-server", Description: "candidate reason"},
	}
	if err := st.SetCandidate(candidate); err != nil {
		t.Fatal(err)
	}
	resp, err = srv.ListThreatExceptions(context.Background(), &openngfwv1.ListThreatExceptionsRequest{})
	if err != nil {
		t.Fatalf("ListThreatExceptions candidate: %v", err)
	}
	if resp.GetSource() != openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE || !resp.GetCandidateStatus().GetDirty() {
		t.Fatalf("candidate source/status = %s %#v", resp.GetSource(), resp.GetCandidateStatus())
	}
	if len(resp.GetExceptions()) != 2 {
		t.Fatalf("candidate records = %#v", resp.GetExceptions())
	}
	if !resp.GetExceptions()[0].GetChangedFromRunning() {
		t.Fatalf("expected running exception to be marked changed: %#v", resp.GetExceptions()[0])
	}
	if !resp.GetExceptions()[1].GetCandidateOnly() || resp.GetExceptions()[1].GetScopeObject() != "web-server" {
		t.Fatalf("expected new destination-scoped candidate-only record: %#v", resp.GetExceptions()[1])
	}
}

func TestThreatExceptionLifecycleStagesCandidateAndAudits(t *testing.T) {
	st, srv := newThreatTuningTestServer(t, nil)
	running := validThreatTuningPolicy()
	running.GetIds().Exceptions = []*openngfwv1.IdsException{{
		Name: "fp-running", SignatureId: 9000001, ThreatId: "phragma.test.web", SourceAddress: "client-net", Description: "known lab false positive",
	}}
	if _, err := st.CommitVersion(running, "tester", "baseline"); err != nil {
		t.Fatal(err)
	}

	updateResp, err := srv.UpdateThreatException(context.Background(), &openngfwv1.UpdateThreatExceptionRequest{
		Name: "fp-running",
		Exception: &openngfwv1.IdsException{
			Name: "fp-renamed", SignatureId: 9000001, ThreatId: "phragma.test.web", SourceAddress: "client-net", Description: "updated reason",
		},
		Reason: "ticket sec-123 updated scope owner",
	})
	if err != nil {
		t.Fatalf("UpdateThreatException: %v", err)
	}
	if updateResp.GetException().GetName() != "fp-renamed" || !updateResp.GetValidation().GetValid() || !updateResp.GetDiff().GetChanged() {
		t.Fatalf("update response = %#v", updateResp)
	}
	got, ok, err := st.GetCandidate()
	if err != nil || !ok {
		t.Fatalf("candidate missing after update: ok=%v err=%v", ok, err)
	}
	if got.GetIds().GetExceptions()[0].GetName() != "fp-renamed" {
		t.Fatalf("candidate exception = %#v", got.GetIds().GetExceptions())
	}

	disableResp, err := srv.SetThreatExceptionState(context.Background(), &openngfwv1.SetThreatExceptionStateRequest{
		Name: "fp-renamed", Disabled: true, Reason: "noise subsided while package is tested",
	})
	if err != nil {
		t.Fatalf("SetThreatExceptionState disable: %v", err)
	}
	if !disableResp.GetException().GetDisabled() || !disableResp.GetValidation().GetValid() {
		t.Fatalf("disable response = %#v", disableResp)
	}
	enableResp, err := srv.SetThreatExceptionState(context.Background(), &openngfwv1.SetThreatExceptionStateRequest{
		Name: "fp-renamed", Disabled: false, Reason: "re-enable after replay regression",
	})
	if err != nil {
		t.Fatalf("SetThreatExceptionState enable: %v", err)
	}
	if enableResp.GetException().GetDisabled() || !enableResp.GetValidation().GetValid() {
		t.Fatalf("enable response = %#v", enableResp)
	}

	removeResp, err := srv.RemoveThreatException(context.Background(), &openngfwv1.RemoveThreatExceptionRequest{
		Name: "fp-renamed", Reason: "package fixed false positive",
	})
	if err != nil {
		t.Fatalf("RemoveThreatException: %v", err)
	}
	if removeResp.GetPreviousException().GetName() != "fp-renamed" || !removeResp.GetValidation().GetValid() {
		t.Fatalf("remove response = %#v", removeResp)
	}
	got, ok, err = st.GetCandidate()
	if err != nil || !ok {
		t.Fatalf("candidate missing after remove: ok=%v err=%v", ok, err)
	}
	if len(got.GetIds().GetExceptions()) != 0 {
		t.Fatalf("expected exception removed from candidate: %#v", got.GetIds().GetExceptions())
	}

	for _, action := range []string{"update-threat-exception", "set-threat-exception-state", "remove-threat-exception"} {
		audit, err := st.ListAuditFiltered(store.AuditFilter{Action: action, Limit: 1})
		if err != nil {
			t.Fatal(err)
		}
		if len(audit) != 1 || !strings.Contains(audit[0].Detail, "reason=") {
			t.Fatalf("audit %s = %#v", action, audit)
		}
	}
}

func TestThreatExceptionLifecycleValidationFailureDoesNotStore(t *testing.T) {
	st, srv := newThreatTuningTestServer(t, nil)
	candidate := validThreatTuningPolicy()
	candidate.GetIds().Exceptions = []*openngfwv1.IdsException{{
		Name: "fp-running", SignatureId: 9000001, SourceAddress: "client-net", Description: "known lab false positive",
	}}
	if err := st.SetCandidate(candidate); err != nil {
		t.Fatal(err)
	}

	resp, err := srv.UpdateThreatException(context.Background(), &openngfwv1.UpdateThreatExceptionRequest{
		Name: "fp-running",
		Exception: &openngfwv1.IdsException{
			Name: "fp-running", SignatureId: 9000001, SourceAddress: "missing-address", Description: "bad address",
		},
		Reason: "operator typo",
	})
	if err != nil {
		t.Fatalf("UpdateThreatException should return validation response, got error: %v", err)
	}
	if resp.GetValidation().GetValid() {
		t.Fatalf("validation should be invalid")
	}
	got, ok, err := st.GetCandidate()
	if err != nil || !ok {
		t.Fatalf("candidate missing: ok=%v err=%v", ok, err)
	}
	if got.GetIds().GetExceptions()[0].GetSourceAddress() != "client-net" {
		t.Fatalf("invalid update mutated candidate: %#v", got.GetIds().GetExceptions())
	}
}

func TestThreatExceptionLifecycleRejectsGlobalWithoutConfirm(t *testing.T) {
	st, srv := newThreatTuningTestServer(t, nil)
	candidate := validThreatTuningPolicy()
	candidate.GetIds().Exceptions = []*openngfwv1.IdsException{{
		Name: "fp-global", SignatureId: 9000001, ThreatId: "phragma.test.web", Disabled: true, Description: "temporarily disabled global fp",
	}}
	if err := st.SetCandidate(candidate); err != nil {
		t.Fatal(err)
	}

	_, err := srv.SetThreatExceptionState(context.Background(), &openngfwv1.SetThreatExceptionStateRequest{
		Name: "fp-global", Disabled: false, Reason: "re-enable global suppression",
	})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "confirm_global") {
		t.Fatalf("global re-enable error = %v, want confirm_global InvalidArgument", err)
	}
	resp, err := srv.SetThreatExceptionState(context.Background(), &openngfwv1.SetThreatExceptionStateRequest{
		Name: "fp-global", Disabled: false, Reason: "re-enable global suppression", ConfirmGlobal: true,
	})
	if err != nil {
		t.Fatalf("global re-enable with confirm: %v", err)
	}
	if resp.GetException().GetDisabled() {
		t.Fatalf("global exception still disabled: %#v", resp.GetException())
	}

	_, err = srv.UpdateThreatException(context.Background(), &openngfwv1.UpdateThreatExceptionRequest{
		Name:      "fp-global",
		Exception: &openngfwv1.IdsException{Name: "fp-global", SignatureId: 9000001, Description: "active global fp"},
		Reason:    "global edit",
	})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "confirm_global") {
		t.Fatalf("global update error = %v, want confirm_global InvalidArgument", err)
	}
}

func TestReplayThreatEvidenceComparesExplicitSampleAndEngineEvidence(t *testing.T) {
	_, srv := newThreatTuningTestServer(t, nil)
	srv.ThreatReplayStatus = fakeThreatReplayStatusSource{resp: &openngfwv1.GetStatusResponse{
		Engines: []*openngfwv1.EngineStatus{{Name: "suricata", Role: "inspection", Mode: "managed", State: "active", Detail: "supervised"}},
		Inspection: &openngfwv1.InspectionStatus{
			State: "ready", EngineName: "suricata", EngineMode: "managed", EngineState: "active", EngineRequired: true,
		},
	}}

	resp, err := srv.ReplayThreatEvidence(context.Background(), &openngfwv1.ReplayThreatEvidenceRequest{
		Samples: []*openngfwv1.ThreatReplaySample{{
			Id:          "operator-sample-1",
			Source:      "sample",
			Signature:   "ET EXPLOIT Test Attack",
			SignatureId: 9000001,
			Category:    "Misc Attack",
			Severity:    1,
			Action:      "blocked",
			Expected: &openngfwv1.ThreatReplayExpectation{
				SignatureId: 9000001,
				ThreatId:    "suricata-sid-9000001",
				Verdict:     "blocked",
			},
		}},
	})
	if err != nil {
		t.Fatalf("ReplayThreatEvidence: %v", err)
	}
	if resp.GetState() != "passed" || len(resp.GetResults()) != 1 || !resp.GetResults()[0].GetPassed() {
		t.Fatalf("replay response = %#v", resp)
	}
	if resp.GetEngine().GetEngineState() != "active" || resp.GetEngine().GetInspectionState() != "ready" {
		t.Fatalf("engine evidence = %#v", resp.GetEngine())
	}
	if !strings.Contains(strings.Join(resp.GetWarnings(), " "), "metadata-only") {
		t.Fatalf("missing bounded replay disclaimer: %#v", resp.GetWarnings())
	}
}

func TestReplayThreatEvidenceUsesRecentAlertsAndReportsDegradedEngine(t *testing.T) {
	_, srv := newThreatTuningTestServer(t, nil)
	srv.ThreatReplayAlerts = fakeThreatReplayAlertSource{resp: &openngfwv1.ListAlertsResponse{
		Alerts: []*openngfwv1.Alert{{
			Time:        timestamppb.Now(),
			Signature:   "ET WEB suspicious",
			SignatureId: 42,
			Severity:    3,
			Category:    "Web Application Attack",
			Action:      "allowed",
			ThreatId:    "suricata-sid-42",
			FlowId:      "flow-1",
		}},
	}}
	srv.ThreatReplayStatus = fakeThreatReplayStatusSource{resp: &openngfwv1.GetStatusResponse{
		Engines: []*openngfwv1.EngineStatus{{Name: "suricata", Role: "inspection", Mode: "managed", State: "failed", Detail: "process exited"}},
		Inspection: &openngfwv1.InspectionStatus{
			State: "failed-open", EngineName: "suricata", EngineState: "failed", EngineRequired: true, BypassPossible: true,
			BypassReason: "ids.failure_behavior is fail-open", DegradedBehavior: "traffic can bypass userspace prevention",
		},
	}}

	resp, err := srv.ReplayThreatEvidence(context.Background(), &openngfwv1.ReplayThreatEvidenceRequest{})
	if err != nil {
		t.Fatalf("ReplayThreatEvidence: %v", err)
	}
	if resp.GetState() != "degraded" || resp.GetRecentAlertCount() != 1 || len(resp.GetResults()) != 1 || !resp.GetResults()[0].GetPassed() {
		t.Fatalf("replay response = %#v", resp)
	}
	if !resp.GetEngine().GetBypassPossible() || resp.GetEngine().GetBypassReason() == "" {
		t.Fatalf("expected degraded bypass evidence: %#v", resp.GetEngine())
	}
}

type fakeThreatReplayAlertSource struct {
	resp *openngfwv1.ListAlertsResponse
	err  error
}

func (f fakeThreatReplayAlertSource) ListAlerts(_ context.Context, _ *openngfwv1.ListAlertsRequest) (*openngfwv1.ListAlertsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

type fakeThreatReplayStatusSource struct {
	resp *openngfwv1.GetStatusResponse
	err  error
}

func (f fakeThreatReplayStatusSource) GetStatus(context.Context, *openngfwv1.GetStatusRequest) (*openngfwv1.GetStatusResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func stageThreatRequest() *openngfwv1.StageThreatExceptionRequest {
	return &openngfwv1.StageThreatExceptionRequest{
		ThreatId:   "phragma.test.web",
		ThreatName: "Suspicious test web traffic",
		EngineSignals: []*openngfwv1.ThreatEngineSignal{{
			Engine: "suricata", Kind: "signature_id", Value: "9000001",
		}},
		Scope:         openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_SOURCE,
		SourceIp:      "10.0.1.10",
		Reason:        "known lab false positive",
		Owner:         "secops-oncall",
		TicketId:      "INC-2026-001",
		ReviewDate:    "2026-07-01",
		ExpiresAt:     "2026-08-01",
		PcapSha256:    strings.Repeat("a", 64),
		RegressionRef: "evidence/fp-regression.json",
	}
}

func validThreatTuningPolicy() *openngfwv1.Policy {
	p := validReferencePolicy()
	p.Ids = &openngfwv1.Ids{
		Enabled:         true,
		Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
		QueueNum:        0,
		FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED,
	}
	return p
}

//nolint:unparam // The render hook keeps the fixture ready for renderer-specific threat tuning tests.
func newThreatTuningTestServer(t *testing.T, render Pipeline) (*store.Store, *PolicyServer) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if render == nil {
		render = func(*openngfwv1.Policy) (map[string][]byte, error) { return map[string][]byte{}, nil }
	}
	return st, NewPolicyServer(st, engines.NewSupervisor(), render)
}
