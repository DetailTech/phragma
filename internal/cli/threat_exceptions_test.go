package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestThreatExceptionListBuildsVersionRequest(t *testing.T) {
	client := &fakeThreatExceptionClient{listResp: &openngfwv1.ListThreatExceptionsResponse{}}
	cmd, _, _ := threatExceptionCommandForTest()

	err := runThreatExceptionsList(context.Background(), cmd, client, threatExceptionListOptions{source: "version", version: 7})
	if err != nil {
		t.Fatalf("runThreatExceptionsList returned error: %v", err)
	}
	if client.listReq.GetSource() != openngfwv1.PolicySource_POLICY_SOURCE_VERSION || client.listReq.GetVersion() != 7 {
		t.Fatalf("list request = %#v, want version 7", client.listReq)
	}

	if err := runThreatExceptionsList(context.Background(), cmd, client, threatExceptionListOptions{source: "version"}); err == nil || !strings.Contains(err.Error(), "--version") {
		t.Fatalf("expected version misuse error, got %v", err)
	}
}

func TestThreatExceptionStageBuildsRequest(t *testing.T) {
	client := &fakeThreatExceptionClient{stageResp: &openngfwv1.StageThreatExceptionResponse{
		Exception:       threatExceptionForTest("fp-9000001"),
		CandidateStatus: &openngfwv1.GetCandidateStatusResponse{Dirty: true, ChangeCount: 2},
		Validation:      &openngfwv1.ValidateResponse{Valid: true},
	}}
	cmd, stdout, _ := threatExceptionCommandForTest()

	err := runThreatExceptionStage(context.Background(), cmd, client, threatExceptionStageOptions{
		name:        "fp-9000001",
		signatureID: 9000001,
		threatID:    "phragma.test.web",
		threatName:  "Test web false positive",
		scope:       "source",
		sourceIP:    "10.0.1.10",
		reason:      "known lab false positive",
		owner:       "secops",
		ticketID:    "INC-1",
	})
	if err != nil {
		t.Fatalf("runThreatExceptionStage returned error: %v", err)
	}
	req := client.stageReq
	if req.GetName() != "fp-9000001" || req.GetThreatId() != "phragma.test.web" || req.GetSourceIp() != "10.0.1.10" || req.GetReason() != "known lab false positive" {
		t.Fatalf("stage request fields = %#v", req)
	}
	if req.GetScope() != openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_SOURCE {
		t.Fatalf("scope = %s, want source", req.GetScope())
	}
	if len(req.GetEngineSignals()) != 1 || req.GetEngineSignals()[0].GetEngine() != "suricata" || req.GetEngineSignals()[0].GetKind() != "signature_id" || req.GetEngineSignals()[0].GetValue() != "9000001" {
		t.Fatalf("engine signals = %#v", req.GetEngineSignals())
	}
	for _, want := range []string{"threat exception staged", "fp-9000001", "candidate-only", "ngfwctl policy validate"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stage output missing %q: %s", want, stdout.String())
		}
	}
}

func TestThreatExceptionStageValidatesRequiredFields(t *testing.T) {
	cmd, _, _ := threatExceptionCommandForTest()
	client := &fakeThreatExceptionClient{}
	cases := []struct {
		name string
		opts threatExceptionStageOptions
		want string
	}{
		{name: "missing signature", opts: threatExceptionStageOptions{scope: "source", sourceIP: "10.0.1.10", reason: "r"}, want: "--signature-id"},
		{name: "missing reason", opts: threatExceptionStageOptions{signatureID: 1, scope: "source", sourceIP: "10.0.1.10"}, want: "--reason"},
		{name: "missing source ip", opts: threatExceptionStageOptions{signatureID: 1, scope: "source", reason: "r"}, want: "--src-ip"},
		{name: "global without confirm", opts: threatExceptionStageOptions{signatureID: 1, scope: "global", reason: "r"}, want: "--confirm-global"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runThreatExceptionStage(context.Background(), cmd, client, tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestThreatExceptionUpdateOverlaysCurrentRecord(t *testing.T) {
	current := threatExceptionForTest("fp-9000001")
	current.Owner = "secops"
	current.TicketId = "INC-1"
	current.PcapSha256 = strings.Repeat("a", 64)
	client := &fakeThreatExceptionClient{
		listResp: &openngfwv1.ListThreatExceptionsResponse{
			Exceptions: []*openngfwv1.ThreatExceptionRecord{{Exception: current}},
		},
		updateResp: &openngfwv1.UpdateThreatExceptionResponse{
			Exception:       current,
			CandidateStatus: &openngfwv1.GetCandidateStatusResponse{Dirty: true, ChangeCount: 1},
			Validation:      &openngfwv1.ValidateResponse{Valid: true},
		},
	}
	cmd, _, _ := threatExceptionCommandForTest()

	err := runThreatExceptionUpdate(context.Background(), cmd, client, "fp-9000001", threatExceptionUpdateOptions{
		description:    "updated reason",
		descriptionSet: true,
		reason:         "ticket update",
	})
	if err != nil {
		t.Fatalf("runThreatExceptionUpdate returned error: %v", err)
	}
	if client.listReq == nil {
		t.Fatal("update did not load current exception")
	}
	got := client.updateReq.GetException()
	want := proto.Clone(current).(*openngfwv1.IdsException)
	want.Description = "updated reason"
	if !proto.Equal(got, want) {
		t.Fatalf("replacement exception = %#v, want %#v", got, want)
	}
}

func TestThreatExceptionStateAndRemoveBuildRequests(t *testing.T) {
	client := &fakeThreatExceptionClient{
		stateResp:  &openngfwv1.SetThreatExceptionStateResponse{Exception: threatExceptionForTest("fp-9000001"), Validation: &openngfwv1.ValidateResponse{Valid: true}},
		removeResp: &openngfwv1.RemoveThreatExceptionResponse{PreviousException: threatExceptionForTest("fp-9000001"), Validation: &openngfwv1.ValidateResponse{Valid: true}},
	}
	cmd, _, _ := threatExceptionCommandForTest()

	if err := runThreatExceptionState(context.Background(), cmd, client, "fp-9000001", true, threatExceptionStateOptions{reason: "disable for replay"}); err != nil {
		t.Fatalf("disable returned error: %v", err)
	}
	if client.stateReq.GetName() != "fp-9000001" || !client.stateReq.GetDisabled() || client.stateReq.GetReason() != "disable for replay" {
		t.Fatalf("state request = %#v", client.stateReq)
	}

	if err := runThreatExceptionRemove(context.Background(), cmd, client, "fp-9000001", threatExceptionRemoveOptions{reason: "fixed upstream"}); err != nil {
		t.Fatalf("remove returned error: %v", err)
	}
	if client.removeReq.GetName() != "fp-9000001" || client.removeReq.GetReason() != "fixed upstream" {
		t.Fatalf("remove request = %#v", client.removeReq)
	}
}

func TestThreatExceptionJSONUsesProtoNames(t *testing.T) {
	client := &fakeThreatExceptionClient{listResp: &openngfwv1.ListThreatExceptionsResponse{
		Exceptions: []*openngfwv1.ThreatExceptionRecord{{Exception: threatExceptionForTest("fp-9000001"), CandidateOnly: true}},
	}}
	cmd, stdout, _ := threatExceptionCommandForTest()

	if err := runThreatExceptionsList(context.Background(), cmd, client, threatExceptionListOptions{outJSON: true}); err != nil {
		t.Fatalf("json list returned error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("output was not JSON: %v\n%s", err, stdout.String())
	}
	raw := stdout.String()
	if !strings.Contains(raw, "candidate_only") || strings.Contains(raw, "candidateOnly") {
		t.Fatalf("expected proto-name JSON, got %s", raw)
	}
}

func threatExceptionForTest(name string) *openngfwv1.IdsException {
	return &openngfwv1.IdsException{
		Name:          name,
		SignatureId:   9000001,
		ThreatId:      "phragma.test.web",
		SourceAddress: "threat-src-10-0-1-10",
		Description:   "known lab false positive",
	}
}

func threatExceptionCommandForTest() (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd := &cobra.Command{}
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	return cmd, stdout, stderr
}

type fakeThreatExceptionClient struct {
	listResp   *openngfwv1.ListThreatExceptionsResponse
	listReq    *openngfwv1.ListThreatExceptionsRequest
	stageResp  *openngfwv1.StageThreatExceptionResponse
	stageReq   *openngfwv1.StageThreatExceptionRequest
	updateResp *openngfwv1.UpdateThreatExceptionResponse
	updateReq  *openngfwv1.UpdateThreatExceptionRequest
	stateResp  *openngfwv1.SetThreatExceptionStateResponse
	stateReq   *openngfwv1.SetThreatExceptionStateRequest
	removeResp *openngfwv1.RemoveThreatExceptionResponse
	removeReq  *openngfwv1.RemoveThreatExceptionRequest
}

func (f *fakeThreatExceptionClient) ListThreatExceptions(_ context.Context, req *openngfwv1.ListThreatExceptionsRequest, _ ...grpc.CallOption) (*openngfwv1.ListThreatExceptionsResponse, error) {
	f.listReq = req
	if f.listResp != nil {
		return f.listResp, nil
	}
	return &openngfwv1.ListThreatExceptionsResponse{}, nil
}

func (f *fakeThreatExceptionClient) StageThreatException(_ context.Context, req *openngfwv1.StageThreatExceptionRequest, _ ...grpc.CallOption) (*openngfwv1.StageThreatExceptionResponse, error) {
	f.stageReq = req
	if f.stageResp != nil {
		return f.stageResp, nil
	}
	return &openngfwv1.StageThreatExceptionResponse{Exception: threatExceptionForTest(req.GetName()), Validation: &openngfwv1.ValidateResponse{Valid: true}}, nil
}

func (f *fakeThreatExceptionClient) UpdateThreatException(_ context.Context, req *openngfwv1.UpdateThreatExceptionRequest, _ ...grpc.CallOption) (*openngfwv1.UpdateThreatExceptionResponse, error) {
	f.updateReq = req
	if f.updateResp != nil {
		return f.updateResp, nil
	}
	return &openngfwv1.UpdateThreatExceptionResponse{Exception: req.GetException(), Validation: &openngfwv1.ValidateResponse{Valid: true}}, nil
}

func (f *fakeThreatExceptionClient) SetThreatExceptionState(_ context.Context, req *openngfwv1.SetThreatExceptionStateRequest, _ ...grpc.CallOption) (*openngfwv1.SetThreatExceptionStateResponse, error) {
	f.stateReq = req
	if f.stateResp != nil {
		return f.stateResp, nil
	}
	return &openngfwv1.SetThreatExceptionStateResponse{Exception: threatExceptionForTest(req.GetName()), Validation: &openngfwv1.ValidateResponse{Valid: true}}, nil
}

func (f *fakeThreatExceptionClient) RemoveThreatException(_ context.Context, req *openngfwv1.RemoveThreatExceptionRequest, _ ...grpc.CallOption) (*openngfwv1.RemoveThreatExceptionResponse, error) {
	f.removeReq = req
	if f.removeResp != nil {
		return f.removeResp, nil
	}
	return &openngfwv1.RemoveThreatExceptionResponse{PreviousException: threatExceptionForTest(req.GetName()), Validation: &openngfwv1.ValidateResponse{Valid: true}}, nil
}
