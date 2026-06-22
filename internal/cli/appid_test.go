package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestRunAppIDObservationsPrintsQueueContextAndSuggestions(t *testing.T) {
	client := &fakeAppIDObservationsClient{resp: &openngfwv1.ListAppIdObservationsResponse{
		RunningPolicyVersion:       7,
		PolicyContext:              "running policy v7",
		ScannedFlows:               250,
		ConfidenceThreshold:        55,
		AppIdPackageVersion:        "2.4.6",
		AppIdPackageManifestSha256: strings.Repeat("f", 64),
		Observations: []*openngfwv1.AppIdObservation{{
			QueueId:            "appid-queue-42",
			Kind:               openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_UNKNOWN,
			AppId:              "unknown",
			AppConfidence:      0,
			EngineSignal:       "weird-proto",
			EngineSignalSource: "suricata.app_proto",
			Protocol:           "TCP",
			DestPort:           8443,
			Count:              3,
			LastSeen:           timestamppb.New(mustTestTime(t, "2026-06-18T12:05:00Z")),
			Bytes:              4096,
			Packets:            12,
			SampleFlowId:       "eve-flow-1",
			SampleSrcIp:        "10.0.1.20",
			SampleSrcPort:      51515,
			SampleDestIp:       "10.0.2.20",
			AppEvidence:        []string{"engine signal weird-proto is unmapped", "tcp/8443 suggests custom app"},
			SuggestedApplication: &openngfwv1.Application{
				Name:          "weird-proto",
				DisplayName:   "weird-proto",
				Category:      "custom",
				EngineSignals: []string{"weird-proto"},
				Ports: []*openngfwv1.ApplicationPort{{
					Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
					Ports:    []*openngfwv1.PortRange{{Start: 8443}},
				}},
			},
		}},
	}}

	out, err := runAppIDObservationsForTest(client, appIDObservationOptions{
		limit:               50,
		flowLimit:           1000,
		confidenceThreshold: 55,
		query:               "weird",
		kind:                "unknown",
		engineSignal:        "weird-proto",
		protocol:            "TCP",
		port:                8443,
		since:               "2026-06-18T12:00:00Z",
		until:               "2026-06-18T13:00:00Z",
	})
	if err != nil {
		t.Fatalf("runAppIDObservations returned error: %v", err)
	}
	req := client.req
	if req == nil || req.GetLimit() != 50 || req.GetFlowLimit() != 1000 || req.GetConfidenceThreshold() != 55 ||
		req.GetQuery() != "weird" || req.GetKind() != openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_UNKNOWN ||
		req.GetEngineSignal() != "weird-proto" || req.GetProtocol() != "TCP" || req.GetPort() != 8443 ||
		req.GetSince() == nil || req.GetUntil() == nil {
		t.Fatalf("request = %#v", req)
	}
	for _, want := range []string{
		"App-ID observations",
		"policy-context: running v7",
		"app-id-package: version=2.4.6 manifest=ffffffffffffffff",
		"scanned-flows: 250 threshold=55%",
		"unknown",
		"confidence=0%",
		"signal=weird-proto",
		"proto=TCP",
		"dport=8443",
		"queue_id=appid-queue-42",
		"flow_id=eve-flow-1",
		"sample=10.0.1.20:51515 -> 10.0.2.20",
		"source=suricata.app_proto",
		"suggested: weird-proto",
		"signals=weird-proto",
		"ports=tcp/8443",
		"evidence: engine signal weird-proto is unmapped, tcp/8443 suggests custom app",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestRunAppIDObservationsPrintsJSON(t *testing.T) {
	client := &fakeAppIDObservationsClient{resp: &openngfwv1.ListAppIdObservationsResponse{
		ScannedFlows:        1,
		ConfidenceThreshold: 70,
	}}
	out, err := runAppIDObservationsForTest(client, appIDObservationOptions{outJSON: true})
	if err != nil {
		t.Fatalf("runAppIDObservations json returned error: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("json output did not parse: %v\n%s", err, out)
	}
	if payload["scanned_flows"] != float64(1) || payload["confidence_threshold"] != float64(70) {
		t.Fatalf("json output missing response fields: %#v\n%s", payload, out)
	}
}

func TestRunAppIDPromoteStagesObservationAndPrintsReview(t *testing.T) {
	client := &fakeAppIDObservationsClient{stageResp: &openngfwv1.StageAppIdObservationResponse{
		Observation: &openngfwv1.AppIdObservation{
			QueueId:      "qid-1",
			Kind:         openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_UNKNOWN,
			EngineSignal: "weird-proto",
			Protocol:     "TCP",
			DestPort:     8443,
			Count:        5,
		},
		Application: &openngfwv1.Application{
			Name:          "corp-admin",
			DisplayName:   "Corporate Admin",
			Category:      "business-app",
			EngineSignals: []string{"weird-proto"},
			Ports: []*openngfwv1.ApplicationPort{{
				Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
				Ports:    []*openngfwv1.PortRange{{Start: 8443}},
			}},
		},
		Rule: &openngfwv1.Rule{
			Name:                 "drop-app-corp-admin",
			Action:               openngfwv1.Action_ACTION_DENY,
			Applications:         []string{"corp-admin"},
			SourceAddresses:      []string{"appid-src-10-0-1-10"},
			DestinationAddresses: []string{"appid-dst-10-0-2-20"},
		},
		Validation:      &openngfwv1.ValidateResponse{Valid: true, RenderPlan: &openngfwv1.RenderPlan{ArtifactCount: 1}},
		CandidateStatus: &openngfwv1.GetCandidateStatusResponse{Dirty: true, ChangeCount: 3, RunningVersion: 7},
		Diff:            &openngfwv1.DiffPolicyResponse{Changed: true, FromLabel: "running policy v7", ToLabel: "candidate", Lines: []*openngfwv1.PolicyDiffLine{{Text: "+ app"}}},
	}}
	out, err := runAppIDPromoteForTest(client, "qid-1", appIDPromoteOptions{
		reason:              "reviewed queue",
		drop:                true,
		confirmDrop:         true,
		flowLimit:           500,
		confidenceThreshold: 55,
		appName:             "corp-admin",
		displayName:         "Corporate Admin",
		category:            "business-app",
		engineSignals:       []string{"weird-proto"},
		tcpPorts:            []string{"8443"},
		description:         "Reviewed override.",
		since:               "2026-06-18T12:00:00Z",
		until:               "2026-06-18T13:00:00Z",
	})
	if err != nil {
		t.Fatalf("runAppIDPromote returned error: %v", err)
	}
	req := client.stageReq
	if req == nil || req.GetQueueId() != "qid-1" ||
		req.GetMode() != openngfwv1.AppIdObservationStageMode_APP_ID_OBSERVATION_STAGE_MODE_DEFINE_AND_DROP ||
		!req.GetConfirmDrop() || req.GetReason() != "reviewed queue" ||
		req.GetFlowLimit() != 500 || req.GetConfidenceThreshold() != 55 ||
		req.GetSince() == nil || req.GetUntil() == nil {
		t.Fatalf("request = %#v", req)
	}
	if req.GetApplicationOverride().GetName() != "corp-admin" ||
		len(req.GetApplicationOverride().GetPorts()) != 1 ||
		req.GetApplicationOverride().GetPorts()[0].GetPorts()[0].GetStart() != 8443 {
		t.Fatalf("override = %#v", req.GetApplicationOverride())
	}
	for _, want := range []string{
		"App-ID observation staged",
		"queue: qid-1",
		"application: corp-admin",
		"rule: drop-app-corp-admin",
		"validation: valid",
		"candidate: dirty=true changes=3 running=v7",
		"diff: running policy v7 -> candidate",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestRunAppIDPromoteRejectsMissingReasonAndBadOverride(t *testing.T) {
	client := &fakeAppIDObservationsClient{}
	_, err := runAppIDPromoteForTest(client, "qid-1", appIDPromoteOptions{})
	if err == nil || !strings.Contains(err.Error(), "--reason is required") {
		t.Fatalf("missing reason error = %v", err)
	}
	if client.stageReq != nil {
		t.Fatalf("client should not be called: %#v", client.stageReq)
	}
	_, err = runAppIDPromoteForTest(client, "qid-1", appIDPromoteOptions{reason: "reviewed", tcpPorts: []string{"443"}})
	if err == nil || !strings.Contains(err.Error(), "--app-name is required") {
		t.Fatalf("override error = %v", err)
	}
}

func TestRunAppIDCorpusAddStagesDraftSample(t *testing.T) {
	client := &fakeAppIDObservationsClient{corpusResp: &openngfwv1.StageAppIdRegressionSampleResponse{
		Observation: &openngfwv1.AppIdObservation{
			QueueId:      "qid-1",
			Kind:         openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_UNKNOWN,
			EngineSignal: "weird-proto",
			Protocol:     "TCP",
			DestPort:     8443,
			Count:        5,
		},
		Sample: &openngfwv1.AppIdRegressionSample{
			SampleId:    "sample-1",
			ExpectedApp: "corp-admin",
			ObservedApp: "weird-proto",
			PcapSha256:  strings.Repeat("a", 64),
			Reason:      "reviewed capture",
		},
		DraftArtifact:              "app-id/.reviewed-corpus/app-regression-corpus.jsonl",
		SampleCount:                2,
		AppIdPackageVersion:        "2.4.6",
		AppIdPackageManifestSha256: strings.Repeat("f", 64),
	}}
	out, err := runAppIDCorpusAddForTest(client, "qid-1", appIDCorpusAddOptions{
		reason:              "reviewed capture",
		pcapSHA256:          strings.Repeat("a", 64),
		expectedApp:         "corp-admin",
		observedApp:         "weird-proto",
		flowLimit:           500,
		confidenceThreshold: 55,
		since:               "2026-06-18T12:00:00Z",
		until:               "2026-06-18T13:00:00Z",
	})
	if err != nil {
		t.Fatalf("runAppIDCorpusAdd returned error: %v", err)
	}
	req := client.corpusReq
	if req == nil || req.GetQueueId() != "qid-1" || req.GetReason() != "reviewed capture" ||
		req.GetPcapSha256() != strings.Repeat("a", 64) || req.GetExpectedApp() != "corp-admin" ||
		req.GetObservedApp() != "weird-proto" || req.GetFlowLimit() != 500 ||
		req.GetConfidenceThreshold() != 55 || req.GetSince() == nil || req.GetUntil() == nil {
		t.Fatalf("request = %#v", req)
	}
	for _, want := range []string{
		"App-ID regression sample staged",
		"queue: qid-1",
		"sample: sample-1 expected=corp-admin observed=weird-proto pcap=aaaaaaaaaaaaaaaa reason=reviewed capture",
		"artifact: app-id/.reviewed-corpus/app-regression-corpus.jsonl samples=2",
		"app-id-package: version=2.4.6 manifest=ffffffffffffffff",
		"build, sign, and compare",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestRunAppIDCorpusAddRejectsRequiredFields(t *testing.T) {
	client := &fakeAppIDObservationsClient{}
	_, err := runAppIDCorpusAddForTest(client, "qid-1", appIDCorpusAddOptions{pcapSHA256: strings.Repeat("a", 64)})
	if err == nil || !strings.Contains(err.Error(), "--reason is required") {
		t.Fatalf("missing reason error = %v", err)
	}
	_, err = runAppIDCorpusAddForTest(client, "qid-1", appIDCorpusAddOptions{reason: "reviewed"})
	if err == nil || !strings.Contains(err.Error(), "--pcap-sha256 is required") {
		t.Fatalf("missing pcap error = %v", err)
	}
	if client.corpusReq != nil {
		t.Fatalf("client should not be called: %#v", client.corpusReq)
	}
}

func TestRunAppIDObservationsRejectsInvalidKindBeforeDialing(t *testing.T) {
	client := &fakeAppIDObservationsClient{}
	_, err := runAppIDObservationsForTest(client, appIDObservationOptions{kind: "bogus"})
	if err == nil || !strings.Contains(err.Error(), "invalid --kind") {
		t.Fatalf("expected invalid kind error, got %v", err)
	}
	if client.req != nil {
		t.Fatalf("client should not be called after invalid kind: %#v", client.req)
	}
}

func TestParseAppIDObservationKindAcceptsEnumAndShortAliases(t *testing.T) {
	tests := map[string]openngfwv1.AppIdObservationKind{
		"":                     openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_UNSPECIFIED,
		"unknown":              openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_UNKNOWN,
		"low-confidence":       openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_LOW_CONFIDENCE,
		"conflicting-evidence": openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_CONFLICTING_EVIDENCE,
		"APP_ID_OBSERVATION_KIND_CONFLICTING_EVIDENCE": openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_CONFLICTING_EVIDENCE,
	}
	for raw, want := range tests {
		got, err := parseAppIDObservationKind(raw)
		if err != nil {
			t.Fatalf("parseAppIDObservationKind(%q): %v", raw, err)
		}
		if got != want {
			t.Fatalf("parseAppIDObservationKind(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestRootCommandIncludesAppIDObservations(t *testing.T) {
	root := NewRootCommand()
	appID, _, err := root.Find([]string{"app-id", "observations"})
	if err != nil {
		t.Fatalf("find app-id observations: %v", err)
	}
	if appID == nil || appID.Use != "observations" {
		t.Fatalf("app-id observations command missing: %#v", appID)
	}
	promote, _, err := root.Find([]string{"app-id", "promote"})
	if err != nil {
		t.Fatalf("find app-id promote: %v", err)
	}
	if promote == nil || promote.Use != "promote QUEUE_ID" {
		t.Fatalf("app-id promote command missing: %#v", promote)
	}
	corpus, _, err := root.Find([]string{"app-id", "corpus", "add"})
	if err != nil {
		t.Fatalf("find app-id corpus add: %v", err)
	}
	if corpus == nil || corpus.Use != "add QUEUE_ID" {
		t.Fatalf("app-id corpus add command missing: %#v", corpus)
	}
}

func runAppIDObservationsForTest(client appIDObservationsClient, opts appIDObservationOptions) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runAppIDObservations(context.Background(), cmd, client, opts)
	return out.String(), err
}

func runAppIDPromoteForTest(client appIDStageClient, queueID string, opts appIDPromoteOptions) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runAppIDPromote(context.Background(), cmd, client, queueID, opts)
	return out.String(), err
}

func runAppIDCorpusAddForTest(client appIDCorpusClient, queueID string, opts appIDCorpusAddOptions) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runAppIDCorpusAdd(context.Background(), cmd, client, queueID, opts)
	return out.String(), err
}

func mustTestTime(t *testing.T, value string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse test time %q: %v", value, err)
	}
	return ts
}

type fakeAppIDObservationsClient struct {
	req        *openngfwv1.ListAppIdObservationsRequest
	resp       *openngfwv1.ListAppIdObservationsResponse
	err        error
	stageReq   *openngfwv1.StageAppIdObservationRequest
	stageResp  *openngfwv1.StageAppIdObservationResponse
	stageErr   error
	corpusReq  *openngfwv1.StageAppIdRegressionSampleRequest
	corpusResp *openngfwv1.StageAppIdRegressionSampleResponse
	corpusErr  error
}

//nolint:revive // Method name mirrors the generated gRPC client interface.
func (f *fakeAppIDObservationsClient) ListAppIdObservations(_ context.Context, req *openngfwv1.ListAppIdObservationsRequest, _ ...grpc.CallOption) (*openngfwv1.ListAppIdObservationsResponse, error) {
	f.req = req
	if f.err != nil {
		return nil, f.err
	}
	if f.resp != nil {
		return f.resp, nil
	}
	return &openngfwv1.ListAppIdObservationsResponse{}, nil
}

//nolint:revive // Method name mirrors the generated gRPC client interface.
func (f *fakeAppIDObservationsClient) StageAppIdObservation(_ context.Context, req *openngfwv1.StageAppIdObservationRequest, _ ...grpc.CallOption) (*openngfwv1.StageAppIdObservationResponse, error) {
	f.stageReq = req
	if f.stageErr != nil {
		return nil, f.stageErr
	}
	if f.stageResp != nil {
		return f.stageResp, nil
	}
	return &openngfwv1.StageAppIdObservationResponse{Validation: &openngfwv1.ValidateResponse{Valid: true}}, nil
}

//nolint:revive // Method name mirrors the generated gRPC client interface.
func (f *fakeAppIDObservationsClient) StageAppIdRegressionSample(_ context.Context, req *openngfwv1.StageAppIdRegressionSampleRequest, _ ...grpc.CallOption) (*openngfwv1.StageAppIdRegressionSampleResponse, error) {
	f.corpusReq = req
	if f.corpusErr != nil {
		return nil, f.corpusErr
	}
	if f.corpusResp != nil {
		return f.corpusResp, nil
	}
	return &openngfwv1.StageAppIdRegressionSampleResponse{}, nil
}
