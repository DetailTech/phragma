package apiserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/engines"
	"github.com/detailtech/oss-ngfw/internal/store"
)

func TestAppIDServerListsObservationQueue(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","flow_id":"f-unknown","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":443,"proto":"TCP","app_proto":"weird-proto","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":80,"bytes_toclient":120}}
{"timestamp":"2026-06-11T10:00:01.000001+0000","event_type":"flow","flow_id":"f-low","src_ip":"10.100.1.3","src_port":40001,"dest_ip":"10.100.2.3","dest_port":443,"proto":"TCP","flow":{"pkts_toserver":1,"pkts_toclient":2,"bytes_toserver":100,"bytes_toclient":200}}
{"timestamp":"2026-06-11T10:00:02.000001+0000","event_type":"flow","flow_id":"f-conflict","src_ip":"10.100.1.4","src_port":40002,"dest_ip":"10.100.2.4","dest_port":443,"proto":"TCP","app_proto":"http","flow":{"pkts_toserver":2,"pkts_toclient":3,"bytes_toserver":300,"bytes_toclient":400}}`
	contentDir := t.TempDir()
	publisher := newAPIContentPublisher(t)
	publisher.trust(t, contentDir)
	publisher.writePackage(t, filepath.Join(contentDir, "app-id"), "app-id", "2.4.6", []byte(`{"apps":["weird-proto"]}`))
	appStatus, err := appIDPackageSnapshot(contentDir)
	if err != nil {
		t.Fatalf("appIDPackageSnapshot: %v", err)
	}
	resp, err := (&AppIDServer{EvePath: writeAppIDEve(t, eve), ContentDir: contentDir}).ListAppIdObservations(context.Background(), &openngfwv1.ListAppIdObservationsRequest{FlowLimit: 10})
	if err != nil {
		t.Fatalf("ListAppIdObservations returned error: %v", err)
	}
	if resp.GetScannedFlows() != 3 {
		t.Fatalf("ScannedFlows = %d, want 3", resp.GetScannedFlows())
	}
	if resp.GetConfidenceThreshold() != 70 {
		t.Fatalf("ConfidenceThreshold = %d, want 70", resp.GetConfidenceThreshold())
	}
	if len(resp.GetObservations()) != 3 {
		t.Fatalf("got %d observations, want 3: %#v", len(resp.GetObservations()), resp.GetObservations())
	}
	if resp.GetObservations()[0].GetKind() != openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_CONFLICTING_EVIDENCE {
		t.Fatalf("first observation kind = %v, want conflict", resp.GetObservations()[0].GetKind())
	}
	var unknown *openngfwv1.AppIdObservation
	for _, obs := range resp.GetObservations() {
		if obs.GetKind() == openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_UNKNOWN {
			unknown = obs
			break
		}
	}
	if unknown == nil {
		t.Fatal("missing unknown observation")
	}
	if unknown.GetAppId() != "unknown" || unknown.GetEngineSignal() != "weird-proto" {
		t.Fatalf("unexpected unknown observation: %#v", unknown)
	}
	if unknown.GetSuggestedApplication().GetName() != "weird-proto" {
		t.Fatalf("suggestion = %#v", unknown.GetSuggestedApplication())
	}
	if unknown.GetSampleSrcPort() != 40000 {
		t.Fatalf("SampleSrcPort = %d, want 40000", unknown.GetSampleSrcPort())
	}
	if resp.GetAppIdPackageVersion() != "2.4.6" {
		t.Fatalf("AppIdPackageVersion = %q, want 2.4.6", resp.GetAppIdPackageVersion())
	}
	if resp.GetAppIdPackageManifestSha256() == "" || resp.GetAppIdPackageManifestSha256() != appStatus.ManifestSHA256 {
		t.Fatalf("AppIdPackageManifestSha256 = %q, want %q", resp.GetAppIdPackageManifestSha256(), appStatus.ManifestSHA256)
	}
	if resp.GetPolicyContext() == "" {
		t.Fatal("expected explicit policy context")
	}
}

func TestAppIDServerFiltersObservations(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":443,"proto":"TCP","app_proto":"weird-proto","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":80,"bytes_toclient":120}}
{"timestamp":"2026-06-11T10:00:01.000001+0000","event_type":"flow","src_ip":"10.100.1.3","src_port":40001,"dest_ip":"10.100.2.3","dest_port":53,"proto":"UDP","flow":{"pkts_toserver":1,"pkts_toclient":2,"bytes_toserver":100,"bytes_toclient":200}}`
	resp, err := (&AppIDServer{EvePath: writeAppIDEve(t, eve)}).ListAppIdObservations(context.Background(), &openngfwv1.ListAppIdObservationsRequest{
		Kind:         openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_UNKNOWN,
		EngineSignal: "WEIRD-PROTO",
		Protocol:     "tcp",
		Port:         443,
		Query:        "weird",
	})
	if err != nil {
		t.Fatalf("ListAppIdObservations returned error: %v", err)
	}
	if len(resp.GetObservations()) != 1 {
		t.Fatalf("got %d observations, want 1: %#v", len(resp.GetObservations()), resp.GetObservations())
	}
}

func TestAppIDServerUsesRunningCustomApplications(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8443,"proto":"TCP","app_proto":"corp-admin","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":80,"bytes_toclient":120}}
{"timestamp":"2026-06-11T10:00:01.000001+0000","event_type":"flow","src_ip":"10.100.1.3","src_port":40001,"dest_ip":"10.100.2.3","dest_port":8443,"proto":"TCP","flow":{"pkts_toserver":1,"pkts_toclient":2,"bytes_toserver":100,"bytes_toclient":200}}`
	st, err := store.Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_, err = st.CommitVersion(&openngfwv1.Policy{Applications: []*openngfwv1.Application{{
		Name:          "corp-admin",
		DisplayName:   "Corporate Admin",
		Category:      "business-app",
		EngineSignals: []string{"corp-admin"},
		Ports: []*openngfwv1.ApplicationPort{{
			Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
			Ports:    []*openngfwv1.PortRange{{Start: 8443}},
		}},
	}}}, "tester", "custom app")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&AppIDServer{EvePath: writeAppIDEve(t, eve), Store: st}).ListAppIdObservations(context.Background(), &openngfwv1.ListAppIdObservationsRequest{})
	if err != nil {
		t.Fatalf("ListAppIdObservations returned error: %v", err)
	}
	if resp.GetRunningPolicyVersion() != 1 {
		t.Fatalf("RunningPolicyVersion = %d, want 1", resp.GetRunningPolicyVersion())
	}
	if len(resp.GetObservations()) != 1 {
		t.Fatalf("got %d observations, want only low-confidence port fallback: %#v", len(resp.GetObservations()), resp.GetObservations())
	}
	got := resp.GetObservations()[0]
	if got.GetAppId() != "corp-admin" || got.GetKind() != openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_LOW_CONFIDENCE {
		t.Fatalf("unexpected observation: %#v", got)
	}
}

func TestAppIDServerRejectsInvalidTimeRange(t *testing.T) {
	_, err := (&AppIDServer{}).ListAppIdObservations(context.Background(), &openngfwv1.ListAppIdObservationsRequest{
		Since: timestamppb.New(time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)),
		Until: timestamppb.New(time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC)),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}
}

func TestAppIDServerMissingEveFileReturnsEmptyQueue(t *testing.T) {
	resp, err := (&AppIDServer{EvePath: filepath.Join(t.TempDir(), "missing.json")}).ListAppIdObservations(context.Background(), &openngfwv1.ListAppIdObservationsRequest{})
	if err != nil {
		t.Fatalf("ListAppIdObservations returned error: %v", err)
	}
	if resp.GetScannedFlows() != 0 || len(resp.GetObservations()) != 0 {
		t.Fatalf("unexpected response for missing file: %#v", resp)
	}
	if resp.GetPolicyContext() == "" {
		t.Fatal("expected explicit policy context")
	}
}

func TestAppIDServerStagesObservationDefineAndDrop(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","flow_id":"f-unknown","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8443,"proto":"TCP","app_proto":"weird-proto","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":80,"bytes_toclient":120}}`
	st, srv := newAppIDPromotionTestServer(t, eve)
	list, err := srv.ListAppIdObservations(context.Background(), &openngfwv1.ListAppIdObservationsRequest{FlowLimit: 10})
	if err != nil {
		t.Fatalf("ListAppIdObservations: %v", err)
	}
	if len(list.GetObservations()) != 1 {
		t.Fatalf("observations = %#v", list.GetObservations())
	}
	resp, err := srv.StageAppIdObservation(context.Background(), &openngfwv1.StageAppIdObservationRequest{
		QueueId:     list.GetObservations()[0].GetQueueId(),
		Mode:        openngfwv1.AppIdObservationStageMode_APP_ID_OBSERVATION_STAGE_MODE_DEFINE_AND_DROP,
		Reason:      "block unknown admin surface",
		ConfirmDrop: true,
	})
	if err != nil {
		t.Fatalf("StageAppIdObservation: %v", err)
	}
	if resp.GetApplication().GetName() != "weird-proto" || resp.GetApplicationReused() {
		t.Fatalf("application = %#v reused=%v", resp.GetApplication(), resp.GetApplicationReused())
	}
	if resp.GetRule().GetAction() != openngfwv1.Action_ACTION_DENY || len(resp.GetRule().GetApplications()) != 1 || resp.GetRule().GetApplications()[0] != "weird-proto" {
		t.Fatalf("rule = %#v", resp.GetRule())
	}
	if !resp.GetValidation().GetValid() || !resp.GetCandidateStatus().GetDirty() || !resp.GetDiff().GetChanged() {
		t.Fatalf("missing review evidence: validation=%#v status=%#v diff=%#v", resp.GetValidation(), resp.GetCandidateStatus(), resp.GetDiff())
	}
	candidate, ok, err := st.GetCandidate()
	if err != nil || !ok {
		t.Fatalf("candidate missing: ok=%v err=%v", ok, err)
	}
	if len(candidate.GetApplications()) != 1 || len(candidate.GetRules()) != 1 {
		t.Fatalf("candidate = %#v", candidate)
	}
	again, err := srv.StageAppIdObservation(context.Background(), &openngfwv1.StageAppIdObservationRequest{
		QueueId:     list.GetObservations()[0].GetQueueId(),
		Mode:        openngfwv1.AppIdObservationStageMode_APP_ID_OBSERVATION_STAGE_MODE_DEFINE_AND_DROP,
		Reason:      "second click should reuse candidate objects",
		ConfirmDrop: true,
	})
	if err != nil {
		t.Fatalf("StageAppIdObservation second time: %v", err)
	}
	if !again.GetApplicationReused() || again.GetRule().GetName() != resp.GetRule().GetName() {
		t.Fatalf("second stage should reuse application and rule: %#v", again)
	}
	candidate, ok, err = st.GetCandidate()
	if err != nil || !ok {
		t.Fatalf("candidate missing after second stage: ok=%v err=%v", ok, err)
	}
	if len(candidate.GetApplications()) != 1 || len(candidate.GetRules()) != 1 {
		t.Fatalf("second stage duplicated candidate objects: %#v", candidate)
	}
	audit, err := st.ListAuditFiltered(store.AuditFilter{Action: "stage-app-id-observation", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(audit) != 1 || !strings.Contains(audit[0].Detail, "queue_id=") || !strings.Contains(audit[0].Detail, "mode=define_and_drop") || !strings.Contains(audit[0].Detail, "rule=") {
		t.Fatalf("audit = %#v", audit)
	}
}

func TestAppIDServerStageRejectsConflictAndMissingDropAck(t *testing.T) {
	conflictEve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","flow_id":"f-conflict","src_ip":"10.100.1.4","src_port":40002,"dest_ip":"10.100.2.4","dest_port":443,"proto":"TCP","app_proto":"http","flow":{"pkts_toserver":2,"pkts_toclient":3,"bytes_toserver":300,"bytes_toclient":400}}`
	_, conflictSrv := newAppIDPromotionTestServer(t, conflictEve)
	list, err := conflictSrv.ListAppIdObservations(context.Background(), &openngfwv1.ListAppIdObservationsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = conflictSrv.StageAppIdObservation(context.Background(), &openngfwv1.StageAppIdObservationRequest{
		QueueId: list.GetObservations()[0].GetQueueId(),
		Reason:  "review conflict",
	})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("conflict error = %v, want FailedPrecondition", err)
	}

	_, dropSrv := newAppIDPromotionTestServer(t, `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","flow_id":"f-unknown","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8443,"proto":"TCP","app_proto":"weird-proto","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":80,"bytes_toclient":120}}`)
	list, err = dropSrv.ListAppIdObservations(context.Background(), &openngfwv1.ListAppIdObservationsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = dropSrv.StageAppIdObservation(context.Background(), &openngfwv1.StageAppIdObservationRequest{
		QueueId: list.GetObservations()[0].GetQueueId(),
		Mode:    openngfwv1.AppIdObservationStageMode_APP_ID_OBSERVATION_STAGE_MODE_DEFINE_AND_DROP,
		Reason:  "block",
	})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "confirm_drop") {
		t.Fatalf("drop ack error = %v, want confirm_drop InvalidArgument", err)
	}
}

func TestAppIDServerStageRejectsDropWithoutMatchingPortHint(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","flow_id":"f-unknown","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8443,"proto":"TCP","app_proto":"weird-proto","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":80,"bytes_toclient":120}}`
	cases := []struct {
		name     string
		override *openngfwv1.Application
	}{
		{
			name: "no port hints",
			override: &openngfwv1.Application{
				Name:          "weird-proto",
				Category:      "business-app",
				EngineSignals: []string{"weird-proto"},
			},
		},
		{
			name: "wrong TCP port",
			override: &openngfwv1.Application{
				Name:          "weird-proto",
				Category:      "business-app",
				EngineSignals: []string{"weird-proto"},
				Ports: []*openngfwv1.ApplicationPort{{
					Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
					Ports:    []*openngfwv1.PortRange{{Start: 9443}},
				}},
			},
		},
		{
			name: "wrong protocol",
			override: &openngfwv1.Application{
				Name:          "weird-proto",
				Category:      "business-app",
				EngineSignals: []string{"weird-proto"},
				Ports: []*openngfwv1.ApplicationPort{{
					Protocol: openngfwv1.Protocol_PROTOCOL_UDP,
					Ports:    []*openngfwv1.PortRange{{Start: 8443}},
				}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, srv := newAppIDPromotionTestServer(t, eve)
			list, err := srv.ListAppIdObservations(context.Background(), &openngfwv1.ListAppIdObservationsRequest{})
			if err != nil {
				t.Fatal(err)
			}
			_, err = srv.StageAppIdObservation(context.Background(), &openngfwv1.StageAppIdObservationRequest{
				QueueId:             list.GetObservations()[0].GetQueueId(),
				Mode:                openngfwv1.AppIdObservationStageMode_APP_ID_OBSERVATION_STAGE_MODE_DEFINE_AND_DROP,
				Reason:              "block only with matching port hint",
				ConfirmDrop:         true,
				ApplicationOverride: tc.override,
			})
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "port hint matching the observation") {
				t.Fatalf("drop port-hint error = %v, want matching-port FailedPrecondition", err)
			}
			if _, ok, err := st.GetCandidate(); err != nil || ok {
				t.Fatalf("failed drop precondition should not store candidate: ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestAppIDServerStageValidationFailureDoesNotStoreCandidate(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","flow_id":"f-unknown","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8443,"proto":"TCP","app_proto":"weird-proto","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":80,"bytes_toclient":120}}`
	st, srv := newAppIDPromotionTestServer(t, eve)
	list, err := srv.ListAppIdObservations(context.Background(), &openngfwv1.ListAppIdObservationsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.StageAppIdObservation(context.Background(), &openngfwv1.StageAppIdObservationRequest{
		QueueId: list.GetObservations()[0].GetQueueId(),
		Reason:  "bad override should not store",
		ApplicationOverride: &openngfwv1.Application{
			Name:          "bad app",
			Category:      "business-app",
			EngineSignals: []string{"weird-proto"},
		},
	})
	if err != nil {
		t.Fatalf("StageAppIdObservation should return validation response, got error: %v", err)
	}
	if resp.GetValidation().GetValid() {
		t.Fatal("validation should be invalid")
	}
	if _, ok, err := st.GetCandidate(); err != nil || ok {
		t.Fatalf("invalid stage should not store candidate: ok=%v err=%v", ok, err)
	}
}

func TestAppIDServerStagesRegressionSampleDraft(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","flow_id":"f-unknown","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8443,"proto":"TCP","app_proto":"weird-proto","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":80,"bytes_toclient":120}}`
	st, srv := newAppIDPromotionTestServer(t, eve)
	contentDir := t.TempDir()
	publisher := newAPIContentPublisher(t)
	publisher.trust(t, contentDir)
	publisher.writePackage(t, filepath.Join(contentDir, "app-id"), "app-id", "2.4.6", []byte(`{"apps":["weird-proto"]}`))
	srv.ContentDir = contentDir
	list, err := srv.ListAppIdObservations(context.Background(), &openngfwv1.ListAppIdObservationsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.StageAppIdRegressionSample(context.Background(), &openngfwv1.StageAppIdRegressionSampleRequest{
		QueueId:    list.GetObservations()[0].GetQueueId(),
		Reason:     "reviewed bounded capture",
		PcapSha256: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatalf("StageAppIdRegressionSample: %v", err)
	}
	if resp.GetDraftArtifact() != "app-id/.reviewed-corpus/app-regression-corpus.jsonl" || resp.GetSampleCount() != 1 {
		t.Fatalf("response = %#v", resp)
	}
	if resp.GetSample().GetExpectedApp() != "weird-proto" || resp.GetSample().GetPcapSha256() != strings.Repeat("a", 64) {
		t.Fatalf("sample = %#v", resp.GetSample())
	}
	raw, err := os.ReadFile(filepath.Join(contentDir, "app-id", ".reviewed-corpus", "app-regression-corpus.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	if err := json.Unmarshal(raw, &row); err != nil {
		t.Fatalf("draft corpus row did not parse: %v\n%s", err, raw)
	}
	if row["queue_id"] != list.GetObservations()[0].GetQueueId() || row["pcap_sha256"] != strings.Repeat("a", 64) {
		t.Fatalf("row = %#v", row)
	}
	audit, err := st.ListAuditFiltered(store.AuditFilter{Action: "stage-app-id-regression-sample", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(audit) != 1 || !strings.Contains(audit[0].Detail, "artifact=app-id/.reviewed-corpus/app-regression-corpus.jsonl") ||
		!strings.Contains(audit[0].Detail, "sample_count=1") {
		t.Fatalf("audit = %#v", audit)
	}
}

func TestAppIDServerComparesReplayFromQueue(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","flow_id":"f-unknown","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8443,"proto":"TCP","app_proto":"weird-proto","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":80,"bytes_toclient":120}}`
	_, srv := newAppIDPromotionTestServer(t, eve)
	list, err := srv.ListAppIdObservations(context.Background(), &openngfwv1.ListAppIdObservationsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.CompareAppIdReplay(context.Background(), &openngfwv1.CompareAppIdReplayRequest{
		QueueId:     list.GetObservations()[0].GetQueueId(),
		ExpectedApp: "corp-admin",
	})
	if err != nil {
		t.Fatalf("CompareAppIdReplay: %v", err)
	}
	report := resp.GetReport()
	if report.GetVerdict() != openngfwv1.AppIdReplayVerdict_APP_ID_REPLAY_VERDICT_MISMATCH {
		t.Fatalf("report = %#v, want mismatch", report)
	}
	if report.GetQueueId() != list.GetObservations()[0].GetQueueId() || report.GetObservedApp() != "weird-proto" || report.GetExpectedApp() != "corp-admin" {
		t.Fatalf("report identity = %#v", report)
	}
	if len(report.GetBoundedEvidence()) == 0 || !strings.Contains(report.GetComparisonScope(), "lab replay") {
		t.Fatalf("report evidence/scope = %#v", report)
	}
	if _, ok, err := srv.Store.GetCandidate(); err != nil || ok {
		t.Fatalf("compare should not store candidate: ok=%v err=%v", ok, err)
	}
}

func TestAppIDServerComparesReplayFromSubmittedCorpusSample(t *testing.T) {
	resp, err := (&AppIDServer{}).CompareAppIdReplay(context.Background(), &openngfwv1.CompareAppIdReplayRequest{
		CorpusSample: &openngfwv1.AppIdRegressionSample{
			SampleId:      "sample-1",
			QueueId:       "qid-1",
			ExpectedApp:   "corp-admin",
			ObservedApp:   "corp-admin",
			PcapSha256:    strings.Repeat("a", 64),
			AppConfidence: 92,
		},
	})
	if err != nil {
		t.Fatalf("CompareAppIdReplay: %v", err)
	}
	if resp.GetReport().GetVerdict() != openngfwv1.AppIdReplayVerdict_APP_ID_REPLAY_VERDICT_MATCH {
		t.Fatalf("report = %#v, want match", resp.GetReport())
	}
}

func TestAppIDServerReplayCompareRequiresSource(t *testing.T) {
	_, err := (&AppIDServer{}).CompareAppIdReplay(context.Background(), &openngfwv1.CompareAppIdReplayRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}
}

func TestAppIDServerRegressionSampleRejectsInvalidInputs(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","flow_id":"f-unknown","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8443,"proto":"TCP","app_proto":"weird-proto","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":80,"bytes_toclient":120}}`
	_, srv := newAppIDPromotionTestServer(t, eve)
	list, err := srv.ListAppIdObservations(context.Background(), &openngfwv1.ListAppIdObservationsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = srv.StageAppIdRegressionSample(context.Background(), &openngfwv1.StageAppIdRegressionSampleRequest{
		QueueId:    list.GetObservations()[0].GetQueueId(),
		Reason:     "reviewed",
		PcapSha256: strings.Repeat("a", 64),
	})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "content directory") {
		t.Fatalf("content dir error = %v", err)
	}
	srv.ContentDir = t.TempDir()
	_, err = srv.StageAppIdRegressionSample(context.Background(), &openngfwv1.StageAppIdRegressionSampleRequest{
		QueueId:    list.GetObservations()[0].GetQueueId(),
		Reason:     "reviewed",
		PcapSha256: "bad",
	})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "pcap_sha256") {
		t.Fatalf("pcap error = %v", err)
	}
}

func writeAppIDEve(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte(content+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func newAppIDPromotionTestServer(t *testing.T, eve string) (*store.Store, *AppIDServer) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	policyServer := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{"nftables": []byte("app-id-promotion")}, nil
	})
	return st, &AppIDServer{EvePath: writeAppIDEve(t, eve), Store: st, Policy: policyServer}
}
