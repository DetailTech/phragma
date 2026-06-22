package apiserver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/contentpkg"
	"github.com/detailtech/oss-ngfw/internal/store"
)

func TestAlertServerReturnsCanonicalThreatID(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"alert","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8080,"proto":"TCP","alert":{"action":"blocked","signature_id":9000001,"signature":"ET EXPLOIT Test Attack","category":"Misc Attack","severity":1}}`
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte(eve+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resp, err := (&AlertServer{EvePath: path}).ListAlerts(context.Background(), &openngfwv1.ListAlertsRequest{})
	if err != nil {
		t.Fatalf("ListAlerts returned error: %v", err)
	}
	if len(resp.GetAlerts()) != 1 {
		t.Fatalf("got %d alerts, want 1", len(resp.GetAlerts()))
	}
	alert := resp.GetAlerts()[0]
	if alert.GetSignatureId() != 9000001 {
		t.Fatalf("SignatureId = %d, want raw SID 9000001", alert.GetSignatureId())
	}
	if alert.GetThreatId() != "suricata-sid-9000001" {
		t.Fatalf("ThreatId = %q, want suricata-sid-9000001", alert.GetThreatId())
	}
	if alert.GetThreatCategory() != "exploit-attempt" {
		t.Fatalf("ThreatCategory = %q, want exploit-attempt", alert.GetThreatCategory())
	}
	if alert.GetThreatSeverity() != "critical" {
		t.Fatalf("ThreatSeverity = %q, want critical", alert.GetThreatSeverity())
	}
	if alert.GetThreatConfidence() != 85 {
		t.Fatalf("ThreatConfidence = %d, want 85", alert.GetThreatConfidence())
	}
	if len(alert.GetThreatEvidence()) == 0 {
		t.Fatal("expected ThreatEvidence")
	}
}

func TestAlertServerEnrichesThreatIDFromSignedPackage(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"alert","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8080,"proto":"TCP","alert":{"action":"blocked","signature_id":9000001,"signature":"ET EXPLOIT Test Attack","category":"Misc Attack","severity":1}}`
	evePath := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(evePath, []byte(eve+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	contentDir := t.TempDir()
	publisher := newAPIContentPublisher(t)
	publisher.trust(t, contentDir)
	taxonomyJSON := []byte(`{"type":"threat-taxonomy","status":"passed","package_version":"1.2.3","threats":[{"id":"ognfw-managed-exploit","name":"Managed Exploit Attempt","category":"exploit-attempt","severity":"critical","confidence":96,"signature_ids":[9000001],"evidence":["curated severity override"]}]}`)
	publisher.writePackageWithMutator(t, filepath.Join(contentDir, "threat-id"), "threat-id", "1.2.3", []byte(`{"threats":["prod"]}`), func(m *contentpkg.Manifest) {
		addAPIProductionEvidenceForTest(t, filepath.Join(contentDir, "threat-id"), m, "threat-id", "1.2.3")
		replaceAPIProductionEvidenceForTest(t, filepath.Join(contentDir, "threat-id"), m, "threat-taxonomy", taxonomyJSON)
	})

	resp, err := (&AlertServer{EvePath: evePath, ContentDir: contentDir}).ListAlerts(context.Background(), &openngfwv1.ListAlertsRequest{
		Query: "signed Threat-ID package",
	})
	if err != nil {
		t.Fatalf("ListAlerts returned error: %v", err)
	}
	if len(resp.GetAlerts()) != 1 {
		t.Fatalf("got %d alerts, want 1", len(resp.GetAlerts()))
	}
	alert := resp.GetAlerts()[0]
	if alert.GetThreatId() != "ognfw-managed-exploit" || alert.GetThreatName() != "Managed Exploit Attempt" {
		t.Fatalf("package metadata not applied: %#v", alert)
	}
	if alert.GetThreatConfidence() != 96 {
		t.Fatalf("ThreatConfidence = %d, want 96", alert.GetThreatConfidence())
	}
	if !strings.Contains(strings.Join(alert.GetThreatEvidence(), "\n"), "signed Threat-ID package 1.2.3@") {
		t.Fatalf("package evidence missing: %#v", alert.GetThreatEvidence())
	}
}

func TestAlertServerFilters(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.700001+0000","event_type":"alert","flow_id":"alert-flow-1","src_ip":"10.100.1.3","src_port":40000,"dest_ip":"10.100.2.3","dest_port":8443,"proto":"TCP","alert":{"action":"blocked","signature_id":9000002,"signature":"ET SCAN Test Probe","category":"Attempted Information Leak","severity":2}}
{"timestamp":"2026-06-11T10:00:01.000001+0000","event_type":"alert","flow_id":"alert-flow-2","src_ip":"10.100.1.3","src_port":40001,"dest_ip":"10.100.2.3","dest_port":8443,"proto":"TCP","alert":{"action":"blocked","signature_id":9000002,"signature":"ET SCAN Test Probe","category":"Attempted Information Leak","severity":2}}`
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte(eve+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resp, err := (&AlertServer{EvePath: path}).ListAlerts(context.Background(), &openngfwv1.ListAlertsRequest{
		Ip:             "10.100.1.3",
		Protocol:       "tcp",
		Action:         "blocked",
		Severity:       2,
		ThreatSeverity: "high",
		SignatureId:    9000002,
		Port:           8443,
		FlowId:         "alert-flow-2",
		Since:          timestamppb.New(time.Date(2026, 6, 11, 10, 0, 0, 500000000, time.UTC)),
		Query:          "probe",
	})
	if err != nil {
		t.Fatalf("ListAlerts returned error: %v", err)
	}
	if len(resp.GetAlerts()) != 1 || resp.GetAlerts()[0].GetSignatureId() != 9000002 {
		t.Fatalf("filtered alerts = %#v", resp.GetAlerts())
	}
	if resp.GetAlerts()[0].GetFlowId() != "alert-flow-2" {
		t.Fatalf("FlowId = %q, want alert-flow-2", resp.GetAlerts()[0].GetFlowId())
	}
}

func TestAlertServerPaginatesFilteredAlerts(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"alert","flow_id":"alert-flow-1","src_ip":"10.100.1.1","src_port":40000,"dest_ip":"10.100.2.1","dest_port":8443,"proto":"TCP","alert":{"action":"blocked","signature_id":9000001,"signature":"ET TEST 1","category":"Misc Attack","severity":2}}
{"timestamp":"2026-06-11T10:00:01.000001+0000","event_type":"alert","flow_id":"alert-flow-2","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8443,"proto":"TCP","alert":{"action":"blocked","signature_id":9000002,"signature":"ET TEST 2","category":"Misc Attack","severity":2}}
{"timestamp":"2026-06-11T10:00:02.000001+0000","event_type":"alert","flow_id":"alert-flow-3","src_ip":"10.100.1.3","src_port":40000,"dest_ip":"10.100.2.3","dest_port":8443,"proto":"TCP","alert":{"action":"blocked","signature_id":9000003,"signature":"ET TEST 3","category":"Misc Attack","severity":2}}`
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte(eve+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := &AlertServer{EvePath: path}
	first, err := srv.ListAlerts(context.Background(), &openngfwv1.ListAlertsRequest{Limit: 2, Action: "blocked"})
	if err != nil {
		t.Fatalf("ListAlerts first page returned error: %v", err)
	}
	if got := alertFlowIDs(first.GetAlerts()); strings.Join(got, ",") != "alert-flow-3,alert-flow-2" {
		t.Fatalf("first page alert flow ids = %v", got)
	}
	if !first.GetHasMore() || first.GetNextCursor() != "2" || first.GetTotalMatches() != 3 {
		t.Fatalf("first page metadata = hasMore:%v cursor:%q total:%d", first.GetHasMore(), first.GetNextCursor(), first.GetTotalMatches())
	}
	second, err := srv.ListAlerts(context.Background(), &openngfwv1.ListAlertsRequest{Limit: 2, Action: "blocked", PageCursor: first.GetNextCursor()})
	if err != nil {
		t.Fatalf("ListAlerts second page returned error: %v", err)
	}
	if got := alertFlowIDs(second.GetAlerts()); strings.Join(got, ",") != "alert-flow-1" {
		t.Fatalf("second page alert flow ids = %v", got)
	}
	if second.GetHasMore() || second.GetNextCursor() != "" || second.GetTotalMatches() != 3 {
		t.Fatalf("second page metadata = hasMore:%v cursor:%q total:%d", second.GetHasMore(), second.GetNextCursor(), second.GetTotalMatches())
	}
}

func TestAlertServerRejectsInvalidPageCursor(t *testing.T) {
	_, err := (&AlertServer{}).ListAlerts(context.Background(), &openngfwv1.ListAlertsRequest{PageCursor: "not-a-cursor"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}
}

func alertFlowIDs(alerts []*openngfwv1.Alert) []string {
	out := make([]string, 0, len(alerts))
	for _, alert := range alerts {
		out = append(out, alert.GetFlowId())
	}
	return out
}

func TestAlertServerReturnsRunningPolicyContext(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"alert","flow_id":67890,"src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8080,"proto":"TCP","openngfw":{"config_version":1,"stamp":"openngfw config v1","freshness":"event-time","source":"openngfw.eve"},"alert":{"action":"blocked","signature_id":9000001,"signature":"ET EXPLOIT Test Attack","category":"Misc Attack","severity":1}}`
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte(eve+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.CommitVersion(&openngfwv1.Policy{}, "tester", "baseline"); err != nil {
		t.Fatal(err)
	}

	resp, err := (&AlertServer{EvePath: path, Store: st}).ListAlerts(context.Background(), &openngfwv1.ListAlertsRequest{})
	if err != nil {
		t.Fatalf("ListAlerts returned error: %v", err)
	}
	if resp.GetRunningPolicyVersion() != 1 {
		t.Fatalf("RunningPolicyVersion = %d, want 1", resp.GetRunningPolicyVersion())
	}
	if resp.GetPolicyContext() == "" {
		t.Fatal("expected policy context")
	}
	if len(resp.GetAlerts()) != 1 {
		t.Fatalf("got %d alerts, want 1", len(resp.GetAlerts()))
	}
	alert := resp.GetAlerts()[0]
	if alert.GetPolicyVersion() != 1 || !alert.GetPolicyVersionKnown() {
		t.Fatalf("alert policy version not preserved: %#v", alert)
	}
	evidenceText := strings.Join(alert.GetThreatEvidence(), "\n")
	if !strings.Contains(evidenceText, "event policy stamp: openngfw config v1") || !strings.Contains(evidenceText, "event policy freshness: event-time") || !strings.Contains(evidenceText, "event policy source: openngfw.eve") {
		t.Fatalf("event policy evidence missing: %#v", alert.GetThreatEvidence())
	}
	if alert.GetFlowId() != "67890" {
		t.Fatalf("FlowId = %q, want 67890", alert.GetFlowId())
	}
}

func TestAlertServerRejectsInvalidTimeRange(t *testing.T) {
	_, err := (&AlertServer{}).ListAlerts(context.Background(), &openngfwv1.ListAlertsRequest{
		Since: timestamppb.New(time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)),
		Until: timestamppb.New(time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC)),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}
}
