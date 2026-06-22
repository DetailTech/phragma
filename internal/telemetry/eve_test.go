package telemetry

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/detailtech/oss-ngfw/internal/appid"
	"github.com/detailtech/oss-ngfw/internal/threatid"
)

const sampleEve = `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","src_ip":"10.0.0.1"}
{"timestamp":"2026-06-11T10:00:01.000001+0000","event_type":"alert","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8080,"proto":"TCP","alert":{"action":"allowed","signature_id":9000001,"signature":"NGFW TEST evil","category":"Misc Attack","severity":2}}
{"timestamp":"2026-06-11T10:00:02.000001+0000","event_type":"alert","src_ip":"10.100.1.3","src_port":40001,"dest_ip":"10.100.2.2","dest_port":8080,"proto":"TCP","alert":{"action":"blocked","signature_id":9000002,"signature":"NGFW TEST evil 2","category":"Misc Attack","severity":1}}
not json at all
`

const sampleFlowEve = `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":80,"proto":"TCP","app_proto":"http","flow":{"pkts_toserver":3,"pkts_toclient":4,"bytes_toserver":500,"bytes_toclient":700}}
{"timestamp":"2026-06-11T10:00:01.000001+0000","event_type":"flow","src_ip":"10.100.1.3","src_port":40001,"dest_ip":"10.100.2.3","dest_port":443,"proto":"TCP","flow":{"pkts_toserver":1,"pkts_toclient":2,"bytes_toserver":100,"bytes_toclient":200}}
`

func writeEve(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadAlerts(t *testing.T) {
	alerts, err := ReadAlerts(writeEve(t, sampleEve), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 2 {
		t.Fatalf("want 2 alerts, got %d: %+v", len(alerts), alerts)
	}
	// Newest first.
	if alerts[0].SignatureID != 9000002 || alerts[0].Action != "blocked" {
		t.Errorf("alerts[0] = %+v", alerts[0])
	}
	if alerts[1].SignatureID != 9000001 || alerts[1].SrcPort != 40000 || alerts[1].Severity != 2 {
		t.Errorf("alerts[1] = %+v", alerts[1])
	}
	if alerts[0].Timestamp.IsZero() {
		t.Error("timestamp not parsed")
	}
}

func TestReadAlertsLimit(t *testing.T) {
	alerts, err := ReadAlerts(writeEve(t, sampleEve), 1)
	if err != nil || len(alerts) != 1 {
		t.Fatalf("limit=1: got %d alerts err=%v", len(alerts), err)
	}
	if alerts[0].SignatureID != 9000002 {
		t.Errorf("limit must keep the newest alert, got %+v", alerts[0])
	}
}

func TestReadAlertsAddsOpenNGFWThreatID(t *testing.T) {
	alerts, err := ReadAlerts(writeEve(t, sampleEve), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 2 {
		t.Fatalf("want 2 alerts, got %d: %+v", len(alerts), alerts)
	}
	if alerts[0].ThreatID != "suricata-sid-9000002" {
		t.Fatalf("ThreatID = %q, want suricata-sid-9000002", alerts[0].ThreatID)
	}
	if alerts[0].ThreatCategory != "exploit-attempt" {
		t.Fatalf("ThreatCategory = %q, want exploit-attempt", alerts[0].ThreatCategory)
	}
	if alerts[0].ThreatSeverity != "critical" {
		t.Fatalf("ThreatSeverity = %q, want critical", alerts[0].ThreatSeverity)
	}
	if alerts[0].ThreatConfidence != 85 {
		t.Fatalf("ThreatConfidence = %d, want 85", alerts[0].ThreatConfidence)
	}
	if len(alerts[0].ThreatEvidence) == 0 {
		t.Fatal("expected ThreatEvidence")
	}
}

func TestReadAlertsWithThreatMetadataEnrichesAlert(t *testing.T) {
	alerts, err := ReadAlertsFilteredWithThreatMetadata(writeEve(t, sampleEve), AlertFilter{
		Query: "signed Threat-ID package",
	}, []threatid.PackageMetadata{{
		ID:           "ognfw-managed-exploit",
		Name:         "Managed Exploit Attempt",
		Category:     "exploit-attempt",
		Severity:     "critical",
		Confidence:   96,
		SignatureIDs: []int64{9000002},
		Evidence:     []string{"signed Threat-ID package 1.2.3@abc123"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("want 1 package-backed alert, got %d: %+v", len(alerts), alerts)
	}
	if alerts[0].ThreatID != "ognfw-managed-exploit" || alerts[0].ThreatName != "Managed Exploit Attempt" {
		t.Fatalf("package metadata not applied: %+v", alerts[0])
	}
	if alerts[0].ThreatConfidence != 96 {
		t.Fatalf("ThreatConfidence = %d, want 96", alerts[0].ThreatConfidence)
	}
}

func TestReadAlertsPreservesStampedPolicyVersion(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:01.000001+0000","event_type":"alert","flow_id":"flow-123","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8080,"proto":"TCP","phragma":{"policy_version":42,"policy_stamp":"policy v42 @ 2026-06-11T10:00:00Z","policy_freshness":"event-time"},"alert":{"action":"blocked","signature_id":9000001,"signature":"NGFW TEST evil","category":"Misc Attack","severity":2}}`
	alerts, err := ReadAlerts(writeEve(t, eve), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("want 1 alert, got %d: %+v", len(alerts), alerts)
	}
	if alerts[0].PolicyVersion != 42 {
		t.Fatalf("PolicyVersion = %d, want 42", alerts[0].PolicyVersion)
	}
	if alerts[0].PolicyStamp != "policy v42 @ 2026-06-11T10:00:00Z" {
		t.Fatalf("PolicyStamp = %q, want event policy stamp", alerts[0].PolicyStamp)
	}
	if alerts[0].PolicyFreshness != "event-time" {
		t.Fatalf("PolicyFreshness = %q, want event-time", alerts[0].PolicyFreshness)
	}
	if alerts[0].FlowID != "flow-123" {
		t.Fatalf("FlowID = %q, want flow-123", alerts[0].FlowID)
	}
}

func TestReadAlertsFiltered(t *testing.T) {
	path := writeEve(t, sampleEve)
	base := time.Date(2026, 6, 11, 10, 0, 1, 500000000, time.UTC)
	tests := []struct {
		name   string
		filter AlertFilter
		want   []int64
	}{
		{name: "action", filter: AlertFilter{Action: "blocked"}, want: []int64{9000002}},
		{name: "severity", filter: AlertFilter{Severity: 2}, want: []int64{9000001}},
		{name: "threat severity", filter: AlertFilter{ThreatSeverity: "critical"}, want: []int64{9000002}},
		{name: "signature id", filter: AlertFilter{SignatureID: 9000001}, want: []int64{9000001}},
		{name: "ip either endpoint", filter: AlertFilter{IP: "10.100.1.2"}, want: []int64{9000001}},
		{name: "port either endpoint", filter: AlertFilter{Port: 8080}, want: []int64{9000002, 9000001}},
		{name: "query", filter: AlertFilter{Query: "evil 2"}, want: []int64{9000002}},
		{name: "since", filter: AlertFilter{Since: base}, want: []int64{9000002}},
		{name: "limit after filter", filter: AlertFilter{Port: 8080, Limit: 1}, want: []int64{9000002}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alerts, err := ReadAlertsFiltered(path, tt.filter)
			if err != nil {
				t.Fatal(err)
			}
			if len(alerts) != len(tt.want) {
				t.Fatalf("got %d alerts (%+v), want %d", len(alerts), alerts, len(tt.want))
			}
			for i, want := range tt.want {
				if alerts[i].SignatureID != want {
					t.Fatalf("alert %d SID = %d, want %d (all %+v)", i, alerts[i].SignatureID, want, alerts)
				}
			}
		})
	}
}

func TestReadAlertsFiltersByFlowID(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"alert","flow_id":"flow-a","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8080,"proto":"TCP","alert":{"action":"allowed","signature_id":9000001,"signature":"NGFW TEST evil","category":"Misc Attack","severity":2}}
{"timestamp":"2026-06-11T10:00:01.000001+0000","event_type":"alert","flow_id":"flow-b","src_ip":"10.100.1.3","src_port":40001,"dest_ip":"10.100.2.2","dest_port":8080,"proto":"TCP","alert":{"action":"blocked","signature_id":9000002,"signature":"NGFW TEST evil 2","category":"Misc Attack","severity":1}}`
	alerts, err := ReadAlertsFiltered(writeEve(t, eve), AlertFilter{FlowID: "flow-a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].SignatureID != 9000001 || alerts[0].FlowID != "flow-a" {
		t.Fatalf("flow-id filtered alerts = %+v, want flow-a SID 9000001", alerts)
	}
}

func TestReadAlertsMissingFile(t *testing.T) {
	alerts, err := ReadAlerts(filepath.Join(t.TempDir(), "absent.json"), 0)
	if err != nil || alerts != nil {
		t.Fatalf("missing file: %v %v", alerts, err)
	}
}

func TestReadFlowsAddsOpenNGFWAppID(t *testing.T) {
	flows, err := ReadFlows(writeEve(t, sampleFlowEve), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 {
		t.Fatalf("want 2 flows, got %d: %+v", len(flows), flows)
	}
	// Newest first; the second raw event has no app_proto and falls back to
	// the OpenNGFW-owned port heuristic.
	if got := flows[0].AppID; got != "ssl" {
		t.Fatalf("flows[0].AppID = %q, want ssl", got)
	}
	if flows[0].AppConfidence != 60 {
		t.Fatalf("flows[0].AppConfidence = %d, want 60", flows[0].AppConfidence)
	}
	if got := flows[1].AppID; got != "web-browsing" {
		t.Fatalf("flows[1].AppID = %q, want web-browsing", got)
	}
	if flows[1].AppProto != "http" || flows[1].AppConfidence != 95 {
		t.Fatalf("engine signal was not preserved with high-confidence App-ID: %+v", flows[1])
	}
	if len(flows[1].AppEvidence) == 0 {
		t.Fatal("expected App-ID evidence")
	}
}

func TestReadFlowsPreservesStampedPolicyVersion(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","flow_id":1234567890123456789,"src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":443,"proto":"TCP","policy_version":7,"policy_stamp":"policy v7 @ 2026-06-11T10:00:00Z","policy_freshness":"fresh","flow":{"pkts_toserver":3,"pkts_toclient":4,"bytes_toserver":500,"bytes_toclient":700}}`
	flows, err := ReadFlows(writeEve(t, eve), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 {
		t.Fatalf("want 1 flow, got %d: %+v", len(flows), flows)
	}
	if flows[0].PolicyVersion != 7 {
		t.Fatalf("PolicyVersion = %d, want 7", flows[0].PolicyVersion)
	}
	if flows[0].PolicyStamp != "policy v7 @ 2026-06-11T10:00:00Z" {
		t.Fatalf("PolicyStamp = %q, want direct event policy stamp", flows[0].PolicyStamp)
	}
	if flows[0].PolicyFreshness != "fresh" {
		t.Fatalf("PolicyFreshness = %q, want fresh", flows[0].PolicyFreshness)
	}
	if flows[0].FlowID != "1234567890123456789" {
		t.Fatalf("FlowID = %q, want decimal Suricata id", flows[0].FlowID)
	}
}

func TestReadFlowsPreservesNestedOpenNGFWPolicyStamp(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","flow_id":"nested-flow","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":443,"proto":"TCP","openngfw":{"config_version":8,"stamp":"openngfw config v8","freshness":"event-time","source":"openngfw.eve"},"flow":{"pkts_toserver":3,"pkts_toclient":4,"bytes_toserver":500,"bytes_toclient":700}}`
	flows, err := ReadFlows(writeEve(t, eve), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 {
		t.Fatalf("want 1 flow, got %d: %+v", len(flows), flows)
	}
	if flows[0].PolicyVersion != 8 || flows[0].PolicyStamp != "openngfw config v8" || flows[0].PolicyFreshness != "event-time" || flows[0].PolicySource != "openngfw.eve" {
		t.Fatalf("nested policy stamp not preserved: %+v", flows[0])
	}
}

func TestReadFlowsFiltered(t *testing.T) {
	path := writeEve(t, sampleFlowEve)
	base := time.Date(2026, 6, 11, 10, 0, 0, 500000000, time.UTC)
	tests := []struct {
		name   string
		filter FlowFilter
		want   []string
	}{
		{name: "ip either endpoint", filter: FlowFilter{IP: "10.100.1.2"}, want: []string{"web-browsing"}},
		{name: "protocol", filter: FlowFilter{Protocol: "tcp"}, want: []string{"ssl", "web-browsing"}},
		{name: "app", filter: FlowFilter{App: "web"}, want: []string{"web-browsing"}},
		{name: "port either endpoint", filter: FlowFilter{Port: 443}, want: []string{"ssl"}},
		{name: "query evidence", filter: FlowFilter{Query: "suricata"}, want: []string{"web-browsing"}},
		{name: "since", filter: FlowFilter{Since: base}, want: []string{"ssl"}},
		{name: "limit after filter", filter: FlowFilter{Protocol: "TCP", Limit: 1}, want: []string{"ssl"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flows, err := ReadFlowsFiltered(path, tt.filter)
			if err != nil {
				t.Fatal(err)
			}
			if len(flows) != len(tt.want) {
				t.Fatalf("got %d flows (%+v), want %d", len(flows), flows, len(tt.want))
			}
			for i, want := range tt.want {
				if flows[i].AppID != want {
					t.Fatalf("flow %d AppID = %q, want %q (all %+v)", i, flows[i].AppID, want, flows)
				}
			}
		})
	}
}

func TestReadFlowsFiltersByFlowID(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","flow_id":"flow-a","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":80,"proto":"TCP","app_proto":"http","flow":{"pkts_toserver":3,"pkts_toclient":4,"bytes_toserver":500,"bytes_toclient":700}}
{"timestamp":"2026-06-11T10:00:01.000001+0000","event_type":"flow","flow_id":"flow-b","src_ip":"10.100.1.3","src_port":40001,"dest_ip":"10.100.2.3","dest_port":443,"proto":"TCP","flow":{"pkts_toserver":1,"pkts_toclient":2,"bytes_toserver":100,"bytes_toclient":200}}`
	flows, err := ReadFlowsFiltered(writeEve(t, eve), FlowFilter{FlowID: "flow-b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 || flows[0].FlowID != "flow-b" || flows[0].AppID != "ssl" {
		t.Fatalf("flow-id filtered flows = %+v, want flow-b ssl", flows)
	}
}

func TestReadFlowsWithCustomAppDefinitions(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8443,"proto":"TCP","flow":{"pkts_toserver":3,"pkts_toclient":4,"bytes_toserver":500,"bytes_toclient":700}}`
	flows, err := ReadFlowsFilteredWithAppDefinitions(writeEve(t, eve), FlowFilter{}, []appid.Definition{{
		ID:       "corp-admin",
		Name:     "Corporate Admin",
		Category: "business-app",
		Ports:    []appid.PortMatch{{Protocol: "tcp", Start: 8443}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 {
		t.Fatalf("want 1 flow, got %d: %+v", len(flows), flows)
	}
	if flows[0].AppID != "corp-admin" || flows[0].AppConfidence != 65 {
		t.Fatalf("custom App-ID not applied: %+v", flows[0])
	}
	if len(flows[0].AppEvidence) != 2 || flows[0].AppEvidence[1] != "custom OpenNGFW port heuristic tcp/8443 -> corp-admin" {
		t.Fatalf("unexpected AppEvidence: %#v", flows[0].AppEvidence)
	}
}
