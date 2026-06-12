package telemetry

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleEve = `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","src_ip":"10.0.0.1"}
{"timestamp":"2026-06-11T10:00:01.000001+0000","event_type":"alert","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8080,"proto":"TCP","alert":{"action":"allowed","signature_id":9000001,"signature":"NGFW TEST evil","category":"Misc Attack","severity":2}}
{"timestamp":"2026-06-11T10:00:02.000001+0000","event_type":"alert","src_ip":"10.100.1.3","src_port":40001,"dest_ip":"10.100.2.2","dest_port":8080,"proto":"TCP","alert":{"action":"blocked","signature_id":9000002,"signature":"NGFW TEST evil 2","category":"Misc Attack","severity":1}}
not json at all
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

func TestReadAlertsMissingFile(t *testing.T) {
	alerts, err := ReadAlerts(filepath.Join(t.TempDir(), "absent.json"), 0)
	if err != nil || alerts != nil {
		t.Fatalf("missing file: %v %v", alerts, err)
	}
}
