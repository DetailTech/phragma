package vector

import (
	"strings"
	"testing"

	"github.com/detailtech/oss-ngfw/internal/compiler"
)

func TestRenderDisabled(t *testing.T) {
	got, err := Render(&compiler.IR{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != ModeMarker+ModeDisabled+"\n" {
		t.Fatalf("disabled artifact = %q", got)
	}
}

func TestRenderEnabled(t *testing.T) {
	ir := &compiler.IR{Telemetry: &compiler.TelemetryIR{
		ClickHouseURL: "http://127.0.0.1:8123",
		Database:      "openngfw",
		Exports: []compiler.TelemetryExportIR{
			{
				Name:   "local-json",
				Type:   compiler.TelemetryExportTypeJSONFile,
				Target: "/var/log/openngfw/exports/eve-%Y-%m-%d.json",
			},
			{
				Name:   "siem-tcp",
				Type:   compiler.TelemetryExportTypeJSONTCP,
				Target: "siem.example:5514",
			},
			{
				Name:   "siem-udp",
				Type:   compiler.TelemetryExportTypeJSONUDP,
				Target: "siem.example:5515",
			},
		},
	}}
	got, err := Render(ir, Options{EvePath: "/var/log/openngfw/eve.json", DataDir: "/var/lib/openngfw/vector"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(got)
	for _, want := range []string{
		ModeMarker + ModeEnabled,
		`include: ["/var/log/openngfw/eve.json"]`,
		"endpoint: http://127.0.0.1:8123",
		"database: openngfw",
		"table: events",
		"table: alerts",
		`condition: .event_type == "alert"`,
		"event_export_local_json:",
		"type: file",
		`path: "/var/log/openngfw/exports/eve-%Y-%m-%d.json"`,
		"event_export_siem_tcp:",
		"type: socket",
		`address: "siem.example:5514"`,
		"mode: tcp",
		"method: newline_delimited",
		"event_export_siem_udp:",
		`address: "siem.example:5515"`,
		"mode: udp",
		"codec: json",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
}
