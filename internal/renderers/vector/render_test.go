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
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
}
