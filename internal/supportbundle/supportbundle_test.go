package supportbundle

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestLimitsNormalizeDefaultsAndCaps(t *testing.T) {
	got := (Limits{}).Normalize()
	if got.VersionLimit != DefaultVersionLimit || got.AuditLimit != DefaultAuditLimit || got.EventLimit != DefaultEventLimit {
		t.Fatalf("default limits = %#v", got)
	}

	got = Limits{
		VersionLimit: MaxVersionLimit + 1,
		AuditLimit:   MaxAuditLimit + 1,
		EventLimit:   MaxEventLimit + 1,
	}.Normalize()
	if got.VersionLimit != MaxVersionLimit || got.AuditLimit != MaxAuditLimit || got.EventLimit != MaxEventLimit {
		t.Fatalf("capped limits = %#v", got)
	}
}

func TestBuildAndToProtoPreserveRedactedEndpointShape(t *testing.T) {
	endpoints := map[string]Endpoint{
		"status": {
			OK:   true,
			Data: RedactRawJSON([]byte(`{"runtime":{"version":"dev","dataDir":"/var/lib/openngfw"},"warnings":[]}`)),
		},
	}
	bundle := Build(
		time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC),
		Collector{Type: "server", Name: "controld", Version: "v-test"},
		Client{},
		endpoints,
		Collected{},
	)
	if bundle.SchemaVersion != Schema {
		t.Fatalf("schema = %q, want %q", bundle.SchemaVersion, Schema)
	}

	resp, err := ToProto(bundle)
	if err != nil {
		t.Fatalf("ToProto: %v", err)
	}
	if resp.GetCollector().GetName() != "controld" {
		t.Fatalf("collector = %#v", resp.GetCollector())
	}
	runtimeFields := resp.GetEndpoints()["status"].GetData().GetFields()["runtime"].GetStructValue().GetFields()
	if got := runtimeFields["dataDir"].GetStringValue(); got != Redacted {
		t.Fatalf("dataDir = %q, want redacted", got)
	}
	if got := resp.GetSummary().GetRunningPolicyVersion(); got != "none" {
		t.Fatalf("running policy version = %q, want none", got)
	}

	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal JSON bundle: %v", err)
	}
	if !json.Valid(raw) {
		t.Fatalf("bundle JSON is invalid: %s", raw)
	}

	roundTrip, err := FromProto(resp, Client{Name: "ngfwctl", Version: "v-client"})
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if roundTrip.Client.Name != "ngfwctl" || roundTrip.Collector.Name != "controld" {
		t.Fatalf("round trip metadata = client:%#v collector:%#v", roundTrip.Client, roundTrip.Collector)
	}
	if got := string(roundTrip.Endpoints["status"].Data); got == "" {
		t.Fatalf("round trip endpoint data missing")
	}
}

func TestSummarizeIncludesTelemetryExportStatus(t *testing.T) {
	bundle := Build(
		time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC),
		Collector{Type: "server", Name: "controld", Version: "v-test"},
		Client{},
		map[string]Endpoint{},
		Collected{
			TelemetryExport: &openngfwv1.GetTelemetryExportStatusResponse{
				State:            "configured",
				TelemetryEnabled: true,
				Vector:           &openngfwv1.TelemetryVectorRuntimeStatus{State: "active"},
				Clickhouse:       &openngfwv1.TelemetryClickHouseSinkStatus{Configured: true, EvidenceState: "configured-unverified"},
				Exports: []*openngfwv1.TelemetryExportSinkStatus{
					{Name: "local-json", EvidenceState: "receiving"},
					{Name: "siem-json", EvidenceState: "configured-unverified"},
				},
				Warnings: []*openngfwv1.StatusWarning{{Severity: "info", Message: "receiver proof required"}},
			},
		},
	)

	if bundle.Summary.TelemetryExportState != "configured" {
		t.Fatalf("telemetry state = %q, want configured", bundle.Summary.TelemetryExportState)
	}
	if !bundle.Summary.TelemetryExportEnabled {
		t.Fatal("telemetry enabled = false, want true")
	}
	if bundle.Summary.TelemetryExportVectorState != "active" {
		t.Fatalf("vector state = %q, want active", bundle.Summary.TelemetryExportVectorState)
	}
	if bundle.Summary.TelemetryExportSinkCount != 2 || bundle.Summary.TelemetryExportObservedSinkCount != 1 {
		t.Fatalf("sink counts = total:%d observed:%d, want 2/1", bundle.Summary.TelemetryExportSinkCount, bundle.Summary.TelemetryExportObservedSinkCount)
	}
	if bundle.Summary.TelemetryExportClickHouseEvidence != "configured-unverified" {
		t.Fatalf("clickhouse evidence = %q, want configured-unverified", bundle.Summary.TelemetryExportClickHouseEvidence)
	}
	if bundle.Summary.TelemetryExportWarnings != 1 {
		t.Fatalf("warnings = %d, want 1", bundle.Summary.TelemetryExportWarnings)
	}

	resp, err := ToProto(bundle)
	if err != nil {
		t.Fatalf("ToProto: %v", err)
	}
	if got := resp.GetSummary().GetTelemetryExportObservedSinkCount(); got != 1 {
		t.Fatalf("proto observed sinks = %d, want 1", got)
	}
	roundTrip, err := FromProto(resp, Client{Name: "ngfwctl"})
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	if roundTrip.Summary.TelemetryExportState != "configured" || roundTrip.Summary.TelemetryExportSinkCount != 2 {
		t.Fatalf("round trip telemetry summary = %#v", roundTrip.Summary)
	}
}

func TestFromProtoRedactsServerEndpointDataAndErrors(t *testing.T) {
	data, err := structpb.NewStruct(map[string]any{
		"authorization": "Bearer raw-token",
		"runtime": map[string]any{
			"dataDir": "/var/lib/openngfw",
		},
		"message": "token=raw-token url=https://user:pass@clickhouse.example:8443?api_key=raw-secret&cluster=prod",
	})
	if err != nil {
		t.Fatalf("NewStruct: %v", err)
	}
	resp := &openngfwv1.GetSupportBundleResponse{
		SchemaVersion: Schema,
		CollectedAt:   "2026-06-18T12:00:00Z",
		Collector: &openngfwv1.SupportBundleCollector{
			Type:    "server",
			Name:    "controld",
			Version: "v-test",
		},
		Endpoints: map[string]*openngfwv1.SupportBundleEndpoint{
			"status": {
				Ok:    false,
				Error: "PermissionDenied Authorization: Bearer raw-token token=raw-token",
				Data:  data,
			},
		},
	}

	bundle, err := FromProto(resp, Client{Name: "ngfwctl"})
	if err != nil {
		t.Fatalf("FromProto: %v", err)
	}
	ep := bundle.Endpoints["status"]
	if strings.Contains(ep.Error, "raw-token") || !strings.Contains(ep.Error, "Bearer "+Redacted) || !strings.Contains(ep.Error, "token="+Redacted) {
		t.Fatalf("endpoint error = %q, want server error re-redacted", ep.Error)
	}
	var decoded map[string]any
	if err := json.Unmarshal(ep.Data, &decoded); err != nil {
		t.Fatalf("unmarshal endpoint data: %v", err)
	}
	if got := decoded["authorization"]; got != Redacted {
		t.Fatalf("authorization = %#v, want redacted", got)
	}
	runtime, ok := decoded["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("runtime = %#v, want object", decoded["runtime"])
	}
	if got := runtime["dataDir"]; got != Redacted {
		t.Fatalf("runtime.dataDir = %#v, want redacted", got)
	}
	message, _ := decoded["message"].(string)
	if strings.Contains(message, "raw-token") || strings.Contains(message, "raw-secret") || strings.Contains(message, "user:pass") {
		t.Fatalf("message = %q, want inline token, query secret, and URL userinfo redacted", message)
	}
	if !strings.Contains(message, "token="+Redacted) || !strings.Contains(message, "https://"+Redacted+"@clickhouse.example:8443?api_key="+Redacted+"&cluster=prod") {
		t.Fatalf("message = %q, want redacted token and URL", message)
	}
}

func TestRedactRawJSONRedactsReleaseAndReadinessCommands(t *testing.T) {
	raw := []byte(`{
		"runtime_readiness_preflight": {
			"detail": "runtime proof at /opt/phragma/runtime/status.json",
			"items": [{
				"message": "token=runtime-secret evidence_path=/data/openngfw/runtime-preflight.json",
				"command": ["ngfwctl", "system", "runtime-readiness", "--token", "runtime-command-secret", "--output=/opt/phragma/runtime-preflight.json"]
			}]
		},
		"release_acceptance_status": {
			"checks": [{
				"next_action": "Record real evidence from /home/opc/field-evidence with token=release-secret.",
				"next_command": ["go", "run", "./cmd/ngfwrelease", "record", "privileged-integration", "--token", "release-command-secret", "--evidence-dir=/opt/phragma/release/evidence", "--", "make", "integration-test"]
			}]
		}
	}`)
	redacted := RedactRawJSON(raw)
	var data map[string]any
	if err := json.Unmarshal(redacted, &data); err != nil {
		t.Fatalf("redacted JSON did not decode: %v", err)
	}

	readinessMessage, _ := dig(data, "runtime_readiness_preflight", "items", 0, "message").(string)
	for _, leaked := range []string{"runtime-secret", "/data/openngfw", "/opt/phragma"} {
		if strings.Contains(readinessMessage, leaked) {
			t.Fatalf("readiness message leaked %q: %q", leaked, readinessMessage)
		}
	}
	wantReadinessCommand := []any{"ngfwctl", "system", "runtime-readiness", "--token", Redacted, "--output=" + Redacted}
	if got := dig(data, "runtime_readiness_preflight", "items", 0, "command"); !reflect.DeepEqual(got, wantReadinessCommand) {
		t.Fatalf("readiness command = %#v, want %#v", got, wantReadinessCommand)
	}

	nextAction, _ := dig(data, "release_acceptance_status", "checks", 0, "next_action").(string)
	for _, leaked := range []string{"/home/opc", "release-secret"} {
		if strings.Contains(nextAction, leaked) {
			t.Fatalf("release next_action leaked %q: %q", leaked, nextAction)
		}
	}
	wantNextCommand := []any{"go", "run", "./cmd/ngfwrelease", "record", "privileged-integration", "--token", Redacted, "--evidence-dir=" + Redacted, "--", "make", "integration-test"}
	if got := dig(data, "release_acceptance_status", "checks", 0, "next_command"); !reflect.DeepEqual(got, wantNextCommand) {
		t.Fatalf("next_command = %#v, want %#v", got, wantNextCommand)
	}
}

func dig(value any, path ...any) any {
	current := value
	for _, part := range path {
		switch key := part.(type) {
		case string:
			object, ok := current.(map[string]any)
			if !ok {
				return nil
			}
			current = object[key]
		case int:
			list, ok := current.([]any)
			if !ok || key < 0 || key >= len(list) {
				return nil
			}
			current = list[key]
		default:
			return nil
		}
	}
	return current
}
