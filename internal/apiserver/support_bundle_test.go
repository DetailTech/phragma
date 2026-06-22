package apiserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/engines"
	"github.com/detailtech/oss-ngfw/internal/store"
	"github.com/detailtech/oss-ngfw/internal/supportbundle"
)

func TestSystemSupportBundleCollectsServerBundle(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	evePath := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(evePath, nil, 0o644); err != nil {
		t.Fatalf("write empty eve file: %v", err)
	}
	contentDir := filepath.Join(t.TempDir(), "content")
	if err := os.MkdirAll(contentDir, 0o755); err != nil {
		t.Fatalf("mkdir content dir: %v", err)
	}
	policyServer := NewPolicyServer(st, engines.NewSupervisor(), func(*openngfwv1.Policy) (map[string][]byte, error) {
		return map[string][]byte{}, nil
	})
	flowServer := &FlowServer{
		EvePath: evePath,
		Store:   st,
		CommandLookup: func(name string) (string, error) {
			return "/usr/sbin/" + name, nil
		},
		CommandRun: func(context.Context, string, ...string) ([]byte, error) {
			return nil, nil
		},
	}
	svc := &SystemService{
		Store:  st,
		Policy: policyServer,
		Alerts: &AlertServer{EvePath: evePath, Store: st},
		Flows:  flowServer,
		Intel:  &IntelServer{Store: st, ContentDir: contentDir},
		Status: SystemStatusConfig{
			StartedAt:                     time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC),
			DataDir:                       "/var/lib/openngfw",
			LogDir:                        "/var/log/openngfw",
			ContentDir:                    contentDir,
			ReleaseAcceptanceManifestPath: filepath.Join(t.TempDir(), "release", "acceptance.json"),
			ReleaseEvidenceDir:            filepath.Join(t.TempDir(), "release", "evidence"),
			ActiveDataplane:               "nftables/conntrack",
		},
	}

	resp, err := svc.GetSupportBundle(context.Background(), &openngfwv1.GetSupportBundleRequest{
		VersionLimit: supportbundle.MaxVersionLimit + 100,
		AuditLimit:   supportbundle.MaxAuditLimit + 100,
		EventLimit:   supportbundle.MaxEventLimit + 100,
	})
	if err != nil {
		t.Fatalf("GetSupportBundle returned error: %v", err)
	}
	if resp.GetSchemaVersion() != supportbundle.Schema {
		t.Fatalf("schema = %q, want %q", resp.GetSchemaVersion(), supportbundle.Schema)
	}
	if resp.GetCollector().GetType() != "server" || resp.GetCollector().GetName() != "controld" {
		t.Fatalf("collector = %#v, want server controld", resp.GetCollector())
	}
	for _, name := range []string{
		"status", "highAvailabilityStatus", "telemetryExportStatus", "identity", "runningPolicy", "candidatePolicy",
		"candidateStatus", "candidateValidation", "runtimeReadinessPreflight", "versions", "audit", "auditIntegrity",
		"alerts", "flows", "sessions", "feeds", "contentPackages", "releaseAcceptanceStatus",
	} {
		if resp.GetEndpoints()[name] == nil {
			t.Fatalf("endpoint %q missing from bundle", name)
		}
	}
	if !resp.GetEndpoints()["candidatePolicy"].GetOk() || !resp.GetEndpoints()["candidateValidation"].GetOk() {
		t.Fatalf("fresh appliance candidate endpoints should be normal: candidate=%#v validation=%#v", resp.GetEndpoints()["candidatePolicy"], resp.GetEndpoints()["candidateValidation"])
	}
	if !resp.GetEndpoints()["runtimeReadinessPreflight"].GetOk() {
		t.Fatalf("runtime readiness preflight endpoint should be normal: %#v", resp.GetEndpoints()["runtimeReadinessPreflight"])
	}
	runtimeReadinessData := resp.GetEndpoints()["runtimeReadinessPreflight"].GetData().GetFields()
	if got := runtimeReadinessData["schemaVersion"].GetStringValue(); got != "phragma.runtime-readiness.v1" {
		t.Fatalf("runtime readiness schemaVersion = %q, want phragma.runtime-readiness.v1", got)
	}
	if got := runtimeReadinessData["operation"].GetStringValue(); got != "commit" {
		t.Fatalf("runtime readiness operation = %q, want commit", got)
	}
	if got := resp.GetSummary().GetRunningPolicyVersion(); got != "none" {
		t.Fatalf("running policy version = %q, want none", got)
	}
	if got := resp.GetSummary().GetTelemetryExportState(); got != "disabled" {
		t.Fatalf("telemetry export state = %q, want disabled", got)
	}
	if got := resp.GetSummary().GetTelemetryExportClickhouseEvidence(); got != "disabled" {
		t.Fatalf("telemetry ClickHouse evidence = %q, want disabled", got)
	}
	if len(resp.GetSummary().GetFailedEndpoints()) != 0 {
		t.Fatalf("failed endpoints = %#v, want none", resp.GetSummary().GetFailedEndpoints())
	}
	runtimeData := resp.GetEndpoints()["status"].GetData().GetFields()["runtime"].GetStructValue().GetFields()
	if got := runtimeData["dataDir"].GetStringValue(); got != supportbundle.Redacted {
		t.Fatalf("runtime dataDir = %q, want redacted", got)
	}
	if got := runtimeData["logDir"].GetStringValue(); got != supportbundle.Redacted {
		t.Fatalf("runtime logDir = %q, want redacted", got)
	}
	releaseData := resp.GetEndpoints()["releaseAcceptanceStatus"].GetData().GetFields()
	if got := releaseData["manifestPath"].GetStringValue(); got != supportbundle.Redacted {
		t.Fatalf("release manifestPath = %q, want redacted", got)
	}
	if got := releaseData["evidenceDir"].GetStringValue(); got != supportbundle.Redacted {
		t.Fatalf("release evidenceDir = %q, want redacted", got)
	}
	haData := resp.GetEndpoints()["highAvailabilityStatus"].GetData().GetFields()
	if got := haData["schemaVersion"].GetStringValue(); got != "phragma.ha.status.v1" {
		t.Fatalf("HA endpoint schemaVersion = %q, want phragma.ha.status.v1", got)
	}
}
