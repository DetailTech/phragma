package cli

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestCandidatePolicyEndpointTreatsMissingCandidateAsNormal(t *testing.T) {
	ep := candidatePolicyEndpoint(nil, status.Error(codes.NotFound, "no candidate policy is set"))
	if !ep.OK {
		t.Fatalf("endpoint OK = false, error %q", ep.Error)
	}
	if string(ep.Data) != "{}" {
		t.Fatalf("endpoint data = %s, want {}", ep.Data)
	}
}

func TestCandidatePolicyEndpointReportsOtherErrors(t *testing.T) {
	ep := candidatePolicyEndpoint(nil, status.Error(codes.PermissionDenied, "no access"))
	if ep.OK {
		t.Fatal("endpoint OK = true, want false")
	}
	if !strings.Contains(ep.Error, "no access") {
		t.Fatalf("endpoint error = %q", ep.Error)
	}
}

func TestRunningPolicyEndpointTreatsMissingRunningPolicyAsNormal(t *testing.T) {
	ep := runningPolicyEndpoint(nil, status.Error(codes.NotFound, "no running policy is set"))
	if !ep.OK {
		t.Fatalf("endpoint OK = false, error %q", ep.Error)
	}
	if string(ep.Data) != "{}" {
		t.Fatalf("endpoint data = %s, want {}", ep.Data)
	}
}

func TestRunningPolicyEndpointReportsOtherErrors(t *testing.T) {
	ep := runningPolicyEndpoint(nil, status.Error(codes.PermissionDenied, "no access"))
	if ep.OK {
		t.Fatal("endpoint OK = true, want false")
	}
	if !strings.Contains(ep.Error, "no access") {
		t.Fatalf("endpoint error = %q", ep.Error)
	}
}

func TestCandidateValidationEndpointTreatsMissingCandidateAsNormal(t *testing.T) {
	ep := candidateValidationEndpoint(nil, status.Error(codes.FailedPrecondition, "no candidate policy is set"))
	if !ep.OK {
		t.Fatalf("endpoint OK = false, error %q", ep.Error)
	}
	if string(ep.Data) != "{}" {
		t.Fatalf("endpoint data = %s, want {}", ep.Data)
	}
}

func TestSupportBundleSchemaUsesPhragmaProductName(t *testing.T) {
	if supportBundleSchema != "phragma.support.bundle.v1" {
		t.Fatalf("support bundle schema = %q, want phragma.support.bundle.v1", supportBundleSchema)
	}
}

func TestSupportBundleCollectorShape(t *testing.T) {
	bundle := supportBundle{
		SchemaVersion: supportBundleSchema,
		CollectedAt:   time.Date(2026, 6, 17, 12, 30, 5, 0, time.UTC).Format(time.RFC3339Nano),
		Collector:     supportBundleCollector{Type: "cli", Name: "ngfwctl", Version: "v-test"},
		Client:        supportBundleClient{Name: "ngfwctl", Version: "v-test"},
		Endpoints:     map[string]supportBundleEndpoint{},
		Summary:       supportBundleSummary{FailedEndpoints: []string{}},
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal support bundle: %v", err)
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("unmarshal support bundle: %v", err)
	}
	collector, ok := data["collector"].(map[string]any)
	if !ok {
		t.Fatalf("collector = %#v, want object", data["collector"])
	}
	if collector["type"] != "cli" || collector["name"] != "ngfwctl" || collector["version"] != "v-test" {
		t.Fatalf("collector = %#v, want cli ngfwctl v-test", collector)
	}
	if _, ok := data["client"].(map[string]any); !ok {
		t.Fatalf("client compatibility field missing: %#v", data["client"])
	}
}

func TestCollectSupportBundleUsesServerRPCWhenAvailable(t *testing.T) {
	serverEndpoint := mustStruct(t, map[string]any{"source": "server-rpc", "count": float64(1)})
	system := &supportBundleTestSystemServer{
		supportBundleResp: &openngfwv1.GetSupportBundleResponse{
			SchemaVersion: supportBundleSchema,
			CollectedAt:   "2026-06-18T12:00:00Z",
			Collector: &openngfwv1.SupportBundleCollector{
				Type:    "server",
				Name:    "controld",
				Version: "v-server",
			},
			Endpoints: map[string]*openngfwv1.SupportBundleEndpoint{
				"serverOnly": {Ok: true, Data: serverEndpoint},
			},
			Summary: &openngfwv1.SupportBundleSummary{
				RuntimeVersion:                             "v-server",
				RunningPolicyVersion:                       "42",
				ReleaseAcceptanceRecordabilityReady:        false,
				ReleaseAcceptanceRecordabilityProblems:     1,
				ReleaseAcceptanceDirtySourcePaths:          2,
				ReleaseAcceptanceTruncatedDirtySourceCount: 4,
				TelemetryExportState:                       "configured",
				TelemetryExportEnabled:                     true,
				TelemetryExportVectorState:                 "active",
				TelemetryExportSinkCount:                   2,
				TelemetryExportObservedSinkCount:           1,
				TelemetryExportClickhouseEvidence:          "configured-unverified",
				TelemetryExportWarnings:                    1,
				AuditIntegrity:                             "verified",
				FailedEndpoints:                            []string{},
			},
		},
	}
	legacy := &supportBundleLegacyServers{}
	conn := newSupportBundleTestConn(t, system, legacy)

	bundle := collectSupportBundle(testSupportBundleContext(t), conn, time.Date(2026, 6, 18, 13, 0, 0, 0, time.UTC), supportBundleOptions{
		versionLimit: 7,
		auditLimit:   8,
		eventLimit:   9,
	})

	if system.supportBundleCallCount() != 1 {
		t.Fatalf("GetSupportBundle calls = %d, want 1", system.supportBundleCallCount())
	}
	req := system.lastSupportBundleRequest()
	if req == nil || req.GetVersionLimit() != 7 || req.GetAuditLimit() != 8 || req.GetEventLimit() != 9 {
		t.Fatalf("GetSupportBundle request = %#v, want requested limits", req)
	}
	if got := system.legacyCallCount(); got != 0 {
		t.Fatalf("legacy SystemService calls = %d, want 0", got)
	}
	if got := legacy.callCount(); got != 0 {
		t.Fatalf("legacy multi-service calls = %d, want 0", got)
	}
	if bundle.Collector != (supportBundleCollector{Type: "server", Name: "controld", Version: "v-server"}) {
		t.Fatalf("collector = %#v, want server collector metadata", bundle.Collector)
	}
	if bundle.Client.Name != "ngfwctl" || bundle.Client.Version == "" {
		t.Fatalf("client = %#v, want ngfwctl client metadata", bundle.Client)
	}
	if bundle.Summary.RuntimeVersion != "v-server" || bundle.Summary.RunningPolicyVersion != "42" {
		t.Fatalf("summary = %#v, want server summary metadata", bundle.Summary)
	}
	if bundle.Summary.ReleaseRecordabilityReady || bundle.Summary.ReleaseRecordabilityProblems != 1 || bundle.Summary.ReleaseDirtySourcePaths != 2 || bundle.Summary.ReleaseTruncatedDirtySourceCount != 4 {
		t.Fatalf("release recordability summary = %#v, want server-provided summary counts", bundle.Summary)
	}
	var endpointData map[string]any
	if err := json.Unmarshal(bundle.Endpoints["serverOnly"].Data, &endpointData); err != nil {
		t.Fatalf("decode serverOnly endpoint: %v", err)
	}
	if endpointData["source"] != "server-rpc" {
		t.Fatalf("serverOnly endpoint data = %#v, want server-rpc source", endpointData)
	}

	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle JSON: %v", err)
	}
	var jsonBundle map[string]any
	if err := json.Unmarshal(raw, &jsonBundle); err != nil {
		t.Fatalf("decode bundle JSON: %v", err)
	}
	if got := dig(jsonBundle, "collector", "name"); got != "controld" {
		t.Fatalf("JSON collector.name = %#v, want controld", got)
	}
	if got := dig(jsonBundle, "client", "name"); got != "ngfwctl" {
		t.Fatalf("JSON client.name = %#v, want ngfwctl", got)
	}
	if got := dig(jsonBundle, "summary", "releaseAcceptanceDirtySourcePaths"); got != float64(2) {
		t.Fatalf("JSON summary.releaseAcceptanceDirtySourcePaths = %#v, want 2", got)
	}
}

func TestCollectSupportBundleFallsBackToLegacyAggregationForUnimplemented(t *testing.T) {
	system := &supportBundleTestSystemServer{
		supportBundleErr: status.Error(codes.Unimplemented, "method GetSupportBundle not implemented"),
	}
	legacy := &supportBundleLegacyServers{}
	conn := newSupportBundleTestConn(t, system, legacy)

	bundle := collectSupportBundle(testSupportBundleContext(t), conn, time.Date(2026, 6, 18, 13, 0, 0, 0, time.UTC), supportBundleOptions{
		versionLimit: 3,
		auditLimit:   4,
		eventLimit:   5,
	})

	if system.supportBundleCallCount() != 1 {
		t.Fatalf("GetSupportBundle calls = %d, want 1", system.supportBundleCallCount())
	}
	if got := system.legacyCallCount(); got != 5 {
		t.Fatalf("legacy SystemService calls = %d, want status, HA status, telemetry export status, identity, release acceptance", got)
	}
	if got := legacy.callCount(); got == 0 {
		t.Fatal("legacy multi-service calls = 0, want fallback aggregation")
	}
	if _, ok := bundle.Endpoints["supportBundle"]; ok {
		t.Fatalf("supportBundle endpoint present during Unimplemented fallback: %#v", bundle.Endpoints["supportBundle"])
	}
	for _, name := range []string{"status", "highAvailabilityStatus", "identity", "runningPolicy", "candidatePolicy", "candidateStatus", "candidateValidation", "versions", "audit", "auditIntegrity", "alerts", "flows", "sessions", "feeds", "contentPackages", "releaseAcceptanceStatus"} {
		ep, ok := bundle.Endpoints[name]
		if !ok {
			t.Fatalf("fallback endpoint %q missing", name)
		}
		if !ep.OK {
			t.Fatalf("fallback endpoint %q failed: %#v", name, ep)
		}
	}
	if bundle.Summary.RuntimeVersion != "legacy-runtime" || bundle.Summary.RunningPolicyVersion != "42" {
		t.Fatalf("summary = %#v, want legacy collected status and running policy", bundle.Summary)
	}
	if bundle.Summary.AlertCount != 1 || bundle.Summary.FlowCount != 1 || bundle.Summary.SessionCount != 1 {
		t.Fatalf("event counts = alerts:%d flows:%d sessions:%d, want 1 each", bundle.Summary.AlertCount, bundle.Summary.FlowCount, bundle.Summary.SessionCount)
	}
	if bundle.Summary.FeedCount != 1 || bundle.Summary.ContentPackageCount != 1 || bundle.Summary.AuditIntegrity != "verified" {
		t.Fatalf("legacy summary = %#v, want feed/content/audit data", bundle.Summary)
	}
}

func TestCollectSupportBundleDoesNotFallbackForNonUnimplementedRPCError(t *testing.T) {
	system := &supportBundleTestSystemServer{
		supportBundleErr: status.Error(codes.PermissionDenied, "support bundle denied token=secret-token"),
	}
	legacy := &supportBundleLegacyServers{}
	conn := newSupportBundleTestConn(t, system, legacy)

	bundle := collectSupportBundle(testSupportBundleContext(t), conn, time.Date(2026, 6, 18, 13, 0, 0, 0, time.UTC), supportBundleOptions{
		versionLimit: 3,
		auditLimit:   4,
		eventLimit:   5,
	})

	if system.supportBundleCallCount() != 1 {
		t.Fatalf("GetSupportBundle calls = %d, want 1", system.supportBundleCallCount())
	}
	if got := system.legacyCallCount(); got != 0 {
		t.Fatalf("legacy SystemService calls = %d, want 0", got)
	}
	if got := legacy.callCount(); got != 0 {
		t.Fatalf("legacy multi-service calls = %d, want 0", got)
	}
	if len(bundle.Endpoints) != 1 {
		t.Fatalf("endpoints = %#v, want only supportBundle failure", bundle.Endpoints)
	}
	ep, ok := bundle.Endpoints["supportBundle"]
	if !ok {
		t.Fatalf("supportBundle endpoint missing from %#v", bundle.Endpoints)
	}
	if ep.OK {
		t.Fatalf("supportBundle endpoint OK = true, want false")
	}
	if !strings.Contains(ep.Error, "PermissionDenied") || !strings.Contains(ep.Error, "token=[redacted]") || strings.Contains(ep.Error, "secret-token") {
		t.Fatalf("supportBundle error = %q, want redacted PermissionDenied error", ep.Error)
	}
	if len(bundle.Summary.FailedEndpoints) != 1 || bundle.Summary.FailedEndpoints[0] != "supportBundle" {
		t.Fatalf("failed endpoints = %#v, want supportBundle", bundle.Summary.FailedEndpoints)
	}
	if bundle.Collector.Type != "cli" || bundle.Collector.Name != "ngfwctl" || bundle.Client.Name != "ngfwctl" {
		t.Fatalf("metadata = collector:%#v client:%#v, want CLI failure bundle metadata", bundle.Collector, bundle.Client)
	}
}

func TestSupportBundleReleaseAcceptanceEndpointIncludesNextAction(t *testing.T) {
	resp := &openngfwv1.GetReleaseAcceptanceStatusResponse{
		State: "blocked",
		Checks: []*openngfwv1.ReleaseAcceptanceCheckStatus{{
			Name:        "proto-verify",
			State:       "missing",
			NextAction:  "Record real evidence for proto-verify with ngfwrelease record; do not edit the manifest by hand.",
			NextCommand: []string{"go", "run", "./cmd/ngfwrelease", "record", "--check", "proto-verify", "--", "make", "proto-verify"},
		}},
	}

	ep := protoEndpoint(resp, nil)
	if !ep.OK {
		t.Fatalf("endpoint OK = false, error %q", ep.Error)
	}
	var data struct {
		State  string `json:"state"`
		Checks []struct {
			Name        string   `json:"name"`
			NextAction  string   `json:"nextAction"`
			NextCommand []string `json:"nextCommand"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(ep.Data, &data); err != nil {
		t.Fatalf("decode release acceptance endpoint: %v\n%s", err, ep.Data)
	}
	if data.State != "blocked" || len(data.Checks) != 1 {
		t.Fatalf("release acceptance endpoint = %+v", data)
	}
	if data.Checks[0].NextAction == "" {
		t.Fatalf("next_action missing in %+v", data.Checks[0])
	}
	if got := strings.Join(data.Checks[0].NextCommand, " "); !strings.Contains(got, "ngfwrelease record") || !strings.Contains(got, "make proto-verify") {
		t.Fatalf("next_command = %q, want ngfwrelease record command ending with make proto-verify", got)
	}
}

func TestSummarizeSupportBundle(t *testing.T) {
	endpoints := map[string]supportBundleEndpoint{
		"status":              {OK: true},
		"candidateStatus":     {OK: true},
		"candidatePolicy":     {OK: true},
		"candidateValidation": {OK: true},
		"auditIntegrity":      {OK: true},
		"identity":            {OK: false, Error: "permission denied"},
	}
	collected := supportBundleCollected{
		Status: &openngfwv1.GetStatusResponse{
			Runtime: &openngfwv1.RuntimeStatus{Version: "v-test", ActiveDataplane: "nftables"},
			Dataplane: &openngfwv1.DataplaneStatus{
				Conntrack: &openngfwv1.ConntrackTableStatus{
					State: "ready", CurrentEntries: 12, MaxEntries: 1024, UsagePercent: 1.2,
				},
			},
			Warnings: []*openngfwv1.StatusWarning{
				{Severity: "critical"},
				{Severity: "warning"},
				{Severity: "info"},
			},
			Engines: []*openngfwv1.EngineStatus{
				{Name: "suricata", State: "failed"},
				{Name: "frr", State: "active"},
			},
		},
		Running: &openngfwv1.GetPolicyResponse{Version: 7},
		CandStat: &openngfwv1.GetCandidateStatusResponse{
			HasCandidate:   true,
			Dirty:          true,
			RunningVersion: 7,
			ChangeCount:    3,
			Impact:         &openngfwv1.ChangeImpact{Risk: openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM},
		},
		Validate: &openngfwv1.ValidateResponse{Valid: false, Impact: &openngfwv1.ChangeImpact{Risk: openngfwv1.ChangeRisk_CHANGE_RISK_HIGH}},
		Alerts:   &openngfwv1.ListAlertsResponse{Alerts: []*openngfwv1.Alert{{}, {}}},
		Flows:    &openngfwv1.ListFlowsResponse{Flows: []*openngfwv1.Flow{{}}},
		Sessions: &openngfwv1.ListSessionsResponse{State: "ready", Sessions: []*openngfwv1.ConntrackSession{{}, {}}},
		Feeds: &openngfwv1.ListFeedsResponse{Feeds: []*openngfwv1.FeedInfo{
			{Name: "one", Enabled: true},
			{Name: "two"},
		}},
		Content: &openngfwv1.ListContentPackagesResponse{Packages: []*openngfwv1.ContentPackageInfo{
			{Kind: "app-id", State: "verified"},
			{Kind: "threat-id", State: "local-only", Blockers: []string{"signed manifest", "package rollback"}},
		}},
		Release: &openngfwv1.GetReleaseAcceptanceStatusResponse{
			State:           "blocked",
			Ready:           false,
			ManifestPresent: false,
			Summary: &openngfwv1.ReleaseAcceptanceStatusSummary{
				Missing:       7,
				Invalid:       1,
				NotApplicable: 2,
				Todo:          3,
			},
			Problems: []string{"proto-verify evidence artifact is missing", "release acceptance manifest release/acceptance.json is missing"},
			Checks: []*openngfwv1.ReleaseAcceptanceCheckStatus{{
				Name:        "proto-verify",
				State:       "missing",
				NextAction:  "Record real evidence for proto-verify with ngfwrelease record; do not edit the manifest by hand.",
				NextCommand: []string{"go", "run", "./cmd/ngfwrelease", "record", "--check", "proto-verify", "--", "make", "proto-verify"},
			}, {
				Name:       "release-benchmark",
				State:      "not_applicable",
				NextAction: "No evidence artifact is required for this check in the current release acceptance context.",
			}},
			Recordability: &openngfwv1.ReleaseAcceptanceRecordabilityStatus{
				Ready:                     false,
				DirtySourcePaths:          []string{" M internal/source.go", "?? internal/generated.go"},
				TruncatedDirtySourceCount: 4,
				Problems:                  []string{"dirty source tree has uncommitted source changes"},
			},
		},
		AuditOK: &openngfwv1.VerifyAuditIntegrityResponse{Ok: true, EntryCount: 4, LatestEntryHash: "abcd1234"},
	}

	summary := summarizeSupportBundle(endpoints, collected)
	if summary.RuntimeVersion != "v-test" || summary.ActiveDataplane != "nftables" || summary.RunningPolicyVersion != "7" {
		t.Fatalf("unexpected identity summary: %#v", summary)
	}
	if summary.CandidateValidation != "invalid" || summary.CandidateImpact != "high" {
		t.Fatalf("unexpected candidate validation summary: %#v", summary)
	}
	if !summary.CandidateHasCandidate || !summary.CandidateDirty || summary.CandidateRunningVersion != 7 || summary.CandidateChangeCount != 3 {
		t.Fatalf("unexpected candidate status summary: %#v", summary)
	}
	if summary.ConntrackState != "ready" || summary.ConntrackEntries != 12 || summary.ConntrackMaxEntries != 1024 || summary.ConntrackUsagePercent != 1.2 {
		t.Fatalf("unexpected conntrack summary: %#v", summary)
	}
	if summary.AlertCount != 2 || summary.FlowCount != 1 || summary.SessionCount != 2 || summary.FeedCount != 2 || summary.EnabledFeeds != 1 {
		t.Fatalf("unexpected count summary: %#v", summary)
	}
	if summary.ContentPackageCount != 2 || summary.VerifiedContentPackages != 1 || summary.ContentPackageBlockers != 2 {
		t.Fatalf("unexpected content package summary: %#v", summary)
	}
	if summary.ReleaseAcceptanceState != "blocked" || summary.ReleaseAcceptanceReady || summary.ReleaseManifestPresent {
		t.Fatalf("unexpected release acceptance state summary: %#v", summary)
	}
	if summary.ReleaseMissing != 7 || summary.ReleaseInvalid != 1 || summary.ReleaseNotApplicable != 2 || summary.ReleaseTodo != 3 || summary.ReleaseProblems != 2 {
		t.Fatalf("unexpected release acceptance count summary: %#v", summary)
	}
	if summary.ReleaseNextActions != 2 || summary.ReleaseNextCommands != 1 {
		t.Fatalf("unexpected release acceptance next-step summary: %#v", summary)
	}
	if summary.ReleaseRecordabilityReady || summary.ReleaseRecordabilityProblems != 1 || summary.ReleaseDirtySourcePaths != 2 || summary.ReleaseTruncatedDirtySourceCount != 4 {
		t.Fatalf("unexpected release acceptance recordability summary: %#v", summary)
	}
	if summary.AuditIntegrity != "verified" || summary.AuditEntryCount != 4 || summary.LatestAuditHash != "abcd1234" {
		t.Fatalf("unexpected audit integrity summary: %#v", summary)
	}
	if summary.CriticalWarnings != 1 || summary.Warnings != 1 || summary.BlockedEngines != 1 {
		t.Fatalf("unexpected warning summary: %#v", summary)
	}
	if len(summary.FailedEndpoints) != 1 || summary.FailedEndpoints[0] != "identity" {
		t.Fatalf("failed endpoints = %#v, want identity", summary.FailedEndpoints)
	}
}

func TestSummarizeSupportBundleReportsNoRunningPolicy(t *testing.T) {
	summary := summarizeSupportBundle(map[string]supportBundleEndpoint{
		"runningPolicy": {OK: true, Data: []byte(`{}`)},
	}, supportBundleCollected{})
	if summary.RunningPolicyVersion != "none" {
		t.Fatalf("running policy version = %q, want none", summary.RunningPolicyVersion)
	}
	if len(summary.FailedEndpoints) != 0 {
		t.Fatalf("failed endpoints = %#v, want none", summary.FailedEndpoints)
	}
}

func TestSummarizeSupportBundleReportsUnavailableRunningPolicy(t *testing.T) {
	summary := summarizeSupportBundle(map[string]supportBundleEndpoint{
		"runningPolicy": {OK: false, Error: "permission denied"},
	}, supportBundleCollected{})
	if summary.RunningPolicyVersion != "unavailable" {
		t.Fatalf("running policy version = %q, want unavailable", summary.RunningPolicyVersion)
	}
	if len(summary.FailedEndpoints) != 1 || summary.FailedEndpoints[0] != "runningPolicy" {
		t.Fatalf("failed endpoints = %#v, want runningPolicy", summary.FailedEndpoints)
	}
}

func TestSupportBundleFilenameIsFilesystemFriendly(t *testing.T) {
	name := supportBundleFilename(time.Date(2026, 6, 17, 12, 30, 5, 123000000, time.UTC))
	if !strings.HasPrefix(name, "phragma-support-2026-06-17T12-30-05-123") || !strings.HasSuffix(name, ".json") {
		t.Fatalf("unexpected filename %q", name)
	}
	stamp := strings.TrimSuffix(strings.TrimPrefix(name, "phragma-support-"), ".json")
	if strings.ContainsAny(stamp, ":.") {
		t.Fatalf("filename contains unsafe timestamp punctuation: %q", name)
	}
}

func TestSupportBundleOutputPath(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 30, 5, 123000000, time.UTC)
	generated := supportBundleFilename(now)

	got, err := supportBundleOutputPath(now, supportBundleOptions{})
	if err != nil {
		t.Fatalf("supportBundleOutputPath(default) error = %v", err)
	}
	if got != generated {
		t.Fatalf("supportBundleOutputPath(default) = %q, want %q", got, generated)
	}

	got, err = supportBundleOutputPath(now, supportBundleOptions{outputDir: "/tmp/support"})
	if err != nil {
		t.Fatalf("supportBundleOutputPath(output-dir) error = %v", err)
	}
	if got != filepath.Join("/tmp/support", generated) {
		t.Fatalf("supportBundleOutputPath(output-dir) = %q, want generated name in dir", got)
	}

	got, err = supportBundleOutputPath(now, supportBundleOptions{outputDir: " /tmp/support "})
	if err != nil {
		t.Fatalf("supportBundleOutputPath(trimmed output-dir) error = %v", err)
	}
	if got != filepath.Join("/tmp/support", generated) {
		t.Fatalf("supportBundleOutputPath(trimmed output-dir) = %q, want generated name in trimmed dir", got)
	}

	got, err = supportBundleOutputPath(now, supportBundleOptions{output: " /tmp/custom.json "})
	if err != nil {
		t.Fatalf("supportBundleOutputPath(output) error = %v", err)
	}
	if got != "/tmp/custom.json" {
		t.Fatalf("supportBundleOutputPath(output) = %q, want explicit path", got)
	}

	got, err = supportBundleOutputPath(now, supportBundleOptions{output: "-"})
	if err != nil {
		t.Fatalf("supportBundleOutputPath(stdout) error = %v", err)
	}
	if got != "-" {
		t.Fatalf("supportBundleOutputPath(stdout) = %q, want -", got)
	}

	if _, err := supportBundleOutputPath(now, supportBundleOptions{output: "/tmp/custom.json", outputDir: "/tmp/support"}); err == nil || !strings.Contains(err.Error(), "either --output or --output-dir") {
		t.Fatalf("supportBundleOutputPath(conflict) error = %v, want flag conflict", err)
	}
}

func TestSupportBundleRedactsSensitiveJSON(t *testing.T) {
	raw := []byte(`{
		"runtime": {"version": "dev", "data_dir": "/var/lib/openngfw", "log_dir": "/var/log/openngfw"},
		"dataplane": {"kernel_tuning": {"sysctl_config_path": "/etc/openngfw/sysctl.d/dataplane.conf"}},
		"latest_entry_hash": "abcd1234",
		"authorization": "Bearer admin-token",
		"oidc_client_secret_file": "/etc/openngfw/oidc-client-secret",
		"policy": {
			"vpn": {
				"ipsec_tunnels": [{"name": "site-a", "psk_file": "/etc/openngfw/secrets/site-a.conf"}],
				"wireguard_interfaces": [{"name": "wg0", "private_key_file": "/etc/openngfw/keys/wg0.key", "public_key": "safe-public-key"}]
			}
		},
		"content_packages": {
			"packages": [{
				"kind": "app-id",
				"manifest_path": "/var/lib/openngfw/content/app-id/manifest.json",
				"rollback_path": "/var/lib/openngfw/content/app-id/.rollback/app-id-1.0.0",
				"restored_rollback_path": "/var/lib/openngfw/content/app-id/.rollback/app-id-0.9.0",
				"source_path": "/tmp/content-import/app-id-1.0.0"
			}]
		},
		"release_acceptance_status": {
			"recordability": {
				"allowed_dirty_paths": ["release/evidence"],
				"dirty_source_paths": [" M internal/source.go", "?? /Users/alice/openngfw/internal/generated.go"]
			}
		},
		"audit": {
			"entries": [{
				"detail": "kind=app-id source='/tmp/content-import/app-id-1.0.0' rollback_path='/var/lib/openngfw/content/app-id/.rollback/app-id-1.0.0' restored_rollback_path='/var/lib/openngfw/content/app-id/.rollback/app-id-0.9.0'"
			}]
		},
		"nested": [{"api_key": "secret-api-key"}],
		"message": "Bearer inline-token password=hunter2 open /Users/alice/Library/Application Support/openngfw/state.db and /home/opc/.config/openngfw/config.yaml and /etc/openngfw/policy.yaml and /var/log/openngfw/controld.log"
	}`)
	redacted := redactSupportBundleRawJSON(raw)
	var data map[string]any
	if err := json.Unmarshal(redacted, &data); err != nil {
		t.Fatalf("redacted JSON did not decode: %v", err)
	}
	if got := data["authorization"]; got != supportBundleRedacted {
		t.Fatalf("authorization = %#v, want redacted", got)
	}
	if got := data["oidc_client_secret_file"]; got != supportBundleRedacted {
		t.Fatalf("oidc_client_secret_file = %#v, want redacted", got)
	}
	if got := data["latest_entry_hash"]; got != "abcd1234" {
		t.Fatalf("latest_entry_hash = %#v, want preserved", got)
	}
	if got := dig(data, "runtime", "data_dir"); got != supportBundleRedacted {
		t.Fatalf("runtime.data_dir = %#v, want redacted", got)
	}
	if got := dig(data, "runtime", "log_dir"); got != supportBundleRedacted {
		t.Fatalf("runtime.log_dir = %#v, want redacted", got)
	}
	if got := dig(data, "dataplane", "kernel_tuning", "sysctl_config_path"); got != supportBundleRedacted {
		t.Fatalf("sysctl_config_path = %#v, want redacted", got)
	}
	if got := dig(data, "policy", "vpn", "ipsec_tunnels", 0, "psk_file"); got != supportBundleRedacted {
		t.Fatalf("psk_file = %#v, want redacted", got)
	}
	if got := dig(data, "policy", "vpn", "wireguard_interfaces", 0, "private_key_file"); got != supportBundleRedacted {
		t.Fatalf("private_key_file = %#v, want redacted", got)
	}
	if got := dig(data, "policy", "vpn", "wireguard_interfaces", 0, "public_key"); got != "safe-public-key" {
		t.Fatalf("public_key = %#v, want preserved", got)
	}
	if got := dig(data, "content_packages", "packages", 0, "manifest_path"); got != supportBundleRedacted {
		t.Fatalf("manifest_path = %#v, want redacted", got)
	}
	if got := dig(data, "content_packages", "packages", 0, "rollback_path"); got != supportBundleRedacted {
		t.Fatalf("rollback_path = %#v, want redacted", got)
	}
	if got := dig(data, "content_packages", "packages", 0, "restored_rollback_path"); got != supportBundleRedacted {
		t.Fatalf("restored_rollback_path = %#v, want redacted", got)
	}
	if got := dig(data, "content_packages", "packages", 0, "source_path"); got != supportBundleRedacted {
		t.Fatalf("source_path = %#v, want redacted", got)
	}
	if got := dig(data, "release_acceptance_status", "recordability", "allowed_dirty_paths", 0); got != supportBundleRedacted {
		t.Fatalf("allowed_dirty_paths[0] = %#v, want redacted", got)
	}
	if got := dig(data, "release_acceptance_status", "recordability", "dirty_source_paths", 0); got != supportBundleRedacted {
		t.Fatalf("dirty_source_paths[0] = %#v, want redacted", got)
	}
	if got := dig(data, "release_acceptance_status", "recordability", "dirty_source_paths", 1); got != supportBundleRedacted {
		t.Fatalf("dirty_source_paths[1] = %#v, want redacted", got)
	}
	detail, _ := dig(data, "audit", "entries", 0, "detail").(string)
	if strings.Contains(detail, "/tmp/") || strings.Contains(detail, "/var/lib/") {
		t.Fatalf("audit detail leaked operational paths: %q", detail)
	}
	if !strings.Contains(detail, "source='[redacted]'") || !strings.Contains(detail, "rollback_path='[redacted]'") || !strings.Contains(detail, "restored_rollback_path='[redacted]'") {
		t.Fatalf("audit detail = %q, want redacted source, rollback_path, and restored_rollback_path", detail)
	}
	if got := dig(data, "nested", 0, "api_key"); got != supportBundleRedacted {
		t.Fatalf("api_key = %#v, want redacted", got)
	}
	message, _ := data["message"].(string)
	if !strings.Contains(message, "Bearer [redacted] password=[redacted]") {
		t.Fatalf("message = %#v, want inline secrets redacted", message)
	}
	for _, leaked := range []string{"inline-token", "hunter2", "/Users/", "/home/", "/etc/openngfw/", "/var/log/"} {
		if strings.Contains(message, leaked) {
			t.Fatalf("message leaked %q: %q", leaked, message)
		}
	}
}

func TestSupportBundleRedactsURLCredentials(t *testing.T) {
	raw := []byte(`{
		"clickhouse_url": "https://writer:hunter2@clickhouse.example:8443?access_token=secret-token&cluster=prod;key=other&public_key=safe",
		"message": "failed to reach https://writer:hunter2@clickhouse.example:8443?cluster=prod;api_key=secret access_token=inline monkey=banana"
	}`)
	redacted := redactSupportBundleRawJSON(raw)
	var data map[string]any
	if err := json.Unmarshal(redacted, &data); err != nil {
		t.Fatalf("redacted JSON did not decode: %v", err)
	}
	wantURL := "https://[redacted]@clickhouse.example:8443?access_token=[redacted]&cluster=prod;key=[redacted]&public_key=safe"
	if got := data["clickhouse_url"]; got != wantURL {
		t.Fatalf("clickhouse_url = %#v, want %q", got, wantURL)
	}
	message, _ := data["message"].(string)
	for _, leaked := range []string{"writer", "hunter2", "secret-token", "api_key=secret", "access_token=inline"} {
		if strings.Contains(message, leaked) {
			t.Fatalf("message leaked %q: %q", leaked, message)
		}
	}
	for _, want := range []string{
		"https://[redacted]@clickhouse.example:8443?cluster=prod;api_key=[redacted]",
		"access_token=[redacted]",
		"monkey=banana",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("message missing %q: %q", want, message)
		}
	}
}

func TestSupportBundleRedactsEndpointErrors(t *testing.T) {
	ep := protoEndpoint(nil, status.Error(codes.Unauthenticated, "Authorization: Bearer rejected-token token=also-secret"))
	if ep.OK {
		t.Fatal("endpoint OK = true, want false")
	}
	if !strings.Contains(ep.Error, "Authorization: Bearer [redacted] token=[redacted]") ||
		strings.Contains(ep.Error, "rejected-token") ||
		strings.Contains(ep.Error, "also-secret") {
		t.Fatalf("endpoint error = %q, want redacted", ep.Error)
	}
}

func TestSupportBundleCollapsesInternalEndpointErrors(t *testing.T) {
	ep := protoEndpoint(nil, status.Error(codes.Internal, "open /var/lib/openngfw/store.db: permission denied"))
	if ep.OK {
		t.Fatal("endpoint OK = true, want false")
	}
	if ep.Error != "internal server error" {
		t.Fatalf("endpoint error = %q, want internal server error", ep.Error)
	}
}

func TestSupportBundleRedactsNonInternalEndpointErrors(t *testing.T) {
	ep := protoEndpoint(nil, status.Error(codes.InvalidArgument, "bad path /var/lib/openngfw/state.db token=also-secret"))
	if ep.OK {
		t.Fatal("endpoint OK = true, want false")
	}
	if strings.Contains(ep.Error, "/var/lib/") || strings.Contains(ep.Error, "also-secret") {
		t.Fatalf("endpoint error leaked sensitive data: %q", ep.Error)
	}
	if !strings.Contains(ep.Error, "token=[redacted]") || !strings.Contains(ep.Error, "[redacted]") {
		t.Fatalf("endpoint error = %q, want redacted non-internal detail", ep.Error)
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
			array, ok := current.([]any)
			if !ok || key < 0 || key >= len(array) {
				return nil
			}
			current = array[key]
		}
	}
	return current
}

func testSupportBundleContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func newSupportBundleTestConn(t *testing.T, system *supportBundleTestSystemServer, legacy *supportBundleLegacyServers) *grpc.ClientConn {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	openngfwv1.RegisterSystemServiceServer(server, system)
	openngfwv1.RegisterPolicyServiceServer(server, &legacy.policy)
	openngfwv1.RegisterAlertServiceServer(server, &legacy.alerts)
	openngfwv1.RegisterFlowServiceServer(server, &legacy.flows)
	openngfwv1.RegisterIntelServiceServer(server, &legacy.intel)
	go func() {
		_ = server.Serve(listener)
	}()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("create bufconn client: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		server.Stop()
		_ = listener.Close()
	})
	return conn
}

func mustStruct(t *testing.T, fields map[string]any) *structpb.Struct {
	t.Helper()
	value, err := structpb.NewStruct(fields)
	if err != nil {
		t.Fatalf("create structpb.Struct: %v", err)
	}
	return value
}

type supportBundleTestSystemServer struct {
	openngfwv1.UnimplementedSystemServiceServer

	mu                sync.Mutex
	supportBundleResp *openngfwv1.GetSupportBundleResponse
	supportBundleErr  error
	supportBundleReq  *openngfwv1.GetSupportBundleRequest
	supportBundle     int
	status            int
	haStatus          int
	telemetryExport   int
	identity          int
	release           int
}

func (s *supportBundleTestSystemServer) GetSupportBundle(_ context.Context, req *openngfwv1.GetSupportBundleRequest) (*openngfwv1.GetSupportBundleResponse, error) {
	s.mu.Lock()
	s.supportBundle++
	if req != nil {
		s.supportBundleReq = proto.Clone(req).(*openngfwv1.GetSupportBundleRequest)
	} else {
		s.supportBundleReq = nil
	}
	resp, err := s.supportBundleResp, s.supportBundleErr
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *supportBundleTestSystemServer) GetStatus(context.Context, *openngfwv1.GetStatusRequest) (*openngfwv1.GetStatusResponse, error) {
	s.mu.Lock()
	s.status++
	s.mu.Unlock()
	return &openngfwv1.GetStatusResponse{
		Runtime: &openngfwv1.RuntimeStatus{Version: "legacy-runtime", ActiveDataplane: "nftables"},
		Dataplane: &openngfwv1.DataplaneStatus{
			ActiveDataplane: "nftables",
			Conntrack:       &openngfwv1.ConntrackTableStatus{State: "ready", CurrentEntries: 11, MaxEntries: 100, UsagePercent: 11},
		},
	}, nil
}

func (s *supportBundleTestSystemServer) GetHighAvailabilityStatus(context.Context, *openngfwv1.GetHighAvailabilityStatusRequest) (*openngfwv1.GetHighAvailabilityStatusResponse, error) {
	s.mu.Lock()
	s.haStatus++
	s.mu.Unlock()
	return &openngfwv1.GetHighAvailabilityStatusResponse{
		SchemaVersion: "phragma.ha.status.v1",
		GeneratedAt:   "2026-06-18T12:00:00Z",
		Status: &openngfwv1.HighAvailabilityStatus{
			State: "standalone",
			Mode:  "standalone",
			Role:  "standalone",
			Sync:  &openngfwv1.HighAvailabilitySyncStatus{State: "not_configured"},
		},
	}, nil
}

func (s *supportBundleTestSystemServer) GetTelemetryExportStatus(context.Context, *openngfwv1.GetTelemetryExportStatusRequest) (*openngfwv1.GetTelemetryExportStatusResponse, error) {
	s.mu.Lock()
	s.telemetryExport++
	s.mu.Unlock()
	return &openngfwv1.GetTelemetryExportStatusResponse{
		SchemaVersion:        "phragma.telemetry.export.status.v1",
		State:                "disabled",
		Detail:               "Telemetry disabled in test fixture.",
		TelemetryEnabled:     false,
		RunningPolicyVersion: 0,
		Vector:               &openngfwv1.TelemetryVectorRuntimeStatus{State: "unmanaged", Detail: "test fixture"},
		Clickhouse:           &openngfwv1.TelemetryClickHouseSinkStatus{Configured: false, EvidenceState: "disabled"},
	}, nil
}

func (s *supportBundleTestSystemServer) GetIdentity(context.Context, *openngfwv1.GetIdentityRequest) (*openngfwv1.GetIdentityResponse, error) {
	s.mu.Lock()
	s.identity++
	s.mu.Unlock()
	return &openngfwv1.GetIdentityResponse{Actor: "test-operator", Role: "admin"}, nil
}

func (s *supportBundleTestSystemServer) GetReleaseAcceptanceStatus(context.Context, *openngfwv1.GetReleaseAcceptanceStatusRequest) (*openngfwv1.GetReleaseAcceptanceStatusResponse, error) {
	s.mu.Lock()
	s.release++
	s.mu.Unlock()
	return &openngfwv1.GetReleaseAcceptanceStatusResponse{
		State:           "ready",
		Ready:           true,
		ManifestPresent: true,
	}, nil
}

func (s *supportBundleTestSystemServer) supportBundleCallCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.supportBundle
}

func (s *supportBundleTestSystemServer) legacyCallCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status + s.haStatus + s.telemetryExport + s.identity + s.release
}

func (s *supportBundleTestSystemServer) lastSupportBundleRequest() *openngfwv1.GetSupportBundleRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.supportBundleReq == nil {
		return nil
	}
	return proto.Clone(s.supportBundleReq).(*openngfwv1.GetSupportBundleRequest)
}

type supportBundleLegacyServers struct {
	policy supportBundleTestPolicyServer
	alerts supportBundleTestAlertServer
	flows  supportBundleTestFlowServer
	intel  supportBundleTestIntelServer
}

func (s *supportBundleLegacyServers) callCount() int {
	return s.policy.callCount() + s.alerts.callCount() + s.flows.callCount() + s.intel.callCount()
}

type supportBundleTestPolicyServer struct {
	openngfwv1.UnimplementedPolicyServiceServer
	mu              sync.Mutex
	getPolicy       int
	candidateStatus int
	validate        int
	versions        int
	audit           int
	auditIntegrity  int
}

func (s *supportBundleTestPolicyServer) GetPolicy(_ context.Context, req *openngfwv1.GetPolicyRequest) (*openngfwv1.GetPolicyResponse, error) {
	s.mu.Lock()
	s.getPolicy++
	s.mu.Unlock()
	if req.GetSource() == openngfwv1.PolicySource_POLICY_SOURCE_RUNNING {
		return &openngfwv1.GetPolicyResponse{Policy: &openngfwv1.Policy{}, Version: 42}, nil
	}
	return &openngfwv1.GetPolicyResponse{Policy: &openngfwv1.Policy{}}, nil
}

func (s *supportBundleTestPolicyServer) GetCandidateStatus(context.Context, *openngfwv1.GetCandidateStatusRequest) (*openngfwv1.GetCandidateStatusResponse, error) {
	s.mu.Lock()
	s.candidateStatus++
	s.mu.Unlock()
	return &openngfwv1.GetCandidateStatusResponse{HasCandidate: true, Dirty: true, RunningVersion: 42, ChangeCount: 1}, nil
}

func (s *supportBundleTestPolicyServer) Validate(context.Context, *openngfwv1.ValidateRequest) (*openngfwv1.ValidateResponse, error) {
	s.mu.Lock()
	s.validate++
	s.mu.Unlock()
	return &openngfwv1.ValidateResponse{Valid: true}, nil
}

func (s *supportBundleTestPolicyServer) ListVersions(context.Context, *openngfwv1.ListVersionsRequest) (*openngfwv1.ListVersionsResponse, error) {
	s.mu.Lock()
	s.versions++
	s.mu.Unlock()
	return &openngfwv1.ListVersionsResponse{}, nil
}

func (s *supportBundleTestPolicyServer) ListAuditEntries(context.Context, *openngfwv1.ListAuditEntriesRequest) (*openngfwv1.ListAuditEntriesResponse, error) {
	s.mu.Lock()
	s.audit++
	s.mu.Unlock()
	return &openngfwv1.ListAuditEntriesResponse{}, nil
}

func (s *supportBundleTestPolicyServer) VerifyAuditIntegrity(context.Context, *openngfwv1.VerifyAuditIntegrityRequest) (*openngfwv1.VerifyAuditIntegrityResponse, error) {
	s.mu.Lock()
	s.auditIntegrity++
	s.mu.Unlock()
	return &openngfwv1.VerifyAuditIntegrityResponse{Ok: true, EntryCount: 1, LatestEntryHash: "hash"}, nil
}

func (s *supportBundleTestPolicyServer) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getPolicy + s.candidateStatus + s.validate + s.versions + s.audit + s.auditIntegrity
}

type supportBundleTestAlertServer struct {
	openngfwv1.UnimplementedAlertServiceServer
	mu    sync.Mutex
	calls int
}

func (s *supportBundleTestAlertServer) ListAlerts(context.Context, *openngfwv1.ListAlertsRequest) (*openngfwv1.ListAlertsResponse, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return &openngfwv1.ListAlertsResponse{Alerts: []*openngfwv1.Alert{{Signature: "alert-1"}}}, nil
}

func (s *supportBundleTestAlertServer) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

type supportBundleTestFlowServer struct {
	openngfwv1.UnimplementedFlowServiceServer
	mu       sync.Mutex
	flows    int
	sessions int
}

func (s *supportBundleTestFlowServer) ListFlows(context.Context, *openngfwv1.ListFlowsRequest) (*openngfwv1.ListFlowsResponse, error) {
	s.mu.Lock()
	s.flows++
	s.mu.Unlock()
	return &openngfwv1.ListFlowsResponse{Flows: []*openngfwv1.Flow{{SrcIp: "10.0.0.10", DestIp: "10.0.0.20"}}}, nil
}

func (s *supportBundleTestFlowServer) ListSessions(context.Context, *openngfwv1.ListSessionsRequest) (*openngfwv1.ListSessionsResponse, error) {
	s.mu.Lock()
	s.sessions++
	s.mu.Unlock()
	return &openngfwv1.ListSessionsResponse{State: "ready", Sessions: []*openngfwv1.ConntrackSession{{Protocol: "tcp"}}}, nil
}

func (s *supportBundleTestFlowServer) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flows + s.sessions
}

type supportBundleTestIntelServer struct {
	openngfwv1.UnimplementedIntelServiceServer
	mu      sync.Mutex
	feeds   int
	content int
}

func (s *supportBundleTestIntelServer) ListFeeds(context.Context, *openngfwv1.ListFeedsRequest) (*openngfwv1.ListFeedsResponse, error) {
	s.mu.Lock()
	s.feeds++
	s.mu.Unlock()
	return &openngfwv1.ListFeedsResponse{Feeds: []*openngfwv1.FeedInfo{{Name: "feed-1", Enabled: true}}}, nil
}

func (s *supportBundleTestIntelServer) ListContentPackages(context.Context, *openngfwv1.ListContentPackagesRequest) (*openngfwv1.ListContentPackagesResponse, error) {
	s.mu.Lock()
	s.content++
	s.mu.Unlock()
	return &openngfwv1.ListContentPackagesResponse{Packages: []*openngfwv1.ContentPackageInfo{{Kind: "app-id", State: "verified"}}}, nil
}

func (s *supportBundleTestIntelServer) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.feeds + s.content
}
