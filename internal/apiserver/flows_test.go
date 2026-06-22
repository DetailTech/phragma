package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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

func TestFlowServerReturnsCanonicalAppID(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":53,"proto":"UDP","app_proto":"dns","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":80,"bytes_toclient":120}}`
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte(eve+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resp, err := (&FlowServer{EvePath: path}).ListFlows(context.Background(), &openngfwv1.ListFlowsRequest{})
	if err != nil {
		t.Fatalf("ListFlows returned error: %v", err)
	}
	if len(resp.GetFlows()) != 1 {
		t.Fatalf("got %d flows, want 1", len(resp.GetFlows()))
	}
	flow := resp.GetFlows()[0]
	if flow.GetAppProtocol() != "dns" {
		t.Fatalf("AppProtocol = %q, want raw dns signal", flow.GetAppProtocol())
	}
	if flow.GetAppId() != "dns" {
		t.Fatalf("AppId = %q, want dns", flow.GetAppId())
	}
	if flow.GetAppCategory() != "network-service" {
		t.Fatalf("AppCategory = %q, want network-service", flow.GetAppCategory())
	}
	if flow.GetAppConfidence() != 95 {
		t.Fatalf("AppConfidence = %d, want 95", flow.GetAppConfidence())
	}
	if len(flow.GetAppEvidence()) != 3 || flow.GetAppEvidence()[2] != "port heuristic udp/53 confirms dns" {
		t.Fatalf("unexpected AppEvidence: %#v", flow.GetAppEvidence())
	}
}

func TestFlowServerFilters(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.700001+0000","event_type":"flow","flow_id":"flow-1","src_ip":"10.100.1.3","src_port":40000,"dest_ip":"10.100.2.3","dest_port":443,"proto":"TCP","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":80,"bytes_toclient":120}}
{"timestamp":"2026-06-11T10:00:01.000001+0000","event_type":"flow","flow_id":"flow-2","src_ip":"10.100.1.3","src_port":40001,"dest_ip":"10.100.2.3","dest_port":443,"proto":"TCP","flow":{"pkts_toserver":1,"pkts_toclient":2,"bytes_toserver":100,"bytes_toclient":200}}`
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte(eve+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resp, err := (&FlowServer{EvePath: path}).ListFlows(context.Background(), &openngfwv1.ListFlowsRequest{
		Ip:       "10.100.1.3",
		Protocol: "tcp",
		App:      "ssl",
		Port:     443,
		FlowId:   "flow-2",
		Since:    timestamppb.New(time.Date(2026, 6, 11, 10, 0, 0, 500000000, time.UTC)),
		Query:    "heuristic",
	})
	if err != nil {
		t.Fatalf("ListFlows returned error: %v", err)
	}
	if len(resp.GetFlows()) != 1 || resp.GetFlows()[0].GetAppId() != "ssl" {
		t.Fatalf("filtered flows = %#v", resp.GetFlows())
	}
	if resp.GetFlows()[0].GetFlowId() != "flow-2" {
		t.Fatalf("FlowId = %q, want flow-2", resp.GetFlows()[0].GetFlowId())
	}
}

func TestFlowServerPaginatesFilteredFlows(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","flow_id":"flow-1","src_ip":"10.100.1.1","src_port":40000,"dest_ip":"10.100.2.1","dest_port":443,"proto":"TCP","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":80,"bytes_toclient":120}}
{"timestamp":"2026-06-11T10:00:01.000001+0000","event_type":"flow","flow_id":"flow-2","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":443,"proto":"TCP","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":80,"bytes_toclient":120}}
{"timestamp":"2026-06-11T10:00:02.000001+0000","event_type":"flow","flow_id":"flow-3","src_ip":"10.100.1.3","src_port":40000,"dest_ip":"10.100.2.3","dest_port":443,"proto":"TCP","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":80,"bytes_toclient":120}}`
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte(eve+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := &FlowServer{EvePath: path}
	first, err := srv.ListFlows(context.Background(), &openngfwv1.ListFlowsRequest{Limit: 2, Protocol: "tcp"})
	if err != nil {
		t.Fatalf("ListFlows first page returned error: %v", err)
	}
	if got := flowIDs(first.GetFlows()); strings.Join(got, ",") != "flow-3,flow-2" {
		t.Fatalf("first page flow ids = %v", got)
	}
	if !first.GetHasMore() || first.GetNextCursor() != "2" || first.GetTotalMatches() != 3 {
		t.Fatalf("first page metadata = hasMore:%v cursor:%q total:%d", first.GetHasMore(), first.GetNextCursor(), first.GetTotalMatches())
	}
	second, err := srv.ListFlows(context.Background(), &openngfwv1.ListFlowsRequest{Limit: 2, Protocol: "tcp", PageCursor: first.GetNextCursor()})
	if err != nil {
		t.Fatalf("ListFlows second page returned error: %v", err)
	}
	if got := flowIDs(second.GetFlows()); strings.Join(got, ",") != "flow-1" {
		t.Fatalf("second page flow ids = %v", got)
	}
	if second.GetHasMore() || second.GetNextCursor() != "" || second.GetTotalMatches() != 3 {
		t.Fatalf("second page metadata = hasMore:%v cursor:%q total:%d", second.GetHasMore(), second.GetNextCursor(), second.GetTotalMatches())
	}
}

func TestFlowServerRejectsInvalidPageCursor(t *testing.T) {
	_, err := (&FlowServer{}).ListFlows(context.Background(), &openngfwv1.ListFlowsRequest{PageCursor: "not-a-cursor"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}
}

func flowIDs(flows []*openngfwv1.Flow) []string {
	out := make([]string, 0, len(flows))
	for _, flow := range flows {
		out = append(out, flow.GetFlowId())
	}
	return out
}

func TestFlowServerUsesRunningPolicyCustomApplications(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","flow_id":12345,"src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8443,"proto":"TCP","policy_version":1,"policy_stamp":"policy v1 @ 2026-06-11T10:00:00Z","policy_freshness":"event-time","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":80,"bytes_toclient":120}}`
	evePath := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(evePath, []byte(eve+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_, err = st.CommitVersion(&openngfwv1.Policy{Applications: []*openngfwv1.Application{{
		Name:        "corp-admin",
		DisplayName: "Corporate Admin",
		Category:    "business-app",
		Ports: []*openngfwv1.ApplicationPort{{
			Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
			Ports:    []*openngfwv1.PortRange{{Start: 8443}},
		}},
	}}}, "tester", "custom app")
	if err != nil {
		t.Fatal(err)
	}

	resp, err := (&FlowServer{EvePath: evePath, Store: st}).ListFlows(context.Background(), &openngfwv1.ListFlowsRequest{})
	if err != nil {
		t.Fatalf("ListFlows returned error: %v", err)
	}
	if len(resp.GetFlows()) != 1 {
		t.Fatalf("got %d flows, want 1", len(resp.GetFlows()))
	}
	if resp.GetRunningPolicyVersion() != 1 {
		t.Fatalf("RunningPolicyVersion = %d, want 1", resp.GetRunningPolicyVersion())
	}
	if resp.GetPolicyContext() == "" {
		t.Fatal("expected policy context")
	}
	flow := resp.GetFlows()[0]
	if flow.GetPolicyVersion() != 1 || !flow.GetPolicyVersionKnown() {
		t.Fatalf("flow policy version not preserved: %#v", flow)
	}
	if flow.GetFlowId() != "12345" {
		t.Fatalf("FlowId = %q, want 12345", flow.GetFlowId())
	}
	if flow.GetAppId() != "corp-admin" || flow.GetAppName() != "Corporate Admin" || flow.GetAppCategory() != "business-app" {
		t.Fatalf("custom App-ID fields not applied: %#v", flow)
	}
	if flow.GetAppConfidence() != 65 {
		t.Fatalf("AppConfidence = %d, want 65", flow.GetAppConfidence())
	}
	evidenceText := strings.Join(flow.GetAppEvidence(), "\n")
	if !strings.Contains(evidenceText, "custom OpenNGFW port heuristic tcp/8443 -> corp-admin") {
		t.Fatalf("unexpected AppEvidence: %#v", flow.GetAppEvidence())
	}
	if !strings.Contains(evidenceText, "event policy stamp: policy v1 @ 2026-06-11T10:00:00Z") || !strings.Contains(evidenceText, "event policy freshness: event-time") {
		t.Fatalf("event policy evidence missing: %#v", flow.GetAppEvidence())
	}
}

func TestFlowServerUsesSignedPackageAppIDTaxonomy(t *testing.T) {
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","flow_id":"pkg-flow","src_ip":"10.100.1.2","src_port":40000,"dest_ip":"10.100.2.2","dest_port":8443,"proto":"TCP","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":80,"bytes_toclient":120}}`
	evePath := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(evePath, []byte(eve+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	contentDir := t.TempDir()
	writeSignedAppIDTaxonomyPackage(t, contentDir, []byte(`{"type":"app-taxonomy","status":"passed","applications":[{"id":"corp-admin","display_name":"Corporate Admin","category":"business-app","ports":[{"protocol":"tcp","ports":[8443]}]}]}`))

	resp, err := (&FlowServer{EvePath: evePath, ContentDir: contentDir}).ListFlows(context.Background(), &openngfwv1.ListFlowsRequest{})
	if err != nil {
		t.Fatalf("ListFlows returned error: %v", err)
	}
	if len(resp.GetFlows()) != 1 {
		t.Fatalf("got %d flows, want 1", len(resp.GetFlows()))
	}
	flow := resp.GetFlows()[0]
	if flow.GetAppId() != "corp-admin" || flow.GetAppName() != "Corporate Admin" || flow.GetAppCategory() != "business-app" {
		t.Fatalf("package App-ID fields not applied: %#v", flow)
	}
	if flow.GetAppConfidence() != 65 {
		t.Fatalf("AppConfidence = %d, want 65", flow.GetAppConfidence())
	}
	if len(flow.GetAppEvidence()) != 2 || !strings.Contains(flow.GetAppEvidence()[1], "signed App-ID package 1.0.0@") {
		t.Fatalf("unexpected AppEvidence: %#v", flow.GetAppEvidence())
	}
}

func TestFlowServerRejectsInvalidTimeRange(t *testing.T) {
	_, err := (&FlowServer{}).ListFlows(context.Background(), &openngfwv1.ListFlowsRequest{
		Since: timestamppb.New(time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)),
		Until: timestamppb.New(time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC)),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("error code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}
}

func writeSignedAppIDTaxonomyPackage(t *testing.T, root string, taxonomyJSON []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyDir := filepath.Join(root, ".trust", "ed25519")
	if err := os.MkdirAll(keyDir, 0o755); err != nil {
		t.Fatalf("mkdir keyring: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "flow-test.pub"), []byte(base64.StdEncoding.EncodeToString(pub)), 0o644); err != nil {
		t.Fatalf("write keyring: %v", err)
	}
	dir := filepath.Join(root, "app-id")
	if err := os.MkdirAll(filepath.Join(dir, "evidence"), 0o755); err != nil {
		t.Fatalf("mkdir package: %v", err)
	}
	content := []byte(`{"apps":["prod"]}`)
	writeFileForFlowTest(t, filepath.Join(dir, "content.json"), content)
	evidence := map[string][]byte{
		"app-taxonomy":          taxonomyJSON,
		"confidence-model":      []byte(`{"type":"confidence-model","status":"passed"}`),
		"app-regression-corpus": []byte(`{"type":"app-regression-corpus","status":"passed","package_version":"1.0.0","samples":[{"pcap_sha256":"` + strings.Repeat("a", 64) + `","expected_app":"corp-admin","observed_app":"corp-admin","verdict":"passed"}]}`),
		"license-review":        []byte(`{"type":"license-review","status":"passed"}`),
		"staged-rollout":        []byte(`{"type":"staged-rollout","status":"passed"}`),
		"rollback-drill":        []byte(`{"type":"rollback-drill","status":"passed"}`),
	}
	contentSum := sha256.Sum256(content)
	manifest := contentpkg.Manifest{
		SchemaVersion: contentpkg.SchemaVersion,
		Kind:          "app-id",
		Name:          "Phragma app-id test package",
		Version:       "1.0.0",
		Source:        "flow test",
		CreatedAt:     "2026-06-17T12:00:00Z",
		InstalledAt:   "2026-06-17T12:05:00Z",
		Files: []contentpkg.File{{
			Path:   "content.json",
			SHA256: hex.EncodeToString(contentSum[:]),
		}},
		Regression: &contentpkg.Regression{Status: "passed", Corpus: "flow", Passed: 1, RunAt: "2026-06-17T12:04:00Z"},
		Rollout:    &contentpkg.Rollout{State: "stable", Scope: "all"},
		Rollback:   &contentpkg.Rollback{Available: true},
		Provenance: []contentpkg.Provenance{{
			Name:                 "Phragma flow test",
			License:              "Apache-2.0",
			AllowsCommercialUse:  boolPtrForFlowTest(true),
			AllowsRedistribution: boolPtrForFlowTest(true),
		}},
		ContentReadiness: &contentpkg.ContentReadiness{
			Scope:                      "production",
			ProductionContent:          true,
			RequiredProductionEvidence: []string{"app-taxonomy", "confidence-model", "app-regression-corpus", "license-review", "staged-rollout", "rollback-drill"},
		},
	}
	for _, evidenceType := range manifest.ContentReadiness.RequiredProductionEvidence {
		raw := evidence[evidenceType]
		artifact := filepath.ToSlash(filepath.Join("evidence", evidenceType+".json"))
		writeFileForFlowTest(t, filepath.Join(dir, artifact), raw)
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		manifest.Files = append(manifest.Files, contentpkg.File{Path: artifact, SHA256: digest})
		manifest.ContentReadiness.Evidence = append(manifest.ContentReadiness.Evidence, contentpkg.EvidenceRef{
			Type:        evidenceType,
			Artifact:    artifact,
			SHA256:      digest,
			GeneratedAt: "2026-06-17T12:03:00Z",
		})
	}
	payload, err := contentpkg.SignaturePayloadForTest(manifest)
	if err != nil {
		t.Fatalf("signature payload: %v", err)
	}
	manifest.Signature = &contentpkg.Signature{
		Algorithm: "ed25519",
		KeyID:     "flow-test",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
	}
	rawManifest, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	writeFileForFlowTest(t, filepath.Join(dir, "manifest.json"), rawManifest)
}

func writeFileForFlowTest(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func boolPtrForFlowTest(value bool) *bool {
	return &value
}

func TestFlowServerListsLiveSessions(t *testing.T) {
	svc := &FlowServer{
		CommandLookup: func(name string) (string, error) {
			return "/usr/sbin/" + name, nil
		},
		CommandRun: func(_ context.Context, name string, _ ...string) ([]byte, error) {
			if name != "conntrack" {
				t.Fatalf("command = %s, want conntrack", name)
			}
			return []byte(`ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.1.20 dst=10.0.2.20 sport=41400 dport=8080 packets=5 bytes=400 src=10.0.2.20 dst=10.0.1.20 sport=8080 dport=41400 packets=4 bytes=300 [ASSURED] mark=0 use=1
ipv4 2 udp 17 28 src=10.0.1.21 dst=10.0.2.53 sport=55331 dport=53 packets=1 bytes=64 src=10.0.2.53 dst=10.0.1.21 sport=53 dport=55331 packets=1 bytes=96 mark=0 use=1
`), nil
		},
	}
	resp, err := svc.ListSessions(context.Background(), &openngfwv1.ListSessionsRequest{
		Ip:       "10.0.2.20",
		Protocol: "tcp",
		Port:     8080,
		State:    "established",
	})
	if err != nil {
		t.Fatalf("ListSessions returned error: %v", err)
	}
	if resp.GetState() != "ready" {
		t.Fatalf("response state = %q, want ready", resp.GetState())
	}
	if len(resp.GetSessions()) != 1 {
		t.Fatalf("sessions = %d, want 1: %#v", len(resp.GetSessions()), resp.GetSessions())
	}
	session := resp.GetSessions()[0]
	if session.GetProtocol() != "TCP" || session.GetSrcIp() != "10.0.1.20" || session.GetDestPort() != 8080 {
		t.Fatalf("unexpected session tuple: %#v", session)
	}
	if session.GetPackets() != 9 || session.GetBytes() != 700 || !session.GetAssured() {
		t.Fatalf("unexpected session counters: %#v", session)
	}
}

func TestFlowServerReportsMissingConntrack(t *testing.T) {
	svc := &FlowServer{
		CommandLookup: func(string) (string, error) {
			return "", errors.New("not found")
		},
	}
	resp, err := svc.ListSessions(context.Background(), &openngfwv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("ListSessions returned error: %v", err)
	}
	if resp.GetState() != "degraded" || len(resp.GetSessions()) != 0 {
		t.Fatalf("response = %#v, want degraded with no sessions", resp)
	}
}
