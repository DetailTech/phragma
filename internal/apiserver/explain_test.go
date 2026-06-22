package apiserver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/store"
)

func TestExplainFlowIncludesRuntimeConntrackEvidence(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.CommitVersion(explainRuntimePolicy(), "tester", "baseline"); err != nil {
		t.Fatal(err)
	}
	evePath := filepath.Join(t.TempDir(), "eve.json")
	eve := `{"timestamp":"2026-06-11T10:00:00.000001+0000","event_type":"flow","flow_id":"eve-42","src_ip":"10.0.1.20","src_port":51515,"dest_ip":"10.0.2.20","dest_port":443,"proto":"TCP","app_proto":"http","policy_version":1,"flow":{"pkts_toserver":5,"pkts_toclient":4,"bytes_toserver":400,"bytes_toclient":300}}
{"timestamp":"2026-06-11T10:00:01.000001+0000","event_type":"alert","flow_id":"eve-42","src_ip":"10.0.1.20","src_port":51515,"dest_ip":"10.0.2.20","dest_port":443,"proto":"TCP","openngfw":{"config_version":1},"alert":{"action":"blocked","signature_id":9000001,"signature":"ET EXPLOIT Test Attack","category":"Misc Attack","severity":1}}`
	if err := os.WriteFile(evePath, []byte(eve+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	captureDir := filepath.Join(t.TempDir(), "pcap")
	if err := os.MkdirAll(captureDir, 0o750); err != nil {
		t.Fatal(err)
	}
	capturePath := filepath.Join(captureDir, "phragma-web-20260618T121500Z.pcap")
	if err := os.WriteFile(capturePath, []byte("matching-pcap"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := writePacketCaptureMetadata(&openngfwv1.PacketCaptureJob{
		Plan: &openngfwv1.PacketCapturePlan{
			OutputPath: capturePath,
			FlowId:     "eve-42",
			SrcIp:      "10.0.1.20",
			SrcPort:    51515,
			DestIp:     "10.0.2.20",
			DestPort:   443,
		},
	}); err != nil {
		t.Fatal(err)
	}

	srv := &ExplainServer{
		Store:      st,
		EvePath:    evePath,
		CaptureDir: captureDir,
		CommandLookup: func(name string) (string, error) {
			if name != "conntrack" {
				t.Fatalf("lookup = %s, want conntrack", name)
			}
			return "/usr/sbin/conntrack", nil
		},
		CommandRun: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "conntrack" || strings.Join(args, " ") != "-L -o extended" {
				t.Fatalf("command = %s %s, want conntrack -L -o extended", name, strings.Join(args, " "))
			}
			return []byte(`ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.1.20 dst=10.0.2.20 sport=51515 dport=443 packets=5 bytes=400 src=10.0.2.20 dst=10.0.1.20 sport=443 dport=51515 packets=4 bytes=300 [ASSURED] mark=0 use=1
ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.1.30 dst=10.0.2.30 sport=40000 dport=443 packets=1 bytes=100 src=10.0.2.30 dst=10.0.1.30 sport=443 dport=40000 packets=1 bytes=100 mark=0 use=1
`), nil
		},
	}

	baseReq := &openngfwv1.ExplainFlowRequest{
		PolicySource: openngfwv1.PolicySource_POLICY_SOURCE_RUNNING,
		FromZone:     "lan",
		ToZone:       "wan",
		SrcIp:        "10.0.1.20",
		SrcPort:      51515,
		DestIp:       "10.0.2.20",
		DestPort:     443,
		Protocol:     openngfwv1.Protocol_PROTOCOL_TCP,
		FlowId:       "eve-42",
	}

	noRuntime, err := srv.ExplainFlow(context.Background(), baseReq)
	if err != nil {
		t.Fatalf("ExplainFlow without runtime: %v", err)
	}
	if noRuntime.GetRuntimeEvidence() != nil {
		t.Fatalf("runtime evidence should be omitted unless requested: %#v", noRuntime.GetRuntimeEvidence())
	}

	req := proto.Clone(baseReq).(*openngfwv1.ExplainFlowRequest)
	req.IncludeRuntime = true
	resp, err := srv.ExplainFlow(context.Background(), req)
	if err != nil {
		t.Fatalf("ExplainFlow: %v", err)
	}
	if got := resp.GetVerdict(); got != openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_ALLOWED {
		t.Fatalf("verdict = %s, want allowed", got)
	}
	if !containsExplainDecisionTerm(resp.GetDecisionTerms(), openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_ALLOWED) ||
		!containsExplainDecisionTerm(resp.GetDecisionTerms(), openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_BYPASSED) {
		t.Fatalf("decision terms should expose allowed and bypassed: %v", resp.GetDecisionTerms())
	}
	if sourceNat := resp.GetNatProfile().GetSource(); !sourceNat.GetEvaluated() || !sourceNat.GetMatched() || !sourceNat.GetMasquerade() {
		t.Fatalf("source NAT profile missing from API response: %#v", sourceNat)
	}
	runtime := resp.GetRuntimeEvidence()
	if runtime == nil || !runtime.GetQueried() {
		t.Fatalf("runtime evidence missing: %#v", runtime)
	}
	if runtime.GetState() != "ready" {
		t.Fatalf("runtime state = %q, want ready", runtime.GetState())
	}
	if runtime.GetRunningPolicyVersion() != 1 || runtime.GetPolicyContext() == "" {
		t.Fatalf("runtime policy context missing: %#v", runtime)
	}
	if len(runtime.GetSessions()) != 1 {
		t.Fatalf("runtime sessions = %d, want 1: %#v", len(runtime.GetSessions()), runtime.GetSessions())
	}
	session := runtime.GetSessions()[0]
	if session.GetSrcIp() != "10.0.1.20" || session.GetDestIp() != "10.0.2.20" || session.GetDestPort() != 443 {
		t.Fatalf("unexpected runtime tuple: %#v", session)
	}
	if session.GetPackets() != 9 || session.GetBytes() != 700 || !session.GetAssured() {
		t.Fatalf("unexpected runtime counters: %#v", session)
	}
	if len(runtime.GetEvidence()) == 0 || !strings.Contains(runtime.GetEvidence()[0], "live conntrack returned 1") {
		t.Fatalf("runtime evidence summary missing: %#v", runtime.GetEvidence())
	}
	if len(runtime.GetCorrelatedFlows()) != 1 || runtime.GetCorrelatedFlows()[0].GetFlowId() != "eve-42" {
		t.Fatalf("correlated flows = %#v, want one eve-42 flow", runtime.GetCorrelatedFlows())
	}
	if len(runtime.GetCorrelatedAlerts()) != 1 || runtime.GetCorrelatedAlerts()[0].GetSignatureId() != 9000001 {
		t.Fatalf("correlated alerts = %#v, want SID 9000001", runtime.GetCorrelatedAlerts())
	}
	if !strings.Contains(strings.Join(runtime.GetEvidence(), "\n"), "EVE correlation returned 1 flow event(s) and 1 alert event(s)") {
		t.Fatalf("EVE correlation evidence missing: %#v", runtime.GetEvidence())
	}
	if len(runtime.GetCorrelatedCaptures()) != 1 || runtime.GetCorrelatedCaptures()[0].GetArtifactId() != "phragma-web-20260618T121500Z" {
		t.Fatalf("correlated captures = %#v, want matching packet capture artifact", runtime.GetCorrelatedCaptures())
	}
	if !strings.Contains(strings.Join(runtime.GetEvidence(), "\n"), "packet capture correlation returned 1 artifact(s)") {
		t.Fatalf("packet capture correlation evidence missing: %#v", runtime.GetEvidence())
	}
}

func TestExplainFlowRuntimeUnavailableAddsFailedDecisionTerm(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.CommitVersion(explainRuntimePolicy(), "tester", "baseline"); err != nil {
		t.Fatal(err)
	}

	srv := &ExplainServer{
		Store: st,
		CommandLookup: func(name string) (string, error) {
			return "/usr/sbin/" + name, nil
		},
		CommandRun: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return nil, errors.New("conntrack unavailable")
		},
	}
	resp, err := srv.ExplainFlow(context.Background(), &openngfwv1.ExplainFlowRequest{
		PolicySource:   openngfwv1.PolicySource_POLICY_SOURCE_RUNNING,
		FromZone:       "lan",
		ToZone:         "wan",
		SrcIp:          "10.0.1.20",
		SrcPort:        51515,
		DestIp:         "10.0.2.20",
		DestPort:       443,
		Protocol:       openngfwv1.Protocol_PROTOCOL_TCP,
		IncludeRuntime: true,
	})
	if err != nil {
		t.Fatalf("ExplainFlow: %v", err)
	}
	if resp.GetRuntimeEvidence().GetState() != "unavailable" {
		t.Fatalf("runtime state = %q, want unavailable", resp.GetRuntimeEvidence().GetState())
	}
	if !containsExplainDecisionTerm(resp.GetDecisionTerms(), openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_FAILED) {
		t.Fatalf("runtime unavailable should expose failed decision term: %v", resp.GetDecisionTerms())
	}
	if !strings.Contains(resp.GetDecisionSummary(), "failed") {
		t.Fatalf("decision summary should include failed: %q", resp.GetDecisionSummary())
	}
}

func explainRuntimePolicy() *openngfwv1.Policy {
	return &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{
			{Name: "lan", Interfaces: []string{"eth0"}},
			{Name: "wan", Interfaces: []string{"eth1"}},
		},
		Addresses: []*openngfwv1.Address{
			{Name: "client", Cidr: "10.0.1.20/32"},
			{Name: "server", Cidr: "10.0.2.20/32"},
		},
		Nat: &openngfwv1.Nat{Source: []*openngfwv1.SourceNat{{
			Name:          "wan-masquerade",
			ToZone:        "wan",
			SourceAddress: "client",
			Masquerade:    true,
		}}},
		Services: []*openngfwv1.Service{{
			Name:     "https",
			Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
			Ports:    []*openngfwv1.PortRange{{Start: 443}},
		}},
		Rules: []*openngfwv1.Rule{{
			Name:                 "allow-client-https",
			FromZones:            []string{"lan"},
			ToZones:              []string{"wan"},
			SourceAddresses:      []string{"client"},
			DestinationAddresses: []string{"server"},
			Services:             []string{"https"},
			Action:               openngfwv1.Action_ACTION_ALLOW,
			Log:                  true,
		}},
	}
}

func containsExplainDecisionTerm(terms []openngfwv1.ExplainDecisionTerm, want openngfwv1.ExplainDecisionTerm) bool {
	for _, term := range terms {
		if term == want {
			return true
		}
	}
	return false
}
