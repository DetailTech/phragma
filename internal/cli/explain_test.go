package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestPrintExplainIncludesInspectionAndRouteProfiles(t *testing.T) {
	out := printExplainForTest(&openngfwv1.ExplainFlowResponse{
		PolicySource:     openngfwv1.PolicySource_POLICY_SOURCE_RUNNING,
		PolicyVersion:    9,
		Verdict:          openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_ALLOWED,
		InspectionState:  openngfwv1.ExplainInspectionState_EXPLAIN_INSPECTION_STATE_IPS_PREVENT,
		DecisionTerms:    []openngfwv1.ExplainDecisionTerm{openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_ALLOWED, openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_PARTIALLY_INSPECTED, openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_FAIL_OPEN},
		DecisionSummary:  "allowed, partially inspected, fail-open",
		Reason:           "first matching policy rule \"allow-web\" returned allow",
		MatchedRule:      "allow-web",
		MatchedRuleId:    "rule-allow-web",
		MatchedRuleIndex: 3,
		InspectionProfile: &openngfwv1.ExplainInspectionProfile{
			IdsEnabled:       true,
			IdsMode:          openngfwv1.IdsMode_IDS_MODE_PREVENT,
			FailureBehavior:  openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_OPEN,
			Engine:           "suricata",
			BypassPossible:   true,
			BypassReason:     "ids.failure_behavior is fail-open",
			InspectionOrder:  "inline NFQUEUE handoff runs before policy",
			DegradedBehavior: "fail-open: queued traffic bypasses inspection",
			Evidence:         []string{"IPS prevent mode", "fail-open NFQUEUE bypass behavior"},
		},
		RouteProfile: &openngfwv1.ExplainRouteProfile{
			Evaluated:       true,
			Matched:         true,
			Destination:     "10.0.2.0/24",
			NextHop:         "10.0.1.1",
			EgressInterface: "eth1",
			Metric:          10,
			Source:          "static",
			Reason:          "static route 10.0.2.0/24 selected",
			Evidence:        []string{"static route 10.0.2.0/24 via 10.0.1.1 dev eth1 metric 10"},
		},
		RuntimeEvidence: &openngfwv1.ExplainRuntimeEvidence{
			Queried:              true,
			State:                "ready",
			Detail:               "1 live session(s) matched",
			RunningPolicyVersion: 9,
			PolicyContext:        "live dataplane context",
			Sessions: []*openngfwv1.ConntrackSession{{
				Protocol: "TCP", State: "ESTABLISHED", SrcIp: "10.0.1.20", SrcPort: 51515,
				DestIp: "10.0.2.20", DestPort: 443, Packets: 9, Bytes: 700, Assured: true,
			}},
			CorrelatedFlows: []*openngfwv1.Flow{{
				FlowId:             "eve-flow-1",
				Protocol:           "TCP",
				SrcIp:              "10.0.1.20",
				SrcPort:            51515,
				DestIp:             "10.0.2.20",
				DestPort:           443,
				AppId:              "web-browsing",
				AppConfidence:      91,
				Packets:            7,
				BytesToServer:      512,
				BytesToClient:      1536,
				PolicyVersion:      9,
				PolicyVersionKnown: true,
			}},
			CorrelatedAlerts: []*openngfwv1.Alert{{
				FlowId:             "eve-flow-1",
				Protocol:           "TCP",
				SrcIp:              "10.0.1.20",
				SrcPort:            51515,
				DestIp:             "10.0.2.20",
				DestPort:           443,
				ThreatId:           "suricata-sid-9000001",
				ThreatSeverity:     "high",
				Action:             "blocked",
				SignatureId:        9000001,
				PolicyVersion:      9,
				PolicyVersionKnown: true,
			}},
			CorrelatedCaptures: []*openngfwv1.PacketCaptureJob{{
				ArtifactId:   "phragma-web-20260618T121500Z",
				BytesWritten: 4096,
				Sha256:       "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
				Filename:     "phragma-web-20260618T121500Z.pcap",
				DownloadPath: "/v1/system/packet-captures/phragma-web-20260618T121500Z/download",
				Plan: &openngfwv1.PacketCapturePlan{
					FlowId: "eve-flow-1",
				},
			}},
			Evidence: []string{"live conntrack returned 1 matching session"},
		},
		Evidence: []string{"matched rule \"allow-web\" at index 3"},
	})

	for _, want := range []string{
		"Verdict: allowed",
		"Inspection: ips-prevent",
		"Decision: allowed, partially inspected, fail-open",
		"Policy: running v9",
		"Matched rule: allow-web (rule-allow-web, index 3)",
		"Inspection profile:",
		"engine:            suricata",
		"ids/ips:           prevent",
		"failure behavior:  fail-open",
		"bypass possible:   yes",
		"ids.failure_behavior is fail-open",
		"Inspection evidence:",
		"fail-open NFQUEUE bypass behavior",
		"Route profile:",
		"evaluated:         yes",
		"source:            static",
		"destination:       10.0.2.0/24",
		"next hop:          10.0.1.1",
		"egress interface:  eth1",
		"Route evidence:",
		"Runtime evidence:",
		"state:             ready",
		"running policy:    v9",
		"live dataplane context",
		"Runtime sessions:",
		"TCP 10.0.1.20:51515 -> 10.0.2.20:443 state=ESTABLISHED packets=9 bytes=700 assured",
		"Runtime correlated flows:",
		"TCP 10.0.1.20:51515 -> 10.0.2.20:443 app=web-browsing confidence=91% packets=7 bytes=2.0 KB (flow_id=eve-flow-1 policy=v9)",
		"Runtime correlated alerts:",
		"TCP 10.0.1.20:51515 -> 10.0.2.20:443 threat=suricata-sid-9000001 severity=high action=blocked sid=9000001 (flow_id=eve-flow-1 policy=v9)",
		"Runtime correlated captures:",
		"id=phragma-web-20260618T121500Z file=phragma-web-20260618T121500Z.pcap bytes=4.0 KB sha256=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff download=/v1/system/packet-captures/phragma-web-20260618T121500Z/download (flow_id=eve-flow-1)",
		"Runtime evidence detail:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestPrintExplainShowsSkippedRouteProfileForDefaultDrop(t *testing.T) {
	out := printExplainForTest(&openngfwv1.ExplainFlowResponse{
		PolicySource:    openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE,
		Verdict:         openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_DEFAULT_DROP,
		InspectionState: openngfwv1.ExplainInspectionState_EXPLAIN_INSPECTION_STATE_NOT_INSPECTED,
		DecisionTerms:   []openngfwv1.ExplainDecisionTerm{openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_BLOCKED},
		DefaultPolicy:   true,
		Reason:          "no enabled security rule matched",
		RouteProfile: &openngfwv1.ExplainRouteProfile{
			Evaluated: false,
			Source:    "not-evaluated",
			Reason:    "route lookup not evaluated because the policy verdict is default drop",
		},
	})

	for _, want := range []string{
		"Verdict: default-drop",
		"Decision: blocked",
		"Policy: candidate",
		"Matched rule: default forward-chain policy",
		"Route profile:",
		"evaluated:         no",
		"source:            not-evaluated",
		"route lookup not evaluated",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func printExplainForTest(resp *openngfwv1.ExplainFlowResponse) string {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	printExplain(cmd, resp)
	return buf.String()
}
