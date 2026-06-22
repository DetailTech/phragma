package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func newExplainCommand(server *string) *cobra.Command {
	var (
		source   string
		version  uint64
		fromZone string
		toZone   string
		srcIP    string
		dstIP    string
		srcPort  uint32
		dstPort  uint32
		proto    string
		appID    string
		runtime  bool
		flowID   string
		outJSON  bool
	)
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Explain how policy treats a flow tuple",
		RunE: func(cmd *cobra.Command, _ []string) error {
			policySource, err := parsePolicySource(source)
			if err != nil {
				return err
			}
			protocol, err := parseProtocol(proto)
			if err != nil {
				return err
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()

			resp, err := openngfwv1.NewExplainServiceClient(conn).ExplainFlow(ctx, &openngfwv1.ExplainFlowRequest{
				PolicySource:   policySource,
				Version:        version,
				FromZone:       fromZone,
				ToZone:         toZone,
				SrcIp:          srcIP,
				SrcPort:        srcPort,
				DestIp:         dstIP,
				DestPort:       dstPort,
				Protocol:       protocol,
				AppId:          appID,
				IncludeRuntime: runtime,
				FlowId:         flowID,
			})
			if err != nil {
				return fmt.Errorf("explain flow: %w", err)
			}
			if outJSON {
				b, err := protojson.MarshalOptions{UseProtoNames: true, Indent: "  "}.Marshal(resp)
				if err != nil {
					return err
				}
				cmd.Println(string(b))
				return nil
			}
			printExplain(cmd, resp)
			return nil
		},
	}
	cmd.Flags().StringVar(&source, "source", "running", "policy source: running | candidate | version")
	cmd.Flags().Uint64Var(&version, "version", 0, "policy version id (with --source version)")
	cmd.Flags().StringVar(&fromZone, "from-zone", "", "source security zone")
	cmd.Flags().StringVar(&toZone, "to-zone", "", "destination security zone")
	cmd.Flags().StringVar(&srcIP, "src", "", "source IP address")
	cmd.Flags().Uint32Var(&srcPort, "sport", 0, "source port")
	cmd.Flags().StringVar(&dstIP, "dst", "", "destination IP address")
	cmd.Flags().Uint32Var(&dstPort, "dport", 0, "destination port")
	cmd.Flags().StringVar(&proto, "protocol", "", "protocol: tcp | udp | icmp | any")
	cmd.Flags().StringVar(&appID, "app-id", "", "observed canonical OpenNGFW App-ID")
	cmd.Flags().BoolVar(&runtime, "runtime", false, "include live runtime evidence such as conntrack sessions")
	cmd.Flags().StringVar(&flowID, "flow-id", "", "engine/telemetry flow identifier for runtime correlation")
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	_ = cmd.MarkFlagRequired("src")
	_ = cmd.MarkFlagRequired("dst")
	_ = cmd.MarkFlagRequired("protocol")
	return cmd
}

func parsePolicySource(s string) (openngfwv1.PolicySource, error) {
	switch strings.ToLower(s) {
	case "", "running":
		return openngfwv1.PolicySource_POLICY_SOURCE_RUNNING, nil
	case "candidate":
		return openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE, nil
	case "version":
		return openngfwv1.PolicySource_POLICY_SOURCE_VERSION, nil
	default:
		return openngfwv1.PolicySource_POLICY_SOURCE_UNSPECIFIED, fmt.Errorf("--source must be running, candidate, or version")
	}
}

func parseProtocol(s string) (openngfwv1.Protocol, error) {
	switch strings.ToLower(s) {
	case "tcp":
		return openngfwv1.Protocol_PROTOCOL_TCP, nil
	case "udp":
		return openngfwv1.Protocol_PROTOCOL_UDP, nil
	case "icmp":
		return openngfwv1.Protocol_PROTOCOL_ICMP, nil
	case "any", "ip":
		return openngfwv1.Protocol_PROTOCOL_ANY, nil
	default:
		return openngfwv1.Protocol_PROTOCOL_UNSPECIFIED, fmt.Errorf("--protocol must be tcp, udp, icmp, or any")
	}
}

func printExplain(cmd *cobra.Command, r *openngfwv1.ExplainFlowResponse) {
	cmd.Printf("Verdict: %s\n", shortEnum(r.GetVerdict().String(), "EXPLAIN_VERDICT_"))
	cmd.Printf("Inspection: %s\n", shortEnum(r.GetInspectionState().String(), "EXPLAIN_INSPECTION_STATE_"))
	if r.GetDecisionSummary() != "" {
		cmd.Printf("Decision: %s\n", r.GetDecisionSummary())
	} else if len(r.GetDecisionTerms()) > 0 {
		cmd.Printf("Decision: %s\n", decisionTermsLabel(r.GetDecisionTerms()))
	}
	cmd.Printf("Policy: %s", shortEnum(r.GetPolicySource().String(), "POLICY_SOURCE_"))
	if r.GetPolicyVersion() != 0 {
		cmd.Printf(" v%d", r.GetPolicyVersion())
	}
	cmd.Println()
	if r.GetMatchedRule() != "" {
		if r.GetMatchedRuleId() != "" {
			cmd.Printf("Matched rule: %s (%s, index %d)\n", r.GetMatchedRule(), r.GetMatchedRuleId(), r.GetMatchedRuleIndex())
		} else {
			cmd.Printf("Matched rule: %s (index %d)\n", r.GetMatchedRule(), r.GetMatchedRuleIndex())
		}
	} else if r.GetDefaultPolicy() {
		cmd.Println("Matched rule: default forward-chain policy")
	}
	cmd.Printf("Reason: %s\n", r.GetReason())
	printInspectionProfile(cmd, r.GetInspectionProfile())
	printRouteProfile(cmd, r.GetRouteProfile())
	printRuntimeEvidence(cmd, r.GetRuntimeEvidence())
	printList(cmd, "Evidence", r.GetEvidence())
	printList(cmd, "Trace", r.GetTrace())
	printList(cmd, "Warnings", r.GetWarnings())
}

func decisionTermsLabel(terms []openngfwv1.ExplainDecisionTerm) string {
	out := make([]string, 0, len(terms))
	for _, term := range terms {
		out = append(out, strings.ToLower(strings.ReplaceAll(shortEnum(term.String(), "EXPLAIN_DECISION_TERM_"), "_", "-")))
	}
	return strings.Join(out, ", ")
}

func printInspectionProfile(cmd *cobra.Command, p *openngfwv1.ExplainInspectionProfile) {
	if p == nil {
		return
	}
	cmd.Println("Inspection profile:")
	printKV(cmd, "engine", valueOrDash(p.GetEngine()))
	printKV(cmd, "ids/ips", boolLabel(p.GetIdsEnabled(), shortEnum(p.GetIdsMode().String(), "IDS_MODE_"), "disabled"))
	if p.GetFailureBehavior() != openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_UNSPECIFIED {
		printKV(cmd, "failure behavior", shortEnum(p.GetFailureBehavior().String(), "IDS_FAILURE_BEHAVIOR_"))
	}
	printKV(cmd, "flow offload", boolLabel(p.GetFlowOffloadEnabled(), "enabled", "disabled"))
	printKV(cmd, "bypass possible", boolLabel(p.GetBypassPossible(), "yes", "no"))
	if p.GetBypassReason() != "" {
		printKV(cmd, "bypass reason", p.GetBypassReason())
	}
	if p.GetInspectionOrder() != "" {
		printKV(cmd, "inspection order", p.GetInspectionOrder())
	}
	if p.GetDegradedBehavior() != "" {
		printKV(cmd, "degraded behavior", p.GetDegradedBehavior())
	}
	printList(cmd, "Inspection evidence", p.GetEvidence())
}

func printRouteProfile(cmd *cobra.Command, p *openngfwv1.ExplainRouteProfile) {
	if p == nil {
		return
	}
	cmd.Println("Route profile:")
	printKV(cmd, "evaluated", boolLabel(p.GetEvaluated(), "yes", "no"))
	printKV(cmd, "source", valueOrDash(p.GetSource()))
	printKV(cmd, "matched", boolLabel(p.GetMatched(), "yes", "no"))
	if p.GetDestination() != "" {
		printKV(cmd, "destination", p.GetDestination())
	}
	if p.GetNextHop() != "" {
		printKV(cmd, "next hop", p.GetNextHop())
	}
	if p.GetEgressInterface() != "" {
		printKV(cmd, "egress interface", p.GetEgressInterface())
	}
	if p.GetMetric() != 0 {
		printKV(cmd, "metric", fmt.Sprintf("%d", p.GetMetric()))
	}
	if p.GetReason() != "" {
		printKV(cmd, "reason", p.GetReason())
	}
	printList(cmd, "Route evidence", p.GetEvidence())
}

func printRuntimeEvidence(cmd *cobra.Command, p *openngfwv1.ExplainRuntimeEvidence) {
	if p == nil || !p.GetQueried() {
		return
	}
	cmd.Println("Runtime evidence:")
	printKV(cmd, "state", valueOrDash(p.GetState()))
	if p.GetRunningPolicyVersion() != 0 {
		printKV(cmd, "running policy", fmt.Sprintf("v%d", p.GetRunningPolicyVersion()))
	}
	if p.GetPolicyContext() != "" {
		printKV(cmd, "policy context", p.GetPolicyContext())
	}
	if p.GetDetail() != "" {
		printKV(cmd, "detail", p.GetDetail())
	}
	if len(p.GetSessions()) > 0 {
		cmd.Println("Runtime sessions:")
		for _, s := range p.GetSessions() {
			cmd.Printf("  - %s %s:%d -> %s:%d state=%s packets=%d bytes=%d%s\n",
				valueOrDash(s.GetProtocol()), s.GetSrcIp(), s.GetSrcPort(), s.GetDestIp(), s.GetDestPort(),
				valueOrDash(s.GetState()), s.GetPackets(), s.GetBytes(), boolSuffix(s.GetAssured(), " assured"))
		}
	}
	printCorrelatedFlows(cmd, p.GetCorrelatedFlows())
	printCorrelatedAlerts(cmd, p.GetCorrelatedAlerts())
	printCorrelatedCaptures(cmd, p.GetCorrelatedCaptures())
	printList(cmd, "Runtime evidence detail", p.GetEvidence())
	printList(cmd, "Runtime warnings", p.GetWarnings())
}

func printCorrelatedFlows(cmd *cobra.Command, flows []*openngfwv1.Flow) {
	if len(flows) == 0 {
		return
	}
	cmd.Println("Runtime correlated flows:")
	for _, f := range flows {
		cmd.Printf("  - %s %s:%d -> %s:%d app=%s confidence=%d%% packets=%d bytes=%s%s\n",
			valueOrDash(f.GetProtocol()),
			f.GetSrcIp(),
			f.GetSrcPort(),
			f.GetDestIp(),
			f.GetDestPort(),
			valueOrDash(firstNonEmpty(f.GetAppId(), f.GetAppName(), f.GetAppProtocol())),
			f.GetAppConfidence(),
			f.GetPackets(),
			humanBytes(f.GetBytesToServer()+f.GetBytesToClient()),
			correlationSuffix(f.GetFlowId(), f.GetPolicyVersion(), f.GetPolicyVersionKnown()))
	}
}

func printCorrelatedAlerts(cmd *cobra.Command, alerts []*openngfwv1.Alert) {
	if len(alerts) == 0 {
		return
	}
	cmd.Println("Runtime correlated alerts:")
	for _, a := range alerts {
		cmd.Printf("  - %s %s:%d -> %s:%d threat=%s severity=%s action=%s sid=%d%s\n",
			valueOrDash(a.GetProtocol()),
			a.GetSrcIp(),
			a.GetSrcPort(),
			a.GetDestIp(),
			a.GetDestPort(),
			valueOrDash(firstNonEmpty(a.GetThreatId(), a.GetThreatName(), a.GetSignature())),
			valueOrDash(firstNonEmpty(a.GetThreatSeverity(), fmt.Sprintf("%d", a.GetSeverity()))),
			valueOrDash(a.GetAction()),
			a.GetSignatureId(),
			correlationSuffix(a.GetFlowId(), a.GetPolicyVersion(), a.GetPolicyVersionKnown()))
	}
}

func printCorrelatedCaptures(cmd *cobra.Command, captures []*openngfwv1.PacketCaptureJob) {
	if len(captures) == 0 {
		return
	}
	cmd.Println("Runtime correlated captures:")
	for _, capture := range captures {
		artifactID := packetCaptureArtifactID(capture)
		filename := capture.GetFilename()
		if filename == "" && artifactID != "" {
			filename = artifactID + ".pcap"
		}
		flowID := ""
		if capture.GetPlan() != nil {
			flowID = capture.GetPlan().GetFlowId()
		}
		cmd.Printf("  - id=%s file=%s bytes=%s sha256=%s download=%s%s\n",
			valueOrDash(artifactID),
			valueOrDash(filename),
			humanBytes(capture.GetBytesWritten()),
			valueOrDash(capture.GetSha256()),
			valueOrDash(capture.GetDownloadPath()),
			captureFlowIDSuffix(flowID))
	}
}

func captureFlowIDSuffix(flowID string) string {
	if strings.TrimSpace(flowID) == "" {
		return ""
	}
	return " (flow_id=" + flowID + ")"
}

func correlationSuffix(flowID string, policyVersion uint64, policyKnown bool) string {
	var parts []string
	if flowID != "" {
		parts = append(parts, "flow_id="+flowID)
	}
	if policyKnown && policyVersion != 0 {
		parts = append(parts, fmt.Sprintf("policy=v%d", policyVersion))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, " ") + ")"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func printKV(cmd *cobra.Command, key, value string) {
	cmd.Printf("  %-18s %s\n", key+":", value)
}

func printList(cmd *cobra.Command, title string, lines []string) {
	if len(lines) == 0 {
		return
	}
	cmd.Println(title + ":")
	for _, line := range lines {
		cmd.Println("  - " + line)
	}
}

func boolLabel(v bool, yes, no string) string {
	if v {
		return yes
	}
	return no
}

func boolSuffix(v bool, s string) string {
	if v {
		return s
	}
	return ""
}

func shortEnum(s, prefix string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(s, prefix), "_", "-"))
}
