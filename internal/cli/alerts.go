package cli

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func newAlertsCommand(server *string) *cobra.Command {
	var limit uint32
	var srcIP string
	var destIP string
	var ip string
	var protocol string
	var action string
	var threatSeverity string
	var query string
	var flowID string
	var since string
	var until string
	var severity uint32
	var signatureID int64
	var port uint32
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "Show recent IDS/IPS alerts, newest first",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			req := &openngfwv1.ListAlertsRequest{
				Limit:          limit,
				SrcIp:          srcIP,
				DestIp:         destIP,
				Ip:             ip,
				Protocol:       protocol,
				Action:         action,
				Severity:       severity,
				ThreatSeverity: threatSeverity,
				SignatureId:    signatureID,
				Port:           port,
				Query:          query,
				FlowId:         flowID,
			}
			if since != "" {
				ts, err := parseAuditTimeBound(since, false)
				if err != nil {
					return fmt.Errorf("invalid --since: %w", err)
				}
				req.Since = timestamppb.New(ts)
			}
			if until != "" {
				ts, err := parseAuditTimeBound(until, true)
				if err != nil {
					return fmt.Errorf("invalid --until: %w", err)
				}
				req.Until = timestamppb.New(ts)
			}
			resp, err := openngfwv1.NewAlertServiceClient(conn).ListAlerts(ctx, req)
			if err != nil {
				return err
			}
			if len(resp.GetAlerts()) == 0 {
				cmd.Println("no alerts")
				return nil
			}
			printAlertsResponse(cmd, resp)
			return nil
		},
	}
	cmd.Flags().Uint32Var(&limit, "limit", 0, "max alerts (0 = server default)")
	cmd.Flags().StringVar(&srcIP, "src-ip", "", "filter by exact source IP")
	cmd.Flags().StringVar(&destIP, "dest-ip", "", "filter by exact destination IP")
	cmd.Flags().StringVar(&ip, "ip", "", "filter by exact source or destination IP")
	cmd.Flags().StringVar(&protocol, "protocol", "", "filter by protocol, e.g. TCP, UDP, ICMP")
	cmd.Flags().StringVar(&action, "action", "", "filter by action, e.g. allowed or blocked")
	cmd.Flags().Uint32Var(&severity, "severity", 0, "filter by Suricata severity (1 = highest)")
	cmd.Flags().StringVar(&threatSeverity, "threat-severity", "", "filter by OpenNGFW severity: critical|high|medium|low|info")
	cmd.Flags().Int64Var(&signatureID, "signature-id", 0, "filter by Suricata signature ID")
	cmd.Flags().Uint32Var(&port, "port", 0, "filter by source or destination port")
	cmd.Flags().StringVar(&query, "query", "", "search endpoints, protocol, signature, categories, Threat-ID fields, and evidence")
	cmd.Flags().StringVar(&flowID, "flow-id", "", "filter by exact engine/telemetry flow ID")
	cmd.Flags().StringVar(&since, "since", "", "include alerts at or after RFC3339, YYYY-MM-DD, or 'YYYY-MM-DD HH:MM:SS' UTC")
	cmd.Flags().StringVar(&until, "until", "", "include alerts at or before RFC3339, YYYY-MM-DD, or 'YYYY-MM-DD HH:MM:SS' UTC")
	return cmd
}

func printAlertsResponse(cmd *cobra.Command, resp *openngfwv1.ListAlertsResponse) {
	printTelemetryPolicyContext(cmd, resp.GetRunningPolicyVersion(), resp.GetPolicyContext())
	for _, alert := range resp.GetAlerts() {
		printAlert(cmd, alert)
	}
}

func printAlert(cmd *cobra.Command, a *openngfwv1.Alert) {
	threat := a.GetThreatId()
	if threat == "" {
		threat = "unknown-threat"
	}
	cmd.Printf("%s  %-18s %-8s %-8s %s:%d -> %s:%d  sid=%d confidence=%d%% flow_id=%s event_policy=%s %s\n",
		a.GetTime().AsTime().Format("2006-01-02 15:04:05"),
		threat, a.GetThreatSeverity(), a.GetAction(),
		a.GetSrcIp(), a.GetSrcPort(), a.GetDestIp(), a.GetDestPort(),
		a.GetSignatureId(), a.GetThreatConfidence(), valueOrDash(a.GetFlowId()), eventPolicyVersionLabel(a.GetPolicyVersion(), a.GetPolicyVersionKnown()), a.GetSignature())
	if version, manifest := threatPackageProvenance(a.GetThreatEvidence()); version != "" || manifest != "" {
		cmd.Printf("  threat-id-package: version=%s manifest=%s\n", valueOrDash(version), valueOrDash(shortAppIDHash(manifest)))
	}
}

var (
	signedThreatPackagePattern = regexp.MustCompile(`(?i)^signed Threat-ID package(?:\s+([^@\s]+))?(?:@([a-f0-9]{8,64}))?$`)
	alertSecretQueryPattern    = regexp.MustCompile(`(?i)[?&](token|secret|password|key)=`)
)

func threatPackageProvenance(evidence []string) (version, manifest string) {
	for _, entry := range evidence {
		text := compactAlertEvidence(entry, 160)
		match := signedThreatPackagePattern.FindStringSubmatch(text)
		if match == nil {
			continue
		}
		return match[1], match[2]
	}
	return "", ""
}

func compactAlertEvidence(value string, maxLen int) string {
	compact := strings.Join(strings.Fields(value), " ")
	if strings.ContainsAny(compact, `/\`) || alertSecretQueryPattern.MatchString(compact) {
		return ""
	}
	if maxLen > 0 && len(compact) > maxLen {
		return strings.TrimSpace(compact[:maxLen])
	}
	return compact
}

func printTelemetryPolicyContext(cmd *cobra.Command, runningVersion uint64, detail string) {
	if runningVersion != 0 {
		cmd.Printf("policy-context: running v%d\n", runningVersion)
		return
	}
	if detail != "" {
		cmd.Printf("policy-context: %s\n", detail)
	}
}

func eventPolicyVersionLabel(version uint64, known bool) string {
	if known && version != 0 {
		return fmt.Sprintf("v%d", version)
	}
	return "-"
}
