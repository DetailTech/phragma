package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func newSessionsCommand(server *string) *cobra.Command {
	var limit uint32
	var srcIP string
	var destIP string
	var ip string
	var protocol string
	var state string
	var query string
	var port uint32
	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "Show live Linux conntrack sessions from the active dataplane",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewFlowServiceClient(conn).ListSessions(ctx, &openngfwv1.ListSessionsRequest{
				Limit:    limit,
				SrcIp:    srcIP,
				DestIp:   destIP,
				Ip:       ip,
				Protocol: protocol,
				Port:     port,
				State:    state,
				Query:    query,
			})
			if err != nil {
				return fmt.Errorf("query sessions: %w", err)
			}
			printSessions(cmd, resp)
			return nil
		},
	}
	cmd.Flags().Uint32Var(&limit, "limit", 0, "max sessions (0 = server default)")
	cmd.Flags().StringVar(&srcIP, "src-ip", "", "filter by exact original source IP")
	cmd.Flags().StringVar(&destIP, "dest-ip", "", "filter by exact original destination IP")
	cmd.Flags().StringVar(&ip, "ip", "", "filter by exact original or reply endpoint IP")
	cmd.Flags().StringVar(&protocol, "protocol", "", "filter by protocol, e.g. TCP, UDP, ICMP")
	cmd.Flags().Uint32Var(&port, "port", 0, "filter by original or reply port")
	cmd.Flags().StringVar(&state, "state", "", "filter by conntrack state, e.g. ESTABLISHED")
	cmd.Flags().StringVar(&query, "query", "", "search endpoints, protocol, state, and raw conntrack record")
	return cmd
}

func printSessions(cmd *cobra.Command, resp *openngfwv1.ListSessionsResponse) {
	state := value(resp.GetState())
	detail := resp.GetDetail()
	if detail == "" {
		detail = fmt.Sprintf("%d live session(s) matched", len(resp.GetSessions()))
	}
	cmd.Printf("conntrack %s: %s\n", state, detail)
	if len(resp.GetSessions()) == 0 {
		cmd.Println("no live sessions")
		return
	}
	for _, s := range resp.GetSessions() {
		flags := sessionFlags(s)
		if flags != "" {
			flags = " " + flags
		}
		cmd.Printf("%-5s %-13s %s -> %s  reply %s -> %s  pkts=%d bytes=%s%s\n",
			value(s.GetProtocol()),
			valueOrDash(s.GetState()),
			sessionEndpoint(s.GetSrcIp(), s.GetSrcPort()),
			sessionEndpoint(s.GetDestIp(), s.GetDestPort()),
			sessionEndpoint(s.GetReplySrcIp(), s.GetReplySrcPort()),
			sessionEndpoint(s.GetReplyDestIp(), s.GetReplyDestPort()),
			s.GetPackets(),
			humanBytes(s.GetBytes()),
			flags)
	}
}

func sessionEndpoint(ip string, port uint32) string {
	if ip == "" {
		ip = "-"
	}
	if port == 0 {
		return ip
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

func sessionFlags(s *openngfwv1.ConntrackSession) string {
	var flags []string
	if s.GetAssured() {
		flags = append(flags, "assured")
	}
	if s.GetTimeoutSeconds() > 0 {
		flags = append(flags, fmt.Sprintf("timeout=%ds", s.GetTimeoutSeconds()))
	}
	if s.GetFamily() != "" {
		flags = append(flags, s.GetFamily())
	}
	return strings.Join(flags, " ")
}
