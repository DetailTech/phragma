package cli

import (
	"github.com/spf13/cobra"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func newIntelCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "intel",
		Short: "Threat-intelligence feeds and blocklists",
	}
	cmd.AddCommand(newIntelFeedsCommand(server), newIntelRefreshCommand(server))
	return cmd
}

func newIntelFeedsCommand(server *string) *cobra.Command {
	return &cobra.Command{
		Use:   "feeds",
		Short: "List registry feeds with license constraints and state",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewIntelServiceClient(conn).ListFeeds(ctx, &openngfwv1.ListFeedsRequest{})
			if err != nil {
				return err
			}
			for _, f := range resp.GetFeeds() {
				state := "disabled"
				if f.GetEnabled() {
					state = "ENABLED"
				}
				kind := "builtin"
				if f.GetCustom() {
					kind = "custom"
				}
				commercial := "commercial-use:no"
				if f.GetAllowsCommercialUse() {
					commercial = "commercial-use:yes"
				}
				cmd.Printf("%-16s %-8s %-8s %-18s %s\n", f.GetName(), state, kind, commercial, f.GetLicense())
				cmd.Printf("                 %s\n", f.GetDescription())
				if f.GetAttribution() != "" {
					cmd.Printf("                 attribution: %s\n", f.GetAttribution())
				}
			}
			return nil
		},
	}
}

func newIntelRefreshCommand(server *string) *cobra.Command {
	return &cobra.Command{
		Use:   "refresh",
		Short: "Fetch enabled feeds now and reprogram the blocklists",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewIntelServiceClient(conn).RefreshFeeds(ctx, &openngfwv1.RefreshFeedsRequest{})
			if err != nil {
				return err
			}
			cmd.Printf("blocklists refreshed: %d entries at %s\n",
				resp.GetEntries(), resp.GetRefreshedAt().AsTime().Format("2006-01-02 15:04:05"))
			return nil
		},
	}
}

func newFlowsCommand(server *string) *cobra.Command {
	var limit uint32
	cmd := &cobra.Command{
		Use:   "flows",
		Short: "Show recent flows with app/protocol labels, newest first",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewFlowServiceClient(conn).ListFlows(ctx, &openngfwv1.ListFlowsRequest{Limit: limit})
			if err != nil {
				return err
			}
			if len(resp.GetFlows()) == 0 {
				cmd.Println("no flows recorded (is IDS enabled?)")
				return nil
			}
			for _, f := range resp.GetFlows() {
				app := f.GetAppProtocol()
				if app == "" {
					app = "-"
				}
				cmd.Printf("%s  %-10s %-6s %s:%d -> %s:%d  bytes=%d/%d pkts=%d\n",
					f.GetTime().AsTime().Format("2006-01-02 15:04:05"),
					app, f.GetProtocol(),
					f.GetSrcIp(), f.GetSrcPort(), f.GetDestIp(), f.GetDestPort(),
					f.GetBytesToServer(), f.GetBytesToClient(), f.GetPackets())
			}
			return nil
		},
	}
	cmd.Flags().Uint32Var(&limit, "limit", 0, "max flows (0 = server default)")
	return cmd
}
