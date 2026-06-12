package cli

import (
	"github.com/spf13/cobra"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func newAlertsCommand(server *string) *cobra.Command {
	var limit uint32
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "Show recent IDS/IPS alerts, newest first",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewAlertServiceClient(conn).ListAlerts(ctx, &openngfwv1.ListAlertsRequest{Limit: limit})
			if err != nil {
				return err
			}
			if len(resp.GetAlerts()) == 0 {
				cmd.Println("no alerts")
				return nil
			}
			for _, a := range resp.GetAlerts() {
				cmd.Printf("%s  sev=%d  %-8s %s:%d -> %s:%d  [%d] %s\n",
					a.GetTime().AsTime().Format("2006-01-02 15:04:05"),
					a.GetSeverity(), a.GetAction(),
					a.GetSrcIp(), a.GetSrcPort(), a.GetDestIp(), a.GetDestPort(),
					a.GetSignatureId(), a.GetSignature())
			}
			return nil
		},
	}
	cmd.Flags().Uint32Var(&limit, "limit", 0, "max alerts (0 = server default)")
	return cmd
}
