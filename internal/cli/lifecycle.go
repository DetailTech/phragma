package cli

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func newCommitCommand(server *string) *cobra.Command {
	var comment string
	cmd := &cobra.Command{
		Use:   "commit",
		Short: "Validate and atomically apply the candidate policy",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewPolicyServiceClient(conn).Commit(ctx, &openngfwv1.CommitRequest{Comment: comment})
			if err != nil {
				return fmt.Errorf("commit: %w", err)
			}
			cmd.Printf("committed version %d\n", resp.GetVersion())
			return nil
		},
	}
	cmd.Flags().StringVarP(&comment, "message", "m", "", "commit comment")
	return cmd
}

func newRollbackCommand(server *string) *cobra.Command {
	return &cobra.Command{
		Use:   "rollback <version>",
		Short: "Re-apply a historical version as a new commit",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ver, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("version must be a number: %w", err)
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewPolicyServiceClient(conn).Rollback(ctx, &openngfwv1.RollbackRequest{Version: ver})
			if err != nil {
				return fmt.Errorf("rollback: %w", err)
			}
			cmd.Printf("rolled back to version %d (new version %d)\n", ver, resp.GetVersion())
			return nil
		},
	}
}

func newVersionsCommand(server *string) *cobra.Command {
	var limit uint32
	cmd := &cobra.Command{
		Use:   "versions",
		Short: "List committed policy versions, newest first",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewPolicyServiceClient(conn).ListVersions(ctx, &openngfwv1.ListVersionsRequest{Limit: limit})
			if err != nil {
				return err
			}
			if len(resp.GetVersions()) == 0 {
				cmd.Println("no versions committed yet")
				return nil
			}
			for _, v := range resp.GetVersions() {
				cmd.Printf("%-6d %s  %-10s %s\n", v.GetId(), v.GetCreatedAt().AsTime().Format("2006-01-02 15:04:05"), v.GetActor(), v.GetComment())
			}
			return nil
		},
	}
	cmd.Flags().Uint32Var(&limit, "limit", 0, "max entries (0 = server default)")
	return cmd
}

func newAuditCommand(server *string) *cobra.Command {
	var limit uint32
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show the audit log, newest first",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewPolicyServiceClient(conn).ListAuditEntries(ctx, &openngfwv1.ListAuditEntriesRequest{Limit: limit})
			if err != nil {
				return err
			}
			if len(resp.GetEntries()) == 0 {
				cmd.Println("audit log is empty")
				return nil
			}
			for _, e := range resp.GetEntries() {
				line := fmt.Sprintf("%-6d %s  %-10s %-16s %s", e.GetId(), e.GetTime().AsTime().Format("2006-01-02 15:04:05"), e.GetActor(), e.GetAction(), e.GetDetail())
				if e.GetVersion() != 0 {
					line += fmt.Sprintf(" (version %d)", e.GetVersion())
				}
				cmd.Println(line)
			}
			return nil
		},
	}
	cmd.Flags().Uint32Var(&limit, "limit", 0, "max entries (0 = server default)")
	return cmd
}
