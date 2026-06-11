// Package cli implements the ngfwctl command tree. ngfwctl is a thin
// client of the canonical gRPC API — it contains no policy logic.
package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/version"
)

// NewRootCommand builds the ngfwctl command tree.
func NewRootCommand() *cobra.Command {
	var server string
	root := &cobra.Command{
		Use:           "ngfwctl",
		Short:         "OpenNGFW command-line client",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.PersistentFlags().StringVar(&server, "server", "127.0.0.1:9443", "controld gRPC address")
	root.PersistentFlags().StringVar(&apiToken, "token", os.Getenv("NGFW_TOKEN"),
		"API token when controld runs with --users-file (env: NGFW_TOKEN)")

	root.AddCommand(
		newVersionCommand(&server),
		newPolicyCommand(&server),
		newCommitCommand(&server),
		newRollbackCommand(&server),
		newVersionsCommand(&server),
		newAuditCommand(&server),
		newAlertsCommand(&server),
		newIntelCommand(&server),
		newFlowsCommand(&server),
	)
	return root
}

// apiToken is the bearer token sent with every RPC when set.
var apiToken string

// dial connects to controld and returns the connection plus a deadline
// context for one RPC, with authentication attached when configured.
func dial(ctx context.Context, addr string) (*grpc.ClientConn, context.Context, context.CancelFunc, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connect to controld at %s: %w", addr, err)
	}
	rpcCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	if apiToken != "" {
		rpcCtx = metadata.AppendToOutgoingContext(rpcCtx, "authorization", "Bearer "+apiToken)
	}
	return conn, rpcCtx, cancel, nil
}

func newVersionCommand(server *string) *cobra.Command {
	var remote bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print client version; with --remote, also the controld version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Println("ngfwctl " + version.String())
			if !remote {
				return nil
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewSystemServiceClient(conn).GetVersion(ctx, &openngfwv1.GetVersionRequest{})
			if err != nil {
				return fmt.Errorf("query controld: %w", err)
			}
			cmd.Printf("controld %s (commit %s, built %s)\n", resp.GetVersion(), resp.GetCommit(), resp.GetBuildDate())
			return nil
		},
	}
	cmd.Flags().BoolVar(&remote, "remote", false, "also query the server version")
	return cmd
}
