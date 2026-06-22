// Package cli implements the ngfwctl command tree. ngfwctl is a thin
// client of the canonical gRPC API — it contains no policy logic.
package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
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
		Short:         "Phragma command-line client",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.PersistentFlags().StringVar(&server, "server", "127.0.0.1:9443", "controld gRPC address")
	root.PersistentFlags().StringVar(&apiToken, "token", os.Getenv("NGFW_TOKEN"),
		"API token when controld runs with --users-file (env: NGFW_TOKEN)")
	root.PersistentFlags().StringVar(&apiTokenFile, "token-file", os.Getenv("NGFW_TOKEN_FILE"),
		"read API token from a file (env: NGFW_TOKEN_FILE)")
	root.PersistentFlags().BoolVar(&apiTokenStdin, "token-stdin", false,
		"read API token from stdin")
	root.PersistentFlags().BoolVar(&allowInsecureTokenTransport, "allow-insecure-token", false,
		"allow sending bearer tokens over insecure gRPC to non-loopback servers (unsafe)")

	root.AddCommand(
		newVersionCommand(&server),
		newPolicyCommand(&server),
		newCommitCommand(&server),
		newRollbackCommand(&server),
		newVersionsCommand(&server),
		newAuditCommand(&server),
		newAlertsCommand(&server),
		newAppIDCommand(&server),
		newThreatExceptionsCommand(&server),
		newIntelCommand(&server),
		newFlowsCommand(&server),
		newSessionsCommand(&server),
		newExplainCommand(&server),
		newWhoamiCommand(&server),
		newAccessCommand(&server),
		newStatusCommand(&server),
		newSystemCommand(&server),
		newSupportBundleCommand(&server),
		newComplianceCommand(&server),
		newFleetCommand(&server),
	)
	return root
}

// apiToken is the bearer token sent with every RPC when set.
var apiToken string
var apiTokenFile string
var apiTokenStdin bool
var apiTokenStdinReader io.Reader = os.Stdin

// allowInsecureTokenTransport explicitly permits token-authenticated RPCs over
// cleartext gRPC to non-loopback targets.
var allowInsecureTokenTransport bool

// dial connects to controld and returns the connection plus a deadline
// context for one RPC, with authentication attached when configured.
func dial(ctx context.Context, addr string) (*grpc.ClientConn, context.Context, context.CancelFunc, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	token, err := resolveAPIToken()
	if err != nil {
		return nil, nil, nil, err
	}
	if err := validateTokenTransport(addr, token); err != nil {
		return nil, nil, nil, err
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connect to controld at %s: %w", addr, err)
	}
	rpcCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	if token != "" {
		rpcCtx = metadata.AppendToOutgoingContext(rpcCtx, "authorization", "Bearer "+token)
	}
	return conn, rpcCtx, cancel, nil
}

func resolveAPIToken() (string, error) {
	token := strings.TrimSpace(apiToken)
	tokenFile := strings.TrimSpace(apiTokenFile)
	var sources []string
	if token != "" {
		sources = append(sources, "--token/NGFW_TOKEN")
	}
	if tokenFile != "" {
		sources = append(sources, "--token-file/NGFW_TOKEN_FILE")
	}
	if apiTokenStdin {
		sources = append(sources, "--token-stdin")
	}
	if len(sources) > 1 {
		return "", fmt.Errorf("conflicting API token sources: %s", strings.Join(sources, ", "))
	}
	if token != "" {
		return token, nil
	}
	if tokenFile != "" {
		raw, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("read API token file: %w", err)
		}
		token = strings.TrimSpace(string(raw))
		if token == "" {
			return "", fmt.Errorf("API token file is empty")
		}
		return token, nil
	}
	if apiTokenStdin {
		raw, err := io.ReadAll(apiTokenStdinReader)
		if err != nil {
			return "", fmt.Errorf("read API token from stdin: %w", err)
		}
		token = strings.TrimSpace(string(raw))
		if token == "" {
			return "", fmt.Errorf("API token from stdin is empty")
		}
		return token, nil
	}
	return "", nil
}

func validateTokenTransport(addr string, token string) error {
	if token == "" || allowInsecureTokenTransport || isLocalGRPCTarget(addr) {
		return nil
	}
	return fmt.Errorf("refusing to send bearer token over insecure gRPC to non-loopback server %q; use loopback, a secure tunnel, or --allow-insecure-token if you accept the risk", addr)
}

func isLocalGRPCTarget(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	lowerTarget := strings.ToLower(target)
	if strings.HasPrefix(lowerTarget, "unix:") || strings.HasPrefix(lowerTarget, "unix-abstract:") || strings.HasPrefix(lowerTarget, "bufconn:") {
		return true
	}

	endpoint := target
	if u, err := url.Parse(target); err == nil && u.Scheme != "" {
		switch strings.ToLower(u.Scheme) {
		case "unix", "unix-abstract", "bufconn":
			return true
		case "dns", "passthrough", "ipv4", "ipv6":
			if u.Opaque != "" {
				endpoint = u.Opaque
			} else if path := strings.TrimLeft(u.Path, "/"); path != "" {
				endpoint = path
			} else if u.Host != "" {
				endpoint = u.Host
			}
		default:
			if u.Host != "" {
				endpoint = u.Host
			}
		}
	}

	host, ok := targetHost(endpoint)
	return ok && isLoopbackHost(host)
}

func targetHost(endpoint string) (string, bool) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", false
	}
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		return strings.Trim(host, "[]"), true
	}
	if strings.HasPrefix(endpoint, "[") {
		if end := strings.Index(endpoint, "]"); end > 1 {
			return endpoint[1:end], true
		}
		return "", false
	}
	if strings.Count(endpoint, ":") > 1 {
		return endpoint, true
	}
	host, _, _ := strings.Cut(endpoint, ":")
	return strings.Trim(host, "[]"), host != ""
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return false
	}
	if i := strings.LastIndex(host, "%"); i >= 0 {
		host = host[:i]
	}
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
