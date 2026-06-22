package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func newWhoamiCommand(server *string) *cobra.Command {
	var outJSON bool
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Show the authenticated API actor and role",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()

			resp, err := openngfwv1.NewSystemServiceClient(conn).GetIdentity(ctx, &openngfwv1.GetIdentityRequest{})
			if err != nil {
				return fmt.Errorf("query identity: %w", err)
			}
			if outJSON {
				b, err := protojson.MarshalOptions{UseProtoNames: true, Indent: "  "}.Marshal(resp)
				if err != nil {
					return err
				}
				cmd.Println(string(b))
				return nil
			}
			printIdentity(cmd, resp)
			return nil
		},
	}
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

func printIdentity(cmd *cobra.Command, r *openngfwv1.GetIdentityResponse) {
	cmd.Printf("Actor:        %s\n", valueOrDash(r.GetActor()))
	cmd.Printf("Role:         %s\n", valueOrDash(r.GetRole()))
	cmd.Printf("Auth enabled: %t\n", r.GetAuthEnabled())
	cmd.Printf("Auth source:  %s\n", valueOrDash(r.GetAuthSource()))
	caps := r.GetCapabilities()
	if len(caps) == 0 {
		cmd.Println("Capabilities: -")
		return
	}
	cmd.Println("Capabilities: " + strings.Join(caps, ", "))
}
