package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func newAccessCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "access",
		Short: "Administer API access and local break-glass users",
	}
	cmd.AddCommand(
		newAccessUsersCommand(server),
		newAccessSessionsCommand(server),
		newAccessOIDCCommand(server),
		newAccessSAMLCommand(server),
	)
	return cmd
}

type accessAdministrationClient interface {
	GetAccessAdministration(context.Context, *openngfwv1.GetAccessAdministrationRequest, ...grpc.CallOption) (*openngfwv1.GetAccessAdministrationResponse, error)
	GetOIDCProviderConfig(context.Context, *openngfwv1.GetOIDCProviderConfigRequest, ...grpc.CallOption) (*openngfwv1.GetOIDCProviderConfigResponse, error)
	ValidateOIDCProviderConfig(context.Context, *openngfwv1.ValidateOIDCProviderConfigRequest, ...grpc.CallOption) (*openngfwv1.ValidateOIDCProviderConfigResponse, error)
	SetOIDCProviderConfig(context.Context, *openngfwv1.SetOIDCProviderConfigRequest, ...grpc.CallOption) (*openngfwv1.SetOIDCProviderConfigResponse, error)
	DisableOIDCProvider(context.Context, *openngfwv1.DisableOIDCProviderRequest, ...grpc.CallOption) (*openngfwv1.DisableOIDCProviderResponse, error)
	GetSAMLProviderConfig(context.Context, *openngfwv1.GetSAMLProviderConfigRequest, ...grpc.CallOption) (*openngfwv1.GetSAMLProviderConfigResponse, error)
	ValidateSAMLProviderConfig(context.Context, *openngfwv1.ValidateSAMLProviderConfigRequest, ...grpc.CallOption) (*openngfwv1.ValidateSAMLProviderConfigResponse, error)
	SetSAMLProviderConfig(context.Context, *openngfwv1.SetSAMLProviderConfigRequest, ...grpc.CallOption) (*openngfwv1.SetSAMLProviderConfigResponse, error)
	DisableSAMLProvider(context.Context, *openngfwv1.DisableSAMLProviderRequest, ...grpc.CallOption) (*openngfwv1.DisableSAMLProviderResponse, error)
	RevokeAccessSession(context.Context, *openngfwv1.RevokeAccessSessionRequest, ...grpc.CallOption) (*openngfwv1.RevokeAccessSessionResponse, error)
}

func newAccessUsersCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "users",
		Short: "List and mutate local API users",
	}
	cmd.AddCommand(
		newAccessUsersListCommand(server),
		newAccessUsersCreateCommand(server),
		newAccessUsersSetRoleCommand(server),
		newAccessUsersRotateCommand(server),
		newAccessUsersDisableCommand(server),
	)
	return cmd
}

func newAccessSessionsCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "List and revoke active browser SSO sessions",
	}
	cmd.AddCommand(
		newAccessSessionsListCommand(server),
		newAccessSessionsRevokeCommand(server),
	)
	return cmd
}

func newAccessOIDCCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "oidc",
		Short: "Administer runtime OIDC browser SSO provider config",
	}
	provider := &cobra.Command{
		Use:   "provider",
		Short: "Show, validate, set, or disable the runtime OIDC provider",
	}
	provider.AddCommand(
		newAccessOIDCShowCommand(server),
		newAccessOIDCValidateCommand(server),
		newAccessOIDCSetCommand(server),
		newAccessOIDCDisableCommand(server),
	)
	cmd.AddCommand(provider)
	return cmd
}

func newAccessOIDCShowCommand(server *string) *cobra.Command {
	var outJSON bool
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show redacted runtime OIDC provider config",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runAccessOIDCShow(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), outJSON)
		},
	}
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

func newAccessOIDCValidateCommand(server *string) *cobra.Command {
	opts := accessOIDCProviderOptions{defaultRole: "viewer", roleClaim: "role", scopes: "openid,profile,email"}
	var outJSON bool
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate OIDC provider config without changing runtime state",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runAccessOIDCValidate(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), opts, outJSON)
		},
	}
	addAccessOIDCProviderFlags(cmd, &opts)
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

func newAccessOIDCSetCommand(server *string) *cobra.Command {
	opts := accessOIDCProviderOptions{defaultRole: "viewer", roleClaim: "role", scopes: "openid,profile,email"}
	var comment string
	var ack, outJSON bool
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Save and activate runtime OIDC provider config",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(comment) == "" {
				return fmt.Errorf("audit comment is required; pass --message/-m")
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runAccessOIDCSet(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), opts, comment, ack, outJSON)
		},
	}
	addAccessOIDCProviderFlags(cmd, &opts)
	cmd.Flags().StringVarP(&comment, "message", "m", "", "required audit comment")
	cmd.Flags().BoolVar(&ack, "ack-oidc-change", false, "acknowledge changing browser SSO access")
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

func newAccessOIDCDisableCommand(server *string) *cobra.Command {
	var comment string
	var ack, outJSON bool
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable runtime OIDC browser SSO provider",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(comment) == "" {
				return fmt.Errorf("audit comment is required; pass --message/-m")
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runAccessOIDCDisable(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), comment, ack, outJSON)
		},
	}
	cmd.Flags().StringVarP(&comment, "message", "m", "", "required audit comment")
	cmd.Flags().BoolVar(&ack, "ack-disable-oidc", false, "acknowledge disabling browser SSO access")
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

func newAccessSAMLCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "saml",
		Short: "Administer SAML browser SSO provider config",
	}
	provider := &cobra.Command{
		Use:   "provider",
		Short: "Show, validate, set, or disable the SAML provider",
	}
	provider.AddCommand(
		newAccessSAMLShowCommand(server),
		newAccessSAMLValidateCommand(server),
		newAccessSAMLSetCommand(server),
		newAccessSAMLDisableCommand(server),
	)
	cmd.AddCommand(provider)
	return cmd
}

func newAccessSAMLShowCommand(server *string) *cobra.Command {
	var outJSON bool
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show redacted SAML provider config",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runAccessSAMLShow(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), outJSON)
		},
	}
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

func newAccessSAMLValidateCommand(server *string) *cobra.Command {
	opts := accessSAMLProviderOptions{defaultRole: "viewer", roleAttribute: "role"}
	var outJSON bool
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate SAML provider config without changing runtime state",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runAccessSAMLValidate(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), opts, outJSON)
		},
	}
	addAccessSAMLProviderFlags(cmd, &opts)
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

func newAccessSAMLSetCommand(server *string) *cobra.Command {
	opts := accessSAMLProviderOptions{defaultRole: "viewer", roleAttribute: "role"}
	var comment string
	var ack, outJSON bool
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Save SAML provider config",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(comment) == "" {
				return fmt.Errorf("audit comment is required; pass --message/-m")
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runAccessSAMLSet(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), opts, comment, ack, outJSON)
		},
	}
	addAccessSAMLProviderFlags(cmd, &opts)
	cmd.Flags().StringVarP(&comment, "message", "m", "", "required audit comment")
	cmd.Flags().BoolVar(&ack, "ack-saml-change", false, "acknowledge changing SAML browser SSO posture")
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

func newAccessSAMLDisableCommand(server *string) *cobra.Command {
	var comment string
	var ack, outJSON bool
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable SAML provider config",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(comment) == "" {
				return fmt.Errorf("audit comment is required; pass --message/-m")
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runAccessSAMLDisable(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), comment, ack, outJSON)
		},
	}
	cmd.Flags().StringVarP(&comment, "message", "m", "", "required audit comment")
	cmd.Flags().BoolVar(&ack, "ack-disable-saml", false, "acknowledge disabling SAML browser SSO posture")
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

type accessOIDCProviderOptions struct {
	issuer            string
	clientID          string
	clientSecretFile  string
	redirectURL       string
	roleClaim         string
	defaultRole       string
	scopes            string
	trustedProxyCIDRs string
	sessionTTLSeconds uint64
	maxSessions       uint32
}

type accessSAMLProviderOptions struct {
	metadataURL            string
	idpEntityID            string
	ssoURL                 string
	spEntityID             string
	acsURL                 string
	roleAttribute          string
	defaultRole            string
	certificateFingerprint string
}

func addAccessOIDCProviderFlags(cmd *cobra.Command, opts *accessOIDCProviderOptions) {
	cmd.Flags().StringVar(&opts.issuer, "issuer", "", "OIDC issuer URL")
	cmd.Flags().StringVar(&opts.clientID, "client-id", "", "OIDC client ID")
	cmd.Flags().StringVar(&opts.clientSecretFile, "client-secret-file", "", "server-local OIDC client secret file path")
	cmd.Flags().StringVar(&opts.redirectURL, "redirect-url", "", "OIDC redirect URL ending in /v1/auth/oidc/callback")
	cmd.Flags().StringVar(&opts.roleClaim, "role-claim", opts.roleClaim, "OIDC claim containing viewer/operator/admin role")
	cmd.Flags().StringVar(&opts.defaultRole, "default-role", opts.defaultRole, "fallback role: viewer | operator | admin")
	cmd.Flags().StringVar(&opts.scopes, "scopes", opts.scopes, "comma-separated OIDC scopes")
	cmd.Flags().StringVar(&opts.trustedProxyCIDRs, "trusted-proxy-cidrs", "", "comma-separated trusted proxy CIDRs")
	cmd.Flags().Uint64Var(&opts.sessionTTLSeconds, "session-ttl-seconds", 0, "optional OIDC session TTL in seconds")
	cmd.Flags().Uint32Var(&opts.maxSessions, "max-sessions", 0, "optional OIDC max browser sessions")
}

func addAccessSAMLProviderFlags(cmd *cobra.Command, opts *accessSAMLProviderOptions) {
	cmd.Flags().StringVar(&opts.metadataURL, "metadata-url", "", "SAML IdP metadata URL")
	cmd.Flags().StringVar(&opts.idpEntityID, "idp-entity-id", "", "SAML IdP entity ID")
	cmd.Flags().StringVar(&opts.ssoURL, "sso-url", "", "SAML IdP SSO URL")
	cmd.Flags().StringVar(&opts.spEntityID, "sp-entity-id", "", "SAML service provider entity ID")
	cmd.Flags().StringVar(&opts.acsURL, "acs-url", "", "SAML ACS URL ending in /v1/auth/saml/acs")
	cmd.Flags().StringVar(&opts.roleAttribute, "role-attribute", opts.roleAttribute, "SAML attribute containing viewer/operator/admin role")
	cmd.Flags().StringVar(&opts.defaultRole, "default-role", opts.defaultRole, "fallback role: viewer | operator | admin")
	cmd.Flags().StringVar(&opts.certificateFingerprint, "certificate-fingerprint", "", "optional SAML IdP signing certificate SHA-256 fingerprint")
}

func newAccessSessionsListCommand(server *string) *cobra.Command {
	var outJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List active browser SSO sessions by non-secret session ID",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runAccessSessionsList(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), outJSON)
		},
	}
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

func newAccessSessionsRevokeCommand(server *string) *cobra.Command {
	var ack, outJSON bool
	cmd := &cobra.Command{
		Use:   "revoke SESSION_ID",
		Short: "Revoke one active browser SSO session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runAccessSessionRevoke(ctx, cmd, openngfwv1.NewSystemServiceClient(conn), strings.TrimSpace(args[0]), ack, outJSON)
		},
	}
	cmd.Flags().BoolVar(&ack, "ack-revoke-session", false, "acknowledge forcing another browser session to sign out")
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

func newAccessUsersListCommand(server *string) *cobra.Command {
	var outJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List non-secret local user inventory",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewSystemServiceClient(conn).GetAccessAdministration(ctx, &openngfwv1.GetAccessAdministrationRequest{})
			if err != nil {
				return fmt.Errorf("list access users: %w", err)
			}
			if outJSON {
				return printJSON(cmd, resp)
			}
			printAccessUsers(cmd, resp.GetLocalUsers())
			return nil
		},
	}
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

func newAccessUsersCreateCommand(server *string) *cobra.Command {
	var role, comment string
	var ack bool
	cmd := &cobra.Command{
		Use:   "create NAME",
		Short: "Create a local API user and print its one-time token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(comment) == "" {
				return fmt.Errorf("audit comment is required; pass --message/-m")
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewSystemServiceClient(conn).CreateLocalUser(ctx, &openngfwv1.CreateLocalUserRequest{
				Name: args[0], Role: role, Comment: comment, AckLocalUserChange: ack,
			})
			if err != nil {
				return fmt.Errorf("create local user: %w", err)
			}
			printLocalUserMutation(cmd, resp.GetUser(), resp.GetDetail(), resp.GetOneTimeToken())
			return nil
		},
	}
	cmd.Flags().StringVar(&role, "role", "viewer", "role: viewer | operator | admin")
	cmd.Flags().StringVarP(&comment, "message", "m", "", "required audit comment")
	cmd.Flags().BoolVar(&ack, "ack-local-user-change", false, "acknowledge creating a local credential")
	return cmd
}

func newAccessUsersSetRoleCommand(server *string) *cobra.Command {
	var role, comment string
	var ack bool
	cmd := &cobra.Command{
		Use:   "set-role NAME",
		Short: "Change a local user's role",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(comment) == "" {
				return fmt.Errorf("audit comment is required; pass --message/-m")
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewSystemServiceClient(conn).UpdateLocalUser(ctx, &openngfwv1.UpdateLocalUserRequest{
				Name: args[0], Role: role, Comment: comment, AckLocalUserChange: ack,
			})
			if err != nil {
				return fmt.Errorf("update local user role: %w", err)
			}
			printLocalUserMutation(cmd, resp.GetUser(), resp.GetDetail(), "")
			return nil
		},
	}
	cmd.Flags().StringVar(&role, "role", "", "role: viewer | operator | admin")
	cmd.Flags().StringVarP(&comment, "message", "m", "", "required audit comment")
	cmd.Flags().BoolVar(&ack, "ack-local-user-change", false, "acknowledge changing local authorization")
	_ = cmd.MarkFlagRequired("role")
	return cmd
}

func newAccessUsersRotateCommand(server *string) *cobra.Command {
	var comment string
	var ack bool
	cmd := &cobra.Command{
		Use:   "rotate-token NAME",
		Short: "Rotate a local user's API token and print the new one-time token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(comment) == "" {
				return fmt.Errorf("audit comment is required; pass --message/-m")
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewSystemServiceClient(conn).RotateLocalUserToken(ctx, &openngfwv1.RotateLocalUserTokenRequest{
				Name: args[0], Comment: comment, AckRotateToken: ack,
			})
			if err != nil {
				return fmt.Errorf("rotate local user token: %w", err)
			}
			printLocalUserMutation(cmd, resp.GetUser(), resp.GetDetail(), resp.GetOneTimeToken())
			return nil
		},
	}
	cmd.Flags().StringVarP(&comment, "message", "m", "", "required audit comment")
	cmd.Flags().BoolVar(&ack, "ack-rotate-token", false, "acknowledge replacing the current local credential")
	return cmd
}

func newAccessUsersDisableCommand(server *string) *cobra.Command {
	var comment string
	var ack bool
	cmd := &cobra.Command{
		Use:   "disable NAME",
		Short: "Disable a local API user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(comment) == "" {
				return fmt.Errorf("audit comment is required; pass --message/-m")
			}
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewSystemServiceClient(conn).DisableLocalUser(ctx, &openngfwv1.DisableLocalUserRequest{
				Name: args[0], Comment: comment, AckDisableUser: ack,
			})
			if err != nil {
				return fmt.Errorf("disable local user: %w", err)
			}
			printLocalUserMutation(cmd, resp.GetUser(), resp.GetDetail(), "")
			return nil
		},
	}
	cmd.Flags().StringVarP(&comment, "message", "m", "", "required audit comment")
	cmd.Flags().BoolVar(&ack, "ack-disable-user", false, "acknowledge disabling local credential access")
	return cmd
}

func runAccessSessionsList(ctx context.Context, cmd *cobra.Command, client accessAdministrationClient, outJSON bool) error {
	resp, err := client.GetAccessAdministration(ctx, &openngfwv1.GetAccessAdministrationRequest{})
	if err != nil {
		return fmt.Errorf("list access sessions: %w", err)
	}
	sessions := resp.GetSessions()
	if sessions == nil {
		sessions = &openngfwv1.AccessAdministrationSessions{}
	}
	if outJSON {
		return printJSON(cmd, sessions)
	}
	printAccessSessions(cmd, sessions)
	return nil
}

func runAccessSessionRevoke(ctx context.Context, cmd *cobra.Command, client accessAdministrationClient, sessionID string, ack, outJSON bool) error {
	if strings.TrimSpace(sessionID) == "" {
		return fmt.Errorf("session ID is required")
	}
	if !ack {
		return fmt.Errorf("acknowledge session revocation with --ack-revoke-session")
	}
	resp, err := client.RevokeAccessSession(ctx, &openngfwv1.RevokeAccessSessionRequest{
		SessionId:        sessionID,
		AckRevokeSession: ack,
	})
	if err != nil {
		return fmt.Errorf("revoke access session: %w", err)
	}
	if outJSON {
		return printJSON(cmd, resp)
	}
	printAccessSessionRevoke(cmd, resp)
	return nil
}

func runAccessOIDCShow(ctx context.Context, cmd *cobra.Command, client accessAdministrationClient, outJSON bool) error {
	resp, err := client.GetOIDCProviderConfig(ctx, &openngfwv1.GetOIDCProviderConfigRequest{})
	if err != nil {
		return fmt.Errorf("show OIDC provider config: %w", err)
	}
	if outJSON {
		return printJSON(cmd, resp)
	}
	if resp.GetDetail() != "" {
		cmd.Println(resp.GetDetail())
	}
	printOIDCProviderConfig(cmd, resp.GetConfig())
	return nil
}

func runAccessOIDCValidate(ctx context.Context, cmd *cobra.Command, client accessAdministrationClient, opts accessOIDCProviderOptions, outJSON bool) error {
	resp, err := client.ValidateOIDCProviderConfig(ctx, &openngfwv1.ValidateOIDCProviderConfigRequest{Config: oidcProviderConfigFromOptions(opts)})
	if err != nil {
		return fmt.Errorf("validate OIDC provider config: %w", err)
	}
	if outJSON {
		return printJSON(cmd, resp)
	}
	printOIDCProviderValidation(cmd, resp)
	return nil
}

func runAccessOIDCSet(ctx context.Context, cmd *cobra.Command, client accessAdministrationClient, opts accessOIDCProviderOptions, comment string, ack, outJSON bool) error {
	if !ack {
		return fmt.Errorf("acknowledge OIDC provider change with --ack-oidc-change")
	}
	resp, err := client.SetOIDCProviderConfig(ctx, &openngfwv1.SetOIDCProviderConfigRequest{
		Config:        oidcProviderConfigFromOptions(opts),
		Comment:       comment,
		AckOidcChange: ack,
	})
	if err != nil {
		return fmt.Errorf("set OIDC provider config: %w", err)
	}
	if outJSON {
		return printJSON(cmd, resp)
	}
	if resp.GetDetail() != "" {
		cmd.Println(resp.GetDetail())
	}
	printOIDCProviderConfig(cmd, resp.GetConfig())
	cmd.Printf("revoked_oidc_sessions=%d\n", resp.GetRevokedOidcSessions())
	return nil
}

func runAccessOIDCDisable(ctx context.Context, cmd *cobra.Command, client accessAdministrationClient, comment string, ack, outJSON bool) error {
	if !ack {
		return fmt.Errorf("acknowledge OIDC provider disable with --ack-disable-oidc")
	}
	resp, err := client.DisableOIDCProvider(ctx, &openngfwv1.DisableOIDCProviderRequest{
		Comment:        comment,
		AckDisableOidc: ack,
	})
	if err != nil {
		return fmt.Errorf("disable OIDC provider: %w", err)
	}
	if outJSON {
		return printJSON(cmd, resp)
	}
	if resp.GetDetail() != "" {
		cmd.Println(resp.GetDetail())
	}
	cmd.Printf("disabled=%t\trevoked_oidc_sessions=%d\n", resp.GetDisabled(), resp.GetRevokedOidcSessions())
	return nil
}

func runAccessSAMLShow(ctx context.Context, cmd *cobra.Command, client accessAdministrationClient, outJSON bool) error {
	resp, err := client.GetSAMLProviderConfig(ctx, &openngfwv1.GetSAMLProviderConfigRequest{})
	if err != nil {
		return fmt.Errorf("show SAML provider config: %w", err)
	}
	if outJSON {
		return printJSON(cmd, resp)
	}
	if resp.GetDetail() != "" {
		cmd.Println(resp.GetDetail())
	}
	printSAMLProviderConfig(cmd, resp.GetConfig())
	return nil
}

func runAccessSAMLValidate(ctx context.Context, cmd *cobra.Command, client accessAdministrationClient, opts accessSAMLProviderOptions, outJSON bool) error {
	resp, err := client.ValidateSAMLProviderConfig(ctx, &openngfwv1.ValidateSAMLProviderConfigRequest{Config: samlProviderConfigFromOptions(opts)})
	if err != nil {
		return fmt.Errorf("validate SAML provider config: %w", err)
	}
	if outJSON {
		return printJSON(cmd, resp)
	}
	printSAMLProviderValidation(cmd, resp)
	return nil
}

func runAccessSAMLSet(ctx context.Context, cmd *cobra.Command, client accessAdministrationClient, opts accessSAMLProviderOptions, comment string, ack, outJSON bool) error {
	if !ack {
		return fmt.Errorf("acknowledge SAML provider change with --ack-saml-change")
	}
	resp, err := client.SetSAMLProviderConfig(ctx, &openngfwv1.SetSAMLProviderConfigRequest{
		Config:        samlProviderConfigFromOptions(opts),
		Comment:       comment,
		AckSamlChange: ack,
	})
	if err != nil {
		return fmt.Errorf("set SAML provider config: %w", err)
	}
	if outJSON {
		return printJSON(cmd, resp)
	}
	if resp.GetDetail() != "" {
		cmd.Println(resp.GetDetail())
	}
	printSAMLProviderConfig(cmd, resp.GetConfig())
	return nil
}

func runAccessSAMLDisable(ctx context.Context, cmd *cobra.Command, client accessAdministrationClient, comment string, ack, outJSON bool) error {
	if !ack {
		return fmt.Errorf("acknowledge SAML provider disable with --ack-disable-saml")
	}
	resp, err := client.DisableSAMLProvider(ctx, &openngfwv1.DisableSAMLProviderRequest{
		Comment:        comment,
		AckDisableSaml: ack,
	})
	if err != nil {
		return fmt.Errorf("disable SAML provider: %w", err)
	}
	if outJSON {
		return printJSON(cmd, resp)
	}
	if resp.GetDetail() != "" {
		cmd.Println(resp.GetDetail())
	}
	cmd.Printf("disabled=%t\n", resp.GetDisabled())
	return nil
}

func oidcProviderConfigFromOptions(opts accessOIDCProviderOptions) *openngfwv1.OIDCProviderConfig {
	return &openngfwv1.OIDCProviderConfig{
		Enabled:           true,
		Issuer:            strings.TrimSpace(opts.issuer),
		ClientId:          strings.TrimSpace(opts.clientID),
		ClientSecretFile:  strings.TrimSpace(opts.clientSecretFile),
		RedirectUrl:       strings.TrimSpace(opts.redirectURL),
		RoleClaim:         strings.TrimSpace(opts.roleClaim),
		DefaultRole:       strings.TrimSpace(opts.defaultRole),
		Scopes:            splitAccessCSV(opts.scopes),
		TrustedProxyCidrs: splitAccessCSV(opts.trustedProxyCIDRs),
		SessionTtlSeconds: opts.sessionTTLSeconds,
		MaxSessions:       opts.maxSessions,
	}
}

func samlProviderConfigFromOptions(opts accessSAMLProviderOptions) *openngfwv1.SAMLProviderConfig {
	return &openngfwv1.SAMLProviderConfig{
		Enabled:                true,
		MetadataUrl:            strings.TrimSpace(opts.metadataURL),
		IdpEntityId:            strings.TrimSpace(opts.idpEntityID),
		SsoUrl:                 strings.TrimSpace(opts.ssoURL),
		SpEntityId:             strings.TrimSpace(opts.spEntityID),
		AcsUrl:                 strings.TrimSpace(opts.acsURL),
		RoleAttribute:          strings.TrimSpace(opts.roleAttribute),
		DefaultRole:            strings.TrimSpace(opts.defaultRole),
		CertificateFingerprint: strings.TrimSpace(opts.certificateFingerprint),
	}
}

func splitAccessCSV(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" || seen[part] {
			continue
		}
		seen[part] = true
		out = append(out, part)
	}
	return out
}

func printAccessUsers(cmd *cobra.Command, users []*openngfwv1.AccessAdministrationLocalUser) {
	if len(users) == 0 {
		cmd.Println("no local users")
		return
	}
	for _, user := range users {
		state := "enabled"
		if !user.GetEnabled() {
			state = "disabled"
		}
		edit := "read-only"
		if user.GetEditable() {
			edit = "editable"
		}
		cmd.Printf("%s\trole=%s\tstate=%s\t%s\t%s\n",
			user.GetName(), user.GetRole(), state, edit, user.GetTokenMaterial())
	}
}

func printAccessSessions(cmd *cobra.Command, sessions *openngfwv1.AccessAdministrationSessions) {
	if sessions == nil {
		cmd.Println("browser SSO session inventory unavailable")
		return
	}
	revocation := "not-available"
	if sessions.GetSessionRevocationAvailable() {
		revocation = "available"
	}
	cmd.Printf("browser_sso_sessions=%d/%d\trevocation=%s\n", sessions.GetOidcActiveSessions(), sessions.GetOidcMaxSessions(), revocation)
	if sessions.GetDetail() != "" {
		cmd.Println(sessions.GetDetail())
	}
	active := sessions.GetActiveSessions()
	if len(active) == 0 {
		cmd.Println("no active browser SSO sessions")
		return
	}
	for _, session := range active {
		cmd.Printf("%s\tactor=%s\trole=%s\tauth_source=%s\texpires=%s\tttl=%ds\n",
			session.GetSessionId(),
			session.GetActor(),
			session.GetRole(),
			session.GetAuthSource(),
			session.GetExpiresAt(),
			session.GetSecondsUntilExpiry(),
		)
	}
}

func printAccessSessionRevoke(cmd *cobra.Command, resp *openngfwv1.RevokeAccessSessionResponse) {
	if resp == nil {
		cmd.Println("session revoke response unavailable")
		return
	}
	if resp.GetDetail() != "" {
		cmd.Println(resp.GetDetail())
	}
	if session := resp.GetSession(); session != nil {
		cmd.Printf("session: %s actor=%s role=%s auth_source=%s revoked=%t\n",
			session.GetSessionId(),
			session.GetActor(),
			session.GetRole(),
			session.GetAuthSource(),
			resp.GetRevoked(),
		)
		return
	}
	cmd.Printf("revoked=%t\n", resp.GetRevoked())
}

func printOIDCProviderConfig(cmd *cobra.Command, cfg *openngfwv1.OIDCProviderConfig) {
	if cfg == nil || !cfg.GetEnabled() {
		cmd.Println("oidc_provider=disabled")
		return
	}
	secret := "not-configured"
	if cfg.GetClientSecretFileConfigured() || strings.TrimSpace(cfg.GetClientSecretFile()) != "" {
		secret = "configured"
	}
	cmd.Printf("oidc_provider=enabled\tissuer=%s\tclient_id=%s\tdefault_role=%s\trole_claim=%s\tsecret_file=%s\n",
		cfg.GetIssuer(),
		cfg.GetClientId(),
		cfg.GetDefaultRole(),
		cfg.GetRoleClaim(),
		secret,
	)
	cmd.Printf("redirect_url=%s\n", cfg.GetRedirectUrl())
	if len(cfg.GetScopes()) > 0 {
		cmd.Printf("scopes=%s\n", strings.Join(cfg.GetScopes(), ","))
	}
	if len(cfg.GetTrustedProxyCidrs()) > 0 {
		cmd.Printf("trusted_proxy_cidrs=%s\n", strings.Join(cfg.GetTrustedProxyCidrs(), ","))
	}
	if cfg.GetSessionTtlSeconds() > 0 {
		cmd.Printf("session_ttl_seconds=%d\n", cfg.GetSessionTtlSeconds())
	}
	if cfg.GetMaxSessions() > 0 {
		cmd.Printf("max_sessions=%d\n", cfg.GetMaxSessions())
	}
}

func printOIDCProviderValidation(cmd *cobra.Command, resp *openngfwv1.ValidateOIDCProviderConfigResponse) {
	if resp == nil {
		cmd.Println("OIDC provider validation unavailable")
		return
	}
	cmd.Printf("state=%s\t%s\n", resp.GetState(), resp.GetDetail())
	printOIDCProviderConfig(cmd, resp.GetNormalizedConfig())
	for _, blocker := range resp.GetBlockers() {
		cmd.Printf("blocker: %s\n", blocker)
	}
	for _, warning := range resp.GetWarnings() {
		cmd.Printf("warning: %s\n", warning)
	}
}

func printSAMLProviderConfig(cmd *cobra.Command, cfg *openngfwv1.SAMLProviderConfig) {
	if cfg == nil || !cfg.GetEnabled() {
		cmd.Println("saml_provider=disabled")
		return
	}
	fingerprint := "not-configured"
	if cfg.GetCertificateFingerprintConfigured() || strings.TrimSpace(cfg.GetCertificateFingerprint()) != "" {
		fingerprint = "configured"
	}
	cmd.Printf("saml_provider=enabled\tmetadata_url=%s\tidp_entity_id=%s\tdefault_role=%s\trole_attribute=%s\tcertificate_fingerprint=%s\n",
		cfg.GetMetadataUrl(),
		cfg.GetIdpEntityId(),
		cfg.GetDefaultRole(),
		cfg.GetRoleAttribute(),
		fingerprint,
	)
	cmd.Printf("sso_url=%s\n", cfg.GetSsoUrl())
	cmd.Printf("sp_entity_id=%s\n", cfg.GetSpEntityId())
	cmd.Printf("acs_url=%s\n", cfg.GetAcsUrl())
}

func printSAMLProviderValidation(cmd *cobra.Command, resp *openngfwv1.ValidateSAMLProviderConfigResponse) {
	if resp == nil {
		cmd.Println("SAML provider validation unavailable")
		return
	}
	cmd.Printf("state=%s\t%s\n", resp.GetState(), resp.GetDetail())
	printSAMLProviderConfig(cmd, resp.GetNormalizedConfig())
	for _, blocker := range resp.GetBlockers() {
		cmd.Printf("blocker: %s\n", blocker)
	}
	for _, warning := range resp.GetWarnings() {
		cmd.Printf("warning: %s\n", warning)
	}
}

func printLocalUserMutation(cmd *cobra.Command, user *openngfwv1.AccessAdministrationLocalUser, detail, token string) {
	if detail != "" {
		cmd.Println(detail)
	}
	if user != nil {
		state := "enabled"
		if !user.GetEnabled() {
			state = "disabled"
		}
		cmd.Printf("user: %s role=%s state=%s\n", user.GetName(), user.GetRole(), state)
	}
	if token != "" {
		cmd.Println("one-time-token:")
		cmd.Println(token)
		cmd.Println("Store this token now; it is not returned by inventory or audit APIs.")
	}
}

func printJSON(cmd *cobra.Command, msg proto.Message) error {
	b, err := protojson.MarshalOptions{UseProtoNames: true, Indent: "  "}.Marshal(msg)
	if err != nil {
		return err
	}
	cmd.Println(string(b))
	return nil
}
