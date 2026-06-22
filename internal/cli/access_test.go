package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestAccessCommandRegistered(t *testing.T) {
	root := NewRootCommand()
	cmd, _, err := root.Find([]string{"access", "users", "list"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd == nil || cmd.Name() != "list" {
		t.Fatalf("access users list command = %v", cmd)
	}
	cmd, _, err = root.Find([]string{"access", "sessions", "revoke", "oidc-session-sha256:abc"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd == nil || cmd.Name() != "revoke" {
		t.Fatalf("access sessions revoke command = %v", cmd)
	}
	cmd, _, err = root.Find([]string{"access", "oidc", "provider", "set"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd == nil || cmd.Name() != "set" {
		t.Fatalf("access oidc set command = %v", cmd)
	}
	cmd, _, err = root.Find([]string{"access", "saml", "provider", "set"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd == nil || cmd.Name() != "set" {
		t.Fatalf("access saml set command = %v", cmd)
	}
}

func TestPrintAccessUsersShowsStateWithoutSecrets(t *testing.T) {
	cmd := testOutputCommand()
	printAccessUsers(cmd, []*openngfwv1.AccessAdministrationLocalUser{
		{Name: "alice", Role: "admin", Enabled: true, Editable: true, TokenMaterial: "prehashed-token-redacted"},
		{Name: "bob", Role: "viewer", Enabled: false, Editable: true, TokenMaterial: "prehashed-token-redacted"},
	})
	out := cmd.OutOrStdout().(*bytes.Buffer).String()
	for _, want := range []string{
		"alice\trole=admin\tstate=enabled\teditable\tprehashed-token-redacted",
		"bob\trole=viewer\tstate=disabled\teditable\tprehashed-token-redacted",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "token_hash") || strings.Contains(out, "sha256:") {
		t.Fatalf("output leaked token hash material:\n%s", out)
	}
}

func TestPrintLocalUserMutationShowsOneTimeTokenOnlyWhenPresent(t *testing.T) {
	cmd := testOutputCommand()
	printLocalUserMutation(cmd, &openngfwv1.AccessAdministrationLocalUser{Name: "alice", Role: "operator", Enabled: true}, "created", "phr_token")
	out := cmd.OutOrStdout().(*bytes.Buffer).String()
	for _, want := range []string{"created", "user: alice role=operator state=enabled", "one-time-token:", "phr_token"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}

	cmd = testOutputCommand()
	printLocalUserMutation(cmd, &openngfwv1.AccessAdministrationLocalUser{Name: "alice", Role: "viewer", Enabled: false}, "disabled", "")
	out = cmd.OutOrStdout().(*bytes.Buffer).String()
	if strings.Contains(out, "one-time-token") {
		t.Fatalf("disable output should not include token section:\n%s", out)
	}
}

func TestRunAccessSessionsListShowsRedactedSessionInventory(t *testing.T) {
	cmd := testOutputCommand()
	client := &fakeAccessAdministrationClient{
		getResp: &openngfwv1.GetAccessAdministrationResponse{
			Sessions: &openngfwv1.AccessAdministrationSessions{
				OidcActiveSessions:         1,
				OidcMaxSessions:            20,
				SessionRevocationAvailable: true,
				Detail:                     "Admins can revoke browser SSO sessions.",
				ActiveSessions: []*openngfwv1.AccessAdministrationSession{
					{
						SessionId:          "oidc-session-sha256:abcdef",
						Actor:              "alice@example.com",
						Role:               "admin",
						AuthSource:         "oidc-session",
						ExpiresAt:          "2026-06-18T12:00:00Z",
						SecondsUntilExpiry: 3600,
					},
				},
			},
		},
	}
	if err := runAccessSessionsList(context.Background(), cmd, client, false); err != nil {
		t.Fatalf("runAccessSessionsList returned error: %v", err)
	}
	out := cmd.OutOrStdout().(*bytes.Buffer).String()
	for _, want := range []string{
		"browser_sso_sessions=1/20\trevocation=available",
		"Admins can revoke browser SSO sessions.",
		"oidc-session-sha256:abcdef\tactor=alice@example.com\trole=admin\tauth_source=oidc-session\texpires=2026-06-18T12:00:00Z\tttl=3600s",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(strings.ToLower(out), "csrf") || strings.Contains(strings.ToLower(out), "cookie") || strings.Contains(strings.ToLower(out), "bearer") {
		t.Fatalf("output leaked browser secret wording:\n%s", out)
	}
}

func TestRunAccessSessionRevokeRequiresAckAndBuildsRequest(t *testing.T) {
	cmd := testOutputCommand()
	client := &fakeAccessAdministrationClient{}
	err := runAccessSessionRevoke(context.Background(), cmd, client, "oidc-session-sha256:abc", false, false)
	if err == nil || !strings.Contains(err.Error(), "--ack-revoke-session") {
		t.Fatalf("runAccessSessionRevoke without ack error = %v, want ack error", err)
	}
	if client.revokeReq != nil {
		t.Fatalf("revoke request sent without acknowledgement: %#v", client.revokeReq)
	}

	cmd = testOutputCommand()
	client = &fakeAccessAdministrationClient{
		revokeResp: &openngfwv1.RevokeAccessSessionResponse{
			Revoked: true,
			Detail:  "OIDC session for alice@example.com revoked.",
			Session: &openngfwv1.AccessAdministrationSession{
				SessionId:  "oidc-session-sha256:abc",
				Actor:      "alice@example.com",
				Role:       "operator",
				AuthSource: "oidc-session",
			},
		},
	}
	if err := runAccessSessionRevoke(context.Background(), cmd, client, "oidc-session-sha256:abc", true, false); err != nil {
		t.Fatalf("runAccessSessionRevoke returned error: %v", err)
	}
	if client.revokeReq == nil || client.revokeReq.GetSessionId() != "oidc-session-sha256:abc" || !client.revokeReq.GetAckRevokeSession() {
		t.Fatalf("revoke request = %#v, want session id and ack", client.revokeReq)
	}
	out := cmd.OutOrStdout().(*bytes.Buffer).String()
	if !strings.Contains(out, "OIDC session for alice@example.com revoked.") ||
		!strings.Contains(out, "session: oidc-session-sha256:abc actor=alice@example.com role=operator auth_source=oidc-session revoked=true") {
		t.Fatalf("unexpected revoke output:\n%s", out)
	}
}

func TestRunAccessOIDCSetRequiresAckAndRedactsOutput(t *testing.T) {
	cmd := testOutputCommand()
	client := &fakeAccessAdministrationClient{}
	opts := accessOIDCProviderOptions{
		issuer:            "https://idp.example.com/",
		clientID:          "openngfw-web",
		clientSecretFile:  "/etc/openngfw/oidc-client-secret",
		redirectURL:       "https://fw.example.com/v1/auth/oidc/callback",
		roleClaim:         "groups",
		defaultRole:       "viewer",
		scopes:            "openid,profile,email,openid",
		trustedProxyCIDRs: "10.0.0.0/8, 192.0.2.0/24",
	}
	err := runAccessOIDCSet(context.Background(), cmd, client, opts, "configure provider", false, false)
	if err == nil || !strings.Contains(err.Error(), "--ack-oidc-change") {
		t.Fatalf("runAccessOIDCSet without ack error = %v, want ack error", err)
	}
	if client.setOIDCReq != nil {
		t.Fatalf("set request sent without acknowledgement: %#v", client.setOIDCReq)
	}

	cmd = testOutputCommand()
	client = &fakeAccessAdministrationClient{
		setOIDCResp: &openngfwv1.SetOIDCProviderConfigResponse{
			Detail: "OIDC browser SSO provider configured.",
			Config: &openngfwv1.OIDCProviderConfig{
				Enabled:                    true,
				Issuer:                     "https://idp.example.com",
				ClientId:                   "openngfw-web",
				RedirectUrl:                "https://fw.example.com/v1/auth/oidc/callback",
				RoleClaim:                  "groups",
				DefaultRole:                "viewer",
				Scopes:                     []string{"openid", "profile", "email"},
				TrustedProxyCidrs:          []string{"10.0.0.0/8"},
				ClientSecretFileConfigured: true,
			},
			RevokedOidcSessions: 2,
		},
	}
	if err := runAccessOIDCSet(context.Background(), cmd, client, opts, "configure provider", true, false); err != nil {
		t.Fatalf("runAccessOIDCSet returned error: %v", err)
	}
	if client.setOIDCReq == nil || !client.setOIDCReq.GetAckOidcChange() || client.setOIDCReq.GetComment() != "configure provider" {
		t.Fatalf("set request = %#v, want ack and comment", client.setOIDCReq)
	}
	cfg := client.setOIDCReq.GetConfig()
	if cfg.GetClientSecretFile() != "/etc/openngfw/oidc-client-secret" || len(cfg.GetScopes()) != 3 || len(cfg.GetTrustedProxyCidrs()) != 2 {
		t.Fatalf("set config = %#v, want secret path in request and normalized lists", cfg)
	}
	out := cmd.OutOrStdout().(*bytes.Buffer).String()
	for _, want := range []string{
		"OIDC browser SSO provider configured.",
		"oidc_provider=enabled",
		"issuer=https://idp.example.com",
		"secret_file=configured",
		"revoked_oidc_sessions=2",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "/etc/openngfw") || strings.Contains(strings.ToLower(out), "client-secret") {
		t.Fatalf("output leaked server-local secret path:\n%s", out)
	}
}

func TestRunAccessOIDCShowValidateAndDisable(t *testing.T) {
	cmd := testOutputCommand()
	client := &fakeAccessAdministrationClient{
		getOIDCResp: &openngfwv1.GetOIDCProviderConfigResponse{
			Detail: "OIDC provider configuration returned.",
			Config: &openngfwv1.OIDCProviderConfig{Enabled: false},
		},
	}
	if err := runAccessOIDCShow(context.Background(), cmd, client, false); err != nil {
		t.Fatalf("runAccessOIDCShow returned error: %v", err)
	}
	if out := cmd.OutOrStdout().(*bytes.Buffer).String(); !strings.Contains(out, "oidc_provider=disabled") {
		t.Fatalf("show output = %q, want disabled provider", out)
	}

	cmd = testOutputCommand()
	client = &fakeAccessAdministrationClient{
		validateOIDCResp: &openngfwv1.ValidateOIDCProviderConfigResponse{
			State:  "blocked",
			Detail: "OIDC provider configuration has blockers before activation.",
			NormalizedConfig: &openngfwv1.OIDCProviderConfig{
				Enabled:     true,
				Issuer:      "https://idp.example.com",
				ClientId:    "openngfw-web",
				RedirectUrl: "https://fw.example.com/v1/auth/oidc/callback",
				RoleClaim:   "role",
				DefaultRole: "viewer",
			},
			Blockers: []string{"Issuer URL is required."},
		},
	}
	if err := runAccessOIDCValidate(context.Background(), cmd, client, accessOIDCProviderOptions{}, false); err != nil {
		t.Fatalf("runAccessOIDCValidate returned error: %v", err)
	}
	if client.validateOIDCReq == nil {
		t.Fatalf("validate request not captured")
	}
	if out := cmd.OutOrStdout().(*bytes.Buffer).String(); !strings.Contains(out, "state=blocked") || !strings.Contains(out, "blocker: Issuer URL is required.") {
		t.Fatalf("validate output missing state/blocker:\n%s", out)
	}

	cmd = testOutputCommand()
	client = &fakeAccessAdministrationClient{}
	err := runAccessOIDCDisable(context.Background(), cmd, client, "disable provider", false, false)
	if err == nil || !strings.Contains(err.Error(), "--ack-disable-oidc") {
		t.Fatalf("runAccessOIDCDisable without ack error = %v, want ack error", err)
	}
	client = &fakeAccessAdministrationClient{
		disableOIDCResp: &openngfwv1.DisableOIDCProviderResponse{
			Disabled:            true,
			Detail:              "OIDC browser SSO provider disabled.",
			RevokedOidcSessions: 3,
		},
	}
	cmd = testOutputCommand()
	if err := runAccessOIDCDisable(context.Background(), cmd, client, "disable provider", true, false); err != nil {
		t.Fatalf("runAccessOIDCDisable returned error: %v", err)
	}
	if client.disableOIDCReq == nil || !client.disableOIDCReq.GetAckDisableOidc() || client.disableOIDCReq.GetComment() != "disable provider" {
		t.Fatalf("disable request = %#v, want ack and comment", client.disableOIDCReq)
	}
	if out := cmd.OutOrStdout().(*bytes.Buffer).String(); !strings.Contains(out, "disabled=true") || !strings.Contains(out, "revoked_oidc_sessions=3") {
		t.Fatalf("disable output missing state:\n%s", out)
	}
}

func TestRunAccessSAMLSetRequiresAckAndRedactsOutput(t *testing.T) {
	cmd := testOutputCommand()
	client := &fakeAccessAdministrationClient{}
	opts := accessSAMLProviderOptions{
		metadataURL:            "https://idp.example.com/metadata",
		idpEntityID:            "https://idp.example.com/saml",
		ssoURL:                 "https://idp.example.com/sso",
		spEntityID:             "https://fw.example.com/ui",
		acsURL:                 "https://fw.example.com/v1/auth/saml/acs",
		roleAttribute:          "groups",
		defaultRole:            "viewer",
		certificateFingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	err := runAccessSAMLSet(context.Background(), cmd, client, opts, "configure saml", false, false)
	if err == nil || !strings.Contains(err.Error(), "--ack-saml-change") {
		t.Fatalf("runAccessSAMLSet without ack error = %v, want ack error", err)
	}
	if client.setSAMLReq != nil {
		t.Fatalf("set request sent without acknowledgement: %#v", client.setSAMLReq)
	}

	cmd = testOutputCommand()
	client = &fakeAccessAdministrationClient{
		setSAMLResp: &openngfwv1.SetSAMLProviderConfigResponse{
			Detail: "SAML browser SSO provider configuration saved.",
			Config: &openngfwv1.SAMLProviderConfig{
				Enabled:                          true,
				MetadataUrl:                      "https://idp.example.com/metadata",
				IdpEntityId:                      "https://idp.example.com/saml",
				SsoUrl:                           "https://idp.example.com/sso",
				SpEntityId:                       "https://fw.example.com/ui",
				AcsUrl:                           "https://fw.example.com/v1/auth/saml/acs",
				RoleAttribute:                    "groups",
				DefaultRole:                      "viewer",
				CertificateFingerprintConfigured: true,
			},
		},
	}
	if err := runAccessSAMLSet(context.Background(), cmd, client, opts, "configure saml", true, false); err != nil {
		t.Fatalf("runAccessSAMLSet returned error: %v", err)
	}
	if client.setSAMLReq == nil || !client.setSAMLReq.GetAckSamlChange() || client.setSAMLReq.GetComment() != "configure saml" {
		t.Fatalf("set request = %#v, want ack and comment", client.setSAMLReq)
	}
	out := cmd.OutOrStdout().(*bytes.Buffer).String()
	for _, want := range []string{
		"SAML browser SSO provider configuration saved.",
		"saml_provider=enabled",
		"metadata_url=https://idp.example.com/metadata",
		"certificate_fingerprint=configured",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, opts.certificateFingerprint) {
		t.Fatalf("output leaked certificate fingerprint:\n%s", out)
	}
}

func testOutputCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(&bytes.Buffer{})
	return cmd
}

type fakeAccessAdministrationClient struct {
	getResp          *openngfwv1.GetAccessAdministrationResponse
	getErr           error
	getOIDCResp      *openngfwv1.GetOIDCProviderConfigResponse
	getOIDCErr       error
	validateOIDCReq  *openngfwv1.ValidateOIDCProviderConfigRequest
	validateOIDCResp *openngfwv1.ValidateOIDCProviderConfigResponse
	validateOIDCErr  error
	setOIDCReq       *openngfwv1.SetOIDCProviderConfigRequest
	setOIDCResp      *openngfwv1.SetOIDCProviderConfigResponse
	setOIDCErr       error
	disableOIDCReq   *openngfwv1.DisableOIDCProviderRequest
	disableOIDCResp  *openngfwv1.DisableOIDCProviderResponse
	disableOIDCErr   error
	getSAMLResp      *openngfwv1.GetSAMLProviderConfigResponse
	getSAMLErr       error
	validateSAMLReq  *openngfwv1.ValidateSAMLProviderConfigRequest
	validateSAMLResp *openngfwv1.ValidateSAMLProviderConfigResponse
	validateSAMLErr  error
	setSAMLReq       *openngfwv1.SetSAMLProviderConfigRequest
	setSAMLResp      *openngfwv1.SetSAMLProviderConfigResponse
	setSAMLErr       error
	disableSAMLReq   *openngfwv1.DisableSAMLProviderRequest
	disableSAMLResp  *openngfwv1.DisableSAMLProviderResponse
	disableSAMLErr   error
	revokeReq        *openngfwv1.RevokeAccessSessionRequest
	revokeResp       *openngfwv1.RevokeAccessSessionResponse
	revokeErr        error
}

func (f *fakeAccessAdministrationClient) GetAccessAdministration(context.Context, *openngfwv1.GetAccessAdministrationRequest, ...grpc.CallOption) (*openngfwv1.GetAccessAdministrationResponse, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.getResp != nil {
		return f.getResp, nil
	}
	return &openngfwv1.GetAccessAdministrationResponse{}, nil
}

func (f *fakeAccessAdministrationClient) GetOIDCProviderConfig(context.Context, *openngfwv1.GetOIDCProviderConfigRequest, ...grpc.CallOption) (*openngfwv1.GetOIDCProviderConfigResponse, error) {
	if f.getOIDCErr != nil {
		return nil, f.getOIDCErr
	}
	if f.getOIDCResp != nil {
		return f.getOIDCResp, nil
	}
	return &openngfwv1.GetOIDCProviderConfigResponse{}, nil
}

func (f *fakeAccessAdministrationClient) ValidateOIDCProviderConfig(_ context.Context, req *openngfwv1.ValidateOIDCProviderConfigRequest, _ ...grpc.CallOption) (*openngfwv1.ValidateOIDCProviderConfigResponse, error) {
	f.validateOIDCReq = req
	if f.validateOIDCErr != nil {
		return nil, f.validateOIDCErr
	}
	if f.validateOIDCResp != nil {
		return f.validateOIDCResp, nil
	}
	return &openngfwv1.ValidateOIDCProviderConfigResponse{}, nil
}

func (f *fakeAccessAdministrationClient) SetOIDCProviderConfig(_ context.Context, req *openngfwv1.SetOIDCProviderConfigRequest, _ ...grpc.CallOption) (*openngfwv1.SetOIDCProviderConfigResponse, error) {
	f.setOIDCReq = req
	if f.setOIDCErr != nil {
		return nil, f.setOIDCErr
	}
	if f.setOIDCResp != nil {
		return f.setOIDCResp, nil
	}
	return &openngfwv1.SetOIDCProviderConfigResponse{}, nil
}

func (f *fakeAccessAdministrationClient) DisableOIDCProvider(_ context.Context, req *openngfwv1.DisableOIDCProviderRequest, _ ...grpc.CallOption) (*openngfwv1.DisableOIDCProviderResponse, error) {
	f.disableOIDCReq = req
	if f.disableOIDCErr != nil {
		return nil, f.disableOIDCErr
	}
	if f.disableOIDCResp != nil {
		return f.disableOIDCResp, nil
	}
	return &openngfwv1.DisableOIDCProviderResponse{}, nil
}

func (f *fakeAccessAdministrationClient) GetSAMLProviderConfig(context.Context, *openngfwv1.GetSAMLProviderConfigRequest, ...grpc.CallOption) (*openngfwv1.GetSAMLProviderConfigResponse, error) {
	if f.getSAMLErr != nil {
		return nil, f.getSAMLErr
	}
	if f.getSAMLResp != nil {
		return f.getSAMLResp, nil
	}
	return &openngfwv1.GetSAMLProviderConfigResponse{}, nil
}

func (f *fakeAccessAdministrationClient) ValidateSAMLProviderConfig(_ context.Context, req *openngfwv1.ValidateSAMLProviderConfigRequest, _ ...grpc.CallOption) (*openngfwv1.ValidateSAMLProviderConfigResponse, error) {
	f.validateSAMLReq = req
	if f.validateSAMLErr != nil {
		return nil, f.validateSAMLErr
	}
	if f.validateSAMLResp != nil {
		return f.validateSAMLResp, nil
	}
	return &openngfwv1.ValidateSAMLProviderConfigResponse{}, nil
}

func (f *fakeAccessAdministrationClient) SetSAMLProviderConfig(_ context.Context, req *openngfwv1.SetSAMLProviderConfigRequest, _ ...grpc.CallOption) (*openngfwv1.SetSAMLProviderConfigResponse, error) {
	f.setSAMLReq = req
	if f.setSAMLErr != nil {
		return nil, f.setSAMLErr
	}
	if f.setSAMLResp != nil {
		return f.setSAMLResp, nil
	}
	return &openngfwv1.SetSAMLProviderConfigResponse{}, nil
}

func (f *fakeAccessAdministrationClient) DisableSAMLProvider(_ context.Context, req *openngfwv1.DisableSAMLProviderRequest, _ ...grpc.CallOption) (*openngfwv1.DisableSAMLProviderResponse, error) {
	f.disableSAMLReq = req
	if f.disableSAMLErr != nil {
		return nil, f.disableSAMLErr
	}
	if f.disableSAMLResp != nil {
		return f.disableSAMLResp, nil
	}
	return &openngfwv1.DisableSAMLProviderResponse{}, nil
}

func (f *fakeAccessAdministrationClient) RevokeAccessSession(_ context.Context, req *openngfwv1.RevokeAccessSessionRequest, _ ...grpc.CallOption) (*openngfwv1.RevokeAccessSessionResponse, error) {
	f.revokeReq = req
	if f.revokeErr != nil {
		return nil, f.revokeErr
	}
	if f.revokeResp != nil {
		return f.revokeResp, nil
	}
	return &openngfwv1.RevokeAccessSessionResponse{}, nil
}
