// Package apiserver hosts the gRPC implementation of the canonical
// OpenNGFW API. The API is the contract: every client (CLI, UI, GitOps)
// goes through it.
package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/authz"
	"github.com/detailtech/oss-ngfw/internal/contentpkg"
	"github.com/detailtech/oss-ngfw/internal/engines"
	policyvalidate "github.com/detailtech/oss-ngfw/internal/policy"
	"github.com/detailtech/oss-ngfw/internal/releaseacceptance"
	"github.com/detailtech/oss-ngfw/internal/securefile"
	"github.com/detailtech/oss-ngfw/internal/store"
	"github.com/detailtech/oss-ngfw/internal/tuning"
	"github.com/detailtech/oss-ngfw/internal/version"
)

var (
	flowtableDevicesRE = regexp.MustCompile(`(?s)flowtable\s+fastpath\s*\{.*?devices\s*=\s*\{([^}]*)\}`)
	counterRE          = regexp.MustCompile(`counter\s+packets\s+([0-9]+)\s+bytes\s+([0-9]+)`)
	commentRE          = regexp.MustCompile(`comment\s+"((?:[^"\\]|\\.)*)"`)
	releaseLocalPathRE = regexp.MustCompile(`(?i)(^|[\s"'({=,;])/(?:var/lib|var/log(?:/openngfw)?|etc/(?:openngfw|phragma)|tmp|private/tmp|var/folders|private/var/folders|home/[^'"\s,;}]+|Users/[^'"\s,;}]+|opt/[^'"\s,;}]+|data/[^'"\s,;}]+)[^'"\s,;}]*`)
	releaseSecretRE    = regexp.MustCompile(`(?i)(^|[?&\s"',;])(-{0,2}(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|passwd|secret|client[_-]?secret|api[_-]?key|api[_-]?access[_-]?key|access[_-]?key|cookie)[=:])[^&\s"',;]+`)
	releaseBearerRE    = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}`)
)

const defaultSysfsRoot = "/sys"
const defaultProcRoot = "/proc"
const defaultTelemetryExportRoot = "/var/log/openngfw/exports"
const conntrackWarningPercent = 75.0
const conntrackDegradedPercent = 90.0

var kernelTuningRequirements = tuning.Requirements

// SystemService implements openngfw.v1.SystemService.
type SystemService struct {
	openngfwv1.UnimplementedSystemServiceServer
	openngfwv1.UnimplementedComplianceServiceServer
	Store  *store.Store
	Policy *PolicyServer
	Alerts *AlertServer
	Flows  *FlowServer
	Intel  *IntelServer
	Auth   *authz.Authenticator
	OIDC   *authz.OIDCAuthenticator
	SAML   *authz.SAMLAuthenticator
	Status SystemStatusConfig

	LocalUsersFile     string
	AccessConfigFile   string
	OIDCProviderConfig authz.OIDCProviderConfig
	SAMLProviderConfig authz.SAMLProviderConfig
	accessMu           sync.Mutex
	haReplicationMu    sync.Mutex
	haReplication      highAvailabilityReplicationState
}

// GetVersion reports the running build's version metadata.
func (s *SystemService) GetVersion(_ context.Context, _ *openngfwv1.GetVersionRequest) (*openngfwv1.GetVersionResponse, error) {
	return &openngfwv1.GetVersionResponse{
		Version:   version.Version,
		Commit:    version.Commit,
		BuildDate: version.BuildDate,
	}, nil
}

// GetIdentity reports the caller identity after auth/RBAC interception.
func (s *SystemService) GetIdentity(ctx context.Context, _ *openngfwv1.GetIdentityRequest) (*openngfwv1.GetIdentityResponse, error) {
	id := authz.RequestIdentity(ctx, s.Status.AuthEnabled)
	role := id.Role.String()
	authSource := id.AuthSource
	if authSource == "" {
		authSource = "unknown"
	}
	return &openngfwv1.GetIdentityResponse{
		Actor:        id.Name,
		Role:         role,
		AuthEnabled:  s.Status.AuthEnabled,
		AuthSource:   authSource,
		Capabilities: roleCapabilities(id.Role),
	}, nil
}

// CreateStepUpChallenge issues one short-lived privileged-action token for the
// authenticated actor. It is intentionally one-time and action-scoped.
func (s *SystemService) CreateStepUpChallenge(ctx context.Context, req *openngfwv1.CreateStepUpChallengeRequest) (*openngfwv1.CreateStepUpChallengeResponse, error) {
	if req == nil {
		req = &openngfwv1.CreateStepUpChallengeRequest{}
	}
	if !req.GetAckStepUp() {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "ack_step_up is required")
	}
	challenge, err := authz.CreateStepUpChallenge(ctx, req.GetAction(), req.GetComment())
	if err != nil {
		return nil, err
	}
	return &openngfwv1.CreateStepUpChallengeResponse{
		Token:      challenge.Token,
		Action:     challenge.Action,
		Actor:      challenge.Actor,
		AuthSource: challenge.AuthSource,
		IssuedAt:   challenge.IssuedAt.Format(time.RFC3339Nano),
		ExpiresAt:  challenge.ExpiresAt.Format(time.RFC3339Nano),
		Detail:     fmt.Sprintf("Step-up token issued for %s and bound to actor %s.", challenge.Action, challenge.Actor),
		Warnings: []string{
			"Functional re-confirmation token only; real MFA or IdP-backed step-up remains production hardening.",
			"Token is one-time, in-memory, action-scoped, and expires quickly.",
		},
	}, nil
}

// GetAccessAdministration reports access-control posture for admin callers,
// including editable local-user inventory and revocable browser sessions.
func (s *SystemService) GetAccessAdministration(_ context.Context, _ *openngfwv1.GetAccessAdministrationRequest) (*openngfwv1.GetAccessAdministrationResponse, error) {
	localUsers := accessAdministrationLocalUsers(s.Auth)
	oidcAuth := s.CurrentOIDC()
	oidc := oidcAuth.Inventory()
	samlAuth := s.CurrentSAML()
	sessions := combinedAccessSessionInventory(oidcAuth.SessionInventory(), samlAuth.SessionInventory())
	s.accessMu.Lock()
	saml := s.SAMLProviderConfig
	s.accessMu.Unlock()
	resp := &openngfwv1.GetAccessAdministrationResponse{
		AuthEnabled: s.Status.AuthEnabled,
		LocalUsers:  localUsers,
		Oidc:        accessAdministrationOIDCProto(oidc),
		Saml:        accessAdministrationSAMLProto(saml, samlAuth),
		Sessions:    accessAdministrationSessionsProto(sessions),
		BreakGlass:  accessAdministrationBreakGlass(s.Status.AuthEnabled, localUsers),
	}
	resp.Blockers = accessAdministrationBlockers(resp.GetAuthEnabled(), localUsers, resp.GetOidc(), resp.GetSessions())
	return resp, nil
}

// RunOIDCPreflight verifies browser SSO readiness without mutating IdP,
// user, or session state and without returning secrets.
func (s *SystemService) RunOIDCPreflight(ctx context.Context, _ *openngfwv1.RunOIDCPreflightRequest) (*openngfwv1.RunOIDCPreflightResponse, error) {
	oidcAuth := s.CurrentOIDC()
	if oidcAuth == nil {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "OIDC browser SSO is not configured")
	}
	return oidcPreflightProto(oidcAuth.Preflight(ctx), time.Now().UTC()), nil
}

// RevokeAccessSession invalidates one active browser SSO session through the
// audited admin workflow. Session IDs are non-secret hashes returned by
// GetAccessAdministration.
func (s *SystemService) RevokeAccessSession(ctx context.Context, req *openngfwv1.RevokeAccessSessionRequest) (*openngfwv1.RevokeAccessSessionResponse, error) {
	if req == nil {
		req = &openngfwv1.RevokeAccessSessionRequest{}
	}
	sessionID := strings.TrimSpace(req.GetSessionId())
	if sessionID == "" {
		msg := "session_id is required"
		s.auditAccessSessionFailure(ctx, sessionID, "validation", msg)
		return nil, grpcstatus.Error(codes.InvalidArgument, msg)
	}
	if !req.GetAckRevokeSession() {
		msg := "ack_revoke_session is required"
		s.auditAccessSessionFailure(ctx, sessionID, "acknowledgement", msg)
		return nil, grpcstatus.Error(codes.FailedPrecondition, msg)
	}
	session, provider, ok := s.findAccessSession(sessionID)
	if !ok {
		msg := "session not found"
		s.auditAccessSessionFailure(ctx, sessionID, "not-found", msg)
		return nil, grpcstatus.Error(codes.NotFound, msg)
	}
	if err := s.auditAccessSession(ctx, "access-session-revoke-intent", accessSessionAuditDetail(sessionID, session, "")); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "audit access session revoke intent: %v", err)
	}
	if !s.revokeAccessSession(sessionID, provider) {
		msg := "session not found"
		s.auditAccessSessionFailure(ctx, sessionID, "revoke", msg)
		return nil, grpcstatus.Error(codes.NotFound, msg)
	}
	if err := s.auditAccessSession(ctx, "access-session-revoke", accessSessionAuditDetail(sessionID, session, "")); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "audit access session revoke: %v", err)
	}
	return &openngfwv1.RevokeAccessSessionResponse{
		Revoked: true,
		Session: accessAdministrationSessionProto(session),
		Detail:  fmt.Sprintf("%s session for %s revoked.", provider, session.Actor),
	}, nil
}

func (s *SystemService) findAccessSession(sessionID string) (authz.OIDCSessionRecord, string, bool) {
	if oidcAuth := s.CurrentOIDC(); oidcAuth != nil {
		if session, ok := oidcAuth.SessionRecord(sessionID); ok {
			return session, "OIDC", true
		}
	}
	if samlAuth := s.CurrentSAML(); samlAuth != nil {
		if session, ok := samlAuth.SessionRecord(sessionID); ok {
			return session, "SAML", true
		}
	}
	return authz.OIDCSessionRecord{}, "", false
}

func (s *SystemService) revokeAccessSession(sessionID, provider string) bool {
	switch provider {
	case "OIDC":
		if oidcAuth := s.CurrentOIDC(); oidcAuth != nil {
			_, ok := oidcAuth.RevokeSession(sessionID)
			return ok
		}
	case "SAML":
		if samlAuth := s.CurrentSAML(); samlAuth != nil {
			_, ok := samlAuth.RevokeSession(sessionID)
			return ok
		}
	}
	return false
}

// RevokeBrowserSessionToken invalidates a browser cookie token across all
// browser SSO providers. Shared logout calls this before expiring the cookie.
func (s *SystemService) RevokeBrowserSessionToken(token string) {
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}
	if oidcAuth := s.CurrentOIDC(); oidcAuth != nil {
		oidcAuth.RevokeSession(authz.OIDCSessionIDForToken(token))
	}
	if samlAuth := s.CurrentSAML(); samlAuth != nil {
		samlAuth.RevokeSession(authz.SAMLSessionIDForToken(token))
	}
}

// CurrentOIDC returns the active browser SSO authenticator, if configured.
func (s *SystemService) CurrentOIDC() *authz.OIDCAuthenticator {
	if s == nil {
		return nil
	}
	s.accessMu.Lock()
	defer s.accessMu.Unlock()
	return s.OIDC
}

// CurrentSAML returns the active SAML browser SSO authenticator, if configured.
func (s *SystemService) CurrentSAML() *authz.SAMLAuthenticator {
	if s == nil {
		return nil
	}
	s.accessMu.Lock()
	defer s.accessMu.Unlock()
	return s.SAML
}

func (s *SystemService) setBrowserSessionLookupLocked() {
	if s.Auth == nil {
		return
	}
	var lookups []authz.SessionLookup
	if s.OIDC != nil {
		lookups = append(lookups, s.OIDC.LookupSession)
	}
	if s.SAML != nil {
		lookups = append(lookups, s.SAML.LookupSession)
	}
	s.Auth.SetSessionLookup(authz.CompositeSessionLookup(lookups...))
	s.Status.AuthEnabled = true
	s.Status.OIDCEnabled = s.OIDC != nil
}

// InstallBrowserSessionLookup refreshes the Authenticator's browser-session
// lookup after startup wiring.
func (s *SystemService) InstallBrowserSessionLookup() {
	s.accessMu.Lock()
	defer s.accessMu.Unlock()
	s.setBrowserSessionLookupLocked()
}

// GetOIDCProviderConfig returns the redacted active/persisted provider config.
func (s *SystemService) GetOIDCProviderConfig(_ context.Context, _ *openngfwv1.GetOIDCProviderConfigRequest) (*openngfwv1.GetOIDCProviderConfigResponse, error) {
	s.accessMu.Lock()
	cfg := s.OIDCProviderConfig
	if !cfg.Enabled && s.OIDC != nil {
		cfg.Enabled = true
	}
	s.accessMu.Unlock()
	return &openngfwv1.GetOIDCProviderConfigResponse{
		Config: oidcProviderConfigProto(cfg, false),
		Detail: "OIDC provider configuration returned without client secret bytes or server-local secret file path.",
	}, nil
}

// ValidateOIDCProviderConfig validates a proposed provider config without
// replacing the active runtime authenticator.
func (s *SystemService) ValidateOIDCProviderConfig(_ context.Context, req *openngfwv1.ValidateOIDCProviderConfigRequest) (*openngfwv1.ValidateOIDCProviderConfigResponse, error) {
	if req == nil {
		req = &openngfwv1.ValidateOIDCProviderConfigRequest{}
	}
	cfg := oidcProviderConfigFromProto(req.GetConfig())
	return oidcProviderValidationResponse(cfg), nil
}

// SetOIDCProviderConfig persists a node-local OIDC provider config, replaces
// the active authenticator, and revokes existing browser SSO sessions.
func (s *SystemService) SetOIDCProviderConfig(ctx context.Context, req *openngfwv1.SetOIDCProviderConfigRequest) (*openngfwv1.SetOIDCProviderConfigResponse, error) {
	if req == nil {
		req = &openngfwv1.SetOIDCProviderConfigRequest{}
	}
	if err := authz.RequireStepUp(ctx, "access-oidc-set", req.GetStepUpToken()); err != nil {
		return nil, err
	}
	comment, err := requiredAuditComment(req.GetComment(), "OIDC provider change comment")
	if err != nil {
		s.auditOIDCProviderFailure(ctx, "access-oidc-provider-set-failed", authz.OIDCProviderConfig{}, "comment", err.Error())
		return nil, err
	}
	if !req.GetAckOidcChange() {
		msg := "ack_oidc_change is required"
		s.auditOIDCProviderFailure(ctx, "access-oidc-provider-set-failed", authz.OIDCProviderConfig{}, "acknowledgement", msg)
		return nil, grpcstatus.Error(codes.FailedPrecondition, msg)
	}
	if localAdminUserCount(accessAdministrationLocalUsers(s.Auth)) == 0 {
		msg := "at least one enabled local admin break-glass credential is required before changing OIDC"
		s.auditOIDCProviderFailure(ctx, "access-oidc-provider-set-failed", authz.OIDCProviderConfig{}, "break-glass", msg)
		return nil, grpcstatus.Error(codes.FailedPrecondition, msg)
	}
	cfg := authz.NormalizeOIDCProviderConfig(oidcProviderConfigFromProto(req.GetConfig()))
	cfg.Enabled = true
	if err := authz.ValidateOIDCProviderConfig(cfg); err != nil {
		s.auditOIDCProviderFailure(ctx, "access-oidc-provider-set-failed", cfg, "validation", err.Error())
		return nil, grpcstatus.Error(codes.InvalidArgument, err.Error())
	}
	secret, err := readOIDCClientSecretFile(cfg.ClientSecretFile)
	if err != nil {
		s.auditOIDCProviderFailure(ctx, "access-oidc-provider-set-failed", cfg, "secret-file", err.Error())
		return nil, grpcstatus.Error(codes.InvalidArgument, err.Error())
	}
	discoveryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	nextOIDC, err := authz.NewOIDCAuthenticator(discoveryCtx, authz.OIDCProviderConfigToRuntime(cfg, secret, oidcProviderCookieSecure(cfg)))
	cancel()
	if err != nil {
		s.auditOIDCProviderFailure(ctx, "access-oidc-provider-set-failed", cfg, "discovery", err.Error())
		return nil, grpcstatus.Errorf(codes.FailedPrecondition, "configure OIDC provider: %v", err)
	}
	if err := s.auditOIDCProvider(ctx, "access-oidc-provider-set-intent", oidcProviderAuditDetail(cfg, comment, 0)); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "audit OIDC provider set intent: %v", err)
	}
	s.accessMu.Lock()
	oldOIDC := s.OIDC
	if err := authz.SaveOIDCProviderConfig(s.AccessConfigFile, cfg); err != nil {
		s.accessMu.Unlock()
		s.auditOIDCProviderFailure(ctx, "access-oidc-provider-set-failed", cfg, "persist", err.Error())
		return nil, grpcstatus.Errorf(codes.Internal, "persist OIDC provider config: %v", err)
	}
	s.OIDC = nextOIDC
	s.OIDCProviderConfig = cfg
	s.Status.OIDCEnabled = true
	s.Status.OIDCCookieSecure = oidcProviderCookieSecure(cfg)
	if s.Auth == nil {
		s.Auth = authz.NewAuthenticator()
	}
	s.setBrowserSessionLookupLocked()
	revoked := oldOIDC.RevokeAllSessions()
	s.accessMu.Unlock()
	if err := s.auditOIDCProvider(ctx, "access-oidc-provider-set", oidcProviderAuditDetail(cfg, comment, revoked)); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "audit OIDC provider set: %v", err)
	}
	return &openngfwv1.SetOIDCProviderConfigResponse{
		Config:              oidcProviderConfigProto(cfg, false),
		Oidc:                accessAdministrationOIDCProto(nextOIDC.Inventory()),
		Detail:              "OIDC browser SSO provider configured and runtime authenticator replaced.",
		RevokedOidcSessions: revoked,
	}, nil
}

// DisableOIDCProvider disables the runtime browser SSO provider and revokes
// existing OIDC sessions while preserving local break-glass access.
func (s *SystemService) DisableOIDCProvider(ctx context.Context, req *openngfwv1.DisableOIDCProviderRequest) (*openngfwv1.DisableOIDCProviderResponse, error) {
	if req == nil {
		req = &openngfwv1.DisableOIDCProviderRequest{}
	}
	if err := authz.RequireStepUp(ctx, "access-oidc-disable", req.GetStepUpToken()); err != nil {
		return nil, err
	}
	comment, err := requiredAuditComment(req.GetComment(), "OIDC provider disable comment")
	if err != nil {
		s.auditOIDCProviderFailure(ctx, "access-oidc-provider-disable-failed", authz.OIDCProviderConfig{}, "comment", err.Error())
		return nil, err
	}
	if !req.GetAckDisableOidc() {
		msg := "ack_disable_oidc is required"
		s.auditOIDCProviderFailure(ctx, "access-oidc-provider-disable-failed", authz.OIDCProviderConfig{}, "acknowledgement", msg)
		return nil, grpcstatus.Error(codes.FailedPrecondition, msg)
	}
	if localAdminUserCount(accessAdministrationLocalUsers(s.Auth)) == 0 {
		msg := "at least one enabled local admin break-glass credential is required before disabling OIDC"
		s.auditOIDCProviderFailure(ctx, "access-oidc-provider-disable-failed", authz.OIDCProviderConfig{}, "break-glass", msg)
		return nil, grpcstatus.Error(codes.FailedPrecondition, msg)
	}
	if err := s.auditOIDCProvider(ctx, "access-oidc-provider-disable-intent", oidcProviderAuditDetail(authz.OIDCProviderConfig{}, comment, 0)); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "audit OIDC provider disable intent: %v", err)
	}
	s.accessMu.Lock()
	disabled := authz.NormalizeOIDCProviderConfig(s.OIDCProviderConfig)
	disabled.Enabled = false
	oldOIDC := s.OIDC
	if err := authz.SaveOIDCProviderConfig(s.AccessConfigFile, disabled); err != nil {
		s.accessMu.Unlock()
		s.auditOIDCProviderFailure(ctx, "access-oidc-provider-disable-failed", disabled, "persist", err.Error())
		return nil, grpcstatus.Errorf(codes.Internal, "persist disabled OIDC provider config: %v", err)
	}
	s.OIDC = nil
	s.OIDCProviderConfig = disabled
	s.Status.OIDCEnabled = false
	s.Status.OIDCCookieSecure = false
	s.setBrowserSessionLookupLocked()
	revoked := oldOIDC.RevokeAllSessions()
	s.accessMu.Unlock()
	if err := s.auditOIDCProvider(ctx, "access-oidc-provider-disable", oidcProviderAuditDetail(disabled, comment, revoked)); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "audit OIDC provider disable: %v", err)
	}
	return &openngfwv1.DisableOIDCProviderResponse{
		Disabled:            true,
		Detail:              "OIDC browser SSO provider disabled and active OIDC sessions revoked.",
		RevokedOidcSessions: revoked,
	}, nil
}

// GetSAMLProviderConfig returns the redacted persisted SAML provider config.
func (s *SystemService) GetSAMLProviderConfig(_ context.Context, _ *openngfwv1.GetSAMLProviderConfigRequest) (*openngfwv1.GetSAMLProviderConfigResponse, error) {
	s.accessMu.Lock()
	cfg := s.SAMLProviderConfig
	s.accessMu.Unlock()
	return &openngfwv1.GetSAMLProviderConfigResponse{
		Config: samlProviderConfigProto(cfg, false),
		Detail: "SAML provider configuration returned without raw certificate fingerprint material.",
	}, nil
}

// ValidateSAMLProviderConfig validates a proposed provider config without
// activating browser login/session runtime.
func (s *SystemService) ValidateSAMLProviderConfig(_ context.Context, req *openngfwv1.ValidateSAMLProviderConfigRequest) (*openngfwv1.ValidateSAMLProviderConfigResponse, error) {
	if req == nil {
		req = &openngfwv1.ValidateSAMLProviderConfigRequest{}
	}
	cfg := samlProviderConfigFromProto(req.GetConfig())
	return samlProviderValidationResponse(cfg), nil
}

// SetSAMLProviderConfig persists node-local SAML provider posture and activates
// browser SAML login when the service has access to a local authenticator.
func (s *SystemService) SetSAMLProviderConfig(ctx context.Context, req *openngfwv1.SetSAMLProviderConfigRequest) (*openngfwv1.SetSAMLProviderConfigResponse, error) {
	if req == nil {
		req = &openngfwv1.SetSAMLProviderConfigRequest{}
	}
	if err := authz.RequireStepUp(ctx, "access-saml-set", req.GetStepUpToken()); err != nil {
		return nil, err
	}
	comment, err := requiredAuditComment(req.GetComment(), "SAML provider change comment")
	if err != nil {
		s.auditSAMLProviderFailure(ctx, "access-saml-provider-set-failed", authz.SAMLProviderConfig{}, "comment", err.Error())
		return nil, err
	}
	if !req.GetAckSamlChange() {
		msg := "ack_saml_change is required"
		s.auditSAMLProviderFailure(ctx, "access-saml-provider-set-failed", authz.SAMLProviderConfig{}, "acknowledgement", msg)
		return nil, grpcstatus.Error(codes.FailedPrecondition, msg)
	}
	if localAdminUserCount(accessAdministrationLocalUsers(s.Auth)) == 0 {
		msg := "at least one enabled local admin break-glass credential is required before changing SAML"
		s.auditSAMLProviderFailure(ctx, "access-saml-provider-set-failed", authz.SAMLProviderConfig{}, "break-glass", msg)
		return nil, grpcstatus.Error(codes.FailedPrecondition, msg)
	}
	cfg := authz.NormalizeSAMLProviderConfig(samlProviderConfigFromProto(req.GetConfig()))
	cfg.Enabled = true
	s.accessMu.Lock()
	existingSAMLConfig := s.SAMLProviderConfig
	s.accessMu.Unlock()
	if strings.TrimSpace(cfg.CertificateFingerprint) == "" && strings.TrimSpace(existingSAMLConfig.CertificateFingerprint) != "" {
		cfg.CertificateFingerprint = existingSAMLConfig.CertificateFingerprint
	}
	if err := authz.ValidateSAMLProviderConfig(cfg); err != nil {
		s.auditSAMLProviderFailure(ctx, "access-saml-provider-set-failed", cfg, "validation", err.Error())
		return nil, grpcstatus.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.auditSAMLProvider(ctx, "access-saml-provider-set-intent", samlProviderAuditDetail(cfg, comment)); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "audit SAML provider set intent: %v", err)
	}
	runtimeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	nextSAML, err := authz.NewSAMLAuthenticator(runtimeCtx, authz.SAMLProviderConfigToRuntime(cfg, samlProviderCookieSecure(cfg)))
	cancel()
	if err != nil {
		s.auditSAMLProviderFailure(ctx, "access-saml-provider-set-failed", cfg, "runtime", err.Error())
		return nil, grpcstatus.Errorf(codes.InvalidArgument, "configure SAML runtime: %v", err)
	}
	s.accessMu.Lock()
	oldSAML := s.SAML
	if err := authz.SaveSAMLProviderConfig(s.AccessConfigFile, cfg); err != nil {
		s.accessMu.Unlock()
		s.auditSAMLProviderFailure(ctx, "access-saml-provider-set-failed", cfg, "persist", err.Error())
		return nil, grpcstatus.Errorf(codes.Internal, "persist SAML provider config: %v", err)
	}
	if s.Auth == nil {
		s.Auth = authz.NewAuthenticator()
	}
	s.SAML = nextSAML
	s.SAMLProviderConfig = cfg
	s.setBrowserSessionLookupLocked()
	var revoked uint32
	if oldSAML != nil {
		revoked = oldSAML.RevokeAllSessions()
	}
	s.accessMu.Unlock()
	if err := s.auditSAMLProvider(ctx, "access-saml-provider-set", samlProviderAuditDetail(cfg, comment)); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "audit SAML provider set: %v", err)
	}
	return &openngfwv1.SetSAMLProviderConfigResponse{
		Config: samlProviderConfigProto(cfg, false),
		Saml:   accessAdministrationSAMLProto(cfg, nextSAML),
		Detail: fmt.Sprintf("SAML browser SSO provider configuration saved; login/session runtime is active and %d previous SAML session(s) were revoked.", revoked),
	}, nil
}

// DisableSAMLProvider disables persisted SAML provider posture.
func (s *SystemService) DisableSAMLProvider(ctx context.Context, req *openngfwv1.DisableSAMLProviderRequest) (*openngfwv1.DisableSAMLProviderResponse, error) {
	if req == nil {
		req = &openngfwv1.DisableSAMLProviderRequest{}
	}
	if err := authz.RequireStepUp(ctx, "access-saml-disable", req.GetStepUpToken()); err != nil {
		return nil, err
	}
	comment, err := requiredAuditComment(req.GetComment(), "SAML provider disable comment")
	if err != nil {
		s.auditSAMLProviderFailure(ctx, "access-saml-provider-disable-failed", authz.SAMLProviderConfig{}, "comment", err.Error())
		return nil, err
	}
	if !req.GetAckDisableSaml() {
		msg := "ack_disable_saml is required"
		s.auditSAMLProviderFailure(ctx, "access-saml-provider-disable-failed", authz.SAMLProviderConfig{}, "acknowledgement", msg)
		return nil, grpcstatus.Error(codes.FailedPrecondition, msg)
	}
	if localAdminUserCount(accessAdministrationLocalUsers(s.Auth)) == 0 {
		msg := "at least one enabled local admin break-glass credential is required before disabling SAML"
		s.auditSAMLProviderFailure(ctx, "access-saml-provider-disable-failed", authz.SAMLProviderConfig{}, "break-glass", msg)
		return nil, grpcstatus.Error(codes.FailedPrecondition, msg)
	}
	if err := s.auditSAMLProvider(ctx, "access-saml-provider-disable-intent", samlProviderAuditDetail(authz.SAMLProviderConfig{}, comment)); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "audit SAML provider disable intent: %v", err)
	}
	s.accessMu.Lock()
	disabled := authz.NormalizeSAMLProviderConfig(s.SAMLProviderConfig)
	disabled.Enabled = false
	oldSAML := s.SAML
	if err := authz.SaveSAMLProviderConfig(s.AccessConfigFile, disabled); err != nil {
		s.accessMu.Unlock()
		s.auditSAMLProviderFailure(ctx, "access-saml-provider-disable-failed", disabled, "persist", err.Error())
		return nil, grpcstatus.Errorf(codes.Internal, "persist disabled SAML provider config: %v", err)
	}
	s.SAML = nil
	s.SAMLProviderConfig = disabled
	s.setBrowserSessionLookupLocked()
	var revoked uint32
	if oldSAML != nil {
		revoked = oldSAML.RevokeAllSessions()
	}
	s.accessMu.Unlock()
	if err := s.auditSAMLProvider(ctx, "access-saml-provider-disable", samlProviderAuditDetail(disabled, comment)); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "audit SAML provider disable: %v", err)
	}
	return &openngfwv1.DisableSAMLProviderResponse{
		Disabled: true,
		Detail:   fmt.Sprintf("SAML browser SSO provider configuration disabled and %d active SAML session(s) revoked.", revoked),
	}, nil
}

func accessAdministrationLocalUsers(auth *authz.Authenticator) []*openngfwv1.AccessAdministrationLocalUser {
	if auth == nil {
		return nil
	}
	inventory := auth.LocalUserInventory()
	out := make([]*openngfwv1.AccessAdministrationLocalUser, 0, len(inventory))
	for _, user := range inventory {
		out = append(out, &openngfwv1.AccessAdministrationLocalUser{
			Name:          user.Name,
			Role:          user.Role,
			AuthSource:    user.AuthSource,
			TokenMaterial: user.TokenMaterial,
			Editable:      user.Editable,
			AuditHash:     user.AuditHash,
			Enabled:       user.Enabled,
		})
	}
	return out
}

// CreateLocalUser creates an enabled local users-file entry and returns the
// generated bearer token once.
func (s *SystemService) CreateLocalUser(ctx context.Context, req *openngfwv1.CreateLocalUserRequest) (*openngfwv1.CreateLocalUserResponse, error) {
	if req == nil {
		req = &openngfwv1.CreateLocalUserRequest{}
	}
	if err := authz.RequireStepUp(ctx, "access-local-user-create", req.GetStepUpToken()); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.GetName())
	role := strings.TrimSpace(req.GetRole())
	comment, err := requiredAuditComment(req.GetComment(), "local user create comment")
	if err != nil {
		s.auditAccessLocalUserFailure(ctx, "access-local-user-create-failed", name, role, "comment", err.Error())
		return nil, err
	}
	if !req.GetAckLocalUserChange() {
		msg := "ack_local_user_change is required"
		s.auditAccessLocalUserFailure(ctx, "access-local-user-create-failed", name, role, "acknowledgement", msg)
		return nil, grpcstatus.Error(codes.FailedPrecondition, msg)
	}
	result, err := s.mutateLocalUser(ctx, "access-local-user-create", name, role, comment, func() (*authz.Authenticator, authz.LocalUserInventory, string, error) {
		return authz.CreateLocalUser(s.LocalUsersFile, name, role)
	})
	if err != nil {
		return nil, err
	}
	return &openngfwv1.CreateLocalUserResponse{User: result.user, OneTimeToken: result.oneTimeToken, Detail: result.detail}, nil
}

// UpdateLocalUser changes local user metadata that does not include token
// material.
func (s *SystemService) UpdateLocalUser(ctx context.Context, req *openngfwv1.UpdateLocalUserRequest) (*openngfwv1.UpdateLocalUserResponse, error) {
	if req == nil {
		req = &openngfwv1.UpdateLocalUserRequest{}
	}
	if err := authz.RequireStepUp(ctx, "access-local-user-update", req.GetStepUpToken()); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.GetName())
	role := strings.TrimSpace(req.GetRole())
	comment, err := requiredAuditComment(req.GetComment(), "local user update comment")
	if err != nil {
		s.auditAccessLocalUserFailure(ctx, "access-local-user-update-failed", name, role, "comment", err.Error())
		return nil, err
	}
	if !req.GetAckLocalUserChange() {
		msg := "ack_local_user_change is required"
		s.auditAccessLocalUserFailure(ctx, "access-local-user-update-failed", name, role, "acknowledgement", msg)
		return nil, grpcstatus.Error(codes.FailedPrecondition, msg)
	}
	result, err := s.mutateLocalUser(ctx, "access-local-user-update", name, role, comment, func() (*authz.Authenticator, authz.LocalUserInventory, string, error) {
		auth, user, err := authz.UpdateLocalUserRole(s.LocalUsersFile, name, role)
		return auth, user, "", err
	})
	if err != nil {
		return nil, err
	}
	return &openngfwv1.UpdateLocalUserResponse{User: result.user, Detail: result.detail}, nil
}

// RotateLocalUserToken replaces one local user's token_hash and returns the
// generated token once.
func (s *SystemService) RotateLocalUserToken(ctx context.Context, req *openngfwv1.RotateLocalUserTokenRequest) (*openngfwv1.RotateLocalUserTokenResponse, error) {
	if req == nil {
		req = &openngfwv1.RotateLocalUserTokenRequest{}
	}
	if err := authz.RequireStepUp(ctx, "access-local-user-rotate-token", req.GetStepUpToken()); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.GetName())
	comment, err := requiredAuditComment(req.GetComment(), "local user token rotation comment")
	if err != nil {
		s.auditAccessLocalUserFailure(ctx, "access-local-user-rotate-token-failed", name, "", "comment", err.Error())
		return nil, err
	}
	if !req.GetAckRotateToken() {
		msg := "ack_rotate_token is required"
		s.auditAccessLocalUserFailure(ctx, "access-local-user-rotate-token-failed", name, "", "acknowledgement", msg)
		return nil, grpcstatus.Error(codes.FailedPrecondition, msg)
	}
	result, err := s.mutateLocalUser(ctx, "access-local-user-rotate-token", name, "", comment, func() (*authz.Authenticator, authz.LocalUserInventory, string, error) {
		return authz.RotateLocalUserToken(s.LocalUsersFile, name)
	})
	if err != nil {
		return nil, err
	}
	return &openngfwv1.RotateLocalUserTokenResponse{User: result.user, OneTimeToken: result.oneTimeToken, Detail: result.detail}, nil
}

// DisableLocalUser disables one local users-file entry.
func (s *SystemService) DisableLocalUser(ctx context.Context, req *openngfwv1.DisableLocalUserRequest) (*openngfwv1.DisableLocalUserResponse, error) {
	if req == nil {
		req = &openngfwv1.DisableLocalUserRequest{}
	}
	if err := authz.RequireStepUp(ctx, "access-local-user-disable", req.GetStepUpToken()); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.GetName())
	comment, err := requiredAuditComment(req.GetComment(), "local user disable comment")
	if err != nil {
		s.auditAccessLocalUserFailure(ctx, "access-local-user-disable-failed", name, "", "comment", err.Error())
		return nil, err
	}
	if !req.GetAckDisableUser() {
		msg := "ack_disable_user is required"
		s.auditAccessLocalUserFailure(ctx, "access-local-user-disable-failed", name, "", "acknowledgement", msg)
		return nil, grpcstatus.Error(codes.FailedPrecondition, msg)
	}
	result, err := s.mutateLocalUser(ctx, "access-local-user-disable", name, "", comment, func() (*authz.Authenticator, authz.LocalUserInventory, string, error) {
		auth, user, err := authz.DisableLocalUser(s.LocalUsersFile, name)
		return auth, user, "", err
	})
	if err != nil {
		return nil, err
	}
	return &openngfwv1.DisableLocalUserResponse{User: result.user, Detail: result.detail}, nil
}

type localUserMutationResult struct {
	user         *openngfwv1.AccessAdministrationLocalUser
	oneTimeToken string
	detail       string
}

func (s *SystemService) mutateLocalUser(ctx context.Context, action, name, role, comment string, mutate func() (*authz.Authenticator, authz.LocalUserInventory, string, error)) (localUserMutationResult, error) {
	if strings.TrimSpace(s.LocalUsersFile) == "" {
		msg := "local users file is not configured"
		s.auditAccessLocalUserFailure(ctx, action+"-failed", name, role, "users-file", msg)
		return localUserMutationResult{}, grpcstatus.Error(codes.FailedPrecondition, msg)
	}
	if err := s.auditAccessLocalUser(ctx, action+"-intent", accessLocalUserAuditDetail(name, role, authz.LocalUserInventory{}, comment)); err != nil {
		return localUserMutationResult{}, grpcstatus.Errorf(codes.Internal, "audit local user intent: %v", err)
	}
	s.accessMu.Lock()
	auth, user, token, err := mutate()
	if err == nil {
		if s.Auth != nil {
			s.Auth.ReplaceLocalUsers(auth)
		} else {
			s.Auth = auth
		}
	}
	s.accessMu.Unlock()
	if err != nil {
		s.auditAccessLocalUserFailure(ctx, action+"-failed", name, role, "mutate", err.Error())
		if strings.Contains(err.Error(), "not found") {
			return localUserMutationResult{}, grpcstatus.Error(codes.NotFound, err.Error())
		}
		return localUserMutationResult{}, grpcstatus.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.auditAccessLocalUser(ctx, action, accessLocalUserAuditDetail(name, role, user, comment)); err != nil {
		return localUserMutationResult{}, grpcstatus.Errorf(codes.Internal, "audit local user mutation: %v", err)
	}
	return localUserMutationResult{
		user:         accessAdministrationLocalUserProto(user),
		oneTimeToken: token,
		detail:       localUserMutationDetail(action, user, token != ""),
	}, nil
}

func accessAdministrationLocalUserProto(user authz.LocalUserInventory) *openngfwv1.AccessAdministrationLocalUser {
	return &openngfwv1.AccessAdministrationLocalUser{
		Name:          user.Name,
		Role:          user.Role,
		AuthSource:    user.AuthSource,
		TokenMaterial: user.TokenMaterial,
		Editable:      user.Editable,
		AuditHash:     user.AuditHash,
		Enabled:       user.Enabled,
	}
}

func accessAdministrationOIDCProto(oidc authz.OIDCInventory) *openngfwv1.AccessAdministrationOidc {
	return &openngfwv1.AccessAdministrationOidc{
		Enabled:           oidc.Enabled,
		Issuer:            oidc.Issuer,
		ClientId:          oidc.ClientID,
		RoleClaim:         oidc.RoleClaim,
		DefaultRole:       oidc.DefaultRole,
		CookieSecure:      oidc.CookieSecure,
		Scopes:            append([]string(nil), oidc.Scopes...),
		TrustedProxyCidrs: append([]string(nil), oidc.TrustedProxyCIDRs...),
		SessionTtlSeconds: oidc.SessionTTLSeconds,
	}
}

func accessAdministrationSAMLProto(cfg authz.SAMLProviderConfig, runtime *authz.SAMLAuthenticator) *openngfwv1.AccessAdministrationSaml {
	cfg = authz.NormalizeSAMLProviderConfig(cfg)
	detail := "SAML browser SSO provider is not configured."
	if cfg.Enabled {
		detail = "SAML provider configuration is saved; browser SAML login/session runtime is not active."
	}
	runtimeAvailable := runtime != nil
	if runtimeAvailable {
		detail = runtime.Inventory().Detail
	}
	return &openngfwv1.AccessAdministrationSaml{
		Enabled:                          cfg.Enabled,
		MetadataUrl:                      cfg.MetadataURL,
		IdpEntityId:                      cfg.IDPEntityID,
		SsoUrl:                           cfg.SSOURL,
		SpEntityId:                       cfg.SPEntityID,
		AcsUrl:                           cfg.ACSURL,
		RoleAttribute:                    cfg.RoleAttribute,
		DefaultRole:                      cfg.DefaultRole,
		CertificateFingerprintConfigured: cfg.CertificateFingerprint != "",
		RuntimeAvailable:                 runtimeAvailable,
		Detail:                           detail,
	}
}

func oidcPreflightProto(preflight authz.OIDCPreflight, generatedAt time.Time) *openngfwv1.RunOIDCPreflightResponse {
	return &openngfwv1.RunOIDCPreflightResponse{
		SchemaVersion: "openngfw.oidc-preflight.v1",
		GeneratedAt:   generatedAt.Format(time.RFC3339),
		State:         preflight.State,
		Label:         preflight.Label,
		Detail:        preflight.Detail,
		Oidc:          accessAdministrationOIDCProto(preflight.Inventory),
		Checks:        oidcPreflightCheckProtos(preflight.Checks),
		Blockers:      append([]string(nil), preflight.Blockers...),
		Warnings:      append([]string(nil), preflight.Warnings...),
		Evidence:      append([]string(nil), preflight.Evidence...),
	}
}

func oidcPreflightCheckProtos(checks []authz.OIDCPreflightCheck) []*openngfwv1.OIDCPreflightCheck {
	out := make([]*openngfwv1.OIDCPreflightCheck, 0, len(checks))
	for _, check := range checks {
		out = append(out, &openngfwv1.OIDCPreflightCheck{
			Id:         check.ID,
			Label:      check.Label,
			State:      check.State,
			Class:      check.Class,
			Detail:     check.Detail,
			Evidence:   check.Evidence,
			NextAction: check.NextAction,
		})
	}
	return out
}

func oidcProviderConfigFromProto(in *openngfwv1.OIDCProviderConfig) authz.OIDCProviderConfig {
	if in == nil {
		return authz.OIDCProviderConfig{}
	}
	return authz.NormalizeOIDCProviderConfig(authz.OIDCProviderConfig{
		Enabled:           in.GetEnabled(),
		Issuer:            in.GetIssuer(),
		ClientID:          in.GetClientId(),
		ClientSecretFile:  in.GetClientSecretFile(),
		RedirectURL:       in.GetRedirectUrl(),
		RoleClaim:         in.GetRoleClaim(),
		DefaultRole:       in.GetDefaultRole(),
		Scopes:            append([]string(nil), in.GetScopes()...),
		TrustedProxyCIDRs: append([]string(nil), in.GetTrustedProxyCidrs()...),
		SessionTTLSeconds: in.GetSessionTtlSeconds(),
		MaxSessions:       in.GetMaxSessions(),
	})
}

func oidcProviderConfigProto(cfg authz.OIDCProviderConfig, includeSecretFilePath bool) *openngfwv1.OIDCProviderConfig {
	cfg = authz.NormalizeOIDCProviderConfig(cfg)
	out := &openngfwv1.OIDCProviderConfig{
		Enabled:                    cfg.Enabled,
		Issuer:                     cfg.Issuer,
		ClientId:                   cfg.ClientID,
		RedirectUrl:                cfg.RedirectURL,
		RoleClaim:                  cfg.RoleClaim,
		DefaultRole:                cfg.DefaultRole,
		Scopes:                     append([]string(nil), cfg.Scopes...),
		TrustedProxyCidrs:          append([]string(nil), cfg.TrustedProxyCIDRs...),
		SessionTtlSeconds:          cfg.SessionTTLSeconds,
		MaxSessions:                cfg.MaxSessions,
		ClientSecretFileConfigured: strings.TrimSpace(cfg.ClientSecretFile) != "",
	}
	if includeSecretFilePath {
		out.ClientSecretFile = cfg.ClientSecretFile
	}
	return out
}

func oidcProviderValidationResponse(cfg authz.OIDCProviderConfig) *openngfwv1.ValidateOIDCProviderConfigResponse {
	cfg = authz.NormalizeOIDCProviderConfig(cfg)
	cfg.Enabled = true
	resp := &openngfwv1.ValidateOIDCProviderConfigResponse{
		NormalizedConfig: oidcProviderConfigProto(cfg, false),
	}
	if err := authz.ValidateOIDCProviderConfig(cfg); err != nil {
		resp.State = "blocked"
		resp.Detail = "OIDC provider configuration has blockers before activation."
		resp.Blockers = []string{sanitizeOIDCProviderDetail(err.Error())}
		return resp
	}
	resp.State = "ready"
	resp.Detail = "OIDC provider configuration shape is ready for runtime discovery and activation."
	if strings.TrimSpace(cfg.ClientSecretFile) == "" {
		resp.Warnings = append(resp.Warnings, "No client secret file is configured; use only for public-client IdP configurations.")
		resp.State = "review"
		resp.Detail = "OIDC provider configuration is usable but has review items before activation."
	}
	return resp
}

func samlProviderConfigFromProto(in *openngfwv1.SAMLProviderConfig) authz.SAMLProviderConfig {
	if in == nil {
		return authz.SAMLProviderConfig{}
	}
	return authz.NormalizeSAMLProviderConfig(authz.SAMLProviderConfig{
		Enabled:                in.GetEnabled(),
		MetadataURL:            in.GetMetadataUrl(),
		IDPEntityID:            in.GetIdpEntityId(),
		SSOURL:                 in.GetSsoUrl(),
		SPEntityID:             in.GetSpEntityId(),
		ACSURL:                 in.GetAcsUrl(),
		RoleAttribute:          in.GetRoleAttribute(),
		DefaultRole:            in.GetDefaultRole(),
		CertificateFingerprint: in.GetCertificateFingerprint(),
		TrustedProxyCIDRs:      append([]string(nil), in.GetTrustedProxyCidrs()...),
		SessionTTLSeconds:      in.GetSessionTtlSeconds(),
		MaxSessions:            in.GetMaxSessions(),
	})
}

func samlProviderConfigProto(cfg authz.SAMLProviderConfig, includeFingerprint bool) *openngfwv1.SAMLProviderConfig {
	cfg = authz.NormalizeSAMLProviderConfig(cfg)
	out := &openngfwv1.SAMLProviderConfig{
		Enabled:                          cfg.Enabled,
		MetadataUrl:                      cfg.MetadataURL,
		IdpEntityId:                      cfg.IDPEntityID,
		SsoUrl:                           cfg.SSOURL,
		SpEntityId:                       cfg.SPEntityID,
		AcsUrl:                           cfg.ACSURL,
		RoleAttribute:                    cfg.RoleAttribute,
		DefaultRole:                      cfg.DefaultRole,
		TrustedProxyCidrs:                append([]string(nil), cfg.TrustedProxyCIDRs...),
		SessionTtlSeconds:                cfg.SessionTTLSeconds,
		MaxSessions:                      cfg.MaxSessions,
		CertificateFingerprintConfigured: strings.TrimSpace(cfg.CertificateFingerprint) != "",
	}
	if includeFingerprint {
		out.CertificateFingerprint = cfg.CertificateFingerprint
	}
	return out
}

func samlProviderValidationResponse(cfg authz.SAMLProviderConfig) *openngfwv1.ValidateSAMLProviderConfigResponse {
	cfg = authz.NormalizeSAMLProviderConfig(cfg)
	cfg.Enabled = true
	resp := &openngfwv1.ValidateSAMLProviderConfigResponse{
		NormalizedConfig: samlProviderConfigProto(cfg, false),
	}
	if err := authz.ValidateSAMLProviderConfig(cfg); err != nil {
		resp.State = "blocked"
		resp.Detail = "SAML provider configuration has blockers before activation."
		resp.Blockers = []string{sanitizeOIDCProviderDetail(err.Error())}
		return resp
	}
	resp.State = "ready"
	resp.Detail = "SAML provider configuration shape is ready for runtime metadata loading and activation."
	if strings.TrimSpace(cfg.CertificateFingerprint) == "" {
		resp.Warnings = append(resp.Warnings, "No SAML certificate fingerprint is configured; pin IdP signing material before enabling runtime SAML login.")
		resp.State = "review"
		resp.Detail = "SAML provider configuration is usable but has review items before activation."
	}
	return resp
}

func readOIDCClientSecretFile(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	if err := securefile.ValidatePrivateFile(path, "OIDC client secret file"); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read OIDC client secret file: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func oidcProviderCookieSecure(cfg authz.OIDCProviderConfig) bool {
	redirect, err := url.Parse(strings.TrimSpace(cfg.RedirectURL))
	if err != nil {
		return false
	}
	return strings.EqualFold(redirect.Scheme, "https")
}

func samlProviderCookieSecure(cfg authz.SAMLProviderConfig) bool {
	acs, err := url.Parse(strings.TrimSpace(cfg.ACSURL))
	if err != nil {
		return false
	}
	return strings.EqualFold(acs.Scheme, "https")
}

func accessAdministrationSessionsProto(sessions authz.OIDCSessionInventory) *openngfwv1.AccessAdministrationSessions {
	return &openngfwv1.AccessAdministrationSessions{
		OidcActiveSessions:         sessions.ActiveSessions,
		OidcMaxSessions:            sessions.MaxSessions,
		SessionRevocationAvailable: sessions.SessionRevocationAvailable,
		Detail:                     sessions.Detail,
		ActiveSessions:             accessAdministrationSessionProtos(sessions.Sessions),
	}
}

func combinedAccessSessionInventory(oidc, saml authz.OIDCSessionInventory) authz.OIDCSessionInventory {
	out := authz.OIDCSessionInventory{
		ActiveSessions:             oidc.ActiveSessions + saml.ActiveSessions,
		MaxSessions:                oidc.MaxSessions + saml.MaxSessions,
		SessionRevocationAvailable: oidc.SessionRevocationAvailable || saml.SessionRevocationAvailable,
		Sessions:                   append(append([]authz.OIDCSessionRecord(nil), oidc.Sessions...), saml.Sessions...),
	}
	sort.Slice(out.Sessions, func(i, j int) bool {
		if !out.Sessions[i].ExpiresAt.Equal(out.Sessions[j].ExpiresAt) {
			return out.Sessions[i].ExpiresAt.Before(out.Sessions[j].ExpiresAt)
		}
		if out.Sessions[i].Actor != out.Sessions[j].Actor {
			return out.Sessions[i].Actor < out.Sessions[j].Actor
		}
		return out.Sessions[i].ID < out.Sessions[j].ID
	})
	switch {
	case oidc.Detail != "" && saml.Detail != "":
		out.Detail = oidc.Detail + " " + saml.Detail
	case oidc.Detail != "":
		out.Detail = oidc.Detail
	default:
		out.Detail = saml.Detail
	}
	return out
}

func accessAdministrationSessionProtos(sessions []authz.OIDCSessionRecord) []*openngfwv1.AccessAdministrationSession {
	out := make([]*openngfwv1.AccessAdministrationSession, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, accessAdministrationSessionProto(session))
	}
	return out
}

func accessAdministrationSessionProto(session authz.OIDCSessionRecord) *openngfwv1.AccessAdministrationSession {
	return &openngfwv1.AccessAdministrationSession{
		SessionId:          session.ID,
		Actor:              session.Actor,
		Role:               session.Role,
		AuthSource:         session.AuthSource,
		ExpiresAt:          session.ExpiresAt.Format(time.RFC3339),
		SecondsUntilExpiry: session.SecondsUntilExpiry,
	}
}

func accessAdministrationBreakGlass(authEnabled bool, localUsers []*openngfwv1.AccessAdministrationLocalUser) *openngfwv1.AccessAdministrationBreakGlass {
	if !authEnabled {
		return &openngfwv1.AccessAdministrationBreakGlass{
			State:      "active",
			Detail:     "API authentication is disabled; local callers are treated as admin.",
			NextAction: "Enable local users or OIDC before exposing the management API or WebUI.",
		}
	}
	admins := localAdminUserCount(localUsers)
	switch {
	case len(localUsers) == 0:
		return &openngfwv1.AccessAdministrationBreakGlass{
			State:      "missing",
			Detail:     "No local break-glass users are loaded.",
			NextAction: "Configure a private local users file with at least one admin user.",
		}
	case admins == 0:
		return &openngfwv1.AccessAdministrationBreakGlass{
			State:      "degraded",
			Detail:     "Local users are loaded, but none has the admin role.",
			NextAction: "Add at least one local admin user through the local users-file workflow.",
		}
	default:
		return &openngfwv1.AccessAdministrationBreakGlass{
			State:      "ready",
			Detail:     fmt.Sprintf("%d local admin break-glass user(s) loaded.", admins),
			NextAction: "Keep local break-glass users protected and rotate tokens through the local users-file workflow.",
		}
	}
}

func accessAdministrationBlockers(authEnabled bool, localUsers []*openngfwv1.AccessAdministrationLocalUser, oidc *openngfwv1.AccessAdministrationOidc, sessions *openngfwv1.AccessAdministrationSessions) []string {
	var blockers []string
	if !authEnabled {
		blockers = append(blockers, "API authentication is disabled; local callers are treated as admin.")
		return blockers
	}
	if len(localUsers) == 0 {
		blockers = append(blockers, "No local break-glass users are loaded.")
	} else if localAdminUserCount(localUsers) == 0 {
		blockers = append(blockers, "No local break-glass user has the admin role.")
	}
	if oidc == nil || !oidc.GetEnabled() {
		blockers = append(blockers, "OIDC browser SSO is not configured.")
	} else {
		if !oidc.GetCookieSecure() {
			blockers = append(blockers, "OIDC browser sessions are not using Secure cookies.")
		}
		if sessions != nil && !sessions.GetSessionRevocationAvailable() {
			blockers = append(blockers, "Admin browser SSO session listing/revocation is not available from the current runtime; only aggregate counts are reported.")
		}
	}
	return dedupeStrings(blockers)
}

func localAdminUserCount(localUsers []*openngfwv1.AccessAdministrationLocalUser) int {
	var admins int
	for _, user := range localUsers {
		if user.GetAuthSource() == authz.AuthSourceLocalUsersFile && user.GetRole() == authz.RoleAdmin.String() {
			admins++
		}
	}
	return admins
}

// TuneHost previews, writes, or applies the host sysctl profile through the
// canonical API. Mutating calls require an explicit acknowledgement because
// they change node-local kernel behavior outside the policy commit path.
func (s *SystemService) TuneHost(ctx context.Context, req *openngfwv1.TuneHostRequest) (*openngfwv1.TuneHostResponse, error) {
	if req == nil {
		req = &openngfwv1.TuneHostRequest{}
	}
	cfg := s.Status
	profile := normalizeTuneProfile(req.GetProfile())
	configPath := cfg.SysctlConfigPath
	if configPath == "" {
		configPath = tuning.DefaultConfigPath
	}
	mutating := req.GetWrite() || req.GetApply()
	text, err := tuning.ConfigTextForProfile(profile)
	if err != nil {
		if mutating {
			s.auditHostTuneFailure(ctx, profile, configPath, req.GetWrite(), req.GetApply(), nil, "profile-validation", err.Error())
		}
		return nil, grpcstatus.Error(codes.InvalidArgument, err.Error())
	}
	resp := &openngfwv1.TuneHostResponse{
		Profile:          profile,
		SysctlConfigPath: configPath,
		ConfigText:       text,
		Results:          plannedTuneResults(profile),
	}
	if mutating && !req.GetAckHostChange() {
		msg := "ack_host_change is required when write or apply is true"
		s.auditHostTuneFailure(ctx, profile, configPath, req.GetWrite(), req.GetApply(), resp.GetResults(), "acknowledgement", msg)
		return nil, grpcstatus.Error(codes.FailedPrecondition, msg)
	}
	if mutating && cfg.DryRun {
		msg := "host tuning cannot write or apply while controld is running in dry-run mode"
		s.auditHostTuneFailure(ctx, profile, configPath, req.GetWrite(), req.GetApply(), resp.GetResults(), "dry-run", msg)
		return nil, grpcstatus.Error(codes.FailedPrecondition, msg)
	}
	if req.GetWrite() {
		if err := tuning.WriteConfigForProfile(configPath, profile); err != nil {
			s.auditHostTuneFailure(ctx, profile, configPath, req.GetWrite(), req.GetApply(), resp.GetResults(), "write", err.Error())
			if os.IsPermission(err) {
				return nil, grpcstatus.Errorf(codes.PermissionDenied, "write host tuning profile: %v", err)
			}
			return nil, grpcstatus.Errorf(codes.Internal, "write host tuning profile: %v", err)
		}
		resp.WroteConfig = true
	}
	if req.GetApply() {
		results, err := tuning.ApplyLiveProfile(ctx, cfg.SysctlRoot, profile, cfg.CommandRun)
		if err != nil {
			s.auditHostTuneFailure(ctx, profile, configPath, req.GetWrite(), req.GetApply(), resp.GetResults(), "apply", err.Error())
			return nil, grpcstatus.Errorf(codes.FailedPrecondition, "apply host tuning profile: %v", err)
		}
		resp.AppliedLive = true
		resp.Results = appliedTuneResults(results)
	}
	if mutating {
		if err := s.auditHostTune(ctx, "system-tune", tuneAuditDetail(profile, configPath, req.GetWrite(), req.GetApply(), resp.GetResults())); err != nil {
			return nil, grpcstatus.Errorf(codes.Internal, "host tuning changed local state but audit write failed: %v", err)
		}
	}
	return resp, nil
}

// SystemStatusConfig is node-local runtime posture reported through the
// canonical SystemService. It intentionally contains no policy state.
type SystemStatusConfig struct {
	StartedAt                           time.Time
	GRPCListen                          string
	HTTPListen                          string
	TLSEnabled                          bool
	PublicSelfSignedTLS                 bool
	AuthEnabled                         bool
	OIDCEnabled                         bool
	OIDCCookieSecure                    bool
	DryRun                              bool
	DataDir                             string
	LogDir                              string
	ContentDir                          string
	ReleaseAcceptanceManifestPath       string
	ReleaseEvidenceDir                  string
	ReleaseNoPerformanceClaims          bool
	InspectionWorkers                   uint32
	HostCPUs                            uint32
	ActiveDataplane                     string
	RateLimitRPM                        int
	RateLimitBurst                      int
	TrustedProxyCIDRs                   []string
	HTTPMaxBodyBytes                    int64
	HTTPMaxHeaderBytes                  int
	HTTPReadHeaderTimeout               time.Duration
	HTTPReadTimeout                     time.Duration
	HTTPWriteTimeout                    time.Duration
	HTTPIdleTimeout                     time.Duration
	GRPCMaxRecvBytes                    int
	GRPCMaxSendBytes                    int
	HighAvailabilityMode                string
	HighAvailabilityRole                string
	HighAvailabilityNodeID              string
	HighAvailabilityPeerID              string
	HighAvailabilityPeerAddress         string
	HighAvailabilityHeartbeatStaleAfter time.Duration
	HighAvailabilityAutoReplicate       bool
	HighAvailabilityReplicationInterval time.Duration
	HighAvailabilityReplicationComment  string
	HighAvailabilityPeerEvidence        func(context.Context) (*HighAvailabilityPeerEvidence, error)
	HighAvailabilityPeerPolicy          func(context.Context) (*openngfwv1.GetPolicyResponse, error)
	HighAvailabilityFencingEvidence     func(context.Context) (*HighAvailabilityFencingEvidence, error)
	HighAvailabilityConntrackSync       func(context.Context) (*HighAvailabilityConntrackSyncEvidence, error)
	HighAvailabilityPromoter            interface {
		Promote(context.Context) (engines.HAPromotionResult, error)
	}
	EbpfPinRoot               string
	EbpfArtifactDir           string
	EbpfAttachProbeInterfaces []string
	EbpfRuntimeProbes         bool
	TelemetryExportRoot       string
	SysctlRoot                string
	SysctlConfigPath          string
	SysfsRoot                 string
	ProcRoot                  string
	Engines                   []SystemEngine
	CommandLookup             func(string) (string, error)
	CommandRun                func(context.Context, string, ...string) ([]byte, error)
}

// HighAvailabilityPeerEvidence is read-only status sampled from a peer node.
// It intentionally carries no mutation or failover action.
type HighAvailabilityPeerEvidence struct {
	NodeID               string
	Role                 string
	RunningPolicyVersion uint64
	ArtifactSetSHA256    string
	LastHeartbeat        time.Time
	Detail               string
}

// HighAvailabilityFencingEvidence is read-only proof from an external fencing
// runbook or controller. The API never performs destructive peer fencing; it
// only records this evidence before local role promotion.
type HighAvailabilityFencingEvidence struct {
	Provider   string
	Claim      string
	PeerID     string
	EvidenceID string
	ObservedAt time.Time
	Detail     string
}

// HighAvailabilityConntrackSyncEvidence is read-only status from an external
// conntrack-state synchronization mechanism. The System API reports and records
// the evidence, but it does not transfer connection state itself.
type HighAvailabilityConntrackSyncEvidence struct {
	Provider   string
	Claim      string
	PeerID     string
	EvidenceID string
	ObservedAt time.Time
	Detail     string
}

type highAvailabilityReplicationState struct {
	LastAttemptAt    time.Time
	LastSuccessAt    time.Time
	LastError        string
	LastPeerVersion  uint64
	LastLocalVersion uint64
}

// EngineRuntime is optional live process state supplied by supervised
// child-process engines such as Suricata and Vector.
type EngineRuntime struct {
	State        string
	PID          int
	Restarts     int
	MaxRestarts  int
	StartedAt    time.Time
	LastExitAt   time.Time
	LastExitErr  string
	LastUptime   time.Duration
	RestartDelay time.Duration
	StartupGrace time.Duration
}

// SystemEngine describes one backend surface managed by controld.
type SystemEngine struct {
	Name         string
	Role         string
	Dependencies []string
	Runtime      func() EngineRuntime
}

func roleCapabilities(role authz.Role) []string {
	if role >= authz.RoleAdmin {
		return []string{"read", "write", "admin"}
	}
	if role >= authz.RoleOperator {
		return []string{"read", "write"}
	}
	if role >= authz.RoleViewer {
		return []string{"read"}
	}
	return nil
}

// GetStatus reports daemon runtime posture and managed engine coverage.
func (s *SystemService) GetStatus(ctx context.Context, _ *openngfwv1.GetStatusRequest) (*openngfwv1.GetStatusResponse, error) {
	cfg := s.Status
	if cfg.StartedAt.IsZero() {
		cfg.StartedAt = time.Now().UTC()
	}
	if cfg.ActiveDataplane == "" {
		cfg.ActiveDataplane = "nftables/conntrack"
	}

	engines := make([]*openngfwv1.EngineStatus, 0, len(cfg.Engines))
	var missingEngines []missingDependency
	var engineWarnings []*openngfwv1.StatusWarning
	for _, e := range cfg.Engines {
		diag := diagnoseEngine(cfg, e)
		if len(diag.missing) > 0 {
			missingEngines = append(missingEngines, missingDependency{engine: e.Name, commands: diag.missing})
		}
		engineWarnings = append(engineWarnings, diag.warnings...)
		engines = append(engines, &openngfwv1.EngineStatus{
			Name:   e.Name,
			Role:   e.Role,
			Mode:   diag.mode,
			State:  diag.state,
			Detail: diag.detail,
		})
	}
	inspection := s.inspectionStatus(engines)

	prereqState := "ready"
	prereqDetail := "required engine commands are present"
	if len(missingEngines) > 0 {
		prereqState = "degraded"
		prereqDetail = "missing " + strconv.Itoa(totalMissing(missingEngines)) + " required command(s)"
	}
	statefulState, statefulDetail := nftablesCapability(cfg)
	conntrackState, conntrackDetail := conntrackCapability(cfg)
	flowtableState, flowtableDetail := flowtableCapability(cfg)
	flowtableRuntime, nftRuleset := flowtableRuntimeEvidence(ctx, cfg)
	dataplaneCounters := parseDataplaneCounters(nftRuleset)
	wireguardRuntime := wireguardRuntimeStatus(ctx, cfg)
	ipsecRuntime := ipsecRuntimeStatus(ctx, cfg)
	routingRuntime := routingRuntimeStatus(ctx, cfg, s.runningDynamicRoutingEnabled())
	runningPolicyVersion := s.runningPolicyVersion()
	highAvailability := s.highAvailabilityStatus(ctx)
	kernelTuning, kernelWarnings := kernelTuningStatus(cfg)
	conntrackTable := conntrackTableStatus(cfg)
	ebpfStatus := ebpfDataplaneStatus(cfg)
	hostResources := hostResourceStatus(cfg)
	managementState, managementDetail := managementGuardrailCapability(cfg)
	contentState, contentDetail, contentWarnings := contentPackageReadiness(cfg)
	degradedEngineState, degradedEngineDetail, degradedEngineWarning := s.degradedEngineDataplaneEvidence(cfg, engines, inspection, statefulState, statefulDetail, flowtableRuntime.state, flowtableRuntime.detail)
	capabilities := []*openngfwv1.SystemCapability{
		{Name: "Stateful firewall", State: statefulState, Detail: statefulDetail},
		{Name: "Live conntrack sessions", State: conntrackState, Detail: conntrackDetail},
		{Name: "Conntrack state-table capacity", State: conntrackTable.GetState(), Detail: conntrackTable.GetDetail()},
		{Name: "nftables flowtable fast path", State: flowtableState, Detail: flowtableDetail},
		{Name: "nftables flowtable runtime", State: flowtableRuntime.state, Detail: flowtableRuntime.detail},
		{Name: "Kernel forwarding tuning", State: kernelTuning.GetState(), Detail: kernelTuning.GetDetail()},
		{Name: "Linux eBPF XDP/tc host readiness", State: ebpfStatus.GetState(), Detail: ebpfStatus.GetDetail()},
		{Name: "Host resource telemetry", State: hostResources.GetState(), Detail: hostResources.GetDetail()},
		{Name: "Inline IDS/IPS fan-out", State: fanoutState(cfg.InspectionWorkers), Detail: fanoutDetail(cfg.InspectionWorkers, cfg.HostCPUs)},
		{Name: "Engine prerequisites", State: prereqState, Detail: prereqDetail},
		{Name: "Inspection policy readiness", State: inspectionCapabilityState(inspection), Detail: inspection.GetDetail()},
		{Name: "WireGuard runtime evidence", State: wireguardRuntime.GetState(), Detail: wireguardRuntime.GetDetail()},
		{Name: "IPsec runtime evidence", State: ipsecRuntime.GetState(), Detail: ipsecRuntime.GetDetail()},
		{Name: "FRR routing runtime evidence", State: routingRuntime.GetFrr().GetState(), Detail: routingRuntime.GetFrr().GetDetail()},
		{Name: "Management plane guardrails", State: managementState, Detail: managementDetail},
		{Name: "Content package verification", State: contentState, Detail: contentDetail},
		{Name: "Active/passive HA readiness", State: highAvailabilityCapabilityState(highAvailability), Detail: highAvailability.GetDetail()},
		{Name: "Degraded engine dataplane evidence", State: degradedEngineState, Detail: degradedEngineDetail},
		{Name: "Candidate/commit/rollback", State: "active", Detail: "all policy mutations use candidate validation, durable apply intent, audited activation, and rollback"},
		{Name: "Linux eBPF XDP/tc dataplane", State: "planned", Detail: "required strategic milestone; not active in this runtime"},
	}

	warnings := make([]*openngfwv1.StatusWarning, 0, 4)
	if cfg.DryRun {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "critical",
			Message:  "The daemon is running in dry-run mode; commits do not change the host firewall.",
			Action:   "Remove --dry-run before production enforcement.",
		})
	}
	if !cfg.AuthEnabled {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "critical",
			Message:  "API authentication is disabled; local callers are treated as admin.",
			Action:   "Start controld with --users-file before exposing the API or UI.",
		})
	}
	if cfg.HTTPListen != "" && !cfg.TLSEnabled {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "critical",
			Message:  "WebUI and REST gateway TLS is disabled.",
			Action:   "Use default TLS or provide --tls-cert and --tls-key.",
		})
	}
	warnings = append(warnings, managementWarnings(cfg)...)
	warnings = append(warnings, contentWarnings...)
	warnings = append(warnings, kernelWarnings...)
	if conntrackTable.GetState() == "warning" || conntrackTable.GetState() == "degraded" {
		severity := "warning"
		message := "Conntrack state table is approaching capacity."
		if conntrackTable.GetState() == "degraded" {
			severity = "critical"
			message = "Conntrack state table is near or over capacity."
		}
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: severity,
			Message:  message,
			Action:   conntrackTable.GetDetail() + "; increase net.netfilter.nf_conntrack_max or reduce connection churn before relying on high-throughput forwarding.",
		})
	}
	if ebpfStatus.GetState() != "ready" {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  "Linux eBPF XDP/tc host readiness is incomplete.",
			Action:   ebpfStatus.GetDetail(),
		})
	}
	if hostResources.GetState() == "degraded" {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  "Host resource telemetry is degraded.",
			Action:   hostResources.GetDetail(),
		})
	}
	if highAvailabilityCapabilityState(highAvailability) == "degraded" {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  "Active/passive HA is not ready.",
			Action:   highAvailability.GetDetail(),
		})
	}
	if systemManagesEngine(cfg, "wireguard") && (wireguardRuntime.GetState() == "degraded" || wireguardRuntime.GetState() == "unknown") {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  "WireGuard runtime evidence is unavailable.",
			Action:   wireguardRuntime.GetDetail(),
		})
	}
	if systemManagesEngine(cfg, "strongswan") && (ipsecRuntime.GetState() == "degraded" || ipsecRuntime.GetState() == "unknown") {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  "IPsec runtime evidence is unavailable.",
			Action:   ipsecRuntime.GetDetail(),
		})
	}
	if frr := routingRuntime.GetFrr(); systemManagesEngine(cfg, "frr") && (frr.GetState() == "degraded" || frr.GetState() == "unknown") {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  "FRR routing runtime evidence is unavailable.",
			Action:   frr.GetDetail(),
		})
	}
	for _, miss := range missingEngines {
		severity := "critical"
		if cfg.DryRun {
			severity = "warning"
		}
		list := strings.Join(miss.commands, ", ")
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: severity,
			Message:  "Engine prerequisites missing for " + miss.engine + ": " + list + ".",
			Action:   "Install required command(s): " + list + ".",
		})
	}
	warnings = append(warnings, engineWarnings...)
	if warning := inspectionWarning(inspection); warning != nil {
		warnings = append(warnings, warning)
	}
	if degradedEngineWarning != nil {
		warnings = append(warnings, degradedEngineWarning)
	}
	warnings = append(warnings, &openngfwv1.StatusWarning{
		Severity: "info",
		Message:  "eBPF XDP/tc dataplane is not active in this build.",
		Action:   "Use nftables/conntrack as the current production renderer and track the eBPF milestone separately.",
	})

	return &openngfwv1.GetStatusResponse{
		Runtime: &openngfwv1.RuntimeStatus{
			Version:           version.Version,
			Commit:            version.Commit,
			BuildDate:         version.BuildDate,
			StartedAt:         cfg.StartedAt.UTC().Format(time.RFC3339),
			UptimeSeconds:     uint64(time.Since(cfg.StartedAt).Seconds()),
			GrpcListen:        cfg.GRPCListen,
			HttpListen:        cfg.HTTPListen,
			TlsEnabled:        cfg.TLSEnabled,
			AuthEnabled:       cfg.AuthEnabled,
			DryRun:            cfg.DryRun,
			DataDir:           cfg.DataDir,
			LogDir:            cfg.LogDir,
			InspectionWorkers: cfg.InspectionWorkers,
			HostCpus:          cfg.HostCPUs,
			ActiveDataplane:   cfg.ActiveDataplane,
		},
		Engines:      engines,
		Capabilities: capabilities,
		Warnings:     warnings,
		Dataplane: &openngfwv1.DataplaneStatus{
			ActiveDataplane: cfg.ActiveDataplane,
			Flowtable: &openngfwv1.FlowtableStatus{
				HostState:          flowtableState,
				HostDetail:         flowtableDetail,
				RuntimeState:       flowtableRuntime.state,
				RuntimeDetail:      flowtableRuntime.detail,
				Devices:            flowtableRuntime.devices,
				Packets:            flowtableRuntime.packets,
				Bytes:              flowtableRuntime.bytes,
				FlowtableDeclared:  flowtableRuntime.declared,
				OffloadRulePresent: flowtableRuntime.offloadRule,
			},
			KernelTuning:         kernelTuning,
			Ebpf:                 ebpfStatus,
			Counters:             dataplaneCounters,
			Conntrack:            conntrackTable,
			RunningPolicyVersion: runningPolicyVersion,
		},
		Management: managementPlaneStatus(cfg),
		Host:       hostResources,
		Inspection: inspection,
		Vpn: &openngfwv1.VpnRuntimeStatus{
			Wireguard: wireguardRuntime,
			Ipsec:     ipsecRuntime,
		},
		Routing:          routingRuntime,
		HighAvailability: highAvailability,
	}, nil
}

// ProveNetworkPath samples passive server-side route and VPN runtime evidence
// for one representative path. It never sends packet probes and only executes a
// fixed kernel route lookup command.
func (s *SystemService) ProveNetworkPath(ctx context.Context, req *openngfwv1.ProveNetworkPathRequest) (*openngfwv1.ProveNetworkPathResponse, error) {
	if req == nil {
		req = &openngfwv1.ProveNetworkPathRequest{}
	}
	src := strings.TrimSpace(req.GetSrcIp())
	dest := strings.TrimSpace(req.GetDestIp())
	if net.ParseIP(src) == nil {
		return nil, grpcstatus.Error(codes.InvalidArgument, "src_ip must be a valid IP address")
	}
	if net.ParseIP(dest) == nil {
		return nil, grpcstatus.Error(codes.InvalidArgument, "dest_ip must be a valid IP address")
	}
	if req.GetDestPort() > 65535 {
		return nil, grpcstatus.Error(codes.InvalidArgument, "dest_port must be between 0 and 65535")
	}
	sourceInterface := strings.TrimSpace(req.GetSourceInterface())
	if sourceInterface != "" && !safeLinuxInterfaceName(sourceInterface) {
		return nil, grpcstatus.Error(codes.InvalidArgument, "source_interface is invalid")
	}

	cfg := s.Status
	resp := &openngfwv1.ProveNetworkPathResponse{
		SchemaVersion:        "phragma.network-path.proof.v1",
		GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
		State:                "unknown",
		RunningPolicyVersion: s.runningPolicyVersion(),
		Evidence: []string{
			"route_lookup=ip -j route get <dest> from <src>",
			"probe_traffic=not_sent",
			"command_input=fixed",
		},
		Limitations: networkPathProofLimitations(),
	}
	resp.Route = kernelRouteProof(ctx, cfg, src, dest, sourceInterface)
	resp.Vpn = vpnRuntimeProof(ctx, cfg, req.GetTunnel())
	resp.Evidence = append(resp.Evidence, networkPathProofEvidence(resp.Route, resp.Vpn)...)
	resp.Evidence = append(resp.Evidence, frrPathProofEvidence(ctx, cfg, dest)...)
	resp.Mismatches = pathProofMismatches(req, resp.Route, resp.Vpn)
	resp.Warnings = append(resp.Warnings, pathProofWarnings(req, resp.Route, resp.Vpn)...)
	resp.CliHandoff, resp.ApiHandoff = networkPathProofHandoffs(req)
	resp.State, resp.Detail = networkPathProofState(resp.Route, resp.Warnings)
	return resp, nil
}

type ipRouteGetEntry struct {
	Dst      string `json:"dst"`
	Gateway  string `json:"gateway"`
	Dev      string `json:"dev"`
	PrefSrc  string `json:"prefsrc"`
	Source   string `json:"src"`
	Protocol string `json:"protocol"`
	Table    any    `json:"table"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Flags    any    `json:"flags"`
	Ifindex  uint32 `json:"ifindex"`
	UID      any    `json:"uid"`
}

func kernelRouteProof(ctx context.Context, cfg SystemStatusConfig, src, dest, expectedDev string) *openngfwv1.NetworkPathRouteProof {
	out := &openngfwv1.NetworkPathRouteProof{
		State:  "unknown",
		Detail: "kernel route proof has not been sampled",
	}
	if cfg.DryRun {
		out.State = "simulation"
		out.Detail = "dry-run mode does not prove live kernel route state"
		return out
	}
	if missing := missingCommands(cfg, []string{"ip"}); len(missing) > 0 {
		out.State = "unavailable"
		out.Detail = "ip command is missing; kernel route lookup cannot be sampled"
		return out
	}
	if cfg.CommandLookup != nil && cfg.CommandRun == nil {
		out.State = "unknown"
		out.Detail = "kernel route query is not configured in this status context"
		return out
	}
	raw, err := runCommand(ctx, cfg, "ip", "-j", "route", "get", dest, "from", src)
	if err != nil {
		out.State = "unavailable"
		out.Detail = "kernel route lookup failed: " + trimCommandError(raw, err)
		out.RawRedacted = redactRouteProofRaw(raw)
		return out
	}
	entries, err := parseIPRouteGetJSON(raw)
	if err != nil || len(entries) == 0 {
		out.State = "unknown"
		out.Detail = "kernel route lookup returned no parseable route"
		out.RawRedacted = redactRouteProofRaw(raw)
		return out
	}
	entry := entries[0]
	out.State = "ready"
	out.Destination = entry.Dst
	if out.Destination == "" {
		out.Destination = dest
	}
	out.Gateway = entry.Gateway
	out.Dev = entry.Dev
	out.PreferredSource = entry.PrefSrc
	out.Protocol = entry.Protocol
	out.Table = fmt.Sprint(entry.Table)
	if out.Table == "<nil>" {
		out.Table = ""
	}
	out.RawRedacted = redactRouteProofRaw(raw)
	identity := kernelRouteIdentityEvidence(ctx, cfg, out.Dev)
	out.Detail = kernelRouteProofDetail(out, entry, identity)
	if expectedDev != "" && out.Dev != "" && out.Dev != expectedDev {
		out.State = "degraded"
		out.Detail = fmt.Sprintf("kernel route dev %s differs from expected interface %s", out.Dev, expectedDev)
	}
	return out
}

type ipLinkShowEntry struct {
	Ifindex  uint32         `json:"ifindex"`
	Ifname   string         `json:"ifname"`
	Master   string         `json:"master"`
	LinkInfo ipLinkInfoJSON `json:"linkinfo"`
}

type ipLinkInfoJSON struct {
	InfoKind string `json:"info_kind"`
}

type routeIdentityEvidence struct {
	InterfaceIndex uint32
	InterfaceName  string
	Master         string
	Kind           string
	Detail         string
}

func kernelRouteIdentityEvidence(ctx context.Context, cfg SystemStatusConfig, dev string) routeIdentityEvidence {
	dev = strings.TrimSpace(dev)
	if dev == "" || !safeLinuxInterfaceName(dev) || cfg.DryRun {
		return routeIdentityEvidence{}
	}
	raw, err := runCommand(ctx, cfg, "ip", "-j", "-d", "link", "show", "dev", dev)
	if err != nil {
		return routeIdentityEvidence{Detail: "interface_identity_unavailable=" + trimCommandError(raw, err)}
	}
	var entries []ipLinkShowEntry
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) == 0 {
		return routeIdentityEvidence{Detail: "interface_identity_unparseable"}
	}
	entry := entries[0]
	identity := routeIdentityEvidence{
		InterfaceIndex: entry.Ifindex,
		InterfaceName:  firstNonEmpty(entry.Ifname, dev),
		Master:         entry.Master,
		Kind:           entry.LinkInfo.InfoKind,
	}
	parts := []string{"interface=" + valueOrDash(identity.InterfaceName)}
	if identity.InterfaceIndex > 0 {
		parts = append(parts, fmt.Sprintf("ifindex=%d", identity.InterfaceIndex))
	}
	if identity.Master != "" {
		parts = append(parts, "master="+identity.Master)
	}
	if identity.Kind != "" {
		parts = append(parts, "kind="+identity.Kind)
	}
	identity.Detail = strings.Join(parts, " ")
	return identity
}

func kernelRouteProofDetail(route *openngfwv1.NetworkPathRouteProof, entry ipRouteGetEntry, identity routeIdentityEvidence) string {
	parts := []string{"kernel route lookup returned dev " + valueOrDash(route.GetDev())}
	if route.GetTable() != "" {
		parts = append(parts, "table "+route.GetTable())
	}
	if entry.Type != "" {
		parts = append(parts, "type "+entry.Type)
	}
	if entry.Scope != "" {
		parts = append(parts, "scope "+entry.Scope)
	}
	if flags := routeFlagsText(entry.Flags); flags != "" {
		parts = append(parts, "flags "+flags)
	}
	if identity.Detail != "" {
		parts = append(parts, identity.Detail)
	}
	return strings.Join(parts, "; ")
}

func parseIPRouteGetJSON(raw []byte) ([]ipRouteGetEntry, error) {
	var entries []ipRouteGetEntry
	if err := json.Unmarshal(raw, &entries); err == nil {
		return entries, nil
	}
	var entry ipRouteGetEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil, err
	}
	return []ipRouteGetEntry{entry}, nil
}

func vpnRuntimeProof(ctx context.Context, cfg SystemStatusConfig, ref *openngfwv1.NetworkPathTunnelRef) *openngfwv1.NetworkPathVpnProof {
	out := &openngfwv1.NetworkPathVpnProof{
		State:  "not-requested",
		Detail: "no VPN tunnel reference was provided",
	}
	if ref == nil {
		return out
	}
	kind := strings.ToLower(strings.TrimSpace(ref.GetKind()))
	out.Kind = kind
	if kind == "" {
		return out
	}
	switch kind {
	case "wireguard", "wg":
		out.Kind = "wireguard"
		return wireguardPathProof(ctx, cfg, ref)
	case "ipsec", "strongswan":
		out.Kind = "ipsec"
		return ipsecPathProof(ctx, cfg, ref)
	default:
		out.State = "unknown"
		out.Detail = "unsupported tunnel kind " + strings.TrimSpace(ref.GetKind())
		return out
	}
}

func wireguardPathProof(ctx context.Context, cfg SystemStatusConfig, ref *openngfwv1.NetworkPathTunnelRef) *openngfwv1.NetworkPathVpnProof {
	runtime := wireguardRuntimeStatus(ctx, cfg)
	out := &openngfwv1.NetworkPathVpnProof{
		Kind:      "wireguard",
		State:     runtime.GetState(),
		Detail:    runtime.GetDetail(),
		Interface: strings.TrimSpace(ref.GetInterface()),
		Peer:      strings.TrimSpace(firstNonEmpty(ref.GetPeer(), ref.GetPeerPublicKey())),
	}
	ifaceName := strings.TrimSpace(ref.GetInterface())
	peerKey := strings.TrimSpace(ref.GetPeerPublicKey())
	for _, iface := range runtime.GetInterfaces() {
		if ifaceName != "" && iface.GetName() != ifaceName {
			continue
		}
		out.Interface = iface.GetName()
		out.MatchedTunnel = iface.GetName()
		out.State = iface.GetState()
		out.Detail = iface.GetDetail()
		for _, peer := range iface.GetPeers() {
			if peerKey != "" && peer.GetPublicKey() != peerKey {
				continue
			}
			out.Peer = firstNonEmpty(ref.GetPeer(), shortPublicKey(peer.GetPublicKey()))
			out.State = peer.GetState()
			out.Detail = peer.GetDetail()
			out.HandshakeAgeSeconds = peer.GetLatestHandshakeAgeSeconds()
			out.Correlation = "matched WireGuard interface " + valueOrDash(iface.GetName()) + " peer " + valueOrDash(shortPublicKey(peer.GetPublicKey()))
			return out
		}
		if peerKey == "" {
			out.Correlation = "matched WireGuard interface " + valueOrDash(iface.GetName()) + " without peer selector"
			return out
		}
		out.State = "unknown"
		out.Detail = "WireGuard interface was observed but requested peer public key was not found"
		out.Correlation = "matched WireGuard interface " + valueOrDash(iface.GetName()) + " but not requested peer"
		return out
	}
	if ifaceName != "" {
		out.State = "unknown"
		out.Detail = "requested WireGuard interface was not observed"
	}
	return out
}

func ipsecPathProof(ctx context.Context, cfg SystemStatusConfig, ref *openngfwv1.NetworkPathTunnelRef) *openngfwv1.NetworkPathVpnProof {
	runtime := ipsecRuntimeStatus(ctx, cfg)
	out := &openngfwv1.NetworkPathVpnProof{
		Kind:   "ipsec",
		State:  runtime.GetState(),
		Detail: runtime.GetDetail(),
		Peer:   strings.TrimSpace(ref.GetPeer()),
	}
	name := strings.TrimSpace(ref.GetName())
	for _, tunnel := range runtime.GetTunnels() {
		if name != "" && tunnel.GetName() != name {
			continue
		}
		out.MatchedTunnel = tunnel.GetName()
		out.State = tunnel.GetState()
		out.Detail = tunnel.GetDetail()
		out.ChildSaCount = tunnel.GetChildSaCount()
		out.InstalledChildSaCount = tunnel.GetInstalledChildSaCount()
		out.Correlation = fmt.Sprintf("matched IPsec tunnel %s with %d/%d installed CHILD SAs", valueOrDash(tunnel.GetName()), tunnel.GetInstalledChildSaCount(), tunnel.GetChildSaCount())
		return out
	}
	if name != "" {
		out.State = "unknown"
		out.Detail = "requested IPsec tunnel was not observed"
	}
	return out
}

func networkPathProofEvidence(route *openngfwv1.NetworkPathRouteProof, vpn *openngfwv1.NetworkPathVpnProof) []string {
	var evidence []string
	if route != nil {
		if route.GetDev() != "" {
			evidence = append(evidence, "route_dev="+route.GetDev())
		}
		if route.GetGateway() != "" {
			evidence = append(evidence, "route_gateway="+route.GetGateway())
		}
		if route.GetPreferredSource() != "" {
			evidence = append(evidence, "route_preferred_source="+route.GetPreferredSource())
		}
		if route.GetTable() != "" {
			evidence = append(evidence, "route_table="+route.GetTable())
		}
		evidence = append(evidence, networkPathRouteDepthEvidence(route)...)
	}
	if vpn != nil && vpn.GetCorrelation() != "" {
		evidence = append(evidence, "vpn_correlation="+vpn.GetCorrelation())
	}
	return evidence
}

func networkPathRouteDepthEvidence(route *openngfwv1.NetworkPathRouteProof) []string {
	if route == nil {
		return nil
	}
	var evidence []string
	detail := route.GetDetail()
	for _, key := range []string{"ifindex=", "master=", "kind="} {
		if value := routeDetailTokenValue(detail, key); value != "" {
			switch key {
			case "ifindex=":
				evidence = append(evidence, "route_interface_index="+value)
			case "master=":
				evidence = append(evidence, "route_interface_master="+value)
			case "kind=":
				evidence = append(evidence, "route_interface_kind="+value)
			}
		}
	}
	if route.GetDev() != "" {
		evidence = append(evidence, "route_interface_identity=dev:"+route.GetDev())
	}
	if route.GetPreferredSource() != "" {
		evidence = append(evidence, "masquerade_egress_observed_source="+route.GetPreferredSource())
		evidence = append(evidence, "masquerade_egress_proof=kernel-preferred-source-only")
	}
	if strings.Contains(detail, "type ") {
		evidence = append(evidence, "route_type="+routeDetailWordAfter(detail, "type "))
	}
	if strings.Contains(detail, "scope ") {
		evidence = append(evidence, "route_scope="+routeDetailWordAfter(detail, "scope "))
	}
	if strings.Contains(detail, "flags ") {
		evidence = append(evidence, "route_flags="+routeDetailWordAfter(detail, "flags "))
	}
	return evidence
}

func frrPathProofEvidence(ctx context.Context, cfg SystemStatusConfig, dest string) []string {
	if !systemManagesEngine(cfg, "frr") {
		return []string{"frr_route_proof=not-configured"}
	}
	if cfg.DryRun {
		return []string{"frr_route_proof=simulation"}
	}
	if missing := missingCommands(cfg, []string{"vtysh"}); len(missing) > 0 {
		return []string{"frr_route_proof=unavailable:vtysh-missing"}
	}
	if cfg.CommandLookup != nil && cfg.CommandRun == nil {
		return []string{"frr_route_proof=unknown:command-runner-not-configured"}
	}
	command := "show ip route " + dest + " json"
	raw, err := runFrrStatusCommand(ctx, cfg, command)
	if err != nil {
		return []string{"frr_route_proof=unavailable:" + boundedEvidenceValue(trimCommandError(raw, err))}
	}
	state := "observed"
	detail := "json-bytes"
	if len(strings.TrimSpace(string(raw))) == 0 {
		state = "unknown"
		detail = "empty-output"
	}
	return []string{
		"frr_route_proof=" + state,
		"frr_route_command=show ip route <dest> json",
		"frr_route_detail=" + detail,
	}
}

func boundedEvidenceValue(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\n", " "))
	if len(value) > 96 {
		return value[:96]
	}
	return value
}

func routeDetailTokenValue(detail, key string) string {
	idx := strings.Index(detail, key)
	if idx < 0 {
		return ""
	}
	rest := detail[idx+len(key):]
	for i, r := range rest {
		if r == ' ' || r == ';' || r == ',' {
			return rest[:i]
		}
	}
	return rest
}

func routeDetailWordAfter(detail, key string) string {
	value := routeDetailTokenValue(detail, key)
	return strings.Trim(value, ";,")
}

func routeFlagsText(flags any) string {
	switch v := flags.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(v)
	case []any:
		var out []string
		for _, item := range v {
			text := strings.TrimSpace(fmt.Sprint(item))
			if text != "" {
				out = append(out, text)
			}
		}
		return strings.Join(out, ",")
	default:
		text := strings.TrimSpace(fmt.Sprint(v))
		if text == "<nil>" {
			return ""
		}
		return text
	}
}

func networkPathProofLimitations() []string {
	return []string{
		"passive_route_lookup_only",
		"frr_route_lookup_correlating_only",
		"vrf_interface_identity_best_effort",
		"masquerade_egress_observed_from_kernel_preferred_source_only",
		"active_probe_not_sent",
		"packet_capture_not_started",
		"remote_peer_not_attested",
		"proof_not_signed_or_server_retained",
	}
}

func pathProofMismatches(req *openngfwv1.ProveNetworkPathRequest, route *openngfwv1.NetworkPathRouteProof, vpn *openngfwv1.NetworkPathVpnProof) []*openngfwv1.NetworkPathMismatch {
	var mismatches []*openngfwv1.NetworkPathMismatch
	expectedDev := strings.TrimSpace(req.GetSourceInterface())
	hasRouteDeviceMismatch := expectedDev != "" && route.GetDev() != "" && route.GetDev() != expectedDev
	if route.GetState() != "ready" && !hasRouteDeviceMismatch {
		mismatches = append(mismatches, &openngfwv1.NetworkPathMismatch{
			Severity: mismatchSeverityForState(route.GetState()),
			Subject:  "route",
			Detail:   "kernel_route_state=" + route.GetState(),
		})
	}
	if hasRouteDeviceMismatch {
		mismatches = append(mismatches, &openngfwv1.NetworkPathMismatch{
			Severity: "warning",
			Subject:  "route",
			Detail:   "route_device_mismatch=" + route.GetDev() + " expected=" + expectedDev,
		})
	}
	if vpn != nil && vpn.GetKind() != "" && !networkPathVpnProofReady(vpn) {
		mismatches = append(mismatches, &openngfwv1.NetworkPathMismatch{
			Severity: mismatchSeverityForState(networkPathVpnMismatchState(vpn)),
			Subject:  "vpn",
			Detail:   "vpn_state=" + networkPathVpnMismatchState(vpn),
		})
	}
	if len(mismatches) == 0 {
		return nil
	}
	return mismatches
}

func pathProofWarnings(req *openngfwv1.ProveNetworkPathRequest, route *openngfwv1.NetworkPathRouteProof, vpn *openngfwv1.NetworkPathVpnProof) []string {
	var warnings []string
	if route.GetState() != "ready" {
		warnings = append(warnings, "kernel_route_state="+route.GetState())
	}
	if expected := strings.TrimSpace(req.GetSourceInterface()); expected != "" && route.GetDev() != "" && route.GetDev() != expected {
		warnings = append(warnings, "route_device_mismatch="+route.GetDev()+" expected="+expected)
	}
	if vpn != nil && vpn.GetKind() != "" && !networkPathVpnProofReady(vpn) {
		warnings = append(warnings, "vpn_state="+networkPathVpnMismatchState(vpn))
	}
	return warnings
}

func networkPathVpnStateReady(state string) bool {
	switch state {
	case "", "not-requested", "active", "handshook", "installed":
		return true
	default:
		return false
	}
}

func networkPathVpnProofReady(vpn *openngfwv1.NetworkPathVpnProof) bool {
	if vpn == nil || vpn.GetKind() == "" {
		return true
	}
	if networkPathVpnStateReady(vpn.GetState()) {
		return true
	}
	return vpn.GetKind() == "ipsec" && vpn.GetMatchedTunnel() != "" && vpn.GetInstalledChildSaCount() > 0
}

func networkPathVpnMismatchState(vpn *openngfwv1.NetworkPathVpnProof) string {
	if vpn == nil {
		return ""
	}
	if vpn.GetKind() == "ipsec" && vpn.GetMatchedTunnel() != "" && vpn.GetInstalledChildSaCount() > 0 {
		return "installed"
	}
	return vpn.GetState()
}

func mismatchSeverityForState(state string) string {
	switch state {
	case "unavailable":
		return "critical"
	case "degraded", "unknown":
		return "warning"
	default:
		return "info"
	}
}

func networkPathProofHandoffs(req *openngfwv1.ProveNetworkPathRequest) (string, string) {
	cli := []string{"ngfwctl", "system", "network-path", "prove", "--src", networkPathShellQuote(req.GetSrcIp()), "--dst", networkPathShellQuote(req.GetDestIp())}
	if req.GetProtocol() != openngfwv1.Protocol_PROTOCOL_UNSPECIFIED {
		cli = append(cli, "--protocol", networkPathShellQuote(req.GetProtocol().String()))
	}
	if req.GetDestPort() > 0 {
		cli = append(cli, "--dport", fmt.Sprint(req.GetDestPort()))
	}
	if req.GetSourceInterface() != "" {
		cli = append(cli, "--source-interface", networkPathShellQuote(req.GetSourceInterface()))
	}
	if t := req.GetTunnel(); t != nil {
		if t.GetKind() != "" {
			cli = append(cli, "--tunnel-kind", networkPathShellQuote(t.GetKind()))
		}
		if t.GetName() != "" {
			cli = append(cli, "--tunnel-name", networkPathShellQuote(t.GetName()))
		}
		if t.GetInterface() != "" {
			cli = append(cli, "--tunnel-interface", networkPathShellQuote(t.GetInterface()))
		}
		if t.GetPeer() != "" {
			cli = append(cli, "--tunnel-peer", networkPathShellQuote(t.GetPeer()))
		}
		if t.GetPeerPublicKey() != "" {
			cli = append(cli, "--tunnel-peer-public-key", networkPathShellQuote(t.GetPeerPublicKey()))
		}
	}
	payload, err := json.Marshal(networkPathProofJSONRequest(req))
	if err != nil {
		return strings.Join(cli, " "), "POST /v1/system/network-path:prove"
	}
	return strings.Join(cli, " "), "POST /v1/system/network-path:prove\n" + string(payload)
}

func networkPathProofJSONRequest(req *openngfwv1.ProveNetworkPathRequest) map[string]any {
	body := map[string]any{
		"srcIp":    req.GetSrcIp(),
		"destIp":   req.GetDestIp(),
		"protocol": req.GetProtocol().String(),
	}
	if req.GetDestPort() > 0 {
		body["destPort"] = req.GetDestPort()
	}
	if req.GetSourceInterface() != "" {
		body["sourceInterface"] = req.GetSourceInterface()
	}
	if t := req.GetTunnel(); t != nil {
		tunnel := map[string]any{}
		if t.GetKind() != "" {
			tunnel["kind"] = t.GetKind()
		}
		if t.GetName() != "" {
			tunnel["name"] = t.GetName()
		}
		if t.GetInterface() != "" {
			tunnel["interface"] = t.GetInterface()
		}
		if t.GetPeer() != "" {
			tunnel["peer"] = t.GetPeer()
		}
		if t.GetPeerPublicKey() != "" {
			tunnel["peerPublicKey"] = t.GetPeerPublicKey()
		}
		if len(tunnel) > 0 {
			body["tunnel"] = tunnel
		}
	}
	return body
}

func networkPathShellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func networkPathProofState(route *openngfwv1.NetworkPathRouteProof, warnings []string) (string, string) {
	if route.GetState() == "ready" && len(warnings) == 0 {
		return "ready", "kernel route and requested passive VPN evidence are ready"
	}
	if route.GetState() == "unavailable" {
		return "unavailable", route.GetDetail()
	}
	if route.GetState() == "degraded" {
		return "degraded", route.GetDetail()
	}
	if route.GetState() == "ready" {
		return "degraded", "kernel route was found with proof warning(s)"
	}
	return "unknown", route.GetDetail()
}

func safeLinuxInterfaceName(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' || r == ':' {
			continue
		}
		return false
	}
	return true
}

func redactRouteProofRaw(raw []byte) string {
	text := strings.TrimSpace(string(raw))
	if len(text) > 512 {
		text = text[:512] + "..."
	}
	return text
}

func valueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func shortPublicKey(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

// GetTelemetryExportStatus reports the running telemetry export posture without
// emitting test events, dialing remote sinks, or mutating local files.
func (s *SystemService) GetTelemetryExportStatus(_ context.Context, _ *openngfwv1.GetTelemetryExportStatusRequest) (*openngfwv1.GetTelemetryExportStatusResponse, error) {
	resp := &openngfwv1.GetTelemetryExportStatusResponse{
		SchemaVersion: "phragma.telemetry.export.status.v1",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		State:         "unknown",
		Detail:        "Running policy telemetry export posture is unavailable.",
		Vector:        s.telemetryVectorRuntimeStatus(false),
	}
	if s.Store == nil {
		resp.Warnings = append(resp.Warnings, &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  "Telemetry export status cannot read the running policy because no policy store is configured.",
			Action:   "Start controld with a configured data store before using telemetry export evidence.",
		})
		return resp, nil
	}
	running, version, err := s.Store.GetRunning()
	if err != nil {
		resp.Detail = "Running policy telemetry export posture could not be loaded."
		resp.Warnings = append(resp.Warnings, &openngfwv1.StatusWarning{
			Severity: "critical",
			Message:  "Telemetry export status could not read the running policy.",
			Action:   err.Error(),
		})
		return resp, nil
	}
	resp.RunningPolicyVersion = version
	tel := running.GetTelemetry()
	if !tel.GetEnabled() {
		resp.State = "disabled"
		resp.Detail = "Telemetry is disabled in the running policy; no Vector export sinks are rendered."
		resp.Clickhouse = &openngfwv1.TelemetryClickHouseSinkStatus{
			Configured:     false,
			EvidenceState:  "disabled",
			EvidenceDetail: "ClickHouse retention is disabled in the running policy.",
			EventsTable:    "events",
			AlertsTable:    "alerts",
			Database:       "none",
			Endpoint:       "disabled",
		}
		return resp, nil
	}

	resp.TelemetryEnabled = true
	resp.Vector = s.telemetryVectorRuntimeStatus(true)
	resp.Clickhouse = telemetryClickHouseSinkStatus(tel)
	resp.Exports = telemetryExportSinkStatuses(s.Status, tel.GetExports())
	resp.Warnings = append(resp.Warnings, telemetryPolicyWarnings(running)...)
	resp.Warnings = append(resp.Warnings, telemetryRuntimeWarnings(resp)...)
	resp.State, resp.Detail = telemetryExportOverall(resp)
	return resp, nil
}

// VerifyTelemetryExport writes or sends one bounded synthetic JSON event to an
// enabled export sink from the running policy. It never accepts an arbitrary
// destination outside that configured policy surface.
func (s *SystemService) VerifyTelemetryExport(ctx context.Context, req *openngfwv1.VerifyTelemetryExportRequest) (*openngfwv1.VerifyTelemetryExportResponse, error) {
	if req == nil {
		req = &openngfwv1.VerifyTelemetryExportRequest{}
	}
	if !req.GetAckTestEvent() {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "ack_test_event is required")
	}
	if s.Store == nil {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "policy store is not configured")
	}
	running, version, err := s.Store.GetRunning()
	if err != nil {
		return nil, grpcstatus.Errorf(codes.FailedPrecondition, "load running policy: %v", err)
	}
	if !running.GetTelemetry().GetEnabled() {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "running policy telemetry is disabled")
	}
	export, err := selectTelemetryExport(req, running.GetTelemetry().GetExports())
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	event, proofID, eventHash, err := telemetryProofEvent(now, export, req.GetReason(), version)
	if err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "build telemetry proof event: %v", err)
	}
	resp := &openngfwv1.VerifyTelemetryExportResponse{
		SchemaVersion:        "phragma.telemetry.export.verify.v1",
		GeneratedAt:          now.Format(time.RFC3339),
		State:                "unknown",
		RunningPolicyVersion: version,
		Proof: &openngfwv1.TelemetryExportProof{
			ProofId:    proofID,
			ExportName: export.GetName(),
			Type:       export.GetType(),
			Protocol:   telemetryExportProtocol(export.GetType()),
			Target:     export.GetTarget(),
			Bytes:      uint64(len(event)),
			EventHash:  eventHash,
		},
	}
	if s.Status.DryRun {
		resp.State = "simulation"
		resp.Detail = "dry-run mode does not write or send telemetry proof events"
		resp.Proof.Evidence = "not_sent"
		return resp, nil
	}
	switch export.GetType() {
	case openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_FILE:
		if err := writeTelemetryProofFile(s.Status, export.GetTarget(), event); err != nil {
			resp.State = "failed"
			resp.Detail = err.Error()
			resp.Proof.Evidence = "file_append_failed"
			return resp, nil
		}
		resp.State = "written"
		resp.Detail = "synthetic telemetry proof event appended to configured JSON export file"
		resp.Proof.Evidence = "file_append"
	case openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_TCP, openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_UDP:
		if err := sendTelemetryProofStream(ctx, export.GetType(), export.GetTarget(), event); err != nil {
			resp.State = "failed"
			resp.Detail = err.Error()
			resp.Proof.Evidence = "stream_send_failed"
			return resp, nil
		}
		resp.State = "delivered"
		resp.Detail = "synthetic telemetry proof event sent to configured JSON stream export"
		resp.Proof.Evidence = "stream_send"
	default:
		resp.State = "invalid"
		resp.Detail = "configured telemetry export type is not supported for verification"
		resp.Proof.Evidence = "unsupported_type"
	}
	resp.Warnings = append(resp.Warnings,
		"receiver_custody_not_verified",
		"clickhouse_row_delivery_not_verified",
		"synthetic_event_not_signed",
	)
	return resp, nil
}

func (s *SystemService) telemetryVectorRuntimeStatus(telemetryEnabled bool) *openngfwv1.TelemetryVectorRuntimeStatus {
	for _, engine := range s.Status.Engines {
		if strings.EqualFold(engine.Name, "vector") {
			diag := diagnoseEngine(s.Status, engine)
			if telemetryEnabled && diag.state == "ready" && strings.Contains(diag.detail, "process is stopped") {
				diag.state = "degraded"
				diag.detail = "telemetry is enabled in the running policy but the Vector process is stopped"
			}
			return &openngfwv1.TelemetryVectorRuntimeStatus{
				State:  diag.state,
				Detail: diag.detail,
			}
		}
	}
	return &openngfwv1.TelemetryVectorRuntimeStatus{
		State:  "unmanaged",
		Detail: "Vector is not registered as a managed engine in this daemon.",
	}
}

func telemetryClickHouseSinkStatus(tel *openngfwv1.Telemetry) *openngfwv1.TelemetryClickHouseSinkStatus {
	endpoint := strings.TrimSpace(tel.GetClickhouseUrl())
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8123"
	}
	database := strings.TrimSpace(tel.GetDatabase())
	if database == "" {
		database = "openngfw"
	}
	return &openngfwv1.TelemetryClickHouseSinkStatus{
		Configured:     true,
		Endpoint:       redactClickHouseEndpoint(endpoint),
		Database:       database,
		EventsTable:    "events",
		AlertsTable:    "alerts",
		EvidenceState:  "configured-unverified",
		EvidenceDetail: "ClickHouse sink is rendered from policy; row delivery requires ClickHouse-side row-count evidence.",
	}
}

func telemetryExportSinkStatuses(cfg SystemStatusConfig, exports []*openngfwv1.TelemetryExport) []*openngfwv1.TelemetryExportSinkStatus {
	out := make([]*openngfwv1.TelemetryExportSinkStatus, 0, len(exports))
	for _, export := range exports {
		if export == nil || !export.GetEnabled() {
			continue
		}
		status := &openngfwv1.TelemetryExportSinkStatus{
			Name:       export.GetName(),
			Configured: true,
			Type:       export.GetType(),
			Target:     export.GetTarget(),
		}
		switch export.GetType() {
		case openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_FILE:
			status.Protocol = "file"
			status.File = telemetryLocalFileEvidence(cfg, export.GetTarget())
			switch {
			case status.File.GetError() != "":
				status.EvidenceState = "invalid"
				status.EvidenceDetail = status.File.GetError()
			case !status.File.GetPresent():
				status.EvidenceState = "pending"
				status.EvidenceDetail = "Configured local JSON export file has not been created yet."
			case status.File.GetSizeBytes() == 0:
				status.EvidenceState = "empty"
				status.EvidenceDetail = "Configured local JSON export file exists but contains no events yet."
			default:
				status.EvidenceState = "receiving"
				status.EvidenceDetail = fmt.Sprintf("Configured local JSON export file is present with %d byte(s).", status.File.GetSizeBytes())
			}
		case openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_TCP:
			status.Protocol = "tcp"
			status.EvidenceState = "configured-unverified"
			status.EvidenceDetail = "TCP JSON stream is configured; passive status does not dial the remote SIEM listener."
		case openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_UDP:
			status.Protocol = "udp"
			status.EvidenceState = "configured-unverified"
			status.EvidenceDetail = "UDP JSON stream is configured; passive status does not dial the remote SIEM listener."
		default:
			status.EvidenceState = "invalid"
			status.EvidenceDetail = "Telemetry export type is not supported by the Vector renderer."
		}
		out = append(out, status)
	}
	return out
}

func selectTelemetryExport(req *openngfwv1.VerifyTelemetryExportRequest, exports []*openngfwv1.TelemetryExport) (*openngfwv1.TelemetryExport, error) {
	name := strings.TrimSpace(req.GetExportName())
	target := strings.TrimSpace(req.GetTarget())
	wantType := req.GetType()
	for _, export := range exports {
		if export == nil || !export.GetEnabled() {
			continue
		}
		if name != "" && export.GetName() != name {
			continue
		}
		if wantType != openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_UNSPECIFIED && export.GetType() != wantType {
			continue
		}
		if target != "" && export.GetTarget() != target {
			continue
		}
		return export, nil
	}
	return nil, grpcstatus.Error(codes.NotFound, "matching enabled running-policy telemetry export was not found")
}

func telemetryProofEvent(now time.Time, export *openngfwv1.TelemetryExport, reason string, version uint64) ([]byte, string, string, error) {
	seed := fmt.Sprintf("%s|%s|%s|%d", now.Format(time.RFC3339Nano), export.GetName(), export.GetTarget(), version)
	sum := sha256.Sum256([]byte(seed))
	proofID := "telproof-" + hex.EncodeToString(sum[:])[:16]
	payload := map[string]any{
		"schema_version":         "phragma.telemetry.synthetic-event.v1",
		"event_type":             "openngfw.telemetry.verify",
		"generated_at":           now.Format(time.RFC3339Nano),
		"proof_id":               proofID,
		"export_name":            export.GetName(),
		"export_type":            export.GetType().String(),
		"running_policy_version": version,
		"reason":                 redactTelemetryProofText(reason),
	}
	event, err := json.Marshal(payload)
	if err != nil {
		return nil, "", "", err
	}
	event = append(event, '\n')
	eventSum := sha256.Sum256(event)
	return event, proofID, "sha256:" + hex.EncodeToString(eventSum[:]), nil
}

func writeTelemetryProofFile(cfg SystemStatusConfig, target string, event []byte) error {
	checkedPath := telemetryExpandFileTarget(target, time.Now().UTC())
	clean, ok := telemetryExportFilePath(cfg, checkedPath)
	if !ok {
		return fmt.Errorf("configured JSON export path is outside the telemetry export root")
	}
	if err := os.MkdirAll(filepath.Dir(clean), 0750); err != nil {
		return fmt.Errorf("create telemetry export directory: %w", err)
	}
	if info, err := os.Lstat(clean); err == nil {
		if info.IsDir() {
			return fmt.Errorf("configured JSON export path is a directory")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("configured JSON export path must not be a symlink")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat telemetry export file: %w", err)
	}
	f, err := os.OpenFile(clean, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("open telemetry export file: %w", err)
	}
	_, writeErr := f.Write(event)
	closeErr := f.Close()
	if writeErr != nil {
		return fmt.Errorf("append telemetry proof event: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close telemetry export file: %w", closeErr)
	}
	return nil
}

func sendTelemetryProofStream(ctx context.Context, exportType openngfwv1.TelemetryExportType, target string, event []byte) error {
	network := "tcp"
	if exportType == openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_UDP {
		network = "udp"
	}
	if _, _, err := net.SplitHostPort(strings.TrimSpace(target)); err != nil {
		return fmt.Errorf("configured JSON stream target must be host:port: %w", err)
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(dialCtx, network, target)
	if err != nil {
		return fmt.Errorf("send telemetry proof event to %s stream: %w", network, err)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, writeErr := conn.Write(event)
	closeErr := conn.Close()
	if writeErr != nil {
		return fmt.Errorf("write telemetry proof event to %s stream: %w", network, writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close telemetry proof %s stream: %w", network, closeErr)
	}
	return nil
}

func telemetryExportProtocol(exportType openngfwv1.TelemetryExportType) string {
	switch exportType {
	case openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_FILE:
		return "file"
	case openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_UDP:
		return "udp"
	case openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_TCP:
		return "tcp"
	default:
		return "unknown"
	}
}

func redactTelemetryProofText(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = regexp.MustCompile(`(?i)(token|secret|password|bearer|api[_-]?key)=\S+`).ReplaceAllString(value, "$1=[redacted]")
	value = regexp.MustCompile(`/((?:home|Users|private|tmp|var/lib|var/log|etc)/(?:\S+))`).ReplaceAllString(value, "[local-path-redacted]")
	if len(value) > 160 {
		value = value[:160]
	}
	return value
}

func telemetryLocalFileEvidence(cfg SystemStatusConfig, target string) *openngfwv1.TelemetryLocalFileEvidence {
	evidence := &openngfwv1.TelemetryLocalFileEvidence{Path: target}
	checkedPath := telemetryExpandFileTarget(target, time.Now().UTC())
	clean, ok := telemetryExportFilePath(cfg, checkedPath)
	if !ok {
		evidence.Error = "Configured JSON export path is outside the telemetry export root."
		return evidence
	}
	evidence.Path = clean
	info, err := os.Lstat(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return evidence
		}
		evidence.Error = "Stat configured JSON export file: " + err.Error()
		return evidence
	}
	if info.IsDir() {
		evidence.Error = "Configured JSON export path is a directory, not a file."
		return evidence
	}
	if info.Mode()&os.ModeSymlink != 0 {
		evidence.Error = "Configured JSON export path must not be a symlink."
		return evidence
	}
	if !info.Mode().IsRegular() {
		evidence.Error = "Configured JSON export path is not a regular file."
		return evidence
	}
	evidence.Present = true
	if info.Size() > 0 {
		evidence.SizeBytes = uint64(info.Size())
	}
	if !info.ModTime().IsZero() {
		evidence.ModifiedAt = info.ModTime().UTC().Format(time.RFC3339)
	}
	return evidence
}

func telemetryExpandFileTarget(target string, now time.Time) string {
	replacer := strings.NewReplacer(
		"%%", "%",
		"%Y", now.Format("2006"),
		"%y", now.Format("06"),
		"%m", now.Format("01"),
		"%d", now.Format("02"),
		"%H", now.Format("15"),
		"%M", now.Format("04"),
		"%S", now.Format("05"),
		"%F", now.Format("2006-01-02"),
	)
	return replacer.Replace(target)
}

func telemetryExportFilePath(cfg SystemStatusConfig, target string) (string, bool) {
	clean := filepath.Clean(strings.TrimSpace(target))
	if clean == "." || !filepath.IsAbs(clean) {
		return clean, false
	}
	root := strings.TrimSpace(cfg.TelemetryExportRoot)
	if root == "" {
		root = defaultTelemetryExportRoot
	}
	root = filepath.Clean(root)
	rel, err := filepath.Rel(root, clean)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return clean, false
	}
	return clean, true
}

func telemetryPolicyWarnings(running *openngfwv1.Policy) []*openngfwv1.StatusWarning {
	var warnings []*openngfwv1.StatusWarning
	for _, issue := range policyvalidate.Validate(running) {
		if strings.HasPrefix(issue, "telemetry") {
			warnings = append(warnings, &openngfwv1.StatusWarning{
				Severity: "critical",
				Message:  "Running policy telemetry configuration is invalid: " + issue + ".",
				Action:   "Stage and commit a corrected telemetry configuration before relying on export evidence.",
			})
		}
	}
	return warnings
}

func telemetryRuntimeWarnings(resp *openngfwv1.GetTelemetryExportStatusResponse) []*openngfwv1.StatusWarning {
	var warnings []*openngfwv1.StatusWarning
	vectorState := resp.GetVector().GetState()
	if telemetryVectorStateBad(vectorState) {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "critical",
			Message:  "Vector telemetry engine is not ready for export delivery.",
			Action:   resp.GetVector().GetDetail(),
		})
	} else if vectorState != "ready" && vectorState != "active" {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  "Vector telemetry engine readiness is not confirmed.",
			Action:   resp.GetVector().GetDetail(),
		})
	}
	if resp.GetClickhouse().GetConfigured() {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "info",
			Message:  "ClickHouse export delivery is not passively verified by this endpoint.",
			Action:   "Record ClickHouse row-count evidence after generating a controlled IDS/IPS event.",
		})
	}
	for _, export := range resp.GetExports() {
		switch export.GetEvidenceState() {
		case "invalid":
			warnings = append(warnings, &openngfwv1.StatusWarning{
				Severity: "critical",
				Message:  fmt.Sprintf("Telemetry export %q has invalid passive evidence configuration.", export.GetName()),
				Action:   export.GetEvidenceDetail(),
			})
		case "pending", "empty":
			warnings = append(warnings, &openngfwv1.StatusWarning{
				Severity: "warning",
				Message:  fmt.Sprintf("Telemetry export %q has no event evidence yet.", export.GetName()),
				Action:   export.GetEvidenceDetail(),
			})
		case "configured-unverified":
			warnings = append(warnings, &openngfwv1.StatusWarning{
				Severity: "info",
				Message:  fmt.Sprintf("Telemetry export %q requires sink-side verification.", export.GetName()),
				Action:   export.GetEvidenceDetail(),
			})
		}
	}
	return warnings
}

func telemetryExportOverall(resp *openngfwv1.GetTelemetryExportStatusResponse) (string, string) {
	if !resp.GetTelemetryEnabled() {
		return "disabled", "Telemetry is disabled in the running policy."
	}
	for _, warning := range resp.GetWarnings() {
		if warning.GetSeverity() == "critical" {
			return "degraded", "Telemetry export configuration is present, but critical runtime or validation blockers remain."
		}
	}
	if resp.GetVector().GetState() == "ready" || resp.GetVector().GetState() == "active" {
		return "configured", "Telemetry export sinks are rendered from the running policy; passive evidence is available where local files exist."
	}
	return "unknown", "Telemetry export sinks are configured, but Vector runtime readiness is not confirmed."
}

func telemetryVectorStateBad(state string) bool {
	switch state {
	case "failed", "missing-prerequisites", "degraded":
		return true
	default:
		return false
	}
}

func redactClickHouseEndpoint(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "[invalid-clickhouse-url]"
	}
	u.User = nil
	u.Fragment = ""
	query := u.Query()
	for key := range query {
		if sensitiveTelemetryURLParam(key) {
			query.Set(key, "[redacted]")
		}
	}
	u.RawQuery = query.Encode()
	return u.String()
}

func sensitiveTelemetryURLParam(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	if lower == "" {
		return false
	}
	for _, needle := range []string{"password", "passwd", "secret", "token", "api_key", "apikey", "access_key", "private_key", "credential"} {
		if lower == needle || strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

// CheckRuntimeReadiness reports the same runtime acknowledgement gate enforced
// by commit and rollback without mutating the candidate or running policy.
func (s *SystemService) CheckRuntimeReadiness(ctx context.Context, req *openngfwv1.CheckRuntimeReadinessRequest) (*openngfwv1.CheckRuntimeReadinessResponse, error) {
	operation := normalizeRuntimeReadinessOperation(req.GetOperation())
	warnings, err := s.RuntimeReadinessWarnings(ctx, req.GetTargetPolicy(), req.GetRunningPolicy())
	if err != nil {
		return runtimeReadinessUnavailablePreflight(operation, err), nil
	}
	return runtimeReadinessPreflight(operation, warnings), nil
}

// GetHighAvailabilityStatus reports read-only HA posture and policy recovery
// metadata. It intentionally does not expose failover or peer-sync mutations.
func (s *SystemService) GetHighAvailabilityStatus(ctx context.Context, _ *openngfwv1.GetHighAvailabilityStatusRequest) (*openngfwv1.GetHighAvailabilityStatusResponse, error) {
	return &openngfwv1.GetHighAvailabilityStatusResponse{
		SchemaVersion: "phragma.ha.status.v1",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Status:        s.highAvailabilityStatus(ctx),
	}, nil
}

// PullHighAvailabilityPolicy lets a passive node manually replicate the active
// peer's running policy through the normal validated, audited apply path.
func (s *SystemService) PullHighAvailabilityPolicy(ctx context.Context, req *openngfwv1.PullHighAvailabilityPolicyRequest) (*openngfwv1.PullHighAvailabilityPolicyResponse, error) {
	if req == nil {
		req = &openngfwv1.PullHighAvailabilityPolicyRequest{}
	}
	comment, err := requiredAuditComment(req.GetComment(), "HA policy pull comment")
	if err != nil {
		return nil, err
	}
	if !req.GetAckPull() {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "ack_pull is required")
	}
	return s.pullHighAvailabilityPolicy(ctx, comment, req.GetAckRisk(), req.GetAckRuntime())
}

// RunHighAvailabilityReplicationOnce performs one background replication
// attempt. It is exported so controld can own the daemon loop while tests can
// prove the replication decision without sleeping.
func (s *SystemService) RunHighAvailabilityReplicationOnce(ctx context.Context) (*openngfwv1.PullHighAvailabilityPolicyResponse, error) {
	if !s.Status.HighAvailabilityAutoReplicate {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "HA automatic replication is disabled")
	}
	comment := strings.TrimSpace(s.Status.HighAvailabilityReplicationComment)
	if comment == "" {
		comment = "automatic passive HA policy replication"
	}
	s.recordHighAvailabilityReplicationAttempt()
	resp, err := s.pullHighAvailabilityPolicy(ctx, comment, true, true)
	if err != nil {
		s.recordHighAvailabilityReplicationFailure(err)
		return nil, err
	}
	s.recordHighAvailabilityReplicationSuccess(resp.GetPeerVersion(), resp.GetVersion())
	return resp, nil
}

// StartHighAvailabilityReplication runs passive-node policy replication until
// ctx is cancelled. The first attempt waits for the configured interval so
// startup health and operator actions can settle before mutation is possible.
func (s *SystemService) StartHighAvailabilityReplication(ctx context.Context, logger func(string, ...any)) {
	if !s.Status.HighAvailabilityAutoReplicate {
		return
	}
	interval := s.Status.HighAvailabilityReplicationInterval
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			resp, err := s.RunHighAvailabilityReplicationOnce(ctx)
			if logger == nil {
				continue
			}
			if err != nil {
				logger("HA automatic replication skipped or failed", "error", err)
				continue
			}
			logger("HA automatic replication applied peer policy", "peer_version", resp.GetPeerVersion(), "local_version", resp.GetVersion())
		}
	}
}

func (s *SystemService) pullHighAvailabilityPolicy(ctx context.Context, comment string, ackRisk, ackRuntime bool) (*openngfwv1.PullHighAvailabilityPolicyResponse, error) {
	if s.Store == nil {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "policy store is not configured")
	}
	if s.Policy == nil {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "policy apply service is not configured")
	}
	mode := normalizeHighAvailabilityMode(s.Status.HighAvailabilityMode)
	role := normalizeHighAvailabilityRole(s.Status.HighAvailabilityRole)
	if mode != "active-passive" {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "HA policy pull requires active-passive mode")
	}
	if role != "passive" {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "HA policy pull must run on the passive node")
	}
	if s.Status.HighAvailabilityPeerEvidence == nil {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "HA peer heartbeat source is not configured")
	}
	if s.Status.HighAvailabilityPeerPolicy == nil {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "HA peer policy source is not configured")
	}
	running, runningVersion, err := s.Store.GetRunning()
	if err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "read running policy: %v", err)
	}
	if candidate, ok, err := s.Store.GetCandidate(); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "read candidate policy: %v", err)
	} else if ok && !proto.Equal(candidate, running) {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "local candidate has staged changes; discard or commit them before HA policy pull")
	}
	before := s.highAvailabilityStatus(ctx)
	evidence, err := s.Status.HighAvailabilityPeerEvidence(ctx)
	if err != nil {
		return nil, grpcstatus.Errorf(codes.FailedPrecondition, "HA peer heartbeat is unreachable: %v", err)
	}
	if err := s.validateHighAvailabilityPullPeer(before, evidence, runningVersion); err != nil {
		return nil, err
	}
	peerResp, err := s.Status.HighAvailabilityPeerPolicy(ctx)
	if err != nil {
		return nil, grpcstatus.Errorf(codes.FailedPrecondition, "HA peer policy fetch failed: %v", err)
	}
	peerPolicy := peerResp.GetPolicy()
	peerVersion := peerResp.GetVersion()
	if peerPolicy == nil {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "HA peer policy response is missing policy")
	}
	if peerVersion == 0 {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "HA peer policy response is missing running version")
	}
	if evidence.RunningPolicyVersion != 0 && evidence.RunningPolicyVersion != peerVersion {
		return nil, grpcstatus.Errorf(codes.FailedPrecondition, "HA peer policy version mismatch: heartbeat v%d, policy v%d", evidence.RunningPolicyVersion, peerVersion)
	}
	if peerVersion <= runningVersion {
		return nil, grpcstatus.Errorf(codes.FailedPrecondition, "HA peer policy version v%d is not newer than local running version v%d", peerVersion, runningVersion)
	}
	id, previousVersion, info, err := s.Policy.ApplyReplicatedPolicy(ctx, peerPolicy, comment, ackRisk, ackRuntime, peerVersion)
	if err != nil {
		return nil, err
	}
	after := s.highAvailabilityStatus(ctx)
	return &openngfwv1.PullHighAvailabilityPolicyResponse{
		Version:               id,
		PreviousVersion:       previousVersion,
		VersionInfo:           versionInfoProto(info),
		Before:                before,
		After:                 after,
		PeerVersion:           peerVersion,
		PeerArtifactSetSha256: strings.TrimSpace(evidence.ArtifactSetSHA256),
		Detail:                fmt.Sprintf("Pulled active peer policy v%d and applied it locally as v%d.", peerVersion, id),
	}, nil
}

func (s *SystemService) recordHighAvailabilityReplicationAttempt() {
	s.haReplicationMu.Lock()
	defer s.haReplicationMu.Unlock()
	s.haReplication.LastAttemptAt = time.Now().UTC()
	s.haReplication.LastError = ""
}

func (s *SystemService) recordHighAvailabilityReplicationFailure(err error) {
	s.haReplicationMu.Lock()
	defer s.haReplicationMu.Unlock()
	if err != nil {
		s.haReplication.LastError = err.Error()
	}
}

func (s *SystemService) recordHighAvailabilityReplicationSuccess(peerVersion, localVersion uint64) {
	s.haReplicationMu.Lock()
	defer s.haReplicationMu.Unlock()
	s.haReplication.LastSuccessAt = time.Now().UTC()
	s.haReplication.LastError = ""
	s.haReplication.LastPeerVersion = peerVersion
	s.haReplication.LastLocalVersion = localVersion
}

func (s *SystemService) highAvailabilityReplicationStatus() *openngfwv1.HighAvailabilityReplicationStatus {
	enabled := s.Status.HighAvailabilityAutoReplicate
	status := &openngfwv1.HighAvailabilityReplicationStatus{
		Enabled: enabled,
		State:   "disabled",
		Detail:  "Automatic passive policy replication is disabled.",
	}
	if !enabled {
		return status
	}
	status.State = "waiting"
	status.Detail = "Automatic passive policy replication is enabled and will apply newer active-peer policies when safety gates pass."
	s.haReplicationMu.Lock()
	defer s.haReplicationMu.Unlock()
	if !s.haReplication.LastAttemptAt.IsZero() {
		status.LastAttemptAt = s.haReplication.LastAttemptAt.Format(time.RFC3339)
	}
	if !s.haReplication.LastSuccessAt.IsZero() {
		status.LastSuccessAt = s.haReplication.LastSuccessAt.Format(time.RFC3339)
		status.LastPeerVersion = s.haReplication.LastPeerVersion
		status.LastLocalVersion = s.haReplication.LastLocalVersion
		status.State = "replicated"
		status.Detail = fmt.Sprintf("Last automatic replication applied peer policy v%d locally as v%d.", s.haReplication.LastPeerVersion, s.haReplication.LastLocalVersion)
	}
	if s.haReplication.LastError != "" {
		status.LastError = s.haReplication.LastError
		status.State = "blocked"
		status.Detail = "Last automatic replication attempt did not apply a policy: " + s.haReplication.LastError
	}
	return status
}

// ActivateHighAvailabilityFailover marks this passive node active in durable
// node-local HA state. It does not move traffic, fence the peer, or synchronize
// connection state.
func (s *SystemService) ActivateHighAvailabilityFailover(ctx context.Context, req *openngfwv1.ActivateHighAvailabilityFailoverRequest) (*openngfwv1.ActivateHighAvailabilityFailoverResponse, error) {
	if req == nil {
		req = &openngfwv1.ActivateHighAvailabilityFailoverRequest{}
	}
	if err := authz.RequireStepUp(ctx, "ha-failover-activate", req.GetStepUpToken()); err != nil {
		return nil, err
	}
	comment, err := requiredAuditComment(req.GetComment(), "HA failover activation comment")
	if err != nil {
		return nil, err
	}
	if !req.GetAckFailover() {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "ack_failover is required")
	}
	if !req.GetAckExternalCutover() {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "ack_external_cutover is required")
	}
	if !req.GetAckExternalFencing() {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "ack_external_fencing is required")
	}
	if s.Store == nil {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "policy store is not configured")
	}
	mode := normalizeHighAvailabilityMode(s.Status.HighAvailabilityMode)
	role := s.effectiveHighAvailabilityRole()
	if mode != "active-passive" {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "HA failover activation requires active-passive mode")
	}
	if role != "passive" {
		return nil, grpcstatus.Errorf(codes.FailedPrecondition, "HA failover activation must run on a passive node; current role is %s", role)
	}
	running, runningVersion, err := s.Store.GetRunning()
	if err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "read running policy: %v", err)
	}
	if candidate, ok, err := s.Store.GetCandidate(); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "read candidate policy: %v", err)
	} else if ok && !proto.Equal(candidate, running) {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "local candidate has staged changes; discard or commit them before HA failover activation")
	}
	lkg, hasLKG := s.lastKnownGoodVersionInfo()
	if !hasLKG {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "last-known-good policy metadata is required before HA failover activation")
	}
	if runningVersion == 0 {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "running policy version is required before HA failover activation")
	}
	if lkg.ID != runningVersion {
		return nil, grpcstatus.Errorf(codes.FailedPrecondition, "running policy v%d does not match last-known-good v%d", runningVersion, lkg.ID)
	}
	before := s.highAvailabilityStatus(ctx)
	if before.GetRole() != "passive" {
		return nil, grpcstatus.Errorf(codes.FailedPrecondition, "HA failover activation requires passive status; current role is %s", before.GetRole())
	}
	if !before.GetFailover().GetEligible() {
		blockers := before.GetFailover().GetBlockers()
		if len(blockers) == 0 {
			blockers = before.GetBlockers()
		}
		return nil, grpcstatus.Errorf(codes.FailedPrecondition, "HA failover activation is not eligible: %s", strings.Join(blockers, "; "))
	}
	identity := auditIdentity(ctx)
	if err := s.Store.AppendAudit(store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role,
		AuthSource: identity.AuthSource,
		Action:     "ha-failover-activate-intent",
		Detail:     comment,
		Version:    runningVersion,
	}); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "record HA failover activation intent: %v", err)
	}
	fencing, err := s.highAvailabilityFencingEvidence(ctx, before.GetPeerId())
	if err != nil {
		return nil, err
	}
	transportClaim := "not_performed"
	transportVIP := ""
	transportInterface := ""
	var transportRoutes []string
	transportGARPState := "not_requested"
	transportGARPDetail := "gratuitous ARP announcement was not requested"
	transportNeighborState := "not_sampled"
	transportNeighborDetail := "neighbor table was not sampled"
	var transportObservedAt time.Time
	transportDetail := "External traffic cutover and peer fencing were acknowledged and must be verified outside this API."
	if s.Status.HighAvailabilityPromoter != nil {
		promotion, err := s.Status.HighAvailabilityPromoter.Promote(ctx)
		if err != nil {
			return nil, grpcstatus.Errorf(codes.FailedPrecondition, "HA VIP/route promotion failed: %v", err)
		}
		transportClaim = promotion.TransportClaim
		if strings.TrimSpace(transportClaim) == "" {
			transportClaim = "linux_local_vip_route_promoted"
		}
		transportVIP = strings.TrimSpace(promotion.VIP)
		transportInterface = strings.TrimSpace(promotion.Interface)
		transportRoutes = append([]string(nil), promotion.Routes...)
		transportGARPState = strings.TrimSpace(promotion.GARPState)
		if transportGARPState == "" {
			transportGARPState = "unknown"
		}
		transportGARPDetail = strings.TrimSpace(promotion.GARPDetail)
		transportNeighborState = strings.TrimSpace(promotion.NeighborState)
		if transportNeighborState == "" {
			transportNeighborState = "unknown"
		}
		transportNeighborDetail = strings.TrimSpace(promotion.NeighborDetail)
		if observedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(promotion.ObservedAt)); err == nil {
			transportObservedAt = observedAt.UTC()
		} else {
			transportObservedAt = time.Now().UTC()
		}
		transportDetail = fmt.Sprintf("Linux-local VIP/route promotion completed for %s on %s with %d route(s); GARP state %s; neighbor proof %s; peer fencing remains external.", promotion.VIP, promotion.Interface, len(promotion.Routes), transportGARPState, transportNeighborState)
		if len(promotion.Warnings) > 0 {
			transportDetail += " Promotion warnings: " + strings.Join(promotion.Warnings, "; ")
		}
	}
	conntrackSync := s.highAvailabilityConntrackSyncEvidence(ctx, before.GetPeerId())
	activatedAt := time.Now().UTC()
	haState := store.HighAvailabilityState{
		Role:                           "active",
		PreviousRole:                   "passive",
		ActivatedAt:                    activatedAt,
		Actor:                          identity.Name,
		ActorRole:                      identity.Role,
		AuthSource:                     identity.AuthSource,
		Comment:                        comment,
		Source:                         "manual-passive-activation",
		RunningPolicyVersion:           runningVersion,
		LastKnownGoodVersion:           lkg.ID,
		PeerID:                         before.GetPeerId(),
		PeerLastHeartbeatSeconds:       before.GetSync().GetSecondsSinceHeartbeat(),
		PreflightPeerPolicyVersion:     before.GetSync().GetPeerVersion(),
		PreflightPeerArtifactSetSHA256: before.GetSync().GetPeerArtifactSetSha256(),
		PreflightFailoverState:         before.GetFailover().GetState(),
		PreflightFailoverEligible:      before.GetFailover().GetEligible(),
		FencingClaim:                   fencing.Claim,
		FencingProvider:                fencing.Provider,
		FencingEvidenceID:              fencing.EvidenceID,
		FencingEvidenceAt:              fencing.ObservedAt,
		FencingEvidenceDetail:          fencing.Detail,
		TransportClaim:                 transportClaim,
		TransportVIP:                   transportVIP,
		TransportInterface:             transportInterface,
		TransportRoutes:                transportRoutes,
		TransportGARPState:             transportGARPState,
		TransportGARPDetail:            transportGARPDetail,
		TransportNeighborState:         transportNeighborState,
		TransportNeighborDetail:        transportNeighborDetail,
		TransportEvidenceAt:            transportObservedAt,
		TransportEvidenceDetail:        transportDetail,
		ConntrackSyncClaim:             conntrackSync.Claim,
		ConntrackSyncProvider:          conntrackSync.Provider,
		ConntrackSyncEvidenceID:        conntrackSync.EvidenceID,
		ConntrackSyncEvidenceAt:        conntrackSync.ObservedAt,
		ConntrackSyncEvidenceDetail:    conntrackSync.Detail,
	}
	if err := s.Store.SetHighAvailabilityStateWithAudit(haState, store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role,
		AuthSource: identity.AuthSource,
		Action:     "ha-failover-activate",
		Detail:     comment,
		Version:    runningVersion,
	}); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "persist HA failover activation: %v", err)
	}
	after := s.highAvailabilityStatus(ctx)
	fencingDetail := fencing.Detail
	if fencingDetail == "" {
		fencingDetail = "Peer fencing was acknowledged but no fencing evidence provider is configured."
	}
	after.TransportEvidence = s.highAvailabilityTransportEvidenceStatus()
	after.ConntrackSync = s.highAvailabilityConntrackSyncStatus(ctx)
	after.Detail = strings.TrimSpace(after.Detail + " Local control-plane role was manually marked active after server preflight; " + transportDetail + " " + fencingDetail + " " + conntrackSync.Detail)
	after.Failover.Detail = "Local control-plane role is active after manual activation; post-activation review must verify peer fencing, VIP/route ownership, neighbor convergence, conntrack sync status, and traffic cutover."
	after.Warnings = append(after.Warnings, &openngfwv1.StatusWarning{
		Severity: "warning",
		Message:  "HA post-activation external controls require verification.",
		Action:   "Verify peer fencing, VIP/route ownership, GARP/neighbor convergence, conntrack sync, and traffic cutover before treating failover as complete.",
	})
	return &openngfwv1.ActivateHighAvailabilityFailoverResponse{
		SchemaVersion:        "phragma.ha.failover.activation.v1",
		ActivatedAt:          activatedAt.Format(time.RFC3339),
		Before:               before,
		After:                after,
		RunningPolicyVersion: runningVersion,
		LastKnownGoodVersion: lkg.ID,
		Detail:               fmt.Sprintf("Marked passive node %s active using running policy v%d after HA preflight. External traffic cutover, peer fencing, neighbor convergence, and connection-state sync must be verified before production failover claims.", before.GetNodeId(), runningVersion),
	}, nil
}

type highAvailabilityFencingEvidenceResult struct {
	Claim      string
	Provider   string
	EvidenceID string
	ObservedAt time.Time
	Detail     string
}

func (s *SystemService) highAvailabilityFencingEvidence(ctx context.Context, expectedPeerID string) (highAvailabilityFencingEvidenceResult, error) {
	result := highAvailabilityFencingEvidenceResult{
		Claim:  "not_performed",
		Detail: "Peer fencing was acknowledged but no fencing evidence provider is configured.",
	}
	if s.Status.HighAvailabilityFencingEvidence == nil {
		return result, nil
	}
	evidence, err := s.Status.HighAvailabilityFencingEvidence(ctx)
	if err != nil {
		return result, grpcstatus.Errorf(codes.FailedPrecondition, "HA external fencing evidence failed: %v", err)
	}
	if evidence == nil {
		return result, grpcstatus.Error(codes.FailedPrecondition, "HA external fencing evidence is missing")
	}
	provider := strings.TrimSpace(evidence.Provider)
	if provider == "" {
		return result, grpcstatus.Error(codes.FailedPrecondition, "HA external fencing evidence provider is required")
	}
	claim := strings.TrimSpace(evidence.Claim)
	if claim == "" {
		return result, grpcstatus.Error(codes.FailedPrecondition, "HA external fencing evidence claim is required")
	}
	if peerID := strings.TrimSpace(evidence.PeerID); peerID != "" && strings.TrimSpace(expectedPeerID) != "" && peerID != strings.TrimSpace(expectedPeerID) {
		return result, grpcstatus.Errorf(codes.FailedPrecondition, "HA external fencing evidence peer mismatch: expected %s, got %s", strings.TrimSpace(expectedPeerID), peerID)
	}
	if strings.EqualFold(claim, "not_performed") || strings.EqualFold(claim, "unknown") {
		return result, grpcstatus.Errorf(codes.FailedPrecondition, "HA external fencing evidence claim %q does not prove peer fencing", claim)
	}
	observedAt := evidence.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	detail := strings.TrimSpace(evidence.Detail)
	if detail == "" {
		detail = fmt.Sprintf("External fencing evidence provider %s reported claim %s.", provider, claim)
	}
	return highAvailabilityFencingEvidenceResult{
		Claim:      claim,
		Provider:   provider,
		EvidenceID: strings.TrimSpace(evidence.EvidenceID),
		ObservedAt: observedAt,
		Detail:     detail,
	}, nil
}

func (s *SystemService) highAvailabilityStatus(ctx context.Context) *openngfwv1.HighAvailabilityStatus {
	cfg := s.Status
	mode := normalizeHighAvailabilityMode(cfg.HighAvailabilityMode)
	role := s.effectiveHighAvailabilityRole()
	nodeID := strings.TrimSpace(cfg.HighAvailabilityNodeID)
	if nodeID == "" {
		if host, err := os.Hostname(); err == nil && strings.TrimSpace(host) != "" {
			nodeID = strings.TrimSpace(host)
		} else {
			nodeID = "local"
		}
	}
	peerID := strings.TrimSpace(cfg.HighAvailabilityPeerID)
	peerAddress := strings.TrimSpace(cfg.HighAvailabilityPeerAddress)
	runningVersion := s.runningPolicyVersion()
	lkg, hasLKG := s.lastKnownGoodVersionInfo()

	resp := &openngfwv1.HighAvailabilityStatus{
		State:                "standalone",
		Role:                 "standalone",
		Mode:                 mode,
		NodeId:               nodeID,
		PeerId:               peerID,
		PeerAddress:          peerAddress,
		RunningPolicyVersion: runningVersion,
		Sync: &openngfwv1.HighAvailabilitySyncStatus{
			State:        "not_configured",
			Detail:       "No HA peer is configured; this node is operating as a standalone firewall.",
			LocalVersion: runningVersion,
		},
		Replication: s.highAvailabilityReplicationStatus(),
		Failover: &openngfwv1.HighAvailabilityFailoverStatus{
			State:    "not_configured",
			Eligible: false,
			Detail:   "Failover is unavailable in standalone mode.",
		},
		Detail: "Standalone single-node operation. Policy recovery relies on local last-known-good metadata and restore drill evidence.",
	}
	resp.FencingEvidence = s.highAvailabilityFencingEvidenceStatus()
	resp.TransportEvidence = s.highAvailabilityTransportEvidenceStatus()
	resp.ConntrackSync = s.highAvailabilityConntrackSyncStatus(ctx)
	if hasLKG {
		resp.LastKnownGoodVersion = lkg.ID
		resp.LastKnownGoodState = lkg.State
		resp.LastKnownGoodArtifactSetSha256 = lkg.ArtifactSetSHA256
		resp.Sync.LocalArtifactSetSha256 = lkg.ArtifactSetSHA256
		if lkg.Action == "ha-policy-pull" && lkg.SourceVersion > 0 {
			resp.Sync.LocalVersion = lkg.SourceVersion
		}
	} else {
		resp.LastKnownGoodState = "missing"
	}

	if mode != "active-passive" {
		resp.Mode = "standalone"
		return resp
	}

	resp.State = "degraded"
	resp.Role = role
	resp.Detail = "Active/passive HA is configured but readiness evidence is incomplete."
	resp.Sync.State = "degraded"
	resp.Sync.Detail = "Local policy and LKG metadata are available, but peer heartbeat evidence is not configured."
	resp.Failover.State = "blocked"
	resp.Failover.Detail = "Manual active/passive recovery is not eligible until peer health, policy sync, and recovery metadata are ready."
	if role == "unknown" {
		resp.Blockers = append(resp.Blockers, "HA role must be active or passive for active/passive mode.")
	}
	if !hasLKG {
		resp.Blockers = append(resp.Blockers, "Last-known-good policy metadata is missing.")
	}
	if peerAddress == "" {
		resp.State = "degraded"
		resp.Sync.State = "degraded"
		resp.Blockers = append(resp.Blockers, "HA peer address is not configured.")
		resp.Sync.Detail = "Active/passive mode is configured without a peer address."
	}
	if cfg.HighAvailabilityPeerEvidence == nil {
		resp.Blockers = append(resp.Blockers, "HA peer heartbeat source is not configured.")
	} else {
		s.applyHighAvailabilityPeerEvidence(ctx, resp, role)
	}
	s.finalizeHighAvailabilityReadiness(resp)
	resp.Failover.Blockers = dedupeStrings(resp.Failover.Blockers)
	resp.Blockers = dedupeStrings(resp.Blockers)
	if len(resp.Blockers) > 0 {
		resp.Warnings = append(resp.Warnings, &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  "Active/passive HA is not ready.",
			Action:   strings.Join(resp.Blockers, " "),
		})
	}
	return resp
}

func (s *SystemService) highAvailabilityFencingEvidenceStatus() *openngfwv1.HighAvailabilityFencingEvidenceStatus {
	status := &openngfwv1.HighAvailabilityFencingEvidenceStatus{
		State:  "not_recorded",
		Detail: "No peer fencing evidence has been recorded for this node-local HA role marker.",
	}
	if s.Store == nil {
		return status
	}
	state, ok, err := s.Store.GetHighAvailabilityState()
	if err != nil {
		return &openngfwv1.HighAvailabilityFencingEvidenceStatus{
			State:  "unavailable",
			Detail: "HA fencing evidence could not be read from the local store.",
		}
	}
	if !ok {
		return status
	}
	claim := strings.TrimSpace(state.FencingClaim)
	provider := strings.TrimSpace(state.FencingProvider)
	evidenceID := strings.TrimSpace(state.FencingEvidenceID)
	detail := strings.TrimSpace(state.FencingEvidenceDetail)
	observedAt := ""
	if !state.FencingEvidenceAt.IsZero() {
		observedAt = state.FencingEvidenceAt.UTC().Format(time.RFC3339)
	}
	if claim == "" && provider == "" && evidenceID == "" && detail == "" && observedAt == "" {
		return status
	}
	evidenceState := "recorded"
	if claim == "" || strings.EqualFold(claim, "not_performed") || strings.EqualFold(claim, "unknown") {
		evidenceState = "acknowledged_external"
		if detail == "" {
			detail = "Peer fencing was acknowledged externally, but no provider-backed proof was recorded."
		}
	} else if detail == "" {
		providerLabel := provider
		if providerLabel == "" {
			providerLabel = "unknown"
		}
		detail = fmt.Sprintf("External fencing evidence provider %s reported claim %s.", providerLabel, claim)
	}
	return &openngfwv1.HighAvailabilityFencingEvidenceStatus{
		State:      evidenceState,
		Provider:   provider,
		Claim:      claim,
		PeerId:     strings.TrimSpace(state.PeerID),
		EvidenceId: evidenceID,
		ObservedAt: observedAt,
		Detail:     detail,
	}
}

type highAvailabilityConntrackSyncResult struct {
	Claim      string
	Provider   string
	PeerID     string
	EvidenceID string
	ObservedAt time.Time
	Detail     string
}

func (s *SystemService) highAvailabilityConntrackSyncEvidence(ctx context.Context, expectedPeerID string) highAvailabilityConntrackSyncResult {
	result := highAvailabilityConntrackSyncResult{
		Claim:  "not_performed",
		Detail: "Connection-state sync evidence is not configured; this API did not transfer conntrack state.",
	}
	if s.Status.HighAvailabilityConntrackSync == nil {
		return result
	}
	evidence, err := s.Status.HighAvailabilityConntrackSync(ctx)
	if err != nil {
		result.Claim = "unavailable"
		result.Detail = "Connection-state sync evidence provider failed: " + err.Error()
		return result
	}
	if evidence == nil {
		result.Claim = "missing"
		result.Detail = "Connection-state sync evidence provider returned no evidence."
		return result
	}
	result.Provider = strings.TrimSpace(evidence.Provider)
	result.Claim = strings.TrimSpace(evidence.Claim)
	result.PeerID = strings.TrimSpace(evidence.PeerID)
	result.EvidenceID = strings.TrimSpace(evidence.EvidenceID)
	result.ObservedAt = evidence.ObservedAt.UTC()
	if result.ObservedAt.IsZero() {
		result.ObservedAt = time.Now().UTC()
	}
	result.Detail = strings.TrimSpace(evidence.Detail)
	if result.Detail == "" {
		result.Detail = fmt.Sprintf("Connection-state sync evidence provider %s reported claim %s.", labelOrUnknown(result.Provider), labelOrUnknown(result.Claim))
	}
	if expected := strings.TrimSpace(expectedPeerID); expected != "" && result.PeerID != "" && result.PeerID != expected {
		result.Claim = "peer_mismatch"
		result.Detail = fmt.Sprintf("Connection-state sync evidence peer mismatch: expected %s, got %s.", expected, result.PeerID)
	}
	return result
}

func (s *SystemService) highAvailabilityTransportEvidenceStatus() *openngfwv1.HighAvailabilityTransportEvidenceStatus {
	status := &openngfwv1.HighAvailabilityTransportEvidenceStatus{
		State:          "not_configured",
		Claim:          "not_performed",
		GarpState:      "not_requested",
		GarpDetail:     "gratuitous ARP announcement was not requested",
		NeighborState:  "not_sampled",
		NeighborDetail: "neighbor table was not sampled",
		Detail:         "No Linux-local HA VIP/route promotion evidence has been recorded.",
	}
	if s.Store == nil {
		return status
	}
	state, ok, err := s.Store.GetHighAvailabilityState()
	if err != nil {
		return &openngfwv1.HighAvailabilityTransportEvidenceStatus{
			State:  "unavailable",
			Claim:  "unavailable",
			Detail: "HA transport evidence could not be read from the local store.",
		}
	}
	if !ok {
		return status
	}
	claim := strings.TrimSpace(state.TransportClaim)
	if claim == "" {
		return status
	}
	status.Claim = claim
	status.Vip = strings.TrimSpace(state.TransportVIP)
	status.Interface = strings.TrimSpace(state.TransportInterface)
	status.Routes = append([]string(nil), state.TransportRoutes...)
	status.GarpState = strings.TrimSpace(state.TransportGARPState)
	status.GarpDetail = strings.TrimSpace(state.TransportGARPDetail)
	status.NeighborState = strings.TrimSpace(state.TransportNeighborState)
	status.NeighborDetail = strings.TrimSpace(state.TransportNeighborDetail)
	status.Detail = strings.TrimSpace(state.TransportEvidenceDetail)
	if !state.TransportEvidenceAt.IsZero() {
		status.ObservedAt = state.TransportEvidenceAt.UTC().Format(time.RFC3339)
	}
	if status.GarpState == "" {
		status.GarpState = "unknown"
	}
	if status.NeighborState == "" {
		status.NeighborState = "unknown"
	}
	switch claim {
	case "linux_local_vip_route_promoted":
		status.State = "promoted"
	case "not_performed":
		status.State = "not_performed"
	default:
		status.State = "degraded"
	}
	if status.Detail == "" {
		status.Detail = fmt.Sprintf("HA transport claim %s recorded; verify traffic cutover separately.", claim)
	}
	return status
}

func (s *SystemService) highAvailabilityConntrackSyncStatus(ctx context.Context) *openngfwv1.HighAvailabilityConntrackSyncStatus {
	status := &openngfwv1.HighAvailabilityConntrackSyncStatus{
		State:  "not_configured",
		Claim:  "not_performed",
		Detail: "Connection-state sync evidence is not configured; this API does not transfer conntrack state.",
	}
	if s.Status.HighAvailabilityConntrackSync != nil {
		evidence := s.highAvailabilityConntrackSyncEvidence(ctx, s.Status.HighAvailabilityPeerID)
		status.Provider = evidence.Provider
		status.Claim = evidence.Claim
		status.PeerId = evidence.PeerID
		status.EvidenceId = evidence.EvidenceID
		if !evidence.ObservedAt.IsZero() {
			status.ObservedAt = evidence.ObservedAt.UTC().Format(time.RFC3339)
		}
		status.Detail = evidence.Detail
		status.State = conntrackSyncState(evidence.Claim)
		return status
	}
	if s.Store == nil {
		return status
	}
	state, ok, err := s.Store.GetHighAvailabilityState()
	if err != nil {
		return &openngfwv1.HighAvailabilityConntrackSyncStatus{
			State:  "unavailable",
			Claim:  "unavailable",
			Detail: "HA conntrack-sync evidence could not be read from the local store.",
		}
	}
	if !ok {
		return status
	}
	claim := strings.TrimSpace(state.ConntrackSyncClaim)
	if claim == "" {
		return status
	}
	status.State = conntrackSyncState(claim)
	status.Provider = strings.TrimSpace(state.ConntrackSyncProvider)
	status.Claim = claim
	status.PeerId = strings.TrimSpace(state.PeerID)
	status.EvidenceId = strings.TrimSpace(state.ConntrackSyncEvidenceID)
	if !state.ConntrackSyncEvidenceAt.IsZero() {
		status.ObservedAt = state.ConntrackSyncEvidenceAt.UTC().Format(time.RFC3339)
	}
	status.Detail = strings.TrimSpace(state.ConntrackSyncEvidenceDetail)
	if status.Detail == "" {
		status.Detail = "Connection-state sync status was recorded without provider detail."
	}
	return status
}

func conntrackSyncState(claim string) string {
	switch strings.ToLower(strings.TrimSpace(claim)) {
	case "synced", "conntrack_synced", "state_synced":
		return "synced"
	case "not_performed", "not_configured", "":
		return "not_performed"
	case "unavailable", "missing", "peer_mismatch", "failed", "degraded":
		return "degraded"
	default:
		return "degraded"
	}
}

func labelOrUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return strings.TrimSpace(value)
}

func (s *SystemService) effectiveHighAvailabilityRole() string {
	role := normalizeHighAvailabilityRole(s.Status.HighAvailabilityRole)
	if s.Store == nil {
		return role
	}
	state, ok, err := s.Store.GetHighAvailabilityState()
	if err != nil || !ok {
		return role
	}
	if persisted := normalizeHighAvailabilityRole(state.Role); persisted != "unknown" {
		return persisted
	}
	return role
}

func (s *SystemService) finalizeHighAvailabilityReadiness(resp *openngfwv1.HighAvailabilityStatus) {
	if resp == nil || normalizeHighAvailabilityMode(resp.GetMode()) != "active-passive" {
		return
	}
	resp.Blockers = dedupeStrings(resp.Blockers)
	if len(resp.Blockers) > 0 {
		resp.State = "degraded"
		if resp.GetSync().GetState() == "" || resp.GetSync().GetState() == "planned" {
			resp.Sync.State = "degraded"
		}
		resp.Failover.State = "blocked"
		resp.Failover.Eligible = false
		resp.Failover.Blockers = dedupeStrings(append(resp.Failover.Blockers, resp.Blockers...))
		if strings.TrimSpace(resp.Failover.Detail) == "" || strings.Contains(resp.Failover.Detail, "not eligible") {
			resp.Failover.Detail = "Manual active/passive recovery is blocked by the listed HA readiness issues."
		}
		return
	}
	resp.State = "ready"
	resp.Detail = "Active/passive HA readiness is satisfied: peer heartbeat is fresh, roles are complementary, policy evidence is synchronized, and last-known-good metadata is present."
	if resp.GetSync().GetState() == "" || resp.GetSync().GetState() == "degraded" || resp.GetSync().GetState() == "planned" {
		resp.Sync.State = "synced"
	}
	if strings.TrimSpace(resp.GetSync().GetDetail()) == "" {
		resp.Sync.Detail = "Peer heartbeat is fresh and policy version/artifact evidence matches the local node."
	}
	resp.Failover.State = "ready"
	resp.Failover.Eligible = true
	resp.Failover.Detail = "Manual active/passive recovery is eligible from current peer heartbeat, synchronized policy, and last-known-good evidence; transport failover remains an external runbook/hardening control."
	resp.Failover.Blockers = nil
	resp.Warnings = nil
}

func normalizeHighAvailabilityMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "standalone", "single-node", "single_node":
		return "standalone"
	case "active-passive", "active_passive", "ha":
		return "active-passive"
	default:
		return "standalone"
	}
}

func (s *SystemService) applyHighAvailabilityPeerEvidence(ctx context.Context, resp *openngfwv1.HighAvailabilityStatus, localRole string) {
	cfg := s.Status
	evidence, err := cfg.HighAvailabilityPeerEvidence(ctx)
	if err != nil {
		resp.State = "degraded"
		resp.Sync.State = "degraded"
		resp.Sync.Detail = "HA peer heartbeat source could not be queried."
		resp.Blockers = append(resp.Blockers, "HA peer heartbeat is unreachable: "+err.Error())
		return
	}
	if evidence == nil {
		resp.State = "degraded"
		resp.Sync.State = "degraded"
		resp.Sync.Detail = "HA peer heartbeat source returned no evidence."
		resp.Blockers = append(resp.Blockers, "HA peer heartbeat evidence is missing.")
		return
	}

	peerRole := normalizeHighAvailabilityRole(evidence.Role)
	resp.Sync.PeerVersion = evidence.RunningPolicyVersion
	resp.Sync.PeerArtifactSetSha256 = strings.TrimSpace(evidence.ArtifactSetSHA256)
	if resp.PeerId == "" {
		resp.PeerId = strings.TrimSpace(evidence.NodeID)
	}
	if !evidence.LastHeartbeat.IsZero() {
		age := time.Since(evidence.LastHeartbeat.UTC())
		if age < 0 {
			age = 0
		}
		resp.Sync.SecondsSinceHeartbeat = uint64(age.Seconds())
	}
	blockers := highAvailabilityPeerEvidenceBlockers(resp, evidence, localRole, peerRole, cfg.HighAvailabilityHeartbeatStaleAfter)
	if len(blockers) > 0 {
		resp.State = "degraded"
		resp.Sync.State = "degraded"
		resp.Sync.Detail = strings.TrimSpace(evidence.Detail)
		if resp.Sync.Detail == "" {
			resp.Sync.Detail = "HA peer heartbeat evidence is present but not synchronized."
		}
		resp.Blockers = append(resp.Blockers, blockers...)
		return
	}
	resp.Sync.State = "synced"
	resp.Sync.Detail = strings.TrimSpace(evidence.Detail)
	if resp.Sync.Detail == "" {
		resp.Sync.Detail = "Peer heartbeat is fresh and policy version/artifact evidence matches the local node."
	}
}

func highAvailabilityPeerEvidenceBlockers(resp *openngfwv1.HighAvailabilityStatus, evidence *HighAvailabilityPeerEvidence, localRole, peerRole string, staleAfter time.Duration) []string {
	var blockers []string
	if staleAfter <= 0 {
		staleAfter = 30 * time.Second
	}
	if evidence.LastHeartbeat.IsZero() {
		blockers = append(blockers, "HA peer heartbeat timestamp is missing.")
	} else if age := time.Since(evidence.LastHeartbeat.UTC()); age > staleAfter {
		blockers = append(blockers, fmt.Sprintf("HA peer heartbeat is stale (%s old).", age.Round(time.Second)))
	}
	if expected := strings.TrimSpace(resp.GetPeerId()); expected != "" && strings.TrimSpace(evidence.NodeID) != "" && expected != strings.TrimSpace(evidence.NodeID) {
		blockers = append(blockers, fmt.Sprintf("HA peer identity mismatch: expected %s, got %s.", expected, strings.TrimSpace(evidence.NodeID)))
	}
	if localRole != "unknown" && peerRole != "unknown" && localRole == peerRole {
		blockers = append(blockers, "HA peer role matches local role; active/passive requires opposite roles.")
	}
	localVersion := resp.GetSync().GetLocalVersion()
	if localVersion == 0 {
		localVersion = resp.GetRunningPolicyVersion()
	}
	if evidence.RunningPolicyVersion > 0 && localVersion > 0 && evidence.RunningPolicyVersion != localVersion {
		blockers = append(blockers, fmt.Sprintf("HA peer policy version mismatch: local v%d, peer v%d.", localVersion, evidence.RunningPolicyVersion))
	}
	if localHash, peerHash := strings.TrimSpace(resp.GetSync().GetLocalArtifactSetSha256()), strings.TrimSpace(evidence.ArtifactSetSHA256); localHash != "" && peerHash != "" && localHash != peerHash {
		blockers = append(blockers, "HA peer artifact set hash does not match local last-known-good artifact set.")
	}
	return blockers
}

func (s *SystemService) validateHighAvailabilityPullPeer(before *openngfwv1.HighAvailabilityStatus, evidence *HighAvailabilityPeerEvidence, runningVersion uint64) error {
	if evidence == nil {
		return grpcstatus.Error(codes.FailedPrecondition, "HA peer heartbeat evidence is missing")
	}
	expectedPeerID := strings.TrimSpace(before.GetPeerId())
	if expectedPeerID != "" && strings.TrimSpace(evidence.NodeID) != expectedPeerID {
		return grpcstatus.Errorf(codes.FailedPrecondition, "HA peer identity mismatch: expected %s, got %s", expectedPeerID, strings.TrimSpace(evidence.NodeID))
	}
	if peerRole := normalizeHighAvailabilityRole(evidence.Role); peerRole != "active" {
		return grpcstatus.Errorf(codes.FailedPrecondition, "HA policy pull requires an active peer; peer role is %s", peerRole)
	}
	if evidence.LastHeartbeat.IsZero() {
		return grpcstatus.Error(codes.FailedPrecondition, "HA peer heartbeat timestamp is missing")
	}
	staleAfter := s.Status.HighAvailabilityHeartbeatStaleAfter
	if staleAfter <= 0 {
		staleAfter = 30 * time.Second
	}
	if age := time.Since(evidence.LastHeartbeat.UTC()); age > staleAfter {
		return grpcstatus.Errorf(codes.FailedPrecondition, "HA peer heartbeat is stale (%s old)", age.Round(time.Second))
	}
	if evidence.RunningPolicyVersion <= runningVersion {
		return grpcstatus.Errorf(codes.FailedPrecondition, "HA peer policy version v%d is not newer than local running version v%d", evidence.RunningPolicyVersion, runningVersion)
	}
	if strings.TrimSpace(evidence.ArtifactSetSHA256) == "" {
		return grpcstatus.Error(codes.FailedPrecondition, "HA peer artifact set hash is missing")
	}
	return nil
}

func normalizeHighAvailabilityRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "active", "primary":
		return "active"
	case "passive", "secondary", "standby":
		return "passive"
	default:
		return "unknown"
	}
}

func highAvailabilityCapabilityState(status *openngfwv1.HighAvailabilityStatus) string {
	switch status.GetState() {
	case "ready":
		return "ready"
	case "degraded":
		return "degraded"
	default:
		return "planned"
	}
}

func (s *SystemService) lastKnownGoodVersionInfo() (store.VersionInfo, bool) {
	if s.Store == nil {
		return store.VersionInfo{}, false
	}
	infos, err := s.Store.ListVersions(0)
	if err != nil {
		return store.VersionInfo{}, false
	}
	for _, info := range infos {
		if info.LastKnownGood {
			return info, true
		}
	}
	return store.VersionInfo{}, false
}

// GetReleaseAcceptanceStatus reports the configured release acceptance gate
// state through the canonical API without letting clients choose filesystem
// paths or mutate release artifacts.
func (s *SystemService) GetReleaseAcceptanceStatus(_ context.Context, _ *openngfwv1.GetReleaseAcceptanceStatusRequest) (*openngfwv1.GetReleaseAcceptanceStatusResponse, error) {
	cfg := s.Status
	report := releaseacceptance.BuildStatusReport(releaseacceptance.StatusOptions{
		ManifestPath:             cfg.ReleaseAcceptanceManifestPath,
		EvidenceDir:              cfg.ReleaseEvidenceDir,
		ExpectedCommit:           version.Commit,
		ExpectedVersion:          version.Version,
		AllowNoPerformanceClaims: cfg.ReleaseNoPerformanceClaims,
		IncludeRecordability:     true,
	})
	return releaseAcceptanceStatusProto(report), nil
}

func releaseAcceptanceStatusProto(report releaseacceptance.StatusReport) *openngfwv1.GetReleaseAcceptanceStatusResponse {
	resp := &openngfwv1.GetReleaseAcceptanceStatusResponse{
		SchemaVersion:   report.SchemaVersion,
		GeneratedAt:     report.GeneratedAt,
		ManifestPath:    releaseAcceptanceDisclosureString(report.ManifestPath),
		EvidenceDir:     releaseAcceptanceDisclosureString(report.EvidenceDir),
		ManifestPresent: report.ManifestPresent,
		Ready:           report.Ready,
		State:           report.State,
		Summary: &openngfwv1.ReleaseAcceptanceStatusSummary{
			Passed:        uint32Count(report.Summary.Passed),
			Recorded:      uint32Count(report.Summary.Recorded),
			Missing:       uint32Count(report.Summary.Missing),
			Invalid:       uint32Count(report.Summary.Invalid),
			NotApplicable: uint32Count(report.Summary.NotApplicable),
			Todo:          uint32Count(report.Summary.Todo),
		},
		Problems: releaseAcceptanceDisclosureStrings(report.Problems),
		Checks:   make([]*openngfwv1.ReleaseAcceptanceCheckStatus, 0, len(report.Checks)),
	}
	if report.Recordability != nil {
		resp.Recordability = releaseAcceptanceRecordabilityProto(*report.Recordability)
	}
	for _, check := range report.Checks {
		resp.Checks = append(resp.Checks, &openngfwv1.ReleaseAcceptanceCheckStatus{
			Name:             releaseAcceptanceDisclosureString(check.Name),
			State:            releaseAcceptanceDisclosureString(check.State),
			Artifact:         releaseAcceptanceDisclosureString(check.Artifact),
			EvidencePath:     releaseAcceptanceDisclosureString(check.EvidencePath),
			BenchmarkSummary: releaseAcceptanceDisclosureString(check.BenchmarkSummary),
			RanAt:            releaseAcceptanceDisclosureString(check.RanAt),
			Detail:           releaseAcceptanceDisclosureString(check.Detail),
			Command:          releaseAcceptanceDisclosureStrings(check.Command),
			Problems:         releaseAcceptanceDisclosureStrings(check.Problems),
			NextAction:       releaseAcceptanceDisclosureString(check.NextAction),
			NextCommand:      releaseAcceptanceDisclosureStrings(check.NextCommand),
		})
	}
	return resp
}

func releaseAcceptanceRecordabilityProto(status releaseacceptance.RecordabilityStatus) *openngfwv1.ReleaseAcceptanceRecordabilityStatus {
	return &openngfwv1.ReleaseAcceptanceRecordabilityStatus{
		Ready:              status.Ready,
		GitHead:            releaseAcceptanceDisclosureString(status.GitHead),
		RecordCommit:       releaseAcceptanceDisclosureString(status.RecordCommit),
		AllowedDirtyPaths:  releaseAcceptanceDisclosureStrings(status.AllowedDirtyPaths),
		DirtySourcePaths:   releaseAcceptanceDisclosureStrings(status.DirtySourcePaths),
		Problems:           releaseAcceptanceDisclosureStrings(status.Problems),
		StaleEvidencePaths: releaseAcceptanceDisclosureStrings(status.StaleEvidencePaths),
	}
}

func releaseAcceptanceDisclosureStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, releaseAcceptanceDisclosureString(value))
	}
	return out
}

func releaseAcceptanceDisclosureString(value string) string {
	value = releaseBearerRE.ReplaceAllString(value, "Bearer [redacted]")
	value = releaseSecretRE.ReplaceAllString(value, "${1}${2}[redacted]")
	return releaseLocalPathRE.ReplaceAllString(value, "$1[server-local path redacted]")
}

func uint32Count(n int) uint32 {
	if n <= 0 {
		return 0
	}
	return uint32(n)
}

func (s *SystemService) runningPolicyVersion() uint64 {
	if s.Store == nil {
		return 0
	}
	_, version, err := s.Store.GetRunning()
	if err != nil {
		return 0
	}
	return version
}

func (s *SystemService) runningDynamicRoutingEnabled() bool {
	if s.Store == nil {
		return false
	}
	policy, _, err := s.Store.GetRunning()
	if err != nil || policy == nil {
		return false
	}
	return policy.GetRouting().GetBgp().GetEnabled() || policy.GetRouting().GetOspf().GetEnabled()
}

func (s *SystemService) inspectionStatus(engines []*openngfwv1.EngineStatus) *openngfwv1.InspectionStatus {
	engine := findEngineStatus(engines, "suricata")
	resp := &openngfwv1.InspectionStatus{
		State:           "disabled",
		Detail:          "No running policy requires IDS/IPS inspection.",
		InspectionState: "not-inspected",
		EngineName:      "suricata",
		EngineRequired:  false,
		DegradedBehavior: "L3/L4 forwarding is controlled by firewall policy; no userspace IDS/IPS " +
			"inspection engine is attached to the running policy path.",
	}
	if engine != nil {
		resp.EngineName = engine.GetName()
		resp.EngineMode = engine.GetMode()
		resp.EngineState = engine.GetState()
	}
	if s.Store == nil {
		return resp
	}
	running, _, err := s.Store.GetRunning()
	if err != nil {
		resp.State = "unknown"
		resp.Detail = "Running policy could not be read for inspection readiness: " + err.Error()
		resp.EngineRequired = true
		return resp
	}
	ids := running.GetIds()
	if ids == nil || !ids.GetEnabled() {
		return resp
	}

	resp.IdsEnabled = true
	resp.IdsMode = ids.GetMode()
	resp.FailureBehavior = ids.GetFailureBehavior()
	resp.EngineRequired = true

	switch ids.GetMode() {
	case openngfwv1.IdsMode_IDS_MODE_DETECT:
		resp.InspectionState = "ids-detect"
		resp.BypassPossible = true
		resp.BypassReason = "IDS detect mode is passive telemetry; traffic continues if Suricata is unavailable."
		resp.DegradedBehavior = "fail-open by design: detection events are degraded, but L3/L4 forwarding continues."
		if engineActive(engine) {
			resp.State = "ready"
			resp.Detail = "Suricata is active for IDS detect mode."
			return resp
		}
		resp.State = "degraded"
		resp.Detail = "IDS detect mode is enabled but Suricata is not active (" + inspectionEngineState(engine) + ")."
		return resp
	case openngfwv1.IdsMode_IDS_MODE_PREVENT:
		resp.InspectionState = "ips-prevent"
		switch ids.GetFailureBehavior() {
		case openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_OPEN:
			resp.BypassPossible = true
			resp.BypassReason = "ids.failure_behavior is fail-open; if Suricata/NFQUEUE is unavailable, queued packets bypass inspection."
			resp.DegradedBehavior = "fail-open: degraded inspection preserves availability but traffic can bypass userspace prevention."
			if engineActive(engine) {
				resp.State = "ready"
				resp.Detail = "Suricata is active for IPS prevent mode; fail-open behavior is policy-visible if the engine degrades."
				return resp
			}
			resp.State = "failed-open"
			resp.Detail = "IPS prevent mode is fail-open and Suricata is not active (" + inspectionEngineState(engine) + "); traffic can bypass inspection."
			return resp
		case openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED:
			resp.BypassPossible = false
			resp.BypassReason = ""
			resp.DegradedBehavior = "fail-closed: degraded inspection holds or drops queued traffic instead of bypassing prevention."
			if engineActive(engine) {
				resp.State = "ready"
				resp.Detail = "Suricata is active for IPS prevent mode; fail-closed behavior is policy-visible if the engine degrades."
				return resp
			}
			resp.State = "failed-closed"
			resp.Detail = "IPS prevent mode is fail-closed and Suricata is not active (" + inspectionEngineState(engine) + "); queued traffic may be held or dropped."
			return resp
		default:
			resp.State = "degraded"
			resp.Detail = "IPS prevent mode is enabled but ids.failure_behavior is not set to fail-open or fail-closed."
			resp.DegradedBehavior = "policy validation rejects this state before commit; inspect the running policy store."
			return resp
		}
	default:
		resp.State = "degraded"
		resp.Detail = "IDS/IPS is enabled with an unknown mode."
		resp.DegradedBehavior = "policy validation rejects this state before commit; inspect the running policy store."
		return resp
	}
}

func findEngineStatus(engines []*openngfwv1.EngineStatus, name string) *openngfwv1.EngineStatus {
	for _, engine := range engines {
		if strings.EqualFold(engine.GetName(), name) {
			return engine
		}
	}
	return nil
}

func engineActive(engine *openngfwv1.EngineStatus) bool {
	return engine != nil && engine.GetState() == "active"
}

func inspectionEngineState(engine *openngfwv1.EngineStatus) string {
	if engine == nil {
		return "not reported"
	}
	if engine.GetState() == "" {
		return "unknown"
	}
	return engine.GetState()
}

func inspectionCapabilityState(status *openngfwv1.InspectionStatus) string {
	switch status.GetState() {
	case "ready", "disabled":
		return "ready"
	default:
		return "degraded"
	}
}

func inspectionWarning(status *openngfwv1.InspectionStatus) *openngfwv1.StatusWarning {
	switch status.GetState() {
	case "failed-open":
		return &openngfwv1.StatusWarning{
			Severity: "critical",
			Message:  "IPS prevent is degraded fail-open; traffic can bypass inspection.",
			Action:   "Restore Suricata/NFQUEUE health or change policy to fail-closed before relying on threat prevention.",
		}
	case "failed-closed":
		return &openngfwv1.StatusWarning{
			Severity: "critical",
			Message:  "IPS prevent is degraded fail-closed; traffic may be held or dropped.",
			Action:   "Restore Suricata/NFQUEUE health before relying on forwarding availability.",
		}
	case "degraded":
		return &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  "IDS/IPS inspection policy is enabled but inspection readiness is degraded.",
			Action:   "Inspect the inspection status, Suricata process state, and policy failure behavior.",
		}
	case "unknown":
		return &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  "IDS/IPS inspection readiness is unknown.",
			Action:   status.GetDetail(),
		}
	default:
		return nil
	}
}

func (s *SystemService) degradedEngineDataplaneEvidence(cfg SystemStatusConfig, engines []*openngfwv1.EngineStatus, inspection *openngfwv1.InspectionStatus, statefulState, statefulDetail, flowtableState, flowtableDetail string) (string, string, *openngfwv1.StatusWarning) {
	running, version := s.runningPolicyForEvidence()
	var degraded []string
	var impact []string
	var limitations []string

	if !statusReady(statefulState) {
		degraded = append(degraded, "nftables="+firstNonEmpty(statefulState, "unknown"))
		impact = append(impact, "stateful firewall/L3-L4 forwarding policy: "+firstNonEmpty(statefulDetail, "nftables readiness is not reported"))
	}
	if policyRequestsFlowOffload(running) && !statusReadyOrActive(flowtableState) {
		degraded = append(degraded, "nftables-flowtable="+firstNonEmpty(flowtableState, "unknown"))
		impact = append(impact, "fast-path policy: "+firstNonEmpty(flowtableDetail, "flowtable runtime evidence is not active"))
	}
	if inspection.GetEngineRequired() && inspection.GetState() != "ready" {
		degraded = append(degraded, "suricata="+firstNonEmpty(inspection.GetEngineState(), inspection.GetState(), "unknown"))
		mode := inspection.GetIdsMode().String()
		failure := inspection.GetFailureBehavior().String()
		exceptions := 0
		if running != nil && running.GetIds() != nil {
			exceptions = len(running.GetIds().GetExceptions())
		}
		impact = append(impact, fmt.Sprintf("IDS/IPS Threat-ID policy: %s; mode=%s failure=%s false_positive_exceptions=%d", inspection.GetDetail(), mode, failure, exceptions))
	}
	if telemetryPolicyActive(running) {
		vector := findEngineStatus(engines, "vector")
		if vector == nil || !engineReadyOrActive(vector) {
			degraded = append(degraded, "vector="+engineStateLabel(vector))
			impact = append(impact, "telemetry/export evidence: Vector is required by running telemetry policy but is "+engineStateLabel(vector))
		}
	}
	if proxyPolicyActive(running) {
		proxy := findProxyEngineStatus(engines)
		if proxy == nil || !engineReadyOrActive(proxy) {
			degraded = append(degraded, "proxy="+engineStateLabel(proxy))
			impact = append(impact, "Proxy/WAF policy: listener and WAF runtime evidence requires a proxy engine; current state is "+engineStateLabel(proxy))
		}
	}

	limitations = append(limitations,
		"unsigned runtime summary only",
		"no packet-capture proof",
		"no remote peer attestation",
		"no signed field-evidence custody",
		"no production certification claim",
	)
	scope := fmt.Sprintf("running_policy_version=%d active_dataplane=%s engines=%s", version, firstNonEmpty(cfg.ActiveDataplane, "nftables/conntrack"), strings.Join(engineEvidenceNames(engines), ","))
	if len(degraded) == 0 {
		detail := scope + "; no degraded required Suricata/Vector/proxy/nftables dependency detected from bounded status inputs; limitations=" + strings.Join(limitations, "; ")
		return "ready", detail, nil
	}
	detail := scope + "; degraded=" + strings.Join(dedupeStrings(degraded), ", ") + "; impacted=" + strings.Join(dedupeStrings(impact), " | ") + "; limitations=" + strings.Join(limitations, "; ")
	return "degraded", detail, &openngfwv1.StatusWarning{
		Severity: "warning",
		Message:  "Degraded engine dataplane evidence affects policy posture.",
		Action:   detail + ". Review fail-open/fail-closed behavior before relying on Threat-ID prevention or false-positive controls.",
	}
}

func (s *SystemService) runningPolicyForEvidence() (*openngfwv1.Policy, uint64) {
	if s == nil || s.Store == nil {
		return nil, 0
	}
	policy, version, err := s.Store.GetRunning()
	if err != nil {
		return nil, 0
	}
	return policy, version
}

func statusReady(state string) bool {
	return state == "ready" || state == "active"
}

func statusReadyOrActive(state string) bool {
	return statusReady(state)
}

func engineReadyOrActive(engine *openngfwv1.EngineStatus) bool {
	return engine != nil && statusReady(engine.GetState())
}

func engineStateLabel(engine *openngfwv1.EngineStatus) string {
	if engine == nil {
		return "not-reported"
	}
	return firstNonEmpty(engine.GetState(), "unknown")
}

func telemetryPolicyActive(policy *openngfwv1.Policy) bool {
	telemetry := policy.GetTelemetry()
	if telemetry == nil {
		return false
	}
	if telemetry.GetEnabled() {
		return true
	}
	for _, export := range telemetry.GetExports() {
		if export.GetEnabled() {
			return true
		}
	}
	return false
}

func proxyPolicyActive(policy *openngfwv1.Policy) bool {
	proxy := policy.GetProxy()
	if proxy == nil {
		return false
	}
	if len(proxy.GetVirtualServices()) > 0 || len(proxy.GetWafPolicies()) > 0 {
		return true
	}
	return false
}

func findProxyEngineStatus(engines []*openngfwv1.EngineStatus) *openngfwv1.EngineStatus {
	for _, name := range []string{"proxy", "envoy", "coraza"} {
		if engine := findEngineStatus(engines, name); engine != nil {
			return engine
		}
	}
	for _, engine := range engines {
		text := strings.ToLower(strings.Join([]string{engine.GetName(), engine.GetRole(), engine.GetDetail()}, " "))
		if strings.Contains(text, "proxy") || strings.Contains(text, "waf") || strings.Contains(text, "envoy") || strings.Contains(text, "coraza") {
			return engine
		}
	}
	return nil
}

func engineEvidenceNames(engines []*openngfwv1.EngineStatus) []string {
	names := make([]string, 0, len(engines))
	for _, engine := range engines {
		if name := strings.TrimSpace(engine.GetName()); name != "" {
			names = append(names, name+":"+firstNonEmpty(engine.GetState(), "unknown"))
		}
	}
	if len(names) == 0 {
		return []string{"none-reported"}
	}
	sort.Strings(names)
	return names
}

func contentPackageReadiness(cfg SystemStatusConfig) (string, string, []*openngfwv1.StatusWarning) {
	if strings.TrimSpace(cfg.ContentDir) == "" {
		return "unknown", "content package directory is not configured", nil
	}
	statuses, err := contentpkg.Statuses(cfg.ContentDir)
	if err != nil {
		return "degraded", "content package status could not be read: " + err.Error(), []*openngfwv1.StatusWarning{{
			Severity: "warning",
			Message:  "Content package verification is unavailable.",
			Action:   "Inspect the content directory and package manifests before production enforcement: " + err.Error(),
		}}
	}
	if len(statuses) == 0 {
		return "degraded", "no content package statuses were returned", []*openngfwv1.StatusWarning{{
			Severity: "warning",
			Message:  "Content package verification returned no packages.",
			Action:   "Install verified App-ID, Threat-ID, and feed content packages before production enforcement.",
		}}
	}
	var verified int
	var blockers []string
	for _, st := range statuses {
		if st.State == "verified" {
			verified++
		}
		for _, blocker := range st.Blockers {
			blockers = append(blockers, st.Kind+": "+blocker)
		}
	}
	if len(blockers) == 0 {
		return "ready", fmt.Sprintf("%d/%d content package(s) verified", verified, len(statuses)), nil
	}
	blockers = dedupeStrings(blockers)
	detail := fmt.Sprintf("%d/%d content package(s) verified; %d blocker(s): %s", verified, len(statuses), len(blockers), strings.Join(limitStrings(blockers, 6), ", "))
	return "degraded", detail, []*openngfwv1.StatusWarning{{
		Severity: "warning",
		Message:  "Content package verification is incomplete.",
		Action:   detail + ". Install signed, regression-passed packages with rollout and rollback metadata.",
	}}
}

// RuntimeReadinessWarnings returns the server-side production blockers and
// warnings that require explicit acknowledgement before a live policy apply.
// The target and running policies let commit/rollback enforce dataplane checks
// that depend on the policy being applied, not just global host posture.
func (s *SystemService) RuntimeReadinessWarnings(ctx context.Context, target, running *openngfwv1.Policy) ([]string, error) {
	resp, err := s.GetStatus(ctx, &openngfwv1.GetStatusRequest{})
	if err != nil {
		return nil, err
	}
	out := runtimeReadinessWarnings(resp, target, running)
	if policyRequestsThreatInspection(target) {
		if warning := threatIDProductionReadinessWarning(s.Status); warning != "" {
			out = append(out, warning)
		}
	}
	return dedupeStrings(out), nil
}

func runtimeReadinessWarnings(resp *openngfwv1.GetStatusResponse, target, running *openngfwv1.Policy) []string {
	if resp == nil {
		return []string{"runtime status endpoint returned no response"}
	}
	var out []string
	if resp.GetRuntime().GetDryRun() {
		out = append(out, "Daemon is running in dry-run mode")
	}
	for _, warning := range resp.GetWarnings() {
		switch warning.GetSeverity() {
		case "critical", "warning":
			out = append(out, compactRuntimeReadinessItem(warning.GetMessage(), warning.GetAction()))
		}
	}
	for _, capability := range resp.GetCapabilities() {
		switch capability.GetState() {
		case "degraded", "missing-prerequisites", "failed":
			out = append(out, compactRuntimeReadinessItem(capability.GetName()+" is "+capability.GetState(), capability.GetDetail()))
		}
	}
	out = append(out, policyRuntimeReadinessWarnings(resp, target, running)...)
	return dedupeStrings(out)
}

func runtimeReadinessPreflight(operation string, warnings []string) *openngfwv1.CheckRuntimeReadinessResponse {
	operation = normalizeRuntimeReadinessOperation(operation)
	warnings = dedupeStrings(warnings)
	resp := &openngfwv1.CheckRuntimeReadinessResponse{
		SchemaVersion: "phragma.runtime-readiness.v1",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Operation:     operation,
		Warnings:      warnings,
	}
	if len(warnings) == 0 {
		resp.Label = "ready"
		resp.Cls = "ok"
		resp.RequiresAck = false
		resp.Detail = "Runtime readiness checks passed for " + operation + "."
		return resp
	}
	resp.Label = "not ready"
	resp.Cls = "bad"
	resp.RequiresAck = true
	resp.Detail = fmt.Sprintf("Runtime readiness reported %d warning(s) before %s.", len(warnings), operation)
	resp.Items = make([]*openngfwv1.RuntimeReadinessItem, 0, len(warnings))
	for _, warning := range warnings {
		resp.Items = append(resp.Items, runtimeReadinessItem(warning))
	}
	return resp
}

func runtimeReadinessUnavailablePreflight(operation string, err error) *openngfwv1.CheckRuntimeReadinessResponse {
	operation = normalizeRuntimeReadinessOperation(operation)
	detail := "The status endpoint did not respond."
	if err != nil && strings.TrimSpace(err.Error()) != "" {
		detail = strings.TrimSpace(err.Error())
	}
	item := &openngfwv1.RuntimeReadinessItem{
		Id:      "runtime-status-unavailable",
		Level:   "medium",
		Badge:   "warning",
		Title:   "Runtime status unavailable",
		Detail:  detail,
		Command: "ngfwctl status",
	}
	return &openngfwv1.CheckRuntimeReadinessResponse{
		SchemaVersion: "phragma.runtime-readiness.v1",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Operation:     operation,
		Label:         "unknown",
		Cls:           "warn",
		RequiresAck:   true,
		Detail:        "Runtime status could not be loaded before " + operation + ".",
		Items:         []*openngfwv1.RuntimeReadinessItem{item},
		Warnings:      []string{compactRuntimeReadinessItem(item.GetTitle(), item.GetDetail())},
	}
}

func runtimeReadinessItem(warning string) *openngfwv1.RuntimeReadinessItem {
	title, detail := splitRuntimeReadinessWarning(warning)
	id := runtimeReadinessItemID(title)
	if id == "" {
		id = "runtime-readiness-warning"
	}
	return &openngfwv1.RuntimeReadinessItem{
		Id:      id,
		Level:   "high",
		Badge:   "runtime",
		Title:   title,
		Detail:  detail,
		Command: "ngfwctl status",
	}
}

func splitRuntimeReadinessWarning(warning string) (string, string) {
	warning = strings.TrimSpace(warning)
	if warning == "" {
		return "Runtime readiness warning", "Review runtime status before applying this policy."
	}
	if before, after, ok := strings.Cut(warning, ":"); ok {
		title := strings.TrimSpace(before)
		detail := strings.TrimSpace(after)
		if title != "" && detail != "" {
			return title, detail
		}
	}
	return warning, "Review this runtime readiness warning before applying this policy."
}

func runtimeReadinessItemID(title string) string {
	title = strings.ToLower(strings.TrimSpace(title))
	var b strings.Builder
	lastDash := false
	for _, r := range title {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func normalizeRuntimeReadinessOperation(operation string) string {
	switch strings.ToLower(strings.TrimSpace(operation)) {
	case "rollback":
		return "rollback"
	default:
		return "commit"
	}
}

func policyRuntimeReadinessWarnings(resp *openngfwv1.GetStatusResponse, target, running *openngfwv1.Policy) []string {
	if resp == nil {
		return nil
	}
	var out []string
	flowtable := resp.GetDataplane().GetFlowtable()
	if policyRequestsFlowOffload(target) {
		hostState := firstNonEmpty(flowtable.GetHostState(), statusCapabilityState(resp.GetCapabilities(), "nftables flowtable fast path"))
		hostDetail := firstNonEmpty(flowtable.GetHostDetail(), statusCapabilityDetail(resp.GetCapabilities(), "nftables flowtable fast path"))
		if hostState != "" && hostState != "ready" && hostState != "active" {
			out = append(out, compactRuntimeReadinessItem("nftables flowtable fast path is "+hostState, hostDetail))
		}
	}

	if !policyRequestsFlowOffload(running) {
		return out
	}
	runtimeState := firstNonEmpty(flowtable.GetRuntimeState(), statusCapabilityState(resp.GetCapabilities(), "nftables flowtable runtime"))
	runtimeDetail := firstNonEmpty(flowtable.GetRuntimeDetail(), statusCapabilityDetail(resp.GetCapabilities(), "nftables flowtable runtime"))
	if runtimeState != "" && runtimeState != "active" {
		out = append(out, compactRuntimeReadinessItem("nftables flowtable runtime is "+runtimeState, runtimeDetail))
	}
	return out
}

func policyRequestsFlowOffload(p *openngfwv1.Policy) bool {
	return p != nil && p.GetNetwork().GetEnableFlowOffload()
}

func policyRequestsThreatInspection(p *openngfwv1.Policy) bool {
	return p != nil && p.GetIds().GetEnabled()
}

func threatIDProductionReadinessWarning(cfg SystemStatusConfig) string {
	if strings.TrimSpace(cfg.ContentDir) == "" {
		return "IDS/IPS is enabled but Threat-ID content package readiness is unknown: content package directory is not configured"
	}
	statuses, err := contentpkg.Statuses(cfg.ContentDir)
	if err != nil {
		return "IDS/IPS is enabled but Threat-ID content package readiness is unavailable: " + err.Error()
	}
	for _, st := range statuses {
		if st.Kind != "threat-id" {
			continue
		}
		readiness := st.ContentReadiness
		if st.State == "verified" && readiness.ProductionReady {
			return ""
		}
		blockers := dedupeStrings(append(append([]string{}, st.Blockers...), readiness.Blockers...))
		detail := fmt.Sprintf("state=%s signature_status=%s regression_status=%s evidence_status=%s production_content=%t production_ready=%t",
			st.State, st.SignatureStatus, st.RegressionStatus, readiness.EvidenceStatus, readiness.ProductionContent, readiness.ProductionReady)
		if len(blockers) > 0 {
			detail += " blockers=" + strings.Join(limitStrings(blockers, 8), ", ")
		}
		return "IDS/IPS is enabled but Threat-ID content is not production-ready: " + detail
	}
	return "IDS/IPS is enabled but Threat-ID content package status is missing"
}

func statusCapabilityState(caps []*openngfwv1.SystemCapability, name string) string {
	for _, cap := range caps {
		if cap.GetName() == name {
			return cap.GetState()
		}
	}
	return ""
}

func statusCapabilityDetail(caps []*openngfwv1.SystemCapability, name string) string {
	for _, cap := range caps {
		if cap.GetName() == name {
			return cap.GetDetail()
		}
	}
	return ""
}

func firstNonEmpty(items ...string) string {
	for _, item := range items {
		if item != "" {
			return item
		}
	}
	return ""
}

func compactRuntimeReadinessItem(title, detail string) string {
	title = strings.TrimSpace(title)
	detail = strings.TrimSpace(detail)
	switch {
	case title == "":
		return detail
	case detail == "":
		return title
	default:
		return title + ": " + detail
	}
}

func dedupeStrings(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func limitStrings(items []string, maxItems int) []string {
	if maxItems <= 0 || len(items) <= maxItems {
		return items
	}
	out := append([]string(nil), items[:maxItems]...)
	out = append(out, fmt.Sprintf("%d more", len(items)-maxItems))
	return out
}

func managementPlaneStatus(cfg SystemStatusConfig) *openngfwv1.ManagementPlaneStatus {
	return &openngfwv1.ManagementPlaneStatus{
		TlsEnabled:                 cfg.TLSEnabled,
		AuthEnabled:                cfg.AuthEnabled,
		RateLimitEnabled:           cfg.RateLimitRPM > 0,
		RateLimitRequestsPerMinute: nonnegativeUint32(cfg.RateLimitRPM),
		RateLimitBurst:             nonnegativeUint32(cfg.RateLimitBurst),
		HttpMaxBodyBytes:           nonnegativeUint64(cfg.HTTPMaxBodyBytes),
		HttpMaxHeaderBytes:         nonnegativeUint32(cfg.HTTPMaxHeaderBytes),
		GrpcMaxRecvBytes:           nonnegativeUint32(cfg.GRPCMaxRecvBytes),
		GrpcMaxSendBytes:           nonnegativeUint32(cfg.GRPCMaxSendBytes),
		HttpReadHeaderTimeout:      durationString(cfg.HTTPReadHeaderTimeout),
		HttpReadTimeout:            durationString(cfg.HTTPReadTimeout),
		HttpWriteTimeout:           durationString(cfg.HTTPWriteTimeout),
		HttpIdleTimeout:            durationString(cfg.HTTPIdleTimeout),
		TrustedProxyCidrs:          dedupeStrings(cfg.TrustedProxyCIDRs),
		RateLimitClientIdentity:    rateLimitClientIdentity(cfg),
	}
}

func rateLimitClientIdentity(cfg SystemStatusConfig) string {
	if cfg.RateLimitRPM <= 0 {
		return "disabled"
	}
	if len(dedupeStrings(cfg.TrustedProxyCIDRs)) > 0 {
		return "rightmost-untrusted-x-forwarded-for"
	}
	return "socket-peer"
}

func managementGuardrailCapability(cfg SystemStatusConfig) (string, string) {
	var issues []string
	if cfg.HTTPListen != "" && !cfg.TLSEnabled {
		issues = append(issues, "TLS disabled")
	}
	if cfg.PublicSelfSignedTLS {
		issues = append(issues, "public listener uses generated self-signed TLS")
	}
	if !cfg.AuthEnabled {
		issues = append(issues, "authentication disabled")
	}
	if cfg.OIDCEnabled && !cfg.OIDCCookieSecure {
		issues = append(issues, "OIDC session cookie not secure")
	}
	if cfg.RateLimitRPM <= 0 {
		issues = append(issues, "rate limit disabled")
	}
	if cfg.HTTPListen != "" && cfg.HTTPMaxBodyBytes <= 0 {
		issues = append(issues, "REST body cap disabled")
	}
	if cfg.GRPCMaxRecvBytes <= 0 || cfg.GRPCMaxSendBytes <= 0 {
		issues = append(issues, "gRPC message cap not explicit")
	}
	if cfg.HTTPListen != "" && (cfg.HTTPReadHeaderTimeout <= 0 || cfg.HTTPReadTimeout <= 0 || cfg.HTTPWriteTimeout <= 0 || cfg.HTTPIdleTimeout <= 0) {
		issues = append(issues, "REST timeout disabled")
	}
	if len(issues) > 0 {
		return "degraded", strings.Join(issues, "; ")
	}
	return "ready", "TLS/auth/rate limits, request-size caps, gRPC message caps, and HTTP timeouts are configured"
}

func managementWarnings(cfg SystemStatusConfig) []*openngfwv1.StatusWarning {
	var warnings []*openngfwv1.StatusWarning
	if cfg.PublicSelfSignedTLS {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "critical",
			Message:  "Public REST/WebUI listener uses generated self-signed TLS.",
			Action:   "Use only a controlled temporary lab path such as an SSH tunnel or explicit browser exception, then replace it with an operator-provided --tls-cert and --tls-key before production.",
		})
	}
	if cfg.RateLimitRPM <= 0 {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  "API rate limiting is disabled.",
			Action:   "Start controld with --rate-limit-rpm greater than 0 except during isolated debugging.",
		})
	}
	if cfg.OIDCEnabled && !cfg.OIDCCookieSecure {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "critical",
			Message:  "OIDC browser sessions are not using Secure cookies.",
			Action:   "Use an https --oidc-redirect-url, or terminate TLS in controld, so browser session cookies are sent only over HTTPS.",
		})
	}
	if cfg.RateLimitRPM > 0 && cfg.HTTPListen != "" && !isLoopbackListenAddress(cfg.HTTPListen) && len(dedupeStrings(cfg.TrustedProxyCIDRs)) == 0 {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  "REST/WebUI rate limiting keys clients by socket peer only.",
			Action:   "Set --trusted-proxy-cidrs when exposing REST/WebUI through a reverse proxy or non-source-preserving load balancer.",
		})
	}
	if cfg.HTTPListen != "" && cfg.HTTPMaxBodyBytes <= 0 {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  "REST/WebUI request body size is not explicitly capped.",
			Action:   "Set --http-max-body-bytes to a bounded value.",
		})
	}
	if cfg.GRPCMaxRecvBytes <= 0 || cfg.GRPCMaxSendBytes <= 0 {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  "Direct gRPC message size limits are not fully explicit.",
			Action:   "Set --grpc-max-recv-bytes and --grpc-max-send-bytes to bounded values.",
		})
	}
	if cfg.HTTPListen != "" && (cfg.HTTPReadHeaderTimeout <= 0 || cfg.HTTPReadTimeout <= 0 || cfg.HTTPWriteTimeout <= 0 || cfg.HTTPIdleTimeout <= 0) {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  "REST/WebUI HTTP timeouts are not fully configured.",
			Action:   "Set --http-read-header-timeout, --http-read-timeout, --http-write-timeout, and --http-idle-timeout.",
		})
	}
	return warnings
}

func isLoopbackListenAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func durationString(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return d.String()
}

func normalizeTuneProfile(profile string) string {
	profile = strings.ToLower(strings.TrimSpace(profile))
	if profile == "" {
		return tuning.DefaultProfile
	}
	return profile
}

func plannedTuneResults(profile string) []*openngfwv1.TuneHostResult {
	reqs, err := tuning.RequirementsForProfile(profile)
	if err != nil {
		return nil
	}
	out := make([]*openngfwv1.TuneHostResult, 0, len(reqs))
	for _, req := range reqs {
		out = append(out, &openngfwv1.TuneHostResult{
			Key:    req.Key,
			Value:  req.Value,
			State:  "planned",
			Detail: req.Detail,
		})
	}
	return out
}

func appliedTuneResults(results []tuning.ApplyResult) []*openngfwv1.TuneHostResult {
	out := make([]*openngfwv1.TuneHostResult, 0, len(results))
	for _, result := range results {
		state := "pending"
		switch {
		case result.Applied:
			state = "applied"
		case result.Skipped:
			state = "skipped"
		}
		out = append(out, &openngfwv1.TuneHostResult{
			Key:    result.Key,
			Value:  result.Value,
			State:  state,
			Detail: result.Detail,
		})
	}
	return out
}

func (s *SystemService) auditHostTune(ctx context.Context, action, detail string) error {
	if s.Store == nil {
		return nil
	}
	identity := auditIdentity(ctx)
	return s.Store.AppendAudit(store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role,
		AuthSource: identity.AuthSource,
		Action:     action,
		Detail:     detail,
	})
}

func (s *SystemService) auditHostTuneFailure(ctx context.Context, profile, configPath string, write, apply bool, results []*openngfwv1.TuneHostResult, stage, message string) {
	detail := tuneAuditDetail(profile, configPath, write, apply, results)
	if stage != "" {
		detail += " stage=" + compactAuditField(stage)
	}
	if message != "" {
		detail += " error=" + compactAuditField(message)
	}
	_ = s.auditHostTune(ctx, "system-tune-failed", detail)
}

func (s *SystemService) auditAccessSession(ctx context.Context, action, detail string) error {
	if s.Store == nil {
		return nil
	}
	identity := auditIdentity(ctx)
	return s.Store.AppendAudit(store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role,
		AuthSource: identity.AuthSource,
		Action:     action,
		Detail:     detail,
	})
}

func (s *SystemService) auditAccessSessionFailure(ctx context.Context, sessionID, stage, message string) {
	detail := accessSessionAuditDetail(sessionID, authz.OIDCSessionRecord{}, "")
	if stage != "" {
		detail += " stage=" + compactAuditField(stage)
	}
	if message != "" {
		detail += " error=" + compactAuditField(message)
	}
	_ = s.auditAccessSession(ctx, "access-session-revoke-failed", detail)
}

func (s *SystemService) auditAccessLocalUser(ctx context.Context, action, detail string) error {
	if s.Store == nil {
		return nil
	}
	identity := auditIdentity(ctx)
	return s.Store.AppendAudit(store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role,
		AuthSource: identity.AuthSource,
		Action:     action,
		Detail:     detail,
	})
}

func (s *SystemService) auditAccessLocalUserFailure(ctx context.Context, action, name, role, stage, message string) {
	detail := accessLocalUserAuditDetail(name, role, authz.LocalUserInventory{}, "")
	if stage != "" {
		detail += " stage=" + compactAuditField(stage)
	}
	if message != "" {
		detail += " error=" + compactAuditField(message)
	}
	_ = s.auditAccessLocalUser(ctx, action, detail)
}

func (s *SystemService) auditOIDCProvider(ctx context.Context, action, detail string) error {
	if s.Store == nil {
		return nil
	}
	identity := auditIdentity(ctx)
	return s.Store.AppendAudit(store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role,
		AuthSource: identity.AuthSource,
		Action:     action,
		Detail:     detail,
	})
}

func (s *SystemService) auditOIDCProviderFailure(ctx context.Context, action string, cfg authz.OIDCProviderConfig, stage, message string) {
	detail := oidcProviderAuditDetail(cfg, "", 0)
	if stage != "" {
		detail += " stage=" + compactAuditField(stage)
	}
	if message != "" {
		detail += " error=" + compactAuditField(sanitizeOIDCProviderDetail(message))
	}
	_ = s.auditOIDCProvider(ctx, action, detail)
}

func oidcProviderAuditDetail(cfg authz.OIDCProviderConfig, message string, revoked uint32) string {
	cfg = authz.NormalizeOIDCProviderConfig(cfg)
	parts := []string{
		fmt.Sprintf("enabled=%t", cfg.Enabled),
		"issuer=" + compactAuditField(cfg.Issuer),
		"client_id=" + compactAuditField(cfg.ClientID),
		"role_claim=" + compactAuditField(cfg.RoleClaim),
		"default_role=" + compactAuditField(cfg.DefaultRole),
		fmt.Sprintf("scopes=%d", len(cfg.Scopes)),
		fmt.Sprintf("trusted_proxy_cidrs=%d", len(cfg.TrustedProxyCIDRs)),
		fmt.Sprintf("client_secret_file_configured=%t", strings.TrimSpace(cfg.ClientSecretFile) != ""),
		fmt.Sprintf("revoked_oidc_sessions=%d", revoked),
	}
	if message != "" {
		parts = append(parts, "detail="+compactAuditField(message))
	}
	return strings.Join(parts, " ")
}

func sanitizeOIDCProviderDetail(value string) string {
	return regexp.MustCompile(`(?i)(client[_-]?secret(?:[_-]?file)?|id[_-]?token|access[_-]?token|refresh[_-]?token|session|cookie|code)\s*[:=]\s*[^,\s;]+`).ReplaceAllStringFunc(value, func(match string) string {
		if idx := strings.IndexAny(match, ":="); idx >= 0 {
			return strings.TrimSpace(match[:idx]) + "=[redacted]"
		}
		return "[redacted]"
	})
}

func (s *SystemService) auditSAMLProvider(ctx context.Context, action, detail string) error {
	if s.Store == nil {
		return nil
	}
	identity := auditIdentity(ctx)
	return s.Store.AppendAudit(store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role,
		AuthSource: identity.AuthSource,
		Action:     action,
		Detail:     detail,
	})
}

func (s *SystemService) auditSAMLProviderFailure(ctx context.Context, action string, cfg authz.SAMLProviderConfig, stage, message string) {
	detail := samlProviderAuditDetail(cfg, "")
	if stage != "" {
		detail += " stage=" + compactAuditField(stage)
	}
	if message != "" {
		detail += " error=" + compactAuditField(sanitizeSAMLProviderDetail(message))
	}
	_ = s.auditSAMLProvider(ctx, action, detail)
}

func samlProviderAuditDetail(cfg authz.SAMLProviderConfig, message string) string {
	cfg = authz.NormalizeSAMLProviderConfig(cfg)
	parts := []string{
		fmt.Sprintf("enabled=%t", cfg.Enabled),
		"metadata_url=" + compactAuditField(cfg.MetadataURL),
		"idp_entity_id=" + compactAuditField(cfg.IDPEntityID),
		"sso_url=" + compactAuditField(cfg.SSOURL),
		"sp_entity_id=" + compactAuditField(cfg.SPEntityID),
		"acs_url=" + compactAuditField(cfg.ACSURL),
		"role_attribute=" + compactAuditField(cfg.RoleAttribute),
		"default_role=" + compactAuditField(cfg.DefaultRole),
		fmt.Sprintf("certificate_fingerprint_configured=%t", strings.TrimSpace(cfg.CertificateFingerprint) != ""),
	}
	if message != "" {
		parts = append(parts, "detail="+compactAuditField(message))
	}
	return strings.Join(parts, " ")
}

func sanitizeSAMLProviderDetail(value string) string {
	value = sanitizeOIDCProviderDetail(value)
	return regexp.MustCompile(`(?i)(certificate[_-]?fingerprint|x509|private[_-]?key|saml[_-]?response|assertion)\s*[:=]\s*[^,\s;]+`).ReplaceAllStringFunc(value, func(match string) string {
		if idx := strings.IndexAny(match, ":="); idx >= 0 {
			return strings.TrimSpace(match[:idx]) + "=[redacted]"
		}
		return "[redacted]"
	})
}

func accessLocalUserAuditDetail(name, role string, user authz.LocalUserInventory, message string) string {
	parts := []string{"user=" + compactAuditField(name)}
	if role != "" {
		parts = append(parts, "requested_role="+compactAuditField(role))
	}
	if user.Role != "" {
		parts = append(parts, "role="+compactAuditField(user.Role))
	}
	if user.AuthSource != "" {
		parts = append(parts, "auth_source="+compactAuditField(user.AuthSource))
	}
	if user.TokenMaterial != "" {
		parts = append(parts, "token_material="+compactAuditField(user.TokenMaterial))
	}
	if user.AuditHash != "" {
		parts = append(parts, "inventory="+compactAuditField(user.AuditHash))
	}
	if user.Name != "" {
		parts = append(parts, fmt.Sprintf("enabled=%t", user.Enabled))
	}
	if message != "" {
		parts = append(parts, "detail="+compactAuditField(message))
	}
	return strings.Join(parts, " ")
}

func localUserMutationDetail(action string, user authz.LocalUserInventory, tokenReturned bool) string {
	verb := strings.TrimPrefix(action, "access-local-user-")
	if tokenReturned {
		return fmt.Sprintf("Local user %s %s; one-time token returned.", user.Name, verb)
	}
	return fmt.Sprintf("Local user %s %s.", user.Name, verb)
}

func accessSessionAuditDetail(sessionID string, session authz.OIDCSessionRecord, message string) string {
	parts := []string{"session_id=" + compactAuditField(sessionID)}
	if session.Actor != "" {
		parts = append(parts, "actor="+compactAuditField(session.Actor))
	}
	if session.Role != "" {
		parts = append(parts, "role="+compactAuditField(session.Role))
	}
	if session.AuthSource != "" {
		parts = append(parts, "auth_source="+compactAuditField(session.AuthSource))
	}
	if message != "" {
		parts = append(parts, "detail="+compactAuditField(message))
	}
	return strings.Join(parts, " ")
}

func tuneAuditDetail(profile, configPath string, write, apply bool, results []*openngfwv1.TuneHostResult) string {
	parts := []string{
		"profile=" + compactAuditField(profile),
		fmt.Sprintf("write=%t", write),
		fmt.Sprintf("apply=%t", apply),
		"config=" + compactAuditField(configPath),
	}
	if len(results) > 0 {
		applied, skipped := tuneResultCounts(results)
		parts = append(parts,
			fmt.Sprintf("results=%d", len(results)),
			fmt.Sprintf("applied=%d", applied),
			fmt.Sprintf("skipped=%d", skipped),
		)
	}
	return strings.Join(parts, " ")
}

func tuneResultCounts(results []*openngfwv1.TuneHostResult) (applied, skipped int) {
	for _, result := range results {
		switch result.GetState() {
		case "applied":
			applied++
		case "skipped":
			skipped++
		}
	}
	return applied, skipped
}

func compactAuditField(v string) string {
	v = strings.Join(strings.Fields(v), "_")
	if v == "" {
		return "unknown"
	}
	return v
}

func nonnegativeUint32(v int) uint32 {
	if v <= 0 {
		return 0
	}
	return uint32(v)
}

func nonnegativeUint64(v int64) uint64 {
	if v <= 0 {
		return 0
	}
	return uint64(v)
}

func kernelTuningStatus(cfg SystemStatusConfig) (*openngfwv1.KernelTuningStatus, []*openngfwv1.StatusWarning) {
	root := cfg.SysctlRoot
	if root == "" {
		root = tuning.DefaultSysctlRoot
	}
	configPath := cfg.SysctlConfigPath
	if configPath == "" {
		configPath = tuning.DefaultConfigPath
	}
	status := &openngfwv1.KernelTuningStatus{
		State:            "ready",
		Detail:           "required forwarding and high-concurrency sysctls match recommended appliance values",
		SysctlConfigPath: configPath,
		Checks:           make([]*openngfwv1.KernelTuningCheck, 0, len(kernelTuningRequirements)),
	}
	if _, err := os.Stat(root); err != nil {
		if cfg.DryRun {
			status.State = "simulation"
			status.Detail = "kernel sysctl tree is not available in dry-run; apply on a Linux host to verify appliance tuning"
			return status, nil
		}
		status.State = "unknown"
		status.Detail = "kernel sysctl tree is not available; run on Linux to verify appliance tuning"
		return status, nil
	}

	var degraded []string
	var unknown []string
	for _, req := range kernelTuningRequirements {
		check := evaluateKernelTuning(root, req)
		status.Checks = append(status.Checks, check)
		switch check.GetState() {
		case "degraded":
			degraded = append(degraded, check.GetName())
		case "unknown":
			unknown = append(unknown, check.GetName())
		}
	}
	switch {
	case len(degraded) > 0:
		status.State = "degraded"
		status.Detail = strconv.Itoa(len(degraded)) + " kernel tuning issue(s): " + strings.Join(degraded, ", ")
	case len(unknown) > 0:
		status.State = "unknown"
		status.Detail = strconv.Itoa(len(unknown)) + " kernel tuning check(s) could not be read: " + strings.Join(unknown, ", ")
	}

	var warnings []*openngfwv1.StatusWarning
	if status.GetState() == "degraded" {
		warnings = append(warnings, &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  "Kernel forwarding/high-throughput tuning is not ready.",
			Action:   "Run ngfwctl system tune --write --apply or apply " + configPath + ", then verify /v1/system/status.",
		})
	}
	return status, warnings
}

func evaluateKernelTuning(root string, req tuning.Requirement) *openngfwv1.KernelTuningCheck {
	check := &openngfwv1.KernelTuningCheck{
		Name:        req.Name,
		Key:         req.Key,
		Recommended: req.Recommended,
		State:       "ready",
		Detail:      req.Detail,
	}
	current, err := readSysctl(root, req.Key)
	if err != nil {
		check.State = "unknown"
		check.Detail = "could not read " + req.Key + ": " + err.Error()
		return check
	}
	check.Current = current
	if req.Exact != "" && current != req.Exact {
		check.State = "degraded"
		check.Detail = req.Detail + "; current value " + current + " does not match recommended " + req.Recommended
		return check
	}
	if req.Min > 0 {
		value, err := strconv.ParseUint(current, 10, 64)
		if err != nil {
			check.State = "unknown"
			check.Detail = "could not parse " + req.Key + " value " + strconv.Quote(current)
			return check
		}
		if value < req.Min {
			check.State = "degraded"
			check.Detail = req.Detail + "; current value " + current + " is below recommended " + req.Recommended
		}
	}
	return check
}

func conntrackTableStatus(cfg SystemStatusConfig) *openngfwv1.ConntrackTableStatus {
	root := cfg.SysctlRoot
	if root == "" {
		root = "/proc/sys"
	}
	status := &openngfwv1.ConntrackTableStatus{
		State:                    "ready",
		Detail:                   "conntrack state table has capacity headroom",
		WarningThresholdPercent:  conntrackWarningPercent,
		DegradedThresholdPercent: conntrackDegradedPercent,
	}
	if _, err := os.Stat(root); err != nil {
		if cfg.DryRun {
			status.State = "simulation"
			status.Detail = "kernel sysctl tree is not available in dry-run; apply on a Linux host to inspect live conntrack capacity"
			return status
		}
		status.State = "unknown"
		status.Detail = "kernel sysctl tree is not available; run on Linux to inspect live conntrack capacity"
		return status
	}

	current, err := readSysctlUint(root, "net.netfilter.nf_conntrack_count")
	if err != nil {
		status.State = "unknown"
		status.Detail = "could not read net.netfilter.nf_conntrack_count: " + err.Error()
		return status
	}
	maximum, err := readSysctlUint(root, "net.netfilter.nf_conntrack_max")
	if err != nil {
		status.State = "unknown"
		status.Detail = "could not read net.netfilter.nf_conntrack_max: " + err.Error()
		return status
	}
	status.CurrentEntries = current
	status.MaxEntries = maximum
	if maximum == 0 {
		status.State = "unknown"
		status.Detail = "net.netfilter.nf_conntrack_max is zero; conntrack capacity cannot be evaluated"
		return status
	}
	status.UsagePercent = (float64(current) / float64(maximum)) * 100
	status.Detail = fmt.Sprintf("%d of %d conntrack entries used (%.1f%%)", current, maximum, status.GetUsagePercent())
	switch {
	case status.GetUsagePercent() >= conntrackDegradedPercent || current >= maximum:
		status.State = "degraded"
		status.Detail += "; state table is near or over capacity"
	case status.GetUsagePercent() >= conntrackWarningPercent:
		status.State = "warning"
		status.Detail += "; state table pressure is elevated"
	default:
		status.State = "ready"
		status.Detail += "; capacity headroom is available"
	}
	return status
}

func readSysctl(root, key string) (string, error) {
	path := filepath.Join(root, strings.ReplaceAll(key, ".", string(os.PathSeparator)))
	out, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func readSysctlUint(root, key string) (uint64, error) {
	current, err := readSysctl(root, key)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(current, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s value %q: %w", key, current, err)
	}
	return value, nil
}

func hostResourceStatus(cfg SystemStatusConfig) *openngfwv1.HostResourceStatus {
	root := cfg.ProcRoot
	explicitRoot := root != ""
	if root == "" {
		root = defaultProcRoot
	}
	cpus := cfg.HostCPUs
	if cpus == 0 {
		cpus = uint32(runtime.NumCPU())
	}
	status := &openngfwv1.HostResourceStatus{
		State:    "ready",
		Detail:   "host load, memory, and interface counters are available from procfs",
		CpuCount: cpus,
	}
	if _, err := os.Stat(root); err != nil {
		state := "unknown"
		if explicitRoot {
			state = "degraded"
		}
		status.State = state
		status.Detail = "procfs root " + root + " is not available; host load, memory, and interface counters cannot be inspected"
		return status
	}

	var issues []string
	if err := fillLoadavg(status, filepath.Join(root, "loadavg")); err != nil {
		issues = append(issues, "loadavg: "+err.Error())
	}
	if err := fillMeminfo(status, filepath.Join(root, "meminfo")); err != nil {
		issues = append(issues, "meminfo: "+err.Error())
	}
	if interfaces, err := readNetDev(filepath.Join(root, "net", "dev")); err != nil {
		issues = append(issues, "net/dev: "+err.Error())
	} else {
		status.Interfaces = interfaces
		for _, iface := range interfaces {
			if iface.GetState() != "ready" {
				issues = append(issues, "interface "+iface.GetName()+" has drops/errors")
			}
		}
	}
	if len(issues) > 0 {
		status.State = "degraded"
		status.Detail = strconv.Itoa(len(issues)) + " host resource issue(s): " + strings.Join(issues, "; ")
	}
	return status
}

func fillLoadavg(status *openngfwv1.HostResourceStatus, path string) error {
	out, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	fields := strings.Fields(string(out))
	if len(fields) < 3 {
		return fmt.Errorf("expected at least 3 fields")
	}
	load1, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return fmt.Errorf("parse 1m load: %w", err)
	}
	load5, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return fmt.Errorf("parse 5m load: %w", err)
	}
	load15, err := strconv.ParseFloat(fields[2], 64)
	if err != nil {
		return fmt.Errorf("parse 15m load: %w", err)
	}
	status.Load1 = load1
	status.Load5 = load5
	status.Load15 = load15
	if status.GetCpuCount() > 0 {
		status.Load1PerCpu = load1 / float64(status.GetCpuCount())
	}
	return nil
}

func fillMeminfo(status *openngfwv1.HostResourceStatus, path string) error {
	out, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		multiplier := uint64(1)
		if len(fields) > 2 && strings.EqualFold(fields[2], "kB") {
			multiplier = 1024
		}
		values[key] = value * multiplier
	}
	total := values["MemTotal"]
	available := values["MemAvailable"]
	if total == 0 {
		return fmt.Errorf("MemTotal missing")
	}
	if available == 0 {
		return fmt.Errorf("MemAvailable missing")
	}
	status.MemoryTotalBytes = total
	status.MemoryAvailableBytes = available
	used := total - available
	if available > total {
		used = 0
	}
	status.MemoryUsedPercent = (float64(used) / float64(total)) * 100
	return nil
}

func readNetDev(path string) ([]*openngfwv1.HostInterfaceCounter, error) {
	out, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var counters []*openngfwv1.HostInterfaceCounter
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		name := strings.TrimSpace(parts[0])
		if name == "" || name == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}
		iface := &openngfwv1.HostInterfaceCounter{
			Name:      name,
			State:     "ready",
			Detail:    "no interface drops or errors reported",
			RxBytes:   parseUintField(fields[0]),
			RxPackets: parseUintField(fields[1]),
			RxErrors:  parseUintField(fields[2]),
			RxDrops:   parseUintField(fields[3]),
			TxBytes:   parseUintField(fields[8]),
			TxPackets: parseUintField(fields[9]),
			TxErrors:  parseUintField(fields[10]),
			TxDrops:   parseUintField(fields[11]),
		}
		if iface.GetRxErrors()+iface.GetTxErrors()+iface.GetRxDrops()+iface.GetTxDrops() > 0 {
			iface.State = "degraded"
			iface.Detail = fmt.Sprintf("rx errors %d, tx errors %d, rx drops %d, tx drops %d",
				iface.GetRxErrors(), iface.GetTxErrors(), iface.GetRxDrops(), iface.GetTxDrops())
		}
		counters = append(counters, iface)
	}
	sort.Slice(counters, func(i, j int) bool { return counters[i].GetName() < counters[j].GetName() })
	return counters, nil
}

func parseUintField(value string) uint64 {
	n, _ := strconv.ParseUint(value, 10, 64)
	return n
}

func ebpfDataplaneStatus(cfg SystemStatusConfig) *openngfwv1.EbpfDataplaneStatus {
	root := cfg.SysfsRoot
	if root == "" {
		root = defaultSysfsRoot
	}
	probes := []*openngfwv1.EbpfProbe{
		commandProbe(cfg, "bpftool", "bpftool", "required to inspect loaded BPF programs, maps, and kernel feature support"),
		commandProbe(cfg, "clang", "clang", "required to compile first-party XDP/tc eBPF programs"),
		commandProbe(cfg, "tc", "tc", "required to attach tc clsact programs when XDP is unavailable or inappropriate"),
		commandProbe(cfg, "iproute2", "ip", "required for link, XDP, and clsact attachment orchestration"),
		sysfsProbe(root, "Kernel BTF", "kernel/btf/vmlinux", "required for CO-RE style eBPF builds and verifier-friendly type information"),
		sysfsProbe(root, "bpffs mount point", "fs/bpf", "required to pin maps and programs for runtime inspection and lifecycle management"),
		sysfsProbe(root, "cgroup v2 BPF hooks", "fs/cgroup/cgroup.controllers", "needed for future cgroup hook expansion and confirms a modern cgroup hierarchy"),
	}
	attachProbes := []*openngfwv1.EbpfProbe{
		commandProbe(cfg, "XDP attach orchestration", "ip", "required to attach and detach XDP programs on Linux links"),
		commandProbe(cfg, "tc clsact attach orchestration", "tc", "required to create clsact qdiscs and attach tc ingress/egress programs"),
		commandProbe(cfg, "BPF runtime inspection", "bpftool", "required to verify attached programs and pinned maps after an attach drill"),
		sysfsProbe(root, "Network link inventory", "class/net", "required to enumerate candidate links for XDP/tc attach validation"),
	}

	var degraded []string
	for _, probe := range probes {
		if probe.GetState() != "ready" {
			degraded = append(degraded, probe.GetName())
		}
	}
	var attachDegraded []string
	for _, probe := range attachProbes {
		if probe.GetState() != "ready" {
			attachDegraded = append(attachDegraded, probe.GetName())
		}
	}
	status := &openngfwv1.EbpfDataplaneStatus{
		State:          "ready",
		Detail:         "host has the tooling and kernel files needed to build, inspect, and attach first-party XDP/tc eBPF programs; nftables remains the active production renderer",
		Probes:         probes,
		AttachState:    "ready",
		AttachDetail:   ebpfAttachDetail(cfg),
		AttachProbes:   attachProbes,
		RendererState:  "planned",
		RendererDetail: "plan-only first-party eBPF renderer scaffolding is present; nftables/conntrack remains the authoritative dataplane until verifier, attach, map lifecycle, and rollback controls are implemented",
		SupportedHooks: []string{"xdp", "tc"},
		EvidenceScope:  "host-prerequisites,attach-prerequisites,renderer-scaffold",
	}
	status.EvidenceCollectedAt = time.Now().UTC().Format(time.RFC3339)
	status.Artifacts = ebpfEvidenceArtifacts(cfg)
	if cfg.EbpfRuntimeProbes {
		status.Attachments = ebpfRuntimeAttachments(context.Background(), cfg)
		status.EvidenceScope = "host-prerequisites,attach-prerequisites,renderer-scaffold,runtime-probes"
		for _, attachment := range status.GetAttachments() {
			if attachment.GetState() == "degraded" || attachment.GetState() == "unknown" {
				attachDegraded = append(attachDegraded, "runtime probe: "+attachment.GetDetail())
			}
		}
	}
	if len(degraded) > 0 {
		status.State = "degraded"
		status.Blockers = append(status.Blockers, degraded...)
	}
	if len(attachDegraded) > 0 {
		status.State = "degraded"
		status.AttachState = "degraded"
		status.AttachDetail = strconv.Itoa(len(attachDegraded)) + " eBPF attach prerequisite issue(s): " + strings.Join(attachDegraded, ", ")
		status.Blockers = append(status.Blockers, attachDegraded...)
	}
	status.Blockers = dedupeStrings(status.Blockers)
	if len(status.Blockers) > 0 {
		status.Detail = strconv.Itoa(len(status.Blockers)) + " eBPF prerequisite issue(s): " + strings.Join(status.Blockers, ", ")
	}
	return status
}

func ebpfAttachDetail(cfg SystemStatusConfig) string {
	detail := "XDP and tc attach prerequisites are present for an OL9/root attach drill; no eBPF program is attached by controld in this build"
	if pinRoot := strings.TrimSpace(cfg.EbpfPinRoot); pinRoot != "" {
		detail += "; bpffs pin root " + pinRoot
	}
	return detail
}

func ebpfEvidenceArtifacts(cfg SystemStatusConfig) []*openngfwv1.EbpfArtifact {
	dir := strings.TrimSpace(cfg.EbpfArtifactDir)
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return []*openngfwv1.EbpfArtifact{{
			Name:   filepath.Base(dir),
			Kind:   "artifact-directory",
			Path:   dir,
			State:  "missing",
			Detail: "eBPF artifact directory is not readable: " + err.Error(),
		}}
	}
	var artifacts []*openngfwv1.EbpfArtifact
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		raw, err := os.ReadFile(path)
		artifact := &openngfwv1.EbpfArtifact{
			Name:  entry.Name(),
			Kind:  ebpfArtifactKind(entry.Name()),
			Path:  path,
			State: "ready",
		}
		if err != nil {
			artifact.State = "degraded"
			artifact.Detail = "read failed: " + err.Error()
		} else {
			sum := sha256.Sum256(raw)
			artifact.Sha256 = hex.EncodeToString(sum[:])
			artifact.Detail = fmt.Sprintf("%d byte artifact indexed for field evidence", len(raw))
		}
		artifacts = append(artifacts, artifact)
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].GetName() < artifacts[j].GetName() })
	return artifacts
}

func ebpfArtifactKind(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "plan"):
		return "renderer-plan"
	case strings.HasSuffix(lower, ".json"):
		return "status-json"
	case strings.HasSuffix(lower, ".o"):
		return "object-file"
	default:
		return "field-evidence"
	}
}

func ebpfRuntimeAttachments(ctx context.Context, cfg SystemStatusConfig) []*openngfwv1.EbpfAttachment {
	if cfg.CommandRun == nil {
		return []*openngfwv1.EbpfAttachment{{
			Hook:   "runtime-probe",
			State:  "unknown",
			Detail: "runtime probe requested but no command runner is configured",
		}}
	}
	out, err := cfg.CommandRun(ctx, "bpftool", "net")
	if err != nil {
		return []*openngfwv1.EbpfAttachment{{
			Hook:   "runtime-probe",
			State:  "degraded",
			Detail: "bpftool net failed: " + err.Error() + commandOutputSuffix(out),
		}}
	}
	text := string(out)
	var attachments []*openngfwv1.EbpfAttachment
	for _, iface := range cfg.EbpfAttachProbeInterfaces {
		iface = strings.TrimSpace(iface)
		if iface == "" {
			continue
		}
		attachments = append(attachments,
			ebpfAttachmentFromText(text, iface, "xdp"),
			ebpfAttachmentFromText(text, iface, "tc"),
		)
	}
	if len(attachments) == 0 {
		attachments = append(attachments, &openngfwv1.EbpfAttachment{
			Hook:   "runtime-probe",
			State:  "unknown",
			Detail: "bpftool net was collected, but no --ebpf-attach-probe-interfaces were configured",
		})
	}
	return attachments
}

func ebpfAttachmentFromText(text, iface, hook string) *openngfwv1.EbpfAttachment {
	attachment := &openngfwv1.EbpfAttachment{
		Interface: iface,
		Hook:      hook,
		State:     "not_attached",
		Detail:    "no " + hook + " program reported by bpftool net for " + iface,
	}
	for _, line := range strings.Split(text, "\n") {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, strings.ToLower(iface)) || !strings.Contains(lower, hook) {
			continue
		}
		attachment.State = "attached"
		attachment.Detail = strings.TrimSpace(line)
		attachment.ProgramId = firstRegexGroup(line, `id[[:space:]]+([0-9]+)`)
		attachment.ProgramName = firstRegexGroup(line, `name[[:space:]]+([^[:space:]]+)`)
		break
	}
	return attachment
}

func firstRegexGroup(text, pattern string) string {
	match := regexp.MustCompile(pattern).FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func commandOutputSuffix(out []byte) string {
	text := strings.TrimSpace(string(out))
	if text == "" {
		return ""
	}
	return ": " + text
}

func commandProbe(cfg SystemStatusConfig, name, command, detail string) *openngfwv1.EbpfProbe {
	probe := &openngfwv1.EbpfProbe{
		Name:   name,
		Key:    command,
		State:  "ready",
		Detail: detail,
	}
	if missing := missingCommands(cfg, []string{command}); len(missing) > 0 {
		probe.State = "degraded"
		probe.Detail = "missing command " + command + "; " + detail
	}
	return probe
}

func sysfsProbe(root, name, rel, detail string) *openngfwv1.EbpfProbe {
	probe := &openngfwv1.EbpfProbe{
		Name:   name,
		Key:    filepath.Join(root, rel),
		State:  "ready",
		Detail: detail,
	}
	if _, err := os.Stat(probe.Key); err != nil {
		probe.State = "degraded"
		probe.Detail = "missing " + probe.Key + "; " + detail
	}
	return probe
}

type engineDiagnostic struct {
	mode     string
	state    string
	detail   string
	missing  []string
	warnings []*openngfwv1.StatusWarning
}

type missingDependency struct {
	engine   string
	commands []string
}

func diagnoseEngine(cfg SystemStatusConfig, engine SystemEngine) engineDiagnostic {
	mode := "managed"
	state := "ready"
	detail := "required commands are present; native config is validated and applied during commit"
	if cfg.DryRun {
		mode = "dry-run"
		state = "simulation"
		detail = "required commands are present; native config is rendered and validated but not applied to the host"
	}

	missing := missingCommands(cfg, engine.Dependencies)
	if len(missing) > 0 {
		state = "missing-prerequisites"
		detail = "missing required command(s): " + strings.Join(missing, ", ")
		if cfg.DryRun {
			detail += "; dry-run can still render demo configs"
		}
	}
	diag := engineDiagnostic{mode: mode, state: state, detail: detail, missing: missing}
	if !cfg.DryRun && len(missing) == 0 && engine.Runtime != nil {
		diag = applyEngineRuntime(engine.Name, diag, engine.Runtime())
	}
	return diag
}

func applyEngineRuntime(name string, diag engineDiagnostic, rt EngineRuntime) engineDiagnostic {
	switch rt.State {
	case "", "stopped":
		diag.state = "ready"
		diag.detail = "process is stopped; it starts when policy enables this engine"
	case "running":
		diag.state = "active"
		diag.detail = processRuntimeDetail("process running", rt)
		if rt.Restarts > 0 {
			diag.warnings = append(diag.warnings, &openngfwv1.StatusWarning{
				Severity: "warning",
				Message:  fmt.Sprintf("Engine %s auto-restarted %d time(s) since last apply.", name, rt.Restarts),
				Action:   "Inspect engine logs and host resource pressure before treating the appliance as healthy.",
			})
		}
	case "restarting":
		diag.state = "restarting"
		diag.detail = processRuntimeDetail("waiting for bounded auto-restart", rt)
		diag.warnings = append(diag.warnings, &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  fmt.Sprintf("Engine %s exited unexpectedly and is waiting for auto-restart.", name),
			Action:   "Inspect engine logs; traffic follows the configured fail-open or fail-closed policy while the engine recovers.",
		})
	case "failed":
		diag.state = "failed"
		diag.detail = processRuntimeDetail("process is not running after an unexpected exit", rt)
		diag.warnings = append(diag.warnings, &openngfwv1.StatusWarning{
			Severity: "critical",
			Message:  fmt.Sprintf("Engine %s is not running after an unexpected exit.", name),
			Action:   "Inspect engine logs, fix configuration or resource pressure, then re-commit or restart controld.",
		})
	default:
		diag.state = "unknown"
		diag.detail = processRuntimeDetail("process state is "+rt.State, rt)
		diag.warnings = append(diag.warnings, &openngfwv1.StatusWarning{
			Severity: "warning",
			Message:  fmt.Sprintf("Engine %s reported unknown process state %q.", name, rt.State),
			Action:   "Inspect controld logs and engine supervision state.",
		})
	}
	return diag
}

func processRuntimeDetail(prefix string, rt EngineRuntime) string {
	parts := []string{prefix}
	if rt.PID > 0 {
		parts = append(parts, "pid "+strconv.Itoa(rt.PID))
	}
	if !rt.StartedAt.IsZero() {
		parts = append(parts, "started "+rt.StartedAt.UTC().Format(time.RFC3339))
	}
	if rt.Restarts > 0 {
		parts = append(parts, fmt.Sprintf("auto-restarts %d/%d", rt.Restarts, rt.MaxRestarts))
	}
	if !rt.LastExitAt.IsZero() {
		exit := "last exit " + rt.LastExitAt.UTC().Format(time.RFC3339)
		if rt.LastUptime > 0 {
			exit += " after " + rt.LastUptime.String()
		}
		parts = append(parts, exit)
	}
	if rt.LastExitErr != "" {
		parts = append(parts, "last error: "+rt.LastExitErr)
	}
	return strings.Join(parts, "; ")
}

func missingCommands(cfg SystemStatusConfig, deps []string) []string {
	lookup := cfg.CommandLookup
	if lookup == nil {
		lookup = exec.LookPath
	}
	var missing []string
	seen := map[string]bool{}
	for _, dep := range deps {
		if dep == "" || seen[dep] {
			continue
		}
		seen[dep] = true
		if _, err := lookup(dep); err != nil {
			missing = append(missing, dep)
			continue
		}
	}
	return missing
}

func totalMissing(items []missingDependency) int {
	seen := map[string]bool{}
	for _, item := range items {
		for _, command := range item.commands {
			seen[command] = true
		}
	}
	return len(seen)
}

func nftablesCapability(cfg SystemStatusConfig) (string, string) {
	if missing := missingCommands(cfg, []string{"nft"}); len(missing) > 0 {
		if cfg.DryRun {
			return "simulation", "nft command is missing; dry-run can render configs but cannot enforce nftables on this host"
		}
		return "degraded", "nft command is missing; install nftables before production enforcement"
	}
	return "active", "nftables/conntrack renderer is the current Linux dataplane path"
}

func conntrackCapability(cfg SystemStatusConfig) (string, string) {
	if missing := missingCommands(cfg, []string{"conntrack"}); len(missing) > 0 {
		if cfg.DryRun {
			return "simulation", "conntrack command is missing; dry-run cannot inspect live session state"
		}
		return "degraded", "conntrack command is missing; install conntrack-tools for live session visibility"
	}
	return "ready", "conntrack-tools can inspect live Linux state-table sessions"
}

func flowtableCapability(cfg SystemStatusConfig) (string, string) {
	if missing := missingCommands(cfg, []string{"nft"}); len(missing) > 0 {
		if cfg.DryRun {
			return "simulation", "nft command is missing; dry-run can render flowtable configs but cannot validate host support"
		}
		return "degraded", "nft command is missing; flowtable acceleration cannot be validated or applied"
	}
	return "ready", "available through network.enable_flow_offload for forwarding-only policies; validation rejects IDS/IPS conflicts and kernel syntax is checked before apply"
}

type flowtableRuntime struct {
	state       string
	detail      string
	devices     []string
	packets     uint64
	bytes       uint64
	declared    bool
	offloadRule bool
}

func flowtableRuntimeEvidence(ctx context.Context, cfg SystemStatusConfig) (flowtableRuntime, string) {
	if missing := missingCommands(cfg, []string{"nft"}); len(missing) > 0 {
		if cfg.DryRun {
			return flowtableRuntime{
				state:  "simulation",
				detail: "nft command is missing; dry-run cannot install or inspect runtime flowtable state",
			}, ""
		}
		return flowtableRuntime{
			state:  "degraded",
			detail: "nft command is missing; runtime flowtable state cannot be inspected",
		}, ""
	}
	if cfg.DryRun {
		return flowtableRuntime{
			state:  "simulation",
			detail: "dry-run does not install kernel rules; commit in enforcing mode to collect runtime flowtable evidence",
		}, ""
	}
	if cfg.CommandLookup != nil && cfg.CommandRun == nil {
		return flowtableRuntime{
			state:  "unknown",
			detail: "runtime nft ruleset query is not configured in this status context",
		}, ""
	}
	out, err := runCommand(ctx, cfg, "nft", "list", "table", "inet", "openngfw")
	if err != nil {
		msg := strings.ToLower(string(out) + " " + err.Error())
		if strings.Contains(msg, "no such file") || strings.Contains(msg, "does not exist") {
			return flowtableRuntime{
				state:  "inactive",
				detail: "openngfw nftables table is not installed; commit a running policy before expecting flowtable evidence",
			}, ""
		}
		return flowtableRuntime{
			state:  "unknown",
			detail: "could not inspect openngfw nftables table: " + trimCommandError(out, err),
		}, ""
	}
	evidence := parseFlowtableRuntimeEvidence(string(out))
	switch {
	case evidence.declared && evidence.offloadRule:
		evidence.state = "active"
		evidence.detail = "runtime ruleset contains flowtable fastpath and the established-flow offload rule"
	case evidence.declared:
		evidence.state = "degraded"
		evidence.detail = "runtime ruleset contains flowtable fastpath but no established-flow offload rule"
	case evidence.offloadRule:
		evidence.state = "degraded"
		evidence.detail = "runtime ruleset contains an offload rule but no flowtable fastpath declaration"
	default:
		evidence.state = "inactive"
		evidence.detail = "runtime ruleset has no flowtable fast path; expected when running policy does not enable network.enable_flow_offload"
	}
	return evidence, string(out)
}

func parseFlowtableRuntimeEvidence(ruleset string) flowtableRuntime {
	evidence := flowtableRuntime{
		declared:    strings.Contains(ruleset, "flowtable fastpath"),
		offloadRule: strings.Contains(ruleset, "flow add @fastpath"),
	}
	if match := flowtableDevicesRE.FindStringSubmatch(ruleset); len(match) == 2 {
		evidence.devices = parseFlowtableDevices(match[1])
	}
	for _, line := range strings.Split(ruleset, "\n") {
		if !strings.Contains(line, "flow add @fastpath") {
			continue
		}
		if match := counterRE.FindStringSubmatch(line); len(match) == 3 {
			packets, _ := strconv.ParseUint(match[1], 10, 64)
			bytes, _ := strconv.ParseUint(match[2], 10, 64)
			evidence.packets += packets
			evidence.bytes += bytes
		}
	}
	return evidence
}

func parseDataplaneCounters(ruleset string) []*openngfwv1.DataplaneCounter {
	byComment := map[string]*openngfwv1.DataplaneCounter{}
	var order []string
	for _, line := range strings.Split(ruleset, "\n") {
		if !strings.Contains(line, "counter") || !strings.Contains(line, "comment") {
			continue
		}
		commentMatch := commentRE.FindStringSubmatch(line)
		counterMatch := counterRE.FindStringSubmatch(line)
		if len(commentMatch) != 2 || len(counterMatch) != 3 {
			continue
		}
		comment := unescapeNftComment(commentMatch[1])
		packets, _ := strconv.ParseUint(counterMatch[1], 10, 64)
		bytes, _ := strconv.ParseUint(counterMatch[2], 10, 64)
		counter := byComment[comment]
		if counter == nil {
			kind, name, ruleID, itemID := classifyDataplaneCounter(comment)
			counter = &openngfwv1.DataplaneCounter{
				Comment: comment,
				Kind:    kind,
				Name:    name,
				RuleId:  ruleID,
				ItemId:  itemID,
			}
			byComment[comment] = counter
			order = append(order, comment)
		}
		counter.Packets += packets
		counter.Bytes += bytes
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := byComment[order[i]], byComment[order[j]]
		if a.GetPackets() == b.GetPackets() {
			if a.GetBytes() == b.GetBytes() {
				return a.GetComment() < b.GetComment()
			}
			return a.GetBytes() > b.GetBytes()
		}
		return a.GetPackets() > b.GetPackets()
	})
	out := make([]*openngfwv1.DataplaneCounter, 0, len(order))
	for _, comment := range order {
		out = append(out, byComment[comment])
	}
	return out
}

func unescapeNftComment(raw string) string {
	replacer := strings.NewReplacer(`\"`, `"`, `\\`, `\`)
	return replacer.Replace(raw)
}

func classifyDataplaneCounter(comment string) (kind, name, ruleID, itemID string) {
	if prefix, rest, ok := strings.Cut(comment, ":"); ok {
		switch prefix {
		case "rule":
			name, ruleID = splitCounterMetadata(rest)
			return prefix, name, ruleID, ruleID
		case "host-input", "snat", "dnat":
			name, itemID = splitCounterMetadata(rest)
			return prefix, name, "", itemID
		default:
			return "system", comment, "", ""
		}
	}
	switch {
	case strings.HasPrefix(comment, "intel-block"):
		return "intel", comment, "", ""
	case comment == "ips-inspect":
		return "ips", comment, "", ""
	case comment == "mss-clamp":
		return "network", comment, "", ""
	case comment == "flow-offload":
		return "flow-offload", comment, "", ""
	case comment == "default-drop" || comment == "default-input-drop":
		return "default", comment, "", ""
	default:
		return "system", comment, "", ""
	}
}

func splitCounterMetadata(rest string) (name, itemID string) {
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return rest, ""
	}
	name = fields[0]
	for _, field := range fields[1:] {
		if value, ok := strings.CutPrefix(field, "id="); ok {
			itemID = value
			break
		}
	}
	return name, itemID
}

func parseFlowtableDevices(raw string) []string {
	parts := strings.Split(raw, ",")
	devices := make([]string, 0, len(parts))
	for _, part := range parts {
		device := strings.Trim(part, " \t\r\n\"")
		if device != "" {
			devices = append(devices, device)
		}
	}
	return devices
}

func routingRuntimeStatus(ctx context.Context, cfg SystemStatusConfig, dynamicRoutingEnabled bool) *openngfwv1.RoutingRuntimeStatus {
	return &openngfwv1.RoutingRuntimeStatus{Frr: frrRuntimeStatus(ctx, cfg, dynamicRoutingEnabled)}
}

func frrRuntimeStatus(ctx context.Context, cfg SystemStatusConfig, dynamicRoutingEnabled bool) *openngfwv1.FrrRuntimeStatus {
	if !dynamicRoutingEnabled {
		return &openngfwv1.FrrRuntimeStatus{
			State:  "not-configured",
			Detail: "running policy does not enable BGP or OSPF",
		}
	}
	if !systemManagesEngine(cfg, "frr") {
		return &openngfwv1.FrrRuntimeStatus{
			State:  "not-configured",
			Detail: "FRR engine is not registered in this status context",
		}
	}
	if missing := missingCommands(cfg, []string{"vtysh"}); len(missing) > 0 {
		if cfg.DryRun {
			return &openngfwv1.FrrRuntimeStatus{
				State:  "simulation",
				Detail: "vtysh command is missing; dry-run cannot inspect FRR protocol state",
			}
		}
		return &openngfwv1.FrrRuntimeStatus{
			State:  "degraded",
			Detail: "vtysh command is missing; FRR protocol state cannot be inspected",
		}
	}
	if cfg.DryRun {
		return &openngfwv1.FrrRuntimeStatus{
			State:  "simulation",
			Detail: "dry-run does not reload FRR daemons; commit in enforcing mode to collect routing evidence",
		}
	}
	if cfg.CommandLookup != nil && cfg.CommandRun == nil {
		return &openngfwv1.FrrRuntimeStatus{
			State:  "unknown",
			Detail: "runtime FRR query is not configured in this status context",
		}
	}

	bgpRaw, bgpErr := runFrrStatusCommand(ctx, cfg, "show bgp ipv4 unicast summary json")
	ospfRaw, ospfErr := runFrrStatusCommand(ctx, cfg, "show ip ospf neighbor json")
	var problems []string
	var bgpNeighbors []*openngfwv1.BgpNeighborRuntimeStatus
	var ospfNeighbors []*openngfwv1.OspfNeighborRuntimeStatus
	if bgpErr != nil {
		problems = append(problems, "BGP summary unavailable: "+trimCommandError(bgpRaw, bgpErr))
	} else {
		var err error
		bgpNeighbors, err = parseFrrBgpNeighbors(bgpRaw)
		if err != nil {
			problems = append(problems, "BGP summary parse failed: "+err.Error())
		}
	}
	if ospfErr != nil {
		problems = append(problems, "OSPF neighbors unavailable: "+trimCommandError(ospfRaw, ospfErr))
	} else {
		var err error
		ospfNeighbors, err = parseFrrOspfNeighbors(ospfRaw)
		if err != nil {
			problems = append(problems, "OSPF neighbors parse failed: "+err.Error())
		}
	}

	status := &openngfwv1.FrrRuntimeStatus{
		State:         "inactive",
		BgpNeighbors:  bgpNeighbors,
		OspfNeighbors: ospfNeighbors,
	}
	if len(problems) > 0 {
		status.State = "degraded"
		if len(bgpNeighbors) == 0 && len(ospfNeighbors) == 0 {
			status.State = "unknown"
		}
		status.Detail = strings.Join(problems, "; ")
		if len(bgpNeighbors) > 0 || len(ospfNeighbors) > 0 {
			status.Detail += "; " + frrNeighborSummary(bgpNeighbors, ospfNeighbors)
		}
		return status
	}

	switch {
	case frrHasEstablishedAdjacency(bgpNeighbors, ospfNeighbors):
		status.State = "active"
		status.Detail = frrNeighborSummary(bgpNeighbors, ospfNeighbors)
	case len(bgpNeighbors) > 0 || len(ospfNeighbors) > 0:
		status.State = "waiting"
		status.Detail = frrNeighborSummary(bgpNeighbors, ospfNeighbors)
	default:
		status.State = "inactive"
		status.Detail = "FRR responded, but no BGP or OSPF neighbor evidence was returned"
	}
	return status
}

func runFrrStatusCommand(ctx context.Context, cfg SystemStatusConfig, command string) ([]byte, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return runCommand(commandCtx, cfg, "vtysh", "-c", command)
}

func parseFrrBgpNeighbors(raw []byte) ([]*openngfwv1.BgpNeighborRuntimeStatus, error) {
	if strings.TrimSpace(string(raw)) == "" {
		return nil, nil
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var peerSets []map[string]any
	collectJSONObjectByKey(doc, "peers", &peerSets)
	byPeer := map[string]*openngfwv1.BgpNeighborRuntimeStatus{}
	for _, peers := range peerSets {
		for peer, value := range peers {
			fields, ok := jsonObject(value)
			if !ok {
				continue
			}
			neighbor := &openngfwv1.BgpNeighborRuntimeStatus{
				Peer:             peer,
				RemoteAsn:        uint32(jsonUint64(fields, "remoteAs", "remoteAsn", "remote_as", "remote_asn")),
				State:            jsonString(fields, "state", "bgpState", "peerState"),
				Uptime:           jsonString(fields, "peerUptime", "uptime", "upDown", "upDownTime"),
				PrefixesReceived: jsonUint64(fields, "pfxRcd", "prefixesReceived", "prefixReceivedCount", "acceptedPrefixCounter"),
				Detail:           jsonString(fields, "description", "desc", "hostname"),
			}
			if neighbor.State == "" {
				neighbor.State = "unknown"
			}
			byPeer[peer] = neighbor
		}
	}
	out := make([]*openngfwv1.BgpNeighborRuntimeStatus, 0, len(byPeer))
	for _, neighbor := range byPeer {
		out = append(out, neighbor)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetPeer() < out[j].GetPeer() })
	return out, nil
}

func parseFrrOspfNeighbors(raw []byte) ([]*openngfwv1.OspfNeighborRuntimeStatus, error) {
	if strings.TrimSpace(string(raw)) == "" {
		return nil, nil
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	var out []*openngfwv1.OspfNeighborRuntimeStatus
	collectFrrOspfNeighbors("", doc, &out)
	sort.Slice(out, func(i, j int) bool {
		if out[i].GetNeighborId() == out[j].GetNeighborId() {
			return out[i].GetInterface() < out[j].GetInterface()
		}
		return out[i].GetNeighborId() < out[j].GetNeighborId()
	})
	return out, nil
}

func collectFrrOspfNeighbors(key string, value any, out *[]*openngfwv1.OspfNeighborRuntimeStatus) {
	switch typed := value.(type) {
	case map[string]any:
		if state := jsonString(typed, "nbrState", "neighborState", "state"); state != "" && hasAnyJSONKey(typed, "ifaceName", "interfaceName", "interface", "ifaceAddress", "address", "neighborAddress", "nbrAddress") {
			neighborID := jsonString(typed, "neighborId", "neighborID", "routerId", "routerID", "nbrId", "nbrID")
			if neighborID == "" {
				neighborID = key
			}
			*out = append(*out, &openngfwv1.OspfNeighborRuntimeStatus{
				NeighborId: neighborID,
				Address:    jsonString(typed, "address", "neighborAddress", "nbrAddress", "ifaceAddress"),
				Interface:  jsonString(typed, "interface", "interfaceName", "ifaceName"),
				State:      state,
				DeadTime:   jsonString(typed, "deadTime", "deadTimeMsec", "deadTimeMsecs"),
				Detail:     jsonString(typed, "role", "priority"),
			})
			return
		}
		for childKey, child := range typed {
			collectFrrOspfNeighbors(childKey, child, out)
		}
	case []any:
		for _, child := range typed {
			collectFrrOspfNeighbors(key, child, out)
		}
	}
}

func collectJSONObjectByKey(value any, want string, out *[]map[string]any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == want {
				if object, ok := jsonObject(child); ok {
					*out = append(*out, object)
				}
				continue
			}
			collectJSONObjectByKey(child, want, out)
		}
	case []any:
		for _, child := range typed {
			collectJSONObjectByKey(child, want, out)
		}
	}
}

func frrHasEstablishedAdjacency(bgpNeighbors []*openngfwv1.BgpNeighborRuntimeStatus, ospfNeighbors []*openngfwv1.OspfNeighborRuntimeStatus) bool {
	for _, neighbor := range bgpNeighbors {
		if strings.EqualFold(neighbor.GetState(), "Established") {
			return true
		}
	}
	for _, neighbor := range ospfNeighbors {
		if strings.HasPrefix(strings.ToLower(neighbor.GetState()), "full") {
			return true
		}
	}
	return false
}

func frrNeighborSummary(bgpNeighbors []*openngfwv1.BgpNeighborRuntimeStatus, ospfNeighbors []*openngfwv1.OspfNeighborRuntimeStatus) string {
	return fmt.Sprintf("%d BGP neighbor(s), %d OSPF neighbor(s)", len(bgpNeighbors), len(ospfNeighbors))
}

func jsonObject(value any) (map[string]any, bool) {
	object, ok := value.(map[string]any)
	return object, ok
}

func jsonString(fields map[string]any, keys ...string) string {
	for _, key := range keys {
		switch value := fields[key].(type) {
		case string:
			if strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		case float64:
			return strconv.FormatFloat(value, 'f', -1, 64)
		case bool:
			return strconv.FormatBool(value)
		}
	}
	return ""
}

func jsonUint64(fields map[string]any, keys ...string) uint64 {
	for _, key := range keys {
		switch value := fields[key].(type) {
		case float64:
			if value > 0 {
				return uint64(value)
			}
		case string:
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
			if err == nil {
				return parsed
			}
		}
	}
	return 0
}

func hasAnyJSONKey(fields map[string]any, keys ...string) bool {
	for _, key := range keys {
		if _, ok := fields[key]; ok {
			return true
		}
	}
	return false
}

func wireguardRuntimeStatus(ctx context.Context, cfg SystemStatusConfig) *openngfwv1.WireGuardRuntimeStatus {
	if !systemManagesEngine(cfg, "wireguard") {
		return &openngfwv1.WireGuardRuntimeStatus{
			State:  "not-configured",
			Detail: "wireguard engine is not registered in this status context",
		}
	}
	if missing := missingCommands(cfg, []string{"wg"}); len(missing) > 0 {
		if cfg.DryRun {
			return &openngfwv1.WireGuardRuntimeStatus{
				State:  "simulation",
				Detail: "wg command is missing; dry-run cannot install or inspect WireGuard runtime state",
			}
		}
		return &openngfwv1.WireGuardRuntimeStatus{
			State:  "degraded",
			Detail: "wg command is missing; WireGuard runtime state cannot be inspected",
		}
	}
	if cfg.DryRun {
		return &openngfwv1.WireGuardRuntimeStatus{
			State:  "simulation",
			Detail: "dry-run does not install WireGuard interfaces; commit in enforcing mode to collect runtime evidence",
		}
	}
	if cfg.CommandLookup != nil && cfg.CommandRun == nil {
		return &openngfwv1.WireGuardRuntimeStatus{
			State:  "unknown",
			Detail: "runtime WireGuard query is not configured in this status context",
		}
	}
	raw, err := runCommand(ctx, cfg, "wg", "show", "interfaces")
	if err != nil {
		return &openngfwv1.WireGuardRuntimeStatus{
			State:  "unknown",
			Detail: "could not inspect WireGuard interfaces: " + trimCommandError(raw, err),
		}
	}
	names := strings.Fields(string(raw))
	if len(names) == 0 {
		return &openngfwv1.WireGuardRuntimeStatus{
			State:  "inactive",
			Detail: "no WireGuard interfaces are installed",
		}
	}
	sort.Strings(names)
	status := &openngfwv1.WireGuardRuntimeStatus{
		State:      "waiting",
		Interfaces: make([]*openngfwv1.WireGuardInterfaceStatus, 0, len(names)),
	}
	var totalPeers, activePeers int
	var degraded bool
	for _, name := range names {
		iface := wireguardInterfaceStatus(ctx, cfg, name)
		status.Interfaces = append(status.Interfaces, iface)
		totalPeers += int(iface.GetPeerCount())
		activePeers += int(iface.GetActivePeerCount())
		if iface.GetState() == "degraded" || iface.GetState() == "unknown" {
			degraded = true
		}
	}
	switch {
	case degraded:
		status.State = "degraded"
		status.Detail = fmt.Sprintf("%d WireGuard interface(s); one or more runtime queries failed", len(status.Interfaces))
	case activePeers > 0:
		status.State = "active"
		status.Detail = fmt.Sprintf("%d WireGuard interface(s), %d/%d peer(s) with recorded handshakes", len(status.Interfaces), activePeers, totalPeers)
	default:
		status.State = "waiting"
		status.Detail = fmt.Sprintf("%d WireGuard interface(s), no recorded peer handshakes", len(status.Interfaces))
	}
	return status
}

func wireguardInterfaceStatus(ctx context.Context, cfg SystemStatusConfig, name string) *openngfwv1.WireGuardInterfaceStatus {
	peersRaw, err := runCommand(ctx, cfg, "wg", "show", name, "peers")
	if err != nil {
		return &openngfwv1.WireGuardInterfaceStatus{
			Name:   name,
			State:  "degraded",
			Detail: "could not inspect WireGuard peers: " + trimCommandError(peersRaw, err),
		}
	}
	peerKeys := strings.Fields(string(peersRaw))
	sort.Strings(peerKeys)
	handshakes, handshakeErr := wireguardFieldMap(ctx, cfg, name, "latest-handshakes")
	transfers, transferErr := wireguardFieldMap(ctx, cfg, name, "transfer")
	endpoints, endpointErr := wireguardFieldMap(ctx, cfg, name, "endpoints")
	if handshakeErr != nil || transferErr != nil || endpointErr != nil {
		return &openngfwv1.WireGuardInterfaceStatus{
			Name:      name,
			State:     "degraded",
			Detail:    "could not inspect WireGuard peer runtime counters",
			PeerCount: uint32(len(peerKeys)),
		}
	}
	now := uint64(time.Now().Unix())
	out := &openngfwv1.WireGuardInterfaceStatus{
		Name:      name,
		PeerCount: uint32(len(peerKeys)),
		Peers:     make([]*openngfwv1.WireGuardPeerStatus, 0, len(peerKeys)),
	}
	for _, publicKey := range peerKeys {
		peer := wireguardPeerStatus(publicKey, now, handshakes[publicKey], transfers[publicKey], endpoints[publicKey])
		out.Peers = append(out.Peers, peer)
		if peer.GetLatestHandshakeUnixSeconds() > 0 {
			out.ActivePeerCount++
		}
	}
	switch {
	case len(peerKeys) == 0:
		out.State = "configured-no-peers"
		out.Detail = "interface is installed but has no peers"
	case out.ActivePeerCount > 0:
		out.State = "active"
		out.Detail = fmt.Sprintf("%d/%d peer(s) have recorded handshakes", out.ActivePeerCount, out.PeerCount)
	default:
		out.State = "waiting"
		out.Detail = fmt.Sprintf("%d peer(s), no recorded handshakes", out.PeerCount)
	}
	return out
}

func wireguardPeerStatus(publicKey string, now uint64, handshakeFields, transferFields, endpointFields []string) *openngfwv1.WireGuardPeerStatus {
	peer := &openngfwv1.WireGuardPeerStatus{
		PublicKey: publicKey,
		State:     "waiting",
		Detail:    "no handshake has been recorded",
	}
	if len(endpointFields) > 0 && endpointFields[0] != "(none)" {
		peer.Endpoint = endpointFields[0]
	}
	if len(handshakeFields) > 0 {
		handshake, _ := strconv.ParseUint(handshakeFields[0], 10, 64)
		peer.LatestHandshakeUnixSeconds = handshake
		if handshake > 0 {
			if now > handshake {
				peer.LatestHandshakeAgeSeconds = now - handshake
			}
			peer.State = "handshook"
			peer.Detail = fmt.Sprintf("latest handshake %s ago", secondsDetail(peer.LatestHandshakeAgeSeconds))
		}
	}
	if len(transferFields) > 0 {
		peer.RxBytes, _ = strconv.ParseUint(transferFields[0], 10, 64)
	}
	if len(transferFields) > 1 {
		peer.TxBytes, _ = strconv.ParseUint(transferFields[1], 10, 64)
	}
	return peer
}

func wireguardFieldMap(ctx context.Context, cfg SystemStatusConfig, iface, field string) (map[string][]string, error) {
	raw, err := runCommand(ctx, cfg, "wg", "show", iface, field)
	if err != nil {
		return nil, err
	}
	return parseWireguardFieldMap(raw), nil
}

func parseWireguardFieldMap(raw []byte) map[string][]string {
	out := map[string][]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		out[parts[0]] = parts[1:]
	}
	return out
}

func ipsecRuntimeStatus(ctx context.Context, cfg SystemStatusConfig) *openngfwv1.IpsecRuntimeStatus {
	if !systemManagesEngine(cfg, "strongswan") {
		return &openngfwv1.IpsecRuntimeStatus{
			State:  "not-configured",
			Detail: "strongSwan engine is not registered in this status context",
		}
	}
	if missing := missingCommands(cfg, []string{"swanctl"}); len(missing) > 0 {
		if cfg.DryRun {
			return &openngfwv1.IpsecRuntimeStatus{
				State:  "simulation",
				Detail: "swanctl command is missing; dry-run cannot inspect IPsec runtime state",
			}
		}
		return &openngfwv1.IpsecRuntimeStatus{
			State:  "degraded",
			Detail: "swanctl command is missing; IPsec runtime state cannot be inspected",
		}
	}
	if cfg.DryRun {
		return &openngfwv1.IpsecRuntimeStatus{
			State:  "simulation",
			Detail: "dry-run does not load strongSwan tunnels; commit in enforcing mode to collect IPsec runtime evidence",
		}
	}
	if cfg.CommandLookup != nil && cfg.CommandRun == nil {
		return &openngfwv1.IpsecRuntimeStatus{
			State:  "unknown",
			Detail: "runtime IPsec query is not configured in this status context",
		}
	}
	raw, err := runCommand(ctx, cfg, "swanctl", "--list-sas")
	if err != nil {
		return &openngfwv1.IpsecRuntimeStatus{
			State:  "unknown",
			Detail: "could not inspect IPsec SAs: " + trimCommandError(raw, err),
		}
	}
	tunnels := parseSwanctlListSAs(raw)
	if len(tunnels) == 0 {
		return &openngfwv1.IpsecRuntimeStatus{
			State:  "inactive",
			Detail: "swanctl returned no active IKE or CHILD SA evidence",
		}
	}
	status := &openngfwv1.IpsecRuntimeStatus{
		State:   "waiting",
		Tunnels: tunnels,
	}
	var active, installed uint32
	for _, tunnel := range tunnels {
		if tunnel.GetState() == "active" {
			active++
		}
		installed += tunnel.GetInstalledChildSaCount()
	}
	if active > 0 {
		status.State = "active"
		status.Detail = fmt.Sprintf("%d IPsec tunnel(s), %d with established IKE and %d installed CHILD SA(s)", len(tunnels), active, installed)
		return status
	}
	status.State = "waiting"
	status.Detail = fmt.Sprintf("%d IPsec tunnel(s), no established IKE with installed CHILD SAs", len(tunnels))
	return status
}

func parseSwanctlListSAs(raw []byte) []*openngfwv1.IpsecTunnelRuntimeStatus {
	var tunnels []*openngfwv1.IpsecTunnelRuntimeStatus
	var current *openngfwv1.IpsecTunnelRuntimeStatus
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		trimmed := strings.TrimSpace(line)
		name, rest, ok := strings.Cut(trimmed, ":")
		if !ok || strings.TrimSpace(name) == "" {
			continue
		}
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if current == nil {
				continue
			}
			current.ChildSaCount++
			childState := swanctlState(rest)
			if strings.EqualFold(childState, "installed") {
				current.InstalledChildSaCount++
			}
			continue
		}
		current = &openngfwv1.IpsecTunnelRuntimeStatus{
			Name:     strings.TrimSpace(name),
			IkeState: swanctlState(rest),
		}
		tunnels = append(tunnels, current)
	}
	for _, tunnel := range tunnels {
		switch {
		case strings.EqualFold(tunnel.GetIkeState(), "established") && tunnel.GetInstalledChildSaCount() > 0:
			tunnel.State = "active"
			tunnel.Detail = fmt.Sprintf("IKE established with %d/%d installed CHILD SA(s)", tunnel.GetInstalledChildSaCount(), tunnel.GetChildSaCount())
		case strings.EqualFold(tunnel.GetIkeState(), "established"):
			tunnel.State = "waiting"
			tunnel.Detail = "IKE is established but no installed CHILD SA was reported"
		case tunnel.GetIkeState() != "":
			tunnel.State = "waiting"
			tunnel.Detail = "IKE state " + strings.ToLower(tunnel.GetIkeState())
		default:
			tunnel.State = "unknown"
			tunnel.Detail = "IKE state was not reported"
		}
	}
	sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].GetName() < tunnels[j].GetName() })
	return tunnels
}

func swanctlState(rest string) string {
	parts := strings.Split(rest, ",")
	for _, part := range parts {
		token := strings.TrimSpace(part)
		if token == "" || strings.HasPrefix(token, "#") || strings.HasPrefix(strings.ToLower(token), "reqid ") {
			continue
		}
		switch strings.ToLower(token) {
		case "established", "connecting", "installed", "routed", "created", "rekeying", "deleting", "destroying":
			return strings.ToLower(token)
		}
	}
	return ""
}

func systemManagesEngine(cfg SystemStatusConfig, name string) bool {
	for _, engine := range cfg.Engines {
		if engine.Name == name {
			return true
		}
	}
	return false
}

func secondsDetail(seconds uint64) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%dm", seconds/60)
	}
	if seconds < 86400 {
		return fmt.Sprintf("%dh", seconds/3600)
	}
	return fmt.Sprintf("%dd", seconds/86400)
}

func runCommand(ctx context.Context, cfg SystemStatusConfig, name string, args ...string) ([]byte, error) {
	if cfg.CommandRun != nil {
		return cfg.CommandRun(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

func trimCommandError(out []byte, err error) string {
	text := strings.TrimSpace(string(out))
	if text == "" {
		return err.Error()
	}
	if len(text) > 240 {
		text = text[:240] + "..."
	}
	return err.Error() + ": " + text
}

func fanoutState(workers uint32) string {
	if workers > 1 {
		return "active"
	}
	return "single-worker"
}

func fanoutDetail(workers, cpus uint32) string {
	if workers == 0 {
		workers = 1
	}
	if cpus == 0 {
		return "Suricata NFQUEUE fan-out uses " + strconv.FormatUint(uint64(workers), 10) + " worker(s)"
	}
	return "Suricata NFQUEUE fan-out uses " + strconv.FormatUint(uint64(workers), 10) + " worker(s) on " + strconv.FormatUint(uint64(cpus), 10) + " host CPU(s)"
}
