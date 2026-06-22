package authz

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/detailtech/oss-ngfw/internal/proxytrust"
)

const (
	// OIDCLoginPath starts the browser SSO login flow.
	OIDCLoginPath = "/v1/auth/oidc/login"
	// OIDCCallbackPath receives the browser SSO provider callback.
	OIDCCallbackPath = "/v1/auth/oidc/callback"
	// OIDCLogoutPath clears the active browser SSO session.
	OIDCLogoutPath = "/v1/auth/logout"
	// OIDCStatusPath reports browser SSO availability and session status.
	OIDCStatusPath = "/v1/auth/oidc/status"
	// OIDCCSRFHeader carries the browser-session CSRF token.
	OIDCCSRFHeader = "X-Phragma-CSRF"

	// DefaultOIDCCookieName is the default browser SSO session cookie name.
	DefaultOIDCCookieName  = "openngfw_session"
	defaultOIDCStateTTL    = 10 * time.Minute
	defaultOIDCSessionTTL  = 8 * time.Hour
	defaultOIDCMaxStates   = 1024
	defaultOIDCMaxSessions = 1024
)

// OIDCConfig configures the single-node browser SSO path. Provider secrets are
// loaded out of band and never serialized.
type OIDCConfig struct {
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	RedirectURL  string   `json:"redirect_url"`
	RoleClaim    string   `json:"role_claim"`
	DefaultRole  string   `json:"default_role"`
	Scopes       []string `json:"scopes,omitempty"`
	ClientSecret string   `json:"-"`
	CookieName   string   `json:"cookie_name,omitempty"`
	CookieSecure bool     `json:"cookie_secure"`
	// TrustedProxyCIDRs gates forwarding headers used by browser CSRF checks.
	TrustedProxyCIDRs []string      `json:"trusted_proxy_cidrs,omitempty"`
	StateTTL          time.Duration `json:"state_ttl,omitempty"`
	SessionTTL        time.Duration `json:"session_ttl,omitempty"`
	MaxStates         int           `json:"max_states,omitempty"`
	MaxSessions       int           `json:"max_sessions,omitempty"`
}

// OIDCInventory is the non-secret access-administration view of browser SSO
// configuration.
type OIDCInventory struct {
	Enabled           bool
	Issuer            string
	ClientID          string
	RoleClaim         string
	DefaultRole       string
	CookieSecure      bool
	Scopes            []string
	TrustedProxyCIDRs []string
	SessionTTLSeconds uint64
}

// OIDCSessionInventory is non-secret session state for access administration.
// It never exposes session tokens or CSRF tokens.
type OIDCSessionInventory struct {
	ActiveSessions             uint32
	MaxSessions                uint32
	SessionRevocationAvailable bool
	Detail                     string
	Sessions                   []OIDCSessionRecord
}

// OIDCPreflight is the non-secret, read-only readiness proof for browser SSO.
// It deliberately excludes client secrets, redirect URLs, cookie names,
// provider tokens, and raw provider error strings.
type OIDCPreflight struct {
	State     string
	Label     string
	Detail    string
	Inventory OIDCInventory
	Checks    []OIDCPreflightCheck
	Blockers  []string
	Warnings  []string
	Evidence  []string
}

// OIDCPreflightCheck is one sanitized readiness check.
type OIDCPreflightCheck struct {
	ID         string
	Label      string
	State      string
	Class      string
	Detail     string
	Evidence   string
	NextAction string
}

// OIDCSessionRecord is a non-secret view of one active browser session. The
// ID is a hash of the server-side session token, never the token itself.
type OIDCSessionRecord struct {
	ID                 string
	Actor              string
	Role               string
	AuthSource         string
	ExpiresAt          time.Time
	SecondsUntilExpiry uint64
}

// OIDCAuthenticator owns the browser OIDC flow and opaque session store. The
// sessions are intentionally server-side; the browser receives only an
// HttpOnly cookie and never sees provider tokens.
type OIDCAuthenticator struct {
	cfg      OIDCConfig
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	proxies  proxytrust.Set

	mu       sync.Mutex
	states   map[string]loginState
	sessions map[string]session
	now      func() time.Time
}

type loginState struct {
	Nonce        string
	CodeVerifier string
	ReturnPath   string
	ExpiresAt    time.Time
}

type session struct {
	Identity  Identity
	ExpiresAt time.Time
	CSRFToken string
}

// NewOIDCAuthenticator discovers the provider and returns an authenticator for
// browser login plus session-cookie to bearer-token bridging.
func NewOIDCAuthenticator(ctx context.Context, cfg OIDCConfig) (*OIDCAuthenticator, error) {
	cfg = normalizeOIDCConfig(cfg)
	if err := validateOIDCConfig(cfg); err != nil {
		return nil, err
	}
	proxies, err := proxytrust.New(cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, fmt.Errorf("configure OIDC trusted proxies: %w", err)
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC issuer: %w", err)
	}
	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}
	return &OIDCAuthenticator{
		cfg:      cfg,
		oauth:    oauthCfg,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		proxies:  proxies,
		states:   map[string]loginState{},
		sessions: map[string]session{},
		now:      func() time.Time { return time.Now().UTC() },
	}, nil
}

// Inventory returns the non-secret OIDC configuration posture. It does not
// include client secrets, redirect URLs, cookie names, provider tokens, or file
// paths.
func (o *OIDCAuthenticator) Inventory() OIDCInventory {
	if o == nil {
		return OIDCInventory{Enabled: false}
	}
	cfg := normalizeOIDCConfig(o.cfg)
	return OIDCInventory{
		Enabled:           true,
		Issuer:            cfg.Issuer,
		ClientID:          cfg.ClientID,
		RoleClaim:         cfg.RoleClaim,
		DefaultRole:       cfg.DefaultRole,
		CookieSecure:      cfg.CookieSecure,
		Scopes:            append([]string(nil), cfg.Scopes...),
		TrustedProxyCIDRs: append([]string(nil), cfg.TrustedProxyCIDRs...),
		SessionTTLSeconds: uint64(cfg.SessionTTL.Seconds()),
	}
}

// SessionInventory returns non-secret OIDC session posture. Admin workflows can
// revoke sessions by the digest IDs returned here.
func (o *OIDCAuthenticator) SessionInventory() OIDCSessionInventory {
	if o == nil {
		return OIDCSessionInventory{
			Detail: "OIDC browser SSO is not configured.",
		}
	}
	cfg := normalizeOIDCConfig(o.cfg)
	o.mu.Lock()
	now := o.now()
	o.reapExpiredLocked(now)
	sessions := o.sessionRecordsLocked(now)
	active := len(sessions)
	o.mu.Unlock()
	return OIDCSessionInventory{
		ActiveSessions:             uint32Count(active),
		MaxSessions:                uint32Count(cfg.MaxSessions),
		SessionRevocationAvailable: true,
		Sessions:                   sessions,
		Detail: fmt.Sprintf(
			"%d active OIDC browser session(s); admin listing and revocation are available through audited access administration.",
			active,
		),
	}
}

// Preflight verifies browser SSO rollout readiness without mutating provider,
// user, or session state. Returned strings are sanitized for the admin UI and
// evidence packets.
func (o *OIDCAuthenticator) Preflight(ctx context.Context) OIDCPreflight {
	if ctx == nil {
		ctx = context.Background()
	}
	if o == nil {
		return OIDCPreflight{
			State:     "blocked",
			Label:     "1 blocker",
			Detail:    "OIDC browser SSO is not configured.",
			Inventory: OIDCInventory{Enabled: false},
			Checks: []OIDCPreflightCheck{{
				ID:         "oidc-configured",
				Label:      "OIDC configured",
				State:      "blocked",
				Class:      "bad",
				Detail:     "OIDC browser SSO is not configured.",
				Evidence:   "No OIDC authenticator is active in this process.",
				NextAction: "Configure an issuer, client ID, redirect callback, and client secret before running preflight.",
			}},
			Blockers: []string{"OIDC browser SSO is not configured."},
			Evidence: []string{"No OIDC authenticator is active in this process."},
		}
	}

	cfg := normalizeOIDCConfig(o.cfg)
	preflightCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	checks := []OIDCPreflightCheck{
		oidcProviderDiscoveryCheck(preflightCtx, cfg),
		oidcRedirectCallbackCheck(cfg),
		oidcCookieSecureCheck(cfg),
		oidcScopeCheck(cfg),
		oidcRoleMappingCheck(cfg),
		oidcTrustedProxyCheck(cfg),
		oidcSessionLimitCheck(cfg),
		oidcSessionCapacityCheck(o.SessionInventory()),
	}
	out := OIDCPreflight{
		Inventory: o.Inventory(),
		Checks:    checks,
	}
	out.State, out.Label, out.Detail = summarizeOIDCPreflight(checks)
	for _, check := range checks {
		if check.Evidence != "" {
			out.Evidence = append(out.Evidence, check.Evidence)
		}
		switch check.Class {
		case "bad":
			out.Blockers = append(out.Blockers, check.Detail)
		case "warn":
			out.Warnings = append(out.Warnings, check.Detail)
		}
	}
	out.Blockers = dedupeOIDCStrings(out.Blockers)
	out.Warnings = dedupeOIDCStrings(out.Warnings)
	out.Evidence = dedupeOIDCStrings(out.Evidence)
	return out
}

func oidcProviderDiscoveryCheck(ctx context.Context, cfg OIDCConfig) OIDCPreflightCheck {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return OIDCPreflightCheck{
			ID:         "provider-discovery",
			Label:      "Provider discovery",
			State:      "blocked",
			Class:      "bad",
			Detail:     "Provider discovery failed; verify issuer reachability from the firewall.",
			Evidence:   "OpenID Connect discovery document could not be loaded.",
			NextAction: "Verify DNS, routing, TLS trust, firewall policy, and the configured issuer.",
		}
	}
	var claims struct {
		JwksURI string `json:"jwks_uri"`
	}
	check := OIDCPreflightCheck{
		ID:         "provider-discovery",
		Label:      "Provider discovery",
		State:      "ready",
		Class:      "ok",
		Detail:     "Provider discovery loaded successfully.",
		Evidence:   "OpenID Connect discovery document loaded.",
		NextAction: "Keep issuer DNS and TLS reachable from the firewall.",
	}
	if err := provider.Claims(&claims); err != nil || strings.TrimSpace(claims.JwksURI) == "" {
		return OIDCPreflightCheck{
			ID:         "jwks-metadata",
			Label:      "JWKS metadata",
			State:      "blocked",
			Class:      "bad",
			Detail:     "Provider discovery did not expose usable JWKS metadata.",
			Evidence:   "Discovery document loaded, but signing-key metadata was not usable.",
			NextAction: "Verify the provider exposes jwks_uri in its discovery document.",
		}
	}
	jwks := oidcJWKSReachabilityCheck(ctx, claims.JwksURI)
	return mergeOIDCDiscoveryChecks(check, jwks)
}

func oidcJWKSReachabilityCheck(ctx context.Context, rawURL string) OIDCPreflightCheck {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || !u.IsAbs() || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return OIDCPreflightCheck{
			ID:         "jwks-metadata",
			Label:      "JWKS metadata",
			State:      "blocked",
			Class:      "bad",
			Detail:     "Provider signing-key metadata is not a usable HTTP endpoint.",
			Evidence:   "Provider advertised signing-key metadata, but the endpoint shape was invalid.",
			NextAction: "Fix provider discovery metadata before browser SSO rollout.",
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return OIDCPreflightCheck{
			ID:         "jwks-metadata",
			Label:      "JWKS metadata",
			State:      "blocked",
			Class:      "bad",
			Detail:     "Provider signing-key metadata could not be requested.",
			Evidence:   "Provider advertised signing-key metadata, but the request could not be built.",
			NextAction: "Fix provider discovery metadata before browser SSO rollout.",
		}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return OIDCPreflightCheck{
			ID:         "jwks-metadata",
			Label:      "JWKS metadata",
			State:      "blocked",
			Class:      "bad",
			Detail:     "Provider signing-key metadata was not reachable from the firewall.",
			Evidence:   "Provider advertised signing-key metadata, but the endpoint could not be reached.",
			NextAction: "Verify DNS, routing, TLS trust, and egress policy to the provider.",
		}
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return OIDCPreflightCheck{
			ID:         "jwks-metadata",
			Label:      "JWKS metadata",
			State:      "blocked",
			Class:      "bad",
			Detail:     "Provider signing-key metadata returned a non-success status.",
			Evidence:   "Provider advertised signing-key metadata, but it did not return a success status.",
			NextAction: "Verify provider availability and any upstream access controls.",
		}
	}
	return OIDCPreflightCheck{
		ID:         "jwks-metadata",
		Label:      "JWKS metadata",
		State:      "ready",
		Class:      "ok",
		Detail:     "Provider signing-key metadata is reachable.",
		Evidence:   "Provider advertised and served JWKS metadata.",
		NextAction: "Keep issuer signing-key metadata reachable from the firewall.",
	}
}

func mergeOIDCDiscoveryChecks(discovery, jwks OIDCPreflightCheck) OIDCPreflightCheck {
	if jwks.Class == "ok" {
		discovery.Detail = "Provider discovery and signing-key metadata loaded successfully."
		discovery.Evidence = discovery.Evidence + " " + jwks.Evidence
		return discovery
	}
	return jwks
}

func oidcRedirectCallbackCheck(cfg OIDCConfig) OIDCPreflightCheck {
	redirect, err := url.Parse(cfg.RedirectURL)
	if err != nil || !redirect.IsAbs() || redirect.Host == "" {
		return OIDCPreflightCheck{
			ID:         "redirect-callback",
			Label:      "Redirect callback",
			State:      "blocked",
			Class:      "bad",
			Detail:     "OIDC redirect callback is not a usable absolute URL.",
			Evidence:   "Redirect callback validation failed without exposing the configured URL.",
			NextAction: "Configure an HTTPS redirect callback before browser SSO rollout.",
		}
	}
	if redirect.Scheme == "https" {
		return OIDCPreflightCheck{
			ID:         "redirect-callback",
			Label:      "Redirect callback",
			State:      "ready",
			Class:      "ok",
			Detail:     "OIDC redirect callback uses HTTPS.",
			Evidence:   "Redirect callback scheme is HTTPS.",
			NextAction: "Keep the IdP redirect registration aligned with the appliance callback.",
		}
	}
	if redirect.Scheme == "http" && isLoopbackRedirectHost(redirect.Hostname()) {
		return OIDCPreflightCheck{
			ID:         "redirect-callback",
			Label:      "Redirect callback",
			State:      "review",
			Class:      "warn",
			Detail:     "OIDC redirect callback uses loopback HTTP, which is only suitable for local development.",
			Evidence:   "Redirect callback uses loopback HTTP.",
			NextAction: "Use an HTTPS callback URL before production browser SSO rollout.",
		}
	}
	return OIDCPreflightCheck{
		ID:         "redirect-callback",
		Label:      "Redirect callback",
		State:      "blocked",
		Class:      "bad",
		Detail:     "OIDC redirect callback does not use HTTPS.",
		Evidence:   "Redirect callback scheme is not production-safe.",
		NextAction: "Configure an HTTPS callback URL before browser SSO rollout.",
	}
}

func oidcCookieSecureCheck(cfg OIDCConfig) OIDCPreflightCheck {
	if cfg.CookieSecure {
		return OIDCPreflightCheck{
			ID:         "session-cookie",
			Label:      "Session cookie",
			State:      "ready",
			Class:      "ok",
			Detail:     "OIDC browser sessions use Secure cookies.",
			Evidence:   "OIDC cookie Secure attribute is enabled.",
			NextAction: "Keep TLS enabled on the management surface.",
		}
	}
	return OIDCPreflightCheck{
		ID:         "session-cookie",
		Label:      "Session cookie",
		State:      "blocked",
		Class:      "bad",
		Detail:     "OIDC browser sessions are not using Secure cookies.",
		Evidence:   "OIDC cookie Secure attribute is disabled.",
		NextAction: "Enable Secure cookies before exposing browser SSO.",
	}
}

func oidcScopeCheck(cfg OIDCConfig) OIDCPreflightCheck {
	scopes := make(map[string]bool, len(cfg.Scopes))
	for _, scope := range cfg.Scopes {
		scopes[strings.ToLower(strings.TrimSpace(scope))] = true
	}
	if !scopes[oidc.ScopeOpenID] {
		return OIDCPreflightCheck{
			ID:         "scopes",
			Label:      "OIDC scopes",
			State:      "blocked",
			Class:      "bad",
			Detail:     "OIDC scopes do not include openid.",
			Evidence:   "Configured OIDC scopes are missing openid.",
			NextAction: "Add the openid scope before browser SSO rollout.",
		}
	}
	var missing []string
	for _, recommended := range []string{"profile", "email"} {
		if !scopes[recommended] {
			missing = append(missing, recommended)
		}
	}
	if len(missing) > 0 {
		return OIDCPreflightCheck{
			ID:         "scopes",
			Label:      "OIDC scopes",
			State:      "review",
			Class:      "warn",
			Detail:     "OIDC scopes are usable but omit recommended identity attributes.",
			Evidence:   "Configured OIDC scopes include openid.",
			NextAction: "Add profile and email scopes when the IdP supports them.",
		}
	}
	return OIDCPreflightCheck{
		ID:         "scopes",
		Label:      "OIDC scopes",
		State:      "ready",
		Class:      "ok",
		Detail:     "OIDC scopes include openid, profile, and email.",
		Evidence:   "Configured OIDC scopes include openid, profile, and email.",
		NextAction: "Keep IdP consent and claim release aligned with these scopes.",
	}
}

func oidcRoleMappingCheck(cfg OIDCConfig) OIDCPreflightCheck {
	if _, err := ParseRole(cfg.DefaultRole); err != nil {
		return OIDCPreflightCheck{
			ID:         "role-mapping",
			Label:      "Role mapping",
			State:      "blocked",
			Class:      "bad",
			Detail:     "OIDC default role is not a valid OpenNGFW role.",
			Evidence:   "OIDC role fallback validation failed.",
			NextAction: "Use viewer, operator, or admin as the default role.",
		}
	}
	return OIDCPreflightCheck{
		ID:         "role-mapping",
		Label:      "Role mapping",
		State:      "ready",
		Class:      "ok",
		Detail:     "OIDC role claim and default role are valid.",
		Evidence:   fmt.Sprintf("OIDC role claim %q defaults to %s.", cfg.RoleClaim, cfg.DefaultRole),
		NextAction: "Verify IdP group or role claims match OpenNGFW role names.",
	}
}

func oidcTrustedProxyCheck(cfg OIDCConfig) OIDCPreflightCheck {
	if len(cfg.TrustedProxyCIDRs) > 0 {
		return OIDCPreflightCheck{
			ID:         "trusted-proxy",
			Label:      "Trusted proxy",
			State:      "ready",
			Class:      "ok",
			Detail:     "Trusted proxy CIDRs are configured for forwarded scheme checks.",
			Evidence:   fmt.Sprintf("%d trusted proxy CIDR(s) configured.", len(cfg.TrustedProxyCIDRs)),
			NextAction: "Keep proxy CIDRs limited to management-plane reverse proxies.",
		}
	}
	return OIDCPreflightCheck{
		ID:         "trusted-proxy",
		Label:      "Trusted proxy",
		State:      "ready",
		Class:      "ok",
		Detail:     "Forwarded scheme headers are ignored because no trusted proxies are configured.",
		Evidence:   "No trusted proxy CIDRs configured; browser same-origin checks rely on direct request properties.",
		NextAction: "Add trusted proxy CIDRs only when TLS terminates before the appliance.",
	}
}

func oidcSessionLimitCheck(cfg OIDCConfig) OIDCPreflightCheck {
	if cfg.SessionTTL <= 0 || cfg.MaxSessions <= 0 || cfg.MaxStates <= 0 {
		return OIDCPreflightCheck{
			ID:         "session-limits",
			Label:      "Session limits",
			State:      "blocked",
			Class:      "bad",
			Detail:     "OIDC session, state, or capacity limits are invalid.",
			Evidence:   "Session TTL, login-state capacity, and session capacity must be positive.",
			NextAction: "Configure positive session TTL, max states, and max sessions.",
		}
	}
	if cfg.SessionTTL > 24*time.Hour {
		return OIDCPreflightCheck{
			ID:         "session-limits",
			Label:      "Session limits",
			State:      "review",
			Class:      "warn",
			Detail:     "OIDC session TTL is longer than one day.",
			Evidence:   fmt.Sprintf("OIDC session TTL is %s.", cfg.SessionTTL),
			NextAction: "Use a shorter browser session TTL for shared operations environments.",
		}
	}
	return OIDCPreflightCheck{
		ID:         "session-limits",
		Label:      "Session limits",
		State:      "ready",
		Class:      "ok",
		Detail:     "OIDC session TTL and capacity limits are bounded.",
		Evidence:   fmt.Sprintf("OIDC session TTL is %s with %d max sessions.", cfg.SessionTTL, cfg.MaxSessions),
		NextAction: "Review session limits against expected administrator concurrency.",
	}
}

func oidcSessionCapacityCheck(sessions OIDCSessionInventory) OIDCPreflightCheck {
	active := sessions.ActiveSessions
	maximum := sessions.MaxSessions
	if maximum == 0 {
		return OIDCPreflightCheck{
			ID:         "session-capacity",
			Label:      "Session capacity",
			State:      "blocked",
			Class:      "bad",
			Detail:     "OIDC session capacity is not available.",
			Evidence:   "OIDC session max capacity is zero.",
			NextAction: "Configure a positive OIDC max session count.",
		}
	}
	if active >= maximum {
		return OIDCPreflightCheck{
			ID:         "session-capacity",
			Label:      "Session capacity",
			State:      "blocked",
			Class:      "bad",
			Detail:     "OIDC session store is at capacity.",
			Evidence:   fmt.Sprintf("%d of %d OIDC sessions are active.", active, maximum),
			NextAction: "Revoke stale sessions or raise the configured max session count.",
		}
	}
	if float64(active) >= float64(maximum)*0.8 {
		return OIDCPreflightCheck{
			ID:         "session-capacity",
			Label:      "Session capacity",
			State:      "review",
			Class:      "warn",
			Detail:     "OIDC session store is approaching capacity.",
			Evidence:   fmt.Sprintf("%d of %d OIDC sessions are active.", active, maximum),
			NextAction: "Revoke stale sessions or review expected admin concurrency.",
		}
	}
	return OIDCPreflightCheck{
		ID:         "session-capacity",
		Label:      "Session capacity",
		State:      "ready",
		Class:      "ok",
		Detail:     "OIDC session store has available capacity.",
		Evidence:   fmt.Sprintf("%d of %d OIDC sessions are active.", active, maximum),
		NextAction: "Use Settings session controls to revoke stale browser sessions.",
	}
}

func summarizeOIDCPreflight(checks []OIDCPreflightCheck) (string, string, string) {
	var blockers, warnings int
	for _, check := range checks {
		switch check.Class {
		case "bad":
			blockers++
		case "warn":
			warnings++
		}
	}
	switch {
	case blockers > 0:
		return "blocked",
			fmt.Sprintf("%d blocker%s", blockers, pluralSuffix(blockers)),
			"OIDC browser SSO preflight has blockers before production rollout."
	case warnings > 0:
		return "review",
			fmt.Sprintf("%d review item%s", warnings, pluralSuffix(warnings)),
			"OIDC browser SSO preflight has review items before production rollout."
	default:
		return "ready", "ready", "OIDC browser SSO preflight is ready for production rollout."
	}
}

func pluralSuffix(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func dedupeOIDCStrings(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
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

// ListSessions returns the non-secret active session inventory.
func (o *OIDCAuthenticator) ListSessions() []OIDCSessionRecord {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	o.reapExpiredLocked(now)
	return o.sessionRecordsLocked(now)
}

// RevokeSession removes an active browser session by non-secret session ID.
func (o *OIDCAuthenticator) RevokeSession(id string) (OIDCSessionRecord, bool) {
	if o == nil {
		return OIDCSessionRecord{}, false
	}
	want := normalizeOIDCSessionID(id)
	if want == "" {
		return OIDCSessionRecord{}, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	o.reapExpiredLocked(now)
	for token, sess := range o.sessions {
		rec := oidcSessionRecord(token, sess, now)
		if normalizeOIDCSessionID(rec.ID) == want {
			delete(o.sessions, token)
			return rec, true
		}
	}
	return OIDCSessionRecord{}, false
}

// RevokeAllSessions removes all active browser sessions and returns the count
// invalidated. Provider lifecycle changes use this to prevent old IdP/session
// assumptions from surviving a runtime config swap.
func (o *OIDCAuthenticator) RevokeAllSessions() uint32 {
	if o == nil {
		return 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	o.reapExpiredLocked(now)
	count := uint32Count(len(o.sessions))
	o.sessions = map[string]session{}
	return count
}

// SessionRecord returns one active session by non-secret session ID without
// mutating the server-side session store.
func (o *OIDCAuthenticator) SessionRecord(id string) (OIDCSessionRecord, bool) {
	if o == nil {
		return OIDCSessionRecord{}, false
	}
	want := normalizeOIDCSessionID(id)
	if want == "" {
		return OIDCSessionRecord{}, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	o.reapExpiredLocked(now)
	for token, sess := range o.sessions {
		rec := oidcSessionRecord(token, sess, now)
		if normalizeOIDCSessionID(rec.ID) == want {
			return rec, true
		}
	}
	return OIDCSessionRecord{}, false
}

func normalizeOIDCConfig(cfg OIDCConfig) OIDCConfig {
	cfg.Issuer = strings.TrimSpace(cfg.Issuer)
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	cfg.RedirectURL = strings.TrimSpace(cfg.RedirectURL)
	cfg.RoleClaim = strings.TrimSpace(cfg.RoleClaim)
	if cfg.RoleClaim == "" {
		cfg.RoleClaim = "role"
	}
	cfg.DefaultRole = strings.TrimSpace(cfg.DefaultRole)
	if cfg.DefaultRole == "" {
		cfg.DefaultRole = RoleViewer.String()
	}
	if cfg.CookieName == "" {
		cfg.CookieName = DefaultOIDCCookieName
	}
	if cfg.StateTTL <= 0 {
		cfg.StateTTL = defaultOIDCStateTTL
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = defaultOIDCSessionTTL
	}
	if cfg.MaxStates <= 0 {
		cfg.MaxStates = defaultOIDCMaxStates
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = defaultOIDCMaxSessions
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	return cfg
}

func uint32Count(n int) uint32 {
	if n <= 0 {
		return 0
	}
	return uint32(n)
}

func (o *OIDCAuthenticator) sessionRecordsLocked(now time.Time) []OIDCSessionRecord {
	out := make([]OIDCSessionRecord, 0, len(o.sessions))
	for token, sess := range o.sessions {
		out = append(out, oidcSessionRecord(token, sess, now))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ExpiresAt.Equal(out[j].ExpiresAt) {
			return out[i].ExpiresAt.Before(out[j].ExpiresAt)
		}
		if out[i].Actor != out[j].Actor {
			return out[i].Actor < out[j].Actor
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func oidcSessionRecord(token string, sess session, now time.Time) OIDCSessionRecord {
	seconds := uint64(0)
	if sess.ExpiresAt.After(now) {
		seconds = uint64(sess.ExpiresAt.Sub(now).Seconds())
	}
	return OIDCSessionRecord{
		ID:                 oidcSessionID(token),
		Actor:              sess.Identity.Name,
		Role:               sess.Identity.Role.String(),
		AuthSource:         sess.Identity.AuthSource,
		ExpiresAt:          sess.ExpiresAt.UTC(),
		SecondsUntilExpiry: seconds,
	}
}

func oidcSessionID(token string) string {
	digest := sha256.Sum256([]byte(token))
	return "oidc-session-sha256:" + hex.EncodeToString(digest[:])
}

// OIDCSessionIDForToken returns the non-secret revocation ID for an opaque
// OIDC session token.
func OIDCSessionIDForToken(token string) string {
	return oidcSessionID(token)
}

func normalizeOIDCSessionID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}

func validateOIDCConfig(cfg OIDCConfig) error {
	if cfg.Issuer == "" {
		return errors.New("OIDC issuer is required")
	}
	if cfg.ClientID == "" {
		return errors.New("OIDC client ID is required")
	}
	if cfg.RedirectURL == "" {
		return errors.New("OIDC redirect URL is required")
	}
	if _, err := ParseRole(cfg.DefaultRole); err != nil {
		return fmt.Errorf("OIDC default role: %w", err)
	}
	redirect, err := url.Parse(cfg.RedirectURL)
	if err != nil {
		return fmt.Errorf("OIDC redirect URL: %w", err)
	}
	if !redirect.IsAbs() || redirect.Host == "" || (redirect.Scheme != "https" && redirect.Scheme != "http") {
		return errors.New("OIDC redirect URL must be an absolute http(s) URL")
	}
	if redirect.Scheme == "http" && !isLoopbackRedirectHost(redirect.Hostname()) {
		return errors.New("OIDC redirect URL must use https unless the redirect host is loopback")
	}
	return nil
}

func isLoopbackRedirectHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ServeHTTP handles OIDC login, callback, logout, and public status endpoints.
func (o *OIDCAuthenticator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	switch r.URL.Path {
	case OIDCLoginPath:
		o.handleLogin(w, r)
	case OIDCCallbackPath:
		o.handleCallback(w, r)
	case OIDCLogoutPath:
		o.handleLogout(w, r)
	case OIDCStatusPath:
		o.handleStatus(w, r)
	default:
		http.NotFound(w, r)
	}
}

// WithSessionCookieAuth maps a validated session cookie to the Authorization
// header expected by grpc-gateway. Explicit bearer tokens always win.
func (o *OIDCAuthenticator) WithSessionCookieAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			if c, err := r.Cookie(o.cfg.CookieName); err == nil {
				if sess, ok := o.lookupSession(c.Value); ok {
					if unsafeHTTPMethod(r.Method) {
						if err := o.validateSessionCSRF(r, sess); err != nil {
							http.Error(w, err.Error(), http.StatusForbidden)
							return
						}
					}
					clone := r.Clone(r.Context())
					clone.Header.Set("Authorization", "Bearer "+c.Value)
					r = clone
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// LookupSession validates an opaque session token and returns the identity used
// by the shared RBAC interceptor.
func (o *OIDCAuthenticator) LookupSession(token string) (Identity, bool) {
	sess, ok := o.lookupSession(token)
	if !ok {
		return Identity{}, false
	}
	return sess.Identity, true
}

func (o *OIDCAuthenticator) lookupSession(token string) (session, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	o.reapExpiredLocked(now)
	sess, ok := o.sessions[token]
	if !ok {
		return session{}, false
	}
	if !now.Before(sess.ExpiresAt) {
		delete(o.sessions, token)
		return session{}, false
	}
	return sess, true
}

func (o *OIDCAuthenticator) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state, err := randomURLToken(32)
	if err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}
	nonce, err := randomURLToken(32)
	if err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}
	verifier, err := randomURLToken(32)
	if err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}
	ret := safeReturnPath(r.URL.Query().Get("return"))
	o.mu.Lock()
	now := o.now()
	o.reapExpiredLocked(now)
	if o.states == nil {
		o.states = map[string]loginState{}
	}
	o.states[state] = loginState{
		Nonce:        nonce,
		CodeVerifier: verifier,
		ReturnPath:   ret,
		ExpiresAt:    now.Add(o.cfg.StateTTL),
	}
	o.enforceStateLimitLocked()
	o.mu.Unlock()
	http.Redirect(w, r, o.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	), http.StatusFound)
}

func (o *OIDCAuthenticator) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Query().Get("error") != "" {
		http.Error(w, "OIDC login failed", http.StatusUnauthorized)
		return
	}
	st, ok := o.popState(r.URL.Query().Get("state"))
	if !ok {
		http.Error(w, "OIDC login failed", http.StatusUnauthorized)
		return
	}
	token, err := o.oauth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(st.CodeVerifier))
	if err != nil {
		http.Error(w, "OIDC login failed", http.StatusUnauthorized)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "OIDC login failed", http.StatusUnauthorized)
		return
	}
	idToken, err := o.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "OIDC login failed", http.StatusUnauthorized)
		return
	}
	if idToken.Nonce != st.Nonce {
		http.Error(w, "OIDC login failed", http.StatusUnauthorized)
		return
	}
	id, err := o.identityFromToken(idToken)
	if err != nil {
		http.Error(w, "OIDC login failed", http.StatusUnauthorized)
		return
	}
	sessionToken, err := randomURLToken(32)
	if err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	csrfToken, err := randomURLToken(32)
	if err != nil {
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	expires := o.now().Add(o.cfg.SessionTTL)
	o.storeSession(sessionToken, session{Identity: id, ExpiresAt: expires, CSRFToken: csrfToken})
	http.SetCookie(w, o.sessionCookie(sessionToken, int(o.cfg.SessionTTL.Seconds())))
	http.Redirect(w, r, st.ReturnPath, http.StatusFound)
}

func (o *OIDCAuthenticator) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c, err := r.Cookie(o.cfg.CookieName); err == nil {
		o.mu.Lock()
		delete(o.sessions, c.Value)
		o.mu.Unlock()
	}
	http.SetCookie(w, o.expiredCookie())
	w.WriteHeader(http.StatusNoContent)
}

func (o *OIDCAuthenticator) handleStatus(w http.ResponseWriter, r *http.Request) {
	body := map[string]any{
		"enabled":     true,
		"issuer":      o.cfg.Issuer,
		"client_id":   o.cfg.ClientID,
		"login_url":   OIDCLoginPath,
		"logout_url":  OIDCLogoutPath,
		"auth_source": AuthSourceOIDCSession,
	}
	if c, err := r.Cookie(o.cfg.CookieName); err == nil {
		if sess, ok := o.lookupSession(c.Value); ok {
			body["authenticated"] = true
			body["actor"] = sess.Identity.Name
			body["role"] = sess.Identity.Role.String()
			body["csrf_token"] = sess.CSRFToken
		}
	}
	if _, ok := body["authenticated"]; !ok {
		body["authenticated"] = false
	}
	writeOIDCStatus(w, body)
}

func unsafeHTTPMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func (o *OIDCAuthenticator) validateSessionCSRF(r *http.Request, sess session) error {
	if !sameOriginRequest(r, o.proxies) {
		return errors.New("same-origin request required")
	}
	got := strings.TrimSpace(r.Header.Get(OIDCCSRFHeader))
	if got == "" || sess.CSRFToken == "" || subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRFToken)) != 1 {
		return errors.New("csrf token required")
	}
	return nil
}

func sameOriginRequest(r *http.Request, proxies proxytrust.Set) bool {
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		return originMatchesRequest(r, origin, proxies)
	}
	if referer := strings.TrimSpace(r.Header.Get("Referer")); referer != "" {
		return originMatchesRequest(r, referer, proxies)
	}
	return false
}

func originMatchesRequest(r *http.Request, raw string, proxies proxytrust.Set) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	expectedScheme := requestScheme(r, proxies)
	if scheme != expectedScheme {
		return false
	}
	reqHost, reqPort := splitHostPortLoose(r.Host)
	originHost, originPort := splitHostPortLoose(u.Host)
	if reqHost == "" || originHost == "" || !strings.EqualFold(reqHost, originHost) {
		return false
	}
	if reqPort == "" {
		reqPort = defaultOriginPort(expectedScheme)
	}
	if originPort == "" {
		originPort = defaultOriginPort(scheme)
	}
	return reqPort == originPort
}

func defaultOriginPort(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func requestScheme(r *http.Request, proxies proxytrust.Set) string {
	if proto := proxies.ForwardedProto(r.RemoteAddr, r.Header.Get("X-Forwarded-Proto")); proto != "" {
		return proto
	}
	if r.TLS != nil {
		return "https"
	}
	if r.URL.Scheme == "http" || r.URL.Scheme == "https" {
		return r.URL.Scheme
	}
	return "http"
}

func splitHostPortLoose(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	host, port, err := net.SplitHostPort(raw)
	if err == nil {
		return strings.Trim(strings.ToLower(host), "[]"), port
	}
	if strings.HasPrefix(raw, "[") {
		if end := strings.LastIndex(raw, "]"); end > 0 {
			return strings.Trim(strings.ToLower(raw[1:end]), "[]"), ""
		}
	}
	if strings.Count(raw, ":") == 1 {
		parts := strings.Split(raw, ":")
		if parts[0] != "" && parts[1] != "" {
			return strings.ToLower(parts[0]), parts[1]
		}
	}
	return strings.Trim(strings.ToLower(raw), "[]"), ""
}

func (o *OIDCAuthenticator) popState(state string) (loginState, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.reapExpiredLocked(o.now())
	st, ok := o.states[state]
	if ok {
		delete(o.states, state)
	}
	if !ok || !o.now().Before(st.ExpiresAt) {
		return loginState{}, false
	}
	return st, true
}

func (o *OIDCAuthenticator) reapExpiredLocked(now time.Time) {
	for state, st := range o.states {
		if !now.Before(st.ExpiresAt) {
			delete(o.states, state)
		}
	}
	for token, sess := range o.sessions {
		if !now.Before(sess.ExpiresAt) {
			delete(o.sessions, token)
		}
	}
}

func (o *OIDCAuthenticator) storeSession(token string, sess session) {
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	o.reapExpiredLocked(now)
	if o.sessions == nil {
		o.sessions = map[string]session{}
	}
	o.sessions[token] = sess
	o.enforceSessionLimitLocked()
}

func (o *OIDCAuthenticator) enforceStateLimitLocked() {
	maxStates := o.cfg.MaxStates
	if maxStates <= 0 {
		maxStates = defaultOIDCMaxStates
	}
	for len(o.states) > maxStates {
		if key, ok := oldestLoginStateKey(o.states); ok {
			delete(o.states, key)
			continue
		}
		return
	}
}

func (o *OIDCAuthenticator) enforceSessionLimitLocked() {
	maxSessions := o.cfg.MaxSessions
	if maxSessions <= 0 {
		maxSessions = defaultOIDCMaxSessions
	}
	for len(o.sessions) > maxSessions {
		if key, ok := oldestSessionKey(o.sessions); ok {
			delete(o.sessions, key)
			continue
		}
		return
	}
}

func oldestLoginStateKey(states map[string]loginState) (string, bool) {
	var oldestKey string
	var oldest time.Time
	for key, st := range states {
		if oldestKey == "" || st.ExpiresAt.Before(oldest) || (st.ExpiresAt.Equal(oldest) && key < oldestKey) {
			oldestKey = key
			oldest = st.ExpiresAt
		}
	}
	return oldestKey, oldestKey != ""
}

func oldestSessionKey(sessions map[string]session) (string, bool) {
	var oldestKey string
	var oldest time.Time
	for key, sess := range sessions {
		if oldestKey == "" || sess.ExpiresAt.Before(oldest) || (sess.ExpiresAt.Equal(oldest) && key < oldestKey) {
			oldestKey = key
			oldest = sess.ExpiresAt
		}
	}
	return oldestKey, oldestKey != ""
}

func (o *OIDCAuthenticator) identityFromToken(idToken *oidc.IDToken) (Identity, error) {
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, err
	}
	defaultRole, _ := ParseRole(o.cfg.DefaultRole)
	role, err := roleFromClaim(claims[o.cfg.RoleClaim], defaultRole)
	if err != nil {
		return Identity{}, err
	}
	name := firstClaimString(claims, "preferred_username", "name", "email")
	if name == "" {
		name = idToken.Subject
	}
	if name == "" {
		return Identity{}, errors.New("OIDC subject is empty")
	}
	return Identity{Name: name, Role: role, AuthSource: AuthSourceOIDCSession}, nil
}

func roleFromClaim(v any, fallback Role) (Role, error) {
	switch t := v.(type) {
	case nil:
		return fallback, nil
	case string:
		return ParseRole(t)
	case []any:
		if len(t) == 0 {
			return fallback, nil
		}
		best := Role(0)
		for _, item := range t {
			s, ok := item.(string)
			if !ok {
				return 0, errors.New("OIDC role claim must contain only strings")
			}
			role, err := ParseRole(s)
			if err != nil {
				return 0, err
			}
			if role > best {
				best = role
			}
		}
		return best, nil
	default:
		return 0, errors.New("OIDC role claim must be a string or string array")
	}
}

func firstClaimString(claims map[string]any, keys ...string) string {
	for _, key := range keys {
		if s, ok := claims[key].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func (o *OIDCAuthenticator) sessionCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     o.cfg.CookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   o.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
}

func (o *OIDCAuthenticator) expiredCookie() *http.Cookie {
	c := o.sessionCookie("", -1)
	c.Expires = time.Unix(0, 0).UTC()
	return c
}

//nolint:unparam // The byte count keeps token entropy explicit at call sites.
func randomURLToken(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func safeReturnPath(raw string) string {
	if raw == "" {
		return "/ui/"
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/ui/"
	}
	if !strings.HasPrefix(u.Path, "/ui/") && u.Path != "/ui" {
		return "/ui/"
	}
	out := u.Path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		out += "#" + u.EscapedFragment()
	}
	return out
}

func setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// DisabledOIDCStatusHandler reports browser SSO availability without requiring
// authentication, allowing the UI to render the right access affordance.
func DisabledOIDCStatusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		setNoStore(w)
		writeOIDCStatus(w, map[string]any{
			"enabled": false,
		})
	})
}

func writeOIDCStatus(w http.ResponseWriter, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}
