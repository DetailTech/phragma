package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"

	"github.com/detailtech/oss-ngfw/internal/proxytrust"
)

const (
	// SAMLLoginPath starts the browser SAML login flow.
	SAMLLoginPath = "/v1/auth/saml/login"
	// SAMLACSPath receives SAML assertion consumer service POSTs.
	SAMLACSPath = "/v1/auth/saml/acs"
	// SAMLStatusPath reports SAML SSO availability and session status.
	SAMLStatusPath = "/v1/auth/saml/status"

	defaultSAMLStateTTL    = 10 * time.Minute
	defaultSAMLSessionTTL  = 8 * time.Hour
	defaultSAMLMaxStates   = 1024
	defaultSAMLMaxSessions = 1024
)

// SAMLConfig configures browser SAML SSO. IdP signing material is represented
// by metadata and an optional SHA-256 certificate fingerprint pin.
type SAMLConfig struct {
	MetadataURL            string        `json:"metadata_url,omitempty"`
	IDPEntityID            string        `json:"idp_entity_id,omitempty"`
	SSOURL                 string        `json:"sso_url,omitempty"`
	SPEntityID             string        `json:"sp_entity_id"`
	ACSURL                 string        `json:"acs_url"`
	RoleAttribute          string        `json:"role_attribute,omitempty"`
	DefaultRole            string        `json:"default_role,omitempty"`
	CertificateFingerprint string        `json:"certificate_fingerprint,omitempty"`
	CookieName             string        `json:"cookie_name,omitempty"`
	CookieSecure           bool          `json:"cookie_secure"`
	TrustedProxyCIDRs      []string      `json:"trusted_proxy_cidrs,omitempty"`
	StateTTL               time.Duration `json:"state_ttl,omitempty"`
	SessionTTL             time.Duration `json:"session_ttl,omitempty"`
	MaxStates              int           `json:"max_states,omitempty"`
	MaxSessions            int           `json:"max_sessions,omitempty"`
}

// SAMLInventory is the non-secret access-administration view of SAML browser
// SSO configuration.
type SAMLInventory struct {
	Enabled                          bool
	MetadataURL                      string
	IDPEntityID                      string
	SSOURL                           string
	SPEntityID                       string
	ACSURL                           string
	RoleAttribute                    string
	DefaultRole                      string
	CertificateFingerprintConfigured bool
	CookieSecure                     bool
	TrustedProxyCIDRs                []string
	SessionTTLSeconds                uint64
	RuntimeAvailable                 bool
	Detail                           string
}

// SAMLAuthenticator owns SAML request state and opaque browser sessions.
type SAMLAuthenticator struct {
	cfg     SAMLConfig
	sp      *saml.ServiceProvider
	proxies proxytrust.Set

	mu       sync.Mutex
	states   map[string]loginState
	sessions map[string]session
	now      func() time.Time
}

// NewSAMLAuthenticator builds a SAML SP runtime without letting the SAML
// library own OpenNGFW sessions.
func NewSAMLAuthenticator(ctx context.Context, cfg SAMLConfig) (*SAMLAuthenticator, error) {
	cfg = normalizeSAMLConfig(cfg)
	if err := validateSAMLConfig(cfg); err != nil {
		return nil, err
	}
	proxies, err := proxytrust.New(cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, fmt.Errorf("configure SAML trusted proxies: %w", err)
	}
	sp, err := samlServiceProvider(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &SAMLAuthenticator{
		cfg:      cfg,
		sp:       sp,
		proxies:  proxies,
		states:   map[string]loginState{},
		sessions: map[string]session{},
		now:      func() time.Time { return time.Now().UTC() },
	}, nil
}

// Inventory returns non-secret SAML runtime posture.
func (s *SAMLAuthenticator) Inventory() SAMLInventory {
	if s == nil {
		return SAMLInventory{Enabled: false, Detail: "SAML browser SSO is not configured."}
	}
	cfg := normalizeSAMLConfig(s.cfg)
	return SAMLInventory{
		Enabled:                          true,
		MetadataURL:                      cfg.MetadataURL,
		IDPEntityID:                      cfg.IDPEntityID,
		SSOURL:                           cfg.SSOURL,
		SPEntityID:                       cfg.SPEntityID,
		ACSURL:                           cfg.ACSURL,
		RoleAttribute:                    cfg.RoleAttribute,
		DefaultRole:                      cfg.DefaultRole,
		CertificateFingerprintConfigured: cfg.CertificateFingerprint != "",
		CookieSecure:                     cfg.CookieSecure,
		TrustedProxyCIDRs:                append([]string(nil), cfg.TrustedProxyCIDRs...),
		SessionTTLSeconds:                uint64(cfg.SessionTTL.Seconds()),
		RuntimeAvailable:                 true,
		Detail:                           "SAML browser SSO login and session runtime is active.",
	}
}

// SessionInventory returns non-secret SAML session posture using the same
// session-record shape as OIDC inventory.
func (s *SAMLAuthenticator) SessionInventory() OIDCSessionInventory {
	if s == nil {
		return OIDCSessionInventory{Detail: "SAML browser SSO is not configured."}
	}
	cfg := normalizeSAMLConfig(s.cfg)
	s.mu.Lock()
	now := s.now()
	s.reapExpiredLocked(now)
	sessions := s.sessionRecordsLocked(now)
	active := len(sessions)
	s.mu.Unlock()
	return OIDCSessionInventory{
		ActiveSessions:             uint32Count(active),
		MaxSessions:                uint32Count(cfg.MaxSessions),
		SessionRevocationAvailable: true,
		Sessions:                   sessions,
		Detail: fmt.Sprintf(
			"%d active SAML browser session(s); admin listing and revocation are available through audited access administration.",
			active,
		),
	}
}

// ListSessions returns the non-secret active SAML session inventory.
func (s *SAMLAuthenticator) ListSessions() []OIDCSessionRecord {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.reapExpiredLocked(now)
	return s.sessionRecordsLocked(now)
}

// SessionRecord returns one active session by non-secret session ID.
func (s *SAMLAuthenticator) SessionRecord(id string) (OIDCSessionRecord, bool) {
	if s == nil {
		return OIDCSessionRecord{}, false
	}
	want := normalizeOIDCSessionID(id)
	if want == "" {
		return OIDCSessionRecord{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.reapExpiredLocked(now)
	for token, sess := range s.sessions {
		rec := samlSessionRecord(token, sess, now)
		if normalizeOIDCSessionID(rec.ID) == want {
			return rec, true
		}
	}
	return OIDCSessionRecord{}, false
}

// RevokeSession removes an active SAML browser session by non-secret ID.
func (s *SAMLAuthenticator) RevokeSession(id string) (OIDCSessionRecord, bool) {
	if s == nil {
		return OIDCSessionRecord{}, false
	}
	want := normalizeOIDCSessionID(id)
	if want == "" {
		return OIDCSessionRecord{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.reapExpiredLocked(now)
	for token, sess := range s.sessions {
		rec := samlSessionRecord(token, sess, now)
		if normalizeOIDCSessionID(rec.ID) == want {
			delete(s.sessions, token)
			return rec, true
		}
	}
	return OIDCSessionRecord{}, false
}

// RevokeAllSessions removes all active SAML sessions.
func (s *SAMLAuthenticator) RevokeAllSessions() uint32 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.reapExpiredLocked(now)
	count := uint32Count(len(s.sessions))
	s.sessions = map[string]session{}
	return count
}

// LookupSession validates an opaque SAML session token.
func (s *SAMLAuthenticator) LookupSession(token string) (Identity, bool) {
	sess, ok := s.lookupSession(token)
	if !ok {
		return Identity{}, false
	}
	return sess.Identity, true
}

// WithSessionCookieAuth maps a validated SAML session cookie to the gateway's
// bearer-token authorization header. Explicit bearer tokens always win.
func (s *SAMLAuthenticator) WithSessionCookieAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			if c, err := r.Cookie(s.cfg.CookieName); err == nil {
				if sess, ok := s.lookupSession(c.Value); ok {
					if unsafeHTTPMethod(r.Method) {
						if err := s.validateSessionCSRF(r, sess); err != nil {
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

// ServeHTTP handles SAML login, ACS, and public status endpoints.
func (s *SAMLAuthenticator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	switch r.URL.Path {
	case SAMLLoginPath:
		s.handleLogin(w, r)
	case SAMLACSPath:
		s.handleACS(w, r)
	case SAMLStatusPath:
		s.handleStatus(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *SAMLAuthenticator) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	relayState, err := randomURLToken(24)
	if err != nil {
		http.Error(w, "could not start login", http.StatusInternalServerError)
		return
	}
	authURL, requestID, err := s.authenticationRequestURL(relayState)
	if err != nil {
		http.Error(w, "SAML login is unavailable", http.StatusServiceUnavailable)
		return
	}
	ret := safeReturnPath(r.URL.Query().Get("return"))
	s.mu.Lock()
	now := s.now()
	s.reapExpiredLocked(now)
	if s.states == nil {
		s.states = map[string]loginState{}
	}
	s.states[relayState] = loginState{
		Nonce:      requestID,
		ReturnPath: ret,
		ExpiresAt:  now.Add(s.cfg.StateTTL),
	}
	s.enforceStateLimitLocked()
	s.mu.Unlock()
	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

func (s *SAMLAuthenticator) handleACS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "SAML login failed", http.StatusUnauthorized)
		return
	}
	st, ok := s.popState(r.Form.Get("RelayState"))
	if !ok {
		http.Error(w, "SAML login failed", http.StatusUnauthorized)
		return
	}
	assertion, err := s.sp.ParseResponse(r, []string{st.Nonce})
	if err != nil {
		http.Error(w, "SAML login failed", http.StatusUnauthorized)
		return
	}
	id, err := s.identityFromAssertion(assertion)
	if err != nil {
		http.Error(w, "SAML login failed", http.StatusUnauthorized)
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
	expires := s.now().Add(s.cfg.SessionTTL)
	s.storeSession(sessionToken, session{Identity: id, ExpiresAt: expires, CSRFToken: csrfToken})
	http.SetCookie(w, s.sessionCookie(sessionToken, int(s.cfg.SessionTTL.Seconds())))
	http.Redirect(w, r, st.ReturnPath, http.StatusFound)
}

func (s *SAMLAuthenticator) handleStatus(w http.ResponseWriter, r *http.Request) {
	body := map[string]any{
		"enabled":           true,
		"runtime_available": true,
		"idp_entity_id":     s.cfg.IDPEntityID,
		"sp_entity_id":      s.cfg.SPEntityID,
		"acs_url":           s.cfg.ACSURL,
		"login_url":         SAMLLoginPath,
		"logout_url":        OIDCLogoutPath,
		"auth_source":       AuthSourceSAMLSession,
	}
	if c, err := r.Cookie(s.cfg.CookieName); err == nil {
		if sess, ok := s.lookupSession(c.Value); ok {
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

func (s *SAMLAuthenticator) authenticationRequestURL(relayState string) (*url.URL, string, error) {
	bindingLocation := s.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	if bindingLocation == "" {
		return nil, "", errors.New("SAML IdP redirect binding is not configured")
	}
	req, err := s.sp.MakeAuthenticationRequest(bindingLocation, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return nil, "", err
	}
	redirectURL, err := req.Redirect(relayState, s.sp)
	if err != nil {
		return nil, "", err
	}
	return redirectURL, req.ID, nil
}

func (s *SAMLAuthenticator) lookupSession(token string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.reapExpiredLocked(now)
	sess, ok := s.sessions[token]
	if !ok {
		return session{}, false
	}
	if !now.Before(sess.ExpiresAt) {
		delete(s.sessions, token)
		return session{}, false
	}
	return sess, true
}

func (s *SAMLAuthenticator) popState(state string) (loginState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapExpiredLocked(s.now())
	st, ok := s.states[state]
	if ok {
		delete(s.states, state)
	}
	if !ok || !s.now().Before(st.ExpiresAt) {
		return loginState{}, false
	}
	return st, true
}

func (s *SAMLAuthenticator) storeSession(token string, sess session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.reapExpiredLocked(now)
	if s.sessions == nil {
		s.sessions = map[string]session{}
	}
	s.sessions[token] = sess
	s.enforceSessionLimitLocked()
}

func (s *SAMLAuthenticator) validateSessionCSRF(r *http.Request, sess session) error {
	if !sameOriginRequest(r, s.proxies) {
		return errors.New("same-origin request required")
	}
	got := strings.TrimSpace(r.Header.Get(OIDCCSRFHeader))
	if got == "" || sess.CSRFToken == "" || subtleCompare(got, sess.CSRFToken) != 1 {
		return errors.New("csrf token required")
	}
	return nil
}

func subtleCompare(a, b string) int {
	if len(a) != len(b) {
		return 0
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	if v == 0 {
		return 1
	}
	return 0
}

func (s *SAMLAuthenticator) reapExpiredLocked(now time.Time) {
	for state, st := range s.states {
		if !now.Before(st.ExpiresAt) {
			delete(s.states, state)
		}
	}
	for token, sess := range s.sessions {
		if !now.Before(sess.ExpiresAt) {
			delete(s.sessions, token)
		}
	}
}

func (s *SAMLAuthenticator) enforceStateLimitLocked() {
	maxStates := s.cfg.MaxStates
	if maxStates <= 0 {
		maxStates = defaultSAMLMaxStates
	}
	for len(s.states) > maxStates {
		if key, ok := oldestLoginStateKey(s.states); ok {
			delete(s.states, key)
			continue
		}
		return
	}
}

func (s *SAMLAuthenticator) enforceSessionLimitLocked() {
	maxSessions := s.cfg.MaxSessions
	if maxSessions <= 0 {
		maxSessions = defaultSAMLMaxSessions
	}
	for len(s.sessions) > maxSessions {
		if key, ok := oldestSessionKey(s.sessions); ok {
			delete(s.sessions, key)
			continue
		}
		return
	}
}

func (s *SAMLAuthenticator) sessionRecordsLocked(now time.Time) []OIDCSessionRecord {
	out := make([]OIDCSessionRecord, 0, len(s.sessions))
	for token, sess := range s.sessions {
		out = append(out, samlSessionRecord(token, sess, now))
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

func samlSessionRecord(token string, sess session, now time.Time) OIDCSessionRecord {
	seconds := uint64(0)
	if sess.ExpiresAt.After(now) {
		seconds = uint64(sess.ExpiresAt.Sub(now).Seconds())
	}
	return OIDCSessionRecord{
		ID:                 samlSessionID(token),
		Actor:              sess.Identity.Name,
		Role:               sess.Identity.Role.String(),
		AuthSource:         sess.Identity.AuthSource,
		ExpiresAt:          sess.ExpiresAt.UTC(),
		SecondsUntilExpiry: seconds,
	}
}

func samlSessionID(token string) string {
	digest := sha256.Sum256([]byte(token))
	return "saml-session-sha256:" + hex.EncodeToString(digest[:])
}

// SAMLSessionIDForToken returns the non-secret revocation ID for an opaque
// SAML session token.
func SAMLSessionIDForToken(token string) string {
	return samlSessionID(token)
}

func (s *SAMLAuthenticator) identityFromAssertion(assertion *saml.Assertion) (Identity, error) {
	if assertion == nil {
		return Identity{}, errors.New("SAML assertion is empty")
	}
	claims := samlAssertionClaims(assertion)
	defaultRole, _ := ParseRole(s.cfg.DefaultRole)
	role, err := roleFromClaim(claims[s.cfg.RoleAttribute], defaultRole)
	if err != nil {
		return Identity{}, err
	}
	name := firstClaimString(claims, "preferred_username", "name", "email", "mail", "uid")
	if name == "" && assertion.Subject != nil && assertion.Subject.NameID != nil {
		name = strings.TrimSpace(assertion.Subject.NameID.Value)
	}
	if name == "" {
		return Identity{}, errors.New("SAML subject is empty")
	}
	return Identity{Name: name, Role: role, AuthSource: AuthSourceSAMLSession}, nil
}

func samlAssertionClaims(assertion *saml.Assertion) map[string]any {
	claims := map[string]any{}
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			keys := []string{strings.TrimSpace(attr.Name), strings.TrimSpace(attr.FriendlyName)}
			var values []any
			for _, value := range attr.Values {
				v := strings.TrimSpace(value.Value)
				if v == "" && value.NameID != nil {
					v = strings.TrimSpace(value.NameID.Value)
				}
				if v != "" {
					values = append(values, v)
				}
			}
			for _, key := range keys {
				if key == "" || len(values) == 0 {
					continue
				}
				if len(values) == 1 {
					claims[key] = values[0]
				} else {
					claims[key] = append([]any(nil), values...)
				}
			}
		}
	}
	return claims
}

func normalizeSAMLConfig(cfg SAMLConfig) SAMLConfig {
	cfg.MetadataURL = strings.TrimRight(strings.TrimSpace(cfg.MetadataURL), "/")
	cfg.IDPEntityID = strings.TrimSpace(cfg.IDPEntityID)
	cfg.SSOURL = strings.TrimSpace(cfg.SSOURL)
	cfg.SPEntityID = strings.TrimSpace(cfg.SPEntityID)
	cfg.ACSURL = strings.TrimSpace(cfg.ACSURL)
	cfg.RoleAttribute = strings.TrimSpace(cfg.RoleAttribute)
	if cfg.RoleAttribute == "" {
		cfg.RoleAttribute = "role"
	}
	cfg.DefaultRole = strings.TrimSpace(cfg.DefaultRole)
	if cfg.DefaultRole == "" {
		cfg.DefaultRole = RoleViewer.String()
	}
	cfg.CertificateFingerprint = normalizeCertificateFingerprint(cfg.CertificateFingerprint)
	if cfg.CookieName == "" {
		cfg.CookieName = DefaultOIDCCookieName
	}
	if cfg.StateTTL <= 0 {
		cfg.StateTTL = defaultSAMLStateTTL
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = defaultSAMLSessionTTL
	}
	if cfg.MaxStates <= 0 {
		cfg.MaxStates = defaultSAMLMaxStates
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = defaultSAMLMaxSessions
	}
	cfg.TrustedProxyCIDRs = normalizeProviderList(cfg.TrustedProxyCIDRs)
	return cfg
}

func validateSAMLConfig(cfg SAMLConfig) error {
	providerCfg := SAMLProviderConfig{
		MetadataURL:            cfg.MetadataURL,
		IDPEntityID:            cfg.IDPEntityID,
		SSOURL:                 cfg.SSOURL,
		SPEntityID:             cfg.SPEntityID,
		ACSURL:                 cfg.ACSURL,
		RoleAttribute:          cfg.RoleAttribute,
		DefaultRole:            cfg.DefaultRole,
		CertificateFingerprint: cfg.CertificateFingerprint,
	}
	if err := ValidateSAMLProviderConfig(providerCfg); err != nil {
		return err
	}
	if cfg.SessionTTL <= 0 || cfg.MaxStates <= 0 || cfg.MaxSessions <= 0 {
		return errors.New("SAML session, state, and capacity limits must be positive")
	}
	return nil
}

func samlServiceProvider(ctx context.Context, cfg SAMLConfig) (*saml.ServiceProvider, error) {
	acsURL, err := url.Parse(cfg.ACSURL)
	if err != nil {
		return nil, fmt.Errorf("SAML ACS URL: %w", err)
	}
	metadataURL := *acsURL
	metadataURL.Path = strings.TrimRight(metadataURL.Path, "/") + "/metadata"
	metadataURL.RawQuery = ""
	metadataURL.Fragment = ""
	idpMetadata, err := samlIDPMetadata(ctx, cfg)
	if err != nil {
		return nil, err
	}
	sp := &saml.ServiceProvider{
		EntityID:          cfg.SPEntityID,
		MetadataURL:       metadataURL,
		AcsURL:            *acsURL,
		IDPMetadata:       idpMetadata,
		AuthnNameIDFormat: saml.UnspecifiedNameIDFormat,
	}
	if cfg.CertificateFingerprint != "" {
		fp := cfg.CertificateFingerprint
		alg := "SHA256"
		sp.IDPCertificateFingerprint = &fp
		sp.IDPCertificateFingerprintAlgorithm = &alg
	}
	return sp, nil
}

func samlIDPMetadata(ctx context.Context, cfg SAMLConfig) (*saml.EntityDescriptor, error) {
	if cfg.MetadataURL != "" {
		u, err := url.Parse(cfg.MetadataURL)
		if err != nil {
			return nil, fmt.Errorf("SAML metadata URL: %w", err)
		}
		fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return samlsp.FetchMetadata(fetchCtx, http.DefaultClient, *u)
	}
	return &saml.EntityDescriptor{
		EntityID: cfg.IDPEntityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SingleSignOnServices: []saml.Endpoint{
				{Binding: saml.HTTPRedirectBinding, Location: cfg.SSOURL},
				{Binding: saml.HTTPPostBinding, Location: cfg.SSOURL},
			},
		}},
	}, nil
}

func (s *SAMLAuthenticator) sessionCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
}

// DisabledSAMLStatusHandler reports disabled SAML runtime status without
// requiring API authentication.
func DisabledSAMLStatusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		setNoStore(w)
		writeOIDCStatus(w, map[string]any{
			"enabled":           false,
			"runtime_available": false,
			"authenticated":     false,
			"login_url":         "",
			"logout_url":        OIDCLogoutPath,
			"auth_source":       AuthSourceSAMLSession,
		})
	})
}
