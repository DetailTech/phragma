package authz

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/detailtech/oss-ngfw/internal/securefile"
)

// OIDCProviderConfig is the node-local, non-secret-at-rest browser SSO
// provider configuration. It stores only a client secret file reference; secret
// bytes remain outside the API and access config document.
type OIDCProviderConfig struct {
	Enabled           bool     `json:"enabled"`
	Issuer            string   `json:"issuer"`
	ClientID          string   `json:"client_id"`
	ClientSecretFile  string   `json:"client_secret_file,omitempty"`
	RedirectURL       string   `json:"redirect_url"`
	RoleClaim         string   `json:"role_claim,omitempty"`
	DefaultRole       string   `json:"default_role,omitempty"`
	Scopes            []string `json:"scopes,omitempty"`
	TrustedProxyCIDRs []string `json:"trusted_proxy_cidrs,omitempty"`
	SessionTTLSeconds uint64   `json:"session_ttl_seconds,omitempty"`
	MaxSessions       uint32   `json:"max_sessions,omitempty"`
}

// SAMLProviderConfig is the node-local browser SSO provider configuration for
// SAML. It intentionally stores only non-secret identifiers and endpoints.
type SAMLProviderConfig struct {
	Enabled                bool     `json:"enabled"`
	MetadataURL            string   `json:"metadata_url,omitempty"`
	IDPEntityID            string   `json:"idp_entity_id,omitempty"`
	SSOURL                 string   `json:"sso_url,omitempty"`
	SPEntityID             string   `json:"sp_entity_id"`
	ACSURL                 string   `json:"acs_url"`
	RoleAttribute          string   `json:"role_attribute,omitempty"`
	DefaultRole            string   `json:"default_role,omitempty"`
	CertificateFingerprint string   `json:"certificate_fingerprint,omitempty"`
	TrustedProxyCIDRs      []string `json:"trusted_proxy_cidrs,omitempty"`
	SessionTTLSeconds      uint64   `json:"session_ttl_seconds,omitempty"`
	MaxSessions            uint32   `json:"max_sessions,omitempty"`
}

type accessConfigFile struct {
	OIDC OIDCProviderConfig `json:"oidc"`
	SAML SAMLProviderConfig `json:"saml,omitempty"`
}

// LoadOIDCProviderConfig reads the node-local access config. A missing file is
// not an error and means browser SSO has no persisted provider config.
func LoadOIDCProviderConfig(path string) (OIDCProviderConfig, error) {
	doc, err := loadAccessConfig(path)
	if err != nil {
		return OIDCProviderConfig{}, err
	}
	return NormalizeOIDCProviderConfig(doc.OIDC), nil
}

// LoadSAMLProviderConfig reads the node-local access config. A missing file is
// not an error and means browser SSO has no persisted SAML provider config.
func LoadSAMLProviderConfig(path string) (SAMLProviderConfig, error) {
	doc, err := loadAccessConfig(path)
	if err != nil {
		return SAMLProviderConfig{}, err
	}
	return NormalizeSAMLProviderConfig(doc.SAML), nil
}

func loadAccessConfig(path string) (accessConfigFile, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return accessConfigFile{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return accessConfigFile{}, nil
		}
		return accessConfigFile{}, fmt.Errorf("read access config: %w", err)
	}
	var doc accessConfigFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return accessConfigFile{}, fmt.Errorf("parse access config: %w", err)
	}
	return doc, nil
}

// SaveOIDCProviderConfig atomically writes the node-local access config. The
// file must remain private because it can contain local path references to
// operator-managed secret material.
func SaveOIDCProviderConfig(path string, cfg OIDCProviderConfig) error {
	doc, err := loadAccessConfig(path)
	if err != nil {
		return err
	}
	doc.OIDC = NormalizeOIDCProviderConfig(cfg)
	return saveAccessConfig(path, doc)
}

// SaveSAMLProviderConfig atomically writes the node-local access config while
// preserving any existing OIDC provider settings in the same document.
func SaveSAMLProviderConfig(path string, cfg SAMLProviderConfig) error {
	doc, err := loadAccessConfig(path)
	if err != nil {
		return err
	}
	doc.SAML = NormalizeSAMLProviderConfig(cfg)
	return saveAccessConfig(path, doc)
}

func saveAccessConfig(path string, doc accessConfigFile) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("access config file is not configured")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create access config directory: %w", err)
	}
	doc.OIDC = NormalizeOIDCProviderConfig(doc.OIDC)
	doc.SAML = NormalizeSAMLProviderConfig(doc.SAML)
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal access config: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("write access config temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace access config: %w", err)
	}
	return nil
}

// NormalizeOIDCProviderConfig returns a stable provider config shape suitable
// for inventory, validation, and persistence.
func NormalizeOIDCProviderConfig(cfg OIDCProviderConfig) OIDCProviderConfig {
	cfg.Issuer = strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	cfg.ClientSecretFile = strings.TrimSpace(cfg.ClientSecretFile)
	cfg.RedirectURL = strings.TrimSpace(cfg.RedirectURL)
	cfg.RoleClaim = strings.TrimSpace(cfg.RoleClaim)
	if cfg.RoleClaim == "" {
		cfg.RoleClaim = "role"
	}
	cfg.DefaultRole = strings.TrimSpace(cfg.DefaultRole)
	if cfg.DefaultRole == "" {
		cfg.DefaultRole = RoleViewer.String()
	}
	cfg.Scopes = normalizeProviderList(cfg.Scopes)
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	cfg.TrustedProxyCIDRs = normalizeProviderList(cfg.TrustedProxyCIDRs)
	return cfg
}

// NormalizeSAMLProviderConfig returns a stable provider config shape suitable
// for inventory, validation, and persistence.
func NormalizeSAMLProviderConfig(cfg SAMLProviderConfig) SAMLProviderConfig {
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
	cfg.TrustedProxyCIDRs = normalizeProviderList(cfg.TrustedProxyCIDRs)
	return cfg
}

// OIDCProviderConfigToRuntime converts persisted provider configuration plus
// the out-of-band client secret into the authenticator runtime config.
func OIDCProviderConfigToRuntime(cfg OIDCProviderConfig, clientSecret string, cookieSecure bool) OIDCConfig {
	cfg = NormalizeOIDCProviderConfig(cfg)
	out := OIDCConfig{
		Issuer:            cfg.Issuer,
		ClientID:          cfg.ClientID,
		ClientSecret:      clientSecret,
		RedirectURL:       cfg.RedirectURL,
		RoleClaim:         cfg.RoleClaim,
		DefaultRole:       cfg.DefaultRole,
		Scopes:            append([]string(nil), cfg.Scopes...),
		CookieSecure:      cookieSecure,
		TrustedProxyCIDRs: append([]string(nil), cfg.TrustedProxyCIDRs...),
	}
	if cfg.SessionTTLSeconds > 0 {
		out.SessionTTL = time.Duration(cfg.SessionTTLSeconds) * time.Second
	}
	if cfg.MaxSessions > 0 {
		out.MaxSessions = int(cfg.MaxSessions)
	}
	return out
}

// SAMLProviderConfigToRuntime converts persisted provider configuration into
// the browser SAML authenticator runtime config.
func SAMLProviderConfigToRuntime(cfg SAMLProviderConfig, cookieSecure bool) SAMLConfig {
	cfg = NormalizeSAMLProviderConfig(cfg)
	out := SAMLConfig{
		MetadataURL:            cfg.MetadataURL,
		IDPEntityID:            cfg.IDPEntityID,
		SSOURL:                 cfg.SSOURL,
		SPEntityID:             cfg.SPEntityID,
		ACSURL:                 cfg.ACSURL,
		RoleAttribute:          cfg.RoleAttribute,
		DefaultRole:            cfg.DefaultRole,
		CertificateFingerprint: cfg.CertificateFingerprint,
		CookieSecure:           cookieSecure,
		TrustedProxyCIDRs:      append([]string(nil), cfg.TrustedProxyCIDRs...),
	}
	if cfg.SessionTTLSeconds > 0 {
		out.SessionTTL = time.Duration(cfg.SessionTTLSeconds) * time.Second
	}
	if cfg.MaxSessions > 0 {
		out.MaxSessions = int(cfg.MaxSessions)
	}
	return out
}

// ValidateOIDCProviderConfig validates the non-secret provider config without
// contacting the issuer. Runtime discovery remains part of NewOIDCAuthenticator
// and Preflight.
func ValidateOIDCProviderConfig(cfg OIDCProviderConfig) error {
	runtime := OIDCProviderConfigToRuntime(cfg, "", true)
	if err := validateOIDCConfig(normalizeOIDCConfig(runtime)); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.ClientSecretFile) != "" {
		if err := securefile.ValidatePrivateFile(cfg.ClientSecretFile, "OIDC client secret file"); err != nil {
			return err
		}
	}
	return nil
}

// ValidateSAMLProviderConfig validates the non-secret provider shape without
// fetching IdP metadata or activating browser sessions.
func ValidateSAMLProviderConfig(cfg SAMLProviderConfig) error {
	cfg = NormalizeSAMLProviderConfig(cfg)
	if cfg.MetadataURL == "" && (cfg.IDPEntityID == "" || cfg.SSOURL == "") {
		return fmt.Errorf("SAML metadata URL or both IdP entity ID and SSO URL are required")
	}
	if cfg.MetadataURL != "" {
		if err := validateProviderHTTPSURL(cfg.MetadataURL, "SAML metadata URL"); err != nil {
			return err
		}
	}
	if cfg.SSOURL != "" {
		if err := validateProviderHTTPSURL(cfg.SSOURL, "SAML SSO URL"); err != nil {
			return err
		}
	}
	if cfg.SPEntityID == "" {
		return fmt.Errorf("SAML SP entity ID is required")
	}
	if cfg.ACSURL == "" {
		return fmt.Errorf("SAML ACS URL is required")
	}
	if err := validateProviderHTTPSURL(cfg.ACSURL, "SAML ACS URL"); err != nil {
		return err
	}
	if _, err := ParseRole(cfg.DefaultRole); err != nil {
		return fmt.Errorf("SAML default role: %w", err)
	}
	if cfg.CertificateFingerprint != "" && len(cfg.CertificateFingerprint) != 64 {
		return fmt.Errorf("SAML certificate fingerprint must be a SHA-256 hex fingerprint")
	}
	return nil
}

func normalizeProviderList(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" || seen[part] {
				continue
			}
			seen[part] = true
			out = append(out, part)
		}
	}
	return out
}

func normalizeCertificateFingerprint(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, ":", "")
	value = strings.ReplaceAll(value, " ", "")
	return value
}

func validateProviderHTTPSURL(raw, label string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if !u.IsAbs() || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("%s must be an absolute http(s) URL", label)
	}
	if u.Scheme == "http" && !isLoopbackProviderHost(u.Hostname()) {
		return fmt.Errorf("%s must use https unless the host is loopback", label)
	}
	return nil
}

func isLoopbackProviderHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
