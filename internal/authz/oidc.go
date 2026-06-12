package authz

import (
	"errors"
)

// OIDCConfig is the scaffolding for single-sign-on (build plan M5).
// The shape is defined so deployment tooling and docs can reference it,
// but the implementation is deliberately absent.
type OIDCConfig struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	RedirectURL  string `json:"redirect_url"`
	RoleClaim    string `json:"role_claim"`
	DefaultRole  string `json:"default_role"`
	ClientSecret string `json:"-"` // never serialized; provisioned out of band
}

// ErrOIDCNotImplemented is returned for any attempt to enable OIDC.
//
// GUARDRAIL: implementing network-exposed authentication (OIDC/SAML)
// beyond scaffolding requires human security review (CLAUDE.md /
// build plan §11). Do not implement this without that review.
var ErrOIDCNotImplemented = errors.New(
	"OIDC authentication is scaffolded but not implemented: " +
		"network-exposed SSO requires human security review before being built")

// NewOIDCAuthenticator always refuses until the implementation passes
// security review.
func NewOIDCAuthenticator(OIDCConfig) (*Authenticator, error) {
	return nil, ErrOIDCNotImplemented
}
