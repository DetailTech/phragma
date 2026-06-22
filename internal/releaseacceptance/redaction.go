package releaseacceptance

import (
	"fmt"
	"regexp"
	"strings"
)

type evidenceSecretPattern struct {
	label string
	re    *regexp.Regexp
}

var evidenceSecretPatterns = []evidenceSecretPattern{
	{
		label: "private key block",
		re:    regexp.MustCompile(`(?i)-----BEGIN[[:space:]][^-]*(PRIVATE|OPENSSH)[[:space:]]KEY-----`),
	},
	{
		label: "WireGuard private key",
		re:    regexp.MustCompile(`(?i)(^|[[:space:]])PrivateKey[[:space:]]*=[[:space:]]*["']?[A-Za-z0-9+/=._~-]{20,}`),
	},
	{
		label: "WireGuard preshared key",
		re:    regexp.MustCompile(`(?i)(^|[[:space:]])PresharedKey[[:space:]]*=[[:space:]]*["']?[A-Za-z0-9+/=._~-]{20,}`),
	},
	{
		label: "pre-shared key",
		re:    regexp.MustCompile(`(?i)(^|[[:space:]_:-])(psk|preshared[_-]?key|pre[_-]?shared[_-]?key)[[:space:]_"'-]*[:=][[:space:]]*["']?[A-Za-z0-9+/=._~-]{12,}`),
	},
	{
		label: "JWT/OIDC token",
		re:    regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
	},
	{
		label: "bearer token",
		re:    regexp.MustCompile(`(?i)Authorization:[[:space:]]*Bearer[[:space:]]+[A-Za-z0-9._~+/-]{12,}`),
	},
	{
		label: "OAuth/API token",
		re:    regexp.MustCompile(`(?i)(access_token|id_token|refresh_token|api[_-]?key|api[_-]?token|client[_-]?secret)[[:space:]_"'-]*[:=][[:space:]]*["']?[A-Za-z0-9._~+/-]{12,}`),
	},
	{
		label: "OIDC authorization code",
		re:    regexp.MustCompile(`(?i)(^|[?&[:space:]])code[[:space:]]*=[[:space:]]*["']?[A-Za-z0-9._~-]{8,}`),
	},
	{
		label: "cookie value",
		re:    regexp.MustCompile(`(?i)(^|[[:space:]])(Cookie|Set-Cookie):[^[:cntrl:]\n=]*=[A-Za-z0-9._~+/-]{12,}`),
	},
	{
		label: "OIDC session token",
		re:    regexp.MustCompile(`(?i)oidc[-_]?session[[:space:]_"'-]*[:=][[:space:]]*["']?[A-Za-z0-9._~+/-]{12,}`),
	},
	{
		label: "CSRF token",
		re:    regexp.MustCompile(`(?i)X-Phragma-CSRF[[:space:]]*[:=][[:space:]]*["']?[A-Za-z0-9._~+/-]{12,}`),
	},
	{
		label: "URL credentials",
		re:    regexp.MustCompile(`(?i)https?://[^[:space:]/:@]+:[^[:space:]@]+@`),
	},
}

const redactedEvidenceSecret = "[redacted]"

// ValidateEvidenceOutputRedaction rejects unredacted secret material before it
// can be persisted in release evidence records or accepted from existing ones.
func ValidateEvidenceOutputRedaction(name, stdout, stderr string) []string {
	var problems []string
	problems = append(problems, validateEvidenceOutputFieldRedaction(name, "stdout", stdout)...)
	problems = append(problems, validateEvidenceOutputFieldRedaction(name, "stderr", stderr)...)
	return compactStrings(problems)
}

// ValidateEvidenceMetadataRedaction rejects unredacted secret material in
// operator-controlled evidence metadata, such as record detail text.
func ValidateEvidenceMetadataRedaction(name, field, value string) []string {
	return compactStrings(validateEvidenceOutputFieldRedaction(name, field, value))
}

// RedactEvidenceSecrets removes secret-looking values from command output
// before failed release commands are surfaced to terminals or CI logs.
func RedactEvidenceSecrets(value string) string {
	if strings.TrimSpace(value) == "" {
		return value
	}
	redacted := value
	for _, pattern := range evidenceSecretPatterns {
		redacted = pattern.re.ReplaceAllString(redacted, redactedEvidenceSecret)
	}
	return redacted
}

func validateEvidenceOutputFieldRedaction(name, field, value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	var problems []string
	for _, pattern := range evidenceSecretPatterns {
		if pattern.re.MatchString(value) {
			problems = append(problems, fmt.Sprintf("%s evidence %s contains unredacted %s", name, field, pattern.label))
		}
	}
	return problems
}
