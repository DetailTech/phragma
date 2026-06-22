//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseSAMLFieldEvidenceCheckAcceptsCompleteBundle(t *testing.T) {
	root := releaseRepoRoot(t)
	evidenceDir := writeSAMLFieldEvidenceBundle(t)
	cmd := exec.Command("bash", "release/saml-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		t.Fatalf("SAML field evidence check failed: %v\n%s", err, output)
	}

	for _, want := range []string{
		"check=m5-saml-field-evidence",
		"mode=check",
		"field_evidence_scope=real-idp-metadata,sp-metadata,https-acs,cookie-security,negative-callbacks,rbac,csrf-origin,logout,redaction",
		"saml_field_evidence_scope=real-provider-backed,browser-sso,authn-request,assertion-validation,session-cookie,csrf,rbac",
		"saml_field_negative_checks=invalid-signature,replayed-assertion,missing-relaystate,logout,viewer-denial",
		"saml_field_redaction=idp-entity-redacted,sp-entity-redacted,subject-redacted,email-redacted,assertions-redacted,cookies-redacted",
		"required_provider_evidence=idp-metadata,sp-metadata",
		"required_deployment_evidence=public-https-acs,secure-cookie-posture",
		"required_browser_evidence=login-redirect,assertion-session-cookie,invalid-signature-rejection,replayed-assertion-rejection,missing-relaystate-rejection,operator-mutation-with-csrf,missing-csrf-rejection,cross-origin-rejection,viewer-mutation-denial,logout-invalidation",
		"required_rbac_evidence=viewer,operator,admin",
		"required_redaction_evidence=identity-redacted,audit-log-redacted,support-bundle-redacted,global-secret-scan",
		"manifest_sha256_policy=required,exact-regular-files,no-extra-files",
		"ok: manifest.sha256 verified exact file set",
		"ok: SAML assertion validation contains expected evidence",
		"ok: SAML public ACS HTTPS posture contains expected evidence",
		"ok: SAML operator mutation CSRF header contains expected evidence",
		"ok: SAML invalid-signature rejection contains expected evidence",
		"ok: SAML replayed assertion rejection contains expected evidence",
		"ok: SAML viewer mutation denial contains expected evidence",
		"ok: SAML support assertion redaction contains expected evidence",
		"status=passed",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("SAML field evidence output missing %q:\n%s", want, output)
		}
	}
}

func TestReleaseSAMLFieldEvidenceCheckRejectsIncompleteBundle(t *testing.T) {
	root := releaseRepoRoot(t)
	evidenceDir := writeSAMLFieldEvidenceBundle(t)
	if err := os.Remove(filepath.Join(evidenceDir, "browser", "missing-csrf-rejection.txt")); err != nil {
		t.Fatalf("remove missing-CSRF evidence: %v", err)
	}

	cmd := exec.Command("bash", "release/saml-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("SAML field evidence check accepted incomplete bundle:\n%s", output)
	}
	if !strings.Contains(output, "SAML missing-CSRF request missing or empty") || !strings.Contains(output, "status=failed") {
		t.Fatalf("expected incomplete bundle failure, got:\n%s", output)
	}
}

func TestReleaseSAMLFieldEvidenceCheckRejectsUnredactedMaterial(t *testing.T) {
	root := releaseRepoRoot(t)
	evidenceDir := writeSAMLFieldEvidenceBundle(t)
	writeOIDCFieldEvidenceFile(t, evidenceDir, "redaction/support-bundle-redacted.txt", strings.Join([]string{
		"support_bundle=collected",
		"authSource=saml-session",
		"cookies=redacted",
		"assertions=redacted",
		"relaystate=redacted",
		"SAMLResponse=PHNhbWxwOlJlc3BvbnNlIElEPSJfMTIzNDU2Nzg5MCI+PHNhbWwyOkFzc2VydGlvbj5zZWNyZXQtc3ViamVjdC1hbmQtYXR0cmlidXRlcy1ub3QtcmVkYWN0ZWQ8L3NhbWwyOkFzc2VydGlvbj48L3NhbWxwOlJlc3BvbnNlPg==",
		"RelayState=relaystate-secret-12345",
		"X-Phragma-CSRF=csrfsecret123456",
		"saml_session=sessionsecret123456",
	}, "\n")+"\n")

	cmd := exec.Command("bash", "release/saml-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("SAML field evidence check accepted unredacted material:\n%s", output)
	}
	if !strings.Contains(output, "SAML response appears unredacted") ||
		!strings.Contains(output, "SAML RelayState appears unredacted") ||
		!strings.Contains(output, "CSRF token appears unredacted") ||
		!strings.Contains(output, "SAML session cookie appears unredacted") ||
		!strings.Contains(output, "status=failed") {
		t.Fatalf("expected unredacted material failure, got:\n%s", output)
	}
}

func writeSAMLFieldEvidenceBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	manifestPaths := []string{
		"provider/idp-metadata.txt",
		"provider/sp-metadata.txt",
		"deployment/public-acs.txt",
		"browser/login-redirect.txt",
		"browser/assertion-session-cookie.txt",
		"browser/invalid-signature-rejection.txt",
		"browser/replayed-assertion-rejection.txt",
		"browser/missing-relaystate-rejection.txt",
		"browser/operator-mutation-with-csrf.txt",
		"browser/missing-csrf-rejection.txt",
		"browser/cross-origin-rejection.txt",
		"browser/viewer-mutation-denial.txt",
		"browser/logout-invalidation.txt",
		"rbac/role-mapping.txt",
		"redaction/identity-redacted.txt",
		"redaction/audit-log-redacted.txt",
		"redaction/support-bundle-redacted.txt",
	}
	writeOIDCFieldEvidenceFile(t, dir, "provider/idp-metadata.txt", strings.Join([]string{
		"idp_entity_id=redacted",
		"metadata_url=https://idp.example.com/metadata",
		"sso_url=https://idp.example.com/sso",
		"certificate_fingerprint=pinned",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "provider/sp-metadata.txt", strings.Join([]string{
		"sp_entity_id=https://fw.example.com/saml/metadata",
		"acs_url=https://fw.example.com/v1/auth/saml/acs",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "deployment/public-acs.txt", strings.Join([]string{
		"acs_url=https://fw.example.com/v1/auth/saml/acs",
		"public_https=true",
		"cookie_secure=true",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/login-redirect.txt", strings.Join([]string{
		"redirect_status=302",
		"authn_request=redacted",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/assertion-session-cookie.txt", strings.Join([]string{
		"assertion_validation=passed",
		"Set-Cookie: saml-session=<redacted>; Path=/; HttpOnly; SameSite=Lax; Secure",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/invalid-signature-rejection.txt", "signature_invalid=true\nstatus=401\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/replayed-assertion-rejection.txt", "assertion_replayed=true\nstatus=401\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/missing-relaystate-rejection.txt", "RelayState=missing\nstatus=401\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/operator-mutation-with-csrf.txt", "actor_role=operator\nX-Phragma-CSRF: <redacted>\nstatus=204\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/missing-csrf-rejection.txt", "actor_role=operator\nX-Phragma-CSRF=missing\nstatus=403\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/cross-origin-rejection.txt", "same_origin=false\nstatus=403\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/viewer-mutation-denial.txt", "actor_role=viewer\nstatus=403\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/logout-invalidation.txt", "logout_status=204\npost_logout_authenticated=false\n")
	writeOIDCFieldEvidenceFile(t, dir, "rbac/role-mapping.txt", strings.Join([]string{
		"authSource=saml-session",
		"role_attribute=groups",
		"provider_role=ngfw-viewer mapped_role=viewer",
		"provider_role=ngfw-operator mapped_role=operator",
		"provider_role=ngfw-admin mapped_role=admin",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "redaction/identity-redacted.txt", "idp_entity_id=redacted\nsp_entity_id=redacted\nsubject=redacted\nemail=redacted\n")
	writeOIDCFieldEvidenceFile(t, dir, "redaction/audit-log-redacted.txt", "authSource=saml-session\ncookies=redacted\nassertions=redacted\nrelaystate=redacted\n")
	writeOIDCFieldEvidenceFile(t, dir, "redaction/support-bundle-redacted.txt", "authSource=saml-session\ncookies=redacted\nassertions=redacted\nrelaystate=redacted\n")
	writeOIDCFieldEvidenceManifest(t, dir, manifestPaths...)
	return dir
}
