//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestReleaseOIDCFieldEvidenceCheckAcceptsCompleteBundle(t *testing.T) {
	root := oidcReleaseRepoRoot(t)
	evidenceDir := writeOIDCFieldEvidenceBundle(t)
	cmd := exec.Command("bash", "release/oidc-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		t.Fatalf("OIDC field evidence check failed: %v\n%s", err, output)
	}

	for _, want := range []string{
		"check=m5-oidc-field-evidence",
		"mode=check",
		"field_evidence_scope=real-issuer-client,id-token-validation,https-callback,secret-file,cookie-security,negative-callbacks,rbac,csrf-origin,logout,redaction",
		"oidc_field_evidence_scope=real-provider-backed,browser-sso,authorization-code-pkce,id-token-verification,nonce,session-cookie,csrf,rbac",
		"oidc_field_negative_checks=missing-state,reused-state,nonce-mismatch,pkce-exchange-failure,logout,viewer-denial",
		"oidc_field_redaction=issuer-host-redacted,client-id-redacted,subject-redacted,email-redacted,tokens-redacted,cookies-redacted",
		"required_provider_evidence=issuer-client-discovery,id-token-validation",
		"required_deployment_evidence=public-https-callback,client-secret-file-permissions",
		"required_browser_evidence=session-cookie,missing-state-rejection,reused-state-rejection,nonce-mismatch-rejection,pkce-exchange-failure,operator-mutation-with-csrf,missing-csrf-rejection,cross-origin-rejection,viewer-mutation-denial,logout-invalidation",
		"required_rbac_evidence=viewer,operator,admin",
		"required_redaction_evidence=identity-redacted,audit-log-redacted,support-bundle-redacted,global-secret-scan",
		"manifest_sha256_policy=required,exact-regular-files,no-extra-files",
		"ok: manifest.sha256 verified exact file set",
		"ok: OIDC ID-token validation contains expected evidence",
		"ok: OIDC public HTTPS callback URL contains expected evidence",
		"ok: OIDC client-secret file private mode contains expected evidence",
		"ok: OIDC session cookie Secure posture contains expected evidence",
		"ok: OIDC missing-state rejection contains expected evidence",
		"ok: OIDC reused-state rejection contains expected evidence",
		"ok: OIDC nonce-mismatch rejection contains expected evidence",
		"ok: OIDC PKCE exchange-failure rejection contains expected evidence",
		"ok: OIDC operator mutation CSRF header contains expected evidence",
		"ok: OIDC cross-origin rejection contains expected evidence",
		"ok: OIDC viewer mutation denial contains expected evidence",
		"ok: OIDC logout invalidates session contains expected evidence",
		"ok: OIDC issuer host redaction contains expected evidence",
		"ok: OIDC support client-secret redaction contains expected evidence",
		"status=passed",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("OIDC field evidence output missing %q:\n%s", want, output)
		}
	}
}

func TestReleaseOIDCFieldEvidenceCheckRejectsIncompleteBundle(t *testing.T) {
	root := oidcReleaseRepoRoot(t)
	evidenceDir := writeOIDCFieldEvidenceBundle(t)
	if err := os.Remove(filepath.Join(evidenceDir, "browser", "missing-csrf-rejection.txt")); err != nil {
		t.Fatalf("remove missing-CSRF evidence: %v", err)
	}

	cmd := exec.Command("bash", "release/oidc-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("OIDC field evidence check accepted incomplete bundle:\n%s", output)
	}
	if !strings.Contains(output, "OIDC missing-CSRF request missing or empty") || !strings.Contains(output, "status=failed") {
		t.Fatalf("expected incomplete bundle failure, got:\n%s", output)
	}
}

func TestReleaseOIDCFieldEvidenceCheckRejectsSymlinkedEvidenceRoot(t *testing.T) {
	root := oidcReleaseRepoRoot(t)
	evidenceDir := writeOIDCFieldEvidenceBundle(t)
	linkDir := filepath.Join(t.TempDir(), "oidc-evidence-link")
	if err := os.Symlink(evidenceDir, linkDir); err != nil {
		t.Fatalf("symlink evidence root: %v", err)
	}

	cmd := exec.Command("bash", "release/oidc-field-evidence.sh", "--evidence-dir", linkDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("OIDC field evidence check accepted symlinked root:\n%s", output)
	}
	if !strings.Contains(output, "OIDC field evidence root must not be a symlink") || !strings.Contains(output, "status=failed") {
		t.Fatalf("expected symlink root rejection, got:\n%s", output)
	}
}

func TestReleaseOIDCFieldEvidenceCheckRejectsSymlinkedEvidenceFile(t *testing.T) {
	root := oidcReleaseRepoRoot(t)
	evidenceDir := writeOIDCFieldEvidenceBundle(t)
	cookieEvidence := filepath.Join(evidenceDir, "browser", "session-cookie.txt")
	if err := os.Remove(cookieEvidence); err != nil {
		t.Fatalf("remove session-cookie evidence: %v", err)
	}
	if err := os.Symlink("/etc/hosts", cookieEvidence); err != nil {
		t.Fatalf("symlink session-cookie evidence: %v", err)
	}

	cmd := exec.Command("bash", "release/oidc-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("OIDC field evidence check accepted symlinked file:\n%s", output)
	}
	if !strings.Contains(output, "evidence bundle must not contain symlinks") || !strings.Contains(output, "OIDC session cookie HttpOnly posture must not be a symlink") || !strings.Contains(output, "status=failed") {
		t.Fatalf("expected symlink file rejection, got:\n%s", output)
	}
}

func TestReleaseOIDCFieldEvidenceCheckRejectsExtraUnmanifestedFile(t *testing.T) {
	root := oidcReleaseRepoRoot(t)
	evidenceDir := writeOIDCFieldEvidenceBundle(t)
	writeOIDCFieldEvidenceFile(t, evidenceDir, "browser/operator-note.txt", "manual note\n")

	cmd := exec.Command("bash", "release/oidc-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("OIDC field evidence check accepted extra unmanifested file:\n%s", output)
	}
	if !strings.Contains(output, "evidence bundle contains unexpected file outside manifest policy: browser/operator-note.txt") || !strings.Contains(output, "status=failed") {
		t.Fatalf("expected extra unmanifested file rejection, got:\n%s", output)
	}
}

func TestReleaseOIDCFieldEvidenceCheckRejectsWeakClientSecretPermissions(t *testing.T) {
	root := oidcReleaseRepoRoot(t)
	evidenceDir := writeOIDCFieldEvidenceBundle(t)
	writeOIDCFieldEvidenceFile(t, evidenceDir, "deployment/client-secret-file-permissions.txt", strings.Join([]string{
		"client_secret_used=true",
		"client_secret_file=/etc/openngfw/oidc-client-secret",
		"regular_file=true",
		"symlink=false",
		"mode=0644",
	}, "\n")+"\n")

	cmd := exec.Command("bash", "release/oidc-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("OIDC field evidence check accepted weak client-secret permissions:\n%s", output)
	}
	if !strings.Contains(output, "OIDC client-secret file private mode missing expected evidence pattern") || !strings.Contains(output, "status=failed") {
		t.Fatalf("expected client-secret permission failure, got:\n%s", output)
	}
}

func TestReleaseOIDCFieldEvidenceCheckRejectsUnredactedMaterial(t *testing.T) {
	root := oidcReleaseRepoRoot(t)
	evidenceDir := writeOIDCFieldEvidenceBundle(t)
	writeOIDCFieldEvidenceFile(t, evidenceDir, "redaction/support-bundle-redacted.txt", strings.Join([]string{
		"support_bundle=collected",
		"authSource=oidc-session",
		"cookies=redacted",
		"codes=redacted",
		"tokens=redacted",
		"client_secrets=redacted",
		"id_token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSIsImF1ZCI6Im9wZW5uZ2Z3In0.signaturevalue1234567890",
		"code=authorizationcode12345",
		"X-Phragma-CSRF=csrfsecret123456",
		"oidc_session=sessionsecret123456",
	}, "\n")+"\n")

	cmd := exec.Command("bash", "release/oidc-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("OIDC field evidence check accepted unredacted material:\n%s", output)
	}
	if !strings.Contains(output, "JWT/OIDC token appears unredacted") ||
		!strings.Contains(output, "OAuth token appears unredacted") ||
		!strings.Contains(output, "OIDC authorization code appears unredacted") ||
		!strings.Contains(output, "CSRF token appears unredacted") ||
		!strings.Contains(output, "OIDC session cookie appears unredacted") ||
		!strings.Contains(output, "status=failed") {
		t.Fatalf("expected unredacted material failure, got:\n%s", output)
	}
}

func writeOIDCFieldEvidenceBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	manifestPaths := []string{
		"provider/issuer-client-discovery.txt",
		"provider/id-token-validation.txt",
		"deployment/public-callback.txt",
		"deployment/client-secret-file-permissions.txt",
		"browser/session-cookie.txt",
		"browser/missing-state-rejection.txt",
		"browser/reused-state-rejection.txt",
		"browser/nonce-mismatch-rejection.txt",
		"browser/pkce-exchange-failure.txt",
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
	writeOIDCFieldEvidenceFile(t, dir, "provider/issuer-client-discovery.txt", strings.Join([]string{
		"issuer=https://idp.example.com/realms/openngfw",
		"client_id=openngfw-production",
		"discovery_document=ok",
		"jwks_uri=https://idp.example.com/realms/openngfw/protocol/openid-connect/certs",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "provider/id-token-validation.txt", strings.Join([]string{
		"id_token_validation=passed",
		"signature=valid",
		"issuer=matched",
		"audience=matched",
		"expiration=valid",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "deployment/public-callback.txt", strings.Join([]string{
		"redirect_url=https://fw.example.com/v1/auth/oidc/callback",
		"public_https=true",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "deployment/client-secret-file-permissions.txt", strings.Join([]string{
		"client_secret_used=true",
		"client_secret_file=/etc/openngfw/oidc-client-secret",
		"regular_file=true",
		"symlink=false",
		"mode=0600",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/session-cookie.txt", "Set-Cookie: oidc-session=<redacted>; Path=/; HttpOnly; SameSite=Lax; Secure\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/missing-state-rejection.txt", strings.Join([]string{
		"callback=/v1/auth/oidc/callback",
		"state=missing",
		"status=401",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/reused-state-rejection.txt", strings.Join([]string{
		"callback=/v1/auth/oidc/callback",
		"state=reused",
		"status=401",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/nonce-mismatch-rejection.txt", strings.Join([]string{
		"callback=/v1/auth/oidc/callback",
		"nonce_mismatch=true",
		"status=401",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/pkce-exchange-failure.txt", strings.Join([]string{
		"callback=/v1/auth/oidc/callback",
		"pkce_exchange_failure=true",
		"status=401",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/operator-mutation-with-csrf.txt", strings.Join([]string{
		"method=POST",
		"path=/v1/system/tune",
		"actor_role=operator",
		"X-Phragma-CSRF: <redacted>",
		"status=204",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/missing-csrf-rejection.txt", strings.Join([]string{
		"method=POST",
		"path=/v1/system/tune",
		"actor_role=operator",
		"X-Phragma-CSRF=missing",
		"status=403",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/cross-origin-rejection.txt", strings.Join([]string{
		"method=POST",
		"path=/v1/system/tune",
		"Origin=https://attacker.example",
		"same_origin=false",
		"status=403",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/viewer-mutation-denial.txt", strings.Join([]string{
		"method=POST",
		"path=/v1/system/tune",
		"actor_role=viewer",
		"X-Phragma-CSRF: <redacted>",
		"status=403",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "browser/logout-invalidation.txt", strings.Join([]string{
		"logout_status=204",
		"post_logout_authenticated=false",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "rbac/role-mapping.txt", strings.Join([]string{
		"authSource=oidc-session",
		"provider_role=ngfw-viewer mapped_role=viewer",
		"provider_role=ngfw-operator mapped_role=operator",
		"provider_role=ngfw-admin mapped_role=admin",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "redaction/identity-redacted.txt", strings.Join([]string{
		"issuer_host=redacted",
		"client_id=redacted",
		"subject=redacted",
		"email=redacted",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "redaction/audit-log-redacted.txt", strings.Join([]string{
		"audit_source=management-api",
		"authSource=oidc-session",
		"cookies=redacted",
		"codes=redacted",
		"tokens=redacted",
		"client_secrets=redacted",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceFile(t, dir, "redaction/support-bundle-redacted.txt", strings.Join([]string{
		"support_bundle=collected",
		"authSource=oidc-session",
		"cookies=redacted",
		"codes=redacted",
		"tokens=redacted",
		"client_secrets=redacted",
	}, "\n")+"\n")
	writeOIDCFieldEvidenceManifest(t, dir, manifestPaths...)
	return dir
}

func writeOIDCFieldEvidenceFile(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeOIDCFieldEvidenceManifest(t *testing.T, root string, rels ...string) {
	t.Helper()
	sort.Strings(rels)
	var b strings.Builder
	for _, rel := range rels {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read manifest entry %s: %v", rel, err)
		}
		sum := sha256.Sum256(body)
		b.WriteString(hex.EncodeToString(sum[:]))
		b.WriteString("  ")
		b.WriteString(rel)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.sha256"), []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write manifest.sha256: %v", err)
	}
}

func oidcReleaseRepoRoot(t *testing.T) string {
	t.Helper()
	return releaseRepoRoot(t)
}
