package releaseacceptance

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testReleaseCommit = "0123456789abcdef0123456789abcdef01234567"

func TestBuildStatusReportIncludesMissingCheckRemediation(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "release", "acceptance.json")
	evidenceDir := filepath.Join(dir, "release", "evidence")

	report := BuildStatusReport(StatusOptions{
		ManifestPath:   manifest,
		EvidenceDir:    evidenceDir,
		ExpectedCommit: testReleaseCommit,
	})
	check := checkStatusByName(t, report, "proto-verify")
	if check.State != "missing" {
		t.Fatalf("proto-verify state = %q, want missing", check.State)
	}
	if check.Command != nil {
		t.Fatalf("proto-verify command = %#v, want no recorded evidence command", check.Command)
	}
	if !strings.Contains(check.NextAction, "Record real evidence for proto-verify") {
		t.Fatalf("proto-verify next_action = %q, want record guidance", check.NextAction)
	}
	wantCommand := []string{
		"go", "run", "./cmd/ngfwrelease", "record",
		"--evidence-dir", evidenceDir,
		"--check", "proto-verify",
		"--commit", testReleaseCommit,
		"--detail", "EVIDENCE_DETAIL",
		"--", "make", "proto-verify",
		"VERSION=" + testReleaseCommit[:7],
		"COMMIT=" + testReleaseCommit,
	}
	if !reflect.DeepEqual(check.NextCommand, wantCommand) {
		t.Fatalf("proto-verify next_command = %#v, want %#v", check.NextCommand, wantCommand)
	}

	var out bytes.Buffer
	if err := WriteStatusText(&out, report); err != nil {
		t.Fatalf("WriteStatusText() error = %v", err)
	}
	if !strings.Contains(out.String(), "next: Record real evidence for proto-verify") {
		t.Fatalf("status text missing next action:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "next_command: go run ./cmd/ngfwrelease record") {
		t.Fatalf("status text missing next command:\n%s", out.String())
	}
}

func TestBuildStatusReportNoPerformanceClaimsHasNoBenchmarkCommand(t *testing.T) {
	dir := t.TempDir()
	report := BuildStatusReport(StatusOptions{
		ManifestPath:             filepath.Join(dir, "release", "acceptance.json"),
		EvidenceDir:              filepath.Join(dir, "release", "evidence"),
		ExpectedCommit:           testReleaseCommit,
		AllowNoPerformanceClaims: true,
	})
	check := checkStatusByName(t, report, "release-benchmark")
	if check.State != "not_applicable" {
		t.Fatalf("release-benchmark state = %q, want not_applicable", check.State)
	}
	if len(check.NextCommand) != 0 {
		t.Fatalf("release-benchmark next_command = %#v, want none", check.NextCommand)
	}
	if !strings.Contains(check.NextAction, "No evidence artifact is required") {
		t.Fatalf("release-benchmark next_action = %q, want no-evidence guidance", check.NextAction)
	}
}

func TestBuildStatusReportRejectsTemplateTodoPlaceholderEvidence(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "release", "acceptance.json")
	evidencePath := filepath.Join(dir, "release", "evidence", "proto-verify.txt")
	if err := os.MkdirAll(filepath.Dir(evidencePath), 0o755); err != nil {
		t.Fatalf("mkdir evidence dir: %v", err)
	}
	if err := os.WriteFile(evidencePath, []byte("TODO replace with ngfwrelease record output\n"), 0o644); err != nil {
		t.Fatalf("write placeholder evidence: %v", err)
	}
	writeStatusJSON(t, manifestPath, map[string]any{
		"schema_version":  AcceptanceTemplateSchemaVersion,
		"release_version": "v-template",
		"commit":          "FULL_RELEASE_COMMIT_SHA",
		"generated_at":    "<generated_at>",
		"operator":        "TODO",
		"checks": []map[string]any{{
			"name":            "proto-verify",
			"status":          "todo",
			"artifact":        "evidence/proto-verify.txt",
			"artifact_sha256": strings.Repeat("0", sha256.Size*2),
			"ran_at":          "<ran_at>",
			"detail":          "TODO",
		}},
	})

	report := BuildStatusReport(StatusOptions{
		ManifestPath:   manifestPath,
		EvidenceDir:    filepath.Join(dir, "release", "evidence"),
		ExpectedCommit: testReleaseCommit,
	})
	if report.Ready {
		t.Fatalf("report ready = true, want blocked for template/todo placeholder manifest")
	}
	if report.State != "blocked" {
		t.Fatalf("report state = %q, want blocked", report.State)
	}
	if !strings.Contains(strings.Join(report.Problems, "\n"), "schema_version must be") {
		t.Fatalf("report problems = %v, want template schema rejection", report.Problems)
	}
	check := checkStatusByName(t, report, "proto-verify")
	if check.State != "invalid" {
		t.Fatalf("proto-verify state = %q, want invalid", check.State)
	}
	joined := strings.Join(check.Problems, "\n")
	for _, want := range []string{
		"proto-verify status must be passed",
		"proto-verify ran_at must be RFC3339",
		"proto-verify artifact_sha256",
		"proto-verify artifact must be JSON produced by ngfwrelease record",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("proto-verify problems = %v, want %q", check.Problems, want)
		}
	}
	if !check.ReviewNeeded {
		t.Fatalf("proto-verify review_needed = false, want true for placeholder digest/evidence mismatch")
	}
	if !strings.Contains(check.NextAction, "do not treat remote continuation notes or edited manifests as durable evidence") {
		t.Fatalf("next_action = %q, want durable-evidence remediation", check.NextAction)
	}
}

func TestBuildStatusReportOnlyBenchmarkCanBeNotApplicable(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "release", "acceptance.json")
	writeStatusJSON(t, manifestPath, map[string]any{
		"schema_version":  AcceptanceSchemaVersion,
		"release_version": "v-test",
		"commit":          testReleaseCommit,
		"generated_at":    "2026-06-18T12:00:00Z",
		"operator":        "tester",
		"checks": []map[string]any{{
			"name":   "e2e-install",
			"status": "not_applicable",
			"ran_at": "2026-06-18T12:00:00Z",
			"detail": "deferred",
		}},
	})

	report := BuildStatusReport(StatusOptions{
		ManifestPath:             manifestPath,
		EvidenceDir:              filepath.Join(dir, "release", "evidence"),
		ExpectedCommit:           testReleaseCommit,
		AllowNoPerformanceClaims: true,
	})
	check := checkStatusByName(t, report, "e2e-install")
	if check.State != "invalid" {
		t.Fatalf("e2e-install state = %q, want invalid", check.State)
	}
	if !strings.Contains(strings.Join(check.Problems, "\n"), "e2e-install status must be passed") {
		t.Fatalf("e2e-install problems = %v, want not_applicable rejection", check.Problems)
	}
	if report.Summary.NotApplicable != 0 {
		t.Fatalf("not_applicable summary = %d, want 0 when only non-benchmark check claims not_applicable", report.Summary.NotApplicable)
	}
}

func TestBuildStatusReportRejectsHardeningDeferredByDefault(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "release", "acceptance.json")
	writeStatusJSON(t, manifestPath, map[string]any{
		"schema_version":  AcceptanceSchemaVersion,
		"release_version": "v-test",
		"commit":          testReleaseCommit,
		"generated_at":    "2026-06-18T12:00:00Z",
		"operator":        "tester",
		"checks": []map[string]any{{
			"name":   ContentProductionReadinessCheckName,
			"status": hardeningDeferredStatus,
			"ran_at": "2026-06-18T12:00:00Z",
			"detail": HardeningDeferredDetail(ContentProductionReadinessCheckName),
		}},
	})

	report := BuildStatusReport(StatusOptions{
		ManifestPath:   manifestPath,
		EvidenceDir:    filepath.Join(dir, "release", "evidence"),
		ExpectedCommit: testReleaseCommit,
	})
	check := checkStatusByName(t, report, ContentProductionReadinessCheckName)
	if check.State != "invalid" {
		t.Fatalf("%s state = %q, want invalid without hardening-deferred mode", check.Name, check.State)
	}
	joined := strings.Join(check.Problems, "\n")
	if !strings.Contains(joined, ContentProductionReadinessCheckName) ||
		!strings.Contains(joined, hardeningDeferredStatus) {
		t.Fatalf("%s problems = %v, want default rejection to name deferred status", check.Name, check.Problems)
	}
}

func TestBuildStatusReportAllowsScopedHardeningDeferredInFunctionalMode(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "release", "acceptance.json")
	for _, name := range []string{
		ContentProductionReadinessCheckName,
		"m3-field-evidence",
		OIDCFieldEvidenceCheckName,
		SAMLFieldEvidenceCheckName,
	} {
		t.Run(name, func(t *testing.T) {
			writeStatusJSON(t, manifestPath, map[string]any{
				"schema_version":  AcceptanceSchemaVersion,
				"release_version": "v-test",
				"commit":          testReleaseCommit,
				"generated_at":    "2026-06-18T12:00:00Z",
				"operator":        "tester",
				"checks": []map[string]any{{
					"name":   name,
					"status": hardeningDeferredStatus,
					"ran_at": "2026-06-18T12:00:00Z",
					"detail": HardeningDeferredDetail(name),
				}},
			})

			report := BuildStatusReport(StatusOptions{
				ManifestPath:           manifestPath,
				EvidenceDir:            filepath.Join(dir, "release", "evidence"),
				ExpectedCommit:         testReleaseCommit,
				AllowHardeningDeferred: true,
			})
			check := checkStatusByName(t, report, name)
			if check.State != hardeningDeferredStatus {
				t.Fatalf("%s state = %q, want %q in functional mode; problems=%v", name, check.State, hardeningDeferredStatus, check.Problems)
			}
			if check.RanAt != "2026-06-18T12:00:00Z" || check.Detail != HardeningDeferredDetail(name) {
				t.Fatalf("%s deferred metadata = ran_at %q detail %q, want required ran_at/detail", name, check.RanAt, check.Detail)
			}
			if check.Artifact != "" || check.EvidencePath != "" || check.BenchmarkSummary != "" || len(check.Command) != 0 {
				t.Fatalf("%s deferred check should not carry evidence references: %+v", name, check)
			}
		})
	}
}

func TestBuildStatusReportRejectsUnscopedHardeningDeferredInFunctionalMode(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "release", "acceptance.json")
	writeStatusJSON(t, manifestPath, map[string]any{
		"schema_version":  AcceptanceSchemaVersion,
		"release_version": "v-test",
		"commit":          testReleaseCommit,
		"generated_at":    "2026-06-18T12:00:00Z",
		"operator":        "tester",
		"checks": []map[string]any{{
			"name":   "proto-verify",
			"status": hardeningDeferredStatus,
			"ran_at": "2026-06-18T12:00:00Z",
			"detail": "attempted deferral for an undeferable check",
		}},
	})

	report := BuildStatusReport(StatusOptions{
		ManifestPath:           manifestPath,
		EvidenceDir:            filepath.Join(dir, "release", "evidence"),
		ExpectedCommit:         testReleaseCommit,
		AllowHardeningDeferred: true,
	})
	check := checkStatusByName(t, report, "proto-verify")
	if check.State != "invalid" {
		t.Fatalf("proto-verify state = %q, want invalid for unscoped hardening-deferred check", check.State)
	}
	joined := strings.Join(check.Problems, "\n")
	if !strings.Contains(joined, "proto-verify") || !strings.Contains(joined, hardeningDeferredStatus) {
		t.Fatalf("proto-verify problems = %v, want unscoped deferred rejection", check.Problems)
	}
}

func TestBuildStatusReportCarriesBenchmarkSummary(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "release", "acceptance.json")
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		t.Fatalf("mkdir manifest dir: %v", err)
	}
	writeStatusJSON(t, manifestPath, map[string]any{
		"schema_version":  "phragma.release.acceptance.v1",
		"release_version": "v-test",
		"commit":          testReleaseCommit,
		"generated_at":    "2026-06-18T12:00:00Z",
		"operator":        "tester",
		"checks": []map[string]any{{
			"name":              "release-benchmark",
			"status":            "passed",
			"artifact":          "evidence/release-benchmark.txt",
			"benchmark_summary": "perf/release-results/run-1/summary.json",
			"ran_at":            "2026-06-18T12:00:00Z",
		}},
	})

	report := BuildStatusReport(StatusOptions{
		ManifestPath:   manifestPath,
		EvidenceDir:    filepath.Join(dir, "release", "evidence"),
		ExpectedCommit: testReleaseCommit,
	})
	check := checkStatusByName(t, report, "release-benchmark")
	if check.BenchmarkSummary != "perf/release-results/run-1/summary.json" {
		t.Fatalf("benchmark summary = %q, want manifest value", check.BenchmarkSummary)
	}
	if check.State != "invalid" {
		t.Fatalf("release-benchmark state = %q, want invalid because fixture omits artifact files", check.State)
	}
}

func TestBuildStatusReportDisclosesEvidenceProvenance(t *testing.T) {
	dir := t.TempDir()
	report := BuildStatusReport(StatusOptions{
		ManifestPath:   filepath.Join(dir, "release", "acceptance.json"),
		EvidenceDir:    filepath.Join(dir, "release", "evidence"),
		ExpectedCommit: testReleaseCommit,
	})
	if !strings.Contains(report.Provenance, "ngfwrelease-recorded artifacts") {
		t.Fatalf("provenance = %q, want durable evidence disclosure", report.Provenance)
	}
	joined := strings.Join(report.Disclosures, "\n")
	for _, want := range []string{
		"remote continuation evidence",
		"stale evidence",
		"skip-proof gates",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("disclosures = %q, want %q", joined, want)
		}
	}
	var out bytes.Buffer
	if err := WriteStatusText(&out, report); err != nil {
		t.Fatalf("WriteStatusText() error = %v", err)
	}
	if !strings.Contains(out.String(), "provenance: durable release evidence") ||
		!strings.Contains(out.String(), "remote continuation evidence") {
		t.Fatalf("status text missing provenance disclosure:\n%s", out.String())
	}
}

func TestBuildStatusReportMarksManifestEvidenceMismatchReviewNeeded(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "release", "acceptance.json")
	evidencePath := filepath.Join(dir, "release", "evidence", "proto-verify.txt")
	record := testEvidenceRecord("proto-verify", strings.Repeat("a", 40), RecommendedEvidenceCommand("proto-verify"), strings.Join(RequiredStdoutFragments("proto-verify"), "\n")+"\n")
	raw := writeStatusJSONBytes(t, evidencePath, record)
	writeStatusJSON(t, manifestPath, map[string]any{
		"schema_version":  AcceptanceSchemaVersion,
		"release_version": "v-test",
		"commit":          testReleaseCommit,
		"generated_at":    "2026-06-18T12:00:00Z",
		"operator":        "tester",
		"checks": []map[string]any{{
			"name":            "proto-verify",
			"status":          "passed",
			"artifact":        "evidence/proto-verify.txt",
			"artifact_sha256": digestHex(raw),
			"ran_at":          "2026-06-18T12:00:00Z",
		}},
	})

	report := BuildStatusReport(StatusOptions{
		ManifestPath:   manifestPath,
		EvidenceDir:    filepath.Join(dir, "release", "evidence"),
		ExpectedCommit: testReleaseCommit,
	})
	check := checkStatusByName(t, report, "proto-verify")
	if check.State != "invalid" || !check.ReviewNeeded {
		t.Fatalf("proto-verify state=%q review_needed=%v problems=%v, want invalid review-needed", check.State, check.ReviewNeeded, check.Problems)
	}
	if report.Summary.ReviewNeeded != 1 {
		t.Fatalf("review_needed summary = %d, want 1", report.Summary.ReviewNeeded)
	}
	if !strings.Contains(check.NextAction, "Review stale or mismatched release evidence") {
		t.Fatalf("next_action = %q, want review-needed remediation", check.NextAction)
	}
	var out bytes.Buffer
	if err := WriteStatusText(&out, report); err != nil {
		t.Fatalf("WriteStatusText() error = %v", err)
	}
	for _, want := range []string{
		"review_needed_checks: proto-verify",
		"review_needed_next: regenerate the listed evidence with ngfwrelease record after source-control acceptance",
		"review_needed: true",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("status text = %q, want %q", out.String(), want)
		}
	}
}

func TestValidateEvidenceStdoutRejectsPrivilegedIntegrationSkips(t *testing.T) {
	stdout := strings.Join(RequiredStdoutFragments("privileged-integration"), "\n") +
		"\n=== RUN   TestPrivilegedPath\n--- SKIP: TestPrivilegedPath (0.01s)\nPASS\n"
	problems := ValidateEvidenceStdout("privileged-integration", stdout)
	if !strings.Contains(strings.Join(problems, "\n"), "skip-proof gates cannot be satisfied by skipped tests") {
		t.Fatalf("ValidateEvidenceStdout() problems = %v, want skipped-test rejection", problems)
	}
}

func TestRecommendedEvidenceCommandsAreApproved(t *testing.T) {
	for _, check := range requiredReleaseChecks {
		command := recommendedEvidenceCommand(check)
		if len(command) == 0 {
			t.Fatalf("%s has no recommended evidence command", check)
		}
		if !allowedEvidenceCommand(check, command) {
			t.Fatalf("%s recommended command %#v is not an approved evidence command", check, command)
		}
	}
}

func TestReleaseAcceptanceDocsListRequiredChecks(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "RELEASE_ACCEPTANCE.md"))
	if err != nil {
		t.Fatalf("read release acceptance docs: %v", err)
	}
	got, err := requiredCheckNamesFromDocs(string(raw))
	if err != nil {
		t.Fatalf("parse required check names: %v", err)
	}
	want := RequiredChecks()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("docs required check names = %#v, want %#v", got, want)
	}
}

func TestAllowedEvidenceCommandAcceptsPinnedMakeBuildVars(t *testing.T) {
	command := []string{
		"make", "e2e-auth-runtime-smoke",
		"VERSION=8149370",
		"COMMIT=814937087703f60380a0eaa928fae8e57870d241",
		"BUILD_DATE=2026-06-18T12:00:00Z",
	}
	if !allowedEvidenceCommand("m5-auth-ui", command) {
		t.Fatalf("m5-auth-ui rejected pinned make command %#v", command)
	}
	command = []string{
		"sudo", "make", "e2e-install",
		"VERSION=8149370",
		"COMMIT=814937087703f60380a0eaa928fae8e57870d241",
		"BUILD_DATE=2026-06-18T12:00:00Z",
	}
	if !allowedEvidenceCommand("e2e-install", command) {
		t.Fatalf("e2e-install rejected pinned sudo make command %#v", command)
	}
	for _, command := range [][]string{
		{"make", "e2e-auth-runtime-smoke", "RELEASE_NO_PERFORMANCE_CLAIMS=1"},
		{"make", "e2e-auth-runtime-smoke", "VERSION="},
		{"make", "e2e-auth-runtime-smoke", "VERSION=8149370", "-n"},
	} {
		if allowedEvidenceCommand("m5-auth-ui", command) {
			t.Fatalf("m5-auth-ui accepted unapproved make command %#v", command)
		}
	}
}

func TestWebUIEnterpriseSmokeReleaseGateModel(t *testing.T) {
	if !IsRequiredCheck(WebUIEnterpriseSmokeCheckName) {
		t.Fatalf("%s is not a required release check", WebUIEnterpriseSmokeCheckName)
	}
	wantCommand := []string{"make", "webui-enterprise-smoke"}
	if got := RecommendedEvidenceCommand(WebUIEnterpriseSmokeCheckName); !reflect.DeepEqual(got, wantCommand) {
		t.Fatalf("recommended command = %#v, want %#v", got, wantCommand)
	}
	command := []string{
		"make", "webui-enterprise-smoke",
		"VERSION=8149370",
		"COMMIT=814937087703f60380a0eaa928fae8e57870d241",
		"BUILD_DATE=2026-06-18T12:00:00Z",
	}
	if !allowedEvidenceCommand(WebUIEnterpriseSmokeCheckName, command) {
		t.Fatalf("%s rejected pinned make command %#v", WebUIEnterpriseSmokeCheckName, command)
	}
	for _, command := range [][]string{
		{"make", "webui-visual-smoke"},
		{"make", "webui-enterprise-smoke", "WEBUI_SMOKE_PATHS=/settings"},
		{"node", "e2e/webui-visual-smoke.mjs"},
	} {
		if allowedEvidenceCommand(WebUIEnterpriseSmokeCheckName, command) {
			t.Fatalf("%s accepted unapproved command %#v", WebUIEnterpriseSmokeCheckName, command)
		}
	}
	stdout := strings.Join(RequiredStdoutFragments(WebUIEnterpriseSmokeCheckName), "\n") + "\n"
	if problems := ValidateEvidenceStdout(WebUIEnterpriseSmokeCheckName, stdout); len(problems) != 0 {
		t.Fatalf("ValidateEvidenceStdout() problems = %v, want none", problems)
	}
	incomplete := strings.Replace(stdout, "[webui-smoke] summary: result=passed mode=broad", "[webui-smoke] summary: result=passed mode=targeted", 1)
	if problems := ValidateEvidenceStdout(WebUIEnterpriseSmokeCheckName, incomplete); len(problems) == 0 {
		t.Fatalf("ValidateEvidenceStdout() accepted non-broad WebUI smoke output")
	}
}

func requiredCheckNamesFromDocs(markdown string) ([]string, error) {
	lines := strings.Split(markdown, "\n")
	inSection := false
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "Required check names:" {
			inSection = true
			continue
		}
		if !inSection {
			continue
		}
		if trimmed == "" {
			if len(out) > 0 {
				break
			}
			continue
		}
		if !strings.HasPrefix(trimmed, "- `") || !strings.HasSuffix(trimmed, "`") {
			if len(out) > 0 {
				break
			}
			return nil, fmt.Errorf("unexpected required check line %q", line)
		}
		out = append(out, strings.TrimSuffix(strings.TrimPrefix(trimmed, "- `"), "`"))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("required check names section not found")
	}
	return out, nil
}

func TestValidateEvidenceOutputRedactionRejectsSecrets(t *testing.T) {
	problems := ValidateEvidenceOutputRedaction(
		"m3-field-evidence",
		"status=passed\nPrivateKey = ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi1234567890=\ncode=authorizationcode12345\noidc_session=sessionsecret123456\n",
		"Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456\nX-Phragma-CSRF=csrfsecret123456\n",
	)
	joined := strings.Join(problems, "\n")
	for _, want := range []string{
		"m3-field-evidence evidence stdout contains unredacted WireGuard private key",
		"m3-field-evidence evidence stdout contains unredacted OIDC authorization code",
		"m3-field-evidence evidence stdout contains unredacted OIDC session token",
		"m3-field-evidence evidence stderr contains unredacted bearer token",
		"m3-field-evidence evidence stderr contains unredacted CSRF token",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("ValidateEvidenceOutputRedaction() problems = %v, want %q", problems, want)
		}
	}
}

func TestValidateEvidenceOutputRedactionAllowsSentinelOnlyOutput(t *testing.T) {
	problems := ValidateEvidenceOutputRedaction(
		"m3-field-evidence",
		"m3_field_redaction=wireguard-private-key-redacted,preshared-key-redacted,bearer-tokens-redacted,api-keys-redacted,url-credentials-redacted\nredaction_scan=private-key,psk,bearer,api-key,token,url-userinfo\nstatus=passed\n",
		"",
	)
	if len(problems) != 0 {
		t.Fatalf("ValidateEvidenceOutputRedaction() problems = %v, want none", problems)
	}
}

func TestValidateEvidenceMetadataRedactionRejectsDetailSecrets(t *testing.T) {
	problems := ValidateEvidenceMetadataRedaction(
		"m5-oidc-field-evidence",
		"detail",
		"operator pasted https://user:secretpass@issuer.example/callback",
	)
	joined := strings.Join(problems, "\n")
	if !strings.Contains(joined, "m5-oidc-field-evidence evidence detail contains unredacted URL credentials") {
		t.Fatalf("ValidateEvidenceMetadataRedaction() problems = %v, want URL credential rejection", problems)
	}
}

func TestRedactEvidenceSecretsScrubsKnownPatterns(t *testing.T) {
	got := RedactEvidenceSecrets("Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456\ncollector=https://operator:secretpass@fw.example/status\ncode=authorizationcode12345\nX-Phragma-CSRF=csrfsecret123456\noidc_session=sessionsecret123456")
	for _, leaked := range []string{"abcdefghijklmnopqrstuvwxyz123456", "operator:secretpass", "authorizationcode12345", "csrfsecret123456", "sessionsecret123456"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("RedactEvidenceSecrets() = %q, leaked %q", got, leaked)
		}
	}
	if !strings.Contains(got, redactedEvidenceSecret) {
		t.Fatalf("RedactEvidenceSecrets() = %q, want redaction marker", got)
	}
}

func TestAllowedEvidenceCommandRejectsNarrowedOrDryRunCommands(t *testing.T) {
	tests := []struct {
		name    string
		check   string
		command []string
	}{
		{
			name:    "proto make dry-run",
			check:   "proto-verify",
			command: []string{"make", "proto-verify", "-n"},
		},
		{
			name:    "privileged narrowed go test",
			check:   "privileged-integration",
			command: []string{"go", "test", "-tags", "integration", "-run", "TestDoesNotExist", "./test/integration/"},
		},
		{
			name:    "privileged raw make can skip",
			check:   "privileged-integration",
			command: []string{"make", "integration-test"},
		},
		{
			name:    "m3 field narrowed scope",
			check:   "m3-field-evidence",
			command: []string{"bash", "release/m3-field-evidence.sh", "--evidence-dir", "release/field-evidence/m3", "--require", "bgp"},
		},
		{
			name:    "eBPF field outside approved bundle root",
			check:   "ebpf-ol9-field-evidence",
			command: []string{"bash", "release/ebpf-ol9-field-evidence.sh", "--evidence-dir", "release/field-evidence/ebpf"},
		},
		{
			name:    "release benchmark engineering archive",
			check:   "release-benchmark",
			command: []string{"go", "run", "./cmd/ngfwperf", "verify", "--strict", "--publishable", "perf/results"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if allowedEvidenceCommand(tt.check, tt.command) {
				t.Fatalf("%s allowed command %#v, want rejected", tt.check, tt.command)
			}
		})
	}
}

func TestAllowedEvidenceCommandAcceptsConstrainedPathArguments(t *testing.T) {
	tests := []struct {
		check   string
		command []string
	}{
		{
			check:   ContentProductionReadinessCheckName,
			command: []string{"bash", "release/content-production-readiness.sh", "--evidence-dir", "release/field-evidence/content-production"},
		},
		{
			check:   "m3-field-evidence",
			command: []string{"./release/m3-field-evidence.sh", "--evidence-dir", "release/field-evidence/m3"},
		},
		{
			check:   "ebpf-ol9-field-evidence",
			command: []string{"bash", "release/ebpf-ol9-field-evidence.sh", "--evidence-dir", "release/field-evidence/ebpf-ol9"},
		},
		{
			check:   OIDCFieldEvidenceCheckName,
			command: []string{"bash", "release/oidc-field-evidence.sh", "--evidence-dir", "release/field-evidence/oidc"},
		},
		{
			check:   SAMLFieldEvidenceCheckName,
			command: []string{"bash", "release/saml-field-evidence.sh", "--evidence-dir", "release/field-evidence/saml"},
		},
		{
			check:   "release-benchmark",
			command: []string{"go", "run", "./cmd/ngfwperf", "verify", "--strict", "--publishable", "perf/release-results"},
		},
		{
			check:   "privileged-integration",
			command: []string{"bash", "release/privileged-integration-no-skip.sh"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.check, func(t *testing.T) {
			if !allowedEvidenceCommand(tt.check, tt.command) {
				t.Fatalf("%s rejected command %#v, want accepted", tt.check, tt.command)
			}
		})
	}
}

func TestApprovedDirectReleaseScriptsAreExecutable(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	for check, prefixes := range evidenceCommandPrefixes {
		for _, prefix := range prefixes {
			if len(prefix) == 0 || !strings.HasPrefix(prefix[0], "./release/") || !strings.HasSuffix(prefix[0], ".sh") {
				continue
			}
			path := filepath.Join(repoRoot, strings.TrimPrefix(prefix[0], "./"))
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("%s approved direct script %s is missing: %v", check, prefix[0], err)
			}
			if info.Mode()&0o111 == 0 {
				t.Fatalf("%s approved direct script %s is not executable; either chmod +x it or remove the direct ./release prefix", check, prefix[0])
			}
		}
	}
}

func checkStatusByName(t *testing.T, report StatusReport, name string) CheckStatus {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("status report missing check %q", name)
	return CheckStatus{}
}

func writeStatusJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw := writeStatusJSONBytes(t, path, value)
	if len(raw) == 0 {
		t.Fatalf("write %s returned empty JSON", path)
	}
}

func writeStatusJSONBytes(t *testing.T, path string, value any) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	raw = append(raw, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return raw
}

func digestHex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("%x", sum[:])
}

func testEvidenceRecord(check, commit string, command []string, stdout string) evidenceRecord {
	return evidenceRecord{
		SchemaVersion: EvidenceSchemaVersion,
		Check:         check,
		Commit:        commit,
		RanAt:         "2026-06-18T12:00:00Z",
		DurationMS:    1,
		CWD:           "/workspace/openngfw",
		Command:       command,
		Detail:        check + " release evidence",
		ExitCode:      0,
		Stdout:        stdout,
	}
}
