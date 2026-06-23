package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/detailtech/oss-ngfw/internal/releaseacceptance"
)

const testReleaseVersion = "v2.0.0"
const testReleaseCommit = "abcdef1234567890abcdef1234567890abcdef12"
const testOtherReleaseCommit = "1234567890abcdef1234567890abcdef12345678"
const testReleaseTime = "2026-06-18T12:00:00Z"

var workingDirMu sync.Mutex

func TestVerifyAcceptanceValidManifest(t *testing.T) {
	manifest := writeAcceptanceManifest(t, t.TempDir(), false)

	err := verifyAcceptance(verifyOptions{
		ManifestPath:    manifest,
		ExpectedCommit:  testReleaseCommit,
		ExpectedVersion: testReleaseVersion,
	})
	if err != nil {
		t.Fatalf("verifyAcceptance() error = %v", err)
	}
}

func TestVerifyAcceptanceRejectsMissingManifest(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "acceptance.json")

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "read release acceptance manifest") {
		t.Fatalf("verifyAcceptance() error = %v, want missing manifest failure", err)
	}
}

func TestVerifyAcceptanceAllowsExplicitNoPerformanceClaims(t *testing.T) {
	manifest := writeAcceptanceManifest(t, t.TempDir(), true)

	err := verifyAcceptance(verifyOptions{
		ManifestPath:             manifest,
		ExpectedCommit:           testReleaseCommit,
		ExpectedVersion:          testReleaseVersion,
		AllowNoPerformanceClaims: true,
	})
	if err != nil {
		t.Fatalf("verifyAcceptance() error = %v", err)
	}
}

func TestVerifyAcceptanceRejectsNoPerformanceClaimsWithoutFlag(t *testing.T) {
	manifest := writeAcceptanceManifest(t, t.TempDir(), true)

	err := verifyAcceptance(verifyOptions{
		ManifestPath:    manifest,
		ExpectedCommit:  testReleaseCommit,
		ExpectedVersion: testReleaseVersion,
	})
	if err == nil || !strings.Contains(err.Error(), "--allow-no-performance-claims") {
		t.Fatalf("verifyAcceptance() error = %v, want allow-no-performance-claims failure", err)
	}
}

func TestVerifyAcceptanceRejectsHardeningDeferredWithoutFunctionalFlag(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	markHardeningDeferred(t, &m, releaseacceptance.ContentProductionReadinessCheckName)
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{
		ManifestPath:    manifest,
		ExpectedCommit:  testReleaseCommit,
		ExpectedVersion: testReleaseVersion,
	})
	if err == nil || !strings.Contains(err.Error(), releaseacceptance.ContentProductionReadinessCheckName) || !strings.Contains(err.Error(), "hardening_deferred") {
		t.Fatalf("verifyAcceptance() error = %v, want strict rejection for hardening-deferred content-production-readiness", err)
	}
}

func TestVerifyAcceptanceAllowsScopedHardeningDeferredInFunctionalMode(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	for _, name := range hardeningDeferredCheckNames() {
		markHardeningDeferred(t, &m, name)
	}
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{
		ManifestPath:           manifest,
		ExpectedCommit:         testReleaseCommit,
		ExpectedVersion:        testReleaseVersion,
		AllowHardeningDeferred: true,
	})
	if err != nil {
		t.Fatalf("verifyAcceptance() error = %v, want functional mode to accept scoped hardening-deferred checks", err)
	}
}

func TestVerifyAcceptanceFunctionalRejectsUnscopedHardeningDeferred(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	markHardeningDeferred(t, &m, "proto-verify")
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{
		ManifestPath:           manifest,
		ExpectedCommit:         testReleaseCommit,
		ExpectedVersion:        testReleaseVersion,
		AllowHardeningDeferred: true,
	})
	if err == nil || !strings.Contains(err.Error(), "proto-verify") || !strings.Contains(err.Error(), "hardening_deferred") {
		t.Fatalf("verifyAcceptance() error = %v, want functional mode to reject unscoped hardening-deferred checks", err)
	}
}

func TestVerifyAcceptanceRejectsMissingRequiredCheck(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	m.Checks = m.Checks[:len(m.Checks)-1]
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), `missing required check "webui-enterprise-smoke"`) {
		t.Fatalf("verifyAcceptance() error = %v, want missing webui-enterprise-smoke", err)
	}
}

func TestVerifyAcceptanceRejectsUnknownManifestField(t *testing.T) {
	dir := t.TempDir()
	manifest := writeAcceptanceManifest(t, dir, false)
	injectJSONFieldAfter(t, manifest, `"operator": "release@example.com",`, `"unexpected_manifest_field": true,`)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), `unknown field "unexpected_manifest_field"`) {
		t.Fatalf("verifyAcceptance() error = %v, want unknown manifest field rejection", err)
	}
}

func TestVerifyAcceptanceRejectsMissingContentProductionReadinessCheck(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	checks := make([]acceptanceCheck, 0, len(m.Checks)-1)
	for _, check := range m.Checks {
		if check.Name != releaseacceptance.ContentProductionReadinessCheckName {
			checks = append(checks, check)
		}
	}
	m.Checks = checks
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), `missing required check "content-production-readiness"`) {
		t.Fatalf("verifyAcceptance() error = %v, want missing content-production-readiness", err)
	}
}

func TestVerifyAcceptanceRejectsMissingArtifact(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	m.Checks[0].Artifact = "evidence/missing.txt"
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "not readable") {
		t.Fatalf("verifyAcceptance() error = %v, want unreadable artifact", err)
	}
}

func TestVerifyAcceptanceRejectsMissingBenchmarkSummary(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	releaseBenchmarkCheck(t, &m).BenchmarkSummary = ""
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "benchmark_summary is required") {
		t.Fatalf("verifyAcceptance() error = %v, want missing benchmark_summary", err)
	}
}

func TestVerifyAcceptanceRejectsBenchmarkSummaryOutsideReleaseResults(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	releaseBenchmarkCheck(t, &m).BenchmarkSummary = "perf/results/local/summary.json"
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "perf/release-results/<run>/summary.json") {
		t.Fatalf("verifyAcceptance() error = %v, want benchmark_summary path failure", err)
	}
}

func TestVerifyAcceptanceRejectsNonPublishableBenchmarkSummary(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	releaseBenchmarkCheck(t, &m).BenchmarkSummary = writeRegressionOnlyBenchmarkSummary(t, dir)
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "not publishable") {
		t.Fatalf("verifyAcceptance() error = %v, want non-publishable benchmark_summary", err)
	}
}

func TestVerifyAcceptanceRejectsMissingArtifactDigest(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	m.Checks[0].ArtifactSHA256 = ""
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "artifact_sha256 is required") {
		t.Fatalf("verifyAcceptance() error = %v, want missing artifact_sha256", err)
	}
}

func TestVerifyAcceptanceRejectsMismatchedArtifactDigest(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	m.Checks[0].ArtifactSHA256 = strings.Repeat("a", 64)
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "does not match artifact digest") {
		t.Fatalf("verifyAcceptance() error = %v, want mismatched artifact_sha256", err)
	}
}

func TestVerifyAcceptanceRejectsEmptyArtifact(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	artifactPath := filepath.Join(dir, filepath.FromSlash(m.Checks[0].Artifact))
	if err := os.WriteFile(artifactPath, nil, 0o600); err != nil {
		t.Fatalf("empty artifact: %v", err)
	}
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("verifyAcceptance() error = %v, want empty artifact failure", err)
	}
}

func TestVerifyAcceptanceRejectsOpaqueArtifact(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	artifactPath := filepath.Join(dir, filepath.FromSlash(m.Checks[0].Artifact))
	raw := []byte("plain text is not structured release evidence\n")
	if err := os.WriteFile(artifactPath, raw, 0o600); err != nil {
		t.Fatalf("write opaque artifact: %v", err)
	}
	m.Checks[0].ArtifactSHA256 = artifactDigest(raw)
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "must be JSON produced by ngfwrelease record") {
		t.Fatalf("verifyAcceptance() error = %v, want structured evidence rejection", err)
	}
}

func TestVerifyAcceptanceRejectsUnknownEvidenceField(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	artifactPath := filepath.Join(dir, filepath.FromSlash(m.Checks[0].Artifact))
	raw := injectJSONFieldAfter(t, artifactPath, `"check": "proto-verify",`, `"unexpected_evidence_field": true,`)
	m.Checks[0].ArtifactSHA256 = artifactDigest(raw)
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), `unknown field "unexpected_evidence_field"`) {
		t.Fatalf("verifyAcceptance() error = %v, want unknown evidence field rejection", err)
	}
}

func TestVerifyAcceptanceRejectsEvidenceCheckMismatch(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	m.Checks[0].ArtifactSHA256 = writeEvidenceRecordArtifact(t, dir, m.Checks[0].Artifact, "e2e-install")
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), `evidence check "e2e-install" does not match`) {
		t.Fatalf("verifyAcceptance() error = %v, want evidence check mismatch", err)
	}
}

func TestVerifyAcceptanceRejectsUnapprovedEvidenceCommand(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	m.Checks[0].ArtifactSHA256 = writeEvidenceRecordArtifactWithCommand(t, dir, m.Checks[0].Artifact, "proto-verify", []string{"true"})
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "not an approved release evidence command") {
		t.Fatalf("verifyAcceptance() error = %v, want command rejection", err)
	}
}

func TestRequiredReleaseChecksHaveApprovedCommandPrefixes(t *testing.T) {
	for _, check := range releaseacceptance.RequiredChecks() {
		if len(releaseacceptance.ApprovedEvidenceCommandPrefixes(check)) == 0 {
			t.Fatalf("%s has no approved evidence command prefixes", check)
		}
	}
}

func TestRequiredReleaseChecksIncludeM5OIDCFieldEvidence(t *testing.T) {
	if !releaseacceptance.IsRequiredCheck(releaseacceptance.OIDCFieldEvidenceCheckName) {
		t.Fatalf("%s is not a required release check", releaseacceptance.OIDCFieldEvidenceCheckName)
	}
}

func TestRequiredReleaseChecksIncludeContentProductionReadiness(t *testing.T) {
	if !releaseacceptance.IsRequiredCheck(releaseacceptance.ContentProductionReadinessCheckName) {
		t.Fatalf("%s is not a required release check", releaseacceptance.ContentProductionReadinessCheckName)
	}
}

func TestEvidenceCommandPrefixesMatchReleaseContract(t *testing.T) {
	expected := map[string][][]string{
		"proto-verify": {
			{"make", "proto-verify"},
		},
		"privileged-integration": {
			{"make", "privileged-integration-evidence-check"},
			{"bash", "release/privileged-integration-no-skip.sh"},
			{"sudo", "/tmp/openngfw-itest", "-test.v", "-test.timeout", "300s"},
		},
		"deploy-hardening": {
			{"bash", "release/deploy-hardening-check.sh", "--check"},
			{"./release/deploy-hardening-check.sh", "--check"},
			{"make", "deploy-hardening-check"},
		},
		"policy-restore-drill": {
			{"make", "policy-restore-drill-check"},
			{"bash", "release/policy-restore-drill.sh", "--check"},
		},
		"ha-readiness-recovery": {
			{"make", "ha-readiness-recovery-check"},
			{"bash", "release/ha-readiness-recovery.sh", "--check"},
		},
		"e2e-install": {
			{"bash", "e2e/install-smoke.sh", "--run"},
			{"make", "e2e-install"},
			{"sudo", "make", "e2e-install"},
		},
		"content-package-verification": {
			{"make", "content-package-smoke"},
			{"bash", "e2e/content-package-smoke.sh", "--check"},
		},
		releaseacceptance.ContentProductionReadinessCheckName: {
			{"make", "content-production-readiness-check"},
			{"bash", "release/content-production-readiness.sh", "--evidence-dir"},
			{"./release/content-production-readiness.sh", "--evidence-dir"},
		},
		"release-benchmark": {
			{"make", "benchmark-verify-release"},
			{"go", "run", "./cmd/ngfwperf", "verify", "--strict", "--publishable"},
		},
		"m3-live-networking": {
			{"bash", "release/m3-live-networking.sh", "--run"},
			{"./release/m3-live-networking.sh", "--run"},
			{"make", "m3-live-networking"},
		},
		"m3-field-evidence": {
			{"bash", "release/m3-field-evidence.sh", "--evidence-dir"},
			{"./release/m3-field-evidence.sh", "--evidence-dir"},
			{"make", "m3-field-evidence-check"},
		},
		"ebpf-ol9-field-evidence": {
			{"make", "ebpf-ol9-field-evidence-check"},
			{"bash", "release/ebpf-ol9-field-evidence.sh", "--evidence-dir"},
		},
		"m5-oidc-provider": {
			{"make", "e2e-oidc-runtime-smoke"},
			{"go", "test", "-count=1", "-run", "TestOIDCRuntimeSmoke", "-v", "./cmd/controld"},
		},
		releaseacceptance.OIDCFieldEvidenceCheckName: {
			{"make", "m5-oidc-field-evidence-check"},
			{"bash", "release/oidc-field-evidence.sh", "--evidence-dir"},
			{"./release/oidc-field-evidence.sh", "--evidence-dir"},
		},
		releaseacceptance.SAMLFieldEvidenceCheckName: {
			{"make", "m5-saml-field-evidence-check"},
			{"bash", "release/saml-field-evidence.sh", "--evidence-dir"},
			{"./release/saml-field-evidence.sh", "--evidence-dir"},
		},
		"m5-auth-ui": {
			{"make", "e2e-auth-runtime-smoke"},
		},
		"webui-enterprise-smoke": {
			{"make", "webui-enterprise-smoke"},
		},
	}
	prefixes := releaseacceptance.AllApprovedEvidenceCommandPrefixes()
	if len(prefixes) != len(expected) {
		t.Fatalf("evidence command prefixes has %d check(s), want %d", len(prefixes), len(expected))
	}
	for _, check := range releaseacceptance.RequiredChecks() {
		want, ok := expected[check]
		if !ok {
			t.Fatalf("%s missing from expected release command contract", check)
		}
		if got := prefixes[check]; !reflect.DeepEqual(got, want) {
			t.Fatalf("%s command prefixes = %#v, want %#v", check, got, want)
		}
	}
	for check := range prefixes {
		if !releaseacceptance.IsRequiredCheck(check) {
			t.Fatalf("command prefixes configured for non-required check %q", check)
		}
	}
}

func TestVerifyAcceptanceAcceptsScopedReleaseEvidenceCommands(t *testing.T) {
	tests := []struct {
		check   string
		command []string
	}{
		{
			check:   "content-package-verification",
			command: []string{"bash", "e2e/content-package-smoke.sh", "--check"},
		},
		{
			check:   "m3-live-networking",
			command: []string{"make", "m3-live-networking"},
		},
		{
			check:   "m3-field-evidence",
			command: []string{"make", "m3-field-evidence-check"},
		},
		{
			check:   "ebpf-ol9-field-evidence",
			command: []string{"make", "ebpf-ol9-field-evidence-check"},
		},
		{
			check:   "m5-oidc-provider",
			command: []string{"make", "e2e-oidc-runtime-smoke"},
		},
		{
			check:   releaseacceptance.OIDCFieldEvidenceCheckName,
			command: []string{"make", "m5-oidc-field-evidence-check"},
		},
		{
			check:   "deploy-hardening",
			command: []string{"make", "deploy-hardening-check"},
		},
		{
			check:   "policy-restore-drill",
			command: []string{"make", "policy-restore-drill-check"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.check, func(t *testing.T) {
			dir := t.TempDir()
			m := validAcceptanceManifest(t, dir, false)
			check := checkByName(t, &m, tt.check)
			check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommand(t, dir, check.Artifact, tt.check, tt.command)
			manifest := writeManifestJSON(t, dir, m)

			if err := verifyAcceptance(verifyOptions{ManifestPath: manifest}); err != nil {
				t.Fatalf("verifyAcceptance() error = %v, want scoped command accepted", err)
			}
		})
	}
}

func TestVerifyAcceptanceAcceptsM5OIDCFieldEvidenceCommands(t *testing.T) {
	tests := []struct {
		name    string
		command []string
	}{
		{
			name:    "make target",
			command: []string{"make", "m5-oidc-field-evidence-check"},
		},
		{
			name:    "bash script",
			command: []string{"bash", "release/oidc-field-evidence.sh", "--evidence-dir", "release/field-evidence/oidc"},
		},
		{
			name:    "executable script",
			command: []string{"./release/oidc-field-evidence.sh", "--evidence-dir", "release/field-evidence/oidc"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			m := validAcceptanceManifest(t, dir, false)
			check := checkByName(t, &m, releaseacceptance.OIDCFieldEvidenceCheckName)
			check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommand(t, dir, check.Artifact, releaseacceptance.OIDCFieldEvidenceCheckName, tt.command)
			manifest := writeManifestJSON(t, dir, m)

			if err := verifyAcceptance(verifyOptions{ManifestPath: manifest}); err != nil {
				t.Fatalf("verifyAcceptance() error = %v, want OIDC field-evidence command accepted", err)
			}
		})
	}
}

func TestVerifyAcceptanceAcceptsEbpfOL9FieldEvidenceCommands(t *testing.T) {
	tests := []struct {
		name    string
		command []string
	}{
		{
			name:    "make target",
			command: []string{"make", "ebpf-ol9-field-evidence-check"},
		},
		{
			name:    "bash script",
			command: []string{"bash", "release/ebpf-ol9-field-evidence.sh", "--evidence-dir", "release/field-evidence/ebpf-ol9"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			m := validAcceptanceManifest(t, dir, false)
			check := checkByName(t, &m, "ebpf-ol9-field-evidence")
			check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommand(t, dir, check.Artifact, "ebpf-ol9-field-evidence", tt.command)
			manifest := writeManifestJSON(t, dir, m)

			if err := verifyAcceptance(verifyOptions{ManifestPath: manifest}); err != nil {
				t.Fatalf("verifyAcceptance() error = %v, want eBPF OL9 field-evidence command accepted", err)
			}
		})
	}
}

func TestVerifyAcceptanceAcceptsContentProductionReadinessCommands(t *testing.T) {
	tests := []struct {
		name    string
		command []string
	}{
		{
			name:    "make target",
			command: []string{"make", "content-production-readiness-check"},
		},
		{
			name:    "bash script",
			command: []string{"bash", "release/content-production-readiness.sh", "--evidence-dir", "release/field-evidence/content-production"},
		},
		{
			name:    "executable script",
			command: []string{"./release/content-production-readiness.sh", "--evidence-dir", "release/field-evidence/content-production"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			m := validAcceptanceManifest(t, dir, false)
			check := checkByName(t, &m, releaseacceptance.ContentProductionReadinessCheckName)
			check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommand(t, dir, check.Artifact, releaseacceptance.ContentProductionReadinessCheckName, tt.command)
			manifest := writeManifestJSON(t, dir, m)

			if err := verifyAcceptance(verifyOptions{ManifestPath: manifest}); err != nil {
				t.Fatalf("verifyAcceptance() error = %v, want content-production-readiness command accepted", err)
			}
		})
	}
}

func TestVerifyAcceptanceRejectsContentProductionReadinessDemoSmokeCommand(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, releaseacceptance.ContentProductionReadinessCheckName)
	check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommand(t, dir, check.Artifact, releaseacceptance.ContentProductionReadinessCheckName, []string{"make", "content-package-smoke"})
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "content-production-readiness evidence command") || !strings.Contains(err.Error(), "not an approved release evidence command") {
		t.Fatalf("verifyAcceptance() error = %v, want demo smoke command rejection", err)
	}
}

func TestVerifyAcceptanceRejectsUnapprovedM3LiveNetworkingCommand(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, "m3-live-networking")
	check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommand(t, dir, check.Artifact, "m3-live-networking", []string{"true"})
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "m3-live-networking evidence command") || !strings.Contains(err.Error(), "not an approved release evidence command") {
		t.Fatalf("verifyAcceptance() error = %v, want m3 command rejection", err)
	}
}

func TestVerifyAcceptanceRejectsM3LiveNetworkingCheckOnlyEvidence(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, "m3-live-networking")
	check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommand(t, dir, check.Artifact, "m3-live-networking", []string{"bash", "release/m3-live-networking.sh", "--check"})
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "m3-live-networking evidence command") || !strings.Contains(err.Error(), "not an approved release evidence command") {
		t.Fatalf("verifyAcceptance() error = %v, want m3 --check command rejection", err)
	}
}

func TestVerifyAcceptanceRejectsStalePrivilegedIntegrationWithoutWrapperMarkers(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, "privileged-integration")
	check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommandAndStdout(
		t,
		dir,
		check.Artifact,
		"privileged-integration",
		[]string{"make", "privileged-integration-evidence-check"},
		"=== RUN   TestNetworkSettingsEndToEnd\n--- PASS: TestNetworkSettingsEndToEnd (0.01s)\nPASS\n",
	)
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), `privileged-integration evidence stdout must include "privileged_integration_skip_policy=no-skipped-tests"`) {
		t.Fatalf("verifyAcceptance() error = %v, want missing privileged wrapper marker rejection", err)
	}
}

func TestVerifyAcceptanceRejectsPrivilegedIntegrationRawMakeEvidence(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, "privileged-integration")
	check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommand(
		t,
		dir,
		check.Artifact,
		"privileged-integration",
		[]string{"make", "integration-test"},
	)
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "privileged-integration evidence command") || !strings.Contains(err.Error(), "not an approved release evidence command") {
		t.Fatalf("verifyAcceptance() error = %v, want raw make command rejection", err)
	}
}

func TestVerifyAcceptanceRejectsM3LiveNetworkingMakeCheckEvidence(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, "m3-live-networking")
	check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommand(t, dir, check.Artifact, "m3-live-networking", []string{"make", "m3-live-networking-check"})
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "m3-live-networking evidence command") || !strings.Contains(err.Error(), "not an approved release evidence command") {
		t.Fatalf("verifyAcceptance() error = %v, want m3 Makefile preflight command rejection", err)
	}
}

func TestVerifyAcceptanceRejectsStaleM3LiveNetworkingScopeEvidence(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, "m3-live-networking")
	check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommandAndStdout(
		t,
		dir,
		check.Artifact,
		"m3-live-networking",
		[]string{"make", "m3-live-networking"},
		"automated_scope=static-route-live-forwarding\nstatus=passed\n",
	)
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), `m3-live-networking evidence stdout must include "automated_scope=static-route-live-forwarding,bgp-frr-netns-route-programming,wireguard-handshake-peer-traffic"`) {
		t.Fatalf("verifyAcceptance() error = %v, want stale m3 scope rejection", err)
	}
}

func TestVerifyAcceptanceRejectsStaleE2EInstallStdout(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, "e2e-install")
	check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommandAndStdout(
		t,
		dir,
		check.Artifact,
		"e2e-install",
		[]string{"bash", "e2e/install-smoke.sh", "--check"},
		"check=e2e-install\nmode=check\ninstall_smoke_scope=static-preflight\nrun_requires=linux-root,systemd,network-namespaces,nftables,ip-forwarding\ninstall smoke static preflight complete\nstatus=passed\n",
	)
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), `e2e-install evidence stdout must include "mode=run"`) {
		t.Fatalf("verifyAcceptance() error = %v, want stale e2e-install stdout rejection", err)
	}
}

func TestVerifyAcceptanceRejectsStalePolicyRestoreDrillStdout(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, "policy-restore-drill")
	check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommandAndStdout(
		t,
		dir,
		check.Artifact,
		"policy-restore-drill",
		[]string{"make", "policy-restore-drill-check"},
		"check=policy-restore-drill\nmode=check\nstatus=passed\n",
	)
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), `policy-restore-drill evidence stdout must include "restore_drill_scope=policy-version-rollback,validation,impact-ack,runtime-ack,audit-comment,audit-log,running-pointer,last-known-good,engine-apply"`) {
		t.Fatalf("verifyAcceptance() error = %v, want stale restore-drill stdout rejection", err)
	}
}

func TestVerifyAcceptanceRejectsEvidenceOutputSecrets(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, "e2e-install")
	check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommandAndStdout(
		t,
		dir,
		check.Artifact,
		"e2e-install",
		[]string{"bash", "e2e/install-smoke.sh", "--check"},
		evidenceStdoutForCheck("e2e-install")+"Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456\n",
	)
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "e2e-install evidence stdout contains unredacted bearer token") {
		t.Fatalf("verifyAcceptance() error = %v, want unredacted evidence output rejection", err)
	}
}

func TestVerifyAcceptanceRejectsEvidenceDetailSecrets(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, "proto-verify")
	check.ArtifactSHA256 = rewriteEvidenceRecordArtifact(t, dir, check.Artifact, func(rec *evidenceRecord) {
		rec.Detail = "release run Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"
	})
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "proto-verify evidence detail contains unredacted bearer token") {
		t.Fatalf("verifyAcceptance() error = %v, want unredacted evidence detail rejection", err)
	}
}

func TestVerifyAcceptanceRejectsIncompleteM3FieldEvidenceStdout(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, "m3-field-evidence")
	check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommandAndStdout(
		t,
		dir,
		check.Artifact,
		"m3-field-evidence",
		[]string{"make", "m3-field-evidence-check"},
		"field_evidence_scope=bgp,ipsec,wireguard\nstatus=passed\n",
	)
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), `m3-field-evidence evidence stdout must include "required_ipsec_evidence=swanctl-list-conns,swanctl-list-sas,swanctl-list-pols,ip-xfrm-state,ip-xfrm-policy,protected-subnet-ping"`) {
		t.Fatalf("verifyAcceptance() error = %v, want incomplete field-evidence stdout rejection", err)
	}
}

func TestVerifyAcceptanceRejectsM3FieldEvidenceWithoutRedactionSentinels(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, "m3-field-evidence")
	check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommandAndStdout(
		t,
		dir,
		check.Artifact,
		"m3-field-evidence",
		[]string{"make", "m3-field-evidence-check"},
		strings.Join([]string{
			"field_evidence_scope=bgp,ipsec,wireguard",
			"required_bgp_evidence=show-bgp-summary,ip-route-remote-prefix,frr-running-config",
			"required_ipsec_evidence=swanctl-list-conns,swanctl-list-sas,swanctl-list-pols,ip-xfrm-state,ip-xfrm-policy,protected-subnet-ping",
			"required_wireguard_evidence=wg-show,client-config-redacted,external-client-ping",
			"status=passed",
			"",
		}, "\n"),
	)
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil ||
		!strings.Contains(err.Error(), `m3-field-evidence evidence stdout must include "m3_field_redaction=wireguard-private-key-redacted,preshared-key-redacted,bearer-tokens-redacted,api-keys-redacted,url-credentials-redacted"`) ||
		!strings.Contains(err.Error(), `m3-field-evidence evidence stdout must include "redaction_scan=private-key,psk,bearer,api-key,token,url-userinfo"`) {
		t.Fatalf("verifyAcceptance() error = %v, want missing M3 redaction sentinel rejection", err)
	}
}

func TestVerifyAcceptanceRejectsIncompleteEbpfOL9FieldEvidenceStdout(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		want   string
	}{
		{
			name: "missing attach evidence",
			stdout: strings.Replace(evidenceStdoutForCheck("ebpf-ol9-field-evidence"),
				"required_attach_evidence=xdp-attach,xdp-detach,tc-clsact-attach,tc-clsact-detach,bpftool-program-inspection,cleanup\n", "", 1),
			want: `ebpf-ol9-field-evidence evidence stdout must include "required_attach_evidence=xdp-attach,xdp-detach,tc-clsact-attach,tc-clsact-detach,bpftool-program-inspection,cleanup"`,
		},
		{
			name: "missing renderer scaffold",
			stdout: strings.Replace(evidenceStdoutForCheck("ebpf-ol9-field-evidence"),
				"required_renderer_evidence=ebpf-render-plan\n", "", 1),
			want: `ebpf-ol9-field-evidence evidence stdout must include "required_renderer_evidence=ebpf-render-plan"`,
		},
		{
			name: "missing attach drill sentinel",
			stdout: strings.Replace(evidenceStdoutForCheck("ebpf-ol9-field-evidence"),
				"required_drill_evidence=drill-manifest,probe-source-sha256,probe-object-sha256,attach-detach-command-records\n", "", 1),
			want: `ebpf-ol9-field-evidence evidence stdout must include "required_drill_evidence=drill-manifest,probe-source-sha256,probe-object-sha256,attach-detach-command-records"`,
		},
		{
			name: "missing redaction scan",
			stdout: strings.Replace(evidenceStdoutForCheck("ebpf-ol9-field-evidence"),
				"redaction_scan=private-key,bearer,api-key,token,url-userinfo,oci-ocid,public-ip\n", "", 1),
			want: `ebpf-ol9-field-evidence evidence stdout must include "redaction_scan=private-key,bearer,api-key,token,url-userinfo,oci-ocid,public-ip"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			m := validAcceptanceManifest(t, dir, false)
			check := checkByName(t, &m, "ebpf-ol9-field-evidence")
			check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommandAndStdout(
				t,
				dir,
				check.Artifact,
				"ebpf-ol9-field-evidence",
				[]string{"make", "ebpf-ol9-field-evidence-check"},
				tt.stdout,
			)
			manifest := writeManifestJSON(t, dir, m)

			err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("verifyAcceptance() error = %v, want incomplete eBPF OL9 field-evidence stdout rejection %q", err, tt.want)
			}
		})
	}
}

func TestVerifyAcceptanceRejectsIncompleteContentProductionReadinessStdout(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		want   string
	}{
		{
			name: "missing app-id evidence set",
			stdout: strings.Join([]string{
				"check=content-production-readiness",
				"mode=check",
				"content_production_scope=app-id,threat-id,intel-feeds",
				"required_content_kinds=app-id,threat-id,intel-feeds",
				"required_threat_id_evidence=threat-taxonomy,pcap-regression-corpus,false-positive-regression,license-review,staged-rollout,rollback-drill",
				"required_intel_feeds_evidence=feed-registry,parser-tests,license-review,false-positive-regression,staged-rollout,rollback-drill",
				"content_readiness=production_content=true,production_ready=true",
				"status=passed",
				"",
			}, "\n"),
			want: `content-production-readiness evidence stdout must include "required_app_id_evidence=app-taxonomy,confidence-model,app-regression-corpus,license-review,staged-rollout,rollback-drill"`,
		},
		{
			name: "missing structured readiness sentinel",
			stdout: strings.Join([]string{
				"check=content-production-readiness",
				"mode=check",
				"content_production_scope=app-id,threat-id,intel-feeds",
				"required_content_kinds=app-id,threat-id,intel-feeds",
				"required_app_id_evidence=app-taxonomy,confidence-model,app-regression-corpus,license-review,staged-rollout,rollback-drill",
				"required_threat_id_evidence=threat-taxonomy,pcap-regression-corpus,false-positive-regression,license-review,staged-rollout,rollback-drill",
				"required_intel_feeds_evidence=feed-registry,parser-tests,license-review,false-positive-regression,staged-rollout,rollback-drill",
				"status=passed",
				"",
			}, "\n"),
			want: `content-production-readiness evidence stdout must include "content_readiness=production_content=true,production_ready=true"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			m := validAcceptanceManifest(t, dir, false)
			check := checkByName(t, &m, releaseacceptance.ContentProductionReadinessCheckName)
			check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommandAndStdout(
				t,
				dir,
				check.Artifact,
				releaseacceptance.ContentProductionReadinessCheckName,
				[]string{"make", "content-production-readiness-check"},
				tt.stdout,
			)
			manifest := writeManifestJSON(t, dir, m)

			err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("verifyAcceptance() error = %v, want incomplete content-production-readiness stdout rejection %q", err, tt.want)
			}
		})
	}
}

func TestVerifyAcceptanceRejectsIncompleteDeployHardeningStdout(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, "deploy-hardening")
	check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommandAndStdout(
		t,
		dir,
		check.Artifact,
		"deploy-hardening",
		[]string{"make", "deploy-hardening-check"},
		"required_service_posture=loopback-listeners,authenticated-by-default,no-dev-bypass,systemd-sandbox,capability-bounds\nstatus=passed\n",
	)
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), `deploy-hardening evidence stdout must include "required_installer_posture=root-only,0700-state-log-config,hashed-admin-token,0600-secret-files,unsafe-remote-install-opt-in"`) {
		t.Fatalf("verifyAcceptance() error = %v, want incomplete deploy-hardening stdout rejection", err)
	}
}

func TestVerifyAcceptanceRejectsM5WebUICheckOnlyEvidence(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, "m5-auth-ui")
	check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommand(t, dir, check.Artifact, "m5-auth-ui", []string{"make", "webui-check"})
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "m5-auth-ui evidence command") || !strings.Contains(err.Error(), "not an approved release evidence command") {
		t.Fatalf("verifyAcceptance() error = %v, want m5 webui-only command rejection", err)
	}
}

func TestVerifyAcceptanceRejectsIncompleteM5OIDCProviderStdout(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, "m5-oidc-provider")
	check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommandAndStdout(
		t,
		dir,
		check.Artifact,
		"m5-oidc-provider",
		[]string{"make", "e2e-oidc-runtime-smoke"},
		"oidc_runtime_provider=loopback-mock\nstatus=passed\n",
	)
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), `m5-oidc-provider evidence stdout must include "oidc_runtime_smoke_scope=provider-discovery,authorization-code-pkce,id-token-verification,nonce,session-cookie,csrf,rbac,runtime-provider-lifecycle"`) {
		t.Fatalf("verifyAcceptance() error = %v, want incomplete m5 OIDC provider stdout rejection", err)
	}
}

func TestVerifyAcceptanceRejectsIncompleteM5OIDCFieldEvidenceStdout(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		want   string
	}{
		{
			name: "missing negative checks",
			stdout: strings.Replace(evidenceStdoutForCheck(releaseacceptance.OIDCFieldEvidenceCheckName),
				"oidc_field_negative_checks=missing-state,reused-state,nonce-mismatch,pkce-exchange-failure,logout,viewer-denial\n", "", 1),
			want: `m5-oidc-field-evidence evidence stdout must include "oidc_field_negative_checks=missing-state,reused-state,nonce-mismatch,pkce-exchange-failure,logout,viewer-denial"`,
		},
		{
			name: "missing redaction evidence",
			stdout: strings.Replace(evidenceStdoutForCheck(releaseacceptance.OIDCFieldEvidenceCheckName),
				"oidc_field_redaction=issuer-host-redacted,client-id-redacted,subject-redacted,email-redacted,tokens-redacted,cookies-redacted\n", "", 1),
			want: `m5-oidc-field-evidence evidence stdout must include "oidc_field_redaction=issuer-host-redacted,client-id-redacted,subject-redacted,email-redacted,tokens-redacted,cookies-redacted"`,
		},
		{
			name: "missing global redaction scan",
			stdout: strings.Replace(evidenceStdoutForCheck(releaseacceptance.OIDCFieldEvidenceCheckName),
				"redaction_scan=jwt,bearer,oauth-token,cookie,auth-code,client-secret,csrf\n", "", 1),
			want: `m5-oidc-field-evidence evidence stdout must include "redaction_scan=jwt,bearer,oauth-token,cookie,auth-code,client-secret,csrf"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			m := validAcceptanceManifest(t, dir, false)
			check := checkByName(t, &m, releaseacceptance.OIDCFieldEvidenceCheckName)
			check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommandAndStdout(
				t,
				dir,
				check.Artifact,
				releaseacceptance.OIDCFieldEvidenceCheckName,
				[]string{"make", "m5-oidc-field-evidence-check"},
				tt.stdout,
			)
			manifest := writeManifestJSON(t, dir, m)

			err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("verifyAcceptance() error = %v, want incomplete OIDC field-evidence stdout rejection %q", err, tt.want)
			}
		})
	}
}

func TestM5OIDCFieldEvidenceHelperCommandAndStdoutCoverage(t *testing.T) {
	command := commandForCheck(releaseacceptance.OIDCFieldEvidenceCheckName)
	wantCommand := []string{"make", "m5-oidc-field-evidence-check"}
	if !reflect.DeepEqual(command, wantCommand) {
		t.Fatalf("commandForCheck(%q) = %#v, want %#v", releaseacceptance.OIDCFieldEvidenceCheckName, command, wantCommand)
	}
	if !releaseacceptance.AllowedEvidenceCommand(releaseacceptance.OIDCFieldEvidenceCheckName, command) {
		t.Fatalf("commandForCheck(%q) is not approved by releaseacceptance.AllowedEvidenceCommand", releaseacceptance.OIDCFieldEvidenceCheckName)
	}

	stdout := evidenceStdoutForCheck(releaseacceptance.OIDCFieldEvidenceCheckName)
	for _, fragment := range releaseacceptance.RequiredStdoutFragments(releaseacceptance.OIDCFieldEvidenceCheckName) {
		if !strings.Contains(stdout, fragment) {
			t.Fatalf("evidenceStdoutForCheck(%q) missing required fragment %q in %q", releaseacceptance.OIDCFieldEvidenceCheckName, fragment, stdout)
		}
	}
}

func TestM5SAMLFieldEvidenceHelperCommandAndStdoutCoverage(t *testing.T) {
	command := commandForCheck(releaseacceptance.SAMLFieldEvidenceCheckName)
	wantCommand := []string{"make", "m5-saml-field-evidence-check"}
	if !reflect.DeepEqual(command, wantCommand) {
		t.Fatalf("commandForCheck(%q) = %#v, want %#v", releaseacceptance.SAMLFieldEvidenceCheckName, command, wantCommand)
	}
	if !releaseacceptance.AllowedEvidenceCommand(releaseacceptance.SAMLFieldEvidenceCheckName, command) {
		t.Fatalf("commandForCheck(%q) is not approved by releaseacceptance.AllowedEvidenceCommand", releaseacceptance.SAMLFieldEvidenceCheckName)
	}

	stdout := evidenceStdoutForCheck(releaseacceptance.SAMLFieldEvidenceCheckName)
	for _, fragment := range releaseacceptance.RequiredStdoutFragments(releaseacceptance.SAMLFieldEvidenceCheckName) {
		if !strings.Contains(stdout, fragment) {
			t.Fatalf("evidenceStdoutForCheck(%q) missing required fragment %q in %q", releaseacceptance.SAMLFieldEvidenceCheckName, fragment, stdout)
		}
	}
}

func TestEbpfOL9FieldEvidenceHelperCommandAndStdoutCoverage(t *testing.T) {
	checkName := "ebpf-ol9-field-evidence"
	command := commandForCheck(checkName)
	wantCommand := []string{"make", "ebpf-ol9-field-evidence-check"}
	if !reflect.DeepEqual(command, wantCommand) {
		t.Fatalf("commandForCheck(%q) = %#v, want %#v", checkName, command, wantCommand)
	}
	if !releaseacceptance.AllowedEvidenceCommand(checkName, command) {
		t.Fatalf("commandForCheck(%q) is not approved by releaseacceptance.AllowedEvidenceCommand", checkName)
	}

	stdout := evidenceStdoutForCheck(checkName)
	for _, fragment := range releaseacceptance.RequiredStdoutFragments(checkName) {
		if !strings.Contains(stdout, fragment) {
			t.Fatalf("evidenceStdoutForCheck(%q) missing required fragment %q in %q", checkName, fragment, stdout)
		}
	}
}

func TestContentProductionReadinessHelperCommandAndStdoutCoverage(t *testing.T) {
	command := commandForCheck(releaseacceptance.ContentProductionReadinessCheckName)
	wantCommand := []string{"make", "content-production-readiness-check"}
	if !reflect.DeepEqual(command, wantCommand) {
		t.Fatalf("commandForCheck(%q) = %#v, want %#v", releaseacceptance.ContentProductionReadinessCheckName, command, wantCommand)
	}
	if !releaseacceptance.AllowedEvidenceCommand(releaseacceptance.ContentProductionReadinessCheckName, command) {
		t.Fatalf("commandForCheck(%q) is not approved by releaseacceptance.AllowedEvidenceCommand", releaseacceptance.ContentProductionReadinessCheckName)
	}

	stdout := evidenceStdoutForCheck(releaseacceptance.ContentProductionReadinessCheckName)
	for _, fragment := range releaseacceptance.RequiredStdoutFragments(releaseacceptance.ContentProductionReadinessCheckName) {
		if !strings.Contains(stdout, fragment) {
			t.Fatalf("evidenceStdoutForCheck(%q) missing required fragment %q in %q", releaseacceptance.ContentProductionReadinessCheckName, fragment, stdout)
		}
	}
}

func TestVerifyAcceptanceRejectsContentProductionReadinessWithoutProductionContentReadiness(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*evidenceRecord)
		want   string
	}{
		{
			name: "missing content_readiness",
			mutate: func(rec *evidenceRecord) {
				rec.ContentReadiness = nil
			},
			want: "content-production-readiness evidence content_readiness is required",
		},
		{
			name: "production content false",
			mutate: func(rec *evidenceRecord) {
				rec.ContentReadiness.ProductionContent = false
			},
			want: "content-production-readiness evidence content_readiness.production_content must be true",
		},
		{
			name: "production ready false",
			mutate: func(rec *evidenceRecord) {
				rec.ContentReadiness.ProductionReady = false
			},
			want: "content-production-readiness evidence content_readiness.production_ready must be true",
		},
		{
			name: "missing threat-id evidence set",
			mutate: func(rec *evidenceRecord) {
				rec.ContentReadiness.RequiredProductionEvidence = []string{
					"app-id:signed-production-package,production-corpus,license-attestation,rollout-plan,rollback-plan",
					"intel-feeds:signed-production-package,source-attribution,license-attestation,staleness-sla,rollout-plan,rollback-plan",
				}
			},
			want: "content-production-readiness required_production_evidence must include threat-id evidence set",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			m := validAcceptanceManifest(t, dir, false)
			check := checkByName(t, &m, releaseacceptance.ContentProductionReadinessCheckName)
			check.ArtifactSHA256 = rewriteEvidenceRecordArtifact(t, dir, check.Artifact, tt.mutate)
			manifest := writeManifestJSON(t, dir, m)

			err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("verifyAcceptance() error = %v, want content production readiness rejection %q", err, tt.want)
			}
		})
	}
}

func TestVerifyAcceptanceRejectsM5EvidenceWithoutStartupGuard(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, "m5-auth-ui")
	check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommandAndStdout(
		t,
		dir,
		check.Artifact,
		"m5-auth-ui",
		[]string{"make", "e2e-auth-runtime-smoke"},
		"auth_runtime_smoke_scope=hashed-local-users,rbac,tls-security-headers,request-limits,rate-limit\nstatus=passed\n",
	)
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), `m5-auth-ui evidence stdout must include "auth_runtime_smoke_scope=hashed-local-users,rbac,tls-security-headers,request-limits,rate-limit,unsafe-noauth-startup-guard"`) {
		t.Fatalf("verifyAcceptance() error = %v, want missing m5 startup guard stdout rejection", err)
	}
}

func TestVerifyAcceptanceRejectsContentPackageUnitOnlyEvidence(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, releaseacceptance.ContentPackageCheckName)
	check.ArtifactSHA256 = writeEvidenceRecordArtifactWithCommand(t, dir, check.Artifact, releaseacceptance.ContentPackageCheckName, []string{"go", "test", "./internal/contentpkg"})
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "content-package-verification evidence command") || !strings.Contains(err.Error(), "not an approved release evidence command") {
		t.Fatalf("verifyAcceptance() error = %v, want content package smoke command rejection", err)
	}
}

func TestVerifyAcceptanceRejectsContentPackageEvidenceWithoutReadinessScope(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, releaseacceptance.ContentPackageCheckName)
	check.ArtifactSHA256 = rewriteEvidenceRecordArtifact(t, dir, check.Artifact, func(rec *evidenceRecord) {
		rec.ContentReadiness = nil
	})
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "content_readiness is required") {
		t.Fatalf("verifyAcceptance() error = %v, want content_readiness failure", err)
	}
}

func TestVerifyAcceptanceRejectsContentPackageDemoSmokeClaimingProductionContent(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	check := checkByName(t, &m, releaseacceptance.ContentPackageCheckName)
	check.Detail = "production content ready"
	check.ArtifactSHA256 = rewriteEvidenceRecordArtifact(t, dir, check.Artifact, func(rec *evidenceRecord) {
		rec.Detail = "production content ready"
		rec.ContentReadiness.ProductionContent = true
		rec.ContentReadiness.Scope = "production"
	})
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "demo smoke evidence must not claim production content") {
		t.Fatalf("verifyAcceptance() error = %v, want production-content overclaim failure", err)
	}
}

func TestVerifyAcceptanceRejectsNoPerformanceClaimsArtifact(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, true)
	check := releaseBenchmarkCheck(t, &m)
	check.Artifact = "evidence/release-benchmark.txt"
	check.ArtifactSHA256 = strings.Repeat("a", 64)
	check.BenchmarkSummary = "perf/release-results/release-good/summary.json"
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{
		ManifestPath:             manifest,
		AllowNoPerformanceClaims: true,
	})
	if err == nil || !strings.Contains(err.Error(), "not_applicable must not reference an artifact or benchmark summary") {
		t.Fatalf("verifyAcceptance() error = %v, want not_applicable artifact failure", err)
	}
}

func TestVerifyAcceptanceRejectsNoPerformanceClaimsDetailOverclaim(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, true)
	check := releaseBenchmarkCheck(t, &m)
	check.Detail = "Release notes claim forwarding throughput reached 10 Gbps."
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{
		ManifestPath:             manifest,
		AllowNoPerformanceClaims: true,
	})
	if err == nil || !strings.Contains(err.Error(), "must not contain performance claim language") {
		t.Fatalf("verifyAcceptance() error = %v, want performance overclaim failure", err)
	}
}

func TestVerifyAcceptanceRejectsMismatchedVersionAndCommit(t *testing.T) {
	manifest := writeAcceptanceManifest(t, t.TempDir(), false)

	err := verifyAcceptance(verifyOptions{
		ManifestPath:    manifest,
		ExpectedCommit:  testOtherReleaseCommit,
		ExpectedVersion: "v9.9.9",
	})
	if err == nil {
		t.Fatal("verifyAcceptance() error = nil, want mismatch failure")
	}
	if !strings.Contains(err.Error(), `release_version "v2.0.0" does not match expected "v9.9.9"`) {
		t.Fatalf("verifyAcceptance() error = %v, want version mismatch", err)
	}
	if !strings.Contains(err.Error(), `commit "abcdef1234567890abcdef1234567890abcdef12" does not match expected "1234567890abcdef1234567890abcdef12345678"`) {
		t.Fatalf("verifyAcceptance() error = %v, want commit mismatch", err)
	}
}

func TestVerifyAcceptanceRejectsShortManifestCommit(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	m.Commit = "abcdef1"
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "commit must be a full 40-character hex git commit") {
		t.Fatalf("verifyAcceptance() error = %v, want full commit failure", err)
	}
}

func TestVerifyAcceptanceRejectsShortExpectedCommit(t *testing.T) {
	manifest := writeAcceptanceManifest(t, t.TempDir(), false)

	err := verifyAcceptance(verifyOptions{
		ManifestPath:   manifest,
		ExpectedCommit: "abcdef1",
	})
	if err == nil || !strings.Contains(err.Error(), "expected commit must be a full 40-character hex git commit") {
		t.Fatalf("verifyAcceptance() error = %v, want full expected commit failure", err)
	}
}

func TestVerifyAcceptanceRejectsEscapingArtifactPath(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	m.Checks[0].Artifact = "../outside.txt"
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "escapes the manifest directory") {
		t.Fatalf("verifyAcceptance() error = %v, want escaping artifact failure", err)
	}
}

func TestVerifyAcceptanceRejectsArtifactOutsideEvidence(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	m.Checks[0].Artifact = "proto-verify.txt"
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "artifact must be under evidence/") {
		t.Fatalf("verifyAcceptance() error = %v, want evidence path failure", err)
	}
}

func TestVerifyAcceptanceRejectsSymlinkEscapingEvidence(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	raw := []byte("outside evidence\n")
	if err := os.WriteFile(outside, raw, 0o600); err != nil {
		t.Fatalf("write outside artifact: %v", err)
	}
	link := filepath.Join(dir, filepath.FromSlash(m.Checks[0].Artifact))
	if err := os.Remove(link); err != nil {
		t.Fatalf("remove original artifact: %v", err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink artifact: %v", err)
	}
	m.Checks[0].ArtifactSHA256 = artifactDigest(raw)
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "must stay under evidence/") {
		t.Fatalf("verifyAcceptance() error = %v, want symlink escape failure", err)
	}
}

func TestVerifyAcceptanceRejectsDuplicateArtifactReuse(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, false)
	m.Checks[1].Artifact = m.Checks[0].Artifact
	m.Checks[1].ArtifactSHA256 = m.Checks[0].ArtifactSHA256
	manifest := writeManifestJSON(t, dir, m)

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil || !strings.Contains(err.Error(), "reuses evidence artifact already used by proto-verify") {
		t.Fatalf("verifyAcceptance() error = %v, want duplicate artifact failure", err)
	}
}

func TestRunWithIORejectsStrayArgs(t *testing.T) {
	tests := [][]string{
		{"verify", "--manifest", "release/acceptance.json", "extra"},
		{"status", "--manifest", "release/acceptance.json", "extra"},
		{"template", "extra"},
		{"assemble", "--version", testReleaseVersion, "--commit", testReleaseCommit, "--operator", "release@example.com", "extra"},
	}
	for _, args := range tests {
		err := runWithIO(args, &bytes.Buffer{}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "does not accept positional arguments") {
			t.Fatalf("runWithIO(%v) error = %v, want stray args failure", args, err)
		}
	}
}

func TestStatusCommandReportsMissingEvidenceAndStrictFailure(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "release", "acceptance.json")
	evidenceDir := filepath.Join(dir, "release", "evidence")
	var stdout bytes.Buffer

	if err := runWithIO([]string{
		"status",
		"--manifest", manifest,
		"--evidence-dir", evidenceDir,
	}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("runWithIO(status) error = %v", err)
	}
	for _, want := range []string{
		"release acceptance status: blocked",
		"manifest: " + manifest + " (missing)",
		"proto-verify: missing",
		"next: Record real evidence for proto-verify",
		"next_command: go run ./cmd/ngfwrelease record",
		"release acceptance manifest " + manifest + " is missing",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("status stdout = %q, want %q", stdout.String(), want)
		}
	}

	err := runWithIO([]string{
		"status",
		"--manifest", manifest,
		"--evidence-dir", evidenceDir,
		"--strict",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "release acceptance status is blocked") {
		t.Fatalf("runWithIO(status --strict) error = %v, want blocked strict failure", err)
	}
}

func TestStatusCommandReportsEvidencePendingManifest(t *testing.T) {
	dir := t.TempDir()
	writeReleaseEvidenceSet(t, dir, true)
	manifest := filepath.Join(dir, "release", "acceptance.json")
	evidenceDir := filepath.Join(dir, "release", "evidence")
	var stdout bytes.Buffer

	if err := runWithIO([]string{
		"status",
		"--manifest", manifest,
		"--evidence-dir", evidenceDir,
	}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("runWithIO(status evidence-only) error = %v", err)
	}
	for _, want := range []string{
		"release acceptance status: evidence-pending-manifest",
		fmt.Sprintf("checks: passed=0 recorded=%d missing=0 invalid=0 review_needed=0 not_applicable=0 hardening_deferred=0 todo=0", len(releaseacceptance.RequiredChecks())),
		"content-production-readiness: recorded",
		"m5-oidc-field-evidence: recorded",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("status stdout = %q, want %q", stdout.String(), want)
		}
	}
}

func TestStatusCommandFunctionalHardeningDeferredReportsDeferredChecks(t *testing.T) {
	dir := t.TempDir()
	writeReleaseEvidenceSet(t, dir, true)
	for _, name := range hardeningDeferredCheckNames() {
		if err := os.Remove(filepath.Join(dir, "release", "evidence", name+".txt")); err != nil {
			t.Fatalf("remove deferred evidence %s: %v", name, err)
		}
	}
	manifest := filepath.Join(dir, "release", "acceptance.json")
	evidenceDir := filepath.Join(dir, "release", "evidence")
	var stdout bytes.Buffer

	if err := runWithIO([]string{
		"status",
		"--manifest", manifest,
		"--evidence-dir", evidenceDir,
		"--functional-hardening-deferred",
	}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("runWithIO(status --functional-hardening-deferred) error = %v", err)
	}
	for _, want := range []string{
		"release acceptance status: evidence-pending-manifest",
		"hardening_deferred=4",
		"content-production-readiness: hardening_deferred",
		"m3-field-evidence: hardening_deferred",
		"m5-oidc-field-evidence: hardening_deferred",
		"m5-saml-field-evidence: hardening_deferred",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("status stdout = %q, want %q", stdout.String(), want)
		}
	}
	if strings.Contains(stdout.String(), "proto-verify: hardening_deferred") {
		t.Fatalf("status stdout = %q, proto-verify must not be deferable", stdout.String())
	}
}

func TestStatusCommandReportsUnknownEvidenceFieldInvalid(t *testing.T) {
	dir := t.TempDir()
	evidenceDir := filepath.Join(dir, "release", "evidence")
	evidencePath := filepath.Join(evidenceDir, "proto-verify.txt")
	writeFile(t, evidencePath, evidenceRecordJSON(t, "proto-verify", commandForCheck("proto-verify"), evidenceStdoutForCheck("proto-verify")))
	injectJSONFieldAfter(t, evidencePath, `"check": "proto-verify",`, `"unexpected_evidence_field": true,`)
	var stdout bytes.Buffer

	if err := runWithIO([]string{
		"status",
		"--manifest", filepath.Join(dir, "release", "acceptance.json"),
		"--evidence-dir", evidenceDir,
		"--json",
	}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("runWithIO(status --json) error = %v", err)
	}
	var report releaseacceptance.StatusReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal status report: %v\n%s", err, stdout.String())
	}
	for _, check := range report.Checks {
		if check.Name != "proto-verify" {
			continue
		}
		if check.State != "invalid" {
			t.Fatalf("proto-verify state = %q, want invalid", check.State)
		}
		for _, problem := range check.Problems {
			if strings.Contains(problem, `unknown field "unexpected_evidence_field"`) {
				return
			}
		}
		t.Fatalf("proto-verify problems = %v, want unknown field problem", check.Problems)
	}
	t.Fatal("proto-verify status missing")
}

func TestStatusCommandPreviewsNoPerformanceClaimsWithoutBenchmarkArtifact(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "release", "acceptance.json")
	evidenceDir := filepath.Join(dir, "release", "evidence")
	var stdout bytes.Buffer

	if err := runWithIO([]string{
		"status",
		"--manifest", manifest,
		"--evidence-dir", evidenceDir,
		"--allow-no-performance-claims",
		"--json",
	}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("runWithIO(status --allow-no-performance-claims --json) error = %v", err)
	}
	var report releaseacceptance.StatusReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal status report: %v\n%s", err, stdout.String())
	}
	if report.Summary.NotApplicable != 1 {
		t.Fatalf("summary = %+v, want exactly one not_applicable check", report.Summary)
	}
	for _, check := range report.Checks {
		if check.Name == "release-benchmark" {
			if check.State != "not_applicable" || check.Artifact != "" || check.EvidencePath != "" {
				t.Fatalf("release-benchmark status = %+v, want not_applicable without artifact", check)
			}
			return
		}
	}
	t.Fatal("release-benchmark status missing")
}

func TestStatusCommandJSONReportsReadyManifest(t *testing.T) {
	dir := t.TempDir()
	manifest := writeAcceptanceManifest(t, dir, true)
	var stdout bytes.Buffer

	if err := runWithIO([]string{
		"status",
		"--manifest", manifest,
		"--evidence-dir", filepath.Join(dir, "evidence"),
		"--allow-no-performance-claims",
		"--json",
	}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("runWithIO(status --json) error = %v", err)
	}
	var report releaseacceptance.StatusReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal status report: %v\n%s", err, stdout.String())
	}
	if report.SchemaVersion != releaseacceptance.AcceptanceStatusSchemaVersion || !report.Ready || report.State != "ready" {
		t.Fatalf("status report = %+v, want ready %s", report, releaseacceptance.AcceptanceStatusSchemaVersion)
	}
	if !report.ManifestPresent {
		t.Fatalf("manifest_present = false in %+v", report)
	}
	if report.Summary.Passed != len(releaseacceptance.RequiredChecks())-1 || report.Summary.NotApplicable != 1 || report.Summary.Invalid != 0 || report.Summary.Missing != 0 {
		t.Fatalf("summary = %+v, want all checks passed except one not_applicable", report.Summary)
	}
	if len(report.Problems) != 0 {
		t.Fatalf("problems = %v, want none", report.Problems)
	}
}

func TestStatusCommandJSONAllowsFunctionalHardeningDeferred(t *testing.T) {
	dir := t.TempDir()
	m := validAcceptanceManifest(t, dir, true)
	for _, name := range hardeningDeferredCheckNames() {
		markHardeningDeferred(t, &m, name)
	}
	manifest := writeManifestJSON(t, dir, m)
	var stdout bytes.Buffer

	if err := runWithIO([]string{
		"status",
		"--manifest", manifest,
		"--evidence-dir", filepath.Join(dir, "evidence"),
		"--allow-no-performance-claims",
		"--functional-hardening-deferred",
		"--json",
	}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("runWithIO(status --functional-hardening-deferred --json) error = %v", err)
	}
	var report releaseacceptance.StatusReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal status report: %v\n%s", err, stdout.String())
	}
	if !report.Ready || report.State != "ready" || report.Summary.HardeningDeferred != len(hardeningDeferredCheckNames()) {
		t.Fatalf("status report = %+v, want ready functional hardening-deferred summary", report)
	}
	for _, name := range hardeningDeferredCheckNames() {
		check := statusCheckByName(t, report, name)
		if check.State != "hardening_deferred" {
			t.Fatalf("%s state = %q, want hardening_deferred", name, check.State)
		}
		if check.RanAt == "" || check.Detail != releaseacceptance.HardeningDeferredDetail(name) {
			t.Fatalf("%s deferred metadata = ran_at %q detail %q, want required functional deferral metadata", name, check.RanAt, check.Detail)
		}
		if check.Artifact != "" || check.EvidencePath != "" || check.BenchmarkSummary != "" || len(check.Command) != 0 {
			t.Fatalf("%s deferred check should not reference evidence: %+v", name, check)
		}
	}
}

func TestStatusCommandReportsStaleE2EInstallEvidenceNextAction(t *testing.T) {
	dir := t.TempDir()
	evidenceDir := filepath.Join(dir, "release", "evidence")
	writeEvidenceRecordArtifactWithCommandAndStdout(
		t,
		dir,
		filepath.ToSlash(filepath.Join("release", "evidence", "e2e-install.txt")),
		"e2e-install",
		[]string{"bash", "e2e/install-smoke.sh", "--check"},
		"check=e2e-install\nmode=check\ninstall_smoke_scope=static-preflight\nrun_requires=linux-root,systemd,network-namespaces,nftables,ip-forwarding\ninstall smoke static preflight complete\nstatus=passed\n",
	)
	var stdout bytes.Buffer

	if err := runWithIO([]string{
		"status",
		"--manifest", filepath.Join(dir, "release", "acceptance.json"),
		"--evidence-dir", evidenceDir,
		"--json",
	}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("runWithIO(status --json) error = %v", err)
	}
	var report releaseacceptance.StatusReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal status report: %v\n%s", err, stdout.String())
	}
	for _, check := range report.Checks {
		if check.Name != "e2e-install" {
			continue
		}
		if check.State != "invalid" {
			t.Fatalf("e2e-install state = %q, want invalid", check.State)
		}
		if !strings.Contains(strings.Join(check.Problems, "\n"), `e2e-install evidence stdout must include "mode=run"`) {
			t.Fatalf("e2e-install problems = %v, want stale run-mode problem", check.Problems)
		}
		if !strings.Contains(check.NextAction, "stale or incomplete") || !strings.Contains(check.NextAction, "clean checkout") {
			t.Fatalf("e2e-install next_action = %q, want stale clean-checkout guidance", check.NextAction)
		}
		return
	}
	t.Fatal("e2e-install status missing")
}

func TestStatusCommandRecordabilityReportsDirtySource(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	writeRepoFile(t, repo, "cmd/source.go", "package dirty\n")
	var stdout bytes.Buffer

	if err := runWithIO([]string{
		"status",
		"--manifest", filepath.Join(repo, "release", "acceptance.json"),
		"--evidence-dir", filepath.Join(repo, "release", "evidence"),
		"--commit", commit,
		"--recordability",
	}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("runWithIO(status --recordability) error = %v", err)
	}
	for _, want := range []string{
		"recordability: blocked",
		"git_head: " + commit,
		"record_commit: " + commit,
		"allowed_dirty_paths: perf/release-results, release/evidence, release/field-evidence",
		"problem: release source tree has uncommitted changes outside allowed release artifact paths",
		"dirty_source_paths: ?? cmd/source.go",
		"next: commit or stash source changes before recording release evidence",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("status stdout = %q, want %q", stdout.String(), want)
		}
	}
}

func TestStatusCommandStrictRecordabilityFailsOnDirtySource(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	releaseDir := filepath.Join(repo, "release")
	m := validAcceptanceManifest(t, releaseDir, true)
	manifest := writeManifestJSON(t, releaseDir, m)
	writeRepoFile(t, repo, "cmd/source.go", "package dirty\n")
	var stdout bytes.Buffer

	err := runWithIO([]string{
		"status",
		"--manifest", manifest,
		"--evidence-dir", filepath.Join(repo, "release", "evidence"),
		"--allow-no-performance-claims",
		"--recordability",
		"--strict",
	}, &stdout, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "release evidence recordability is blocked") {
		t.Fatalf("runWithIO(status --strict --recordability) error = %v, want recordability failure", err)
	}
	if !strings.Contains(stdout.String(), "release acceptance status: ready") ||
		!strings.Contains(stdout.String(), "recordability: blocked") ||
		!strings.Contains(stdout.String(), "dirty_source_paths: ?? cmd/source.go") {
		t.Fatalf("status stdout = %q, want ready manifest plus blocked recordability", stdout.String())
	}
}

func TestRecordabilityCommandAllowsCleanCheckoutWithoutAcceptanceManifest(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	var stdout bytes.Buffer

	if err := runWithIO([]string{
		"recordability",
		"--evidence-dir", filepath.Join(repo, "release", "evidence"),
		"--commit", commit,
		"--strict",
	}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("runWithIO(recordability --strict) error = %v", err)
	}
	if !strings.Contains(stdout.String(), "recordability: ready") ||
		!strings.Contains(stdout.String(), "git_head: "+commit) ||
		!strings.Contains(stdout.String(), "record_commit: "+commit) {
		t.Fatalf("recordability stdout = %q, want ready clean checkout", stdout.String())
	}
	if strings.Contains(stdout.String(), "release acceptance status:") {
		t.Fatalf("recordability stdout = %q, want no release acceptance status output", stdout.String())
	}
}

func TestRecordabilityCommandFailsOnDirtySourceWithoutAcceptanceManifest(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	writeRepoFile(t, repo, "cmd/source.go", "package dirty\n")
	var stdout bytes.Buffer

	err := runWithIO([]string{
		"recordability",
		"--evidence-dir", filepath.Join(repo, "release", "evidence"),
		"--commit", commit,
		"--strict",
	}, &stdout, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "release evidence recordability is blocked") {
		t.Fatalf("runWithIO(recordability --strict) error = %v, want recordability failure", err)
	}
	if !strings.Contains(stdout.String(), "recordability: blocked") ||
		!strings.Contains(stdout.String(), "dirty_source_paths: ?? cmd/source.go") {
		t.Fatalf("recordability stdout = %q, want dirty source guidance", stdout.String())
	}
	if strings.Contains(stdout.String(), "release acceptance status:") {
		t.Fatalf("recordability stdout = %q, want no release acceptance status output", stdout.String())
	}
}

func TestRecordabilityCommandFailsOnStaleEvidenceCommit(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	evidenceDir := filepath.Join(repo, "release", "evidence")
	writeRepoFile(t, repo, "release/evidence/proto-verify.txt", string(evidenceRecordJSON(t, "proto-verify", commandForCheck("proto-verify"), evidenceStdoutForCheck("proto-verify"))))
	var stdout bytes.Buffer

	err := runWithIO([]string{
		"recordability",
		"--evidence-dir", evidenceDir,
		"--commit", commit,
		"--strict",
	}, &stdout, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "release evidence recordability is blocked") {
		t.Fatalf("runWithIO(recordability --strict) error = %v, want stale evidence failure", err)
	}
	for _, want := range []string{
		"recordability: blocked",
		"problem: release evidence directory contains artifacts recorded for a different commit",
		"stale_evidence_paths: release/evidence/proto-verify.txt (evidence commit " + testReleaseCommit + " != record commit " + commit + ")",
		"next: move stale evidence out of release/evidence or re-record it with --overwrite for the accepted release commit before assembling acceptance",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("recordability stdout = %q, want %q", stdout.String(), want)
		}
	}
}

func TestStatusCommandRecordabilityAllowsDirtyReleaseArtifactPaths(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	writeRepoFile(t, repo, "release/evidence/notes.json", `{"operator":"release"}`+"\n")
	writeRepoFile(t, repo, "release/field-evidence/m3/show-bgp-summary.txt", "redacted bgp summary\n")
	writeRepoFile(t, repo, "perf/release-results/run-1/summary.json", `{"publishable":true}`+"\n")
	var stdout bytes.Buffer

	if err := runWithIO([]string{
		"status",
		"--manifest", filepath.Join(repo, "release", "acceptance.json"),
		"--evidence-dir", filepath.Join(repo, "release", "evidence"),
		"--commit", commit,
		"--recordability",
	}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("runWithIO(status --recordability) error = %v", err)
	}
	for _, want := range []string{
		"recordability: ready",
		"allowed_dirty_paths: perf/release-results, release/evidence, release/field-evidence",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("status stdout = %q, want %q", stdout.String(), want)
		}
	}
	if strings.Contains(stdout.String(), "dirty_source_paths:") {
		t.Fatalf("status stdout = %q, want no dirty source paths", stdout.String())
	}
}

func TestStatusCommandRecordabilityRejectsJSON(t *testing.T) {
	err := runWithIO([]string{
		"status",
		"--json",
		"--recordability",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined with --json") {
		t.Fatalf("runWithIO(status --json --recordability) error = %v, want json incompatibility", err)
	}
}

func TestRecordCommandCreatesEvidenceArtifact(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	evidenceDir := filepath.Join(repo, "release", "evidence")
	installFakeMakeTargets(t, map[string]fakeMakeTarget{
		"proto-verify": {stdout: evidenceStdoutForCheck("proto-verify"), stderr: "helper stderr ok\n"},
	})
	var stdout bytes.Buffer

	err := runWithIO([]string{
		"record",
		"--evidence-dir", evidenceDir,
		"--check", "proto-verify",
		"--commit", commit,
		"--detail", "local rootless gate",
		"--",
		"make", "proto-verify",
	}, &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("runWithIO(record) error = %v", err)
	}
	if !strings.Contains(stdout.String(), "recorded release evidence") {
		t.Fatalf("record stdout = %q, want success message", stdout.String())
	}

	path := filepath.Join(evidenceDir, "proto-verify.txt")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	var rec evidenceRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("unmarshal evidence record: %v", err)
	}
	if rec.SchemaVersion != releaseacceptance.EvidenceSchemaVersion || rec.Check != "proto-verify" || rec.Commit != commit || rec.ExitCode != 0 {
		t.Fatalf("evidence record = %+v, want schema/check/exit", rec)
	}
	if rec.Detail != "local rootless gate" {
		t.Fatalf("detail = %q, want local rootless gate", rec.Detail)
	}
	if !strings.Contains(rec.Stdout, "buf lint") || !strings.Contains(rec.Stderr, "helper stderr ok") {
		t.Fatalf("evidence stdout/stderr = %q/%q, want helper output", rec.Stdout, rec.Stderr)
	}
	if len(rec.Command) == 0 {
		t.Fatalf("recorded command is empty: %+v", rec)
	}
}

func TestRecordContentPackageEvidenceAddsDemoOnlyReadiness(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	evidenceDir := filepath.Join(repo, "release", "evidence")
	installFakeMake(t, releaseacceptance.ContentPackageSmokeSentinel+"\n")
	var stdout bytes.Buffer

	err := runWithIO([]string{
		"record",
		"--evidence-dir", evidenceDir,
		"--check", releaseacceptance.ContentPackageCheckName,
		"--commit", commit,
		"--detail", releaseacceptance.ContentPackageDemoRecordDetail,
		"--",
		"make", "content-package-smoke",
	}, &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("runWithIO(record content package) error = %v", err)
	}
	if !strings.Contains(stdout.String(), "recorded release evidence") {
		t.Fatalf("record stdout = %q, want success message", stdout.String())
	}

	path := filepath.Join(evidenceDir, releaseacceptance.ContentPackageCheckName+".txt")
	rec, err := releaseacceptance.ReadEvidenceRecordFile(path)
	if err != nil {
		t.Fatalf("read evidence record: %v", err)
	}
	if rec.ContentReadiness == nil {
		t.Fatalf("content_readiness missing in %+v", rec)
	}
	if rec.ContentReadiness.Scope != releaseacceptance.ContentPackageDemoScope ||
		rec.ContentReadiness.ProductionContent ||
		rec.ContentReadiness.ProductionReady ||
		!rec.ContentReadiness.MechanicsVerified {
		t.Fatalf("content_readiness = %+v, want demo-only non-production mechanics evidence", rec.ContentReadiness)
	}
	if !strings.Contains(rec.Stdout, releaseacceptance.ContentPackageSmokeSentinel) {
		t.Fatalf("stdout = %q, want smoke sentinel", rec.Stdout)
	}
}

func TestRecordCommandRefusesOverwriteByDefault(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	evidenceDir := filepath.Join(repo, "release", "evidence")
	installFakeMakeTargets(t, map[string]fakeMakeTarget{
		"proto-verify": {stdout: evidenceStdoutForCheck("proto-verify")},
	})
	writeFile(t, filepath.Join(evidenceDir, "proto-verify.txt"), []byte("existing\n"))

	err := runWithIO([]string{
		"record",
		"--evidence-dir", evidenceDir,
		"--check", "proto-verify",
		"--commit", commit,
		"--",
		"make", "proto-verify",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite existing evidence artifact") {
		t.Fatalf("runWithIO(record existing) error = %v, want overwrite refusal", err)
	}
}

func TestRecordCommandRejectsUnknownCheckAndMissingCommand(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)

	if err := runWithIO([]string{"record", "--check", "future-check", "--", "true"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "not one of required release checks") {
		t.Fatalf("runWithIO(record bad check) error = %v, want check rejection", err)
	}
	if err := runWithIO([]string{"record", "--check", "proto-verify", "--commit", commit}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "requires a command") {
		t.Fatalf("runWithIO(record missing command) error = %v, want command rejection", err)
	}
}

func TestRecordCommandRejectsUnapprovedCommandBeforeRunning(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	evidenceDir := filepath.Join(repo, "release", "evidence")
	helperMarker := filepath.Join(t.TempDir(), "helper-ran")

	err := runWithIO(append([]string{
		"record",
		"--evidence-dir", evidenceDir,
		"--check", "proto-verify",
		"--commit", commit,
		"--",
	}, helperCommand("touch", helperMarker)...), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "not an approved release evidence command") {
		t.Fatalf("runWithIO(record unapproved command) error = %v, want approved command rejection", err)
	}
	if _, statErr := os.Stat(helperMarker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("helper marker stat after unapproved command rejection = %v, want not exist", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(evidenceDir, "proto-verify.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("evidence stat after unapproved command rejection = %v, want not exist", statErr)
	}
}

func TestRecordCommandRejectsUnredactedDetailBeforeRunning(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	evidenceDir := filepath.Join(repo, "release", "evidence")
	helperMarker := filepath.Join(t.TempDir(), "helper-ran")
	installFakeMakeTargets(t, map[string]fakeMakeTarget{
		"proto-verify": {stdout: evidenceStdoutForCheck("proto-verify"), writePath: helperMarker, writeBody: "ran\n"},
	})

	err := runWithIO([]string{
		"record",
		"--evidence-dir", evidenceDir,
		"--check", "proto-verify",
		"--commit", commit,
		"--detail", "operator api_key=abcdefghijklmnopqrstuvwxyz123456",
		"--",
		"make", "proto-verify",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil ||
		!strings.Contains(err.Error(), "record proto-verify evidence rejected") ||
		!strings.Contains(err.Error(), "proto-verify evidence detail contains unredacted OAuth/API token") ||
		!strings.Contains(err.Error(), "passing evidence was not written") {
		t.Fatalf("runWithIO(record unredacted detail) error = %v, want detail redaction rejection", err)
	}
	if _, statErr := os.Stat(helperMarker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("helper marker stat after detail rejection = %v, want not exist", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(evidenceDir, "proto-verify.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("evidence stat after detail rejection = %v, want not exist", statErr)
	}
}

func TestRecordCommandFailureDoesNotWritePassingEvidence(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	evidenceDir := filepath.Join(repo, "release", "evidence")
	installFakeMakeTargets(t, map[string]fakeMakeTarget{
		"proto-verify": {stderr: "helper stderr fail\n", exitCode: 17},
	})

	err := runWithIO([]string{
		"record",
		"--evidence-dir", evidenceDir,
		"--check", "proto-verify",
		"--commit", commit,
		"--",
		"make", "proto-verify",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "passing evidence was not written") {
		t.Fatalf("runWithIO(record fail) error = %v, want command failure", err)
	}
	if _, statErr := os.Stat(filepath.Join(evidenceDir, "proto-verify.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("evidence stat after failed command = %v, want not exist", statErr)
	}
}

func TestRecordCommandFailureRedactsSecretStderr(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	evidenceDir := filepath.Join(repo, "release", "evidence")
	installFakeMakeTargets(t, map[string]fakeMakeTarget{
		"proto-verify": {stderr: "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456\n", exitCode: 17},
	})

	err := runWithIO([]string{
		"record",
		"--evidence-dir", evidenceDir,
		"--check", "proto-verify",
		"--commit", commit,
		"--",
		"make", "proto-verify",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "stderr: [redacted]") || strings.Contains(err.Error(), "abcdefghijklmnopqrstuvwxyz123456") {
		t.Fatalf("runWithIO(record fail secret stderr) error = %v, want redacted command failure", err)
	}
	if _, statErr := os.Stat(filepath.Join(evidenceDir, "proto-verify.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("evidence stat after failed command = %v, want not exist", statErr)
	}
}

func TestRecordCommandRejectsStaleStdoutBeforeWritingEvidence(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	evidenceDir := filepath.Join(repo, "release", "evidence")
	installFakeMakeTargets(t, map[string]fakeMakeTarget{
		"e2e-install": {stdout: "check=e2e-install\nmode=check\ninstall_smoke_scope=static-preflight\nrun_requires=linux-root,systemd,network-namespaces,nftables,ip-forwarding\ninstall smoke static preflight complete\nstatus=passed\n"},
	})

	err := runWithIO([]string{
		"record",
		"--evidence-dir", evidenceDir,
		"--check", "e2e-install",
		"--commit", commit,
		"--",
		"make", "e2e-install",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil ||
		!strings.Contains(err.Error(), "record e2e-install evidence rejected") ||
		!strings.Contains(err.Error(), `e2e-install evidence stdout must include "mode=run"`) ||
		!strings.Contains(err.Error(), "passing evidence was not written") {
		t.Fatalf("runWithIO(record stale stdout) error = %v, want stale stdout rejection", err)
	}
	if _, statErr := os.Stat(filepath.Join(evidenceDir, "e2e-install.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("evidence stat after stale stdout = %v, want not exist", statErr)
	}
}

func TestRecordCommandRejectsUnredactedEvidenceOutputBeforeWritingEvidence(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	evidenceDir := filepath.Join(repo, "release", "evidence")
	installFakeMakeTargets(t, map[string]fakeMakeTarget{
		"e2e-install": {stdout: evidenceStdoutForCheck("e2e-install") + "collector=https://operator:secretpass@fw.example/status\n"},
	})

	err := runWithIO([]string{
		"record",
		"--evidence-dir", evidenceDir,
		"--check", "e2e-install",
		"--commit", commit,
		"--",
		"make", "e2e-install",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil ||
		!strings.Contains(err.Error(), "record e2e-install evidence rejected") ||
		!strings.Contains(err.Error(), "e2e-install evidence stdout contains unredacted URL credentials") ||
		!strings.Contains(err.Error(), "passing evidence was not written") {
		t.Fatalf("runWithIO(record unredacted output) error = %v, want redaction rejection", err)
	}
	if _, statErr := os.Stat(filepath.Join(evidenceDir, "e2e-install.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("evidence stat after unredacted output = %v, want not exist", statErr)
	}
}

func TestRecordCommandRejectsOIDCCodeOutputBeforeWritingEvidence(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	evidenceDir := filepath.Join(repo, "release", "evidence")
	installFakeMakeTargets(t, map[string]fakeMakeTarget{
		"m5-oidc-field-evidence-check": {stdout: evidenceStdoutForCheck(releaseacceptance.OIDCFieldEvidenceCheckName) + "code=authorizationcode12345\n"},
	})

	err := runWithIO([]string{
		"record",
		"--evidence-dir", evidenceDir,
		"--check", releaseacceptance.OIDCFieldEvidenceCheckName,
		"--commit", commit,
		"--",
		"make", "m5-oidc-field-evidence-check",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil ||
		!strings.Contains(err.Error(), "record m5-oidc-field-evidence evidence rejected") ||
		!strings.Contains(err.Error(), "m5-oidc-field-evidence evidence stdout contains unredacted OIDC authorization code") ||
		!strings.Contains(err.Error(), "passing evidence was not written") {
		t.Fatalf("runWithIO(record unredacted OIDC code) error = %v, want redaction rejection", err)
	}
	if _, statErr := os.Stat(filepath.Join(evidenceDir, releaseacceptance.OIDCFieldEvidenceCheckName+".txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("evidence stat after unredacted OIDC code = %v, want not exist", statErr)
	}
}

func TestRecordCommandRejectsDirtySourceOutsideAllowedPrefixes(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	writeRepoFile(t, repo, "cmd/source.go", "package dirty\n")
	evidenceDir := filepath.Join(repo, "release", "evidence")
	helperMarker := filepath.Join(t.TempDir(), "helper-ran")
	installFakeMakeTargets(t, map[string]fakeMakeTarget{
		"proto-verify": {stdout: evidenceStdoutForCheck("proto-verify"), writePath: helperMarker, writeBody: "ran\n"},
	})

	err := runWithIO([]string{
		"record",
		"--evidence-dir", evidenceDir,
		"--check", "proto-verify",
		"--commit", commit,
		"--",
		"make", "proto-verify",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "uncommitted changes outside allowed release artifact paths") || !strings.Contains(err.Error(), "cmd/source.go") {
		t.Fatalf("runWithIO(record dirty source) error = %v, want dirty source rejection", err)
	}
	if _, statErr := os.Stat(helperMarker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("helper marker stat after pre-command rejection = %v, want not exist", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(evidenceDir, "proto-verify.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("evidence stat after dirty source rejection = %v, want not exist", statErr)
	}
}

func TestRecordCommandAllowsDirtyReleaseArtifactPaths(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	evidenceDir := filepath.Join(repo, "release", "evidence")
	writeRepoFile(t, repo, "release/evidence/notes.json", `{"operator":"release"}`+"\n")
	writeRepoFile(t, repo, "release/field-evidence/m3/show-bgp-summary.txt", "redacted bgp summary\n")
	writeRepoFile(t, repo, "perf/release-results/run-1/summary.json", `{"publishable":true}`+"\n")
	installFakeMakeTargets(t, map[string]fakeMakeTarget{
		"proto-verify": {stdout: evidenceStdoutForCheck("proto-verify")},
	})

	err := runWithIO([]string{
		"record",
		"--evidence-dir", evidenceDir,
		"--check", "proto-verify",
		"--commit", commit,
		"--",
		"make", "proto-verify",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("runWithIO(record allowed dirty artifact paths) error = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(evidenceDir, "proto-verify.txt")); statErr != nil {
		t.Fatalf("evidence stat after allowed dirty artifact paths = %v, want artifact", statErr)
	}
}

func TestRecordCommandRequiresReadableGitCheckoutEvenWithExplicitCommit(t *testing.T) {
	dir := t.TempDir()
	withWorkingDir(t, dir)
	evidenceDir := filepath.Join(dir, "release", "evidence")
	helperMarker := filepath.Join(t.TempDir(), "helper-ran")
	installFakeMakeTargets(t, map[string]fakeMakeTarget{
		"proto-verify": {stdout: evidenceStdoutForCheck("proto-verify"), writePath: helperMarker, writeBody: "ran\n"},
	})

	err := runWithIO([]string{
		"record",
		"--evidence-dir", evidenceDir,
		"--check", "proto-verify",
		"--commit", testReleaseCommit,
		"--",
		"make", "proto-verify",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "requires a readable git checkout") {
		t.Fatalf("runWithIO(record outside git) error = %v, want readable git checkout failure", err)
	}
	if _, statErr := os.Stat(helperMarker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("helper marker stat outside git = %v, want not exist", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(evidenceDir, "proto-verify.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("evidence stat outside git = %v, want not exist", statErr)
	}
}

func TestRecordCommandRejectsCommitThatDoesNotMatchHEAD(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	head := gitHead(t, repo)
	wrongCommit := strings.Repeat("a", 40)
	if wrongCommit == head {
		wrongCommit = strings.Repeat("b", 40)
	}
	evidenceDir := filepath.Join(repo, "release", "evidence")
	helperMarker := filepath.Join(t.TempDir(), "helper-ran")
	installFakeMakeTargets(t, map[string]fakeMakeTarget{
		"proto-verify": {stdout: evidenceStdoutForCheck("proto-verify"), writePath: helperMarker, writeBody: "ran\n"},
	})

	err := runWithIO([]string{
		"record",
		"--evidence-dir", evidenceDir,
		"--check", "proto-verify",
		"--commit", wrongCommit,
		"--",
		"make", "proto-verify",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "does not match git HEAD") {
		t.Fatalf("runWithIO(record commit mismatch) error = %v, want commit mismatch failure", err)
	}
	if _, statErr := os.Stat(helperMarker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("helper marker stat after commit mismatch = %v, want not exist", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(evidenceDir, "proto-verify.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("evidence stat after commit mismatch = %v, want not exist", statErr)
	}
}

func TestRecordCommandRejectsEvidenceDirOutsideReleaseEvidence(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	evidenceDir := filepath.Join(repo, "release", "other-evidence")
	helperMarker := filepath.Join(t.TempDir(), "helper-ran")
	installFakeMakeTargets(t, map[string]fakeMakeTarget{
		"proto-verify": {stdout: evidenceStdoutForCheck("proto-verify"), writePath: helperMarker, writeBody: "ran\n"},
	})

	err := runWithIO([]string{
		"record",
		"--evidence-dir", evidenceDir,
		"--check", "proto-verify",
		"--commit", commit,
		"--",
		"make", "proto-verify",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "must resolve inside release/evidence") {
		t.Fatalf("runWithIO(record evidence dir outside release/evidence) error = %v, want evidence-dir rejection", err)
	}
	if _, statErr := os.Stat(helperMarker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("helper marker stat after evidence-dir rejection = %v, want not exist", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(evidenceDir, "proto-verify.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("evidence stat after evidence-dir rejection = %v, want not exist", statErr)
	}
}

func TestRecordCommandRejectsRenameFromSourceIntoAllowedEvidencePath(t *testing.T) {
	repo := newCleanGitRepo(t)
	writeRepoFile(t, repo, "cmd/source.go", "package source\n")
	runGit(t, repo, "add", "cmd/source.go")
	runGit(t, repo, "commit", "-m", "add source")
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	evidenceDir := filepath.Join(repo, "release", "evidence")
	if err := os.MkdirAll(evidenceDir, 0o755); err != nil {
		t.Fatalf("mkdir evidence dir: %v", err)
	}
	runGit(t, repo, "mv", "cmd/source.go", "release/evidence/source.go")
	helperMarker := filepath.Join(t.TempDir(), "helper-ran")
	installFakeMakeTargets(t, map[string]fakeMakeTarget{
		"proto-verify": {stdout: evidenceStdoutForCheck("proto-verify"), writePath: helperMarker, writeBody: "ran\n"},
	})

	err := runWithIO([]string{
		"record",
		"--evidence-dir", evidenceDir,
		"--check", "proto-verify",
		"--commit", commit,
		"--",
		"make", "proto-verify",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "cmd/source.go") {
		t.Fatalf("runWithIO(record renamed source into evidence) error = %v, want source path rejection", err)
	}
	if _, statErr := os.Stat(helperMarker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("helper marker stat after rename rejection = %v, want not exist", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(evidenceDir, "proto-verify.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("evidence stat after rename rejection = %v, want not exist", statErr)
	}
}

func TestRecordCommandRejectsCommandCreatedDirtySourceBeforeWritingEvidence(t *testing.T) {
	repo := newCleanGitRepo(t)
	withWorkingDir(t, repo)
	commit := gitHead(t, repo)
	evidenceDir := filepath.Join(repo, "release", "evidence")
	dirtyPath := filepath.Join(repo, "cmd", "generated.go")
	installFakeMakeTargets(t, map[string]fakeMakeTarget{
		"proto-verify": {stdout: evidenceStdoutForCheck("proto-verify"), writePath: "cmd/generated.go", writeBody: "package generated\n"},
	})

	err := runWithIO([]string{
		"record",
		"--evidence-dir", evidenceDir,
		"--check", "proto-verify",
		"--commit", commit,
		"--",
		"make", "proto-verify",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "cmd/generated.go") {
		t.Fatalf("runWithIO(record command-created dirty source) error = %v, want generated source rejection", err)
	}
	if _, statErr := os.Stat(dirtyPath); statErr != nil {
		t.Fatalf("command-created dirty source stat = %v, want file to prove command ran", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(evidenceDir, "proto-verify.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("evidence stat after command-created dirty source = %v, want not exist", statErr)
	}
}

func TestRecordDirtyPathAllowedMatchesExactPathOrDescendant(t *testing.T) {
	allowed := []string{"release/evidence"}
	for _, path := range []string{"release/evidence", "release/evidence/proto-verify.txt"} {
		if !recordDirtyPathAllowed(path, allowed) {
			t.Fatalf("recordDirtyPathAllowed(%q) = false, want true", path)
		}
	}
	for _, path := range []string{"release/evidence-old", "release/evidence-old/proto-verify.txt", "release"} {
		if recordDirtyPathAllowed(path, allowed) {
			t.Fatalf("recordDirtyPathAllowed(%q) = true, want false", path)
		}
	}
}

func TestLimitStringsAddsRemainder(t *testing.T) {
	got := limitStrings([]string{"a", "b", "c"}, 2)
	want := []string{"a", "b", "...and 1 more"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("limitStrings() = %v, want %v", got, want)
	}
}

func helperCommand(mode string, args ...string) []string {
	cmd := []string{os.Args[0], "-test.run=TestRecordHelperProcess", "--", mode}
	return append(cmd, args...)
}

func newCleanGitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found")
	}
	repo := t.TempDir()
	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.email", "test@example.com")
	runGit(t, repo, "config", "user.name", "Test User")
	runGit(t, repo, "config", "commit.gpgsign", "false")
	writeRepoFile(t, repo, "README.md", "test repo\n")
	runGit(t, repo, "add", "README.md")
	runGit(t, repo, "commit", "-m", "initial")
	return repo
}

func gitHead(t *testing.T, repo string) string {
	t.Helper()
	return normalizeCommit(runGit(t, repo, "rev-parse", "HEAD"))
}

func runGit(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, string(raw))
	}
	return string(raw)
}

func withWorkingDir(t *testing.T, dir string) {
	t.Helper()
	workingDirMu.Lock()
	old, err := os.Getwd()
	if err != nil {
		workingDirMu.Unlock()
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		workingDirMu.Unlock()
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() {
		defer workingDirMu.Unlock()
		if err := os.Chdir(old); err != nil {
			t.Fatalf("restore cwd %s: %v", old, err)
		}
	})
}

func writeRepoFile(t *testing.T, repo, rel, body string) {
	t.Helper()
	writeFile(t, filepath.Join(repo, filepath.FromSlash(rel)), []byte(body))
}

type fakeMakeTarget struct {
	stdout    string
	stderr    string
	exitCode  int
	writePath string
	writeBody string
}

func installFakeMake(t *testing.T, stdout string) {
	t.Helper()
	installFakeMakeTargets(t, map[string]fakeMakeTarget{
		"content-package-smoke": {stdout: stdout},
	})
}

func installFakeMakeTargets(t *testing.T, targets map[string]fakeMakeTarget) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bin")
	path := filepath.Join(dir, "make")
	var script strings.Builder
	script.WriteString("#!/bin/sh\n")
	script.WriteString("set -eu\n")
	script.WriteString("case \"$1\" in\n")
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		target := targets[name]
		script.WriteString(shellSingleQuote(name) + ")\n")
		if target.writePath != "" {
			script.WriteString("mkdir -p " + shellSingleQuote(filepath.Dir(target.writePath)) + "\n")
			script.WriteString("printf '%s' " + shellSingleQuote(target.writeBody) + " > " + shellSingleQuote(target.writePath) + "\n")
		}
		if target.stdout != "" {
			script.WriteString("printf '%s' " + shellSingleQuote(target.stdout) + "\n")
		}
		if target.stderr != "" {
			script.WriteString("printf '%s' " + shellSingleQuote(target.stderr) + " >&2\n")
		}
		_, _ = fmt.Fprintf(&script, "exit %d\n", target.exitCode)
		script.WriteString(";;\n")
	}
	script.WriteString("*) echo unexpected make target: \"$1\" >&2; exit 2;;\n")
	script.WriteString("esac\n")
	writeFile(t, path, []byte(script.String()))
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatalf("chmod fake make: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func TestRecordHelperProcess(_ *testing.T) {
	idx := -1
	for i, arg := range os.Args {
		if arg == "--" {
			idx = i
			break
		}
	}
	if idx == -1 || idx+1 >= len(os.Args) {
		return
	}
	switch os.Args[idx+1] {
	case "ok":
		_, _ = fmt.Fprintln(os.Stdout, "helper stdout ok")
		fmt.Fprintln(os.Stderr, "helper stderr ok")
		os.Exit(0)
	case "touch":
		if idx+2 >= len(os.Args) {
			fmt.Fprintln(os.Stderr, "touch helper requires a path")
			os.Exit(2)
		}
		path := os.Args[idx+2]
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "mkdir touch helper dir: %v\n", err)
			os.Exit(2)
		}
		if err := os.WriteFile(path, []byte("ran\n"), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "write touch helper path: %v\n", err)
			os.Exit(2)
		}
		_, _ = fmt.Fprintln(os.Stdout, "helper stdout touch")
		os.Exit(0)
	case "write-repo-file":
		if idx+2 >= len(os.Args) {
			fmt.Fprintln(os.Stderr, "write-repo-file helper requires a repo-relative path")
			os.Exit(2)
		}
		path := filepath.Clean(os.Args[idx+2])
		if filepath.IsAbs(path) {
			fmt.Fprintln(os.Stderr, "write-repo-file helper path must be relative")
			os.Exit(2)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "mkdir write-repo-file helper dir: %v\n", err)
			os.Exit(2)
		}
		if err := os.WriteFile(path, []byte("package generated\n"), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "write repo file helper path: %v\n", err)
			os.Exit(2)
		}
		_, _ = fmt.Fprintln(os.Stdout, "helper stdout write-repo-file")
		os.Exit(0)
	case "fail":
		fmt.Fprintln(os.Stderr, "helper stderr fail")
		os.Exit(17)
	default:
		fmt.Fprintln(os.Stderr, "unknown helper mode")
		os.Exit(2)
	}
}

func TestTemplateCommandPrintsManifestThatFailsVerification(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := runWithIO([]string{"template"}, &stdout, &stderr); err != nil {
		t.Fatalf("runWithIO(template) error = %v", err)
	}
	if !strings.Contains(stderr.String(), "template only: verifier rejects") {
		t.Fatalf("template stderr = %q, want rejection guidance", stderr.String())
	}

	dir := t.TempDir()
	manifest := filepath.Join(dir, "acceptance.json")
	if err := os.WriteFile(manifest, stdout.Bytes(), 0o600); err != nil {
		t.Fatalf("write generated template: %v", err)
	}

	var m acceptanceManifest
	if err := json.Unmarshal(stdout.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal generated template: %v", err)
	}
	if m.SchemaVersion == releaseacceptance.AcceptanceSchemaVersion {
		t.Fatalf("template schema_version = %q, want non-verifiable template schema", m.SchemaVersion)
	}
	if len(m.Checks) != len(releaseacceptance.RequiredChecks()) {
		t.Fatalf("template checks len = %d, want %d", len(m.Checks), len(releaseacceptance.RequiredChecks()))
	}
	for _, check := range m.Checks {
		if check.Status != "todo" {
			t.Fatalf("template check %q status = %q, want todo", check.Name, check.Status)
		}
	}
	for _, tt := range []struct {
		check string
		want  string
	}{
		{releaseacceptance.ContentProductionReadinessCheckName, "release-evidence-content-production-readiness"},
		{releaseacceptance.ContentProductionReadinessCheckName, "content-production/<kind>/status.json"},
		{"m3-field-evidence", "release-evidence-m3-field-evidence"},
		{"ebpf-ol9-field-evidence", "release-evidence-ebpf-ol9-field-evidence"},
		{releaseacceptance.OIDCFieldEvidenceCheckName, "release-evidence-m5-oidc-field-evidence"},
		{releaseacceptance.SAMLFieldEvidenceCheckName, "release-evidence-m5-saml-field-evidence"},
	} {
		if detail := checkByName(t, &m, tt.check).Detail; !strings.Contains(detail, tt.want) {
			t.Fatalf("template detail for %s = %q, want %q", tt.check, detail, tt.want)
		}
	}

	err := verifyAcceptance(verifyOptions{ManifestPath: manifest})
	if err == nil {
		t.Fatal("verifyAcceptance(generated template) error = nil, want failure")
	}
	for _, want := range []string{
		"schema_version must be",
		"generated_at must be RFC3339",
		"proto-verify status must be passed",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("verifyAcceptance(generated template) error = %v, want %q", err, want)
		}
	}
}

func TestTemplateCommandWritesWithoutOverwriting(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "acceptance.template.json")
	var stderr bytes.Buffer

	if err := runWithIO([]string{"template", "--output", manifest}, &bytes.Buffer{}, &stderr); err != nil {
		t.Fatalf("runWithIO(template --output) error = %v", err)
	}
	if !strings.Contains(stderr.String(), "wrote non-passing release acceptance template") {
		t.Fatalf("template stderr = %q, want write guidance", stderr.String())
	}

	err := runWithIO([]string{"template", "--output", manifest}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("runWithIO(template --output existing) error = %v, want overwrite refusal", err)
	}
}

func TestAssembleCommandCreatesVerifiedManifest(t *testing.T) {
	dir := t.TempDir()
	writeReleaseEvidenceSet(t, dir, true)
	summary := writePublishableBenchmarkSummary(t, dir)
	manifest := filepath.Join(dir, "release", "acceptance.json")
	var stdout bytes.Buffer

	err := runWithIO([]string{
		"assemble",
		"--manifest", manifest,
		"--version", testReleaseVersion,
		"--commit", testReleaseCommit,
		"--operator", "release@example.com",
		"--evidence-dir", filepath.Join(dir, "release", "evidence"),
		"--benchmark-summary", summary,
	}, &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("runWithIO(assemble) error = %v", err)
	}
	if !strings.Contains(stdout.String(), "assembled release acceptance manifest") {
		t.Fatalf("assemble stdout = %q, want success message", stdout.String())
	}

	var m acceptanceManifest
	readManifestJSON(t, manifest, &m)
	if m.Commit != testReleaseCommit {
		t.Fatalf("assembled commit = %q, want %q", m.Commit, testReleaseCommit)
	}
	if m.NoPerformanceClaims {
		t.Fatal("assembled no_performance_claims = true, want false")
	}
	contentCheck := checkByName(t, &m, releaseacceptance.ContentPackageCheckName)
	if !strings.Contains(contentCheck.Detail, "demo-only") || !strings.Contains(contentCheck.Detail, "does not certify production") {
		t.Fatalf("content-package detail = %q, want demo-only production boundary", contentCheck.Detail)
	}
	for _, check := range m.Checks {
		if check.Name == "release-benchmark" && check.BenchmarkSummary != summary {
			t.Fatalf("release-benchmark summary = %q, want %q", check.BenchmarkSummary, summary)
		}
		if check.Status != "passed" {
			t.Fatalf("check %s status = %q, want passed", check.Name, check.Status)
		}
		if !strings.HasPrefix(check.Artifact, "evidence/") {
			t.Fatalf("check %s artifact = %q, want evidence/ path", check.Name, check.Artifact)
		}
	}
	if err := verifyAcceptance(verifyOptions{
		ManifestPath:    manifest,
		ExpectedCommit:  testReleaseCommit,
		ExpectedVersion: testReleaseVersion,
	}); err != nil {
		t.Fatalf("verify assembled manifest: %v", err)
	}
}

func TestAssembleCommandRefusesOverwriteByDefault(t *testing.T) {
	dir := t.TempDir()
	writeReleaseEvidenceSet(t, dir, true)
	summary := writePublishableBenchmarkSummary(t, dir)
	manifest := filepath.Join(dir, "release", "acceptance.json")
	writeFile(t, manifest, []byte("{}\n"))

	err := runWithIO([]string{
		"assemble",
		"--manifest", manifest,
		"--version", testReleaseVersion,
		"--commit", testReleaseCommit,
		"--operator", "release@example.com",
		"--evidence-dir", filepath.Join(dir, "release", "evidence"),
		"--benchmark-summary", summary,
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite existing manifest") {
		t.Fatalf("runWithIO(assemble existing) error = %v, want overwrite refusal", err)
	}
}

func TestAssembleCommandRejectsMissingEvidenceBeforeWrite(t *testing.T) {
	dir := t.TempDir()
	writeReleaseEvidenceSet(t, dir, true)
	summary := writePublishableBenchmarkSummary(t, dir)
	manifest := filepath.Join(dir, "release", "acceptance.json")
	if err := os.Remove(filepath.Join(dir, "release", "evidence", "m5-auth-ui.txt")); err != nil {
		t.Fatalf("remove evidence: %v", err)
	}

	err := runWithIO([]string{
		"assemble",
		"--manifest", manifest,
		"--version", testReleaseVersion,
		"--commit", testReleaseCommit,
		"--operator", "release@example.com",
		"--evidence-dir", filepath.Join(dir, "release", "evidence"),
		"--benchmark-summary", summary,
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "m5-auth-ui evidence artifact") {
		t.Fatalf("runWithIO(assemble missing evidence) error = %v, want missing evidence refusal", err)
	}
	if _, statErr := os.Stat(manifest); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("manifest stat after failed assemble = %v, want not exist", statErr)
	}
}

func TestAssembleCommandAllowsFunctionalHardeningDeferred(t *testing.T) {
	dir := t.TempDir()
	writeReleaseEvidenceSet(t, dir, true)
	for _, name := range hardeningDeferredCheckNames() {
		if err := os.Remove(filepath.Join(dir, "release", "evidence", name+".txt")); err != nil {
			t.Fatalf("remove deferred evidence %s: %v", name, err)
		}
	}
	summary := writePublishableBenchmarkSummary(t, dir)
	manifest := filepath.Join(dir, "release", "acceptance.json")

	err := runWithIO([]string{
		"assemble",
		"--manifest", manifest,
		"--version", testReleaseVersion,
		"--commit", testReleaseCommit,
		"--operator", "release@example.com",
		"--evidence-dir", filepath.Join(dir, "release", "evidence"),
		"--benchmark-summary", summary,
		"--functional-hardening-deferred",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("runWithIO(assemble --functional-hardening-deferred) error = %v", err)
	}

	var m acceptanceManifest
	readManifestJSON(t, manifest, &m)
	for _, name := range hardeningDeferredCheckNames() {
		check := checkByName(t, &m, name)
		if check.Status != "hardening_deferred" {
			t.Fatalf("%s status = %q, want hardening_deferred", name, check.Status)
		}
		if check.RanAt == "" || check.Detail != releaseacceptance.HardeningDeferredDetail(name) {
			t.Fatalf("%s deferred metadata = ran_at %q detail %q, want functional deferral detail", name, check.RanAt, check.Detail)
		}
		if check.Artifact != "" || check.ArtifactSHA256 != "" || check.BenchmarkSummary != "" {
			t.Fatalf("%s deferred check should not reference evidence: %+v", name, *check)
		}
	}
	err = verifyAcceptance(verifyOptions{
		ManifestPath:    manifest,
		ExpectedCommit:  testReleaseCommit,
		ExpectedVersion: testReleaseVersion,
	})
	if err == nil || !strings.Contains(err.Error(), "hardening_deferred") {
		t.Fatalf("verifyAcceptance(strict deferred manifest) error = %v, want production verifier rejection", err)
	}
}

func TestAssembleCommandFunctionalRejectsOtherMissingEvidence(t *testing.T) {
	dir := t.TempDir()
	writeReleaseEvidenceSet(t, dir, true)
	if err := os.Remove(filepath.Join(dir, "release", "evidence", "proto-verify.txt")); err != nil {
		t.Fatalf("remove proto evidence: %v", err)
	}
	summary := writePublishableBenchmarkSummary(t, dir)
	manifest := filepath.Join(dir, "release", "acceptance.json")

	err := runWithIO([]string{
		"assemble",
		"--manifest", manifest,
		"--version", testReleaseVersion,
		"--commit", testReleaseCommit,
		"--operator", "release@example.com",
		"--evidence-dir", filepath.Join(dir, "release", "evidence"),
		"--benchmark-summary", summary,
		"--functional-hardening-deferred",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "proto-verify evidence artifact") {
		t.Fatalf("runWithIO(assemble --functional-hardening-deferred missing proto) error = %v, want non-deferred missing evidence refusal", err)
	}
	if _, statErr := os.Stat(manifest); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("manifest stat after failed functional assemble = %v, want not exist", statErr)
	}
}

func TestAssembleCommandSupportsNoPerformanceClaims(t *testing.T) {
	dir := t.TempDir()
	writeReleaseEvidenceSet(t, dir, false)
	manifest := filepath.Join(dir, "release", "acceptance.json")
	detail := "This tag publishes no throughput, latency, connection-rate, or comparison claims."

	err := runWithIO([]string{
		"assemble",
		"--manifest", manifest,
		"--version", testReleaseVersion,
		"--commit", testReleaseCommit,
		"--operator", "release@example.com",
		"--evidence-dir", filepath.Join(dir, "release", "evidence"),
		"--no-performance-claims",
		"--no-performance-detail", detail,
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("runWithIO(assemble no claims) error = %v", err)
	}

	var m acceptanceManifest
	readManifestJSON(t, manifest, &m)
	if !m.NoPerformanceClaims {
		t.Fatal("assembled no_performance_claims = false, want true")
	}
	check := releaseBenchmarkCheck(t, &m)
	if check.Status != "not_applicable" || check.Detail != detail {
		t.Fatalf("release-benchmark check = %+v, want not_applicable with detail", *check)
	}
	if check.Artifact != "" || check.ArtifactSHA256 != "" || check.BenchmarkSummary != "" {
		t.Fatalf("release-benchmark no-claims check should not reference evidence: %+v", *check)
	}
	if err := verifyAcceptance(verifyOptions{
		ManifestPath:             manifest,
		ExpectedCommit:           testReleaseCommit,
		ExpectedVersion:          testReleaseVersion,
		AllowNoPerformanceClaims: true,
	}); err != nil {
		t.Fatalf("verify no-claims assembled manifest: %v", err)
	}
}

func writeAcceptanceManifest(t *testing.T, dir string, noPerformanceClaims bool) string {
	t.Helper()
	return writeManifestJSON(t, dir, validAcceptanceManifest(t, dir, noPerformanceClaims))
}

func validAcceptanceManifest(t *testing.T, dir string, noPerformanceClaims bool) acceptanceManifest {
	t.Helper()
	checks := make([]acceptanceCheck, 0, len(releaseacceptance.RequiredChecks()))
	for _, name := range releaseacceptance.RequiredChecks() {
		check := acceptanceCheck{
			Name:     name,
			Status:   "passed",
			Artifact: filepath.ToSlash(filepath.Join("evidence", name+".txt")),
			RanAt:    testReleaseTime,
		}
		if noPerformanceClaims && name == "release-benchmark" {
			check.Status = "not_applicable"
			check.Artifact = ""
			check.ArtifactSHA256 = ""
			check.BenchmarkSummary = ""
			check.Detail = "This release publishes no throughput, latency, or connection-rate claims."
		} else {
			check.ArtifactSHA256 = writeArtifact(t, dir, check.Artifact)
		}
		if name == "release-benchmark" && !noPerformanceClaims {
			check.BenchmarkSummary = writePublishableBenchmarkSummary(t, dir)
		}
		if name == releaseacceptance.ContentPackageCheckName {
			check.Detail = releaseacceptance.ContentPackageAcceptanceDetail(releaseacceptance.DemoContentReadiness())
		}
		if name == releaseacceptance.ContentProductionReadinessCheckName {
			check.Detail = releaseacceptance.ContentReadinessAcceptanceDetail(name, releaseacceptance.ProductionContentReadiness())
		}
		checks = append(checks, check)
	}
	return acceptanceManifest{
		SchemaVersion:       releaseacceptance.AcceptanceSchemaVersion,
		ReleaseVersion:      testReleaseVersion,
		Commit:              testReleaseCommit,
		GeneratedAt:         testReleaseTime,
		Operator:            "release@example.com",
		NoPerformanceClaims: noPerformanceClaims,
		Checks:              checks,
	}
}

func releaseBenchmarkCheck(t *testing.T, m *acceptanceManifest) *acceptanceCheck {
	t.Helper()
	return checkByName(t, m, "release-benchmark")
}

func hardeningDeferredCheckNames() []string {
	return []string{
		releaseacceptance.ContentProductionReadinessCheckName,
		"m3-field-evidence",
		releaseacceptance.OIDCFieldEvidenceCheckName,
		releaseacceptance.SAMLFieldEvidenceCheckName,
	}
}

func markHardeningDeferred(t *testing.T, m *acceptanceManifest, name string) {
	t.Helper()
	check := checkByName(t, m, name)
	check.Status = "hardening_deferred"
	check.Artifact = ""
	check.ArtifactSHA256 = ""
	check.BenchmarkSummary = ""
	check.RanAt = testReleaseTime
	check.Detail = releaseacceptance.HardeningDeferredDetail(name)
	if check.Detail == "" {
		check.Detail = "functional hardening-deferred acceptance for " + name
	}
}

func statusCheckByName(t *testing.T, report releaseacceptance.StatusReport, name string) releaseacceptance.CheckStatus {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("%s status missing", name)
	return releaseacceptance.CheckStatus{}
}

func checkByName(t *testing.T, m *acceptanceManifest, name string) *acceptanceCheck {
	t.Helper()
	for i := range m.Checks {
		if m.Checks[i].Name == name {
			return &m.Checks[i]
		}
	}
	t.Fatalf("%s check missing", name)
	return nil
}

func writeManifestJSON(t *testing.T, dir string, m acceptanceManifest) string {
	t.Helper()
	path := filepath.Join(dir, "acceptance.json")
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}

func readManifestJSON(t *testing.T, path string, m *acceptanceManifest) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, m); err != nil {
		t.Fatalf("unmarshal manifest %s: %v", path, err)
	}
}

func writeReleaseEvidenceSet(t *testing.T, root string, includeBenchmark bool) {
	t.Helper()
	for _, name := range releaseacceptance.RequiredChecks() {
		if name == "release-benchmark" && !includeBenchmark {
			continue
		}
		artifact := filepath.ToSlash(filepath.Join("release", "evidence", name+".txt"))
		raw := evidenceRecordJSON(t, name, commandForCheck(name), evidenceStdoutForCheck(name))
		writeFile(t, filepath.Join(root, filepath.FromSlash(artifact)), raw)
	}
}

func writeArtifact(t *testing.T, dir, artifact string) string {
	t.Helper()
	check := strings.TrimSuffix(filepath.Base(filepath.FromSlash(artifact)), ".txt")
	return writeEvidenceRecordArtifact(t, dir, artifact, check)
}

func writeEvidenceRecordArtifact(t *testing.T, dir, artifact, check string) string {
	t.Helper()
	return writeEvidenceRecordArtifactWithCommand(t, dir, artifact, check, commandForCheck(check))
}

func writeEvidenceRecordArtifactWithCommand(t *testing.T, dir, artifact, check string, command []string) string {
	t.Helper()
	return writeEvidenceRecordArtifactWithCommandAndStdout(t, dir, artifact, check, command, evidenceStdoutForCheck(check))
}

func writeEvidenceRecordArtifactWithCommandAndStdout(t *testing.T, dir, artifact, check string, command []string, stdout string) string {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(artifact))
	raw := evidenceRecordJSON(t, check, command, stdout)
	writeFile(t, path, raw)
	return artifactDigest(raw)
}

func rewriteEvidenceRecordArtifact(t *testing.T, dir, artifact string, mutate func(*evidenceRecord)) string {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(artifact))
	rec, err := releaseacceptance.ReadEvidenceRecordFile(path)
	if err != nil {
		t.Fatalf("read evidence record: %v", err)
	}
	mutate(&rec)
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatalf("marshal evidence record: %v", err)
	}
	raw = append(raw, '\n')
	writeFile(t, path, raw)
	return artifactDigest(raw)
}

func evidenceRecordJSON(t *testing.T, check string, command []string, stdout string) []byte {
	t.Helper()
	detail := check + " release evidence"
	var contentReadiness *contentReadinessEvidence
	if check == releaseacceptance.ContentPackageCheckName {
		detail = releaseacceptance.ContentPackageDemoRecordDetail
		readiness := releaseacceptance.DemoContentReadiness()
		contentReadiness = &readiness
	}
	if check == releaseacceptance.ContentProductionReadinessCheckName {
		detail = "production App-ID, Threat-ID, and intel-feed content readiness evidence"
		readiness := releaseacceptance.ProductionContentReadiness()
		contentReadiness = &readiness
	}
	rec := evidenceRecord{
		SchemaVersion:    releaseacceptance.EvidenceSchemaVersion,
		Check:            check,
		Commit:           testReleaseCommit,
		RanAt:            testReleaseTime,
		DurationMS:       100,
		CWD:              "/repo",
		Command:          command,
		Detail:           detail,
		ExitCode:         0,
		Stdout:           stdout,
		Stderr:           "",
		ContentReadiness: contentReadiness,
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatalf("marshal evidence record: %v", err)
	}
	return append(raw, '\n')
}

func evidenceStdoutForCheck(check string) string {
	fragments := releaseacceptance.RequiredStdoutFragments(check)
	if len(fragments) == 0 {
		return check + " passed\n"
	}
	return strings.Join(append(fragments, ""), "\n")
}

func commandForCheck(check string) []string {
	command := releaseacceptance.RecommendedEvidenceCommand(check)
	if len(command) == 0 {
		return []string{"unknown"}
	}
	return command
}

func artifactDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func writePublishableBenchmarkSummary(t *testing.T, root string) string {
	t.Helper()
	rel := "perf/release-results/release-good/summary.json"
	dir := filepath.Join(root, "perf", "release-results", "release-good")
	writeBenchmarkSummary(t, dir, `{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "ids-prevent-large-flow",
		"security_services": "suricata-prevent",
		"inspection_state": "fully-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 60,
		"parallel_streams": 16,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"connection_churn": {"attempts": "100"},
		"inspection_evidence": {
			"state": "ready",
			"status_captured": true,
			"inspection_state": "fully-inspected"
		},
		"host_tuning_evidence": {
			"state": "ready",
			"status_captured": true
		},
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"claim_scope": "cloud benchmark with full profile context"
	}`)
	writeFile(t, filepath.Join(dir, "iperf3.json"), []byte(`{
		"start": {
			"connecting_to": {"host": "10.0.2.20", "port": 5201},
			"test_start": {"num_streams": 16, "duration": 60}
		},
		"end": {
			"sum_received": {"bits_per_second": 1000000000},
			"sum_sent": {"bits_per_second": 1000000000, "retransmits": 0}
		}
	}`))
	writeFile(t, filepath.Join(dir, "ngfw-status.txt"), []byte("  inspection:      IPS prevent\n  inspection ready:ready\n  kernel tuning:  ready\n  state table:    ready 25/1048576 entries (0.002%)\n"))
	return rel
}

func writeRegressionOnlyBenchmarkSummary(t *testing.T, root string) string {
	t.Helper()
	rel := "perf/release-results/regression-only/summary.json"
	dir := filepath.Join(root, "perf", "release-results", "regression-only")
	writeBenchmarkSummary(t, dir, `{
		"schema_version": "phragma.perf.v1",
		"generated_at": "2026-06-17T05:00:00Z",
		"profile": "local-netns-forwarding",
		"security_services": "none",
		"inspection_state": "not-inspected",
		"target": {"ip": "10.0.2.20", "port": 5201},
		"duration_seconds": 20,
		"parallel_streams": 8,
		"tcp_bits_per_second": 1000000000,
		"tcp_gbps": 1.0,
		"tcp_retransmits": 0,
		"conntrack_evidence": {
			"state": "ready",
			"status_captured": true,
			"current_entries": 25,
			"max_entries": 1048576,
			"usage_percent": 0.002
		},
		"claim_scope": "single-host Linux network namespace benchmark; not a cloud-NIC throughput claim"
	}`)
	return rel
}

func writeBenchmarkSummary(t *testing.T, dir, summary string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, "summary.json"), []byte(summary))
}

func writeFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func injectJSONFieldAfter(t *testing.T, path, after, field string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	marker := []byte(after)
	if !bytes.Contains(raw, marker) {
		t.Fatalf("%s does not contain injection marker %q", path, after)
	}
	replacement := []byte(after + "\n  " + field)
	raw = bytes.Replace(raw, marker, replacement, 1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return raw
}
