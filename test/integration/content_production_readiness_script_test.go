//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseContentProductionReadinessAcceptsCompleteBundle(t *testing.T) {
	root := releaseRepoRoot(t)
	bundleDir := writeContentProductionReadinessBundle(t, nil)

	output, err := runContentProductionReadinessCheck(t, root, bundleDir)
	if err != nil {
		t.Fatalf("content production readiness check failed: %v\n%s", err, output)
	}

	for _, want := range []string{
		"check=content-production-readiness",
		"mode=check",
		"content_production_scope=app-id,threat-id,intel-feeds",
		"required_content_kinds=app-id,threat-id,intel-feeds",
		"required_app_id_evidence=app-taxonomy,confidence-model,app-regression-corpus,license-review,staged-rollout,rollback-drill",
		"required_threat_id_evidence=threat-taxonomy,pcap-regression-corpus,false-positive-regression,license-review,staged-rollout,rollback-drill",
		"required_intel_feeds_evidence=feed-registry,parser-tests,license-review,false-positive-regression,staged-rollout,rollback-drill",
		"content_readiness=production_content=true,production_ready=true",
		"manifest_sha256_policy=required,exact-regular-files,no-extra-files",
		"ok: manifest.sha256 verified exact file set",
		"ok: app-id production content status verified",
		"ok: threat-id production content status verified",
		"ok: intel-feeds production content status verified",
		"status=passed",
	} {
		if !hasOutputLine(output, want) {
			t.Fatalf("content production readiness output missing line %q:\n%s", want, output)
		}
	}
}

func TestReleaseContentProductionReadinessRejectsMissingKind(t *testing.T) {
	root := releaseRepoRoot(t)
	bundleDir := writeContentProductionReadinessBundle(t, nil)
	if err := os.RemoveAll(filepath.Join(bundleDir, "threat-id")); err != nil {
		t.Fatalf("remove threat-id bundle: %v", err)
	}

	output, err := runContentProductionReadinessCheck(t, root, bundleDir)
	if err == nil {
		t.Fatalf("content production readiness accepted missing kind:\n%s", output)
	}
	for _, want := range []string{
		"threat-id status directory missing",
		"status=failed",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected missing kind failure %q, got:\n%s", want, output)
		}
	}
}

func TestReleaseContentProductionReadinessRejectsDemoOrNotProductionReadyStatus(t *testing.T) {
	root := releaseRepoRoot(t)
	bundleDir := writeContentProductionReadinessBundle(t, func(kind string, status map[string]any) {
		if kind != "app-id" {
			return
		}
		readiness := status["content_readiness"].(map[string]any)
		readiness["scope"] = "demo-only"
		readiness["production_content"] = false
		readiness["production_ready"] = false
		readiness["evidence_status"] = "demo-only"
	})

	output, err := runContentProductionReadinessCheck(t, root, bundleDir)
	if err == nil {
		t.Fatalf("content production readiness accepted demo-only status:\n%s", output)
	}
	for _, want := range []string{
		`app-id content_readiness.scope = "demo-only", want production`,
		"app-id content_readiness.production_content must be true",
		"app-id content_readiness.production_ready must be true",
		"status=failed",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected demo/not-ready failure %q, got:\n%s", want, output)
		}
	}
}

func TestReleaseContentProductionReadinessRejectsMissingEvidenceArtifact(t *testing.T) {
	root := releaseRepoRoot(t)
	bundleDir := writeContentProductionReadinessBundle(t, nil)
	missing := filepath.Join(bundleDir, "intel-feeds", "evidence", "parser-tests.json")
	if err := os.Remove(missing); err != nil {
		t.Fatalf("remove evidence artifact: %v", err)
	}

	output, err := runContentProductionReadinessCheck(t, root, bundleDir)
	if err == nil {
		t.Fatalf("content production readiness accepted missing evidence:\n%s", output)
	}
	for _, want := range []string{
		"intel-feeds evidence artifact missing for parser-tests",
		"status=failed",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected missing evidence failure %q, got:\n%s", want, output)
		}
	}
}

func TestReleaseContentProductionReadinessRejectsManifestPolicyViolations(t *testing.T) {
	root := releaseRepoRoot(t)

	t.Run("missing manifest entry", func(t *testing.T) {
		bundleDir := writeContentProductionReadinessBundle(t, nil)
		writeFieldEvidenceManifest(t, bundleDir, "app-id/status.json")

		output, err := runContentProductionReadinessCheck(t, root, bundleDir)
		if err == nil {
			t.Fatalf("content production readiness accepted incomplete manifest:\n%s", output)
		}
		if !strings.Contains(output, "manifest.sha256 missing required entry: app-id/evidence/app-taxonomy.json") ||
			!strings.Contains(output, "status=failed") {
			t.Fatalf("expected missing manifest entry rejection, got:\n%s", output)
		}
	})

	t.Run("extra file", func(t *testing.T) {
		bundleDir := writeContentProductionReadinessBundle(t, nil)
		writeContentProductionJSONFile(t, filepath.Join(bundleDir, "app-id", "evidence", "operator-note.json"), map[string]any{
			"note": "not release evidence",
		})

		output, err := runContentProductionReadinessCheck(t, root, bundleDir)
		if err == nil {
			t.Fatalf("content production readiness accepted extra evidence file:\n%s", output)
		}
		if !strings.Contains(output, "evidence bundle contains unexpected file outside manifest policy: app-id/evidence/operator-note.json") ||
			!strings.Contains(output, "status=failed") {
			t.Fatalf("expected extra file rejection, got:\n%s", output)
		}
	})
}

func TestReleaseContentProductionReadinessRejectsWeakEvidenceSemantics(t *testing.T) {
	root := releaseRepoRoot(t)

	t.Run("missing evidence signature", func(t *testing.T) {
		bundleDir := writeContentProductionReadinessBundle(t, func(kind string, status map[string]any) {
			if kind != "app-id" {
				return
			}
			readiness := status["content_readiness"].(map[string]any)
			evidence := readiness["evidence"].([]map[string]any)
			delete(evidence[0], "signed")
			delete(evidence[0], "signature_status")
		})

		output, err := runContentProductionReadinessCheck(t, root, bundleDir)
		if err == nil {
			t.Fatalf("content production readiness accepted unsigned evidence:\n%s", output)
		}
		for _, want := range []string{
			"app-id evidence artifact must be signed for app-taxonomy",
			`app-id evidence signature_status = "" for app-taxonomy, want verified`,
			"status=failed",
		} {
			if !strings.Contains(output, want) {
				t.Fatalf("expected weak signature failure %q, got:\n%s", want, output)
			}
		}
	})

	t.Run("mismatched artifact evidence type", func(t *testing.T) {
		bundleDir := writeContentProductionReadinessBundle(t, nil)
		rewriteContentProductionEvidenceArtifact(t, bundleDir, "threat-id", "pcap-regression-corpus", map[string]string{
			"evidence_type": "license-review",
			"verdict":       "passed",
		})

		output, err := runContentProductionReadinessCheck(t, root, bundleDir)
		if err == nil {
			t.Fatalf("content production readiness accepted mismatched evidence type:\n%s", output)
		}
		if !strings.Contains(output, `threat-id evidence artifact evidence_type = "license-review" for pcap-regression-corpus, want pcap-regression-corpus`) ||
			!strings.Contains(output, "status=failed") {
			t.Fatalf("expected mismatched evidence type failure, got:\n%s", output)
		}
	})

	t.Run("artifact verdict not passed", func(t *testing.T) {
		bundleDir := writeContentProductionReadinessBundle(t, nil)
		rewriteContentProductionEvidenceArtifact(t, bundleDir, "intel-feeds", "parser-tests", map[string]string{
			"evidence_type": "parser-tests",
			"status":        "failed",
		})

		output, err := runContentProductionReadinessCheck(t, root, bundleDir)
		if err == nil {
			t.Fatalf("content production readiness accepted failed evidence verdict:\n%s", output)
		}
		if !strings.Contains(output, `intel-feeds evidence artifact verdict/status = "failed" for parser-tests, want passed`) ||
			!strings.Contains(output, "status=failed") {
			t.Fatalf("expected failed evidence verdict rejection, got:\n%s", output)
		}
	})

	t.Run("app regression corpus missing samples", func(t *testing.T) {
		bundleDir := writeContentProductionReadinessBundle(t, nil)
		rewriteContentProductionEvidenceArtifact(t, bundleDir, "app-id", "app-regression-corpus", map[string]any{
			"evidence_type":   "app-regression-corpus",
			"package_version": "1.2.3",
			"manifest_sha256": contentReadinessDigestHex("app-id-manifest"),
			"verdict":         "passed",
			"samples":         []map[string]any{},
		})

		output, err := runContentProductionReadinessCheck(t, root, bundleDir)
		if err == nil {
			t.Fatalf("content production readiness accepted empty App-ID regression corpus:\n%s", output)
		}
		if !strings.Contains(output, "app-id app-regression-corpus samples must be a non-empty list") ||
			!strings.Contains(output, "status=failed") {
			t.Fatalf("expected empty App-ID corpus rejection, got:\n%s", output)
		}
	})

	t.Run("app regression corpus failed sample verdict", func(t *testing.T) {
		bundleDir := writeContentProductionReadinessBundle(t, nil)
		rewriteContentProductionEvidenceArtifact(t, bundleDir, "app-id", "app-regression-corpus", map[string]any{
			"evidence_type":   "app-regression-corpus",
			"package_version": "1.2.3",
			"manifest_sha256": contentReadinessDigestHex("app-id-manifest"),
			"verdict":         "passed",
			"samples": []map[string]any{{
				"pcap_sha256":  contentReadinessDigestHex("app-id-corpus-pcap"),
				"expected_app": "corp-admin",
				"observed_app": "corp-admin",
				"verdict":      "failed",
			}},
		})

		output, err := runContentProductionReadinessCheck(t, root, bundleDir)
		if err == nil {
			t.Fatalf("content production readiness accepted failed App-ID regression sample:\n%s", output)
		}
		if !strings.Contains(output, `app-id app-regression-corpus sample[0] verdict/status = "failed", want passed`) ||
			!strings.Contains(output, "status=failed") {
			t.Fatalf("expected failed App-ID sample verdict rejection, got:\n%s", output)
		}
	})
}

func TestReleaseContentProductionReadinessRejectsSymlinkedRootOrFiles(t *testing.T) {
	root := releaseRepoRoot(t)

	t.Run("root", func(t *testing.T) {
		realBundle := writeContentProductionReadinessBundle(t, nil)
		symlinkRoot := filepath.Join(t.TempDir(), "content-readiness-link")
		if err := os.Symlink(realBundle, symlinkRoot); err != nil {
			t.Fatalf("symlink bundle root: %v", err)
		}

		output, err := runContentProductionReadinessCheck(t, root, symlinkRoot)
		if err == nil {
			t.Fatalf("content production readiness accepted symlinked root:\n%s", output)
		}
		if !strings.Contains(output, "content evidence root must not be a symlink") || !strings.Contains(output, "status=failed") {
			t.Fatalf("expected symlinked root rejection, got:\n%s", output)
		}
	})

	t.Run("file", func(t *testing.T) {
		bundleDir := writeContentProductionReadinessBundle(t, nil)
		statusPath := filepath.Join(bundleDir, "app-id", "status.json")
		statusCopy := filepath.Join(t.TempDir(), "status-copy.json")
		body, err := os.ReadFile(statusPath)
		if err != nil {
			t.Fatalf("read status: %v", err)
		}
		if err := os.WriteFile(statusCopy, body, 0o600); err != nil {
			t.Fatalf("write status copy: %v", err)
		}
		if err := os.Remove(statusPath); err != nil {
			t.Fatalf("remove status: %v", err)
		}
		if err := os.Symlink(statusCopy, statusPath); err != nil {
			t.Fatalf("symlink status file: %v", err)
		}

		output, err := runContentProductionReadinessCheck(t, root, bundleDir)
		if err == nil {
			t.Fatalf("content production readiness accepted symlinked status file:\n%s", output)
		}
		if !strings.Contains(output, "content evidence bundle must not contain symlinks") || !strings.Contains(output, "status=failed") {
			t.Fatalf("expected symlinked file rejection, got:\n%s", output)
		}
	})
}

func runContentProductionReadinessCheck(t *testing.T, root, bundleDir string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", "release/content-production-readiness.sh", "--evidence-dir", bundleDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func writeContentProductionReadinessBundle(t *testing.T, mutate func(kind string, status map[string]any)) string {
	t.Helper()
	dir := t.TempDir()
	for _, kind := range []string{"app-id", "threat-id", "intel-feeds"} {
		kindDir := filepath.Join(dir, kind)
		required := requiredProductionEvidenceForContentReadinessTest(kind)
		version := "1.2.3"
		manifestSha256 := contentReadinessDigestHex(kind + "-manifest")
		evidence := make([]map[string]any, 0, len(required))
		for _, evidenceType := range required {
			artifact := "evidence/" + evidenceType + ".json"
			hash := writeContentProductionEvidenceArtifact(t, kindDir, artifact, kind, evidenceType, version, manifestSha256)
			evidence = append(evidence, map[string]any{
				"type":             evidenceType,
				"artifact":         artifact,
				"sha256":           hash,
				"generated_at":     "2026-06-18T12:00:00Z",
				"signed":           true,
				"signature_status": "verified",
			})
		}

		status := map[string]any{
			"kind":               kind,
			"version":            version,
			"manifest_sha256":    manifestSha256,
			"state":              "verified",
			"signature_status":   "verified",
			"regression_status":  "passed",
			"provenance_status":  "verified",
			"rollout_status":     "staged",
			"rollback_available": true,
			"blockers":           []string{},
			"content_readiness": map[string]any{
				"scope":                        "production",
				"production_content":           true,
				"production_ready":             true,
				"evidence_status":              "passed",
				"required_production_evidence": required,
				"evidence":                     evidence,
				"blockers":                     []string{},
			},
		}
		if mutate != nil {
			mutate(kind, status)
		}
		writeContentProductionJSONFile(t, filepath.Join(kindDir, "status.json"), status)
	}
	writeFieldEvidenceManifest(t, dir, requiredContentProductionManifestPaths()...)
	return dir
}

func requiredContentProductionManifestPaths() []string {
	return []string{
		"app-id/status.json",
		"app-id/evidence/app-taxonomy.json",
		"app-id/evidence/confidence-model.json",
		"app-id/evidence/app-regression-corpus.json",
		"app-id/evidence/license-review.json",
		"app-id/evidence/staged-rollout.json",
		"app-id/evidence/rollback-drill.json",
		"threat-id/status.json",
		"threat-id/evidence/threat-taxonomy.json",
		"threat-id/evidence/pcap-regression-corpus.json",
		"threat-id/evidence/false-positive-regression.json",
		"threat-id/evidence/license-review.json",
		"threat-id/evidence/staged-rollout.json",
		"threat-id/evidence/rollback-drill.json",
		"intel-feeds/status.json",
		"intel-feeds/evidence/feed-registry.json",
		"intel-feeds/evidence/parser-tests.json",
		"intel-feeds/evidence/license-review.json",
		"intel-feeds/evidence/false-positive-regression.json",
		"intel-feeds/evidence/staged-rollout.json",
		"intel-feeds/evidence/rollback-drill.json",
	}
}

func requiredProductionEvidenceForContentReadinessTest(kind string) []string {
	switch kind {
	case "app-id":
		return []string{"app-taxonomy", "confidence-model", "app-regression-corpus", "license-review", "staged-rollout", "rollback-drill"}
	case "threat-id":
		return []string{"threat-taxonomy", "pcap-regression-corpus", "false-positive-regression", "license-review", "staged-rollout", "rollback-drill"}
	case "intel-feeds":
		return []string{"feed-registry", "parser-tests", "license-review", "false-positive-regression", "staged-rollout", "rollback-drill"}
	default:
		panic("unknown content kind: " + kind)
	}
}

func writeContentProductionEvidenceArtifact(t *testing.T, kindDir, artifact, kind, evidenceType, version, manifestSha256 string) string {
	t.Helper()
	payload := map[string]any{
		"evidence_type": evidenceType,
		"verdict":       "passed",
	}
	if kind == "app-id" && evidenceType == "app-regression-corpus" {
		payload["package_version"] = version
		payload["manifest_sha256"] = manifestSha256
		payload["samples"] = []map[string]any{{
			"queue_id":     "appid-queue-1",
			"pcap_sha256":  contentReadinessDigestHex("app-id-corpus-pcap"),
			"expected_app": "corp-admin",
			"observed_app": "corp-admin",
			"confidence":   97,
			"captured_at":  "2026-06-18T12:01:00Z",
			"verdict":      "passed",
		}}
	}
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal evidence artifact: %v", err)
	}
	body = append(body, '\n')
	path := filepath.Join(kindDir, filepath.FromSlash(artifact))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func rewriteContentProductionEvidenceArtifact(t *testing.T, bundleDir, kind, evidenceType string, payload any) {
	t.Helper()
	statusPath := filepath.Join(bundleDir, kind, "status.json")
	var status map[string]any
	body, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatalf("read %s: %v", statusPath, err)
	}
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatalf("unmarshal %s: %v", statusPath, err)
	}
	readiness := status["content_readiness"].(map[string]any)
	evidence := readiness["evidence"].([]any)
	for _, raw := range evidence {
		item := raw.(map[string]any)
		if item["type"] != evidenceType {
			continue
		}
		artifact := item["artifact"].(string)
		nextBody, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			t.Fatalf("marshal rewritten evidence: %v", err)
		}
		nextBody = append(nextBody, '\n')
		artifactPath := filepath.Join(bundleDir, kind, filepath.FromSlash(artifact))
		if err := os.WriteFile(artifactPath, nextBody, 0o600); err != nil {
			t.Fatalf("rewrite %s: %v", artifactPath, err)
		}
		sum := sha256.Sum256(nextBody)
		item["sha256"] = hex.EncodeToString(sum[:])
		writeContentProductionJSONFile(t, statusPath, status)
		writeFieldEvidenceManifest(t, bundleDir, requiredContentProductionManifestPaths()...)
		return
	}
	t.Fatalf("evidence type %s not found for %s", evidenceType, kind)
}

func contentReadinessDigestHex(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

func writeContentProductionJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	body = append(body, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
