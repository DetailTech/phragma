package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseAndCIWorkflowContractCoverage(t *testing.T) {
	root := releaseWorkflowContractRepoRoot(t)
	makefile := readReleaseWorkflowContractFile(t, filepath.Join(root, "Makefile"))
	ciWorkflow := readReleaseWorkflowContractFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"))
	releaseWorkflow := readReleaseWorkflowContractFile(t, filepath.Join(root, ".github", "workflows", "release.yml"))

	assertMakeTargetListedPhony(t, makefile, []string{
		"proto-status",
		"proto-verify",
		"webui-check",
		"webui-visual-smoke",
		"webui-enterprise-smoke",
		"privileged-integration-evidence-check",
		"e2e-auth-runtime-smoke",
		"e2e-oidc-runtime-smoke",
		"content-package-smoke",
		"ha-readiness-recovery-check",
		"benchmark-verify-release",
		"release-check-rootless",
		"release-acceptance-status",
		"release-recordability-check",
		"release-acceptance-verify",
		"release-verify",
	})

	assertReleaseWorkflowContractContainsAll(t, "proto-verify target", makeTargetBlock(t, makefile, "proto-verify"), []string{
		"proto-verify: proto",
		"git diff --exit-code --quiet -- $(API_CONTRACT_INPUTS)",
		"git diff --exit-code --quiet -- $(API_CONTRACT_OUTPUTS)",
		"git diff --cached --exit-code --quiet -- $(API_CONTRACT_INPUTS) $(API_CONTRACT_OUTPUTS)",
		"git ls-files --others --exclude-standard -- $(API_CONTRACT_INPUTS)",
		"git ls-files --others --exclude-standard -- $(API_CONTRACT_OUTPUTS)",
		"untracked API contract inputs:",
		"untracked generated API files/specs:",
	})
	assertReleaseWorkflowContractContainsAll(t, "proto-status target", makeTargetBlock(t, makefile, "proto-status"), []string{
		"API contract source/generated diff against index:",
		"staged API contract source/generated diff:",
		"untracked API contract inputs:",
		"untracked generated files/specs:",
		"OpenAPI spec copy consistency:",
	})
	assertReleaseWorkflowContractContainsAll(t, "webui-check target", makeTargetBlock(t, makefile, "webui-check"), []string{
		"node --check",
		"*.test.mjs",
		"WEBUI_CHECK_REQUIRE_NODE",
		"webui_js_checks=passed",
		"javascript_checks=required",
	})
	assertReleaseWorkflowContractContainsAll(t, "webui-visual-smoke target", makeTargetBlock(t, makefile, "webui-visual-smoke"), []string{
		"webui-visual-smoke: webui-check",
		`WEBUI_SMOKE_REQUIRE_BROWSER="$(WEBUI_SMOKE_REQUIRE_BROWSER)" node e2e/webui-visual-smoke.mjs`,
		"WebUI visual smoke requires Node.js",
		"exit 1",
	})
	assertReleaseWorkflowContractContainsAll(t, "webui-enterprise-smoke target", makeTargetBlock(t, makefile, "webui-enterprise-smoke"), []string{
		"webui-enterprise-smoke:",
		"$(MAKE) webui-check WEBUI_CHECK_REQUIRE_NODE=1",
		"release_smoke_mode=desktop-enterprise",
		"browser_required=$(WEBUI_SMOKE_REQUIRE_BROWSER)",
		"viewport_coverage=$(WEBUI_ENTERPRISE_SMOKE_VIEWPORTS)",
		`WEBUI_SMOKE_REQUIRE_BROWSER="$(WEBUI_SMOKE_REQUIRE_BROWSER)"`,
		`WEBUI_SMOKE_PATHS="$(WEBUI_ENTERPRISE_SMOKE_PATHS)"`,
		`WEBUI_SMOKE_VIEWPORTS="$(WEBUI_ENTERPRISE_SMOKE_VIEWPORTS)"`,
		`WEBUI_SMOKE_TOTAL_TIMEOUT_MS="$(WEBUI_ENTERPRISE_SMOKE_TOTAL_TIMEOUT_MS)"`,
		`WEBUI_SMOKE_ARTIFACT_DIR="$(WEBUI_ENTERPRISE_SMOKE_ARTIFACT_DIR)"`,
		"node e2e/webui-visual-smoke.mjs",
		"WebUI enterprise visual smoke requires Node.js",
	})

	assertMakeTargetDeps(t, makefile, "release-check-rootless", []string{
		"build",
		"test",
		"vet",
		"integration-compile",
		"deploy-hardening-check",
		"policy-restore-drill-check",
		"ha-readiness-recovery-check",
		"e2e-install-check",
		"content-package-smoke",
		"e2e-auth-runtime-smoke",
		"e2e-oidc-runtime-smoke",
		"webui-enterprise-smoke",
		"benchmark-verify-release",
		"benchmark-citation-check",
	})
	assertMakeTargetDeps(t, makefile, "release-verify", []string{
		"proto-verify",
		"release-check-rootless",
		"release-acceptance-verify",
		"release-recordability-check",
	})
	assertReleaseWorkflowContractContainsAll(t, "release-evidence-m5-auth-ui target", makeTargetBlock(t, makefile, "release-evidence-m5-auth-ui"), []string{
		"--check m5-auth-ui",
		"make e2e-auth-runtime-smoke",
	})
	assertReleaseWorkflowContractContainsAll(t, "release-evidence-m5-oidc-provider target", makeTargetBlock(t, makefile, "release-evidence-m5-oidc-provider"), []string{
		"--check m5-oidc-provider",
		"make e2e-oidc-runtime-smoke",
	})
	assertReleaseWorkflowContractContainsAll(t, "release-evidence-webui-enterprise-smoke target", makeTargetBlock(t, makefile, "release-evidence-webui-enterprise-smoke"), []string{
		"--check webui-enterprise-smoke",
		"make webui-enterprise-smoke",
		"browser-required broad desktop WebUI enterprise smoke",
	})
	assertReleaseWorkflowContractContainsAll(t, "release-evidence-m5-saml-field-evidence target", makeTargetBlock(t, makefile, "release-evidence-m5-saml-field-evidence"), []string{
		"--check m5-saml-field-evidence",
		"make m5-saml-field-evidence-check",
	})
	assertReleaseWorkflowContractContainsAll(t, "release-evidence-ha-readiness-recovery target", makeTargetBlock(t, makefile, "release-evidence-ha-readiness-recovery"), []string{
		"--check ha-readiness-recovery",
		"make ha-readiness-recovery-check",
		"does not certify VIP/route promotion, fencing, or connection-state sync",
	})
	assertReleaseWorkflowContractContainsAll(t, "privileged-integration-evidence-check target", makeTargetBlock(t, makefile, "privileged-integration-evidence-check"), []string{
		"bash release/privileged-integration-no-skip.sh",
		"$(MAKE) integration-test",
	})
	assertReleaseWorkflowContractContainsAll(t, "release-evidence-privileged-integration target", makeTargetBlock(t, makefile, "release-evidence-privileged-integration"), []string{
		"--check privileged-integration",
		"make privileged-integration-evidence-check",
		"skipped integration tests are rejected",
	})
	assertReleaseWorkflowContractContainsAll(t, "content-package-smoke target", makeTargetBlock(t, makefile, "content-package-smoke"), []string{
		"bash e2e/content-package-smoke.sh --check",
	})
	assertReleaseWorkflowContractContainsAll(t, "benchmark-verify-release target", makeTargetBlock(t, makefile, "benchmark-verify-release"), []string{
		"go run ./cmd/ngfwperf verify --strict --publishable $(RELEASE_PERF_RESULTS)",
		"RELEASE_NO_PERFORMANCE_CLAIMS",
	})
	assertReleaseWorkflowContractContainsAll(t, "release-acceptance-status target", makeTargetBlock(t, makefile, "release-acceptance-status"), []string{
		"go run ./cmd/ngfwrelease status",
		"--recordability",
		"--allow-no-performance-claims",
	})
	assertReleaseWorkflowContractContainsAll(t, "release-recordability-check target", makeTargetBlock(t, makefile, "release-recordability-check"), []string{
		"go run ./cmd/ngfwrelease recordability",
		"--strict",
	})
	assertReleaseWorkflowContractContainsAll(t, "release-acceptance-verify target", makeTargetBlock(t, makefile, "release-acceptance-verify"), []string{
		"go run ./cmd/ngfwrelease verify",
		"--allow-no-performance-claims",
	})

	assertReleaseWorkflowContractContainsAll(t, "CI workflow release gate job", ciWorkflow, []string{
		"rootless-release-gate:",
		"WEBUI_SMOKE_REQUIRE_BROWSER: \"1\"",
		"npm install --no-save --no-package-lock \"playwright@${PLAYWRIGHT_VERSION}\"",
		"npx playwright install --with-deps chromium",
		"run: make release-check-rootless RELEASE_NO_PERFORMANCE_CLAIMS=\"${RELEASE_NO_PERFORMANCE_CLAIMS}\"",
	})
	assertReleaseWorkflowContractContainsAll(t, "CI proto verification job", ciWorkflow, []string{
		"proto-verify:",
		"run: make proto-verify",
	})

	assertReleaseWorkflowContractContainsAll(t, "release workflow gate steps", releaseWorkflow, []string{
		"WEBUI_SMOKE_REQUIRE_BROWSER: \"1\"",
		"npm install --no-save --no-package-lock \"playwright@${PLAYWRIGHT_VERSION}\"",
		"npx playwright install --with-deps chromium",
		"run: make proto-verify",
		"run: make release-check-rootless RELEASE_NO_PERFORMANCE_CLAIMS=\"${RELEASE_NO_PERFORMANCE_CLAIMS}\"",
		"run: make release-acceptance-status VERSION=\"${GITHUB_REF_NAME}\" COMMIT=\"${GITHUB_SHA}\" RELEASE_NO_PERFORMANCE_CLAIMS=\"${RELEASE_NO_PERFORMANCE_CLAIMS}\"",
		"run: make release-acceptance-verify VERSION=\"${GITHUB_REF_NAME}\" COMMIT=\"${GITHUB_SHA}\" RELEASE_NO_PERFORMANCE_CLAIMS=\"${RELEASE_NO_PERFORMANCE_CLAIMS}\"",
		"run: make release-recordability-check COMMIT=\"${GITHUB_SHA}\"",
	})
}

func releaseWorkflowContractRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	for {
		if fileExists(filepath.Join(dir, "Makefile")) && fileExists(filepath.Join(dir, ".github", "workflows", "ci.yml")) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("repository root not found from %s", dir)
		}
		dir = parent
	}
}

func readReleaseWorkflowContractFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

func assertMakeTargetListedPhony(t *testing.T, makefile string, targets []string) {
	t.Helper()
	phony := makeTargetHeader(t, makefile, ".PHONY")
	for _, target := range targets {
		if !makeHeaderHasWord(phony, target) {
			t.Fatalf(".PHONY missing %q in %q", target, phony)
		}
	}
}

func assertMakeTargetDeps(t *testing.T, makefile, target string, deps []string) {
	t.Helper()
	header := makeTargetHeader(t, makefile, target)
	for _, dep := range deps {
		if !makeHeaderHasWord(header, dep) {
			t.Fatalf("%s dependencies missing %q in %q", target, dep, header)
		}
	}
}

func assertReleaseWorkflowContractContainsAll(t *testing.T, name, body string, wants []string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Fatalf("%s missing %q", name, want)
		}
	}
}

func makeTargetHeader(t *testing.T, makefile, target string) string {
	t.Helper()
	block := makeTargetBlock(t, makefile, target)
	return strings.SplitN(block, "\n", 2)[0]
}

func makeTargetBlock(t *testing.T, makefile, target string) string {
	t.Helper()
	lines := strings.Split(makefile, "\n")
	prefix := target + ":"
	for i, line := range lines {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		var block strings.Builder
		block.WriteString(line)
		block.WriteByte('\n')
		for _, next := range lines[i+1:] {
			if next != "" && !strings.HasPrefix(next, "\t") && !strings.HasPrefix(next, " ") && !strings.HasPrefix(next, "#") && looksLikeMakeTargetHeader(next) {
				break
			}
			block.WriteString(next)
			block.WriteByte('\n')
		}
		return block.String()
	}
	t.Fatalf("Makefile target %q not found", target)
	return ""
}

func looksLikeMakeTargetHeader(line string) bool {
	if strings.Contains(line, ":=") || strings.Contains(line, "?=") || strings.Contains(line, "=") {
		return false
	}
	colon := strings.IndexByte(line, ':')
	return colon > 0 && !strings.ContainsAny(line[:colon], " \t")
}

func makeHeaderHasWord(header, word string) bool {
	for _, field := range strings.Fields(strings.TrimPrefix(header, ".PHONY:")) {
		if strings.TrimSuffix(field, ":") == word {
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
