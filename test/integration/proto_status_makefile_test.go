//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtoStatusReportsUntrackedContractInputs(t *testing.T) {
	root := releaseRepoRoot(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found")
	}
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make not found")
	}

	repo := t.TempDir()
	runProtoStatusTestCommand(t, repo, "git", "init")
	runProtoStatusTestCommand(t, repo, "git", "config", "user.email", "test@example.invalid")
	runProtoStatusTestCommand(t, repo, "git", "config", "user.name", "OpenNGFW Test")
	writeProtoStatusTestFile(t, filepath.Join(repo, ".gitkeep"), "")
	runProtoStatusTestCommand(t, repo, "git", "add", ".gitkeep")
	runProtoStatusTestCommand(t, repo, "git", "commit", "-m", "baseline")

	writeProtoStatusTestFile(t, filepath.Join(repo, "api/openapi.yaml"), "openapiOptions: {}\n")
	writeProtoStatusTestFile(t, filepath.Join(repo, "api/proto/openngfw/v1/app_service.proto"), "syntax = \"proto3\";\n")
	writeProtoStatusTestFile(t, filepath.Join(repo, "buf.yaml"), "version: v2\n")
	writeProtoStatusTestFile(t, filepath.Join(repo, "buf.gen.yaml"), "version: v2\n")
	writeProtoStatusTestFile(t, filepath.Join(repo, "cmd/ngfwopenapi/main.go"), "package main\n")

	cmd := exec.Command("make", "-f", filepath.Join(root, "Makefile"), "proto-status")
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("proto-status accepted untracked contract inputs:\n%s", output)
	}
	for _, want := range []string{
		"untracked API contract inputs:",
		"  api/openapi.yaml",
		"  api/proto/openngfw/v1/app_service.proto",
		"  buf.yaml",
		"  buf.gen.yaml",
		"  cmd/ngfwopenapi/main.go",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("proto-status output missing %q:\n%s", want, output)
		}
	}
}

func TestProtoVerifyReportsUntrackedContractInputsAfterGeneration(t *testing.T) {
	root := releaseRepoRoot(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found")
	}
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make not found")
	}

	repo := t.TempDir()
	runProtoStatusTestCommand(t, repo, "git", "init")
	runProtoStatusTestCommand(t, repo, "git", "config", "user.email", "test@example.invalid")
	runProtoStatusTestCommand(t, repo, "git", "config", "user.name", "OpenNGFW Test")
	writeProtoStatusTestFile(t, filepath.Join(repo, ".gitkeep"), "")
	runProtoStatusTestCommand(t, repo, "git", "add", ".gitkeep")
	runProtoStatusTestCommand(t, repo, "git", "commit", "-m", "baseline")

	writeProtoStatusTestFile(t, filepath.Join(repo, "api/openapi.yaml"), "openapiOptions: {}\n")
	writeProtoStatusTestFile(t, filepath.Join(repo, "api/proto/openngfw/v1/app_service.proto"), "syntax = \"proto3\";\n")
	writeProtoStatusTestFile(t, filepath.Join(repo, "buf.yaml"), "version: v2\n")
	writeProtoStatusTestFile(t, filepath.Join(repo, "buf.gen.yaml"), "version: v2\n")
	writeProtoStatusTestFile(t, filepath.Join(repo, "cmd/ngfwopenapi/main.go"), "package main\n")
	override := filepath.Join(repo, "proto-override.mk")
	writeProtoStatusTestFile(t, override, "proto:\n\t@echo proto override no-op\n")

	cmd := exec.Command("make", "-f", filepath.Join(root, "Makefile"), "-f", override, "proto-verify")
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("proto-verify accepted untracked contract inputs:\n%s", output)
	}
	for _, want := range []string{
		"proto override no-op",
		"untracked API contract inputs:",
		"api/openapi.yaml",
		"api/proto/openngfw/v1/app_service.proto",
		"buf.yaml",
		"buf.gen.yaml",
		"cmd/ngfwopenapi/main.go",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("proto-verify output missing %q:\n%s", want, output)
		}
	}
}

func TestReleaseRecordabilityDiagnosticsReportsBothBlockerSetsWithoutEvidence(t *testing.T) {
	root := releaseRepoRoot(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found")
	}
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make not found")
	}

	repo := t.TempDir()
	runProtoStatusTestCommand(t, repo, "git", "init")
	runProtoStatusTestCommand(t, repo, "git", "config", "user.email", "test@example.invalid")
	runProtoStatusTestCommand(t, repo, "git", "config", "user.name", "OpenNGFW Test")
	writeProtoStatusTestFile(t, filepath.Join(repo, ".gitkeep"), "")
	runProtoStatusTestCommand(t, repo, "git", "add", ".gitkeep")
	runProtoStatusTestCommand(t, repo, "git", "commit", "-m", "baseline")

	writeProtoStatusTestFile(t, filepath.Join(repo, "api/openapi.yaml"), "openapiOptions: {}\n")
	writeProtoStatusTestFile(t, filepath.Join(repo, "api/proto/openngfw/v1/app_service.proto"), "syntax = \"proto3\";\n")
	writeProtoStatusTestFile(t, filepath.Join(repo, "api/gen/openapi/api-spec.swagger.yaml"), "openapi: 3.0.3\n")

	makefile := filepath.Join(repo, "Makefile")
	writeProtoStatusTestFile(t, makefile, "include "+filepath.ToSlash(filepath.Join(root, "Makefile"))+"\n")

	binDir := filepath.Join(repo, "bin")
	writeProtoStatusTestFile(t, filepath.Join(binDir, "go"), `#!/bin/sh
echo "$@" >> go-invocations.log
if [ "$1" = "run" ] && [ "$2" = "./cmd/ngfwrelease" ] && [ "$3" = "recordability" ]; then
	echo "recordability: blocked"
	echo "blocked source paths:"
	echo "  api/openapi.yaml"
	exit 1
fi
echo "unexpected go invocation: $*" >&2
exit 127
`)
	if err := os.Chmod(filepath.Join(binDir, "go"), 0o700); err != nil {
		t.Fatalf("chmod fake go: %v", err)
	}

	cmd := exec.Command("make", "release-recordability-diagnostics")
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("release-recordability-diagnostics accepted blocked repo:\n%s", output)
	}
	for _, want := range []string{
		"== API contract recordability diagnostics ==",
		"untracked API contract inputs:",
		"  api/openapi.yaml",
		"  api/proto/openngfw/v1/app_service.proto",
		"== Release evidence recordability diagnostics ==",
		"recordability: blocked",
		"blocked source paths:",
		"  api/openapi.yaml",
		"release recordability diagnostics found blockers; this target is diagnostic only and records no evidence",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("release-recordability-diagnostics output missing %q:\n%s", want, output)
		}
	}

	invocations, err := os.ReadFile(filepath.Join(repo, "go-invocations.log"))
	if err != nil {
		t.Fatalf("read fake go invocations: %v", err)
	}
	if !strings.Contains(string(invocations), "run ./cmd/ngfwrelease recordability") {
		t.Fatalf("release-recordability-check did not invoke ngfwrelease recordability:\n%s", invocations)
	}
	assertProtoStatusTestNoFiles(t, filepath.Join(repo, "release", "evidence"))
}

func runProtoStatusTestCommand(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
}

func writeProtoStatusTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertProtoStatusTestNoFiles(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no release evidence files under %s, found %d", path, len(entries))
	}
}
