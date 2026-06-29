package webui

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWebUICheckTargetsPropagateJavaScriptTestFailure(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make not found")
	}

	root := webUICheckRepoRoot(t)
	for _, target := range []string{"webui-check", "webui-enterprise-smoke"} {
		t.Run(target, func(t *testing.T) {
			repo := t.TempDir()
			copyWebUICheckFile(t, filepath.Join(root, "Makefile"), filepath.Join(repo, "Makefile"), 0o600)
			writeWebUICheckFile(
				t,
				filepath.Join(repo, "internal/webui/static/js/injected_failure.test.mjs"),
				"throw new Error('the node stub must report this injected failure');\n",
				0o600,
			)

			binDir := filepath.Join(repo, "bin")
			nodeStub := filepath.Join(binDir, "node")
			writeWebUICheckFile(t, nodeStub, `#!/bin/sh
if [ "${1:-}" = "--check" ]; then
	exit 0
fi
last=""
for arg in "$@"; do
	last="$arg"
done
case "$last" in
	*injected_failure.test.mjs)
		echo "injected webui test failure" >&2
		exit 23
		;;
esac
exit 0
`, 0o700)

			cmd := exec.Command("make", target, "WEBUI_CHECK_REQUIRE_NODE=1")
			cmd.Dir = repo
			cmd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			out, err := cmd.CombinedOutput()
			output := string(out)
			if err == nil {
				t.Fatalf("%s accepted an injected failing JavaScript test:\n%s", target, output)
			}
			if !strings.Contains(output, "injected webui test failure") {
				t.Fatalf("%s output did not preserve the injected failure:\n%s", target, output)
			}
			if strings.Contains(output, "webui_js_checks=passed") {
				t.Fatalf("%s reported success after the injected failure:\n%s", target, output)
			}
		})
	}
}

func webUICheckRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	for dir := wd; ; dir = filepath.Dir(dir) {
		if info, statErr := os.Stat(filepath.Join(dir, "Makefile")); statErr == nil && !info.IsDir() {
			return dir
		}
		next := filepath.Dir(dir)
		if next == dir {
			t.Fatalf("find repository root above %s", wd)
		}
	}
}

func copyWebUICheckFile(t *testing.T, src, dst string, mode os.FileMode) {
	t.Helper()
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	writeWebUICheckFile(t, dst, string(body), mode)
}

func writeWebUICheckFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
