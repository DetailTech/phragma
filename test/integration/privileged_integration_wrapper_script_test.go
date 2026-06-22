//go:build integration

package integration

import (
	"os/exec"
	"strings"
	"testing"
)

func TestPrivilegedIntegrationWrapperAcceptsPassingTranscript(t *testing.T) {
	root := releaseRepoRoot(t)
	cmd := exec.Command("bash", "release/privileged-integration-no-skip.sh", "--", "sh", "-c", "printf '%s\n' '=== RUN   TestPrivilegedPath' '--- PASS: TestPrivilegedPath (0.01s)' 'PASS'")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		t.Fatalf("privileged wrapper rejected passing transcript: %v\n%s", err, output)
	}
	for _, want := range []string{
		"check=privileged-integration",
		"mode=run",
		"privileged_integration_skip_policy=no-skipped-tests",
		"run_requires=linux-root,nftables,iproute2,netcat,tcpdump",
		"skipped_tests=0",
		"status=passed",
	} {
		if !hasOutputLine(output, want) {
			t.Fatalf("privileged wrapper output missing line %q:\n%s", want, output)
		}
	}
}

func TestPrivilegedIntegrationWrapperRejectsSkippedTranscript(t *testing.T) {
	root := releaseRepoRoot(t)
	cmd := exec.Command("bash", "release/privileged-integration-no-skip.sh", "--", "sh", "-c", "printf '%s\n' '=== RUN   TestPrivilegedPath' '--- SKIP: TestPrivilegedPath (0.01s)' 'PASS'")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("privileged wrapper accepted skipped transcript:\n%s", output)
	}
	for _, want := range []string{
		"privileged_integration_skip_policy=no-skipped-tests",
		"failure=privileged-integration-skipped-tests",
		"skipped_tests=1",
		"status=failed",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("privileged wrapper output missing failure %q:\n%s", want, output)
		}
	}
}
