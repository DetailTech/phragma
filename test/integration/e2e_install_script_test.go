//go:build integration

package integration

import (
	"os/exec"
	"testing"
)

func TestE2EInstallCheckReportsReleaseEvidenceSentinels(t *testing.T) {
	root := releaseRepoRoot(t)
	cmd := exec.Command("bash", "e2e/install-smoke.sh", "--check")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		t.Fatalf("e2e install check failed: %v\n%s", err, output)
	}

	for _, want := range []string{
		"check=e2e-install",
		"mode=check",
		"install_smoke_scope=static-preflight",
		"required_install_artifacts=deploy/install.sh,deploy/systemd/controld.service,docs/testing-plan.md,docs/testing-plan-ol9.md",
		"run_requires=linux-root,systemd,network-namespaces,nftables,ip-forwarding",
		"install smoke static preflight complete",
		"status=passed",
	} {
		if !hasOutputLine(output, want) {
			t.Fatalf("e2e install check output missing line %q:\n%s", want, output)
		}
	}
}
