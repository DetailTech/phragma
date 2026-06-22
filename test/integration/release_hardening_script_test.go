//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseDeployHardeningCheckAcceptsPackagedArtifacts(t *testing.T) {
	root := releaseRepoRoot(t)
	cmd := exec.Command("bash", "release/deploy-hardening-check.sh", "--check")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		t.Fatalf("deploy hardening check failed: %v\n%s", err, output)
	}

	for _, want := range []string{
		"check=deploy-hardening",
		"mode=check",
		"required_service_posture=loopback-listeners,authenticated-by-default,no-dev-bypass,systemd-sandbox,capability-bounds",
		"required_installer_posture=root-only,0700-state-log-config,hashed-admin-token,0600-secret-files,unsafe-remote-install-opt-in",
		"ok: gRPC management listener is loopback by default",
		"ok: REST/WebUI listener is loopback by default",
		"ok: users file authentication is configured",
		"ok: unauthenticated local dev bypass absent",
		"ok: cleartext TLS-disable flag absent",
		"ok: NoNewPrivileges systemd sandbox",
		"ok: capability bounding set is explicit",
		"ok: installer requires root",
		"ok: users file uses sha256 token hash format",
		"ok: bootstrap token file is created mode 0600",
		"ok: remote Vector installer requires explicit unsafe opt-in",
		"status=passed",
	} {
		if !hasOutputLine(output, want) {
			t.Fatalf("deploy hardening output missing line %q:\n%s", want, output)
		}
	}
}

func TestReleaseDeployHardeningCheckRejectsUnauthenticatedService(t *testing.T) {
	root := releaseRepoRoot(t)
	service := copyRepoFileToTemp(t, root, "deploy/systemd/controld.service")
	installer := filepath.Join(root, "deploy/install.sh")

	body := readTestFile(t, service)
	body = strings.Replace(body, "--users-file /etc/openngfw/users.yaml", "--allow-unauthenticated-local", 1)
	writeTestFile(t, service, body)

	cmd := exec.Command("bash", "release/deploy-hardening-check.sh", "--service-unit", service, "--installer", installer)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("deploy hardening check accepted unauthenticated service:\n%s", output)
	}
	for _, want := range []string{
		"users file authentication is configured",
		"contains prohibited active setting: unauthenticated local dev bypass",
		"status=failed",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("deploy hardening output missing failure %q:\n%s", want, output)
		}
	}
}

func TestReleaseDeployHardeningCheckRejectsBroadServiceCapability(t *testing.T) {
	root := releaseRepoRoot(t)
	service := copyRepoFileToTemp(t, root, "deploy/systemd/controld.service")
	installer := filepath.Join(root, "deploy/install.sh")

	body := readTestFile(t, service)
	body = strings.Replace(
		body,
		"CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH",
		"CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH",
		1,
	)
	writeTestFile(t, service, body)

	cmd := exec.Command("bash", "release/deploy-hardening-check.sh", "--service-unit", service, "--installer", installer)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("deploy hardening check accepted broad service capability:\n%s", output)
	}
	for _, want := range []string{
		"missing required active setting: capability bounding set is explicit",
		"contains prohibited active setting: CAP_SYS_ADMIN",
		"status=failed",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("deploy hardening output missing failure %q:\n%s", want, output)
		}
	}
}

func copyRepoFileToTemp(t *testing.T, root, rel string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), filepath.Base(rel))
	body := readTestFile(t, filepath.Join(root, rel))
	writeTestFile(t, dst, body)
	return dst
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}

func writeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
