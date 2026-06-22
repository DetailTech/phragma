//go:build integration

package integration

import (
	"os/exec"
	"strings"
	"testing"
)

func TestReleaseEbpfOL9AttachDrillCheckReportsPreflight(t *testing.T) {
	root := releaseRepoRoot(t)
	cmd := exec.Command("bash", "release/ebpf-ol9-attach-drill.sh", "--check", "--evidence-dir", t.TempDir())
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		t.Fatalf("eBPF OL9 attach drill check failed: %v\n%s", err, output)
	}

	for _, want := range []string{
		"check=ebpf-ol9-attach-drill",
		"mode=check",
		"field_evidence_check=ebpf-ol9-field-evidence",
		"run_requires_os=linux",
		"run_requires_euid=0",
		"run_requires_interface=explicit-disposable-interface",
		"run_requires_commands=go,bpftool,clang,tc,ip,findmnt,curl,ngfwctl",
		"run_requires_status_json=EBPF_OL9_STATUS_JSON_COMMAND or NGFW_API_ORIGIN",
		"active_dataplane=nftables/conntrack",
		"ebpf_renderer_state=planned",
		"supported_hooks=xdp,tc",
		"ok: field-evidence validator requires XDP attach evidence",
		"ok: field-evidence validator requires tc attach evidence",
		"ok: field-evidence validator preserves nftables active dataplane",
		"status=passed",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("eBPF attach drill check output missing %q:\n%s", want, output)
		}
	}
}

func TestReleaseEbpfOL9AttachDrillRunRequiresExplicitInterface(t *testing.T) {
	root := releaseRepoRoot(t)
	cmd := exec.Command("bash", "release/ebpf-ol9-attach-drill.sh", "--run", "--evidence-dir", t.TempDir())
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("eBPF OL9 attach drill --run accepted missing interface:\n%s", output)
	}
	if !strings.Contains(output, "EBPF_OL9_ATTACH_IFACE or --iface is required for --run") || !strings.Contains(output, "status=failed") {
		t.Fatalf("expected missing interface failure, got:\n%s", output)
	}
}
