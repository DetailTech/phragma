//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseEbpfOL9FieldEvidenceCheckAcceptsCompleteBundle(t *testing.T) {
	root := releaseRepoRoot(t)
	evidenceDir := writeEbpfOL9FieldEvidenceBundle(t)
	cmd := exec.Command("bash", "release/ebpf-ol9-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		t.Fatalf("eBPF OL9 field evidence check failed: %v\n%s", err, output)
	}

	for _, want := range []string{
		"check=ebpf-ol9-field-evidence",
		"mode=check",
		"field_evidence_scope=ol9-oci-host,ebpf-host-prereqs,xdp-attach-probe,tc-attach-probe,status-api,renderer-scaffold,cleanup",
		"required_ebpf_prereqs=bpftool,clang,tc,ip,kernel-btf,bpffs,cgroup-v2,link-inventory",
		"required_attach_evidence=xdp-attach,xdp-detach,tc-clsact-attach,tc-clsact-detach,bpftool-program-inspection,cleanup",
		"required_status_evidence=ngfwctl-status,system-status-ebpf-json",
		"required_renderer_evidence=ebpf-render-plan",
		"required_drill_evidence=drill-manifest,probe-source-sha256,probe-object-sha256,attach-detach-command-records",
		"manifest_sha256_policy=required,exact-regular-files,no-extra-files",
		"ok: manifest.sha256 verified exact file set",
		"active_dataplane=nftables/conntrack",
		"ebpf_renderer_state=planned",
		"supported_hooks=xdp,tc",
		"xdp_attach_result=passed",
		"tc_attach_result=passed",
		"cleanup_result=passed",
		"ebpf_field_redaction=oci-ocids-redacted,public-ips-redacted,tokens-redacted",
		"redaction_scan=private-key,bearer,api-key,token,url-userinfo,oci-ocid,public-ip",
		"ok: eBPF OL9 evidence directory present",
		"ok: kernel BTF evidence contains expected evidence",
		"ok: bpffs mount evidence contains expected evidence",
		"ok: cgroup v2 evidence contains expected evidence",
		"ok: link inventory evidence contains expected evidence",
		"ok: eBPF attach drill manifest tool contains expected evidence",
		"ok: eBPF attach drill manifest mode contains expected evidence",
		"ok: XDP attach drill contains expected evidence",
		"ok: XDP attach command record contains expected evidence",
		"ok: tc clsact attach drill contains expected evidence",
		"ok: tc attach command record contains expected evidence",
		"ok: post-cleanup active dataplane contains expected evidence",
		"status=passed",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("eBPF field evidence output missing %q:\n%s", want, output)
		}
	}
}

func TestReleaseEbpfOL9FieldEvidenceCheckRejectsSymlinkEscape(t *testing.T) {
	root := releaseRepoRoot(t)
	evidenceDir := writeEbpfOL9FieldEvidenceBundle(t)
	extraDir := filepath.Join(evidenceDir, "operator-notes")
	if err := os.MkdirAll(extraDir, 0o755); err != nil {
		t.Fatalf("mkdir operator notes: %v", err)
	}
	if err := os.Symlink("/etc/hosts", filepath.Join(extraDir, "host-file.txt")); err != nil {
		t.Fatalf("symlink extra evidence: %v", err)
	}

	cmd := exec.Command("bash", "release/ebpf-ol9-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("eBPF OL9 field evidence check accepted symlink escape:\n%s", output)
	}
	if !strings.Contains(output, "evidence bundle must not contain symlinks") || !strings.Contains(output, "status=failed") {
		t.Fatalf("expected bundle symlink rejection, got:\n%s", output)
	}
}

func TestReleaseEbpfOL9FieldEvidenceCheckRejectsUnredactedMaterial(t *testing.T) {
	root := releaseRepoRoot(t)
	evidenceDir := writeEbpfOL9FieldEvidenceBundle(t)
	writeFieldEvidenceFile(t, evidenceDir, "host/oci-instance.txt", strings.Join([]string{
		"oci_instance=verified",
		"instance_ocid=ocid1.instance.oc1..example",
		"public_ip=203.0.113.10",
		"Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456",
		"token=abcdefghijklmnopqrstuvwxyz123456",
		"-----BEGIN PRIVATE KEY-----",
		"collector=https://operator:secretpass@evidence.example/status",
	}, "\n")+"\n")

	cmd := exec.Command("bash", "release/ebpf-ol9-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("eBPF OL9 field evidence check accepted unredacted material:\n%s", output)
	}
	for _, want := range []string{
		"private key appears unredacted",
		"bearer token appears unredacted",
		"token appears unredacted",
		"OCI OCID appears unredacted",
		"public IP appears unredacted",
		"URL credentials appears unredacted",
		"status=failed",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected unredacted material failure %q, got:\n%s", want, output)
		}
	}
}

func TestReleaseEbpfOL9FieldEvidenceCheckRejectsManifestHashMismatch(t *testing.T) {
	root := releaseRepoRoot(t)
	evidenceDir := writeEbpfOL9FieldEvidenceBundle(t)
	writeFieldEvidenceFile(t, evidenceDir, "renderer/ebpf-plan.txt", "state=planned\nauthoritative_renderer=nftables\nsupported_hooks=xdp,tc\nchanged_after_manifest=true\n")

	cmd := exec.Command("bash", "release/ebpf-ol9-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("eBPF OL9 field evidence check accepted manifest hash mismatch:\n%s", output)
	}
	if !strings.Contains(output, "manifest.sha256 mismatch for renderer/ebpf-plan.txt") || !strings.Contains(output, "status=failed") {
		t.Fatalf("expected manifest mismatch rejection, got:\n%s", output)
	}
}

func TestReleaseEbpfOL9FieldEvidenceCheckRejectsMissingAttachEvidence(t *testing.T) {
	root := releaseRepoRoot(t)
	evidenceDir := writeEbpfOL9FieldEvidenceBundle(t)
	if err := os.Remove(filepath.Join(evidenceDir, "attach", "tc-clsact-attach.txt")); err != nil {
		t.Fatalf("remove tc attach evidence: %v", err)
	}

	cmd := exec.Command("bash", "release/ebpf-ol9-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("eBPF OL9 field evidence check accepted incomplete bundle:\n%s", output)
	}
	if !strings.Contains(output, "tc clsact attach drill missing or empty") || !strings.Contains(output, "status=failed") {
		t.Fatalf("expected missing tc attach evidence failure, got:\n%s", output)
	}
}

func TestReleaseEbpfOL9FieldEvidenceCheckRejectsMissingDrillManifest(t *testing.T) {
	assertEbpfOL9FieldEvidenceMissingFileRejected(t, "drill/manifest.txt", "eBPF attach drill manifest tool missing or empty")
}

func TestReleaseEbpfOL9FieldEvidenceCheckRejectsMissingKernelBTF(t *testing.T) {
	assertEbpfOL9FieldEvidenceMissingFileRejected(t, "host/kernel-btf.txt", "kernel BTF evidence missing or empty")
}

func TestReleaseEbpfOL9FieldEvidenceCheckRejectsMissingBpffs(t *testing.T) {
	assertEbpfOL9FieldEvidenceMissingFileRejected(t, "host/bpffs.txt", "bpffs mount evidence missing or empty")
}

func TestReleaseEbpfOL9FieldEvidenceCheckRejectsMissingCgroupV2(t *testing.T) {
	assertEbpfOL9FieldEvidenceMissingFileRejected(t, "host/cgroup-v2.txt", "cgroup v2 evidence missing or empty")
}

func TestReleaseEbpfOL9FieldEvidenceCheckRejectsMissingLinkInventory(t *testing.T) {
	assertEbpfOL9FieldEvidenceMissingFileRejected(t, "host/link-inventory.txt", "link inventory evidence missing or empty")
}

func assertEbpfOL9FieldEvidenceMissingFileRejected(t *testing.T, relPath, want string) {
	t.Helper()
	root := releaseRepoRoot(t)
	evidenceDir := writeEbpfOL9FieldEvidenceBundle(t)
	if err := os.Remove(filepath.Join(evidenceDir, filepath.FromSlash(relPath))); err != nil {
		t.Fatalf("remove %s: %v", relPath, err)
	}

	cmd := exec.Command("bash", "release/ebpf-ol9-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("eBPF OL9 field evidence check accepted bundle missing %s:\n%s", relPath, output)
	}
	if !strings.Contains(output, want) || !strings.Contains(output, "status=failed") {
		t.Fatalf("expected %q failure, got:\n%s", want, output)
	}
}

func writeEbpfOL9FieldEvidenceBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	manifestPaths := []string{
		"host/os-release.txt",
		"host/uname.txt",
		"host/oci-instance.txt",
		"host/kernel-btf.txt",
		"host/bpffs.txt",
		"host/cgroup-v2.txt",
		"host/link-inventory.txt",
		"tooling/versions.txt",
		"status/ngfwctl-status.txt",
		"status/system-status-ebpf.json",
		"renderer/ebpf-plan.txt",
		"drill/manifest.txt",
		"attach/xdp-attach.txt",
		"attach/xdp-detach.txt",
		"attach/tc-clsact-attach.txt",
		"attach/tc-clsact-detach.txt",
		"attach/bpftool-prog-show.txt",
		"cleanup/post-cleanup.txt",
	}
	writeFieldEvidenceFile(t, dir, "host/os-release.txt", "NAME=\"Oracle Linux Server\"\nVERSION_ID=\"9.4\"\nID=\"ol\"\n")
	writeFieldEvidenceFile(t, dir, "host/uname.txt", "Linux ol9 5.15.0-310.176.5.el9uek.x86_64 #1 SMP x86_64 GNU/Linux\n")
	writeFieldEvidenceFile(t, dir, "host/oci-instance.txt", "oci_instance=verified\ncloud=oci\n")
	writeFieldEvidenceFile(t, dir, "host/kernel-btf.txt", "kernel_btf=present\npath=/sys/kernel/btf/vmlinux\n")
	writeFieldEvidenceFile(t, dir, "host/bpffs.txt", "bpffs_mount=mounted\ntype=bpf\npath=/sys/fs/bpf\n")
	writeFieldEvidenceFile(t, dir, "host/cgroup-v2.txt", "cgroup_v2=mounted\ntype=cgroup2\npath=/sys/fs/cgroup\n")
	writeFieldEvidenceFile(t, dir, "host/link-inventory.txt", "link_inventory=verified\nxdp_candidate_iface=ens5\ntc_candidate_iface=ens5\n")
	writeFieldEvidenceFile(t, dir, "tooling/versions.txt", "bpftool v7.2.0\nclang version 17.0.0\ntc = iproute2-6.4\nip = iproute2-6.4\n")
	writeFieldEvidenceFile(t, dir, "status/ngfwctl-status.txt", "eBPF host:      ready\neBPF attach:    ready\neBPF renderer:  planned\neBPF hooks:     xdp, tc\n")
	writeFieldEvidenceFile(t, dir, "status/system-status-ebpf.json", "{\"state\":\"ready\",\"attach_state\":\"ready\",\"renderer_state\":\"planned\"}\n")
	writeFieldEvidenceFile(t, dir, "renderer/ebpf-plan.txt", "state=planned\nauthoritative_renderer=nftables\nsupported_hooks=xdp,tc\n")
	hashA := strings.Repeat("a", 64)
	hashB := strings.Repeat("b", 64)
	hashC := strings.Repeat("c", 64)
	hashD := strings.Repeat("d", 64)
	writeFieldEvidenceFile(t, dir, "drill/manifest.txt", "drill_tool=release/ebpf-ol9-attach-drill.sh\ndrill_mode=run\ndrill_schema=phragma.ebpf.ol9.attach-drill.v1\ninterface=ens5\nxdp_probe_source=build/xdp_probe.c\nxdp_probe_source_sha256="+hashA+"\nxdp_probe_object=build/xdp_probe.o\nxdp_probe_object_sha256="+hashB+"\ntc_probe_source=build/tc_probe.c\ntc_probe_source_sha256="+hashC+"\ntc_probe_object=build/tc_probe.o\ntc_probe_object_sha256="+hashD+"\nactive_dataplane=nftables/conntrack\n")
	writeFieldEvidenceFile(t, dir, "attach/xdp-attach.txt", "command=ip link set dev ens5 xdpgeneric obj build/xdp_probe.o sec xdp\nxdp_attach_result=passed\n")
	writeFieldEvidenceFile(t, dir, "attach/xdp-detach.txt", "command=ip link set dev ens5 xdpgeneric off\nxdp_detach_result=passed\n")
	writeFieldEvidenceFile(t, dir, "attach/tc-clsact-attach.txt", "command=tc qdisc add dev ens5 clsact && tc filter add dev ens5 ingress bpf da obj build/tc_probe.o sec tc\ntc_attach_result=passed\n")
	writeFieldEvidenceFile(t, dir, "attach/tc-clsact-detach.txt", "command=tc filter del dev ens5 ingress && tc qdisc del dev ens5 clsact\ntc_detach_result=passed\n")
	writeFieldEvidenceFile(t, dir, "attach/bpftool-prog-show.txt", "programs_inspected=true\nxdp id 10 name xdp_probe\ntc id 11 name tc_probe\n")
	writeFieldEvidenceFile(t, dir, "cleanup/post-cleanup.txt", "cleanup_result=passed\nactive_dataplane=nftables/conntrack\n")
	writeFieldEvidenceManifest(t, dir, manifestPaths...)
	return dir
}
