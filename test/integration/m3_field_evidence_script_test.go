//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

func TestReleaseM3FieldEvidenceCheckAcceptsCompleteBundle(t *testing.T) {
	root := releaseRepoRoot(t)
	evidenceDir := writeM3FieldEvidenceBundle(t)
	cmd := exec.Command("bash", "release/m3-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		t.Fatalf("m3 field evidence check failed: %v\n%s", err, output)
	}

	for _, want := range []string{
		"check=m3-field-evidence",
		"mode=check",
		"field_evidence_scope=bgp,ipsec,wireguard",
		"required_bgp_evidence=show-bgp-summary,ip-route-remote-prefix,frr-running-config",
		"required_ipsec_evidence=swanctl-list-conns,swanctl-list-sas,swanctl-list-pols,ip-xfrm-state,ip-xfrm-policy,protected-subnet-ping",
		"required_wireguard_evidence=wg-show,client-config-redacted,external-client-ping",
		"manifest_sha256_policy=required,exact-regular-files,no-extra-files",
		"ok: manifest.sha256 verified exact file set",
		"m3_field_redaction=wireguard-private-key-redacted,preshared-key-redacted,bearer-tokens-redacted,api-keys-redacted,url-credentials-redacted",
		"redaction_scan=private-key,psk,bearer,api-key,token,url-userinfo",
		"ok: evidence bundle contains no symlinks",
		"ok: BGP peer summary contains expected evidence",
		"ok: IPsec established IKE SA contains expected evidence",
		"ok: IPsec installed CHILD SA contains expected evidence",
		"ok: WireGuard handshake contains expected evidence",
		"status=passed",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("field evidence output missing %q:\n%s", want, output)
		}
	}
}

func TestReleaseM3FieldEvidenceCheckRejectsBundleSymlinkEscape(t *testing.T) {
	root := releaseRepoRoot(t)
	evidenceDir := writeM3FieldEvidenceBundle(t)
	extraDir := filepath.Join(evidenceDir, "operator-notes")
	if err := os.MkdirAll(extraDir, 0o755); err != nil {
		t.Fatalf("mkdir operator notes: %v", err)
	}
	if err := os.Symlink("/etc/hosts", filepath.Join(extraDir, "host-file.txt")); err != nil {
		t.Fatalf("symlink extra evidence: %v", err)
	}

	cmd := exec.Command("bash", "release/m3-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("m3 field evidence check accepted symlink escape:\n%s", output)
	}
	if !strings.Contains(output, "evidence bundle must not contain symlinks") || !strings.Contains(output, "status=failed") {
		t.Fatalf("expected bundle symlink rejection, got:\n%s", output)
	}
}

func TestReleaseM3FieldEvidenceCheckRejectsMissingManifest(t *testing.T) {
	root := releaseRepoRoot(t)
	evidenceDir := writeM3FieldEvidenceBundle(t)
	if err := os.Remove(filepath.Join(evidenceDir, "manifest.sha256")); err != nil {
		t.Fatalf("remove manifest.sha256: %v", err)
	}

	cmd := exec.Command("bash", "release/m3-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("m3 field evidence check accepted missing manifest.sha256:\n%s", output)
	}
	if !strings.Contains(output, "manifest.sha256 missing or empty") || !strings.Contains(output, "status=failed") {
		t.Fatalf("expected missing manifest rejection, got:\n%s", output)
	}
}

func TestReleaseM3FieldEvidenceCheckRejectsExtraManifestFile(t *testing.T) {
	root := releaseRepoRoot(t)
	evidenceDir := writeM3FieldEvidenceBundle(t)
	writeFieldEvidenceFile(t, evidenceDir, "operator-notes/extra.txt", "manual note\n")
	writeFieldEvidenceManifest(t, evidenceDir,
		"bgp-external-peer/show-bgp-summary.txt",
		"bgp-external-peer/ip-route-remote-prefix.txt",
		"bgp-external-peer/frr-running-config.txt",
		"ipsec-strongswan-sa-traffic/swanctl-list-conns.txt",
		"ipsec-strongswan-sa-traffic/swanctl-list-sas.txt",
		"ipsec-strongswan-sa-traffic/swanctl-list-pols.txt",
		"ipsec-strongswan-sa-traffic/ip-xfrm-state.txt",
		"ipsec-strongswan-sa-traffic/ip-xfrm-policy.txt",
		"ipsec-strongswan-sa-traffic/protected-subnet-ping.txt",
		"wireguard-external-client/wg-show.txt",
		"wireguard-external-client/client-config-redacted.txt",
		"wireguard-external-client/external-client-ping.txt",
		"operator-notes/extra.txt",
	)

	cmd := exec.Command("bash", "release/m3-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("m3 field evidence check accepted extra manifest file:\n%s", output)
	}
	if !strings.Contains(output, "manifest.sha256 has unexpected entry: operator-notes/extra.txt") || !strings.Contains(output, "status=failed") {
		t.Fatalf("expected unexpected manifest entry rejection, got:\n%s", output)
	}
}

func TestReleaseM3FieldEvidenceCheckRejectsNonRegularBundleEntry(t *testing.T) {
	root := releaseRepoRoot(t)
	evidenceDir := writeM3FieldEvidenceBundle(t)
	fifoDir := filepath.Join(evidenceDir, "operator-notes")
	if err := os.MkdirAll(fifoDir, 0o755); err != nil {
		t.Fatalf("mkdir operator notes: %v", err)
	}
	if err := syscall.Mkfifo(filepath.Join(fifoDir, "capture.pipe"), 0o600); err != nil {
		t.Fatalf("mkfifo extra evidence: %v", err)
	}

	cmd := exec.Command("bash", "release/m3-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("m3 field evidence check accepted non-regular bundle entry:\n%s", output)
	}
	if !strings.Contains(output, "evidence bundle contains unsupported non-regular file: operator-notes/capture.pipe") ||
		!strings.Contains(output, "status=failed") {
		t.Fatalf("expected non-regular bundle entry rejection, got:\n%s", output)
	}
}

func TestReleaseM3FieldEvidenceCheckRejectsUnredactedMaterial(t *testing.T) {
	root := releaseRepoRoot(t)
	evidenceDir := writeM3FieldEvidenceBundle(t)
	writeFieldEvidenceFile(t, evidenceDir, "wireguard-external-client/client-config-redacted.txt", strings.Join([]string{
		"[Interface]",
		"PrivateKey = ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi1234567890=",
		"[Peer]",
		"PresharedKey = ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210abcd=",
	}, "\n")+"\n")
	writeFieldEvidenceFile(t, evidenceDir, "ipsec-strongswan-sa-traffic/swanctl-list-conns.txt", strings.Join([]string{
		"site-test: local_addrs 10.0.1.10 remote_addrs 10.0.2.20 children site-test-child",
		"psk = super-secret-ipsec-key",
		"Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456",
		"api_key=abcdefghijklmnopqrstuvwxyz123456",
		"collector=https://operator:secretpass@vpn.example.com/status",
	}, "\n")+"\n")

	cmd := exec.Command("bash", "release/m3-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("m3 field evidence check accepted unredacted material:\n%s", output)
	}
	for _, want := range []string{
		"WireGuard private key appears unredacted",
		"WireGuard preshared key appears unredacted",
		"IPsec pre-shared key appears unredacted",
		"bearer token appears unredacted",
		"API token appears unredacted",
		"URL credentials appears unredacted",
		"status=failed",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected unredacted material failure %q, got:\n%s", want, output)
		}
	}
}

func TestReleaseM3FieldEvidenceCheckRejectsMissingIPsecSA(t *testing.T) {
	root := releaseRepoRoot(t)
	evidenceDir := writeM3FieldEvidenceBundle(t)
	if err := os.Remove(filepath.Join(evidenceDir, "ipsec-strongswan-sa-traffic", "swanctl-list-sas.txt")); err != nil {
		t.Fatalf("remove swanctl-list-sas: %v", err)
	}

	cmd := exec.Command("bash", "release/m3-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("m3 field evidence check accepted incomplete bundle:\n%s", output)
	}
	if !strings.Contains(output, "IPsec established IKE SA missing or empty") || !strings.Contains(output, "status=failed") {
		t.Fatalf("expected missing IPsec SA failure, got:\n%s", output)
	}
}

func TestReleaseM3FieldEvidenceCheckRejectsSymlinkedEvidence(t *testing.T) {
	root := releaseRepoRoot(t)
	evidenceDir := writeM3FieldEvidenceBundle(t)
	routeEvidence := filepath.Join(evidenceDir, "bgp-external-peer", "ip-route-remote-prefix.txt")
	if err := os.Remove(routeEvidence); err != nil {
		t.Fatalf("remove route evidence: %v", err)
	}
	if err := os.Symlink("/etc/hosts", routeEvidence); err != nil {
		t.Fatalf("symlink route evidence: %v", err)
	}

	cmd := exec.Command("bash", "release/m3-field-evidence.sh", "--evidence-dir", evidenceDir)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("m3 field evidence check accepted symlinked bundle:\n%s", output)
	}
	if !strings.Contains(output, "BGP learned route must not be a symlink") || !strings.Contains(output, "status=failed") {
		t.Fatalf("expected symlink rejection, got:\n%s", output)
	}
}

func TestReleaseM3FieldEvidenceCheckRejectsUnknownScope(t *testing.T) {
	root := releaseRepoRoot(t)
	evidenceDir := writeM3FieldEvidenceBundle(t)
	cmd := exec.Command("bash", "release/m3-field-evidence.sh", "--evidence-dir", evidenceDir, "--require", "bgp,ospf")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err == nil {
		t.Fatalf("m3 field evidence check accepted unknown scope:\n%s", output)
	}
	if !strings.Contains(output, "unknown --require scope: ospf") || !strings.Contains(output, "status=failed") {
		t.Fatalf("expected unknown scope failure, got:\n%s", output)
	}
}

func writeM3FieldEvidenceBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	manifestPaths := []string{
		"bgp-external-peer/show-bgp-summary.txt",
		"bgp-external-peer/ip-route-remote-prefix.txt",
		"bgp-external-peer/frr-running-config.txt",
		"ipsec-strongswan-sa-traffic/swanctl-list-conns.txt",
		"ipsec-strongswan-sa-traffic/swanctl-list-sas.txt",
		"ipsec-strongswan-sa-traffic/swanctl-list-pols.txt",
		"ipsec-strongswan-sa-traffic/ip-xfrm-state.txt",
		"ipsec-strongswan-sa-traffic/ip-xfrm-policy.txt",
		"ipsec-strongswan-sa-traffic/protected-subnet-ping.txt",
		"wireguard-external-client/wg-show.txt",
		"wireguard-external-client/client-config-redacted.txt",
		"wireguard-external-client/external-client-ping.txt",
	}
	writeFieldEvidenceFile(t, dir, "bgp-external-peer/show-bgp-summary.txt", "Neighbor        V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd\n10.0.2.20       4 65002 12 12 0 0 0 00:01:14 Established\n")
	writeFieldEvidenceFile(t, dir, "bgp-external-peer/ip-route-remote-prefix.txt", "192.168.200.0/24 via 10.0.2.20 dev eth1 proto bgp metric 20\n")
	writeFieldEvidenceFile(t, dir, "bgp-external-peer/frr-running-config.txt", "router bgp 65001\n neighbor 10.0.2.20 remote-as 65002\n")

	writeFieldEvidenceFile(t, dir, "ipsec-strongswan-sa-traffic/swanctl-list-conns.txt", "site-test: local_addrs 10.0.1.10 remote_addrs 10.0.2.20 children site-test-child\n")
	writeFieldEvidenceFile(t, dir, "ipsec-strongswan-sa-traffic/swanctl-list-sas.txt", "site-test: #1, ESTABLISHED, IKEv2\n  site-test-child: #1, INSTALLED, TUNNEL, reqid 1, ESP SPIs c1_i c1_o\n")
	writeFieldEvidenceFile(t, dir, "ipsec-strongswan-sa-traffic/swanctl-list-pols.txt", "site-test-child: local 10.10.0.0/24 remote 10.20.0.0/24 in out\n")
	writeFieldEvidenceFile(t, dir, "ipsec-strongswan-sa-traffic/ip-xfrm-state.txt", "src 10.0.1.10 dst 10.0.2.20\n\tproto esp spi 0x00000001 reqid 1 mode tunnel\n")
	writeFieldEvidenceFile(t, dir, "ipsec-strongswan-sa-traffic/ip-xfrm-policy.txt", "src 10.10.0.0/24 dst 10.20.0.0/24\n\tdir out priority 371327\n")
	writeFieldEvidenceFile(t, dir, "ipsec-strongswan-sa-traffic/protected-subnet-ping.txt", "3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n")

	writeFieldEvidenceFile(t, dir, "wireguard-external-client/wg-show.txt", "peer: abc\n  latest handshake: 12 seconds ago\n  transfer: 1.2 KiB received, 2.1 KiB sent\n")
	writeFieldEvidenceFile(t, dir, "wireguard-external-client/client-config-redacted.txt", "[Interface]\nAddress = 10.99.0.2/32\n[Peer]\nPublicKey = redacted\n")
	writeFieldEvidenceFile(t, dir, "wireguard-external-client/external-client-ping.txt", "3 packets transmitted, 3 received, 0% packet loss, time 2002ms\n")
	writeFieldEvidenceManifest(t, dir, manifestPaths...)
	return dir
}

func writeFieldEvidenceFile(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeFieldEvidenceManifest(t *testing.T, root string, rels ...string) {
	t.Helper()
	sort.Strings(rels)
	var b strings.Builder
	for _, rel := range rels {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read manifest entry %s: %v", rel, err)
		}
		sum := sha256.Sum256(body)
		b.WriteString(hex.EncodeToString(sum[:]))
		b.WriteString("  ")
		b.WriteString(rel)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.sha256"), []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write manifest.sha256: %v", err)
	}
}
