//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseM3LiveNetworkingCheckReportsAutomatedScope(t *testing.T) {
	root := releaseRepoRoot(t)
	cmd := exec.Command("bash", "release/m3-live-networking.sh", "--check")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		t.Fatalf("m3 live-networking check failed: %v\n%s", err, output)
	}

	for _, want := range []string{
		"automated_scope=static-route-live-forwarding,bgp-frr-netns-route-programming,wireguard-handshake-peer-traffic",
		"automated_tests=TestM3StaticRouteProgramsLiveForwarding,TestM3BGPProgramsKernelRouteFromFRRPeer,TestM3WireGuardPolicyCreatesInterfaceAndPassesPeerTraffic",
		"manual_field_tests=bgp-external-peer,ipsec-strongswan-sa-traffic,wireguard-external-client",
		"manual_ipsec_evidence=swanctl-list-conns,swanctl-list-sas,swanctl-list-pols,ip-xfrm-state,ip-xfrm-policy,protected-subnet-ping",
		"manual_ipsec_template=docs/testing-plan.md:T3.3,docs/examples/policy-routing-vpn.yaml",
		"test_regex=^(TestM3StaticRouteProgramsLiveForwarding|TestM3BGPProgramsKernelRouteFromFRRPeer|TestM3WireGuardPolicyCreatesInterfaceAndPassesPeerTraffic)$",
		"run_requires_commands=ip,nft,nc,wg,vtysh,zebra,bgpd",
		"run_requires_kernel=network-namespaces,nftables,ip-forwarding,wireguard,ipv4-kernel-route-table",
		"run_requires_services=none",
		"ok: manual IPsec field-test row present",
		"ok: manual IPsec evidence requires swanctl connection listing",
		"ok: manual IPsec evidence requires SA listing",
		"ok: manual IPsec evidence requires policy listing",
		"ok: manual IPsec evidence requires XFRM state",
		"ok: manual IPsec evidence requires XFRM policy",
		"ok: manual IPsec evidence requires protected-subnet traffic",
		"ok: example policy documents manual IPsec evidence",
		"test: TestM3StaticRouteProgramsLiveForwarding",
		"test: TestM3BGPProgramsKernelRouteFromFRRPeer",
		"test: TestM3WireGuardPolicyCreatesInterfaceAndPassesPeerTraffic",
		"ok: release-gate test selected: TestM3StaticRouteProgramsLiveForwarding",
		"ok: release-gate test selected: TestM3BGPProgramsKernelRouteFromFRRPeer",
		"ok: release-gate test selected: TestM3WireGuardPolicyCreatesInterfaceAndPassesPeerTraffic",
		"status=passed",
	} {
		if !hasOutputLine(output, want) {
			t.Fatalf("m3 check output missing line %q:\n%s", want, output)
		}
	}

	for _, notWant := range []string{
		"manual_field_tests=bgp-frr,ipsec-strongswan,wireguard",
		"automated_scope=static-route-live-forwarding,bgp-frr-netns-route-programming,ipsec-strongswan-sa-traffic,wireguard-handshake-peer-traffic",
		"automated_scope=static-route-live-forwarding,bgp-frr-netns-route-programming,ipsec-strongswan,wireguard-handshake-peer-traffic",
		"run_requires_services=frr,strongswan-or-charon",
		"automated_scope=static-route-live-forwarding,bgp-external-peer,wireguard-handshake-peer-traffic",
	} {
		if hasOutputLine(output, notWant) {
			t.Fatalf("m3 check output overclaims automated live prerequisites with %q:\n%s", notWant, output)
		}
	}
}

func releaseRepoRoot(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	wd, wdErr := os.Getwd()
	if wdErr != nil {
		t.Fatalf("find repo root: git failed: %v; get working directory: %v", err, wdErr)
	}
	for dir := wd; ; dir = filepath.Dir(dir) {
		if fileExists(filepath.Join(dir, "Makefile")) && fileExists(filepath.Join(dir, "release", "m3-live-networking.sh")) {
			return dir
		}
		next := filepath.Dir(dir)
		if next == dir {
			t.Fatalf("find repo root: git failed: %v; no repo markers above %s", err, wd)
		}
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func hasOutputLine(output, want string) bool {
	for _, line := range strings.Split(output, "\n") {
		if line == want {
			return true
		}
	}
	return false
}
