//go:build integration

// Global network settings end-to-end: managed MTU lands on the kernel
// links, the MSS clamp is live in the ruleset, NIC offloads are turned
// off on IDS-monitored interfaces, and traffic still flows.
package integration

import (
	"os/exec"
	"strings"
	"testing"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestNetworkSettingsEndToEnd(t *testing.T) {
	requireRoot(t)
	if _, err := exec.LookPath("ethtool"); err != nil {
		t.Skip("ethtool not installed")
	}
	setupTopology(t)
	startEchoServer(t)
	srv := newStack(t)

	pol := allowPolicy()
	pol.Network = &openngfwv1.Network{
		Mtu:               9000,
		InterfaceMtus:     []*openngfwv1.InterfaceMtu{{Interface: "cveth0", Mtu: 1500}},
		ClampMssToPmtu:    true,
		ManageNicOffloads: true,
	}
	pol.Ids = &openngfwv1.Ids{
		Enabled: true, Mode: openngfwv1.IdsMode_IDS_MODE_DETECT,
		MonitorInterfaces: []string{"sveth0"},
	}
	// IDS is enabled only to mark sveth0 as monitored — the stack under
	// test has no suricata engine, so its artifact is simply unused;
	// the netdev engine acts on the offload directives regardless.
	mustCommit(t, srv, pol, "jumbo + clamp + offloads")

	// MTU: global on sveth0, override on cveth0.
	if out := run(t, "ip", "link", "show", "sveth0"); !strings.Contains(out, "mtu 9000") {
		t.Fatalf("sveth0 MTU not applied:\n%s", out)
	}
	if out := run(t, "ip", "link", "show", "cveth0"); !strings.Contains(out, "mtu 1500") {
		t.Fatalf("cveth0 MTU override not applied:\n%s", out)
	}

	// MSS clamp is in the live ruleset.
	if rs := run(t, "nft", "list", "table", "inet", "openngfw"); !strings.Contains(rs, "maxseg size set rt mtu") {
		t.Fatalf("mss clamp missing from live ruleset:\n%s", rs)
	}

	// Offloads off on the monitored interface.
	out := run(t, "ethtool", "-k", "sveth0")
	for _, feature := range []string{"generic-receive-offload: off", "tcp-segmentation-offload: off"} {
		if !strings.Contains(out, feature) {
			t.Fatalf("offload not disabled (%s):\n%s", feature, out)
		}
	}

	// And traffic still flows with the clamp + MTU mix in place.
	if !tcpReachable(serverIP, 8080) {
		t.Fatal("traffic broken after network settings applied")
	}
}
