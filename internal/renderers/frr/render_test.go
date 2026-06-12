package frr

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/detailtech/oss-ngfw/internal/compiler"
)

func routingIR() *compiler.IR {
	return &compiler.IR{Routing: &compiler.RoutingIR{
		BGP: &compiler.BGPIR{
			ASN:      65001,
			RouterID: "192.0.2.1",
			Neighbors: []compiler.BGPNeighborIR{
				{Address: netip.MustParseAddr("10.0.0.2"), RemoteASN: 65002, Description: "upstream"},
			},
			Announce: []netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")},
		},
		OSPF: &compiler.OSPFIR{
			RouterID: "192.0.2.1",
			Areas: []compiler.OSPFAreaIR{
				{Area: "0.0.0.0", Networks: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}},
			},
		},
	}}
}

func TestRenderDisabled(t *testing.T) {
	got, err := Render(&compiler.IR{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != ModeMarker+ModeDisabled+"\n" {
		t.Fatalf("disabled artifact = %q", got)
	}
}

func TestRender(t *testing.T) {
	got, err := Render(routingIR())
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(got)
	for _, want := range []string{
		ModeMarker + "bgpd,ospfd",
		"router bgp 65001",
		" bgp router-id 192.0.2.1",
		" neighbor 10.0.0.2 remote-as 65002",
		" neighbor 10.0.0.2 description upstream",
		"  network 10.10.0.0/24",
		"router ospf",
		" network 10.20.0.0/24 area 0.0.0.0",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
}

// TestRenderedConfigPassesVtysh dry-checks the rendered config with the
// real FRR parser when available.
func TestRenderedConfigPassesVtysh(t *testing.T) {
	bin, err := exec.LookPath("vtysh")
	if err != nil {
		t.Skip("vtysh not installed")
	}
	got, err := Render(routingIR())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(path, got, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "-C", "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("vtysh -C rejected rendered config: %v\n%s\n--- config ---\n%s", err, out, got)
	}
}
