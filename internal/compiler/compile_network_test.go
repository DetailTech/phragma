package compiler

import (
	"testing"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func networkPolicy() *openngfwv1.Policy {
	p := testPolicy()
	p.Network = &openngfwv1.Network{
		Mtu:            9000,
		InterfaceMtus:  []*openngfwv1.InterfaceMtu{{Interface: "eth1", Mtu: 1500}, {Interface: "mgmt0", Mtu: 9000}},
		ClampMssToPmtu: true,
	}
	return p
}

func TestCompileNetwork(t *testing.T) {
	ir, err := Compile(networkPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if ir.Network == nil {
		t.Fatal("Network IR missing")
	}
	// Zone interfaces: eth0 (wan), eth1+eth2 (lan); eth1 overridden to
	// 1500; mgmt0 is an extra non-zone interface.
	want := map[string]uint32{"eth0": 9000, "eth1": 1500, "eth2": 9000, "mgmt0": 9000}
	if len(ir.Network.Links) != len(want) {
		t.Fatalf("links = %+v", ir.Network.Links)
	}
	for _, l := range ir.Network.Links {
		if want[l.Interface] != l.MTU {
			t.Errorf("link %s mtu = %d, want %d", l.Interface, l.MTU, want[l.Interface])
		}
	}
	if !ir.Network.ClampMSS {
		t.Error("ClampMSS not set")
	}
	if ir.Network.MaxMTU != 9000 {
		t.Errorf("MaxMTU = %d", ir.Network.MaxMTU)
	}
}

func TestCompileNetworkOffloads(t *testing.T) {
	p := networkPolicy()
	p.Network.ManageNicOffloads = true
	p.Ids = &openngfwv1.Ids{
		Enabled: true, Mode: openngfwv1.IdsMode_IDS_MODE_DETECT,
		MonitorInterfaces: []string{"eth1"},
	}
	ir, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(ir.Network.OffloadOffIfaces) != 1 || ir.Network.OffloadOffIfaces[0] != "eth1" {
		t.Fatalf("OffloadOffIfaces = %v", ir.Network.OffloadOffIfaces)
	}

	// Prevent mode (NFQUEUE) doesn't sniff wire frames: no offload work.
	p.Ids.Mode = openngfwv1.IdsMode_IDS_MODE_PREVENT
	ir, err = Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(ir.Network.OffloadOffIfaces) != 0 {
		t.Fatalf("prevent mode must not manage offloads: %v", ir.Network.OffloadOffIfaces)
	}
}

func TestCompileNetworkAbsent(t *testing.T) {
	ir, err := Compile(testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if ir.Network != nil {
		t.Fatalf("Network should be nil when unset, got %+v", ir.Network)
	}
}
