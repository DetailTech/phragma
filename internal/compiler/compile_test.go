package compiler

import (
	"net/netip"
	"testing"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func testPolicy() *openngfwv1.Policy {
	return &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{
			{Name: "wan", Interfaces: []string{"eth0"}},
			{Name: "lan", Interfaces: []string{"eth1", "eth2"}},
		},
		Addresses: []*openngfwv1.Address{
			{Name: "lan-net", Cidr: "10.10.0.0/24"},
			{Name: "host", Cidr: "10.10.0.80/32"},
		},
		Services: []*openngfwv1.Service{
			{Name: "web", Protocol: openngfwv1.Protocol_PROTOCOL_TCP, Ports: []*openngfwv1.PortRange{{Start: 80}, {Start: 8000, End: 8100}}},
		},
		Rules: []*openngfwv1.Rule{
			{Name: "r1", FromZones: []string{"lan"}, ToZones: []string{"wan"}, SourceAddresses: []string{"lan-net"}, Services: []string{"web"}, Action: openngfwv1.Action_ACTION_ALLOW},
			{Name: "skipped", FromZones: []string{"lan"}, ToZones: []string{"wan"}, Action: openngfwv1.Action_ACTION_ALLOW, Disabled: true},
			{Name: "wildcard", FromZones: []string{"any"}, Action: openngfwv1.Action_ACTION_DENY},
		},
		Nat: &openngfwv1.Nat{
			Source: []*openngfwv1.SourceNat{
				{Name: "masq", ToZone: "wan", SourceAddress: "lan-net", Masquerade: true},
			},
			Destination: []*openngfwv1.DestinationNat{
				{Name: "dn", FromZone: "wan", Service: "web", DestinationAddress: "host", TranslatedAddress: "host", TranslatedPort: 8080},
			},
		},
		StaticRoutes: []*openngfwv1.StaticRoute{
			{Destination: "192.168.0.0/16", Via: "10.10.0.1", Metric: 50},
		},
	}
}

func TestCompile(t *testing.T) {
	ir, err := Compile(testPolicy())
	if err != nil {
		t.Fatal(err)
	}

	if len(ir.Rules) != 2 {
		t.Fatalf("want 2 rules (disabled dropped), got %d", len(ir.Rules))
	}
	r1 := ir.Rules[0]
	if got, want := len(r1.FromIfaces), 2; got != want {
		t.Errorf("r1 FromIfaces = %v", r1.FromIfaces)
	}
	if got := r1.SrcPrefixes; len(got) != 1 || got[0] != netip.MustParsePrefix("10.10.0.0/24") {
		t.Errorf("r1 SrcPrefixes = %v", got)
	}
	if len(r1.Services) != 1 || r1.Services[0].Protocol != ProtoTCP {
		t.Errorf("r1 Services = %+v", r1.Services)
	}
	if got := r1.Services[0].Ports; len(got) != 2 || got[0] != (PortRange{80, 80}) || got[1] != (PortRange{8000, 8100}) {
		t.Errorf("r1 ports = %v", got)
	}

	wildcard := ir.Rules[1]
	if wildcard.FromIfaces != nil {
		t.Errorf("wildcard zones should resolve to nil, got %v", wildcard.FromIfaces)
	}
	if wildcard.Action != ActionDeny {
		t.Errorf("wildcard action = %v", wildcard.Action)
	}

	if len(ir.SNAT) != 1 || !ir.SNAT[0].Masquerade || ir.SNAT[0].SrcPrefix == nil {
		t.Errorf("SNAT = %+v", ir.SNAT)
	}
	if len(ir.DNAT) != 1 || ir.DNAT[0].ToPort != 8080 || ir.DNAT[0].Protocol != ProtoTCP {
		t.Errorf("DNAT = %+v", ir.DNAT)
	}
	if len(ir.Routes) != 1 || ir.Routes[0].Metric != 50 || !ir.Routes[0].Via.IsValid() {
		t.Errorf("Routes = %+v", ir.Routes)
	}
}

func TestCompileRejectsInvalidPolicy(t *testing.T) {
	p := testPolicy()
	p.Rules[0].Services = []string{"missing"}
	if _, err := Compile(p); err == nil {
		t.Fatal("expected compile error for invalid policy")
	}
}
