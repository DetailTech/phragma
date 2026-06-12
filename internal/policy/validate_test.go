package policy

import (
	"strings"
	"testing"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func validPolicy() *openngfwv1.Policy {
	return &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{
			{Name: "wan", Interfaces: []string{"eth0"}},
			{Name: "lan", Interfaces: []string{"eth1"}},
		},
		Addresses: []*openngfwv1.Address{
			{Name: "lan-net", Cidr: "10.10.0.0/24"},
			{Name: "web-server", Cidr: "10.10.0.80/32"},
		},
		Services: []*openngfwv1.Service{
			{Name: "web", Protocol: openngfwv1.Protocol_PROTOCOL_TCP, Ports: []*openngfwv1.PortRange{{Start: 80}, {Start: 443}}},
		},
		Rules: []*openngfwv1.Rule{
			{Name: "lan-out", FromZones: []string{"lan"}, ToZones: []string{"wan"}, Action: openngfwv1.Action_ACTION_ALLOW},
		},
		Nat: &openngfwv1.Nat{
			Source: []*openngfwv1.SourceNat{
				{Name: "lan-masq", ToZone: "wan", SourceAddress: "lan-net", Masquerade: true},
			},
		},
		StaticRoutes: []*openngfwv1.StaticRoute{
			{Destination: "192.168.50.0/24", Via: "10.10.0.254"},
		},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*openngfwv1.Policy)
		wantErr string // substring of one expected error; "" = valid
	}{
		{name: "valid policy", mutate: func(*openngfwv1.Policy) {}},
		{
			name:    "duplicate zone",
			mutate:  func(p *openngfwv1.Policy) { p.Zones = append(p.Zones, &openngfwv1.Zone{Name: "wan"}) },
			wantErr: `duplicate zone "wan"`,
		},
		{
			name: "interface in two zones",
			mutate: func(p *openngfwv1.Policy) {
				p.Zones = append(p.Zones, &openngfwv1.Zone{Name: "dmz", Interfaces: []string{"eth0"}})
			},
			wantErr: `interface "eth0" is in both`,
		},
		{
			name:    "bad cidr",
			mutate:  func(p *openngfwv1.Policy) { p.Addresses[0].Cidr = "10.10.0.0" },
			wantErr: "invalid CIDR",
		},
		{
			name:    "reserved name any",
			mutate:  func(p *openngfwv1.Policy) { p.Addresses[0].Name = "any" },
			wantErr: "reserved",
		},
		{
			name:    "uppercase name rejected",
			mutate:  func(p *openngfwv1.Policy) { p.Zones[0].Name = "WAN" },
			wantErr: "invalid",
		},
		{
			name:    "port zero",
			mutate:  func(p *openngfwv1.Policy) { p.Services[0].Ports[0].Start = 0 },
			wantErr: "out of range",
		},
		{
			name:    "inverted range",
			mutate:  func(p *openngfwv1.Policy) { p.Services[0].Ports[0] = &openngfwv1.PortRange{Start: 100, End: 10} },
			wantErr: "invalid port range",
		},
		{
			name: "icmp with ports",
			mutate: func(p *openngfwv1.Policy) {
				p.Services = append(p.Services, &openngfwv1.Service{
					Name: "bad-icmp", Protocol: openngfwv1.Protocol_PROTOCOL_ICMP,
					Ports: []*openngfwv1.PortRange{{Start: 1}},
				})
			},
			wantErr: "cannot have ports",
		},
		{
			name:    "rule unknown zone",
			mutate:  func(p *openngfwv1.Policy) { p.Rules[0].FromZones = []string{"nope"} },
			wantErr: `unknown zone "nope"`,
		},
		{
			name:    "rule unknown service",
			mutate:  func(p *openngfwv1.Policy) { p.Rules[0].Services = []string{"nope"} },
			wantErr: `unknown service "nope"`,
		},
		{
			name:    "rule action unset",
			mutate:  func(p *openngfwv1.Policy) { p.Rules[0].Action = openngfwv1.Action_ACTION_UNSPECIFIED },
			wantErr: "action must be set",
		},
		{
			name:    "rule wildcard zones ok",
			mutate:  func(p *openngfwv1.Policy) { p.Rules[0].FromZones = []string{"any"} },
			wantErr: "",
		},
		{
			name: "snat both masquerade and address",
			mutate: func(p *openngfwv1.Policy) {
				p.Nat.Source[0].TranslatedAddress = "web-server"
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "snat translated address must be host",
			mutate: func(p *openngfwv1.Policy) {
				p.Nat.Source[0].Masquerade = false
				p.Nat.Source[0].TranslatedAddress = "lan-net"
			},
			wantErr: "must be a /32 or /128",
		},
		{
			name: "dnat requires tcp or udp service",
			mutate: func(p *openngfwv1.Policy) {
				p.Services = append(p.Services, &openngfwv1.Service{Name: "anyproto", Protocol: openngfwv1.Protocol_PROTOCOL_ANY})
				p.Nat.Destination = []*openngfwv1.DestinationNat{{
					Name: "bad", FromZone: "wan", Service: "anyproto",
					DestinationAddress: "web-server", TranslatedAddress: "web-server",
				}}
			},
			wantErr: "must be TCP or UDP",
		},
		{
			name:    "route needs via or interface",
			mutate:  func(p *openngfwv1.Policy) { p.StaticRoutes[0].Via = "" },
			wantErr: "one of via or interface",
		},
		{
			name:    "route bad destination",
			mutate:  func(p *openngfwv1.Policy) { p.StaticRoutes[0].Destination = "not-a-cidr" },
			wantErr: "invalid destination CIDR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validPolicy()
			tt.mutate(p)
			errs := Validate(p)
			if tt.wantErr == "" {
				if len(errs) > 0 {
					t.Fatalf("expected valid, got errors: %v", errs)
				}
				return
			}
			found := false
			for _, e := range errs {
				if strings.Contains(e, tt.wantErr) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected an error containing %q, got: %v", tt.wantErr, errs)
			}
		})
	}
}

func TestValidateNilPolicy(t *testing.T) {
	if errs := Validate(nil); len(errs) != 1 {
		t.Fatalf("expected one error for nil policy, got %v", errs)
	}
}
