package policy

import (
	"fmt"
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
			{Name: "host", Cidr: "10.10.0.90/32"},
		},
		Services: []*openngfwv1.Service{
			{Name: "web", Protocol: openngfwv1.Protocol_PROTOCOL_TCP, Ports: []*openngfwv1.PortRange{{Start: 80}, {Start: 443}}},
		},
		Rules: []*openngfwv1.Rule{
			{Name: "lan-out", Id: "rule-lan-out", FromZones: []string{"lan"}, ToZones: []string{"wan"}, Action: openngfwv1.Action_ACTION_ALLOW},
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
			name:    "rule id required after normalization boundary",
			mutate:  func(p *openngfwv1.Policy) { p.Rules[0].Id = "" },
			wantErr: "id is required",
		},
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
			name:    "rule id valid",
			mutate:  func(p *openngfwv1.Policy) { p.Rules[0].Id = "rule:lan-out:001" },
			wantErr: "",
		},
		{
			name:    "rule id invalid",
			mutate:  func(p *openngfwv1.Policy) { p.Rules[0].Id = "Rule 1" },
			wantErr: `id "Rule 1" is invalid`,
		},
		{
			name: "rule id duplicate",
			mutate: func(p *openngfwv1.Policy) {
				p.Rules[0].Id = "rule-001"
				p.Rules = append(p.Rules, &openngfwv1.Rule{
					Name:   "lan-out-renamed",
					Id:     "rule-001",
					Action: openngfwv1.Action_ACTION_DENY,
				})
			},
			wantErr: `duplicate rule id "rule-001"`,
		},
		{
			name:    "rule wildcard zones ok",
			mutate:  func(p *openngfwv1.Policy) { p.Rules[0].FromZones = []string{"any"} },
			wantErr: "",
		},
		{
			name: "rule tags valid",
			mutate: func(p *openngfwv1.Policy) {
				p.Rules[0].Tags = []string{"env:prod", "owner_secops", "pci.zone-1"}
			},
		},
		{
			name: "rule match context valid",
			mutate: func(p *openngfwv1.Policy) {
				p.Rules[0].MatchContext = &openngfwv1.RuleMatchContext{
					Users:         []string{"alice@example.com"},
					Groups:        []string{"idp/secops"},
					Devices:       []string{"device:managed-laptop"},
					PostureLabels: []string{"posture:edr-healthy"},
				}
			},
		},
		{
			name: "rule match context rejects wildcard",
			mutate: func(p *openngfwv1.Policy) {
				p.Rules[0].MatchContext = &openngfwv1.RuleMatchContext{Users: []string{"any"}}
			},
			wantErr: `match_context.users must use explicit labels`,
		},
		{
			name: "rule match context rejects invalid label",
			mutate: func(p *openngfwv1.Policy) {
				p.Rules[0].MatchContext = &openngfwv1.RuleMatchContext{Groups: []string{"Domain Users"}}
			},
			wantErr: `match_context.groups value "Domain Users" is invalid`,
		},
		{
			name: "rule match context rejects duplicates",
			mutate: func(p *openngfwv1.Policy) {
				p.Rules[0].MatchContext = &openngfwv1.RuleMatchContext{Devices: []string{"device-1", "device-1"}}
			},
			wantErr: `duplicate match_context.devices value "device-1"`,
		},
		{
			name: "rule tag invalid",
			mutate: func(p *openngfwv1.Policy) {
				p.Rules[0].Tags = []string{"Needs Review"}
			},
			wantErr: "tag \"Needs Review\" is invalid",
		},
		{
			name: "rule tag duplicate",
			mutate: func(p *openngfwv1.Policy) {
				p.Rules[0].Tags = []string{"env:prod", "env:prod"}
			},
			wantErr: "duplicate tag \"env:prod\"",
		},
		{
			name: "rule tag limit",
			mutate: func(p *openngfwv1.Policy) {
				for i := 0; i <= maxRuleTags; i++ {
					p.Rules[0].Tags = append(p.Rules[0].Tags, fmt.Sprintf("tag-%02d", i))
				}
			},
			wantErr: "too many tags",
		},
		{
			name: "security profile rule reference valid",
			mutate: func(p *openngfwv1.Policy) {
				p.SecurityProfiles = []*openngfwv1.SecurityProfile{{
					Name:          "inspect-standard",
					TlsInspection: openngfwv1.TlsInspectionMode_TLS_INSPECTION_MODE_METADATA_ONLY,
					UrlCategories: []string{"malware", "phishing"},
					DnsSecurity:   openngfwv1.DnsSecurityMode_DNS_SECURITY_MODE_BLOCK_MALICIOUS,
					FileSecurity:  openngfwv1.FileSecurityMode_FILE_SECURITY_MODE_LOG_ONLY,
				}}
				p.Ids = &openngfwv1.Ids{
					Enabled:         true,
					Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
					FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED,
				}
				p.Rules[0].SecurityProfiles = []string{"inspect-standard"}
			},
		},
		{
			name: "metadata only security profile rule reference does not require ips prevent",
			mutate: func(p *openngfwv1.Policy) {
				p.SecurityProfiles = []*openngfwv1.SecurityProfile{{
					Name:          "observe-tls",
					TlsInspection: openngfwv1.TlsInspectionMode_TLS_INSPECTION_MODE_METADATA_ONLY,
					DnsSecurity:   openngfwv1.DnsSecurityMode_DNS_SECURITY_MODE_LOG_ONLY,
					FileSecurity:  openngfwv1.FileSecurityMode_FILE_SECURITY_MODE_LOG_ONLY,
				}}
				p.Rules[0].SecurityProfiles = []string{"observe-tls"}
			},
		},
		{
			name: "blocking security profile on allow requires fail closed ips",
			mutate: func(p *openngfwv1.Policy) {
				p.SecurityProfiles = []*openngfwv1.SecurityProfile{{
					Name:        "block-malicious-dns",
					DnsSecurity: openngfwv1.DnsSecurityMode_DNS_SECURITY_MODE_BLOCK_MALICIOUS,
				}}
				p.Ids = &openngfwv1.Ids{
					Enabled:         true,
					Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
					FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_OPEN,
				}
				p.Rules[0].SecurityProfiles = []string{"block-malicious-dns"}
			},
			wantErr: "blocking security profiles on ACTION_ALLOW rules require ids enabled with mode IDS_MODE_PREVENT and failure_behavior IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
		},
		{
			name: "duplicate security profile",
			mutate: func(p *openngfwv1.Policy) {
				p.SecurityProfiles = []*openngfwv1.SecurityProfile{{Name: "inspect-standard"}, {Name: "inspect-standard"}}
			},
			wantErr: `duplicate security profile "inspect-standard"`,
		},
		{
			name: "security profile duplicate url category",
			mutate: func(p *openngfwv1.Policy) {
				p.SecurityProfiles = []*openngfwv1.SecurityProfile{{
					Name:          "inspect-standard",
					UrlCategories: []string{"malware", "malware"},
				}}
			},
			wantErr: `duplicate url category "malware"`,
		},
		{
			name: "security profile decrypt intent requires description",
			mutate: func(p *openngfwv1.Policy) {
				p.SecurityProfiles = []*openngfwv1.SecurityProfile{{
					Name:          "decrypt-intent",
					TlsInspection: openngfwv1.TlsInspectionMode_TLS_INSPECTION_MODE_DECRYPTION_REQUIRED,
				}}
			},
			wantErr: "need a description",
		},
		{
			name: "rule security profile unknown reference",
			mutate: func(p *openngfwv1.Policy) {
				p.Rules[0].SecurityProfiles = []string{"missing-profile"}
			},
			wantErr: `unknown security profile "missing-profile"`,
		},
		{
			name: "rule security profile rejects any",
			mutate: func(p *openngfwv1.Policy) {
				p.Rules[0].SecurityProfiles = []string{"any"}
			},
			wantErr: "security profiles must name explicit",
		},
		{
			name: "custom application valid",
			mutate: func(p *openngfwv1.Policy) {
				p.Applications = []*openngfwv1.Application{{
					Name:          "corp-admin",
					DisplayName:   "Corporate Admin",
					Category:      "business-app",
					EngineSignals: []string{"http"},
					Ports: []*openngfwv1.ApplicationPort{{
						Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
						Ports:    []*openngfwv1.PortRange{{Start: 8443}},
					}},
				}}
			},
		},
		{
			name: "application deny rule valid with port hint",
			mutate: func(p *openngfwv1.Policy) {
				p.Applications = []*openngfwv1.Application{{
					Name:     "corp-admin",
					Category: "business-app",
					Ports: []*openngfwv1.ApplicationPort{{
						Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
						Ports:    []*openngfwv1.PortRange{{Start: 8443}},
					}},
				}}
				p.Rules = append([]*openngfwv1.Rule{{
					Name:         "block-corp-admin",
					Id:           "rule-block-corp-admin",
					FromZones:    []string{"lan"},
					ToZones:      []string{"wan"},
					Applications: []string{"corp-admin"},
					Action:       openngfwv1.Action_ACTION_DENY,
				}}, p.Rules...)
			},
		},
		{
			name: "application rule unknown reference",
			mutate: func(p *openngfwv1.Policy) {
				p.Rules[0].Applications = []string{"missing-app"}
				p.Rules[0].Action = openngfwv1.Action_ACTION_DENY
			},
			wantErr: `unknown application "missing-app"`,
		},
		{
			name: "application rule allow with port hints valid",
			mutate: func(p *openngfwv1.Policy) {
				p.Applications = []*openngfwv1.Application{{
					Name:     "corp-admin",
					Category: "business-app",
					Ports: []*openngfwv1.ApplicationPort{{
						Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
						Ports:    []*openngfwv1.PortRange{{Start: 8443}},
					}},
				}}
				p.Rules[0].Applications = []string{"corp-admin"}
				p.Rules[0].Services = nil
			},
		},
		{
			name: "application rule with service rejected",
			mutate: func(p *openngfwv1.Policy) {
				p.Applications = []*openngfwv1.Application{{
					Name:     "corp-admin",
					Category: "business-app",
					Ports: []*openngfwv1.ApplicationPort{{
						Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
						Ports:    []*openngfwv1.PortRange{{Start: 8443}},
					}},
				}}
				p.Rules[0].Action = openngfwv1.Action_ACTION_DENY
				p.Rules[0].Applications = []string{"corp-admin"}
				p.Rules[0].Services = []string{"web"}
			},
			wantErr: "services and applications cannot be combined",
		},
		{
			name: "application rule engine signal only valid with fail closed ips prevent",
			mutate: func(p *openngfwv1.Policy) {
				p.Applications = []*openngfwv1.Application{{
					Name:          "corp-admin",
					Category:      "business-app",
					EngineSignals: []string{"http"},
				}}
				p.Ids = &openngfwv1.Ids{
					Enabled:         true,
					Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
					FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED,
				}
				p.Rules = []*openngfwv1.Rule{{
					Name:         "block-corp-admin",
					Id:           "rule-block-corp-admin",
					Applications: []string{"corp-admin"},
					Action:       openngfwv1.Action_ACTION_DENY,
				}}
			},
		},
		{
			name: "application rule engine signal only requires ids enabled",
			mutate: func(p *openngfwv1.Policy) {
				p.Applications = []*openngfwv1.Application{{
					Name:          "corp-admin",
					Category:      "business-app",
					EngineSignals: []string{"http"},
				}}
				p.Rules = []*openngfwv1.Rule{{
					Name:         "block-corp-admin",
					Id:           "rule-block-corp-admin",
					Applications: []string{"corp-admin"},
					Action:       openngfwv1.Action_ACTION_DENY,
				}}
			},
			wantErr: "engine-signal-only App-ID enforcement requires ids enabled with mode IDS_MODE_PREVENT and failure_behavior IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
		},
		{
			name: "application rule engine signal only requires prevent mode",
			mutate: func(p *openngfwv1.Policy) {
				p.Applications = []*openngfwv1.Application{{
					Name:          "corp-admin",
					Category:      "business-app",
					EngineSignals: []string{"http"},
				}}
				p.Ids = &openngfwv1.Ids{
					Enabled: true,
					Mode:    openngfwv1.IdsMode_IDS_MODE_DETECT,
				}
				p.Rules = []*openngfwv1.Rule{{
					Name:         "block-corp-admin",
					Id:           "rule-block-corp-admin",
					Applications: []string{"corp-admin"},
					Action:       openngfwv1.Action_ACTION_DENY,
				}}
			},
			wantErr: "engine-signal-only App-ID enforcement requires ids enabled with mode IDS_MODE_PREVENT and failure_behavior IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
		},
		{
			name: "application rule engine signal only requires fail closed",
			mutate: func(p *openngfwv1.Policy) {
				p.Applications = []*openngfwv1.Application{{
					Name:          "corp-admin",
					Category:      "business-app",
					EngineSignals: []string{"http"},
				}}
				p.Ids = &openngfwv1.Ids{
					Enabled:         true,
					Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
					FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_OPEN,
				}
				p.Rules = []*openngfwv1.Rule{{
					Name:         "block-corp-admin",
					Id:           "rule-block-corp-admin",
					Applications: []string{"corp-admin"},
					Action:       openngfwv1.Action_ACTION_DENY,
				}}
			},
			wantErr: "engine-signal-only App-ID enforcement requires ids enabled with mode IDS_MODE_PREVENT and failure_behavior IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
		},
		{
			name: "application rule engine signal only rejects services",
			mutate: func(p *openngfwv1.Policy) {
				p.Applications = []*openngfwv1.Application{{
					Name:          "corp-admin",
					Category:      "business-app",
					EngineSignals: []string{"http"},
				}}
				p.Ids = &openngfwv1.Ids{
					Enabled:         true,
					Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
					FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED,
				}
				p.Rules = []*openngfwv1.Rule{{
					Name:         "block-corp-admin",
					Id:           "rule-block-corp-admin",
					Applications: []string{"corp-admin"},
					Services:     []string{"web"},
					Action:       openngfwv1.Action_ACTION_DENY,
				}}
			},
			wantErr: "services and applications cannot be combined",
		},
		{
			name: "application rule engine signal only rejects zone-only scope",
			mutate: func(p *openngfwv1.Policy) {
				p.Applications = []*openngfwv1.Application{{
					Name:          "corp-admin",
					Category:      "business-app",
					EngineSignals: []string{"http"},
				}}
				p.Ids = &openngfwv1.Ids{
					Enabled:         true,
					Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
					FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED,
				}
				p.Rules = []*openngfwv1.Rule{{
					Name:         "block-corp-admin",
					Id:           "rule-block-corp-admin",
					FromZones:    []string{"lan"},
					ToZones:      []string{"wan"},
					Applications: []string{"corp-admin"},
					Action:       openngfwv1.Action_ACTION_DENY,
				}}
			},
			wantErr: "signal-only App-ID rules cannot be scoped only by From/To zones",
		},
		{
			name: "application rule engine signal only accepts address scope",
			mutate: func(p *openngfwv1.Policy) {
				p.Applications = []*openngfwv1.Application{{
					Name:          "corp-admin",
					Category:      "business-app",
					EngineSignals: []string{"http"},
				}}
				p.Ids = &openngfwv1.Ids{
					Enabled:         true,
					Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
					FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED,
				}
				p.Rules = []*openngfwv1.Rule{{
					Name:                 "block-corp-admin",
					Id:                   "rule-block-corp-admin",
					SourceAddresses:      []string{"lan-net"},
					DestinationAddresses: []string{"web-server"},
					Applications:         []string{"corp-admin"},
					Action:               openngfwv1.Action_ACTION_DENY,
				}}
			},
		},
		{
			name: "application rule signal-only allow requires port hints",
			mutate: func(p *openngfwv1.Policy) {
				p.Applications = []*openngfwv1.Application{{
					Name:          "corp-admin",
					Category:      "business-app",
					EngineSignals: []string{"http"},
				}}
				p.Ids = &openngfwv1.Ids{
					Enabled:         true,
					Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
					FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED,
				}
				p.Rules = []*openngfwv1.Rule{{
					Name:         "allow-corp-admin",
					Applications: []string{"corp-admin"},
					Action:       openngfwv1.Action_ACTION_ALLOW,
				}}
			},
			wantErr: "signal-only App-ID allow requires TCP/UDP port hints",
		},
		{
			name: "duplicate application",
			mutate: func(p *openngfwv1.Policy) {
				p.Applications = []*openngfwv1.Application{{Name: "corp-admin", Category: "business-app", EngineSignals: []string{"corp-admin"}}, {Name: "corp-admin", Category: "business-app", EngineSignals: []string{"corp-admin-alt"}}}
			},
			wantErr: `duplicate application "corp-admin"`,
		},
		{
			name: "application requires category",
			mutate: func(p *openngfwv1.Policy) {
				p.Applications = []*openngfwv1.Application{{Name: "corp-admin", EngineSignals: []string{"corp-admin"}}}
			},
			wantErr: "category must be set",
		},
		{
			name: "application requires signal or port",
			mutate: func(p *openngfwv1.Policy) {
				p.Applications = []*openngfwv1.Application{{Name: "corp-admin", Category: "business-app"}}
			},
			wantErr: "at least one engine_signal or port hint is required",
		},
		{
			name: "application signal invalid",
			mutate: func(p *openngfwv1.Policy) {
				p.Applications = []*openngfwv1.Application{{Name: "corp-admin", Category: "business-app", EngineSignals: []string{"Corp Admin"}}}
			},
			wantErr: "engine_signal",
		},
		{
			name: "application port requires tcp or udp",
			mutate: func(p *openngfwv1.Policy) {
				p.Applications = []*openngfwv1.Application{{
					Name:     "corp-admin",
					Category: "business-app",
					Ports: []*openngfwv1.ApplicationPort{{
						Protocol: openngfwv1.Protocol_PROTOCOL_ICMP,
						Ports:    []*openngfwv1.PortRange{{Start: 8443}},
					}},
				}}
			},
			wantErr: "protocol must be TCP or UDP",
		},
		{
			name: "application port range invalid",
			mutate: func(p *openngfwv1.Policy) {
				p.Applications = []*openngfwv1.Application{{
					Name:     "corp-admin",
					Category: "business-app",
					Ports: []*openngfwv1.ApplicationPort{{
						Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
						Ports:    []*openngfwv1.PortRange{{Start: 9000, End: 8000}},
					}},
				}}
			},
			wantErr: "invalid port range",
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
		{
			name: "ids prevent requires failure behavior",
			mutate: func(p *openngfwv1.Policy) {
				p.Ids = &openngfwv1.Ids{Enabled: true, Mode: openngfwv1.IdsMode_IDS_MODE_PREVENT}
			},
			wantErr: "failure_behavior must be set",
		},
		{
			name: "ids prevent fail closed valid",
			mutate: func(p *openngfwv1.Policy) {
				p.Ids = &openngfwv1.Ids{
					Enabled: true, Mode: openngfwv1.IdsMode_IDS_MODE_PREVENT,
					FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED,
				}
			},
		},
		{
			name: "ids failure behavior detect rejected",
			mutate: func(p *openngfwv1.Policy) {
				p.Ids = &openngfwv1.Ids{
					Enabled: true, Mode: openngfwv1.IdsMode_IDS_MODE_DETECT,
					FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_OPEN,
				}
			},
			wantErr: "failure_behavior applies only",
		},
		{
			name: "ids exception source scope valid",
			mutate: func(p *openngfwv1.Policy) {
				p.Ids = &openngfwv1.Ids{
					Enabled: true,
					Mode:    openngfwv1.IdsMode_IDS_MODE_DETECT,
					Exceptions: []*openngfwv1.IdsException{{
						Name: "fp-web-test", SignatureId: 9000001, ThreatId: "openngfw.test",
						SourceAddress: "lan-net", Description: "lab false positive",
						Owner: "secops-oncall", TicketId: "INC-2026-001", ReviewDate: "2026-07-01",
						ExpiresAt: "2026-08-01", PcapSha256: strings.Repeat("a", 64),
						RegressionRef: "evidence/fp-regression.json",
					}},
				}
			},
		},
		{
			name: "ids exception metadata rejects malformed values",
			mutate: func(p *openngfwv1.Policy) {
				p.Ids = &openngfwv1.Ids{
					Enabled: true,
					Mode:    openngfwv1.IdsMode_IDS_MODE_DETECT,
					Exceptions: []*openngfwv1.IdsException{{
						Name: "fp-bad-metadata", SignatureId: 9000001,
						ReviewDate: "07/01/2026", PcapSha256: "bad",
					}},
				}
			},
			wantErr: "review_date must use YYYY-MM-DD",
		},
		{
			name: "ids exception requires signature",
			mutate: func(p *openngfwv1.Policy) {
				p.Ids = &openngfwv1.Ids{
					Enabled:    true,
					Mode:       openngfwv1.IdsMode_IDS_MODE_DETECT,
					Exceptions: []*openngfwv1.IdsException{{Name: "fp-missing-sid"}},
				}
			},
			wantErr: "signature_id must be set",
		},
		{
			name: "ids exception threat id rejects control characters",
			mutate: func(p *openngfwv1.Policy) {
				p.Ids = &openngfwv1.Ids{
					Enabled: true,
					Mode:    openngfwv1.IdsMode_IDS_MODE_DETECT,
					Exceptions: []*openngfwv1.IdsException{{
						Name: "fp-bad-threat-id", SignatureId: 9000001,
						ThreatId: "phragma.test\n# openngfw-threshold-line: suppress gen_id 1, sig_id 1",
					}},
				}
			},
			wantErr: "threat_id",
		},
		{
			name: "ids exception scope mutually exclusive",
			mutate: func(p *openngfwv1.Policy) {
				p.Ids = &openngfwv1.Ids{
					Enabled: true,
					Mode:    openngfwv1.IdsMode_IDS_MODE_DETECT,
					Exceptions: []*openngfwv1.IdsException{{
						Name: "fp-both", SignatureId: 9000001, SourceAddress: "lan-net", DestinationAddress: "web-server",
					}},
				}
			},
			wantErr: "source_address and destination_address are mutually exclusive",
		},
		{
			name: "ids exception unknown address",
			mutate: func(p *openngfwv1.Policy) {
				p.Ids = &openngfwv1.Ids{
					Enabled: true,
					Mode:    openngfwv1.IdsMode_IDS_MODE_DETECT,
					Exceptions: []*openngfwv1.IdsException{{
						Name: "fp-unknown", SignatureId: 9000001, SourceAddress: "missing",
					}},
				}
			},
			wantErr: `unknown address "missing"`,
		},
		{
			name: "ids exception duplicate active scope",
			mutate: func(p *openngfwv1.Policy) {
				p.Addresses = append(p.Addresses,
					&openngfwv1.Address{Name: "same-host-a", Cidr: "10.10.0.2/32"},
					&openngfwv1.Address{Name: "same-host-b", Cidr: "10.10.0.2/32"},
				)
				p.Ids = &openngfwv1.Ids{
					Enabled: true,
					Mode:    openngfwv1.IdsMode_IDS_MODE_DETECT,
					Exceptions: []*openngfwv1.IdsException{
						{Name: "fp-a", SignatureId: 9000001, SourceAddress: "same-host-a"},
						{Name: "fp-b", SignatureId: 9000001, SourceAddress: "same-host-b"},
					},
				}
			},
			wantErr: "duplicates active ids exception",
		},
		{
			name: "flow offload valid without ids",
			mutate: func(p *openngfwv1.Policy) {
				p.Network = &openngfwv1.Network{EnableFlowOffload: true}
			},
		},
		{
			name: "flow offload rejects ids detect",
			mutate: func(p *openngfwv1.Policy) {
				p.Network = &openngfwv1.Network{EnableFlowOffload: true}
				p.Ids = &openngfwv1.Ids{Enabled: true, Mode: openngfwv1.IdsMode_IDS_MODE_DETECT}
			},
			wantErr: "enable_flow_offload cannot be used with IDS/IPS enabled",
		},
		{
			name: "flow offload requires zone interfaces",
			mutate: func(p *openngfwv1.Policy) {
				p.Network = &openngfwv1.Network{EnableFlowOffload: true}
				for _, z := range p.Zones {
					z.Interfaces = nil
				}
			},
			wantErr: "enable_flow_offload requires at least one zone interface",
		},
		{
			name: "bgp neighbor description rejects rendered config injection",
			mutate: func(p *openngfwv1.Policy) {
				p.Routing = &openngfwv1.Routing{Bgp: &openngfwv1.Bgp{
					Enabled:  true,
					Asn:      65001,
					RouterId: "192.0.2.1",
					Neighbors: []*openngfwv1.BgpNeighbor{{
						Address: "198.51.100.2", RemoteAsn: 65002,
						Description: "upstream\nneighbor 203.0.113.9 remote-as 65009",
					}},
				}}
			},
			wantErr: "description must not contain control characters",
		},
		{
			name: "ipsec psk path must stay under managed secret roots",
			mutate: func(p *openngfwv1.Policy) {
				p.Vpn = &openngfwv1.Vpn{IpsecTunnels: []*openngfwv1.IpsecTunnel{{
					Name: "site-b", RemoteAddress: "203.0.113.1",
					LocalSubnets: []string{"10.10.0.0/24"}, RemoteSubnets: []string{"10.20.0.0/24"},
					PskFile: "/tmp/site-b.conf",
				}}}
			},
			wantErr: "psk_file must be under",
		},
		{
			name: "ipsec psk path rejects traversal",
			mutate: func(p *openngfwv1.Policy) {
				p.Vpn = &openngfwv1.Vpn{IpsecTunnels: []*openngfwv1.IpsecTunnel{{
					Name: "site-b", RemoteAddress: "203.0.113.1",
					LocalSubnets: []string{"10.10.0.0/24"}, RemoteSubnets: []string{"10.20.0.0/24"},
					PskFile: "/etc/phragma/secrets/../site-b.conf",
				}}}
			},
			wantErr: "psk_file must be normalized",
		},
		{
			name: "ipsec proposal rejects rendered config injection",
			mutate: func(p *openngfwv1.Policy) {
				p.Vpn = &openngfwv1.Vpn{IpsecTunnels: []*openngfwv1.IpsecTunnel{{
					Name: "site-b", RemoteAddress: "203.0.113.1",
					LocalSubnets: []string{"10.10.0.0/24"}, RemoteSubnets: []string{"10.20.0.0/24"},
					PskFile:     "/etc/phragma/secrets/site-b.conf",
					IkeProposal: "aes256-sha256-modp2048\nchildren { bad {",
				}}}
			},
			wantErr: "ike_proposal contains characters unsafe",
		},
		{
			name: "wireguard key path must stay under managed key roots",
			mutate: func(p *openngfwv1.Policy) {
				p.Vpn = &openngfwv1.Vpn{WireguardInterfaces: []*openngfwv1.WireguardInterface{{
					Name: "wg0", Address: "10.99.0.1/24", PrivateKeyFile: "/tmp/wg0.key",
					Peers: []*openngfwv1.WireguardPeer{{
						Name: "laptop", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
						AllowedIps: []string{"10.99.0.2/32"},
					}},
				}}}
			},
			wantErr: "private_key_file must be under",
		},
		{
			name: "wireguard interface rejects rendered config injection",
			mutate: func(p *openngfwv1.Policy) {
				p.Vpn = &openngfwv1.Vpn{WireguardInterfaces: []*openngfwv1.WireguardInterface{{
					Name: "wg0\ninterface wg1", Address: "10.99.0.1/24", PrivateKeyFile: "/etc/phragma/keys/wg0.key",
				}}}
			},
			wantErr: "invalid interface name",
		},
		{
			name: "vpn managed secret roots valid",
			mutate: func(p *openngfwv1.Policy) {
				p.Vpn = &openngfwv1.Vpn{
					IpsecTunnels: []*openngfwv1.IpsecTunnel{{
						Name: "site-b", LocalAddress: "%any", RemoteAddress: "203.0.113.1",
						LocalSubnets: []string{"10.10.0.0/24"}, RemoteSubnets: []string{"10.20.0.0/24"},
						PskFile: "/etc/phragma/secrets/site-b.conf",
					}},
					WireguardInterfaces: []*openngfwv1.WireguardInterface{{
						Name: "wg0", Address: "10.99.0.1/24", PrivateKeyFile: "/etc/openngfw/keys/wg0.key",
						Peers: []*openngfwv1.WireguardPeer{{
							Name: "laptop", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
							Endpoint: "203.0.113.5:51820", AllowedIps: []string{"10.99.0.2/32"},
						}},
					}},
				}
			},
		},
		{
			name: "host input default deny valid",
			mutate: func(p *openngfwv1.Policy) {
				p.Services = append(p.Services, &openngfwv1.Service{
					Name: "ssh", Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
					Ports: []*openngfwv1.PortRange{{Start: 22}},
				})
				p.HostInput = &openngfwv1.HostInput{
					DefaultAction: openngfwv1.Action_ACTION_DENY,
					Rules: []*openngfwv1.HostInputRule{{
						Name: "allow-lan-ssh", FromZones: []string{"lan"}, Services: []string{"ssh"},
						Action: openngfwv1.Action_ACTION_ALLOW,
					}},
				}
			},
		},
		{
			name: "host input default deny requires allow rule",
			mutate: func(p *openngfwv1.Policy) {
				p.HostInput = &openngfwv1.HostInput{DefaultAction: openngfwv1.Action_ACTION_DENY}
			},
			wantErr: "requires at least one enabled ACTION_ALLOW host-input rule",
		},
		{
			name: "host input default deny ignores disabled allow",
			mutate: func(p *openngfwv1.Policy) {
				p.HostInput = &openngfwv1.HostInput{
					DefaultAction: openngfwv1.Action_ACTION_DENY,
					Rules: []*openngfwv1.HostInputRule{{
						Name: "disabled-allow", Action: openngfwv1.Action_ACTION_ALLOW, Disabled: true,
					}},
				}
			},
			wantErr: "requires at least one enabled ACTION_ALLOW host-input rule",
		},
		{
			name: "host input default deny ignores deny-only rules",
			mutate: func(p *openngfwv1.Policy) {
				p.HostInput = &openngfwv1.HostInput{
					DefaultAction: openngfwv1.Action_ACTION_DENY,
					Rules: []*openngfwv1.HostInputRule{{
						Name: "deny-wan", Action: openngfwv1.Action_ACTION_DENY,
					}},
				}
			},
			wantErr: "requires at least one enabled ACTION_ALLOW host-input rule",
		},
		{
			name: "host input default reject rejected",
			mutate: func(p *openngfwv1.Policy) {
				p.HostInput = &openngfwv1.HostInput{DefaultAction: openngfwv1.Action_ACTION_REJECT}
			},
			wantErr: "host_input: default_action must be ACTION_ALLOW or ACTION_DENY",
		},
		{
			name: "host input unknown zone",
			mutate: func(p *openngfwv1.Policy) {
				p.HostInput = &openngfwv1.HostInput{Rules: []*openngfwv1.HostInputRule{{
					Name: "bad", FromZones: []string{"mgmt"}, Action: openngfwv1.Action_ACTION_ALLOW,
				}}}
			},
			wantErr: `unknown zone "mgmt"`,
		},
		{
			name: "host input unknown service",
			mutate: func(p *openngfwv1.Policy) {
				p.HostInput = &openngfwv1.HostInput{Rules: []*openngfwv1.HostInputRule{{
					Name: "bad", Services: []string{"ssh"}, Action: openngfwv1.Action_ACTION_ALLOW,
				}}}
			},
			wantErr: `unknown service "ssh"`,
		},
		{
			name: "host input action unset",
			mutate: func(p *openngfwv1.Policy) {
				p.HostInput = &openngfwv1.HostInput{Rules: []*openngfwv1.HostInputRule{{Name: "bad"}}}
			},
			wantErr: "host-input rule \"bad\": action must be set",
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

func TestValidateTelemetryClickHouseURLAllowsCredentialFreeEndpoint(t *testing.T) {
	p := validPolicy()
	p.Telemetry = &openngfwv1.Telemetry{
		Enabled:       true,
		ClickhouseUrl: "https://clickhouse.example:8443/ingest?cluster=prod",
		Database:      "openngfw",
	}
	if errs := Validate(p); len(errs) > 0 {
		t.Fatalf("expected credential-free ClickHouse URL to be valid, got: %v", errs)
	}
}

func TestValidateTelemetryClickHouseURLRejectsCredentials(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{
			name:    "userinfo password",
			url:     "https://writer:secret@clickhouse.example:8443",
			wantErr: "must not include URL userinfo",
		},
		{
			name:    "token query",
			url:     "https://clickhouse.example:8443?token=secret",
			wantErr: `sensitive query parameter "token"`,
		},
		{
			name:    "api key query",
			url:     "https://clickhouse.example:8443?api_key=secret",
			wantErr: `sensitive query parameter "api_key"`,
		},
		{
			name:    "access token query",
			url:     "https://clickhouse.example:8443?access_token=secret",
			wantErr: `sensitive query parameter "access_token"`,
		},
		{
			name:    "semicolon access token query",
			url:     "https://clickhouse.example:8443?cluster=prod;access_token=secret",
			wantErr: `sensitive query parameter "access_token"`,
		},
		{
			name:    "generic key query",
			url:     "https://clickhouse.example:8443?key=secret",
			wantErr: `sensitive query parameter "key"`,
		},
		{
			name:    "password query",
			url:     "https://clickhouse.example:8443?clickhouse_password=secret",
			wantErr: `sensitive query parameter "clickhouse_password"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validPolicy()
			p.Telemetry = &openngfwv1.Telemetry{
				Enabled:       true,
				ClickhouseUrl: tt.url,
				Database:      "openngfw",
			}
			errs := Validate(p)
			found := false
			for _, err := range errs {
				if strings.Contains(err, tt.wantErr) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErr, errs)
			}
		})
	}
}

func TestValidateTelemetryClickHouseURLRedactsInvalidURL(t *testing.T) {
	p := validPolicy()
	p.Telemetry = &openngfwv1.Telemetry{
		Enabled:       true,
		ClickhouseUrl: "clickhouse://writer:secret@clickhouse.example:9000",
		Database:      "openngfw",
	}
	errs := Validate(p)
	joined := strings.Join(errs, "\n")
	if !strings.Contains(joined, "telemetry: clickhouse_url must be an http(s) URL") {
		t.Fatalf("expected invalid clickhouse_url error, got: %v", errs)
	}
	for _, leaked := range []string{"writer", "secret", "clickhouse.example:9000", "clickhouse://"} {
		if strings.Contains(joined, leaked) {
			t.Fatalf("validation error leaked %q: %v", leaked, errs)
		}
	}
}

func TestValidateTelemetryExportsAcceptsSafeJSONSinks(t *testing.T) {
	p := validPolicy()
	p.Telemetry = &openngfwv1.Telemetry{
		Enabled: true,
		Exports: []*openngfwv1.TelemetryExport{
			{
				Name:    "local-json",
				Enabled: true,
				Type:    openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_FILE,
				Target:  "/var/log/openngfw/exports/eve-%Y-%m-%d.json",
			},
			{
				Name:    "siem-tcp",
				Enabled: true,
				Type:    openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_TCP,
				Target:  "siem.example:5514",
			},
			{
				Name:    "siem-udp",
				Enabled: true,
				Type:    openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_UDP,
				Target:  "[2001:db8::10]:5514",
			},
		},
	}
	if errs := Validate(p); len(errs) > 0 {
		t.Fatalf("expected safe telemetry exports to be valid, got: %v", errs)
	}
}

func TestValidateTelemetryExportsRejectsUnsafeTargets(t *testing.T) {
	tests := []struct {
		name    string
		export  *openngfwv1.TelemetryExport
		wantErr string
	}{
		{
			name: "duplicate name",
			export: &openngfwv1.TelemetryExport{
				Name:    "local-json",
				Enabled: true,
				Type:    openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_FILE,
				Target:  "/var/log/openngfw/exports/other.json",
			},
			wantErr: "duplicate export name",
		},
		{
			name: "file outside export root",
			export: &openngfwv1.TelemetryExport{
				Name:    "bad-file",
				Enabled: true,
				Type:    openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_FILE,
				Target:  "/etc/openngfw/eve.json",
			},
			wantErr: "file target must stay under /var/log/openngfw/exports/",
		},
		{
			name: "socket url",
			export: &openngfwv1.TelemetryExport{
				Name:    "bad-socket",
				Enabled: true,
				Type:    openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_TCP,
				Target:  "tcp://siem.example:5514",
			},
			wantErr: "socket target must be host:port without whitespace, URL scheme, or path",
		},
		{
			name: "socket missing port",
			export: &openngfwv1.TelemetryExport{
				Name:    "missing-port",
				Enabled: true,
				Type:    openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_UDP,
				Target:  "siem.example",
			},
			wantErr: "socket target must be host:port",
		},
		{
			name: "unspecified type",
			export: &openngfwv1.TelemetryExport{
				Name:    "missing-type",
				Enabled: true,
				Target:  "siem.example:5514",
			},
			wantErr: "type is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validPolicy()
			p.Telemetry = &openngfwv1.Telemetry{
				Enabled: true,
				Exports: []*openngfwv1.TelemetryExport{
					{
						Name:    "local-json",
						Enabled: true,
						Type:    openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_FILE,
						Target:  "/var/log/openngfw/exports/eve.json",
					},
					tt.export,
				},
			}
			errs := Validate(p)
			found := false
			for _, err := range errs {
				if strings.Contains(err, tt.wantErr) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErr, errs)
			}
		})
	}
}

func TestValidateIntelCustomFeedURLRejectsCredentials(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{
			name:    "userinfo password",
			url:     "https://reader:secret@feeds.example.com/blocklist.txt",
			wantErr: "must not include URL userinfo",
		},
		{
			name:    "token query",
			url:     "https://feeds.example.com/blocklist.txt?token=secret",
			wantErr: `sensitive query parameter "token"`,
		},
		{
			name:    "access token query",
			url:     "https://feeds.example.com/blocklist.txt?source=secops;access_token=secret",
			wantErr: `sensitive query parameter "access_token"`,
		},
		{
			name:    "api key query",
			url:     "https://feeds.example.com/blocklist.txt?api_key=secret",
			wantErr: `sensitive query parameter "api_key"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validPolicy()
			p.Intel = &openngfwv1.Intel{
				CustomFeeds: []*openngfwv1.CustomFeed{{
					Name: "corp-feed",
					Url:  tt.url,
				}},
			}
			errs := Validate(p)
			found := false
			for _, err := range errs {
				if strings.Contains(err, tt.wantErr) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErr, errs)
			}
			joined := strings.Join(errs, "\n")
			for _, leaked := range []string{"reader", "secret"} {
				if strings.Contains(joined, leaked) {
					t.Fatalf("validation error leaked %q: %v", leaked, errs)
				}
			}
		})
	}
}

func TestValidateIntelCustomFeedURLAllowsCredentialFreeEndpoint(t *testing.T) {
	p := validPolicy()
	p.Intel = &openngfwv1.Intel{
		CustomFeeds: []*openngfwv1.CustomFeed{{
			Name:        "corp-feed",
			Url:         "https://feeds.example.com/blocklist.txt?source=secops",
			Description: "SecOps curated feed",
		}},
	}
	if errs := Validate(p); len(errs) > 0 {
		t.Fatalf("expected credential-free custom feed URL to be valid, got: %v", errs)
	}
}

func TestValidateProxySurface(t *testing.T) {
	p := validPolicy()
	p.Proxy = validProxyPolicy()
	if errs := Validate(p); len(errs) > 0 {
		t.Fatalf("expected valid proxy policy, got: %v", errs)
	}
}

func TestAnalyzeProxyTrafficPolicyFindings(t *testing.T) {
	p := validPolicy()
	p.Applications = []*openngfwv1.Application{{
		Name:          "corp-admin",
		DisplayName:   "Corp Admin",
		Category:      "business-app",
		EngineSignals: []string{"http"},
		Ports: []*openngfwv1.ApplicationPort{{
			Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
			Ports:    []*openngfwv1.PortRange{{Start: 443}},
		}},
	}}
	p.SecurityProfiles = []*openngfwv1.SecurityProfile{{
		Name:          "web-inspect",
		Description:   "inline web inspection",
		TlsInspection: openngfwv1.TlsInspectionMode_TLS_INSPECTION_MODE_DECRYPTION_REQUIRED,
	}}
	p.Rules = []*openngfwv1.Rule{{
		Name:             "allow-proxy",
		Id:               "rule-allow-proxy",
		FromZones:        []string{"wan"},
		ToZones:          []string{"lan"},
		Services:         []string{"web"},
		Applications:     []string{"corp-admin"},
		SecurityProfiles: []string{"web-inspect"},
		Action:           openngfwv1.Action_ACTION_ALLOW,
	}}
	p.StaticRoutes = []*openngfwv1.StaticRoute{{Destination: "10.20.30.0/24", Via: "10.10.0.254"}}
	p.Proxy = validProxyPolicy()
	p.Proxy.VirtualServices[0].Routes[0].Backends[0].Url = "https://10.20.30.44"

	findings := AnalyzeProxyTrafficPolicy(p)
	joined := fmt.Sprint(findings)
	if !strings.Contains(joined, "listener TCP/443 is reviewable against allow rule") {
		t.Fatalf("expected allow-rule coupling finding, got: %#v", findings)
	}
	if strings.Contains(joined, "no matching allow rule carries an inline inspection") {
		t.Fatalf("did not expect inspection warning with matching profile, got: %#v", findings)
	}
	if strings.Contains(joined, "not covered by configured static routes") {
		t.Fatalf("did not expect route warning for covered backend, got: %#v", findings)
	}
}

func TestAnalyzeProxyTrafficPolicyWarnsOnUncoupledIntent(t *testing.T) {
	p := validPolicy()
	p.Proxy = validProxyPolicy()
	p.Proxy.VirtualServices[0].Routes[0].WafPolicy = ""
	p.Proxy.VirtualServices[0].Routes[0].Backends[0].Url = "https://10.99.0.10"
	p.Rules[0].Services = []string{}
	p.StaticRoutes = nil

	findings := AnalyzeProxyTrafficPolicy(p)
	joined := fmt.Sprint(findings)
	for _, want := range []string{
		"has no enabled ACTION_ALLOW rule",
		"not tied to an App-ID port hint",
		"no matching allow rule carries an inline inspection",
		"has no WAF policy attached",
		"not covered by configured static routes",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected finding containing %q, got: %#v", want, findings)
		}
	}
	if errs := Validate(p); len(errs) > 0 {
		t.Fatalf("policy findings should be non-blocking validation context, got validation errors: %v", errs)
	}
}

func TestValidateProxySurfaceRejectsUnsafePosture(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*openngfwv1.Proxy)
		wantErr string
	}{
		{
			name: "WAF ruleset provenance hash required",
			mutate: func(proxy *openngfwv1.Proxy) {
				proxy.WafPolicies[0].RuleSets[0].Sha256 = ""
			},
			wantErr: "sha256 must be a 64-character hex digest",
		},
		{
			name: "request bodies must be redacted",
			mutate: func(proxy *openngfwv1.Proxy) {
				proxy.WafPolicies[0].RedactRequestBody = false
			},
			wantErr: "redact_request_body must be true",
		},
		{
			name: "unknown WAF reference",
			mutate: func(proxy *openngfwv1.Proxy) {
				proxy.VirtualServices[0].Routes[0].WafPolicy = "missing-waf"
			},
			wantErr: `references unknown WAF policy "missing-waf"`,
		},
		{
			name: "backend mTLS is mandatory",
			mutate: func(proxy *openngfwv1.Proxy) {
				proxy.VirtualServices[0].Routes[0].RequireMtlsToBackend = false
			},
			wantErr: "require_mtls_to_backend must be true",
		},
		{
			name: "backend URL credentials rejected",
			mutate: func(proxy *openngfwv1.Proxy) {
				proxy.VirtualServices[0].Routes[0].Backends[0].Url = "https://user:pass@app.internal"
			},
			wantErr: "url must be http(s) with host only",
		},
		{
			name: "TLS secret reference required",
			mutate: func(proxy *openngfwv1.Proxy) {
				proxy.VirtualServices[0].Listener.TlsSecretRef = ""
			},
			wantErr: "tls_secret_ref is required",
		},
		{
			name: "hostnames are bounded",
			mutate: func(proxy *openngfwv1.Proxy) {
				proxy.VirtualServices[0].Hostnames = []string{"Admin.EXAMPLE.com"}
			},
			wantErr: "must be lowercase",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := validPolicy()
			p.Proxy = validProxyPolicy()
			tt.mutate(p.Proxy)
			errs := Validate(p)
			found := false
			for _, err := range errs {
				if strings.Contains(err, tt.wantErr) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErr, errs)
			}
		})
	}
}

func validProxyPolicy() *openngfwv1.Proxy {
	return &openngfwv1.Proxy{
		WafPolicies: []*openngfwv1.WafPolicy{{
			Name:               "corp-waf",
			Mode:               openngfwv1.WafMode_WAF_MODE_BLOCK,
			RequestBodyLimitKb: 128,
			AuditLogging:       true,
			RedactRequestBody:  true,
			RuleSets: []*openngfwv1.WafRuleSet{{
				Name:    "crs",
				Version: "4.0.0",
				Source:  "owasp-crs",
				Sha256:  strings.Repeat("a", 64),
			}},
		}},
		VirtualServices: []*openngfwv1.VirtualService{{
			Name:      "admin-api",
			Enabled:   true,
			Hostnames: []string{"admin.example.com"},
			Listener: &openngfwv1.ProxyListener{
				BindAddress:  "0.0.0.0",
				Port:         443,
				Tls:          true,
				TlsSecretRef: "vault://openngfw/admin-api",
			},
			Routes: []*openngfwv1.ProxyRoute{{
				Name:                 "api",
				PathPrefix:           "/api",
				WafPolicy:            "corp-waf",
				RequireMtlsToBackend: true,
				Backends: []*openngfwv1.ProxyBackend{{
					Name:   "api-1",
					Url:    "https://api.internal",
					Weight: 100,
				}},
			}},
		}},
	}
}

func TestValidateIntelCustomFeedURLRejectsUnsafeDestinations(t *testing.T) {
	tests := []string{
		"http://localhost/blocklist.txt",
		"http://127.0.0.1/blocklist.txt",
		"http://10.0.0.8/blocklist.txt",
		"http://172.16.0.8/blocklist.txt",
		"http://192.168.1.8/blocklist.txt",
		"http://169.254.169.254/opc/v2/instance/",
		"http://[::1]/blocklist.txt",
		"http://feed.local/blocklist.txt",
		"http://metadata.oraclecloud.com/opc/v2/instance/",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			p := validPolicy()
			p.Intel = &openngfwv1.Intel{
				CustomFeeds: []*openngfwv1.CustomFeed{{
					Name: "corp-feed",
					Url:  raw,
				}},
			}
			errs := Validate(p)
			joined := strings.Join(errs, "\n")
			if !strings.Contains(joined, "must not target loopback, private, link-local, local, or metadata destinations") {
				t.Fatalf("expected unsafe destination error, got: %v", errs)
			}
			if strings.Contains(joined, raw) {
				t.Fatalf("validation error leaked raw URL %q: %v", raw, errs)
			}
		})
	}
}

func TestValidateNilPolicy(t *testing.T) {
	if errs := Validate(nil); len(errs) != 1 {
		t.Fatalf("expected one error for nil policy, got %v", errs)
	}
}

func TestValidateQoSAndZoneProtectionBounds(t *testing.T) {
	p := validPolicy()
	p.QosProfiles = []*openngfwv1.QosProfile{{
		Name:                    "voice-priority",
		MaxBandwidthKbps:        50_000,
		GuaranteedBandwidthKbps: 10_000,
		Priority:                openngfwv1.QosPriority_QOS_PRIORITY_HIGH,
		DscpMark:                46,
		BurstKbytes:             1024,
	}}
	p.ZoneProtectionProfiles = []*openngfwv1.ZoneProtectionProfile{{
		Name:                     "internet-edge",
		Enabled:                  true,
		SynFloodPps:              20_000,
		UdpFloodPps:              50_000,
		IcmpFloodPps:             10_000,
		MaxConcurrentConnections: 1_000_000,
		Action:                   openngfwv1.ZoneProtectionAction_ZONE_PROTECTION_ACTION_ALERT,
		AuditLog:                 true,
	}}
	p.Rules[0].QosProfile = "voice-priority"
	p.Zones[0].ZoneProtectionProfile = "internet-edge"
	if errs := Validate(p); len(errs) != 0 {
		t.Fatalf("valid QoS/zone protection policy got errors: %v", errs)
	}

	p.QosProfiles[0].GuaranteedBandwidthKbps = 60_000
	p.QosProfiles[0].DscpMark = 64
	p.ZoneProtectionProfiles[0].Action = openngfwv1.ZoneProtectionAction_ZONE_PROTECTION_ACTION_UNSPECIFIED
	errs := strings.Join(Validate(p), "\n")
	for _, want := range []string{
		"guaranteed_bandwidth_kbps cannot exceed max_bandwidth_kbps",
		"dscp_mark 64 out of range 0-63",
		"enabled profile requires action ALERT or DROP",
	} {
		if !strings.Contains(errs, want) {
			t.Fatalf("validation errors missing %q:\n%s", want, errs)
		}
	}
}
