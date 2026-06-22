package compiler

import (
	"net/netip"
	"strings"
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

	p := testPolicy()
	p.Rules[0].MatchContext = &openngfwv1.RuleMatchContext{
		Users:         []string{"alice@example.com"},
		Groups:        []string{"idp/secops"},
		Devices:       []string{"laptop-123"},
		PostureLabels: []string{"posture:edr-healthy"},
	}
	irWithContext, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := irWithContext.Rules[0].MatchContext; len(got.Users) != 1 || got.Users[0] != "alice@example.com" || got.Groups[0] != "idp/secops" || got.Devices[0] != "laptop-123" || got.PostureLabels[0] != "posture:edr-healthy" {
		t.Fatalf("compiled match context = %#v", got)
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
	if got := ir.SNAT[0].ID; got == "" || !strings.HasPrefix(got, "snat-masq-") {
		t.Errorf("SNAT ID = %q, want generated snat-masq ID", got)
	}
	if len(ir.DNAT) != 1 || ir.DNAT[0].ToPort != 8080 || ir.DNAT[0].Protocol != ProtoTCP {
		t.Errorf("DNAT = %+v", ir.DNAT)
	}
	if got := ir.DNAT[0].ID; got == "" || !strings.HasPrefix(got, "dnat-dn-") {
		t.Errorf("DNAT ID = %q, want generated dnat-dn ID", got)
	}
	if len(ir.Routes) != 1 || ir.Routes[0].Metric != 50 || !ir.Routes[0].Via.IsValid() {
		t.Errorf("Routes = %+v", ir.Routes)
	}
}

func TestCompileHostInput(t *testing.T) {
	p := testPolicy()
	p.Services = append(p.Services, &openngfwv1.Service{
		Name:     "ssh",
		Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
		Ports:    []*openngfwv1.PortRange{{Start: 22}},
	})
	p.HostInput = &openngfwv1.HostInput{
		DefaultAction: openngfwv1.Action_ACTION_DENY,
		Rules: []*openngfwv1.HostInputRule{
			{
				Name:            "allow-lan-ssh",
				FromZones:       []string{"lan"},
				SourceAddresses: []string{"lan-net"},
				Services:        []string{"ssh"},
				Action:          openngfwv1.Action_ACTION_ALLOW,
				Log:             true,
			},
			{Name: "disabled", Action: openngfwv1.Action_ACTION_ALLOW, Disabled: true},
			{Name: "reject-wan", FromZones: []string{"wan"}, Action: openngfwv1.Action_ACTION_REJECT},
		},
	}

	ir, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if ir.HostInputDefault != ActionDeny {
		t.Fatalf("HostInputDefault = %v, want ActionDeny", ir.HostInputDefault)
	}
	if len(ir.HostInputRules) != 2 {
		t.Fatalf("HostInputRules = %+v, want two active rules", ir.HostInputRules)
	}
	allowSSH := ir.HostInputRules[0]
	if got := allowSSH.FromIfaces; len(got) != 2 || got[0] != "eth1" || got[1] != "eth2" {
		t.Fatalf("allow-lan-ssh FromIfaces = %v, want eth1,eth2", got)
	}
	if got := allowSSH.SrcPrefixes; len(got) != 1 || got[0] != netip.MustParsePrefix("10.10.0.0/24") {
		t.Fatalf("allow-lan-ssh SrcPrefixes = %v", got)
	}
	if len(allowSSH.Services) != 1 || allowSSH.Services[0].Protocol != ProtoTCP || allowSSH.Services[0].Ports[0] != (PortRange{22, 22}) {
		t.Fatalf("allow-lan-ssh Services = %+v", allowSSH.Services)
	}
	if !allowSSH.Log || allowSSH.Action != ActionAllow {
		t.Fatalf("allow-lan-ssh = %+v, want logged allow", allowSSH)
	}
	if got := allowSSH.ID; got == "" || !strings.HasPrefix(got, "host-input-allow-lan-ssh-") {
		t.Fatalf("allow-lan-ssh ID = %q, want generated host-input ID", got)
	}
	if ir.HostInputRules[1].Action != ActionReject {
		t.Fatalf("reject-wan action = %v, want ActionReject", ir.HostInputRules[1].Action)
	}
}

func TestCompileApplicationDenyRuleUsesPortHints(t *testing.T) {
	p := testPolicy()
	p.Applications = []*openngfwv1.Application{{
		Name:     "corp-admin",
		Category: "business-app",
		Ports: []*openngfwv1.ApplicationPort{
			{Protocol: openngfwv1.Protocol_PROTOCOL_TCP, Ports: []*openngfwv1.PortRange{{Start: 8443}, {Start: 9443, End: 9445}}},
			{Protocol: openngfwv1.Protocol_PROTOCOL_UDP, Ports: []*openngfwv1.PortRange{{Start: 5353}}},
		},
	}}
	p.Rules = []*openngfwv1.Rule{{
		Name:         "block-corp-admin",
		FromZones:    []string{"lan"},
		ToZones:      []string{"wan"},
		Applications: []string{"corp-admin"},
		Action:       openngfwv1.Action_ACTION_DENY,
	}}

	ir, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(ir.Rules) != 1 {
		t.Fatalf("Rules = %+v, want one rule", ir.Rules)
	}
	r := ir.Rules[0]
	if len(r.Applications) != 1 || r.Applications[0] != "corp-admin" {
		t.Fatalf("Applications = %v, want corp-admin", r.Applications)
	}
	if len(r.Services) != 2 {
		t.Fatalf("Services = %+v, want TCP and UDP hints", r.Services)
	}
	if r.Services[0].Protocol != ProtoTCP || r.Services[0].Ports[0] != (PortRange{8443, 8443}) || r.Services[0].Ports[1] != (PortRange{9443, 9445}) {
		t.Fatalf("TCP app port hints = %+v", r.Services[0])
	}
	if r.Services[1].Protocol != ProtoUDP || r.Services[1].Ports[0] != (PortRange{5353, 5353}) {
		t.Fatalf("UDP app port hints = %+v", r.Services[1])
	}
}

func TestCompileSignalOnlyApplicationDenyRuleEmitsAppIDDrop(t *testing.T) {
	p := testPolicy()
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
		Applications: []string{"corp-admin"},
		Action:       openngfwv1.Action_ACTION_DENY,
		Log:          true,
	}}

	ir, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(ir.Rules) != 1 {
		t.Fatalf("Rules = %+v, want one policy rule", ir.Rules)
	}
	r := ir.Rules[0]
	if r.Action != ActionDeny || !r.Log {
		t.Fatalf("compiled rule = %+v, want logged deny", r)
	}
	if len(r.Applications) != 1 || r.Applications[0] != "corp-admin" {
		t.Fatalf("Applications = %v, want corp-admin", r.Applications)
	}
	if len(r.Services) != 0 {
		t.Fatalf("signal-only App-ID deny rule must not receive L4 service hints, got %+v", r.Services)
	}
	if !r.AppIDOnly {
		t.Fatalf("AppIDOnly = false, want true")
	}
	if len(r.AppIDSignals) != 1 || r.AppIDSignals[0].Application != "corp-admin" || len(r.AppIDSignals[0].Signals) != 1 || r.AppIDSignals[0].Signals[0] != "http" {
		t.Fatalf("AppIDSignals = %+v, want http signal", r.AppIDSignals)
	}
	if len(ir.AppIDDrops) != 1 {
		t.Fatalf("AppIDDrops = %+v, want one generated drop", ir.AppIDDrops)
	}
	drop := ir.AppIDDrops[0]
	if drop.RuleName != "block-corp-admin" || drop.Application != "corp-admin" || drop.EngineSignal != "http" {
		t.Fatalf("AppID drop metadata = %+v", drop)
	}
	if drop.SID == 0 {
		t.Fatalf("AppID drop SID = 0, want generated Suricata SID")
	}
	if len(ir.AppIDControls) != 1 {
		t.Fatalf("AppIDControls = %+v, want one generated control", ir.AppIDControls)
	}
	control := ir.AppIDControls[0]
	if control.Action != ActionDeny || control.RuleName != "block-corp-admin" || control.Application != "corp-admin" || control.EngineSignal != "http" {
		t.Fatalf("AppID control metadata = %+v", control)
	}
}

func TestCompileApplicationAllowRuleEmitsScopedAppIDControl(t *testing.T) {
	p := testPolicy()
	p.Applications = []*openngfwv1.Application{{
		Name:          "corp-admin",
		Category:      "business-app",
		EngineSignals: []string{"http"},
		Ports: []*openngfwv1.ApplicationPort{
			{Protocol: openngfwv1.Protocol_PROTOCOL_TCP, Ports: []*openngfwv1.PortRange{{Start: 8443}}},
		},
	}}
	p.Ids = &openngfwv1.Ids{
		Enabled:         true,
		Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
		FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED,
	}
	p.Rules = []*openngfwv1.Rule{{
		Id:                   "rule-allow-corp-admin",
		Name:                 "allow-corp-admin",
		FromZones:            []string{"lan"},
		ToZones:              []string{"wan"},
		SourceAddresses:      []string{"lan-net"},
		DestinationAddresses: []string{"host"},
		Applications:         []string{"corp-admin"},
		Action:               openngfwv1.Action_ACTION_ALLOW,
	}}

	ir, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(ir.Rules) != 1 || ir.Rules[0].Action != ActionAllow {
		t.Fatalf("Rules = %+v, want one allow rule", ir.Rules)
	}
	if len(ir.AppIDControls) != 1 {
		t.Fatalf("AppIDControls = %+v, want one generated allow control", ir.AppIDControls)
	}
	control := ir.AppIDControls[0]
	if control.Action != ActionAllow || control.RuleID != "rule-allow-corp-admin" || control.Application != "corp-admin" || control.EngineSignal != "http" {
		t.Fatalf("AppID control metadata = %+v", control)
	}
	if control.Service.Protocol != ProtoTCP || len(control.Service.Ports) != 1 || control.Service.Ports[0] != (PortRange{8443, 8443}) {
		t.Fatalf("AppID control service = %+v, want tcp/8443", control.Service)
	}
	if len(control.SrcPrefixes) != 1 || control.SrcPrefixes[0] != netip.MustParsePrefix("10.10.0.0/24") {
		t.Fatalf("AppID control source scope = %+v", control.SrcPrefixes)
	}
	if len(control.DstPrefixes) != 1 || control.DstPrefixes[0] != netip.MustParsePrefix("10.10.0.80/32") {
		t.Fatalf("AppID control destination scope = %+v", control.DstPrefixes)
	}
}

func TestCompileBlockingSecurityProfileRequiresInspection(t *testing.T) {
	p := testPolicy()
	p.SecurityProfiles = []*openngfwv1.SecurityProfile{{
		Name:        "block-malicious-dns",
		DnsSecurity: openngfwv1.DnsSecurityMode_DNS_SECURITY_MODE_BLOCK_MALICIOUS,
	}}
	p.Ids = &openngfwv1.Ids{
		Enabled:         true,
		Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
		FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED,
	}
	p.Rules[0].SecurityProfiles = []string{"block-malicious-dns"}

	ir, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	r := ir.Rules[0]
	if !r.InspectionRequired {
		t.Fatalf("InspectionRequired = false, want true")
	}
	if len(r.SecurityProfiles) != 1 || r.SecurityProfiles[0] != "block-malicious-dns" {
		t.Fatalf("SecurityProfiles = %v, want block-malicious-dns", r.SecurityProfiles)
	}
	if len(ir.SecurityProfileRules) != 1 {
		t.Fatalf("SecurityProfileRules = %+v, want one generated profile rule", ir.SecurityProfileRules)
	}
	profileRule := ir.SecurityProfileRules[0]
	if profileRule.RuleName != "r1" || profileRule.ProfileName != "block-malicious-dns" || profileRule.Control != "dns-security:block-malicious" || profileRule.Protocol != "dns" {
		t.Fatalf("SecurityProfileRule = %+v", profileRule)
	}
	if profileRule.SID == 0 {
		t.Fatalf("SecurityProfileRule SID = 0, want generated Suricata SID")
	}
}

func TestCompileSecurityProfileControlsPreservesProfileIntent(t *testing.T) {
	p := testPolicy()
	p.SecurityProfiles = []*openngfwv1.SecurityProfile{{
		Name:          "strict-web",
		Description:   "TLS broker prerequisite approved for this lab policy.",
		TlsInspection: openngfwv1.TlsInspectionMode_TLS_INSPECTION_MODE_DECRYPTION_REQUIRED,
		UrlCategories: []string{"malware", "phishing"},
		DnsSecurity:   openngfwv1.DnsSecurityMode_DNS_SECURITY_MODE_BLOCK_MALICIOUS,
		FileSecurity:  openngfwv1.FileSecurityMode_FILE_SECURITY_MODE_BLOCK_EXECUTABLES,
	}}
	p.Ids = &openngfwv1.Ids{
		Enabled:         true,
		Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
		FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED,
	}
	p.Rules[0].SecurityProfiles = []string{"strict-web"}

	ir, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, rule := range ir.SecurityProfileRules {
		got = append(got, rule.Protocol+" "+rule.Control)
	}
	want := []string{
		"tls tls-inspection:decryption-required",
		"http url-category:malware",
		"http url-category:phishing",
		"dns dns-security:block-malicious",
		"http file-security:block-executables",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("SecurityProfileRules controls = %q, want %q", got, want)
	}
}

func TestCompileIDSExceptions(t *testing.T) {
	p := testPolicy()
	p.Ids = &openngfwv1.Ids{
		Enabled: true,
		Mode:    openngfwv1.IdsMode_IDS_MODE_DETECT,
		Exceptions: []*openngfwv1.IdsException{
			{
				Name: "fp-by-src", SignatureId: 9000001, ThreatId: "openngfw.test",
				SourceAddress: "lan-net", Description: "lab false positive",
			},
			{Name: "disabled", SignatureId: 9000002, DestinationAddress: "host", Disabled: true},
		},
	}

	ir, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if ir.IDs == nil {
		t.Fatal("IDsIR is nil")
	}
	if len(ir.IDs.Exceptions) != 1 {
		t.Fatalf("IDS exceptions = %+v, want one active exception", ir.IDs.Exceptions)
	}
	ex := ir.IDs.Exceptions[0]
	if ex.Name != "fp-by-src" || ex.SignatureID != 9000001 || ex.ThreatID != "openngfw.test" {
		t.Fatalf("exception metadata = %+v", ex)
	}
	if ex.Track != "by_src" || ex.Address != netip.MustParsePrefix("10.10.0.0/24") {
		t.Fatalf("exception scope = track %q address %s", ex.Track, ex.Address)
	}
}

func TestCompileRejectsInvalidPolicy(t *testing.T) {
	p := testPolicy()
	p.Rules[0].Services = []string{"missing"}
	if _, err := Compile(p); err == nil {
		t.Fatal("expected compile error for invalid policy")
	}
}

func TestCompileTrafficControlIntent(t *testing.T) {
	p := testPolicy()
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

	ir, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(ir.QoSControls) != 1 {
		t.Fatalf("QoSControls = %+v, want one", ir.QoSControls)
	}
	qos := ir.QoSControls[0]
	if qos.RuleName != "r1" || qos.ProfileName != "voice-priority" || qos.Priority != "high" || qos.DSCPMark != 46 {
		t.Fatalf("QoSControl = %+v", qos)
	}
	if len(ir.ZoneProtections) != 1 {
		t.Fatalf("ZoneProtections = %+v, want one", ir.ZoneProtections)
	}
	zp := ir.ZoneProtections[0]
	if zp.ZoneName != "wan" || zp.ProfileName != "internet-edge" || zp.Action != "alert" || !zp.AuditLog {
		t.Fatalf("ZoneProtection = %+v", zp)
	}
}
