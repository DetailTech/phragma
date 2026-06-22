package explain

import (
	"strings"
	"testing"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func testPolicy() *openngfwv1.Policy {
	return &openngfwv1.Policy{
		Zones: []*openngfwv1.Zone{
			{Name: "untrust", Interfaces: []string{"eth0"}},
			{Name: "trust", Interfaces: []string{"eth1"}},
		},
		Addresses: []*openngfwv1.Address{
			{Name: "client", Cidr: "10.0.1.20/32"},
			{Name: "server", Cidr: "10.0.2.20/32"},
			{Name: "public-server", Cidr: "203.0.113.10/32"},
			{Name: "trust-iface", Cidr: "10.0.2.10/32"},
		},
		Services: []*openngfwv1.Service{
			{Name: "https", Protocol: openngfwv1.Protocol_PROTOCOL_TCP, Ports: []*openngfwv1.PortRange{{Start: 443}}},
			{Name: "ssh", Protocol: openngfwv1.Protocol_PROTOCOL_TCP, Ports: []*openngfwv1.PortRange{{Start: 22}}},
		},
		Nat: &openngfwv1.Nat{
			Source: []*openngfwv1.SourceNat{
				{Name: "trust-snat", ToZone: "trust", SourceAddress: "client", TranslatedAddress: "trust-iface"},
			},
			Destination: []*openngfwv1.DestinationNat{
				{Name: "public-https", FromZone: "untrust", Service: "https", DestinationAddress: "public-server", TranslatedAddress: "server"},
			},
		},
		StaticRoutes: []*openngfwv1.StaticRoute{
			{Destination: "10.0.0.0/8", Via: "10.0.1.1", Metric: 200},
			{Destination: "10.0.2.0/24", Interface: "eth1", Metric: 10},
			{Destination: "0.0.0.0/0", Via: "203.0.113.1", Interface: "eth0", Metric: 500},
		},
		Ids: &openngfwv1.Ids{Enabled: true, Mode: openngfwv1.IdsMode_IDS_MODE_DETECT},
		Rules: []*openngfwv1.Rule{
			{
				Name:                 "disabled-deny",
				FromZones:            []string{"untrust"},
				ToZones:              []string{"trust"},
				SourceAddresses:      []string{"client"},
				DestinationAddresses: []string{"server"},
				Services:             []string{"https"},
				Action:               openngfwv1.Action_ACTION_DENY,
				Disabled:             true,
			},
			{
				Name:                 "allow-client-server",
				FromZones:            []string{"untrust"},
				ToZones:              []string{"trust"},
				SourceAddresses:      []string{"client"},
				DestinationAddresses: []string{"server"},
				Services:             []string{"https"},
				Action:               openngfwv1.Action_ACTION_ALLOW,
				Log:                  true,
			},
		},
	}
}

func explainHTTPS(t *testing.T, p *openngfwv1.Policy, dst string, port uint32) *openngfwv1.ExplainFlowResponse {
	t.Helper()
	resp, err := ExplainFlow(p, &openngfwv1.ExplainFlowRequest{
		PolicySource: openngfwv1.PolicySource_POLICY_SOURCE_RUNNING,
		FromZone:     "untrust",
		ToZone:       "trust",
		SrcIp:        "10.0.1.20",
		SrcPort:      51515,
		DestIp:       dst,
		DestPort:     port,
		Protocol:     openngfwv1.Protocol_PROTOCOL_TCP,
	}, 7)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestExplainFlowAllowIncludesRuleInspectionAndSNAT(t *testing.T) {
	resp := explainHTTPS(t, testPolicy(), "10.0.2.20", 443)
	if got, want := resp.GetVerdict(), openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_ALLOWED; got != want {
		t.Fatalf("verdict = %s, want %s", got, want)
	}
	if got := resp.GetMatchedRule(); got != "allow-client-server" {
		t.Fatalf("matched rule = %q", got)
	}
	if got := resp.GetMatchedRuleId(); got == "" || !strings.HasPrefix(got, "rule-allow-client-server-") {
		t.Fatalf("matched rule id = %q, want generated allow-client-server id", got)
	}
	if got, want := resp.GetInspectionState(), openngfwv1.ExplainInspectionState_EXPLAIN_INSPECTION_STATE_IDS_DETECT; got != want {
		t.Fatalf("inspection = %s, want %s", got, want)
	}
	if !containsDecisionTerm(resp.GetDecisionTerms(), openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_ALLOWED) ||
		!containsDecisionTerm(resp.GetDecisionTerms(), openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_PARTIALLY_INSPECTED) {
		t.Fatalf("decision terms should expose allowed and partially inspected: %v", resp.GetDecisionTerms())
	}
	if got, want := resp.GetDecisionSummary(), "allowed, partially inspected"; got != want {
		t.Fatalf("decision summary = %q, want %q", got, want)
	}
	if got, want := resp.GetInspectionProfile().GetEngine(), "suricata"; got != want {
		t.Fatalf("inspection engine = %q, want %q", got, want)
	}
	if got, want := resp.GetInspectionProfile().GetIdsMode(), openngfwv1.IdsMode_IDS_MODE_DETECT; got != want {
		t.Fatalf("inspection mode = %s, want %s", got, want)
	}
	if !contains(resp.GetTrace(), "\"disabled-deny\" skipped: disabled") {
		t.Fatalf("trace should mention disabled rule skip: %v", resp.GetTrace())
	}
	if !contains(resp.GetEvidence(), "source-nat \"trust-snat\" will translate source to 10.0.2.10") {
		t.Fatalf("evidence should mention matching SNAT: %v", resp.GetEvidence())
	}
	sourceNat := resp.GetNatProfile().GetSource()
	if !sourceNat.GetEvaluated() || !sourceNat.GetMatched() {
		t.Fatalf("source NAT profile should match: %#v", sourceNat)
	}
	if got, want := sourceNat.GetMatchedRule(), "trust-snat"; got != want {
		t.Fatalf("source NAT rule = %q, want %q", got, want)
	}
	if got := sourceNat.GetMatchedRuleId(); got == "" || !strings.HasPrefix(got, "snat-trust-snat-") {
		t.Fatalf("source NAT rule ID = %q, want generated trust-snat ID", got)
	}
	if got, want := sourceNat.GetMatchedRuleIndex(), uint32(0); got != want {
		t.Fatalf("source NAT index = %d, want %d", got, want)
	}
	if got, want := sourceNat.GetOriginalSourceIp(), "10.0.1.20"; got != want {
		t.Fatalf("source NAT original source = %q, want %q", got, want)
	}
	if got, want := sourceNat.GetTranslatedSourceIp(), "10.0.2.10"; got != want {
		t.Fatalf("source NAT translated source = %q, want %q", got, want)
	}
	if sourceNat.GetMasquerade() {
		t.Fatalf("source NAT should not masquerade static translation: %#v", sourceNat)
	}
	if route := resp.GetRouteProfile(); !route.GetMatched() || route.GetDestination() != "10.0.2.0/24" || route.GetEgressInterface() != "eth1" {
		t.Fatalf("route profile should select trust static route: %#v", route)
	}
	if !contains(resp.GetEvidence(), "route decision: static route 10.0.2.0/24 dev eth1 metric 10") {
		t.Fatalf("evidence should mention selected route: %v", resp.GetEvidence())
	}
}

func TestExplainFlowRuleMatchContext(t *testing.T) {
	p := testPolicy()
	p.Rules[1].MatchContext = &openngfwv1.RuleMatchContext{
		Users:         []string{"alice@example.com"},
		Groups:        []string{"idp/secops"},
		Devices:       []string{"laptop-123"},
		PostureLabels: []string{"posture:edr-healthy"},
	}
	req := &openngfwv1.ExplainFlowRequest{
		PolicySource: openngfwv1.PolicySource_POLICY_SOURCE_RUNNING,
		FromZone:     "untrust",
		ToZone:       "trust",
		SrcIp:        "10.0.1.20",
		SrcPort:      51515,
		DestIp:       "10.0.2.20",
		DestPort:     443,
		Protocol:     openngfwv1.Protocol_PROTOCOL_TCP,
		MatchContext: &openngfwv1.RuleMatchContext{
			Users:         []string{"alice@example.com"},
			Groups:        []string{"idp/secops", "idp/helpdesk"},
			Devices:       []string{"laptop-123"},
			PostureLabels: []string{"posture:edr-healthy"},
		},
	}
	resp, err := ExplainFlow(p, req, 7)
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.GetMatchedRule(); got != "allow-client-server" {
		t.Fatalf("matched rule = %q", got)
	}
	if got := resp.GetMatchedRuleContext().GetUsers(); len(got) != 1 || got[0] != "alice@example.com" {
		t.Fatalf("matched rule context = %#v", resp.GetMatchedRuleContext())
	}
	if !contains(resp.GetEvidence(), "matched rule identity/posture context: users=alice@example.com groups=idp/secops devices=laptop-123 posture_labels=posture:edr-healthy") {
		t.Fatalf("evidence should include match context: %v", resp.GetEvidence())
	}
	if !contains(resp.GetWarnings(), "no live directory, group freshness, MDM, or step-up authentication lookup was performed") {
		t.Fatalf("warnings should disclose no live identity/posture lookup: %v", resp.GetWarnings())
	}
}

func TestExplainFlowRuleMatchContextSkipsMissingContext(t *testing.T) {
	p := testPolicy()
	p.Rules[1].MatchContext = &openngfwv1.RuleMatchContext{Groups: []string{"idp/secops"}}
	resp, err := ExplainFlow(p, &openngfwv1.ExplainFlowRequest{
		PolicySource: openngfwv1.PolicySource_POLICY_SOURCE_RUNNING,
		FromZone:     "untrust",
		ToZone:       "trust",
		SrcIp:        "10.0.1.20",
		SrcPort:      51515,
		DestIp:       "10.0.2.20",
		DestPort:     443,
		Protocol:     openngfwv1.Protocol_PROTOCOL_TCP,
		MatchContext: &openngfwv1.RuleMatchContext{Groups: []string{"idp/helpdesk"}},
	}, 7)
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.GetVerdict(); got != openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_DEFAULT_DROP {
		t.Fatalf("verdict = %s, want default drop", got)
	}
	if !contains(resp.GetTrace(), `rule[1] "allow-client-server" skipped: group context [idp/helpdesk] not in [idp/secops]`) {
		t.Fatalf("trace should mention context skip: %v", resp.GetTrace())
	}
}

func TestExplainFlowAppliesDNATBeforePolicyMatch(t *testing.T) {
	resp := explainHTTPS(t, testPolicy(), "203.0.113.10", 443)
	if got, want := resp.GetVerdict(), openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_ALLOWED; got != want {
		t.Fatalf("verdict = %s, want %s", got, want)
	}
	if !contains(resp.GetEvidence(), "dnat \"public-https\" translated destination 203.0.113.10:443 -> 10.0.2.20:443") {
		t.Fatalf("evidence should mention DNAT translation: %v", resp.GetEvidence())
	}
	destNat := resp.GetNatProfile().GetDestination()
	if !destNat.GetEvaluated() || !destNat.GetMatched() {
		t.Fatalf("destination NAT profile should match: %#v", destNat)
	}
	if got, want := destNat.GetMatchedRule(), "public-https"; got != want {
		t.Fatalf("destination NAT rule = %q, want %q", got, want)
	}
	if got := destNat.GetMatchedRuleId(); got == "" || !strings.HasPrefix(got, "dnat-public-https-") {
		t.Fatalf("destination NAT rule ID = %q, want generated public-https ID", got)
	}
	if got, want := destNat.GetMatchedRuleIndex(), uint32(0); got != want {
		t.Fatalf("destination NAT index = %d, want %d", got, want)
	}
	if got, want := destNat.GetOriginalDestinationIp(), "203.0.113.10"; got != want {
		t.Fatalf("destination NAT original IP = %q, want %q", got, want)
	}
	if got, want := destNat.GetTranslatedDestinationIp(), "10.0.2.20"; got != want {
		t.Fatalf("destination NAT translated IP = %q, want %q", got, want)
	}
	if got, want := destNat.GetOriginalDestinationPort(), uint32(443); got != want {
		t.Fatalf("destination NAT original port = %d, want %d", got, want)
	}
	if got, want := destNat.GetTranslatedDestinationPort(), uint32(443); got != want {
		t.Fatalf("destination NAT translated port = %d, want %d", got, want)
	}
	if route := resp.GetRouteProfile(); route.GetDestination() != "10.0.2.0/24" {
		t.Fatalf("route should use post-DNAT destination: %#v", route)
	}
}

func TestExplainFlowDNATTranslatedPortProfile(t *testing.T) {
	p := testPolicy()
	p.Services = append(p.Services, &openngfwv1.Service{
		Name:     "tcp-8443",
		Protocol: openngfwv1.Protocol_PROTOCOL_TCP,
		Ports:    []*openngfwv1.PortRange{{Start: 8443}},
	})
	p.Nat.Destination[0].TranslatedPort = 8443
	p.Rules[1].Services = []string{"tcp-8443"}

	resp := explainHTTPS(t, p, "203.0.113.10", 443)
	if got, want := resp.GetVerdict(), openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_ALLOWED; got != want {
		t.Fatalf("verdict = %s, want %s", got, want)
	}
	destNat := resp.GetNatProfile().GetDestination()
	if got, want := destNat.GetTranslatedDestinationPort(), uint32(8443); got != want {
		t.Fatalf("translated port = %d, want %d", got, want)
	}
	if !contains(destNat.GetEvidence(), "203.0.113.10:443 -> 10.0.2.20:8443") {
		t.Fatalf("destination NAT evidence should include translated port: %v", destNat.GetEvidence())
	}
}

func TestExplainFlowSNATMasqueradeProfile(t *testing.T) {
	p := testPolicy()
	p.Nat.Source[0].TranslatedAddress = ""
	p.Nat.Source[0].Masquerade = true

	resp := explainHTTPS(t, p, "10.0.2.20", 443)
	sourceNat := resp.GetNatProfile().GetSource()
	if !sourceNat.GetEvaluated() || !sourceNat.GetMatched() {
		t.Fatalf("source NAT profile should match masquerade rule: %#v", sourceNat)
	}
	if got, want := sourceNat.GetMatchedRule(), "trust-snat"; got != want {
		t.Fatalf("source NAT rule = %q, want %q", got, want)
	}
	if !sourceNat.GetMasquerade() {
		t.Fatalf("source NAT should mark masquerade: %#v", sourceNat)
	}
	if sourceNat.GetTranslatedSourceIp() != "" {
		t.Fatalf("masquerade source should not claim a static translated IP: %#v", sourceNat)
	}
	if !contains(sourceNat.GetEvidence(), "will masquerade") {
		t.Fatalf("source NAT evidence should mention masquerade: %v", sourceNat.GetEvidence())
	}
}

func TestExplainFlowApplicationDenyRuleMatchesPortHint(t *testing.T) {
	p := testPolicy()
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
		FromZones:    []string{"untrust"},
		ToZones:      []string{"trust"},
		Applications: []string{"corp-admin"},
		Action:       openngfwv1.Action_ACTION_DENY,
	}}, p.Rules...)

	resp := explainHTTPSWithApp(t, p, "10.0.2.20", 8443, "corp-admin")
	if got, want := resp.GetVerdict(), openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_DENIED; got != want {
		t.Fatalf("verdict = %s, want %s", got, want)
	}
	if got := resp.GetMatchedRule(); got != "block-corp-admin" {
		t.Fatalf("matched rule = %q", got)
	}
	if !contains(resp.GetEvidence(), `application "corp-admin" matched TCP/UDP port-hint enforcement for tcp/8443`) {
		t.Fatalf("evidence should mention App-ID port hint: %v", resp.GetEvidence())
	}
	if !contains(resp.GetWarnings(), "port hints") {
		t.Fatalf("warnings should mention App-ID port-hint enforcement: %v", resp.GetWarnings())
	}
}

func TestExplainFlowApplicationRuleRequiresPortHintMatch(t *testing.T) {
	p := testPolicy()
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
		FromZones:    []string{"untrust"},
		ToZones:      []string{"trust"},
		Applications: []string{"corp-admin"},
		Action:       openngfwv1.Action_ACTION_DENY,
	}}, p.Rules...)

	resp := explainHTTPSWithApp(t, p, "10.0.2.20", 443, "corp-admin")
	if got, want := resp.GetVerdict(), openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_ALLOWED; got != want {
		t.Fatalf("verdict = %s, want %s", got, want)
	}
	if got := resp.GetMatchedRule(); got != "allow-client-server" {
		t.Fatalf("matched rule = %q", got)
	}
	if !contains(resp.GetTrace(), `rule[0] "block-corp-admin" skipped: application corp-admin with tcp/443 not in [corp-admin]`) {
		t.Fatalf("trace should mention application port-hint skip: %v", resp.GetTrace())
	}
}

func TestExplainFlowSignalOnlyApplicationDenyRuleMatchesObservedAppID(t *testing.T) {
	p := testPolicy()
	p.Ids = &openngfwv1.Ids{
		Enabled:         true,
		Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
		FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED,
	}
	p.Applications = []*openngfwv1.Application{{
		Name:          "web-browsing",
		Category:      "business-app",
		EngineSignals: []string{"http"},
	}}
	p.Rules = append([]*openngfwv1.Rule{{
		Name:         "block-web-browsing",
		Applications: []string{"web-browsing"},
		Action:       openngfwv1.Action_ACTION_DENY,
	}}, p.Rules...)

	resp := explainHTTPSWithApp(t, p, "10.0.2.20", 8080, "http")
	if got, want := resp.GetVerdict(), openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_DENIED; got != want {
		t.Fatalf("verdict = %s, want %s", got, want)
	}
	if got := resp.GetMatchedRule(); got != "block-web-browsing" {
		t.Fatalf("matched rule = %q", got)
	}
	if !contains(resp.GetEvidence(), `application "web-browsing" matched Suricata App-ID signal "http" with IDS/IPS Prevent fail-closed`) {
		t.Fatalf("evidence should mention Suricata App-ID signal: %v", resp.GetEvidence())
	}
	if !contains(resp.GetWarnings(), "supported Suricata App-ID signals") {
		t.Fatalf("warnings should mention bounded Suricata App-ID enforcement: %v", resp.GetWarnings())
	}
}

func TestExplainFlowDefaultDrop(t *testing.T) {
	resp := explainHTTPS(t, testPolicy(), "10.0.2.20", 22)
	if got, want := resp.GetVerdict(), openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_DEFAULT_DROP; got != want {
		t.Fatalf("verdict = %s, want %s", got, want)
	}
	if !resp.GetDefaultPolicy() {
		t.Fatal("default_policy should be true")
	}
	if !strings.Contains(resp.GetReason(), "no enabled security rule matched") {
		t.Fatalf("unexpected reason: %q", resp.GetReason())
	}
	if route := resp.GetRouteProfile(); route.GetEvaluated() || route.GetSource() != "not-evaluated" {
		t.Fatalf("default drop should skip route lookup: %#v", route)
	}
	if sourceNat := resp.GetNatProfile().GetSource(); sourceNat.GetEvaluated() || !strings.Contains(sourceNat.GetReason(), "default_drop") {
		t.Fatalf("default drop should skip source NAT: %#v", sourceNat)
	}
	if !containsDecisionTerm(resp.GetDecisionTerms(), openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_BLOCKED) {
		t.Fatalf("default drop should expose blocked decision term: %v", resp.GetDecisionTerms())
	}
}

func TestExplainFlowRouteUnresolvedWarnsWhenOnlyDynamicRoutesMayApply(t *testing.T) {
	p := testPolicy()
	p.StaticRoutes = nil
	p.Routing = &openngfwv1.Routing{Bgp: &openngfwv1.Bgp{Enabled: true, Asn: 65001, RouterId: "192.0.2.1"}}
	resp := explainHTTPS(t, p, "10.0.2.20", 443)
	route := resp.GetRouteProfile()
	if !route.GetEvaluated() || route.GetMatched() {
		t.Fatalf("route should be evaluated but unresolved in static policy model: %#v", route)
	}
	if got, want := route.GetSource(), "kernel-unresolved"; got != want {
		t.Fatalf("route source = %q, want %q", got, want)
	}
	if !contains(resp.GetWarnings(), "FRR/kernel route state") {
		t.Fatalf("warnings should mention live FRR/kernel route gap: %v", resp.GetWarnings())
	}
}

func TestExplainFlowProfilesIPSFailOpen(t *testing.T) {
	p := testPolicy()
	p.Ids = &openngfwv1.Ids{
		Enabled:         true,
		Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
		FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_OPEN,
	}
	resp := explainHTTPS(t, p, "10.0.2.20", 443)
	if got, want := resp.GetInspectionState(), openngfwv1.ExplainInspectionState_EXPLAIN_INSPECTION_STATE_IPS_PREVENT; got != want {
		t.Fatalf("inspection = %s, want %s", got, want)
	}
	profile := resp.GetInspectionProfile()
	if !profile.GetBypassPossible() {
		t.Fatalf("fail-open profile should mark bypass_possible: %#v", profile)
	}
	if !strings.Contains(profile.GetBypassReason(), "fail-open") {
		t.Fatalf("bypass reason should mention fail-open: %q", profile.GetBypassReason())
	}
	if !contains(resp.GetWarnings(), "fail-open") {
		t.Fatalf("warnings should expose fail-open bypass: %v", resp.GetWarnings())
	}
	for _, term := range []openngfwv1.ExplainDecisionTerm{
		openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_ALLOWED,
		openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_PARTIALLY_INSPECTED,
		openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_BYPASSED,
		openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_FAIL_OPEN,
	} {
		if !containsDecisionTerm(resp.GetDecisionTerms(), term) {
			t.Fatalf("decision terms missing %s: %v", term, resp.GetDecisionTerms())
		}
	}
}

func TestExplainFlowProfilesIPSFailClosed(t *testing.T) {
	p := testPolicy()
	p.Ids = &openngfwv1.Ids{
		Enabled:         true,
		Mode:            openngfwv1.IdsMode_IDS_MODE_PREVENT,
		FailureBehavior: openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED,
	}
	resp := explainHTTPS(t, p, "10.0.2.20", 443)
	profile := resp.GetInspectionProfile()
	if profile.GetBypassPossible() {
		t.Fatalf("fail-closed profile should not mark bypass_possible: %#v", profile)
	}
	if !strings.Contains(profile.GetDegradedBehavior(), "fail-closed") {
		t.Fatalf("degraded behavior should mention fail-closed: %q", profile.GetDegradedBehavior())
	}
	if !contains(profile.GetEvidence(), "fail-closed") {
		t.Fatalf("profile evidence should expose fail-closed behavior: %v", profile.GetEvidence())
	}
	if !containsDecisionTerm(resp.GetDecisionTerms(), openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_FULLY_INSPECTED) ||
		!containsDecisionTerm(resp.GetDecisionTerms(), openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_FAIL_CLOSED) {
		t.Fatalf("fail-closed prevent should expose fully inspected and fail-closed terms: %v", resp.GetDecisionTerms())
	}
}

func TestExplainFlowProfilesFlowOffloadBypass(t *testing.T) {
	p := testPolicy()
	p.Ids = nil
	p.Network = &openngfwv1.Network{EnableFlowOffload: true}
	resp := explainHTTPS(t, p, "10.0.2.20", 443)
	if got, want := resp.GetInspectionState(), openngfwv1.ExplainInspectionState_EXPLAIN_INSPECTION_STATE_NOT_INSPECTED; got != want {
		t.Fatalf("inspection = %s, want %s", got, want)
	}
	profile := resp.GetInspectionProfile()
	if !profile.GetFlowOffloadEnabled() {
		t.Fatalf("profile should mark flow_offload_enabled: %#v", profile)
	}
	if !profile.GetBypassPossible() {
		t.Fatalf("flow offload should mark bypass_possible: %#v", profile)
	}
	if !strings.Contains(profile.GetBypassReason(), "enable_flow_offload") {
		t.Fatalf("bypass reason should mention enable_flow_offload: %q", profile.GetBypassReason())
	}
	if !contains(resp.GetWarnings(), "flowtable fast path") {
		t.Fatalf("warnings should expose flowtable bypass: %v", resp.GetWarnings())
	}
	if !containsDecisionTerm(resp.GetDecisionTerms(), openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_BYPASSED) {
		t.Fatalf("flow offload should expose bypassed decision term: %v", resp.GetDecisionTerms())
	}
}

func explainHTTPSWithApp(t *testing.T, p *openngfwv1.Policy, dst string, port uint32, appID string) *openngfwv1.ExplainFlowResponse {
	t.Helper()
	resp, err := ExplainFlow(p, &openngfwv1.ExplainFlowRequest{
		PolicySource: openngfwv1.PolicySource_POLICY_SOURCE_RUNNING,
		FromZone:     "untrust",
		ToZone:       "trust",
		SrcIp:        "10.0.1.20",
		SrcPort:      51515,
		DestIp:       dst,
		DestPort:     port,
		Protocol:     openngfwv1.Protocol_PROTOCOL_TCP,
		AppId:        appID,
	}, 7)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func contains(lines []string, needle string) bool {
	for _, line := range lines {
		if strings.Contains(line, needle) {
			return true
		}
	}
	return false
}

func containsDecisionTerm(terms []openngfwv1.ExplainDecisionTerm, want openngfwv1.ExplainDecisionTerm) bool {
	for _, term := range terms {
		if term == want {
			return true
		}
	}
	return false
}
