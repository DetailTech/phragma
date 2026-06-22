package policy

import (
	"testing"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func hasImpact(items []*openngfwv1.ChangeImpactItem, risk openngfwv1.ChangeRisk, title string) bool {
	for _, item := range items {
		if item.GetRisk() == risk && item.GetTitle() == title {
			return true
		}
	}
	return false
}

func hasImpactDetail(items []*openngfwv1.ChangeImpactItem, risk openngfwv1.ChangeRisk, title, detail string) bool {
	for _, item := range items {
		if item.GetRisk() == risk && item.GetTitle() == title && item.GetDetail() == detail {
			return true
		}
	}
	return false
}

func TestImpactBroadAllowIsHighRisk(t *testing.T) {
	candidate := &openngfwv1.Policy{Rules: []*openngfwv1.Rule{{
		Name: "allow-any", Action: openngfwv1.Action_ACTION_ALLOW, Log: true,
	}}}

	impact := Impact(&openngfwv1.Policy{}, candidate)
	if impact.GetRisk() != openngfwv1.ChangeRisk_CHANGE_RISK_HIGH {
		t.Fatalf("risk = %s, want high", impact.GetRisk())
	}
	if !hasImpact(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "New active allow rule") {
		t.Fatalf("missing high-risk broad allow item: %#v", impact.GetItems())
	}
	if !hasImpact(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Active broad allow rule") {
		t.Fatalf("missing broad allow hygiene item: %#v", impact.GetItems())
	}
}

func TestImpactExistingBroadAllowRemainsHighRisk(t *testing.T) {
	candidate := &openngfwv1.Policy{Rules: []*openngfwv1.Rule{{
		Name: "allow-any", Action: openngfwv1.Action_ACTION_ALLOW,
	}}}

	impact := Impact(candidate, candidate)
	if impact.GetRisk() != openngfwv1.ChangeRisk_CHANGE_RISK_HIGH {
		t.Fatalf("risk = %s, want high", impact.GetRisk())
	}
	if !hasImpact(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Active broad allow rule") {
		t.Fatalf("missing existing broad allow hygiene item: %#v", impact.GetItems())
	}
}

func TestImpactShadowedRuleIsMediumRisk(t *testing.T) {
	candidate := &openngfwv1.Policy{Rules: []*openngfwv1.Rule{
		{
			Name: "allow-web", FromZones: []string{"wan"}, ToZones: []string{"lan"},
			DestinationAddresses: []string{"web-server"}, Services: []string{"web"},
			Action: openngfwv1.Action_ACTION_ALLOW,
		},
		{
			Name: "deny-web-admin", FromZones: []string{"wan"}, ToZones: []string{"lan"},
			DestinationAddresses: []string{"web-server"}, Services: []string{"web"},
			Action: openngfwv1.Action_ACTION_DENY,
		},
	}}

	impact := Impact(&openngfwv1.Policy{}, candidate)
	if !hasImpactDetail(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, "Shadowed rule",
		"deny-web-admin is fully covered by earlier rule allow-web; first-match evaluation will not reach it.") {
		t.Fatalf("missing shadowed rule impact: %#v", impact.GetItems())
	}
}

func TestImpactMatchesRuleByDurableIDAcrossRename(t *testing.T) {
	running := &openngfwv1.Policy{Rules: []*openngfwv1.Rule{{
		Name:   "allow-old",
		Id:     "rule-001",
		Action: openngfwv1.Action_ACTION_ALLOW,
	}}}
	candidate := &openngfwv1.Policy{Rules: []*openngfwv1.Rule{{
		Name:   "allow-new",
		Id:     "rule-001",
		Action: openngfwv1.Action_ACTION_DENY,
	}}}

	impact := Impact(running, candidate)
	if !hasImpactDetail(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Rule can interrupt traffic",
		"allow-new changed toward deny/reject behavior.") {
		t.Fatalf("rule rename with same durable id should be a modification, got %#v", impact.GetItems())
	}
	if hasImpact(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, "New active blocking rule") {
		t.Fatalf("rule rename with same durable id was treated as an add: %#v", impact.GetItems())
	}
}

func TestImpactRuleOrderUsesDurableIDs(t *testing.T) {
	running := &openngfwv1.Policy{Rules: []*openngfwv1.Rule{
		{Name: "old-a", Id: "rule-a", Action: openngfwv1.Action_ACTION_ALLOW},
		{Name: "old-b", Id: "rule-b", Action: openngfwv1.Action_ACTION_DENY},
	}}
	candidate := &openngfwv1.Policy{Rules: []*openngfwv1.Rule{
		{Name: "new-b", Id: "rule-b", Action: openngfwv1.Action_ACTION_DENY},
		{Name: "new-a", Id: "rule-a", Action: openngfwv1.Action_ACTION_ALLOW},
	}}

	impact := Impact(running, candidate)
	if !hasImpact(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, "Rule order changed") {
		t.Fatalf("missing durable-id rule order impact: %#v", impact.GetItems())
	}
}

func TestImpactDisabledRuleDoesNotShadow(t *testing.T) {
	candidate := &openngfwv1.Policy{Rules: []*openngfwv1.Rule{
		{
			Name: "disabled-allow-web", Disabled: true, FromZones: []string{"wan"}, ToZones: []string{"lan"},
			DestinationAddresses: []string{"web-server"}, Services: []string{"web"},
			Action: openngfwv1.Action_ACTION_ALLOW,
		},
		{
			Name: "deny-web-admin", FromZones: []string{"wan"}, ToZones: []string{"lan"},
			DestinationAddresses: []string{"web-server"}, Services: []string{"web"},
			Action: openngfwv1.Action_ACTION_DENY,
		},
	}}

	impact := Impact(&openngfwv1.Policy{}, candidate)
	if hasImpact(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, "Shadowed rule") {
		t.Fatalf("unexpected shadowed rule impact: %#v", impact.GetItems())
	}
}

func TestImpactRouteAndNATAreHighRisk(t *testing.T) {
	candidate := validPolicy()

	impact := Impact(&openngfwv1.Policy{}, candidate)
	if impact.GetRisk() != openngfwv1.ChangeRisk_CHANGE_RISK_HIGH {
		t.Fatalf("risk = %s, want high", impact.GetRisk())
	}
	for _, title := range []string{"NAT changed", "Static routes changed"} {
		if !hasImpact(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, title) {
			t.Fatalf("missing %q in %#v", title, impact.GetItems())
		}
	}
}

func TestImpactDisablingInspectionIsHighRisk(t *testing.T) {
	running := &openngfwv1.Policy{Ids: &openngfwv1.Ids{Enabled: true, Mode: openngfwv1.IdsMode_IDS_MODE_DETECT}}
	candidate := &openngfwv1.Policy{Ids: &openngfwv1.Ids{Enabled: false}}

	impact := Impact(running, candidate)
	if !hasImpact(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "IDS/IPS disabled") {
		t.Fatalf("missing IDS disablement impact: %#v", impact.GetItems())
	}
}

func TestImpactApplicationObjectChangeIsMediumRisk(t *testing.T) {
	candidate := &openngfwv1.Policy{Applications: []*openngfwv1.Application{{
		Name:          "corp-admin",
		DisplayName:   "Corporate Admin",
		Category:      "business-app",
		EngineSignals: []string{"corp-admin"},
	}}}

	impact := Impact(&openngfwv1.Policy{}, candidate)
	if !hasImpactDetail(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, "Added application object", "corp-admin") {
		t.Fatalf("missing application object impact: %#v", impact.GetItems())
	}
}

func TestImpactSecurityProfileChangeIsMediumRisk(t *testing.T) {
	candidate := &openngfwv1.Policy{SecurityProfiles: []*openngfwv1.SecurityProfile{{
		Name:          "inspect-standard",
		TlsInspection: openngfwv1.TlsInspectionMode_TLS_INSPECTION_MODE_METADATA_ONLY,
		DnsSecurity:   openngfwv1.DnsSecurityMode_DNS_SECURITY_MODE_BLOCK_MALICIOUS,
	}}}

	impact := Impact(&openngfwv1.Policy{}, candidate)
	if !hasImpactDetail(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, "Added security profile",
		"inspect-standard changes layered TLS/DNS/URL/file inspection intent attached to rules.") {
		t.Fatalf("missing security profile impact: %#v", impact.GetItems())
	}
}

func TestImpactSecurityProfileDecryptionIntentIsHighRisk(t *testing.T) {
	candidate := &openngfwv1.Policy{SecurityProfiles: []*openngfwv1.SecurityProfile{{
		Name:          "decrypt-intent",
		Description:   "Operator-reviewed outbound TLS inspection intent.",
		TlsInspection: openngfwv1.TlsInspectionMode_TLS_INSPECTION_MODE_DECRYPTION_REQUIRED,
	}}}

	impact := Impact(&openngfwv1.Policy{}, candidate)
	if impact.GetRisk() != openngfwv1.ChangeRisk_CHANGE_RISK_HIGH {
		t.Fatalf("risk = %s, want high", impact.GetRisk())
	}
	if !hasImpactDetail(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Added security profile",
		"decrypt-intent declares decryption-required inspection intent; confirm external TLS broker and certificate prerequisites before commit.") {
		t.Fatalf("missing decryption-intent impact: %#v", impact.GetItems())
	}
}

func TestImpactFlowtableFastPathEnablementIsHighRisk(t *testing.T) {
	running := validPolicy()
	candidate := validPolicy()
	candidate.Network = &openngfwv1.Network{EnableFlowOffload: true}

	impact := Impact(running, candidate)
	if impact.GetRisk() != openngfwv1.ChangeRisk_CHANGE_RISK_HIGH {
		t.Fatalf("risk = %s, want high", impact.GetRisk())
	}
	for _, title := range []string{"Interface/network changed", "Flowtable fast path enabled"} {
		if !hasImpact(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, title) {
			t.Fatalf("missing %q in %#v", title, impact.GetItems())
		}
	}
}

func TestImpactFlowtableFastPathDisablementIsMediumRisk(t *testing.T) {
	running := validPolicy()
	running.Network = &openngfwv1.Network{EnableFlowOffload: true}
	candidate := validPolicy()

	impact := Impact(running, candidate)
	if !hasImpact(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, "Flowtable fast path disabled") {
		t.Fatalf("missing flowtable disablement impact: %#v", impact.GetItems())
	}
}

func TestImpactFlowtableInspectionConflictIsHighRisk(t *testing.T) {
	running := validPolicy()
	candidate := validPolicy()
	candidate.Network = &openngfwv1.Network{EnableFlowOffload: true}
	candidate.Ids = &openngfwv1.Ids{Enabled: true, Mode: openngfwv1.IdsMode_IDS_MODE_DETECT}

	impact := Impact(running, candidate)
	if !hasImpact(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Flowtable fast path conflicts with IDS/IPS") {
		t.Fatalf("missing flowtable IDS/IPS conflict impact: %#v", impact.GetItems())
	}
}

func TestImpactHostInputHardenedIsHighRisk(t *testing.T) {
	running := validPolicy()
	candidate := validPolicy()
	candidate.HostInput = &openngfwv1.HostInput{
		DefaultAction: openngfwv1.Action_ACTION_DENY,
		Rules: []*openngfwv1.HostInputRule{{
			Name: "allow-lan-web", FromZones: []string{"lan"}, Services: []string{"web"},
			Action: openngfwv1.Action_ACTION_ALLOW,
		}},
	}

	impact := Impact(running, candidate)
	if !hasImpact(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Host input hardened") {
		t.Fatalf("missing host-input hardening impact: %#v", impact.GetItems())
	}
}

func TestImpactHostInputOpenedIsHighRisk(t *testing.T) {
	running := validPolicy()
	running.HostInput = &openngfwv1.HostInput{DefaultAction: openngfwv1.Action_ACTION_DENY}
	candidate := validPolicy()
	candidate.HostInput = &openngfwv1.HostInput{DefaultAction: openngfwv1.Action_ACTION_ALLOW}

	impact := Impact(running, candidate)
	if !hasImpact(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Host input opened") {
		t.Fatalf("missing host-input opened impact: %#v", impact.GetItems())
	}
}

func TestImpactFlowtableRequiresZoneInterface(t *testing.T) {
	running := &openngfwv1.Policy{}
	candidate := &openngfwv1.Policy{Network: &openngfwv1.Network{EnableFlowOffload: true}}

	impact := Impact(running, candidate)
	if !hasImpact(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Flowtable fast path needs zone interfaces") {
		t.Fatalf("missing flowtable interface impact: %#v", impact.GetItems())
	}
}

func TestImpactThreatIntelFeedDisablementIsHighRisk(t *testing.T) {
	running := &openngfwv1.Policy{Intel: &openngfwv1.Intel{Feeds: []*openngfwv1.FeedEnable{{Name: "emerging-drop", Enabled: true}}}}
	candidate := &openngfwv1.Policy{Intel: &openngfwv1.Intel{Feeds: []*openngfwv1.FeedEnable{{Name: "emerging-drop", Enabled: false}}}}

	impact := Impact(running, candidate)
	if !hasImpact(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Threat intel changed") {
		t.Fatalf("missing high-risk intel impact: %#v", impact.GetItems())
	}
}

func TestImpactNoMaterialChange(t *testing.T) {
	p := validPolicy()
	impact := Impact(p, p)
	if impact.GetRisk() != openngfwv1.ChangeRisk_CHANGE_RISK_LOW {
		t.Fatalf("risk = %s, want low", impact.GetRisk())
	}
	if !hasImpact(impact.GetItems(), openngfwv1.ChangeRisk_CHANGE_RISK_LOW, "No material policy risk detected") {
		t.Fatalf("missing no-change item: %#v", impact.GetItems())
	}
}
