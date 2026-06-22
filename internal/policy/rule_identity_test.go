package policy

import (
	"testing"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestNormalizeRuleIDsBackfillsStableIDs(t *testing.T) {
	p := &openngfwv1.Policy{Rules: []*openngfwv1.Rule{{
		Name:      "Allow Corp Admin",
		FromZones: []string{"lan"},
		ToZones:   []string{"wan"},
		Action:    openngfwv1.Action_ACTION_ALLOW,
	}}}

	first, report := NormalizeRuleIDs(p)
	if report.Added != 1 || report.Normalized != 0 || report.Deduped != 0 {
		t.Fatalf("report = %+v, want one added id", report)
	}
	if got := first.GetRules()[0].GetId(); !ValidRuleID(got) || got == "" {
		t.Fatalf("generated id %q is not valid", got)
	}
	if p.GetRules()[0].GetId() != "" {
		t.Fatalf("NormalizeRuleIDs mutated the input policy")
	}

	second, _ := NormalizeRuleIDs(p)
	if first.GetRules()[0].GetId() != second.GetRules()[0].GetId() {
		t.Fatalf("generated ids are not stable: %q != %q", first.GetRules()[0].GetId(), second.GetRules()[0].GetId())
	}
}

func TestNormalizeRuleIDsPreservesUniqueValidIDsAndRepairsDuplicates(t *testing.T) {
	p := &openngfwv1.Policy{Rules: []*openngfwv1.Rule{
		{Name: "allow-web", Id: "rule-allow-web", Action: openngfwv1.Action_ACTION_ALLOW},
		{Name: "allow-api", Id: "rule-allow-web", Action: openngfwv1.Action_ACTION_ALLOW},
		{Name: "bad-id", Id: "Rule 1", Action: openngfwv1.Action_ACTION_DENY},
	}}

	out, report := NormalizeRuleIDs(p)
	if report.Deduped == 0 || report.Normalized != 1 {
		t.Fatalf("report = %+v, want duplicate and invalid id repair", report)
	}
	ids := map[string]bool{}
	for _, r := range out.GetRules() {
		if !ValidRuleID(r.GetId()) {
			t.Fatalf("id %q is not valid", r.GetId())
		}
		if ids[r.GetId()] {
			t.Fatalf("duplicate id after normalization: %q", r.GetId())
		}
		ids[r.GetId()] = true
	}
	if out.GetRules()[0].GetId() != "rule-allow-web" {
		t.Fatalf("valid unique id was not preserved: %q", out.GetRules()[0].GetId())
	}
}

func TestNormalizePolicyItemIDsBackfillsAndRepairsNATAndHostInput(t *testing.T) {
	p := &openngfwv1.Policy{
		HostInput: &openngfwv1.HostInput{Rules: []*openngfwv1.HostInputRule{
			{Name: "Allow SSH", Action: openngfwv1.Action_ACTION_ALLOW},
			{Name: "Trimmed", Id: " host-input-trimmed ", Action: openngfwv1.Action_ACTION_ALLOW},
			{Name: "Duplicate", Id: "host-input-trimmed", Action: openngfwv1.Action_ACTION_ALLOW},
		}},
		Nat: &openngfwv1.Nat{
			Source: []*openngfwv1.SourceNat{
				{Name: "LAN Masq", Masquerade: true},
				{Name: "Bad SNAT", Id: "Source NAT"},
			},
			Destination: []*openngfwv1.DestinationNat{
				{Name: "Web DNAT", Id: "dnat-web"},
				{Name: "Web DNAT Copy", Id: "dnat-web"},
			},
		},
	}

	out, report := NormalizePolicyItemIDs(p)
	if report.HostInputAdded != 1 || report.HostInputNormalized != 1 || report.HostInputDeduped == 0 {
		t.Fatalf("host-input report = %+v, want add, normalize, and dedupe", report)
	}
	if report.SourceNatAdded != 1 || report.SourceNatNormalized != 1 {
		t.Fatalf("source NAT report = %+v, want add and normalize", report)
	}
	if report.DestinationNatDeduped == 0 {
		t.Fatalf("destination NAT report = %+v, want dedupe", report)
	}
	if p.GetHostInput().GetRules()[0].GetId() != "" {
		t.Fatalf("NormalizePolicyItemIDs mutated the input policy")
	}

	itemIDs := []string{
		out.GetHostInput().GetRules()[0].GetId(),
		out.GetHostInput().GetRules()[1].GetId(),
		out.GetHostInput().GetRules()[2].GetId(),
		out.GetNat().GetSource()[0].GetId(),
		out.GetNat().GetSource()[1].GetId(),
		out.GetNat().GetDestination()[0].GetId(),
		out.GetNat().GetDestination()[1].GetId(),
	}
	seen := map[string]bool{}
	for _, id := range itemIDs {
		if !ValidRuleID(id) {
			t.Fatalf("generated item id %q is not valid", id)
		}
		if seen[id] {
			t.Fatalf("duplicate item id after normalization: %q", id)
		}
		seen[id] = true
	}
	if got := out.GetHostInput().GetRules()[1].GetId(); got != "host-input-trimmed" {
		t.Fatalf("trimmed host-input id = %q, want host-input-trimmed", got)
	}
	if got := out.GetNat().GetDestination()[0].GetId(); got != "dnat-web" {
		t.Fatalf("valid destination NAT id = %q, want dnat-web", got)
	}

	second, _ := NormalizePolicyItemIDs(p)
	if got, want := second.GetNat().GetSource()[0].GetId(), out.GetNat().GetSource()[0].GetId(); got != want {
		t.Fatalf("generated source NAT ID is not stable: %q != %q", got, want)
	}
}
