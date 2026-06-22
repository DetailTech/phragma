package policy

import (
	"fmt"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

const maxOverlapFindings = 25

// SemanticFindings returns non-fatal policy hygiene findings. These warnings
// keep rulebase cleanup, API automation, and GUI preflight on the same server
// source of truth.
func SemanticFindings(p *openngfwv1.Policy) []*openngfwv1.ValidationFinding {
	if p == nil {
		return nil
	}
	var out []*openngfwv1.ValidationFinding
	out = append(out, missingRuleLogFindings(p.GetRules())...)
	out = append(out, missingHostInputLogFindings(p.GetHostInput().GetRules())...)
	out = append(out, overlappingRuleFindings(p.GetRules())...)
	out = append(out, unusedObjectFindings(p)...)
	return out
}

func warningFinding(code, message, fieldPath, detail string) *openngfwv1.ValidationFinding {
	return &openngfwv1.ValidationFinding{
		Severity:  openngfwv1.ValidationSeverity_VALIDATION_SEVERITY_WARNING,
		Stage:     openngfwv1.ValidationStage_VALIDATION_STAGE_POLICY_MODEL,
		Code:      code,
		Message:   message,
		FieldPath: fieldPath,
		Detail:    detail,
	}
}

func missingRuleLogFindings(rules []*openngfwv1.Rule) []*openngfwv1.ValidationFinding {
	var out []*openngfwv1.ValidationFinding
	for i, rule := range rules {
		if !active(rule) || rule.GetLog() {
			continue
		}
		out = append(out, warningFinding(
			"POLICY_HYGIENE_MISSING_RULE_LOG",
			"Active rule has logging disabled",
			fmt.Sprintf("rules[%d].log", i),
			fmt.Sprintf("%s can change forwarding behavior without emitting rule-level audit evidence.", displayName(rule.GetName(), "rule", i)),
		))
	}
	return out
}

func missingHostInputLogFindings(rules []*openngfwv1.HostInputRule) []*openngfwv1.ValidationFinding {
	var out []*openngfwv1.ValidationFinding
	for i, rule := range rules {
		if rule == nil || rule.GetDisabled() || rule.GetLog() {
			continue
		}
		out = append(out, warningFinding(
			"POLICY_HYGIENE_MISSING_HOST_INPUT_LOG",
			"Active host-input rule has logging disabled",
			fmt.Sprintf("hostInput.rules[%d].log", i),
			fmt.Sprintf("%s controls management-plane access without rule-level audit evidence.", displayName(rule.GetName(), "host-input rule", i)),
		))
	}
	return out
}

func overlappingRuleFindings(rules []*openngfwv1.Rule) []*openngfwv1.ValidationFinding {
	var out []*openngfwv1.ValidationFinding
	for i, earlier := range rules {
		if !active(earlier) {
			continue
		}
		for j := i + 1; j < len(rules); j++ {
			later := rules[j]
			if !active(later) || !rulesPartiallyOverlap(earlier, later) {
				continue
			}
			out = append(out, warningFinding(
				"POLICY_HYGIENE_RULE_OVERLAP",
				"Rules have overlapping match criteria",
				fmt.Sprintf("rules[%d]", j),
				fmt.Sprintf("%s and %s can match some of the same traffic; first-match rule order decides the verdict.",
					displayName(earlier.GetName(), "rule", i),
					displayName(later.GetName(), "rule", j)),
			))
			if len(out) >= maxOverlapFindings {
				return out
			}
		}
	}
	return out
}

func rulesPartiallyOverlap(a, b *openngfwv1.Rule) bool {
	if a == nil || b == nil {
		return false
	}
	if ruleCovers(a, b) || ruleCovers(b, a) {
		return false
	}
	return dimsOverlap(a.GetFromZones(), b.GetFromZones()) &&
		dimsOverlap(a.GetToZones(), b.GetToZones()) &&
		dimsOverlap(a.GetSourceAddresses(), b.GetSourceAddresses()) &&
		dimsOverlap(a.GetDestinationAddresses(), b.GetDestinationAddresses()) &&
		dimsOverlap(a.GetServices(), b.GetServices()) &&
		dimsOverlap(a.GetApplications(), b.GetApplications())
}

func dimsOverlap(a, b []string) bool {
	if anyToken(a) || anyToken(b) {
		return true
	}
	seen := map[string]bool{}
	for _, item := range a {
		seen[item] = true
	}
	for _, item := range b {
		if seen[item] {
			return true
		}
	}
	return false
}

func unusedObjectFindings(p *openngfwv1.Policy) []*openngfwv1.ValidationFinding {
	addressRefs, serviceRefs, appRefs := referencedPolicyObjects(p)
	var out []*openngfwv1.ValidationFinding
	for i, obj := range p.GetAddresses() {
		if obj.GetName() != "" && !addressRefs[obj.GetName()] {
			out = append(out, warningFinding(
				"POLICY_HYGIENE_UNUSED_ADDRESS",
				"Address object is unused",
				fmt.Sprintf("addresses[%d]", i),
				fmt.Sprintf("%s is not referenced by forwarding policy, host-input policy, or NAT.", obj.GetName()),
			))
		}
	}
	for i, obj := range p.GetServices() {
		if obj.GetName() != "" && !serviceRefs[obj.GetName()] {
			out = append(out, warningFinding(
				"POLICY_HYGIENE_UNUSED_SERVICE",
				"Service object is unused",
				fmt.Sprintf("services[%d]", i),
				fmt.Sprintf("%s is not referenced by forwarding policy, host-input policy, or destination NAT.", obj.GetName()),
			))
		}
	}
	for i, obj := range p.GetApplications() {
		if obj.GetName() != "" && !appRefs[obj.GetName()] {
			out = append(out, warningFinding(
				"POLICY_HYGIENE_UNUSED_APPLICATION",
				"Application object is unused",
				fmt.Sprintf("applications[%d]", i),
				fmt.Sprintf("%s is not referenced by any forwarding rule.", obj.GetName()),
			))
		}
	}
	return out
}

func referencedPolicyObjects(p *openngfwv1.Policy) (map[string]bool, map[string]bool, map[string]bool) {
	addresses := map[string]bool{}
	services := map[string]bool{}
	apps := map[string]bool{}
	addRefs := func(dst map[string]bool, refs ...string) {
		for _, ref := range refs {
			if ref != "" && ref != Any {
				dst[ref] = true
			}
		}
	}

	for _, rule := range p.GetRules() {
		addRefs(addresses, rule.GetSourceAddresses()...)
		addRefs(addresses, rule.GetDestinationAddresses()...)
		addRefs(services, rule.GetServices()...)
		addRefs(apps, rule.GetApplications()...)
	}
	for _, rule := range p.GetHostInput().GetRules() {
		addRefs(addresses, rule.GetSourceAddresses()...)
		addRefs(services, rule.GetServices()...)
	}
	for _, rule := range p.GetNat().GetSource() {
		addRefs(addresses, rule.GetSourceAddress(), rule.GetTranslatedAddress())
	}
	for _, rule := range p.GetNat().GetDestination() {
		addRefs(addresses, rule.GetDestinationAddress(), rule.GetTranslatedAddress())
		addRefs(services, rule.GetService())
	}
	return addresses, services, apps
}
