package policy

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

var riskRank = map[openngfwv1.ChangeRisk]int{
	openngfwv1.ChangeRisk_CHANGE_RISK_LOW:    1,
	openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM: 2,
	openngfwv1.ChangeRisk_CHANGE_RISK_HIGH:   3,
}

// Impact returns an operator-facing risk summary for staged policy changes.
// It is intentionally conservative: this is a preflight review aid, not an
// authorization model or formal proof of blast radius.
func Impact(running, candidate *openngfwv1.Policy) *openngfwv1.ChangeImpact {
	if running == nil {
		running = &openngfwv1.Policy{}
	}
	if candidate == nil {
		candidate = &openngfwv1.Policy{}
	}
	out := &openngfwv1.ChangeImpact{Risk: openngfwv1.ChangeRisk_CHANGE_RISK_LOW}
	add := func(risk openngfwv1.ChangeRisk, title, detail string) {
		out.Items = append(out.Items, &openngfwv1.ChangeImpactItem{Risk: risk, Title: title, Detail: detail})
		if riskRank[risk] > riskRank[out.Risk] {
			out.Risk = risk
		}
	}

	for _, c := range ruleChanges(running.GetRules(), candidate.GetRules()) {
		r := c.after
		if r == nil {
			r = c.before
		}
		name := displayName(r.GetName(), "rule", c.index)
		switch c.kind {
		case "added":
			switch {
			case active(r) && allow(r):
				risk := openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM
				if broadRule(r) {
					risk = openngfwv1.ChangeRisk_CHANGE_RISK_HIGH
				}
				add(risk, "New active allow rule", fmt.Sprintf("%s can permit traffic when committed.", name))
			case active(r) && block(r):
				add(openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, "New active blocking rule", fmt.Sprintf("%s can drop or reject matching traffic.", name))
			default:
				add(openngfwv1.ChangeRisk_CHANGE_RISK_LOW, "New disabled rule", fmt.Sprintf("%s is staged but disabled.", name))
			}
		case "removed":
			switch {
			case active(r) && block(r):
				add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Removed active blocking rule", fmt.Sprintf("%s may expose traffic that was previously denied.", name))
			case active(r) && allow(r):
				add(openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, "Removed active allow rule", fmt.Sprintf("%s may interrupt allowed traffic.", name))
			default:
				add(openngfwv1.ChangeRisk_CHANGE_RISK_LOW, "Removed disabled rule", name)
			}
		case "modified":
			wasActive, nowActive := active(c.before), active(c.after)
			switch {
			case (!wasActive && nowActive && allow(c.after)) || (!allow(c.before) && allow(c.after)):
				risk := openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM
				if broadRule(c.after) {
					risk = openngfwv1.ChangeRisk_CHANGE_RISK_HIGH
				}
				add(risk, "Rule now allows traffic", fmt.Sprintf("%s changed to an active allow path.", name))
			case (allow(c.before) && !allow(c.after)) || (!wasActive && nowActive && block(c.after)):
				add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Rule can interrupt traffic", fmt.Sprintf("%s changed toward deny/reject behavior.", name))
			case wasActive != nowActive:
				if nowActive {
					add(openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, "Rule enabled", name)
				} else {
					add(openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, "Rule disabled", name)
				}
			default:
				add(openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, "Rule match changed", fmt.Sprintf("%s changed match criteria, action, logging, or description.", name))
			}
		}
	}
	if ruleOrderChanged(running.GetRules(), candidate.GetRules()) {
		add(openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, "Rule order changed", "Security rules are first-match; order changes can alter verdicts.")
	}
	addRuleHygieneImpact(add, candidate.GetRules())

	for _, c := range objectChanges(running.GetZones(), candidate.GetZones()) {
		add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, changeTitle(c.kind, "zone"), displayName(zoneName(c.after, c.before), "zone", c.index))
	}
	for _, c := range objectChanges(running.GetAddresses(), candidate.GetAddresses()) {
		add(openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, changeTitle(c.kind, "address object"), displayName(addressName(c.after, c.before), "address", c.index))
	}
	for _, c := range objectChanges(running.GetServices(), candidate.GetServices()) {
		add(openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, changeTitle(c.kind, "service object"), displayName(serviceName(c.after, c.before), "service", c.index))
	}
	for _, c := range objectChanges(running.GetApplications(), candidate.GetApplications()) {
		add(openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, changeTitle(c.kind, "application object"), displayName(applicationName(c.after, c.before), "application", c.index))
	}
	for _, c := range objectChanges(running.GetSecurityProfiles(), candidate.GetSecurityProfiles()) {
		profile := c.after
		if profile == nil {
			profile = c.before
		}
		name := displayName(securityProfileName(c.after, c.before), "security profile", c.index)
		if profile.GetTlsInspection() == openngfwv1.TlsInspectionMode_TLS_INSPECTION_MODE_DECRYPTION_REQUIRED {
			add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, changeTitle(c.kind, "security profile"), fmt.Sprintf("%s declares decryption-required inspection intent; confirm external TLS broker and certificate prerequisites before commit.", name))
			continue
		}
		add(openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, changeTitle(c.kind, "security profile"), fmt.Sprintf("%s changes layered TLS/DNS/URL/file inspection intent attached to rules.", name))
	}
	for _, c := range objectChanges(running.GetQosProfiles(), candidate.GetQosProfiles()) {
		name := displayName(qosProfileName(c.after, c.before), "QoS profile", c.index)
		add(openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, changeTitle(c.kind, "QoS profile"), fmt.Sprintf("%s changes plan-only shaping intent; live tc/nft enforcement proof remains hardening.", name))
	}
	for _, c := range objectChanges(running.GetZoneProtectionProfiles(), candidate.GetZoneProtectionProfiles()) {
		name := displayName(zoneProtectionProfileName(c.after, c.before), "zone protection profile", c.index)
		add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, changeTitle(c.kind, "zone protection profile"), fmt.Sprintf("%s changes plan-only DoS/zone-protection intent; live flood enforcement, scale limits, HA sync, and abuse proof remain hardening.", name))
	}

	if !proto.Equal(running.GetNat(), candidate.GetNat()) {
		add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "NAT changed", "Source or destination translation can redirect production traffic.")
	}
	if !proto.Equal(staticRoutesMessage(running.GetStaticRoutes()), staticRoutesMessage(candidate.GetStaticRoutes())) {
		add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Static routes changed", "Routing changes can redirect or blackhole traffic.")
	}
	if !proto.Equal(running.GetRouting(), candidate.GetRouting()) {
		add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Dynamic routing changed", "FRR/BGP/OSPF behavior can change forwarding paths.")
	}
	if !proto.Equal(running.GetVpn(), candidate.GetVpn()) {
		add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "VPN changed", "Tunnel, peer, or cryptographic settings changed.")
	}
	if !proto.Equal(running.GetNetwork(), candidate.GetNetwork()) {
		add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Interface/network changed", "Interface ownership, MTU, offload, or forwarding acceleration changed.")
		if !running.GetNetwork().GetEnableFlowOffload() && candidate.GetNetwork().GetEnableFlowOffload() {
			add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Flowtable fast path enabled", "Established L3/L4 flows can use nftables flowtable acceleration; this profile must not use IDS/IPS inspection.")
		} else if running.GetNetwork().GetEnableFlowOffload() && !candidate.GetNetwork().GetEnableFlowOffload() {
			add(openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, "Flowtable fast path disabled", "Forwarding returns to the standard nftables/conntrack path.")
		}
	}
	if !proto.Equal(running.GetHostInput(), candidate.GetHostInput()) {
		switch {
		case hostInputDefault(running.GetHostInput()) == openngfwv1.Action_ACTION_DENY && hostInputDefault(candidate.GetHostInput()) == openngfwv1.Action_ACTION_ALLOW:
			add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Host input opened", "Traffic to the firewall appliance changes from default-deny to default-allow.")
		case hostInputDefault(candidate.GetHostInput()) == openngfwv1.Action_ACTION_DENY:
			add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Host input hardened", "Traffic to the firewall appliance is default-deny; confirm management allow rules before commit.")
		default:
			add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Host input policy changed", "Management-plane access to the firewall appliance changed.")
		}
	}
	if !proto.Equal(running.GetIds(), candidate.GetIds()) {
		switch {
		case running.GetIds().GetEnabled() && !candidate.GetIds().GetEnabled():
			add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "IDS/IPS disabled", "Traffic inspection will stop for this policy.")
		case candidate.GetIds().GetEnabled() && candidate.GetIds().GetMode() == openngfwv1.IdsMode_IDS_MODE_PREVENT:
			add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "IPS prevention changed", "Inline prevention can drop traffic and depends on fail behavior.")
		default:
			add(openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, "IDS detection changed", "Inspection settings changed.")
		}
	}
	if candidate.GetNetwork().GetEnableFlowOffload() && candidate.GetIds().GetEnabled() {
		add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Flowtable fast path conflicts with IDS/IPS", "Offloaded flows can bypass inspection. Disable IDS/IPS or turn off flowtable before commit.")
	}
	if candidate.GetNetwork().GetEnableFlowOffload() && !hasZoneInterface(candidate.GetZones()) {
		add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Flowtable fast path needs zone interfaces", "Assign at least one interface to a zone before enabling the fast path.")
	}
	if !proto.Equal(running.GetIntel(), candidate.GetIntel()) {
		risk := openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM
		if intelFeedDisabled(running.GetIntel(), candidate.GetIntel()) {
			risk = openngfwv1.ChangeRisk_CHANGE_RISK_HIGH
		}
		add(risk, "Threat intel changed", "Feed or content settings changed.")
	}
	if !proto.Equal(running.GetTelemetry(), candidate.GetTelemetry()) {
		add(openngfwv1.ChangeRisk_CHANGE_RISK_LOW, "Telemetry changed", "Logging or export behavior changed.")
	}

	if len(out.Items) == 0 {
		add(openngfwv1.ChangeRisk_CHANGE_RISK_LOW, "No material policy risk detected", "The candidate matches the running policy.")
	}
	return out
}

type ruleChange struct {
	kind          string
	before, after *openngfwv1.Rule
	index         int
}

func ruleChanges(before, after []*openngfwv1.Rule) []ruleChange {
	oldMap := map[string]ruleChange{}
	for i, r := range before {
		oldMap[ruleKey(r, i)] = ruleChange{before: r, index: i}
	}
	newMap := map[string]ruleChange{}
	for i, r := range after {
		newMap[ruleKey(r, i)] = ruleChange{after: r, index: i}
	}
	var out []ruleChange
	for k, n := range newMap {
		o, ok := oldMap[k]
		if !ok {
			n.kind = "added"
			out = append(out, n)
			continue
		}
		if !proto.Equal(o.before, n.after) {
			out = append(out, ruleChange{kind: "modified", before: o.before, after: n.after, index: n.index})
		}
	}
	for k, o := range oldMap {
		if _, ok := newMap[k]; !ok {
			o.kind = "removed"
			out = append(out, o)
		}
	}
	return out
}

type namedObject interface {
	GetName() string
	proto.Message
}

type objectChange[T namedObject] struct {
	kind          string
	before, after T
	index         int
}

func objectChanges[T namedObject](before, after []T) []objectChange[T] {
	oldMap := map[string]objectChange[T]{}
	for i, r := range before {
		oldMap[objectKey(r, i)] = objectChange[T]{before: r, index: i}
	}
	newMap := map[string]objectChange[T]{}
	for i, r := range after {
		newMap[objectKey(r, i)] = objectChange[T]{after: r, index: i}
	}
	var out []objectChange[T]
	for k, n := range newMap {
		o, ok := oldMap[k]
		if !ok {
			n.kind = "added"
			out = append(out, n)
			continue
		}
		if !proto.Equal(o.before, n.after) {
			out = append(out, objectChange[T]{kind: "modified", before: o.before, after: n.after, index: n.index})
		}
	}
	for k, o := range oldMap {
		if _, ok := newMap[k]; !ok {
			o.kind = "removed"
			out = append(out, o)
		}
	}
	return out
}

func ruleKey(r *openngfwv1.Rule, i int) string {
	if r != nil && r.GetId() != "" {
		return "id:" + r.GetId()
	}
	return objectKey(r, i)
}

func objectKey(o interface{ GetName() string }, i int) string {
	if o != nil && o.GetName() != "" {
		return "name:" + o.GetName()
	}
	return fmt.Sprintf("index:%d", i)
}

func displayName(name, kind string, i int) string {
	if name != "" {
		return name
	}
	return fmt.Sprintf("%s #%d", kind, i+1)
}

func active(r *openngfwv1.Rule) bool { return r != nil && !r.GetDisabled() }
func allow(r *openngfwv1.Rule) bool {
	return r != nil && r.GetAction() == openngfwv1.Action_ACTION_ALLOW
}
func block(r *openngfwv1.Rule) bool {
	return r != nil && (r.GetAction() == openngfwv1.Action_ACTION_DENY || r.GetAction() == openngfwv1.Action_ACTION_REJECT)
}

func hostInputDefault(hostInput *openngfwv1.HostInput) openngfwv1.Action {
	if hostInput == nil || hostInput.GetDefaultAction() == openngfwv1.Action_ACTION_UNSPECIFIED {
		return openngfwv1.Action_ACTION_ALLOW
	}
	return hostInput.GetDefaultAction()
}

func anyToken(xs []string) bool {
	if len(xs) == 0 {
		return true
	}
	for _, x := range xs {
		if x == Any {
			return true
		}
	}
	return false
}

func broadRule(r *openngfwv1.Rule) bool {
	if r == nil {
		return false
	}
	return anyToken(r.GetFromZones()) && anyToken(r.GetToZones()) &&
		anyToken(r.GetSourceAddresses()) && anyToken(r.GetDestinationAddresses()) &&
		anyToken(r.GetServices())
}

func addRuleHygieneImpact(add func(openngfwv1.ChangeRisk, string, string), rules []*openngfwv1.Rule) {
	for _, s := range shadowedRules(rules) {
		add(openngfwv1.ChangeRisk_CHANGE_RISK_MEDIUM, "Shadowed rule",
			fmt.Sprintf("%s is fully covered by earlier rule %s; first-match evaluation will not reach it.",
				displayName(rules[s.index].GetName(), "rule", s.index),
				displayName(rules[s.by].GetName(), "rule", s.by)))
	}
	for i, r := range rules {
		if active(r) && allow(r) && broadRule(r) {
			add(openngfwv1.ChangeRisk_CHANGE_RISK_HIGH, "Active broad allow rule",
				fmt.Sprintf("%s permits any source to any destination/service; narrow the match or document the exception before production use.",
					displayName(r.GetName(), "rule", i)))
		}
	}
}

type shadowedRule struct {
	index int
	by    int
}

func shadowedRules(rules []*openngfwv1.Rule) []shadowedRule {
	var out []shadowedRule
	for i, r := range rules {
		if !active(r) {
			continue
		}
		for j := 0; j < i; j++ {
			if active(rules[j]) && ruleCovers(rules[j], r) {
				out = append(out, shadowedRule{index: i, by: j})
				break
			}
		}
	}
	return out
}

func ruleCovers(a, b *openngfwv1.Rule) bool {
	if a == nil || b == nil {
		return false
	}
	return coversDim(a.GetFromZones(), b.GetFromZones()) &&
		coversDim(a.GetToZones(), b.GetToZones()) &&
		coversDim(a.GetSourceAddresses(), b.GetSourceAddresses()) &&
		coversDim(a.GetDestinationAddresses(), b.GetDestinationAddresses()) &&
		coversDim(a.GetServices(), b.GetServices()) &&
		coversDim(a.GetApplications(), b.GetApplications())
}

func coversDim(a, b []string) bool {
	if anyToken(a) {
		return true
	}
	if anyToken(b) {
		return false
	}
	seen := map[string]bool{}
	for _, x := range a {
		seen[x] = true
	}
	for _, x := range b {
		if !seen[x] {
			return false
		}
	}
	return true
}

func ruleOrderChanged(before, after []*openngfwv1.Rule) bool {
	if len(before) != len(after) {
		return false
	}
	seen := map[string]bool{}
	for i := range before {
		beforeKey := ruleOrderKey(before[i])
		afterKey := ruleOrderKey(after[i])
		if beforeKey == "" || afterKey == "" {
			return false
		}
		seen[beforeKey] = true
	}
	for _, r := range after {
		if !seen[ruleOrderKey(r)] {
			return false
		}
	}
	for i := range before {
		if ruleOrderKey(before[i]) != ruleOrderKey(after[i]) {
			return true
		}
	}
	return false
}

func ruleOrderKey(r *openngfwv1.Rule) string {
	if r == nil {
		return ""
	}
	if r.GetId() != "" {
		return "id:" + r.GetId()
	}
	if r.GetName() != "" {
		return "name:" + r.GetName()
	}
	return ""
}

func changeTitle(kind, noun string) string {
	switch kind {
	case "added":
		return "Added " + noun
	case "removed":
		return "Removed " + noun
	default:
		return "Modified " + noun
	}
}

func zoneName(after, before *openngfwv1.Zone) string {
	if after != nil {
		return after.GetName()
	}
	return before.GetName()
}

func addressName(after, before *openngfwv1.Address) string {
	if after != nil {
		return after.GetName()
	}
	return before.GetName()
}

func serviceName(after, before *openngfwv1.Service) string {
	if after != nil {
		return after.GetName()
	}
	return before.GetName()
}

func applicationName(after, before *openngfwv1.Application) string {
	if after != nil {
		return after.GetName()
	}
	return before.GetName()
}

func securityProfileName(after, before *openngfwv1.SecurityProfile) string {
	if after != nil {
		return after.GetName()
	}
	return before.GetName()
}

func qosProfileName(after, before *openngfwv1.QosProfile) string {
	if after != nil {
		return after.GetName()
	}
	return before.GetName()
}

func zoneProtectionProfileName(after, before *openngfwv1.ZoneProtectionProfile) string {
	if after != nil {
		return after.GetName()
	}
	return before.GetName()
}

func staticRoutesMessage(routes []*openngfwv1.StaticRoute) proto.Message {
	return &openngfwv1.Policy{StaticRoutes: routes}
}

func hasZoneInterface(zones []*openngfwv1.Zone) bool {
	for _, z := range zones {
		if len(z.GetInterfaces()) > 0 {
			return true
		}
	}
	return false
}

func intelFeedDisabled(before, after *openngfwv1.Intel) bool {
	oldFeeds := map[string]bool{}
	for _, f := range before.GetFeeds() {
		oldFeeds[f.GetName()] = f.GetEnabled()
	}
	for _, f := range after.GetFeeds() {
		if oldFeeds[f.GetName()] && !f.GetEnabled() {
			return true
		}
	}
	return false
}
