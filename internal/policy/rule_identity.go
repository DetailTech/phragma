package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"google.golang.org/protobuf/proto"
)

var (
	ruleIDValidRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	ruleIDSanitizeRE    = regexp.MustCompile(`[^a-z0-9._:-]+`)
	ruleIDSeparatorRE   = regexp.MustCompile(`[-._:]{2,}`)
	ruleIDTrimChars     = "-._:"
	ruleIDFallbackLabel = "unnamed"
)

// RuleIdentityReport describes server-side normalization applied to forwarding
// rule identities. It intentionally excludes host-input and NAT rules.
type RuleIdentityReport struct {
	Added      int
	Deduped    int
	Normalized int
}

// PolicyItemIdentityReport describes server-side normalization applied to
// durable non-forwarding policy item identities such as host-input and NAT.
//
//nolint:revive // Retain the established exported name for source compatibility.
type PolicyItemIdentityReport struct {
	HostInputAdded           int
	HostInputDeduped         int
	HostInputNormalized      int
	SourceNatAdded           int
	SourceNatDeduped         int
	SourceNatNormalized      int
	DestinationNatAdded      int
	DestinationNatDeduped    int
	DestinationNatNormalized int
}

// Changed reports whether normalization modified any forwarding rule IDs.
func (r RuleIdentityReport) Changed() bool {
	return r.Added > 0 || r.Deduped > 0 || r.Normalized > 0
}

// Changed reports whether normalization modified any durable policy item IDs.
func (r PolicyItemIdentityReport) Changed() bool {
	return r.HostInputAdded > 0 || r.HostInputDeduped > 0 || r.HostInputNormalized > 0 ||
		r.SourceNatAdded > 0 || r.SourceNatDeduped > 0 || r.SourceNatNormalized > 0 ||
		r.DestinationNatAdded > 0 || r.DestinationNatDeduped > 0 || r.DestinationNatNormalized > 0
}

// NormalizeRuleIDs returns a cloned policy with durable forwarding rule IDs.
// Existing valid unique IDs are preserved. Missing, invalid, or duplicate IDs
// are backfilled from the rule label and a deterministic hash of the rule body
// with the ID cleared.
func NormalizeRuleIDs(p *openngfwv1.Policy) (*openngfwv1.Policy, RuleIdentityReport) {
	if p == nil {
		return &openngfwv1.Policy{}, RuleIdentityReport{}
	}
	out := proto.Clone(p).(*openngfwv1.Policy)
	seen := map[string]struct{}{}
	var report RuleIdentityReport
	for i, r := range out.GetRules() {
		if r == nil {
			continue
		}
		id := strings.TrimSpace(r.GetId())
		switch {
		case id == "":
			r.Id = generatedRuleID(r, i)
			report.Added++
		case !ValidRuleID(id):
			r.Id = generatedRuleID(r, i)
			report.Normalized++
		case id != r.GetId():
			r.Id = id
			report.Normalized++
		}
		if _, ok := seen[r.GetId()]; ok {
			r.Id = generatedRuleID(r, i)
			report.Deduped++
		}
		base := r.GetId()
		for suffix := 2; ; suffix++ {
			if _, ok := seen[r.GetId()]; !ok {
				break
			}
			r.Id = withRuleIDSuffix(base, suffix)
			report.Deduped++
		}
		seen[r.GetId()] = struct{}{}
	}
	return out, report
}

// NormalizePolicyItemIDs returns a cloned policy with durable host-input and
// NAT item IDs. Existing valid unique IDs are preserved. Missing, invalid, or
// duplicate IDs are backfilled from the item label and a deterministic hash of
// the item body with the ID cleared.
func NormalizePolicyItemIDs(p *openngfwv1.Policy) (*openngfwv1.Policy, PolicyItemIdentityReport) {
	if p == nil {
		return &openngfwv1.Policy{}, PolicyItemIdentityReport{}
	}
	out := proto.Clone(p).(*openngfwv1.Policy)
	var report PolicyItemIdentityReport
	seen := map[string]struct{}{}
	if hostInput := out.GetHostInput(); hostInput != nil {
		for i, item := range hostInput.GetRules() {
			if item == nil {
				continue
			}
			id := strings.TrimSpace(item.GetId())
			switch {
			case id == "":
				item.Id = generatedHostInputID(item, i)
				report.HostInputAdded++
			case !ValidRuleID(id):
				item.Id = generatedHostInputID(item, i)
				report.HostInputNormalized++
			case id != item.GetId():
				item.Id = id
				report.HostInputNormalized++
			}
			if _, ok := seen[item.GetId()]; ok {
				item.Id = generatedHostInputID(item, i)
				report.HostInputDeduped++
			}
			base := item.GetId()
			for suffix := 2; ; suffix++ {
				if _, ok := seen[item.GetId()]; !ok {
					break
				}
				item.Id = withRuleIDSuffix(base, suffix)
				report.HostInputDeduped++
			}
			seen[item.GetId()] = struct{}{}
		}
	}
	if nat := out.GetNat(); nat != nil {
		normalizeSourceNatIDs(nat.GetSource(), &report, seen)
		normalizeDestinationNatIDs(nat.GetDestination(), &report, seen)
	}
	return out, report
}

// ValidRuleID reports whether id is a supported durable forwarding-rule ID.
func ValidRuleID(id string) bool {
	return id != "" && strings.TrimSpace(id) == id && ruleIDValidRE.MatchString(id)
}

// RuleIdentityKey returns the best stable key for a forwarding rule.
func RuleIdentityKey(rule *openngfwv1.Rule, index int) string {
	if rule != nil && rule.GetId() != "" {
		return "id:" + rule.GetId()
	}
	if rule != nil && rule.GetName() != "" {
		return "name:" + rule.GetName()
	}
	return "index:" + strconvItoa(index)
}

func generatedRuleID(rule *openngfwv1.Rule, index int) string {
	label := sanitizeRuleIDLabel(rule.GetName())
	hash := ruleIdentityHash(rule, index)
	return withRuleIDLimit("rule-" + label + "-" + hash)
}

func normalizeSourceNatIDs(items []*openngfwv1.SourceNat, report *PolicyItemIdentityReport, seen map[string]struct{}) {
	for i, item := range items {
		if item == nil {
			continue
		}
		id := strings.TrimSpace(item.GetId())
		switch {
		case id == "":
			item.Id = generatedSourceNatID(item, i)
			report.SourceNatAdded++
		case !ValidRuleID(id):
			item.Id = generatedSourceNatID(item, i)
			report.SourceNatNormalized++
		case id != item.GetId():
			item.Id = id
			report.SourceNatNormalized++
		}
		if _, ok := seen[item.GetId()]; ok {
			item.Id = generatedSourceNatID(item, i)
			report.SourceNatDeduped++
		}
		base := item.GetId()
		for suffix := 2; ; suffix++ {
			if _, ok := seen[item.GetId()]; !ok {
				break
			}
			item.Id = withRuleIDSuffix(base, suffix)
			report.SourceNatDeduped++
		}
		seen[item.GetId()] = struct{}{}
	}
}

func normalizeDestinationNatIDs(items []*openngfwv1.DestinationNat, report *PolicyItemIdentityReport, seen map[string]struct{}) {
	for i, item := range items {
		if item == nil {
			continue
		}
		id := strings.TrimSpace(item.GetId())
		switch {
		case id == "":
			item.Id = generatedDestinationNatID(item, i)
			report.DestinationNatAdded++
		case !ValidRuleID(id):
			item.Id = generatedDestinationNatID(item, i)
			report.DestinationNatNormalized++
		case id != item.GetId():
			item.Id = id
			report.DestinationNatNormalized++
		}
		if _, ok := seen[item.GetId()]; ok {
			item.Id = generatedDestinationNatID(item, i)
			report.DestinationNatDeduped++
		}
		base := item.GetId()
		for suffix := 2; ; suffix++ {
			if _, ok := seen[item.GetId()]; !ok {
				break
			}
			item.Id = withRuleIDSuffix(base, suffix)
			report.DestinationNatDeduped++
		}
		seen[item.GetId()] = struct{}{}
	}
}

func generatedHostInputID(item *openngfwv1.HostInputRule, index int) string {
	label := sanitizeRuleIDLabel(item.GetName())
	hash := policyItemIdentityHash(item, index)
	return withRuleIDLimit("host-input-" + label + "-" + hash)
}

func generatedSourceNatID(item *openngfwv1.SourceNat, index int) string {
	label := sanitizeRuleIDLabel(item.GetName())
	hash := policyItemIdentityHash(item, index)
	return withRuleIDLimit("snat-" + label + "-" + hash)
}

func generatedDestinationNatID(item *openngfwv1.DestinationNat, index int) string {
	label := sanitizeRuleIDLabel(item.GetName())
	hash := policyItemIdentityHash(item, index)
	return withRuleIDLimit("dnat-" + label + "-" + hash)
}

func sanitizeRuleIDLabel(name string) string {
	label := strings.ToLower(strings.TrimSpace(name))
	label = ruleIDSanitizeRE.ReplaceAllString(label, "-")
	label = ruleIDSeparatorRE.ReplaceAllString(label, "-")
	label = strings.Trim(label, ruleIDTrimChars)
	if label == "" {
		return ruleIDFallbackLabel
	}
	if len(label) > 64 {
		label = strings.Trim(label[:64], ruleIDTrimChars)
	}
	if label == "" {
		return ruleIDFallbackLabel
	}
	return label
}

func ruleIdentityHash(rule *openngfwv1.Rule, index int) string {
	clone := proto.Clone(rule).(*openngfwv1.Rule)
	clone.Id = ""
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		raw = []byte(strconvItoa(index) + ":" + rule.GetName())
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:12]
}

func policyItemIdentityHash(msg proto.Message, index int) string {
	clone := proto.Clone(msg)
	switch item := clone.(type) {
	case *openngfwv1.HostInputRule:
		item.Id = ""
	case *openngfwv1.SourceNat:
		item.Id = ""
	case *openngfwv1.DestinationNat:
		item.Id = ""
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		raw = []byte(strconvItoa(index))
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:12]
}

func withRuleIDSuffix(base string, suffix int) string {
	return withRuleIDLimit(base + "-" + strconvItoa(suffix))
}

func withRuleIDLimit(id string) string {
	id = strings.Trim(id, ruleIDTrimChars)
	if len(id) <= 128 {
		return id
	}
	parts := strings.Split(id, "-")
	hash := parts[len(parts)-1]
	prefixLimit := 128 - len(hash) - 1
	if prefixLimit < len("rule-x") {
		return id[:128]
	}
	return strings.Trim(id[:prefixLimit], ruleIDTrimChars) + "-" + hash
}

func strconvItoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	n := v
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
