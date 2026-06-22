// Package explain evaluates a flow tuple against the declarative policy
// model and returns a normalized OpenNGFW explanation.
package explain

import (
	"fmt"
	"net/netip"
	"strings"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/policy"
)

// ExplainFlow explains how p would treat req. It is intentionally pure:
// callers can use it for running, candidate, and historical policies without
// touching engines or the store.
//
//nolint:revive // The name mirrors the public ExplainFlow RPC and request/response types.
func ExplainFlow(p *openngfwv1.Policy, req *openngfwv1.ExplainFlowRequest, version uint64) (*openngfwv1.ExplainFlowResponse, error) {
	if p == nil {
		return nil, fmt.Errorf("policy is required")
	}
	if req == nil {
		return nil, fmt.Errorf("request is required")
	}
	p, _ = policy.NormalizeRuleIDs(p)
	p, _ = policy.NormalizePolicyItemIDs(p)
	input, err := parseInput(req)
	if err != nil {
		return nil, err
	}
	idx, err := newIndex(p)
	if err != nil {
		return nil, err
	}

	resp := &openngfwv1.ExplainFlowResponse{
		PolicySource:  sourceOrRunning(req.GetPolicySource()),
		PolicyVersion: version,
		Warnings: []string{
			"policy-model verdict; dynamic intel set contents and engine-native verdicts are not included yet",
		},
	}
	if req.GetFromZone() == "" || req.GetToZone() == "" {
		resp.Warnings = append(resp.Warnings, "from_zone and to_zone were not both provided; only wildcard zone rules can match missing zone context")
	}

	resp.Evidence = append(resp.Evidence, fmt.Sprintf("flow %s:%d -> %s:%d %s, zones %s -> %s",
		input.src, input.srcPort, input.dst, input.dstPort, protocolName(input.proto), anyIfEmpty(input.fromZone), anyIfEmpty(input.toZone)))

	natProfile, translated, err := idx.applyDNAT(input)
	if err != nil {
		return nil, err
	}
	resp.NatProfile = natProfile
	if dest := natProfile.GetDestination(); dest.GetMatched() {
		resp.Evidence = append(resp.Evidence, dest.GetEvidence()...)
		resp.Trace = append(resp.Trace, fmt.Sprintf("destination-nat %q matched before policy evaluation", dest.GetMatchedRule()))
	}
	input = translated

	for i, r := range p.GetRules() {
		if r.GetDisabled() {
			resp.Trace = append(resp.Trace, fmt.Sprintf("rule[%d] %q skipped: disabled", i, r.GetName()))
			continue
		}
		if reason, ok, err := idx.ruleMatches(input, r); err != nil {
			return nil, err
		} else if !ok {
			resp.Trace = append(resp.Trace, fmt.Sprintf("rule[%d] %q skipped: %s", i, r.GetName(), reason))
			continue
		}

		resp.MatchedRule = r.GetName()
		resp.MatchedRuleId = r.GetId()
		resp.MatchedRuleIndex = uint32(i)
		resp.MatchedRuleContext = cloneRuleMatchContext(r.GetMatchContext())
		resp.Verdict = verdictForAction(r.GetAction())
		inspection := explainInspection(p, resp.Verdict)
		resp.InspectionState = inspection.state
		resp.InspectionProfile = inspection.profile
		resp.Reason = fmt.Sprintf("first matching policy rule %q returned %s", r.GetName(), actionName(r.GetAction()))
		resp.Evidence = append(resp.Evidence,
			fmt.Sprintf("matched rule %q at index %d", r.GetName(), i),
			fmt.Sprintf("rule action %s", actionName(r.GetAction())),
		)
		resp.Evidence = append(resp.Evidence, idx.applicationEvidence(input, r)...)
		resp.Warnings = append(resp.Warnings, applicationWarnings(input, r)...)
		resp.Evidence = append(resp.Evidence, ruleMatchContextEvidence(r.GetMatchContext())...)
		resp.Warnings = append(resp.Warnings, ruleMatchContextWarnings(r.GetMatchContext())...)
		resp.Evidence = append(resp.Evidence, inspection.evidence...)
		resp.Warnings = append(resp.Warnings, inspection.warnings...)
		route := idx.explainRoute(input, resp.Verdict)
		resp.RouteProfile = route.profile
		resp.Evidence = append(resp.Evidence, route.evidence...)
		resp.Warnings = append(resp.Warnings, route.warnings...)
		if resp.Verdict == openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_ALLOWED {
			if snat := idx.evaluateSNAT(input, resp.NatProfile); snat != "" {
				resp.Evidence = append(resp.Evidence, snat)
			}
		} else {
			markSNATSkipped(resp.NatProfile, resp.Verdict)
		}
		AnnotateDecisionVocabulary(resp)
		return resp, nil
	}

	resp.DefaultPolicy = true
	resp.Verdict = openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_DEFAULT_DROP
	inspection := explainInspection(p, resp.Verdict)
	resp.InspectionState = inspection.state
	resp.InspectionProfile = inspection.profile
	resp.Reason = "no enabled security rule matched; nftables forward chain policy drops by default"
	resp.Evidence = append(resp.Evidence, "default forward-chain policy is drop")
	resp.Evidence = append(resp.Evidence, inspection.evidence...)
	resp.Warnings = append(resp.Warnings, inspection.warnings...)
	route := idx.explainRoute(input, resp.Verdict)
	resp.RouteProfile = route.profile
	resp.Evidence = append(resp.Evidence, route.evidence...)
	resp.Warnings = append(resp.Warnings, route.warnings...)
	markSNATSkipped(resp.NatProfile, resp.Verdict)
	AnnotateDecisionVocabulary(resp)
	return resp, nil
}

// AnnotateDecisionVocabulary derives the hard-requirement decision vocabulary
// from the detailed verdict, inspection profile, and optional runtime evidence.
func AnnotateDecisionVocabulary(resp *openngfwv1.ExplainFlowResponse) {
	if resp == nil {
		return
	}
	terms := []openngfwv1.ExplainDecisionTerm{}
	add := func(term openngfwv1.ExplainDecisionTerm) {
		if term == openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_UNSPECIFIED {
			return
		}
		for _, existing := range terms {
			if existing == term {
				return
			}
		}
		terms = append(terms, term)
	}

	if resp.GetVerdict() == openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_ALLOWED {
		add(openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_ALLOWED)
	} else if resp.GetVerdict() != openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_UNSPECIFIED {
		add(openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_BLOCKED)
	}

	profile := resp.GetInspectionProfile()
	switch resp.GetInspectionState() {
	case openngfwv1.ExplainInspectionState_EXPLAIN_INSPECTION_STATE_NOT_INSPECTED:
		if resp.GetVerdict() == openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_ALLOWED {
			add(openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_BYPASSED)
		}
	case openngfwv1.ExplainInspectionState_EXPLAIN_INSPECTION_STATE_IDS_DETECT:
		add(openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_PARTIALLY_INSPECTED)
	case openngfwv1.ExplainInspectionState_EXPLAIN_INSPECTION_STATE_IPS_PREVENT:
		if profile.GetFailureBehavior() == openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED {
			add(openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_FULLY_INSPECTED)
		} else {
			add(openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_PARTIALLY_INSPECTED)
		}
	case openngfwv1.ExplainInspectionState_EXPLAIN_INSPECTION_STATE_BLOCKED_BEFORE_INSPECTION:
		add(openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_BLOCKED)
	}

	if profile.GetBypassPossible() || profile.GetFlowOffloadEnabled() {
		add(openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_BYPASSED)
	}
	switch profile.GetFailureBehavior() {
	case openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_OPEN:
		add(openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_FAIL_OPEN)
	case openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED:
		add(openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_FAIL_CLOSED)
	case openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_UNSPECIFIED:
		if profile.GetIdsEnabled() && profile.GetIdsMode() == openngfwv1.IdsMode_IDS_MODE_PREVENT {
			add(openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_FAILED)
		}
	}
	if resp.GetRuntimeEvidence().GetQueried() && resp.GetRuntimeEvidence().GetState() == "unavailable" {
		add(openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_FAILED)
	}

	resp.DecisionTerms = terms
	resp.DecisionSummary = decisionSummary(terms)
}

type flowInput struct {
	fromZone string
	toZone   string
	src      netip.Addr
	srcPort  uint16
	dst      netip.Addr
	dstPort  uint16
	proto    openngfwv1.Protocol
	appID    string
	context  matchContext
}

type matchContext struct {
	users         []string
	groups        []string
	devices       []string
	postureLabels []string
}

func parseInput(req *openngfwv1.ExplainFlowRequest) (flowInput, error) {
	src, err := netip.ParseAddr(req.GetSrcIp())
	if err != nil {
		return flowInput{}, fmt.Errorf("src_ip %q is invalid: %w", req.GetSrcIp(), err)
	}
	dst, err := netip.ParseAddr(req.GetDestIp())
	if err != nil {
		return flowInput{}, fmt.Errorf("dest_ip %q is invalid: %w", req.GetDestIp(), err)
	}
	if req.GetSrcPort() > 65535 {
		return flowInput{}, fmt.Errorf("src_port %d out of range 0-65535", req.GetSrcPort())
	}
	if req.GetDestPort() > 65535 {
		return flowInput{}, fmt.Errorf("dest_port %d out of range 0-65535", req.GetDestPort())
	}
	switch req.GetProtocol() {
	case openngfwv1.Protocol_PROTOCOL_TCP, openngfwv1.Protocol_PROTOCOL_UDP:
		if req.GetDestPort() == 0 {
			return flowInput{}, fmt.Errorf("dest_port is required for %s", protocolName(req.GetProtocol()))
		}
	case openngfwv1.Protocol_PROTOCOL_ICMP, openngfwv1.Protocol_PROTOCOL_ANY:
	default:
		return flowInput{}, fmt.Errorf("protocol is required")
	}
	return flowInput{
		fromZone: req.GetFromZone(),
		toZone:   req.GetToZone(),
		src:      src,
		srcPort:  uint16(req.GetSrcPort()),
		dst:      dst,
		dstPort:  uint16(req.GetDestPort()),
		proto:    req.GetProtocol(),
		appID:    strings.ToLower(strings.TrimSpace(req.GetAppId())),
		context:  requestMatchContext(req.GetMatchContext()),
	}, nil
}

func requestMatchContext(ctx *openngfwv1.RuleMatchContext) matchContext {
	if ctx == nil {
		return matchContext{}
	}
	return matchContext{
		users:         canonicalContextValues(ctx.GetUsers()),
		groups:        canonicalContextValues(ctx.GetGroups()),
		devices:       canonicalContextValues(ctx.GetDevices()),
		postureLabels: canonicalContextValues(ctx.GetPostureLabels()),
	}
}

func cloneRuleMatchContext(ctx *openngfwv1.RuleMatchContext) *openngfwv1.RuleMatchContext {
	if ctx == nil || ruleContextEmpty(ctx) {
		return nil
	}
	return &openngfwv1.RuleMatchContext{
		Users:         append([]string(nil), ctx.GetUsers()...),
		Groups:        append([]string(nil), ctx.GetGroups()...),
		Devices:       append([]string(nil), ctx.GetDevices()...),
		PostureLabels: append([]string(nil), ctx.GetPostureLabels()...),
	}
}

func canonicalContextValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized != "" {
			out = append(out, normalized)
		}
	}
	return out
}

type index struct {
	policy    *openngfwv1.Policy
	addresses map[string]netip.Prefix
	services  map[string]*openngfwv1.Service
	apps      map[string]*openngfwv1.Application
	routes    []routeInfo
}

type routeInfo struct {
	route  *openngfwv1.StaticRoute
	prefix netip.Prefix
	index  int
}

func newIndex(p *openngfwv1.Policy) (*index, error) {
	idx := &index{policy: p, addresses: map[string]netip.Prefix{}, services: map[string]*openngfwv1.Service{}, apps: map[string]*openngfwv1.Application{}}
	for _, a := range p.GetAddresses() {
		pfx, err := netip.ParsePrefix(a.GetCidr())
		if err != nil {
			return nil, fmt.Errorf("address %q has invalid CIDR %q: %w", a.GetName(), a.GetCidr(), err)
		}
		idx.addresses[a.GetName()] = pfx
	}
	for _, s := range p.GetServices() {
		idx.services[s.GetName()] = s
	}
	for _, app := range p.GetApplications() {
		idx.apps[app.GetName()] = app
	}
	for i, r := range p.GetStaticRoutes() {
		pfx, err := netip.ParsePrefix(r.GetDestination())
		if err != nil {
			return nil, fmt.Errorf("static route #%d has invalid destination %q: %w", i+1, r.GetDestination(), err)
		}
		if r.GetVia() != "" {
			if _, err := netip.ParseAddr(r.GetVia()); err != nil {
				return nil, fmt.Errorf("static route %q has invalid next-hop %q: %w", r.GetDestination(), r.GetVia(), err)
			}
		}
		idx.routes = append(idx.routes, routeInfo{route: r, prefix: pfx, index: i})
	}
	return idx, nil
}

func (idx *index) ruleMatches(in flowInput, r *openngfwv1.Rule) (string, bool, error) {
	if !zoneMatches(r.GetFromZones(), in.fromZone) {
		return fmt.Sprintf("from_zone %q not in %s", anyIfEmpty(in.fromZone), refsString(r.GetFromZones())), false, nil
	}
	if !zoneMatches(r.GetToZones(), in.toZone) {
		return fmt.Sprintf("to_zone %q not in %s", anyIfEmpty(in.toZone), refsString(r.GetToZones())), false, nil
	}
	if ok, err := idx.addressMatches(r.GetSourceAddresses(), in.src); err != nil {
		return "", false, fmt.Errorf("rule %q source address match: %w", r.GetName(), err)
	} else if !ok {
		return fmt.Sprintf("source %s not in %s", in.src, refsString(r.GetSourceAddresses())), false, nil
	}
	if ok, err := idx.addressMatches(r.GetDestinationAddresses(), in.dst); err != nil {
		return "", false, fmt.Errorf("rule %q destination address match: %w", r.GetName(), err)
	} else if !ok {
		return fmt.Sprintf("destination %s not in %s", in.dst, refsString(r.GetDestinationAddresses())), false, nil
	}
	if ok, err := idx.serviceMatches(r.GetServices(), in.proto, in.dstPort); err != nil {
		return "", false, fmt.Errorf("rule %q service match: %w", r.GetName(), err)
	} else if !ok {
		return fmt.Sprintf("service %s/%d not in %s", protocolName(in.proto), in.dstPort, refsString(r.GetServices())), false, nil
	}
	if ok, err := idx.applicationMatches(r.GetApplications(), in); err != nil {
		return "", false, fmt.Errorf("rule %q application match: %w", r.GetName(), err)
	} else if !ok {
		return fmt.Sprintf("application %s with %s/%d not in %s", anyIfEmpty(in.appID), protocolName(in.proto), in.dstPort, refsString(r.GetApplications())), false, nil
	}
	if reason, ok := ruleMatchContextMatches(r.GetMatchContext(), in.context); !ok {
		return reason, false, nil
	}
	return "matched", true, nil
}

func ruleMatchContextMatches(required *openngfwv1.RuleMatchContext, supplied matchContext) (string, bool) {
	if required == nil || ruleContextEmpty(required) {
		return "", true
	}
	checks := []struct {
		name     string
		required []string
		supplied []string
	}{
		{name: "user", required: required.GetUsers(), supplied: supplied.users},
		{name: "group", required: required.GetGroups(), supplied: supplied.groups},
		{name: "device", required: required.GetDevices(), supplied: supplied.devices},
		{name: "posture", required: required.GetPostureLabels(), supplied: supplied.postureLabels},
	}
	for _, check := range checks {
		if len(check.required) == 0 {
			continue
		}
		if !intersectsContext(check.required, check.supplied) {
			return fmt.Sprintf("%s context %s not in %s", check.name, refsString(check.supplied), refsString(check.required)), false
		}
	}
	return "", true
}

func ruleContextEmpty(ctx *openngfwv1.RuleMatchContext) bool {
	return len(ctx.GetUsers()) == 0 && len(ctx.GetGroups()) == 0 && len(ctx.GetDevices()) == 0 && len(ctx.GetPostureLabels()) == 0
}

func intersectsContext(required, supplied []string) bool {
	if len(required) == 0 {
		return true
	}
	seen := map[string]bool{}
	for _, value := range supplied {
		seen[strings.ToLower(strings.TrimSpace(value))] = true
	}
	for _, value := range required {
		if seen[strings.ToLower(strings.TrimSpace(value))] {
			return true
		}
	}
	return false
}

func ruleMatchContextEvidence(ctx *openngfwv1.RuleMatchContext) []string {
	if ctx == nil || ruleContextEmpty(ctx) {
		return nil
	}
	return []string{"matched rule identity/posture context: " + ruleMatchContextSummary(ctx)}
}

func ruleMatchContextWarnings(ctx *openngfwv1.RuleMatchContext) []string {
	if ctx == nil || ruleContextEmpty(ctx) {
		return nil
	}
	return []string{"identity/posture context was matched from ExplainFlow request fields only; no live directory, group freshness, MDM, or step-up authentication lookup was performed"}
}

func ruleMatchContextSummary(ctx *openngfwv1.RuleMatchContext) string {
	if ctx == nil {
		return ""
	}
	parts := []string{}
	if values := ctx.GetUsers(); len(values) > 0 {
		parts = append(parts, "users="+strings.Join(values, ","))
	}
	if values := ctx.GetGroups(); len(values) > 0 {
		parts = append(parts, "groups="+strings.Join(values, ","))
	}
	if values := ctx.GetDevices(); len(values) > 0 {
		parts = append(parts, "devices="+strings.Join(values, ","))
	}
	if values := ctx.GetPostureLabels(); len(values) > 0 {
		parts = append(parts, "posture_labels="+strings.Join(values, ","))
	}
	return strings.Join(parts, " ")
}

func baseNatProfile(in flowInput) *openngfwv1.ExplainNatProfile {
	return &openngfwv1.ExplainNatProfile{
		Destination: &openngfwv1.ExplainDestinationNatProfile{
			Evaluated:                 true,
			OriginalDestinationIp:     in.dst.String(),
			OriginalDestinationPort:   uint32(in.dstPort),
			TranslatedDestinationIp:   in.dst.String(),
			TranslatedDestinationPort: uint32(in.dstPort),
			Reason:                    "no destination NAT rule matched before policy evaluation",
		},
		Source: &openngfwv1.ExplainSourceNatProfile{
			OriginalSourceIp: in.src.String(),
			Reason:           "source NAT is evaluated only after an allow verdict",
		},
	}
}

func (idx *index) applyDNAT(in flowInput) (*openngfwv1.ExplainNatProfile, flowInput, error) {
	profile := baseNatProfile(in)
	for i, dn := range idx.policy.GetNat().GetDestination() {
		if !zoneMatches([]string{dn.GetFromZone()}, in.fromZone) {
			continue
		}
		svc, ok := idx.services[dn.GetService()]
		if !ok {
			return nil, in, fmt.Errorf("destination-nat %q references unknown service %q", dn.GetName(), dn.GetService())
		}
		if !serviceMatches(svc, in.proto, in.dstPort) {
			continue
		}
		matchDst, ok := idx.addresses[dn.GetDestinationAddress()]
		if !ok {
			return nil, in, fmt.Errorf("destination-nat %q references unknown destination_address %q", dn.GetName(), dn.GetDestinationAddress())
		}
		if !matchDst.Contains(in.dst) {
			continue
		}
		translated, ok := idx.addresses[dn.GetTranslatedAddress()]
		if !ok {
			return nil, in, fmt.Errorf("destination-nat %q references unknown translated_address %q", dn.GetName(), dn.GetTranslatedAddress())
		}
		out := in
		out.dst = translated.Addr()
		if dn.GetTranslatedPort() != 0 {
			out.dstPort = uint16(dn.GetTranslatedPort())
		}
		evidence := fmt.Sprintf("dnat %q translated destination %s:%d -> %s:%d", dn.GetName(), in.dst, in.dstPort, out.dst, out.dstPort)
		profile.Destination.Matched = true
		profile.Destination.MatchedRule = dn.GetName()
		profile.Destination.MatchedRuleId = dn.GetId()
		profile.Destination.MatchedRuleIndex = uint32(i)
		profile.Destination.TranslatedDestinationIp = out.dst.String()
		profile.Destination.TranslatedDestinationPort = uint32(out.dstPort)
		profile.Destination.Reason = fmt.Sprintf("destination NAT %q matched before policy evaluation", dn.GetName())
		profile.Destination.Evidence = append(profile.Destination.Evidence, evidence)
		profile.Evidence = append(profile.Evidence, evidence)
		return profile, out, nil
	}
	return profile, in, nil
}

func (idx *index) evaluateSNAT(in flowInput, profile *openngfwv1.ExplainNatProfile) string {
	if profile == nil {
		return ""
	}
	source := profile.GetSource()
	if source == nil {
		source = &openngfwv1.ExplainSourceNatProfile{OriginalSourceIp: in.src.String()}
		profile.Source = source
	}
	source.Evaluated = true
	source.Reason = "no source NAT rule matched after policy allow"
	for i, sn := range idx.policy.GetNat().GetSource() {
		if !zoneMatches([]string{sn.GetToZone()}, in.toZone) {
			continue
		}
		if ref := sn.GetSourceAddress(); ref != "" && ref != policy.Any {
			pfx, ok := idx.addresses[ref]
			if !ok || !pfx.Contains(in.src) {
				continue
			}
		}
		if sn.GetMasquerade() {
			evidence := fmt.Sprintf("source-nat %q will masquerade the source after policy allow", sn.GetName())
			source.Matched = true
			source.MatchedRule = sn.GetName()
			source.MatchedRuleId = sn.GetId()
			source.MatchedRuleIndex = uint32(i)
			source.Masquerade = true
			source.Reason = fmt.Sprintf("source NAT %q matched after policy allow", sn.GetName())
			source.Evidence = append(source.Evidence, evidence)
			profile.Evidence = append(profile.Evidence, evidence)
			return evidence
		}
		if ref := sn.GetTranslatedAddress(); ref != "" {
			if pfx, ok := idx.addresses[ref]; ok {
				evidence := fmt.Sprintf("source-nat %q will translate source to %s after policy allow", sn.GetName(), pfx.Addr())
				source.Matched = true
				source.MatchedRule = sn.GetName()
				source.MatchedRuleId = sn.GetId()
				source.MatchedRuleIndex = uint32(i)
				source.TranslatedSourceIp = pfx.Addr().String()
				source.Reason = fmt.Sprintf("source NAT %q matched after policy allow", sn.GetName())
				source.Evidence = append(source.Evidence, evidence)
				profile.Evidence = append(profile.Evidence, evidence)
				return evidence
			}
		}
	}
	return ""
}

func markSNATSkipped(profile *openngfwv1.ExplainNatProfile, verdict openngfwv1.ExplainVerdict) {
	if profile == nil {
		return
	}
	source := profile.GetSource()
	if source == nil {
		source = &openngfwv1.ExplainSourceNatProfile{}
		profile.Source = source
	}
	source.Evaluated = false
	source.Reason = fmt.Sprintf("source NAT not evaluated because policy verdict is %s", strings.ToLower(strings.TrimPrefix(verdict.String(), "EXPLAIN_VERDICT_")))
}

type routeExplanation struct {
	profile  *openngfwv1.ExplainRouteProfile
	evidence []string
	warnings []string
}

func (idx *index) explainRoute(in flowInput, verdict openngfwv1.ExplainVerdict) routeExplanation {
	profile := &openngfwv1.ExplainRouteProfile{
		Evaluated: false,
		Source:    "not-evaluated",
	}
	out := routeExplanation{profile: profile}
	if verdict != openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_ALLOWED {
		profile.Reason = fmt.Sprintf("route lookup not evaluated because the policy verdict is %s", verdictName(verdict))
		profile.Evidence = append(profile.Evidence, "routing skipped for non-allow verdict")
		out.evidence = append(out.evidence, profile.Reason)
		return out
	}

	profile.Evaluated = true
	if best, ok := idx.matchRoute(in.dst); ok {
		r := best.route
		profile.Matched = true
		profile.Source = "static"
		profile.Destination = best.prefix.String()
		profile.NextHop = r.GetVia()
		profile.EgressInterface = r.GetInterface()
		profile.Metric = r.GetMetric()
		profile.Reason = fmt.Sprintf("static route %s selected for destination %s by longest-prefix match", best.prefix, in.dst)
		profile.Evidence = append(profile.Evidence, routeLine(best))
		out.evidence = append(out.evidence, "route decision: "+routeLine(best))
		return out
	}

	profile.Source = "kernel-unresolved"
	profile.Reason = fmt.Sprintf("no OpenNGFW static route matched destination %s", in.dst)
	profile.Evidence = append(profile.Evidence, "no static route entry matched the post-DNAT destination")
	if routingEnabled(idx.policy) {
		profile.Evidence = append(profile.Evidence, "FRR dynamic routing is enabled, but live kernel/FRR route state is outside this pure policy explanation")
		out.warnings = append(out.warnings, "no static route matched; live FRR/kernel route state is not included in ExplainFlow yet")
	} else {
		profile.Evidence = append(profile.Evidence, "connected and default kernel routes are outside this pure policy explanation")
		out.warnings = append(out.warnings, "no static route matched; connected/default kernel route state is not included in ExplainFlow yet")
	}
	out.evidence = append(out.evidence, "route decision unresolved in policy model: "+profile.Reason)
	return out
}

func (idx *index) matchRoute(dst netip.Addr) (routeInfo, bool) {
	var best routeInfo
	found := false
	for _, r := range idx.routes {
		if !r.prefix.Contains(dst) {
			continue
		}
		if !found ||
			r.prefix.Bits() > best.prefix.Bits() ||
			(r.prefix.Bits() == best.prefix.Bits() && r.route.GetMetric() < best.route.GetMetric()) {
			best = r
			found = true
		}
	}
	return best, found
}

func routeLine(r routeInfo) string {
	parts := []string{fmt.Sprintf("static route %s", r.prefix)}
	if via := r.route.GetVia(); via != "" {
		parts = append(parts, "via "+via)
	}
	if dev := r.route.GetInterface(); dev != "" {
		parts = append(parts, "dev "+dev)
	}
	if metric := r.route.GetMetric(); metric != 0 {
		parts = append(parts, fmt.Sprintf("metric %d", metric))
	}
	return strings.Join(parts, " ")
}

func routingEnabled(p *openngfwv1.Policy) bool {
	return p.GetRouting().GetBgp().GetEnabled() || p.GetRouting().GetOspf().GetEnabled()
}

func (idx *index) addressMatches(refs []string, ip netip.Addr) (bool, error) {
	if len(refs) == 0 || containsAny(refs) {
		return true, nil
	}
	for _, ref := range refs {
		pfx, ok := idx.addresses[ref]
		if !ok {
			return false, fmt.Errorf("unknown address %q", ref)
		}
		if pfx.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}

func (idx *index) serviceMatches(refs []string, proto openngfwv1.Protocol, dstPort uint16) (bool, error) {
	if len(refs) == 0 || containsAny(refs) {
		return true, nil
	}
	for _, ref := range refs {
		svc, ok := idx.services[ref]
		if !ok {
			return false, fmt.Errorf("unknown service %q", ref)
		}
		if serviceMatches(svc, proto, dstPort) {
			return true, nil
		}
	}
	return false, nil
}

func (idx *index) applicationMatches(refs []string, in flowInput) (bool, error) {
	if len(refs) == 0 || containsAny(refs) {
		return true, nil
	}
	for _, ref := range refs {
		app, ok := idx.apps[ref]
		if !ok {
			return false, fmt.Errorf("unknown application %q", ref)
		}
		if applicationPortMatches(app, in.proto, in.dstPort) {
			return true, nil
		}
		if applicationSignalMatches(app, in.appID) && idsPreventFailClosed(idx.policy.GetIds()) {
			return true, nil
		}
	}
	return false, nil
}

func (idx *index) applicationEvidence(in flowInput, r *openngfwv1.Rule) []string {
	if len(r.GetApplications()) == 0 || containsAny(r.GetApplications()) {
		return nil
	}
	var out []string
	for _, ref := range r.GetApplications() {
		app, ok := idx.apps[ref]
		if !ok {
			continue
		}
		switch {
		case applicationPortMatches(app, in.proto, in.dstPort):
			out = append(out, fmt.Sprintf("application %q matched TCP/UDP port-hint enforcement for %s/%d", ref, protocolName(in.proto), in.dstPort))
		case applicationSignalMatches(app, in.appID) && idsPreventFailClosed(idx.policy.GetIds()):
			out = append(out, fmt.Sprintf("application %q matched Suricata App-ID signal %q with IDS/IPS Prevent fail-closed", ref, in.appID))
		default:
			continue
		}
		if in.appID != "" && in.appID != ref && !applicationSignalValue(app, in.appID) {
			out = append(out, fmt.Sprintf("observed app_id %q differs from rule application %q; current enforcement is by port hint, not engine signal", in.appID, ref))
		}
	}
	return out
}

func applicationWarnings(in flowInput, r *openngfwv1.Rule) []string {
	if len(r.GetApplications()) == 0 || containsAny(r.GetApplications()) {
		return nil
	}
	out := []string{"application-scoped deny rules use TCP/UDP port hints, or supported Suricata App-ID signals when IDS/IPS is Prevent fail-closed"}
	if in.appID == "" {
		out = append(out, "no app_id was supplied; signal-only App-ID rules cannot be explained as matching without observed application evidence")
	}
	return out
}

func idsPreventFailClosed(ids *openngfwv1.Ids) bool {
	return ids.GetEnabled() &&
		ids.GetMode() == openngfwv1.IdsMode_IDS_MODE_PREVENT &&
		ids.GetFailureBehavior() == openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED
}

func applicationPortMatches(app *openngfwv1.Application, proto openngfwv1.Protocol, dstPort uint16) bool {
	for _, hint := range app.GetPorts() {
		if hint.GetProtocol() != proto {
			continue
		}
		for _, pr := range hint.GetPorts() {
			end := pr.GetEnd()
			if end == 0 {
				end = pr.GetStart()
			}
			if uint32(dstPort) >= pr.GetStart() && uint32(dstPort) <= end {
				return true
			}
		}
	}
	return false
}

func applicationSignalMatches(app *openngfwv1.Application, observed string) bool {
	observed = strings.ToLower(strings.TrimSpace(observed))
	if observed == "" {
		return false
	}
	if observed == strings.ToLower(strings.TrimSpace(app.GetName())) && hasSupportedAppIDSignal(app) {
		return true
	}
	return applicationSignalValue(app, observed)
}

func applicationSignalValue(app *openngfwv1.Application, observed string) bool {
	observed = strings.ToLower(strings.TrimSpace(observed))
	for _, signal := range app.GetEngineSignals() {
		if strings.ToLower(strings.TrimSpace(signal)) == observed && supportedAppIDSignal(observed) {
			return true
		}
	}
	return false
}

func hasSupportedAppIDSignal(app *openngfwv1.Application) bool {
	for _, signal := range app.GetEngineSignals() {
		if supportedAppIDSignal(strings.ToLower(strings.TrimSpace(signal))) {
			return true
		}
	}
	return false
}

func supportedAppIDSignal(signal string) bool {
	switch signal {
	case "dns", "http", "ssh", "tls":
		return true
	}
	return false
}

func serviceMatches(svc *openngfwv1.Service, proto openngfwv1.Protocol, dstPort uint16) bool {
	switch svc.GetProtocol() {
	case openngfwv1.Protocol_PROTOCOL_ANY:
		return true
	case openngfwv1.Protocol_PROTOCOL_ICMP:
		return proto == openngfwv1.Protocol_PROTOCOL_ICMP
	case openngfwv1.Protocol_PROTOCOL_TCP, openngfwv1.Protocol_PROTOCOL_UDP:
		if proto != svc.GetProtocol() {
			return false
		}
		if len(svc.GetPorts()) == 0 {
			return true
		}
		for _, pr := range svc.GetPorts() {
			end := pr.GetEnd()
			if end == 0 {
				end = pr.GetStart()
			}
			if uint32(dstPort) >= pr.GetStart() && uint32(dstPort) <= end {
				return true
			}
		}
	}
	return false
}

func zoneMatches(refs []string, zone string) bool {
	if len(refs) == 0 || containsAny(refs) {
		return true
	}
	if zone == "" {
		return false
	}
	for _, ref := range refs {
		if ref == zone {
			return true
		}
	}
	return false
}

func containsAny(refs []string) bool {
	for _, ref := range refs {
		if ref == policy.Any {
			return true
		}
	}
	return false
}

func verdictForAction(a openngfwv1.Action) openngfwv1.ExplainVerdict {
	switch a {
	case openngfwv1.Action_ACTION_ALLOW:
		return openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_ALLOWED
	case openngfwv1.Action_ACTION_DENY:
		return openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_DENIED
	case openngfwv1.Action_ACTION_REJECT:
		return openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_REJECTED
	default:
		return openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_DEFAULT_DROP
	}
}

type inspectionExplanation struct {
	state    openngfwv1.ExplainInspectionState
	profile  *openngfwv1.ExplainInspectionProfile
	evidence []string
	warnings []string
}

func explainInspection(p *openngfwv1.Policy, _ openngfwv1.ExplainVerdict) inspectionExplanation {
	ids := p.GetIds()
	network := p.GetNetwork()
	profile := &openngfwv1.ExplainInspectionProfile{
		IdsEnabled:         ids.GetEnabled(),
		IdsMode:            ids.GetMode(),
		FailureBehavior:    ids.GetFailureBehavior(),
		FlowOffloadEnabled: network.GetEnableFlowOffload(),
	}
	out := inspectionExplanation{
		state:   openngfwv1.ExplainInspectionState_EXPLAIN_INSPECTION_STATE_NOT_INSPECTED,
		profile: profile,
	}

	if network.GetEnableFlowOffload() {
		profile.BypassPossible = true
		profile.BypassReason = "network.enable_flow_offload can fast-path established L3/L4 flows around userspace inspection; validation requires IDS/IPS disabled for this profile"
		out.evidence = append(out.evidence, "flowtable fast path enabled for established forwarded flows")
		out.warnings = append(out.warnings, "flowtable fast path is enabled; established flows can bypass userspace inspection by policy")
	}

	if ids == nil || !ids.GetEnabled() {
		profile.Engine = "none"
		profile.InspectionOrder = "no IDS/IPS inspection engine is attached to the policy path"
		profile.DegradedBehavior = "engine outage has no IDS/IPS effect because inspection is disabled"
		profile.Evidence = append(profile.Evidence, "IDS/IPS disabled")
		out.evidence = append(out.evidence, "IDS/IPS disabled; flow is not inspected by the Suricata engine")
		return out
	}

	profile.Engine = "suricata"
	if ids.GetMode() == openngfwv1.IdsMode_IDS_MODE_PREVENT {
		out.state = openngfwv1.ExplainInspectionState_EXPLAIN_INSPECTION_STATE_IPS_PREVENT
		profile.InspectionOrder = "inline NFQUEUE handoff runs before the OpenNGFW policy rule/default verdict in the current nftables renderer"
		if ids.GetFailureBehavior() == openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED {
			profile.DegradedBehavior = "fail-closed: if Suricata/NFQUEUE is unavailable, queued traffic is held or dropped instead of bypassing inspection"
			profile.Evidence = append(profile.Evidence, "IPS prevent mode", "fail-closed NFQUEUE behavior")
			out.evidence = append(out.evidence, "IDS/IPS prevent mode enabled with fail-closed NFQUEUE behavior")
			return out
		}
		profile.BypassPossible = true
		profile.BypassReason = "ids.failure_behavior is fail-open; if Suricata/NFQUEUE is unavailable, queued packets bypass inspection and continue to policy evaluation"
		if ids.GetFailureBehavior() == openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_UNSPECIFIED {
			profile.DegradedBehavior = "failure behavior is unspecified; policy validation rejects prevent mode until fail-open or fail-closed is declared"
			profile.Evidence = append(profile.Evidence, "IPS prevent mode", "failure behavior unspecified")
			out.evidence = append(out.evidence, "IDS/IPS prevent mode enabled but failure behavior is unspecified")
			out.warnings = append(out.warnings, "IDS/IPS prevent mode requires explicit fail-open or fail-closed behavior before commit")
			return out
		}
		profile.DegradedBehavior = "fail-open: if Suricata/NFQUEUE is unavailable, queued traffic bypasses inspection and continues to policy evaluation"
		profile.Evidence = append(profile.Evidence, "IPS prevent mode", "fail-open NFQUEUE bypass behavior")
		out.evidence = append(out.evidence, "IDS/IPS prevent mode enabled with fail-open NFQUEUE bypass behavior")
		out.warnings = append(out.warnings, "IDS/IPS prevent mode is configured fail-open; degraded Suricata/NFQUEUE can bypass inspection")
		return out
	}
	out.state = openngfwv1.ExplainInspectionState_EXPLAIN_INSPECTION_STATE_IDS_DETECT
	profile.InspectionOrder = "passive AF_PACKET observation is outside the nftables forward verdict path"
	profile.DegradedBehavior = "engine outage stops detections and flow telemetry but does not change the OpenNGFW policy verdict"
	profile.Evidence = append(profile.Evidence, "IDS detect mode", "passive Suricata observation")
	out.evidence = append(out.evidence, "IDS/IPS detect mode enabled; Suricata observes traffic passively")
	return out
}

func sourceOrRunning(src openngfwv1.PolicySource) openngfwv1.PolicySource {
	if src == openngfwv1.PolicySource_POLICY_SOURCE_UNSPECIFIED {
		return openngfwv1.PolicySource_POLICY_SOURCE_RUNNING
	}
	return src
}

func actionName(a openngfwv1.Action) string {
	switch a {
	case openngfwv1.Action_ACTION_ALLOW:
		return "allow"
	case openngfwv1.Action_ACTION_DENY:
		return "deny"
	case openngfwv1.Action_ACTION_REJECT:
		return "reject"
	default:
		return "unspecified"
	}
}

func verdictName(v openngfwv1.ExplainVerdict) string {
	switch v {
	case openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_ALLOWED:
		return "allowed"
	case openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_DENIED:
		return "denied"
	case openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_REJECTED:
		return "rejected"
	case openngfwv1.ExplainVerdict_EXPLAIN_VERDICT_DEFAULT_DROP:
		return "default drop"
	default:
		return "unspecified"
	}
}

func decisionSummary(terms []openngfwv1.ExplainDecisionTerm) string {
	labels := make([]string, 0, len(terms))
	for _, term := range terms {
		if label := decisionTermName(term); label != "" {
			labels = append(labels, label)
		}
	}
	return strings.Join(labels, ", ")
}

func decisionTermName(term openngfwv1.ExplainDecisionTerm) string {
	switch term {
	case openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_ALLOWED:
		return "allowed"
	case openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_BLOCKED:
		return "blocked"
	case openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_BYPASSED:
		return "bypassed"
	case openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_PARTIALLY_INSPECTED:
		return "partially inspected"
	case openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_FULLY_INSPECTED:
		return "fully inspected"
	case openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_DECRYPTED:
		return "decrypted"
	case openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_FAILED:
		return "failed"
	case openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_FAIL_OPEN:
		return "fail-open"
	case openngfwv1.ExplainDecisionTerm_EXPLAIN_DECISION_TERM_FAIL_CLOSED:
		return "fail-closed"
	default:
		return ""
	}
}

func protocolName(p openngfwv1.Protocol) string {
	switch p {
	case openngfwv1.Protocol_PROTOCOL_TCP:
		return "tcp"
	case openngfwv1.Protocol_PROTOCOL_UDP:
		return "udp"
	case openngfwv1.Protocol_PROTOCOL_ICMP:
		return "icmp"
	case openngfwv1.Protocol_PROTOCOL_ANY:
		return "any"
	default:
		return "unspecified"
	}
}

func refsString(refs []string) string {
	if len(refs) == 0 {
		return "[any]"
	}
	return "[" + strings.Join(refs, ", ") + "]"
}

func anyIfEmpty(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
