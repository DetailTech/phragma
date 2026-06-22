package compiler

import (
	"fmt"
	"net/netip"
	"strings"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/policy"
)

// Compile resolves p into the IR. p must already have passed
// policy.Validate; Compile re-checks only what it needs to avoid
// undefined behavior and returns an error on any dangling reference.
func Compile(p *openngfwv1.Policy) (*IR, error) {
	p, _ = policy.NormalizeRuleIDs(p)
	p, _ = policy.NormalizePolicyItemIDs(p)
	if errs := policy.Validate(p); len(errs) > 0 {
		return nil, fmt.Errorf("policy invalid: %s (and %d more)", errs[0], len(errs)-1)
	}

	c := &compilation{
		zoneIfaces:       map[string][]string{},
		addrs:            map[string]netip.Prefix{},
		svcs:             map[string]ServiceMatch{},
		apps:             map[string]*openngfwv1.Application{},
		appServiceHints:  map[string][]ServiceMatch{},
		securityProfiles: map[string]*openngfwv1.SecurityProfile{},
		qosProfiles:      map[string]*openngfwv1.QosProfile{},
		zoneProtections:  map[string]*openngfwv1.ZoneProtectionProfile{},
	}
	ir := &IR{}

	for _, z := range p.GetZones() {
		c.zoneIfaces[z.GetName()] = z.GetInterfaces()
		ir.Zones = append(ir.Zones, ZoneIR{Name: z.GetName(), Interfaces: z.GetInterfaces(), ZoneProtectionProfile: z.GetZoneProtectionProfile()})
	}
	for _, a := range p.GetAddresses() {
		pfx, err := netip.ParsePrefix(a.GetCidr())
		if err != nil {
			return nil, fmt.Errorf("address %q: %w", a.GetName(), err)
		}
		c.addrs[a.GetName()] = pfx
	}
	for _, s := range p.GetServices() {
		m, err := serviceMatch(s)
		if err != nil {
			return nil, err
		}
		c.svcs[s.GetName()] = m
	}
	for _, app := range p.GetApplications() {
		c.apps[app.GetName()] = app
		c.appServiceHints[app.GetName()] = applicationServiceMatches(app)
	}
	for _, profile := range p.GetSecurityProfiles() {
		c.securityProfiles[profile.GetName()] = profile
	}
	for _, profile := range p.GetQosProfiles() {
		c.qosProfiles[profile.GetName()] = profile
	}
	for _, profile := range p.GetZoneProtectionProfiles() {
		c.zoneProtections[profile.GetName()] = profile
	}

	for _, r := range p.GetRules() {
		if r.GetDisabled() {
			continue
		}
		rule, err := c.compileRule(r)
		if err != nil {
			return nil, err
		}
		ir.Rules = append(ir.Rules, rule)
	}
	if hostInput := p.GetHostInput(); hostInput != nil {
		defaultAction, err := actionFromProto("host_input default_action", hostInput.GetDefaultAction(), true)
		if err != nil {
			return nil, err
		}
		ir.HostInputDefault = defaultAction
		for _, r := range hostInput.GetRules() {
			if r.GetDisabled() {
				continue
			}
			rule, err := c.compileHostInputRule(r)
			if err != nil {
				return nil, err
			}
			ir.HostInputRules = append(ir.HostInputRules, rule)
		}
	}

	for _, sn := range p.GetNat().GetSource() {
		snat, err := c.compileSNAT(sn)
		if err != nil {
			return nil, err
		}
		ir.SNAT = append(ir.SNAT, snat)
	}
	for _, dn := range p.GetNat().GetDestination() {
		dnat, err := c.compileDNAT(dn)
		if err != nil {
			return nil, err
		}
		ir.DNAT = append(ir.DNAT, dnat)
	}

	for _, sr := range p.GetStaticRoutes() {
		route, err := compileRoute(sr)
		if err != nil {
			return nil, err
		}
		ir.Routes = append(ir.Routes, route)
	}

	ids, err := compileIDs(p, c.addrs)
	if err != nil {
		return nil, err
	}
	ir.IDs = ids
	ir.AppIDControls = compileAppIDControls(ir.Rules, ids)
	ir.AppIDDrops = compileAppIDDrops(ir.AppIDControls)
	ir.SecurityProfileRules = compileSecurityProfileRules(ir.Rules, ids, c.securityProfiles)
	ir.QoSControls = compileQoSControls(ir.Rules, c.qosProfiles)
	ir.ZoneProtections = compileZoneProtections(ir.Zones, c.zoneProtections)
	ir.Telemetry = compileTelemetry(p)

	routing, err := compileRouting(p)
	if err != nil {
		return nil, err
	}
	ir.Routing = routing

	vpn, err := compileVPN(p)
	if err != nil {
		return nil, err
	}
	ir.VPN = vpn

	ir.Network = compileNetwork(p, ids)
	ir.Proxy = compileProxy(p)

	if intel := p.GetIntel(); intel != nil {
		enabled := len(intel.GetCustomFeeds()) > 0
		for _, fe := range intel.GetFeeds() {
			if fe.GetEnabled() {
				enabled = true
				break
			}
		}
		if enabled {
			ir.Intel = &IntelIR{Enabled: true}
		}
	}

	return ir, nil
}

func compileProxy(p *openngfwv1.Policy) *ProxyIR {
	proxy := p.GetProxy()
	if proxy == nil || (len(proxy.GetVirtualServices()) == 0 && len(proxy.GetWafPolicies()) == 0) {
		return nil
	}
	out := &ProxyIR{}
	for _, waf := range proxy.GetWafPolicies() {
		item := WAFPolicyIR{
			Name:               waf.GetName(),
			Mode:               wafModeString(waf.GetMode()),
			RequestBodyLimitKB: waf.GetRequestBodyLimitKb(),
			AuditLogging:       waf.GetAuditLogging(),
			RedactRequestBody:  waf.GetRedactRequestBody(),
			Description:        waf.GetDescription(),
		}
		for _, ruleSet := range waf.GetRuleSets() {
			item.RuleSets = append(item.RuleSets, WAFRuleSetIR{
				Name:    ruleSet.GetName(),
				Version: ruleSet.GetVersion(),
				Source:  ruleSet.GetSource(),
				SHA256:  ruleSet.GetSha256(),
			})
		}
		out.WAFPolicies = append(out.WAFPolicies, item)
	}
	for _, vs := range proxy.GetVirtualServices() {
		item := VirtualServiceIR{
			Name:        vs.GetName(),
			Enabled:     vs.GetEnabled(),
			Hostnames:   append([]string(nil), vs.GetHostnames()...),
			Description: vs.GetDescription(),
		}
		if listener := vs.GetListener(); listener != nil {
			item.Listener = ProxyListenerIR{
				BindAddress:  listener.GetBindAddress(),
				Port:         listener.GetPort(),
				TLS:          listener.GetTls(),
				TLSSecretRef: listener.GetTlsSecretRef(),
			}
		}
		for _, route := range vs.GetRoutes() {
			routeIR := ProxyRouteIR{
				Name:                 route.GetName(),
				PathPrefix:           route.GetPathPrefix(),
				WAFPolicy:            route.GetWafPolicy(),
				RequireMTLSToBackend: route.GetRequireMtlsToBackend(),
				StripPrefix:          route.GetStripPrefix(),
			}
			for _, backend := range route.GetBackends() {
				routeIR.Backends = append(routeIR.Backends, ProxyBackendIR{
					Name:   backend.GetName(),
					URL:    backend.GetUrl(),
					Weight: backend.GetWeight(),
				})
			}
			item.Routes = append(item.Routes, routeIR)
		}
		out.VirtualServices = append(out.VirtualServices, item)
	}
	return out
}

func wafModeString(mode openngfwv1.WafMode) string {
	switch mode {
	case openngfwv1.WafMode_WAF_MODE_DETECT:
		return "detect"
	case openngfwv1.WafMode_WAF_MODE_BLOCK:
		return "block"
	default:
		return "unspecified"
	}
}

type compilation struct {
	zoneIfaces       map[string][]string
	addrs            map[string]netip.Prefix
	svcs             map[string]ServiceMatch
	apps             map[string]*openngfwv1.Application
	appServiceHints  map[string][]ServiceMatch
	securityProfiles map[string]*openngfwv1.SecurityProfile
	qosProfiles      map[string]*openngfwv1.QosProfile
	zoneProtections  map[string]*openngfwv1.ZoneProtectionProfile
}

// resolveIfaces expands zone references to interface names. A wildcard
// or empty list resolves to nil (match any interface).
func (c *compilation) resolveIfaces(refs []string) ([]string, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	var out []string
	for _, r := range refs {
		if r == policy.Any {
			return nil, nil
		}
		ifaces, ok := c.zoneIfaces[r]
		if !ok {
			return nil, fmt.Errorf("unknown zone %q", r)
		}
		out = append(out, ifaces...)
	}
	return out, nil
}

func (c *compilation) resolvePrefixes(refs []string) ([]netip.Prefix, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	var out []netip.Prefix
	for _, r := range refs {
		if r == policy.Any {
			return nil, nil
		}
		pfx, ok := c.addrs[r]
		if !ok {
			return nil, fmt.Errorf("unknown address %q", r)
		}
		out = append(out, pfx)
	}
	return out, nil
}

func (c *compilation) compileRule(r *openngfwv1.Rule) (RuleIR, error) {
	var (
		rule RuleIR
		err  error
	)
	rule.ID = r.GetId()
	rule.Name = r.GetName()
	rule.Log = r.GetLog()

	if rule.FromIfaces, err = c.resolveIfaces(r.GetFromZones()); err != nil {
		return rule, fmt.Errorf("rule %q: %w", r.GetName(), err)
	}
	if rule.ToIfaces, err = c.resolveIfaces(r.GetToZones()); err != nil {
		return rule, fmt.Errorf("rule %q: %w", r.GetName(), err)
	}
	if rule.SrcPrefixes, err = c.resolvePrefixes(r.GetSourceAddresses()); err != nil {
		return rule, fmt.Errorf("rule %q: %w", r.GetName(), err)
	}
	if rule.DstPrefixes, err = c.resolvePrefixes(r.GetDestinationAddresses()); err != nil {
		return rule, fmt.Errorf("rule %q: %w", r.GetName(), err)
	}
	rule.MatchContext = compileRuleMatchContext(r.GetMatchContext())

	for _, ref := range r.GetServices() {
		if ref == policy.Any {
			rule.Services = nil
			break
		}
		m, ok := c.svcs[ref]
		if !ok {
			return rule, fmt.Errorf("rule %q: unknown service %q", r.GetName(), ref)
		}
		rule.Services = append(rule.Services, m)
	}
	for _, ref := range r.GetApplications() {
		if ref == policy.Any {
			rule.Applications = nil
			break
		}
		app, ok := c.apps[ref]
		if !ok {
			return rule, fmt.Errorf("rule %q: unknown application %q", r.GetName(), ref)
		}
		rule.Applications = append(rule.Applications, ref)
		if signals := supportedAppIDSignals(app.GetEngineSignals()); len(signals) > 0 {
			rule.AppIDSignals = append(rule.AppIDSignals, AppIDSignalIR{
				Application: ref,
				Signals:     signals,
			})
		}
		matches := c.appServiceHints[ref]
		rule.Services = append(rule.Services, matches...)
	}
	if len(r.GetApplications()) > 0 && len(r.GetServices()) == 0 && len(rule.Services) == 0 && len(rule.AppIDSignals) > 0 {
		rule.AppIDOnly = true
	}
	for _, ref := range r.GetSecurityProfiles() {
		profile, ok := c.securityProfiles[ref]
		if !ok {
			return rule, fmt.Errorf("rule %q: unknown security profile %q", r.GetName(), ref)
		}
		if securityProfileRequiresInspection(profile) {
			rule.SecurityProfiles = append(rule.SecurityProfiles, ref)
			rule.InspectionRequired = true
		}
	}
	if ref := r.GetQosProfile(); ref != "" {
		if _, ok := c.qosProfiles[ref]; !ok {
			return rule, fmt.Errorf("rule %q: unknown QoS profile %q", r.GetName(), ref)
		}
		rule.QoSProfile = ref
	}

	if rule.Action, err = actionFromProto("rule "+r.GetName(), r.GetAction(), false); err != nil {
		return rule, err
	}
	return rule, nil
}

func compileRuleMatchContext(ctx *openngfwv1.RuleMatchContext) RuleMatchContextIR {
	if ctx == nil {
		return RuleMatchContextIR{}
	}
	return RuleMatchContextIR{
		Users:         append([]string(nil), ctx.GetUsers()...),
		Groups:        append([]string(nil), ctx.GetGroups()...),
		Devices:       append([]string(nil), ctx.GetDevices()...),
		PostureLabels: append([]string(nil), ctx.GetPostureLabels()...),
	}
}

const appIDControlSIDBase uint32 = 4200000
const securityProfileRuleSIDBase uint32 = 4300000

func compileAppIDControls(rules []RuleIR, ids *IDsIR) []AppIDControlIR {
	if ids == nil || !ids.Prevent || ids.FailOpen {
		return nil
	}
	var out []AppIDControlIR
	for _, rule := range rules {
		if rule.Action != ActionAllow && rule.Action != ActionDeny {
			continue
		}
		for _, app := range rule.AppIDSignals {
			for _, signal := range app.Signals {
				services := rule.Services
				if len(services) == 0 {
					services = []ServiceMatch{{Protocol: ProtoAny}}
				}
				for _, service := range services {
					out = append(out, AppIDControlIR{
						RuleName:     rule.Name,
						RuleID:       rule.ID,
						Application:  app.Application,
						EngineSignal: signal,
						Action:       rule.Action,
						SrcPrefixes:  append([]netip.Prefix(nil), rule.SrcPrefixes...),
						DstPrefixes:  append([]netip.Prefix(nil), rule.DstPrefixes...),
						Service:      service,
						SID:          appIDControlSIDBase + uint32(len(out)+1),
					})
				}
			}
		}
	}
	return out
}

func compileAppIDDrops(controls []AppIDControlIR) []AppIDDropIR {
	var out []AppIDDropIR
	for _, control := range controls {
		if control.Action != ActionDeny {
			continue
		}
		out = append(out, AppIDDropIR{
			RuleName:     control.RuleName,
			Application:  control.Application,
			EngineSignal: control.EngineSignal,
			SID:          control.SID,
		})
	}
	return out
}

func compileSecurityProfileRules(rules []RuleIR, ids *IDsIR, profiles map[string]*openngfwv1.SecurityProfile) []SecurityProfileRuleIR {
	if ids == nil || !ids.Prevent || ids.FailOpen {
		return nil
	}
	var out []SecurityProfileRuleIR
	for _, rule := range rules {
		if rule.Action != ActionAllow || !rule.InspectionRequired {
			continue
		}
		for _, ref := range rule.SecurityProfiles {
			for _, control := range securityProfileControls(profiles[ref]) {
				out = append(out, SecurityProfileRuleIR{
					RuleName:    rule.Name,
					ProfileName: ref,
					Control:     control.Control,
					Protocol:    control.Protocol,
					SID:         securityProfileRuleSIDBase + uint32(len(out)+1),
				})
			}
		}
	}
	return out
}

func compileQoSControls(rules []RuleIR, profiles map[string]*openngfwv1.QosProfile) []QoSControlIR {
	var out []QoSControlIR
	for _, rule := range rules {
		if rule.QoSProfile == "" {
			continue
		}
		profile := profiles[rule.QoSProfile]
		if profile == nil {
			continue
		}
		out = append(out, QoSControlIR{
			RuleName:                rule.Name,
			RuleID:                  rule.ID,
			ProfileName:             rule.QoSProfile,
			MaxBandwidthKbps:        profile.GetMaxBandwidthKbps(),
			GuaranteedBandwidthKbps: profile.GetGuaranteedBandwidthKbps(),
			Priority:                qosPriorityLabel(profile.GetPriority()),
			DSCPMark:                profile.GetDscpMark(),
			BurstKBytes:             profile.GetBurstKbytes(),
		})
	}
	return out
}

func compileZoneProtections(zones []ZoneIR, profiles map[string]*openngfwv1.ZoneProtectionProfile) []ZoneProtectionIR {
	var out []ZoneProtectionIR
	for _, zone := range zones {
		if zone.ZoneProtectionProfile == "" {
			continue
		}
		profile := profiles[zone.ZoneProtectionProfile]
		if profile == nil {
			continue
		}
		out = append(out, ZoneProtectionIR{
			ZoneName:                 zone.Name,
			Interfaces:               append([]string(nil), zone.Interfaces...),
			ProfileName:              zone.ZoneProtectionProfile,
			Enabled:                  profile.GetEnabled(),
			SynFloodPPS:              profile.GetSynFloodPps(),
			UDPFloodPPS:              profile.GetUdpFloodPps(),
			ICMPFloodPPS:             profile.GetIcmpFloodPps(),
			MaxConcurrentConnections: profile.GetMaxConcurrentConnections(),
			Action:                   zoneProtectionActionLabel(profile.GetAction()),
			AuditLog:                 profile.GetAuditLog(),
		})
	}
	return out
}

func qosPriorityLabel(priority openngfwv1.QosPriority) string {
	switch priority {
	case openngfwv1.QosPriority_QOS_PRIORITY_LOW:
		return "low"
	case openngfwv1.QosPriority_QOS_PRIORITY_MEDIUM:
		return "medium"
	case openngfwv1.QosPriority_QOS_PRIORITY_HIGH:
		return "high"
	case openngfwv1.QosPriority_QOS_PRIORITY_CRITICAL:
		return "critical"
	default:
		return "unspecified"
	}
}

func zoneProtectionActionLabel(action openngfwv1.ZoneProtectionAction) string {
	switch action {
	case openngfwv1.ZoneProtectionAction_ZONE_PROTECTION_ACTION_ALERT:
		return "alert"
	case openngfwv1.ZoneProtectionAction_ZONE_PROTECTION_ACTION_DROP:
		return "drop"
	default:
		return "unspecified"
	}
}

type securityProfileControl struct {
	Control  string
	Protocol string
}

func securityProfileControls(profile *openngfwv1.SecurityProfile) []securityProfileControl {
	if profile == nil {
		return nil
	}
	var out []securityProfileControl
	switch profile.GetTlsInspection() {
	case openngfwv1.TlsInspectionMode_TLS_INSPECTION_MODE_DECRYPTION_REQUIRED:
		out = append(out, securityProfileControl{Control: "tls-inspection:decryption-required", Protocol: "tls"})
	}
	for _, category := range profile.GetUrlCategories() {
		out = append(out, securityProfileControl{Control: "url-category:" + category, Protocol: "http"})
	}
	switch profile.GetDnsSecurity() {
	case openngfwv1.DnsSecurityMode_DNS_SECURITY_MODE_BLOCK_MALICIOUS:
		out = append(out, securityProfileControl{Control: "dns-security:block-malicious", Protocol: "dns"})
	}
	switch profile.GetFileSecurity() {
	case openngfwv1.FileSecurityMode_FILE_SECURITY_MODE_BLOCK_EXECUTABLES:
		out = append(out, securityProfileControl{Control: "file-security:block-executables", Protocol: "http"})
	case openngfwv1.FileSecurityMode_FILE_SECURITY_MODE_BLOCK_HIGH_RISK:
		out = append(out, securityProfileControl{Control: "file-security:block-high-risk", Protocol: "http"})
	}
	return out
}

func securityProfileRequiresInspection(profile *openngfwv1.SecurityProfile) bool {
	if profile == nil {
		return false
	}
	switch profile.GetTlsInspection() {
	case openngfwv1.TlsInspectionMode_TLS_INSPECTION_MODE_DECRYPTION_REQUIRED:
		return true
	}
	if len(profile.GetUrlCategories()) > 0 {
		return true
	}
	switch profile.GetDnsSecurity() {
	case openngfwv1.DnsSecurityMode_DNS_SECURITY_MODE_BLOCK_MALICIOUS:
		return true
	}
	switch profile.GetFileSecurity() {
	case openngfwv1.FileSecurityMode_FILE_SECURITY_MODE_BLOCK_EXECUTABLES,
		openngfwv1.FileSecurityMode_FILE_SECURITY_MODE_BLOCK_HIGH_RISK:
		return true
	}
	return false
}

func (c *compilation) compileHostInputRule(r *openngfwv1.HostInputRule) (RuleIR, error) {
	var (
		rule RuleIR
		err  error
	)
	rule.ID = r.GetId()
	rule.Name = r.GetName()
	rule.Log = r.GetLog()
	if rule.FromIfaces, err = c.resolveIfaces(r.GetFromZones()); err != nil {
		return rule, fmt.Errorf("host-input rule %q: %w", r.GetName(), err)
	}
	if rule.SrcPrefixes, err = c.resolvePrefixes(r.GetSourceAddresses()); err != nil {
		return rule, fmt.Errorf("host-input rule %q: %w", r.GetName(), err)
	}
	for _, ref := range r.GetServices() {
		if ref == policy.Any {
			rule.Services = nil
			break
		}
		m, ok := c.svcs[ref]
		if !ok {
			return rule, fmt.Errorf("host-input rule %q: unknown service %q", r.GetName(), ref)
		}
		rule.Services = append(rule.Services, m)
	}
	if rule.Action, err = actionFromProto("host-input rule "+r.GetName(), r.GetAction(), false); err != nil {
		return rule, err
	}
	return rule, nil
}

func actionFromProto(ctx string, action openngfwv1.Action, allowUnspecified bool) (RuleAction, error) {
	switch action {
	case openngfwv1.Action_ACTION_UNSPECIFIED:
		if allowUnspecified {
			return ActionAllow, nil
		}
	case openngfwv1.Action_ACTION_ALLOW:
		return ActionAllow, nil
	case openngfwv1.Action_ACTION_DENY:
		return ActionDeny, nil
	case openngfwv1.Action_ACTION_REJECT:
		return ActionReject, nil
	}
	return 0, fmt.Errorf("%s: action unset", ctx)
}

func (c *compilation) compileSNAT(sn *openngfwv1.SourceNat) (SNATIR, error) {
	out := SNATIR{ID: sn.GetId(), Name: sn.GetName(), Masquerade: sn.GetMasquerade()}
	ifaces, err := c.resolveIfaces([]string{sn.GetToZone()})
	if err != nil {
		return out, fmt.Errorf("source-nat %q: %w", sn.GetName(), err)
	}
	out.OutIfaces = ifaces
	if ref := sn.GetSourceAddress(); ref != "" && ref != policy.Any {
		pfx, ok := c.addrs[ref]
		if !ok {
			return out, fmt.Errorf("source-nat %q: unknown address %q", sn.GetName(), ref)
		}
		out.SrcPrefix = &pfx
	}
	if !sn.GetMasquerade() {
		pfx, ok := c.addrs[sn.GetTranslatedAddress()]
		if !ok {
			return out, fmt.Errorf("source-nat %q: unknown address %q", sn.GetName(), sn.GetTranslatedAddress())
		}
		out.TranslateTo = pfx.Addr()
	}
	return out, nil
}

func (c *compilation) compileDNAT(dn *openngfwv1.DestinationNat) (DNATIR, error) {
	out := DNATIR{ID: dn.GetId(), Name: dn.GetName(), ToPort: uint16(dn.GetTranslatedPort())}
	ifaces, err := c.resolveIfaces([]string{dn.GetFromZone()})
	if err != nil {
		return out, fmt.Errorf("destination-nat %q: %w", dn.GetName(), err)
	}
	out.InIfaces = ifaces

	m, ok := c.svcs[dn.GetService()]
	if !ok {
		return out, fmt.Errorf("destination-nat %q: unknown service %q", dn.GetName(), dn.GetService())
	}
	out.Protocol = m.Protocol
	out.Ports = m.Ports

	dst, ok := c.addrs[dn.GetDestinationAddress()]
	if !ok {
		return out, fmt.Errorf("destination-nat %q: unknown address %q", dn.GetName(), dn.GetDestinationAddress())
	}
	out.MatchDst = dst.Addr()

	to, ok := c.addrs[dn.GetTranslatedAddress()]
	if !ok {
		return out, fmt.Errorf("destination-nat %q: unknown address %q", dn.GetName(), dn.GetTranslatedAddress())
	}
	out.TranslateTo = to.Addr()
	return out, nil
}

func serviceMatch(s *openngfwv1.Service) (ServiceMatch, error) {
	var m ServiceMatch
	switch s.GetProtocol() {
	case openngfwv1.Protocol_PROTOCOL_TCP:
		m.Protocol = ProtoTCP
	case openngfwv1.Protocol_PROTOCOL_UDP:
		m.Protocol = ProtoUDP
	case openngfwv1.Protocol_PROTOCOL_ICMP:
		m.Protocol = ProtoICMP
	case openngfwv1.Protocol_PROTOCOL_ANY:
		m.Protocol = ProtoAny
	default:
		return m, fmt.Errorf("service %q: protocol unset", s.GetName())
	}
	for _, pr := range s.GetPorts() {
		end := uint16(pr.GetEnd())
		if end == 0 {
			end = uint16(pr.GetStart())
		}
		m.Ports = append(m.Ports, PortRange{Start: uint16(pr.GetStart()), End: end})
	}
	return m, nil
}

func applicationServiceMatches(app *openngfwv1.Application) []ServiceMatch {
	var out []ServiceMatch
	for _, hint := range app.GetPorts() {
		var proto Proto
		switch hint.GetProtocol() {
		case openngfwv1.Protocol_PROTOCOL_TCP:
			proto = ProtoTCP
		case openngfwv1.Protocol_PROTOCOL_UDP:
			proto = ProtoUDP
		default:
			continue
		}
		m := ServiceMatch{Protocol: proto}
		for _, pr := range hint.GetPorts() {
			end := uint16(pr.GetEnd())
			if end == 0 {
				end = uint16(pr.GetStart())
			}
			m.Ports = append(m.Ports, PortRange{Start: uint16(pr.GetStart()), End: end})
		}
		if len(m.Ports) > 0 {
			out = append(out, m)
		}
	}
	return out
}

func supportedAppIDSignals(signals []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, signal := range signals {
		normalized := strings.ToLower(strings.TrimSpace(signal))
		switch normalized {
		case "http", "tls", "dns", "ssh":
			if !seen[normalized] {
				seen[normalized] = true
				out = append(out, normalized)
			}
		}
	}
	return out
}

func compileRoute(sr *openngfwv1.StaticRoute) (RouteIR, error) {
	var out RouteIR
	pfx, err := netip.ParsePrefix(sr.GetDestination())
	if err != nil {
		return out, fmt.Errorf("static route %q: %w", sr.GetDestination(), err)
	}
	out.Destination = pfx
	if sr.GetVia() != "" {
		via, err := netip.ParseAddr(sr.GetVia())
		if err != nil {
			return out, fmt.Errorf("static route %q: %w", sr.GetDestination(), err)
		}
		out.Via = via
	}
	out.Interface = sr.GetInterface()
	out.Metric = sr.GetMetric()
	return out, nil
}

// rfc1918 is the default HOME_NET when policy doesn't specify one.
var rfc1918 = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

func compileIDs(p *openngfwv1.Policy, addrs map[string]netip.Prefix) (*IDsIR, error) {
	ids := p.GetIds()
	if !ids.GetEnabled() {
		return nil, nil
	}
	out := &IDsIR{
		Prevent:  ids.GetMode() == openngfwv1.IdsMode_IDS_MODE_PREVENT,
		QueueNum: uint16(ids.GetQueueNum()),
	}
	if out.Prevent {
		out.FailOpen = ids.GetFailureBehavior() == openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_OPEN
	}
	out.Interfaces = ids.GetMonitorInterfaces()
	if len(out.Interfaces) == 0 {
		for _, z := range p.GetZones() {
			out.Interfaces = append(out.Interfaces, z.GetInterfaces()...)
		}
	}
	if !out.Prevent && len(out.Interfaces) == 0 {
		return nil, fmt.Errorf("ids: detect mode needs zone interfaces or monitor_interfaces")
	}
	for _, hn := range ids.GetHomeNetworks() {
		pfx, err := netip.ParsePrefix(hn)
		if err != nil {
			return nil, fmt.Errorf("ids: invalid home network %q", hn)
		}
		out.HomeNets = append(out.HomeNets, pfx)
	}
	if len(out.HomeNets) == 0 {
		out.HomeNets = rfc1918
	}
	out.RuleFiles = ids.GetRuleFiles()
	if len(out.RuleFiles) == 0 {
		out.RuleFiles = []string{"local.rules"}
	}
	for _, ex := range ids.GetExceptions() {
		if ex.GetDisabled() {
			continue
		}
		ir := IDSExceptionIR{
			Name:        ex.GetName(),
			SignatureID: ex.GetSignatureId(),
			ThreatID:    ex.GetThreatId(),
			Description: ex.GetDescription(),
			Owner:       ex.GetOwner(),
			TicketID:    ex.GetTicketId(),
			ReviewDate:  ex.GetReviewDate(),
			ExpiresAt:   ex.GetExpiresAt(),
			PCAPSHA256:  ex.GetPcapSha256(),
			Regression:  ex.GetRegressionRef(),
		}
		switch {
		case ex.GetSourceAddress() != "":
			pfx, ok := addrs[ex.GetSourceAddress()]
			if !ok {
				return nil, fmt.Errorf("ids exception %q: unknown source address %q", ex.GetName(), ex.GetSourceAddress())
			}
			ir.Track, ir.Address = "by_src", pfx
		case ex.GetDestinationAddress() != "":
			pfx, ok := addrs[ex.GetDestinationAddress()]
			if !ok {
				return nil, fmt.Errorf("ids exception %q: unknown destination address %q", ex.GetName(), ex.GetDestinationAddress())
			}
			ir.Track, ir.Address = "by_dst", pfx
		}
		out.Exceptions = append(out.Exceptions, ir)
	}
	return out, nil
}

func compileTelemetry(p *openngfwv1.Policy) *TelemetryIR {
	tel := p.GetTelemetry()
	if !tel.GetEnabled() {
		return nil
	}
	out := &TelemetryIR{ClickHouseURL: tel.GetClickhouseUrl(), Database: tel.GetDatabase()}
	if out.ClickHouseURL == "" {
		out.ClickHouseURL = "http://127.0.0.1:8123"
	}
	if out.Database == "" {
		out.Database = "openngfw"
	}
	for _, export := range tel.GetExports() {
		if !export.GetEnabled() {
			continue
		}
		out.Exports = append(out.Exports, compilerTelemetryExport(export))
	}
	return out
}

func compilerTelemetryExport(export *openngfwv1.TelemetryExport) TelemetryExportIR {
	return TelemetryExportIR{
		Name:   export.GetName(),
		Type:   export.GetType().String(),
		Target: export.GetTarget(),
	}
}
