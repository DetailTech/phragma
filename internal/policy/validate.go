// Package policy validates the declarative model before compilation.
// Validation is exhaustive: it returns every problem found, not just the
// first, so a user can fix a candidate in one pass.
package policy

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

// ProxyTrafficPolicyFinding is a non-mutating review finding that relates
// planned Proxy/WAF listener and backend intent to the current L3/L4 policy.
// It is candidate-safe: findings are review context and do not launch proxy
// listeners, alter routes, or take custody of TLS material.
type ProxyTrafficPolicyFinding struct {
	Severity       string
	VirtualService string
	Route          string
	Dimension      string
	Message        string
}

// Any is the reserved wildcard reference usable wherever an object name is.
const Any = "any"

var (
	nameRE      = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]{0,62}[a-z0-9])?$`)
	appSignalRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
	tagRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,63}$`)
	contextRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:@/-]{0,127}$`)
	threatIDRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,127}$`)
	sha256RE    = regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)
	hostnameRE  = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
)

const maxRuleTags = 32
const maxRuleSecurityProfiles = 8
const maxQoSRateKbps = 100_000_000
const maxQoSBurstKBytes = 1_048_576
const maxZoneProtectionRatePPS = 10_000_000
const maxZoneProtectionConnections = 100_000_000
const maxRuleContextValues = 64
const maxWAFRequestBodyKB = 1024

// Validate checks p for structural and referential integrity. It returns
// a list of human-readable problems; an empty list means the policy is
// valid.
func Validate(p *openngfwv1.Policy) []string {
	if p == nil {
		return []string{"policy is empty"}
	}
	v := &validator{
		zones:            map[string]bool{},
		addresses:        map[string]*openngfwv1.Address{},
		services:         map[string]*openngfwv1.Service{},
		apps:             map[string]*openngfwv1.Application{},
		securityProfiles: map[string]*openngfwv1.SecurityProfile{},
		qosProfiles:      map[string]*openngfwv1.QosProfile{},
		zoneProtections:  map[string]*openngfwv1.ZoneProtectionProfile{},
	}
	v.collectZones(p.GetZones())
	v.collectAddresses(p.GetAddresses())
	v.collectServices(p.GetServices())
	v.collectApplications(p.GetApplications())
	v.collectSecurityProfiles(p.GetSecurityProfiles())
	v.collectQoSProfiles(p.GetQosProfiles())
	v.collectZoneProtectionProfiles(p.GetZoneProtectionProfiles())
	v.checkZoneProtectionRefs(p.GetZones())
	v.checkRules(p.GetRules(), p.GetIds())
	v.checkNat(p.GetNat())
	v.checkRoutes(p.GetStaticRoutes())
	v.checkIDs(p.GetIds())
	v.checkTelemetry(p.GetTelemetry())
	v.checkRouting(p.GetRouting())
	v.checkVPN(p.GetVpn())
	v.checkIntel(p.GetIntel())
	v.checkNetwork(p.GetNetwork(), p)
	v.checkHostInput(p.GetHostInput())
	v.checkProxy(p.GetProxy())
	return v.errs
}

// AnalyzeProxyTrafficPolicy returns bounded review findings that connect
// Proxy/WAF virtual service intent to security rules, App-ID port hints,
// inspection profile attachments, and static route context. The findings are
// intentionally non-blocking so operators can review planned L7 intent before
// active proxy rollout hardening exists.
func AnalyzeProxyTrafficPolicy(p *openngfwv1.Policy) []ProxyTrafficPolicyFinding {
	if p == nil || p.GetProxy() == nil {
		return nil
	}
	servicePorts := tcpServicePorts(p.GetServices())
	appPorts := tcpApplicationPorts(p.GetApplications())
	inspectionProfiles := inlineInspectionProfiles(p.GetSecurityProfiles())
	staticRoutes := parseStaticRoutePrefixes(p.GetStaticRoutes())
	var findings []ProxyTrafficPolicyFinding
	for _, vs := range p.GetProxy().GetVirtualServices() {
		if vs == nil || !vs.GetEnabled() {
			continue
		}
		listener := vs.GetListener()
		listenerPort := listener.GetPort()
		serviceMatches, appMatches, inspectionMatches := proxyListenerPolicyMatches(p.GetRules(), listenerPort, servicePorts, appPorts, inspectionProfiles)
		if len(serviceMatches) == 0 && len(appMatches) == 0 {
			findings = append(findings, ProxyTrafficPolicyFinding{
				Severity:       "warning",
				VirtualService: vs.GetName(),
				Dimension:      "security-rule",
				Message:        fmt.Sprintf("enabled virtual service listener TCP/%d has no enabled ACTION_ALLOW rule with a matching service or App-ID port hint; review firewall policy before traffic cutover", listenerPort),
			})
		} else {
			findings = append(findings, ProxyTrafficPolicyFinding{
				Severity:       "info",
				VirtualService: vs.GetName(),
				Dimension:      "security-rule",
				Message:        fmt.Sprintf("listener TCP/%d is reviewable against allow rule(s): %s", listenerPort, strings.Join(append(serviceMatches, appMatches...), ", ")),
			})
		}
		if len(appMatches) == 0 {
			findings = append(findings, ProxyTrafficPolicyFinding{
				Severity:       "info",
				VirtualService: vs.GetName(),
				Dimension:      "app-id",
				Message:        fmt.Sprintf("listener TCP/%d is not tied to an App-ID port hint; WAF intent remains proxy-plan context until App-ID classification evidence is reviewed", listenerPort),
			})
		}
		if len(inspectionMatches) == 0 {
			findings = append(findings, ProxyTrafficPolicyFinding{
				Severity:       "warning",
				VirtualService: vs.GetName(),
				Dimension:      "inspection",
				Message:        "no matching allow rule carries an inline inspection security profile; review IDS/inspection posture alongside WAF mode",
			})
		}
		for _, route := range vs.GetRoutes() {
			if route == nil {
				continue
			}
			if route.GetWafPolicy() == "" {
				findings = append(findings, ProxyTrafficPolicyFinding{
					Severity:       "warning",
					VirtualService: vs.GetName(),
					Route:          route.GetName(),
					Dimension:      "waf",
					Message:        "proxy route has no WAF policy attached; traffic-policy review will not show WAF enforcement intent for this path",
				})
			}
			for _, backend := range route.GetBackends() {
				host := backendURLHost(backend.GetUrl())
				if host == "" {
					continue
				}
				ip, err := netip.ParseAddr(host)
				if err != nil {
					findings = append(findings, ProxyTrafficPolicyFinding{
						Severity:       "info",
						VirtualService: vs.GetName(),
						Route:          route.GetName(),
						Dimension:      "route",
						Message:        fmt.Sprintf("backend %q uses DNS host %q; static-route proof needs resolver and runtime route evidence before cutover", backend.GetName(), host),
					})
					continue
				}
				if !addrCoveredByAnyPrefix(ip, staticRoutes) {
					findings = append(findings, ProxyTrafficPolicyFinding{
						Severity:       "warning",
						VirtualService: vs.GetName(),
						Route:          route.GetName(),
						Dimension:      "route",
						Message:        fmt.Sprintf("backend %q address %s is not covered by configured static routes; review connected/default route evidence before cutover", backend.GetName(), ip.String()),
					})
				}
			}
		}
	}
	return findings
}

type validator struct {
	errs             []string
	zones            map[string]bool
	addresses        map[string]*openngfwv1.Address
	services         map[string]*openngfwv1.Service
	apps             map[string]*openngfwv1.Application
	securityProfiles map[string]*openngfwv1.SecurityProfile
	qosProfiles      map[string]*openngfwv1.QosProfile
	zoneProtections  map[string]*openngfwv1.ZoneProtectionProfile
}

func (v *validator) errf(format string, args ...any) {
	v.errs = append(v.errs, fmt.Sprintf(format, args...))
}

func (v *validator) checkName(kind, name string) bool {
	if name == "" {
		v.errf("%s with empty name", kind)
		return false
	}
	if name == Any {
		v.errf("%s name %q is reserved", kind, Any)
		return false
	}
	if !nameRE.MatchString(name) {
		v.errf("%s name %q is invalid (lowercase alphanumeric, '-', '_', max 64 chars)", kind, name)
		return false
	}
	return true
}

func (v *validator) collectZones(zones []*openngfwv1.Zone) {
	ifaceOwner := map[string]string{}
	for _, z := range zones {
		if !v.checkName("zone", z.GetName()) {
			continue
		}
		if v.zones[z.GetName()] {
			v.errf("duplicate zone %q", z.GetName())
			continue
		}
		v.zones[z.GetName()] = true
		for _, ifc := range z.GetInterfaces() {
			if ifc == "" {
				v.errf("zone %q has an empty interface name", z.GetName())
				continue
			}
			if owner, dup := ifaceOwner[ifc]; dup {
				v.errf("interface %q is in both zone %q and zone %q", ifc, owner, z.GetName())
				continue
			}
			ifaceOwner[ifc] = z.GetName()
		}
	}
}

func (v *validator) collectAddresses(addrs []*openngfwv1.Address) {
	for _, a := range addrs {
		if !v.checkName("address", a.GetName()) {
			continue
		}
		if _, dup := v.addresses[a.GetName()]; dup {
			v.errf("duplicate address %q", a.GetName())
			continue
		}
		if _, err := netip.ParsePrefix(a.GetCidr()); err != nil {
			v.errf("address %q: invalid CIDR %q (host addresses need /32 or /128)", a.GetName(), a.GetCidr())
			continue
		}
		v.addresses[a.GetName()] = a
	}
}

func (v *validator) collectServices(svcs []*openngfwv1.Service) {
	for _, s := range svcs {
		if !v.checkName("service", s.GetName()) {
			continue
		}
		if _, dup := v.services[s.GetName()]; dup {
			v.errf("duplicate service %q", s.GetName())
			continue
		}
		switch s.GetProtocol() {
		case openngfwv1.Protocol_PROTOCOL_TCP, openngfwv1.Protocol_PROTOCOL_UDP:
			for _, pr := range s.GetPorts() {
				start, end := pr.GetStart(), pr.GetEnd()
				if start == 0 || start > 65535 {
					v.errf("service %q: port %d out of range 1-65535", s.GetName(), start)
				}
				if end != 0 && (end > 65535 || end < start) {
					v.errf("service %q: invalid port range %d-%d", s.GetName(), start, end)
				}
			}
		case openngfwv1.Protocol_PROTOCOL_ICMP, openngfwv1.Protocol_PROTOCOL_ANY:
			if len(s.GetPorts()) > 0 {
				v.errf("service %q: protocol %s cannot have ports", s.GetName(), s.GetProtocol())
			}
		default:
			v.errf("service %q: protocol must be set", s.GetName())
		}
		v.services[s.GetName()] = s
	}
}

func (v *validator) collectApplications(apps []*openngfwv1.Application) {
	for _, app := range apps {
		if !v.checkName("application", app.GetName()) {
			continue
		}
		if _, dup := v.apps[app.GetName()]; dup {
			v.errf("duplicate application %q", app.GetName())
			continue
		}
		ctx := fmt.Sprintf("application %q", app.GetName())
		if app.GetCategory() == "" {
			v.errf("%s: category must be set", ctx)
		} else if !nameRE.MatchString(app.GetCategory()) {
			v.errf("%s: category %q is invalid (lowercase alphanumeric, '-', '_', max 64 chars)", ctx, app.GetCategory())
		}
		if len(app.GetEngineSignals()) == 0 && len(app.GetPorts()) == 0 {
			v.errf("%s: at least one engine_signal or port hint is required", ctx)
		}
		seenSignals := map[string]bool{}
		for _, signal := range app.GetEngineSignals() {
			normalized := strings.ToLower(strings.TrimSpace(signal))
			switch {
			case normalized == "":
				v.errf("%s: engine_signals cannot contain an empty value", ctx)
			case !appSignalRE.MatchString(normalized):
				v.errf("%s: engine_signal %q is invalid (lowercase app label characters: letters, digits, '_', '.', '-')", ctx, signal)
			case seenSignals[normalized]:
				v.errf("%s: duplicate engine_signal %q", ctx, normalized)
			default:
				seenSignals[normalized] = true
			}
		}
		for i, port := range app.GetPorts() {
			v.checkApplicationPort(ctx, i, port)
		}
		v.apps[app.GetName()] = app
	}
}

func (v *validator) collectSecurityProfiles(profiles []*openngfwv1.SecurityProfile) {
	for _, profile := range profiles {
		if !v.checkName("security profile", profile.GetName()) {
			continue
		}
		if _, dup := v.securityProfiles[profile.GetName()]; dup {
			v.errf("duplicate security profile %q", profile.GetName())
			continue
		}
		ctx := fmt.Sprintf("security profile %q", profile.GetName())
		if profile.GetTlsInspection() == openngfwv1.TlsInspectionMode_TLS_INSPECTION_MODE_DECRYPTION_REQUIRED &&
			strings.TrimSpace(profile.GetDescription()) == "" {
			v.errf("%s: decryption-required profiles need a description documenting operator intent and external certificate/broker prerequisites", ctx)
		}
		seenCategories := map[string]bool{}
		for _, category := range profile.GetUrlCategories() {
			normalized := strings.TrimSpace(category)
			switch {
			case normalized == "":
				v.errf("%s: url_categories cannot contain an empty value", ctx)
			case normalized != category:
				v.errf("%s: url category %q must not contain leading or trailing whitespace", ctx, category)
			case !tagRE.MatchString(normalized):
				v.errf("%s: url category %q is invalid (lowercase alphanumeric plus '-', '_', '.', ':', max 64 chars)", ctx, category)
			case seenCategories[normalized]:
				v.errf("%s: duplicate url category %q", ctx, normalized)
			default:
				seenCategories[normalized] = true
			}
		}
		v.securityProfiles[profile.GetName()] = profile
	}
}

func (v *validator) collectQoSProfiles(profiles []*openngfwv1.QosProfile) {
	for _, profile := range profiles {
		if !v.checkName("QoS profile", profile.GetName()) {
			continue
		}
		if _, dup := v.qosProfiles[profile.GetName()]; dup {
			v.errf("duplicate QoS profile %q", profile.GetName())
			continue
		}
		ctx := fmt.Sprintf("QoS profile %q", profile.GetName())
		maxRate := profile.GetMaxBandwidthKbps()
		guaranteed := profile.GetGuaranteedBandwidthKbps()
		if maxRate == 0 && guaranteed == 0 && profile.GetDscpMark() == 0 {
			v.errf("%s: at least one of max_bandwidth_kbps, guaranteed_bandwidth_kbps, or dscp_mark must be set", ctx)
		}
		if maxRate > maxQoSRateKbps {
			v.errf("%s: max_bandwidth_kbps %d exceeds supported bound %d", ctx, maxRate, maxQoSRateKbps)
		}
		if guaranteed > maxQoSRateKbps {
			v.errf("%s: guaranteed_bandwidth_kbps %d exceeds supported bound %d", ctx, guaranteed, maxQoSRateKbps)
		}
		if maxRate > 0 && guaranteed > maxRate {
			v.errf("%s: guaranteed_bandwidth_kbps cannot exceed max_bandwidth_kbps", ctx)
		}
		switch profile.GetPriority() {
		case openngfwv1.QosPriority_QOS_PRIORITY_UNSPECIFIED,
			openngfwv1.QosPriority_QOS_PRIORITY_LOW,
			openngfwv1.QosPriority_QOS_PRIORITY_MEDIUM,
			openngfwv1.QosPriority_QOS_PRIORITY_HIGH,
			openngfwv1.QosPriority_QOS_PRIORITY_CRITICAL:
		default:
			v.errf("%s: priority is invalid", ctx)
		}
		if profile.GetDscpMark() > 63 {
			v.errf("%s: dscp_mark %d out of range 0-63", ctx, profile.GetDscpMark())
		}
		if profile.GetBurstKbytes() > maxQoSBurstKBytes {
			v.errf("%s: burst_kbytes %d exceeds supported bound %d", ctx, profile.GetBurstKbytes(), maxQoSBurstKBytes)
		}
		v.qosProfiles[profile.GetName()] = profile
	}
}

func (v *validator) collectZoneProtectionProfiles(profiles []*openngfwv1.ZoneProtectionProfile) {
	for _, profile := range profiles {
		if !v.checkName("zone protection profile", profile.GetName()) {
			continue
		}
		if _, dup := v.zoneProtections[profile.GetName()]; dup {
			v.errf("duplicate zone protection profile %q", profile.GetName())
			continue
		}
		ctx := fmt.Sprintf("zone protection profile %q", profile.GetName())
		if profile.GetEnabled() {
			switch profile.GetAction() {
			case openngfwv1.ZoneProtectionAction_ZONE_PROTECTION_ACTION_ALERT,
				openngfwv1.ZoneProtectionAction_ZONE_PROTECTION_ACTION_DROP:
			default:
				v.errf("%s: enabled profile requires action ALERT or DROP", ctx)
			}
			if profile.GetSynFloodPps() == 0 && profile.GetUdpFloodPps() == 0 &&
				profile.GetIcmpFloodPps() == 0 && profile.GetMaxConcurrentConnections() == 0 {
				v.errf("%s: enabled profile requires at least one flood or connection threshold", ctx)
			}
		}
		v.checkZoneProtectionRate(ctx, "syn_flood_pps", profile.GetSynFloodPps())
		v.checkZoneProtectionRate(ctx, "udp_flood_pps", profile.GetUdpFloodPps())
		v.checkZoneProtectionRate(ctx, "icmp_flood_pps", profile.GetIcmpFloodPps())
		if profile.GetMaxConcurrentConnections() > maxZoneProtectionConnections {
			v.errf("%s: max_concurrent_connections %d exceeds supported bound %d", ctx, profile.GetMaxConcurrentConnections(), maxZoneProtectionConnections)
		}
		v.zoneProtections[profile.GetName()] = profile
	}
}

func (v *validator) checkZoneProtectionRate(ctx, field string, value uint64) {
	if value > maxZoneProtectionRatePPS {
		v.errf("%s: %s %d exceeds supported bound %d", ctx, field, value, maxZoneProtectionRatePPS)
	}
}

func (v *validator) checkZoneProtectionRefs(zones []*openngfwv1.Zone) {
	for _, zone := range zones {
		ref := strings.TrimSpace(zone.GetZoneProtectionProfile())
		if ref == "" {
			continue
		}
		if ref != zone.GetZoneProtectionProfile() {
			v.errf("zone %q: zone_protection_profile %q must not contain leading or trailing whitespace", zone.GetName(), zone.GetZoneProtectionProfile())
			continue
		}
		if _, ok := v.zoneProtections[ref]; !ok {
			v.errf("zone %q references unknown zone protection profile %q", zone.GetName(), ref)
		}
	}
}

func (v *validator) checkApplicationPort(ctx string, index int, port *openngfwv1.ApplicationPort) {
	portCtx := fmt.Sprintf("%s port[%d]", ctx, index)
	switch port.GetProtocol() {
	case openngfwv1.Protocol_PROTOCOL_TCP, openngfwv1.Protocol_PROTOCOL_UDP:
	default:
		v.errf("%s: protocol must be TCP or UDP", portCtx)
		return
	}
	if len(port.GetPorts()) == 0 {
		v.errf("%s: at least one port range is required", portCtx)
		return
	}
	for _, pr := range port.GetPorts() {
		start, end := pr.GetStart(), pr.GetEnd()
		if start == 0 || start > 65535 {
			v.errf("%s: port %d out of range 1-65535", portCtx, start)
		}
		if end != 0 && (end > 65535 || end < start) {
			v.errf("%s: invalid port range %d-%d", portCtx, start, end)
		}
	}
}

func (v *validator) checkProxy(proxy *openngfwv1.Proxy) {
	if proxy == nil {
		return
	}
	wafPolicies := map[string]*openngfwv1.WafPolicy{}
	for _, waf := range proxy.GetWafPolicies() {
		if !v.checkName("WAF policy", waf.GetName()) {
			continue
		}
		if _, dup := wafPolicies[waf.GetName()]; dup {
			v.errf("duplicate WAF policy %q", waf.GetName())
			continue
		}
		v.checkWAFPolicy(waf)
		wafPolicies[waf.GetName()] = waf
	}
	for _, vs := range proxy.GetVirtualServices() {
		v.checkVirtualService(vs, wafPolicies)
	}
}

func (v *validator) checkWAFPolicy(waf *openngfwv1.WafPolicy) {
	ctx := fmt.Sprintf("WAF policy %q", waf.GetName())
	switch waf.GetMode() {
	case openngfwv1.WafMode_WAF_MODE_DETECT, openngfwv1.WafMode_WAF_MODE_BLOCK:
	default:
		v.errf("%s: mode must be detect or block", ctx)
	}
	if len(waf.GetRuleSets()) == 0 {
		v.errf("%s: at least one rule_set is required", ctx)
	}
	for i, ruleSet := range waf.GetRuleSets() {
		rsCtx := fmt.Sprintf("%s rule_set[%d]", ctx, i)
		if !v.checkName(rsCtx, ruleSet.GetName()) {
			continue
		}
		if strings.TrimSpace(ruleSet.GetVersion()) == "" {
			v.errf("%s: version is required for provenance", rsCtx)
		}
		if strings.TrimSpace(ruleSet.GetSource()) == "" {
			v.errf("%s: source is required for provenance", rsCtx)
		}
		if !sha256RE.MatchString(strings.TrimSpace(ruleSet.GetSha256())) {
			v.errf("%s: sha256 must be a 64-character hex digest", rsCtx)
		}
	}
	limit := waf.GetRequestBodyLimitKb()
	if limit == 0 || limit > maxWAFRequestBodyKB {
		v.errf("%s: request_body_limit_kb must be between 1 and %d", ctx, maxWAFRequestBodyKB)
	}
	if !waf.GetRedactRequestBody() {
		v.errf("%s: redact_request_body must be true until request-body privacy custody is configured", ctx)
	}
}

func (v *validator) checkVirtualService(vs *openngfwv1.VirtualService, wafPolicies map[string]*openngfwv1.WafPolicy) {
	if !v.checkName("virtual service", vs.GetName()) {
		return
	}
	ctx := fmt.Sprintf("virtual service %q", vs.GetName())
	if len(vs.GetHostnames()) == 0 {
		v.errf("%s: at least one hostname is required", ctx)
	}
	seenHosts := map[string]bool{}
	for _, hostname := range vs.GetHostnames() {
		normalized := strings.ToLower(strings.TrimSpace(hostname))
		switch {
		case normalized == "":
			v.errf("%s: hostnames cannot contain an empty value", ctx)
		case normalized != hostname:
			v.errf("%s: hostname %q must be lowercase without surrounding whitespace", ctx, hostname)
		case !hostnameRE.MatchString(normalized):
			v.errf("%s: hostname %q is invalid", ctx, hostname)
		case seenHosts[normalized]:
			v.errf("%s: duplicate hostname %q", ctx, normalized)
		default:
			seenHosts[normalized] = true
		}
	}
	v.checkProxyListener(ctx, vs.GetListener())
	if len(vs.GetRoutes()) == 0 {
		v.errf("%s: at least one route is required", ctx)
	}
	seenRoutes := map[string]bool{}
	for _, route := range vs.GetRoutes() {
		v.checkProxyRoute(ctx, route, wafPolicies, seenRoutes)
	}
}

func (v *validator) checkProxyListener(ctx string, listener *openngfwv1.ProxyListener) {
	if listener == nil {
		v.errf("%s: listener is required", ctx)
		return
	}
	if net.ParseIP(strings.TrimSpace(listener.GetBindAddress())) == nil {
		v.errf("%s: listener bind_address %q is not a valid IP address", ctx, listener.GetBindAddress())
	}
	port := listener.GetPort()
	if port == 0 || port > 65535 {
		v.errf("%s: listener port %d out of range 1-65535", ctx, port)
	}
	if listener.GetTls() && strings.TrimSpace(listener.GetTlsSecretRef()) == "" {
		v.errf("%s: listener tls_secret_ref is required when tls is enabled", ctx)
	}
}

func (v *validator) checkProxyRoute(vsCtx string, route *openngfwv1.ProxyRoute, wafPolicies map[string]*openngfwv1.WafPolicy, seenRoutes map[string]bool) {
	if route == nil {
		v.errf("%s: route is empty", vsCtx)
		return
	}
	if !v.checkName(vsCtx+" route", route.GetName()) {
		return
	}
	ctx := fmt.Sprintf("%s route %q", vsCtx, route.GetName())
	if seenRoutes[route.GetName()] {
		v.errf("%s: duplicate route name %q", vsCtx, route.GetName())
	} else {
		seenRoutes[route.GetName()] = true
	}
	prefix := strings.TrimSpace(route.GetPathPrefix())
	if prefix == "" || !strings.HasPrefix(prefix, "/") || strings.Contains(prefix, " ") || path.Clean(prefix) != prefix {
		v.errf("%s: path_prefix %q must be an absolute clean path", ctx, route.GetPathPrefix())
	}
	if route.GetWafPolicy() != "" {
		if _, ok := wafPolicies[route.GetWafPolicy()]; !ok {
			v.errf("%s references unknown WAF policy %q", ctx, route.GetWafPolicy())
		}
	}
	if len(route.GetBackends()) == 0 {
		v.errf("%s: at least one backend is required", ctx)
	}
	var totalWeight uint32
	seenBackends := map[string]bool{}
	for _, backend := range route.GetBackends() {
		if backend == nil {
			v.errf("%s: backend is empty", ctx)
			continue
		}
		if !v.checkName(ctx+" backend", backend.GetName()) {
			continue
		}
		if seenBackends[backend.GetName()] {
			v.errf("%s: duplicate backend name %q", ctx, backend.GetName())
		}
		seenBackends[backend.GetName()] = true
		u, err := url.Parse(strings.TrimSpace(backend.GetUrl()))
		if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			v.errf("%s backend %q: url must be http(s) with host only, no credentials, query, or fragment", ctx, backend.GetName())
		}
		weight := backend.GetWeight()
		if weight == 0 {
			v.errf("%s backend %q: weight must be greater than 0", ctx, backend.GetName())
		}
		totalWeight += weight
	}
	if totalWeight == 0 && len(route.GetBackends()) > 0 {
		v.errf("%s: backend weights must sum to greater than 0", ctx)
	}
	if !route.GetRequireMtlsToBackend() {
		v.errf("%s: require_mtls_to_backend must be true until backend transport hardening is configured", ctx)
	}
}

func (v *validator) checkZoneRefs(ctx string, refs []string) {
	for _, r := range refs {
		if r != Any && !v.zones[r] {
			v.errf("%s references unknown zone %q", ctx, r)
		}
	}
}

func (v *validator) checkAddressRefs(ctx string, refs []string) {
	for _, r := range refs {
		if _, ok := v.addresses[r]; r != Any && !ok {
			v.errf("%s references unknown address %q", ctx, r)
		}
	}
}

func (v *validator) checkApplicationRefs(ctx string, refs []string) []*openngfwv1.Application {
	var out []*openngfwv1.Application
	for _, r := range refs {
		if r == Any {
			continue
		}
		app, ok := v.apps[r]
		if !ok {
			v.errf("%s references unknown application %q", ctx, r)
			continue
		}
		out = append(out, app)
	}
	return out
}

func (v *validator) checkSecurityProfileRefs(ctx string, refs []string) []*openngfwv1.SecurityProfile {
	var out []*openngfwv1.SecurityProfile
	if len(refs) > maxRuleSecurityProfiles {
		v.errf("%s: too many security profiles (%d > %d)", ctx, len(refs), maxRuleSecurityProfiles)
	}
	seen := map[string]bool{}
	for _, r := range refs {
		switch {
		case r == "":
			v.errf("%s: security profiles cannot contain an empty value", ctx)
		case r == Any:
			v.errf("%s: security profiles must name explicit profile objects, not %q", ctx, Any)
		case seen[r]:
			v.errf("%s: duplicate security profile %q", ctx, r)
		case v.securityProfiles[r] == nil:
			v.errf("%s references unknown security profile %q", ctx, r)
		default:
			seen[r] = true
			out = append(out, v.securityProfiles[r])
		}
	}
	return out
}

func (v *validator) checkRules(rules []*openngfwv1.Rule, ids *openngfwv1.Ids) {
	seen := map[string]bool{}
	seenIDs := map[string]string{}
	for _, r := range rules {
		if !v.checkName("rule", r.GetName()) {
			continue
		}
		if seen[r.GetName()] {
			v.errf("duplicate rule %q", r.GetName())
			continue
		}
		seen[r.GetName()] = true
		ctx := fmt.Sprintf("rule %q", r.GetName())
		if id := r.GetId(); id == "" {
			v.errf("%s: id is required; server-side rule identity normalization must run before validation", ctx)
		} else {
			switch {
			case strings.TrimSpace(id) != id:
				v.errf("%s: id %q must not contain leading or trailing whitespace", ctx, id)
			case !ValidRuleID(id):
				v.errf("%s: id %q is invalid (lowercase alphanumeric plus '-', '_', '.', ':', max 128 chars)", ctx, id)
			case seenIDs[id] != "":
				v.errf("%s: duplicate rule id %q also used by rule %q", ctx, id, seenIDs[id])
			default:
				seenIDs[id] = r.GetName()
			}
		}
		if r.GetAction() == openngfwv1.Action_ACTION_UNSPECIFIED {
			v.errf("%s: action must be set", ctx)
		}
		v.checkZoneRefs(ctx, r.GetFromZones())
		v.checkZoneRefs(ctx, r.GetToZones())
		v.checkAddressRefs(ctx, r.GetSourceAddresses())
		v.checkAddressRefs(ctx, r.GetDestinationAddresses())
		for _, s := range r.GetServices() {
			if _, ok := v.services[s]; s != Any && !ok {
				v.errf("%s references unknown service %q", ctx, s)
			}
		}
		apps := v.checkApplicationRefs(ctx, r.GetApplications())
		profiles := v.checkSecurityProfileRefs(ctx, r.GetSecurityProfiles())
		if ref := strings.TrimSpace(r.GetQosProfile()); ref != "" {
			switch {
			case ref != r.GetQosProfile():
				v.errf("%s: qos_profile %q must not contain leading or trailing whitespace", ctx, r.GetQosProfile())
			case ref == Any:
				v.errf("%s: qos_profile must name an explicit QoS profile, not %q", ctx, Any)
			case v.qosProfiles[ref] == nil:
				v.errf("%s references unknown QoS profile %q", ctx, ref)
			}
		}
		if r.GetAction() == openngfwv1.Action_ACTION_ALLOW && profilesRequireFailClosedInspection(profiles) && !idsPreventFailClosed(ids) {
			v.errf("%s: blocking security profiles on ACTION_ALLOW rules require ids enabled with mode IDS_MODE_PREVENT and failure_behavior IDS_FAILURE_BEHAVIOR_FAIL_CLOSED", ctx)
		}
		if hasSpecificRefs(r.GetApplications()) {
			if hasSpecificRefs(r.GetServices()) {
				v.errf("%s: services and applications cannot be combined in the current v1 renderer; application objects supply the enforced TCP/UDP port hints", ctx)
			}
			for _, app := range apps {
				if len(app.GetPorts()) == 0 {
					if r.GetAction() == openngfwv1.Action_ACTION_ALLOW {
						v.errf("%s: signal-only App-ID allow requires TCP/UDP port hints so nftables can preserve a bounded forwarding path", ctx)
					}
					if !idsPreventFailClosed(ids) {
						v.errf("%s: application %q has no TCP/UDP port hints; engine-signal-only App-ID enforcement requires ids enabled with mode IDS_MODE_PREVENT and failure_behavior IDS_FAILURE_BEHAVIOR_FAIL_CLOSED", ctx, app.GetName())
					}
					if !hasSupportedAppIDSignal(app.GetEngineSignals()) {
						v.errf("%s: application %q has no supported Suricata App-ID engine_signal (supported: dns, http, ssh, tls)", ctx, app.GetName())
					}
					if hasSpecificRefs(r.GetFromZones()) || hasSpecificRefs(r.GetToZones()) {
						v.errf("%s: signal-only App-ID rules cannot be scoped only by From/To zones because the current Suricata control path cannot enforce interface zones; add TCP/UDP port hints or use Source/Destination address scope", ctx)
					}
				}
			}
		}
		v.checkRuleMatchContext(ctx, r.GetMatchContext())
		v.checkRuleTags(ctx, r.GetTags())
	}
}

func (v *validator) checkRuleMatchContext(ctx string, match *openngfwv1.RuleMatchContext) {
	if match == nil {
		return
	}
	total := len(match.GetUsers()) + len(match.GetGroups()) + len(match.GetDevices()) + len(match.GetPostureLabels())
	if total == 0 {
		v.errf("%s: match_context must contain at least one user, group, device, or posture label", ctx)
		return
	}
	v.checkRuleContextList(ctx, "users", match.GetUsers())
	v.checkRuleContextList(ctx, "groups", match.GetGroups())
	v.checkRuleContextList(ctx, "devices", match.GetDevices())
	v.checkRuleContextList(ctx, "posture_labels", match.GetPostureLabels())
}

func (v *validator) checkRuleContextList(ctx, field string, values []string) {
	if len(values) > maxRuleContextValues {
		v.errf("%s: match_context.%s has too many values (%d > %d)", ctx, field, len(values), maxRuleContextValues)
	}
	seen := map[string]bool{}
	for _, value := range values {
		switch {
		case value == "":
			v.errf("%s: match_context.%s cannot contain an empty value", ctx, field)
		case value == Any:
			v.errf("%s: match_context.%s must use explicit labels, not %q", ctx, field, Any)
		case strings.TrimSpace(value) != value:
			v.errf("%s: match_context.%s value %q must not contain leading or trailing whitespace", ctx, field, value)
		case !contextRE.MatchString(value):
			v.errf("%s: match_context.%s value %q is invalid (lowercase label, email, or provider-scoped id, max 128 chars)", ctx, field, value)
		case seen[value]:
			v.errf("%s: duplicate match_context.%s value %q", ctx, field, value)
		default:
			seen[value] = true
		}
	}
}

func (v *validator) checkRuleTags(ctx string, tags []string) {
	if len(tags) > maxRuleTags {
		v.errf("%s: too many tags (%d > %d)", ctx, len(tags), maxRuleTags)
	}
	seen := map[string]bool{}
	for _, tag := range tags {
		switch {
		case tag == "":
			v.errf("%s: tags cannot contain an empty value", ctx)
		case strings.TrimSpace(tag) != tag:
			v.errf("%s: tag %q must not contain leading or trailing whitespace", ctx, tag)
		case !tagRE.MatchString(tag):
			v.errf("%s: tag %q is invalid (lowercase alphanumeric plus '-', '_', '.', ':', max 64 chars)", ctx, tag)
		case seen[tag]:
			v.errf("%s: duplicate tag %q", ctx, tag)
		default:
			seen[tag] = true
		}
	}
}

func hasSpecificRefs(refs []string) bool {
	for _, r := range refs {
		if r != "" && r != Any {
			return true
		}
	}
	return false
}

func hasSupportedAppIDSignal(signals []string) bool {
	for _, signal := range signals {
		switch strings.ToLower(strings.TrimSpace(signal)) {
		case "dns", "http", "ssh", "tls":
			return true
		}
	}
	return false
}

func profilesRequireFailClosedInspection(profiles []*openngfwv1.SecurityProfile) bool {
	for _, profile := range profiles {
		if securityProfileRequiresInlineInspection(profile) {
			return true
		}
	}
	return false
}

func securityProfileRequiresInlineInspection(profile *openngfwv1.SecurityProfile) bool {
	if profile == nil {
		return false
	}
	if profile.GetTlsInspection() == openngfwv1.TlsInspectionMode_TLS_INSPECTION_MODE_DECRYPTION_REQUIRED {
		return true
	}
	if len(profile.GetUrlCategories()) > 0 {
		return true
	}
	if profile.GetDnsSecurity() == openngfwv1.DnsSecurityMode_DNS_SECURITY_MODE_BLOCK_MALICIOUS {
		return true
	}
	switch profile.GetFileSecurity() {
	case openngfwv1.FileSecurityMode_FILE_SECURITY_MODE_BLOCK_EXECUTABLES,
		openngfwv1.FileSecurityMode_FILE_SECURITY_MODE_BLOCK_HIGH_RISK:
		return true
	}
	return false
}

func idsPreventFailClosed(ids *openngfwv1.Ids) bool {
	return ids.GetEnabled() &&
		ids.GetMode() == openngfwv1.IdsMode_IDS_MODE_PREVENT &&
		ids.GetFailureBehavior() == openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED
}

func tcpServicePorts(services []*openngfwv1.Service) map[string]map[uint32]bool {
	out := map[string]map[uint32]bool{}
	for _, service := range services {
		if service.GetProtocol() != openngfwv1.Protocol_PROTOCOL_TCP {
			continue
		}
		ports := map[uint32]bool{}
		for _, pr := range service.GetPorts() {
			start, end := pr.GetStart(), pr.GetEnd()
			if end == 0 {
				end = start
			}
			for port := start; port > 0 && port <= end && port <= 65535; port++ {
				ports[port] = true
				if port == end {
					break
				}
			}
		}
		if len(ports) > 0 {
			out[service.GetName()] = ports
		}
	}
	return out
}

func tcpApplicationPorts(apps []*openngfwv1.Application) map[string]map[uint32]bool {
	out := map[string]map[uint32]bool{}
	for _, app := range apps {
		ports := map[uint32]bool{}
		for _, appPort := range app.GetPorts() {
			if appPort.GetProtocol() != openngfwv1.Protocol_PROTOCOL_TCP {
				continue
			}
			for _, pr := range appPort.GetPorts() {
				start, end := pr.GetStart(), pr.GetEnd()
				if end == 0 {
					end = start
				}
				for port := start; port > 0 && port <= end && port <= 65535; port++ {
					ports[port] = true
					if port == end {
						break
					}
				}
			}
		}
		if len(ports) > 0 {
			out[app.GetName()] = ports
		}
	}
	return out
}

func inlineInspectionProfiles(profiles []*openngfwv1.SecurityProfile) map[string]bool {
	out := map[string]bool{}
	for _, profile := range profiles {
		if securityProfileRequiresInlineInspection(profile) {
			out[profile.GetName()] = true
		}
	}
	return out
}

func proxyListenerPolicyMatches(rules []*openngfwv1.Rule, listenerPort uint32, servicePorts, appPorts map[string]map[uint32]bool, inspectionProfiles map[string]bool) ([]string, []string, []string) {
	var serviceMatches []string
	var appMatches []string
	var inspectionMatches []string
	for _, rule := range rules {
		if rule.GetDisabled() || rule.GetAction() != openngfwv1.Action_ACTION_ALLOW {
			continue
		}
		ruleMatched := false
		for _, service := range rule.GetServices() {
			if service == Any || servicePorts[service][listenerPort] {
				serviceMatches = append(serviceMatches, rule.GetName())
				ruleMatched = true
				break
			}
		}
		for _, app := range rule.GetApplications() {
			if app == Any || appPorts[app][listenerPort] {
				appMatches = append(appMatches, rule.GetName())
				ruleMatched = true
				break
			}
		}
		if !ruleMatched {
			continue
		}
		for _, profile := range rule.GetSecurityProfiles() {
			if inspectionProfiles[profile] {
				inspectionMatches = append(inspectionMatches, rule.GetName())
				break
			}
		}
	}
	return uniqueStrings(serviceMatches), uniqueStrings(appMatches), uniqueStrings(inspectionMatches)
}

func parseStaticRoutePrefixes(routes []*openngfwv1.StaticRoute) []netip.Prefix {
	var out []netip.Prefix
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(route.GetDestination())
		if err == nil {
			out = append(out, prefix)
		}
	}
	return out
}

func backendURLHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil {
		return ""
	}
	host := u.Hostname()
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	return host
}

func addrCoveredByAnyPrefix(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func uniqueStrings(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func (v *validator) checkHostInput(hostInput *openngfwv1.HostInput) {
	if hostInput == nil {
		return
	}
	switch hostInput.GetDefaultAction() {
	case openngfwv1.Action_ACTION_UNSPECIFIED, openngfwv1.Action_ACTION_ALLOW, openngfwv1.Action_ACTION_DENY:
	default:
		v.errf("host_input: default_action must be ACTION_ALLOW or ACTION_DENY")
	}
	if hostInput.GetDefaultAction() == openngfwv1.Action_ACTION_DENY && !hasActiveHostInputAllow(hostInput.GetRules()) {
		v.errf("host_input: default_action ACTION_DENY requires at least one enabled ACTION_ALLOW host-input rule to prevent management lockout")
	}
	seen := map[string]bool{}
	for _, r := range hostInput.GetRules() {
		if !v.checkName("host-input rule", r.GetName()) {
			continue
		}
		if seen[r.GetName()] {
			v.errf("duplicate host-input rule %q", r.GetName())
			continue
		}
		seen[r.GetName()] = true
		ctx := fmt.Sprintf("host-input rule %q", r.GetName())
		if r.GetAction() == openngfwv1.Action_ACTION_UNSPECIFIED {
			v.errf("%s: action must be set", ctx)
		}
		v.checkZoneRefs(ctx, r.GetFromZones())
		v.checkAddressRefs(ctx, r.GetSourceAddresses())
		for _, s := range r.GetServices() {
			if _, ok := v.services[s]; s != Any && !ok {
				v.errf("%s references unknown service %q", ctx, s)
			}
		}
	}
}

func hasActiveHostInputAllow(rules []*openngfwv1.HostInputRule) bool {
	for _, r := range rules {
		if r.GetDisabled() {
			continue
		}
		if r.GetAction() == openngfwv1.Action_ACTION_ALLOW {
			return true
		}
	}
	return false
}

// hostAddress reports whether ref names a single-host address object.
func (v *validator) hostAddress(ref string) bool {
	a, ok := v.addresses[ref]
	if !ok {
		return false
	}
	p, err := netip.ParsePrefix(a.GetCidr())
	return err == nil && p.IsSingleIP()
}

func (v *validator) checkNat(nat *openngfwv1.Nat) {
	seen := map[string]bool{}
	for _, sn := range nat.GetSource() {
		if !v.checkName("source-nat", sn.GetName()) {
			continue
		}
		if seen[sn.GetName()] {
			v.errf("duplicate source-nat %q", sn.GetName())
			continue
		}
		seen[sn.GetName()] = true
		ctx := fmt.Sprintf("source-nat %q", sn.GetName())
		if sn.GetToZone() == "" || (sn.GetToZone() != Any && !v.zones[sn.GetToZone()]) {
			v.errf("%s: to_zone %q is not a known zone", ctx, sn.GetToZone())
		}
		if sn.GetSourceAddress() != "" {
			v.checkAddressRefs(ctx, []string{sn.GetSourceAddress()})
		}
		switch {
		case sn.GetMasquerade() && sn.GetTranslatedAddress() != "":
			v.errf("%s: masquerade and translated_address are mutually exclusive", ctx)
		case !sn.GetMasquerade() && sn.GetTranslatedAddress() == "":
			v.errf("%s: one of masquerade or translated_address is required", ctx)
		case sn.GetTranslatedAddress() != "" && !v.hostAddress(sn.GetTranslatedAddress()):
			v.errf("%s: translated_address %q must be a /32 or /128 address object", ctx, sn.GetTranslatedAddress())
		}
	}
	seen = map[string]bool{}
	for _, dn := range nat.GetDestination() {
		if !v.checkName("destination-nat", dn.GetName()) {
			continue
		}
		if seen[dn.GetName()] {
			v.errf("duplicate destination-nat %q", dn.GetName())
			continue
		}
		seen[dn.GetName()] = true
		ctx := fmt.Sprintf("destination-nat %q", dn.GetName())
		if dn.GetFromZone() == "" || (dn.GetFromZone() != Any && !v.zones[dn.GetFromZone()]) {
			v.errf("%s: from_zone %q is not a known zone", ctx, dn.GetFromZone())
		}
		svc, ok := v.services[dn.GetService()]
		if !ok {
			v.errf("%s: service %q is not a known service", ctx, dn.GetService())
		} else if p := svc.GetProtocol(); p != openngfwv1.Protocol_PROTOCOL_TCP && p != openngfwv1.Protocol_PROTOCOL_UDP {
			v.errf("%s: service %q must be TCP or UDP", ctx, dn.GetService())
		}
		if !v.hostAddress(dn.GetDestinationAddress()) {
			v.errf("%s: destination_address %q must be a /32 or /128 address object", ctx, dn.GetDestinationAddress())
		}
		if !v.hostAddress(dn.GetTranslatedAddress()) {
			v.errf("%s: translated_address %q must be a /32 or /128 address object", ctx, dn.GetTranslatedAddress())
		}
		if dn.GetTranslatedPort() > 65535 {
			v.errf("%s: translated_port %d out of range", ctx, dn.GetTranslatedPort())
		}
	}
}

func (v *validator) checkRoutes(routes []*openngfwv1.StaticRoute) {
	for i, r := range routes {
		ctx := fmt.Sprintf("static route #%d (%s)", i+1, r.GetDestination())
		if _, err := netip.ParsePrefix(r.GetDestination()); err != nil {
			v.errf("%s: invalid destination CIDR", ctx)
		}
		if r.GetVia() == "" && r.GetInterface() == "" {
			v.errf("%s: one of via or interface is required", ctx)
		}
		if r.GetVia() != "" {
			if _, err := netip.ParseAddr(r.GetVia()); err != nil {
				v.errf("%s: invalid via address %q", ctx, r.GetVia())
			}
		}
	}
}

func (v *validator) checkIDs(ids *openngfwv1.Ids) {
	if !ids.GetEnabled() {
		v.checkIDSExceptions(ids.GetExceptions())
		return
	}
	if ids.GetMode() == openngfwv1.IdsMode_IDS_MODE_UNSPECIFIED {
		v.errf("ids: mode must be set when enabled")
	}
	switch ids.GetFailureBehavior() {
	case openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_UNSPECIFIED:
		if ids.GetMode() == openngfwv1.IdsMode_IDS_MODE_PREVENT {
			v.errf("ids: failure_behavior must be set to FAIL_OPEN or FAIL_CLOSED when prevent mode is enabled")
		}
	case openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_OPEN,
		openngfwv1.IdsFailureBehavior_IDS_FAILURE_BEHAVIOR_FAIL_CLOSED:
		if ids.GetMode() != openngfwv1.IdsMode_IDS_MODE_PREVENT {
			v.errf("ids: failure_behavior applies only when mode is IDS_MODE_PREVENT")
		}
	default:
		v.errf("ids: unknown failure_behavior %d", ids.GetFailureBehavior())
	}
	for _, hn := range ids.GetHomeNetworks() {
		if _, err := netip.ParsePrefix(hn); err != nil {
			v.errf("ids: invalid home network CIDR %q", hn)
		}
	}
	for _, rf := range ids.GetRuleFiles() {
		if rf == "" || strings.Contains(rf, "..") || strings.HasPrefix(rf, "/") {
			v.errf("ids: rule file %q must be a relative path inside the rules directory", rf)
		}
	}
	if ids.GetQueueNum() > 65535 {
		v.errf("ids: queue_num %d out of range", ids.GetQueueNum())
	}
	v.checkIDSExceptions(ids.GetExceptions())
}

func (v *validator) checkIDSExceptions(ex []*openngfwv1.IdsException) {
	seen := map[string]bool{}
	activeScopes := map[string]string{}
	for _, e := range ex {
		if !v.checkName("ids exception", e.GetName()) {
			continue
		}
		if seen[e.GetName()] {
			v.errf("duplicate ids exception %q", e.GetName())
			continue
		}
		seen[e.GetName()] = true
		ctx := fmt.Sprintf("ids exception %q", e.GetName())
		v.checkIDSExceptionMetadata(ctx, e)
		if e.GetDisabled() {
			continue
		}
		if e.GetSignatureId() <= 0 {
			v.errf("%s: signature_id must be set to a positive Suricata SID", ctx)
		}
		if tid := e.GetThreatId(); tid != "" && !threatIDRE.MatchString(tid) {
			v.errf("%s: threat_id %q is invalid (lowercase alphanumeric plus '.', ':', '-', '_', max 128 chars)", ctx, tid)
		}
		if e.GetSourceAddress() != "" && e.GetDestinationAddress() != "" {
			v.errf("%s: source_address and destination_address are mutually exclusive", ctx)
		}
		if e.GetSourceAddress() != "" {
			v.checkAddressRefs(ctx, []string{e.GetSourceAddress()})
		}
		if e.GetDestinationAddress() != "" {
			v.checkAddressRefs(ctx, []string{e.GetDestinationAddress()})
		}
		scopeKey := v.idsExceptionScopeKey(e)
		semanticKey := fmt.Sprintf("%d/%s", e.GetSignatureId(), scopeKey)
		if prev := activeScopes[semanticKey]; prev != "" {
			v.errf("%s duplicates active ids exception %q for signature_id and scope", ctx, prev)
		} else {
			activeScopes[semanticKey] = e.GetName()
		}
	}
}

func (v *validator) checkIDSExceptionMetadata(ctx string, e *openngfwv1.IdsException) {
	if len(e.GetOwner()) > 80 {
		v.errf("%s: owner must be at most 80 characters", ctx)
	}
	if len(e.GetTicketId()) > 80 {
		v.errf("%s: ticket_id must be at most 80 characters", ctx)
	}
	if len(e.GetRegressionRef()) > 160 {
		v.errf("%s: regression_ref must be at most 160 characters", ctx)
	}
	if date := e.GetReviewDate(); date != "" {
		if _, err := time.Parse("2006-01-02", date); err != nil {
			v.errf("%s: review_date must use YYYY-MM-DD", ctx)
		}
	}
	if date := e.GetExpiresAt(); date != "" {
		if _, err := time.Parse("2006-01-02", date); err != nil {
			v.errf("%s: expires_at must use YYYY-MM-DD", ctx)
		}
	}
	if pcap := e.GetPcapSha256(); pcap != "" && !sha256RE.MatchString(pcap) {
		v.errf("%s: pcap_sha256 must be a 64-character hex SHA-256", ctx)
	}
}

func (v *validator) idsExceptionScopeKey(e *openngfwv1.IdsException) string {
	if ref := e.GetSourceAddress(); ref != "" {
		return "src:" + v.addressCIDROrRef(ref)
	}
	if ref := e.GetDestinationAddress(); ref != "" {
		return "dst:" + v.addressCIDROrRef(ref)
	}
	return "global"
}

func (v *validator) addressCIDROrRef(ref string) string {
	if addr, ok := v.addresses[ref]; ok {
		return addr.GetCidr()
	}
	return ref
}

func (v *validator) checkTelemetry(tel *openngfwv1.Telemetry) {
	if !tel.GetEnabled() {
		return
	}
	if u := tel.GetClickhouseUrl(); u != "" {
		parsed, err := url.Parse(u)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			v.errf("telemetry: clickhouse_url must be an http(s) URL")
		} else {
			if parsed.User != nil {
				v.errf("telemetry: clickhouse_url must not include URL userinfo; store ClickHouse credentials outside policy")
			}
			for _, key := range telemetryRawQueryParamNames(parsed.RawQuery) {
				if telemetrySensitiveQueryParam(key) {
					v.errf("telemetry: clickhouse_url must not include sensitive query parameter %q; store ClickHouse credentials outside policy", key)
				}
			}
		}
	}
	if db := tel.GetDatabase(); db != "" && !nameRE.MatchString(db) {
		v.errf("telemetry: database %q is not a valid name", db)
	}
	seenExports := map[string]bool{}
	for _, export := range tel.GetExports() {
		v.checkTelemetryExport(export, seenExports)
	}
}

func (v *validator) checkTelemetryExport(export *openngfwv1.TelemetryExport, seen map[string]bool) {
	if export == nil || !export.GetEnabled() {
		return
	}
	name := strings.TrimSpace(export.GetName())
	if name == "" {
		v.errf("telemetry export: name is required")
	} else if !nameRE.MatchString(name) {
		v.errf("telemetry export %q: name is not valid", name)
	} else if seen[name] {
		v.errf("telemetry export %q: duplicate export name", name)
	} else {
		seen[name] = true
	}
	switch export.GetType() {
	case openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_FILE:
		if err := validateTelemetryExportFileTarget(export.GetTarget()); err != nil {
			v.errf("telemetry export %q: %v", name, err)
		}
	case openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_TCP,
		openngfwv1.TelemetryExportType_TELEMETRY_EXPORT_TYPE_JSON_UDP:
		if err := validateTelemetryExportSocketTarget(export.GetTarget()); err != nil {
			v.errf("telemetry export %q: %v", name, err)
		}
	default:
		v.errf("telemetry export %q: type is required", name)
	}
}

func validateTelemetryExportFileTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("file target is required")
	}
	if strings.ContainsAny(target, "\x00\r\n\t") || strings.Contains(target, " ") {
		return fmt.Errorf("file target must not contain whitespace or control characters")
	}
	if !strings.HasPrefix(target, "/") {
		return fmt.Errorf("file target must be an absolute path")
	}
	clean := path.Clean(target)
	const root = "/var/log/openngfw/exports"
	if clean == root || !strings.HasPrefix(clean, root+"/") {
		return fmt.Errorf("file target must stay under %s/", root)
	}
	if strings.HasSuffix(clean, "/") {
		return fmt.Errorf("file target must name a file")
	}
	return nil
}

func validateTelemetryExportSocketTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("socket target is required")
	}
	if strings.ContainsAny(target, "\x00\r\n\t /") {
		return fmt.Errorf("socket target must be host:port without whitespace, URL scheme, or path")
	}
	if strings.Contains(target, "://") || strings.Contains(target, "@") {
		return fmt.Errorf("socket target must be host:port without URL scheme or credentials")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("socket target must be host:port")
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("socket target host is required")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("socket target port must be 1-65535")
	}
	return nil
}

func telemetryRawQueryParamNames(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '&' || r == ';'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		name, _, _ := strings.Cut(part, "=")
		decodedName, err := url.QueryUnescape(name)
		if err != nil {
			decodedName = name
		}
		out = append(out, decodedName)
	}
	return out
}

func telemetrySensitiveQueryParam(key string) bool {
	normalized := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return -1
		}
	}, key)
	switch normalized {
	case "token", "accesstoken", "refreshtoken", "idtoken",
		"password", "passwd",
		"secret", "clientsecret",
		"key", "apikey", "apiaccesskey", "accesskey":
		return true
	}
	return strings.Contains(normalized, "token") ||
		strings.Contains(normalized, "password") ||
		strings.Contains(normalized, "secret") ||
		strings.Contains(normalized, "apikey") ||
		strings.Contains(normalized, "accesskey")
}
