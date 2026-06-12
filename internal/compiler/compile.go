package compiler

import (
	"fmt"
	"net/netip"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/policy"
)

// Compile resolves p into the IR. p must already have passed
// policy.Validate; Compile re-checks only what it needs to avoid
// undefined behavior and returns an error on any dangling reference.
func Compile(p *openngfwv1.Policy) (*IR, error) {
	if errs := policy.Validate(p); len(errs) > 0 {
		return nil, fmt.Errorf("policy invalid: %s (and %d more)", errs[0], len(errs)-1)
	}

	c := &compilation{
		zoneIfaces: map[string][]string{},
		addrs:      map[string]netip.Prefix{},
		svcs:       map[string]ServiceMatch{},
	}
	ir := &IR{}

	for _, z := range p.GetZones() {
		c.zoneIfaces[z.GetName()] = z.GetInterfaces()
		ir.Zones = append(ir.Zones, ZoneIR{Name: z.GetName(), Interfaces: z.GetInterfaces()})
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

	ids, err := compileIDs(p)
	if err != nil {
		return nil, err
	}
	ir.IDs = ids
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

type compilation struct {
	zoneIfaces map[string][]string
	addrs      map[string]netip.Prefix
	svcs       map[string]ServiceMatch
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

	switch r.GetAction() {
	case openngfwv1.Action_ACTION_ALLOW:
		rule.Action = ActionAllow
	case openngfwv1.Action_ACTION_DENY:
		rule.Action = ActionDeny
	case openngfwv1.Action_ACTION_REJECT:
		rule.Action = ActionReject
	default:
		return rule, fmt.Errorf("rule %q: action unset", r.GetName())
	}
	return rule, nil
}

func (c *compilation) compileSNAT(sn *openngfwv1.SourceNat) (SNATIR, error) {
	out := SNATIR{Name: sn.GetName(), Masquerade: sn.GetMasquerade()}
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
	out := DNATIR{Name: dn.GetName(), ToPort: uint16(dn.GetTranslatedPort())}
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

func compileIDs(p *openngfwv1.Policy) (*IDsIR, error) {
	ids := p.GetIds()
	if !ids.GetEnabled() {
		return nil, nil
	}
	out := &IDsIR{
		Prevent:  ids.GetMode() == openngfwv1.IdsMode_IDS_MODE_PREVENT,
		QueueNum: uint16(ids.GetQueueNum()),
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
	return out
}
