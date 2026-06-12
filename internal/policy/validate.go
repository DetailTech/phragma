// Package policy validates the declarative model before compilation.
// Validation is exhaustive: it returns every problem found, not just the
// first, so a user can fix a candidate in one pass.
package policy

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

// Any is the reserved wildcard reference usable wherever an object name is.
const Any = "any"

var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]{0,62}[a-z0-9])?$`)

// Validate checks p for structural and referential integrity. It returns
// a list of human-readable problems; an empty list means the policy is
// valid.
func Validate(p *openngfwv1.Policy) []string {
	if p == nil {
		return []string{"policy is empty"}
	}
	v := &validator{
		zones:     map[string]bool{},
		addresses: map[string]*openngfwv1.Address{},
		services:  map[string]*openngfwv1.Service{},
	}
	v.collectZones(p.GetZones())
	v.collectAddresses(p.GetAddresses())
	v.collectServices(p.GetServices())
	v.checkRules(p.GetRules())
	v.checkNat(p.GetNat())
	v.checkRoutes(p.GetStaticRoutes())
	v.checkIDs(p.GetIds())
	v.checkTelemetry(p.GetTelemetry())
	v.checkRouting(p.GetRouting())
	v.checkVPN(p.GetVpn())
	v.checkIntel(p.GetIntel())
	v.checkNetwork(p.GetNetwork())
	return v.errs
}

type validator struct {
	errs      []string
	zones     map[string]bool
	addresses map[string]*openngfwv1.Address
	services  map[string]*openngfwv1.Service
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

func (v *validator) checkRules(rules []*openngfwv1.Rule) {
	seen := map[string]bool{}
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
	}
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
		return
	}
	if ids.GetMode() == openngfwv1.IdsMode_IDS_MODE_UNSPECIFIED {
		v.errf("ids: mode must be set when enabled")
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
}

func (v *validator) checkTelemetry(tel *openngfwv1.Telemetry) {
	if !tel.GetEnabled() {
		return
	}
	if u := tel.GetClickhouseUrl(); u != "" {
		parsed, err := url.Parse(u)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			v.errf("telemetry: clickhouse_url %q must be an http(s) URL", u)
		}
	}
	if db := tel.GetDatabase(); db != "" && !nameRE.MatchString(db) {
		v.errf("telemetry: database %q is not a valid name", db)
	}
}
