package policy

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"unicode"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

var (
	ipsecSecretRoots  = []string{"/etc/phragma/secrets", "/etc/openngfw/secrets"}
	wireguardKeyRoots = []string{"/etc/phragma/keys", "/etc/openngfw/keys"}
)

func (v *validator) checkRouting(r *openngfwv1.Routing) {
	if bgp := r.GetBgp(); bgp.GetEnabled() {
		if bgp.GetAsn() == 0 {
			v.errf("bgp: asn must be set")
		}
		if bgp.GetRouterId() == "" {
			v.errf("bgp: router_id must be set")
		} else if ip, err := netip.ParseAddr(bgp.GetRouterId()); err != nil || !ip.Is4() {
			v.errf("bgp: router_id %q must be an IPv4 address", bgp.GetRouterId())
		}
		if len(bgp.GetNeighbors()) == 0 {
			v.errf("bgp: at least one neighbor is required")
		}
		for _, n := range bgp.GetNeighbors() {
			if _, err := netip.ParseAddr(n.GetAddress()); err != nil {
				v.errf("bgp neighbor %q: invalid address", n.GetAddress())
			}
			if n.GetRemoteAsn() == 0 {
				v.errf("bgp neighbor %q: remote_asn must be set", n.GetAddress())
			}
			if hasControl(n.GetDescription()) {
				v.errf("bgp neighbor %q: description must not contain control characters", n.GetAddress())
			}
		}
		v.checkCIDRList("bgp announce_networks", bgp.GetAnnounceNetworks())
	}

	if ospf := r.GetOspf(); ospf.GetEnabled() {
		if rid := ospf.GetRouterId(); rid != "" {
			if ip, err := netip.ParseAddr(rid); err != nil || !ip.Is4() {
				v.errf("ospf: router_id %q must be an IPv4 address", rid)
			}
		}
		if len(ospf.GetAreas()) == 0 {
			v.errf("ospf: at least one area is required")
		}
		for _, a := range ospf.GetAreas() {
			if ip, err := netip.ParseAddr(a.GetArea()); err != nil || !ip.Is4() {
				v.errf("ospf area %q: must be in dotted form (e.g. 0.0.0.0)", a.GetArea())
			}
			if len(a.GetNetworks()) == 0 {
				v.errf("ospf area %q: at least one network is required", a.GetArea())
			}
			v.checkCIDRList(fmt.Sprintf("ospf area %q networks", a.GetArea()), a.GetNetworks())
		}
	}
}

func (v *validator) checkVPN(vpn *openngfwv1.Vpn) {
	seen := map[string]bool{}
	for _, t := range vpn.GetIpsecTunnels() {
		if !v.checkName("ipsec tunnel", t.GetName()) {
			continue
		}
		if seen[t.GetName()] {
			v.errf("duplicate ipsec tunnel %q", t.GetName())
			continue
		}
		seen[t.GetName()] = true
		ctx := fmt.Sprintf("ipsec tunnel %q", t.GetName())
		if t.GetRemoteAddress() == "" {
			v.errf("%s: remote_address is required", ctx)
		}
		v.checkConfigToken(ctx, "local_address", t.GetLocalAddress(), false)
		v.checkConfigToken(ctx, "remote_address", t.GetRemoteAddress(), true)
		v.checkConfigToken(ctx, "ike_proposal", t.GetIkeProposal(), false)
		v.checkConfigToken(ctx, "esp_proposal", t.GetEspProposal(), false)
		if len(t.GetLocalSubnets()) == 0 || len(t.GetRemoteSubnets()) == 0 {
			v.errf("%s: local_subnets and remote_subnets are required", ctx)
		}
		v.checkCIDRList(ctx+" local_subnets", t.GetLocalSubnets())
		v.checkCIDRList(ctx+" remote_subnets", t.GetRemoteSubnets())
		v.checkManagedFilePath(ctx, "psk_file", t.GetPskFile(), ipsecSecretRoots)
	}

	seenIf := map[string]bool{}
	for _, w := range vpn.GetWireguardInterfaces() {
		name := w.GetName()
		if name == "" || len(name) > 15 || strings.ContainsAny(name, "/") || hasSpaceOrControl(name) {
			v.errf("wireguard interface %q: invalid interface name", name)
			continue
		}
		if seenIf[name] {
			v.errf("duplicate wireguard interface %q", name)
			continue
		}
		seenIf[name] = true
		ctx := fmt.Sprintf("wireguard %q", name)
		if _, err := netip.ParsePrefix(w.GetAddress()); err != nil {
			v.errf("%s: address %q must be CIDR (e.g. 10.99.0.1/24)", ctx, w.GetAddress())
		}
		if w.GetListenPort() > 65535 {
			v.errf("%s: listen_port out of range", ctx)
		}
		v.checkManagedFilePath(ctx, "private_key_file", w.GetPrivateKeyFile(), wireguardKeyRoots)
		for _, p := range w.GetPeers() {
			pctx := fmt.Sprintf("%s peer %q", ctx, p.GetName())
			if raw, err := base64.StdEncoding.DecodeString(p.GetPublicKey()); err != nil || len(raw) != 32 {
				v.errf("%s: public_key must be a base64 32-byte key", pctx)
			}
			if len(p.GetAllowedIps()) == 0 {
				v.errf("%s: allowed_ips is required", pctx)
			}
			v.checkCIDRList(pctx+" allowed_ips", p.GetAllowedIps())
			if ep := p.GetEndpoint(); ep != "" {
				if !v.checkConfigToken(pctx, "endpoint", ep, false) {
					continue
				}
				if _, _, err := net.SplitHostPort(ep); err != nil {
					v.errf("%s: endpoint %q must be host:port", pctx, ep)
				}
			}
			if p.GetPersistentKeepalive() > 65535 {
				v.errf("%s: persistent_keepalive out of range", pctx)
			}
		}
	}
}

func (v *validator) checkCIDRList(ctx string, cidrs []string) {
	for _, c := range cidrs {
		if _, err := netip.ParsePrefix(c); err != nil {
			v.errf("%s: invalid CIDR %q", ctx, c)
		}
	}
}

func (v *validator) checkConfigToken(ctx, field, value string, required bool) bool {
	if value == "" {
		if required {
			v.errf("%s: %s is required", ctx, field)
		}
		return !required
	}
	if hasSpaceOrControl(value) || strings.ContainsAny(value, "{}\"'`#;") {
		v.errf("%s: %s contains characters unsafe for rendered engine config", ctx, field)
		return false
	}
	return true
}

//nolint:unparam // The boolean result is useful for callers that may need to short-circuit future checks.
func (v *validator) checkManagedFilePath(ctx, field, value string, roots []string) bool {
	if value == "" {
		v.errf("%s: %s must reference an operator-provisioned file", ctx, field)
		return false
	}
	if hasSpaceOrControl(value) {
		v.errf("%s: %s must not contain whitespace or control characters", ctx, field)
		return false
	}
	if !filepath.IsAbs(value) {
		v.errf("%s: %s must be an absolute path", ctx, field)
		return false
	}
	clean := filepath.Clean(value)
	if clean != value || hasParentComponent(value) {
		v.errf("%s: %s must be normalized and must not contain path traversal", ctx, field)
		return false
	}
	for _, root := range roots {
		root = filepath.Clean(root)
		if strings.HasPrefix(clean, root+string(filepath.Separator)) && len(clean) > len(root)+1 {
			return true
		}
	}
	v.errf("%s: %s must be under %s", ctx, field, strings.Join(roots, " or "))
	return false
}

func hasParentComponent(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, unicode.IsControl)
}

func hasSpaceOrControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	})
}
