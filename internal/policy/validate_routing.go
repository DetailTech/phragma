package policy

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strings"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
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
		if len(t.GetLocalSubnets()) == 0 || len(t.GetRemoteSubnets()) == 0 {
			v.errf("%s: local_subnets and remote_subnets are required", ctx)
		}
		v.checkCIDRList(ctx+" local_subnets", t.GetLocalSubnets())
		v.checkCIDRList(ctx+" remote_subnets", t.GetRemoteSubnets())
		if t.GetPskFile() == "" || !strings.HasPrefix(t.GetPskFile(), "/") {
			v.errf("%s: psk_file must be an absolute path to a swanctl secrets snippet", ctx)
		}
	}

	seenIf := map[string]bool{}
	for _, w := range vpn.GetWireguardInterfaces() {
		name := w.GetName()
		if name == "" || len(name) > 15 || strings.ContainsAny(name, " /\t") {
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
		if w.GetPrivateKeyFile() == "" || !strings.HasPrefix(w.GetPrivateKeyFile(), "/") {
			v.errf("%s: private_key_file must be an absolute path", ctx)
		}
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
