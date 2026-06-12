package compiler

import (
	"fmt"
	"net/netip"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func compileRouting(p *openngfwv1.Policy) (*RoutingIR, error) {
	r := p.GetRouting()
	bgp := r.GetBgp()
	ospf := r.GetOspf()
	if !bgp.GetEnabled() && !ospf.GetEnabled() {
		return nil, nil
	}
	out := &RoutingIR{}

	if bgp.GetEnabled() {
		b := &BGPIR{ASN: bgp.GetAsn(), RouterID: bgp.GetRouterId()}
		for _, n := range bgp.GetNeighbors() {
			addr, err := netip.ParseAddr(n.GetAddress())
			if err != nil {
				return nil, fmt.Errorf("bgp neighbor %q: invalid address", n.GetAddress())
			}
			b.Neighbors = append(b.Neighbors, BGPNeighborIR{
				Address: addr, RemoteASN: n.GetRemoteAsn(), Description: n.GetDescription(),
			})
		}
		for _, net := range bgp.GetAnnounceNetworks() {
			pfx, err := netip.ParsePrefix(net)
			if err != nil {
				return nil, fmt.Errorf("bgp announce network %q: invalid CIDR", net)
			}
			b.Announce = append(b.Announce, pfx)
		}
		out.BGP = b
	}

	if ospf.GetEnabled() {
		o := &OSPFIR{RouterID: ospf.GetRouterId()}
		for _, a := range ospf.GetAreas() {
			area := OSPFAreaIR{Area: a.GetArea()}
			for _, net := range a.GetNetworks() {
				pfx, err := netip.ParsePrefix(net)
				if err != nil {
					return nil, fmt.Errorf("ospf area %q network %q: invalid CIDR", a.GetArea(), net)
				}
				area.Networks = append(area.Networks, pfx)
			}
			o.Areas = append(o.Areas, area)
		}
		out.OSPF = o
	}
	return out, nil
}

func compileVPN(p *openngfwv1.Policy) (*VPNIR, error) {
	vpn := p.GetVpn()
	if len(vpn.GetIpsecTunnels()) == 0 && len(vpn.GetWireguardInterfaces()) == 0 {
		return nil, nil
	}
	out := &VPNIR{}

	for _, t := range vpn.GetIpsecTunnels() {
		ir := IpsecIR{
			Name:          t.GetName(),
			LocalAddress:  t.GetLocalAddress(),
			RemoteAddress: t.GetRemoteAddress(),
			PSKFile:       t.GetPskFile(),
			IKEProposal:   t.GetIkeProposal(),
			ESPProposal:   t.GetEspProposal(),
			Initiate:      t.GetInitiate(),
		}
		if ir.LocalAddress == "" {
			ir.LocalAddress = "%any"
		}
		if ir.IKEProposal == "" {
			ir.IKEProposal = "aes256-sha256-modp2048"
		}
		if ir.ESPProposal == "" {
			ir.ESPProposal = "aes256-sha256-modp2048"
		}
		var err error
		if ir.LocalSubnets, err = parsePrefixList("ipsec tunnel "+t.GetName()+" local subnet", t.GetLocalSubnets()); err != nil {
			return nil, err
		}
		if ir.RemoteSubnets, err = parsePrefixList("ipsec tunnel "+t.GetName()+" remote subnet", t.GetRemoteSubnets()); err != nil {
			return nil, err
		}
		out.IPsec = append(out.IPsec, ir)
	}

	for _, w := range vpn.GetWireguardInterfaces() {
		ir := WireguardIR{
			Name:           w.GetName(),
			ListenPort:     uint16(w.GetListenPort()),
			PrivateKeyFile: w.GetPrivateKeyFile(),
		}
		pfx, err := netip.ParsePrefix(w.GetAddress())
		if err != nil {
			return nil, fmt.Errorf("wireguard %q: invalid address %q", w.GetName(), w.GetAddress())
		}
		ir.Address = pfx
		for _, peer := range w.GetPeers() {
			p := WireguardPeerIR{
				Name: peer.GetName(), PublicKey: peer.GetPublicKey(),
				Endpoint: peer.GetEndpoint(), Keepalive: uint16(peer.GetPersistentKeepalive()),
			}
			if p.AllowedIPs, err = parsePrefixList("wireguard peer "+peer.GetName()+" allowed ip", peer.GetAllowedIps()); err != nil {
				return nil, err
			}
			ir.Peers = append(ir.Peers, p)
		}
		out.Wireguard = append(out.Wireguard, ir)
	}
	return out, nil
}

func parsePrefixList(ctx string, cidrs []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, c := range cidrs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("%s %q: invalid CIDR", ctx, c)
		}
		out = append(out, pfx)
	}
	return out, nil
}
