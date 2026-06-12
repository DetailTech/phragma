package policy

import (
	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

// MTU bounds: IPv6 minimum to common jumbo-frame NIC maximums.
const (
	minMTU = 1280
	maxMTU = 9600
)

func (v *validator) checkNetwork(n *openngfwv1.Network) {
	if n == nil {
		return
	}
	if mtu := n.GetMtu(); mtu != 0 && (mtu < minMTU || mtu > maxMTU) {
		v.errf("network: mtu %d out of range %d-%d", mtu, minMTU, maxMTU)
	}
	seen := map[string]bool{}
	for _, im := range n.GetInterfaceMtus() {
		if im.GetInterface() == "" {
			v.errf("network: interface_mtus entry with empty interface")
			continue
		}
		if seen[im.GetInterface()] {
			v.errf("network: duplicate interface_mtus entry for %q", im.GetInterface())
			continue
		}
		seen[im.GetInterface()] = true
		if mtu := im.GetMtu(); mtu < minMTU || mtu > maxMTU {
			v.errf("network: interface %q mtu %d out of range %d-%d", im.GetInterface(), mtu, minMTU, maxMTU)
		}
	}
}
