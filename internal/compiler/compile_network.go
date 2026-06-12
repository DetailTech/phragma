package compiler

import (
	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

// compileNetwork resolves the global network section. The IDS section
// must already be compiled (offload management applies to its monitored
// interfaces).
func compileNetwork(p *openngfwv1.Policy, ids *IDsIR) *NetworkIR {
	net := p.GetNetwork()
	if net == nil {
		return nil
	}
	out := &NetworkIR{ClampMSS: net.GetClampMssToPmtu()}

	// Global MTU covers every zone interface, deterministically ordered;
	// overrides replace or extend (for non-zone interfaces like mgmt).
	override := map[string]uint32{}
	for _, im := range net.GetInterfaceMtus() {
		override[im.GetInterface()] = im.GetMtu()
	}
	seen := map[string]bool{}
	if net.GetMtu() != 0 {
		for _, z := range p.GetZones() {
			for _, ifc := range z.GetInterfaces() {
				if seen[ifc] {
					continue
				}
				seen[ifc] = true
				mtu := net.GetMtu()
				if o, ok := override[ifc]; ok {
					mtu = o
				}
				out.Links = append(out.Links, LinkIR{Interface: ifc, MTU: mtu})
			}
		}
	}
	for _, im := range net.GetInterfaceMtus() {
		if !seen[im.GetInterface()] {
			seen[im.GetInterface()] = true
			out.Links = append(out.Links, LinkIR{Interface: im.GetInterface(), MTU: im.GetMtu()})
		}
	}
	for _, l := range out.Links {
		if l.MTU > out.MaxMTU {
			out.MaxMTU = l.MTU
		}
	}

	// Offload management only matters where the IDS sniffs wire frames.
	if net.GetManageNicOffloads() && ids != nil && !ids.Prevent {
		out.OffloadOffIfaces = ids.Interfaces
	}

	if len(out.Links) == 0 && !out.ClampMSS && len(out.OffloadOffIfaces) == 0 {
		return nil
	}
	return out
}
