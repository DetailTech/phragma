// Package ebpf contains the plan-only first-party eBPF dataplane scaffold.
//
// It deliberately does not emit loadable programs yet. The v2-mixed runtime
// keeps nftables as the authoritative renderer while the eBPF milestone builds
// verifier, attach, map lifecycle, rollback, and release-evidence coverage.
package ebpf

import (
	"fmt"
	"sort"
	"strings"

	"github.com/detailtech/oss-ngfw/internal/compiler"
)

// SupportedHooks are the Linux attachment points the first-party dataplane is
// being shaped around.
var SupportedHooks = []string{"xdp", "tc"}

// RenderPlan returns a deterministic, non-loadable renderer plan for the
// compiled policy. It is release evidence for scaffold coverage, not an engine
// artifact and not a substitute for nftables output.
func RenderPlan(ir *compiler.IR) ([]byte, error) {
	if ir == nil {
		return nil, fmt.Errorf("nil IR")
	}
	var b strings.Builder
	b.WriteString("# Phragma eBPF dataplane scaffold plan\n")
	b.WriteString("state=planned\n")
	b.WriteString("authoritative_renderer=nftables\n")
	b.WriteString("supported_hooks=xdp,tc\n")
	b.WriteString("program_families=xdp-ingress,tc-ingress,tc-egress\n")
	b.WriteString("map_lifecycle=planned\n")
	b.WriteString("rollback=planned\n")
	b.WriteString("verifier_gate=required\n")
	fmt.Fprintf(&b, "zone_interfaces=%s\n", strings.Join(zoneInterfaces(ir), ","))
	fmt.Fprintf(&b, "policy_rules=%d\n", len(ir.Rules))
	fmt.Fprintf(&b, "host_input_rules=%d\n", len(ir.HostInputRules))
	if ir.Network != nil && len(ir.Network.FlowOffloadDevices) > 0 {
		fmt.Fprintf(&b, "flow_offload_devices=%s\n", strings.Join(sorted(ir.Network.FlowOffloadDevices), ","))
	} else {
		b.WriteString("flow_offload_devices=\n")
	}
	b.WriteString("limitations=not-loadable,no-attach,no-map-pinning,no-runtime-enforcement\n")
	return []byte(b.String()), nil
}

func zoneInterfaces(ir *compiler.IR) []string {
	var out []string
	seen := map[string]bool{}
	for _, zone := range ir.Zones {
		for _, iface := range zone.Interfaces {
			if iface == "" || seen[iface] {
				continue
			}
			seen[iface] = true
			out = append(out, iface)
		}
	}
	sort.Strings(out)
	return out
}

func sorted(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}
