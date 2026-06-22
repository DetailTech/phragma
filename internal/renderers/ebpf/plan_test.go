package ebpf

import (
	"strings"
	"testing"

	"github.com/detailtech/oss-ngfw/internal/compiler"
)

func TestRenderPlanReportsScaffoldScope(t *testing.T) {
	plan, err := RenderPlan(&compiler.IR{
		Zones: []compiler.ZoneIR{
			{Name: "wan", Interfaces: []string{"eth0"}},
			{Name: "lan", Interfaces: []string{"eth1"}},
		},
		Rules:          []compiler.RuleIR{{Name: "allow-web"}},
		HostInputRules: []compiler.RuleIR{{Name: "ssh-admin"}},
		Network:        &compiler.NetworkIR{FlowOffloadDevices: []string{"eth1", "eth0"}},
	})
	if err != nil {
		t.Fatalf("RenderPlan returned error: %v", err)
	}
	text := string(plan)
	for _, want := range []string{
		"state=planned",
		"authoritative_renderer=nftables",
		"supported_hooks=xdp,tc",
		"program_families=xdp-ingress,tc-ingress,tc-egress",
		"zone_interfaces=eth0,eth1",
		"policy_rules=1",
		"host_input_rules=1",
		"flow_offload_devices=eth0,eth1",
		"limitations=not-loadable,no-attach,no-map-pinning,no-runtime-enforcement",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("plan missing %q:\n%s", want, text)
		}
	}
}

func TestRenderPlanRejectsNilIR(t *testing.T) {
	if _, err := RenderPlan(nil); err == nil {
		t.Fatal("RenderPlan(nil) error = nil, want error")
	}
}
