package explain

import (
	"testing"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestSimulateRouteDecisionsReportsCandidateDeltaAndLimitations(t *testing.T) {
	running := &openngfwv1.Policy{StaticRoutes: []*openngfwv1.StaticRoute{
		{Destination: "0.0.0.0/0", Via: "203.0.113.1", Interface: "wan0", Metric: 100},
		{Destination: "10.20.0.0/16", Via: "10.0.0.1", Interface: "ipsec0", Metric: 50},
	}}
	candidate := &openngfwv1.Policy{StaticRoutes: []*openngfwv1.StaticRoute{
		{Destination: "0.0.0.0/0", Via: "203.0.113.1", Interface: "wan0", Metric: 100},
		{Destination: "10.20.30.0/24", Interface: "wg0", Metric: 10},
	}}

	got := SimulateRouteDecisions(running, candidate, []RouteSimulationScenario{{
		Name:              "branch tunnel after DNAT",
		DestinationIP:     "10.20.30.44",
		Tunnel:            "wireguard:wg0",
		NAT:               "dnat publish-web",
		ExpectedInterface: "wg0",
	}})
	if len(got) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(got))
	}
	result := got[0]
	if result.Running.Interface != "ipsec0" || result.Candidate.Interface != "wg0" {
		t.Fatalf("unexpected decisions: %#v", result)
	}
	if !hasRouteSimulationDelta(result.Deltas, "prefix", "10.20.0.0/16", "10.20.30.0/24") ||
		!hasRouteSimulationDelta(result.Deltas, "interface", "ipsec0", "wg0") {
		t.Fatalf("missing structured deltas: %#v", result.Deltas)
	}
	if !hasString(result.Limitations, "active_probe_not_sent") ||
		!hasString(result.Limitations, "remote_peer_attestation_not_claimed") ||
		!hasString(result.Limitations, "dynamic_frr_kernel_state_not_sampled") {
		t.Fatalf("missing simulation limitations: %#v", result.Limitations)
	}
}

func TestSimulateRouteDecisionsHandlesMultipleScenarios(t *testing.T) {
	running := &openngfwv1.Policy{StaticRoutes: []*openngfwv1.StaticRoute{{Destination: "0.0.0.0/0", Interface: "wan0", Metric: 100}}}
	candidate := &openngfwv1.Policy{StaticRoutes: []*openngfwv1.StaticRoute{{Destination: "10.99.0.0/24", Interface: "wg0", Metric: 5}}}
	got := SimulateRouteDecisions(running, candidate, []RouteSimulationScenario{
		{Name: "source NAT egress", DestinationIP: "198.51.100.10", NAT: "masquerade"},
		{Name: "tunnel selector", DestinationIP: "10.99.0.7", Tunnel: "wireguard:wg0", ExpectedInterface: "wg1"},
	})
	if len(got) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(got))
	}
	if got[0].Candidate.Matched {
		t.Fatalf("candidate should not claim a route for source NAT egress scenario: %#v", got[0])
	}
	if !hasRouteSimulationDelta(got[1].Deltas, "expected_interface", "wg1", "wg0") {
		t.Fatalf("expected-interface mismatch not surfaced: %#v", got[1].Deltas)
	}
}

func hasRouteSimulationDelta(rows []RouteSimulationDelta, field, running, candidate string) bool {
	for _, row := range rows {
		if row.Field == field && row.Running == running && row.Candidate == candidate {
			return true
		}
	}
	return false
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
