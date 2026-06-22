package explain

import (
	"fmt"
	"net/netip"
	"strings"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

// RouteSimulationScenario identifies one bounded route/tunnel/NAT what-if.
// DestinationIP is the post-DNAT route lookup destination.
type RouteSimulationScenario struct {
	Name              string
	DestinationIP     string
	Tunnel            string
	NAT               string
	ExpectedInterface string
}

type RouteSimulationResult struct {
	Name        string
	Tunnel      string
	NAT         string
	Running     RouteSimulationDecision
	Candidate   RouteSimulationDecision
	Deltas      []RouteSimulationDelta
	Limitations []string
}

type RouteSimulationDecision struct {
	Matched   bool
	Source    string
	Prefix    string
	NextHop   string
	Interface string
	Metric    uint32
	Reason    string
}

type RouteSimulationDelta struct {
	Field     string
	Running   string
	Candidate string
}

func SimulateRouteDecisions(running, candidate *openngfwv1.Policy, scenarios []RouteSimulationScenario) []RouteSimulationResult {
	out := make([]RouteSimulationResult, 0, len(scenarios))
	for _, scenario := range scenarios {
		result := RouteSimulationResult{
			Name:   strings.TrimSpace(scenario.Name),
			Tunnel: strings.TrimSpace(scenario.Tunnel),
			NAT:    strings.TrimSpace(scenario.NAT),
			Limitations: []string{
				"simulation_model=static_policy_routes_only",
				"active_probe_not_sent",
				"packet_capture_not_started",
				"remote_peer_attestation_not_claimed",
				"dynamic_frr_kernel_state_not_sampled",
			},
		}
		if result.Name == "" {
			result.Name = "route scenario"
		}
		dst, err := netip.ParseAddr(strings.TrimSpace(scenario.DestinationIP))
		if err != nil {
			result.Running = invalidRouteSimulationDecision(scenario.DestinationIP, err)
			result.Candidate = result.Running
			result.Limitations = append(result.Limitations, "invalid_destination_skipped")
			out = append(out, result)
			continue
		}
		result.Running = routeSimulationDecision(running, dst)
		result.Candidate = routeSimulationDecision(candidate, dst)
		result.Deltas = routeSimulationDeltas(result.Running, result.Candidate)
		if expected := strings.TrimSpace(scenario.ExpectedInterface); expected != "" {
			if result.Candidate.Interface != "" && result.Candidate.Interface != expected {
				result.Deltas = append(result.Deltas, RouteSimulationDelta{
					Field:     "expected_interface",
					Running:   expected,
					Candidate: result.Candidate.Interface,
				})
			}
		}
		out = append(out, result)
	}
	return out
}

func invalidRouteSimulationDecision(destination string, err error) RouteSimulationDecision {
	return RouteSimulationDecision{
		Source: "invalid",
		Reason: fmt.Sprintf("destination %q is not a valid IP address: %v", destination, err),
	}
}

func routeSimulationDecision(policy *openngfwv1.Policy, dst netip.Addr) RouteSimulationDecision {
	if policy == nil {
		return RouteSimulationDecision{Source: "missing-policy", Reason: "policy was not provided"}
	}
	var best routeInfo
	found := false
	for _, route := range policy.GetStaticRoutes() {
		prefix, err := netip.ParsePrefix(route.GetDestination())
		if err != nil || !prefix.Contains(dst) {
			continue
		}
		if !found ||
			prefix.Bits() > best.prefix.Bits() ||
			(prefix.Bits() == best.prefix.Bits() && route.GetMetric() < best.route.GetMetric()) {
			best = routeInfo{route: route, prefix: prefix}
			found = true
		}
	}
	if !found {
		return RouteSimulationDecision{
			Source: "unresolved",
			Reason: fmt.Sprintf("no OpenNGFW static route matched destination %s", dst),
		}
	}
	return RouteSimulationDecision{
		Matched:   true,
		Source:    "static",
		Prefix:    best.prefix.String(),
		NextHop:   best.route.GetVia(),
		Interface: best.route.GetInterface(),
		Metric:    best.route.GetMetric(),
		Reason:    fmt.Sprintf("static route %s selected by longest-prefix match", best.prefix),
	}
}

func routeSimulationDeltas(running, candidate RouteSimulationDecision) []RouteSimulationDelta {
	var out []RouteSimulationDelta
	add := func(field, r, c string) {
		if r != c {
			out = append(out, RouteSimulationDelta{Field: field, Running: r, Candidate: c})
		}
	}
	add("matched", fmt.Sprint(running.Matched), fmt.Sprint(candidate.Matched))
	add("source", running.Source, candidate.Source)
	add("prefix", running.Prefix, candidate.Prefix)
	add("next_hop", running.NextHop, candidate.NextHop)
	add("interface", running.Interface, candidate.Interface)
	add("metric", fmt.Sprint(running.Metric), fmt.Sprint(candidate.Metric))
	return out
}
