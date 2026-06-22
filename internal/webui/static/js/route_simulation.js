export const ROUTE_SIMULATION_LIMITATIONS = Object.freeze([
  "simulation_model=explain_route_profiles_only",
  "active_probe_not_sent",
  "packet_capture_not_started",
  "remote_peer_attestation_not_claimed",
  "dynamic_frr_kernel_state_not_sampled",
]);

export function boundedRouteSimulationFromCompare(compare = {}) {
  const running = compare.running?.result || null;
  const candidate = compare.candidate?.result || null;
  if (!running || !candidate) return null;
  const scenarios = routeSimulationScenarios(running, candidate);
  return {
    schemaVersion: "route-simulation.v1",
    statement: "Bounded route simulation only; it compares running and candidate explain route profiles without sending packets or attesting remote peers.",
    limitations: [...ROUTE_SIMULATION_LIMITATIONS],
    scenarios,
    changed: scenarios.some((scenario) => scenario.deltas.some((delta) => delta.changed)),
  };
}

export function routeSimulationScenarios(running = {}, candidate = {}) {
  const base = routeSimulationScenario("policy-route-decision", "Policy route decision", running, candidate, {
    nat: natScenarioLabel(candidate),
    tunnel: tunnelScenarioLabel(candidate),
  });
  const scenarios = [base];
  const nat = candidate.natProfile || candidate.natDecision || {};
  if (nat.destination?.matched || nat.source?.matched) {
    scenarios.push(routeSimulationScenario("nat-adjusted-route", "NAT-adjusted route", running, candidate, {
      nat: natScenarioLabel(candidate),
      tunnel: tunnelScenarioLabel(candidate),
    }));
  }
  const tunnel = tunnelScenarioLabel(candidate);
  if (tunnel !== "no tunnel hint") {
    scenarios.push(routeSimulationScenario("tunnel-egress-route", "Tunnel egress route", running, candidate, {
      nat: natScenarioLabel(candidate),
      tunnel,
    }));
  }
  return uniqueScenarioKeys(scenarios);
}

export function routeSimulationScenario(key, label, running = {}, candidate = {}, metadata = {}) {
  const runningDecision = routeDecision(running.routeProfile || {});
  const candidateDecision = routeDecision(candidate.routeProfile || {});
  return {
    key,
    label,
    nat: metadata.nat || "no NAT hint",
    tunnel: metadata.tunnel || "no tunnel hint",
    running: runningDecision,
    candidate: candidateDecision,
    deltas: routeDecisionDeltas(runningDecision, candidateDecision),
    limitations: [...ROUTE_SIMULATION_LIMITATIONS],
  };
}

export function routeDecision(profile = {}) {
  return {
    evaluated: Boolean(profile.evaluated),
    matched: Boolean(profile.matched),
    source: String(profile.source || ""),
    prefix: String(profile.destination || ""),
    nextHop: String(profile.nextHop || profile.next_hop || ""),
    interface: String(profile.egressInterface || profile.egress_interface || ""),
    metric: profile.metric ? String(profile.metric) : "",
    reason: String(profile.reason || ""),
  };
}

export function routeDecisionDeltas(running = {}, candidate = {}) {
  return ["evaluated", "matched", "source", "prefix", "nextHop", "interface", "metric"].map((field) => ({
    field,
    running: routeDecisionValue(running[field]),
    candidate: routeDecisionValue(candidate[field]),
    changed: routeDecisionValue(running[field]) !== routeDecisionValue(candidate[field]),
  })).filter((row) => row.changed);
}

function routeDecisionValue(value) {
  if (value === true) return "true";
  if (value === false) return "false";
  return String(value || "-");
}

function natScenarioLabel(result = {}) {
  const nat = result.natProfile || result.natDecision || {};
  const labels = [];
  if (nat.destination?.matched) labels.push(`DNAT ${nat.destination.matchedRule || "matched"}`);
  if (nat.source?.matched) labels.push(nat.source.masquerade ? `SNAT ${nat.source.matchedRule || "matched"} masquerade` : `SNAT ${nat.source.matchedRule || "matched"}`);
  return labels.join("; ") || "no NAT hint";
}

function tunnelScenarioLabel(result = {}) {
  const iface = String(result.routeProfile?.egressInterface || result.routeProfile?.egress_interface || "");
  if (/^wg/i.test(iface)) return `WireGuard ${iface}`;
  if (/ipsec|xfrm|swan|vti/i.test(iface)) return `IPsec ${iface}`;
  if (/tun|tap/i.test(iface)) return `Tunnel ${iface}`;
  return "no tunnel hint";
}

function uniqueScenarioKeys(scenarios = []) {
  const seen = new Set();
  return scenarios.filter((scenario) => {
    if (seen.has(scenario.key)) return false;
    seen.add(scenario.key);
    return true;
  });
}
