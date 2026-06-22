import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  buildTroubleshootRuleDraft,
  compareDeltaSummary,
  compareQueryKey,
  compareQueriesFromRouteState,
  correlatedEveRows,
  engineHealthContext,
  explanationTimelineModel,
  explainQueryFromRouteState,
  isCurrentTroubleshootRequest,
  normalizeTroubleshootRoute,
  normalizeTroubleshootCaseContext,
  normalizeTroubleshootCaptureContext,
  recommendedTroubleshootRuleInsertIndex,
  routeStateFromExplainQuery,
  safeTroubleshootRouteToken,
  troubleshootQueryKey,
} from "./views/troubleshoot.js";
import { boundedRouteSimulationFromCompare, routeSimulationScenarios } from "./route_simulation.js";

const troubleshootSource = readFileSync(new URL("./views/troubleshoot.js", import.meta.url), "utf8");
assert.match(troubleshootSource, /captureAction: "copy-command"/);
assert.match(troubleshootSource, /type: "button", title: "Copy capture command", "aria-label": "Copy capture command"/);
assert.match(troubleshootSource, /type: "button",\s+title: "Clear Troubleshoot flow query",\s+"aria-label": "Clear Troubleshoot flow query",\s+dataset: \{ troubleshootAction: "clear-query" \}/);
assert.match(troubleshootSource, /type: "submit", title: "Explain this flow against the selected policy", "aria-label": "Explain this flow against the selected policy", dataset: \{ troubleshootAction: "explain-flow" \}/);
assert.match(troubleshootSource, /title: "Compare this flow against running and candidate policy",\s+"aria-label": "Compare this flow against running and candidate policy",\s+dataset: \{ troubleshootAction: "compare-policy" \}/);
assert.match(troubleshootSource, /title: "Review and stage an allow rule for this explained tuple",\s+"aria-label": "Review and stage an allow rule for this explained tuple",\s+dataset: \{ troubleshootAction: "stage-allow" \}/);
assert.match(troubleshootSource, /title: `\$\{row\.pivotLabel\} for correlated \$\{row\.kind\}`/);
assert.match(troubleshootSource, /title: "Refresh server-validated packet-capture plan", "aria-label": "Refresh server-validated packet-capture plan"/);
assert.match(troubleshootSource, /title: "Pin packet-capture handoff to the investigation case", "aria-label": "Pin packet-capture handoff to the investigation case"/);
assert.match(troubleshootSource, /title: `Pin \$\{label\} handoff to the investigation case`, "aria-label": `Pin \$\{label\} handoff to the investigation case`/);
assert.match(troubleshootSource, /"From log plan\. "/);
assert.match(troubleshootSource, /System Logs supplied this bounded capture plan/);
assert.doesNotMatch(troubleshootSource, /api\.startPacketCapture\([^)]*\)\s*;?\s*setTimeout/);
assert.match(troubleshootSource, /Bounded route simulation/);
assert.match(troubleshootSource, /dataset: \{ troubleshootRouteSimulation: "bounded" \}/);
assert.match(troubleshootSource, /routeSimulationLimitations/);

{
  const timeline = explanationTimelineModel({
    verdict: "EXPLAIN_VERDICT_ALLOWED",
    matchedRule: "allow-web",
    matchedRuleIndex: 2,
    reason: "first matching policy rule \"allow-web\" returned allow",
    evidence: [
      "flow 10.0.1.20:51515 -> 203.0.113.10:443 TCP, zones lan -> wan",
      "application web-browsing matched by TCP/443 hint",
    ],
    natProfile: {
      destination: {
        evaluated: true,
        matched: true,
        matchedRule: "publish-web",
        originalDestinationIp: "203.0.113.10",
        originalDestinationPort: 443,
        translatedDestinationIp: "10.0.2.20",
        translatedDestinationPort: 8443,
        evidence: ["destination NAT publish-web matched"],
      },
      source: {
        evaluated: true,
        matched: true,
        matchedRule: "masq-wan",
        masquerade: true,
        originalSourceIp: "10.0.1.20",
      },
    },
    routeProfile: {
      evaluated: true,
      matched: true,
      destination: "0.0.0.0/0",
      egressInterface: "wan0",
      evidence: ["route 0.0.0.0/0 via wan0"],
    },
    inspectionState: "EXPLAIN_INSPECTION_STATE_IDS_DETECT",
    inspectionProfile: {
      idsEnabled: true,
      idsMode: "IDS_MODE_DETECT",
      evidence: ["IDS detect profile applies"],
    },
    runtimeEvidence: {
      queried: true,
      state: "ready",
      sessions: [{ id: "ct-1" }],
      correlatedFlows: [{ flowId: "eve-1" }],
      correlatedAlerts: [],
      evidence: ["runtime EVE flow matched"],
    },
    warnings: ["policy-model verdict only"],
  });

  assert.deepEqual(timeline.map((step) => step.stage), ["input", "dnat", "policy", "app", "inspection", "route", "snat", "runtime", "warnings"]);
  assert.equal(timeline.find((step) => step.stage === "policy").tone, "ok");
  assert.match(timeline.find((step) => step.stage === "dnat").detail, /203\.0\.113\.10:443 to 10\.0\.2\.20:8443/);
  assert.match(timeline.find((step) => step.stage === "runtime").detail, /1 conntrack, 1 EVE flow, and 0 alert matches/);
}

{
  const compare = {
    running: {
      result: {
        routeProfile: { evaluated: true, matched: true, source: "static", destination: "10.20.0.0/16", nextHop: "10.0.0.1", egressInterface: "ipsec0", metric: 50 },
      },
    },
    candidate: {
      result: {
        routeProfile: { evaluated: true, matched: true, source: "static", destination: "10.20.30.0/24", egressInterface: "wg0", metric: 10 },
        natProfile: { destination: { matched: true, matchedRule: "publish-web" }, source: { matched: true, matchedRule: "masq-wan", masquerade: true } },
      },
    },
  };
  const model = boundedRouteSimulationFromCompare(compare);
  assert.equal(model.schemaVersion, "route-simulation.v1");
  assert.equal(model.changed, true);
  assert.ok(model.limitations.includes("active_probe_not_sent"));
  assert.ok(model.limitations.includes("remote_peer_attestation_not_claimed"));
  assert.ok(model.limitations.includes("dynamic_frr_kernel_state_not_sampled"));
  assert.ok(model.scenarios.some((scenario) => scenario.key === "nat-adjusted-route"));
  assert.ok(model.scenarios.some((scenario) => scenario.key === "tunnel-egress-route"));
  assert.ok(model.scenarios[0].deltas.some((delta) => delta.field === "prefix" && delta.running === "10.20.0.0/16" && delta.candidate === "10.20.30.0/24"));
  assert.ok(model.scenarios[0].deltas.some((delta) => delta.field === "interface" && delta.running === "ipsec0" && delta.candidate === "wg0"));
  assert.equal(routeSimulationScenarios(compare.running.result, compare.candidate.result).length, 3);
}

{
  const timeline = explanationTimelineModel({
    verdict: "EXPLAIN_VERDICT_DEFAULT_DROP",
    defaultPolicy: true,
    reason: "no enabled security rule matched; nftables forward chain policy drops by default",
    evidence: ["flow 10.0.1.20:0 -> 10.0.2.20:0 ANY, zones any -> any"],
    inspectionState: "EXPLAIN_INSPECTION_STATE_NOT_INSPECTED",
    inspectionProfile: { bypassPossible: true, bypassReason: "IDS/IPS disabled" },
    routeProfile: { evaluated: true, matched: false, reason: "no route matched" },
  });

  assert.deepEqual(timeline.map((step) => step.stage), ["input", "policy", "inspection", "route"]);
  assert.equal(timeline.find((step) => step.stage === "policy").tone, "bad");
  assert.equal(timeline.find((step) => step.stage === "inspection").tone, "warn");
  assert.match(timeline.find((step) => step.stage === "policy").detail, /drops by default/);
}

{
  const rows = correlatedEveRows([
    {
      flowId: "eve-flow-42",
      srcIp: "10.0.1.20",
      srcPort: 51515,
      destIp: "203.0.113.10",
      destPort: 443,
      protocol: "TCP",
      appId: "web-browsing",
      policyVersionKnown: true,
      policyVersion: 7,
      bytesToServer: 2048,
      bytesToClient: 4096,
      packets: 12,
    },
  ], [
    {
      flowId: "eve-flow-42",
      srcIp: "10.0.1.20",
      srcPort: 51515,
      destIp: "203.0.113.10",
      destPort: 443,
      threatId: "ET.TEST",
      policyVersionKnown: false,
      policyVersion: 0,
      severity: 1,
      action: "allowed",
      signatureId: 9000001,
    },
  ], { runningPolicyVersion: 8 });

  assert.equal(rows.length, 2);
  assert.equal(rows[0].kind, "flow");
  assert.equal(rows[0].signal, "web-browsing");
  assert.match(rows[0].detail, /flow_id=eve-flow-42/);
  assert.equal(rows[0].policyStamp, "v7");
  assert.match(rows[0].policyFreshness, /stale at query time/);
  assert.equal(rows[0].href, "#/traffic?mode=flows&flowId=eve-flow-42&limit=100");
  assert.equal(rows[1].kind, "alert");
  assert.equal(rows[1].signal, "ET.TEST");
  assert.match(rows[1].detail, /SID 9000001/);
  assert.equal(rows[1].policyStamp, "unknown event policy stamp");
  assert.equal(rows[1].policyFreshness, "freshness unknown");
  assert.equal(rows[1].href, "#/threats?flowId=eve-flow-42&limit=100");
}

{
  assert.deepEqual(engineHealthContext({}, { queried: false }), { available: false });
  const model = engineHealthContext({
    inspection: {
      state: "failed-open",
      detail: "Suricata inline unavailable; fail-open bypass active.",
      engineName: "suricata",
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_OPEN",
      bypassPossible: true,
    },
    engines: [
      { name: "suricata", role: "inspection", mode: "inline", state: "failed", detail: "process not running" },
      { name: "vector", role: "telemetry", mode: "eve", state: "ready", detail: "shipping events" },
      { name: "postgres", role: "storage", state: "ready" },
    ],
    warnings: [
      "inspection engine failed open",
      "database compaction pending",
    ],
  }, { queried: true });
  assert.equal(model.available, true);
  assert.equal(model.state, "failed-open");
  assert.equal(model.cls, "bad");
  assert.equal(model.engineLabel, "suricata");
  assert.equal(model.failureBehavior, "fail-open");
  assert.equal(model.bypassPossible, true);
  assert.deepEqual(model.engines.map((engine) => engine.name), ["suricata", "vector"]);
  assert.deepEqual(model.warnings, ["inspection engine failed open"]);
}

{
  const policy = {
    zones: [{ name: "inside" }, { name: "outside" }],
    addresses: [
      { name: "inside-host", cidr: "10.0.1.20/32" },
      { name: "web-server", cidr: "10.0.2.20/32" },
    ],
    services: [
      { name: "https", protocol: "PROTOCOL_TCP", ports: [{ start: 443 }] },
    ],
    rules: [
      { name: "allow-dns" },
      { name: "drop-web" },
    ],
  };
  const original = structuredClone(policy);
  const draft = buildTroubleshootRuleDraft(policy, {
    policySource: "POLICY_SOURCE_RUNNING",
    fromZone: "inside",
    toZone: "outside",
    srcIp: "10.0.1.20",
    srcPort: 51515,
    destIp: "10.0.2.20",
    destPort: 443,
    protocol: "tcp",
  }, {
    verdict: "EXPLAIN_VERDICT_DENIED",
    matchedRule: "drop-web",
    matchedRuleIndex: 1,
  }, "ACTION_ALLOW");

  assert.deepEqual(policy, original);
  assert.equal(draft.insertAt, 1);
  assert.deepEqual(draft.generated, { addresses: [], services: [] });
  assert.deepEqual(draft.rule.fromZones, ["inside"]);
  assert.deepEqual(draft.rule.toZones, ["outside"]);
  assert.deepEqual(draft.rule.sourceAddresses, ["inside-host"]);
  assert.deepEqual(draft.rule.destinationAddresses, ["web-server"]);
  assert.deepEqual(draft.rule.services, ["https"]);
  assert.equal(draft.rule.action, "ACTION_ALLOW");
  assert.equal(draft.rule.log, true);
  assert.equal(draft.rule.disabled, false);
  assert.match(draft.rule.description, /Current explanation matched drop-web at index 1/);
}

{
  const policy = {
    addresses: [],
    services: [],
    rules: [{ name: "allow-any" }],
  };
  const original = structuredClone(policy);
  const draft = buildTroubleshootRuleDraft(policy, {
    srcIp: "192.0.2.10",
    destIp: "2001:db8::10",
    destPort: 53,
    protocol: "udp",
  }, {
    verdict: "EXPLAIN_VERDICT_ALLOWED",
  }, "ACTION_DENY");

  assert.deepEqual(policy, original);
  assert.equal(draft.insertAt, 0);
  assert.equal(draft.generated.addresses.length, 2);
  assert.deepEqual(draft.generated.addresses.map((addr) => addr.cidr), ["192.0.2.10/32", "2001:db8::10/128"]);
  assert.deepEqual(draft.generated.services, [
    {
      name: "udp-53",
      protocol: "PROTOCOL_UDP",
      ports: [{ start: 53 }],
      description: "Created from Troubleshoot explain for udp destination port 53.",
    },
  ]);
  assert.equal(draft.rule.action, "ACTION_DENY");
  assert.equal(draft.rule.log, true);
  assert.deepEqual(draft.rule.fromZones, ["any"]);
  assert.deepEqual(draft.rule.toZones, ["any"]);
  assert.deepEqual(draft.rule.services, ["udp-53"]);
}

{
  assert.equal(recommendedTroubleshootRuleInsertIndex([{ name: "a" }], {}, "ACTION_ALLOW"), 1);
  assert.equal(recommendedTroubleshootRuleInsertIndex([{ name: "a" }], {}, "ACTION_DENY"), 0);
  assert.equal(recommendedTroubleshootRuleInsertIndex([{ name: "a" }, { name: "b" }], { matchedRule: "b", matchedRuleIndex: 1 }, "ACTION_ALLOW"), 1);
}

{
  assert.throws(
    () => buildTroubleshootRuleDraft({}, { srcIp: "10.0.1.20" }, {}, "ACTION_ALLOW"),
    /Source and destination IPs are required/,
  );
}

{
  assert.deepEqual(normalizeTroubleshootCaseContext({
    caseKey: " case:INC-2026-001 ",
    caseAction: "candidate-remediation",
    caseKind: "traffic-flow",
  }), {
    caseKey: "case:INC-2026-001",
    caseAction: "candidate-remediation",
    caseKind: "traffic-flow",
  });
  assert.equal(safeTroubleshootRouteToken("Bearer abc123", 320), "");
  assert.equal(safeTroubleshootRouteToken("/var/log/secret.pcap", 320), "");
  assert.equal(safeTroubleshootRouteToken("x".repeat(321), 320), "");
  assert.deepEqual(normalizeTroubleshootCaptureContext({ captureContext: "log-plan" }), { captureContext: "log-plan" });
  assert.deepEqual(normalizeTroubleshootCaptureContext({ captureContext: "Bearer abc123" }), { captureContext: "" });
  assert.deepEqual(normalizeTroubleshootCaptureContext({ captureContext: "manual" }), { captureContext: "" });
}

{
  const route = normalizeTroubleshootRoute({
    policyVersion: "7",
    fromZone: "inside",
    toZone: "outside",
    srcIp: "10.0.1.20",
    srcPort: "51515",
    destIp: "10.0.2.20",
    destPort: "443",
    protocol: "tcp",
    appId: "web-browsing",
    flowId: "eve-flow-42",
    caseKey: "case:INC-2026-001",
    caseAction: "candidate-remediation",
    caseKind: "traffic-flow",
  });

  assert.deepEqual(route, {
    source: "POLICY_SOURCE_VERSION",
    version: "7",
    fromZone: "inside",
    toZone: "outside",
    protocol: "PROTOCOL_TCP",
    app: "web-browsing",
    src: "10.0.1.20",
    sport: "51515",
    dst: "10.0.2.20",
    dport: "443",
    runtime: true,
    flowId: "eve-flow-42",
    run: false,
    intent: "",
    captureInterface: "any",
    captureDuration: "20",
    capturePackets: "500",
    captureSnaplen: "256",
    captureContext: "",
    caseKey: "case:INC-2026-001",
    caseAction: "candidate-remediation",
    caseKind: "traffic-flow",
  });

  assert.deepEqual(explainQueryFromRouteState(route), {
    policySource: "POLICY_SOURCE_VERSION",
    version: "7",
    fromZone: "inside",
    toZone: "outside",
    srcIp: "10.0.1.20",
    srcPort: 51515,
    destIp: "10.0.2.20",
    destPort: 443,
    protocol: "PROTOCOL_TCP",
    appId: "web-browsing",
    includeRuntime: true,
    flowId: "eve-flow-42",
  });
  assert.equal("caseKey" in explainQueryFromRouteState(route), false);
}

{
  const route = normalizeTroubleshootRoute({
    source: "POLICY_SOURCE_RUNNING",
    version: "7",
    src: "10.0.1.20",
    dst: "10.0.2.20",
  });

  assert.equal(route.source, "POLICY_SOURCE_RUNNING");
  assert.equal(route.version, "7");
  assert.equal(explainQueryFromRouteState(route).policySource, "POLICY_SOURCE_RUNNING");
}

{
  const query = {
    policySource: "POLICY_SOURCE_CANDIDATE",
    version: "0",
    fromZone: "",
    toZone: "",
    srcIp: "10.0.1.20",
    srcPort: 0,
    destIp: "10.0.2.20",
    destPort: 443,
    protocol: "udp",
    appId: "",
    includeRuntime: false,
    flowId: "",
  };

  assert.deepEqual(routeStateFromExplainQuery(query), {
    source: "POLICY_SOURCE_CANDIDATE",
    version: "",
    fromZone: "",
    toZone: "",
    protocol: "PROTOCOL_UDP",
    app: "",
    src: "10.0.1.20",
    sport: "",
    dst: "10.0.2.20",
    dport: "443",
    runtime: false,
    flowId: "",
    run: false,
    intent: "",
    caseKey: "",
    caseAction: "",
    caseKind: "",
    captureInterface: "any",
    captureDuration: "20",
    capturePackets: "500",
    captureSnaplen: "256",
    captureContext: "",
  });
}

{
  const summary = compareDeltaSummary(
    {
      verdict: "EXPLAIN_VERDICT_ALLOWED",
      decisionTerms: [
        "EXPLAIN_DECISION_TERM_ALLOWED",
        "EXPLAIN_DECISION_TERM_PARTIALLY_INSPECTED",
        "EXPLAIN_DECISION_TERM_FAIL_OPEN",
      ],
      inspectionState: "EXPLAIN_INSPECTION_STATE_IPS_PREVENT",
      inspectionProfile: {
        engine: "suricata",
        idsEnabled: true,
        idsMode: "IDS_MODE_PREVENT",
        failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_OPEN",
      },
      routeProfile: { evaluated: true, matched: true, source: "static", destination: "0.0.0.0/0" },
    },
    {
      verdict: "EXPLAIN_VERDICT_DEFAULT_DROP",
      decisionSummary: "blocked",
      inspectionState: "EXPLAIN_INSPECTION_STATE_NOT_INSPECTED",
      inspectionProfile: { idsEnabled: false },
      routeProfile: { evaluated: false, source: "not-evaluated" },
    },
  );

  assert.equal(summary.find((item) => item.key === "verdict").running, "allowed, partially inspected, fail-open");
  assert.equal(summary.find((item) => item.key === "verdict").candidate, "blocked");
  assert.match(summary.find((item) => item.key === "inspection").running, /fail fail open/);
}

{
  const route = normalizeTroubleshootRoute({
    src: "10.0.1.20",
    dst: "10.0.2.20",
    dport: "443",
    run: "1",
    intent: "capture",
  });

  assert.equal(route.run, true);
  assert.equal(route.intent, "capture");
  assert.equal(route.captureInterface, "any");
  assert.equal(route.captureDuration, "20");
  assert.deepEqual(explainQueryFromRouteState(route), {
    policySource: "POLICY_SOURCE_RUNNING",
    version: "0",
    fromZone: "",
    toZone: "",
    srcIp: "10.0.1.20",
    srcPort: 0,
    destIp: "10.0.2.20",
    destPort: 443,
    protocol: "PROTOCOL_TCP",
    appId: "",
    includeRuntime: false,
    flowId: "",
  });
}

{
  const route = normalizeTroubleshootRoute({
    src: "10.0.1.20",
    dst: "10.0.2.20",
    dport: "443",
    run: "1",
    intent: "compare",
    runtime: "1",
  });
  const queries = compareQueriesFromRouteState(route);

  assert.equal(route.run, true);
  assert.equal(route.intent, "compare");
  assert.equal(queries.running.policySource, "POLICY_SOURCE_RUNNING");
  assert.equal(queries.candidate.policySource, "POLICY_SOURCE_CANDIDATE");
  assert.equal(queries.running.destIp, "10.0.2.20");
  assert.equal(queries.candidate.destPort, 443);
  assert.equal(queries.running.includeRuntime, true);
  assert.equal(queries.candidate.includeRuntime, true);
}

{
  const route = normalizeTroubleshootRoute({
    src: "10.0.1.20",
    dst: "10.0.2.20",
    dport: "443",
    run: "1",
    intent: "capture",
    captureContext: "log-plan",
    captureInterface: "eth0;bad",
    captureDuration: "600",
    capturePackets: "0",
    captureSnaplen: "999999",
  });

  assert.equal(route.run, true);
  assert.equal(route.intent, "capture");
  assert.equal(route.captureContext, "log-plan");
  assert.equal(route.captureInterface, "any");
  assert.equal(route.captureDuration, "60");
  assert.equal(route.capturePackets, "1");
  assert.equal(route.captureSnaplen, "4096");
  assert.deepEqual(
    normalizeTroubleshootRoute(route),
    route,
  );
}

{
  const original = explainQueryFromRouteState({ src: "10.0.1.20", dst: "10.0.2.20", dport: "443" });
  const edited = explainQueryFromRouteState({ src: "10.0.1.21", dst: "10.0.2.20", dport: "443" });

  assert.notEqual(troubleshootQueryKey(original), troubleshootQueryKey(edited));
  assert.equal(
    troubleshootQueryKey(original),
    troubleshootQueryKey({
      policySource: "POLICY_SOURCE_RUNNING",
      version: "0",
      srcIp: "10.0.1.20",
      destIp: "10.0.2.20",
      destPort: "443",
      protocol: "TCP",
    }),
  );
}

{
  const queries = compareQueriesFromRouteState({
    source: "POLICY_SOURCE_VERSION",
    version: "99",
    fromZone: "inside",
    toZone: "outside",
    src: "10.0.1.20",
    sport: "51515",
    dst: "10.0.2.20",
    dport: "443",
    protocol: "PROTOCOL_TCP",
    app: "web-browsing",
    runtime: true,
    flowId: "flow-42",
  });

  assert.equal(queries.running.policySource, "POLICY_SOURCE_RUNNING");
  assert.equal(queries.running.version, "0");
  assert.equal(queries.candidate.policySource, "POLICY_SOURCE_CANDIDATE");
  assert.equal(queries.candidate.version, "0");
  for (const side of [queries.running, queries.candidate]) {
    assert.equal(side.fromZone, "inside");
    assert.equal(side.toZone, "outside");
    assert.equal(side.srcIp, "10.0.1.20");
    assert.equal(side.srcPort, 51515);
    assert.equal(side.destIp, "10.0.2.20");
    assert.equal(side.destPort, 443);
    assert.equal(side.protocol, "PROTOCOL_TCP");
    assert.equal(side.appId, "web-browsing");
    assert.equal(side.includeRuntime, true);
    assert.equal(side.flowId, "flow-42");
  }
  assert.equal(
    compareQueryKey(queries),
    compareQueryKey(compareQueriesFromRouteState(queries.running)),
  );
  assert.equal(compareQueryKey(queries), compareQueryKey(compareQueriesFromRouteState({
    ...queries.running,
    caseKey: "case:INC-2026-001",
    caseAction: "candidate-remediation",
    caseKind: "traffic-flow",
  })));
  assert.notEqual(
    compareQueryKey(queries),
    compareQueryKey(compareQueriesFromRouteState({ ...queries.running, srcIp: "10.0.1.21" })),
  );
}

{
  const first = { id: 1, kind: "compare", key: "tuple-a" };
  const second = { id: 2, kind: "explain", key: "tuple-a" };
  assert.equal(isCurrentTroubleshootRequest(first, first, "tuple-a"), true);
  assert.equal(isCurrentTroubleshootRequest(second, first, "tuple-a"), false);
  assert.equal(isCurrentTroubleshootRequest(first, first, "tuple-b"), false);
  assert.equal(isCurrentTroubleshootRequest(null, first, "tuple-a"), false);
}

{
  const running = {
    verdict: "EXPLAIN_VERDICT_ALLOWED",
    matchedRule: "allow-web",
    matchedRuleIndex: 4,
    policySource: "POLICY_SOURCE_RUNNING",
    policyVersion: 7,
    natProfile: {
      destination: { evaluated: true, matched: false },
      source: { evaluated: true, matched: false },
    },
    routeProfile: {
      evaluated: true,
      matched: true,
      destination: "0.0.0.0/0",
      nextHop: "10.0.0.1",
      egressInterface: "eth0",
    },
    inspectionState: "EXPLAIN_INSPECTION_STATE_IDS_DETECT",
    inspectionProfile: {
      idsEnabled: true,
      idsMode: "IDS_MODE_DETECT",
    },
  };
  const candidate = {
    verdict: "EXPLAIN_VERDICT_DENIED",
    matchedRule: "drop-web",
    matchedRuleIndex: 1,
    policySource: "POLICY_SOURCE_CANDIDATE",
    policyVersion: 0,
    natProfile: {
      destination: { evaluated: true, matched: true, matchedRule: "dnat-web" },
      source: { evaluated: true, matched: false },
    },
    routeProfile: {
      evaluated: true,
      matched: true,
      destination: "10.0.2.0/24",
      egressInterface: "eth1",
    },
    inspectionState: "EXPLAIN_INSPECTION_STATE_NOT_INSPECTED",
    inspectionProfile: {
      idsEnabled: false,
      bypassPossible: true,
      bypassReason: "fast path",
    },
  };

  const deltas = compareDeltaSummary(running, candidate);
  assert.deepEqual(deltas.map((delta) => delta.key), ["verdict", "rule", "nat", "route", "inspection"]);
  assert.equal(deltas.find((delta) => delta.key === "verdict").running, "allowed");
  assert.equal(deltas.find((delta) => delta.key === "verdict").candidate, "denied");
  assert.equal(deltas.find((delta) => delta.key === "rule").running, "allow-web (#5)");
  assert.equal(deltas.find((delta) => delta.key === "rule").candidate, "drop-web (#2)");
  assert.match(deltas.find((delta) => delta.key === "inspection").candidate, /not inspected/);
}

{
  assert.deepEqual(compareDeltaSummary(
    {
      verdict: "EXPLAIN_VERDICT_ALLOWED",
      matchedRule: "allow-web",
      matchedRuleIndex: 0,
      routeProfile: { evaluated: true, matched: false, reason: "no route" },
      inspectionState: "EXPLAIN_INSPECTION_STATE_IDS_DETECT",
      inspectionProfile: { idsEnabled: true, idsMode: "IDS_MODE_DETECT" },
    },
    {
      verdict: "EXPLAIN_VERDICT_ALLOWED",
      matchedRule: "allow-web",
      matchedRuleIndex: 0,
      routeProfile: { evaluated: true, matched: false, reason: "no route" },
      inspectionState: "EXPLAIN_INSPECTION_STATE_IDS_DETECT",
      inspectionProfile: { idsEnabled: true, idsMode: "IDS_MODE_DETECT" },
    },
  ), []);
}
