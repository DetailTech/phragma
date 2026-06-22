import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  buildNatPreviewHash,
  buildNatPreviewRouteState,
  destinationNatPreviewFlow,
  explainRequestFromFlow,
  natPathCouplingReview,
  natPathDelta,
  natPreviewRouteStateFromFlow,
  normalizeNatPreviewRouteState,
  representativeNatFlow,
  routeProfileLines,
  sourceNatDeleteImpactReview,
  troubleshootHashFromNatPreview,
  troubleshootRouteStateFromNatPreview,
} from "./nat_path_preview.js";

const policy = {
  zones: [{ name: "outside" }, { name: "dmz" }, { name: "inside" }],
  addresses: [
    { name: "public-web", cidr: "203.0.113.10/32" },
    { name: "dmz-web", cidr: "10.0.2.20/32" },
    { name: "inside-net", cidr: "10.0.1.0/24" },
  ],
  services: [{ name: "https", protocol: "PROTOCOL_TCP", ports: [{ start: 443 }] }],
  nat: {
    destination: [{
      name: "public-https",
      fromZone: "outside",
      service: "https",
      destinationAddress: "public-web",
      translatedAddress: "dmz-web",
    }],
  },
};

assert.deepEqual(representativeNatFlow(policy), {
  fromZone: "outside",
  toZone: "dmz",
  srcIp: "198.51.100.10",
  srcPort: "51515",
  destIp: "203.0.113.10",
  destPort: "443",
  protocol: "PROTOCOL_TCP",
});

assert.deepEqual(destinationNatPreviewFlow(policy, policy.nat.destination[0], "inside"), {
  fromZone: "outside",
  toZone: "inside",
  srcIp: "198.51.100.10",
  srcPort: "51515",
  destIp: "203.0.113.10",
  destPort: "443",
  protocol: "PROTOCOL_TCP",
});

assert.deepEqual(explainRequestFromFlow({
  fromZone: "outside",
  toZone: "dmz",
  srcIp: " 198.51.100.9 ",
  srcPort: "51515.9",
  destIp: "203.0.113.10",
  destPort: "443",
  protocol: "PROTOCOL_TCP",
}, "POLICY_SOURCE_RUNNING"), {
  policySource: "POLICY_SOURCE_RUNNING",
  version: "0",
  fromZone: "outside",
  toZone: "dmz",
  srcIp: "198.51.100.9",
  srcPort: 51515,
  destIp: "203.0.113.10",
  destPort: 443,
  protocol: "PROTOCOL_TCP",
  appId: "",
});

assert.deepEqual(normalizeNatPreviewRouteState({
  fromZone: " outside ",
  toZone: " dmz ",
  protocol: "udp",
  src: " 198.51.100.9 ",
  sport: "51515.9",
  dst: " 203.0.113.10 ",
  dport: "8443.7",
  run: "1",
}), {
  fromZone: "outside",
  toZone: "dmz",
  protocol: "PROTOCOL_UDP",
  srcIp: "198.51.100.9",
  srcPort: "51515",
  destIp: "203.0.113.10",
  destPort: "8443",
  run: true,
  caseKey: "",
  caseAction: "",
  caseKind: "",
});

assert.deepEqual(normalizeNatPreviewRouteState({
  protocol: "bogus",
  srcPort: "70000",
  destPort: "-1",
  autoRun: "true",
  caseKey: "nat-path:preview:abc",
  caseAction: "nat-route",
  caseKind: "nat-path",
}), {
  fromZone: "",
  toZone: "",
  protocol: "PROTOCOL_TCP",
  srcIp: "",
  srcPort: "",
  destIp: "",
  destPort: "",
  run: true,
  caseKey: "nat-path:preview:abc",
  caseAction: "nat-route",
  caseKind: "nat-path",
});

assert.equal(normalizeNatPreviewRouteState({ caseKey: "/etc/passwd" }).caseKey, "");

assert.deepEqual(natPreviewRouteStateFromFlow({
  fromZone: "outside",
  toZone: "dmz",
  srcIp: "198.51.100.9",
  srcPort: 51515,
  destIp: "203.0.113.10",
  destPort: "443",
  protocol: "tcp",
}), {
  fromZone: "outside",
  toZone: "dmz",
  protocol: "PROTOCOL_TCP",
  srcIp: "198.51.100.9",
  srcPort: "51515",
  destIp: "203.0.113.10",
  destPort: "443",
  run: false,
  caseKey: "",
  caseAction: "",
  caseKind: "",
});

assert.deepEqual(buildNatPreviewRouteState({
  fromZone: "outside",
  toZone: "dmz",
  srcIp: "198.51.100.9",
  srcPort: 51515,
  destIp: "203.0.113.10",
  destPort: "443",
}, { run: true }), {
  fromZone: "outside",
  toZone: "dmz",
  protocol: "PROTOCOL_TCP",
  srcIp: "198.51.100.9",
  srcPort: "51515",
  destIp: "203.0.113.10",
  destPort: "443",
  run: true,
  caseKey: "",
  caseAction: "",
  caseKind: "",
});

assert.equal(buildNatPreviewHash({
  fromZone: "outside",
  toZone: "dmz",
  protocol: "PROTOCOL_TCP",
  srcIp: "198.51.100.9",
  srcPort: "51515",
  destIp: "203.0.113.10",
  destPort: "443",
  run: true,
}), "#/nat?fromZone=outside&toZone=dmz&srcIp=198.51.100.9&srcPort=51515&destIp=203.0.113.10&destPort=443&run=1");
assert.equal(buildNatPreviewHash({ protocol: "PROTOCOL_TCP" }), "#/nat");

assert.deepEqual(troubleshootRouteStateFromNatPreview({
  fromZone: "outside",
  toZone: "dmz",
  protocol: "PROTOCOL_UDP",
  srcIp: "198.51.100.9",
  srcPort: "51515",
  destIp: "203.0.113.10",
  destPort: "443",
  run: true,
}, { runtime: true, source: "POLICY_SOURCE_RUNNING" }), {
  source: "POLICY_SOURCE_RUNNING",
  fromZone: "outside",
  toZone: "dmz",
  src: "198.51.100.9",
  sport: "51515",
  dst: "203.0.113.10",
  dport: "443",
  protocol: "PROTOCOL_UDP",
  runtime: "1",
  run: "1",
  intent: "explain",
});

assert.equal(
  troubleshootHashFromNatPreview({
    fromZone: "outside",
    toZone: "dmz",
    srcIp: "198.51.100.9",
    srcPort: "51515",
    destIp: "203.0.113.10",
    destPort: "443",
    run: true,
  }, { runtime: true }),
  "#/troubleshoot?source=POLICY_SOURCE_CANDIDATE&fromZone=outside&toZone=dmz&src=198.51.100.9&sport=51515&dst=203.0.113.10&dport=443&protocol=PROTOCOL_TCP&runtime=1&run=1&intent=explain",
);

assert.deepEqual(troubleshootRouteStateFromNatPreview({
  fromZone: "outside",
  toZone: "dmz",
  protocol: "PROTOCOL_TCP",
  srcIp: "198.51.100.9",
  srcPort: "51515",
  destIp: "203.0.113.10",
  destPort: "443",
  run: true,
}, { runtime: true, intent: "compare" }), {
  source: "POLICY_SOURCE_CANDIDATE",
  fromZone: "outside",
  toZone: "dmz",
  src: "198.51.100.9",
  sport: "51515",
  dst: "203.0.113.10",
  dport: "443",
  protocol: "PROTOCOL_TCP",
  runtime: "1",
  run: "1",
  intent: "compare",
});

assert.equal(
  troubleshootHashFromNatPreview({
    fromZone: "outside",
    toZone: "dmz",
    srcIp: "198.51.100.9",
    srcPort: "51515",
    destIp: "203.0.113.10",
    destPort: "443",
    run: true,
  }, { runtime: true, intent: "compare" }),
  "#/troubleshoot?source=POLICY_SOURCE_CANDIDATE&fromZone=outside&toZone=dmz&src=198.51.100.9&sport=51515&dst=203.0.113.10&dport=443&protocol=PROTOCOL_TCP&runtime=1&run=1&intent=compare",
);

const running = {
  verdict: "EXPLAIN_VERDICT_DEFAULT_DROP",
  decisionSummary: "blocked",
  defaultPolicy: true,
  natProfile: {
    destination: { evaluated: true, matched: false },
    source: { evaluated: false, reason: "source NAT not evaluated because policy verdict is default_drop" },
  },
  routeProfile: { evaluated: false, source: "not-evaluated" },
};

const candidate = {
  verdict: "EXPLAIN_VERDICT_ALLOWED",
  decisionTerms: ["EXPLAIN_DECISION_TERM_ALLOWED", "EXPLAIN_DECISION_TERM_FULLY_INSPECTED", "EXPLAIN_DECISION_TERM_FAIL_CLOSED"],
  matchedRule: "allow-public-web",
  matchedRuleIndex: 3,
  natProfile: {
    destination: {
      evaluated: true,
      matched: true,
      matchedRule: "public-https",
      originalDestinationIp: "203.0.113.10",
      originalDestinationPort: 443,
      translatedDestinationIp: "10.0.2.20",
      translatedDestinationPort: 8443,
    },
    source: { evaluated: true, matched: false },
  },
  routeProfile: {
    evaluated: true,
    matched: true,
    source: "static",
    destination: "10.0.2.0/24",
    nextHop: "10.0.2.1",
    egressInterface: "eth1",
    metric: 10,
  },
};

const delta = natPathDelta(running, candidate);
assert.equal(delta.changed, true);
assert.equal(delta.tone, "bad");
assert.equal(delta.headline, "Candidate changes path behavior");
assert.deepEqual(delta.rows.map((row) => [row.label, row.running, row.candidate, row.changed]), [
  ["Decision", "blocked", "allowed, fully inspected, fail-closed", true],
  ["Matched rule", "default policy", "allow-public-web (#4)", true],
  ["DNAT", "no match", "public-https: 203.0.113.10:443 -> 10.0.2.20:8443", true],
  ["SNAT", "not evaluated", "no match", true],
  ["Route", "not evaluated", "10.0.2.0/24", true],
  ["Egress", "-", "via 10.0.2.1 dev eth1", true],
]);

assert.deepEqual(routeProfileLines(candidate.routeProfile), [
  "source: static",
  "destination: 10.0.2.0/24",
  "next hop: 10.0.2.1",
  "interface: eth1",
  "metric: 10",
]);

const coupling = natPathCouplingReview(running, candidate, {
  fromZone: "outside",
  toZone: "dmz",
  srcIp: "198.51.100.9",
  srcPort: "51515",
  destIp: "203.0.113.10",
  destPort: "443",
  protocol: "PROTOCOL_TCP",
  run: true,
});
assert.equal(coupling.changed, true);
assert.equal(coupling.tone, "bad");
assert.match(coupling.summary, /cross policy, NAT, or route/);
assert.deepEqual(coupling.items.map((item) => [item.key, item.label]), [
  ["policy", "Policy decision"],
  ["dnat", "Destination NAT"],
  ["snat", "Source NAT"],
  ["route", "Route and egress"],
]);
assert.ok(coupling.items.find((item) => item.key === "policy")?.href.includes("#/rules?rule=allow-public-web"));
assert.ok(coupling.items.find((item) => item.key === "dnat")?.href.includes("#/nat?"));
assert.ok(coupling.items.find((item) => item.key === "route")?.href.includes("#/netvpn"));
assert.ok(coupling.actions.some((item) => item.key === "troubleshoot" && item.href.includes("#/troubleshoot?")));
assert.ok(coupling.actions.some((item) => item.key === "candidate" && item.href === "#/changes?tab=candidate"));

const sourceDeleteReview = sourceNatDeleteImpactReview({
  zones: [{ name: "inside" }, { name: "dmz" }, { name: "outside" }],
  addresses: [
    { name: "inside-net", cidr: "10.0.1.0/24" },
    { name: "egress-ip", cidr: "198.51.100.25/32" },
  ],
  nat: {
    source: [
      { name: "inside-static", toZone: "outside", sourceAddress: "inside-net", translatedAddress: "egress-ip" },
      { name: "fallback-masq", toZone: "outside", masquerade: true },
    ],
  },
}, { name: "inside-static", toZone: "outside", sourceAddress: "inside-net", translatedAddress: "egress-ip" }, { index: 0 });
assert.equal(sourceDeleteReview.ruleName, "inside-static");
assert.deepEqual(sourceDeleteReview.affectedSourceZones, ["inside", "dmz"]);
assert.equal(sourceDeleteReview.sourceAddress, "inside-net");
assert.equal(sourceDeleteReview.egressZone, "outside");
assert.equal(sourceDeleteReview.translatedAction, "static source egress-ip");
assert.deepEqual(sourceDeleteReview.flow, {
  fromZone: "inside",
  toZone: "outside",
  srcIp: "10.0.1.1",
  srcPort: "51515",
  destIp: "198.51.100.10",
  destPort: "443",
  protocol: "PROTOCOL_TCP",
});
assert.match(sourceDeleteReview.candidateEffect, /fallback-masq/);
assert.equal(sourceDeleteReview.fallbackRule, "fallback-masq");
assert.ok(sourceDeleteReview.previewHash.includes("#/nat?"));
assert.ok(sourceDeleteReview.troubleshootHash.includes("#/troubleshoot?"));
assert.equal(sourceDeleteReview.explainApi.running.policySource, "POLICY_SOURCE_RUNNING");
assert.equal(sourceDeleteReview.explainApi.candidate.policySource, "POLICY_SOURCE_CANDIDATE");
assert.ok(sourceDeleteReview.commands.some((command) => command.includes("ngfwctl explain --source candidate")));
assert.ok(sourceDeleteReview.commands.includes("ngfwctl policy diff"));

const natViewSource = readFileSync(new URL("./views/nat.js", import.meta.url), "utf8");
assert.match(natViewSource, /pinInvestigationPacket/);
assert.match(natViewSource, /function natPathPreviewPacket/);
assert.match(natViewSource, /function pinNatPathHandoff/);
assert.match(natViewSource, /onclick: pinNatPathHandoff/);
assert.match(natViewSource, /Pin to case/);
assert.match(natViewSource, /natCouplingReview/);
assert.match(natViewSource, /natCouplingRow/);
assert.match(natViewSource, /natCouplingAction/);
assert.match(natViewSource, /previewSourceNatRule/);
assert.match(natViewSource, /previewDestinationNatRule/);
assert.match(natViewSource, /type: "button", title: "Add source NAT rule", "aria-label": "Add source NAT rule", dataset: \{ natAction: "add-source" \}/);
assert.match(natViewSource, /type: "button", title: "Add destination NAT rule", "aria-label": "Add destination NAT rule", dataset: \{ natAction: "add-destination" \}/);
assert.match(natViewSource, /dataset: \{ natDestinationEditor: "true" \}/);
assert.match(natViewSource, /type: "button", title: editing \? "Save source NAT rule" : "Add source NAT rule"/);
assert.match(natViewSource, /type: "button", title: editing \? "Save destination NAT rule" : "Add destination NAT rule"/);
assert.match(natViewSource, /type: "button", title: `Delete destination NAT \$\{rule\.name \|\| "entry"\}`/);
assert.match(natViewSource, /dataset: \{ natDeleteSourceReview: "true", natRuleName: review\.ruleName, natMutationSelector: mutation\.selectorKind, natMutationPath: mutation\.path \}/);
assert.match(natViewSource, /function confirmDeleteSourceNat/);
assert.match(natViewSource, /natSourceDeleteAction: "copy-api"/);
assert.match(natViewSource, /natSourceDeleteAction: "copy-cli"/);
assert.match(natViewSource, /natSourceDeleteAction: "troubleshoot"/);
assert.match(natViewSource, /dataset: \{ natDeleteDestinationReview: "true", natMutationSelector: mutation\.selectorKind, natMutationPath: mutation\.path \}/);
assert.match(natViewSource, /natDestinationDeleteAction: "copy-api"/);
assert.match(natViewSource, /natDestinationDeleteAction: "copy-cli"/);
assert.match(natViewSource, /After confirmation, the NAT path preview will run on this same tuple/);
assert.match(natViewSource, /button\("Preview path", "preview", previewRule, "search"\)/);
assert.match(natViewSource, /type: "button",[\s\S]*title,[\s\S]*"aria-label": title,[\s\S]*dataset: \{ natAction: `\$\{action\}-\$\{type\}`/);
assert.match(natViewSource, /validatePendingNatObjects\(session\.draft \|\| \{\}, inputs\.pendingAddresses \|\| \[\], inputs\.pendingServices \|\| \[\]\)/);
assert.match(natViewSource, /No source NAT changes/);
assert.match(natViewSource, /function validateNatServicePorts/);
assert.match(natViewSource, /Service ports invalid/);
