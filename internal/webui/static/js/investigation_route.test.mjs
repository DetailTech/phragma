import assert from "node:assert/strict";

import {
  investigationHashFromAlert,
  investigationHashFromFlow,
  investigationRouteFromAlert,
  investigationRouteFromFlow,
} from "./investigation_route.js";

{
  const flow = {
    srcIp: "10.0.1.20",
    srcPort: "51515",
    destIp: "10.0.2.20",
    destPort: 443,
    protocol: "tcp",
    appId: "web-browsing",
    flowId: "eve-flow-42",
    policyVersionKnown: true,
    policyVersion: 7,
  };
  const route = investigationRouteFromFlow(flow, { intent: "capture" });

  assert.deepEqual(route, {
    src: "10.0.1.20",
    sport: "51515",
    dst: "10.0.2.20",
    dport: "443",
    protocol: "PROTOCOL_TCP",
    app: "web-browsing",
    flowId: "eve-flow-42",
    source: "POLICY_SOURCE_VERSION",
    version: "7",
    runtime: "1",
    run: "1",
    intent: "capture",
  });

  const hash = investigationHashFromFlow(flow);
  assert.equal(hash.startsWith("#/troubleshoot?"), true);
  assert.match(hash, /run=1/);
  assert.match(hash, /intent=explain/);
  assert.match(hash, /source=POLICY_SOURCE_VERSION/);
}

{
  const route = investigationRouteFromFlow({
    srcIp: "10.0.1.20",
    destIp: "10.0.2.20",
    protocol: "tcp",
    policyVersionKnown: false,
    policyVersion: 9,
  });
  assert.equal(route.source, undefined);
  assert.equal(route.version, undefined);
}

{
  const alert = {
    srcIp: "10.0.3.10",
    srcPort: 44444,
    destIp: "10.0.4.20",
    destPort: "53",
    protocol: "PROTOCOL_UDP",
    appId: "unknown",
    flowId: "alert-flow-1",
    policyVersionKnown: true,
    policyVersion: 11,
  };
  const route = investigationRouteFromAlert(alert, { intent: "capture" });

  assert.deepEqual(route, {
    src: "10.0.3.10",
    sport: "44444",
    dst: "10.0.4.20",
    dport: "53",
    protocol: "PROTOCOL_UDP",
    flowId: "alert-flow-1",
    source: "POLICY_SOURCE_VERSION",
    version: "11",
    runtime: "1",
    run: "1",
    intent: "capture",
  });

  const hash = investigationHashFromAlert(alert, { intent: "capture" });
  const params = new URLSearchParams(hash.split("?")[1]);
  assert.equal(params.get("protocol"), "PROTOCOL_UDP");
  assert.equal(params.get("intent"), "capture");
  assert.equal(params.get("app"), null);
}
