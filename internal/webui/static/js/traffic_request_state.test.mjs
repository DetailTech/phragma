import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  appIdObservationRequestFromState,
  flowRequestFromState,
  normalizeTrafficState,
  sessionKey,
  sessionRequestFromState,
  trafficCaptureRegressionWorkflow,
  trafficWorkflowPacket,
} from "./views/traffic.js";
import { flowHandoffPacket } from "./investigation_packet.js";

const trafficViewSource = readFileSync(new URL("./views/traffic.js", import.meta.url), "utf8");
assert.match(trafficViewSource, /activeInvestigationServerCaseId/);
assert.match(trafficViewSource, /caseEvidencePayloadFromPacket/);
assert.match(trafficViewSource, /api\.addInvestigationCaseEvidence\(activeCaseId, \[caseEvidencePayloadFromPacket\(packet\)\]\)/);
assert.match(trafficViewSource, /Server append unavailable/);
assert.match(trafficViewSource, /Event policy stamp/);
assert.match(trafficViewSource, /Event policy freshness/);
assert.match(trafficViewSource, /unknown event policy stamp/);
assert.match(trafficViewSource, /stale at query time/);

const expectedISO = (value) => new Date(value).toISOString();

{
  const state = normalizeTrafficState({
    mode: "flows",
    q: "dns evidence",
    ip: "10.0.0.15",
    protocol: "TCP",
    app: "ssl",
    port: "443",
    since: "2026-06-19T08:30:00Z",
    until: "2026-06-19T09:45:00Z",
    limit: "1000",
    pageCursor: "2",
    pageStack: "0,1",
    flowId: "eve-flow-123",
    queueId: "queue-should-clear",
    sessionKey: "ct1|ipv4|tcp|10.0.0.15|53000|10.0.0.20|443||||",
  });

  assert.equal(state.queueId, "");
  assert.equal(state.sessionKey, "");
  assert.deepEqual(flowRequestFromState(state), {
    limit: 1000,
    query: "dns evidence",
    ip: "10.0.0.15",
    protocol: "TCP",
    app: "ssl",
    port: "443",
    since: expectedISO("2026-06-19T08:30:00Z"),
    until: expectedISO("2026-06-19T09:45:00Z"),
    flowId: "eve-flow-123",
    pageCursor: "2",
  });
}

{
  const key = sessionKey({
    family: "ipv4",
    protocol: "tcp",
    srcIp: "10.0.0.15",
    srcPort: 53000,
    destIp: "10.0.0.20",
    destPort: 443,
    replySrcIp: "10.0.0.20",
    replySrcPort: 443,
    replyDestIp: "10.0.0.15",
    replyDestPort: 53000,
  });
  const state = normalizeTrafficState({
    mode: "sessions",
    q: "established",
    ip: "10.0.0.15",
    protocol: "UDP",
    port: "53",
    sessionState: "ESTABLISHED",
    limit: "100",
    pageCursor: "4",
    flowId: "flow-should-clear",
    queueId: "queue-should-clear",
    sessionKey: key,
  });

  assert.equal(state.flowId, "");
  assert.equal(state.queueId, "");
  assert.equal(state.sessionKey, key);
  assert.deepEqual(sessionRequestFromState(state), {
    limit: 100,
    query: "established",
    ip: "10.0.0.15",
    protocol: "UDP",
    port: "53",
    state: "ESTABLISHED",
    pageCursor: "4",
  });
}

{
  const state = normalizeTrafficState({
    mode: "app-id",
    q: "unknown app",
    observationKind: "APP_ID_OBSERVATION_KIND_LOW_CONFIDENCE",
    engineSignal: "suricata=http2",
    protocol: "TCP",
    port: "8443",
    confidenceThreshold: "101",
    flowLimit: "750",
    pageCursor: "6",
    pageStack: "0,2,4",
    since: "2026-06-19T10:00:00Z",
    until: "2026-06-19T11:00:00Z",
    limit: "250",
    flowId: "flow-should-clear",
    queueId: "queue-7",
    sessionKey: "ct1|ipv4|tcp|10.0.0.15|53000|10.0.0.20|443||||",
  });

  assert.equal(state.flowId, "");
  assert.equal(state.sessionKey, "");
  assert.equal(state.queueId, "queue-7");
  assert.equal(state.confidenceThreshold, "100");
  assert.deepEqual(appIdObservationRequestFromState(state), {
    limit: 250,
    flowLimit: 750,
    confidenceThreshold: 100,
    query: "unknown app",
    kind: "APP_ID_OBSERVATION_KIND_LOW_CONFIDENCE",
    engineSignal: "suricata=http2",
    protocol: "TCP",
    port: "8443",
    since: expectedISO("2026-06-19T10:00:00Z"),
    until: expectedISO("2026-06-19T11:00:00Z"),
    pageCursor: "6",
  });
}

{
  const state = normalizeTrafficState({
    mode: "flows",
    pageCursor: "../secret",
    pageStack: "0,2,bad,4",
  });

  assert.equal(state.pageCursor, "");
  assert.equal(state.pageStack, "0,2,4");
  assert.deepEqual(flowRequestFromState(state), { limit: 500 });
}

{
  const state = normalizeTrafficState({
    mode: "sessions",
    protocol: "SCTP",
    port: "70000",
    sessionState: "BAD_STATE",
    limit: "250",
    sessionKey: "ct1|bad",
  });

  assert.equal(state.protocol, "");
  assert.equal(state.port, "");
  assert.equal(state.sessionState, "");
  assert.equal(state.limit, "500");
  assert.equal(state.sessionKey, "");
  assert.deepEqual(sessionRequestFromState(state), { limit: 500 });
}

{
  const flow = {
    flowId: "flow-bridge-1",
    srcIp: "10.0.1.10",
    srcPort: 51515,
    destIp: "203.0.113.20",
    destPort: 443,
    protocol: "TCP",
    appId: "unknown",
  };
  const workflow = trafficCaptureRegressionWorkflow(flow, { kind: "flow", caseAction: "flow-capture-regression" });
  assert.match(workflow.captureRoute, /#\/troubleshoot\?/);
  assert.match(workflow.captureRoute, /intent=capture/);
  assert.equal(workflow.captureLimits.durationSeconds, 20);
  assert.equal(workflow.captureLimits.packetCount, 500);
  assert.match(workflow.custodyBoundary, /browser-local/);

  const packet = trafficWorkflowPacket(flowHandoffPacket(flow, { route: "#/traffic?mode=flows&flowId=flow-bridge-1" }), workflow);
  assert.equal(packet.summary.operatorWorkflow.captureRoute, workflow.captureRoute);
  assert.equal(packet.artifacts.operatorWorkflow.caseFocusRoute, packet.summary.operatorWorkflow.caseFocusRoute);
  assert.match(packet.summary.operatorWorkflow.caseFocusRoute, /#\/investigation\?caseKey=flow%3A/);
  assert.ok(packet.evidence.some((line) => line.startsWith("capture_route=#/troubleshoot?")));
  assert.ok(packet.evidence.some((line) => line.includes("workflow_boundary=browser-local")));
}
