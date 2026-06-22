import assert from "node:assert/strict";

import { normalizeTrafficState, sessionKey } from "./views/traffic.js";
import { normalizeThreatState } from "./views/threats.js";

const invalidTraffic = normalizeTrafficState({ mode: "bad", limit: "9999", protocol: "SCTP", port: "70000" });
assert.deepEqual(pick(invalidTraffic, ["mode", "limit", "protocol", "port"]), {
  mode: "flows",
  limit: "500",
  protocol: "",
  port: "",
});

const invalidObservation = normalizeTrafficState({ mode: "app-id", limit: "1000", observationKind: "bad", confidenceThreshold: "999" });
assert.deepEqual(pick(invalidObservation, ["mode", "limit", "observationKind", "confidenceThreshold"]), {
  mode: "app-id",
  limit: "100",
  observationKind: "",
  confidenceThreshold: "100",
});

const liveSessionKey = "ct1|ipv4|tcp|10.0.1.20|51515|203.0.113.20|443|203.0.113.20|443|10.0.1.20|51515";
const normalizedSessionSelection = normalizeTrafficState({
  mode: "sessions",
  flowId: "eve-flow-42",
  queueId: "appid-42",
  sessionKey: liveSessionKey.toUpperCase(),
});
assert.deepEqual(pick(normalizedSessionSelection, ["mode", "flowId", "queueId", "sessionKey"]), {
  mode: "sessions",
  flowId: "",
  queueId: "",
  sessionKey: liveSessionKey,
});

const normalizedFlowSelection = normalizeTrafficState({
  mode: "flows",
  flowId: "eve-flow-42",
  queueId: "appid-42",
  sessionKey: liveSessionKey,
});
assert.deepEqual(pick(normalizedFlowSelection, ["mode", "flowId", "queueId", "sessionKey"]), {
  mode: "flows",
  flowId: "eve-flow-42",
  queueId: "",
  sessionKey: "",
});
assert.equal(normalizeTrafficState({ mode: "flows", flowId: "eve-flow-42\u0000" }).flowId, "");
assert.equal(normalizeTrafficState({ mode: "flows", flowId: "x".repeat(129) }).flowId, "");
assert.deepEqual(pick(normalizeTrafficState({
  mode: "app-id",
  queueId: "appid-42",
  caseKey: "alert:flow-77:abc",
  caseAction: "app-id",
  caseKind: "alert",
}), ["caseKey", "caseAction", "caseKind"]), {
  caseKey: "alert:flow-77:abc",
  caseAction: "app-id",
  caseKind: "alert",
});
assert.equal(normalizeTrafficState({ caseKey: "token=secret" }).caseKey, "");

const normalizedObservationSelection = normalizeTrafficState({
  mode: "app-id",
  flowId: "eve-flow-42",
  queueId: "appid-42",
  sessionKey: liveSessionKey,
});
assert.deepEqual(pick(normalizedObservationSelection, ["mode", "flowId", "queueId", "sessionKey"]), {
  mode: "app-id",
  flowId: "",
  queueId: "appid-42",
  sessionKey: "",
});

assert.equal(normalizeTrafficState({ mode: "sessions", sessionKey: "ct1|bad" }).sessionKey, "");
assert.equal(normalizeTrafficState({ mode: "sessions", sessionKey: "ct1|ipv4|tcp|10.0.1.20|bad|203.0.113.20|443|203.0.113.20|443|10.0.1.20|51515" }).sessionKey, "");
assert.equal(normalizeTrafficState({ mode: "sessions", sessionKey: "ct1|ipv4|tcp|10.0.1.20|51515|203.0.113.20|443|203.0.113.20|443|10.0.1.20|51515\u0000" }).sessionKey, "");

const baseSession = {
  family: "IPv4",
  protocol: "TCP",
  srcIp: "10.0.1.20",
  srcPort: 51515,
  destIp: "203.0.113.20",
  destPort: 443,
  replySrcIp: "203.0.113.20",
  replySrcPort: 443,
  replyDestIp: "10.0.1.20",
  replyDestPort: 51515,
  state: "ESTABLISHED",
  packets: 10,
  bytes: 4096,
  timeoutSeconds: 300,
  raw: "first observation",
};
assert.equal(sessionKey(baseSession), liveSessionKey);
assert.equal(sessionKey({
  ...baseSession,
  state: "TIME_WAIT",
  packets: 999,
  bytes: 999999,
  timeoutSeconds: 1,
  raw: "updated counters should not change identity",
}), liveSessionKey);

const invalidThreat = normalizeThreatState({ action: "drop", protocol: "SCTP", threatSeverity: "urgent", sev: 99, signatureId: "-1", port: "0", limit: "5000" });
assert.deepEqual(pick(invalidThreat, ["action", "protocol", "threatSeverity", "sev", "signatureId", "port", "limit"]), {
  action: "",
  protocol: "",
  threatSeverity: "",
  sev: 0,
  signatureId: "",
  port: "",
  limit: "500",
});
assert.equal(normalizeThreatState({ flowId: "eve-flow-42" }).flowId, "eve-flow-42");
assert.equal(normalizeThreatState({ flowId: "eve-flow-42\u0000" }).flowId, "");
assert.deepEqual(pick(normalizeThreatState({
  flowId: "eve-flow-42",
  caseKey: "alert:flow-77:abc",
  caseAction: "threat-exception",
  caseKind: "alert",
}), ["caseKey", "caseAction", "caseKind"]), {
  caseKey: "alert:flow-77:abc",
  caseAction: "threat-exception",
  caseKind: "alert",
});
assert.equal(normalizeThreatState({ caseKey: "file:/tmp/capture.pcap" }).caseKey, "");

function pick(obj, keys) {
  return Object.fromEntries(keys.map((key) => [key, obj[key]]));
}
