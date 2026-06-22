import assert from "node:assert/strict";

import { alertRequestFromState, normalizeThreatState, threatReplayRequestFromState } from "./views/threats.js";

const expectedISO = (value) => new Date(value).toISOString();

{
  const state = normalizeThreatState({
    q: "probe",
    sev: "2",
    action: "blocked",
    ip: "10.0.1.10",
    protocol: "TCP",
    signatureId: "9000001",
    threatSeverity: "high",
    port: "8443",
    since: "2026-06-19T08:00:00Z",
    until: "2026-06-19T09:00:00Z",
    limit: "1000",
    pageCursor: "3",
    pageStack: "0,1,2",
    flowId: "flow-a",
  });

  assert.deepEqual(alertRequestFromState(state), {
    limit: 1000,
    query: "probe",
    ip: "10.0.1.10",
    protocol: "TCP",
    action: "blocked",
    severity: "2",
    threatSeverity: "high",
    signatureId: "9000001",
    port: "8443",
    since: expectedISO("2026-06-19T08:00:00Z"),
    until: expectedISO("2026-06-19T09:00:00Z"),
    flowId: "flow-a",
    pageCursor: "3",
  });
}

{
  const state = normalizeThreatState({
    action: "drop-all",
    protocol: "SCTP",
    signatureId: "sid900",
    port: "70000",
    threatSeverity: "emergency",
    limit: "50",
    pageCursor: "../../etc/passwd",
    pageStack: "0,bad,2",
  });

  assert.equal(state.action, "");
  assert.equal(state.protocol, "");
  assert.equal(state.signatureId, "");
  assert.equal(state.port, "");
  assert.equal(state.threatSeverity, "");
  assert.equal(state.limit, "500");
  assert.equal(state.pageCursor, "");
  assert.equal(state.pageStack, "0,2");
  assert.deepEqual(alertRequestFromState(state), { limit: 500 });
}

{
  const state = normalizeThreatState({
    q: "exploit",
    action: "blocked",
    signatureId: "9000001",
    threatSeverity: "critical",
    flowId: "flow-a",
    limit: "1000",
  });
  assert.deepEqual(threatReplayRequestFromState(state), {
    recentAlerts: {
      limit: 25,
      query: "exploit",
      action: "blocked",
      signatureId: 9000001,
      threatSeverity: "critical",
      flowId: "flow-a",
    },
  });
}
