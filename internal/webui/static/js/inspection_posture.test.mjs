import assert from "node:assert/strict";

import { currentInspectionPosture, degradedEngineEvidence, inspectionCoverageForRule, inspectionCoverageMap, inspectionPostureSummary } from "./inspection_posture.js";

{
  const posture = currentInspectionPosture({
    inspection: {
      state: "failed-open",
      detail: "IPS prevent mode is fail-open and Suricata is not active.",
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_OPEN",
      inspectionState: "EXPLAIN_INSPECTION_STATE_BYPASSED",
      engineName: "suricata",
      engineMode: "inline",
      engineState: "failed",
      bypassPossible: true,
      bypassReason: "NFQUEUE unavailable",
      degradedBehavior: "traffic can bypass userspace prevention",
    },
  });

  assert.equal(posture.state, "failed-open");
  assert.equal(posture.cls, "bad");
  assert.equal(posture.engineLabel, "suricata inline failed");
  assert.equal(posture.failureBehavior, "fail-open");
  assert.equal(posture.inspectionState, "bypassed");
  assert.equal(posture.bypassPossible, true);
  assert.match(posture.detail, /NFQUEUE unavailable/);
}

{
  const summary = inspectionPostureSummary({
    inspection: {
      state: "ready",
      detail: "Inspection engine is attached.",
      engineName: "suricata",
      engineMode: "detect",
      engineState: "active",
    },
  });

  assert.equal(summary.state, "ready");
  assert.equal(summary.engine, "suricata detect active");
  assert.match(summary.scope, /handoff time/);
}

{
  const posture = currentInspectionPosture({});

  assert.equal(posture.state, "unknown");
  assert.equal(posture.engineLabel, "inspection engine unavailable");
  assert.equal(posture.bypassPossible, false);
}

{
  const status = {
    capabilities: [
      { name: "Stateful firewall", state: "ready", detail: "nft available" },
      { name: "Degraded engine dataplane evidence", state: "degraded", detail: "suricata=failed vector=failed proxy=not-reported; limitations=no production certification claim" },
    ],
    engines: [
      { name: "suricata", state: "failed", role: "IDS/IPS" },
      { name: "vector", state: "failed", role: "telemetry" },
    ],
    inspection: {
      state: "failed-open",
      detail: "IPS prevent mode is fail-open and Suricata is not active.",
      engineRequired: true,
      engineName: "suricata",
      engineState: "failed",
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_OPEN",
      bypassPossible: true,
    },
  };
  const policy = {
    ids: {
      enabled: true,
      mode: "IDS_MODE_PREVENT",
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_OPEN",
      exceptions: [{ name: "fp-test", signatureId: 9000001 }],
    },
    telemetry: { enabled: true },
    proxy: { virtualServices: [{ name: "admin", enabled: true }] },
    securityProfiles: [{ name: "strict", dnsSecurity: "DNS_SECURITY_MODE_BLOCK_MALICIOUS" }],
  };

  const evidence = degradedEngineEvidence(status, policy);
  assert.equal(evidence.state, "degraded");
  assert.equal(evidence.cls, "bad");
  assert.equal(evidence.degradedRows.length, 3);
  assert.ok(evidence.degradedRows.some((row) => row.name === "IDS/IPS" && row.tone === "bad"));
  assert.ok(evidence.degradedRows.some((row) => row.name === "Telemetry"));
  assert.ok(evidence.degradedRows.some((row) => row.name === "proxy" && row.state === "not-reported"));
  assert.match(evidence.impact.join(" "), /1 active false-positive exception/);
  assert.match(evidence.impact.join(" "), /1 blocking security profile/);
  assert.match(evidence.limitations.join(" "), /No signed field evidence/);
}

{
  const policy = {
    network: { enableFlowOffload: true },
    ids: { enabled: true, mode: "IDS_MODE_DETECT" },
    rules: [
      { name: "allow-web", action: "ACTION_ALLOW", fromZones: ["lan"], toZones: ["wan"] },
      { name: "drop-admin", action: "ACTION_DENY", fromZones: ["wan"], toZones: ["lan"] },
    ],
  };
  const allow = inspectionCoverageForRule(policy, policy.rules[0]);
  const drop = inspectionCoverageForRule(policy, policy.rules[1]);

  assert.equal(allow.state, "bypass-risk");
  assert.equal(allow.cls, "bad");
  assert.equal(allow.bypassPossible, true);
  assert.equal(drop.state, "pre-filter-drop");

  const map = inspectionCoverageMap(policy, {
    inspection: {
      state: "ready",
      detail: "Suricata is attached.",
    },
  });
  assert.equal(map.totalRules, 2);
  assert.equal(map.activeAllowRules, 1);
  assert.equal(map.riskCount, 1);
  assert.match(map.summary.label, /1 risk/);
  assert.ok(map.buckets.some((bucket) => bucket.state === "bypass-risk" && bucket.examples.includes("allow-web")));
}

{
  const policy = {
    securityProfiles: [
      { name: "strict-web", tlsInspection: "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED" },
    ],
    ids: {
      enabled: true,
      mode: "IDS_MODE_PREVENT",
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
    },
    rules: [
      { name: "allow-strict-web", action: "ACTION_ALLOW", securityProfiles: ["strict-web"] },
    ],
  };

  const coverage = inspectionCoverageForRule(policy, policy.rules[0]);
  assert.equal(coverage.state, "profile-enforced");
  assert.equal(coverage.cls, "ok");
  assert.equal(coverage.bypassPossible, false);

  const map = inspectionCoverageMap(policy, {});
  assert.equal(map.summary.label, "covered");
  assert.equal(map.riskCount, 0);
  assert.equal(map.warningCount, 0);
}

{
  const policy = {
    securityProfiles: [
      { name: "strict-web", dnsSecurity: "DNS_SECURITY_MODE_BLOCK_MALICIOUS" },
    ],
    ids: {
      enabled: true,
      mode: "IDS_MODE_PREVENT",
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_OPEN",
    },
    rules: [
      { name: "allow-strict-web", action: "ACTION_ALLOW", securityProfiles: ["strict-web"] },
    ],
  };

  const coverage = inspectionCoverageForRule(policy, policy.rules[0]);
  assert.equal(coverage.state, "profile-needs-fail-closed");
  assert.equal(coverage.cls, "bad");
  assert.equal(coverage.bypassPossible, true);

  const map = inspectionCoverageMap(policy, {
    inspection: {
      state: "failed-open",
      bypassPossible: true,
      bypassReason: "NFQUEUE unavailable",
    },
  });
  assert.equal(map.runtimeBypass, true);
  assert.equal(map.summary.label, "runtime bypass");
  assert.match(map.summary.detail, /NFQUEUE unavailable/);
}
