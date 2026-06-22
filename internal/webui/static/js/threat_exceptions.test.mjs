import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  alertCliCommandFromRequest,
  alertRequestFromState,
  baseExceptionName,
  cleanName,
  normalizeThreatState,
  signatureID,
  stageThreatExceptionRequest,
  stageThreatExceptionDraft,
  threatExceptionStageResultModel,
  threatExceptionMutationResultModel,
  threatExceptionRecordModel,
  threatExceptionRegressionBridge,
  threatExceptionUpdateRequest,
  threatExceptionWorkbenchModel,
  threatAlertOperatorWorkflow,
  threatDropRulePlan,
  threatWorkflowPacket,
  threatPackageProvenanceFromAlert,
  threatPackageSummary,
  threatExceptionDraftPreview,
  threatSeverity,
  uniqueName,
} from "./views/threats.js";
import { alertHandoffPacket } from "./investigation_packet.js";
import { applyIdsProfilePreset, buildIdsEditorCandidate, idsEditorFormValues, idsRolloutActions, idsProfileSummary } from "./views/ids.js";
import { alertAction } from "./format.js";

const threatsViewSource = readFileSync(new URL("./views/threats.js", import.meta.url), "utf8");
const rulesViewSource = readFileSync(new URL("./views/rules.js", import.meta.url), "utf8");
assert.match(threatsViewSource, /buildInvestigationPacket/);
assert.match(threatsViewSource, /type: "button", title: "Explain this threat alert"/);
assert.match(threatsViewSource, /title: "Open packet capture audit for this threat alert"/);
assert.match(threatsViewSource, /title: "Pin threat alert handoff to investigation case"/);
assert.match(threatsViewSource, /Package provenance/);
assert.match(threatsViewSource, /Package manifest/);
assert.match(threatsViewSource, /threatHandoffAction: "copy-handoff"/);
assert.match(threatsViewSource, /activeInvestigationServerCaseId/);
assert.match(threatsViewSource, /caseEvidencePayloadFromPacket/);
assert.match(threatsViewSource, /api\.addInvestigationCaseEvidence\(activeCaseId, \[caseEvidencePayloadFromPacket\(packet\)\]\)/);
assert.match(threatsViewSource, /Server append unavailable/);
assert.match(threatsViewSource, /title: `Edit threat exception \$\{model\.name\}`/);
assert.match(threatsViewSource, /title: `Remove threat exception \$\{model\.name\}`/);
assert.match(threatsViewSource, /title: "Open threat exception API and CLI context"/);
assert.match(threatsViewSource, /title: "Review threat exception candidate changes"/);
assert.match(threatsViewSource, /function threatExceptionBridgePanel/);
assert.match(threatsViewSource, /dataset: \{ threatRegressionBridge: "exception" \}/);
assert.match(threatsViewSource, /title: "Review Threat-ID content quality evidence"/);
assert.match(threatsViewSource, /title: "Review Threat-ID canary and false-positive telemetry"/);
assert.match(threatsViewSource, /title: `Stage edit for threat exception \$\{model\.name\}`/);
assert.match(threatsViewSource, /title: `\$\{actionLabel\(action\)\} threat exception \$\{model\.name\}`/);
assert.match(threatsViewSource, /type: "button", title: "Stage false-positive exception"/);
assert.match(threatsViewSource, /title: "Back to threat detail"/);
assert.match(threatsViewSource, /function pinThreatCaseRemediation/);
assert.match(threatsViewSource, /function threatCaseRemediationPacket/);
assert.match(threatsViewSource, /kind: "candidate-remediation"/);
assert.match(threatsViewSource, /caseKey: state\.caseKey/);
assert.match(threatsViewSource, /changesRoute: "#\/changes\?tab=candidate"/);
assert.match(threatsViewSource, /sourceWorkspace: "threats"/);
assert.match(threatsViewSource, /mode: "drop-source"/);
assert.match(rulesViewSource, /function pinPrefilledCaseRemediation/);
assert.match(rulesViewSource, /function prefilledRuleRemediationPacket/);
assert.match(rulesViewSource, /opts\.caseContext\?\.caseKey/);

assert.deepEqual(alertRequestFromState({
  limit: "1000",
  q: "cve-2026",
  ip: "10.0.1.10",
  protocol: "TCP",
  action: "blocked",
  sev: 2,
  threatSeverity: "high",
  signatureId: "9000001",
  port: "443",
  flowId: "flow-123",
}), {
  limit: 1000,
  query: "cve-2026",
  ip: "10.0.1.10",
  protocol: "TCP",
  action: "blocked",
  severity: "2",
  threatSeverity: "high",
  signatureId: "9000001",
  port: "443",
  flowId: "flow-123",
});

assert.equal(
  alertCliCommandFromRequest({ limit: 100, query: "web shell", ip: "10.0.1.10", protocol: "TCP", action: "blocked", severity: "2", threatSeverity: "high", signatureId: "9000001", port: "443", flowId: "flow-123" }),
  "ngfwctl alerts --limit 100 --query \"web shell\" --ip 10.0.1.10 --protocol TCP --action blocked --severity 2 --threat-severity high --signature-id 9000001 --port 443 --flow-id flow-123",
);
assert.equal(normalizeThreatState({ flowId: " flow-123 " }).flowId, "flow-123");
assert.equal(normalizeThreatState({ flowId: "flow-123\u0000" }).flowId, "");
assert.equal(normalizeThreatState({ view: "exceptions", exception: " FP Running " }).view, "exceptions");
assert.equal(normalizeThreatState({ view: "exceptions", exception: " FP Running " }).exception, "fp-running");
assert.equal(normalizeThreatState({ view: "bogus", exception: "fp-running" }).exception, "");

assert.equal(cleanName(" FP:9000001 Source 10.0.1.10 "), "fp-9000001-source-10-0-1-10");
assert.equal(uniqueName([{ name: "fp-1" }, { name: "fp-1-2" }], "fp-1"), "fp-1-3");
assert.equal(signatureID({ signatureId: "9000001" }), 9000001);
assert.equal(signatureID({ signatureId: "0" }), 0);
assert.equal(alertAction("blocked").cls, "bad");
assert.equal(alertAction("allowed").cls, "warn");
assert.deepEqual(threatSeverity({ threatSeverity: "critical" }), { label: "Critical", cls: "bad", n: 1 });
assert.deepEqual(threatSeverity({ threatSeverity: "high" }), { label: "High", cls: "warn", n: 2 });
assert.deepEqual(threatSeverity({ threatSeverity: "medium" }), { label: "Medium", cls: "info", n: 3 });
assert.deepEqual(threatSeverity({ threatSeverity: "low" }), { label: "Low", cls: "neutral", n: 4 });

assert.deepEqual(threatPackageProvenanceFromAlert({
  threatEvidence: [
    "engine signal suricata.signature_id=9000001",
    `signed Threat-ID package 7.8.9@${"b".repeat(64)}`,
  ],
}), {
  version: "7.8.9",
  manifestSha256: "b".repeat(64),
  manifestShort: "bbbbbbbbbbbbbbbb",
  label: "package 7.8.9 · manifest bbbbbbbbbbbbbbbb",
});
assert.equal(threatPackageProvenanceFromAlert({
  threatEvidence: ["signed Threat-ID package /var/lib/openngfw/content/threat-id"],
}).label, "");

{
  const bridge = threatExceptionRegressionBridge({
    name: "fp-9000001-source",
    signatureId: 9000001,
    pcapSha256: "a".repeat(64),
    regressionRef: "evidence/fp-regression.json",
  }, {
    surfaces: [{
      kind: "threat-id",
      name: "Phragma Threat-ID catalog",
      version: "2.0.0",
      state: "verified",
      signatureStatus: "verified",
      regressionStatus: "passed",
      rolloutState: "canary",
      rollbackAvailable: true,
      provenance: [{ name: "Phragma", license: "Apache-2.0" }],
      blockers: [],
      contentReadinessEvidence: [
        { type: "pcap-regression-corpus", artifact: "evidence/pcap-regression.json", sha256: "b".repeat(64), sha256Short: "b".repeat(12) },
        { type: "false-positive-regression", artifact: "evidence/fp-regression.json", sha256: "c".repeat(64), sha256Short: "c".repeat(12) },
      ],
      keyContentReadinessEvidence: {
        pcapRegressionCorpus: { type: "pcap-regression-corpus", artifact: "evidence/pcap-regression.json", sha256Short: "b".repeat(12) },
        falsePositiveRegression: { type: "false-positive-regression", artifact: "evidence/fp-regression.json", sha256Short: "c".repeat(12) },
      },
      falsePositiveTelemetry: {
        signals: [{ label: "canary FP", status: "clean", count: 0 }],
      },
      canaryScopes: [{ name: "branch", exposure: 5, status: "healthy" }],
      decision: { cls: "ok", checks: [], blockers: [] },
    }],
  });
  assert.equal(bridge.hasExceptionEvidence, true);
  assert.equal(bridge.pcapSha256, "a".repeat(64));
  assert.equal(bridge.pcapCorpus, `evidence/pcap-regression.json · sha256:${"b".repeat(12)}`);
  assert.equal(bridge.falsePositiveCorpus, `evidence/fp-regression.json · sha256:${"c".repeat(12)}`);
  assert.equal(bridge.canarySignals, "2");
  assert.equal(bridge.canaryScopes, "1");
  assert.equal(bridge.routes.contentQuality, "#/intel?surface=threat-id&drawer=quality");
  assert.equal(bridge.routes.canary, "#/intel?surface=threat-id&drawer=canary");
  assert.match(bridge.routes.pcapAudit, /#\/changes\?tab=audit&action=packet-capture&query=/);
  assert.match(bridge.boundary, /candidate workflows/);
}

{
  const alert = {
    flowId: "flow-threat-1",
    srcIp: "10.0.1.10",
    srcPort: 51515,
    destIp: "203.0.113.20",
    destPort: 443,
    protocol: "TCP",
    signatureId: "9000001",
    threatId: "suricata-sid-9000001",
    signature: "ET TEST Malware",
    pcapSha256: "d".repeat(64),
    regressionRef: "evidence/fp-regression.json",
  };
  const workflow = threatAlertOperatorWorkflow(alert, {});
  assert.match(workflow.captureRoute, /#\/troubleshoot\?/);
  assert.match(workflow.captureRoute, /intent=capture/);
  assert.match(workflow.captureAuditRoute, /#\/changes\?tab=audit&action=packet-capture/);
  assert.equal(workflow.exceptionRoute, "#/threats?view=exceptions&signatureId=9000001&flowId=flow-threat-1&ip=10.0.1.10&protocol=TCP&port=443&limit=100");
  assert.match(workflow.custodyBoundary, /browser-local/);

  const packet = threatWorkflowPacket(alertHandoffPacket(alert, { route: "#/threats?alert=flow-threat-1" }), workflow);
  assert.equal(packet.summary.operatorWorkflow.captureRoute, workflow.captureRoute);
  assert.equal(packet.artifacts.operatorWorkflow.caseFocusRoute, packet.summary.operatorWorkflow.caseFocusRoute);
  assert.match(packet.summary.operatorWorkflow.caseFocusRoute, /#\/investigation\?caseKey=alert%3A/);
  assert.ok(packet.evidence.some((line) => line.startsWith("capture_route=#/troubleshoot?")));
  assert.ok(packet.evidence.some((line) => line.includes("workflow_boundary=browser-local")));
}

{
  const policy = { addresses: [] };
  const before = structuredClone(policy);
  const plan = threatDropRulePlan(policy, {
    srcIp: "10.0.1.10",
    signature: "ET TEST Malware",
    threatId: "suricata-sid-9000001",
  });
  assert.deepEqual(policy, before);
  assert.equal(plan.rule.name, "drop-10-0-1-10");
  assert.deepEqual(plan.rule.sourceAddresses, ["threat-10-0-1-10"]);
  assert.equal(plan.rule.action, "ACTION_DENY");
  const draft = structuredClone(policy);
  plan.beforeSave(draft);
  assert.deepEqual(draft.addresses, [{ name: "threat-10-0-1-10", cidr: "10.0.1.10/32", description: "Auto-added from threat alert" }]);
}

{
  const policy = { addresses: [{ name: "known-attacker", cidr: "10.0.1.10/32" }] };
  const before = structuredClone(policy);
  const plan = threatDropRulePlan(policy, { srcIp: "10.0.1.10", signature: "Known attacker" });
  assert.deepEqual(policy, before);
  assert.deepEqual(plan.rule.sourceAddresses, ["known-attacker"]);
  const draft = structuredClone(policy);
  plan.beforeSave(draft);
  assert.deepEqual(draft, before);
}

{
  const summary = idsProfileSummary({}, {});
  assert.equal(summary.status, "disabled");
  assert.equal(summary.cls, "neutral");
  assert.equal(summary.changed, false);
  assert.equal(summary.stateLabel, "running");
  assert.equal(summary.exceptionCounts.label, "0 active / 0 total");
}

{
  const summary = idsProfileSummary({
    enabled: true,
    mode: "IDS_MODE_DETECT",
    monitorInterfaces: ["wan0", "lan0"],
    homeNetworks: ["10.0.0.0/8"],
    ruleFiles: ["emerging-threats.rules"],
    exceptions: [
      { name: "fp-active", signatureId: 9000001 },
      { name: "fp-disabled", signatureId: 9000002, disabled: true },
    ],
  }, {});
  assert.equal(summary.status, "detect");
  assert.equal(summary.cls, "info");
  assert.equal(summary.changed, true);
  assert.equal(summary.stateLabel, "candidate-only");
  assert.match(summary.deltaLabel, /disabled -> Detect/);
  assert.match(summary.deltaLabel, /exceptions 0 active \/ 0 total -> 1 active \/ 2 total/);
  assert.equal(summary.monitorInterfacesLabel, "wan0, lan0");
  assert.equal(summary.homeNetworksLabel, "10.0.0.0/8");
  assert.equal(summary.ruleFilesLabel, "emerging-threats.rules");
  assert.deepEqual(summary.exceptionCounts, { total: 2, active: 1, disabled: 1, label: "1 active / 2 total" });
}

{
  const summary = idsProfileSummary({
    enabled: true,
    mode: "IDS_MODE_PREVENT",
  }, {});
  assert.equal(summary.status, "incomplete");
  assert.equal(summary.cls, "warn");
  assert.match(summary.detail, /failure behavior/);
}

{
  const summary = idsProfileSummary({
    enabled: true,
    mode: "IDS_MODE_PREVENT",
    queueNum: 7,
    failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
  }, {
    enabled: true,
    mode: "IDS_MODE_PREVENT",
    queueNum: 7,
    failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
  });
  assert.equal(summary.status, "prevent");
  assert.equal(summary.cls, "bad");
  assert.equal(summary.changed, false);
  assert.equal(summary.failureBehaviorLabel, "Fail closed");
  assert.equal(summary.queueLabel, "7");
}

{
  const summary = idsProfileSummary({}, {
    enabled: true,
    mode: "IDS_MODE_DETECT",
    exceptions: [{ name: "fp-running", signatureId: 9000001 }],
  });
  assert.equal(summary.status, "disabled");
  assert.equal(summary.cls, "warn");
  assert.equal(summary.changed, true);
  assert.match(summary.deltaLabel, /Detect \(IDS\) -> disabled/);
  assert.match(summary.deltaLabel, /exceptions 1 active \/ 1 total -> 0 active \/ 0 total/);
}

{
  const summary = idsProfileSummary({
    enabled: true,
    mode: "IDS_MODE_DETECT",
  }, {}, {
    available: true,
    blockerCount: 2,
    cls: "bad",
  });
  assert.equal(summary.status, "package blocked");
  assert.equal(summary.cls, "bad");
  assert.equal(summary.packageBlocked, true);
  assert.match(summary.detail, /2 production gates/);
}

{
  const policy = {
    ids: {
      enabled: true,
      mode: "IDS_MODE_PREVENT",
      queueNum: 4,
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
      monitorInterfaces: ["wan0"],
      homeNetworks: ["10.0.0.0/8"],
      ruleFiles: ["managed.rules"],
      exceptions: [{ name: "fp-active", signatureId: 9000001, description: "lab" }],
    },
  };
  applyIdsProfilePreset(policy, "detect");
  assert.deepEqual(policy.ids, {
    enabled: true,
    mode: "IDS_MODE_DETECT",
    monitorInterfaces: ["wan0"],
    homeNetworks: ["10.0.0.0/8"],
    ruleFiles: ["managed.rules"],
    exceptions: [{ name: "fp-active", disabled: false, signatureId: 9000001, threatId: "", sourceAddress: "", destinationAddress: "", description: "lab" }],
  });
}

{
  const policy = { ids: { enabled: true, mode: "IDS_MODE_DETECT", queueNum: 7 } };
  applyIdsProfilePreset(policy, "prevent-fail-open");
  assert.equal(policy.ids.enabled, true);
  assert.equal(policy.ids.mode, "IDS_MODE_PREVENT");
  assert.equal(policy.ids.queueNum, 0);
  assert.equal(policy.ids.failureBehavior, "IDS_FAILURE_BEHAVIOR_FAIL_OPEN");
  applyIdsProfilePreset(policy, "prevent-fail-closed");
  assert.equal(policy.ids.failureBehavior, "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED");
}

{
  const policy = { ids: { enabled: true, mode: "IDS_MODE_PREVENT", queueNum: 2, failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_OPEN" } };
  applyIdsProfilePreset(policy, "disable");
  assert.deepEqual(policy.ids, {
    enabled: false,
    monitorInterfaces: [],
    homeNetworks: [],
    ruleFiles: [],
  });
}

{
  const actions = idsRolloutActions({}, {}, { available: true, blockerCount: 2 });
  assert.equal(actions.find((action) => action.key === "detect").disabled, false);
  const prevent = actions.find((action) => action.key === "prevent-fail-closed");
  assert.equal(prevent.disabled, true);
  assert.match(prevent.disabledReason, /2 Threat-ID package gates/);
}

{
  const actions = idsRolloutActions({}, {}, { available: true, blockerCount: 0, version: "1.2.3" });
  assert.equal(actions.find((action) => action.key === "prevent-fail-open").disabled, false);
  assert.equal(actions.find((action) => action.key === "prevent-fail-closed").disabled, false);
}

{
  const form = idsEditorFormValues({
    enabled: true,
    mode: "IDS_MODE_PREVENT",
    monitorInterfaces: "wan0, lan0",
    homeNetworks: "10.0.0.0/8, 192.168.0.0/16",
    ruleFiles: "managed.rules, local.rules",
    queueNum: "7",
    failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
    exceptions: [{ name: "fp-active", signatureId: 9000001, description: "lab" }],
  });
  assert.deepEqual(form, {
    enabled: true,
    mode: "IDS_MODE_PREVENT",
    monitorInterfaces: ["wan0", "lan0"],
    homeNetworks: ["10.0.0.0/8", "192.168.0.0/16"],
    ruleFiles: ["managed.rules", "local.rules"],
    queueNum: 7,
    failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
    exceptions: [{ name: "fp-active", disabled: false, signatureId: 9000001, threatId: "", sourceAddress: "", destinationAddress: "", description: "lab" }],
  });
  const candidate = buildIdsEditorCandidate({ zones: [{ name: "wan" }], ids: { enabled: false } }, form);
  assert.deepEqual(candidate.ids, {
    enabled: true,
    monitorInterfaces: ["wan0", "lan0"],
    homeNetworks: ["10.0.0.0/8", "192.168.0.0/16"],
    ruleFiles: ["managed.rules", "local.rules"],
    exceptions: [{ name: "fp-active", disabled: false, signatureId: 9000001, threatId: "", sourceAddress: "", destinationAddress: "", description: "lab" }],
    mode: "IDS_MODE_PREVENT",
    queueNum: 7,
    failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
  });
}

{
  const candidate = buildIdsEditorCandidate({ ids: { enabled: true, mode: "IDS_MODE_PREVENT", queueNum: 11, failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_OPEN" } }, idsEditorFormValues({
    enabled: false,
    mode: "IDS_MODE_DETECT",
    monitorInterfaces: "eth0",
    homeNetworks: "10.0.0.0/8",
    ruleFiles: "local.rules",
    queueNum: "70000",
    failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
  }));
  assert.deepEqual(candidate.ids, {
    enabled: false,
    monitorInterfaces: ["eth0"],
    homeNetworks: ["10.0.0.0/8"],
    ruleFiles: ["local.rules"],
  });
}

assert.deepEqual(threatPackageSummary({ surfaces: [] }), {
  available: false,
  label: "unknown",
  status: "unknown",
  cls: "warn",
  version: "",
  packageState: "unknown",
  blockerCount: 0,
  detail: "Threat-ID package posture is unavailable.",
});

{
  const summary = threatPackageSummary({
    surfaces: [{
      kind: "threat-id",
      badge: "verified",
      cls: "ok",
      version: "1.2.3",
      decision: { checks: [{ key: "production-evidence", status: "passed", cls: "ok" }], blockers: [] },
      contentReadiness: { productionReady: true, blockers: [] },
      contentReadinessEvidence: [
        { type: "pcap-regression-corpus", artifact: "evidence/pcap.json", sha256Short: "abc123" },
        { type: "false-positive-regression", artifact: "evidence/fp.json", sha256Short: "def456" },
      ],
      keyContentReadinessEvidence: {
        pcapRegressionCorpus: { type: "pcap-regression-corpus", artifact: "evidence/pcap.json", sha256Short: "abc123" },
      },
      blockers: [],
    }],
  });
  assert.equal(summary.available, true);
  assert.equal(summary.label, "1.2.3 / passed");
  assert.equal(summary.cls, "ok");
  assert.equal(summary.blockerCount, 0);
  assert.equal(summary.contentReadinessEvidence.length, 2);
  assert.equal(summary.keyContentReadinessEvidence.pcapRegressionCorpus.artifact, "evidence/pcap.json");
  assert.match(summary.detail, /Production Threat-ID evidence/);
}

{
  const summary = threatPackageSummary({
    surfaces: [{
      kind: "threat-id",
      badge: "verified",
      cls: "ok",
      version: "1.2.3",
      decision: { checks: [{ key: "production-evidence", status: "passed", cls: "bad" }], blockers: ["production evidence"] },
      contentReadiness: { productionReady: true, blockers: ["pcap-regression-corpus"] },
      blockers: [],
    }],
  });
  assert.equal(summary.cls, "bad");
  assert.equal(summary.blockerCount, 2);
}

const alert = {
  signatureId: "9000001",
  threatId: "phragma.test.web",
  threatName: "Suspicious test traffic",
  srcIp: "10.0.1.10",
  destIp: "198.51.100.20",
};

assert.equal(baseExceptionName(alert, "source"), "fp-9000001-source-10-0-1-10");
assert.deepEqual(stageThreatExceptionRequest(alert, "source", baseExceptionName(alert, "source"), "known lab false positive", false, {
  owner: " secops-oncall ",
  ticketId: "INC-2026-001",
  reviewDate: "2026-07-01",
  expiresAt: "2026-08-01",
  pcapSha256: "A".repeat(64),
  regressionRef: "evidence/fp-regression.json",
}), {
  name: "fp-9000001-source-10-0-1-10",
  threatId: "phragma.test.web",
  threatName: "Suspicious test traffic",
  engineSignals: [{ engine: "suricata", kind: "signature_id", value: "9000001" }],
  scope: "THREAT_EXCEPTION_SCOPE_SOURCE",
  sourceIp: "10.0.1.10",
  reason: "known lab false positive",
  confirmGlobal: false,
  owner: "secops-oncall",
  ticketId: "INC-2026-001",
  reviewDate: "2026-07-01",
  expiresAt: "2026-08-01",
  pcapSha256: "a".repeat(64),
  regressionRef: "evidence/fp-regression.json",
});
assert.deepEqual(stageThreatExceptionRequest(alert, "global", "fp-global", "global exception", true), {
  name: "fp-global",
  threatId: "phragma.test.web",
  threatName: "Suspicious test traffic",
  engineSignals: [{ engine: "suricata", kind: "signature_id", value: "9000001" }],
  scope: "THREAT_EXCEPTION_SCOPE_GLOBAL",
  reason: "global exception",
  confirmGlobal: true,
});

{
  const draft = {
    addresses: [{ name: "existing-host", cidr: "10.0.1.10/32" }],
  };

  const staged = stageThreatExceptionDraft(draft, alert, "source", baseExceptionName(alert, "source"), "known lab false positive", {
    owner: "secops-oncall",
    ticketId: "INC-2026-001",
    expiresAt: "2026-08-01",
    pcapSha256: "a".repeat(64),
  });

  assert.deepEqual(staged.exception, {
    name: "fp-9000001-source-10-0-1-10",
    signatureId: 9000001,
    threatId: "phragma.test.web",
    description: "known lab false positive",
    owner: "secops-oncall",
    ticketId: "INC-2026-001",
    expiresAt: "2026-08-01",
    pcapSha256: "a".repeat(64),
    sourceAddress: "existing-host",
  });
  assert.equal(draft.addresses.length, 1);
  assert.equal(draft.ids.exceptions.length, 1);
}

{
  const draft = {};
  const staged = stageThreatExceptionDraft(draft, alert, "destination", "fp-dst", "destination-side false positive");

  assert.deepEqual(draft.addresses, [{
    name: "threat-dst-198-51-100-20",
    cidr: "198.51.100.20/32",
    description: "Auto-added from threat exception",
  }]);
  assert.equal(staged.exception.destinationAddress, "threat-dst-198-51-100-20");
  assert.equal(staged.exception.description, "destination-side false positive");
}

{
  const draft = {};
  const staged = stageThreatExceptionDraft(draft, alert, "global", "fp-global", "global exception");

  assert.equal(staged.exception.sourceAddress, undefined);
  assert.equal(staged.exception.destinationAddress, undefined);
  assert.equal(draft.addresses, undefined);
}

assert.throws(
  () => stageThreatExceptionDraft({}, { signatureId: 0 }, "global", "fp-bad", ""),
  /signature_id is required/,
);
assert.throws(
  () => stageThreatExceptionDraft({}, alert, "global", "fp-bad", ""),
  /operator reason is required/,
);
assert.throws(
  () => stageThreatExceptionDraft({}, { ...alert, srcIp: "" }, "source", "fp-bad", "has reason"),
  /selected exception scope is unavailable/,
);
assert.throws(
  () => stageThreatExceptionDraft({}, alert, "source", "fp-bad", "has reason", { pcapSha256: "bad" }),
  /pcap_sha256/,
);

{
  const model = threatExceptionRecordModel({
    exception: {
      name: "fp-running",
      signatureId: 9000001,
      threatId: "phragma.test.web",
      sourceAddress: "client-net",
      description: "known lab false positive",
      owner: "secops-oncall",
      ticketId: "INC-2026-001",
      reviewDate: "2026-07-01",
      expiresAt: "2026-08-01",
      pcapSha256: "a".repeat(64),
      regressionRef: "evidence/fp-regression.json",
    },
    presentInRunning: true,
    candidateOnly: false,
    changedFromRunning: true,
    scope: "THREAT_EXCEPTION_SCOPE_SOURCE",
  });
  assert.equal(model.name, "fp-running");
  assert.equal(model.signatureLabel, "SID 9000001");
  assert.equal(model.scopeKey, "source");
  assert.equal(model.scopeLabel, "source client-net");
  assert.equal(model.owner, "secops-oncall");
  assert.equal(model.ticketId, "INC-2026-001");
  assert.equal(model.expiresAt, "2026-08-01");
  assert.equal(model.stateLabel, "candidate edit");
  assert.equal(model.stateCls, "violet");
}

{
  const model = threatExceptionRecordModel({
    exception: {
      name: "fp-disabled",
      signature_id: 9000002,
      disabled: true,
      description: "disabled reason",
    },
    candidate_only: true,
  });
  assert.equal(model.threatId, "—");
  assert.equal(model.scopeKey, "global");
  assert.equal(model.stateLabel, "disabled");
}

{
  const inventory = threatExceptionWorkbenchModel({
    source: "POLICY_SOURCE_CANDIDATE",
    candidateStatus: { dirty: true },
    exceptions: [
      { exception: { name: "fp-a", signatureId: 1 } },
      { exception: { name: "fp-b", signatureId: 2, disabled: true }, candidateOnly: true },
      { exception: { name: "fp-c", signatureId: 3 }, changedFromRunning: true },
    ],
  });
  assert.equal(inventory.records.length, 3);
  assert.equal(inventory.active, 2);
  assert.equal(inventory.disabled, 1);
  assert.equal(inventory.candidateOnly, 1);
  assert.equal(inventory.changed, 1);
  assert.equal(inventory.sourceLabel, "candidate");
  assert.equal(inventory.candidateDirty, true);
}

{
  const current = threatExceptionRecordModel({ exception: { name: "fp-a", signatureId: 1, sourceAddress: "client-net" } });
  const req = threatExceptionUpdateRequest(current, {
    name: "FP A",
    signatureId: "9000001",
    threatId: "phragma.test.web",
    scope: "destination",
    destinationAddress: "web-server",
    description: "policy reason",
    owner: "secops-oncall",
    ticketId: "INC-2026-001",
    reviewDate: "2026-07-01",
    expiresAt: "2026-08-01",
    pcapSha256: "B".repeat(64),
    regressionRef: "evidence/fp-regression.json",
    reason: "ticket sec-123",
  });
  assert.equal(req.ok, true);
  assert.deepEqual(req.exception, {
    name: "fp-a",
    disabled: false,
    signatureId: 9000001,
    threatId: "phragma.test.web",
    description: "policy reason",
    owner: "secops-oncall",
    ticketId: "INC-2026-001",
    reviewDate: "2026-07-01",
    expiresAt: "2026-08-01",
    pcapSha256: "b".repeat(64),
    regressionRef: "evidence/fp-regression.json",
    destinationAddress: "web-server",
  });
  assert.equal(req.reason, "ticket sec-123");
}

{
  const req = threatExceptionUpdateRequest({}, {
    name: "fp-global",
    signatureId: "9000001",
    scope: "global",
    description: "global reason",
    reason: "ticket sec-456",
  });
  assert.equal(req.ok, false);
  assert.match(req.error, /global acknowledgement/);
}

{
  const draft = {
    addresses: [{ name: "existing-host", cidr: "10.0.1.10/32" }],
    ids: { exceptions: [{ name: "existing-fp", signatureId: 9000001, sourceAddress: "existing-host" }] },
  };
  const preview = threatExceptionDraftPreview(draft, alert, "source", "new-fp", "same scoped SID");
  assert.equal(preview.ok, false);
  assert.match(preview.error, /existing-fp/);
  assert.throws(
    () => stageThreatExceptionDraft(draft, alert, "source", "new-fp", "same scoped SID"),
    /existing-fp/,
  );
}

{
  const model = threatExceptionStageResultModel({
    exception: {
      name: "fp-9000001-source-10-0-1-10",
      signatureId: 9000001,
      threatId: "phragma.test.web",
      description: "known lab false positive",
      sourceAddress: "existing-host",
    },
    address: { name: "existing-host", cidr: "10.0.1.10/32" },
    addressReused: true,
    candidateStatus: { dirty: true, changeCount: 2 },
    validation: { valid: true, warnings: ["runtime not checked"] },
    diff: {
      fromLabel: "running policy",
      toLabel: "candidate",
      lines: [
        { type: "POLICY_DIFF_LINE_TYPE_ADD", text: "+ ids.exceptions fp-9000001-source-10-0-1-10" },
      ],
    },
  }, "source");

  assert.equal(model.name, "fp-9000001-source-10-0-1-10");
  assert.equal(model.signatureId, "9000001");
  assert.equal(model.threatId, "phragma.test.web");
  assert.equal(model.reason, "known lab false positive");
  assert.equal(model.scopeLabel, "source existing-host (10.0.1.10/32, reused)");
  assert.equal(model.addressLabel, "existing-host 10.0.1.10/32 (reused)");
  assert.equal(model.candidateLabel, "2 pending changes");
  assert.deepEqual(model.validationWarnings, ["runtime not checked"]);
  assert.equal(model.diff.changed, true);
  assert.deepEqual(model.diff.lines, [{ t: "add", s: "+ ids.exceptions fp-9000001-source-10-0-1-10" }]);
}

{
  const model = threatExceptionStageResultModel({
    exception: { name: "fp-global", signature_id: 9000002 },
    candidate_status: { dirty: true, change_count: 1 },
    validation: { valid: true },
    diff: {},
  }, "global");

  assert.equal(model.scopeLabel, "global signature");
  assert.equal(model.addressLabel, "not scoped to an address object");
  assert.equal(model.candidateLabel, "1 pending change");
  assert.equal(model.artifact, "openngfw-threshold.config");
}

{
  const model = threatExceptionMutationResultModel("disable", {
    exception: { name: "fp-a", signatureId: 9000001, sourceAddress: "client-net" },
    previousException: { name: "fp-a", signatureId: 9000001, sourceAddress: "client-net" },
    candidateStatus: { dirty: true, changeCount: 2 },
    validation: { valid: true, warnings: ["review commit"] },
    diff: { lines: [{ type: "modified", path: "ids.exceptions[0]" }] },
  });
  assert.equal(model.title, "Threat exception disabled");
  assert.equal(model.candidateLabel, "2 pending changes");
  assert.equal(model.validationWarnings[0], "review commit");
  assert.equal(model.diff.changed, true);
}
