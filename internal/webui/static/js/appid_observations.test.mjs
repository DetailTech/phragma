import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { investigationPacketJson } from "./investigation_packet.js";
import {
  appIdObservationRequestFromState,
  appIdObservationDecision,
  appIdObservationClusterHandoffPacket,
  appIdClusterCorpusCustodyChecklist,
  appIdClusterEnforcementModel,
  appIdClusterProductionReadinessRows,
  appIdClusterReviewOnlyBoundary,
  appIdClusterReviewBoundary,
  appIdDirectStageEligibilityLabel,
  appIdProductionEvidenceLabel,
  appIdObservationClusters,
  appIdObservationRepresentative,
  appIdEvidenceBridgePlan,
  appIdContentContext,
  appIdReplayCompareBody,
  buildFlowRule,
  buildFlowRulePlan,
  buildAppDropRulePlan,
  appIdRegressionSampleStageBody,
  appIdObservationStageBody,
  appIdObservationPackageProvenance,
  appIdPackageProvenanceFromEvidence,
  applicationPortsLabel,
  flowCliCommandFromRequest,
  flowFromObservation,
  observationKindClass,
  observationKindLabel,
  sessionCliCommandFromRequest,
} from "./views/traffic.js";

const trafficViewSource = readFileSync(new URL("./views/traffic.js", import.meta.url), "utf8");
const rulesViewSource = readFileSync(new URL("./views/rules.js", import.meta.url), "utf8");
assert.match(trafficViewSource, /buildInvestigationPacket/);
assert.match(trafficViewSource, /function pinAppIdCaseRemediation/);
assert.match(trafficViewSource, /function appIdCaseRemediationPacket/);
assert.match(trafficViewSource, /kind: "candidate-remediation"/);
assert.match(trafficViewSource, /caseKey: state\.caseKey/);
assert.match(trafficViewSource, /changesRoute: "#\/changes\?tab=candidate"/);
assert.match(trafficViewSource, /sourceWorkspace: "traffic"/);
assert.match(trafficViewSource, /mode: "define-and-drop"/);
assert.match(trafficViewSource, /appidRegressionSamplePanel: "true"/);
assert.match(trafficViewSource, /appidAction: "stage-regression-sample"/);
assert.match(trafficViewSource, /appidRegressionSampleDrawer: "true"/);
assert.match(trafficViewSource, /appidRegressionField: "pcap-sha256"/);
assert.match(trafficViewSource, /appidRegressionStatus: "true"/);
assert.match(trafficViewSource, /appidReplayCompareDrawer: "true"/);
assert.match(trafficViewSource, /appidReplayAction: "compare"/);
assert.match(trafficViewSource, /appidReplayReport: "true"/);
assert.match(trafficViewSource, /trafficBridgeAction: "compare-replay"/);
assert.match(trafficViewSource, /appidEvidenceBridge: bridge\.kind/);
assert.match(trafficViewSource, /trafficBridgeAction: "capture"/);
assert.match(trafficViewSource, /trafficBridgeAction: "stage-regression-sample"/);
assert.match(trafficViewSource, /Package provenance/);
assert.match(trafficViewSource, /Package manifest/);
assert.match(trafficViewSource, /trafficAction: "explain-flow"/);
assert.match(trafficViewSource, /trafficAction: "custom-app-session"/);
assert.match(trafficViewSource, /appidObservationAction: "save-drop"/);
assert.match(trafficViewSource, /appidObservationAction: "capture"/);
assert.match(trafficViewSource, /appidClusterWorkbench: "true"/);
assert.match(trafficViewSource, /appidClusterAction: "review"/);
assert.match(trafficViewSource, /appidClusterAction: "pin"/);
assert.match(trafficViewSource, /appidClusterAction: "copy"/);
assert.match(trafficViewSource, /appidClusterAction: "export"/);
assert.match(trafficViewSource, /appidClusterAction: "stage-drop"/);
assert.match(trafficViewSource, /appidClusterAction: "review-drop"/);
assert.match(trafficViewSource, /appidClusterAction: "define"/);
assert.match(trafficViewSource, /appidClusterAction: "blocked"/);
assert.match(trafficViewSource, /appidClusterEnforcement: model\.action/);
assert.match(trafficViewSource, /Representative path type/);
assert.match(trafficViewSource, /Direct-stage eligibility/);
assert.match(trafficViewSource, /Production evidence/);
assert.match(trafficViewSource, /Production enforcement decision rows/);
assert.match(trafficViewSource, /appidClusterDecisionRows: "true"/);
assert.match(trafficViewSource, /Production-ready App-ID corpus/);
assert.match(trafficViewSource, /L7 evidence confidence/);
assert.match(trafficViewSource, /Representative port-hint rule staging/);
assert.match(trafficViewSource, /Reviewed drop-rule staging/);
assert.match(trafficViewSource, /Non-port-hint\/L7-only boundary/);
assert.match(trafficViewSource, /Review-only boundary/);
assert.match(trafficViewSource, /Corpus custody checklist/);
assert.match(trafficViewSource, /no signed corpus custody, legal retention, capture execution, policy commit, or true L7\/proxy allow claim/);
assert.match(trafficViewSource, /function appIdClusterDetail/);
assert.match(trafficViewSource, /Representative queue action only/);
assert.match(trafficViewSource, /function drawerButton/);
assert.match(trafficViewSource, /trafficDrawerAction: action \|\| ""/);
assert.match(trafficViewSource, /"aria-label": ariaLabel \|\| title/);
for (const action of [
  "close-appid-observation",
  "matching-flows",
  "capture-observation",
  "compare-appid-replay",
  "appid-api-cli",
  "promote-appid",
  "promote-appid-drop",
  "close-regression-sample",
  "stage-regression-sample",
  "close-appid-replay",
  "compare-appid-replay-run",
  "close-flow",
  "related-threats",
  "explain-flow-drawer",
  "capture-flow-drawer",
  "capture-audit",
  "custom-app-flow-drawer",
  "allow-flow-drawer",
  "drop-flow-drawer",
  "close-session",
  "explain-session-drawer",
  "capture-session-drawer",
  "capture-audit-session",
  "custom-app-session-drawer",
  "allow-session-drawer",
  "drop-session-drawer",
  "pin-handoff",
  "copy-handoff",
  "export-handoff",
  "cluster-define-appid",
  "cluster-review-drop",
  "cluster-stage-drop",
  "bridge-capture",
  "bridge-appid-queue",
  "bridge-corpus-review",
  "cancel-custom-app",
  "save-custom-app-view",
  "review-custom-app-drop",
  "save-custom-app-drop",
  "save-custom-app",
]) {
  assert.match(trafficViewSource, new RegExp(`action: "${action}"[\\s\\S]{0,180}title:`), `drawer action ${action} has a title`);
}
for (const action of ["pin", "copy", "export"]) {
  assert.match(trafficViewSource, new RegExp(`trafficHandoffAction: "${action}"`), `handoff action ${action} has stable selector`);
}
assert.match(rulesViewSource, /function pinPrefilledCaseRemediation/);
assert.match(rulesViewSource, /function prefilledRuleRemediationPacket/);
assert.match(rulesViewSource, /opts\.caseContext\?\.caseKey/);

assert.deepEqual(appIdObservationRequestFromState({
  limit: "50",
  flowLimit: "2000",
  confidenceThreshold: "65",
  q: "weird",
  observationKind: "APP_ID_OBSERVATION_KIND_UNKNOWN",
  engineSignal: "weird-proto",
  protocol: "TCP",
  port: "443",
}), {
  limit: 50,
  flowLimit: 2000,
  confidenceThreshold: 65,
  query: "weird",
  kind: "APP_ID_OBSERVATION_KIND_UNKNOWN",
  engineSignal: "weird-proto",
  protocol: "TCP",
  port: "443",
});

assert.equal(
  flowCliCommandFromRequest({ limit: 100, query: "admin api", ip: "10.0.1.10", protocol: "TCP", app: "web-browsing", port: 443, flowId: "flow-123", since: "2026-06-18T12:00:00.000Z" }),
  "ngfwctl flows --limit 100 --query \"admin api\" --ip 10.0.1.10 --protocol TCP --app web-browsing --port 443 --flow-id flow-123 --since 2026-06-18T12:00:00.000Z",
);

assert.deepEqual(appIdReplayCompareBody({
  queueId: "qid-1",
  appId: "unknown",
  engineSignal: "weird-proto",
  suggestedApplication: { name: "corp-admin" },
}, {
  expectedApp: "corp-admin",
  flowLimit: 1000,
  confidenceThreshold: 65,
}), {
  queueId: "qid-1",
  observation: undefined,
  expectedApp: "corp-admin",
  flowLimit: 1000,
  confidenceThreshold: 65,
  since: undefined,
  until: undefined,
});
assert.equal(
  sessionCliCommandFromRequest({ limit: 50, query: "reply state", protocol: "UDP", state: "ESTABLISHED" }),
  "ngfwctl sessions --limit 50 --query \"reply state\" --protocol UDP --state ESTABLISHED",
);

assert.equal(observationKindLabel("APP_ID_OBSERVATION_KIND_CONFLICTING_EVIDENCE"), "CONFLICTING EVIDENCE");
assert.equal(observationKindClass("APP_ID_OBSERVATION_KIND_CONFLICTING_EVIDENCE"), "bad");
assert.equal(observationKindClass("APP_ID_OBSERVATION_KIND_LOW_CONFIDENCE"), "warn");

const obs = {
  sampleSrcIp: "10.0.1.10",
  sampleSrcPort: 51515,
  sampleDestIp: "10.0.2.20",
  destPort: 8443,
  protocol: "TCP",
  engineSignal: "weird-proto",
  appId: "unknown",
  appEvidence: ["engine signal suricata.app_proto=weird-proto"],
  appIdPackageVersion: "2.4.6",
  appIdPackageManifestSha256: "f".repeat(64),
  sampleFlowId: "flow-1",
  bytes: 300,
  packets: 4,
};
const suggestedApp = {
  name: "weird-proto",
  displayName: "Weird Proto",
  category: "business-app",
  engineSignals: ["weird-proto"],
  ports: [{ protocol: "PROTOCOL_TCP", ports: [{ start: 8443 }] }],
};
assert.deepEqual(flowFromObservation(obs), {
  srcIp: "10.0.1.10",
  srcPort: 51515,
  destIp: "10.0.2.20",
  destPort: 8443,
  protocol: "TCP",
  appProtocol: "weird-proto",
  appId: "unknown",
  appName: undefined,
  appCategory: undefined,
  appConfidence: undefined,
  appEvidence: ["engine signal suricata.app_proto=weird-proto"],
  appIdPackageVersion: "2.4.6",
  appIdPackageManifestSha256: "f".repeat(64),
  flowId: "flow-1",
  bytesToServer: 300,
  bytesToClient: 0,
  packets: 4,
});

assert.deepEqual(appIdObservationPackageProvenance(obs), {
  version: "2.4.6",
  manifestSha256: "f".repeat(64),
  manifestShort: "ffffffffffff",
  label: "package 2.4.6 · manifest ffffffffffff",
});
assert.deepEqual(appIdPackageProvenanceFromEvidence([
  "engine signal suricata.app_proto=corp-admin",
  `signed App-ID package 2.4.6@${"a".repeat(64)} App-ID taxonomy match corp-admin -> corp-admin`,
]), {
  version: "2.4.6",
  manifestSha256: "a".repeat(64),
  manifestShort: "aaaaaaaaaaaa",
  label: "package 2.4.6 · manifest aaaaaaaaaaaa",
});
assert.equal(appIdPackageProvenanceFromEvidence(["signed App-ID package /var/lib/openngfw/content/app-id"]).label, "");

{
  const clusterObservations = [
    {
      ...obs,
      queueId: "qid-weak",
      sampleFlowId: "flow-weak",
      kind: "APP_ID_OBSERVATION_KIND_UNKNOWN",
      appConfidence: 44,
      count: 1,
      bytes: 100,
      packets: 2,
      appEvidence: ["engine signal token=secret-value"],
      suggestedApplication: suggestedApp,
    },
    {
      ...obs,
      queueId: "qid-representative",
      sampleFlowId: "flow-representative",
      kind: "APP_ID_OBSERVATION_KIND_UNKNOWN",
      appConfidence: 41,
      count: 22,
      bytes: 64000,
      packets: 40,
      appEvidence: [
        "engine signal suricata.app_proto=weird-proto",
        "bounded replay matched Authorization: Bearer should-not-leak",
      ],
      suggestedApplication: suggestedApp,
    },
    {
      ...obs,
      queueId: "qid-conflict",
      sampleFlowId: "flow-conflict",
      kind: "APP_ID_OBSERVATION_KIND_CONFLICTING_EVIDENCE",
      appConfidence: 88,
      count: 7,
      bytes: 900,
      appEvidence: ["conflicting taxonomy api_key=supersecret"],
      suggestedApplication: { ...suggestedApp, name: "weird-proto" },
    },
  ];
  const clusters = appIdObservationClusters(clusterObservations);
  assert.equal(clusters.length, 2);
  const lowConfidence = clusters.find((cluster) => cluster.confidenceBand === "low confidence");
  assert.equal(lowConfidence.observationCount, 2);
  assert.equal(lowConfidence.candidateTaxonomy, "weird-proto");
  assert.equal(lowConfidence.conflictState, "non-conflict");
  assert.equal(lowConfidence.flowCount, 23);
  assert.equal(lowConfidence.evidenceCount, 3);
  assert.equal(lowConfidence.representative.queueId, "qid-representative");
  assert.deepEqual(lowConfidence.representatives.map((item) => item.queueId), ["qid-representative", "qid-weak"]);

  const conflictCluster = clusters.find((cluster) => cluster.conflictState === "conflict");
  assert.equal(conflictCluster.observationCount, 1);
  assert.equal(conflictCluster.fallbackSingle, true);
  assert.equal(conflictCluster.representative.queueId, "qid-conflict");

  assert.equal(appIdObservationRepresentative(clusterObservations).queueId, "qid-conflict");

  const packet = appIdObservationClusterHandoffPacket(lowConfidence, {
    route: "#/traffic?mode=app-id",
    appIdReadiness: { explicit: true, productionReady: false, status: "token=package-secret", blockers: ["signed corpus custody"] },
    currentInspectionPosture: { label: "Prevent", detail: "runtime posture" },
  });
  const jsonText = investigationPacketJson(packet);
  const json = JSON.parse(jsonText);
  assert.equal(json.kind, "app-id-observation-cluster");
  assert.equal(json.summary.candidateBoundary, "No policy mutation; review, promotion, and drop remain individual queue actions.");
  assert.equal(json.summary.operatorWorkflow.corpusRoute, "#/intel?surface=app-id&drawer=review");
  assert.equal(json.summary.clusterEnforcement.action, "define");
  assert.ok(json.summary.clusterEnforcement.blockers.some((item) => /confidence is below 50/.test(item)));
  assert.equal(json.summary.clusterEnforcement.canDefine, true);
  assert.equal(json.summary.clusterEnforcement.canReviewDrop, false);
  assert.equal(json.summary.clusterEnforcement.canStageDrop, false);
  assert.equal(json.summary.representativePathType, "tcp-udp-port-hint");
  assert.equal(json.summary.directStageEligible, false);
  assert.match(json.summary.directStageEligibility, /not eligible yet/);
  assert.match(json.summary.productionEvidence, /not production ready/);
  assert.ok(json.summary.productionReadinessRows.some((item) => item.key === "production-appid-corpus" && item.status === "blocked"));
  assert.ok(json.summary.productionReadinessRows.some((item) => item.key === "reviewed-drop-rule-staging" && item.status === "blocked"));
  assert.match(json.summary.reviewBoundary, /does not directly stage policy/);
  assert.match(json.summary.reviewOnlyBoundary, /production evidence/);
  assert.match(json.summary.corpusCustody.boundary, /no signed corpus custody/);
  assert.match(json.summary.corpusCustody.boundary, /true L7\/proxy allow/);
  assert.equal(json.summary.corpusCustody.corpusRoute, "#/intel?surface=app-id&drawer=review");
  assert.ok(json.summary.corpusCustody.checklist.some((item) => item.label === "Representative queue observation" && item.status === "present"));
  assert.ok(json.summary.corpusCustody.checklist.some((item) => item.label === "Boundary" && /not signed custody/.test(item.status)));
  assert.equal(json.artifacts.enforcementPlan.canStageDrop, false);
  assert.equal(json.artifacts.enforcementPlan.representativePathType, "tcp-udp-port-hint");
  assert.equal(json.artifacts.enforcementPlan.directStageEligible, false);
  assert.match(json.artifacts.enforcementPlan.directStageEligibility, /not eligible yet/);
  assert.match(json.artifacts.enforcementPlan.productionEvidence, /not production ready/);
  assert.ok(json.artifacts.enforcementPlan.productionReadinessRows.some((item) => item.key === "production-appid-corpus"));
  assert.match(json.artifacts.enforcementPlan.reviewBoundary, /does not directly stage policy/);
  assert.match(json.artifacts.enforcementPlan.reviewOnlyBoundary, /production evidence/);
  assert.equal(json.artifacts.cluster.observationCount, 2);
  assert.equal(json.artifacts.regressionHandoff.representativeQueueId, "qid-representative");
  assert.ok(json.artifacts.regressionHandoff.corpusCustodyChecklist.some((item) => item.label === "Signed App-ID package manifest"));
  assert.match(json.artifacts.regressionHandoff.handoffBoundary, /not signed corpus custody/);
  assert.match(jsonText, /token=\[redacted\]/);
  assert.match(jsonText, /Authorization: Bearer \[redacted\]/i);
  assert.doesNotMatch(jsonText, /secret-value|should-not-leak|supersecret/);
}

{
  const [cluster] = appIdObservationClusters([{
    ...obs,
    queueId: "qid-drop",
    kind: "APP_ID_OBSERVATION_KIND_UNKNOWN",
    appConfidence: 82,
    count: 12,
    suggestedApplication: suggestedApp,
  }], { explicit: true, productionReady: true, status: "passed", blockers: [] });
  const model = appIdClusterEnforcementModel(cluster, {
    explicit: true,
    productionReady: true,
    status: "passed",
    version: "2.4.6",
    manifestSha256: "f".repeat(64),
    blockers: [],
  });
  assert.equal(model.action, "stage-drop");
  assert.equal(model.canDefine, true);
  assert.equal(model.canReviewDrop, true);
  assert.equal(model.canStageDrop, true);
  assert.deepEqual(model.blockers, []);
  assert.match(model.packageEvidence, /production ready/);
  assert.match(model.candidateBoundary, /Representative queue action only/);
  assert.equal(model.representativePathType, "tcp-udp-port-hint");
  assert.equal(model.directStageEligible, true);
  assert.deepEqual(appIdClusterProductionReadinessRows(model).map((item) => [item.key, item.status]), [
    ["production-appid-corpus", "ready"],
    ["l7-evidence-confidence", "ready"],
    ["representative-port-hint-staging", "stageable"],
    ["reviewed-drop-rule-staging", "reviewable"],
    ["non-port-hint-l7-only-boundary", "bounded port-hint"],
  ]);
  assert.match(model.reviewBoundary, /Direct staging is limited/);
  assert.equal(appIdDirectStageEligibilityLabel(model), "eligible: representative TCP/UDP port-hint queue path");
  assert.match(appIdProductionEvidenceLabel(model), /production ready/);
  assert.match(appIdClusterReviewOnlyBoundary(model), /Direct staging remains limited/);
  const stagePacket = JSON.parse(investigationPacketJson(appIdObservationClusterHandoffPacket(cluster, {
    route: "#/traffic?mode=app-id",
    appIdReadiness: {
      explicit: true,
      productionReady: true,
      status: "passed",
      version: "2.4.6",
      manifestSha256: "f".repeat(64),
      blockers: [],
    },
  })));
  assert.equal(stagePacket.summary.clusterEnforcement.action, "stage-drop");
  assert.equal(stagePacket.summary.clusterEnforcement.canStageDrop, true);
  assert.equal(stagePacket.summary.clusterEnforcement.directStageEligible, true);
  assert.ok(stagePacket.summary.productionReadinessRows.some((item) => item.key === "representative-port-hint-staging" && item.status === "stageable"));
  assert.ok(stagePacket.evidence.some((item) => /readiness_row production-appid-corpus=ready/.test(item)));
  assert.match(stagePacket.artifacts.enforcementPlan.candidateBoundary, /does not claim true L7\/proxy allow enforcement/);
  assert.match(stagePacket.artifacts.regressionHandoff.handoffBoundary, /not signed corpus custody/);
}

{
  const signalOnlyObs = {
    ...obs,
    queueId: "qid-signal-only",
    engineSignal: "http",
    kind: "APP_ID_OBSERVATION_KIND_UNKNOWN",
    appConfidence: 79,
    count: 11,
    suggestedApplication: { ...suggestedApp, name: "web-browsing", engineSignals: ["http"], ports: [] },
  };
  const [cluster] = appIdObservationClusters([signalOnlyObs], { explicit: true, productionReady: true, status: "passed", blockers: [] });
  const blocked = appIdClusterEnforcementModel(cluster, { explicit: true, productionReady: true, status: "passed", blockers: [] }, {
    policy: { ids: { enabled: true, mode: "IDS_MODE_PREVENT", failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_OPEN" } },
  });
  assert.equal(blocked.action, "define");
  assert.equal(blocked.canReviewDrop, false);
  assert.ok(blocked.blockers.some((item) => /Fail closed/.test(item)));

  const ready = appIdClusterEnforcementModel(cluster, { explicit: true, productionReady: true, status: "passed", blockers: [] }, {
    policy: { ids: { enabled: true, mode: "IDS_MODE_PREVENT", failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED" } },
  });
  assert.equal(ready.action, "review-drop");
  assert.equal(ready.canStageDrop, false);
  assert.equal(ready.canReviewDrop, true);
  assert.deepEqual(ready.blockers, []);
  assert.match(ready.signalSupport, /supported Suricata/);
  assert.equal(ready.representativePathType, "suricata-signal-only-review");
  assert.equal(ready.directStageEligible, false);
  assert.deepEqual(appIdClusterProductionReadinessRows(ready).map((item) => [item.key, item.status]), [
    ["production-appid-corpus", "ready"],
    ["l7-evidence-confidence", "ready"],
    ["representative-port-hint-staging", "not stageable"],
    ["reviewed-drop-rule-staging", "reviewable"],
    ["non-port-hint-l7-only-boundary", "review-only"],
  ]);
  assert.equal(appIdDirectStageEligibilityLabel(ready), "review-only: supported Suricata signal path, no direct stage");
  assert.match(appIdClusterReviewOnlyBoundary(ready), /Review-only boundary/);
  assert.match(ready.reviewBoundary, /Signal-only clusters are review-only handoffs/);
  assert.match(ready.reviewBoundary, /true L7\/proxy allow/);
  const signalPacket = JSON.parse(investigationPacketJson(appIdObservationClusterHandoffPacket(cluster, {
    route: "#/traffic?mode=app-id",
    appIdReadiness: { explicit: true, productionReady: true, status: "passed", blockers: [] },
    policy: { ids: { enabled: true, mode: "IDS_MODE_PREVENT", failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED" } },
  })));
  assert.equal(signalPacket.summary.representativePathType, "suricata-signal-only-review");
  assert.equal(signalPacket.summary.directStageEligible, false);
  assert.match(signalPacket.summary.directStageEligibility, /review-only: supported Suricata signal/);
  assert.match(signalPacket.summary.productionEvidence, /production ready/);
  assert.equal(signalPacket.summary.clusterEnforcement.canStageDrop, false);
  assert.equal(signalPacket.summary.clusterEnforcement.canReviewDrop, true);
  assert.ok(signalPacket.summary.clusterEnforcement.productionReadinessRows.some((item) => item.key === "non-port-hint-l7-only-boundary" && item.status === "review-only"));
  assert.ok(signalPacket.evidence.some((item) => /readiness_row non-port-hint-l7-only-boundary=review-only/.test(item)));
  assert.match(signalPacket.summary.clusterEnforcement.reviewOnlyBoundary, /no direct stage/);
  assert.match(signalPacket.summary.reviewBoundary, /review-only/);
  assert.match(signalPacket.artifacts.regressionHandoff.handoffBoundary, /not signed corpus custody/);
}

assert.match(
  appIdClusterReviewBoundary("custom-signal-needs-port-boundary", false),
  /no direct staging or true L7\/proxy allow/,
);
assert.deepEqual(appIdClusterCorpusCustodyChecklist({
  representative: { queueId: "qid-secret", appIdPackageManifestSha256: "b".repeat(64) },
}, {
  representative: { queueId: "qid-secret", appIdPackageManifestSha256: "b".repeat(64) },
  representativePathType: "tcp-udp-port-hint",
  directStageEligible: true,
}, {
  appIdReadiness: { manifestSha256: "a".repeat(64) },
}).map((item) => item.label), [
  "Representative queue observation",
  "Representative path type",
  "Production readiness evidence",
  "Signed App-ID package manifest",
  "Corpus review route",
  "Boundary",
]);

{
  const [cluster] = appIdObservationClusters([{
    ...obs,
    queueId: "",
    kind: "APP_ID_OBSERVATION_KIND_UNKNOWN",
    appConfidence: 41,
    count: 8,
    suggestedApplication: suggestedApp,
  }], { explicit: true, productionReady: false, status: "demo-only", blockers: ["production corpus evidence"] });
  const model = appIdClusterEnforcementModel(cluster, { explicit: true, productionReady: false, status: "demo-only", blockers: ["production corpus evidence"] });
  assert.equal(model.action, "blocked");
  assert.equal(model.canDefine, false);
  assert.equal(model.canReviewDrop, false);
  assert.ok(model.blockers.some((item) => /not queue-backed/.test(item)));
  assert.ok(model.blockers.some((item) => /confidence is below 50/.test(item)));
  assert.ok(model.blockers.some((item) => /production corpus evidence/.test(item)));
}

{
  const [cluster] = appIdObservationClusters([{
    ...obs,
    queueId: "qid-implicit-readiness",
    kind: "APP_ID_OBSERVATION_KIND_UNKNOWN",
    appConfidence: 86,
    count: 14,
    suggestedApplication: suggestedApp,
  }]);
  const model = appIdClusterEnforcementModel(cluster);
  assert.equal(model.action, "define");
  assert.equal(model.packageReady, false);
  assert.equal(model.canReviewDrop, false);
  assert.equal(model.canStageDrop, false);
  assert.ok(model.blockers.some((item) => /production-ready App-ID corpus not explicitly reported/.test(item)));
  assert.deepEqual(appIdClusterProductionReadinessRows(model).map((item) => [item.key, item.status]), [
    ["production-appid-corpus", "blocked"],
    ["l7-evidence-confidence", "ready"],
    ["representative-port-hint-staging", "not stageable"],
    ["reviewed-drop-rule-staging", "blocked"],
    ["non-port-hint-l7-only-boundary", "bounded port-hint"],
  ]);
  const packet = JSON.parse(investigationPacketJson(appIdObservationClusterHandoffPacket(cluster, { route: "#/traffic?mode=app-id" })));
  assert.equal(packet.summary.productionReadinessRows.find((item) => item.key === "production-appid-corpus").status, "blocked");
  assert.match(packet.summary.productionEvidence, /not explicitly reported/);
}

{
  const single = appIdObservationClusters([{
    ...obs,
    queueId: "qid-single",
    kind: "APP_ID_OBSERVATION_KIND_LOW_CONFIDENCE",
    appConfidence: 49,
    count: 1,
    suggestedApplication: { ...suggestedApp, name: "single-app", displayName: "Single App" },
  }]);
  assert.equal(single.length, 1);
  assert.equal(single[0].fallbackSingle, true);
  assert.equal(single[0].observationCount, 1);
  assert.equal(single[0].representative.queueId, "qid-single");
  assert.match(investigationPacketJson(appIdObservationClusterHandoffPacket(single[0], { route: "#/traffic?mode=app-id" })), /Single App/);
}

{
  const policy = {
    addresses: [{ name: "inside-existing", cidr: "10.0.1.10/32" }],
    services: [],
  };
  const before = structuredClone(policy);
  const flow = {
    srcIp: "10.0.1.10",
    srcPort: 51515,
    destIp: "10.0.2.20",
    destPort: 8443,
    protocol: "TCP",
    appId: "unknown",
  };
  const rule = buildFlowRule(policy, flow, "ACTION_DENY");
  assert.deepEqual(policy, before);
  assert.deepEqual(rule.sourceAddresses, ["inside-existing"]);
  assert.deepEqual(rule.destinationAddresses, ["dst-10-0-2-20"]);
  assert.deepEqual(rule.services, ["unknown-8443"]);
  assert.equal(rule.log, true);

  const plan = buildFlowRulePlan(policy, flow, "ACTION_DENY");
  const draft = structuredClone(policy);
  plan.beforeSave(draft);
  assert.deepEqual(draft.addresses.map((item) => item.name), ["inside-existing", "dst-10-0-2-20"]);
  assert.deepEqual(draft.services.map((item) => item.name), ["unknown-8443"]);

  const appPlan = buildAppDropRulePlan(policy, flow, suggestedApp);
  assert.deepEqual(appPlan.rule.services, []);
  assert.deepEqual(appPlan.rule.applications, ["weird-proto"]);
  assert.equal(appPlan.rule.action, "ACTION_DENY");
  assert.equal(appPlan.rule.log, true);
  assert.equal(appPlan.rule.description.includes("TCP/UDP port-hint enforcement"), true);
  const appDraft = structuredClone(policy);
  appPlan.beforeSave(appDraft);
  assert.deepEqual(appDraft.addresses.map((item) => item.name), ["inside-existing", "dst-10-0-2-20"]);
  assert.deepEqual(appDraft.services || [], []);
  assert.deepEqual(appDraft.applications.map((item) => item.name), ["weird-proto"]);

  const signalOnlyPlan = buildAppDropRulePlan(policy, flow, {
    name: "web-browsing",
    displayName: "Web Browsing",
    category: "business-app",
    engineSignals: ["http"],
    ports: [],
  });
  assert.deepEqual(signalOnlyPlan.rule.sourceAddresses, []);
  assert.deepEqual(signalOnlyPlan.rule.destinationAddresses, []);
  assert.deepEqual(signalOnlyPlan.dependencies.addresses, []);
  assert.equal(signalOnlyPlan.rule.description.includes("supported Suricata signal enforcement"), true);
  const signalDraft = structuredClone(policy);
  signalOnlyPlan.beforeSave(signalDraft);
  assert.deepEqual(signalDraft.addresses.map((item) => item.name), ["inside-existing"]);
  assert.deepEqual(signalDraft.applications.map((item) => item.name), ["web-browsing"]);
}

assert.equal(applicationPortsLabel({
  ports: [
    { protocol: "PROTOCOL_TCP", ports: [{ start: 8443 }] },
    { protocol: "PROTOCOL_UDP", ports: [{ start: 5353, end: 5355 }] },
  ],
}), "TCP/8443, UDP/5353-5355");

assert.deepEqual(appIdObservationStageBody({ queueId: "qid-1" }, suggestedApp, "block", {
  reason: "reviewed repeated unknown app",
  flowLimit: 1000,
  confidenceThreshold: 70,
  since: "2026-06-18T12:00:00.000Z",
}), {
  mode: "APP_ID_OBSERVATION_STAGE_MODE_DEFINE_AND_DROP",
  reason: "reviewed repeated unknown app",
  confirmDrop: true,
  applicationOverride: suggestedApp,
  flowLimit: 1000,
  confidenceThreshold: 70,
  since: "2026-06-18T12:00:00.000Z",
});

assert.deepEqual(appIdRegressionSampleStageBody({
  queueId: "qid-1",
  appId: "unknown",
  appName: "Unknown",
  engineSignal: "weird-proto",
  suggestedApplication: suggestedApp,
}, {
  reason: "reviewed capture",
  pcapSha256: "a".repeat(64),
  flowLimit: 1000,
  confidenceThreshold: 70,
  since: "2026-06-18T12:00:00.000Z",
}), {
  queueId: "qid-1",
  reason: "reviewed capture",
  pcapSha256: "a".repeat(64),
  expectedApp: "weird-proto",
  observedApp: "weird-proto",
  flowLimit: 1000,
  confidenceThreshold: 70,
  since: "2026-06-18T12:00:00.000Z",
  until: undefined,
});

{
  const bridge = appIdEvidenceBridgePlan(flowFromObservation({ ...obs, queueId: "qid-1", suggestedApplication: suggestedApp }), {
    kind: "observation",
    observation: { ...obs, queueId: "qid-1", kind: "APP_ID_OBSERVATION_KIND_UNKNOWN", suggestedApplication: suggestedApp },
    readiness: {
      productionReady: false,
      status: "missing",
      packageState: "draft",
      blockers: ["app-regression-corpus"],
    },
  });
  assert.equal(bridge.kind, "observation");
  assert.equal(bridge.canStageRegressionSample, true);
  assert.equal(bridge.candidateSafeLabel, "candidate-safe");
  assert.match(bridge.captureHref, /^#\/troubleshoot\?/);
  assert.match(bridge.captureHref, /intent=capture/);
  assert.match(bridge.queueHref, /mode=app-id/);
  assert.match(bridge.queueHref, /queueId=qid-1/);
  assert.equal(bridge.corpusHref, "#/intel?surface=app-id&drawer=review");
  assert.match(bridge.regressionStep, /Existing endpoint supports reviewed draft sample staging/);
  assert.match(bridge.candidateBoundary, /No direct policy mutation/);
  assert.match(bridge.captureFilter, /host 10\.0\.1\.10/);
}

{
  const bridge = appIdEvidenceBridgePlan({
    srcIp: "10.0.1.10",
    srcPort: 51515,
    destIp: "10.0.2.20",
    destPort: 8443,
    protocol: "TCP",
    appProtocol: "weird-proto",
    appId: "unknown",
    flowId: "flow-1",
  }, { kind: "flow" });
  assert.equal(bridge.kind, "flow");
  assert.equal(bridge.canStageRegressionSample, false);
  assert.match(bridge.regressionStep, /Browser-local only/);
  assert.match(bridge.queueHref, /engineSignal=weird-proto/);
  assert.match(bridge.captureStep, /tcp 10\.0\.1\.10:51515 -> 10\.0\.2\.20:8443/);
}

assert.deepEqual(pickDecision(appIdObservationDecision({
  kind: "APP_ID_OBSERVATION_KIND_CONFLICTING_EVIDENCE",
  appId: "web-browsing",
  appConfidence: 80,
  engineSignal: "http",
  protocol: "TCP",
  destPort: 443,
  count: 20,
  appEvidence: ["port heuristic tcp/443 suggests ssl; reduced confidence for engine signal http -> web-browsing"],
  suggestedApplication: suggestedApp,
})), {
  action: "investigate",
  label: "Investigate conflict",
  tone: "bad",
  evidenceStrength: "conflicting",
  canStageDrop: false,
});

assert.deepEqual(pickDecision(appIdObservationDecision({
  kind: "APP_ID_OBSERVATION_KIND_UNKNOWN",
  appId: "unknown",
  count: 1,
})), {
  action: "filter_related_evidence",
  label: "Filter evidence",
  tone: "warn",
  evidenceStrength: "weak",
  canStageDrop: false,
});

assert.deepEqual(pickDecision(appIdObservationDecision({
  ...obs,
  kind: "APP_ID_OBSERVATION_KIND_UNKNOWN",
  count: 2,
  suggestedApplication: suggestedApp,
})), {
  action: "define_custom_app",
  label: "Define App-ID",
  tone: "info",
  evidenceStrength: "strong",
  canStageDrop: true,
});

{
  const signalOnlyDecision = appIdObservationDecision({
    ...obs,
    engineSignal: "http",
    kind: "APP_ID_OBSERVATION_KIND_UNKNOWN",
    count: 8,
    suggestedApplication: { ...suggestedApp, name: "web-browsing", engineSignals: ["http"], ports: [] },
  });
  assert.deepEqual(pickDecision(signalOnlyDecision), {
    action: "define_custom_app",
    label: "Define App-ID",
    tone: "info",
    evidenceStrength: "strong",
    canStageDrop: false,
  });
  assert.equal(signalOnlyDecision.candidatePath, "Stage the App-ID object only; signal-only drop remains review-only and requires IDS/IPS Prevent fail-closed before candidate review.");
}

assert.deepEqual(pickDecision(appIdObservationDecision({
  ...obs,
  kind: "APP_ID_OBSERVATION_KIND_UNKNOWN",
  count: 8,
  suggestedApplication: suggestedApp,
})), {
  action: "save_drop",
  label: "Save & drop",
  tone: "bad",
  evidenceStrength: "strong",
  canStageDrop: true,
});

assert.deepEqual(pickDecision(appIdObservationDecision({
  ...obs,
  kind: "APP_ID_OBSERVATION_KIND_UNKNOWN",
  count: 8,
  suggestedApplication: suggestedApp,
}, { explicit: true, productionReady: true, status: "passed", blockers: [] })), {
  action: "save_drop",
  label: "Save & drop",
  tone: "bad",
  evidenceStrength: "strong",
  canStageDrop: true,
});

{
  const gated = appIdObservationDecision({
    ...obs,
    kind: "APP_ID_OBSERVATION_KIND_UNKNOWN",
    count: 8,
    suggestedApplication: suggestedApp,
  }, { explicit: true, productionReady: false, status: "demo-only", blockers: ["production content scope"] });
  assert.deepEqual(pickDecision(gated), {
    action: "define_custom_app",
    label: "Define App-ID",
    tone: "info",
    evidenceStrength: "strong",
    canStageDrop: false,
  });
  assert.match(gated.reason, /production content scope/);
}

assert.equal(appIdContentContext({
  appEvidence: ["content package app-id version 1.2.3 matched custom taxonomy"],
  suggestedApplication: suggestedApp,
}), "content package app-id version 1.2.3 matched custom taxonomy");

function pickDecision(decision) {
  return {
    action: decision.action,
    label: decision.label,
    tone: decision.tone,
    evidenceStrength: decision.evidenceStrength,
    canStageDrop: decision.canStageDrop,
  };
}
