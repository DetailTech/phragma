import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { buildFleetModel, fleetNodeEvidenceModel, localTemplateCustodyModel, noPeerApplyBoundaryModel, orchestrationHandoffText, orchestrationPreviewInvestigationPacket, orchestrationPreviewModel, serverTemplateHandoffText, serverTemplateInvestigationPacket, serverTemplateWorkbenchModel, templateHandoffText, templatePreviewInvestigationPacket } from "./views/fleet.js";

const fleetViewSource = readFileSync(new URL("./views/fleet.js", import.meta.url), "utf8");

assert.match(fleetViewSource, /appendInvestigationPacketToActiveServerCase/);
assert.match(fleetViewSource, /dataset: \{ fleetTemplateAction: "pin-handoff" \}/);
assert.match(fleetViewSource, /dataset: \{ fleetTemplateAction: "pin-api-handoff", fleetTemplateKey: item\.id \}/);
assert.match(fleetViewSource, /dataset: \{ fleetTemplateAction: "apply-plan", fleetTemplateKey: item\.id \}/);
assert.match(fleetViewSource, /dataset: \{ fleetTemplateAction: "apply", fleetTemplateKey: item\.id \}/);
assert.match(fleetViewSource, /dataset: \{ fleetOrchestrationAction: "pin-preview" \}/);
assert.match(fleetViewSource, /dataset: \{ fleetOrchestrationAction: "copy-preview" \}/);
assert.match(fleetViewSource, /dataset: \{ fleetOrchestrationBoundary: "no-peer-apply" \}/);
assert.match(fleetViewSource, /api\.applyPlanFleetTemplate\(item\.id/);
assert.match(fleetViewSource, /api\.applyFleetTemplate\(item\.id/);
assert.match(fleetViewSource, /api\.addInvestigationCaseEvidence\(id, evidence\)/);
assert.match(fleetViewSource, /activeInvestigationServerCaseHref\(\)/);

const blocked = buildFleetModel({
  status: {
    hostname: "fw-edge-1",
    mode: "appliance",
    dataplane: { runningPolicyVersion: 17 },
  },
  ha: {
    role: "active",
    sync: { peerVersion: 16 },
  },
  running: {
    version: 17,
    policy: {
      zones: [{ name: "untrust" }, { name: "dmz" }],
      rules: [{ name: "allow-web" }],
      nat: { destination: [{ name: "publish-web" }] },
      vpn: { wireguardInterfaces: [{ name: "wg0" }] },
    },
  },
  candidate: {
    policy: {
      zones: [{ name: "untrust" }, { name: "dmz" }, { name: "corp" }],
      rules: [{ name: "allow-web" }, { name: "allow-corp" }],
      nat: { destination: [{ name: "publish-web" }] },
      vpn: { wireguardInterfaces: [{ name: "wg0" }] },
    },
  },
  candidateStatus: { dirty: true, changeCount: 3 },
  feeds: { feeds: [{ name: "builtin", enabled: true, allowsCommercialUse: true }] },
  contentPackages: { packages: [] },
  releaseAcceptance: { state: "incomplete", summary: { missing: 2 } },
  fleetNodes: {
    nodes: [{
      id: "local",
      name: "fw-api-1",
      detail: "nftables/conntrack",
      runningVersion: 17,
      role: "active",
      haReady: false,
      runtimeState: "degraded",
    }],
  },
  fleetTemplates: {
    templates: [{
      id: "tmpl-edge-baseline",
      name: "Edge baseline API draft",
      scope: "local-appliance",
      revision: "sha256:template",
      policySummary: { zones: 2, rules: 1, sourceNat: 0, destinationNat: 1, ipsecTunnels: 0, wireGuardPeers: 1 },
    }],
  },
  fleetResults: {
    results: [{
      id: "apply-20260622T120000Z-abcd",
      templateId: "tmpl-edge-baseline",
      templateName: "Edge baseline API draft",
      status: "applied",
      finishedAt: "2026-06-22T12:00:00Z",
      custodyBoundary: "server-retained local Fleet apply result; unsigned and not distributed custody",
      nodeResults: [
        { nodeId: "local", nodeName: "local appliance", result: "applied", mutation: "local candidate policy updated; running policy not applied", reason: "template staged to local candidate revision sha256:new" },
        { nodeId: "fw-peer", nodeName: "fw-peer", result: "skipped", mutation: "none", reason: "peer eligible but skipped because Fleet has no safe peer RPC transport in this slice" },
      ],
    }],
  },
});

assert.equal(blocked.nodes.length, 1);
assert.equal(blocked.nodes[0].name, "fw-api-1");
assert.equal(blocked.nodes[0].roleLabel, "active");
assert.equal(blocked.nodes[0].policyVersion, "v17");
assert.equal(blocked.nodes[0].haLabel, "review");
assert.equal(blocked.scopeLabel, "local control plane only");
assert.ok(blocked.boundaries.some((item) => item.key === "authority" && /not durable fleet inventory/.test(item.detail)));
assert.ok(blocked.boundaries.some((item) => item.key === "ha-traffic" && item.tone === "warn" && /traffic-control procedure/.test(item.detail)));
assert.equal(blocked.drift.label, "candidate drift");
assert.ok(blocked.drift.items.some((item) => item.key === "candidate" && item.tone === "warn"));
assert.ok(blocked.actions.some((item) => item.key === "candidate"));
assert.ok(!blocked.actions.some((item) => item.key === "release"));
assert.ok(blocked.templates.some((item) => item.key === "tmpl-edge-baseline" && item.serverBacked && item.state === "server draft"));
assert.ok(blocked.templates.some((item) => item.key === "edge-policy" && item.state === "drift"));
assert.ok(blocked.templates.some((item) => item.key === "routing-vpn" && item.state === "modeled"));
assert.ok(blocked.evidence.some((item) => item.key === "fleet-api" && item.state === "loaded"));
assert.equal(blocked.applyResults.length, 1);
assert.equal(blocked.applyResults[0].nodeSummary, "1 applied, 1 skipped");
assert.ok(blocked.evidence.some((item) => item.key === "fleet-results" && item.state === "retained"));
assert.ok(blocked.evidence.some((item) => item.key === "policy" && item.state === "drift"));
assert.equal(blocked.orchestrationPreview.eligibleCount, 0);
assert.equal(blocked.orchestrationPreview.positiveEvidenceNodes, 0);
assert.ok(blocked.orchestrationPreview.blockers.some((item) => item.key === "candidate"));
assert.ok(!blocked.orchestrationPreview.blockers.some((item) => item.key === "release"));
assert.ok(blocked.orchestrationPreview.blockers.some((item) => item.key === "inventory"));
assert.ok(blocked.orchestrationPreview.blockers.some((item) => item.key === "nodes" && /fw-api-1/.test(item.detail)));
assert.ok(blocked.orchestrationPreview.plan.some((item) => item.key === "fanout-preview" && item.boundary === "blocked plan"));
assert.ok(blocked.orchestrationPreview.plan.some((item) => item.key === "no-running-apply" && /no Fleet fan-out/.test(item.command)));
assert.ok(blocked.templatePreviews.some((item) => item.key === "edge-policy"));
const blockedEdgePreview = blocked.templatePreviews.find((item) => item.key === "edge-policy");
assert.equal(blockedEdgePreview.candidate.title, "candidate staged");
assert.equal(blockedEdgePreview.applyPath.title, "Changes import");
assert.ok(blockedEdgePreview.changes.some((item) => item.key === "candidate" && item.tone === "warn"));
assert.ok(blockedEdgePreview.context.some((item) => item.value === "GET /v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE"));
assert.ok(!blockedEdgePreview.context.some((item) => item.value === "#/readiness?drawer=release-acceptance"));
assert.ok(blockedEdgePreview.context.some((item) => item.value === "ngfwctl policy validate"));
const handoff = templateHandoffText(blockedEdgePreview);
assert.match(handoff, /Phragma Fleet local template preview/);
assert.match(handoff, /Scope: connected local appliance only; not authoritative fleet inventory/);
assert.match(handoff, /Apply boundary: stage\/import through Changes/);
assert.match(handoff, /no peer fan-out, distributed apply result, signed template custody, traffic failover, or HA fencing/);
const localPreviewPacket = templatePreviewInvestigationPacket(blockedEdgePreview);
assert.equal(localPreviewPacket.schemaVersion, "phragma.investigation.handoff.v1");
assert.equal(localPreviewPacket.kind, "fleet-template-preview");
assert.equal(localPreviewPacket.subject.id, "edge-policy");
assert.match(localPreviewPacket.summary.custodyBoundary, /browser-local template preview only/);
assert.equal(localPreviewPacket.summary.localTemplateCustody.signed, false);
assert.equal(localPreviewPacket.summary.localTemplateCustody.retainedByServer, false);
assert.match(localPreviewPacket.evidence.join("\n"), /local_template_custody=browser-local preview only/);
assert.match(localPreviewPacket.evidence.join("\n"), /apply_boundary=stage\/import through Changes/);
assert.match(localPreviewPacket.artifacts.handoffText, /Phragma Fleet local template preview/);

const blockedHaPreview = blocked.templatePreviews.find((item) => item.key === "ha");
assert.ok(blockedHaPreview.changes.some((item) => item.key === "ha-boundary" && item.tone === "warn"));
assert.ok(!blockedHaPreview.context.some((item) => item.value === "#/readiness?drawer=ha-cockpit"));
assert.ok(blockedHaPreview.context.some((item) => item.value === "ngfwctl system ha status"));

const aligned = buildFleetModel({
  status: { hostname: "fw-standalone", dataplane: { runningPolicyVersion: 21 } },
  running: {
    version: 21,
    policy: {
      zones: [{ name: "lan" }, { name: "wan" }],
      rules: [{ name: "allow-outbound" }],
      nat: { source: [{ name: "masq" }] },
      intel: { commercialUse: true },
    },
  },
  candidate: { policy: { zones: [{ name: "lan" }, { name: "wan" }], rules: [{ name: "allow-outbound" }], nat: { source: [{ name: "masq" }] }, intel: { commercialUse: true } } },
  candidateStatus: { dirty: false, changeCount: 0 },
  feeds: { feeds: [{ name: "builtin", enabled: true, allowsCommercialUse: true }] },
  contentPackages: {
    packages: [
      readyPackage("app-id"),
      readyPackage("threat-id"),
      readyPackage("intel-feeds"),
    ],
  },
  releaseAcceptance: { ready: true, state: "ready", summary: {} },
});

assert.equal(aligned.nodes[0].roleLabel, "standalone");
assert.equal(aligned.nodes[0].haLabel, "standalone");
assert.ok(aligned.boundaries.some((item) => item.key === "ha-traffic" && item.title === "No HA traffic-control claim"));
assert.equal(aligned.drift.label, "aligned");
assert.equal(aligned.release.tone, "ok");
assert.ok(aligned.actions.some((item) => item.key === "monitor"));
assert.ok(aligned.templates.some((item) => item.key === "edge-policy" && item.state === "aligned"));
assert.ok(!aligned.evidence.some((item) => item.key === "release"));

const apiWorkbench = serverTemplateWorkbenchModel({
  id: "tmpl-edge-baseline",
  label: "Edge baseline API draft",
  revision: "sha256:template",
}, {
  template: {
    id: "tmpl-edge-baseline",
    name: "Edge baseline API draft",
    revision: "sha256:template",
    policySummary: {
      zones: 2,
      rules: 7,
      sourceNat: 1,
      destinationNat: 1,
      staticRoutes: 2,
      dynamicRouting: true,
      ipsecTunnels: 1,
      wireGuardPeers: 1,
      hostInputRules: 2,
      securityProfiles: 3,
      applications: 4,
    },
  },
  validation: { valid: true },
  impact: {
    risk: "CHANGE_RISK_MEDIUM",
    items: [{ risk: "CHANGE_RISK_HIGH", title: "NAT publish changed", detail: "DNAT changes require review." }],
  },
  candidateRevision: "sha256:candidate",
  previousCandidateRevision: "sha256:previous",
  applyPath: "stage through /v1/candidate, validate, diff, approval when required, commit, audit, rollback",
  orchestrationBoundary: "local preview only; no peer fan-out, distributed apply result, signed custody, HA fencing, or traffic failover",
  applyResult: {
    id: "apply-20260622T120000Z-abcd",
    status: "applied",
    custodyBoundary: "server-retained local Fleet apply result; unsigned and not distributed custody",
    nodeResults: [
      { nodeId: "local", nodeName: "local appliance", role: "standalone", runtimeState: "ready", result: "applied", mutation: "local candidate policy updated; running policy not applied", reason: "template staged to local candidate revision sha256:candidate" },
      { nodeId: "fw-peer", nodeName: "fw-peer", role: "passive", runtimeState: "ready", result: "skipped", mutation: "none", reason: "peer eligible but skipped because Fleet has no safe peer RPC transport in this slice" },
    ],
  },
}, "Template apply preview");

assert.equal(apiWorkbench.risk.title, "medium");
assert.equal(apiWorkbench.risk.tone, "warn");
assert.equal(apiWorkbench.candidateFact.title, "sha256:candidate");
assert.ok(apiWorkbench.candidateFact.detail.includes("previous sha256:previous"));
assert.ok(apiWorkbench.changedAreas.some((item) => item.key === "rules" && item.badge === "7"));
assert.ok(apiWorkbench.changedAreas.some((item) => item.key === "routing" && item.detail.includes("3")));
assert.ok(apiWorkbench.changedAreas.some((item) => item.key === "profiles"));
assert.ok(apiWorkbench.impactItems.some((item) => item.title === "NAT publish changed" && item.tone === "bad"));
assert.ok(apiWorkbench.handoff.some((item) => item.value.includes("POST /v1/fleet/templates/tmpl-edge-baseline:apply-preview")));
assert.ok(apiWorkbench.handoff.some((item) => item.value.includes("POST /v1/fleet/templates/tmpl-edge-baseline:apply-plan")));
assert.ok(apiWorkbench.handoff.some((item) => item.value.includes("POST /v1/fleet/templates/tmpl-edge-baseline:apply")));
assert.ok(apiWorkbench.handoff.some((item) => item.value.includes("GET /v1/fleet/template-results?templateId=tmpl-edge-baseline")));
assert.ok(apiWorkbench.handoff.some((item) => item.value.includes("ngfwctl fleet templates apply-plan 'tmpl-edge-baseline' --expected-candidate-revision 'sha256:candidate'")));
assert.ok(apiWorkbench.handoff.some((item) => item.value.includes("ngfwctl fleet templates apply 'tmpl-edge-baseline' --expected-candidate-revision 'sha256:candidate' --message <reason>")));
assert.equal(apiWorkbench.applyResultNodes.length, 2);
assert.equal(apiWorkbench.applyResultNodes[0].result, "applied");
assert.equal(apiWorkbench.applyResultNodes[1].result, "skipped");
assert.ok(apiWorkbench.handoff.some((item) => item.value.includes("ngfwctl fleet templates stage-candidate 'tmpl-edge-baseline' --expected-candidate-revision 'sha256:candidate'")));
assert.equal(apiWorkbench.custody.signed, false);
assert.equal(apiWorkbench.custody.retainedByServer, true);
const apiHandoff = serverTemplateHandoffText(apiWorkbench);
assert.match(apiHandoff, /Phragma Fleet local template API handoff/);
assert.match(apiHandoff, /Changed areas:/);
assert.match(apiHandoff, /Security rules: 7 ordered policy rules/);
assert.match(apiHandoff, /Apply-plan nodes:\n- not requested/);
assert.match(apiHandoff, /Apply result nodes:\n- local appliance: applied - template staged to local candidate revision sha256:candidate/);
assert.match(apiHandoff, /Scope: connected local appliance only; not authoritative fleet inventory/);
assert.match(apiHandoff, /Local template custody: unsigned local Fleet template registry draft/);
assert.match(apiHandoff, /no peer fan-out, distributed apply result, signed custody, HA fencing, or traffic failover/);
const apiPacket = serverTemplateInvestigationPacket(apiWorkbench);
assert.equal(apiPacket.schemaVersion, "phragma.investigation.handoff.v1");
assert.equal(apiPacket.kind, "fleet-template-api");
assert.equal(apiPacket.subject.id, "tmpl-edge-baseline");
assert.equal(apiPacket.summary.risk, "medium");
assert.equal(apiPacket.summary.changedAreas, apiWorkbench.changedAreas.length);
assert.match(apiPacket.summary.custodyBoundary, /no peer fan-out/);
assert.equal(apiPacket.summary.localTemplateCustody.retainedByServer, true);
assert.match(apiPacket.evidence.join("\n"), /apply_boundary=candidate-only workflow/);
assert.match(apiPacket.evidence.join("\n"), /local_template_custody=unsigned local Fleet template registry draft/);
assert.match(apiPacket.artifacts.handoffText, /Phragma Fleet local template API handoff/);

const apiPlanWorkbench = serverTemplateWorkbenchModel({
  id: "tmpl-edge-baseline",
  label: "Edge baseline API draft",
}, {
  template: { id: "tmpl-edge-baseline", name: "Edge baseline API draft", revision: "sha256:template", policySummary: { zones: 2, rules: 7 } },
  validation: { valid: true },
  candidateRevision: "sha256:candidate",
  result: "previewable",
  nodes: [
    { id: "local", name: "local appliance", role: "standalone", runtimeState: "unknown", runningVersion: "", eligible: false, status: "blocked", plannedAction: "hold; collect readiness evidence", blockers: ["runtime readiness needs positive evidence"] },
    { id: "fw-peer", name: "fw-peer", role: "passive", runtimeState: "ready", runningVersion: "17", eligible: true, status: "eligible", plannedAction: "handoff candidate apply through node-local workflow", blockers: [] },
  ],
  orchestrationBoundary: "multi-node apply plan only; no peer RPC, distributed commit custody, HA fencing, or running-policy apply",
}, "Template apply plan");
assert.equal(apiPlanWorkbench.applyPlanResult, "previewable");
assert.equal(apiPlanWorkbench.applyPlanNodes.length, 2);
assert.equal(apiPlanWorkbench.applyPlanNodes[1].eligible, true);
assert.match(serverTemplateHandoffText(apiPlanWorkbench), /fw-peer: eligible - handoff candidate apply through node-local workflow/);
const apiPlanPacket = serverTemplateInvestigationPacket(apiPlanWorkbench);
assert.equal(apiPlanPacket.summary.applyPlanNodes, 2);
assert.equal(apiPlanPacket.summary.eligiblePlanNodes, 1);
assert.equal(apiPlanPacket.artifacts.workbench.applyPlanNodes[0].blockers[0], "runtime readiness needs positive evidence");

const unsafeApiWorkbench = serverTemplateWorkbenchModel({ id: "tmpl bad'; cat /etc/passwd #", label: "Unsafe" }, {
  validation: { valid: true },
  candidateRevision: "sha256:candidate bad'; env #",
});
const unsafeApiHandoff = serverTemplateHandoffText(unsafeApiWorkbench);
assert.match(unsafeApiHandoff, /ngfwctl fleet templates validate 'tmpl bad'\\''; cat \/etc\/passwd #'/);
assert.match(unsafeApiHandoff, /--expected-candidate-revision 'sha256:candidate bad'\\''; env #'/);
assert.doesNotMatch(unsafeApiHandoff, /ngfwctl fleet templates validate tmpl bad'; cat/);

const cleanOrchestration = buildFleetModel({
  status: { hostname: "fw-primary", dataplane: { runningPolicyVersion: 44 } },
  running: {
    version: 44,
    policy: {
      zones: [{ name: "lan" }, { name: "wan" }],
      rules: [{ name: "allow-outbound" }],
      nat: { source: [{ name: "masq" }] },
      intel: { commercialUse: true },
    },
  },
  candidate: { policy: { zones: [{ name: "lan" }, { name: "wan" }], rules: [{ name: "allow-outbound" }], nat: { source: [{ name: "masq" }] }, intel: { commercialUse: true } } },
  candidateStatus: { dirty: false, changeCount: 0, candidateRevision: "sha256:clean" },
  feeds: { feeds: [{ name: "builtin", enabled: true, allowsCommercialUse: true }] },
  contentPackages: { packages: [readyPackage("app-id"), readyPackage("threat-id"), readyPackage("intel-feeds")] },
  releaseAcceptance: { ready: true, state: "ready", summary: {} },
  fleetNodes: {
    nodes: [
      { id: "fw-primary", name: "fw-primary", runningVersion: 44, role: "active", haReady: true, runtimeState: "healthy" },
      { id: "fw-secondary", name: "fw-secondary", runningVersion: 44, role: "passive", haReady: true, runtimeState: "ready" },
    ],
  },
  fleetTemplates: {
    templates: [{
      id: "tmpl-clean",
      name: "Clean baseline",
      scope: "local-appliance",
      revision: "sha256:template-clean",
      policySummary: { zones: 2, rules: 1, sourceNat: 1 },
    }],
  },
});

assert.equal(cleanOrchestration.orchestrationPreview.eligibleCount, 2);
assert.equal(cleanOrchestration.orchestrationPreview.positiveEvidenceNodes, 2);
assert.equal(cleanOrchestration.orchestrationPreview.blockers.length, 0);
assert.equal(cleanOrchestration.orchestrationPreview.fanout.title, "previewable");
assert.equal(cleanOrchestration.orchestrationPreview.boundary.peerRpc, false);
assert.equal(cleanOrchestration.orchestrationPreview.boundary.runningPolicyApply, false);
assert.ok(cleanOrchestration.orchestrationPreview.plan.some((item) => item.key === "fanout-preview" && item.boundary === "preview only" && item.command.includes("--preview-node-set eligible-only")));
const orchestrationHandoff = orchestrationHandoffText(cleanOrchestration.orchestrationPreview);
assert.match(orchestrationHandoff, /Phragma Fleet orchestration preview/);
assert.match(orchestrationHandoff, /Eligible nodes: 2\/2/);
assert.match(orchestrationHandoff, /Positive-evidence nodes: 2/);
assert.match(orchestrationHandoff, /No-peer-apply boundary: Fleet can assemble a redacted eligible-node preview packet only/);
assert.match(orchestrationHandoff, /no running-policy apply is performed from Fleet/);
assert.match(orchestrationHandoff, /no policy bodies, secrets, bearer tokens, node credentials/);
const orchestrationPacket = orchestrationPreviewInvestigationPacket(cleanOrchestration.orchestrationPreview);
assert.equal(orchestrationPacket.schemaVersion, "phragma.investigation.handoff.v1");
assert.equal(orchestrationPacket.kind, "fleet-orchestration-preview");
assert.equal(orchestrationPacket.summary.eligibleNodes, 2);
assert.equal(orchestrationPacket.summary.positiveEvidenceNodes, 2);
assert.equal(orchestrationPacket.summary.noPeerApplyBoundary.haTrafficControl, false);
assert.match(orchestrationPacket.summary.custodyBoundary, /no peer RPC/);
assert.match(orchestrationPacket.evidence.join("\n"), /redaction=no policy bodies/);
assert.equal(orchestrationPacket.artifacts.preview.nodes.length, 2);
assert.equal(orchestrationPacket.artifacts.preview.nodes[0].positiveEvidence.length >= 3, true);
assert.equal(orchestrationPacket.artifacts.preview.boundary.distributedResultCustody, false);
assert.ok(!JSON.stringify(orchestrationPacket).includes("allow-outbound"));

const directPreview = orchestrationPreviewModel({
  nodes: [{ id: "fw1", name: "fw1", roleLabel: "active", policyVersion: "v9", haTone: "ok", haLabel: "ready", runtimeTone: "ok", runtimeLabel: "healthy" }],
  templates: [{ key: "edge-policy", label: "Edge policy template" }],
  candidateDirty: false,
  release: { label: "ready", detail: "release gates recorded", tone: "ok" },
  content: { label: "ready", detail: "content packages ready", tone: "ok" },
});
assert.ok(directPreview.blockers.some((item) => item.key === "template"));
assert.ok(directPreview.blockers.some((item) => item.key === "inventory"));

const unknownRuntimePreview = orchestrationPreviewModel({
  nodes: [
    { id: "fw-unknown", name: "fw-unknown", roleLabel: "active", policyVersion: "v12", haTone: "ok", haLabel: "ready", runtimeTone: "info", runtimeLabel: "unknown" },
    { id: "fw-ok", name: "fw-ok", roleLabel: "passive", policyVersion: "v12", haTone: "ok", haLabel: "ready", runtimeTone: "ok", runtimeLabel: "healthy" },
  ],
  templates: [{ id: "tmpl-clean", key: "tmpl-clean", label: "Clean", serverBacked: true }],
  candidateDirty: false,
  release: { label: "ready", detail: "release gates recorded", tone: "ok" },
  content: { label: "ready", detail: "content packages ready", tone: "ok" },
});
assert.equal(unknownRuntimePreview.eligibleCount, 1);
assert.ok(unknownRuntimePreview.nodes.find((node) => node.id === "fw-unknown").reason.includes("system preflight needs positive evidence"));
assert.ok(unknownRuntimePreview.nodes.find((node) => node.id === "fw-unknown").missingEvidence.includes("system preflight needs positive evidence"));

const unsafeOrchestration = orchestrationPreviewModel({
  nodes: [{ id: "fw1", name: "fw1", roleLabel: "active", policyVersion: "v9", haTone: "ok", haLabel: "ready", runtimeTone: "ok", runtimeLabel: "healthy" }],
  templates: [{ id: "tmpl bad'; cat /etc/passwd #", key: "tmpl bad'; cat /etc/passwd #", label: "Unsafe", serverBacked: true }],
  candidateDirty: false,
  release: { label: "ready", detail: "release gates recorded", tone: "ok" },
  content: { label: "ready", detail: "content packages ready", tone: "ok" },
});
assert.ok(unsafeOrchestration.plan.find((item) => item.key === "fanout-preview").command.includes("'tmpl bad'\\''; cat /etc/passwd #'"));
const unsafeFleetPacket = orchestrationPreviewInvestigationPacket({
  ...unsafeOrchestration,
  nodes: Array.from({ length: 20 }, (_, idx) => ({ id: `fw-${idx}`, label: `fw-${idx} bearer token=secret-${idx}`, eligible: idx % 2 === 0, reason: `credential=secret-${idx}; runtime ok` })),
  blockers: [{ key: "secret", label: "token=abc", title: "Bearer token leaked", detail: "password=hunter2; /etc/openngfw/key" }],
});
const unsafeFleetJson = JSON.stringify(unsafeFleetPacket);
assert.equal(unsafeFleetPacket.artifacts.preview.nodes.length, 12);
assert.equal(unsafeFleetJson.includes("hunter2"), false);
assert.equal(unsafeFleetJson.includes("secret-1"), false);
assert.match(unsafeFleetJson, /credential=\[redacted\]/);

const invalidWorkbench = serverTemplateWorkbenchModel({ id: "tmpl-invalid", label: "Invalid" }, {
  validation: { valid: false, errors: ["rule action is required"] },
});
assert.equal(invalidWorkbench.risk.title, "blocked");
assert.equal(invalidWorkbench.risk.tone, "bad");
assert.equal(invalidWorkbench.changedAreas[0].key, "empty");

{
  const evidence = fleetNodeEvidenceModel({
    roleLabel: "active",
    policyVersion: "v12",
    runtimeLabel: "healthy",
    runtimeTone: "ok",
    haTone: "warn",
  });
  assert.equal(evidence.ready, false);
  assert.ok(evidence.positiveEvidence.includes("running policy v12"));
  assert.ok(evidence.positiveEvidence.includes("runtime healthy"));
  assert.ok(evidence.missingEvidence.includes("HA/readiness evidence needs review"));

  const custody = localTemplateCustodyModel("browser-preview");
  assert.equal(custody.signed, false);
  assert.equal(custody.retainedByServer, false);

  const boundary = noPeerApplyBoundaryModel();
  assert.equal(boundary.peerRpc, false);
  assert.equal(boundary.runningPolicyApply, false);
  assert.match(boundary.detail, /does not call peer RPCs/);
}

function readyPackage(kind) {
  return {
    kind,
    name: kind,
    state: "verified",
    version: "1.0.0",
    manifestSha256: "a".repeat(64),
    signatureStatus: "verified",
    source: "signed-test-package",
    provenance: ["unit-test"],
    regressionStatus: "passed",
    rolloutState: "staged",
    rollbackAvailable: true,
    contentReadiness: {
      productionReady: true,
      evidenceStatus: "passed",
      blockers: [],
      evidence: [
        { type: "license-review", artifact: "license.json", sha256: "b".repeat(64) },
      ],
    },
  };
}
