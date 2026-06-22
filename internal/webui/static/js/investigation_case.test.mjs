import assert from "node:assert/strict";

import { appIdRegressionSampleHandoffPacket, captureHandoffPacket, contentPackageLifecycleHandoffPacket, flowHandoffPacket, alertHandoffPacket, natPathHandoffPacket, vpnTunnelHandoffPacket } from "./investigation_packet.js";
import {
  INVESTIGATION_CASE_LIMITS,
  INVESTIGATION_CASE_SCHEMA,
  activeInvestigationServerCaseId,
  activeInvestigationServerCaseHref,
  addInvestigationCasePacket,
  appendInvestigationPacketToActiveServerCase,
  buildInvestigationCasePacket,
  caseItemCaptureSource,
  caseEvidencePayloadFromPacket,
  caseEvidencePayloadsFromItems,
  caseItemHasCaptureSource,
  clearActiveInvestigationServerCaseId,
  clearInvestigationCase,
  investigationCaseTargetSummary,
  investigationCase,
  investigationCaseItems,
  investigationCaseJson,
  investigationCaseRemediationPlan,
  investigationCaseRemediationActions,
  investigationCaseText,
  investigationCaseWorkbench,
  normalizeServerInvestigationSynthesis,
  normalizeInvestigationServerCaseId,
  removeInvestigationCaseItem,
  serverInvestigationCaseItems,
  setActiveInvestigationServerCaseId,
} from "./investigation_case.js";

function memoryStorage() {
  const data = new Map();
  return {
    getItem: (key) => data.has(key) ? data.get(key) : null,
    setItem: (key, value) => data.set(key, String(value)),
    removeItem: (key) => data.delete(key),
  };
}

function packet(id, route = "#/traffic") {
  return flowHandoffPacket({
    flowId: id,
    srcIp: "10.0.1.20",
    srcPort: 51515,
    destIp: "10.0.2.20",
    destPort: 443,
    protocol: "TCP",
    appId: "web-browsing",
  }, { route, collectedAt: "2026-06-18T12:00:00.000Z" });
}

{
  const synthesis = normalizeServerInvestigationSynthesis({
    schemaVersion: "phragma.investigation.server-synthesis.v1",
    source: "retained-server-records",
    state: "server-multi-flow-ready",
    status: "server multi-flow synthesis ready",
    detail: "Retained evidence records correlate across flows.",
    confidence: {
      score: 0.9,
      level: "high",
      basis: ["server-retained evidence records", "packet proof retained"],
    },
    coverage: {
      evidenceRecords: 3,
      serverRetainedRecords: 3,
      correlationKeys: 1,
      flowGroups: 1,
      multiRecordGroups: 1,
      captureProofRecords: 1,
      ownerRouteRecords: 2,
    },
    limitations: [
      "review-only synthesis; does not create authoritative tickets",
      "does not commit, publish, or mutate running policy",
    ],
    actions: [
      {
        id: "candidate-compare",
        owner: "Rules",
        label: "Compare candidate policy path",
        href: "#/rules?simRun=1",
        confidence: "high",
        detail: "Candidate review only.",
        safe: true,
      },
      {
        id: "unsafe",
        owner: "Ticket",
        label: "Create ticket",
        href: "https://tickets.example.invalid/new",
        safe: false,
      },
    ],
    flows: [{
      key: "flow:flow-77",
      title: "Threat flow",
      recordCount: 3,
      kinds: ["flow", "alert", "capture"],
      tuple: "TCP 10.0.1.20:51515 -> 10.0.2.20:443",
      captureProof: true,
      ownerRoutes: ["#/traffic?flowId=flow-77", "#/threats?flowId=flow-77"],
      limitations: [],
    }],
    mutatesPolicy: false,
    createsTicket: false,
  });

  assert.equal(synthesis.schemaVersion, "phragma.investigation.synthesis.v1");
  assert.equal(synthesis.state, "server-multi-flow-ready");
  assert.equal(synthesis.confidence.level, "high");
  assert.equal(synthesis.coverage.multiRecordGroups, 1);
  assert.equal(synthesis.serverRetainedCount, 3);
  assert.equal(synthesis.captureReadyCount, 1);
  assert.equal(synthesis.readyOwnerCount, 2);
  assert.equal(synthesis.serverActions.length, 1);
  assert.equal(synthesis.serverActions[0].href, "#/rules?simRun=1");
  assert.equal(synthesis.primaryActionId, "candidate-compare");
  assert.equal(synthesis.rows[0].status, "ready");
  assert.match(synthesis.limitations.join(" "), /does not create authoritative tickets/);
  assert.equal(synthesis.mutatesPolicy, false);
  assert.equal(synthesis.createsTicket, false);
}

{
  const storage = memoryStorage();
  assert.equal(normalizeInvestigationServerCaseId("case-20260622T120000Z-abcdef12"), "case-20260622T120000Z-abcdef12");
  assert.equal(normalizeInvestigationServerCaseId("case-20260622T120000Z-ABCDEF12"), "");
  assert.equal(normalizeInvestigationServerCaseId("token=secret"), "");
  assert.equal(activeInvestigationServerCaseId({ storage }), "");
  assert.equal(setActiveInvestigationServerCaseId("case-20260622T120000Z-abcdef12", { storage }), "case-20260622T120000Z-abcdef12");
  assert.equal(activeInvestigationServerCaseId({ storage }), "case-20260622T120000Z-abcdef12");
  assert.equal(activeInvestigationServerCaseHref({ storage }), "#/investigation?activeCase=case-20260622T120000Z-abcdef12");
  assert.equal(setActiveInvestigationServerCaseId("unsafe", { storage }), "");
  assert.equal(activeInvestigationServerCaseId({ storage }), "");
  setActiveInvestigationServerCaseId("case-20260622T120001Z-abcdef13", { storage });
  clearActiveInvestigationServerCaseId({ storage });
  assert.equal(activeInvestigationServerCaseId({ storage }), "");
}

{
  const storage = memoryStorage();
  setActiveInvestigationServerCaseId("case-20260622T120000Z-abcdef12", { storage });
  const packet = contentPackageLifecycleHandoffPacket({
    kind: "app-id",
    name: "Phragma App-ID catalog",
    source: "/var/lib/openngfw/content-import/app-id-package token=server-secret",
    version: "1.2.3",
    blockers: ["sourcePath=/tmp/operator-upload access_token=secret-token"],
    contentReadinessEvidence: [
      { type: "app-regression-corpus", artifact: "/home/opc/private/app-regression.json", sha256: "a".repeat(64), sha256Short: "a".repeat(12) },
    ],
  }, {
    route: "#/intel?surface=app-id&drawer=review&token=secret-token&path=/var/lib/openngfw/content",
    lifecycleAction: "review",
    collectedAt: "2026-06-18T12:00:00.000Z",
  });
  const calls = [];
  const result = await appendInvestigationPacketToActiveServerCase(packet, {
    storage,
    pinnedAt: "2026-06-18T12:00:01.000Z",
    appendEvidence: async (id, evidence) => calls.push({ id, evidence }),
  });
  assert.equal(result.appended, true);
  assert.equal(result.activeCaseId, "case-20260622T120000Z-abcdef12");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].id, "case-20260622T120000Z-abcdef12");
  assert.equal(calls[0].evidence[0].kind, "content-package-lifecycle");
  assert.equal(calls[0].evidence[0].target.kind, "content-package-lifecycle");
  assert.equal(calls[0].evidence[0].target.pinnedAt, "2026-06-18T12:00:01.000Z");
  assert.equal(calls[0].evidence[0].source.route, "");
  assert.equal(calls[0].evidence[0].source.routeRedacted, true);
  assert.match(calls[0].evidence[0].target.route, /\[redacted\]/);
  assert.match(calls[0].evidence[0].target.route, /\[server-local path redacted\]/);
  assert.doesNotMatch(JSON.stringify(calls[0].evidence[0]), /secret-token|server-secret|\/var\/lib\/openngfw|\/home\/opc|sourcePath=/);
}

{
  const storage = memoryStorage();
  const packet = contentPackageLifecycleHandoffPacket({
    kind: "threat-id",
    name: "Phragma Threat-ID catalog",
    source: "/tmp/content token=fallback-secret",
  }, {
    route: "#/intel?surface=threat-id&drawer=quality&token=fallback-secret&path=/tmp/content",
    lifecycleAction: "quality",
    collectedAt: "2026-06-18T12:00:00.000Z",
  });
  const result = await appendInvestigationPacketToActiveServerCase(packet, {
    storage,
    pinnedAt: "2026-06-18T12:00:02.000Z",
    appendEvidence: async () => assert.fail("appendEvidence should not run without an active case"),
  });
  assert.equal(result.appended, false);
  assert.equal(result.reason, "no active case");
  assert.equal(result.payload.kind, "content-package-lifecycle");
  assert.equal(result.payload.target.routeRedacted, true);
  assert.match(JSON.stringify(result.payload.target), /\[server-local path redacted\]/);
  assert.doesNotMatch(JSON.stringify(result.payload), /fallback-secret|\/tmp\/content/);
}

{
  const storage = memoryStorage();
  const first = addInvestigationCasePacket(packet("flow-1"), { storage, pinnedAt: "2026-06-18T12:00:01.000Z" });
  assert.equal(first.replaced, false);
  assert.equal(investigationCaseItems({ storage }).length, 1);

  const replaced = addInvestigationCasePacket(packet("flow-1"), { storage, pinnedAt: "2026-06-18T12:00:02.000Z" });
  assert.equal(replaced.replaced, true);
  assert.equal(investigationCaseItems({ storage }).length, 1);
  assert.equal(investigationCaseItems({ storage })[0].pinnedAt, "2026-06-18T12:00:02.000Z");

  addInvestigationCasePacket(alertHandoffPacket({
    flowId: "alert-flow-1",
    threatId: "threat.http.shell",
    threatName: "Suspicious web shell",
  }, { route: "#/threats?alert=alert-flow-1", collectedAt: "2026-06-18T12:00:00.000Z" }), { storage, pinnedAt: "2026-06-18T12:00:03.000Z" });
  const items = investigationCaseItems({ storage });
  assert.deepEqual(items.map((item) => item.kind), ["alert", "flow"]);

  const casePacket = buildInvestigationCasePacket(items, { collectedAt: "2026-06-18T12:01:00.000Z" });
  assert.equal(casePacket.schemaVersion, INVESTIGATION_CASE_SCHEMA);
  assert.equal(casePacket.summary.itemCount, 2);
  assert.equal(casePacket.summary.kinds.alert, 1);
  assert.equal(casePacket.summary.kinds.flow, 1);
  assert.ok(casePacket.summary.rootCause.title);
  assert.ok(casePacket.workbench.actions.length > 0);
  assert.match(investigationCaseJson(casePacket), /"schemaVersion": "phragma\.investigation\.case\.v1"/);
  assert.match(investigationCaseText(casePacket), /Phragma investigation case/);
  assert.match(investigationCaseText(casePacket), /\[case actions\]/);

  const afterRemove = removeInvestigationCaseItem(items[0].key, { storage, removedAt: "2026-06-18T12:02:00.000Z" });
  assert.equal(afterRemove.items.length, 1);
  clearInvestigationCase({ storage, clearedAt: "2026-06-18T12:03:00.000Z" });
  assert.equal(investigationCase({ storage }).items.length, 0);
}

{
  const payload = caseEvidencePayloadFromPacket(packet("flow-server"), { pinnedAt: "2026-06-18T12:00:01.000Z" });
  assert.equal(payload.kind, "flow");
  assert.equal(payload.packet.kind, "flow");
  assert.equal(payload.target.kind, "flow");
  assert.equal(payload.target.key, payload.key);
  assert.equal(payload.target.source, "webui");
  assert.equal(payload.target.pinnedAt, "2026-06-18T12:00:01.000Z");
  const hydrated = serverInvestigationCaseItems({
    id: "case-20260622T120000Z-abcdef12",
    evidence: [{ payload }],
  });
  assert.equal(hydrated.length, 1);
  assert.equal(hydrated[0].kind, "flow");
  assert.equal(hydrated[0].subject.tuple.srcIp, "10.0.1.20");
  assert.match(hydrated[0].source.route, /#\/traffic/);
  assert.equal(hydrated[0].serverCustody.caseId, "case-20260622T120000Z-abcdef12");
  assert.equal(caseEvidencePayloadsFromItems(hydrated)[0].target.kind, "flow");

  const unsafePayload = caseEvidencePayloadFromPacket(packet("flow-unsafe", "#/traffic?flowId=flow-unsafe&token=super-secret&path=/var/log/openngfw/eve.json"), { pinnedAt: "2026-06-18T12:00:02.000Z" });
  assert.equal(unsafePayload.source.route, "");
  assert.equal(unsafePayload.source.routeRedacted, true);
  assert.match(unsafePayload.target.route, /\[redacted\]/);
  assert.match(unsafePayload.target.route, /\[server-local path redacted\]/);
  assert.doesNotMatch(JSON.stringify(unsafePayload.target), /super-secret|\/var\/log\/openngfw\/eve\.json/);
}

{
  const longTitle = "Hydrated source record ".repeat(30) + "token=super-secret /var/log/openngfw/eve.json";
  const hydrated = serverInvestigationCaseItems({
    id: "case-20260622T120000Z-abcdef12",
    evidence: [{
      id: "ev-1",
      addedAt: "2026-06-18T12:05:00.000Z",
      addedBy: "operator",
      target: {
        kind: "flow",
        key: "k".repeat(400),
        route: "#/traffic?flowId=flow-server&token=super-secret&path=/var/log/openngfw/eve.json",
        source: "server-hydrated",
        title: longTitle,
        pinnedAt: "2026-06-18T12:00:01.000Z",
        collectedAt: "2026-06-18T12:00:00.000Z",
      },
      payload: caseEvidencePayloadFromPacket(packet("flow-server"), { pinnedAt: "2026-06-18T12:00:01.000Z" }),
    }],
  });
  assert.equal(hydrated.length, 1);
  const target = investigationCaseTargetSummary(hydrated[0]);
  assert.equal(target.kind, "flow");
  assert.equal(target.source, "server-hydrated");
  assert.equal(target.pinnedAt, "2026-06-18T12:00:01.000Z");
  assert.equal(target.collectedAt, "2026-06-18T12:00:00.000Z");
  assert.equal(target.addedAt, "2026-06-18T12:05:00.000Z");
  assert.ok(target.key.length <= INVESTIGATION_CASE_LIMITS.maxTargetKeyChars);
  assert.ok(target.title.length <= INVESTIGATION_CASE_LIMITS.maxTargetTitleChars);
  assert.ok(target.route.length <= INVESTIGATION_CASE_LIMITS.maxTargetRouteChars);
  assert.match(JSON.stringify(target), /\[redacted\]/);
  assert.match(JSON.stringify(target), /\[server-local path redacted\]/);
  assert.doesNotMatch(JSON.stringify(target), /super-secret|\/var\/log\/openngfw\/eve\.json/);
  const appendPayload = caseEvidencePayloadsFromItems(hydrated)[0];
  assert.deepEqual(appendPayload.target, target);
}

{
  const storage = memoryStorage();
  addInvestigationCasePacket(packet("flow-77"), { storage, pinnedAt: "2026-06-18T12:00:01.000Z" });
  addInvestigationCasePacket(alertHandoffPacket({
    flowId: "flow-77",
    srcIp: "10.0.1.20",
    srcPort: 51515,
    destIp: "10.0.2.20",
    destPort: 443,
    protocol: "TCP",
    threatId: "threat.http.shell",
    threatName: "Suspicious web shell",
    signatureId: "9000001",
    action: "blocked",
    policyVersionKnown: true,
    policyVersion: 8,
  }, { route: "#/threats?flowId=flow-77", collectedAt: "2026-06-18T12:00:00.000Z" }), { storage, pinnedAt: "2026-06-18T12:00:02.000Z" });

  const workbench = investigationCaseWorkbench(investigationCaseItems({ storage }));
  assert.equal(workbench.itemCount, 2);
  assert.match(workbench.rootCause.title, /Threat evidence/);
  assert.equal(workbench.metrics.find((metric) => metric.label === "Shared tuples").value, "1");
  assert.ok(workbench.rows.some((row) => row.verdict === "blocked"));
  assert.ok(workbench.rows.some((row) => row.policyVersion === "v8"));
  assert.ok(workbench.actions.some((action) => action.id === "explain" && action.href.includes("#/troubleshoot?")));
  assert.ok(workbench.actions.some((action) => action.id === "capture" && action.href.includes("intent=capture")));
  assert.ok(workbench.actions.some((action) => action.id === "threat"));
  assert.equal(workbench.remediationPlan.status, "ready");
  assert.equal(workbench.remediationPlan.primaryActionId, "threat-exception");
  assert.match(workbench.remediationPlan.title, /Threat-to-policy remediation ready/);
  assert.equal(workbench.remediationPlan.evidence.find((item) => item.id === "traffic").ready, true);
  assert.equal(workbench.remediationPlan.evidence.find((item) => item.id === "threat").ready, true);
  assert.equal(workbench.remediationPlan.evidence.find((item) => item.id === "capture").ready, true);
  assert.equal(workbench.remediationPlan.steps.find((step) => step.id === "correlate").status, "complete");
  assert.equal(workbench.remediationPlan.steps.find((step) => step.id === "owner-workspace").status, "ready");

  const remediation = workbench.remediationActions;
  assert.equal(remediation.find((action) => action.id === "explain").disabled, false);
  assert.match(remediation.find((action) => action.id === "explain").href, /#\/troubleshoot\?/);
  assert.match(remediation.find((action) => action.id === "capture").href, /intent=capture/);
  assert.match(remediation.find((action) => action.id === "candidate-rule").href, /#\/rules\?/);
  assert.match(remediation.find((action) => action.id === "candidate-rule").href, /simSource=POLICY_SOURCE_CANDIDATE/);
  assert.match(remediation.find((action) => action.id === "candidate-rule").href, /simRun=1/);
  assert.match(remediation.find((action) => action.id === "candidate-rule").href, /caseKey=/);
  assert.match(remediation.find((action) => action.id === "candidate-rule").href, /caseAction=candidate-rule/);
  assert.match(remediation.find((action) => action.id === "candidate-rule").href, /caseKind=flow|caseKind=alert/);
  assert.match(remediation.find((action) => action.id === "threat-exception").href, /#\/threats\?/);
  assert.match(remediation.find((action) => action.id === "threat-exception").href, /signatureId=9000001/);
  assert.match(remediation.find((action) => action.id === "threat-exception").href, /caseAction=threat-exception/);
  assert.match(remediation.find((action) => action.id === "nat-route").href, /#\/nat\?/);
  assert.match(remediation.find((action) => action.id === "nat-route").href, /caseAction=nat-route/);

  const exported = investigationCaseText(buildInvestigationCasePacket(investigationCaseItems({ storage })));
  assert.match(exported, /\[multi-evidence fix plan\]/);
  assert.match(exported, /status=ready/);
  assert.match(exported, /Threat-to-policy remediation ready/);
}

{
  const storage = memoryStorage();
  addInvestigationCasePacket(flowHandoffPacket({
    flowId: "flow-a",
    srcIp: "10.10.1.10",
    srcPort: 50100,
    destIp: "10.10.2.20",
    destPort: 443,
    protocol: "TCP",
    appId: "web-browsing",
  }, { route: "#/traffic?flowId=flow-a" }), { storage, pinnedAt: "2026-06-18T12:00:01.000Z" });
  addInvestigationCasePacket(alertHandoffPacket({
    flowId: "flow-a",
    srcIp: "10.10.1.10",
    srcPort: 50100,
    destIp: "10.10.2.20",
    destPort: 443,
    protocol: "TCP",
    threatId: "threat.http.shell",
    threatName: "Suspicious web shell",
    signatureId: "9000001",
    action: "blocked",
  }, { route: "#/threats?flowId=flow-a" }), { storage, pinnedAt: "2026-06-18T12:00:02.000Z" });
  addInvestigationCasePacket(captureHandoffPacket({
    query: {
      flowId: "flow-a",
      protocol: "PROTOCOL_TCP",
      srcIp: "10.10.1.10",
      srcPort: 50100,
      destIp: "10.10.2.20",
      destPort: 443,
    },
    capturePlan: {
      interface: "ens5",
      protocol: "tcp",
      srcIp: "10.10.1.10",
      srcPort: 50100,
      destIp: "10.10.2.20",
      destPort: 443,
    },
  }, { route: "#/troubleshoot?flowId=flow-a&intent=capture" }), { storage, pinnedAt: "2026-06-18T12:00:03.000Z" });
  addInvestigationCasePacket(natPathHandoffPacket({
    flow: {
      fromZone: "outside",
      toZone: "dmz",
      srcIp: "198.51.100.10",
      srcPort: 51515,
      destIp: "203.0.113.10",
      destPort: 8443,
      protocol: "PROTOCOL_TCP",
    },
    running: {
      verdict: "EXPLAIN_VERDICT_DEFAULT_DROP",
      defaultPolicy: true,
      policySource: "POLICY_SOURCE_RUNNING",
    },
    candidate: {
      verdict: "EXPLAIN_VERDICT_ALLOWED",
      matchedRule: "allow-public-admin",
      policySource: "POLICY_SOURCE_CANDIDATE",
      routeProfile: { matched: true },
    },
    delta: {
      changed: true,
      headline: "Candidate changes path behavior",
      rows: [{ label: "Verdict", running: "default drop", candidate: "allowed", changed: true }],
    },
  }, { route: "#/nat?fromZone=outside&toZone=dmz&run=1" }), { storage, pinnedAt: "2026-06-18T12:00:04.000Z" });

  const workbench = investigationCaseWorkbench(investigationCaseItems({ storage }));
  assert.equal(workbench.remediationGroups.length, 2);
  assert.equal(workbench.remediationPlan.groups.length, 2);
  assert.equal(workbench.remediationPlan.groupedReadiness, "2/2");
  const threatGroup = workbench.remediationGroups.find((group) => group.title.includes("Threat"));
  const natGroup = workbench.remediationGroups.find((group) => group.title.includes("NAT/route"));
  assert.ok(threatGroup);
  assert.ok(natGroup);
  assert.equal(threatGroup.status, "ready");
  assert.equal(natGroup.status, "ready");
  assert.match(threatGroup.handoff, /Route owners:/);
  assert.match(threatGroup.handoff, /Do not mutate running policy directly/);
  assert.match(natGroup.handoff, /candidate-delta/);
  assert.ok(threatGroup.owners.some((owner) => owner.owner === "Threats" && owner.href.includes("flow-a")));
  assert.ok(threatGroup.owners.some((owner) => owner.owner === "Rules" && owner.href.includes("10.10.1.10")));
  assert.ok(natGroup.owners.some((owner) => owner.owner === "NAT" && owner.href.includes("203.0.113.10")));
  assert.ok(natGroup.owners.some((owner) => owner.owner === "Rules" && owner.href.includes("198.51.100.10")));
  assert.notEqual(
    threatGroup.owners.find((owner) => owner.owner === "Rules")?.href,
    natGroup.owners.find((owner) => owner.owner === "Rules")?.href,
  );
  const exported = investigationCaseText(buildInvestigationCasePacket(investigationCaseItems({ storage })));
  assert.match(exported, /\[grouped remediation handoffs\]/);
  assert.match(exported, /Threat remediation group 1|Threat remediation group 2/);
  assert.match(exported, /NAT\/route remediation group 1|NAT\/route remediation group 2/);
  assert.match(exported, /owner=Rules action=Plan allow\/drop rule state=ready/);
}

{
  const storage = memoryStorage();
  addInvestigationCasePacket(packet("flow-42"), { storage, pinnedAt: "2026-06-18T12:00:01.000Z" });
  const [item] = investigationCaseItems({ storage });
  assert.equal(caseItemHasCaptureSource(item), true);
  assert.deepEqual(caseItemCaptureSource(item), {
    flowId: "flow-42",
    protocol: "TCP",
    srcIp: "10.0.1.20",
    srcPort: 51515,
    destIp: "10.0.2.20",
    destPort: 443,
  });
}

{
  const storage = memoryStorage();
  addInvestigationCasePacket(natPathHandoffPacket({
    flow: {
      fromZone: "outside",
      toZone: "dmz",
      srcIp: "198.51.100.10",
      srcPort: 51515,
      destIp: "203.0.113.10",
      destPort: 443,
      protocol: "PROTOCOL_TCP",
    },
    running: {
      verdict: "EXPLAIN_VERDICT_DEFAULT_DROP",
      defaultPolicy: true,
      policySource: "POLICY_SOURCE_RUNNING",
    },
    candidate: {
      verdict: "EXPLAIN_VERDICT_ALLOWED",
      matchedRule: "allow-public-web",
      matchedRuleIndex: 3,
      policySource: "POLICY_SOURCE_CANDIDATE",
      routeProfile: { matched: true },
    },
    delta: {
      changed: true,
      tone: "bad",
      headline: "Candidate changes path behavior",
      rows: [
        { label: "Verdict", running: "default drop", candidate: "allowed", changed: true },
        { label: "DNAT", running: "no match", candidate: "public-https", changed: true },
      ],
      warnings: ["candidate route unresolved: no route"],
    },
  }, { route: "#/nat?fromZone=outside&toZone=dmz&run=1" }), { storage, pinnedAt: "2026-06-18T12:00:01.000Z" });
  const [item] = investigationCaseItems({ storage });
  assert.equal(item.kind, "nat-path");
  assert.equal(item.source.route, "#/nat?fromZone=outside&toZone=dmz&run=1");
  assert.equal(caseItemHasCaptureSource(item), true);
  assert.deepEqual(caseItemCaptureSource(item), {
    flowId: "",
    protocol: "TCP",
    srcIp: "198.51.100.10",
    srcPort: 51515,
    destIp: "203.0.113.10",
    destPort: 443,
  });
  const actions = investigationCaseRemediationActions(investigationCaseItems({ storage }));
  assert.equal(actions.find((action) => action.id === "nat-route").disabled, false);
  assert.match(actions.find((action) => action.id === "nat-route").href, /#\/nat\?/);
  assert.equal(actions.find((action) => action.id === "candidate-rule").disabled, false);
}

{
  const storage = memoryStorage();
  addInvestigationCasePacket(vpnTunnelHandoffPacket({
    kind: "wireguard",
    kindLabel: "WireGuard",
    id: "wireguard:wg0:laptop",
    name: "wg0:laptop",
    interfaceName: "wg0",
    peerName: "laptop",
    localPrefixes: ["10.99.0.1/24"],
    remotePrefixes: ["10.99.0.2/32"],
    targets: [{
      name: "wg0:laptop",
      srcIp: "10.99.0.1",
      destIp: "10.99.0.2",
      protocol: "PROTOCOL_ANY",
    }],
  }, { route: "#/netvpn?drawer=tunnel&kind=wireguard&iface=wg0&peer=laptop" }), { storage, pinnedAt: "2026-06-18T12:00:01.000Z" });
  const [item] = investigationCaseItems({ storage });
  assert.equal(item.kind, "vpn-tunnel");
  assert.equal(item.source.route, "#/netvpn?drawer=tunnel&kind=wireguard&iface=wg0&peer=laptop");
  assert.equal(caseItemHasCaptureSource(item), true);
  assert.equal(caseItemCaptureSource(item).srcIp, "10.99.0.1");
  assert.equal(caseItemCaptureSource(item).destIp, "10.99.0.2");
  assert.equal(investigationCaseWorkbench(investigationCaseItems({ storage })).metrics.find((metric) => metric.label === "Items").value, "1");
}

{
  const storage = memoryStorage();
  addInvestigationCasePacket(contentPackageLifecycleHandoffPacket({
    kind: "app-id",
    name: "App-ID",
    badge: "review",
    version: "1.2.3",
    decision: {
      label: "review required",
      cls: "warn",
      detail: "Attach production evidence.",
      nextAction: "Review package evidence.",
      checks: [{ key: "signature", label: "Signature", status: "verified", cls: "ok" }],
      blockers: ["production evidence"],
    },
  }, { route: "#/intel?surface=app-id&drawer=review", lifecycleAction: "review" }), { storage, pinnedAt: "2026-06-18T12:00:01.000Z" });
  const [item] = investigationCaseItems({ storage });
  assert.equal(item.kind, "content-package-lifecycle");
  assert.equal(item.source.route, "#/intel?surface=app-id&drawer=review");
  assert.equal(caseItemHasCaptureSource(item), false);
  assert.match(investigationCaseText(buildInvestigationCasePacket(investigationCaseItems({ storage }))), /content-package-lifecycle/);
}

{
  const storage = memoryStorage();
  addInvestigationCasePacket(captureHandoffPacket({
    query: {
      flowId: "capture-flow-1",
      protocol: "PROTOCOL_UDP",
      srcIp: "10.0.3.10",
      srcPort: 53000,
      destIp: "10.0.2.53",
      destPort: 53,
    },
    capturePlan: {
      interface: "ens5",
      protocol: "udp",
      srcIp: "10.0.3.10",
      srcPort: 53000,
      destIp: "10.0.2.53",
      destPort: 53,
      outputPath: "/var/log/openngfw/pcap/phragma-dns.pcap",
    },
  }, { route: "#/troubleshoot?flowId=capture-flow-1" }), { storage, pinnedAt: "2026-06-18T12:00:01.000Z" });
  const [item] = investigationCaseItems({ storage });
  assert.equal(caseItemHasCaptureSource(item), true);
  assert.equal(caseItemCaptureSource(item).flowId, "capture-flow-1");
  assert.equal(caseItemCaptureSource(item).destPort, 53);
  assert.equal(item.summary.outputPath, "[server-local path redacted]");
  assert.equal(item.packet.summary.outputPath, "[server-local path redacted]");
  assert.equal(item.packet.artifacts.capturePlan.outputPath, "[server-local path redacted]");
  const actions = investigationCaseRemediationActions(investigationCaseItems({ storage }));
  const hrefs = actions.map((action) => action.href).join("\n");
  assert.doesNotMatch(hrefs, /\/var\/log|phragma-dns\.pcap|token|secret/i);
  const casePacket = buildInvestigationCasePacket(investigationCaseItems({ storage }));
  assert.match(investigationCaseText(casePacket), /\[server-local path redacted\]/);
  assert.doesNotMatch(investigationCaseJson(casePacket), /\/var\/log|phragma-dns\.pcap/i);
  assert.equal(actions.find((action) => action.id === "threat-exception").disabled, true);
}

{
  const storage = memoryStorage();
  const unsafeRoute = "#/traffic?flowId=unsafe-flow&token=Bearer-secret&password=secret&path=/etc/passwd&file=file:/tmp/pcap";
  addInvestigationCasePacket(packet("unsafe-flow", unsafeRoute), { storage, pinnedAt: "2026-06-18T12:00:01.000Z" });
  const [item] = investigationCaseItems({ storage });
  assert.equal(item.source.route, "");
  assert.equal(item.packet.source.route, "");
  assert.equal(item.source.routeRedacted, true);
  assert.equal(item.packet.source.routeRedacted, true);

  const casePacket = buildInvestigationCasePacket(investigationCaseItems({ storage }), { route: unsafeRoute });
  assert.equal(casePacket.source.route, "");
  assert.equal(casePacket.summary.redactedRouteCount, 1);
  const legacyHrefs = casePacket.workbench.actions.map((action) => action.href).join("\n");
  assert.doesNotMatch(legacyHrefs, /Bearer-secret|password|\/etc\/passwd|file:|\/tmp\/pcap/i);
  const exported = investigationCaseText(casePacket);
  assert.match(exported, /route=redacted unsafe route/);
  assert.doesNotMatch(exported, /Bearer-secret|password|\/etc\/passwd|file:|\/tmp\/pcap/i);
  const actions = investigationCaseRemediationActions(investigationCaseItems({ storage }));
  for (const action of actions) {
    assert.doesNotMatch(action.href || "", /Bearer-secret|password|\/etc\/passwd|file:|\/tmp\/pcap/i);
  }
}

{
  const storage = memoryStorage();
  addInvestigationCasePacket(appIdRegressionSampleHandoffPacket({
    queueId: "appid-q-1",
    kind: "APP_ID_OBSERVATION_KIND_UNKNOWN",
    appId: "unknown",
    protocol: "TCP",
    destPort: 8443,
    sampleSrcIp: "10.0.1.40",
    sampleSrcPort: 51515,
    sampleDestIp: "10.0.2.40",
    sampleFlowId: "appid-flow-1",
    suggestedApplication: { name: "weird-admin" },
  }, { route: "#/traffic?mode=app-id&queueId=appid-q-1" }), { storage, pinnedAt: "2026-06-18T12:00:01.000Z" });
  const [item] = investigationCaseItems({ storage });
  assert.equal(caseItemHasCaptureSource(item), true);
  assert.deepEqual(caseItemCaptureSource(item), {
    flowId: "appid-flow-1",
    protocol: "TCP",
    srcIp: "10.0.1.40",
    srcPort: 51515,
    destIp: "10.0.2.40",
    destPort: 8443,
  });
  const actions = investigationCaseRemediationActions(investigationCaseItems({ storage }));
  const appAction = actions.find((action) => action.id === "app-id");
  assert.equal(appAction.disabled, false);
  assert.match(appAction.href, /#\/traffic\?mode=app-id/);
  assert.match(appAction.href, /queueId=appid-q-1/);
  assert.match(appAction.href, /caseAction=app-id/);
}

{
  const actions = investigationCaseRemediationActions([{
    key: "alert:no-sig",
    pinnedAt: "2026-06-18T12:00:01.000Z",
    packet: alertHandoffPacket({
      flowId: "alert-no-sig",
      threatId: "threat.no.sid",
      threatName: "No SID threat",
      srcIp: "10.0.1.20",
      destIp: "10.0.2.20",
      protocol: "TCP",
    }, { route: "#/threats?flowId=alert-no-sig" }),
  }]);
  const threatAction = actions.find((action) => action.id === "threat-exception");
  assert.equal(threatAction.disabled, true);
  assert.match(threatAction.disabledReason, /no signature ID/);
  assert.equal(actions.find((action) => action.id === "candidate-rule").disabled, false);
  const plan = investigationCaseRemediationPlan({
    rows: [{
      kind: "alert",
      verdict: "unknown",
      captureReady: true,
      policyVersion: "",
      app: "unknown",
      source: { srcIp: "10.0.1.20", destIp: "10.0.2.20" },
    }],
    remediationActions: actions,
    sharedTupleCount: 0,
  });
  assert.equal(plan.status, "needs evidence");
  assert.equal(plan.evidence.find((item) => item.id === "threat").ready, true);
  assert.equal(plan.steps.find((step) => step.id === "correlate").status, "missing");
  assert.equal(plan.steps.find((step) => step.id === "owner-workspace").status, "ready");
}

{
  const storage = memoryStorage();
  for (let i = 0; i < INVESTIGATION_CASE_LIMITS.maxItems + 5; i += 1) {
    addInvestigationCasePacket(packet(`flow-${i}`, `#/traffic?flowId=flow-${i}`), {
      storage,
      pinnedAt: new Date(Date.UTC(2026, 5, 18, 12, 0, i)).toISOString(),
    });
  }
  const items = investigationCaseItems({ storage });
  assert.equal(items.length, INVESTIGATION_CASE_LIMITS.maxItems);
  assert.equal(items[0].subject.id, `flow-${INVESTIGATION_CASE_LIMITS.maxItems + 4}`);
  assert.equal(items.at(-1).subject.id, "flow-5");
}

{
  const storage = memoryStorage();
  assert.throws(() => addInvestigationCasePacket({}, { storage }), /schema/);
  storage.setItem("phragma.investigation.case.v1", "{malformed");
  assert.equal(investigationCaseItems({ storage }).length, 0);
}
