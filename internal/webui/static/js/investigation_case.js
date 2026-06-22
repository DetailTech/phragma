import {
  INVESTIGATION_PACKET_SCHEMA,
  investigationPacketText,
} from "./investigation_packet.js";
import { investigationHashFromFlow } from "./investigation_route.js";

export const INVESTIGATION_CASE_SCHEMA = "phragma.investigation.case.v1";
export const INVESTIGATION_CASE_STORAGE_KEY = "phragma.investigation.case.v1";
export const INVESTIGATION_ACTIVE_SERVER_CASE_STORAGE_KEY = "phragma.investigation.active-server-case.v1";

export const INVESTIGATION_CASE_LIMITS = Object.freeze({
  maxItems: 50,
  maxPacketChars: 60000,
  maxTargetKeyChars: 240,
  maxTargetRouteChars: 1000,
  maxTargetSourceChars: 80,
  maxTargetTitleChars: 240,
});

export function investigationCase({ storage = defaultStorage() } = {}) {
  return readEnvelope(storage);
}

export function investigationCaseItems(options = {}) {
  return investigationCase(options).items;
}

export function caseItemCaptureSource(item = {}) {
  const packet = item.packet || {};
  const artifacts = packet.artifacts || {};
  const summary = packet.summary || item.summary || {};
  const tuple = packet.subject?.tuple || item.subject?.tuple || {};
  const captureJobPlan = artifacts.captureJob?.plan || {};
  const capturePlan = artifacts.capturePlan || {};
  const captureSubject = artifacts.captureSubject || {};
  const query = artifacts.query || {};
  const result = artifacts.result || {};
  const flow = artifacts.flow || {};
  const alert = artifacts.alert || {};
  const observation = artifacts.observation || {};
  return {
    flowId: firstValue(
      captureSubject.flowId,
      query.flowId,
      result.flowId,
      flow.flowId,
      alert.flowId,
      observation.sampleFlowId,
      summary.flowId,
      summary.sampleFlowId,
      capturePlan.flowId,
      captureJobPlan.flowId,
    ),
    protocol: firstValue(
      captureSubject.protocol,
      tuple.protocol,
      query.protocol,
      result.protocol,
      flow.protocol,
      alert.protocol,
      observation.protocol,
      summary.protocol,
      capturePlan.protocol,
      captureJobPlan.protocol,
    ),
    srcIp: firstValue(
      captureSubject.srcIp,
      tuple.srcIp,
      query.srcIp,
      flow.srcIp,
      alert.srcIp,
      observation.sampleSrcIp,
      summary.srcIp,
      capturePlan.srcIp,
      captureJobPlan.srcIp,
    ),
    srcPort: firstValue(
      captureSubject.srcPort,
      tuple.srcPort,
      query.srcPort,
      flow.srcPort,
      alert.srcPort,
      observation.sampleSrcPort,
      summary.srcPort,
      summary.sampleSrcPort,
      capturePlan.srcPort,
      captureJobPlan.srcPort,
    ),
    destIp: firstValue(
      captureSubject.destIp,
      tuple.destIp,
      query.destIp,
      flow.destIp,
      alert.destIp,
      observation.sampleDestIp,
      summary.destIp,
      capturePlan.destIp,
      captureJobPlan.destIp,
    ),
    destPort: firstValue(
      captureSubject.destPort,
      tuple.destPort,
      query.destPort,
      flow.destPort,
      alert.destPort,
      observation.destPort,
      summary.destPort,
      capturePlan.destPort,
      captureJobPlan.destPort,
    ),
  };
}

export function caseItemHasCaptureSource(item = {}) {
  const source = caseItemCaptureSource(item);
  return Boolean(source.flowId || (source.srcIp && source.destIp));
}

export function investigationCaseWorkbench(items = investigationCaseItems()) {
  const safeItems = normalizeItems(items);
  const rows = safeItems.map(caseCompareRow);
  const tupleGroups = countBy(rows.map((row) => row.tupleKey).filter(Boolean));
  const sharedTupleCount = Object.values(tupleGroups).filter((count) => count > 1).length;
  const captureReady = rows.filter((row) => row.captureState !== "missing").length;
  const policyVersions = unique(rows.map((row) => row.policyVersion).filter(Boolean));
  const apps = unique(rows.map((row) => row.app).filter(Boolean));
  const verdicts = unique(rows.map((row) => row.verdict).filter(Boolean));
  const rootCause = investigationRootCause(rows, { sharedTupleCount });
  const primary = rows.find((row) => row.captureReady) || rows[0] || null;
  const remediationActions = investigationCaseRemediationActions(safeItems);
  const remediationGroups = investigationCaseRemediationGroups({ rows, remediationActions });
  const remediationPlan = investigationCaseRemediationPlan({ rows, remediationActions, sharedTupleCount, remediationGroups });
  const synthesis = investigationCaseSynthesis({ items: safeItems, rows, remediationActions, remediationGroups, remediationPlan, sharedTupleCount });
  return {
    itemCount: safeItems.length,
    rows,
    rootCause,
    metrics: [
      { label: "Items", value: String(safeItems.length), detail: `${unique(rows.map((row) => row.kind)).length} evidence type${unique(rows.map((row) => row.kind)).length === 1 ? "" : "s"}` },
      { label: "Shared tuples", value: String(sharedTupleCount), detail: sharedTupleCount ? "Pinned evidence overlaps by flow or tuple." : "No repeated tuple across pinned items." },
      { label: "Policy versions", value: String(policyVersions.length || 0), detail: policyVersions.length ? policyVersions.join(", ") : "No policy-version stamp pinned." },
      { label: "Capture proof", value: `${captureReady}/${safeItems.length}`, detail: captureReady ? "At least one item has packet-capture context." : "No pinned item includes packet-capture context yet." },
    ],
    actions: investigationCaseActions({ rows, primary, apps, verdicts }),
    remediationActions,
    remediationGroups,
    remediationPlan,
    synthesis,
  };
}

export function investigationCaseSynthesis({
  items = [],
  rows = [],
  remediationActions = [],
  remediationGroups = [],
  remediationPlan = {},
  sharedTupleCount = 0,
} = {}) {
  const safeRows = Array.isArray(rows) ? rows : [];
  const safeItems = Array.isArray(items) ? items : [];
  const safeGroups = Array.isArray(remediationGroups) ? remediationGroups : [];
  const readyOwners = safeGroups.flatMap((group) => Array.isArray(group.owners) ? group.owners : [])
    .filter((owner) => owner.state === "ready" && owner.href);
  const serverRetained = safeItems.filter((item) => item.serverCustody?.caseId || item.serverCustody?.evidenceId).length;
  const routeReady = safeRows.filter((row) => safeHash(row.route)).length;
  const captureReady = safeRows.filter((row) => row.captureReady).length;
  const unresolvedGroups = safeGroups.filter((group) => group.status !== "ready").length;
  const readyActions = (Array.isArray(remediationActions) ? remediationActions : []).filter((action) => !action.disabled).length;
  const correlationKeys = unique(safeRows.map((row) => row.tupleKey || row.source?.flowId || row.subjectId || "").filter(Boolean));
  const state = !safeRows.length ? "empty"
    : unresolvedGroups ? "needs-review"
      : serverRetained && serverRetained === safeItems.length ? "server-retained"
        : "browser-synthesized";
  return {
    schemaVersion: "phragma.investigation.synthesis.v1",
    state,
    status: state === "server-retained" ? "retained synthesis ready" : state === "browser-synthesized" ? "browser synthesis ready" : state === "needs-review" ? "review gaps" : "empty",
    detail: state === "server-retained"
      ? "All pinned evidence carries server-custody references; synthesis remains unsigned until hardening."
      : state === "browser-synthesized"
        ? "Pinned evidence has enough owner-route context for a functional browser-local synthesis."
        : state === "needs-review"
          ? "One or more evidence groups need correlation, packet proof, or owner-route review before closure."
          : "Pin evidence before building a case synthesis.",
    itemCount: safeItems.length,
    correlationKeyCount: correlationKeys.length,
    sharedTupleCount,
    groupCount: safeGroups.length,
    readyGroupCount: safeGroups.length - unresolvedGroups,
    unresolvedGroupCount: unresolvedGroups,
    serverRetainedCount: serverRetained,
    routeReadyCount: routeReady,
    captureReadyCount: captureReady,
    readyActionCount: readyActions,
    readyOwnerCount: readyOwners.length,
    primaryActionId: remediationPlan.primaryActionId || "",
    primaryHref: safeHash(remediationPlan.primaryHref || ""),
    custody: {
      status: serverRetained ? "partially server retained" : "browser local",
      unsigned: true,
      retentionEnforced: false,
      legalHoldEnforced: false,
      exportCustody: "bounded browser/server case synthesis; no signed evidence chain",
      hardeningRequired: [
        "immutable evidence identity",
        "signed synthesis and export custody",
        "retention and legal hold enforcement",
        "RBAC-scoped disclosure parity",
        "HA/fleet replication and conflict handling",
      ],
    },
    rows: safeGroups.map((group) => ({
      id: group.id || "",
      title: group.title || "Remediation group",
      status: group.status || "review",
      tuple: group.tuple || "tuple not pinned",
      itemCount: group.itemCount || 0,
      missing: Array.isArray(group.missing) ? group.missing.slice(0, 6) : [],
      readyOwners: (Array.isArray(group.owners) ? group.owners : [])
        .filter((owner) => owner.state === "ready" && owner.href)
        .map((owner) => `${owner.owner || "Owner"}:${owner.label || owner.actionId || "workflow"}`)
        .slice(0, 6),
    })),
  };
}

export function normalizeServerInvestigationSynthesis(synthesis = {}) {
  if (!synthesis || typeof synthesis !== "object" || !synthesis.schemaVersion) return null;
  const coverage = synthesis.coverage && typeof synthesis.coverage === "object" ? synthesis.coverage : {};
  const confidence = synthesis.confidence && typeof synthesis.confidence === "object" ? synthesis.confidence : {};
  const flows = Array.isArray(synthesis.flows) ? synthesis.flows.slice(0, 12).map((flow, index) => ({
    id: safeSynthesisToken(flow.key || `server-flow-${index + 1}`, 240),
    title: cleanText(flow.title || `Retained flow group ${index + 1}`, 200),
    status: flow.captureProof && Array.isArray(flow.ownerRoutes) && flow.ownerRoutes.length ? "ready" : "review",
    tuple: cleanText(flow.tuple || "tuple not retained", 240),
    itemCount: boundedNumber(flow.recordCount, 0, 999),
    missing: Array.isArray(flow.limitations) ? flow.limitations.map((item) => cleanText(item, 180)).filter(Boolean).slice(0, 6) : [],
    readyOwners: Array.isArray(flow.ownerRoutes) ? flow.ownerRoutes.map((route) => `Source:${safeHash(route) || "redacted route"}`).slice(0, 6) : [],
  })) : [];
  const actions = Array.isArray(synthesis.actions) ? synthesis.actions.map((action) => ({
    id: safeSynthesisToken(action.id || "", 80),
    owner: cleanText(action.owner || "Owner", 80),
    label: cleanText(action.label || "Open owner workspace", 120),
    href: safeHash(action.href || ""),
    confidence: cleanText(action.confidence || "low", 40),
    detail: cleanText(action.detail || "", 240),
    safe: action.safe !== false,
  })).filter((action) => action.safe).slice(0, 8) : [];
  const limitations = Array.isArray(synthesis.limitations)
    ? synthesis.limitations.map((item) => cleanText(item, 220)).filter(Boolean).slice(0, 10)
    : [];
  const correlationKeyCount = boundedNumber(coverage.correlationKeys, 0, 999);
  const itemCount = boundedNumber(coverage.evidenceRecords, 0, 999);
  const captureReadyCount = boundedNumber(coverage.captureProofRecords, 0, itemCount || 999);
  const readyOwnerCount = boundedNumber(coverage.ownerRouteRecords, 0, itemCount || 999);
  return {
    schemaVersion: "phragma.investigation.synthesis.v1",
    serverSchemaVersion: cleanText(synthesis.schemaVersion, 120),
    source: cleanText(synthesis.source || "retained-server-records", 120),
    state: cleanText(synthesis.state || "server-records-review", 80),
    status: cleanText(synthesis.status || "server synthesis review", 120),
    detail: cleanText(synthesis.detail || "Server retained evidence records were synthesized for review.", 260),
    confidence: {
      score: boundedNumber(confidence.score, 0, 1),
      level: cleanText(confidence.level || "low", 40),
      basis: Array.isArray(confidence.basis) ? confidence.basis.map((item) => cleanText(item, 140)).filter(Boolean).slice(0, 6) : [],
    },
    coverage: {
      evidenceRecords: itemCount,
      serverRetainedRecords: boundedNumber(coverage.serverRetainedRecords, 0, 999),
      correlationKeys: correlationKeyCount,
      flowGroups: boundedNumber(coverage.flowGroups, 0, 999),
      multiRecordGroups: boundedNumber(coverage.multiRecordGroups, 0, 999),
      captureProofRecords: captureReadyCount,
      ownerRouteRecords: readyOwnerCount,
    },
    limitations,
    actions,
    itemCount,
    correlationKeyCount,
    sharedTupleCount: boundedNumber(coverage.multiRecordGroups, 0, 999),
    groupCount: boundedNumber(coverage.flowGroups, 0, 999),
    readyGroupCount: flows.filter((row) => row.status === "ready").length,
    unresolvedGroupCount: flows.filter((row) => row.status !== "ready").length,
    serverRetainedCount: boundedNumber(coverage.serverRetainedRecords, 0, 999),
    routeReadyCount: readyOwnerCount,
    captureReadyCount,
    readyActionCount: actions.length,
    readyOwnerCount,
    primaryActionId: actions.find((action) => action.href)?.id || actions[0]?.id || "",
    primaryHref: actions.find((action) => action.href)?.href || "",
    mutatesPolicy: synthesis.mutatesPolicy === true,
    createsTicket: synthesis.createsTicket === true,
    custody: {
      status: "server retained",
      unsigned: true,
      retentionEnforced: false,
      legalHoldEnforced: false,
      exportCustody: "server-retained evidence synthesis; no authoritative ticket or policy mutation",
      hardeningRequired: limitations,
    },
    rows: flows,
    serverActions: actions,
  };
}

export function investigationCaseRemediationPlan({ rows = [], remediationActions = [], sharedTupleCount = 0, remediationGroups = [] } = {}) {
  const safeRows = Array.isArray(rows) ? rows : [];
  const actionById = Object.fromEntries((Array.isArray(remediationActions) ? remediationActions : []).map((action) => [action.id, action]));
  const hasAlert = safeRows.some((row) => row.kind === "alert");
  const hasFlow = safeRows.some((row) => row.kind === "flow" || row.source?.flowId);
  const hasCapture = safeRows.some((row) => row.captureReady);
  const hasAppReview = safeRows.some((row) => isAppIdReviewRow(row));
  const hasNatPath = safeRows.some((row) => row.kind === "nat-path" || /->/.test(row.verdict || ""));
  const hasCandidateDelta = safeRows.some((row) => /->/.test(row.verdict || ""));
  const hasPolicy = safeRows.some((row) => row.policyVersion);
  const tupleCorrelated = sharedTupleCount > 0 || (hasFlow && hasAlert);
  const evidence = [
    evidenceBadge("traffic", hasFlow, "Traffic flow"),
    evidenceBadge("threat", hasAlert, "Threat alert"),
    evidenceBadge("capture", hasCapture, "Packet proof"),
    evidenceBadge("policy", hasPolicy || hasCandidateDelta, "Policy context"),
    evidenceBadge("app-id", hasAppReview, "App-ID review"),
    evidenceBadge("nat", hasNatPath, "NAT/route path"),
  ];
  const completed = evidence.filter((item) => item.ready).length;
  const ownerAction = firstReadyAction(
    actionById[hasAlert ? "threat-exception" : ""],
    actionById[hasAppReview ? "app-id" : ""],
    actionById[hasNatPath ? "nat-route" : ""],
    actionById["candidate-rule"],
  );
  const steps = [
    planStep({
      id: "correlate",
      label: "Correlate evidence",
      status: tupleCorrelated ? "complete" : safeRows.length > 1 ? "review" : "missing",
      detail: tupleCorrelated ? "Pinned items share a flow or tuple." : "Pin a matching flow, alert, explain result, or capture for the same tuple.",
      href: actionById.explain?.href,
    }),
    planStep({
      id: "packet-proof",
      label: "Verify packet proof",
      status: hasCapture ? "complete" : "missing",
      detail: hasCapture ? "At least one pinned item carries capture-ready tuple context." : "Run bounded capture before closing or suppressing the case.",
      href: actionById.capture?.href,
    }),
    planStep({
      id: "candidate-compare",
      label: "Compare candidate path",
      status: hasCandidateDelta ? "complete" : actionById["candidate-rule"]?.disabled ? "missing" : "review",
      detail: hasCandidateDelta ? "Pinned evidence already shows running-to-candidate behavior." : "Replay the tuple against candidate policy before staging a fix.",
      href: actionById["candidate-rule"]?.href,
    }),
    planStep({
      id: "owner-workspace",
      label: "Use owner workspace",
      status: ownerAction ? "ready" : "missing",
      detail: ownerAction ? `${ownerAction.owner || "Owner"} is the next candidate-safe workflow.` : "No owner workflow has enough evidence yet.",
      href: ownerAction?.href,
    }),
  ];
  const missing = steps.filter((step) => step.status === "missing").length;
  const ready = missing === 0 && Boolean(ownerAction);
  const groupCount = Array.isArray(remediationGroups) ? remediationGroups.length : 0;
  const readyGroups = (Array.isArray(remediationGroups) ? remediationGroups : []).filter((group) => group.status === "ready").length;
  const threatReady = hasAlert && tupleCorrelated && hasCapture;
  const appReady = hasAppReview && hasCapture && Boolean(actionById["app-id"] && !actionById["app-id"].disabled);
  const natReady = hasNatPath && Boolean(actionById["nat-route"] && !actionById["nat-route"].disabled);
  return {
    title: threatReady ? "Threat-to-policy remediation ready" : appReady ? "App-ID remediation ready" : natReady ? "NAT/path remediation ready" : ready ? "Reviewed remediation path ready" : "Evidence needs correlation",
    detail: threatReady
      ? "Threat, traffic, packet, and policy evidence support a reviewed owner-workspace change."
      : appReady
        ? "Application evidence has enough packet context for Traffic review before policy staging."
        : natReady
          ? "NAT or route evidence is ready for path replay before policy staging."
          : "Pin matching flow, alert, capture, and policy context before choosing a candidate fix.",
    tone: ready ? (hasAlert ? "bad" : "warn") : "warn",
    status: ready ? "ready" : "needs evidence",
    evidence,
    steps,
    primaryActionId: ownerAction?.id || "",
    primaryHref: ownerAction?.href || "",
    readiness: `${completed}/${evidence.length}`,
    groupedReadiness: groupCount ? `${readyGroups}/${groupCount}` : "",
    groups: Array.isArray(remediationGroups) ? remediationGroups : [],
  };
}

export function investigationCaseRemediationGroups({ rows = [], remediationActions = [] } = {}) {
  const safeRows = Array.isArray(rows) ? rows : [];
  if (!safeRows.length) return [];
  const actionById = Object.fromEntries((Array.isArray(remediationActions) ? remediationActions : []).map((action) => [action.id, action]));
  return Object.entries(groupRowsByRemediationKey(safeRows)).map(([groupKey, groupRows], index) => {
    const profile = remediationEvidenceProfile(groupRows);
    const representative = groupRows.find((row) => row.tupleReady) || groupRows.find((row) => row.captureReady) || groupRows[0] || {};
    const owners = remediationOwnersForGroup(profile, representative, groupRows, actionById);
    const missing = [];
    if (!profile.hasFlow && !profile.hasExplain && !profile.hasNatRoute) missing.push("traffic or explain evidence");
    if (!profile.hasCapture) missing.push("packet proof");
    if (profile.hasThreat && !profile.hasThreatOwner) missing.push("threat signature scope");
    if (!profile.hasCandidateDelta && !profile.hasCandidateOwner) missing.push("candidate comparison");
    const status = missing.length === 0 && owners.some((owner) => owner.state === "ready") ? "ready" : missing.length <= 1 && owners.length ? "review" : "needs evidence";
    const title = remediationGroupTitle(profile, representative, index);
    return {
      id: `group-${index + 1}`,
      key: groupKey,
      title,
      tuple: representative.tuple || "tuple not pinned",
      status,
      tone: profile.hasThreat ? "bad" : profile.hasCandidateDelta || profile.hasAppReview ? "warn" : "info",
      itemCount: groupRows.length,
      evidenceKinds: unique(groupRows.map((row) => row.kind).filter(Boolean)),
      missing,
      owners,
      handoff: remediationGroupHandoff({ title, profile, owners, missing, row: representative }),
      evidence: [
        evidenceBadge("flow", profile.hasFlow, "Flow"),
        evidenceBadge("threat", profile.hasThreat, "Threat"),
        evidenceBadge("capture", profile.hasCapture, "Capture"),
        evidenceBadge("nat-route", profile.hasNatRoute, "NAT/route"),
        evidenceBadge("candidate", profile.hasCandidateDelta, "Candidate delta"),
        evidenceBadge("app-id", profile.hasAppReview, "App-ID"),
      ],
    };
  });
}

export function investigationCaseRemediationActions(items = investigationCaseItems()) {
	const rows = normalizeItems(items).map(caseCompareRow);
	const primary = rows.find((row) => row.tupleReady) || rows.find((row) => row.captureReady) || rows[0] || null;
	const alertRow = rows.find((row) => row.kind === "alert");
	const appRow = rows.find(isAppIdReviewRow);
  return [
    plannerAction({
      id: "explain",
      label: "Explain tuple",
      owner: "Troubleshoot",
      tone: "info",
      href: primary?.troubleshootHref || "",
      disabledReason: primary?.troubleshootHref ? "" : "Missing flow ID or source/destination tuple.",
      detail: "Replay the pinned tuple against policy, NAT, route, App-ID, Threat-ID, and runtime evidence.",
    }),
    plannerAction({
      id: "capture",
      label: "Capture packet proof",
      owner: "Troubleshoot",
      tone: "info",
      href: primary?.captureHref || "",
      disabledReason: primary?.captureHref ? "" : "Missing tuple fields for bounded capture planning.",
      detail: "Open the capture workflow with the tuple prefilled; capture start remains guarded and audited.",
    }),
    plannerAction({
      id: "candidate-rule",
      label: "Plan allow/drop rule",
      owner: "Rules",
      tone: "warn",
      href: primary ? rulesFlowCheckHref(primary) : "",
      disabledReason: primary && rulesFlowCheckHref(primary) ? "" : "Missing source and destination IPs for a representative flow check.",
      detail: "Open Rules Flow check; any allow/drop rule is staged only after operator review.",
    }),
    plannerAction({
      id: "threat-exception",
      label: "Stage threat exception",
      owner: "Threats",
      tone: alertRow?.signatureId ? "bad" : "neutral",
      href: alertRow && alertRow.signatureId ? threatExceptionHref(alertRow) : "",
      disabledReason: alertRow ? (alertRow.signatureId ? "" : "Threat alert has no signature ID.") : "No pinned threat alert.",
      detail: "Open the matching threat evidence; false-positive suppression stays in Threats candidate review.",
    }),
    plannerAction({
      id: "app-id",
      label: "Promote App-ID evidence",
      owner: "Traffic",
      tone: appRow ? "warn" : "neutral",
      href: appRow ? appIdReviewHref(appRow) : "",
      disabledReason: appRow ? "" : "No pinned App-ID observation or unknown application evidence.",
      detail: "Open App-ID evidence review before creating a custom application or staged drop rule.",
    }),
    plannerAction({
      id: "nat-route",
      label: "Review NAT/route path",
      owner: "NAT",
      tone: "info",
      href: primary ? natPreviewHref(primary) : "",
      disabledReason: primary && natPreviewHref(primary) ? "" : "Missing source and destination tuple for NAT path preview.",
      detail: "Replay the tuple through running/candidate NAT and routing before staging a policy fix.",
    }),
  ];
}

export function safeInvestigationRoute(value = "") {
  return safeHash(value);
}

export function addInvestigationCasePacket(packet, {
  storage = defaultStorage(),
  pinnedAt = new Date().toISOString(),
} = {}) {
  const cleanPacket = normalizePacket(packet);
  const envelope = readEnvelope(storage);
  const key = caseItemKey(cleanPacket);
  const existingIndex = envelope.items.findIndex((item) => item.key === key);
  const item = caseItemFromPacket(cleanPacket, key, pinnedAt);
  const items = existingIndex >= 0
    ? [item, ...envelope.items.filter((_, index) => index !== existingIndex)]
    : [item, ...envelope.items];
  const next = {
    schemaVersion: INVESTIGATION_CASE_SCHEMA,
    updatedAt: pinnedAt,
    items: items.slice(0, INVESTIGATION_CASE_LIMITS.maxItems),
  };
  writeEnvelope(storage, next);
  return { case: next, item, replaced: existingIndex >= 0 };
}

export function pinInvestigationPacket(packet, options = {}) {
  const result = addInvestigationCasePacket(packet, options);
  return {
    ...result,
    toastTitle: result.replaced ? "Case item updated" : "Pinned to case",
    toastDetail: `${kindLabel(result.item.kind)} evidence is available in Investigation.`,
  };
}

export function caseEvidencePayloadFromPacket(packet, {
  pinnedAt = new Date().toISOString(),
} = {}) {
  const cleanPacket = normalizePacket(packet);
  return caseItemFromPacket(cleanPacket, caseItemKey(cleanPacket), pinnedAt);
}

export function caseEvidencePayloadsFromItems(items = []) {
  return normalizeItems(items).map((item) => ({
    ...item,
    target: investigationCaseTargetSummary(item),
  }));
}

export function investigationCaseTargetSummary(item = {}) {
  const packet = item.packet || {};
  const target = item.target || {};
  const source = item.source || packet.source || {};
  return cleanTargetSummary({
    kind: target.kind || item.kind || packet.kind || "investigation",
    key: target.key || item.key || caseItemKey(packet),
    route: target.route || source.route || source.redactedRoute || packet.source?.route || packet.source?.redactedRoute || "",
    routeRedacted: Boolean(target.routeRedacted || source.routeRedacted || packet.source?.routeRedacted),
    source: target.source || source.interface || packet.source?.interface || "webui",
    title: target.title || item.title || item.subject?.label || packet.title || "Investigation evidence",
    pinnedAt: target.pinnedAt || item.pinnedAt || "",
    collectedAt: target.collectedAt || packet.collectedAt || "",
    addedAt: target.addedAt || item.serverCustody?.addedAt || "",
  });
}

export function normalizeInvestigationServerCaseId(id = "") {
  const text = String(id || "").trim();
  return /^case-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$/.test(text) ? text : "";
}

export function activeInvestigationServerCaseId({ storage = defaultStorage() } = {}) {
  if (!storage) return "";
  try {
    return normalizeInvestigationServerCaseId(storage.getItem(INVESTIGATION_ACTIVE_SERVER_CASE_STORAGE_KEY));
  } catch {
    return "";
  }
}

export function activeInvestigationServerCaseHref({ storage = defaultStorage() } = {}) {
  const id = activeInvestigationServerCaseId({ storage });
  if (!id) return "#/investigation";
  const q = new URLSearchParams();
  q.set("activeCase", id);
  return `#/investigation?${q.toString()}`;
}

export async function appendInvestigationPacketToActiveServerCase(packet, {
  appendEvidence,
  storage = defaultStorage(),
  pinnedAt = new Date().toISOString(),
} = {}) {
  const activeCaseId = activeInvestigationServerCaseId({ storage });
  const payload = caseEvidencePayloadFromPacket(packet, { pinnedAt });
  if (!activeCaseId || typeof appendEvidence !== "function") {
    return {
      activeCaseId,
      appended: false,
      payload,
      reason: activeCaseId ? "append unavailable" : "no active case",
    };
  }
  await appendEvidence(activeCaseId, [payload]);
  return { activeCaseId, appended: true, payload };
}

export function setActiveInvestigationServerCaseId(id, { storage = defaultStorage() } = {}) {
  const clean = normalizeInvestigationServerCaseId(id);
  if (!storage) return "";
  try {
    if (clean) storage.setItem(INVESTIGATION_ACTIVE_SERVER_CASE_STORAGE_KEY, clean);
    else storage.removeItem?.(INVESTIGATION_ACTIVE_SERVER_CASE_STORAGE_KEY);
  } catch {
    return "";
  }
  return clean;
}

export function clearActiveInvestigationServerCaseId({ storage = defaultStorage() } = {}) {
  if (!storage) return "";
  try {
    storage.removeItem?.(INVESTIGATION_ACTIVE_SERVER_CASE_STORAGE_KEY);
  } catch {
    return "";
  }
  return "";
}

export function serverInvestigationCaseItems(record = {}) {
  const evidence = Array.isArray(record.evidence) ? record.evidence : [];
  return normalizeItems(evidence
    .map((item) => {
      if (!item?.payload || typeof item.payload !== "object") return null;
      const target = cleanTargetSummary(item.target || item.payload.target || {});
      return {
        ...item.payload,
        target,
        serverCustody: {
          caseId: record.id || "",
          evidenceId: item.id || "",
          addedAt: item.addedAt || target.addedAt || "",
          addedBy: item.addedBy || "",
          target,
        },
      };
    })
    .filter(Boolean));
}

export function removeInvestigationCaseItem(key, {
  storage = defaultStorage(),
  removedAt = new Date().toISOString(),
} = {}) {
  const envelope = readEnvelope(storage);
  const next = {
    ...envelope,
    updatedAt: removedAt,
    items: envelope.items.filter((item) => item.key !== key),
  };
  writeEnvelope(storage, next);
  return next;
}

export function clearInvestigationCase({
  storage = defaultStorage(),
  clearedAt = new Date().toISOString(),
} = {}) {
  const next = {
    schemaVersion: INVESTIGATION_CASE_SCHEMA,
    updatedAt: clearedAt,
    items: [],
  };
  writeEnvelope(storage, next);
  return next;
}

export function buildInvestigationCasePacket(items = investigationCaseItems(), {
  collectedAt = new Date().toISOString(),
  route = "#/investigation",
} = {}) {
  const safeItems = normalizeItems(items);
  const kinds = countBy(safeItems.map((item) => item.kind));
  const routes = unique(safeItems.map((item) => item.source?.route || "").filter(Boolean));
  const redactedRouteCount = safeItems.filter((item) => item.source?.routeRedacted || item.packet?.source?.routeRedacted).length;
  const workbench = investigationCaseWorkbench(safeItems);
  return {
    schemaVersion: INVESTIGATION_CASE_SCHEMA,
    collectedAt,
    generatedBy: "openngfw-webui",
    source: {
      interface: "webui",
      route: safeInvestigationRoute(route),
    },
    summary: {
      itemCount: safeItems.length,
      kindCount: Object.keys(kinds).length,
      kinds,
      routes,
      redactedRouteCount,
      rootCause: workbench.rootCause,
      actionCount: workbench.actions.length,
    },
    workbench: {
      metrics: workbench.metrics,
      actions: workbench.actions,
      remediationActions: workbench.remediationActions,
      remediationPlan: workbench.remediationPlan,
      remediationGroups: workbench.remediationGroups,
      synthesis: workbench.synthesis,
      rows: workbench.rows,
    },
    items: safeItems.map((item) => ({
      key: item.key,
      pinnedAt: item.pinnedAt,
      kind: item.kind,
      title: item.title,
      target: investigationCaseTargetSummary(item),
      subject: item.subject,
      source: item.source,
      summary: item.summary,
      evidence: item.packet?.evidence || [],
      packet: item.packet,
    })),
  };
}

export function investigationCaseJson(casePacket) {
  return JSON.stringify(casePacket || buildInvestigationCasePacket(), null, 2) + "\n";
}

export function investigationCaseText(casePacket) {
  const packet = casePacket || buildInvestigationCasePacket();
  const lines = [
    "Phragma investigation case",
    `schema=${packet.schemaVersion || INVESTIGATION_CASE_SCHEMA}`,
    `collected_at=${packet.collectedAt || ""}`,
    `item_count=${packet.summary?.itemCount || 0}`,
  ];
  if (packet.summary?.rootCause?.title) {
    lines.push(`root_cause=${packet.summary.rootCause.title}`);
    if (packet.summary.rootCause.detail) lines.push(`root_cause_detail=${packet.summary.rootCause.detail}`);
  }
  const actions = Array.isArray(packet.workbench?.actions) ? packet.workbench.actions : [];
  if (actions.length) {
    lines.push("", "[case actions]");
    for (const action of actions) {
      lines.push(`- ${action.label}: ${action.href || "no route"}${action.detail ? ` (${action.detail})` : ""}`);
    }
  }
  const remediationActions = Array.isArray(packet.workbench?.remediationActions) ? packet.workbench.remediationActions : [];
  if (remediationActions.length) {
    lines.push("", "[remediation planner]");
    for (const action of remediationActions) {
      lines.push(`- ${action.label}: ${action.disabled ? "disabled" : action.href || "no route"}${action.disabledReason ? ` (${action.disabledReason})` : ""}`);
    }
  }
  const plan = packet.workbench?.remediationPlan || {};
  const synthesis = packet.workbench?.synthesis || {};
  if (synthesis.schemaVersion) {
    lines.push("", "[retained case synthesis]");
    lines.push(`state=${synthesis.state || ""}`);
    lines.push(`status=${synthesis.status || ""}`);
    lines.push(`correlation_keys=${synthesis.correlationKeyCount || 0}`);
    lines.push(`groups=${synthesis.readyGroupCount || 0}/${synthesis.groupCount || 0} ready`);
    lines.push(`server_retained=${synthesis.serverRetainedCount || 0}/${synthesis.itemCount || 0}`);
    lines.push(`custody=${synthesis.custody?.exportCustody || ""}`);
    if (synthesis.custody?.unsigned) lines.push("boundary=unsigned synthesis; legal hold and signed custody require hardening");
  }
  if (plan.title) {
    lines.push("", "[multi-evidence fix plan]");
    lines.push(`status=${plan.status || ""}`);
    lines.push(`readiness=${plan.readiness || ""}`);
    lines.push(`title=${plan.title}`);
    if (plan.detail) lines.push(`detail=${plan.detail}`);
    for (const step of Array.isArray(plan.steps) ? plan.steps : []) {
      lines.push(`- ${step.label}: ${step.status}${step.href ? ` (${step.href})` : ""}`);
    }
    const groups = Array.isArray(plan.groups) ? plan.groups : Array.isArray(packet.workbench?.remediationGroups) ? packet.workbench.remediationGroups : [];
    if (groups.length) {
      lines.push("", "[grouped remediation handoffs]");
      for (const group of groups) {
        lines.push(`- ${group.title}: ${group.status}; tuple=${group.tuple || "tuple not pinned"}`);
        if (group.handoff) lines.push(`  handoff=${group.handoff}`);
        for (const owner of Array.isArray(group.owners) ? group.owners : []) {
          lines.push(`  owner=${owner.owner || "Owner"} action=${owner.label || owner.actionId || ""} state=${owner.state || ""}${owner.href ? ` route=${owner.href}` : ""}`);
        }
      }
    }
  }
  const items = Array.isArray(packet.items) ? packet.items : [];
  for (const item of items) {
    const safeRoute = safeInvestigationRoute(item.source?.route || "");
    lines.push(
      "",
      `[${item.kind || "evidence"}]`,
      `pinned_at=${item.pinnedAt || ""}`,
      `subject=${item.subject?.label || item.title || "selected evidence"}`,
      item.subject?.id ? `subject_id=${item.subject.id}` : "",
      safeRoute ? `route=${safeRoute}` : item.source?.routeRedacted || item.packet?.source?.routeRedacted || item.source?.route ? "route=redacted unsafe route" : "",
      ...investigationPacketText(item.packet).split("\n").filter((line) => line && !line.startsWith("Phragma investigation handoff")).slice(0, 80),
    );
  }
  return lines.filter((line) => line !== "").join("\n") + "\n";
}

function caseCompareRow(item = {}) {
  const summary = item.summary || {};
  const packet = item.packet || {};
  const artifacts = packet.artifacts || {};
  const capture = caseItemCaptureSource(item);
  const tupleKey = tupleKeyFrom(capture, item.subject?.tuple || {});
  const flow = artifacts.flow || {};
  const alert = artifacts.alert || {};
  const observation = artifacts.observation || {};
  const running = artifacts.running || {};
  const candidate = artifacts.candidate || {};
  const captureJob = artifacts.captureJob || {};
  const capturePlan = artifacts.capturePlan || {};
  const natFlow = artifacts.flow || artifacts.natFlow || {};
  const app = firstValue(summary.appId, summary.appName, observation.appId, observation.appName, flow.appId, flow.appName, item.subject?.tuple?.appId);
  const source = {
    flowId: capture.flowId,
    protocol: capture.protocol,
    srcIp: capture.srcIp,
    srcPort: capture.srcPort,
    destIp: capture.destIp,
    destPort: capture.destPort,
    appId: app,
    fromZone: firstValue(summary.fromZone, item.subject?.tuple?.fromZone, flow.fromZone, alert.fromZone, natFlow.fromZone),
    toZone: firstValue(summary.toZone, item.subject?.tuple?.toZone, flow.toZone, alert.toZone, natFlow.toZone),
    policyVersionKnown: Boolean(flow.policyVersionKnown || alert.policyVersionKnown),
    policyVersion: firstValue(flow.policyVersion, alert.policyVersion),
  };
  const verdict = firstValue(
    summary.candidateVerdict && summary.runningVerdict && summary.candidateVerdict !== summary.runningVerdict ? `${summary.runningVerdict} -> ${summary.candidateVerdict}` : "",
    summary.candidateVerdict,
    summary.runningVerdict,
    summary.action,
    summary.state,
    running.verdict,
    candidate.verdict,
    alert.action,
  );
  const rule = firstValue(summary.candidateMatchedRule, summary.runningMatchedRule, summary.matchedRule, summary.rule, summary.ruleName, running.matchedRule, candidate.matchedRule, flow.rule, alert.rule);
  const policyVersion = firstValue(summary.eventPolicy, summary.runningPolicyVersion ? `v${summary.runningPolicyVersion}` : "", flow.policyVersionKnown && flow.policyVersion ? `v${flow.policyVersion}` : "", alert.policyVersionKnown && alert.policyVersion ? `v${alert.policyVersion}` : "");
  const captureState = firstValue(summary.captureState, captureJob.state, capturePlan.outputPath ? "planned" : "", caseItemHasCaptureSource(item) ? "source-ready" : "missing");
  return {
    key: item.key,
    kind: item.kind || "investigation",
    title: item.subject?.label || item.title || "Selected evidence",
    subjectId: item.subject?.id || "",
    tuple: tupleLabel(capture, item.subject?.tuple || {}),
    tupleKey,
    tupleReady: Boolean(capture.srcIp && capture.destIp),
    source,
    app: app || "unknown",
    verdict: verdict || "unknown",
    rule: rule || "not pinned",
    policyVersion: policyVersion || "",
    captureState,
    captureReady: captureState !== "missing",
    route: item.source?.route || "",
    signatureId: firstValue(summary.signatureId, alert.signatureId, alert.signature_id, alert.sid, alert.signatureIdText),
    threatId: firstValue(summary.threatId, alert.threatId),
    queueId: firstValue(summary.queueId, observation.queueId),
    observationKind: firstValue(summary.reason, observation.kind),
    engineSignal: firstValue(summary.engineSignal, observation.engineSignal),
    troubleshootHref: troubleshootHashFromSource(source, { app, flowId: capture.flowId, intent: "explain" }),
    captureHref: troubleshootHashFromSource(source, { app, flowId: capture.flowId, intent: "capture" }),
  };
}

function plannerAction({ id, label, owner, tone = "info", href = "", disabledReason = "", detail = "" } = {}) {
  const safeHref = safeHash(href);
  return {
    id,
    label,
    owner,
    tone,
    href: safeHref,
    disabled: !safeHref || Boolean(disabledReason),
    disabledReason: disabledReason || (!safeHref ? "Required evidence is not pinned." : ""),
    detail,
  };
}

function evidenceBadge(id, ready, label) {
  return {
    id,
    label,
    ready: Boolean(ready),
    state: ready ? "ready" : "missing",
  };
}

function planStep({ id, label, status = "missing", detail = "", href = "" } = {}) {
  return {
    id,
    label,
    status,
    detail,
    href: safeHash(href),
  };
}

function firstReadyAction(...actions) {
  return actions.find((action) => action && !action.disabled && action.href) || null;
}

function boundedNumber(value, minValue = 0, maxValue = Number.MAX_SAFE_INTEGER) {
  const number = Number(value);
  if (!Number.isFinite(number)) return minValue;
  return Math.max(minValue, Math.min(maxValue, number));
}

function cleanText(value = "", maxLength = 240) {
  const text = String(value || "").replace(/[\u0000-\u001f\u007f]/g, " ").trim();
  return text.length > maxLength ? text.slice(0, maxLength) : text;
}

function safeSynthesisToken(value = "", maxLength = 120) {
  return cleanText(value, maxLength).replace(/[^\w:|./-]+/g, "-");
}

function groupRowsByRemediationKey(rows = []) {
  const groups = {};
  for (const row of rows) {
    const key = row.tupleKey || row.source?.flowId || row.subjectId || row.key || "uncorrelated";
    if (!groups[key]) groups[key] = [];
    groups[key].push(row);
  }
  return groups;
}

function remediationEvidenceProfile(rows = []) {
	const hasThreat = rows.some((row) => row.kind === "alert");
	const hasFlow = rows.some((row) => row.kind === "flow" || Boolean(row.source?.flowId));
	const hasExplain = rows.some((row) => row.kind === "explain");
  const hasCapture = rows.some((row) => row.kind === "capture" || row.captureReady);
  const hasNatRoute = rows.some((row) => row.kind === "nat-path" || row.kind === "vpn-tunnel" || /route|nat/i.test(row.rule || "") || /->/.test(row.verdict || ""));
  const hasCandidateDelta = rows.some((row) => /->/.test(row.verdict || ""));
  const hasAppReview = rows.some((row) => row.kind.includes("app-id") || row.queueId || ((row.kind === "flow" || row.kind === "session") && row.app === "unknown"));
  const hasThreatOwner = rows.some((row) => row.kind === "alert" && row.signatureId);
  const hasCandidateOwner = rows.some((row) => row.tupleReady);
  return {
    hasThreat,
    hasFlow,
    hasExplain,
    hasCapture,
    hasNatRoute,
    hasCandidateDelta,
    hasAppReview,
    hasThreatOwner,
    hasCandidateOwner,
	};
}

function isAppIdReviewRow(row = {}) {
	return Boolean(row.kind?.includes("app-id") || row.queueId || ((row.kind === "flow" || row.kind === "session") && row.app === "unknown"));
}

function remediationOwnersForGroup(profile = {}, row = {}, rows = [], actionById = {}) {
	const alertRow = rows.find((candidate) => candidate.kind === "alert") || row;
	const appRow = rows.find(isAppIdReviewRow) || row;
  const natRow = rows.find((candidate) => candidate.kind === "nat-path" || candidate.kind === "vpn-tunnel" || /->/.test(candidate.verdict || "")) || row;
  const owners = [];
  pushOwner(owners, ownerActionFromPlanner({ ...(actionById.explain || {}), href: row.troubleshootHref || actionById.explain?.href || "" }, {
    owner: "Troubleshoot",
    actionId: "explain",
    label: "Explain tuple",
    detail: "Replay policy, NAT, route, App-ID, Threat-ID, and runtime evidence for this tuple.",
  }));
  if (!profile.hasCapture) {
    pushOwner(owners, ownerActionFromPlanner({ ...(actionById.capture || {}), href: row.captureHref || actionById.capture?.href || "" }, {
      owner: "Troubleshoot",
      actionId: "capture",
      label: "Capture packet proof",
      detail: "Collect bounded packet proof before suppression or candidate staging.",
    }));
  }
  if (profile.hasThreat) {
    pushOwner(owners, ownerActionFromPlanner({ ...(actionById["threat-exception"] || {}), href: threatExceptionHref(alertRow), disabled: !alertRow.signatureId }, {
      owner: "Threats",
      actionId: "threat-exception",
      label: "Review threat exception",
      detail: "Scope any false-positive exception in Threats candidate review.",
    }));
  }
  if (profile.hasAppReview) {
    pushOwner(owners, ownerActionFromPlanner({ ...(actionById["app-id"] || {}), href: appIdReviewHref(appRow) }, {
      owner: "Traffic",
      actionId: "app-id",
      label: "Review App-ID evidence",
      detail: "Promote application identity only from representative flow and packet evidence.",
    }));
  }
  if (profile.hasNatRoute) {
    pushOwner(owners, ownerActionFromPlanner({ ...(actionById["nat-route"] || {}), href: natPreviewHref(natRow) || actionById["nat-route"]?.href || "" }, {
      owner: "NAT",
      actionId: "nat-route",
      label: "Review NAT/route path",
      detail: "Replay running and candidate path behavior before staging a firewall change.",
    }));
  }
  pushOwner(owners, ownerActionFromPlanner({ ...(actionById["candidate-rule"] || {}), href: rulesFlowCheckHref(row) || actionById["candidate-rule"]?.href || "" }, {
    owner: "Rules",
    actionId: "candidate-rule",
    label: profile.hasCandidateDelta ? "Review candidate delta" : "Compare candidate policy",
    detail: "Use Rules Flow check; policy edits remain staged candidate changes.",
  }));
  if (row.route) {
    pushOwner(owners, {
      owner: "Source",
      actionId: "source-evidence",
      label: "Open source evidence",
      href: safeHash(row.route),
      state: safeHash(row.route) ? "ready" : "blocked",
      detail: "Return to the original owner workspace for this pinned item.",
    });
  }
  return owners.slice(0, 6);
}

function ownerActionFromPlanner(action = {}, fallback = {}) {
  const href = safeHash(action.href || "");
  return {
    owner: action.owner || fallback.owner || "Owner",
    actionId: action.id || fallback.actionId || "",
    label: action.label || fallback.label || "Open workflow",
    href,
    state: href && !action.disabled ? "ready" : "blocked",
    detail: action.disabledReason || action.detail || fallback.detail || "",
  };
}

function pushOwner(owners, owner = {}) {
  if (!owner.actionId && !owner.label) return;
  if (owners.some((item) => item.actionId === owner.actionId && item.owner === owner.owner)) return;
  owners.push(owner);
}

function remediationGroupTitle(profile = {}, row = {}, index = 0) {
  if (profile.hasThreat) return `Threat remediation group ${index + 1}`;
  if (profile.hasNatRoute) return `NAT/route remediation group ${index + 1}`;
  if (profile.hasAppReview) return `App-ID remediation group ${index + 1}`;
  if (profile.hasCandidateDelta) return `Candidate-delta remediation group ${index + 1}`;
  return `Flow remediation group ${index + 1}`;
}

function remediationGroupHandoff({ title = "", profile = {}, owners = [], missing = [], row = {} } = {}) {
  const readyOwners = owners.filter((owner) => owner.state === "ready").map((owner) => `${owner.owner}:${owner.label}`);
  const evidence = [
    profile.hasFlow || profile.hasExplain ? "flow/explain" : "",
    profile.hasThreat ? "threat" : "",
    profile.hasCapture ? "capture" : "",
    profile.hasNatRoute ? "nat/route" : "",
    profile.hasCandidateDelta ? "candidate-delta" : "",
    profile.hasAppReview ? "app-id" : "",
  ].filter(Boolean).join(", ") || "uncorrelated";
  const missingText = missing.length ? ` Missing: ${missing.join(", ")}.` : "";
  const ownerText = readyOwners.length ? ` Route owners: ${readyOwners.join("; ")}.` : " No owner route is ready yet.";
  const tuple = row.tuple && row.tuple !== "tuple not pinned" ? ` Tuple: ${row.tuple}.` : "";
  return `${title}. Evidence: ${evidence}.${tuple}${ownerText}${missingText} Do not mutate running policy directly; use the linked owner workspace and candidate review.`;
}

function rulesFlowCheckHref(row = {}) {
  const source = row.source || {};
  if (!source.srcIp || !source.destIp) return "";
  const q = new URLSearchParams();
  q.set("simSource", "POLICY_SOURCE_CANDIDATE");
  setQuery(q, "simFrom", source.fromZone);
  setQuery(q, "simTo", source.toZone);
  setQuery(q, "simProtocol", protocolParam(source.protocol));
  setQuery(q, "simApp", row.app && row.app !== "unknown" ? row.app : "");
  setQuery(q, "simSrc", source.srcIp);
  setQuery(q, "simSport", source.srcPort);
  setQuery(q, "simDst", source.destIp);
  setQuery(q, "simDport", source.destPort);
  q.set("simRun", "1");
  setCaseQuery(q, row, "candidate-rule");
  return "#/rules?" + q.toString();
}

function threatExceptionHref(row = {}) {
  const q = new URLSearchParams();
  setQuery(q, "signatureId", row.signatureId);
  setQuery(q, "flowId", row.source?.flowId);
  setQuery(q, "ip", row.source?.srcIp || row.source?.destIp);
  q.set("limit", "100");
  setCaseQuery(q, row, "threat-exception");
  return "#/threats?" + q.toString();
}

function appIdReviewHref(row = {}) {
  const q = new URLSearchParams();
  q.set("mode", "app-id");
  setQuery(q, "queueId", row.queueId);
  setQuery(q, "engineSignal", row.engineSignal);
  setQuery(q, "protocol", protocolLabelForTraffic(row.source?.protocol));
  setQuery(q, "port", row.source?.destPort);
  q.set("limit", "100");
  setCaseQuery(q, row, "app-id");
  return "#/traffic?" + q.toString();
}

function natPreviewHref(row = {}) {
  const source = row.source || {};
  if (!source.srcIp || !source.destIp) return "";
  const q = new URLSearchParams();
  setQuery(q, "fromZone", source.fromZone);
  setQuery(q, "toZone", source.toZone);
  setQuery(q, "protocol", protocolParam(source.protocol));
  setQuery(q, "srcIp", source.srcIp);
  setQuery(q, "srcPort", source.srcPort);
  setQuery(q, "destIp", source.destIp);
  setQuery(q, "destPort", source.destPort);
  q.set("run", "1");
  setCaseQuery(q, row, "nat-route");
  return "#/nat?" + q.toString();
}

function setCaseQuery(q, row = {}, action = "") {
  setQuery(q, "caseKey", row.key);
  setQuery(q, "caseAction", action);
  setQuery(q, "caseKind", row.kind);
}

function investigationRootCause(rows = [], { sharedTupleCount = 0 } = {}) {
  if (!rows.length) {
    return {
      tone: "neutral",
      title: "No case evidence pinned",
      detail: "Pin flows, alerts, explanations, captures, or audit entries from the operator workspaces.",
    };
  }
  if (rows.some((row) => /->/.test(row.verdict))) {
    return {
      tone: "warn",
      title: "Candidate decision differs from running policy",
      detail: "Compare the pinned explain/NAT evidence before committing or rolling back.",
    };
  }
  if (rows.some((row) => row.kind === "alert")) {
    return {
      tone: "bad",
      title: sharedTupleCount ? "Threat evidence is correlated with traffic" : "Threat evidence needs flow correlation",
      detail: sharedTupleCount ? "Review the matched flow, packet capture, and exception scope before staging a change." : "Open matching flows or capture the tuple before staging a threat exception.",
    };
  }
  if (rows.some((row) => row.kind.includes("app-id") || row.app === "unknown")) {
    return {
      tone: "warn",
      title: "Application identity needs review",
      detail: "Promote App-ID only from evidence that has representative flow and packet-capture context.",
    };
  }
  if (rows.every((row) => row.captureState === "missing")) {
    return {
      tone: "warn",
      title: "Packet proof is missing",
      detail: "Run a bounded capture from the pinned tuple before closing the case.",
    };
  }
  return {
    tone: "info",
    title: sharedTupleCount ? "Pinned evidence shares a case tuple" : "Pinned evidence is ready for review",
    detail: "Use the compare table to confirm app, verdict, rule, policy version, and capture state before taking action.",
  };
}

function investigationCaseActions({ rows = [], primary = null, apps = [], verdicts = [] } = {}) {
  if (!rows.length || !primary) return [];
  const actions = [];
  if (primary.troubleshootHref) {
    actions.push({
      id: "explain",
      label: "Explain tuple",
      href: primary.troubleshootHref,
      detail: "Open candidate-aware Troubleshoot for the pinned tuple.",
    });
  }
  if (primary.captureHref) {
    actions.push({
      id: "capture",
      label: "Capture tuple",
      href: primary.captureHref,
      detail: "Open bounded packet-capture planning for the pinned tuple.",
    });
  }
  const flowId = rows.map((row) => row.subjectId).find(Boolean) || "";
  actions.push({
    id: "traffic",
    label: "Review matching traffic",
    href: flowId ? `#/traffic?flowId=${encodeURIComponent(flowId)}` : "#/traffic",
    detail: "Inspect live flow/session context before staging policy.",
  });
  if (rows.some((row) => row.kind === "alert")) {
    actions.push({
      id: "threat",
      label: "Tune threat safely",
      href: "#/threats",
      detail: "Stage any exception through Threats candidate review.",
    });
  } else if (apps.some((app) => app && app !== "unknown") || verdicts.some((value) => /deny|drop|allow|block/i.test(value))) {
    actions.push({
      id: "candidate-fix",
      label: "Stage candidate fix",
      href: primary.route || "#/rules",
      detail: "Use the source drawer action; changes stay candidate-only.",
    });
  }
  actions.push({
    id: "audit",
    label: "Check audit trail",
    href: "#/changes?tab=audit",
    detail: "Verify related commits, rollbacks, captures, and exceptions.",
  });
  return actions.map((action) => ({
    ...action,
    href: safeHash(action.href) || fallbackActionHref(action.id),
  })).slice(0, 5);
}

function fallbackActionHref(id = "") {
  if (id === "traffic") return "#/traffic";
  if (id === "threat") return "#/threats";
  if (id === "candidate-fix") return "#/rules";
  if (id === "audit") return "#/changes?tab=audit";
  return "#/investigation";
}

function troubleshootHashFromSource(source = {}, { app = "", flowId = "", intent = "explain" } = {}) {
  if (!source.flowId && !(source.srcIp && source.destIp)) return "";
  const hash = investigationHashFromFlow({
    srcIp: source.srcIp,
    srcPort: source.srcPort,
    destIp: source.destIp,
    destPort: source.destPort,
    protocol: source.protocol,
    appId: app && app !== "unknown" ? app : source.appId,
    flowId: flowId || source.flowId,
    fromZone: source.fromZone,
    toZone: source.toZone,
    policyVersionKnown: source.policyVersionKnown,
    policyVersion: source.policyVersion,
  }, { intent });
  return safeHash(hash);
}

function setQuery(q, key, value) {
  if (value == null || value === "") return;
  q.set(key, String(value));
}

function protocolParam(value = "") {
  const proto = String(value || "").toUpperCase().replace(/^PROTOCOL_/, "");
  if (proto === "UDP") return "PROTOCOL_UDP";
  if (proto === "ICMP") return "PROTOCOL_ICMP";
  if (proto === "ANY" || proto === "IP") return "PROTOCOL_ANY";
  return "PROTOCOL_TCP";
}

function protocolLabelForTraffic(value = "") {
  const proto = String(protocolParam(value) || "").replace(/^PROTOCOL_/, "");
  return ["TCP", "UDP", "ICMP"].includes(proto) ? proto : "";
}

function safeHash(value = "") {
  const text = String(value || "").trim();
  if (!text.startsWith("#/")) return "";
  if (/[\u0000-\u001f\u007f]/.test(text)) return "";
  if (text.length > 1200) return "";
  if (/bearer|token|secret|password|\/var\/|\/etc\/|\/tmp\/|file:/i.test(text)) return "";
  return text;
}

function tupleKeyFrom(source = {}, tuple = {}) {
  const src = firstValue(source.srcIp, tuple.srcIp);
  const sport = firstValue(source.srcPort, tuple.srcPort);
  const dst = firstValue(source.destIp, tuple.destIp);
  const dport = firstValue(source.destPort, tuple.destPort);
  const proto = firstValue(source.protocol, tuple.protocol);
  if (!src && !dst && !source.flowId && !tuple.flowId) return "";
  return [proto, src, sport, dst, dport].map((value) => String(value || "").toLowerCase()).join("|");
}

function tupleLabel(source = {}, tuple = {}) {
  const src = firstValue(source.srcIp, tuple.srcIp);
  const sport = firstValue(source.srcPort, tuple.srcPort);
  const dst = firstValue(source.destIp, tuple.destIp);
  const dport = firstValue(source.destPort, tuple.destPort);
  const proto = firstValue(source.protocol, tuple.protocol);
  const left = [src, sport].filter(Boolean).join(":");
  const right = [dst, dport].filter(Boolean).join(":");
  if (left || right) return `${proto ? proto + " " : ""}${left || "source"} -> ${right || "destination"}`;
  return "tuple not pinned";
}

export function investigationCaseFilename(now = new Date()) {
  return `phragma-investigation-case-${timestampForFilename(now)}.json`;
}

export function caseItemKey(packet = {}) {
  const kind = safeToken(packet.kind || "investigation");
  const subjectID = packet.subject?.id || packet.subject?.label || packet.title || "selected";
  const route = packet.source?.route || "";
  return [kind, stableToken(subjectID), stableToken(route)].join(":");
}

function readEnvelope(storage) {
  if (!storage) return emptyEnvelope();
  try {
    const raw = storage.getItem(INVESTIGATION_CASE_STORAGE_KEY);
    if (!raw) return emptyEnvelope();
    const parsed = JSON.parse(raw);
    if (parsed?.schemaVersion !== INVESTIGATION_CASE_SCHEMA) return emptyEnvelope();
    return {
      schemaVersion: INVESTIGATION_CASE_SCHEMA,
      updatedAt: timestampString(parsed.updatedAt),
      items: normalizeItems(parsed.items),
    };
  } catch {
    return emptyEnvelope();
  }
}

function writeEnvelope(storage, envelope) {
  if (!storage) return;
  storage.setItem(INVESTIGATION_CASE_STORAGE_KEY, JSON.stringify({
    schemaVersion: INVESTIGATION_CASE_SCHEMA,
    updatedAt: timestampString(envelope.updatedAt),
    items: normalizeItems(envelope.items),
  }));
}

function emptyEnvelope() {
  return {
    schemaVersion: INVESTIGATION_CASE_SCHEMA,
    updatedAt: "",
    items: [],
  };
}

function normalizeItems(items = []) {
  return (Array.isArray(items) ? items : [])
    .map(normalizeItem)
    .filter(Boolean)
    .sort((a, b) => String(b.pinnedAt || "").localeCompare(String(a.pinnedAt || "")))
    .slice(0, INVESTIGATION_CASE_LIMITS.maxItems);
}

function normalizeItem(item = {}) {
  try {
    const packet = normalizePacket(item.packet);
    const key = String(item.key || caseItemKey(packet));
    return {
      key,
      pinnedAt: timestampString(item.pinnedAt || packet.collectedAt),
      kind: safeToken(item.kind || packet.kind || "investigation"),
      title: boundedString(item.title || packet.title || "Investigation evidence", 240),
      target: cleanTargetSummary(item.target || {}),
      serverCustody: cleanServerCustody(item.serverCustody || {}),
      subject: cleanSubject(item.subject || packet.subject || {}),
      source: cleanSource(item.source || packet.source || {}),
      summary: cleanSummary(item.summary || packet.summary || {}),
      packet,
    };
  } catch {
    return null;
  }
}

function caseItemFromPacket(packet, key, pinnedAt) {
  return {
    key,
    pinnedAt,
    kind: safeToken(packet.kind || "investigation"),
    title: boundedString(packet.title || "Investigation evidence", 240),
    subject: cleanSubject(packet.subject || {}),
    source: cleanSource(packet.source || {}),
    summary: cleanSummary(packet.summary || {}),
    target: investigationCaseTargetSummary({ key, pinnedAt, kind: packet.kind, title: packet.title, subject: packet.subject, source: packet.source, packet }),
    packet,
  };
}

function normalizePacket(packet) {
  if (!packet || typeof packet !== "object") throw new Error("investigation packet is required");
  if (packet.schemaVersion !== INVESTIGATION_PACKET_SCHEMA) throw new Error("investigation packet schema is unsupported");
  if (!packet.kind) throw new Error("investigation packet kind is required");
  const text = JSON.stringify(packet);
  if (text.length > INVESTIGATION_CASE_LIMITS.maxPacketChars) throw new Error("investigation packet exceeds case storage limit");
  const clean = JSON.parse(text);
  if (clean.source?.route) {
    const rawRoute = String(clean.source.route || "");
    clean.source.route = safeInvestigationRoute(rawRoute);
    if (rawRoute && !clean.source.route) {
      clean.source.routeRedacted = true;
      clean.source.redactedRoute = cleanTargetRoute(rawRoute);
    }
  }
  return redactCaseValue(clean);
}

function cleanSubject(subject = {}) {
  return {
    id: boundedString(subject.id || "", 320),
    label: boundedString(subject.label || "", 320),
    tuple: subject.tuple && typeof subject.tuple === "object" ? cleanSummary(subject.tuple) : {},
  };
}

function cleanSource(source = {}) {
  const rawRoute = String(source.route || "");
  const safeRoute = safeInvestigationRoute(rawRoute);
  const redactedRoute = source.redactedRoute || (rawRoute && !safeRoute ? cleanTargetRoute(rawRoute) : "");
  return {
    interface: boundedString(source.interface || "webui", 80),
    route: boundedString(safeRoute, 1000),
    redactedRoute: boundedString(redactedRoute, INVESTIGATION_CASE_LIMITS.maxTargetRouteChars),
    routeRedacted: Boolean(source.routeRedacted || (rawRoute && !safeRoute)),
  };
}

function cleanTargetSummary(target = {}) {
  const rawRoute = String(target.route || "");
  const route = cleanTargetRoute(rawRoute);
  return {
    kind: target.kind ? safeToken(target.kind) : "",
    key: boundedString(redactCaseString(target.key || ""), INVESTIGATION_CASE_LIMITS.maxTargetKeyChars),
    route,
    routeRedacted: Boolean(target.routeRedacted || (rawRoute && !route)),
    source: boundedString(redactCaseString(target.source || ""), INVESTIGATION_CASE_LIMITS.maxTargetSourceChars),
    title: boundedString(redactCaseString(target.title || ""), INVESTIGATION_CASE_LIMITS.maxTargetTitleChars),
    pinnedAt: timestampString(target.pinnedAt),
    collectedAt: timestampString(target.collectedAt),
    addedAt: timestampString(target.addedAt),
  };
}

function cleanTargetRoute(value = "") {
  const text = redactCaseString(String(value || "").trim());
  if (!text.startsWith("#/")) return "";
  if (/[\u0000-\u001f\u007f]/.test(text)) return "";
  return boundedString(text, INVESTIGATION_CASE_LIMITS.maxTargetRouteChars);
}

function cleanServerCustody(custody = {}) {
  return {
    caseId: normalizeInvestigationServerCaseId(custody.caseId || ""),
    evidenceId: boundedString(redactCaseString(custody.evidenceId || ""), 160),
    addedAt: timestampString(custody.addedAt),
    addedBy: boundedString(redactCaseString(custody.addedBy || ""), 160),
    target: cleanTargetSummary(custody.target || {}),
  };
}

function cleanSummary(summary = {}) {
  const out = {};
  for (const [key, value] of Object.entries(summary || {}).slice(0, 24)) {
    if (value == null || value === "") continue;
    if (typeof value === "object") continue;
    out[key] = typeof value === "string" ? boundedString(redactCaseString(value), 320) : value;
  }
  return out;
}

function redactCaseValue(value, depth = 0) {
  if (value == null) return value;
  if (typeof value === "string") return redactCaseString(value);
  if (typeof value === "number") return Number.isFinite(value) ? value : 0;
  if (typeof value === "boolean") return value;
  if (Array.isArray(value)) {
    if (depth > 8) return [];
    return value.map((item) => redactCaseValue(item, depth + 1));
  }
  if (typeof value !== "object") return String(value);
  if (depth > 8) return {};
  const out = {};
  for (const [key, child] of Object.entries(value)) {
    out[key] = redactCaseValue(child, depth + 1);
  }
  return out;
}

function redactCaseString(value) {
  return redactSensitivePairs(redactServerLocalPaths(redactSensitiveURLs(boundedString(value))));
}

function redactServerLocalPaths(value) {
  return String(value).replace(
    /(^|[\s"'({=,;])\/(?:var\/lib|var\/log(?:\/openngfw)?|etc\/(?:openngfw|phragma)?|tmp|private\/tmp|var\/folders|private\/var\/folders|home\/[^'"\s,;}]+|Users\/[^'"\s,;}]+|opt\/[^'"\s,;}]+|data\/[^'"\s,;}]+)[^'"\s,;}]*/gi,
    "$1[server-local path redacted]",
  );
}

function redactSensitiveURLs(value) {
  return String(value).replace(/https?:\/\/[^\s"'<>]+/gi, (raw) => {
    try {
      const parsed = new URL(raw);
      if (parsed.username || parsed.password) parsed.username = "[redacted]";
      parsed.password = "";
      for (const key of [...parsed.searchParams.keys()]) {
        if (isSensitiveKey(key)) parsed.searchParams.set(key, "[redacted]");
      }
      return parsed.toString();
    } catch {
      return raw;
    }
  });
}

function redactSensitivePairs(value) {
  return String(value)
    .replace(/\b(Authorization:\s*Bearer)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 [redacted]")
    .replace(/\b(Bearer)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 [redacted]")
    .replace(/\b(token|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|password|passwd|secret|client[_-]?secret)\s*[:=]\s*[^\s"',;}&]+/gi, (match, key) => `${key}=[redacted]`);
}

function isSensitiveKey(key) {
  const normalized = String(key || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  return normalized.includes("token") ||
    normalized.includes("password") ||
    normalized.includes("secret") ||
    normalized.includes("apikey") ||
    normalized.includes("accesskey") ||
    normalized === "key";
}

function firstValue(...values) {
  for (const value of values) {
    if (value == null || value === "") continue;
    return value;
  }
  return "";
}

function timestampString(value) {
  if (!value) return "";
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toISOString();
}

function timestampForFilename(now = new Date()) {
  const date = now instanceof Date ? now : new Date(now);
  return (Number.isNaN(date.getTime()) ? new Date() : date).toISOString().replace(/[:.]/g, "-");
}

function boundedString(value, limit = 1600) {
  const text = String(value ?? "");
  return text.length > limit ? text.slice(0, limit - 15) + "...[truncated]" : text;
}

function safeToken(value) {
  return String(value || "").trim().toLowerCase().replace(/[^a-z0-9_.:-]+/g, "-").replace(/^-+|-+$/g, "") || "investigation";
}

function stableToken(value) {
  const text = String(value || "").trim().toLowerCase();
  return text.replace(/[^a-z0-9_.:@/?&=-]+/g, "-").replace(/^-+|-+$/g, "") || "selected";
}

function unique(values = []) {
  return [...new Set(values)];
}

function countBy(values = []) {
  const counts = {};
  for (const value of values) counts[value] = (counts[value] || 0) + 1;
  return counts;
}

function kindLabel(kind = "") {
  return String(kind || "selected").replace(/[-_]+/g, " ");
}

function defaultStorage() {
  return globalThis.localStorage || null;
}
