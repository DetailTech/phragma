// Threats — IDS/IPS alerts with severity facets, search, drill-in, and a
// one-click pivot to a drop rule (the observe → act loop).

import { h, icon, clear } from "../core.js";
import { api } from "../api.js";
import { throwIfAccessDenied } from "../auth_gate.js";
import { cliCommand, openAutomationContext } from "../automation_context.js";
import { session } from "../policy.js";
import { readQueryState, writeQueryState } from "../query_state.js";
import { normalizePolicyDiffLines, policyDiffLabels, renderDiffLines } from "../diff_view.js";
import { pageHead, emptyState, pill, toast, openDrawer, closeDrawer, keyboardRowAttrs, labeledCell, responsiveTable } from "../ui.js";
import * as fmt from "../format.js";
import { evidenceToolbar } from "../evidence_toolbar.js";
import { alertHandoffPacket, buildInvestigationPacket, investigationPacketFilename, investigationPacketJson, investigationPacketText } from "../investigation_packet.js";
import { activeInvestigationServerCaseId, caseEvidencePayloadFromPacket, caseItemKey, pinInvestigationPacket } from "../investigation_case.js";
import { captureEvidencePanel } from "../capture_evidence.js";
import { captureAuditHash } from "../packet_capture.js";
import { currentInspectionPosture, degradedEngineEvidence, inspectionPostureSummary } from "../inspection_posture.js";
import { investigationHashFromFlow, openTroubleshootInvestigation } from "../investigation_route.js";
import { savedFilterControls } from "../saved_filters.js";
import { buildContentPosture, contentCanaryTelemetryWorkbench } from "../content_posture.js";
import { openRuleEditorPrefilled } from "./rules.js";
import { openIdsEditor, idsStatusPill, idsProfileSummary, idsRolloutActions, applyIdsProfilePreset } from "./ids.js";

const DEFAULT_STATE = { q: "", sev: 0, action: "", ip: "", protocol: "", signatureId: "", threatSeverity: "", port: "", since: "", until: "", limit: "500", pageCursor: "", pageStack: "", flowId: "", alert: "", view: "alerts", exception: "", caseKey: "", caseAction: "", caseKind: "" };
const QUERY_KEYS = Object.keys(DEFAULT_STATE);
const SAVED_FILTER_KEYS = QUERY_KEYS.filter((key) => !["pageCursor", "pageStack", "alert", "flowId", "view", "exception", "caseKey", "caseAction", "caseKind"].includes(key));
let state = { ...DEFAULT_STATE };
let routePath = "/threats";
let lastOpenedAlert = "";
let lastOpenedException = "";
let runtimeStatus = {};
let threatContentPosture = null;
let threatExceptionInventory = { exceptions: [] };
let threatReplay = { loading: false, result: null, error: "" };

const ALERT_EVIDENCE_COLUMNS = [
  { key: "time", label: "Time" },
  { key: "policyVersion", label: "Policy version" },
  { key: "policyContext", label: "Policy context" },
  { key: "threatId", label: "Threat-ID" },
  { key: "threatName", label: "Threat name" },
  { key: "threatSeverity", label: "Threat severity" },
  { key: "threatPackageVersion", label: "Package version" },
  { key: "threatPackageManifestSha256", label: "Package manifest" },
  { key: "signatureId", label: "Signature ID" },
  { key: "signature", label: "Signature" },
  { key: "category", label: "Category" },
  { key: "action", label: "Outcome" },
  { key: "protocol", label: "Protocol" },
  { key: "srcIp", label: "Source IP" },
  { key: "srcPort", label: "Source port" },
  { key: "destIp", label: "Destination IP" },
  { key: "destPort", label: "Destination port" },
  { key: "flowId", label: "Flow ID" },
];

export async function render(ctx = {}) {
  routePath = ctx.path || "/threats";
  state = normalizeThreatState(readQueryState(ctx.query, DEFAULT_STATE, QUERY_KEYS));
  lastOpenedAlert = "";
  lastOpenedException = "";
  const root = h("div", {});
  await loadAndPaint(root);
  return root;
}

async function loadAndPaint(root) {
  clear(root);
  root.appendChild(h("div", { class: "loading" }, "Loading threats…"));
  const statusPromise = api.status().catch((e) => ({ inspection: { state: "unknown", detail: e.message || String(e) } }));
  const contentPromise = api.contentPackages().catch((e) => ({ packages: [], error: e.message || String(e) }));
  const exceptionsPromise = api.threatExceptions().catch((e) => ({ exceptions: [], error: e.message || String(e) }));
  const [alertsR, statusR, contentR, exceptionsR, sessionR] = await Promise.allSettled([api.alerts(alertRequest()), statusPromise, contentPromise, exceptionsPromise, session.load()]);
  throwIfAccessDenied(alertsR, statusR, contentR, exceptionsR, sessionR);
  if (alertsR.status !== "fulfilled" || sessionR.status !== "fulfilled") {
    paintThreatLoadFailure(root, firstRejectedReason(alertsR, sessionR));
    return;
  }
  const data = alertsR.value || {};
  const status = statusR.status === "fulfilled" ? statusR.value : {};
  const content = contentR.status === "fulfilled" ? contentR.value : { packages: [], error: loadErrorDetail(contentR.reason, "Content package status unavailable.") };
  const exceptions = exceptionsR.status === "fulfilled" ? exceptionsR.value : { exceptions: [], error: loadErrorDetail(exceptionsR.reason, "Threat exceptions unavailable.") };
  runtimeStatus = status || {};
  threatContentPosture = buildContentPosture([], session.draft || {}, content.packages || [], content.error || "");
  threatExceptionInventory = exceptions || { exceptions: [] };
  paint(root, data, runtimeStatus);
  if (state.view === "exceptions") maybeOpenThreatException(root, data, threatExceptionInventory.exceptions || []);
  else maybeOpenAlert(data.alerts || []);
}

function paintThreatLoadFailure(root, err) {
  runtimeStatus = {};
  threatContentPosture = buildContentPosture([], session.draft || {}, [], loadErrorDetail(err, "Threat package posture unavailable."));
  threatExceptionInventory = { exceptions: [], error: loadErrorDetail(err, "Threat exceptions unavailable.") };
  clear(root);
  root.appendChild(pageHead("Threats", "Threat telemetry unavailable",
    h("button", { class: "btn", type: "button", title: "Retry loading threat telemetry", "aria-label": "Retry loading threat telemetry", dataset: { threatAction: "retry-load" }, onclick: () => loadAndPaint(root) }, h("span", { html: icon("refresh", 16) }), "Retry")));
  root.appendChild(threatUnavailableBanner(err));
  root.appendChild(inspectionPostureStrip(runtimeStatus));
  root.appendChild(degradedEngineEvidenceStrip(runtimeStatus));
  const packageStrip = threatPackagePostureStrip(threatContentPosture);
  if (packageStrip) root.appendChild(packageStrip);
  root.appendChild(alertFilterBar(root));
  root.appendChild(emptyState("shield", "Threat data unavailable", "The Threats workspace shell is still available. Retry the alert request or use API / CLI context to verify IDS/IPS telemetry.",
    h("button", { class: "btn", type: "button", title: "Open Threats API and CLI context", "aria-label": "Open Threats API and CLI context", dataset: { threatAction: "api-cli" }, onclick: () => openAutomationContext(routePath) }, h("span", { html: icon("terminal", 16) }), "API / CLI")));
}

function threatUnavailableBanner(err) {
  return h("div", { class: "alert-box bad", dataset: { threatLoadError: "true" } },
    h("strong", {}, "Threat telemetry unavailable. "),
    loadErrorDetail(err, "The alerts API did not return data."));
}

function firstRejectedReason(...results) {
  const failed = results.find((result) => result?.status === "rejected");
  return failed?.reason || new Error("request failed");
}

function loadErrorDetail(err, fallback) {
  return err?.message || String(err || fallback);
}

function idsBtn(root, data) {
  return h("button", { class: "btn", type: "button", title: "Open IDS/IPS settings", "aria-label": "Open IDS/IPS settings", dataset: { threatAction: "ids-settings" }, onclick: () => openIdsEditor(() => paint(root, data, runtimeStatus)) },
    h("span", { html: icon("threats", 16) }), "IDS/IPS settings");
}

function inspectionPostureStrip(status = {}) {
  const posture = currentInspectionPosture(status);
  return h("div", { class: "inspection-posture alert-box " + inspectionPostureBoxClass(posture.cls) },
    h("div", { class: "flex wrap", style: { justifyContent: "space-between" } },
      h("div", { class: "flex wrap" },
        h("strong", {}, "Current inspection posture"),
        pill(posture.label, posture.cls, true),
        h("span", { class: "tag" }, posture.engineLabel))),
    h("div", { class: "note" }, posture.detail),
    h("div", { class: "note" }, "Current runtime posture at handoff time; threat rows retain their own event policy context when stamped."));
}

function degradedEngineEvidenceStrip(status = {}) {
  const model = degradedEngineEvidence(status, session.running || session.draft || {});
  return h("div", { class: "inspection-posture alert-box " + inspectionPostureBoxClass(model.cls), dataset: { threatEngineEvidence: model.state || "unknown" } },
    h("div", { class: "flex wrap", style: { justifyContent: "space-between" } },
      h("div", { class: "flex wrap" },
        h("strong", {}, "Engine degradation evidence"),
        pill(model.label || model.state || "unknown", model.cls || "neutral", true),
        model.failMode ? h("span", { class: "tag" }, model.failMode) : null),
      h("a", { class: "linklike", href: "#/inspection", title: "Open inspection workspace", "aria-label": "Open inspection workspace", dataset: { threatAction: "open-inspection-workspace" } }, "Inspection ->")),
    h("div", { class: "note" }, (model.impact || []).slice(0, 2).join(" ")),
    h("div", { class: "note" }, (model.limitations || []).join(" ")));
}

function inspectionPostureBoxClass(cls) {
  if (cls === "bad" || cls === "warn" || cls === "ok" || cls === "info") return cls;
  return "info";
}

function paint(root, data, status = {}) {
  const alerts = data.alerts || [];
  clear(root);
  const ids = session.draft.ids || {};
  root.appendChild(pageHead("Threats",
    h("span", { class: "flex", style: { gap: "8px" } }, joinParts(`${alerts.length} recent IDS/IPS detections`, telemetryContextLabel(data)), h("span", {}, "·"), idsStatusPill(ids)),
    h("span", { class: "flex", style: { gap: "8px" } }, idsBtn(root, data),
      h("button", { class: "btn", type: "button", title: state.view === "exceptions" ? "Return to threat alert triage" : "Manage threat exceptions", "aria-label": state.view === "exceptions" ? "Return to threat alert triage" : "Manage threat exceptions", dataset: { threatAction: "manage-exceptions" }, onclick: async () => {
        state.view = state.view === "exceptions" ? "alerts" : "exceptions";
        state.alert = "";
        state.exception = "";
        syncRoute();
        await loadAndPaint(root);
      } }, h("span", { html: icon("threats", 16) }), state.view === "exceptions" ? "Alert triage" : "Manage exceptions"),
	      h("button", { class: "btn", type: "button", title: "Refresh threat detections", "aria-label": "Refresh threat detections", dataset: { threatAction: "refresh" }, onclick: () => loadAndPaint(root) }, h("span", { html: icon("refresh", 16) }), "Refresh"))));

  root.appendChild(inspectionPostureStrip(status));
  root.appendChild(degradedEngineEvidenceStrip(status));
  const packageSummary = threatPackageSummary(threatContentPosture);
  const packageStrip = threatPackagePostureStrip(threatContentPosture);
  if (packageStrip) root.appendChild(packageStrip);
  root.appendChild(stagedIdsProfileStrip(root, data, ids, session.running.ids || {}, packageSummary));
  root.appendChild(threatReplayPanel(root));

  if (state.view === "exceptions") {
    root.appendChild(threatExceptionWorkbench(root, data, threatExceptionInventory));
    return;
  }

  root.appendChild(alertFilterBar(root));

  if (!alerts.length) {
    const why = ids.enabled
      ? "The inspection engine is enabled but hasn't logged any alerts yet. Generate traffic through the firewall, or load rules (e.g. ids-ips-update)."
      : "IDS/IPS is disabled, so no traffic is being inspected. Enable it to populate Threats and Traffic.";
    root.appendChild(emptyState("shield", ids.enabled ? "No detections yet" : "Inspection is off", why,
      h("button", { class: "btn primary", type: "button", title: ids.enabled ? "Open IDS/IPS settings" : "Enable IDS/IPS inspection", "aria-label": ids.enabled ? "Open IDS/IPS settings" : "Enable IDS/IPS inspection", dataset: { threatAction: "ids-settings" }, onclick: () => openIdsEditor(() => location.reload()) }, h("span", { html: icon("threats", 16) }), ids.enabled ? "IDS/IPS settings" : "Enable IDS/IPS")));
    return;
  }

  // Severity facet tiles
  const counts = { 1: 0, 2: 0, 3: 0, 4: 0 };
  alerts.forEach((a) => counts[fmt.severity(a.severity).n]++);
  const facet = (n, label) => h("button", {
    class: "card tight threat-facet" + (state.sev === n ? " is-selected" : ""),
    type: "button",
    title: `Filter threat alerts to ${label} severity`,
    "aria-label": `Filter threat alerts to ${label} severity`,
    "aria-pressed": state.sev === n ? "true" : "false",
    dataset: { threatFacet: String(n) },
    onclick: async () => { state.sev = state.sev === n ? 0 : n; state.pageCursor = ""; state.pageStack = ""; state.alert = ""; syncRoute(); await loadAndPaint(root); },
  }, h("div", { class: "stat" }, h("span", { class: "stat-label" }, label),
      h("span", { class: "stat-value " + ("sev-" + n) }, String(counts[n]))));
  root.appendChild(h("div", { class: "grid cols-4 threat-facet-grid" },
    facet(1, "Critical"), facet(2, "High"), facet(3, "Medium"), facet(4, "Low")));

  const actionSel = h("select", { class: "input threat-outcome-filter", onchange: async (e) => { state.action = e.target.value; state.pageCursor = ""; state.pageStack = ""; state.alert = ""; syncRoute(); await loadAndPaint(root); } },
    h("option", { value: "" }, "All outcomes"), h("option", { value: "blocked" }, "Dropped"), h("option", { value: "allowed" }, "Detected only"));
  actionSel.value = state.action;
  root.appendChild(h("div", { class: "toolbar" },
    h("div", { class: "note" }, pageSummary(alerts.length, data, "matching detection")),
    paginationControls(root, data),
    actionSel,
    state.sev ? h("button", { class: "btn sm ghost", type: "button", title: "Clear threat severity filter", "aria-label": "Clear threat severity filter", dataset: { threatAction: "clear-severity-filter" }, onclick: async () => { state.sev = 0; state.pageCursor = ""; state.pageStack = ""; state.alert = ""; syncRoute(); await loadAndPaint(root); } }, "Clear severity filter") : null));
  root.appendChild(evidenceToolbar({
    surface: "threat-alerts",
    title: "Threat evidence",
    summary: "Filtered IDS/IPS alerts with policy and tuple context.",
    request: alertRequest,
    rows: () => alertEvidenceRows(alerts),
    columns: ALERT_EVIDENCE_COLUMNS,
    route: () => location.hash || "#/threats",
    apiPath: "/v1/alerts",
    cliCommand: () => alertCliCommandFromRequest(alertRequest()),
  }));

  const wrap = h("div", { class: "table-wrap" });
  root.appendChild(wrap);
  function repaint() { renderTable(wrap, alerts); }
  repaint();
}

function filtered(alerts) {
  return alerts.filter((a) => {
    if (state.sev && fmt.severity(a.severity).n !== state.sev) return false;
    if (state.action && a.action !== state.action) return false;
    return true;
  });
}

function alertEvidenceRows(alerts) {
  return filtered(alerts).map((alert) => {
    const packageProvenance = threatPackageProvenanceFromAlert(alert);
    return {
      ...alert,
      threatPackageVersion: packageProvenance.version,
      threatPackageManifestSha256: packageProvenance.manifestShort,
    };
  });
}

function renderTable(wrap, alerts) {
  clear(wrap);
  const rows = filtered(alerts);
  if (!rows.length) { wrap.appendChild(emptyState("search", "No matching alerts", "Adjust your filters.")); return; }
  wrap.appendChild(responsiveTable([
    { label: "Severity", attrs: { class: "threat-severity-col" } },
    "Policy",
    "Threat-ID",
    "Source",
    "Destination",
    "Outcome",
    { label: "Time", attrs: { class: "threat-time-col" } },
  ], rows.slice(0, 300).map((a) => {
      const s = threatSeverity(a), act = fmt.alertAction(a.action);
      return h("tr", { ...keyboardRowAttrs(() => detail(a), { label: `Open threat ${a.threatName || a.threatId || a.signatureId || "alert"}` }), dataset: { threatAlertRow: alertKey(a) || "" } },
        labeledCell("Severity", {}, pill(s.label, s.cls, true)),
        labeledCell("Policy", {}, eventPolicyPill(a)),
        labeledCell("Threat-ID", { class: "threat-id-cell" },
          threatName(a), h("div", { class: "note" }, threatSubline(a))),
        labeledCell("Source", { class: "mono" }, fmt.endpoint(a.srcIp, a.srcPort)),
        labeledCell("Destination", { class: "mono" }, fmt.endpoint(a.destIp, a.destPort)),
        labeledCell("Outcome", {}, pill(act.label, act.cls)),
        labeledCell("Time", { class: "muted cell-time", title: fmt.absTime(a.time) }, fmt.relTime(a.time)));
    }), { className: "threats-table" }));
}

function alertFilterBar(root) {
  const query = h("input", { class: "input", type: "search", value: state.q, placeholder: "threat, signature, category, evidence" });
  const ip = h("input", { class: "input mono", value: state.ip, placeholder: "10.100.1.2" });
  const protocol = h("select", { class: "input" },
    option("", "Any protocol"),
    option("TCP", "TCP"),
    option("UDP", "UDP"),
    option("ICMP", "ICMP"));
  protocol.value = state.protocol;
  const threatSeverity = h("select", { class: "input" },
    option("", "Any severity"),
    option("critical", "Critical"),
    option("high", "High"),
    option("medium", "Medium"),
    option("low", "Low"),
    option("info", "Info"));
  threatSeverity.value = state.threatSeverity;
  const signatureId = h("input", { class: "input", type: "number", min: "1", value: state.signatureId, placeholder: "SID" });
  const port = h("input", { class: "input", type: "number", min: "1", max: "65535", value: state.port, placeholder: "port" });
  const since = h("input", { class: "input", type: "datetime-local", value: state.since });
  const until = h("input", { class: "input", type: "datetime-local", value: state.until });
  const limit = h("select", { class: "input" },
    option("100", "100"),
    option("500", "500"),
    option("1000", "1000"));
  limit.value = state.limit;
  const apply = async () => {
    state = {
      ...state,
      q: query.value.trim(),
      ip: ip.value.trim(),
      protocol: protocol.value,
      threatSeverity: threatSeverity.value,
      signatureId: signatureId.value.trim(),
      port: port.value.trim(),
      since: since.value,
      until: until.value,
      flowId: "",
      limit: limit.value,
      pageCursor: "",
      pageStack: "",
      alert: "",
    };
    syncRoute();
    await loadAndPaint(root);
  };
  const submitOnEnter = (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      apply();
    }
  };
  [query, ip, signatureId, port, since, until].forEach((el) => el.addEventListener("keydown", submitOnEnter));
  return h("div", { class: "telemetry-filters" },
    h("label", { class: "field" }, h("span", {}, "Search"), query),
    h("label", { class: "field" }, h("span", {}, "IP"), ip),
    h("label", { class: "field" }, h("span", {}, "Protocol"), protocol),
    h("label", { class: "field" }, h("span", {}, "Threat severity"), threatSeverity),
    h("label", { class: "field" }, h("span", {}, "Signature ID"), signatureId),
    h("label", { class: "field" }, h("span", {}, "Port"), port),
    h("label", { class: "field" }, h("span", {}, "Since"), since),
    h("label", { class: "field" }, h("span", {}, "Until"), until),
    h("label", { class: "field" }, h("span", {}, "Limit"), limit),
    h("button", { class: "btn primary", type: "button", title: "Apply threat filters", "aria-label": "Apply threat filters", dataset: { threatAction: "apply-filters" }, onclick: apply }, h("span", { html: icon("filter", 16) }), "Apply filters"),
	    h("button", { class: "btn ghost", type: "button", title: "Reset threat filters", "aria-label": "Reset threat filters", dataset: { threatAction: "reset-filters" }, onclick: async () => {
      state = { ...DEFAULT_STATE };
      syncRoute();
      await loadAndPaint(root);
    } }, "Reset"),
    savedFilterControls({ scope: "threats", state, defaults: DEFAULT_STATE, keys: SAVED_FILTER_KEYS, onApply: (next) => applySavedThreatFilter(root, next) }));
}

async function applySavedThreatFilter(root, next) {
  state = normalizeThreatState({ ...DEFAULT_STATE, ...next, pageCursor: "", pageStack: "", alert: "" });
  syncRoute();
  await loadAndPaint(root);
}

function alertRequest() {
  return alertRequestFromState(state);
}

export function alertRequestFromState(s = {}) {
  const req = { limit: Number(s.limit) || 500 };
  if (s.q) req.query = s.q;
  if (s.ip) req.ip = s.ip;
  if (s.protocol) req.protocol = s.protocol;
  if (s.action) req.action = s.action;
  if (s.sev) req.severity = String(s.sev);
  if (s.threatSeverity) req.threatSeverity = s.threatSeverity;
  if (s.signatureId) req.signatureId = s.signatureId;
  if (s.port) req.port = s.port;
  if (s.since) req.since = localDateTimeToISOString(s.since);
  if (s.until) req.until = localDateTimeToISOString(s.until);
  if (s.flowId) req.flowId = s.flowId;
  if (s.pageCursor) req.pageCursor = s.pageCursor;
  return req;
}

export function alertCliCommandFromRequest(req = {}) {
  return cliCommand("ngfwctl alerts", [
    ["--limit", req.limit],
    ["--query", req.query],
    ["--ip", req.ip],
    ["--protocol", req.protocol],
    ["--action", req.action],
    ["--severity", req.severity],
    ["--threat-severity", req.threatSeverity],
    ["--signature-id", req.signatureId],
    ["--port", req.port],
    ["--flow-id", req.flowId],
    ["--since", req.since],
    ["--until", req.until],
  ]);
}

function localDateTimeToISOString(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toISOString();
}

function option(value, label) {
  return h("option", { value }, label);
}

function detail(a) {
  const key = alertKey(a);
  if (key) {
    state.alert = key;
    syncRoute();
  }
  const s = threatSeverity(a), act = fmt.alertAction(a.action);
  const packageSummary = threatPackageSummary(threatContentPosture);
  const packageProvenance = threatPackageProvenanceFromAlert(a);
  openDrawer({
    title: "Threat detail",
    subtitle: threatName(a),
    width: "620px",
    onClose: clearThreatSelection,
    body: h("div", {},
      h("div", { class: "flex wrap", style: { marginBottom: "16px" } }, pill(s.label, s.cls, true), pill(act.label, act.cls),
        a.threatConfidence ? h("span", { class: "tag" }, a.threatConfidence + "% confidence") : null,
        a.protocol ? h("span", { class: "tag" }, a.protocol) : null,
        a.signatureId ? h("span", { class: "tag" }, "SID " + a.signatureId) : null),
      h("dl", { class: "kv" },
        kv("Threat-ID", a.threatId || "unknown-threat"),
        kv("Threat category", a.threatCategory || "unknown"),
        kv("Signature", a.signature || "—"), kv("Engine category", a.category || "—"),
        kv("Threat-ID package", packageSummary.label),
        kv("Package provenance", packageProvenance.label || "—"),
        kv("Package version", packageProvenance.version || "—"),
        kv("Package manifest", packageProvenance.manifestShort ? `sha256:${packageProvenance.manifestShort}` : "—"),
        kv("Flow ID", a.flowId || "—"),
        kv("Source", fmt.endpoint(a.srcIp, a.srcPort)), kv("Destination", fmt.endpoint(a.destIp, a.destPort)),
        kv("Protocol", a.protocol || "—"),
        kv("Event policy", eventPolicyLabel(a)),
        kv("Time", fmt.absTime(a.time))),
      threatPackageEvidenceBlock(packageSummary),
      threatAlertRegressionBridge(a, threatContentPosture),
      a.threatEvidence?.length ? h("div", {},
        h("h3", { style: { marginTop: "16px" } }, "Evidence"),
        h("ul", { class: "trace-list" }, a.threatEvidence.map((e) => h("li", {}, e)))) : null,
      captureEvidencePanel(a),
      handoffActions(threatWorkflowPacket(
        alertHandoffPacket(a, { route: currentRoute(), currentInspectionPosture: inspectionPostureSummary(runtimeStatus), threatPackageSummary: packageSummary }),
        threatAlertOperatorWorkflow(a, threatContentPosture),
      )),
      h("hr", { class: "divider" }),
      h("div", { class: "note", style: { marginBottom: "10px" } }, "Respond to this detection:")),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close threat detail", "aria-label": "Close threat detail", dataset: { threatAlertAction: "close" }, onclick: closeDrawer }, "Close"),
      a.flowId ? h("a", { class: "btn", href: relatedFlowHash(a), title: `Open related flow ${a.flowId}`, "aria-label": `Open related flow ${a.flowId}`, dataset: { threatAlertAction: "related-flow" }, onclick: closeDrawer }, h("span", { html: icon("traffic", 16) }), "Related flow") : null,
      h("button", { class: "btn", type: "button", title: "Explain this threat alert", "aria-label": "Explain this threat alert", dataset: { threatAlertAction: "explain" }, onclick: () => { closeDrawer(); explainThreat(a); } }, h("span", { html: icon("search", 16) }), "Explain"),
      h("button", { class: "btn", type: "button", title: "Start packet capture for this threat alert", "aria-label": "Start packet capture for this threat alert", dataset: { threatAlertAction: "capture" }, onclick: () => { closeDrawer(); captureThreat(a); } }, h("span", { html: icon("download", 16) }), "Capture"),
      h("a", { class: "btn", href: captureAuditHash(a), title: "Open packet capture audit for this threat alert", "aria-label": "Open packet capture audit for this threat alert", dataset: { threatAlertAction: "capture-audit" }, onclick: closeDrawer }, h("span", { html: icon("clock", 16) }), "Capture audit"),
      h("button", { class: "btn", type: "button", dataset: { threatAlertAction: "stage-fp" }, disabled: !signatureID(a), title: signatureID(a) ? "Stage a false-positive exception" : "This alert has no signature ID to suppress", "aria-label": signatureID(a) ? "Stage false-positive exception for this threat alert" : "Cannot stage false-positive exception without a signature ID", onclick: () => suppressThreat(a) }, h("span", { html: icon("check", 16) }), "Stage FP exception"),
      h("button", { class: "btn danger", type: "button", title: "Stage a drop rule for this threat source", "aria-label": "Stage a drop rule for this threat source", dataset: { threatAlertAction: "drop-source" }, onclick: () => blockSource(a) }, h("span", { html: icon("block", 16) }), "Drop this source"),
    ],
  });
}

function threatPackagePostureStrip(posture) {
  const summary = threatPackageSummary(posture);
  if (!summary.available) return null;
  return h("div", { class: "alert-box " + summary.cls },
    h("div", { class: "flex wrap", style: { justifyContent: "space-between" } },
      h("div", { class: "flex wrap" },
        h("strong", {}, "Threat-ID package"),
        pill(summary.status, summary.cls, true),
        summary.version ? h("span", { class: "tag" }, summary.version) : null,
        h("span", { class: "tag" }, summary.packageState)),
      h("a", { class: "linklike", href: "#/intel?surface=threat-id&drawer=review", title: "Open Threat-ID intel review", "aria-label": "Open Threat-ID intel review", dataset: { threatAction: "threat-id-intel-review" } }, "Intel review ->")),
    h("div", { class: "note" }, summary.detail),
    summary.blockerCount ? h("div", { class: "note" }, `${summary.blockerCount} package gate${summary.blockerCount === 1 ? "" : "s"} need review before production rollout.`) : null);
}

function stagedIdsProfileStrip(root, data, ids = {}, runningIds = {}, packageSummary = null) {
  const summary = idsProfileSummary(ids, runningIds, packageSummary);
  const rolloutActions = idsRolloutActions(ids, runningIds, packageSummary);
  return h("div", { class: "profile-strip" },
    h("div", { class: "profile-strip-head" },
      h("div", { class: "flex wrap" },
        h("strong", {}, "Staged inspection profile"),
        pill(summary.status, summary.cls, true),
        h("span", { class: "tag" }, summary.stateLabel)),
      h("button", { class: "btn sm", type: "button", title: "Edit staged IDS/IPS inspection profile", "aria-label": "Edit staged IDS/IPS inspection profile", dataset: { threatAction: "ids-settings" }, onclick: () => openIdsEditor(() => paint(root, data, runtimeStatus)) },
        h("span", { html: icon("threats", 14) }), "Edit")),
    h("div", { class: "note" }, summary.detail),
    h("div", { class: "note" }, summary.stateDetail),
    summary.deltaLabel !== "none" ? h("div", { class: "note" }, "Candidate delta: " + summary.deltaLabel) : null,
    h("dl", { class: "kv compact" },
      kv("Mode", summary.modeLabel),
      kv("Interfaces", summary.monitorInterfacesLabel),
      kv("Home networks", summary.homeNetworksLabel),
      kv("Rule files", summary.ruleFilesLabel),
      kv("Failure behavior", summary.failureBehaviorLabel),
      kv("NFQUEUE", summary.queueLabel),
      kv("Exceptions", summary.exceptionCounts.label)),
    h("div", { class: "alert-box info", style: { marginBottom: "0" } },
      h("div", { class: "flex wrap", style: { justifyContent: "space-between" } },
        h("strong", {}, "Threat rollout actions"),
        h("span", { class: "tag" }, idsRolloutGateLabel(packageSummary))),
      h("div", { class: "note" }, "Candidate-only profile presets for detect, inline prevention, or inspection rollback."),
      h("div", { class: "flex wrap", style: { marginTop: "10px" } },
        rolloutActions.map((action) => idsRolloutActionButton(root, data, action)))),
    h("div", { class: "flex wrap" },
	      h("a", { class: "btn sm", href: "#/changes?tab=candidate", title: "Open candidate change review", "aria-label": "Open candidate change review", dataset: { threatAction: "open-candidate" } }, h("span", { html: icon("changes", 14) }), "Candidate"),
      h("a", { class: "btn sm", href: "#/threats?view=exceptions", title: "Manage threat exceptions", "aria-label": "Manage threat exceptions", dataset: { threatAction: "manage-exceptions" } }, h("span", { html: icon("threats", 14) }), "Exceptions"),
      h("a", { class: "btn sm", href: "#/intel?surface=threat-id&drawer=review", title: "Review Threat-ID package evidence", "aria-label": "Review Threat-ID package evidence", dataset: { threatAction: "open-intel" } }, h("span", { html: icon("intel", 14) }), "Intel")));
}

function threatReplayPanel(root) {
  const model = threatReplayModel(threatReplay);
  return h("div", { class: "profile-strip", dataset: { threatReplayWorkbench: "true" } },
    h("div", { class: "profile-strip-head" },
      h("div", { class: "flex wrap" },
        h("strong", {}, "Threat-ID replay evidence"),
        pill(model.stateLabel, model.cls, true),
        model.engineLabel ? h("span", { class: "tag" }, model.engineLabel) : null),
      h("div", { class: "flex wrap" },
        h("button", { class: "btn sm", type: "button", title: "Run Threat-ID replay evidence check", "aria-label": "Run Threat-ID replay evidence check", disabled: threatReplay.loading, dataset: { threatReplayAction: "run" }, onclick: () => runThreatReplay(root) },
          h("span", { html: icon("search", 14) }), threatReplay.loading ? "Checking..." : "Run replay"),
        h("button", { class: "btn sm ghost", type: "button", title: "Open Threat-ID replay API context", "aria-label": "Open Threat-ID replay API context", dataset: { threatReplayAction: "api-cli" }, onclick: () => openAutomationContext(currentRoute()) },
          h("span", { html: icon("terminal", 14) }), "API / CLI"))),
    h("div", { class: "note" }, model.detail),
    h("dl", { class: "kv compact" },
      kv("Bound", "current filters, max 25 recent alerts"),
      kv("Engine state", model.engineState || "unknown"),
      kv("Degraded mode", model.degradedBehavior || "—"),
      kv("Bypass", model.bypassLabel)),
    model.error ? h("div", { class: "alert-box warn" }, model.error) : null,
    model.warnings.length ? h("div", { class: "alert-box info" },
      h("ul", { class: "trace-list" }, model.warnings.slice(0, 4).map((item) => h("li", {}, item)))) : null,
    model.results.length ? h("div", { class: "table-wrap flat" },
      responsiveTable(["Sample", "Expected", "Observed", "Result"], model.results.slice(0, 8).map((item) =>
        h("tr", { dataset: { threatReplayResult: item.sampleId || item.sample_id || "" } },
          labeledCell("Sample", {}, h("strong", {}, item.sampleId || item.sample_id || "sample"), h("div", { class: "note" }, item.source || "evidence")),
          labeledCell("Expected", {}, replayExpectationCell(item.expected || {})),
          labeledCell("Observed", {}, replayObservedCell(item)),
          labeledCell("Result", {}, pill(item.passed ? "match" : "review", item.passed ? "ok" : "bad", true),
            h("div", { class: "note" }, replayMatchSummary(item))))),
        { className: "threat-replay-table" })) : null);
}

async function runThreatReplay(root) {
  threatReplay = { loading: true, result: threatReplay.result, error: "" };
  paint(root, { alerts: [] }, runtimeStatus);
  try {
    const result = await api.replayThreatEvidence(threatReplayRequestFromState(state));
    threatReplay = { loading: false, result, error: "" };
    toast("Threat-ID replay complete", result.detail || "Replay evidence check completed.", replayTone(result.state));
  } catch (e) {
    threatReplay = { loading: false, result: null, error: e.message || String(e) };
    toast("Replay failed", threatReplay.error, "bad");
  }
  await loadAndPaint(root);
}

export function threatReplayRequestFromState(s = {}) {
  const recentAlerts = { limit: Math.min(Math.max(Number(s.limit) || 10, 1), 25) };
  if (s.q) recentAlerts.query = s.q;
  if (s.signatureId) recentAlerts.signatureId = Number(s.signatureId);
  if (s.flowId) recentAlerts.flowId = s.flowId;
  if (s.action) recentAlerts.action = s.action;
  if (s.threatSeverity) recentAlerts.threatSeverity = s.threatSeverity;
  return { recentAlerts };
}

export function threatReplayModel(state = {}) {
  const result = state.result || {};
  const engine = result.engine || {};
  const rawState = state.error ? "unavailable" : result.state || "not run";
  const cls = rawState === "passed" ? "ok" : rawState === "mismatched" || rawState === "unavailable" ? "bad" : rawState === "degraded" ? "warn" : "info";
  const engineState = joinParts(engine.engineState || engine.engine_state, engine.inspectionState || engine.inspection_state);
  return {
    stateLabel: rawState,
    cls,
    detail: state.loading ? "Running bounded replay against recent alert evidence." : result.detail || "Run a bounded metadata-only replay against recent alert evidence and compare expected signature, Threat-ID, and verdict fields.",
    engineLabel: engine.engineName || engine.engine_name || "",
    engineState,
    degradedBehavior: engine.degradedBehavior || engine.degraded_behavior || "",
    bypassLabel: (engine.bypassPossible ?? engine.bypass_possible) ? (engine.bypassReason || engine.bypass_reason || "possible") : "not reported",
    warnings: result.warnings || [],
    results: result.results || [],
    error: state.error || "",
  };
}

function replayExpectationCell(expected = {}) {
  return h("div", {},
    h("div", { class: "mono" }, expected.threatId || expected.threat_id || "—"),
    h("div", { class: "note" }, joinParts(expected.signatureId || expected.signature_id ? `SID ${expected.signatureId || expected.signature_id}` : "", expected.verdict || "")));
}

function replayObservedCell(item = {}) {
  return h("div", {},
    h("div", { class: "mono" }, item.observedThreatId || item.observed_threat_id || "—"),
    h("div", { class: "note" }, joinParts(item.observedSignatureId || item.observed_signature_id ? `SID ${item.observedSignatureId || item.observed_signature_id}` : "", item.observedVerdict || item.observed_verdict || "", item.observedThreatSeverity || item.observed_threat_severity || "")));
}

function replayMatchSummary(item = {}) {
  const parts = [
    (item.signatureMatched ?? item.signature_matched) ? "signature ok" : "signature mismatch",
    (item.threatIdMatched ?? item.threat_id_matched) ? "Threat-ID ok" : "Threat-ID mismatch",
    (item.verdictMatched ?? item.verdict_matched) ? "verdict ok" : "verdict mismatch",
  ];
  return parts.join(" · ");
}

function replayTone(state = "") {
  if (state === "passed") return "ok";
  if (state === "degraded") return "warn";
  return "bad";
}

function idsRolloutGateLabel(packageSummary = null) {
  if (!packageSummary?.available) return "package unknown";
  if (packageSummary.blockerCount) return `${packageSummary.blockerCount} gate${packageSummary.blockerCount === 1 ? "" : "s"} open`;
  return packageSummary.version ? `package ${packageSummary.version}` : "package ready";
}

function idsRolloutActionButton(root, data, action) {
  const cls = "btn sm" + (action.tone === "bad" ? " danger" : action.tone === "neutral" ? " ghost" : "");
	  return h("button", {
	    class: cls,
	    type: "button",
	    dataset: { idsProfileAction: action.key || "" },
	    disabled: action.disabled,
	    title: action.disabledReason || action.detail,
	    "aria-label": `${action.label}: ${action.disabledReason || action.detail || "stage IDS/IPS profile change"}`,
	    onclick: () => stageIdsRolloutAction(root, data, action),
	  }, h("span", { html: icon(action.icon || "check", 14) }), action.label);
}

async function stageIdsRolloutAction(root, data, action) {
  try {
    await session.load();
    await session.apply((d) => applyIdsProfilePreset(d, action.key));
    paint(root, data, runtimeStatus);
    toast("Inspection profile staged", `${action.label.replace(/^Stage /, "")} is pending commit review.`, "ok");
  } catch (e) {
    toast("Could not stage inspection profile", e.message, "bad");
  }
}

function threatExceptionWorkbench(root, data, inventory = {}) {
  const model = threatExceptionWorkbenchModel(inventory);
  return h("div", { class: "profile-strip", dataset: { threatExceptionWorkbench: "true" } },
    h("div", { class: "profile-strip-head" },
      h("div", { class: "flex wrap" },
        h("strong", {}, "Threat-ID exceptions"),
        pill(model.sourceLabel, model.sourceCls),
        model.candidateDirty ? pill("candidate dirty", "violet", true) : pill("running aligned", "ok", true)),
      h("div", { class: "flex wrap" },
	        h("a", { class: "btn sm", href: "#/changes?tab=candidate", title: "Open candidate change review", "aria-label": "Open candidate change review", dataset: { threatExceptionAction: "open-candidate" } }, h("span", { html: icon("changes", 14) }), "Candidate"),
	        h("button", { class: "btn sm", type: "button", title: "Refresh threat exceptions", "aria-label": "Refresh threat exceptions", dataset: { threatExceptionAction: "refresh" }, onclick: () => loadAndPaint(root) }, h("span", { html: icon("refresh", 14) }), "Refresh"))),
    model.error ? h("div", { class: "alert-box warn" }, model.error) : null,
    h("div", { class: "note" }, "Lifecycle changes stage to the candidate only. Commit review is required before IDS/IPS engine receives or removes a suppression."),
    h("dl", { class: "kv compact" },
      kv("Active", String(model.active)),
      kv("Disabled", String(model.disabled)),
      kv("Candidate-only", String(model.candidateOnly)),
      kv("Changed from running", String(model.changed))),
    model.records.length ? threatExceptionTable(root, data, model.records) :
      emptyState("shield", "No false-positive exceptions", "Stage an exception from a threat alert, then manage it here before commit."));
}

function threatExceptionTable(root, data, records = []) {
  return h("div", { class: "table-wrap" },
    responsiveTable(["Threat-ID", "Scope", "Reason", "Review", "Policy state", { label: "Actions", attrs: { class: "actions-col" } }],
      records.map((record) => {
        const model = threatExceptionRecordModel(record, threatContentPosture);
        return h("tr", {
          ...keyboardRowAttrs(() => openThreatExceptionDetail(root, data, record), { label: `Open exception ${model.name}` }),
          dataset: { threatExceptionRow: model.name },
        },
          labeledCell("Threat-ID", {},
            h("strong", { class: model.threatId === "—" ? "muted" : "mono" }, model.threatId),
            h("div", { class: "note" }, model.signatureLabel),
            h("div", { class: "note" }, model.name)),
          labeledCell("Scope", {},
            h("span", { class: "tag" }, model.scopeLabel),
            h("div", { class: "note" }, model.scopeDetail)),
          labeledCell("Reason", {}, model.reason || h("span", { class: "muted" }, "No reason recorded")),
          labeledCell("Review", {},
            h("div", {}, model.owner || h("span", { class: "muted" }, "Unassigned")),
            h("div", { class: "note" }, joinParts(model.ticketId, model.expiresAt ? `expires ${model.expiresAt}` : "", model.reviewDate ? `review ${model.reviewDate}` : "") || "No review metadata"),
            h("div", { class: "note" }, model.bridge.summary)),
          labeledCell("Policy state", {}, pill(model.stateLabel, model.stateCls, model.stateDot),
            h("div", { class: "note" }, model.stateDetail)),
          labeledCell("Actions", { class: "cell-actions" },
            h("button", { class: "btn sm", type: "button", title: `Edit threat exception ${model.name}`, "aria-label": `Edit threat exception ${model.name}`, dataset: { threatExceptionAction: "edit" }, onclick: () => openThreatExceptionEdit(root, data, record) }, "Edit"),
            h("button", { class: "btn sm", type: "button", title: `${model.disabled ? "Enable" : "Disable"} threat exception ${model.name}`, "aria-label": `${model.disabled ? "Enable" : "Disable"} threat exception ${model.name}`, dataset: { threatExceptionAction: model.disabled ? "enable" : "disable" }, onclick: () => openThreatExceptionReasonDrawer(root, data, record, model.disabled ? "enable" : "disable") }, model.disabled ? "Enable" : "Disable"),
            h("button", { class: "btn sm danger", type: "button", title: `Remove threat exception ${model.name}`, "aria-label": `Remove threat exception ${model.name}`, dataset: { threatExceptionAction: "remove" }, onclick: () => openThreatExceptionReasonDrawer(root, data, record, "remove") }, "Remove")));
      }),
      { className: "threat-exception-table" }));
}

function openThreatExceptionDetail(root, data, record) {
  const model = threatExceptionRecordModel(record, threatContentPosture);
  state.view = "exceptions";
  state.exception = model.name;
  syncRoute();
  openDrawer({
    title: "Threat exception",
    subtitle: model.name,
    width: "680px",
    onClose: clearThreatExceptionSelection,
    body: h("div", { dataset: { threatExceptionDetail: model.name } },
      h("div", { class: "alert-box info" },
        h("strong", {}, "Candidate lifecycle. "),
        "Edits here change policy only; engine state changes after validate and commit."),
      h("dl", { class: "kv" },
        kv("Exception", model.name),
        kv("Signature ID", String(model.signatureId || "—")),
        kv("Threat-ID", model.threatId),
        kv("Scope", model.scopeLabel),
        kv("Scope object", model.scopeObject || "global"),
        kv("Reason", model.reason || "—"),
        kv("Owner", model.owner || "—"),
        kv("Ticket", model.ticketId || "—"),
        kv("Review date", model.reviewDate || "—"),
        kv("Expires", model.expiresAt || "—"),
        kv("PCAP SHA-256", model.pcapSha256 || "—"),
        kv("Regression ref", model.regressionRef || "—"),
        kv("Policy state", model.stateLabel),
        kv("Post-commit artifact", "openngfw-threshold.config")),
      threatExceptionBridgePanel(model, threatContentPosture),
      h("div", { class: "note" }, model.stateDetail)),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close threat exception detail", "aria-label": "Close threat exception detail", dataset: { threatExceptionAction: "close" }, onclick: closeDrawer }, "Close"),
      h("button", { class: "btn", type: "button", title: "Open threat exception API and CLI context", "aria-label": "Open threat exception API and CLI context", dataset: { threatExceptionAction: "api-cli" }, onclick: () => openAutomationContext(currentRoute()) }, h("span", { html: icon("terminal", 16) }), "API / CLI"),
      model.pcapSha256 ? h("a", { class: "btn", href: captureAuditHash({ sha256: model.pcapSha256 }), title: "Open packet-capture audit context for this exception PCAP hash", "aria-label": "Open packet-capture audit context for this exception PCAP hash", dataset: { threatExceptionAction: "pcap-audit" }, onclick: closeDrawer }, h("span", { html: icon("clock", 16) }), "PCAP audit") : null,
      h("a", { class: "btn", href: "#/intel?surface=threat-id&drawer=quality", title: "Review Threat-ID content quality evidence", "aria-label": "Review Threat-ID content quality evidence", dataset: { threatExceptionAction: "intel-quality" }, onclick: closeDrawer }, h("span", { html: icon("intel", 16) }), "Content quality"),
      h("a", { class: "btn", href: "#/intel?surface=threat-id&drawer=canary", title: "Review Threat-ID canary and false-positive telemetry", "aria-label": "Review Threat-ID canary and false-positive telemetry", dataset: { threatExceptionAction: "intel-canary" }, onclick: closeDrawer }, h("span", { html: icon("intel", 16) }), "Canary"),
      h("button", { class: "btn", type: "button", title: `Edit threat exception ${model.name}`, "aria-label": `Edit threat exception ${model.name}`, dataset: { threatExceptionAction: "edit" }, onclick: () => openThreatExceptionEdit(root, data, record) }, "Edit"),
      h("button", { class: "btn", type: "button", title: `${model.disabled ? "Enable" : "Disable"} threat exception ${model.name}`, "aria-label": `${model.disabled ? "Enable" : "Disable"} threat exception ${model.name}`, dataset: { threatExceptionAction: model.disabled ? "enable" : "disable" }, onclick: () => openThreatExceptionReasonDrawer(root, data, record, model.disabled ? "enable" : "disable") }, model.disabled ? "Enable" : "Disable"),
      h("button", { class: "btn danger", type: "button", title: `Remove threat exception ${model.name}`, "aria-label": `Remove threat exception ${model.name}`, dataset: { threatExceptionAction: "remove" }, onclick: () => openThreatExceptionReasonDrawer(root, data, record, "remove") }, "Remove"),
      h("a", { class: "btn primary", href: "#/changes?tab=candidate", title: "Review threat exception candidate changes", "aria-label": "Review threat exception candidate changes", dataset: { threatExceptionAction: "review-commit" }, onclick: closeDrawer }, h("span", { html: icon("upload", 16) }), "Review & commit"),
    ],
  });
}

function openThreatExceptionEdit(root, data, record) {
  closeDrawer({ invokeOnClose: false });
  const model = threatExceptionRecordModel(record);
  const sourceOptions = addressOptions();
  const name = h("input", { class: "input", value: model.name, maxlength: 64 });
  const signature = h("input", { class: "input", type: "number", min: "1", value: model.signatureId ? String(model.signatureId) : "" });
  const threatId = h("input", { class: "input", value: model.threatId === "—" ? "" : model.threatId, maxlength: 128 });
  const scope = h("select", { class: "input" },
    option("global", "Global signature"),
    option("source", "Source address object"),
    option("destination", "Destination address object"));
  scope.value = model.scopeKey;
  const sourceAddress = h("input", { class: "input", value: model.scopeKey === "source" ? model.scopeObject : "", list: "threat-exception-addresses", placeholder: "address object name" });
  const destinationAddress = h("input", { class: "input", value: model.scopeKey === "destination" ? model.scopeObject : "", list: "threat-exception-addresses", placeholder: "address object name" });
  const description = h("textarea", { class: "input", rows: 3, value: model.reason === "—" ? "" : model.reason, placeholder: "Exception reason stored in policy" });
  const owner = h("input", { class: "input", value: model.owner, maxlength: 80, placeholder: "secops-oncall" });
  const ticketId = h("input", { class: "input", value: model.ticketId, maxlength: 80, placeholder: "INC-2026-001" });
  const reviewDate = h("input", { class: "input", type: "date", value: model.reviewDate });
  const expiresAt = h("input", { class: "input", type: "date", value: model.expiresAt });
  const pcapSha256 = h("input", { class: "input mono", value: model.pcapSha256, maxlength: 64, placeholder: "64-character PCAP SHA-256" });
  const regressionRef = h("input", { class: "input", value: model.regressionRef, maxlength: 160, placeholder: "evidence/fp-regression.json" });
  const reason = h("textarea", { class: "input", rows: 3, placeholder: "Required audit reason for this lifecycle change" });
  const globalConfirm = h("input", { type: "checkbox" });
  const globalConfirmRow = h("label", { class: "field" },
    h("span", {}, "Global acknowledgement"),
    h("label", { class: "flex", style: { gap: "8px", alignItems: "center" } },
      globalConfirm, h("span", { class: "note" }, "I understand this stages an active global signature suppression.")));
  const preview = h("div", {});
  const save = h("button", { class: "btn primary", type: "button", title: `Stage edit for threat exception ${model.name}`, "aria-label": `Stage edit for threat exception ${model.name}`, dataset: { threatExceptionAction: "save-edit" } }, h("span", { html: icon("check", 16) }), "Stage edit");
  const refresh = () => {
    const req = threatExceptionUpdateRequest(model, {
      name: name.value,
      signatureId: signature.value,
      threatId: threatId.value,
      scope: scope.value,
      sourceAddress: sourceAddress.value,
      destinationAddress: destinationAddress.value,
      description: description.value,
      owner: owner.value,
      ticketId: ticketId.value,
      reviewDate: reviewDate.value,
      expiresAt: expiresAt.value,
      pcapSha256: pcapSha256.value,
      regressionRef: regressionRef.value,
      reason: reason.value,
      disabled: model.disabled,
      confirmGlobal: globalConfirm.checked,
    });
    globalConfirmRow.hidden = !(req.global && !model.disabled);
    save.disabled = !req.ok;
    save.title = req.ok ? `Stage edit for threat exception ${model.name}` : req.error || "Complete required fields before staging threat exception edit.";
    preview.replaceChildren(req.ok
      ? h("div", { class: "alert-box info" }, `Stages ${req.exception.name} as ${exceptionScopeLabelFromException(req.exception)} with audit reason.`)
      : h("div", { class: "alert-box warn" }, req.error || "Complete the required fields."));
  };
  [name, signature, threatId, scope, sourceAddress, destinationAddress, description, owner, ticketId, reviewDate, expiresAt, pcapSha256, regressionRef, reason, globalConfirm].forEach((el) => {
    el.addEventListener?.("input", refresh);
    el.addEventListener?.("change", refresh);
  });
  refresh();
  save.onclick = async () => {
    const req = threatExceptionUpdateRequest(model, {
      name: name.value,
      signatureId: signature.value,
      threatId: threatId.value,
      scope: scope.value,
      sourceAddress: sourceAddress.value,
      destinationAddress: destinationAddress.value,
      description: description.value,
      owner: owner.value,
      ticketId: ticketId.value,
      reviewDate: reviewDate.value,
      expiresAt: expiresAt.value,
      pcapSha256: pcapSha256.value,
      regressionRef: regressionRef.value,
      reason: reason.value,
      disabled: model.disabled,
      confirmGlobal: globalConfirm.checked,
    });
    if (!req.ok) { toast("Cannot stage edit", req.error, "warn"); return; }
    await mutateThreatException(root, data, "update", model.name, () => api.updateThreatException(model.name, {
      exception: req.exception,
      reason: req.reason,
      confirmGlobal: req.confirmGlobal,
    }));
  };
  openDrawer({
    title: "Edit threat exception",
    subtitle: model.name,
    width: "680px",
    body: h("div", { dataset: { threatExceptionEdit: model.name } },
      h("datalist", { id: "threat-exception-addresses" }, sourceOptions.map((addr) => h("option", { value: addr }))),
      h("div", { class: "alert-box warn" }, h("strong", {}, "Candidate-only. "), "The running suppression is unchanged until commit."),
      h("label", { class: "field" }, h("span", {}, "Exception name"), name),
      h("label", { class: "field" }, h("span", {}, "Signature ID"), signature),
      h("label", { class: "field" }, h("span", {}, "Threat-ID"), threatId),
      h("label", { class: "field" }, h("span", {}, "Scope"), scope),
      h("label", { class: "field" }, h("span", {}, "Source address object"), sourceAddress),
      h("label", { class: "field" }, h("span", {}, "Destination address object"), destinationAddress),
      h("label", { class: "field" }, h("span", {}, "Policy reason"), description),
      h("div", { class: "two-col" },
        h("label", { class: "field" }, h("span", {}, "Owner"), owner),
        h("label", { class: "field" }, h("span", {}, "Ticket / change ID"), ticketId)),
      h("div", { class: "two-col" },
        h("label", { class: "field" }, h("span", {}, "Review date"), reviewDate),
        h("label", { class: "field" }, h("span", {}, "Expires"), expiresAt)),
      h("label", { class: "field" }, h("span", {}, "PCAP SHA-256"), pcapSha256),
      h("label", { class: "field" }, h("span", {}, "Regression reference"), regressionRef),
      h("label", { class: "field" }, h("span", {}, "Audit reason"), reason),
      globalConfirmRow,
      preview),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: `Back to threat exception ${model.name}`, "aria-label": `Back to threat exception ${model.name}`, dataset: { threatExceptionAction: "back-to-detail" }, onclick: () => openThreatExceptionDetail(root, data, record) }, "Back"),
      save,
    ],
  });
}

function openThreatExceptionReasonDrawer(root, data, record, action) {
  closeDrawer({ invokeOnClose: false });
  const model = threatExceptionRecordModel(record);
  const reason = h("textarea", { class: "input", rows: 3, placeholder: reasonPlaceholder(action) });
  const globalConfirm = h("input", { type: "checkbox" });
  const needsGlobalConfirm = action === "enable" && model.scopeKey === "global";
  const submit = h("button", { class: "btn " + (action === "remove" ? "danger" : "primary"), type: "button", title: `${actionLabel(action)} threat exception ${model.name}`, "aria-label": `${actionLabel(action)} threat exception ${model.name}`, dataset: { threatExceptionAction: action } }, actionLabel(action));
  const refresh = () => {
    const ok = Boolean(reason.value.trim()) && (!needsGlobalConfirm || globalConfirm.checked);
    submit.disabled = !ok;
    submit.title = ok ? `${actionLabel(action)} threat exception ${model.name}` : needsGlobalConfirm ? "Reason and global acknowledgement are required." : "Reason is required.";
  };
  reason.addEventListener("input", refresh);
  globalConfirm.addEventListener("change", refresh);
  refresh();
  submit.onclick = async () => {
    const auditReason = reason.value.trim();
    if (!auditReason) { toast("Reason required", "Enter an audit reason for this lifecycle change.", "warn"); return; }
    if (needsGlobalConfirm && !globalConfirm.checked) { toast("Global acknowledgement required", "Confirm the global suppression before staging.", "warn"); return; }
    if (action === "remove") {
      await mutateThreatException(root, data, action, model.name, () => api.removeThreatException(model.name, auditReason));
      return;
    }
    await mutateThreatException(root, data, action, model.name, () => api.setThreatExceptionState(model.name, {
      disabled: action === "disable",
      reason: auditReason,
      confirmGlobal: Boolean(globalConfirm.checked),
    }));
  };
  openDrawer({
    title: actionTitle(action),
    subtitle: model.name,
    width: "560px",
    body: h("div", { dataset: { threatExceptionReason: action } },
      h("div", { class: "alert-box " + (action === "remove" ? "warn" : "info") },
        h("strong", {}, "Candidate-only. "),
        action === "remove" ? "Removal clears the suppression from candidate policy after commit." : "State changes are staged for commit review."),
      h("dl", { class: "kv compact" },
        kv("Signature ID", String(model.signatureId || "—")),
        kv("Scope", model.scopeLabel),
        kv("Current state", model.stateLabel)),
      h("label", { class: "field" }, h("span", {}, "Audit reason"), reason),
      needsGlobalConfirm ? h("label", { class: "field" },
        h("span", {}, "Global acknowledgement"),
        h("label", { class: "flex", style: { gap: "8px", alignItems: "center" } },
          globalConfirm, h("span", { class: "note" }, "I understand this re-enables a global signature suppression."))) : null),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: `Back to threat exception ${model.name}`, "aria-label": `Back to threat exception ${model.name}`, dataset: { threatExceptionAction: "back-to-detail" }, onclick: () => openThreatExceptionDetail(root, data, record) }, "Back"),
      submit,
    ],
  });
}

async function mutateThreatException(root, data, action, previousName, call) {
  try {
    const res = await call();
    if (res.validation && !res.validation.valid) {
      openThreatExceptionMutationResult(action, res);
      toast("Exception not staged", (res.validation.errors || []).slice(0, 2).join("; ") || "Candidate validation rejected this lifecycle change.", "bad");
      return;
    }
    await session.load();
    threatExceptionInventory = await api.threatExceptions().catch((e) => ({ exceptions: [], error: e.message || String(e) }));
    const result = threatExceptionMutationResultModel(action, res);
    state.view = "exceptions";
    state.exception = action === "remove" ? "" : (result.name || previousName);
    syncRoute();
    paint(root, data, runtimeStatus);
    openThreatExceptionMutationResult(action, res);
    toast("Threat exception staged", result.toastDetail, "ok");
  } catch (e) {
    toast("Could not stage exception change", e.message, "bad");
  }
}

function openThreatExceptionMutationResult(action, res = {}) {
  const model = threatExceptionMutationResultModel(action, res);
  openDrawer({
    title: model.title,
    subtitle: model.name || model.previousName || "Threat exception",
    width: "720px",
    body: h("div", { dataset: { threatExceptionMutationResult: model.name || model.previousName || "" } },
      h("div", { class: model.valid ? "alert-box ok" : "alert-box bad" },
        h("strong", {}, model.valid ? "Candidate only. " : "Not staged. "),
        model.valid ? "Review the diff and commit before engine state changes." : "Candidate validation rejected this lifecycle change."),
      h("dl", { class: "kv" },
        kv("Action", model.actionLabel),
        kv("Exception", model.name || "removed"),
        kv("Previous exception", model.previousName || "—"),
        kv("Signature ID", model.signatureId || "—"),
        kv("Scope", model.scopeLabel),
        kv("Candidate status", model.candidateLabel),
        kv("Post-commit artifact", "openngfw-threshold.config")),
      model.validationErrors.length ? h("div", { class: "alert-box bad" },
        h("strong", {}, "Validation errors"),
        h("ul", { class: "trace-list" }, model.validationErrors.map((item) => h("li", {}, item)))) : null,
      model.validationWarnings.length ? h("div", { class: "alert-box warn" },
        h("strong", {}, "Validation warnings"),
        h("ul", { class: "trace-list" }, model.validationWarnings.map((item) => h("li", {}, item)))) : null,
      h("details", { class: "diff-details", open: true },
        h("summary", {}, `Diff: ${model.diff.fromLabel} -> ${model.diff.toLabel}`),
        model.diff.changed ? renderDiffLines(model.diff.lines) : h("div", { class: "alert-box ok" }, "Candidate matches the running policy."))),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close threat exception result", "aria-label": "Close threat exception result", dataset: { threatExceptionAction: "close-result" }, onclick: closeDrawer }, "Close"),
      h("a", { class: "btn", href: "#/changes?tab=candidate", title: "Open candidate change review", "aria-label": "Open candidate change review", dataset: { threatExceptionAction: "open-candidate" }, onclick: closeDrawer }, h("span", { html: icon("changes", 16) }), "Open candidate"),
      h("a", { class: "btn primary", href: "#/changes?tab=candidate", title: "Review and commit threat exception candidate changes", "aria-label": "Review and commit threat exception candidate changes", dataset: { threatExceptionAction: "review-commit" }, onclick: closeDrawer }, h("span", { html: icon("upload", 16) }), "Review & commit"),
    ],
  });
}

export function threatExceptionWorkbenchModel(inventory = {}) {
  const records = (inventory.exceptions || []).map(threatExceptionRecordModel);
  return {
    records,
    error: inventory.error || "",
    active: records.filter((item) => !item.disabled).length,
    disabled: records.filter((item) => item.disabled).length,
    candidateOnly: records.filter((item) => item.candidateOnly).length,
    changed: records.filter((item) => item.changedFromRunning).length,
    sourceLabel: threatExceptionSourceLabel(inventory.source || inventory.policySource),
    sourceCls: (inventory.source || inventory.policySource) === "POLICY_SOURCE_RUNNING" ? "ok" : "violet",
    candidateDirty: Boolean(inventory.candidateStatus?.dirty ?? inventory.candidate_status?.dirty),
  };
}

export function threatExceptionRecordModel(record = {}, posture = null) {
  const ex = normalizeException(record.exception || record);
  const candidateOnly = Boolean(record.candidateOnly ?? record.candidate_only);
  const changedFromRunning = Boolean(record.changedFromRunning ?? record.changed_from_running);
  const presentInRunning = Boolean(record.presentInRunning ?? record.present_in_running);
  const scopeKey = exceptionScopeKey(record.scope, ex);
  let stateLabel = "running";
  let stateCls = "ok";
  let stateDetail = "Matches the running policy.";
  let stateDot = true;
  if (ex.disabled) {
    stateLabel = "disabled";
    stateCls = "neutral";
    stateDetail = presentInRunning ? "Disabled in the candidate policy." : "Staged disabled before first commit.";
    stateDot = false;
  } else if (candidateOnly) {
    stateLabel = "candidate";
    stateCls = "violet";
    stateDetail = "Staged only; commit before IDS/IPS engine receives this suppression.";
    stateDot = false;
  } else if (changedFromRunning) {
    stateLabel = "candidate edit";
    stateCls = "violet";
    stateDetail = "Differs from the running exception until commit.";
    stateDot = false;
  }
  return {
    ...ex,
    threatId: ex.threatId || "—",
    reason: ex.description || "",
    signatureLabel: ex.signatureId ? "SID " + ex.signatureId : "SID —",
    scopeKey,
    scopeObject: exceptionScopeObject(ex),
    scopeLabel: exceptionScopeLabel(scopeKey, exceptionScopeObject(ex)),
    scopeDetail: exceptionScopeDetail(scopeKey),
    candidateOnly,
    changedFromRunning,
    presentInRunning,
    stateLabel,
    stateCls,
    stateDetail,
    stateDot,
    bridge: threatExceptionRegressionBridge(ex, posture),
  };
}

export function threatExceptionRegressionBridge(record = {}, posture = null) {
  const ex = normalizeException(record.exception || record);
  const surface = threatPackageSurface(posture);
  const packageSummary = threatPackageSummary(posture);
  const keyRefs = surface?.keyContentEvidence || surface?.keyContentReadinessEvidence || packageSummary.keyContentEvidence || packageSummary.keyContentReadinessEvidence || {};
  const canary = surface ? contentCanaryTelemetryWorkbench(surface) : null;
  const canarySignalCount = String((Number(canary?.metrics?.falsePositiveSignals) || 0) + (Number(canary?.metrics?.canaryScopes) || 0));
  const context = [
    ex.pcapSha256 ? "exception PCAP hash" : "",
    ex.regressionRef ? "exception regression ref" : "",
    keyRefs.pcapRegressionCorpus ? "package PCAP corpus" : "",
    keyRefs.falsePositiveRegression ? "package false-positive corpus" : "",
    canary?.metrics?.falsePositiveSignals && canary.metrics.falsePositiveSignals !== "0" ? `${canary.metrics.falsePositiveSignals} canary FP signal${canary.metrics.falsePositiveSignals === "1" ? "" : "s"}` : "",
  ].filter(Boolean);
  return {
    hasExceptionEvidence: Boolean(ex.pcapSha256 || ex.regressionRef),
    pcapSha256: ex.pcapSha256 || "",
    regressionRef: ex.regressionRef || "",
    packageVersion: packageSummary.version || "",
    packageStatus: packageSummary.status || "unknown",
    pcapCorpus: evidenceRefSummary(keyRefs.pcapRegressionCorpus),
    falsePositiveCorpus: evidenceRefSummary(keyRefs.falsePositiveRegression),
    canaryStatus: canary?.cls || "warn",
    canarySignals: canarySignalCount,
    canaryScopes: canary?.metrics?.canaryScopes || "0",
    summary: context.length ? context.join(" · ") : "No PCAP/regression/canary context attached",
    routes: {
      pcapAudit: ex.pcapSha256 ? captureAuditHash({ sha256: ex.pcapSha256 }) : "",
      contentQuality: "#/intel?surface=threat-id&drawer=quality",
      canary: "#/intel?surface=threat-id&drawer=canary",
      candidate: "#/changes?tab=candidate",
    },
    boundary: "Read-only review handoff. Exception changes still stage through candidate workflows and require commit review.",
  };
}

export function threatExceptionUpdateRequest(current = {}, values = {}) {
  const name = cleanName(values.name);
  const signatureId = Number(values.signatureId || 0);
  const reason = String(values.reason || "").trim();
  const scope = values.scope || current.scopeKey || "global";
  const exception = {
    name,
    disabled: Boolean(values.disabled),
    signatureId: Number.isFinite(signatureId) ? Math.trunc(signatureId) : 0,
    threatId: String(values.threatId || "").trim(),
    description: String(values.description || "").trim() || reason,
    owner: compactThreatExceptionField(values.owner, 80),
    ticketId: compactThreatExceptionField(values.ticketId, 80),
    reviewDate: String(values.reviewDate || "").trim(),
    expiresAt: String(values.expiresAt || "").trim(),
    pcapSha256: String(values.pcapSha256 || "").trim().toLowerCase(),
    regressionRef: compactThreatExceptionField(values.regressionRef, 160),
  };
  if (scope === "source") exception.sourceAddress = String(values.sourceAddress || "").trim();
  if (scope === "destination") exception.destinationAddress = String(values.destinationAddress || "").trim();
  const global = scope === "global";
  if (!exception.name) return { ok: false, error: "exception name is required", exception, reason, global };
  if (!exception.signatureId || exception.signatureId < 1) return { ok: false, error: "signature_id must be positive", exception, reason, global };
  if (scope === "source" && !exception.sourceAddress) return { ok: false, error: "source address object is required", exception, reason, global };
  if (scope === "destination" && !exception.destinationAddress) return { ok: false, error: "destination address object is required", exception, reason, global };
  if (exception.reviewDate && !/^\d{4}-\d{2}-\d{2}$/.test(exception.reviewDate)) return { ok: false, error: "review_date must use YYYY-MM-DD", exception, reason, global };
  if (exception.expiresAt && !/^\d{4}-\d{2}-\d{2}$/.test(exception.expiresAt)) return { ok: false, error: "expires_at must use YYYY-MM-DD", exception, reason, global };
  if (exception.pcapSha256 && !/^[a-f0-9]{64}$/.test(exception.pcapSha256)) return { ok: false, error: "pcap_sha256 must be a 64-character SHA-256", exception, reason, global };
  if (!reason) return { ok: false, error: "audit reason is required", exception, reason, global };
  if (global && !exception.disabled && !values.confirmGlobal) return { ok: false, error: "global acknowledgement is required", exception, reason, global };
  return { ok: true, exception, reason, global, confirmGlobal: Boolean(values.confirmGlobal) };
}

function compactThreatExceptionField(value, maxLen) {
  const compact = String(value || "").trim().replace(/\s+/g, " ");
  return maxLen > 0 ? compact.slice(0, maxLen).trim() : compact;
}

function shortHash(value = "") {
  const v = String(value || "");
  return v.length > 16 ? v.slice(0, 16) : v;
}

export function threatExceptionMutationResultModel(action = "", res = {}) {
  const current = normalizeException(res.exception || {});
  const previous = normalizeException(res.previousException || res.previous_exception || {});
  const validation = res.validation || {};
  const candidate = res.candidateStatus || res.candidate_status || {};
  const labels = policyDiffLabels(res.diff || {}, "running policy", "candidate");
  const lines = normalizePolicyDiffLines(res.diff?.lines || []);
  const changeCount = Number(candidate.changeCount || candidate.change_count || 0);
  const dirty = Boolean(candidate.dirty ?? candidate.hasCandidate ?? candidate.has_candidate ?? changeCount > 0);
  const subject = current.name ? current : previous;
  const valid = validation.valid !== false;
  return {
    title: mutationTitle(action, valid),
    actionLabel: mutationActionLabel(action),
    name: current.name || "",
    previousName: previous.name || "",
    signatureId: subject.signatureId ? String(subject.signatureId) : "",
    scopeLabel: exceptionScopeLabel(exceptionScopeKey("", subject), exceptionScopeObject(subject)),
    candidateLabel: dirty ? `${changeCount || 1} pending change${(changeCount || 1) === 1 ? "" : "s"}` : "clean",
    validationErrors: Array.isArray(validation.errors) ? validation.errors : [],
    validationWarnings: Array.isArray(validation.warnings) ? validation.warnings : [],
    diff: { ...labels, lines, changed: lines.length > 0 },
    valid,
    toastDetail: mutationToastDetail(action, current.name || previous.name || "exception"),
  };
}

function normalizeException(ex = {}) {
  return {
    name: ex.name || "",
    disabled: Boolean(ex.disabled),
    signatureId: Number(ex.signatureId || ex.signature_id || 0),
    threatId: ex.threatId || ex.threat_id || "",
    sourceAddress: ex.sourceAddress || ex.source_address || "",
    destinationAddress: ex.destinationAddress || ex.destination_address || "",
    description: ex.description || "",
    owner: ex.owner || "",
    ticketId: ex.ticketId || ex.ticket_id || "",
    reviewDate: ex.reviewDate || ex.review_date || "",
    expiresAt: ex.expiresAt || ex.expires_at || "",
    pcapSha256: ex.pcapSha256 || ex.pcap_sha256 || "",
    regressionRef: ex.regressionRef || ex.regression_ref || "",
  };
}

function exceptionScopeKey(scope = "", ex = {}) {
  const value = String(scope || "").toLowerCase();
  if (value.includes("source") || ex.sourceAddress) return "source";
  if (value.includes("destination") || ex.destinationAddress) return "destination";
  return "global";
}

function exceptionScopeObject(ex = {}) {
  return ex.sourceAddress || ex.destinationAddress || "";
}

function exceptionScopeLabel(scopeKey, object = "") {
  if (scopeKey === "source") return "source " + (object || "address");
  if (scopeKey === "destination") return "destination " + (object || "address");
  return "global signature";
}

function exceptionScopeLabelFromException(ex = {}) {
  return exceptionScopeLabel(exceptionScopeKey("", normalizeException(ex)), exceptionScopeObject(normalizeException(ex)));
}

function exceptionScopeDetail(scopeKey) {
  if (scopeKey === "source") return "suppresses only matching source address object";
  if (scopeKey === "destination") return "suppresses only matching destination address object";
  return "suppresses all matching traffic after commit";
}

function threatExceptionSourceLabel(source = "") {
  if (source === "POLICY_SOURCE_CANDIDATE") return "candidate";
  if (source === "POLICY_SOURCE_RUNNING") return "running";
  if (source === "POLICY_SOURCE_VERSION") return "version";
  return "effective";
}

function addressOptions() {
  const values = [...(session.draft.addresses || []), ...(session.running.addresses || [])]
    .map((item) => item?.name || "")
    .filter(Boolean);
  return [...new Set(values)].sort();
}

function maybeOpenThreatException(root, data, records = []) {
  if (!state.exception) return;
  const record = records.find((item) => threatExceptionRecordModel(item).name === state.exception);
  if (!record || state.exception === lastOpenedException) return;
  lastOpenedException = state.exception;
  setTimeout(() => openThreatExceptionDetail(root, data, record), 0);
}

function clearThreatExceptionSelection() {
  state.exception = "";
  syncRoute();
}

function reasonPlaceholder(action) {
  if (action === "remove") return "Required: why this exception can be removed";
  if (action === "disable") return "Required: why this exception should be disabled";
  return "Required: why this exception should be re-enabled";
}

function actionTitle(action) {
  if (action === "remove") return "Remove threat exception";
  if (action === "disable") return "Disable threat exception";
  return "Enable threat exception";
}

function actionLabel(action) {
  if (action === "remove") return "Stage removal";
  if (action === "disable") return "Stage disable";
  return "Stage enable";
}

function mutationTitle(action, valid = true) {
  if (!valid) return "Threat exception rejected";
  if (action === "remove") return "Threat exception removal staged";
  if (action === "disable") return "Threat exception disabled";
  if (action === "enable") return "Threat exception enabled";
  return "Threat exception edit staged";
}

function mutationActionLabel(action) {
  if (action === "remove") return "remove";
  if (action === "disable") return "disable";
  if (action === "enable") return "enable";
  return "update";
}

function mutationToastDetail(action, name) {
  if (action === "remove") return `${name} removal is pending commit review.`;
  if (action === "disable") return `${name} disable is pending commit review.`;
  if (action === "enable") return `${name} enable is pending commit review.`;
  return `${name} edit is pending commit review.`;
}

export function threatPackageSummary(posture = null) {
  const surface = (posture?.surfaces || []).find((item) => item.kind === "threat-id") || null;
  if (!surface) {
    return {
      available: false,
      label: "unknown",
      status: "unknown",
      cls: "warn",
      version: "",
      packageState: "unknown",
      blockerCount: 0,
      detail: "Threat-ID package posture is unavailable.",
    };
  }
  const check = (surface.decision?.checks || []).find((item) => item.key === "production-evidence") || {};
  const blockers = uniqueThreatPackageBlockers([
    ...(Array.isArray(surface.blockers) ? surface.blockers : []),
    ...(Array.isArray(surface.decision?.blockers) ? surface.decision.blockers : []),
    ...(Array.isArray(surface.content?.blockers) ? surface.content.blockers : []),
  ]);
  const status = check.status || surface.signatureStatus || surface.badge || "unknown";
  return {
    available: true,
    kind: surface.kind || "threat-id",
    label: surface.version ? `${surface.version} / ${status}` : status,
    status,
    cls: check.cls || surface.cls || "warn",
    version: surface.version || "",
    packageState: surface.badge || "unknown",
    blockerCount: blockers.length,
    contentEvidence: Array.isArray(surface.contentEvidence) ? surface.contentEvidence : [],
    keyContentEvidence: surface.keyContentEvidence || {},
    detail: surface.content?.productionReady
      ? "Production Threat-ID evidence is attached to the signed package."
      : "Threat severity and exception decisions use the normalized package posture reported by Intel.",
  };
}

function threatPackageEvidenceBlock(summary) {
  const refs = Array.isArray(summary?.contentEvidence) ? summary.contentEvidence : [];
  if (!refs.length) return null;
  return h("div", { class: "profile-strip" },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Threat-ID package evidence"),
      pill(summary.status || "package", summary.cls || "info")),
    h("div", { class: "note" }, "Package-level evidence attached to the installed Threat-ID catalog."),
    h("dl", { class: "kv compact" },
      refs.map((ref) => kv(contentEvidenceTypeLabel(ref.type), contentEvidenceRefLabel(ref)))));
}

function threatAlertRegressionBridge(alert = {}, posture = null) {
  const packageSummary = threatPackageSummary(posture);
  const surface = threatPackageSurface(posture);
  const keyRefs = surface?.keyContentEvidence || surface?.keyContentReadinessEvidence || packageSummary.keyContentEvidence || packageSummary.keyContentReadinessEvidence || {};
  const canary = surface ? contentCanaryTelemetryWorkbench(surface) : null;
  const pcapSha256 = String(alert.pcapSha256 || alert.pcap_sha256 || "").trim().toLowerCase();
  const regressionRef = compactThreatEvidence(alert.regressionRef || alert.regression_ref || "", 160);
  const rows = [
    bridgeRow("Alert PCAP", pcapSha256 ? shortHash(pcapSha256) : "not attached", pcapSha256 ? "ok" : "warn"),
    bridgeRow("Alert regression", regressionRef || "not attached", regressionRef ? "ok" : "warn"),
    bridgeRow("Package PCAP corpus", evidenceRefSummary(keyRefs.pcapRegressionCorpus) || "not attached", keyRefs.pcapRegressionCorpus ? "ok" : "warn"),
    bridgeRow("Package FP corpus", evidenceRefSummary(keyRefs.falsePositiveRegression) || "not attached", keyRefs.falsePositiveRegression ? "ok" : "warn"),
    bridgeRow("Canary FP signals", canary ? `${canary.metrics.falsePositiveSignals} signals / ${canary.metrics.canaryScopes} scopes` : "not reported", canary?.cls || "warn"),
  ];
  return h("div", { class: "profile-strip threat-regression-bridge", dataset: { threatRegressionBridge: "alert" } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Regression and content context"),
      pill(packageSummary.status || "unknown", packageSummary.cls || "warn")),
    h("div", { class: "note" }, "Read-only links into PCAP audit, package quality, and canary telemetry. Staging a false-positive exception remains a candidate workflow."),
    h("dl", { class: "kv compact" }, rows.map((row) => kv(row.label, row.value))),
    h("div", { class: "flex wrap" },
      pcapSha256 ? h("a", { class: "btn sm", href: captureAuditHash({ sha256: pcapSha256 }), title: "Open packet-capture audit context", "aria-label": "Open packet-capture audit context", dataset: { threatRegressionAction: "pcap-audit" }, onclick: closeDrawer }, h("span", { html: icon("clock", 14) }), "PCAP audit") : null,
      h("a", { class: "btn sm", href: "#/intel?surface=threat-id&drawer=quality", title: "Open Threat-ID content quality evidence", "aria-label": "Open Threat-ID content quality evidence", dataset: { threatRegressionAction: "content-quality" }, onclick: closeDrawer }, h("span", { html: icon("intel", 14) }), "Content quality"),
      h("a", { class: "btn sm", href: "#/intel?surface=threat-id&drawer=canary", title: "Open Threat-ID canary telemetry", "aria-label": "Open Threat-ID canary telemetry", dataset: { threatRegressionAction: "canary" }, onclick: closeDrawer }, h("span", { html: icon("intel", 14) }), "Canary")));
}

export function threatAlertOperatorWorkflow(alert = {}, posture = null) {
  const pcapSha256 = String(alert.pcapSha256 || alert.pcap_sha256 || "").trim().toLowerCase();
  const regressionRef = compactThreatEvidence(alert.regressionRef || alert.regression_ref || "", 160);
  return {
    custodyBoundary: "browser-local handoff only; no capture execution, false-positive approval, corpus custody, or server-side case record is created here",
    caseAction: "threat-capture-regression",
    captureRoute: investigationHashFromFlow(alert, { kind: "alert", intent: "capture" }),
    captureAuditRoute: pcapSha256 ? captureAuditHash({ sha256: pcapSha256 }) : captureAuditHash(alert),
    contentQualityRoute: "#/intel?surface=threat-id&drawer=quality",
    canaryRoute: "#/intel?surface=threat-id&drawer=canary",
    exceptionRoute: threatExceptionReviewRoute(alert),
    candidateRoute: "#/changes?tab=candidate",
    pcapSha256,
    regressionRef,
    packageSummary: threatPackageSummary(posture),
    candidateBoundary: "False-positive exceptions and drop rules still stage only through candidate workflows and require commit review.",
  };
}

export function threatCaseFocusRoute(packet = {}, action = "threat-capture-regression") {
  const key = caseItemKey(packet);
  const q = new URLSearchParams();
  q.set("caseKey", key);
  q.set("caseAction", action);
  q.set("caseKind", packet.kind || "alert");
  return "#/investigation?" + q.toString();
}

export function threatWorkflowPacket(packet = {}, workflow = {}) {
  const caseFocusRoute = threatCaseFocusRoute(packet, workflow.caseAction || "threat-capture-regression");
  return {
    ...packet,
    summary: {
      ...(packet.summary || {}),
      operatorWorkflow: {
        captureRoute: workflow.captureRoute || "",
        captureAuditRoute: workflow.captureAuditRoute || "",
        contentQualityRoute: workflow.contentQualityRoute || "",
        canaryRoute: workflow.canaryRoute || "",
        exceptionRoute: workflow.exceptionRoute || "",
        candidateRoute: workflow.candidateRoute || "",
        caseFocusRoute,
        custodyBoundary: workflow.custodyBoundary || "",
      },
    },
    evidence: [
      ...((packet.evidence || []).filter(Boolean)),
      workflow.captureRoute ? `capture_route=${workflow.captureRoute}` : "",
      workflow.captureAuditRoute ? `capture_audit_route=${workflow.captureAuditRoute}` : "",
      workflow.contentQualityRoute ? `content_quality_route=${workflow.contentQualityRoute}` : "",
      workflow.canaryRoute ? `canary_route=${workflow.canaryRoute}` : "",
      workflow.exceptionRoute ? `exception_review_route=${workflow.exceptionRoute}` : "",
      `case_focus_route=${caseFocusRoute}`,
      "workflow_boundary=browser-local handoff; explicit Troubleshoot capture and candidate review remain required",
    ].filter(Boolean),
    artifacts: {
      ...(packet.artifacts || {}),
      operatorWorkflow: {
        ...workflow,
        caseFocusRoute,
      },
    },
  };
}

function threatExceptionReviewRoute(alert = {}) {
  const q = new URLSearchParams();
  q.set("view", "exceptions");
  if (signatureID(alert)) q.set("signatureId", String(signatureID(alert)));
  if (alert.flowId) q.set("flowId", alert.flowId);
  if (alert.srcIp || alert.destIp) q.set("ip", alert.srcIp || alert.destIp);
  if (alert.protocol) q.set("protocol", threatRouteProtocol(alert.protocol));
  if (alert.destPort) q.set("port", String(alert.destPort));
  q.set("limit", "100");
  return "#/threats?" + q.toString();
}

function threatRouteProtocol(value = "") {
  const proto = String(value || "").trim().toUpperCase().replace(/^PROTOCOL_/, "");
  return ["TCP", "UDP", "ICMP"].includes(proto) ? proto : "";
}

function threatExceptionBridgePanel(model = {}, posture = null) {
  const bridge = model.bridge || threatExceptionRegressionBridge(model, posture);
  return h("div", { class: "profile-strip threat-regression-bridge", dataset: { threatRegressionBridge: "exception" } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Regression and content handoff"),
      pill(bridge.canaryStatus === "bad" ? "review" : bridge.hasExceptionEvidence ? "linked" : "needs evidence", bridge.canaryStatus === "bad" ? "bad" : bridge.hasExceptionEvidence ? "ok" : "warn")),
    h("div", { class: "note" }, bridge.boundary),
    h("dl", { class: "kv compact" },
      kv("Exception PCAP", bridge.pcapSha256 ? shortHash(bridge.pcapSha256) : "—"),
      kv("Exception regression", bridge.regressionRef || "—"),
      kv("Package PCAP corpus", bridge.pcapCorpus || "—"),
      kv("Package FP corpus", bridge.falsePositiveCorpus || "—"),
      kv("Canary context", `${bridge.canarySignals} FP signals / ${bridge.canaryScopes} scopes`)),
    h("div", { class: "flex wrap" },
      bridge.routes.pcapAudit ? h("a", { class: "btn sm", href: bridge.routes.pcapAudit, title: "Open packet-capture audit context for this threat bridge", "aria-label": "Open packet-capture audit context for this threat bridge", dataset: { threatBridgeAction: "pcap-audit" }, onclick: closeDrawer }, h("span", { html: icon("clock", 14) }), "PCAP audit") : null,
      h("a", { class: "btn sm", href: bridge.routes.contentQuality, title: "Open Threat-ID content quality context for this bridge", "aria-label": "Open Threat-ID content quality context for this bridge", dataset: { threatBridgeAction: "content-quality" }, onclick: closeDrawer }, h("span", { html: icon("intel", 14) }), "Content quality"),
      h("a", { class: "btn sm", href: bridge.routes.canary, title: "Open Threat-ID canary telemetry for this bridge", "aria-label": "Open Threat-ID canary telemetry for this bridge", dataset: { threatBridgeAction: "canary" }, onclick: closeDrawer }, h("span", { html: icon("intel", 14) }), "Canary"),
	      h("a", { class: "btn sm", href: bridge.routes.candidate, title: "Open candidate change review", "aria-label": "Open candidate change review", dataset: { threatBridgeAction: "open-candidate" }, onclick: closeDrawer }, h("span", { html: icon("changes", 14) }), "Candidate")));
}

function threatPackageSurface(posture = null) {
  return (posture?.surfaces || []).find((item) => item.kind === "threat-id") || null;
}

function evidenceRefSummary(ref = null) {
  if (!ref) return "";
  return joinParts(ref.artifact || "", ref.sha256Short ? `sha256:${ref.sha256Short}` : "", ref.generatedAt || "");
}

function bridgeRow(label, value, cls = "info") {
  return { label, value, cls };
}

function contentEvidenceTypeLabel(type = "") {
  if (type === "pcap-regression-corpus") return "PCAP regression";
  if (type === "false-positive-regression") return "False-positive regression";
  return String(type || "Evidence").replace(/[-_]+/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());
}

function contentEvidenceRefLabel(ref = {}) {
  const parts = [];
  if (ref.artifact) parts.push(ref.artifact);
  if (ref.sha256Short || ref.sha256) parts.push(`sha256:${ref.sha256Short || String(ref.sha256).slice(0, 12)}`);
  if (ref.generatedAt) parts.push(fmt.absTime(ref.generatedAt));
  return parts.join(" · ") || "attached";
}

export function threatPackageProvenanceFromAlert(alert = {}) {
  const evidence = Array.isArray(alert.threatEvidence || alert.threat_evidence) ? (alert.threatEvidence || alert.threat_evidence) : [];
  for (const entry of evidence) {
    const text = compactThreatEvidence(entry, 160);
    const match = /^signed Threat-ID package(?:\s+([^@\s]+))?(?:@([a-fA-F0-9]{8,64}))?$/i.exec(text);
    if (!match) continue;
    const version = match[1] || "";
    const manifestSha256 = match[2] || "";
    const manifestShort = shortHash(manifestSha256);
    return {
      version,
      manifestSha256,
      manifestShort,
      label: joinParts(version ? `package ${version}` : "signed package", manifestShort ? `manifest ${manifestShort}` : ""),
    };
  }
  return { version: "", manifestSha256: "", manifestShort: "", label: "" };
}

function compactThreatEvidence(value, maxLen) {
  const compact = String(value || "").trim().replace(/\s+/g, " ");
  if (/[/\\]|[?&](?:token|secret|password|key)=/i.test(compact)) return "";
  return maxLen > 0 ? compact.slice(0, maxLen).trim() : compact;
}

function uniqueThreatPackageBlockers(values = []) {
  const seen = new Set();
  const out = [];
  for (const value of values) {
    const text = String(value || "").trim();
    if (!text || seen.has(text)) continue;
    seen.add(text);
    out.push(text);
  }
  return out;
}

function kv(k, v) { return [h("dt", {}, k), h("dd", { class: "mono" }, v)]; }

function explainThreat(a) {
  openTroubleshootInvestigation(a, { kind: "alert", intent: "explain" });
}

function captureThreat(a) {
  openTroubleshootInvestigation(a, { kind: "alert", intent: "capture" });
}

function handoffActions(packet) {
  return h("div", { class: "flex wrap", style: { marginTop: "16px" } },
    h("button", { class: "btn", type: "button", title: "Pin threat alert handoff to investigation case", "aria-label": "Pin threat alert handoff to investigation case", dataset: { threatHandoffAction: "pin-case" }, onclick: () => pinHandoff(packet) }, h("span", { html: icon("inbox", 16) }), "Pin to case"),
    h("button", { class: "btn", type: "button", title: "Copy threat alert handoff", "aria-label": "Copy threat alert handoff", dataset: { threatHandoffAction: "copy-handoff" }, onclick: () => copyHandoff(packet) }, h("span", { html: icon("copy", 16) }), "Copy handoff"),
    h("button", { class: "btn", type: "button", title: "Export threat alert handoff JSON", "aria-label": "Export threat alert handoff JSON", dataset: { threatHandoffAction: "export-json" }, onclick: () => exportHandoff(packet) }, h("span", { html: icon("download", 16) }), "Export JSON"));
}

async function pinHandoff(packet) {
  const activeCaseId = activeInvestigationServerCaseId();
  if (activeCaseId) {
    try {
      await api.addInvestigationCaseEvidence(activeCaseId, [caseEvidencePayloadFromPacket(packet)]);
      toast("Evidence appended", `Threat evidence appended to ${activeCaseId}.`, "ok");
      return;
    } catch (e) {
      const result = pinInvestigationPacket(packet);
      toast("Server append unavailable", `${result.toastDetail} Local fallback was used.`, "warn");
      return;
    }
  }
  try {
    const result = pinInvestigationPacket(packet);
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Selected evidence could not be pinned.", "bad");
  }
}

async function copyHandoff(packet) {
  try {
    await navigator.clipboard.writeText(investigationPacketText(packet));
    toast("Handoff copied", "Selected threat evidence copied as plain text.", "ok");
  } catch {
    toast("Copy failed", "Select the evidence and copy it manually.", "warn");
  }
}

function exportHandoff(packet) {
  const text = investigationPacketJson(packet);
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: investigationPacketFilename(packet) });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  toast("Handoff exported", "Downloaded selected threat evidence as JSON.", "ok");
}

function currentRoute() {
  return location.hash || "#/threats";
}

// Pivot: ensure an address object for the source IP exists in the draft,
// then open the rule editor prefilled with a drop rule, inserted at the
// top so the drop is evaluated first.
async function blockSource(a) {
  if (!a.srcIp) { toast("No source IP", "This alert has no source address.", "warn"); return; }
  try {
    await session.load();
    const plan = threatDropRulePlan(session.draft, a);
    closeDrawer();
    openRuleEditorPrefilled(plan.rule, 0, {
      beforeSave: plan.beforeSave,
      caseContext: state.caseKey ? {
        caseKey: state.caseKey,
        caseAction: state.caseAction,
        caseKind: state.caseKind,
        sourceWorkspace: "threats",
        mode: "drop-source",
        source: {
          flowId: a.flowId || "",
          srcIp: a.srcIp || "",
          srcPort: a.srcPort || "",
          destIp: a.destIp || "",
          destPort: a.destPort || "",
          protocol: a.protocol || "",
          signatureId: signatureID(a) || "",
          threatId: a.threatId || "",
        },
      } : null,
    });
  } catch (e) { toast("Failed", e.message, "bad"); }
}

export function threatDropRulePlan(policy = {}, a = {}) {
  const cidr = a.srcIp?.includes(":") ? a.srcIp + "/128" : a.srcIp + "/32";
  const existing = (policy.addresses || []).find((x) => x.cidr === cidr);
  const name = existing ? existing.name : uniqueName(policy.addresses || [], "threat-" + String(a.srcIp || "").replace(/[.:]/g, "-"));
  const address = existing ? null : { name, cidr, description: "Auto-added from threat alert" };
  return {
    rule: {
      name: "drop-" + String(a.srcIp || "").replace(/[.:]/g, "-"),
      fromZones: [], toZones: [], sourceAddresses: [name], destinationAddresses: [], services: [],
      action: "ACTION_DENY", log: true, disabled: false,
      description: ("Drop source from threat event: " + threatName(a)).trim(),
    },
    dependency: address,
    beforeSave: (draft) => {
      if (!address?.name || !address.cidr) return;
      if ((draft.addresses || []).some((x) => x.cidr === address.cidr || x.name === address.name)) return;
      (draft.addresses ||= []).push({ ...address });
    },
  };
}

async function suppressThreat(a) {
  const sid = signatureID(a);
  if (!sid) { toast("No signature ID", "This alert cannot be suppressed without a signature ID.", "warn"); return; }
  try {
    await session.load();
  } catch (e) {
    toast("Could not load candidate", e.message, "bad");
    return;
  }
  const src = a.srcIp ? `Source ${fmt.endpoint(a.srcIp, a.srcPort)}` : "Source unavailable";
  const dst = a.destIp ? `Destination ${fmt.endpoint(a.destIp, a.destPort)}` : "Destination unavailable";
  const scope = h("select", { class: "input", dataset: { threatFpScope: "true" } },
    h("option", { value: "source", disabled: !a.srcIp }, src),
    h("option", { value: "destination", disabled: !a.destIp }, dst),
    h("option", { value: "global" }, "Global signature suppression"));
  if (!a.srcIp && a.destIp) scope.value = "destination";
  if (!a.srcIp && !a.destIp) scope.value = "global";
  const name = h("input", { class: "input", value: baseExceptionName(a, scope.value), maxlength: 64 });
  const reason = h("textarea", { class: "input", rows: 3, placeholder: "Required: why this alert is safe to suppress", dataset: { threatFpReason: "true" } });
  const owner = h("input", { class: "input", maxlength: 80, placeholder: "secops-oncall" });
  const ticketId = h("input", { class: "input", maxlength: 80, placeholder: "INC-2026-001" });
  const reviewDate = h("input", { class: "input", type: "date" });
  const expiresAt = h("input", { class: "input", type: "date" });
  const pcapSha256 = h("input", { class: "input mono", maxlength: 64, placeholder: "64-character PCAP SHA-256" });
  const regressionRef = h("input", { class: "input", maxlength: 160, placeholder: "evidence/fp-regression.json" });
  const globalConfirm = h("input", { type: "checkbox" });
  const globalConfirmRow = h("label", { class: "field" },
    h("span", {}, "Global acknowledgement"),
    h("label", { class: "flex", style: { gap: "8px", alignItems: "center" } },
      globalConfirm, h("span", { class: "note" }, "I understand this suppresses the signature everywhere after commit.")));
  const previewWrap = h("div", {});
  const stageBtn = h("button", { class: "btn primary", type: "button", title: "Stage false-positive exception", "aria-label": "Stage false-positive exception", dataset: { threatFpStage: "true" } },
    h("span", { html: icon("check", 16) }), stageButtonLabel(scope.value));
  const refreshPreview = () => {
    const metadata = threatExceptionMetadataFormValues({ owner, ticketId, reviewDate, expiresAt, pcapSha256, regressionRef });
    const preview = threatExceptionDraftPreview(session.draft, a, scope.value, name.value, reason.value, metadata);
    const requiresGlobalAck = scope.value === "global" && !globalConfirm.checked;
    const shown = preview.ok && requiresGlobalAck ? { ok: false, error: "global acknowledgement is required" } : preview;
    previewWrap.replaceChildren(exceptionPreview(shown));
    stageBtn.disabled = !shown.ok;
    stageBtn.title = shown.ok ? stageButtonLabel(scope.value) : shown.error || "Complete required fields before staging false-positive exception.";
    stageBtn.setAttribute("aria-label", stageBtn.title);
    stageBtn.replaceChildren(h("span", { html: icon("check", 16) }), stageButtonLabel(scope.value));
    globalConfirmRow.hidden = scope.value !== "global";
  };
  scope.onchange = () => { name.value = baseExceptionName(a, scope.value); refreshPreview(); };
  name.addEventListener("input", refreshPreview);
  reason.addEventListener("input", refreshPreview);
  [owner, ticketId, reviewDate, expiresAt, pcapSha256, regressionRef].forEach((el) => el.addEventListener("input", refreshPreview));
  [reviewDate, expiresAt].forEach((el) => el.addEventListener("change", refreshPreview));
  globalConfirm.addEventListener("change", refreshPreview);
  refreshPreview();
  stageBtn.onclick = () => stageException(a, scope.value, name.value, reason.value, globalConfirm.checked, threatExceptionMetadataFormValues({ owner, ticketId, reviewDate, expiresAt, pcapSha256, regressionRef }));
  openDrawer({
    title: "Stage false-positive exception",
    subtitle: threatName(a),
    width: "620px",
    body: h("div", { dataset: { threatFpDrawer: "true" } },
      h("div", { class: "alert-box warn" }, h("strong", {}, "Candidate-only. "),
        "This stages a Phragma IDS exception. Commit review is still required before IDS/IPS engine receives the suppression."),
      h("dl", { class: "kv" },
        kv("Signature ID", String(sid)),
        kv("Threat-ID", a.threatId || "—"),
        kv("Severity", threatSeverity(a).label)),
      h("label", { class: "field" }, h("span", {}, "Scope"), scope),
      h("label", { class: "field" }, h("span", {}, "Exception name"), name),
      h("label", { class: "field" }, h("span", {}, "Reason"), reason),
      h("div", { class: "two-col" },
        h("label", { class: "field" }, h("span", {}, "Owner"), owner),
        h("label", { class: "field" }, h("span", {}, "Ticket / change ID"), ticketId)),
      h("div", { class: "two-col" },
        h("label", { class: "field" }, h("span", {}, "Review date"), reviewDate),
        h("label", { class: "field" }, h("span", {}, "Expires"), expiresAt)),
      h("label", { class: "field" }, h("span", {}, "PCAP SHA-256"), pcapSha256),
      h("label", { class: "field" }, h("span", {}, "Regression reference"), regressionRef),
      globalConfirmRow,
      previewWrap),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Back to threat detail", "aria-label": "Back to threat detail", dataset: { threatAlertAction: "back-to-detail" }, onclick: () => detail(a) }, "Back"),
      stageBtn,
    ],
  });
}

async function stageException(a, scope, rawName, description, confirmGlobal = false, metadata = {}) {
  const name = cleanName(rawName);
  if (!name) { toast("Name required", "Use a lowercase exception name.", "warn"); return; }
  try {
    const res = await api.stageThreatException(stageThreatExceptionRequest(a, scope, name, description, confirmGlobal, metadata));
    if (res.validation && !res.validation.valid) {
      const msg = (res.validation.errors || []).join("; ") || "Candidate validation rejected this exception.";
      toast("Exception not staged", msg, "bad");
      return;
    }
    await session.load();
    pinThreatCaseRemediation(a, scope, res);
    openThreatExceptionStageResult(a, scope, res);
    toast("Exception staged", `${res.exception?.name || name} is pending commit review.`, "ok");
  } catch (e) { toast("Could not stage exception", e.message, "bad"); }
}

function pinThreatCaseRemediation(a = {}, scope = "", res = {}) {
  if (!state.caseKey) return;
  try {
    pinInvestigationPacket(threatCaseRemediationPacket(a, scope, res));
  } catch (e) {
    toast("Case custody pin failed", e.message || "The exception was staged, but custody evidence could not be pinned.", "warn");
  }
}

function threatCaseRemediationPacket(a = {}, scope = "", res = {}) {
  const ex = res.exception || {};
  const candidate = res.candidateStatus || res.candidate_status || {};
  const changeCount = Number(candidate.changeCount || candidate.change_count || session.serverChangeCount?.() || 0) || 0;
  const dirty = Boolean(candidate.dirty ?? candidate.hasCandidate ?? candidate.has_candidate ?? changeCount > 0);
  return buildInvestigationPacket({
    kind: "candidate-remediation",
    title: "Candidate threat exception staged",
    subject: {
      id: ex.name || state.caseKey,
      label: `Threat exception staged from case`,
      tuple: {
        flowId: a.flowId || "",
        srcIp: a.srcIp || "",
        srcPort: a.srcPort || "",
        destIp: a.destIp || "",
        destPort: a.destPort || "",
        protocol: a.protocol || "",
      },
    },
    summary: {
      caseKey: state.caseKey,
      caseAction: state.caseAction,
      caseKind: state.caseKind,
      exceptionName: ex.name || "",
      signatureId: String(ex.signatureId || ex.signature_id || signatureID(a) || ""),
      threatId: ex.threatId || ex.threat_id || a.threatId || "",
      scope: threatExceptionScope(scope),
      reason: ex.description || "",
      candidateDirty: dirty,
      candidateChangeCount: changeCount,
      changesRoute: "#/changes?tab=candidate",
    },
    evidence: [
      "candidate threat exception staged from investigation case handoff",
      `case key: ${state.caseKey}`,
      ex.name ? `exception: ${ex.name}` : "",
      `signature id: ${String(ex.signatureId || ex.signature_id || signatureID(a) || "")}`,
      `scope: ${scope || "unknown"}`,
      `candidate changes: ${changeCount}`,
      "review in Changes before commit",
    ],
    artifacts: {
      caseContext: {
        caseKey: state.caseKey,
        caseAction: state.caseAction,
        caseKind: state.caseKind,
      },
      alert: a,
      stageResult: res,
      candidateStatus: {
        dirty,
        changeCount,
        changes: Array.isArray(candidate.changes) ? candidate.changes.slice(0, 12) : [],
      },
    },
  }, {
    route: "#/changes?tab=candidate",
  });
}

function openThreatExceptionStageResult(a, scope, res = {}) {
  const model = threatExceptionStageResultModel(res, scope);
  openDrawer({
    title: "False-positive exception staged",
    subtitle: threatName(a),
    width: "720px",
    body: h("div", { dataset: { threatExceptionStageResult: model.name || "" } },
      h("div", { class: "alert-box ok" },
        h("strong", {}, "Candidate only. "),
        "Review the diff and commit before IDS/IPS engine receives this suppression."),
      h("dl", { class: "kv" },
        kv("Exception", model.name || "—"),
        kv("Signature ID", model.signatureId || "—"),
        kv("Threat-ID", model.threatId || "—"),
        kv("Scope", model.scopeLabel),
        kv("Reason", model.reason || "—"),
        kv("Address", model.addressLabel),
        kv("Post-commit artifact", model.artifact),
        kv("Candidate status", model.candidateLabel)),
      model.validationErrors.length ? h("div", { class: "alert-box bad" },
        h("strong", {}, "Validation errors"),
        h("ul", { class: "trace-list" }, model.validationErrors.map((item) => h("li", {}, item)))) : null,
      model.validationWarnings.length ? h("div", { class: "alert-box warn" },
        h("strong", {}, "Validation warnings"),
        h("ul", { class: "trace-list" }, model.validationWarnings.map((item) => h("li", {}, item)))) : null,
      h("details", { class: "diff-details", open: true },
        h("summary", {}, `Diff: ${model.diff.fromLabel} -> ${model.diff.toLabel}`),
        model.diff.changed
          ? renderDiffLines(model.diff.lines)
          : h("div", { class: "alert-box ok" }, "Candidate matches the running policy."))),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close threat exception stage result", "aria-label": "Close threat exception stage result", dataset: { threatExceptionAction: "close-stage-result" }, onclick: closeDrawer }, "Close"),
      h("a", { class: "btn", href: "#/changes?tab=candidate", title: "Open candidate change review", "aria-label": "Open candidate change review", dataset: { threatExceptionAction: "open-candidate" }, onclick: closeDrawer }, h("span", { html: icon("changes", 16) }), "Open candidate"),
      h("a", { class: "btn primary", href: "#/changes?tab=candidate", title: "Review and commit staged threat exception", "aria-label": "Review and commit staged threat exception", dataset: { threatExceptionAction: "review-commit" }, onclick: closeDrawer }, h("span", { html: icon("upload", 16) }), "Review & commit"),
    ],
  });
}

export function threatExceptionStageResultModel(res = {}, requestedScope = "") {
  const ex = res.exception || {};
  const addr = res.address || null;
  const validation = res.validation || {};
  const candidate = res.candidateStatus || res.candidate_status || {};
  const labels = policyDiffLabels(res.diff || {}, "running policy", "candidate");
  const lines = normalizePolicyDiffLines(res.diff?.lines || []);
  const changeCount = Number(candidate.changeCount || candidate.change_count || 0);
  const dirty = Boolean(candidate.dirty ?? candidate.hasCandidate ?? candidate.has_candidate ?? changeCount > 0);
  return {
    name: ex.name || "",
    signatureId: ex.signatureId || ex.signature_id ? String(ex.signatureId || ex.signature_id) : "",
    threatId: ex.threatId || ex.threat_id || "",
    reason: ex.description || "",
    scopeLabel: threatExceptionResultScopeLabel(ex, requestedScope, addr, Boolean(res.addressReused ?? res.address_reused)),
    addressLabel: threatExceptionResultAddressLabel(addr, Boolean(res.addressReused ?? res.address_reused)),
    artifact: "openngfw-threshold.config",
    candidateLabel: dirty ? `${changeCount || 1} pending change${(changeCount || 1) === 1 ? "" : "s"}` : "clean",
    validationErrors: Array.isArray(validation.errors) ? validation.errors : [],
    validationWarnings: Array.isArray(validation.warnings) ? validation.warnings : [],
    diff: { ...labels, lines, changed: lines.length > 0 },
  };
}

function threatExceptionResultScopeLabel(ex = {}, requestedScope = "", address = null, reused = false) {
  if (ex.sourceAddress || ex.source_address || requestedScope === "source") {
    const ref = ex.sourceAddress || ex.source_address || address?.name || "source";
    return `source ${ref}${address?.cidr ? ` (${address.cidr}, ${reused ? "reused" : "new"})` : ""}`;
  }
  if (ex.destinationAddress || ex.destination_address || requestedScope === "destination") {
    const ref = ex.destinationAddress || ex.destination_address || address?.name || "destination";
    return `destination ${ref}${address?.cidr ? ` (${address.cidr}, ${reused ? "reused" : "new"})` : ""}`;
  }
  return "global signature";
}

function threatExceptionResultAddressLabel(address = null, reused = false) {
  if (!address) return "not scoped to an address object";
  return `${address.name || "address"} ${address.cidr || ""} (${reused ? "reused" : "created"})`.trim();
}

export function stageThreatExceptionRequest(a, scope, rawName, description, confirmGlobal = false, metadata = {}) {
  const req = {
    name: cleanName(rawName),
    threatId: a.threatId || "",
    threatName: threatName(a),
    engineSignals: [{ engine: "suricata", kind: "signature_id", value: String(signatureID(a)) }],
    scope: threatExceptionScope(scope),
    reason: String(description || "").trim(),
    confirmGlobal: Boolean(confirmGlobal),
  };
  const meta = normalizeThreatExceptionMetadata(metadata);
  Object.assign(req, meta);
  if (scope === "source" && a.srcIp) req.sourceIp = a.srcIp;
  if (scope === "destination" && a.destIp) req.destinationIp = a.destIp;
  return req;
}

function threatExceptionScope(scope) {
  if (scope === "source") return "THREAT_EXCEPTION_SCOPE_SOURCE";
  if (scope === "destination") return "THREAT_EXCEPTION_SCOPE_DESTINATION";
  if (scope === "global") return "THREAT_EXCEPTION_SCOPE_GLOBAL";
  return "THREAT_EXCEPTION_SCOPE_UNSPECIFIED";
}

function threatExceptionMetadataFormValues({ owner, ticketId, reviewDate, expiresAt, pcapSha256, regressionRef } = {}) {
  return {
    owner: val(owner),
    ticketId: val(ticketId),
    reviewDate: val(reviewDate),
    expiresAt: val(expiresAt),
    pcapSha256: val(pcapSha256),
    regressionRef: val(regressionRef),
  };
}

function normalizeThreatExceptionMetadata(metadata = {}) {
  const out = {
    owner: compactThreatExceptionField(metadata.owner, 80),
    ticketId: compactThreatExceptionField(metadata.ticketId, 80),
    reviewDate: String(metadata.reviewDate || "").trim(),
    expiresAt: String(metadata.expiresAt || "").trim(),
    pcapSha256: String(metadata.pcapSha256 || "").trim().toLowerCase(),
    regressionRef: compactThreatExceptionField(metadata.regressionRef, 160),
  };
  for (const key of Object.keys(out)) {
    if (!out[key]) delete out[key];
  }
  return out;
}

export function stageThreatExceptionDraft(d, a, scope, rawName, description, metadata = {}) {
  const preview = threatExceptionDraftPreview(d, a, scope, rawName, description, metadata);
  if (!preview.ok) throw new Error(preview.error);
  d.ids ||= {};
  d.ids.exceptions ||= [];
  if (preview.address && !preview.address.reused) {
    (d.addresses ||= []).push({ name: preview.address.name, cidr: preview.address.cidr, description: "Auto-added from threat exception" });
  }
  d.ids.exceptions.push(preview.exception);
  return { exception: preview.exception, address: preview.address || null };
}

export function ensureAddress(d, ip, prefix) {
  const plan = addressPlan(d, ip, prefix);
  if (!plan.reused) (d.addresses ||= []).push({ name: plan.name, cidr: plan.cidr, description: "Auto-added from threat exception" });
  return plan.name;
}

export function threatExceptionDraftPreview(d = {}, a = {}, scope = "source", rawName = "", description = "", metadata = {}) {
  const sid = signatureID(a);
  if (!sid) return { ok: false, error: "signature_id is required" };
  const reason = String(description || "").trim();
  if (!reason) return { ok: false, error: "operator reason is required" };
  const baseName = cleanName(rawName);
  if (!baseName) return { ok: false, error: "exception name is required" };

  const ex = {
    name: uniqueName(d.ids?.exceptions || [], baseName),
    signatureId: sid,
    threatId: a.threatId || "",
    description: reason,
    ...normalizeThreatExceptionMetadata(metadata),
  };
  if (ex.reviewDate && !/^\d{4}-\d{2}-\d{2}$/.test(ex.reviewDate)) return { ok: false, error: "review_date must use YYYY-MM-DD" };
  if (ex.expiresAt && !/^\d{4}-\d{2}-\d{2}$/.test(ex.expiresAt)) return { ok: false, error: "expires_at must use YYYY-MM-DD" };
  if (ex.pcapSha256 && !/^[a-f0-9]{64}$/.test(ex.pcapSha256)) return { ok: false, error: "pcap_sha256 must be a 64-character SHA-256" };
  let address = null;
  if (scope === "source") {
    if (!a.srcIp) return { ok: false, error: "selected exception scope is unavailable" };
    address = addressPlan(d, a.srcIp, "threat-src-");
    ex.sourceAddress = address.name;
  } else if (scope === "destination") {
    if (!a.destIp) return { ok: false, error: "selected exception scope is unavailable" };
    address = addressPlan(d, a.destIp, "threat-dst-");
    ex.destinationAddress = address.name;
  } else if (scope !== "global") {
    return { ok: false, error: "selected exception scope is unavailable" };
  }
  const duplicate = matchingException(d, sid, scope, address);
  if (duplicate) return { ok: false, error: `matching exception ${duplicate.name || "(unnamed)"} already exists`, duplicate };
  return { ok: true, exception: ex, address, scope, artifact: "openngfw-threshold.config" };
}

export function addressPlan(d = {}, ip, prefix) {
  const cidr = ip.includes(":") ? ip + "/128" : ip + "/32";
  const existing = (d.addresses || []).find((x) => x.cidr === cidr);
  if (existing) return { name: existing.name, cidr, reused: true };
  return { name: uniqueName(d.addresses || [], cleanName(prefix + ip)), cidr, reused: false };
}

function exceptionPreview(preview) {
  if (!preview.ok) {
    return h("div", { class: "profile-strip" },
      h("div", { class: "profile-strip-head" }, h("strong", {}, "Candidate preview"), pill("incomplete", "warn")),
      h("div", { class: "alert-box warn" }, preview.error || "Complete the required fields."));
  }
  return h("div", { class: "profile-strip" },
    h("div", { class: "profile-strip-head" }, h("strong", {}, "Candidate preview"), pill("staged after click", "violet")),
    h("dl", { class: "kv" },
      kv("Exception", preview.exception.name),
      kv("Signature ID", String(preview.exception.signatureId)),
      kv("Threat-ID", preview.exception.threatId || "—"),
      kv("Scope", exceptionPreviewScope(preview)),
      kv("Reason", preview.exception.description),
      kv("Owner", preview.exception.owner || "—"),
      kv("Ticket", preview.exception.ticketId || "—"),
      kv("Expires", preview.exception.expiresAt || "—"),
      kv("Evidence", joinParts(preview.exception.pcapSha256 ? `pcap ${shortHash(preview.exception.pcapSha256)}` : "", preview.exception.regressionRef) || "—"),
      kv("Post-commit artifact", preview.artifact)),
    preview.scope === "global" ? h("div", { class: "alert-box warn" },
      h("strong", {}, "Global scope. "), "This suppresses the signature everywhere after commit.") : null);
}

function exceptionPreviewScope(preview) {
  if (!preview.address) return "global";
  const state = preview.address.reused ? "reused" : "new";
  if (preview.scope === "source") return `source ${preview.address.name} (${preview.address.cidr}, ${state})`;
  return `destination ${preview.address.name} (${preview.address.cidr}, ${state})`;
}

function stageButtonLabel(scope) {
  if (scope === "source") return "Stage source exception";
  if (scope === "destination") return "Stage destination exception";
  return "Stage global exception";
}

function matchingException(d = {}, sid, scope, address) {
  return (d.ids?.exceptions || []).find((ex) =>
    !ex.disabled && Number(ex.signatureId) === Number(sid) && exceptionScopeMatches(d, ex, scope, address));
}

function exceptionScopeMatches(d, ex, scope, address) {
  if (scope === "global") return !ex.sourceAddress && !ex.destinationAddress;
  if (scope === "source") return Boolean(ex.sourceAddress) && addressCidr(d, ex.sourceAddress) === address?.cidr;
  if (scope === "destination") return Boolean(ex.destinationAddress) && addressCidr(d, ex.destinationAddress) === address?.cidr;
  return false;
}

function addressCidr(d = {}, ref) {
  return (d.addresses || []).find((addr) => addr.name === ref)?.cidr || "";
}

export function signatureID(a) {
  const sid = Number(a.signatureId || 0);
  return Number.isFinite(sid) && sid > 0 ? sid : 0;
}

export function baseExceptionName(a, scope) {
  const sid = signatureID(a) || "signature";
  const suffix = scope === "source" ? a.srcIp : scope === "destination" ? a.destIp : "global";
  return cleanName(`fp-${sid}-${scope}-${suffix || "any"}`);
}

export function cleanName(s) {
  return String(s || "").toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64).replace(/[-_]+$/g, "");
}

export function uniqueName(items, base) {
  const names = new Set((items || []).map((x) => x.name));
  if (!names.has(base)) return base;
  for (let i = 2; i < 1000; i++) {
    const suffix = "-" + i;
    const candidate = base.slice(0, 64 - suffix.length) + suffix;
    if (!names.has(candidate)) return candidate;
  }
  return base.slice(0, 56) + "-" + Date.now().toString(36).slice(-7);
}

function threatName(a) {
  return a.threatName || a.signature || "Unknown threat";
}

function threatSubline(a) {
  const parts = [];
  if (a.threatId) parts.push(a.threatId);
  if (a.threatCategory) parts.push(a.threatCategory);
  if (a.threatConfidence) parts.push(a.threatConfidence + "% confidence");
  const packageProvenance = threatPackageProvenanceFromAlert(a);
  if (packageProvenance.label) parts.push(packageProvenance.label);
  if (a.signatureId) parts.push("SID " + a.signatureId);
  if (a.flowId) parts.push("flow " + a.flowId);
  return parts.join(" · ") || a.category || "—";
}

function telemetryContextLabel(data = {}) {
  const version = Number(data.runningPolicyVersion || 0);
  if (version > 0) return `running policy v${version}`;
  return data.policyContext || "";
}

function eventPolicyLabel(event = {}) {
  const version = Number(event.policyVersion || 0);
  if (event.policyVersionKnown && version > 0) return `v${version}`;
  return "unknown";
}

function eventPolicyPill(event = {}) {
  const known = Boolean(event.policyVersionKnown && Number(event.policyVersion || 0) > 0);
  return pill(eventPolicyLabel(event), known ? "ok" : "warn", true);
}

function joinParts(...parts) {
  return parts.filter(Boolean).join(" · ");
}

function val(el) {
  return el.value.trim();
}

export function threatSeverity(a) {
  const sev = (a.threatSeverity || "").toLowerCase();
  if (sev === "critical") return { label: "Critical", cls: "bad", n: 1 };
  if (sev === "high") return { label: "High", cls: "warn", n: 2 };
  if (sev === "medium") return { label: "Medium", cls: "info", n: 3 };
  if (sev === "low") return { label: "Low", cls: "neutral", n: 4 };
  return fmt.severity(a.severity);
}

function maybeOpenAlert(alerts = []) {
  if (!state.alert) return;
  const alert = alerts.find((item) => alertKey(item) === state.alert);
  if (!alert || state.alert === lastOpenedAlert) return;
  lastOpenedAlert = state.alert;
  setTimeout(() => detail(alert), 0);
}

function clearThreatSelection() {
  state.alert = "";
  syncRoute();
}

function syncRoute() {
  state = normalizeThreatState(state);
  writeQueryState(routePath, state, DEFAULT_STATE, QUERY_KEYS);
}

function cursorStack() {
  return String(state.pageStack || "")
    .split(",")
    .map((item) => normalizePageCursor(item))
    .filter(Boolean);
}

function setPageCursor(nextCursor, stack) {
  state.pageCursor = normalizePageCursor(nextCursor);
  state.pageStack = stack.map((item) => normalizePageCursor(item)).filter(Boolean).slice(-20).join(",");
}

function paginationControls(root, data = {}) {
  const stack = cursorStack();
  const current = normalizePageCursor(state.pageCursor);
  const prev = h("button", {
    class: "btn sm ghost",
    type: "button",
    title: "Previous threat results page",
    "aria-label": "Previous threat results page",
    dataset: { threatPaginationAction: "previous" },
    disabled: stack.length === 0,
    onclick: async () => {
      const previousCursor = stack[stack.length - 1] || "";
      const nextStack = stack.slice(0, -1);
      setPageCursor(previousCursor === "0" ? "" : previousCursor, nextStack);
      clearThreatSelection();
      syncRoute();
      await loadAndPaint(root);
    },
  }, "Prev");
  const next = h("button", {
    class: "btn sm",
    type: "button",
    title: "Next threat results page",
    "aria-label": "Next threat results page",
    dataset: { threatPaginationAction: "next" },
    disabled: !data.hasMore || !data.nextCursor,
    onclick: async () => {
      setPageCursor(data.nextCursor, [...stack, current || "0"]);
      clearThreatSelection();
      syncRoute();
      await loadAndPaint(root);
    },
  }, "Next");
  return h("div", { class: "seg", dataset: { threatPagination: "alerts" } }, prev, next);
}

function pageSummary(count, data = {}, label = "matching detection") {
  const total = Number(data.totalMatches || 0);
  const start = Number(state.pageCursor || 0) + (count ? 1 : 0);
  const end = Number(state.pageCursor || 0) + count;
  const plural = total === 1 ? label : `${label}s`;
  if (total > 0) return `${start}-${end} of ${total} ${plural}`;
  return `${count} ${count === 1 ? label : `${label}s`}`;
}

function alertKey(a = {}) {
  if (a.flowId) return "flow:" + a.flowId;
  const sid = signatureID(a);
  if (!sid) return "";
  return ["sid", sid, a.srcIp || "", a.srcPort || "", a.destIp || "", a.destPort || "", a.time || ""].join(":");
}

export function normalizeThreatState(next = {}) {
  const normalized = { ...DEFAULT_STATE, ...next };
  if (!["", "blocked", "allowed"].includes(normalized.action)) normalized.action = "";
  if (!["", "TCP", "UDP", "ICMP"].includes(normalized.protocol)) normalized.protocol = "";
  if (!["", "critical", "high", "medium", "low", "info"].includes(normalized.threatSeverity)) normalized.threatSeverity = "";
  if (![0, 1, 2, 3, 4].includes(Number(normalized.sev))) normalized.sev = 0;
  else normalized.sev = Number(normalized.sev);
  normalized.signatureId = validPositiveIntText(normalized.signatureId);
  normalized.port = validPortText(normalized.port);
  normalized.flowId = normalizeEventFlowID(normalized.flowId);
  normalized.caseKey = normalizeCaseRouteToken(normalized.caseKey, 320);
  normalized.caseAction = normalizeCaseRouteToken(normalized.caseAction, 80);
  normalized.caseKind = normalizeCaseRouteToken(normalized.caseKind, 80);
  normalized.view = normalized.view === "exceptions" ? "exceptions" : "alerts";
  normalized.exception = cleanName(normalized.exception);
  if (normalized.view !== "exceptions") normalized.exception = "";
  if (!["100", "500", "1000"].includes(normalized.limit)) normalized.limit = "500";
  normalized.pageCursor = normalizePageCursor(normalized.pageCursor);
  normalized.pageStack = String(normalized.pageStack || "").split(",").map((item) => normalizePageCursor(item)).filter(Boolean).slice(-20).join(",");
  return normalized;
}

function normalizePageCursor(value = "") {
  const text = String(value || "").trim();
  if (!text) return "";
  return /^\d{1,10}$/.test(text) ? text : "";
}

function normalizeCaseRouteToken(value = "", limit = 320) {
  const text = String(value || "").trim();
  if (!text || text.length > limit) return "";
  if (/[\u0000-\u001f\u007f]/.test(text)) return "";
  if (/bearer|token|secret|password|\/var\/|\/etc\/|\/tmp\/|file:/i.test(text)) return "";
  return text;
}

function relatedFlowHash(a = {}) {
  const q = new URLSearchParams();
  q.set("mode", "flows");
  q.set("flowId", a.flowId);
  q.set("limit", "100");
  return "#/traffic?" + q.toString();
}

function normalizeEventFlowID(value) {
  const text = String(value || "").trim();
  if (!text || text.length > 128 || /[\u0000-\u001f\u007f]/.test(text)) return "";
  return text;
}

function validPortText(value) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 65535) return "";
  return String(n);
}

function validPositiveIntText(value) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1) return "";
  return String(n);
}
