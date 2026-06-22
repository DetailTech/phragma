// Traffic — recorded inspection flows and live kernel sessions. Flows carry
// Phragma App-ID evidence; sessions come from Linux conntrack current state.

import { h, icon, clear } from "../core.js";
import { api } from "../api.js";
import { cliCommand, openAutomationContext } from "../automation_context.js";
import { session } from "../policy.js";
import { readQueryState, writeQueryState } from "../query_state.js";
import { pageHead, emptyState, pill, toast, openDrawer, closeDrawer, keyboardRowAttrs, labeledCell, responsiveTable } from "../ui.js";
import * as fmt from "../format.js";
import { evidenceToolbar } from "../evidence_toolbar.js";
import { appIdObservationHandoffPacket, appIdRegressionSampleHandoffPacket, buildInvestigationPacket, flowHandoffPacket, investigationPacketFilename, investigationPacketJson, investigationPacketText, sessionHandoffPacket } from "../investigation_packet.js";
import { activeInvestigationServerCaseId, caseEvidencePayloadFromPacket, caseItemKey, pinInvestigationPacket } from "../investigation_case.js";
import { captureEvidencePanel } from "../capture_evidence.js";
import { buildCapturePlan, captureAuditHash } from "../packet_capture.js";
import { currentInspectionPosture, inspectionPostureSummary } from "../inspection_posture.js";
import { investigationHashFromFlow, openTroubleshootInvestigation } from "../investigation_route.js";
import { savedFilterControls } from "../saved_filters.js";
import { buildContentPosture } from "../content_posture.js";
import { openRuleEditorPrefilled, parsePorts } from "./rules.js";
import { openIdsEditor } from "./ids.js";

const DEFAULT_STATE = {
  mode: "flows",
  q: "",
  sort: "bytes",
  observationSort: "severity",
  sessionSort: "bytes",
  ip: "",
  protocol: "",
  app: "",
  port: "",
  sessionState: "",
  observationKind: "",
  engineSignal: "",
  confidenceThreshold: "70",
  flowLimit: "1000",
  since: "",
  until: "",
  limit: "500",
  pageCursor: "",
  pageStack: "",
  flowId: "",
  queueId: "",
  sessionKey: "",
  caseKey: "",
  caseAction: "",
  caseKind: "",
};

const QUERY_KEYS = Object.keys(DEFAULT_STATE);
const SAVED_FILTER_KEYS = QUERY_KEYS.filter((key) => !["pageCursor", "pageStack", "flowId", "queueId", "sessionKey", "caseKey", "caseAction", "caseKind"].includes(key));
let state = { ...DEFAULT_STATE };
let routePath = "/traffic";
let lastOpenedSelection = "";
let runtimeStatus = {};

const FLOW_EVIDENCE_COLUMNS = [
  { key: "flowId", label: "Flow ID" },
  { key: "eventPolicyStamp", label: "Event policy stamp" },
  { key: "eventPolicyFreshness", label: "Event policy freshness" },
  { key: "policyContext", label: "Policy context" },
  { key: "appId", label: "App-ID" },
  { key: "appName", label: "App name" },
  { key: "appConfidence", label: "Confidence" },
  { key: "appIdPackageVersion", label: "Package version" },
  { key: "appIdPackageManifestSha256", label: "Package manifest" },
  { key: "protocol", label: "Protocol" },
  { key: "srcIp", label: "Source IP" },
  { key: "srcPort", label: "Source port" },
  { key: "destIp", label: "Destination IP" },
  { key: "destPort", label: "Destination port" },
  { key: "bytesToServer", label: "Bytes to server" },
  { key: "bytesToClient", label: "Bytes to client" },
  { key: "packets", label: "Packets" },
  { key: "time", label: "Last seen" },
];

const SESSION_EVIDENCE_COLUMNS = [
  { key: "protocol", label: "Protocol" },
  { key: "state", label: "State" },
  { key: "srcIp", label: "Source IP" },
  { key: "srcPort", label: "Source port" },
  { key: "destIp", label: "Destination IP" },
  { key: "destPort", label: "Destination port" },
  { key: "replySrcIp", label: "Reply source IP" },
  { key: "replySrcPort", label: "Reply source port" },
  { key: "replyDestIp", label: "Reply destination IP" },
  { key: "replyDestPort", label: "Reply destination port" },
  { key: "packets", label: "Packets" },
  { key: "bytes", label: "Bytes" },
  { key: "timeoutSeconds", label: "Timeout seconds" },
];

const APPID_EVIDENCE_COLUMNS = [
  { key: "queueId", label: "Queue ID" },
  { key: "kind", label: "Reason" },
  { key: "reviewAction", label: "Recommended action" },
  { key: "evidenceStrength", label: "Evidence strength" },
  { key: "engineSignalSource", label: "Signal source" },
  { key: "engineSignal", label: "Engine signal" },
  { key: "appId", label: "Observed App-ID" },
  { key: "appName", label: "Observed app" },
  { key: "appConfidence", label: "Confidence" },
  { key: "appIdPackageVersion", label: "Package version" },
  { key: "appIdPackageManifestSha256", label: "Package manifest" },
  { key: "suggestedApplication.name", label: "Suggested App-ID" },
  { key: "protocol", label: "Protocol" },
  { key: "destPort", label: "Destination port" },
  { key: "count", label: "Flows" },
  { key: "bytes", label: "Bytes" },
  { key: "packets", label: "Packets" },
  { key: "lastSeen", label: "Last seen" },
];

export async function render(ctx = {}) {
	routePath = ctx.path || "/traffic";
	state = normalizeTrafficState(readQueryState(ctx.query, DEFAULT_STATE, QUERY_KEYS));
	lastOpenedSelection = "";
	const root = h("div", {});
	loadAndPaint(root).catch((err) => paintTrafficLoadError(root, err));
	return root;
}

async function loadAndPaint(root) {
  clear(root);
  root.appendChild(h("div", { class: "loading" }, loadingLabel()));
  const dataPromise = state.mode === "sessions"
    ? api.sessions(sessionRequest())
    : state.mode === "app-id"
      ? appIdQueueData()
      : api.flows(flowRequest());
  const statusPromise = api.status().catch((e) => ({ inspection: { state: "unknown", detail: e.message || String(e) } }));
  const [data, status] = await Promise.all([dataPromise, statusPromise, session.load()]);
  runtimeStatus = status || {};
  if (state.mode === "sessions") paintSessions(root, data, runtimeStatus);
  else if (state.mode === "app-id") paintAppIdQueue(root, data, runtimeStatus);
  else paintFlows(root, data, runtimeStatus);
  maybeOpenSelection(root, data);
}

async function appIdQueueData() {
  const [observations, content] = await Promise.all([
    api.appIdObservations(observationRequest()),
    api.contentPackages().catch((e) => ({ packages: [], error: e.message || String(e) })),
  ]);
  const contentPackages = content.packages || [];
  const packageContext = appIdPackageContextFromResponse(observations);
  return {
    ...observations,
    observations: attachAppIdPackageContext(observations.observations || [], packageContext),
    contentPackages,
    contentError: content.error || "",
    appIdReadiness: appIdReadinessContext(contentPackages, content.error || "", packageContext),
  };
}

function appIdPackageContextFromResponse(resp = {}) {
  return {
    version: resp.appIdPackageVersion || resp.app_id_package_version || "",
    manifestSha256: resp.appIdPackageManifestSha256 || resp.app_id_package_manifest_sha256 || "",
  };
}

function attachAppIdPackageContext(observations = [], context = {}) {
  return observations.map((obs) => ({
    ...obs,
    appIdPackageVersion: obs.appIdPackageVersion || obs.app_id_package_version || context.version || "",
    appIdPackageManifestSha256: obs.appIdPackageManifestSha256 || obs.app_id_package_manifest_sha256 || context.manifestSha256 || "",
  }));
}

function appIdReadinessContext(contentPackages = [], contentError = "", packageContext = {}) {
  const posture = buildContentPosture([], {}, contentPackages, contentError);
  const surface = (posture.surfaces || []).find((item) => item.kind === "app-id") || null;
  const readiness = surface?.contentReadiness || null;
  const readinessBlockers = Array.isArray(readiness?.blockers) ? readiness.blockers : [];
  const productionReady = Boolean(readiness?.productionReady && readiness.evidenceStatus === "passed" && readinessBlockers.length === 0);
  const blockers = uniqueText([
    ...(Array.isArray(surface?.decision?.blockers) ? surface.decision.blockers : []),
    ...readinessBlockers,
    ...(contentError ? ["content package API"] : []),
  ]);
  return {
    explicit: true,
    productionReady,
    status: readiness?.evidenceStatus || (contentError ? "unavailable" : "missing"),
    version: packageContext.version || surface?.version || "",
    manifestSha256: packageContext.manifestSha256 || surface?.manifestSha256 || "",
    packageState: surface?.badge || "unknown",
    blockers,
    detail: contentError || surface?.detail || "App-ID package posture is unavailable.",
  };
}

function loadingLabel() {
	if (state.mode === "sessions") return "Loading sessions…";
	if (state.mode === "app-id") return "Loading App-ID observations…";
	return "Loading flows…";
}

function paintTrafficLoadError(root, err) {
	clear(root);
	root.appendChild(pageHead("Traffic", "Telemetry unavailable",
		h("button", { class: "btn", type: "button", title: "Retry loading traffic telemetry", "aria-label": "Retry loading traffic telemetry", dataset: { trafficAction: "retry-load" }, onclick: () => loadAndPaint(root).catch((e) => paintTrafficLoadError(root, e)) }, h("span", { html: icon("refresh", 16) }), "Retry")));
	root.appendChild(modeBar(root, "Telemetry request failed"));
	root.appendChild(emptyState("traffic", "Traffic data unavailable",
		err?.message || String(err || "The telemetry API did not return traffic data.")));
}

function paintFlows(root, data, status = {}) {
	const flows = data.flows || [];
	clear(root);
	root.appendChild(pageHead("Traffic", `${flows.length} recent flows`,
    h("button", { class: "btn", type: "button", title: "Refresh traffic telemetry", "aria-label": "Refresh traffic telemetry", dataset: { trafficAction: "refresh" }, onclick: () => loadAndPaint(root) }, h("span", { html: icon("refresh", 16) }), "Refresh")));

  root.appendChild(modeBar(root, joinParts(`${flows.length} matching flow${flows.length === 1 ? "" : "s"}`, telemetryContextLabel(data))));
  root.appendChild(inspectionPostureStrip(status));
  root.appendChild(flowFilterBar(root));

  if (!flows.length) {
    const ids = session.draft.ids || {};
    root.appendChild(emptyState("traffic", "No flows yet",
      ids.enabled
        ? "The inspection engine is enabled but hasn't reported flows yet. Generate traffic through the firewall."
        : "Flow records come from the inspection engine (Suricata). Enable IDS/IPS to start seeing flows here.",
	      ids.enabled ? null : h("button", { class: "btn primary", type: "button", title: "Open IDS/IPS candidate editor", "aria-label": "Open IDS/IPS candidate editor", dataset: { trafficAction: "enable-ids" }, onclick: () => openIdsEditor(() => location.reload()) }, h("span", { html: icon("threats", 16) }), "Enable IDS/IPS")));
    return;
  }

  const sortSel = h("select", { style: { maxWidth: "180px" }, onchange: (e) => { state.sort = e.target.value; syncRoute(); repaint(); } },
    option("bytes", "Sort: most bytes"),
    option("time", "Sort: newest"),
    option("packets", "Sort: most packets"));
  sortSel.value = state.sort;
  root.appendChild(h("div", { class: "toolbar" },
    h("div", { class: "note" }, pageSummary(flows.length, data, "matching flow")),
    paginationControls(root, data),
    sortSel));
  root.appendChild(evidenceToolbar({
    surface: "traffic-flows",
    title: "Flow evidence",
    summary: "Filtered flow telemetry with App-ID and policy context.",
    request: flowRequest,
    rows: () => flowRows(flows, data),
    columns: FLOW_EVIDENCE_COLUMNS,
    route: () => location.hash || "#/traffic",
    apiPath: "/v1/flows",
    cliCommand: () => flowCliCommandFromRequest(flowRequest()),
  }));

  const wrap = h("div", { class: "table-wrap" });
  root.appendChild(wrap);
  function repaint() { renderFlowTable(wrap, flows, data); }
  repaint();
}

function paintSessions(root, data, status = {}) {
  const sessions = data.sessions || [];
  clear(root);
  root.appendChild(pageHead("Traffic", `${sessions.length} live sessions`,
    h("button", { class: "btn", type: "button", title: "Refresh live session telemetry", "aria-label": "Refresh live session telemetry", dataset: { trafficAction: "refresh-sessions" }, onclick: () => loadAndPaint(root) }, h("span", { html: icon("refresh", 16) }), "Refresh")));

  root.appendChild(modeBar(root, joinParts(sessionStatusText(data), telemetryContextLabel(data))));
  root.appendChild(inspectionPostureStrip(status));
  root.appendChild(flowFilterBar(root));

  if (data.state && data.state !== "ready") {
    root.appendChild(h("div", { class: "alert-box warn" }, data.detail || "Live conntrack sessions are not available."));
  }

  if (!sessions.length) {
    root.appendChild(emptyState("traffic", data.state === "ready" ? "No live sessions" : "No session data",
      data.state === "ready"
        ? "No entries are currently present in the Linux conntrack table."
        : (data.detail || "The appliance could not read the Linux conntrack table.")));
    return;
  }

  const sortSel = h("select", { style: { maxWidth: "200px" }, onchange: (e) => { state.sessionSort = e.target.value; syncRoute(); repaint(); } },
    option("bytes", "Sort: most bytes"),
    option("packets", "Sort: most packets"),
    option("timeout", "Sort: longest timeout"));
  sortSel.value = state.sessionSort;
  root.appendChild(h("div", { class: "toolbar" },
    h("div", { class: "note" }, pageSummary(sessions.length, data, "matching live session")),
    paginationControls(root, data),
    sortSel));
  root.appendChild(evidenceToolbar({
    surface: "traffic-sessions",
    title: "Live session evidence",
    summary: "Filtered conntrack session view for runtime correlation.",
    request: sessionRequest,
    rows: () => sessionRows(sessions),
    columns: SESSION_EVIDENCE_COLUMNS,
    route: () => location.hash || "#/traffic",
    apiPath: "/v1/sessions",
    cliCommand: () => sessionCliCommandFromRequest(sessionRequest()),
  }));

  const wrap = h("div", { class: "table-wrap" });
  root.appendChild(wrap);
  function repaint() { renderSessionTable(wrap, sessions); }
  repaint();
}

function modeBar(root, detail) {
  return h("div", { class: "toolbar" },
    h("div", { class: "seg" },
      modeButton(root, "flows", "Flows"),
      modeButton(root, "sessions", "Sessions"),
      modeButton(root, "app-id", "App-ID queue")),
    detail ? h("span", { class: "note" }, detail) : null);
}

function inspectionPostureStrip(status = {}) {
  const posture = currentInspectionPosture(status);
  return h("div", { class: "inspection-posture alert-box " + inspectionPostureBoxClass(posture.cls) },
    h("div", { class: "flex wrap", style: { justifyContent: "space-between" } },
      h("div", { class: "flex wrap" },
        h("strong", {}, "Current inspection posture"),
        pill(posture.label, posture.cls, true),
        h("span", { class: "tag" }, posture.engineLabel)),
      h("a", { class: "linklike", href: "#/readiness", title: "Open readiness", "aria-label": "Open readiness", dataset: { trafficAction: "readiness" } }, "Readiness ->")),
    h("div", { class: "note" }, posture.detail),
    h("div", { class: "note" }, "Current runtime posture at handoff time; flow and session rows retain their own event policy context when stamped."));
}

function inspectionPostureBoxClass(cls) {
  if (cls === "bad" || cls === "warn" || cls === "ok" || cls === "info") return cls;
  return "info";
}

function modeButton(root, mode, label) {
  return h("button", { class: state.mode === mode ? "active" : "", type: "button", title: `Show ${label}`, "aria-label": `Show ${label}`, dataset: { trafficMode: mode }, onclick: async () => {
    if (state.mode === mode) return;
    state.mode = mode;
    state.pageCursor = "";
    state.pageStack = "";
    state.flowId = "";
    state.queueId = "";
    state.sessionKey = "";
    if (mode === "app-id" && !["50", "100", "250"].includes(state.limit)) state.limit = "100";
    if (mode !== "app-id" && !["100", "500", "1000"].includes(state.limit)) state.limit = "500";
    syncRoute();
    await loadAndPaint(root);
  } }, label);
}

function sessionStatusText(data) {
  const status = data.state || "unknown";
  return `${status}: ${data.detail || "live Linux conntrack state"}`;
}

function flowRows(flows, context = {}) {
  let r = flows;
  const total = (f) => fmt.num(f.bytesToServer) + fmt.num(f.bytesToClient);
  if (state.sort === "bytes") r = [...r].sort((a, b) => total(b) - total(a));
  else if (state.sort === "packets") r = [...r].sort((a, b) => fmt.num(b.packets) - fmt.num(a.packets));
  else r = [...r].sort((a, b) => (b.time || "").localeCompare(a.time || ""));
  return r.map((flow) => {
    const packageProvenance = appIdPackageProvenanceFromEvidence(flow.appEvidence || flow.app_evidence || []);
    const policyStamp = eventPolicyStamp(flow);
    const policyFreshness = eventPolicyFreshness(flow, context);
    return {
      ...flow,
      flowId: flow.flowId || flow.flow_id || "",
      eventPolicyStamp: policyStamp,
      eventPolicyFreshness: policyFreshness,
      policyContext: context.policyContext || context.policy_context || "",
      appIdPackageVersion: packageProvenance.version,
      appIdPackageManifestSha256: packageProvenance.manifestShort,
    };
  });
}

function sessionRows(sessions) {
  let r = sessions;
  if (state.sessionSort === "packets") r = [...r].sort((a, b) => fmt.num(b.packets) - fmt.num(a.packets));
  else if (state.sessionSort === "timeout") r = [...r].sort((a, b) => fmt.num(b.timeoutSeconds) - fmt.num(a.timeoutSeconds));
  else r = [...r].sort((a, b) => fmt.num(b.bytes) - fmt.num(a.bytes));
  return r;
}

function flowFilterBar(root) {
  const query = h("input", { class: "input", type: "search", value: state.q, placeholder: state.mode === "sessions" ? "IP, protocol, state, raw record" : "IP, app, protocol, evidence" });
  const ip = h("input", { class: "input mono", value: state.ip, placeholder: "10.100.1.2" });
  const protocol = h("select", { class: "input" },
    option("", "Any protocol"),
    option("TCP", "TCP"),
    option("UDP", "UDP"),
    option("ICMP", "ICMP"));
  protocol.value = state.protocol;
  const app = h("input", { class: "input", value: state.app, placeholder: "dns, ssl, web" });
  const port = h("input", { class: "input", type: "number", min: "1", max: "65535", value: state.port, placeholder: "port" });
  const sessionState = h("select", { class: "input" },
    option("", "Any state"),
    option("ESTABLISHED", "ESTABLISHED"),
    option("SYN_SENT", "SYN_SENT"),
    option("SYN_RECV", "SYN_RECV"),
    option("FIN_WAIT", "FIN_WAIT"),
    option("TIME_WAIT", "TIME_WAIT"),
    option("CLOSE", "CLOSE"),
    option("UNREPLIED", "UNREPLIED"));
  sessionState.value = state.sessionState;
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
      app: app.value.trim(),
      port: port.value.trim(),
      sessionState: sessionState.value,
      since: since.value,
      until: until.value,
      limit: limit.value,
      pageCursor: "",
      pageStack: "",
      flowId: "",
      queueId: "",
      sessionKey: "",
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
  [query, ip, app, port, since, until].forEach((el) => el.addEventListener("keydown", submitOnEnter));
  return h("div", { class: "telemetry-filters" },
    h("label", { class: "field" }, h("span", {}, "Search"), query),
    h("label", { class: "field" }, h("span", {}, "IP"), ip),
    h("label", { class: "field" }, h("span", {}, "Protocol"), protocol),
    state.mode === "sessions"
      ? h("label", { class: "field" }, h("span", {}, "State"), sessionState)
      : h("label", { class: "field" }, h("span", {}, "App"), app),
    h("label", { class: "field" }, h("span", {}, "Port"), port),
    state.mode === "sessions" ? null : h("label", { class: "field" }, h("span", {}, "Since"), since),
    state.mode === "sessions" ? null : h("label", { class: "field" }, h("span", {}, "Until"), until),
    h("label", { class: "field" }, h("span", {}, "Limit"), limit),
    h("button", { class: "btn primary", type: "button", title: "Apply traffic filters", "aria-label": "Apply traffic filters", dataset: { trafficAction: "apply-filters" }, onclick: apply }, h("span", { html: icon("filter", 16) }), "Apply filters"),
	    h("button", { class: "btn ghost", type: "button", title: "Reset traffic filters", "aria-label": "Reset traffic filters", dataset: { trafficAction: "reset-filters" }, onclick: async () => {
      state = normalizeTrafficState({ ...state, q: "", ip: "", protocol: "", app: "", port: "", sessionState: "", since: "", until: "", limit: "500", pageCursor: "", pageStack: "", flowId: "", queueId: "", sessionKey: "" });
      syncRoute();
      await loadAndPaint(root);
    } }, "Reset"),
    savedFilterControls({ scope: "traffic", state, defaults: DEFAULT_STATE, keys: SAVED_FILTER_KEYS, onApply: (next) => applySavedTrafficFilter(root, next) }));
}

function appIdObservationFilterBar(root) {
  const query = h("input", { class: "input", type: "search", value: state.q, placeholder: "queue ID, App-ID, signal, evidence" });
  const kind = h("select", { class: "input" },
    option("", "Any reason"),
    option("APP_ID_OBSERVATION_KIND_UNKNOWN", "Unknown"),
    option("APP_ID_OBSERVATION_KIND_LOW_CONFIDENCE", "Low confidence"),
    option("APP_ID_OBSERVATION_KIND_CONFLICTING_EVIDENCE", "Conflicting evidence"));
  kind.value = state.observationKind;
  const signal = h("input", { class: "input mono", value: state.engineSignal, placeholder: "suricata signal" });
  const protocol = h("select", { class: "input" },
    option("", "Any protocol"),
    option("TCP", "TCP"),
    option("UDP", "UDP"),
    option("ICMP", "ICMP"));
  protocol.value = state.protocol;
  const port = h("input", { class: "input", type: "number", min: "1", max: "65535", value: state.port, placeholder: "port" });
  const threshold = h("input", { class: "input", type: "number", min: "1", max: "100", value: state.confidenceThreshold, placeholder: "70" });
  const since = h("input", { class: "input", type: "datetime-local", value: state.since });
  const until = h("input", { class: "input", type: "datetime-local", value: state.until });
  const limit = h("select", { class: "input" }, option("50", "50"), option("100", "100"), option("250", "250"));
  limit.value = ["50", "100", "250"].includes(state.limit) ? state.limit : "100";
  const apply = async () => {
    state = {
      ...state,
      q: query.value.trim(),
      observationKind: kind.value,
      engineSignal: signal.value.trim(),
      protocol: protocol.value,
      port: port.value.trim(),
      confidenceThreshold: threshold.value.trim() || "70",
      since: since.value,
      until: until.value,
      limit: limit.value,
      pageCursor: "",
      pageStack: "",
      flowId: "",
      queueId: "",
      sessionKey: "",
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
  [query, signal, port, threshold, since, until].forEach((el) => el.addEventListener("keydown", submitOnEnter));
  return h("div", { class: "telemetry-filters appid-observation-filters" },
    h("label", { class: "field" }, h("span", {}, "Search"), query),
    h("label", { class: "field" }, h("span", {}, "Reason"), kind),
    h("label", { class: "field" }, h("span", {}, "Signal"), signal),
    h("label", { class: "field" }, h("span", {}, "Protocol"), protocol),
    h("label", { class: "field" }, h("span", {}, "Port"), port),
    h("label", { class: "field" }, h("span", {}, "Threshold"), threshold),
    h("label", { class: "field" }, h("span", {}, "Since"), since),
    h("label", { class: "field" }, h("span", {}, "Until"), until),
    h("label", { class: "field" }, h("span", {}, "Limit"), limit),
    h("button", { class: "btn primary", type: "button", title: "Apply App-ID observation filters", "aria-label": "Apply App-ID observation filters", dataset: { trafficAction: "apply-appid-filters" }, onclick: apply }, h("span", { html: icon("filter", 16) }), "Apply filters"),
	    h("button", { class: "btn ghost", type: "button", title: "Reset App-ID observation filters", "aria-label": "Reset App-ID observation filters", dataset: { trafficAction: "reset-appid-filters" }, onclick: async () => {
      state = normalizeTrafficState({ ...state, q: "", observationKind: "", engineSignal: "", protocol: "", port: "", confidenceThreshold: "70", since: "", until: "", limit: "100", pageCursor: "", pageStack: "", flowId: "", queueId: "", sessionKey: "" });
      syncRoute();
      await loadAndPaint(root);
    } }, "Reset"),
    savedFilterControls({ scope: "traffic", state, defaults: DEFAULT_STATE, keys: SAVED_FILTER_KEYS, onApply: (next) => applySavedTrafficFilter(root, next) }));
}

async function applySavedTrafficFilter(root, next) {
  state = normalizeTrafficState({ ...DEFAULT_STATE, ...next, pageCursor: "", pageStack: "", flowId: "", queueId: "", sessionKey: "" });
  syncRoute();
  await loadAndPaint(root);
}

function flowRequest() {
  return flowRequestFromState(state);
}

function sessionRequest() {
  return sessionRequestFromState(state);
}

function observationRequest() {
  return appIdObservationRequestFromState(state);
}

export function flowRequestFromState(source = {}) {
  const req = { limit: Number(source.limit) || 500 };
  if (source.q) req.query = source.q;
  if (source.ip) req.ip = source.ip;
  if (source.protocol) req.protocol = source.protocol;
  if (source.app) req.app = source.app;
  if (source.port) req.port = source.port;
  if (source.since) req.since = localDateTimeToISOString(source.since);
  if (source.until) req.until = localDateTimeToISOString(source.until);
  if (source.flowId) req.flowId = source.flowId;
  if (source.pageCursor) req.pageCursor = source.pageCursor;
  return req;
}

export function sessionRequestFromState(source = {}) {
  const req = { limit: Number(source.limit) || 500 };
  if (source.q) req.query = source.q;
  if (source.ip) req.ip = source.ip;
  if (source.protocol) req.protocol = source.protocol;
  if (source.port) req.port = source.port;
  if (source.sessionState) req.state = source.sessionState;
  if (source.pageCursor) req.pageCursor = source.pageCursor;
  return req;
}

export function appIdObservationRequestFromState(source = {}) {
  const req = {
    limit: Number(source.limit) || 100,
    flowLimit: Number(source.flowLimit) || 1000,
    confidenceThreshold: Number(source.confidenceThreshold) || 70,
  };
  if (source.q) req.query = source.q;
  if (source.observationKind) req.kind = source.observationKind;
  if (source.engineSignal) req.engineSignal = source.engineSignal;
  if (source.protocol) req.protocol = source.protocol;
  if (source.port) req.port = source.port;
  if (source.since) req.since = localDateTimeToISOString(source.since);
  if (source.until) req.until = localDateTimeToISOString(source.until);
  if (source.pageCursor) req.pageCursor = source.pageCursor;
  return req;
}

export function flowCliCommandFromRequest(req = {}) {
  return cliCommand("ngfwctl flows", [
    ["--limit", req.limit],
    ["--query", req.query],
    ["--ip", req.ip],
    ["--protocol", req.protocol],
    ["--app", req.app],
    ["--port", req.port],
    ["--flow-id", req.flowId],
    ["--since", req.since],
    ["--until", req.until],
  ]);
}

export function sessionCliCommandFromRequest(req = {}) {
  return cliCommand("ngfwctl sessions", [
    ["--limit", req.limit],
    ["--query", req.query],
    ["--ip", req.ip],
    ["--protocol", req.protocol],
    ["--port", req.port],
    ["--state", req.state],
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

function trafficTupleLabel(item = {}) {
  return `${fmt.endpoint(item.srcIp, item.srcPort)} to ${fmt.endpoint(item.destIp, item.destPort)}`;
}

function observationActionLabel(obs = {}) {
  const app = obs.suggestedApplication || {};
  return obs.queueId || app.name || obs.engineSignal || obs.appId || "queued observation";
}

function actionButton({ className = "btn sm ghost", title, ariaLabel, dataset = {}, onclick, iconName, iconSize = 15, label }) {
  return h("button", {
    class: className,
    type: "button",
    title,
    "aria-label": ariaLabel || title,
    dataset: { trafficAction: "action", ...dataset },
    onclick,
  }, h("span", { html: icon(iconName, iconSize) }), label);
}

function drawerButton({ className = "btn", action, title, ariaLabel, dataset = {}, onclick, iconName, iconSize = 16, label }) {
  return h("button", {
    class: className,
    type: "button",
    title,
    "aria-label": ariaLabel || title,
    dataset: { trafficDrawerAction: action || "", ...dataset },
    onclick,
  }, iconName ? h("span", { html: icon(iconName, iconSize) }) : null, label);
}

function drawerLink({ className = "btn", action, title, ariaLabel, dataset = {}, href, onclick, iconName, iconSize = 16, label }) {
  return h("a", {
    class: className,
    href,
    title,
    "aria-label": ariaLabel || title,
    dataset: { trafficDrawerAction: action || "", ...dataset },
    onclick,
  }, iconName ? h("span", { html: icon(iconName, iconSize) }) : null, label);
}

function renderFlowTable(wrap, flows, context = {}) {
  clear(wrap);
  const r = flowRows(flows, context);
  if (!r.length) { wrap.appendChild(emptyState("search", "No matching flows", "Adjust your search.")); return; }
  wrap.appendChild(responsiveTable(["App-ID", "Policy", "Proto", "Source", "Destination", { label: "To server", attrs: { class: "num" } }, { label: "To client", attrs: { class: "num" } }, { label: "Packets", attrs: { class: "num" } }, { label: "", attrs: { class: "actions-col traffic-actions-col" } }],
    r.slice(0, 300).map((f) => {
      const flowLabel = trafficTupleLabel(f);
      const flowDataset = { trafficFlowId: f.flowId || "" };
      return (
      h("tr", { ...keyboardRowAttrs(() => flowDetail(f), { label: `Open flow ${fmt.endpoint(f.srcIp, f.srcPort)} to ${fmt.endpoint(f.destIp, f.destPort)}` }), dataset: flowDataset },
        labeledCell("App-ID", {}, appCell(f)),
        labeledCell("Policy", {}, eventPolicyPill(f, context)),
        labeledCell("Proto", {}, f.protocol || "—"),
        labeledCell("Source", { class: "mono" }, fmt.endpoint(f.srcIp, f.srcPort)),
        labeledCell("Destination", { class: "mono" }, fmt.endpoint(f.destIp, f.destPort)),
        labeledCell("To server", { class: "num" }, fmt.bytes(f.bytesToServer)),
        labeledCell("To client", { class: "num" }, fmt.bytes(f.bytesToClient)),
        labeledCell("Packets", { class: "num" }, fmt.compactNum(fmt.num(f.packets))),
        labeledCell("Actions", { class: "cell-actions" },
          h("div", { class: "row-actions" },
            actionButton({ title: "Open flow detail", ariaLabel: `Open flow detail for ${flowLabel}`, dataset: { ...flowDataset, trafficAction: "view-flow" }, onclick: (e) => { e.stopPropagation(); flowDetail(f); }, iconName: "traffic", label: "Details" }),
            actionButton({ title: "Explain this flow", ariaLabel: `Explain flow ${flowLabel}`, dataset: { ...flowDataset, trafficAction: "explain-flow" }, onclick: (e) => { e.stopPropagation(); explainFlow(f); }, iconName: "search", label: "Explain" }),
            actionButton({ title: "Stage a custom App-ID definition from this flow", ariaLabel: `Stage custom App-ID from flow ${flowLabel}`, dataset: { ...flowDataset, trafficAction: "custom-app-flow" }, onclick: (e) => { e.stopPropagation(); customAppFromFlow(f); }, iconName: "objects", label: "App-ID" }),
            actionButton({ title: "Stage an allow rule from this flow", ariaLabel: `Stage allow rule from flow ${flowLabel}`, dataset: { ...flowDataset, trafficAction: "allow-flow" }, onclick: (e) => { e.stopPropagation(); ruleFromFlow(f, "ACTION_ALLOW"); }, iconName: "check", label: "Allow" }),
            actionButton({ className: "btn sm danger", title: "Stage a drop rule from this flow", ariaLabel: `Stage drop rule from flow ${flowLabel}`, dataset: { ...flowDataset, trafficAction: "drop-flow" }, onclick: (e) => { e.stopPropagation(); ruleFromFlow(f, "ACTION_DENY"); }, iconName: "block", label: "Drop" })))));
    }),
    { className: "traffic-flow-table" }));
}

function renderSessionTable(wrap, sessions) {
  clear(wrap);
  const r = sessionRows(sessions);
  if (!r.length) { wrap.appendChild(emptyState("search", "No matching sessions", "Adjust your filters.")); return; }
  wrap.appendChild(responsiveTable(["Proto", "State", "Original", "Reply", { label: "Packets", attrs: { class: "num" } }, { label: "Bytes", attrs: { class: "num" } }, { label: "Timeout", attrs: { class: "num" } }, "Flags", { label: "", attrs: { class: "actions-col" } }],
    r.slice(0, 300).map((s) => {
      const f = flowFromSession(s);
      const sessionLabel = trafficTupleLabel(s);
      const sessionDataset = { trafficSessionKey: sessionKey(s) || "" };
      return h("tr", keyboardRowAttrs(() => sessionDetail(s), { label: `Open session ${fmt.endpoint(s.srcIp, s.srcPort)} to ${fmt.endpoint(s.destIp, s.destPort)}` }),
        labeledCell("Proto", {}, s.protocol || "—"),
        labeledCell("State", {}, s.state ? pill(s.state, sessionStateClass(s.state)) : "—"),
        labeledCell("Original", { class: "mono" }, fmt.endpoint(s.srcIp, s.srcPort), " → ", fmt.endpoint(s.destIp, s.destPort)),
        labeledCell("Reply", { class: "mono" }, fmt.endpoint(s.replySrcIp, s.replySrcPort), " → ", fmt.endpoint(s.replyDestIp, s.replyDestPort)),
        labeledCell("Packets", { class: "num" }, fmt.compactNum(fmt.num(s.packets))),
        labeledCell("Bytes", { class: "num" }, fmt.bytes(s.bytes)),
        labeledCell("Timeout", { class: "num" }, s.timeoutSeconds ? `${s.timeoutSeconds}s` : "—"),
        labeledCell("Flags", {}, sessionFlags(s).map((flag) => h("span", { class: "tag" }, flag))),
        labeledCell("Actions", { class: "cell-actions" },
          h("div", { class: "row-actions" },
            actionButton({ title: "Explain this session tuple", ariaLabel: `Explain session ${sessionLabel}`, dataset: { ...sessionDataset, trafficAction: "explain-session" }, onclick: (e) => { e.stopPropagation(); explainFlow(f); }, iconName: "search", label: "Explain" }),
            actionButton({ title: "Stage a custom App-ID definition from this session", ariaLabel: `Stage custom App-ID from session ${sessionLabel}`, dataset: { ...sessionDataset, trafficAction: "custom-app-session" }, onclick: (e) => { e.stopPropagation(); customAppFromFlow(f); }, iconName: "objects", label: "App-ID" }),
            actionButton({ title: "Stage an allow rule from this session", ariaLabel: `Stage allow rule from session ${sessionLabel}`, dataset: { ...sessionDataset, trafficAction: "allow-session" }, onclick: (e) => { e.stopPropagation(); ruleFromFlow(f, "ACTION_ALLOW"); }, iconName: "check", label: "Allow" }),
            actionButton({ className: "btn sm danger", title: "Stage a drop rule from this session", ariaLabel: `Stage drop rule from session ${sessionLabel}`, dataset: { ...sessionDataset, trafficAction: "drop-session" }, onclick: (e) => { e.stopPropagation(); ruleFromFlow(f, "ACTION_DENY"); }, iconName: "block", label: "Drop" }))));
    }),
    { className: "traffic-session-table" }));
}

function paintAppIdQueue(root, data, status = {}) {
  const observations = data.observations || [];
  const readiness = data.appIdReadiness || null;
  const clusters = appIdObservationClusters(observations, readiness);
  clear(root);
  root.appendChild(pageHead("Traffic", `${observations.length} App-ID observations`,
    h("button", { class: "btn", type: "button", title: "Refresh App-ID observation queue", "aria-label": "Refresh App-ID observation queue", dataset: { trafficAction: "refresh-appid-observations" }, onclick: () => loadAndPaint(root) }, h("span", { html: icon("refresh", 16) }), "Refresh")));

  root.appendChild(modeBar(root, joinParts(`${observations.length} review item${observations.length === 1 ? "" : "s"}`, `${clusters.length} cluster${clusters.length === 1 ? "" : "s"}`, `threshold ${data.confidenceThreshold || 70}%`, telemetryContextLabel(data))));
  root.appendChild(inspectionPostureStrip(status));
  root.appendChild(appIdObservationFilterBar(root));
  root.appendChild(h("div", { class: "alert-box info" },
    h("strong", {}, "Engine labels are evidence. "),
    "Phragma owns canonical App-ID, confidence, explanations, and staged policy objects."));
  root.appendChild(appIdPackageReadinessStrip(readiness));

  if (!observations.length) {
    root.appendChild(emptyState("traffic", "No App-ID observations",
      "Recent flow telemetry has no unknown, low-confidence, or conflicting application evidence for the selected filters."));
    return;
  }

  const sortSel = h("select", { style: { maxWidth: "220px" }, onchange: (e) => { state.observationSort = e.target.value; syncRoute(); repaint(); } },
    option("severity", "Sort: reason"),
    option("decision", "Sort: recommended action"),
    option("count", "Sort: most flows"),
    option("bytes", "Sort: most bytes"),
    option("time", "Sort: latest"));
  sortSel.value = state.observationSort;
  root.appendChild(h("div", { class: "toolbar" },
    h("div", { class: "note" }, joinParts(pageSummary(observations.length, data, "review item"), `${data.scannedFlows || 0} flows scanned`)),
    paginationControls(root, data),
    sortSel));
  root.appendChild(evidenceToolbar({
    surface: "appid-observations",
    title: "App-ID queue evidence",
    summary: "Filtered App-ID review queue with engine signal and suggested taxonomy.",
    request: observationRequest,
    rows: () => appIdObservationEvidenceRows(observations, readiness),
    columns: APPID_EVIDENCE_COLUMNS,
    route: () => location.hash || "#/traffic",
    apiPath: "/v1/app-id/observations",
  }));
  root.appendChild(appIdQueueDecisionStrip(observations, readiness));
  root.appendChild(appIdClusterReviewPanel(root, clusters, readiness));

  const wrap = h("div", { class: "table-wrap" });
  root.appendChild(wrap);
  function repaint() { renderAppIdObservationTable(root, wrap, observations, readiness); }
  repaint();
}

function observationRows(observations, readiness = null) {
  let r = observations;
  if (state.observationSort === "count") r = [...r].sort((a, b) => fmt.num(b.count) - fmt.num(a.count));
  else if (state.observationSort === "bytes") r = [...r].sort((a, b) => fmt.num(b.bytes) - fmt.num(a.bytes));
  else if (state.observationSort === "time") r = [...r].sort((a, b) => (b.lastSeen || "").localeCompare(a.lastSeen || ""));
  else if (state.observationSort === "decision") r = [...r].sort((a, b) => appIdObservationDecision(b, readiness).priority - appIdObservationDecision(a, readiness).priority || fmt.num(b.count) - fmt.num(a.count));
  else r = [...r].sort((a, b) => observationRank(a.kind) - observationRank(b.kind) || fmt.num(b.count) - fmt.num(a.count));
  return r;
}

function appIdQueueDecisionStrip(observations, readiness = null) {
  const rows = observations.map((obs) => ({ obs, decision: appIdObservationDecision(obs, readiness) }))
    .sort((a, b) => b.decision.priority - a.decision.priority);
  const top = rows[0]?.decision;
  const counts = rows.reduce((acc, row) => {
    acc[row.decision.action] = (acc[row.decision.action] || 0) + 1;
    return acc;
  }, {});
  return h("div", { class: "profile-strip" },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Review workbench"),
      h("span", {}, top ? `Next: ${top.label}` : "No queued action")),
    h("div", { class: "flex wrap" },
      appIdDecisionCount("Define App-ID", counts.define_custom_app),
      appIdDecisionCount("Save & drop", counts.save_drop),
      appIdDecisionCount("Investigate", counts.investigate),
      appIdDecisionCount("Filter evidence", counts.filter_related_evidence)),
    top ? h("div", { class: "note", style: { marginTop: "8px" } }, top.reason) : null);
}

function appIdDecisionCount(label, count = 0) {
  return h("span", { class: "tag" }, `${label}: ${count}`);
}

function appIdClusterReviewPanel(root, clusters = [], readiness = null) {
  if (!clusters.length) return null;
  const top = clusters[0];
  const models = clusters.map((cluster) => appIdClusterEnforcementModel(cluster, readiness, {
    policy: session.draft || {},
    status: runtimeStatus || {},
  }));
  return h("div", { class: "profile-strip", dataset: { appidClusterWorkbench: "true" } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Cluster review"),
      h("span", {}, `${clusters.length} candidate taxonomy/confidence cluster${clusters.length === 1 ? "" : "s"}`)),
    h("div", { class: "note" },
      "Cluster actions use the representative queue observation and the same candidate App-ID/drop review paths as individual observations. Only rows marked direct-stage eligible can stage a drop directly; signal-only or non-port-hint clusters remain review-only and do not imply true L7/proxy allow behavior."),
    h("div", { class: "flex wrap" },
      appIdDecisionCount("Needs conflict review", clusters.filter((cluster) => cluster.conflictState === "conflict").length),
      appIdDecisionCount("Strong evidence", clusters.filter((cluster) => cluster.evidenceStrength === "strong").length),
      appIdDecisionCount("Production corpus ready", models.filter((model) => model.packageReady).length),
      appIdDecisionCount("Port-hint stage ready", models.filter((model) => model.canStageDrop).length),
      appIdDecisionCount("Review-only drop", models.filter((model) => model.canReviewDrop && !model.canStageDrop).length),
      appIdDecisionCount("Blocked", models.filter((model) => model.blockers.length).length),
      appIdDecisionCount("Single observation", clusters.filter((cluster) => cluster.fallbackSingle).length)),
    top ? h("div", { class: "note", style: { marginTop: "8px" } },
      `Next cluster: ${top.label} · ${top.observationCount} observation${top.observationCount === 1 ? "" : "s"} · ${top.evidenceCount} evidence note${top.evidenceCount === 1 ? "" : "s"}`) : null,
    h("div", { class: "cluster-list", style: { marginTop: "12px" } },
      clusters.slice(0, 6).map((cluster) => appIdClusterRow(root, cluster, readiness))),
    clusters.length > 6 ? h("div", { class: "note" }, `${clusters.length - 6} additional cluster${clusters.length - 6 === 1 ? "" : "s"} available in this filtered queue.`) : null);
}

function appIdClusterRow(root, cluster, readiness = null) {
  const packet = appIdObservationClusterHandoffPacket(cluster, {
    route: currentRoute(),
    appIdReadiness: readiness || {},
    policy: session.draft || {},
    status: runtimeStatus || {},
    currentInspectionPosture: inspectionPostureSummary(runtimeStatus),
  });
  const model = appIdClusterEnforcementModel(cluster, readiness, {
    policy: session.draft || {},
    status: runtimeStatus || {},
  });
  return h("div", { class: "profile-strip", dataset: { appidClusterId: cluster.id } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, cluster.label),
      pill(cluster.conflictState === "conflict" ? "conflict" : cluster.confidenceBand, cluster.conflictState === "conflict" ? "bad" : clusterTone(cluster))),
    h("dl", { class: "kv" },
      kv("Representative flow", cluster.representative ? sampleTupleLabel(cluster.representative) : "—"),
      kv("Evidence", `${cluster.observationCount} observations · ${fmt.compactNum(cluster.flowCount)} flows · ${cluster.evidenceCount} notes`),
      kv("Decision", joinParts(model.label, cluster.evidenceStrength, cluster.protocol, cluster.destPort ? "port " + cluster.destPort : "")),
      kv("Path type", model.representativePathType),
      kv("Direct stage", appIdDirectStageEligibilityLabel(model)),
      kv("Production evidence", appIdProductionEvidenceLabel(model)),
      kv("L7 evidence confidence", appIdClusterReadinessRowDetail(model, "l7-evidence-confidence")),
      kv("Drop-rule staging", appIdClusterReadinessRowDetail(model, "reviewed-drop-rule-staging")),
      kv("Enforcement readiness", model.blockers.length ? model.blockers[0] : model.detail)),
    h("div", { class: "row-actions" },
      appIdClusterPrimaryAction(root, cluster, model, readiness),
      actionButton({ title: "Review App-ID observation cluster", ariaLabel: `Review App-ID observation cluster ${cluster.label}`, dataset: { appidClusterAction: "review", appidClusterId: cluster.id }, onclick: () => appIdClusterDetail(root, cluster, readiness), iconName: "search", label: "Review cluster" }),
      actionButton({ title: "Pin cluster-level App-ID regression handoff", ariaLabel: `Pin App-ID cluster handoff ${cluster.label}`, dataset: { appidClusterAction: "pin", appidClusterId: cluster.id }, onclick: () => pinHandoff(packet), iconName: "inbox", label: "Pin" }),
      actionButton({ title: "Copy cluster-level App-ID regression handoff", ariaLabel: `Copy App-ID cluster handoff ${cluster.label}`, dataset: { appidClusterAction: "copy", appidClusterId: cluster.id }, onclick: () => copyHandoff(packet), iconName: "copy", label: "Copy" }),
      actionButton({ title: "Export cluster-level App-ID regression handoff JSON", ariaLabel: `Export App-ID cluster handoff ${cluster.label}`, dataset: { appidClusterAction: "export", appidClusterId: cluster.id }, onclick: () => exportHandoff(packet), iconName: "download", label: "Export" })));
}

function appIdClusterDetail(root, cluster, readiness = null) {
  const packet = appIdObservationClusterHandoffPacket(cluster, {
    route: currentRoute(),
    appIdReadiness: readiness || {},
    policy: session.draft || {},
    status: runtimeStatus || {},
    currentInspectionPosture: inspectionPostureSummary(runtimeStatus),
  });
  const model = appIdClusterEnforcementModel(cluster, readiness, {
    policy: session.draft || {},
    status: runtimeStatus || {},
  });
  openDrawer({
    title: "App-ID observation cluster",
    subtitle: "Representative queue action with cluster evidence and blockers.",
    width: "720px",
    body: h("div", { dataset: { appidClusterDrawer: "true", appidClusterId: cluster.id } },
      h("div", { class: "flex wrap", style: { marginBottom: "16px" } },
        pill(cluster.kindLabel, observationKindClass(cluster.kind)),
        pill(cluster.confidenceBand, clusterTone(cluster)),
        cluster.conflictState === "conflict" ? pill("conflicting evidence", "bad") : null,
        cluster.protocol ? h("span", { class: "tag" }, cluster.protocol) : null,
        cluster.destPort ? h("span", { class: "tag" }, "port " + cluster.destPort) : null),
      h("div", { class: "profile-strip" },
        h("div", { class: "profile-strip-head" },
          h("strong", {}, "Cluster summary"),
          h("span", {}, cluster.label)),
        h("dl", { class: "kv" },
          kv("Cluster ID", cluster.id),
          kv("Candidate taxonomy", cluster.candidateTaxonomy || "—"),
          kv("Decision", joinParts(model.label, cluster.evidenceStrength)),
          kv("Evidence count", `${cluster.evidenceCount} note${cluster.evidenceCount === 1 ? "" : "s"}`),
          kv("Volume", `${fmt.compactNum(cluster.flowCount)} flows · ${fmt.bytes(cluster.bytes)} · ${fmt.compactNum(cluster.packets)} packets`),
          kv("Path type", model.representativePathType),
          kv("Candidate boundary", model.candidateBoundary))),
      h("div", { class: "profile-strip", dataset: { appidClusterEnforcement: model.action } },
        h("div", { class: "profile-strip-head" },
          h("strong", {}, "Cluster enforcement readiness"),
          pill(model.label, model.tone)),
        h("div", { class: "note" }, model.detail),
        h("dl", { class: "kv" },
          kv("Representative action", model.actionLabel),
          kv("Production evidence", appIdProductionEvidenceLabel(model)),
          kv("IDS Prevent fail-closed", model.idsFailClosed ? "ready" : "not confirmed"),
          kv("Confidence", model.confidence ? `${model.confidence}%` : "unavailable"),
          kv("Signal support", model.signalSupport),
          kv("Direct-stage eligibility", appIdDirectStageEligibilityLabel(model)),
          kv("Review boundary", model.reviewBoundary),
          kv("Review-only boundary", appIdClusterReviewOnlyBoundary(model)),
          kv("Candidate boundary", model.candidateBoundary)),
        model.blockers.length ? h("ul", { class: "trace-list" }, model.blockers.map((blocker) => h("li", {}, blocker))) : null),
      h("div", { class: "profile-strip", dataset: { appidClusterDecisionRows: "true" } },
        h("div", { class: "profile-strip-head" },
          h("strong", {}, "Production enforcement decision rows"),
          h("span", {}, "bounded review model")),
        h("dl", { class: "kv" },
          model.productionReadinessRows.map((row) => kv(row.label, `${row.status} · ${row.detail}`)))),
      h("div", { class: "profile-strip" },
        h("div", { class: "profile-strip-head" },
          h("strong", {}, "Corpus custody checklist"),
          h("span", {}, "handoff only")),
        h("ul", { class: "trace-list" }, appIdClusterCorpusCustodyChecklist(cluster, model, {
          appIdReadiness: readiness || {},
        }).map((item) => h("li", {},
          h("strong", {}, item.label),
          " · ",
          item.status,
          item.detail ? " · " + item.detail : "")))),
      h("div", { class: "profile-strip" },
        h("div", { class: "profile-strip-head" },
          h("strong", {}, "Representative flows"),
          h("span", {}, `${cluster.representatives.length} sample${cluster.representatives.length === 1 ? "" : "s"}`)),
        h("ul", { class: "trace-list" }, cluster.representatives.map((obs) => h("li", {},
          h("strong", {}, obs.queueId || obs.sampleFlowId || obs.engineSignal || "observation"),
          " ",
          sampleTupleLabel(obs),
          " · ",
          joinParts(obs.engineSignal ? `${obs.engineSignalSource || "engine"}=${obs.engineSignal}` : "", obs.appConfidence ? `${obs.appConfidence}% confidence` : "", `${fmt.compactNum(obs.count)} flows`))))),
      h("div", { class: "profile-strip" },
        h("div", { class: "profile-strip-head" },
          h("strong", {}, "Review queue members"),
          h("span", {}, `${cluster.observationCount} observation${cluster.observationCount === 1 ? "" : "s"}`)),
        h("ul", { class: "trace-list" }, cluster.observations.slice(0, 12).map((obs) => h("li", {},
          h("button", {
            class: "linklike",
            type: "button",
            title: "Open individual App-ID observation review",
            "aria-label": `Open App-ID observation review ${obs.queueId || obs.sampleFlowId || obs.engineSignal || "observation"}`,
            dataset: { appidClusterAction: "review-observation", appidObservationId: obs.queueId || "" },
            onclick: () => observationDetail(root, obs, readiness),
          }, obs.queueId || obs.sampleFlowId || obs.engineSignal || "observation"),
          " ",
          joinParts(observationKindLabel(obs.kind), sampleTupleLabel(obs), `${fmt.compactNum(obs.count)} flows`)))),
        cluster.observationCount > 12 ? h("div", { class: "note" }, `${cluster.observationCount - 12} additional queue members omitted from the drawer.`) : null),
      handoffActions(packet)),
    footer: [
      drawerButton({ className: "btn ghost", action: "close-appid-cluster", title: "Close App-ID cluster drawer", dataset: { appidClusterAction: "close" }, onclick: closeDrawer, label: "Close" }),
      cluster.representative ? drawerButton({ action: "cluster-matching-flows", title: "Open matching flow filters for the representative observation", dataset: { appidClusterAction: "matching-flows" }, onclick: () => { closeDrawer(); matchingFlows(root, cluster.representative); }, iconName: "traffic", label: "Representative flows" }) : null,
      model.canDefine ? drawerButton({ action: "cluster-define-appid", title: "Promote the representative observation into a candidate App-ID object", dataset: { appidClusterAction: "define", appidClusterId: cluster.id }, onclick: () => { closeDrawer(); promoteObservation(model.representative); }, iconName: "objects", label: "Define representative" }) : null,
      model.canReviewDrop ? drawerButton({ action: "cluster-review-drop", title: model.directStageEligible ? "Review a candidate drop rule for the representative App-ID cluster" : "Review-only candidate drop boundary for this representative App-ID cluster", dataset: { appidClusterAction: "review-drop", appidClusterId: cluster.id }, onclick: () => reviewClusterDrop(model), iconName: "rules", label: model.directStageEligible ? "Review drop" : "Review only" }) : null,
      model.canStageDrop ? drawerButton({ className: "btn danger", action: "cluster-stage-drop", title: "Stage the representative App-ID object and candidate drop rule", dataset: { appidClusterAction: "stage-drop", appidClusterId: cluster.id }, onclick: () => { closeDrawer(); promoteObservation(model.representative, "block"); }, iconName: "block", label: "Stage drop" }) : null,
    ],
  });
}

function appIdClusterPrimaryAction(root, cluster, model, readiness = null) {
  const dataset = { appidClusterId: cluster.id };
  if (model.canStageDrop) {
    return actionButton({ className: "btn sm danger", title: "Stage the representative App-ID object and candidate drop rule", ariaLabel: `Stage representative drop for App-ID cluster ${cluster.label}`, dataset: { ...dataset, appidClusterAction: "stage-drop" }, onclick: (e) => { e.stopPropagation(); promoteObservation(model.representative, "block"); }, iconName: "block", label: "Stage drop" });
  }
  if (model.canReviewDrop) {
    return actionButton({ className: "btn sm", title: model.directStageEligible ? "Review a bounded candidate drop rule for this representative App-ID" : "Review-only candidate drop boundary for this representative App-ID", ariaLabel: `Review representative drop for App-ID cluster ${cluster.label}`, dataset: { ...dataset, appidClusterAction: "review-drop" }, onclick: (e) => { e.stopPropagation(); reviewClusterDrop(model); }, iconName: "rules", label: model.directStageEligible ? "Review drop" : "Review only" });
  }
  if (model.canDefine) {
    return actionButton({ className: "btn sm", title: "Define the representative App-ID through the existing observation promotion flow", ariaLabel: `Define representative App-ID for cluster ${cluster.label}`, dataset: { ...dataset, appidClusterAction: "define" }, onclick: (e) => { e.stopPropagation(); promoteObservation(model.representative); }, iconName: "objects", label: "Define" });
  }
  return actionButton({ className: "btn sm ghost", title: model.blockers[0] || "Review cluster blockers", ariaLabel: `Review blockers for App-ID cluster ${cluster.label}`, dataset: { ...dataset, appidClusterAction: "blocked" }, onclick: (e) => { e.stopPropagation(); appIdClusterDetail(root, cluster, readiness); }, iconName: "search", label: "Blocked" });
}

async function reviewClusterDrop(model = {}) {
  try {
    await session.load();
    const representative = model.representative || {};
    const flow = flowFromObservation(representative);
    const app = normalizeSuggestedApplication(representative.suggestedApplication) || suggestedApplication(flow, session.draft);
    reviewAppDropRule(flow, app);
  } catch (e) {
    toast("Failed", e.message, "bad");
  }
}

function clusterTone(cluster = {}) {
  if (cluster.conflictState === "conflict") return "bad";
  if (cluster.evidenceStrength === "strong") return "ok";
  if (cluster.evidenceStrength === "moderate") return "info";
  return "warn";
}

export function appIdObservationClusters(observations = [], readiness = null) {
  const groups = new Map();
  for (const obs of observations || []) {
    const decision = appIdObservationDecision(obs, readiness);
    const meta = appIdObservationClusterMeta(obs, decision);
    const key = appIdObservationClusterKey(meta);
    if (!groups.has(key)) groups.set(key, { key, meta, observations: [], decisions: [] });
    const group = groups.get(key);
    group.observations.push(obs);
    group.decisions.push(decision);
  }
  return [...groups.values()]
    .map((group) => appIdObservationClusterFromGroup(group))
    .sort((a, b) => b.priority - a.priority || b.flowCount - a.flowCount || a.label.localeCompare(b.label));
}

function appIdObservationClusterMeta(obs = {}, decision = appIdObservationDecision(obs)) {
  const app = obs.suggestedApplication || {};
  const candidateTaxonomy = app.name || obs.appId || obs.engineSignal || "unmapped";
  return {
    candidateTaxonomy,
    candidateDisplayName: app.displayName || obs.appName || app.name || obs.appId || obs.engineSignal || "Unmapped application",
    category: app.category || obs.appCategory || "",
    confidenceBand: appIdConfidenceBand(obs.appConfidence),
    conflictState: String(obs.kind || "").includes("CONFLICTING") ? "conflict" : "non-conflict",
    kind: obs.kind || "",
    kindLabel: observationKindLabel(obs.kind),
    protocol: protocolEnum(obs.protocol).replace(/^PROTOCOL_/, "") || String(obs.protocol || ""),
    destPort: numberOrZero(obs.destPort),
    engineSignal: normalizeSignal(obs.engineSignal),
    decisionAction: decision.action,
    decisionLabel: decision.label,
    evidenceStrength: decision.evidenceStrength,
  };
}

function appIdObservationClusterKey(meta = {}) {
  return [
    stableKeyPart(meta.candidateTaxonomy),
    meta.confidenceBand || "unknown",
    meta.conflictState || "non-conflict",
  ].join("|");
}

function appIdObservationClusterFromGroup(group = {}) {
  const observations = [...(group.observations || [])];
  const representatives = appIdObservationRepresentativeSet(observations, 3);
  const representative = representatives[0] || observations[0] || {};
  const topDecision = [...(group.decisions || [])].sort((a, b) => (b.priority || 0) - (a.priority || 0))[0] || appIdObservationDecision(representative);
  const meta = {
    ...(group.meta || appIdObservationClusterMeta(representative, topDecision)),
    decisionAction: topDecision.action,
    decisionLabel: topDecision.label,
    evidenceStrength: topDecision.evidenceStrength,
  };
  const kindLabels = uniqueText(observations.map((obs) => observationKindLabel(obs.kind)).filter(Boolean));
  const queueIds = uniqueText(observations.map((obs) => obs.queueId).filter(Boolean));
  const sampleFlowIds = uniqueText(observations.map((obs) => obs.sampleFlowId).filter(Boolean));
  const evidenceCount = observations.reduce((sum, obs) => sum + (Array.isArray(obs.appEvidence) ? obs.appEvidence.filter(Boolean).length : 0), 0);
  const flowCount = observations.reduce((sum, obs) => sum + fmt.num(obs.count), 0);
  const bytes = observations.reduce((sum, obs) => sum + fmt.num(obs.bytes), 0);
  const packets = observations.reduce((sum, obs) => sum + fmt.num(obs.packets), 0);
  const firstSeen = observations.map((obs) => obs.firstSeen).filter(Boolean).sort()[0] || "";
  const lastSeen = observations.map((obs) => obs.lastSeen).filter(Boolean).sort().pop() || "";
  return {
    id: "appid-cluster-" + stableHash(group.key || JSON.stringify(meta)),
    key: group.key || "",
    label: joinParts(meta.candidateDisplayName || meta.candidateTaxonomy, meta.confidenceBand, meta.conflictState === "conflict" ? "conflict" : ""),
    candidateTaxonomy: meta.candidateTaxonomy,
    candidateDisplayName: meta.candidateDisplayName,
    category: meta.category,
    confidenceBand: meta.confidenceBand,
    conflictState: meta.conflictState,
    kind: meta.kind,
    kindLabel: kindLabels.length > 1 ? "MIXED REASONS" : (kindLabels[0] || meta.kindLabel),
    protocol: meta.protocol,
    destPort: meta.destPort,
    engineSignal: meta.engineSignal,
    decisionAction: meta.decisionAction,
    decisionLabel: meta.decisionLabel,
    evidenceStrength: meta.evidenceStrength,
    observationCount: observations.length,
    flowCount,
    bytes,
    packets,
    evidenceCount,
    queueIds,
    sampleFlowIds,
    firstSeen,
    lastSeen,
    representative,
    representatives,
    observations,
    fallbackSingle: observations.length === 1,
    priority: appIdClusterPriority(meta, observations, evidenceCount, flowCount),
  };
}

function appIdObservationRepresentativeSet(observations = [], limit = 3) {
  return [...(observations || [])]
    .sort((a, b) => appIdObservationRepresentativeScore(b) - appIdObservationRepresentativeScore(a) || (b.lastSeen || "").localeCompare(a.lastSeen || ""))
    .slice(0, limit);
}

export function appIdObservationRepresentative(observations = []) {
  return appIdObservationRepresentativeSet(observations, 1)[0] || null;
}

function appIdObservationRepresentativeScore(obs = {}) {
  const evidenceCount = Array.isArray(obs.appEvidence) ? obs.appEvidence.filter(Boolean).length : 0;
  const conflictBoost = String(obs.kind || "").includes("CONFLICTING") ? 500000 : 0;
  const sampleBoost = obs.sampleFlowId ? 25000 : 0;
  const queueBoost = obs.queueId ? 5000 : 0;
  return conflictBoost + sampleBoost + queueBoost + (evidenceCount * 10000) + Math.min(fmt.num(obs.count), 1000) + Math.min(Math.floor(fmt.num(obs.bytes) / 1024), 5000);
}

function appIdClusterPriority(meta = {}, observations = [], evidenceCount = 0, flowCount = 0) {
  const conflict = meta.conflictState === "conflict" ? 1000000 : 0;
  const strength = meta.evidenceStrength === "strong" ? 200000 : meta.evidenceStrength === "moderate" ? 100000 : 0;
  return conflict + strength + (observations.length * 1000) + Math.min(flowCount, 10000) + (evidenceCount * 50);
}

function appIdConfidenceBand(value) {
  const confidence = Number(value || 0);
  if (!confidence) return "confidence unknown";
  if (confidence >= 80) return "high confidence";
  if (confidence >= 50) return "medium confidence";
  return "low confidence";
}

export function appIdObservationClusterHandoffPacket(cluster = {}, options = {}) {
  const representative = cluster.representative || appIdObservationRepresentative(cluster.observations || []) || {};
  const enforcement = appIdClusterEnforcementModel(cluster, options.appIdReadiness || null, {
    policy: options.policy || {},
    status: options.status || {},
    inspectionPosture: options.currentInspectionPosture || null,
  });
  const custodyChecklist = appIdClusterCorpusCustodyChecklist(cluster, enforcement, options);
  const packet = buildInvestigationPacket({
    kind: "app-id-observation-cluster",
    title: "App-ID observation cluster handoff",
    route: options.route || currentRoute(),
    subject: {
      id: cluster.id || "",
      label: cluster.label || "App-ID observation cluster",
      candidateTaxonomy: cluster.candidateTaxonomy || "",
      confidenceBand: cluster.confidenceBand || "",
      conflictState: cluster.conflictState || "",
    },
    summary: {
      candidateTaxonomy: cluster.candidateTaxonomy || "",
      candidateDisplayName: cluster.candidateDisplayName || "",
      category: cluster.category || "",
      confidenceBand: cluster.confidenceBand || "",
      conflictState: cluster.conflictState || "",
      decision: cluster.decisionLabel || "",
      evidenceStrength: cluster.evidenceStrength || "",
      observationCount: fmt.num(cluster.observationCount),
      representativeCount: (cluster.representatives || []).length,
      evidenceCount: fmt.num(cluster.evidenceCount),
      flowCount: fmt.num(cluster.flowCount),
      bytes: fmt.num(cluster.bytes),
      packets: fmt.num(cluster.packets),
      firstSeen: cluster.firstSeen || "",
      lastSeen: cluster.lastSeen || "",
      candidateBoundary: "No policy mutation; review, promotion, and drop remain individual queue actions.",
      representativePathType: enforcement.representativePathType,
      directStageEligible: enforcement.directStageEligible,
      directStageEligibility: appIdDirectStageEligibilityLabel(enforcement),
      productionEvidence: appIdProductionEvidenceLabel(enforcement),
      reviewBoundary: enforcement.reviewBoundary,
      reviewOnlyBoundary: appIdClusterReviewOnlyBoundary(enforcement),
      productionReadinessRows: enforcement.productionReadinessRows,
      corpusCustody: {
        boundary: "Handoff packet only; no signed corpus custody, legal retention, capture execution, policy commit, or true L7/proxy allow claim is created here.",
        corpusRoute: "#/intel?surface=app-id&drawer=review",
        checklist: custodyChecklist,
      },
      clusterEnforcement: {
        action: enforcement.action,
        label: enforcement.label,
        canDefine: enforcement.canDefine,
        canReviewDrop: enforcement.canReviewDrop,
        canStageDrop: enforcement.canStageDrop,
        representativePathType: enforcement.representativePathType,
        directStageEligible: enforcement.directStageEligible,
        directStageEligibility: appIdDirectStageEligibilityLabel(enforcement),
        productionEvidence: appIdProductionEvidenceLabel(enforcement),
        reviewBoundary: enforcement.reviewBoundary,
        reviewOnlyBoundary: appIdClusterReviewOnlyBoundary(enforcement),
        productionReadinessRows: enforcement.productionReadinessRows,
        blockers: enforcement.blockers,
        candidateBoundary: enforcement.candidateBoundary,
      },
      appIdReadiness: options.appIdReadiness ? {
        productionReady: Boolean(options.appIdReadiness.productionReady),
        status: noSecretText(options.appIdReadiness.status || ""),
        blockerCount: Array.isArray(options.appIdReadiness.blockers) ? options.appIdReadiness.blockers.length : 0,
      } : undefined,
      currentInspectionPosture: options.currentInspectionPosture || undefined,
    },
    evidence: appIdObservationClusterEvidenceLines(cluster, enforcement),
    artifacts: {
      cluster: appIdObservationClusterArtifact(cluster),
      enforcementPlan: appIdClusterEnforcementArtifact(enforcement),
      representativeObservations: (cluster.representatives || []).map(appIdObservationClusterObservationArtifact),
      regressionHandoff: {
        representativeQueueId: representative.queueId || "",
        representativeFlowId: representative.sampleFlowId || "",
        captureRoute: representative.sampleFlowId || representative.sampleSrcIp ? investigationHashFromFlow(flowFromObservation(representative), { intent: "capture" }) : "",
        corpusRoute: "#/intel?surface=app-id&drawer=review",
        corpusCustodyChecklist: custodyChecklist,
        handoffBoundary: "Exported review packet is redacted browser/operator handoff metadata, not signed corpus custody or a true L7/proxy allow.",
        candidateBoundary: "No direct policy mutation from cluster handoff.",
      },
    },
  });
  return trafficWorkflowPacket(packet, trafficCaptureRegressionWorkflow(flowFromObservation(representative), {
    kind: "observation",
    observation: representative,
    readiness: options.appIdReadiness || {},
    caseAction: "app-id-cluster-regression",
  }));
}

function appIdObservationClusterEvidenceLines(cluster = {}, enforcementModel = null) {
  const model = enforcementModel || cluster.enforcementModel || appIdClusterEnforcementModel(cluster);
  const lines = [
    `cluster=${cluster.id || "appid-cluster"}`,
    cluster.candidateTaxonomy ? `candidate_taxonomy=${noSecretText(cluster.candidateTaxonomy)}` : "",
    cluster.confidenceBand ? `confidence_band=${cluster.confidenceBand}` : "",
    cluster.conflictState ? `conflict_state=${cluster.conflictState}` : "",
    cluster.decisionLabel ? `review_decision=${cluster.decisionLabel}` : "",
    `observations=${fmt.num(cluster.observationCount)} flows=${fmt.num(cluster.flowCount)} evidence_notes=${fmt.num(cluster.evidenceCount)}`,
    cluster.representative ? `representative=${noSecretText(cluster.representative.queueId || cluster.representative.sampleFlowId || cluster.representative.engineSignal || "observation")}` : "",
    `cluster_enforcement=${model.action || "blocked"} blockers=${model.blockers.length}`,
    `representative_path_type=${model.representativePathType || "unknown"} direct_stage_eligible=${model.directStageEligible ? "true" : "false"}`,
    `direct_stage_eligibility=${noSecretText(appIdDirectStageEligibilityLabel(model))}`,
    `production_evidence=${noSecretText(appIdProductionEvidenceLabel(model))}`,
    ...appIdClusterProductionReadinessRows(model).map((row) => `readiness_row ${stableKeyPart(row.key)}=${noSecretText(row.status)} detail=${noSecretText(row.detail)}`),
    `review_boundary=${noSecretText(model.reviewBoundary || "")}`,
    `review_only_boundary=${noSecretText(appIdClusterReviewOnlyBoundary(model))}`,
    "corpus_custody=handoff checklist only; no signed custody or legal retention is created by export",
    "policy_mutation=representative queue action only; validation and commit remain separate",
  ];
  for (const obs of (cluster.representatives || []).slice(0, 3)) {
    lines.push(noSecretText(`representative_flow ${obs.queueId || obs.sampleFlowId || "observation"} ${sampleTupleLabel(obs)} ${obs.engineSignal || ""} count=${fmt.num(obs.count)}`));
  }
  return lines.filter(Boolean);
}

export function appIdClusterEnforcementModel(cluster = {}, readinessContext = null, options = {}) {
  const representative = cluster.representative || appIdObservationRepresentative(cluster.observations || []) || {};
  const decision = appIdObservationDecision(representative, readinessContext);
  const app = representative.suggestedApplication || {};
  const confidence = Number(representative.appConfidence || 0);
  const hasQueue = Boolean(representative.queueId);
  const hasConflict = cluster.conflictState === "conflict" || String(representative.kind || "").includes("CONFLICTING");
  const explicitReadiness = appIdReadinessWasExplicit(readinessContext);
  const packageReady = Boolean(explicitReadiness && appIdPackageReadyForEnforcement(readinessContext));
  const packageEvidence = explicitReadiness
    ? packageReady
      ? joinParts("production ready", readinessContext?.version || "", readinessContext?.manifestSha256 ? `manifest ${shortHash(readinessContext.manifestSha256)}` : "")
      : appIdReadinessReason(readinessContext)
    : "production-ready App-ID corpus not explicitly reported; candidate validation still required";
  const portDrop = appIdObservationCanStageDrop(representative);
  const signalDrop = appIdObservationCanReviewSignalDrop(representative);
  const idsFailClosed = appIdIdsPreventFailClosed(options.policy || {}, options.status || {}, options.inspectionPosture || null);
  const representativePathType = portDrop
    ? "tcp-udp-port-hint"
    : signalDrop
      ? "suricata-signal-only-review"
      : usefulObservationSignal(representative)
        ? "custom-signal-needs-port-boundary"
        : "insufficient-enforcement-context";
  const signalSupport = signalDrop
    ? "supported Suricata signal-only drop"
    : usefulObservationSignal(representative)
      ? "custom signal requires TCP/UDP port boundary for enforcement"
      : "no supported signal for App-ID enforcement";
  const blockers = [];
  if (!hasQueue) blockers.push("Representative cluster member is not queue-backed; use individual flow review before candidate staging.");
  if (hasConflict) blockers.push("Conflicting App-ID evidence must be resolved before cluster-level enforcement.");
  if (decision.evidenceStrength === "weak") blockers.push("Cluster representative has weak signal, sample, or port evidence.");
  if (confidence > 0 && confidence < 50) blockers.push("Representative confidence is below 50%; collect more package or replay evidence first.");
  if (!confidence) blockers.push("Representative confidence is unavailable; review package evidence before enforcement.");
  if (!packageReady) blockers.push(packageEvidence);
  if (!portDrop && !signalDrop) blockers.push("Representative lacks a TCP/UDP port boundary or supported Suricata signal for bounded drop review.");
  if (!portDrop && signalDrop && !idsFailClosed) blockers.push("Signal-only App-ID drop review requires IDS/IPS Prevent with Fail closed.");
  const uniqueBlockers = uniqueText(blockers);
  const baseSafe = hasQueue && !hasConflict && decision.evidenceStrength !== "weak" && (confidence >= 50) && packageReady;
  const canReviewDrop = Boolean(baseSafe && (portDrop || (signalDrop && idsFailClosed)));
  const canStageDrop = Boolean(canReviewDrop && portDrop && decision.action === "save_drop");
  const canDefine = Boolean(hasQueue && !hasConflict && decision.evidenceStrength !== "weak" && app.name);
  const action = canStageDrop ? "stage-drop" : canReviewDrop ? "review-drop" : canDefine ? "define" : "blocked";
  const directStageEligible = Boolean(canStageDrop && portDrop);
  const reviewBoundary = appIdClusterReviewBoundary(representativePathType, directStageEligible);
  const actionLabel = action === "stage-drop" ? "Stage representative App-ID and drop rule"
    : action === "review-drop" && signalDrop ? "Review signal-only drop boundary"
    : action === "review-drop" ? "Review representative bounded drop rule"
    : action === "define" ? "Define representative App-ID"
    : "Resolve blockers before enforcement";
  const readyDetail = directStageEligible
    ? "Representative TCP/UDP port-hint observation is direct-stage eligible through the existing queue workflow; validation and commit remain separate."
    : canReviewDrop
      ? "Representative observation can enter review-only drop-rule review; the cluster packet itself cannot directly stage policy."
      : canDefine
        ? "Representative observation can define an App-ID object; drop enforcement needs more bounded evidence."
        : "Resolve blockers before App-ID enforcement review.";
  const model = {
    action,
    label: action === "blocked" ? "Blocked" : actionLabel,
    actionLabel,
    tone: action === "stage-drop" ? "bad" : action === "review-drop" ? "warn" : action === "define" ? "info" : "bad",
    detail: uniqueBlockers.length
      ? `Cluster enforcement is blocked: ${uniqueBlockers[0]}`
      : readyDetail,
    representative,
    representativeDecision: decision,
    confidence,
    packageReady,
    packageEvidence,
    idsFailClosed,
    representativePathType,
    directStageEligible,
    reviewBoundary,
    signalSupport,
    portDrop,
    signalDrop,
    canDefine,
    canReviewDrop,
    canStageDrop,
    blockers: uniqueBlockers,
    candidateBoundary: "Representative queue action only; candidate validation, review, and commit remain separate. This does not claim true L7/proxy allow enforcement.",
  };
  model.productionReadinessRows = appIdClusterProductionReadinessRows(model);
  return model;
}

export function appIdClusterProductionReadinessRows(model = {}) {
  const blockers = model.blockers || [];
  const hasConfidence = Number(model.confidence || 0) > 0;
  const strongConfidence = Number(model.confidence || 0) >= 50 && model.representativeDecision?.evidenceStrength !== "weak";
  const portHintReady = Boolean(model.portDrop && model.packageReady && strongConfidence && !blockers.some((item) => /conflicting|queue-backed/i.test(item)));
  const reviewedDropReady = Boolean(model.canReviewDrop);
  const l7Only = model.representativePathType === "suricata-signal-only-review" || model.representativePathType === "custom-signal-needs-port-boundary" || model.representativePathType === "insufficient-enforcement-context";
  return [
    {
      key: "production-appid-corpus",
      label: "Production-ready App-ID corpus",
      status: model.packageReady ? "ready" : "blocked",
      detail: appIdProductionEvidenceLabel(model),
      authority: model.packageReady ? "allows bounded review workflow" : "blocks drop-rule staging",
    },
    {
      key: "l7-evidence-confidence",
      label: "L7 evidence confidence",
      status: strongConfidence ? "ready" : "review",
      detail: hasConfidence ? `${model.confidence}% confidence with ${model.representativeDecision?.evidenceStrength || "unknown"} evidence` : "confidence unavailable; collect replay or package evidence",
      authority: strongConfidence ? "can support bounded review" : "review-only",
    },
    {
      key: "representative-port-hint-staging",
      label: "Representative port-hint rule staging",
      status: model.directStageEligible ? "stageable" : portHintReady ? "review" : "not stageable",
      detail: model.portDrop ? "representative TCP/UDP port-hint matches the suggested App-ID" : "no representative TCP/UDP port-hint boundary",
      authority: model.directStageEligible ? "representative queue action only" : "no direct staging",
    },
    {
      key: "reviewed-drop-rule-staging",
      label: "Reviewed drop-rule staging",
      status: reviewedDropReady ? "reviewable" : "blocked",
      detail: reviewedDropReady ? model.reviewBoundary : (blockers[0] || "bounded drop-rule review is not available"),
      authority: model.canStageDrop ? "direct queue staging after review" : reviewedDropReady ? "review-only candidate path" : "blocked",
    },
    {
      key: "non-port-hint-l7-only-boundary",
      label: "Non-port-hint/L7-only boundary",
      status: l7Only ? "review-only" : "bounded port-hint",
      detail: l7Only ? appIdClusterReviewOnlyBoundary(model) : "port-hint path only; true L7 enforcement remains follow-on hardening",
      authority: "no true production L7/proxy allow authority",
    },
  ].map((row) => ({
    key: noSecretText(row.key),
    label: noSecretText(row.label),
    status: noSecretText(row.status),
    detail: noSecretText(row.detail),
    authority: noSecretText(row.authority),
  }));
}

function appIdClusterReadinessRowDetail(model = {}, key = "") {
  const row = (model.productionReadinessRows || appIdClusterProductionReadinessRows(model)).find((item) => item.key === key);
  return row ? `${row.status}: ${row.detail}` : "unavailable";
}

export function appIdDirectStageEligibilityLabel(model = {}) {
  if (model.directStageEligible) return "eligible: representative TCP/UDP port-hint queue path";
  if (model.representativePathType === "tcp-udp-port-hint") return "not eligible yet: production evidence, confidence, or blockers must clear first";
  if (model.representativePathType === "suricata-signal-only-review") return "review-only: supported Suricata signal path, no direct stage";
  if (model.representativePathType === "custom-signal-needs-port-boundary") return "review-only: add TCP/UDP port boundary or corpus evidence";
  return "review-only: insufficient bounded enforcement context";
}

export function appIdProductionEvidenceLabel(model = {}) {
  if (model.packageReady) return model.packageEvidence || "production ready";
  const evidence = model.packageEvidence || "production package evidence missing";
  return evidence.match(/^not production ready/i) ? evidence : `not production ready: ${evidence}`;
}

export function appIdClusterReviewOnlyBoundary(model = {}) {
  if (model.directStageEligible) return "Direct staging remains limited to the representative queue action; validation and commit are separate.";
  if (model.representativePathType === "suricata-signal-only-review") return "Review-only boundary: supported Suricata signal can be reviewed only with IDS/IPS Prevent fail-closed; no direct stage.";
  if (model.representativePathType === "custom-signal-needs-port-boundary") return "Review-only boundary: custom signal needs a TCP/UDP port boundary or stronger corpus evidence before drop review.";
  if (model.representativePathType === "tcp-udp-port-hint") return "Review-only boundary until production evidence, confidence, and representative blockers clear.";
  return "Review-only boundary: evidence handoff only; no policy staging.";
}

export function appIdClusterReviewBoundary(pathType = "", directStageEligible = false) {
  if (pathType === "tcp-udp-port-hint") {
    return directStageEligible
      ? "Direct staging is limited to the representative queue path and TCP/UDP port-hint drop candidate; validation and commit remain separate."
      : "TCP/UDP port-hint path can be reviewed, but this cluster packet does not directly stage policy.";
  }
  if (pathType === "suricata-signal-only-review") {
    return "Signal-only clusters are review-only handoffs; IDS/IPS Prevent fail-closed is required for candidate review, and export does not create true L7/proxy allow or direct staging.";
  }
  if (pathType === "custom-signal-needs-port-boundary") {
    return "Custom signal requires a TCP/UDP port boundary or corpus evidence before drop review; no direct staging or true L7/proxy allow is implied.";
  }
  return "Insufficient enforcement context; use the handoff for evidence review only.";
}

function appIdClusterEnforcementArtifact(model = {}) {
  return {
    action: model.action || "blocked",
    label: model.label || "",
    actionLabel: model.actionLabel || "",
    canDefine: Boolean(model.canDefine),
    canReviewDrop: Boolean(model.canReviewDrop),
    canStageDrop: Boolean(model.canStageDrop),
    blockers: (model.blockers || []).map(noSecretText),
    representativeQueueId: noSecretText(model.representative?.queueId || ""),
    representativeFlowId: noSecretText(model.representative?.sampleFlowId || ""),
    confidence: fmt.num(model.confidence),
    packageReady: Boolean(model.packageReady),
    packageEvidence: noSecretText(model.packageEvidence || ""),
    productionEvidence: noSecretText(appIdProductionEvidenceLabel(model)),
    idsFailClosed: Boolean(model.idsFailClosed),
    representativePathType: model.representativePathType || "",
    directStageEligible: Boolean(model.directStageEligible),
    directStageEligibility: noSecretText(appIdDirectStageEligibilityLabel(model)),
    productionReadinessRows: appIdClusterProductionReadinessRows(model),
    reviewBoundary: noSecretText(model.reviewBoundary || ""),
    reviewOnlyBoundary: noSecretText(appIdClusterReviewOnlyBoundary(model)),
    signalSupport: noSecretText(model.signalSupport || ""),
    candidateBoundary: model.candidateBoundary || "",
  };
}

export function appIdClusterCorpusCustodyChecklist(cluster = {}, model = {}, options = {}) {
  const representative = model.representative || cluster.representative || appIdObservationRepresentative(cluster.observations || []) || {};
  const readiness = options.appIdReadiness || {};
  const manifest = readiness.manifestSha256 || appIdObservationPackageProvenance(representative).manifestSha256 || "";
  const readinessStatus = readiness.productionReady ? "passed" : noSecretText(readiness.status || "missing");
  return [
    {
      label: "Representative queue observation",
      status: representative.queueId ? "present" : "missing",
      detail: noSecretText(representative.queueId || representative.sampleFlowId || "no queue id"),
    },
    {
      label: "Representative path type",
      status: model.representativePathType || "unknown",
      detail: appIdDirectStageEligibilityLabel(model),
    },
    {
      label: "Production readiness evidence",
      status: readinessStatus,
      detail: readiness.productionReady ? appIdProductionEvidenceLabel(model) : noSecretText(joinParts(appIdReadinessReason(readiness), "release-grade App-ID package evidence required")),
    },
    {
      label: "Signed App-ID package manifest",
      status: manifest ? "present" : "missing",
      detail: manifest ? `manifest ${shortHash(manifest)}` : "production corpus evidence required before custody handoff",
    },
    {
      label: "Corpus review route",
      status: "operator handoff",
      detail: "#/intel?surface=app-id&drawer=review",
    },
    {
      label: "Boundary",
      status: "not signed custody",
      detail: "no capture execution, legal retention, policy commit, or true L7/proxy allow claim",
    },
  ].map((item) => ({
    label: noSecretText(item.label),
    status: noSecretText(item.status),
    detail: noSecretText(item.detail),
  }));
}

function appIdObservationClusterArtifact(cluster = {}) {
  return {
    id: cluster.id || "",
    label: noSecretText(cluster.label || ""),
    candidateTaxonomy: noSecretText(cluster.candidateTaxonomy || ""),
    candidateDisplayName: noSecretText(cluster.candidateDisplayName || ""),
    category: noSecretText(cluster.category || ""),
    confidenceBand: cluster.confidenceBand || "",
    conflictState: cluster.conflictState || "",
    kind: cluster.kind || "",
    decisionAction: cluster.decisionAction || "",
    decisionLabel: cluster.decisionLabel || "",
    evidenceStrength: cluster.evidenceStrength || "",
    observationCount: fmt.num(cluster.observationCount),
    flowCount: fmt.num(cluster.flowCount),
    bytes: fmt.num(cluster.bytes),
    packets: fmt.num(cluster.packets),
    evidenceCount: fmt.num(cluster.evidenceCount),
    queueIds: (cluster.queueIds || []).slice(0, 20).map(noSecretText),
    sampleFlowIds: (cluster.sampleFlowIds || []).slice(0, 20).map(noSecretText),
    firstSeen: cluster.firstSeen || "",
    lastSeen: cluster.lastSeen || "",
    fallbackSingle: Boolean(cluster.fallbackSingle),
  };
}

function appIdObservationClusterObservationArtifact(obs = {}) {
  const app = obs.suggestedApplication || {};
  return {
    queueId: noSecretText(obs.queueId || ""),
    kind: obs.kind || "",
    appId: noSecretText(obs.appId || ""),
    appName: noSecretText(obs.appName || ""),
    appConfidence: fmt.num(obs.appConfidence),
    engineSignalSource: noSecretText(obs.engineSignalSource || ""),
    engineSignal: noSecretText(obs.engineSignal || ""),
    protocol: protocolEnum(obs.protocol).replace(/^PROTOCOL_/, "") || String(obs.protocol || ""),
    destPort: numberOrZero(obs.destPort),
    sampleFlowId: noSecretText(obs.sampleFlowId || ""),
    sampleSrcIp: obs.sampleSrcIp || "",
    sampleSrcPort: numberOrZero(obs.sampleSrcPort || obs.sample_src_port),
    sampleDestIp: obs.sampleDestIp || "",
    count: fmt.num(obs.count),
    bytes: fmt.num(obs.bytes),
    packets: fmt.num(obs.packets),
    firstSeen: obs.firstSeen || "",
    lastSeen: obs.lastSeen || "",
    appEvidence: (obs.appEvidence || []).slice(0, 6).map(noSecretText),
    suggestedApplication: {
      name: noSecretText(app.name || ""),
      displayName: noSecretText(app.displayName || ""),
      category: noSecretText(app.category || ""),
      engineSignals: (app.engineSignals || []).slice(0, 8).map(noSecretText),
      ports: app.ports || [],
    },
  };
}

function noSecretText(value) {
  let text = String(value || "");
  text = text.replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, "[redacted-secret]");
  text = text.replace(/\b(authorization:\s*bearer\s+)[^\s,;]+/ig, "$1[redacted]");
  text = text.replace(/\b(token|secret|password|passwd|api[_-]?key|private[_-]?key)=([^ \t\n\r,;]+)/ig, "$1=[redacted]");
  text = text.replace(/\b(token|secret|password|passwd|api[_-]?key|private[_-]?key):\s*([^ \t\n\r,;]+)/ig, "$1: [redacted]");
  return text;
}

function stableHash(value) {
  let hash = 2166136261;
  for (const ch of String(value || "")) {
    hash ^= ch.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(36);
}

function appIdPackageReadinessStrip(readiness = null) {
  if (!readiness) return null;
  const cls = readiness.productionReady ? "ok" : readiness.status === "unavailable" ? "bad" : "warn";
  return h("div", { class: "alert-box " + cls },
    h("div", { class: "flex wrap", style: { justifyContent: "space-between" } },
      h("div", { class: "flex wrap" },
        h("strong", {}, "App-ID package"),
        pill(readiness.productionReady ? "production ready" : readiness.status || "not ready", cls, true),
        readiness.version ? h("span", { class: "tag" }, readiness.version) : null,
        readiness.manifestSha256 ? h("span", { class: "tag" }, "manifest " + shortHash(readiness.manifestSha256)) : null,
        h("span", { class: "tag" }, readiness.packageState || "unknown")),
      h("a", { class: "linklike", href: "#/intel?surface=app-id&drawer=review", title: "Open App-ID intel review", "aria-label": "Open App-ID intel review", dataset: { trafficAction: "appid-intel-review" } }, "Intel review ->")),
    h("div", { class: "note" }, readiness.productionReady
      ? "Drop recommendations can include candidate enforcement when observation evidence is strong."
      : "Candidate drop recommendations are paused until App-ID production evidence is explicit."),
    readiness.blockers?.length ? h("div", { class: "note" }, `Blockers: ${readiness.blockers.slice(0, 4).join(", ")}`) : null);
}

function renderAppIdObservationTable(root, wrap, observations, readiness = null) {
  clear(wrap);
  const r = observationRows(observations, readiness);
  if (!r.length) { wrap.appendChild(emptyState("search", "No matching observations", "Adjust your filters.")); return; }
  wrap.appendChild(responsiveTable(["Review", "Evidence", "Suggested App-ID", "Context", { label: "Volume", attrs: { class: "num" } }, "Next action", { label: "", attrs: { class: "actions-col" } }],
    r.slice(0, 300).map((obs) => {
      const decision = appIdObservationDecision(obs, readiness);
      return h("tr", { ...keyboardRowAttrs(() => observationDetail(root, obs, readiness), { label: `Review App-ID observation ${obs.queueId || obs.engineSignal || obs.appId || "item"}` }), dataset: { appidObservationId: obs.queueId || "" } },
        labeledCell("Review", {}, h("div", {},
          pill(observationKindLabel(obs.kind), observationKindClass(obs.kind)),
          h("div", { class: "note" }, obs.queueId ? `queue ${obs.queueId}` : "grouped observation"))),
        labeledCell("Evidence", {}, h("div", { class: "appid-signal-cell" },
          h("code", {}, obs.engineSignal ? `${obs.engineSignalSource || "engine"}=${obs.engineSignal}` : "none"),
          h("div", { class: "note" }, appIdEvidenceDigest(obs, decision)))),
        labeledCell("Suggested App-ID", {}, suggestedAppCell(obs)),
        labeledCell("Context", {}, observationContextCell(obs)),
        labeledCell("Volume", { class: "num" }, h("div", {}, fmt.compactNum(fmt.num(obs.count)), h("div", { class: "note" }, `${fmt.bytes(obs.bytes)} · ${fmt.compactNum(fmt.num(obs.packets))} pkts`))),
        labeledCell("Next action", {}, h("div", {},
          pill(decision.label, decision.tone),
          h("div", { class: "note" }, decision.reason))),
        labeledCell("Actions", { class: "cell-actions" },
          appIdObservationActions(root, obs, decision, readiness)));
    }),
    { className: "appid-observation-table" }));
}

function suggestedAppCell(obs) {
  const app = obs.suggestedApplication || {};
  const detail = [];
  if (app.displayName) detail.push(app.displayName);
  if (app.category) detail.push(app.category);
  const ports = applicationPortsLabel(app);
  if (ports !== "—") detail.push(ports);
  return h("div", {},
    h("div", { class: "mono" }, app.name || obs.appId || "custom-app"),
    detail.length ? h("div", { class: "note" }, detail.join(" · ")) : null);
}

function observationContextCell(obs) {
  const contentContext = appIdContentContext(obs);
  return h("div", {},
    h("div", { class: "mono" }, sampleTupleLabel(obs)),
    h("div", { class: "note" }, joinParts(`last ${fmt.absTime(obs.lastSeen)}`, appIdObservationPackageLabel(obs), contentContext)));
}

function appIdEvidenceDigest(obs, decision) {
  const parts = [];
  parts.push(obs.appConfidence ? `${obs.appConfidence}% confidence` : "confidence unavailable");
  parts.push(`${decision.evidenceStrength} evidence`);
  if (obs.appEvidence?.length) parts.push(`${obs.appEvidence.length} note${obs.appEvidence.length === 1 ? "" : "s"}`);
  return parts.join(" · ");
}

function appIdObservationActions(root, obs, decision = appIdObservationDecision(obs), readiness = null) {
  const obsLabel = observationActionLabel(obs);
  const obsDataset = { appidObservationId: obs.queueId || "" };
  const primary = decision.action === "filter_related_evidence"
    ? actionButton({ className: "btn sm", title: "Open matching flow filters", ariaLabel: `Open matching flows for App-ID observation ${obsLabel}`, dataset: { ...obsDataset, appidObservationAction: "flows" }, onclick: (e) => { e.stopPropagation(); matchingFlows(root, obs); }, iconName: "traffic", label: "Flows" })
    : decision.action === "save_drop"
      ? actionButton({ className: "btn sm danger", title: "Stage a custom App-ID and candidate drop rule", ariaLabel: `Stage custom App-ID and drop rule for observation ${obsLabel}`, dataset: { ...obsDataset, appidObservationAction: "save-drop" }, onclick: (e) => { e.stopPropagation(); promoteObservation(obs, "block"); }, iconName: "block", label: "Save & drop" })
      : decision.action === "define_custom_app"
        ? actionButton({ className: "btn sm", title: "Stage a custom App-ID definition from this observation", ariaLabel: `Stage custom App-ID definition for observation ${obsLabel}`, dataset: { ...obsDataset, appidObservationAction: "define" }, onclick: (e) => { e.stopPropagation(); promoteObservation(obs); }, iconName: "objects", label: "Define" })
        : actionButton({ title: "Review conflicting or weak observation evidence", ariaLabel: `Investigate App-ID observation ${obsLabel}`, dataset: { ...obsDataset, appidObservationAction: "investigate" }, onclick: (e) => { e.stopPropagation(); observationDetail(root, obs, readiness); }, iconName: "search", label: "Investigate" });
  return h("div", { class: "row-actions" },
    primary,
    actionButton({ title: "Review observation evidence", ariaLabel: `Review App-ID observation ${obsLabel}`, dataset: { ...obsDataset, appidObservationAction: "review" }, onclick: (e) => { e.stopPropagation(); observationDetail(root, obs, readiness); }, iconName: "search", label: "Review" }),
    actionButton({ title: "Plan a packet capture from the representative sample tuple", ariaLabel: `Plan packet capture for App-ID observation ${obsLabel}`, dataset: { ...obsDataset, appidObservationAction: "capture" }, onclick: (e) => { e.stopPropagation(); captureObservation(obs); }, iconName: "download", label: "Capture" }),
    decision.action !== "filter_related_evidence" ? actionButton({ title: "Open matching flow filters", ariaLabel: `Open matching flows for App-ID observation ${obsLabel}`, dataset: { ...obsDataset, appidObservationAction: "flows" }, onclick: (e) => { e.stopPropagation(); matchingFlows(root, obs); }, iconName: "traffic", label: "Flows" }) : null);
}

function observationDetail(root, obs, readiness = null) {
  if (obs.queueId) {
    state.queueId = obs.queueId;
    state.flowId = "";
    state.sessionKey = "";
    syncRoute();
  }
  const app = obs.suggestedApplication || {};
  const decision = appIdObservationDecision(obs, readiness);
  const packageProvenance = appIdObservationPackageProvenance(obs);
  openDrawer({
    title: "App-ID observation",
    subtitle: "Engine labels are evidence; Phragma owns the canonical App-ID.",
    width: "680px",
    onClose: clearTrafficSelection,
    body: h("div", {},
      h("div", { class: "flex wrap", style: { marginBottom: "16px" } },
        pill(observationKindLabel(obs.kind), observationKindClass(obs.kind)),
        obs.appConfidence ? h("span", { class: "tag" }, obs.appConfidence + "% confidence") : null,
        obs.protocol ? h("span", { class: "tag" }, obs.protocol) : null,
        obs.destPort ? h("span", { class: "tag" }, "port " + obs.destPort) : null,
        obs.count ? h("span", { class: "tag" }, fmt.compactNum(fmt.num(obs.count)) + " flows") : null),
      h("div", { class: "profile-strip" },
        h("div", { class: "profile-strip-head" },
          h("strong", {}, "Recommended next action"),
          pill(decision.label, decision.tone)),
        h("div", { class: "note" }, decision.reason),
        h("dl", { class: "kv" },
          kv("Evidence strength", decision.evidenceStrength),
          kv("Candidate path", decision.candidatePath),
          kv("Content context", appIdContentContext(obs) || "not present in observation"))),
      h("dl", { class: "kv" },
        kv("Queue ID", obs.queueId || "—"),
        kv("Engine signal", obs.engineSignal ? `${obs.engineSignalSource || "engine"}=${obs.engineSignal}` : "—"),
        kv("Observed App-ID", joinParts(obs.appId || "—", obs.appName, obs.appCategory)),
        kv("Confidence", obs.appConfidence ? obs.appConfidence + "%" : "—"),
        kv("Sample flow", obs.sampleFlowId || "—"),
        kv("Sample tuple", sampleTupleLabel(obs)),
        kv("App-ID package", packageProvenance.label || "—"),
        kv("Package version", packageProvenance.version || "—"),
        kv("Package manifest", packageProvenance.manifestShort ? `sha256:${packageProvenance.manifestShort}` : "—"),
        kv("First seen", fmt.absTime(obs.firstSeen)),
        kv("Last seen", fmt.absTime(obs.lastSeen)),
        kv("Volume", `${fmt.compactNum(fmt.num(obs.count))} flows · ${fmt.bytes(obs.bytes)} · ${fmt.compactNum(fmt.num(obs.packets))} packets`)),
      obs.appEvidence?.length ? h("div", {},
        h("h3", { style: { marginTop: "16px" } }, "Evidence"),
        h("ul", { class: "trace-list" }, obs.appEvidence.map((e) => h("li", {}, e)))) : null,
      captureEvidencePanel(flowFromObservation(obs)),
      appIdEvidenceBridgePanel(flowFromObservation(obs), { kind: "observation", observation: obs, readiness, decision }),
      appIdRegressionSamplePanel(obs, readiness, decision),
      h("div", { class: "profile-strip" },
        h("div", { class: "profile-strip-head" },
          h("strong", {}, "Suggested object"),
          h("span", {}, "staged through candidate policy")),
        h("dl", { class: "kv" },
          kv("App-ID", app.name || "—"),
          kv("Display name", app.displayName || "—"),
          kv("Category", app.category || "—"),
          kv("Engine signals", (app.engineSignals || []).join(", ") || "—"),
          kv("Port hints", applicationPortsLabel(app)))),
      handoffActions(trafficWorkflowPacket(appIdObservationHandoffPacket(obs, {
        route: currentRoute(),
        reviewAction: decision.label,
        evidenceStrength: decision.evidenceStrength,
        currentInspectionPosture: inspectionPostureSummary(runtimeStatus),
      }), trafficCaptureRegressionWorkflow(flowFromObservation(obs), {
        kind: "observation",
        observation: obs,
        readiness,
        decision,
        caseAction: "app-id-capture-regression",
      })))),
    footer: [
      drawerButton({ className: "btn ghost", action: "close-appid-observation", title: "Close App-ID observation drawer", dataset: { appidObservationAction: "close" }, onclick: closeDrawer, label: "Close" }),
      drawerButton({ action: "matching-flows", title: "Open matching flow filters for this App-ID observation", dataset: { appidObservationAction: "matching-flows" }, onclick: () => { closeDrawer(); matchingFlows(root, obs); }, iconName: "traffic", label: "Matching flows" }),
      drawerButton({ action: "capture-observation", title: "Plan packet capture for this App-ID observation sample", dataset: { appidObservationAction: "capture-sample" }, onclick: () => { closeDrawer(); captureObservation(obs); }, iconName: "download", label: "Capture sample" }),
      drawerButton({ action: "compare-appid-replay", title: "Compare this observation as an App-ID lab replay report", dataset: { appidObservationAction: "compare-replay" }, onclick: () => compareAppIdReplay(obs), iconName: "diff", label: "Compare" }),
      obs.queueId ? drawerButton({ action: "appid-api-cli", title: "Open App-ID observation API and CLI context", dataset: { appidObservationAction: "api-cli" }, onclick: () => openAutomationContext(currentRoute()), iconName: "copy", label: "API / CLI" }) : null,
      drawerButton({ action: "promote-appid", title: "Promote this observation into a candidate App-ID object", dataset: { appidObservationAction: "promote-app-id" }, onclick: () => { closeDrawer(); promoteObservation(obs); }, iconName: "objects", label: "Promote App-ID" }),
      decision.canStageDrop ? drawerButton({ className: "btn danger", action: "promote-appid-drop", title: "Promote this observation and stage a candidate drop rule", dataset: { appidObservationAction: "promote-drop" }, onclick: () => { closeDrawer(); promoteObservation(obs, "block"); }, iconName: "block", label: "Promote & drop" }) : null,
    ],
  });
}

function appIdEvidenceBridgePanel(flow = {}, opts = {}) {
  const bridge = appIdEvidenceBridgePlan(flow, opts);
  const kind = bridge.kind || (opts.kind === "observation" ? "observation" : "flow");
  return h("div", { class: "profile-strip", dataset: { appidEvidenceBridge: bridge.kind } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Capture / regression bridge"),
      pill(bridge.candidateSafeLabel, "info")),
    h("div", { class: "note" }, bridge.detail),
    h("dl", { class: "kv" },
      kv("Capture next step", bridge.captureStep),
      kv("Regression next step", bridge.regressionStep),
      kv("Corpus review", bridge.corpusStep),
      kv("Candidate boundary", bridge.candidateBoundary)),
    h("div", { class: "row-actions" },
      drawerLink({ className: "btn sm", action: "bridge-capture", title: "Open bounded packet-capture planning for this evidence", dataset: { trafficBridgeAction: "capture" }, href: bridge.captureHref, onclick: closeDrawer, iconName: "download", iconSize: 15, label: "Plan capture" }),
      bridge.queueHref ? drawerLink({ className: "btn sm ghost", action: "bridge-appid-queue", title: "Open matching App-ID queue filters", dataset: { trafficBridgeAction: "queue" }, href: bridge.queueHref, onclick: closeDrawer, iconName: "traffic", iconSize: 15, label: "Queue review" }) : null,
      bridge.corpusHref ? drawerLink({ className: "btn sm ghost", action: "bridge-corpus-review", title: "Open App-ID corpus package review", dataset: { trafficBridgeAction: "corpus" }, href: bridge.corpusHref, onclick: closeDrawer, iconName: "objects", iconSize: 15, label: "Corpus review" }) : null,
      bridge.canStageRegressionSample && opts.observation ? h("button", {
        class: "btn sm",
        type: "button",
        title: "Stage this reviewed observation as draft App-ID regression corpus input",
        "aria-label": "Stage this reviewed observation as draft App-ID regression corpus input",
        dataset: { trafficBridgeAction: "stage-regression-sample" },
        onclick: () => stageAppIdRegressionSample(opts.observation),
      }, h("span", { html: icon("upload", 15) }), "Stage sample") : null,
      kind === "observation" && opts.observation ? h("button", {
        class: "btn sm ghost",
        type: "button",
        title: "Compare this observation as a read-only App-ID lab replay report",
        "aria-label": "Compare this observation as a read-only App-ID lab replay report",
        dataset: { trafficBridgeAction: "compare-replay" },
        onclick: () => compareAppIdReplay(opts.observation),
      }, h("span", { html: icon("diff", 15) }), "Compare") : null));
}

export function appIdEvidenceBridgePlan(flow = {}, opts = {}) {
  const kind = opts.kind === "observation" ? "observation" : "flow";
  const obs = opts.observation || {};
  const capturePlan = buildCapturePlan({
    flowId: flow.flowId || obs.sampleFlowId || "",
    srcIp: flow.srcIp || obs.sampleSrcIp || "",
    srcPort: flow.srcPort || obs.sampleSrcPort || obs.sample_src_port || "",
    destIp: flow.destIp || obs.sampleDestIp || "",
    destPort: flow.destPort || obs.destPort || "",
    protocol: flow.protocol || obs.protocol || "",
    label: kind === "observation" ? "appid-observation" : "flow",
  });
  const captureHref = investigationHashFromFlow(flow, { intent: "capture" });
  const queueHref = appIdBridgeQueueHref(flow, obs);
  const corpusHref = "#/intel?surface=app-id&drawer=review";
  const decision = opts.decision || appIdObservationDecision(obs, opts.readiness || null);
  const readiness = opts.readiness || {};
  const hasQueue = Boolean(obs.queueId);
  const canStageRegressionSample = kind === "observation" && hasQueue;
  const captureTupleReady = Boolean(capturePlan.srcIp && capturePlan.destIp);
  return {
    kind,
    captureHref,
    queueHref,
    corpusHref,
    canStageRegressionSample,
    candidateSafeLabel: "candidate-safe",
    detail: kind === "observation"
      ? "Use the selected observation as the reviewed bridge from flow evidence to bounded packet capture, draft regression sample, and App-ID corpus review."
      : "Use the selected flow to plan bounded packet capture and gather/pin evidence before any candidate App-ID or rule workflow.",
    captureStep: captureTupleReady
      ? `${capturePlan.protocol} ${fmt.endpoint(capturePlan.srcIp, capturePlan.srcPort)} -> ${fmt.endpoint(capturePlan.destIp, capturePlan.destPort)}; ${capturePlan.durationSeconds}s / ${capturePlan.packetCount} packets / snaplen ${capturePlan.snaplenBytes}`
      : "Open Troubleshoot capture planning; tuple fields are incomplete, so server review must scope the capture.",
    regressionStep: canStageRegressionSample
      ? `Existing endpoint supports reviewed draft sample staging for queue ${obs.queueId}; attach the capture SHA-256 before staging.`
      : "Browser-local only from this drawer; capture and pin/export evidence, then select a queued App-ID observation before draft sample staging.",
    corpusStep: readiness.productionReady
      ? "Review the installed App-ID package corpus and readiness evidence before promotion."
      : joinParts("Open App-ID corpus package review", readiness.status ? `package ${readiness.status}` : "", decision.evidenceStrength ? `${decision.evidenceStrength} evidence` : ""),
    candidateBoundary: "No direct policy mutation; promotion/drop remains in the existing candidate App-ID and Rules workflows.",
    captureFilter: capturePlan.filter,
    captureLimits: {
      interface: capturePlan.interface,
      durationSeconds: capturePlan.durationSeconds,
      packetCount: capturePlan.packetCount,
      snaplenBytes: capturePlan.snaplenBytes,
    },
    captureWarnings: capturePlan.warnings || [],
    packageReady: Boolean(readiness.productionReady),
    reviewAction: decision.label || "",
  };
}

function appIdBridgeQueueHref(flow = {}, obs = {}) {
  const q = new URLSearchParams();
  q.set("mode", "app-id");
  const signal = obs.engineSignal || flow.appProtocol || flow.appId || "";
  const protocol = obs.protocol || flow.protocol || "";
  const port = obs.destPort || flow.destPort || "";
  if (signal && signal !== "unknown") q.set("engineSignal", signal);
  if (protocol) q.set("protocol", String(protocol).toUpperCase().replace(/^PROTOCOL_/, ""));
  if (port) q.set("port", String(port));
  if (obs.queueId) q.set("queueId", obs.queueId);
  q.set("limit", "100");
  return "#/traffic?" + q.toString();
}

function appIdRegressionSamplePanel(obs, readiness = null, decision = appIdObservationDecision(obs, readiness)) {
  const packet = appIdRegressionSamplePacket(obs, readiness, decision);
  const blockers = Array.isArray(readiness?.blockers) ? readiness.blockers : [];
  const packageTone = readiness?.productionReady ? "ok" : readiness?.status === "unavailable" ? "bad" : "warn";
  const packageLabel = readiness?.productionReady ? "package ready" : readiness?.status || "package pending";
  const packageDetail = joinParts(
    readiness?.version ? `version ${readiness.version}` : "",
    readiness?.manifestSha256 ? `manifest ${shortHash(readiness.manifestSha256)}` : "",
    readiness?.packageState ? `state ${readiness.packageState}` : "",
  ) || "package context unavailable";
  return h("div", { class: "profile-strip", dataset: { appidRegressionSamplePanel: "true" } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Regression sample"),
      pill(packageLabel, packageTone)),
    h("div", { class: "note" },
      "Preserve the representative flow, capture context, package version, and suggested taxonomy as App-ID corpus evidence."),
    h("dl", { class: "kv" },
      kv("Sample ID", packet.summary?.sampleId || "—"),
      kv("Capture", packet.summary?.captureRequirement || "bounded packet capture"),
      kv("Package", packageDetail),
      kv("Blockers", blockers.length ? blockers.slice(0, 4).join(", ") : "none reported")),
    h("div", { class: "row-actions" },
      h("button", {
        class: "btn sm",
        type: "button",
        title: "Stage this reviewed observation as draft App-ID regression corpus input",
        "aria-label": "Stage this reviewed observation as draft App-ID regression corpus input",
        dataset: { appidAction: "stage-regression-sample" },
        onclick: () => stageAppIdRegressionSample(obs),
      },
        h("span", { html: icon("upload", 15) }), "Stage sample")),
    handoffActions(packet));
}

function appIdRegressionSamplePacket(obs, readiness = null, decision = appIdObservationDecision(obs, readiness)) {
  const packet = appIdRegressionSampleHandoffPacket(obs, {
    route: currentRoute(),
    reviewAction: decision.label,
    evidenceStrength: decision.evidenceStrength,
    appIdReadiness: readiness || {},
    currentInspectionPosture: inspectionPostureSummary(runtimeStatus),
  });
  return trafficWorkflowPacket(packet, trafficCaptureRegressionWorkflow(flowFromObservation(obs), {
    kind: "observation",
    observation: obs,
    readiness,
    decision,
    caseAction: "app-id-regression-sample",
  }));
}

function stageAppIdRegressionSample(obs = {}) {
  const app = obs.suggestedApplication || {};
  const pcapSHA = inp("", "64-character capture SHA-256", { dataset: { appidRegressionField: "pcap-sha256" } });
  const expectedApp = inp(app.name || obs.appId || obs.engineSignal || "", "expected App-ID", { dataset: { appidRegressionField: "expected-app" } });
  const observedApp = inp(obs.appId && obs.appId !== "unknown" ? obs.appId : (obs.appName && obs.appName !== "Unknown" ? obs.appName : obs.engineSignal || ""), "observed App-ID", { dataset: { appidRegressionField: "observed-app" } });
  const reason = h("textarea", {
    class: "input",
    placeholder: "Review reason for draft corpus staging",
    dataset: { appidRegressionField: "reason" },
  }, appIdRegressionSampleReason(obs));
  const status = h("div", { class: "note", dataset: { appidRegressionStatus: "true" } }, "Draft sample only; package signing and production install remain in the content workflow.");
  const save = async () => {
    const req = observationRequest();
    const body = appIdRegressionSampleStageBody(obs, {
      pcapSha256: val(pcapSHA),
      expectedApp: val(expectedApp),
      observedApp: val(observedApp),
      reason: val(reason),
      flowLimit: req.flowLimit,
      confidenceThreshold: req.confidenceThreshold,
      since: req.since,
      until: req.until,
    });
    if (!body.reason) {
      toast("Reason required", "Add a review reason before staging the draft sample.", "warn");
      return;
    }
    if (!/^[a-fA-F0-9]{64}$/.test(body.pcapSha256 || "")) {
      toast("Capture SHA required", "Enter a 64-character packet-capture SHA-256.", "warn");
      return;
    }
    try {
      const response = await api.stageAppIdRegressionSample(obs.queueId, body);
      status.textContent = `Staged ${response.sample?.sampleId || "sample"} in ${response.draftArtifact || "draft corpus"} (${fmt.num(response.sampleCount)} samples).`;
      status.dataset.appidRegressionStatus = "staged";
      toast("Regression sample staged", response.draftArtifact || "Draft corpus updated.", "ok");
    } catch (e) {
      toast("Stage sample failed", e.message, "bad");
    }
  };
  openDrawer({
    title: "App-ID regression sample",
    subtitle: "Reviewed observation to draft content corpus.",
    width: "560px",
    body: h("div", { dataset: { appidRegressionSampleDrawer: "true" } },
      h("dl", { class: "kv" },
        kv("Queue ID", obs.queueId || "—"),
        kv("Sample tuple", sampleTupleLabel(obs)),
        kv("Engine signal", obs.engineSignal ? `${obs.engineSignalSource || "engine"}=${obs.engineSignal}` : "—")),
      field("PCAP SHA-256", pcapSHA),
      field("Expected App-ID", expectedApp),
      field("Observed App-ID", observedApp),
      field("Reason", reason),
      status),
    footer: [
      drawerButton({ className: "btn ghost", action: "close-regression-sample", title: "Close App-ID regression sample drawer", dataset: { appidRegressionAction: "close" }, onclick: closeDrawer, label: "Close" }),
      drawerButton({ action: "stage-regression-sample", title: "Stage reviewed App-ID regression sample", dataset: { appidRegressionAction: "stage-sample" }, onclick: save, iconName: "upload", label: "Stage sample" }),
    ],
  });
}

function compareAppIdReplay(obs = {}) {
  const app = obs.suggestedApplication || {};
  const expectedApp = inp(app.name || obs.appId || obs.engineSignal || "", "expected App-ID", { dataset: { appidReplayField: "expected-app" } });
  const status = h("div", { class: "note", dataset: { appidReplayStatus: "true" } }, "Read-only lab replay comparison; no candidate, corpus, or dataplane state changes.");
  const resultSlot = h("div", { dataset: { appidReplayReport: "true" } });
  const run = async () => {
    const req = observationRequest();
    const body = appIdReplayCompareBody(obs, {
      expectedApp: val(expectedApp),
      flowLimit: req.flowLimit,
      confidenceThreshold: req.confidenceThreshold,
      since: req.since,
      until: req.until,
    });
    try {
      status.textContent = "Comparing selected App-ID evidence.";
      const response = await api.compareAppIdReplay(body);
      clear(resultSlot);
      resultSlot.appendChild(appIdReplayReportPanel(response.report || {}));
      status.textContent = response.detail || "Replay comparison complete.";
      toast("Replay compared", appIdReplayVerdictLabel(response.report?.verdict || ""), "ok");
    } catch (e) {
      status.textContent = e.message || "Replay comparison failed.";
      toast("Replay compare failed", e.message, "bad");
    }
  };
  openDrawer({
    title: "App-ID replay comparison",
    subtitle: "Read-only lab report for clustering and PCAP replay evidence.",
    width: "620px",
    body: h("div", { dataset: { appidReplayCompareDrawer: "true" } },
      h("dl", { class: "kv" },
        kv("Queue ID", obs.queueId || "—"),
        kv("Observed App-ID", joinParts(obs.appId || "—", obs.appName, obs.appCategory)),
        kv("Confidence", obs.appConfidence ? obs.appConfidence + "%" : "—"),
        kv("Sample tuple", sampleTupleLabel(obs))),
      field("Expected App-ID", expectedApp),
      status,
      resultSlot),
    footer: [
      drawerButton({ className: "btn ghost", action: "close-appid-replay", title: "Close App-ID replay comparison drawer", dataset: { appidReplayAction: "close" }, onclick: closeDrawer, label: "Close" }),
      drawerButton({ action: "compare-appid-replay-run", title: "Run read-only App-ID replay comparison", dataset: { appidReplayAction: "compare" }, onclick: run, iconName: "diff", label: "Compare" }),
    ],
  });
}

export function appIdReplayCompareBody(obs = {}, opts = {}) {
  return {
    queueId: obs.queueId || "",
    observation: obs.queueId ? undefined : obs,
    expectedApp: String(opts.expectedApp || obs.suggestedApplication?.name || obs.appId || obs.engineSignal || "").trim(),
    flowLimit: opts.flowLimit,
    confidenceThreshold: opts.confidenceThreshold,
    since: opts.since,
    until: opts.until,
  };
}

function appIdReplayReportPanel(report = {}) {
  const reasons = report.mismatchReasons || [];
  const evidence = report.boundedEvidence || [];
  const tone = report.verdict === "APP_ID_REPLAY_VERDICT_MATCH" ? "ok"
    : report.verdict === "APP_ID_REPLAY_VERDICT_NEEDS_EXPECTED_APP" || report.verdict === "APP_ID_REPLAY_VERDICT_NEEDS_EVIDENCE" ? "warn"
      : "bad";
  return h("div", { class: "profile-strip", dataset: { appidReplayResult: report.verdict || "unknown" } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Replay report"),
      pill(appIdReplayVerdictLabel(report.verdict), tone)),
    h("dl", { class: "kv" },
      kv("Report ID", report.reportId || "—"),
      kv("Observed App-ID", report.observedApp || "—"),
      kv("Expected App-ID", report.expectedApp || "—"),
      kv("Confidence", report.confidence ? report.confidence + "%" : "—"),
      kv("Sample", joinParts(report.sampleId, report.queueId, report.pcapSha256 ? "pcap " + shortHash(report.pcapSha256) : "") || "—"),
      kv("Scope", report.comparisonScope || "lab replay comparison only"),
      kv("Next action", report.recommendedNextAction || "Review replay evidence.")),
    reasons.length ? h("div", {},
      h("h3", { style: { marginTop: "14px" } }, "Mismatch reasons"),
      h("ul", { class: "trace-list" }, reasons.map((reason) => h("li", {}, reason)))) : null,
    evidence.length ? h("div", {},
      h("h3", { style: { marginTop: "14px" } }, "Bounded evidence"),
      h("ul", { class: "trace-list" }, evidence.map((item) => h("li", {}, item)))) : null);
}

function appIdReplayVerdictLabel(verdict = "") {
  if (verdict === "APP_ID_REPLAY_VERDICT_MATCH") return "match";
  if (verdict === "APP_ID_REPLAY_VERDICT_MISMATCH") return "mismatch";
  if (verdict === "APP_ID_REPLAY_VERDICT_NEEDS_EXPECTED_APP") return "needs expected App-ID";
  if (verdict === "APP_ID_REPLAY_VERDICT_NEEDS_EVIDENCE") return "needs evidence";
  return "not compared";
}

export function appIdRegressionSampleStageBody(obs = {}, opts = {}) {
  return {
    queueId: obs.queueId || "",
    reason: String(opts.reason || appIdRegressionSampleReason(obs)).trim(),
    pcapSha256: String(opts.pcapSha256 || "").trim(),
    expectedApp: String(opts.expectedApp || obs.suggestedApplication?.name || obs.appId || obs.engineSignal || "").trim(),
    observedApp: String(opts.observedApp || (obs.appId && obs.appId !== "unknown" ? obs.appId : (obs.appName && obs.appName !== "Unknown" ? obs.appName : obs.engineSignal || ""))).trim(),
    flowLimit: opts.flowLimit,
    confidenceThreshold: opts.confidenceThreshold,
    since: opts.since,
    until: opts.until,
  };
}

function appIdRegressionSampleReason(obs = {}) {
  return `reviewed App-ID observation ${obs.queueId || "queue"} for draft regression corpus`;
}

function appIdObservationEvidenceRows(observations, readiness = null) {
  return observationRows(observations, readiness).map((obs) => {
    const decision = appIdObservationDecision(obs, readiness);
    return {
      ...obs,
      reviewAction: decision.label,
      evidenceStrength: decision.evidenceStrength,
      appIdPackageVersion: obs.appIdPackageVersion || obs.app_id_package_version || "",
      appIdPackageManifestSha256: shortHash(obs.appIdPackageManifestSha256 || obs.app_id_package_manifest_sha256 || ""),
    };
  });
}

export function flowFromObservation(obs = {}) {
  return {
    srcIp: obs.sampleSrcIp,
    srcPort: numberOrZero(obs.sampleSrcPort || obs.sample_src_port),
    destIp: obs.sampleDestIp,
    destPort: obs.destPort,
    protocol: obs.protocol,
    appProtocol: obs.engineSignal,
    appId: obs.appId,
    appName: obs.appName,
    appCategory: obs.appCategory,
    appConfidence: obs.appConfidence,
    appEvidence: obs.appEvidence || [],
    appIdPackageVersion: obs.appIdPackageVersion || obs.app_id_package_version || "",
    appIdPackageManifestSha256: obs.appIdPackageManifestSha256 || obs.app_id_package_manifest_sha256 || "",
    flowId: obs.sampleFlowId,
    bytesToServer: obs.bytes,
    bytesToClient: 0,
    packets: obs.packets,
  };
}

async function promoteObservation(obs, mode = "save") {
  try {
    await session.load();
    openCustomAppDrawer(flowFromObservation(obs), obs.suggestedApplication, mode, { observation: obs });
  } catch (e) { toast("Failed", e.message, "bad"); }
}

async function matchingFlows(root, obs) {
  state = {
    ...state,
    mode: "flows",
    q: "",
    app: obs.engineSignal || obs.appId || "",
    protocol: obs.protocol || "",
    port: obs.destPort ? String(obs.destPort) : "",
    since: "",
    until: "",
    limit: "500",
    flowId: "",
    queueId: "",
    sessionKey: "",
  };
  syncRoute();
  await loadAndPaint(root);
}

function captureObservation(obs) {
  captureFlow(flowFromObservation(obs));
}

function explainFlow(f) {
  openTroubleshootInvestigation(f, { intent: "explain" });
}

function captureFlow(f) {
  openTroubleshootInvestigation(f, { intent: "capture" });
}

function flowDetail(f) {
  state.flowId = f.flowId || "";
  state.queueId = "";
  state.sessionKey = "";
  syncRoute();
  const totalBytes = flowTotalBytes(f);
  const packageProvenance = appIdPackageProvenanceFromEvidence(f.appEvidence || f.app_evidence || []);
  openDrawer({
    title: "Flow detail",
    subtitle: `${fmt.endpoint(f.srcIp, f.srcPort)} → ${fmt.endpoint(f.destIp, f.destPort)}`,
    width: "600px",
    onClose: clearTrafficSelection,
    body: h("div", {},
      h("div", { class: "flex wrap", style: { marginBottom: "16px" } },
        pill(appLabel(f).toUpperCase(), f.appId === "unknown" ? "warn" : "info"),
        f.appCategory ? h("span", { class: "tag" }, f.appCategory) : null,
        f.appConfidence ? h("span", { class: "tag" }, f.appConfidence + "% confidence") : null,
        f.protocol ? h("span", { class: "tag" }, f.protocol) : null),
      h("dl", { class: "kv" },
        kv("Source", fmt.endpoint(f.srcIp, f.srcPort)),
        kv("Destination", fmt.endpoint(f.destIp, f.destPort)),
        kv("Protocol", f.protocol || "—"),
        kv("Flow ID", f.flowId || "—"),
        kv("App-ID", f.appId || "—"),
        kv("App name", f.appName || "—"),
        kv("Engine signal", f.appProtocol || "—"),
        kv("Package provenance", packageProvenance.label || "—"),
        kv("Package version", packageProvenance.version || "—"),
        kv("Package manifest", packageProvenance.manifestShort ? `sha256:${packageProvenance.manifestShort}` : "—"),
        kv("Event policy", eventPolicyLabel(f)),
        kv("Event policy freshness", eventPolicyFreshness(f)),
        kv("Bytes", `${fmt.bytes(totalBytes)} (${fmt.bytes(f.bytesToServer)} to server / ${fmt.bytes(f.bytesToClient)} to client)`),
        kv("Packets", fmt.compactNum(fmt.num(f.packets))),
        kv("Last seen", fmt.absTime(f.time))),
      f.appEvidence?.length ? h("div", {},
        h("h3", { style: { marginTop: "16px" } }, "App-ID evidence"),
        h("ul", { class: "trace-list" }, f.appEvidence.map((e) => h("li", {}, e)))) : null,
      captureEvidencePanel(f),
      appIdEvidenceBridgePanel(f, { kind: "flow" }),
      handoffActions(trafficWorkflowPacket(
        flowHandoffPacket(f, { route: currentRoute(), currentInspectionPosture: inspectionPostureSummary(runtimeStatus) }),
        trafficCaptureRegressionWorkflow(f, { kind: "flow", caseAction: "flow-capture-regression" }),
      ))),
    footer: [
      drawerButton({ className: "btn ghost", action: "close-flow", title: "Close flow detail drawer", dataset: { trafficAction: "close-flow" }, onclick: closeDrawer, label: "Close" }),
      f.flowId ? drawerLink({ action: "related-threats", title: "Open related threats for this flow", dataset: { trafficAction: "related-threats" }, href: relatedThreatsHash(f), onclick: closeDrawer, iconName: "threats", label: "Related threats" }) : null,
      drawerButton({ action: "explain-flow-drawer", title: "Explain this flow in Troubleshoot", dataset: { trafficAction: "explain-flow-drawer" }, onclick: () => { closeDrawer(); explainFlow(f); }, iconName: "search", label: "Explain" }),
      drawerButton({ action: "capture-flow-drawer", title: "Plan packet capture for this flow", dataset: { trafficAction: "capture-flow-drawer" }, onclick: () => { closeDrawer(); captureFlow(f); }, iconName: "download", label: "Capture" }),
      drawerLink({ action: "capture-audit", title: "Open capture audit for this flow", dataset: { trafficAction: "capture-audit" }, href: captureAuditHash(f), onclick: closeDrawer, iconName: "clock", label: "Capture audit" }),
      drawerButton({ action: "custom-app-flow-drawer", title: "Stage custom App-ID from this flow", dataset: { trafficAction: "custom-app-flow-drawer" }, onclick: () => { closeDrawer(); customAppFromFlow(f); }, iconName: "objects", label: "App-ID" }),
      drawerButton({ className: "btn primary", action: "allow-flow-drawer", title: "Stage allow rule from this flow", dataset: { trafficAction: "allow-flow-drawer" }, onclick: () => { closeDrawer(); ruleFromFlow(f, "ACTION_ALLOW"); }, iconName: "check", label: "Allow" }),
      drawerButton({ className: "btn danger", action: "drop-flow-drawer", title: "Stage drop rule from this flow", dataset: { trafficAction: "drop-flow-drawer" }, onclick: () => { closeDrawer(); ruleFromFlow(f, "ACTION_DENY"); }, iconName: "block", label: "Drop" }),
    ],
  });
}

function sessionDetail(s) {
  const key = sessionKey(s);
  state.flowId = "";
  state.queueId = "";
  state.sessionKey = key;
  syncRoute();
  const f = flowFromSession(s);
  openDrawer({
    title: "Session detail",
    subtitle: `${fmt.endpoint(s.srcIp, s.srcPort)} → ${fmt.endpoint(s.destIp, s.destPort)}`,
    width: "640px",
    onClose: clearTrafficSelection,
    body: h("div", {},
      h("div", { class: "flex wrap", style: { marginBottom: "16px" } },
        s.protocol ? h("span", { class: "tag" }, s.protocol) : null,
        s.state ? pill(s.state, sessionStateClass(s.state)) : null,
        ...sessionFlags(s).map((flag) => h("span", { class: "tag" }, flag))),
      h("dl", { class: "kv" },
        kv("Family", s.family || "—"),
        kv("Protocol", s.protocol || "—"),
        kv("State", s.state || "—"),
        kv("Session key", key || "—"),
        kv("Original", `${fmt.endpoint(s.srcIp, s.srcPort)} → ${fmt.endpoint(s.destIp, s.destPort)}`),
        kv("Reply", `${fmt.endpoint(s.replySrcIp, s.replySrcPort)} → ${fmt.endpoint(s.replyDestIp, s.replyDestPort)}`),
        kv("Bytes", fmt.bytes(s.bytes)),
        kv("Packets", fmt.compactNum(fmt.num(s.packets))),
        kv("Timeout", s.timeoutSeconds ? `${s.timeoutSeconds}s` : "—")),
      captureEvidencePanel(f),
      h("h3", { style: { marginTop: "18px" } }, "Raw conntrack record"),
      h("pre", { class: "mono", style: {
        whiteSpace: "pre-wrap",
        overflowWrap: "anywhere",
        background: "var(--panel-2)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius)",
        padding: "12px",
      } }, s.raw || "—"),
      handoffActions(trafficWorkflowPacket(sessionHandoffPacket(s, {
        route: currentRoute(),
        sessionKey: key,
        currentInspectionPosture: inspectionPostureSummary(runtimeStatus),
      }), trafficCaptureRegressionWorkflow(f, { kind: "flow", caseAction: "session-capture-regression" })))),
    footer: [
      drawerButton({ className: "btn ghost", action: "close-session", title: "Close session detail drawer", dataset: { trafficAction: "close-session" }, onclick: closeDrawer, label: "Close" }),
      drawerButton({ action: "explain-session-drawer", title: "Explain this session tuple in Troubleshoot", dataset: { trafficAction: "explain-session-drawer" }, onclick: () => { closeDrawer(); explainFlow(f); }, iconName: "search", label: "Explain" }),
      drawerButton({ action: "capture-session-drawer", title: "Plan packet capture for this session tuple", dataset: { trafficAction: "capture-session-drawer" }, onclick: () => { closeDrawer(); captureFlow(f); }, iconName: "download", label: "Capture" }),
      drawerLink({ action: "capture-audit-session", title: "Open capture audit for this session tuple", dataset: { trafficAction: "capture-audit-session" }, href: captureAuditHash(f), onclick: closeDrawer, iconName: "clock", label: "Capture audit" }),
      drawerButton({ action: "custom-app-session-drawer", title: "Stage custom App-ID from this session", dataset: { trafficAction: "custom-app-session-drawer" }, onclick: () => { closeDrawer(); customAppFromFlow(f); }, iconName: "objects", label: "App-ID" }),
      drawerButton({ className: "btn primary", action: "allow-session-drawer", title: "Stage allow rule from this session", dataset: { trafficAction: "allow-session-drawer" }, onclick: () => { closeDrawer(); ruleFromFlow(f, "ACTION_ALLOW"); }, iconName: "check", label: "Allow" }),
      drawerButton({ className: "btn danger", action: "drop-session-drawer", title: "Stage drop rule from this session", dataset: { trafficAction: "drop-session-drawer" }, onclick: () => { closeDrawer(); ruleFromFlow(f, "ACTION_DENY"); }, iconName: "block", label: "Drop" }),
    ],
  });
}

function kv(k, v) { return [h("dt", {}, k), h("dd", { class: "mono" }, v)]; }

function handoffActions(packet) {
  return h("div", { class: "flex wrap", style: { marginTop: "16px" } },
    drawerButton({ action: "pin-handoff", title: "Pin traffic evidence handoff to investigation case", dataset: { trafficHandoffAction: "pin" }, onclick: () => pinHandoff(packet), iconName: "inbox", label: "Pin to case" }),
    drawerButton({ action: "copy-handoff", title: "Copy traffic evidence handoff", dataset: { trafficHandoffAction: "copy" }, onclick: () => copyHandoff(packet), iconName: "copy", label: "Copy handoff" }),
    drawerButton({ action: "export-handoff", title: "Export traffic evidence handoff JSON", dataset: { trafficHandoffAction: "export" }, onclick: () => exportHandoff(packet), iconName: "download", label: "Export JSON" }));
}

export function trafficCaptureRegressionWorkflow(flow = {}, opts = {}) {
  const bridge = appIdEvidenceBridgePlan(flow, opts);
  return {
    custodyBoundary: "browser-local handoff only; no capture execution, corpus custody, policy mutation, or server-side case record is created here",
    caseAction: opts.caseAction || (bridge.kind === "observation" ? "app-id-capture-regression" : "flow-capture-regression"),
    captureRoute: bridge.captureHref,
    captureFilter: bridge.captureFilter,
    captureLimits: bridge.captureLimits,
    captureWarnings: bridge.captureWarnings,
    queueRoute: bridge.queueHref || "",
    corpusRoute: bridge.corpusHref || "",
    regressionAction: bridge.regressionStep,
    candidateBoundary: bridge.candidateBoundary,
  };
}

export function trafficCaseFocusRoute(packet = {}, action = "flow-capture-regression") {
  const key = caseItemKey(packet);
  const q = new URLSearchParams();
  q.set("caseKey", key);
  q.set("caseAction", action);
  q.set("caseKind", packet.kind || "traffic");
  return "#/investigation?" + q.toString();
}

export function trafficWorkflowPacket(packet = {}, workflow = {}) {
  const caseFocusRoute = trafficCaseFocusRoute(packet, workflow.caseAction || "flow-capture-regression");
  const handoff = {
    ...workflow,
    caseFocusRoute,
  };
  return {
    ...packet,
    summary: {
      ...(packet.summary || {}),
      operatorWorkflow: {
        captureRoute: workflow.captureRoute || "",
        queueRoute: workflow.queueRoute || "",
        corpusRoute: workflow.corpusRoute || "",
        caseFocusRoute,
        custodyBoundary: workflow.custodyBoundary || "",
      },
    },
    evidence: [
      ...((packet.evidence || []).filter(Boolean)),
      workflow.captureRoute ? `capture_route=${workflow.captureRoute}` : "",
      workflow.queueRoute ? `app_id_queue_route=${workflow.queueRoute}` : "",
      workflow.corpusRoute ? `corpus_review_route=${workflow.corpusRoute}` : "",
      `case_focus_route=${caseFocusRoute}`,
      "workflow_boundary=browser-local handoff; explicit Troubleshoot capture and candidate review remain required",
    ].filter(Boolean),
    artifacts: {
      ...(packet.artifacts || {}),
      operatorWorkflow: handoff,
    },
  };
}

async function pinHandoff(packet) {
  const activeCaseId = activeInvestigationServerCaseId();
  if (activeCaseId) {
    try {
      await api.addInvestigationCaseEvidence(activeCaseId, [caseEvidencePayloadFromPacket(packet)]);
      toast("Evidence appended", `Traffic evidence appended to ${activeCaseId}.`, "ok");
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
    toast("Handoff copied", "Selected traffic evidence copied as plain text.", "ok");
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
  toast("Handoff exported", "Downloaded selected traffic evidence as JSON.", "ok");
}

function currentRoute() {
  return location.hash || "#/traffic";
}

// Pivot: create address + service objects for this flow/session tuple, then
// open a prefilled allow or drop rule for review.
async function ruleFromFlow(f, action = "ACTION_ALLOW") {
  try {
    await session.load();
    const plan = buildFlowRulePlan(session.draft, f, action);
    openRuleEditorPrefilled(plan.rule, action === "ACTION_DENY" ? 0 : undefined, {
      beforeSave: plan.beforeSave,
      caseContext: state.caseKey ? {
        caseKey: state.caseKey,
        caseAction: state.caseAction,
        caseKind: state.caseKind,
        sourceWorkspace: "traffic",
        mode: action === "ACTION_DENY" ? "drop-flow" : "allow-flow",
        source: {
          flowId: f.flowId || "",
          srcIp: f.srcIp || "",
          srcPort: f.srcPort || "",
          destIp: f.destIp || "",
          destPort: f.destPort || "",
          protocol: f.protocol || "",
          appId: f.appId || "",
        },
      } : null,
    });
  } catch (e) { toast("Failed", e.message, "bad"); }
}

async function customAppFromFlow(f) {
  try {
    await session.load();
    openCustomAppDrawer(f);
  } catch (e) { toast("Failed", e.message, "bad"); }
}

function openCustomAppDrawer(f, preferredSuggestion = null, initialMode = "", opts = {}) {
  const observation = opts.observation?.queueId ? opts.observation : null;
  const suggestion = normalizeSuggestedApplication(preferredSuggestion) || suggestedApplication(f, session.draft);
  const name = inp(suggestion.name, "corp-admin");
  const displayName = inp(suggestion.displayName, "Corporate Admin");
  const category = inp(suggestion.category, "business-app");
  const signals = inp(suggestion.engineSignals.join(", "), "corp-admin, custom-proto");
  const tcpPorts = inp(suggestion.tcpPorts, "8443, 9443-9445");
  const udpPorts = inp(suggestion.udpPorts, "5353");
  const desc = h("textarea", { class: "input", placeholder: "Why this App-ID exists" }, suggestion.description);
  const auditReason = observation
    ? h("textarea", { class: "input", placeholder: "Audit reason for candidate staging" }, appIdObservationPromotionReason(observation))
    : null;

  const body = h("div", {},
    h("div", { class: "flex wrap", style: { marginBottom: "12px" } },
      pill(appLabel(f).toUpperCase(), f.appId === "unknown" ? "warn" : "info"),
      f.appProtocol ? h("span", { class: "tag" }, "signal " + f.appProtocol) : null,
      f.protocol ? h("span", { class: "tag" }, f.protocol) : null,
      f.destPort ? h("span", { class: "tag" }, "port " + f.destPort) : null),
    field("App-ID", name),
    field("Display name", displayName),
    field("Category", category),
    field("Engine signals", signals, "exact observed aliases; optional"),
    field("TCP ports", tcpPorts, "fallback hint only"),
    field("UDP ports", udpPorts, "fallback hint only"),
    field("Description", desc),
    auditReason ? field("Audit reason", auditReason, "recorded with the candidate staging event") : null);

  const save = async (mode = "save") => {
    const app = buildApplication(name, displayName, category, signals, tcpPorts, udpPorts, desc);
    if (!app) return;
    if (mode === "review-block") {
      reviewAppDropRule(f, app);
      return;
    }
    if (mode === "block" && !appMatchesFlowPort(app, f)) {
      toast("Port hint required", "One-click Save & drop uses the server queue promotion path and still requires a TCP/UDP port hint. Use Review drop rule for supported signal-only App-ID denies.", "warn");
      return;
    }
    try {
      if (observation) {
        const req = observationRequest();
        const response = await api.stageAppIdObservation(observation.queueId, appIdObservationStageBody(observation, app, mode, {
          reason: val(auditReason),
          flowLimit: req.flowLimit,
          confidenceThreshold: req.confidenceThreshold,
          since: req.since,
          until: req.until,
        }));
        if (response.validation?.valid === false) {
          toast("Candidate validation failed", validationFailureSummary(response.validation), "bad");
          return;
        }
        await session.load();
        closeDrawer();
        const stagedApp = response.application?.name || app.name;
        if (mode === "block") {
          const ruleName = response.rule?.name || "candidate drop rule";
          pinAppIdCaseRemediation(f, app, mode, { response, ruleName, observation });
          toast("App-ID drop staged", `${stagedApp} and ${ruleName} are in the candidate. Validate and commit to enforce.`, "ok");
          return;
        }
        pinAppIdCaseRemediation(f, app, mode, { response, observation });
        toast("App-ID staged", `${stagedApp} is in the candidate. Validate and commit to use it for classification.`, "ok");
        if (mode === "view") location.hash = "#/objects?tab=applications";
        return;
      }
      const duplicate = (session.draft.applications || []).find((a) => a.name === app.name);
      if (duplicate) {
        toast("Duplicate App-ID", `${app.name} already exists in the candidate.`, "warn");
        return;
      }
      let ruleName = "";
      await session.apply((d) => {
        (d.applications ||= []).push(app);
        if (mode === "block") {
          const rule = buildAppDropRule(d, f, app);
          ruleName = rule.name;
          (d.rules ||= []).splice(0, 0, rule);
        }
      });
      closeDrawer();
      if (mode === "block") {
        pinAppIdCaseRemediation(f, app, mode, { ruleName });
        toast("App-ID drop staged", `${app.name} and ${ruleName} are in the candidate. Validate and commit to enforce.`, "ok");
        return;
      }
      pinAppIdCaseRemediation(f, app, mode, {});
      toast("App-ID staged", `${app.name} is in the candidate. Validate and commit to use it for classification.`, "ok");
      if (mode === "view") location.hash = "#/objects?tab=applications";
    } catch (e) {
      toast("Could not stage App-ID", e.message, "bad");
    }
  };

  openDrawer({
    title: "Custom App-ID",
    subtitle: "Stages an application object to the candidate.",
    width: "560px",
    body,
    footer: [
      drawerButton({ className: "btn ghost", action: "cancel-custom-app", title: "Cancel custom App-ID staging", dataset: { appidAction: "cancel-custom-app" }, onclick: closeDrawer, label: "Cancel" }),
      drawerButton({ action: "save-custom-app-view", title: "Save custom App-ID and open Objects", dataset: { appidAction: "save-view" }, onclick: () => save("view"), iconName: "objects", label: "Save & view" }),
      drawerButton({ action: "review-custom-app-drop", title: "Review candidate drop rule for this App-ID", dataset: { appidAction: "review-drop" }, onclick: () => save("review-block"), iconName: "rules", label: "Review drop rule" }),
      drawerButton({ action: "save-custom-app-drop", title: "Save custom App-ID and stage candidate drop rule", dataset: { appidAction: "save-drop" }, onclick: () => save("block"), iconName: "block", label: "Save & drop" }),
      drawerButton({ className: "btn primary", action: "save-custom-app", title: "Save custom App-ID to candidate", dataset: { appidAction: "save" }, onclick: () => save("save"), iconName: "check", label: "Save" }),
    ],
  });
  if (initialMode === "block") {
    setTimeout(() => {
      const buttons = Array.from(document.querySelectorAll(".drawer-foot .btn"));
      const blockButton = buttons.find((btn) => btn.textContent.trim() === "Save & drop");
      blockButton?.focus();
    }, 0);
  }
}

function reviewAppDropRule(f, app) {
  if (!appMatchesFlowPort(app, f) && !appSupportsSignalOnlyDrop(app)) {
    toast("Enforcement evidence required", "Add a TCP/UDP port hint or a supported Suricata signal (dns, http, ssh, tls) before reviewing the drop rule.", "warn");
    return;
  }
  const existing = (session.draft.applications || []).find((candidate) => candidate.name === app.name);
  const reviewedApp = existing || app;
  const plan = buildAppDropRulePlan(session.draft || {}, f, reviewedApp);
  closeDrawer();
  openRuleEditorPrefilled(plan.rule, 0, {
    beforeSave: plan.beforeSave,
    pendingApplications: existing ? [] : [app],
    caseContext: state.caseKey ? {
      caseKey: state.caseKey,
      caseAction: state.caseAction,
      caseKind: state.caseKind,
      sourceWorkspace: "traffic",
      mode: "define-and-drop",
      source: {
        flowId: f.flowId || "",
        srcIp: f.srcIp || "",
        srcPort: f.srcPort || "",
        destIp: f.destIp || "",
        destPort: f.destPort || "",
        protocol: f.protocol || "",
        appId: reviewedApp.name || "",
      },
    } : null,
  });
  toast("Review App-ID drop rule", appSupportsSignalOnlyDrop(reviewedApp)
    ? `${reviewedApp.name} will use the bounded Suricata signal-only review path; IDS/IPS Prevent fail-closed remains required before staging.`
    : `${reviewedApp.name} will use current v1 TCP/UDP port-hint enforcement.`, "info");
}

function pinAppIdCaseRemediation(f = {}, app = {}, mode = "save", { response = null, ruleName = "", observation = null } = {}) {
  if (!state.caseKey) return;
  try {
    pinInvestigationPacket(appIdCaseRemediationPacket(f, app, mode, { response, ruleName, observation }));
  } catch (e) {
    toast("Case custody pin failed", e.message || "The App-ID change was staged, but custody evidence could not be pinned.", "warn");
  }
}

function appIdCaseRemediationPacket(f = {}, app = {}, mode = "save", { response = null, ruleName = "", observation = null } = {}) {
  const candidate = response?.candidateStatus || response?.candidate_status || session.candidateStatus || {};
  const changeCount = Number(candidate.changeCount || candidate.change_count || session.serverChangeCount?.() || 0) || 0;
  const dirty = Boolean(candidate.dirty ?? candidate.hasCandidate ?? candidate.has_candidate ?? changeCount > 0);
  const stagedApp = response?.application?.name || app.name || "";
  const stagedRule = response?.rule?.name || ruleName || "";
  return buildInvestigationPacket({
    kind: "candidate-remediation",
    title: mode === "block" ? "Candidate App-ID drop staged" : "Candidate App-ID staged",
    subject: {
      id: stagedRule || stagedApp || state.caseKey,
      label: mode === "block" ? "App-ID and drop rule staged from case" : "App-ID staged from case",
      tuple: {
        flowId: f.flowId || observation?.sampleFlowId || "",
        srcIp: f.srcIp || observation?.sampleSrcIp || "",
        srcPort: f.srcPort || observation?.sampleSrcPort || observation?.sample_src_port || "",
        destIp: f.destIp || observation?.sampleDestIp || "",
        destPort: f.destPort || observation?.destPort || "",
        protocol: f.protocol || observation?.protocol || "",
        appId: stagedApp,
      },
    },
    summary: {
      caseKey: state.caseKey,
      caseAction: state.caseAction,
      caseKind: state.caseKind,
      applicationName: stagedApp,
      ruleName: stagedRule,
      mode: mode === "block" ? "define-and-drop" : "define-only",
      queueId: observation?.queueId || "",
      candidateDirty: dirty,
      candidateChangeCount: changeCount,
      changesRoute: "#/changes?tab=candidate",
    },
    evidence: [
      "candidate App-ID remediation staged from investigation case handoff",
      `case key: ${state.caseKey}`,
      stagedApp ? `application: ${stagedApp}` : "",
      stagedRule ? `rule: ${stagedRule}` : "",
      observation?.queueId ? `observation queue: ${observation.queueId}` : "",
      `mode: ${mode === "block" ? "define-and-drop" : "define-only"}`,
      `candidate changes: ${changeCount}`,
      "review in Changes before commit",
    ],
    artifacts: {
      caseContext: {
        caseKey: state.caseKey,
        caseAction: state.caseAction,
        caseKind: state.caseKind,
      },
      flow: f,
      observation: observation || {},
      application: app,
      stageResult: response || {},
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

export function appIdObservationStageBody(obs = {}, app = {}, mode = "save", opts = {}) {
  const reason = String(opts.reason || app.description || appIdObservationPromotionReason(obs)).trim();
  const flowLimit = numberOrZero(opts.flowLimit);
  const confidenceThreshold = numberOrZero(opts.confidenceThreshold);
  const body = {
    mode: mode === "block"
      ? "APP_ID_OBSERVATION_STAGE_MODE_DEFINE_AND_DROP"
      : "APP_ID_OBSERVATION_STAGE_MODE_DEFINE_ONLY",
    reason: reason || appIdObservationPromotionReason(obs),
    confirmDrop: mode === "block",
    applicationOverride: app,
  };
  if (flowLimit) body.flowLimit = flowLimit;
  if (confidenceThreshold) body.confidenceThreshold = confidenceThreshold;
  if (opts.since) body.since = opts.since;
  if (opts.until) body.until = opts.until;
  return body;
}

function appIdObservationPromotionReason(obs = {}) {
  return `Promote App-ID observation ${obs.queueId || "from reviewed traffic evidence"}`;
}

function validationFailureSummary(validation = {}) {
  const errors = Array.isArray(validation.errors) ? validation.errors.filter(Boolean) : [];
  if (errors.length) return errors.slice(0, 2).join("; ");
  const findings = Array.isArray(validation.findings) ? validation.findings : [];
  const labels = findings.map((finding) => finding?.message || finding?.summary || finding?.code || finding?.field).filter(Boolean);
  if (labels.length) return labels.slice(0, 2).join("; ");
  return "Server validation rejected the staged candidate.";
}

function maybeOpenSelection(root, data = {}) {
  if (state.mode === "flows" && state.flowId) {
    const f = (data.flows || []).find((flow) => flow.flowId === state.flowId);
    const key = "flow:" + state.flowId;
    if (f && key !== lastOpenedSelection) {
      lastOpenedSelection = key;
      setTimeout(() => flowDetail(f), 0);
    }
  } else if (state.mode === "app-id" && state.queueId) {
    const obs = (data.observations || []).find((item) => item.queueId === state.queueId);
    const key = "queue:" + state.queueId;
    if (obs && key !== lastOpenedSelection) {
      lastOpenedSelection = key;
      setTimeout(() => observationDetail(root, obs, data.appIdReadiness || null), 0);
    }
  } else if (state.mode === "sessions" && state.sessionKey) {
    const s = (data.sessions || []).find((item) => sessionKey(item) === state.sessionKey);
    const key = "session:" + state.sessionKey;
    if (s && key !== lastOpenedSelection) {
      lastOpenedSelection = key;
      setTimeout(() => sessionDetail(s), 0);
    }
  }
}

function clearTrafficSelection() {
  state.flowId = "";
  state.queueId = "";
  state.sessionKey = "";
  syncRoute();
}

function syncRoute() {
  state = normalizeTrafficState(state);
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
    title: "Previous traffic results page",
    "aria-label": "Previous traffic results page",
    dataset: { telemetryPaginationAction: "previous", telemetryPagination: state.mode },
    disabled: stack.length === 0,
    onclick: async () => {
      const previousCursor = stack[stack.length - 1] || "";
      const nextStack = stack.slice(0, -1);
      setPageCursor(previousCursor === "0" ? "" : previousCursor, nextStack);
      clearTrafficSelection();
      syncRoute();
      await loadAndPaint(root);
    },
  }, "Prev");
  const next = h("button", {
    class: "btn sm",
    type: "button",
    title: "Next traffic results page",
    "aria-label": "Next traffic results page",
    dataset: { telemetryPaginationAction: "next", telemetryPagination: state.mode },
    disabled: !data.hasMore || !data.nextCursor,
    onclick: async () => {
      const nextStack = [...stack, current || "0"];
      setPageCursor(data.nextCursor, nextStack);
      clearTrafficSelection();
      syncRoute();
      await loadAndPaint(root);
    },
  }, "Next");
  return h("div", { class: "seg", dataset: { telemetryPagination: state.mode } }, prev, next);
}

function pageSummary(count, data = {}, label = "matching item") {
  const total = Number(data.totalMatches || 0);
  const start = Number(state.pageCursor || 0) + (count ? 1 : 0);
  const end = Number(state.pageCursor || 0) + count;
  const plural = total === 1 ? label : `${label}s`;
  if (total > 0) return `${start}-${end} of ${total} ${plural}`;
  return `${count} ${count === 1 ? label : `${label}s`}`;
}

export function normalizeTrafficState(next = {}) {
  const mode = ["sessions", "flows", "app-id"].includes(next.mode) ? next.mode : "flows";
  const normalized = { ...DEFAULT_STATE, ...next, mode };
  if (!["", "TCP", "UDP", "ICMP"].includes(normalized.protocol)) normalized.protocol = "";
  normalized.port = validSinglePortText(normalized.port);
  normalized.sessionKey = normalizeSessionKeyText(normalized.sessionKey);
  normalized.sessionState = ["", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT", "TIME_WAIT", "CLOSE", "UNREPLIED"].includes(normalized.sessionState) ? normalized.sessionState : "";
  normalized.observationKind = ["", "APP_ID_OBSERVATION_KIND_UNKNOWN", "APP_ID_OBSERVATION_KIND_LOW_CONFIDENCE", "APP_ID_OBSERVATION_KIND_CONFLICTING_EVIDENCE"].includes(normalized.observationKind) ? normalized.observationKind : "";
  normalized.confidenceThreshold = clampNumberText(normalized.confidenceThreshold, 1, 100, "70");
  if (normalized.mode === "app-id" && !["50", "100", "250"].includes(normalized.limit)) normalized.limit = "100";
  if (normalized.mode !== "app-id" && !["100", "500", "1000"].includes(normalized.limit)) normalized.limit = "500";
  normalized.pageCursor = normalizePageCursor(normalized.pageCursor);
  normalized.pageStack = String(normalized.pageStack || "").split(",").map((item) => normalizePageCursor(item)).filter(Boolean).slice(-20).join(",");
  normalized.flowId = normalizeEventFlowID(normalized.flowId);
  normalized.caseKey = normalizeCaseRouteToken(normalized.caseKey, 320);
  normalized.caseAction = normalizeCaseRouteToken(normalized.caseAction, 80);
  normalized.caseKind = normalizeCaseRouteToken(normalized.caseKind, 80);
  if (normalized.mode !== "flows") normalized.flowId = "";
  if (normalized.mode !== "app-id") normalized.queueId = "";
  if (normalized.mode !== "sessions") normalized.sessionKey = "";
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

function relatedThreatsHash(f = {}) {
  const q = new URLSearchParams();
  q.set("flowId", f.flowId);
  q.set("limit", "100");
  return "#/threats?" + q.toString();
}

function normalizeEventFlowID(value) {
  const text = String(value || "").trim();
  if (!text || text.length > 128 || /[\u0000-\u001f\u007f]/.test(text)) return "";
  return text;
}

function uniqueText(values = []) {
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

function validSinglePortText(value) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 65535) return "";
  return String(n);
}

function clampNumberText(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return String(Math.min(max, Math.max(min, Math.trunc(n))));
}

function normalizeSessionKeyText(value) {
  const text = String(value || "").trim();
  if (!text || text.length > 512 || /[\u0000-\u001f\u007f]/.test(text)) return "";
  const parts = text.split("|");
  if (parts.length !== 11 || stableKeyPart(parts[0]) !== "ct1") return "";
  const normalized = [
    "ct1",
    stableKeyPart(parts[1]),
    stableKeyPart(parts[2]),
    stableKeyPart(parts[3]),
    stablePortPart(parts[4]),
    stableKeyPart(parts[5]),
    stablePortPart(parts[6]),
    stableKeyPart(parts[7]),
    stablePortPart(parts[8]),
    stableKeyPart(parts[9]),
    stablePortPart(parts[10]),
  ];
  if (!normalized[1] || !normalized[2] || !normalized[3] || !normalized[5]) return "";
  for (const index of [4, 6, 8, 10]) {
    if (String(parts[index] ?? "").trim() && !normalized[index]) return "";
  }
  return normalized.join("|");
}

function normalizeSuggestedApplication(app) {
  if (!app?.name) return null;
  return {
    name: app.name,
    displayName: app.displayName || titleFromName(app.name),
    category: app.category || "business-app",
    engineSignals: app.engineSignals || [],
    tcpPorts: appPortsText(app, "PROTOCOL_TCP"),
    udpPorts: appPortsText(app, "PROTOCOL_UDP"),
    description: app.description || "Created from App-ID observation evidence.",
  };
}

function appPortsText(app, proto) {
  return (app.ports || [])
    .filter((hint) => hint.protocol === proto)
    .flatMap((hint) => hint.ports || [])
    .map((port) => port.end ? `${port.start}-${port.end}` : String(port.start))
    .join(", ");
}

function buildApplication(name, displayName, category, signals, tcpPorts, udpPorts, desc) {
  const app = {
    name: val(name),
    displayName: val(displayName),
    category: val(category),
    engineSignals: csvList(val(signals)),
    ports: appPortHints(val(tcpPorts), val(udpPorts)),
    description: val(desc),
  };
  if (!validObjectName(app.name)) {
    toast("Invalid App-ID", "Use lowercase letters, numbers, hyphen, or underscore; start and end with a letter or number.", "warn");
    return null;
  }
  if (!validObjectName(app.category)) {
    toast("Invalid category", "Use lowercase letters, numbers, hyphen, or underscore; start and end with a letter or number.", "warn");
    return null;
  }
  const badSignal = app.engineSignals.find((signal) => !validAppSignal(signal));
  if (badSignal) {
    toast("Invalid engine signal", `${badSignal} is not a valid lowercase app signal.`, "warn");
    return null;
  }
  if (new Set(app.engineSignals).size !== app.engineSignals.length) {
    toast("Duplicate engine signal", "Each engine signal can appear only once in an App-ID definition.", "warn");
    return null;
  }
  if (!validPortText(val(tcpPorts)) || !validPortText(val(udpPorts))) {
    toast("Invalid ports", "Use ports or ranges from 1-65535, with range ends greater than starts.", "warn");
    return null;
  }
  if (!validAppPorts(app.ports)) {
    toast("Invalid ports", "Use ports or ranges from 1-65535, with range ends greater than starts.", "warn");
    return null;
  }
  if (!app.engineSignals.length && !app.ports.length) {
    toast("Match evidence required", "Add at least one engine signal or TCP/UDP port hint.", "warn");
    return null;
  }
  return app;
}

function suggestedApplication(f, policy = {}) {
  const proto = protocolEnum(f.protocol);
  const port = numberOrZero(f.destPort);
  const signal = usefulCustomSignal(f);
  const base = signal || (port ? `app-${port}` : "custom-app");
  const name = uniqueAppName(policy.applications || [], sanitizeObjectName(base));
  return {
    name,
    displayName: titleFromName(name),
    category: "business-app",
    engineSignals: signal ? [signal] : [],
    tcpPorts: proto === "PROTOCOL_TCP" && port ? String(port) : "",
    udpPorts: proto === "PROTOCOL_UDP" && port ? String(port) : "",
    description: `Created from observed ${protocolLabel(f.protocol)} traffic ${fmt.endpoint(f.srcIp, f.srcPort)} to ${fmt.endpoint(f.destIp, f.destPort)}.`,
  };
}

function usefulCustomSignal(f) {
  const signal = normalizeSignal(f.appProtocol);
  if (!signal || BUILTIN_ENGINE_SIGNALS.has(signal)) return "";
  const id = normalizeSignal(f.appId);
  const evidence = (f.appEvidence || []).join(" ").toLowerCase();
  if (id === "unknown" || evidence.includes("no openngfw taxonomy match")) return signal;
  return "";
}

const BUILTIN_ENGINE_SIGNALS = new Set([
  "unknown", "failed", "conntrack", "http", "tls", "ssl", "quic", "dns", "ssh", "ntp", "dhcp",
  "smtp", "imap", "pop3", "ftp", "smb", "rdp", "bittorrent",
]);

function protocolEnum(protocol) {
  const p = String(protocol || "").toUpperCase();
  if (p === "TCP" || p === "UDP" || p === "ICMP") return "PROTOCOL_" + p;
  if (p === "PROTOCOL_TCP" || p === "PROTOCOL_UDP" || p === "PROTOCOL_ICMP") return p;
  return "";
}

function protocolLabel(protocol) {
  return String(protocol || "traffic").toUpperCase().replace(/^PROTOCOL_/, "");
}

function sanitizeObjectName(value) {
  let out = String(value || "custom-app").toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
  if (!out) out = "custom-app";
  if (!/^[a-z0-9]/.test(out)) out = "app-" + out;
  out = out.slice(0, 63).replace(/[-_]+$/g, "");
  if (!/[a-z0-9]$/.test(out)) out += "1";
  return out || "custom-app";
}

function uniqueAppName(apps, base) {
  const names = new Set(apps.map((a) => a.name));
  if (!names.has(base)) return base;
  let i = 2;
  while (true) {
    const suffix = "-" + i;
    const candidate = sanitizeObjectName(base.slice(0, 63 - suffix.length) + suffix);
    if (!names.has(candidate)) return candidate;
    i++;
  }
}

function titleFromName(name) {
  return String(name || "Custom App").split(/[-_]+/).filter(Boolean).map((part) =>
    part ? part[0].toUpperCase() + part.slice(1) : part).join(" ");
}

function normalizeSignal(value) {
  return String(value || "").trim().toLowerCase();
}

function validObjectName(value) {
  return /^[a-z0-9]([a-z0-9_-]{0,62}[a-z0-9])?$/.test(value);
}

function validAppSignal(value) {
  return /^[a-z0-9][a-z0-9_.-]{0,127}$/.test(value);
}

function validPortText(value) {
  return String(value || "").split(",").map((x) => x.trim()).filter(Boolean).every((part) => {
    const m = part.match(/^(\d+)(?:-(\d+))?$/);
    if (!m) return false;
    const start = Number(m[1]);
    const end = m[2] ? Number(m[2]) : start;
    return Number.isInteger(start) && Number.isInteger(end) && start >= 1 && end >= start && end <= 65535;
  });
}

function csvList(value) {
  return value.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
}

function appPortHints(tcp, udp) {
  const hints = [];
  const tcpPorts = parsePorts(tcp);
  if (tcpPorts.length) hints.push({ protocol: "PROTOCOL_TCP", ports: tcpPorts });
  const udpPorts = parsePorts(udp);
  if (udpPorts.length) hints.push({ protocol: "PROTOCOL_UDP", ports: udpPorts });
  return hints;
}

function validAppPorts(hints = []) {
  return hints.every((hint) => (hint.protocol === "PROTOCOL_TCP" || hint.protocol === "PROTOCOL_UDP") &&
    (hint.ports || []).length > 0 &&
    hint.ports.every((p) => Number.isInteger(p.start) && p.start >= 1 && p.start <= 65535 &&
      (p.end == null || (Number.isInteger(p.end) && p.end >= p.start && p.end <= 65535))));
}

function appMatchesFlowPort(app, f) {
  const proto = protocolEnum(f.protocol);
  const port = numberOrZero(f.destPort);
  if (!port || (proto !== "PROTOCOL_TCP" && proto !== "PROTOCOL_UDP")) return false;
  return (app.ports || []).some((hint) => hint.protocol === proto &&
    (hint.ports || []).some((p) => portInRange(port, p)));
}

function appSupportsSignalOnlyDrop(app = {}) {
  return !hasEnforceableAppPorts(app) && hasSupportedSuricataAppSignal(app);
}

function hasEnforceableAppPorts(app = {}) {
  return (app.ports || []).some((hint) =>
    (hint.protocol === "PROTOCOL_TCP" || hint.protocol === "PROTOCOL_UDP") &&
    (hint.ports || []).some((p) => {
      const start = Number(p.start);
      const end = Number(p.end || p.start);
      return Number.isInteger(start) && Number.isInteger(end) && start >= 1 && end >= start && end <= 65535;
    }));
}

function hasSupportedSuricataAppSignal(app = {}) {
  const supported = new Set(["dns", "http", "ssh", "tls"]);
  return (app.engineSignals || []).some((signal) => supported.has(normalizeSignal(signal)));
}

function portInRange(port, range = {}) {
  const start = Number(range.start);
  const end = Number(range.end || range.start);
  return Number.isInteger(start) && Number.isInteger(end) && port >= start && port <= end;
}

export function buildAppDropRulePlan(policy = {}, f = {}, app = {}) {
  const signalOnly = appSupportsSignalOnlyDrop(app);
  const srcCidr = ipCidr(f.srcIp);
  const dstCidr = ipCidr(f.destIp);
  const srcAddress = addressDependency(policy, srcCidr, "src-" + clean(f.srcIp));
  const dstAddress = addressDependency(policy, dstCidr, "dst-" + clean(f.destIp));
  const appName = app.name || sanitizeObjectName(appLabel(f));
  const addresses = [srcAddress.object, dstAddress.object].filter(Boolean);
  const applications = app?.name && !(policy.applications || []).some((candidate) => candidate.name === app.name)
    ? [{ ...app, engineSignals: [...(app.engineSignals || [])], ports: cloneApplicationPorts(app.ports || []) }]
    : [];
  return {
    rule: {
      name: uniqueRuleName(policy.rules || [], sanitizeObjectName(`drop-app-${appName}-${clean(f.srcIp)}-to-${clean(f.destIp)}`)),
      fromZones: [],
      toZones: [],
      sourceAddresses: signalOnly ? [] : [srcAddress.name],
      destinationAddresses: signalOnly ? [] : [dstAddress.name],
      services: [],
      applications: [appName],
      action: "ACTION_DENY",
      log: true,
      disabled: false,
      description: signalOnly
        ? `Drop observed App-ID ${appName} with supported Suricata signal enforcement. Requires IDS/IPS Prevent fail-closed before staging.`
        : `Drop observed App-ID ${appName} for ${f.srcIp} → ${fmt.endpoint(f.destIp, f.destPort)} using TCP/UDP port-hint enforcement.`,
    },
    dependencies: { addresses: signalOnly ? [] : addresses, services: [], applications },
    beforeSave: (draft) => {
      if (!signalOnly) stageFlowRuleDependencies(draft, { addresses, services: [] });
      stageApplicationDependencies(draft, applications);
    },
  };
}

function buildAppDropRule(policy, f, app) {
  const plan = buildAppDropRulePlan(policy, f, app);
  plan.beforeSave(policy);
  return plan.rule;
}

function stageApplicationDependencies(draft, applications = []) {
  const existing = new Set((draft.applications || []).map((item) => item?.name).filter(Boolean));
  for (const app of applications || []) {
    if (!app?.name || existing.has(app.name)) continue;
    (draft.applications ||= []).push({ ...app, engineSignals: [...(app.engineSignals || [])], ports: cloneApplicationPorts(app.ports || []) });
    existing.add(app.name);
  }
}

function cloneApplicationPorts(hints = []) {
  return (hints || []).map((hint) => ({
    ...hint,
    ports: (hint.ports || []).map((port) => ({ ...port })),
  }));
}

function uniqueRuleName(rules, base) {
  const names = new Set((rules || []).map((r) => r.name));
  if (!names.has(base)) return base;
  let i = 2;
  while (true) {
    const suffix = "-" + i;
    const candidate = sanitizeObjectName(base.slice(0, 63 - suffix.length) + suffix);
    if (!names.has(candidate)) return candidate;
    i++;
  }
}

function field(label, control, help) {
  return h("label", { class: "field" }, h("span", {}, label, help ? h("span", { class: "help" }, " — " + help) : null), control);
}

function inp(v, ph, attrs = {}) { return h("input", { class: "input", value: v || "", placeholder: ph, ...attrs }); }
function val(el) { return el.value.trim(); }

function appCell(f) {
  const label = appLabel(f);
  const detail = [];
  if (f.appConfidence) detail.push(`${f.appConfidence}%`);
  if (f.appProtocol && f.appProtocol !== f.appId) detail.push(`signal ${f.appProtocol}`);
  return h("div", {},
    pill(label.toUpperCase(), f.appId === "unknown" ? "warn" : "info"),
    detail.length ? h("div", { class: "note" }, detail.join(" · ")) : null);
}

function appLabel(f) {
  return f.appId || f.appProtocol || f.protocol || "unknown";
}

export function observationKindLabel(kind) {
  return String(kind || "").replace(/^APP_ID_OBSERVATION_KIND_/, "").replace(/_/g, " ") || "REVIEW";
}

export function observationKindClass(kind) {
  const v = String(kind || "");
  if (v.includes("CONFLICTING")) return "bad";
  if (v.includes("UNKNOWN") || v.includes("LOW_CONFIDENCE")) return "warn";
  return "info";
}

export function appIdObservationDecision(obs = {}, readinessContext = null) {
  const kind = String(obs.kind || "");
  const confidence = Number(obs.appConfidence || 0);
  const count = Number(obs.count || 0);
  const hasConflict = kind.includes("CONFLICTING");
  const hasUnknown = kind.includes("UNKNOWN") || normalizeSignal(obs.appId) === "unknown" || !normalizeSignal(obs.appId);
  const hasSignal = Boolean(usefulObservationSignal(obs));
  const hasSuggestedApp = Boolean(obs.suggestedApplication?.name);
  const hasPortScope = observationHasPortScope(obs);
  const evidenceStrength = observationEvidenceStrength(obs, { hasConflict, hasSignal, hasSuggestedApp, hasPortScope });
  const appIdReadyForEnforcement = appIdPackageReadyForEnforcement(readinessContext);
  const canStageDrop = appIdObservationCanStageDrop(obs) && appIdReadyForEnforcement;
  const canReviewSignalDrop = appIdObservationCanReviewSignalDrop(obs) && appIdReadyForEnforcement;
  const volumeBoost = Math.min(120, count * 4);

  if (hasConflict) {
    return {
      action: "investigate",
      label: "Investigate conflict",
      tone: "bad",
      priority: 900 + volumeBoost,
      evidenceStrength,
      canStageDrop: false,
      candidatePath: "No policy mutation recommended until the conflicting evidence is resolved.",
      reason: "Conflicting App-ID evidence can misclassify traffic; inspect the sample flow and related evidence before staging policy.",
    };
  }
  if (evidenceStrength === "weak") {
    return {
      action: "filter_related_evidence",
      label: "Filter evidence",
      tone: "warn",
      priority: 250 + volumeBoost,
      evidenceStrength,
      canStageDrop: false,
      candidatePath: "Open matching flow filters and collect stronger evidence before staging candidate objects.",
      reason: "The observation lacks enough signal, port, or sample evidence for a precise App-ID decision.",
    };
  }
  if (canStageDrop && hasUnknown && count >= 5) {
    return {
      action: "save_drop",
      label: "Save & drop",
      tone: "bad",
      priority: 760 + volumeBoost,
      evidenceStrength,
      canStageDrop,
      candidatePath: "Stage a custom App-ID and TCP/UDP port-hint candidate drop rule; validate and commit separately to enforce.",
      reason: "Repeated unknown traffic has enough TCP/UDP port context to stage a contained custom App-ID drop candidate.",
    };
  }
  if (hasSuggestedApp && (hasSignal || hasPortScope)) {
    return {
      action: "define_custom_app",
      label: "Define App-ID",
      tone: "info",
      priority: 620 + volumeBoost + (confidence && confidence < 50 ? 40 : 0),
      evidenceStrength,
      canStageDrop,
      candidatePath: canStageDrop
        ? "Stage the App-ID object now; a TCP/UDP port-hint candidate drop rule is available after review."
        : canReviewSignalDrop
          ? "Stage the App-ID object only; signal-only drop remains review-only and requires IDS/IPS Prevent fail-closed before candidate review."
        : appIdReadinessWasExplicit(readinessContext) && !appIdReadyForEnforcement
          ? "Stage the App-ID object only; drop enforcement waits for production-ready App-ID package evidence."
          : "Stage the App-ID object only; no TCP/UDP port-hint or supported review-only signal context is present.",
      reason: appIdReadinessWasExplicit(readinessContext) && !appIdReadyForEnforcement
        ? appIdReadinessReason(readinessContext)
        : hasUnknown
        ? "The engine produced an unmapped signal that can become a first-party custom App-ID."
        : "The current App-ID needs a custom object or taxonomy refinement before it is safe policy evidence.",
    };
  }
  return {
    action: "filter_related_evidence",
    label: "Filter evidence",
    tone: "warn",
    priority: 180 + volumeBoost,
    evidenceStrength,
    canStageDrop,
    candidatePath: "Use related flow filters before staging candidate policy.",
    reason: "More related samples are needed before defining or enforcing this App-ID.",
  };
}

function appIdPackageReadyForEnforcement(readinessContext) {
  if (!appIdReadinessWasExplicit(readinessContext)) return true;
  return readinessContext.productionReady === true;
}

function appIdReadinessWasExplicit(readinessContext) {
  return Boolean(readinessContext && readinessContext.explicit);
}

function appIdReadinessReason(readinessContext = {}) {
  const blockers = Array.isArray(readinessContext.blockers) ? readinessContext.blockers : [];
  if (blockers.length) return `App-ID package enforcement is waiting on ${blockers[0]}.`;
  return "App-ID package enforcement is waiting on explicit production-ready package evidence.";
}

function appIdIdsPreventFailClosed(policy = {}, status = {}, inspectionPosture = null) {
  const ids = policy.ids || {};
  if (ids.enabled && ids.mode === "IDS_MODE_PREVENT" &&
    (ids.failureBehavior || ids.failure_behavior) === "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED") {
    return true;
  }
  const posture = inspectionPosture || inspectionPostureSummary(status || {});
  const failure = String(posture.failureBehavior || posture.failure_behavior || "").toLowerCase();
  const state = String(posture.state || posture.inspectionState || posture.inspection_state || "").toLowerCase();
  return failure.includes("fail closed") || failure.includes("fail_closed") || state.includes("failed-closed");
}

function observationRank(kind) {
  const v = String(kind || "");
  if (v.includes("CONFLICTING")) return 0;
  if (v.includes("UNKNOWN")) return 1;
  if (v.includes("LOW_CONFIDENCE")) return 2;
  return 3;
}

function observationEvidenceStrength(obs, signals = {}) {
  if (signals.hasConflict) return "conflicting";
  const evidenceCount = (obs.appEvidence || []).filter(Boolean).length;
  const count = Number(obs.count || 0);
  const confidence = Number(obs.appConfidence || 0);
  const strongSignal = signals.hasSignal && evidenceCount > 0;
  if ((strongSignal && signals.hasPortScope) || (signals.hasSuggestedApp && count >= 5 && (signals.hasSignal || signals.hasPortScope))) return "strong";
  if (signals.hasSignal || signals.hasPortScope || confidence > 0 || evidenceCount > 0) return "moderate";
  return "weak";
}

function usefulObservationSignal(obs = {}) {
  const signal = normalizeSignal(obs.engineSignal);
  if (!signal || BUILTIN_ENGINE_SIGNALS.has(signal)) return "";
  return signal;
}

function observationHasPortScope(obs = {}) {
  const proto = protocolEnum(obs.protocol);
  const port = numberOrZero(obs.destPort);
  return Boolean(port && (proto === "PROTOCOL_TCP" || proto === "PROTOCOL_UDP"));
}

function appIdObservationCanStageDrop(obs = {}) {
  if (!observationHasPortScope(obs)) return false;
  const app = obs.suggestedApplication || {};
  if (!app.name) return true;
  if (!(app.ports || []).length) return false;
  return appMatchesObservationPort(app, obs);
}

function appIdObservationCanReviewSignalDrop(obs = {}) {
  const app = obs.suggestedApplication || {};
  return Boolean(app.name) && appSupportsSignalOnlyDrop(app);
}

function appMatchesObservationPort(app, obs) {
  const proto = protocolEnum(obs.protocol);
  const port = numberOrZero(obs.destPort);
  return Boolean(port && (app.ports || []).some((hint) => hint.protocol === proto &&
    (hint.ports || []).some((p) => portInRange(port, p))));
}

export function appIdContentContext(obs = {}) {
  const packageProvenance = appIdPackageProvenanceFromEvidence(obs.appEvidence || []);
  if (packageProvenance.label) return packageProvenance.label;
  const evidence = (obs.appEvidence || [])
    .map((item) => compactPackageEvidence(item, 180))
    .find((item) => /content|package|taxonomy|version/i.test(item));
  if (evidence) return evidence;
  const app = obs.suggestedApplication || {};
  if (app.category) return `category ${app.category}`;
  return "";
}

function sampleTupleLabel(obs = {}) {
  const srcPort = numberOrZero(obs.sampleSrcPort || obs.sample_src_port);
  const destPort = numberOrZero(obs.destPort || obs.dest_port);
  return `${endpointLabel(obs.sampleSrcIp || obs.sample_src_ip || "", srcPort)} -> ${endpointLabel(obs.sampleDestIp || obs.sample_dest_ip || "", destPort)}`;
}

function endpointLabel(ip, port) {
  const value = String(ip || "—");
  if (!port) return value;
  return value.includes(":") && value !== "—" ? `[${value}]:${port}` : `${value}:${port}`;
}

function appIdObservationPackageLabel(obs = {}) {
  const provenance = appIdObservationPackageProvenance(obs);
  return provenance.label;
}

export function appIdObservationPackageProvenance(obs = {}) {
  const version = obs.appIdPackageVersion || obs.app_id_package_version || "";
  const manifest = obs.appIdPackageManifestSha256 || obs.app_id_package_manifest_sha256 || "";
  const manifestShort = shortHash(manifest);
  return {
    version,
    manifestSha256: manifest,
    manifestShort,
    label: joinParts(version ? `package ${version}` : "", manifestShort ? `manifest ${manifestShort}` : ""),
  };
}

export function appIdPackageProvenanceFromEvidence(evidence = []) {
  const entries = Array.isArray(evidence) ? evidence : [];
  for (const entry of entries) {
    const text = compactPackageEvidence(entry, 180);
    const match = /^signed App-ID package(?:\s+([^@\s]+))?(?:@([a-fA-F0-9]{8,64}))?/i.exec(text);
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

function compactPackageEvidence(value, maxLen) {
  const compact = String(value || "").trim().replace(/\s+/g, " ");
  if (/[/\\]|[?&](?:token|secret|password|key)=/i.test(compact)) return "";
  return maxLen > 0 ? compact.slice(0, maxLen).trim() : compact;
}

export function applicationPortsLabel(app = {}) {
  const labels = [];
  for (const hint of app.ports || []) {
    const proto = String(hint.protocol || "").replace(/^PROTOCOL_/, "");
    for (const port of hint.ports || []) {
      labels.push(`${proto}/${port.end ? `${port.start}-${port.end}` : port.start}`);
    }
  }
  return labels.join(", ") || "—";
}

function telemetryContextLabel(data = {}) {
  const version = Number(data.runningPolicyVersion || 0);
  if (version > 0) return `running policy v${version}`;
  return data.policyContext || "";
}

function eventPolicyLabel(event = {}) {
  return eventPolicyStamp(event);
}

function eventPolicyStamp(event = {}) {
  const version = Number(event.policyVersion || 0);
  if (event.policyVersionKnown && version > 0) return event.policyStamp || event.eventPolicyStamp || `v${version}`;
  return "unknown event policy stamp";
}

function eventPolicyFreshness(event = {}, context = {}) {
  if (event.eventPolicyFreshness) return event.eventPolicyFreshness;
  if (!event.policyVersionKnown || Number(event.policyVersion || 0) <= 0) return "freshness unknown";
  const eventVersion = Number(event.policyVersion || 0);
  const runningVersion = Number(context.runningPolicyVersion || event.runningPolicyVersion || 0);
  if (!runningVersion) return "freshness unknown";
  if (eventVersion === runningVersion) return `current at query time (running v${runningVersion})`;
  if (eventVersion < runningVersion) return `stale at query time (running v${runningVersion})`;
  return `newer than running policy at query time (running v${runningVersion})`;
}

function eventPolicyPill(event = {}, context = {}) {
  const known = Boolean(event.policyVersionKnown && Number(event.policyVersion || 0) > 0);
  const freshness = eventPolicyFreshness(event, context);
  const stale = /^stale\b/.test(freshness);
  return pill(joinParts(eventPolicyLabel(event), known ? freshness.replace(/\s*\(running v\d+\)$/, "") : ""), known && !stale ? "ok" : "warn", true);
}

function joinParts(...parts) {
  return parts.filter(Boolean).join(" · ");
}

function shortHash(value) {
  return String(value || "").trim().slice(0, 12);
}

function numberOrZero(value) {
  const n = Number(value);
  return Number.isInteger(n) ? n : 0;
}

function flowFromSession(s) {
  return {
    flowId: sessionKey(s),
    srcIp: s.srcIp,
    srcPort: s.srcPort,
    destIp: s.destIp,
    destPort: s.destPort,
    protocol: s.protocol,
    appProtocol: "conntrack",
    bytesToServer: s.bytes,
    bytesToClient: 0,
    packets: s.packets,
    appEvidence: ["live conntrack session"],
  };
}

export function sessionKey(s = {}) {
  const family = stableKeyPart(s.family);
  const protocol = stableKeyPart(s.protocol);
  const srcIp = stableKeyPart(s.srcIp);
  const destIp = stableKeyPart(s.destIp);
  if (!family || !protocol || !srcIp || !destIp) return "";
  return [
    "ct1",
    family,
    protocol,
    srcIp,
    stablePortPart(s.srcPort),
    destIp,
    stablePortPart(s.destPort),
    stableKeyPart(s.replySrcIp),
    stablePortPart(s.replySrcPort),
    stableKeyPart(s.replyDestIp),
    stablePortPart(s.replyDestPort),
  ].join("|");
}

function stableKeyPart(value) {
  return String(value ?? "").trim().toLowerCase();
}

function stablePortPart(value) {
  const text = String(value ?? "").trim();
  if (!text) return "";
  const n = Number(text);
  if (!Number.isInteger(n) || n < 0 || n > 65535) return "";
  return String(n);
}

function sessionFlags(s) {
  const flags = [];
  if (s.assured) flags.push("assured");
  if (s.family) flags.push(s.family);
  return flags;
}

function sessionStateClass(value) {
  const v = String(value || "").toUpperCase();
  if (v === "ESTABLISHED" || v === "ASSURED") return "ok";
  if (v.includes("SYN") || v === "UNREPLIED") return "warn";
  if (v.includes("CLOSE") || v.includes("TIME")) return "neutral";
  return "info";
}

export function flowTotalBytes(f = {}) {
  return fmt.num(f.bytesToServer) + fmt.num(f.bytesToClient);
}

export function buildFlowRule(policy, f, action = "ACTION_ALLOW") {
  return buildFlowRulePlan(policy, f, action).rule;
}

export function buildFlowRulePlan(policy = {}, f = {}, action = "ACTION_ALLOW") {
  const srcCidr = ipCidr(f.srcIp), dstCidr = ipCidr(f.destIp);
  const srcAddress = addressDependency(policy, srcCidr, "src-" + clean(f.srcIp));
  const dstAddress = addressDependency(policy, dstCidr, "dst-" + clean(f.destIp));
  const svcNames = [];
  const services = [];
  const proto = protocolEnum(f.protocol);
  if (f.destPort && proto && proto !== "PROTOCOL_ICMP") {
    const service = serviceDependency(policy, proto, f.destPort, appLabel(f).toLowerCase() + "-" + f.destPort);
    svcNames.push(service.name);
    if (service.object) services.push(service.object);
  }
  const block = action === "ACTION_DENY" || action === "ACTION_REJECT";
  const verb = block ? "drop" : "allow";
  const addresses = [srcAddress.object, dstAddress.object].filter(Boolean);
  return {
    rule: {
      name: `${verb}-flow-${clean(f.srcIp)}-to-${clean(f.destIp)}`,
      fromZones: [],
      toZones: [],
      sourceAddresses: [srcAddress.name],
      destinationAddresses: [dstAddress.name],
      services: svcNames,
      action,
      log: block,
      disabled: false,
      description: `${block ? "Drop" : "Allow"} observed flow ${f.srcIp} → ${fmt.endpoint(f.destIp, f.destPort)} (${appLabel(f)})`,
    },
    dependencies: { addresses, services },
    beforeSave: (draft) => stageFlowRuleDependencies(draft, { addresses, services }),
  };
}

function ipCidr(ip) { return ip && ip.includes(":") ? ip + "/128" : (ip || "0.0.0.0") + "/32"; }
function clean(ip) { return (ip || "x").replace(/[.:]/g, "-"); }
function addressDependency(policy, cidr, baseName) {
  const ex = (policy.addresses || []).find((x) => x.cidr === cidr);
  if (ex) return { name: ex.name, object: null };
  const name = uniqueObjectName(policy.addresses || [], baseName);
  return { name, object: { name, cidr } };
}
function serviceDependency(policy, proto, port, baseName) {
  const ex = (policy.services || []).find((x) => serviceMatchesPort(x, proto, port));
  if (ex) return { name: ex.name, object: null };
  const name = uniqueObjectName(policy.services || [], baseName);
  return { name, object: { name, protocol: proto, ports: [{ start: port }] } };
}
function stageFlowRuleDependencies(draft, deps = {}) {
  for (const address of deps.addresses || []) {
    if (!address?.name || !address.cidr) continue;
    if ((draft.addresses || []).some((x) => x.cidr === address.cidr || x.name === address.name)) continue;
    (draft.addresses ||= []).push({ ...address });
  }
  for (const service of deps.services || []) {
    if (!service?.name || !service.protocol) continue;
    const port = Number(service.ports?.[0]?.start || 0);
    if ((draft.services || []).some((x) => x.name === service.name || serviceMatchesPort(x, service.protocol, port))) continue;
    (draft.services ||= []).push({ ...service, ports: (service.ports || []).map((p) => ({ ...p })) });
  }
}
function serviceMatchesPort(service, proto, port) {
  return service?.protocol === proto && (service.ports || []).some((p) => Number(p.start) === Number(port) && !p.end);
}
function uniqueObjectName(items = [], base = "object") {
  const cleanBase = String(base || "object").toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "object";
  const names = new Set((items || []).map((item) => item?.name).filter(Boolean));
  if (!names.has(cleanBase)) return cleanBase;
  let i = 2;
  while (names.has(`${cleanBase}-${i}`)) i += 1;
  return `${cleanBase}-${i}`;
}
