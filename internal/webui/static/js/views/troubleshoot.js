// Troubleshoot — policy-model flow explanations. Operators can enter a
// tuple, select the relevant zones, and see the first-match rule, verdict,
// inspection posture, NAT evidence, and skipped-rule trace.

import { h, icon, clear } from "../core.js";
import { api } from "../api.js";
import { openAutomationContext } from "../automation_context.js";
import { throwIfAccessDenied } from "../auth_gate.js";
import { captureHandoffPacket, explainHandoffPacket, investigationPacketFilename, investigationPacketJson, investigationPacketText } from "../investigation_packet.js";
import { pinInvestigationPacket } from "../investigation_case.js";
import { CAPTURE_LIMITS, buildCapturePlan, captureArtifactFilename, captureAuditHash, captureHistoryItems, captureReference, captureReferenceLabel, captureRetentionApiState } from "../packet_capture.js";
import { natEvidence, natProfileLines, natProfileSummary } from "../explain_profiles.js";
import { inspectionPostureSummary } from "../inspection_posture.js";
import { session } from "../policy.js";
import { writeQueryState } from "../query_state.js";
import { boundedRouteSimulationFromCompare } from "../route_simulation.js";
import { pageHead, card, emptyState, pill, toast, confirmDialog, labeledCell, responsiveTable } from "../ui.js";
import { openRuleEditorPrefilled } from "./rules.js";
import * as fmt from "../format.js";

const state = {
  result: null,
  query: null,
  resultKey: "",
  error: "",
  errorKey: "",
  compare: null,
  compareKey: "",
  compareLoading: false,
  runtimeStatus: null,
  runtimeStatusKey: "",
  requestSeq: 0,
  activeRequest: null,
};

export const TROUBLESHOOT_ROUTE_DEFAULTS = Object.freeze({
  source: "POLICY_SOURCE_RUNNING",
  version: "",
  fromZone: "",
  toZone: "",
  protocol: "PROTOCOL_TCP",
  app: "",
  src: "",
  sport: "",
  dst: "",
  dport: "",
  runtime: false,
  flowId: "",
  run: false,
  intent: "",
  captureInterface: CAPTURE_LIMITS.defaultInterface,
  captureDuration: String(CAPTURE_LIMITS.defaultDurationSeconds),
  capturePackets: String(CAPTURE_LIMITS.defaultPacketCount),
  captureSnaplen: String(CAPTURE_LIMITS.defaultSnaplenBytes),
  captureContext: "",
  caseKey: "",
  caseAction: "",
  caseKind: "",
});
export const TROUBLESHOOT_ROUTE_KEYS = Object.freeze(Object.keys(TROUBLESHOOT_ROUTE_DEFAULTS));
const POLICY_SOURCES = new Set(["POLICY_SOURCE_RUNNING", "POLICY_SOURCE_CANDIDATE", "POLICY_SOURCE_VERSION"]);

export async function render(ctx = {}) {
  const routePath = ctx.path || "/troubleshoot";
  const q = normalizeTroubleshootRoute(ctx.query || {});
  const root = h("div", {});
  const sessionR = await Promise.allSettled([session.load()]);
  throwIfAccessDenied(...sessionR);
  if (sessionR[0].status === "rejected") {
    paintTroubleshootUnavailable(root, q, sessionR[0].reason, routePath);
    return root;
  }
  reconcileResultWithQuery(explainQueryFromRouteState(q));
  const controls = formControls(q);
  const resultNode = paint(root, controls);
  if (shouldAutoRun(q)) setTimeout(() => {
    if (q.intent === "compare") runCompare(controls, resultNode);
    else runExplain(controls, resultNode, { intent: q.intent });
  }, 0);
  return root;
}

function paintTroubleshootUnavailable(root, q, err, routePath = "/troubleshoot") {
  clear(root);
  root.appendChild(pageHead("Troubleshoot",
    "Explain how the selected policy treats a flow before changing the firewall.",
    h("div", { class: "flex wrap" },
      h("button", { class: "btn", type: "button", title: "Retry loading candidate session", "aria-label": "Retry loading candidate session", dataset: { troubleshootAction: "retry-load" }, onclick: () => renderAndReplaceTroubleshoot(root, q, routePath) },
        h("span", { html: icon("refresh", 16) }), "Retry"),
      h("button", { class: "btn", type: "button", title: "Open Troubleshoot API and CLI context", "aria-label": "Open Troubleshoot API and CLI context", dataset: { troubleshootAction: "api-cli-context" }, onclick: () => openAutomationContext(routePath) },
        h("span", { html: icon("copy", 16) }), "API / CLI context"))));
  root.appendChild(h("div", { class: "alert-box bad", dataset: { troubleshootLoadError: "true" } },
    h("strong", {}, "Candidate session unavailable. "),
    loadErrorDetail(err, "The candidate or running policy API did not return session data."),
    h("div", { class: "note" }, "The route shell remains available. Retry after the API is reachable, or use API / CLI context for equivalent explain and candidate comparison commands.")));
  root.appendChild(h("div", { class: "explain-layout" },
    card(h("h2", {}, "Flow query"), unavailableRouteSummary(q)),
    h("div", { class: "explain-result" },
      emptyState("search", "Troubleshoot data unavailable", "Policy source choices, zones, applications, and candidate comparison require the policy session API."))));
}

async function renderAndReplaceTroubleshoot(root, q, routePath = "/troubleshoot") {
  const current = await render({ path: routePath, query: troubleshootQueryFromState(q) });
  root.replaceChildren(...Array.from(current.childNodes));
}

function unavailableRouteSummary(q = {}) {
  return h("dl", { class: "kv compact" },
    kv("Policy source", q.source || TROUBLESHOOT_ROUTE_DEFAULTS.source),
    kv("From zone", q.fromZone || "unknown / wildcard"),
    kv("To zone", q.toZone || "unknown / wildcard"),
    kv("Source", routeEndpointLabel(q.src, q.sport)),
    kv("Destination", routeEndpointLabel(q.dst, q.dport)),
    kv("Protocol", q.protocol || TROUBLESHOOT_ROUTE_DEFAULTS.protocol));
}

function routeEndpointLabel(address = "", port = "") {
  const base = address || "any";
  return port ? `${base}:${port}` : base;
}

function troubleshootQueryFromState(q = {}) {
  return { ...TROUBLESHOOT_ROUTE_DEFAULTS, ...q };
}

function loadErrorDetail(err, fallback = "The API request failed.") {
  return err?.message || String(err || fallback);
}

function paint(root, controls) {
  clear(root);
  root.appendChild(pageHead("Troubleshoot",
    "Explain how the selected policy treats a flow before changing the firewall.",
    h("button", {
      class: "btn",
      type: "button",
      title: "Clear Troubleshoot flow query",
      "aria-label": "Clear Troubleshoot flow query",
      dataset: { troubleshootAction: "clear-query" },
      onclick: () => { controls.clear(); paint(root, formControls(TROUBLESHOOT_ROUTE_DEFAULTS)); },
    }, h("span", { html: icon("x", 16) }), "Clear")));

  const result = h("div", { class: "explain-result" });
  root.appendChild(h("div", { class: "explain-layout" },
    card(h("h2", {}, "Flow query"), flowForm(controls, result)),
    result));
  renderResult(result, false, controls);
  return result;
}

function formControls(q) {
  const zones = (session.draft.zones || []).map((z) => z.name).filter(Boolean);
  const source = select([
    ["POLICY_SOURCE_RUNNING", "Running"],
    ["POLICY_SOURCE_CANDIDATE", "Candidate"],
    ["POLICY_SOURCE_VERSION", "Version"],
  ], q.source);
  const fromZone = select([["", "Unknown / wildcard"], ...zones.map((z) => [z, z])], q.fromZone || "");
  const toZone = select([["", "Unknown / wildcard"], ...zones.map((z) => [z, z])], q.toZone || "");
  const protocol = select([
    ["PROTOCOL_TCP", "TCP"],
    ["PROTOCOL_UDP", "UDP"],
    ["PROTOCOL_ICMP", "ICMP"],
    ["PROTOCOL_ANY", "Any IP"],
  ], q.protocol);
  const apps = (session.draft.applications || []).map((a) => [a.name, a.displayName ? `${a.displayName} (${a.name})` : a.name]);
  const appId = select([["", "No App-ID"], ...apps], q.app || "");
  const version = input("number", q.version || "", "0");
  const src = input("text", q.src || "", "10.0.1.20");
  const sport = input("number", q.sport || "", "51515");
  const dst = input("text", q.dst || "", "10.0.2.20");
  const dport = input("number", q.dport || "", "443");
  const includeRuntime = h("input", { type: "checkbox" });
  includeRuntime.checked = Boolean(q.runtime);
  const flowId = input("text", q.flowId || "", "optional EVE flow ID");
  const capture = {
    interface: q.captureInterface,
    duration: q.captureDuration,
    packets: q.capturePackets,
    snaplen: q.captureSnaplen,
    captureContext: q.captureContext,
  };
  const caseContext = normalizeTroubleshootCaseContext(q);
  return {
    source, version, fromZone, toZone, protocol, appId, src, sport, dst, dport, includeRuntime, flowId, capture, caseContext,
    clear: () => {
      cancelTroubleshootRequests();
      state.result = null; state.query = null; state.resultKey = ""; state.error = ""; state.errorKey = "";
      state.compare = null; state.compareKey = ""; state.compareLoading = false; state.runtimeStatus = null; state.runtimeStatusKey = "";
      if (typeof location !== "undefined") location.hash = "#/troubleshoot";
    },
  };
}

function flowForm(c, resultNode) {
  const submit = async (e) => {
    e.preventDefault();
    await runExplain(c, resultNode);
  };
  const onEdit = () => {
    const key = queryKeyFromControls(c);
    const compareKey = compareQueryKeyFromControls(c);
    syncRouteFromControls(c);
    const resultStale = state.result && state.resultKey !== key;
    const errorStale = state.error && state.errorKey !== key;
    const compareStale = (state.compare || state.compareLoading) && state.compareKey !== compareKey;
    if (!resultStale && !errorStale && !compareStale) return;
    cancelTroubleshootRequests();
    state.result = null; state.query = null; state.resultKey = ""; state.error = ""; state.errorKey = "";
    state.compare = null; state.compareKey = ""; state.compareLoading = false;
    renderResult(resultNode, false, c);
  };
  controlFields(c).forEach((el) => {
    el.addEventListener("input", onEdit);
    el.addEventListener("change", onEdit);
  });
  return h("form", { class: "explain-form", onsubmit: submit },
    h("label", { class: "field" }, h("span", {}, "Policy source"), c.source),
    h("label", { class: "field" }, h("span", {}, "Version"), c.version),
    h("div", { class: "form-grid two" },
      h("label", { class: "field" }, h("span", {}, "From zone"), c.fromZone),
      h("label", { class: "field" }, h("span", {}, "To zone"), c.toZone)),
    h("div", { class: "form-grid two" },
      h("label", { class: "field" }, h("span", {}, "Source IP"), c.src),
      h("label", { class: "field" }, h("span", {}, "Source port"), c.sport)),
    h("div", { class: "form-grid two" },
      h("label", { class: "field" }, h("span", {}, "Destination IP"), c.dst),
      h("label", { class: "field" }, h("span", {}, "Destination port"), c.dport)),
    h("label", { class: "field" }, h("span", {}, "Protocol"), c.protocol),
    h("label", { class: "field" }, h("span", {}, "App-ID"), c.appId),
    h("label", { class: "field" }, h("span", {}, "Flow ID"), c.flowId),
    h("label", { class: "field inline-check" }, c.includeRuntime, h("span", {}, "Include live runtime evidence")),
    h("button", { class: "btn primary", type: "submit", title: "Explain this flow against the selected policy", "aria-label": "Explain this flow against the selected policy", dataset: { troubleshootAction: "explain-flow" } }, h("span", { html: icon("search", 16) }), "Explain flow"));
}

async function runExplain(c, resultNode, opts = {}) {
  const query = queryFromControls(c);
  const key = troubleshootQueryKey(query);
  const request = beginTroubleshootRequest("explain", key);
  state.error = ""; state.errorKey = ""; state.result = null; state.resultKey = ""; state.query = query;
  state.compare = null; state.compareKey = ""; state.compareLoading = false; state.runtimeStatus = null; state.runtimeStatusKey = "";
  syncRouteFromControls(c, opts.intent ? { run: true, intent: opts.intent } : {});
  renderResult(resultNode, true, c);
  const statusPromise = query.includeRuntime
    ? api.status().catch((err) => ({ inspection: { state: "unknown", detail: err?.message || String(err) }, engines: [], warnings: ["runtime status unavailable"] }))
    : Promise.resolve(null);
  try {
    const result = await api.explainFlow(query);
    const runtimeStatus = await statusPromise;
    if (!isActiveTroubleshootRequest(request) || queryKeyFromControls(c) !== key) return;
    state.query = query;
    state.result = result;
    state.resultKey = key;
    state.runtimeStatus = runtimeStatus;
    state.runtimeStatusKey = runtimeStatus ? key : "";
  } catch (err) {
    if (!isActiveTroubleshootRequest(request) || queryKeyFromControls(c) !== key) return;
    state.error = err.message;
    state.errorKey = key;
    toast("Explain failed", err.message, "bad");
  }
  renderResult(resultNode, false, c);
  if (opts.intent === "capture") focusPacketCapture(resultNode);
}

async function runCompare(c, resultNode) {
  const queries = compareQueriesFromRouteState(routeStateFromControls(c));
  const key = compareQueryKey(queries);
  const request = beginTroubleshootRequest("compare", key);
  state.compare = null;
  state.compareKey = key;
  state.compareLoading = true;
  syncRouteFromControls(c, { run: true, intent: "compare" });
  renderResult(resultNode, false, c);
  const [running, candidate] = await Promise.all([
    collectCompareSide("running", queries.running),
    collectCompareSide("candidate", queries.candidate),
  ]);
  if (!isActiveTroubleshootRequest(request) || compareQueryKeyFromControls(c) !== key) return;
  state.compare = {
    running,
    candidate,
    deltas: compareDeltaSummary(running.result, candidate.result),
  };
  state.compareKey = key;
  state.compareLoading = false;
  if (running.error && candidate.error) {
    toast("Compare failed", "Running and candidate explain calls failed.", "bad");
  } else if (running.error || candidate.error) {
    toast("Compare partial", "One explain call failed; showing the successful side.", "warn");
  } else {
    toast("Compare complete", "Running and candidate explanations are side by side.", "ok");
  }
  renderResult(resultNode, false, c);
}

async function collectCompareSide(label, query) {
  try {
    return { label, query, result: await api.explainFlow(query), error: "" };
  } catch (err) {
    return { label, query, result: null, error: err?.message || String(err) };
  }
}

export function normalizeTroubleshootRoute(query = {}) {
  const rawSource = query.source || query.policySource;
  const version = versionText(query.version || query.policyVersion);
  const source = sourceValue(rawSource || (version ? "POLICY_SOURCE_VERSION" : ""));
  const flowId = stringValue(query.flowId);
  const capture = normalizeCaptureRoute(query);
  return {
    source,
    version,
    fromZone: stringValue(query.fromZone),
    toZone: stringValue(query.toZone),
    protocol: normalizeProto(query.protocol || TROUBLESHOOT_ROUTE_DEFAULTS.protocol),
    app: stringValue(query.app || query.appId),
    src: stringValue(query.src || query.srcIp),
    sport: portText(query.sport || query.srcPort),
    dst: stringValue(query.dst || query.destIp),
    dport: portText(query.dport || query.destPort),
    runtime: runtimeValue(query) || Boolean(flowId),
    flowId,
    run: booleanValue(query.run || query.autorun || query.autoRun || query.investigate),
    intent: intentValue(query.intent),
    ...normalizeTroubleshootCaseContext(query),
    ...normalizeTroubleshootCaptureContext(query),
    ...capture,
  };
}

export function normalizeTroubleshootCaptureContext(query = {}) {
  const context = safeTroubleshootRouteToken(query.captureContext || query.captureSource || "", 80);
  return {
    captureContext: context === "log-plan" ? context : "",
  };
}

export function normalizeTroubleshootCaseContext(query = {}) {
  return {
    caseKey: safeTroubleshootRouteToken(query.caseKey, 320),
    caseAction: safeTroubleshootRouteToken(query.caseAction, 80),
    caseKind: safeTroubleshootRouteToken(query.caseKind, 80),
  };
}

export function safeTroubleshootRouteToken(value = "", limit = 320) {
  const text = String(value || "").trim();
  if (!text || text.length > limit) return "";
  if (/[\u0000-\u001f\u007f]/.test(text)) return "";
  if (/bearer|token|secret|password|\/var\/|\/etc\/|\/tmp\/|file:/i.test(text)) return "";
  return text;
}

export function explainQueryFromRouteState(route = {}) {
  const q = normalizeTroubleshootRoute(route);
  return {
    policySource: q.source,
    version: q.version ? String(q.version) : "0",
    fromZone: q.fromZone,
    toZone: q.toZone,
    srcIp: q.src,
    srcPort: numberOrZero(q.sport),
    destIp: q.dst,
    destPort: numberOrZero(q.dport),
    protocol: q.protocol,
    appId: q.app,
    includeRuntime: Boolean(q.runtime),
    flowId: q.flowId,
  };
}

export function routeStateFromExplainQuery(query = {}) {
  return normalizeTroubleshootRoute({
    source: query.policySource,
    version: query.version,
    fromZone: query.fromZone,
    toZone: query.toZone,
    src: query.srcIp,
    sport: query.srcPort,
    dst: query.destIp,
    dport: query.destPort,
    protocol: query.protocol,
    app: query.appId,
    runtime: query.includeRuntime,
    flowId: query.flowId,
  });
}

export function troubleshootQueryKey(query = {}) {
  return JSON.stringify(explainQueryFromRouteState(routeStateFromExplainQuery(query)));
}

export function compareQueriesFromRouteState(route = {}) {
  const normalized = normalizeTroubleshootRoute(route);
  const base = {
    ...normalized,
    source: "POLICY_SOURCE_RUNNING",
    version: "",
  };
  return {
    running: explainQueryFromRouteState(base),
    candidate: explainQueryFromRouteState({ ...base, source: "POLICY_SOURCE_CANDIDATE" }),
  };
}

export function compareQueryKey(queries = {}) {
  return JSON.stringify({
    running: explainQueryFromRouteState(routeStateFromExplainQuery(queries.running || {})),
    candidate: explainQueryFromRouteState(routeStateFromExplainQuery(queries.candidate || {})),
  });
}

export function compareDeltaSummary(running, candidate) {
  if (!running || !candidate) return [];
  return [
    compareDelta("verdict", "Verdict", verdictSummary(running), verdictSummary(candidate)),
    compareDelta("rule", "Matched rule", ruleSummary(running), ruleSummary(candidate)),
    compareDelta("nat", "NAT", natSummary(running), natSummary(candidate)),
    compareDelta("route", "Route", routeSummary(running), routeSummary(candidate)),
    compareDelta("inspection", "Inspection", inspectionSummary(running), inspectionSummary(candidate)),
  ].filter(Boolean);
}

export function buildTroubleshootRuleDraft(policy = {}, query = {}, result = {}, action = "ACTION_ALLOW") {
  const normalizedAction = action === "ACTION_DENY" ? "ACTION_DENY" : "ACTION_ALLOW";
  const tuple = explainQueryFromRouteState(routeStateFromExplainQuery(query || {}));
  if (!tuple.srcIp || !tuple.destIp) {
    throw new Error("Source and destination IPs are required to prepare a rule.");
  }

  const next = structuredClone(policy || {});
  const generated = { addresses: [], services: [] };
  const source = ensureTroubleshootAddress(next, generated, tuple.srcIp, "src");
  const destination = ensureTroubleshootAddress(next, generated, tuple.destIp, "dst");
  const service = ensureTroubleshootService(next, generated, tuple.protocol, tuple.destPort);
  const fromZones = tuple.fromZone ? [tuple.fromZone] : ["any"];
  const toZones = tuple.toZone ? [tuple.toZone] : ["any"];
  const verb = normalizedAction === "ACTION_DENY" ? "drop" : "allow";
  const rule = {
    name: uniqueTroubleshootName(next.rules || [], sanitizeTroubleshootName(`${verb}-${fromZones[0]}-${toZones[0]}-${service}`)),
    fromZones,
    toZones,
    sourceAddresses: [source],
    destinationAddresses: [destination],
    services: [service],
    applications: [],
    tags: [],
    action: normalizedAction,
    log: true,
    disabled: false,
    description: troubleshootRuleDescription(tuple, result, normalizedAction),
  };
  return {
    rule,
    insertAt: recommendedTroubleshootRuleInsertIndex(policy.rules || [], result, normalizedAction),
    generated,
    policy: next,
  };
}

export function recommendedTroubleshootRuleInsertIndex(rules = [], result = {}, action = "ACTION_ALLOW") {
  const idx = Number(result?.matchedRuleIndex);
  if (result?.matchedRule && Number.isInteger(idx) && idx >= 0 && idx <= (rules || []).length) return idx;
  return action === "ACTION_DENY" ? 0 : (rules || []).length;
}

function reconcileResultWithQuery(query) {
  const key = troubleshootQueryKey(query);
  const route = routeStateFromExplainQuery(query);
  const compareKey = compareQueryKey(compareQueriesFromRouteState(route));
  if (state.result && state.resultKey !== key) {
    state.result = null; state.query = null; state.resultKey = "";
  }
  if (state.error && state.errorKey !== key) {
    state.error = ""; state.errorKey = "";
  }
  if ((state.compare || state.compareLoading) && state.compareKey !== compareKey) {
    cancelTroubleshootRequests();
    state.compare = null; state.compareKey = ""; state.compareLoading = false;
  }
  if (state.result && state.resultKey === key) state.query = query;
}

function beginTroubleshootRequest(kind, key) {
  const request = { id: ++state.requestSeq, kind, key };
  state.activeRequest = request;
  return request;
}

function cancelTroubleshootRequests() {
  state.requestSeq += 1;
  state.activeRequest = null;
}

export function isCurrentTroubleshootRequest(active, request, currentKey = "") {
  if (!active || !request) return false;
  return active.id === request.id && active.kind === request.kind && active.key === request.key && (!currentKey || currentKey === request.key);
}

function isActiveTroubleshootRequest(request) {
  return isCurrentTroubleshootRequest(state.activeRequest, request);
}

function queryFromControls(c) {
  return explainQueryFromRouteState(routeStateFromControls(c));
}

function queryKeyFromControls(c) {
  return troubleshootQueryKey(queryFromControls(c));
}

function compareQueryKeyFromControls(c) {
  return compareQueryKey(compareQueriesFromRouteState(routeStateFromControls(c)));
}

function routeStateFromControls(c, overrides = {}) {
  return normalizeTroubleshootRoute({
    source: c.source.value,
    version: c.version.value,
    fromZone: c.fromZone.value,
    toZone: c.toZone.value,
    src: c.src.value,
    sport: c.sport.value,
    dst: c.dst.value,
    dport: c.dport.value,
    protocol: c.protocol.value,
    app: c.appId.value,
    runtime: c.includeRuntime.checked,
    flowId: c.flowId.value,
    captureInterface: c.capture?.interface,
    captureDuration: c.capture?.duration,
    capturePackets: c.capture?.packets,
    captureSnaplen: c.capture?.snaplen,
    ...normalizeTroubleshootCaseContext(c.caseContext || {}),
    ...normalizeTroubleshootCaptureContext(c.capture || {}),
    ...overrides,
  });
}

function syncRouteFromControls(c, overrides = {}) {
  writeQueryState("/troubleshoot", routeStateFromControls(c, overrides), TROUBLESHOOT_ROUTE_DEFAULTS, TROUBLESHOOT_ROUTE_KEYS);
}

function controlFields(c) {
  return [c.source, c.version, c.fromZone, c.toZone, c.protocol, c.appId, c.src, c.sport, c.dst, c.dport, c.includeRuntime, c.flowId];
}

function renderResult(node, loading = false, controls = null) {
  if (!node) return;
  clear(node);
  if (loading) {
    node.appendChild(h("div", { class: "loading" }, "Explaining flow…"));
    return;
  }
  if (state.error) {
    node.appendChild(h("div", { class: "alert-box bad" }, h("strong", {}, "Explain failed. "), state.error));
    if (controls) node.appendChild(compareEvidenceCard(controls, node));
    return;
  }
  if (!state.result) {
    node.appendChild(card(h("h2", {}, "Explanation"), h("div", { class: "empty compact" },
      h("div", { html: icon("search", 34) }),
      h("h3", {}, "No flow explained yet"),
      h("div", {}, "Enter a tuple or pivot from Traffic."))));
    if (controls) node.appendChild(compareEvidenceCard(controls, node));
    return;
  }

  const r = state.result;
  node.appendChild(h("div", { class: "explain-summary " + verdictClass(r.verdict) },
    h("div", { class: "explain-verdict" }, verdictLabel(r.verdict)),
      h("div", {},
        h("div", { class: "explain-reason" }, r.reason || "No reason returned."),
        h("div", { class: "note" }, `Decision: ${decisionLabel(r)}`),
        h("div", { class: "note" }, r.matchedRule
          ? `Matched ${r.matchedRule} at index ${r.matchedRuleIndex}.`
          : r.defaultPolicy ? "Matched the default forward-chain policy." : "No matching rule returned.")),
    h("div", { class: "flex wrap", style: { justifyContent: "flex-end" } },
      pill(policyLabel(r), "info"),
      pill(inspectionLabel(r.inspectionState), inspectionClass(r.inspectionState)))));

  node.appendChild(resultActions(
    explainHandoffPacket({ query: state.query, result: r }, { route: currentRoute(), currentInspectionPosture: inspectionPostureSummary(state.runtimeStatus || {}) }),
    "explain",
    controls,
    node,
  ));

  if (state.compare || state.compareLoading) node.appendChild(compareEvidenceCard(null, node));

  node.appendChild(packetCaptureCard(state.query, r, controls));

  node.appendChild(h("div", { class: "explain-stack" },
    explanationTimelineCard(explanationTimelineModel(r)),
    runtimeEvidenceCard(r.runtimeEvidence),
    engineHealthCard(state.runtimeStatus, r.runtimeEvidence),
    inspectionProfileCard(r.inspectionProfile),
    natProfileCard(r.natProfile || r.natDecision),
    routeProfileCard(r.routeProfile),
    listCard("Evidence", r.evidence, "check"),
    listCard("Trace", r.trace, "changes"),
    r.warnings?.length ? listCard("Warnings", r.warnings, "threats", "warn") : null));
}

export function explanationTimelineModel(result = {}) {
  if (!result || typeof result !== "object") return [];
  const steps = [];
  const add = (stage, title, detail, tone = "neutral", evidence = []) => {
    steps.push({
      stage,
      title,
      detail: String(detail || "").trim(),
      tone,
      evidence: uniqueStrings(evidence),
    });
  };
  const nat = result.natProfile || result.natDecision || {};
  const destNat = nat.destination || {};
  const sourceNat = nat.source || {};
  const route = result.routeProfile || {};
  const inspection = result.inspectionProfile || {};
  const runtime = result.runtimeEvidence || {};

  add("input", "Flow tuple", firstLine(result.evidence) || "Tuple accepted for policy-model evaluation.", "info", firstLines(result.evidence, 1));

  if (destNat.evaluated || destNat.matched || destNat.reason) {
    add(
      "dnat",
      "Destination NAT",
      destNat.matched
        ? `${destNat.matchedRule || "destination NAT"} translated ${fmt.endpoint(destNat.originalDestinationIp, destNat.originalDestinationPort)} to ${fmt.endpoint(destNat.translatedDestinationIp, destNat.translatedDestinationPort)}.`
        : destNat.reason || "No destination NAT rule matched before policy evaluation.",
      destNat.matched ? "warn" : "neutral",
      destNat.evidence,
    );
  }

  const ruleTitle = result.defaultPolicy ? "Default policy" : result.matchedRule ? "Policy rule" : "Policy decision";
  const ruleDetail = result.defaultPolicy
    ? result.reason || "No enabled security rule matched; default drop applies."
    : result.matchedRule
      ? `${result.matchedRule} matched at index ${Number(result.matchedRuleIndex || 0) + 1}; verdict ${verdictLabel(result.verdict)}.`
      : result.reason || "No matching rule detail returned.";
  add("policy", ruleTitle, ruleDetail, verdictClass(result.verdict), [
    ...(result.matchedRule ? [`matched rule ${result.matchedRule}`] : []),
    result.reason || "",
  ]);

  if (result.appId || (Array.isArray(result.evidence) && result.evidence.some((line) => String(line).toLowerCase().includes("app")))) {
    add("app", "Application evidence", result.appId ? `App-ID ${result.appId} participated in matching.` : "Application evidence contributed to the policy explanation.", "info", (result.evidence || []).filter((line) => String(line).toLowerCase().includes("app")));
  }

  add("inspection", "Inspection posture", inspectionUiSummary(result) || "Inspection state unavailable.", inspectionTone(result.inspectionState, inspection), [
    ...(inspection.evidence || []),
    inspection.bypassReason || "",
    inspection.degradedBehavior || "",
  ]);

  if (route.evaluated || route.reason || route.destination || route.egressInterface) {
    add("route", "Route decision", routeUiSummary(result) || route.reason || "Route evaluation completed.", route.matched ? "info" : "warn", route.evidence);
  }

  if (sourceNat.evaluated || sourceNat.matched || sourceNat.reason) {
    add(
      "snat",
      "Source NAT",
      sourceNat.matched
        ? `${sourceNat.matchedRule || "source NAT"} ${sourceNat.masquerade ? "masquerades" : "translates"} ${sourceNat.originalSourceIp || "source"}.`
        : sourceNat.reason || "Source NAT did not match.",
      sourceNat.matched ? "info" : "neutral",
      sourceNat.evidence,
    );
  }

  if (runtime.queried) {
    const flowCount = (runtime.correlatedFlows || []).length;
    const alertCount = (runtime.correlatedAlerts || []).length;
    const sessionCount = (runtime.sessions || []).length;
    add("runtime", "Runtime correlation", `${sessionCount} conntrack, ${flowCount} EVE flow, and ${alertCount} alert match${flowCount + alertCount + sessionCount === 1 ? "" : "es"} sampled beside the policy model.`, runtime.state === "ready" ? "ok" : "info", [
      ...(runtime.evidence || []),
      ...(runtime.warnings || []),
    ]);
  }

  if (Array.isArray(result.warnings) && result.warnings.length) {
    add("warnings", "Review warnings", `${result.warnings.length} warning${result.warnings.length === 1 ? "" : "s"} returned with this explanation.`, "warn", result.warnings);
  }
  return steps;
}

function explanationTimelineCard(steps = []) {
  return explainProfileCard("timeline", h("h2", {}, h("span", { html: icon("changes", 16) }), "Explanation timeline"),
    steps.length
      ? h("ol", { class: "explain-timeline", dataset: { explainTimeline: "true" } }, steps.map(explanationTimelineStep))
      : h("div", { class: "note" }, "No timeline entries."));
}

function explanationTimelineStep(step = {}) {
  return h("li", { class: "explain-timeline-step " + (step.tone || "neutral"), dataset: { explainTimelineStage: step.stage || "" } },
    h("div", { class: "timeline-stage" }, step.stage || "step"),
    h("div", { class: "timeline-body" },
      h("strong", {}, step.title || "Decision step"),
      step.detail ? h("div", { class: "note" }, step.detail) : null,
      step.evidence?.length ? h("ul", { class: "timeline-evidence" }, step.evidence.slice(0, 3).map((line) => h("li", {}, line))) : null));
}

function firstLine(lines = []) {
  return firstLines(lines, 1)[0] || "";
}

function firstLines(lines = [], limit = 1) {
  return (Array.isArray(lines) ? lines : []).map((line) => String(line || "").trim()).filter(Boolean).slice(0, limit);
}

function inspectionTone(state = "", profile = {}) {
  if (state === "EXPLAIN_INSPECTION_STATE_IPS_PREVENT" || state === "EXPLAIN_INSPECTION_STATE_IDS_DETECT") return "info";
  if (state === "EXPLAIN_INSPECTION_STATE_BLOCKED_BEFORE_INSPECTION") return "neutral";
  if (profile?.bypassPossible || state === "EXPLAIN_INSPECTION_STATE_BYPASSED" || state === "EXPLAIN_INSPECTION_STATE_NOT_INSPECTED") return "warn";
  return "neutral";
}

function resultActions(packet, label, controls, resultNode) {
  const actions = handoffActions(packet, label);
  actions.prepend(
    h("button", {
      class: "btn primary",
      type: "button",
      title: "Review and stage an allow rule for this explained tuple",
      "aria-label": "Review and stage an allow rule for this explained tuple",
      dataset: { troubleshootAction: "stage-allow" },
      onclick: () => openTroubleshootRuleEditor("ACTION_ALLOW"),
    }, h("span", { html: icon("check", 16) }), "Stage allow"),
    h("button", {
      class: "btn danger",
      type: "button",
      title: "Review and stage a drop rule for this explained tuple",
      "aria-label": "Review and stage a drop rule for this explained tuple",
      dataset: { troubleshootAction: "stage-drop" },
      onclick: () => openTroubleshootRuleEditor("ACTION_DENY"),
    }, h("span", { html: icon("block", 16) }), "Stage drop"));
  if (controls) {
    actions.prepend(h("button", {
      class: "btn",
      type: "button",
      title: "Compare this flow against running and candidate policy",
      "aria-label": "Compare this flow against running and candidate policy",
      dataset: { troubleshootAction: "compare-policy" },
      disabled: state.compareLoading,
      onclick: () => runCompare(controls, resultNode),
    }, h("span", { html: icon("diff", 16) }), state.compareLoading ? "Comparing…" : "Compare running vs candidate"));
  }
  return actions;
}

async function openTroubleshootRuleEditor(action) {
  try {
    await session.load();
    const draft = buildTroubleshootRuleDraft(session.draft, state.query, state.result, action);
    openRuleEditorPrefilled(draft.rule, draft.insertAt, {
      beforeSave: (policy, rule) => stageTroubleshootGeneratedObjects(policy, draft.generated, rule),
    });
    toast("Review rule", `${draft.rule.name} is ready. Save the drawer to stage it to the candidate.`, "ok");
  } catch (e) {
    toast("Could not prepare rule", e.message, "bad");
  }
}

function stageTroubleshootGeneratedObjects(policy, generated = {}, rule = {}) {
  const addressMap = new Map();
  for (const object of generated.addresses || []) {
    const staged = stageTroubleshootAddress(policy, object);
    if (staged?.name) addressMap.set(object.name, staged.name);
  }
  rewriteRuleRefs(rule.sourceAddresses, addressMap);
  rewriteRuleRefs(rule.destinationAddresses, addressMap);

  const serviceMap = new Map();
  for (const object of generated.services || []) {
    const staged = stageTroubleshootService(policy, object);
    if (staged?.name) serviceMap.set(object.name, staged.name);
  }
  rewriteRuleRefs(rule.services, serviceMap);
}

function stageTroubleshootAddress(policy, object = {}) {
  if (!object.name || !object.cidr) return null;
  const addresses = (policy.addresses ||= []);
  const existing = addresses.find((addr) => addr.cidr === object.cidr);
  if (existing) return existing;
  const name = addresses.some((addr) => addr.name === object.name)
    ? uniqueTroubleshootName(addresses, object.name)
    : object.name;
  const staged = { ...object, name };
  addresses.push(staged);
  return staged;
}

function stageTroubleshootService(policy, object = {}) {
  if (!object.name || !object.protocol) return null;
  const services = (policy.services ||= []);
  const existing = services.find((svc) => equivalentService(svc, object));
  if (existing) return existing;
  const name = services.some((svc) => svc.name === object.name)
    ? uniqueTroubleshootName(services, object.name)
    : object.name;
  const staged = { ...object, name };
  services.push(staged);
  return staged;
}

function rewriteRuleRefs(refs, refMap) {
  if (!Array.isArray(refs) || !refMap?.size) return;
  refs.forEach((ref, idx) => {
    if (refMap.has(ref)) refs[idx] = refMap.get(ref);
  });
}

function compareEvidenceCard(controls, resultNode) {
  const runButton = controls ? h("button", {
    class: "btn",
    type: "button",
    title: "Compare this flow against running and candidate policy",
    "aria-label": "Compare this flow against running and candidate policy",
    dataset: { troubleshootAction: "compare-policy" },
    disabled: state.compareLoading,
    onclick: () => runCompare(controls, resultNode),
  }, h("span", { html: icon("diff", 16) }), state.compareLoading ? "Comparing…" : "Compare running vs candidate") : null;
  const body = [];
  if (state.compareLoading) {
    body.push(h("div", { class: "loading compact" }, "Comparing running and candidate policy…"));
  } else if (state.compare) {
    body.push(compareResultGrid(state.compare));
  } else {
    body.push(h("div", { class: "note" }, "Run a side-by-side explain check before commit. This calls the explain API for running and candidate policy without changing either policy."));
  }
  return card(h("div", { class: "compare-head" },
    h("h2", {}, h("span", { html: icon("diff", 16) }), "Running vs candidate"),
    runButton),
  ...body);
}

function compareResultGrid(compare = {}) {
  const deltas = compare.deltas || [];
  const deltaKeys = new Set(deltas.map((d) => d.key));
  const failedSides = [compare.running, compare.candidate].filter((entry) => entry?.error).length;
  return h("div", { class: "compare-evidence" },
    h("div", { class: "compare-delta-summary" },
      deltas.length
        ? deltas.map((d) => h("div", { class: "compare-delta" },
            h("strong", {}, d.label),
            h("span", {}, `${d.running || "—"} -> ${d.candidate || "—"}`)))
        : h("div", { class: "note" }, failedSides
            ? "Delta summary requires both sides; showing available evidence."
            : "No verdict, rule, NAT, route, or inspection deltas detected.")),
    h("div", { class: "compare-grid" },
      compareSideCard("Running", compare.running, deltaKeys),
      compareSideCard("Candidate", compare.candidate, deltaKeys)),
    routeSimulationPanel(boundedRouteSimulationFromCompare(compare)));
}

function routeSimulationPanel(model) {
  if (!model) return null;
  const rows = model.scenarios.flatMap((scenario) => {
    const deltas = scenario.deltas.length ? scenario.deltas : [{ field: "route", running: "aligned", candidate: "aligned", changed: false }];
    return deltas.map((delta) => h("tr", { dataset: { routeSimulationScenario: scenario.key } },
      labeledCell("Scenario", {}, h("strong", {}, scenario.label), h("div", { class: "note" }, `${scenario.nat}; ${scenario.tunnel}`)),
      labeledCell("Field", {}, delta.field),
      labeledCell("Running", { class: "mono data-wrap" }, delta.running),
      labeledCell("Candidate", { class: "mono data-wrap " + (delta.changed ? "warn" : "") }, delta.candidate)));
  });
  return h("div", { class: "route-simulation-panel", dataset: { troubleshootRouteSimulation: "bounded" } },
    h("div", { class: "section-head" },
      h("h3", {}, "Bounded route simulation"),
      pill(model.changed ? "route deltas" : "aligned", model.changed ? "warn" : "ok")),
    h("div", { class: "note" }, model.statement),
    h("div", { class: "table-wrap flat" },
      responsiveTable(["Scenario", "Field", "Running", "Candidate"], rows, { className: "responsive-evidence" })),
    h("div", { class: "note mono", dataset: { routeSimulationLimitations: "true" } }, model.limitations.join("; ")));
}

function compareSideCard(title, entry = {}, deltaKeys = new Set()) {
  if (entry.error) {
    return h("div", { class: "compare-side failed" },
      h("div", { class: "compare-side-title" }, title),
      h("div", { class: "alert-box bad compact" }, h("strong", {}, "Explain failed. "), entry.error));
  }
  const r = entry.result || {};
  const cues = compareCues(r);
  return h("div", { class: "compare-side " + verdictClass(r.verdict) },
    h("div", { class: "compare-side-title" },
      h("span", {}, title),
      pill(policyLabel(r), "info")),
    h("div", { class: "compare-fields" },
      compareField("verdict", "Verdict", verdictSummary(r), deltaKeys),
      compareField("rule", "Matched rule", ruleSummary(r), deltaKeys),
      compareField("policy", "Policy", policyLabel(r), deltaKeys),
      compareField("nat", "NAT", natUiSummary(r), deltaKeys),
      compareField("route", "Route", routeUiSummary(r), deltaKeys),
      compareField("inspection", "Inspection", inspectionUiSummary(r), deltaKeys)),
    cues.length ? h("div", { class: "compare-cues" }, cues.map((cue) => h("div", { class: "alert-box warn compact" }, cue))) : null);
}

function compareField(key, label, value, deltaKeys) {
  return h("div", { class: "compare-field " + (deltaKeys.has(key) ? "changed" : "") },
    h("span", {}, label),
    h("strong", {}, value || "—"));
}

function focusPacketCapture(node) {
  const target = node?.querySelector?.(".capture-command-row");
  if (target && typeof target.scrollIntoView === "function") {
    target.scrollIntoView({ block: "center" });
  }
}

function shouldAutoRun(route = {}) {
  const q = normalizeTroubleshootRoute(route);
  if (!q.run) return false;
  if (!q.flowId && !q.src && !q.dst) return false;
  if (q.intent === "compare") {
    const key = compareQueryKey(compareQueriesFromRouteState(q));
    return !(state.compare && state.compareKey === key);
  }
  const key = troubleshootQueryKey(explainQueryFromRouteState(q));
  return !(state.result && state.resultKey === key);
}

function runtimeEvidenceCard(p) {
  if (!p || !p.queried) return null;
  const sessions = p.sessions || [];
  const correlatedFlows = p.correlatedFlows || [];
  const correlatedAlerts = p.correlatedAlerts || [];
  return explainProfileCard("runtime", h("h2", {}, h("span", { html: icon("traffic", 16) }), "Runtime evidence"),
    h("dl", { class: "kv explain-profile" },
      kv("State", p.state || "unknown"),
      kv("Detail", p.detail || "—"),
      p.runningPolicyVersion ? kv("Running policy", `v${p.runningPolicyVersion}`) : null,
      p.policyContext ? kv("Context", p.policyContext) : null,
      kv("Conntrack matches", String(sessions.length)),
      kv("Correlated EVE flows", String(correlatedFlows.length)),
      kv("Correlated EVE alerts", String(correlatedAlerts.length))),
    h("div", { class: "note" }, "Runtime evidence is sampled from the live dataplane at query time and does not change the policy-model verdict above."),
    sessions.length ? h("div", { class: "runtime-session-list" }, sessions.slice(0, 5).map(runtimeSessionRow)) : null,
    correlatedFlows.length || correlatedAlerts.length ? correlatedEvePanel(correlatedFlows, correlatedAlerts, p) : null,
    p.evidence?.length ? h("ol", { class: "trace-list compact-list" }, p.evidence.map((line) => h("li", {}, line))) : null,
    p.warnings?.length ? h("ol", { class: "trace-list warn compact-list" }, p.warnings.map((line) => h("li", {}, line))) : null);
}

function engineHealthCard(status = null, runtimeEvidence = null) {
  const model = engineHealthContext(status, runtimeEvidence);
  if (!model.available) return null;
  return explainProfileCard("engine-health", h("h2", {}, h("span", { html: icon("settings", 16) }), "Engine health at query time"),
    h("dl", { class: "kv explain-profile" },
      kv("Inspection", model.label),
      kv("Detail", model.detail),
      kv("Engine", model.engineLabel),
      model.failureBehavior ? kv("Failure behavior", model.failureBehavior) : null,
      kv("Bypass possible", model.bypassPossible ? "yes" : "no")),
    h("div", { class: "note" }, "Current runtime health is sampled beside Explain and does not change the policy-model verdict."),
    model.engines.length ? h("div", { class: "runtime-session-list" }, model.engines.map(engineHealthRow)) : null,
    model.warnings.length ? h("ol", { class: "trace-list warn compact-list" }, model.warnings.map((line) => h("li", {}, line))) : null);
}

function engineHealthRow(engine = {}) {
  return h("div", { class: "runtime-session" },
    h("div", { class: "mono" }, engine.name || "engine"),
    h("div", { class: "note" }, [engine.role, engine.mode, engine.state].filter(Boolean).join(" · ") || "runtime engine"),
    engine.detail ? h("div", { class: "note" }, engine.detail) : null);
}

export function engineHealthContext(status = null, runtimeEvidence = null) {
  if (!runtimeEvidence?.queried) return { available: false };
  const posture = inspectionPostureSummary(status || {});
  const engines = engineHealthRows(status);
  const warnings = engineHealthWarnings(status);
  return {
    available: true,
    state: posture.state || "unknown",
    cls: postureClass(posture.state),
    label: posture.state || "unknown",
    detail: posture.detail || "Runtime inspection status is unavailable.",
    engineLabel: posture.engine || "inspection engine unavailable",
    failureBehavior: posture.failureBehavior || "",
    bypassPossible: Boolean(posture.bypassPossible),
    engines,
    warnings,
  };
}

function engineHealthRows(status = null) {
  return (Array.isArray(status?.engines) ? status.engines : [])
    .filter((engine) => {
      const text = [field(engine, "name"), field(engine, "role"), field(engine, "detail")].join(" ").toLowerCase();
      return /ids-ips|vector|eve|inspection|telemetry/.test(text);
    })
    .slice(0, 4)
    .map((engine) => ({
      name: field(engine, "name") || "engine",
      role: field(engine, "role"),
      mode: field(engine, "mode"),
      state: field(engine, "state"),
      detail: field(engine, "detail"),
    }));
}

function engineHealthWarnings(status = null) {
  return (Array.isArray(status?.warnings) ? status.warnings : [])
    .map((warning) => typeof warning === "string" ? warning : field(warning, "detail") || field(warning, "message") || field(warning, "summary"))
    .map((warning) => String(warning || "").trim())
    .filter((warning) => /engine|inspection|ids-ips|vector|runtime|ids|ips|eve/i.test(warning))
    .slice(0, 5);
}

function field(obj = {}, camel, fallback = "") {
  const snake = camel.replace(/[A-Z]/g, (m) => "_" + m.toLowerCase());
  return obj?.[camel] || obj?.[snake] || fallback;
}

function postureClass(state = "") {
  if (state === "ready" || state === "disabled") return "ok";
  if (state === "failed-open" || state === "failed-closed") return "bad";
  if (state === "degraded") return "warn";
  return "neutral";
}

function runtimeSessionRow(s = {}) {
  return h("div", { class: "runtime-session" },
    h("div", { class: "mono" }, `${s.protocol || "IP"} ${fmt.endpoint(s.srcIp, s.srcPort)} -> ${fmt.endpoint(s.destIp, s.destPort)}`),
    h("div", { class: "note" },
      [s.state, s.assured ? "assured" : "", s.timeoutSeconds ? `${s.timeoutSeconds}s timeout` : ""].filter(Boolean).join(" · ") || "live session"),
    h("div", { class: "note" }, `${fmt.compactNum(fmt.num(s.packets))} packets · ${fmt.bytes(s.bytes)}`),
    s.raw ? h("pre", { class: "mono data-pre" }, s.raw) : null);
}

function correlatedEvePanel(flows = [], alerts = [], runtime = {}) {
  const rows = correlatedEveRows(flows, alerts, runtime);
  if (!rows.length) return null;
  return h("div", { class: "table-wrap flat", dataset: { correlatedEveTable: "true" } },
    responsiveTable(["Type", "Tuple", "Signal", "Event policy", "Volume", { label: "Pivot", attrs: { class: "actions-col" } }],
      rows.map((row) => h("tr", {
        dataset: {
          correlatedEveRow: row.kind,
          correlatedEveFlowId: row.flowId || "",
        },
      },
        labeledCell("Type", {}, pill(row.typeLabel, row.tone)),
        labeledCell("Tuple", { class: "mono" }, row.tuple),
        labeledCell("Signal", {}, h("strong", {}, row.signal), row.detail ? h("div", { class: "note" }, row.detail) : null),
        labeledCell("Event policy", {}, h("strong", {}, row.policyStamp), h("div", { class: "note" }, row.policyFreshness)),
        labeledCell("Volume", {}, row.volume || "—"),
        labeledCell("Pivot", { class: "cell-actions" }, row.href ? h("a", {
          class: "btn sm ghost",
          href: row.href,
          title: `${row.pivotLabel} for correlated ${row.kind}`,
          "aria-label": `${row.pivotLabel} for correlated ${row.kind}`,
          dataset: { troubleshootAction: row.kind === "alert" ? "open-correlated-threat" : "open-correlated-traffic" },
        }, h("span", { html: icon(row.kind === "alert" ? "threats" : "traffic", 14) }), row.pivotLabel) : "—"))),
      { className: "troubleshoot-correlated-eve-table" }));
}

export function correlatedEveRows(flows = [], alerts = [], runtime = {}) {
  const flowRows = flows.slice(0, 5).map((f = {}) => ({
    kind: "flow",
    typeLabel: "flow",
    tone: "info",
    tuple: `flow ${fmt.endpoint(f.srcIp, f.srcPort)} -> ${fmt.endpoint(f.destIp, f.destPort)}`,
    signal: f.appId || f.appProtocol || "unknown-app",
    detail: [f.protocol, f.flowId ? `flow_id=${f.flowId}` : ""].filter(Boolean).join(" · "),
    policyStamp: eventPolicyStamp(f),
    policyFreshness: eventPolicyFreshness(f, runtime),
    volume: `${fmt.bytes((Number(f.bytesToServer) || 0) + (Number(f.bytesToClient) || 0))} · ${fmt.compactNum(fmt.num(f.packets))} packets`,
    flowId: f.flowId || "",
    href: f.flowId ? trafficFlowHash(f.flowId) : "",
    pivotLabel: "Open in Traffic",
  }));
  const alertRows = alerts.slice(0, 5).map((a = {}) => ({
    kind: "alert",
    typeLabel: "alert",
    tone: "bad",
    tuple: `alert ${fmt.endpoint(a.srcIp, a.srcPort)} -> ${fmt.endpoint(a.destIp, a.destPort)}`,
    signal: a.threatId || a.signature || "unknown-threat",
    detail: [a.threatSeverity || fmt.severity(a.severity).label, a.action, a.flowId ? `flow_id=${a.flowId}` : "", a.signatureId ? `SID ${a.signatureId}` : ""].filter(Boolean).join(" · "),
    policyStamp: eventPolicyStamp(a),
    policyFreshness: eventPolicyFreshness(a, runtime),
    volume: "—",
    flowId: a.flowId || "",
    href: a.flowId ? threatFlowHash(a.flowId) : "",
    pivotLabel: "Open in Threats",
  }));
  return [...flowRows, ...alertRows];
}

function eventPolicyStamp(event = {}) {
  const version = Number(event.policyVersion || 0);
  if (event.policyVersionKnown && version > 0) return event.policyStamp || event.eventPolicyStamp || `v${version}`;
  return "unknown event policy stamp";
}

function eventPolicyFreshness(event = {}, runtime = {}) {
  if (event.policyFreshness || event.eventPolicyFreshness) return event.policyFreshness || event.eventPolicyFreshness;
  if (!event.policyVersionKnown || Number(event.policyVersion || 0) <= 0) return "freshness unknown";
  const eventVersion = Number(event.policyVersion || 0);
  const runningVersion = Number(runtime.runningPolicyVersion || 0);
  if (!runningVersion) return "freshness unknown";
  if (eventVersion === runningVersion) return `current at query time (running v${runningVersion})`;
  if (eventVersion < runningVersion) return `stale at query time (running v${runningVersion})`;
  return `newer than running policy at query time (running v${runningVersion})`;
}

function trafficFlowHash(flowId) {
  const q = new URLSearchParams();
  q.set("mode", "flows");
  q.set("flowId", flowId);
  q.set("limit", "100");
  return "#/traffic?" + q.toString();
}

function threatFlowHash(flowId) {
  const q = new URLSearchParams();
  q.set("flowId", flowId);
  q.set("limit", "100");
  return "#/threats?" + q.toString();
}

function inspectionProfileCard(p) {
  if (!p) return null;
  return explainProfileCard("inspection", h("h2", {}, h("span", { html: icon("settings", 16) }), "Inspection profile"),
    h("dl", { class: "kv explain-profile" },
      kv("Engine", p.engine || "none"),
      kv("IDS/IPS", p.idsEnabled ? clean(p.idsMode, "IDS_MODE_") : "disabled"),
      kv("Failure behavior", p.failureBehavior ? clean(p.failureBehavior, "IDS_FAILURE_BEHAVIOR_") : "not applicable"),
      kv("Flow offload", p.flowOffloadEnabled ? "enabled" : "disabled"),
      kv("Bypass possible", p.bypassPossible ? "yes" : "no"),
      p.bypassReason ? kv("Bypass reason", p.bypassReason) : null,
      p.inspectionOrder ? kv("Inspection order", p.inspectionOrder) : null,
      p.degradedBehavior ? kv("Degraded behavior", p.degradedBehavior) : null),
    p.evidence?.length ? h("ol", { class: "trace-list compact-list" }, p.evidence.map((line) => h("li", {}, line))) : null);
}

function natProfileCard(p) {
  if (!p) return null;
  const dest = p.destination || {};
  const source = p.source || {};
  const evidence = natEvidence(p);
  return explainProfileCard("nat", h("h2", {}, h("span", { html: icon("nat", 16) }), "NAT decision"),
    h("dl", { class: "kv explain-profile" },
      kv("Summary", natProfileSummary(p)),
      kv("Destination NAT", dest.matched ? dest.matchedRule || "matched" : dest.evaluated ? "no match" : "not evaluated"),
      dest.matched ? kv("Destination translation", `${fmt.endpoint(dest.originalDestinationIp, dest.originalDestinationPort)} -> ${fmt.endpoint(dest.translatedDestinationIp, dest.translatedDestinationPort)}`) : null,
      dest.reason ? kv("Destination reason", dest.reason) : null,
      kv("Source NAT", source.matched ? source.matchedRule || "matched" : source.evaluated ? "no match" : "not evaluated"),
      source.matched ? kv("Source translation", source.masquerade ? `${source.originalSourceIp || "source"} -> masquerade` : `${source.originalSourceIp || "source"} -> ${source.translatedSourceIp || "translated source unknown"}`) : null,
      source.reason ? kv("Source reason", source.reason) : null),
    natProfileLines(p).length ? h("ol", { class: "trace-list compact-list" }, natProfileLines(p).map((line) => h("li", {}, line))) : null,
    evidence.length ? h("ol", { class: "trace-list compact-list" }, evidence.map((line) => h("li", {}, line))) : null);
}

function routeProfileCard(p) {
  if (!p) return null;
  return explainProfileCard("route", h("h2", {}, h("span", { html: icon("changes", 16) }), "Route decision"),
    h("dl", { class: "kv explain-profile" },
      kv("Evaluated", p.evaluated ? "yes" : "no"),
      kv("Source", p.source || "unknown"),
      kv("Matched", p.matched ? "yes" : "no"),
      p.destination ? kv("Destination", p.destination) : null,
      p.nextHop ? kv("Next hop", p.nextHop) : null,
      p.egressInterface ? kv("Egress interface", p.egressInterface) : null,
      p.metric ? kv("Metric", String(p.metric)) : null,
      p.reason ? kv("Reason", p.reason) : null),
    p.evidence?.length ? h("ol", { class: "trace-list compact-list" }, p.evidence.map((line) => h("li", {}, line))) : null);
}

function explainProfileCard(kind, titleNode, ...children) {
  const el = card(titleNode, ...children);
  el.dataset.explainProfile = kind;
  return el;
}

function listCard(title, lines = [], iconName, kind = "") {
  return card(h("h2", {}, h("span", { html: icon(iconName, 16) }), title),
    lines.length
      ? h("ol", { class: "trace-list " + kind }, lines.map((line) => h("li", {}, line)))
      : h("div", { class: "note" }, "No entries."));
}

function packetCaptureCard(query, result, controls = null) {
  const route = controls ? routeStateFromControls(controls) : routeStateFromExplainQuery(query || {});
  const captureContext = normalizeTroubleshootCaptureContext(route).captureContext;
  const iface = input("text", route.captureInterface, "ens5, eth0, wg0, or any");
  iface.dataset.captureField = "interface";
  const duration = input("number", route.captureDuration, "seconds");
  duration.min = "1"; duration.max = "60";
  duration.dataset.captureField = "duration";
  const packets = input("number", route.capturePackets, "packets");
  packets.min = "1"; packets.max = "10000";
  packets.dataset.captureField = "packets";
  const snaplen = input("number", route.captureSnaplen, "bytes");
  snaplen.min = "96"; snaplen.max = "4096";
  snaplen.dataset.captureField = "snaplen";
  const command = h("code", { class: "capture-command mono", dataset: { captureCommand: "true" } });
  const detail = h("dl", { class: "kv capture-detail", dataset: { captureDetail: "true" } });
  const warnings = h("div", { class: "capture-warnings", dataset: { captureWarnings: "true" } });
  const source = h("div", { class: "note" });
  const jobBox = h("div", { class: "capture-warnings", dataset: { captureJobResult: "true" } });
  const historyBox = h("div", { class: "capture-history-list", dataset: { captureHistory: "true" } });
  let current = null;
  let currentFromServer = false;
  let currentJob = null;
  let planButton = null;
  let startButton = null;
  let historyButton = null;

  function body(extra = {}) {
    return {
      interface: iface.value.trim(),
      protocol: query?.protocol || "PROTOCOL_ANY",
      srcIp: query?.srcIp || "",
      srcPort: numberOrZero(query?.srcPort),
      destIp: query?.destIp || "",
      destPort: numberOrZero(query?.destPort),
      flowId: query?.flowId || "",
      durationSeconds: numberOrZero(duration.value),
      packetCount: numberOrZero(packets.value),
      snaplenBytes: numberOrZero(snaplen.value),
      label: result?.matchedRule || "flow",
      ...extra,
    };
  }

  function update() {
    applyPlan(buildCapturePlan(body()), false);
    currentJob = null;
    jobBox.replaceChildren();
    syncCaptureRoute();
  }

  function applyPlan(plan, fromServer) {
    current = normalizeCapturePlan(plan, body());
    currentFromServer = Boolean(fromServer);
    command.textContent = current.command;
    detail.replaceChildren(
      ...kv("BPF filter", current.bpfFilter || current.filter),
      ...kv("Output path", current.outputPath),
      ...kv("Limits", `${current.durationSeconds}s, ${current.packetCount} packets, ${current.snaplenBytes} byte snaplen`));
    source.textContent = fromServer
      ? "Server-validated plan from the audited Phragma API."
      : "Local preview; refresh the server plan before execution.";
    warnings.replaceChildren(...(current.warnings.length
      ? current.warnings.map((w) => h("div", { class: "alert-box warn compact" }, w))
      : [h("div", { class: "note" }, "Capture is scoped to this flow tuple and bounded by time, packet count, and snaplen.")]));
  }

  async function refreshServerPlan(quiet = false) {
    setCaptureBusy(true);
    if (!quiet) source.textContent = "Requesting server plan…";
    try {
      const resp = await api.planPacketCapture(body());
      applyPlan(resp.plan, true);
      if (!quiet) syncCaptureRoute();
      if (!quiet) toast("Capture plan ready", "Server validated the bounded packet-capture plan.", "ok");
    } catch (err) {
      if (!quiet) toast("Capture plan failed", err.message, "warn");
      else source.textContent = `Local preview; server plan unavailable: ${err.message}`;
    } finally {
      setCaptureBusy(false);
    }
  }

  async function startCapture() {
    const confirmed = await confirmDialog({
      title: "Start packet capture",
      message: "This starts a bounded tcpdump job on the firewall host and writes the pcap under the configured log directory.",
      confirmLabel: "Start capture",
      danger: true,
    });
    if (!confirmed) return;
    setCaptureBusy(true);
    jobBox.replaceChildren(h("div", { class: "loading compact" }, "Starting capture…"));
    try {
      const resp = await api.startPacketCapture(body({ ackCapture: true }));
      const job = resp.job || {};
      currentJob = job;
      if (job.plan) applyPlan(job.plan, true);
      const ok = job.state === "completed";
      const bytesWritten = job.bytesWritten ?? job.bytes_written;
      const ref = captureReference(job.plan || current, job);
      jobBox.replaceChildren(
        h("div", { class: "alert-box " + (ok ? "ok" : "warn") + " compact" },
          h("strong", {}, ok ? "Capture completed. " : "Capture finished. "),
          job.detail || "No detail returned.",
          bytesWritten != null ? ` ${bytesWritten} bytes written.` : ""),
        h("dl", { class: "kv capture-detail", dataset: { captureDetail: "job" } },
          ...kv("Capture reference", captureReferenceLabel(ref)),
          ref.sha256 ? kv("PCAP SHA-256", ref.sha256) : null,
          ref.completedAt ? kv("Completed", fmt.absTime(ref.completedAt)) : null),
        h("div", { class: "flex wrap" },
          h("a", {
            class: "btn sm",
            href: captureAuditHash(ref),
            title: "Open audit evidence for this packet capture",
            "aria-label": "Open audit evidence for this packet capture",
            dataset: { captureAction: "audit" },
          }, h("span", { html: icon("clock", 14) }), "View audit evidence")));
      syncCaptureRoute();
      await refreshCaptureHistory(true);
      toast(ok ? "Capture completed" : "Capture finished", job.detail || "Packet-capture job returned.", ok ? "ok" : "warn");
    } catch (err) {
      const detailText = err?.message || String(err || "packet capture failed");
      currentJob = {
        state: "failed",
        detail: detailText,
        plan: current || normalizeCapturePlan(null, body()),
        completedAt: new Date().toISOString(),
      };
      syncCaptureRoute();
      jobBox.replaceChildren(h("div", { class: "alert-box bad compact" }, detailText));
      toast("Packet capture failed", detailText, "bad");
    } finally {
      setCaptureBusy(false);
    }
  }

  function setCaptureBusy(busy) {
    if (planButton) planButton.disabled = busy;
    if (startButton) startButton.disabled = busy;
  }

  async function refreshCaptureHistory(quiet = false) {
    if (historyButton) historyButton.disabled = true;
    if (!quiet) historyBox.replaceChildren(h("div", { class: "loading compact" }, "Loading recent captures..."));
    try {
      const resp = await api.packetCaptures({ limit: 8, flowId: query?.flowId || "" });
      renderCaptureHistory(resp);
    } catch (err) {
      const adminOnly = err?.status === 401 || err?.status === 403;
      historyBox.replaceChildren(h("div", { class: "note" },
        adminOnly ? "Recent capture artifacts require admin access." : `Capture history unavailable: ${err?.message || err}`));
    } finally {
      if (historyButton) historyButton.disabled = false;
    }
  }

  function renderCaptureHistory(resp = {}) {
    const items = captureHistoryItems(resp);
    if (!items.length) {
      historyBox.replaceChildren(h("div", { class: "note" }, "No completed capture artifacts found."));
      return;
    }
    historyBox.replaceChildren(...items.map(captureHistoryRow));
  }

  function captureHistoryRow(ref) {
    const statusClass = ref.state === "completed" ? "ok" : ref.state === "unavailable" ? "warn" : "info";
    const artifactId = ref.artifactId || ref.id || "";
    return h("div", {
      class: "capture-history-row",
      dataset: {
        captureArtifactRow: artifactId,
        captureArtifactId: artifactId,
        captureRetentionState: ref.retentionState || "",
      },
    },
      h("div", { class: "capture-history-main" },
        h("div", { class: "capture-history-title" },
          h("strong", {}, ref.filename || ref.artifactId || ref.id || "capture artifact"),
          pill(ref.state || "indexed", statusClass),
          ref.integrity?.label ? pill(`integrity ${ref.integrity.label}`, ref.integrity.tone) : null,
          ref.retentionSummary ? pill(ref.retentionSummary, ref.retentionTone) : null),
        h("dl", { class: "kv capture-detail", dataset: { captureDetail: "artifact" } },
          ref.completedAt ? kv("Completed", fmt.absTime(ref.completedAt)) : null,
          ref.integrity?.detail ? kv("Integrity", ref.integrity.detail) : null,
          ref.bytesWritten ? kv("Size", fmt.bytes(ref.bytesWritten)) : null,
          ref.sha256 ? kv("SHA-256", ref.sha256) : null,
          ref.retainUntil ? kv("Retain until", fmt.absTime(ref.retainUntil)) : null,
          ref.caseId ? kv("Case", ref.caseId) : null,
          ref.retentionReason ? kv("Retention reason", ref.retentionReason) : null,
          ref.flowId ? kv("Flow ID", ref.flowId) : null,
          ref.bpfFilter ? kv("Filter", ref.bpfFilter) : null,
          ref.detail ? kv("Detail", ref.detail) : null)),
      h("div", { class: "capture-history-actions" },
        ref.artifactId && ref.retentionState !== "retained" ? h("button", { class: "btn sm ghost", type: "button", title: "Retain this packet-capture artifact", "aria-label": "Retain this packet-capture artifact", onclick: () => updateCaptureRetention(ref, "retained"), dataset: { captureAction: "retain" } },
          h("span", { html: icon("shield", 14) }), "Retain") : null,
        ref.artifactId && ref.retentionState === "retained" ? h("button", { class: "btn sm ghost", type: "button", title: "Release retention for this packet-capture artifact", "aria-label": "Release retention for this packet-capture artifact", onclick: () => updateCaptureRetention(ref, "released"), dataset: { captureAction: "release" } },
          h("span", { html: icon("check", 14) }), "Release") : null,
        ref.artifactId ? h("button", { class: "btn sm", type: "button", title: "Download this packet-capture artifact", "aria-label": "Download this packet-capture artifact", onclick: () => downloadCaptureArtifact(ref), dataset: { captureAction: "download" } },
          h("span", { html: icon("download", 14) }), "Download") : null,
        h("a", { class: "btn sm ghost", href: captureAuditHash(ref), title: "Open audit evidence for this packet capture", "aria-label": "Open audit evidence for this packet capture", dataset: { captureAction: "audit" } }, h("span", { html: icon("clock", 14) }), "Audit")));
  }

  async function updateCaptureRetention(ref, state) {
    if (!ref?.artifactId) return;
    const retaining = state === "retained";
    const reason = h("textarea", {
      class: "input",
      rows: "3",
      maxlength: "256",
      required: true,
      placeholder: retaining ? "Incident evidence review" : "Case review complete",
      dataset: { captureRetentionField: "reason" },
    }, ref.retentionReason || "");
    const caseId = h("input", {
      class: "input mono",
      maxlength: "128",
      value: ref.caseId || "",
      placeholder: "INC-2026-001",
      dataset: { captureRetentionField: "case-id" },
    });
    const defaultUntil = ref.retainUntil || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().replace(/\.000Z$/, "Z");
    const retainUntil = retaining ? h("input", {
      class: "input mono",
      value: defaultUntil,
      placeholder: "2026-07-19T00:00:00Z",
      dataset: { captureRetentionField: "retain-until" },
    }) : null;
    const body = h("div", { class: "capture-retention-form", dataset: { captureRetentionForm: "true" } },
      retaining ? h("label", { class: "field" }, h("span", {}, "Retain until"), retainUntil) : null,
      h("label", { class: "field" }, h("span", {}, "Reason"), reason),
      h("label", { class: "field" }, h("span", {}, "Case"), caseId));
    const confirmed = await confirmDialog({
      title: retaining ? "Retain packet capture" : "Release packet capture",
      message: retaining
        ? "This records retention metadata for the completed pcap sidecar."
        : "This marks the completed pcap sidecar as released from retention metadata.",
      confirmLabel: retaining ? "Retain" : "Release",
      danger: retaining,
      body,
    });
    if (!confirmed) return;
    const payload = {
      state: captureRetentionApiState(state),
      retentionReason: reason.value.trim(),
      caseId: caseId.value.trim(),
      ackRetentionChange: true,
    };
    if (retaining) payload.retainUntil = retainUntil.value.trim();
    if (!payload.retentionReason) {
      toast("Retention reason required", "Add a short operator reason before updating capture metadata.", "warn");
      return;
    }
    setCaptureBusy(true);
    try {
      await api.setPacketCaptureRetention(ref.artifactId, payload);
      await refreshCaptureHistory(true);
      toast(retaining ? "Capture retained" : "Capture released", ref.filename || ref.artifactId, "ok");
    } catch (err) {
      toast("Retention update failed", err?.message || String(err || "packet capture retention update failed"), "bad");
    } finally {
      setCaptureBusy(false);
    }
  }

  async function downloadCaptureArtifact(ref) {
    if (!ref?.artifactId) return;
    try {
      const blob = await api.downloadPacketCapture(ref.artifactId);
      downloadBlob(captureArtifactFilename(ref), blob);
      toast("Capture downloaded", captureArtifactFilename(ref), "ok");
    } catch (err) {
      toast("Download failed", err?.message || String(err || "packet capture download failed"), "bad");
    }
  }

  function capturePacket() {
    return captureHandoffPacket({
      query,
      result,
      capturePlan: { ...(current || normalizeCapturePlan(null, body())), source: currentFromServer ? "server" : "local-preview" },
      captureJob: currentJob,
    }, { route: currentRoute() });
  }

  function syncCaptureRoute() {
    if (!controls || !current) return;
    controls.capture.interface = current.interface || CAPTURE_LIMITS.defaultInterface;
    controls.capture.duration = String(current.durationSeconds || CAPTURE_LIMITS.defaultDurationSeconds);
    controls.capture.packets = String(current.packetCount || CAPTURE_LIMITS.defaultPacketCount);
    controls.capture.snaplen = String(current.snaplenBytes || CAPTURE_LIMITS.defaultSnaplenBytes);
    controls.capture.captureContext = captureContext;
    syncRouteFromControls(controls, { run: true, intent: "capture" });
  }

  [iface, duration, packets, snaplen].forEach((el) => el.addEventListener("input", update));
  planButton = h("button", { class: "btn", type: "button", title: "Refresh server-validated packet-capture plan", "aria-label": "Refresh server-validated packet-capture plan", onclick: () => refreshServerPlan(), dataset: { captureAction: "server-plan" } },
    h("span", { html: icon("refresh", 16) }), "Server plan");
  startButton = h("button", { class: "btn danger", type: "button", title: "Start bounded packet capture on the firewall host", "aria-label": "Start bounded packet capture on the firewall host", onclick: startCapture, dataset: { captureAction: "start" } },
    h("span", { html: icon("download", 16) }), "Start capture");
  historyButton = h("button", { class: "btn sm ghost", type: "button", title: "Refresh recent packet captures", "aria-label": "Refresh recent packet captures", onclick: () => refreshCaptureHistory(), dataset: { captureAction: "refresh-history" } },
    h("span", { html: icon("refresh", 14) }), "Refresh");
  applyPlan(buildCapturePlan(body()), false);
  setTimeout(() => refreshServerPlan(true), 0);
  setTimeout(() => refreshCaptureHistory(true), 0);

  const root = card(h("h2", {}, h("span", { html: icon("download", 16) }), "Packet capture"),
    h("div", { class: "note" }, "Use the audited API to run a bounded host capture, or copy the generated command for break-glass validation."),
    captureContext === "log-plan" ? h("div", { class: "alert-box info compact", dataset: { captureContext: "log-plan" } },
      h("strong", {}, "From log plan. "),
      "System Logs supplied this bounded capture plan; review the server plan and use Start capture only when ready.") : null,
    h("div", { class: "capture-controls" },
      h("label", { class: "field" }, h("span", {}, "Interface"), iface),
      h("label", { class: "field" }, h("span", {}, "Duration"), duration),
      h("label", { class: "field" }, h("span", {}, "Packets"), packets),
      h("label", { class: "field" }, h("span", {}, "Snaplen"), snaplen)),
    h("div", { class: "flex wrap" },
      planButton,
      startButton,
      h("button", { class: "btn", type: "button", title: "Pin packet-capture handoff to the investigation case", "aria-label": "Pin packet-capture handoff to the investigation case", onclick: () => pinHandoff(capturePacket(), "capture"), dataset: { captureAction: "pin" } }, h("span", { html: icon("inbox", 16) }), "Pin to case"),
      h("button", { class: "btn", type: "button", title: "Copy packet-capture handoff text", "aria-label": "Copy packet-capture handoff text", onclick: () => copyHandoff(capturePacket(), "capture"), dataset: { captureAction: "copy-handoff" } }, h("span", { html: icon("copy", 16) }), "Copy handoff"),
      h("button", { class: "btn", type: "button", title: "Export packet-capture handoff JSON", "aria-label": "Export packet-capture handoff JSON", onclick: () => exportHandoff(capturePacket(), "capture"), dataset: { captureAction: "export-json" } }, h("span", { html: icon("download", 16) }), "Export JSON")),
    h("div", { class: "capture-command-row" },
      command,
      h("button", { class: "icon-btn", type: "button", title: "Copy capture command", "aria-label": "Copy capture command", onclick: () => copyCaptureCommand(current?.command || ""), html: icon("copy", 16), dataset: { captureAction: "copy-command" } })),
    source,
    detail,
    warnings,
    jobBox,
    h("div", { class: "capture-history-head" },
      h("div", {},
        h("strong", {}, "Recent captures"),
        h("span", {}, "Completed PCAP artifacts from the firewall host")),
      historyButton),
    historyBox);
  root.dataset.captureWorkbench = "troubleshoot";
  return root;
}

function downloadBlob(filename, blob) {
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

async function copyCaptureCommand(command) {
  try {
    await navigator.clipboard.writeText(command);
    toast("Capture command copied", "Run it on the firewall host when API execution is unavailable.", "ok");
  } catch {
    toast("Copy failed", "Select and copy the command manually.", "warn");
  }
}

function handoffActions(packet, label) {
  return h("div", { class: "flex wrap", style: { margin: "12px 0 16px" } },
    h("button", { class: "btn", type: "button", title: `Pin ${label} handoff to the investigation case`, "aria-label": `Pin ${label} handoff to the investigation case`, dataset: { troubleshootAction: "pin-handoff" }, onclick: () => pinHandoff(packet, label) }, h("span", { html: icon("inbox", 16) }), "Pin to case"),
    h("button", { class: "btn", type: "button", title: `Copy ${label} handoff text`, "aria-label": `Copy ${label} handoff text`, dataset: { troubleshootAction: "copy-handoff" }, onclick: () => copyHandoff(packet, label) }, h("span", { html: icon("copy", 16) }), "Copy handoff"),
    h("button", { class: "btn", type: "button", title: `Export ${label} handoff JSON`, "aria-label": `Export ${label} handoff JSON`, dataset: { troubleshootAction: "export-handoff" }, onclick: () => exportHandoff(packet, label) }, h("span", { html: icon("download", 16) }), "Export JSON"));
}

function pinHandoff(packet, label = "investigation") {
  try {
    const result = pinInvestigationPacket(packet);
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || `Selected ${label} evidence could not be pinned.`, "bad");
  }
}

async function copyHandoff(packet, label = "investigation") {
  try {
    await navigator.clipboard.writeText(investigationPacketText(packet));
    toast("Handoff copied", `Selected ${label} evidence copied as plain text.`, "ok");
  } catch {
    toast("Copy failed", "Select the evidence and copy it manually.", "warn");
  }
}

function exportHandoff(packet, label = "investigation") {
  const text = investigationPacketJson(packet);
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: investigationPacketFilename(packet) });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  toast("Handoff exported", `Downloaded selected ${label} evidence as JSON.`, "ok");
}

function currentRoute() {
  return location.hash || "#/troubleshoot";
}

function normalizeCapturePlan(plan, fallbackInput) {
  const fallback = buildCapturePlan(fallbackInput);
  const p = plan || {};
  return {
    ...fallback,
    ...p,
    bpfFilter: p.bpfFilter || p.filter || fallback.filter,
    filter: p.filter || p.bpfFilter || fallback.filter,
    command: p.command || fallback.command,
    outputPath: p.outputPath || fallback.outputPath,
    durationSeconds: Number(p.durationSeconds || fallback.durationSeconds),
    packetCount: Number(p.packetCount || fallback.packetCount),
    snaplenBytes: Number(p.snaplenBytes || fallback.snaplenBytes),
    warnings: Array.isArray(p.warnings) ? p.warnings : fallback.warnings,
  };
}

function ensureTroubleshootAddress(policy, generated, ip, prefix) {
  const cidr = ipToCidr(ip);
  const existing = (policy.addresses || []).find((addr) => addr.cidr === cidr);
  if (existing?.name) return existing.name;
  const addresses = (policy.addresses ||= []);
  const object = {
    name: uniqueTroubleshootName(addresses, sanitizeTroubleshootName(`${prefix}-${String(ip || "").replace("/", "-")}`)),
    cidr,
    description: `Created from Troubleshoot explain for ${ip}.`,
  };
  addresses.push(object);
  generated.addresses.push(object);
  return object.name;
}

function ensureTroubleshootService(policy, generated, protocol, portValue) {
  const proto = normalizeProto(protocol);
  if (proto === "PROTOCOL_ANY") return "any";
  if (proto === "PROTOCOL_ICMP") return ensureProtocolTroubleshootService(policy, generated, "icmp", "PROTOCOL_ICMP");
  const port = numberOrZero(portValue);
  if (!port) return "any";
  const existing = (policy.services || []).find((svc) =>
    svc.protocol === proto &&
    (svc.ports || []).length === 1 &&
    Number(svc.ports[0].start) === port &&
    Number(svc.ports[0].end || 0) === 0);
  if (existing?.name) return existing.name;
  const services = (policy.services ||= []);
  const object = {
    name: uniqueTroubleshootName(services, sanitizeTroubleshootName(`${proto.replace("PROTOCOL_", "").toLowerCase()}-${port}`)),
    protocol: proto,
    ports: [{ start: port }],
    description: `Created from Troubleshoot explain for ${proto.replace("PROTOCOL_", "").toLowerCase()} destination port ${port}.`,
  };
  services.push(object);
  generated.services.push(object);
  return object.name;
}

function ensureProtocolTroubleshootService(policy, generated, base, protocol) {
  const existing = (policy.services || []).find((svc) => svc.protocol === protocol && !(svc.ports || []).length);
  if (existing?.name) return existing.name;
  const services = (policy.services ||= []);
  const object = {
    name: uniqueTroubleshootName(services, sanitizeTroubleshootName(base)),
    protocol,
    ports: [],
    description: "Created from Troubleshoot explain.",
  };
  services.push(object);
  generated.services.push(object);
  return object.name;
}

function troubleshootRuleDescription(tuple, result, action) {
  const verb = action === "ACTION_DENY" ? "Drop" : "Allow";
  const proto = tuple.protocol ? clean(tuple.protocol, "PROTOCOL_") : "ip";
  const src = endpointText(tuple.srcIp, tuple.srcPort);
  const dst = endpointText(tuple.destIp, tuple.destPort);
  const matched = matchedRuleText(result);
  return `${verb} explained ${proto} flow ${src} to ${dst}.${matched ? " " + matched : ""}`;
}

function matchedRuleText(result = {}) {
  if (result?.matchedRule) {
    const idx = Number(result.matchedRuleIndex);
    const indexText = Number.isInteger(idx) && idx >= 0 ? ` at index ${idx}` : "";
    return `Current explanation matched ${result.matchedRule}${indexText}.`;
  }
  if (result?.defaultPolicy) return "Current explanation reached the default policy.";
  return "";
}

function endpointText(ip, port) {
  const value = String(ip || "").trim();
  const p = numberOrZero(port);
  return p ? `${value}:${p}` : value;
}

function equivalentService(a = {}, b = {}) {
  return a.protocol === b.protocol && servicePortsKey(a.ports || []) === servicePortsKey(b.ports || []);
}

function servicePortsKey(ports = []) {
  return (ports || []).map((port) => `${Number(port.start || 0)}-${Number(port.end || 0)}`).join(",");
}

function ipToCidr(ip) {
  const value = String(ip || "").trim();
  if (value.includes("/")) return value;
  return value + (value.includes(":") ? "/128" : "/32");
}

function uniqueTroubleshootName(items = [], base = "rule") {
  const cleanName = sanitizeTroubleshootName(base);
  const names = new Set((items || []).map((item) => item?.name).filter(Boolean));
  if (!names.has(cleanName)) return cleanName;
  let i = 2;
  while (names.has(`${cleanName}-${i}`)) i++;
  return `${cleanName}-${i}`;
}

function sanitizeTroubleshootName(value) {
  let out = String(value || "rule").toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
  if (!out) out = "rule";
  if (!/^[a-z0-9]/.test(out)) out = "r-" + out;
  out = out.slice(0, 63).replace(/[-_]+$/g, "");
  if (!/[a-z0-9]$/.test(out)) out += "1";
  return out || "rule";
}

function compareDelta(key, label, running, candidate) {
  if (String(running || "") === String(candidate || "")) return null;
  return { key, label, running, candidate };
}

function verdictSummary(result = {}) {
  return decisionLabel(result) || verdictLabel(result?.verdict) || "unknown";
}

function ruleSummary(result = {}) {
  if (result?.matchedRule) {
    const idx = Number(result.matchedRuleIndex);
    return Number.isInteger(idx) && idx >= 0 ? `${result.matchedRule} (#${idx + 1})` : result.matchedRule;
  }
  if (result?.defaultPolicy) return "default policy";
  return "none";
}

function natSummary(result = {}) {
  const profile = result?.natProfile || result?.natDecision;
  return [natProfileSummary(profile), ...natProfileLines(profile)].filter(Boolean).join(" | ");
}

function natUiSummary(result = {}) {
  return natSummary(result) || "unknown";
}

function routeSummary(result = {}) {
  const p = result?.routeProfile;
  if (!p) return "unknown";
  return [
    p.evaluated ? "evaluated" : "not evaluated",
    p.matched ? "matched" : "no match",
    p.source ? `source:${p.source}` : "",
    p.destination ? `destination:${p.destination}` : "",
    p.nextHop ? `nextHop:${p.nextHop}` : "",
    p.egressInterface ? `egress:${p.egressInterface}` : "",
    p.metric ? `metric:${p.metric}` : "",
    p.reason ? `reason:${p.reason}` : "",
  ].filter(Boolean).join(" | ");
}

function routeUiSummary(result = {}) {
  const p = result?.routeProfile;
  if (!p) return "unknown";
  if (!p.evaluated) return "not evaluated";
  const path = [p.destination, p.nextHop ? `via ${p.nextHop}` : "", p.egressInterface ? `dev ${p.egressInterface}` : ""].filter(Boolean).join(" ");
  if (p.matched) return path || p.reason || "matched";
  return p.reason || "no match";
}

function inspectionSummary(result = {}) {
  const p = result?.inspectionProfile || {};
  return [
    inspectionLabel(result?.inspectionState) || "unknown",
    p.engine || "",
    p.idsEnabled ? clean(p.idsMode || "ids enabled", "IDS_MODE_") : "ids disabled",
    p.failureBehavior ? `fail ${clean(p.failureBehavior, "IDS_FAILURE_BEHAVIOR_")}` : "",
    p.flowOffloadEnabled ? "flow offload enabled" : "flow offload disabled",
    p.bypassPossible ? "bypass possible" : "bypass not expected",
    p.bypassReason || "",
    p.inspectionOrder || "",
    p.degradedBehavior || "",
  ].filter(Boolean).join(" | ");
}

function inspectionUiSummary(result = {}) {
  const p = result?.inspectionProfile || {};
  return [
    inspectionLabel(result?.inspectionState) || "unknown",
    p.failureBehavior ? `fail ${clean(p.failureBehavior, "IDS_FAILURE_BEHAVIOR_")}` : "",
    p.degradedBehavior ? `degraded ${p.degradedBehavior}` : "",
    p.bypassPossible ? "bypass possible" : "",
  ].filter(Boolean).join(" | ");
}

function compareCues(result = {}) {
  const p = result?.inspectionProfile || {};
  return uniqueStrings([
    ...(result?.warnings || []),
    result?.inspectionState === "EXPLAIN_INSPECTION_STATE_NOT_INSPECTED" ? "Inspection did not run for this flow." : "",
    result?.inspectionState === "EXPLAIN_INSPECTION_STATE_BYPASSED" ? "Inspection was bypassed for this flow." : "",
    p.failureBehavior ? `Failure behavior: ${clean(p.failureBehavior, "IDS_FAILURE_BEHAVIOR_")}` : "",
    p.bypassPossible ? `Bypass possible${p.bypassReason ? `: ${p.bypassReason}` : "."}` : "",
    p.degradedBehavior ? `Degraded behavior: ${p.degradedBehavior}` : "",
  ]);
}

function uniqueStrings(values = []) {
  return Array.from(new Set(values.map((v) => String(v || "").trim()).filter(Boolean)));
}

function kv(label, value) {
  return [h("dt", {}, label), h("dd", {}, value || "—")];
}

function input(type, value, placeholder) {
  return h("input", { class: "input", type, value, placeholder, min: type === "number" ? "0" : null, max: type === "number" ? "65535" : null });
}

function select(options, value) {
  const el = h("select", {}, options.map(([v, label]) => h("option", { value: v }, label)));
  el.value = value;
  return el;
}

function numberOrZero(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.trunc(n) : 0;
}

function normalizeCaptureRoute(query = {}) {
  const plan = buildCapturePlan({
    interface: query.captureInterface || query.interface || query.iface,
    durationSeconds: query.captureDuration || query.durationSeconds,
    packetCount: query.capturePackets || query.packetCount,
    snaplenBytes: query.captureSnaplen || query.snaplenBytes,
  });
  return {
    captureInterface: plan.interface || CAPTURE_LIMITS.defaultInterface,
    captureDuration: String(plan.durationSeconds || CAPTURE_LIMITS.defaultDurationSeconds),
    capturePackets: String(plan.packetCount || CAPTURE_LIMITS.defaultPacketCount),
    captureSnaplen: String(plan.snaplenBytes || CAPTURE_LIMITS.defaultSnaplenBytes),
  };
}

function stringValue(v) {
  return String(v ?? "").trim();
}

function sourceValue(v) {
  const source = String(v || TROUBLESHOOT_ROUTE_DEFAULTS.source);
  return POLICY_SOURCES.has(source) ? source : TROUBLESHOOT_ROUTE_DEFAULTS.source;
}

function versionText(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? String(Math.trunc(n)) : "";
}

function portText(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 && n <= 65535 ? String(Math.trunc(n)) : "";
}

function runtimeValue(query = {}) {
  const value = query.runtime ?? query.includeRuntime;
  return value === true || value === "1" || value === "true";
}

function booleanValue(value) {
  return value === true || value === "1" || value === "true";
}

function intentValue(value) {
  if (value === "capture" || value === "explain" || value === "compare") return value;
  return "";
}

function normalizeProto(p) {
  const v = String(p || "").toUpperCase();
  if (v === "TCP") return "PROTOCOL_TCP";
  if (v === "UDP") return "PROTOCOL_UDP";
  if (v === "ICMP") return "PROTOCOL_ICMP";
  if (v === "ANY" || v === "IP") return "PROTOCOL_ANY";
  return v.startsWith("PROTOCOL_") ? v : "PROTOCOL_TCP";
}

function verdictLabel(v) { return clean(v, "EXPLAIN_VERDICT_"); }
function inspectionLabel(v) { return clean(v, "EXPLAIN_INSPECTION_STATE_"); }
function decisionLabel(r = {}) {
  if (r.decisionSummary) return r.decisionSummary;
  return (r.decisionTerms || [])
    .map((term) => clean(term, "EXPLAIN_DECISION_TERM_").replace(/\bfail open\b/g, "fail-open").replace(/\bfail closed\b/g, "fail-closed"))
    .filter(Boolean)
    .join(", ");
}
function policyLabel(r = {}) {
  const source = clean(r.policySource, "POLICY_SOURCE_") || "running";
  const version = Number(r.policyVersion || 0);
  if (version > 0) return `${source} v${version}`;
  return source;
}
function clean(v, prefix) { return String(v || "").replace(prefix, "").replaceAll("_", " ").toLowerCase(); }
function verdictClass(v) {
  if (v === "EXPLAIN_VERDICT_ALLOWED") return "ok";
  if (v === "EXPLAIN_VERDICT_DEFAULT_DROP" || v === "EXPLAIN_VERDICT_DENIED" || v === "EXPLAIN_VERDICT_REJECTED") return "bad";
  return "warn";
}
function inspectionClass(v) {
  if (v === "EXPLAIN_INSPECTION_STATE_IDS_DETECT" || v === "EXPLAIN_INSPECTION_STATE_IPS_PREVENT") return "info";
  if (v === "EXPLAIN_INSPECTION_STATE_NOT_INSPECTED") return "warn";
  if (v === "EXPLAIN_INSPECTION_STATE_BLOCKED_BEFORE_INSPECTION") return "neutral";
  return "neutral";
}
