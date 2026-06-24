// NAT — source and destination translation policy. Edits stage to the
// candidate only; commit renders packet filter srcnat/dstnat chains.

import { h, icon, clear } from "../core.js";
import { api } from "../api.js";
import { throwIfAccessDenied } from "../auth_gate.js";
import { equal, session } from "../policy.js";
import { buildHash, readQueryState, writeQueryState } from "../query_state.js";
import { pageHead, emptyState, pill, toast, openDrawer, closeDrawer, labeledCell, responsiveTable } from "../ui.js";
import { natProfileLines } from "../explain_profiles.js";
import { pinInvestigationPacket } from "../investigation_case.js";
import { investigationPacketFilename, investigationPacketJson, natPathHandoffPacket } from "../investigation_packet.js";
import { buildNatPreviewHash, buildNatPreviewRouteState, destinationNatPreviewFlow, explainRequestFromFlow, NAT_PREVIEW_ROUTE_DEFAULTS, NAT_PREVIEW_ROUTE_KEYS, natPathCouplingReview, natPathDelta, normalizeNatPreviewRouteState, representativeNatFlow, routeProfileLines, sourceNatDeleteImpactReview, troubleshootHashFromNatPreview } from "../nat_path_preview.js";

const preview = {
  initialized: false,
  loading: false,
  error: "",
  warning: "",
  contextNote: "",
  running: null,
  candidate: null,
  runRequested: false,
  autorunKey: "",
  requestSeq: 0,
  activeRequestId: 0,
  activeRequestKey: "",
};
let routePath = "/nat";
let focusRoute = { nat: "", rule: "", idx: "" };

export const NAT_FOCUS_ROUTE_DEFAULTS = Object.freeze({ nat: "", rule: "", idx: "" });
export const NAT_FOCUS_ROUTE_KEYS = Object.freeze(Object.keys(NAT_FOCUS_ROUTE_DEFAULTS));

export async function render(ctx = {}) {
  routePath = ctx.path || "/nat";
  const unavailableError = await loadNatSession();
  const query = ctx.query || {};
  applyPreviewRoute(query);
  focusRoute = normalizeNatFocusRoute(query);
  const root = h("div", {});
  if (unavailableError) {
    paintNatUnavailable(root, unavailableError);
    return root;
  }
  paint(root);
  return root;
}

async function loadNatSession() {
  const result = await Promise.allSettled([session.load()]);
  throwIfAccessDenied(...result);
  if (result[0].status === "rejected") return result[0].reason;
  if (!session.candidateLoadError) return null;
  throwIfAccessDenied({ status: "rejected", reason: session.candidateLoadError });
  return session.candidateLoadError;
}

function paintNatUnavailable(root, err) {
  clear(root);
  root.appendChild(pageHead("NAT",
    "Source and destination translation policy stages through the candidate policy.",
    h("div", { class: "flex wrap" },
      h("button", { class: "btn primary", type: "button", title: "Retry loading NAT candidate policy", "aria-label": "Retry loading NAT candidate policy", dataset: { natAction: "retry-unavailable" }, onclick: retryRouteLoad }, h("span", { html: icon("refresh", 16) }), "Retry"))));
  root.appendChild(routeUnavailablePanel("NAT candidate workspace unavailable", err, [
    { label: "Candidate policy", value: "GET /v1/policy?source=POLICY_SOURCE_CANDIDATE", detail: "Loads staged NAT source and destination rules before browser edits." },
    { label: "Candidate status", value: "GET /v1/candidate/status", detail: "Reads dirty state and candidate revision required for guarded writes." },
    { label: "CLI review", value: "ngfwctl policy show --source candidate --json", detail: "Export the staged policy headlessly, then review NAT sections before editing." },
    { label: "CLI diff", value: "ngfwctl policy diff", detail: "Compare running and candidate policy before retrying browser edits." },
  ]));
}

function routeUnavailablePanel(title, err, rows = []) {
  return h("section", { class: "alert-box warn", dataset: { routeUnavailable: "nat" } },
    h("strong", {}, title),
    h("div", { class: "note" }, errorMessage(err) || "The candidate session could not be loaded. Retry after the API is reachable."),
    h("div", { class: "row-actions", style: { marginTop: "12px" } },
      h("button", { class: "btn sm ghost", type: "button", title: "Retry loading this NAT route", "aria-label": "Retry loading this NAT route", dataset: { natAction: "retry-unavailable-inline" }, onclick: retryRouteLoad }, h("span", { html: icon("refresh", 14) }), "Retry"),
      h("a", { class: "btn sm ghost", href: "#/changes?tab=candidate", title: "Open Changes candidate review", "aria-label": "Open Changes candidate review", dataset: { natAction: "changes" } }, h("span", { html: icon("changes", 14) }), "Changes")),
    responsiveTable(["Context", "Command / endpoint", "Use"], rows.map((row) => h("tr", {},
      labeledCell("Context", row.label),
      labeledCell("Command / endpoint", { class: "mono" }, row.value),
      labeledCell("Use", row.detail))), { className: "nat-unavailable-context-table" }));
}

function retryRouteLoad() {
  globalThis.dispatchEvent(new Event("hashchange"));
}

function paint(root) {
  clear(root);
  const snat = session.draft.nat?.source || [];
  const dnat = session.draft.nat?.destination || [];
  root.appendChild(pageHead("NAT",
    `${snat.length} source · ${dnat.length} destination · staged through candidate policy`,
    h("div", { class: "flex wrap" },
      h("button", { class: "btn", type: "button", title: "Add source NAT rule", "aria-label": "Add source NAT rule", dataset: { natAction: "add-source" }, onclick: () => editSourceNat(root, null) }, h("span", { html: icon("plus", 16) }), "Add source NAT"),
      h("button", { class: "btn primary", type: "button", title: "Add destination NAT rule", "aria-label": "Add destination NAT rule", dataset: { natAction: "add-destination" }, onclick: () => editDestinationNat(root, null) }, h("span", { html: icon("plus", 16) }), "Add destination NAT"))));

  root.appendChild(natSummary());
  root.appendChild(natPathPreviewPanel(root));
  const focusIssue = natFocusIssue();
  if (focusIssue) root.appendChild(natFocusIssueAlert(focusIssue));
  root.appendChild(h("div", { class: "grid cols-2" },
    sourceNatPanel(root, snat),
    destinationNatPanel(root, dnat)));
  maybeFocusNatRule(root);
}

export function normalizeNatFocusRoute(query = {}) {
  const parsed = readQueryState(query, NAT_FOCUS_ROUTE_DEFAULTS, NAT_FOCUS_ROUTE_KEYS);
  const nat = normalizeNatFocusSide(parsed.nat);
  if (!nat) return { ...NAT_FOCUS_ROUTE_DEFAULTS };
  return {
    nat,
    rule: String(parsed.rule || "").trim(),
    idx: normalizeNatFocusIndex(parsed.idx),
  };
}

export function natRuleFocusRouteState(ref = {}) {
  const nat = natSideFromReferenceArea(ref.area);
  if (!nat) return { ...NAT_FOCUS_ROUTE_DEFAULTS };
  return {
    nat,
    rule: String(ref.id || ref.itemId || ref.ruleId || ref.item || "").trim(),
    idx: normalizeNatFocusIndex(ref.index),
  };
}

export function natRuleFocusHash(ref = {}, path = "/nat") {
  return buildHash(path, natRuleFocusRouteState(ref), NAT_FOCUS_ROUTE_DEFAULTS, NAT_FOCUS_ROUTE_KEYS);
}

export function focusedNatRuleIndex(route = {}, type = "", rules = []) {
  const focus = normalizeNatFocusRoute(route);
  if (!focus.nat || focus.nat !== normalizeNatFocusSide(type)) return -1;
  const wantedIdx = focus.idx === "" ? -1 : Number(focus.idx);
  const wantedRule = focus.rule;
  if (wantedRule) {
    const idMatches = (rules || [])
      .map((rule, idx) => ({ rule, idx }))
      .filter(({ rule }) => natRuleDurableId(rule) === wantedRule);
    if (idMatches.length === 1) return idMatches[0].idx;
    if (idMatches.length > 1 && wantedIdx >= 0 && idMatches.some((match) => match.idx === wantedIdx)) return wantedIdx;
    const matches = (rules || [])
      .map((rule, idx) => ({ rule, idx }))
      .filter(({ rule, idx }) => natRuleDisplayName(rule, idx) === wantedRule || String(rule?.name || "").trim() === wantedRule);
    if (matches.length === 1) return matches[0].idx;
    if (matches.length > 1 && wantedIdx >= 0 && matches.some((match) => match.idx === wantedIdx)) return wantedIdx;
  }
  if (wantedIdx >= 0 && wantedIdx < (rules || []).length) return wantedIdx;
  return -1;
}

function natSummary() {
  const dirty = !equal((session.running || {}).nat || {}, (session.draft || {}).nat || {});
  const snat = session.draft.nat?.source || [];
  const dnat = session.draft.nat?.destination || [];
  return h("div", { class: "runtime-grid", style: { marginBottom: "16px" } },
    metric("Candidate state", dirty ? pill("pending NAT change", "warn") : pill("matches running", "neutral")),
    metric("Source NAT", String(snat.length)),
    metric("Destination NAT", String(dnat.length)));
}

function natPathPreviewPanel(root) {
  ensurePreviewDefaults();
  const zones = names(session.draft.zones);
  const resultNode = h("div", { class: "sim-result" });
  const controls = {
    fromZone: select(zones, preview.fromZone, "Any from-zone"),
    toZone: select(zones, preview.toZone, "Any to-zone"),
    protocol: protocolSelect(preview.protocol),
    srcIp: text(preview.srcIp, "10.0.1.20"),
    srcPort: h("input", { class: "input", type: "number", min: "0", max: "65535", value: preview.srcPort || "", placeholder: "51515" }),
    destIp: text(preview.destIp, "203.0.113.10"),
    destPort: h("input", { class: "input", type: "number", min: "0", max: "65535", value: preview.destPort || "", placeholder: "443" }),
  };
  const form = h("form", { class: "sim-form", onsubmit: (e) => runNatPathPreview(e, controls, resultNode, root) },
    h("div", { class: "sim-fields" },
      field("From", controls.fromZone),
      field("To", controls.toZone),
      field("Protocol", controls.protocol),
      field("Source IP", controls.srcIp),
      field("Source port", controls.srcPort),
      field("Destination IP", controls.destIp),
      field("Destination port", controls.destPort)),
    h("div", { class: "sim-actions" },
      h("button", { class: "btn primary", type: "submit", title: "Preview NAT path for representative tuple", "aria-label": "Preview NAT path for representative tuple", dataset: { natPathAction: "preview" } }, h("span", { html: icon("search", 16) }), "Preview path"),
      h("button", { class: "btn ghost", type: "button", title: "Use representative NAT policy sample", "aria-label": "Use representative NAT policy sample", dataset: { natPathAction: "use-policy-sample" }, onclick: () => resetNatPathPreview(root) },
        h("span", { html: icon("refresh", 16) }), "Use policy sample")));

  paintNatPathPreview(resultNode);
  maybeRunSharedNatPreview(resultNode);
  return h("section", { class: "rule-simulator", style: { marginBottom: "16px" } },
    h("div", { class: "sim-head" },
      h("div", {},
        h("h2", {}, "NAT path preview"),
        h("div", { class: "note" }, "Compare running and candidate policy for one representative flow before commit.")),
      !equal((session.running || {}).nat || {}, (session.draft || {}).nat || {}) ? pill("NAT staged", "warn", true) : pill("running aligned", "neutral", true)),
    form,
    resultNode);
}

function ensurePreviewDefaults(force = false) {
  if (preview.initialized && !force) return;
  invalidateNatPreviewRequest();
  Object.assign(preview, representativeNatFlow(session.draft || {}), {
    initialized: true,
    loading: false,
    error: "",
    warning: "",
    contextNote: "",
    running: null,
    candidate: null,
    runRequested: false,
    autorunKey: "",
  });
}

function applyPreviewRoute(query = {}) {
  const route = normalizeNatPreviewRouteState(queryObject(query));
  if (!hasPreviewRouteState(route)) return;
  invalidateNatPreviewRequest();
  Object.assign(preview, representativeNatFlow(session.draft || {}), route, {
    initialized: true,
    loading: false,
    error: "",
    warning: "",
    contextNote: "",
    running: null,
    candidate: null,
    runRequested: route.run,
    autorunKey: "",
  });
}

function maybeRunSharedNatPreview(resultNode) {
  if (!preview.runRequested || preview.loading) return;
  const key = natPreviewRouteKey(true);
  if (preview.autorunKey === key) return;
  preview.autorunKey = key;
  queueMicrotask(() => evaluateNatPathPreview(resultNode));
}

function resetNatPathPreview(root) {
  ensurePreviewDefaults(true);
  syncNatPreviewRoute(false);
  paint(root);
}

async function runNatPathPreview(e, controls, resultNode, root) {
  e.preventDefault();
  rememberPreview(controls);
  syncNatPreviewRoute(true);
  await evaluateNatPathPreview(resultNode);
}

async function evaluateNatPathPreview(resultNode) {
  preview.runRequested = false;
  if (!preview.srcIp || !preview.destIp) {
    invalidateNatPreviewRequest();
    preview.error = "Source IP and destination IP are required.";
    preview.running = null;
    preview.candidate = null;
    preview.loading = false;
    paintNatPathPreview(resultNode);
    return;
  }

  preview.error = "";
  preview.warning = "";
  preview.running = null;
  preview.candidate = null;
  preview.loading = true;
  const flow = buildNatPreviewRouteState(preview, { run: false });
  const requestId = ++preview.requestSeq;
  const requestKey = JSON.stringify(flow);
  preview.activeRequestId = requestId;
  preview.activeRequestKey = requestKey;
  paintNatPathPreview(resultNode);
  try {
    const [runningResult, candidateResult] = await Promise.allSettled([
      api.explainFlow(explainRequestFromFlow(flow, "POLICY_SOURCE_RUNNING")),
      api.explainFlow(explainRequestFromFlow(flow, "POLICY_SOURCE_CANDIDATE")),
    ]);
    if (!isCurrentNatPreviewRequest(requestId, requestKey)) return;
    if (runningResult.status === "fulfilled") preview.running = runningResult.value;
    if (candidateResult.status === "fulfilled") {
      preview.candidate = candidateResult.value;
    } else if (preview.running && isMissingCandidateError(candidateResult.reason)) {
      preview.candidate = structuredClone(preview.running);
      preview.warning = "No candidate policy is staged; candidate preview is using the running baseline.";
    }
    const errors = [];
    if (runningResult.status === "rejected") errors.push(`running: ${errorMessage(runningResult.reason)}`);
    if (candidateResult.status === "rejected" && !preview.candidate) errors.push(`candidate: ${errorMessage(candidateResult.reason)}`);
    if (errors.length) preview.error = errors.join(" · ");
  } catch (err) {
    if (!isCurrentNatPreviewRequest(requestId, requestKey)) return;
    preview.error = errorMessage(err);
  } finally {
    if (!isCurrentNatPreviewRequest(requestId, requestKey)) return;
    if (preview.error) toast("NAT path preview failed", preview.error, "bad");
    preview.loading = false;
    paintNatPathPreview(resultNode);
  }
}

function rememberPreview(c) {
  Object.assign(preview, normalizeNatPreviewRouteState({
    fromZone: c.fromZone.value,
    toZone: c.toZone.value,
    protocol: c.protocol.value,
    srcIp: c.srcIp.value,
    srcPort: c.srcPort.value,
    destIp: c.destIp.value,
    destPort: c.destPort.value,
  }));
}

function paintNatPathPreview(node) {
  clear(node);
  delete node.dataset.natPreviewResult;
  delete node.dataset.natPreviewKey;
  if (preview.loading) {
    node.appendChild(h("div", { class: "sim-empty" }, "Evaluating running and candidate policy..."));
    return;
  }
  if (preview.error) {
    node.appendChild(h("div", { class: "alert-box bad" }, preview.error));
    return;
  }
  if (!preview.running && !preview.candidate) {
    node.appendChild(h("div", { class: "sim-empty" }, "No path preview evaluated."));
    return;
  }
  const delta = natPathDelta(preview.running, preview.candidate);
  node.appendChild(h("div", { class: "sim-summary " + delta.tone },
    h("div", {},
      h("strong", {}, delta.headline),
      h("span", {}, `${preview.srcIp || "-"}:${preview.srcPort || "0"} -> ${preview.destIp || "-"}:${preview.destPort || "0"} ${preview.protocol || "PROTOCOL_TCP"}`)),
    pill(delta.changed ? "review" : "aligned", delta.tone === "ok" ? "ok" : delta.tone)));
  node.appendChild(pathDeltaTable(delta.rows));
  node.appendChild(pathCouplingReviewPanel(natPathCouplingReview(
    preview.running,
    preview.candidate,
    buildNatPreviewRouteState(preview, { run: true }),
  )));

  const candidateNat = preview.candidate?.natProfile || preview.candidate?.natDecision;
  const candidateRoute = preview.candidate?.routeProfile;
  const details = [
    preview.contextNote ? simList("Publish workflow", [preview.contextNote], "info") : null,
    preview.warning ? simList("Preview note", [preview.warning], "warn") : null,
    natProfileLines(candidateNat).length ? simList("Candidate NAT", natProfileLines(candidateNat), "", "nat") : null,
    routeProfileLines(candidateRoute).length ? simList("Candidate route", routeProfileLines(candidateRoute), candidateRoute?.matched || !candidateRoute?.evaluated ? "" : "warn", "route") : null,
    delta.warnings.length ? simList("Warnings", delta.warnings, "warn") : null,
  ].filter(Boolean);
  if (details.length) node.appendChild(h("div", { class: "sim-evidence" }, details));
  node.dataset.natPreviewResult = "true";
  node.dataset.natPreviewKey = JSON.stringify(buildNatPreviewRouteState(preview, { run: false }));
  node.appendChild(h("div", { class: "sim-actions", style: { marginTop: "12px" } },
    h("button", { class: "btn", type: "button", title: "Copy NAT path preview link", "aria-label": "Copy NAT path preview link", dataset: { natPreviewAction: "copy" }, onclick: copyNatPreviewLink }, h("span", { html: icon("copy", 16) }), "Copy link"),
    h("button", { class: "btn", type: "button", title: "Open NAT path preview in Troubleshoot", "aria-label": "Open NAT path preview in Troubleshoot", dataset: { natPreviewAction: "troubleshoot" }, onclick: openNatPreviewInTroubleshoot }, h("span", { html: icon("search", 16) }), "Open in Troubleshoot"),
    h("button", { class: "btn", type: "button", title: "Pin NAT path preview to investigation case", "aria-label": "Pin NAT path preview to investigation case", dataset: { natPreviewAction: "pin" }, onclick: pinNatPathHandoff }, h("span", { html: icon("inbox", 16) }), "Pin to case"),
    h("button", { class: "btn", type: "button", title: "Export NAT path preview handoff", "aria-label": "Export NAT path preview handoff", dataset: { natPreviewAction: "export" }, onclick: exportNatPathHandoff }, h("span", { html: icon("download", 16) }), "Export handoff")));
}

function invalidateNatPreviewRequest() {
  preview.activeRequestId = 0;
  preview.activeRequestKey = "";
  preview.requestSeq = Number(preview.requestSeq || 0) + 1;
}

function isCurrentNatPreviewRequest(requestId, requestKey) {
  return preview.activeRequestId === requestId && preview.activeRequestKey === requestKey;
}

function syncNatPreviewRoute(run = false) {
  return writeQueryState(routePath, buildNatPreviewRouteState(preview, { run }), NAT_PREVIEW_ROUTE_DEFAULTS, NAT_PREVIEW_ROUTE_KEYS);
}

function natPreviewRouteKey(run = false) {
  return JSON.stringify(buildNatPreviewRouteState(preview, { run }));
}

function natPreviewShareHash(run = true) {
  return buildNatPreviewHash(buildNatPreviewRouteState(preview, { run }), { path: routePath });
}

function natPreviewShareURL(run = true) {
  const hash = natPreviewShareHash(run);
  if (typeof location === "undefined") return hash;
  try {
    const url = new URL(location.href);
    url.hash = hash;
    return url.toString();
  } catch {
    return hash;
  }
}

async function copyNatPreviewLink() {
  try {
    syncNatPreviewRoute(true);
    await navigator.clipboard.writeText(natPreviewShareURL(true));
    toast("NAT preview link copied", "Reloading the link replays this running/candidate comparison.", "ok");
  } catch {
    toast("Copy failed", "Copy the current browser URL after running the preview.", "warn");
  }
}

function openNatPreviewInTroubleshoot() {
  const hash = troubleshootHashFromNatPreview(buildNatPreviewRouteState(preview, { run: true }), {
    runtime: true,
    source: "POLICY_SOURCE_CANDIDATE",
    intent: "compare",
  });
  if (typeof location !== "undefined") location.hash = hash;
  return hash;
}

function natPathPreviewPacket() {
  const delta = natPathDelta(preview.running, preview.candidate);
  return natPathHandoffPacket({
    flow: buildNatPreviewRouteState(preview, { run: false }),
    running: preview.running,
    candidate: preview.candidate,
    delta,
  }, {
    route: natPreviewShareHash(true),
    previewWarning: preview.warning,
  });
}

function pinNatPathHandoff() {
  try {
    const result = pinInvestigationPacket(natPathPreviewPacket());
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Selected NAT path evidence could not be pinned.", "bad");
  }
}

function exportNatPathHandoff() {
  const packet = natPathPreviewPacket();
  const text = investigationPacketJson(packet);
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: investigationPacketFilename(packet) });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  toast("NAT handoff exported", "Downloaded the preview tuple and running/candidate path delta.", "ok");
}

function hasPreviewRouteState(route = {}) {
  return Boolean(route.run) || NAT_PREVIEW_ROUTE_KEYS.some((key) => key !== "run" && String(route[key] ?? "") !== String(NAT_PREVIEW_ROUTE_DEFAULTS[key] ?? ""));
}

function queryObject(query = {}) {
  if (query instanceof URLSearchParams) return Object.fromEntries(query.entries());
  return query || {};
}

function maybeFocusNatRule(root) {
  const type = focusRoute.nat;
  if (!type) return;
  const rules = type === "source" ? session.draft.nat?.source || [] : session.draft.nat?.destination || [];
  const idx = focusedNatRuleIndex(focusRoute, type, rules);
  if (idx < 0) return;
  setTimeout(() => {
    const target = root?.querySelector?.(`[data-nat-rule-type="${type}"][data-nat-rule-index="${idx}"]`);
    if (!target) return;
    try {
      target.focus?.({ preventScroll: true });
    } catch {
      target.focus?.();
    }
    target.scrollIntoView?.({ block: "center", inline: "nearest", behavior: "smooth" });
  }, 0);
}

function natRuleRowAttrs(type, rule, idx, focusedIdx = -1) {
  const focused = focusedIdx === idx;
  const id = natRuleDurableId(rule);
  const attrs = {
    class: ["clickable", focusedIdx === idx ? "selected-row" : ""].filter(Boolean).join(" "),
    tabindex: "-1",
    dataset: {
      natRuleType: type,
      natRuleIndex: String(idx),
      natRuleName: rule?.name || "",
      natRuleId: id,
    },
  };
  if (focused) {
    attrs["aria-current"] = "true";
    attrs.style = { background: "color-mix(in srgb, var(--accent-bg) 55%, transparent)" };
  }
  return attrs;
}

function natRuleDurableId(rule = {}) {
  return String(rule?.id || "").trim();
}

function natRuleIdentityNode(rule = {}, idx = 0) {
  const id = natRuleDurableId(rule);
  return h("div", {},
    h("strong", {}, rule.name || "unnamed"),
    id ? h("div", { class: "note mono", title: "Durable policy item ID" }, `ID ${id}`) : h("div", { class: "note" }, `legacy target #${idx + 1}`));
}

function natRuleDisplayName(rule, idx) {
  return String(rule?.name || `#${Number(idx) + 1}`).trim();
}

function natRuleRouteToken(rule = {}, idx = 0) {
  return natRuleDurableId(rule) || natRuleDisplayName(rule, idx);
}

function natRuleRouteHash(type, rule = {}, idx = 0) {
  return buildHash(routePath, {
    nat: normalizeNatFocusSide(type),
    rule: natRuleRouteToken(rule, idx),
    idx: normalizeNatFocusIndex(idx),
  }, NAT_FOCUS_ROUTE_DEFAULTS, NAT_FOCUS_ROUTE_KEYS);
}

export function natMutationContext(type = "", action = "update", rule = {}, nextRule = null) {
  const side = normalizeNatFocusSide(type);
  const mutation = action === "delete" ? "delete" : "update";
  const current = rule || {};
  const target = nextRule || current;
  const id = natRuleDurableId(current);
  const name = String(current?.name || target?.name || "").trim();
  const selectorKind = id ? "id" : "name";
  const selectorValue = id || name;
  const encodedSelector = encodeURIComponent(selectorValue || (side === "destination" ? "destination-nat-name" : "source-nat-name"));
  const base = `/v1/candidate/nat/${side || "source"}`;
  const path = selectorKind === "id" ? `${base}/by-id/${encodedSelector}` : `${base}/${encodedSelector}`;
  const cli = mutation === "delete"
    ? natDeleteCli(side, selectorKind, selectorValue)
    : natUpdateCli(side, selectorKind, selectorValue, target);
  const body = mutation === "delete" ? null : {
    rule: sanitizeNatRuleForContext(side, target, id),
    expectedCandidateRevision: "<candidate-revision>",
    comment: "<operator reason>",
  };
  if (body?.rule && selectorKind === "id") body.id = id;
  return {
    type: side,
    action: mutation,
    selectorKind,
    selectorValue,
    method: mutation === "delete" ? "DELETE" : "PUT",
    path,
    body,
    cli,
  };
}

function canUseGranularNatUpsert(previous = null, item = {}) {
  if (!previous) return true;
  if (natRuleDurableId(previous)) return true;
  return String(previous?.name || "").trim() === String(item?.name || "").trim();
}

function natMutationSelector(rule = {}) {
  const id = natRuleDurableId(rule);
  return id ? { id } : { name: String(rule?.name || "").trim() };
}

function natEditorMutationComment(type = "", action = "") {
  const label = type === "destination" ? "destination NAT" : "source NAT";
  const verb = action === "delete" ? "delete" : action === "add" ? "add" : "update";
  return `WebUI ${label} ${verb}; candidate-only granular NAT mutation.`;
}

function ensureGranularNatReady(action = "stage NAT") {
  session.ensureCandidateAvailable(action);
  if (!session.candidateRevision) {
    throw new Error("Candidate revision is unavailable. Reload candidate NAT before staging.");
  }
}

async function stageGranularSourceNat(item = {}, previous = null, action = "update") {
  ensureGranularNatReady("stage source NAT");
  const selector = natMutationSelector(previous || item);
  const resp = await api.upsertCandidateSourceNat({
    ...selector,
    rule: item,
    expectedCandidateRevision: session.candidateRevision,
    comment: natEditorMutationComment("source", action),
  });
  await session.load();
  return resp?.sourceNat || item;
}

async function stageGranularDestinationNat(item = {}, previous = null, action = "update") {
  ensureGranularNatReady("stage destination NAT");
  const selector = natMutationSelector(previous || item);
  const resp = await api.upsertCandidateDestinationNat({
    ...selector,
    rule: item,
    expectedCandidateRevision: session.candidateRevision,
    comment: natEditorMutationComment("destination", action),
  });
  await session.load();
  return resp?.destinationNat || item;
}

async function deleteGranularSourceNat(rule = {}) {
  ensureGranularNatReady("delete source NAT");
  await api.deleteCandidateSourceNat({
    ...natMutationSelector(rule),
    expectedCandidateRevision: session.candidateRevision,
    comment: natEditorMutationComment("source", "delete"),
  });
  await session.load();
}

async function deleteGranularDestinationNat(rule = {}) {
  ensureGranularNatReady("delete destination NAT");
  await api.deleteCandidateDestinationNat({
    ...natMutationSelector(rule),
    expectedCandidateRevision: session.candidateRevision,
    comment: natEditorMutationComment("destination", "delete"),
  });
  await session.load();
}

function sanitizeNatRuleForContext(type = "", rule = {}, id = "") {
  const out = {};
  if (id) out.id = id;
  out.name = String(rule?.name || "").trim() || (type === "destination" ? "<destination-nat-name>" : "<source-nat-name>");
  if (type === "destination") {
    out.fromZone = rule?.fromZone || "<ingress-zone>";
    out.service = rule?.service || "<service-object>";
    out.destinationAddress = rule?.destinationAddress || "<public-address-object>";
    out.translatedAddress = rule?.translatedAddress || "<translated-address-object>";
    if (rule?.translatedPort) out.translatedPort = Number(rule.translatedPort);
  } else {
    out.toZone = rule?.toZone || "<egress-zone>";
    if (rule?.sourceAddress) out.sourceAddress = rule.sourceAddress;
    if (rule?.masquerade || !rule?.translatedAddress) out.masquerade = true;
    else out.translatedAddress = rule.translatedAddress;
  }
  return out;
}

function natUpdateCli(type = "", selectorKind = "name", selectorValue = "", rule = {}) {
  const command = ["ngfwctl", "policy", "nat", type || "source", "upsert"];
  if (selectorKind === "id" && selectorValue) command.push("--id", selectorValue);
  if (type === "destination") {
    command.push(
      "--name", rule?.name || "<destination-nat-name>",
      "--from-zone", rule?.fromZone || "<ingress-zone>",
      "--service", rule?.service || "<service-object>",
      "--destination-address", rule?.destinationAddress || "<public-address-object>",
      "--translated-address", rule?.translatedAddress || "<translated-address-object>",
    );
    if (rule?.translatedPort) command.push("--translated-port", String(rule.translatedPort));
  } else {
    command.push(
      "--name", rule?.name || "<source-nat-name>",
      "--to-zone", rule?.toZone || "<egress-zone>",
    );
    if (rule?.sourceAddress) command.push("--source-address", rule.sourceAddress);
    if (rule?.masquerade || !rule?.translatedAddress) command.push("--masquerade");
    else command.push("--translated-address", rule.translatedAddress);
  }
  command.push("--expected-candidate-revision", "<candidate-revision>", "--comment", "<operator reason>");
  return shellJoin(command);
}

function natDeleteCli(type = "", selectorKind = "name", selectorValue = "") {
  const command = ["ngfwctl", "policy", "nat", type || "source", "delete"];
  command.push(selectorKind === "id" ? "--id" : "--name", selectorValue || (type === "destination" ? "<destination-nat-name>" : "<source-nat-name>"));
  command.push("--expected-candidate-revision", "<candidate-revision>", "--comment", "<operator reason>");
  return shellJoin(command);
}

function shellJoin(args = []) {
  return args.map((arg) => shellQuote(String(arg || ""))).join(" ");
}

function shellQuote(value = "") {
  return /^[A-Za-z0-9_./:-]+$/.test(value) ? value : "'" + value.replaceAll("'", "'\\''") + "'";
}

function natMutationContextText(context = {}) {
  const lines = [
    `${context.method || "PUT"} ${context.path || "/v1/candidate/nat/source/<name>"}`,
    `selector=${context.selectorKind || "name"}:${context.selectorValue || ""}`,
  ];
  if (context.body) {
    lines.push("", "JSON body:", JSON.stringify(context.body, null, 2));
  }
  if (context.cli) lines.push("", "CLI:", context.cli);
  return lines.join("\n");
}

function natFocusIssue() {
  const focus = normalizeNatFocusRoute(focusRoute);
  if (!focus.nat || (!focus.rule && focus.idx === "")) return null;
  const rules = focus.nat === "source" ? session.draft.nat?.source || [] : session.draft.nat?.destination || [];
  if (focusedNatRuleIndex(focus, focus.nat, rules) >= 0) return null;
  return {
    type: focus.nat,
    rule: focus.rule,
    idx: focus.idx,
  };
}

function natFocusIssueAlert(issue = {}) {
  const label = issue.type === "source" ? "source NAT" : "destination NAT";
  const target = issue.rule || (issue.idx !== "" ? `index ${Number(issue.idx) + 1}` : "requested item");
  return h("div", { class: "alert-box warn", dataset: { natFocusMissing: "true", natFocusType: issue.type, natFocusTarget: target }, style: { marginBottom: "16px" } },
    h("strong", {}, "NAT route target not found. "),
    `The linked ${label} target ${target} is not present in the staged candidate. Reload after refreshing policy, or use the current row ID/name from this table.`,
    h("div", { class: "toolbar compact", style: { marginTop: "10px" } },
      h("a", { class: "btn sm ghost", href: "#/nat", title: "Clear missing NAT route focus", "aria-label": "Clear missing NAT route focus", dataset: { natAction: "clear-focus" } }, "Clear focus")));
}

function natSideFromReferenceArea(area = "") {
  const normalized = String(area || "").trim().toLowerCase();
  if (normalized === "source nat") return "source";
  if (normalized === "destination nat") return "destination";
  return "";
}

function normalizeNatFocusSide(value = "") {
  const normalized = String(value || "").trim().toLowerCase().replace(/[\s_-]+/g, " ");
  if (normalized === "source" || normalized === "source nat" || normalized === "snat") return "source";
  if (normalized === "destination" || normalized === "destination nat" || normalized === "dnat") return "destination";
  return "";
}

function normalizeNatFocusIndex(value = "") {
  if (value == null || value === "") return "";
  const n = Number(value);
  return Number.isInteger(n) && n >= 0 ? String(n) : "";
}

function isMissingCandidateError(err) {
  return /candidate policy is set|candidate.*not found|no candidate/i.test(errorMessage(err));
}

function errorMessage(err) {
  return err?.message || String(err || "unknown error");
}

function pathDeltaTable(rows = []) {
  return responsiveTable(["Decision point", "Running", "Candidate"],
    rows.map((row) => h("tr", { class: row.changed ? "selected-row" : "" },
      labeledCell("Decision point", {}, row.tone ? pill(row.label, row.tone) : h("strong", {}, row.label)),
      labeledCell("Running", { class: "mono" }, row.running),
      labeledCell("Candidate", { class: "mono" }, row.candidate))),
    { className: "nat-path-delta-table" });
}

function pathCouplingReviewPanel(review = {}) {
  const tone = review.tone === "bad" ? "bad" : review.tone === "ok" ? "ok" : "warn";
  const actionButton = (action = {}, fallbackLabel = "Open review") => {
    const label = action.label || fallbackLabel;
    const detail = action.detail || `Open ${label.toLowerCase()} context`;
    const key = action.key || "open";
    return h("a", {
      class: "btn sm ghost nat-coupling-action",
      href: action.href || "#/nat",
      title: detail,
      "aria-label": `${label}: ${detail}`,
      dataset: { natCouplingAction: key },
    }, h("span", { html: icon("search", 14) }), h("span", {}, label));
  };
  return h("div", { class: "alert-box " + tone, dataset: { natCouplingReview: "true", natCouplingTone: tone } },
    h("strong", {}, "Path coupling review"),
    h("div", { class: "note" }, review.summary || "Review policy, NAT, route, and egress before commit."),
    h("div", { class: "automation-list compact" }, (review.items || []).map((item) =>
      h("div", { class: "automation-row", dataset: { natCouplingRow: item.key || "" } },
        h("div", { class: "automation-meta" },
          pill(item.label || "Review", item.tone || "warn"),
          h("span", {}, item.detail || "")),
        item.href ? actionButton({ key: item.key || "open", href: item.href, label: item.label ? `Open ${item.label}` : "Open review", detail: item.detail || "Open related NAT coupling context" }) : null))),
    h("div", { class: "toolbar compact" }, (review.actions || []).map((action) =>
      actionButton(action, "Open review"))));
}

function simList(title, lines = [], cls = "", profile = "") {
  const attrs = { class: "sim-list " + cls };
  if (profile) attrs["data-flow-check-profile"] = profile;
  return h("div", attrs,
    h("span", {}, title),
    lines.length ? h("ol", {}, lines.slice(0, 5).map((line) => h("li", {}, line))) : h("div", { class: "note" }, "No entries."));
}

function sourceNatPanel(root, rules) {
  const focusedIdx = focusedNatRuleIndex(focusRoute, "source", rules);
  const head = h("div", { class: "card-head" },
    h("h2", {}, "Source NAT"),
    h("span", { class: "spacer" }),
    h("button", { class: "btn sm", type: "button", title: "Add source NAT rule", "aria-label": "Add source NAT rule", dataset: { natAction: "add-source" }, onclick: () => editSourceNat(root, null) }, h("span", { html: icon("plus", 14) }), "Add"));
  if (!rules.length) {
    return h("section", { class: "card" }, head,
      emptyState("nat", "No source NAT", "Translate inside clients as they leave an egress zone.",
        h("button", { class: "btn primary", type: "button", title: "Add source NAT rule", "aria-label": "Add source NAT rule", dataset: { natAction: "add-source" }, onclick: () => editSourceNat(root, null) }, h("span", { html: icon("plus", 16) }), "Add source NAT")));
  }
  return h("section", { class: "card surface-zero" },
    h("div", { class: "section-head-pad" }, head),
    h("div", { class: "table-wrap flat" }, responsiveTable(["Name", "Egress zone", "Source", "Translation", { label: "", attrs: { class: "actions-col" } }],
      rules.map((r, i) => h("tr", natRuleRowAttrs("source", r, i, focusedIdx),
        labeledCell("Name", { onclick: () => editSourceNat(root, i) }, natRuleIdentityNode(r, i)),
        labeledCell("Egress zone", { onclick: () => editSourceNat(root, i) }, tag(r.toZone || "—")),
        labeledCell("Source", { onclick: () => editSourceNat(root, i) }, tag(r.sourceAddress || "any")),
        labeledCell("Translation", { onclick: () => editSourceNat(root, i) },
          r.masquerade ? pill("masquerade", "info") : tag(r.translatedAddress || "—")),
        labeledCell("Actions", { class: "cell-actions" }, rowActions(
          () => previewSourceNatRule(root, r),
          () => editSourceNat(root, i),
          () => deleteSourceNat(root, i, r),
          "source",
          r,
          i)))))));
}

function destinationNatPanel(root, rules) {
  const focusedIdx = focusedNatRuleIndex(focusRoute, "destination", rules);
  const head = h("div", { class: "card-head" },
    h("h2", {}, "Destination NAT"),
    h("span", { class: "spacer" }),
    h("button", { class: "btn sm", type: "button", title: "Add destination NAT rule", "aria-label": "Add destination NAT rule", dataset: { natAction: "add-destination" }, onclick: () => editDestinationNat(root, null) }, h("span", { html: icon("plus", 14) }), "Add"));
  if (!rules.length) {
    return h("section", { class: "card" }, head,
      emptyState("nat", "No destination NAT", "Publish an internal service behind an address on an ingress zone.",
        h("button", { class: "btn primary", type: "button", title: "Add destination NAT rule", "aria-label": "Add destination NAT rule", dataset: { natAction: "add-destination" }, onclick: () => editDestinationNat(root, null) }, h("span", { html: icon("plus", 16) }), "Add destination NAT")));
  }
  return h("section", { class: "card surface-zero" },
    h("div", { class: "section-head-pad" }, head),
    h("div", { class: "table-wrap flat" }, responsiveTable(["Name", "Ingress zone", "Public destination", "Service", "Translated to", { label: "", attrs: { class: "actions-col" } }],
      rules.map((r, i) => h("tr", natRuleRowAttrs("destination", r, i, focusedIdx),
        labeledCell("Name", { onclick: () => editDestinationNat(root, i) }, natRuleIdentityNode(r, i)),
        labeledCell("Ingress zone", { onclick: () => editDestinationNat(root, i) }, tag(r.fromZone || "—")),
        labeledCell("Public destination", { onclick: () => editDestinationNat(root, i) }, tag(r.destinationAddress || "—")),
        labeledCell("Service", { onclick: () => editDestinationNat(root, i) }, tag(r.service || "—")),
        labeledCell("Translated to", { onclick: () => editDestinationNat(root, i) },
          tag([r.translatedAddress || "—", r.translatedPort ? ":" + r.translatedPort : ""].join(""))),
        labeledCell("Actions", { class: "cell-actions" }, rowActions(
          () => previewDestinationNatRule(root, r),
          () => editDestinationNat(root, i),
          () => deleteDestinationNat(root, i, r),
          "destination",
          r,
          i)))))));
}

function previewSourceNatRule(root, rule = {}) {
  stageSourceNatPreview(rule, { action: "review" });
  paint(root);
  toast("Source NAT preview queued", "Running and candidate path review will use this source NAT tuple.", "ok");
}

function previewDestinationNatRule(root, rule = {}) {
  const linkedRule = findPublishRule(rule);
  const targetZone = (linkedRule?.toZones || [])[0] || suggestedTargetZone(rule.fromZone, names(session.draft.zones));
  stageDestinationNatPreview(rule, targetZone, linkedRule?.name || "", { action: "review" });
  paint(root);
  toast("Destination NAT preview queued", "Running and candidate path review will use this destination NAT tuple.", "ok");
}

function editSourceNat(root, idx) {
  const editing = idx != null;
  const rule = editing ? structuredClone(session.draft.nat?.source?.[idx] || {}) : {};
  const zones = names(session.draft.zones);
  const addrs = names(session.draft.addresses);
  const hostAddrs = hostAddressNames(session.draft.addresses);
  const pendingAddresses = [];
  const name = text(rule.name, "lan-masq", { dataset: { natSourceField: "name" } });
  const toZone = select(zones, rule.toZone, "Select egress zone", { dataset: { natSourceField: "egress-zone" } });
  const sourceAddress = select(addrs, rule.sourceAddress, "Any source", { dataset: { natSourceField: "source-address" } });
  const mode = h("select", { class: "input", dataset: { natSourceField: "translation-mode", natSourceMode: "true" } },
    h("option", { value: "masquerade" }, "Masquerade on egress interface"),
    h("option", { value: "static" }, "Static source address"));
  mode.value = rule.masquerade || !rule.translatedAddress ? "masquerade" : "static";
  const translatedAddress = select(hostAddrs, rule.translatedAddress, "Select translated host address", { dataset: { natSourceField: "translated-address" } });
  const translatedField = field("Translated address", translatedAddress, "required for static source NAT");
  const translatedCreator = inlineHostCreator("Create translated host", translatedAddress, pendingAddresses);
  const syncMode = () => {
    const hidden = mode.value !== "static";
    translatedField.hidden = hidden;
    translatedCreator.hidden = hidden;
  };
  mode.onchange = syncMode;
  syncMode();

  openDrawer({
    title: editing ? "Edit source NAT" : "Add source NAT",
    subtitle: "Applied in postrouting for traffic leaving the selected zone.",
    width: "560px",
    body: h("div", { dataset: { natSourceEditor: "true" } },
      field("Name", name),
      field("Egress zone", toZone),
      field("Source address", sourceAddress, "blank means any source"),
      field("Translation", mode),
      translatedField,
      translatedCreator),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Cancel source NAT edit", "aria-label": "Cancel source NAT edit", dataset: { natAction: "cancel-source-edit" }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: editing ? "Save source NAT rule" : "Add source NAT rule", "aria-label": editing ? "Save source NAT rule" : "Add source NAT rule", dataset: { natAction: "save-source" }, onclick: () => saveSourceNat(root, idx, { name, toZone, sourceAddress, mode, translatedAddress, pendingAddresses }) },
        h("span", { html: icon("check", 16) }), editing ? "Save source NAT" : "Add source NAT"),
    ],
  });
}

async function saveSourceNat(root, idx, inputs) {
  const name = inputs.name.value.trim();
  const toZone = inputs.toZone.value;
  if (!name) return toast("Name required", "Give the source NAT entry a name.", "warn");
  if (!toZone) return toast("Egress zone required", "Select the zone whose interfaces perform translation.", "warn");
  const previous = idx != null ? structuredClone(session.draft.nat?.source?.[idx] || {}) : null;
  const item = { name, toZone };
  if (previous?.id) item.id = previous.id;
  if (inputs.sourceAddress.value) item.sourceAddress = inputs.sourceAddress.value;
  if (inputs.mode.value === "static") {
    if (!inputs.translatedAddress.value) return toast("Translated address required", "Static source NAT needs a host address object.", "warn");
    item.translatedAddress = inputs.translatedAddress.value;
  } else {
    item.masquerade = true;
  }
  const pendingIssue = validatePendingNatObjects(session.draft || {}, inputs.pendingAddresses || [], []);
  if (pendingIssue) return toast(pendingIssue.title, pendingIssue.message, pendingIssue.tone || "warn");
  const hasCompoundChanges = pendingNatObjectsChange(session.draft || {}, inputs.pendingAddresses || [], []);
  try {
    if (idx != null && equal(previous, item) && !hasCompoundChanges) {
      closeDrawer();
      return toast("No source NAT changes", "The candidate already matches this source NAT editor state.", "warn");
    }
    let staged = item;
    if (!hasCompoundChanges && canUseGranularNatUpsert(previous, item)) {
      staged = await stageGranularSourceNat(item, previous, idx != null ? "edit" : "add");
    } else {
      await session.apply((d) => {
        ensurePendingAddressObjects(d, inputs.pendingAddresses || []);
        d.nat ||= {};
        d.nat.source ||= [];
        if (idx != null) d.nat.source[idx] = item;
        else d.nat.source.push(item);
        normalizeNat(d);
      });
    }
    closeDrawer();
    stageSourceNatPreview(staged, { action: idx != null ? "edit" : "add", previous });
    paint(root);
    toast(idx != null ? "Source NAT saved" : "Source NAT added", "Staged to candidate.", "ok");
  } catch (e) {
    toast("Could not stage source NAT", e.message, "bad");
  }
}

function editDestinationNat(root, idx) {
  const editing = idx != null;
  const rule = editing ? structuredClone(session.draft.nat?.destination?.[idx] || {}) : {};
  const zones = names(session.draft.zones);
  const hostAddrs = hostAddressNames(session.draft.addresses);
  const svcs = tcpUdpServiceNames(session.draft.services);
  const pendingAddresses = [];
  const pendingServices = [];
  const name = text(rule.name, "web-dnat");
  const fromZone = select(zones, rule.fromZone, "Select ingress zone");
  const service = select(svcs, rule.service, "Select TCP/UDP service");
  const destinationAddress = select(hostAddrs, rule.destinationAddress, "Select public host address");
  const translatedAddress = select(hostAddrs, rule.translatedAddress, "Select internal host address");
  const translatedPort = h("input", { class: "input", type: "number", min: "0", max: "65535", value: rule.translatedPort || "", placeholder: "keep original" });
  const existingPublishRule = editing ? findPublishRule(rule) : null;
  const existingPublishTarget = (existingPublishRule?.toZones || [])[0] || "";
  const publishAllow = checkbox(!editing || Boolean(existingPublishTarget));
  const targetZone = select(zones, existingPublishTarget || suggestedTargetZone(rule.fromZone, zones), "Select target zone");
  const targetZoneField = field("Target zone", targetZone, "allow rule destination zone");
  const syncPublish = () => { targetZoneField.hidden = !publishAllow.checked; };
  publishAllow.querySelector("input").onchange = syncPublish;
  syncPublish();

  openDrawer({
    title: editing ? "Edit destination NAT" : "Add destination NAT",
    subtitle: "Applied in prerouting before forwarding policy evaluation.",
    width: "600px",
    body: h("div", { dataset: { natDestinationEditor: "true" } },
      field("Name", name),
      h("div", { class: "form-grid two" },
        field("Ingress zone", fromZone),
        field("Service", service, "must be TCP or UDP"),
        field("Public destination", destinationAddress, "host address object"),
        field("Translated address", translatedAddress, "host address object")),
      inlineServiceCreator("Create service object", service, pendingServices),
      h("div", { class: "form-grid two" },
        inlineHostCreator("Create public host", destinationAddress, pendingAddresses),
        inlineHostCreator("Create internal host", translatedAddress, pendingAddresses)),
      field("Translated port", translatedPort, "optional; leave blank to keep the original port"),
      h("div", { class: "alert-box neutral", dataset: { natPublishAssistant: "true" } },
        h("strong", {}, "Publish plan"),
        h("ol", { class: "compact-list" },
          h("li", {}, "Queue any missing public address, internal address, and TCP/UDP service objects."),
          h("li", {}, "Stage destination NAT in the candidate policy."),
          h("li", {}, "Stage the matching allow rule so forwarding policy matches the translated service."),
          h("li", {}, "Review the running-vs-candidate path preview before commit."))),
      h("div", { class: "alert-box info" },
        h("div", { class: "field flex", style: { justifyContent: "space-between", marginBottom: "8px" } },
        h("span", {}, "Stage matching allow rule"),
          publishAllow),
        h("div", { class: "note" }, "Creates or updates an allow rule from the ingress zone to the translated host using this service."),
        existingPublishRule ? h("div", { class: "note" }, `Linked generated rule: ${existingPublishRule.name}`) : null,
        targetZoneField)),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Cancel destination NAT edit", "aria-label": "Cancel destination NAT edit", dataset: { natAction: "cancel-destination-edit" }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: editing ? "Save destination NAT rule" : "Add destination NAT rule", "aria-label": editing ? "Save destination NAT rule" : "Add destination NAT rule", dataset: { natAction: "save-destination" }, onclick: () => saveDestinationNat(root, idx, { name, fromZone, service, destinationAddress, translatedAddress, translatedPort, publishAllow, targetZone, publishRuleName: existingPublishRule?.name || "", pendingAddresses, pendingServices }) },
        h("span", { html: icon("check", 16) }), editing ? "Save destination NAT" : "Add destination NAT"),
    ],
  });
}

async function saveDestinationNat(root, idx, inputs) {
  const item = {
    name: inputs.name.value.trim(),
    fromZone: inputs.fromZone.value,
    service: inputs.service.value,
    destinationAddress: inputs.destinationAddress.value,
    translatedAddress: inputs.translatedAddress.value,
  };
  const previous = idx != null ? structuredClone(session.draft.nat?.destination?.[idx] || {}) : null;
  if (previous?.id) item.id = previous.id;
  if (!item.name) return toast("Name required", "Give the destination NAT entry a name.", "warn");
  if (!item.fromZone || !item.service || !item.destinationAddress || !item.translatedAddress) {
    return toast("Missing fields", "Select the ingress zone, service, public address, and translated address.", "warn");
  }
  if (inputs.publishAllow.checked && !inputs.targetZone.value) {
    return toast("Target zone required", "Select the destination zone for the matching allow rule.", "warn");
  }
  const portText = String(inputs.translatedPort.value || "").trim();
  if (portText) {
    if (!/^[0-9]+$/.test(portText)) return toast("Translated port invalid", "Use a whole TCP/UDP port number from 1 to 65535, or leave it blank.", "warn");
    const port = Number(portText);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return toast("Translated port invalid", "Use a whole TCP/UDP port number from 1 to 65535, or leave it blank.", "warn");
    item.translatedPort = port;
  }
  const pendingIssue = validatePendingNatObjects(session.draft || {}, inputs.pendingAddresses || [], inputs.pendingServices || []);
  if (pendingIssue) return toast(pendingIssue.title, pendingIssue.message, pendingIssue.tone || "warn");
  const hasCompoundChanges = pendingNatObjectsChange(session.draft || {}, inputs.pendingAddresses || [], inputs.pendingServices || []) ||
    destinationNatPublishIntentChanged(session.draft || {}, item, {
      publishAllow: Boolean(inputs.publishAllow.checked),
      targetZone: inputs.targetZone.value,
      publishRuleName: inputs.publishRuleName,
    });
  let ruleName = "";
  let removedRuleName = "";
  try {
    if (idx != null &&
      equal(previous, item) &&
      !hasCompoundChanges) {
      closeDrawer();
      return toast("No destination NAT changes", "The candidate already matches this destination NAT and publish-rule editor state.", "warn");
    }
    let staged = item;
    if (!hasCompoundChanges && canUseGranularNatUpsert(previous, item)) {
      staged = await stageGranularDestinationNat(item, previous, idx != null ? "edit" : "add");
    } else {
      await session.apply((d) => {
        ensurePendingAddressObjects(d, inputs.pendingAddresses || []);
        ensurePendingServices(d, inputs.pendingServices || []);
        d.nat ||= {};
        d.nat.destination ||= [];
        if (idx != null) d.nat.destination[idx] = item;
        else d.nat.destination.push(item);
        if (inputs.publishAllow.checked) ruleName = upsertPublishRule(d, item, inputs.targetZone.value, inputs.publishRuleName);
        else removedRuleName = removeGeneratedPublishRule(d, inputs.publishRuleName);
        normalizeNat(d);
      });
    }
    closeDrawer();
    stageDestinationNatPreview(staged, inputs.targetZone.value, ruleName);
    paint(root);
    toast(idx != null ? "Destination NAT saved" : "Destination NAT added",
      ruleName
        ? `${item.name} and ${ruleName} staged; previewing candidate path.`
        : removedRuleName
          ? `${item.name} staged and ${removedRuleName} removed; previewing candidate path.`
          : "Staged to candidate; previewing candidate path.", "ok");
  } catch (e) {
    toast("Could not stage destination NAT", e.message, "bad");
  }
}

function stageDestinationNatPreview(item, targetZone = "", ruleName = "", opts = {}) {
  const flow = destinationNatPreviewFlow(session.draft || {}, item, targetZone);
  invalidateNatPreviewRequest();
  Object.assign(preview, flow, {
    initialized: true,
    loading: false,
    error: "",
    warning: "",
    contextNote: ruleName
      ? destinationNatContextNote(item, { ...opts, ruleName })
      : destinationNatContextNote(item, opts),
    running: null,
    candidate: null,
    runRequested: true,
    autorunKey: "",
  });
  syncNatPreviewRoute(true);
}

function destinationNatContextNote(item = {}, opts = {}) {
  if (opts.action === "review") {
    return opts.ruleName
      ? `Destination NAT ${item.name || "entry"} path review queued with generated allow rule ${opts.ruleName}; review running versus candidate before commit.`
      : `Destination NAT ${item.name || "entry"} path review queued; review running versus candidate before commit.`;
  }
  if (opts.ruleName) {
    return `Publish assistant staged ${item.name} with allow rule ${opts.ruleName}; review this candidate path before commit.`;
  }
  return `Publish assistant staged ${item.name}; review this candidate path before commit.`;
}

function stageSourceNatPreview(item, opts = {}) {
  const flow = sourceNatPreviewFlow(session.draft || {}, item);
  invalidateNatPreviewRequest();
  Object.assign(preview, flow, {
    initialized: true,
    loading: false,
    error: "",
    warning: "",
    contextNote: sourceNatContextNote(item, opts),
    running: null,
    candidate: null,
    runRequested: true,
    autorunKey: "",
  });
  syncNatPreviewRoute(true);
}

function sourceNatContextNote(item = {}, opts = {}) {
  if (opts.action === "delete") return `Source NAT ${item.name || "entry"} deleted from candidate; review this path before commit.`;
  if (opts.action === "edit") return `Source NAT ${item.name || "entry"} edited in candidate; review this egress path before commit.`;
  if (opts.action === "review") return `Source NAT ${item.name || "entry"} path review queued; review running versus candidate before commit.`;
  return `Source NAT ${item.name || "entry"} staged in candidate; review this egress path before commit.`;
}

function sourceNatPreviewFlow(policy = {}, snat = {}) {
  const fromZone = firstOtherZone(policy.zones, snat.toZone);
  return {
    fromZone,
    toZone: snat.toZone || "",
    srcIp: addressIp(policy, snat.sourceAddress) || representativeZoneIp(policy, fromZone) || "10.0.1.20",
    srcPort: "51515",
    destIp: representativeOutsideIp(snat.toZone),
    destPort: "443",
    protocol: "PROTOCOL_TCP",
  };
}

function deleteSourceNat(root, idx, rule = {}) {
  const review = sourceNatDeleteImpactReview(session.draft || {}, rule, { index: idx });
  const mutation = natMutationContext("source", "delete", rule);
  openDrawer({
    title: "Delete source NAT?",
    subtitle: "Candidate-only egress path impact review.",
    width: "680px",
    body: h("div", { dataset: { natDeleteSourceReview: "true", natRuleName: review.ruleName, natMutationSelector: mutation.selectorKind, natMutationPath: mutation.path } },
      h("div", { class: "alert-box warn" },
        h("strong", {}, "Candidate-only removal. "),
        `This removes ${review.ruleName} from the candidate. Running policy is unchanged until commit.`),
      h("dl", { class: "kv compact" },
        h("dt", {}, "Source NAT"), h("dd", { class: "mono" }, review.ruleName),
        h("dt", {}, "Affected source zones"), h("dd", { class: "mono" }, review.affectedSourceZones.join(", ")),
        h("dt", {}, "Source address"), h("dd", { class: "mono" }, review.sourceAddress),
        h("dt", {}, "Egress zone"), h("dd", { class: "mono" }, review.egressZone),
        h("dt", {}, "Translation"), h("dd", { class: "mono" }, review.translatedAction)),
      h("div", { class: "alert-box neutral", dataset: { natSourceDeleteTuple: "true" } },
        h("strong", {}, "Representative tuple"),
        h("div", { class: "note mono" }, natFlowTupleLabel(review.flow)),
        h("div", { class: "note" }, review.candidateEffect)),
      h("div", { class: "automation-list compact" },
        h("div", { class: "automation-row" },
          h("div", { class: "automation-meta" },
            pill("API", "info"),
            h("span", {}, `${mutation.method} ${mutation.path}`)),
          h("button", { class: "btn sm ghost", type: "button", title: `Copy API delete for source NAT ${review.ruleName}`, "aria-label": `Copy API delete for source NAT ${review.ruleName}`, dataset: { natSourceDeleteAction: "copy-api" }, onclick: () => copyNatMutationApi("Source NAT delete API copied", mutation) }, h("span", { html: icon("copy", 14) }), "Copy API")),
        h("div", { class: "automation-row" },
          h("div", { class: "automation-meta" },
            pill("CLI", "neutral"),
            h("span", {}, mutation.cli)),
          h("button", { class: "btn sm ghost", type: "button", title: `Copy CLI delete for source NAT ${review.ruleName}`, "aria-label": `Copy CLI delete for source NAT ${review.ruleName}`, dataset: { natSourceDeleteAction: "copy-cli" }, onclick: () => copyNatMutationCli("Source NAT delete command copied", mutation) }, h("span", { html: icon("copy", 14) }), "Copy CLI")),
        h("div", { class: "automation-row" },
          h("div", { class: "automation-meta" },
            pill("Troubleshoot", "warn"),
            h("span", {}, "Open the same tuple in the running/candidate compare workflow.")),
          h("a", { class: "btn sm", href: review.troubleshootHash, title: `Open Troubleshoot compare for source NAT ${review.ruleName}`, "aria-label": `Open Troubleshoot compare for source NAT ${review.ruleName}`, dataset: { natSourceDeleteAction: "troubleshoot" } }, h("span", { html: icon("search", 14) }), "Open Troubleshoot"))),
      h("div", { class: "note" }, "After confirmation, the NAT path preview will run on this same tuple so the operator can compare running versus the staged candidate before commit.")),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Cancel source NAT delete", "aria-label": "Cancel source NAT delete", dataset: { natAction: "cancel-delete-source" }, onclick: closeDrawer }, "Cancel"),
      h("a", { class: "btn", href: review.previewHash, title: `Preview current path for source NAT ${review.ruleName}`, "aria-label": `Preview current path for source NAT ${review.ruleName}`, dataset: { natSourceDeleteAction: "preview-current" } }, h("span", { html: icon("search", 16) }), "Preview current"),
      h("button", { class: "btn danger", type: "button", title: `Delete source NAT ${review.ruleName}`, "aria-label": `Delete source NAT ${review.ruleName}`, dataset: { natAction: "confirm-delete-source" }, onclick: () => confirmDeleteSourceNat(root, idx, rule) },
        h("span", { html: icon("trash", 16) }), "Delete"),
    ],
  });
}

async function confirmDeleteSourceNat(root, idx, rule) {
  try {
    const removed = structuredClone(rule || {});
    await deleteGranularSourceNat(rule);
    closeDrawer();
    stageSourceNatPreview(removed, { action: "delete" });
    paint(root);
    toast("Source NAT deleted", "Staged to candidate.", "ok");
  } catch (e) {
    toast("Could not delete source NAT", e.message, "bad");
  }
}

function natFlowTupleLabel(flow = {}) {
  const proto = String(flow.protocol || "PROTOCOL_TCP").replace("PROTOCOL_", "").toLowerCase();
  const src = `${flow.srcIp || "-"}:${flow.srcPort || "0"}`;
  const dst = `${flow.destIp || "-"}:${flow.destPort || "0"}`;
  return `${flow.fromZone || "any"} -> ${flow.toZone || "any"} - ${proto} - ${src} -> ${dst}`;
}

async function copyNatMutationApi(title, mutation = {}) {
  await copyNatReviewText(title, natMutationContextText(mutation), `Copy ${mutation.method || "PUT"} ${mutation.path || ""} into a guarded operator request.`);
}

async function copyNatMutationCli(title, mutation = {}) {
  await copyNatReviewText(title, mutation.cli || "", "Run from a trusted operator shell with the current candidate revision.");
}

async function copyNatReviewText(title, text, detail) {
  try {
    if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(text);
    toast(title, detail, "ok");
  } catch {
    toast("Copy unavailable", "Select and copy the review text from this drawer.", "warn");
  }
}

function deleteDestinationNat(root, idx, rule = {}) {
  const linkedRule = findPublishRule(rule);
  const removeLinked = checkbox(Boolean(linkedRule));
  const linkedName = linkedRule?.name || "";
  const linkedTargetZone = (linkedRule?.toZones || [])[0] || "";
  const mutation = natMutationContext("destination", "delete", rule);
  openDrawer({
    title: "Delete destination NAT?",
    subtitle: "Reviewed candidate cleanup for published services.",
    width: "620px",
    body: h("div", { dataset: { natDeleteDestinationReview: "true", natMutationSelector: mutation.selectorKind, natMutationPath: mutation.path } },
      h("div", { class: "alert-box warn" },
        h("strong", {}, "Candidate-only removal. "),
        `This removes ${rule.name || "the destination NAT entry"} from the candidate. Running policy is unchanged until commit.`),
      h("dl", { class: "kv compact" },
        h("dt", {}, "Destination NAT"), h("dd", { class: "mono" }, rule.name || "unnamed"),
        h("dt", {}, "Ingress"), h("dd", { class: "mono" }, rule.fromZone || "—"),
        h("dt", {}, "Public destination"), h("dd", { class: "mono" }, rule.destinationAddress || "—"),
        h("dt", {}, "Translated target"), h("dd", { class: "mono" }, rule.translatedAddress || "—"),
        h("dt", {}, "Service"), h("dd", { class: "mono" }, rule.service || "—")),
      linkedRule ? h("div", { class: "alert-box info", dataset: { natLinkedPublishRule: linkedName } },
        h("strong", {}, "Linked generated allow rule found. "),
        h("span", { class: "mono" }, linkedName),
        h("label", { class: "field flex", style: { justifyContent: "space-between", marginTop: "10px", marginBottom: 0 } },
          h("span", {}, "Delete linked generated allow rule"),
          removeLinked),
        h("div", { class: "note" }, "Only generated DNAT publish rules are eligible. Operator-owned allow rules are preserved.")) :
        h("div", { class: "alert-box neutral" },
          h("strong", {}, "No linked generated allow rule found. "),
          "Only the destination NAT entry will be removed."),
      h("div", { class: "automation-list compact" },
        h("div", { class: "automation-row" },
          h("div", { class: "automation-meta" },
            pill("API", "info"),
            h("span", {}, `${mutation.method} ${mutation.path}`)),
          h("button", { class: "btn sm ghost", type: "button", title: "Copy destination NAT delete API request", "aria-label": "Copy destination NAT delete API request", dataset: { natDestinationDeleteAction: "copy-api" }, onclick: () => copyNatMutationApi("Destination NAT delete API copied", mutation) }, "Copy")),
        h("div", { class: "automation-row" },
          h("div", { class: "automation-meta" },
            pill("CLI", "neutral"),
            h("span", {}, mutation.cli)),
          h("button", { class: "btn sm ghost", type: "button", title: "Copy destination NAT delete CLI command", "aria-label": "Copy destination NAT delete CLI command", dataset: { natDestinationDeleteAction: "copy-cli" }, onclick: () => copyNatMutationCli("Destination NAT delete command copied", mutation) }, "Copy"))),
      h("div", { class: "note" }, "After staging, the NAT path preview opens on the former published tuple so the operator can review the candidate impact before commit.")),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Cancel destination NAT delete", "aria-label": "Cancel destination NAT delete", dataset: { natAction: "cancel-delete-destination" }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn danger", type: "button", title: `Delete destination NAT ${rule.name || "entry"}`, "aria-label": `Delete destination NAT ${rule.name || "entry"}`, dataset: { natAction: "confirm-delete-destination" }, onclick: () => confirmDeleteDestinationNat(root, idx, rule, { linkedRuleName: linkedName, linkedTargetZone, removeLinked }) },
        h("span", { html: icon("trash", 16) }), "Delete destination NAT"),
    ],
  });
}

async function confirmDeleteDestinationNat(root, idx, rule, opts = {}) {
  try {
    const removed = structuredClone(rule || {});
    let removedRuleName = "";
    const linkedRuleName = opts.linkedRuleName || "";
    if (linkedRuleName && Boolean(opts.removeLinked?.checked)) {
      await session.apply((d) => {
        const result = removeDestinationNatWithPublishRule(d, idx, {
          linkedRuleName,
          removeLinkedRule: true,
        });
        removedRuleName = result.removedRuleName;
      });
    } else {
      await deleteGranularDestinationNat(rule);
    }
    closeDrawer();
    stageDeletedDestinationNatPreview(removed, {
      linkedRuleName,
      linkedTargetZone: opts.linkedTargetZone || "",
      removedRuleName,
      preservedRule: linkedRuleName && !removedRuleName,
    });
    paint(root);
    toast("Destination NAT deleted",
      removedRuleName ? `${removed.name || "Entry"} and ${removedRuleName} removed from candidate.` : "Staged to candidate.",
      "ok");
  } catch (e) {
    toast("Could not delete destination NAT", e.message, "bad");
  }
}

function stageDeletedDestinationNatPreview(item = {}, opts = {}) {
  const targetZone = opts.linkedTargetZone || (opts.removedRuleName || opts.linkedRuleName
    ? publishRuleTargetZone(session.draft || {}, opts.removedRuleName || opts.linkedRuleName)
    : "") ||
    suggestedTargetZone(item.fromZone, names(session.draft.zones));
  const flow = destinationNatPreviewFlow(session.draft || {}, item, targetZone);
  invalidateNatPreviewRequest();
  Object.assign(preview, flow, {
    initialized: true,
    loading: false,
    error: "",
    warning: "",
    contextNote: destinationNatDeleteContextNote(item, opts),
    running: null,
    candidate: null,
    runRequested: true,
    autorunKey: "",
  });
  syncNatPreviewRoute(true);
}

function destinationNatDeleteContextNote(item = {}, opts = {}) {
  if (opts.removedRuleName) {
    return `Destination NAT ${item.name || "entry"} deleted from candidate and linked generated allow rule ${opts.removedRuleName} removed; review the former published path before commit.`;
  }
  if (opts.preservedRule && opts.linkedRuleName) {
    return `Destination NAT ${item.name || "entry"} deleted from candidate; linked generated allow rule ${opts.linkedRuleName} was preserved by operator choice.`;
  }
  return `Destination NAT ${item.name || "entry"} deleted from candidate; review the former published path before commit.`;
}

function rowActions(previewRule, edit, del, type = "", rule = {}, idx = 0) {
  const button = (title, action, fn, ico) => h("button", {
    class: "icon-btn",
    type: "button",
    title,
    "aria-label": title,
    dataset: { natAction: `${action}-${type}`, natRuleName: rule?.name || "", natRuleId: natRuleDurableId(rule) },
    onclick: (e) => { e.stopPropagation(); fn(); },
    html: icon(ico, 16),
  });
  const id = natRuleDurableId(rule);
  const copyTitle = id ? "Copy durable NAT route and API context" : "Copy legacy NAT route and API context";
  return h("div", { class: "flex", style: { justifyContent: "flex-end", gap: "2px" } },
    button("Preview path", "preview", previewRule, "search"),
    button(copyTitle, "copy-route", () => copyNatRuleRoute(type, rule, idx), "copy"),
    button("Edit", "edit", edit, "edit"),
    button("Delete", "delete", del, "trash"));
}

async function copyNatRuleRoute(type, rule = {}, idx = 0) {
  const id = natRuleDurableId(rule);
  const route = natRuleRouteHash(type, rule, idx);
  const update = natMutationContext(type, "update", rule, rule);
  const del = natMutationContext(type, "delete", rule);
  const body = [
    `${type === "source" ? "Source NAT" : "Destination NAT"} ${rule.name || "unnamed"}`,
    id ? `id=${id}` : `name=${rule.name || ""}`,
    `route=${route}`,
    "",
    `update=${update.method} ${update.path}`,
    `delete=${del.method} ${del.path}`,
    `update_cli=${update.cli}`,
    `delete_cli=${del.cli}`,
  ].filter(Boolean).join("\n");
  try {
    if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(body);
    toast("NAT context copied", id ? "Durable NAT route and by-ID API/CLI context copied." : "Legacy NAT route and name-keyed API/CLI context copied.", "ok");
  } catch {
    toast("Copy unavailable", "Open the row and copy the route/API context from the table.", "warn");
  }
}

export function normalizeNat(policy) {
  if (!policy.nat) return;
  if (!policy.nat.source?.length) delete policy.nat.source;
  if (!policy.nat.destination?.length) delete policy.nat.destination;
  if (!policy.nat.source && !policy.nat.destination) delete policy.nat;
}

export function upsertPublishRule(policy, dnat, targetZone, preferredName = "") {
  policy.rules ||= [];
  const existing = policy.rules.find((r) => preferredName && r.name === preferredName && generatedPublishRule(r)) || policy.rules.find((r) =>
    generatedPublishRule(r, dnat.name) ||
    (generatedPublishRule(r) &&
      sameRefs(r.fromZones, [dnat.fromZone]) &&
      sameRefs(r.toZones, [targetZone]) &&
      sameRefs(r.destinationAddresses, [dnat.translatedAddress]) &&
      sameRefs(r.services, [dnat.service]) &&
      r.action === "ACTION_ALLOW"));
  const rule = {
    name: existing?.name || uniqueName(policy.rules, sanitizeName(`allow-${dnat.fromZone}-to-${targetZone}-${dnat.translatedAddress}-${dnat.service}`)),
    fromZones: [dnat.fromZone],
    toZones: [targetZone],
    sourceAddresses: [],
    destinationAddresses: [dnat.translatedAddress],
    services: [dnat.service],
    action: "ACTION_ALLOW",
    log: true,
    disabled: false,
    description: `Created from DNAT ${dnat.name} to publish ${dnat.translatedAddress}.`,
    tags: publishRuleTags(dnat),
  };
  if (existing) Object.assign(existing, rule);
  else policy.rules.splice(publishInsertIndex(policy.rules), 0, rule);
  return rule.name;
}

export function destinationNatPublishIntentChanged(policy = {}, dnat = {}, opts = {}) {
  const preferredName = String(opts.publishRuleName || "").trim();
  const targetZone = String(opts.targetZone || "").trim();
  if (!opts.publishAllow) {
    return Boolean(preferredName && findGeneratedPublishRuleByName(policy, preferredName));
  }
  if (!targetZone) return false;
  const existing = findGeneratedPublishRuleByName(policy, preferredName) || findPublishRuleForPolicy(policy, dnat);
  if (!existing) return true;
  return !publishRuleMatches(existing, dnat, targetZone);
}

function findGeneratedPublishRuleByName(policy = {}, ruleName = "") {
  if (!ruleName) return null;
  return (policy.rules || []).find((rule) => rule.name === ruleName && generatedPublishRule(rule)) || null;
}

function publishRuleMatches(rule = {}, dnat = {}, targetZone = "") {
  return generatedPublishRule(rule, dnat.name) &&
    sameRefs(rule.fromZones, [dnat.fromZone]) &&
    sameRefs(rule.toZones, [targetZone]) &&
    sameRefs(rule.destinationAddresses, [dnat.translatedAddress]) &&
    sameRefs(rule.services, [dnat.service]) &&
    rule.action === "ACTION_ALLOW" &&
    rule.log === true &&
    rule.disabled === false;
}

function findPublishRule(dnat = {}) {
  return findPublishRuleForPolicy(session.draft || {}, dnat);
}

function findPublishRuleForPolicy(policy = {}, dnat = {}) {
  if (!dnat.fromZone || !dnat.translatedAddress || !dnat.service) return "";
  return (policy.rules || []).find((r) =>
    generatedPublishRule(r, dnat.name) &&
    sameRefs(r.fromZones, [dnat.fromZone]) &&
    sameRefs(r.destinationAddresses, [dnat.translatedAddress]) &&
    sameRefs(r.services, [dnat.service]) &&
    r.action === "ACTION_ALLOW" &&
    !r.disabled);
}

export function removeDestinationNatWithPublishRule(policy, idx, opts = {}) {
  policy.nat ||= {};
  policy.nat.destination ||= [];
  const [removed] = policy.nat.destination.splice(idx, 1);
  let removedRuleName = "";
  const linkedRuleName = opts.linkedRuleName || findPublishRuleForPolicy(policy, removed || {})?.name || "";
  if (opts.removeLinkedRule) {
    removedRuleName = removeGeneratedPublishRule(policy, linkedRuleName);
  }
  normalizeNat(policy);
  return {
    removed,
    linkedRuleName,
    removedRuleName,
  };
}

export function removeGeneratedPublishRule(policy, ruleName = "") {
  if (!ruleName || !Array.isArray(policy.rules)) return "";
  const idx = policy.rules.findIndex((rule) => rule.name === ruleName && generatedPublishRule(rule));
  if (idx < 0) return "";
  const [removed] = policy.rules.splice(idx, 1);
  return removed?.name || "";
}

function publishRuleTargetZone(policy = {}, ruleName = "") {
  if (!ruleName) return "";
  const rule = (policy.rules || []).find((item) => item?.name === ruleName);
  return (rule?.toZones || [])[0] || "";
}

function generatedPublishRule(rule = {}, dnatName = "") {
  const tags = Array.isArray(rule.tags) ? rule.tags : [];
  const tagged = tags.includes("generated:dnat-publish");
  const linked = dnatName ? tags.includes(`dnat:${sanitizeName(dnatName)}`) : true;
  const legacy = /^Created from DNAT\s+/i.test(String(rule.description || ""));
  const legacyLinked = !dnatName || String(rule.description || "").includes(`DNAT ${dnatName}`);
  return (tagged && linked) || (legacy && legacyLinked);
}

function publishRuleTags(dnat = {}) {
  return ["generated:dnat-publish", `dnat:${sanitizeName(dnat.name || "destination-nat")}`];
}

function suggestedTargetZone(fromZone, zones) {
  return zones.find((z) => z !== fromZone) || zones[0] || "";
}

export function publishInsertIndex(rules = []) {
  const idx = rules.findIndex((r) =>
    !r.disabled &&
    (r.action === "ACTION_DENY" || r.action === "ACTION_REJECT") &&
    broadRefs(r.fromZones) &&
    broadRefs(r.toZones) &&
    broadRefs(r.sourceAddresses) &&
    broadRefs(r.destinationAddresses) &&
    broadRefs(r.services));
  return idx >= 0 ? idx : rules.length;
}

function sameRefs(a = [], b = []) {
  return JSON.stringify([...(a || [])].sort()) === JSON.stringify([...(b || [])].sort());
}

function broadRefs(values = []) {
  return !values || values.length === 0 || values.includes("any");
}

function metric(label, value) {
  return h("div", { class: "posture-metric" },
    h("span", {}, label),
    h("strong", {}, value));
}

function field(label, control, help) {
  return h("label", { class: "field" }, h("span", {}, label, help ? h("span", { class: "help" }, " — " + help) : null), control);
}

function checkbox(on) {
  const input = h("input", { type: "checkbox" });
  input.checked = on;
  const label = h("label", { class: "switch" }, input, h("span", { class: "slider" }));
  Object.defineProperty(label, "checked", { get: () => input.checked });
  return label;
}

function inlineHostCreator(title, targetSelect, pending) {
  const name = text("", "web-server");
  const cidr = text("", "10.20.0.80/32");
  return h("div", { class: "posture-metric", style: { marginBottom: "14px" } },
    h("div", { class: "flex", style: { justifyContent: "space-between", marginBottom: "8px" } },
      h("strong", { style: { marginTop: "0" } }, title),
      h("button", { class: "btn sm", type: "button", title: "Create pending address object", "aria-label": "Create pending address object", dataset: { natObjectAction: "create-pending-host" }, onclick: () => addPendingHost(name, cidr, targetSelect, pending) },
        h("span", { html: icon("plus", 14) }), "Create")),
    h("div", { class: "form-grid two" },
      field("Name", name),
      field("Host IP/CIDR", cidr, "host uses /32 or /128")));
}

function inlineServiceCreator(title, targetSelect, pending) {
  const name = text("", "web");
  const proto = h("select", { class: "input" },
    h("option", { value: "PROTOCOL_TCP" }, "TCP"),
    h("option", { value: "PROTOCOL_UDP" }, "UDP"));
  const ports = text("", "80, 443");
  return h("div", { class: "posture-metric", style: { marginBottom: "14px" } },
    h("div", { class: "flex", style: { justifyContent: "space-between", marginBottom: "8px" } },
      h("strong", { style: { marginTop: "0" } }, title),
      h("button", { class: "btn sm", type: "button", title: "Create pending service object", "aria-label": "Create pending service object", dataset: { natObjectAction: "create-pending-service" }, onclick: () => addPendingService(name, proto, ports, targetSelect, pending) },
        h("span", { html: icon("plus", 14) }), "Create")),
    h("div", { class: "form-grid two" },
      field("Name", name),
      field("Protocol", proto),
      field("Ports", ports, "comma-separated; ranges with a dash")));
}

function addPendingHost(nameInput, cidrInput, targetSelect, pending) {
  const name = sanitizeName(nameInput.value || hostNameFromCidr(cidrInput.value));
  const cidr = normalizeHostCidr(cidrInput.value);
  if (!name || !cidr) return toast("Host object fields required", "Enter a name and host IP/CIDR.", "warn");
  const queued = pending.find((obj) => obj.name === name);
  if (queued) {
    if (!selectHasValue(targetSelect, name)) addSelectOption(targetSelect, name);
    targetSelect.value = name;
    return toast("Host object already queued", `${name} selected; existing queued values were preserved.`, "warn");
  }
  if (selectHasValue(targetSelect, name)) {
    targetSelect.value = name;
    return toast("Object already exists", `${name} selected.`, "warn");
  }
  pending.push({ name, cidr, description: "Created from NAT editor." });
  addSelectOption(targetSelect, name);
  targetSelect.value = name;
  nameInput.value = "";
  cidrInput.value = "";
  toast("Host object queued", `${name} will be staged with the NAT change.`, "ok");
}

function addPendingService(nameInput, proto, portsInput, targetSelect, pending) {
  const name = sanitizeName(nameInput.value || "service");
  const rawPorts = portsInput.value.trim();
  if (!name || !rawPorts) return toast("Service fields required", "Enter a name and one or more ports.", "warn");
  const portCheck = validateNatServicePorts(rawPorts);
  if (!portCheck.ok) return toast("Service ports invalid", portCheck.message, "warn");
  const queued = pending.find((obj) => obj.name === name);
  if (queued) {
    if (!selectHasValue(targetSelect, name)) addSelectOption(targetSelect, name);
    targetSelect.value = name;
    return toast("Service already queued", `${name} selected; existing queued values were preserved.`, "warn");
  }
  if (selectHasValue(targetSelect, name)) {
    targetSelect.value = name;
    return toast("Service already exists", `${name} selected.`, "warn");
  }
  const ports = portCheck.ports;
  pending.push({ name, protocol: proto.value, ports, description: "Created from NAT editor." });
  addSelectOption(targetSelect, name);
  targetSelect.value = name;
  nameInput.value = "";
  portsInput.value = "";
  toast("Service object queued", `${name} will be staged with the NAT change.`, "ok");
}

export function ensurePendingAddressObjects(policy, pending = []) {
  if (!pending.length) return;
  policy.addresses ||= [];
  for (const obj of pending) {
    if (!obj?.name || !obj?.cidr) continue;
    const existing = policy.addresses.find((a) => a.name === obj.name);
    if (!existing) policy.addresses.push(obj);
  }
}

export function ensurePendingServices(policy, pending = []) {
  if (!pending.length) return;
  policy.services ||= [];
  for (const obj of pending) {
    if (!obj?.name || !obj?.protocol || !validNatServicePorts(obj.ports)) continue;
    const existing = policy.services.find((s) => s.name === obj.name);
    if (!existing) policy.services.push(obj);
  }
}

function validatePendingNatObjects(policy = {}, pendingAddresses = [], pendingServices = []) {
  for (const obj of pendingAddresses || []) {
    if (!obj?.name || !obj?.cidr) {
      return { title: "Queued host invalid", message: "Queued NAT host objects need both a name and host IP/CIDR before staging.", tone: "warn" };
    }
    const existing = (policy.addresses || []).find((address) => address.name === obj.name);
    if (existing && !equal(existing, obj)) {
      return { title: "Queued host conflicts", message: `${obj.name} already exists with different address data. Select the existing object or choose a unique name.`, tone: "warn" };
    }
  }
  for (const obj of pendingServices || []) {
    if (!obj?.name || !obj?.protocol || !validNatServicePorts(obj.ports)) {
      return { title: "Queued service invalid", message: "Queued NAT service objects need a name, protocol, and valid TCP/UDP port list before staging.", tone: "warn" };
    }
    const existing = (policy.services || []).find((service) => service.name === obj.name);
    if (existing && !equal(existing, obj)) {
      return { title: "Queued service conflicts", message: `${obj.name} already exists with different service data. Select the existing object or choose a unique name.`, tone: "warn" };
    }
  }
  return null;
}

function pendingNatObjectsChange(policy = {}, pendingAddresses = [], pendingServices = []) {
  return (pendingAddresses || []).some((obj) => obj?.name && !(policy.addresses || []).some((address) => address.name === obj.name)) ||
    (pendingServices || []).some((obj) => obj?.name && !(policy.services || []).some((service) => service.name === obj.name));
}

export function validateNatServicePorts(value = "") {
  const raw = String(value || "").trim();
  if (!raw) return { ok: false, ports: [], message: "Enter one or more TCP/UDP ports before queuing the service object." };
  const ports = [];
  for (const token of raw.split(",").map((x) => x.trim()).filter(Boolean)) {
    const parts = token.split("-");
    if (parts.length > 2 || !parts.every((part) => /^[0-9]+$/.test(part))) {
      return { ok: false, ports: [], message: "Use whole TCP/UDP port numbers from 1 to 65535, separated by commas; ranges use start-end." };
    }
    const start = Number(parts[0]);
    const end = parts.length === 2 ? Number(parts[1]) : undefined;
    if (!Number.isInteger(start) || start < 1 || start > 65535) {
      return { ok: false, ports: [], message: "Ports must be whole numbers from 1 to 65535." };
    }
    if (end !== undefined) {
      if (!Number.isInteger(end) || end < 1 || end > 65535 || end < start) {
        return { ok: false, ports: [], message: "Port ranges must stay within 1 to 65535 and end at or above the start port." };
      }
      ports.push({ start, end });
    } else {
      ports.push({ start });
    }
  }
  return { ok: true, ports };
}

function validNatServicePorts(ports = []) {
  return Array.isArray(ports) && ports.length > 0 && ports.every((port) => {
    const start = Number(port?.start);
    const end = port?.end == null ? undefined : Number(port.end);
    return Number.isInteger(start) && start >= 1 && start <= 65535 &&
      (end === undefined || (Number.isInteger(end) && end >= start && end <= 65535));
  });
}

function addSelectOption(selectEl, value) {
  selectEl.appendChild(h("option", { value }, value));
}

function selectHasValue(selectEl, value) {
  return [...selectEl.options].some((opt) => opt.value === value);
}

function normalizeHostCidr(value) {
  const v = String(value || "").trim();
  if (!v) return "";
  if (v.includes("/")) return v;
  return v + (v.includes(":") ? "/128" : "/32");
}

function hostNameFromCidr(value) {
  return String(value || "").replace("/", "-");
}

function text(value, placeholder, attrs = {}) {
  return h("input", { class: "input", value: value || "", placeholder, ...attrs });
}

function protocolSelect(selected) {
  const el = h("select", { class: "input" },
    h("option", { value: "PROTOCOL_TCP" }, "TCP"),
    h("option", { value: "PROTOCOL_UDP" }, "UDP"),
    h("option", { value: "PROTOCOL_ICMP" }, "ICMP"),
    h("option", { value: "PROTOCOL_ANY" }, "Any IP"));
  el.value = selected || "PROTOCOL_TCP";
  return el;
}

function select(values, selected, placeholder, attrs = {}) {
  const el = h("select", { class: "input", ...attrs },
    h("option", { value: "" }, placeholder),
    values.map((v) => h("option", { value: v }, v)));
  el.value = selected || "";
  return el;
}

function names(xs = []) {
  return xs.map((x) => x.name).filter(Boolean).sort();
}

function firstOtherZone(zones = [], exclude = "") {
  const names = (zones || []).map((z) => z.name).filter(Boolean);
  return names.find((name) => name !== exclude) || names[0] || "";
}

function representativeZoneIp(policy = {}, zoneName = "") {
  const zone = (policy.zones || []).find((z) => z.name === zoneName);
  const ifaceHint = (zone?.interfaces || [])[0] || "";
  const lanish = /lan|trust|inside|priv|int/i.test(zoneName || ifaceHint);
  return lanish ? "10.0.1.20" : "198.51.100.20";
}

function representativeOutsideIp(toZone = "") {
  return /wan|untrust|outside|internet/i.test(toZone) ? "203.0.113.10" : "198.51.100.10";
}

function addressIp(policy = {}, name = "") {
  if (!name) return "";
  const obj = (policy.addresses || []).find((addr) => addr.name === name);
  const cidr = String(obj?.cidr || "");
  return cidr.split("/")[0] || "";
}

export function hostAddressNames(xs = []) {
  return xs
    .filter((x) => String(x.cidr || "").endsWith("/32") || String(x.cidr || "").endsWith("/128"))
    .map((x) => x.name)
    .filter(Boolean)
    .sort();
}

export function tcpUdpServiceNames(xs = []) {
  return xs
    .filter((x) => x.protocol === "PROTOCOL_TCP" || x.protocol === "PROTOCOL_UDP")
    .map((x) => x.name)
    .filter(Boolean)
    .sort();
}

function uniqueName(list, base) {
  const names = new Set((list || []).map((x) => x.name));
  if (!names.has(base)) return base;
  let i = 2;
  while (names.has(base + "-" + i)) i++;
  return base + "-" + i;
}

function sanitizeName(value) {
  let out = String(value || "rule").toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
  if (!out) out = "rule";
  if (!/^[a-z0-9]/.test(out)) out = "r-" + out;
  out = out.slice(0, 63).replace(/[-_]+$/g, "");
  if (!/[a-z0-9]$/.test(out)) out += "1";
  return out || "rule";
}

function tag(value) {
  return h("span", { class: "tag" }, value);
}
