import { h, icon } from "../core.js";
import { api } from "../api.js";
import { openAutomationContext } from "../automation_context.js";
import { pageHead, emptyState, pill, toast, labeledCell, responsiveTable } from "../ui.js";
import {
  buildInvestigationCasePacket,
  caseItemCaptureSource,
  caseItemHasCaptureSource,
  clearInvestigationCase,
  activeInvestigationServerCaseId,
  investigationCaseWorkbench,
  investigationCaseFilename,
  caseEvidencePayloadsFromItems,
  investigationCaseItems,
  investigationCaseJson,
  normalizeServerInvestigationSynthesis,
  safeInvestigationRoute,
  serverInvestigationCaseItems,
  setActiveInvestigationServerCaseId,
  investigationCaseText,
  removeInvestigationCaseItem,
} from "../investigation_case.js";
import { captureEvidencePanel } from "../capture_evidence.js";

const serverCustodyState = {
  loading: false,
  error: "",
  cases: [],
  activeCaseId: activeInvestigationServerCaseId(),
  activeSynthesis: null,
  lastSyncedAt: "",
};

export async function render(ctx = {}) {
  return renderInvestigationCase({ routeState: normalizeInvestigationRoute(ctx.query || {}) });
}

export function renderInvestigationCase({
  items = investigationCaseItems(),
  onRefresh = () => {},
  routeState = normalizeInvestigationRoute(),
} = {}) {
  const root = h("div", {});
  paint(root, items, onRefresh, routeState);
  return root;
}

function paint(root, items, onRefresh, routeState = normalizeInvestigationRoute()) {
  const currentItems = Array.isArray(items) ? items : [];
  const workbench = investigationCaseWorkbench(currentItems);
  const serverSynthesis = normalizeServerInvestigationSynthesis(serverCustodyState.activeSynthesis);
  const focused = focusedCaseItem(currentItems, routeState);
  root.replaceChildren(
    pageHead("Investigation", `${currentItems.length} pinned evidence item${currentItems.length === 1 ? "" : "s"}`,
      h("div", { class: "flex wrap" },
        h("button", { class: "btn", type: "button", title: "Open Investigation API and CLI context", "aria-label": "Open Investigation API and CLI context", dataset: { investigationAction: "api-cli" }, onclick: () => openAutomationContext(currentRoute()) }, h("span", { html: icon("terminal", 16) }), "API / CLI"),
        h("button", { class: "btn", type: "button", title: "Refresh server-retained investigation cases", "aria-label": "Refresh server-retained investigation cases", dataset: { investigationAction: "server-refresh" }, onclick: async () => { await refreshServerCustody(root, currentItems, onRefresh, routeState); } }, h("span", { html: icon("refresh", 16) }), "Refresh custody"),
        h("button", { class: "btn primary", type: "button", title: currentItems.length === 0 ? "Pin evidence before saving a server case" : "Save browser case to server custody", "aria-label": "Save browser case to server custody", dataset: { investigationAction: "server-save" }, disabled: currentItems.length === 0, onclick: async () => { await saveServerCase(root, currentItems, onRefresh, routeState); } }, h("span", { html: icon("upload", 16) }), "Save server case"),
        h("button", { class: "btn", type: "button", title: "Copy investigation case", "aria-label": "Copy investigation case", dataset: { investigationAction: "copy-case" }, onclick: () => copyCase(currentItems) }, h("span", { html: icon("copy", 16) }), "Copy case"),
        h("button", { class: "btn", type: "button", title: "Export investigation case JSON", "aria-label": "Export investigation case JSON", dataset: { investigationAction: "export-case" }, onclick: () => exportCase(currentItems) }, h("span", { html: icon("download", 16) }), "Export JSON"),
        h("button", {
          class: "btn danger",
          type: "button",
          title: currentItems.length === 0 ? "No pinned investigation evidence to clear" : "Clear investigation case",
          "aria-label": "Clear investigation case",
          dataset: { investigationAction: "clear-case" },
          disabled: currentItems.length === 0,
          onclick: () => {
            clearInvestigationCase();
            toast("Case cleared", "Pinned investigation evidence was removed from this browser.", "ok");
            onRefresh();
            paint(root, investigationCaseItems(), onRefresh, routeState);
          },
        }, h("span", { html: icon("trash", 16) }), "Clear"))),
    serverCustodyPanel(root, currentItems, onRefresh, routeState),
    currentItems.length ? focusedCaseBanner(focused, routeState) : null,
    currentItems.length ? caseWorkbench({ ...workbench, serverSynthesis }) : emptyState("inbox", "No pinned evidence", "This browser has no investigation case items.", h("a", { class: "btn primary", href: "#/traffic", title: "Open Traffic to pin investigation evidence", "aria-label": "Open Traffic to pin investigation evidence", dataset: { investigationAction: "open-traffic-empty" } }, h("span", { html: icon("traffic", 16) }), "Open traffic")),
    currentItems.length ? caseEvidencePosture(currentItems, workbench) : null,
    currentItems.length ? caseSummary(currentItems) : null,
    currentItems.length ? groupedItems(currentItems, root, onRefresh, routeState) : null,
  );
}

function serverCustodyPanel(root, items = [], onRefresh, routeState) {
  const cases = Array.isArray(serverCustodyState.cases) ? serverCustodyState.cases : [];
  return h("section", { class: "investigation-posture", dataset: { investigationServerCustody: "true" } },
    h("div", { class: "profile-strip-head" },
      h("div", {},
        h("strong", {}, "Server custody"),
        h("span", {}, "Audited server-retained cases when available; browser-local pins remain the fallback.")),
      pill(serverCustodyState.activeCaseId ? "linked" : cases.length ? "available" : "local fallback", serverCustodyState.error ? "warn" : serverCustodyState.activeCaseId ? "ok" : "info", true)),
    serverCustodyState.error ? h("div", { class: "investigation-posture-note" },
      h("span", { html: icon("shield", 14) }),
      h("span", {}, serverCustodyState.error)) : null,
    h("div", { class: "investigation-summary-grid" },
      postureStat("Server cases", cases.length, serverCustodyState.loading ? "refreshing" : serverCustodyState.lastSyncedAt ? `synced ${serverCustodyState.lastSyncedAt}` : "not loaded"),
      postureStat("Linked case", serverCustodyState.activeCaseId || "none", serverCustodyState.activeCaseId ? "new evidence appends to this record" : "saving creates a new audited record"),
      postureStat("Local pins", items.length, "browser-local fallback")),
    cases.length ? h("div", { class: "investigation-list compact", dataset: { investigationServerCases: "true" } },
      cases.slice(0, 5).map((record) => serverCaseRow(record, root, items, onRefresh, routeState))) : null);
}

function serverCaseRow(record = {}, root, items = [], onRefresh, routeState) {
  const active = record.id && record.id === serverCustodyState.activeCaseId;
  const synthesis = normalizeServerInvestigationSynthesis(record.synthesis);
  return h("article", { class: "investigation-row" + (active ? " is-focused" : ""), dataset: { serverCaseId: record.id || "" } },
    h("div", { class: "investigation-row-main" },
      h("div", { class: "investigation-row-head" },
        h("strong", {}, record.title || record.id || "Investigation case"),
        h("span", { class: "tag" }, record.state || "open"),
        active ? pill("linked", "ok", true) : null),
      record.id ? h("div", { class: "mono muted" }, record.id) : null,
      h("div", { class: "note" }, `${record.evidenceCount || 0} evidence item${record.evidenceCount === 1 ? "" : "s"} retained on server`),
      synthesis ? h("div", { class: "note" }, `Synthesis: ${synthesis.confidence.level} confidence, ${synthesis.coverage.multiRecordGroups} multi-record group${synthesis.coverage.multiRecordGroups === 1 ? "" : "s"}`) : null),
    h("div", { class: "investigation-row-actions" },
      h("button", { class: "btn sm", type: "button", title: "Link this browser case to the server record", "aria-label": "Link this browser case to the server record", onclick: () => { serverCustodyState.activeCaseId = setActiveInvestigationServerCaseId(record.id); paint(root, items, onRefresh, routeState); } }, h("span", { html: icon("check", 14) }), "Link"),
      h("button", { class: "btn sm", type: "button", title: "Open this server case in the browser workbench", "aria-label": "Open this server case in the browser workbench", dataset: { investigationServerAction: "hydrate" }, onclick: async () => { await hydrateServerCase(root, record.id, onRefresh, routeState); } }, h("span", { html: icon("inbox", 14) }), "Open"),
      h("button", { class: "btn sm ghost", type: "button", title: items.length === 0 ? "No browser-local evidence to append" : "Append current browser evidence to this server case", "aria-label": "Append current browser evidence to this server case", disabled: items.length === 0, onclick: async () => { serverCustodyState.activeCaseId = setActiveInvestigationServerCaseId(record.id); await appendServerEvidence(root, items, onRefresh, routeState); } }, h("span", { html: icon("plus", 14) }), "Append")));
}

async function refreshServerCustody(root, items = [], onRefresh, routeState) {
  serverCustodyState.loading = true;
  serverCustodyState.error = "";
  paint(root, items, onRefresh, routeState);
  try {
    const resp = await api.investigationCases({ limit: 25, state: "open" });
    serverCustodyState.cases = Array.isArray(resp.cases) ? resp.cases : [];
    serverCustodyState.lastSyncedAt = new Date().toLocaleTimeString();
    toast("Server custody refreshed", `${serverCustodyState.cases.length} open case${serverCustodyState.cases.length === 1 ? "" : "s"} returned.`, "ok");
  } catch (err) {
    serverCustodyState.error = serverCustodyError(err);
    toast("Server custody unavailable", "Keeping browser-local investigation pins.", "warn");
  } finally {
    serverCustodyState.loading = false;
    paint(root, investigationCaseItems(), onRefresh, routeState);
  }
}

async function saveServerCase(root, items = [], onRefresh, routeState) {
  const packet = buildInvestigationCasePacket(items, { route: currentRoute() });
  try {
    const resp = await api.createInvestigationCase({
      title: packet.summary?.rootCause?.title || "Investigation case",
      packet,
      evidence: caseEvidencePayloadsFromItems(items),
    });
    const record = resp.case || {};
    serverCustodyState.activeCaseId = setActiveInvestigationServerCaseId(record.id);
    serverCustodyState.activeSynthesis = record.synthesis || null;
    serverCustodyState.error = "";
    await refreshServerCustody(root, investigationCaseItems(), onRefresh, routeState);
    toast("Server case saved", record.id || "Investigation case retained on server.", "ok");
  } catch (err) {
    serverCustodyState.error = serverCustodyError(err);
    toast("Server save unavailable", "Browser-local case is still available for copy or JSON export.", "warn");
    paint(root, investigationCaseItems(), onRefresh, routeState);
  }
}

async function appendServerEvidence(root, items = [], onRefresh, routeState) {
  if (!serverCustodyState.activeCaseId) {
    await saveServerCase(root, items, onRefresh, routeState);
    return;
  }
  try {
    await api.addInvestigationCaseEvidence(serverCustodyState.activeCaseId, caseEvidencePayloadsFromItems(items));
    serverCustodyState.activeSynthesis = null;
    serverCustodyState.error = "";
    await refreshServerCustody(root, investigationCaseItems(), onRefresh, routeState);
    toast("Evidence appended", serverCustodyState.activeCaseId, "ok");
  } catch (err) {
    serverCustodyState.error = serverCustodyError(err);
    toast("Append unavailable", "Browser-local evidence was not removed.", "warn");
    paint(root, investigationCaseItems(), onRefresh, routeState);
  }
}

async function hydrateServerCase(root, caseId, onRefresh, routeState) {
  const id = setActiveInvestigationServerCaseId(caseId);
  if (!id) return;
  try {
    const resp = await api.investigationCase(id);
    const hydratedItems = serverInvestigationCaseItems(resp.case || {});
    serverCustodyState.activeCaseId = id;
    serverCustodyState.activeSynthesis = resp.case?.synthesis || null;
    serverCustodyState.error = "";
    toast("Server case opened", `${hydratedItems.length} evidence item${hydratedItems.length === 1 ? "" : "s"} loaded into the workbench.`, "ok");
    paint(root, hydratedItems, onRefresh, routeState);
  } catch (err) {
    serverCustodyState.error = serverCustodyError(err);
    toast("Server case unavailable", "Browser-local evidence was not changed.", "warn");
    paint(root, investigationCaseItems(), onRefresh, routeState);
  }
}

function serverCustodyError(err) {
  if (!err) return "Server custody unavailable; browser-local fallback remains active.";
  if (err.status === 404) return "Server custody API is not available on this daemon; browser-local fallback remains active.";
  if (err.status === 401 || err.status === 403) return "Server custody requires an authenticated operator session.";
  return err.message || "Server custody unavailable; browser-local fallback remains active.";
}

export function normalizeInvestigationRoute(query = {}) {
  const caseKey = cleanCaseRouteValue(queryValue(query, "caseKey"), 160);
  return {
    caseKey,
    caseAction: caseKey ? cleanCaseRouteValue(queryValue(query, "caseAction"), 64) : "",
    caseKind: caseKey ? cleanCaseRouteValue(queryValue(query, "caseKind"), 64) : "",
  };
}

function queryValue(query, key) {
  if (query && typeof query.get === "function") return String(query.get(key) || "").trim();
  return String(query?.[key] || "").trim();
}

function cleanCaseRouteValue(value = "", maxLength = 96) {
  const text = String(value || "").trim();
  if (!text || text.length > maxLength) return "";
  if (/[\u0000-\u001f\u007f]/.test(text)) return "";
  if (/(?:bearer|token|secret|password|passwd|client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|file:|\/etc\/|\/tmp\/|\/var\/|\/home\/|\/Users\/)/i.test(text)) return "";
  return text;
}

function focusedCaseItem(items = [], routeState = {}) {
  if (!routeState.caseKey) return null;
  return items.find((item) => item.key === routeState.caseKey) || null;
}

function focusedCaseBanner(item = null, routeState = {}) {
  if (!routeState.caseKey) return null;
  const safeRoute = safeInvestigationRoute(item?.source?.route || "");
  const label = item?.subject?.label || item?.title || routeState.caseKey;
  const action = routeState.caseAction || "case action";
  const kind = routeState.caseKind || item?.kind || "evidence";
  return h("section", {
    class: "investigation-focus-banner " + (item ? "ready" : "missing"),
    dataset: {
      caseFocusBanner: "true",
      caseFocused: item ? "true" : "false",
      caseAction: action,
      caseKind: kind,
    },
  },
    h("div", {},
      h("strong", {}, item ? `Focused case action: ${caseRouteLabel(action)}` : "Focused case item unavailable"),
      h("div", { class: "note" }, item ? `${caseRouteLabel(kind)} evidence: ${label}` : "The route references a case item that is not pinned in this browser.")),
    safeRoute ? h("a", { class: "btn sm", href: safeRoute, title: "Open source workflow for focused evidence", "aria-label": "Open source workflow for focused evidence", dataset: { caseAction: "source-workflow" } }, h("span", { html: icon("arrowRight", 14) }), "Open source workflow") : null);
}

function caseRouteLabel(value = "") {
  return titleLabel(String(value || "").replace(/[-_]+/g, " "));
}

function caseWorkbench(model = {}) {
  const rootCause = model.rootCause || {};
  return h("section", { class: "investigation-cockpit", dataset: { investigationCockpit: "true" } },
    h("div", { class: "profile-strip-head" },
      h("div", {},
        h("strong", {}, "Case cockpit"),
        h("span", {}, "Compare cause, policy context, packet proof, and next operator action.")),
      pill(rootCauseBadge(rootCause), rootCause.tone || "info")),
    h("div", { class: "investigation-cause " + (rootCause.tone || "info") },
      h("strong", {}, rootCause.title || "Pinned evidence ready for review"),
      h("div", { class: "note" }, rootCause.detail || "Use the compare table before staging a candidate change.")),
    remediationPlan(model.remediationPlan || {}),
    h("div", { class: "investigation-summary-grid" },
      (model.metrics || []).map((metric) =>
        h("div", { class: "investigation-kind-stat" },
          h("span", {}, metric.label || ""),
          h("strong", {}, metric.value || "0"),
          metric.detail ? h("small", {}, metric.detail) : null))),
    remediationPlanner(model.remediationActions || []),
    caseSynthesisPanel(model.serverSynthesis || model.synthesis || {}),
    h("div", { class: "investigation-action-row", dataset: { investigationActionRow: "case-cockpit" } },
      (model.actions || []).map((action) =>
        h("a", { class: "btn sm", href: action.href || "#/investigation", dataset: { caseAction: action.id || "" }, title: action.detail || action.label || "Open investigation case action", "aria-label": action.label ? `Open ${action.label}` : "Open investigation case action" },
          h("span", { html: icon(actionIcon(action.id), 14) }), action.label || "Open"))),
    h("div", { class: "table-wrap investigation-compare-wrap" },
      responsiveTable(["Evidence", "Tuple", "App", "Verdict", "Rule", "Policy", "Capture"],
        (model.rows || []).map((row) => h("tr", {},
          labeledCell("Evidence", {}, h("strong", {}, row.title || row.kind || "Evidence"), h("div", { class: "note" }, row.kind || "")),
          labeledCell("Tuple", { class: "mono" }, row.tuple || "tuple not pinned"),
          labeledCell("App", {}, row.app || "unknown"),
          labeledCell("Verdict", {}, row.verdict || "unknown"),
          labeledCell("Rule", {}, row.rule || "not pinned"),
          labeledCell("Policy", {}, row.policyVersion || "unknown"),
          labeledCell("Capture", {}, row.captureState || "missing"))),
        { className: "investigation-compare" })));
}

function caseSynthesisPanel(synthesis = {}) {
  if (!synthesis.schemaVersion) return null;
  const custody = synthesis.custody || {};
  const rows = Array.isArray(synthesis.rows) ? synthesis.rows : [];
  const confidence = synthesis.confidence || {};
  const coverage = synthesis.coverage || {};
  const limitations = Array.isArray(synthesis.limitations) ? synthesis.limitations : [];
  const serverActions = Array.isArray(synthesis.serverActions) ? synthesis.serverActions : [];
  return h("section", {
    class: "investigation-posture",
    dataset: {
      investigationSynthesis: "true",
      investigationSynthesisState: synthesis.state || "",
    },
  },
    h("div", { class: "profile-strip-head" },
      h("div", {},
        h("strong", {}, "Retained synthesis"),
        h("span", {}, synthesis.detail || "Correlation, owner route, and custody posture for the active case.")),
      pill(synthesis.status || "review", /ready|retained/.test(synthesis.state || "") ? "ok" : synthesis.state === "needs-review" ? "warn" : "info", true)),
    h("div", { class: "investigation-summary-grid" },
      postureStat("Correlation keys", synthesis.correlationKeyCount || 0, `${synthesis.sharedTupleCount || 0} shared tuple group${synthesis.sharedTupleCount === 1 ? "" : "s"}`),
      postureStat("Owner routes", synthesis.readyOwnerCount || 0, `${synthesis.readyActionCount || 0} planner action${synthesis.readyActionCount === 1 ? "" : "s"} ready`),
      postureStat("Server retained", `${synthesis.serverRetainedCount || 0}/${synthesis.itemCount || 0}`, custody.status || "browser local"),
      postureStat("Packet proof", `${synthesis.captureReadyCount || 0}/${synthesis.itemCount || 0}`, "capture-ready evidence items"),
      confidence.level ? postureStat("Confidence", confidence.level, `${Math.round((confidence.score || 0) * 100)}% bounded score`) : null,
      coverage.flowGroups != null ? postureStat("Coverage", coverage.flowGroups, `${coverage.multiRecordGroups || 0} multi-record group${coverage.multiRecordGroups === 1 ? "" : "s"}`) : null),
    serverActions.length ? h("div", { class: "investigation-action-row", dataset: { serverSynthesisActions: "true" } },
      serverActions.map((action) => action.href
        ? h("a", { class: "btn sm", href: action.href, title: action.detail || action.label, "aria-label": action.label, dataset: { serverSynthesisAction: action.id || "" } }, h("span", { html: icon(actionIcon(action.id), 14) }), action.owner || action.label || "Owner")
        : h("button", { class: "btn sm ghost", type: "button", disabled: true, title: action.detail || "Owner route not retained", "aria-label": action.label || "Owner route unavailable", dataset: { serverSynthesisAction: action.id || "" } }, action.owner || action.label || "Owner"))) : null,
    rows.length ? responsiveTable(["Group", "Status", "Owners", "Missing"],
      rows.map((row) => h("tr", {},
        labeledCell("Group", {}, h("strong", {}, row.title || row.id || "Group"), h("div", { class: "note" }, row.tuple || "tuple not pinned")),
        labeledCell("Status", {}, pill(row.status || "review", row.status === "ready" ? "ok" : "warn", true), h("div", { class: "note" }, `${row.itemCount || 0} item${row.itemCount === 1 ? "" : "s"}`)),
        labeledCell("Owners", {}, (Array.isArray(row.readyOwners) && row.readyOwners.length) ? row.readyOwners.join("; ") : "none ready"),
        labeledCell("Missing", {}, (Array.isArray(row.missing) && row.missing.length) ? row.missing.join(", ") : "none"))),
      { className: "investigation-synthesis-table" }) : null,
    h("div", { class: "investigation-posture-note" },
      h("span", { html: icon("shield", 14) }),
      h("span", {}, custody.unsigned
        ? "Unsigned synthesis: legal hold, signing, RBAC-scoped export custody, and HA/fleet replication remain hardening requirements."
        : custody.exportCustody || "Synthesis custody boundary not reported.")),
    limitations.length ? h("ul", { class: "note-list", dataset: { serverSynthesisLimitations: "true" } },
      limitations.map((item) => h("li", {}, item))) : null);
}

function remediationPlan(plan = {}) {
  if (!plan.title) return null;
  const steps = Array.isArray(plan.steps) ? plan.steps : [];
  const evidence = Array.isArray(plan.evidence) ? plan.evidence : [];
  const groups = Array.isArray(plan.groups) ? plan.groups : [];
  const header = h("div", { class: "investigation-plan-synthesis-head" },
    h("div", {},
      h("strong", {}, "Multi-evidence fix plan"),
      h("span", {}, plan.detail || "Correlate evidence before choosing an owner workflow.")),
    h("div", { class: "investigation-plan-synthesis-status" },
      pill(plan.status || "review", plan.tone || "warn", true),
      plan.readiness ? h("span", { class: "tag" }, plan.readiness) : null));
  const body = h("div", { class: "investigation-plan-synthesis-body" },
    h("div", { class: "investigation-evidence-strip" },
      evidence.map((item) => h("span", {
        class: "investigation-evidence-chip " + (item.ready ? "ready" : "missing"),
        dataset: { evidenceId: item.id || "" },
      }, h("span", { html: icon(item.ready ? "check" : "clock", 13) }), item.label || item.id || "Evidence"))),
    h("ol", { class: "investigation-plan-steps" },
      steps.map((step) => h("li", {
        class: "investigation-plan-step " + (step.status || "missing"),
        dataset: { remediationStep: step.id || "" },
      },
        h("span", { class: "investigation-step-status" }, step.status || "missing"),
        h("div", {},
          h("strong", {}, step.label || "Review"),
          h("span", {}, step.detail || ""),
          step.href ? h("a", { href: step.href, class: "link" }, "Open workflow") : null)))),
    groups.length ? groupedRemediationHandoffs(groups) : null);
  return h("div", {
    class: "investigation-plan-synthesis " + (plan.tone || "warn"),
    dataset: {
      remediationPlan: "true",
      remediationPlanStatus: plan.status || "",
      remediationPrimaryAction: plan.primaryActionId || "",
    },
  }, header, h("strong", { class: "investigation-plan-title" }, plan.title), body);
}

function groupedRemediationHandoffs(groups = []) {
  return h("div", { class: "investigation-remediation-groups", dataset: { remediationGroups: "true" } },
    h("div", { class: "profile-strip-head" },
      h("div", {},
        h("strong", {}, "Grouped remediation handoffs"),
        h("span", {}, "Per-flow owner workspaces; review only until a candidate change is staged.")),
      pill(`${groups.filter((group) => group.status === "ready").length}/${groups.length} ready`, groups.some((group) => group.status !== "ready") ? "warn" : "ok", true)),
    h("div", { class: "investigation-plan-grid" },
      groups.map((group) => groupedRemediationCard(group))));
}

function groupedRemediationCard(group = {}) {
  const evidence = Array.isArray(group.evidence) ? group.evidence : [];
  const owners = Array.isArray(group.owners) ? group.owners : [];
  const missing = Array.isArray(group.missing) ? group.missing : [];
  return h("article", {
    class: "investigation-plan-action " + (group.tone || "info"),
    dataset: {
      remediationGroup: group.id || "",
      remediationGroupStatus: group.status || "",
    },
  },
    h("div", { class: "investigation-plan-main" },
      h("span", { class: "investigation-plan-icon", html: icon(groupIcon(group), 15) }),
      h("div", {},
        h("strong", {}, group.title || "Remediation group"),
        h("span", {}, group.tuple || "tuple not pinned"))),
    h("div", { class: "investigation-evidence-strip" },
      evidence.map((item) => h("span", {
        class: "investigation-evidence-chip " + (item.ready ? "ready" : "missing"),
        dataset: { groupEvidenceId: item.id || "" },
      }, h("span", { html: icon(item.ready ? "check" : "clock", 13) }), item.label || item.id || "Evidence"))),
    h("div", { class: "investigation-plan-meta" },
      pill(group.status || "review", group.status === "ready" ? "ok" : group.tone || "warn", true),
      h("span", { class: "tag" }, `${group.itemCount || 0} item${group.itemCount === 1 ? "" : "s"}`)),
    group.handoff ? h("p", { class: "note" }, group.handoff) : null,
    missing.length ? h("div", { class: "note" }, `Missing: ${missing.join(", ")}`) : null,
    owners.length ? h("div", { class: "investigation-action-row", dataset: { remediationGroupOwners: group.id || "" } },
      owners.map((owner) => owner.href && owner.state === "ready"
        ? h("a", { class: "btn sm", href: owner.href, title: owner.detail || owner.label || "Open owner workspace", "aria-label": owner.label ? `Open ${owner.label}` : "Open owner workspace", dataset: { ownerWorkspace: owner.actionId || "" } }, h("span", { html: icon(actionIcon(owner.actionId), 14) }), owner.owner || "Owner")
        : h("button", { class: "btn sm ghost", type: "button", disabled: true, title: owner.detail || "Owner workspace is not ready", "aria-label": owner.label ? `${owner.label} unavailable` : "Owner workspace unavailable", dataset: { ownerWorkspace: owner.actionId || "" } }, owner.owner || "Owner"))) : null);
}

function groupIcon(group = {}) {
  const kinds = Array.isArray(group.evidenceKinds) ? group.evidenceKinds.join(" ") : "";
  if (/alert|threat/i.test(kinds + " " + group.title)) return "threats";
  if (/nat|route|vpn/i.test(kinds + " " + group.title)) return "nat";
  if (/app-id/i.test(kinds + " " + group.title)) return "traffic";
  if (/candidate/i.test(group.title || "")) return "rules";
  return "traffic";
}

function rootCauseBadge(rootCause = {}) {
  const title = String(rootCause.title || "").toLowerCase();
  if (title.includes("candidate decision")) return "candidate drift";
  if (title.includes("threat")) return "threat";
  if (title.includes("application")) return "app-id";
  if (title.includes("packet")) return "packet proof";
  if (title.includes("ready")) return "review";
  return "review";
}

function caseEvidencePosture(items = [], model = {}) {
  const safeRoutes = items.filter((item) => item.source?.route).length;
  const redactedRoutes = items.filter((item) => item.source?.routeRedacted || item.packet?.source?.routeRedacted).length;
  const captureSources = items.filter((item) => caseItemHasCaptureSource(item)).length;
  const plannerActions = Array.isArray(model.remediationActions) ? model.remediationActions : [];
  const readyPlannerActions = plannerActions.filter((action) => !action.disabled).length;
  return h("section", { class: "investigation-posture", dataset: { investigationPosture: "true" } },
    h("div", { class: "profile-strip-head" },
      h("div", {},
        h("strong", {}, "Evidence custody"),
        h("span", {}, "Bounded case packet with route, export, and packet-capture posture.")),
      pill(redactedRoutes ? "redaction active" : "export ready", redactedRoutes ? "warn" : "ok", true)),
    h("div", { class: "investigation-summary-grid" },
      postureStat("Safe routes", safeRoutes, `${redactedRoutes} redacted`),
      postureStat("Capture sources", captureSources, `${items.length - captureSources} without packet proof`),
      postureStat("Planner actions", readyPlannerActions, `${plannerActions.length} total`),
      postureStat("Case export", items.length, "schema-bound evidence items")),
    redactedRoutes ? h("div", { class: "investigation-posture-note" },
      h("span", { html: icon("shield", 14) }),
      h("span", {}, "Unsafe route material was removed before rendering, copy, and JSON export.")) : null);
}

function postureStat(label, value, detail = "") {
  return h("div", { class: "investigation-kind-stat" },
    h("span", {}, label),
    h("strong", {}, String(value)),
    detail ? h("small", {}, detail) : null);
}

function remediationPlanner(actions = []) {
  return h("div", { class: "investigation-planner", dataset: { investigationPlanner: "true" } },
    h("div", { class: "profile-strip-head" },
      h("div", {},
        h("strong", {}, "Remediation planner"),
        h("span", {}, "Candidate-safe pivots derived from pinned evidence.")),
      pill(`${actions.filter((action) => !action.disabled).length}/${actions.length} ready`, actions.some((action) => action.disabled) ? "warn" : "ok", true)),
    h("div", { class: "investigation-plan-grid" },
      actions.map((action) => remediationAction(action))));
}

function remediationAction(action = {}) {
  const body = [
    h("div", { class: "investigation-plan-main" },
      h("span", { class: "investigation-plan-icon", html: icon(actionIcon(action.id), 15) }),
      h("div", {},
        h("strong", {}, action.label || "Action"),
        h("span", {}, action.disabled ? action.disabledReason || action.detail || "Required evidence is missing." : action.detail || ""))),
    h("div", { class: "investigation-plan-meta" },
      action.owner ? h("span", { class: "tag" }, action.owner) : null,
      pill(action.disabled ? "blocked" : "ready", action.disabled ? "neutral" : action.tone || "info", true)),
  ];
  const attrs = {
    class: "investigation-plan-action " + (action.disabled ? "disabled" : action.tone || "info"),
    dataset: { remediationAction: action.id || "" },
    title: action.disabled ? action.disabledReason || "" : action.detail || "",
  };
  if (action.disabled) return h("button", { ...attrs, type: "button", disabled: true, "aria-label": action.label ? `${action.label} unavailable` : "Investigation remediation action unavailable" }, body);
  return h("a", { ...attrs, href: action.href || "#/investigation", "aria-label": action.label ? `Open ${action.label}` : "Open investigation remediation action" }, body);
}

function caseSummary(items = []) {
  const counts = kindCounts(items);
  return h("div", { class: "investigation-summary" },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Case evidence"),
      pill(`${items.length} item${items.length === 1 ? "" : "s"}`, "info")),
    h("div", { class: "investigation-summary-grid" },
      Object.entries(counts).map(([kind, count]) =>
        h("div", { class: "investigation-kind-stat" },
          h("span", {}, kindLabel(kind)),
          h("strong", {}, String(count))))));
}

function actionIcon(id = "") {
  if (id === "capture") return "download";
  if (id === "audit") return "clock";
  if (id === "threat") return "threats";
  if (id === "threat-exception") return "threats";
  if (id === "candidate-fix") return "rules";
  if (id === "candidate-rule") return "rules";
  if (id === "app-id") return "traffic";
  if (id === "nat-route") return "nat";
  if (id === "traffic") return "traffic";
  return "terminal";
}

function groupedItems(items, root, onRefresh, routeState = normalizeInvestigationRoute()) {
  const groups = groupByKind(items);
  return h("div", { class: "investigation-groups" },
    Object.entries(groups).map(([kind, rows]) =>
      h("section", { class: "investigation-group" },
        h("div", { class: "profile-strip-head" },
          h("strong", {}, kindLabel(kind)),
          pill(String(rows.length), "neutral")),
        h("div", { class: "investigation-list" },
          rows.map((item) => investigationRow(item, root, onRefresh, routeState))))));
}

function investigationRow(item, root, onRefresh, routeState = normalizeInvestigationRoute()) {
  const subject = item.subject?.label || item.title || "Selected evidence";
  const id = item.subject?.id || "";
  const rawRoute = item.source?.route || "";
  const route = safeInvestigationRoute(rawRoute);
  const routeLabel = route || (item.source?.routeRedacted || item.packet?.source?.routeRedacted ? "redacted unsafe route" : rawRoute ? "redacted unsafe route" : "");
  const captureSource = caseItemCaptureSource(item);
  const focused = Boolean(routeState.caseKey && item.key === routeState.caseKey);
  return h("article", {
    class: "investigation-row" + (focused ? " is-focused" : ""),
    dataset: {
      caseKey: item.key,
      caseFocused: focused ? "true" : "false",
      caseAction: focused ? routeState.caseAction || "" : "",
      caseKind: focused ? routeState.caseKind || item.kind || "" : "",
    },
  },
    h("div", { class: "investigation-row-main" },
      h("div", { class: "investigation-row-head" },
        h("strong", {}, subject),
        h("span", { class: "tag" }, item.kind),
        focused ? pill("focused", "info", true) : null),
      id ? h("div", { class: "mono muted" }, id) : null,
      h("div", { class: "note" }, item.title || "Pinned handoff evidence"),
      h("dl", { class: "kv compact investigation-kv" },
        routeLabel ? kv("Route", routeLabel) : null,
        item.pinnedAt ? kv("Pinned", item.pinnedAt) : null,
        ...summaryPairs(item.summary).map(([key, value]) => kv(key, value))),
      caseItemHasCaptureSource(item) ? captureEvidencePanel(captureSource, {
        title: "Case capture evidence",
        historyLimit: 8,
        matchLimit: 2,
      }) : null),
    h("div", { class: "investigation-row-actions" },
      route ? h("a", { class: "btn sm", href: route, title: `Open source workflow for ${subject}`, "aria-label": `Open source workflow for ${subject}`, dataset: { investigationCaseAction: "open", investigationCaseKey: item.key || "" } }, h("span", { html: icon("arrowRight", 14) }), "Open") : null,
      h("button", { class: "btn sm ghost", type: "button", title: `Copy ${subject} case item`, "aria-label": `Copy ${subject} case item`, dataset: { investigationCaseAction: "copy", investigationCaseKey: item.key || "" }, onclick: () => copyItem(item) }, h("span", { html: icon("copy", 14) }), "Copy"),
      h("button", {
        class: "icon-btn",
        type: "button",
        title: "Remove from case",
        "aria-label": `Remove ${subject} from investigation case`,
        dataset: { investigationCaseAction: "remove", investigationCaseKey: item.key || "" },
        onclick: () => {
          removeInvestigationCaseItem(item.key);
          toast("Case item removed", subject, "ok");
          onRefresh();
          paint(root, investigationCaseItems(), onRefresh, routeState);
        },
        html: icon("trash", 15),
      })));
}

function kv(k, v) {
  return [h("dt", {}, titleLabel(k)), h("dd", { class: "mono" }, String(v || ""))];
}

function summaryPairs(summary = {}) {
  return Object.entries(summary || {})
    .filter(([, value]) => value != null && value !== "" && typeof value !== "object")
    .map(([key, value]) => [key, displaySummaryValue(value)])
    .filter(([, value]) => value !== "")
    .slice(0, 6);
}

function displaySummaryValue(value) {
  const text = String(value ?? "");
  if (!text) return "";
  return text
    .replace(/(^|[\s"'({=,;])\/(?:var\/lib|var\/log(?:\/openngfw)?|etc\/(?:openngfw|phragma)?|tmp|private\/tmp|var\/folders|private\/var\/folders|home\/[^'"\s,;}]+|Users\/[^'"\s,;}]+|opt\/[^'"\s,;}]+|data\/[^'"\s,;}]+)[^'"\s,;}]*/gi, "$1[server-local path redacted]")
    .replace(/\b(Authorization:\s*Bearer)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 [redacted]")
    .replace(/\b(Bearer)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 [redacted]")
    .replace(/\b(token|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|password|passwd|secret|client[_-]?secret)\s*[:=]\s*[^\s"',;}]+/gi, (match, key) => `${key}=[redacted]`);
}

async function copyCase(items) {
  const packet = buildInvestigationCasePacket(items, { route: currentRoute() });
  if (await copyText(investigationCaseText(packet))) {
    toast("Case copied", `${items.length} pinned item${items.length === 1 ? "" : "s"} copied as text.`, "ok");
  } else {
    toast("Copy failed", "Export JSON to download the case packet.", "warn");
  }
}

function exportCase(items) {
  downloadText(investigationCaseFilename(), investigationCaseJson(buildInvestigationCasePacket(items, { route: currentRoute() })), "application/json");
  toast("Case exported", "Downloaded pinned investigation evidence as JSON.", "ok");
}

async function copyItem(item) {
  if (await copyText(investigationCaseText(buildInvestigationCasePacket([item], { route: currentRoute() })))) {
    toast("Case item copied", item.subject?.label || item.kind || "Evidence copied.", "ok");
  } else {
    toast("Copy failed", "Open the case export and copy the item from JSON.", "warn");
  }
}

function downloadText(filename, text, type) {
  if (typeof document === "undefined" || typeof URL === "undefined") return;
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

async function copyText(text) {
  try {
    if (globalThis.navigator?.clipboard?.writeText) {
      await globalThis.navigator.clipboard.writeText(text);
      return true;
    }
  } catch {}
  return false;
}

function groupByKind(items = []) {
  const groups = {};
  for (const item of items) {
    const kind = item.kind || "investigation";
    if (!groups[kind]) groups[kind] = [];
    groups[kind].push(item);
  }
  return groups;
}

function kindCounts(items = []) {
  const counts = {};
  for (const item of items) counts[item.kind || "investigation"] = (counts[item.kind || "investigation"] || 0) + 1;
  return counts;
}

function kindLabel(kind = "") {
  return titleLabel(String(kind || "Investigation").replace(/[-_]+/g, " "));
}

function titleLabel(value = "") {
  return String(value || "").replace(/([a-z])([A-Z])/g, "$1 $2").replace(/\b\w/g, (m) => m.toUpperCase());
}

function currentRoute() {
  if (typeof location === "undefined") return "#/investigation";
  return location.hash || "#/investigation";
}
