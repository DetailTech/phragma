// Fleet — operations cockpit for appliance and template posture. The current
// control plane manages one local appliance; this view makes that boundary
// explicit while giving operators the same drift/readiness shape a fleet view
// will use when multi-node inventory exists.

import { h, icon } from "../core.js";
import { api } from "../api.js";
import { openAutomationContext } from "../automation_context.js";
import { buildContentPosture } from "../content_posture.js";
import { activeInvestigationServerCaseHref, appendInvestigationPacketToActiveServerCase, pinInvestigationPacket } from "../investigation_case.js";
import { buildInvestigationPacket } from "../investigation_packet.js";
import { buildHash, readQueryState, writeQueryState } from "../query_state.js";
import { pageHead, card, emptyState, pill, labeledCell, responsiveTable, openDrawer, closeDrawer, toast } from "../ui.js";

const FLEET_ROUTE_DEFAULTS = Object.freeze({
  drawer: "",
  template: "",
});
const FLEET_ROUTE_KEYS = Object.freeze(Object.keys(FLEET_ROUTE_DEFAULTS));

let routePath = "/fleet";
let routeState = normalizeFleetRoute();

export async function render(ctx = {}) {
  routePath = ctx.path || "/fleet";
  routeState = normalizeFleetRoute(ctx.query || {});
  const [
    statusR,
    haR,
    runningR,
    candidateStatusR,
    versionsR,
    feedsR,
    contentR,
    releaseR,
    identityR,
    fleetNodesR,
    fleetTemplatesR,
    fleetResultsR,
  ] = await Promise.allSettled([
    api.status(),
    api.highAvailabilityStatus(),
    api.running(),
    api.candidateStatus(),
    api.versions(8),
    api.feeds(),
    api.contentPackages(),
    api.releaseAcceptanceStatus(),
    api.identity(),
    api.fleetNodes(),
    api.fleetTemplates(),
    api.fleetTemplateResults(),
  ]);
  if (statusR.status !== "fulfilled") throw statusR.reason;
  const inputs = {
    status: statusR.value || {},
    ha: haR.status === "fulfilled" ? haR.value || {} : {},
    running: runningR.status === "fulfilled" ? runningR.value || {} : {},
    candidateStatus: candidateStatusR.status === "fulfilled" ? candidateStatusR.value || {} : {},
    versions: versionsR.status === "fulfilled" ? versionsR.value || {} : {},
    feeds: feedsR.status === "fulfilled" ? feedsR.value || {} : {},
    contentPackages: contentR.status === "fulfilled" ? contentR.value || {} : {},
    releaseAcceptance: releaseR.status === "fulfilled" ? releaseR.value || {} : {},
    identity: identityR.status === "fulfilled" ? identityR.value || {} : {},
    fleetNodes: fleetNodesR.status === "fulfilled" ? fleetNodesR.value || {} : {},
    fleetTemplates: fleetTemplatesR.status === "fulfilled" ? fleetTemplatesR.value || {} : {},
    fleetResults: fleetResultsR.status === "fulfilled" ? fleetResultsR.value || {} : {},
    errors: settledErrors({ haR, candidateStatusR, versionsR, feedsR, contentR, releaseR, identityR, fleetNodesR, fleetTemplatesR, fleetResultsR }),
  };
  const model = buildFleetModel(inputs);
  const root = fleetView(model);
  maybeOpenRouteBackedDrawer(root, model);
  return root;
}

function fleetView(model) {
  return h("div", { dataset: { fleetWorkspace: "true" } },
    pageHead("Fleet operations", "Appliance posture, policy drift, content package state, and templates.",
      h("button", { class: "btn", type: "button", title: "Open Fleet API and CLI context", "aria-label": "Open Fleet API and CLI context", dataset: { fleetAction: "api-cli" }, onclick: () => openAutomationContext("#/fleet") },
        h("span", { html: icon("terminal", 16) }), "API / CLI")),
    summaryBand(model),
    boundaryCard(model),
    h("div", { class: "grid cols-2", style: { marginBottom: "16px" } },
      nodeInventoryCard(model),
      driftCard(model)),
    h("div", { class: "grid cols-2", style: { marginBottom: "16px" } },
      templateCard(model),
      operationsCard(model)),
    orchestrationPreviewCard(model),
    applyResultsCard(model),
    evidenceCard(model));
}

function summaryBand(model) {
  return h("div", { class: "runtime-grid", dataset: { fleetSummary: "true" } },
    metric("Managed nodes", String(model.nodes.length), model.scopeLabel, "info"),
    metric("Policy drift", model.drift.label, model.drift.detail, model.drift.tone),
    metric("Content posture", model.content.label, model.content.detail, model.content.tone));
}

function boundaryCard(model) {
  return card(h("h2", {}, "Production boundary"),
    h("div", { class: "warning-list" }, model.boundaries.map((item) =>
      h("div", { class: "warning-row " + item.tone, dataset: { fleetBoundary: item.key } },
        h("div", {}, pill(item.label, item.tone, true)),
        h("div", {}, h("strong", {}, item.title), h("div", { class: "note" }, item.detail),
          item.href ? h("div", { class: "warning-actions" },
            h("a", { class: "btn sm ghost", href: item.href, title: `${item.action || "Open"}: ${item.title}`, "aria-label": `${item.action || "Open"}: ${item.title}`, dataset: { fleetBoundaryAction: item.key } }, h("span", { html: icon("arrowRight", 14) }), item.action || "Open")) : null)))));
}

function nodeInventoryCard(model) {
  const rows = model.nodes.map((node) => h("tr", { dataset: { fleetNode: node.id } },
    labeledCell("Appliance", {}, h("strong", {}, node.name), h("div", { class: "note" }, node.detail)),
    labeledCell("Role", {}, pill(node.roleLabel, node.roleTone, true)),
    labeledCell("Policy", { class: "mono" }, node.policyVersion),
    labeledCell("HA sync", {}, pill(node.haLabel, node.haTone)),
    labeledCell("Runtime", {}, pill(node.runtimeLabel, node.runtimeTone))));
  return card(h("h2", {}, "Managed appliances"),
    h("div", { class: "note" }, "Current inventory is scoped to the connected control-plane appliance; multi-node discovery remains a hardening item."),
    h("div", { class: "table-wrap flat" },
      responsiveTable(["Appliance", "Role", "Policy", "HA sync", "Runtime"], rows, { className: "fleet-node-table" })));
}

function driftCard(model) {
  return card(h("h2", {}, "Policy drift"),
    h("div", { class: "warning-list" }, model.drift.items.map((item) =>
      h("div", { class: "warning-row " + item.tone, dataset: { fleetDrift: item.key } },
        h("div", {}, pill(item.label, item.tone, true)),
        h("div", {}, h("strong", {}, item.title), h("div", { class: "note" }, item.detail),
          item.href ? h("div", { class: "warning-actions" },
            h("a", { class: "btn sm ghost", href: item.href, title: `${item.action || "Open"}: ${item.title}`, "aria-label": `${item.action || "Open"}: ${item.title}`, dataset: { fleetDriftAction: item.key } }, h("span", { html: icon("arrowRight", 14) }), item.action || "Open")) : null)))));
}

function templateCard(model) {
  const rows = model.templates.map((item) => h("tr", { dataset: { fleetTemplate: item.key } },
    labeledCell("Template", {}, h("strong", {}, item.label), h("div", { class: "note" }, item.detail)),
    labeledCell("State", {}, pill(item.state, item.tone, true)),
    labeledCell("Scope", {}, item.scope),
    labeledCell("Action", { class: "cell-actions" },
      item.serverBacked ? h("button", {
        class: "btn sm ghost",
        type: "button",
        title: `Validate ${item.label} through Fleet API`,
        "aria-label": `Validate ${item.label} through Fleet API`,
        dataset: { fleetTemplateAction: "validate", fleetTemplateKey: item.id },
        onclick: () => validateServerTemplate(item),
      }, h("span", { html: icon("check", 14) }), "Validate") : h("button", {
        class: "btn sm ghost",
        type: "button",
        title: `Preview ${item.label} local template intent`,
        "aria-label": `Preview ${item.label} local template intent`,
        dataset: { fleetTemplateAction: "preview", fleetTemplateKey: item.key },
        onclick: () => openTemplatePreviewDrawer(model, item.key),
      }, h("span", { html: icon("search", 14) }), "Preview"),
      item.serverBacked ? h("button", {
        class: "btn sm ghost",
        type: "button",
        title: `Run apply preview for ${item.label}`,
        "aria-label": `Run apply preview for ${item.label}`,
        dataset: { fleetTemplateAction: "apply-preview", fleetTemplateKey: item.id },
        onclick: () => applyPreviewServerTemplate(item, model),
      }, h("span", { html: icon("search", 14) }), "Apply preview") : null,
      item.serverBacked ? h("button", {
        class: "btn sm ghost",
        type: "button",
        title: `Build multi-node apply plan for ${item.label}`,
        "aria-label": `Build multi-node apply plan for ${item.label}`,
        dataset: { fleetTemplateAction: "apply-plan", fleetTemplateKey: item.id },
        onclick: () => applyPlanServerTemplate(item, model),
      }, h("span", { html: icon("diff", 14) }), "Apply plan") : null,
      item.serverBacked ? h("button", {
        class: "btn sm ghost",
        type: "button",
        title: `Apply ${item.label} to local candidate and retain peer results`,
        "aria-label": `Apply ${item.label} to local candidate and retain peer results`,
        dataset: { fleetTemplateAction: "apply", fleetTemplateKey: item.id },
        onclick: () => applyServerTemplate(item, model),
      }, h("span", { html: icon("upload", 14) }), "Apply") : null,
      item.serverBacked ? h("button", {
        class: "btn sm ghost",
        type: "button",
        title: `Stage ${item.label} to local candidate`,
        "aria-label": `Stage ${item.label} to local candidate`,
        dataset: { fleetTemplateAction: "stage-candidate", fleetTemplateKey: item.id },
        onclick: () => stageServerTemplate(item, model.candidateRevision || ""),
      }, h("span", { html: icon("upload", 14) }), "Stage") : null,
      item.href ? h("a", { class: "btn sm ghost", href: item.href, title: `${item.action}: ${item.label}`, "aria-label": `${item.action}: ${item.label}`, dataset: { fleetTemplateAction: "open", fleetTemplateKey: item.key } }, h("span", { html: icon("arrowRight", 14) }), item.action) : h("span", { class: "muted" }, item.action))));
  return card(h("h2", {}, "Template and drift"),
    h("div", { class: "split-line", style: { marginBottom: "10px" } },
      h("div", { class: "note" }, "Template posture is derived from running policy, candidate state, content packages, and the local Fleet template API; staging still uses the normal candidate/import workflow."),
      h("button", {
        class: "btn sm",
        type: "button",
        title: "Save running policy as local Fleet template",
        "aria-label": "Save running policy as local Fleet template",
        dataset: { fleetTemplateAction: "create-running-template" },
        onclick: () => createTemplateFromRunning(model),
      }, h("span", { html: icon("save", 14) }), "Save running")),
    h("div", { class: "table-wrap flat" },
      responsiveTable(["Template", "State", "Scope", { label: "Action", attrs: { class: "actions-col" } }], rows, { className: "fleet-template-table" })));
}

function operationsCard(model) {
  return card(h("h2", {}, "Operator queue"),
    model.actions.length ? h("div", { class: "warning-list" }, model.actions.map((item) =>
      h("div", { class: "warning-row " + item.tone, dataset: { fleetActionItem: item.key } },
        h("div", {}, pill(item.badge, item.tone, true)),
        h("div", {}, h("strong", {}, item.title), h("div", { class: "note" }, item.detail),
          h("div", { class: "warning-actions" },
            h("a", { class: "btn sm ghost", href: item.href, title: `${item.action}: ${item.title}`, "aria-label": `${item.action}: ${item.title}`, dataset: { fleetQueueAction: item.key } }, h("span", { html: icon("arrowRight", 14) }), item.action)))))) :
      emptyState("check", "No fleet actions", "No candidate, content, or release action is pending for the managed appliance."));
}

function orchestrationPreviewCard(model) {
  const preview = model.orchestrationPreview;
  const nodeRows = preview.nodes.map((node) => h("tr", { dataset: { fleetOrchestrationNode: node.id } },
    labeledCell("Node", {}, h("strong", {}, node.label), h("div", { class: "note" }, node.detail)),
    labeledCell("Eligibility", {}, pill(node.eligible ? "eligible" : "blocked", node.eligible ? "ok" : "warn", true)),
    labeledCell("Reason", {}, node.reason),
    labeledCell("Preview action", { class: "mono" }, node.previewAction)));
  const blockerRows = preview.blockers.map((blocker) => h("div", { class: "warning-row " + blocker.tone, dataset: { fleetOrchestrationBlocker: blocker.key } },
    h("div", {}, pill(blocker.label, blocker.tone, true)),
    h("div", {}, h("strong", {}, blocker.title), h("div", { class: "note" }, blocker.detail))));
  const planRows = preview.plan.map((step) => h("tr", { dataset: { fleetOrchestrationStep: step.key } },
    labeledCell("Step", {}, h("strong", {}, step.label), h("div", { class: "note" }, step.detail)),
    labeledCell("Boundary", {}, pill(step.boundary, step.tone, true)),
    labeledCell("Exact command or endpoint", { class: "mono" }, step.command)));
  return card(h("h2", {}, "Distributed orchestration preview"),
    h("div", { class: "split-line", style: { marginBottom: "10px" } },
      h("div", { class: "note" }, "Preview-only fanout planning across visible Fleet nodes. No peer RPC, running-policy apply, HA fencing, VIP movement, or distributed result custody is performed here."),
      h("div", { class: "warning-actions" },
        h("button", { class: "btn sm", type: "button", title: "Pin Fleet orchestration preview to the active investigation case", "aria-label": "Pin Fleet orchestration preview to the active investigation case", dataset: { fleetOrchestrationAction: "pin-preview" }, onclick: () => pinOrchestrationPreview(preview) }, h("span", { html: icon("inbox", 14) }), "Pin"),
        h("button", { class: "btn sm", type: "button", title: "Copy Fleet orchestration preview packet", "aria-label": "Copy Fleet orchestration preview packet", dataset: { fleetOrchestrationAction: "copy-preview" }, onclick: () => copyOrchestrationPreview(preview) }, h("span", { html: icon("copy", 14) }), "Copy"))),
    h("div", { class: "runtime-grid", style: { marginBottom: "12px" } },
      metric("Eligible nodes", `${preview.eligibleCount}/${preview.nodes.length}`, preview.scope, preview.eligibleCount ? "info" : "warn"),
      metric("Fanout", preview.fanout.title, preview.fanout.detail, preview.fanout.tone),
      metric("Template", preview.template.title, preview.template.detail, preview.template.tone),
      metric("Rollback", preview.rollback.title, preview.rollback.detail, preview.rollback.tone)),
    h("div", { class: "callout info", dataset: { fleetOrchestrationBoundary: "no-peer-apply" } },
      h("strong", {}, preview.boundary.title),
      h("div", { class: "note" }, preview.boundary.detail)),
    preview.blockers.length ? h("div", { class: "warning-list" }, blockerRows) :
      h("div", { class: "callout ok" }, h("strong", {}, "No preview blockers"), h("div", { class: "note" }, "Loaded signals are sufficient for a preview packet. Commit and distributed apply remain outside Fleet.")),
    h("div", { class: "table-wrap flat" },
      responsiveTable(["Node", "Eligibility", "Reason", "Preview action"], nodeRows, { className: "fleet-orchestration-node-table" })),
    h("div", { class: "table-wrap flat" },
      responsiveTable(["Step", "Boundary", "Exact command or endpoint"], planRows, { className: "fleet-orchestration-plan-table" })));
}

function applyResultsCard(model) {
  const rows = model.applyResults.map((result) => h("tr", { dataset: { fleetApplyResult: result.id } },
    labeledCell("Result", {}, h("strong", {}, result.id), h("div", { class: "note" }, result.finishedAt || "time not retained")),
    labeledCell("Template", {}, result.templateName || result.templateId),
    labeledCell("Status", {}, pill(result.status, result.status === "applied" ? "ok" : result.status === "error" ? "bad" : "warn", true)),
    labeledCell("Nodes", {}, result.nodeSummary),
    labeledCell("Custody", {}, result.custodyBoundary || "server-retained unsigned result")));
  return card(h("h2", {}, "Template apply results"),
    h("div", { class: "note" }, "Server-retained per-peer result records for bounded Fleet template applies. Peer entries are skipped or blocked unless safe peer transport is added later."),
    model.applyResults.length ? h("div", { class: "table-wrap flat" },
      responsiveTable(["Result", "Template", "Status", "Nodes", "Custody"], rows, { className: "fleet-apply-results-table" })) :
      emptyState("inbox", "No retained apply results", "Run a bounded Fleet template apply to retain local candidate and peer result records."));
}

function evidenceCard(model) {
  const rows = model.evidence.map((item) => h("tr", { dataset: { fleetEvidence: item.key } },
    labeledCell("Evidence", {}, h("strong", {}, item.label), h("div", { class: "note" }, item.detail)),
    labeledCell("Source", { class: "mono" }, item.source),
    labeledCell("State", {}, pill(item.state, item.tone))));
  return card(h("h2", {}, "Evidence sources"),
    h("div", { class: "table-wrap flat" },
      responsiveTable(["Evidence", "Source", "State"], rows, { className: "fleet-evidence-table" })));
}

function metric(label, value, detail, tone = "neutral") {
  return h("div", { class: "metric " + tone },
    h("span", {}, label),
    h("strong", {}, value),
    h("small", {}, detail || ""));
}

function openTemplatePreviewDrawer(model, templateKey, opts = {}) {
  const preview = (model.templatePreviews || []).find((item) => item.key === templateKey) || model.templatePreviews?.[0];
  if (!preview) return;
  if (opts.sync !== false) setFleetRouteState({ drawer: "template-preview", template: preview.key });
  openDrawer({
    title: `${preview.label} preview`,
    subtitle: "Browser-local template intent comparison for the connected appliance.",
    width: "760px",
    onClose: clearFleetRouteState,
    body: h("div", { class: "stack", dataset: { fleetTemplatePreview: preview.key } },
      opts.routeBacked ? h("div", { class: "callout info" },
        h("strong", {}, "Opened from route state"),
        h("div", { class: "note" }, "This template preview can be restored from a copied Fleet route without storing or applying a template.")) : null,
      h("div", { class: "callout info" },
        h("strong", {}, "Local preview only"),
        h("div", { class: "note" }, "This drawer is non-authoritative local-appliance guidance. It does not store signed templates, orchestrate peers, claim traffic failover, or apply policy. Stage or import through Changes, then validate, diff, commit, audit, and rollback from the existing workflow.")),
      h("div", { class: "grid cols-2" },
        previewFact("Intent", preview.intent),
        previewFact("Current posture", preview.posture),
        previewFact("Candidate", preview.candidate),
        previewFact("Apply path", preview.applyPath)),
      preview.changes.length ? h("div", { class: "warning-list" }, preview.changes.map((change) =>
        h("div", { class: "warning-row " + change.tone, dataset: { fleetTemplateChange: change.key } },
          h("div", {}, pill(change.label, change.tone, true)),
          h("div", {}, h("strong", {}, change.title), h("div", { class: "note" }, change.detail))))) :
        emptyState("check", "No local deltas", "The example intent is aligned with the currently loaded posture signals."),
      h("div", { class: "table-wrap flat" },
        responsiveTable(["Context", "Exact command or endpoint"], preview.context.map((item) =>
          h("tr", { dataset: { fleetTemplateContext: item.key } },
            labeledCell("Context", {}, h("strong", {}, item.label), h("div", { class: "note" }, item.detail)),
            labeledCell("Exact command or endpoint", { class: "mono" }, item.value))), { className: "fleet-template-context-table" })),
      h("div", { class: "note" }, "Changes handoff: use the copied text with a candidate import or review ticket. The browser does not retain, sign, or approve the template.")),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close template preview", "aria-label": "Close template preview", dataset: { fleetTemplateAction: "close-preview" }, onclick: closeDrawer }, "Close"),
      h("button", { class: "btn", type: "button", title: "Pin Fleet template preview to the active investigation case", "aria-label": "Pin Fleet template preview to the active investigation case", dataset: { fleetTemplateAction: "pin-handoff" }, onclick: () => pinTemplatePreviewHandoff(preview) }, h("span", { html: icon("inbox", 16) }), "Pin to case"),
      h("button", { class: "btn", type: "button", title: "Copy Changes handoff", "aria-label": "Copy Changes handoff", dataset: { fleetTemplateAction: "copy-handoff" }, onclick: () => copyTemplateHandoff(preview) }, h("span", { html: icon("copy", 16) }), "Copy handoff"),
      h("button", { class: "btn", type: "button", title: "Open Fleet API and CLI context", "aria-label": "Open Fleet API and CLI context", dataset: { fleetTemplateAction: "api-cli" }, onclick: () => openAutomationContext(fleetTemplatePreviewHash(preview.key)) }, h("span", { html: icon("terminal", 16) }), "API / CLI"),
      h("a", { class: "btn", href: activeInvestigationServerCaseHref(), title: "Open active investigation case", "aria-label": "Open active investigation case", dataset: { fleetTemplateAction: "open-active-case" } }, h("span", { html: icon("search", 16) }), "Open active case"),
      h("a", { class: "btn primary", href: preview.changesHref, title: "Open Changes candidate import and diff workflow", "aria-label": "Open Changes candidate import and diff workflow", dataset: { fleetTemplateAction: "open-changes" }, onclick: closeDrawer }, h("span", { html: icon("arrowRight", 16) }), "Open Changes"),
    ],
  });
}

function maybeOpenRouteBackedDrawer(root, model) {
  if (routeState.drawer !== "template-preview") return;
  const preview = (model.templatePreviews || []).find((item) => item.key === routeState.template) || model.templatePreviews?.[0];
  if (!preview) return;
  const canonical = normalizeFleetRoute({ drawer: "template-preview", template: preview.key });
  if (canonical.template !== routeState.template) {
    routeState = canonical;
    writeQueryState(routePath, routeState, FLEET_ROUTE_DEFAULTS, FLEET_ROUTE_KEYS);
  }
  openTemplatePreviewDrawer(model, preview.key, { sync: false, routeBacked: true });
}

function setFleetRouteState(state = {}) {
  routeState = normalizeFleetRoute(state);
  writeQueryState(routePath, routeState, FLEET_ROUTE_DEFAULTS, FLEET_ROUTE_KEYS);
}

function clearFleetRouteState() {
  routeState = { ...FLEET_ROUTE_DEFAULTS };
  if (typeof location !== "undefined" && (location.hash || "").startsWith("#/fleet")) {
    writeQueryState(routePath, routeState, FLEET_ROUTE_DEFAULTS, FLEET_ROUTE_KEYS);
  }
}

function normalizeFleetRoute(query = {}) {
  const state = readQueryState(query, FLEET_ROUTE_DEFAULTS, FLEET_ROUTE_KEYS);
  const drawer = String(state.drawer || "").trim().toLowerCase();
  if (drawer !== "template-preview") return { ...FLEET_ROUTE_DEFAULTS };
  return { drawer, template: cleanTemplateKey(state.template) || "ha" };
}

function fleetTemplatePreviewHash(templateKey = "") {
  return buildHash(routePath || "/fleet", normalizeFleetRoute({ drawer: "template-preview", template: templateKey }), FLEET_ROUTE_DEFAULTS, FLEET_ROUTE_KEYS);
}

function cleanTemplateKey(value = "") {
  return String(value || "").trim().toLowerCase().replace(/[^a-z0-9_.-]/g, "").slice(0, 80);
}

function previewFact(label, value) {
  return h("div", { class: "metric neutral" }, h("span", {}, label), h("strong", {}, value.title), h("small", {}, value.detail));
}

async function copyTemplateHandoff(preview) {
  const text = templateHandoffText(preview);
  try {
    if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(text);
    toast("Template handoff copied", "Paste into Changes review or an import ticket; no apply was performed.", "ok");
  } catch {
    toast("Copy unavailable", "Select and copy the template handoff text from the drawer.", "warn");
  }
}

async function pinTemplatePreviewHandoff(preview) {
  await appendOrPinFleetPacket(templatePreviewInvestigationPacket(preview), "Fleet template preview");
}

export function templateHandoffText(preview = {}) {
  const lines = [
    "Phragma Fleet local template preview",
    `Template: ${preview.label || "unknown"}`,
    `Route: ${fleetTemplatePreviewHash(preview.key || "unknown")}`,
    "Scope: connected local appliance only; not authoritative fleet inventory",
    "Apply boundary: stage/import through Changes; validate, diff, commit, audit, and rollback through existing candidate workflow.",
    "Orchestration boundary: no peer fan-out, distributed apply result, signed template custody, traffic failover, or HA fencing is performed from Fleet.",
    "",
    "Intent:",
    `- ${preview.intent?.title || ""}: ${preview.intent?.detail || ""}`,
    "Current posture:",
    `- ${preview.posture?.title || ""}: ${preview.posture?.detail || ""}`,
    "Candidate:",
    `- ${preview.candidate?.title || ""}: ${preview.candidate?.detail || ""}`,
    "",
    "Preview deltas:",
    ...(preview.changes || []).map((item) => `- [${item.label}] ${item.title}: ${item.detail}`),
    "",
    "Operator context:",
    ...(preview.context || []).map((item) => `- ${item.label}: ${item.value}`),
  ];
  return lines.filter((line) => line !== undefined).join("\n") + "\n";
}

export function buildFleetModel(inputs = {}) {
  const status = inputs.status || {};
  const running = inputs.running || {};
  const candidate = inputs.candidate || {};
  const candidateStatus = inputs.candidateStatus || {};
  const policy = running.policy || {};
  const draft = candidate.policy || {};
  const feeds = inputs.feeds?.feeds || [];
  const packages = inputs.contentPackages?.packages || [];
  const contentPosture = buildContentPosture(feeds, draft || policy || {}, packages, "");
  const runningVersion = Number(running.version || status.dataplane?.runningPolicyVersion || status.runningPolicyVersion || 0);
  const candidateDirty = Boolean(candidateStatus.dirty || candidateStatus.hasChanges || candidateStatus.changeCount || candidateStatus.changes);
  const ha = inputs.ha && Object.keys(inputs.ha).length ? inputs.ha : (status.highAvailability || status.high_availability || status.ha || {});
  const release = releaseModel(inputs.releaseAcceptance || {});
  const content = contentModel(contentPosture);
  const posture = policyPosture({ policy, candidateDirty, candidateStatus, release, content, ha, runningVersion });
  const apiNodes = normalizeFleetNodes(inputs.fleetNodes);
  const apiTemplates = normalizeFleetTemplates(inputs.fleetTemplates);
  const applyResults = normalizeFleetApplyResults(inputs.fleetResults);
  const node = apiNodes[0] || nodeModel({ status, ha, runningVersion, release, content });
  const drift = driftModel({ candidateDirty, candidateStatus, runningVersion, release, content });
  const templates = templateModels({ policy, draft, candidateDirty, release, content, ha, apiTemplates });
  const templatePreviews = templatePreviewModels({ posture, templates, candidateDirty, candidateStatus, release, content, ha });
  const actions = actionModels({ drift, release, content, candidateDirty });
  const errors = inputs.errors || [];
  const nodes = apiNodes.length ? apiNodes : [node];
  const orchestrationPreview = orchestrationPreviewModel({ nodes, templates, candidateDirty, candidateStatus, release, content, ha });
  return {
    scopeLabel: "local control plane only",
    nodes,
    boundaries: boundaryModels({ ha, release, candidateDirty }),
    drift,
    release,
    content,
    templates,
    templatePreviews,
    orchestrationPreview,
    applyResults,
    actions,
    evidence: evidenceModels({ errors, release, content, candidateDirty, apiTemplates, applyResults }),
    sourcePolicy: policy,
    candidateRevision: String(candidateStatus.candidateRevision || ""),
    apiTemplates,
  };
}

async function createTemplateFromRunning(model) {
  const policy = model.sourcePolicy || {};
  const name = `Running policy v${model.nodes?.[0]?.policyVersion || "current"}`;
  try {
    const resp = await api.createFleetTemplate({
      name,
      description: "Saved from Fleet running-policy posture for local validation and apply-preview.",
      scope: "local-appliance",
      labels: ["fleet", "running-policy"],
      policy,
    });
    toast("Fleet template saved", resp.template?.id || name, "ok");
  } catch (err) {
    toast("Fleet template save failed", err.message || String(err), "warn");
  }
}

async function validateServerTemplate(item) {
  try {
    const resp = await api.validateFleetTemplate(item.id);
    openServerTemplateResultDrawer("Template validation", item, resp);
  } catch (err) {
    toast("Template validation failed", err.message || String(err), "warn");
  }
}

async function applyPreviewServerTemplate(item, model) {
  try {
    const resp = await api.applyPreviewFleetTemplate(item.id, { expectedCandidateRevision: model.candidateRevision || "" });
    openServerTemplateResultDrawer("Template apply preview", item, resp);
  } catch (err) {
    toast("Template apply preview failed", err.message || String(err), "warn");
  }
}

async function applyPlanServerTemplate(item, model) {
  try {
    const resp = await api.applyPlanFleetTemplate(item.id, {
      expectedCandidateRevision: model.candidateRevision || "",
      nodes: fleetPeerInventoryForApplyPlan(model.nodes || []),
    });
    openServerTemplateResultDrawer("Template apply plan", item, resp);
  } catch (err) {
    toast("Template apply plan failed", err.message || String(err), "warn");
  }
}

async function applyServerTemplate(item, model) {
  if (!model.candidateRevision) {
    toast("Template apply blocked", "Reload Fleet so the current candidate revision can be included.", "warn");
    return;
  }
  try {
    const resp = await api.applyFleetTemplate(item.id, {
      expectedCandidateRevision: model.candidateRevision || "",
      comment: "Fleet template apply from WebUI",
      nodes: fleetPeerInventoryForApplyPlan(model.nodes || []),
    });
    toast("Template apply recorded", resp.applyResult?.id || "Fleet apply result retained.", "ok");
    openServerTemplateResultDrawer("Template apply result", item, resp);
  } catch (err) {
    toast("Template apply failed", err.message || String(err), "warn");
  }
}

async function stageServerTemplate(item, expectedCandidateRevision = "") {
  if (!expectedCandidateRevision) {
    toast("Template stage blocked", "Reload Fleet so the current candidate revision can be included.", "warn");
    return;
  }
  try {
    const resp = await api.stageCandidateFleetTemplate(item.id, {
      expectedCandidateRevision,
      comment: "Fleet template staged from WebUI",
    });
    toast("Template staged", "Candidate is ready for Changes review.", "ok");
    openServerTemplateResultDrawer("Template staged to candidate", item, resp);
  } catch (err) {
    toast("Template stage failed", err.message || String(err), "warn");
  }
}

function openServerTemplateResultDrawer(title, item, resp = {}) {
  const workbench = serverTemplateWorkbenchModel(item, resp, title);
  const validation = workbench.validation;
  const errors = workbench.errors;
  const findings = workbench.findings;
  const canStage = !resp.stagedCandidate && Boolean(resp.candidateRevision);
  openDrawer({
    title,
    subtitle: `${item.label} through /v1/fleet/templates/${item.id}`,
    width: "860px",
    body: h("div", { class: "stack", dataset: { fleetTemplateApiResult: item.id } },
      h("div", { class: "callout info" },
        h("strong", {}, "Fleet API boundary"),
        h("div", { class: "note" }, resp.orchestrationBoundary || "Local template API only; no peer fan-out, distributed result custody, or running-policy apply was performed.")),
      h("div", { class: "grid cols-2" },
        previewFact("Risk", workbench.risk),
        previewFact("Validation", workbench.validationFact),
        previewFact("Candidate revision", workbench.candidateFact),
        previewFact("Template revision", workbench.templateFact)),
      h("div", { class: "table-wrap flat" },
        responsiveTable(["Changed area", "Template impact"], workbench.changedAreas.map((area) =>
          h("tr", { dataset: { fleetTemplateArea: area.key } },
            labeledCell("Changed area", {}, h("strong", {}, area.label), h("div", { class: "note" }, area.detail)),
            labeledCell("Template impact", {}, pill(area.badge, area.tone, true)))), { className: "fleet-template-context-table" })),
      findings.length ? h("div", { class: "warning-list" }, findings.map((finding, index) =>
        h("div", { class: "warning-row " + findingTone(finding), dataset: { fleetTemplateFinding: String(index) } },
          h("div", {}, pill(finding.severity || "finding", findingTone(finding), true)),
          h("div", {}, h("strong", {}, finding.code || finding.stage || "finding"), h("div", { class: "note" }, finding.message || ""))))) :
        emptyState("check", "No findings", "Validation returned no findings at this preview depth."),
      workbench.applyPlanNodes.length ? h("div", { class: "table-wrap flat", dataset: { fleetApplyPlan: "true" } },
        responsiveTable(["Node", "Status", "Planned action", "Blockers"], workbench.applyPlanNodes.map((node) =>
          h("tr", { dataset: { fleetApplyPlanNode: node.id } },
            labeledCell("Node", {}, h("strong", {}, node.name), h("div", { class: "note" }, `${node.role} / ${node.runtimeState} / ${node.runningVersion || "version unknown"}`)),
            labeledCell("Status", {}, pill(node.status, node.eligible ? "ok" : "warn", true)),
            labeledCell("Planned action", {}, node.plannedAction),
            labeledCell("Blockers", {}, node.blockers.length ? node.blockers.join("; ") : "none"))), { className: "fleet-template-context-table" })) : null,
      workbench.applyResultNodes.length ? h("div", { class: "table-wrap flat", dataset: { fleetApplyResultNodes: "true" } },
        responsiveTable(["Node", "Result", "Mutation", "Reason"], workbench.applyResultNodes.map((node) =>
          h("tr", { dataset: { fleetApplyResultNode: node.id } },
            labeledCell("Node", {}, h("strong", {}, node.name), h("div", { class: "note" }, `${node.role} / ${node.runtimeState || "state unknown"}`)),
            labeledCell("Result", {}, pill(node.result, node.result === "applied" ? "ok" : node.result === "error" ? "bad" : "warn", true)),
            labeledCell("Mutation", {}, node.mutation || "none"),
            labeledCell("Reason", {}, node.reason || "not reported"))), { className: "fleet-template-context-table" })) : null,
      workbench.impactItems.length ? h("div", { class: "warning-list" }, workbench.impactItems.map((impact, index) =>
        h("div", { class: "warning-row " + impact.tone, dataset: { fleetTemplateImpact: String(index) } },
          h("div", {}, pill(impact.risk || "impact", impact.tone, true)),
          h("div", {}, h("strong", {}, impact.title), h("div", { class: "note" }, impact.detail))))) :
        emptyState("check", "No impact items", "No additional impact rows were returned for this template review."),
      h("div", { class: "table-wrap flat" },
        responsiveTable(["Step", "Required action"], (resp.requiredOperatorNextSteps || ["stage candidate", "validate", "diff", "commit through Changes"]).map((step, index) =>
          h("tr", {}, labeledCell("Step", { class: "mono" }, String(index + 1)), labeledCell("Required action", {}, step))), { className: "fleet-template-context-table" })),
      h("div", { class: "table-wrap flat" },
        responsiveTable(["Handoff", "Exact command or endpoint"], workbench.handoff.map((entry) =>
          h("tr", { dataset: { fleetTemplateHandoff: entry.key } },
            labeledCell("Handoff", {}, h("strong", {}, entry.label), h("div", { class: "note" }, entry.detail)),
            labeledCell("Exact command or endpoint", { class: "mono" }, entry.value))), { className: "fleet-template-context-table" })),
      h("div", { class: "note" }, "Copy handoff records the API and CLI review path only. Fleet does not fan out, sign, distribute, or apply the template to running policy.")),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close Fleet template preview", "aria-label": "Close Fleet template preview", dataset: { fleetTemplateAction: "close-preview", fleetTemplateKey: item.id }, onclick: closeDrawer }, "Close"),
      h("button", { class: "btn", type: "button", title: "Pin Fleet template API handoff to the active investigation case", "aria-label": "Pin Fleet template API handoff to the active investigation case", dataset: { fleetTemplateAction: "pin-api-handoff", fleetTemplateKey: item.id }, onclick: () => pinServerTemplateHandoff(workbench) }, h("span", { html: icon("inbox", 16) }), "Pin to case"),
      h("button", { class: "btn", type: "button", title: "Copy Fleet template API and CLI handoff", "aria-label": "Copy Fleet template API and CLI handoff", dataset: { fleetTemplateAction: "copy-api-handoff", fleetTemplateKey: item.id }, onclick: () => copyServerTemplateHandoff(workbench) }, h("span", { html: icon("copy", 16) }), "Copy handoff"),
      h("a", { class: "btn", href: activeInvestigationServerCaseHref(), title: "Open active investigation case", "aria-label": "Open active investigation case", dataset: { fleetTemplateAction: "open-active-case" } }, h("span", { html: icon("search", 16) }), "Open active case"),
      canStage ? h("button", {
        class: "btn",
        type: "button",
        title: "Stage this validated template to local candidate",
        "aria-label": "Stage this validated template to local candidate",
        dataset: { fleetTemplateAction: "stage-candidate-result", fleetTemplateKey: item.id },
        onclick: () => stageServerTemplate(item, resp.candidateRevision || ""),
      }, h("span", { html: icon("upload", 16) }), "Stage candidate") : null,
      h("a", { class: "btn primary", href: "#/changes?tab=candidate", title: "Open Changes candidate workflow for this Fleet template", "aria-label": "Open Changes candidate workflow for this Fleet template", dataset: { fleetTemplateAction: "open-changes", fleetTemplateKey: item.id }, onclick: closeDrawer }, h("span", { html: icon("arrowRight", 16) }), "Open Changes"),
    ],
  });
}

async function copyServerTemplateHandoff(workbench) {
  const text = serverTemplateHandoffText(workbench);
  try {
    if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(text);
    toast("Template API handoff copied", "Paste into a local candidate review ticket; no distributed apply was performed.", "ok");
  } catch {
    toast("Copy unavailable", "Select and copy the Fleet API and CLI handoff rows from the drawer.", "warn");
  }
}

async function pinServerTemplateHandoff(workbench) {
  await appendOrPinFleetPacket(serverTemplateInvestigationPacket(workbench), "Fleet template API handoff");
}

async function copyOrchestrationPreview(preview) {
  const text = orchestrationHandoffText(preview);
  try {
    if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(text);
    toast("Orchestration preview copied", "Paste into a review ticket; no peer fanout or running apply was performed.", "ok");
  } catch {
    toast("Copy unavailable", "Select and copy the orchestration preview rows from the Fleet workbench.", "warn");
  }
}

async function pinOrchestrationPreview(preview) {
  await appendOrPinFleetPacket(orchestrationPreviewInvestigationPacket(preview), "Fleet orchestration preview");
}

async function appendOrPinFleetPacket(packet, label = "Fleet evidence") {
  try {
    const serverResult = await appendInvestigationPacketToActiveServerCase(packet, {
      appendEvidence: (id, evidence) => api.addInvestigationCaseEvidence(id, evidence),
    });
    if (serverResult.appended) {
      toast("Evidence appended", `${label} appended to ${serverResult.activeCaseId}.`, "ok");
      return;
    }
  } catch {
    try {
      const result = pinInvestigationPacket(packet);
      toast("Server append unavailable", `${result.toastDetail} Local fallback was used.`, "warn");
    } catch (fallbackError) {
      toast("Pin failed", fallbackError.message || `${label} could not be pinned.`, "bad");
    }
    return;
  }
  try {
    const result = pinInvestigationPacket(packet);
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || `${label} could not be pinned.`, "bad");
  }
}

export function templatePreviewInvestigationPacket(preview = {}, options = {}) {
  return buildInvestigationPacket({
    kind: "fleet-template-preview",
    title: "Fleet template preview handoff",
    subject: {
      id: preview.key || "fleet-template-preview",
      label: preview.label || "Fleet template preview",
    },
    summary: {
      scope: "connected local appliance only",
      intent: preview.intent?.title || "",
      posture: preview.posture?.title || "",
      candidate: preview.candidate?.title || "",
      applyPath: preview.applyPath?.title || "Changes import",
      deltaCount: preview.changes?.length || 0,
      custodyBoundary: "browser-local template preview only; no signed template custody, peer fan-out, traffic failover, HA fencing, or running-policy apply",
      localTemplateCustody: localTemplateCustodyModel("browser-preview"),
    },
    evidence: [
      `template=${preview.label || preview.key || "unknown"}`,
      `route=${fleetTemplatePreviewHash(preview.key || "unknown")}`,
      `candidate=${preview.candidate?.title || "unknown"}`,
      `deltas=${preview.changes?.length || 0}`,
      "apply_boundary=stage/import through Changes, then validate, diff, commit, audit, and rollback",
      "local_template_custody=browser-local preview only; unsigned; not retained by Fleet template registry",
      "orchestration_boundary=no signed custody, peer fan-out, traffic failover, HA fencing, or running-policy apply",
    ],
    artifacts: {
      handoffText: templateHandoffText(preview),
      preview: {
        key: preview.key || "",
        label: preview.label || "",
        intent: preview.intent || {},
        posture: preview.posture || {},
        candidate: preview.candidate || {},
        applyPath: preview.applyPath || {},
        changes: preview.changes || [],
        context: preview.context || [],
      },
    },
  }, { route: options.route || fleetTemplatePreviewHash(preview.key || "unknown") });
}

export function serverTemplateInvestigationPacket(workbench = {}, options = {}) {
  return buildInvestigationPacket({
    kind: "fleet-template-api",
    title: "Fleet template API handoff",
    subject: {
      id: workbench.id || "fleet-template",
      label: workbench.label || "Fleet template API review",
    },
    summary: {
      operation: workbench.operation || "Template review",
      templateRevision: workbench.templateFact?.title || "unknown",
      candidateRevision: workbench.candidateFact?.title || "not reported",
      risk: workbench.risk?.title || "review",
      validation: workbench.validationFact?.title || "review",
      changedAreas: workbench.changedAreas?.length || 0,
      applyPlanNodes: workbench.applyPlanNodes?.length || 0,
      eligiblePlanNodes: workbench.applyPlanNodes?.filter((node) => node.eligible).length || 0,
      applyResultNodes: workbench.applyResultNodes?.length || 0,
      stagedCandidate: Boolean(workbench.stagedCandidate),
      custodyBoundary: "local Fleet template API handoff; no peer fan-out, distributed apply result, signed custody, HA fencing, traffic failover, or running-policy apply",
      localTemplateCustody: workbench.custody || localTemplateCustodyModel("server-template"),
    },
    evidence: [
      `operation=${workbench.operation || "Template review"}`,
      `template=${workbench.label || workbench.id || "unknown"}`,
      `risk=${workbench.risk?.title || "review"}`,
      `validation=${workbench.validationFact?.title || "review"}`,
      `candidate_revision=${workbench.candidateFact?.title || "not reported"}`,
      `local_template_custody=${workbench.custody?.detail || "unsigned local template registry draft"}`,
      "apply_boundary=candidate-only workflow before normal validate, diff, commit, audit, and rollback",
      "orchestration_boundary=no peer fan-out, distributed apply result, signed custody, HA fencing, traffic failover, or running-policy apply",
    ],
    artifacts: {
      handoffText: serverTemplateHandoffText(workbench),
      workbench: {
        operation: workbench.operation || "",
        id: workbench.id || "",
        label: workbench.label || "",
        risk: workbench.risk || {},
        validationFact: workbench.validationFact || {},
        candidateFact: workbench.candidateFact || {},
        templateFact: workbench.templateFact || {},
        changedAreas: workbench.changedAreas || [],
        impactItems: workbench.impactItems || [],
        applyPlanNodes: workbench.applyPlanNodes || [],
        applyResultNodes: workbench.applyResultNodes || [],
        applyPlanResult: workbench.applyPlanResult || "",
        applyResultId: workbench.applyResultId || "",
        handoff: workbench.handoff || [],
        boundary: workbench.boundary || "",
        applyPath: workbench.applyPath || "",
        custody: workbench.custody || localTemplateCustodyModel("server-template"),
      },
    },
  }, { route: options.route || "#/fleet" });
}

export function orchestrationPreviewInvestigationPacket(preview = {}, options = {}) {
  const safePreview = safeOrchestrationPreview(preview);
  return buildInvestigationPacket({
    kind: "fleet-orchestration-preview",
    title: "Fleet orchestration preview handoff",
    subject: {
      id: preview.id || "fleet-orchestration-preview",
      label: "Fleet orchestration preview",
    },
    summary: {
      scope: safePreview.scope || "visible Fleet nodes only",
      eligibleNodes: safePreview.eligibleCount || 0,
      totalNodes: safePreview.nodes?.length || 0,
      blockers: safePreview.blockers?.length || 0,
      fanoutBoundary: safePreview.fanout?.detail || "preview only",
      template: safePreview.template?.title || "not selected",
      rollback: safePreview.rollback?.title || "review",
      custodyBoundary: "redacted preview packet only; no peer RPC, distributed apply result, signed template custody, HA fencing, traffic failover, or running-policy apply",
      positiveEvidenceNodes: safePreview.positiveEvidenceNodes || 0,
      noPeerApplyBoundary: safePreview.boundary || noPeerApplyBoundaryModel(),
    },
    evidence: [
      `nodes=${safePreview.eligibleCount || 0}/${safePreview.nodes?.length || 0}`,
      `positive_evidence_nodes=${safePreview.positiveEvidenceNodes || 0}`,
      `blockers=${safePreview.blockers?.length || 0}`,
      `template=${safePreview.template?.title || "not selected"}`,
      "fanout_boundary=preview-only local workbench; no peer RPC or distributed result custody",
      "apply_boundary=no running-policy apply; use candidate workflow, validate, diff, commit, audit, and rollback",
      "redaction=no policy bodies, secrets, tokens, or node credentials included",
    ],
    artifacts: {
      handoffText: orchestrationHandoffText(safePreview),
      preview: {
        scope: safePreview.scope || "",
        eligibleCount: safePreview.eligibleCount || 0,
        nodes: (safePreview.nodes || []).map((node) => ({
          id: node.id,
          label: node.label,
          eligible: Boolean(node.eligible),
          reason: node.reason,
          positiveEvidence: node.positiveEvidence || [],
          missingEvidence: node.missingEvidence || [],
        })),
        blockers: safePreview.blockers || [],
        plan: safePreview.plan || [],
        boundary: safePreview.boundary || noPeerApplyBoundaryModel(),
      },
    },
  }, { route: options.route || "#/fleet" });
}

export function serverTemplateWorkbenchModel(item = {}, resp = {}, operation = "Template review") {
  const template = resp.template || item || {};
  const validation = resp.validation || {};
  const errors = jsonStringArray(validation.errors);
  const findings = Array.isArray(validation.findings) ? validation.findings : [];
  const impact = resp.impact || validation.impact || {};
  const candidateRevision = String(resp.candidateRevision || "");
  const previousRevision = String(resp.previousCandidateRevision || "");
  const templateRevision = String(template.revision || item.revision || "");
  const risk = riskFact({ validation, errors, impact, resp });
  return {
    operation,
    id: item.id || template.id || "",
    label: item.label || template.name || template.id || "Fleet template",
    validation,
    errors,
    findings,
    impact,
    risk,
    validationFact: {
      title: validation.valid ? "valid" : errors.length ? "blocked" : "review",
      detail: errors.length ? errors.join("; ") : "No validation errors returned.",
    },
    candidateFact: {
      title: candidateRevision || "not reported",
      detail: previousRevision ? `previous ${previousRevision}; ${resp.applyPath || "candidate-only workflow"}` : resp.applyPath || "No candidate mutation performed.",
    },
    templateFact: {
      title: templateRevision || "unknown",
      detail: item.detail || template.description || "Local template draft revision.",
    },
    changedAreas: changedAreasFromPolicySummary(template.policySummary || item.policySummary || {}),
    impactItems: impactItemsFromResponse(impact),
    applyPlanNodes: applyPlanNodesFromResponse(resp),
    applyResultNodes: applyResultNodesFromResponse(resp),
    applyPlanResult: String(resp.result || ""),
    applyResultId: String(resp.applyResult?.id || ""),
    handoff: serverTemplateHandoffRows(item, resp),
    boundary: resp.orchestrationBoundary || "local template API only; no peer fan-out, distributed result custody, or running-policy apply was performed",
    applyPath: resp.applyPath || "stage through /v1/candidate, validate, diff, commit, audit, rollback",
    custody: localTemplateCustodyModel("server-template", { templateRevision }),
    stagedCandidate: Boolean(resp.stagedCandidate),
    wouldMutateCandidate: Boolean(resp.wouldMutateCandidate),
    wouldApplyRunningPolicy: Boolean(resp.wouldApplyRunningPolicy || resp.runningPolicyApplied),
  };
}

function riskFact({ validation = {}, errors = [], impact = {}, resp = {} }) {
  const risk = String(impact.risk || "").replace(/^CHANGE_RISK_/, "").toLowerCase();
  if (errors.length || validation.valid === false) return { title: "blocked", detail: "Template validation must pass before staging.", tone: "bad" };
  if (risk) return { title: risk, detail: "Impact comes from existing policy validation; review before commit.", tone: riskTone(risk) };
  if (resp.stagedCandidate) return { title: "candidate staged", detail: "Local candidate changed; running policy was not applied.", tone: "warn" };
  return { title: "review", detail: "No explicit impact risk was returned; continue through candidate diff.", tone: "info" };
}

function changedAreasFromPolicySummary(summary = {}) {
  const nat = numberValue(summary.sourceNat) + numberValue(summary.destinationNat);
  const vpn = numberValue(summary.ipsecTunnels) + numberValue(summary.wireGuardPeers);
  const areas = [
    areaRow("zones", "Zones", numberValue(summary.zones), "trust boundary objects"),
    areaRow("rules", "Security rules", numberValue(summary.rules), "ordered policy rules"),
    areaRow("nat", "NAT", nat, "source and destination NAT entries"),
    areaRow("routing", "Routing", numberValue(summary.staticRoutes) + (summary.dynamicRouting ? 1 : 0), "static routes and dynamic routing posture"),
    areaRow("vpn", "VPN", vpn, "IPsec tunnels and WireGuard peers"),
    areaRow("host-input", "Host input", numberValue(summary.hostInputRules), "management-plane access rules"),
    areaRow("profiles", "Security profiles", numberValue(summary.securityProfiles), "inspection profile references"),
    areaRow("applications", "Applications", numberValue(summary.applications), "application match objects"),
  ].filter(Boolean);
  return areas.length ? areas : [{
    key: "empty",
    label: "No policy areas reported",
    detail: "Template summary did not report zones, rules, NAT, routing, VPN, host-input, profiles, or applications.",
    badge: "review",
    tone: "neutral",
  }];
}

function areaRow(key, label, count, detail) {
  if (!count) return null;
  return { key, label, detail: `${count} ${detail}`, badge: String(count), tone: count > 0 ? "info" : "neutral" };
}

function impactItemsFromResponse(impact = {}) {
  const items = Array.isArray(impact.items) ? impact.items : [];
  return items.map((item) => {
    const risk = String(item.risk || "").replace(/^CHANGE_RISK_/, "").toLowerCase() || "impact";
    return {
      risk,
      title: item.title || "Template impact",
      detail: item.detail || "Review this impact item before staging or commit.",
      tone: riskTone(risk),
    };
  });
}

function serverTemplateHandoffRows(item = {}, resp = {}) {
  const id = encodeURIComponent(item.id || resp.template?.id || "TEMPLATE_ID");
  const revision = resp.candidateRevision || "CANDIDATE_REVISION";
  const templateArg = fleetShellArg(item.id || resp.template?.id || "TEMPLATE_ID");
  const candidateRevisionArg = fleetShellArg(revision);
  return [
    { key: "validate-api", label: "API validate", value: `POST /v1/fleet/templates/${id}:validate`, detail: "Validate the stored local template without mutating candidate or running policy" },
    { key: "preview-api", label: "API apply preview", value: `POST /v1/fleet/templates/${id}:apply-preview {"expectedCandidateRevision":"${revision}"}`, detail: "Preview candidate impact with a revision guard" },
    { key: "plan-api", label: "API apply plan", value: `POST /v1/fleet/templates/${id}:apply-plan {"expectedCandidateRevision":"${revision}","nodes":[...]}`, detail: "Return per-node eligibility and handoff rows without peer RPC or running apply" },
    { key: "apply-api", label: "API bounded apply", value: `POST /v1/fleet/templates/${id}:apply {"expectedCandidateRevision":"${revision}","comment":"<reason>","nodes":[...]}`, detail: "Apply to local candidate and retain explicit peer result records without peer RPC" },
    { key: "results-api", label: "API apply results", value: `GET /v1/fleet/template-results?templateId=${id}`, detail: "Inspect retained local Fleet apply result custody" },
    { key: "stage-api", label: "API stage candidate", value: `POST /v1/fleet/templates/${id}:stage-candidate {"expectedCandidateRevision":"${revision}","comment":"<reason>"}`, detail: "Stage only the local candidate after review" },
    { key: "validate-cli", label: "CLI validate", value: `ngfwctl fleet templates validate ${templateArg}`, detail: "Headless template validation" },
    { key: "preview-cli", label: "CLI apply preview", value: `ngfwctl fleet templates apply-preview ${templateArg} --expected-candidate-revision ${candidateRevisionArg}`, detail: "Headless preview with candidate revision context" },
    { key: "plan-cli", label: "CLI apply plan", value: `ngfwctl fleet templates apply-plan ${templateArg} --expected-candidate-revision ${candidateRevisionArg} --peer id=<peer>,runtime=ready,running=<version>,haReady=true`, detail: "Headless multi-node apply plan with operator-supplied peer inventory" },
    { key: "apply-cli", label: "CLI bounded apply", value: `ngfwctl fleet templates apply ${templateArg} --expected-candidate-revision ${candidateRevisionArg} --message <reason> --peer id=<peer>,runtime=ready,running=<version>,haReady=true`, detail: "Apply local candidate and retain per-peer result records without peer RPC" },
    { key: "results-cli", label: "CLI apply results", value: `ngfwctl fleet templates results --template ${templateArg}`, detail: "Inspect retained Fleet result custody" },
    { key: "stage-cli", label: "CLI stage candidate", value: `ngfwctl fleet templates stage-candidate ${templateArg} --expected-candidate-revision ${candidateRevisionArg} --message <reason>`, detail: "Candidate-only staging before normal validate, diff, commit, audit, and rollback" },
  ];
}

export function serverTemplateHandoffText(workbench = {}) {
  const custody = workbench.custody || localTemplateCustodyModel("server-template");
  const lines = [
    "Phragma Fleet local template API handoff",
    `Operation: ${workbench.operation || "Template review"}`,
    `Template: ${workbench.label || "unknown"} (${workbench.id || "unknown"})`,
    `Template revision: ${workbench.templateFact?.title || "unknown"}`,
    `Candidate revision: ${workbench.candidateFact?.title || "not reported"}`,
    `Risk: ${workbench.risk?.title || "review"} - ${workbench.risk?.detail || ""}`,
    "Scope: connected local appliance only; not authoritative fleet inventory",
    `Local template custody: ${custody.detail}`,
    `Apply boundary: ${workbench.applyPath || "candidate-only workflow"}`,
    `Orchestration boundary: ${workbench.boundary || "no peer fan-out, distributed apply result, signed template custody, traffic failover, or HA fencing"}`,
    "",
    "Changed areas:",
    ...(workbench.changedAreas || []).map((item) => `- ${item.label}: ${item.detail}`),
    "",
    "Apply-plan nodes:",
    ...((workbench.applyPlanNodes || []).length ? workbench.applyPlanNodes.map((node) => `- ${node.name}: ${node.status} - ${node.plannedAction}`) : ["- not requested"]),
    "",
    "Apply result nodes:",
    ...((workbench.applyResultNodes || []).length ? workbench.applyResultNodes.map((node) => `- ${node.name}: ${node.result} - ${node.reason}`) : ["- not requested"]),
    "",
    "Handoff:",
    ...(workbench.handoff || []).map((item) => `- ${item.label}: ${item.value}`),
  ];
  return lines.join("\n") + "\n";
}

function applyPlanNodesFromResponse(resp = {}) {
  const nodes = Array.isArray(resp.nodes) ? resp.nodes : [];
  return nodes.map((node) => ({
    id: scrubFleetText(node.id || node.name || "node", 80),
    name: scrubFleetText(node.name || node.id || "node", 120),
    role: scrubFleetText(node.role || "peer", 80),
    runtimeState: scrubFleetText(node.runtimeState || "unknown", 80),
    runningVersion: scrubFleetText(String(node.runningVersion || ""), 80),
    eligible: Boolean(node.eligible),
    status: scrubFleetText(node.status || (node.eligible ? "eligible" : "blocked"), 80),
    plannedAction: scrubFleetText(node.plannedAction || "review", 180),
    blockers: Array.isArray(node.blockers) ? node.blockers.slice(0, 6).map((item) => scrubFleetText(item, 180)) : [],
  }));
}

function applyResultNodesFromResponse(resp = {}) {
  const nodes = Array.isArray(resp.applyResult?.nodeResults) ? resp.applyResult.nodeResults : Array.isArray(resp.nodeResults) ? resp.nodeResults : [];
  return nodes.map((node) => ({
    id: scrubFleetText(node.nodeId || node.id || node.nodeName || "node", 80),
    name: scrubFleetText(node.nodeName || node.name || node.nodeId || "node", 120),
    role: scrubFleetText(node.role || "peer", 80),
    runtimeState: scrubFleetText(node.runtimeState || "unknown", 80),
    result: scrubFleetText(node.result || "unknown", 80),
    reason: scrubFleetText(node.reason || "", 220),
    mutation: scrubFleetText(node.mutation || "none", 160),
  }));
}

function fleetPeerInventoryForApplyPlan(nodes = []) {
  return nodes.filter((node) => String(node.id || "").toLowerCase() !== "local").slice(0, 32).map((node) => ({
    id: node.id || node.name || "",
    name: node.name || node.label || node.id || "",
    role: node.roleLabel || node.role || "peer",
    runtimeState: node.runtimeLabel || node.runtimeState || "",
    runningVersion: node.policyVersion ? String(node.policyVersion).replace(/^v/, "") : "",
    haState: node.haLabel || "",
    haReady: node.haTone === "ok" || node.haReady === true,
    authoritative: false,
  })).filter((node) => node.id);
}

export function orchestrationHandoffText(preview = {}) {
  const safePreview = safeOrchestrationPreview(preview);
  const boundary = safePreview.boundary || noPeerApplyBoundaryModel();
  const lines = [
    "Phragma Fleet orchestration preview",
    `Scope: ${safePreview.scope || "visible Fleet nodes only"}`,
    `Eligible nodes: ${safePreview.eligibleCount || 0}/${safePreview.nodes?.length || 0}`,
    `Positive-evidence nodes: ${safePreview.positiveEvidenceNodes || 0}`,
    `Fanout boundary: ${safePreview.fanout?.detail || "preview only; no peer RPC or distributed apply result"}`,
    `No-peer-apply boundary: ${boundary.detail}`,
    "Apply boundary: no running-policy apply is performed from Fleet; use candidate validate, diff, commit, audit, and rollback workflows.",
    "Redaction: no policy bodies, secrets, bearer tokens, node credentials, or signed template payloads are included.",
    "",
    "Node eligibility:",
    ...(safePreview.nodes || []).map((node) => `- ${node.label}: ${node.eligible ? "eligible" : "blocked"} - ${node.reason}`),
    "",
    "Blockers:",
    ...((safePreview.blockers || []).length ? safePreview.blockers.map((item) => `- [${item.label}] ${item.title}: ${item.detail}`) : ["- none at preview depth"]),
    "",
    "Preview plan:",
    ...(safePreview.plan || []).map((step) => `- ${step.label}: ${step.command} (${step.boundary})`),
  ];
  return lines.join("\n") + "\n";
}

export function orchestrationPreviewModel({ nodes = [], templates = [], candidateDirty = false, candidateStatus = {}, release = {}, content = {}, ha = {} } = {}) {
  const selectedTemplate = templates.find((item) => item.serverBacked) || templates.find((item) => item.key === "edge-policy") || templates[0] || {};
  const modeledNodes = (nodes.length ? nodes : [{ id: "local", name: "local appliance", roleLabel: "standalone", haTone: "neutral", runtimeTone: "warn", policyVersion: "unknown" }]).map(orchestrationNodeModel);
  const eligibleCount = modeledNodes.filter((node) => node.eligible).length;
  const positiveEvidenceNodes = modeledNodes.filter((node) => node.positiveEvidence.length && !node.missingEvidence.length).length;
  const blockers = orchestrationBlockers({
    nodes: modeledNodes,
    selectedTemplate,
    candidateDirty,
    candidateStatus,
    release,
    content,
    ha,
  });
  const templateId = selectedTemplate.id || selectedTemplate.key || "TEMPLATE_ID";
  const encodedTemplateId = encodeURIComponent(templateId);
  const candidateRevision = String(candidateStatus.candidateRevision || "CANDIDATE_REVISION");
  const scope = nodes.length > 1 ? "visible Fleet API nodes; preview only" : "connected local appliance plus modeled peer boundary";
  const boundary = noPeerApplyBoundaryModel();
  return {
    id: "fleet-orchestration-preview",
    scope,
    nodes: modeledNodes,
    eligibleCount,
    positiveEvidenceNodes,
    blockers,
    fanout: blockers.length ? {
      title: "blocked",
      detail: "fanout remains a redacted plan until blockers clear; no peer RPC is attempted",
      tone: "warn",
    } : {
      title: "previewable",
      detail: "eligible-node plan can be reviewed locally; no peer RPC is attempted",
      tone: "info",
    },
    template: {
      title: selectedTemplate.label || selectedTemplate.key || "not selected",
      detail: selectedTemplate.serverBacked ? `local Fleet template ${templateId}` : "modeled browser-local template intent",
      tone: selectedTemplate.serverBacked ? "info" : "warn",
    },
    rollback: {
      title: "candidate rollback",
      detail: "rollback commands are check-only until normal Changes commit/audit produces a restorable version",
      tone: "info",
    },
    boundary,
    plan: orchestrationPlanRows({ templateId, encodedTemplateId, candidateRevision, nodes: modeledNodes, blockers }),
  };
}

function orchestrationNodeModel(node = {}) {
  const id = String(node.id || node.name || "local").slice(0, 80);
  const label = node.name || node.label || id || "local appliance";
  const role = String(node.roleLabel || node.role || "standalone").toLowerCase();
  const runtime = String(node.runtimeLabel || "").toLowerCase();
  const runtimePositive = /^(ok|ready|healthy|operable|active)$/.test(runtime) || node.runtimeTone === "ok";
  const runtimeTone = runtimePositive ? "ok" : "warn";
  const haTone = node.haTone || "neutral";
  const hasPolicy = node.policyVersion && node.policyVersion !== "unknown";
  const evidence = fleetNodeEvidenceModel({
    ...node,
    roleLabel: role,
    runtimeLabel: runtime,
    runtimeTone,
    haTone,
    hasPolicy,
  });
  const eligible = evidence.ready;
  const reasons = evidence.ready
    ? [role === "standalone" ? "positive local standalone evidence loaded" : `${role} node has positive policy, runtime, and HA evidence`]
    : evidence.missingEvidence;
  return {
    id,
    label,
    detail: `${role || "node"} / ${node.policyVersion || "unknown"} / ${node.haLabel || "HA unknown"} / ${node.runtimeLabel || "runtime unknown"}`,
    eligible,
    reason: reasons.join("; "),
    positiveEvidence: evidence.positiveEvidence,
    missingEvidence: evidence.missingEvidence,
    previewAction: eligible ? "validate + apply-preview only" : "hold; review appliance evidence",
  };
}

export function fleetNodeEvidenceModel(node = {}) {
  const role = String(node.roleLabel || node.role || "standalone").toLowerCase();
  const runtime = String(node.runtimeLabel || node.runtimeState || "").toLowerCase();
  const runtimeTone = node.runtimeTone || (/^(ok|ready|healthy|operable|active)$/.test(runtime) ? "ok" : "warn");
  const haTone = node.haTone || "neutral";
  const policyVersion = String(node.policyVersion || (node.runningVersion ? `v${node.runningVersion}` : ""));
  const hasPolicy = Boolean(node.hasPolicy ?? (policyVersion && policyVersion !== "unknown"));
  const positiveEvidence = [];
  const missingEvidence = [];
  if (hasPolicy) positiveEvidence.push(`running policy ${policyVersion}`);
  else missingEvidence.push("running policy version unknown");
  if (runtimeTone === "ok") positiveEvidence.push(`runtime ${runtime || "ready"}`);
  else missingEvidence.push("system preflight needs positive evidence");
  if (role === "standalone") {
    positiveEvidence.push("standalone boundary acknowledged");
  } else if (haTone === "ok" || node.haReady === true) {
    positiveEvidence.push("HA evidence ready");
  } else {
    missingEvidence.push("HA evidence needs review");
  }
  return {
    ready: missingEvidence.length === 0,
    positiveEvidence,
    missingEvidence,
  };
}

export function localTemplateCustodyModel(kind = "server-template", opts = {}) {
  const browserPreview = kind === "browser-preview";
  return {
    kind: browserPreview ? "browser-local-preview" : "local-template-registry",
    signed: false,
    retainedByServer: !browserPreview,
    templateRevision: opts.templateRevision || "",
    detail: browserPreview
      ? "browser-local preview only; unsigned; not retained as a Fleet template"
      : "unsigned local Fleet template registry draft; candidate staging still requires Changes validation, diff, commit, audit, and rollback",
  };
}

export function noPeerApplyBoundaryModel() {
  return {
    title: "No peer apply or traffic movement",
    detail: "Fleet can assemble a redacted eligible-node preview packet only; it does not call peer RPCs, apply running policy, move VIPs/routes, fence peers, transfer conntrack state, or retain distributed result custody.",
    peerRpc: false,
    runningPolicyApply: false,
    haTrafficControl: false,
    distributedResultCustody: false,
  };
}

function orchestrationBlockers({ nodes = [], selectedTemplate = {}, candidateDirty = false, candidateStatus = {}, release = {}, content = {}, ha = {} } = {}) {
  const blockers = [];
  if (!selectedTemplate.serverBacked) blockers.push(orchestrationBlocker("template", "template", "No server-backed template selected", "Save or load a local Fleet template draft before treating this as a distributable preview packet.", "warn"));
  if (candidateDirty) blockers.push(orchestrationBlocker("candidate", "candidate", "Candidate drift blocks clean fanout planning", `${candidateStatus.changeCount || "Existing"} staged change${candidateStatus.changeCount === 1 ? "" : "s"} must be reviewed before another template is staged.`, "warn"));
  if (content.tone === "bad" || content.tone === "warn") blockers.push(orchestrationBlocker("content", content.label || "content", "Content package review needed", content.detail || "Content package evidence needs review.", content.tone));
  if (nodes.length < 2) blockers.push(orchestrationBlocker("inventory", "inventory", "No durable multi-node inventory", "Only the connected appliance is visible, so Fleet can model fanout shape but cannot prove distributed eligibility.", "info"));
  const blockedNodes = nodes.filter((node) => !node.eligible);
  if (blockedNodes.length) blockers.push(orchestrationBlocker("nodes", "nodes", "One or more nodes are not eligible", blockedNodes.map((node) => `${node.label}: ${node.reason}`).join("; "), "warn"));
  if (ha && Object.keys(ha).length && haBoundaryFacts(ha).tone === "warn") blockers.push(orchestrationBlocker("ha", "HA", "HA evidence is not a traffic-control authorization", "Review HA state before any failover, fencing, VIP, or connection-state claim.", "warn"));
  return blockers;
}

function orchestrationBlocker(key, label, title, detail, tone) {
  return { key, label, title, detail, tone: tone || "warn" };
}

function orchestrationPlanRows({ templateId, encodedTemplateId, candidateRevision, nodes = [], blockers = [] } = {}) {
  const eligibleLabels = nodes.filter((node) => node.eligible).map((node) => node.label).join(", ") || "none";
  const templateArg = fleetShellArg(templateId || "TEMPLATE_ID");
  const candidateRevisionArg = fleetShellArg(candidateRevision || "CANDIDATE_REVISION");
  return [
    { key: "inventory", label: "Load visible inventory", detail: "Read Fleet API nodes and templates for a bounded, redacted preview.", boundary: "read-only", tone: "info", command: "GET /v1/fleet/nodes && GET /v1/fleet/templates" },
    { key: "validate", label: "Validate template", detail: "Validate the selected local template without changing candidate or running policy.", boundary: "no mutation", tone: "info", command: `POST /v1/fleet/templates/${encodedTemplateId}:validate` },
    { key: "fanout-preview", label: "Preview eligible fanout", detail: `Eligible nodes: ${eligibleLabels}. This row is a workbench plan, not a peer RPC loop.`, boundary: blockers.length ? "blocked plan" : "preview only", tone: blockers.length ? "warn" : "info", command: `ngfwctl fleet templates apply-preview ${templateArg} --expected-candidate-revision ${candidateRevisionArg} --preview-node-set eligible-only` },
    { key: "candidate-check", label: "Check candidate", detail: "Use the normal local candidate diff before any commit review.", boundary: "local candidate", tone: "info", command: "ngfwctl policy diff && ngfwctl policy validate" },
    { key: "rollback-check", label: "Rollback check", detail: "Confirm restorable policy history before promotion; Fleet does not roll back peers.", boundary: "check only", tone: "info", command: "ngfwctl policy history --limit 5 && ngfwctl policy rollback --dry-run <version>" },
    { key: "no-running-apply", label: "Running apply boundary", detail: "Commit, audit, rollback, HA operations, and traffic movement stay in their existing workflows.", boundary: "no apply", tone: "warn", command: "# no Fleet fan-out or running-policy apply command is executed" },
  ];
}

function riskTone(risk = "") {
  const clean = String(risk || "").toLowerCase();
  if (clean.includes("high") || clean.includes("critical")) return "bad";
  if (clean.includes("medium") || clean.includes("review")) return "warn";
  if (clean.includes("low")) return "info";
  return "neutral";
}

function jsonStringArray(value) {
  return Array.isArray(value) ? value.map((item) => String(item)) : [];
}

function numberValue(value) {
  const n = Number(value || 0);
  return Number.isFinite(n) ? n : 0;
}

function findingTone(finding = {}) {
  const severity = String(finding.severity || "").toLowerCase();
  if (severity.includes("error")) return "bad";
  if (severity.includes("warn")) return "warn";
  return "info";
}

function policyPosture({ policy, candidateDirty, candidateStatus, release, content, ha, runningVersion }) {
  const zones = arrayCount(policy.zones);
  const rules = arrayCount(policy.rules);
  const sourceNat = arrayCount(policy.nat?.source);
  const destinationNat = arrayCount(policy.nat?.destination);
  const staticRoutes = arrayCount(policy.staticRoutes || policy.static_routes);
  const bgp = Boolean(policy.routing?.bgp?.enabled || policy.bgp?.enabled);
  const ospf = Boolean(policy.routing?.ospf?.enabled || policy.ospf?.enabled);
  const ipsec = arrayCount(policy.vpn?.ipsecTunnels);
  const wireguard = arrayCount(policy.vpn?.wireguardInterfaces);
  const hostInput = arrayCount(policy.hostInput?.rules || policy.host_input?.rules);
  const changeCount = Number(candidateStatus.changeCount || candidateStatus.changes || 0);
  return {
    zones,
    rules,
    nat: sourceNat + destinationNat,
    sourceNat,
    destinationNat,
    staticRoutes,
    bgp,
    ospf,
    vpn: ipsec + wireguard,
    ipsec,
    wireguard,
    hostInput,
    candidateDirty,
    changeCount,
    runningVersion,
    content,
    release,
    haVisible: Boolean(ha && Object.keys(ha).length),
  };
}

function templatePreviewModels({ posture, templates, candidateDirty, candidateStatus, release, content, ha }) {
  const baseContext = [
    { key: "running-policy", label: "Running policy", value: "GET /v1/policy?source=POLICY_SOURCE_RUNNING", detail: "Loaded source for local posture counts" },
    { key: "candidate-status", label: "Candidate status", value: "GET /v1/candidate/status", detail: "Dirty-state and staged-change count" },
    { key: "candidate-diff", label: "Candidate diff", value: "GET /v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE", detail: "Existing diff endpoint used after staging or import" },
    { key: "cli-diff", label: "CLI diff", value: "ngfwctl policy diff", detail: "Headless running-to-candidate review" },
  ];
  return (templates || []).map((template) => {
    const changes = templatePreviewChanges(template.key, posture, { release, content, candidateDirty, candidateStatus, ha });
    const drillthrough = templateDrillthroughContext(template.key, { release, ha });
    return {
      key: template.key,
      label: template.label,
      intent: templateIntent(template.key),
      posture: {
        title: `v${posture.runningVersion || "unknown"} running posture`,
        detail: `${posture.zones} zones, ${posture.rules} rules, ${posture.nat} NAT entries, ${posture.vpn} VPN entries`,
      },
      candidate: {
        title: candidateDirty ? "candidate staged" : "no candidate drift",
        detail: candidateDirty ? `${posture.changeCount || "unknown"} staged change${posture.changeCount === 1 ? "" : "s"} must be reviewed in Changes before commit.` : "Candidate status reports no pending drift.",
      },
      applyPath: {
        title: "Changes import",
        detail: "Use candidate import/edit, validation, diff, commit, audit, and rollback; Fleet does not apply or distribute templates.",
      },
      changes,
      context: [
        ...baseContext,
        ...drillthrough,
        { key: "show-running", label: "CLI running export", value: "ngfwctl policy show --source running --json", detail: "Export current local-appliance posture" },
        { key: "show-candidate", label: "CLI candidate export", value: "ngfwctl policy show --source candidate --json", detail: "Review staged template import when present" },
        { key: "validate", label: "CLI validation", value: "ngfwctl policy validate", detail: "Validate staged template intent before commit" },
      ],
      changesHref: "#/changes?tab=candidate",
    };
  });
}

function templateDrillthroughContext(key, { release }) {
  const context = [];
  if (key === "ha") {
    context.push(
      { key: "ha-route", label: "HA", value: "#/fleet", detail: "Read-only HA and recovery context" },
      { key: "ha-cli", label: "CLI HA status", value: "ngfwctl system ha status", detail: "Focused local HA evidence handoff" },
    );
  }
  return context;
}

function templateIntent(key) {
  const intents = {
    "edge-policy": { title: "edge firewall baseline", detail: "Zones, ordered security rules, NAT publish/egress posture, and host-input guardrails." },
    content: { title: "content package baseline", detail: "App-ID, Threat-ID, and feed packages ready with rollback evidence before rollout." },
    "routing-vpn": { title: "branch routing template", detail: "Static route, dynamic routing, and VPN posture ready for candidate review." },
    ha: { title: "HA template", detail: "Local role, peer evidence, and recovery visibility before any operational failover claim." },
  };
  return intents[key] || { title: "local template intent", detail: "Example template intent compared with current local appliance posture." };
}

function templatePreviewChanges(key, posture, { release, content, candidateDirty, ha }) {
  const changes = [];
  if (key === "edge-policy") {
    if (posture.zones < 2) changes.push(previewChange("zones", "missing", "Add explicit trust boundaries", "Example edge intent expects at least inside/outside zones.", "warn"));
    if (!posture.rules) changes.push(previewChange("rules", "missing", "Add ordered security rules", "No running security rules are visible in the loaded policy.", "warn"));
    if (!posture.nat) changes.push(previewChange("nat", "review", "Review NAT intent", "No NAT entries are visible; stage SNAT/DNAT only through candidate import or editors.", "info"));
    if (!posture.hostInput) changes.push(previewChange("host-input", "review", "Review management access", "Host-input rules are not visible in the running policy posture.", "info"));
  } else if (key === "content") {
    if (content.tone !== "ok") changes.push(previewChange("content", content.label, "Resolve content package review", content.detail, content.tone));
  } else if (key === "routing-vpn") {
    if (!posture.staticRoutes && !posture.bgp && !posture.ospf) changes.push(previewChange("routing", "review", "No routing template posture visible", "Static routes, BGP, or OSPF would need candidate review before import.", "info"));
    if (!posture.vpn) changes.push(previewChange("vpn", "optional", "No VPN entries visible", "VPN tunnel intent remains an example until staged through Routing & VPN.", "neutral"));
  } else if (key === "ha") {
    const haBoundary = haBoundaryFacts(ha, posture.runningVersion);
    changes.push(previewChange("ha-boundary", haBoundary.label, haBoundary.title, haBoundary.detail, haBoundary.tone));
    if (!posture.haVisible) changes.push(previewChange("ha", "local", "HA evidence is local-only", "No peer inventory is reported by this control plane.", "neutral"));
  }
  if (candidateDirty) changes.unshift(previewChange("candidate", "staged", "Candidate already has pending changes", "Review the existing candidate before importing another template intent.", "warn"));
  if (!changes.length) changes.push(previewChange("aligned", "aligned", "No immediate local delta", "The loaded posture signals satisfy this example intent at preview depth.", "ok"));
  return changes;
}

function boundaryModels({ ha, release, candidateDirty }) {
  const haFacts = haBoundaryFacts(ha);
  return [
    {
      key: "authority",
      label: "local",
      title: "Connected appliance is the authority boundary",
      detail: "Fleet summarizes the current management API, running policy, candidate state, and content posture for this appliance only. It is not durable fleet inventory or peer orchestration.",
      tone: "info",
      href: "#/fleet",
      action: "Stay here",
    },
    {
      key: "templates",
      label: "candidate",
      title: candidateDirty ? "Template intent must wait behind existing candidate drift" : "Template intent uses existing candidate workflow",
      detail: candidateDirty ? "Review the staged candidate before importing another template intent; Fleet will not merge, approve, or apply distributed templates." : "Previewed templates are browser-local comparisons. Use Changes for import, validation, diff, commit, audit, and rollback.",
      tone: candidateDirty ? "warn" : "ok",
      href: "#/changes?tab=candidate",
      action: "Open Changes",
    },
    {
      key: "ha-traffic",
      label: haFacts.label,
      title: haFacts.title,
      detail: haFacts.detail,
      tone: haFacts.tone,
      href: "#/fleet",
      action: "Open HA",
    },
  ];
}

function haBoundaryFacts(ha = {}, runningVersion = 0) {
  const visible = Boolean(ha && Object.keys(ha).length);
  const role = String(ha.role || ha.localRole || ha.local_role || "standalone").toLowerCase();
  const sync = ha.sync || ha.policySync || {};
  const transport = ha.transportEvidence || ha.transport_evidence || {};
  const conntrack = ha.conntrackSync || ha.conntrack_sync || {};
  const peerVersion = Number(sync.peerVersion || sync.peer_version || ha.peerPolicyVersion || 0);
  const synchronized = Boolean(visible && runningVersion && peerVersion && peerVersion === runningVersion) || Boolean(ha.ready || ha.synchronized);
  const evidenceSuffix = ` VIP/GARP:${String(transport.state || "not_configured").toLowerCase()}; conntrack:${String(conntrack.state || "not_configured").toLowerCase()}.`;
  if (!visible || role === "standalone") {
    return {
      label: "local only",
      title: "No HA traffic-control claim",
      detail: "Fleet has no authoritative peer inventory here and does not claim VIP movement, fencing, connection-state transfer, or failover traffic control.",
      tone: "neutral",
    };
  }
  if (synchronized) {
    return {
      label: "evidence",
      title: "HA evidence is visible, not traffic authority",
      detail: "Policy/role evidence is visible, but Fleet still does not move traffic, fence peers, elect nodes, or synchronize connection state." + evidenceSuffix,
      tone: "info",
    };
  }
  return {
    label: "review",
    title: "HA peer evidence needs review before failover claims",
    detail: "Visible HA status is not synchronized enough for an operator failover claim; inspect  before any traffic-control procedure." + evidenceSuffix,
    tone: "warn",
  };
}

function previewChange(key, label, title, detail, tone) {
  return { key, label, title, detail, tone: tone || "neutral" };
}

function arrayCount(value) {
  return Array.isArray(value) ? value.length : 0;
}

function nodeModel({ status, ha, runningVersion, release, content }) {
  const hostname = status.host?.hostname || status.hostname || status.nodeName || "local appliance";
  const role = String(ha.role || ha.localRole || ha.local_role || status.highAvailability?.role || "standalone").toLowerCase();
  const sync = ha.sync || ha.policySync || {};
  const transport = ha.transportEvidence || ha.transport_evidence || {};
  const conntrack = ha.conntrackSync || ha.conntrack_sync || {};
  const peerVersion = Number(sync.peerVersion || sync.peer_version || ha.peerPolicyVersion || 0);
  const runtimeReady = release.tone !== "bad" && content.tone !== "bad";
  const haReady = role === "standalone" || ha.ready || ha.synchronized || (peerVersion && peerVersion === runningVersion);
  const evidenceDetail = [
    transport.state && transport.state !== "not_configured" ? `VIP/GARP ${transport.state}` : "",
    conntrack.state && conntrack.state !== "not_configured" ? `conntrack ${conntrack.state}` : "",
  ].filter(Boolean).join(" / ");
  return {
    id: "local",
    name: hostname,
    detail: [status.mode || status.runtimeMode || "connected management API", evidenceDetail].filter(Boolean).join(" / "),
    roleLabel: role === "active" ? "active" : role === "passive" ? "passive" : "standalone",
    roleTone: role === "passive" ? "info" : role === "active" ? "ok" : "neutral",
    policyVersion: runningVersion ? `v${runningVersion}` : "unknown",
    haLabel: role === "standalone" ? "standalone" : haReady ? "synchronized" : "review",
    haTone: role === "standalone" ? "neutral" : haReady ? "ok" : "warn",
    runtimeLabel: runtimeReady ? "operable" : "review",
    runtimeTone: runtimeReady ? "ok" : "warn",
  };
}

function driftModel({ candidateDirty, candidateStatus, runningVersion, release, content }) {
  const items = [];
  if (candidateDirty) {
    items.push({
      key: "candidate",
      label: "candidate",
      title: "Candidate differs from running",
      detail: candidateStatus.changeCount ? `${candidateStatus.changeCount} staged change${candidateStatus.changeCount === 1 ? "" : "s"} waiting for review.` : "A staged candidate is waiting for validation and commit review.",
      tone: "warn",
      href: "#/changes?tab=candidate",
      action: "Review changes",
    });
  } else {
    items.push({
      key: "candidate",
      label: "clean",
      title: "Running and candidate are aligned",
      detail: runningVersion ? `Managed appliance is on running policy v${runningVersion}.` : "No candidate drift is reported.",
      tone: "ok",
      href: "#/changes",
      action: "Open changes",
    });
  }
  if (content.tone !== "ok") items.push({ key: "content", label: "content", title: "Content package review needed", detail: content.detail, tone: content.tone, href: "#/intel", action: "Review content" });
  const worst = worstTone(items.map((item) => item.tone));
  return {
    label: candidateDirty ? "candidate drift" : worst === "ok" ? "aligned" : "review",
    detail: candidateDirty ? "staged candidate pending" : "running/candidate state",
    tone: worst,
    items,
  };
}

function contentModel(posture = {}) {
  const summary = posture.summary || {};
  const blockers = posture.blockers || [];
  if (summary.cls === "bad") return { label: "blocked", detail: summary.detail || blockers.join(", "), tone: "bad" };
  if (blockers.length) return { label: "review", detail: blockers.join(", "), tone: "warn" };
  if (summary.cls === "ok") return { label: "ready", detail: summary.detail || "content packages ready", tone: "ok" };
  return { label: summary.title || "review", detail: summary.detail || "content package evidence needs review", tone: summary.cls || "warn" };
}

function releaseModel(release = {}) {
  const state = String(release.state || "").toLowerCase();
  const summary = release.summary || {};
  const missing = Number(summary.missing || summary.invalid || summary.todo || 0);
  if (release.ready || state === "ready") return { label: "ready", detail: "release gates recorded", tone: "ok" };
  if (missing) return { label: "blocked", detail: `${missing} release gate item${missing === 1 ? "" : "s"} need evidence`, tone: "bad" };
  return { label: state || "review", detail: "release acceptance evidence is not complete", tone: state === "unavailable" ? "warn" : "warn" };
}

function templateModels({ policy, draft, candidateDirty, release, content, ha, apiTemplates = [] }) {
  const zones = (draft.zones || policy.zones || []).length;
  const rules = (draft.rules || policy.rules || []).length;
  const nat = ((draft.nat || policy.nat || {}).source || []).length + ((draft.nat || policy.nat || {}).destination || []).length;
  const vpnCount = ((draft.vpn || policy.vpn || {}).ipsecTunnels || []).length + ((draft.vpn || policy.vpn || {}).wireguardInterfaces || []).length;
  const builtins = [
    {
      key: "edge-policy",
      label: "Edge policy template",
      detail: `${zones} zones, ${rules} security rules, ${nat} NAT entries`,
      state: candidateDirty ? "drift" : "aligned",
      tone: candidateDirty ? "warn" : "ok",
      scope: "candidate policy",
      href: "#/changes?tab=candidate",
      action: "Review diff",
    },
    {
      key: "content",
      label: "Content package template",
      detail: content.detail,
      state: content.label,
      tone: content.tone,
      scope: "App-ID, Threat-ID, feeds",
      href: "#/intel",
      action: "Open Intel",
    },
    {
      key: "routing-vpn",
      label: "Routing and VPN template",
      detail: vpnCount ? `${vpnCount} VPN interface or tunnel entries` : "No VPN tunnel entries in policy",
      state: vpnCount ? "modeled" : "not configured",
      tone: vpnCount ? "info" : "neutral",
      scope: "static routes, dynamic routing, VPN",
      href: "#/netvpn",
      action: "Open Routing",
    },
    {
      key: "ha",
      label: "HA role template",
      detail: ha && Object.keys(ha).length ? "HA status is visible for this node." : "No peer inventory reported by this control plane.",
      state: ha && Object.keys(ha).length ? "visible" : "local only",
      tone: ha && Object.keys(ha).length ? "info" : "neutral",
      scope: "active/passive",
      href: "#/fleet",
      action: "Open HA",
    },
  ];
  return [
    ...apiTemplates.map(serverTemplateModel),
    ...builtins,
  ];
}

function serverTemplateModel(record) {
  const summary = record.policySummary || {};
  const nat = Number(summary.sourceNat || 0) + Number(summary.destinationNat || 0);
  const vpn = Number(summary.ipsecTunnels || 0) + Number(summary.wireGuardPeers || 0);
  return {
    key: record.id,
    id: record.id,
    label: record.name || record.id,
    detail: `${Number(summary.zones || 0)} zones, ${Number(summary.rules || 0)} rules, ${nat} NAT entries, ${vpn} VPN entries`,
    state: "server draft",
    tone: "info",
    scope: record.scope || "local-appliance",
    href: "",
    action: "API preview",
    serverBacked: true,
    revision: record.revision || "",
  };
}

function actionModels({ drift, release, content, candidateDirty }) {
  const actions = [];
  if (candidateDirty) actions.push({ key: "candidate", badge: "candidate", title: "Review staged candidate", detail: "Validate and compare the candidate before promoting it to the running appliance.", tone: "warn", href: "#/changes?tab=candidate", action: "Review" });
  if (content.tone !== "ok") actions.push({ key: "content", badge: "content", title: "Resolve content posture", detail: content.detail, tone: content.tone, href: "#/intel", action: "Open Intel" });
  if (!actions.length && drift.tone === "ok") actions.push({ key: "monitor", badge: "monitor", title: "Monitor appliance posture", detail: "No immediate fleet action is pending for the managed appliance.", tone: "ok", href: "#/", action: "" });
  return actions;
}

function evidenceModels({ errors, release, content, candidateDirty, apiTemplates = [], applyResults = [] }) {
  return [
    { key: "status", label: "Runtime and HA posture", detail: "System status and HA status shape the managed-node row.", source: "/v1/system/status, /v1/system/ha/status", state: errors.length ? "partial" : "loaded", tone: errors.length ? "warn" : "ok" },
    { key: "policy", label: "Policy drift", detail: "Running policy, candidate policy, and candidate status drive template drift.", source: "/v1/policy, /v1/candidate/status", state: candidateDirty ? "drift" : "aligned", tone: candidateDirty ? "warn" : "ok" },
    { key: "content", label: "Content packages", detail: content.detail, source: "/v1/intel/feeds, /v1/intel/content/packages", state: content.label, tone: content.tone },
    { key: "fleet-api", label: "Fleet inventory and templates", detail: `${apiTemplates.length} local template draft${apiTemplates.length === 1 ? "" : "s"} loaded from the Fleet API.`, source: "/v1/fleet/nodes, /v1/fleet/templates", state: errors.some((item) => /fleet/i.test(item)) ? "partial" : "loaded", tone: errors.some((item) => /fleet/i.test(item)) ? "warn" : "ok" },
    { key: "fleet-results", label: "Fleet apply result custody", detail: `${applyResults.length} retained apply result${applyResults.length === 1 ? "" : "s"} loaded.`, source: "/v1/fleet/template-results", state: applyResults.length ? "retained" : "empty", tone: applyResults.length ? "info" : "neutral" },
  ];
}

function normalizeFleetApplyResults(resp = {}) {
  return (resp.results || []).slice(0, 20).map((result) => {
    const nodes = Array.isArray(result.nodeResults) ? result.nodeResults : [];
    const counts = nodes.reduce((acc, node) => {
      const key = String(node.result || "unknown").toLowerCase();
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});
    const summary = ["applied", "skipped", "blocked", "error"].filter((key) => counts[key]).map((key) => `${counts[key]} ${key}`).join(", ");
    return {
      id: scrubFleetText(result.id || "apply-result", 120),
      templateId: scrubFleetText(result.templateId || "", 120),
      templateName: scrubFleetText(result.templateName || result.templateId || "template", 120),
      status: scrubFleetText(result.status || "unknown", 80),
      finishedAt: scrubFleetText(result.finishedAt || "", 120),
      custodyBoundary: scrubFleetText(result.custodyBoundary || "", 220),
      nodeSummary: summary || "no node results",
      nodes,
    };
  });
}

function normalizeFleetNodes(resp = {}) {
  return (resp.nodes || []).map((node) => {
    const role = String(node.role || "standalone").toLowerCase();
    const runningVersion = Number(node.runningVersion || 0);
    const haReady = Boolean(node.haReady);
    const runtimeState = String(node.runtimeState || "unknown").toLowerCase();
    const normalized = {
      id: node.id || "local",
      name: node.name || "local appliance",
      detail: node.detail || node.scope || "connected management API",
      roleLabel: role === "active" ? "active" : role === "passive" ? "passive" : "standalone",
      roleTone: role === "passive" ? "info" : role === "active" ? "ok" : "neutral",
      policyVersion: runningVersion ? `v${runningVersion}` : "unknown",
      haLabel: role === "standalone" ? "standalone" : haReady ? "ready" : "review",
      haTone: role === "standalone" ? "neutral" : haReady ? "ok" : "warn",
      runtimeLabel: runtimeState,
      runtimeTone: /^(ok|ready|healthy|operable|active)$/.test(runtimeState) ? "ok" : "warn",
      haReady,
    };
    const evidence = fleetNodeEvidenceModel(normalized);
    return {
      ...normalized,
      positiveEvidence: evidence.positiveEvidence,
      missingEvidence: evidence.missingEvidence,
    };
  });
}

function fleetShellArg(value = "") {
  return `'${String(value || "").replaceAll("'", "'\\''").slice(0, 160)}'`;
}

function scrubFleetText(value = "", limit = 240) {
  return String(value || "")
    .replace(/\b(bearer|token|secret|password|credential|private[_-]?key|api[_-]?key)\s*[:=]\s*[^,\s;&]+/gi, "$1=[redacted]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[redacted-jwt]")
    .replace(/\/(?:etc\/(?:openngfw|phragma)|var\/lib|var\/log|tmp|home|Users)\/[^\s,;}]+/gi, "[local-path-redacted]")
    .replace(/[;\n\r]/g, " ")
    .trim()
    .slice(0, limit);
}

function safeOrchestrationPreview(preview = {}) {
  const boundary = preview.boundary || noPeerApplyBoundaryModel();
  return {
    scope: scrubFleetText(preview.scope || "visible Fleet nodes only", 160),
    eligibleCount: Number(preview.eligibleCount || 0) || 0,
    positiveEvidenceNodes: Number(preview.positiveEvidenceNodes || 0) || 0,
    nodes: (preview.nodes || []).slice(0, 12).map((node) => ({
      id: scrubFleetText(node.id, 96),
      label: scrubFleetText(node.label, 120),
      eligible: Boolean(node.eligible),
      reason: scrubFleetText(node.reason, 240),
      positiveEvidence: (node.positiveEvidence || []).slice(0, 6).map((item) => scrubFleetText(item, 160)),
      missingEvidence: (node.missingEvidence || []).slice(0, 6).map((item) => scrubFleetText(item, 160)),
    })),
    blockers: (preview.blockers || []).slice(0, 12).map((item) => ({
      key: scrubFleetText(item.key, 80),
      label: scrubFleetText(item.label, 80),
      title: scrubFleetText(item.title, 160),
      detail: scrubFleetText(item.detail, 280),
      tone: scrubFleetText(item.tone, 24),
    })),
    plan: (preview.plan || []).slice(0, 8).map((step) => ({
      key: scrubFleetText(step.key, 80),
      label: scrubFleetText(step.label, 140),
      detail: scrubFleetText(step.detail, 260),
      boundary: scrubFleetText(step.boundary, 80),
      tone: scrubFleetText(step.tone, 24),
      command: scrubFleetText(step.command, 320),
    })),
    fanout: {
      detail: scrubFleetText(preview.fanout?.detail || "preview only", 220),
    },
    template: {
      title: scrubFleetText(preview.template?.title || "not selected", 160),
    },
    rollback: {
      title: scrubFleetText(preview.rollback?.title || "review", 80),
    },
    boundary: {
      title: scrubFleetText(boundary.title || "No peer apply", 120),
      detail: scrubFleetText(boundary.detail || "", 360),
      peerRpc: false,
      runningPolicyApply: false,
      haTrafficControl: false,
      distributedResultCustody: false,
    },
  };
}

function normalizeFleetTemplates(resp = {}) {
  return (resp.templates || []).filter((item) => item && item.id);
}

function settledErrors(results = {}) {
  return Object.entries(results)
    .filter(([, result]) => result?.status === "rejected")
    .map(([key, result]) => `${key.replace(/R$/, "")}: ${result.reason?.message || result.reason}`);
}

function worstTone(tones = []) {
  if (tones.includes("bad")) return "bad";
  if (tones.includes("warn")) return "warn";
  if (tones.includes("info")) return "info";
  return "ok";
}
