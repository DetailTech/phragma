// Intel — threat-intelligence feed registry. Shows license posture
// (commercial-use compliance is enforced at commit by the server),
// lets operators enable/disable feeds (staged to candidate), and
// triggers an immediate refresh of the blocklist sets.

import { h, icon, clear } from "../core.js";
import { api } from "../api.js";
import { throwIfAccessDenied } from "../auth_gate.js";
import { openAutomationContext } from "../automation_context.js";
import { activeInvestigationServerCaseHref, appendInvestigationPacketToActiveServerCase, pinInvestigationPacket } from "../investigation_case.js";
import { contentPackageLifecycleHandoffPacket, investigationPacketFilename, investigationPacketJson, investigationPacketText } from "../investigation_packet.js";
import { readQueryState, writeQueryState } from "../query_state.js";
import {
  buildContentPosture,
  contentCanaryTelemetryWorkbench,
  contentPackageDecisionPath,
  contentPackageInstallGuidance,
  contentPackagePreviewComparison,
  contentPromotionDecision,
  contentQualityWorkbench,
  contentActionPlan,
  customFeeds,
  effectiveFeedEnabled,
  normalizeCustomFeed,
  removeCustomFeed,
  upsertCustomFeed,
} from "../content_posture.js";
import { session } from "../policy.js";
import { pageHead, emptyState, pill, toast, card, openDrawer, closeDrawer, confirmDialog, labeledCell, responsiveTable } from "../ui.js";

export {
  buildContentPosture,
  contentCanaryTelemetryWorkbench,
  contentPackageDecisionPath,
  contentPackagePreviewComparison,
  contentPromotionDecision,
  contentQualityWorkbench,
  contentActionPlan,
  customFeeds,
  effectiveFeedEnabled,
  normalizeCustomFeed,
  removeCustomFeed,
  upsertCustomFeed,
};

export const INTEL_ROUTE_DEFAULTS = Object.freeze({
  surface: "",
  drawer: "",
});
export const INTEL_ROUTE_KEYS = Object.freeze(Object.keys(INTEL_ROUTE_DEFAULTS));
const INTEL_SURFACES = Object.freeze(["app-id", "threat-id", "intel-feeds"]);
const INTEL_DRAWERS = Object.freeze(["review", "quality", "canary", "install", "rollback"]);
let routeState = { ...INTEL_ROUTE_DEFAULTS };
let routePath = "/intel";
let lastOpenedPackageDrawer = "";

export async function render(ctx = {}) {
  routePath = ctx.path || "/intel";
  routeState = normalizeIntelRoute(readQueryState(ctx.query, INTEL_ROUTE_DEFAULTS, INTEL_ROUTE_KEYS));
  lastOpenedPackageDrawer = "";
  syncIntelRoute();
  const root = h("div", {});
  await loadAndPaint(root);
  return root;
}

async function loadAndPaint(root) {
  clear(root);
  root.appendChild(h("div", { class: "loading" }, "Loading threat intelligence..."));
  const [feedsR, contentR, sessionR] = await Promise.allSettled([
    api.feeds(),
    api.contentPackages().catch((e) => ({ packages: [], error: e.message || String(e) })),
    session.load(),
  ]);
  throwIfAccessDenied(feedsR, contentR, sessionR);
  const feeds = feedsR.status === "fulfilled" ? (feedsR.value?.feeds || []) : [];
  const content = contentR.status === "fulfilled" ? contentR.value : { packages: [], error: loadErrorDetail(contentR.reason, "Content package status unavailable.") };
  const loadError = [
    feedsR.status === "rejected" ? `feed registry: ${loadErrorDetail(feedsR.reason, "unavailable")}` : "",
    sessionR.status === "rejected" ? `candidate policy: ${loadErrorDetail(sessionR.reason, "unavailable")}` : "",
  ].filter(Boolean).join("; ");
  paint(root, feeds, content.packages || [], content.error || "", loadError);
}

function draftEnabled(name) {
  const fe = (session.draft.intel?.feeds || []).find((f) => f.name === name);
  return fe ? fe.enabled : null; // null => not declared in draft
}

export function normalizeIntelRoute(query = {}) {
  const surface = INTEL_SURFACES.includes(query.surface) ? query.surface : "";
  const drawer = INTEL_DRAWERS.includes(query.drawer) ? query.drawer : "";
  return {
    surface,
    drawer: surface ? drawer : "",
  };
}

function syncIntelRoute() {
  routeState = normalizeIntelRoute(routeState);
  writeQueryState(routePath, routeState, INTEL_ROUTE_DEFAULTS, INTEL_ROUTE_KEYS);
}

function setIntelDrawerState(surface, drawer) {
  routeState = normalizeIntelRoute({
    surface: surface?.kind || surface || "",
    drawer,
  });
  syncIntelRoute();
}

function clearIntelDrawerState() {
  routeState = { ...INTEL_ROUTE_DEFAULTS };
  lastOpenedPackageDrawer = "";
  syncIntelRoute();
}

function maybeOpenContentPackageDrawer(root, feeds, surfaces = []) {
  if (!routeState.surface || !routeState.drawer) return;
  const surface = surfaces.find((item) => item.kind === routeState.surface);
  if (!surface) return;
  const key = `${routeState.surface}:${routeState.drawer}`;
  if (key === lastOpenedPackageDrawer) return;
  lastOpenedPackageDrawer = key;
  openContentPackageDrawer(surface, routeState.drawer, root, feeds, { sync: false });
}

function openContentPackageDrawer(surface, drawer, root, feeds, opts = {}) {
  if (drawer === "install") return openInstallPackageDrawer(surface, root, feeds, opts);
  if (drawer === "rollback") return openRollbackPackageDrawer(surface, root, feeds, opts);
  if (drawer === "canary") return openCanaryTelemetryDrawer(surface, opts);
  if (drawer === "quality") return openPackageQualityDrawer(surface, opts);
  return openPackageReviewDrawer(surface, "review", opts);
}

function paint(root, feeds, contentPackages = [], contentError = "", loadError = "") {
  clear(root);
  const commercial = !!session.draft.intel?.commercialUse;
  const effectiveEnabledCount = feeds.filter((f) => effectiveFeedEnabled(f, session.draft.intel || {})).length;
  root.appendChild(pageHead("Threat intelligence",
    `${effectiveEnabledCount} of ${feeds.length} feeds enabled`,
    h("div", { class: "flex wrap" },
      loadError ? h("button", { class: "btn", type: "button", title: "Retry loading threat intelligence", "aria-label": "Retry loading threat intelligence", dataset: { intelAction: "retry-load" }, onclick: () => loadAndPaint(root) }, h("span", { html: icon("refresh", 16) }), "Retry") : null,
      h("button", { class: "btn", type: "button", title: "Refresh threat-intelligence feeds now", "aria-label": "Refresh threat-intelligence feeds now", dataset: { intelAction: "refresh-feeds" }, onclick: async () => {
        try { const r = await api.refreshFeeds(); toast("Feeds refreshed", `${r.entries || 0} entries programmed into blocklist sets.`, "ok"); }
        catch (e) { toast("Refresh failed", e.message, "bad"); }
      } }, h("span", { html: icon("refresh", 16) }), "Refresh now"))));

  if (loadError) root.appendChild(intelUnavailableBanner(loadError));

  const posture = buildContentPosture(feeds, session.draft || {}, contentPackages, contentError);
  posture.productionEvidenceInventory = productionEvidenceInventoryModel(contentPackages, contentError);
  posture.surfaces = attachProductionEvidenceInventory(posture.surfaces, posture.productionEvidenceInventory);
  root.appendChild(contentPostureCard(root, feeds, posture));
  maybeOpenContentPackageDrawer(root, feeds, posture.surfaces);

  root.appendChild(card(h("h2", {}, "Deployment use"),
    h("div", { class: "flex wrap", style: { justifyContent: "space-between", gap: "12px" } },
      h("div", {}, h("div", {}, h("strong", {}, "Commercial use"), " ", commercial ? pill("declared", "violet") : pill("not declared", "neutral")),
        h("div", { class: "note" }, "When declared, the registry refuses feeds whose license forbids commercial use. Enforced at commit.")),
      toggleCommercial(commercial, root, feeds, contentPackages, contentError)),
    refreshIntervalControl(root, feeds, contentPackages, contentError)));

  root.appendChild(customFeedsCard(root, feeds, contentPackages, contentError));

  if (!feeds.length) { root.appendChild(emptyState("intel", "No feeds", "No threat-intel feeds are registered.")); return; }

  const wrap = h("div", { class: "table-wrap intel-feed-registry-wrap" });
  root.appendChild(wrap);
  renderTable(wrap, feeds, commercial, root, contentPackages, contentError);
}

function intelUnavailableBanner(detail) {
  return h("div", { class: "alert-box bad", dataset: { intelLoadError: "true" } },
    h("strong", {}, "Threat-intelligence inventory unavailable. "),
    detail || "The feed registry API did not return data.",
    h("div", { class: "note" }, "The route shell remains available with package context where possible. Retry loading or open API / CLI context for feed registry verification."),
    h("div", { class: "flex wrap", style: { marginTop: "8px" } },
      h("button", { class: "btn sm ghost", type: "button", title: "Open Intel API and CLI context", "aria-label": "Open Intel API and CLI context", dataset: { intelAction: "api-cli" }, onclick: () => openAutomationContext(routePath) }, h("span", { html: icon("terminal", 14) }), "API / CLI")));
}

function contentPostureCard(root, feeds, posture) {
  return card(h("h2", {}, "Content posture"),
    h("div", { class: "runtime-grid" },
      metric("App-ID package", posture.metrics.appPackage),
      metric("Threat-ID package", posture.metrics.threatPackage),
      metric("Registry feeds", posture.metrics.feedRegistry),
      metric("Signed packages", posture.metrics.signedPackages)),
    h("div", { class: "alert-box " + posture.summary.cls },
      h("strong", {}, posture.summary.title + " "),
      posture.summary.detail),
    h("div", { class: "alert-box " + posture.rolloutReview.cls },
      h("strong", {}, `Rollout review: ${posture.rolloutReview.label}. `),
      posture.rolloutReview.detail,
      h("div", { class: "note", style: { marginTop: "6px" } }, posture.rolloutReview.nextAction)),
    productionEvidenceInventoryPanel(posture.productionEvidenceInventory),
    h("div", { class: "warning-list" }, posture.surfaces.map((surface) => contentSurfaceRow(surface, root, feeds))),
    h("div", { class: "profile-strip", style: { marginBottom: 0 } },
      h("div", { class: "profile-strip-head" },
        h("strong", {}, "Production blockers"),
        h("span", {}, "required before content updates can change verdicts safely")),
      h("div", { class: "setup-list" },
        h("span", {}, "Missing"),
        h("div", {}, posture.blockers.length ? posture.blockers.map((b) => pill(b, b === "commercial license conflict" ? "bad" : "warn", true)) : pill("none", "ok", true)))));
}

function productionEvidenceInventoryPanel(inventory = {}) {
  const rows = Array.isArray(inventory.rows) ? inventory.rows : [];
  return h("div", { class: "profile-strip content-production-inventory", dataset: { intelProductionEvidenceInventory: inventory.status || "missing" } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Production evidence inventory"),
      h("span", {}, inventory.status || "missing")),
    h("div", { class: "alert-box " + (inventory.cls || "warn") },
      h("strong", {}, (inventory.title || "Production evidence inventory") + " "),
      inventory.detail || "Review signed content evidence status before production rollout."),
    h("div", { class: "content-quality-evidence-list" },
      rows.map((row) => productionEvidenceInventoryRow(row))),
    inventory.commands?.length ? h("div", { class: "content-quality-command-list" },
      inventory.commands.slice(0, 7).map((command) => h("div", { class: "system-evidence-row info", dataset: { intelProductionEvidenceCommand: command } },
        h("div", {},
          h("strong", {}, command),
          h("div", { class: "note" }, commandPurpose(command)))),
      )) : null);
}

function productionEvidenceInventoryRow(row = {}) {
  return h("div", { class: "system-evidence-row " + (row.cls || "warn"), dataset: { intelProductionEvidenceSurface: row.kind || "package" } },
    h("div", {},
      h("strong", {}, row.label || row.kind || "Content package"),
      h("div", { class: "note" }, row.detail || row.nextAction || "Review production evidence status."),
      h("div", { class: "system-evidence-meta" },
        `version=${row.version || "missing"} signature=${row.signature || "missing"} evidence=${row.attachedCount || 0}/${row.requiredCount || 0}`)),
    h("div", {},
      pill(row.status || "missing", row.cls || "warn", true),
      row.blockers?.length ? h("div", { class: "note" }, `${row.blockers.length} blocker${row.blockers.length === 1 ? "" : "s"}`) : null));
}

export function productionEvidenceInventoryModel(contentPackages = [], contentError = "") {
  if (contentError) {
    return {
      status: "production-blocked",
      cls: "bad",
      title: "Production evidence inventory unavailable.",
      detail: "The content package API did not return App-ID, Threat-ID, and intel-feed package status.",
      rows: expectedProductionEvidenceKinds().map((item) => productionEvidenceInventoryModelRow(item.kind, null, { unavailable: true })),
      commands: ["ngfwctl intel content"],
      blockers: ["content package API"],
    };
  }
  const packages = new Map((contentPackages || []).filter((pkg) => pkg?.kind).map((pkg) => [pkg.kind, pkg]));
  const rows = expectedProductionEvidenceKinds().map((item) => productionEvidenceInventoryModelRow(item.kind, packages.get(item.kind)));
  const blockers = rows.flatMap((row) => row.blockers.map((blocker) => `${row.kind}:${blocker}`));
  const status = productionInventoryAggregateStatus(rows);
  return {
    status,
    cls: productionInventoryClass(status),
    title: productionInventoryTitle(status),
    detail: productionInventoryDetail(rows, blockers),
    rows,
    commands: productionInventoryCommands(rows),
    blockers: uniqueValues(blockers),
  };
}

function attachProductionEvidenceInventory(surfaces = [], inventory = {}) {
  const rows = new Map((inventory.rows || []).map((row) => [row.kind, row]));
  return surfaces.map((surface) => {
    const row = rows.get(surface.kind);
    if (!row) return surface;
    const inventoryField = {
      label: "Production inventory",
      value: `${row.status} (${row.attachedCount}/${row.requiredCount} evidence)`,
      cls: row.cls,
    };
    return {
      ...surface,
      productionEvidenceInventory: row,
      evidence: [...(surface.evidence || []), `production-evidence:${row.status}`],
      fields: [...(surface.fields || []), inventoryField],
    };
  });
}

function expectedProductionEvidenceKinds() {
  return [
    { kind: "app-id", label: "App-ID", required: ["app-taxonomy", "confidence-model", "app-regression-corpus", "license-review", "staged-rollout", "rollback-drill"] },
    { kind: "threat-id", label: "Threat-ID", required: ["threat-taxonomy", "pcap-regression-corpus", "false-positive-regression", "license-review", "staged-rollout", "rollback-drill"] },
    { kind: "intel-feeds", label: "Intel feeds", required: ["feed-registry", "parser-tests", "license-review", "false-positive-regression", "staged-rollout", "rollback-drill"] },
  ];
}

function productionEvidenceInventoryModelRow(kind, pkg, opts = {}) {
  const expected = expectedProductionEvidenceKinds().find((item) => item.kind === kind) || { kind, label: kind, required: [] };
  if (opts.unavailable) {
    return {
      kind,
      label: expected.label,
      status: "production-blocked",
      cls: "bad",
      detail: "Content package API status is unavailable.",
      version: "",
      signature: "unknown",
      requiredCount: expected.required.length,
      attachedCount: 0,
      blockers: ["content package API"],
      evidence: [],
      nextAction: "Restore /v1/intel/content/packages visibility, then re-run content review.",
    };
  }
  if (!pkg) {
    return {
      kind,
      label: expected.label,
      status: "missing",
      cls: "warn",
      detail: "No signed local content package is installed for this inventory surface.",
      version: "",
      signature: "missing",
      requiredCount: expected.required.length,
      attachedCount: 0,
      blockers: ["content package"],
      evidence: [],
      nextAction: `Preview and install a signed ${kind} package from the firewall content import directory.`,
    };
  }
  const readiness = normalizeContentForInventory(pkg.content || pkg.content_readiness || {});
  const required = readiness.requiredProductionEvidence.length ? readiness.requiredProductionEvidence : expected.required;
  const attached = new Set(readiness.evidence.filter((ref) => ref.artifact && ref.sha256).map((ref) => ref.type));
  const missing = required.filter((type) => !attached.has(type));
  const blockers = uniqueValues([...(pkg.blockers || []), ...readiness.blockers, ...missing.map((type) => `production evidence:${type}`)]);
  const status = productionEvidenceInventoryStatus(pkg, readiness, missing);
  return {
    kind,
    label: expected.label,
    status,
    cls: productionInventoryClass(status),
    detail: productionEvidenceInventoryDetail(status, pkg, readiness, missing),
    version: pkg.version || "",
    signature: pkg.signatureStatus || "missing",
    requiredCount: required.length,
    attachedCount: required.length - missing.length,
    blockers,
    evidence: readiness.evidence,
    nextAction: productionEvidenceInventoryNextAction(status, kind, missing),
  };
}

function normalizeContentForInventory(readiness = {}) {
  const evidence = Array.isArray(readiness.evidence) ? readiness.evidence : [];
  return {
    scope: readiness.scope || "",
    productionContent: !!(readiness.productionContent ?? readiness.production_content),
    productionReady: !!(readiness.productionReady ?? readiness.production_ready),
    evidenceStatus: readiness.evidenceStatus || readiness.evidence_status || "",
    readinessLabel: readiness.readinessLabel || readiness.readiness_label || "",
    readinessDetail: readiness.readinessDetail || readiness.readiness_detail || "",
    requiredProductionEvidence: Array.isArray(readiness.requiredProductionEvidence)
      ? readiness.requiredProductionEvidence
      : Array.isArray(readiness.required_production_evidence) ? readiness.required_production_evidence : [],
    evidence: evidence.map((ref) => ({
      type: safeEvidenceToken(ref.type || ref.evidenceType || ref.evidence_type),
      artifact: safeEvidenceArtifact(ref.artifact || ref.path || ref.name),
      sha256: safeSha256(ref.sha256 || ref.sha256Hash || ref.sha256_hash),
    })).filter((ref) => ref.type || ref.artifact || ref.sha256),
    blockers: Array.isArray(readiness.blockers) ? readiness.blockers : [],
  };
}

function productionEvidenceInventoryStatus(pkg = {}, readiness = {}, missing = []) {
  const packageBlockers = Array.isArray(pkg.blockers) ? pkg.blockers : [];
  if (!readiness.readinessLabel && !readiness.evidenceStatus) return "missing";
  if (readiness.readinessLabel === "missing-readiness" || readiness.evidenceStatus === "missing") return "missing";
  if (readiness.readinessLabel === "demo-only" || readiness.evidenceStatus === "demo-only" || readiness.scope === "demo-only" || !readiness.productionContent) return "demo";
  if (readiness.productionReady && readiness.evidenceStatus === "passed" && missing.length === 0 && readiness.blockers.length === 0 && packageBlockers.length === 0 && pkg.signatureStatus === "verified") return "production-ready";
  return "production-blocked";
}

function productionInventoryAggregateStatus(rows = []) {
  if (rows.every((row) => row.status === "production-ready")) return "production-ready";
  if (rows.some((row) => row.status === "production-blocked")) return "production-blocked";
  if (rows.some((row) => row.status === "demo")) return "demo";
  return "missing";
}

function productionInventoryClass(status = "") {
  if (status === "production-ready") return "ok";
  if (status === "production-blocked") return "bad";
  return "warn";
}

function productionInventoryTitle(status = "") {
  if (status === "production-ready") return "Production evidence inventory ready.";
  if (status === "production-blocked") return "Production evidence inventory blocked.";
  if (status === "demo") return "Production evidence inventory is demo-only.";
  return "Production evidence inventory missing.";
}

function productionInventoryDetail(rows = [], blockers = []) {
  const counts = rows.reduce((acc, row) => {
    acc[row.status] = (acc[row.status] || 0) + 1;
    return acc;
  }, {});
  const summary = ["production-ready", "production-blocked", "demo", "missing"]
    .filter((key) => counts[key])
    .map((key) => `${counts[key]} ${key}`)
    .join(", ");
  return blockers.length
    ? `${summary}; ${blockers.length} blocker${blockers.length === 1 ? "" : "s"} remain before signed content can be treated as production-ready.`
    : `${summary}; signed App-ID, Threat-ID, and intel-feed evidence is complete for reviewed production rollout.`;
}

function productionInventoryCommands(rows = []) {
  const commands = ["ngfwctl intel content"];
  for (const row of rows) {
    commands.push(`ngfwctl intel content preview ${row.kind} --source <data-dir>/content-import/${row.kind}`);
    const corpus = row.evidence.find((ref) => isInventoryCorpusEvidenceType(ref.type));
    if (corpus) commands.push(`ngfwctl intel content corpus ${row.kind} --evidence-type ${corpus.type}`);
  }
  return uniqueValues(commands);
}

function productionEvidenceInventoryDetail(status, pkg = {}, readiness = {}, missing = []) {
  if (status === "production-ready") return readiness.readinessDetail || "Signed package evidence is ready.";
  if (status === "demo") return readiness.readinessDetail || "Package evidence is explicitly demo-only and not approved for production verdict changes.";
  if (status === "missing") return "Signed package evidence is not installed for this package.";
  if (missing.length) return `Missing required production evidence: ${missing.join(", ")}.`;
  return readiness.readinessDetail || pkg.detail || "Package evidence needs review.";
}

function productionEvidenceInventoryNextAction(status, kind, missing = []) {
  if (status === "production-ready") return `Inspect ${kind} evidence and keep rollback/canary handoff attached to the change record.`;
  if (status === "demo") return `Replace demo ${kind} content with a production-scoped signed package before verdict-changing use.`;
  if (status === "missing") return `Install signed ${kind} content with package evidence.`;
  if (missing.length) return `Attach ${missing[0]} and re-run content package preview for ${kind}.`;
  return `Resolve package blockers and re-run content package preview for ${kind}.`;
}

function isInventoryCorpusEvidenceType(type = "") {
  const text = String(type || "");
  return text.includes("regression-corpus") ||
    text.includes("parser-tests") ||
    text.includes("false-positive-regression");
}

function safeEvidenceToken(value = "") {
  return String(value || "").trim().toLowerCase().replace(/[^a-z0-9_.:-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 128);
}

function safeEvidenceArtifact(value = "") {
  const text = String(value || "").trim();
  if (!text || text.startsWith("/") || /^[a-z][a-z0-9+.-]*:/i.test(text) || text.includes("..")) return "";
  return text.split(/[\\/]+/).filter(Boolean).join("/").slice(0, 240);
}

function safeSha256(value = "") {
  const text = String(value || "").trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(text) ? text : "";
}

function uniqueValues(values = []) {
  const seen = new Set();
  const out = [];
  for (const value of values) {
    if (!value || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}

function contentSurfaceRow(surface, root, feeds) {
  const decision = surface.decision || contentPackageDecisionPath({ kind: surface.kind, name: surface.name });
  return h("div", { class: "warning-row " + surface.cls, dataset: { intelContentSurface: surface.kind } },
    h("div", {}, pill(surface.badge, surface.cls, true)),
    h("div", {},
      h("strong", {}, surface.name),
      h("div", { class: "note" }, surface.detail),
      contentDecisionStrip(decision),
      contentPromotionMiniStrip(surface),
      h("div", { class: "note" }, "Next action: ", decision.nextAction),
      h("div", { class: "warning-actions" },
        surface.evidence?.length ? surface.evidence.map((item) => h("code", {}, item)) : null,
        surface.kind === "app-id" ? h("button", { class: "btn sm ghost", type: "button", title: "Review App-ID observations in Traffic", "aria-label": "Review App-ID observations in Traffic", dataset: { intelContentAction: "review-observations" }, onclick: () => { location.hash = "#/traffic?mode=app-id"; } },
          h("span", { html: icon("traffic", 14) }), "Review observations") : null,
        h("button", { class: "btn sm ghost", type: "button", title: `Open ${surface.name} package quality gates`, "aria-label": `Open ${surface.name} package quality gates`, dataset: { intelContentAction: "quality", intelContentSurface: surface.kind }, onclick: () => openPackageQualityDrawer(surface) },
          h("span", { html: icon("check", 14) }), "Quality gates"),
        h("button", { class: "btn sm ghost", type: "button", title: `Open ${surface.name} canary rollout and false-positive telemetry`, "aria-label": `Open ${surface.name} canary rollout and false-positive telemetry`, dataset: { intelContentAction: "canary", intelContentSurface: surface.kind }, onclick: () => openCanaryTelemetryDrawer(surface) },
          h("span", { html: icon("clock", 14) }), "Canary"),
        h("button", { class: "btn sm ghost", type: "button", title: `Review ${surface.name} rollout gates`, "aria-label": `Review ${surface.name} rollout gates`, dataset: { intelContentAction: "review", intelContentSurface: surface.kind }, onclick: () => openPackageReviewDrawer(surface) },
          h("span", { html: icon("shield", 14) }), "Review"),
        h("button", { class: "btn sm", type: "button", title: `Install ${surface.name} from the firewall content import directory`, "aria-label": `Install ${surface.name} from the firewall content import directory`, dataset: { intelContentAction: "install", intelContentSurface: surface.kind }, onclick: () => openInstallPackageDrawer(surface, root, feeds) },
          h("span", { html: icon("terminal", 14) }), "Install"),
        h("button", {
          class: "btn sm ghost",
          type: "button",
          dataset: { intelContentAction: "rollback", intelContentSurface: surface.kind },
          disabled: !surface.rollbackAvailable,
          title: surface.rollbackAvailable ? `Restore latest verified backup for ${surface.name}` : `No verified rollback backup reported for ${surface.name}`,
          "aria-label": surface.rollbackAvailable ? `Restore latest verified backup for ${surface.name}` : `Rollback unavailable for ${surface.name}`,
          onclick: () => openRollbackPackageDrawer(surface, root, feeds),
        }, h("span", { html: icon("rollback", 14) }), "Rollback"))));
}

function contentDecisionStrip(decision) {
  return h("div", { class: "warning-actions", style: { marginTop: "8px", marginBottom: "4px" } },
    (decision.checks || []).map((check) => pill(`${check.label}: ${check.status}`, check.cls, true)));
}

function contentPromotionMiniStrip(surface = {}) {
  const decision = contentPromotionDecision(surface);
  return h("div", { class: "warning-actions", style: { marginTop: "6px", marginBottom: "4px" }, dataset: { intelPromotionDecision: surface.kind || decision.kind } },
    pill(decision.label, decision.cls, true),
    pill("handoff only", "info", true),
    decision.blockers.length ? pill(`${decision.blockers.length} hold`, "bad", true) : null,
    decision.reviewItems.length ? pill(`${decision.reviewItems.length} review`, "warn", true) : null);
}

function contentPromotionDecisionPanel(surface = {}, opts = {}) {
  const decision = contentPromotionDecision(surface, opts);
  return h("div", { class: "profile-strip content-promotion-decision", dataset: { intelPromotionDecisionPanel: decision.kind, intelPromotionLifecycle: opts.lifecycleAction || "promotion" } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Promotion and rollback decision handoff"),
      h("span", {}, decision.label)),
    h("div", { class: "alert-box " + decision.cls },
      h("strong", {}, `${decision.label}. `),
      decision.detail,
      h("div", { class: "note", style: { marginTop: "6px" } }, decision.nextAction)),
    h("div", { class: "runtime-grid content-quality-metrics" },
      decision.checks.map((check) => metric(check.label, check.status))),
    decision.blockers.length || decision.reviewItems.length ? h("div", { class: "release-acceptance-problem-list" },
      decision.blockers.map((item) => h("span", {}, `hold: ${item}`)),
      decision.reviewItems.map((item) => h("span", {}, `review: ${item}`))) : null,
    h("div", { class: "content-quality-command-list" },
      decision.commands.map((item) => h("div", { class: "system-evidence-row info", dataset: { intelPromotionCommand: item.label } },
        h("div", {},
          h("strong", {}, item.label),
          h("div", { class: "note" }, "Operator-run lifecycle command; this panel does not execute it.")),
        h("div", {}, h("code", {}, item.command))))),
    h("div", { class: "note" }, decision.boundary));
}

function openPackageReviewDrawer(surface, mode = "review", opts = {}) {
  if (opts.sync !== false) setIntelDrawerState(surface, mode);
  openDrawer({
    title: `${surface.name} rollout review`,
    subtitle: mode === "install"
      ? "Current installed posture before replacement. The server verifies the source package during install."
      : mode === "rollback"
        ? "Rollback restores the latest verified backup; review current blockers before replacing active content."
        : "Per-package decision path for verdict-changing content rollout.",
    width: "660px",
    onClose: clearIntelDrawerState,
    body: packageReviewBody(surface, mode),
    footer: [
      h("button", { class: "btn primary", type: "button", title: `Close ${surface.name} rollout review`, "aria-label": `Close ${surface.name} rollout review`, dataset: { intelContentAction: "close-review", intelContentSurface: surface.kind }, onclick: closeDrawer }, "Done"),
    ],
  });
}

function packageReviewBody(surface, mode = "review") {
  const decision = surface.decision || contentPackageDecisionPath({ kind: surface.kind, name: surface.name });
  return h("div", { dataset: { intelContentDrawer: mode, intelContentSurface: surface.kind } },
    h("div", { class: "alert-box " + decision.cls },
      h("strong", {}, `${decision.label}. `),
      decision.detail,
      h("div", { class: "note", style: { marginTop: "6px" } }, decision.nextAction)),
    contentPromotionDecisionPanel(surface, { lifecycleAction: mode }),
    h("div", { class: "warning-list" }, (decision.checks || []).map((check) =>
      h("div", { class: "warning-row " + check.cls },
        h("div", {}, pill(check.label, check.cls, true)),
        h("div", {},
          h("strong", {}, check.status || "missing"),
          h("div", { class: "note" }, check.cls === "ok" ? "Reported by the content package API." : check.action))))),
    mode === "install" ? h("div", { class: "alert-box info", style: { marginBottom: 0 } },
      h("strong", {}, "Candidate source verification. "),
      "The browser cannot inspect the server-local source directory. Install remains audited and the API rejects packages that do not verify.") : null,
    handoffActions(contentPackageLifecycleHandoffPacket(surface, { route: currentRoute(), lifecycleAction: mode })));
}

function openPackageQualityDrawer(surface, opts = {}) {
  if (opts.sync !== false) setIntelDrawerState(surface, "quality");
  openDrawer({
    title: `${surface.name} quality gates`,
    subtitle: "Package version, required evidence, and package posture.",
    width: "780px",
    onClose: clearIntelDrawerState,
    body: packageQualityBody(surface),
    footer: [
      h("button", { class: "btn primary", type: "button", title: `Close ${surface.name} quality gates`, "aria-label": `Close ${surface.name} quality gates`, dataset: { intelContentAction: "close-quality", intelContentSurface: surface.kind }, onclick: closeDrawer }, "Done"),
    ],
  });
}

function packageQualityBody(surface) {
  const workbench = contentQualityWorkbench(surface);
  return h("div", { class: "content-quality-workbench", dataset: { intelContentDrawer: "quality", intelContentSurface: surface.kind } },
    h("div", { class: "alert-box " + workbench.cls },
      h("strong", {}, `Quality gates: ${workbench.metrics.gateScore}. `),
      workbench.summary,
      h("div", { class: "note", style: { marginTop: "6px" } }, workbench.nextAction)),
    h("div", { class: "runtime-grid content-quality-metrics" },
      metric("Package version", workbench.metrics.version),
      metric("Gate score", workbench.metrics.gateScore),
      metric("Required evidence", workbench.metrics.requiredEvidence),
      metric("Blockers", workbench.metrics.blockers)),
    workbench.blockers.length ? h("div", { class: "profile-strip" },
      h("div", { class: "profile-strip-head" },
        h("strong", {}, "Blocking items"),
        h("span", {}, "must be resolved before production use")),
      h("div", { class: "release-acceptance-problem-list" },
        workbench.blockers.slice(0, 10).map((item) => h("span", {}, item)))) : null,
    contentActionPlanPanel(surface),
    contentCanaryTelemetryPanel(surface),
    contentPromotionDecisionPanel(surface, { lifecycleAction: "quality" }),
    contentQualityEvidenceInventory(workbench, surface),
    h("div", { class: "content-quality-gates" }, workbench.gates.map((gate) => contentQualityGateRow(gate, surface))),
    handoffActions(contentPackageLifecycleHandoffPacket(surface, { route: currentRoute(), lifecycleAction: "quality" })));
}

function openCanaryTelemetryDrawer(surface, opts = {}) {
  if (opts.sync !== false) setIntelDrawerState(surface, "canary");
  openDrawer({
    title: `${surface.name} canary telemetry`,
    subtitle: "Bounded rollout scope, false-positive signals, rollback posture, and review boundary.",
    width: "780px",
    onClose: clearIntelDrawerState,
    body: canaryTelemetryBody(surface),
    footer: [
      h("button", { class: "btn primary", type: "button", title: `Close ${surface.name} canary telemetry`, "aria-label": `Close ${surface.name} canary telemetry`, dataset: { intelContentAction: "close-canary", intelContentSurface: surface.kind }, onclick: closeDrawer }, "Done"),
    ],
  });
}

function contentCanaryTelemetryPanel(surface = {}) {
  const workbench = contentCanaryTelemetryWorkbench(surface);
  return h("div", { class: "profile-strip content-canary-telemetry", dataset: { intelCanaryTelemetry: workbench.kind } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Canary rollout and false-positive telemetry"),
      h("span", {}, workbench.metrics.rolloutState)),
    h("div", { class: "alert-box " + workbench.cls },
      h("strong", {}, `${workbench.title} `),
      workbench.detail),
    h("div", { class: "runtime-grid content-quality-metrics" },
      metric("Canary scopes", workbench.metrics.canaryScopes),
      metric("FP signals", workbench.metrics.falsePositiveSignals),
      metric("Rollback", workbench.metrics.rollback),
      metric("Boundary", "browser-local")),
    h("div", { class: "warning-actions" },
      h("button", { class: "btn sm ghost", type: "button", title: `Open ${surface.name} canary telemetry workbench`, "aria-label": `Open ${surface.name} canary telemetry workbench`, dataset: { intelContentAction: "open-canary-workbench", intelContentSurface: surface.kind }, onclick: () => openCanaryTelemetryDrawer(surface) },
        h("span", { html: icon("clock", 14) }), "Open workbench")));
}

function canaryTelemetryBody(surface = {}) {
  const workbench = contentCanaryTelemetryWorkbench(surface);
  return h("div", { class: "content-canary-workbench", dataset: { intelContentDrawer: "canary", intelContentSurface: surface.kind } },
    h("div", { class: "alert-box " + workbench.cls },
      h("strong", {}, `${workbench.title} `),
      workbench.detail,
      h("div", { class: "note", style: { marginTop: "6px" } }, workbench.nextAction)),
    h("div", { class: "runtime-grid content-quality-metrics" },
      metric("Rollout state", workbench.metrics.rolloutState),
      metric("Canary scopes", workbench.metrics.canaryScopes),
      metric("False-positive signals", workbench.metrics.falsePositiveSignals),
      metric("Rollback", workbench.metrics.rollback)),
    workbench.blockers.length ? h("div", { class: "profile-strip" },
      h("div", { class: "profile-strip-head" },
        h("strong", {}, "Promotion blockers"),
        h("span", {}, "resolve before expanding rollout")),
      h("div", { class: "release-acceptance-problem-list" },
        workbench.blockers.map((item) => h("span", {}, item)))) : null,
    contentPromotionDecisionPanel(surface, { lifecycleAction: "canary", canary: workbench }),
    canaryScopeRows(workbench),
    falsePositiveTelemetryRows(workbench),
    h("div", { class: "alert-box info" },
      h("strong", {}, "Boundary. "),
      workbench.boundary),
    handoffActions(contentPackageLifecycleHandoffPacket(surface, {
      route: currentRoute(),
      lifecycleAction: "canary",
      extra: {
        rolloutState: workbench.metrics.rolloutState,
        canaryScopes: workbench.metrics.canaryScopes,
        falsePositiveSignals: workbench.metrics.falsePositiveSignals,
      },
    })));
}

function canaryScopeRows(workbench = {}) {
  const rows = workbench.scopes.length ? workbench.scopes : [{
    name: "not declared",
    mode: "review",
    exposure: "0%",
    status: "missing",
    cls: "warn",
    detail: "No package canary scopes were reported by the content package API.",
  }];
  return h("div", { class: "profile-strip content-canary-scopes" },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Canary scopes"),
      h("span", {}, "package-reported rollout bounds")),
    h("div", { class: "table-wrap" },
      responsiveTable(["Scope", "Mode", "Exposure", "Status"], rows.map((row) => h("tr", { dataset: { intelCanaryScope: row.name } },
        labeledCell("Scope", {}, h("strong", {}, row.name), row.detail ? h("div", { class: "note" }, row.detail) : null),
        labeledCell("Mode", {}, row.mode),
        labeledCell("Exposure", {}, row.exposure),
        labeledCell("Status", {}, pill(row.status || "missing", row.cls || "warn", true)))),
      { className: "content-canary-scope-table" })));
}

function falsePositiveTelemetryRows(workbench = {}) {
  const signals = workbench.telemetry.signals.length ? workbench.telemetry.signals : [{
    label: "not reported",
    status: "missing",
    count: "",
    evidence: "",
    detail: "No false-positive telemetry or false-positive regression evidence was reported by the package API.",
    cls: "warn",
  }];
  return h("div", { class: "profile-strip content-fp-telemetry" },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "False-positive telemetry"),
      h("span", {}, workbench.telemetry.label)),
    h("div", { class: "table-wrap" },
      responsiveTable(["Signal", "Count", "Evidence", "Status"], signals.map((signal) => h("tr", { dataset: { intelFalsePositiveSignal: signal.label } },
        labeledCell("Signal", {}, h("strong", {}, signal.label), signal.detail ? h("div", { class: "note" }, signal.detail) : null),
        labeledCell("Count", {}, signal.count || "n/a"),
        labeledCell("Evidence", {}, signal.evidence ? h("code", {}, signal.evidence) : "not attached"),
        labeledCell("Status", {}, pill(signal.status || "missing", signal.cls || "warn", true)))),
      { className: "content-fp-telemetry-table" })));
}

function contentActionPlanPanel(surface = {}) {
  const plan = contentActionPlan(surface);
  return h("div", { class: "profile-strip content-readiness-action-plan", dataset: { intelContentActionPlan: plan.kind } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Operator action plan"),
      h("span", {}, plan.cls === "ok" ? "inspect before rollout approval" : "resolve before production use")),
    h("div", { class: "alert-box " + plan.cls },
      h("strong", {}, `${plan.title} `),
      plan.detail),
    plan.missingEvidence.length ? h("div", { class: "release-acceptance-problem-list" },
      plan.missingEvidence.map((item) => h("span", {}, item))) : null,
    h("div", { class: "content-quality-command-list" },
      plan.commands.map((item) => h("div", { class: "system-evidence-row info", dataset: { intelContentCommand: item.label } },
        h("div", {},
          h("strong", {}, item.label),
          h("div", { class: "note" }, commandPurpose(item.command))),
        h("div", {}, h("code", {}, item.command))))),
    plan.evidence.length ? h("div", { class: "note" },
      "Inspectable evidence: ",
      plan.evidence.map((ref, index) => h("span", {}, index ? ", " : "", `${ref.type}${ref.sha256Short ? ` sha256:${ref.sha256Short}` : ""}`))) : null);
}

function commandPurpose(command = "") {
  if (command.includes(" preview ")) return "Non-mutating review of a server-local import candidate.";
  if (command.includes(" install ")) return "Audited lifecycle promotion after preview and evidence review.";
  if (command.includes(" corpus ")) return "Typed regression sample inspection from verified package evidence.";
  if (command.includes(" rollback ")) return "Restore the latest verified backup for this package kind.";
  return "List installed App-ID, Threat-ID, and feed package posture.";
}

function contentQualityEvidenceInventory(workbench = {}, surface = {}) {
  const attached = Array.isArray(workbench.attachedEvidence) ? workbench.attachedEvidence : [];
  const required = Array.isArray(workbench.requiredEvidence) ? workbench.requiredEvidence : [];
  const attachedTypes = new Set(attached.map((ref) => ref.type).filter(Boolean));
  const rows = required.map((type) => {
    const ref = attached.find((item) => item.type === type);
    return {
      type,
      label: contentEvidenceTypeTitle(type),
      artifact: ref?.artifact || "not attached",
      sha: ref?.sha256Short || (ref?.sha256 ? String(ref.sha256).slice(0, 12) : ""),
      attached: attachedTypes.has(type),
    };
  });
  const corpus = contentQualityCorpusRow(surface, attached);
  return h("div", { class: "profile-strip content-quality-inventory", dataset: { contentQualityInventory: surface.kind || workbench.kind || "package" } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Evidence inventory"),
      h("span", {}, `${attached.length}/${required.length} required artifacts attached`)),
    h("div", { class: "runtime-grid content-quality-metrics" },
      metric(" scope", surface.content?.scope || "missing"),
      metric("Evidence status", surface.content?.evidenceStatus || "missing"),
      metric("Regression corpus", corpus.status),
      metric("Inspectable artifacts", String(attached.length))),
    h("div", { class: "content-quality-evidence-list" },
      rows.map((row) => h("div", { class: "system-evidence-row " + (row.attached ? "ok" : "bad"), dataset: { contentQualityEvidence: row.type } },
        h("div", {},
          h("strong", {}, row.label),
          h("div", { class: "note" }, row.artifact),
          row.sha ? h("div", { class: "system-evidence-meta" }, `sha256:${row.sha}`) : null),
        h("div", {}, pill(row.attached ? "attached" : "missing", row.attached ? "ok" : "bad", true))))));
}

function contentQualityCorpusRow(surface = {}, evidenceRefs = []) {
  const expected = surface.kind === "app-id"
    ? "app-regression-corpus"
    : surface.kind === "threat-id"
      ? "pcap-regression-corpus"
      : "parser-tests";
  const ref = evidenceRefs.find((item) => item.type === expected);
  return {
    type: expected,
    status: ref ? `${contentEvidenceTypeTitle(expected)} attached` : `${contentEvidenceTypeTitle(expected)} missing`,
  };
}

function contentQualityGateRow(gate, surface) {
  const cls = gate.cls || "warn";
  const inspect = gate.evidenceRef ? h("button", {
    class: "btn sm ghost",
    type: "button",
    title: `Inspect ${contentEvidenceTypeTitle(gate.evidenceRef.type || gate.requiredType || "package")} evidence JSON for ${surface.name}`,
    "aria-label": `Inspect ${contentEvidenceTypeTitle(gate.evidenceRef.type || gate.requiredType || "package")} evidence JSON for ${surface.name}`,
    dataset: { intelContentAction: "inspect-evidence", intelContentSurface: surface.kind, evidenceType: gate.evidenceRef.type || gate.requiredType || "" },
    onclick: () => openContentEvidenceDrawer(surface, gate.evidenceRef, gate),
  }, h("span", { html: icon("search", 14) }), "Inspect") : null;
  const browseCorpus = isCorpusEvidenceType(gate.evidenceRef?.type || gate.requiredType) && gate.evidenceRef ? h("button", {
    class: "btn sm ghost",
    type: "button",
    title: `Browse ${contentEvidenceTypeTitle(gate.evidenceRef.type || gate.requiredType || "regression corpus")} rows for ${surface.name}`,
    "aria-label": `Browse ${contentEvidenceTypeTitle(gate.evidenceRef.type || gate.requiredType || "regression corpus")} rows for ${surface.name}`,
    dataset: { intelContentAction: "browse-corpus", intelContentSurface: surface.kind, evidenceType: gate.evidenceRef.type || gate.requiredType || "" },
    onclick: () => openContentCorpusDrawer(surface, gate.evidenceRef, gate),
  }, h("span", { html: icon("filter", 14) }), "Browse corpus") : null;
  return h("div", { class: "system-evidence-row " + cls, dataset: { contentQualityGate: gate.key || "" } },
    h("div", {},
      h("strong", {}, gate.label || "Quality gate"),
      h("div", { class: "note" }, gate.detail || "Review this quality gate before changing content."),
      h("div", { class: "system-evidence-meta" }, `${gate.group || "Gate"} / ${gate.action || "No operator action required."}`)),
    h("div", { class: "content-quality-actions" },
      inspect,
      browseCorpus,
      pill(gate.status || cls, cls, true)));
}

function openContentEvidenceDrawer(surface, ref, gate = {}) {
  const body = h("div", { class: "content-evidence-drawer" },
    h("div", { class: "alert-box info" },
      h("strong", {}, "Loading evidence. "),
      "Reading the package-local JSON artifact referenced by the signed content readiness metadata."));
  openDrawer({
    title: `${surface.name} evidence`,
    subtitle: gate.label || ref.type || "Content package evidence",
    width: "780px",
    body,
    footer: [
      h("button", { class: "btn primary", type: "button", title: `Close ${surface.name} evidence drawer`, "aria-label": `Close ${surface.name} evidence drawer`, dataset: { intelContentAction: "close-evidence", intelContentSurface: surface.kind }, onclick: closeDrawer }, "Done"),
    ],
  });
  (async () => {
    try {
      const result = await api.contentEvidence(surface.kind, ref.type || gate.requiredType || "");
      clear(body).appendChild(contentEvidenceBody(result));
    } catch (e) {
      clear(body).appendChild(h("div", { class: "alert-box bad" },
        h("strong", {}, "Evidence unavailable. "),
        e.message || "The content evidence artifact could not be loaded."));
    }
  })();
}

function openContentCorpusDrawer(surface, ref, gate = {}) {
  const body = h("div", { class: "content-corpus-drawer", dataset: { intelCorpusBrowser: surface.kind || "package" } },
    h("div", { class: "alert-box info" },
      h("strong", {}, "Loading corpus. "),
      "Reading regression sample rows from the package-local evidence artifact."));
  openDrawer({
    title: `${surface.name} corpus browser`,
    subtitle: gate.label || ref.type || "Regression corpus evidence",
    width: "880px",
    body,
    footer: [
      h("button", { class: "btn primary", type: "button", title: `Close ${surface.name} corpus browser`, "aria-label": `Close ${surface.name} corpus browser`, dataset: { intelContentAction: "close-corpus", intelContentSurface: surface.kind }, onclick: closeDrawer }, "Done"),
    ],
  });
  (async () => {
    try {
      const result = await api.contentCorpus(surface.kind, { evidenceType: ref.type || gate.requiredType || "" });
      clear(body).appendChild(contentCorpusBrowserBody(surface, result));
    } catch (e) {
      clear(body).appendChild(h("div", { class: "alert-box bad" },
        h("strong", {}, "Corpus unavailable. "),
        e.message || "The regression corpus evidence artifact could not be loaded."));
    }
  })();
}

function contentCorpusBrowserBody(surface = {}, result = {}) {
  const evidenceType = result.evidence?.type || result.evidence_type || "";
  const model = Array.isArray(result.samples)
    ? contentRegressionCorpusAPIModel(result, evidenceType)
    : contentRegressionCorpusModel(result.contentJson || result.content_json || "", evidenceType);
  const state = { q: "", verdict: "" };
  const tableSlot = h("div", { class: "content-corpus-table" });
  const query = h("input", {
    class: "input",
    type: "search",
    placeholder: "sample, app, SID, verdict, pcap hash",
    dataset: { intelCorpusFilter: "query" },
    oninput: () => { state.q = query.value; renderCorpusRows(); },
  });
  const verdict = h("select", {
    class: "input",
    dataset: { intelCorpusFilter: "verdict" },
    onchange: () => { state.verdict = verdict.value; renderCorpusRows(); },
  },
  h("option", { value: "" }, "All verdicts"),
  ...model.verdicts.map((item) => h("option", { value: item }, item)));
  const renderCorpusRows = () => {
    const rows = filterCorpusRows(model.rows, state);
    tableSlot.replaceChildren(contentCorpusTable(rows));
  };
  renderCorpusRows();
  return h("div", { class: "content-corpus-browser", dataset: { intelCorpusEvidence: evidenceType || model.type || "corpus" } },
    h("div", { class: "alert-box " + (model.failedSamples ? "warn" : "ok") },
      h("strong", {}, "Persisted regression corpus. "),
      model.summary,
      h("div", { class: "note", style: { marginTop: "6px" } }, "Rows come from the typed content corpus API after the server verifies package-local evidence against the manifest.")),
    h("div", { class: "runtime-grid content-quality-metrics" },
      metric("Evidence type", contentEvidenceTypeTitle(model.type || evidenceType || "corpus")),
      metric("Package version", model.packageVersion || result.packageVersion || result.package_version || "not declared"),
      metric("Samples", String(model.sampleCount || 0)),
      metric("Failed samples", String(model.failedSamples || 0))),
    h("div", { class: "filter-row content-corpus-filters" },
      h("label", { class: "field" }, h("span", {}, "Search"), query),
      h("label", { class: "field" }, h("span", {}, "Verdict"), verdict)),
    tableSlot,
    handoffActions(contentPackageLifecycleHandoffPacket(surface, {
      route: currentRoute(),
      lifecycleAction: "corpus",
      extra: {
        evidenceType: model.type || evidenceType || "corpus",
        sampleCount: model.sampleCount || 0,
        failedSamples: model.failedSamples || 0,
      },
    })));
}

function contentCorpusTable(rows = []) {
  if (!rows.length) {
    return h("div", { class: "empty-state compact" },
      h("strong", {}, "No matching corpus rows"),
      h("p", {}, "Adjust the search or verdict filter."));
  }
  return h("div", { class: "table-wrap" },
    responsiveTable(["Sample", "Expected", "Observed", "PCAP hash", "Verdict"], rows.map((sample) => h("tr", { dataset: { intelCorpusSample: sample.id || "sample" } },
      labeledCell("Sample", {}, sample.id || "sample"),
      labeledCell("Expected", {}, sample.expected || "missing"),
      labeledCell("Observed", {}, sample.observed || "missing"),
      labeledCell("PCAP hash", {}, h("code", {}, sample.pcapSha256 ? shortHash(sample.pcapSha256) : "missing")),
      labeledCell("Verdict", {}, pill(sample.verdict || "missing", sample.verdict === "passed" ? "ok" : "bad", true)))),
    { className: "content-corpus-samples" }));
}

function contentEvidenceBody(result = {}) {
  const ref = result.evidence || {};
  const summary = summarizeContentEvidence(result.contentJson || result.content_json || "");
  return h("div", { class: "content-evidence-packet" },
    h("div", { class: "alert-box ok" },
      h("strong", {}, "Package-local JSON evidence. "),
      "The API verified this artifact against the manifest reference before returning it."),
    h("div", { class: "runtime-grid content-quality-metrics" },
      metric("Package", result.kind || "unknown"),
      metric("Version", result.packageVersion || result.package_version || "missing"),
      metric("Bytes", String(result.bytes || 0)),
      metric("Manifest hash", shortHash(result.manifestSha256 || result.manifest_sha256 || ""))),
    h("dl", { class: "kv" },
      h("dt", {}, "Evidence type"), h("dd", {}, ref.type || "unknown"),
      h("dt", {}, "Artifact"), h("dd", {}, h("code", {}, ref.artifact || "missing")),
      h("dt", {}, "SHA-256"), h("dd", {}, h("code", {}, ref.sha256 || "missing")),
      h("dt", {}, "Generated"), h("dd", {}, ref.generatedAt || ref.generated_at || "not declared")),
    contentEvidenceSummaryPanel(summary),
    h("pre", { class: "system-evidence-report content-evidence-report" }, prettyEvidenceJson(result.contentJson || result.content_json || "")));
}

function contentEvidenceSummaryPanel(summary = {}) {
  const rows = (summary.samples || []).slice(0, 8).map((sample) => h("tr", { dataset: { intelEvidenceSample: sample.id || sample.expectedApp || "sample" } },
    labeledCell("Expected", {}, sample.expectedApp || "missing"),
    labeledCell("Observed", {}, sample.observedApp || "missing"),
    labeledCell("PCAP hash", {}, h("code", {}, sample.pcapSha256 ? shortHash(sample.pcapSha256) : "missing")),
    labeledCell("Verdict", {}, pill(sample.verdict || "missing", sample.verdict === "passed" ? "ok" : "bad", true))));
  const sampleRows = summary.samples?.length ? h("div", { class: "table-wrap" },
    responsiveTable(["Expected", "Observed", "PCAP hash", "Verdict"], rows, { className: "content-evidence-samples" })) :
    h("div", { class: "note" }, "No per-sample corpus rows were declared in this evidence artifact.");
  return h("div", { class: "profile-strip content-evidence-summary", dataset: { contentEvidenceSummary: summary.type || "evidence" } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Evidence artifact summary"),
      h("span", {}, summary.status || "unknown status")),
    h("div", { class: "runtime-grid content-quality-metrics" },
      metric("Evidence type", contentEvidenceTypeTitle(summary.type || "unknown")),
      metric("Package version", summary.packageVersion || "not declared"),
      metric("Sample count", String(summary.sampleCount || 0)),
      metric("Failed samples", String(summary.failedSamples || 0))),
    sampleRows);
}

function summarizeContentEvidence(value = "") {
  const corpus = contentRegressionCorpusModel(value);
  if (corpus.sampleCount) {
    return {
      type: corpus.type,
      status: corpus.status,
      packageVersion: corpus.packageVersion,
      sampleCount: corpus.sampleCount,
      failedSamples: corpus.failedSamples,
      samples: corpus.rows.map((sample) => ({
        pcapSha256: sample.pcapSha256,
        expectedApp: sample.expectedApp || sample.expected,
        observedApp: sample.observedApp || sample.observed,
        verdict: sample.verdict,
      })),
    };
  }
  let parsed = null;
  try {
    parsed = JSON.parse(String(value || "{}"));
  } catch {
    parsed = {};
  }
  const samples = Array.isArray(parsed.samples) ? parsed.samples : Array.isArray(parsed.Samples) ? parsed.Samples : [];
  const normalized = samples.map((sample = {}) => ({
    pcapSha256: sample.pcap_sha256 || sample.pcapSha256 || sample.PcapSha256 || "",
    expectedApp: sample.expected_app || sample.expectedApp || sample.ExpectedApp || "",
    observedApp: sample.observed_app || sample.observedApp || sample.ObservedApp || "",
    verdict: String(sample.verdict || sample.status || sample.Verdict || sample.Status || "").toLowerCase(),
  }));
  return {
    type: parsed.evidence_type || parsed.type || parsed.EvidenceType || parsed.Type || "",
    status: parsed.verdict || parsed.status || parsed.Verdict || parsed.Status || "",
    packageVersion: parsed.package_version || parsed.packageVersion || parsed.PackageVersion || "",
    sampleCount: normalized.length,
    failedSamples: normalized.filter((sample) => sample.verdict && sample.verdict !== "passed").length,
    samples: normalized,
  };
}

export function contentRegressionCorpusAPIModel(result = {}, fallbackType = "") {
  const rows = (Array.isArray(result.samples) ? result.samples : []).map((sample = {}, idx) => ({
    id: String(sample.id || sample.sampleId || `sample-${idx + 1}`),
    pcapSha256: sample.pcapSha256 || sample.pcap_sha256 || "",
    expectedApp: sample.expectedApp || sample.expected_app || "",
    observedApp: sample.observedApp || sample.observed_app || "",
    signatureId: String(sample.signatureId || sample.signature_id || ""),
    expected: sample.expected || sample.expectedApp || sample.expected_app || (sample.signatureId || sample.signature_id ? `SID ${sample.signatureId || sample.signature_id}` : ""),
    observed: sample.observed || sample.observedApp || sample.observed_app || "",
    verdict: String(sample.verdict || "").toLowerCase(),
    detail: sample.detail || "",
  }));
  const failedSamples = typeof result.failedSamples === "number" ? result.failedSamples : rows.filter((sample) => sample.verdict && sample.verdict !== "passed").length;
  return {
    type: result.evidenceType || result.evidence_type || fallbackType || result.evidence?.type || "",
    status: result.status || "",
    packageVersion: result.packageVersion || result.package_version || "",
    sampleCount: typeof result.sampleCount === "number" ? result.sampleCount : rows.length,
    failedSamples,
    verdicts: Array.isArray(result.verdicts) ? result.verdicts : [...new Set(rows.map((sample) => sample.verdict).filter(Boolean))].sort(),
    rows,
    summary: result.summary || (rows.length
      ? `${rows.length} sample${rows.length === 1 ? "" : "s"} loaded; ${failedSamples} failing sample${failedSamples === 1 ? "" : "s"} reported.`
      : "No sample rows were declared in this evidence artifact."),
  };
}

export function contentRegressionCorpusModel(value = "", fallbackType = "") {
  let parsed = null;
  try {
    parsed = JSON.parse(String(value || "{}"));
  } catch {
    parsed = {};
  }
  const rawSamples = Array.isArray(parsed.samples) ? parsed.samples
    : Array.isArray(parsed.Samples) ? parsed.Samples
      : Array.isArray(parsed.corpus) ? parsed.corpus
        : Array.isArray(parsed.rows) ? parsed.rows
          : [];
  const rows = rawSamples.map((sample = {}, idx) => {
    const signatureId = sample.signature_id || sample.signatureId || sample.sid || sample.SID || "";
    const expectedApp = sample.expected_app || sample.expectedApp || sample.ExpectedApp || "";
    const observedApp = sample.observed_app || sample.observedApp || sample.ObservedApp || "";
    const expectedVerdict = sample.expected_verdict || sample.expectedVerdict || sample.expected || sample.Expected || "";
    const observedVerdict = sample.observed_verdict || sample.observedVerdict || sample.observed || sample.Observed || "";
    const expected = expectedApp || (signatureId ? `SID ${signatureId}` : expectedVerdict);
    const observed = observedApp || observedVerdict || sample.result || sample.Result || "";
    return {
      id: String(sample.id || sample.name || sample.sample_id || sample.sampleId || `sample-${idx + 1}`),
      pcapSha256: sample.pcap_sha256 || sample.pcapSha256 || sample.PcapSha256 || "",
      expectedApp,
      observedApp,
      signatureId: String(signatureId || ""),
      expected,
      observed,
      verdict: String(sample.verdict || sample.status || sample.Verdict || sample.Status || "").toLowerCase(),
      detail: sample.detail || sample.reason || "",
    };
  });
  const failedSamples = rows.filter((sample) => sample.verdict && sample.verdict !== "passed").length;
  const type = parsed.evidence_type || parsed.type || parsed.EvidenceType || parsed.Type || fallbackType || "";
  return {
    type,
    status: parsed.verdict || parsed.status || parsed.Verdict || parsed.Status || "",
    packageVersion: parsed.package_version || parsed.packageVersion || parsed.PackageVersion || "",
    sampleCount: rows.length,
    failedSamples,
    verdicts: [...new Set(rows.map((sample) => sample.verdict).filter(Boolean))].sort(),
    rows,
    summary: rows.length
      ? `${rows.length} sample${rows.length === 1 ? "" : "s"} loaded; ${failedSamples} failing sample${failedSamples === 1 ? "" : "s"} reported.`
      : "No sample rows were declared in this evidence artifact.",
  };
}

function filterCorpusRows(rows = [], state = {}) {
  const q = String(state.q || "").trim().toLowerCase();
  const verdict = String(state.verdict || "").trim().toLowerCase();
  return rows.filter((row) => {
    if (verdict && row.verdict !== verdict) return false;
    if (!q) return true;
    return [row.id, row.expected, row.observed, row.pcapSha256, row.verdict, row.signatureId, row.detail]
      .some((value) => String(value || "").toLowerCase().includes(q));
  });
}

function isCorpusEvidenceType(type = "") {
  return /(?:regression-corpus|parser-tests|false-positive-regression)/.test(String(type || ""));
}

function contentEvidenceTypeTitle(type = "") {
  const titleOverrides = {
    "app-regression-corpus": "App Regression Corpus",
    "pcap-regression-corpus": "PCAP Regression Corpus",
    "false-positive-regression": "False-Positive Regression",
  };
  const normalized = String(type || "").trim().toLowerCase();
  if (titleOverrides[normalized]) return titleOverrides[normalized];
  return String(type || "evidence")
    .split(/[-_]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function prettyEvidenceJson(value = "") {
  const text = String(value || "");
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}

function shortHash(value = "") {
  const text = String(value || "");
  return text ? `sha256:${text.slice(0, 12)}` : "missing";
}

function openInstallPackageDrawer(surface, root, feeds, opts = {}) {
  if (opts.sync !== false) setIntelDrawerState(surface, "install");
  const guidance = contentPackageInstallGuidance(surface.kind);
  const source = h("input", {
    class: "input mono",
    placeholder: guidance.placeholder,
    autocomplete: "off",
    spellcheck: "false",
    title: `Server-local source directory for ${surface.name}`,
    "aria-label": `Server-local source directory for ${surface.name}`,
    dataset: { intelInstallSource: surface.kind },
  });
  const previewSlot = h("div", { class: "content-package-preview", dataset: { intelPackagePreview: surface.kind } });
  const previewButton = h("button", { class: "btn ghost", type: "button", title: `Preview ${surface.name} package source before install`, "aria-label": `Preview ${surface.name} package source before install`, dataset: { intelContentAction: "preview-install", intelContentSurface: surface.kind }, onclick: async (e) => {
    const path = source.value.trim();
    if (!path) { toast("Source path required", guidance.emptySourceMessage, "warn"); source.focus(); return; }
    const btn = e.target.closest("button");
    btn.disabled = true;
    setActionButtonLabel(btn, "search", 16, "Previewing...");
    previewSlot.replaceChildren(h("div", { class: "loading compact" }, "Verifying server-local package source..."));
    try {
      const result = await api.previewContentPackage(surface.kind, path);
      const previewSurface = previewContentPackageSurface(result, surface, feeds);
      const comparison = contentPackagePreviewComparison(surface, previewSurface);
      const corpusCompare = await api.compareContentPackage(surface.kind, path).catch(() => null);
      previewSlot.replaceChildren(
        h("div", { class: "alert-box " + (previewSurface.decision?.cls || previewSurface.cls || "info") },
          h("strong", {}, result.detail || "Package source preview complete. "),
          "No files were promoted and no lifecycle audit entry was written."),
        packagePreviewComparisonBody(comparison),
        contentPromotionDecisionPanel(previewSurface, { lifecycleAction: "install", previewComparison: comparison }),
        corpusCompare?.corpusDiff ? contentCorpusDiffBody(corpusCompare.corpusDiff) : null,
        packageReviewBody(previewSurface, "preview"));
    } catch (err) {
      previewSlot.replaceChildren(h("div", { class: "alert-box bad" },
        h("strong", {}, "Preview failed. "),
        err.message || "The package source could not be verified."));
    } finally {
      btn.disabled = false;
      setActionButtonLabel(btn, "search", 16, "Preview");
    }
  } }, h("span", { html: icon("search", 16) }), "Preview");
  openDrawer({
    title: `Install ${surface.name}`,
    subtitle: guidance.subtitle,
    width: "620px",
    onClose: clearIntelDrawerState,
    body: h("div", {},
      packageReviewBody(surface, "install"),
      h("label", { class: "field" },
        h("span", {}, guidance.label),
        source),
      h("div", { class: "note" }, guidance.detail),
      previewSlot,
      h("div", { class: "note" }, "Install is an audited content lifecycle action; policy feed enablement and custom feed edits still stage to the candidate and require commit.")),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: `Cancel ${surface.name} package install`, "aria-label": `Cancel ${surface.name} package install`, dataset: { intelContentAction: "cancel-install", intelContentSurface: surface.kind }, onclick: closeDrawer }, "Cancel"),
      previewButton,
      h("button", { class: "btn primary", type: "button", title: `Install ${surface.name} content package`, "aria-label": `Install ${surface.name} content package`, dataset: { intelContentAction: "confirm-install", intelContentSurface: surface.kind }, onclick: async (e) => {
        const path = source.value.trim();
        if (!path) { toast("Source path required", guidance.emptySourceMessage, "warn"); source.focus(); return; }
        const btn = e.target.closest("button");
        btn.disabled = true;
        setActionButtonLabel(btn, "terminal", 16, "Installing...");
        try {
          const result = await api.installContentPackage(surface.kind, path);
          closeDrawer();
          toast("Package installed", result.detail || `${surface.kind} content package installed.`, "ok");
          await refreshContentPackages(root, feeds);
        } catch (err) {
          btn.disabled = false;
          setActionButtonLabel(btn, "terminal", 16, "Install");
          toast("Install failed", err.message, "bad");
        }
      } }, h("span", { html: icon("terminal", 16) }), "Install"),
    ],
  });
  source.focus();
}

function contentCorpusDiffBody(diff = {}) {
  const rows = Array.isArray(diff.sampleDiffs) ? diff.sampleDiffs : Array.isArray(diff.sample_diffs) ? diff.sample_diffs : [];
  const failedDelta = diff.failedDelta ?? diff.failed_delta ?? 0;
  return h("div", { class: "content-package-comparison", dataset: { intelCorpusDiff: diff.kind || "package" } },
    h("div", { class: "alert-box " + (failedDelta > 0 ? "warn" : "info") },
      h("strong", {}, "Regression corpus diff. "),
      diff.summary || "Review sample-level changes between installed and preview package evidence."),
    h("div", { class: "runtime-grid content-quality-metrics" },
      metric("Evidence type", contentEvidenceTypeTitle(diff.evidenceType || diff.evidence_type || "corpus")),
      metric("Samples", `${diff.currentSampleCount ?? diff.current_sample_count ?? 0} -> ${diff.previewSampleCount ?? diff.preview_sample_count ?? 0}`),
      metric("Failed samples", `${diff.currentFailedSamples ?? diff.current_failed_samples ?? 0} -> ${diff.previewFailedSamples ?? diff.preview_failed_samples ?? 0}`),
      metric("Changed rows", String((diff.added || 0) + (diff.removed || 0) + (diff.changed || 0)))),
    rows.length ? h("div", { class: "table-wrap" },
      responsiveTable(["Change", "Sample", "Current", "Preview"], rows.slice(0, 12).map((row) => h("tr", { dataset: { intelCorpusDiffSample: row.id || "sample" } },
        labeledCell("Change", {}, pill(row.change || "changed", row.change === "added" ? "ok" : row.change === "removed" ? "bad" : "warn", true)),
        labeledCell("Sample", {}, row.id || "sample"),
        labeledCell("Current", {}, corpusDiffSampleLabel(row.current)),
        labeledCell("Preview", {}, corpusDiffSampleLabel(row.preview)))),
      { className: "content-corpus-diff-samples" })) :
      h("div", { class: "note" }, "No sample-level corpus changes were reported."));
}

function corpusDiffSampleLabel(sample = {}) {
  if (!sample) return "missing";
  const expected = sample.expected || sample.expectedApp || sample.expected_app || "";
  const observed = sample.observed || sample.observedApp || sample.observed_app || "";
  const verdict = sample.verdict || "";
  const label = [expected, observed].filter(Boolean).join(" -> ");
  return label ? `${label}${verdict ? ` (${verdict})` : ""}` : (verdict || "missing");
}

function previewContentPackageSurface(result = {}, fallback = {}, feeds = []) {
  const pkg = result.package || result.pkg || {};
  const surfaces = buildContentPosture(feeds || [], session.draft || {}, [pkg]).surfaces || [];
  return surfaces.find((item) => item.kind === (pkg.kind || fallback.kind)) || {
    ...fallback,
    ...pkg,
    decision: contentPackageDecisionPath(pkg),
  };
}

function packagePreviewComparisonBody(comparison = {}) {
  return h("div", { class: "content-package-comparison", dataset: { intelPackageComparison: comparison.kind || "package" } },
    h("div", { class: "alert-box " + (comparison.cls || "info") },
      h("strong", {}, (comparison.title || "Preview comparison") + " "),
      comparison.detail || "Review installed and preview package posture before install.",
      h("div", { class: "note", style: { marginTop: "6px" } }, comparison.nextAction || "Review previewed package gates before install.")),
    h("div", { class: "package-compare-labels" },
      h("div", {}, h("span", {}, "Installed"), h("strong", {}, comparison.currentLabel || "not installed")),
      h("div", {}, h("span", {}, "Preview"), h("strong", {}, comparison.previewLabel || "missing"))),
    h("div", { class: "package-compare-grid" }, (comparison.rows || []).map((row) => packagePreviewComparisonRow(row))));
}

function packagePreviewComparisonRow(row = {}) {
  return h("div", { class: "package-compare-row " + (row.cls || "neutral"), dataset: { contentPackageCompareField: row.key || "" } },
    h("div", {}, h("strong", {}, row.label || "Field"), row.changed ? pill("changed", row.cls || "info", true) : pill("same", "neutral", true)),
    h("div", { class: "package-compare-values" },
      h("span", {}, row.current || "missing"),
      h("span", { html: icon("arrowRight", 14), "aria-hidden": "true" }),
      h("span", {}, row.preview || "missing")));
}

function openRollbackPackageDrawer(surface, root, feeds, opts = {}) {
  if (opts.sync !== false) setIntelDrawerState(surface, "rollback");
  const ack = h("input", { type: "checkbox", title: `Acknowledge rollback of ${surface.name}`, "aria-label": `Acknowledge rollback of ${surface.name}`, dataset: { intelRollbackAck: surface.kind } });
  const rollbackBtn = h("button", { class: "btn danger", type: "button", title: `Rollback ${surface.name} to the latest verified backup`, "aria-label": `Rollback ${surface.name} to the latest verified backup`, dataset: { intelContentAction: "confirm-rollback", intelContentSurface: surface.kind }, disabled: true, onclick: async (e) => {
    if (!surface.rollbackAvailable) return;
    const btn = e.target.closest("button");
    btn.disabled = true;
    setActionButtonLabel(btn, "rollback", 16, "Rolling back...");
    try {
      const result = await api.rollbackContentPackage(surface.kind);
      closeDrawer();
      toast("Package rolled back", result.detail || `${surface.kind} content package restored.`, "ok");
      await refreshContentPackages(root, feeds);
    } catch (err) {
      btn.disabled = false;
      setActionButtonLabel(btn, "rollback", 16, "Rollback");
      toast("Rollback failed", err.message, "bad");
    }
  } }, h("span", { html: icon("rollback", 16) }), "Rollback");
  ack.disabled = !surface.rollbackAvailable;
  ack.addEventListener("change", () => { rollbackBtn.disabled = !surface.rollbackAvailable || !ack.checked; });
  openDrawer({
    title: `Rollback ${surface.name}`,
    subtitle: "Restores the latest verified backup and audits the content lifecycle action.",
    width: "660px",
    onClose: clearIntelDrawerState,
    body: h("div", {},
      packageReviewBody(surface, "rollback"),
      !surface.rollbackAvailable ? h("div", { class: "alert-box warn" },
        h("strong", {}, "Rollback unavailable. "),
        "The API has not reported a verified backup for this package kind.") : null,
      h("label", { class: "field", style: { marginTop: "14px" } },
        h("span", {}, "Acknowledgement"),
        h("div", { class: "flex", style: { alignItems: "center" } },
          ack,
          h("span", {}, "I understand rollback replaces active content and is separate from policy candidate rollback.")))),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: `Cancel ${surface.name} rollback`, "aria-label": `Cancel ${surface.name} rollback`, dataset: { intelContentAction: "cancel-rollback", intelContentSurface: surface.kind }, onclick: closeDrawer }, "Cancel"),
      rollbackBtn,
    ],
  });
}

async function refreshContentPackages(root, feeds) {
  const contentR = await api.contentPackages().catch((e) => ({ packages: [], error: e.message }));
  paint(root, feeds, contentR.packages || [], contentR.error || "");
}

function handoffActions(packet) {
  return h("div", { class: "flex wrap", style: { marginTop: "16px" } },
    h("button", { class: "btn", type: "button", title: "Open API and CLI context for this content package workflow", "aria-label": "Open API and CLI context for this content package workflow", dataset: { intelContentAction: "api-cli" }, onclick: () => openAutomationContext(currentRoute()) }, h("span", { html: icon("terminal", 16) }), "API / CLI"),
    h("button", { class: "btn", type: "button", title: "Pin this content package handoff to the investigation case", "aria-label": "Pin this content package handoff to the investigation case", dataset: { intelContentAction: "pin-handoff" }, onclick: () => pinHandoff(packet) }, h("span", { html: icon("inbox", 16) }), "Pin to case"),
    h("button", { class: "btn", type: "button", title: "Copy this content package handoff as text", "aria-label": "Copy this content package handoff as text", dataset: { intelContentAction: "copy-handoff" }, onclick: () => copyHandoff(packet) }, h("span", { html: icon("copy", 16) }), "Copy handoff"),
    h("button", { class: "btn", type: "button", title: "Export this content package handoff as JSON", "aria-label": "Export this content package handoff as JSON", dataset: { intelContentAction: "export-handoff" }, onclick: () => exportHandoff(packet) }, h("span", { html: icon("download", 16) }), "Export JSON"),
    h("a", { class: "btn ghost", href: activeInvestigationServerCaseHref(), title: "Open active investigation case", "aria-label": "Open active investigation case", dataset: { intelContentAction: "open-active-case" } }, h("span", { html: icon("search", 16) }), "Open active case"));
}

async function pinHandoff(packet) {
  try {
    const serverResult = await appendInvestigationPacketToActiveServerCase(packet, {
      appendEvidence: (id, evidence) => api.addInvestigationCaseEvidence(id, evidence),
    });
    if (serverResult.appended) {
      toast("Evidence appended", `Content package evidence appended to ${serverResult.activeCaseId}.`, "ok");
      return;
    }
  } catch (e) {
    try {
      const result = pinInvestigationPacket(packet);
      toast("Server append unavailable", `${result.toastDetail} Local fallback was used.`, "warn");
    } catch (fallbackError) {
      toast("Pin failed", fallbackError.message || "Selected content package evidence could not be pinned.", "bad");
    }
    return;
  }
  try {
    const result = pinInvestigationPacket(packet);
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Selected content package evidence could not be pinned.", "bad");
  }
}

async function copyHandoff(packet) {
  try {
    await navigator.clipboard.writeText(investigationPacketText(packet));
    toast("Handoff copied", "Selected content package evidence copied as plain text.", "ok");
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
  URL.revokeObjectURL(url);
  toast("Handoff exported", "Downloaded selected content package evidence as JSON.", "ok");
}

function currentRoute() {
  if (typeof location === "undefined") return "#/intel";
  return location.hash || "#/intel";
}

function setActionButtonLabel(button, iconName, size, label) {
  button.replaceChildren(h("span", { html: icon(iconName, size) }), label);
}

function metric(label, value) {
  return h("div", { class: "posture-metric" }, h("span", {}, label), h("strong", {}, value));
}

function refreshIntervalControl(root, feeds, contentPackages, contentError) {
  const input = h("input", { class: "input intel-refresh-interval-input", type: "number", min: "5", placeholder: "60", value: session.draft.intel?.refreshIntervalMinutes || "", title: "Threat-intelligence feed refresh interval in minutes", "aria-label": "Threat-intelligence feed refresh interval in minutes", dataset: { intelField: "refresh-interval" } });
  return h("div", { class: "field intel-refresh-interval-field" },
    h("span", {}, "Refresh interval ", h("span", { class: "help" }, "— minutes; blank uses default")),
    h("div", { class: "flex" }, input,
      h("button", { class: "btn", type: "button", title: "Stage threat-intelligence feed refresh interval", "aria-label": "Stage threat-intelligence feed refresh interval", dataset: { intelAction: "stage-refresh-interval" }, onclick: async () => {
        const value = parseInt(input.value, 10);
        if (input.value.trim() && (!Number.isFinite(value) || value < 5)) return toast("Invalid interval", "Use 5 minutes or more, or leave it blank.", "warn");
        try {
          await session.apply((d) => {
            d.intel ||= {};
            if (input.value.trim()) d.intel.refreshIntervalMinutes = value;
            else delete d.intel.refreshIntervalMinutes;
          });
          paint(root, feeds, contentPackages, contentError);
          toast("Interval staged", "Commit to apply the feed refresh schedule.", "ok");
        } catch (e) { toast("Failed", e.message, "bad"); }
      } }, "Stage")));
}

function customFeedsCard(root, feeds, contentPackages, contentError) {
  const custom = customFeeds(session.draft);
  const head = h("div", { class: "card-head" },
    h("h2", {}, "Custom feeds"),
    h("span", { class: "spacer" }),
    h("button", { class: "btn sm primary", type: "button", title: "Add custom threat-intelligence feed", "aria-label": "Add custom threat-intelligence feed", dataset: { intelAction: "add-custom-feed" }, onclick: () => openCustomFeedEditor(root, feeds, contentPackages, contentError, null) }, h("span", { html: icon("plus", 14) }), "Add"));
  if (!custom.length) {
    return card(head,
      emptyState("intel", "No custom feeds", "Add HTTP(S) blocklists with one IP or CIDR per line. Custom feed license compliance is operator-owned.",
        h("button", { class: "btn primary", type: "button", title: "Add custom threat-intelligence feed", "aria-label": "Add custom threat-intelligence feed", dataset: { intelAction: "add-custom-feed" }, onclick: () => openCustomFeedEditor(root, feeds, contentPackages, contentError, null) }, h("span", { html: icon("plus", 16) }), "Add custom feed")));
  }
  const rows = custom.map((f, index) => h("tr", { dataset: { intelCustomFeed: f.name || String(index) } },
    labeledCell("Name", {}, h("strong", {}, f.name || "unnamed")),
    labeledCell("URL", { class: "mono data-clip", title: f.url || "" }, f.url || "—"),
    labeledCell("Description", { class: "muted" }, f.description || "—"),
    labeledCell("Actions", { class: "cell-actions" },
      h("div", { class: "flex row-actions" },
        h("button", { class: "btn sm ghost", type: "button", title: `Edit custom feed ${f.name || "unnamed"}`, "aria-label": `Edit custom feed ${f.name || "unnamed"}`, dataset: { intelAction: "edit-custom-feed", intelCustomFeedAction: f.name || String(index) }, onclick: () => openCustomFeedEditor(root, feeds, contentPackages, contentError, index) }, h("span", { html: icon("edit", 14) }), "Edit"),
        h("button", { class: "btn sm danger", type: "button", title: `Delete custom feed ${f.name || "unnamed"}`, "aria-label": `Delete custom feed ${f.name || "unnamed"}`, dataset: { intelAction: "delete-custom-feed", intelCustomFeedAction: f.name || String(index) }, onclick: () => deleteCustomFeed(root, feeds, contentPackages, contentError, index) }, h("span", { html: icon("trash", 14) }), "Delete")))));
  const table = responsiveTable(["Name", "URL", "Description", { label: "Actions", attrs: { class: "actions-col" } }], rows, { className: "intel-custom-feed-table" });
  return card(head, h("div", { class: "table-wrap flat" }, table));
}

function openCustomFeedEditor(root, feeds, contentPackages, contentError, index) {
  const editing = index != null;
  const existing = editing ? customFeeds(session.draft)[index] || {} : {};
  const name = h("input", { class: "input", value: existing.name || "", placeholder: "abuse-feed", title: "Custom feed name", "aria-label": "Custom feed name", dataset: { intelCustomField: "name" } });
  const url = h("input", { class: "input", value: existing.url || "", placeholder: "https://example.com/blocklist.txt", title: "Custom feed URL", "aria-label": "Custom feed URL", dataset: { intelCustomField: "url" } });
  const description = h("textarea", { class: "input", placeholder: "Purpose, owner, or license note", title: "Custom feed description", "aria-label": "Custom feed description", dataset: { intelCustomField: "description" } }, existing.description || "");
  openDrawer({
    title: editing ? "Edit custom feed" : "Add custom feed",
    subtitle: "Stages to the candidate. Feed contents are fetched when threat intel is refreshed.",
    width: "560px",
    body: h("div", {},
      h("label", { class: "field" }, h("span", {}, "Name"), name),
      h("label", { class: "field" }, h("span", {}, "URL"), url),
      h("label", { class: "field" }, h("span", {}, "Description"), description),
      h("div", { class: "note" }, "Use lowercase names. Feed URLs must be HTTP(S), serve one IP or CIDR per line, avoid URL credentials or secret query keys, and avoid obvious local/private/metadata destinations.")),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: editing ? "Cancel custom feed edit" : "Cancel custom feed add", "aria-label": editing ? "Cancel custom feed edit" : "Cancel custom feed add", dataset: { intelAction: "cancel-custom-feed" }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: editing ? "Save custom feed changes" : "Add custom feed to candidate", "aria-label": editing ? "Save custom feed changes" : "Add custom feed to candidate", dataset: { intelAction: "save-custom-feed" }, onclick: async () => {
        const result = normalizeCustomFeed({ name: name.value, url: url.value, description: description.value }, feeds, customFeeds(session.draft), index);
        if (result.error) return toast("Invalid feed", result.error, "warn");
        try {
          await session.apply((d) => upsertCustomFeed(d, result.feed, index));
          closeDrawer();
          paint(root, feeds, contentPackages, contentError);
          toast(editing ? "Custom feed saved" : "Custom feed added", "Staged to candidate. Commit and refresh to enforce.", "ok");
        } catch (e) { toast("Failed", e.message, "bad"); }
      } }, editing ? "Save feed" : "Add feed"),
    ],
  });
}

async function deleteCustomFeed(root, feeds, contentPackages, contentError, index) {
  const feed = customFeeds(session.draft)[index];
  if (!feed) return;
  if (!(await confirmDialog({ title: "Delete custom feed?", message: `Remove "${feed.name || "this feed"}" from the candidate? Commit and refresh to remove its entries from enforcement sets.`, confirmLabel: "Delete", danger: true }))) return;
  try {
    await session.apply((d) => removeCustomFeed(d, index));
    paint(root, feeds, contentPackages, contentError);
    toast("Custom feed deleted", "Staged to candidate.", "ok");
  } catch (e) { toast("Failed", e.message, "bad"); }
}

function toggleCommercial(on, root, feeds, contentPackages, contentError) {
  const input = h("input", { type: "checkbox", title: "Declare commercial use for threat-intelligence feed governance", "aria-label": "Declare commercial use for threat-intelligence feed governance", dataset: { intelField: "commercial-use" }, onchange: async (e) => {
    try { await session.apply((d) => { (d.intel ||= {}).commercialUse = e.target.checked; }); paint(root, feeds, contentPackages, contentError); toast("Updated", "Staged to candidate — commit to apply.", "ok"); }
    catch (err) { toast("Failed", err.message, "bad"); e.target.checked = on; }
  } });
  input.checked = on;
  return h("label", { class: "switch" }, input, h("span", { class: "slider" }));
}

function renderTable(wrap, feeds, commercial, root, contentPackages, contentError) {
  clear(wrap);
  wrap.appendChild(responsiveTable(["On", "Feed", "License", "Commercial", "Kind", "Status"], feeds.map((f) => {
      const di = draftEnabled(f.name);
      const effective = di == null ? f.enabled : di;
      const pending = di != null && di !== f.enabled;
      const blocked = commercial && !f.allowsCommercialUse && !f.custom;
      return h("tr", { class: f.custom ? "" : "", dataset: { intelFeedRow: f.name || "" } },
        labeledCell("On", {}, f.custom ? h("span", { class: "muted", title: "Custom feeds are managed in the policy" }, "—") : feedToggle(f, effective, blocked, root, feeds, contentPackages, contentError)),
        labeledCell("Feed", {}, h("strong", {}, f.name), f.description ? h("div", { class: "note" }, f.description) : null,
          f.url ? h("div", { class: "note mono data-clip", title: f.url }, f.url) : null),
        labeledCell("License", {}, f.license || "—", f.attribution ? h("div", { class: "note" }, "Attribution required") : null),
        labeledCell("Commercial", {}, f.allowsCommercialUse ? pill("allowed", "ok") : pill("non-commercial", "warn")),
        labeledCell("Kind", {}, f.custom ? pill("custom", "violet") : pill("built-in", "neutral")),
        labeledCell("Status", {}, blocked ? pill("blocked by license", "bad") : pending ? pill(effective ? "enabling" : "disabling", "warn") : effective ? pill("enabled", "ok", true) : pill("disabled", "neutral")));
    }), { className: "intel-feed-registry-table" }));
}

function feedToggle(f, enabled, blocked, root, feeds, contentPackages, contentError) {
  const input = h("input", { type: "checkbox", disabled: blocked, title: blocked ? `Feed ${f.name} cannot be enabled for commercial use` : `Enable or disable feed ${f.name}`, "aria-label": blocked ? `Feed ${f.name} cannot be enabled for commercial use` : `Enable or disable feed ${f.name}`, dataset: { intelFeedToggle: f.name || "" }, onchange: async (e) => {
    try {
      await session.apply((d) => {
        d.intel ||= {}; d.intel.feeds ||= [];
        const fe = d.intel.feeds.find((x) => x.name === f.name);
        if (fe) fe.enabled = e.target.checked; else d.intel.feeds.push({ name: f.name, enabled: e.target.checked });
      });
      paint(root, feeds, contentPackages, contentError);
      toast("Staged", `Feed "${f.name}" ${e.target.checked ? "enabled" : "disabled"} — commit to apply.`, "ok");
    } catch (err) { toast("Failed", err.message, "bad"); e.target.checked = enabled; }
  } });
  input.checked = enabled;
  return h("label", { class: "switch", title: blocked ? "License forbids commercial use" : "" }, input, h("span", { class: "slider" }));
}

function loadErrorDetail(err, fallback) {
  return err?.message || String(err || fallback);
}
