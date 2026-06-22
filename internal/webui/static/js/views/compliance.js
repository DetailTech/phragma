// Compliance reports — retained operational report workbench. This view keeps
// server-side parity with ngfwctl compliance reports while making export and
// copy flows explicit for browser operators.

import { h, icon, clear } from "../core.js";
import { api } from "../api.js";
import { throwIfAccessDenied } from "../auth_gate.js";
import { activeInvestigationServerCaseHref, appendInvestigationPacketToActiveServerCase, pinInvestigationPacket } from "../investigation_case.js";
import { buildInvestigationPacket } from "../investigation_packet.js";
import { pageHead, card, emptyState, pill, labeledCell, responsiveTable, openDrawer, closeDrawer, toast } from "../ui.js";

export const COMPLIANCE_PROFILES = Object.freeze([
  ["", "All frameworks"],
  ["operational", "Operational"],
  ["change-control", "Change control"],
  ["privileged-access", "Privileged access"],
  ["content-lifecycle", "Content lifecycle"],
  ["incident-evidence", "Incident evidence"],
]);

export const COMPLIANCE_STATUSES = Object.freeze([
  ["", "All statuses"],
  ["unsigned", "Unsigned"],
  ["signed", "Signed"],
  ["server-stored", "Server stored"],
  ["retention-gap", "Retention gap"],
]);

const DEFAULT_CREATE = Object.freeze({
  profile: "operational",
  title: "",
  auditLimit: 300,
  versionLimit: 100,
  logLimit: 100,
  actor: "",
  action: "",
  version: "",
  since: "",
  until: "",
  query: "",
});

let routePath = "/compliance";
let routeState = normalizeComplianceRoute();
let currentModel = buildComplianceModel();

export async function render(ctx = {}) {
  routePath = ctx.path || "/compliance";
  routeState = normalizeComplianceRoute(ctx.query || {});
  const root = h("div", {});
  await loadComplianceWorkbench(root);
  return root;
}

async function loadComplianceWorkbench(root) {
  clear(root);
  root.appendChild(h("div", { class: "loading" }, "Loading compliance reports..."));
  const [reportR] = await Promise.allSettled([api.complianceReports({ limit: 100 })]);
  throwIfAccessDenied(reportR);
  currentModel = reportR.status === "fulfilled"
    ? buildComplianceModel(reportR.value || {}, routeState)
    : { ...buildComplianceModel({}, routeState), unavailable: true, error: loadErrorDetail(reportR.reason, "Compliance reports unavailable.") };
  clear(root);
  root.appendChild(complianceWorkbench(currentModel, root));
  if (routeState.report) {
    const report = currentModel.reports.find((item) => item.id === routeState.report);
    if (report) queueMicrotask(() => openReportDrawer(report));
  }
}

export function normalizeComplianceRoute(query = {}) {
  const profile = profileValue(query.profile || "");
  const status = statusValue(query.status || "");
  return {
    profile,
    status,
    search: cleanText(query.search || query.q || ""),
    report: cleanText(query.report || ""),
  };
}

export function buildComplianceModel(resp = {}, filters = {}) {
  const normalizedFilters = normalizeComplianceRoute(filters);
  const reports = (Array.isArray(resp.reports) ? resp.reports : []).map(normalizeReportSummary);
  const filtered = reports.filter((report) => reportMatchesFilters(report, normalizedFilters));
  const counts = {
    total: reports.length,
    visible: filtered.length,
    unsigned: reports.filter((report) => report.unsigned).length,
    signed: reports.filter((report) => report.signed).length,
    stored: reports.filter((report) => report.serverStored).length,
    retentionGaps: reports.filter((report) => !report.retentionEnforced).length,
  };
  return {
    schemaVersion: resp.schemaVersion || resp.schema_version || "phragma.compliance.report-api.v1",
    reports,
    filtered,
    filters: normalizedFilters,
    counts,
    caveats: complianceCaveats(counts),
  };
}

export function normalizeReportSummary(report = {}) {
  const profile = profileValue(report.profile || "operational") || "operational";
  const signed = Boolean(report.signed);
  const unsigned = report.unsigned !== undefined ? Boolean(report.unsigned) : !signed;
  const serverStored = report.serverStored ?? report.server_stored;
  const retentionEnforced = report.retentionEnforced ?? report.retention_enforced;
  return {
    id: cleanText(report.id),
    schemaVersion: cleanText(report.schemaVersion || report.schema_version),
    generatedAt: cleanText(report.generatedAt || report.generated_at),
    generatedBy: cleanText(report.generatedBy || report.generated_by),
    generatedByRole: cleanText(report.generatedByRole || report.generated_by_role),
    authSource: cleanText(report.authSource || report.auth_source),
    profile,
    profileLabel: cleanText(report.profileLabel || report.profile_label || profileLabel(profile)),
    title: cleanText(report.title || profileLabel(profile) + " compliance report"),
    source: cleanText(report.source || "server-retained"),
    unsigned,
    signed,
    serverStored: serverStored === undefined ? true : Boolean(serverStored),
    retentionEnforced: retentionEnforced === undefined ? false : Boolean(retentionEnforced),
    auditEntryCount: countValue(report.auditEntryCount ?? report.audit_entry_count),
    versionCount: countValue(report.versionCount ?? report.version_count),
    systemLogEntryCount: countValue(report.systemLogEntryCount ?? report.system_log_entry_count),
    entryHashes: Array.isArray(report.entryHashes) ? report.entryHashes : Array.isArray(report.entry_hashes) ? report.entry_hashes : [],
    latestAuditHash: cleanText(report.latestAuditHash || report.latest_audit_hash),
    filters: report.filters && typeof report.filters === "object" ? { ...report.filters } : {},
    payloadSha256: cleanText(report.payloadSha256 || report.payload_sha256),
    exportPath: cleanText(report.exportPath || report.export_path),
  };
}

export function complianceReportCreateRequest(values = {}) {
  const merged = { ...DEFAULT_CREATE, ...values };
  return {
    profile: profileValue(merged.profile) || DEFAULT_CREATE.profile,
    title: cleanText(merged.title),
    auditLimit: boundedInt(merged.auditLimit, 1, 1000, DEFAULT_CREATE.auditLimit),
    versionLimit: boundedInt(merged.versionLimit, 1, 250, DEFAULT_CREATE.versionLimit),
    logLimit: boundedInt(merged.logLimit, 0, 1000, DEFAULT_CREATE.logLimit),
    actor: cleanText(merged.actor),
    action: cleanText(merged.action),
    version: cleanText(merged.version),
    since: cleanText(merged.since),
    until: cleanText(merged.until),
    query: cleanText(merged.query),
  };
}

export function complianceReportContextText(report = {}) {
  const r = normalizeReportSummary(report);
  const id = r.id || "<report-id>";
  const lines = [
    "Phragma compliance report context",
    `id=${id}`,
    `title=${redactComplianceText(r.title) || "-"}`,
    `profile=${r.profile}`,
    `status=${r.signed ? "signed" : "unsigned"}`,
    `serverStored=${r.serverStored}`,
    `retentionEnforced=${r.retentionEnforced}`,
    `generatedAt=${r.generatedAt || "-"}`,
    `generatedBy=${redactComplianceText(r.generatedBy) || "-"}`,
    `counts=audit:${r.auditEntryCount} versions:${r.versionCount} systemLogs:${r.systemLogEntryCount}`,
    `payloadSha256=${r.payloadSha256 || "-"}`,
    "",
    "API",
    `GET /v1/compliance/reports/${encodeURIComponent(id)}`,
    `GET /v1/compliance/reports/${encodeURIComponent(id)}/export`,
    "",
    "CLI",
    `ngfwctl compliance reports get ${shellQuote(id)}`,
    `ngfwctl compliance reports export ${shellQuote(id)} --output ${shellQuote(id + ".json")}`,
    "",
    "Caveat",
    "Operational evidence only. This is not a signed custody artifact, legal-hold record, or proof of retention enforcement.",
  ];
  const filterLines = Object.entries(r.filters || {})
    .filter(([, value]) => cleanText(value))
    .map(([key, value]) => `filter.${key}=${redactComplianceText(value)}`);
  if (filterLines.length) lines.splice(10, 0, ...filterLines);
  return lines.join("\n") + "\n";
}

export function complianceReportHandoffPacket(report = {}, route = "") {
  const r = normalizeReportSummary(report);
  const context = complianceReportContextText(r);
  const reportRoute = route || (r.id ? `#/compliance?report=${encodeURIComponent(r.id)}` : "#/compliance");
  return buildInvestigationPacket({
    kind: "compliance-report",
    title: "Compliance report handoff",
    subject: {
      id: r.id || "compliance-report",
      label: r.title || "Compliance report",
    },
    summary: {
      profile: r.profile,
      profileLabel: r.profileLabel,
      signed: Boolean(r.signed),
      unsigned: Boolean(r.unsigned),
      serverStored: Boolean(r.serverStored),
      retentionEnforced: Boolean(r.retentionEnforced),
      auditEntryCount: r.auditEntryCount,
      versionCount: r.versionCount,
      systemLogEntryCount: r.systemLogEntryCount,
      payloadSha256: r.payloadSha256,
      exportPath: r.exportPath || (r.id ? `/v1/compliance/reports/${encodeURIComponent(r.id)}/export` : ""),
      boundary: "Server report metadata is retained; this WebUI handoff is unsigned operational context and is not legal-hold or proof of retention enforcement.",
    },
    evidence: [
      ...context.split("\n").filter(Boolean),
      "handoff_boundary=browser-local packet; retained evidence remains the server compliance report/export.",
    ],
    artifacts: {
      complianceReport: {
        id: r.id,
        schemaVersion: r.schemaVersion,
        generatedAt: r.generatedAt,
        profile: r.profile,
        profileLabel: r.profileLabel,
        title: r.title,
        source: r.source,
        unsigned: r.unsigned,
        signed: r.signed,
        serverStored: r.serverStored,
        retentionEnforced: r.retentionEnforced,
        auditEntryCount: r.auditEntryCount,
        versionCount: r.versionCount,
        systemLogEntryCount: r.systemLogEntryCount,
        latestAuditHash: r.latestAuditHash,
        payloadSha256: r.payloadSha256,
        exportPath: r.exportPath,
      },
    },
  }, {
    route: reportRoute,
    collectedAt: r.generatedAt,
    custody: {
      serverRetained: r.serverStored,
      retentionEnforced: r.retentionEnforced,
      packetSigned: false,
      retainedArtifact: r.id ? `/v1/compliance/reports/${encodeURIComponent(r.id)}/export` : "",
      retainedArtifactType: "compliance-report-export",
      boundary: "Server compliance report metadata/export may be retained; this WebUI packet is unsigned operational handoff context and is not legal-hold custody.",
      hardeningRequired: ["signed compliance reports", "retention/legal-hold policy", "export authorization review"],
    },
  });
}

export function redactComplianceText(value = "") {
  return String(value || "")
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[redacted-identity]")
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}\b/gi, "$1[redacted-token]")
    .replace(/\b(api[_-]?key|token|password|secret)=([^&\s]+)/gi, "$1=[redacted]")
    .replace(/\/(?:Users|home|var|private|etc)\/[^\s,;]+/g, "[redacted-path]");
}

export function exportFilenameForReport(report = {}) {
  const id = cleanText(report.id) || "compliance-report";
  return id.endsWith(".json") ? id : `${id}.json`;
}

function complianceWorkbench(model, root) {
  return h("div", { dataset: { complianceWorkspace: "true" } },
    pageHead("Compliance reports", "Create, inspect, copy, and export server-retained operational reports.",
      [
        model.unavailable ? h("button", { class: "btn", type: "button", title: "Retry loading compliance reports", "aria-label": "Retry loading compliance reports", dataset: { complianceAction: "retry-load" }, onclick: () => loadComplianceWorkbench(root) },
          h("span", { html: icon("refresh", 16) }), "Retry") : null,
        h("button", { class: "btn", type: "button", title: "Copy Compliance API and CLI context", "aria-label": "Copy Compliance API and CLI context", dataset: { complianceAction: "copy-workbench" }, onclick: () => copyWorkbenchContext(model) },
          h("span", { html: icon("copy", 16) }), "Copy context"),
        h("button", { class: "btn primary", type: "button", title: "Create retained compliance report", "aria-label": "Create retained compliance report", dataset: { complianceAction: "create" }, onclick: () => openCreateReportDrawer() },
          h("span", { html: icon("plus", 16) }), "Create report"),
      ]),
    model.unavailable ? complianceUnavailableBanner(model.error) : null,
    summaryBand(model),
    filterPanel(model),
    h("div", { class: "grid cols-2", style: { marginBottom: "16px" } },
      evidenceCaveatsCard(model),
      copyContextCard(model)),
    reportsCard(model));
}

function complianceUnavailableBanner(detail) {
  return h("div", { class: "alert-box bad", dataset: { complianceLoadError: "true" } },
    h("strong", {}, "Compliance report inventory unavailable. "),
    detail || "The retained report API did not return data.",
    h("div", { class: "note" }, "The route shell, create action, copy context, and filters remain available; report rows will appear after a successful retry."));
}

function summaryBand(model) {
  return h("div", { class: "runtime-grid", dataset: { complianceSummary: "true" } },
    metric("Reports", String(model.counts.total), `${model.counts.visible} visible`, "info"),
    metric("Unsigned", String(model.counts.unsigned), "signing remains hardening work", model.counts.unsigned ? "warn" : "ok"),
    metric("Server stored", String(model.counts.stored), "retained report metadata", "ok"),
    metric("Retention gaps", String(model.counts.retentionGaps), "not legal-hold evidence", model.counts.retentionGaps ? "warn" : "ok"));
}

function metric(label, value, detail, tone = "neutral") {
  return h("div", { class: "runtime-card " + tone },
    h("div", { class: "runtime-label" }, label),
    h("div", { class: "runtime-value" }, value),
    h("div", { class: "runtime-detail" }, detail));
}

function filterPanel(model) {
  const profile = selectControl("Framework", "profile", COMPLIANCE_PROFILES, model.filters.profile);
  const status = selectControl("Status", "status", COMPLIANCE_STATUSES, model.filters.status);
  const search = h("input", { class: "input", type: "search", value: model.filters.search, placeholder: "Search title, id, actor, hash", dataset: { complianceFilter: "search" } });
  const apply = () => updateRoute({
    profile: profile.input.value,
    status: status.input.value,
    search: search.value,
  });
  profile.input.onchange = apply;
  status.input.onchange = apply;
  search.onkeydown = (e) => { if (e.key === "Enter") apply(); };
  return card(h("h2", {}, "Report filters"),
    h("div", { class: "grid cols-3" },
      profile.el,
      status.el,
      h("label", { class: "field" }, h("span", {}, "Search"), search)),
    h("div", { class: "flex wrap", style: { marginTop: "10px" } },
      h("button", { class: "btn sm", type: "button", title: "Apply compliance report filters", "aria-label": "Apply compliance report filters", dataset: { complianceAction: "apply-filters" }, onclick: apply }, h("span", { html: icon("filter", 14) }), "Apply filters"),
      h("button", { class: "btn sm ghost", type: "button", title: "Clear compliance report filters", "aria-label": "Clear compliance report filters", dataset: { complianceAction: "clear-filters" }, onclick: () => updateRoute({ profile: "", status: "", search: "" }) }, "Clear filters")));
}

function evidenceCaveatsCard(model) {
  return card(h("h2", {}, "Evidence caveats"),
    h("div", { class: "warning-list" }, model.caveats.map((item) =>
      h("div", { class: "warning-row " + item.tone, dataset: { complianceCaveat: item.key } },
        h("div", {}, pill(item.label, item.tone, true)),
        h("div", {}, h("strong", {}, item.title), h("div", { class: "note" }, item.detail))))));
}

function copyContextCard(model) {
  const report = model.filtered[0] || model.reports[0] || {};
  return card(h("h2", {}, "API / CLI context"),
    h("div", { class: "note" }, "Copy snippets include REST and ngfwctl commands for the selected report flow. Actor and token-like values are redacted."),
    h("textarea", { class: "input", readonly: true, rows: 9, spellcheck: "false", dataset: { complianceCopyPreview: "true" } }, complianceReportContextText(report)),
    h("div", { class: "flex wrap", style: { marginTop: "10px" } },
      h("button", { class: "btn sm", type: "button", title: `Copy compliance report ${report.id || "context"} API and CLI context`, "aria-label": `Copy compliance report ${report.id || "context"} API and CLI context`, dataset: { complianceAction: "copy-first-report" }, onclick: () => copyReportContext(report) }, h("span", { html: icon("copy", 14) }), "Copy report context"),
      report.id ? h("button", { class: "btn sm ghost", type: "button", title: "Pin compliance report handoff to investigation case", "aria-label": `Pin compliance report ${report.id} to investigation case`, dataset: { complianceAction: "pin-first-report" }, onclick: () => pinReportHandoff(report) }, h("span", { html: icon("inbox", 14) }), "Pin to case") : null,
      h("a", { class: "btn sm ghost", href: activeInvestigationServerCaseHref(), title: "Open active investigation case", "aria-label": "Open active investigation case", dataset: { complianceAction: "open-active-case" } }, h("span", { html: icon("search", 14) }), "Open active case"),
      report.id ? h("button", { class: "btn sm ghost", type: "button", title: `Export compliance report ${report.id} JSON`, "aria-label": `Export compliance report ${report.id} JSON`, dataset: { complianceAction: "export-first-report" }, onclick: () => exportReport(report) }, h("span", { html: icon("download", 14) }), "Export report JSON") : null));
}

function reportsCard(model) {
  if (!model.filtered.length) {
    return card(h("h2", {}, "Retained reports"),
      emptyState("search", "No reports match", "Clear filters or create a new retained report from the current audit, version, and system-log state.",
        h("button", { class: "btn primary", type: "button", title: "Create retained compliance report", "aria-label": "Create retained compliance report", dataset: { complianceAction: "create-report-empty" }, onclick: () => openCreateReportDrawer() }, h("span", { html: icon("plus", 16) }), "Create report")));
  }
  const rows = model.filtered.map((report) => h("tr", { dataset: { complianceReportId: report.id } },
    labeledCell("Report", {}, h("strong", {}, report.title || report.id), h("div", { class: "note mono" }, report.id)),
    labeledCell("Framework", {}, pill(report.profileLabel, "info")),
    labeledCell("Status", {}, reportStatusPills(report)),
    labeledCell("Evidence", {}, `${report.auditEntryCount} audit / ${report.versionCount} versions / ${report.systemLogEntryCount} logs`),
    labeledCell("Generated", {}, h("span", { class: "mono" }, formatDate(report.generatedAt)), h("div", { class: "note" }, redactComplianceText(report.generatedBy) || "actor not reported")),
    labeledCell("Hash", { class: "mono" }, report.payloadSha256 ? `sha256:${report.payloadSha256.slice(0, 16)}` : "not reported"),
    labeledCell("Actions", { class: "cell-actions" },
      h("button", { class: "btn sm ghost", type: "button", title: "Inspect report summary", "aria-label": `Inspect ${report.id}`, dataset: { complianceAction: "inspect", complianceReportId: report.id }, onclick: () => openReportDrawer(report) }, h("span", { html: icon("search", 14) }), "Inspect"),
      h("button", { class: "btn sm ghost", type: "button", title: "Copy report API and CLI context", "aria-label": `Copy context for ${report.id}`, dataset: { complianceAction: "copy", complianceReportId: report.id }, onclick: () => copyReportContext(report) }, h("span", { html: icon("copy", 14) }), "Copy"),
      h("button", { class: "btn sm ghost", type: "button", title: "Pin compliance report handoff to investigation case", "aria-label": `Pin compliance report ${report.id} to investigation case`, dataset: { complianceAction: "pin", complianceReportId: report.id }, onclick: () => pinReportHandoff(report) }, h("span", { html: icon("inbox", 14) }), "Pin"),
      h("button", { class: "btn sm ghost", type: "button", title: "Export report JSON", "aria-label": `Export ${report.id}`, dataset: { complianceAction: "export", complianceReportId: report.id }, onclick: () => exportReport(report) }, h("span", { html: icon("download", 14) }), "Export"))));
  return card(h("h2", {}, "Retained reports"),
    h("div", { class: "table-wrap flat" },
      responsiveTable(["Report", "Framework", "Status", "Evidence", "Generated", "Hash", { label: "Actions", attrs: { class: "actions-col" } }], rows, { className: "compliance-report-table" })));
}

function reportStatusPills(report) {
  return [
    pill(report.signed ? "signed" : "unsigned", report.signed ? "ok" : "warn", true),
    report.serverStored ? pill("stored", "ok") : pill("not stored", "warn"),
    report.retentionEnforced ? pill("retention enforced", "ok") : pill("retention gap", "warn"),
  ];
}

async function openReportDrawer(report) {
  let detail = report;
  try {
    const resp = await api.complianceReport(report.id);
    detail = normalizeReportSummary(resp.report || report);
  } catch (e) {
    toast("Report detail unavailable", e.message || "Using list summary for this report.", "warn");
  }
  const context = complianceReportContextText(detail);
  openDrawer({
    title: detail.title || "Compliance report",
    subtitle: `${detail.profileLabel} · ${detail.id}`,
    width: "720px",
    body: h("div", {},
      h("div", { class: "profile-strip" },
        h("div", {}, h("strong", {}, detail.signed ? "Signed report metadata" : "Unsigned operational report"), h("span", {}, "Export is raw retained JSON from the server.")),
        h("div", {}, reportStatusPills(detail))),
      h("div", { class: "grid cols-3", style: { marginTop: "14px" } },
        metric("Audit entries", String(detail.auditEntryCount), "bounded by create request", "info"),
        metric("Versions", String(detail.versionCount), "policy history included", "info"),
        metric("System logs", String(detail.systemLogEntryCount), "local log evidence", "info")),
      h("div", { class: "kv-list", style: { marginTop: "14px" } },
        kv("Generated", formatDate(detail.generatedAt)),
        kv("Generated by", redactComplianceText(detail.generatedBy) || "-"),
        kv("Role", detail.generatedByRole || "-"),
        kv("Payload SHA-256", detail.payloadSha256 || "-"),
        kv("Latest audit hash", detail.latestAuditHash || "-"),
        kv("Export route", detail.exportPath || `/v1/compliance/reports/${encodeURIComponent(detail.id)}/export`)),
      filterSummary(detail),
      h("label", { class: "field", style: { marginTop: "14px" } }, h("span", {}, "Copyable context"), h("textarea", { class: "input", readonly: true, rows: 14, spellcheck: "false" }, context))),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close compliance report detail", "aria-label": "Close compliance report detail", dataset: { complianceAction: "close-report-detail" }, onclick: closeDrawer }, "Close"),
      h("button", { class: "btn", type: "button", title: `Copy compliance report ${detail.id || "detail"} API and CLI context`, "aria-label": `Copy compliance report ${detail.id || "detail"} API and CLI context`, dataset: { complianceAction: "copy-report-detail" }, onclick: () => copyReportContext(detail) }, h("span", { html: icon("copy", 16) }), "Copy context"),
      h("button", { class: "btn", type: "button", title: "Pin compliance report handoff to investigation case", "aria-label": "Pin compliance report handoff to investigation case", dataset: { complianceAction: "pin-report-detail" }, onclick: () => pinReportHandoff(detail) }, h("span", { html: icon("inbox", 16) }), "Pin to case"),
      h("a", { class: "btn ghost", href: activeInvestigationServerCaseHref(), title: "Open active investigation case", "aria-label": "Open active investigation case", dataset: { complianceAction: "open-active-case" } }, h("span", { html: icon("search", 16) }), "Open active case"),
      h("button", { class: "btn primary", type: "button", title: `Export compliance report ${detail.id || "detail"} JSON`, "aria-label": `Export compliance report ${detail.id || "detail"} JSON`, dataset: { complianceAction: "export-report-detail" }, onclick: () => exportReport(detail) }, h("span", { html: icon("download", 16) }), "Export JSON"),
    ],
    onClose: () => {
      if (routeState.report) updateRoute({ ...routeState, report: "" }, { replaceOnly: true });
    },
  });
}

function filterSummary(report) {
  const entries = Object.entries(report.filters || {}).filter(([, value]) => cleanText(value));
  if (!entries.length) return h("div", { class: "note", style: { marginTop: "14px" } }, "No report filters were recorded.");
  return h("div", { class: "profile-strip", style: { marginTop: "14px" } },
    h("div", {}, h("strong", {}, "Recorded filters"), h("span", {}, "Sensitive-looking filter values are redacted in copied context.")),
    h("div", { class: "tag-list" }, entries.map(([key, value]) => pill(`${key}: ${redactComplianceText(value)}`, "neutral"))));
}

function openCreateReportDrawer() {
  const controls = {};
  const body = h("div", {},
    h("div", { class: "alert-box warn" },
      h("strong", {}, "Unsigned report boundary"),
      h("div", { class: "note" }, "This creates a retained operational report only. It does not claim signed custody, legal hold, or retention enforcement.")),
    h("div", { class: "grid cols-2", style: { marginTop: "14px" } },
      createSelectField("Framework", "profile", COMPLIANCE_PROFILES.slice(1), DEFAULT_CREATE.profile, controls),
      createField("Title", "title", "CAB window report", DEFAULT_CREATE.title, controls),
      createField("Audit limit", "auditLimit", "300", DEFAULT_CREATE.auditLimit, controls, "number"),
      createField("Version limit", "versionLimit", "100", DEFAULT_CREATE.versionLimit, controls, "number"),
      createField("Log limit", "logLimit", "100", DEFAULT_CREATE.logLimit, controls, "number"),
      createField("Actor", "actor", "optional actor filter", DEFAULT_CREATE.actor, controls),
      createField("Action", "action", "optional audit action", DEFAULT_CREATE.action, controls),
      createField("Version", "version", "optional running version", DEFAULT_CREATE.version, controls),
      createField("Since", "since", "2026-06-22T00:00:00Z", DEFAULT_CREATE.since, controls),
      createField("Until", "until", "2026-06-22T23:59:59Z", DEFAULT_CREATE.until, controls)),
    createField("Query", "query", "optional audit detail search", DEFAULT_CREATE.query, controls));
  openDrawer({
    title: "Create compliance report",
    subtitle: "Generate and retain bounded audit, version, and system-log evidence.",
    width: "680px",
    body,
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Cancel compliance report creation", "aria-label": "Cancel compliance report creation", dataset: { complianceAction: "cancel-create" }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: "Create retained compliance report", "aria-label": "Create retained compliance report", dataset: { complianceAction: "submit-create" }, onclick: () => submitCreateReport(controls) }, h("span", { html: icon("check", 16) }), "Create"),
    ],
  });
}

async function submitCreateReport(controls) {
  const values = {};
  for (const [key, input] of Object.entries(controls)) values[key] = input.value;
  const req = complianceReportCreateRequest(values);
  try {
    const resp = await api.createComplianceReport(req);
    const report = normalizeReportSummary(resp.report || {});
    toast("Compliance report retained", `${report.id || "Report"} was stored as unsigned operational JSON.`, "ok");
    closeDrawer();
    updateRoute({ ...routeState, report: report.id || "" });
  } catch (e) {
    toast("Create failed", e.message || "The server could not retain the report.", "bad");
  }
}

async function copyWorkbenchContext(model) {
  const report = model.filtered[0] || model.reports[0] || {};
  await copyText(complianceReportContextText(report), "Compliance context copied", "API and CLI report context copied.");
}

async function copyReportContext(report) {
  await copyText(complianceReportContextText(report), "Report context copied", "API, CLI, and caveat context copied.");
}

async function pinReportHandoff(report) {
  const packet = complianceReportHandoffPacket(report);
  try {
    const serverResult = await appendInvestigationPacketToActiveServerCase(packet, {
      appendEvidence: (id, evidence) => api.addInvestigationCaseEvidence(id, evidence),
    });
    if (serverResult.appended) {
      toast("Evidence appended", `Compliance report handoff appended to ${serverResult.activeCaseId}.`, "ok");
      return;
    }
  } catch (e) {
    try {
      const result = pinInvestigationPacket(packet);
      toast("Server append unavailable", `${result.toastDetail} Local browser-only fallback was used.`, "warn");
    } catch (fallbackError) {
      toast("Pin failed", fallbackError.message || "Compliance report handoff could not be pinned.", "bad");
    }
    return;
  }
  try {
    const result = pinInvestigationPacket(packet);
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Compliance report handoff could not be pinned.", "bad");
  }
}

async function copyText(text, title, body) {
  try {
    if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(text);
    toast(title, body, "ok");
  } catch {
    toast("Copy failed", "Select the visible context text and copy it manually.", "warn");
  }
}

async function exportReport(report) {
  const id = cleanText(report.id);
  if (!id) {
    toast("Export unavailable", "The retained report summary does not include an id.", "warn");
    return;
  }
  try {
    const blob = await api.exportComplianceReport(id);
    downloadBlob(exportFilenameForReport(report), blob);
    toast("Compliance report exported", "Downloaded the retained unsigned report JSON.", "ok");
  } catch (e) {
    toast("Export failed", e.message || "The retained report could not be exported.", "bad");
  }
}

function downloadBlob(filename, blob) {
  const url = URL.createObjectURL(blob);
  const a = h("a", { href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function complianceCaveats(counts) {
  return [
    {
      key: "unsigned",
      label: counts.unsigned ? "review" : "clear",
      tone: counts.unsigned ? "warn" : "ok",
      title: "No signed custody claim",
      detail: counts.unsigned ? `${counts.unsigned} retained report(s) are unsigned operational evidence.` : "Visible reports do not advertise unsigned status.",
    },
    {
      key: "retention",
      label: counts.retentionGaps ? "gap" : "enforced",
      tone: counts.retentionGaps ? "warn" : "ok",
      title: "Retention is metadata only unless enforced",
      detail: counts.retentionGaps ? `${counts.retentionGaps} report(s) do not claim retention enforcement or legal hold.` : "Report metadata claims retention enforcement.",
    },
    {
      key: "scope",
      label: "bounded",
      tone: "info",
      title: "Evidence is bounded by create filters",
      detail: "Audit, version, and local system-log counts reflect the create request limits and filters.",
    },
  ];
}

function reportMatchesFilters(report, filters) {
  if (filters.profile && report.profile !== filters.profile) return false;
  if (filters.status === "unsigned" && !report.unsigned) return false;
  if (filters.status === "signed" && !report.signed) return false;
  if (filters.status === "server-stored" && !report.serverStored) return false;
  if (filters.status === "retention-gap" && report.retentionEnforced) return false;
  if (!filters.search) return true;
  const haystack = [
    report.id,
    report.title,
    report.profile,
    report.profileLabel,
    report.generatedBy,
    report.generatedByRole,
    report.payloadSha256,
    report.latestAuditHash,
    ...Object.values(report.filters || {}),
  ].join(" ").toLowerCase();
  return haystack.includes(filters.search.toLowerCase());
}

function selectControl(label, key, options, value) {
  const input = h("select", { class: "input", dataset: { complianceFilter: key } },
    options.map(([v, text]) => h("option", { value: v, selected: v === value }, text)));
  return { input, el: h("label", { class: "field" }, h("span", {}, label), input) };
}

function createField(label, key, placeholder, value, controls, type = "text") {
  const input = h("input", { class: "input", type, placeholder, value, dataset: { complianceCreateField: key } });
  controls[key] = input;
  return h("label", { class: "field" }, h("span", {}, label), input);
}

function createSelectField(label, key, options, value, controls) {
  const input = h("select", { class: "input", dataset: { complianceCreateField: key } },
    options.map(([v, text]) => h("option", { value: v, selected: v === value }, text)));
  controls[key] = input;
  return h("label", { class: "field" }, h("span", {}, label), input);
}

function kv(label, value) {
  return h("div", { class: "kv" }, h("span", {}, label), h("strong", {}, value || "-"));
}

function updateRoute(patch, opts = {}) {
  const next = normalizeComplianceRoute({ ...routeState, ...patch });
  const qs = new URLSearchParams();
  if (next.profile) qs.set("profile", next.profile);
  if (next.status) qs.set("status", next.status);
  if (next.search) qs.set("search", next.search);
  if (next.report) qs.set("report", next.report);
  const hash = "#" + routePath + (qs.toString() ? "?" + qs.toString() : "");
  if (opts.replaceOnly && globalThis.history?.replaceState) {
    history.replaceState(null, "", hash);
    routeState = next;
    return;
  }
  globalThis.location.hash = hash;
}

function profileValue(value = "") {
  const key = cleanText(value).toLowerCase();
  return COMPLIANCE_PROFILES.some(([profile]) => profile === key) ? key : "";
}

function statusValue(value = "") {
  const key = cleanText(value).toLowerCase();
  return COMPLIANCE_STATUSES.some(([status]) => status === key) ? key : "";
}

function profileLabel(profile = "") {
  return (COMPLIANCE_PROFILES.find(([value]) => value === profile)?.[1]) || "Operational";
}

function cleanText(value = "") {
  return String(value ?? "").trim();
}

function loadErrorDetail(err, fallback) {
  return err?.message || String(err || fallback);
}

function countValue(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

function boundedInt(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(n)));
}

function formatDate(value = "") {
  const text = cleanText(value);
  if (!text) return "-";
  const date = new Date(text);
  return Number.isNaN(date.getTime()) ? text : date.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, "Z");
}

function shellQuote(value = "") {
  const text = String(value);
  return /^[A-Za-z0-9._:/=-]+$/.test(text) ? text : "'" + text.replace(/'/g, "'\\''") + "'";
}
