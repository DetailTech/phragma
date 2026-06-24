// Changes — the compliance & change-management surface. Version history
// with diff and one-click rollback, and the full audit log of who did
// what. This is the documented change pipeline operators ask for.

import { h, icon, clear } from "../core.js";
import { api } from "../api.js";
import { cliCommand, openAutomationContext } from "../automation_context.js";
import { throwIfAccessDenied } from "../auth_gate.js";
import { candidateReviewModel, changesLifecycleGuidanceModel, governanceApprovalModel } from "../candidate_review.js";
import { commitRuntimePreflight } from "../commit_preflight.js";
import { normalizePolicyDiffLines, policyDiffLabels, renderDiffLines } from "../diff_view.js";
import { auditEntryHandoffPacket, auditLogHandoffPacket, buildInvestigationPacket, governanceApprovalHandoffPacket, investigationPacketFilename, investigationPacketJson, investigationPacketText } from "../investigation_packet.js";
import { pinInvestigationPacket } from "../investigation_case.js";
import { session, diffLines, changeImpact, normalizeServerImpact } from "../policy.js";
import { normalizeSnapshotDrawer, normalizeSnapshotId, parsePolicyImportText, policyExportEnvelope, policyExportFilename, replacePolicyDraft, snapshotRestoreReviewFilename, snapshotRestoreReviewHash, snapshotRestoreReviewJson, snapshotRestoreReviewPacket } from "../policy_io.js";
import { pageHead, emptyState, pill, card, toast, openDrawer, closeDrawer, confirmDialog, keyboardRowAttrs, labeledCell, responsiveTable } from "../ui.js";
import { renderValidationEvidence } from "../validation_view.js";
import * as fmt from "../format.js";
import { readQueryState, writeQueryState } from "../query_state.js";
import { evidenceToolbar } from "../evidence_toolbar.js";
import { savedFilterControls } from "../saved_filters.js";

let tab = "candidate";
let candidateDrawer = "";
let auditFilters = defaultAuditFilters();
let auditDrawer = "";
let versionRoute = defaultVersionRoute();
let snapshotRoute = defaultSnapshotRoute();
let preserveVersionDrawerRoute = false;
let preserveSnapshotDrawerRoute = false;
const AUDIT_QUERY_KEYS = Object.keys(defaultAuditFilters());
const AUDIT_SAVED_FILTER_KEYS = AUDIT_QUERY_KEYS.filter((key) => key !== "entry");
const CHANGES_QUERY_DEFAULTS = { tab: "candidate", ...defaultAuditFilters(), version: "", snapshot: "", drawer: "" };
const CHANGES_QUERY_KEYS = ["tab", ...AUDIT_QUERY_KEYS, "version", "snapshot", "drawer"];
const CHANGE_TABS = new Set(["candidate", "versions", "snapshots", "audit"]);
const CANDIDATE_DRAWERS = new Set(["governance-approval"]);
const VERSION_DRAWERS = new Set(["diff", "rollback"]);
const SNAPSHOT_DRAWERS = new Set(["validate", "restore-preview"]);
const AUDIT_DRAWERS = new Set(["report"]);
const AUDIT_REPORT_SCHEMA = "phragma.audit.report.v1";
const AUDIT_COMPLIANCE_PROFILES = Object.freeze([
  { value: "operational", label: "Operational" },
  { value: "change-control", label: "Change control" },
  { value: "privileged-access", label: "Privileged access" },
  { value: "content-lifecycle", label: "Content lifecycle" },
  { value: "incident-evidence", label: "Incident evidence" },
]);

export function versionRecoveryModel(v = {}, runningVersion = 0) {
  const id = Number(v.id || 0);
  const state = cleanVersionText(v.state || "unknown").toLowerCase() || "unknown";
  const action = cleanVersionText(v.action || "");
  const sourceVersion = Number(v.sourceVersion || v.source_version || 0);
  const artifactSetSha256 = cleanVersionText(v.artifactSetSha256 || v.artifact_set_sha256 || "");
  const createdAt = v.createdAt || v.created_at || "";
  const activatedAt = v.activatedAt || v.activated_at || "";
  const stateDetail = cleanVersionText(v.stateDetail || v.state_detail || "");
  const lastKnownGood = Boolean(v.lastKnownGood ?? v.last_known_good);
  const isRunning = id > 0 && id === Number(runningVersion || 0);
  const artifacts = Array.isArray(v.artifacts) ? v.artifacts.map(versionArtifactModel).filter(Boolean) : [];
  const recoveryLabel = versionRecoveryLabel({ state, lastKnownGood, isRunning, sourceVersion });
  return {
    id,
    action,
    sourceVersion,
    state,
    stateClass: versionStateClass(state),
    lastKnownGood,
    isRunning,
    artifactSetSha256,
    artifactLabel: artifactSetSha256 ? `sha256:${artifactSetSha256.slice(0, 12)}` : "no artifact hash",
    artifacts,
    createdAt,
    activatedAt,
    displayTime: activatedAt || createdAt,
    stateDetail,
    recoveryLabel,
  };
}

function versionArtifactModel(artifact = {}) {
  const engine = cleanVersionText(artifact.engine || "");
  const name = cleanVersionText(artifact.name || engine || "");
  const sha256 = cleanVersionText(artifact.sha256 || artifact.sha256Hash || "");
  const sizeBytes = Number(artifact.sizeBytes || artifact.size_bytes || 0);
  if (!engine && !name && !sha256 && !sizeBytes) return null;
  return { engine, name, sha256, sizeBytes };
}

function versionRecoveryLabel({ state, lastKnownGood, isRunning, sourceVersion } = {}) {
  if (state === "activation_failed") return "reconcile runtime and store";
  if (state === "apply_failed") return "running remains on LKG";
  if (state === "prepared") return "prepared, not active";
  if (lastKnownGood && isRunning) return "current last-known-good";
  if (lastKnownGood) return "last-known-good target";
  if (sourceVersion > 0) return `rollback from v${sourceVersion}`;
  if (state === "active") return "rollback target";
  return "metadata incomplete";
}

function versionStateClass(state = "") {
  if (state === "active") return "ok";
  if (state === "prepared") return "info";
  if (state.includes("fail")) return "bad";
  return "neutral";
}

function cleanVersionText(value) {
  return String(value || "").trim();
}

export function normalizeChangesTab(value = "") {
  return CHANGE_TABS.has(value) ? value : "candidate";
}

export function normalizeChangesRouteState(query = {}) {
  const state = readQueryState(query, CHANGES_QUERY_DEFAULTS, CHANGES_QUERY_KEYS);
  const routeTab = normalizeChangesTab(state.tab);
  if (routeTab === "audit") {
    return { tab: "audit", ...normalizeAuditFilters(state), drawer: normalizeAuditDrawer(state.drawer) };
  }
  if (routeTab === "versions") {
    const version = normalizeVersionRoute(state.version);
    return {
      ...defaultAuditFilters(),
      tab: "versions",
      version,
      drawer: version ? normalizeVersionDrawer(state.drawer) : "",
    };
  }
  if (routeTab === "snapshots") {
    const snapshot = normalizeSnapshotId(state.snapshot);
    return {
      ...defaultAuditFilters(),
      tab: "snapshots",
      version: "",
      snapshot,
      drawer: snapshot ? normalizeSnapshotRouteDrawer(state.drawer) : "",
    };
  }
  return { ...defaultAuditFilters(), tab: "candidate", drawer: normalizeCandidateDrawer(state.drawer) };
}

export const AUDIT_ACTION_OPTIONS = [
  ["", "Any action"],
  ["set-candidate", "set-candidate"],
  ["stage-threat-exception", "stage-threat-exception"],
  ["change-approval-create", "change-approval-create"],
  ["backup-snapshot-create", "backup-snapshot-create"],
  ["backup-snapshot-restore-stage", "backup-snapshot-restore-stage"],
  ["commit-intent", "commit-intent"],
  ["commit", "commit"],
  ["commit-failed", "commit-failed"],
  ["rollback-intent", "rollback-intent"],
  ["rollback", "rollback"],
  ["rollback-failed", "rollback-failed"],
  ["system-tune", "system-tune"],
  ["system-tune-failed", "system-tune-failed"],
  ["packet-capture", "packet-capture"],
  ["packet-capture-failed", "packet-capture-failed"],
  ["content-package-install-intent", "content-package-install-intent"],
  ["content-package-install", "content-package-install"],
  ["content-package-install-failed", "content-package-install-failed"],
  ["content-package-rollback-intent", "content-package-rollback-intent"],
  ["content-package-rollback", "content-package-rollback"],
  ["content-package-rollback-failed", "content-package-rollback-failed"],
  ["access-local-user-create-intent", "access-local-user-create-intent"],
  ["access-local-user-create", "access-local-user-create"],
  ["access-local-user-create-failed", "access-local-user-create-failed"],
  ["access-local-user-update-intent", "access-local-user-update-intent"],
  ["access-local-user-update", "access-local-user-update"],
  ["access-local-user-update-failed", "access-local-user-update-failed"],
  ["access-local-user-rotate-token-intent", "access-local-user-rotate-token-intent"],
  ["access-local-user-rotate-token", "access-local-user-rotate-token"],
  ["access-local-user-rotate-token-failed", "access-local-user-rotate-token-failed"],
  ["access-local-user-disable-intent", "access-local-user-disable-intent"],
  ["access-local-user-disable", "access-local-user-disable"],
  ["access-local-user-disable-failed", "access-local-user-disable-failed"],
  ["access-oidc-provider-set-intent", "access-oidc-provider-set-intent"],
  ["access-oidc-provider-set", "access-oidc-provider-set"],
  ["access-oidc-provider-set-failed", "access-oidc-provider-set-failed"],
  ["access-oidc-provider-disable-intent", "access-oidc-provider-disable-intent"],
  ["access-oidc-provider-disable", "access-oidc-provider-disable"],
  ["access-oidc-provider-disable-failed", "access-oidc-provider-disable-failed"],
  ["access-saml-provider-set-intent", "access-saml-provider-set-intent"],
  ["access-saml-provider-set", "access-saml-provider-set"],
  ["access-saml-provider-set-failed", "access-saml-provider-set-failed"],
  ["access-saml-provider-disable-intent", "access-saml-provider-disable-intent"],
  ["access-saml-provider-disable", "access-saml-provider-disable"],
  ["access-saml-provider-disable-failed", "access-saml-provider-disable-failed"],
  ["access-session-revoke-intent", "access-session-revoke-intent"],
  ["access-session-revoke", "access-session-revoke"],
  ["access-session-revoke-failed", "access-session-revoke-failed"],
];

const AUDIT_EVIDENCE_COLUMNS = [
  { key: "id", label: "Entry" },
  { key: "time", label: "Time" },
  { key: "action", label: "Action" },
  { key: "detail", label: "Detail" },
  { key: "actor", label: "Actor" },
  { key: "actorRole", label: "Actor role" },
  { key: "authSource", label: "Auth source" },
  { key: "version", label: "Version" },
  { key: "entryHash", label: "Entry hash" },
  { key: "previousHash", label: "Previous hash" },
];
const AUDIT_ACTION_VALUES = new Set(AUDIT_ACTION_OPTIONS.map(([value]) => value));
const AUDIT_LIMIT_VALUES = new Set(["100", "300", "500", "1000"]);

export async function render(ctx = {}) {
  const routePath = ctx.path || "/changes";
  const route = normalizeChangesRouteState(ctx.query || {});
  tab = route.tab;
  if (tab === "audit") {
    candidateDrawer = "";
    auditFilters = normalizeAuditFilters(route);
    auditDrawer = normalizeAuditDrawer(route.drawer);
    versionRoute = defaultVersionRoute();
    snapshotRoute = defaultSnapshotRoute();
  } else if (tab === "versions") {
    candidateDrawer = "";
    auditFilters = defaultAuditFilters();
    auditDrawer = "";
    versionRoute = { version: route.version, drawer: route.drawer };
    snapshotRoute = defaultSnapshotRoute();
  } else if (tab === "snapshots") {
    candidateDrawer = "";
    auditFilters = defaultAuditFilters();
    auditDrawer = "";
    versionRoute = defaultVersionRoute();
    snapshotRoute = { snapshot: route.snapshot, drawer: route.drawer };
  } else {
    candidateDrawer = normalizeCandidateDrawer(route.drawer);
    auditFilters = defaultAuditFilters();
    auditDrawer = "";
    versionRoute = defaultVersionRoute();
    snapshotRoute = defaultSnapshotRoute();
  }
  const root = h("div", {});
  const sessionR = await Promise.allSettled([session.load()]);
  throwIfAccessDenied(...sessionR);
  if (sessionR[0].status === "rejected") {
    paintChangesUnavailable(root, sessionR[0].reason, routePath);
    return root;
  }
  await paint(root);
  return root;
}

function paintChangesUnavailable(root, err, routePath = "/changes") {
  clear(root);
  root.appendChild(pageHead("Changes", "Version history, diffs, rollback, import/export, and the audit trail.",
    h("div", { class: "flex wrap" },
      h("button", { class: "btn", type: "button", title: "Retry loading candidate session", "aria-label": "Retry loading candidate session", dataset: { changesAction: "retry-load" }, onclick: () => renderAndReplaceChanges(root, routePath) },
        h("span", { html: icon("refresh", 16) }), "Retry"),
      h("button", { class: "btn", type: "button", title: "Open Changes API and CLI context", "aria-label": "Open Changes API and CLI context", dataset: { changesAction: "api-cli-context" }, onclick: () => openAutomationContext(routePath) },
        h("span", { html: icon("copy", 16) }), "API / CLI context"))));
  root.appendChild(changesTabBar(root, { unavailable: true, routePath }));
  root.appendChild(h("div", { class: "alert-box bad", dataset: { changesLoadError: "true" } },
    h("strong", {}, "Candidate session unavailable. "),
    loadErrorDetail(err, "The candidate or running policy API did not return session data."),
    h("div", { class: "note" }, "The route shell remains available. Retry after the API is reachable, or use API / CLI context for the equivalent candidate review commands.")));
}

async function renderAndReplaceChanges(root, routePath = "/changes") {
  const current = await render({ path: routePath, query: currentChangesQuery() });
  root.replaceChildren(...Array.from(current.childNodes));
}

async function paint(root) {
  clear(root);
  root.appendChild(pageHead("Changes", "Version history, diffs, rollback, import/export, and the audit trail.",
    h("div", { class: "flex wrap" },
      h("button", { class: "btn", type: "button", title: "Export the running policy as JSON", "aria-label": "Export the running policy as JSON", dataset: { changesAction: "export-running" }, onclick: () => exportRunningPolicy() }, h("span", { html: icon("download", 16) }), "Export running"),
      h("button", { class: "btn primary", type: "button", title: "Import JSON into the candidate policy", "aria-label": "Import JSON into the candidate policy", dataset: { changesAction: "import-candidate" }, onclick: () => openImportPolicy(root) }, h("span", { html: icon("upload", 16) }), "Import to candidate"))));
  root.appendChild(changesTabBar(root));
  const wrap = h("div", {});
  root.appendChild(wrap);
  if (tab === "candidate") await candidateReview(wrap, root);
  else if (tab === "versions") await versions(wrap, root);
  else if (tab === "snapshots") await snapshots(wrap, root);
  else await audit(wrap);
}

function changesTabBar(root, opts = {}) {
  const activate = (nextTab) => {
    tab = nextTab;
    syncChangesRoute();
    if (opts.unavailable) renderAndReplaceChanges(root, opts.routePath || "/changes");
    else paint(root);
  };
  return h("div", { class: "toolbar" }, h("div", { class: "seg" },
    h("button", { class: tab === "candidate" ? "active" : "", type: "button", title: "Open candidate changes", "aria-label": "Open candidate changes", dataset: { changesTab: "candidate" }, onclick: () => activate("candidate") }, "Candidate"),
    h("button", { class: tab === "versions" ? "active" : "", type: "button", title: "Open policy versions", "aria-label": "Open policy versions", dataset: { changesTab: "versions" }, onclick: () => activate("versions") }, "Versions"),
    h("button", { class: tab === "snapshots" ? "active" : "", type: "button", title: "Open appliance-owned backup snapshots", "aria-label": "Open appliance-owned backup snapshots", dataset: { changesTab: "snapshots" }, onclick: () => activate("snapshots") }, "Snapshots"),
    h("button", { class: tab === "audit" ? "active" : "", type: "button", title: "Open audit log", "aria-label": "Open audit log", dataset: { changesTab: "audit" }, onclick: () => activate("audit") }, "Audit log")));
}

function loadErrorDetail(err, fallback = "The API request failed.") {
  return err?.message || String(err || fallback);
}

function currentChangesQuery() {
  if (tab === "versions") return { tab, version: versionRoute.version || "", drawer: versionRoute.drawer || "" };
  if (tab === "snapshots") return { tab, snapshot: snapshotRoute.snapshot || "", drawer: snapshotRoute.drawer || "" };
  if (tab === "audit") return { tab, ...auditFilters, drawer: auditDrawer || "" };
  return { tab: "candidate", drawer: candidateDrawer || "" };
}

async function candidateReview(wrap, root) {
  clear(wrap);
  if (session.candidateUnavailable) {
    wrap.appendChild(card(h("h2", {}, "Current candidate", h("span", { class: "spacer" }), pill("blocked", "bad")),
      h("div", { class: "alert-box bad" }, session.candidateUnavailableMessage()),
      h("div", { class: "flex wrap", style: { marginTop: "12px" } },
        h("button", { class: "btn", type: "button", title: "Reload candidate state", "aria-label": "Reload candidate state", dataset: { changesAction: "reload-candidate" }, onclick: async () => { await session.load(); await paint(root); } }, h("span", { html: icon("refresh", 16) }), "Reload candidate state"))));
    return;
  }
  await session.refreshStatus();
  const dirty = session.dirty;
  if (!dirty) {
    const model = candidateReviewModel({
      dirty: false,
      runningVersion: session.runningVersion,
    });
    wrap.appendChild(card(h("h2", {}, "Current candidate", h("span", { class: "spacer" }), pill("clean", "ok")),
      h("div", { class: "preflight-summary" },
        candidateReviewMetric("Candidate", pill(model.changeLabel, "ok")),
        candidateReviewMetric("Validation", pill(model.validationLabel, model.validationTone)),
        candidateReviewMetric("Runtime", pill(model.runtimeLabel, model.runtimeTone)),
        candidateReviewMetric("Commit", pill(model.commitLabel, model.commitTone))),
      emptyState("check", model.title, model.detail,
        h("button", { class: "btn primary", type: "button", title: "Import JSON into the candidate policy", "aria-label": "Import JSON into the candidate policy", dataset: { changesAction: "import-candidate" }, onclick: () => openImportPolicy(root) }, h("span", { html: icon("upload", 16) }), "Import to candidate"))));
    return;
  }

  wrap.appendChild(h("div", { class: "loading" }, "Loading candidate review…"));
  const [validationResult, runtimePreflightResult, statusResult, diffResult, releaseResult] = await Promise.allSettled([
    api.validate(),
    api.runtimePreflight({ targetPolicy: session.draft, runningPolicy: session.running, operation: "commit" }),
    api.status(),
    loadCandidateDiff(),
    api.releaseAcceptanceStatus(),
  ]);
  clear(wrap);
  const validation = validationResult.status === "fulfilled" ? validationResult.value : null;
  const validationError = validationResult.status === "rejected" ? validationResult.reason : null;
  const runtimePreflight = runtimePreflightResult.status === "fulfilled" ? runtimePreflightResult.value : null;
  const runtimePreflightError = runtimePreflightResult.status === "rejected" ? runtimePreflightResult.reason : null;
  const status = statusResult.status === "fulfilled" ? statusResult.value : null;
  const statusError = statusResult.status === "rejected" ? statusResult.reason : null;
  const diff = diffResult.status === "fulfilled" ? diffResult.value : localCandidateDiff(diffResult.reason);
  const releaseAcceptance = releaseResult.status === "fulfilled" ? releaseResult.value : null;
  const releaseError = releaseResult.status === "rejected" ? releaseResult.reason : null;
  const impact = normalizeServerImpact(validation?.impact) || changeImpact(session.running, session.draft);
  const runtime = commitRuntimePreflight({
    preflight: runtimePreflight,
    status,
    error: statusError || runtimePreflightError,
    draftPolicy: session.draft,
    runningPolicy: session.running,
  });
  const model = candidateReviewModel({
    dirty,
    runningVersion: session.runningVersion,
    changeCount: session.serverChangeCount(),
    changeSummary: session.serverChangeSummary(),
    validation,
    validationError,
    runtime,
    impact,
    diff,
  });
  const strictEvidence = strictUiEvidenceModel({
    operation: "commit",
    validation,
    validationError,
    runtime,
    releaseAcceptance,
    releaseError,
  });
  const lifecycle = changesLifecycleGuidanceModel({
    scenario: model.state === "blocked" ? "strict-blocked" : "candidate",
    candidateDirty: dirty,
    runningVersion: session.runningVersion,
    validationBlocked: Boolean(validationError || !validation?.valid),
    runtimeBlocked: runtime.label === "not ready" || runtime.cls === "bad",
  });
  const approval = governanceApprovalModel({
    dirty,
    runningVersion: session.runningVersion,
    changeCount: session.serverChangeCount(),
    changeSummary: session.serverChangeSummary(),
    validation,
    validationError,
    runtime,
    impact,
    diff,
  });
  const approvalContext = { model: approval, validation, validationError, runtime, impact, diff };

  wrap.appendChild(card(h("h2", {}, "Current candidate", h("span", { class: "spacer" }), pill(model.commitLabel, model.commitTone)),
    h("div", { class: "preflight-summary" },
      candidateReviewMetric("Candidate", pill(model.changeLabel, "warn")),
      candidateReviewMetric("Validation", pill(model.validationLabel, model.validationTone)),
      candidateReviewMetric("Runtime", pill(model.runtimeLabel, model.runtimeTone)),
      candidateReviewMetric("Impact", pill(model.impactLabel, model.impactTone))),
    h("div", { class: "note", style: { marginBottom: "12px" } }, model.detail),
    lifecycleGuidancePanel(lifecycle, { validation, validationError, runtime, impact, diff, status, releaseAcceptance, strictEvidence, decision: "candidate-review" }),
    strictUiEvidencePanel(strictEvidence),
    h("div", { class: "flex wrap", style: { marginBottom: "12px" } },
      h("button", { class: "btn", type: "button", title: "Refresh candidate review", "aria-label": "Refresh candidate review", dataset: { changesAction: "refresh-review" }, onclick: async () => { await session.load(); await paint(root); } }, h("span", { html: icon("refresh", 16) }), "Refresh review"),
      h("button", { class: "btn primary", type: "button", title: "Open commit review for the current candidate", "aria-label": "Open commit review for the current candidate", dataset: { changesAction: "commit-candidate" }, disabled: model.state === "blocked", onclick: () => openCandidateCommitReview(root, { validation, validationError, runtime, impact, diff, releaseAcceptance, strictEvidence }) },
        h("span", { html: icon("upload", 16) }), "Commit candidate"),
      h("button", { class: "btn", type: "button", title: "Prepare governance approval packet", "aria-label": "Prepare governance approval packet", dataset: { changesAction: "prepare-approval" }, onclick: () => openRoutedGovernanceApproval(approvalContext) },
        h("span", { html: icon("check", 16) }), "Prepare approval"),
      h("button", { class: "btn ghost", type: "button", title: "Open candidate diff", "aria-label": "Open candidate diff", dataset: { changesAction: "open-diff" }, onclick: () => showCandidateDiff(diff) }, h("span", { html: icon("diff", 16) }), "Open diff"),
      h("button", { class: "btn ghost", type: "button", title: "Discard the current candidate", "aria-label": "Discard the current candidate", dataset: { changesAction: "discard-candidate" }, onclick: () => discardCandidate(root) }, "Discard candidate")),
    validationError ? h("div", { class: "alert-box bad" }, validationError.message || "Candidate validation failed.") :
      renderValidationEvidence(validation, {
        validText: "Candidate validated successfully. Policy checks passed.",
        invalidLead: "Fix these before committing:",
      }),
    candidateRuntimePanel(runtime),
    h("div", { class: "impact-section-head" },
      h("strong", {}, "Commit impact"),
      h("span", {}, `${impact.items.length} item${impact.items.length === 1 ? "" : "s"}`)),
    h("div", { class: "impact-list impact-list-scroll" }, impact.items.map((it) =>
      h("div", { class: "impact-row " + it.level },
        h("div", {}, pill(it.level, it.level === "high" ? "bad" : it.level === "medium" ? "warn" : "neutral")),
        h("div", {}, h("strong", {}, it.title), h("span", {}, it.detail))))),
    h("details", { class: "diff-details", open: true },
      h("summary", {}, `Diff: ${diff.fromLabel} -> ${diff.toLabel}`),
      diff.source === "fallback" ? h("div", { class: "alert-box warn" }, "Diff API unavailable; showing local candidate diff.") : null,
      diff.changed ? renderDiffLines(diff.lines) : h("div", { class: "alert-box ok" }, "Candidate matches the running policy."))));
  maybeOpenGovernanceApproval(approvalContext);
}

function candidateReviewMetric(label, value) {
  return h("div", {}, h("span", {}, label), h("strong", {}, value));
}

function candidateRuntimePanel(runtime) {
  if (!runtime.items.length) {
    return h("div", { class: "alert-box ok" }, runtime.detail);
  }
  return h("div", { class: "runtime-preflight" },
    h("div", { class: "alert-box " + runtime.cls },
      h("strong", {}, runtime.detail),
      h("div", { class: "note" }, "Review the action queue before committing this candidate.")),
    h("div", { class: "impact-list impact-list-scroll" }, runtime.items.map((it) =>
      runtimePreflightActionRow(it, "candidate"))));
}

export function strictUiEvidenceModel({
  operation = "commit",
  validation = null,
  validationError = null,
  runtime = {},
  releaseAcceptance = null,
  releaseError = null,
} = {}) {
  const op = operation === "rollback" ? "rollback" : "commit";
  const validationBlocked = Boolean(validationError || (validation && !validation.valid));
  const runtimeBlocked = runtime?.label === "not ready" || runtime?.cls === "bad";
  const runtimeReview = Boolean(runtime?.requiresAck || runtime?.cls === "warn");
  const blockers = [];
  if (validationBlocked) blockers.push(validationError ? "validation unavailable" : "validation failed");
  if (runtimeBlocked) blockers.push("system preflight blocks UI apply");
  const canClickUiApply = !validationBlocked && !runtimeBlocked;
  const state = !canClickUiApply ? "blocked" : runtimeReview ? "review" : "ready";
  const label = state === "blocked" ? "strict apply blocked" : state === "review" ? "strict evidence review" : "strict apply ready";
  const tone = state === "blocked" ? "bad" : state === "review" ? "warn" : "ok";
  const action = op === "rollback" ? "rollback" : "commit";
  const detail = state === "blocked"
    ? `${action} must stay disabled until validation and system preflight blockers are fixed.`
    : state === "review"
      ? `UI ${action} can proceed only after operator acknowledgement.`
      : `UI ${action} can be clicked under strict smoke; this is runtime preflight evidence, not field certification.`;
  return {
    operation: op,
    state,
    label,
    tone,
    detail,
    canClickUiApply,
    runtimeReady: !runtimeBlocked,
    runtimeRequiresAck: Boolean(runtime?.requiresAck),
    validation: validationBlocked ? "blocked" : validation?.valid ? "passed" : "unknown",
    release: releaseAcceptanceSummary(null, null),
    blockers,
    handoff: [
      "Preserve the candidate before cleanup, rollback, or strict apply retry.",
      "Do not treat this panel as ready-runtime field evidence until the strict UI apply smoke passes on a supported runtime-ready host.",
    ],
    readinessHref: "",
    fieldEvidenceHref: "",
  };
}

function releaseAcceptanceSummary(releaseAcceptance = null, releaseError = null) {
  if (releaseError) {
    return {
      available: false,
      ready: false,
      state: "unavailable",
      detail: releaseError.message || "release acceptance status unavailable",
      openCount: 0,
      missing: 0,
      invalid: 0,
      review: 0,
      manifestPresent: false,
    };
  }
  if (!releaseAcceptance) {
    return {
      available: false,
      ready: false,
      state: "unknown",
      detail: "release acceptance status was not loaded",
      openCount: 0,
      missing: 0,
      invalid: 0,
      review: 0,
      manifestPresent: false,
    };
  }
  const summary = releaseAcceptance.summary || {};
  const recordability = releaseAcceptance.recordability || {};
  const missing = Number(summary.missing || 0);
  const invalid = Number(summary.invalid || 0);
  const todo = Number(summary.todo || 0);
  const reviewNeeded = Number(summary.reviewNeeded || summary.review_needed || 0);
  const recordabilityProblems = Number(recordability.problems || 0);
  const openCount = missing + invalid + todo + reviewNeeded + recordabilityProblems;
  const ready = Boolean(releaseAcceptance.ready) || String(releaseAcceptance.state || "").toLowerCase() === "ready";
  return {
    available: true,
    ready,
    state: releaseAcceptance.state || (ready ? "ready" : "review"),
    detail: ready ? "release gates report ready" : `${openCount} release evidence item${openCount === 1 ? "" : "s"} need review`,
    openCount,
    missing,
    invalid,
    todo,
    review: reviewNeeded + recordabilityProblems,
    manifestPresent: Boolean(releaseAcceptance.manifestPresent ?? releaseAcceptance.manifest_present),
  };
}

function strictUiEvidenceArtifact(model = {}) {
  const release = model.release || {};
  return {
    operation: model.operation || "",
    state: model.state || "",
    label: safePreservationText(model.label || ""),
    tone: model.tone || "",
    detail: safePreservationText(model.detail || ""),
    canClickUiApply: Boolean(model.canClickUiApply),
    runtimeReady: Boolean(model.runtimeReady),
    runtimeRequiresAck: Boolean(model.runtimeRequiresAck),
    validation: model.validation || "",
    release: {
      available: Boolean(release.available),
      ready: Boolean(release.ready),
      state: safePreservationText(release.state || ""),
      openCount: Number(release.openCount || 0),
      missing: Number(release.missing || 0),
      invalid: Number(release.invalid || 0),
      review: Number(release.review || 0),
      manifestPresent: Boolean(release.manifestPresent),
    },
    blockers: asStringList(model.blockers || []).map(safePreservationText).slice(0, 12),
    handoff: asStringList(model.handoff || []).map(safePreservationText).slice(0, 12),
    readinessHref: safePreservationRoute(model.readinessHref || ""),
    fieldEvidenceHref: safePreservationRoute(model.fieldEvidenceHref || ""),
    fieldEvidenceClaim: "not-claimed-by-changes",
  };
}

function strictUiEvidencePanel(model = {}) {
  const release = model.release || {};
  return h("div", { class: "profile-strip", dataset: { changesStrictUiEvidence: model.operation || "commit" }, style: { margin: "0 0 14px" } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Strict UI apply evidence"),
      pill(model.label || "strict evidence", model.tone || "info", true)),
    h("div", { class: "note" }, model.detail || "Strict UI apply evidence is unavailable."),
    h("dl", { class: "kv" },
      kv("UI action", model.canClickUiApply ? "enabled by preflight" : "blocked by preflight"),
      kv("Runtime", model.runtimeRequiresAck ? "acknowledgement required" : model.runtimeReady ? "ready" : "not ready"),
      kv("Validation", model.validation || "unknown"),
      kv("Field evidence claim", "not claimed by Changes")),
    model.blockers?.length ? h("div", { class: "warning-list compact" }, model.blockers.map((item) =>
      h("div", { class: "warning-row warn" },
        h("div", {}, pill("review", "warn", true)),
        h("div", {}, item)))) : null,
    null);
}

function lifecycleGuidancePanel(model = {}, packetContext = {}) {
  const preservationPacket = () => candidatePreservationPacket({
    ...packetContext,
    lifecycle: model,
    runningVersion: session.runningVersion,
    dirty: session.dirty,
    changeCount: session.serverChangeCount(),
    changeSummary: session.serverChangeSummary(),
    route: currentRoute(),
  });
  return h("div", { class: "profile-strip", dataset: { changesLifecycleGuidance: model.scenario || "candidate" }, style: { margin: "0 0 14px" } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, model.title || "Lifecycle guidance"),
      pill(model.guidanceLabel || "operator guidance", model.guidanceTone || "info", true)),
    h("div", { class: "note" }, model.consequence || ""),
    h("div", { class: "alert-box " + (model.guidanceTone === "warn" ? "warn" : "info"), style: { marginTop: "10px" } },
      h("strong", {}, "Operator decision"),
      h("div", { class: "note" }, model.operatorDecision || "")),
    model.runbookTitle ? h("details", { class: "diff-details", dataset: { changesLifecycleRunbook: model.scenario || "candidate" } },
      h("summary", {}, model.runbookTitle),
      h("ol", { class: "compact-list" }, (model.steps || []).map((step) => h("li", {}, step))),
      model.commands?.length ? h("div", { class: "warning-list compact" }, model.commands.map((command, index) =>
        h("div", { class: "warning-row info", dataset: { changesRunbookCommand: `${model.scenario || "candidate"}-${index + 1}` } },
          h("div", {}, pill("command", "info", true)),
          h("div", {},
            h("pre", { class: "mono perf-command" }, command),
            h("button", { class: "btn sm ghost", type: "button", title: "Copy lifecycle runbook command", "aria-label": "Copy lifecycle runbook command", dataset: { changesAction: "copy-lifecycle-command" }, onclick: () => copyLifecycleText(command) },
              h("span", { html: icon("copy", 15) }), "Copy"))))) : null,
      h("div", { class: "note" }, model.custodyNote || ""),
      h("button", { class: "btn sm ghost", type: "button", title: "Copy lifecycle cleanup and preserve runbook", "aria-label": "Copy lifecycle cleanup and preserve runbook", dataset: { changesAction: "copy-lifecycle-runbook" }, onclick: () => copyLifecycleText(lifecycleRunbookText(model)) },
        h("span", { html: icon("copy", 15) }), "Copy runbook")) : null,
    candidatePreservationActions(preservationPacket));
}

function candidatePreservationActions(packetFactory) {
  return h("div", { class: "profile-strip", dataset: { candidatePreservationPacket: "true" }, style: { marginTop: "12px" } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Candidate preservation"),
      pill("browser-local packet", "warn", true)),
    h("div", { class: "note" }, "Capture candidate status, diff, validation, runtime posture, and cleanup runbook context before discard, rollback, or strict apply decisions."),
    h("div", { class: "flex wrap", style: { marginTop: "10px" } },
      h("button", { class: "btn sm ghost", type: "button", title: "Pin candidate preservation packet to investigation case", "aria-label": "Pin candidate preservation packet to investigation case", dataset: { candidatePreservationAction: "pin" }, onclick: () => pinCandidatePreservation(packetFactory()) },
        h("span", { html: icon("inbox", 15) }), "Pin packet"),
      h("button", { class: "btn sm ghost", type: "button", title: "Copy candidate preservation packet", "aria-label": "Copy candidate preservation packet", dataset: { candidatePreservationAction: "copy" }, onclick: () => copyCandidatePreservation(packetFactory()) },
        h("span", { html: icon("copy", 15) }), "Copy packet"),
      h("button", { class: "btn sm ghost", type: "button", title: "Export candidate preservation packet as JSON", "aria-label": "Export candidate preservation packet as JSON", dataset: { candidatePreservationAction: "export" }, onclick: () => exportCandidatePreservation(packetFactory()) },
        h("span", { html: icon("download", 15) }), "Export JSON")));
}

export function candidatePreservationPacket({
  lifecycle = {},
  runningVersion = 0,
  dirty = false,
  changeCount = 0,
  changeSummary = [],
  validation = null,
  validationError = "",
  runtime = {},
  impact = {},
  diff = {},
  status = null,
  releaseAcceptance = null,
  strictEvidence = null,
  decision = "candidate-review",
  route = "#/changes?tab=candidate",
} = {}) {
  const commands = Array.isArray(lifecycle.commands) ? lifecycle.commands : [];
  const steps = Array.isArray(lifecycle.steps) ? lifecycle.steps : [];
  const validationState = validation?.valid ? "passed" : validationError ? "error" : validation ? "failed" : "unknown";
  const diffPreview = (Array.isArray(diff.lines) ? diff.lines : [])
    .map((line) => line?.s || line?.text || "")
    .map(safePreservationText)
    .filter(Boolean)
    .slice(0, 20);
  const runtimeItems = (Array.isArray(runtime.items) ? runtime.items : []).map((item) => ({
    level: item?.level || "",
    badge: item?.badge || "",
    title: safePreservationText(item?.title || ""),
    detail: safePreservationText(item?.detail || ""),
    href: safePreservationRoute(item?.href || ""),
  })).slice(0, 20);
  const impactItems = (Array.isArray(impact.items) ? impact.items : []).map((item) => ({
    level: item?.level || "",
    title: safePreservationText(item?.title || ""),
    detail: safePreservationText(item?.detail || ""),
  })).slice(0, 20);
  const safeChangeSummary = asStringList(changeSummary).map(safePreservationText).slice(0, 12);
  const safeLifecycle = {
    scenario: lifecycle.scenario || "",
    title: safePreservationText(lifecycle.title || ""),
    guidanceLabel: safePreservationText(lifecycle.guidanceLabel || ""),
    consequence: safePreservationText(lifecycle.consequence || ""),
    operatorDecision: safePreservationText(lifecycle.operatorDecision || ""),
    steps: steps.map(safePreservationText),
    commands: commands.map(safePreservationText),
    custodyNote: safePreservationText(lifecycle.custodyNote || ""),
  };
  const strict = strictEvidence || strictUiEvidenceModel({
    runtime,
    validation,
    validationError,
    releaseAcceptance,
  });
  return buildInvestigationPacket({
    kind: "candidate-preservation",
    title: "Candidate preservation packet",
    subject: {
      id: `candidate-v${Number(runningVersion || 0)}`,
      label: "Changes candidate preservation",
    },
    summary: {
      decision,
      lifecycleScenario: lifecycle.scenario || "",
      lifecycleGuidance: lifecycle.guidanceLabel || "",
      candidateDirty: Boolean(dirty),
      runningVersion: Number(runningVersion || 0),
      pendingChanges: Number(changeCount || 0),
      validation: validationState,
      runtime: runtime.label || "",
      runtimeRequiresAck: Boolean(runtime.requiresAck),
      strictUiApply: strict.label || "",
      releaseAcceptance: strict.release?.state || "",
      releaseOpenItems: Number(strict.release?.openCount || 0),
      impact: impact.level || "",
      diffSource: diff.source || "",
      diffChanged: Boolean(diff.changed),
      status: candidateStatusSummary(status),
      custody: "Browser-local packet only; no policy mutation, server-side custody, signature, or retention is created.",
    },
    evidence: [
      `decision point: ${decision}`,
      lifecycle.title ? `runbook: ${lifecycle.title}` : "",
      lifecycle.operatorDecision ? `operator decision: ${lifecycle.operatorDecision}` : "",
      `candidate dirty: ${Boolean(dirty)}`,
      `pending changes: ${Number(changeCount || 0)}`,
      ...safeChangeSummary.map((item) => `change: ${item}`),
      `validation: ${validationState}`,
      runtime.label ? `runtime: ${safePreservationText(runtime.label)}${runtime.requiresAck ? " (acknowledgement required)" : ""}` : "",
      strict.label ? `strict UI apply: ${safePreservationText(strict.label)}; field evidence claim: not claimed by Changes` : "",
      strict.release?.available ? `release acceptance: ${safePreservationText(strict.release.state)}; open items: ${Number(strict.release.openCount || 0)}` : "release acceptance: unavailable",
      impact.level ? `impact: ${impact.level}` : "",
      diff.source ? `diff: ${diff.source}${diff.changed ? " changed" : " unchanged"}` : "",
      status ? `candidate status: ${candidateStatusSummary(status)}` : "",
      lifecycle.custodyNote ? `custody boundary: ${safeLifecycle.custodyNote}` : "",
    ],
    artifacts: {
      lifecycle: safeLifecycle,
      candidate: {
        dirty: Boolean(dirty),
        runningVersion: Number(runningVersion || 0),
        pendingChanges: Number(changeCount || 0),
        changeSummary: safeChangeSummary,
        status: candidateStatusArtifact(status),
      },
      validation: {
        state: validationState,
        valid: Boolean(validation?.valid),
        issueCount: Array.isArray(validation?.issues) ? validation.issues.length : 0,
        warningCount: Array.isArray(validation?.warnings) ? validation.warnings.length : 0,
        error: safePreservationText(validationError?.message || validationError || ""),
      },
      runtime: {
        label: safePreservationText(runtime.label || ""),
        tone: runtime.cls || "",
        detail: safePreservationText(runtime.detail || ""),
        requiresAck: Boolean(runtime.requiresAck),
        items: runtimeItems,
      },
      strictUiEvidence: strictUiEvidenceArtifact(strict),
      impact: {
        level: impact.level || "",
        itemCount: Array.isArray(impact.items) ? impact.items.length : 0,
        items: impactItems,
      },
      diff: {
        source: diff.source || "",
        fromLabel: safePreservationText(diff.fromLabel || ""),
        toLabel: safePreservationText(diff.toLabel || ""),
        changed: Boolean(diff.changed),
        lineCount: Array.isArray(diff.lines) ? diff.lines.length : 0,
        preview: diffPreview,
      },
    },
  }, { route });
}

function candidateStatusSummary(status = null) {
  if (!status) return "unavailable";
  const dirty = Boolean(status.dirty);
  const changes = Number(status.changeCount || status.change_count || 0);
  const version = Number(status.runningVersion || status.running_version || 0);
  return `${dirty ? "dirty" : "clean"}; ${changes} pending change${changes === 1 ? "" : "s"}; running v${version || 0}`;
}

function candidateStatusArtifact(status = null) {
  if (!status) return null;
  return {
    dirty: Boolean(status.dirty),
    changeCount: Number(status.changeCount || status.change_count || 0),
    runningVersion: Number(status.runningVersion || status.running_version || 0),
    updatedAt: status.updatedAt || status.updated_at || "",
  };
}

function asStringList(value = []) {
  return (Array.isArray(value) ? value : [value]).map((item) => String(item || "").trim()).filter(Boolean);
}

function safePreservationText(value = "") {
  return String(value || "")
    .replace(/(^|[\s"'({=,;])\/(?:var\/lib|var\/log(?:\/openngfw)?|etc\/(?:openngfw|phragma)|tmp|private\/tmp|var\/folders|private\/var\/folders|home\/[^'"\s,;}]+|Users\/[^'"\s,;}]+|opt\/[^'"\s,;}]+|data\/[^'"\s,;}]+)[^'"\s,;}]*/gi, "$1[server-local path redacted]")
    .replace(/(Authorization:\s*Bearer\s+)(?!\[redacted\])["']?[^"'\s,;}]+["']?/gi, "$1[redacted]")
    .replace(/\bBearer\s+(?!\[redacted\])[A-Za-z0-9._~+/-]{8,}/gi, "Bearer [redacted]")
    .replace(/(^|[?&\s"',;])((?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|passwd|secret|client[_-]?secret|api[_-]?key|cookie)=)[^&\s"',;]+/gi, "$1$2[redacted]")
    .replace(/(^|[\s"',;{])((?:access[_-]?token|refresh[_-]?token|id[_-]?token|password|passwd|secret|client[_-]?secret|api[_-]?key|cookie)\s*:\s*)[^\s"',;]+/gi, "$1$2[redacted]")
    .slice(0, 1600);
}

function safePreservationRoute(value = "") {
  const text = String(value || "").trim();
  return text.startsWith("#/") && !/[?&](?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|secret|api[_-]?key)=/i.test(text) ? text : "";
}

function lifecycleRunbookText(model = {}) {
  const steps = (model.steps || []).map((step, index) => `${index + 1}. ${step}`).join("\n");
  const commands = (model.commands || []).map((command) => `- ${command}`).join("\n");
  return [
    model.runbookTitle || model.title || "Changes lifecycle runbook",
    "",
    model.consequence || "",
    model.operatorDecision ? `Decision: ${model.operatorDecision}` : "",
    steps ? `\nSteps:\n${steps}` : "",
    commands ? `\nCommands:\n${commands}` : "",
    model.custodyNote ? `\nBoundary: ${model.custodyNote}` : "",
  ].filter(Boolean).join("\n") + "\n";
}

function runtimePreflightActionRow(it, context = "candidate") {
  return h("div", { class: "impact-row " + it.level },
    h("div", {}, pill(it.badge, it.level === "high" ? "bad" : "warn")),
    h("div", {},
      h("strong", {}, it.title),
      h("span", {}, it.detail || "No action detail returned."),
      h("div", { class: "warning-actions" },
        it.href ? h("a", {
          class: "btn sm ghost",
          href: it.href,
          title: `Open the ${context} fix surface`,
          "aria-label": `Open the ${context} fix surface`,
          dataset: { changesRuntimeAction: "open-fix" },
        }, "Open fix") : null)));
}

async function loadCandidateDiff() {
  try {
    const data = await api.policyDiff({
      fromSource: "POLICY_SOURCE_RUNNING",
      toSource: "POLICY_SOURCE_CANDIDATE",
    });
    const labels = policyDiffLabels(data, "running policy", "candidate");
    return {
      ...labels,
      lines: normalizePolicyDiffLines(data.lines || []),
      changed: Boolean(data.changed),
      source: "api",
    };
  } catch (e) {
    return localCandidateDiff(e);
  }
}

function localCandidateDiff(error = null) {
  const lines = diffLines(session.running, session.draft);
  return {
    fromLabel: "running policy",
    toLabel: "candidate",
    lines,
    changed: lines.some((l) => l.t !== "ctx"),
    source: "fallback",
    error: error?.message || String(error || ""),
  };
}

function showCandidateDiff(diff) {
  openDrawer({
    title: `Diff: ${diff.fromLabel} -> ${diff.toLabel}`,
    subtitle: diff.changed ? "Current staged candidate changes" : "Candidate matches running policy",
    width: "720px",
    body: h("div", {},
      diff.source === "fallback" ? h("div", { class: "alert-box warn" }, "Diff API unavailable; showing local candidate diff.") : null,
      diff.changed ? renderDiffLines(diff.lines) : h("div", { class: "alert-box ok" }, "Candidate matches the running policy.")),
    footer: [h("button", { class: "btn ghost", type: "button", title: "Close candidate diff", "aria-label": "Close candidate diff", dataset: { changesAction: "close-candidate-diff" }, onclick: closeDrawer }, "Close")],
  });
}

function maybeOpenGovernanceApproval(context = {}) {
  if (candidateDrawer !== "governance-approval") return;
  openGovernanceApprovalDrawer(context, { routeBacked: true });
}

function openRoutedGovernanceApproval(context = {}) {
  candidateDrawer = "governance-approval";
  syncChangesRoute();
  openGovernanceApprovalDrawer(context, { routeBacked: true });
}

function openGovernanceApprovalDrawer({ model, validation, validationError, runtime, impact, diff } = {}, opts = {}) {
  const packet = governanceApprovalHandoffPacket({
    model,
    runningVersion: session.runningVersion,
    changeCount: session.serverChangeCount(),
    changeSummary: session.serverChangeSummary(),
    validation,
    validationError: validationError?.message || String(validationError || ""),
    runtime,
    impact,
    diff,
  }, { route: currentRoute() });
  openDrawer({
    title: "Governance review packet",
    subtitle: "Browser-local CAB handoff for the current candidate",
    width: "760px",
    onClose: opts.routeBacked ? clearCandidateDrawerState : null,
    body: h("div", { dataset: { governanceApprovalDrawer: "true" } },
      h("div", { class: "flex wrap", style: { marginBottom: "16px" } },
        pill(model?.approvalLabel || "review", model?.approvalTone || "neutral", true),
        pill(packet.summary.validation || "validation", packet.summary.validation === "passed" ? "ok" : "bad", true),
        pill(packet.summary.impact || "impact", packet.summary.impact === "high" ? "bad" : packet.summary.impact === "medium" ? "warn" : "ok", true),
        h("span", { class: "tag" }, `${packet.summary.pendingChanges || 0} changes`)),
      h("div", { class: "alert-box warn" },
        h("strong", {}, "Review handoff only"),
        h("div", { class: "note" }, model?.custodyNote || "Server-side approval records gate commit; signed custody and external CAB integration remain hardening work.")),
      h("dl", { class: "kv" },
        kv("State", model?.title || "Governance review"),
        kv("Commit readiness", packet.summary.commit || "—"),
        kv("Running version", packet.summary.runningVersion ? `v${packet.summary.runningVersion}` : "—"),
        kv("Runtime", packet.summary.runtime || "—"),
        kv("Diff", `${packet.summary.diffSource || "unknown"}${packet.summary.diffChanged ? ", changed" : ", unchanged"}`),
        kv("Route", packet.source?.route || currentRoute())),
      h("div", { class: "profile-strip" },
        h("div", { class: "profile-strip-head" },
          h("strong", {}, "Required reviewers"),
          h("span", {}, "derived from current candidate risk")),
        governanceList(packet.summary.reviewerRoles, "No additional reviewer role detected.")),
      h("div", { class: "profile-strip" },
        h("div", { class: "profile-strip-head" },
          h("strong", {}, "Risk factors"),
          h("span", {}, "operational review cues")),
        governanceList(packet.summary.riskFactors, "Standard candidate review.")),
      h("div", { class: "profile-strip" },
        h("div", { class: "profile-strip-head" },
          h("strong", {}, "Candidate summary"),
          h("span", {}, "bounded visible changes")),
        governanceList(governanceCandidateEvidence(packet), "Candidate differs from running policy."))),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close governance review packet", "aria-label": "Close governance review packet", dataset: { governanceApprovalAction: "close" }, onclick: closeDrawer }, "Close"),
      h("button", { class: "btn", type: "button", title: "Pin governance approval packet to investigation case", "aria-label": "Pin governance approval packet to investigation case", dataset: { governanceApprovalAction: "pin-case" }, onclick: () => pinGovernanceApproval(packet) }, h("span", { html: icon("inbox", 16) }), "Pin to case"),
      h("button", { class: "btn", type: "button", title: "Copy governance approval packet", "aria-label": "Copy governance approval packet", dataset: { governanceApprovalAction: "copy" }, onclick: () => copyGovernanceApproval(packet) }, h("span", { html: icon("copy", 16) }), "Copy packet"),
      h("button", { class: "btn primary", type: "button", title: "Export governance approval packet as JSON", "aria-label": "Export governance approval packet as JSON", dataset: { governanceApprovalAction: "export-json" }, onclick: () => exportGovernanceApproval(packet) }, h("span", { html: icon("download", 16) }), "Export JSON"),
    ],
  });
}

function governanceCandidateEvidence(packet = {}) {
  const summary = packet.artifacts?.candidate?.changeSummary || [];
  const preview = packet.artifacts?.diff?.preview || [];
  return [...summary, ...preview].filter(Boolean).slice(0, 20);
}

function governanceList(items = [], empty = "None") {
  const rows = Array.isArray(items) ? items.filter(Boolean) : [];
  if (!rows.length) return h("div", { class: "note" }, empty);
  return h("div", { class: "impact-list" }, rows.map((item) => h("div", { class: "impact-row neutral" },
    h("div", {}, pill("review", "neutral")),
    h("div", {}, h("span", {}, item)))));
}

export function commitRevisionRecoveryMessage(reviewedRevision = "", currentRevision = "", err = null) {
  const reviewed = String(reviewedRevision || "").trim();
  const current = String(currentRevision || "").trim();
  const detail = err?.message || String(err || "");
  const parts = ["Candidate changed after this commit review opened."];
  if (reviewed) parts.push(`Reviewed revision: ${reviewed}.`);
  if (current) parts.push(`Current revision: ${current}.`);
  if (detail && !/candidate changed after this commit review opened/i.test(detail)) parts.push(detail);
  parts.push("Reload candidate state, reopen the diff, and use an approval bound to the current candidate revision before committing.");
  return parts.join(" ");
}

function statusCandidateRevision(status = null) {
  return String(status?.candidateRevision || status?.candidate_revision || "").trim();
}

function openCandidateCommitReview(root, { validation, validationError, runtime, impact, diff, releaseAcceptance, strictEvidence }) {
  const valid = Boolean(!validationError && validation?.valid);
  const reviewedCandidateRevision = String(session.candidateRevision || statusCandidateRevision(session.candidateStatus)).trim();
  const comment = h("textarea", { class: "input", placeholder: "Describe this change for the audit trail", dataset: { changesField: "commit-comment" } });
  const approvalId = h("input", { class: "input", placeholder: "Approval ID", dataset: { changesField: "commit-approval-id" } });
  const approvalComment = h("textarea", { class: "input", placeholder: "Approval rationale for this exact candidate revision", dataset: { changesField: "approval-comment" } });
  const approvalAckRisk = h("input", { type: "checkbox", dataset: { changesAck: "approval-risk" } });
  const approvalAckRuntime = h("input", { type: "checkbox", dataset: { changesAck: "approval-runtime" } });
  const approvalList = h("div", { class: "warning-list compact", dataset: { changesApprovalList: "true" } },
    h("div", { class: "warning-row info" }, h("div", {}, pill("loading", "info", true)), h("div", {}, "Loading approvals for this candidate revision.")));
  const commitRecovery = h("div", { dataset: { changesCommitRecovery: "true" } });
  const acknowledge = h("input", { type: "checkbox", dataset: { changesAck: "commit-runtime-risk" } });
  const needsRiskAck = impact.level === "high";
  const needsAck = needsRiskAck || runtime.requiresAck;
  approvalAckRisk.checked = needsRiskAck;
  approvalAckRuntime.checked = Boolean(runtime.requiresAck);
  const lifecycle = changesLifecycleGuidanceModel({
    scenario: blockedLifecycleScenario(validationError, validation, runtime),
    candidateDirty: true,
    runningVersion: session.runningVersion,
    validationBlocked: Boolean(validationError || !validation?.valid),
    runtimeBlocked: runtime.label === "not ready" || runtime.cls === "bad",
  });
  const blocked = () => Boolean(!valid || !reviewedCandidateRevision || !approvalId.value.trim() || (needsAck && !acknowledge.checked));
  const selectApproval = (id) => {
    approvalId.value = String(id || "").trim();
    commitBtn.disabled = blocked();
  };
  const showCommitRecovery = (message) => {
    clear(commitRecovery);
    commitRecovery.appendChild(h("div", { class: "alert-box warn" },
      h("strong", {}, "Reload required before commit"),
      h("div", { class: "note" }, message)));
  };
  const approvalRow = (approval) => h("div", { class: "warning-row info", dataset: { changesApprovalId: String(approval.id || "") } },
    h("div", {}, pill(`#${approval.id || "?"}`, "info", true)),
    h("div", {},
      h("strong", {}, approval.comment || "Approved candidate"),
      h("span", {}, `${approval.actor || "unknown actor"}${approval.actorRole ? ` (${approval.actorRole})` : ""}; ${fmt.relTime(approval.createdAt || approval.created_at)}`),
      h("div", { class: "warning-actions" },
        h("button", { class: "btn sm ghost", type: "button", title: `Use approval ${approval.id} for commit`, "aria-label": `Use approval ${approval.id} for commit`, dataset: { changesApprovalAction: "use" }, onclick: () => selectApproval(approval.id) },
          h("span", { html: icon("check", 15) }), "Use approval"))));
  const refreshApprovalList = async () => {
    clear(approvalList);
    const revision = reviewedCandidateRevision;
    if (!revision) {
      approvalList.appendChild(h("div", { class: "warning-row warn" }, h("div", {}, pill("blocked", "warn", true)), h("div", {}, "Candidate revision is unavailable. Reload candidate state before approving.")));
      return;
    }
    approvalList.appendChild(h("div", { class: "warning-row info" }, h("div", {}, pill("loading", "info", true)), h("div", {}, "Loading active approvals.")));
    try {
      const res = await api.changeApprovals({ candidateRevision: revision, limit: 25 });
      clear(approvalList);
      const approvals = Array.isArray(res.approvals) ? res.approvals : [];
      if (!approvals.length) {
        approvalList.appendChild(h("div", { class: "warning-row warn" }, h("div", {}, pill("required", "warn", true)), h("div", {}, "No active approval exists for this candidate revision.")));
        return;
      }
      approvals.forEach((approval) => approvalList.appendChild(approvalRow(approval)));
      if (!approvalId.value.trim() && approvals[0]?.id) selectApproval(approvals[0].id);
    } catch (err) {
      clear(approvalList);
      approvalList.appendChild(h("div", { class: "warning-row warn" }, h("div", {}, pill("unavailable", "warn", true)), h("div", {}, err.message || "Could not load change approvals.")));
    }
  };
  const createApproval = async (btn) => {
    const revision = reviewedCandidateRevision;
    const approvalText = approvalComment.value.trim();
    if (!revision) {
      toast("Approval blocked", "Candidate revision is unavailable. Reload candidate state before approving.", "warn");
      return;
    }
    if (!approvalText) {
      toast("Approval comment required", "Add an approval rationale before creating the server approval record.", "warn");
      approvalComment.focus();
      return;
    }
    btn.disabled = true;
    btn.textContent = "Approving...";
    try {
      const res = await api.createChangeApproval({
        candidateRevision: revision,
        comment: approvalText,
        ackRisk: Boolean(approvalAckRisk.checked),
        ackRuntime: Boolean(approvalAckRuntime.checked),
      });
      const approval = res.approval || {};
      if (approval.id) selectApproval(approval.id);
      approvalComment.value = "";
      toast("Approval recorded", `Approval #${approval.id || "created"} is bound to this candidate revision.`, "ok");
      await refreshApprovalList();
    } catch (err) {
      toast("Approval failed", err.message, "bad");
    } finally {
      btn.disabled = false;
      btn.textContent = "Create approval";
    }
  };
  const commitBtn = h("button", { class: "btn primary", type: "button", title: "Commit the current candidate policy", "aria-label": "Commit the current candidate policy", dataset: { changesSubmit: "commit" }, disabled: blocked(), onclick: async (e) => {
    const auditComment = comment.value.trim();
    const approval = approvalId.value.trim();
    if (!auditComment) {
      toast("Comment required", "Add an audit comment before committing.", "warn");
      comment.focus();
      return;
    }
    if (!approval) {
      toast("Approval required", "Enter a server approval id before committing.", "warn");
      approvalId.focus();
      return;
    }
    if (needsAck && !acknowledge.checked) {
      toast("Review required", "Acknowledge the risk and runtime posture before committing.", "warn");
      return;
    }
    const btn = e.target.closest("button");
    btn.disabled = true;
    btn.textContent = "Committing...";
    try {
      await session.refreshStatus();
      const currentRevision = String(session.candidateRevision || statusCandidateRevision(session.candidateStatus)).trim();
      if (!currentRevision || currentRevision !== reviewedCandidateRevision) {
        const msg = commitRevisionRecoveryMessage(reviewedCandidateRevision, currentRevision);
        showCommitRecovery(msg);
        toast("Candidate changed", msg, "warn");
        btn.disabled = blocked();
        btn.textContent = "Commit";
        return;
      }
      const r = await session.commit(
        auditComment,
        needsRiskAck && acknowledge.checked,
        runtime.requiresAck && acknowledge.checked,
        approval,
        reviewedCandidateRevision,
      );
      closeDrawer();
      toast("Committed", `Applied as version v${r.version}.`, "ok");
      await session.load();
      await paint(root);
    } catch (err) {
      const currentRevision = String(session.candidateRevision || statusCandidateRevision(session.candidateStatus)).trim();
      if (/candidate|revision|precondition|approval/i.test(err?.message || "")) {
        showCommitRecovery(commitRevisionRecoveryMessage(reviewedCandidateRevision, currentRevision, err));
      }
      btn.disabled = false;
      btn.textContent = "Commit";
      toast("Commit failed", err.message, "bad");
    }
  } }, h("span", { html: icon("upload", 16) }), "Commit");
  acknowledge.onchange = () => { commitBtn.disabled = blocked(); };
  approvalId.oninput = () => { commitBtn.disabled = blocked(); };

  openDrawer({
    title: "Commit candidate",
    subtitle: "Validate, inspect impact, then apply to the live firewall.",
    width: "760px",
    body: h("div", {},
      h("div", { class: "preflight-summary" },
        h("div", {}, h("span", {}, "Pending changes"), h("strong", {}, String(session.serverChangeCount()))),
        h("div", {}, h("span", {}, "Validation"), validationError ? pill("error", "bad") : valid ? pill("passed", "ok") : pill("failed", "bad")),
        h("div", {}, h("span", {}, "Impact"), pill(impact.level, impact.level === "high" ? "bad" : impact.level === "medium" ? "warn" : "ok")),
        h("div", {}, h("span", {}, "Runtime"), pill(runtime.label, runtime.cls))),
      lifecycleGuidancePanel(lifecycle, { validation, validationError, runtime, impact, diff, releaseAcceptance, strictEvidence, decision: "commit-review" }),
      strictUiEvidencePanel(strictEvidence || strictUiEvidenceModel({ operation: "commit", validation, validationError, runtime, releaseAcceptance })),
      validationError ? h("div", { class: "alert-box bad" }, validationError.message) :
        renderValidationEvidence(validation, {
          validText: "Candidate validated successfully. Engine syntax checks passed.",
          invalidLead: "Fix these before committing:",
        }),
      candidateRuntimePanel(runtime),
      h("div", { class: "impact-section-head" },
        h("strong", {}, "Commit impact"),
        h("span", {}, `${impact.items.length} item${impact.items.length === 1 ? "" : "s"}`)),
      h("div", { class: "impact-list impact-list-scroll" }, impact.items.map((it) =>
        h("div", { class: "impact-row " + it.level },
          h("div", {}, pill(it.level, it.level === "high" ? "bad" : it.level === "medium" ? "warn" : "neutral")),
          h("div", {}, h("strong", {}, it.title), h("span", {}, it.detail))))),
      h("details", { class: "diff-details" },
        h("summary", {}, `Diff: ${diff.fromLabel} -> ${diff.toLabel}`),
        diff.source === "fallback" ? h("div", { class: "alert-box warn" }, "Diff API unavailable; showing local candidate diff.") : null,
        diff.changed ? renderDiffLines(diff.lines) : h("div", { class: "alert-box ok" }, "Candidate matches the running policy.")),
      h("div", { class: "profile-strip", dataset: { changesServerApproval: "true" } },
        h("div", { class: "profile-strip-head" },
          h("strong", {}, "Server approval"),
          pill(reviewedCandidateRevision ? "review-bound" : "revision unavailable", reviewedCandidateRevision ? "ok" : "warn", true)),
        h("div", { class: "note" }, "Commit uses the candidate revision reviewed when this drawer opened. If the shared candidate changes, reload and review the new diff before committing."),
        h("dl", { class: "kv" },
          kv("Reviewed candidate revision", reviewedCandidateRevision || "unavailable"),
          kv("Approval state", "stored on the policy service; consumed by commit intent")),
        approvalList,
        h("label", { class: "field" }, h("span", {}, "Approval rationale"), approvalComment),
        h("label", { class: "ack-row" }, approvalAckRisk, h("span", {}, "Approver reviewed high-risk policy impact.")),
        h("label", { class: "ack-row" }, approvalAckRuntime, h("span", {}, "Approver reviewed system preflight warnings.")),
        h("div", { class: "flex wrap", style: { marginTop: "10px" } },
          h("button", { class: "btn sm", type: "button", title: "Create a server approval for this candidate revision", "aria-label": "Create a server approval for this candidate revision", dataset: { changesApprovalAction: "create" }, onclick: (e) => createApproval(e.target.closest("button")) },
            h("span", { html: icon("check", 15) }), "Create approval"),
          h("button", { class: "btn sm ghost", type: "button", title: "Reload server approvals for this candidate revision", "aria-label": "Reload server approvals for this candidate revision", dataset: { changesApprovalAction: "refresh" }, onclick: () => refreshApprovalList() },
            h("span", { html: icon("refresh", 15) }), "Refresh approvals"))),
      commitRecovery,
      needsAck ? h("label", { class: "ack-row" },
        acknowledge,
        h("span", {}, candidateAckText(impact, runtime))) : null,
      h("label", { class: "field" }, h("span", {}, "Approval ID"), approvalId),
      h("label", { class: "field" }, h("span", {}, "Audit comment"), comment)),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Cancel candidate commit", "aria-label": "Cancel candidate commit", dataset: { changesAction: "cancel-commit" }, onclick: closeDrawer }, "Cancel"),
      commitBtn,
    ],
  });
  refreshApprovalList();
}

function candidateAckText(impact, runtime) {
  if (impact.level === "high" && runtime.requiresAck) {
    return "I reviewed the high-risk policy impact and the system preflight warnings, and intend to apply this candidate.";
  }
  if (runtime.requiresAck) {
    return "I reviewed the system preflight warnings and intend to apply this candidate.";
  }
  return "I reviewed the high-risk policy impact and intend to apply it to the live firewall.";
}

async function discardCandidate(root) {
  const lifecycle = changesLifecycleGuidanceModel({ scenario: "discard", candidateDirty: true, runningVersion: session.runningVersion });
  if (!(await confirmDialog({ title: "Discard pending changes?", message: `${lifecycle.consequence} ${lifecycle.operatorDecision}`, confirmLabel: "Discard", danger: true }))) return;
  try {
    await session.discard();
    toast("Candidate discarded", "Staged changes were reset to the running policy.", "ok");
    await paint(root);
  } catch (e) {
    toast("Discard failed", e.message, "bad");
  }
}

async function versions(wrap, root) {
  clear(wrap);
  let data, run;
  try { [data, run] = await Promise.all([api.versions(100), api.running()]); }
  catch (e) { wrap.appendChild(h("div", { class: "alert-box bad" }, e.message)); return; }
  const list = data.versions || [];
  const runningV = Number(run.version) || 0;
  if (!list.length) { wrap.appendChild(emptyState("changes", "No versions yet", "Commit a policy change to create the first version.")); return; }
  wrap.appendChild(h("div", { class: "table-wrap" },
    responsiveTable(["Version", "Comment", "Recovery", "Actor", "Time", { label: "Actions", attrs: { class: "actions-col" } }],
    list.map((v) => {
      const meta = versionRecoveryModel(v, runningV);
      const isRunning = meta.isRunning;
      return h("tr", { dataset: { changesVersionRow: String(v.id || "") } },
        labeledCell("Version", {}, h("div", { class: "flex wrap" },
          h("span", { class: "tag" }, "v" + v.id),
          isRunning ? pill("running", "ok", true) : null,
          meta.lastKnownGood ? pill("LKG", "ok", true) : null,
          pill(meta.state, meta.stateClass))),
        labeledCell("Comment", {}, v.comment || h("span", { class: "muted" }, "(no comment)")),
        labeledCell("Recovery", {}, h("div", { class: "mono", title: meta.artifactSetSha256 || "" }, meta.artifactLabel),
          h("div", { class: "muted" }, meta.recoveryLabel)),
        labeledCell("Actor", { class: "mono", title: authTitle(v) }, actorLabel(v)),
        labeledCell("Time", { class: "muted", title: fmt.absTime(meta.displayTime) }, fmt.relTime(meta.displayTime)),
        labeledCell("Actions", { class: "cell-actions" }, h("div", { class: "flex row-actions" },
          h("button", { class: "btn sm ghost", type: "button", title: `Compare version ${v.id} to running`, "aria-label": `Compare version ${v.id} to running`, dataset: { changesAction: "diff-version" }, onclick: () => openRoutedVersionDiff(v, run) }, h("span", { html: icon("diff", 15) }), "Diff"),
          h("button", { class: "btn sm ghost", type: "button", title: `Download version ${v.id} as JSON`, "aria-label": `Download version ${v.id} as JSON`, dataset: { changesAction: "export-version" }, onclick: () => exportVersionPolicy(v) }, h("span", { html: icon("download", 15) }), "Export"),
          isRunning ? null : h("button", { class: "btn sm", type: "button", title: `Open rollback review for version ${v.id}`, "aria-label": `Open rollback review for version ${v.id}`, dataset: { changesAction: "rollback-version" }, onclick: () => openRoutedVersionRollback(v, root) }, h("span", { html: icon("rollback", 15) }), "Roll back"))));
    }), { className: "changes-version-table" })));
  maybeOpenVersionDrawer(list, run, root);
}

async function snapshots(wrap, root) {
  clear(wrap);
  let data;
  try { data = await api.backupSnapshots(100); }
  catch (e) { wrap.appendChild(h("div", { class: "alert-box bad" }, e.message)); return; }
  const list = Array.isArray(data.snapshots) ? data.snapshots : [];
  wrap.appendChild(card(h("h2", {}, "Appliance snapshots", h("span", { class: "spacer" }), pill("server-owned", "info", true)),
    h("div", { class: "note" }, "Snapshots are stored by the appliance and can be validated or staged into candidate without relying on browser downloads."),
    h("div", { class: "flex wrap", style: { marginTop: "12px" } },
      h("button", { class: "btn primary", type: "button", title: "Create a server-side snapshot of the running policy", "aria-label": "Create a server-side snapshot of the running policy", dataset: { changesAction: "create-backup-snapshot" }, onclick: () => openCreateSnapshot(root) },
        h("span", { html: icon("download", 16) }), "Snapshot running"),
      h("button", { class: "btn", type: "button", title: "Reload backup snapshots", "aria-label": "Reload backup snapshots", dataset: { changesAction: "refresh-backup-snapshots" }, onclick: () => snapshots(wrap, root) },
        h("span", { html: icon("refresh", 16) }), "Refresh"))));
  if (!list.length) {
    wrap.appendChild(emptyState("download", "No appliance snapshots", "Create a running-policy snapshot before maintenance or import workflows."));
    return;
  }
  wrap.appendChild(h("div", { class: "table-wrap" },
    responsiveTable(["Snapshot", "Source", "Comment", "Actor", "Hash", "Time", { label: "Actions", attrs: { class: "actions-col" } }],
      list.map((snapshot) => h("tr", { dataset: { backupSnapshotRow: snapshot.id || "" } },
        labeledCell("Snapshot", {}, h("div", { class: "flex wrap" },
          h("span", { class: "tag" }, snapshot.id || "snapshot"),
          pill("server", "info", true))),
        labeledCell("Source", {}, backupSnapshotSourceLabel(snapshot)),
        labeledCell("Comment", {}, snapshot.comment || h("span", { class: "muted" }, "(no comment)")),
        labeledCell("Actor", { class: "mono", title: authTitle(snapshot) }, actorLabel(snapshot)),
        labeledCell("Hash", { class: "mono", title: snapshot.policySha256 || snapshot.policy_sha256 || "" }, shortHash(snapshot.policySha256 || snapshot.policy_sha256 || "")),
        labeledCell("Time", { class: "muted", title: fmt.absTime(snapshot.createdAt || snapshot.created_at) }, fmt.relTime(snapshot.createdAt || snapshot.created_at)),
        labeledCell("Actions", { class: "cell-actions" }, h("div", { class: "flex row-actions" },
          h("button", { class: "btn sm ghost", type: "button", title: `Validate snapshot ${snapshot.id}`, "aria-label": `Validate snapshot ${snapshot.id}`, dataset: { changesAction: "validate-backup-snapshot" }, onclick: () => openRoutedSnapshotValidation(snapshot) }, h("span", { html: icon("check", 15) }), "Validate"),
          h("button", { class: "btn sm ghost", type: "button", title: `Download snapshot ${snapshot.id} as JSON`, "aria-label": `Download snapshot ${snapshot.id} as JSON`, dataset: { changesAction: "export-backup-snapshot" }, onclick: () => exportSnapshotPolicy(snapshot) }, h("span", { html: icon("download", 15) }), "Export"),
          h("button", { class: "btn sm ghost", type: "button", title: `Copy maintenance review link for snapshot ${snapshot.id}`, "aria-label": `Copy maintenance review link for snapshot ${snapshot.id}`, dataset: { changesAction: "copy-snapshot-review-link" }, onclick: () => copySnapshotReviewLink(snapshot, "restore-preview") }, h("span", { html: icon("copy", 15) }), "Link"),
          h("button", { class: "btn sm", type: "button", title: `Preview restore for snapshot ${snapshot.id}`, "aria-label": `Preview restore for snapshot ${snapshot.id}`, dataset: { changesAction: "preview-backup-restore" }, onclick: () => openRoutedSnapshotRestore(snapshot, root) }, h("span", { html: icon("rollback", 15) }), "Restore preview"))))),
      { className: "changes-version-table" })));
  maybeOpenSnapshotDrawer(list, root);
}

function backupSnapshotSourceLabel(snapshot = {}) {
  const source = snapshot.source || "running";
  const version = Number(snapshot.sourceVersion || snapshot.source_version || 0);
  return version ? `${source} v${version}` : source;
}

function shortHash(value = "") {
  const text = String(value || "");
  return text ? `sha256:${text.slice(0, 12)}` : "no policy hash";
}

function openCreateSnapshot(root) {
  const comment = h("textarea", { class: "input", placeholder: "Recovery point comment", dataset: { changesField: "snapshot-comment" } });
  openDrawer({
    title: "Create backup snapshot",
    subtitle: "Stores the running policy on the appliance for later validation and restore preview.",
    width: "620px",
    body: h("div", {},
      h("div", { class: "alert-box info" }, "This creates a server-side recovery point. It does not download a browser file and does not change candidate or running policy."),
      h("label", { class: "field" }, h("span", {}, "Comment"), comment)),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Cancel backup snapshot creation", "aria-label": "Cancel backup snapshot creation", dataset: { changesAction: "cancel-create-snapshot" }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: "Create running-policy backup snapshot", "aria-label": "Create running-policy backup snapshot", dataset: { changesAction: "confirm-create-snapshot" }, onclick: async (e) => {
        const btn = e.target.closest("button");
        btn.disabled = true;
        btn.textContent = "Creating...";
        try {
          const res = await api.createBackupSnapshot({ source: "POLICY_SOURCE_RUNNING", comment: comment.value.trim() });
          closeDrawer();
          toast("Snapshot created", `${res.snapshot?.id || "Snapshot"} stored on the appliance.`, "ok");
          await paint(root);
        } catch (err) {
          btn.disabled = false;
          btn.textContent = "Create snapshot";
          toast("Snapshot failed", err.message, "bad");
        }
      } }, h("span", { html: icon("download", 16) }), "Create snapshot"),
    ],
  });
}

function openRoutedSnapshotValidation(snapshot = {}) {
  setSnapshotDrawerState(snapshot.id, "validate");
  validateSnapshot(snapshot, { routeBacked: true });
}

function openRoutedSnapshotRestore(snapshot = {}, root) {
  setSnapshotDrawerState(snapshot.id, "restore-preview");
  previewSnapshotRestore(snapshot, root, { routeBacked: true });
}

function maybeOpenSnapshotDrawer(list = [], root) {
  if (!snapshotRoute.snapshot || !snapshotRoute.drawer) return;
  const selected = list.find((item) => String(item.id || "") === snapshotRoute.snapshot);
  if (!selected) return;
  setTimeout(() => {
    if (!snapshotRouteMatches(selected.id, snapshotRoute.drawer)) return;
    if (snapshotRoute.drawer === "validate") {
      validateSnapshot(selected, { routeBacked: true });
      return;
    }
    previewSnapshotRestore(selected, root, { routeBacked: true });
  }, 0);
}

async function validateSnapshot(snapshot = {}, opts = {}) {
  openDrawer({
    title: `Validating ${snapshot.id}`,
    subtitle: "Checking the stored policy without mutating candidate or running policy.",
    width: "680px",
    onClose: opts.routeBacked ? clearSnapshotDrawerState : null,
    body: h("div", { class: "loading" }, "Running server validation..."),
    footer: [h("button", { class: "btn ghost", type: "button", title: "Close snapshot validation", "aria-label": "Close snapshot validation", dataset: { changesAction: "close-snapshot-validation" }, onclick: closeDrawer }, "Close")],
  });
  try {
    const res = await api.validateBackupSnapshot(snapshot.id);
    if (opts.routeBacked && !snapshotRouteMatches(snapshot.id, "validate")) return;
    const validation = res.validation || {};
    replaceSnapshotDrawer(() => openDrawer({
      title: `Snapshot validation: ${snapshot.id}`,
      subtitle: validation.valid ? "Snapshot policy is valid" : "Snapshot policy has validation errors",
      width: "720px",
      onClose: opts.routeBacked ? clearSnapshotDrawerState : null,
      body: h("div", {},
        snapshotSummaryPanel(res.snapshot || snapshot),
        renderValidationEvidence(validation, {
          validText: "Snapshot validated successfully. Candidate and running policy are unchanged.",
          invalidLead: "Fix or choose another snapshot before staging:",
        })),
      footer: [h("button", { class: "btn ghost", type: "button", title: "Close snapshot validation result", "aria-label": "Close snapshot validation result", dataset: { changesAction: "close-snapshot-validation-result" }, onclick: closeDrawer }, "Close")],
    }));
  } catch (err) {
    if (opts.routeBacked && !snapshotRouteMatches(snapshot.id, "validate")) return;
    replaceSnapshotDrawer(() => openDrawer({
      title: "Snapshot validation failed",
      subtitle: "Candidate and running policy are unchanged.",
      width: "620px",
      onClose: opts.routeBacked ? clearSnapshotDrawerState : null,
      body: h("div", { class: "alert-box bad" }, err.message),
      footer: [h("button", { class: "btn ghost", type: "button", title: "Close snapshot validation failure", "aria-label": "Close snapshot validation failure", dataset: { changesAction: "close-snapshot-validation-failure" }, onclick: closeDrawer }, "Close")],
    }));
  }
}

async function exportSnapshotPolicy(snapshot = {}) {
  try {
    const res = await api.backupSnapshot(snapshot.id);
    downloadPolicy("backup-snapshot", snapshot.id, res.policy || {});
  } catch (e) {
    toast("Snapshot export failed", e.message, "bad");
  }
}

async function previewSnapshotRestore(snapshot = {}, root, opts = {}) {
  openDrawer({
    title: `Restore preview: ${snapshot.id}`,
    subtitle: "Building validation and diff preview without changing running policy.",
    width: "680px",
    onClose: opts.routeBacked ? clearSnapshotDrawerState : null,
    body: h("div", { class: "loading" }, "Loading restore preview..."),
    footer: [h("button", { class: "btn ghost", type: "button", title: "Cancel restore preview", "aria-label": "Cancel restore preview", dataset: { changesAction: "cancel-snapshot-restore-preview" }, onclick: closeDrawer }, "Cancel")],
  });
  let preview;
  try {
    preview = await api.previewBackupSnapshotRestore(snapshot.id, { stageCandidate: false });
  } catch (err) {
    if (opts.routeBacked && !snapshotRouteMatches(snapshot.id, "restore-preview")) return;
    replaceSnapshotDrawer(() => openDrawer({
      title: "Restore preview failed",
      subtitle: "Candidate and running policy are unchanged.",
      width: "620px",
      onClose: opts.routeBacked ? clearSnapshotDrawerState : null,
      body: h("div", { class: "alert-box bad" }, err.message),
      footer: [h("button", { class: "btn ghost", type: "button", title: "Close restore preview failure", "aria-label": "Close restore preview failure", dataset: { changesAction: "close-snapshot-restore-preview-failure" }, onclick: closeDrawer }, "Close")],
    }));
    return;
  }
  if (opts.routeBacked && !snapshotRouteMatches(snapshot.id, "restore-preview")) return;
  replaceSnapshotDrawer(() => openSnapshotRestorePreview(preview, root, opts));
}

function openSnapshotRestorePreview(preview = {}, root, opts = {}) {
  const snapshot = preview.snapshot || {};
  const validation = preview.validation || {};
  const diff = {
    ...policyDiffLabels(preview.diff || {}, "running policy", `backup snapshot ${snapshot.id || ""}`),
    lines: normalizePolicyDiffLines(preview.diff?.lines || []),
    changed: Boolean(preview.diff?.changed),
  };
  const comment = h("textarea", { class: "input", placeholder: "Reason for staging this backup snapshot", dataset: { changesField: "snapshot-restore-comment" } }, `Stage backup snapshot ${snapshot.id || ""} for review`);
  const reviewPacket = snapshotRestoreReviewPacket({ ...preview, diff }, {
    route: currentRoute(),
    reviewLink: snapshotRestoreReviewHash(snapshot.id || "", "restore-preview"),
  });
  const stageBtn = h("button", { class: "btn primary", type: "button", title: "Stage this backup snapshot into candidate", "aria-label": "Stage this backup snapshot into candidate", dataset: { changesAction: "stage-backup-snapshot" }, disabled: !validation.valid, onclick: async (e) => {
    const auditComment = comment.value.trim();
    if (!auditComment) {
      toast("Comment required", "Add an audit comment before staging the snapshot.", "warn");
      comment.focus();
      return;
    }
    const btn = e.target.closest("button");
    btn.disabled = true;
    btn.textContent = "Staging...";
    try {
      await api.previewBackupSnapshotRestore(snapshot.id, {
        comment: auditComment,
        stageCandidate: true,
        expectedCandidateRevision: session.candidateRevision || session.candidateStatus?.candidateRevision || "",
      });
      closeDrawer();
      toast("Snapshot staged", `${snapshot.id} is now the candidate. Validate and commit to apply.`, "ok");
      await session.load();
      await paint(root);
    } catch (err) {
      btn.disabled = false;
      btn.textContent = "Stage to candidate";
      toast("Snapshot stage failed", err.message, "bad");
    }
  } }, h("span", { html: icon("upload", 16) }), "Stage to candidate");
  openDrawer({
    title: `Restore preview: ${snapshot.id}`,
    subtitle: "Running policy is unchanged; staging creates a candidate only.",
    width: "760px",
    onClose: opts.routeBacked ? clearSnapshotDrawerState : null,
    body: h("div", {},
      snapshotSummaryPanel(snapshot),
      h("div", { class: "preflight-summary" },
        h("div", {}, h("span", {}, "Validation"), validation.valid ? pill("passed", "ok") : pill("failed", "bad")),
        h("div", {}, h("span", {}, "Diff"), diff.changed ? pill("changed", "warn") : pill("unchanged", "ok")),
        h("div", {}, h("span", {}, "Restore job"), h("strong", {}, preview.jobId || "preview")),
        h("div", {}, h("span", {}, "Candidate"), pill("unchanged", "neutral"))),
      renderValidationEvidence(validation, {
        validText: "Snapshot validated successfully. You may stage it as candidate for normal commit review.",
        invalidLead: "Snapshot cannot be staged until validation errors are resolved:",
      }),
      h("details", { class: "diff-details", open: true },
        h("summary", {}, `Diff: ${diff.fromLabel} -> ${diff.toLabel}`),
        diff.changed ? renderDiffLines(diff.lines) : h("div", { class: "alert-box ok" }, "Snapshot matches the running policy.")),
      h("div", { class: "profile-strip", dataset: { snapshotRestorePacket: "true" }, style: { margin: "12px 0" } },
        h("div", {}, h("strong", {}, "Maintenance review packet"), h("div", { class: "note" }, "Browser-local packet for review and reproduction; it is not signed, encrypted, retained, or a restore approval.")),
        h("div", { class: "flex wrap" },
          h("button", { class: "btn sm ghost", type: "button", title: "Copy snapshot restore maintenance review packet", "aria-label": "Copy snapshot restore maintenance review packet", dataset: { snapshotRestoreAction: "copy-packet" }, onclick: () => copySnapshotRestorePacket(reviewPacket) }, h("span", { html: icon("copy", 15) }), "Copy packet"),
          h("button", { class: "btn sm ghost", type: "button", title: "Export snapshot restore maintenance review packet", "aria-label": "Export snapshot restore maintenance review packet", dataset: { snapshotRestoreAction: "export-packet" }, onclick: () => exportSnapshotRestorePacket(reviewPacket) }, h("span", { html: icon("download", 15) }), "Export packet"),
          h("button", { class: "btn sm ghost", type: "button", title: "Copy snapshot restore review link", "aria-label": "Copy snapshot restore review link", dataset: { snapshotRestoreAction: "copy-link" }, onclick: () => copySnapshotReviewLink(snapshot, "restore-preview") }, h("span", { html: icon("copy", 15) }), "Copy link"))),
      h("label", { class: "field" }, h("span", {}, "Audit comment"), comment)),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close backup restore preview", "aria-label": "Close backup restore preview", dataset: { changesAction: "close-backup-restore-preview" }, onclick: closeDrawer }, "Close"),
      stageBtn,
    ],
  });
}

function snapshotSummaryPanel(snapshot = {}) {
  return h("dl", { class: "kv" },
    kv("Snapshot", snapshot.id || "unknown"),
    kv("Source", backupSnapshotSourceLabel(snapshot)),
    kv("Policy hash", shortHash(snapshot.policySha256 || snapshot.policy_sha256 || "")),
    kv("Created", fmt.absTime(snapshot.createdAt || snapshot.created_at)),
    kv("Comment", snapshot.comment || "(no comment)"));
}

async function exportRunningPolicy() {
  try {
    const run = await api.running();
    downloadPolicy("running", run.version, run.policy || {});
  } catch (e) {
    toast("Export failed", e.message, "bad");
  }
}

async function exportVersionPolicy(v) {
  try {
    const vp = await api.versionPolicy(v.id);
    downloadPolicy("version", v.id, vp.policy || {});
  } catch (e) {
    toast("Export failed", e.message, "bad");
  }
}

function downloadPolicy(source, version, policy) {
  const payload = policyExportEnvelope({ source, version, policy });
  const text = JSON.stringify(payload, null, 2) + "\n";
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: policyExportFilename(source, version) });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  toast("Policy exported", `Downloaded ${source}${version ? " v" + version : ""}.`, "ok");
}

function openImportPolicy(root, initialText = "") {
  const text = h("textarea", {
    class: "input mono",
    spellcheck: "false",
    placeholder: "{\n  \"schemaVersion\": \"phragma.policy.export.v1\",\n  \"policy\": { ... }\n}",
    style: { minHeight: "280px" },
  }, initialText);
  const file = h("input", { class: "input", type: "file", accept: "application/json,.json", onchange: async (e) => {
    const selected = e.target.files?.[0];
    if (!selected) return;
    try { text.value = await selected.text(); }
    catch (err) { toast("Could not read file", err.message, "bad"); }
  } });
  openDrawer({
    title: "Import policy to candidate",
    subtitle: "Replaces the staged candidate only; running policy is unchanged until commit.",
    width: "700px",
    body: h("div", {},
      session.dirty ? h("div", { class: "alert-box warn" },
        h("strong", {}, "This replaces the current candidate. "),
        "Existing staged edits remain safe in the running policy until commit, but the candidate draft will be overwritten.") : null,
      h("label", { class: "field" }, h("span", {}, "JSON file"), file),
      h("label", { class: "field" }, h("span", {}, "Policy JSON"), text),
      h("div", { class: "note" }, "Accepted input: a Phragma export envelope, a REST policy response containing a policy object, or a raw policy object. Preview runs server validation before the candidate is replaced.")),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Cancel policy import", "aria-label": "Cancel policy import", dataset: { changesAction: "cancel-import" }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: "Preview imported policy", "aria-label": "Preview imported policy", dataset: { changesAction: "preview-import" }, onclick: () => previewImportedPolicy(root, text.value) },
        h("span", { html: icon("check", 16) }), "Preview import"),
    ],
  });
}

async function previewImportedPolicy(root, raw) {
  let imported;
  try { imported = parsePolicyImportText(raw); }
  catch (e) { toast("Import rejected", e.message, "bad"); return; }
  openDrawer({
    title: "Validating import",
    subtitle: "Checking the imported policy without replacing the candidate.",
    width: "680px",
    body: h("div", { class: "loading" }, "Running server validation…"),
    footer: [h("button", { class: "btn ghost", type: "button", title: "Return to policy import editor", "aria-label": "Return to policy import editor", dataset: { changesAction: "edit-import-json" }, onclick: () => openImportPolicy(root, raw) }, "Edit JSON")],
  });
  let validation;
  try {
    validation = await api.validatePolicy(imported);
  } catch (e) {
    openDrawer({
      title: "Import validation failed",
      subtitle: "The candidate has not been changed.",
      width: "680px",
      body: h("div", { class: "alert-box bad" }, e.message),
      footer: [
        h("button", { class: "btn ghost", type: "button", title: "Close import validation failure", "aria-label": "Close import validation failure", dataset: { changesAction: "close-import-validation" }, onclick: closeDrawer }, "Close"),
        h("button", { class: "btn", type: "button", title: "Return to policy import editor", "aria-label": "Return to policy import editor", dataset: { changesAction: "edit-import-json" }, onclick: () => openImportPolicy(root, raw) }, "Edit JSON"),
      ],
    });
    return;
  }
  const impact = normalizeServerImpact(validation?.impact) || changeImpact(session.running, imported);
  openImportPreview(root, raw, imported, validation, impact);
}

function openImportPreview(root, raw, imported, validation, impact) {
  const stats = policyStats(imported);
  const valid = Boolean(validation?.valid);
  const lines = diffLines(session.running, imported);
  const changed = lines.some((l) => l.t !== "ctx");
  openDrawer({
    title: "Import preview",
    subtitle: "Review server validation and impact before replacing the staged candidate.",
    width: "760px",
    body: h("div", {},
      session.dirty ? h("div", { class: "alert-box warn" },
        h("strong", {}, "This will replace the current candidate. "),
        "The running firewall is unchanged until commit, but existing staged edits will be overwritten.") : null,
      h("div", { class: "preflight-summary" },
        h("div", {}, h("span", {}, "Imported policy"), h("strong", {}, `${stats.rules} rules`), h("small", {}, `${stats.zones} zones, ${stats.objects} objects`)),
        h("div", {}, h("span", {}, "Validation"), valid ? pill("passed", "ok") : pill("failed", "bad")),
        h("div", {}, h("span", {}, "Impact"), pill(impact.level, impact.level === "high" ? "bad" : impact.level === "medium" ? "warn" : "ok")),
        h("div", {}, h("span", {}, "Candidate"), pill("unchanged", "neutral"))),
      renderValidationEvidence(validation, {
        validText: "Imported policy validated successfully. Engine syntax checks passed and the existing candidate has not been changed.",
        invalidLead: "Fix these errors before staging:",
      }),
      h("div", { class: "impact-section-head" },
        h("strong", {}, "Commit impact if staged"),
        h("span", {}, `${impact.items.length} item${impact.items.length === 1 ? "" : "s"}`)),
      h("div", { class: "impact-list impact-list-scroll" }, impact.items.map((it) =>
        h("div", { class: "impact-row " + it.level },
          h("div", {}, pill(it.level, it.level === "high" ? "bad" : it.level === "medium" ? "warn" : "neutral")),
          h("div", {}, h("strong", {}, it.title), h("span", {}, it.detail))))),
      h("details", { class: "diff-details" },
        h("summary", {}, "Diff against running policy"),
        changed ? renderDiffLines(lines)
          : h("div", { class: "alert-box ok" }, "Imported policy matches the running policy."))),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Cancel policy import preview", "aria-label": "Cancel policy import preview", dataset: { changesAction: "cancel-import-preview" }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn", type: "button", title: "Return to policy import editor", "aria-label": "Return to policy import editor", dataset: { changesAction: "edit-import-json" }, onclick: () => openImportPolicy(root, raw) }, "Edit JSON"),
      h("button", { class: "btn primary", type: "button", title: "Stage imported policy as candidate", "aria-label": "Stage imported policy as candidate", dataset: { changesAction: "stage-import" }, disabled: !valid, onclick: () => stageImportedPolicy(root, imported) },
        h("span", { html: icon("upload", 16) }), "Stage import"),
    ],
  });
}

async function stageImportedPolicy(root, imported) {
  try {
    await session.apply((draft) => replacePolicyDraft(draft, imported));
    closeDrawer();
    toast("Policy imported", "Imported policy is staged as the candidate. Validate and commit to apply.", "ok");
    await paint(root);
  } catch (e) {
    toast("Import failed", e.message, "bad");
  }
}

function policyStats(policy = {}) {
  const count = (xs) => Array.isArray(xs) ? xs.length : 0;
  return {
    zones: count(policy.zones),
    rules: count(policy.rules),
    objects: count(policy.addresses) + count(policy.services) + count(policy.applications),
  };
}

function openRoutedVersionDiff(v, run) {
  setVersionDrawerState(v.id, "diff");
  showDiff(v, run, { routeBacked: true });
}

function openRoutedVersionRollback(v, root) {
  setVersionDrawerState(v.id, "rollback");
  rollback(v, root, { routeBacked: true });
}

function maybeOpenVersionDrawer(list = [], run = {}, root) {
  if (!versionRoute.version || !versionRoute.drawer) return;
  const selected = list.find((item) => String(item.id) === versionRoute.version);
  if (!selected) return;
  setTimeout(() => {
    if (!versionRoute.version || String(selected.id) !== versionRoute.version) return;
    if (versionRoute.drawer === "diff") {
      showDiff(selected, run, { routeBacked: true });
      return;
    }
    if (Number(selected.id) === Number(run.version)) {
      toast("Rollback unavailable", "The selected version is already running.", "warn");
      clearVersionDrawerState();
      return;
    }
    rollback(selected, root, { routeBacked: true });
  }, 0);
}

async function showDiff(v, run, opts = {}) {
  const diff = await loadVersionDiff(v.id, run.policy || {});
  openDrawer({
    title: `Diff: ${diff.fromLabel} -> ${diff.toLabel}`,
    subtitle: diff.changed ? "Lines that would change if you roll back to this version" : "Identical to the running policy",
    width: "720px",
    onClose: opts.routeBacked ? clearVersionDrawerState : null,
    body: h("div", {},
      diff.source === "fallback" ? h("div", { class: "alert-box warn" }, "Diff API unavailable; showing local policy diff.") : null,
      diff.changed ? renderDiffLines(diff.lines) : h("div", { class: "alert-box ok" }, "This version matches the running policy.")),
    footer: [h("button", { class: "btn ghost", type: "button", title: `Close diff for version ${v.id}`, "aria-label": `Close diff for version ${v.id}`, dataset: { changesAction: "close-version-diff" }, onclick: closeDrawer }, "Close")],
  });
}

async function rollback(v, root, opts = {}) {
  openDrawer({
    title: `Preparing rollback to v${v.id}`,
    subtitle: "Validating the historical policy and runtime posture before live apply.",
    width: "620px",
    onClose: opts.routeBacked ? clearVersionDrawerState : null,
    body: h("div", { class: "loading" }, "Running rollback preflight…"),
    footer: [h("button", { class: "btn ghost", type: "button", title: `Cancel rollback to version ${v.id}`, "aria-label": `Cancel rollback to version ${v.id}`, dataset: { changesAction: "cancel-rollback-preflight" }, onclick: closeDrawer }, "Cancel")],
  });
  let vp;
  try {
    vp = await api.versionPolicy(v.id);
  } catch (e) {
    if (opts.routeBacked && !versionRouteMatches(v.id, "rollback")) return;
    replaceVersionDrawer(() => openDrawer({
        title: "Rollback preflight failed",
        subtitle: "The running firewall has not been changed.",
        width: "620px",
        onClose: opts.routeBacked ? clearVersionDrawerState : null,
        body: h("div", { class: "alert-box bad" }, e.message),
        footer: [h("button", { class: "btn ghost", type: "button", title: "Close rollback preflight failure", "aria-label": "Close rollback preflight failure", dataset: { changesAction: "close-rollback-preflight" }, onclick: closeDrawer }, "Close")],
      }));
    return;
  }
  if (opts.routeBacked && !versionRouteMatches(v.id, "rollback")) return;
  const target = vp.policy || {};
  const [validationResult, runtimePreflightResult, statusResult, releaseResult] = await Promise.allSettled([
    api.validatePolicy(target),
    api.runtimePreflight({ targetPolicy: target, runningPolicy: session.running, operation: "rollback" }),
    api.status(),
    api.releaseAcceptanceStatus(),
  ]);
  if (opts.routeBacked && !versionRouteMatches(v.id, "rollback")) return;
  const validation = validationResult.status === "fulfilled" ? validationResult.value : null;
  const validationError = validationResult.status === "rejected" ? validationResult.reason : null;
  const runtimePreflight = runtimePreflightResult.status === "fulfilled" ? runtimePreflightResult.value : null;
  const runtimePreflightError = runtimePreflightResult.status === "rejected" ? runtimePreflightResult.reason : null;
  const status = statusResult.status === "fulfilled" ? statusResult.value : null;
  const statusError = statusResult.status === "rejected" ? statusResult.reason : null;
  const releaseAcceptance = releaseResult.status === "fulfilled" ? releaseResult.value : null;
  const releaseError = releaseResult.status === "rejected" ? releaseResult.reason : null;
  const impact = normalizeServerImpact(validation?.impact) || changeImpact(session.running, target);
  const runtime = commitRuntimePreflight({
    preflight: runtimePreflight,
    status,
    error: statusError || runtimePreflightError,
    draftPolicy: target,
    runningPolicy: session.running,
    operation: "rollback",
  });
  const strictEvidence = strictUiEvidenceModel({
    operation: "rollback",
    validation,
    validationError,
    runtime,
    releaseAcceptance,
    releaseError,
  });
  const diff = await loadVersionDiff(v.id, session.running, target);
  replaceVersionDrawer(() => openRollbackReview(root, v, validation, validationError, impact, runtime, diff, { ...opts, releaseAcceptance, strictEvidence }));
}

function openRollbackReview(root, v, validation, validationError, impact, runtime, diff, opts = {}) {
  const valid = Boolean(!validationError && validation?.valid);
  const comment = h("textarea", { class: "input", placeholder: "Reason for this rollback", dataset: { changesField: "rollback-comment" } }, defaultRollbackComment(v));
  const acknowledge = h("input", { type: "checkbox", dataset: { changesAck: "rollback-runtime-risk" } });
  const needsRiskAck = impact.level === "high";
  const needsAck = needsRiskAck || runtime.requiresAck;
  const lifecycle = changesLifecycleGuidanceModel({
    scenario: "rollback",
    candidateDirty: session.dirty,
    runningVersion: session.runningVersion,
    targetVersion: v.id,
    validationBlocked: Boolean(validationError || !validation?.valid),
    runtimeBlocked: runtime.label === "not ready" || runtime.cls === "bad",
  });
  const blocked = () => Boolean(!valid || (needsAck && !acknowledge.checked));
  const rollbackBtn = h("button", { class: "btn danger", type: "button", title: `Roll back to version ${v.id}`, "aria-label": `Roll back to version ${v.id}`, dataset: { changesSubmit: "rollback" }, disabled: blocked(), onclick: async (e) => {
    const auditComment = comment.value.trim();
    if (!auditComment) {
      toast("Comment required", "Add an audit comment before rolling back.", "warn");
      comment.focus();
      return;
    }
    if (needsAck && !acknowledge.checked) {
      toast("Review required", "Acknowledge the rollback impact and runtime posture before applying.", "warn");
      return;
    }
    const btn = e.target.closest("button");
    btn.disabled = true;
    btn.textContent = "Rolling back…";
    try {
      const r = await api.rollback(
        v.id,
        auditComment,
        needsRiskAck && acknowledge.checked,
        runtime.requiresAck && acknowledge.checked,
      );
      closeDrawer();
      toast("Rolled back", `Re-applied v${v.id} as new version v${r.version}.`, "ok");
      await session.load();
      paint(root);
    } catch (err) {
      btn.disabled = false;
      btn.textContent = "Roll back";
      toast("Rollback failed", err.message, "bad");
    }
  } }, h("span", { html: icon("rollback", 16) }), "Roll back");
  acknowledge.onchange = () => { rollbackBtn.disabled = blocked(); };

  openDrawer({
    title: `Rollback review: v${v.id}`,
    subtitle: "Validate, inspect impact, then re-apply this version as a new live commit.",
    width: "760px",
    onClose: opts.routeBacked ? clearVersionDrawerState : null,
    body: h("div", {},
      h("div", { class: "preflight-summary" },
        h("div", {}, h("span", {}, "Target version"), h("strong", {}, "v" + v.id), h("small", {}, v.comment || "(no comment)")),
        h("div", {}, h("span", {}, "Validation"), validationError ? pill("error", "bad") : valid ? pill("passed", "ok") : pill("failed", "bad")),
        h("div", {}, h("span", {}, "Impact"), pill(impact.level, impact.level === "high" ? "bad" : impact.level === "medium" ? "warn" : "ok")),
        h("div", {}, h("span", {}, "Runtime"), pill(runtime.label, runtime.cls))),
      versionRecoveryPanel(v, session.runningVersion),
      lifecycleGuidancePanel(lifecycle, { validation, validationError, runtime, impact, diff, releaseAcceptance: opts.releaseAcceptance, strictEvidence: opts.strictEvidence, decision: "rollback-review" }),
      strictUiEvidencePanel(opts.strictEvidence || strictUiEvidenceModel({ operation: "rollback", validation, validationError, runtime, releaseAcceptance: opts.releaseAcceptance })),
      validationError ? h("div", { class: "alert-box bad" }, validationError.message) :
        renderValidationEvidence(validation, {
          validText: "Rollback target validated successfully. Engine syntax checks passed.",
          invalidLead: "This version cannot be applied until the validation errors are resolved:",
          emptyError: "Rollback target validation failed without a detailed error.",
        }),
      rollbackRuntimePanel(runtime),
      h("div", { class: "impact-section-head" },
        h("strong", {}, "Rollback impact"),
        h("span", {}, `${impact.items.length} item${impact.items.length === 1 ? "" : "s"}`)),
      h("div", { class: "impact-list impact-list-scroll" }, impact.items.map((it) =>
        h("div", { class: "impact-row " + it.level },
          h("div", {}, pill(it.level, it.level === "high" ? "bad" : it.level === "medium" ? "warn" : "neutral")),
          h("div", {}, h("strong", {}, it.title), h("span", {}, it.detail))))),
      h("details", { class: "diff-details" },
        h("summary", {}, `Diff: ${diff.fromLabel} -> ${diff.toLabel}`),
        diff.source === "fallback" ? h("div", { class: "alert-box warn" }, "Diff API unavailable; showing local policy diff.") : null,
        diff.changed ? renderDiffLines(diff.lines) : h("div", { class: "alert-box ok" }, "This version matches the running policy.")),
      needsAck ? h("label", { class: "ack-row" },
        acknowledge,
        h("span", {}, rollbackAckText(impact, runtime))) : null,
      h("label", { class: "field" }, h("span", {}, "Audit comment"), comment)),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: `Cancel rollback to version ${v.id}`, "aria-label": `Cancel rollback to version ${v.id}`, dataset: { changesAction: "cancel-rollback" }, onclick: closeDrawer }, "Cancel"),
      rollbackBtn,
    ],
  });
}

function blockedLifecycleScenario(validationError, validation, runtime) {
  if (validationError || !validation?.valid || runtime.label === "not ready" || runtime.cls === "bad") return "strict-blocked";
  return "candidate";
}

function versionRecoveryPanel(v, runningVersion = 0) {
  const meta = versionRecoveryModel(v, runningVersion);
  return h("div", { class: "profile-strip", style: { margin: "14px 0" } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Recovery metadata"),
      h("span", {}, meta.recoveryLabel)),
    h("dl", { class: "kv" },
      kv("State", meta.state),
      kv("Activated", meta.displayTime ? fmt.absTime(meta.displayTime) : "—"),
      kv("Artifact set", meta.artifactLabel),
      meta.sourceVersion > 0 ? kv("Source", "v" + meta.sourceVersion) : null,
      kv("Detail", meta.stateDetail || "—")),
    meta.artifacts.length ? h("details", { class: "diff-details" },
      h("summary", {}, `${meta.artifacts.length} rendered artifact${meta.artifacts.length === 1 ? "" : "s"}`),
      h("div", { class: "impact-list impact-list-scroll" }, meta.artifacts.map((artifact) =>
        h("div", { class: "impact-row neutral" },
          h("div", {}, pill(artifact.engine || "engine", "neutral")),
          h("div", {},
            h("strong", {}, artifact.name || artifact.engine || "artifact"),
            h("span", { class: "mono" }, artifact.sha256 ? `sha256:${artifact.sha256.slice(0, 12)}` : "no hash"),
            h("span", { class: "muted" }, `${artifact.sizeBytes || 0} bytes`)))))) : null);
}

function replaceVersionDrawer(fn) {
  preserveVersionDrawerRoute = true;
  try {
    fn();
  } finally {
    preserveVersionDrawerRoute = false;
  }
}

async function loadVersionDiff(version, runningPolicy, targetPolicy = null) {
  try {
    const data = await api.policyDiff({
      fromSource: "POLICY_SOURCE_RUNNING",
      toSource: "POLICY_SOURCE_VERSION",
      toVersion: version,
    });
    const labels = policyDiffLabels(data, "running policy", "version " + version);
    return {
      ...labels,
      lines: normalizePolicyDiffLines(data.lines || []),
      changed: Boolean(data.changed),
      source: "api",
    };
  } catch (e) {
    let target = targetPolicy;
    if (!target) {
      try {
        const vp = await api.versionPolicy(version);
        target = vp.policy || {};
      } catch (err) {
        toast("Failed", err.message, "bad");
        target = {};
      }
    }
    const lines = diffLines(runningPolicy || {}, target || {});
    return {
      fromLabel: "running policy",
      toLabel: "version " + version,
      lines,
      changed: lines.some((l) => l.t !== "ctx"),
      source: "fallback",
      error: e.message || String(e),
    };
  }
}

function defaultRollbackComment(v) {
  const suffix = v.comment ? `: ${v.comment}` : "";
  return `Rollback to version ${v.id}${suffix}`;
}

function rollbackRuntimePanel(runtime) {
  if (!runtime.items.length) {
    return h("div", { class: "alert-box ok" }, runtime.detail);
  }
  return h("div", { class: "runtime-preflight" },
    h("div", { class: "alert-box " + runtime.cls },
      h("strong", {}, runtime.detail),
      h("div", { class: "note" }, "Review the action queue before applying this rollback.")),
    h("div", { class: "impact-list impact-list-scroll" }, runtime.items.map((it) =>
      runtimePreflightActionRow(it, "rollback"))));
}

function rollbackAckText(impact, runtime) {
  if (impact.level === "high" && runtime.requiresAck) {
    return "I reviewed the high-risk rollback impact and the system preflight warnings, and intend to apply this version.";
  }
  if (runtime.requiresAck) {
    return "I reviewed the system preflight warnings and intend to apply this rollback.";
  }
  return "I reviewed the high-risk rollback impact and intend to apply it to the live firewall.";
}

async function audit(wrap) {
  clear(wrap);
  const result = h("div", {});
  wrap.appendChild(auditFilterBar(wrap));
  wrap.appendChild(result);
  let data;
  let integrity;
  let retainedReports = [];
  try { data = await api.audit(auditRequest()); } catch (e) { result.appendChild(h("div", { class: "alert-box bad" }, e.message)); return; }
  try { integrity = await api.auditVerify(); } catch (e) { integrity = { ok: false, detail: e.message || "audit verification unavailable" }; }
  try { retainedReports = (await api.complianceReports({ limit: 5 })).reports || []; } catch (e) { retainedReports = [{ error: e.message || "retained reports unavailable" }]; }
  const entries = data.entries || [];
  result.appendChild(auditIntegrityBar(integrity));
  result.appendChild(retainedComplianceReportsPanel(retainedReports));
  if (!entries.length) { result.appendChild(emptyState("clock", "No audit entries", "Configuration actions matching these filters are recorded here.")); return; }
  const rows = entries.map((e) => h("tr", { ...keyboardRowAttrs(() => openRoutedAuditEntry(e, integrity), { label: `Open audit entry ${auditEntryKey(e)}` }), dataset: { auditEntryRow: auditEntryKey(e) || String(e.id || "") } },
    labeledCell("#", { class: "muted" }, e.id),
    labeledCell("Action", {}, actionPill(e.action)),
    labeledCell("Detail", { class: "data-wrap" }, e.detail || h("span", { class: "muted" }, "—")),
    labeledCell("Actor", { class: "mono", title: authTitle(e) }, actorLabel(e)),
    labeledCell("Version", {}, e.version && Number(e.version) ? h("span", { class: "tag" }, "v" + e.version) : h("span", { class: "muted" }, "—")),
    labeledCell("Hash", { class: "mono muted", title: auditHashTitle(e) }, auditHashLabel(e)),
    labeledCell("Time", { class: "muted", title: fmt.absTime(e.time) }, fmt.relTime(e.time))));
  result.appendChild(h("div", { class: "toolbar" },
    h("div", { class: "note" }, `${entries.length} matching entr${entries.length === 1 ? "y" : "ies"}`),
    auditLogHandoffActions(entries, integrity)));
  result.appendChild(evidenceToolbar({
    surface: "audit-log",
    title: "Audit evidence",
    summary: "Filtered append-only audit entries with integrity hashes.",
    request: auditRequest,
    rows: () => entries,
    columns: AUDIT_EVIDENCE_COLUMNS,
    route: () => location.hash || "#/changes?tab=audit",
    apiPath: "/v1/audit",
    cliCommand: () => auditCliCommandFromRequest(auditRequest()),
  }));
  result.appendChild(h("div", { class: "table-wrap" }, responsiveTable(["#", "Action", "Detail", "Actor", "Version", "Hash", "Time"], rows, { className: "audit-table" })));
  maybeOpenAuditReport(entries, integrity);
  maybeOpenAuditEntry(entries, integrity);
}

function retainedComplianceReportsPanel(reports = []) {
  if (reports.length && reports[0]?.error) {
    return h("div", { class: "alert-box warn", dataset: { complianceReports: "unavailable" } },
      h("strong", {}, "Server-retained reports unavailable"),
      h("div", { class: "note" }, reports[0].error));
  }
  const rows = reports.slice(0, 5).map((report) => h("div", { class: "impact-row", dataset: { complianceReportId: report.id || "" } },
    h("div", {}, pill(report.signed ? "signed" : "unsigned", report.signed ? "ok" : "warn")),
    h("div", {},
      h("strong", {}, report.title || report.profileLabel || "Compliance report"),
      h("span", {}, `${report.profileLabel || report.profile || "Operational"} · ${report.auditEntryCount || 0} audit · ${report.versionCount || 0} versions · ${report.systemLogEntryCount || 0} logs`),
      h("span", { class: "muted mono" }, report.payloadSha256 ? `sha256:${String(report.payloadSha256).slice(0, 16)}` : "no payload hash")),
    h("div", { class: "flex wrap" },
      h("button", { class: "btn sm ghost", type: "button", title: "Export retained compliance report JSON", "aria-label": "Export retained compliance report JSON", dataset: { complianceReportAction: "export", complianceReportId: report.id || "" }, onclick: () => exportServerComplianceReport(report) }, h("span", { html: icon("download", 14) }), "Export"))));
  return h("div", { class: "profile-strip", dataset: { complianceReports: "server-retained" } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Server-retained compliance reports"),
      h("span", {}, reports.length ? "metadata from retained report records" : "none generated yet")),
    reports.length
      ? h("div", { class: "impact-list" }, rows)
      : h("div", { class: "note" }, "Generate a report from the audit builder to retain audit, version, and local log metadata server-side. Reports remain unsigned until custody hardening is complete."));
}

function maybeOpenAuditReport(entries = [], integrity = {}) {
  if (auditDrawer !== "report" || auditFilters.entry) return;
  openAuditReportDrawer(entries, integrity, { routeBacked: true });
}

function openRoutedAuditReport(entries = [], integrity = {}) {
  auditDrawer = "report";
  syncChangesRoute();
  openAuditReportDrawer(entries, integrity, { routeBacked: true });
}

function openAuditReportDrawer(entries = [], integrity = {}, opts = {}) {
  const selectedProfile = normalizeAuditComplianceProfile(opts.profile);
  const packet = auditReportPacket(entries, {
    filters: auditFilters,
    request: auditRequest(),
    integrity,
    route: currentRoute(),
    profile: selectedProfile,
  });
  const profileSelect = h("select", {
    class: "input",
    style: { maxWidth: "240px" },
    dataset: { auditComplianceProfile: "true" },
    onchange: (e) => openAuditReportDrawer(entries, integrity, { ...opts, profile: e.target.value }),
  }, AUDIT_COMPLIANCE_PROFILES.map((profile) =>
    h("option", { value: profile.value, selected: profile.value === selectedProfile }, profile.label)));
  openDrawer({
    title: "Audit report builder",
    subtitle: "Browser-generated compliance report from the current audit filters",
    width: "760px",
    onClose: opts.routeBacked ? clearAuditReportState : null,
    body: h("div", { dataset: { auditReportDrawer: "true" } },
      h("div", { class: "flex wrap", style: { marginBottom: "16px" } },
        pill(packet.integrity.ok ? "integrity verified" : "integrity review", packet.integrity.ok ? "ok" : "warn", true),
        pill("unsigned browser report", "warn", true),
        h("span", { class: "tag" }, `${packet.includedEntryCount} entries`)),
      h("div", { class: "alert-box warn" },
        h("strong", {}, "Operational report only"),
        h("div", { class: "note" }, "This browser-generated JSON is not signed, server-stored, or retention-enforced.")),
      h("label", { class: "field" },
        h("span", {}, "Compliance profile"),
        profileSelect,
        h("small", {}, "Profiles group the visible audit window into auditor-oriented controls without changing source data.")),
      h("dl", { class: "kv" },
        kv("Schema", packet.schemaVersion),
        kv("Profile", packet.compliance.profileLabel),
        kv("Route", packet.route),
        kv("API replay", packet.replay.api),
        kv("Verify replay", packet.replay.verifyApi),
        kv("CLI replay", packet.replay.cli),
        kv("Integrity", packet.integrity.summary),
        kv("Latest hash", packet.integrity.latestEntryHash || "—")),
      h("div", { class: "profile-strip", dataset: { auditComplianceSummary: "true" } },
        h("div", { class: "profile-strip-head" },
          h("strong", {}, "Compliance coverage"),
          h("span", {}, `${packet.compliance.passed}/${packet.compliance.controlCount} controls passed; ${packet.compliance.review} need review`)),
        h("div", { class: "impact-list impact-list-scroll" }, packet.compliance.controls.map((control) =>
          h("div", { class: "impact-row " + (control.status === "passed" ? "ok" : "warn"), dataset: { auditComplianceControl: control.id } },
            h("div", {}, pill(control.status, control.status === "passed" ? "ok" : "warn")),
            h("div", {},
              h("strong", {}, control.label),
              h("span", {}, control.detail),
              h("span", { class: "muted" }, control.nextAction)))))),
      h("div", { class: "profile-strip" },
        h("div", { class: "profile-strip-head" },
          h("strong", {}, "Current filters"),
          h("span", {}, "normalized and redacted before export")),
        h("pre", { class: "mono audit-detail-pre" }, JSON.stringify(packet.filters, null, 2))),
      h("div", { class: "profile-strip" },
        h("div", { class: "profile-strip-head" },
          h("strong", {}, "Included entry hashes"),
          h("span", {}, "bounded visible audit rows")),
        h("pre", { class: "mono audit-detail-pre" }, packet.entryHashes.length ? packet.entryHashes.join("\n") : "No entry hashes returned."))),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close audit report builder", "aria-label": "Close audit report builder", dataset: { auditAction: "close-report" }, onclick: closeDrawer }, "Close"),
      h("button", { class: "btn", type: "button", title: "Copy audit report JSON", "aria-label": "Copy audit report JSON", dataset: { auditAction: "copy-report" }, onclick: () => copyAuditReport(packet) }, h("span", { html: icon("copy", 16) }), "Copy report"),
      h("button", { class: "btn", type: "button", title: "Export audit report JSON", "aria-label": "Export audit report JSON", dataset: { auditAction: "export-report" }, onclick: () => exportAuditReport(packet) }, h("span", { html: icon("download", 16) }), "Export preview"),
      h("button", { class: "btn primary", type: "button", title: "Generate retained server-side compliance report", "aria-label": "Generate retained server-side compliance report", dataset: { auditAction: "generate-server-report" }, onclick: () => createServerComplianceReport(selectedProfile) }, h("span", { html: icon("check", 16) }), "Generate server report"),
    ],
  });
}

function clearAuditReportState() {
  if (auditDrawer !== "report") return;
  auditDrawer = "";
  syncChangesRoute();
}

function maybeOpenAuditEntry(entries = [], integrity = {}) {
  if (!auditFilters.entry) return;
  const entry = entries.find((item) => auditEntryKey(item) === auditFilters.entry);
  if (!entry) return;
  openAuditEntryDrawer(entry, integrity, { routeBacked: true });
}

function openRoutedAuditEntry(entry, integrity = {}) {
  auditFilters = normalizeAuditFilters({ ...auditFilters, entry: auditEntryKey(entry) });
  syncChangesRoute();
  openAuditEntryDrawer(entry, integrity, { routeBacked: true });
}

function openAuditEntryDrawer(entry = {}, integrity = {}, opts = {}) {
  const packet = auditEntryHandoffPacket(entry, { route: currentRoute(), integrity });
  openDrawer({
    title: `Audit entry ${auditEntryKey(entry)}`,
    subtitle: entry.action || "audit action",
    width: "680px",
    onClose: opts.routeBacked ? clearAuditEntryState : null,
    body: h("div", { dataset: { auditEntryDrawer: "true" } },
      h("div", { class: "flex wrap", style: { marginBottom: "16px" } },
        actionPill(entry.action),
        entry.version && Number(entry.version) ? h("span", { class: "tag" }, "v" + entry.version) : null,
        integrity.ok ? pill("integrity verified", "ok", true) : pill("integrity review", "warn", true)),
      h("dl", { class: "kv" },
        kv("ID", entry.id || "—"),
        kv("Action", entry.action || "—"),
        kv("Actor", actorLabel(entry)),
        kv("Auth source", entry.authSource || entry.auth_source || "—"),
        kv("Version", entry.version && Number(entry.version) ? "v" + entry.version : "—"),
        kv("Time", fmt.absTime(entry.time)),
        kv("Entry hash", entry.entryHash || "—"),
        kv("Previous hash", entry.previousHash || "genesis"),
        kv("Integrity", auditIntegritySummary(integrity))),
      h("div", { class: "profile-strip" },
        h("div", { class: "profile-strip-head" },
          h("strong", {}, "Audit detail"),
          h("span", {}, "append-only evidence")),
        h("pre", { class: "mono audit-detail-pre" }, entry.detail || "—")),
      h("div", { class: "flex wrap", style: { marginTop: "16px" } },
        h("button", { class: "btn", type: "button", title: "Pin audit handoff to investigation case", "aria-label": "Pin audit handoff to investigation case", dataset: { auditAction: "pin-handoff" }, onclick: () => pinAuditHandoff(packet) }, h("span", { html: icon("inbox", 16) }), "Pin to case"),
        h("button", { class: "btn", type: "button", title: "Copy audit handoff packet", "aria-label": "Copy audit handoff packet", dataset: { auditAction: "copy-handoff" }, onclick: () => copyAuditHandoff(packet) }, h("span", { html: icon("copy", 16) }), "Copy handoff"),
        h("button", { class: "btn", type: "button", title: "Export audit handoff JSON", "aria-label": "Export audit handoff JSON", dataset: { auditAction: "export-handoff" }, onclick: () => exportAuditHandoff(packet) }, h("span", { html: icon("download", 16) }), "Export JSON"))),
    footer: [
      h("button", { class: "btn primary", type: "button", title: "Close audit entry", "aria-label": "Close audit entry", dataset: { auditAction: "close-entry" }, onclick: closeDrawer }, "Close"),
    ],
  });
}

function clearAuditEntryState() {
  if (!auditFilters.entry) return;
  auditFilters = normalizeAuditFilters({ ...auditFilters, entry: "" });
  syncChangesRoute();
}

function auditIntegrityBar(integrity = {}) {
  const ok = Boolean(integrity.ok);
  return h("div", { class: "toolbar" },
    pill(ok ? "integrity verified" : "integrity failed", ok ? "ok" : "bad", true),
    h("div", { class: "note" }, auditIntegritySummary(integrity)));
}

function auditLogHandoffActions(entries = [], integrity = {}) {
  const packet = () => auditLogHandoffPacket(entries, {
    route: currentRoute(),
    request: auditRequest(),
    integrity,
  });
  return h("div", { class: "flex wrap" },
    h("button", { class: "btn sm ghost", type: "button", title: "Pin filtered audit log to investigation case", "aria-label": "Pin filtered audit log to investigation case", dataset: { auditAction: "pin-filtered-log" }, onclick: () => pinAuditHandoff(packet()) }, h("span", { html: icon("inbox", 15) }), "Pin filtered log"),
    h("button", { class: "btn sm ghost", type: "button", title: "Copy filtered audit log handoff", "aria-label": "Copy filtered audit log handoff", dataset: { auditAction: "copy-filtered-log" }, onclick: () => copyAuditHandoff(packet()) }, h("span", { html: icon("copy", 15) }), "Copy filtered log"),
    h("button", { class: "btn sm ghost", type: "button", title: "Export filtered audit log JSON", "aria-label": "Export filtered audit log JSON", dataset: { auditAction: "export-filtered-log" }, onclick: () => exportAuditHandoff(packet()) }, h("span", { html: icon("download", 15) }), "Export filtered log"),
    h("button", { class: "btn sm ghost", type: "button", title: "Build audit compliance report", "aria-label": "Build audit compliance report", dataset: { auditAction: "open-report-builder" }, onclick: () => openRoutedAuditReport(entries, integrity) }, h("span", { html: icon("clock", 15) }), "Build report"));
}

export function auditIntegritySummary(integrity = {}) {
  const latest = integrity.latestEntryHash ? ` latest ${shortAuditHash(integrity.latestEntryHash)}` : "";
  const count = Number(integrity.entryCount || 0);
  return `${count} audit entr${count === 1 ? "y" : "ies"} checked${latest}. ${integrity.detail || ""}`;
}

export function auditReportPacket(entries = [], {
  filters = {},
  request,
  integrity = {},
  route = "#/changes?tab=audit",
  profile = "operational",
  generatedAt = new Date().toISOString(),
} = {}) {
  const safeFilters = safeAuditReportFilters(filters);
  const req = request || auditRequestFromFilters(safeFilters);
  const includedEntries = (Array.isArray(entries) ? entries : []).slice(0, Number(req.limit || 300) || 300).map(auditReportEntry).filter(Boolean);
  const entryHashes = includedEntries.map((entry) => entry.entryHash).filter(Boolean);
  const compliance = auditComplianceSummary(includedEntries, integrity, profile);
  return {
    schemaVersion: AUDIT_REPORT_SCHEMA,
    generatedAt,
    source: "browser-generated",
    unsigned: true,
    custody: {
      serverStored: false,
      signed: false,
      retentionEnforced: false,
      note: "Unsigned browser-generated operational report; production signing, retention, and custody remain hardening work.",
    },
    route: safeAuditReportText(route),
    filters: safeFilters,
    request: {
      method: "GET",
      path: "/v1/audit",
      query: req,
    },
    replay: {
      api: auditApiPathFromRequest(req),
      cli: auditCliCommandFromRequest(req),
      verifyApi: "GET /v1/audit/verify",
    },
    integrity: {
      ok: Boolean(integrity.ok),
      entryCount: Number(integrity.entryCount || 0),
      latestEntryHash: safeHashText(integrity.latestEntryHash),
      detail: safeAuditReportText(integrity.detail || ""),
      summary: auditIntegritySummary(integrity),
    },
    compliance,
    includedEntryCount: includedEntries.length,
    entryHashes,
    entries: includedEntries,
    notes: [
      "Report includes the bounded audit entries currently visible for the active filters.",
      "Use the replay commands to regenerate source data before treating this as evidence.",
      "This report is not a signed custody artifact.",
    ],
  };
}

export function auditComplianceSummary(entries = [], integrity = {}, profile = "operational") {
  const list = Array.isArray(entries) ? entries : [];
  const normalizedProfile = normalizeAuditComplianceProfile(profile);
  const profileLabel = auditComplianceProfileLabel(normalizedProfile);
  const matching = list.filter((entry) => auditActionMatchesComplianceProfile(entry.action, normalizedProfile));
  const reviewSet = matching.length ? matching : list;
  const attributed = reviewSet.filter((entry) => entry.actor || entry.actorRole || entry.authSource);
  const versions = reviewSet.filter((entry) => entry.version);
  const hashes = reviewSet.filter((entry) => entry.entryHash);
  const controls = [
    complianceControl("audit-integrity", "Audit chain integrity", Boolean(integrity.ok), auditIntegritySummary(integrity), "Run GET /v1/audit/verify before export."),
    complianceControl("profile-coverage", `${profileLabel} coverage`, matching.length > 0, `${matching.length}/${list.length} visible entries match the ${profileLabel.toLowerCase()} profile.`, `Filter audit actions for ${profileLabel.toLowerCase()} evidence before export.`),
    complianceControl("actor-attribution", "Actor attribution", !reviewSet.length || attributed.length === reviewSet.length, `${attributed.length}/${reviewSet.length} reviewed entries include actor, role, or auth-source context.`, "Review entries missing actor context before CAB evidence use."),
    complianceControl("change-traceability", "Change traceability", !reviewSet.length || versions.length > 0, `${versions.length}/${reviewSet.length} reviewed entries include a policy version link.`, "Use version-filtered audit replay for a specific commit window."),
    complianceControl("hash-evidence", "Hash evidence", !reviewSet.length || hashes.length === reviewSet.length, `${hashes.length}/${reviewSet.length} reviewed entries include entry hashes.`, "Regenerate with --hashes and verify the audit chain."),
    complianceControl("custody-boundary", "Custody boundary", false, "Browser report is unsigned and not server-retained.", "Use production signing and retention controls during the hardening pass."),
  ];
  return {
    scope: "visible-audit-window",
    generatedBy: "browser-report-builder",
    profile: normalizedProfile,
    profileLabel,
    matchedEntryCount: matching.length,
    controlCount: controls.length,
    passed: controls.filter((control) => control.status === "passed").length,
    review: controls.filter((control) => control.status === "review").length,
    controls,
  };
}

function normalizeAuditComplianceProfile(profile = "") {
  const value = String(profile || "").trim().toLowerCase();
  return AUDIT_COMPLIANCE_PROFILES.some((item) => item.value === value) ? value : "operational";
}

function auditComplianceProfileLabel(profile = "") {
  return AUDIT_COMPLIANCE_PROFILES.find((item) => item.value === profile)?.label || "Operational";
}

function auditActionMatchesComplianceProfile(action = "", profile = "operational") {
  const value = String(action || "").toLowerCase();
  if (profile === "change-control") {
    return value.includes("commit") || value.includes("rollback") || value.includes("candidate") || value.includes("policy");
  }
  if (profile === "privileged-access") {
    return value.includes("access-") || value.includes("oidc") || value.includes("saml") || value.includes("break-glass") || value.includes("session");
  }
  if (profile === "content-lifecycle") {
    return value.includes("content-package") || value.includes("intel") || value.includes("app-id") || value.includes("threat");
  }
  if (profile === "incident-evidence") {
    return value.includes("packet-capture") || value.includes("threat") || value.includes("exception") || value.includes("investigation");
  }
  return true;
}

function complianceControl(id, label, passed, detail, nextAction) {
  return {
    id,
    label,
    status: passed ? "passed" : "review",
    detail: safeAuditReportText(detail || ""),
    nextAction: safeAuditReportText(nextAction || ""),
  };
}

function auditReportEntry(entry = {}) {
  return {
    id: entry.id == null ? "" : String(entry.id),
    action: safeAuditReportText(entry.action || ""),
    actor: safeAuditReportText(entry.actor || ""),
    actorRole: safeAuditReportText(entry.actorRole || entry.actor_role || ""),
    authSource: safeAuditReportText(entry.authSource || entry.auth_source || ""),
    version: entry.version && Number(entry.version) ? String(Number(entry.version)) : "",
    time: safeAuditReportText(entry.time || ""),
    detail: safeAuditReportText(entry.detail || ""),
    entryHash: safeHashText(entry.entryHash),
    previousHash: safeHashText(entry.previousHash),
  };
}

function safeAuditReportFilters(filters = {}) {
  const normalized = normalizeAuditFilters(filters);
  return {
    query: safeAuditReportText(normalized.query),
    actor: safeAuditReportText(normalized.actor),
    action: normalized.action,
    version: normalized.version,
    since: normalized.since,
    until: normalized.until,
    limit: normalized.limit,
    entry: safeAuditReportText(normalized.entry),
  };
}

function safeAuditReportText(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  if (/(^|[_-])(token|password|passwd|secret|cookie|authorization|api[_-]?key)($|[_-])/i.test(text)) return "[redacted]";
  if (/Bearer\s+[A-Za-z0-9._~+/-]{8,}/i.test(text)) return "[redacted]";
  if (/https?:\/\/[^/\s"']+:[^@\s"']+@/i.test(text)) return "[redacted]";
  if (/(^|[/:])(?:etc|tmp|var|Users|home|private)(?:\/|$)|file:/i.test(text)) return "[redacted]";
  if (/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/.test(text)) return "[redacted]";
  return text.slice(0, 2000);
}

function safeHashText(value) {
  const text = String(value || "").trim();
  return /^[A-Za-z0-9:_-]{1,160}$/.test(text) ? text : "";
}

function auditApiPathFromRequest(req = {}) {
  const params = new URLSearchParams();
  for (const key of ["limit", "actor", "action", "version", "query", "since", "until"]) {
    if (req[key] != null && req[key] !== "") params.set(key, String(req[key]));
  }
  const query = params.toString();
  return "/v1/audit" + (query ? "?" + query : "");
}

function auditFilterBar(wrap) {
  const query = h("input", { class: "input", type: "search", value: auditFilters.query, placeholder: "detail, actor, action" });
  const actor = h("input", { class: "input", value: auditFilters.actor, placeholder: "alice@example.com" });
  const action = h("select", { class: "input" }, AUDIT_ACTION_OPTIONS.map(([value, label]) => auditOption(value, label)));
  action.value = auditFilters.action;
  const version = h("input", { class: "input", type: "number", min: "1", value: auditFilters.version, placeholder: "v" });
  const since = h("input", { class: "input", type: "datetime-local", value: auditFilters.since });
  const until = h("input", { class: "input", type: "datetime-local", value: auditFilters.until });
  const limit = h("select", { class: "input" },
    auditOption("100", "100"),
    auditOption("300", "300"),
    auditOption("500", "500"),
    auditOption("1000", "1000"));
  limit.value = auditFilters.limit;
  const apply = async () => {
    auditFilters = normalizeAuditFilters({
      query: query.value.trim(),
      actor: actor.value.trim(),
      action: action.value,
      version: version.value.trim(),
      since: since.value,
      until: until.value,
      limit: limit.value,
    });
    syncChangesRoute();
    await audit(wrap);
  };
  const submitOnEnter = (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      apply();
    }
  };
  [query, actor, version, since, until].forEach((el) => el.addEventListener("keydown", submitOnEnter));
  return h("div", { class: "audit-filters" },
    h("label", { class: "field" }, h("span", {}, "Search"), query),
    h("label", { class: "field" }, h("span", {}, "Actor"), actor),
    h("label", { class: "field" }, h("span", {}, "Action"), action),
    h("label", { class: "field" }, h("span", {}, "Version"), version),
    h("label", { class: "field" }, h("span", {}, "Since"), since),
    h("label", { class: "field" }, h("span", {}, "Until"), until),
    h("label", { class: "field" }, h("span", {}, "Limit"), limit),
    h("button", { class: "btn primary", type: "button", title: "Apply audit filters", "aria-label": "Apply audit filters", dataset: { auditAction: "apply-filters" }, onclick: apply }, h("span", { html: icon("filter", 16) }), "Apply"),
    h("button", { class: "btn ghost", type: "button", title: "Reset audit filters", "aria-label": "Reset audit filters", dataset: { auditAction: "reset-filters" }, onclick: async () => { auditFilters = defaultAuditFilters(); syncChangesRoute(); await audit(wrap); } }, "Reset"),
    savedFilterControls({ scope: "changes-audit", state: auditFilters, defaults: defaultAuditFilters(), keys: AUDIT_SAVED_FILTER_KEYS, onApply: (next) => applySavedAuditFilter(wrap, next) }));
}

async function applySavedAuditFilter(wrap, next) {
  auditFilters = normalizeAuditFilters({ ...defaultAuditFilters(), ...next });
  syncChangesRoute();
  await audit(wrap);
}

function auditRequest() {
  return auditRequestFromFilters(auditFilters);
}

export function auditRequestFromFilters(filters = {}) {
  const normalized = normalizeAuditFilters(filters);
  const req = { limit: Number(normalized.limit) || 300 };
  for (const key of ["actor", "action", "version", "query"]) {
    if (normalized[key]) req[key] = normalized[key];
  }
  if (normalized.since) req.since = localDateTimeToISOString(normalized.since);
  if (normalized.until) req.until = localDateTimeToISOString(normalized.until);
  return req;
}

export function auditCliCommandFromRequest(req = {}) {
  return cliCommand("ngfwctl audit", [
    ["--limit", req.limit],
    ["--actor", req.actor],
    ["--action", req.action],
    ["--version", req.version],
    ["--query", req.query],
    ["--since", req.since],
    ["--until", req.until],
    ["--hashes", true],
  ]);
}

export function normalizeAuditFilters(filters = {}) {
  const out = { ...defaultAuditFilters() };
  out.query = String(filters.query || "").trim();
  out.actor = String(filters.actor || "").trim();
  const action = String(filters.action || "").trim();
  out.action = AUDIT_ACTION_VALUES.has(action) ? action : "";
  const version = Number(String(filters.version || "").trim());
  out.version = Number.isInteger(version) && version > 0 ? String(version) : "";
  const limit = String(filters.limit || "").trim();
  out.limit = AUDIT_LIMIT_VALUES.has(limit) ? limit : defaultAuditFilters().limit;
  out.since = localDateTimeToISOString(filters.since) ? String(filters.since || "").trim() : "";
  out.until = localDateTimeToISOString(filters.until) ? String(filters.until || "").trim() : "";
  out.entry = normalizeAuditEntryKey(filters.entry);
  return out;
}

function syncChangesRoute() {
  if (tab === "candidate") {
    writeQueryState("/changes", { tab: "candidate", ...defaultAuditFilters(), version: "", snapshot: "", drawer: candidateDrawer }, CHANGES_QUERY_DEFAULTS, CHANGES_QUERY_KEYS);
    return;
  }
  if (tab === "versions") {
    writeQueryState("/changes", { tab: "versions", ...defaultAuditFilters(), ...versionRoute, snapshot: "" }, CHANGES_QUERY_DEFAULTS, CHANGES_QUERY_KEYS);
    return;
  }
  if (tab === "snapshots") {
    writeQueryState("/changes", { tab: "snapshots", ...defaultAuditFilters(), version: "", ...snapshotRoute }, CHANGES_QUERY_DEFAULTS, CHANGES_QUERY_KEYS);
    return;
  }
  writeQueryState("/changes", { tab: "audit", ...auditFilters, version: auditFilters.version, snapshot: "", drawer: auditDrawer }, CHANGES_QUERY_DEFAULTS, CHANGES_QUERY_KEYS);
}

function clearCandidateDrawerState() {
  if (!candidateDrawer) return;
  candidateDrawer = "";
  syncChangesRoute();
}

function localDateTimeToISOString(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toISOString();
}

function defaultAuditFilters() {
  return { query: "", actor: "", action: "", version: "", since: "", until: "", limit: "300", entry: "" };
}

function normalizeCandidateDrawer(value) {
  const drawer = String(value || "").trim();
  return CANDIDATE_DRAWERS.has(drawer) ? drawer : "";
}

function normalizeAuditDrawer(value) {
  const drawer = String(value || "").trim();
  return AUDIT_DRAWERS.has(drawer) ? drawer : "";
}

function defaultVersionRoute() {
  return { version: "", drawer: "" };
}

function defaultSnapshotRoute() {
  return { snapshot: "", drawer: "" };
}

function setVersionDrawerState(version, drawer) {
  const normalizedVersion = normalizeVersionRoute(version);
  versionRoute = {
    version: normalizedVersion,
    drawer: normalizedVersion ? normalizeVersionDrawer(drawer) : "",
  };
  syncChangesRoute();
}

function clearVersionDrawerState() {
  if (preserveVersionDrawerRoute) return;
  if (!versionRoute.version && !versionRoute.drawer) return;
  versionRoute = defaultVersionRoute();
  syncChangesRoute();
}

function versionRouteMatches(version, drawer) {
  return versionRoute.version === normalizeVersionRoute(version) && versionRoute.drawer === drawer;
}

function setSnapshotDrawerState(snapshot, drawer) {
  const normalizedSnapshot = normalizeSnapshotId(snapshot);
  snapshotRoute = {
    snapshot: normalizedSnapshot,
    drawer: normalizedSnapshot ? normalizeSnapshotRouteDrawer(drawer) : "",
  };
  syncChangesRoute();
}

function clearSnapshotDrawerState() {
  if (preserveSnapshotDrawerRoute) return;
  if (!snapshotRoute.snapshot && !snapshotRoute.drawer) return;
  snapshotRoute = defaultSnapshotRoute();
  syncChangesRoute();
}

function snapshotRouteMatches(snapshot, drawer) {
  return snapshotRoute.snapshot === normalizeSnapshotId(snapshot) && snapshotRoute.drawer === normalizeSnapshotRouteDrawer(drawer);
}

function replaceSnapshotDrawer(fn) {
  preserveSnapshotDrawerRoute = true;
  try {
    fn();
  } finally {
    preserveSnapshotDrawerRoute = false;
  }
}

function normalizeVersionRoute(value) {
  const version = Number(String(value || "").trim());
  return Number.isInteger(version) && version > 0 ? String(version) : "";
}

function normalizeVersionDrawer(value) {
  const drawer = String(value || "").trim();
  return VERSION_DRAWERS.has(drawer) ? drawer : "";
}

function normalizeSnapshotRouteDrawer(value) {
  const drawer = normalizeSnapshotDrawer(value);
  return SNAPSHOT_DRAWERS.has(drawer) ? drawer : "";
}

export function auditEntryKey(entry = {}) {
  return normalizeAuditEntryKey(entry.id || entry.entryHash || entry.time || "");
}

function normalizeAuditEntryKey(value) {
  const text = String(value || "").trim();
  if (!text || text.length > 128 || /[\u0000-\u001f\u007f]/.test(text)) return "";
  return text.replace(/\s+/g, "-");
}

function kv(k, v) {
  return [h("dt", {}, k), h("dd", { class: "mono" }, v || "—")];
}

function actorLabel(e = {}) {
  if (!e.actor) return "—";
  const role = e.actorRole || e.actor_role || "";
  return role ? `${e.actor} / ${role}` : e.actor;
}

function authTitle(e = {}) {
  const source = e.authSource || e.auth_source || "";
  return source ? `Auth source: ${source}` : "";
}

export function auditHashLabel(e = {}) {
  return shortAuditHash(e.entryHash);
}

function auditHashTitle(e = {}) {
  if (!e.entryHash) return "";
  const prev = e.previousHash ? shortAuditHash(e.previousHash) : "genesis";
  return `Entry hash ${e.entryHash}; previous ${prev}`;
}

function shortAuditHash(hash) {
  if (!hash) return "—";
  return String(hash).slice(0, 12);
}

export function auditActionClass(a) {
  if (!a) return "neutral";
  if (a.includes("fail")) return "bad";
  if (a === "commit") return "ok";
  if (a === "rollback" || a === "rollback-intent" || a.includes("content-package-rollback") || a === "system-tune") return "warn";
  if (a === "stage-threat-exception") return "info";
  if (a.includes("access-local-user") || a.includes("access-session") || a.includes("access-oidc-provider") || a.includes("access-saml-provider")) return "violet";
  if (a.includes("candidate") || a.includes("packet-capture")) return "info";
  if (a === "commit-intent") return "info";
  if (a.includes("content-package-install")) return "violet";
  return "neutral";
}

function actionPill(a) {
  if (!a) return "—";
  return pill(a, auditActionClass(a));
}

function currentRoute() {
  if (typeof location === "undefined") return "#/changes?tab=audit";
  return location.hash || "#/changes?tab=audit";
}

function pinAuditHandoff(packet) {
  try {
    const result = pinInvestigationPacket(packet);
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Selected audit evidence could not be pinned.", "bad");
  }
}

function pinGovernanceApproval(packet) {
  try {
    const result = pinInvestigationPacket(packet);
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Governance review packet could not be pinned.", "bad");
  }
}

function pinCandidatePreservation(packet) {
  try {
    const result = pinInvestigationPacket(packet);
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Candidate preservation packet could not be pinned.", "bad");
  }
}

async function copyAuditHandoff(packet) {
  try {
    await navigator.clipboard.writeText(investigationPacketText(packet));
    toast("Audit handoff copied", "Selected audit entry evidence copied as plain text.", "ok");
  } catch {
    toast("Copy failed", "Select the visible audit detail and copy it manually.", "warn");
  }
}

async function copyGovernanceApproval(packet) {
  try {
    await navigator.clipboard.writeText(investigationPacketText(packet));
    toast("Approval packet copied", "Browser-local governance review packet copied as plain text.", "ok");
  } catch {
    toast("Copy failed", "Select the visible governance packet and copy it manually.", "warn");
  }
}

async function copyCandidatePreservation(packet) {
  try {
    await navigator.clipboard.writeText(investigationPacketText(packet));
    toast("Preservation packet copied", "Browser-local candidate preservation packet copied as plain text.", "ok");
  } catch {
    toast("Copy failed", "Select the visible preservation packet and copy it manually.", "warn");
  }
}

async function copySnapshotReviewLink(snapshot = {}, drawer = "restore-preview") {
  const link = snapshotRestoreReviewHash(snapshot.id || snapshot.snapshotId || "", drawer);
  try {
    await navigator.clipboard.writeText(link);
    toast("Review link copied", "Snapshot maintenance review link copied.", "ok");
  } catch {
    toast("Copy failed", "Select the visible route and copy it manually.", "warn");
  }
}

async function copySnapshotRestorePacket(packet) {
  try {
    await navigator.clipboard.writeText(snapshotRestoreReviewJson(packet));
    toast("Restore packet copied", "Snapshot restore maintenance review packet copied as JSON.", "ok");
  } catch {
    toast("Copy failed", "Select the visible restore packet and copy it manually.", "warn");
  }
}

async function copyLifecycleText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Lifecycle runbook copied", "Cleanup and preserve guidance copied for operator handoff.", "ok");
  } catch {
    toast("Copy failed", "Select the visible lifecycle runbook and copy it manually.", "warn");
  }
}

async function copyAuditReport(packet) {
  try {
    await navigator.clipboard.writeText(JSON.stringify(packet, null, 2) + "\n");
    toast("Audit report copied", "Browser-generated audit report copied as JSON.", "ok");
  } catch {
    toast("Copy failed", "Select the visible audit report and copy it manually.", "warn");
  }
}

async function createServerComplianceReport(profile = "operational") {
  try {
    const report = await api.createComplianceReport(complianceReportCreateRequest(profile));
    const record = report.report || {};
    toast("Compliance report retained", `Server stored ${record.id || "the report"} as unsigned JSON metadata.`, "ok");
  } catch (e) {
    toast("Report generation failed", e.message || "The server could not retain the compliance report.", "warn");
  }
}

export function complianceReportCreateRequest(profile = "operational", filters = auditFilters) {
  const req = auditRequestFromFilters(filters);
  return {
    profile: normalizeAuditComplianceProfile(profile),
    title: `${auditComplianceProfileLabel(profile)} compliance report`,
    auditLimit: Number(req.limit || 300),
    versionLimit: 100,
    logLimit: 100,
    actor: req.actor || "",
    action: req.action || "",
    version: req.version || "",
    since: req.since || "",
    until: req.until || "",
    query: req.query || "",
  };
}

async function exportServerComplianceReport(report = {}) {
  const id = String(report.id || "").trim();
  if (!id) {
    toast("Export unavailable", "The retained report metadata did not include an id.", "warn");
    return;
  }
  try {
    const blob = await api.exportComplianceReport(id);
    const url = URL.createObjectURL(blob);
    const a = h("a", { class: "download-anchor-hidden", href: url, download: `${id}.json` });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
    toast("Compliance report exported", "Downloaded the server-retained unsigned report JSON.", "ok");
  } catch (e) {
    toast("Export failed", e.message || "The retained report could not be exported.", "warn");
  }
}

function exportGovernanceApproval(packet) {
  const text = investigationPacketJson(packet);
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: investigationPacketFilename(packet) });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  toast("Approval packet exported", "Downloaded browser-local governance review packet JSON.", "ok");
}

function exportCandidatePreservation(packet) {
  const text = investigationPacketJson(packet);
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: investigationPacketFilename(packet) });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  toast("Preservation packet exported", "Downloaded browser-local candidate preservation packet JSON.", "ok");
}

function exportSnapshotRestorePacket(packet) {
  const snapshotId = packet?.snapshot?.id || "snapshot";
  const text = snapshotRestoreReviewJson(packet);
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: snapshotRestoreReviewFilename(snapshotId) });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  toast("Restore packet exported", "Downloaded browser-local snapshot restore review JSON.", "ok");
}

function exportAuditReport(packet) {
  const text = JSON.stringify(packet, null, 2) + "\n";
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: auditReportFilename(packet) });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  toast("Audit report exported", "Downloaded unsigned browser-generated audit report JSON.", "ok");
}

function auditReportFilename(packet = {}) {
  const stamp = String(packet.generatedAt || new Date().toISOString()).replace(/[:.]/g, "-");
  return `phragma-audit-report-${stamp}.json`;
}

function exportAuditHandoff(packet) {
  const text = investigationPacketJson(packet);
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: investigationPacketFilename(packet) });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  toast("Audit handoff exported", "Downloaded selected audit entry evidence as JSON.", "ok");
}

function auditOption(value, label) {
  return h("option", { value }, label);
}
