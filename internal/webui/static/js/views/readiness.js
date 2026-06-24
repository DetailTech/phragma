// Readiness — operator preflight view backed by /v1/system/status.
// The page is deliberately factual: it shows what blocks production
// enforcement, what is degraded, and what action closes each gap.

import { h, icon, mount } from "../core.js";
import { api } from "../api.js";
import { throwIfAccessDenied } from "../auth_gate.js";
import { openAutomationContext } from "../automation_context.js";
import { buildContentPosture } from "../content_posture.js";
import { capabilityClass, conntrackCapacity, dataplaneNameRequiresEbpf, dataplanePosture, ebpfHostReadiness, flowtableHostReadiness, flowtableRuntimeEvidence, idsModeLabel, inspectionReadiness, kernelTuningRollup, kernelTuningStatus } from "../dataplane.js";
import { degradedEngineEvidence } from "../inspection_posture.js";
import { activeInvestigationServerCaseHref, appendInvestigationPacketToActiveServerCase, pinInvestigationPacket } from "../investigation_case.js";
import { buildInvestigationPacket, investigationPacketFilename, investigationPacketJson, investigationPacketText } from "../investigation_packet.js";
import { readQueryState, writeQueryState } from "../query_state.js";
import { buildEbpfDrillEvidencePacket, buildHAEvidencePacket, buildSystemEvidencePacket, ebpfDrillEvidencePacketReport, haEvidencePacketReport, haReadiness, readinessActionHash, releaseArtifactWorkbenchModel, releaseEvidenceChecklist, releaseEvidenceCounts, releaseEvidencePacketDefinition, releaseEvidencePacketIds, releaseEvidenceReport, remediationSteps, routingRuntimeEvidence, summarizeReadiness, systemEvidencePacketReport } from "../readiness_model.js";
import { buildSupportBundle, supportBundleFilename, supportBundlePreviewModel, supportBundlePreviewReport } from "../support_bundle.js";
import { pageHead, card, badge, emptyState, toast, confirmDialog, openDrawer, closeDrawer, labeledCell, responsiveTable } from "../ui.js";
import { vpnTunnelHash, vpnTunnelModels } from "./netvpn.js";
import * as fmt from "../format.js";

export const ENGINE_READINESS_COLUMNS = Object.freeze(["Engine", "State", "Mode", "Role", "Detail"]);
const READINESS_ROUTE = "/readiness";
const DEFAULT_ROUTE_STATE = Object.freeze({ drawer: "", packet: "", action: "" });
const ROUTE_KEYS = Object.freeze(["drawer", "packet", "action"]);
const RECORDABILITY_DIRTY_PATH_DISPLAY_LIMIT = 8;
let activeReadinessRouteDrawer = "";

function readinessActionAttrs(action, label, extraDataset = {}) {
  return {
    type: "button",
    title: label,
    "aria-label": label,
    dataset: { readinessAction: action, ...extraDataset },
  };
}

const RELEASE_ACCEPTANCE_NEXT_COMMANDS = Object.freeze({
  "proto-verify": [
    ["Validate", "make proto-verify"],
    ["Record", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-proto-verify"],
  ],
  "deploy-hardening": [
    ["Validate", "bash release/deploy-hardening-check.sh --check"],
    ["Record", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-deploy-hardening"],
  ],
  "privileged-integration": [
    ["Validate", "make privileged-integration-evidence-check"],
    ["Record", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-privileged-integration"],
  ],
  "policy-restore-drill": [
    ["Validate", "make policy-restore-drill-check"],
    ["Record", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-policy-restore-drill"],
  ],
  "ha-readiness-recovery": [
    ["Validate", "make ha-readiness-recovery-check"],
    ["Record", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-ha-readiness-recovery"],
  ],
  "e2e-install": [
    ["Validate", "sudo -E make e2e-install"],
    ["Record", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-e2e-install"],
  ],
  "content-package-verification": [
    ["Validate", "make content-package-smoke"],
    ["Record", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-content-package-verification"],
  ],
  "content-production-readiness": [
    ["Validate", "make content-production-readiness-check CONTENT_PRODUCTION_EVIDENCE_DIR=release/field-evidence/content-production"],
    ["Record", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-content-production-readiness CONTENT_PRODUCTION_EVIDENCE_DIR=release/field-evidence/content-production"],
  ],
  "release-benchmark": [
    ["Validate", "make benchmark-verify-release"],
    ["No claims", "RELEASE_NO_PERFORMANCE_CLAIMS=1 make release-acceptance-status"],
  ],
  "m3-live-networking": [
    ["Preflight", "make m3-live-networking-check"],
    ["Validate", "sudo make m3-live-networking"],
    ["Record", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-m3-live-networking"],
  ],
  "m3-field-evidence": [
    ["Validate", "make m3-field-evidence-check M3_FIELD_EVIDENCE_DIR=release/field-evidence/m3"],
    ["Record", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-m3-field-evidence M3_FIELD_EVIDENCE_DIR=release/field-evidence/m3"],
  ],
  "ebpf-ol9-field-evidence": [
    ["Collect", "make ebpf-ol9-attach-drill-check"],
    ["Validate", "make ebpf-ol9-field-evidence-check EBPF_OL9_FIELD_EVIDENCE_DIR=release/field-evidence/ebpf-ol9"],
    ["Record", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-ebpf-ol9-field-evidence EBPF_OL9_FIELD_EVIDENCE_DIR=release/field-evidence/ebpf-ol9"],
  ],
  "m5-oidc-field-evidence": [
    ["Validate", "make m5-oidc-field-evidence-check OIDC_FIELD_EVIDENCE_DIR=release/field-evidence/oidc"],
    ["Record", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-m5-oidc-field-evidence OIDC_FIELD_EVIDENCE_DIR=release/field-evidence/oidc"],
  ],
  "m5-saml-field-evidence": [
    ["Collect", "mkdir -p release/field-evidence/saml/{provider,deployment,browser,rbac,redaction} && printf '%s\\n' 'Copy redacted SAML IdP/SP, ACS, browser, RBAC, and redaction artifacts into release/field-evidence/saml; this command only prepares the bundle directory.'"],
    ["Validate", "make m5-saml-field-evidence-check SAML_FIELD_EVIDENCE_DIR=release/field-evidence/saml"],
    ["Record", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-m5-saml-field-evidence SAML_FIELD_EVIDENCE_DIR=release/field-evidence/saml"],
  ],
  "m5-auth-ui": [
    ["Validate", "make webui-check"],
    ["Record", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-m5-auth-ui"],
  ],
  "m5-oidc-provider": [
    ["Validate", "make e2e-oidc-runtime-smoke"],
    ["Record", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-m5-oidc-provider"],
  ],
  "webui-enterprise-smoke": [
    ["Validate", "make webui-enterprise-smoke"],
    ["Record", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-webui-enterprise-smoke"],
  ],
});

export async function render(ctx = {}) {
  let routeState = normalizeReadinessRouteState(readQueryState(ctx.query, DEFAULT_ROUTE_STATE, ROUTE_KEYS));
  const [statusR, runningR, feedsR, contentR, releaseAcceptanceR, telemetryExportStatusR] = await Promise.allSettled([
    api.status(),
    api.running(),
    api.feeds(),
    api.contentPackages(),
    api.releaseAcceptanceStatus(),
    api.telemetryExportStatus(),
  ]);
  throwIfAccessDenied(statusR, runningR, feedsR, contentR, releaseAcceptanceR, telemetryExportStatusR);
  const statusUnavailable = statusR.status !== "fulfilled";
  const status = statusR.value || {};
  const running = runningR.status === "fulfilled" ? runningR.value : {};
  const policy = running.policy || {};
  const feeds = feedsR.status === "fulfilled" ? (feedsR.value?.feeds || []) : [];
  const contentPackages = contentR.status === "fulfilled" ? (contentR.value?.packages || []) : [];
  const releaseAcceptanceStatus = releaseAcceptanceFromResult(releaseAcceptanceR);
  const telemetryExportStatus = telemetryExportStatusR.status === "fulfilled" ? telemetryExportStatusR.value : null;
  const contentError = [
    feedsR.status === "rejected" ? `feed registry: ${feedsR.reason?.message || feedsR.reason}` : "",
    contentR.status === "rejected" ? `content packages: ${contentR.reason?.message || contentR.reason}` : "",
  ].filter(Boolean).join("; ");
  const contentPosture = buildContentPosture(feeds, policy, contentPackages, contentError);
  const flowCap = flowtableHostReadiness(status);
  const flowRuntime = flowtableRuntimeEvidence(status);
  const ebpfHost = ebpfHostReadiness(status);
  const conntrack = conntrackCapacity(status);
  const inspection = inspectionReadiness(status);
  const policyDp = dataplanePosture(policy, status);
  const tuning = kernelTuningRollup(status);
  const routingRuntime = routingRuntimeEvidence(status, policy);
  const routingVpnPosture = routingVpnPostureModel(policy, status, routingRuntime);
  const proxyPosture = proxyGatewayPosture(policy);
  const engineEvidence = degradedEngineEvidence(status, policy);
  const ha = haReadiness(status);
  const summary = summarizeReadiness(status, policyDp, flowCap, flowRuntime, ebpfHost, conntrack, contentPosture, routingRuntime);
  const actions = remediationSteps(status, policyDp, flowCap, flowRuntime, ebpfHost, conntrack, tuning, contentPosture, routingRuntime);
  routeState = normalizeReadinessRouteState(routeState, actions);
  const releaseEvidence = releaseEvidenceChecklist({ summary, status, policyDp, flowCap, flowRuntime, ebpfHost, conntrack, tuning, contentPosture, inspection, releaseAcceptanceStatus, telemetry: policy.telemetry, telemetryExportStatus });
  const systemEvidence = buildSystemEvidencePacket({ summary, status, policyDp, flowCap, flowRuntime, ebpfHost, conntrack, tuning, contentPosture, inspection, releaseEvidence, releaseAcceptanceStatus });
  const haEvidence = buildHAEvidencePacket(status);
  const ebpfDrillEvidence = buildEbpfDrillEvidencePacket({ ebpfHost, releaseItem: releaseEvidence.find((item) => item.id === "ebpf-ol9-field-evidence") });
  maybeOpenRouteDrawer(routeState, { systemEvidence, haEvidence, ha, releaseEvidence, releaseAcceptanceStatus, ebpfDrillEvidence });
  const root = h("div", {},
    pageHead("Readiness", "Runtime posture, engine prerequisites, and deployment blockers.",
      h("div", { class: "flex wrap" },
        h("button", {
          class: "btn",
          type: "button",
          title: "Open system evidence handoff",
          "aria-label": "Open system evidence handoff",
          dataset: { readinessAction: "open-system-evidence" },
          onclick: () => openRoutedSystemEvidencePacket(systemEvidence),
        }, h("span", { html: icon("terminal", 16) }), "System evidence"),
        h("button", { class: "btn", type: "button", title: "Preview support bundle contents", "aria-label": "Preview support bundle contents", dataset: { readinessAction: "preview-support-bundle" }, onclick: openRoutedSupportBundlePreview }, h("span", { html: icon("download", 16) }), "Preview support bundle"),
        h("button", { class: "btn", type: "button", title: "Refresh readiness data", "aria-label": "Refresh readiness data", dataset: { readinessAction: "refresh" }, onclick: () => location.reload() }, h("span", { html: icon("refresh", 16) }), "Refresh"))),

    statusUnavailable ? readinessUnavailableBanner(statusR.reason) : null,

    h("div", { class: "readiness-summary " + summary.cls },
      h("div", { class: "readiness-mark", html: icon("shield", 34) }),
      h("div", {},
        h("div", { class: "readiness-title" }, summary.title),
        h("div", { class: "readiness-sub" }, summary.detail)),
      h("div", { class: "readiness-score" },
        h("strong", {}, summary.readyEngines + "/" + summary.engineCount),
        h("span", {}, "engines ready"))),

    h("div", { class: "grid cols-2", style: { marginBottom: "16px" } },
      actionQueueCard(actions, routeState.action),
      runtimeCard(status)),

    h("div", { class: "grid cols-2", style: { marginBottom: "16px" } },
      kernelTuningCard(tuning, status),
      haReadinessCard(ha, haEvidence, { hasAction: actions.some((item) => item.id === "ha-readiness") })),

    h("div", { style: { marginBottom: "16px" } },
      ebpfReadinessCard(ebpfHost, ebpfDrillEvidence)),

    h("div", { style: { marginBottom: "16px" } },
      policyDataplaneCard(policyDp, policy, running.version, flowCap, flowRuntime, ebpfHost, inspection)),

    h("div", { style: { marginBottom: "16px" } },
      degradedEngineEvidenceCard(engineEvidence)),

    h("div", { style: { marginBottom: "16px" } },
      proxyGatewayCard(proxyPosture)),

    h("div", { style: { marginBottom: "16px" } },
      routingVpnPostureCard(routingVpnPosture)),

    h("div", { style: { marginBottom: "16px" } },
      contentReadinessCard(contentPosture)),

    h("div", { style: { marginBottom: "16px" } },
      capabilityCard(status.capabilities || [])),

    engineCard(status.engines || []));
  maybeFocusRouteAction(routeState, actions, root);
  return root;
}

function readinessUnavailableBanner(err) {
  return h("div", { class: "alert-box bad", dataset: { readinessLoadError: "true" } },
    h("strong", {}, "Runtime status unavailable. "),
    loadErrorDetail(err, "The system status API did not return data."),
    h("div", { class: "note" }, "Readiness is showing the route shell with degraded evidence context. Retry after the runtime API recovers."),
    h("div", { class: "flex wrap", style: { marginTop: "8px" } },
      h("button", { class: "btn sm", type: "button", title: "Retry loading readiness data", "aria-label": "Retry loading readiness data", dataset: { readinessAction: "retry-load" }, onclick: () => location.reload() }, h("span", { html: icon("refresh", 14) }), "Retry"),
      h("button", { class: "btn sm ghost", type: "button", title: "Open readiness API and CLI context", "aria-label": "Open readiness API and CLI context", dataset: { readinessAction: "api-cli" }, onclick: () => openAutomationContext(READINESS_ROUTE) }, h("span", { html: icon("terminal", 14) }), "API / CLI")));
}

export async function exportSupportBundle(opts = {}) {
  try {
    const bundle = await collectSupportBundle();
    openSupportBundlePreview(bundle, opts);
  } catch (err) {
    openSupportBundleError(err, opts);
  }
}

export function releaseAcceptanceFromResult(result = {}) {
  if (result.status === "fulfilled") return result.value || {};
  return releaseAcceptanceUnavailableStatus(result.reason);
}

export function releaseAcceptanceUnavailableStatus(err) {
  const detail = err?.message || String(err || "release acceptance status unavailable");
  return {
    schemaVersion: "phragma.release.status.v1",
    state: "unavailable",
    ready: false,
    manifestPresent: false,
    summary: { passed: 0, recorded: 0, missing: 0, invalid: 0, notApplicable: 0, todo: 0 },
    problems: [`release acceptance status endpoint unavailable: ${detail}`],
    checks: [],
  };
}

export async function collectSupportBundle() {
  try {
    return await api.supportBundle({ versionLimit: 100, auditLimit: 300, eventLimit: 500 });
  } catch (err) {
    if (!isUnsupportedSupportBundleEndpoint(err)) throw err;
  }
  return collectBrowserSupportBundle();
}

function isUnsupportedSupportBundleEndpoint(err) {
  return err?.status === 404 || err?.status === 405 || err?.status === 501;
}

async function collectBrowserSupportBundle() {
  const runningPolicyResult = await settledResult(optionalNoRunningPolicy(api.running()));
  const candidatePolicyResult = await settledResult(optionalNoCandidate(api.candidate()));
  const runningPolicy = runningPolicyResult.status === "fulfilled" ? runningPolicyResult.value?.policy || {} : {};
  const candidatePolicy = candidatePolicyResult.status === "fulfilled" ? candidatePolicyResult.value?.policy || null : null;
  const targetPolicy = candidatePolicy || runningPolicy;
  const names = [
    "status",
    "highAvailabilityStatus",
    "telemetryExportStatus",
    "identity",
    "candidateStatus",
    "candidateValidation",
    "runtimeReadinessPreflight",
    "versions",
    "audit",
    "auditIntegrity",
    "alerts",
    "flows",
    "sessions",
    "feeds",
    "contentPackages",
    "releaseAcceptanceStatus",
  ];
  const calls = [
    api.status(),
    api.highAvailabilityStatus(),
    api.telemetryExportStatus(),
    api.identity(),
    api.candidateStatus(),
    optionalNoCandidate(api.validate()),
    api.runtimeReadinessPreflight({ targetPolicy, runningPolicy, operation: "commit" }),
    api.versions(100),
    api.audit(300),
    api.auditVerify(),
    api.alerts(500),
    api.flows(500),
    api.sessions(500),
    api.feeds(),
    api.contentPackages(),
    api.releaseAcceptanceStatus(),
  ];
  const settled = await Promise.allSettled(calls);
  const results = {
    runningPolicy: runningPolicyResult,
    candidatePolicy: candidatePolicyResult,
    ...Object.fromEntries(names.map((name, index) => [name, settled[index]])),
  };
  return buildSupportBundle({ results });
}

async function settledResult(promise) {
  const settled = await Promise.allSettled([promise]);
  return settled[0];
}

function downloadSupportBundle(bundle) {
  const text = JSON.stringify(bundle, null, 2) + "\n";
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: supportBundleFilename() });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  const failed = bundle.summary?.failedEndpoints || [];
  if (failed.length) toast("Support bundle exported", `Downloaded with ${failed.length} endpoint error(s): ${failed.join(", ")}.`, "warn");
  else toast("Support bundle exported", "Downloaded runtime, HA, policy, audit-chain, telemetry, sessions, feed, and content-package evidence.", "ok");
}

function openRoutedSupportBundlePreview() {
  writeReadinessRouteState({ drawer: "support-bundle" });
  exportSupportBundle({ routeBacked: "support-bundle" });
}

function openSupportBundlePreview(bundle, opts = {}) {
  const routeDrawer = readinessRouteBackedKind(opts.routeBacked, "support-bundle");
  if (routeDrawer) {
    if (!isCurrentReadinessRouteDrawer(routeDrawer)) return;
    activeReadinessRouteDrawer = routeDrawer;
  }
  const preview = supportBundlePreviewModel(bundle);
  const report = supportBundlePreviewReport(bundle);
  openDrawer({
    title: "Support bundle preview",
    subtitle: preview.collectedAt || "Collected runtime evidence",
    width: "760px",
    body: h("div", { class: "support-bundle-preview" },
      h("div", { class: "preflight-summary" },
        h("div", {}, h("span", {}, "Sections"), h("strong", {}, `${preview.totals.included}/${preview.totals.sections}`)),
        h("div", {}, h("span", {}, "Failures"), h("strong", {}, String(preview.totals.failed))),
        h("div", {}, h("span", {}, "Redactions"), h("strong", {}, String(preview.totals.redactions))),
        h("div", {}, h("span", {}, "Package blockers"), h("strong", {}, String(preview.totals.contentPackageBlockers)))),
      h("div", { class: "alert-box " + (preview.failures.length ? "warn" : "ok") },
        h("strong", {}, preview.failure.title),
        h("div", { class: "note" }, preview.failure.detail)),
      h("div", { class: "alert-box info" },
        h("strong", {}, preview.redaction.title),
        h("div", { class: "note" }, preview.redaction.detail)),
      h("textarea", {
        class: "input support-bundle-report",
        dataset: { supportBundleReport: "true" },
        readonly: true,
        rows: 12,
        wrap: "soft",
        spellcheck: "false",
      }, report),
      h("div", { class: "support-section-list" }, preview.sections.map((section) => supportBundleSectionRow(section)))),
    footer: [
      h("button", { class: "btn ghost", ...readinessActionAttrs("close-support-bundle", "Close support bundle preview"), onclick: closeDrawer }, "Close"),
	      h("button", { class: "btn", type: "button", title: "Copy support bundle summary", "aria-label": "Copy support bundle summary", dataset: { supportBundleAction: "copy-report" }, onclick: () => copySupportBundlePreviewReport(report) },
	        h("span", { html: icon("copy", 16) }), "Copy summary"),
	      h("button", { class: "btn primary", type: "button", title: "Download support bundle JSON", "aria-label": "Download support bundle JSON", dataset: { supportBundleAction: "download-json" }, onclick: () => downloadSupportBundle(bundle) },
	        h("span", { html: icon("download", 16) }), "Download JSON"),
    ],
    onClose: routeDrawer ? () => clearReadinessRouteStateFor(routeDrawer) : null,
  });
}

async function copySupportBundlePreviewReport(report) {
  try {
    if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(report);
    toast("Support summary copied", "Copied redacted bundle posture, release status, endpoint health, and collection notes.", "ok");
  } catch {
    toast("Copy unavailable", "Select and copy the support bundle summary from the preview drawer.", "warn");
  }
}

export function supportBundleErrorModel(err = {}) {
  const status = err?.status ? `HTTP ${err.status}` : "request failed";
  const message = redactReadinessDisclosureText(err?.message || String(err || "support bundle preview failed"));
  const auth = err?.status === 401 || err?.status === 403;
  return {
    title: auth ? "Support bundle access denied" : "Support bundle preview failed",
    tone: auth ? "bad" : "warn",
    detail: auth
      ? `${status}: ${message}. Sign in with an operator role that can read support evidence, then retry.`
      : `${status}: ${message}. Runtime evidence was not exported.`,
    command: "ngfwctl support-bundle --output-dir .",
  };
}

function openSupportBundleError(err, opts = {}) {
  const routeDrawer = readinessRouteBackedKind(opts.routeBacked, "support-bundle");
  if (routeDrawer) {
    if (!isCurrentReadinessRouteDrawer(routeDrawer)) return;
    activeReadinessRouteDrawer = routeDrawer;
  }
  const model = supportBundleErrorModel(err);
  toast(model.title, model.detail, model.tone);
  openDrawer({
    title: model.title,
    subtitle: "No support bundle was generated.",
    width: "620px",
    body: h("div", { class: "support-bundle-preview" },
      h("div", { class: "alert-box " + model.tone },
        h("strong", {}, model.title),
        h("div", { class: "note" }, model.detail)),
      h("div", { class: "release-evidence-command-row" },
        h("div", {},
          h("span", {}, "CLI fallback"),
          h("code", {}, model.command)),
        readinessCommandCopyButton("support bundle CLI fallback", model.command))),
    footer: [h("button", { class: "btn primary", ...readinessActionAttrs("close-support-bundle-error", "Close support bundle error"), onclick: closeDrawer }, "Close")],
    onClose: routeDrawer ? () => clearReadinessRouteStateFor(routeDrawer) : null,
  });
}

function supportBundleSectionRow(section) {
  return h("div", {
    class: "support-section-row " + (section.ok ? "" : "bad"),
    dataset: { supportBundleSection: section.name || "" },
  },
    h("div", {}, badge(section.state, section.tone || (section.ok ? "ok" : "bad"), { dot: true })),
    h("div", {},
      h("strong", {}, section.label || section.name || "Section"),
      h("div", { class: "note" }, section.detail || "No detail returned."),
      section.redactions ? h("div", { class: "support-section-meta" }, badge(`${section.redactions} redacted`, "warn")) : null));
}

function optionalNoCandidate(promise) {
  return promise.catch((err) => {
    if (isNoCandidateError(err)) return {};
    throw err;
  });
}

function isNoCandidateError(err) {
  const msg = String(err?.message || err || "").toLowerCase();
  return (err?.status === 404 || err?.status === 400 || err?.status === 412) && msg.includes("candidate");
}

function loadErrorDetail(err, fallback) {
  return err?.message || String(err || fallback);
}

function optionalNoRunningPolicy(promise) {
  return promise.catch((err) => {
    if (isNoRunningPolicyError(err)) return {};
    throw err;
  });
}

function isNoRunningPolicyError(err) {
  const msg = String(err?.message || err || "").toLowerCase();
  return err?.status === 404 && (msg.includes("running policy") || msg.includes("no running"));
}

function actionQueueCard(actions, activeAction = "") {
  return card(h("h2", {}, "Action queue", h("span", { class: "spacer" }), badge(actions.length + " item" + (actions.length === 1 ? "" : "s"), actions.some((item) => item.level === "high") ? "bad" : actions.length ? "warn" : "ok")),
    actions.length ? h("div", { class: "warning-list" }, actions.map((item) => actionRow(item, activeAction))) :
      emptyState("check", "No actions", "controld has not reported runtime blockers."));
}

function releaseEvidenceCard(items, releaseAcceptanceStatus = null) {
  const counts = releaseEvidenceCounts(items);
  const artifactWorkbench = releaseArtifactWorkbenchModel(items, releaseAcceptanceStatus);
  const tone = counts.blocked ? "bad" : counts.review ? "warn" : "ok";
  const label = counts.blocked
    ? `${counts.blocked} blocked`
    : counts.review
      ? `${counts.review} review`
      : `${counts.clear} clear`;
  return card(h("div", { class: "release-evidence-card-head" },
    h("h2", {}, "Release evidence"),
    h("span", { class: "spacer" }),
	    h("button", {
	      class: "btn sm ghost",
	      type: "button",
	      title: "Copy release evidence summary",
	      "aria-label": "Copy release evidence summary",
	      dataset: { releaseEvidenceAction: "copy-summary" },
	      onclick: () => copyReleaseEvidenceSummary(items),
	    }, h("span", { html: icon("copy", 15) }), "Copy summary"),
    releaseAcceptanceStatus ? h("button", {
      class: "btn sm ghost",
      type: "button",
      title: "Open release acceptance status",
      "aria-label": "Open release acceptance status",
      dataset: { releaseEvidenceAction: "open-acceptance-status" },
      onclick: () => openRoutedReleaseAcceptanceStatus(releaseAcceptanceStatus),
    }, h("span", { html: icon("terminal", 15) }), "Acceptance status") : null,
    badge(label, tone)),
    releaseArtifactWorkbench(artifactWorkbench, items),
    h("div", { class: "release-evidence-grid" },
      items.map((item) => releaseEvidenceRow(item))));
}

function releaseArtifactWorkbench(model = {}, items = []) {
  const rows = Array.isArray(model.rows) ? model.rows : [];
  const counts = model.counts || {};
  const itemById = new Map((Array.isArray(items) ? items : []).map((item) => [item.id, item]));
  return h("div", {
    class: "release-artifact-workbench",
    dataset: { releaseArtifactWorkbench: "true" },
  },
    h("div", { class: "release-artifact-workbench-head" },
      h("div", {},
        h("strong", {}, "Artifact matching workbench"),
        h("div", { class: "note" }, "Match each expected release gate to the recorded artifact and manifest binding before treating Readiness as release-ready. Remote continuation output, templates, and stale artifacts are not accepted-source evidence.")),
      h("div", { class: "flex wrap" },
        badge(`${Number(counts.recorded || 0)} recorded`, Number(counts.recorded || 0) ? "ok" : "info", { dot: true }),
        badge(`${Number(counts.missing || 0)} missing`, Number(counts.missing || 0) ? "bad" : "ok", { dot: true }),
        badge(`${Number(counts.stale || 0)} stale`, Number(counts.stale || 0) ? "warn" : "ok", { dot: true }),
        badge(model.manifestPresent ? "manifest present" : "manifest missing", model.manifestPresent ? "ok" : "bad", { dot: true }),
        badge("signing/custody hardening", "warn", { dot: true }))),
    h("div", { class: "note release-artifact-custody-note" }, "Artifact signing, retained custody, and stale-evidence quarantine remain hardening-only controls; use this workbench to decide whether the current artifact can be recorded or must be regenerated."),
    h("div", { class: "release-artifact-table" },
      rows.map((row) => releaseArtifactWorkbenchRow(row, itemById.get(row.id)))));
}

function releaseArtifactWorkbenchRow(row = {}, item = {}) {
  const command = readinessDisclosureValue(row.nextCommand || "");
  const evidenceBoundary = classifyReleaseArtifactEvidenceBoundary(row, item);
  const custodyBoundary = releaseArtifactCustodyBoundary(row);
  return h("div", {
    class: "release-artifact-row " + (row.cls || "info"),
    dataset: { releaseArtifactGate: row.id || "" },
  },
    h("div", {},
      h("span", {}, "Expected gate"),
      h("strong", { class: "mono" }, row.expectedGate || row.id || "release gate")),
    h("div", {},
      h("span", {}, "Current status"),
      h("strong", {}, row.label || "unknown"),
      h("div", { class: "note" }, readinessDisclosureValue(row.currentStatus || ""))),
    h("div", {},
      h("span", {}, "Evidence class"),
      badge(evidenceBoundary.label, evidenceBoundary.tone, { dot: true }),
      h("div", { class: "note", dataset: { releaseArtifactEvidenceClass: row.id || "" } }, evidenceBoundary.detail)),
    h("div", {},
      h("span", {}, "Manifest binding"),
      h("strong", {}, readinessDisclosureValue(row.manifestBinding || "")),
      h("code", { class: "mono" }, readinessDisclosureValue(row.artifactPath || row.evidencePath || "no artifact path"))),
    h("div", {},
      h("span", {}, "Signing/custody"),
      h("strong", {}, custodyBoundary.label),
      h("div", { class: "note", dataset: { releaseArtifactCustody: row.id || "" } }, custodyBoundary.detail)),
    h("div", {},
      h("span", {}, row.nextCommandRole || "Next command"),
      command ? h("code", {
        class: "mono",
        dataset: { releaseArtifactNextCommand: row.id || "" },
      }, command) : h("strong", {}, "No command metadata")),
    h("div", { class: "release-artifact-actions" },
      row.packetRoute ? h("a", {
        class: "btn sm ghost",
        href: row.packetRoute,
        title: `Open release drill for ${row.expectedGate || row.id || "release gate"}`,
        "aria-label": `Open release drill for ${row.expectedGate || row.id || "release gate"}`,
        dataset: { releaseArtifactAction: "drill", releaseEvidencePacket: row.id || "" },
      }, h("span", { html: icon("terminal", 15) }), "Drill") : null,
      command ? readinessCommandCopyButton(row.nextCommandRole || "next", command, {
        ariaLabel: `Copy ${String(row.nextCommandRole || "next").toLowerCase()} command for ${row.expectedGate || row.id || "release gate"}`,
        dataset: { releaseArtifactAction: "copy-command", releaseArtifactGate: row.id || "" },
      }) : null,
      item?.packet ? h("button", {
        class: "btn sm ghost",
        type: "button",
        title: `Pin ${row.expectedGate || row.id || "release gate"} evidence packet to investigation case`,
        "aria-label": `Pin ${row.expectedGate || row.id || "release gate"} evidence packet to investigation case`,
        dataset: { releaseArtifactAction: "pin-handoff", releaseEvidencePacket: row.id || "" },
        onclick: () => pinReleaseEvidencePacket(releaseEvidenceInvestigationHandoffPacket(item)),
      }, h("span", { html: icon("inbox", 15) }), "Pin") : null));
}

export function classifyReleaseArtifactEvidenceBoundary(row = {}, item = {}) {
  const state = String(row.evidenceState || row.label || "").trim().toLowerCase().replace(/-/g, "_");
  const haystack = [
    row.currentStatus,
    row.manifestBinding,
    row.evidencePath,
    row.artifactPath,
    row.nextCommand,
    ...(Array.isArray(row.problems) ? row.problems : []),
    item?.detail,
    item?.meta,
    item?.label,
    item?.packet?.summary,
  ].map((value) => String(value || "").toLowerCase()).join("\n");

  if (state === "stale" || state === "invalid" || /\bstale\b|mismatch|copied|reused|skipped-test|skipped test|different commit/.test(haystack)) {
    return {
      label: state === "invalid" ? "invalid or stale" : "stale evidence",
      tone: state === "invalid" ? "bad" : "warn",
      detail: "Regenerate and record this artifact from the accepted checkout before using it for release acceptance.",
    };
  }

  if (/\baccepted by\b|verified release acceptance manifest/.test(haystack) || row.label === "passed") {
    return {
      label: "accepted-source evidence",
      tone: "ok",
      detail: "This artifact is bound to the verified release acceptance manifest for the accepted source snapshot.",
    };
  }

  if (/remote continuation|continuation evidence|targeted repair|desktop-scoped smoke|same-snapshot broad|remote validation/.test(haystack)) {
    return {
      label: "remote continuation evidence",
      tone: "warn",
      detail: "Useful for handoff and repair context only; rerun and record through repo-local release tooling before acceptance.",
    };
  }

  if (/template|planned-not-executed|only prepares|prepares? the bundle directory|browser-local|diagnostic only|does not record durable release evidence/.test(haystack)) {
    return {
      label: "template/non-evidence",
      tone: "info",
      detail: "This is a template, plan, or browser-local handoff and does not satisfy the release gate by itself.",
    };
  }

  if (state === "recorded") {
    return {
      label: "recorded source evidence",
      tone: "warn",
      detail: "Recorded artifact exists, but it is not accepted until the release manifest is assembled and verified.",
    };
  }

  if (state === "missing") {
    return {
      label: "no evidence recorded",
      tone: "bad",
      detail: "Run the validate and record commands from this checkout to create release evidence.",
    };
  }

  return {
    label: "review required",
    tone: row.cls === "bad" ? "bad" : "warn",
    detail: "The current artifact state is not enough to classify as accepted-source evidence.",
  };
}

export function releaseArtifactCustodyBoundary(row = {}) {
  const accepted = /\baccepted by\b/i.test(String(row.manifestBinding || "")) || row.label === "passed";
  return {
    label: "hardening-only",
    tone: "warn",
    detail: accepted
      ? "Manifest acceptance is present, but artifact signing and retained custody controls are still tracked as hardening."
      : "Do not treat this artifact as signed, retained, or custody-certified; signing and custody remain hardening backlog items.",
  };
}

async function copyReleaseEvidenceSummary(items) {
  const report = redactReadinessDisclosureText(releaseEvidenceReport(items));
  try {
    if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(report);
    toast("Release evidence copied", "Pasted summary includes release gate counts, item states, details, and target UI links.", "ok");
  } catch {
    toast("Copy unavailable", "Review the generated release evidence summary in the drawer.", "warn");
    openDrawer({
      title: "Release evidence summary",
      subtitle: "Browser-generated from the current Readiness evidence strip",
      width: "720px",
      body: h("textarea", { class: "input release-evidence-report", readonly: true, rows: 16, spellcheck: "false" }, report),
      footer: [
        h("button", { class: "btn primary", type: "button", title: "Close release evidence summary", "aria-label": "Close release evidence summary", dataset: { releaseEvidenceAction: "close-summary-fallback" }, onclick: closeDrawer }, "Close"),
      ],
    });
  }
}

function openRoutedReleaseAcceptanceStatus(status = {}) {
  writeReadinessRouteState({ drawer: "release-acceptance" });
  openReleaseAcceptanceStatus(status, { routeBacked: "release-acceptance" });
}

function openReleaseAcceptanceStatus(status = {}, opts = {}) {
  const routeDrawer = readinessRouteBackedKind(opts.routeBacked, "release-acceptance");
  if (routeDrawer) {
    if (!isCurrentReadinessRouteDrawer(routeDrawer)) return;
    activeReadinessRouteDrawer = routeDrawer;
  }
  const model = releaseAcceptanceStatusViewModel(status);
  const report = redactReadinessDisclosureText(releaseAcceptanceStatusReport(model));
  openDrawer({
    title: "Release acceptance status",
    subtitle: model.schema || "phragma.release.status.v1",
    width: "860px",
    body: h("div", {
      class: "release-acceptance-status",
      dataset: { readinessReleaseAcceptance: "true" },
    },
      h("div", { class: "preflight-summary" },
        h("div", {}, h("span", {}, "State"), h("strong", {}, model.state || "unknown")),
        h("div", {}, h("span", {}, "Passed"), h("strong", {}, String(model.summary.passed))),
        h("div", {}, h("span", {}, "Recorded"), h("strong", {}, String(model.summary.recorded))),
        h("div", {}, h("span", {}, "Missing"), h("strong", {}, String(model.summary.missing))),
        h("div", {}, h("span", {}, "Invalid"), h("strong", {}, String(model.summary.invalid))),
        h("div", {}, h("span", {}, "Not applicable"), h("strong", {}, String(model.summary.notApplicable))),
        h("div", {}, h("span", {}, "Todo"), h("strong", {}, String(model.summary.todo))),
        h("div", {}, h("span", {}, "Manifest"), h("strong", {}, model.manifestPresent ? "present" : "missing"))),
      h("div", { class: "alert-box " + readinessBoxClass(model.cls) },
        h("strong", {}, model.title),
        h("div", { class: "note" }, model.detail)),
      model.recordability ? releaseAcceptanceRecordabilityBlock(model.recordability) : null,
      model.problems.length ? h("div", { class: "warning-list release-acceptance-problems" },
        model.problems.slice(0, 8).map((problem) => h("div", { class: "warning-row bad" },
          h("div", {}, badge("problem", "bad", { dot: true })),
          h("div", {},
            h("strong", {}, problem),
            h("div", { class: "note" }, "Release acceptance remains blocked until this problem is closed."))))) : null,
      h("div", { class: "release-acceptance-check-list" },
        model.checks.map((check) => releaseAcceptanceCheckRow(check))),
      model.omittedCommandGuidance.length ? releaseAcceptanceOmittedCommandGuidanceBlock(model.omittedCommandGuidance) : null,
      h("textarea", {
        class: "input release-acceptance-report",
        dataset: { releaseAcceptanceReport: "true" },
        readonly: true,
        rows: 14,
        wrap: "soft",
        spellcheck: "false",
      }, report)),
    footer: [
      h("button", { class: "btn ghost", ...readinessActionAttrs("close-release-acceptance", "Close release acceptance status"), dataset: { releaseAcceptanceAction: "close" }, onclick: closeDrawer }, "Close"),
      h("button", { class: "btn primary", ...readinessActionAttrs("copy-release-acceptance-status", "Copy release acceptance status", { releaseAcceptanceAction: "copy-report" }), onclick: () => copyReleaseAcceptanceStatus(report) },
        h("span", { html: icon("copy", 16) }), "Copy status"),
    ],
    onClose: routeDrawer ? () => clearReadinessRouteStateFor(routeDrawer) : null,
  });
}

function releaseAcceptanceOmittedCommandGuidanceBlock(items = []) {
  return h("div", {
    class: "alert-box warn release-acceptance-omitted-command-guidance",
    dataset: { releaseAcceptanceOmittedCommandGuidance: "true" },
  },
    h("div", { class: "release-evidence-head" },
      h("strong", {}, "Next commands for omitted checks"),
      badge(`${items.length} omitted`, "warn", { dot: true })),
    h("div", { class: "note" }, "The status endpoint did not report these known release gates. Operators can still use the packet catalog commands below to validate and record the missing evidence through release tooling."),
    h("div", { class: "release-acceptance-check-list compact" },
      items.map((item) => h("div", {
        class: "release-acceptance-check-row warn",
        dataset: { releaseAcceptanceOmittedCheck: item.name || "" },
      },
        h("div", {},
          h("strong", { class: "mono" }, item.name || "release-check"),
          h("div", { class: "note" }, item.title || "Known release gate omitted from the status endpoint."),
          h("div", { class: "release-evidence-command-list release-acceptance-command-list" },
            item.nextCommands.map((command) => releaseAcceptanceCommandRow(item.name, command)))),
        badge("not reported", "warn", { dot: true })))));
}

function releaseAcceptanceCheckRow(check = {}) {
  const packetHref = releaseEvidencePacketDrillHref(check.name);
  return h("div", {
    class: "release-acceptance-check-row " + (check.cls || "info"),
    dataset: { releaseAcceptanceCheck: check.name || "" },
  },
    h("div", {},
      h("strong", { class: "mono" }, check.name || "release-check"),
      h("div", { class: "note" }, check.detail || releaseAcceptanceCheckDetail(check)),
      check.meta ? h("div", { class: "release-acceptance-meta mono" }, check.meta) : null,
      check.sourceAcceptance ? releaseEvidenceSourceAcceptance(check.sourceAcceptance) : null,
      check.problems.length ? h("div", { class: "release-acceptance-problem-list" },
        check.problems.slice(0, 4).map((problem) => h("span", {}, problem))) : null,
      check.nextCommands.length ? h("div", { class: "release-evidence-command-list release-acceptance-command-list" },
        check.nextCommands.map((item) => releaseAcceptanceCommandRow(check.name, item))) : null,
      packetHref ? h("div", { class: "row-actions release-acceptance-packet-actions" },
        h("a", {
          class: "btn sm ghost",
          href: packetHref,
          title: `Open release packet for ${check.name || "release acceptance check"}`,
          dataset: { releaseAcceptancePacketLink: check.name || "" },
          "aria-label": `Open release packet for ${check.name || "release acceptance check"}`,
        }, h("span", { html: icon("arrowRight", 15) }), "Open packet")) : null),
    badge(check.label || check.state || "unknown", check.cls || "info", { dot: true }));
}

function releaseAcceptanceCommandRow(checkName, item = {}) {
  const role = item.role || "Command";
  const command = redactReadinessDisclosureText(item.command || "");
  return h("div", { class: "release-evidence-command-row release-acceptance-command-row" },
    h("div", {},
      h("span", {}, role),
      h("code", {
        dataset: {
          releaseAcceptanceCommand: checkName || "",
          releaseAcceptanceCommandRole: role.toLowerCase().replace(/\s+/g, "-"),
        },
      }, command)),
    readinessCommandCopyButton(role, command, {
      ariaLabel: `Copy ${role.toLowerCase()} command for ${checkName || "release acceptance"}`,
      dataset: { releaseAcceptanceCommandCopy: checkName || "", releaseAcceptanceCommandRole: role.toLowerCase().replace(/\s+/g, "-") },
    }));
}

function releaseEvidencePacketDrillHref(id = "") {
  const packet = String(id || "").trim();
  if (!packet || !releaseEvidencePacketIds().includes(packet)) return "";
  return `#/readiness?packet=${encodeURIComponent(packet)}`;
}

function releaseEvidenceSourceAcceptance(model = {}) {
  const dirtyCount = Number(model.dirtySourceCount || 0) + Number(model.truncatedDirtySourceCount || 0);
  return h("div", {
    class: "alert-box " + readinessBoxClass(model.cls || "warn") + " release-acceptance-source-acceptance",
    dataset: { releaseAcceptanceSourceAcceptance: model.state || "unknown" },
  },
    h("div", { class: "release-evidence-head" },
      h("strong", {}, "API contract source acceptance"),
      badge(model.label || model.state || "review", model.cls || "warn", { dot: true })),
    h("div", { class: "note" }, model.detail || "Source-control acceptance status is unavailable."),
    h("dl", { class: "kv compact release-acceptance-source-acceptance-kv" },
      releaseAcceptanceRecordabilityKv("Dirty source count", String(dirtyCount)),
      releaseAcceptanceRecordabilityKv("Problem count", String(Number(model.problemCount || 0)))));
}

function releaseAcceptanceRecordabilityBlock(recordability = {}) {
  const rows = [
    recordability.gitHead ? releaseAcceptanceRecordabilityKv("Git HEAD", recordability.gitHead) : null,
    recordability.recordCommit ? releaseAcceptanceRecordabilityKv("Record commit", recordability.recordCommit) : null,
    recordability.allowedDirtyPaths.length ? releaseAcceptanceRecordabilityKv("Allowed dirty paths", recordability.allowedDirtyPaths.join(", ")) : null,
    recordability.staleEvidencePaths.length ? releaseAcceptanceRecordabilityKv("Stale evidence paths", recordability.staleEvidencePaths.join(", ")) : null,
  ].filter(Boolean).flat();
  const tone = recordability.ready ? "info" : "bad";
  return h("div", {
    class: "alert-box " + tone + " release-acceptance-recordability",
    dataset: { releaseAcceptanceRecordability: recordability.ready ? "ready" : "blocked" },
  },
    h("div", { class: "release-evidence-head" },
      h("strong", {}, recordability.title),
      badge("advisory", "info", { dot: true })),
    h("div", { class: "note" }, recordability.detail),
    rows.length ? h("dl", { class: "kv compact release-acceptance-recordability-kv" }, rows) : null,
    recordability.problems.length ? h("div", { class: "release-acceptance-problem-list" },
      recordability.problems.slice(0, 4).map((problem) => h("span", {}, problem))) : null,
    recordability.visibleDirtySourcePaths.length ? h("div", { class: "release-acceptance-problem-list" },
      recordability.visibleDirtySourcePaths.map((path) => h("span", { class: "mono" }, path))) : null,
    recordability.omittedDirtySourceCount ? h("div", { class: "note" }, `${recordability.omittedDirtySourceCount} more dirty source path(s) omitted from this drawer.`) : null,
    recordability.nextAction ? h("div", { class: "note" }, recordability.nextAction) : null,
    recordability.command ? h("div", { class: "release-evidence-command-list release-acceptance-command-list" },
      releaseAcceptanceCommandRow("recordability", { role: "Preflight", command: recordability.command })) : null);
}

function releaseAcceptanceRecordabilityKv(label, value) {
  return [h("dt", {}, label), h("dd", {}, value || "—")];
}

export function releaseAcceptanceStatusViewModel(status = {}) {
  const recordability = releaseAcceptanceRecordabilityModel(status?.recordability);
  const checks = Array.isArray(status?.checks) ? status.checks.map((check) => releaseAcceptanceCheckModel(check, { recordability })) : [];
  const omittedCommandGuidance = releaseAcceptanceOmittedCommandGuidance(checks);
  const summary = releaseAcceptanceSummary(status?.summary || {}, checks);
  const problems = asStringArray(status?.problems).map(readinessDisclosureValue);
  const manifestPresent = Boolean(status?.manifestPresent ?? status?.manifest_present);
  const ready = Boolean(status?.ready);
  const state = String(status?.state || (ready ? "ready" : "unknown")).trim() || "unknown";
  const pendingManifest = state === "evidence-pending-manifest";
  const hasBlockingCounts = summary.invalid || summary.missing || summary.todo;
  const hasBlockingDisclosure = (problems.length && !pendingManifest) || (!manifestPresent && !pendingManifest);
  const cls = ready || state === "ready"
    ? "ok"
    : hasBlockingCounts || hasBlockingDisclosure
      ? "bad"
      : "warn";
  const title = cls === "ok"
    ? "Release acceptance evidence is ready."
    : pendingManifest
      ? "Release evidence is recorded; manifest assembly is pending."
    : cls === "bad"
      ? "Release acceptance is blocked."
      : "Release acceptance needs review.";
  const blockers = [
    summary.missing ? `${summary.missing} missing check(s)` : "",
    summary.invalid ? `${summary.invalid} invalid check(s)` : "",
    summary.todo ? `${summary.todo} todo check(s)` : "",
    !manifestPresent && !pendingManifest ? "manifest missing" : "",
    problems.length ? `${problems.length} problem(s)` : "",
  ].filter(Boolean);
  return {
    schema: status?.schemaVersion || status?.schema_version || "",
    generatedAt: status?.generatedAt || status?.generated_at || "",
    manifestPath: status?.manifestPath || status?.manifest_path || "",
    evidenceDir: status?.evidenceDir || status?.evidence_dir || "",
    manifestPresent,
    ready,
    state,
    cls,
    title,
    detail: pendingManifest
      ? "All required evidence is recorded, but the release acceptance manifest has not been assembled and verified yet."
      : blockers.length
      ? blockers.join("; ") + "."
      : "All required checks in the configured release acceptance report are clear.",
    summary,
    problems,
    recordability,
    checks,
    omittedCommandGuidance,
  };
}

export function releaseAcceptanceAggregateSummary(model = {}) {
  const summary = releaseAcceptanceSummary(model.summary || {}, Array.isArray(model.checks) ? model.checks : []);
  const state = String(model.state || (model.ready ? "ready" : "unknown")).trim() || "unknown";
  const manifestPresent = Boolean(model.manifestPresent);
  const problemCount = asStringArray(model.problems).length;
  const pendingManifest = state === "evidence-pending-manifest";
  const blockers = [
    summary.missing ? `${summary.missing} missing check(s)` : "",
    summary.invalid ? `${summary.invalid} invalid check(s)` : "",
    summary.todo ? `${summary.todo} todo check(s)` : "",
    !manifestPresent && !pendingManifest ? "manifest missing" : "",
    problemCount ? `${problemCount} problem(s)` : "",
  ].filter(Boolean);
  return {
    state,
    ready: Boolean(model.ready),
    manifestPresent,
    summary,
    problemCount,
    detail: pendingManifest
      ? "All required evidence is recorded, but the release acceptance manifest has not been assembled and verified yet."
      : blockers.length
        ? blockers.join("; ") + "."
        : "All required checks in the configured release acceptance report are clear.",
  };
}

function releaseAcceptanceSummary(summary = {}, checks = []) {
  const value = (snake, camel) => Number(summary?.[snake] ?? summary?.[camel] ?? 0);
  const out = {
    passed: value("passed", "passed"),
    recorded: value("recorded", "recorded"),
    missing: value("missing", "missing"),
    invalid: value("invalid", "invalid"),
    notApplicable: value("not_applicable", "notApplicable"),
    todo: value("todo", "todo"),
  };
  if (!Object.values(out).some(Boolean) && checks.length) {
    for (const check of checks) {
      if (check.state === "passed") out.passed += 1;
      else if (check.state === "recorded") out.recorded += 1;
      else if (check.state === "missing") out.missing += 1;
      else if (check.state === "invalid") out.invalid += 1;
      else if (check.state === "not_applicable") out.notApplicable += 1;
      else out.todo += 1;
    }
  }
  return out;
}

function releaseAcceptanceCheckModel(check = {}, opts = {}) {
  const state = String(check?.state || check?.status || "unknown").trim().toLowerCase().replace(/-/g, "_") || "unknown";
  const name = String(check?.name || "").trim();
  const evidencePath = check?.evidencePath || check?.evidence_path || "";
  const artifact = check?.artifact || "";
  const problems = asStringArray(check?.problems).map(readinessDisclosureValue);
  const command = asStringArray(check?.command).map(readinessDisclosureValue);
  const nextAction = readinessDisclosureValue(check?.nextAction || check?.next_action || "");
  const nextCommand = asStringArray(check?.nextCommand || check?.next_command);
  const detail = readinessDisclosureValue(releaseAcceptanceCheckModelDetail(state, check?.detail || ""));
  const cls = state === "passed" || (state === "not_applicable" && name === "release-benchmark")
    ? "ok"
    : state === "recorded" || state === "not_applicable"
      ? "warn"
    : state === "review_needed" || state === "review-needed"
      ? "warn"
    : state === "invalid" || state === "missing" || problems.length
      ? "bad"
    : "warn";
  return {
    name,
    state,
    cls,
    label: state === "recorded" ? "pending manifest" : state === "review_needed" || state === "review-needed" ? "review needed" : state === "not_applicable" && name !== "release-benchmark" ? "review needed" : state === "not_applicable" ? "not applicable" : state || "unknown",
    detail,
    meta: readinessDisclosureValue(evidencePath || artifact || ""),
    ranAt: check?.ranAt || check?.ran_at || "",
    command,
    nextAction,
    nextCommands: releaseAcceptanceNextCommands({ name, state, command, problems, nextAction, nextCommand })
      .map((item) => ({ ...item, role: readinessDisclosureValue(item.role || "Command"), command: readinessDisclosureValue(item.command || "") }))
      .filter((item) => item.command),
    problems,
    sourceAcceptance: name === "proto-verify" ? apiContractSourceAcceptanceForView(opts.recordability) : null,
  };
}

function releaseAcceptanceOmittedCommandGuidance(checks = []) {
  const reported = new Set(checks.map((check) => check.name).filter(Boolean));
  return releaseEvidencePacketIds()
    .filter((id) => !reported.has(id))
    .map((id) => {
      const definition = releaseEvidencePacketDefinition(id);
      const commandItems = releaseAcceptanceCatalogCommandItems(id);
      return {
        name: id,
        title: definition?.title || id,
        nextCommands: commandItems,
      };
    })
    .filter((item) => item.nextCommands.length);
}

function apiContractSourceAcceptanceForView(recordability = null) {
  if (!recordability) {
    return {
      state: "unknown",
      cls: "warn",
      label: "source acceptance unknown",
      dirtySourceCount: 0,
      problemCount: 0,
      truncatedDirtySourceCount: 0,
      detail: "Functional proto/OpenAPI generation and copy consistency can be validated independently, but proto-verify release evidence is not acceptable until the atomic API contract tree is accepted in source control.",
    };
  }
  const dirtySourceCount = asStringArray(recordability.dirtySourcePaths).length;
  const truncatedDirtySourceCount = Number(recordability.truncatedDirtySourceCount || 0);
  const problemCount = asStringArray(recordability.problems).length;
  const staleEvidenceCount = asStringArray(recordability.staleEvidencePaths).length;
  const blocked = !recordability.ready || dirtySourceCount > 0 || truncatedDirtySourceCount > 0 || problemCount > 0 || staleEvidenceCount > 0;
  return {
    state: blocked ? "blocked" : "clear",
    cls: blocked ? "bad" : "ok",
    label: blocked ? "source acceptance pending" : "source accepted",
    dirtySourceCount,
    staleEvidenceCount,
    problemCount,
    truncatedDirtySourceCount,
    detail: blocked
      ? "Source-control recordability is blocked. Functional proto/OpenAPI generation can still be OK, but proto-verify release evidence is not acceptable until the atomic API contract tree is accepted."
      : "Source-control recordability is clear for recording evidence; functional proto/OpenAPI generation still needs the proto-verify command path.",
  };
}

function releaseAcceptanceCheckModelDetail(state = "", detail = "") {
  const text = String(detail || "").trim();
  const fallback = releaseAcceptanceCheckDetail({ state });
  if (state !== "recorded") return text || fallback;
  if (!text) return fallback;
  if (/not accepted until/i.test(text)) return text;
  return `${text} ${fallback}`;
}

function releaseAcceptanceNextCommands(check = {}) {
  const state = String(check.state || "").trim();
  const blocked = state === "missing" || state === "invalid" || asStringArray(check.problems).length > 0;
  if (!blocked) return [];
  const catalogFallback = releaseAcceptanceCatalogCommandItems(check.name);
  const tableFallback = (RELEASE_ACCEPTANCE_NEXT_COMMANDS[check.name] || [])
    .map(([role, command]) => ({ role, command }))
    .filter((item) => item.command);
  const fallback = catalogFallback.length ? catalogFallback : tableFallback;
  const nextCommand = asStringArray(check.nextCommand);
  if (nextCommand.length) {
    const commands = [{ role: check.nextAction ? "Next" : "Record", command: shellJoin(nextCommand) }];
    const seen = new Set(commands.map((item) => item.command));
    for (const item of fallback) {
      if (!seen.has(item.command)) commands.push(item);
    }
    return commands;
  }
  const recorded = asStringArray(check.command);
  if (state === "invalid" && recorded.length) {
    return [{ role: "Rerun", command: recorded.join(" ") }];
  }
  return fallback;
}

function releaseAcceptanceCatalogCommandItems(checkName = "") {
  const definition = releaseEvidencePacketDefinition(checkName);
  const items = Array.isArray(definition?.packet?.commandItems) ? definition.packet.commandItems : [];
  return items
    .map((item) => ({ role: item?.role || "Command", command: item?.command || "" }))
    .filter((item) => item.command);
}

function releaseAcceptanceCheckDetail(check = {}) {
  if (check.state === "missing") return "Evidence artifact is missing.";
  if (check.state === "invalid") return "Evidence exists but did not pass validation.";
  if (check.state === "review_needed") return "Evidence is present, but stale, copied, mismatched, reused, skipped, or otherwise needs human review before it can be accepted.";
  if (check.state === "not_applicable") return "This check is explicitly not applicable for the configured release mode.";
  if (check.state === "recorded") return "Evidence is recorded but is not accepted until the release acceptance manifest is assembled and verified.";
  if (check.state === "passed") return "Evidence is accepted by the verified release acceptance manifest.";
  return "Release check requires review.";
}

function releaseAcceptanceRecordabilityModel(recordability = null) {
  if (!recordability || typeof recordability !== "object") return null;
  const problems = asStringArray(recordability.problems).map(readinessDisclosureValue);
  const dirtySourcePaths = asStringArray(recordability.dirtySourcePaths || recordability.dirty_source_paths).map(readinessDisclosureValue);
  const staleEvidencePaths = asStringArray(recordability.staleEvidencePaths || recordability.stale_evidence_paths).map(readinessDisclosureValue);
  const truncated = Number(recordability.truncatedDirtySourceCount ?? recordability.truncated_dirty_source_count ?? 0);
  const serverTruncated = Number.isFinite(truncated) && truncated > 0 ? truncated : 0;
  const visibleDirtySourcePaths = dirtySourcePaths.slice(0, RECORDABILITY_DIRTY_PATH_DISPLAY_LIMIT);
  const omittedDirtySourceCount = Math.max(0, dirtySourcePaths.length - visibleDirtySourcePaths.length) + serverTruncated;
  const ready = Boolean(recordability.ready);
  const blocked = !ready || problems.length > 0 || dirtySourcePaths.length > 0 || staleEvidencePaths.length > 0 || serverTruncated > 0;
  const nextAction = readinessDisclosureValue(recordability.nextAction || recordability.next_action || (blocked ? "Commit or stash source changes before recording release evidence." : ""));
  const detail = blocked
    ? "The local checkout is not clean enough for ngfwrelease record. This preflight does not create evidence, assemble the manifest, or make any check clear."
    : "The local checkout is clean enough to record release evidence. This preflight does not create evidence, assemble the manifest, or make any check clear.";
  return {
    ready,
    cls: blocked ? "bad" : "info",
    title: blocked ? "Recording preflight is blocked." : "Recording preflight is clear.",
    detail,
    gitHead: readinessDisclosureValue(recordability.gitHead || recordability.git_head || ""),
    recordCommit: readinessDisclosureValue(recordability.recordCommit || recordability.record_commit || ""),
    allowedDirtyPaths: asStringArray(recordability.allowedDirtyPaths || recordability.allowed_dirty_paths).map(readinessDisclosureValue),
    staleEvidencePaths,
    dirtySourcePaths,
    visibleDirtySourcePaths,
    omittedDirtySourceCount,
    truncatedDirtySourceCount: serverTruncated,
    problems,
    nextAction,
    command: "make release-recordability-check COMMIT=<full-commit>",
  };
}

export function releaseAcceptanceStatusSummaryReport(model = {}) {
  const checks = Array.isArray(model.checks) ? model.checks : [];
  const recordability = model.recordability || null;
  const lines = [
    "OpenNGFW release acceptance summary",
    `schema=${oneLine(model.schema || "phragma.release.status.v1")}`,
    `generated_at=${oneLine(model.generatedAt || "")}`,
    `state=${oneLine(model.state || "unknown")}`,
    `ready=${model.ready ? "true" : "false"}`,
    `manifest=${model.manifestPresent ? "present" : "missing"}`,
    `summary=passed:${model.summary?.passed || 0} recorded:${model.summary?.recorded || 0} missing:${model.summary?.missing || 0} invalid:${model.summary?.invalid || 0} not_applicable:${model.summary?.notApplicable || 0} todo:${model.summary?.todo || 0}`,
    `problem_count=${asStringArray(model.problems).length}`,
  ];
  if (recordability) {
    lines.push(`recordability=${recordability.ready ? "ready" : "blocked"} dirty_source_count=${asStringArray(recordability.dirtySourcePaths).length} stale_evidence_count=${asStringArray(recordability.staleEvidencePaths).length} problem_count=${asStringArray(recordability.problems).length}`);
  }
  lines.push("");
  lines.push("checks:");
  if (!checks.length) {
    lines.push("- none reported");
  } else {
    for (const check of checks) {
      lines.push(`- ${oneLine(check.name || "release-check")}: ${oneLine(check.state || "unknown")}`);
    }
  }
  lines.push("");
  lines.push("note=Summary report intentionally omits manifest paths, evidence paths, dirty source paths, problem text, and commands. Open Readiness as an authorized operator for detailed remediation.");
  return lines.join("\n").trimEnd() + "\n";
}

export function releaseAcceptanceStatusReport(model = {}) {
  const lines = [
    "OpenNGFW release acceptance status",
    `schema=${oneLine(model.schema || "phragma.release.status.v1")}`,
    `generated_at=${oneLine(model.generatedAt || "")}`,
    `state=${oneLine(model.state || "unknown")}`,
    `manifest=${oneLine(model.manifestPath || "release/acceptance.json")} present=${model.manifestPresent ? "true" : "false"}`,
    `evidence_dir=${oneLine(model.evidenceDir || "release/evidence")}`,
    `summary=passed:${model.summary?.passed || 0} recorded:${model.summary?.recorded || 0} missing:${model.summary?.missing || 0} invalid:${model.summary?.invalid || 0} not_applicable:${model.summary?.notApplicable || 0} todo:${model.summary?.todo || 0}`,
    "",
  ];
  for (const problem of asStringArray(model.problems)) {
    lines.push(`problem: ${oneLine(problem)}`);
  }
  if (model.problems?.length) lines.push("");
  if (model.recordability) {
    const r = model.recordability;
    lines.push(`recordability=${r.ready ? "ready" : "blocked"} advisory=true`);
    if (r.gitHead) lines.push(`  git_head=${oneLine(r.gitHead)}`);
    if (r.recordCommit) lines.push(`  record_commit=${oneLine(r.recordCommit)}`);
    if (r.allowedDirtyPaths?.length) lines.push(`  allowed_dirty_paths=${r.allowedDirtyPaths.map(oneLine).join(", ")}`);
    if (r.staleEvidencePaths?.length) lines.push(`  stale_evidence_paths=${r.staleEvidencePaths.map(oneLine).join(", ")}`);
    for (const problem of asStringArray(r.problems)) lines.push(`  problem: ${oneLine(problem)}`);
    if (r.dirtySourcePaths?.length) lines.push(`  dirty_source_paths=${r.dirtySourcePaths.map(oneLine).join(", ")}`);
    if (r.truncatedDirtySourceCount) lines.push(`  dirty_source_paths_truncated=${r.truncatedDirtySourceCount}`);
    if (r.nextAction) lines.push(`  next: ${oneLine(r.nextAction)}`);
    if (r.command) lines.push(`  command (Preflight): ${oneLine(r.command)}`);
    lines.push("  note: advisory only; does not create evidence, assemble the manifest, or make checks clear.");
    lines.push("");
  }
  for (const check of Array.isArray(model.checks) ? model.checks : []) {
    lines.push(`- ${oneLine(check.name || "release-check")}: ${oneLine(check.state || "unknown")}`);
    if (check.meta) lines.push(`  evidence: ${oneLine(check.meta)}`);
    if (check.detail) lines.push(`  detail: ${oneLine(check.detail)}`);
    for (const problem of asStringArray(check.problems)) lines.push(`  problem: ${oneLine(problem)}`);
    if (check.nextAction) lines.push(`  next: ${oneLine(check.nextAction)}`);
    for (const item of Array.isArray(check.nextCommands) ? check.nextCommands : []) {
      lines.push(`  command (${oneLine(item.role || "Command")}): ${oneLine(item.command || "")}`);
    }
  }
  if (Array.isArray(model.omittedCommandGuidance) && model.omittedCommandGuidance.length) {
    lines.push("");
    lines.push("next commands for checks omitted from status report:");
    for (const check of model.omittedCommandGuidance) {
      lines.push(`- ${oneLine(check.name || "release-check")}: not reported by status endpoint`);
      for (const item of Array.isArray(check.nextCommands) ? check.nextCommands : []) {
        lines.push(`  command (${oneLine(item.role || "Command")}): ${oneLine(item.command || "")}`);
      }
    }
  }
  return lines.join("\n").trimEnd() + "\n";
}

function asStringArray(value) {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean);
  if (typeof value === "string" && value.trim()) return [value.trim()];
  return [];
}

function oneLine(value) {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}

function currentReadinessRoute() {
  if (typeof location === "undefined") return "#/readiness";
  return location.hash || "#/readiness";
}

function shellJoin(argv = []) {
  return asStringArray(argv).map(shellQuote).join(" ");
}

function shellQuote(arg) {
  const value = String(arg ?? "");
  if (/^[A-Za-z0-9_./:=@%+-]+$/.test(value)) return value;
  return "'" + value.replace(/'/g, "'\"'\"'") + "'";
}

async function copyReleaseAcceptanceStatus(report) {
  try {
    if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(report);
    toast("Acceptance status copied", "Copied configured release manifest, evidence counts, check states, and blockers.", "ok");
  } catch {
    toast("Copy unavailable", "Select and copy the release acceptance status text from the drawer.", "warn");
  }
}

function releaseEvidenceRow(item) {
  const packetCommands = releaseEvidencePacketCommands(item.packet);
  const hasPacket = Boolean(item.packet && (item.packet.check || item.packet.evidencePath || packetCommands.length));
  return h("div", {
    class: "release-evidence-item " + (item.cls || "info"),
    dataset: { releaseEvidence: item.id || "" },
  },
    h("div", { class: "release-evidence-icon", "aria-hidden": "true", html: icon(item.icon || "check", 18) }),
    h("div", { class: "release-evidence-main" },
      h("div", { class: "release-evidence-head" },
        h("strong", {}, item.title || "Release evidence"),
        badge(item.label || item.cls || "status", item.cls || "info", { dot: true })),
      h("div", { class: "note" }, item.detail || "No detail available."),
      item.meta ? h("div", { class: "release-evidence-meta mono" }, item.meta) : null,
      item.sourceAcceptance ? releaseEvidenceSourceAcceptance(item.sourceAcceptance) : null,
      h("div", { class: "release-evidence-actions" },
        item.href ? h("a", {
          class: "btn sm ghost",
          href: item.href,
          title: `Open ${item.title || item.id || "release evidence"}`,
          dataset: { releaseEvidenceAction: "open-route", releaseEvidenceLink: item.id || "" },
          "aria-label": `Open ${item.title || item.id || "release evidence"}`,
        }, h("span", { html: icon("arrowRight", 15) }), "Open") : null,
        hasPacket ? h("button", {
          class: "btn sm ghost",
          type: "button",
          title: `Open ${item.title || item.id || "release evidence"} packet`,
          "aria-label": `Open ${item.title || item.id || "release evidence"} packet`,
          dataset: { releaseEvidenceAction: "open-packet", releaseEvidencePacket: item.id || "" },
          onclick: () => openRoutedReleaseEvidencePacket(item),
        }, h("span", { html: icon("terminal", 15) }), "Packet") : null),
      hasPacket ? releaseEvidenceInlineDetails(item) : null));
}

function releaseEvidenceInlineDetails(item = {}) {
  const packet = item.packet || {};
  const commandItems = releaseEvidencePacketCommandItems(packet);
  const reference = readinessDisclosureValue(packet.reference || item.reference || "");
  const evidencePath = readinessDisclosureValue(packet.evidencePath || item.meta || "release evidence");
  const artifactPath = readinessDisclosureValue(packet.artifactPath || "release/evidence");
  const packetRoute = readinessDisclosureValue(releaseEvidencePacketRoute(item));
  const operatorRoute = readinessDisclosureValue(item.href || "");
  return h("details", {
    class: "release-evidence-detail",
    dataset: { releaseEvidenceDetail: item.id || "" },
  },
    h("summary", {},
      h("span", { html: icon("terminal", 14) }),
      "Evidence details"),
    h("div", { class: "release-evidence-detail-body" },
      h("div", { class: "release-evidence-packet-field" },
        h("span", {}, "Evidence path"),
        h("code", {
          class: "mono",
          dataset: { releaseEvidencePath: item.id || "" },
        }, evidencePath)),
      h("div", { class: "release-evidence-packet-field" },
        h("span", {}, "Artifact"),
        h("code", { class: "mono" }, artifactPath)),
      h("div", { class: "release-evidence-packet-field" },
        h("span", {}, "Status"),
        h("code", { class: "mono" }, readinessDisclosureValue(item.label || item.cls || "unknown"))),
      packetRoute ? h("div", { class: "release-evidence-packet-field" },
        h("span", {}, "Packet route"),
        h("code", { class: "mono", dataset: { releaseEvidencePacketRoute: item.id || "" } }, packetRoute)) : null,
      operatorRoute ? h("div", { class: "release-evidence-packet-field" },
        h("span", {}, "Operator route"),
        h("code", { class: "mono", dataset: { releaseEvidenceOperatorRoute: item.id || "" } }, operatorRoute)) : null,
      reference ? h("div", { class: "release-evidence-packet-field" },
        h("span", {}, "Reference"),
        h("code", {
          class: "mono",
          dataset: { releaseEvidenceReference: item.id || "" },
        }, reference)) : null,
      commandItems.length ? h("div", { class: "release-evidence-command-list" },
        commandItems.map((command) => releaseEvidenceCommandRow(command.role, command.command))) : null));
}

function openRoutedReleaseEvidencePacket(item = {}) {
  const id = String(item.id || "").trim();
  if (id) writeReadinessRouteState({ packet: id });
  openReleaseEvidencePacket(item, { routeBacked: id ? `packet:${id}` : false });
}

function openReleaseEvidencePacket(item = {}, opts = {}) {
  const routeDrawer = readinessRouteBackedKind(opts.routeBacked, item.id ? `packet:${item.id}` : "packet");
  if (routeDrawer) {
    if (!isCurrentReadinessRouteDrawer(routeDrawer)) return;
    activeReadinessRouteDrawer = routeDrawer;
  }
  const packet = item.packet || {};
  const commandItems = releaseEvidencePacketCommandItems(packet);
  const commands = commandItems.map((item) => item.command).filter(Boolean);
  const reference = readinessDisclosureValue(packet.reference || item.reference || "");
  const text = releaseEvidencePacketText(item);
  const handoff = releaseEvidenceInvestigationHandoffPacket(item, text);
  const evidencePath = readinessDisclosureValue(packet.evidencePath || "release evidence");
  const artifactPath = readinessDisclosureValue(packet.artifactPath || "release/evidence");
  openDrawer({
    title: item.title || "Release evidence packet",
    subtitle: packet.check || item.id || "release gate",
    width: "760px",
    body: h("div", {
      class: "release-evidence-packet",
      dataset: { releaseEvidencePacket: item.id || "", releaseEvidencePacketDetail: item.id || "" },
    },
      h("div", { class: "preflight-summary" },
        h("div", {}, h("span", {}, "State"), h("strong", {}, item.label || item.cls || "unknown")),
        h("div", {}, h("span", {}, "Check"), h("strong", { class: "mono" }, packet.check || item.id || "unknown")),
        h("div", {}, h("span", {}, "Evidence"), h("strong", { class: "mono", dataset: { releaseEvidencePath: item.id || "" } }, evidencePath)),
        h("div", {}, h("span", {}, "Artifact"), h("strong", { class: "mono" }, artifactPath))),
      h("div", { class: "alert-box " + readinessBoxClass(item.cls || "info") },
        h("strong", {}, item.meta || item.label || "Release evidence"),
        h("div", { class: "note" }, item.detail || "No detail available.")),
      h("div", { class: "alert-box info", dataset: { releaseEvidencePacketBoundary: item.id || "" } },
        h("strong", {}, "Browser-local handoff"),
        h("div", { class: "note" }, "Copy, export, and pin actions preserve the currently displayed packet for operator review. They do not record durable release evidence, assemble a manifest, or make a release gate pass.")),
      releaseEvidencePacketCurrentGap(item),
      reference ? h("div", { class: "release-evidence-packet-field" },
        h("span", {}, "Reference"),
        h("code", {
          class: "mono",
          dataset: { releaseEvidenceReference: item.id || "" },
        }, reference)) : null,
      commandItems.length ? h("div", { class: "release-evidence-command-list" },
        commandItems.map((item) => releaseEvidenceCommandRow(item.role, item.command))) :
        emptyState("terminal", "No packet commands", "This release evidence item has no command metadata."),
      h("textarea", {
        class: "input release-evidence-report",
        dataset: { releaseEvidencePacketReport: item.id || "" },
        readonly: true,
        rows: 12,
        wrap: "soft",
        spellcheck: "false",
      }, text)),
    footer: [
      h("button", { class: "btn ghost", ...readinessActionAttrs("close-release-evidence-packet", "Close release evidence packet", { releaseEvidencePacketAction: "close", releaseEvidencePacket: item.id || "" }), onclick: closeDrawer }, "Close"),
      h("button", { class: "btn", ...readinessActionAttrs("pin-release-evidence-packet", "Pin release evidence packet to case", { releaseEvidencePacketAction: "pin", releaseEvidencePacket: item.id || "" }), onclick: () => pinReleaseEvidencePacket(handoff) },
        h("span", { html: icon("inbox", 16) }), "Pin to case"),
      h("a", { class: "btn ghost", href: activeInvestigationServerCaseHref(), title: "Open active investigation case", "aria-label": "Open active investigation case", dataset: { releaseEvidencePacketAction: "open-active-case", releaseEvidencePacket: item.id || "" } },
        h("span", { html: icon("search", 16) }), "Open active case"),
      h("button", { class: "btn", ...readinessActionAttrs("export-release-evidence-packet", "Export release evidence packet JSON", { releaseEvidencePacketAction: "export", releaseEvidencePacket: item.id || "" }), onclick: () => exportReleaseEvidencePacket(handoff) },
        h("span", { html: icon("download", 16) }), "Export JSON"),
      commands.length ? h("button", { class: "btn", ...readinessActionAttrs("copy-release-evidence-packet-commands", "Copy release evidence packet commands", { releaseEvidencePacketAction: "copy-commands", releaseEvidencePacket: item.id || "" }), onclick: () => copyReleaseEvidencePacketCommands(item) },
        h("span", { html: icon("copy", 16) }), "Copy commands") : null,
      h("button", { class: "btn primary", ...readinessActionAttrs("copy-release-evidence-packet", "Copy release evidence packet", { releaseEvidencePacketAction: "copy", releaseEvidencePacket: item.id || "" }), onclick: () => copyReleaseEvidencePacket(handoff) },
        h("span", { html: icon("copy", 16) }), "Copy packet"),
    ],
    onClose: routeDrawer ? () => clearReadinessRouteStateFor(routeDrawer) : null,
  });
}

function releaseEvidenceInvestigationHandoffPacket(item = {}, text = releaseEvidencePacketText(item)) {
  const packet = item.packet || {};
  const commandItems = releaseEvidencePacketCommandItems(packet);
  const safeItem = releaseEvidencePacketDisclosureItem(item);
  const safePacket = safeItem.packet || {};
  return buildInvestigationPacket({
    kind: "release-evidence",
    title: "Release evidence packet handoff",
    subject: {
      id: item.id || packet.check || "release-evidence",
      label: item.title || packet.check || "Release evidence",
    },
    summary: {
      check: packet.check || item.id || "",
      state: item.label || item.cls || "unknown",
      gateTone: item.cls || "info",
      evidencePath: safePacket.evidencePath || readinessDisclosureValue(item.meta || ""),
      artifactPath: safePacket.artifactPath || "",
      packetRoute: readinessDisclosureValue(releaseEvidencePacketRoute(item)),
      operatorRoute: safeItem.href || "",
      commandCount: commandItems.length,
      durableEvidenceRecorded: false,
      boundary: "Browser-local handoff only; run the record command through release tooling after source-control acceptance.",
    },
    evidence: text.split("\n"),
    artifacts: {
      releaseEvidenceItem: safeItem,
      releaseEvidencePacket: safePacket,
    },
  }, { route: currentReadinessRoute(), collectedAt: new Date().toISOString() });
}

export function releaseEvidencePacketText(item = {}) {
  const packet = item.packet || {};
  const commandItems = releaseEvidencePacketCommandItems(packet);
  const packetRoute = releaseEvidencePacketRoute(item);
  const lines = [
    "OpenNGFW release evidence packet",
    `check=${oneLine(packet.check || item.id || "release-evidence")}`,
    `title=${readinessDisclosureValue(item.title || "Release evidence")}`,
    `state=${readinessDisclosureValue(item.label || item.cls || "unknown")}`,
    `current_gap=${readinessDisclosureValue(item.meta || item.label || item.cls || "unknown")}`,
    `current_gap_detail=${readinessDisclosureValue(item.detail || packet.summary || "")}`,
    `operator_route=${readinessDisclosureValue(item.href || "")}`,
    `packet_route=${readinessDisclosureValue(packetRoute)}`,
    `evidence_path=${readinessDisclosureValue(packet.evidencePath || item.meta || "")}`,
    `artifact_path=${readinessDisclosureValue(packet.artifactPath || "")}`,
    `reference=${readinessDisclosureValue(packet.reference || item.reference || "")}`,
    `summary=${readinessDisclosureValue(packet.summary || item.detail || "")}`,
    "boundary=Browser-local copy/export/pin only; durable release evidence still requires ngfwrelease/release tooling record and manifest verification.",
    "",
  ];
  for (const command of commandItems) {
    lines.push(`command (${readinessDisclosureValue(command.role)}): ${readinessDisclosureValue(command.command)}`);
  }
  return lines.join("\n").trimEnd() + "\n";
}

function releaseEvidencePacketDisclosureItem(item = {}) {
  const packet = item.packet || {};
  const cleanPacket = {
    check: readinessDisclosureValue(packet.check || ""),
    evidencePath: readinessDisclosureValue(packet.evidencePath || ""),
    artifactPath: readinessDisclosureValue(packet.artifactPath || ""),
    summary: readinessDisclosureValue(packet.summary || ""),
    makeTargets: asStringArray(packet.makeTargets).map(readinessDisclosureValue).filter(Boolean),
    reference: readinessDisclosureValue(packet.reference || ""),
    diagnoseCommand: readinessDisclosureValue(packet.diagnoseCommand || ""),
    collectCommand: readinessDisclosureValue(packet.collectCommand || ""),
    validateCommand: readinessDisclosureValue(packet.validateCommand || ""),
    recordCommand: readinessDisclosureValue(packet.recordCommand || ""),
    noClaimsCommand: readinessDisclosureValue(packet.noClaimsCommand || ""),
    commandItems: releaseEvidencePacketCommandItems(packet).map((command) => ({
      role: readinessDisclosureValue(command.role || "Command"),
      command: readinessDisclosureValue(command.command || ""),
    })).filter((command) => command.command),
    commands: releaseEvidencePacketCommands(packet).map(readinessDisclosureValue).filter(Boolean),
  };
  return {
    id: readinessDisclosureValue(item.id || ""),
    cls: readinessDisclosureValue(item.cls || ""),
    label: readinessDisclosureValue(item.label || ""),
    title: readinessDisclosureValue(item.title || ""),
    detail: readinessDisclosureValue(item.detail || ""),
    meta: readinessDisclosureValue(item.meta || ""),
    href: readinessDisclosureValue(item.href || ""),
    reference: readinessDisclosureValue(item.reference || ""),
    packet: cleanPacket,
  };
}

function releaseEvidencePacketCurrentGap(item = {}) {
  const packetRoute = readinessDisclosureValue(releaseEvidencePacketRoute(item));
  const operatorRoute = readinessDisclosureValue(item.href || "");
  const currentGap = readinessDisclosureValue(item.meta || item.label || item.cls || "unknown");
  const detail = readinessDisclosureValue(item.detail || "No current release acceptance detail is available.");
  return h("div", {
    class: "alert-box " + readinessBoxClass(item.cls || "info"),
    dataset: { releaseEvidenceCurrentGap: item.id || "" },
  },
    h("div", { class: "release-evidence-head" },
      h("strong", {}, "Current gate status"),
      badge(item.label || item.cls || "unknown", item.cls || "info", { dot: true })),
    h("div", { class: "note" }, detail),
    h("dl", { class: "kv compact release-evidence-current-gap-kv" },
      h("dt", {}, "Current gap"), h("dd", { class: "mono" }, currentGap || "unknown"),
      h("dt", {}, "Packet route"), h("dd", { class: "mono", dataset: { releaseEvidencePacketRoute: item.id || "" } }, packetRoute || "not route-backed"),
      h("dt", {}, "Operator route"), h("dd", { class: "mono", dataset: { releaseEvidenceOperatorRoute: item.id || "" } }, operatorRoute || "not linked")),
    h("div", { class: "row-actions" },
      operatorRoute ? h("a", {
        class: "btn sm ghost",
        href: operatorRoute,
        title: `Open release workflow for ${item.id || "selected gate"}`,
        "aria-label": `Open release workflow for ${item.id || "selected gate"}`,
        dataset: { releaseEvidenceAction: "open-current-gap", releaseEvidenceLink: item.id || "" },
      }, h("span", { html: icon("arrowRight", 15) }), "Open workflow") : null,
      packetRoute ? h("a", {
        class: "btn sm ghost",
        href: packetRoute,
        title: `Open release evidence packet route for ${item.id || "selected gate"}`,
        "aria-label": `Open release evidence packet route for ${item.id || "selected gate"}`,
        dataset: { releaseEvidenceAction: "open-current-packet", releaseEvidencePacket: item.id || "" },
      }, h("span", { html: icon("terminal", 15) }), "Open packet route") : null));
}

function releaseEvidencePacketRoute(item = {}) {
  const id = String(item.id || item.packet?.check || "").trim();
  if (!id || !releaseEvidencePacketIds().includes(id)) return "";
  return `#/readiness?packet=${encodeURIComponent(id)}`;
}

async function copyReleaseEvidencePacket(handoff) {
  try {
    await navigator.clipboard.writeText(investigationPacketText(handoff));
    toast("Release packet copied", "Browser-local release evidence handoff copied as plain text.", "ok");
  } catch {
    toast("Copy unavailable", "Select and copy the generated release evidence packet from the drawer.", "warn");
  }
}

function exportReleaseEvidencePacket(handoff) {
  const text = investigationPacketJson(handoff);
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: investigationPacketFilename(handoff) });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  toast("Release packet exported", "Downloaded browser-local release evidence handoff JSON.", "ok");
}

async function pinReleaseEvidencePacket(handoff) {
  await appendReadinessHandoffToCase(handoff, "release evidence packet", "Release evidence packet could not be pinned.");
}

function releaseEvidenceCommandRow(label, command) {
  const safeCommand = redactReadinessDisclosureText(command);
  return h("div", { class: "release-evidence-command-row" },
    h("div", {},
      h("span", {}, label),
      h("code", { dataset: { releaseEvidenceCommand: label.toLowerCase() } }, safeCommand)),
    readinessCommandCopyButton(label, safeCommand, {
      ariaLabel: `Copy ${label.toLowerCase()} release evidence command`,
      dataset: { releaseEvidenceCommandCopy: label.toLowerCase() },
    }));
}

function releaseEvidencePacketCommands(packet = {}) {
  const items = releaseEvidencePacketCommandItems(packet);
  if (items.length) return items.map((item) => item.command).filter(Boolean);
  return [];
}

function releaseEvidencePacketCommandItems(packet = {}) {
  if (Array.isArray(packet.commandItems) && packet.commandItems.length) {
    return packet.commandItems
      .map((item) => ({
        role: item?.role || "Command",
        command: item?.command || "",
      }))
      .filter((item) => item.command);
  }
  if (Array.isArray(packet.commands) && packet.commands.length) {
    return packet.commands
      .filter(Boolean)
      .map((command, index) => ({ role: index === 0 ? "Validate" : "Record", command }));
  }
  return [packet.validateCommand, packet.recordCommand]
    .filter(Boolean)
    .map((command, index) => ({ role: index === 0 ? "Validate" : "Record", command }));
}

async function copyReleaseEvidencePacketCommands(item = {}) {
  const commands = releaseEvidencePacketCommands(item.packet).map(redactReadinessDisclosureText);
  try {
    if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(commands.join("\n"));
    toast("Release commands copied", `${commands.length} command${commands.length === 1 ? "" : "s"} copied for ${item.id || "release evidence"}.`, "ok");
  } catch {
    toast("Copy unavailable", "Select and copy the packet commands from this drawer.", "warn");
  }
}

function openRoutedSystemEvidencePacket(packet = {}) {
  writeReadinessRouteState({ drawer: "system" });
  openSystemEvidencePacket(packet, { routeBacked: "system" });
}

function openRoutedHAEvidencePacket(packet = {}) {
  writeReadinessRouteState({ drawer: "ha" });
  openHAEvidencePacket(packet, { routeBacked: "ha" });
}

function openRoutedEbpfDrillEvidencePacket(packet = {}) {
  writeReadinessRouteState({ drawer: "ebpf-drill" });
  openEbpfDrillEvidencePacket(packet, { routeBacked: "ebpf-drill" });
}

function openRoutedHACockpit(ha = {}, packet = buildHAEvidencePacket(ha)) {
  writeReadinessRouteState({ drawer: "ha-cockpit" });
  openHAOperationsCockpit(ha, packet, { routeBacked: "ha-cockpit" });
}

function openSystemEvidencePacket(packet = {}, opts = {}) {
  const routeDrawer = readinessRouteBackedKind(opts.routeBacked, "system");
  if (routeDrawer) {
    if (!isCurrentReadinessRouteDrawer(routeDrawer)) return;
    activeReadinessRouteDrawer = routeDrawer;
  }
  const counts = packet.releaseEvidenceCounts || {};
  const rows = Array.isArray(packet.rows) ? packet.rows : [];
  const text = packet.text || systemEvidencePacketReport(packet);
  openDrawer({
    title: "System evidence packet",
    subtitle: packet.schema || "phragma.system.evidence.v1",
    width: "800px",
    body: h("div", {
      class: "system-evidence-packet",
      dataset: { readinessSystemEvidence: "true" },
    },
      h("div", { class: "preflight-summary" },
        h("div", {}, h("span", {}, "State"), h("strong", {}, packet.state || "unknown")),
        h("div", {}, h("span", {}, "Blocked"), h("strong", {}, String(counts.blocked || 0))),
        h("div", {}, h("span", {}, "Review"), h("strong", {}, String(counts.review || 0))),
        h("div", {}, h("span", {}, "Clear"), h("strong", {}, String(counts.clear || 0)))),
      h("div", { class: "alert-box " + readinessBoxClass(packet.cls || "info") },
        h("strong", {}, packet.title || "System evidence"),
        h("div", { class: "note" }, packet.detail || "Browser-generated evidence from the current Readiness model.")),
      rows.length ? h("div", { class: "system-evidence-list" }, rows.map(systemEvidenceRow)) :
        emptyState("terminal", "No system evidence rows", "The current Readiness model did not produce packet rows."),
      h("textarea", {
        class: "input system-evidence-report",
        dataset: { readinessSystemEvidenceReport: "true" },
        readonly: true,
        rows: 18,
        wrap: "soft",
        spellcheck: "false",
      }, text)),
    footer: [
      h("button", { class: "btn ghost", ...readinessActionAttrs("close-system-evidence", "Close system evidence packet"), onclick: closeDrawer }, "Close"),
      h("button", { class: "btn", ...readinessActionAttrs("pin-system-evidence", "Pin system evidence packet to case"), onclick: () => pinSystemEvidencePacket(packet) },
        h("span", { html: icon("inbox", 16) }), "Pin to case"),
      h("a", { class: "btn ghost", href: activeInvestigationServerCaseHref(), title: "Open active investigation case", "aria-label": "Open active investigation case", dataset: { readinessSystemEvidenceAction: "open-active-case" } },
        h("span", { html: icon("search", 16) }), "Open active case"),
      h("button", { class: "btn primary", ...readinessActionAttrs("copy-system-evidence", "Copy system evidence packet"), onclick: () => copySystemEvidencePacket(text) },
        h("span", { html: icon("copy", 16) }), "Copy evidence"),
    ],
    onClose: routeDrawer ? () => clearReadinessRouteStateFor(routeDrawer) : null,
  });
}

function openHAEvidencePacket(packet = {}, opts = {}) {
  const routeDrawer = readinessRouteBackedKind(opts.routeBacked, "ha");
  if (routeDrawer) {
    if (!isCurrentReadinessRouteDrawer(routeDrawer)) return;
    activeReadinessRouteDrawer = routeDrawer;
  }
  const rows = Array.isArray(packet.rows) ? packet.rows : [];
  const text = packet.text || haEvidencePacketReport(packet);
  const sync = packet.sync || {};
  const failover = packet.failover || {};
  const boundary = haFailoverPacketBoundaryModel({}, packet);
  openDrawer({
    title: "HA evidence packet",
    subtitle: packet.schema || "phragma.ha.evidence.v1",
    width: "760px",
    body: h("div", {
      class: "system-evidence-packet ha-evidence-packet",
      dataset: { readinessHaEvidence: "true" },
    },
      h("div", { class: "preflight-summary" },
        h("div", {}, h("span", {}, "State"), h("strong", {}, packet.state || "unknown")),
        h("div", {}, h("span", {}, "Mode"), h("strong", {}, packet.mode || "unknown")),
        h("div", {}, h("span", {}, "Role"), h("strong", {}, packet.role || "unknown")),
        h("div", {}, h("span", {}, "Failover"), h("strong", {}, failover.eligible ? "eligible" : "blocked"))),
      h("div", { class: "alert-box " + readinessBoxClass(packet.cls || "info") },
        h("strong", {}, packet.title || "HA evidence"),
        h("div", { class: "note" }, packet.detail || "Browser-generated HA evidence from the current Readiness model.")),
      h("div", { class: "alert-box info", dataset: { readinessHaPacketBoundary: "true" } },
        h("strong", {}, boundary.title),
        h("div", { class: "note" }, boundary.detail)),
      h("dl", { class: "kv readiness-kv" },
        h("dt", {}, "Node"), h("dd", { class: "mono" }, packet.nodeId || "—"),
        h("dt", {}, "Peer"), h("dd", { class: "mono" }, [packet.peerId || "", packet.peerAddress || ""].filter(Boolean).join(" / ") || "—"),
        h("dt", {}, "Running policy"), h("dd", { class: "mono" }, packet.runningPolicyVersion ? `v${packet.runningPolicyVersion}` : "—"),
        h("dt", {}, "Last-known-good"), h("dd", { class: "mono" }, packet.lastKnownGoodVersion ? `v${packet.lastKnownGoodVersion} / ${packet.lastKnownGoodState || "unknown"}` : "missing"),
        h("dt", {}, "Sync"), h("dd", { class: "mono" }, [sync.state || "unknown", sync.detail || ""].filter(Boolean).join(" / ")),
        h("dt", {}, "Failover"), h("dd", { class: "mono" }, [failover.state || "unknown", failover.detail || ""].filter(Boolean).join(" / "))),
      rows.length ? h("div", { class: "system-evidence-list" }, rows.map(systemEvidenceRow)) :
        emptyState("terminal", "No HA evidence rows", "The current HA model did not produce packet rows."),
      h("textarea", {
        class: "input system-evidence-report",
        dataset: { readinessHaEvidenceReport: "true" },
        readonly: true,
        rows: 16,
        wrap: "soft",
        spellcheck: "false",
      }, text)),
    footer: [
      h("button", { class: "btn ghost", ...readinessActionAttrs("close-ha-evidence", "Close HA evidence packet"), onclick: closeDrawer }, "Close"),
      h("button", { class: "btn", ...readinessActionAttrs("pin-ha-evidence", "Pin HA evidence packet to case"), onclick: () => pinHAEvidencePacket(packet) },
        h("span", { html: icon("inbox", 16) }), "Pin to case"),
      h("a", { class: "btn ghost", href: activeInvestigationServerCaseHref(), title: "Open active investigation case", "aria-label": "Open active investigation case", dataset: { readinessHaEvidenceAction: "open-active-case" } },
        h("span", { html: icon("search", 16) }), "Open active case"),
      h("button", { class: "btn primary", ...readinessActionAttrs("copy-ha-evidence", "Copy HA evidence packet"), onclick: () => copyHAEvidencePacket(text) },
        h("span", { html: icon("copy", 16) }), "Copy evidence"),
    ],
    onClose: routeDrawer ? () => clearReadinessRouteStateFor(routeDrawer) : null,
  });
}

function openEbpfDrillEvidencePacket(packet = {}, opts = {}) {
  const routeDrawer = readinessRouteBackedKind(opts.routeBacked, "ebpf-drill");
  if (routeDrawer) {
    if (!isCurrentReadinessRouteDrawer(routeDrawer)) return;
    activeReadinessRouteDrawer = routeDrawer;
  }
  const rows = Array.isArray(packet.rows) ? packet.rows : [];
  const text = packet.text || ebpfDrillEvidencePacketReport(packet);
  openDrawer({
    title: "eBPF attach-drill evidence",
    subtitle: packet.schema || "phragma.ebpf.drill-evidence.v1",
    width: "780px",
    body: h("div", {
      class: "system-evidence-packet ebpf-drill-evidence-packet",
      dataset: { readinessEbpfDrillEvidence: "true" },
    },
      h("div", { class: "preflight-summary" },
        h("div", {}, h("span", {}, "State"), h("strong", {}, packet.state || "unknown")),
        h("div", {}, h("span", {}, "Dataplane"), h("strong", { class: "mono" }, packet.activeDataplane || "nftables/conntrack")),
        h("div", {}, h("span", {}, "Host"), h("strong", {}, packet.hostState || "unknown")),
        h("div", {}, h("span", {}, "Attach"), h("strong", {}, packet.attachState || "unknown"))),
      h("div", { class: "alert-box " + readinessBoxClass(packet.cls || "info") },
        h("strong", {}, packet.title || "eBPF drill evidence"),
        h("div", { class: "note" }, packet.detail || "Browser-generated eBPF drill handoff from the current Readiness model.")),
      h("dl", { class: "kv readiness-kv" },
        h("dt", {}, "Release check"), h("dd", { class: "mono" }, packet.releaseCheck || "ebpf-ol9-field-evidence"),
        h("dt", {}, "Evidence path"), h("dd", { class: "mono" }, packet.evidencePath || "release/field-evidence/ebpf-ol9"),
        h("dt", {}, "Artifact"), h("dd", { class: "mono" }, packet.artifactPath || "release/evidence/ebpf-ol9-field-evidence.txt"),
        h("dt", {}, "Hooks"), h("dd", { class: "mono" }, Array.isArray(packet.supportedHooks) && packet.supportedHooks.length ? packet.supportedHooks.join(", ") : "xdp, tc"),
        h("dt", {}, "Renderer"), h("dd", {}, badge(packet.rendererState || "unknown", capabilityClass(packet.rendererState)))),
      rows.length ? h("div", { class: "system-evidence-list" }, rows.map(systemEvidenceRow)) :
        emptyState("terminal", "No drill rows", "The current eBPF drill model did not produce packet rows."),
      h("textarea", {
        class: "input system-evidence-report",
        dataset: { readinessEbpfDrillEvidenceReport: "true" },
        readonly: true,
        rows: 15,
        wrap: "soft",
        spellcheck: "false",
      }, text)),
    footer: [
      h("button", { class: "btn ghost", ...readinessActionAttrs("close-ebpf-drill-evidence", "Close eBPF attach-drill evidence"), onclick: closeDrawer }, "Close"),
      h("button", { class: "btn", ...readinessActionAttrs("pin-ebpf-drill-evidence", "Pin eBPF attach-drill evidence to case", { readinessEbpfDrillAction: "pin" }), onclick: () => pinEbpfDrillEvidencePacket(packet) },
        h("span", { html: icon("inbox", 16) }), "Pin to case"),
      h("a", { class: "btn ghost", href: activeInvestigationServerCaseHref(), title: "Open active investigation case", "aria-label": "Open active investigation case", dataset: { readinessEbpfDrillAction: "open-active-case" } },
        h("span", { html: icon("search", 16) }), "Open active case"),
      h("button", { class: "btn", ...readinessActionAttrs("export-ebpf-drill-evidence", "Export eBPF attach-drill evidence JSON", { readinessEbpfDrillAction: "export" }), onclick: () => exportEbpfDrillEvidencePacket(packet) },
        h("span", { html: icon("download", 16) }), "Export JSON"),
      h("button", { class: "btn primary", ...readinessActionAttrs("copy-ebpf-drill-evidence", "Copy eBPF attach-drill evidence", { readinessEbpfDrillAction: "copy" }), onclick: () => copyEbpfDrillEvidencePacket(text) },
        h("span", { html: icon("copy", 16) }), "Copy evidence"),
    ],
    onClose: routeDrawer ? () => clearReadinessRouteStateFor(routeDrawer) : null,
  });
}

function openHAOperationsCockpit(ha = {}, packet = buildHAEvidencePacket(ha), opts = {}) {
  const routeDrawer = readinessRouteBackedKind(opts.routeBacked, "ha-cockpit");
  if (routeDrawer) {
    if (!isCurrentReadinessRouteDrawer(routeDrawer)) return;
    activeReadinessRouteDrawer = routeDrawer;
  }
  const model = haOperationsCockpitModel(ha, packet);
  const text = haOperationsCockpitReport(model);
  const rows = model.rows || [];
  const pullAction = model.pullAction || haPolicyPullActionState(ha);
  const activationAction = model.activationAction || haFailoverActivationActionState(ha);
  openDrawer({
    title: "HA operations cockpit",
    subtitle: "Active/passive readiness, peer comparison, guarded pull, and manual activation workflow",
    width: "860px",
    body: h("div", {
      class: "system-evidence-packet ha-operations-cockpit",
      dataset: { readinessHaCockpit: "true" },
    },
      h("div", { class: "preflight-summary" },
        h("div", {}, h("span", {}, "Mode"), h("strong", {}, model.mode)),
        h("div", {}, h("span", {}, "Role"), h("strong", {}, model.role)),
        h("div", {}, h("span", {}, "Sync"), h("strong", {}, model.syncState)),
        h("div", {}, h("span", {}, "Failover"), h("strong", {}, model.failoverEligible ? "eligible" : "blocked"))),
      h("div", { class: "alert-box " + readinessBoxClass(model.cls || "info") },
        h("strong", {}, model.cls === "bad" ? "HA operations are blocked." : model.cls === "warn" ? "HA operations need review." : "HA operations posture"),
        h("div", { class: "note" }, model.detail || "High availability status is unavailable.")),
      h("div", { class: "alert-box info", dataset: { readinessHaOperationsBoundary: "true" } },
        h("strong", {}, model.packetBoundary.title),
        h("div", { class: "note" }, model.packetBoundary.detail)),
      h("div", { class: "grid cols-2" },
        h("div", {},
          h("h3", {}, "Local node"),
          h("dl", { class: "kv readiness-kv" },
            h("dt", {}, "Node ID"), h("dd", { class: "mono" }, model.nodeId),
            h("dt", {}, "Role"), h("dd", {}, badge(model.role, model.role === "active" ? "ok" : model.role === "passive" ? "warn" : "info")),
            h("dt", {}, "Running policy"), h("dd", { class: "mono" }, model.localVersion ? `v${model.localVersion}` : "unknown"),
            h("dt", {}, "Artifact set"), h("dd", { class: "mono" }, shortEvidenceHash(model.localArtifact) || "missing"))),
        h("div", {},
          h("h3", {}, "Peer node"),
          h("dl", { class: "kv readiness-kv" },
            h("dt", {}, "Peer ID"), h("dd", { class: "mono" }, model.peerId),
            h("dt", {}, "Peer address"), h("dd", { class: "mono" }, model.peerAddress),
            h("dt", {}, "Peer policy"), h("dd", { class: "mono" }, model.peerVersion ? `v${model.peerVersion}` : "unknown"),
            h("dt", {}, "Artifact set"), h("dd", { class: "mono" }, shortEvidenceHash(model.peerArtifact) || "missing")))),
      rows.length ? h("div", { class: "system-evidence-list" }, rows.map(systemEvidenceRow)) :
        emptyState("terminal", "No HA operations rows", "The current HA model did not produce operations rows."),
      h("textarea", {
        class: "input system-evidence-report",
        dataset: { readinessHaCockpitReport: "true" },
        readonly: true,
        rows: 14,
        wrap: "soft",
        spellcheck: "false",
      }, text)),
    footer: [
      h("button", { class: "btn ghost", ...readinessActionAttrs("close-ha-cockpit", "Close HA operations cockpit"), onclick: closeDrawer }, "Close"),
      h("button", { class: "btn ghost", ...readinessActionAttrs("ha-cockpit-api-cli", "Open HA cockpit API and CLI context"), onclick: () => openAutomationContext("#/readiness?drawer=ha-cockpit") },
        h("span", { html: icon("terminal", 16) }), "API / CLI"),
      h("button", { class: "btn", ...readinessActionAttrs("pin-ha-cockpit-evidence", "Pin HA cockpit evidence to case"), onclick: () => pinHAEvidencePacket(packet) },
        h("span", { html: icon("inbox", 16) }), "Pin evidence"),
      h("button", { class: "btn", ...readinessActionAttrs("copy-ha-cockpit", "Copy HA operations cockpit"), onclick: () => copyHAEvidencePacket(text) },
        h("span", { html: icon("copy", 16) }), "Copy cockpit"),
      h("button", {
        class: "btn primary",
        type: "button",
        disabled: !pullAction.canPull,
        title: pullAction.canPull ? "Review and pull the active peer policy." : pullAction.disabledReason,
        "aria-label": pullAction.canPull ? "Review and pull the active peer policy" : `HA policy pull unavailable: ${pullAction.disabledReason || "not eligible"}`,
        dataset: { readinessAction: "ha-cockpit-review-pull" },
        onclick: () => openHAPolicyPullReview(ha),
      }, h("span", { html: icon("download", 16) }), "Review pull"),
      h("button", {
        class: "btn primary",
        type: "button",
        disabled: !activationAction.canActivate,
        title: activationAction.canActivate ? "Review and mark this passive node active." : activationAction.disabledReason,
        "aria-label": activationAction.canActivate ? "Review and mark this passive node active" : `HA activation unavailable: ${activationAction.disabledReason || "not eligible"}`,
        dataset: { readinessAction: "ha-cockpit-review-activation" },
        onclick: () => openHAFailoverActivationReview(ha),
      }, h("span", { html: icon("shield", 16) }), "Review activation"),
    ],
    onClose: routeDrawer ? () => clearReadinessRouteStateFor(routeDrawer) : null,
  });
}

export function haOperationsCockpitModel(ha = {}, packet = buildHAEvidencePacket(ha)) {
  const sync = ha.sync || packet.sync || {};
  const failover = ha.failover || packet.failover || {};
  const replication = ha.replication || packet.replication || {};
  const blockers = Array.isArray(ha.blockers) ? ha.blockers : Array.isArray(packet.blockers) ? packet.blockers : [];
  const localVersion = Number(sync.localVersion || sync.local_version || ha.runningPolicyVersion || packet.runningPolicyVersion || 0);
  const peerVersion = Number(sync.peerVersion || sync.peer_version || 0);
  const localArtifact = sync.localArtifactSetSha256 || sync.local_artifact_set_sha256 || ha.artifactSet || packet.artifactSet || "";
  const peerArtifact = sync.peerArtifactSetSha256 || sync.peer_artifact_set_sha256 || "";
  const pullAction = haPolicyPullActionState(ha);
  const activationAction = haFailoverActivationActionState(ha);
  const policy = haPolicyComparison(localVersion, peerVersion, localArtifact, peerArtifact);
  const cls = ha.cls || packet.cls || "info";
  const packetBoundary = haFailoverPacketBoundaryModel(ha, packet);
  const model = {
    schema: "phragma.ha.operations.v1",
    generatedAt: packet.generatedAt || new Date().toISOString(),
    state: ha.state || packet.state || "unknown",
    cls,
    detail: ha.detail || packet.detail || "",
    mode: ha.mode || packet.mode || "unknown",
    role: ha.role || packet.role || "unknown",
    nodeId: ha.nodeId || packet.nodeId || "unknown",
    peerId: ha.peerId || packet.peerId || "unknown",
    peerAddress: ha.peerAddress || packet.peerAddress || "missing",
    localVersion,
    peerVersion,
    localArtifact,
    peerArtifact,
    syncState: sync.state || "unknown",
    syncDetail: sync.detail || "",
    replicationState: replication.state || "unknown",
    replicationEnabled: Boolean(replication.enabled),
    replicationDetail: replication.detail || "",
    replicationLastAttempt: replication.lastAttemptAt || replication.last_attempt_at || "",
    replicationLastSuccess: replication.lastSuccessAt || replication.last_success_at || "",
    replicationLastError: replication.lastError || replication.last_error || "",
    replicationLastPeerVersion: Number(replication.lastPeerVersion || replication.last_peer_version || 0),
    replicationLastLocalVersion: Number(replication.lastLocalVersion || replication.last_local_version || 0),
    failoverState: failover.state || "unknown",
    failoverEligible: Boolean(failover.eligible),
    failoverDetail: failover.detail || "",
    postActivationReview: String(ha.role || packet.role || "").toLowerCase() === "active" && String(failover.state || "").toLowerCase() === "blocked",
    lastKnownGoodVersion: Number(ha.lastKnownGoodVersion || packet.lastKnownGoodVersion || 0),
    lastKnownGoodState: ha.lastKnownGoodState || packet.lastKnownGoodState || "",
    blockers,
    pullAction,
    activationAction,
    policy,
    packetBoundary,
  };
  model.rows = [
    {
      id: "ha-cockpit-policy-compare",
      cls: policy.cls,
      label: policy.label,
      title: "Policy comparison",
      detail: policy.detail,
      meta: `local:v${localVersion || "unknown"} peer:v${peerVersion || "unknown"}`,
    },
    {
      id: "ha-cockpit-sync-blockers",
      cls: blockers.length ? "bad" : capabilityClass(sync.state),
      label: blockers.length ? `${blockers.length} blocker(s)` : model.syncState,
      title: "Sync blockers",
      detail: blockers.length ? blockers.join(" ") : model.syncDetail || "No HA blockers were returned by the system API.",
      meta: model.peerAddress !== "missing" ? `peer_address:${model.peerAddress}` : "peer_address:missing",
    },
    {
      id: "ha-cockpit-recovery-point",
      cls: model.lastKnownGoodVersion ? "ok" : "warn",
      label: model.lastKnownGoodVersion ? `v${model.lastKnownGoodVersion}` : "missing",
      title: "Recovery point",
      detail: model.lastKnownGoodVersion ? `Last-known-good policy is ${model.lastKnownGoodState || "available"}.` : "No last-known-good recovery version is reported.",
      meta: `artifact:${shortEvidenceHash(ha.artifactSet || packet.artifactSet || "") || "missing"}`,
    },
    {
      id: "ha-cockpit-auto-replication",
      cls: haReplicationClass(replication),
      label: replication.enabled ? (replication.state || "enabled") : "disabled",
      title: "Automatic passive replication",
      detail: replication.detail || (replication.enabled ? "Automatic passive replication is enabled." : "Automatic passive replication is disabled."),
      meta: replication.lastSuccessAt || replication.last_success_at
        ? `last_success:${replication.lastSuccessAt || replication.last_success_at}`
        : `last_attempt:${replication.lastAttemptAt || replication.last_attempt_at || "none"}`,
    },
    {
      id: "ha-cockpit-failover-readiness",
      cls: model.failoverEligible ? "ok" : cls === "bad" ? "bad" : "warn",
      label: `${model.failoverState}${model.failoverEligible ? " eligible" : ""}`,
      title: "Failover eligibility",
      detail: model.failoverDetail || "Failover detail was not returned.",
      meta: model.failoverEligible ? "operator failover eligible" : "operator failover blocked",
    },
    {
      id: "ha-cockpit-policy-pull",
      cls: pullAction.canPull ? "ok" : "warn",
      label: pullAction.canPull ? "available" : "guarded",
      title: "Manual recovery policy pull",
      detail: pullAction.canPull ? "Manual resync remains available as a reviewed recovery action; routine passive replication is automatic when enabled." : pullAction.disabledReason,
      meta: "mutation=manual recovery pull only",
    },
    {
      id: "ha-cockpit-failover-activation",
      cls: activationAction.canActivate ? "ok" : "warn",
      label: activationAction.canActivate ? "available" : "guarded",
      title: "Manual passive activation",
      detail: activationAction.canActivate ? "Server preflight can mark this passive node active after external cutover and fencing acknowledgements." : activationAction.disabledReason,
      meta: "preflight=server readiness; mutation=local role marker only; transport/fencing external",
    },
    {
      id: "ha-cockpit-packet-boundary",
      cls: "info",
      label: "packet only",
      title: "HA/failover packet boundary",
      detail: packetBoundary.detail,
      meta: `positive_evidence=${packetBoundary.positiveEvidence.length}; external_boundaries=${packetBoundary.externalBoundaries.length}`,
    },
    {
      id: "ha-cockpit-post-activation-review",
      cls: model.postActivationReview ? "warn" : "info",
      label: model.postActivationReview ? "required" : "pending activation",
      title: "Post-activation split-brain review",
      detail: model.postActivationReview
        ? model.failoverDetail || "After local activation, verify peer fencing, VIP/route ownership, and traffic cutover before treating failover as complete."
        : "Available after manual activation; this API does not claim peer fencing, VIP/route ownership, or connection-state transfer.",
      meta: "verification=peer fencing + VIP/route ownership + traffic cutover",
    },
  ];
  return model;
}

function haPolicyComparison(localVersion, peerVersion, localArtifact = "", peerArtifact = "") {
  if (!peerVersion) {
    return {
      cls: "warn",
      label: "peer unknown",
      detail: "Peer running policy version is not available yet.",
    };
  }
  if (!localVersion) {
    return {
      cls: "warn",
      label: "local unknown",
      detail: "Local running policy version is not available yet.",
    };
  }
  if (localVersion === peerVersion && localArtifact && peerArtifact && localArtifact !== peerArtifact) {
    return {
      cls: "warn",
      label: "version match / hash drift",
      detail: "Local and peer policy versions match, but artifact hashes differ; review peer synchronization evidence.",
    };
  }
  if (localVersion === peerVersion) {
    return {
      cls: "ok",
      label: "in sync",
      detail: `Local and peer report running policy v${localVersion}.`,
    };
  }
  if (peerVersion > localVersion) {
    return {
      cls: "warn",
      label: "peer ahead",
      detail: `Peer policy v${peerVersion} is ahead of local v${localVersion}; passive pull may be required.`,
    };
  }
  return {
    cls: "warn",
    label: "local ahead",
    detail: `Local policy v${localVersion} is ahead of peer v${peerVersion}; review HA role and synchronization direction.`,
  };
}

function haReplicationClass(replication = {}) {
  if (!replication?.enabled) return "warn";
  const state = String(replication.state || "").toLowerCase();
  if (state === "replicated" || state === "waiting") return "ok";
  if (state === "blocked" || state === "failed") return "bad";
  return "warn";
}

export function haFailoverPacketBoundaryModel(ha = {}, packet = buildHAEvidencePacket(ha)) {
  const sync = ha.sync || packet.sync || {};
  const failover = ha.failover || packet.failover || {};
  const fencing = ha.fencingEvidence || packet.fencingEvidence || {};
  const transport = ha.transportEvidence || packet.transportEvidence || {};
  const conntrack = ha.conntrackSync || packet.conntrackSync || {};
  const positiveEvidence = [];
  const missingEvidence = [];
  if (ha.runningPolicyVersion || packet.runningPolicyVersion) positiveEvidence.push(`running policy v${ha.runningPolicyVersion || packet.runningPolicyVersion}`);
  else missingEvidence.push("running policy version missing");
  if (ha.lastKnownGoodVersion || packet.lastKnownGoodVersion) positiveEvidence.push(`last-known-good v${ha.lastKnownGoodVersion || packet.lastKnownGoodVersion}`);
  else missingEvidence.push("last-known-good recovery point missing");
  if (String(sync.state || "").toLowerCase() === "synced") positiveEvidence.push("peer policy sync evidence is synced");
  else missingEvidence.push("peer policy sync is not proven synced");
  if (failover.eligible) positiveEvidence.push("server failover preflight reports eligible");
  else missingEvidence.push("server failover preflight is blocked or unavailable");
  const externalBoundaries = [
    fencing.state === "recorded" ? "peer fencing is recorded as evidence only" : "peer fencing remains external",
    transport.state === "promoted" ? "VIP/GARP promotion is locally evidenced only" : "VIP/route movement remains external",
    conntrack.state === "synced" ? "conntrack sync is reported as evidence only" : "connection-state transfer remains external",
    "packet copy/export/pin does not execute failover or certify traffic cutover",
  ];
  const eligible = failover.eligible && missingEvidence.length === 0;
  return {
    schema: "phragma.ha.failover-boundary.v1",
    title: eligible ? "HA packet has positive preflight evidence." : "HA packet is not traffic authority.",
    detail: eligible
      ? "Loaded HA signals can support a failover review packet, but traffic cutover, peer fencing, VIP/route ownership, and connection-state transfer remain separately verified operational boundaries."
      : "This packet is evidence for review only. It does not authorize or perform traffic cutover, peer fencing, VIP/route movement, or connection-state transfer.",
    eligible,
    positiveEvidence,
    missingEvidence,
    externalBoundaries,
    packetOnly: true,
    localRoleMarkerOnly: true,
    trafficCutoverExternal: true,
    peerFencingExternal: fencing.state !== "recorded",
    vipRouteMovementExternal: transport.state !== "promoted",
    connectionStateTransferExternal: conntrack.state !== "synced",
  };
}

export function haOperationsCockpitReport(modelOrHA = {}, packet = null) {
  const model = packet ? haOperationsCockpitModel(modelOrHA, packet) : modelOrHA;
  const lines = [
    "OpenNGFW high availability operations cockpit",
    `schema=${oneLine(model.schema || "phragma.ha.operations.v1")}`,
    `generated_at=${oneLine(model.generatedAt || new Date().toISOString())}`,
    `state=${oneLine(model.state || "unknown")}`,
    `mode=${oneLine(model.mode || "unknown")}`,
    `role=${oneLine(model.role || "unknown")}`,
    `node_id=${oneLine(model.nodeId || "unknown")}`,
    `peer_id=${oneLine(model.peerId || "unknown")}`,
    `peer_address=${oneLine(model.peerAddress || "missing")}`,
    `policy_compare=${oneLine(model.policy?.label || "unknown")}`,
    `policy_detail=${oneLine(model.policy?.detail || "unavailable")}`,
    `sync_state=${oneLine(model.syncState || "unknown")}`,
    `sync_detail=${oneLine(model.syncDetail || "unavailable")}`,
    `replication_state=${oneLine(model.replicationState || "unknown")}`,
    `replication_enabled=${model.replicationEnabled ? "true" : "false"}`,
    `replication_last_success=${oneLine(model.replicationLastSuccess || "none")}`,
    `replication_last_error=${oneLine(model.replicationLastError || "none")}`,
    `failover_state=${oneLine(model.failoverState || "unknown")}`,
    `failover_eligible=${model.failoverEligible ? "true" : "false"}`,
    `last_known_good=${oneLine(model.lastKnownGoodVersion ? `v${model.lastKnownGoodVersion}` : "missing")}`,
    `blockers=${asStringArray(model.blockers).map(oneLine).join("; ") || "none"}`,
    `packet_boundary=${oneLine(model.packetBoundary?.detail || "HA packet is evidence-only; traffic movement remains external")}`,
    `positive_evidence=${asStringArray(model.packetBoundary?.positiveEvidence).map(oneLine).join("; ") || "none"}`,
    `external_boundaries=${asStringArray(model.packetBoundary?.externalBoundaries).map(oneLine).join("; ") || "none"}`,
    "mutation_surface=automatic-passive-policy-replication-and-manual-activation",
    `activation_available=${model.activationAction?.canActivate ? "true" : "false"}`,
    `activation_detail=${oneLine(model.activationAction?.disabledReason || "local role marker only; transport cutover and peer fencing external")}`,
    `post_activation_review=${model.postActivationReview ? "required" : "pending"}`,
    "source=browser Readiness view; already-loaded /v1/system/status highAvailability object",
  ];
  for (const row of Array.isArray(model.rows) ? model.rows : []) {
    lines.push(`- [${String(row.cls || "info").toUpperCase()}] ${oneLine(row.id)} - ${oneLine(row.title)}`);
    if (row.label) lines.push(`  label: ${oneLine(row.label)}`);
    if (row.detail) lines.push(`  detail: ${oneLine(row.detail)}`);
    if (row.meta) lines.push(`  meta: ${oneLine(row.meta)}`);
  }
  return lines.join("\n").trimEnd() + "\n";
}

function systemEvidenceRow(row = {}) {
  return h("div", {
    class: "system-evidence-row " + (row.cls || "info"),
    dataset: { systemEvidenceRow: row.id || "" },
  },
    h("div", {},
      h("strong", {}, row.title || "Evidence"),
      row.detail ? h("div", { class: "note" }, row.detail) : null,
      row.meta ? h("div", { class: "system-evidence-meta mono" }, row.meta) : null),
    badge(row.label || row.cls || "status", row.cls || "info", { dot: true }));
}

function systemInvestigationHandoffPacket(packet = {}) {
  const counts = packet.releaseEvidenceCounts || {};
  const unresolved = Array.isArray(packet.unresolvedExternalGateIds) ? packet.unresolvedExternalGateIds : [];
  const text = packet.text || systemEvidencePacketReport(packet);
  return buildInvestigationPacket({
    kind: "system-evidence",
    title: "System evidence handoff",
    subject: {
      id: "readiness:system",
      label: packet.title || "System evidence",
    },
    summary: {
      state: packet.state || "unknown",
      cls: packet.cls || "info",
      schema: packet.schema || "phragma.system.evidence.v1",
      blocked: Number(counts.blocked || 0),
      review: Number(counts.review || 0),
      clear: Number(counts.clear || 0),
      unresolvedExternalGateCount: unresolved.length,
      unresolvedExternalGateIds: unresolved,
    },
    evidence: text.split("\n"),
    artifacts: { systemEvidence: packet },
  }, { route: "#/readiness?drawer=system", collectedAt: packet.generatedAt });
}

function haInvestigationHandoffPacket(packet = {}) {
  const sync = packet.sync || {};
  const failover = packet.failover || {};
  const text = packet.text || haEvidencePacketReport(packet);
  const boundary = haFailoverPacketBoundaryModel({}, packet);
  return buildInvestigationPacket({
    kind: "ha-evidence",
    title: "HA evidence handoff",
    subject: {
      id: packet.nodeId || "readiness:ha",
      label: packet.title || "HA evidence",
    },
    summary: {
      state: packet.state || "unknown",
      cls: packet.cls || "info",
      schema: packet.schema || "phragma.ha.evidence.v1",
      mode: packet.mode || "unknown",
      role: packet.role || "unknown",
      nodeId: packet.nodeId || "",
      peerId: packet.peerId || "",
      runningPolicyVersion: Number(packet.runningPolicyVersion || 0),
      lastKnownGoodVersion: Number(packet.lastKnownGoodVersion || 0),
      syncState: sync.state || "unknown",
      failoverState: failover.state || "unknown",
      failoverEligible: Boolean(failover.eligible),
      blockerCount: Array.isArray(packet.blockers) ? packet.blockers.length : 0,
      packetBoundary: boundary,
      positiveEvidenceCount: boundary.positiveEvidence.length,
      externalBoundaryCount: boundary.externalBoundaries.length,
    },
    evidence: [
      ...text.split("\n"),
      `packet_boundary=${boundary.detail}`,
      `positive_evidence=${boundary.positiveEvidence.join("; ") || "none"}`,
      `external_boundaries=${boundary.externalBoundaries.join("; ") || "none"}`,
    ],
    artifacts: { haEvidence: packet },
  }, { route: "#/readiness?drawer=ha", collectedAt: packet.generatedAt });
}

function ebpfDrillInvestigationHandoffPacket(packet = {}) {
  const text = packet.text || ebpfDrillEvidencePacketReport(packet);
  return buildInvestigationPacket({
    kind: "ebpf-drill-evidence",
    title: "eBPF attach-drill evidence handoff",
    subject: {
      id: "readiness:ebpf-drill",
      label: packet.title || "eBPF attach-drill evidence",
    },
    summary: {
      state: packet.state || "unknown",
      cls: packet.cls || "info",
      schema: packet.schema || "phragma.ebpf.drill-evidence.v1",
      activeDataplane: packet.activeDataplane || "nftables/conntrack",
      hostState: packet.hostState || "unknown",
      attachState: packet.attachState || "unknown",
      rendererState: packet.rendererState || "unknown",
      blockerCount: Array.isArray(packet.blockers) ? packet.blockers.length : 0,
      releaseCheck: packet.releaseCheck || "ebpf-ol9-field-evidence",
    },
    evidence: text.split("\n"),
    artifacts: { ebpfDrillEvidence: packet },
  }, { route: "#/readiness?drawer=ebpf-drill", collectedAt: packet.generatedAt });
}

async function pinSystemEvidencePacket(packet) {
  await appendReadinessHandoffToCase(systemInvestigationHandoffPacket(packet), "system evidence", "System evidence could not be pinned.");
}

async function pinHAEvidencePacket(packet) {
  await appendReadinessHandoffToCase(haInvestigationHandoffPacket(packet), "HA evidence", "HA evidence could not be pinned.");
}

async function pinEbpfDrillEvidencePacket(packet) {
  await appendReadinessHandoffToCase(ebpfDrillInvestigationHandoffPacket(packet), "eBPF drill evidence", "eBPF drill evidence could not be pinned.");
}

async function appendReadinessHandoffToCase(handoff, label = "readiness evidence", failure = "Readiness evidence could not be pinned.") {
  try {
    const serverResult = await appendInvestigationPacketToActiveServerCase(handoff, {
      appendEvidence: (id, evidence) => api.addInvestigationCaseEvidence(id, evidence),
    });
    if (serverResult.appended) {
      toast("Evidence appended", `${label[0].toUpperCase()}${label.slice(1)} appended to ${serverResult.activeCaseId}.`, "ok");
      return;
    }
  } catch (e) {
    try {
      const result = pinInvestigationPacket(handoff);
      toast("Server append unavailable", `${result.toastDetail} Local browser-only fallback was used.`, "warn");
    } catch (fallbackError) {
      toast("Pin failed", fallbackError.message || failure, "bad");
    }
    return;
  }
  try {
    const result = pinInvestigationPacket(handoff);
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || failure, "bad");
  }
}

async function copyHAEvidencePacket(text) {
  try {
    if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(text);
    toast("HA evidence copied", "Packet text includes HA state, peer sync, failover, and recovery metadata.", "ok");
  } catch {
    toast("Copy unavailable", "Select and copy the generated HA evidence text from the drawer.", "warn");
  }
}

async function copyEbpfDrillEvidencePacket(text) {
  try {
    if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(text);
    toast("eBPF evidence copied", "Packet text includes drill state, release commands, blockers, and the nftables fallback boundary.", "ok");
  } catch {
    toast("Copy unavailable", "Select and copy the generated eBPF drill evidence text from the drawer.", "warn");
  }
}

function exportEbpfDrillEvidencePacket(packet = {}) {
  const body = {
    schemaVersion: packet.schema || "phragma.ebpf.drill-evidence.v1",
    exportedAt: new Date().toISOString(),
    source: "browser-local-readiness",
    custody: {
      serverStored: false,
      signed: false,
      activeDataplaneCertified: false,
    },
    packet,
  };
  const blob = new Blob([JSON.stringify(body, null, 2) + "\n"], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", {
    class: "download-anchor-hidden",
    href: url,
    download: `phragma-ebpf-drill-evidence-${Date.now()}.json`,
  });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  toast("eBPF evidence exported", "Downloaded browser-local drill handoff JSON; release acceptance still requires recorded field evidence.", "ok");
}

async function copySystemEvidencePacket(text) {
  try {
    if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(text);
    toast("System evidence copied", "Packet text includes system posture, release counts, and unresolved external gates.", "ok");
  } catch {
    toast("Copy unavailable", "Select and copy the generated system evidence text from the drawer.", "warn");
  }
}

function maybeOpenRouteDrawer(routeState = {}, models = {}) {
  reconcileReadinessRouteDrawer(routeState, models);
}

function reconcileReadinessRouteDrawer(routeState = {}, models = {}) {
  const releaseEvidence = Array.isArray(models.releaseEvidence) ? models.releaseEvidence : [];
  const desired = readinessRouteDrawerKey(routeState);
  if (!desired) {
    closeActiveReadinessRouteDrawer();
    return;
  }
  if (activeReadinessRouteDrawer === desired) return;
  closeActiveReadinessRouteDrawer();
  if (routeState.drawer === "system") {
    setTimeout(() => openSystemEvidencePacket(models.systemEvidence, { routeBacked: "system" }), 0);
    return;
  }
  if (routeState.drawer === "ha") {
    setTimeout(() => openHAEvidencePacket(models.haEvidence, { routeBacked: "ha" }), 0);
    return;
  }
  if (routeState.drawer === "ebpf-drill") {
    setTimeout(() => openEbpfDrillEvidencePacket(models.ebpfDrillEvidence, { routeBacked: "ebpf-drill" }), 0);
    return;
  }
  if (routeState.drawer === "ha-cockpit") {
    setTimeout(() => openHAOperationsCockpit(models.ha, models.haEvidence, { routeBacked: "ha-cockpit" }), 0);
    return;
  }
  if (routeState.drawer === "support-bundle") {
    activeReadinessRouteDrawer = "support-bundle";
    setTimeout(() => exportSupportBundle({ routeBacked: "support-bundle" }), 0);
    return;
  }
  if (routeState.drawer === "release-acceptance") {
    if (models.releaseAcceptanceStatus) {
      setTimeout(() => openReleaseAcceptanceStatus(models.releaseAcceptanceStatus, { routeBacked: "release-acceptance" }), 0);
      return;
    }
    setTimeout(clearReadinessRouteState, 0);
    return;
  }
  if (routeState.packet) {
    const item = releaseEvidence.find((candidate) => candidate.id === routeState.packet);
    if (item?.packet) {
      setTimeout(() => openReleaseEvidencePacket(item, { routeBacked: `packet:${routeState.packet}` }), 0);
      return;
    }
    setTimeout(clearReadinessRouteState, 0);
  }
}

export function readinessRouteDrawerKey(routeState = {}) {
  if (routeState.drawer) return String(routeState.drawer);
  const packet = String(routeState.packet || "").trim();
  if (packet && !releaseEvidencePacketIds().includes(packet)) return "";
  return packet ? `packet:${packet}` : "";
}

export function shouldClearReadinessRouteOnClose(expectedDrawer, currentRouteState = {}) {
  const expected = readinessRouteBackedKind(expectedDrawer, "");
  return Boolean(expected && readinessRouteDrawerKey(currentRouteState) === expected);
}

function closeActiveReadinessRouteDrawer() {
  if (!activeReadinessRouteDrawer) return;
  activeReadinessRouteDrawer = "";
  closeDrawer({ invokeOnClose: false });
}

export function normalizeReadinessRouteState(next = {}, actions = null) {
  const validActions = Array.isArray(actions) ? new Set(actions.map((item) => item.id).filter(Boolean)) : null;
  const validPackets = new Set(releaseEvidencePacketIds());
  const normalized = { ...DEFAULT_ROUTE_STATE, ...next };
  normalized.drawer = ["system", "ha", "ebpf-drill", "ha-cockpit", "support-bundle", "release-acceptance"].includes(normalized.drawer) ? normalized.drawer : "";
  normalized.packet = normalized.drawer ? "" : String(normalized.packet || "").trim();
  if (normalized.packet && !validPackets.has(normalized.packet)) normalized.packet = "";
  normalized.action = normalized.drawer || normalized.packet ? "" : String(normalized.action || "").trim();
  if (validActions && normalized.action && !validActions.has(normalized.action)) normalized.action = "";
  return normalized;
}

function writeReadinessRouteState(patch = {}) {
  const current = typeof location !== "undefined" && location.hash.includes("?")
    ? Object.fromEntries(new URLSearchParams(location.hash.slice(location.hash.indexOf("?") + 1)).entries())
    : {};
  const next = normalizeReadinessRouteState({ ...DEFAULT_ROUTE_STATE, ...current, ...patch });
  writeQueryState(READINESS_ROUTE, next, DEFAULT_ROUTE_STATE, ROUTE_KEYS);
}

function clearReadinessRouteState() {
  activeReadinessRouteDrawer = "";
  writeQueryState(READINESS_ROUTE, DEFAULT_ROUTE_STATE, DEFAULT_ROUTE_STATE, ROUTE_KEYS);
}

function clearReadinessRouteStateFor(expectedDrawer) {
  if (!shouldClearReadinessRouteOnClose(expectedDrawer, currentReadinessRouteState())) return;
  clearReadinessRouteState();
}

function currentReadinessRouteState() {
  if (typeof location === "undefined") return { ...DEFAULT_ROUTE_STATE };
  const raw = location.hash.slice(1) || READINESS_ROUTE;
  const [path, queryString = ""] = raw.split("?");
  if (path !== READINESS_ROUTE) return { ...DEFAULT_ROUTE_STATE };
  if (!queryString) return { ...DEFAULT_ROUTE_STATE };
  const query = Object.fromEntries(new URLSearchParams(queryString).entries());
  return normalizeReadinessRouteState(readQueryState(query, DEFAULT_ROUTE_STATE, ROUTE_KEYS));
}

function isCurrentReadinessRouteDrawer(expectedDrawer) {
  if (typeof location === "undefined") return true;
  return shouldClearReadinessRouteOnClose(expectedDrawer, currentReadinessRouteState());
}

function readinessRouteBackedKind(routeBacked, fallback) {
  if (!routeBacked) return "";
  if (routeBacked === true) return fallback || "";
  return String(routeBacked);
}

function maybeFocusRouteAction(routeState = {}, actions = [], root) {
  if (!routeState.action) return;
  const item = actions.find((candidate) => candidate.id === routeState.action);
  if (!item) {
    setTimeout(clearReadinessRouteState, 0);
    return;
  }
  setTimeout(() => {
    const rows = Array.from(root?.querySelectorAll?.("[data-readiness-action-id]") || []);
    const target = rows.find((row) => row.dataset?.readinessActionId === item.id);
    if (!target) return;
    try {
      target.focus?.({ preventScroll: true });
    } catch {
      target.focus?.();
    }
    target.scrollIntoView?.({ block: "center", inline: "nearest", behavior: "smooth" });
  }, 0);
}

async function copyReadinessActionLink(actionId) {
  const hash = readinessActionHash(actionId);
  let text = hash;
  if (typeof location !== "undefined") {
    try {
      const url = new URL(location.href);
      url.hash = hash;
      text = url.toString();
    } catch {
      text = hash;
    }
  }
  try {
    if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(text);
    toast("Readiness link copied", "Reloading the link focuses this action queue item.", "ok");
  } catch {
    toast("Copy unavailable", "Open the action link, then copy the browser URL.", "warn");
  }
}

function actionRow(item, activeAction = "") {
  const active = item.id && item.id === activeAction;
  return h("div", {
    id: item.id ? "readiness-action-" + item.id : null,
    class: "warning-row " + actionClass(item.level) + (active ? " active" : ""),
    tabindex: item.id ? "-1" : null,
    "aria-label": item.id ? `Readiness action ${item.title || item.id}` : null,
    dataset: item.id ? { readinessActionId: item.id } : {},
  },
    h("div", {}, badge(item.badge || item.level || "action", actionClass(item.level), { dot: true })),
    h("div", {},
      h("strong", {}, item.title || "Action"),
      item.detail ? h("div", { class: "note" }, item.detail) : null,
      item.command || item.href || item.id ? h("div", { class: "warning-actions" },
        item.command ? h("code", {}, item.command) : null,
        item.command ? h("button", { class: "btn sm ghost", type: "button", title: `Copy readiness command for ${item.title || item.id || "action"}`, "aria-label": `Copy readiness command for ${item.title || item.id || "action"}`, dataset: { readinessActionCommand: item.id || "action" }, onclick: () => copyCommand(item.command) }, h("span", { html: icon("copy", 15) }), "Copy command") : null,
        item.id ? h("a", { class: "btn sm ghost", href: readinessActionHash(item.id), title: `Focus readiness action ${item.title || item.id}`, "aria-label": `Focus readiness action ${item.title || item.id}`, dataset: { readinessActionFocus: item.id } }, h("span", { html: icon("shield", 15) }), "Focus") : null,
        item.id ? h("button", { class: "btn sm ghost", type: "button", title: `Copy readiness action link for ${item.title || item.id}`, "aria-label": `Copy readiness action link for ${item.title || item.id}`, dataset: { readinessActionLink: item.id }, onclick: () => copyReadinessActionLink(item.id) }, h("span", { html: icon("copy", 15) }), "Copy link") : null,
        item.href ? h("a", { class: "btn sm ghost", href: item.href, title: `Open ${item.title || item.id || "readiness action"}`, "aria-label": `Open ${item.title || item.id || "readiness action"}`, dataset: { readinessActionOpen: item.id || item.href } }, "Open") : null) : null));
}

function postureMetric(label, value) {
  return h("div", { class: "posture-metric" },
    h("span", {}, label),
    h("strong", {}, value));
}

export function routingVpnPostureModel(policy = {}, status = {}, routingRuntime = routingRuntimeEvidence(status, policy)) {
  const bgp = policy.routing?.bgp || {};
  const ospf = policy.routing?.ospf || {};
  const ipsecTunnels = Array.isArray(policy.vpn?.ipsecTunnels) ? policy.vpn.ipsecTunnels : [];
  const wireguardInterfaces = Array.isArray(policy.vpn?.wireguardInterfaces) ? policy.vpn.wireguardInterfaces : [];
  const tunnelModels = vpnTunnelModels(policy, status);
  const ipsecRuntime = status.vpn?.ipsec || {};
  const wireguardRuntime = status.vpn?.wireguard || {};
  const wgPeers = wireguardInterfaces.reduce((sum, iface) => sum + (Array.isArray(iface?.peers) ? iface.peers.length : 0), 0);
  const handshookPeers = tunnelModels.filter((model) => model.kind === "wireguard" && model.runtime?.state === "handshook").length;
  const activeIpsecNames = new Set((Array.isArray(ipsecRuntime.tunnels) ? ipsecRuntime.tunnels : [])
    .filter((tunnel) => String(tunnel?.state || "").toLowerCase() === "active")
    .map((tunnel) => String(tunnel?.name || "").trim())
    .filter(Boolean));
  const activeIpsec = ipsecTunnels.filter((tunnel, index) => activeIpsecNames.has(tunnel?.name || `ipsec-${index + 1}`)).length;
  const ipsecState = ipsecTunnels.length
    ? activeIpsec === ipsecTunnels.length && String(ipsecRuntime.state || "").toLowerCase() === "active"
      ? "active"
      : ipsecRuntime.state === "degraded" || ipsecRuntime.state === "unknown"
        ? ipsecRuntime.state
        : "waiting"
    : "not-configured";
  const wireguardState = wgPeers
    ? handshookPeers === wgPeers && String(wireguardRuntime.state || "").toLowerCase() === "active"
      ? "active"
      : wireguardRuntime.state === "degraded" || wireguardRuntime.state === "unknown"
        ? wireguardRuntime.state
        : "waiting"
    : "not-configured";
  const tunnelPathCount = tunnelModels.reduce((sum, model) => sum + (Array.isArray(model.targets) ? model.targets.length : 0), 0);
  const firstAffectedIpsec = ipsecTunnels.map((tunnel, index) => ({ kind: "ipsec", name: tunnel?.name || `ipsec-${index + 1}` }))
    .find((tunnel) => !activeIpsecNames.has(tunnel.name));
  const firstAffected = firstAffectedIpsec || tunnelModels.find((model) =>
    model.runtime?.state && !["active", "handshook"].includes(String(model.runtime.state).toLowerCase())) || tunnelModels[0] || null;
  const rows = [
    {
      id: "routing-vpn-bgp",
      label: "BGP",
      state: bgp.enabled ? (routingRuntime.state || "unknown") : "not-configured",
      tone: bgp.enabled ? routingVpnTone(routingRuntime.state) : "neutral",
      detail: bgp.enabled
        ? `${routingRuntime.bgpCount || 0} runtime neighbor(s); ${Array.isArray(bgp.neighbors) ? bgp.neighbors.length : 0} configured.`
        : "BGP is not enabled in the running policy.",
    },
    {
      id: "routing-vpn-ospf",
      label: "OSPF",
      state: ospf.enabled ? (routingRuntime.state || "unknown") : "not-configured",
      tone: ospf.enabled ? routingVpnTone(routingRuntime.state) : "neutral",
      detail: ospf.enabled
        ? `${routingRuntime.ospfCount || 0} runtime neighbor(s); ${Array.isArray(ospf.networks) ? ospf.networks.length : 0} configured network(s).`
        : "OSPF is not enabled in the running policy.",
    },
    {
      id: "routing-vpn-ipsec",
      label: "IPsec",
      state: ipsecState,
      tone: ipsecTunnels.length ? routingVpnTone(ipsecState) : "neutral",
      detail: ipsecTunnels.length
        ? `${activeIpsec}/${ipsecTunnels.length} configured tunnel(s) have active SA evidence.`
        : "No IPsec tunnels are configured in the running policy.",
    },
    {
      id: "routing-vpn-wireguard",
      label: "WireGuard",
      state: wireguardState,
      tone: wgPeers ? routingVpnTone(wireguardState) : "neutral",
      detail: wgPeers
        ? `${handshookPeers}/${wgPeers} configured peer(s) have recorded handshake evidence.`
        : "No WireGuard peers are configured in the running policy.",
    },
  ];
  const activeRows = rows.filter((row) => row.state !== "not-configured");
  const blocked = activeRows.filter((row) => ["bad", "warn"].includes(row.tone)).length;
  const cls = blocked ? activeRows.some((row) => row.tone === "bad") ? "bad" : "warn" : activeRows.length ? "ok" : "info";
  return {
    cls,
    label: activeRows.length ? `${blocked ? blocked + " review" : "observed"}` : "not configured",
    detail: activeRows.length
      ? "Summarizes running policy configuration and passive FRR/VPN system status evidence."
      : "Running policy does not configure dynamic routing or VPN tunnels; passive FRR/VPN status remains available after configuration.",
    metrics: {
      staticRoutes: Array.isArray(policy.staticRoutes) ? policy.staticRoutes.length : 0,
      tunnelPaths: tunnelPathCount,
      ipsecTunnels: ipsecTunnels.length,
      wireguardPeers: wgPeers,
    },
    rows,
    firstTunnelHref: firstAffected ? vpnTunnelHash(firstAffected) : "",
  };
}

function routingVpnPostureCard(posture = {}) {
  return card(h("h2", {}, "Routing & VPN posture", h("span", { class: "spacer" }), badge(posture.label || "unknown", posture.cls || "info")),
    h("div", {
      class: "runtime-grid",
      dataset: { readinessRoutingVpnPosture: "true" },
    },
      postureMetric("Static routes", String(posture.metrics?.staticRoutes || 0)),
      postureMetric("Tunnel paths", String(posture.metrics?.tunnelPaths || 0)),
      postureMetric("IPsec tunnels", String(posture.metrics?.ipsecTunnels || 0)),
      postureMetric("WG peers", String(posture.metrics?.wireguardPeers || 0))),
    h("div", { class: "alert-box " + readinessBoxClass(posture.cls || "info") },
      h("strong", {}, posture.cls === "bad" ? "Routing or VPN runtime evidence needs attention." : posture.cls === "warn" ? "Routing or VPN runtime evidence needs review." : "Routing and VPN posture"),
      h("div", { class: "note" }, posture.detail || "Routing and VPN status is summarized from running policy and system status.")),
    posture.rows?.length ? h("div", { class: "readiness-list compact" }, posture.rows.map(routingVpnPostureRow)) :
      emptyState("vpn", "No routing or VPN posture", "Running policy and system status did not return routing or VPN evidence."),
    h("div", { class: "warning-actions" },
	      h("a", { class: "btn sm ghost", href: "#/netvpn", title: "Open Routing and VPN workspace", "aria-label": "Open Routing and VPN workspace", dataset: { readinessRoutingVpnAction: "open-netvpn" } }, h("span", { html: icon("vpn", 15) }), "Open Routing & VPN"),
      posture.firstTunnelHref ? h("a", { class: "btn sm ghost", href: posture.firstTunnelHref, title: "Open affected Routing and VPN tunnel", "aria-label": "Open affected Routing and VPN tunnel", dataset: { readinessRoutingVpnAction: "open-affected-tunnel" } }, h("span", { html: icon("arrowRight", 15) }), "Open affected tunnel") : null));
}

function routingVpnPostureRow(row = {}) {
  return h("div", {
    class: "readiness-row",
    dataset: { readinessRoutingVpnItem: row.id || "", readinessRoutingVpnState: row.state || "unknown" },
  },
    h("div", {},
      h("strong", {}, row.label || "Surface"),
      h("div", { class: "note" }, row.detail || "")),
    badge(row.state || "unknown", row.tone || "neutral", { dot: true }));
}

function routingVpnTone(state = "") {
  const normalized = String(state || "").toLowerCase();
  if (["active", "ready", "handshook", "established"].includes(normalized) || normalized.startsWith("full")) return "ok";
  if (["waiting", "simulation", "not observed", "inactive", "configured-no-peers"].includes(normalized)) return "warn";
  if (["degraded", "unknown", "failed", "missing-prerequisites"].includes(normalized)) return "bad";
  return "neutral";
}

function contentReadinessCard(posture) {
  const blockers = Array.isArray(posture.blockers) ? posture.blockers : [];
  const surfaces = Array.isArray(posture.surfaces) ? posture.surfaces : [];
  return card(h("h2", {}, "Content readiness", h("span", { class: "spacer" }), badge(contentBadgeLabel(posture), posture.summary?.cls || "neutral")),
    h("div", { class: "runtime-grid" },
      postureMetric("App-ID package", posture.metrics?.appPackage || "unknown"),
      postureMetric("Threat-ID package", posture.metrics?.threatPackage || "unknown"),
      postureMetric("Registry feeds", posture.metrics?.feedRegistry || "unknown"),
      postureMetric("Signed packages", posture.metrics?.signedPackages || "unknown")),
    h("div", { class: "alert-box " + readinessBoxClass(posture.summary?.cls || "warn") },
      h("strong", {}, posture.summary?.title || "Content package posture is unknown."),
      h("div", { class: "note" }, posture.summary?.detail || "Threat content package evidence is not available.")),
    blockers.length ? h("div", { class: "warning-list" }, blockers.map((blocker) =>
      h("div", { class: "warning-row " + contentBlockerClass(blocker) },
        h("div", {}, badge(contentBlockerBadge(blocker), contentBlockerClass(blocker), { dot: true })),
        h("div", {},
          h("strong", {}, blocker),
          h("div", { class: "note" }, contentBlockerDetail(blocker)))))) :
      emptyState("check", "No content blockers", "Signed App-ID, Threat-ID, and feed package evidence is complete."),
    surfaces.length ? h("div", { class: "readiness-list compact" }, surfaces.map(contentReadinessSurfaceRow)) : null,
    h("div", { class: "warning-actions" },
	      h("a", { class: "btn sm ghost", href: "#/intel", title: "Open threat intelligence workspace", "aria-label": "Open threat intelligence workspace", dataset: { readinessContentAction: "open-intel" } }, h("span", { html: icon("intel", 15) }), "Open threat intel")));
}

function contentReadinessSurfaceRow(surface) {
  const fields = Array.isArray(surface.fields) ? surface.fields : [];
  const provenance = Array.isArray(surface.provenance) ? surface.provenance : [];
  return h("div", { class: "readiness-row content-package-row" },
    h("div", {},
      h("div", { class: "content-package-head" },
        h("strong", {}, surface.name || "Content surface"),
        badge(surface.badge || "unknown", surface.cls || "neutral")),
      h("div", { class: "note" }, surface.detail || ""),
      fields.length ? h("div", { class: "content-package-evidence" },
        fields.map((field) => h("div", { class: "content-package-field " + (field.cls || "neutral") },
          h("span", {}, field.label || "Field"),
          h("strong", { class: "mono", title: field.value || "" }, field.value || "—")))) : null,
      provenance.length ? h("div", { class: "content-provenance-list" },
        provenance.slice(0, 3).map((item) => h("span", { class: "content-provenance-item", title: item.url || "" },
          h("strong", {}, item.name || "source"),
          h("small", {}, item.license || "license missing")))) : null),
    badge(surface.rollbackAvailable ? "rollback ready" : "rollback missing", surface.rollbackAvailable ? "ok" : "warn"));
}

function contentBadgeLabel(posture) {
  if (posture.summary?.cls === "ok") return "verified";
  if (posture.summary?.cls === "bad") return "blocked";
  return `${posture.blockers?.length || 0} blocker${posture.blockers?.length === 1 ? "" : "s"}`;
}

function contentBlockerClass(blocker) {
  if (blocker === "content package API" || blocker === "commercial license conflict") return "bad";
  return "warn";
}

function contentBlockerBadge(blocker) {
  if (blocker === "commercial license conflict") return "license";
  if (blocker === "content package API") return "api";
  if (/rollback/.test(blocker)) return "rollback";
  if (/regression/.test(blocker)) return "test";
  if (/signature|signed/.test(blocker)) return "signature";
  return "package";
}

function contentBlockerDetail(blocker) {
  if (blocker === "commercial license conflict") return "A feed that forbids commercial use is enabled while commercial use is declared.";
  if (blocker === "content package API") return "The firewall could not report package status; verify the local content package API before production.";
  if (/rollback/.test(blocker)) return "Content updates must have a verified rollback point before they can safely change verdicts.";
  if (/regression/.test(blocker)) return "Package promotion needs a passed regression result so false-positive and parsing failures are caught.";
  if (/signature|signed/.test(blocker)) return "Install a signed package manifest so App-ID, Threat-ID, and feed provenance can be verified.";
  if (/version|hash/.test(blocker)) return "Package identity must include version and hash evidence for audit and explainability.";
  if (/staged rollout/.test(blocker)) return "Package promotion needs staged rollout state before it is considered production ready.";
  return "Resolve this content control before relying on package-driven verdict changes.";
}

function runtimeCard(status) {
  const rt = status.runtime || {};
  const mgmt = status.management || {};
  const host = status.host || {};
  const kernel = kernelTuningStatus(status);
  const conntrack = conntrackCapacity(status);
  const rateLabel = mgmt.rateLimitEnabled
    ? `${mgmt.rateLimitRequestsPerMinute || 0}/min, burst ${mgmt.rateLimitBurst || 0}`
    : "disabled";
  const trustedProxies = Array.isArray(mgmt.trustedProxyCidrs) && mgmt.trustedProxyCidrs.length
    ? mgmt.trustedProxyCidrs.join(", ")
    : "none";
  const restCaps = [
    mgmt.httpMaxBodyBytes ? `${fmt.bytes(mgmt.httpMaxBodyBytes)} body` : "body uncapped",
    mgmt.httpMaxHeaderBytes ? `${fmt.bytes(mgmt.httpMaxHeaderBytes)} headers` : "header default",
  ].join(" / ");
  const grpcCaps = [
    mgmt.grpcMaxRecvBytes ? `${fmt.bytes(mgmt.grpcMaxRecvBytes)} recv` : "recv default",
    mgmt.grpcMaxSendBytes ? `${fmt.bytes(mgmt.grpcMaxSendBytes)} send` : "send default",
  ].join(" / ");
  const httpTimeouts = [
    mgmt.httpReadHeaderTimeout ? `header ${mgmt.httpReadHeaderTimeout}` : "",
    mgmt.httpReadTimeout ? `read ${mgmt.httpReadTimeout}` : "",
    mgmt.httpWriteTimeout ? `write ${mgmt.httpWriteTimeout}` : "",
    mgmt.httpIdleTimeout ? `idle ${mgmt.httpIdleTimeout}` : "",
  ].filter(Boolean).join(" / ") || "not configured";
  return card(h("h2", {}, "Runtime"),
    h("dl", { class: "kv readiness-kv" },
      h("dt", {}, "Dataplane"), h("dd", { class: "mono" }, rt.activeDataplane || "—"),
      h("dt", {}, "Mode"), h("dd", {}, rt.dryRun ? badge("dry-run", "warn") : badge("enforcing", "ok")),
      h("dt", {}, "TLS"), h("dd", {}, rt.tlsEnabled ? badge("enabled", "ok") : badge("disabled", "bad")),
      h("dt", {}, "Auth"), h("dd", {}, rt.authEnabled ? badge("enabled", "ok") : badge("disabled", "bad")),
      h("dt", {}, "Rate limit"), h("dd", {}, badge(rateLabel, mgmt.rateLimitEnabled ? "ok" : "warn")),
      h("dt", {}, "Rate identity"), h("dd", { class: "mono" }, mgmt.rateLimitClientIdentity || "socket-peer"),
      h("dt", {}, "Trusted proxies"), h("dd", { class: "mono" }, trustedProxies),
      h("dt", {}, "REST caps"), h("dd", { class: "mono" }, restCaps),
      h("dt", {}, "gRPC caps"), h("dd", { class: "mono" }, grpcCaps),
      h("dt", {}, "HTTP timeouts"), h("dd", { class: "mono" }, httpTimeouts),
      h("dt", {}, "Kernel tuning"), h("dd", {}, badge(kernel.label, kernel.cls)),
      h("dt", {}, "Sysctl profile"), h("dd", { class: "mono" }, kernel.configPath || "—"),
      h("dt", {}, "State table"), h("dd", {}, badge(conntrackLabel(conntrack), conntrack.cls)),
      h("dt", {}, "State detail"), h("dd", { class: "mono" }, conntrack.detail || "—"),
      h("dt", {}, "Inspection fan-out"), h("dd", { class: "mono" }, `${rt.inspectionWorkers || 0} worker(s) / ${rt.hostCpus || 0} CPU(s)`),
      h("dt", {}, "Host resources"), h("dd", {}, badge(host.state || "unknown", capabilityClass(host.state))),
      h("dt", {}, "Host load"), h("dd", { class: "mono" }, hostLoadLabel(host)),
      h("dt", {}, "Memory"), h("dd", { class: "mono" }, hostMemoryLabel(host)),
      h("dt", {}, "Interfaces"), h("dd", { class: "mono" }, hostInterfaceSummary(host)),
      h("dt", {}, "gRPC"), h("dd", { class: "mono" }, rt.grpcListen || "—"),
      h("dt", {}, "WebUI / REST"), h("dd", { class: "mono" }, rt.httpListen || "—"),
      h("dt", {}, "Data directory"), h("dd", { class: "mono" }, rt.dataDir || "—"),
      h("dt", {}, "Log directory"), h("dd", { class: "mono" }, rt.logDir || "—")));
}

function haReadinessCard(ha = {}, packet = buildHAEvidencePacket(ha), opts = {}) {
  const blockers = Array.isArray(ha.blockers) ? ha.blockers : [];
  const sync = ha.sync || {};
  const replication = ha.replication || {};
  const failover = ha.failover || {};
  const fencingEvidence = ha.fencingEvidence || {};
  const transportEvidence = ha.transportEvidence || {};
  const conntrackSync = ha.conntrackSync || {};
  const pullAction = haPolicyPullActionState(ha);
  const activationAction = haFailoverActivationActionState(ha);
  const nodeLine = [ha.nodeId || "", ha.peerId || ""].filter(Boolean).join(" -> ") || "—";
  const peerLine = ha.peerAddress ? `${nodeLine} (${ha.peerAddress})` : nodeLine;
  const policyLine = [
    ha.runningPolicyVersion ? `running v${ha.runningPolicyVersion}` : "running unknown",
    ha.lastKnownGoodVersion ? `LKG v${ha.lastKnownGoodVersion}` : "LKG missing",
    ha.lastKnownGoodState || "",
  ].filter(Boolean).join(" / ");
  return card(h("h2", {}, "High availability", h("span", { class: "spacer" }), badge(ha.label || ha.state || "unknown", ha.cls || "info")),
    h("div", { class: "alert-box " + readinessBoxClass(ha.cls || "info") },
      h("strong", {}, ha.cls === "bad" ? "HA readiness is blocked." : ha.cls === "warn" ? "HA readiness needs review." : "HA readiness"),
      h("div", { class: "note" }, ha.detail || "High availability status is unavailable.")),
    h("dl", { class: "kv readiness-kv" },
      h("dt", {}, "Mode"), h("dd", {}, badge(ha.mode || "unknown", ha.cls || "info")),
      h("dt", {}, "Role"), h("dd", {}, badge(ha.role || "unknown", ha.role === "active" ? "ok" : ha.role === "passive" ? "warn" : "info")),
      h("dt", {}, "Nodes"), h("dd", { class: "mono" }, peerLine),
      h("dt", {}, "Policy"), h("dd", { class: "mono" }, policyLine),
      h("dt", {}, "Artifact set"), h("dd", { class: "mono" }, shortEvidenceHash(ha.artifactSet) || "—"),
      h("dt", {}, "Sync"), h("dd", {}, badge(sync.state || "unknown", capabilityClass(sync.state))),
      h("dt", {}, "Replication"), h("dd", {}, badge(replication.enabled ? (replication.state || "enabled") : "disabled", haReplicationClass(replication))),
      h("dt", {}, "Fencing evidence"), h("dd", {}, badge(fencingEvidence.state || "not_recorded", haFencingEvidenceClass(fencingEvidence))),
      h("dt", {}, "VIP/GARP evidence"), h("dd", {}, badge(transportEvidence.state || "not_configured", haTransportEvidenceClass(transportEvidence))),
      h("dt", {}, "Conntrack sync"), h("dd", {}, badge(conntrackSync.state || "not_configured", haConntrackSyncClass(conntrackSync))),
      h("dt", {}, "Failover"), h("dd", {}, badge(`${failover.state || "unknown"}${failover.eligible ? " eligible" : ""}`, failover.eligible ? "ok" : capabilityClass(failover.state)))),
    h("div", { class: "alert-box " + readinessBoxClass(haFencingEvidenceClass(fencingEvidence)), dataset: { readinessHaFencingEvidence: fencingEvidence.state || "not_recorded" } },
      h("strong", {}, fencingEvidence.state === "recorded" ? "Peer-fencing evidence recorded." : "Peer fencing remains external."),
      h("div", { class: "note" }, fencingEvidence.detail || "No provider-backed peer-fencing evidence is recorded in the HA status."),
      h("dl", { class: "kv readiness-kv compact" },
        h("dt", {}, "Provider"), h("dd", { class: "mono" }, fencingEvidence.provider || "—"),
        h("dt", {}, "Claim"), h("dd", { class: "mono" }, fencingEvidence.claim || "—"),
        h("dt", {}, "Evidence ID"), h("dd", { class: "mono" }, fencingEvidence.evidenceId || "—"),
        h("dt", {}, "Observed"), h("dd", { class: "mono" }, fencingEvidence.observedAt || "—"))),
    h("div", { class: "alert-box " + readinessBoxClass(haTransportEvidenceClass(transportEvidence)), dataset: { readinessHaTransportEvidence: transportEvidence.state || "not_configured" } },
      h("strong", {}, transportEvidence.state === "promoted" ? "Local VIP/GARP evidence recorded." : "VIP/GARP evidence is incomplete."),
      h("div", { class: "note" }, transportEvidence.detail || "No Linux-local VIP, GARP, or neighbor evidence has been recorded."),
      h("dl", { class: "kv readiness-kv compact" },
        h("dt", {}, "VIP"), h("dd", { class: "mono" }, transportEvidence.vip || "—"),
        h("dt", {}, "Interface"), h("dd", { class: "mono" }, transportEvidence.interface || "—"),
        h("dt", {}, "GARP"), h("dd", { class: "mono" }, [transportEvidence.garpState || "—", transportEvidence.garpDetail || ""].filter(Boolean).join(" / ")),
        h("dt", {}, "Neighbor"), h("dd", { class: "mono" }, [transportEvidence.neighborState || "—", transportEvidence.neighborDetail || ""].filter(Boolean).join(" / ")))),
    h("div", { class: "alert-box " + readinessBoxClass(haConntrackSyncClass(conntrackSync)), dataset: { readinessHaConntrackSync: conntrackSync.state || "not_configured" } },
      h("strong", {}, conntrackSync.state === "synced" ? "Conntrack-sync evidence reported." : "Conntrack sync is not proven."),
      h("div", { class: "note" }, conntrackSync.detail || "No connection-state synchronization evidence was returned."),
      h("dl", { class: "kv readiness-kv compact" },
        h("dt", {}, "Provider"), h("dd", { class: "mono" }, conntrackSync.provider || "—"),
        h("dt", {}, "Claim"), h("dd", { class: "mono" }, conntrackSync.claim || "—"),
        h("dt", {}, "Evidence ID"), h("dd", { class: "mono" }, conntrackSync.evidenceId || "—"),
        h("dt", {}, "Observed"), h("dd", { class: "mono" }, conntrackSync.observedAt || "—"))),
    h("div", { class: "flex wrap", style: { marginTop: "12px" } },
      h("button", {
        class: "btn sm",
        type: "button",
        title: "Open HA evidence packet",
        "aria-label": "Open HA evidence packet",
        dataset: { readinessAction: "open-ha-evidence" },
        onclick: () => openRoutedHAEvidencePacket(packet),
      }, h("span", { html: icon("terminal", 15) }), "HA evidence"),
      h("button", {
        class: "btn sm",
        type: "button",
        title: "Open HA operations cockpit",
        "aria-label": "Open HA operations cockpit",
        dataset: { readinessAction: "open-ha-cockpit" },
        onclick: () => openRoutedHACockpit(ha, packet),
      }, h("span", { html: icon("shield", 15) }), "Operations cockpit"),
      h("button", {
        class: "btn sm " + (pullAction.canPull ? "primary" : "ghost"),
        type: "button",
        disabled: !pullAction.canPull,
        title: pullAction.canPull ? "Manually resync from the active peer through the audited apply path." : pullAction.disabledReason,
        "aria-label": pullAction.canPull ? "Manually resync from the active peer" : `Manual HA resync unavailable: ${pullAction.disabledReason || "not eligible"}`,
        dataset: { readinessAction: "ha-policy-pull" },
        onclick: () => openHAPolicyPullReview(ha),
      }, h("span", { html: icon("download", 15) }), "Manual resync"),
      h("button", {
        class: "btn sm " + (activationAction.canActivate ? "primary" : "ghost"),
        type: "button",
        disabled: !activationAction.canActivate,
        title: activationAction.canActivate ? "Mark this passive node active after manual cutover review." : activationAction.disabledReason,
        "aria-label": activationAction.canActivate ? "Mark this passive node active after manual cutover review" : `HA activation unavailable: ${activationAction.disabledReason || "not eligible"}`,
        dataset: { readinessAction: "ha-failover-activate" },
        onclick: () => openHAFailoverActivationReview(ha),
      }, h("span", { html: icon("shield", 15) }), "Activate"),
      opts.hasAction ? h("a", {
        class: "btn sm ghost",
        href: readinessActionHash("ha-readiness"),
        title: "Open HA readiness action",
        "aria-label": "Open HA readiness action",
        dataset: { readinessAction: "ha-action-link" },
      }, h("span", { html: icon("arrowRight", 15) }), "Action link") : null),
    blockers.length ? h("div", { class: "release-acceptance-problem-list", style: { marginTop: "12px" } },
      blockers.slice(0, 4).map((blocker) => h("span", {}, blocker)),
      blockers.length > 4 ? h("span", {}, `${blockers.length - 4} more blocker(s)`) : null) : null);
}

function haFencingEvidenceClass(evidence = {}) {
  const state = String(evidence.state || "").trim().toLowerCase();
  if (state === "recorded") return "ok";
  if (state === "unavailable") return "bad";
  if (state === "acknowledged_external" || state === "not_recorded") return "warn";
  return "info";
}

function haTransportEvidenceClass(evidence = {}) {
  const state = String(evidence.state || "").trim().toLowerCase();
  if (state === "promoted") return "ok";
  if (state === "unavailable" || state === "degraded") return "bad";
  if (state === "not_configured" || state === "not_performed") return "warn";
  return "info";
}

function haConntrackSyncClass(evidence = {}) {
  const state = String(evidence.state || "").trim().toLowerCase();
  if (state === "synced") return "ok";
  if (state === "unavailable" || state === "degraded") return "bad";
  if (state === "not_configured" || state === "not_performed") return "warn";
  return "info";
}

export function haPolicyPullActionState(ha = {}) {
  const mode = String(ha.mode || "").toLowerCase();
  const role = String(ha.role || "").toLowerCase();
  const sync = ha.sync || {};
  if (mode !== "active-passive") {
    return { canPull: false, disabledReason: "Policy pull requires active/passive HA mode." };
  }
  if (role !== "passive") {
    return { canPull: false, disabledReason: "Policy pull runs from the passive node only." };
  }
  if (!ha.peerAddress && !ha.peerId) {
    return { canPull: false, disabledReason: "Configure an HA peer before pulling policy." };
  }
  if (!sync.peerVersion) {
    return { canPull: false, disabledReason: "Peer running policy version is not available yet." };
  }
  return { canPull: true, disabledReason: "" };
}

export function haFailoverActivationActionState(ha = {}) {
  const mode = String(ha.mode || "").toLowerCase();
  const role = String(ha.role || "").toLowerCase();
  const sync = ha.sync || {};
  const failover = ha.failover || {};
  if (mode !== "active-passive") {
    return { canActivate: false, disabledReason: "Manual activation requires active/passive HA mode." };
  }
  if (role !== "passive") {
    return { canActivate: false, disabledReason: "Manual activation runs from the passive node only." };
  }
  if (!failover.eligible) {
    const blockers = Array.isArray(failover.blockers) && failover.blockers.length ? failover.blockers : Array.isArray(ha.blockers) ? ha.blockers : [];
    return { canActivate: false, disabledReason: blockers.join(" ") || "Failover readiness is not eligible yet." };
  }
  if (!ha.runningPolicyVersion || !ha.lastKnownGoodVersion) {
    return { canActivate: false, disabledReason: "Running policy and last-known-good metadata are required." };
  }
  if (sync.state && sync.state !== "synced") {
    return { canActivate: false, disabledReason: "Policy sync must be synchronized before activation." };
  }
  return { canActivate: true, disabledReason: "" };
}

function openHAPolicyPullReview(ha = {}) {
  const comment = h("textarea", {
    class: "input",
    rows: 4,
    placeholder: "Audit comment",
    spellcheck: "true",
    dataset: { haPolicyPullField: "comment" },
  });
  const ackRisk = h("input", { type: "checkbox", dataset: { haPolicyPullAck: "risk" } });
  const ackRuntime = h("input", { type: "checkbox", dataset: { haPolicyPullAck: "runtime" } });
  const applyBtn = h("button", {
    class: "btn primary",
    type: "button",
    title: "Submit audited manual HA policy resync",
    "aria-label": "Submit audited manual HA policy resync",
    dataset: { haPolicyPullSubmit: "resync" },
    onclick: () => submitHAPolicyPull(comment, ackRisk, ackRuntime, applyBtn),
  }, h("span", { html: icon("download", 16) }), "Manual resync");
  openDrawer({
    title: "Manual HA policy resync",
    subtitle: "Audited recovery operation",
    width: "620px",
    body: h("div", { class: "support-bundle-preview" },
      h("div", { class: "alert-box warn" },
        h("strong", {}, "Review before replacing the local running policy."),
        h("div", { class: "note" }, "Routine passive replication is automatic when enabled. This recovery action fetches the active peer running policy, validates it locally, and applies it through the normal durable policy path.")),
      h("dl", { class: "kv readiness-kv" },
        h("dt", {}, "Local role"), h("dd", {}, badge(ha.role || "unknown", "warn")),
        h("dt", {}, "Peer"), h("dd", { class: "mono" }, [ha.peerId || "", ha.peerAddress || ""].filter(Boolean).join(" / ") || "—"),
        h("dt", {}, "Local policy"), h("dd", { class: "mono" }, ha.runningPolicyVersion ? `v${ha.runningPolicyVersion}` : "—"),
        h("dt", {}, "Peer policy"), h("dd", { class: "mono" }, ha.sync?.peerVersion ? `v${ha.sync.peerVersion}` : "—")),
      h("label", { class: "field" },
        h("span", {}, "Audit comment"),
        comment),
      h("label", { class: "field inline-check" }, ackRisk, h("span", {}, "Acknowledge high-risk policy impact if reported")),
      h("label", { class: "field inline-check" }, ackRuntime, h("span", {}, "Acknowledge runtime readiness warnings if reported"))),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Cancel HA policy pull review", "aria-label": "Cancel HA policy pull review", dataset: { readinessAction: "ha-policy-pull-cancel" }, onclick: closeDrawer }, "Cancel"),
      applyBtn,
    ],
  });
  comment.focus?.();
}

function openHAFailoverActivationReview(ha = {}) {
  const fencingEvidence = ha.fencingEvidence || {};
  const comment = h("textarea", {
    class: "input",
    rows: 4,
    placeholder: "Audit comment",
    spellcheck: "true",
    dataset: { haFailoverField: "comment" },
  });
  const ackFailover = h("input", { type: "checkbox", dataset: { haFailoverAck: "failover" } });
  const ackCutover = h("input", { type: "checkbox", dataset: { haFailoverAck: "external-cutover" } });
  const ackFencing = h("input", { type: "checkbox", dataset: { haFailoverAck: "external-fencing" } });
  const applyBtn = h("button", {
    class: "btn primary",
    type: "button",
    title: "Submit audited passive-node activation",
    "aria-label": "Submit audited passive-node activation",
    dataset: { haFailoverSubmit: "activate" },
    onclick: () => submitHAFailoverActivation(comment, ackFailover, ackCutover, ackFencing, applyBtn),
  }, h("span", { html: icon("shield", 16) }), "Activate passive");
  openDrawer({
    title: "Activate passive node",
    subtitle: "Audited local HA role marker",
    width: "660px",
    body: h("div", { class: "support-bundle-preview" },
      h("div", { class: "alert-box warn" },
        h("strong", {}, "Review before marking this node active."),
        h("div", { class: "note" }, "This records durable local control-plane HA state only. Configured VIP/route promotion can record local GARP and neighbor-table evidence, but peer fencing, traffic path proof, and connection-state sync remain external unless provider evidence is returned.")),
      h("dl", { class: "kv readiness-kv" },
        h("dt", {}, "Local role"), h("dd", {}, badge(ha.role || "unknown", "warn")),
        h("dt", {}, "Peer"), h("dd", { class: "mono" }, [ha.peerId || "", ha.peerAddress || ""].filter(Boolean).join(" / ") || "—"),
        h("dt", {}, "Running policy"), h("dd", { class: "mono" }, ha.runningPolicyVersion ? `v${ha.runningPolicyVersion}` : "—"),
        h("dt", {}, "Last known good"), h("dd", { class: "mono" }, ha.lastKnownGoodVersion ? `v${ha.lastKnownGoodVersion}` : "—"),
        h("dt", {}, "Fencing evidence"), h("dd", {}, badge(fencingEvidence.state || "not_recorded", haFencingEvidenceClass(fencingEvidence))),
        h("dt", {}, "Failover"), h("dd", {}, badge(ha.failover?.eligible ? "eligible" : (ha.failover?.state || "blocked"), ha.failover?.eligible ? "ok" : "warn"))),
      h("div", { class: "alert-box " + readinessBoxClass(haFencingEvidenceClass(fencingEvidence)) },
        h("strong", {}, "Peer fencing is evidence-only in this workflow."),
        h("div", { class: "note" }, fencingEvidence.detail || "This activation request records local HA state. It does not execute destructive peer fencing.")),
      h("label", { class: "field" },
        h("span", {}, "Audit comment"),
        comment),
      h("label", { class: "field inline-check" }, ackFailover, h("span", {}, "Acknowledge marking this passive node active")),
      h("label", { class: "field inline-check" }, ackCutover, h("span", {}, "Acknowledge traffic cutover and neighbor convergence require separate verification")),
      h("label", { class: "field inline-check" }, ackFencing, h("span", {}, "Acknowledge peer fencing is external"))),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Cancel HA failover activation review", "aria-label": "Cancel HA failover activation review", dataset: { readinessAction: "ha-failover-cancel" }, onclick: closeDrawer }, "Cancel"),
      applyBtn,
    ],
  });
  comment.focus?.();
}

async function submitHAPolicyPull(comment, ackRisk, ackRuntime, button) {
  const message = String(comment?.value || "").trim();
  if (!message) {
    toast("Audit comment required", "Enter why this passive node is pulling the active peer policy.", "warn");
    comment?.focus?.();
    return;
  }
  button.disabled = true;
  mount(button, "Pulling...");
  try {
    const resp = await api.pullHighAvailabilityPolicy({
      comment: message,
      ackPull: true,
      ackRisk: Boolean(ackRisk?.checked),
      ackRuntime: Boolean(ackRuntime?.checked),
    });
    closeDrawer();
    toast("HA policy pulled", resp.detail || `Applied peer policy as v${resp.version || "new"}.`, "ok");
    setTimeout(() => location.reload(), 800);
  } catch (err) {
    button.disabled = false;
    mount(button, h("span", { html: icon("download", 16) }), "Pull policy");
    toast("HA policy pull failed", err.message || String(err), "bad");
  }
}

async function submitHAFailoverActivation(comment, ackFailover, ackCutover, ackFencing, button) {
  const message = String(comment?.value || "").trim();
  if (!message) {
    toast("Audit comment required", "Enter why this passive node is being marked active.", "warn");
    comment?.focus?.();
    return;
  }
  if (!ackFailover?.checked || !ackCutover?.checked || !ackFencing?.checked) {
    toast("Acknowledgements required", "Confirm local activation, external traffic cutover, and external peer fencing before continuing.", "warn");
    return;
  }
  button.disabled = true;
  mount(button, "Activating...");
  try {
    const resp = await api.activateHighAvailabilityFailover({
      comment: message,
      ackFailover: true,
      ackExternalCutover: true,
      ackExternalFencing: true,
    });
    closeDrawer();
    toast("HA node activated", resp.detail || "Local HA role was marked active. External cutover and fencing remain operator-controlled.", "ok");
    setTimeout(() => location.reload(), 800);
  } catch (err) {
    button.disabled = false;
    mount(button, h("span", { html: icon("shield", 16) }), "Activate passive");
    toast("HA activation failed", err.message || String(err), "bad");
  }
}

function shortEvidenceHash(value = "") {
  const text = String(value || "");
  if (text.length <= 16) return text;
  return text.slice(0, 16);
}

function ebpfReadinessCard(ebpf = {}, drillEvidence = buildEbpfDrillEvidencePacket({ ebpfHost: ebpf })) {
  const probes = Array.isArray(ebpf.probes) ? ebpf.probes : [];
  const attachProbes = Array.isArray(ebpf.attachProbes) ? ebpf.attachProbes : [];
  const attachments = Array.isArray(ebpf.attachments) ? ebpf.attachments : [];
  const artifacts = Array.isArray(ebpf.artifacts) ? ebpf.artifacts : [];
  const hooks = Array.isArray(ebpf.supportedHooks) && ebpf.supportedHooks.length ? ebpf.supportedHooks.join(", ") : "—";
  const blockers = Array.isArray(ebpf.blockers) ? ebpf.blockers : [];
  return card(h("h2", {}, "XDP/tc readiness", h("span", { class: "spacer" }), badge(ebpf.state || "unknown", capabilityClass(ebpf.state))),
    h("div", { class: "alert-box " + readinessBoxClass(ebpf.state === "ready" ? "ok" : ebpf.state === "degraded" ? "warn" : "info") },
      h("strong", {}, ebpf.state === "ready" ? "eBPF host prerequisites are ready." : "eBPF milestone evidence needs review."),
      h("div", { class: "note" }, ebpf.detail || "XDP/tc readiness was not returned by the system API.")),
    h("dl", { class: "kv readiness-kv" },
      h("dt", {}, "Host"), h("dd", {}, badge(ebpf.state || "unknown", capabilityClass(ebpf.state))),
      h("dt", {}, "Attach"), h("dd", {}, badge(ebpf.attachState || "unknown", capabilityClass(ebpf.attachState))),
      h("dt", {}, "Renderer"), h("dd", {}, badge(ebpf.rendererState || "unknown", capabilityClass(ebpf.rendererState))),
      h("dt", {}, "Hooks"), h("dd", { class: "mono" }, hooks),
      h("dt", {}, "Evidence scope"), h("dd", { class: "mono" }, ebpf.evidenceScope || "—"),
      h("dt", {}, "Collected"), h("dd", { class: "mono" }, ebpf.evidenceCollectedAt || "—")),
    h("div", { class: "row-actions readiness-ebpf-actions" },
      h("button", {
        class: "btn sm ghost",
        type: "button",
        title: "Open eBPF drill handoff",
        "aria-label": "Open eBPF drill handoff",
        dataset: { readinessEbpfEvidenceAction: "drill-handoff" },
        onclick: () => openRoutedEbpfDrillEvidencePacket(drillEvidence),
      }, h("span", { html: icon("terminal", 15) }), "Drill handoff"),
      h("a", {
        class: "btn sm ghost",
        href: "#/readiness?packet=ebpf-ol9-field-evidence",
        title: "Open eBPF OL9 field evidence",
        "aria-label": "Open eBPF OL9 field evidence",
        dataset: { readinessEbpfEvidenceAction: "field-evidence" },
      }, h("span", { html: icon("shield", 15) }), "Field evidence"),
	      h("button", {
	        class: "btn sm ghost",
	        type: "button",
	        title: "Copy eBPF drill handoff",
	        "aria-label": "Copy eBPF drill handoff",
	        dataset: { readinessEbpfEvidenceAction: "copy-drill" },
	        onclick: () => copyEbpfDrillEvidencePacket(drillEvidence.text || ebpfDrillEvidencePacketReport(drillEvidence)),
	      }, h("span", { html: icon("copy", 15) }), "Copy drill")),
    blockers.length ? h("div", { class: "release-acceptance-problem-list readiness-ebpf-blockers" },
      blockers.slice(0, 5).map((blocker) => h("span", {}, blocker)),
      blockers.length > 5 ? h("span", {}, `${blockers.length - 5} more blocker(s)`) : null) : null,
    ebpfProbeTable(probes, attachProbes),
    attachments.length ? ebpfAttachmentTable(attachments) : null,
    artifacts.length ? ebpfArtifactTable(artifacts) : null);
}

function ebpfProbeTable(probes = [], attachProbes = []) {
  const rows = [
    ...probes.slice(0, 8).map((probe) => ebpfProbeRow(probe, "host")),
    ...attachProbes.slice(0, 8).map((probe) => ebpfProbeRow(probe, "attach")),
  ];
  if (!rows.length) return emptyState("settings", "No eBPF probes", "Status has not returned host or attach probe evidence.");
  return h("div", { class: "table-wrap flat readiness-ebpf-table-wrap", dataset: { readinessEbpfTable: "probes" } },
    responsiveTable(["Scope", "Probe", "Key", "State", "Detail"], rows, { className: "readiness-ebpf-probe-table" }));
}

function ebpfProbeRow(probe = {}, scope = "host") {
  const key = probe.key || "—";
  return h("tr", { dataset: { readinessEbpfProbe: key, readinessEbpfScope: scope } },
    labeledCell("Scope", {}, scope === "attach" ? "Attach" : "Host"),
    labeledCell("Probe", {}, probe.name || "eBPF probe"),
    labeledCell("Key", { class: "mono" }, key),
    labeledCell("State", {}, badge(probe.state || "unknown", capabilityClass(probe.state))),
    labeledCell("Detail", { class: "muted" }, probe.detail || "No detail returned."));
}

function ebpfAttachmentTable(attachments = []) {
  return h("div", { class: "table-wrap flat readiness-ebpf-table-wrap", dataset: { readinessEbpfTable: "attachments" } },
    responsiveTable(["Interface / hook", "Program", "State", "Detail"], attachments.slice(0, 6).map(ebpfAttachmentRow), { className: "readiness-ebpf-attachment-table" }));
}

function ebpfAttachmentRow(attachment = {}) {
  const title = [attachment.interface || attachment.interface_ || "", attachment.hook || ""].filter(Boolean).join(" / ") || "Attachment";
  const program = [attachment.programName || attachment.program_name || "", attachment.programId || attachment.program_id || ""].filter(Boolean).join(" #") || "—";
  return h("tr", { dataset: { readinessEbpfAttachment: title } },
    labeledCell("Interface / hook", {}, title),
    labeledCell("Program", { class: "mono" }, program),
    labeledCell("State", {}, badge(attachment.state || "unknown", capabilityClass(attachment.state))),
    labeledCell("Detail", { class: "muted" }, attachment.detail || attachment.pinnedPath || attachment.pinned_path || "No attachment detail returned."));
}

function ebpfArtifactTable(artifacts = []) {
  return h("div", { class: "table-wrap flat readiness-ebpf-table-wrap", dataset: { readinessEbpfTable: "artifacts" } },
    responsiveTable(["Artifact", "Path", "State", "Digest"], artifacts.slice(0, 6).map(ebpfArtifactRow), { className: "readiness-ebpf-artifact-table" }));
}

function ebpfArtifactRow(artifact = {}) {
  return h("tr", { dataset: { readinessEbpfArtifact: artifact.name || "eBPF artifact" } },
    labeledCell("Artifact", {}, artifact.name || "eBPF artifact"),
    labeledCell("Path", { class: "mono" }, artifact.path || "—"),
    labeledCell("State", {}, badge(artifact.state || "unknown", capabilityClass(artifact.state))),
    labeledCell("Digest", { class: "mono" }, shortEvidenceHash(artifact.sha256 || "") || artifact.detail || "No digest returned."));
}

function kernelTuningCard(tuning, status) {
  const baseline = hostTuningActionState(status, "appliance");
  const throughput = hostTuningActionState(status, "throughput");
  return card(h("h2", {}, "Host tuning", h("span", { class: "spacer" }), badge(tuning.readinessLabel, tuning.cls)),
    tuningCommandRow(tuning.needsAction ? "Repair command" : "Baseline command", tuning.remediationCommand),
    tuningCommandRow("Throughput profile", tuning.throughputCommand, tuning.throughputDetail),
    h("div", { class: "tuning-actions" },
	      h("button", { class: "btn primary", type: "button", title: baseline.reviewTitle, "aria-label": baseline.reviewTitle, dataset: { readinessAction: "review-host-baseline" }, onclick: () => reviewHostTuning("appliance", status) },
	        h("span", { html: icon("check", 16) }), tuning.needsAction ? "Review baseline" : "Review baseline"),
	      h("button", { class: "btn", type: "button", title: throughput.reviewTitle, "aria-label": throughput.reviewTitle, dataset: { readinessAction: "review-host-throughput" }, onclick: () => reviewHostTuning("throughput", status) },
	        h("span", { html: icon("traffic", 16) }), "Review throughput profile")),
    baseline.applyDisabled ? h("div", { class: "note", style: { margin: "-4px 0 12px" } }, baseline.disabledReason) : null,
    h("div", { class: "alert-box " + readinessBoxClass(tuning.needsAction ? "warn" : tuning.cls) },
      h("strong", {}, tuning.needsAction ? "Host sysctls need attention." : "Host sysctl baseline"),
      h("div", { class: "note" }, tuning.detail || "Kernel forwarding tuning status is not available.")),
    h("dl", { class: "kv readiness-kv tuning-kv" },
      h("dt", {}, "Persistent profile"), h("dd", { class: "mono" }, tuning.configPath || "—"),
      h("dt", {}, "Throughput headroom"), h("dd", {}, badge(tuning.throughputLabel, tuning.throughputCls)),
      h("dt", {}, "Checks"), h("dd", {}, `${tuning.readyCount}/${tuning.totalCount || 0} ready`),
      h("dt", {}, "Degraded"), h("dd", {}, String(tuning.degradedCount)),
      h("dt", {}, "Unknown"), h("dd", {}, String(tuning.unknownCount))),
    tuning.checks.length ? h("div", { class: "tuning-checks" }, tuning.checks.map((check) => tuningCheckRow(check))) :
      emptyState("settings", "No kernel checks", "Status has not returned per-sysctl evidence for this host."));
}

export function hostTuningActionState(status = {}, profile = "appliance") {
  const normalized = profile === "throughput" ? "throughput" : "appliance";
  const dryRun = Boolean(status.runtime?.dryRun);
  const label = normalized === "throughput" ? "throughput profile" : "host baseline";
  const applyLabel = normalized === "throughput" ? "Apply throughput" : "Apply baseline";
  const dryRunReason = "Live host changes are disabled while controld is running in dry-run mode. Preview the profile here, then apply it from an enforcing Linux host or with ngfwctl system tune.";
  return {
    profile: normalized,
    label,
    reviewTitle: dryRun ? "Preview only; dry-run mode cannot write or apply host sysctls." : "Preview the sysctl profile before applying live host changes.",
    applyLabel,
    previewBody: { profile: normalized },
    mutationBody: { profile: normalized, write: true, apply: true, ackHostChange: true },
    applyDisabled: dryRun,
    disabledReason: dryRun ? dryRunReason : "",
  };
}

async function reviewHostTuning(profile, status) {
  const action = hostTuningActionState(status, profile);
  try {
    const resp = await api.tuneHost(action.previewBody);
    toast("Host tuning preview ready", `${action.label} changes are staged for review only.`, "ok");
    openTuneResult(resp, { action, preview: true });
  } catch (e) {
    toast("Host tuning preview failed", e.message, "bad");
  }
}

async function confirmAndApplyHostTuning(action) {
  const ok = await confirmDialog({
    title: "Apply " + action.label + "?",
    message: action.profile === "throughput"
      ? "This writes the high-bandwidth sysctl profile and applies live kernel values on the firewall host."
      : "This writes the appliance sysctl baseline and applies live kernel values on the firewall host.",
    confirmLabel: action.applyLabel,
  });
  if (!ok) return;
  try {
    const resp = await api.tuneHost(action.mutationBody);
    toast("Host tuning applied", `${resp.profile || action.profile} profile applied. Refresh readiness to verify live values.`, "ok");
    openTuneResult(resp, { action: { ...action, applyDisabled: true }, preview: false });
  } catch (e) {
    toast("Host tuning failed", e.message, "bad");
  }
}

function openTuneResult(resp = {}, opts = {}) {
  const results = Array.isArray(resp.results) ? resp.results : [];
  const action = opts.action || hostTuningActionState({}, resp.profile || "appliance");
  const profile = resp.profile || action.profile || "appliance";
  const canApply = opts.preview && !action.applyDisabled;
  openDrawer({
    title: opts.preview ? "Host tuning preview" : "Host tuning result",
    subtitle: `${profile} profile · ${resp.sysctlConfigPath || "sysctl config"}`,
    width: "720px",
    body: h("div", {},
      h("div", { class: "preflight-summary" },
        h("div", {}, h("span", {}, "Config"), h("strong", {}, resp.wroteConfig ? "written" : "preview")),
        h("div", {}, h("span", {}, "Live apply"), h("strong", {}, resp.appliedLive ? "applied" : "not applied")),
        h("div", {}, h("span", {}, "Profile"), h("strong", {}, profile)),
        h("div", {}, h("span", {}, "Results"), h("strong", {}, String(results.length)))),
      opts.preview ? h("div", { class: "alert-box " + (canApply ? "info" : "warn") },
        h("strong", {}, canApply ? "Review before applying live host changes." : "Preview only on this runtime."),
        h("div", { class: "note" }, canApply
          ? "No host files or live kernel values have been changed yet. Apply from this drawer when the planned values match the operator intent."
          : action.disabledReason || "This runtime cannot apply live host changes.")) : null,
      results.length ? h("div", { class: "table-wrap flat" },
        responsiveTable(["Key", "Value", "State", "Detail"], results.map((item) =>
          h("tr", { dataset: { readinessTuneResult: item.key || "" } },
            labeledCell("Key", { class: "mono" }, item.key || "—"),
            labeledCell("Value", { class: "mono" }, item.value || "—"),
            labeledCell("State", {}, badge(item.state || "unknown", tuneResultClass(item.state))),
            labeledCell("Detail", { class: "muted" }, item.detail || "—"))), { className: "readiness-tune-result-table" })) :
        emptyState("settings", "No tune results", "The API returned no per-sysctl result rows.")),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close host tuning preview", "aria-label": "Close host tuning preview", dataset: { readinessTuneAction: "close" }, onclick: closeDrawer }, "Close"),
      canApply ? h("button", { class: "btn primary", type: "button", title: `${action.applyLabel} host tuning profile`, "aria-label": `${action.applyLabel} host tuning profile`, dataset: { readinessTuneAction: "apply" }, onclick: () => confirmAndApplyHostTuning(action) },
        h("span", { html: icon("check", 16) }), action.applyLabel) : null,
      h("button", { class: "btn primary", type: "button", title: "Refresh readiness after host tuning", "aria-label": "Refresh readiness after host tuning", dataset: { readinessTuneAction: "refresh-readiness" }, onclick: () => { closeDrawer(); location.reload(); } },
        h("span", { html: icon("refresh", 16) }), "Refresh readiness"),
    ],
  });
}

function tuneResultClass(state) {
  if (state === "applied") return "ok";
  if (state === "skipped" || state === "planned") return "warn";
  return "neutral";
}

function tuningCommandRow(label, command, detail = "") {
  return h("div", { class: "tuning-command" },
    h("div", {},
      h("strong", {}, label),
      h("code", {}, command),
      detail ? h("div", { class: "note" }, detail) : null),
    readinessCommandCopyButton(label, command, {
      ariaLabel: `Copy ${label.toLowerCase()} host tuning command`,
      dataset: { readinessTuningCommandCopy: label.toLowerCase().replace(/\s+/g, "-") },
    }));
}

function readinessCommandCopyButton(label, command, attrs = {}) {
  const normalizedLabel = String(label || "command").trim() || "command";
  const copyLabel = attrs.ariaLabel || `Copy ${normalizedLabel.toLowerCase()} command`;
  const { ariaLabel: _ariaLabel, ...buttonAttrs } = attrs;
  return h("button", {
    class: "icon-btn",
    type: "button",
    title: copyLabel,
    "aria-label": copyLabel,
    dataset: { readinessCommandAction: "copy", readinessCommandLabel: normalizedLabel },
    onclick: () => copyCommand(command),
    html: icon("copy", 16),
    ...buttonAttrs,
  });
}

function tuningCheckRow(check) {
  return h("div", { class: "tuning-check " + check.cls },
    h("div", { class: "tuning-check-main" },
      h("strong", { class: "mono" }, check.key || check.name),
      h("span", {}, check.name)),
    h("div", { class: "tuning-values" },
      h("span", {}, "current", h("code", {}, check.current || "—")),
      h("span", {}, "recommended", h("code", {}, check.recommended || "—"))),
    h("div", { class: "tuning-state" }, badge(check.state || "unknown", check.cls)),
    check.detail ? h("div", { class: "note tuning-detail" }, check.detail) : null);
}

async function copyCommand(command) {
  try {
    const safeCommand = redactReadinessDisclosureText(command);
    await navigator.clipboard.writeText(safeCommand);
    toast("Command copied", safeCommand, "ok");
  } catch {
    toast("Copy failed", "Select and copy the command manually.", "warn");
  }
}

function readinessDisclosureValue(value) {
  return oneLine(redactReadinessDisclosureText(value));
}

export function redactReadinessDisclosureText(value = "") {
  return redactReadinessSecretPairs(redactReadinessServerLocalPaths(redactReadinessURLs(String(value ?? ""))));
}

function redactReadinessServerLocalPaths(value = "") {
  return String(value).replace(
    /(^|[\s"'({=,;])\/(?:var\/lib|var\/log(?:\/openngfw)?|etc\/(?:openngfw|phragma)|tmp|private\/tmp|var\/folders|private\/var\/folders|home\/[^'"\s,;}]+|Users\/[^'"\s,;}]+|opt\/[^'"\s,;}]+|data\/[^'"\s,;}]+)[^'"\s,;}]*/gi,
    "$1[server-local path redacted]",
  );
}

function redactReadinessSecretPairs(value = "") {
  return String(value)
    .replace(/(Authorization:\s*Bearer\s+)(?!\[redacted\])["']?[^"'\s,;}]+["']?/gi, "$1[redacted]")
    .replace(/\bBearer\s+(?!\[redacted\])[A-Za-z0-9._~+/-]{8,}/gi, "Bearer [redacted]")
    .replace(/(^|[?&\s"',;])(-{0,2}(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|passwd|secret|client[_-]?secret|api[_-]?key|api[_-]?access[_-]?key|access[_-]?key|cookie)=)[^&\s"',;]+/gi, "$1$2[redacted]")
    .replace(/(^|[\s"',;{])(-{0,2}(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|passwd|secret|client[_-]?secret|api[_-]?key|api[_-]?access[_-]?key|access[_-]?key|cookie)\s*:\s*)[^\s"',;]+/gi, "$1$2[redacted]");
}

function redactReadinessURLs(value = "") {
  return String(value).replace(/https?:\/\/[^\s"'<>]+/gi, (raw) => redactReadinessURL(raw));
}

function redactReadinessURL(raw) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return raw;
  }
  if (!["http:", "https:"].includes(parsed.protocol) || !parsed.host) return raw;
  if (parsed.username) parsed.username = "[redacted]";
  if (parsed.password) parsed.password = "[redacted]";
  for (const key of Array.from(parsed.searchParams.keys())) {
    if (readinessSensitiveKey(key)) parsed.searchParams.set(key, "[redacted]");
  }
  return parsed.toString();
}

function readinessSensitiveKey(key = "") {
  const normalized = String(key || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  return normalized.includes("token") ||
    normalized.includes("password") ||
    normalized.includes("passwd") ||
    normalized.includes("secret") ||
    normalized.includes("apikey") ||
    normalized.includes("accesskey") ||
    normalized.includes("cookie") ||
    normalized.includes("authorization");
}

function conntrackLabel(conntrack) {
  if (!conntrack.maxEntries) return conntrack.state || "unknown";
  return `${conntrack.state} · ${conntrack.usagePercent.toFixed(1)}%`;
}

function hostLoadLabel(host) {
  const load = Number(host?.load1 || 0);
  const perCPU = Number(host?.load1PerCpu || 0);
  if (!load && !perCPU) return "—";
  return `${load.toFixed(2)} / ${Number(host?.load5 || 0).toFixed(2)} / ${Number(host?.load15 || 0).toFixed(2)} (${perCPU.toFixed(2)}/CPU)`;
}

function hostMemoryLabel(host) {
  const total = fmt.num(host?.memoryTotalBytes);
  const available = fmt.num(host?.memoryAvailableBytes);
  if (!total) return "—";
  const used = Math.max(0, total - available);
  return `${Number(host?.memoryUsedPercent || 0).toFixed(1)}% used · ${fmt.bytes(used)} / ${fmt.bytes(total)}`;
}

function hostInterfaceSummary(host) {
  const interfaces = Array.isArray(host?.interfaces) ? host.interfaces : [];
  if (!interfaces.length) return "none";
  const degraded = interfaces.filter((iface) => iface.state && iface.state !== "ready");
  if (!degraded.length) return `${interfaces.length} clean`;
  return degraded.slice(0, 3).map((iface) => {
    const drops = fmt.num(iface.rxDrops) + fmt.num(iface.txDrops);
    const errors = fmt.num(iface.rxErrors) + fmt.num(iface.txErrors);
    return `${iface.name}: ${errors} err / ${drops} drop`;
  }).join(", ");
}

function engineCard(engines) {
  return card(h("h2", {}, "Engine prerequisites"),
    engines.length ? h("div", { class: "table-wrap flat" },
      responsiveTable(ENGINE_READINESS_COLUMNS, engines.map((e) =>
        h("tr", { dataset: { readinessEngineRow: e.name || "engine" } },
          engineReadinessRowModel(e).map(engineCell))), { className: "engine-readiness readiness-engine-table" })) :
      emptyState("settings", "No engines", "controld did not return managed engine status."));
}

function degradedEngineEvidenceCard(model = {}) {
  const rows = Array.isArray(model.rows) ? model.rows : [];
  return card(h("h2", {}, "Engine degradation impact", h("span", { class: "spacer" }), badge(model.label || model.state || "unknown", model.cls || "neutral")),
    h("div", { class: "alert-box " + readinessBoxClass(model.cls || "info"), dataset: { readinessEngineEvidence: model.state || "unknown" } },
      h("strong", {}, model.degradedRows?.length ? "Runtime engine degradation affects policy posture." : "No required engine degradation reported."),
      h("div", { class: "note" }, model.detail || "Status did not return degraded-engine evidence.")),
    rows.length ? h("div", { class: "table-wrap flat" },
      responsiveTable(["Engine", "Required", "State", "Impact"], rows.map((row) =>
        h("tr", { dataset: { readinessEngineEvidenceRow: row.name || "engine" } },
          labeledCell("Engine", { class: "mono" }, row.name || "engine"),
          labeledCell("Required", {}, row.required ? badge("yes", row.degraded ? row.tone : "ok") : badge("no", "neutral")),
          labeledCell("State", {}, badge(row.state || "unknown", row.tone || "neutral")),
          labeledCell("Impact", { class: "muted" }, row.impact || "No impact detail returned."))), { className: "readiness-engine-evidence-table responsive-evidence" })) : null,
    h("div", { class: "release-acceptance-problem-list", style: { marginTop: "12px" } },
      (model.impact || []).slice(0, 5).map((item) => h("span", {}, item))),
    h("div", { class: "note" }, (model.limitations || []).join(" ")));
}

export function engineReadinessRowModel(engine = {}) {
  return [
    { label: "Engine", text: engine.name || "—", className: "mono" },
    { label: "State", badge: engine.state || "unknown", tone: engineClass(engine) },
    { label: "Mode", badge: engine.mode || "unknown", tone: engine.mode === "dry-run" ? "warn" : "neutral" },
    { label: "Role", text: engine.role || "—" },
    { label: "Detail", text: engine.detail || "—", className: "muted" },
  ];
}

function engineCell(cell) {
  const attrs = {};
  if (cell.className) attrs.class = cell.className;
  return labeledCell(cell.label, attrs, cell.badge ? badge(cell.badge, cell.tone) : cell.text);
}

function policyDataplaneCard(posture, policy, version, flowCap, flowRuntime, ebpfHost, inspection) {
  const capState = flowCap.state || "unknown";
  const capDetail = flowCap.detail || "Runtime flowtable capability is not available.";
  const runtimeState = flowRuntime.state || "unknown";
  const runtimeDetail = flowRuntime.detail || "Runtime flowtable evidence is not available.";
  const capWarn = posture.accelerated && capState !== "ready" && capState !== "active";
  const runtimeWarn = posture.accelerated && runtimeState !== "active";
  const ebpfBlocksCurrent = dataplaneNameRequiresEbpf(posture.baseDataplane) && !ebpfHost.ready;
  const runtimeFacts = [
    flowRuntime.devices?.length ? `devices: ${flowRuntime.devices.join(", ")}` : "",
    flowRuntime.packets || flowRuntime.bytes ? `hits: ${flowRuntime.packets} packets / ${fmt.bytes(flowRuntime.bytes)}` : "",
    flowRuntime.flowtableDeclared ? "flowtable declared" : "",
    flowRuntime.offloadRulePresent ? "offload rule present" : "",
  ].filter(Boolean).join(" · ");
  const ebpfMissing = (ebpfHost.degraded || []).slice(0, 4).map((p) => p.name).join(", ");
  const trafficControl = trafficControlPosture(policy);
  return card(h("h2", {}, "Running policy dataplane", h("span", { class: "spacer" }), badge(posture.label, posture.cls)),
    h("dl", { class: "kv readiness-kv" },
      h("dt", {}, "Policy"), h("dd", { class: "mono" }, "v" + (version || 0)),
      h("dt", {}, "Base dataplane"), h("dd", { class: "mono" }, posture.baseDataplane || "—"),
      h("dt", {}, "Throughput path"), h("dd", {}, badge(posture.label, posture.cls)),
      h("dt", {}, "Inspection"), h("dd", {}, idsModeLabel(policy)),
      h("dt", {}, "Inspection readiness"), h("dd", {}, badge(inspection.label, inspection.cls)),
      h("dt", {}, "Inspection engine"), h("dd", { class: "mono" }, inspection.engineLabel || "—"),
      h("dt", {}, "Failure behavior"), h("dd", { class: "mono" }, failureBehaviorLabel(inspection.failureBehavior)),
      h("dt", {}, "eBPF host readiness"), h("dd", {}, badge(ebpfHost.state || "unknown", capabilityClass(ebpfHost.state))),
      h("dt", {}, "Fast-path interfaces"), h("dd", { class: "mono" }, posture.devices.length ? posture.devices.join(", ") : "none"),
      h("dt", {}, "Host flowtable readiness"), h("dd", {}, badge(capState, capabilityClass(capState))),
      h("dt", {}, "Runtime flowtable evidence"), h("dd", {}, badge(runtimeState, capabilityClass(runtimeState))),
      h("dt", {}, "Runtime proof"), h("dd", { class: "mono" }, runtimeFacts || "none"),
      h("dt", {}, "eBPF missing"), h("dd", { class: "mono" }, ebpfMissing || "none"),
      h("dt", {}, "Traffic control intent"), h("dd", {}, badge(trafficControl.label, trafficControl.cls)),
      h("dt", {}, "QoS / zone protection"), h("dd", { class: "mono" }, trafficControl.detail)),
    h("div", { class: "alert-box " + readinessBoxClass(inspection.cls === "bad" ? "bad" : ebpfBlocksCurrent ? "bad" : (inspection.cls === "warn" || capWarn || runtimeWarn) ? "warn" : posture.cls) },
      h("strong", {}, inspection.ready ? posture.summary : inspection.detail),
      h("div", { class: "note" }, inspection.bypassPossible && inspection.bypassReason ? inspection.bypassReason :
        inspection.degradedBehavior || (ebpfBlocksCurrent ? ebpfHost.detail : capWarn ? capDetail : runtimeWarn ? runtimeDetail : posture.detail))));
}

function trafficControlPosture(policy = {}) {
  const qosRefs = (policy.rules || []).filter((rule) => rule?.qosProfile).length;
  const zoneRefs = (policy.zones || []).filter((zone) => zone?.zoneProtectionProfile).length;
  if (!qosRefs && !zoneRefs) {
    return { label: "none", cls: "neutral", detail: "no QoS or zone-protection profiles attached" };
  }
  return {
    label: "planned only",
    cls: "warn",
    detail: `${qosRefs} QoS rule attachment${qosRefs === 1 ? "" : "s"}; ${zoneRefs} zone-protection attachment${zoneRefs === 1 ? "" : "s"}; live tc/nft proof unsupported in this slice`,
  };
}

export function proxyGatewayPosture(policy = {}) {
  const proxy = policy.proxy || {};
  const services = Array.isArray(proxy.virtualServices) ? proxy.virtualServices : [];
  const wafs = Array.isArray(proxy.wafPolicies) ? proxy.wafPolicies : [];
  const enabled = services.filter((service) => service?.enabled !== false);
  const routes = services.flatMap((service) => (Array.isArray(service?.routes) ? service.routes : []).map((route) => ({ service, route })));
  const wafNames = new Set(wafs.map((waf) => waf?.name).filter(Boolean));
  const runtimeReadinessArtifacts = [
    "bounded daemon/listener/cutover/rollback proof artifacts are modeled as planned-not-executed runtime-readiness evidence",
  ];
  const blockers = [
    "Active Envoy/Coraza listener execution remains hardening.",
    "Traffic cutover execution remains hardening.",
    "TLS private-key custody is external to policy.",
    "HA traffic proof for proxy listeners is not recorded.",
  ];
  for (const waf of wafs) {
    const ruleSets = Array.isArray(waf?.ruleSets) ? waf.ruleSets : [];
    if (!ruleSets.length) blockers.push(`WAF ${waf?.name || "unnamed"} has no ruleset provenance.`);
    if (!waf?.redactRequestBody) blockers.push(`WAF ${waf?.name || "unnamed"} does not declare request body redaction.`);
  }
  for (const { service, route } of routes) {
    if (route?.wafPolicy && !wafNames.has(route.wafPolicy)) blockers.push(`Route ${service?.name || "service"}/${route?.name || "route"} references missing WAF ${route.wafPolicy}.`);
    if (!route?.requireMtlsToBackend) blockers.push(`Route ${service?.name || "service"}/${route?.name || "route"} lacks backend mTLS intent.`);
  }
  const hasPolicy = services.length > 0 || wafs.length > 0;
  const cls = !hasPolicy ? "info" : blockers.length > 3 ? "bad" : "warn";
  return {
    cls,
    label: !hasPolicy ? "not configured" : "planned",
    hasPolicy,
    services,
    wafs,
    routes,
    enabledCount: enabled.length,
    runtimeReadinessArtifacts,
    blockers,
    detail: hasPolicy
      ? `${enabled.length}/${services.length} virtual services enabled, ${wafs.length} WAF policies, ${routes.length} route(s).`
      : "No L7 virtual-service or WAF policy is declared in the running policy.",
  };
}

function proxyGatewayCard(posture = {}) {
  const routeRows = posture.routes.slice(0, 6).map(({ service, route }) => {
    const backendCount = Array.isArray(route.backends) ? route.backends.length : 0;
    return [
      service?.name || "service",
      route?.pathPrefix || "/",
      route?.wafPolicy || "none",
      route?.requireMtlsToBackend ? badge("mTLS", "ok") : badge("missing", "bad"),
      String(backendCount),
    ];
  });
  const wafRows = posture.wafs.slice(0, 4).map((waf) => [
    waf.name || "waf",
    waf.mode || "unspecified",
    String(Array.isArray(waf.ruleSets) ? waf.ruleSets.length : 0),
    waf.redactRequestBody ? badge("redacted", "ok") : badge("not redacted", "bad"),
  ]);
  return card(h("h2", {}, "L7 proxy / WAF plan", h("span", { class: "spacer" }), badge(posture.label || "unknown", posture.cls || "info")),
    h("dl", { class: "kv readiness-kv" },
      h("dt", {}, "Virtual services"), h("dd", { class: "mono" }, String(posture.services?.length || 0)),
      h("dt", {}, "Enabled services"), h("dd", { class: "mono" }, String(posture.enabledCount || 0)),
      h("dt", {}, "WAF policies"), h("dd", { class: "mono" }, String(posture.wafs?.length || 0)),
      h("dt", {}, "Plan renderer"), h("dd", { class: "mono" }, posture.hasPolicy ? "proxy artifact (Envoy/Coraza style)" : "none")),
    h("div", { class: "alert-box " + readinessBoxClass(posture.cls || "info") },
      h("strong", {}, posture.hasPolicy ? "Proxy deployment is a planned configuration surface." : "No proxy policy configured."),
      h("div", { class: "note" }, posture.detail || "")),
    posture.hasPolicy && posture.runtimeReadinessArtifacts?.length ? h("div", { class: "note", style: { marginTop: "10px" } },
      "Runtime-readiness modeled: " + posture.runtimeReadinessArtifacts.join(" ")) : null,
    posture.hasPolicy ? h("div", { class: "grid cols-2", style: { marginTop: "12px" } },
      routeRows.length ? responsiveTable(["Service", "Path", "WAF", "Backend TLS", "Backends"], routeRows, { className: "proxy-route-table" }) : emptyState("route", "No routes", "Virtual services have no routes."),
      wafRows.length ? responsiveTable(["WAF", "Mode", "Rule sets", "Body"], wafRows, { className: "proxy-waf-table" }) : emptyState("shield", "No WAF policies", "Routes can still be planned without WAF attachment.")) : null,
    h("div", { class: "flex wrap", style: { marginTop: "10px" } },
      h("a", { class: "btn sm", href: "#/proxy", title: "Configure Proxy/WAF", "aria-label": "Configure Proxy/WAF", dataset: { readinessProxyAction: "configure-proxy-waf" } }, h("span", { html: icon("globe", 14) }), "Configure Proxy/WAF")),
    posture.hasPolicy ? h("div", { class: "note", style: { marginTop: "10px" } }, "Hardening tracked separately: " + posture.blockers.slice(0, 6).join(" ")) : null);
}

function failureBehaviorLabel(value) {
  if (value === "IDS_FAILURE_BEHAVIOR_FAIL_OPEN" || value === 1) return "fail-open";
  if (value === "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED" || value === 2) return "fail-closed";
  return "—";
}

function capabilityCard(capabilities) {
  return card(h("h2", {}, "Capability posture"),
    capabilities.length ? h("div", { class: "readiness-list" }, capabilities.map((c) =>
      h("div", { class: "readiness-row" },
        h("div", {},
          h("strong", {}, c.name || "Capability"),
          h("div", { class: "note" }, c.detail || "")),
        badge(c.state || "unknown", capabilityClass(c.state))))) :
      emptyState("inbox", "No capabilities", "Runtime capabilities are not available."));
}

function actionClass(level) {
  if (level === "high") return "bad";
  if (level === "medium") return "warn";
  return "info";
}

function engineClass(engine) {
  if (engine.state === "missing-prerequisites" || engine.state === "failed") return "bad";
  if (engine.state === "simulation" || engine.state === "restarting" || engine.mode === "dry-run") return "warn";
  if (engine.state === "ready" || engine.state === "active") return "ok";
  return "neutral";
}

function readinessBoxClass(cls) {
  if (cls === "bad" || cls === "warn" || cls === "ok" || cls === "info") return cls;
  return "";
}
