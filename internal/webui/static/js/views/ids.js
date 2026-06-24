// IDS/IPS configuration editor. Edits policy.ids and stages it to the
// candidate like every other change; committing starts/stops IDS/IPS engine.
// IDS/IPS engine produces both alerts (Threats) and flow records (Traffic),
// so enabling detect mode is what populates the telemetry views.

import { h, icon, clear } from "../core.js";
import { api } from "../api.js";
import { openAutomationContext } from "../automation_context.js";
import { throwIfAccessDenied } from "../auth_gate.js";
import { buildContentPosture } from "../content_posture.js";
import { currentInspectionPosture, degradedEngineEvidence, inspectionCoverageMap } from "../inspection_posture.js";
import { equal, session } from "../policy.js";
import { validationErrors } from "../validation_view.js";
import { pageHead, card, emptyState, openDrawer, closeDrawer, toast, pill, labeledCell, responsiveTable } from "../ui.js";

export async function render(ctx = {}) {
  const routePath = ctx.path || "/inspection";
  const root = h("div", {});
  const [sessionR, statusR, contentR] = await Promise.allSettled([
    session.load(),
    api.status(),
    api.contentPackages(),
  ]);
  throwIfAccessDenied(sessionR, statusR, contentR);
  if (sessionR.status === "rejected") {
    paintInspectionUnavailable(root, sessionR.reason, routePath);
    return root;
  }
  const status = statusR.status === "fulfilled" ? statusR.value || {} : {};
  const contentPackages = contentR.status === "fulfilled" ? contentR.value?.packages || [] : [];
  const contentError = contentR.status === "rejected" ? contentR.reason?.message || String(contentR.reason) : "";
  const contentPosture = buildContentPosture([], session.draft || {}, contentPackages, contentError);
  const threatSurface = contentPosture.surfaces.find((surface) => surface.kind === "threat-id") || null;
  const packageSummary = threatSurface ? {
    available: true,
    version: threatSurface.version || "",
    status: threatSurface.status || threatSurface.badge || "unknown",
    packageState: threatSurface.packageState || threatSurface.badge || "unknown",
    cls: threatSurface.cls || "warn",
    detail: threatSurface.detail || "",
    blockerCount: Array.isArray(threatSurface.blockers) ? threatSurface.blockers.length : 0,
  } : { available: false, blockerCount: 0, cls: "warn", detail: contentError || "Threat-ID package posture is unavailable." };
  root.appendChild(inspectionWorkspace({ status, packageSummary, contentError }));
  return root;
}

function paintInspectionUnavailable(root, err, routePath = "/inspection") {
  clear(root);
  root.appendChild(pageHead("Inspection", "IDS/IPS profile, Threat-ID package gates, runtime posture, and false-positive exceptions.",
    h("div", { class: "flex wrap" },
      h("button", { class: "btn", type: "button", title: "Retry loading inspection candidate session", "aria-label": "Retry loading inspection candidate session", dataset: { inspectionAction: "retry-load" }, onclick: () => renderAndReplaceInspection(root, routePath) },
        h("span", { html: icon("refresh", 16) }), "Retry"),
      h("button", { class: "btn", type: "button", title: "Open Inspection API and CLI context", "aria-label": "Open Inspection API and CLI context", dataset: { inspectionAction: "api-cli-context" }, onclick: () => openAutomationContext(routePath) },
        h("span", { html: icon("copy", 16) }), "API / CLI context"))));
  root.appendChild(h("div", { class: "alert-box bad", dataset: { inspectionLoadError: "true" } },
    h("strong", {}, "Candidate session unavailable. "),
    loadErrorDetail(err, "The candidate or running policy API did not return session data."),
    h("div", { class: "note" }, "The route shell remains available. Retry after the API is reachable, or use API / CLI context for equivalent inspection and candidate policy commands.")));
  root.appendChild(emptyState("shield", "Inspection data unavailable", "IDS/IPS profile, coverage, rollout, and exception state require the policy session API."));
}

async function renderAndReplaceInspection(root, routePath = "/inspection") {
  const current = await render({ path: routePath });
  root.replaceChildren(...Array.from(current.childNodes));
}

function loadErrorDetail(err, fallback = "The API request failed.") {
  return err?.message || String(err || fallback);
}

function inspectionWorkspace({ status = {}, packageSummary = null, contentError = "" } = {}) {
  const summary = idsProfileSummary(session.draft?.ids || {}, session.running?.ids || {}, packageSummary);
  const posture = currentInspectionPosture(status);
  const engineEvidence = degradedEngineEvidence(status, session.running || session.draft || {});
  const coverageMap = inspectionCoverageMap(session.draft || {}, status);
  const exceptions = normalizeExceptions(session.draft?.ids?.exceptions || []);
  const runningExceptions = normalizeExceptions(session.running?.ids?.exceptions || []);
  return h("div", { dataset: { inspectionWorkspace: "true" } },
    pageHead("Inspection", "IDS/IPS profile, Threat-ID package gates, runtime posture, and false-positive exceptions.",
      h("div", { class: "flex wrap" },
        h("button", { class: "btn primary", type: "button", title: "Edit IDS/IPS inspection profile", "aria-label": "Edit IDS/IPS inspection profile", dataset: { inspectionAction: "edit-profile" }, onclick: () => openIdsEditor(reloadInspectionRoute) },
          h("span", { html: icon("threats", 16) }), "Edit profile"),
        h("a", { class: "btn", href: "#/threats?view=exceptions", title: "Open threat events and exceptions", "aria-label": "Open threat events and exceptions", dataset: { inspectionAction: "open-threat-events" } }, h("span", { html: icon("threats", 16) }), "Threat events"),
        h("a", { class: "btn", href: "#/changes?tab=candidate", title: "Open candidate review", "aria-label": "Open candidate review", dataset: { inspectionAction: "open-candidate-review" } }, h("span", { html: icon("changes", 16) }), "Candidate review"))),
    h("div", { class: "grid cols-2", style: { marginBottom: "16px" } },
      inspectionProfileCard(summary, packageSummary),
      inspectionRuntimeCard(posture, status)),
    h("div", { style: { marginBottom: "16px" } },
      inspectionCoverageMapCard(coverageMap)),
    h("div", { style: { marginBottom: "16px" } },
      degradedEngineEvidenceCard(engineEvidence)),
    h("div", { style: { marginBottom: "16px" } },
      inspectionRolloutCard(packageSummary)),
    h("div", { class: "grid cols-2" },
      inspectionPackageCard(packageSummary, contentError),
      inspectionExceptionCard(exceptions, runningExceptions)));
}

function degradedEngineEvidenceCard(model = {}) {
  const rows = Array.isArray(model.rows) ? model.rows : [];
  return card(h("h2", {}, "Degraded engine evidence", h("span", { class: "spacer" }), pill(model.label || model.state || "unknown", model.cls || "neutral", true)),
    h("div", { class: "note" }, model.detail || "Runtime engine evidence is unavailable."),
    h("div", { class: "alert-box " + ((model.cls === "bad" || model.cls === "warn") ? model.cls : "info") },
      h("strong", {}, "Threat-ID impact"),
      h("div", { class: "note" }, (model.impact || []).slice(0, 3).join(" "))),
    rows.length ? h("div", { class: "table-wrap", style: { marginTop: "10px" } },
      responsiveTable(["Engine", "Required", "State", "Policy impact"], rows.map((row) =>
        h("tr", { dataset: { inspectionEngineEvidence: row.name || "engine" } },
          labeledCell("Engine", { class: "mono" }, row.name || "engine"),
          labeledCell("Required", row.required ? "yes" : "no"),
          labeledCell("State", pill(row.state || "unknown", row.tone || "neutral")),
          labeledCell("Policy impact", row.impact || "not reported"))), { className: "inspection-engine-evidence-table" })) : null,
    h("div", { class: "note" }, (model.limitations || []).join(" ")));
}

function inspectionCoverageMapCard(model = {}) {
  const buckets = Array.isArray(model.buckets) ? model.buckets : [];
  const panel = card(h("h2", {}, "Inspection coverage map", h("span", { class: "spacer" }), pill(model.summary?.label || "unknown", model.summary?.cls || "neutral", true)),
    h("div", { class: "note" }, model.summary?.detail || "Candidate rule coverage is unavailable."),
    h("div", { class: "automation-session-grid", style: { marginTop: "10px" } },
      h("div", {}, h("strong", {}, String(model.totalRules || 0)), h("span", {}, " candidate rules")),
      h("div", {}, h("strong", {}, String(model.activeAllowRules || 0)), h("span", {}, " active allow paths")),
      h("div", {}, h("strong", {}, String((model.riskCount || 0) + (model.warningCount || 0))), h("span", {}, " review items"))),
    model.runtimeBypass ? h("div", { class: "alert-box bad", style: { marginTop: "10px" } },
      h("strong", {}, "Runtime bypass risk"),
      h("div", { class: "note" }, model.runtimeDetail || "Runtime inspection posture reports bypass risk.")) : null,
    buckets.length ? h("div", { class: "table-wrap", style: { marginTop: "10px" } },
      responsiveTable(["Coverage", "Rules", "Examples", "Operator action"], buckets.map((bucket) => {
        const href = coverageBucketHref(bucket);
        return h("tr", { dataset: { inspectionCoverageBucket: bucket.state } },
          labeledCell("Coverage", pill(bucket.label, bucket.cls, true), h("div", { class: "note" }, bucket.detail)),
          labeledCell("Rules", String(bucket.count)),
          labeledCell("Examples", bucket.examples?.length ? bucket.examples.join(", ") : "none"),
          labeledCell("Operator action", href
            ? h("a", { class: "btn sm ghost", href, title: bucketActionTitle(bucket), "aria-label": bucketActionTitle(bucket), dataset: { inspectionAction: "coverage-bucket", inspectionCoverageState: bucket.state || "" } }, h("span", { html: icon(bucket.cls === "bad" ? "block" : "search", 14) }), bucketActionLabel(bucket))
            : h("span", { class: "muted" }, "No action needed")));
      }), { className: "inspection-coverage-table" })) : emptyState("shield", "No rules to map", "Create security rules to review IDS/IPS coverage."));
  panel.dataset.inspectionCoverageMap = "true";
  return panel;
}

function coverageBucketHref(bucket = {}) {
  if (bucket.state === "profile-needs-ips" || bucket.state === "profile-needs-fail-closed") return "#/inspection";
  if (bucket.state === "bypass-risk" || bucket.state === "ips-fail-open") return "#/rules?q=bypass-risk";
  if (bucket.state === "ids-detect" || bucket.state === "not-inspected") return "#/rules?q=" + encodeURIComponent(bucket.label || bucket.state);
  return "";
}

function bucketActionLabel(bucket = {}) {
  if (bucket.state === "profile-needs-ips" || bucket.state === "profile-needs-fail-closed") return "Stage fail-closed";
  if (bucket.state === "bypass-risk" || bucket.state === "ips-fail-open") return "Review bypass";
  return "Review rules";
}

function bucketActionTitle(bucket = {}) {
  return `${bucketActionLabel(bucket)} for ${bucket.label || bucket.state || "inspection coverage"}`;
}

function inspectionProfileCard(summary = {}, packageSummary = null) {
  return card(h("h2", {}, "Inspection profile", h("span", { class: "spacer" }), pill(summary.status, summary.cls, true)),
    h("div", { class: "note" }, summary.detail),
    h("div", { class: "note" }, summary.stateDetail),
    summary.deltaLabel !== "none" ? h("div", { class: "alert-box info" },
      h("strong", {}, "Candidate delta"),
      h("div", { class: "note" }, summary.deltaLabel)) : null,
    h("dl", { class: "kv compact" },
      kv("Mode", summary.modeLabel),
      kv("Interfaces", summary.monitorInterfacesLabel),
      kv("Home networks", summary.homeNetworksLabel),
      kv("Rule files", summary.ruleFilesLabel),
      kv("Failure behavior", summary.failureBehaviorLabel),
      kv("NFQUEUE", summary.queueLabel),
      kv("Exceptions", summary.exceptionCounts.label)),
    summary.packageBlocked ? h("div", { class: "alert-box warn" },
      h("strong", {}, "Threat-ID package gate"),
      h("div", { class: "note" }, packageSummary?.detail || "Review Intel before rollout.")) : null);
}

function inspectionRuntimeCard(posture = {}, status = {}) {
  const engines = Array.isArray(status.engines) ? status.engines : [];
  const idsIps = engines.find((engine) => /ids-ips|suricata/i.test(engine.name || engine.role || engine.detail || "")) || engines[0] || null;
  return card(h("h2", {}, "Runtime posture", h("span", { class: "spacer" }), pill(posture.label, posture.cls, true)),
    h("div", { class: "note" }, posture.detail),
    h("dl", { class: "kv compact" },
      kv("Engine", posture.engineLabel || "inspection engine unavailable"),
      kv("Inspection state", posture.inspectionState || "unknown"),
      kv("Failure behavior", posture.failureBehavior || "not reported"),
      kv("Bypass possible", posture.bypassPossible ? "yes" : "no"),
      kv("Bypass reason", posture.bypassReason || "none"),
      kv("Degraded behavior", posture.degradedBehavior || "none")),
    idsIps ? h("div", { class: "alert-box " + (idsIps.state === "failed" ? "bad" : idsIps.state === "active" || idsIps.state === "ready" ? "ok" : "info") },
      h("strong", {}, "IDS/IPS"),
      h("div", { class: "note" }, [idsIps.state, idsIps.mode, idsIps.detail || idsIps.role].filter(Boolean).join(" · "))) : null);
}

function inspectionRolloutCard(packageSummary = null) {
  const actions = idsRolloutActions(session.draft?.ids || {}, session.running?.ids || {}, packageSummary);
  return card(h("h2", {}, "Threat rollout actions", h("span", { class: "spacer" }), pill(idsRolloutGateLabel(packageSummary), packageSummary?.blockerCount ? "warn" : "info")),
    h("div", { class: "note" }, "All actions stage the IDS/IPS profile to candidate only. Commit review is required before IDS/IPS engine runtime changes."),
    h("div", { class: "flex wrap", style: { marginTop: "10px" } },
      actions.map((action) => inspectionRolloutButton(action))));
}

function inspectionRolloutButton(action = {}) {
  const cls = "btn" + (action.tone === "bad" ? " danger" : action.tone === "neutral" ? " ghost" : "");
  return h("button", {
    class: cls,
    type: "button",
    title: action.disabledReason || action.detail || action.label,
    "aria-label": action.label,
    dataset: { idsProfileAction: action.key || "", inspectionAction: "stage-profile" },
    disabled: action.disabled,
    onclick: () => stageInspectionRolloutAction(action),
  }, h("span", { html: icon(action.icon || "check", 15) }), action.label);
}

async function stageInspectionRolloutAction(action = {}) {
  try {
    globalThis.__inspectionWorkspaceLastError = "";
    await session.load();
    await session.apply((draft) => applyIdsProfilePreset(draft, action.key));
    toast("Inspection profile staged", `${action.label.replace(/^Stage /, "")} is pending commit review.`, "ok");
    reloadInspectionRoute();
  } catch (e) {
    globalThis.__inspectionWorkspaceLastError = e.message || String(e);
    toast("Could not stage inspection profile", e.message, "bad");
  }
}

function inspectionPackageCard(packageSummary = null, contentError = "") {
  const cls = packageSummary?.cls || (contentError ? "bad" : "warn");
  return card(h("h2", {}, "Threat-ID package", h("span", { class: "spacer" }), pill(packageSummary?.status || "unknown", cls, true)),
    h("div", { class: "note" }, packageSummary?.detail || contentError || "Package status is unavailable."),
    h("dl", { class: "kv compact" },
      kv("Version", packageSummary?.version || "not reported"),
      kv("State", packageSummary?.packageState || "unknown"),
      kv("Open gates", String(packageSummary?.blockerCount || 0))),
	    h("div", { class: "flex wrap" },
	      h("a", { class: "btn sm", href: "#/intel?surface=threat-id&drawer=review", title: "Review Threat-ID package evidence", "aria-label": "Review Threat-ID package evidence", dataset: { inspectionPackageAction: "review" } }, h("span", { html: icon("intel", 14) }), "Review package"),
	      h("a", { class: "btn sm", href: "#/intel?surface=threat-id&drawer=quality", title: "Open Threat-ID quality gates", "aria-label": "Open Threat-ID quality gates", dataset: { inspectionPackageAction: "quality" } }, h("span", { html: icon("search", 14) }), "Quality gates")));
}

function inspectionExceptionCard(exceptions = [], runningExceptions = []) {
  const summary = exceptionSummary(exceptions);
  return card(h("h2", {}, "False-positive exceptions", h("span", { class: "spacer" }), pill(summary.label, summary.active ? "info" : "neutral")),
    h("div", { class: "note" }, "Exceptions stage to policy and compile to IDS/IPS engine suppressions only after validation and commit."),
    exceptions.length ? h("div", { class: "table-wrap" },
      responsiveTable(["Threat-ID", "Scope", "Reason", "Evidence", "Policy state"], exceptions.map((ex, index) => {
        const scope = exceptionScopeModel(ex);
        const state = exceptionPolicyState(ex, runningExceptions);
        const evidence = exceptionEvidenceModel(ex);
        return h("tr", { dataset: { inspectionExceptionRow: ex.name || String(index) } },
          labeledCell("Threat-ID", threatCell(ex)),
          labeledCell("Scope", scopeCell(scope)),
          labeledCell("Reason", ex.description || h("span", { class: "muted" }, "No reason recorded")),
          labeledCell("Evidence", evidenceCell(evidence)),
          labeledCell("Policy state", pill(state.label, state.cls, state.withDot), h("div", { class: "note" }, state.detail)));
      }), { className: "inspection-exception-table" })) : emptyState("shield", "No false-positive exceptions", "Stage an exception from a Threat alert, then review it here before commit."));
}

function idsRolloutGateLabel(packageSummary = null) {
  if (!packageSummary?.available) return "package unknown";
  if (packageSummary.blockerCount) return `${packageSummary.blockerCount} gate${packageSummary.blockerCount === 1 ? "" : "s"} open`;
  return packageSummary.version ? `package ${packageSummary.version}` : "package ready";
}

function reloadInspectionRoute() {
  if (location.hash.startsWith("#/inspection")) {
    location.hash = "#/inspection";
    window.dispatchEvent(new HashChangeEvent("hashchange"));
  }
}

function kv(label, value) {
  return [h("dt", {}, label), h("dd", { class: "mono" }, value || "—")];
}

// Current IDS state as a pill, for headers/cards.
export function idsStatusPill(ids) {
  if (!ids || !ids.enabled) return pill("disabled", "neutral");
  if (ids.mode === "IDS_MODE_PREVENT") return pill("prevent (IPS)", "bad", true);
  return pill("detect (IDS)", "ok", true);
}

export function idsProfileSummary(draftIds = {}, runningIds = {}, packageSummary = null) {
  const draft = normalizeIdsProfile(draftIds);
  const running = normalizeIdsProfile(runningIds);
  const changed = !equal(draft, running);
  const exceptionCounts = exceptionSummary(draft.exceptions);
  const blockers = idsProfileBlockers(draft);
  const packageBlocked = Boolean(draft.enabled && packageSummary?.available && packageSummary.blockerCount > 0);
  const stateLabel = changed ? "candidate-only" : "running";
  const stateDetail = changed
    ? "Commit before alerts, suppressions, and runtime evidence reflect this profile."
    : "Matches the running IDS/IPS profile.";
  const deltaLabel = idsProfileDelta(draft, running);

  if (blockers.length) {
    return {
      changed,
      stateLabel,
      stateDetail,
      deltaLabel,
      packageBlocked,
      status: "incomplete",
      cls: "warn",
      modeLabel: modeLabel(draft.mode),
      detail: "Candidate IDS/IPS profile is enabled but missing " + blockers.join(" and ") + ".",
      monitorInterfacesLabel: listLabel(draft.monitorInterfaces, "all zone interfaces"),
      homeNetworksLabel: listLabel(draft.homeNetworks, "RFC1918 private ranges"),
      ruleFilesLabel: listLabel(draft.ruleFiles, "local.rules"),
      failureBehaviorLabel: failureBehaviorLabel(draft.failureBehavior),
      queueLabel: String(draft.queueNum),
      exceptionCounts,
    };
  }

  if (!draft.enabled) {
    return {
      changed,
      stateLabel,
      stateDetail,
      deltaLabel,
      packageBlocked: false,
      status: "disabled",
      cls: changed && running.enabled ? "warn" : "neutral",
      modeLabel: "disabled",
      detail: changed ? "Candidate disables inspection; commit to stop the engine." : "Inspection is disabled in the staged profile.",
      monitorInterfacesLabel: "not inspecting",
      homeNetworksLabel: "not inspecting",
      ruleFilesLabel: "not loading rules",
      failureBehaviorLabel: "not applicable",
      queueLabel: "not applicable",
      exceptionCounts,
    };
  }

  if (packageBlocked) {
    return {
      changed,
      stateLabel,
      stateDetail,
      deltaLabel,
      packageBlocked,
      status: "package blocked",
      cls: packageSummary?.cls === "bad" ? "bad" : "warn",
      modeLabel: modeLabel(draft.mode),
      detail: `Threat-ID package has ${packageSummary.blockerCount} production gate${packageSummary.blockerCount === 1 ? "" : "s"} open; review Intel before rollout.`,
      monitorInterfacesLabel: listLabel(draft.monitorInterfaces, "all zone interfaces"),
      homeNetworksLabel: listLabel(draft.homeNetworks, "RFC1918 private ranges"),
      ruleFilesLabel: listLabel(draft.ruleFiles, "local.rules"),
      failureBehaviorLabel: draft.mode === "IDS_MODE_PREVENT" ? failureBehaviorLabel(draft.failureBehavior) : "not applicable",
      queueLabel: draft.mode === "IDS_MODE_PREVENT" ? String(draft.queueNum) : "not applicable",
      exceptionCounts,
    };
  }

  if (draft.mode === "IDS_MODE_PREVENT") {
    return {
      changed,
      stateLabel,
      stateDetail,
      deltaLabel,
      packageBlocked,
      status: "prevent",
      cls: "bad",
      modeLabel: "Prevent (IPS)",
      detail: `Inline NFQUEUE prevention is staged with ${failureBehaviorLabel(draft.failureBehavior).toLowerCase()} behavior.`,
      monitorInterfacesLabel: listLabel(draft.monitorInterfaces, "all zone interfaces"),
      homeNetworksLabel: listLabel(draft.homeNetworks, "RFC1918 private ranges"),
      ruleFilesLabel: listLabel(draft.ruleFiles, "local.rules"),
      failureBehaviorLabel: failureBehaviorLabel(draft.failureBehavior),
      queueLabel: String(draft.queueNum),
      exceptionCounts,
    };
  }

  return {
    changed,
    stateLabel,
    stateDetail,
    deltaLabel,
    packageBlocked,
    status: "detect",
    cls: changed ? "info" : "ok",
    modeLabel: "Detect (IDS)",
    detail: "Passive IDS/IPS engine detection is staged for alerting without inline drops.",
    monitorInterfacesLabel: listLabel(draft.monitorInterfaces, "all zone interfaces"),
    homeNetworksLabel: listLabel(draft.homeNetworks, "RFC1918 private ranges"),
    ruleFilesLabel: listLabel(draft.ruleFiles, "local.rules"),
    failureBehaviorLabel: "not applicable",
    queueLabel: "not applicable",
    exceptionCounts,
  };
}

export function idsRolloutActions(draftIds = {}, runningIds = {}, packageSummary = null) {
  const draft = normalizeIdsProfile(draftIds);
  const running = normalizeIdsProfile(runningIds);
  const preventGate = idsPreventRolloutGate(packageSummary);
  const disabledChanged = draft.enabled || running.enabled;
  return [
    {
      key: "detect",
      label: "Stage Detect",
      tone: "info",
      icon: "check",
      status: draft.enabled && draft.mode === "IDS_MODE_DETECT" && equal(draft, running) ? "running" : "candidate",
      detail: "Passive IDS detection without inline drops.",
      disabled: false,
    },
    {
      key: "prevent-fail-open",
      label: "Stage Prevent fail-open",
      tone: "warn",
      icon: "threats",
      status: preventGate.blocked ? "gated" : "candidate",
      detail: preventGate.blocked ? preventGate.reason : "Inline prevention that preserves forwarding if inspection fails.",
      disabled: preventGate.blocked,
      disabledReason: preventGate.reason,
    },
    {
      key: "prevent-fail-closed",
      label: "Stage Prevent fail-closed",
      tone: "bad",
      icon: "block",
      status: preventGate.blocked ? "gated" : "candidate",
      detail: preventGate.blocked ? preventGate.reason : "Inline prevention that blocks traffic if inspection fails.",
      disabled: preventGate.blocked,
      disabledReason: preventGate.reason,
    },
    {
      key: "disable",
      label: "Stage Disable",
      tone: disabledChanged ? "warn" : "neutral",
      icon: "block",
      status: disabledChanged ? "candidate" : "running",
      detail: "Stop IDS/IPS inspection after commit.",
      disabled: false,
    },
  ];
}

export function applyIdsProfilePreset(policy = {}, preset = "detect") {
  policy.ids ||= {};
  const ids = policy.ids;
  const previous = normalizeIdsProfile(ids);
  ids.monitorInterfaces = previous.monitorInterfaces;
  ids.homeNetworks = previous.homeNetworks;
  ids.ruleFiles = previous.ruleFiles;
  if (previous.exceptions.length) ids.exceptions = previous.exceptions;
  else delete ids.exceptions;

  if (preset === "disable") {
    ids.enabled = false;
    delete ids.mode;
    delete ids.queueNum;
    delete ids.failureBehavior;
    return ids;
  }

  ids.enabled = true;
  if (preset === "prevent-fail-open" || preset === "prevent-fail-closed") {
    ids.mode = "IDS_MODE_PREVENT";
    ids.queueNum = previous.queueNum;
    ids.failureBehavior = preset === "prevent-fail-closed"
      ? "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED"
      : "IDS_FAILURE_BEHAVIOR_FAIL_OPEN";
    return ids;
  }

  ids.mode = "IDS_MODE_DETECT";
  delete ids.queueNum;
  delete ids.failureBehavior;
  return ids;
}

export async function openIdsEditor(onSaved) {
  await session.load();
  const ids = structuredClone(session.draft.ids || {});
  if (ids.mode == null || ids.mode === "IDS_MODE_UNSPECIFIED") ids.mode = "IDS_MODE_DETECT";

  const enable = checkbox(!!ids.enabled, { field: "enabled" });
  const modeSeg = segment(["Detect (IDS)", "Prevent (IPS)"], ids.mode === "IDS_MODE_PREVENT" ? 1 : 0,
    (i) => (ids.mode = i === 1 ? "IDS_MODE_PREVENT" : "IDS_MODE_DETECT"));
  modeSeg.dataset.idsField = "mode";
  modeSeg.querySelectorAll("button").forEach((button, index) => {
    button.dataset.idsMode = index === 1 ? "prevent" : "detect";
  });
  const ifaces = input((ids.monitorInterfaces || []).join(", "), "all zone interfaces", "monitor-interfaces");
  const home = input((ids.homeNetworks || []).join(", "), "RFC1918 private ranges", "home-networks");
  const rules = input((ids.ruleFiles || []).join(", "), "local.rules", "rule-files");
  const queue = input(ids.queueNum != null ? String(ids.queueNum) : "", "0", "queue-num");
  if (!ids.failureBehavior || ids.failureBehavior === "IDS_FAILURE_BEHAVIOR_UNSPECIFIED") {
    ids.failureBehavior = "IDS_FAILURE_BEHAVIOR_FAIL_OPEN";
  }
  const failSeg = segment(["Fail open", "Fail closed"], ids.failureBehavior === "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED" ? 1 : 0,
    (i) => (ids.failureBehavior = i === 1 ? "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED" : "IDS_FAILURE_BEHAVIOR_FAIL_OPEN"));
  failSeg.dataset.idsField = "failure-behavior";
  failSeg.querySelectorAll("button").forEach((button, index) => {
    button.dataset.idsFailureBehavior = index === 1 ? "fail-closed" : "fail-open";
  });
  const exceptionsWrap = h("div", {});
  const preflightSlot = h("div", { dataset: { idsValidationPreflight: "true" } });

  const body = h("div", { dataset: { idsEditor: "true" } },
    h("div", { class: "alert-box" }, h("strong", {}, "Inspection engine: IDS/IPS engine. "),
      "Detect sniffs traffic passively (AF_PACKET). Prevent inspects inline via NFQUEUE and can drop. Failure behavior is explicit policy, not an engine default."),
    field("Enable IDS/IPS", enable, "Off leaves the inspection engine stopped."),
    field("Mode", modeSeg),
    field("Monitor interfaces", ifaces, "comma-separated NIC names; empty = every zone interface"),
    field("Home networks", home, "comma-separated CIDRs treated as internal; empty = RFC1918"),
    field("Rule files", rules, "comma-separated files in the managed rules dir; empty = local.rules"),
    field("NFQUEUE number (Prevent only)", queue, "default 0"),
    field("Failure behavior (Prevent only)", failSeg, "fail open preserves availability; fail closed preserves inspection"),
    preflightSlot,
    h("hr", { class: "divider" }),
    h("h3", {}, "False-positive exceptions"),
    h("div", { class: "note", style: { marginBottom: "10px" } }, "Exceptions are Phragma policy objects. They compile to IDS/IPS engine suppressions only after validation and commit."),
    exceptionsWrap);
  renderExceptions();

  openDrawer({
    title: "IDS / IPS configuration",
    subtitle: "Stages to the candidate — commit to apply.",
    width: "560px",
    body,
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Cancel IDS/IPS configuration", "aria-label": "Cancel IDS/IPS configuration", dataset: { idsAction: "cancel-settings" }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: "Stage IDS/IPS settings", "aria-label": "Stage IDS/IPS settings", dataset: { idsAction: "stage-settings" }, onclick: save }, h("span", { html: icon("check", 16) }), "Stage IDS settings"),
    ],
  });

  async function save() {
    try {
      preflightSlot.replaceChildren(h("div", { class: "note" }, "Validating IDS/IPS candidate profile..."));
      const form = idsEditorFormValues({
        enabled: enable.checked,
        mode: ids.mode,
        monitorInterfaces: ifaces.value,
        homeNetworks: home.value,
        ruleFiles: rules.value,
        queueNum: queue.value,
        failureBehavior: ids.failureBehavior,
        exceptions: ids.exceptions || [],
      });
      const candidate = buildIdsEditorCandidate(session.draft || {}, form);
      const validation = await api.validatePolicy(candidate);
      if (!validation?.valid) {
        renderIdsPreflightFailure(preflightSlot, validation);
        toast("IDS/IPS validation failed", validationErrors(validation, "Fix the IDS/IPS profile before staging.")[0], "bad");
        return;
      }
      await session.apply((d) => applyIdsEditorForm(d, form));
      closeDrawer();
      toast("IDS/IPS staged", enable.checked ? "Commit to start inspection." : "Commit to stop inspection.", "ok");
      if (onSaved) onSaved();
    } catch (e) { toast("Could not stage IDS settings", e.message, "bad"); }
  }

  function renderExceptions() {
    const exceptions = ids.exceptions || [];
    if (!exceptions.length) {
      exceptionsWrap.replaceChildren(h("div", { class: "empty mini" }, "No IDS exceptions staged."));
      return;
    }
    exceptionsWrap.replaceChildren(h("div", { class: "table-wrap" },
      responsiveTable(["Threat-ID", "Reason", "Scope object", "Evidence", "Policy state", { label: "", attrs: { class: "actions-col" } }],
        exceptions.map((ex, i) => {
          const scope = exceptionScopeModel(ex);
          const state = exceptionPolicyState(ex, session.running?.ids || {});
          const evidence = exceptionEvidenceModel(ex);
          return h("tr", { dataset: { idsExceptionRow: ex.name || String(ex.signatureId || i) } },
            labeledCell("Threat-ID", threatCell(ex)),
            labeledCell("Reason", ex.description || h("span", { class: "muted" }, "No reason recorded")),
            labeledCell("Scope object", scopeCell(scope)),
            labeledCell("Evidence", evidenceCell(evidence)),
            labeledCell("Policy state", pill(state.label, state.cls, state.withDot), h("div", { class: "note" }, state.detail)),
            labeledCell("Actions", { class: "cell-actions" },
              h("button", { class: "btn sm danger", type: "button", title: `Remove IDS exception ${ex.name || ex.signatureId || i}`, "aria-label": `Remove IDS exception ${ex.name || ex.signatureId || i}`, dataset: { idsExceptionAction: "remove" }, onclick: () => {
                ids.exceptions.splice(i, 1);
                renderExceptions();
              } }, "Remove")));
        }), { className: "ids-exception-table" })));
  }
}

// --- local helpers (kept self-contained) ---
function field(label, control, help) {
  return h("label", { class: "field" }, h("span", {}, label, help ? h("span", { class: "help" }, " — " + help) : null), control);
}
function input(value, ph, fieldName = "") {
  return h("input", { class: "input", value: value || "", placeholder: ph, dataset: fieldName ? { idsField: fieldName } : {} });
}
function csv(s) { return (s || "").split(",").map((x) => x.trim()).filter(Boolean); }

export function idsEditorFormValues(form = {}) {
  const mode = form.mode === "IDS_MODE_PREVENT" ? "IDS_MODE_PREVENT" : "IDS_MODE_DETECT";
  const q = parseInt(form.queueNum, 10);
  return {
    enabled: Boolean(form.enabled),
    mode,
    monitorInterfaces: csv(form.monitorInterfaces),
    homeNetworks: csv(form.homeNetworks),
    ruleFiles: csv(form.ruleFiles),
    queueNum: isNaN(q) ? 0 : q,
    failureBehavior: form.failureBehavior === "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED"
      ? "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED"
      : "IDS_FAILURE_BEHAVIOR_FAIL_OPEN",
    exceptions: normalizeExceptions(form.exceptions || []),
  };
}

export function buildIdsEditorCandidate(policy = {}, form = {}) {
  const draft = structuredClone(policy || {});
  applyIdsEditorForm(draft, form);
  return draft;
}

export function applyIdsEditorForm(policy = {}, form = {}) {
  policy.ids ||= {};
  const ids = policy.ids;
  ids.enabled = Boolean(form.enabled);
  ids.monitorInterfaces = stringList(form.monitorInterfaces);
  ids.homeNetworks = stringList(form.homeNetworks);
  ids.ruleFiles = stringList(form.ruleFiles);
  if (Array.isArray(form.exceptions) && form.exceptions.length) ids.exceptions = normalizeExceptions(form.exceptions);
  else delete ids.exceptions;
  if (!ids.enabled) {
    delete ids.mode;
    delete ids.queueNum;
    delete ids.failureBehavior;
    return policy;
  }
  ids.mode = form.mode === "IDS_MODE_PREVENT" ? "IDS_MODE_PREVENT" : "IDS_MODE_DETECT";
  if (ids.mode === "IDS_MODE_PREVENT") {
    ids.queueNum = normalizeQueue(form.queueNum);
    ids.failureBehavior = form.failureBehavior === "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED"
      ? "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED"
      : "IDS_FAILURE_BEHAVIOR_FAIL_OPEN";
  } else {
    delete ids.queueNum;
    delete ids.failureBehavior;
  }
  return policy;
}

function renderIdsPreflightFailure(slot, validation) {
  slot.replaceChildren(h("div", { class: "alert-box bad", dataset: { idsValidationState: "failed" } },
    h("strong", {}, "IDS/IPS profile did not validate."),
    h("ul", { class: "compact-list" },
      validationErrors(validation, "Fix the IDS/IPS profile before staging.").map((item) => h("li", {}, item)))));
}

function normalizeIdsProfile(ids = {}) {
  const enabled = Boolean(ids?.enabled);
  const mode = enabled ? (ids.mode || "IDS_MODE_UNSPECIFIED") : "";
  const prevent = mode === "IDS_MODE_PREVENT";
  return {
    enabled,
    mode,
    monitorInterfaces: stringList(ids?.monitorInterfaces),
    homeNetworks: stringList(ids?.homeNetworks),
    ruleFiles: stringList(ids?.ruleFiles),
    queueNum: prevent ? normalizeQueue(ids?.queueNum) : 0,
    failureBehavior: prevent ? (ids.failureBehavior || "IDS_FAILURE_BEHAVIOR_UNSPECIFIED") : "",
    exceptions: normalizeExceptions(ids?.exceptions),
  };
}

function idsProfileBlockers(profile) {
  const blockers = [];
  if (!profile.enabled) return blockers;
  if (!profile.mode || profile.mode === "IDS_MODE_UNSPECIFIED") blockers.push("inspection mode");
  if (profile.mode === "IDS_MODE_PREVENT" &&
      (!profile.failureBehavior || profile.failureBehavior === "IDS_FAILURE_BEHAVIOR_UNSPECIFIED")) {
    blockers.push("failure behavior");
  }
  return blockers;
}

function normalizeQueue(value) {
  const n = Number(value || 0);
  return Number.isFinite(n) && n >= 0 ? Math.trunc(n) : 0;
}

function idsPreventRolloutGate(packageSummary = null) {
  if (!packageSummary?.available) {
    return {
      blocked: true,
      reason: "Threat-ID package posture is unavailable; review Intel before staging prevention.",
    };
  }
  const blockers = Number(packageSummary.blockerCount || 0);
  if (blockers > 0) {
    return {
      blocked: true,
      reason: `${blockers} Threat-ID package gate${blockers === 1 ? "" : "s"} must close before staging prevention.`,
    };
  }
  return { blocked: false, reason: "" };
}

function stringList(values) {
  return (values || []).map((value) => String(value || "").trim()).filter(Boolean);
}

function normalizeExceptions(values) {
  return (values || []).map((ex = {}) => {
    const out = {
      name: ex.name || "",
      disabled: Boolean(ex.disabled),
      signatureId: Number(ex.signatureId || 0),
      threatId: ex.threatId || "",
      sourceAddress: ex.sourceAddress || "",
      destinationAddress: ex.destinationAddress || "",
      description: ex.description || "",
    };
    for (const [key, value] of [
      ["owner", ex.owner],
      ["ticketId", ex.ticketId || ex.ticket_id],
      ["reviewDate", ex.reviewDate || ex.review_date],
      ["expiresAt", ex.expiresAt || ex.expires_at],
      ["pcapSha256", String(ex.pcapSha256 || ex.pcap_sha256 || "").trim().toLowerCase()],
      ["regressionRef", ex.regressionRef || ex.regression_ref],
    ]) {
      if (value) out[key] = value;
    }
    return out;
  });
}

function exceptionSummary(exceptions = []) {
  const total = exceptions.length;
  const disabled = exceptions.filter((ex) => ex.disabled).length;
  const active = total - disabled;
  return { total, active, disabled, label: `${active} active / ${total} total` };
}

function idsProfileDelta(draft, running) {
  if (equal(draft, running)) return "none";
  const parts = [];
  if (idsModeKey(draft) !== idsModeKey(running)) {
    parts.push(`${modeLabel(running.mode)} -> ${modeLabel(draft.mode)}`);
  }
  if (!equal(draft.monitorInterfaces, running.monitorInterfaces)) parts.push("interfaces changed");
  if (!equal(draft.homeNetworks, running.homeNetworks)) parts.push("home networks changed");
  if (!equal(draft.ruleFiles, running.ruleFiles)) parts.push("rule files changed");
  if (draft.mode === "IDS_MODE_PREVENT" && draft.queueNum !== running.queueNum) parts.push(`NFQUEUE ${running.queueNum} -> ${draft.queueNum}`);
  if (draft.failureBehavior !== running.failureBehavior) {
    parts.push(`${failureBehaviorLabel(running.failureBehavior)} -> ${failureBehaviorLabel(draft.failureBehavior)}`);
  }
  const draftExceptions = exceptionSummary(draft.exceptions);
  const runningExceptions = exceptionSummary(running.exceptions);
  if (!equal(draftExceptions, runningExceptions)) {
    parts.push(`exceptions ${runningExceptions.label} -> ${draftExceptions.label}`);
  }
  return parts.length ? parts.join("; ") : "candidate profile changed";
}

function idsModeKey(profile) {
  if (!profile.enabled) return "disabled";
  return profile.mode || "IDS_MODE_UNSPECIFIED";
}

function listLabel(values, fallback) {
  return values.length ? values.join(", ") : fallback;
}

function modeLabel(mode) {
  if (mode === "IDS_MODE_DETECT") return "Detect (IDS)";
  if (mode === "IDS_MODE_PREVENT") return "Prevent (IPS)";
  if (mode === "IDS_MODE_UNSPECIFIED") return "unspecified";
  return "disabled";
}

function failureBehaviorLabel(value) {
  if (value === "IDS_FAILURE_BEHAVIOR_FAIL_OPEN") return "Fail open";
  if (value === "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED") return "Fail closed";
  return "not set";
}

function threatCell(ex) {
  const t = exceptionThreatLabel(ex);
  return h("div", {},
    h("strong", { class: t.threatId === "—" ? "muted" : "mono" }, t.threatId),
    h("div", { class: "note" }, t.signature),
    h("div", { class: "note" }, t.name));
}

function scopeCell(scope) {
  if (scope.object) {
    return h("div", {},
      h("span", { class: "tag" }, scope.object),
      h("div", { class: "note" }, scope.detail));
  }
  return h("div", {},
    h("span", { class: "tag" }, "global"),
    h("div", { class: "note" }, scope.detail));
}

function evidenceCell(evidence = {}) {
  if (!evidence.hasEvidence) return h("span", { class: "muted" }, "No PCAP or regression reference");
  return h("div", {},
    evidence.pcapSha256 ? h("div", {}, h("code", {}, evidence.pcapShort)) : null,
    evidence.regressionRef ? h("div", { class: "note" }, evidence.regressionRef) : null);
}

export function exceptionThreatLabel(ex = {}) {
  return {
    threatId: ex.threatId || "—",
    signature: ex.signatureId ? "SID " + ex.signatureId : "SID —",
    name: ex.name || "(unnamed exception)",
  };
}

export function exceptionScope(ex) {
  const scope = exceptionScopeModel(ex);
  return scope.object ? `${scope.kind} ${scope.object}` : "global";
}

export function exceptionScopeModel(ex = {}) {
  if (ex.sourceAddress) return { kind: "source", object: ex.sourceAddress, detail: "source address object" };
  if (ex.destinationAddress) return { kind: "destination", object: ex.destinationAddress, detail: "destination address object" };
  return { kind: "global", object: "", detail: "all matching traffic after commit" };
}

export function exceptionEvidenceModel(ex = {}) {
  const pcapSha256 = String(ex.pcapSha256 || ex.pcap_sha256 || "").trim().toLowerCase();
  const regressionRef = String(ex.regressionRef || ex.regression_ref || "").trim().replace(/\s+/g, " ").slice(0, 160);
  return {
    pcapSha256,
    pcapShort: pcapSha256 ? pcapSha256.slice(0, 16) : "",
    regressionRef,
    hasEvidence: Boolean(pcapSha256 || regressionRef),
    label: [pcapSha256 ? `pcap ${pcapSha256.slice(0, 16)}` : "", regressionRef].filter(Boolean).join(" · ") || "No PCAP or regression reference",
  };
}

export function exceptionPolicyState(ex = {}, runningIds = {}) {
  const running = Array.isArray(runningIds) ? runningIds : runningIds.exceptions || [];
  const match = runningExceptionMatch(ex, running);
  if (ex.disabled) {
    return {
      label: "disabled",
      cls: "neutral",
      detail: match ? "Disabled in candidate policy." : "Staged disabled in candidate policy.",
      withDot: false,
    };
  }
  if (!match) {
    return {
      label: "candidate",
      cls: "violet",
      detail: "Staged only; commit before IDS/IPS engine receives the suppression.",
      withDot: false,
    };
  }
  if (equal(ex, match)) {
    return {
      label: "running",
      cls: "ok",
      detail: "Matches the running policy.",
      withDot: true,
    };
  }
  return {
    label: "candidate edit",
    cls: "violet",
    detail: "Differs from the running exception until commit.",
    withDot: false,
  };
}

function runningExceptionMatch(ex, running = []) {
  if (ex.name) {
    const byName = running.find((candidate) => candidate?.name === ex.name);
    if (byName) return byName;
  }
  return running.find((candidate) =>
    Number(candidate?.signatureId || 0) === Number(ex.signatureId || 0) &&
    (candidate?.threatId || "") === (ex.threatId || "") &&
    (candidate?.sourceAddress || "") === (ex.sourceAddress || "") &&
    (candidate?.destinationAddress || "") === (ex.destinationAddress || ""));
}
function checkbox(on, opts = {}) {
  const i = h("input", { type: "checkbox" }); i.checked = on;
  if (opts.field) i.dataset.idsField = opts.field;
  const l = h("label", { class: "switch" }, i, h("span", { class: "slider" }));
  if (opts.field) l.dataset.idsField = opts.field;
  Object.defineProperty(l, "checked", { get: () => i.checked });
  return l;
}
function segment(labels, activeIdx, onChange) {
  const seg = h("div", { class: "seg" });
  labels.forEach((lbl, i) => {
    const b = h("button", { class: i === activeIdx ? "active" : "", type: "button", title: lbl, "aria-label": lbl, dataset: { inspectionSegment: lbl.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || String(i) }, onclick: () => { seg.querySelectorAll("button").forEach((x) => x.classList.remove("active")); b.classList.add("active"); onChange(i); } }, lbl);
    seg.appendChild(b);
  });
  return seg;
}
