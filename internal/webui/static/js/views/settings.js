// Settings — system info, global dataplane settings (editable, staged to
// candidate), theme, and the API token used when auth is enabled.

import { h, icon, clear } from "../core.js";
import { api, getToken, setToken } from "../api.js";
import { oidcAccessPosture, oidcLoginTarget, samlLoginTarget, throwIfAccessDenied } from "../auth_gate.js";
import { MAX_MTU, MIN_MTU, dataplanePosture, networkCandidateIssues, flowtableHostReadiness, idsEnabled, idsModeLabel, zoneInterfaces } from "../dataplane.js";
import { equal, session } from "../policy.js";
import { pageHead, card, toast, pill, openDrawer, closeDrawer, confirmDialog, labeledCell, responsiveTable } from "../ui.js";
import { getTheme, setTheme } from "../app.js";
import { hostInputManagementCoverage, managementRuleTemplate } from "../host_input_readiness.js";
import { pinInvestigationPacket } from "../investigation_case.js";
import { buildInvestigationPacket } from "../investigation_packet.js";
import { NETWORK_PROFILES, applyNetworkProfile, matchingNetworkProfile } from "../network_profiles.js";
import { interfaceMtuEditorModel, normalizeInterfaceMtus, parseCustomInterfaceMtus } from "../network_settings.js";
import { buildHash, readQueryState, writeQueryState } from "../query_state.js";
import {
  SETTINGS_ROUTE_DEFAULTS,
  SETTINGS_ROUTE_KEYS,
  settingsPanelHash,
  settingsPanelById,
  settingsPanelLinkModel,
  settingsPanelURL,
  normalizeSettingsRoute,
  scheduleSettingsPanelFocus,
} from "../settings_route.js";
import {
  comparableTelemetry,
  telemetryEvidencePacket,
  telemetryEvidenceFilename,
  telemetryEvidencePacketJson,
  telemetryEvidenceText,
  telemetryExportSettings,
  telemetryFromInputs,
  telemetryReadinessModel,
  telemetryReceiverProofFromInputs,
  validateTelemetryInputs,
  validateTelemetryReceiverProof,
} from "../telemetry_settings.js";
import {
  accessAdministrationUnavailable,
  accessAuditHash,
  accessGovernanceModel,
  accessLifecycleReviewModel,
  accessLifecycleReviewText,
  oidcPreflightEvidenceText,
  oidcPreflightModel,
  oidcRolloutInitialValues,
  oidcRolloutPlan,
  oidcRolloutPlanText,
  roleImpactPreview,
  samlRolloutPlan,
  samlRolloutPlanText,
} from "../access_governance.js";
import { openIdsEditor, idsStatusPill } from "./ids.js";

const HOST_INPUT_FOCUS_DEFAULTS = Object.freeze({ panel: "", rule: "", idx: "" });
const HOST_INPUT_FOCUS_KEYS = Object.freeze(["panel", "rule", "idx"]);

export async function render(ctx = {}) {
  const routePath = ctx.path || "/settings";
  const routeState = normalizeSettingsRoute(ctx.query || {});
  const hostInputFocus = normalizeHostInputFocusRoute(ctx.query || {}, routeState);
  if (hostInputFocus.rule || hostInputFocus.idx) routeState.panel = "host-input";
  const queryKeys = Object.keys(ctx.query || {});
  const rawPanel = Object.prototype.hasOwnProperty.call(ctx.query || {}, "panel") ? ctx.query.panel : "";
  const allowedKeys = new Set([...SETTINGS_ROUTE_KEYS, "rule", "idx"]);
  if (queryKeys.some((key) => !allowedKeys.has(key)) || rawPanel !== routeState.panel || hostInputRouteNeedsRewrite(ctx.query || {}, hostInputFocus)) {
    writeQueryState(routePath, { ...routeState, ...hostInputFocus }, HOST_INPUT_FOCUS_DEFAULTS, HOST_INPUT_FOCUS_KEYS);
  }
  const [statusR, identityR, oidcR, samlR, accessAdministrationR, oidcProviderConfigR, telemetryExportStatusR, sessionR] = await Promise.allSettled([
    api.status(),
    api.identity(),
    api.authStatus(),
    api.samlAuthStatus(),
    api.accessAdministration(),
    api.oidcProviderConfig(),
    api.telemetryExportStatus(),
    session.load(),
  ]);
  throwIfAccessDenied(statusR, identityR, oidcR, sessionR);
  if (sessionR.status === "rejected") throw sessionR.reason;
  const status = statusR.status === "fulfilled" ? statusR.value : {};
  const identity = identityR.status === "fulfilled" ? identityR.value : null;
  const oidc = oidcR.status === "fulfilled" ? oidcR.value : { enabled: false };
  const saml = samlR.status === "fulfilled" ? samlR.value : { enabled: false, runtimeAvailable: false };
  const accessAdministration = accessAdministrationR.status === "fulfilled"
    ? accessAdministrationWithOIDCConfig(accessAdministrationR.value, oidcProviderConfigR.status === "fulfilled" ? oidcProviderConfigR.value : null)
    : accessAdministrationUnavailable(accessAdministrationR.reason);
  const telemetryExportStatus = telemetryExportStatusR.status === "fulfilled" ? telemetryExportStatusR.value : null;
  const root = h("div", {});
  paint(root, status, identity, oidc, saml, accessAdministration, telemetryExportStatus, { routePath, routeState, hostInputFocus });
  return root;
}

function paint(root, status, identity, oidc, saml, accessAdministration, telemetryExportStatus = null, routeContext = defaultSettingsRouteContext()) {
  if (saml && (Object.prototype.hasOwnProperty.call(saml, "available") || Object.prototype.hasOwnProperty.call(saml, "authEnabled") || Object.prototype.hasOwnProperty.call(saml, "localUsers"))) {
    const oldAccessAdministration = saml;
    const oldTelemetryExportStatus = accessAdministration;
    const oldRouteContext = telemetryExportStatus;
    saml = { enabled: false, runtimeAvailable: false };
    accessAdministration = oldAccessAdministration;
    telemetryExportStatus = oldTelemetryExportStatus;
    routeContext = oldRouteContext || defaultSettingsRouteContext();
  }
  clear(root);
  root.appendChild(pageHead("Settings", "System, dataplane, appearance, and access."));
  root.appendChild(settingsPanelNav(routeContext));
  const activePanel = routeContext.routeState?.panel || "";
  root.appendChild(h("div", { class: "grid cols-2" },
    systemCard(status),
    servicesCard(root, status, identity, oidc, accessAdministration, telemetryExportStatus, routeContext),
    settingsSection("telemetry", telemetryCard(root, status, identity, oidc, accessAdministration, telemetryExportStatus, routeContext), activePanel),
    appearanceCard(),
    settingsSection("network", networkCard(root, status, routeContext), activePanel),
    settingsSection("host-input", hostInputCard(root, status, identity, oidc, accessAdministration, routeContext), activePanel),
    settingsSection("access", accessCard(root, status, identity, oidc, saml, accessAdministration, telemetryExportStatus, routeContext), activePanel)));
  scheduleSettingsPanelFocus(root, activePanel);
  scheduleHostInputRuleFocus(root, routeContext);
}

function defaultSettingsRouteContext() {
  return {
    routePath: "/settings",
    routeState: { ...SETTINGS_ROUTE_DEFAULTS },
    hostInputFocus: { rule: "", idx: "" },
  };
}

function normalizeHostInputFocusRoute(query = {}, routeState = {}) {
  const state = readQueryState(query, HOST_INPUT_FOCUS_DEFAULTS, HOST_INPUT_FOCUS_KEYS);
  const panel = normalizeSettingsRoute({ panel: routeState.panel || state.panel }).panel;
  const rule = String(state.rule || "").trim();
  const idx = normalizeHostInputFocusIndex(state.idx);
  if (panel !== "host-input" && !rule && idx === "") return { rule: "", idx: "" };
  return { rule, idx };
}

function hostInputRouteNeedsRewrite(query = {}, focus = {}) {
  const source = query instanceof URLSearchParams ? Object.fromEntries(query.entries()) : (query || {});
  if (!focus.rule && !focus.idx) return Boolean(source.rule || source.idx);
  return String(source.rule || "").trim() !== focus.rule || normalizeHostInputFocusIndex(source.idx) !== focus.idx;
}

function normalizeHostInputFocusIndex(value = "") {
  if (value == null || value === "") return "";
  const n = Number(value);
  return Number.isInteger(n) && n >= 0 ? String(n) : "";
}

function hostInputRuleDurableId(rule = {}) {
  return String(rule?.id || "").trim();
}

function hostInputRuleDisplayName(rule = {}, idx = 0) {
  return String(rule?.name || `#${Number(idx) + 1}`).trim();
}

function hostInputRuleRouteToken(rule = {}, idx = 0) {
  return hostInputRuleDurableId(rule) || hostInputRuleDisplayName(rule, idx);
}

function hostInputRuleRouteHash(rule = {}, idx = 0, routePath = "/settings") {
  return buildHash(routePath, {
    panel: "host-input",
    rule: hostInputRuleRouteToken(rule, idx),
    idx: normalizeHostInputFocusIndex(idx),
  }, HOST_INPUT_FOCUS_DEFAULTS, HOST_INPUT_FOCUS_KEYS);
}

function focusedHostInputRuleIndex(routeContext = defaultSettingsRouteContext(), rules = []) {
  const focus = routeContext.hostInputFocus || {};
  const wantedIdx = focus.idx === "" ? -1 : Number(focus.idx);
  const wantedRule = String(focus.rule || "").trim();
  if (wantedRule) {
    const idMatches = (rules || [])
      .map((rule, idx) => ({ rule, idx }))
      .filter(({ rule }) => hostInputRuleDurableId(rule) === wantedRule);
    if (idMatches.length === 1) return idMatches[0].idx;
    if (idMatches.length > 1 && wantedIdx >= 0 && idMatches.some((match) => match.idx === wantedIdx)) return wantedIdx;
    const matches = (rules || [])
      .map((rule, idx) => ({ rule, idx }))
      .filter(({ rule, idx }) => hostInputRuleDisplayName(rule, idx) === wantedRule || String(rule?.name || "").trim() === wantedRule);
    if (matches.length === 1) return matches[0].idx;
    if (matches.length > 1 && wantedIdx >= 0 && matches.some((match) => match.idx === wantedIdx)) return wantedIdx;
  }
  if (wantedIdx >= 0 && wantedIdx < (rules || []).length) return wantedIdx;
  return -1;
}

function hostInputFocusIssue(routeContext = defaultSettingsRouteContext(), rules = []) {
  const focus = routeContext.hostInputFocus || {};
  if (!focus.rule && focus.idx === "") return null;
  if (focusedHostInputRuleIndex(routeContext, rules) >= 0) return null;
  return {
    rule: focus.rule,
    idx: focus.idx,
  };
}

function hostInputFocusIssueAlert(issue = {}) {
  const target = issue.rule || (issue.idx !== "" ? `index ${Number(issue.idx) + 1}` : "requested rule");
  return h("div", { class: "alert-box warn", dataset: { hostInputFocusMissing: "true", hostInputFocusTarget: target } },
    h("strong", {}, "Host-input route target not found. "),
    `The linked host-input rule ${target} is not present in the staged candidate. Refresh policy or use the current row ID/name below.`,
    h("div", { class: "toolbar compact", style: { marginTop: "10px" } },
      h("a", { class: "btn sm ghost", href: settingsPanelHash("host-input"), title: "Clear missing host-input route focus", "aria-label": "Clear missing host-input route focus", dataset: { hostInputAction: "clear-focus" } }, "Clear focus")));
}

function scheduleHostInputRuleFocus(root, routeContext = defaultSettingsRouteContext()) {
  const focus = routeContext.hostInputFocus || {};
  if (!focus.rule && focus.idx === "") return false;
  setTimeout(() => {
    const rules = session.draft.hostInput?.rules || [];
    const idx = focusedHostInputRuleIndex(routeContext, rules);
    if (idx < 0) return;
    const target = root?.querySelector?.(`[data-host-input-rule-index="${idx}"]`);
    if (!target) return;
    try {
      target.focus?.({ preventScroll: true });
    } catch {
      target.focus?.();
    }
    target.scrollIntoView?.({ block: "center", inline: "nearest", behavior: "smooth" });
  }, 0);
  return true;
}

function settingsPanelNav(routeContext = defaultSettingsRouteContext()) {
  const activePanel = routeContext.routeState?.panel || "";
  return h("nav", { class: "settings-panel-nav", "aria-label": "Settings sections" },
    h("div", { class: "settings-panel-links" },
      settingsPanelLinkModel(activePanel, routeContext.routePath).map((panel) =>
        h("div", { class: "settings-panel-link " + (panel.active ? "active" : "") },
          h("a", {
            href: panel.href,
            "aria-current": panel.active ? "page" : null,
          },
            h("strong", {}, panel.label),
            h("span", {}, panel.detail)),
	          h("button", {
	            class: "icon-btn",
	            type: "button",
	            title: "Copy " + panel.label + " settings link",
	            "aria-label": "Copy " + panel.label + " settings link",
            dataset: { settingsPanelAction: "copy-link", settingsPanelTarget: panel.id },
            onclick: (e) => {
              e.preventDefault();
              copySettingsPanelLink(panel.id, routeContext.routePath);
            },
            html: icon("copy", 16),
          })))));
}

function settingsSection(panelId, child, activePanel) {
  const panel = settingsPanelById(panelId);
  return h("section", {
    id: "settings-panel-" + panelId,
    class: "settings-section " + (activePanel === panelId ? "active" : ""),
    tabindex: "-1",
    dataset: { settingsPanel: panelId },
    "aria-label": panel?.title || panelId,
  }, child);
}

async function copySettingsPanelLink(panelId, routePath) {
  try {
    await navigator.clipboard.writeText(settingsPanelURL(panelId, routePath, globalThis.location));
    const panel = settingsPanelById(panelId);
    toast("Settings link copied", (panel?.label || "Settings") + " section link copied.", "ok");
  } catch {
    toast("Copy failed", "Copy the current browser URL after opening the section.", "warn");
  }
}

function servicesCard(root, status, identity, oidc, accessAdministration, telemetryExportStatus = null, routeContext = defaultSettingsRouteContext()) {
  const ids = session.draft.ids || {};
  const rt = status.runtime || {};
  return card(h("h2", {}, "Security services"),
    h("div", { class: "settings-service-row" },
      h("div", {}, h("strong", {}, "IDS / IPS (Suricata) "), idsStatusPill(ids),
        h("div", { class: "note" }, `Inspects traffic for threats; inline fan-out is ${rt.inspectionWorkers || 0} worker(s).`)),
      h("button", {
        class: "btn",
        type: "button",
        title: "Configure IDS/IPS security service",
        "aria-label": "Configure IDS/IPS security service",
        dataset: { settingsServiceAction: "configure-ids" },
        onclick: () => openIdsEditor(() => paint(root, status, identity, oidc, accessAdministration, telemetryExportStatus, routeContext)),
      }, h("span", { html: icon("threats", 16) }), "Configure")),
    h("div", { class: "note" }, "Routing, VPN, telemetry, and dataplane settings are also staged through the candidate workflow."));
}

function telemetryCard(root, status, identity, oidc, accessAdministration, telemetryExportStatus = null, routeContext = defaultSettingsRouteContext()) {
  const tel = session.draft.telemetry || {};
  const running = comparableTelemetry(session.running.telemetry);
  const current = comparableTelemetry(tel);
  const exportSettings = telemetryExportSettings(tel.exports || []);
  const draftDirty = !equal(running, current);
  const enabled = checkbox(Boolean(tel.enabled));
  const clickhouseUrl = h("input", { class: "input", value: tel.clickhouseUrl || "", placeholder: "http://127.0.0.1:8123" });
  const database = h("input", { class: "input", value: tel.database || "", placeholder: "openngfw" });
  const jsonFileEnabled = checkbox(exportSettings.jsonFileEnabled);
  const jsonFilePath = h("input", { class: "input", value: exportSettings.jsonFilePath, placeholder: "/var/log/openngfw/exports/eve-%Y-%m-%d.json" });
  const jsonStreamEnabled = checkbox(exportSettings.jsonStreamEnabled);
  const jsonStreamTarget = h("input", { class: "input", value: exportSettings.jsonStreamTarget, placeholder: "siem.example:5514" });
  const jsonStreamProtocol = h("select", { class: "input" },
    h("option", { value: "tcp", selected: exportSettings.jsonStreamProtocol !== "udp" }, "TCP"),
    h("option", { value: "udp", selected: exportSettings.jsonStreamProtocol === "udp" }, "UDP"));
  const preview = h("div", {});
  const stageBtn = h("button", { class: "btn primary", type: "button", title: "Stage telemetry settings", "aria-label": "Stage telemetry settings to candidate", dataset: { telemetryAction: "stage" }, onclick: () => stageTelemetry() }, h("span", { html: icon("check", 16) }), "Stage telemetry");

  const read = () => ({
    enabled: enabled.checked,
    clickhouseUrl: clickhouseUrl.value,
    database: database.value,
    jsonFileEnabled: jsonFileEnabled.checked,
    jsonFilePath: jsonFilePath.value,
    jsonStreamEnabled: jsonStreamEnabled.checked,
    jsonStreamTarget: jsonStreamTarget.value,
    jsonStreamProtocol: jsonStreamProtocol.value,
  });
  const updatePreview = () => {
    const values = read();
    const issues = validateTelemetryInputs(values);
    const next = telemetryFromInputs(values);
    const dirty = !equal(running, comparableTelemetry(next));
    clear(preview);
    preview.appendChild(telemetryPreview(status, next, dirty, telemetryExportStatus));
    if (issues.length) {
      preview.appendChild(h("div", { class: "alert-box bad" },
        h("strong", {}, "Telemetry cannot be staged."),
        h("ul", { class: "compact-list" }, ...issues.map((issue) => h("li", {}, issue)))));
    }
    stageBtn.disabled = issues.length > 0;
    stageBtn.title = issues[0] || "Stage telemetry settings";
  };
  [enabled.querySelector("input"), clickhouseUrl, database, jsonFileEnabled.querySelector("input"), jsonFilePath, jsonStreamEnabled.querySelector("input"), jsonStreamTarget, jsonStreamProtocol].forEach((el) => {
    el.addEventListener("input", updatePreview);
    el.addEventListener("change", updatePreview);
  });
  updatePreview();

  return card(h("h2", {}, "Telemetry readiness", h("span", { class: "spacer" }),
      draftDirty ? pill("candidate edit", "warn", true) : null,
      pill(tel.enabled ? "local retention enabled" : "disabled", tel.enabled ? "ok" : "neutral", true)),
    preview,
    h("label", { class: "field flex", style: { justifyContent: "space-between" } },
      h("span", {}, "Enable ClickHouse local retention"),
      enabled),
    h("label", { class: "field" }, h("span", {}, "ClickHouse HTTP endpoint"), clickhouseUrl),
    h("label", { class: "field" }, h("span", {}, "Database"), database),
    h("label", { class: "field flex", style: { justifyContent: "space-between" } },
      h("span", {}, "Mirror parsed events to local JSON file"),
      jsonFileEnabled),
    h("label", { class: "field" }, h("span", {}, "JSON export path"), jsonFilePath),
    h("label", { class: "field flex", style: { justifyContent: "space-between" } },
      h("span", {}, "Stream parsed events to remote SIEM"),
      jsonStreamEnabled),
    h("label", { class: "field" }, h("span", {}, "Remote JSON target"), jsonStreamTarget),
    h("label", { class: "field" }, h("span", {}, "Remote JSON protocol"), jsonStreamProtocol),
    stageBtn);

  async function stageTelemetry() {
    const values = read();
    const issues = validateTelemetryInputs(values);
    if (issues.length) {
      updatePreview();
      toast("Telemetry cannot be staged", issues[0], "warn");
      return;
    }
    try {
      const next = telemetryFromInputs(values);
      await session.apply((draft) => {
        if (next) draft.telemetry = next;
        else delete draft.telemetry;
      });
      toast(next ? "Telemetry staged" : "Telemetry disabled", "Commit to update Vector -> ClickHouse retention.", "ok");
      paint(root, status, identity, oidc, accessAdministration, telemetryExportStatus, routeContext);
    } catch (e) {
      toast("Failed", e.message, "bad");
    }
  }
}

function telemetryPreview(status, telemetry, dirty, telemetryExportStatus = null) {
  const model = telemetryReadinessModel({ status, telemetry, dirty, exportStatus: telemetryExportStatus });
  return h("div", { class: "network-preview" },
    h("div", { class: "alert-box " + postureBoxClass(model.tone) },
      h("div", { class: "flex wrap", style: { justifyContent: "space-between" } },
        h("strong", {}, model.headline),
        pill(model.pipelineLabel, model.tone)),
      h("div", { class: "note" }, model.summary)),
    model.active && model.engineTone !== "ok" ? h("div", { class: "alert-box " + postureBoxClass(model.engineTone === "bad" ? "bad" : "warn") },
      h("strong", {}, "Vector runtime posture is " + model.engineState + "."),
      h("div", { class: "note" }, model.engineDetail)) : null,
    h("div", { class: "runtime-grid network-metrics" },
      networkMetric("Vector engine", pill(model.engineState, model.engineTone)),
      networkMetric("Passive status", model.passiveStatusAvailable
        ? pill(model.passiveState, model.passiveState === "degraded" ? "bad" : "warn")
        : model.passiveStatusStale ? pill("running only", "warn") : pill("unavailable", "neutral")),
      networkMetric("Endpoint", model.endpoint),
      networkMetric("Database", model.database),
      networkMetric("Telemetry delta", model.dirty ? pill("will change", "warn") : pill("matches running", "neutral"))),
    telemetryCapabilityTable(model.channels),
    h("div", { class: "alert-box info" },
      h("div", { class: "flex wrap", style: { justifyContent: "space-between", marginBottom: "8px" } },
        h("strong", {}, "Test-event / export-health evidence"),
        h("span", { class: "telemetry-evidence-actions" },
          h("button", { class: "btn sm ghost", type: "button", title: "Pin telemetry evidence plan to investigation case", "aria-label": "Pin telemetry evidence plan to investigation case", dataset: { telemetryAction: "pin-evidence-plan" }, onclick: () => pinTelemetryEvidencePlan(model) },
            h("span", { html: icon("inbox", 14) }), "Pin to case"),
          h("button", { class: "btn sm ghost", type: "button", title: "Copy telemetry evidence plan", "aria-label": "Copy telemetry evidence plan", dataset: { telemetryAction: "copy-evidence-plan" }, onclick: () => copyTelemetryEvidencePlan(model) },
            h("span", { html: icon("copy", 14) }), "Copy plan"),
          h("button", { class: "btn sm ghost", type: "button", title: "Export telemetry evidence JSON", "aria-label": "Export telemetry evidence JSON", dataset: { telemetryAction: "export-evidence-json" }, onclick: () => exportTelemetryEvidencePacket(model) },
            h("span", { html: icon("download", 14) }), "Export JSON"),
          h("button", {
            class: "btn sm ghost",
            type: "button",
            disabled: !telemetryServerProofAvailable(model),
            title: telemetryServerProofAvailable(model) ? "Send one server-side telemetry test event" : "Commit a telemetry export before sending a server-side test event",
            "aria-label": "Send server-side telemetry test event",
            dataset: { telemetryAction: "server-proof" },
            onclick: () => verifyTelemetryServerExport(model),
          }, h("span", { html: icon("check", 14) }), "Send test event"),
          h("button", {
            class: "btn sm ghost",
            type: "button",
            disabled: !model.exportSettings?.jsonStreamEnabled,
            title: model.exportSettings?.jsonStreamEnabled ? "Attach receiver-side SIEM evidence" : "Enable remote SIEM stream before attaching receiver proof",
            "aria-label": "Attach telemetry receiver proof",
            dataset: { telemetryAction: "receiver-proof" },
            onclick: () => openTelemetryReceiverProof(model),
          }, h("span", { html: icon("inbox", 14) }), "Attach receiver proof"))),
      h("ul", { class: "compact-list" }, model.healthChecks.map((check) => h("li", {}, check)))),
    h("div", { class: "alert-box warn" },
      h("strong", {}, "Export limitations"),
      h("ul", { class: "compact-list" }, model.limitations.map((limit) => h("li", {}, limit)))));
}

function telemetryServerProofAvailable(model = {}) {
  return Boolean(model.active && !model.dirty && (model.exportSettings?.jsonFileEnabled || model.exportSettings?.jsonStreamEnabled));
}

function telemetryServerProofRequest(model = {}) {
  if (model.exportSettings?.jsonStreamEnabled) {
    const udp = model.exportSettings.jsonStreamProtocol === "udp";
    return {
      exportName: "siem-json",
      type: udp ? "TELEMETRY_EXPORT_TYPE_JSON_UDP" : "TELEMETRY_EXPORT_TYPE_JSON_TCP",
      target: model.exportSettings.jsonStreamTarget || "",
      reason: "settings telemetry verification",
      ackTestEvent: true,
    };
  }
  return {
    exportName: "local-json",
    type: "TELEMETRY_EXPORT_TYPE_JSON_FILE",
    target: model.exportSettings?.jsonFilePath || "",
    reason: "settings telemetry verification",
    ackTestEvent: true,
  };
}

async function verifyTelemetryServerExport(model = {}) {
  if (!telemetryServerProofAvailable(model)) {
    toast("Telemetry test unavailable", "Commit a running telemetry export before sending a server-side test event.", "warn");
    return;
  }
  const req = telemetryServerProofRequest(model);
  const target = req.target || req.exportName;
  const ok = await confirmDialog({
    title: "Send telemetry test event?",
    message: `This sends one synthetic telemetry verification event to the configured running-policy export ${target}. Receiver-side custody and ClickHouse row delivery still require separate proof.`,
    confirmLabel: "Send test event",
  });
  if (!ok) return;
  try {
    const proof = await api.verifyTelemetryExport(req);
    openTelemetryServerProofResult(proof);
  } catch (e) {
    toast("Telemetry test failed", e.message || "The server-side telemetry proof event could not be sent.", "bad");
  }
}

function openTelemetryServerProofResult(proof = {}) {
  const p = proof.proof || {};
  openDrawer({
    title: "Telemetry test-event proof",
    subtitle: proof.state || "unknown",
    width: "640px",
    body: h("div", { class: "stack", dataset: { telemetryServerProof: proof.state || "unknown" } },
      h("div", { class: "alert-box " + postureBoxClass(proof.state === "delivered" || proof.state === "written" ? "ok" : proof.state === "failed" ? "bad" : "warn") },
        h("strong", {}, proof.state || "unknown"),
        h("div", { class: "note" }, proof.detail || "No server detail returned.")),
      h("div", { class: "table-wrap flat" },
        responsiveTable(["Field", "Value"], [
          proofRow("Proof ID", p.proofId || "-"),
          proofRow("Export", p.exportName || "-"),
          proofRow("Protocol", p.protocol || "-"),
          proofRow("Target", p.target || "-"),
          proofRow("Bytes", p.bytes ? String(p.bytes) : "0"),
          proofRow("Event hash", p.eventHash || "-"),
          proofRow("Evidence", p.evidence || "-"),
          proofRow("Warnings", (proof.warnings || []).join("; ") || "none"),
        ])),
      h("div", { class: "note" }, "This proves the appliance wrote or sent one synthetic event to the configured export. It does not prove SIEM ingestion, ClickHouse rows, signed custody, or retention.")),
    footer: [h("button", { class: "btn ghost", type: "button", title: "Close telemetry proof", "aria-label": "Close telemetry proof", dataset: { telemetryProofAction: "close-server-proof" }, onclick: closeDrawer }, "Close")],
  });
}

function proofRow(label, value) {
  return h("tr", {},
    labeledCell("Field", {}, h("strong", {}, label)),
    labeledCell("Value", { class: "mono data-wrap" }, value || "-"));
}

async function copyTelemetryEvidencePlan(model) {
  try {
    await navigator.clipboard.writeText(telemetryEvidenceText(model));
    toast("Telemetry evidence plan copied", "Post-commit telemetry checks copied as plain text.", "ok");
  } catch {
    toast("Copy failed", "Review the visible telemetry evidence checks before recording field evidence.", "warn");
  }
}

function telemetryInvestigationHandoffPacket(model = {}, receiverProof = null) {
  const packet = telemetryEvidencePacket(model, { route: settingsPanelHash("telemetry"), receiverProof });
  const channels = Array.isArray(model.channels) ? model.channels : [];
  return buildInvestigationPacket({
    kind: "telemetry-evidence",
    title: "Telemetry evidence handoff",
    subject: {
      id: "settings:telemetry",
      label: "Telemetry export readiness",
    },
    summary: {
      state: model.headline || model.pipelineLabel || "Telemetry readiness",
      pipeline: model.pipelineLabel || "off",
      active: Boolean(model.active),
      dirty: Boolean(model.dirty),
      engineState: model.engineState || "unknown",
      engineTone: model.engineTone || "neutral",
      passiveState: model.passiveStatusAvailable ? model.passiveState || "unknown" : model.passiveStatusStale ? "running only" : "unavailable",
      sinkCount: channels.length,
      observedSinkCount: channels.filter((channel) => channel.observed).length,
      receiverProofAttached: Boolean(packet.receiverProof),
    },
    evidence: telemetryEvidenceText(model, { receiverProof }).split("\n"),
    artifacts: { telemetryEvidence: packet },
  }, { route: packet.route || settingsPanelHash("telemetry"), collectedAt: packet.collectedAt });
}

function pinTelemetryEvidencePlan(model, receiverProof = null) {
  try {
    const result = pinInvestigationPacket(telemetryInvestigationHandoffPacket(model, receiverProof));
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Telemetry evidence could not be pinned.", "bad");
  }
}

function exportTelemetryEvidencePacket(model, receiverProof = null) {
  const blob = new Blob([telemetryEvidencePacketJson(model, { receiverProof })], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: telemetryEvidenceFilename() });
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  toast("Telemetry evidence exported", "Downloaded the redacted telemetry verification packet.", "ok");
}

function openTelemetryReceiverProof(model = {}) {
  const target = h("input", { class: "input", value: model.exportSettings?.jsonStreamTarget || "", placeholder: "siem.example:5514", dataset: { telemetryProofField: "target" } });
  const protocol = h("select", { class: "input", dataset: { telemetryProofField: "protocol" } },
    h("option", { value: "tcp" }, "TCP"),
    h("option", { value: "udp" }, "UDP"));
  protocol.value = model.exportSettings?.jsonStreamProtocol === "udp" ? "udp" : "tcp";
  const windowStart = h("input", { class: "input", placeholder: "2026-06-19T15:10:00Z", dataset: { telemetryProofField: "window-start" } });
  const windowEnd = h("input", { class: "input", placeholder: "2026-06-19T15:15:00Z", dataset: { telemetryProofField: "window-end" } });
  const observedEventCount = h("input", { class: "input", type: "number", min: "0", step: "1", placeholder: "0", dataset: { telemetryProofField: "event-count" } });
  const sampleEventHashes = h("textarea", { class: "input", rows: 3, placeholder: "one lowercase event hash per line", dataset: { telemetryProofField: "hashes" } });
  const collectedBy = h("input", { class: "input", placeholder: "SOC operator or system", dataset: { telemetryProofField: "collected-by" } });
  const commands = h("textarea", { class: "input", rows: 3, placeholder: "receiver-side commands or query IDs", dataset: { telemetryProofField: "commands" } });
  const notes = h("textarea", { class: "input", rows: 3, placeholder: "receiver-side observation notes", dataset: { telemetryProofField: "notes" } });
  const status = h("div", {});
  const copyBtn = h("button", { class: "btn ghost", type: "button", title: "Copy telemetry receiver proof", "aria-label": "Copy telemetry receiver proof", dataset: { telemetryProofAction: "copy" }, onclick: async () => {
    const proof = readTelemetryReceiverProof();
    if (!proof) return;
    try {
      await navigator.clipboard.writeText(telemetryEvidenceText(model, { receiverProof: proof }));
      toast("Receiver proof copied", "Telemetry evidence plan copied with receiver-side proof attached.", "ok");
    } catch {
      toast("Copy failed", "Receiver proof is still visible in the drawer.", "warn");
    }
  } }, h("span", { html: icon("copy", 16) }), "Copy proof");
  const exportBtn = h("button", { class: "btn ghost", type: "button", title: "Export telemetry receiver proof JSON", "aria-label": "Export telemetry receiver proof JSON", dataset: { telemetryProofAction: "export" }, onclick: () => {
    const proof = readTelemetryReceiverProof();
    if (proof) exportTelemetryEvidencePacket(model, proof);
  } }, h("span", { html: icon("download", 16) }), "Export JSON");
  const pinBtn = h("button", { class: "btn primary", type: "button", title: "Pin telemetry receiver proof to investigation case", "aria-label": "Pin telemetry receiver proof to investigation case", dataset: { telemetryProofAction: "pin" }, onclick: () => {
    const proof = readTelemetryReceiverProof();
    if (proof) pinTelemetryEvidencePlan(model, proof);
  } }, h("span", { html: icon("inbox", 16) }), "Pin to case");

  const update = () => {
    const proof = buildProof();
    const issues = validateTelemetryReceiverProof(proof);
    clear(status);
    if (issues.length) {
      status.appendChild(h("div", { class: "alert-box warn", style: { marginBottom: 0 } },
        h("strong", {}, "Receiver proof is incomplete."),
        h("ul", { class: "compact-list" }, ...issues.map((issue) => h("li", {}, issue)))));
    } else {
      status.appendChild(h("div", { class: "alert-box ok", style: { marginBottom: 0 } },
        h("strong", {}, "Receiver proof ready."),
        h("div", { class: "note" }, `${proof.observedEventCount} event(s) observed at ${proof.target} during ${proof.windowStart}..${proof.windowEnd}.`)));
    }
    copyBtn.disabled = exportBtn.disabled = pinBtn.disabled = issues.length > 0;
  };
  [target, protocol, windowStart, windowEnd, observedEventCount, sampleEventHashes, collectedBy, commands, notes].forEach((el) => {
    el.addEventListener("input", update);
    el.addEventListener("change", update);
  });
  update();

  openDrawer({
    title: "Attach SIEM receiver proof",
    subtitle: "Receiver proof is operator supplied; passive status never dials the remote SIEM.",
    body: h("div", { dataset: { telemetryProofDrawer: "true" } },
      h("div", { class: "alert-box info" },
        h("strong", {}, "Receiver-side handoff"),
        h("div", { class: "note" }, "Attach counts, sample event hashes, and receiver commands after the SIEM listener confirms newline-delimited JSON events.")),
      h("label", { class: "field" }, h("span", {}, "Receiver target"), target),
      h("label", { class: "field" }, h("span", {}, "Protocol"), protocol),
      h("label", { class: "field" }, h("span", {}, "Window start"), windowStart),
      h("label", { class: "field" }, h("span", {}, "Window end"), windowEnd),
      h("label", { class: "field" }, h("span", {}, "Observed event count"), observedEventCount),
      h("label", { class: "field" }, h("span", {}, "Sample event hashes"), sampleEventHashes),
      h("label", { class: "field" }, h("span", {}, "Collected by"), collectedBy),
      h("label", { class: "field" }, h("span", {}, "Receiver commands"), commands),
      h("label", { class: "field" }, h("span", {}, "Notes"), notes),
      status),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close telemetry receiver proof drawer", "aria-label": "Close telemetry receiver proof drawer", dataset: { telemetryProofAction: "close" }, onclick: closeDrawer }, "Close"),
      copyBtn,
      exportBtn,
      pinBtn,
    ],
    width: "560px",
  });

  function buildProof() {
    return telemetryReceiverProofFromInputs({
      target: target.value,
      protocol: protocol.value,
      windowStart: windowStart.value,
      windowEnd: windowEnd.value,
      observedEventCount: observedEventCount.value,
      sampleEventHashes: sampleEventHashes.value,
      collectedBy: collectedBy.value,
      commands: commands.value,
      notes: notes.value,
    }, model);
  }

  function readTelemetryReceiverProof() {
    const proof = buildProof();
    const issues = validateTelemetryReceiverProof(proof);
    if (issues.length) {
      toast("Receiver proof incomplete", issues[0], "warn");
      update();
      return null;
    }
    return proof;
  }
}

function telemetryCapabilityTable(channels = []) {
  return h("div", { class: "table-wrap flat" },
    responsiveTable(["Capability", "Status", "Operator note"],
      channels.map((channel) => h("tr", {},
        labeledCell("Capability", {}, channel.label),
        labeledCell("Status", {}, pill(channel.statusLabel, channel.tone)),
        labeledCell("Operator note", { class: "note" }, channel.detail))),
      { className: "settings-telemetry-capability-table" }));
}

function systemCard(status) {
  const rt = status.runtime || {};
  return card(h("h2", {}, "System"),
    h("dl", { class: "kv" },
      h("dt", {}, "Daemon"), h("dd", {}, "controld"),
      h("dt", {}, "Version"), h("dd", { class: "mono" }, rt.version || "—"),
      h("dt", {}, "Commit"), h("dd", { class: "mono" }, rt.commit || "—"),
      h("dt", {}, "Built"), h("dd", { class: "mono" }, rt.buildDate || "—"),
      h("dt", {}, "Started"), h("dd", { class: "mono" }, rt.startedAt || "—"),
      h("dt", {}, "gRPC"), h("dd", { class: "mono" }, rt.grpcListen || "—"),
      h("dt", {}, "WebUI / REST"), h("dd", { class: "mono" }, rt.httpListen || "—"),
      h("dt", {}, "TLS / Auth / Dry-run"), h("dd", {}, `${yesNo(rt.tlsEnabled)} / ${yesNo(rt.authEnabled)} / ${yesNo(rt.dryRun)}`),
      h("dt", {}, "Data directory"), h("dd", { class: "mono" }, rt.dataDir || "—"),
      h("dt", {}, "Log directory"), h("dd", { class: "mono" }, rt.logDir || "—"),
      h("dt", {}, "Running policy"), h("dd", { class: "mono" }, "v" + session.runningVersion)));
}

function appearanceCard() {
  const seg = h("div", { class: "seg" },
    themeBtn("Dark", "dark"), themeBtn("Light", "light"));
  return card(h("h2", {}, "Appearance"),
    h("label", { class: "field" }, h("span", {}, "Theme"), seg));
}
function themeBtn(label, val) {
  return h("button", { class: getTheme() === val ? "active" : "", type: "button", title: `Use ${label} theme`, "aria-label": `Use ${label} theme`, dataset: { settingsThemeAction: val }, onclick: (e) => {
    setTheme(val);
    e.target.parentElement.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b === e.target));
  } }, label);
}

function networkCard(root, status, routeContext = defaultSettingsRouteContext()) {
  const n = structuredClone(session.draft.network || {});
  const inspectionOn = idsEnabled(session.draft);
  const mtu = h("input", { class: "input", type: "number", min: "0", max: String(MAX_MTU), placeholder: "0 = unmanaged", value: n.mtu || "", dataset: { settingsNetworkField: "global-mtu" } });
  const mtuModel = interfaceMtuEditorModel(n, session.draft);
  const mtuRows = interfaceMtuRows(mtuModel.rows);
  const customMtus = h("textarea", { class: "input", placeholder: "mgmt0=1500\nha0=9000", rows: 2, dataset: { settingsNetworkField: "custom-interface-mtus" } });
  customMtus.value = mtuModel.customText;
  const mss = checkbox(!!n.clampMssToPmtu);
  const offload = checkbox(!!n.manageNicOffloads);
  const flow = checkbox(!!n.enableFlowOffload, { disabled: inspectionOn && !n.enableFlowOffload });
  const preview = h("div", {});
  const profileHost = h("div", {});
  const stageBtn = h("button", { class: "btn primary", type: "button", title: "Stage network settings", "aria-label": "Stage network settings to candidate", dataset: { settingsNetworkAction: "stage" }, onclick: () => stageNetwork() }, h("span", { html: icon("check", 16) }), "Stage network settings");
  mss.dataset.settingsNetworkField = "clamp-mss";
  offload.dataset.settingsNetworkField = "manage-offloads";
  flow.dataset.settingsNetworkField = "flow-offload";
  const updatePreview = () => {
    const policy = previewPolicy(mtu, mtuRows, customMtus, mss, offload, flow);
    const posture = dataplanePosture(policy, status);
    const issues = networkCandidateIssues(policy);
    clear(preview);
    clear(profileHost);
    profileHost.appendChild(networkProfileSelector(inspectionOn, readNetworkInputs(mtu, mtuRows, customMtus, mss, offload, flow), applyProfile));
    preview.appendChild(networkPreview(status, policy, posture));
    if (issues.length) {
      preview.appendChild(h("div", { class: "alert-box bad" },
        h("strong", {}, "Network settings cannot be staged."),
        h("ul", { class: "compact-list" }, ...issues.map((issue) => h("li", {}, issue)))));
    }
    stageBtn.disabled = issues.length > 0;
    stageBtn.title = issues[0] || "Stage network settings";
  };
  const applyProfile = (profileId) => {
    const next = applyNetworkProfile(readNetworkInputs(mtu, mtuRows, customMtus, mss, offload, flow), profileId);
    writeNetworkInputs(next, mtu, mtuRows, customMtus, mss, offload, flow);
    updatePreview();
  };
  [mtu, ...mtuRows.map((row) => row.input), customMtus, mss.querySelector("input"), offload.querySelector("input"), flow.querySelector("input")]
    .filter(Boolean)
    .forEach((el) => {
      el.addEventListener("input", updatePreview);
      el.addEventListener("change", updatePreview);
    });
  updatePreview();
  return card(h("h2", {}, "Dataplane (global network)"),
    preview,
    profileHost,
    h("label", { class: "field" }, h("span", {}, "Global MTU ", h("span", { class: "help" }, `— e.g. 9000 for jumbo frames; 0 leaves MTUs unmanaged; valid ${MIN_MTU}-${MAX_MTU}`)), mtu),
    h("label", { class: "field" }, h("span", {}, "Per-interface MTU ", h("span", { class: "help" }, "— blank inherits global/unmanaged")), interfaceMtuEditor(mtuRows)),
    h("label", { class: "field" }, h("span", {}, "Additional interface MTUs ", h("span", { class: "help" }, "— one per line, interface=mtu; may name management interfaces")), customMtus),
    h("label", { class: "field flex", style: { justifyContent: "space-between" } }, h("span", {}, "Clamp TCP MSS to path MTU ", h("span", { class: "help" }, "— recommended with jumbo frames / VPN")), mss),
    h("label", { class: "field flex", style: { justifyContent: "space-between" } }, h("span", {}, "Manage NIC offloads ", h("span", { class: "help" }, "— disable GRO/LRO/TSO/GSO on IDS interfaces")), offload),
    h("label", { class: "field flex", style: { justifyContent: "space-between" } },
      h("span", {}, "Flowtable fast path ", h("span", { class: "help" }, inspectionOn && !n.enableFlowOffload
        ? `— unavailable while ${idsModeLabel(session.draft)} is enabled`
        : "— accelerates established L3/L4 flows; rejected when IDS/IPS is enabled")),
      flow),
    stageBtn);

  async function stageNetwork() {
    const policy = previewPolicy(mtu, mtuRows, customMtus, mss, offload, flow);
    const issues = networkCandidateIssues(policy);
    if (issues.length) {
      updatePreview();
      toast("Network settings cannot be staged", issues[0], "warn");
      return;
    }
    try {
      await session.apply((d) => {
        applyNetworkInputs(d, readNetworkInputs(mtu, mtuRows, customMtus, mss, offload, flow));
      });
      toast("Network settings staged", "Commit to apply to the dataplane.", "ok");
    } catch (e) { toast("Failed", e.message, "bad"); }
  }
}

function networkProfileSelector(inspectionOn, network, onApply) {
  const current = matchingNetworkProfile(network);
  return h("div", { class: "profile-strip" },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Operating profile"),
      h("span", {}, current ? current.title : "Custom settings")),
    h("div", { class: "profile-options" }, NETWORK_PROFILES.map((profile) => {
      const blocked = Boolean(profile.requiresInspectionOff && inspectionOn);
      const active = current?.id === profile.id;
      return h("button", {
        class: "profile-option " + (active ? "active " : "") + (blocked ? "disabled" : ""),
        type: "button",
        dataset: { settingsNetworkProfile: profile.id },
        disabled: blocked,
        title: blocked ? "Turn off IDS/IPS before enabling the forwarding throughput profile." : profile.detail,
        "aria-label": `Apply ${profile.title} network profile`,
        onclick: () => onApply(profile.id),
      },
        h("span", {}, profile.title),
        h("small", {}, blocked ? "Unavailable with IDS/IPS enabled" : profile.detail));
    })));
}

function hostInputCard(root, status, identity, oidc, accessAdministration, routeContext = defaultSettingsRouteContext()) {
  const host = session.draft.hostInput || {};
  const rules = host.rules || [];
  const focusedIdx = focusedHostInputRuleIndex(routeContext, rules);
  const focusIssue = hostInputFocusIssue(routeContext, rules);
  const defaultAction = h("select", { class: "input" },
    option("ACTION_ALLOW", "Allow by default"),
    option("ACTION_DENY", "Drop by default"));
  defaultAction.dataset.hostInputField = "default-action";
  defaultAction.value = hostInputDefault(host);
  const hardened = defaultAction.value === "ACTION_DENY";
  const coverage = hostInputManagementCoverage({ ...session.draft, hostInput: host }, status);
  const ruleRows = rules.length ? h("div", { class: "table-wrap flat" },
    responsiveTable(["Rule", "Source", "Services", "Action", { label: "", attrs: { class: "actions-col" } }],
      rules.map((rule, idx) => hostInputRuleRow(root, status, identity, oidc, accessAdministration, routeContext, rule, idx, focusedIdx)))) :
    h("div", { class: "empty compact" }, "No host-input rules.");

  return card(h("h2", {}, "Host input", h("span", { class: "spacer" }), pill(hardened ? "hardened" : "open", hardened ? "ok" : "warn", true)),
    h("div", { class: "alert-box " + (hardened ? "ok" : "warn") },
      h("strong", {}, hardened ? "Management-plane traffic is dropped unless a rule allows it." : "Host input is allow-by-default."),
      h("div", { class: "note" }, hardened ? "Loopback and established return traffic remain allowed before host-input rules." : "Set default drop before exposing the appliance outside a trusted lab.")),
    h("div", { class: "alert-box " + postureBoxClass(coverage.cls) },
      h("strong", {}, coverage.title),
      h("div", { class: "note" }, coverage.detail),
      h("div", { class: "note mono" }, "Required: " + coverage.requiredServices.map((svc) => `${svc.label} tcp/${svc.port}`).join(", ")),
      coverage.allowRules.length ? h("div", { class: "note" }, "Covering rule(s): " + coverage.allowRules.join(", ")) : null),
    h("label", { class: "field" }, h("span", {}, "Default host-input action"), defaultAction),
    focusIssue ? hostInputFocusIssueAlert(focusIssue) : null,
    ruleRows,
    h("div", { class: "flex wrap", style: { marginTop: "12px" } },
      h("button", { class: "btn primary", type: "button", title: "Stage host-input default action", "aria-label": "Stage host-input default action to candidate", dataset: { hostInputAction: "stage-default" }, onclick: async () => stageHostInputDefault(root, status, identity, oidc, accessAdministration, routeContext, defaultAction.value) }, h("span", { html: icon("check", 16) }), "Stage default"),
      h("button", { class: "btn", type: "button", title: "Add host-input rule", "aria-label": "Add host-input rule to candidate", dataset: { hostInputAction: "add-rule" }, onclick: () => openHostInputRuleEditor(root, status, identity, oidc, accessAdministration, routeContext, -1) }, h("span", { html: icon("plus", 16) }), "Add rule"),
      h("button", { class: "btn", type: "button", title: "Add management allow rule", "aria-label": "Add host-input management allow rule to candidate", dataset: { hostInputAction: "add-management-allow" }, onclick: () => openHostInputRuleEditor(root, status, identity, oidc, accessAdministration, routeContext, -1, managementRuleTemplate(session.draft, status)) }, h("span", { html: icon("shield", 16) }), "Add management allow")));
}

function hostInputRuleRow(root, status, identity, oidc, accessAdministration, routeContext, rule, idx, focusedIdx = -1) {
  const ruleLabel = rule.name || `rule ${idx + 1}`;
  const id = hostInputRuleDurableId(rule);
  const source = [
    (rule.fromZones || []).length ? "zones: " + rule.fromZones.join(", ") : "zones: any",
    (rule.sourceAddresses || []).length ? "sources: " + rule.sourceAddresses.join(", ") : "",
  ].filter(Boolean).join(" | ");
  const attrs = {
    class: focusedIdx === idx ? "selected-row" : "",
    tabindex: "-1",
    dataset: {
      hostInputRule: rule.name || String(idx),
      hostInputRuleIndex: String(idx),
      hostInputRuleId: id,
    },
  };
  if (focusedIdx === idx) {
    attrs["aria-current"] = "true";
    attrs.style = { background: "color-mix(in srgb, var(--accent-bg) 55%, transparent)" };
  }

  return h("tr", attrs,
    labeledCell("Rule",
      h("strong", {}, rule.name || "unnamed"),
      id ? h("div", { class: "note mono", title: "Durable policy item ID" }, `ID ${id}`) : h("div", { class: "note" }, `legacy target #${idx + 1}`),
      rule.disabled ? h("div", { class: "note" }, "disabled") : null),
    labeledCell("Source", { class: "mono" }, source),
    labeledCell("Services", { class: "mono" }, (rule.services || []).length ? rule.services.join(", ") : "any"),
    labeledCell("Action", pill(actionLabel(rule.action), actionClass(rule.action))),
    labeledCell("Actions", { class: "cell-actions" },
      h("div", { class: "row-actions" },
        id ? h("button", { class: "icon-btn", type: "button", title: "Copy durable host-input route", "aria-label": `Copy durable host-input route ${ruleLabel}`, dataset: { hostInputAction: "copy-rule-route", hostInputRuleId: id }, onclick: () => copyHostInputRuleRoute(routeContext, rule, idx), html: icon("copy", 16) }) : null,
        h("button", { class: "icon-btn", type: "button", title: "Edit host-input rule", "aria-label": `Edit host-input rule ${ruleLabel}`, dataset: { hostInputAction: "edit-rule" }, onclick: () => openHostInputRuleEditor(root, status, identity, oidc, accessAdministration, routeContext, idx), html: icon("edit", 16) }),
        h("button", { class: "icon-btn", type: "button", title: "Delete host-input rule", "aria-label": `Delete host-input rule ${ruleLabel}`, dataset: { hostInputAction: "delete-rule" }, onclick: () => deleteHostInputRule(root, status, identity, oidc, accessAdministration, routeContext, idx), html: icon("trash", 16) }))));
}

async function copyHostInputRuleRoute(routeContext = defaultSettingsRouteContext(), rule = {}, idx = 0) {
  const id = hostInputRuleDurableId(rule);
  const route = hostInputRuleRouteHash(rule, idx, routeContext.routePath || "/settings");
  const body = [
    `Host input ${rule.name || "unnamed"}`,
    id ? `id=${id}` : "",
    `route=${route}`,
  ].filter(Boolean).join("\n");
  try {
    if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(body);
    toast("Host-input identity copied", "Durable host-input ID and route copied.", "ok");
  } catch {
    toast("Copy unavailable", "Open the row and copy the ID from the table.", "warn");
  }
}

async function stageHostInputDefault(root, status, identity, oidc, accessAdministration, routeContext, value) {
  const nextHost = { ...(session.draft.hostInput || {}), defaultAction: value };
  const coverage = hostInputManagementCoverage({ ...session.draft, hostInput: nextHost }, status);
  if (coverage.state === "lockout" || coverage.state === "unverified") {
    toast("Management allow required", coverage.detail, "warn");
    openHostInputRuleEditor(root, status, identity, oidc, accessAdministration, routeContext, -1, managementRuleTemplate(session.draft, status));
    return;
  }
  try {
    await session.apply((draft) => {
      setHostInput(draft, nextHost);
    });
    toast("Host input staged", "Commit to apply host-input policy to the appliance.", "ok");
    paint(root, status, identity, oidc, accessAdministration, null, routeContext);
  } catch (e) {
    toast("Failed", e.message, "bad");
  }
}

function openHostInputRuleEditor(root, status, identity, oidc, accessAdministration, routeContext, index, template = {}) {
  const existing = index >= 0 ? structuredClone((session.draft.hostInput?.rules || [])[index] || {}) : structuredClone(template || {});
  const zones = (session.draft.zones || []).map((z) => z.name);
  const name = h("input", { class: "input", value: existing.name || "", placeholder: "allow-lan-management", dataset: { hostInputField: "rule-name" } });
  const fromZones = h("input", { class: "input", value: (existing.fromZones || []).join(", "), placeholder: zones.includes("lan") ? "lan" : "any", dataset: { hostInputField: "rule-from-zones" } });
  const sources = h("input", { class: "input", value: (existing.sourceAddresses || []).join(", "), placeholder: "admin-net or any", dataset: { hostInputField: "rule-source-addresses" } });
  const services = h("input", { class: "input", value: (existing.services || []).join(", "), placeholder: "ssh, https", dataset: { hostInputField: "rule-services" } });
  const action = h("select", { class: "input" },
    option("ACTION_ALLOW", "Allow"),
    option("ACTION_DENY", "Drop"),
    option("ACTION_REJECT", "Reject"));
  action.dataset.hostInputField = "rule-action";
  action.value = existing.action || "ACTION_ALLOW";
  const log = checkbox(Boolean(existing.log));
  log.dataset.hostInputField = "rule-log";
  const disabled = checkbox(Boolean(existing.disabled));
  disabled.dataset.hostInputField = "rule-disabled";
  const description = h("textarea", { class: "input", placeholder: "Why this host-input rule exists", dataset: { hostInputField: "rule-description" } }, existing.description || "");

  openDrawer({
    title: index >= 0 ? "Edit host-input rule" : "Add host-input rule",
    subtitle: "Rules apply only to traffic destined to the firewall appliance.",
    body: h("div", {},
      h("label", { class: "field" }, h("span", {}, "Name"), name),
      h("label", { class: "field" }, h("span", {}, "From zones"), fromZones),
      h("label", { class: "field" }, h("span", {}, "Source address objects"), sources),
      h("label", { class: "field" }, h("span", {}, "Services"), services),
      h("label", { class: "field" }, h("span", {}, "Action"), action),
      h("label", { class: "field flex", style: { justifyContent: "space-between" } }, h("span", {}, "Log matches"), log),
      h("label", { class: "field flex", style: { justifyContent: "space-between" } }, h("span", {}, "Disabled"), disabled),
      h("label", { class: "field" }, h("span", {}, "Description"), description)),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Cancel host-input rule edit", "aria-label": "Cancel host-input rule edit", dataset: { hostInputAction: "cancel-rule" }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: index >= 0 ? "Stage host-input rule changes" : "Stage new host-input rule", "aria-label": index >= 0 ? "Stage host-input rule changes to candidate" : "Stage new host-input rule to candidate", dataset: { hostInputAction: "stage-rule" }, onclick: async () => {
        const rule = {
          name: name.value.trim(),
          fromZones: csvList(fromZones.value),
          sourceAddresses: csvList(sources.value),
          services: csvList(services.value),
          action: action.value,
          log: log.checked,
          disabled: disabled.checked,
          description: description.value.trim(),
        };
        if (existing.id) rule.id = existing.id;
        const nextHost = { ...(session.draft.hostInput || {}) };
        nextHost.rules = [...(nextHost.rules || [])];
        if (index >= 0) nextHost.rules[index] = rule;
        else nextHost.rules.push(rule);
        const coverage = hostInputManagementCoverage({ ...session.draft, hostInput: nextHost }, status);
        if (coverage.state === "lockout" || coverage.state === "unverified") {
          toast("Management allow required", coverage.detail, "warn");
          return;
        }
        try {
          await session.apply((draft) => {
            setHostInput(draft, nextHost);
          });
          closeDrawer();
          toast("Host-input rule staged", "Commit to apply the host-input policy.", "ok");
          paint(root, status, identity, oidc, accessAdministration, null, routeContext);
        } catch (e) {
          toast("Failed", e.message, "bad");
        }
      } }, "Stage rule"),
    ],
  });
}

async function deleteHostInputRule(root, status, identity, oidc, accessAdministration, routeContext, index) {
  const rule = (session.draft.hostInput?.rules || [])[index];
  if (!rule) return;
  const ok = await confirmDialog({
    title: "Delete host-input rule",
    message: `Remove ${rule.name || "this rule"} from the candidate policy?`,
    confirmLabel: "Delete",
    danger: true,
  });
  if (!ok) return;
  const nextHost = { ...(session.draft.hostInput || {}) };
  nextHost.rules = [...(nextHost.rules || [])];
  nextHost.rules.splice(index, 1);
  const coverage = hostInputManagementCoverage({ ...session.draft, hostInput: nextHost }, status);
  if (coverage.state === "lockout" || coverage.state === "unverified") {
    toast("Management allow required", "Add another SSH/WebUI management allow rule before deleting this one.", "warn");
    return;
  }
  try {
    await session.apply((draft) => {
      setHostInput(draft, nextHost);
    });
    toast("Host-input rule removed", "Commit to apply the host-input policy.", "ok");
    paint(root, status, identity, oidc, accessAdministration, null, routeContext);
  } catch (e) {
    toast("Failed", e.message, "bad");
  }
}

function normalizeHostInput(host = {}) {
  const next = {
    defaultAction: host.defaultAction || "ACTION_ALLOW",
    rules: (host.rules || []).filter(Boolean),
  };
  if (next.defaultAction === "ACTION_ALLOW" && next.rules.length === 0) return undefined;
  return next;
}

function setHostInput(draft, host) {
  const next = normalizeHostInput(host);
  if (next) draft.hostInput = next;
  else delete draft.hostInput;
}

function hostInputDefault(host = {}) {
  return host.defaultAction || "ACTION_ALLOW";
}

function csvList(value) {
  return String(value || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)
    .filter((x) => x !== "any");
}

function actionLabel(action) {
  if (action === "ACTION_DENY") return "drop";
  if (action === "ACTION_REJECT") return "reject";
  return "allow";
}

function actionClass(action) {
  if (action === "ACTION_ALLOW") return "ok";
  return "bad";
}

function option(value, label) {
  return h("option", { value }, label);
}

function readNetworkInputs(mtu, mtuRows, customMtus, mss, offload, flow) {
  const v = parseInt(mtu.value, 10);
  return {
    mtu: Number.isFinite(v) && v > 0 ? v : 0,
    interfaceMtus: readInterfaceMtus(mtuRows, customMtus.value),
    clampMssToPmtu: mss.checked,
    manageNicOffloads: offload.checked,
    enableFlowOffload: flow.checked,
  };
}

function writeNetworkInputs(network, mtu, mtuRows, customMtus, mss, offload, flow) {
  mtu.value = network?.mtu || "";
  for (const row of mtuRows) {
    const override = (network?.interfaceMtus || []).find((item) => item.interface === row.iface);
    row.input.value = override?.mtu || "";
  }
  customMtus.value = (network?.interfaceMtus || [])
    .filter((item) => !mtuRows.some((row) => row.iface === item.interface))
    .map((item) => `${item.interface}=${item.mtu}`)
    .join("\n");
  setCheckbox(mss, Boolean(network?.clampMssToPmtu));
  setCheckbox(offload, Boolean(network?.manageNicOffloads));
  setCheckbox(flow, Boolean(network?.enableFlowOffload));
}

function setCheckbox(label, checked) {
  const input = label.querySelector("input");
  if (input && !input.disabled) input.checked = checked;
}

function previewPolicy(mtu, mtuRows, customMtus, mss, offload, flow) {
  const policy = structuredClone(session.draft || {});
  applyNetworkInputs(policy, readNetworkInputs(mtu, mtuRows, customMtus, mss, offload, flow));
  return policy;
}

function applyNetworkInputs(policy, values) {
  const next = { ...(policy.network || {}), ...values };
  if (networkHasConfig(next)) policy.network = next;
  else delete policy.network;
}

function networkHasConfig(network = {}) {
  return Boolean(
    Number(network.mtu) > 0 ||
    (network.interfaceMtus || []).length ||
    network.clampMssToPmtu ||
    network.manageNicOffloads ||
    network.enableFlowOffload
  );
}

function networkPreview(status, policy, posture) {
  const host = flowtableHostReadiness(status);
  const devices = zoneInterfaces(policy);
  const mtuOverrides = policy.network?.interfaceMtus || [];
  const dirty = !equal(comparableNetwork((session.running || {}).network), comparableNetwork(policy.network));
  return h("div", { class: "network-preview" },
    h("div", { class: "alert-box " + postureBoxClass(posture.cls) },
      h("div", { class: "flex wrap", style: { justifyContent: "space-between" } },
        h("strong", {}, posture.summary),
        pill(posture.label, posture.cls)),
      h("div", { class: "note" }, posture.detail)),
    posture.accelerated && !host.ready ? h("div", { class: "alert-box warn" },
      h("strong", {}, "Host flowtable readiness is " + host.state + "."),
      h("div", { class: "note" }, host.detail)) : null,
    h("div", { class: "runtime-grid network-metrics" },
      networkMetric("Host flowtable", pill(host.label, host.cls)),
      networkMetric("Fast-path interfaces", devices.length ? devices.join(", ") : "none"),
      networkMetric("MTU overrides", mtuOverrides.length ? mtuOverrides.map((x) => `${x.interface}:${x.mtu}`).join(", ") : "none"),
      networkMetric("Network delta", dirty ? pill("will change", "warn") : pill("matches running", "neutral"))));
}

function networkMetric(label, value) {
  return h("div", { class: "posture-metric" },
    h("span", {}, label),
    h("strong", {}, value));
}

function comparableNetwork(network = {}) {
  return {
    mtu: Number(network?.mtu) || 0,
    interfaceMtus: normalizeInterfaceMtus(network?.interfaceMtus || []),
    clampMssToPmtu: Boolean(network?.clampMssToPmtu),
    manageNicOffloads: Boolean(network?.manageNicOffloads),
    enableFlowOffload: Boolean(network?.enableFlowOffload),
  };
}

function interfaceMtuRows(rows = []) {
  return rows.map((row) => ({
    iface: row.iface,
    input: h("input", {
      class: "input",
      type: "number",
      min: "0",
      max: String(MAX_MTU),
      placeholder: "inherit",
      value: row.mtu || "",
      dataset: { settingsNetworkInterfaceMtu: row.iface },
    }),
  }));
}

function interfaceMtuEditor(rows) {
  if (!rows.length) {
    return h("div", { class: "alert-box info", style: { marginBottom: 0 } },
      h("strong", {}, "No zone interfaces yet."),
      h("div", { class: "note" }, "Add interfaces to zones in Policy -> Objects, or use Additional interface MTUs for management-only interfaces."));
  }
  return h("div", { class: "table-wrap flat" },
    responsiveTable(["Interface", "MTU override"],
      rows.map((row) => h("tr", {},
        labeledCell("Interface", { class: "mono" }, row.iface),
        labeledCell("MTU override", {}, row.input))),
      { className: "settings-interface-mtu-table" }));
}

function readInterfaceMtus(rows = [], customText = "") {
  const fixed = rows.map((row) => {
    const raw = row.input.value.trim();
    if (!raw) return null;
    const mtu = parseInt(raw, 10);
    return { interface: row.iface, mtu: Number.isFinite(mtu) ? mtu : 0 };
  }).filter(Boolean);
  return [...fixed, ...parseCustomInterfaceMtus(customText)];
}

function checkbox(on, opts = {}) {
  const i = h("input", { type: "checkbox", disabled: opts.disabled });
  i.checked = on;
  const l = h("label", { class: "switch" + (opts.disabled ? " disabled" : "") }, i, h("span", { class: "slider" }));
  l.checked = on;
  Object.defineProperty(l, "checked", { get: () => i.checked });
  Object.defineProperty(l, "disabled", { get: () => i.disabled });
  return l;
}

function postureBoxClass(cls) {
  if (cls === "bad" || cls === "warn" || cls === "ok" || cls === "info") return cls;
  return "";
}

function accessCard(root, status, identity, oidc = {}, saml = {}, accessAdministration, telemetryExportStatus = null, routeContext = defaultSettingsRouteContext()) {
  const rt = status.runtime || {};
  const tok = h("input", { class: "input", type: "password", placeholder: "Session-only bearer token (leave blank if auth disabled)", value: getToken() });
  const identityNode = h("div", {});
  const governanceNode = h("div", {});
  const renderAccessState = (id) => {
    renderIdentity(identityNode, id, rt);
    renderAccessGovernance(governanceNode, rt, id, oidc, accessAdministration, { root, status, identity: id, oidc, saml, telemetryExportStatus, routeContext });
  };
  renderAccessState(identity);
  return card(h("h2", {}, "API access"),
    h("p", { class: "note" }, "Runtime auth is ", h("strong", {}, runtimeBool(rt, "authEnabled")), ". TLS is ", h("strong", {}, runtimeBool(rt, "tlsEnabled")), "."),
    accessPostureStrip(rt, oidc, saml, identity),
    oidc?.enabled || saml?.enabled ? browserSSOAccess(identityNode, governanceNode, rt, oidc, saml, identity, accessAdministration, { root, status, telemetryExportStatus, routeContext }) : null,
    h("p", { class: "note settings-access-browser-sso-note" }, "Browser SSO is the preferred path when OIDC or SAML is enabled. API tokens remain available for break-glass, CLI, and automation access. A token saved here is kept only for this browser session and sent as ", h("span", { class: "mono" }, "Authorization: Bearer …"), "."),
    identityNode,
    governanceNode,
    h("label", { class: "field" }, h("span", {}, "API token"), tok),
    h("div", { class: "flex" },
      h("button", { class: "btn primary", type: "button", title: "Save session API token", "aria-label": "Save session API token", "data-access-action": "save-session-token", onclick: async () => {
        const candidate = tok.value.trim();
        if (!candidate) {
          setToken("");
          renderAccessState(null);
          toast("Token cleared", "", "ok");
          return;
        }
        try {
          const id = await api.identityWithToken(candidate);
          setToken(candidate);
          renderAccessState(id);
          toast("Token saved for this session", `${id.actor || "unknown"} (${id.role || "unknown"}) verified.`, "ok");
        }
        catch (e) {
          toast("Token rejected", `${e.message}. The candidate token was not saved.`, "bad");
          tok.focus();
        }
      } }, "Save token"),
      h("button", { class: "btn ghost", type: "button", title: "Clear session access token", "aria-label": "Clear session access token", "data-access-action": "clear-session-token", onclick: () => {
        setToken("");
        tok.value = "";
        renderAccessState(null);
        toast("Token cleared", "", "ok");
      } }, "Clear")));
}

function accessPostureStrip(rt, oidc, saml, identity) {
  return h("div", { class: "access-posture", dataset: { accessPosture: "oidc" } },
    oidcAccessPosture(rt, oidc, identity, saml).map((item) => h("div", {
      class: "access-posture-item " + item.tone,
      dataset: { accessPostureItem: item.id },
    },
      h("span", {}, item.label),
      h("strong", {}, item.value),
      h("small", {}, item.detail))));
}

function browserSSOAccess(identityNode, governanceNode, rt, oidc, saml, identity, accessAdministration, opts = {}) {
  const oidcReady = Boolean(oidc?.enabled && (oidc.loginUrl || oidc.login_url));
  const samlReady = Boolean(saml?.enabled && (saml.runtimeAvailable ?? saml.runtime_available ?? true) && (saml.loginUrl || saml.login_url));
  return h("div", { class: "alert-box info" },
    h("strong", {}, "Browser SSO is enabled and preferred. "),
    h("div", { class: "note" }, "Browser sessions use an HTTP-only cookie and the same RBAC/audit path as API tokens."),
    h("div", { class: "flex", style: { marginTop: "10px" } },
      oidcReady ? h("button", { class: "btn primary", type: "button", title: identity?.authSource === "oidc-session" ? "Re-authenticate with OIDC" : "Sign in with OIDC", "aria-label": identity?.authSource === "oidc-session" ? "Re-authenticate with OIDC" : "Sign in with OIDC", "data-access-action": "sign-in-oidc", onclick: () => {
        location.href = oidcLoginTarget(oidc, location.hash) || "/ui/";
      } }, h("span", { html: icon("key", 16) }), identity?.authSource === "oidc-session" ? "Re-authenticate OIDC" : "Sign in with OIDC") : null,
      samlReady ? h("button", { class: "btn primary", type: "button", title: identity?.authSource === "saml-session" ? "Re-authenticate with SAML" : "Sign in with SAML", "aria-label": identity?.authSource === "saml-session" ? "Re-authenticate with SAML" : "Sign in with SAML", "data-access-action": "sign-in-saml", onclick: () => {
        location.href = samlLoginTarget(saml, location.hash) || "/ui/";
      } }, h("span", { html: icon("key", 16) }), identity?.authSource === "saml-session" ? "Re-authenticate SAML" : "Sign in with SAML") : null,
      identity?.authSource === "oidc-session" || identity?.authSource === "saml-session" ? h("button", { class: "btn ghost", type: "button", title: "Sign out of browser SSO", "aria-label": "Sign out of browser SSO", "data-access-action": "sign-out-browser-sso", onclick: async () => {
        try {
          await api.logout();
          setToken("");
          renderIdentity(identityNode, null, rt);
          renderAccessGovernance(governanceNode, rt, null, oidc, accessAdministration, { ...opts, identity: null, oidc, saml });
          toast("Signed out", "The browser session was cleared.", "ok");
          setTimeout(() => location.reload(), 250);
        } catch (e) {
          toast("Logout failed", e.message, "bad");
        }
      } }, "Sign out") : null));
}

function renderAccessGovernance(node, rt, identity, oidc, accessAdministration, opts = {}) {
  clear(node);
  node.appendChild(accessGovernancePanel(rt, identity, oidc, accessAdministration, opts));
}

function accessGovernancePanel(rt, identity, oidc, accessAdministration, opts = {}) {
  const model = accessGovernanceModel(rt, identity, oidc, accessAdministration);
  return h("div", { class: "access-governance" },
    h("div", { class: "access-governance-head" },
      h("strong", {}, "Access governance"),
      h("div", { class: "access-governance-actions" },
        model.actorAuditHash ? h("a", { class: "btn sm ghost", href: model.actorAuditHash, title: "Open actor audit", "aria-label": "Open actor audit", "data-access-action": "actor-audit" }, h("span", { html: icon("clock", 15) }), "Actor audit") : null,
        model.authSourceAuditHash ? h("a", { class: "btn sm ghost", href: model.authSourceAuditHash, title: "Open auth-source audit", "aria-label": "Open auth-source audit", "data-access-action": "auth-source-audit" }, h("span", { html: icon("filter", 15) }), "Auth-source audit") : null)),
    h("div", { class: "runtime-grid access-governance-summary" },
      networkMetric("Actor", model.actor),
      networkMetric("Role", pill(model.role, roleClass(model.role))),
      networkMetric("Auth source", model.authSource),
      networkMetric("Capabilities", model.capabilitiesLabel),
      networkMetric("Browser session", pill(model.sessionLabel, model.sessionClass)),
      networkMetric("Mutation guard", pill(model.csrfLabel, model.csrfClass))),
    h("div", { class: "table-wrap access-governance-table" }, responsiveTable(["Workflow", "Required role", "Viewer", "Operator", "Admin", "Current", "Audit"],
      model.rows.map((row) => h("tr", {},
        labeledCell("Workflow", {}, h("strong", {}, row.label), h("div", { class: "note" }, row.detail)),
        labeledCell("Required role", {}, pill(row.requiredRole, roleClass(row.requiredRole))),
        labeledCell("Viewer", {}, accessRoleCell(row.roleAccess.viewer)),
        labeledCell("Operator", {}, accessRoleCell(row.roleAccess.operator)),
        labeledCell("Admin", {}, accessRoleCell(row.roleAccess.admin)),
        labeledCell("Current", {}, pill(row.allowed ? "allowed" : "restricted", row.allowed ? "ok" : "warn")),
        labeledCell("Audit", {}, accessAuditLinkList(row.auditLinks)))),
      { className: "settings-access-governance-table" })),
    accessAdministrationPanel(model.administration, opts),
    accessAdminReadinessPanel(model.adminReadiness),
    h("div", { class: "note" }, "Local users, IdP lifecycle, and break-glass changes stay on audited backend workflows. Browser session revoke uses the canonical access administration API."));
}

function accessAdministrationPanel(administration, opts = {}) {
  if (!administration?.available) {
    return h("div", { class: "access-admin-inventory" },
      h("div", { class: "alert-box warn" },
        h("strong", {}, "Access administration inventory unavailable. "),
        administration?.detail || "GET /v1/system/access-administration did not return read-only state.",
        h("div", { class: "note", style: { marginTop: "6px" } },
          "Settings is using runtime identity and OIDC status only.")));
  }
  return h("div", { class: "access-admin-inventory" },
      h("div", { class: "access-inventory-head" },
      h("strong", {}, "Administration inventory and session controls"),
      h("div", { class: "flex", style: { gap: "8px" } },
        pill(administration.label, administration.cls, true),
        h("button", { class: "btn sm", type: "button", title: "Open access lifecycle review", "aria-label": "Open access lifecycle review for providers, sessions, and break-glass access", "data-access-action": "access-lifecycle-review", onclick: () => openAccessLifecycleReview(opts, administration) },
          h("span", { html: icon("shield", 14) }), "Lifecycle review"),
        h("button", { class: "btn sm", type: "button", title: "Configure OIDC provider", "aria-label": "Configure OIDC browser SSO provider", "data-access-action": "configure-oidc", onclick: () => openOIDCRollout(opts, administration) },
          h("span", { html: icon("key", 14) }), "Configure OIDC"),
        h("button", { class: "btn sm", type: "button", title: "Prepare SAML provider", "aria-label": "Prepare SAML browser SSO provider", "data-access-action": "prepare-saml", onclick: () => openSAMLRollout(opts, administration) },
          h("span", { html: icon("shield", 14) }), "Prepare SAML"),
        administration.oidc.enabled ? h("button", { class: "btn sm", type: "button", title: "Run OIDC preflight", "aria-label": "Run OIDC browser SSO preflight checks", "data-access-action": "oidc-preflight", onclick: () => openOIDCPreflight(opts) },
          h("span", { html: icon("shield", 14) }), "OIDC preflight") : null,
        h("button", { class: "btn sm", type: "button", title: "Open OIDC/SAML field evidence handoff", "aria-label": "Open OIDC and SAML real-provider field evidence handoff workflow", "data-access-action": "field-evidence-certification", onclick: () => openAccessFieldEvidenceCertification(opts, administration) },
          h("span", { html: icon("inbox", 14) }), "Field evidence"),
        h("button", { class: "btn sm", type: "button", title: "Create local user", "aria-label": "Create audited local user credential", "data-access-action": "create-local-user", onclick: () => openCreateLocalUser(opts) },
          h("span", { html: icon("plus", 14) }), "Create user"))),
    h("div", { class: "runtime-grid access-governance-summary" },
      networkMetric("Runtime auth", pill(authEnabledLabel(administration.authEnabled), authEnabledClass(administration.authEnabled))),
      networkMetric("Local users", String(administration.localUsers.length)),
      networkMetric("OIDC", pill(administration.oidc.label, administration.oidc.cls)),
      networkMetric("SAML", pill(administration.saml.label, administration.saml.cls)),
      networkMetric("Sessions", administration.sessions.label),
      networkMetric("Break-glass", pill(administration.breakGlass.state, administration.breakGlass.cls)),
      networkMetric("Blockers", pill(String(administration.blockers.length), administration.blockers.length ? "bad" : "ok"))),
    accessBlockerList(administration.blockers),
    accessRoleComparisonPanel(),
    breakGlassRotationPanel(administration, opts),
    accessLocalUsersTable(administration.localUsers, opts),
    accessSessionsTable(administration.sessions.activeSessions, opts),
    h("div", { class: "grid cols-2 access-inventory-grid" },
      accessInventoryTable("OIDC posture", administration.oidc.rows),
      accessInventoryTable("SAML posture", administration.saml.rows),
      accessInventoryTable("Session posture", administration.sessions.rows),
      accessInventoryTable("Break-glass", [
        { label: "State", value: administration.breakGlass.state, cls: administration.breakGlass.cls },
        { label: "Detail", value: administration.breakGlass.detail },
        { label: "Next action", value: administration.breakGlass.nextAction },
	      ])));
  }

function openAccessLifecycleReview(opts = {}, administration = null) {
  const review = accessLifecycleReviewModel(opts.status?.runtime || {}, opts.identity || null, opts.oidc || {}, administration);
  openDrawer({
    title: "Access lifecycle review",
    subtitle: "Provider, session, and break-glass handoff",
    width: "min(900px, 96vw)",
    body: accessLifecycleReviewBody(review),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close access lifecycle review", "aria-label": "Close access lifecycle review", "data-access-lifecycle-action": "close", onclick: closeDrawer }, "Close"),
      h("button", { class: "btn", type: "button", title: "Copy access lifecycle review", "aria-label": "Copy redacted access lifecycle review", "data-access-lifecycle-action": "copy", onclick: () => copyAccessLifecycleReview(review) },
        h("span", { html: icon("copy", 14) }), "Copy review"),
      h("button", { class: "btn", type: "button", title: "Copy Access settings route", "aria-label": "Copy route-backed Access settings link", "data-access-lifecycle-action": "copy-route", onclick: () => copyAccessLifecycleRoute() },
        h("span", { html: icon("copy", 14) }), "Route"),
      h("button", { class: "btn", type: "button", title: "Export access lifecycle review JSON", "aria-label": "Export redacted access lifecycle review JSON", "data-access-lifecycle-action": "export", onclick: () => exportAccessLifecycleReview(review) },
        h("span", { html: icon("download", 14) }), "Export JSON"),
      h("button", { class: "btn primary", type: "button", title: "Pin access lifecycle review to investigation case", "aria-label": "Pin access lifecycle review to investigation case", "data-access-lifecycle-action": "pin", onclick: () => pinAccessLifecycleReview(review) },
        h("span", { html: icon("inbox", 14) }), "Pin to case"),
    ],
  });
}

function accessLifecycleReviewBody(review = {}) {
  return h("div", { class: "access-lifecycle-review", "data-access-lifecycle-review": review.state },
    h("div", { class: "alert-box " + review.cls },
      h("strong", {}, `Lifecycle review: ${review.label}. `),
      review.detail),
    h("div", { class: "runtime-grid access-governance-summary" },
      networkMetric("Actor", review.actor),
      networkMetric("Role", pill(review.role, roleClass(review.role))),
      networkMetric("Auth source", review.authSource),
      networkMetric("Local admins", String(review.localAdminCount)),
      networkMetric("Browser sessions", String(review.activeSessionCount)),
      networkMetric("Admin verified", pill(review.adminVerified ? "yes" : "no", review.adminVerified ? "ok" : "warn"))),
    accessLifecycleHandoffPanel(review),
    h("div", { class: "table-wrap flat access-governance-table" },
      responsiveTable(["Lifecycle check", "State", "Detail", "Next action", "Evidence"],
        review.lifecycleRows.map((row) => h("tr", { "data-access-lifecycle-row": row.id },
          labeledCell("Lifecycle check", {}, h("strong", {}, row.label)),
          labeledCell("State", {}, pill(row.state, row.cls)),
          labeledCell("Detail", {}, row.detail),
          labeledCell("Next action", {}, row.nextAction),
          labeledCell("Evidence", {}, row.auditHash
            ? h("a", { href: row.auditHash }, row.evidence)
            : row.evidence))),
        { className: "settings-access-lifecycle-table" })),
    h("div", { class: "grid cols-2 access-inventory-grid" },
      accessLifecycleList("Public API", review.endpoints.map((endpoint) => `${endpoint.method} ${endpoint.path} - ${endpoint.purpose}`)),
      accessLifecycleList("CLI parity", review.cli),
      accessLifecycleList("Audit links", review.auditLinks.map((link) => `${link.label}: ${link.href}`))),
    h("div", { class: "note" }, "This review is browser-local evidence over existing public access APIs. It does not grant approval authority or replace backend RBAC, audit, or future signed custody controls."));
}

function accessLifecycleHandoffPanel(review = {}) {
  const handoffs = accessLifecycleHandoffs(review);
  return h("div", { class: "table-wrap flat access-governance-table", "data-access-lifecycle-handoffs": "true" },
    responsiveTable(["Operator handoff", "Continue at", "Audit", "Custody boundary"],
      handoffs.map((item) => h("tr", { "data-access-lifecycle-handoff": item.id },
        labeledCell("Operator handoff", {}, h("strong", {}, item.label), h("div", { class: "note" }, item.detail)),
        labeledCell("Continue at", { class: "data-wrap" }, h("a", { class: "data-wrap", href: item.route }, item.routeLabel)),
        labeledCell("Audit", { class: "data-wrap" }, item.auditRoute ? h("a", { class: "data-wrap", href: item.auditRoute }, item.auditLabel) : "not applicable"),
        labeledCell("Custody boundary", { class: "data-wrap" }, item.boundary))),
      { className: "settings-access-lifecycle-handoff-table" }));
}

function accessLifecycleHandoffs(review = {}) {
  const route = settingsPanelHash("access");
  return [
    {
      id: "settings-access-route",
      label: "Access panel route",
      detail: "Reopen the exact Settings Access panel before changing IdP, local user, session, or break-glass state.",
      route,
      routeLabel: "#/settings?panel=access",
      auditRoute: accessAuditHash({ query: "access-" }),
      auditLabel: "All access audit",
      boundary: "Route and packet are browser-local; backend RBAC remains authoritative.",
    },
    {
      id: "provider-lifecycle",
      label: "OIDC/SAML provider lifecycle",
      detail: "Use Configure OIDC, Prepare SAML, provider validation, and required audit comments before save or disable.",
      route,
      routeLabel: "Settings Access provider controls",
      auditRoute: accessAuditHash({ query: "access-oidc-provider-set access-saml-provider-set" }),
      auditLabel: "Provider audit",
      boundary: "Step-up authentication and production identity custody are hardening items.",
    },
    {
      id: "breakglass-lifecycle",
      label: "Break-glass credential lifecycle",
      detail: `${review.localAdminCount || 0} enabled local admin credential${review.localAdminCount === 1 ? "" : "s"} reported; token values are never included in copied, exported, or pinned evidence.`,
      route,
      routeLabel: "Settings Access break-glass controls",
      auditRoute: accessAuditHash({ query: "break-glass" }),
      auditLabel: "Break-glass audit",
      boundary: "Credential inventory custody and secret-manager proof remain hardening.",
    },
    {
      id: "session-lifecycle",
      label: "Browser SSO session lifecycle",
      detail: `${review.activeSessionCount || 0} active browser SSO session row${review.activeSessionCount === 1 ? "" : "s"} loaded; revoke remains a backend access-administration action.`,
      route,
      routeLabel: "Settings Access session table",
      auditRoute: accessAuditHash({ action: "access-session-revoke" }),
      auditLabel: "Session revoke audit",
      boundary: "Full production session custody and step-up requirements remain hardening.",
    },
  ];
}

function accessLifecycleList(title, items = []) {
  return h("div", { class: "access-inventory-table" },
    h("strong", {}, title),
    h("ul", { class: "compact-list" }, (items || []).map((item) => h("li", { class: "mono" }, item))));
}

function accessLifecycleReviewCopyText(review = {}) {
  const handoffs = accessLifecycleHandoffs(review);
  return [
    accessLifecycleReviewText(review),
    "",
    "Operator handoffs:",
    ...handoffs.map((item) => `- ${item.label}: continue=${item.route}; audit=${item.auditRoute || "not applicable"}; boundary=${item.boundary}`),
  ].map(sanitizeDrawerText).join("\n");
}

async function copyAccessLifecycleReview(review = {}) {
  try {
    await navigator.clipboard.writeText(accessLifecycleReviewCopyText(review));
    toast("Lifecycle review copied", "Redacted access lifecycle review copied as plain text.", "ok");
  } catch {
    toast("Copy failed", "Review the visible access lifecycle packet before recording evidence.", "warn");
  }
}

async function copyAccessLifecycleRoute() {
  try {
    await navigator.clipboard.writeText(settingsPanelURL("access", "/settings", globalThis.location));
    toast("Access route copied", "Route-backed Settings Access link copied.", "ok");
  } catch {
    toast("Copy failed", "Open Settings Access and copy the browser URL.", "warn");
  }
}

function accessLifecycleReviewPacket(review = {}) {
  return redactedAccessPacket({
    schemaVersion: review.schemaVersion || "phragma.access.lifecycle-review.v1",
    generatedAt: new Date().toISOString(),
    source: { interface: "webui", route: settingsPanelHash("access") },
    state: review.state,
    label: review.label,
    actor: review.actor,
    role: review.role,
    authSource: review.authSource,
    authEnabled: review.authEnabled,
    localAdminCount: review.localAdminCount,
    localUserCount: review.localUserCount,
    activeSessionCount: review.activeSessionCount,
    lifecycleRows: review.lifecycleRows,
    handoffs: accessLifecycleHandoffs(review),
    endpoints: review.endpoints,
    cli: review.cli,
    auditLinks: review.auditLinks,
  });
}

function exportAccessLifecycleReview(review = {}) {
  const packet = accessLifecycleReviewPacket(review);
  const blob = new Blob([JSON.stringify(packet, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: accessLifecycleReviewFilename() });
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  toast("Lifecycle review exported", "Downloaded redacted access lifecycle JSON.", "ok");
}

function pinAccessLifecycleReview(review = {}) {
  try {
    const packet = accessLifecycleReviewPacket(review);
    const result = pinInvestigationPacket(buildInvestigationPacket({
      kind: "access-lifecycle-review",
      title: "Access lifecycle review",
      subject: { id: "settings:access:lifecycle-review", label: "Settings access lifecycle" },
      summary: {
        state: review.state,
        label: review.label,
        localAdminCount: review.localAdminCount,
        activeSessionCount: review.activeSessionCount,
        role: review.role,
      },
      evidence: accessLifecycleReviewCopyText(review).split("\n"),
      artifacts: { accessLifecycleReview: packet },
    }, { route: settingsPanelHash("access") }));
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Access lifecycle review could not be pinned.", "bad");
  }
}

function accessLifecycleReviewFilename() {
  const stamp = new Date().toISOString().replace(/[^0-9A-Za-z]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 32);
  return `openngfw-access-lifecycle-${stamp}.json`;
}

function openAccessFieldEvidenceCertification(opts = {}, administration = null) {
  const model = accessFieldEvidenceCertificationModel(administration, opts);
  openDrawer({
    title: "OIDC/SAML field evidence",
    subtitle: model.externalCertificationLabel || "Real-provider field-evidence handoff; not certified",
    width: "min(960px, 96vw)",
    body: accessFieldEvidenceCertificationBody(model, opts, administration),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close field evidence handoff", "aria-label": "Close field evidence handoff drawer", "data-access-field-evidence-action": "close", onclick: closeDrawer }, "Close"),
      h("button", { class: "btn", type: "button", title: "Copy OIDC/SAML field evidence checklist", "aria-label": "Copy redacted OIDC and SAML field evidence checklist", "data-access-field-evidence-action": "copy", onclick: () => copyAccessFieldEvidenceCertification(model) },
        h("span", { html: icon("copy", 14) }), "Copy checklist"),
      h("button", { class: "btn", type: "button", title: "Export OIDC/SAML field evidence JSON", "aria-label": "Export redacted OIDC and SAML field evidence JSON", "data-access-field-evidence-action": "export", onclick: () => exportAccessFieldEvidenceCertification(model) },
        h("span", { html: icon("download", 14) }), "Export JSON"),
      h("button", { class: "btn primary", type: "button", title: "Pin OIDC/SAML field evidence handoff to investigation case", "aria-label": "Pin OIDC and SAML field evidence handoff to investigation case", "data-access-field-evidence-action": "pin", onclick: () => pinAccessFieldEvidenceCertification(model) },
        h("span", { html: icon("inbox", 14) }), "Pin to case"),
    ],
  });
}

function accessActiveBrowserSessionCount(sessions = {}) {
  const detailed = Array.isArray(sessions?.activeSessions) ? sessions.activeSessions.length : 0;
  const oidc = Number(sessions?.oidcActiveSessions || sessions?.oidc_active_sessions || 0) || 0;
  return Math.max(detailed, oidc);
}

export function accessFieldEvidenceCertificationModel(administration = {}, opts = {}) {
  const generatedAt = new Date().toISOString();
  const artifactEvidence = opts?.fieldEvidenceArtifacts || opts?.accessFieldEvidenceArtifacts || administration?.fieldEvidenceArtifacts || {};
  const protocols = [
    accessFieldEvidenceProtocolWithInventory(accessOIDCFieldEvidenceProtocol(), artifactEvidence.oidc),
    accessFieldEvidenceProtocolWithInventory(accessSAMLFieldEvidenceProtocol(), artifactEvidence.saml),
  ];
  const summary = accessFieldEvidenceOverallStatus(protocols);
  const fieldRunEvidenceComplete = summary.state === "field-run-evidence-complete";
  return redactedAccessPacket({
    schemaVersion: "openngfw.access.field-evidence-certification.v1",
    generatedAt,
    state: summary.state,
    label: summary.label,
    detail: `${summary.detail} This is a redacted checklist and handoff for evidence captured in a real IdP lab. It does not claim that an OIDC or SAML provider run has happened.`,
    source: { interface: "webui", route: settingsPanelHash("access") },
    docsReference: "docs/testing-plan.md M5 OIDC/SAML provider field evidence",
    accessPosture: {
      oidcEnabled: Boolean(administration?.oidc?.enabled || opts.oidc?.enabled),
      samlEnabled: Boolean(administration?.saml?.enabled || opts.saml?.enabled),
      breakGlassState: administration?.breakGlass?.state || "not loaded",
      activeBrowserSessions: accessActiveBrowserSessionCount(administration?.sessions),
    },
    statusParser: {
      requiredSentinel: "status=passed",
      passed: "Artifact text must include a standalone status=passed sentinel after the real-provider run.",
      missing: "Expected artifact is absent or has no parseable status sentinel.",
      stale: "Artifact carries stale status or collected_at/evidence_collected_at is older than the accepted freshness window.",
      unsafe: "Artifact text appears to contain token, cookie, authorization-code, private-key, assertion, or certificate-body material and must not be copied, exported, or pinned.",
    },
    protocols,
    fieldRunEvidenceComplete,
    fieldRunCertification: fieldRunEvidenceComplete ? "certified-by-evidence" : "not-certified",
    externalCertification: "not-certified",
    externalCertificationLabel: fieldRunEvidenceComplete ? "Field-run evidence complete; external IdP certification deferred" : "Real-provider field-evidence handoff; not certified",
    nonClaim: "No real IdP run is certified by this browser-generated packet; validate and record only from the lab where the browser SSO run happened.",
    certificationBoundary: "certified-by-evidence means the required redacted field-run artifact packet parsed cleanly; it is not vendor certification, signed provider evidence, production MFA reauth, cert rollover, or secret-custody approval.",
    handoffs: [
      { id: "import", label: "Import artifact status", detail: "Paste a local JSON map of artifact paths to redacted status text for browser-local review; raw text is not exported or pinned." },
      { id: "copy", label: "Copy checklist", detail: "Plain-text checklist for a change ticket or test note; all generated content is redacted." },
      { id: "export", label: "Export JSON", detail: "Machine-readable handoff packet for attaching to local release evidence preparation." },
      { id: "pin", label: "Pin to Investigation", detail: "Local Investigation case handoff without provider tokens, cookies, assertions, authorization codes, or client secrets." },
    ],
  });
}

const ACCESS_FIELD_EVIDENCE_STALE_AFTER_MS = 14 * 24 * 60 * 60 * 1000;
const ACCESS_FIELD_EVIDENCE_UNSAFE_RE = /(bearer\s+[a-z0-9._~+/=-]+|-----BEGIN [A-Z ]*PRIVATE KEY-----|-----BEGIN CERTIFICATE-----|x509_certificate_body\s*[:=])/i;
const ACCESS_FIELD_EVIDENCE_SECRET_ASSIGNMENT_RE = /\b(id[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret|authorization[_-]?code|set-cookie|cookie|csrf|samlresponse|relaystate)\s*[:=]\s*([^\s;&]+)/gi;
const ACCESS_FIELD_EVIDENCE_SAFE_SECRET_VALUES = new Set(["<redacted>", "[redacted]", "redacted", "missing", "present", "false", "true", "none", "not-present", "not_applicable"]);

function accessFieldEvidenceProtocolWithInventory(protocol = {}, artifactsByPath = {}) {
  const inventory = accessFieldEvidenceArtifactInventory(protocol, artifactsByPath);
  const statusSummary = accessFieldEvidenceInventoryStatus(inventory);
  const fieldFacts = accessFieldEvidenceProtocolFacts(protocol, inventory);
  return {
    ...protocol,
    state: statusSummary.state,
    statusLabel: statusSummary.label,
    statusDetail: statusSummary.detail,
    statusSummary,
    fieldFacts,
    artifactInventory: inventory,
  };
}

function accessFieldEvidenceArtifactInventory(protocol = {}, artifactsByPath = {}) {
  const supplied = artifactsByPath && typeof artifactsByPath === "object" ? artifactsByPath : {};
  return (protocol.buckets || []).flatMap((bucket) => (bucket.artifacts || []).map((path) => {
    const raw = supplied[path] || supplied[`${protocol.id}/${path}`] || null;
    const parsed = accessFieldEvidenceArtifactStatus(raw);
    return {
      protocol: protocol.id,
      bucket: bucket.id,
      path,
      requiredSentinel: "status=passed",
      state: parsed.state,
      detail: parsed.detail,
      collectedAt: parsed.collectedAt,
      observedFields: parsed.observedFields,
      unsafeReason: parsed.unsafeReason,
    };
  }));
}

export function accessFieldEvidenceArtifactStatus(raw) {
  const text = typeof raw === "string" ? raw : String(raw?.content || raw?.text || raw?.detail || raw?.stdout || "");
  const explicitStatus = accessFieldEvidenceStatusValue(raw, text);
  const collectedAt = accessFieldEvidenceCollectedAt(raw, text);
  const observedFields = accessFieldEvidenceObservedFields(raw, text);
  if (!raw && text.trim() === "") {
    return { state: "missing", detail: "missing artifact; status=passed sentinel not observed", observedFields };
  }
  if (accessFieldEvidenceHasUnsafeMaterial(text)) {
    return { state: "unsafe", detail: "unsafe artifact content detected; redact before handoff", collectedAt, observedFields, unsafeReason: "secret-adjacent material" };
  }
  if (explicitStatus === "unsafe") {
    return { state: "unsafe", detail: "artifact status reports unsafe content; redact before handoff", collectedAt, observedFields, unsafeReason: "status=unsafe" };
  }
  if (explicitStatus === "stale" || accessFieldEvidenceIsStale(collectedAt)) {
    return { state: "stale", detail: "artifact is stale; rerun the real-provider evidence collection", collectedAt, observedFields };
  }
  if (explicitStatus === "passed") {
    return { state: "passed", detail: "status=passed sentinel present", collectedAt, observedFields };
  }
  return { state: "missing", detail: "status=passed sentinel missing", collectedAt, observedFields };
}

function accessFieldEvidenceHasUnsafeMaterial(text = "") {
  const body = String(text || "");
  if (ACCESS_FIELD_EVIDENCE_UNSAFE_RE.test(body)) return true;
  ACCESS_FIELD_EVIDENCE_SECRET_ASSIGNMENT_RE.lastIndex = 0;
  let match;
  while ((match = ACCESS_FIELD_EVIDENCE_SECRET_ASSIGNMENT_RE.exec(body))) {
    const value = String(match[2] || "").trim().toLowerCase().replace(/[,.]+$/g, "");
    if (!ACCESS_FIELD_EVIDENCE_SAFE_SECRET_VALUES.has(value) && !value.includes("redacted")) return true;
  }
  return false;
}

function accessFieldEvidenceObservedFields(raw, text = "") {
  const source = typeof raw === "object" && raw ? raw : {};
  const body = String(text || "");
  return {
    providerUrl: accessFieldEvidenceFirstValue(source, body, ["providerUrl", "provider_url", "issuer", "issuer_url", "metadata_url", "idp_entity_id", "entity_id"]),
    callbackOrAcs: accessFieldEvidenceFirstValue(source, body, ["callback", "callback_url", "redirect_url", "acs", "acs_url", "public_acs"]),
    roleMapping: accessFieldEvidenceFirstValue(source, body, ["role_claim", "roleClaim", "role_attribute", "roleAttribute", "group_mapping", "provider_role", "mapped_role", "authSource"]),
    sessionProof: accessFieldEvidenceFirstValue(source, body, ["session_proof", "session_cookie", "assertion_session", "post_login_authenticated", "authenticated"]),
    stepUpProof: accessFieldEvidenceFirstValue(source, body, ["step_up_proof", "stepup_proof", "mfa_reauth", "reauth", "step_up_required", "step_up_status"]),
    disableRollbackProof: accessFieldEvidenceFirstValue(source, body, ["disable_rollback_proof", "rollback_proof", "disable_status", "provider_disabled", "rollback_status", "break_glass_verified"]),
    artifactStatus: accessFieldEvidenceStatusValue(raw, body),
  };
}

function accessFieldEvidenceFirstValue(source = {}, text = "", keys = []) {
  for (const key of keys) {
    const direct = source && Object.prototype.hasOwnProperty.call(source, key) ? source[key] : "";
    const directValue = sanitizeDrawerText(String(direct || "").trim());
    if (directValue) return directValue;
    const pattern = new RegExp(`(?:^|\\s)${escapeRegExp(key)}\\s*=\\s*([^\\n\\r]+)`, "i");
    const match = String(text || "").match(pattern);
    const value = sanitizeDrawerText(String(match?.[1] || "").trim());
    if (value) return value;
  }
  return "";
}

function escapeRegExp(value = "") {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function accessFieldEvidenceStatusValue(raw, text = "") {
  const direct = typeof raw === "object" && raw ? raw.status || raw.state : "";
  const value = String(direct || "").trim().toLowerCase();
  if (value) return value;
  const match = String(text || "").match(/(?:^|\s)status\s*=\s*([a-z0-9_-]+)(?:\s|$)/i);
  return match ? match[1].toLowerCase() : "";
}

function accessFieldEvidenceCollectedAt(raw, text = "") {
  const direct = typeof raw === "object" && raw ? raw.collectedAt || raw.collected_at || raw.evidenceCollectedAt || raw.evidence_collected_at : "";
  const value = String(direct || "").trim() || (String(text || "").match(/(?:^|\s)(?:collected_at|evidence_collected_at)\s*=\s*([0-9TZ:.-]+)(?:\s|$)/i)?.[1] || "");
  return value;
}

function accessFieldEvidenceIsStale(collectedAt) {
  if (!collectedAt) return false;
  const t = Date.parse(collectedAt);
  return Number.isFinite(t) && Date.now() - t > ACCESS_FIELD_EVIDENCE_STALE_AFTER_MS;
}

function accessFieldEvidenceInventoryStatus(inventory = []) {
  const counts = { passed: 0, missing: 0, stale: 0, unsafe: 0 };
  (inventory || []).forEach((item) => { counts[item.state] = (counts[item.state] || 0) + 1; });
  const total = inventory.length;
  const state = counts.unsafe ? "unsafe" : counts.stale ? "stale" : counts.missing ? "missing" : total && counts.passed === total ? "passed" : "operator-evidence-required";
  const label = state === "passed" ? "artifact inventory passed" : state === "unsafe" ? "unsafe artifacts" : state === "stale" ? "stale artifacts" : "missing artifacts";
  const detail = `${counts.passed}/${total} artifact(s) have status=passed; missing=${counts.missing || 0} stale=${counts.stale || 0} unsafe=${counts.unsafe || 0}.`;
  return { state, label, detail, counts, total };
}

function accessFieldEvidenceProtocolFacts(protocol = {}, inventory = []) {
  const fieldRows = accessFieldEvidenceRequiredFieldRows(protocol, inventory);
  const complete = fieldRows.every((row) => row.state === "passed");
  return {
    complete,
    label: complete ? "required field-run facts present" : "required field-run facts missing",
    rows: fieldRows,
  };
}

function accessFieldEvidenceRequiredFieldRows(protocol = {}, inventory = []) {
  const byPath = new Map((inventory || []).map((item) => [item.path, item]));
  const findValue = (paths = [], key) => {
    for (const path of paths) {
      const value = byPath.get(path)?.observedFields?.[key] || "";
      if (value) return value;
    }
    return "";
  };
  const allPassed = (paths = []) => paths.every((path) => byPath.get(path)?.state === "passed");
  const fields = protocol.id === "saml" ? [
    { id: "provider", label: "Provider URL / IdP entity", paths: ["provider/idp-metadata.txt", "provider/sp-metadata.txt"], key: "providerUrl" },
    { id: "callback", label: "ACS URL", paths: ["deployment/public-acs.txt", "provider/sp-metadata.txt"], key: "callbackOrAcs" },
    { id: "role-mapping", label: "Role claim / group mapping", paths: ["rbac/role-mapping.txt"], key: "roleMapping" },
    { id: "session-proof", label: "Session proof", paths: ["browser/assertion-session-cookie.txt"], key: "sessionProof" },
    { id: "step-up-proof", label: "Step-up proof", paths: ["browser/step-up-proof.txt"], key: "stepUpProof" },
    { id: "disable-rollback-proof", label: "Disable / rollback proof", paths: ["lifecycle/disable-rollback-proof.txt"], key: "disableRollbackProof" },
  ] : [
    { id: "provider", label: "Provider URL / issuer", paths: ["provider/issuer-client-discovery.txt", "provider/id-token-validation.txt"], key: "providerUrl" },
    { id: "callback", label: "Callback URL", paths: ["deployment/public-callback.txt"], key: "callbackOrAcs" },
    { id: "role-mapping", label: "Role claim / group mapping", paths: ["rbac/role-mapping.txt"], key: "roleMapping" },
    { id: "session-proof", label: "Session proof", paths: ["browser/session-cookie.txt"], key: "sessionProof" },
    { id: "step-up-proof", label: "Step-up proof", paths: ["browser/step-up-proof.txt"], key: "stepUpProof" },
    { id: "disable-rollback-proof", label: "Disable / rollback proof", paths: ["lifecycle/disable-rollback-proof.txt"], key: "disableRollbackProof" },
  ];
  return fields.map((field) => {
    const value = findValue(field.paths, field.key);
    const passed = allPassed(field.paths) && Boolean(value || field.id === "session-proof" || field.id === "step-up-proof" || field.id === "disable-rollback-proof");
    return {
      ...field,
      value: value || (passed ? "status=passed" : ""),
      state: passed ? "passed" : "missing",
      detail: passed ? "required field-run artifact present" : `missing ${field.label.toLowerCase()} in ${field.paths.join(", ")}`,
    };
  });
}

function accessFieldEvidenceOverallStatus(protocols = []) {
  const summaries = protocols.map((protocol) => protocol.statusSummary || accessFieldEvidenceInventoryStatus(protocol.artifactInventory || []));
  const counts = summaries.reduce((acc, item) => {
    Object.entries(item.counts || {}).forEach(([key, value]) => { acc[key] = (acc[key] || 0) + value; });
    acc.total += item.total || 0;
    return acc;
  }, { passed: 0, missing: 0, stale: 0, unsafe: 0, total: 0 });
  const fieldFactsComplete = protocols.every((protocol) => protocol.fieldFacts?.complete);
  const artifactComplete = counts.total && counts.passed === counts.total;
  const state = counts.unsafe ? "unsafe-artifacts" : counts.stale ? "stale-artifacts" : counts.missing ? "missing-artifacts" : artifactComplete && fieldFactsComplete ? "field-run-evidence-complete" : artifactComplete ? "passed-artifact-inventory" : "operator-evidence-required";
  const label = state === "field-run-evidence-complete" ? "certified-by-evidence; external certification deferred" : state === "passed-artifact-inventory" ? "not certified; artifacts passed parser" : state.replace(/-/g, " ");
  const detail = `Artifact parser status: ${counts.passed}/${counts.total} passed, ${counts.missing || 0} missing, ${counts.stale || 0} stale, ${counts.unsafe || 0} unsafe.`;
  return { state, label, detail, counts, fieldFactsComplete };
}

function accessOIDCFieldEvidenceProtocol() {
  return {
    id: "oidc",
    label: "OIDC real-provider field evidence",
    rootDir: "release/field-evidence/oidc",
    validateCommand: "make m5-oidc-field-evidence-check OIDC_FIELD_EVIDENCE_DIR=release/field-evidence/oidc",
    recordCommand: "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-m5-oidc-field-evidence OIDC_FIELD_EVIDENCE_DIR=release/field-evidence/oidc",
    buckets: [
      { id: "provider", label: "Provider", artifacts: ["provider/issuer-client-discovery.txt", "provider/id-token-validation.txt"], preserve: "issuer, client ID, discovery, JWKS, ID-token signature/issuer/audience/expiration validation" },
      { id: "deployment", label: "Deployment", artifacts: ["deployment/public-callback.txt", "deployment/client-secret-file-permissions.txt"], preserve: "public HTTPS callback, Secure cookie posture, client-secret file permissions or explicit public-client note" },
      { id: "browser", label: "Browser, callback, CSRF", artifacts: ["browser/session-cookie.txt", "browser/missing-state-rejection.txt", "browser/reused-state-rejection.txt", "browser/nonce-mismatch-rejection.txt", "browser/pkce-exchange-failure.txt", "browser/operator-mutation-with-csrf.txt", "browser/missing-csrf-rejection.txt", "browser/cross-origin-rejection.txt", "browser/viewer-mutation-denial.txt", "browser/logout-invalidation.txt"], preserve: "session cookie flags, negative callback failures, RBAC denial, CSRF success/failure, logout invalidation" },
      { id: "step-up", label: "Step-up proof", artifacts: ["browser/step-up-proof.txt"], preserve: "operator step-up or explicit IdP/MFA reauth proof captured during the same field run" },
      { id: "rollback", label: "Disable / rollback proof", artifacts: ["lifecycle/disable-rollback-proof.txt"], preserve: "provider disable, browser logout/session invalidation, and break-glass fallback proof" },
      { id: "rbac", label: "RBAC", artifacts: ["rbac/role-mapping.txt"], preserve: "viewer, operator, and admin role mappings with authSource=oidc-session" },
      { id: "redaction", label: "Redaction", artifacts: ["redaction/identity-redacted.txt", "redaction/audit-log-redacted.txt", "redaction/support-bundle-redacted.txt"], preserve: "identity, audit, support-bundle redaction plus global secret scan output" },
    ],
    sentinels: [
      "status=passed",
      "field_evidence_scope=real-issuer-client,id-token-validation,https-callback,secret-file,cookie-security,negative-callbacks,rbac,csrf-origin,logout,redaction",
      "oidc_field_evidence_scope=real-provider-backed,browser-sso,authorization-code-pkce,id-token-verification,nonce,session-cookie,csrf,rbac",
      "oidc_field_negative_checks=missing-state,reused-state,nonce-mismatch,pkce-exchange-failure,logout,viewer-denial",
      "oidc_field_redaction=issuer-host-redacted,client-id-redacted,subject-redacted,email-redacted,tokens-redacted,cookies-redacted",
      "required_provider_evidence=issuer-client-discovery,id-token-validation",
      "required_deployment_evidence=public-https-callback,client-secret-file-permissions",
      "required_browser_evidence=session-cookie,missing-state-rejection,reused-state-rejection,nonce-mismatch-rejection,pkce-exchange-failure,operator-mutation-with-csrf,missing-csrf-rejection,cross-origin-rejection,viewer-mutation-denial,logout-invalidation",
      "required_step_up_evidence=browser-step-up-proof",
      "required_disable_rollback_evidence=provider-disable,session-invalidation,break-glass-fallback",
      "required_rbac_evidence=viewer,operator,admin",
      "required_redaction_evidence=identity-redacted,audit-log-redacted,support-bundle-redacted,global-secret-scan",
      "redaction_scan=jwt,bearer,oauth-token,cookie,auth-code,client-secret,csrf",
    ],
    redactionChecklist: ["cookies", "authorization codes", "provider tokens", "ID tokens", "refresh tokens", "client secrets", "subjects and email addresses when exported outside the lab"],
  };
}

function accessSAMLFieldEvidenceProtocol() {
  return {
    id: "saml",
    label: "SAML real-provider field evidence",
    rootDir: "release/field-evidence/saml",
    validateCommand: "make m5-saml-field-evidence-check SAML_FIELD_EVIDENCE_DIR=release/field-evidence/saml",
    recordCommand: "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-m5-saml-field-evidence SAML_FIELD_EVIDENCE_DIR=release/field-evidence/saml",
    buckets: [
      { id: "provider", label: "Provider", artifacts: ["provider/idp-metadata.txt", "provider/sp-metadata.txt"], preserve: "IdP entity, SP entity, metadata source, SSO URL, ACS URL, signature or signing-certificate validation" },
      { id: "deployment", label: "Deployment", artifacts: ["deployment/public-acs.txt"], preserve: "public HTTPS ACS URL and Secure cookie posture" },
      { id: "browser", label: "Browser, callback, CSRF", artifacts: ["browser/login-redirect.txt", "browser/assertion-session-cookie.txt", "browser/invalid-signature-rejection.txt", "browser/replayed-assertion-rejection.txt", "browser/missing-relaystate-rejection.txt", "browser/operator-mutation-with-csrf.txt", "browser/missing-csrf-rejection.txt", "browser/cross-origin-rejection.txt", "browser/viewer-mutation-denial.txt", "browser/logout-invalidation.txt"], preserve: "AuthnRequest redirect, assertion-backed session, negative assertion/RelayState failures, RBAC denial, CSRF success/failure, logout invalidation" },
      { id: "step-up", label: "Step-up proof", artifacts: ["browser/step-up-proof.txt"], preserve: "operator step-up or explicit IdP/MFA reauth proof captured during the same field run" },
      { id: "rollback", label: "Disable / rollback proof", artifacts: ["lifecycle/disable-rollback-proof.txt"], preserve: "provider disable, browser logout/session invalidation, and break-glass fallback proof" },
      { id: "rbac", label: "RBAC", artifacts: ["rbac/role-mapping.txt"], preserve: "viewer, operator, and admin role mappings with authSource=saml-session" },
      { id: "redaction", label: "Redaction", artifacts: ["redaction/identity-redacted.txt", "redaction/audit-log-redacted.txt", "redaction/support-bundle-redacted.txt"], preserve: "identity, audit, support-bundle redaction plus global secret scan output" },
    ],
    sentinels: [
      "status=passed",
      "field_evidence_scope=real-idp-metadata,sp-metadata,https-acs,cookie-security,negative-callbacks,rbac,csrf-origin,logout,redaction",
      "saml_field_evidence_scope=real-provider-backed,browser-sso,authn-request,assertion-validation,session-cookie,csrf,rbac",
      "saml_field_negative_checks=invalid-signature,replayed-assertion,missing-relaystate,logout,viewer-denial",
      "saml_field_redaction=idp-entity-redacted,sp-entity-redacted,subject-redacted,email-redacted,assertions-redacted,cookies-redacted",
      "required_provider_evidence=idp-metadata,sp-metadata",
      "required_deployment_evidence=public-https-acs,secure-cookie-posture",
      "required_browser_evidence=login-redirect,assertion-session-cookie,invalid-signature-rejection,replayed-assertion-rejection,missing-relaystate-rejection,operator-mutation-with-csrf,missing-csrf-rejection,cross-origin-rejection,viewer-mutation-denial,logout-invalidation",
      "required_step_up_evidence=browser-step-up-proof",
      "required_disable_rollback_evidence=provider-disable,session-invalidation,break-glass-fallback",
      "required_rbac_evidence=viewer,operator,admin",
      "required_redaction_evidence=identity-redacted,audit-log-redacted,support-bundle-redacted,global-secret-scan",
      "redaction_scan=saml-response,relaystate,assertion,x509,private-key,cookie,csrf",
    ],
    redactionChecklist: ["SAMLResponse", "RelayState", "assertions", "X.509 certificate bodies", "X.509 private keys", "session cookies", "CSRF tokens", "subjects and email addresses when exported outside the lab"],
  };
}

function accessFieldEvidenceCertificationBody(model = {}, opts = {}, administration = null) {
  return h("div", { class: "access-field-evidence", "data-access-field-evidence-certification": model.state },
    h("div", { class: "alert-box warn" },
      h("strong", {}, "Field evidence is external. "),
      "This drawer maps the required OIDC/SAML evidence bundle and commands; it does not certify that a real IdP or browser run happened."),
    h("div", { class: "runtime-grid access-governance-summary" },
      networkMetric("State", pill(model.label, "warn")),
      networkMetric("Field-run claim", pill(model.fieldRunCertification || "not-certified", model.fieldRunEvidenceComplete ? "ok" : "warn")),
      networkMetric("External certification", pill(model.externalCertification || "not-certified", "warn")),
      networkMetric("OIDC configured", pill(model.accessPosture?.oidcEnabled ? "yes" : "no", model.accessPosture?.oidcEnabled ? "ok" : "warn")),
      networkMetric("SAML configured", pill(model.accessPosture?.samlEnabled ? "yes" : "no", model.accessPosture?.samlEnabled ? "ok" : "warn")),
      networkMetric("Break-glass", pill(model.accessPosture?.breakGlassState || "not loaded", model.accessPosture?.breakGlassState === "ready" ? "ok" : "warn")),
      networkMetric("Browser sessions", String(model.accessPosture?.activeBrowserSessions || 0)),
      networkMetric("Route", h("a", { href: settingsPanelHash("access") }, "#/settings?panel=access"))),
    accessFieldEvidenceImportPanel(opts, administration),
    h("div", { class: "grid cols-2 access-inventory-grid" }, model.protocols.map((protocol) => accessFieldEvidenceProtocolPanel(protocol))),
    h("div", { class: "note" }, model.certificationBoundary),
    h("div", { class: "note" }, model.nonClaim));
}

function accessFieldEvidenceImportPanel(opts = {}, administration = null) {
  const oidcText = h("textarea", {
    class: "input",
    rows: 4,
    placeholder: "{\"provider/issuer-client-discovery.txt\":\"status=passed\\nissuer=https://idp.example.com\", ...}",
    "data-access-field-evidence-import": "oidc",
  });
  const samlText = h("textarea", {
    class: "input",
    rows: 4,
    placeholder: "{\"provider/idp-metadata.txt\":\"status=passed\\nidp_entity_id=https://idp.example.com/saml\", ...}",
    "data-access-field-evidence-import": "saml",
  });
  const status = h("div", {});
  const review = () => {
    const imported = {};
    try {
      imported.oidc = accessFieldEvidenceParseImport(oidcText.value);
      imported.saml = accessFieldEvidenceParseImport(samlText.value);
    } catch (err) {
      clear(status);
      status.appendChild(h("div", { class: "alert-box bad", style: { marginBottom: 0 } },
        h("strong", {}, "Import failed. "),
        sanitizeDrawerText(err?.message || String(err))));
      return;
    }
    const current = opts?.fieldEvidenceArtifacts || opts?.accessFieldEvidenceArtifacts || administration?.fieldEvidenceArtifacts || {};
    const nextArtifacts = {
      ...current,
      oidc: Object.keys(imported.oidc).length ? imported.oidc : current.oidc,
      saml: Object.keys(imported.saml).length ? imported.saml : current.saml,
    };
    openAccessFieldEvidenceCertification({ ...opts, fieldEvidenceArtifacts: nextArtifacts }, administration);
  };
  return h("div", { class: "access-governance", "data-access-field-evidence-importer": "true" },
    h("div", { class: "access-governance-head" },
      h("strong", {}, "Import redacted field-run artifact status"),
      h("button", { class: "btn sm", type: "button", title: "Review imported OIDC/SAML field evidence packet", "aria-label": "Review imported OIDC and SAML field evidence packet", "data-access-field-evidence-action": "review-import", onclick: review },
        h("span", { html: icon("inbox", 14) }), "Review import")),
    h("div", { class: "note" }, "Paste JSON objects keyed by artifact path. Values may be strings or objects with status/content/collectedAt. Raw pasted text stays in this browser pass and is not copied, exported, or pinned."),
    h("div", { class: "grid cols-2" },
      h("label", { class: "field" }, h("span", {}, "OIDC artifacts JSON"), oidcText),
      h("label", { class: "field" }, h("span", {}, "SAML artifacts JSON"), samlText)),
    status);
}

export function accessFieldEvidenceParseImport(value = "") {
  const text = String(value || "").trim();
  if (!text) return {};
  const parsed = JSON.parse(text);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Artifact import must be a JSON object keyed by artifact path.");
  }
  return parsed;
}

function accessFieldEvidenceProtocolPanel(protocol = {}) {
  return h("div", { class: "access-inventory-table", "data-access-field-evidence-protocol": protocol.id },
    h("div", { class: "access-role-preview-head" },
      h("strong", {}, protocol.label),
      pill(protocol.statusLabel || "evidence required", accessFieldEvidenceStatusClass(protocol.state), true)),
    h("div", { class: "note" }, "Bundle root: ", h("span", { class: "mono" }, protocol.rootDir)),
    h("div", { class: "note" }, protocol.statusDetail || "Artifact inventory has not been parsed."),
    accessFieldEvidenceFactsTable(protocol),
    h("div", { class: "table-wrap flat access-governance-table" },
      responsiveTable(["Bucket", "Artifacts", "Status", "Preserve"],
        protocol.buckets.map((bucket) => h("tr", { "data-access-field-evidence-bucket": `${protocol.id}:${bucket.id}` },
          labeledCell("Bucket", {}, h("strong", {}, bucket.label)),
          labeledCell("Artifacts", { class: "data-wrap" }, accessCompactMonoList(bucket.artifacts)),
          labeledCell("Status", { class: "data-wrap" }, accessFieldEvidenceBucketStatus(protocol, bucket)),
          labeledCell("Preserve", {}, bucket.preserve))),
        { className: "settings-access-field-evidence-table" })),
    h("div", { class: "field" },
      h("span", {}, "Validate command"),
      h("pre", { class: "mono audit-detail-pre", "data-access-field-evidence-command": `${protocol.id}:validate` }, protocol.validateCommand)),
    h("div", { class: "field" },
      h("span", {}, "Record command"),
      h("pre", { class: "mono audit-detail-pre", "data-access-field-evidence-command": `${protocol.id}:record` }, protocol.recordCommand)),
    accessLifecycleList("Required sentinel output", protocol.sentinels),
    accessLifecycleList("Redact before copy/export/pin", protocol.redactionChecklist));
}

function accessFieldEvidenceFactsTable(protocol = {}) {
  const rows = protocol.fieldFacts?.rows || [];
  return h("div", { class: "table-wrap flat access-governance-table", "data-access-field-evidence-facts": protocol.id },
    responsiveTable(["Required field-run fact", "Status", "Evidence value", "Detail"],
      rows.map((row) => h("tr", { "data-access-field-evidence-fact": `${protocol.id}:${row.id}` },
        labeledCell("Required field-run fact", {}, h("strong", {}, row.label)),
        labeledCell("Status", {}, pill(row.state, accessFieldEvidenceStatusClass(row.state))),
        labeledCell("Evidence value", { class: "data-wrap" }, row.value || "missing"),
        labeledCell("Detail", {}, row.detail))),
      { className: "settings-access-field-evidence-facts-table" }));
}

function accessFieldEvidenceBucketStatus(protocol = {}, bucket = {}) {
  const byPath = new Map((protocol.artifactInventory || []).map((item) => [item.path, item]));
  return h("ul", { class: "compact-list", "data-access-field-evidence-status-parser": `${protocol.id}:${bucket.id}` },
    (bucket.artifacts || []).map((path) => {
      const item = byPath.get(path) || { state: "missing", detail: "status=passed sentinel missing", requiredSentinel: "status=passed" };
      return h("li", { "data-access-field-evidence-artifact-state": item.state },
        pill(item.state, accessFieldEvidenceStatusClass(item.state), true),
        " ",
        h("span", { class: "mono" }, item.requiredSentinel || "status=passed"),
        " ",
        h("span", {}, item.detail || ""));
    }));
}

function accessFieldEvidenceStatusClass(state) {
  if (state === "passed" || state === "passed-artifact-inventory") return "ok";
  if (state === "unsafe" || state === "unsafe-artifacts") return "bad";
  if (state === "stale" || state === "stale-artifacts") return "warn";
  return "warn";
}

function accessCompactMonoList(items = []) {
  return h("ul", { class: "compact-list" }, (items || []).map((item) => h("li", { class: "mono" }, item)));
}

function accessFieldEvidenceCertificationText(model = {}) {
  const lines = [
    `OIDC/SAML field evidence: ${model.label || "not certified"}`,
    `state=${model.state || "operator-evidence-required"}`,
    `field_run_certification=${model.fieldRunCertification || "not-certified"}`,
    `external_certification=${model.externalCertification || "not-certified"}`,
    `generated_at=${model.generatedAt || ""}`,
    `route=${settingsPanelHash("access")}`,
    `certification_boundary=${model.certificationBoundary || ""}`,
    `non_claim=${model.nonClaim || "No real IdP run is certified by this browser-generated packet."}`,
    "",
  ];
  (model.protocols || []).forEach((protocol) => {
    lines.push(`${protocol.label}:`);
    lines.push(`root=${protocol.rootDir}`);
    lines.push(`artifact_status=${protocol.state || "missing"} ${protocol.statusDetail || ""}`);
    lines.push(`required_field_facts=${protocol.fieldFacts?.complete ? "passed" : "missing"}`);
    (protocol.fieldFacts?.rows || []).forEach((row) => lines.push(`fact=${row.id} state=${row.state} value=${row.value || "missing"} detail=${row.detail}`));
    lines.push(`validate=${protocol.validateCommand}`);
    lines.push(`record=${protocol.recordCommand}`);
    (protocol.buckets || []).forEach((bucket) => {
      lines.push(`bucket=${bucket.id} artifacts=${(bucket.artifacts || []).join(",")} preserve=${bucket.preserve}`);
    });
    lines.push("artifact_inventory:");
    (protocol.artifactInventory || []).forEach((artifact) => lines.push(`- path=${artifact.path} bucket=${artifact.bucket} state=${artifact.state} required=${artifact.requiredSentinel} detail=${artifact.detail}`));
    lines.push("sentinels:");
    (protocol.sentinels || []).forEach((sentinel) => lines.push(`- ${sentinel}`));
    lines.push(`redact=${(protocol.redactionChecklist || []).join(",")}`);
    lines.push("");
  });
  return sanitizeDrawerText(lines.join("\n"));
}

async function copyAccessFieldEvidenceCertification(model = {}) {
  try {
    await navigator.clipboard.writeText(accessFieldEvidenceCertificationText(model));
	    toast("Field evidence checklist copied", "Redacted OIDC/SAML field-evidence checklist copied as plain text; this is not certification.", "ok");
  } catch {
    toast("Copy failed", "Review the visible field-evidence checklist before recording release evidence.", "warn");
  }
}

function accessFieldEvidenceCertificationPacket(model = {}) {
  return redactedAccessPacket(model);
}

function exportAccessFieldEvidenceCertification(model = {}) {
  const packet = accessFieldEvidenceCertificationPacket(model);
  const blob = new Blob([JSON.stringify(packet, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: accessFieldEvidenceCertificationFilename() });
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  toast("Field evidence exported", "Downloaded redacted OIDC/SAML field-evidence handoff JSON.", "ok");
}

function pinAccessFieldEvidenceCertification(model = {}) {
  try {
    const packet = accessFieldEvidenceCertificationPacket(model);
    const result = pinInvestigationPacket(buildInvestigationPacket({
      kind: "access-field-evidence-certification",
      title: "OIDC/SAML field evidence handoff",
      subject: { id: "settings:access:field-evidence-certification", label: "OIDC/SAML field evidence" },
      summary: {
        state: model.state,
        label: model.label,
        oidcEnabled: model.accessPosture?.oidcEnabled,
        samlEnabled: model.accessPosture?.samlEnabled,
        claim: model.fieldRunCertification || "not-certified",
        externalCertification: model.externalCertification || "not-certified",
      },
      evidence: accessFieldEvidenceCertificationText(model).split("\n"),
      artifacts: { accessFieldEvidenceCertification: packet },
    }, { route: settingsPanelHash("access"), collectedAt: model.generatedAt }));
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "OIDC/SAML field evidence handoff could not be pinned.", "bad");
  }
}

function accessFieldEvidenceCertificationFilename() {
  const stamp = new Date().toISOString().replace(/[^0-9A-Za-z]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 32);
  return `openngfw-access-field-evidence-${stamp}.json`;
}

function openSAMLRollout(opts = {}, administration = null) {
  const saml = administration?.saml?.enabled ? administration.saml : {};
  const samlStatus = opts.saml || {};
  const samlRuntimeReady = Boolean(samlStatus.enabled && (samlStatus.runtimeAvailable ?? samlStatus.runtime_available ?? true) && (samlStatus.loginUrl || samlStatus.login_url));
  const defaultRole = roleSelect("viewer");
  defaultRole.setAttribute("data-access-field", "saml-default-role");
  const idpEntityId = h("input", { class: "input", value: saml.idpEntityId || saml.entityId || "", placeholder: "https://idp.example.com/saml", "data-access-field": "saml-idp-entity-id" });
  const metadataUrl = h("input", { class: "input", value: saml.metadataUrl || "", placeholder: "https://idp.example.com/metadata", "data-access-field": "saml-metadata-url" });
  const ssoUrl = h("input", { class: "input", value: saml.ssoUrl || "", placeholder: "https://idp.example.com/sso", "data-access-field": "saml-sso-url" });
  const spEntityId = h("input", { class: "input", value: saml.spEntityId || "", placeholder: "https://firewall.example.com/ui", "data-access-field": "saml-sp-entity-id" });
  const acsUrl = h("input", { class: "input", value: saml.acsUrl || "", placeholder: "https://firewall.example.com/v1/auth/saml/acs", "data-access-field": "saml-acs-url" });
  const roleAttribute = h("input", { class: "input", value: saml.roleAttribute || "groups", placeholder: "groups", "data-access-field": "saml-role-attribute" });
  if (saml.defaultRole) defaultRole.value = saml.defaultRole;
  const certificateFingerprint = h("input", {
    class: "input",
    value: "",
    placeholder: saml.certificateFingerprintConfigured ? "configured; enter a new fingerprint to rotate" : "SHA256 fingerprint",
    "data-access-field": "saml-certificate-fingerprint",
  });
  const auditComment = h("input", { class: "input", placeholder: "Change ticket or operator reason", "data-access-field": "saml-audit-comment" });
  const result = h("div", { "data-access-saml-rollout-result": "true" });
  const currentValues = () => ({
    idpEntityId: idpEntityId.value,
    metadataUrl: metadataUrl.value,
    ssoUrl: ssoUrl.value,
    spEntityId: spEntityId.value,
    acsUrl: acsUrl.value,
    roleAttribute: roleAttribute.value,
    defaultRole: defaultRole.value,
    certificateFingerprint: certificateFingerprint.value,
  });
  const rolloutValues = () => {
    const values = currentValues();
    if (!values.certificateFingerprint && saml.certificateFingerprintConfigured) {
      values.certificateFingerprint = "configured";
    }
    return values;
  };
  const providerConfig = () => samlConfigFromRolloutValues(currentValues());
  const renderPlan = () => {
    const plan = samlRolloutPlan(rolloutValues(), administration || {});
    clear(result);
    result.appendChild(samlRolloutPlanBody(plan));
    return plan;
  };
  const validateServerPacket = async () => {
    const plan = renderPlan();
    try {
      const resp = await api.validateSAMLProviderConfig(providerConfig());
      result.appendChild(h("div", { class: `alert-box ${resp.state === "blocked" ? "warn" : "ok"}` },
        h("strong", {}, `Server validation: ${resp.state || "unknown"}`),
        h("div", { class: "note" }, resp.detail || "SAML provider validation completed."),
        ...(resp.blockers || []).map((item) => h("div", { class: "note" }, `Blocker: ${sanitizeDrawerText(item)}`)),
        ...(resp.warnings || []).map((item) => h("div", { class: "note" }, `Warning: ${sanitizeDrawerText(item)}`))));
    } catch (err) {
      result.appendChild(h("div", { class: "alert-box warn" },
        h("strong", {}, "Server validation unavailable"),
        h("div", { class: "note" }, sanitizeDrawerText(err?.message || String(err)))));
    }
    return plan;
  };
  const saveProvider = async (e) => {
    const btn = e.target.closest("button");
    const comment = auditComment.value.trim();
    const plan = renderPlan();
    if (!comment) {
      toast("Comment required", "Add an audit comment before saving SAML provider config.", "warn");
      return;
    }
    if (plan.state === "blocked") {
      toast("SAML blocked", "Resolve rollout blockers before saving the provider.", "warn");
      return;
    }
    btn.disabled = true;
	    try {
	      const resp = await api.setSAMLProviderConfig({ config: providerConfig(), comment });
	      await refreshAccessAdministration(opts);
	      toast("SAML provider saved", resp.detail || "Runtime browser SSO provider was updated.", "ok");
	      closeDrawer();
	    } catch (err) {
	      btn.disabled = false;
	      toast("SAML save failed", err.message, "bad");
	    }
  };
  const disableProvider = async (e) => {
    const comment = auditComment.value.trim();
    if (!comment) {
      toast("Comment required", "Add an audit comment before disabling SAML.", "warn");
      return;
    }
    if (!(await confirmDialog({
      title: "Disable SAML provider?",
      message: "Disable browser SSO and revoke active SAML sessions while preserving local break-glass access?",
      confirmLabel: "Disable SAML",
      danger: true,
    }))) return;
    const btn = e.target.closest("button");
    btn.disabled = true;
    try {
      const resp = await api.disableSAMLProvider(comment);
      await refreshAccessAdministration(opts);
      toast("SAML provider disabled", resp.detail || "Browser SAML was disabled.", "ok");
      closeDrawer();
    } catch (err) {
      btn.disabled = false;
      toast("SAML disable failed", err.message, "bad");
    }
  };
  [idpEntityId, metadataUrl, ssoUrl, spEntityId, acsUrl, roleAttribute, defaultRole, certificateFingerprint]
    .forEach((el) => el.addEventListener("input", renderPlan));
  openDrawer({
    title: "Prepare SAML",
    subtitle: "Capture IdP metadata, RBAC mapping, and activation blockers.",
    width: "min(860px, 96vw)",
    body: h("div", { class: "stack", "data-access-saml-rollout": "true" },
      h("div", { class: "alert-box " + (samlRuntimeReady ? "ok" : "warn") },
        h("strong", {}, samlRuntimeReady ? "SAML runtime is active. " : "SAML runtime is not active. "),
        h("div", { class: "note" }, samlRuntimeReady
          ? "Use this drawer to validate metadata changes and launch a controlled test login against the active browser SAML endpoint."
          : "Use this drawer to validate and save the IdP/SP metadata packet before production SAML rollout.")),
      h("div", { class: "grid cols-2" },
        h("label", { class: "field" }, h("span", {}, "IdP entity ID"), idpEntityId),
        h("label", { class: "field" }, h("span", {}, "IdP metadata URL"), metadataUrl),
        h("label", { class: "field" }, h("span", {}, "IdP SSO URL"), ssoUrl),
        h("label", { class: "field" }, h("span", {}, "SP entity ID"), spEntityId),
        h("label", { class: "field" }, h("span", {}, "ACS URL"), acsUrl),
        h("label", { class: "field" }, h("span", {}, "Role attribute"), roleAttribute),
        h("label", { class: "field" }, h("span", {}, "Default role"), defaultRole),
        h("label", { class: "field" }, h("span", {}, "Signing cert fingerprint"), certificateFingerprint),
        h("label", { class: "field" }, h("span", {}, "Audit comment"), auditComment)),
      result),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close SAML rollout drawer", "aria-label": "Close SAML rollout drawer", "data-access-action": "close-saml-rollout", onclick: closeDrawer }, "Close"),
      h("button", { class: "btn", type: "button", title: "Validate SAML metadata packet", "aria-label": "Validate SAML metadata packet", "data-access-submit": "validate-saml", onclick: validateServerPacket },
        h("span", { html: icon("shield", 14) }), "Validate packet"),
      saml.enabled ? h("button", { class: "btn danger", type: "button", title: "Disable SAML provider", "aria-label": "Disable SAML provider", "data-access-action": "disable-saml-provider", onclick: disableProvider },
        h("span", { html: icon("block", 14) }), "Disable") : null,
      h("button", { class: "btn primary", type: "button", title: "Save SAML provider", "aria-label": "Save SAML provider", "data-access-submit": "save-saml-provider", onclick: saveProvider },
        h("span", { html: icon("save", 14) }), "Save provider"),
      h("button", { class: "btn ghost", type: "button", title: "Copy SAML rollout packet", "aria-label": "Copy SAML rollout packet", "data-access-action": "copy-saml-rollout", onclick: () => copySAMLRolloutPlan(renderPlan()) },
        h("span", { html: icon("copy", 14) }), "Copy packet"),
      h("button", { class: "btn ghost", type: "button", title: "Export SAML rollout packet JSON", "aria-label": "Export SAML rollout packet JSON", "data-access-action": "export-saml-rollout", onclick: () => exportSAMLRolloutPlan(renderPlan()) },
        h("span", { html: icon("download", 14) }), "Export JSON"),
      h("button", { class: "btn ghost", type: "button", title: "Pin SAML rollout packet to investigation case", "aria-label": "Pin SAML rollout packet to investigation case", "data-access-action": "pin-saml-rollout", onclick: () => pinSAMLRolloutPlan(renderPlan()) },
        h("span", { html: icon("pin", 14) }), "Pin to case"),
      samlRuntimeReady ? h("button", { class: "btn primary", type: "button", title: "Test SAML browser login", "aria-label": "Test SAML browser login", "data-access-action": "test-saml-login", onclick: () => {
        location.href = samlLoginTarget(samlStatus, location.hash) || "/ui/";
      } }, h("span", { html: icon("key", 14) }), "Test SAML login") : h("button", { class: "btn ghost", type: "button", disabled: true, "aria-disabled": "true", title: "SAML browser login/session runtime is not active.", "aria-label": "SAML browser login runtime inactive", "data-access-action": "test-saml-login-unavailable" },
        h("span", { html: icon("block", 14) }), "Runtime inactive"),
    ],
  });
  renderPlan();
}

function samlConfigFromRolloutValues(values = {}) {
  return {
    enabled: true,
    metadataUrl: String(values.metadataUrl || "").trim(),
    idpEntityId: String(values.idpEntityId || "").trim(),
    ssoUrl: String(values.ssoUrl || "").trim(),
    spEntityId: String(values.spEntityId || "").trim(),
    acsUrl: String(values.acsUrl || "").trim(),
    roleAttribute: String(values.roleAttribute || "").trim(),
    defaultRole: String(values.defaultRole || "").trim(),
    certificateFingerprint: String(values.certificateFingerprint || "").trim(),
  };
}

function sanitizeDrawerText(value = "") {
  return String(value || "")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[redacted-jwt]")
    .replace(/\b(?:oidc|saml)?-?session-sha256:[A-Za-z0-9_-]{16,}\b/gi, "[redacted-session]")
    .replace(/\b(client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?id|session|cookie|code|certificate[_-]?fingerprint|saml[_-]?response|assertion)(?:\s*[:=]\s*|\s*%3[dD]\s*)[^,\s;&]+/gi, "$1=[redacted]")
    .replace(/(^|[\s"'({=,;])\/(?:var\/lib|var\/log(?:\/openngfw)?|etc\/(?:openngfw|phragma)|tmp|private\/tmp|var\/folders|private\/var\/folders|home\/[^'"\s,;}]+|Users\/[^'"\s,;}]+)[^'"\s,;}]*/gi, "$1[server-local path redacted]")
    .trim();
}

function redactedAccessPacket(value) {
  if (Array.isArray(value)) return value.map((item) => redactedAccessPacket(item));
  if (!value || typeof value !== "object") {
    return typeof value === "string" ? sanitizeDrawerText(value) : value;
  }
  return Object.fromEntries(Object.entries(value).map(([key, item]) => {
    const normalizedKey = key.replace(/[_-]/g, "").toLowerCase();
    if (typeof item === "string" && ["clientsecret", "clientsecretfile", "certificatefingerprint", "samlresponse", "assertion"].includes(normalizedKey)) {
      return [key, item ? "[redacted]" : ""];
    }
    return [key, redactedAccessPacket(item)];
  }));
}

function samlRolloutPlanBody(plan = {}) {
  const ready = plan.state === "ready";
  const review = plan.state === "review";
  return h("div", { class: "oidc-preflight", "data-access-saml-rollout-state": plan.state },
    h("div", { class: "alert-box " + plan.cls },
      h("strong", {}, `SAML rollout: ${plan.label}. `),
      h("span", {}, ready || review
        ? "Save the provider, then run a controlled SAML test login from this drawer when the runtime reports a login URL."
        : "Resolve blockers before saving the provider or attempting a SAML test login.")),
    h("div", { class: "runtime-grid" },
      networkMetric("IdP entity", plan.values.idpEntityId || "missing"),
      networkMetric("SP entity", plan.values.spEntityId || "missing"),
      networkMetric("ACS URL", plan.values.acsUrl || "missing"),
      networkMetric("Default role", pill(plan.values.defaultRole || "viewer", roleClass(plan.values.defaultRole)))),
    plan.blockers.length ? oidcPreflightIssueList("Blockers", plan.blockers.map((label, idx) => ({ id: `saml-blocker-${idx}`, label })), "bad") : null,
    plan.warnings.length ? oidcPreflightIssueList("Warnings", plan.warnings.map((label, idx) => ({ id: `saml-warning-${idx}`, label })), "warn") : null,
    oidcPreflightChecksTable(plan.checks),
    h("div", { class: "field" },
      h("span", {}, "Planned CLI parity"),
      h("pre", { class: "mono audit-detail-pre", "data-access-saml-rollout-command": "true" }, plan.command)));
}

async function copySAMLRolloutPlan(plan) {
  try {
    await navigator.clipboard.writeText(samlRolloutPlanText(plan));
    toast("SAML rollout copied", "Redacted SAML readiness packet copied as plain text.", "ok");
  } catch {
    toast("Copy failed", "Review the visible SAML rollout before recording evidence.", "warn");
  }
}

function samlRolloutPacket(plan = {}) {
  return redactedAccessPacket({
    schemaVersion: "openngfw.saml-rollout.v1",
    generatedAt: new Date().toISOString(),
    state: plan.state,
    label: plan.label,
    values: plan.values,
    checks: plan.checks,
    blockers: plan.blockers,
    warnings: plan.warnings,
    command: plan.command,
  });
}

function exportSAMLRolloutPlan(plan) {
  const packet = samlRolloutPacket(plan);
  const blob = new Blob([JSON.stringify(packet, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: samlRolloutFilename() });
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  toast("SAML rollout exported", "Downloaded the redacted SAML readiness packet.", "ok");
}

function pinSAMLRolloutPlan(plan) {
  try {
    const packet = samlRolloutPacket(plan);
    const result = pinInvestigationPacket({
      schemaVersion: "phragma.investigation.handoff.v1",
      kind: "saml-rollout",
      title: "SAML rollout handoff",
      collectedAt: new Date().toISOString(),
      generatedBy: "openngfw-webui",
      source: { interface: "webui", route: settingsPanelHash("access") },
      subject: { id: "settings:access:saml-rollout", label: "SAML rollout" },
      summary: {
        state: plan.state,
        blockers: plan.blockers.length,
        idpEntityId: plan.values.idpEntityId,
        spEntityId: plan.values.spEntityId,
      },
      evidence: samlRolloutPlanText(plan).split("\n"),
      artifacts: { samlRollout: packet },
    });
    toast("SAML rollout pinned", `${result.count} item${result.count === 1 ? "" : "s"} in the investigation case.`, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "SAML rollout evidence could not be pinned.", "bad");
  }
}

function samlRolloutFilename() {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  return `openngfw-saml-rollout-${stamp}.json`;
}

function openOIDCRollout(opts = {}, administration = null) {
  const oidc = administration?.oidc || {};
  const values = oidcRolloutInitialValues(oidc);
  const issuer = h("input", { class: "input", value: values.issuer, placeholder: "https://idp.example.com", "data-access-field": "oidc-issuer" });
  const clientId = h("input", { class: "input", value: values.clientId, placeholder: "phragma-webui", "data-access-field": "oidc-client-id" });
  const redirectUrl = h("input", { class: "input", value: values.redirectUrl, placeholder: "https://firewall.example.com/v1/auth/oidc/callback", "data-access-field": "oidc-redirect-url" });
  const roleClaim = h("input", { class: "input", value: values.roleClaim, placeholder: "role", "data-access-field": "oidc-role-claim" });
  const defaultRole = roleSelect(values.defaultRole);
  defaultRole.setAttribute("data-access-field", "oidc-default-role");
  const scopes = h("input", { class: "input", value: values.scopes, placeholder: "openid,profile,email", "data-access-field": "oidc-scopes" });
  const trustedProxyCidrs = h("input", { class: "input", value: values.trustedProxyCidrs, placeholder: "10.0.0.0/8,192.0.2.0/24", "data-access-field": "oidc-trusted-proxy-cidrs" });
  const clientSecretFile = h("input", { class: "input", value: values.clientSecretFile, placeholder: values.clientSecretFilePlaceholder, "data-access-field": "oidc-client-secret-file" });
  const auditComment = h("input", { class: "input", placeholder: "Change ticket or operator reason", "data-access-field": "oidc-audit-comment" });
  const result = h("div", { "data-access-oidc-rollout-result": "true" });
  const currentValues = () => ({
    issuer: issuer.value,
    clientId: clientId.value,
    redirectUrl: redirectUrl.value,
    roleClaim: roleClaim.value,
    defaultRole: defaultRole.value,
    scopes: scopes.value,
    trustedProxyCidrs: trustedProxyCidrs.value,
    clientSecretFile: clientSecretFile.value,
  });
  const providerConfig = () => oidcProviderConfigFromRolloutValues(currentValues(), oidc);
  const renderPlan = () => {
    const values = currentValues();
    const plan = oidcRolloutPlan(values, administration || {}, opts.oidc || {});
    normalizeOIDCConfiguredSecretPlan(plan, values, oidc);
    clear(result);
    result.appendChild(oidcRolloutPlanBody(plan, opts));
    return plan;
  };
  const saveProvider = async (e) => {
    const btn = e.target.closest("button");
    const comment = auditComment.value.trim();
    const plan = renderPlan();
    if (!comment) {
      toast("Comment required", "Add an audit comment before saving OIDC provider config.", "warn");
      return;
    }
    if (plan.state === "blocked") {
      toast("OIDC blocked", "Resolve rollout blockers before saving the provider.", "warn");
      return;
    }
    btn.disabled = true;
	    try {
	      const resp = await api.setOIDCProviderConfig({ config: providerConfig(), comment });
	      await refreshAccessAdministration(opts);
	      toast("OIDC provider saved", resp.detail || "Runtime browser SSO provider was updated.", "ok");
	      closeDrawer();
	    } catch (err) {
	      btn.disabled = false;
	      toast("OIDC save failed", err.message, "bad");
	    }
  };
  const disableProvider = async (e) => {
    const comment = auditComment.value.trim();
    if (!comment) {
      toast("Comment required", "Add an audit comment before disabling OIDC.", "warn");
      return;
    }
    if (!(await confirmDialog({
      title: "Disable OIDC provider?",
      message: "Disable browser SSO and revoke active OIDC sessions while preserving local break-glass access?",
      confirmLabel: "Disable OIDC",
      danger: true,
    }))) return;
    const btn = e.target.closest("button");
    btn.disabled = true;
    try {
      const resp = await api.disableOIDCProvider(comment);
      await refreshAccessAdministration(opts);
      toast("OIDC provider disabled", resp.detail || "Browser SSO was disabled.", "ok");
      closeDrawer();
    } catch (err) {
      btn.disabled = false;
      toast("OIDC disable failed", err.message, "bad");
    }
  };
  [issuer, clientId, redirectUrl, roleClaim, defaultRole, scopes, trustedProxyCidrs, clientSecretFile]
    .forEach((el) => el.addEventListener("input", renderPlan));
  renderPlan();
  openDrawer({
    title: "Configure OIDC",
    subtitle: "Validate IdP rollout posture and generate activation evidence.",
    width: "min(820px, 96vw)",
    body: h("div", {},
      h("div", { class: "alert-box info" },
        h("strong", {}, "OIDC activation is runtime-managed. "),
        "This workflow validates the provider posture, checks break-glass readiness, and produces redacted activation material for the supported daemon configuration path."),
      h("div", { class: "grid cols-2" },
        h("label", { class: "field" }, h("span", {}, "Issuer URL"), issuer),
        h("label", { class: "field" }, h("span", {}, "Client ID"), clientId),
        h("label", { class: "field" }, h("span", {}, "Redirect URL"), redirectUrl),
        h("label", { class: "field" }, h("span", {}, "Role claim"), roleClaim),
        h("label", { class: "field" }, h("span", {}, "Default role"), defaultRole),
        h("label", { class: "field" }, h("span", {}, "Scopes"), scopes),
        h("label", { class: "field" }, h("span", {}, "Trusted proxy CIDRs"), trustedProxyCidrs),
        h("label", { class: "field" }, h("span", {}, "Client secret file"), clientSecretFile),
        h("label", { class: "field" }, h("span", {}, "Audit comment"), auditComment)),
      result),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close OIDC rollout drawer", "aria-label": "Close OIDC rollout drawer", "data-access-action": "close-oidc-rollout", onclick: closeDrawer }, "Close"),
      h("button", { class: "btn", type: "button", title: "Validate OIDC rollout plan", "aria-label": "Validate OIDC rollout plan", "data-access-submit": "validate-oidc", onclick: renderPlan }, h("span", { html: icon("shield", 14) }), "Validate"),
      oidc.enabled ? h("button", { class: "btn danger", type: "button", title: "Disable OIDC provider", "aria-label": "Disable OIDC provider", "data-access-action": "disable-oidc-provider", onclick: disableProvider },
        h("span", { html: icon("block", 14) }), "Disable") : null,
      h("button", { class: "btn primary", type: "button", title: "Save OIDC provider", "aria-label": "Save OIDC provider", "data-access-submit": "save-oidc-provider", onclick: saveProvider },
        h("span", { html: icon("save", 14) }), "Save provider"),
    ],
  });
}

function normalizeOIDCConfiguredSecretPlan(plan = {}, values = {}, oidc = {}) {
  if (!oidc?.clientSecretFileConfigured || values.clientSecretFile) return plan;
  plan.values = { ...(plan.values || {}), clientSecretFile: "[configured]" };
  plan.warnings = (plan.warnings || []).filter((warning) => !/No client secret file is set/i.test(warning));
  plan.state = plan.blockers?.length ? "blocked" : plan.warnings.length ? "review" : "ready";
  plan.cls = plan.blockers?.length ? "bad" : plan.warnings.length ? "warn" : "ok";
  plan.label = plan.blockers?.length
    ? `${plan.blockers.length} blocker${plan.blockers.length === 1 ? "" : "s"}`
    : plan.warnings.length
    ? `${plan.warnings.length} review item${plan.warnings.length === 1 ? "" : "s"}`
    : "ready";
  return plan;
}

function oidcProviderConfigFromRolloutValues(values = {}, existing = {}) {
  const config = {
    enabled: true,
    issuer: values.issuer || "",
    clientId: values.clientId || "",
    clientSecretFile: values.clientSecretFile || "",
    redirectUrl: values.redirectUrl || "",
    roleClaim: values.roleClaim || "role",
    defaultRole: values.defaultRole || "viewer",
    scopes: String(values.scopes || "").split(",").map((v) => v.trim()).filter(Boolean),
    trustedProxyCidrs: String(values.trustedProxyCidrs || "").split(",").map((v) => v.trim()).filter(Boolean),
  };
  if (!config.clientSecretFile && existing?.clientSecretFileConfigured) delete config.clientSecretFile;
  return config;
}

function oidcRolloutPlanBody(plan, opts = {}) {
  return h("div", { class: "oidc-preflight", "data-access-oidc-rollout-state": plan.state },
    h("div", { class: "alert-box " + plan.cls },
      h("strong", {}, `OIDC rollout: ${plan.label}. `),
      plan.state === "blocked"
        ? "Resolve blockers before activating browser SSO."
        : plan.state === "review"
        ? "Review warnings before activating browser SSO."
        : "Provider posture is ready for controlled activation."),
    h("div", { class: "runtime-grid access-governance-summary" },
      networkMetric("State", pill(plan.state, plan.cls)),
      networkMetric("Issuer", plan.values.issuer || "not set"),
      networkMetric("Client ID", h("span", { class: "mono" }, plan.values.clientId || "not set")),
      networkMetric("Break-glass", pill(plan.breakGlassReady ? "ready" : "blocked", plan.breakGlassReady ? "ok" : "bad")),
      networkMetric("Local admins", String(plan.localAdminCount)),
      networkMetric("Default role", pill(plan.values.defaultRole, roleClass(plan.values.defaultRole)))),
    plan.blockers.length ? oidcPreflightIssueList("Blockers", plan.blockers.map((label, idx) => ({ id: `blocker-${idx}`, label })), "bad") : null,
    plan.warnings.length ? oidcPreflightIssueList("Warnings", plan.warnings.map((label, idx) => ({ id: `warning-${idx}`, label })), "warn") : null,
    oidcPreflightChecksTable(plan.checks),
    h("div", { class: "profile-strip" },
      h("div", { class: "profile-strip-head" },
        h("strong", {}, "Activation command"),
        h("span", {}, "redacted runbook")),
      h("pre", { class: "mono audit-detail-pre", "data-access-oidc-rollout-command": "true" }, plan.command)),
    h("div", { class: "flex wrap", style: { marginTop: "12px", gap: "8px" } },
      h("button", { class: "btn ghost", type: "button", title: "Copy OIDC rollout plan", "aria-label": "Copy OIDC rollout plan", "data-access-action": "copy-oidc-rollout", onclick: () => copyOIDCRolloutPlan(plan) },
        h("span", { html: icon("copy", 14) }), "Copy rollout"),
      h("button", { class: "btn ghost", type: "button", title: "Export OIDC rollout plan JSON", "aria-label": "Export OIDC rollout plan JSON", "data-access-action": "export-oidc-rollout", onclick: () => exportOIDCRolloutPlan(plan) },
        h("span", { html: icon("download", 14) }), "Export JSON"),
      h("button", { class: "btn ghost", type: "button", title: "Pin OIDC rollout plan to investigation case", "aria-label": "Pin OIDC rollout plan to investigation case", "data-access-action": "pin-oidc-rollout", onclick: () => pinOIDCRolloutPlan(plan) },
        h("span", { html: icon("inbox", 14) }), "Pin to case"),
      opts.oidc?.enabled ? h("button", { class: "btn", type: "button", title: "Test OIDC browser login", "aria-label": "Test OIDC browser login", "data-access-action": "test-oidc-login", onclick: () => {
        location.href = oidcLoginTarget(opts.oidc, location.hash) || "/ui/";
      } }, h("span", { html: icon("key", 14) }), "Test login") : null,
      opts.oidc?.enabled ? h("button", { class: "btn", type: "button", title: "Run OIDC browser preflight", "aria-label": "Run OIDC browser preflight", "data-access-action": "run-oidc-preflight", onclick: () => openOIDCPreflight(opts) },
        h("span", { html: icon("shield", 14) }), "Run preflight") : null));
}

async function copyOIDCRolloutPlan(plan) {
  try {
    await navigator.clipboard.writeText(oidcRolloutPlanText(plan));
    toast("OIDC rollout copied", "Redacted IdP activation runbook copied as plain text.", "ok");
  } catch {
    toast("Copy failed", "Review the visible OIDC rollout before recording evidence.", "warn");
  }
}

function oidcRolloutPacket(plan = {}) {
  return redactedAccessPacket({
    schemaVersion: "openngfw.oidc-rollout.v1",
    generatedAt: new Date().toISOString(),
    state: plan.state,
    label: plan.label,
    values: plan.values,
    checks: plan.checks,
    blockers: plan.blockers,
    warnings: plan.warnings,
    command: plan.command,
    systemdDropIn: plan.systemdDropIn,
    breakGlassReady: plan.breakGlassReady,
    localAdminCount: plan.localAdminCount,
  });
}

function exportOIDCRolloutPlan(plan) {
  const packet = oidcRolloutPacket(plan);
  const blob = new Blob([JSON.stringify(packet, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: oidcRolloutFilename() });
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  toast("OIDC rollout exported", "Downloaded the redacted IdP rollout packet.", "ok");
}

function pinOIDCRolloutPlan(plan) {
  try {
    const packet = oidcRolloutPacket(plan);
    const result = pinInvestigationPacket(buildInvestigationPacket({
      kind: "oidc-rollout",
      title: "OIDC rollout handoff",
      subject: { id: "settings:access:oidc-rollout", label: "OIDC rollout" },
      summary: {
        state: plan.state,
        label: plan.label,
        issuer: plan.values.issuer,
        clientId: plan.values.clientId,
        blockerCount: plan.blockers.length,
        warningCount: plan.warnings.length,
        breakGlassReady: plan.breakGlassReady,
      },
      evidence: oidcRolloutPlanText(plan).split("\n"),
      artifacts: { oidcRollout: packet },
    }, { route: settingsPanelHash("access") }));
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "OIDC rollout evidence could not be pinned.", "bad");
  }
}

function oidcRolloutFilename() {
  const stamp = new Date().toISOString().replace(/[^0-9A-Za-z]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 32);
  return `openngfw-oidc-rollout-${stamp}.json`;
}

async function openOIDCPreflight(opts = {}) {
  openDrawer({
    title: "OIDC preflight",
    subtitle: "Read-only browser SSO rollout evidence",
    width: "min(760px, 96vw)",
    body: h("div", { class: "alert-box info" },
      h("strong", {}, "Running OIDC preflight. "),
      "Provider discovery, signing keys, session-cookie posture, role mapping, proxy trust, and session capacity are being checked."),
    footer: h("button", { class: "btn ghost", type: "button", title: "Close OIDC preflight drawer", "aria-label": "Close OIDC preflight drawer", "data-access-action": "close-oidc-preflight", onclick: closeDrawer }, "Close"),
  });
  try {
    const model = oidcPreflightModel(await api.oidcPreflight());
    openDrawer({
      title: "OIDC preflight",
      subtitle: "Read-only browser SSO rollout evidence",
      width: "min(760px, 96vw)",
      body: oidcPreflightBody(model),
      footer: oidcPreflightFooter(model, opts),
    });
  } catch (e) {
    openDrawer({
      title: "OIDC preflight",
      subtitle: "Read-only browser SSO rollout evidence",
      width: "min(760px, 96vw)",
      body: h("div", { class: "alert-box bad" },
        h("strong", {}, "OIDC preflight could not run. "),
        e.message || "The backend did not return preflight evidence."),
      footer: h("button", { class: "btn ghost", type: "button", title: "Close OIDC preflight drawer", "aria-label": "Close OIDC preflight drawer", "data-access-action": "close-oidc-preflight", onclick: closeDrawer }, "Close"),
    });
  }
}

function oidcPreflightBody(model) {
  return h("div", { class: "oidc-preflight" },
    h("div", { class: "alert-box " + model.cls },
      h("strong", {}, `OIDC preflight: ${model.label}. `),
      model.detail),
    h("div", { class: "runtime-grid access-governance-summary" },
      networkMetric("State", pill(model.state, model.cls)),
      networkMetric("Generated", h("span", { class: "mono" }, model.generatedAt)),
      networkMetric("Issuer", model.oidc.issuer),
      networkMetric("Client ID", h("span", { class: "mono" }, model.oidc.clientId)),
      networkMetric("Cookie secure", pill(model.oidc.cookieSecure === null ? "unknown" : model.oidc.cookieSecure ? "yes" : "no", model.oidc.cookieSecure === false ? "bad" : "ok")),
      networkMetric("Checks", `${model.checks.length} returned`)),
    oidcPreflightIssueList("Blockers", model.blockers, "bad"),
    oidcPreflightIssueList("Warnings", model.warnings, "warn"),
    oidcPreflightChecksTable(model.checks),
    model.evidence.length ? h("div", { class: "alert-box info" },
      h("strong", {}, "Evidence"),
      h("ul", { class: "compact-list" }, model.evidence.map((item) => h("li", {}, item)))) : null);
}

function oidcPreflightIssueList(title, items = [], cls = "warn") {
  if (!items.length) return null;
  return h("div", { class: "alert-box " + cls },
    h("strong", {}, title),
    h("ul", { class: "compact-list" }, items.map((item) => h("li", {}, item.label))));
}

function oidcPreflightChecksTable(checks = []) {
  return h("div", { class: "table-wrap flat access-governance-table" },
    responsiveTable(["Check", "State", "Detail", "Evidence", "Next action"],
      checks.map((check) => h("tr", {},
        labeledCell("Check", {}, h("strong", {}, check.label), h("div", { class: "note" }, check.id)),
        labeledCell("State", {}, pill(check.state, check.cls)),
        labeledCell("Detail", {}, check.detail),
        labeledCell("Evidence", {}, check.evidence),
        labeledCell("Next action", {}, check.nextAction))),
      { className: "settings-oidc-preflight-table" }));
}

function oidcPreflightFooter(model, opts = {}) {
  return h("div", { class: "flex wrap", style: { gap: "8px", justifyContent: "space-between", width: "100%" } },
    h("div", { class: "flex wrap", style: { gap: "8px" } },
      h("button", { class: "btn ghost", type: "button", title: "Pin OIDC preflight evidence to investigation case", "aria-label": "Pin OIDC preflight evidence to investigation case", "data-access-action": "pin-oidc-preflight", onclick: () => pinOIDCPreflightEvidence(model) },
        h("span", { html: icon("inbox", 14) }), "Pin to case"),
      h("button", { class: "btn ghost", type: "button", title: "Copy OIDC preflight evidence", "aria-label": "Copy OIDC preflight evidence", "data-access-action": "copy-oidc-preflight", onclick: () => copyOIDCPreflightEvidence(model) },
        h("span", { html: icon("copy", 14) }), "Copy evidence"),
      h("button", { class: "btn ghost", type: "button", title: "Export OIDC preflight evidence JSON", "aria-label": "Export OIDC preflight evidence JSON", "data-access-action": "export-oidc-preflight", onclick: () => exportOIDCPreflightEvidence(model) },
        h("span", { html: icon("download", 14) }), "Export JSON")),
    h("div", { class: "flex wrap", style: { gap: "8px" } },
      opts.oidc?.enabled ? h("button", { class: "btn", type: "button", title: "Sign in with OIDC", "aria-label": "Sign in with OIDC", "data-access-action": "sign-in-oidc-preflight", onclick: () => {
        location.href = oidcLoginTarget(opts.oidc, location.hash) || "/ui/";
      } }, h("span", { html: icon("key", 14) }), "Sign in") : null,
      h("button", { class: "btn ghost", type: "button", title: "Close OIDC preflight drawer", "aria-label": "Close OIDC preflight drawer", "data-access-action": "close-oidc-preflight", onclick: closeDrawer }, "Close")));
}

async function copyOIDCPreflightEvidence(model) {
  try {
    await navigator.clipboard.writeText(oidcPreflightEvidenceText(model));
    toast("OIDC preflight copied", "Redacted browser SSO rollout evidence copied as plain text.", "ok");
  } catch {
    toast("Copy failed", "Review the visible OIDC preflight before recording field evidence.", "warn");
  }
}

function oidcPreflightEvidencePacket(model) {
  return redactedAccessPacket({
    schemaVersion: model.schemaVersion,
    generatedAt: model.generatedAt,
    state: model.state,
    label: model.label,
    detail: model.detail,
    oidc: {
      issuer: model.oidc.issuer,
      clientId: model.oidc.clientId,
      roleClaim: model.oidc.roleClaim,
      defaultRole: model.oidc.defaultRole,
      cookieSecure: model.oidc.cookieSecure,
      scopes: model.oidc.scopes,
      trustedProxyCidrs: model.oidc.trustedProxyCidrs,
      sessionTtlSeconds: model.oidc.sessionTtlSeconds,
    },
    checks: model.checks,
    blockers: model.blockers.map((item) => item.label),
    warnings: model.warnings.map((item) => item.label),
    evidence: model.evidence,
  });
}

function oidcPreflightInvestigationHandoffPacket(model = {}) {
  const packet = oidcPreflightEvidencePacket(model);
  return buildInvestigationPacket({
    kind: "oidc-preflight",
    title: "OIDC preflight handoff",
    subject: {
      id: "settings:access:oidc-preflight",
      label: "OIDC preflight",
    },
    summary: {
      state: model.state || "unknown",
      label: model.label || "",
      detail: model.detail || "",
      generatedAt: model.generatedAt || "",
      issuer: model.oidc?.issuer || "",
      clientId: model.oidc?.clientId || "",
      checkCount: Array.isArray(model.checks) ? model.checks.length : 0,
      blockerCount: Array.isArray(model.blockers) ? model.blockers.length : 0,
      warningCount: Array.isArray(model.warnings) ? model.warnings.length : 0,
    },
    evidence: oidcPreflightEvidenceText(model).split("\n"),
    artifacts: { oidcPreflight: packet },
  }, { route: settingsPanelHash("access"), collectedAt: model.generatedAt });
}

function pinOIDCPreflightEvidence(model) {
  try {
    const result = pinInvestigationPacket(oidcPreflightInvestigationHandoffPacket(model));
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "OIDC preflight evidence could not be pinned.", "bad");
  }
}

function exportOIDCPreflightEvidence(model) {
  const packet = oidcPreflightEvidencePacket(model);
  const blob = new Blob([JSON.stringify(packet, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: oidcPreflightEvidenceFilename(model) });
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  toast("OIDC preflight exported", "Downloaded the redacted browser SSO verification packet.", "ok");
}

function oidcPreflightEvidenceFilename(model = {}) {
  const stamp = String(model.generatedAt || new Date().toISOString())
    .replace(/[^0-9A-Za-z]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 32) || "latest";
  return `openngfw-oidc-preflight-${stamp}.json`;
}

function accessSessionsTable(sessions = [], opts = {}) {
  if (!sessions.length) {
    return h("div", { class: "alert-box info" },
      h("strong", {}, "No active browser SSO sessions reported."),
      h("div", { class: "note" }, "The endpoint returned no active server-side browser sessions."));
  }
  return h("div", { class: "table-wrap flat access-governance-table" },
    responsiveTable(["Browser SSO session", "Actor", "Role", "Expires", "Audit", { label: "Action", attrs: { class: "actions-col" } }],
      sessions.map((session) => h("tr", {},
        labeledCell("Browser SSO session", {}, h("code", { title: session.sessionId }, session.sessionFingerprint)),
        labeledCell("Actor", {}, h("strong", {}, session.actor), h("div", { class: "note" }, session.authSource)),
        labeledCell("Role", {}, pill(session.role, roleClass(session.role))),
        labeledCell("Expires", {}, h("span", { class: "mono", title: session.expiresAt }, session.expiryLabel)),
        labeledCell("Audit", {}, h("a", { class: "btn sm ghost", href: session.auditHash, title: `Open browser SSO session audit for ${session.actor}`, "aria-label": `Open browser SSO session audit for ${session.actor}`, "data-access-action": "session-audit" }, h("span", { html: icon("clock", 14) }), "Audit")),
        labeledCell("Action", { class: "cell-actions" },
          h("button", { class: "btn sm danger", type: "button", title: `Revoke browser SSO session for ${session.actor}`, "aria-label": `Revoke browser SSO session for ${session.actor}`, "data-access-action": "revoke-session", "data-access-session": session.sessionFingerprint || session.sessionId, onclick: () => revokeAccessSession(session, opts) },
            h("span", { html: icon("block", 14) }), "Revoke"))))));
}

async function revokeAccessSession(session, opts = {}) {
  if (!(await confirmDialog({
    title: "Revoke browser SSO session?",
    message: `Sign out ${session.actor} by revoking this server-side browser session?`,
    confirmLabel: "Revoke session",
    danger: true,
  }))) return;
  try {
    await api.revokeAccessSession(session.sessionId);
    await refreshAccessAdministration(opts);
    toast("Session revoked", `${session.actor} was signed out.`, "ok");
  } catch (e) {
    toast("Could not revoke session", e.message, "bad");
  }
}

function accessBlockerList(blockers = []) {
  if (!blockers.length) return null;
  return h("div", { class: "alert-box bad" },
    h("strong", {}, "Access blockers"),
    h("ul", { class: "compact-list" }, blockers.map((blocker) => h("li", {}, blocker.label))));
}

function accessRoleComparisonPanel() {
  const previews = ["viewer", "operator", "admin"].map((role) => roleImpactPreview("unknown", role));
  return h("div", { class: "access-role-preview-panel" },
    h("div", { class: "access-role-preview-head" },
      h("strong", {}, "RBAC role preview"),
      h("span", { class: "note" }, "Server-side authorization remains authoritative.")),
    h("div", { class: "table-wrap flat access-governance-table" },
      responsiveTable(["Role", "Allowed workflows", "Restricted workflows"],
        previews.map((preview) => h("tr", {},
          labeledCell("Role", {}, pill(preview.targetRole, roleClass(preview.targetRole))),
          labeledCell("Allowed workflows", {}, accessRoleWorkflowChips(preview.allowed, "ok")),
          labeledCell("Restricted workflows", {}, accessRoleWorkflowChips(preview.restricted, "neutral")))),
        { className: "settings-access-role-preview-table" })));
}

function accessRolePreviewPanel(preview, title = "Role impact preview") {
  return h("div", { class: "access-role-preview-panel" },
    h("div", { class: "access-role-preview-head" },
      h("strong", {}, title),
      pill(preview.label, preview.cls, true)),
    h("div", { class: "note" }, preview.detail),
    h("div", { class: "runtime-grid access-governance-summary" },
      networkMetric("Current role", pill(preview.currentRole, roleClass(preview.currentRole))),
      networkMetric("Target role", pill(preview.targetRole, roleClass(preview.targetRole))),
      networkMetric("Newly allowed", String(preview.gained.length)),
      networkMetric("Lost", String(preview.lost.length))),
    h("div", { class: "grid cols-2 access-role-preview-lists" },
      accessRolePreviewList("Newly allowed", preview.gained, "ok"),
      accessRolePreviewList("Lost access", preview.lost, "bad"),
      accessRolePreviewList("Allowed after change", preview.allowed, "info"),
      accessRolePreviewList("Restricted after change", preview.restricted, "neutral")));
}

function accessRolePreviewList(title, rows = [], cls = "neutral") {
  return h("div", { class: "access-role-preview-list" },
    h("strong", {}, title),
    rows.length
      ? h("ul", { class: "compact-list" }, rows.map((row) => h("li", {},
        pill(row.requiredRole, roleClass(row.requiredRole)),
        " ",
        row.label)))
      : h("div", { class: "note" }, cls === "bad" ? "No workflows removed." : cls === "ok" ? "No workflows added." : "None."));
}

function accessRoleWorkflowChips(rows = [], cls = "neutral") {
  if (!rows.length) return h("span", { class: "muted" }, "none");
  return h("div", { class: "access-role-chip-list" }, rows.map((row) =>
    h("span", { class: "tag access-role-chip " + cls, title: row.detail }, row.label)));
}

function breakGlassRotationPanel(administration = {}, opts = {}) {
  const admins = breakGlassAdminUsers(administration.localUsers || []);
  const editableAdmins = admins.filter((user) => user.editable && user.enabled);
  const singleAdmin = admins.filter((user) => user.enabled).length === 1;
  const cls = editableAdmins.length ? (singleAdmin ? "warn" : "ok") : "bad";
  const selected = h("select", { class: "input", "data-access-field": "breakglass-user", disabled: !editableAdmins.length },
    editableAdmins.length
      ? editableAdmins.map((user) => h("option", { value: user.name }, `${user.name} (${user.role})`))
      : h("option", { value: "" }, "No editable enabled local admin"));
  return h("div", { class: "access-breakglass-panel", dataset: { accessBreakglassPanel: "true" } },
    h("div", { class: "access-role-preview-head" },
      h("strong", {}, "Break-glass rotation"),
      pill(administration.breakGlass?.state || "unknown", administration.breakGlass?.cls || cls, true)),
    h("div", { class: "alert-box " + cls },
      h("strong", {}, editableAdmins.length ? "Local admin credential available. " : "No editable enabled local admin. "),
      singleAdmin
        ? "This is the only enabled local admin; rotate during a controlled window and store the one-time token before leaving the drawer."
        : editableAdmins.length
        ? "Rotate emergency local admin credentials without changing OIDC or normal operator sessions."
        : "Create or enable an audited local admin before relying on browser SSO or remote IdP access."),
    h("div", { class: "runtime-grid access-governance-summary" },
      networkMetric("Enabled local admins", String(admins.filter((user) => user.enabled).length)),
      networkMetric("Editable admins", String(editableAdmins.length)),
      networkMetric("Posture", pill(administration.breakGlass?.state || "unknown", administration.breakGlass?.cls || cls)),
      networkMetric("Next action", administration.breakGlass?.nextAction || "Review emergency access rotation schedule.")),
    h("div", { class: "grid cols-2" },
      h("label", { class: "field" }, h("span", {}, "Credential"), selected),
      h("div", { class: "field" },
        h("span", {}, "Evidence"),
        h("a", { class: "btn ghost", href: accessAuditHash({ action: "access-local-user-rotate", query: "break-glass" }), title: "Open break-glass rotation audit", "aria-label": "Open break-glass rotation audit", "data-access-action": "breakglass-rotation-audit" },
          h("span", { html: icon("clock", 14) }), "Rotation audit"))),
    h("div", { class: "flex wrap", style: { gap: "8px" } },
      h("button", { class: "btn", type: "button", title: "Rotate selected break-glass credential", "aria-label": "Rotate selected break-glass local admin credential", disabled: !editableAdmins.length, "data-access-action": "rotate-breakglass", onclick: () => {
        const user = editableAdmins.find((item) => item.name === selected.value);
        if (user) openBreakGlassRotation(user, administration, opts);
      } }, h("span", { html: icon("refresh", 14) }), "Rotate break-glass"),
      h("button", { class: "btn ghost", type: "button", title: "Create break-glass admin", "aria-label": "Create audited break-glass local admin credential", "data-access-action": "create-breakglass-admin", onclick: () => openCreateBreakGlassAdmin(opts) },
        h("span", { html: icon("plus", 14) }), "Create admin")));
}

function breakGlassAdminUsers(users = []) {
  return (Array.isArray(users) ? users : []).filter((user) => {
    const source = String(user?.authSource || "").toLowerCase();
    return user?.role === "admin" && !source.includes("oidc");
  });
}

function accessLocalUsersTable(users = [], opts = {}) {
  if (!users.length) {
    return h("div", { class: "alert-box info" },
      h("strong", {}, "No local users reported."),
      h("div", { class: "note" }, "The endpoint returned an empty local user inventory."));
  }
  return h("div", { class: "table-wrap flat access-governance-table" },
    responsiveTable(["Local user", "Role", "State", "Source", "Token material", "Edit", "Evidence", { label: "Action", attrs: { class: "actions-col" } }],
      users.map((user) => h("tr", { "data-local-user": user.name },
        labeledCell("Local user", {}, h("strong", {}, user.name)),
        labeledCell("Role", {}, pill(user.role, roleClass(user.role))),
        labeledCell("State", {}, pill(user.enabledLabel, user.enabledCls)),
        labeledCell("Source", { class: "mono" }, user.authSource),
        labeledCell("Token material", {}, user.tokenMaterial),
        labeledCell("Edit", {}, pill(user.editableLabel, user.editableCls)),
        labeledCell("Evidence", {}, accessUserEvidenceCell(user)),
        labeledCell("Action", { class: "cell-actions" }, localUserActionButtons(user, opts))))));
}

function localUserActionButtons(user, opts = {}) {
  if (!user.editable) return h("span", { class: "muted" }, "—");
  return h("div", { class: "flex wrap" },
    h("button", { class: "btn sm ghost", type: "button", title: `Change role for ${user.name}`, "aria-label": `Change role for local user ${user.name}`, "data-access-action": "update-local-user", "data-access-user": user.name, onclick: () => openUpdateLocalUser(user, opts) },
      h("span", { html: icon("edit", 14) }), "Role"),
    h("button", { class: "btn sm ghost", type: "button", title: `Rotate token for ${user.name}`, "aria-label": `Rotate token for local user ${user.name}`, "data-access-action": "rotate-local-user", "data-access-user": user.name, onclick: () => openRotateLocalUser(user, opts) },
      h("span", { html: icon("refresh", 14) }), "Rotate"),
    user.enabled ? h("button", { class: "btn sm danger", type: "button", title: `Disable local user ${user.name}`, "aria-label": `Disable local user ${user.name}`, "data-access-action": "disable-local-user", "data-access-user": user.name, onclick: () => disableLocalUser(user, opts) },
      h("span", { html: icon("block", 14) }), "Disable") : null);
}

function roleSelect(current = "viewer") {
  return h("select", { class: "input" },
    h("option", { value: "viewer", selected: current === "viewer" }, "viewer"),
    h("option", { value: "operator", selected: current === "operator" }, "operator"),
    h("option", { value: "admin", selected: current === "admin" }, "admin"));
}

function openCreateLocalUser(opts = {}) {
  const name = h("input", { class: "input", placeholder: "alice", "data-access-field": "local-user-name" });
  const role = roleSelect("viewer");
  role.setAttribute("data-access-field", "local-user-role");
  const comment = h("textarea", { class: "input", placeholder: "Why this credential is being created", "data-access-field": "local-user-comment" });
  const preview = h("div", {});
  const renderPreview = () => {
    clear(preview);
    preview.appendChild(accessRolePreviewPanel(roleImpactPreview("unknown", role.value), "New user role impact"));
  };
  role.addEventListener("change", renderPreview);
  renderPreview();
  const createBtn = h("button", { class: "btn primary", type: "button", title: "Create local user", "aria-label": "Create audited local user credential", "data-access-submit": "create-local-user", onclick: async () => {
    const userName = name.value.trim();
    const auditComment = comment.value.trim();
    if (!userName || !auditComment) {
      toast("Missing fields", "Add a user name and audit comment.", "warn");
      return;
    }
    createBtn.disabled = true;
    try {
      const result = await api.createLocalUser({ name: userName, role: role.value, comment: auditComment });
      await refreshAccessAdministration(opts);
      showOneTimeToken(result, "Local user created");
    } catch (e) {
      createBtn.disabled = false;
      toast("Create failed", e.message, "bad");
    }
  } }, h("span", { html: icon("plus", 16) }), "Create");
  openDrawer({
    title: "Create local user",
    subtitle: "Generates a one-time bearer token and stores only a token hash.",
    width: "560px",
    body: h("div", {},
      h("label", { class: "field" }, h("span", {}, "User name"), name),
      h("label", { class: "field" }, h("span", {}, "Role"), role),
      preview,
      h("label", { class: "field" }, h("span", {}, "Audit comment"), comment)),
    footer: [h("button", { class: "btn ghost", type: "button", title: "Cancel local user creation", "aria-label": "Cancel local user creation", "data-access-action": "cancel-create-local-user", onclick: closeDrawer }, "Cancel"), createBtn],
  });
}

function openCreateBreakGlassAdmin(opts = {}) {
  const name = h("input", { class: "input", placeholder: "breakglass-admin", "data-access-field": "local-user-name" });
  const comment = h("textarea", { class: "input", "data-access-field": "local-user-comment" },
    "create audited break-glass local admin");
  const createBtn = h("button", { class: "btn primary", type: "button", title: "Create break-glass admin", "aria-label": "Create audited break-glass local admin credential", "data-access-submit": "create-breakglass-admin", onclick: async () => {
    const userName = name.value.trim();
    const auditComment = comment.value.trim();
    if (!userName || !auditComment) {
      toast("Missing fields", "Add a break-glass user name and audit comment.", "warn");
      return;
    }
    createBtn.disabled = true;
    try {
      const result = await api.createLocalUser({ name: userName, role: "admin", comment: auditComment });
      await refreshAccessAdministration(opts);
      showOneTimeToken(result, "Break-glass admin created", {
        purpose: "break-glass-create",
        evidenceTitle: "Break-glass admin creation",
        detail: "A local admin break-glass credential was created through the audited access workflow.",
      });
    } catch (e) {
      createBtn.disabled = false;
      toast("Create failed", e.message, "bad");
    }
  } }, h("span", { html: icon("plus", 16) }), "Create admin");
  openDrawer({
    title: "Create break-glass admin",
    subtitle: "Generates a one-time local admin token for emergency access.",
    width: "600px",
    body: h("div", {},
      h("div", { class: "alert-box warn" },
        h("strong", {}, "Emergency credential. "),
        "Store the one-time token in the approved secret manager before closing the result drawer."),
      h("label", { class: "field" }, h("span", {}, "User name"), name),
      accessRolePreviewPanel(roleImpactPreview("unknown", "admin"), "Break-glass admin role impact"),
      h("label", { class: "field" }, h("span", {}, "Audit comment"), comment)),
    footer: [h("button", { class: "btn ghost", type: "button", title: "Cancel break-glass admin creation", "aria-label": "Cancel break-glass admin creation", "data-access-action": "cancel-create-breakglass-admin", onclick: closeDrawer }, "Cancel"), createBtn],
  });
}

function openUpdateLocalUser(user, opts = {}) {
  const role = roleSelect(user.role);
  role.setAttribute("data-access-field", "local-user-role");
  const comment = h("textarea", { class: "input", placeholder: "Why this role is changing", "data-access-field": "local-user-comment" });
  const preview = h("div", {});
  const renderPreview = () => {
    clear(preview);
    preview.appendChild(accessRolePreviewPanel(roleImpactPreview(user.role, role.value), "Role change impact"));
  };
  role.addEventListener("change", renderPreview);
  renderPreview();
  openDrawer({
    title: `Change role: ${user.name}`,
    subtitle: "Updates local authorization through the audited access workflow.",
    width: "540px",
    body: h("div", {},
      h("label", { class: "field" }, h("span", {}, "Role"), role),
      preview,
      h("label", { class: "field" }, h("span", {}, "Audit comment"), comment)),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: `Cancel role change for ${user.name}`, "aria-label": `Cancel role change for local user ${user.name}`, "data-access-action": "cancel-update-local-user", onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: `Update role for ${user.name}`, "aria-label": `Update role for local user ${user.name}`, "data-access-submit": "update-local-user", onclick: async (e) => {
        const auditComment = comment.value.trim();
        if (!auditComment) {
          toast("Comment required", "Add an audit comment before changing this role.", "warn");
          return;
        }
        const btn = e.target.closest("button");
        btn.disabled = true;
        try {
          await api.updateLocalUser(user.name, { role: role.value, comment: auditComment });
          closeDrawer();
          await refreshAccessAdministration(opts);
          toast("Role updated", `${user.name} is now ${role.value}.`, "ok");
        } catch (err) {
          btn.disabled = false;
          toast("Update failed", err.message, "bad");
        }
      } }, h("span", { html: icon("check", 16) }), "Update"),
    ],
  });
}

function openRotateLocalUser(user, opts = {}) {
  const comment = h("textarea", { class: "input", placeholder: "Why this credential is being rotated", "data-access-field": "local-user-comment" });
  openDrawer({
    title: `Rotate token: ${user.name}`,
    subtitle: "The previous bearer token stops working after rotation.",
    width: "540px",
    body: h("div", {}, h("label", { class: "field" }, h("span", {}, "Audit comment"), comment)),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: `Cancel token rotation for ${user.name}`, "aria-label": `Cancel token rotation for local user ${user.name}`, "data-access-action": "cancel-rotate-local-user", onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn danger", type: "button", title: `Rotate token for ${user.name}`, "aria-label": `Rotate token for local user ${user.name}`, "data-access-submit": "rotate-local-user", onclick: async (e) => {
        const auditComment = comment.value.trim();
        if (!auditComment) {
          toast("Comment required", "Add an audit comment before rotating this token.", "warn");
          return;
        }
        const btn = e.target.closest("button");
        btn.disabled = true;
        try {
          const result = await api.rotateLocalUserToken(user.name, auditComment);
          await refreshAccessAdministration(opts);
          showOneTimeToken(result, "Token rotated");
        } catch (err) {
          btn.disabled = false;
          toast("Rotation failed", err.message, "bad");
        }
      } }, h("span", { html: icon("refresh", 16) }), "Rotate"),
    ],
  });
}

function openBreakGlassRotation(user, administration = {}, opts = {}) {
  const enabledAdmins = breakGlassAdminUsers(administration.localUsers || []).filter((item) => item.enabled);
  const singleAdmin = enabledAdmins.length === 1;
  const comment = h("textarea", { class: "input", "data-access-field": "local-user-comment" },
    `break-glass credential rotation for ${user.name}`);
  openDrawer({
    title: `Rotate break-glass: ${user.name}`,
    subtitle: "Emergency local admin credential rotation",
    width: "640px",
    body: h("div", { dataset: { accessBreakglassRotation: user.name } },
      h("div", { class: singleAdmin ? "alert-box warn" : "alert-box info" },
        h("strong", {}, singleAdmin ? "Only enabled local admin. " : "Audited emergency rotation. "),
        singleAdmin
          ? "Do not close the result drawer until the new one-time token is stored; the previous token stops working immediately."
          : "The previous token stops working immediately after rotation. OIDC sessions and other local users are unchanged."),
      h("div", { class: "runtime-grid access-governance-summary" },
        networkMetric("Credential", h("span", { class: "mono" }, user.name)),
        networkMetric("Role", pill(user.role, roleClass(user.role))),
        networkMetric("Enabled admins", String(enabledAdmins.length)),
        networkMetric("Token material", user.tokenMaterial || "not reported")),
      h("label", { class: "field" }, h("span", {}, "Audit comment"), comment)),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: `Cancel break-glass rotation for ${user.name}`, "aria-label": `Cancel break-glass rotation for local user ${user.name}`, "data-access-action": "cancel-rotate-breakglass", onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn danger", type: "button", title: `Rotate break-glass credential for ${user.name}`, "aria-label": `Rotate break-glass local admin credential for ${user.name}`, "data-access-submit": "rotate-breakglass", onclick: async (e) => {
        const auditComment = comment.value.trim();
        if (!auditComment) {
          toast("Comment required", "Add an audit comment before rotating break-glass access.", "warn");
          return;
        }
        const btn = e.target.closest("button");
        btn.disabled = true;
        try {
          const result = await api.rotateLocalUserToken(user.name, auditComment);
          await refreshAccessAdministration(opts);
          showOneTimeToken(result, "Break-glass token rotated", {
            purpose: "break-glass-rotate",
            evidenceTitle: "Break-glass rotation",
            detail: "A local admin break-glass token was rotated through the audited access workflow.",
            warning: singleAdmin ? "This was the only enabled local admin at rotation time." : "",
          });
        } catch (err) {
          btn.disabled = false;
          toast("Rotation failed", err.message, "bad");
        }
      } }, h("span", { html: icon("refresh", 16) }), "Rotate break-glass"),
    ],
  });
}

async function disableLocalUser(user, opts = {}) {
  const comment = h("textarea", { class: "input", placeholder: "Why this credential is being disabled", "data-access-field": "local-user-comment" });
  openDrawer({
    title: `Disable user: ${user.name}`,
    subtitle: "Disabled users remain visible for audit correlation but cannot authenticate.",
    width: "540px",
    body: h("div", {}, h("label", { class: "field" }, h("span", {}, "Audit comment"), comment)),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: `Cancel disabling local user ${user.name}`, "aria-label": `Cancel disabling local user ${user.name}`, "data-access-action": "cancel-disable-local-user", onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn danger", type: "button", title: `Disable local user ${user.name}`, "aria-label": `Disable local user ${user.name}`, "data-access-submit": "disable-local-user", onclick: async (e) => {
        const auditComment = comment.value.trim();
        if (!auditComment) {
          toast("Comment required", "Add an audit comment before disabling this user.", "warn");
          return;
        }
        if (!(await confirmDialog({
          title: "Disable local user?",
          message: `Disable ${user.name} and revoke its local bearer token access?`,
          confirmLabel: "Disable",
          danger: true,
        }))) return;
        const btn = e.target.closest("button");
        btn.disabled = true;
        try {
          await api.disableLocalUser(user.name, auditComment);
          closeDrawer();
          await refreshAccessAdministration(opts);
          toast("User disabled", `${user.name} can no longer authenticate.`, "ok");
        } catch (err) {
          btn.disabled = false;
          toast("Disable failed", err.message, "bad");
        }
      } }, h("span", { html: icon("block", 16) }), "Disable"),
    ],
  });
}

async function refreshAccessAdministration(opts = {}) {
  const [accessAdministrationR, oidcProviderConfigR, oidcR, samlR] = await Promise.allSettled([
    api.accessAdministration(),
    api.oidcProviderConfig(),
    api.authStatus(),
    api.samlAuthStatus(),
  ]);
  if (accessAdministrationR.status === "rejected") throw accessAdministrationR.reason;
  const accessAdministration = accessAdministrationWithOIDCConfig(
    accessAdministrationR.value,
    oidcProviderConfigR.status === "fulfilled" ? oidcProviderConfigR.value : null,
  );
  const oidc = oidcStatusForAccessRefresh(oidcR.status === "fulfilled" ? oidcR.value : opts.oidc || {}, accessAdministration);
  const saml = samlR.status === "fulfilled" ? samlR.value : opts.saml || { enabled: false, runtimeAvailable: false };
  if (opts.root) {
    paint(opts.root, opts.status || {}, opts.identity || null, oidc, saml, accessAdministration, opts.telemetryExportStatus || null, opts.routeContext || defaultSettingsRouteContext());
  }
  return accessAdministration;
}

function accessAdministrationWithOIDCConfig(accessAdministration = {}, oidcProviderConfigResponse = null) {
  const config = oidcProviderConfigResponse?.config || oidcProviderConfigResponse?.oidc || null;
  if (!config || !accessAdministration || accessAdministration.unavailable) return accessAdministration;
  return {
    ...accessAdministration,
    oidc: {
      ...(accessAdministration.oidc || {}),
      enabled: Boolean(config.enabled),
      issuer: config.enabled ? config.issuer || "" : "",
      clientId: config.enabled ? config.clientId || config.client_id || "" : "",
      redirectUrl: config.enabled ? config.redirectUrl || config.redirect_url || "" : "",
      roleClaim: config.enabled ? config.roleClaim || config.role_claim || "" : "",
      defaultRole: config.enabled ? config.defaultRole || config.default_role || "" : "",
      scopes: config.enabled && Array.isArray(config.scopes) ? [...config.scopes] : [],
      trustedProxyCidrs: config.enabled && Array.isArray(config.trustedProxyCidrs || config.trusted_proxy_cidrs)
        ? [...(config.trustedProxyCidrs || config.trusted_proxy_cidrs)]
        : [],
      clientSecretFileConfigured: Boolean(config.clientSecretFileConfigured || config.client_secret_file_configured),
    },
  };
}

function oidcStatusForAccessRefresh(statusOidc = {}, accessAdministration = {}) {
  const adminOidc = accessAdministration?.oidc || {};
  if (!Object.prototype.hasOwnProperty.call(adminOidc, "enabled")) return statusOidc || {};
  return {
    ...(statusOidc || {}),
    enabled: Boolean(adminOidc.enabled),
    issuer: adminOidc.issuer || "",
    clientId: adminOidc.clientId || "",
    redirectUrl: adminOidc.redirectUrl || "",
    roleClaim: adminOidc.roleClaim || "",
    defaultRole: adminOidc.defaultRole || "",
    scopes: Array.isArray(adminOidc.scopes) ? [...adminOidc.scopes] : [],
    trustedProxyCidrs: Array.isArray(adminOidc.trustedProxyCidrs) ? [...adminOidc.trustedProxyCidrs] : [],
    clientSecretFileConfigured: Boolean(adminOidc.clientSecretFileConfigured),
  };
}

function showOneTimeToken(result = {}, title = "One-time token", opts = {}) {
  const token = result.oneTimeToken || result.one_time_token || "";
  const user = result.user || {};
  const tokenNode = h("pre", { class: "mono audit-detail-pre", "data-one-time-token": "true" }, token || "No token returned.");
  const evidence = opts.purpose ? breakGlassTokenEvidence(result, title, opts) : null;
  openDrawer({
    title,
    subtitle: `${user.name || "local user"} / ${user.role || "role"}`,
    width: "640px",
    body: h("div", { "data-access-token-result": "true" },
      h("div", { class: "alert-box warn" },
        h("strong", {}, "Copy this token now."),
        h("div", { class: "note" }, "It is shown once and is not available from inventory, audit, or support bundles.")),
      tokenNode,
      evidence ? h("div", { class: "alert-box info", dataset: { accessBreakglassEvidence: opts.purpose } },
        h("strong", {}, opts.evidenceTitle || title),
        h("div", { class: "note" }, opts.detail || "Break-glass access changed through the audited access workflow."),
        opts.warning ? h("div", { class: "note" }, opts.warning) : null,
        h("div", { class: "flex wrap", style: { gap: "8px", marginTop: "10px" } },
          h("button", { class: "btn sm ghost", type: "button", title: "Copy break-glass evidence", "aria-label": `Copy ${opts.evidenceTitle || title} evidence`, "data-access-action": "copy-breakglass-evidence", onclick: () => copyBreakGlassEvidence(evidence) },
            h("span", { html: icon("copy", 14) }), "Copy evidence"),
          h("button", { class: "btn sm ghost", type: "button", title: "Export break-glass evidence JSON", "aria-label": `Export ${opts.evidenceTitle || title} evidence JSON`, "data-access-action": "export-breakglass-evidence", onclick: () => exportBreakGlassEvidence(evidence) },
            h("span", { html: icon("download", 14) }), "Export JSON"),
          h("button", { class: "btn sm ghost", type: "button", title: "Pin break-glass evidence to investigation case", "aria-label": `Pin ${opts.evidenceTitle || title} evidence to investigation case`, "data-access-action": "pin-breakglass-evidence", onclick: () => pinBreakGlassEvidence(evidence) },
            h("span", { html: icon("inbox", 14) }), "Pin to case"))) : null),
    footer: [
      h("button", { class: "btn", type: "button", title: "Copy one-time token", "aria-label": `Copy one-time token for ${user.name || "local user"}`, "data-access-action": "copy-one-time-token", onclick: () => copyOneTimeToken(token) }, h("span", { html: icon("copy", 16) }), "Copy token"),
      h("button", { class: "btn primary", type: "button", title: "Close token result", "aria-label": "Close one-time token result", "data-access-action": "close-token-result", onclick: closeDrawer }, "Close"),
    ],
  });
}

function breakGlassTokenEvidence(result = {}, title = "Break-glass access", opts = {}) {
  const user = result.user || {};
  return {
    schemaVersion: "openngfw.breakglass-token.v1",
    generatedAt: new Date().toISOString(),
    purpose: opts.purpose || "break-glass",
    title: opts.evidenceTitle || title,
    detail: opts.detail || "",
    warning: opts.warning || "",
    user: {
      name: user.name || "",
      role: user.role || "",
      authSource: user.authSource || user.auth_source || "local",
      enabled: user.enabled !== false,
    },
    oneTimeTokenShown: Boolean(result.oneTimeToken || result.one_time_token),
    tokenStoredInInventory: false,
    auditRoute: accessAuditHash({ action: opts.purpose === "break-glass-create" ? "access-local-user-create" : "access-local-user-rotate", query: `user=${user.name || ""}` }),
  };
}

function breakGlassEvidenceText(evidence = {}) {
  const user = evidence.user || {};
  return [
    `${evidence.title || "Break-glass evidence"}: ${evidence.purpose || "break-glass"}`,
    `generated_at=${evidence.generatedAt || ""}`,
    `user=${user.name || ""}`,
    `role=${user.role || ""}`,
    `auth_source=${user.authSource || "local"}`,
    `enabled=${user.enabled === false ? "false" : "true"}`,
    `one_time_token_shown=${evidence.oneTimeTokenShown ? "true" : "false"}`,
    `token_stored_in_inventory=false`,
    evidence.warning ? `warning=${evidence.warning}` : "",
    evidence.detail ? `detail=${evidence.detail}` : "",
    `audit_route=${evidence.auditRoute || ""}`,
  ].filter(Boolean).join("\n") + "\n";
}

async function copyBreakGlassEvidence(evidence) {
  try {
    await navigator.clipboard.writeText(breakGlassEvidenceText(evidence));
    toast("Break-glass evidence copied", "Rotation evidence copied without the one-time token.", "ok");
  } catch {
    toast("Copy failed", "Review the visible break-glass evidence before recording.", "warn");
  }
}

function exportBreakGlassEvidence(evidence) {
  const packet = redactedAccessPacket(evidence);
  const blob = new Blob([JSON.stringify(packet, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: breakGlassEvidenceFilename(packet) });
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  toast("Break-glass evidence exported", "Downloaded evidence without the one-time token.", "ok");
}

function pinBreakGlassEvidence(evidence) {
  try {
    const packet = redactedAccessPacket(evidence);
    const result = pinInvestigationPacket(buildInvestigationPacket({
      kind: "break-glass",
      title: packet.title || "Break-glass access",
      subject: { id: `settings:access:breakglass:${packet.user?.name || "local-admin"}`, label: packet.user?.name || "local admin" },
      summary: {
        purpose: packet.purpose,
        user: packet.user?.name || "",
        role: packet.user?.role || "",
        oneTimeTokenShown: packet.oneTimeTokenShown,
        tokenStoredInInventory: false,
      },
      evidence: breakGlassEvidenceText(packet).split("\n").filter(Boolean),
      artifacts: { breakGlass: packet },
    }, { route: settingsPanelHash("access"), collectedAt: packet.generatedAt }));
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Break-glass evidence could not be pinned.", "bad");
  }
}

function breakGlassEvidenceFilename(evidence = {}) {
  const stamp = String(evidence.generatedAt || new Date().toISOString())
    .replace(/[^0-9A-Za-z]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 32) || "latest";
  const name = String(evidence.user?.name || "local-admin").replace(/[^A-Za-z0-9_.-]+/g, "-").slice(0, 48) || "local-admin";
  return `openngfw-breakglass-${name}-${stamp}.json`;
}

async function copyOneTimeToken(token) {
  if (!token) return;
  try {
    await navigator.clipboard.writeText(token);
    toast("Token copied", "Store it in the approved secret manager.", "ok");
  } catch {
    toast("Copy failed", "Select the visible token and copy it manually.", "warn");
  }
}

function accessUserEvidenceCell(user) {
  return h("div", { class: "access-user-evidence" },
    h("code", {
      class: "access-user-fingerprint",
      title: user.auditHash || "Inventory fingerprint not reported",
    }, user.auditFingerprint || "not reported"),
    user.actorAuditHash
      ? h("a", { class: "btn sm ghost", href: user.actorAuditHash, title: "Open audit log filtered to " + user.name, "aria-label": "Open audit log filtered to " + user.name, "data-access-action": "local-user-audit" },
        h("span", { html: icon("clock", 14) }),
        "Audit")
      : null);
}

function accessInventoryTable(title, rows = []) {
  return h("div", { class: "table-wrap flat access-inventory-table" },
    h("div", { class: "note" }, title),
    responsiveTable(["Posture", "State"],
      rows.map((row) => h("tr", {},
        labeledCell("Posture", {}, row.label),
        labeledCell("State", {}, row.cls ? pill(row.value, row.cls) : h("span", { class: "mono" }, row.value)))),
      { className: "settings-access-inventory-table" }));
}

function authEnabledLabel(value) {
  if (value === true) return "enabled";
  if (value === false) return "disabled";
  return "unknown";
}

function authEnabledClass(value) {
  if (value === true) return "ok";
  if (value === false) return "warn";
  return "neutral";
}

function accessAdminReadinessPanel(readiness) {
  return h("div", { class: "access-admin-readiness" },
    h("div", { class: "alert-box " + readiness.cls },
      h("strong", {}, `Administration readiness: ${readiness.label}. `),
      readiness.detail,
      h("div", { class: "note", style: { marginTop: "6px" } },
        readiness.adminVerified ? "Current actor has admin-level capability for administrative workflows." : "Current actor is not verified as admin for administrative workflows.")),
    h("div", { class: "warning-list" }, readiness.items.map((item) =>
      h("div", { class: "warning-row " + item.cls },
        h("div", {}, pill(item.status, item.cls, true)),
        h("div", {},
          h("strong", {}, item.label),
          h("div", { class: "note" }, item.detail),
          h("div", { class: "setup-list" },
            h("span", {}, "Next"),
            h("div", {}, h("span", {}, item.nextAction)),
            h("span", {}, "Evidence"),
            h("div", {}, h("span", {}, item.evidence))))))));
}

function accessRoleCell(allowed) {
  return pill(allowed ? "allow" : "restrict", allowed ? "ok" : "neutral");
}

function accessAuditLinkList(links = []) {
  if (!links.length) return h("span", { class: "muted" }, "—");
  return h("div", { class: "flex wrap" }, links.map((link) =>
    h("a", { class: "btn sm ghost", href: link.href, title: "Open audit log filtered to " + link.action, "aria-label": "Open audit log filtered to " + link.action, "data-access-action": "open-audit-link" },
      h("span", { html: icon("clock", 14) }),
      link.label)));
}

function renderIdentity(node, identity, rt = {}) {
  clear(node);
  if (identity?.actor) {
    node.appendChild(h("div", { class: "alert-box info" },
      h("strong", {}, "Authenticated as ", identity.actor, " "),
      pill(identity.role || "unknown", roleClass(identity.role), true),
      h("div", { class: "note" }, `Source: ${identity.authSource || "unknown"} · Capabilities: ${(identity.capabilities || []).join(", ") || "none"}`)));
    return;
  }
  const authKnown = Object.prototype.hasOwnProperty.call(rt, "authEnabled");
  node.appendChild(h("div", { class: "alert-box " + (!authKnown || rt.authEnabled ? "warn" : "info") },
    h("strong", {}, !authKnown ? "Identity unavailable." : rt.authEnabled ? "Identity unavailable." : "Local admin mode."),
      h("div", { class: "note" }, !authKnown
      ? "Sign in with OIDC or save a valid session-only API token to verify this browser and load runtime auth posture."
      : rt.authEnabled
      ? "Sign in with OIDC or save a valid session-only API token to verify the actor and role used by this browser."
      : "Authentication is disabled; local callers are treated as admin.")));
}

function runtimeBool(rt, field) {
  if (!Object.prototype.hasOwnProperty.call(rt, field)) return "unknown";
  return rt[field] ? "enabled" : "disabled";
}

function roleClass(role) {
  if (role === "admin") return "bad";
  if (role === "operator") return "warn";
  if (role === "viewer") return "info";
  return "neutral";
}

function yesNo(v) { return v ? "yes" : "no"; }
