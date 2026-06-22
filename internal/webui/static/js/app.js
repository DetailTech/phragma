// app.js — bootstrap: sidebar nav, hash router, the candidate/commit bar,
// command palette (⌘K), theme, and connection status. Views are loaded
// per route and rendered into #content.

import { h, mount, clear, icon, $, Router } from "./core.js";
import { api, getToken, setToken } from "./api.js";
import { accessDetail, accessTitle, isAuthError, isPermissionError, oidcLoginTarget } from "./auth_gate.js";
import { API_CONTRACT, openAutomationContext } from "./automation_context.js";
import { candidateBarModel } from "./candidate_bar.js";
import { commitRuntimePreflight } from "./commit_preflight.js";
import { buildContentPosture } from "./content_posture.js";
import { conntrackCapacity, dataplanePosture, ebpfHostReadiness, flowtableHostReadiness, flowtableRuntimeEvidence, kernelTuningRollup } from "./dataplane.js";
import { openDiagnosticConsole } from "./diagnostic_console.js";
import { normalizePolicyDiffLines, policyDiffLabels, renderDiffLines } from "./diff_view.js";
import { applyNetworkProfileToPolicy } from "./network_profiles.js";
import { session, diffLines, changeImpact, normalizeServerImpact } from "./policy.js";
import { readinessActionHash, remediationSteps, summarizeReadiness } from "./readiness_model.js";
import { toast, openDrawer, closeDrawer, confirmDialog, pill, handleFocusTrap } from "./ui.js";
import { renderValidationEvidence } from "./validation_view.js";

import * as dashboard from "./views/dashboard.js";
import * as setup from "./views/setup.js";
import * as rules from "./views/rules.js";
import * as objects from "./views/objects.js";
import * as nat from "./views/nat.js";
import * as ids from "./views/ids.js";
import * as threats from "./views/threats.js";
import * as traffic from "./views/traffic.js";
import * as logs from "./views/logs.js";
import * as troubleshoot from "./views/troubleshoot.js";
import * as performance from "./views/performance.js";
import * as investigation from "./views/investigation.js";
import * as fleet from "./views/fleet.js";
import * as intel from "./views/intel.js";
import * as netvpn from "./views/netvpn.js";
import * as proxy from "./views/proxy.js";
import * as compliance from "./views/compliance.js";
import * as changes from "./views/changes.js";
import * as readiness from "./views/readiness.js";
import * as settings from "./views/settings.js";

const NAV = [
  { path: "/", title: "Dashboard", icon: "dashboard", view: dashboard },
  { path: "/setup", title: "Guided setup", crumb: "Setup", icon: "shield", view: setup },
  { path: "/rules", title: "Security rules", crumb: "Rules", icon: "rules", view: rules },
  { path: "/objects", title: "Objects", icon: "objects", view: objects },
  { path: "/nat", title: "NAT", icon: "nat", view: nat },
  { path: "/inspection", title: "Inspection", icon: "threats", view: ids },
  { path: "/threats", title: "Threats", icon: "threats", view: threats },
  { path: "/traffic", title: "Traffic", icon: "traffic", view: traffic },
  { path: "/logs", title: "System logs", crumb: "Logs", icon: "terminal", view: logs },
  { path: "/troubleshoot", title: "Troubleshoot", icon: "search", view: troubleshoot },
  { path: "/performance", title: "Performance", icon: "traffic", view: performance },
  { path: "/investigation", title: "Investigation", icon: "inbox", view: investigation },
  { path: "/fleet", title: "Fleet & templates", crumb: "Fleet", icon: "globe", view: fleet },
  { path: "/intel", title: "Threat intel", crumb: "Intel", icon: "intel", view: intel },
  { path: "/netvpn", title: "Routing & VPN", icon: "vpn", view: netvpn },
  { path: "/proxy", title: "Proxy / WAF", icon: "globe", view: proxy },
  { path: "/compliance", title: "Compliance", icon: "shield", view: compliance },
  { path: "/readiness", title: "Readiness", icon: "shield", view: readiness },
  { path: "/changes", title: "Changes", icon: "changes", view: changes },
  { path: "/settings", title: "Settings", icon: "settings", view: settings },
];

// ---------- Theme ----------
const THEME_KEY = "phragma.theme";
const LEGACY_THEME_KEY = "openngfw.theme";
export function getTheme() { return document.documentElement.getAttribute("data-theme") || "dark"; }
export function setTheme(t) {
  document.documentElement.setAttribute("data-theme", t);
  localStorage.setItem(THEME_KEY, t);
  const btn = $("#theme-toggle");
  if (btn) btn.innerHTML = icon(t === "dark" ? "globe" : "shield", 18); // sun/moon-ish via available icons
}
function initTheme() {
  setTheme(localStorage.getItem(THEME_KEY) || localStorage.getItem(LEGACY_THEME_KEY) || "dark");
  $("#theme-toggle").onclick = () => setTheme(getTheme() === "dark" ? "light" : "dark");
}

// ---------- Nav ----------
function buildNav() {
  const nav = $("#nav");
  mount(nav, NAV.map((n) =>
    h("a", { href: "#" + n.path, dataset: { path: n.path }, html: icon(n.icon, 18) + "<span>" + n.title + "</span>" })));
}
function highlightNav(path) {
  $("#nav").querySelectorAll("a").forEach((a) => a.classList.toggle("active", a.dataset.path === path));
}

function setMenuOpen(open) {
  $("#app").classList.toggle("menu-open", open);
  document.body.classList.toggle("shell-menu-open", open);
  $("#menu-toggle")?.setAttribute("aria-expanded", open ? "true" : "false");
  $("#sidebar-scrim").hidden = !open;
  syncSidebarSemantics(open);
}

function toggleMenu() {
  setMenuOpen(!$("#app").classList.contains("menu-open"));
}

function closeMenu() {
  setMenuOpen(false);
}

function syncSidebarSemantics(open = $("#app")?.classList.contains("menu-open")) {
  const sidebar = $("#sidebar");
  if (!sidebar) return;
  const mobile = typeof matchMedia === "function" && matchMedia("(max-width: 820px)").matches;
  if (mobile) {
    sidebar.setAttribute("aria-hidden", open ? "false" : "true");
  } else {
    sidebar.removeAttribute("aria-hidden");
    $("#sidebar-scrim").hidden = true;
    document.body.classList.remove("shell-menu-open");
  }
}

// ---------- Router ----------
const router = new Router();
let currentRoute = null;
let routeRenderToken = 0;
NAV.forEach((n) => router.add(n.path, n));

async function renderRoute(r) {
  if (!r) {
    renderNotFound();
    return;
  }
  const renderToken = ++routeRenderToken;
  if (currentRoute?.path && currentRoute.path !== r.path) {
    closeDrawer({ invokeOnClose: false });
  }
  currentRoute = r;
  const n = r.route.handler; // the NAV entry registered with router.add
  highlightNav(n.path);
  $("#crumb").textContent = n.crumb || n.title;
  document.title = "Phragma · " + (n.crumb || n.title);
  closeMenu();
  const content = $("#content");
  mount(content, h("div", { class: "loading" }, "Loading…"));
  try {
    const node = await n.view.render({ params: r.params, query: r.query, path: r.path });
    if (renderToken !== routeRenderToken) return;
    mount(content, node);
    content.scrollTop = 0;
  } catch (e) {
    if (renderToken !== routeRenderToken) return;
    if (isAuthError(e) || isPermissionError(e)) {
      await renderAccessGate(content, e);
      return;
    }
    mount(content, h("div", { class: "alert-box bad" },
      h("strong", {}, "Could not load this view. "),
      e.message,
      e.status === 401 || e.status === 16 ? h("div", { style: { marginTop: "8px" } }, "Authentication may be required — sign in or set your API token in ",
        h("a", { href: "#/settings" }, "Settings"), ".") : null));
  }
}

export function renderNotFound(route = router.current()) {
  routeRenderToken++;
  currentRoute = null;
  highlightNav("");
  $("#crumb").textContent = "Not found";
  document.title = "Phragma · Not found";
  closeMenu();
  const badPath = route?.path || "/";
  mount($("#content"),
    h("div", { class: "not-found-view" },
      h("div", { class: "alert-box warn" },
        h("strong", {}, "Route not found"),
        h("div", { class: "note" }, `${badPath} is not a Phragma WebUI route.`)),
      h("a", { class: "btn primary", href: "#/", title: "Return to dashboard", "aria-label": "Return to dashboard", "data-app-action": "not-found-dashboard" }, h("span", { html: icon("dashboard", 16) }), "Dashboard")));
}

function reloadCurrent() {
  const resolved = router.resolve();
  if (resolved) renderRoute(resolved);
  else renderNotFound(router.current());
}

async function renderAccessGate(content, err) {
  let oidc = {};
  try { oidc = await api.authStatus(); } catch {}
  const token = h("input", {
    class: "input",
    type: "password",
    placeholder: "Local API token",
    value: getToken(),
  });
  const retryBtn = h("button", { class: "btn ghost", type: "button", title: "Retry loading this view", "aria-label": "Retry loading this view", "data-app-action": "retry-access-gate", onclick: reloadCurrent }, h("span", { html: icon("refresh", 16) }), "Retry");
  const saveBtn = h("button", { class: "btn primary", type: "button", title: "Use local API token", "aria-label": "Use local API token", "data-app-action": "use-local-token", onclick: () => saveAccessToken(token, saveBtn) },
    h("span", { html: icon("key", 16) }), "Use token");
  token.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      saveAccessToken(token, saveBtn);
    }
  });

  const oidcTarget = oidcLoginTarget(oidc, location.hash);
  mount(content, h("div", { class: "auth-gate" },
    h("div", { class: "auth-panel" },
      h("div", { class: "auth-mark", html: icon(isPermissionError(err) ? "block" : "key", 34) }),
      h("h1", {}, accessTitle(err)),
      h("p", {}, accessDetail(err)),
      oidcTarget ? h("div", { class: "auth-option" },
        h("div", {},
          h("strong", {}, "Browser SSO"),
          h("span", {}, "Uses the server-side OIDC session cookie.")),
        h("button", { class: "btn primary", type: "button", title: "Sign in with browser SSO", "aria-label": "Sign in with browser SSO", "data-app-action": "oidc-sign-in", onclick: () => { location.href = oidcTarget; } },
          h("span", { html: icon("key", 16) }), "Sign in with OIDC")) : null,
      h("div", { class: "auth-option" },
        h("div", {},
          h("strong", {}, "Local API token"),
          h("span", {}, "For break-glass access, CLI users, and automation accounts.")),
        h("div", { class: "auth-token-row" }, token, saveBtn)),
      h("div", { class: "auth-foot" },
        h("span", {}, err.message || "The API rejected the request."),
        retryBtn))));
}

async function saveAccessToken(input, button) {
  const value = input.value.trim();
  if (!value) {
    toast("Token required", "Enter a local API token first.", "warn");
    input.focus();
    return;
  }
  button.disabled = true;
  mount(button, "Verifying...");
  try {
    const id = await api.identityWithToken(value);
    setToken(value);
    toast("Signed in", `${id.actor || "unknown"} (${id.role || "unknown"})`, "ok");
    reloadCurrent();
  } catch (e) {
    button.disabled = false;
    mount(button, h("span", { html: icon("key", 16) }), "Use token");
    toast("Token rejected", e.message, "bad");
    input.focus();
  }
}

// ---------- Candidate / commit bar ----------
function renderCandidateBar() {
  const bar = $("#candidate-bar");
  const model = candidateBarModel(session);
  bar.classList.toggle("blocked", model.state === "blocked");
  bar.classList.toggle("clean", model.state === "clean");
  bar.classList.toggle("dirty", model.state === "dirty");
  bar.hidden = false;
  mount(bar,
    h("span", { class: "cb-icon", html: icon(model.icon, 18) }),
    h("div", { class: "cb-text" },
      model.title,
      h("small", {}, model.detail)),
    h("div", { class: "cb-actions" },
      h("a", { class: "btn sm ghost", href: "#/changes", title: "Open candidate changes", "aria-label": "Open candidate changes", "data-candidate-bar-action": "changes" }, h("span", { html: icon("changes", 15) }), "Changes"),
      h("a", { class: "btn sm ghost", href: "#/readiness", title: "Open readiness", "aria-label": "Open readiness", "data-candidate-bar-action": "readiness" }, h("span", { html: icon("shield", 15) }), "Readiness"),
      h("button", { class: "btn sm ghost", type: "button", title: "Review pending candidate diff", "aria-label": "Review pending candidate diff", "data-candidate-bar-action": "diff", disabled: model.state !== "dirty", onclick: showDiff }, h("span", { html: icon("diff", 15) }), "Diff"),
      h("button", { class: "btn sm", type: "button", title: "Validate candidate policy", "aria-label": "Validate candidate policy", "data-candidate-bar-action": "validate", disabled: model.state === "blocked", onclick: validate }, h("span", { html: icon("check", 15) }), "Validate"),
      model.state === "dirty" ? h("button", { class: "btn sm danger", type: "button", title: "Discard pending candidate changes", "aria-label": "Discard pending candidate changes", "data-candidate-bar-action": "discard", onclick: discard }, "Discard") : null,
      model.state === "blocked"
        ? h("button", { class: "btn sm primary", type: "button", title: "Reload candidate state", "aria-label": "Reload candidate state", "data-candidate-bar-action": "reload", onclick: reloadCandidateState }, h("span", { html: icon("refresh", 15) }), "Reload")
        : h("button", { class: "btn sm primary", type: "button", title: "Review and commit candidate", "aria-label": "Review and commit candidate", "data-candidate-bar-action": "review-commit", disabled: model.state !== "dirty", onclick: commit }, h("span", { html: icon("upload", 15) }), "Review & commit")));
}

async function reloadCandidateState() {
  try {
    await session.load();
    renderCandidateBar();
    toast("Candidate state reloaded", session.dirty ? "Review the staged candidate before committing." : "No pending candidate changes were found.", "ok");
    reloadCurrent();
  } catch (e) {
    toast("Reload failed", e.message, "bad");
    renderCandidateBar();
  }
}

// ---------- Runtime readiness banner ----------
async function refreshRuntimeBanner() {
  const bar = $("#runtime-banner");
  if (!bar) return;
  try {
    const [statusR, runningR, feedsR, contentR] = await Promise.allSettled([
      api.status(),
      api.running(),
      api.feeds(),
      api.contentPackages(),
    ]);
    if (statusR.status !== "fulfilled") throw statusR.reason;
    const status = statusR.value || {};
    const policy = runningR.status === "fulfilled" ? (runningR.value?.policy || {}) : {};
    const feeds = feedsR.status === "fulfilled" ? (feedsR.value?.feeds || []) : [];
    const contentPackages = contentR.status === "fulfilled" ? (contentR.value?.packages || []) : [];
    const contentError = [
      runningR.status === "rejected" ? `running policy: ${runtimeErrorText(runningR.reason)}` : "",
      feedsR.status === "rejected" ? `feed registry: ${runtimeErrorText(feedsR.reason)}` : "",
      contentR.status === "rejected" ? `content packages: ${runtimeErrorText(contentR.reason)}` : "",
    ].filter(Boolean).join("; ");
    const contentPosture = buildContentPosture(feeds, policy, contentPackages, contentError);
    const flowCap = flowtableHostReadiness(status);
    const flowRuntime = flowtableRuntimeEvidence(status);
    const ebpfHost = ebpfHostReadiness(status);
    const conntrack = conntrackCapacity(status);
    const policyDp = dataplanePosture(policy, status);
    const tuning = kernelTuningRollup(status);
    const summary = summarizeReadiness(status, policyDp, flowCap, flowRuntime, ebpfHost, conntrack, contentPosture);
    const actions = remediationSteps(status, policyDp, flowCap, flowRuntime, ebpfHost, conntrack, tuning, contentPosture);
    renderRuntimeBanner(bar, summary, actions);
  } catch (e) {
    if (isAuthError(e) || isPermissionError(e)) {
      bar.hidden = true;
      clear(bar);
      return;
    }
    renderRuntimeBannerError(bar, e);
  }
}

function renderRuntimeBanner(bar, summary, actions = []) {
  if (!summary || summary.cls === "ok") {
    bar.hidden = true;
    clear(bar);
    return;
  }
  const cls = summary.cls === "bad" ? "bad" : "warn";
  const high = actions.filter((item) => item.level === "high").length;
  const medium = actions.filter((item) => item.level === "medium").length;
  const primary = actions[0] || null;
  bar.hidden = false;
  mount(bar,
    h("span", { class: "rb-icon", html: icon(cls === "bad" ? "block" : "shield", 18) }),
    h("div", { class: "rb-text" },
      h("strong", {}, summary.title),
      h("small", {}, primary ? `${summary.detail} Next: ${primary.title}.` : summary.detail)),
    h("div", { class: "rb-meta" },
      high ? pill(`${high} critical`, "bad", true) : null,
      medium ? pill(`${medium} warning${medium === 1 ? "" : "s"}`, "warn", true) : null),
    h("div", { class: "rb-actions" },
      primary?.href ? h("a", { class: "btn sm ghost", href: primary.href, title: `Open fix for ${summary.title}`, "aria-label": `Open fix for ${summary.title}`, dataset: { runtimeBlockerAction: "open-fix" } },
        h("span", { html: icon("arrowRight", 15) }), "Open fix") : null,
      h("a", { class: "btn sm primary", href: "#/readiness", title: "Open readiness", "aria-label": "Open readiness", "data-runtime-banner-action": "readiness" },
        h("span", { html: icon("shield", 15) }), "Readiness")));
}

function renderRuntimeBannerError(bar, err) {
  bar.hidden = false;
  mount(bar,
    h("span", { class: "rb-icon", html: icon("block", 18) }),
    h("div", { class: "rb-text" },
      h("strong", {}, "Runtime readiness unavailable"),
      h("small", {}, runtimeErrorText(err))),
    h("div", { class: "rb-actions" },
      h("button", { class: "btn sm ghost", type: "button", title: "Retry runtime readiness status", "aria-label": "Retry runtime readiness status", "data-runtime-banner-action": "retry", onclick: refreshRuntimeBanner },
        h("span", { html: icon("refresh", 15) }), "Retry"),
      h("a", { class: "btn sm primary", href: "#/readiness", title: "Open readiness", "aria-label": "Open readiness", "data-runtime-banner-action": "readiness-error" },
        h("span", { html: icon("shield", 15) }), "Readiness")));
}

function runtimeErrorText(err) {
  return err?.message || String(err || "Runtime status could not be loaded.");
}

async function showDiff() {
  if (session.candidateUnavailable) {
    toast("Candidate unavailable", session.candidateUnavailableMessage(), "bad");
    return;
  }
  const diff = await loadCandidateDiff();
  openDrawer({
    title: "Pending changes", subtitle: `${diff.fromLabel} -> ${diff.toLabel}`, width: "720px",
    body: h("div", {},
      diff.source === "fallback" ? h("div", { class: "alert-box warn" }, "Diff API unavailable; showing local draft diff.") : null,
      renderDiffLines(diff.lines)),
    footer: [h("button", { class: "btn ghost", type: "button", title: "Close pending changes drawer", "aria-label": "Close pending changes drawer", "data-app-drawer-action": "close-diff", onclick: closeDrawer }, "Close"),
      h("button", { class: "btn primary", type: "button", title: "Open commit review for pending changes", "aria-label": "Open commit review for pending changes", "data-app-drawer-action": "review-commit", onclick: () => { closeDrawer(); commit(); } }, "Review & commit…")],
  });
}

async function validate() {
  if (session.candidateUnavailable) {
    toast("Candidate unavailable", session.candidateUnavailableMessage(), "bad");
    return;
  }
  try {
    const r = await session.validate();
    if (r.valid) toast("Validation passed", "The candidate is valid and renderable.", "ok");
    openDrawer({ title: r.valid ? "Validation passed" : "Validation failed", width: "620px",
      body: renderValidationEvidence(r, {
        validText: "Candidate validated successfully. Engine syntax checks passed.",
        invalidLead: "Fix these before committing:",
      }),
      footer: [h("button", { class: "btn ghost", type: "button", title: "Close validation drawer", "aria-label": "Close validation drawer", "data-app-drawer-action": "close-validation", onclick: closeDrawer }, "Close")] });
  } catch (e) { toast("Validation error", e.message, "bad"); }
}

async function commit() {
  if (session.candidateUnavailable) { toast("Candidate unavailable", session.candidateUnavailableMessage(), "bad"); return; }
  if (!session.dirty) { toast("Nothing to commit", "No pending changes.", "warn"); return; }
  openDrawer({
    title: "Preparing commit review",
    subtitle: "Validating the candidate and runtime posture before live apply.",
    width: "560px",
    body: h("div", { class: "loading" }, "Running policy and runtime preflight…"),
    footer: [h("button", { class: "btn ghost", type: "button", title: "Cancel commit review preparation", "aria-label": "Cancel commit review preparation", "data-app-drawer-action": "cancel-commit-prep", onclick: closeDrawer }, "Cancel")],
  });

  let validation = null;
  let validationError = null;
  let runtimePreflight = null;
  let runtimePreflightError = null;
  let status = null;
  let statusError = null;
  const [validationResult, runtimePreflightResult, statusResult] = await Promise.allSettled([
    session.validate(),
    api.runtimeReadinessPreflight({ targetPolicy: session.draft, runningPolicy: session.running, operation: "commit" }),
    api.status(),
  ]);
  if (validationResult.status === "fulfilled") validation = validationResult.value;
  else validationError = validationResult.reason;
  if (runtimePreflightResult.status === "fulfilled") runtimePreflight = runtimePreflightResult.value;
  else runtimePreflightError = runtimePreflightResult.reason;
  if (statusResult.status === "fulfilled") status = statusResult.value;
  else statusError = statusResult.reason;
  const diff = await loadCandidateDiff();
  const impact = normalizeServerImpact(validation?.impact) || changeImpact(session.running, session.draft);
  const runtime = commitRuntimePreflight({
    preflight: runtimePreflight,
    status,
    error: statusError || runtimePreflightError,
    draftPolicy: session.draft,
    runningPolicy: session.running,
  });
  const comment = h("textarea", { class: "input", placeholder: "Describe this change (recommended for the audit trail)" });
  const acknowledge = h("input", { type: "checkbox" });
  const needsRiskAck = impact.level === "high";
  const needsAck = needsRiskAck || runtime.requiresAck;
  const commitBlocked = () => Boolean(validationError || !validation?.valid || (needsAck && !acknowledge.checked));
  const commitBtn = h("button", { class: "btn primary", type: "button", title: "Commit candidate to running policy", "aria-label": "Commit candidate to running policy", "data-app-drawer-action": "commit-candidate", disabled: commitBlocked(), onclick: async (e) => {
    if (!comment.value.trim()) { toast("Comment required", "Add an audit comment before committing.", "warn"); comment.focus(); return; }
    if (needsAck && !acknowledge.checked) { toast("Review required", "Acknowledge the risk and runtime posture before committing.", "warn"); return; }
    const btn = e.target.closest("button"); btn.disabled = true; btn.textContent = "Committing…";
    try {
      const r = await session.commit(
        comment.value.trim(),
        needsRiskAck && acknowledge.checked,
        runtime.requiresAck && acknowledge.checked,
      );
      closeDrawer();
      toast("Committed", `Applied as version v${r.version}.`, "ok");
      reloadCurrent();
    } catch (err) {
      btn.disabled = false; btn.textContent = "Commit";
      toast("Commit failed", err.message, "bad");
    }
  } }, h("span", { html: icon("upload", 16) }), "Commit");
  acknowledge.onchange = () => { commitBtn.disabled = commitBlocked(); };

  openDrawer({
    title: "Commit review",
    subtitle: "Validate, inspect impact, then apply to the live firewall.",
    width: "760px",
    body: h("div", {},
      h("div", { class: "preflight-summary" },
        h("div", {}, h("span", {}, "Pending changes"), h("strong", {}, String(session.changeCount()))),
        h("div", {}, h("span", {}, "Validation"), validationError ? pill("error", "bad") : validation?.valid ? pill("passed", "ok") : pill("failed", "bad")),
        h("div", {}, h("span", {}, "Impact"), pill(impact.level, impact.level === "high" ? "bad" : impact.level === "medium" ? "warn" : "ok")),
        h("div", {}, h("span", {}, "Runtime"), pill(runtime.label, runtime.cls))),
      validationError ? h("div", { class: "alert-box bad" }, validationError.message) :
        renderValidationEvidence(validation, {
          validText: "Candidate validated successfully. Engine syntax checks passed.",
          invalidLead: "Fix these before committing:",
        }),
      runtimePreflightPanel(runtime),
      h("div", { class: "impact-section-head" },
        h("strong", {}, "Policy impact"),
        h("span", {}, `${impact.items.length} item${impact.items.length === 1 ? "" : "s"}`)),
      h("div", { class: "impact-list impact-list-scroll" }, impact.items.map((it) =>
        h("div", { class: "impact-row " + it.level },
          h("div", {}, pill(it.level, it.level === "high" ? "bad" : it.level === "medium" ? "warn" : "neutral")),
          h("div", {}, h("strong", {}, it.title), h("span", {}, it.detail))))),
      h("details", { class: "diff-details" },
        h("summary", {}, "Candidate diff"),
        diff.source === "fallback" ? h("div", { class: "alert-box warn" }, "Diff API unavailable; showing local draft diff.") : null,
        renderDiffLines(diff.lines)),
      needsAck ? h("label", { class: "ack-row" },
        acknowledge,
        h("span", {}, ackText(impact, runtime))) : null,
      h("label", { class: "field" }, h("span", {}, "Comment"), comment)),
    footer: [h("button", { class: "btn ghost", type: "button", title: "Cancel commit review", "aria-label": "Cancel commit review", "data-app-drawer-action": "cancel-commit-review", onclick: closeDrawer }, "Cancel"),
      commitBtn],
  });
}

async function loadCandidateDiff() {
  try {
    const data = await api.policyDiff({
      fromSource: "POLICY_SOURCE_RUNNING",
      toSource: "POLICY_SOURCE_CANDIDATE",
    });
    const labels = policyDiffLabels(data);
    return {
      ...labels,
      lines: normalizePolicyDiffLines(data.lines || []),
      source: "api",
    };
  } catch (e) {
    return {
      fromLabel: "running policy",
      toLabel: "candidate",
      lines: diffLines(session.running, session.draft),
      source: "fallback",
      error: e.message || String(e),
    };
  }
}

function runtimePreflightPanel(runtime) {
  if (!runtime.items.length) {
    return h("div", { class: "alert-box ok" }, runtime.detail);
  }
  return h("div", { class: "runtime-preflight" },
    h("div", { class: "alert-box " + runtime.cls },
      h("strong", {}, runtime.detail),
      h("div", { class: "note" }, "Review the action queue before applying this candidate.")),
    h("div", { class: "impact-list impact-list-scroll" }, runtime.items.map((it) =>
      runtimePreflightActionRow(it))));
}

function runtimePreflightActionRow(it) {
  return h("div", { class: "impact-row " + it.level },
    h("div", {}, pill(it.badge, it.level === "high" ? "bad" : "warn")),
    h("div", {},
      h("strong", {}, it.title),
      h("span", {}, it.detail || "No action detail returned."),
      h("div", { class: "warning-actions" },
        h("a", {
          class: "btn sm ghost",
          href: readinessActionHash(it.id || it.title),
          title: "Open this runtime blocker in Readiness",
          "aria-label": "Open this runtime blocker in Readiness",
          dataset: { runtimeBlockerAction: "readiness" },
        }, h("span", { html: icon("shield", 15) }), "Readiness"),
        it.href ? h("a", { class: "btn sm ghost", href: it.href, title: `Open fix for ${it.title || "runtime blocker"}`, "aria-label": `Open fix for ${it.title || "runtime blocker"}`, dataset: { runtimeBlockerAction: "open-fix", runtimeBlockerId: it.id || it.title || "" } }, "Open fix") : null)));
}

function ackText(impact, runtime) {
  if (impact.level === "high" && runtime.requiresAck) {
    return "I reviewed the high-risk policy impact and the runtime readiness warnings, and intend to apply this candidate.";
  }
  if (runtime.requiresAck) {
    return "I reviewed the runtime readiness warnings and intend to apply this candidate.";
  }
  return "I reviewed the high-risk policy impact and intend to apply it to the live firewall.";
}

async function discard() {
  if (session.candidateUnavailable) { toast("Candidate unavailable", session.candidateUnavailableMessage(), "bad"); return; }
  if (!(await confirmDialog({ title: "Discard pending changes?", message: "This resets the candidate to match the running policy. Your staged edits are lost. The live firewall is unaffected.", confirmLabel: "Discard", danger: true }))) return;
  try { await session.discard(); toast("Discarded", "Candidate reset to running policy.", "ok"); reloadCurrent(); }
  catch (e) { toast("Failed", e.message, "bad"); }
}

// ---------- Command palette ----------
const PALETTE_VISIBLE_LIMIT = 40;
let paletteItems = [], paletteActive = 0, paletteReturnFocus = null;
function openPalette() {
  const scrim = $("#palette-scrim"), input = $("#palette-input");
  paletteReturnFocus = document.activeElement;
  scrim.hidden = false; input.value = ""; buildPalette("");
  input.setAttribute("aria-expanded", "true");
  input.focus();
  input.oninput = () => buildPalette(input.value);
  scrim.onclick = (e) => { if (e.target === scrim) closePalette(); };
}
function closePalette() {
  $("#palette-scrim").hidden = true;
  const input = $("#palette-input");
  input.setAttribute("aria-expanded", "false");
  input.setAttribute("aria-activedescendant", "");
  const returnFocus = paletteReturnFocus;
  paletteReturnFocus = null;
  if (returnFocus && document.contains(returnFocus) && typeof returnFocus.focus === "function") returnFocus.focus();
}

function buildPalette(q) {
  q = q.toLowerCase();
  const items = [];
  NAV.forEach((n) => items.push({ kind: "Page", icon: n.icon, label: n.title, run: () => (location.hash = "#" + n.path) }));
  items.push(
    { kind: "Action", icon: "plus", label: "Add rule", run: () => { location.hash = "#/rules"; setTimeout(() => rules.openRuleEditor(null), 60); } },
    { kind: "Action", icon: "objects", label: "Manage App-ID objects", run: () => { location.hash = "#/objects?tab=applications"; } },
    { kind: "Action", icon: "traffic", label: "Review App-ID observations", sub: "unknown, low-confidence, and conflicting app evidence", run: () => { location.hash = "#/traffic?mode=app-id"; } },
    { kind: "Action", icon: "search", label: "Explain a flow", run: () => { location.hash = "#/troubleshoot"; } },
    { kind: "Action", icon: "inbox", label: "Open investigation case", sub: "Pinned flow, threat, audit, explain, and capture evidence", run: () => { location.hash = "#/investigation"; } },
    { kind: "Action", icon: "terminal", label: "Open API diagnostic console", sub: "version, posture, engines, sessions, audit", run: openDiagnosticConsole },
    { kind: "Action", icon: "copy", label: "Show API / CLI context", sub: "REST endpoints and ngfwctl equivalents for this screen", run: () => openAutomationContext(automationRoute()) },
    { kind: "Action", icon: "download", label: "Open API contract", sub: "generated Swagger YAML for CLI, SDK, and automation review", run: () => globalThis.open?.(API_CONTRACT.path, "_blank", "noopener,noreferrer") },
    { kind: "Action", icon: "threats", label: "Configure IDS/IPS", run: () => import("./views/ids.js").then((m) => m.openIdsEditor(() => location.reload())) },
    { kind: "Action", icon: "settings", label: "Open dataplane settings", sub: "MTU, MSS clamp, NIC offload, flowtable", run: () => { location.hash = "#/settings"; } },
    { kind: "Action", icon: "shield", label: "Open readiness action queue", sub: "production blockers, host tuning, support bundle", run: () => { location.hash = "#/readiness"; } },
    { kind: "Action", icon: "traffic", label: "Open performance evidence verifier", sub: "benchmark summary, raw iperf3, status, nftables evidence", run: () => { location.hash = "#/performance"; } },
    { kind: "Action", icon: "traffic", label: "Stage forwarding throughput profile", sub: "jumbo MTU, MSS clamp, flowtable fast path", run: () => stageNetworkProfileFromPalette("throughput") },
    { kind: "Action", icon: "shield", label: "Stage IDS/IPS inspected network profile", sub: "disable flowtable, manage NIC offloads for inspection", run: () => stageNetworkProfileFromPalette("inspection") },
    { kind: "Action", icon: "vpn", label: "Stage edge/VPN network profile", sub: "standard MTU and MSS clamp for tunnels", run: () => stageNetworkProfileFromPalette("edge-vpn") },
    { kind: "Action", icon: "download", label: "Export support bundle", run: () => readiness.exportSupportBundle() },
    { kind: "Action", icon: "refresh", label: "Refresh threat intel feeds", run: async () => { try { const r = await api.refreshFeeds(); toast("Feeds refreshed", `${r.entries || 0} entries.`, "ok"); } catch (e) { toast("Failed", e.message, "bad"); } } },
    { kind: "Action", icon: "diff", label: "Commit pending changes", run: () => { if (session.dirty) commit(); else toast("Nothing to commit", "No pending changes.", "warn"); } },
    { kind: "Action", icon: "globe", label: "Toggle theme", run: () => setTheme(getTheme() === "dark" ? "light" : "dark") });
  // Dynamic: rules and objects from the loaded draft.
  (session.draft.rules || []).forEach((r, i) => items.push({ kind: "Rule", icon: "rules", label: r.name || "(unnamed rule)", sub: (r.fromZones || ["any"]).join(",") + " → " + (r.toZones || ["any"]).join(","), run: () => { location.hash = "#/rules"; setTimeout(() => rules.openRuleEditor(i), 60); } }));
  (session.draft.addresses || []).forEach((a) => items.push({ kind: "Address", icon: "objects", label: a.name, sub: a.cidr, run: () => (location.hash = "#/objects?tab=addresses") }));
  (session.draft.services || []).forEach((s) => items.push({ kind: "Service", icon: "objects", label: s.name, run: () => (location.hash = "#/objects?tab=services") }));
  (session.draft.applications || []).forEach((a) => items.push({ kind: "App-ID", icon: "objects", label: a.name, sub: a.displayName || a.category || "", run: () => (location.hash = "#/objects?tab=applications") }));

  paletteItems = q ? items.filter((it) => (it.label + " " + (it.sub || "")).toLowerCase().includes(q)) : items.filter((it) => it.kind === "Page" || it.kind === "Action");
  paletteActive = 0;
  paintPalette();
}
function paintPalette() {
  const box = $("#palette-results");
  const input = $("#palette-input");
  const visible = paletteItems.slice(0, PALETTE_VISIBLE_LIMIT);
  paletteActive = clampPaletteIndex(paletteActive);
  input.setAttribute("aria-activedescendant", visible[paletteActive] ? `palette-option-${paletteActive}` : "");
  if (!paletteItems.length) { mount(box, h("div", { class: "palette-sec" }, "No matches")); return; }
  mount(box, visible.map((it, i) =>
    h("div", {
      id: `palette-option-${i}`,
      class: "palette-item" + (i === paletteActive ? " active" : ""),
      role: "option",
      "aria-selected": i === paletteActive ? "true" : "false",
      onclick: () => runPalette(i),
      onmouseenter: () => { paletteActive = i; paintPalette(); },
    },
      h("span", { html: icon(it.icon, 18) }),
      h("div", {}, h("div", {}, it.label), it.sub ? h("div", { class: "pi-sub" }, it.sub) : null),
      h("span", { class: "pi-kind" }, it.kind))));
}
function runPalette(i) { const it = paletteItems[i]; if (!it) return; closePalette(); it.run(); }
function visiblePaletteLength() { return Math.min(paletteItems.length, PALETTE_VISIBLE_LIMIT); }
function clampPaletteIndex(next) { return Math.min(Math.max(Number(next) || 0, 0), Math.max(visiblePaletteLength() - 1, 0)); }

function automationRoute() {
  if (typeof location !== "undefined" && location.hash) return location.hash;
  return currentRoute?.path || "/";
}

async function stageNetworkProfileFromPalette(profileId) {
  try {
    await session.load();
    const plan = applyNetworkProfileToPolicy(session.draft, profileId);
    if (!plan.ok) {
      toast("Profile not staged", (plan.blockers || []).join(" "), "warn");
      location.hash = "#/settings";
      return;
    }
    await session.apply((draft) => {
      draft.network = structuredClone(plan.policy.network || {});
    });
    toast(`${plan.profile.title} staged`, "Review the candidate, then validate and commit to apply.", "ok");
    location.hash = "#/settings";
  } catch (e) {
    toast("Profile not staged", e.message, "bad");
  }
}

// ---------- Connection status ----------
async function pingConnection() {
  const conn = $("#conn"), text = $("#conn-text");
  try {
    const v = await api.version();
    conn.className = "conn ok"; text.textContent = "v" + (v.version || "?");
    text.title = "controld " + v.version + " (" + (v.commit || "") + ")";
  } catch (e) {
    conn.className = "conn bad";
    text.textContent = e.status === 401 || e.status === 16 ? "auth required" : "unreachable";
  }
}

// ---------- Boot ----------
function boot() {
  initTheme();
  buildNav();
  const menuToggle = $("#menu-toggle");
  menuToggle.setAttribute("aria-controls", "sidebar");
  closeMenu();
  menuToggle.onclick = toggleMenu;
  $("#sidebar-scrim").onclick = closeMenu;
  globalThis.addEventListener?.("resize", () => syncSidebarSemantics());
  $("#open-palette").onclick = openPalette;
  $("#palette-hint").onclick = openPalette;
  $("#open-diagnostics").innerHTML = icon("terminal", 18);
  $("#open-diagnostics").onclick = openDiagnosticConsole;
  $("#open-automation").innerHTML = icon("copy", 18);
  $("#open-automation").onclick = () => openAutomationContext(automationRoute());

  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key.toLowerCase() === "p") { e.preventDefault(); openDiagnosticConsole(); return; }
    if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key.toLowerCase() === "a") { e.preventDefault(); openAutomationContext(automationRoute()); return; }
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openPalette(); return; }
    if (!$("#palette-scrim").hidden) {
      if (e.key === "Escape") closePalette();
      else if (e.key === "Tab") handleFocusTrap(e, $("#palette-scrim"));
      else if (e.key === "ArrowDown") { e.preventDefault(); paletteActive = clampPaletteIndex(paletteActive + 1); paintPalette(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); paletteActive = clampPaletteIndex(paletteActive - 1); paintPalette(); }
      else if (e.key === "Enter") { e.preventDefault(); runPalette(paletteActive); }
      return;
    }
    if (e.key === "Escape" && $("#app").classList.contains("menu-open")) {
      e.preventDefault();
      closeMenu();
      $("#menu-toggle").focus();
    }
  });

  session.subscribe(renderCandidateBar);
  // Load the editing session once so the candidate bar reflects state on
  // any page; failures (e.g. auth) are surfaced by the view/connection.
  session.load().then(renderCandidateBar).catch(() => {});

  router.start(renderRoute);
  pingConnection();
  refreshRuntimeBanner();
  setInterval(pingConnection, 30000);
  setInterval(refreshRuntimeBanner, 60000);
}

boot();
