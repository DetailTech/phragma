// diagnostic_console.js — API-backed operator console. It looks like a
// terminal, but it never executes shell commands; every line is collected
// through the public control-plane API.

import { h, icon, mount } from "./core.js";
import { api } from "./api.js";
import { handleFocusTrap, toast } from "./ui.js";
import * as fmt from "./format.js";
import { redactReadinessDisclosureText } from "./views/readiness.js";

const ENDPOINTS = ["version", "status", "identity", "releaseAcceptance", "candidateStatus", "sessions", "audit"];
let diagnosticReturnFocus = null;

export function openDiagnosticConsole() {
  const existing = document.getElementById("diagnostic-console-scrim");
  if (existing) {
    const refresh = existing.querySelector("[data-action='refresh']");
    refresh?.focus();
    return;
  }

  diagnosticReturnFocus = document.activeElement;
  const body = h("div", { class: "diag-body" }, h("div", { class: "diag-loading" }, "Collecting API evidence..."));
  const close = () => closeDiagnosticConsole();
  const refreshButton = h("button", {
    class: "btn sm",
    type: "button",
    title: "Refresh API diagnostic evidence",
    "aria-label": "Refresh API diagnostic evidence",
    dataset: { action: "refresh", sharedControl: "diagnostic-refresh" },
    onclick: () => refreshDiagnosticConsole(body),
  },
    h("span", { html: icon("refresh", 15) }), "Refresh");
  const copyButton = h("button", {
    class: "btn sm ghost",
    type: "button",
    title: "Copy API diagnostic snapshot",
    "aria-label": "Copy API diagnostic snapshot",
    dataset: { action: "copy", sharedControl: "diagnostic-copy" },
    onclick: () => copyDiagnosticSnapshot(body),
  },
    h("span", { html: icon("copy", 15) }), "Copy");
  const scrim = h("div", { id: "diagnostic-console-scrim", class: "diag-scrim", onclick: (e) => { if (e.target === scrim) close(); } },
    h("section", { class: "diag-console", role: "dialog", "aria-modal": "true", "aria-labelledby": "diagnostic-console-title", tabindex: "-1" },
      h("header", { class: "diag-bar" },
        h("span", { html: icon("terminal", 16) }),
        h("span", { id: "diagnostic-console-title" }, "API Diagnostic Console"),
        h("span", { class: "diag-live" }, "read-only"),
        h("button", { class: "icon-btn diag-close", type: "button", title: "Close", "aria-label": "Close diagnostic console", onclick: close, html: icon("x", 18) })),
      body,
      h("footer", { class: "diag-foot" },
        refreshButton,
        copyButton,
        h("a", { class: "btn sm ghost", href: "#/readiness", title: "Open readiness workbench", "aria-label": "Open readiness workbench", dataset: { action: "readiness", sharedControl: "diagnostic-readiness" }, onclick: close }, h("span", { html: icon("shield", 15) }), "Readiness"),
        h("a", { class: "btn sm ghost", href: "#/traffic?mode=sessions", title: "Open traffic sessions", "aria-label": "Open traffic sessions", dataset: { action: "sessions", sharedControl: "diagnostic-sessions" }, onclick: close }, h("span", { html: icon("traffic", 15) }), "Sessions"))));
  document.body.appendChild(scrim);
  document.addEventListener("keydown", diagnosticKeydown);
  refreshButton.focus();
  refreshDiagnosticConsole(body);
}

export function closeDiagnosticConsole() {
  const scrim = document.getElementById("diagnostic-console-scrim");
  if (scrim) scrim.remove();
  document.removeEventListener("keydown", diagnosticKeydown);
  const returnFocus = diagnosticReturnFocus;
  diagnosticReturnFocus = null;
  if (returnFocus && document.contains(returnFocus) && typeof returnFocus.focus === "function") returnFocus.focus();
}

function diagnosticKeydown(e) {
  if (e.key === "Escape") {
    e.preventDefault();
    closeDiagnosticConsole();
    return;
  }
  if (e.key === "Tab") {
    handleFocusTrap(e, document.querySelector("#diagnostic-console-scrim .diag-console"));
  }
}

async function refreshDiagnosticConsole(body) {
  mount(body, h("div", { class: "diag-loading" }, "Collecting API evidence..."));
  const results = await collectDiagnosticSnapshot();
  const summary = summarizeDiagnosticSnapshot(results);
  body.dataset.snapshot = diagnosticSnapshotText(summary);
  renderDiagnosticSummary(body, summary);
}

export async function collectDiagnosticSnapshot() {
  const calls = [
    api.version(),
    api.status(),
    api.identity(),
    api.releaseAcceptanceStatus(),
    api.candidateStatus(),
    api.sessions({ limit: 8 }),
    api.audit({ limit: 8 }),
  ];
  const settled = await Promise.allSettled(calls);
  return Object.fromEntries(ENDPOINTS.map((name, index) => [name, settled[index]]));
}

export function summarizeDiagnosticSnapshot(results, now = new Date()) {
  const statusAvailable = results.status?.status === "fulfilled";
  const identityAvailable = results.identity?.status === "fulfilled";
  const version = settledValue(results.version) || {};
  const status = settledValue(results.status) || {};
  const identity = settledValue(results.identity) || {};
  const releaseAcceptance = settledValue(results.releaseAcceptance) || {};
  const candidateStatus = settledValue(results.candidateStatus) || {};
  const sessionsData = settledValue(results.sessions) || {};
  const auditData = settledValue(results.audit) || {};
  const rt = status.runtime || {};
  const host = status.host || {};
  const dataplane = status.dataplane || {};
  const engines = Array.isArray(status.engines) ? status.engines : [];
  const warnings = Array.isArray(status.warnings) ? status.warnings : [];
  const sessions = Array.isArray(sessionsData.sessions) ? sessionsData.sessions : [];
  const audit = Array.isArray(auditData.entries) ? auditData.entries : [];
  const mode = statusAvailable ? (rt.dryRun ? "dry-run" : "enforcing") : "unknown";
  const tls = statusAvailable ? (rt.tlsEnabled ? "on" : "off") : "unknown";
  const auth = statusAvailable ? (rt.authEnabled ? "on" : "off") : "unknown";
  return {
    collectedAt: now.toISOString(),
    failures: endpointFailures(results),
    commands: [
      {
        name: "ngfwctl status",
        rows: [
          `version ${version.version || rt.version || "unknown"} · commit ${version.commit || rt.commit || "unknown"}`,
          `mode ${mode} · dataplane ${dataplane.activeDataplane || rt.activeDataplane || "unknown"} · tls ${tls} · auth ${auth}`,
          `uptime ${formatDuration(rt.uptimeSeconds)} · load ${hostLoad(host)} · memory ${hostMemory(host)}`,
        ],
      },
      {
        name: "ngfwctl whoami",
        rows: [
          identity.actor
            ? `${identity.actor} · role ${identity.role || "unknown"} · source ${identity.authSource || "unknown"}`
            : identityAvailable ? (rt.authEnabled ? "authentication required" : "local admin context") : "identity endpoint unavailable",
          `capabilities ${(identity.capabilities || []).join(", ") || "none reported"}`,
        ],
      },
      {
        name: "ngfwctl status # engines",
        rows: engines.length
          ? engines.map((engine) => `${safeDiagnosticToken(engine.name || "engine")} · ${safeDiagnosticToken(engine.state || "unknown")} · role ${safeDiagnosticToken(engine.role || "runtime")}`)
          : ["no engine status returned"],
      },
      {
        name: "ngfwctl status # routing-vpn",
        rows: routingVpnRows(status, statusAvailable),
      },
      {
        name: "ngfwctl system release-acceptance-status --json",
        rows: releaseAcceptanceRows(releaseAcceptance, results.releaseAcceptance?.status === "fulfilled"),
      },
      {
        name: "ngfwctl policy status --json",
        rows: candidateStatusRows(candidateStatus, results.candidateStatus?.status === "fulfilled"),
      },
      {
        name: "ngfwctl sessions --limit 8",
        rows: sessionSummaryRows(sessions, sessionsData),
      },
      {
        name: "ngfwctl audit --limit 8",
        rows: auditSummaryRows(audit),
      },
      {
        name: "ngfwctl status # warnings",
        rows: warningSummaryRows(warnings),
      },
    ],
  };
}

export function diagnosticSnapshotText(summary) {
  const lines = [`# Phragma diagnostic snapshot`, `collected_at=${summary.collectedAt}`];
  if (summary.failures.length) {
    lines.push("", "[endpoint failures]", ...summary.failures.map((failure) => `${failure.name}: ${failure.message}`));
  }
  for (const command of summary.commands) {
    lines.push("", `$ ${command.name}`, ...command.rows);
  }
  return lines.join("\n") + "\n";
}

function renderDiagnosticSummary(body, summary) {
  const failures = summary.failures.length
    ? h("div", { class: "diag-alert" },
      h("strong", {}, `${summary.failures.length} endpoint error${summary.failures.length === 1 ? "" : "s"}`),
      h("span", {}, summary.failures.map((failure) => `${failure.name}: ${failure.message}`).join(" · ")))
    : null;
  mount(body,
    h("div", { class: "diag-meta" },
      h("span", {}, "Collected ", new Date(summary.collectedAt).toLocaleString()),
      h("span", {}, summary.failures.length ? "partial evidence" : "all endpoints responded")),
    failures,
    summary.commands.map((command) => h("div", { class: "diag-command" },
      h("div", { class: "diag-prompt" }, h("span", {}, "$"), h("strong", {}, command.name)),
      h("div", { class: "diag-lines" }, command.rows.map((row) => diagnosticLine(row))))));
}

function diagnosticLine(row) {
  const cls = /\b(error|failed|critical|down|degraded|dry-run)\b/i.test(row)
    ? "bad"
    : /\b(warn|warning|partial|unknown|auth required)\b/i.test(row)
      ? "warn"
      : /\b(ready|active|enforcing|completed|on)\b/i.test(row)
        ? "ok"
        : "";
  return h("div", { class: "diag-line " + cls }, row);
}

async function copyDiagnosticSnapshot(body) {
  const text = body?.dataset?.snapshot || "";
  if (!text) {
    toast("No snapshot", "Refresh the diagnostic console first.", "warn");
    return;
  }
  try {
    await navigator.clipboard.writeText(text);
    toast("Diagnostic snapshot copied", "API evidence copied as plain text.", "ok");
  } catch {
    toast("Copy failed", "Select the diagnostic output and copy it manually.", "warn");
  }
}

function settledValue(result) {
  return result?.status === "fulfilled" ? result.value : null;
}

function endpointFailures(results) {
  return ENDPOINTS.flatMap((name) => {
    const result = results[name];
    if (!result || result.status === "fulfilled") return [];
    return [{ name, message: safeDiagnosticText(result.reason?.message || String(result.reason || "request failed")) }];
  });
}

function sessionSummaryRows(sessions = [], sessionsData = {}) {
  if (!sessions.length) return [`${safeDiagnosticToken(sessionsData.state || "unknown")} · no live sessions returned`];
  const states = countBy(sessions, (s) => safeDiagnosticToken(s.state || "unknown"));
  const protocols = countBy(sessions, (s) => safeDiagnosticToken(s.protocol || "IP"));
  const packets = sessions.reduce((sum, s) => sum + fmt.num(s.packets), 0);
  const bytes = sessions.reduce((sum, s) => sum + fmt.num(s.bytes), 0);
  return [
    `${sessions.length} session sample(s) · protocols ${formatCounts(protocols)} · states ${formatCounts(states)}`,
    `sample totals ${fmt.compactNum(packets)} pkts · ${fmt.bytes(bytes)} · endpoint values omitted from summary snapshot`,
  ];
}

function auditSummaryRows(entries = []) {
  if (!entries.length) return ["no audit entries returned"];
  const actions = countBy(entries, (e) => safeDiagnosticToken(e.action || "action"));
  const latest = entries.map((e) => e.time).filter(Boolean).sort().pop();
  const versions = entries.map((e) => Number(e.version || 0)).filter((value) => Number.isFinite(value) && value > 0);
  const maxVersion = versions.length ? Math.max(...versions) : 0;
  return [
    `${entries.length} audit sample(s) · actions ${formatCounts(actions)}`,
    `${latest ? "latest " + fmt.absTime(latest) : "latest time unavailable"}${maxVersion ? " · max version v" + maxVersion : ""} · actor and detail values omitted from summary snapshot`,
  ];
}

function releaseAcceptanceRows(status, available) {
  if (!available) return ["release acceptance endpoint unavailable"];
  const summary = status.summary || {};
  const count = (snake, camel) => Number(summary?.[snake] ?? summary?.[camel] ?? 0);
  const state = safeDiagnosticToken(status.state || (status.ready ? "ready" : "unknown"));
  const manifest = status.manifestPresent ?? status.manifest_present ? "present" : "missing";
  const problems = Array.isArray(status.problems) ? status.problems.length : 0;
  const rows = [
    `state ${state} · ready ${yesNo(Boolean(status.ready))} · manifest ${manifest}`,
    `checks passed ${count("passed", "passed")} · recorded ${count("recorded", "recorded")} · missing ${count("missing", "missing")} · invalid ${count("invalid", "invalid")} · todo ${count("todo", "todo")} · n/a ${count("not_applicable", "notApplicable")}`,
    `problem count ${problems}`,
    "release paths, problem text, and commands omitted from summary snapshot; open Readiness for redacted gate-level detail",
  ];
  if (state === "evidence-pending-manifest") {
    rows.push("manifest assembly pending · recorded evidence is not accepted until the release manifest is assembled and verified");
  }
  return rows;
}

function routingVpnRows(status, available) {
  if (!available) return ["routing and VPN status endpoint unavailable"];
  const frr = status.routing?.frr || {};
  const vpn = status.vpn || {};
  const ipsec = vpn.ipsec || {};
  const wg = vpn.wireguard || {};
  const bgp = frr.bgpNeighbors || frr.bgp_neighbors || [];
  const ospf = frr.ospfNeighbors || frr.ospf_neighbors || [];
  const ipsecTunnels = Array.isArray(ipsec.tunnels) ? ipsec.tunnels : [];
  const wgIfaces = Array.isArray(wg.interfaces) ? wg.interfaces : [];
  const wgPeers = wgIfaces.reduce((sum, iface) => sum + (Array.isArray(iface?.peers) ? iface.peers.length : 0), 0);
  const wgHandshook = wgIfaces.reduce((sum, iface) => sum + (Array.isArray(iface?.peers) ? iface.peers.filter((peer) => peer?.state === "handshook").length : 0), 0);
  const ipsecActive = ipsecTunnels.filter((tunnel) => tunnel?.state === "active").length;
  return [
    `frr ${frr.state || "not-configured"} · bgp neighbors ${bgp.length} · ospf neighbors ${ospf.length}`,
    `ipsec ${ipsec.state || "not-configured"} · active tunnels ${ipsecActive}/${ipsecTunnels.length}`,
    `wireguard ${wg.state || "not-configured"} · handshook peers ${wgHandshook}/${wgPeers}`,
  ];
}

function candidateStatusRows(status, available) {
  if (!available) return ["candidate status endpoint unavailable"];
  const changes = Array.isArray(status.changes) ? status.changes : [];
  const version = status.runningVersion ?? status.running_version ?? 0;
  const changeCount = Number(status.changeCount ?? status.change_count ?? changes.length);
  const rows = [
    `candidate ${status.hasCandidate || status.has_candidate ? "staged" : "none"} · dirty ${yesNo(Boolean(status.dirty))} · running v${version} · changes ${changeCount}`,
  ];
  const sectionRows = changes.slice(0, 4).map((change) => {
    const section = change.section || "policy";
    return `${section}: +${Number(change.added || 0)} ~${Number(change.modified || 0)} -${Number(change.removed || 0)}`;
  });
  if (sectionRows.length) rows.push(`sections ${sectionRows.join(" · ")}`);
  if (changes.length > sectionRows.length) rows.push(`${changes.length - sectionRows.length} more changed section(s)`);
  return rows;
}

function warningSummaryRows(warnings = []) {
  if (!warnings.length) return ["no runtime warnings returned"];
  const severities = countBy(warnings, (warning) => safeDiagnosticToken(warning.severity || "warning"));
  return [
    `${warnings.length} runtime warning(s) · severities ${formatCounts(severities)}`,
    "warning text and action detail omitted from summary snapshot; open Readiness or Logs for operator-scoped detail",
  ];
}

function countBy(items = [], pick) {
  const counts = new Map();
  for (const item of items) {
    const key = pick(item) || "unknown";
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return counts;
}

function formatCounts(counts) {
  return Array.from(counts.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, count]) => `${key}:${count}`)
    .join(", ") || "none";
}

function safeDiagnosticToken(value = "") {
  const safe = safeDiagnosticText(value)
    .replace(/[^a-z0-9_.:-]+/gi, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return safe || "unknown";
}

function safeDiagnosticText(value = "") {
  return redactReadinessDisclosureText(String(value ?? ""))
    .replace(/[\r\n\t]+/g, " ")
    .replace(/\s{2,}/g, " ")
    .trim()
    .slice(0, 220) || "request failed";
}

function yesNo(value) {
  return value ? "yes" : "no";
}

function hostLoad(host) {
  const load = Number(host?.load1 || 0);
  const perCPU = Number(host?.load1PerCpu || 0);
  if (!load && !perCPU) return host?.state || "unknown";
  return `${load.toFixed(2)} (${perCPU.toFixed(2)}/CPU)`;
}

function hostMemory(host) {
  const total = fmt.num(host?.memoryTotalBytes);
  if (!total) return "unknown";
  return `${Number(host.memoryUsedPercent || 0).toFixed(1)}% of ${fmt.bytes(total)}`;
}

function formatDuration(seconds) {
  const s = fmt.num(seconds);
  if (!s) return "unknown";
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
}
