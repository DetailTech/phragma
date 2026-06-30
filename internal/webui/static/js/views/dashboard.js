// Dashboard — at-a-glance situational awareness, built only from real
// API data (flows, alerts, policy, versions, feeds). Charts are
// client-side aggregations of actual records; no metrics are fabricated.

import { h, icon } from "../core.js";
import { api } from "../api.js";
import { throwIfAccessDenied } from "../auth_gate.js";
import { capabilityClass, conntrackCapacity, dataplanePosture, idsModeLabel } from "../dataplane.js";
import { policyNeedsBaseline } from "../baseline.js";
import { releaseEvidenceOwnerRoute } from "../readiness_model.js";
import { pageHead, card, emptyState, pill, metricCard, tag, labeledCell, responsiveTable } from "../ui.js";
import * as fmt from "../format.js";
import { area, donut, hbars } from "../charts.js";

export async function render() {
  const [statusR, identityR, run, alertsR, flowsR, versR, feedsR, candidateStatusR] = await Promise.allSettled([
    api.status(), api.identity(), api.running(), api.alerts(500), api.flows(500), api.versions(8), api.feeds(), api.candidateStatus(),
  ]);
  throwIfAccessDenied(statusR, identityR, run, alertsR, flowsR, versR, feedsR);
  const status = ok(statusR) || {};
  const identity = ok(identityR) || {};
  const policy = ok(run)?.policy || {};
  const alertsData = ok(alertsR) || {};
  const flowsData = ok(flowsR) || {};
  const alerts = alertsData.alerts || [];
  const flows = flowsData.flows || [];
  const versions = ok(versR)?.versions || [];
  const feeds = ok(feedsR)?.feeds || [];
  const telemetryScope = dashboardTelemetryScopeModel(alertsData, flowsData);
  const loadIssues = dashboardLoadIssues({ statusR, identityR, run, alertsR, flowsR, versR, feedsR, candidateStatusR });

  const rules = policy.rules || [];
  const activeRules = rules.filter((r) => !r.disabled).length;
  const critical = alerts.filter((a) => dashboardThreatSeverity(a).n <= 2).length;
  const totalBytes = flows.reduce((s, f) => s + fmt.num(f.bytesToServer) + fmt.num(f.bytesToClient), 0);
  const enabledFeeds = feeds.filter((f) => f.enabled).length;

  const root = h("div", {},
    pageHead("Dashboard", `Running policy v${ok(run)?.version || 0} · ${relFresh(alerts, flows)}`,
      [
        policyNeedsBaseline(policy) ? h("a", { class: "btn primary", href: "#/setup", title: "Open guided setup", "aria-label": "Open guided setup", dataset: { dashboardAction: "guided-setup" } }, h("span", { html: icon("shield", 16) }), "Guided setup") : null,
        h("button", { class: "btn", type: "button", title: "Refresh dashboard data", "aria-label": "Refresh dashboard data", dataset: { dashboardAction: "refresh" }, onclick: () => location.reload() }, h("span", { html: icon("refresh", 16) }), "Refresh"),
      ]),

    loadIssues.length ? dashboardLoadIssueBanner(loadIssues) : null,

    h("div", { class: "grid" },
      h("div", { class: "grid cols-3" },
        runtimePostureCard(status, policy, identity),
        changeReadinessCard(dashboardCandidateStatusModel(ok(candidateStatusR) || {}, candidateStatusR.status !== "fulfilled")),
        engineCoverageCard(status)),

      h("div", { class: "grid cols-4" },
        metricCard({ label: "Active rules", value: activeRules, foot: `${rules.length} total`, iconName: "rules", spark: ruleSpark(rules), tone: activeRules ? "info" : "neutral" }),
        metricCard({ label: "Threats (recent)", value: alerts.length, foot: telemetryScope.alertFoot || `${critical} high/critical`, iconName: "threats", spark: bucketSpark(alerts, "--bad"), tone: critical ? "drop" : alerts.length ? "reject" : "allow" }),
        metricCard({ label: "Traffic (recent)", value: fmt.bytes(totalBytes), foot: telemetryScope.flowFoot || `${flows.length} flows`, iconName: "traffic", spark: bytesSpark(flows), tone: flows.length ? "allow" : "neutral" }),
        metricCard({ label: "Intel feeds", value: enabledFeeds, foot: `${feeds.length} available`, iconName: "intel", tone: enabledFeeds ? "change" : "neutral" })),

      telemetryScope.limited ? telemetryScopeCard(telemetryScope) : null,

      h("div", { class: "grid cols-3" },
        severityCard(alerts),
        talkersCard(flows),
        appsCard(flows)),

      h("div", { class: "grid cols-3" },
        ruleCountersCard(status),
        recentThreatsCard(alerts),
        changeActivityCard(versions, ok(run)?.version || 0))));

  return root;
}

const ok = (r) => (r.status === "fulfilled" ? r.value : null);

function dashboardLoadIssues(results = {}) {
  const labels = {
    statusR: "System status",
    identityR: "Identity",
    run: "Running policy",
    alertsR: "Threats",
    flowsR: "Traffic",
    versR: "Version history",
    feedsR: "Intel feeds",
    candidateStatusR: "Candidate status",
  };
  return Object.entries(labels)
    .filter(([key]) => results[key]?.status === "rejected")
    .map(([key, label]) => ({ key, label, detail: dashboardLoadIssueDetail(results[key]?.reason) }));
}

function dashboardLoadIssueBanner(issues = []) {
  const routeLinks = [
    ["Traffic", dashboardTrafficHash({ limit: 500 })],
    ["Threats", dashboardThreatHash({ limit: 500 })],
    ["Changes", dashboardHash("/changes", { tab: "audit" })],
  ];
  return h("div", { class: "alert-box warn", dataset: { dashboardLoadIssues: String(issues.length) } },
    h("strong", {}, "Dashboard is showing partial data. "),
    h("span", {}, issues.length === 1 ? issues[0].label : `${issues.length} data sources unavailable`),
    issues.length === 1 ? h("div", { class: "note" }, issues[0].detail) : null,
    h("div", { class: "flex wrap" },
      h("button", { class: "btn sm", type: "button", title: "Retry dashboard data load", "aria-label": "Retry dashboard data load", dataset: { dashboardAction: "retry" }, onclick: () => location.reload() }, h("span", { html: icon("refresh", 14) }), "Retry"),
      ...routeLinks.map(([label, href]) => h("a", { class: "btn sm", href, title: `Open ${label} workspace`, "aria-label": `Open ${label} workspace`, dataset: { dashboardLoadIssueAction: label.toLowerCase().replace(/\s+/g, "-") } }, label))));
}

function dashboardLoadIssueDetail(reason) {
  const raw = String(reason?.message || reason || "Request failed");
  if (/<html|<!doctype|error response/i.test(raw)) return "The API did not return dashboard data.";
  return raw.replace(/\s+/g, " ").slice(0, 120);
}

export function dashboardHash(path, params = {}) {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value == null || value === "") continue;
    qs.set(key, String(value));
  }
  const query = qs.toString();
  return "#" + path + (query ? "?" + query : "");
}

export function dashboardTrafficHash(filters = {}) {
  return dashboardHash("/traffic", { mode: "flows", ...filters });
}

export function dashboardThreatHash(filters = {}) {
  return dashboardHash("/threats", filters);
}

export function dashboardAuditHash(filters = {}) {
  return dashboardHash("/changes", { tab: "audit", limit: "300", ...filters });
}

export function dashboardRulesRemediationHash() {
  return dashboardHash("/rules", { changed: "1", density: "compact" });
}

export function dashboardTroubleshootCompareHash() {
  return dashboardHash("/troubleshoot", { intent: "compare", run: "1" });
}

export function dashboardTelemetryScopeModel(alertData = {}, flowData = {}) {
  const alertCount = Array.isArray(alertData.alerts) ? alertData.alerts.length : 0;
  const flowCount = Array.isArray(flowData.flows) ? flowData.flows.length : 0;
  const alertTotal = Number(alertData.totalMatches ?? alertData.total_matches ?? alertCount) || 0;
  const flowTotal = Number(flowData.totalMatches ?? flowData.total_matches ?? flowCount) || 0;
  const alertMore = Boolean(alertData.hasMore ?? alertData.has_more) || alertTotal > alertCount;
  const flowMore = Boolean(flowData.hasMore ?? flowData.has_more) || flowTotal > flowCount;
  const limited = alertMore || flowMore;
  return {
    limited,
    tone: limited ? "warn" : "info",
    alertCount,
    flowCount,
    alertTotal,
    flowTotal,
    alertFoot: alertMore ? `${alertCount}/${alertTotal || "many"} shown` : `${alertCount} shown`,
    flowFoot: flowMore ? `${flowCount}/${flowTotal || "many"} shown` : `${flowCount} shown`,
    detail: limited
      ? `${alertCount}/${alertTotal || "many"} alerts and ${flowCount}/${flowTotal || "many"} flows shown.`
      : `${alertCount} alerts and ${flowCount} flows shown.`,
  };
}

function telemetryScopeCard(model) {
  return h("div", { class: "alert-box " + (model.limited ? "warn" : "info"), dataset: { dashboardTelemetryScope: model.limited ? "limited" : "complete" } },
    h("strong", {}, model.limited ? "Some telemetry is paged." : "Telemetry summaries are current."),
    h("div", { class: "note" }, model.detail),
    h("div", { class: "flex wrap" },
      h("a", { class: "btn sm", href: dashboardTrafficHash({ limit: 500 }), title: "Open paged Traffic review", "aria-label": "Open paged Traffic review", dataset: { dashboardTelemetryAction: "traffic" } }, h("span", { html: icon("traffic", 14) }), "Traffic"),
      h("a", { class: "btn sm", href: dashboardThreatHash({ limit: 500 }), title: "Open paged Threats review", "aria-label": "Open paged Threats review", dataset: { dashboardTelemetryAction: "threats" } }, h("span", { html: icon("threats", 14) }), "Threats")));
}

export function dashboardEngineActionLinks(engine = {}) {
  const name = String(engine.name || engine.role || "engine").toLowerCase();
  const detail = String(engine.detail || engine.state || "").slice(0, 120);
  const engineFilter = engine.name || engine.role || "";
  const links = [];
  if (/ids-ips|ids|ips|threat|inspection/.test(name)) {
    links.push({
      id: "inspection",
      label: "Inspection",
      href: dashboardHash("/inspection", { engine: engineFilter, state: engine.state || "" }),
      title: "Open inspection profile and Threat-ID package posture",
    });
  } else if (/frr|route|routing|bgp|ospf|strongswan|ipsec|wireguard|vpn/.test(name)) {
    links.push({
      id: "netvpn",
      label: "Net/VPN",
      href: dashboardHash("/netvpn", { drawer: "runtime-review", engine: engineFilter }),
      title: "Open Routing and VPN runtime review",
    });
  } else {
    links.push({
      id: "troubleshoot",
      label: "Troubleshoot",
      href: dashboardHash("/troubleshoot", { intent: "runtime", run: "1", engine: engineFilter }),
      title: "Open Troubleshoot runtime review",
    });
  }
  links.push({
    id: "logs",
    label: "Logs",
    href: dashboardHash("/logs", { source: "engine", engine: engineFilter, severity: engineStateClass(engine) === "bad" ? "error" : "", q: detail }),
    title: "Open engine logs filtered to this posture",
  });
  return links;
}

export function dashboardAlertKey(alert = {}) {
  if (alert.flowId) return "flow:" + alert.flowId;
  const sid = Number(alert.signatureId || 0);
  if (!Number.isFinite(sid) || sid <= 0) return "";
  return ["sid", sid, alert.srcIp || "", alert.srcPort || "", alert.destIp || "", alert.destPort || "", alert.time || ""].join(":");
}

function relFresh(alerts, flows) {
  const t = [...alerts, ...flows].map((x) => x.time).filter(Boolean).sort().pop();
  return t ? "telemetry updated " + fmt.relTime(t) : "no telemetry yet";
}

export function dashboardCandidateStatusModel(status = {}, unavailable = false) {
  if (unavailable) {
    return {
      unavailable: true,
      dirty: false,
      changeCount: 0,
      label: "candidate unavailable",
      detail: "Candidate status could not be loaded.",
    };
  }
  const hasCandidate = Boolean(status?.hasCandidate ?? status?.has_candidate);
  const dirty = Boolean(status?.dirty ?? false);
  const changeCount = Number(status?.changeCount ?? status?.change_count ?? 0) || 0;
  const pending = dirty || (hasCandidate && changeCount > 0);
  const runningVersion = Number(status?.runningVersion ?? status?.running_version ?? 0) || 0;
  return {
    unavailable: false,
    dirty: pending,
    changeCount,
    label: pending ? `${changeCount || 1} pending change${(changeCount || 1) === 1 ? "" : "s"}` : "candidate clean",
    detail: pending
      ? `Review ${changeCount || 1} candidate change${(changeCount || 1) === 1 ? "" : "s"} before commit.`
      : runningVersion ? `No staged candidate; running policy v${runningVersion}.` : "No staged candidate.",
  };
}

export function dashboardReleaseReadinessModel(input = {}, candidate = {}, unavailable = false) {
  const summary = input.summary || {};
  const checks = Array.isArray(input.checks) ? input.checks : Array.isArray(input.requiredGates) ? input.requiredGates : [];
  const first = checks.find((item) => item.state && item.state !== "passed") || checks[0] || {};
  const firstId = first.name || first.id || "";
  const openCount = Number(summary.missing || 0) + Number(summary.invalid || 0) + Number(summary.todo || 0);
  const stateLabel = unavailable ? "unavailable" : input.state || "unknown";
  return {
    ready: Boolean(input.ready),
    stateLabel,
    cls: unavailable ? "warn" : input.ready ? "ok" : stateLabel === "blocked" ? "bad" : "warn",
    title: stateLabel === "evidence-pending-manifest" ? "Release manifest assembly is pending" : stateLabel,
    detail: unavailable ? "Release evidence status could not be loaded." : openCount ? `${openCount} release gate items need attention.` : "All required evidence is recorded.",
    summary,
    openCount,
    firstGate: firstId ? {
      id: firstId,
      name: firstId,
      state: first.state === "recorded" ? "pending manifest" : first.state || "",
      detail: String(first.detail || "").replace(/\/[^\s]+/g, "[redacted]"),
      href: firstId ? releaseEvidenceOwnerRoute(firstId) : "",
    } : null,
    candidate: dashboardCandidateStatusModel(candidate, unavailable),
    rulesHref: dashboardRulesRemediationHash(),
    compareHref: dashboardTroubleshootCompareHash(),
  };
}

function changeReadinessCard(candidate) {
  return card(h("div", { dataset: { dashboardCandidateState: candidate.dirty ? "dirty" : "clean" } },
    h("h2", {}, "Candidate", h("span", { class: "spacer" }), pill(candidate.label, candidate.dirty ? "warn" : "ok", true)),
    candidate.dirty ? h("div", { class: "alert-box warn" },
      h("strong", {}, candidate.label),
      h("div", { class: "note" }, candidate.detail)) : null,
    h("div", { class: "flex wrap" },
      h("a", { class: "btn sm", href: "#/changes?tab=candidate", title: "Open candidate review", "aria-label": "Open candidate review", dataset: { dashboardCandidateReview: "true" } }, h("span", { html: icon("diff", 14) }), "Review"),
      h("a", { class: "btn sm ghost", href: dashboardRulesRemediationHash(), title: "Open rules", "aria-label": "Open rules", dataset: { dashboardCandidateRules: "true" } }, h("span", { html: icon("rules", 14) }), "Rules"))));
}

function runtimePostureCard(status, policy, identity) {
  const rt = status.runtime || {};
  const host = status.host || {};
  const dp = dataplanePosture(policy, status);
  const warnings = status.warnings || [];
  const conntrack = conntrackCapacity(status);
  const critical = warnings.filter((w) => w.severity === "critical").length;
  const warn = warnings.filter((w) => w.severity === "warning").length;
  const cls = critical ? "bad" : warn ? "warn" : "ok";
  const label = critical ? "Action required" : warn ? "Review needed" : "Ready";
  const management = managementPlaneSummary(status, identity);
  return card(h("h2", {}, "Runtime posture", h("span", { class: "spacer" }), pill(label, cls, true)),
    h("div", { class: "runtime-grid" },
      postureMetric("Dataplane", displayDataplane(status.dataplane?.activeDataplane || rt.activeDataplane || "—")),
      postureMetric("Throughput path", dp.label),
      postureMetric("State table", conntrackLabel(conntrack)),
      postureMetric("Inspection", idsModeLabel(policy)),
      postureMetric("Mode", rt.dryRun ? "Dry run" : "Enforcing"),
      postureMetric("Auth", rt.authEnabled ? "Enabled" : "Disabled"),
      postureMetric("Host load", hostLoadLabel(host)),
      postureMetric("Interfaces", hostInterfaceHealth(host))),
    management.cls !== "ok" ? h("div", { class: "alert-box " + management.cls },
      h("strong", {}, management.title),
      h("div", { class: "note" }, management.detail)) : null,
    dp.cls !== "ok" ? h("div", { class: "alert-box " + postureBoxClass(dp.cls) },
      h("strong", {}, dp.summary),
      h("div", { class: "note" }, dp.detail)) : null,
    warnings.length ? h("div", { class: "status-warnings" }, warnings.slice(0, 3).map((w) =>
      h("div", { class: "alert-box " + warningClass(w.severity) },
        h("strong", {}, w.message),
        w.action ? h("div", { class: "note" }, w.action) : null))) : null);
}

function displayDataplane(value = "") {
  const text = String(value || "").toLowerCase();
  if (/ebpf|xdp|tc/.test(text)) return "Advanced dataplane";
  if (/nft|conntrack|iptables/.test(text)) return "Stateful forwarding";
  if (/flowtable|offload/.test(text)) return "Forwarding acceleration";
  return value || "—";
}

export function managementPlaneSummary(status = {}, identity = {}) {
  const rt = status.runtime || {};
  const mgmt = status.management || {};
  const issues = [];
  if (rt.dryRun) issues.push("dry-run mode");
  if (rt.authEnabled === false) issues.push("auth disabled");
  if (rt.tlsEnabled === false) issues.push("TLS disabled");
  if (mgmt.rateLimitEnabled === false) issues.push("rate limiting disabled");
  const proxyCIDRs = Array.isArray(mgmt.trustedProxyCidrs) ? mgmt.trustedProxyCidrs : [];
  if (mgmt.rateLimitClientIdentity === "socket-peer" && proxyCIDRs.length === 0) {
    issues.push("socket-peer client identity");
  }

  const actor = identity.actor
    ? `${identity.actor} (${identity.role || "unknown"}, ${identity.authSource || "unknown"})`
    : rt.authEnabled ? "identity pending" : "local admin";
  const rate = mgmt.rateLimitEnabled
    ? `${mgmt.rateLimitRequestsPerMinute || 0}/min burst ${mgmt.rateLimitBurst || 0}`
    : "disabled";

  if (!issues.length) {
    return {
      cls: "ok",
      title: "Management controls are active.",
      detail: `TLS, authentication, rate limits, and trusted client identity are active. Current actor: ${actor}.`,
    };
  }
  const cls = rt.authEnabled === false || rt.tlsEnabled === false || rt.dryRun ? "bad" : "warn";
  return {
    cls,
    title: "Management controls need review.",
    detail: `${issues.join(", ")}. Actor: ${actor}. Rate limit: ${rate}. Review before exposing the UI or API.`,
  };
}

function conntrackLabel(conntrack) {
  if (!conntrack.maxEntries) return conntrack.state || "unknown";
  return `${conntrack.usagePercent.toFixed(1)}% · ${conntrack.currentEntries}/${conntrack.maxEntries}`;
}

function hostLoadLabel(host) {
  if (!host || !host.state) return "—";
  const load = Number(host.load1 || 0);
  const perCPU = Number(host.load1PerCpu || 0);
  if (!load && !perCPU) return host.state || "unknown";
  return `${load.toFixed(2)} · ${perCPU.toFixed(2)}/CPU`;
}

function hostInterfaceHealth(host) {
  const interfaces = Array.isArray(host?.interfaces) ? host.interfaces : [];
  if (!interfaces.length) return "none";
  const degraded = interfaces.filter((iface) => iface.state && iface.state !== "ready");
  return degraded.length ? `${degraded.length}/${interfaces.length} degraded` : `${interfaces.length} clean`;
}

function engineCoverageCard(status) {
  const engines = status.engines || [];
  const caps = status.capabilities || [];
  return card(h("h2", {}, "Capability coverage", h("span", { class: "spacer" }),
      pill(`${engines.length} managed`, "info")),
    engines.length ? h("div", { class: "table-wrap flat" },
      responsiveTable([
        { label: "Capability", attrs: { class: "dashboard-engine-name-col" } },
        { label: "State", attrs: { class: "dashboard-engine-state-col" } },
        { label: "Detail", attrs: { class: "dashboard-engine-detail-col" } },
        { label: "Open", attrs: { class: "dashboard-engine-actions-col" } },
      ], engines.map((e) =>
        h("tr", { dataset: { dashboardEngine: e.name || "engine" } },
          labeledCell("Capability", { class: "data-clip" }, dashboardEngineCapability(e)),
          labeledCell("State", {}, pill(e.state || "unknown", engineStateClass(e))),
          labeledCell("Detail", { class: "muted data-wrap" }, dashboardEngineCustomerDetail(e)),
          labeledCell("Open", { class: "dashboard-engine-actions" },
            h("div", { class: "flex wrap" }, dashboardEngineActionLinks(e).map((link) =>
              h("a", {
                class: "btn sm ghost",
                href: link.href,
                title: link.title,
                "aria-label": `${link.label} for ${e.name || e.role || "engine"}`,
                dataset: { dashboardEngineAction: link.id, dashboardEngineName: e.name || e.role || "engine" },
              }, link.label)))))),
      { className: "dashboard-engine-table" })) :
      emptyState("settings", "No capability status", "Runtime coverage is not available."),
    caps.length ? h("div", { class: "cap-list" }, caps.map((c) =>
      h("div", { class: "cap-item" },
        h("span", {}, dashboardCapabilityName(c.name)),
        pill(c.state || "unknown", capabilityClass(c.state)),
        h("span", { class: "muted" }, dashboardCapabilityDetail(c.detail || ""))))) : null);
}

function dashboardEngineCapability(engine = {}) {
  const text = `${engine.role || ""} ${engine.name || ""}`.toLowerCase();
  if (/ids|ips|threat|inspection|suricata/.test(text)) return "IDS/IPS";
  if (/route|routing|bgp|ospf|frr/.test(text)) return "Routing";
  if (/vpn|ipsec|wireguard|strongswan/.test(text)) return "VPN";
  if (/dns|url|intel|feed/.test(text)) return "Threat intelligence";
  if (/log|telemetry|siem/.test(text)) return "Telemetry";
  return titleCase(engine.role || "System service");
}

function dashboardEngineCustomerDetail(engine = {}) {
  const state = engine.state || "unknown";
  const capability = dashboardEngineCapability(engine).toLowerCase();
  if (state === "ready" || state === "active") return `${capability} is active.`;
  if (state === "simulation") return `${capability} is in simulation mode.`;
  if (state === "missing-prerequisites") return `${capability} needs configuration.`;
  if (state === "failed") return `${capability} needs attention.`;
  return `${capability} status is ${state}.`;
}

function dashboardCapabilityName(name = "") {
  return dashboardEngineCapability({ name });
}

function dashboardCapabilityDetail(detail = "") {
  return String(detail || "")
    .replace(/\b(Suricata|FRR|strongSwan|WireGuard|nftables|conntrack|eBPF|XDP|tc)\b/gi, "the backing service")
    .replace(/\s+/g, " ")
    .trim();
}

function titleCase(value = "") {
  return String(value || "")
    .replace(/[-_]+/g, " ")
    .replace(/\b\w/g, (ch) => ch.toUpperCase());
}

function engineStateClass(engine) {
  if (engine.state === "missing-prerequisites" || engine.state === "failed") return "bad";
  if (engine.mode === "dry-run" || engine.state === "simulation" || engine.state === "restarting") return "warn";
  if (engine.state === "ready" || engine.state === "active") return "ok";
  return "neutral";
}

function postureMetric(label, value) {
  return h("div", { class: "posture-metric" },
    h("span", {}, label),
    h("strong", {}, value));
}

function warningClass(sev) {
  if (sev === "critical") return "bad";
  if (sev === "warning") return "warn";
  return "ok";
}
function postureBoxClass(cls) {
  if (cls === "bad" || cls === "warn" || cls === "ok" || cls === "info") return cls;
  return "";
}

function ruleSpark(rules) {
  // Bar-ish spark of allow vs deny composition is more meaningful than a series.
  const allow = rules.filter((r) => r.action === "ACTION_ALLOW").length;
  const deny = rules.length - allow;
  return area([allow, Math.max(allow, deny), deny || 1], { height: 42, color: getCss("--accent") });
}
function bucketSpark(items, colorVar) {
  return area(timeBuckets(items, 16).map((b) => b.length), { height: 42, color: getCss(colorVar) });
}
function bytesSpark(flows) {
  const buckets = timeBuckets(flows, 16).map((b) => b.reduce((s, f) => s + fmt.num(f.bytesToServer) + fmt.num(f.bytesToClient), 0));
  return area(buckets, { height: 42, color: getCss("--ok") });
}
function getCss(n) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); }

// Split items (with .time) into N equal time buckets across their range.
function timeBuckets(items, n) {
  const buckets = Array.from({ length: n }, () => []);
  const ts = items.map((x) => new Date(x.time).getTime()).filter((t) => !isNaN(t));
  if (!ts.length) return buckets;
  const min = Math.min(...ts), max = Math.max(...ts), span = max - min || 1;
  for (const x of items) {
    const t = new Date(x.time).getTime();
    if (isNaN(t)) continue;
    let i = Math.floor(((t - min) / span) * (n - 1));
    if (i < 0) i = 0; if (i >= n) i = n - 1;
    buckets[i].push(x);
  }
  return buckets;
}

function severityCard(alerts) {
  const colors = { 1: getCss("--bad"), 2: getCss("--warn"), 3: getCss("--info"), 4: getCss("--text-faint") };
  const counts = { 1: 0, 2: 0, 3: 0, 4: 0 };
  alerts.forEach((a) => { counts[dashboardThreatSeverity(a).n]++; });
  const segs = [1, 2, 3, 4].map((n) => ({ value: counts[n], color: colors[n], label: fmt.severity(n === 4 ? 5 : n).label }));
  const body = alerts.length
    ? h("div", { class: "dashboard-severity-layout" },
        h("div", { class: "dashboard-severity-chart", html: donut(segs, { size: 168, center: alerts.length, sub: "alerts" }) }),
        h("div", { class: "legend dashboard-severity-legend" },
          [["Critical", 1], ["High", 2], ["Medium", 3], ["Low", 4]].map(([lbl, n]) =>
            h("a", { class: "li linklike", href: dashboardThreatHash({ sev: n }), title: `Open ${lbl.toLowerCase()} threats`, "aria-label": `Open ${lbl.toLowerCase()} threats`, dataset: { dashboardSeverityLegend: String(n) } },
              h("span", { class: `sw dashboard-severity-swatch severity-${n}` }),
              h("span", {}, `${lbl} · ${counts[n]}`)))))
    : emptyState("threats", "No alerts", "IDS/IPS has not logged any detections yet.");
  return card(h("h2", {}, "Threats by severity"), body);
}

function talkersCard(flows) {
  const by = new Map();
  flows.forEach((f) => {
    const k = f.srcIp || "?";
    by.set(k, (by.get(k) || 0) + fmt.num(f.bytesToServer) + fmt.num(f.bytesToClient));
  });
  const items = [...by.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6)
    .map(([ip, v]) => ({ label: ip, value: v, valueLabel: fmt.bytes(v), href: dashboardTrafficHash({ ip }) }));
  return card(h("h2", {}, "Top talkers"),
    items.length ? hbars(items) : emptyState("traffic", "No flows", "No traffic has been observed yet."));
}

function appsCard(flows) {
  const by = new Map();
  flows.forEach((f) => {
    const summary = dashboardAppSummary(f);
    const current = by.get(summary.appId) || { summary, count: 0 };
    current.count++;
    by.set(summary.appId, current);
  });
  const items = [...by.values()].sort((a, b) => b.count - a.count).slice(0, 6)
    .map(({ summary, count }) => ({
      label: summary.label,
      value: count,
      valueLabel: count + " flows",
      sub: summary.evidence.join(" · "),
      color: getCss("--accent-2"),
      href: dashboardTrafficHash({ app: summary.appId }),
    }));
  return card(h("h2", {}, "Top applications"),
    items.length ? hbars(items) : emptyState("traffic", "No application data", "Phragma App-ID labels appear once flows are observed."));
}

export function dashboardAppSummary(flow = {}) {
  const appId = String(flow.appId || flow.appProtocol || flow.protocol || "unknown").trim() || "unknown";
  const canonical = String(flow.appId || "").trim();
  const appName = String(flow.appName || "").trim();
  const signal = String(flow.appProtocol || "").trim();
  const protocol = String(flow.protocol || "").trim();
  const label = canonical || appId.toUpperCase();
  const evidence = [];
  if (appName && appName !== label) evidence.push(appName);
  if (signal && signal !== appId) evidence.push(`signal ${signal}`);
  if (protocol && protocol !== appId && protocol !== signal) evidence.push(protocol);
  return { appId, label, evidence };
}

export function dashboardThreatSeverity(alert = {}) {
  const sev = String(alert.threatSeverity || "").trim().toLowerCase();
  if (sev === "critical") return { label: "Critical", cls: "bad", n: 1 };
  if (sev === "high") return { label: "High", cls: "warn", n: 2 };
  if (sev === "medium") return { label: "Medium", cls: "info", n: 3 };
  if (sev === "low") return { label: "Low", cls: "neutral", n: 4 };
  return fmt.severity(alert.severity);
}

export function dashboardThreatSummary(alert = {}) {
  const threatID = String(alert.threatId || "").trim();
  const threatName = String(alert.threatName || "").trim();
  const signature = String(alert.signature || "").trim();
  const label = threatName || threatID || signature || "Unknown threat";
  const evidence = [];
  if (threatID && threatID !== label) evidence.push(threatID);
  if (signature && signature !== label) evidence.push(signature);
  if (alert.signatureId) evidence.push(`SID ${alert.signatureId}`);
  if (alert.threatCategory) evidence.push(alert.threatCategory);
  if (alert.threatConfidence) evidence.push(`confidence ${alert.threatConfidence}%`);
  if (alert.category && alert.category !== alert.threatCategory) evidence.push(alert.category);
  if (alert.protocol) evidence.push(alert.protocol);
  return { label, evidence };
}

function ruleCountersCard(status) {
  const version = Number(status.dataplane?.runningPolicyVersion || 0);
  const counters = (status.dataplane?.counters || [])
    .filter((c) => c.kind === "rule" || c.kind === "host-input" || c.kind === "snat" || c.kind === "dnat" || c.kind === "default" || c.kind === "ips")
    .slice(0, 6);
  const items = counters.map((c) => ({
    label: counterLabel(c),
    value: fmt.num(c.packets),
    valueLabel: `${fmt.num(c.packets)} pkts / ${fmt.bytes(c.bytes)}`,
    color: counterColor(c.kind),
  }));
  return card(h("h2", {}, "Policy counters", tag(version > 0 ? `v${version}` : "version unknown"), h("span", { class: "spacer" }), h("a", { href: "#/rules", class: "linklike", title: "Open rules workbench", "aria-label": "Open rules workbench", dataset: { dashboardLink: "rules" } }, "Rules →")),
    items.length ? hbars(items) : emptyState("rules", "No counters", "Commit a policy on Linux to collect packet filter rule hit counters."));
}

function counterLabel(c) {
  const name = c.name || c.comment || "counter";
  const id = c.itemId || c.ruleId || "";
  const suffix = id ? ` · ${id}` : "";
  if (c.kind === "host-input") return "host · " + name + suffix;
  if (c.kind === "snat" || c.kind === "dnat") return c.kind + " · " + name + suffix;
  if (c.kind === "rule") return name + suffix;
  if (c.kind === "default") return name.replaceAll("-", " ");
  if (c.kind === "ips") return "ips inspect";
  return name;
}

function counterColor(kind) {
  if (kind === "default") return getCss("--bad");
  if (kind === "ips") return getCss("--info");
  if (kind === "host-input") return getCss("--accent-2");
  return getCss("--accent");
}

function recentThreatsCard(alerts) {
  const top = [...alerts].sort((a, b) => dashboardThreatSeverity(a).n - dashboardThreatSeverity(b).n).slice(0, 6);
  const body = top.length
    ? h("div", { class: "table-wrap flat" }, responsiveTable([
        { label: "Severity", attrs: { class: "dashboard-threat-severity-col" } },
        { label: "Threat", attrs: { class: "dashboard-threat-name-col" } },
        { label: "Source", attrs: { class: "dashboard-threat-source-col" } },
        { label: "Time", attrs: { class: "dashboard-threat-time-col" } },
      ], top.map((a) => {
        const s = dashboardThreatSeverity(a);
        const summary = dashboardThreatSummary(a);
        const alert = dashboardAlertKey(a);
        return h("tr", { dataset: { dashboardThreat: alert || summary.label || "threat" } },
          labeledCell("Severity", {}, pill(s.label, s.cls, true)),
          labeledCell("Threat", { class: "mono data-clip" },
            h("a", { class: "linklike", href: dashboardThreatHash({ sev: s.n, alert, signatureId: a.signatureId || "", ip: a.srcIp || "" }), title: `Open threat ${summary.label}`, "aria-label": `Open threat ${summary.label}`, dataset: { dashboardThreatLink: alert || summary.label || "threat" } }, summary.label),
            summary.evidence.length ? h("div", { class: "muted data-clip" }, summary.evidence.join(" · ")) : null),
          labeledCell("Source", { class: "mono muted data-clip" }, a.srcIp || "—"),
          labeledCell("Time", { class: "muted data-clip" }, fmt.relTime(a.time)));
      }), { className: "dashboard-threat-table" }))
    : emptyState("shield", "All clear", "No recent threats to review.");
  return card(h("h2", {}, "Recent threats", h("span", { class: "spacer" }), h("a", { href: "#/threats", class: "linklike", title: "Open all threats", "aria-label": "Open all threats", dataset: { dashboardLink: "threats" } }, "View all →")), body);
}

function changeActivityCard(versions, runningV) {
  const body = versions.length
    ? h("div", { class: "table-wrap flat" }, responsiveTable([
        { label: "Version", attrs: { class: "dashboard-version-id-col" } },
        { label: "Comment", attrs: { class: "dashboard-version-comment-col" } },
        { label: "Actor", attrs: { class: "dashboard-version-actor-col" } },
        { label: "Time", attrs: { class: "dashboard-version-time-col" } },
      ], versions.map((v) =>
        h("tr", { dataset: { dashboardVersion: String(v.id || "") } },
          labeledCell("Version", {}, tag("v" + v.id), Number(v.id) === runningV ? pill("running", "ok") : null),
          labeledCell("Comment", { class: "data-clip" },
            h("a", { class: "linklike", href: dashboardAuditHash({ version: v.id }), title: `Open audit history for version ${v.id}`, "aria-label": `Open audit history for version ${v.id}`, dataset: { dashboardVersionAudit: String(v.id || "") } }, v.comment || "(no comment)")),
          labeledCell("Actor", { class: "muted data-clip" }, v.actor),
          labeledCell("Time", { class: "muted data-clip" }, fmt.relTime(v.createdAt)))),
      { className: "dashboard-version-table" }))
    : emptyState("changes", "No versions yet", "Committed policy versions will appear here.");
  return card(h("h2", {}, "Recent changes", h("span", { class: "spacer" }), h("a", { href: "#/changes", class: "linklike", title: "Open change history", "aria-label": "Open change history", dataset: { dashboardLink: "changes" } }, "History →")), body);
}
