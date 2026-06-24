// Logs — read-only system and engine log workbench backed by /v1/system/logs.

import { h, icon, clear } from "../core.js";
import { api } from "../api.js";
import { cliCommand, openAutomationContext } from "../automation_context.js";
import { evidenceToolbar } from "../evidence_toolbar.js";
import { activeInvestigationServerCaseHref, appendInvestigationPacketToActiveServerCase, caseItemKey, pinInvestigationPacket } from "../investigation_case.js";
import { buildInvestigationPacket, investigationPacketFilename, investigationPacketJson, investigationPacketText } from "../investigation_packet.js";
import { CAPTURE_LIMITS, buildCapturePlan } from "../packet_capture.js";
import { readQueryState, writeQueryState } from "../query_state.js";
import { savedFilterControls } from "../saved_filters.js";
import { pageHead, emptyState, pill, toast, openDrawer, closeDrawer, keyboardRowAttrs, labeledCell, responsiveTable } from "../ui.js";

const DEFAULT_STATE = Object.freeze({
  q: "",
  source: "",
  engine: "",
  severity: "",
  since: "",
  until: "",
  limit: "200",
  entry: "",
});
const QUERY_KEYS = Object.keys(DEFAULT_STATE);
const SAVED_FILTER_KEYS = QUERY_KEYS.filter((key) => key !== "entry");
const LOG_COLUMNS = Object.freeze([
  { key: "timestamp", label: "Time" },
  { key: "source", label: "Source" },
  { key: "engine", label: "Engine" },
  { key: "severity", label: "Severity" },
  { key: "message", label: "Message" },
  { key: "facility", label: "Facility" },
  { key: "file", label: "File" },
  { key: "line", label: "Line" },
]);
const LOG_CAPTURE_DEFAULTS = Object.freeze({
  interface: CAPTURE_LIMITS.defaultInterface,
  durationSeconds: CAPTURE_LIMITS.defaultDurationSeconds,
  packetCount: CAPTURE_LIMITS.defaultPacketCount,
  snaplenBytes: CAPTURE_LIMITS.defaultSnaplenBytes,
});

let state = { ...DEFAULT_STATE };
let routePath = "/logs";
let latestEntries = [];

export async function render(ctx = {}) {
  routePath = ctx.path || "/logs";
  state = normalizeLogsState(readQueryState(ctx.query, DEFAULT_STATE, QUERY_KEYS));
  const root = h("div", { "data-logs-workbench": "true" });
  try {
    await loadAndPaint(root);
  } catch (err) {
    paintLoadFailure(root, err);
  }
  return root;
}

async function loadAndPaint(root) {
  clear(root);
  root.appendChild(h("div", { class: "loading" }, "Loading system logs..."));
  const [logs, status] = await Promise.all([
    api.systemLogs(logRequest()),
    api.status().catch((e) => ({ engines: [], warnings: [{ severity: "warning", message: e.message || String(e) }] })),
  ]);
  paint(root, logs || {}, status || {});
}

function paintLoadFailure(root, err) {
  latestEntries = [];
  clear(root);
  const detail = err?.message || String(err || "System log API request failed.");
  root.appendChild(pageHead("System logs", "Log data unavailable",
    h("div", { class: "flex wrap" },
      h("button", { class: "btn", type: "button", title: "Retry loading system logs", "aria-label": "Retry loading system logs", "data-logs-action": "retry", onclick: () => loadAndPaint(root).catch((e) => paintLoadFailure(root, e)) }, h("span", { html: icon("refresh", 16) }), "Retry"),
      h("button", { class: "btn", type: "button", title: "Open system logs API and CLI context", "aria-label": "Open system logs API and CLI context", "data-logs-action": "api-cli", onclick: () => openAutomationContext(routePath) }, h("span", { html: icon("terminal", 16) }), "API / CLI"))));
  root.appendChild(h("div", { class: "alert-box bad", "data-logs-load-error": "true" },
    h("strong", {}, "System logs unavailable. "),
    detail));
  root.appendChild(emptyState("terminal", "No log data loaded", "Retry the bounded system-log request or use the API / CLI context to verify the appliance log source."));
}

function paint(root, logs, status) {
  latestEntries = logs.entries || [];
  clear(root);
  const summary = logs.summary || {};
  const engines = status.engines || [];
  const headline = `${latestEntries.length} matching event${latestEntries.length === 1 ? "" : "s"} · ${summary.scannedFiles || 0} files · ${summary.scannedLines || 0} lines scanned`;
  root.appendChild(pageHead("System logs", headline,
    h("div", { class: "flex wrap" },
      h("button", { class: "btn", type: "button", title: "Open system logs API and CLI context", "aria-label": "Open system logs API and CLI context", "data-logs-action": "api-cli", onclick: () => openAutomationContext(routePath) }, h("span", { html: icon("terminal", 16) }), "API / CLI"),
      h("button", { class: "btn", type: "button", title: "Refresh system logs", "aria-label": "Refresh system logs", "data-logs-action": "refresh", onclick: () => loadAndPaint(root) }, h("span", { html: icon("refresh", 16) }), "Refresh"))));

  root.appendChild(logPostureStrip(summary, engines));
  root.appendChild(filterBar(root));
  root.appendChild(evidenceToolbar({
    surface: "system-logs",
    title: "System log evidence",
    summary: evidenceSummary(summary),
    request: logRequest,
    rows: () => latestEntries,
    columns: LOG_COLUMNS,
    route: () => currentRoute(),
    apiPath: "/v1/system/logs",
    cliCommand: () => logsCliCommand(state),
    cliLabel: "Copy CLI",
  }));

  if (!latestEntries.length) {
    const empty = emptyState("terminal", "No matching log events", summary.warnings?.length ? summary.warnings.join(" ") : "Adjust filters or confirm the appliance log root is populated.");
    empty.dataset.logsEmptyState = "true";
    root.appendChild(empty);
    return;
  }
  root.appendChild(logTable(latestEntries));
  maybeOpenRoutedEntry();
}

function logPostureStrip(summary = {}, engines = []) {
  const blocked = engines.filter((e) => ["failed", "missing-prerequisites"].includes(e.state)).length;
  const degraded = engines.filter((e) => ["degraded", "stopped"].includes(e.state)).length;
  return h("div", { class: "metric-strip" },
    metric("Matched", String(summary.matchedLines || 0), summary.truncated ? "truncated by limit" : "complete within scan cap", summary.truncated ? "warn" : "ok"),
    metric("Sources", (summary.sources || []).join(", ") || "none", "from bounded log root", "info"),
    metric("Engines", (summary.engines || []).join(", ") || `${engines.length || 0} configured`, blocked ? `${blocked} blocked` : degraded ? `${degraded} degraded` : "no blocked engines", blocked ? "bad" : degraded ? "warn" : "ok"),
    metric("Warnings", String((summary.warnings || []).length), (summary.warnings || [])[0] || "log API returned without warnings", summary.warnings?.length ? "warn" : "ok"));
}

function metric(label, value, detail, tone = "neutral") {
  return h("div", { class: "metric-card" },
    h("span", {}, label),
    h("strong", {}, value),
    h("small", {}, detail),
    pill(toneLabel(tone), tone, true));
}

function filterBar(root) {
  const q = input("Search logs", state.q, (value) => updateState(root, { q: value }), "search", { "data-logs-filter": "query" });
  const source = select([
    ["", "All sources"], ["system", "System"], ["engine", "Engines"], ["dataplane", "Dataplane"], ["audit", "Audit"],
  ], state.source, (value) => updateState(root, { source: value }), { "data-logs-filter": "source" });
  const engine = select([
    ["", "All engines"], ["suricata", "IDS/IPS"], ["vector", "Telemetry"], ["frr", "Routing"], ["strongswan", "IPsec"], ["wireguard", "WireGuard"], ["nftables", "Packet filter"], ["routes", "Routes"], ["netdev", "Network device"],
  ], state.engine, (value) => updateState(root, { engine: value }), { "data-logs-filter": "engine" });
  const severity = select([
    ["", "All severities"], ["critical", "Critical"], ["error", "Error"], ["warn", "Warn"], ["notice", "Notice"], ["info", "Info"], ["debug", "Debug"],
  ], state.severity, (value) => updateState(root, { severity: value }), { "data-logs-filter": "severity" });
  const limit = select([["100", "100 rows"], ["200", "200 rows"], ["500", "500 rows"]], state.limit, (value) => updateState(root, { limit: value }), { "data-logs-filter": "limit" });
  return h("div", { class: "toolbar filters" },
    h("label", { class: "field" }, h("span", {}, "Query"), q),
    h("label", { class: "field" }, h("span", {}, "Source"), source),
    h("label", { class: "field" }, h("span", {}, "Engine"), engine),
    h("label", { class: "field" }, h("span", {}, "Severity"), severity),
    h("label", { class: "field" }, h("span", {}, "Since"), input("RFC3339", state.since, (value) => updateState(root, { since: value }), "datetime-local", { "data-logs-filter": "since" })),
    h("label", { class: "field" }, h("span", {}, "Until"), input("RFC3339", state.until, (value) => updateState(root, { until: value }), "datetime-local", { "data-logs-filter": "until" })),
    h("label", { class: "field" }, h("span", {}, "Limit"), limit),
    ...savedFilterControls({ scope: "system-logs", state, defaults: DEFAULT_STATE, keys: SAVED_FILTER_KEYS, onApply: async (next) => { state = normalizeLogsState(next); syncRoute(); await loadAndPaint(root); } }),
    h("button", { class: "btn ghost", type: "button", title: "Clear system log filters", "aria-label": "Clear system log filters", "data-logs-action": "clear", onclick: () => { state = { ...DEFAULT_STATE }; syncRoute(); loadAndPaint(root); } }, h("span", { html: icon("x", 16) }), "Clear"));
}

function logTable(entries) {
  return h("div", { class: "table-wrap system-log-table-wrap" },
      responsiveTable([
        { label: "Time", attrs: { class: "system-log-time-col" } },
        { label: "Source", attrs: { class: "system-log-source-col" } },
        { label: "Engine", attrs: { class: "system-log-engine-col" } },
        { label: "Severity", attrs: { class: "system-log-severity-col" } },
        { label: "Message", attrs: { class: "system-log-message-col" } },
        { label: "File", attrs: { class: "system-log-file-col" } },
      ], entries.slice(0, 500).map((entry) => {
        const attrs = keyboardRowAttrs(() => openLogEntry(entry), { label: `Open log entry ${entry.id || entry.message || ""}` });
        return h("tr", {
          ...attrs,
          "data-system-log-row": "true",
          "data-log-entry-id": entry.id || "",
          "data-log-source": entry.source || "system",
          "data-log-engine": entry.engine || "node",
          "data-log-severity": entry.severity || "info",
        },
          labeledCell("Time", { class: "mono muted data-clip" }, compactTime(entry.timestamp)),
          labeledCell("Source", { class: "data-clip" }, entry.source || "system"),
          labeledCell("Engine", { class: "data-clip" }, entry.engine || "node"),
          labeledCell("Severity", {}, pill(entry.severity || "info", severityTone(entry.severity), true)),
          labeledCell("Message", { class: "system-log-message-cell" }, h("code", {}, truncate(entry.message || "", 220))),
          labeledCell("File", { class: "system-log-file-cell" }, h("span", { class: "mono" }, entry.file || "-")));
      }), { className: "system-log-table" }));
}

function openLogEntry(entry) {
  state.entry = entry.id || "";
  syncRoute();
  const packet = systemLogHandoffPacket(entry);
  const context = deriveLogPivotContext(entry);
  openDrawer({
    title: entry.severity ? `${entry.severity.toUpperCase()} log event` : "Log event",
    subtitle: [entry.source || "system", entry.engine || "", entry.timestamp || ""].filter(Boolean).join(" · "),
    width: "720px",
    onClose: () => { state.entry = ""; syncRoute(); },
    body: h("div", { "data-system-log-drawer": "true" },
      h("div", { class: "kv" },
        kv("Source", entry.source || "system"),
        kv("Engine", entry.engine || "node"),
        kv("Severity", entry.severity || "info"),
        kv("Facility", entry.facility || "-"),
        kv("File", entry.file || "-"),
        kv("Line", String(entry.line || "")),
        kv("Timestamp", entry.timestamp || "unavailable")),
      h("h3", {}, "Message"),
      h("pre", { class: "code-block" }, entry.message || ""),
      logDerivedContext(context),
      logCapturePlanPanel(context),
      h("h3", {}, "Pivots"),
      h("div", { class: "flex wrap" }, ...logPivots(entry, context))),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Copy system log handoff packet", "aria-label": "Copy system log handoff packet", "data-log-action": "copy-packet", onclick: () => copyText(investigationPacketText(packet), "Log packet copied", "Plain-text handoff copied.") }, h("span", { html: icon("copy", 16) }), "Copy packet"),
      h("button", { class: "btn ghost", type: "button", title: "Export system log handoff JSON", "aria-label": "Export system log handoff JSON", "data-log-action": "export-json", onclick: () => exportPacket(packet) }, h("span", { html: icon("download", 16) }), "Export JSON"),
      h("button", { class: "btn primary", type: "button", title: "Pin system log handoff to investigation case", "aria-label": "Pin system log handoff to investigation case", "data-log-action": "pin-case", onclick: () => pinPacket(packet) }, h("span", { html: icon("inbox", 16) }), "Pin to case"),
      h("a", { class: "btn ghost", href: activeInvestigationServerCaseHref(), title: "Open active investigation case", "aria-label": "Open active investigation case", "data-log-action": "open-active-case" }, h("span", { html: icon("search", 16) }), "Open active case"),
      h("button", { class: "btn ghost", type: "button", title: "Close system log drawer", "aria-label": "Close system log drawer", "data-log-action": "close", onclick: closeDrawer }, "Close"),
    ],
  });
}

function logPivots(entry, context = deriveLogPivotContext(entry)) {
  const lower = String(entry.message || "").toLowerCase();
  const pivots = [];
  if (entry.source === "audit" || lower.includes("audit") || lower.includes("commit") || lower.includes("rollback")) {
    pivots.push(h("a", { class: "btn sm", href: "#/changes?tab=audit", title: "Pivot to audit log", "aria-label": "Pivot to audit log", "data-log-pivot": "audit" }, h("span", { html: icon("changes", 14) }), "Audit"));
  }
  if (entry.engine === "ids-ips" || lower.includes("alert") || lower.includes("signature")) {
    pivots.push(h("a", { class: "btn sm", href: context.threatsHash || "#/threats", title: "Pivot to threats workbench", "aria-label": "Pivot to threats workbench", "data-log-pivot": "threats" }, h("span", { html: icon("threats", 14) }), "Threats"));
  }
  if (lower.includes("flow") || lower.includes("conntrack") || lower.includes("session") || context.hasTrafficContext) {
    pivots.push(h("a", { class: "btn sm", href: context.trafficHash || "#/traffic", title: "Pivot to traffic workbench", "aria-label": "Pivot to traffic workbench", "data-log-pivot": "traffic" }, h("span", { html: icon("traffic", 14) }), "Traffic"));
  }
  if (context.troubleshootHash) {
    pivots.push(h("a", { class: "btn sm", href: context.troubleshootHash, title: "Pivot to troubleshooting", "aria-label": "Pivot to troubleshooting", "data-log-pivot": "troubleshoot" }, h("span", { html: icon("search", 14) }), "Troubleshoot"));
  }
  if (context.capturePlanHash) {
    pivots.push(h("a", { class: "btn sm", href: context.capturePlanHash, title: "Open bounded packet-capture plan in Troubleshoot", "aria-label": "Open bounded packet-capture plan in Troubleshoot", "data-log-pivot": "capture-plan" }, h("span", { html: icon("download", 14) }), "Plan capture"));
  }
  pivots.push(h("a", { class: "btn sm", href: "#/investigation", title: "Pivot to investigation case", "aria-label": "Pivot to investigation case", "data-log-pivot": "investigation" }, h("span", { html: icon("inbox", 14) }), "Investigation"));
  return pivots;
}

function logDerivedContext(context = {}) {
  if (!context.hasDerivedContext) return h("div", { class: "note", "data-log-derived-context": "none" }, "No flow tuple or threat id was detected in this log line.");
  const rows = [
    ["Flow", context.flowId],
    ["Source", endpointText(context.srcIp, context.srcPort)],
    ["Destination", endpointText(context.destIp, context.destPort)],
    ["Protocol", context.protocol],
    ["App", context.appId],
    ["Signature", context.signatureId],
  ].filter(([, value]) => value);
  return h("div", { class: "callout", "data-log-derived-context": "true" },
    h("strong", {}, "Derived context"),
    h("div", { class: "kv compact" }, ...rows.map(([key, value]) => kv(key, value))));
}

function logCapturePlanPanel(context = {}) {
  const capture = context.capturePlan;
  if (!capture) {
    return h("div", { class: "note", "data-log-capture-plan": "none" }, "Packet-capture planning needs both source and destination IP context.");
  }
  return h("div", { class: "callout", "data-log-capture-plan": "true" },
    h("strong", {}, "Bounded packet-capture plan"),
    h("div", { class: "kv compact" },
      kv("Scope", `${endpointText(capture.srcIp, capture.srcPort)} -> ${endpointText(capture.destIp, capture.destPort)}`),
      kv("Filter", capture.filter),
      kv("Limits", `${capture.durationSeconds}s, ${capture.packetCount} packets, ${capture.snaplenBytes} byte snaplen`),
      kv("Interface", capture.interface),
      kv("Execution", "plan only; start capture remains explicit in Troubleshoot")),
    capture.warnings?.length ? h("ol", { class: "trace-list compact-list" }, capture.warnings.map((warning) => h("li", {}, warning))) : null,
    h("div", { class: "flex wrap" },
      h("a", { class: "btn sm", href: context.capturePlanHash, title: "Open bounded packet-capture plan in Troubleshoot", "aria-label": "Open bounded packet-capture plan in Troubleshoot", "data-log-action": "open-capture-plan" }, h("span", { html: icon("download", 14) }), "Open plan"),
      h("button", { class: "btn sm ghost", type: "button", title: "Copy log-derived packet-capture plan handoff", "aria-label": "Copy log-derived packet-capture plan handoff", "data-log-action": "copy-capture-plan", onclick: () => copyText(logCapturePlanText(context), "Capture plan copied", "Troubleshoot capture-plan handoff copied.") }, h("span", { html: icon("copy", 14) }), "Copy handoff")));
}

export function deriveLogPivotContext(entry = {}) {
  const text = `${entry.message || ""} ${entry.raw || ""}`;
  const srcIp = firstValue(entry.srcIp, entry.src_ip, keyedValue(text, ["src_ip", "srcIp", "src", "source_ip", "sourceIp"]));
  const destIp = firstValue(entry.destIp, entry.dest_ip, entry.dstIp, keyedValue(text, ["dest_ip", "destIp", "dst_ip", "dstIp", "dst", "destination_ip", "destinationIp"]));
  const srcPort = portValue(firstValue(entry.srcPort, entry.src_port, keyedValue(text, ["src_port", "srcPort", "sport", "source_port", "sourcePort"])));
  const destPort = portValue(firstValue(entry.destPort, entry.dest_port, entry.dstPort, keyedValue(text, ["dest_port", "destPort", "dport", "dst_port", "dstPort", "destination_port", "destinationPort"])));
  const protocol = normalizeLogProtocol(firstValue(entry.protocol, entry.proto, keyedValue(text, ["protocol", "proto"])));
  const flowId = cleanRouteToken(firstValue(entry.flowId, entry.flow_id, keyedValue(text, ["flow_id", "flowId", "flow"])), 128);
  const appId = cleanRouteToken(firstValue(entry.appId, entry.app_id, entry.app_proto, keyedValue(text, ["app_id", "appId", "app_proto", "appProto", "app"])), 96);
  const signatureId = cleanRouteToken(firstValue(entry.signatureId, entry.signature_id, entry.sid, keyedValue(text, ["signature_id", "signatureId", "sid"])), 64);
  const arrowTuple = parseArrowTuple(text);
  const tuple = {
    srcIp: srcIp || arrowTuple.srcIp,
    srcPort: srcPort || arrowTuple.srcPort,
    destIp: destIp || arrowTuple.destIp,
    destPort: destPort || arrowTuple.destPort,
    protocol: protocol || normalizeLogProtocol(arrowTuple.protocol),
    flowId,
    appId,
    signatureId,
  };
  const hasTuple = Boolean(tuple.srcIp || tuple.destIp || tuple.srcPort || tuple.destPort || tuple.protocol);
  const hasTrafficContext = Boolean(hasTuple || tuple.flowId || tuple.appId);
  const hasThreatContext = Boolean(tuple.signatureId || entry.engine === "ids-ips" || String(entry.message || "").toLowerCase().includes("signature"));
  const captureContext = logCapturePlanContext(tuple);
  return {
    ...tuple,
    hasDerivedContext: Boolean(hasTrafficContext || tuple.signatureId),
    hasTrafficContext,
    trafficHash: hasTrafficContext ? hashWithParams("#/traffic", {
      mode: "flows",
      ip: tuple.srcIp || tuple.destIp,
      protocol: trafficProtocol(tuple.protocol),
      port: tuple.destPort,
      app: tuple.appId,
      flowId: tuple.flowId,
      limit: "100",
    }) : "",
    threatsHash: hasThreatContext ? hashWithParams("#/threats", {
      signatureId: tuple.signatureId,
      ip: tuple.srcIp || tuple.destIp,
      protocol: trafficProtocol(tuple.protocol),
      port: tuple.destPort,
      flowId: tuple.flowId,
      limit: "100",
    }) : "",
    troubleshootHash: tuple.srcIp && tuple.destIp ? hashWithParams("#/troubleshoot", {
      source: "POLICY_SOURCE_RUNNING",
      src: tuple.srcIp,
      sport: tuple.srcPort,
      dst: tuple.destIp,
      dport: tuple.destPort,
      protocol: troubleshootProtocol(tuple.protocol),
      app: tuple.appId,
      flowId: tuple.flowId,
      runtime: "1",
    }) : "",
    capturePlan: captureContext?.plan || null,
    capturePlanHash: captureContext?.hash || "",
  };
}

export function logCapturePlanContext(tuple = {}) {
  if (!tuple.srcIp || !tuple.destIp) return null;
  const plan = buildCapturePlan({
    interface: LOG_CAPTURE_DEFAULTS.interface,
    protocol: tuple.protocol || "ip",
    srcIp: tuple.srcIp,
    srcPort: tuple.srcPort,
    destIp: tuple.destIp,
    destPort: tuple.destPort,
    flowId: tuple.flowId,
    durationSeconds: LOG_CAPTURE_DEFAULTS.durationSeconds,
    packetCount: LOG_CAPTURE_DEFAULTS.packetCount,
    snaplenBytes: LOG_CAPTURE_DEFAULTS.snaplenBytes,
    label: tuple.flowId ? `log-${tuple.flowId}` : "log-tuple",
  });
  return {
    plan,
    hash: hashWithParams("#/troubleshoot", {
      source: "POLICY_SOURCE_RUNNING",
      src: tuple.srcIp,
      sport: tuple.srcPort,
      dst: tuple.destIp,
      dport: tuple.destPort,
      protocol: troubleshootProtocol(tuple.protocol),
      app: tuple.appId,
      flowId: tuple.flowId,
      runtime: "1",
      run: "1",
      intent: "capture",
      captureContext: "log-plan",
      captureInterface: plan.interface,
      captureDuration: String(plan.durationSeconds),
      capturePackets: String(plan.packetCount),
      captureSnaplen: String(plan.snaplenBytes),
    }),
  };
}

function maybeOpenRoutedEntry() {
  if (!state.entry) return;
  const entry = latestEntries.find((item) => item.id === state.entry);
  if (entry) setTimeout(() => openLogEntry(entry), 0);
}

export function systemLogHandoffPacket(entry = {}, opts = {}) {
  const context = deriveLogPivotContext(entry);
  const safeMessage = redactLogHandoffText(entry.message || "System log event");
  const safeFile = redactLogHandoffText(entry.file || "");
  const packet = buildInvestigationPacket({
    kind: "system-log",
    title: `System log ${entry.severity || "event"}`,
    subject: {
      type: "system-log",
      label: `${entry.source || "system"} ${entry.severity || "event"}`,
      id: entry.id || "",
      engine: entry.engine || "",
      tuple: context.hasTrafficContext ? {
        flowId: context.flowId,
        srcIp: context.srcIp,
        srcPort: context.srcPort,
        destIp: context.destIp,
        destPort: context.destPort,
        protocol: context.protocol,
        appId: context.appId,
      } : undefined,
    },
    summary: {
      message: safeMessage,
      source: entry.source || "system",
      engine: entry.engine || "node",
      severity: entry.severity || "info",
      timestamp: entry.timestamp || "",
      flowId: context.flowId,
      srcIp: context.srcIp,
      srcPort: context.srcPort,
      destIp: context.destIp,
      destPort: context.destPort,
      protocol: context.protocol,
      appId: context.appId,
      signatureId: context.signatureId,
    },
    artifacts: {
      log: {
        id: entry.id || "",
        timestamp: entry.timestamp || "",
        source: entry.source || "",
        engine: entry.engine || "",
        severity: entry.severity || "",
        facility: entry.facility || "",
        file: safeFile,
        line: entry.line || 0,
        message: safeMessage,
      },
      logContext: {
        flowId: context.flowId,
        srcIp: context.srcIp,
        srcPort: context.srcPort,
        destIp: context.destIp,
        destPort: context.destPort,
        protocol: context.protocol,
        appId: context.appId,
        signatureId: context.signatureId,
        trafficHash: context.trafficHash,
        threatsHash: context.threatsHash,
        troubleshootHash: context.troubleshootHash,
        capturePlanHash: context.capturePlanHash,
      },
      operatorWorkflow: {
        custodyBoundary: "browser-local handoff only; no capture execution, log retention change, or server-side case record is created here",
        trafficRoute: context.trafficHash,
        threatsRoute: context.threatsHash,
        troubleshootRoute: context.troubleshootHash,
        capturePlanRoute: context.capturePlanHash,
        candidateBoundary: "Logs can only hand off context; candidate policy changes still require the owning Traffic, Threats, Rules, or Changes workflow.",
      },
      capturePlan: context.capturePlan ? {
        interface: context.capturePlan.interface,
        protocol: context.capturePlan.protocol,
        srcIp: context.capturePlan.srcIp,
        srcPort: context.capturePlan.srcPort,
        destIp: context.capturePlan.destIp,
        destPort: context.capturePlan.destPort,
        flowId: context.capturePlan.flowId,
        filter: context.capturePlan.filter,
        durationSeconds: context.capturePlan.durationSeconds,
        packetCount: context.capturePlan.packetCount,
        snaplenBytes: context.capturePlan.snaplenBytes,
        warnings: context.capturePlan.warnings || [],
        route: context.capturePlanHash,
        workflow: "plan-only troubleshoot handoff; does not start capture",
      } : undefined,
      flow: context.hasTrafficContext ? {
        flowId: context.flowId,
        srcIp: context.srcIp,
        srcPort: context.srcPort,
        destIp: context.destIp,
        destPort: context.destPort,
        protocol: context.protocol,
        appId: context.appId,
      } : undefined,
      alert: context.signatureId ? {
        flowId: context.flowId,
        srcIp: context.srcIp,
        srcPort: context.srcPort,
        destIp: context.destIp,
        destPort: context.destPort,
        protocol: context.protocol,
        appId: context.appId,
        signatureId: context.signatureId,
      } : undefined,
    },
    evidence: [
      `source=${entry.source || "system"}`,
      `engine=${entry.engine || "node"}`,
      `severity=${entry.severity || "info"}`,
      `file=${safeFile || "unknown"}`,
      `line=${entry.line || 0}`,
      context.flowId ? `flow_id=${context.flowId}` : "",
      context.srcIp && context.destIp ? `tuple=${endpointText(context.srcIp, context.srcPort)} -> ${endpointText(context.destIp, context.destPort)}` : "",
      context.signatureId ? `signature_id=${context.signatureId}` : "",
      context.capturePlanHash ? `capture_plan_route=${context.capturePlanHash}` : "",
      "workflow_boundary=browser-local handoff; explicit Troubleshoot capture and candidate review remain required",
    ],
  }, { route: opts.route || currentRoute() });
  return logWorkflowPacket(packet);
}

export function logCaseFocusRoute(packet = {}, action = "log-capture-plan") {
  const key = caseItemKey(packet);
  const q = new URLSearchParams();
  q.set("caseKey", key);
  q.set("caseAction", action);
  q.set("caseKind", packet.kind || "system-log");
  return "#/investigation?" + q.toString();
}

export function logWorkflowPacket(packet = {}) {
  const caseFocusRoute = logCaseFocusRoute(packet, packet.artifacts?.capturePlan ? "log-capture-plan" : "log-review");
  return {
    ...packet,
    summary: {
      ...(packet.summary || {}),
      operatorWorkflow: {
        trafficRoute: packet.artifacts?.logContext?.trafficHash || "",
        threatsRoute: packet.artifacts?.logContext?.threatsHash || "",
        troubleshootRoute: packet.artifacts?.logContext?.troubleshootHash || "",
        capturePlanRoute: packet.artifacts?.logContext?.capturePlanHash || "",
        caseFocusRoute,
        custodyBoundary: "browser-local handoff only; no capture execution, log retention change, or server-side case record is created here",
      },
    },
    evidence: [
      ...((packet.evidence || []).filter(Boolean)),
      `case_focus_route=${caseFocusRoute}`,
    ],
    artifacts: {
      ...(packet.artifacts || {}),
      logContext: {
        ...(packet.artifacts?.logContext || {}),
        caseFocusRoute,
      },
      operatorWorkflow: {
        ...(packet.artifacts?.operatorWorkflow || {}),
        caseFocusRoute,
      },
    },
  };
}

function logCapturePlanText(context = {}) {
  const plan = context.capturePlan || {};
  return [
    "Phragma log-derived packet-capture plan",
    `route=${context.capturePlanHash || ""}`,
    `scope=${endpointText(plan.srcIp, plan.srcPort)} -> ${endpointText(plan.destIp, plan.destPort)}`,
    `protocol=${plan.protocol || "ip"}`,
    `interface=${plan.interface || CAPTURE_LIMITS.defaultInterface}`,
    `filter=${plan.filter || ""}`,
    `limits=${plan.durationSeconds || CAPTURE_LIMITS.defaultDurationSeconds}s ${plan.packetCount || CAPTURE_LIMITS.defaultPacketCount} packets ${plan.snaplenBytes || CAPTURE_LIMITS.defaultSnaplenBytes} byte snaplen`,
    "execution=plan-only; open Troubleshoot to review server plan before any explicit Start capture action",
  ].join("\n");
}

function logRequest() {
  return {
    limit: state.limit,
    source: state.source,
    engine: state.engine,
    severity: state.severity,
    query: state.q,
    since: htmlDateTimeToRFC3339(state.since),
    until: htmlDateTimeToRFC3339(state.until),
  };
}

function logsCliCommand(s = state) {
  return cliCommand("ngfwctl system logs", [
    ["--limit", s.limit],
    ["--source", s.source],
    ["--engine", s.engine],
    ["--severity", s.severity],
    ["--query", s.q],
    ["--since", htmlDateTimeToRFC3339(s.since)],
    ["--until", htmlDateTimeToRFC3339(s.until)],
  ]);
}

function normalizeLogsState(raw = {}) {
  const next = { ...DEFAULT_STATE, ...raw };
  next.limit = ["100", "200", "500"].includes(String(next.limit)) ? String(next.limit) : DEFAULT_STATE.limit;
  next.source = ["", "system", "engine", "dataplane", "audit"].includes(next.source) ? next.source : "";
  next.severity = ["", "critical", "error", "warn", "notice", "info", "debug"].includes(next.severity) ? next.severity : "";
  next.engine = String(next.engine || "").trim().toLowerCase().replace(/[^a-z0-9_-]+/g, "").slice(0, 32);
  next.q = String(next.q || "").slice(0, 160);
  next.since = normalizeDateInput(next.since);
  next.until = normalizeDateInput(next.until);
  next.entry = String(next.entry || "").replace(/[^a-f0-9]/gi, "").slice(0, 32);
  return next;
}

function updateState(root, patch) {
  state = normalizeLogsState({ ...state, ...patch, entry: "" });
  syncRoute();
  loadAndPaint(root);
}

function syncRoute() {
  writeQueryState(routePath, state, DEFAULT_STATE, QUERY_KEYS);
}

function currentRoute() {
  return typeof location === "undefined" ? "#/logs" : location.hash || "#/logs";
}

function input(placeholder, value, onChange, type = "search", attrs = {}) {
  return h("input", { class: "input", type, placeholder, value, ...attrs, oninput: (e) => onChange(e.target.value) });
}

function select(options, value, onChange, attrs = {}) {
  const el = h("select", { class: "input", ...attrs, onchange: (e) => onChange(e.target.value) },
    ...options.map(([v, label]) => h("option", { value: v }, label)));
  el.value = value;
  return el;
}

function kv(key, value) {
  return h("div", {}, h("span", {}, key), h("strong", {}, value || "-"));
}

function endpointText(ip, port) {
  if (!ip) return "";
  return port ? `${ip}:${port}` : ip;
}

function compactTime(value) {
  if (!value) return "-";
  return String(value).replace("T", " ").replace(/\.\d+Z$/, "Z");
}

function truncate(value, max) {
  const text = String(value || "");
  return text.length > max ? text.slice(0, max - 1) + "..." : text;
}

function severityTone(severity) {
  switch (severity) {
    case "critical": return "bad";
    case "error": return "bad";
    case "warn": return "warn";
    case "notice": return "change";
    case "debug": return "neutral";
    default: return "info";
  }
}

function toneLabel(tone) {
  if (tone === "ok") return "ready";
  if (tone === "bad") return "blocked";
  return tone;
}

function evidenceSummary(summary = {}) {
  const parts = [];
  if (summary.truncated) parts.push("truncated");
  if (summary.sources?.length) parts.push(`sources ${summary.sources.join("/")}`);
  if (summary.severities?.length) parts.push(`severity ${summary.severities.join("/")}`);
  if (summary.warnings?.length) parts.push(`${summary.warnings.length} warning${summary.warnings.length === 1 ? "" : "s"}`);
  return parts.join(" · ");
}

function normalizeDateInput(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(text)) return text.slice(0, 16);
  return text;
}

function htmlDateTimeToRFC3339(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(text)) return `${text}:00Z`;
  return text;
}

function firstValue(...values) {
  for (const value of values) {
    const text = String(value ?? "").trim();
    if (text) return text;
  }
  return "";
}

function keyedValue(text, keys = []) {
  for (const key of keys) {
    const re = new RegExp(`(?:^|[\\s,{])${escapeRegExp(key)}\\s*[:=]\\s*"?([^"\\s,;}]+)`, "i");
    const match = String(text || "").match(re);
    if (match?.[1]) return match[1];
  }
  return "";
}

function parseArrowTuple(text) {
  const match = String(text || "").match(/(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?\s*(?:->|to)\s*(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?/i);
  if (!match) return {};
  return {
    srcIp: match[1],
    srcPort: portValue(match[2]),
    destIp: match[3],
    destPort: portValue(match[4]),
  };
}

function normalizeLogProtocol(value) {
  const text = String(value || "").trim().toUpperCase().replace(/^PROTOCOL_/, "");
  if (["TCP", "UDP", "ICMP"].includes(text)) return text;
  return "";
}

function trafficProtocol(protocol) {
  return ["TCP", "UDP", "ICMP"].includes(protocol) ? protocol : "";
}

function troubleshootProtocol(protocol) {
  return ["TCP", "UDP", "ICMP"].includes(protocol) ? `PROTOCOL_${protocol}` : "";
}

function portValue(value) {
  const text = String(value || "").trim();
  if (!/^\d{1,5}$/.test(text)) return "";
  const num = Number(text);
  return num >= 1 && num <= 65535 ? String(num) : "";
}

function cleanRouteToken(value, max = 128) {
  return String(value || "").trim().replace(/[^\w.:-]+/g, "").slice(0, max);
}

function redactLogHandoffText(value = "") {
  return String(value || "")
    .replace(/(Authorization:\s*Bearer\s+)(?!\[redacted\])["']?[^"'\s,;}]+["']?/gi, "$1[redacted]")
    .replace(/\bBearer\s+(?!\[redacted\])[A-Za-z0-9._~+/-]{8,}/gi, "Bearer [redacted]")
    .replace(/(^|[?&\s"',;])((?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|passwd|secret|client[_-]?secret|api[_-]?key|api[_-]?access[_-]?key|access[_-]?key|cookie)=)[^&\s"',;]+/gi, "$1$2[redacted]")
    .replace(/(^|[\s"',;{])((?:access[_-]?token|refresh[_-]?token|id[_-]?token|password|passwd|secret|client[_-]?secret|api[_-]?key|api[_-]?access[_-]?key|access[_-]?key|cookie)\s*:\s*)[^\s"',;]+/gi, "$1$2[redacted]")
    .replace(/(^|[\s"'({=,;])\/(?:var\/lib|var\/log(?:\/openngfw)?|etc\/(?:openngfw|phragma)|tmp|private\/tmp|var\/folders|private\/var\/folders|home\/[^'"\s,;}]+|Users\/[^'"\s,;}]+|opt\/[^'"\s,;}]+|data\/[^'"\s,;}]+)[^'"\s,;}]*/gi, "$1[server-local path redacted]");
}

function hashWithParams(hash, params = {}) {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    const text = String(value || "").trim();
    if (text) q.set(key, text);
  }
  const query = q.toString();
  return query ? `${hash}?${query}` : hash;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function copyText(text, title, body) {
  try {
    await navigator.clipboard.writeText(text);
    toast(title, body, "ok");
  } catch {
    toast("Copy failed", "Use Export JSON for a durable packet.", "warn");
  }
}

function exportPacket(packet) {
  const text = investigationPacketJson(packet);
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: investigationPacketFilename(packet) });
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  toast("Log packet exported", "Investigation JSON downloaded.", "ok");
}

async function pinPacket(packet) {
  try {
    const serverResult = await appendInvestigationPacketToActiveServerCase(packet, {
      appendEvidence: (id, evidence) => api.addInvestigationCaseEvidence(id, evidence),
    });
    if (serverResult.appended) {
      toast("Evidence appended", `System log evidence appended to ${serverResult.activeCaseId}.`, "ok");
      return;
    }
  } catch (e) {
    try {
      const result = pinInvestigationPacket(packet);
      toast("Server append unavailable", `${result.toastDetail} Local fallback was used.`, "warn");
    } catch (fallbackError) {
      toast("Pin failed", fallbackError.message || "Selected log evidence could not be pinned.", "bad");
    }
    return;
  }
  try {
    const result = pinInvestigationPacket(packet);
    toast("Pinned to investigation", result.replaced ? "Existing log evidence was refreshed." : "Log evidence is available in the Investigation workbench.", "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Selected log evidence could not be pinned.", "bad");
  }
}
