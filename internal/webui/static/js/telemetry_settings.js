// telemetry_settings.js - pure helpers for the Settings telemetry editor.
// Policy uses proto JSON names, so clickhouse_url appears as clickhouseUrl.

export const DEFAULT_CLICKHOUSE_URL = "http://127.0.0.1:8123";
export const DEFAULT_TELEMETRY_DATABASE = "openngfw";
export const DEFAULT_JSON_EXPORT_PATH = "/var/log/openngfw/exports/eve-%Y-%m-%d.json";
export const DEFAULT_JSON_STREAM_TARGET = "127.0.0.1:5514";
export const TELEMETRY_EXPORT_TYPE_JSON_FILE = "TELEMETRY_EXPORT_TYPE_JSON_FILE";
export const TELEMETRY_EXPORT_TYPE_JSON_TCP = "TELEMETRY_EXPORT_TYPE_JSON_TCP";
export const TELEMETRY_EXPORT_TYPE_JSON_UDP = "TELEMETRY_EXPORT_TYPE_JSON_UDP";
export const TELEMETRY_EVIDENCE_SCHEMA = "phragma.telemetry.evidence.v1";
export const TELEMETRY_RECEIVER_PROOF_SCHEMA = "phragma.telemetry.receiver-proof.v1";

const DATABASE_RE = /^[a-z][a-z0-9_]{0,63}$/;
const CLICKHOUSE_SYSTEM_DATABASES = new Set(["system", "information_schema"]);
const READY_ENGINE_STATES = new Set(["ready", "active"]);
const BAD_ENGINE_STATES = new Set(["failed", "missing-prerequisites", "degraded"]);

export function telemetryFromInputs(inputs = {}) {
  const { enabled = false, clickhouseUrl = "", database = "" } = inputs;
  if (!enabled) return undefined;
  const telemetry = {
    enabled: true,
    clickhouseUrl: String(clickhouseUrl || "").trim() || DEFAULT_CLICKHOUSE_URL,
    database: String(database || "").trim() || DEFAULT_TELEMETRY_DATABASE,
  };
  const exports = telemetryExportsFromInputs(inputs);
  if (exports.length) telemetry.exports = exports;
  return telemetry;
}

export function validateTelemetryInputs(inputs = {}) {
  const { enabled = false, clickhouseUrl = "", database = "" } = inputs;
  if (!enabled) return [];
  const issues = [];
  const url = String(clickhouseUrl || "").trim() || DEFAULT_CLICKHOUSE_URL;
  const db = String(database || "").trim() || DEFAULT_TELEMETRY_DATABASE;
  if (/[\s\u0000-\u001f\u007f]/.test(url)) {
    issues.push("ClickHouse endpoint must not contain whitespace or control characters.");
  }
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      issues.push("ClickHouse endpoint must use http:// or https://.");
    }
    if (!parsed.hostname) {
      issues.push("ClickHouse endpoint must include a host.");
    }
    if (parsed.username || parsed.password) {
      issues.push("ClickHouse endpoint must not include URL userinfo.");
    }
    if (parsed.pathname && parsed.pathname !== "/") {
      issues.push("ClickHouse endpoint must not include a path; use the HTTP origin only.");
    }
    if (parsed.hash) {
      issues.push("ClickHouse endpoint must not include a URL fragment.");
    }
    for (const key of clickhouseQueryKeys(parsed.search)) {
      if (sensitiveClickhouseQueryKey(key)) {
        issues.push(`ClickHouse endpoint must not include sensitive query parameter "${key}".`);
      } else if (clickhouseControlQueryKey(key)) {
        issues.push(`ClickHouse endpoint must not include ClickHouse control query parameter "${key}".`);
      }
    }
  } catch {
    issues.push("ClickHouse endpoint must be a valid URL.");
  }
  if (!DATABASE_RE.test(db)) {
    issues.push("Database must start with a lowercase letter and use only lowercase letters, numbers, or underscores (max 64).");
  } else if (CLICKHOUSE_SYSTEM_DATABASES.has(db)) {
    issues.push(`Database must not target ClickHouse system database "${db}".`);
  }
  if (inputs.jsonFileEnabled) {
    issues.push(...validateJSONFileTarget(inputs.jsonFilePath || DEFAULT_JSON_EXPORT_PATH));
  }
  if (inputs.jsonStreamEnabled) {
    issues.push(...validateJSONStreamTarget(inputs.jsonStreamTarget || DEFAULT_JSON_STREAM_TARGET, inputs.jsonStreamProtocol || "tcp"));
  }
  return issues;
}

export function comparableTelemetry(telemetry = {}) {
  if (!telemetry || !telemetry.enabled) return { enabled: false };
  return {
    enabled: true,
    clickhouseUrl: telemetry.clickhouseUrl || DEFAULT_CLICKHOUSE_URL,
    database: telemetry.database || DEFAULT_TELEMETRY_DATABASE,
    exports: comparableTelemetryExports(telemetry.exports),
  };
}

export function telemetryExportSettings(exports = []) {
  const enabled = Array.isArray(exports) ? exports.filter((item) => item?.enabled) : [];
  const file = enabled.find((item) => item.type === TELEMETRY_EXPORT_TYPE_JSON_FILE);
  const stream = enabled.find((item) => item.type === TELEMETRY_EXPORT_TYPE_JSON_TCP || item.type === TELEMETRY_EXPORT_TYPE_JSON_UDP);
  return {
    jsonFileEnabled: Boolean(file),
    jsonFilePath: file?.target || DEFAULT_JSON_EXPORT_PATH,
    jsonStreamEnabled: Boolean(stream),
    jsonStreamTarget: stream?.target || DEFAULT_JSON_STREAM_TARGET,
    jsonStreamProtocol: stream?.type === TELEMETRY_EXPORT_TYPE_JSON_UDP ? "udp" : "tcp",
  };
}

export function telemetryExportsFromInputs({
  jsonFileEnabled = false,
  jsonFilePath = "",
  jsonStreamEnabled = false,
  jsonStreamTarget = "",
  jsonStreamProtocol = "tcp",
} = {}) {
  const exports = [];
  if (jsonFileEnabled) {
    exports.push({
      name: "local-json",
      enabled: true,
      type: TELEMETRY_EXPORT_TYPE_JSON_FILE,
      target: String(jsonFilePath || "").trim() || DEFAULT_JSON_EXPORT_PATH,
    });
  }
  if (jsonStreamEnabled) {
    exports.push({
      name: "siem-json",
      enabled: true,
      type: String(jsonStreamProtocol || "").toLowerCase() === "udp" ? TELEMETRY_EXPORT_TYPE_JSON_UDP : TELEMETRY_EXPORT_TYPE_JSON_TCP,
      target: String(jsonStreamTarget || "").trim() || DEFAULT_JSON_STREAM_TARGET,
    });
  }
  return exports;
}

export function telemetryEngine(status = {}) {
  return (status.engines || []).find((engine) => engine.name === "vector") || null;
}

export function telemetryReadinessModel({ status = {}, telemetry = undefined, dirty = false, exportStatus = null } = {}) {
  const active = Boolean(telemetry?.enabled);
  const comparable = comparableTelemetry(telemetry);
  const exportSettings = telemetryExportSettings(comparable.exports);
  const passiveStatus = telemetryPassiveStatus(exportStatus, { active, dirty });
  const engine = telemetryEngine(status);
  const passiveVector = passiveStatus?.vector || null;
  const engineState = passiveVector?.state || engine?.state || "unknown";
  const engineTone = telemetryEngineTone(engineState);
  const tone = active ? (engineTone === "bad" ? "bad" : passiveStatus ? "warn" : "warn") : "neutral";
  const database = active ? comparable.database : "none";
  const endpoint = active ? comparable.clickhouseUrl : "disabled";
  const configuredExports = Number(exportSettings.jsonFileEnabled) + Number(exportSettings.jsonStreamEnabled);
  const pipelineLabel = active ? `Vector -> ClickHouse${configuredExports ? ` + ${configuredExports} export${configuredExports === 1 ? "" : "s"}` : ""}` : "off";
  const passiveExports = telemetryPassiveExportsByName(passiveStatus?.exports);
  const clickhouseEvidence = telemetryClickHouseEvidence(passiveStatus?.clickhouse, active);
  const fileEvidence = telemetryExportEvidence(passiveExports, { name: "local-json", type: TELEMETRY_EXPORT_TYPE_JSON_FILE, active: exportSettings.jsonFileEnabled });
  const streamEvidence = telemetryExportEvidence(passiveExports, { name: "siem-json", type: exportSettings.jsonStreamProtocol === "udp" ? TELEMETRY_EXPORT_TYPE_JSON_UDP : TELEMETRY_EXPORT_TYPE_JSON_TCP, active: exportSettings.jsonStreamEnabled });
  return {
    active,
    dirty: Boolean(dirty),
    passiveStatusAvailable: Boolean(passiveStatus),
    passiveStatusStale: Boolean(active && dirty && exportStatus),
    passiveState: passiveStatus?.state || "unavailable",
    passiveGeneratedAt: passiveStatus?.generatedAt || "",
    passivePolicyVersion: passiveStatus?.runningPolicyVersion || 0,
    tone,
    pipelineLabel,
    engineState,
    engineTone,
    engineDetail: passiveVector?.detail || engine?.detail || "Vector runtime posture is not available from system status.",
    endpoint,
    database,
    exportSettings,
    headline: active ? "ClickHouse local retention will be enabled." : "ClickHouse local retention is disabled.",
    summary: active
      ? "Current policy support retains Suricata EVE events in ClickHouse after commit and can mirror parsed events to JSON file or remote JSON stream exports."
      : "Traffic forwarding and IDS/IPS enforcement continue, but this build has no alternate syslog or continuous JSON export sink.",
    channels: [
      {
        id: "clickhouse",
        label: "ClickHouse local retention",
        statusLabel: clickhouseEvidence.label,
        tone: clickhouseEvidence.tone,
        detail: active
          ? clickhouseEvidence.detail || `Vector is configured to write parsed EVE events to ${database}.events and alert events to ${database}.alerts.`
          : "No Vector ClickHouse sink is rendered while telemetry is disabled.",
        observed: clickhouseEvidence.observed,
        evidenceState: clickhouseEvidence.state,
      },
      {
        id: "json-file",
        label: "Continuous JSON file export",
        statusLabel: fileEvidence.label,
        tone: fileEvidence.tone,
        detail: exportSettings.jsonFileEnabled
          ? fileEvidence.detail || `Vector is configured to mirror parsed EVE events to ${exportSettings.jsonFilePath}.`
          : "No policy-backed JSON file sink is rendered.",
        observed: fileEvidence.observed,
        evidenceState: fileEvidence.state,
      },
      {
        id: "json-stream",
        label: "Remote JSON SIEM stream",
        statusLabel: streamEvidence.label,
        tone: streamEvidence.tone,
        detail: exportSettings.jsonStreamEnabled
          ? streamEvidence.detail || `Vector is configured to stream newline-delimited JSON events over ${exportSettings.jsonStreamProtocol.toUpperCase()} to ${exportSettings.jsonStreamTarget}; receiver-side proof is still required.`
          : "No policy-backed remote JSON socket sink is rendered.",
        observed: streamEvidence.observed,
        evidenceState: streamEvidence.state,
      },
    ],
    healthChecks: active ? [
      "Commit the candidate, then confirm the Vector engine is ready or active in system status.",
      passiveStatus ? "Review passive export status from /v1/system/telemetry/exports/status; it does not send test events or dial remote receivers." : "Passive export status is unavailable; use candidate settings and Vector engine posture as context only.",
      `Generate a controlled IDS/IPS event and verify new rows in ${database}.events or ${database}.alerts.`,
      exportSettings.jsonFileEnabled ? `Confirm the JSON export file receives parsed events at ${exportSettings.jsonFilePath}.` : "No local JSON export file is configured.",
      exportSettings.jsonStreamEnabled ? `Confirm the SIEM listener receives parsed JSON events at ${exportSettings.jsonStreamTarget}.` : "No remote JSON SIEM stream is configured.",
      "No WebUI test-event workflow exists in this build; use Vector lifecycle, passive status, ClickHouse row counts, and sink-side event counts as evidence.",
    ] : [
      "Enable ClickHouse retention and commit before expecting telemetry sink health.",
      "Passive export status is read-only and only reports running-policy telemetry posture.",
      "With telemetry disabled, only manual evidence exports from Traffic, Threats, Troubleshoot, and support bundles are available.",
    ],
    limitations: [
      "CEF/syslog normalization is not policy-backed yet; the supported external SIEM path is parsed JSON over TCP or UDP.",
      "Settings stages telemetry.enabled, clickhouse_url, database, and explicit JSON export sinks.",
      "Sink authentication material must not be embedded in the ClickHouse endpoint.",
      active && dirty ? "Passive export status reflects the running policy until the staged candidate is committed." : "",
    ].filter(Boolean),
  };
}

function telemetryPassiveStatus(exportStatus, { active = false, dirty = false } = {}) {
  if (!active || dirty || !exportStatus || typeof exportStatus !== "object") return null;
  if (exportStatus.telemetryEnabled !== true) return null;
  return exportStatus;
}

function telemetryPassiveExportsByName(exports = []) {
  const out = new Map();
  if (!Array.isArray(exports)) return out;
  for (const item of exports) {
    if (!item?.name) continue;
    out.set(item.name, item);
  }
  return out;
}

function telemetryClickHouseEvidence(clickhouse = null, active = false) {
  if (!active) return { state: "disabled", label: "disabled", tone: "neutral", detail: "", observed: false };
  if (!clickhouse) {
    return {
      state: "configured",
      label: "configured",
      tone: "warn",
      detail: "Vector is configured for ClickHouse retention; passive appliance status is not available.",
      observed: false,
    };
  }
  return telemetryEvidenceDisplay(clickhouse.evidenceState || "configured-unverified", {
    configuredLabel: "needs row proof",
    configuredDetail: clickhouse.evidenceDetail || "ClickHouse retention is configured; row delivery requires ClickHouse-side evidence.",
  });
}

function telemetryExportEvidence(passiveExports, { name = "", type = "", active = false } = {}) {
  if (!active) return { state: "disabled", label: "disabled", tone: "neutral", detail: "", observed: false };
  const item = passiveExports.get(name) || [...passiveExports.values()].find((entry) => entry?.type === type) || null;
  if (!item) {
    return {
      state: "configured",
      label: "configured",
      tone: "warn",
      detail: "Vector is configured for this sink; passive appliance status is not available.",
      observed: false,
    };
  }
  return telemetryEvidenceDisplay(item.evidenceState || "configured-unverified", {
    configuredLabel: item.protocol === "file" ? "pending" : "needs receiver proof",
    configuredDetail: item.evidenceDetail || "Sink delivery requires independent evidence.",
    detail: item.evidenceDetail,
  });
}

function telemetryEvidenceDisplay(state = "", opts = {}) {
  switch (state) {
  case "receiving":
    return { state, label: "observed locally", tone: "ok", detail: opts.detail || opts.configuredDetail || "", observed: true };
  case "empty":
    return { state, label: "empty", tone: "warn", detail: opts.detail || opts.configuredDetail || "", observed: false };
  case "pending":
    return { state, label: "pending", tone: "warn", detail: opts.detail || opts.configuredDetail || "", observed: false };
  case "invalid":
    return { state, label: "invalid", tone: "bad", detail: opts.detail || opts.configuredDetail || "", observed: false };
  case "configured-unverified":
    return { state, label: opts.configuredLabel || "needs proof", tone: "warn", detail: opts.detail || opts.configuredDetail || "", observed: false };
  default:
    return { state: state || "configured", label: "configured", tone: "warn", detail: opts.detail || opts.configuredDetail || "", observed: false };
  }
}

export function telemetryEvidenceCommands(input = {}) {
  const model = input && Object.prototype.hasOwnProperty.call(input, "active")
    ? input
    : telemetryReadinessModel(input);
  const commands = [
    {
      label: "Runtime status",
      command: "ngfwctl status",
      detail: "Confirm the Vector engine state after the telemetry candidate is committed.",
    },
    {
      label: "Passive export status",
      command: "ngfwctl system telemetry-export-status --json",
      detail: "Read running-policy export posture without sending test events or dialing remote receivers.",
    },
    {
      label: "Candidate validation",
      command: "ngfwctl policy validate",
      detail: "Validate the staged telemetry policy before commit and after any evidence rerun.",
    },
  ];
  if (!model.active) {
    commands.push({
      label: "Candidate telemetry",
      command: "ngfwctl policy show --source candidate --json",
      detail: "Inspect candidate telemetry settings before enabling export evidence checks.",
    });
    return commands;
  }
  const database = safeTelemetryDatabase(model.database);
  commands.push({
    label: "ClickHouse rows",
    command: `clickhouse-client --query ${shellQuote(`SELECT count() FROM ${database}.events`)}`,
    detail: `Run after generating a controlled IDS/IPS event; repeat for ${database}.alerts when validating alert-specific retention.`,
  });
  if (model.exportSettings?.jsonFileEnabled) {
    commands.push({
      label: "JSON file export",
      command: `sudo test -s ${shellQuote(model.exportSettings.jsonFilePath)} && sudo tail -n 5 ${shellQuote(model.exportSettings.jsonFilePath)}`,
      detail: "Confirm parsed events are mirrored to the configured local JSON export file.",
    });
  }
  if (model.exportSettings?.jsonStreamEnabled) {
    commands.push({
      label: "SIEM stream",
      command: `# SIEM-side check: confirm ${redactTelemetryText(model.exportSettings.jsonStreamTarget)} receives newline-delimited JSON events over ${String(model.exportSettings.jsonStreamProtocol || "tcp").toUpperCase()}`,
      detail: "Collect listener-side event counts because this build has no WebUI test-event/export-health API.",
    });
  }
  return commands;
}

export function telemetryReceiverProofFromInputs(inputs = {}, model = {}) {
  const target = String(inputs.target || model.exportSettings?.jsonStreamTarget || "").trim();
  const protocol = String(inputs.protocol || model.exportSettings?.jsonStreamProtocol || "tcp").trim().toLowerCase();
  const observedEventCount = Math.max(0, Number.parseInt(String(inputs.observedEventCount || "0"), 10) || 0);
  const sampleEventHashes = String(inputs.sampleEventHashes || "")
    .split(/[\s,]+/)
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean)
    .slice(0, 12);
  const commands = String(inputs.commands || "")
    .split(/\r?\n/)
    .map((line) => redactTelemetryText(line.trim()))
    .filter(Boolean)
    .slice(0, 12);
  return {
    schemaVersion: TELEMETRY_RECEIVER_PROOF_SCHEMA,
    target: redactTelemetryText(target),
    protocol: protocol === "udp" ? "udp" : "tcp",
    windowStart: redactTelemetryText(String(inputs.windowStart || "").trim()),
    windowEnd: redactTelemetryText(String(inputs.windowEnd || "").trim()),
    observedEventCount,
    sampleEventHashes,
    collectedBy: redactTelemetryText(String(inputs.collectedBy || "").trim()),
    notes: redactTelemetryText(String(inputs.notes || "").trim()),
    commands,
    source: "operator-attached-receiver-proof",
    custody: "browser-local unsigned receiver evidence; passive status did not dial the SIEM",
  };
}

export function validateTelemetryReceiverProof(proof = {}) {
  const issues = [];
  if (!proof || typeof proof !== "object") {
    return ["Receiver proof is required."];
  }
  if (!proof.target) issues.push("Receiver target is required.");
  if (!["tcp", "udp"].includes(String(proof.protocol || "").toLowerCase())) issues.push("Receiver protocol must be TCP or UDP.");
  if (!proof.windowStart || !proof.windowEnd) issues.push("Receiver proof window start and end are required.");
  if (!Number.isInteger(Number(proof.observedEventCount)) || Number(proof.observedEventCount) <= 0) {
    issues.push("Observed event count must be greater than zero.");
  }
  let validSampleHashCount = 0;
  for (const hash of proof.sampleEventHashes || []) {
    if (!/^[a-f0-9]{16,64}$/.test(hash)) {
      issues.push("Sample event hashes must be lowercase hex strings between 16 and 64 characters.");
      break;
    }
    validSampleHashCount += 1;
  }
  if (!proof.commands?.length && validSampleHashCount === 0 && !proof.notes) {
    issues.push("Receiver proof needs commands, sample event hashes, or operator notes.");
  }
  return issues;
}

export function telemetryEvidenceText(input = {}, opts = {}) {
  const model = input && Object.prototype.hasOwnProperty.call(input, "active")
    ? input
    : telemetryReadinessModel(input);
  const commands = telemetryEvidenceCommands(model);
  const receiverProof = validReceiverProof(opts.receiverProof);
  const lines = [
    "Phragma telemetry export evidence plan",
    `pipeline=${model.pipelineLabel || "off"}`,
    `endpoint=${redactClickHouseEndpoint(model.endpoint || "disabled")}`,
    `database=${safeTelemetryDatabase(model.database || "none")}`,
    `vector_engine=${model.engineState || "unknown"}`,
    "",
    "Evidence checks:",
    ...model.healthChecks.map((check) => `- ${redactTelemetryText(check)}`),
    "",
    "Commands:",
    ...commands.flatMap((item) => [
      `- ${item.label}: ${redactTelemetryText(item.detail)}`,
      `  ${redactTelemetryText(item.command)}`,
    ]),
    receiverProof ? "" : null,
    receiverProof ? "Receiver proof:" : null,
    receiverProof ? `- target=${receiverProof.target}` : null,
    receiverProof ? `- protocol=${receiverProof.protocol}` : null,
    receiverProof ? `- window=${receiverProof.windowStart}..${receiverProof.windowEnd}` : null,
    receiverProof ? `- observed_events=${receiverProof.observedEventCount}` : null,
    receiverProof && receiverProof.sampleEventHashes.length ? `- sample_hashes=${receiverProof.sampleEventHashes.join(",")}` : null,
    receiverProof && receiverProof.collectedBy ? `- collected_by=${receiverProof.collectedBy}` : null,
    receiverProof ? `- custody=${receiverProof.custody}` : null,
    receiverProof && receiverProof.notes ? `- notes=${receiverProof.notes}` : null,
    receiverProof && receiverProof.commands.length ? "- receiver_commands:" : null,
    ...(receiverProof ? receiverProof.commands.map((cmd) => `  ${cmd}`) : []),
    "",
    "Limitations:",
    ...model.limitations.map((limit) => `- ${redactTelemetryText(limit)}`),
  ].filter((line) => line !== null);
  return lines.join("\n") + "\n";
}

export function telemetryEvidencePacket(input = {}, opts = {}) {
  const model = input && Object.prototype.hasOwnProperty.call(input, "active")
    ? input
    : telemetryReadinessModel(input);
  const commands = telemetryEvidenceCommands(model);
  const receiverProof = validReceiverProof(opts.receiverProof);
  return {
    schemaVersion: TELEMETRY_EVIDENCE_SCHEMA,
    collectedAt: opts.collectedAt || new Date().toISOString(),
    surface: "settings.telemetry",
    route: opts.route || "#/settings?panel=telemetry",
    pipeline: {
      active: Boolean(model.active),
      label: model.pipelineLabel || "off",
      dirty: Boolean(model.dirty),
      endpoint: redactClickHouseEndpoint(model.endpoint || "disabled"),
      database: safeTelemetryDatabase(model.database || "none"),
      vectorEngine: {
        state: model.engineState || "unknown",
        tone: model.engineTone || "neutral",
        detail: redactTelemetryText(model.engineDetail || ""),
      },
      passiveStatus: {
        available: Boolean(model.passiveStatusAvailable),
        state: model.passiveState || "unavailable",
        generatedAt: model.passiveGeneratedAt || "",
        runningPolicyVersion: Number(model.passivePolicyVersion || 0),
        source: "/v1/system/telemetry/exports/status",
        staleForCandidate: Boolean(model.passiveStatusStale),
      },
    },
    sinks: (model.channels || []).map((channel) => ({
      id: channel.id,
      label: channel.label,
      status: channel.statusLabel,
      tone: channel.tone,
      evidenceState: channel.evidenceState || "unknown",
      observed: Boolean(channel.observed),
      detail: redactTelemetryText(channel.detail || ""),
      evidenceSource: telemetrySinkEvidenceSource(channel.id),
    })),
    checks: (model.healthChecks || []).map((check) => redactTelemetryText(check)),
    receiverProof,
    commands: commands.map((item) => ({
      label: item.label,
      detail: redactTelemetryText(item.detail),
      command: redactTelemetryText(item.command),
    })),
    limitations: (model.limitations || []).map((limit) => redactTelemetryText(limit)),
  };
}

export function telemetryEvidencePacketJson(input = {}, opts = {}) {
  return JSON.stringify(telemetryEvidencePacket(input, opts), null, 2) + "\n";
}

function validReceiverProof(proof = null) {
  if (!proof) return null;
  const normalized = {
    ...proof,
    target: redactTelemetryText(proof.target || ""),
    protocol: String(proof.protocol || "tcp").toLowerCase() === "udp" ? "udp" : "tcp",
    windowStart: redactTelemetryText(proof.windowStart || ""),
    windowEnd: redactTelemetryText(proof.windowEnd || ""),
    observedEventCount: Number(proof.observedEventCount || 0),
    sampleEventHashes: Array.isArray(proof.sampleEventHashes) ? proof.sampleEventHashes.map((item) => String(item || "").toLowerCase()).filter(Boolean).slice(0, 12) : [],
    collectedBy: redactTelemetryText(proof.collectedBy || ""),
    notes: redactTelemetryText(proof.notes || ""),
    commands: Array.isArray(proof.commands) ? proof.commands.map((cmd) => redactTelemetryText(cmd)).filter(Boolean).slice(0, 12) : [],
    source: "operator-attached-receiver-proof",
    custody: "browser-local unsigned receiver evidence; passive status did not dial the SIEM",
  };
  if (validateTelemetryReceiverProof(normalized).length) return null;
  return normalized;
}

export function telemetryEvidenceFilename(now = new Date()) {
  const stamp = now.toISOString().replace(/[:.]/g, "-");
  return `phragma-telemetry-evidence-${stamp}.json`;
}

export function telemetryEngineTone(state = "") {
  if (READY_ENGINE_STATES.has(state)) return "ok";
  if (BAD_ENGINE_STATES.has(state)) return "bad";
  if (state === "simulation" || state === "restarting" || state === "dry-run") return "warn";
  return "neutral";
}

function safeTelemetryDatabase(value) {
  const text = String(value || "").trim();
  return DATABASE_RE.test(text) ? text : DEFAULT_TELEMETRY_DATABASE;
}

function shellQuote(value) {
  const text = String(value || "");
  if (/^[A-Za-z0-9_./:@%=-]+$/.test(text)) return text;
  return `"${text.replace(/["\\$`]/g, "\\$&")}"`;
}

function redactClickHouseEndpoint(value) {
  const raw = String(value || "");
  if (!raw || raw === "disabled") return raw || "disabled";
  try {
    const parsed = new URL(raw);
    parsed.username = "";
    parsed.password = "";
    parsed.hash = "";
    for (const key of [...parsed.searchParams.keys()]) {
      if (sensitiveClickhouseQueryKey(key) || clickhouseControlQueryKey(key)) parsed.searchParams.set(key, "[redacted]");
    }
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return redactSensitivePairs(raw);
  }
}

function redactTelemetryText(value) {
  return String(value || "")
    .replace(/https?:\/\/[^\s"'<>]+/gi, (raw) => redactClickHouseEndpoint(raw))
    .replace(/\/Users\/[^\s"',;}]+/g, "/Users/[redacted]")
    .replace(/\/private\/tmp\/[^\s"',;}]+/g, "/private/tmp/[redacted]")
    .replace(/\/etc\/[^\s"',;}]+/g, "/etc/[redacted]")
    .replace(/\b(token|access_token|api_key|password|secret|client_secret|key)=([^\s"'&]+)/gi, (_, key) => `${key}=[redacted]`);
}

function redactSensitivePairs(value) {
  return String(value || "").replace(/\b(token|access_token|api_key|password|secret|client_secret|key)=([^\s"'&]+)/gi, (_, key) => `${key}=[redacted]`);
}

function telemetrySinkEvidenceSource(id = "") {
  switch (id) {
  case "clickhouse":
    return "clickhouse-row-count";
  case "json-file":
    return "local-json-file";
  case "json-stream":
    return "siem-listener";
  default:
    return "operator-evidence";
  }
}

function clickhouseQueryKeys(search = "") {
  return String(search || "")
    .replace(/^\?/, "")
    .split(/[&;]/)
    .map((part) => part.split("=")[0] || "")
    .map((key) => {
      try { return decodeURIComponent(key.replace(/\+/g, " ")); }
      catch { return key; }
    })
    .filter(Boolean);
}

function sensitiveClickhouseQueryKey(key) {
  const normalized = String(key || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  if ([
    "token",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "password",
    "passwd",
    "secret",
    "clientsecret",
    "key",
    "apikey",
    "apiaccesskey",
    "accesskey",
  ].includes(normalized)) return true;
  return normalized.includes("token") ||
    normalized.includes("password") ||
    normalized.includes("secret") ||
    normalized.includes("apikey") ||
    normalized.includes("accesskey");
}

function clickhouseControlQueryKey(key) {
  const normalized = String(key || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  return [
    "query",
    "database",
    "defaultdatabase",
    "user",
    "username",
  ].includes(normalized);
}

function comparableTelemetryExports(exports = []) {
  if (!Array.isArray(exports)) return [];
  return exports
    .filter((item) => item?.enabled)
    .map((item) => ({
      name: item.name || "",
      enabled: true,
      type: item.type || "",
      target: item.target || "",
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

function validateJSONFileTarget(target = "") {
  const value = String(target || "").trim() || DEFAULT_JSON_EXPORT_PATH;
  const issues = [];
  if (/[\s\u0000-\u001f\u007f]/.test(value)) {
    issues.push("JSON file export path must not contain whitespace or control characters.");
  }
  if (!value.startsWith("/")) {
    issues.push("JSON file export path must be absolute.");
  }
  const clean = cleanPosixPath(value);
  if (clean === "/var/log/openngfw/exports" || !clean.startsWith("/var/log/openngfw/exports/")) {
    issues.push("JSON file export path must stay under /var/log/openngfw/exports/.");
  }
  return issues;
}

function validateJSONStreamTarget(target = "", protocol = "tcp") {
  const value = String(target || "").trim() || DEFAULT_JSON_STREAM_TARGET;
  const issues = [];
  if (!["tcp", "udp"].includes(String(protocol || "").toLowerCase())) {
    issues.push("Remote JSON stream protocol must be TCP or UDP.");
  }
  if (/[\s\u0000-\u001f\u007f/]/.test(value) || value.includes("://") || value.includes("@")) {
    issues.push("Remote JSON stream target must be host:port without whitespace, URL scheme, credentials, or path.");
    return issues;
  }
  const parsed = parseHostPort(value);
  if (!parsed) {
    issues.push("Remote JSON stream target must be host:port.");
    return issues;
  }
  const port = Number(parsed.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    issues.push("Remote JSON stream port must be 1-65535.");
  }
  return issues;
}

function parseHostPort(value = "") {
  const bracket = value.match(/^\[([^\]]+)\]:(\d+)$/);
  if (bracket) return { host: bracket[1], port: bracket[2] };
  const simple = value.match(/^([^:]+):(\d+)$/);
  if (simple) return { host: simple[1], port: simple[2] };
  return null;
}

function cleanPosixPath(value = "") {
  const parts = [];
  for (const part of String(value || "").split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") parts.pop();
    else parts.push(part);
  }
  return "/" + parts.join("/");
}
