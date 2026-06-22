import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  DEFAULT_CLICKHOUSE_URL,
  DEFAULT_JSON_EXPORT_PATH,
  DEFAULT_JSON_STREAM_TARGET,
  DEFAULT_TELEMETRY_DATABASE,
  TELEMETRY_EXPORT_TYPE_JSON_FILE,
  TELEMETRY_EXPORT_TYPE_JSON_TCP,
  TELEMETRY_EXPORT_TYPE_JSON_UDP,
  TELEMETRY_EVIDENCE_SCHEMA,
  TELEMETRY_RECEIVER_PROOF_SCHEMA,
  comparableTelemetry,
  telemetryEvidenceCommands,
  telemetryEvidenceFilename,
  telemetryEvidencePacket,
  telemetryEvidencePacketJson,
  telemetryEvidenceText,
  telemetryExportSettings,
  telemetryExportsFromInputs,
  telemetryEngineTone,
  telemetryFromInputs,
  telemetryReadinessModel,
  telemetryReceiverProofFromInputs,
  validateTelemetryInputs,
  validateTelemetryReceiverProof,
} from "./telemetry_settings.js";

const settingsViewSource = readFileSync(new URL("./views/settings.js", import.meta.url), "utf8");
assert.match(settingsViewSource, /import \{ pinInvestigationPacket \} from "\.\.\/investigation_case\.js";/);
assert.match(settingsViewSource, /function telemetryInvestigationHandoffPacket/);
assert.match(settingsViewSource, /function pinTelemetryEvidencePlan/);
assert.match(settingsViewSource, /Pin to case/);
assert.match(settingsViewSource, /function openTelemetryReceiverProof/);
assert.match(settingsViewSource, /telemetryProofAction/);

{
  assert.equal(telemetryFromInputs({ enabled: false }), undefined);
  assert.deepEqual(telemetryFromInputs({ enabled: true }), {
    enabled: true,
    clickhouseUrl: DEFAULT_CLICKHOUSE_URL,
    database: DEFAULT_TELEMETRY_DATABASE,
  });
}

{
  assert.deepEqual(telemetryFromInputs({
    enabled: true,
    clickhouseUrl: " https://clickhouse.example:8443 ",
    database: " openngfw_prod ",
    jsonFileEnabled: true,
    jsonFilePath: " /var/log/openngfw/exports/eve.json ",
    jsonStreamEnabled: true,
    jsonStreamTarget: " siem.example:5514 ",
    jsonStreamProtocol: "udp",
  }), {
    enabled: true,
    clickhouseUrl: "https://clickhouse.example:8443",
    database: "openngfw_prod",
    exports: [
      { name: "local-json", enabled: true, type: TELEMETRY_EXPORT_TYPE_JSON_FILE, target: "/var/log/openngfw/exports/eve.json" },
      { name: "siem-json", enabled: true, type: TELEMETRY_EXPORT_TYPE_JSON_UDP, target: "siem.example:5514" },
    ],
  });
}

{
  assert.deepEqual(telemetryExportsFromInputs({
    jsonFileEnabled: true,
    jsonStreamEnabled: true,
  }), [
    { name: "local-json", enabled: true, type: TELEMETRY_EXPORT_TYPE_JSON_FILE, target: DEFAULT_JSON_EXPORT_PATH },
    { name: "siem-json", enabled: true, type: TELEMETRY_EXPORT_TYPE_JSON_TCP, target: DEFAULT_JSON_STREAM_TARGET },
  ]);
  assert.deepEqual(telemetryExportSettings([
    { name: "siem-json", enabled: true, type: TELEMETRY_EXPORT_TYPE_JSON_UDP, target: "siem.example:5515" },
    { name: "local-json", enabled: true, type: TELEMETRY_EXPORT_TYPE_JSON_FILE, target: "/var/log/openngfw/exports/eve.json" },
  ]), {
    jsonFileEnabled: true,
    jsonFilePath: "/var/log/openngfw/exports/eve.json",
    jsonStreamEnabled: true,
    jsonStreamTarget: "siem.example:5515",
    jsonStreamProtocol: "udp",
  });
}

{
  assert.deepEqual(validateTelemetryInputs({
    enabled: true,
    clickhouseUrl: "tcp://127.0.0.1:9000",
    database: "Phragma",
  }), [
    "ClickHouse endpoint must use http:// or https://.",
    "Database must start with a lowercase letter and use only lowercase letters, numbers, or underscores (max 64).",
  ]);
}

{
  assert.deepEqual(validateTelemetryInputs({ enabled: false, clickhouseUrl: "not a url", database: "Bad" }), []);
  assert.deepEqual(validateTelemetryInputs({ enabled: true, clickhouseUrl: "", database: "" }), []);
}

{
  assert.deepEqual(validateTelemetryInputs({
    enabled: true,
    clickhouseUrl: "https://writer:secret@clickhouse.example:8443?cluster=prod",
    database: "phragma",
  }), [
    "ClickHouse endpoint must not include URL userinfo.",
  ]);
  assert.deepEqual(validateTelemetryInputs({
    enabled: true,
    clickhouseUrl: "https://clickhouse.example:8443?cluster=prod;access_token=secret&api_key=secret",
    database: "phragma",
  }), [
    'ClickHouse endpoint must not include sensitive query parameter "access_token".',
    'ClickHouse endpoint must not include sensitive query parameter "api_key".',
  ]);
}

{
  assert.deepEqual(validateTelemetryInputs({
    enabled: true,
    clickhouseUrl: "https://clickhouse.example:8443/path#sink",
    database: "openngfw-prod",
  }), [
    "ClickHouse endpoint must not include a path; use the HTTP origin only.",
    "ClickHouse endpoint must not include a URL fragment.",
    "Database must start with a lowercase letter and use only lowercase letters, numbers, or underscores (max 64).",
  ]);
  assert.deepEqual(validateTelemetryInputs({
    enabled: true,
    clickhouseUrl: "https://clickhouse.example:8443/?database=openngfw&query=select+1&user=default",
    database: "openngfw",
  }), [
    'ClickHouse endpoint must not include ClickHouse control query parameter "database".',
    'ClickHouse endpoint must not include ClickHouse control query parameter "query".',
    'ClickHouse endpoint must not include ClickHouse control query parameter "user".',
  ]);
  assert.deepEqual(validateTelemetryInputs({
    enabled: true,
    clickhouseUrl: "https://clickhouse.example:8443",
    database: "system",
  }), [
    'Database must not target ClickHouse system database "system".',
  ]);
}

{
  assert.deepEqual(validateTelemetryInputs({
    enabled: true,
    jsonFileEnabled: true,
    jsonFilePath: "/etc/openngfw/eve.json",
    jsonStreamEnabled: true,
    jsonStreamTarget: "tcp://siem.example:5514",
  }), [
    "JSON file export path must stay under /var/log/openngfw/exports/.",
    "Remote JSON stream target must be host:port without whitespace, URL scheme, credentials, or path.",
  ]);
  assert.deepEqual(validateTelemetryInputs({
    enabled: true,
    jsonStreamEnabled: true,
    jsonStreamTarget: "siem.example",
    jsonStreamProtocol: "sctp",
  }), [
    "Remote JSON stream protocol must be TCP or UDP.",
    "Remote JSON stream target must be host:port.",
  ]);
  assert.deepEqual(validateTelemetryInputs({
    enabled: false,
    jsonFileEnabled: true,
    jsonFilePath: "/etc/openngfw/eve.json",
    jsonStreamEnabled: true,
    jsonStreamTarget: "not-host-port",
  }), []);
}

{
  assert.deepEqual(comparableTelemetry({}), { enabled: false });
  assert.deepEqual(comparableTelemetry({ enabled: true }), {
    enabled: true,
    clickhouseUrl: DEFAULT_CLICKHOUSE_URL,
    database: DEFAULT_TELEMETRY_DATABASE,
    exports: [],
  });
}

{
  assert.equal(telemetryEngineTone("ready"), "ok");
  assert.equal(telemetryEngineTone("failed"), "bad");
  assert.equal(telemetryEngineTone("restarting"), "warn");
  assert.equal(telemetryEngineTone("unknown"), "neutral");
}

{
  const model = telemetryReadinessModel({
    status: { engines: [{ name: "vector", state: "ready", detail: "running" }] },
    telemetry: {
      enabled: true,
      clickhouseUrl: "https://clickhouse.example:8443",
      database: "openngfw_prod",
      exports: [
        { name: "local-json", enabled: true, type: TELEMETRY_EXPORT_TYPE_JSON_FILE, target: "/var/log/openngfw/exports/eve.json" },
        { name: "siem-json", enabled: true, type: TELEMETRY_EXPORT_TYPE_JSON_TCP, target: "siem.example:5514" },
      ],
    },
    dirty: true,
  });

  assert.equal(model.active, true);
  assert.equal(model.tone, "warn");
  assert.equal(model.pipelineLabel, "Vector -> ClickHouse + 2 exports");
  assert.equal(model.endpoint, "https://clickhouse.example:8443");
  assert.equal(model.database, "openngfw_prod");
  assert.deepEqual(model.channels.map(({ id, statusLabel, tone }) => ({ id, statusLabel, tone })), [
    { id: "clickhouse", statusLabel: "configured", tone: "warn" },
    { id: "json-file", statusLabel: "configured", tone: "warn" },
    { id: "json-stream", statusLabel: "configured", tone: "warn" },
  ]);
  assert.match(model.summary, /remote JSON stream exports/);
  assert.match(model.healthChecks.join("\n"), /Passive export status is unavailable/);
  assert.match(model.healthChecks.join("\n"), /No WebUI test-event workflow exists/);
  assert.match(model.healthChecks.join("\n"), /openngfw_prod\.events/);
  assert.match(model.healthChecks.join("\n"), /siem\.example:5514/);

  const commands = telemetryEvidenceCommands(model);
  assert.ok(commands.some((item) => item.label === "Runtime status" && item.command === "ngfwctl status"));
  assert.ok(commands.some((item) => item.label === "Passive export status" && item.command === "ngfwctl system telemetry-export-status --json"));
  assert.ok(commands.some((item) => item.label === "Candidate validation" && item.command === "ngfwctl policy validate"));
  assert.ok(commands.some((item) => item.label === "ClickHouse rows" && item.command.includes("SELECT count() FROM openngfw_prod.events")));
  assert.ok(commands.some((item) => item.label === "JSON file export" && item.command.includes("/var/log/openngfw/exports/eve.json")));
  assert.ok(commands.some((item) => item.label === "SIEM stream" && item.command.includes("siem.example:5514")));

  const text = telemetryEvidenceText(model);
  assert.match(text, /Phragma telemetry export evidence plan/);
  assert.match(text, /pipeline=Vector -> ClickHouse \+ 2 exports/);
  assert.match(text, /ClickHouse rows/);
  assert.match(text, /JSON file export/);
  assert.match(text, /SIEM stream/);

  const packet = telemetryEvidencePacket(model, {
    collectedAt: "2026-06-19T15:00:00Z",
    route: "#/settings?panel=telemetry",
  });
  assert.equal(packet.schemaVersion, TELEMETRY_EVIDENCE_SCHEMA);
  assert.equal(packet.collectedAt, "2026-06-19T15:00:00Z");
  assert.equal(packet.surface, "settings.telemetry");
  assert.equal(packet.pipeline.label, "Vector -> ClickHouse + 2 exports");
  assert.equal(packet.pipeline.vectorEngine.state, "ready");
  assert.equal(packet.pipeline.passiveStatus.available, false);
  assert.deepEqual(packet.sinks.map(({ id, evidenceSource }) => ({ id, evidenceSource })), [
    { id: "clickhouse", evidenceSource: "clickhouse-row-count" },
    { id: "json-file", evidenceSource: "local-json-file" },
    { id: "json-stream", evidenceSource: "siem-listener" },
  ]);
  assert.ok(packet.commands.some((item) => item.label === "ClickHouse rows"));
  assert.match(telemetryEvidencePacketJson(model, { collectedAt: "2026-06-19T15:00:00Z" }), /phragma\.telemetry\.evidence\.v1/);
  assert.equal(telemetryEvidenceFilename(new Date("2026-06-19T15:00:00.123Z")), "phragma-telemetry-evidence-2026-06-19T15-00-00-123Z.json");
}

{
  const model = telemetryReadinessModel({
    status: { engines: [{ name: "vector", state: "ready" }] },
    telemetry: {
      enabled: true,
      clickhouseUrl: "https://clickhouse.example:8443",
      database: "openngfw_prod",
      exports: [
        { name: "siem-json", enabled: true, type: TELEMETRY_EXPORT_TYPE_JSON_TCP, target: "siem.example:5514" },
      ],
    },
  });
  const proof = telemetryReceiverProofFromInputs({
    target: "siem.example:5514",
    protocol: "tcp",
    windowStart: "2026-06-19T15:10:00Z",
    windowEnd: "2026-06-19T15:15:00Z",
    observedEventCount: "7",
    sampleEventHashes: "aaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    collectedBy: "soc-operator",
    commands: "wc -l siem-json.ndjson\nquery receiver token=secret-token /Users/alice/evidence.json",
    notes: "receiver accepted access_token=secret-token for /etc/openngfw/private.json",
  }, model);

  assert.equal(proof.schemaVersion, TELEMETRY_RECEIVER_PROOF_SCHEMA);
  assert.equal(proof.observedEventCount, 7);
  assert.deepEqual(validateTelemetryReceiverProof(proof), []);
  assert.equal(JSON.stringify(proof).includes("secret-token"), false);
  assert.equal(JSON.stringify(proof).includes("/Users/alice"), false);
  assert.equal(JSON.stringify(proof).includes("/etc/openngfw"), false);

  const text = telemetryEvidenceText(model, { receiverProof: proof });
  assert.match(text, /Receiver proof/);
  assert.match(text, /observed_events=7/);
  assert.match(text, /sample_hashes=aaaaaaaaaaaaaaaa,bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/);
  assert.match(text, /passive status did not dial the SIEM/);
  assert.equal(text.includes("secret-token"), false);
  assert.equal(text.includes("/Users/alice"), false);

  const packet = telemetryEvidencePacket(model, { collectedAt: "2026-06-19T15:20:00Z", receiverProof: proof });
  assert.equal(packet.receiverProof.schemaVersion, TELEMETRY_RECEIVER_PROOF_SCHEMA);
  assert.equal(packet.receiverProof.observedEventCount, 7);
  assert.equal(packet.receiverProof.custody, "browser-local unsigned receiver evidence; passive status did not dial the SIEM");

  assert.deepEqual(validateTelemetryReceiverProof({
    ...proof,
    observedEventCount: 0,
    sampleEventHashes: ["NOTHEX"],
    commands: [],
    notes: "",
  }), [
    "Observed event count must be greater than zero.",
    "Sample event hashes must be lowercase hex strings between 16 and 64 characters.",
    "Receiver proof needs commands, sample event hashes, or operator notes.",
  ]);
}

{
  const model = telemetryReadinessModel({
    status: { engines: [{ name: "vector", state: "ready", detail: "running" }] },
    telemetry: {
      enabled: true,
      clickhouseUrl: "https://clickhouse.example:8443",
      database: "openngfw_prod",
      exports: [
        { name: "local-json", enabled: true, type: TELEMETRY_EXPORT_TYPE_JSON_FILE, target: "/var/log/openngfw/exports/eve.json" },
        { name: "siem-json", enabled: true, type: TELEMETRY_EXPORT_TYPE_JSON_TCP, target: "siem.example:5514" },
      ],
    },
    exportStatus: {
      telemetryEnabled: true,
      state: "configured",
      generatedAt: "2026-06-19T15:05:00Z",
      runningPolicyVersion: "7",
      vector: { state: "active", detail: "process running" },
      clickhouse: { evidenceState: "configured-unverified", evidenceDetail: "row delivery requires ClickHouse-side evidence" },
      exports: [
        { name: "local-json", type: TELEMETRY_EXPORT_TYPE_JSON_FILE, protocol: "file", evidenceState: "receiving", evidenceDetail: "file is present with 128 bytes" },
        { name: "siem-json", type: TELEMETRY_EXPORT_TYPE_JSON_TCP, protocol: "tcp", evidenceState: "configured-unverified", evidenceDetail: "receiver proof required" },
      ],
    },
  });

  assert.equal(model.passiveStatusAvailable, true);
  assert.equal(model.engineState, "active");
  assert.deepEqual(model.channels.map(({ id, statusLabel, tone, observed }) => ({ id, statusLabel, tone, observed })), [
    { id: "clickhouse", statusLabel: "needs row proof", tone: "warn", observed: false },
    { id: "json-file", statusLabel: "observed locally", tone: "ok", observed: true },
    { id: "json-stream", statusLabel: "needs receiver proof", tone: "warn", observed: false },
  ]);
  assert.match(model.healthChecks.join("\n"), /\/v1\/system\/telemetry\/exports\/status/);

  const packet = telemetryEvidencePacket(model, { collectedAt: "2026-06-19T15:06:00Z" });
  assert.equal(packet.pipeline.passiveStatus.available, true);
  assert.equal(packet.pipeline.passiveStatus.runningPolicyVersion, 7);
  assert.ok(packet.sinks.some((sink) => sink.id === "json-file" && sink.observed === true && sink.evidenceState === "receiving"));
}

{
  const model = telemetryReadinessModel({ status: {}, telemetry: undefined });

  assert.equal(model.active, false);
  assert.equal(model.tone, "neutral");
  assert.equal(model.pipelineLabel, "off");
  assert.equal(model.channels[0].statusLabel, "disabled");
  assert.match(model.summary, /no alternate syslog or continuous JSON export sink/);
  assert.match(model.limitations.join("\n"), /Settings stages telemetry\.enabled, clickhouse_url, database, and explicit JSON export sinks/);

  const disabledCommands = telemetryEvidenceCommands(model);
  assert.ok(disabledCommands.some((item) => item.label === "Passive export status" && item.command === "ngfwctl system telemetry-export-status --json"));
  assert.ok(disabledCommands.some((item) => item.label === "Candidate telemetry" && item.command === "ngfwctl policy show --source candidate --json"));
  assert.equal(disabledCommands.some((item) => item.label === "ClickHouse rows"), false);
}

{
  const model = telemetryReadinessModel({
    status: { engines: [{ name: "vector", state: "ready" }] },
    telemetry: {
      enabled: true,
      clickhouseUrl: "https://user:secret@clickhouse.example:8443?access_token=secret-token&database=system",
      database: "openngfw",
      exports: [
        { name: "siem-json", enabled: true, type: TELEMETRY_EXPORT_TYPE_JSON_TCP, target: "siem.example:5514" },
      ],
    },
  });
  const text = telemetryEvidenceText(model);
  assert.equal(text.includes("user:secret"), false);
  assert.equal(text.includes("secret-token"), false);
  assert.equal(text.includes("database=system"), false);
  assert.match(text, /access_token=%5Bredacted%5D/);

  const packetJSON = telemetryEvidencePacketJson(model, { collectedAt: "2026-06-19T15:00:00Z" });
  for (const leaked of ["user:secret", "secret-token", "database=system"]) {
    assert.equal(packetJSON.includes(leaked), false, `packet leaked ${leaked}`);
  }
  assert.match(packetJSON, /access_token=%5Bredacted%5D/);
}
