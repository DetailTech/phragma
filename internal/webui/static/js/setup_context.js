// Shared Guided Setup route and CLI helpers. Keep this dependency-free so the
// setup view and automation-context drawer can both use the same command shape.

export const SETUP_ROUTE_KEYS = Object.freeze([
  "scenario",
  "profile",
  "insideZone",
  "outsideZone",
  "insideInterfaces",
  "outsideInterfaces",
  "insideCidr",
  "webuiPort",
  "mtu",
  "allowOutbound",
  "masquerade",
  "hardenHostInput",
  "clampMss",
  "flowOffload",
  "manageNicOffloads",
  "idsRuleFiles",
  "idsQueueNum",
  "failureBehavior",
]);

export function setupRouteHashFromConfig(config = {}) {
  const params = new URLSearchParams();
  for (const key of SETUP_ROUTE_KEYS) {
    const value = setupRouteValue(config[key]);
    if (value !== "") params.set(key, value);
  }
  const query = params.toString();
  return "#/setup" + (query ? `?${query}` : "");
}

export function setupConfigFromQuery(query = {}, defaults = {}) {
  const read = (key) => {
    if (query instanceof URLSearchParams) return query.get(key);
    return query?.[key];
  };
  const out = { ...defaults };
  for (const key of SETUP_ROUTE_KEYS) {
    const value = read(key);
    if (value === undefined || value === null || value === "") continue;
    out[key] = booleanSetupKey(key) ? setupBoolean(value) : String(value);
  }
  return out;
}

export function setupBaselineCliCommand(config = {}) {
  const c = normalizeSetupConfig(config);
  const parts = ["ngfwctl", "policy", "baseline"];
  addFlag(parts, "--profile", c.profile);
  addFlag(parts, "--inside-zone", c.insideZone);
  addFlag(parts, "--outside-zone", c.outsideZone);
  for (const name of splitSetupList(c.insideInterfaces)) addFlag(parts, "--inside-interface", name);
  for (const name of splitSetupList(c.outsideInterfaces)) addFlag(parts, "--outside-interface", name);
  addFlag(parts, "--inside-cidr", c.insideCidr);
  addFlag(parts, "--webui-port", c.webuiPort);
  if (c.mtu) addFlag(parts, "--mtu", c.mtu);
  addBoolFlag(parts, "--allow-outbound", c.allowOutbound);
  addBoolFlag(parts, "--masquerade", c.masquerade);
  addBoolFlag(parts, "--harden-host-input", c.hardenHostInput);
  addBoolFlag(parts, "--flow-offload", c.flowOffload);
  addBoolFlag(parts, "--clamp-mss", c.clampMss);
  addBoolFlag(parts, "--manage-nic-offloads", c.manageNicOffloads);
  if (c.profile === "ids-detect" || c.profile === "ips-prevent") {
    for (const file of splitSetupList(c.idsRuleFiles || "local.rules")) addFlag(parts, "--ids-rule-file", file);
  }
  if (c.profile === "ips-prevent") {
    addFlag(parts, "--ids-queue", c.idsQueueNum || "0");
    addFlag(parts, "--ids-failure-behavior", idsFailureCliValue(c.failureBehavior));
  }
  return parts.map(shellArgIfNeeded).join(" ");
}

export function setupContextSummary(config = {}) {
  const c = normalizeSetupConfig(config);
  const bits = [
    c.scenario ? `scenario ${c.scenario}` : "",
    `profile ${c.profile}`,
    `${c.insideZone || "inside"} -> ${c.outsideZone || "outside"}`,
    c.allowOutbound ? "outbound allow staged" : "no outbound allow",
    c.masquerade ? "source NAT staged" : "no source NAT",
    c.flowOffload ? "flow offload on" : "flow offload off",
  ].filter(Boolean);
  return bits.join("; ");
}

export function normalizeSetupConfig(config = {}) {
  return {
    scenario: safeText(config.scenario, 64),
    profile: choice(config.profile, ["throughput", "ids-detect", "ips-prevent"], "throughput"),
    insideZone: safeText(config.insideZone, 64) || "lan",
    outsideZone: safeText(config.outsideZone, 64) || "wan",
    insideInterfaces: safeListText(config.insideInterfaces) || "eth1",
    outsideInterfaces: safeListText(config.outsideInterfaces) || "eth0",
    insideCidr: safeText(config.insideCidr, 64) || "10.0.0.0/24",
    webuiPort: portText(config.webuiPort) || "8080",
    mtu: numberText(config.mtu, 1, 65535),
    allowOutbound: setupBoolean(config.allowOutbound),
    masquerade: setupBoolean(config.masquerade),
    hardenHostInput: setupBoolean(config.hardenHostInput),
    clampMss: setupBoolean(config.clampMss),
    flowOffload: setupBoolean(config.flowOffload),
    manageNicOffloads: setupBoolean(config.manageNicOffloads),
    idsRuleFiles: safeListText(config.idsRuleFiles) || "local.rules",
    idsQueueNum: numberText(config.idsQueueNum, 0, 65535) || "0",
    failureBehavior: choice(config.failureBehavior, ["IDS_FAILURE_BEHAVIOR_FAIL_CLOSED", "IDS_FAILURE_BEHAVIOR_FAIL_OPEN"], "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED"),
  };
}

function addFlag(parts, flag, value) {
  const text = String(value || "").trim();
  if (!text) return;
  parts.push(flag, text);
}

function addBoolFlag(parts, flag, value) {
  parts.push(`${flag}=${setupBoolean(value) ? "true" : "false"}`);
}

function setupRouteValue(value) {
  if (typeof value === "boolean") return value ? "1" : "0";
  return safeText(value, 160);
}

function booleanSetupKey(key) {
  return ["allowOutbound", "masquerade", "hardenHostInput", "clampMss", "flowOffload", "manageNicOffloads"].includes(key);
}

function setupBoolean(value) {
  if (value === true) return true;
  const text = String(value ?? "").trim().toLowerCase();
  return ["1", "true", "yes", "on"].includes(text);
}

function splitSetupList(value = "") {
  return String(value || "").split(",").map((part) => safeText(part, 96)).filter(Boolean);
}

function safeListText(value) {
  return splitSetupList(value).join(",");
}

function safeText(value, max = 128) {
  const text = String(value ?? "").trim();
  if (!text || text.length > max || /[\u0000-\u001f\u007f]/.test(text)) return "";
  if (/(^|[/:])(?:etc|tmp|var|Users|home|private)(?:\/|$)|file:/i.test(text)) return "";
  if (/(token|password|secret|authorization|bearer)/i.test(text)) return "";
  return text.replace(/[^\w .,:/@%+=-]/g, "").slice(0, max);
}

function portText(value) {
  return numberText(value, 1, 65535);
}

function numberText(value, min, max) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) return "";
  return String(n);
}

function choice(value, allowed, fallback) {
  const text = String(value || "").trim();
  return allowed.includes(text) ? text : fallback;
}

function idsFailureCliValue(value) {
  return value === "IDS_FAILURE_BEHAVIOR_FAIL_OPEN" ? "fail-open" : "fail-closed";
}

function shellArgIfNeeded(value) {
  const text = String(value);
  if (/^[A-Za-z0-9_./:@%+=-]+$/.test(text)) return text;
  return `"${text.replace(/["\\$`]/g, "\\$&")}"`;
}
