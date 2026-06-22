// Shared pivots from evidence views into Troubleshoot. The route keeps the
// original flow tuple intact and asks Troubleshoot to run exactly once.

export function investigationRouteFromFlow(flow = {}, opts = {}) {
  const intent = investigationIntent(opts.intent);
  const route = {
    src: stringValue(flow.srcIp),
    sport: portText(flow.srcPort),
    dst: stringValue(flow.destIp),
    dport: portText(flow.destPort),
    protocol: protocolParam(flow.protocol),
    app: appParam(flow.appId),
    flowId: stringValue(flow.flowId),
    source: policySourceParam(flow),
    version: policyVersionText(flow),
    runtime: "1",
    run: "1",
    intent,
  };
  if (flow.fromZone || flow.srcZone) route.fromZone = stringValue(flow.fromZone || flow.srcZone);
  if (flow.toZone || flow.destZone) route.toZone = stringValue(flow.toZone || flow.destZone);
  return compactRoute(route);
}

export function investigationRouteFromAlert(alert = {}, opts = {}) {
  return investigationRouteFromFlow({
    srcIp: alert.srcIp,
    srcPort: alert.srcPort,
    destIp: alert.destIp,
    destPort: alert.destPort,
    protocol: alert.protocol,
    appId: alert.appId,
    flowId: alert.flowId,
    policyVersionKnown: alert.policyVersionKnown,
    policyVersion: alert.policyVersion,
    fromZone: alert.fromZone,
    toZone: alert.toZone,
  }, opts);
}

export function investigationHashFromFlow(flow = {}, opts = {}) {
  return troubleshootHash(investigationRouteFromFlow(flow, opts));
}

export function investigationHashFromAlert(alert = {}, opts = {}) {
  return troubleshootHash(investigationRouteFromAlert(alert, opts));
}

export function openTroubleshootInvestigation(source = {}, opts = {}) {
  const route = opts.kind === "alert"
    ? investigationRouteFromAlert(source, opts)
    : investigationRouteFromFlow(source, opts);
  const hash = troubleshootHash(route);
  if (typeof location !== "undefined") location.hash = hash;
  return hash;
}

function troubleshootHash(route = {}) {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(route)) {
    if (value === "" || value == null) continue;
    q.set(key, String(value));
  }
  const query = q.toString();
  return "#/troubleshoot" + (query ? "?" + query : "");
}

function compactRoute(route = {}) {
  return Object.fromEntries(Object.entries(route).filter(([, value]) => value !== "" && value != null));
}

function investigationIntent(value) {
  return value === "capture" ? "capture" : "explain";
}

function appParam(value) {
  const app = stringValue(value);
  if (!app || app === "unknown") return "";
  return app;
}

function policyVersionText(flow = {}) {
  if (!flow.policyVersionKnown) return "";
  const n = Number(flow.policyVersion);
  return Number.isFinite(n) && n > 0 ? String(Math.trunc(n)) : "";
}

function policySourceParam(flow = {}) {
  return policyVersionText(flow) ? "POLICY_SOURCE_VERSION" : "";
}

function portText(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 && n <= 65535 ? String(Math.trunc(n)) : "";
}

function protocolParam(value) {
  const proto = String(value || "").toUpperCase().replace(/^PROTOCOL_/, "");
  if (proto === "TCP") return "PROTOCOL_TCP";
  if (proto === "UDP") return "PROTOCOL_UDP";
  if (proto === "ICMP") return "PROTOCOL_ICMP";
  if (proto === "ANY" || proto === "IP") return "PROTOCOL_ANY";
  return "PROTOCOL_TCP";
}

function stringValue(value) {
  return String(value ?? "").trim();
}
