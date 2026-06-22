export const NAT_PREVIEW_ROUTE_DEFAULTS = Object.freeze({
  fromZone: "",
  toZone: "",
  protocol: "PROTOCOL_TCP",
  srcIp: "",
  srcPort: "",
  destIp: "",
  destPort: "",
  run: false,
  caseKey: "",
  caseAction: "",
  caseKind: "",
});

export const NAT_PREVIEW_ROUTE_KEYS = Object.freeze(Object.keys(NAT_PREVIEW_ROUTE_DEFAULTS));

export function representativeNatFlow(policy = {}) {
  const dnat = (policy.nat?.destination || [])[0];
  if (dnat) {
    return destinationNatPreviewFlow(policy, dnat);
  }

  const snat = (policy.nat?.source || [])[0];
  if (snat) {
    return {
      fromZone: firstOtherZone(policy.zones, snat.toZone),
      toZone: snat.toZone || "",
      srcIp: addressIp(policy, snat.sourceAddress) || representativeZoneIp(policy, firstOtherZone(policy.zones, snat.toZone)) || "",
      srcPort: "51515",
      destIp: representativeOutsideIp(policy, snat.toZone),
      destPort: "443",
      protocol: "PROTOCOL_TCP",
    };
  }

  const zones = (policy.zones || []).map((z) => z.name).filter(Boolean);
  return {
    fromZone: zones[0] || "",
    toZone: zones[1] || "",
    srcIp: representativeZoneIp(policy, zones[0]) || "10.0.1.20",
    srcPort: "51515",
    destIp: representativeZoneIp(policy, zones[1]) || "10.0.2.20",
    destPort: "443",
    protocol: "PROTOCOL_TCP",
  };
}

export function destinationNatPreviewFlow(policy = {}, dnat = {}, targetZone = "") {
  const service = findByName(policy.services, dnat.service) || {};
  const protocol = tcpUdpProtocol(service.protocol) || "PROTOCOL_TCP";
  const destPort = firstPort(service.ports) || 443;
  return {
    fromZone: dnat.fromZone || "",
    toZone: targetZone || firstOtherZone(policy.zones, dnat.fromZone),
    srcIp: representativeOutsideIp(policy, dnat.fromZone),
    srcPort: "51515",
    destIp: addressIp(policy, dnat.destinationAddress) || "",
    destPort: String(destPort),
    protocol,
  };
}

export function sourceNatDeleteImpactReview(policy = {}, snat = {}, opts = {}) {
  const flow = sourceNatPreviewFlow(policy, snat);
  const fallback = sourceNatFallbackRule(policy, snat, opts.index);
  const commands = sourceNatDeleteReviewCommands(flow);
  return {
    ruleName: String(snat.name || "unnamed"),
    affectedSourceZones: affectedSourceZones(policy, snat, flow),
    sourceAddress: snat.sourceAddress || "any source",
    egressZone: snat.toZone || "any egress zone",
    translatedAction: snat.masquerade || !snat.translatedAddress
      ? "masquerade on egress interface"
      : `static source ${snat.translatedAddress}`,
    flow,
    candidateEffect: fallback
      ? `After deletion, candidate traffic may fall through to source NAT ${fallback.name || "unnamed"} before leaving ${snat.toZone || "the egress zone"}.`
      : "After deletion, candidate traffic no longer uses this source translation unless another broader rule matches.",
    fallbackRule: fallback?.name || "",
    previewHash: buildNatPreviewHash({ ...flow, run: true }, { path: "/nat" }),
    troubleshootHash: troubleshootHashFromNatPreview({ ...flow, run: true }, { runtime: true, intent: "compare" }),
    explainApi: {
      running: explainRequestFromFlow(flow, "POLICY_SOURCE_RUNNING"),
      candidate: explainRequestFromFlow(flow, "POLICY_SOURCE_CANDIDATE"),
    },
    commands,
  };
}

export function normalizeNatPreviewRouteState(query = {}) {
  return {
    fromZone: stringValue(query.fromZone),
    toZone: stringValue(query.toZone),
    protocol: protocolValue(query.protocol || NAT_PREVIEW_ROUTE_DEFAULTS.protocol),
    srcIp: stringValue(query.srcIp || query.src),
    srcPort: portText(query.srcPort || query.sport),
    destIp: stringValue(query.destIp || query.dst),
    destPort: portText(query.destPort || query.dport),
    run: booleanValue(query.run || query.autorun || query.autoRun),
    caseKey: caseRouteToken(query.caseKey),
    caseAction: caseRouteToken(query.caseAction, 80),
    caseKind: caseRouteToken(query.caseKind, 80),
  };
}

export function buildNatPreviewRouteState(flow = {}, opts = {}) {
  return natPreviewRouteStateFromFlow(flow, opts);
}

export function natPreviewRouteStateFromFlow(flow = {}, opts = {}) {
  return normalizeNatPreviewRouteState({
    fromZone: flow.fromZone,
    toZone: flow.toZone,
    protocol: flow.protocol,
    srcIp: flow.srcIp,
    srcPort: flow.srcPort,
    destIp: flow.destIp,
    destPort: flow.destPort,
    run: opts.run ?? flow.run,
    caseKey: opts.caseKey ?? flow.caseKey,
    caseAction: opts.caseAction ?? flow.caseAction,
    caseKind: opts.caseKind ?? flow.caseKind,
  });
}

export function buildNatPreviewHash(route = {}, opts = {}) {
  return routeHash(opts.path || "/nat", normalizeNatPreviewRouteState(route), NAT_PREVIEW_ROUTE_DEFAULTS, NAT_PREVIEW_ROUTE_KEYS);
}

export function troubleshootRouteStateFromNatPreview(route = {}, opts = {}) {
  const q = normalizeNatPreviewRouteState(route);
  return compactRoute({
    source: opts.source || "POLICY_SOURCE_CANDIDATE",
    fromZone: q.fromZone,
    toZone: q.toZone,
    src: q.srcIp,
    sport: q.srcPort,
    dst: q.destIp,
    dport: q.destPort,
    protocol: q.protocol,
    runtime: opts.runtime ? "1" : "",
    run: q.run ? "1" : "",
    intent: opts.intent || "explain",
  });
}

export function troubleshootHashFromNatPreview(route = {}, opts = {}) {
  const state = troubleshootRouteStateFromNatPreview(route, opts);
  return routeHash("/troubleshoot", state, {}, Object.keys(state));
}

export function explainRequestFromFlow(flow = {}, policySource = "POLICY_SOURCE_CANDIDATE") {
  return {
    policySource,
    version: "0",
    fromZone: String(flow.fromZone || ""),
    toZone: String(flow.toZone || ""),
    srcIp: String(flow.srcIp || "").trim(),
    srcPort: numberOrZero(flow.srcPort),
    destIp: String(flow.destIp || "").trim(),
    destPort: numberOrZero(flow.destPort),
    protocol: flow.protocol || "PROTOCOL_TCP",
    appId: "",
  };
}

export function natPathDelta(running = null, candidate = null) {
  const rows = [
    deltaRow("Decision", decisionLabel(running), decisionLabel(candidate), decisionChanged(running, candidate) ? "bad" : ""),
    deltaRow("Matched rule", ruleLabel(running), ruleLabel(candidate), valueChanged(ruleLabel(running), ruleLabel(candidate)) ? "warn" : ""),
    deltaRow("DNAT", dnatLabel(running), dnatLabel(candidate), natSideChanged(running, candidate, "destination") ? "warn" : ""),
    deltaRow("SNAT", snatLabel(running), snatLabel(candidate), natSideChanged(running, candidate, "source") ? "warn" : ""),
    deltaRow("Route", routeLabel(running), routeLabel(candidate), routeChanged(running, candidate) ? "warn" : ""),
    deltaRow("Egress", egressLabel(running), egressLabel(candidate), valueChanged(egressLabel(running), egressLabel(candidate)) ? "warn" : ""),
  ];
  const changed = rows.some((row) => row.changed);
  return {
    changed,
    tone: decisionChanged(running, candidate) ? "bad" : changed ? "warn" : "ok",
    headline: !running && candidate ? "Candidate path only" : changed ? "Candidate changes path behavior" : "Candidate matches running path",
    rows,
    warnings: unique([
      ...(running?.warnings || []),
      ...(candidate?.warnings || []),
      ...routeWarnings(candidate),
    ]),
  };
}

export function natPathCouplingReview(running = null, candidate = null, flow = {}) {
  const delta = natPathDelta(running, candidate);
  const changedLabels = new Set(delta.rows.filter((row) => row.changed).map((row) => row.label));
  const items = [];
  const add = (key, label, detail, tone = "warn", href = "") => items.push({ key, label, detail, tone, href });
  const matchedRule = candidate?.matchedRule || "";

  if (changedLabels.has("Decision") || changedLabels.has("Matched rule")) {
    add("policy", "Policy decision", policyReviewDetail(candidate), decisionChanged(running, candidate) ? "bad" : "warn",
      matchedRule ? `#/rules?rule=${encodeURIComponent(matchedRule)}` : "#/rules");
  }
  if (changedLabels.has("DNAT")) {
    add("dnat", "Destination NAT", natReviewDetail(candidate, "destination"), "warn", buildNatPreviewHash(flow, { path: "/nat" }));
  }
  if (changedLabels.has("SNAT")) {
    add("snat", "Source NAT", natReviewDetail(candidate, "source"), "warn", buildNatPreviewHash(flow, { path: "/nat" }));
  }
  if (changedLabels.has("Route") || changedLabels.has("Egress")) {
    add("route", "Route and egress", routeReviewDetail(candidate), "warn", "#/netvpn");
  }
  if (!items.length) {
    add("aligned", "Coupling aligned", "Running and candidate policy agree for policy, NAT, route, and egress on this tuple.", "ok", "");
  }

  const actions = [
    {
      key: "troubleshoot",
      label: "Open running/candidate compare",
      detail: "Replay the same tuple in Troubleshoot with NAT and route evidence.",
      href: troubleshootHashFromNatPreview(flow, { runtime: true, intent: "compare" }),
    },
  ];
  if (delta.changed) {
    actions.push({
      key: "candidate",
      label: "Review candidate diff",
      detail: "Confirm the NAT, security rule, and route sections before commit.",
      href: "#/changes?tab=candidate",
    });
  }

  return {
    changed: delta.changed,
    tone: delta.tone,
    summary: delta.changed
      ? "Candidate path changes cross policy, NAT, or route boundaries; review each affected decision before commit."
      : "Candidate path is aligned with running for this tuple.",
    items,
    actions,
  };
}

export function routeProfileLines(profile = {}) {
  if (!profile) return [];
  const lines = [];
  if (profile.reason) lines.push(profile.reason);
  if (profile.source) lines.push("source: " + profile.source);
  if (profile.destination) lines.push("destination: " + profile.destination);
  if (profile.nextHop) lines.push("next hop: " + profile.nextHop);
  if (profile.egressInterface) lines.push("interface: " + profile.egressInterface);
  if (profile.metric) lines.push("metric: " + profile.metric);
  return lines;
}

function policyReviewDetail(result = {}) {
  const verdict = decisionLabel(result);
  const rule = ruleLabel(result);
  return `Candidate decision ${verdict}; matched ${rule}.`;
}

function natReviewDetail(result = {}, side = "") {
  const label = side === "destination" ? dnatLabel(result) : snatLabel(result);
  return label === "not run" ? "Candidate NAT was not evaluated." : `Candidate ${side === "destination" ? "DNAT" : "SNAT"}: ${label}.`;
}

function routeReviewDetail(result = {}) {
  const route = routeLabel(result);
  const egress = egressLabel(result);
  return `Candidate route ${route}; egress ${egress || "-"}.`;
}

function sourceNatPreviewFlow(policy = {}, snat = {}) {
  const fromZone = firstOtherZone(policy.zones, snat.toZone);
  return {
    fromZone,
    toZone: snat.toZone || "",
    srcIp: addressIp(policy, snat.sourceAddress) || representativeZoneIp(policy, fromZone) || "10.0.1.20",
    srcPort: "51515",
    destIp: representativeOutsideIp(policy, snat.toZone),
    destPort: "443",
    protocol: "PROTOCOL_TCP",
  };
}

function affectedSourceZones(policy = {}, snat = {}, flow = {}) {
  const zones = (policy.zones || []).map((z) => z.name || z).filter(Boolean);
  const candidates = zones.filter((zone) => zone !== snat.toZone);
  return candidates.length ? candidates : [flow.fromZone || "any source zone"];
}

function sourceNatFallbackRule(policy = {}, snat = {}, index = -1) {
  const rules = policy.nat?.source || [];
  return rules.find((rule, idx) =>
    idx !== index &&
    rule?.toZone === snat.toZone &&
    (!rule.sourceAddress || !snat.sourceAddress || rule.sourceAddress === snat.sourceAddress));
}

function sourceNatDeleteReviewCommands(flow = {}) {
  const proto = cliProtocol(flow.protocol);
  const base = [
    ["--from-zone", flow.fromZone],
    ["--to-zone", flow.toZone],
    ["--src", flow.srcIp],
    ["--dst", flow.destIp],
    ["--protocol", proto],
    ["--sport", flow.srcPort],
    ["--dport", flow.destPort],
  ].filter(([, value]) => String(value || "").trim());
  return [
    cliCommand("ngfwctl explain", [["--source", "running"], ...base]),
    cliCommand("ngfwctl explain", [["--source", "candidate"], ...base]),
    "ngfwctl policy diff",
    "ngfwctl policy validate",
  ];
}

function cliProtocol(protocol = "") {
  return label(protocol, "PROTOCOL_");
}

function cliCommand(command = "", args = []) {
  const parts = [command];
  for (const [key, value] of args) {
    if (value == null || value === "") continue;
    parts.push(key, shellQuote(String(value)));
  }
  return parts.join(" ");
}

function shellQuote(value = "") {
  return /^[A-Za-z0-9_./:-]+$/.test(value) ? value : "'" + value.replaceAll("'", "'\\''") + "'";
}

function deltaRow(label, running, candidate, tone = "") {
  const r = running || "-";
  const c = candidate || "-";
  return { label, running: r, candidate: c, changed: valueChanged(r, c), tone };
}

function caseRouteToken(value = "", limit = 320) {
  const text = String(value || "").trim();
  if (!text || text.length > limit) return "";
  if (/[\u0000-\u001f\u007f]/.test(text)) return "";
  if (/bearer|token|secret|password|\/var\/|\/etc\/|\/tmp\/|file:/i.test(text)) return "";
  return text;
}

function valueChanged(a, b) {
  return String(a || "-") !== String(b || "-");
}

function decisionChanged(running, candidate) {
  return valueChanged(decisionLabel(running), decisionLabel(candidate));
}

function natSideChanged(running, candidate, side) {
  return valueChanged(natSideKey(running, side), natSideKey(candidate, side));
}

function natSideKey(result, side) {
  const p = result?.natProfile || result?.natDecision || {};
  const part = p?.[side] || {};
  return [
    part.evaluated ? "evaluated" : "not-evaluated",
    part.matched ? "matched" : "no-match",
    part.matchedRule || "",
    side === "destination" ? part.translatedDestinationIp || "" : part.translatedSourceIp || "",
    side === "destination" ? part.translatedDestinationPort || "" : part.masquerade ? "masquerade" : "",
  ].join("|");
}

function routeChanged(running, candidate) {
  const key = (r) => {
    const p = r?.routeProfile || {};
    return [p.evaluated, p.matched, p.destination, p.nextHop, p.egressInterface, p.metric, p.source].join("|");
  };
  return valueChanged(key(running), key(candidate));
}

function verdictLabel(result) {
  const v = label(result?.verdict, "EXPLAIN_VERDICT_");
  return v === "unspecified" ? "not run" : v;
}

function decisionLabel(result) {
  if (!result) return "not run";
  if (result.decisionSummary) return result.decisionSummary;
  const terms = Array.isArray(result.decisionTerms) ? result.decisionTerms : [];
  const labels = terms
    .map((term) => label(term, "EXPLAIN_DECISION_TERM_").replace(/\bfail open\b/g, "fail-open").replace(/\bfail closed\b/g, "fail-closed"))
    .filter(Boolean);
  return labels.length ? labels.join(", ") : verdictLabel(result);
}

function ruleLabel(result) {
  if (!result) return "not run";
  if (result.matchedRule) return `${result.matchedRule} (#${Number(result.matchedRuleIndex || 0) + 1})`;
  if (result.defaultPolicy) return "default policy";
  return "none";
}

function dnatLabel(result) {
  const d = (result?.natProfile || result?.natDecision || {})?.destination || {};
  if (!result) return "not run";
  if (d.matched) return `${d.matchedRule || "matched"}: ${endpoint(d.originalDestinationIp, d.originalDestinationPort)} -> ${endpoint(d.translatedDestinationIp, d.translatedDestinationPort)}`;
  if (d.evaluated) return "no match";
  return "not evaluated";
}

function snatLabel(result) {
  const s = (result?.natProfile || result?.natDecision || {})?.source || {};
  if (!result) return "not run";
  if (s.matched) return `${s.matchedRule || "matched"}: ${s.originalSourceIp || "source"} -> ${s.masquerade ? "masquerade" : s.translatedSourceIp || "translated source"}`;
  if (s.evaluated) return "no match";
  return "not evaluated";
}

function routeLabel(result) {
  const r = result?.routeProfile || {};
  if (!result) return "not run";
  if (!r.evaluated) return "not evaluated";
  if (r.matched) return r.destination || "matched";
  return r.source || "unresolved";
}

function egressLabel(result) {
  const r = result?.routeProfile || {};
  if (!result) return "not run";
  return [r.nextHop ? "via " + r.nextHop : "", r.egressInterface ? "dev " + r.egressInterface : ""].filter(Boolean).join(" ") || "-";
}

function routeWarnings(result) {
  const r = result?.routeProfile || {};
  if (!r.evaluated || r.matched) return [];
  return r.reason ? ["candidate route unresolved: " + r.reason] : ["candidate route unresolved"];
}

function label(value, prefix) {
  return String(value || "unspecified").replace(prefix, "").replaceAll("_", " ").toLowerCase();
}

function endpoint(ip, port) {
  const value = String(ip || "").trim();
  const n = Number(port || 0);
  return n > 0 ? `${value}:${n}` : value || "-";
}

function findByName(items = [], name = "") {
  return (items || []).find((x) => x?.name === name);
}

function addressIp(policy = {}, name = "") {
  const cidr = findByName(policy.addresses, name)?.cidr || "";
  return representativeIp(cidr);
}

function representativeZoneIp(policy = {}, zoneName = "") {
  const lower = String(zoneName || "").toLowerCase();
  const object = (policy.addresses || []).find((a) => {
    const hay = `${a.name || ""} ${a.description || ""}`.toLowerCase();
    return lower && hay.includes(lower);
  }) || (policy.addresses || [])[0];
  return representativeIp(object?.cidr || "");
}

function representativeOutsideIp(policy = {}, avoidZone = "") {
  if (isExternalZone(avoidZone)) return "198.51.100.10";
  const zones = (policy.zones || []).map((z) => z.name).filter(Boolean);
  return representativeZoneIp(policy, firstOtherZone(policy.zones, avoidZone)) || (zones.length ? "198.51.100.10" : "203.0.113.10");
}

function isExternalZone(zone = "") {
  return /^(outside|untrust|internet|wan|external)$/i.test(String(zone || ""));
}

function firstOtherZone(zones = [], zone = "") {
  return (zones || []).map((z) => z.name || z).find((name) => name && name !== zone) || "";
}

function representativeIp(value = "") {
  const raw = String(value || "").trim();
  if (!raw) return "";
  const [addr, prefixText] = raw.split("/");
  if (!addr.includes(".") || prefixText == null) return addr;
  const prefix = Number(prefixText);
  const octets = addr.split(".").map((part) => Number(part));
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return addr;
  if (prefix >= 32) return addr;
  if (octets[3] === 0) octets[3] = 1;
  else if (octets[3] === 255) octets[3] = 254;
  return octets.join(".");
}

function firstPort(ports = []) {
  const p = (ports || [])[0] || {};
  return Number(p.start || p.from || p.port || 0) || 0;
}

function tcpUdpProtocol(protocol = "") {
  return protocol === "PROTOCOL_TCP" || protocol === "PROTOCOL_UDP" ? protocol : "";
}

function protocolValue(value = "") {
  const proto = String(value || "").toUpperCase().replace(/^PROTOCOL_/, "");
  if (proto === "TCP") return "PROTOCOL_TCP";
  if (proto === "UDP") return "PROTOCOL_UDP";
  if (proto === "ICMP") return "PROTOCOL_ICMP";
  if (proto === "ANY" || proto === "IP") return "PROTOCOL_ANY";
  return NAT_PREVIEW_ROUTE_DEFAULTS.protocol;
}

function stringValue(value) {
  return String(value ?? "").trim();
}

function portText(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 && n <= 65535 ? String(Math.trunc(n)) : "";
}

function booleanValue(value) {
  return value === true || value === 1 || value === "1" || value === "true";
}

function numberOrZero(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.trunc(n) : 0;
}

function routeHash(path, state = {}, defaults = {}, keys = Object.keys(state)) {
  const params = new URLSearchParams();
  for (const key of keys) {
    const value = state[key];
    if (routeDefaultValue(value, defaults[key])) continue;
    const serialized = routeValue(value);
    if (serialized === "") continue;
    params.set(key, serialized);
  }
  const query = params.toString();
  return "#" + (path || "/") + (query ? "?" + query : "");
}

function routeDefaultValue(value, defaultValue) {
  if (value == null) return true;
  if (typeof value === "string" && value === "") return true;
  return String(value) === String(defaultValue ?? "");
}

function routeValue(value) {
  if (typeof value === "boolean") return value ? "1" : "0";
  return String(value ?? "").trim();
}

function compactRoute(route = {}) {
  return Object.fromEntries(Object.entries(route).filter(([, value]) => value !== "" && value != null));
}

function unique(values = []) {
  return Array.from(new Set(values.filter(Boolean)));
}
