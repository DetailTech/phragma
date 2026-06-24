// baseline.js — candidate-safe first policy builder used by the Rules UI.
// It constructs a practical two-zone firewall baseline without owning the
// product model: the output is ordinary Phragma policy objects.

export const BASELINE_PROFILES = [
  {
    id: "throughput",
    title: "High-throughput edge",
    summary: "Forwarding, SNAT, host-input hardening, and packet filter flowtable acceleration with IDS/IPS off.",
    defaults: {
      inspectionMode: "off",
      flowOffload: true,
      manageNicOffloads: false,
      failureBehavior: "",
    },
  },
  {
    id: "ids-detect",
    title: "IDS detect",
    summary: "IDS/IPS engine detect mode with explicit home networks and NIC offload management; flowtable off.",
    defaults: {
      inspectionMode: "detect",
      flowOffload: false,
      manageNicOffloads: true,
      failureBehavior: "",
    },
  },
  {
    id: "ips-prevent",
    title: "IPS prevent",
    summary: "Inline IDS/IPS engine prevention via NFQUEUE with explicit fail behavior; flowtable off.",
    defaults: {
      inspectionMode: "prevent",
      flowOffload: false,
      manageNicOffloads: false,
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
    },
  },
];

export function policyNeedsBaseline(policy = {}) {
  return !(
    (policy.zones || []).length ||
    (policy.addresses || []).length ||
    (policy.services || []).length ||
    (policy.rules || []).length ||
    (policy.nat?.source || []).length ||
    (policy.nat?.destination || []).length ||
    policy.hostInput
  );
}

export function baselineProfile(id) {
  return BASELINE_PROFILES.find((profile) => profile.id === id) || BASELINE_PROFILES[0];
}

export function previewBaselinePolicy(policy, raw = {}) {
  const next = structuredClone(policy || {});
  const summary = applyBaselinePolicy(next, raw);
  return { policy: next, summary };
}

export function applyBaselinePolicy(policy, raw = {}) {
  const opts = normalizeOptions(raw);
  const summary = { profile: opts.profile, zones: [], addresses: [], services: [], rules: [], nat: [], hostInput: [], network: [], ids: [] };

  const insideZone = upsertZone(policy, {
    name: opts.insideZone,
    interfaces: opts.insideInterfaces,
    description: "Inside/trusted forwarding zone created by baseline setup.",
  });
  const outsideZone = upsertZone(policy, {
    name: opts.outsideZone,
    interfaces: opts.outsideInterfaces,
    description: "Outside/untrusted forwarding zone created by baseline setup.",
  });
  summary.zones.push(insideZone, outsideZone);

  const insideNet = ensureAddress(policy, opts.insideAddressName, opts.insideCidr,
    "Inside network created by baseline setup.");
  summary.addresses.push(insideNet);

  const ssh = ensureService(policy, "ssh", "PROTOCOL_TCP", [{ start: 22 }],
    "SSH management service created by baseline setup.");
  const webui = ensureService(policy, "webui", "PROTOCOL_TCP", [{ start: opts.webuiPort }],
    "Phragma WebUI/API management service created by baseline setup.");
  summary.services.push(ssh, webui);

  if (opts.allowOutbound) {
    upsertRule(policy, "allow-" + insideZone + "-to-" + outsideZone, {
      name: "allow-" + insideZone + "-to-" + outsideZone,
      fromZones: [insideZone],
      toZones: [outsideZone],
      sourceAddresses: [insideNet],
      destinationAddresses: ["any"],
      services: ["any"],
      action: "ACTION_ALLOW",
      log: true,
      disabled: false,
      description: "Baseline outbound rule. Review scope before committing in production.",
    });
    summary.rules.push("allow-" + insideZone + "-to-" + outsideZone);
  }

  if (opts.masquerade) {
    const name = insideZone + "-masq";
    policy.nat ||= {};
    policy.nat.source ||= [];
    upsertByName(policy.nat.source, {
      name,
      toZone: outsideZone,
      sourceAddress: insideNet,
      masquerade: true,
    });
    summary.nat.push(name);
  }

  if (opts.hardenHostInput) {
    const ruleName = "allow-" + insideZone + "-management";
    const host = { ...(policy.hostInput || {}) };
    host.defaultAction = "ACTION_DENY";
    host.rules = [...(host.rules || [])];
    upsertByName(host.rules, {
      name: ruleName,
      fromZones: [insideZone],
      sourceAddresses: [insideNet],
      services: [ssh, webui],
      action: "ACTION_ALLOW",
      log: true,
      disabled: false,
      description: "Baseline management access. Restrict the source object before exposing the appliance.",
    });
    policy.hostInput = host;
    summary.hostInput.push("default deny", ruleName);
  }

  const network = { ...(policy.network || {}) };
  if (opts.clampMss) {
    network.clampMssToPmtu = true;
    summary.network.push("MSS clamp");
  }
  if (opts.manageNicOffloads) {
    network.manageNicOffloads = true;
    summary.network.push("IDS NIC offload management");
  } else if (opts.inspectionMode !== "detect" && "manageNicOffloads" in network) {
    network.manageNicOffloads = false;
  }
  if (opts.flowOffload) {
    network.enableFlowOffload = true;
    summary.network.push("flowtable fast path");
  } else if ("enableFlowOffload" in network) {
    network.enableFlowOffload = false;
  }
  if (opts.mtu > 0) {
    network.mtu = opts.mtu;
    summary.network.push("MTU " + opts.mtu);
  }
  if (Object.keys(network).length) policy.network = network;

  applyInspection(policy, opts, summary);

  return summary;
}

function normalizeOptions(raw = {}) {
  const profile = baselineProfile(raw.profile || "throughput");
  const defaults = profile.defaults || {};
  const insideZone = sanitizeName(raw.insideZone || "lan");
  const outsideZone = sanitizeName(raw.outsideZone || "wan");
  const insideCidr = String(raw.insideCidr || "10.0.0.0/24").trim();
  const webuiPort = boundedPort(raw.webuiPort, 8080);
  const mtu = boundedMtu(raw.mtu);
  const inspectionMode = raw.inspectionMode || defaults.inspectionMode || "off";
  let flowOffload = raw.flowOffload != null ? raw.flowOffload !== false : defaults.flowOffload !== false;
  if (inspectionMode !== "off") flowOffload = false;
  const insideInterfaces = splitList(raw.insideInterfaces || "eth1");
  const outsideInterfaces = splitList(raw.outsideInterfaces || "eth0");
  return {
    profile: profile.id,
    insideZone,
    outsideZone,
    insideInterfaces,
    outsideInterfaces,
    insideCidr,
    insideAddressName: sanitizeName(raw.insideAddressName || insideZone + "-net"),
    webuiPort,
    mtu,
    allowOutbound: raw.allowOutbound !== false,
    masquerade: raw.masquerade !== false,
    hardenHostInput: raw.hardenHostInput !== false,
    clampMss: raw.clampMss !== false,
    manageNicOffloads: raw.manageNicOffloads != null ? raw.manageNicOffloads === true : defaults.manageNicOffloads === true,
    flowOffload,
    inspectionMode,
    failureBehavior: raw.failureBehavior || defaults.failureBehavior || "IDS_FAILURE_BEHAVIOR_FAIL_OPEN",
    idsMonitorInterfaces: splitList(raw.idsMonitorInterfaces || [...insideInterfaces, ...outsideInterfaces].join(",")),
    idsHomeNetworks: splitList(raw.idsHomeNetworks || insideCidr),
    idsRuleFiles: splitList(raw.idsRuleFiles || "local.rules"),
    idsQueueNum: boundedQueue(raw.idsQueueNum),
  };
}

function applyInspection(policy, opts, summary) {
  if (opts.inspectionMode === "off") {
    policy.ids = { ...(policy.ids || {}), enabled: false };
    delete policy.ids.failureBehavior;
    summary.ids.push("IDS/IPS disabled");
    return;
  }
  const prevent = opts.inspectionMode === "prevent";
  policy.ids = {
    ...(policy.ids || {}),
    enabled: true,
    mode: prevent ? "IDS_MODE_PREVENT" : "IDS_MODE_DETECT",
    monitorInterfaces: opts.idsMonitorInterfaces,
    homeNetworks: opts.idsHomeNetworks,
    ruleFiles: opts.idsRuleFiles,
    queueNum: opts.idsQueueNum,
  };
  if (prevent) {
    policy.ids.failureBehavior = opts.failureBehavior;
    summary.ids.push(opts.failureBehavior === "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED" ? "IPS prevent fail-closed" : "IPS prevent fail-open");
  } else {
    delete policy.ids.failureBehavior;
    summary.ids.push("IDS detect");
  }
}

function upsertZone(policy, zone) {
  policy.zones ||= [];
  const existing = policy.zones.find((z) => z.name === zone.name);
  if (!existing) {
    policy.zones.push(zone);
    return zone.name;
  }
  const ifaces = new Set([...(existing.interfaces || []), ...zone.interfaces]);
  existing.interfaces = [...ifaces];
  if (!existing.description) existing.description = zone.description;
  return existing.name;
}

function ensureAddress(policy, desiredName, cidr, description) {
  policy.addresses ||= [];
  const sameCidr = policy.addresses.find((a) => a.cidr === cidr);
  if (sameCidr) return sameCidr.name;
  const name = uniqueName(policy.addresses, desiredName);
  policy.addresses.push({ name, cidr, description });
  return name;
}

function ensureService(policy, desiredName, protocol, ports, description) {
  policy.services ||= [];
  const same = policy.services.find((s) =>
    s.protocol === protocol &&
    samePorts(s.ports || [], ports || []));
  if (same) return same.name;
  const name = uniqueName(policy.services, desiredName);
  policy.services.push({ name, protocol, ports, description });
  return name;
}

function upsertRule(policy, name, rule) {
  policy.rules ||= [];
  const existing = policy.rules.find((r) => r.name === name);
  if (existing) Object.assign(existing, rule);
  else policy.rules.push(rule);
}

function upsertByName(list, item) {
  const existing = list.find((x) => x.name === item.name);
  if (existing) Object.assign(existing, item);
  else list.push(item);
}

function samePorts(a, b) {
  if (a.length !== b.length) return false;
  return a.every((p, i) => Number(p.start) === Number(b[i].start) && Number(p.end || 0) === Number(b[i].end || 0));
}

function splitList(value) {
  return String(value || "").split(",").map((x) => x.trim()).filter(Boolean);
}

function boundedPort(value, fallback) {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 && n <= 65535 ? n : fallback;
}

function boundedMtu(value) {
  const n = Number(value);
  return Number.isInteger(n) && n >= 1280 && n <= 9600 ? n : 0;
}

function boundedQueue(value) {
  const n = Number(value);
  return Number.isInteger(n) && n >= 0 && n <= 65535 ? n : 0;
}

function uniqueName(list, base) {
  const clean = sanitizeName(base);
  const names = new Set((list || []).map((x) => x.name));
  if (!names.has(clean)) return clean;
  let i = 2;
  while (names.has(clean + "-" + i)) i++;
  return clean + "-" + i;
}

function sanitizeName(value) {
  let out = String(value || "object").toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
  if (!out) out = "object";
  if (!/^[a-z0-9]/.test(out)) out = "o-" + out;
  out = out.slice(0, 63).replace(/[-_]+$/g, "");
  if (!/[a-z0-9]$/.test(out)) out += "1";
  return out || "object";
}
