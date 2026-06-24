// dataplane.js — shared client-side posture model for the current Linux
// dataplane. The server remains the authority; this only makes policy/runtime
// state easier for operators to read consistently across views.

export const FLOWTABLE_CAPABILITY = "nftables flowtable fast path";
export const FLOWTABLE_RUNTIME_CAPABILITY = "nftables flowtable runtime";
export const KERNEL_TUNING_CAPABILITY = "Kernel forwarding tuning";
export const EBPF_HOST_CAPABILITY = "Linux eBPF XDP/tc host readiness";
export const CONNTRACK_CAPACITY_CAPABILITY = "Conntrack state-table capacity";
export const BASELINE_TUNING_COMMAND = "sudo ngfwctl system tune --write --apply";
export const THROUGHPUT_TUNING_COMMAND = "sudo ngfwctl system tune --profile throughput --write --apply";
export const THROUGHPUT_CONNTRACK_MIN = 4194304;
export const MIN_MTU = 1280;
export const MAX_MTU = 9600;

export function capability(capabilities = [], name) {
  return (capabilities || []).find((c) => c.name === name) || null;
}

function flowtable(status = {}) {
  return status.dataplane?.flowtable || {};
}

function ebpf(status = {}) {
  return status.dataplane?.ebpf || {};
}

export function capabilityClass(state) {
  if (state === "active" || state === "ready") return "ok";
  if (state === "degraded") return "bad";
  if (state === "warning" || state === "planned" || state === "single-worker" || state === "simulation") return "warn";
  return "neutral";
}

export function flowtableHostReadiness(status = {}) {
  const ft = flowtable(status);
  const cap = capability(status.capabilities || [], FLOWTABLE_CAPABILITY);
  const state = ft.hostState || cap?.state || "unknown";
  const ready = state === "ready" || state === "active";
  return {
    ready,
    state,
    cls: capabilityClass(state),
    label: state,
    detail: ft.hostDetail || cap?.detail || "Runtime flowtable capability is not available.",
  };
}

export function flowtableRuntimeEvidence(status = {}) {
  const ft = flowtable(status);
  const cap = capability(status.capabilities || [], FLOWTABLE_RUNTIME_CAPABILITY);
  const state = ft.runtimeState || cap?.state || "unknown";
  const devices = Array.isArray(ft.devices) ? ft.devices : [];
  const packets = Number(ft.packets || 0);
  const bytes = Number(ft.bytes || 0);
  return {
    active: state === "active",
    state,
    cls: capabilityClass(state),
    label: state,
    detail: ft.runtimeDetail || cap?.detail || "Runtime flowtable evidence is not available.",
    devices,
    packets,
    bytes,
    flowtableDeclared: Boolean(ft.flowtableDeclared),
    offloadRulePresent: Boolean(ft.offloadRulePresent),
  };
}

export function kernelTuningStatus(status = {}) {
  const kt = status.dataplane?.kernelTuning || {};
  const cap = capability(status.capabilities || [], KERNEL_TUNING_CAPABILITY);
  const state = kt.state || cap?.state || "unknown";
  return {
    ready: state === "ready" || state === "active",
    state,
    cls: capabilityClass(state),
    label: state,
    detail: kt.detail || cap?.detail || "Kernel forwarding tuning status is not available.",
    configPath: kt.sysctlConfigPath || "",
    checks: Array.isArray(kt.checks) ? kt.checks : [],
  };
}

export function kernelTuningRollup(status = {}) {
  const base = kernelTuningStatus(status);
  const conntrack = conntrackCapacity(status);
  const checks = base.checks.map((check) => {
    const state = check.state || "unknown";
    return {
      name: check.name || check.key || "Kernel setting",
      key: check.key || "",
      current: check.current || "",
      recommended: check.recommended || "",
      state,
      cls: capabilityClass(state),
      detail: check.detail || "",
    };
  });
  const readyCount = checks.filter((check) => check.state === "ready" || check.state === "active").length;
  const degradedCount = checks.filter((check) => check.state === "degraded").length;
  const unknownCount = checks.filter((check) => check.state === "unknown").length;
  const needsAction = base.state === "degraded" || degradedCount > 0;
  const throughputReady = conntrack.maxEntries >= THROUGHPUT_CONNTRACK_MIN;
  const throughputObserved = conntrack.maxEntries > 0;
  return {
    ...base,
    checks,
    readyCount,
    degradedCount,
    unknownCount,
    totalCount: checks.length,
    needsAction,
    remediationCommand: BASELINE_TUNING_COMMAND,
    baselineCommand: BASELINE_TUNING_COMMAND,
    throughputCommand: THROUGHPUT_TUNING_COMMAND,
    throughputConntrackTarget: THROUGHPUT_CONNTRACK_MIN,
    throughputReady,
    throughputCls: throughputReady ? "ok" : throughputObserved ? "warn" : "neutral",
    throughputLabel: throughputReady ? "state-table headroom ready" : "throughput profile available",
    throughputDetail: throughputObserved
      ? `State table limit ${formatWhole(conntrack.maxEntries)}; throughput profile target ${formatWhole(THROUGHPUT_CONNTRACK_MIN)}+.`
      : `State table limit unavailable; throughput profile target ${formatWhole(THROUGHPUT_CONNTRACK_MIN)}+.`,
    readinessLabel: checks.length ? `${readyCount}/${checks.length} ready` : base.state,
  };
}

export function conntrackCapacity(status = {}) {
  const ct = status.dataplane?.conntrack || {};
  const cap = capability(status.capabilities || [], CONNTRACK_CAPACITY_CAPABILITY);
  const state = ct.state || cap?.state || "unknown";
  return {
    ready: state === "ready" || state === "active",
    state,
    cls: capabilityClass(state),
    label: state,
    detail: ct.detail || cap?.detail || "Conntrack state-table capacity is not available.",
    currentEntries: Number(ct.currentEntries || 0),
    maxEntries: Number(ct.maxEntries || 0),
    usagePercent: Number(ct.usagePercent || 0),
    warningThresholdPercent: Number(ct.warningThresholdPercent || 75),
    degradedThresholdPercent: Number(ct.degradedThresholdPercent || 90),
  };
}

export function ebpfHostReadiness(status = {}) {
  const eb = ebpf(status);
  const cap = capability(status.capabilities || [], EBPF_HOST_CAPABILITY);
  const state = eb.state || cap?.state || "unknown";
  const probes = Array.isArray(eb.probes) ? eb.probes : [];
  const attachState = eb.attachState || eb.attach_state || "";
  const attachDetail = eb.attachDetail || eb.attach_detail || "";
  const attachProbes = Array.isArray(eb.attachProbes) ? eb.attachProbes : Array.isArray(eb.attach_probes) ? eb.attach_probes : [];
  const rendererState = eb.rendererState || eb.renderer_state || "";
  const rendererDetail = eb.rendererDetail || eb.renderer_detail || "";
  const supportedHooks = Array.isArray(eb.supportedHooks) ? eb.supportedHooks : Array.isArray(eb.supported_hooks) ? eb.supported_hooks : [];
  const blockers = Array.isArray(eb.blockers) ? eb.blockers : [];
  const attachments = Array.isArray(eb.attachments) ? eb.attachments : [];
  const artifacts = Array.isArray(eb.artifacts) ? eb.artifacts : [];
  const evidenceCollectedAt = eb.evidenceCollectedAt || eb.evidence_collected_at || "";
  const evidenceScope = eb.evidenceScope || eb.evidence_scope || "";
  const degraded = probes.filter((p) => p.state && p.state !== "ready");
  const attachDegraded = attachProbes.filter((p) => p.state && p.state !== "ready");
  return {
    ready: state === "ready" || state === "active",
    attachReady: attachState === "ready" || attachState === "active",
    state,
    cls: capabilityClass(state),
    label: state,
    detail: eb.detail || cap?.detail || "Linux eBPF XDP/tc host readiness is not available.",
    probes,
    attachState,
    attachDetail,
    attachProbes,
    rendererState,
    rendererDetail,
    supportedHooks,
    blockers,
    attachments,
    artifacts,
    evidenceCollectedAt,
    evidenceScope,
    degraded,
    attachDegraded,
  };
}

export function inspectionReadiness(status = {}) {
  const inspection = status.inspection || {};
  const state = inspection.state || "unknown";
  const degraded = state === "degraded" || state === "failed-open" || state === "failed-closed";
  return {
    ...inspection,
    state,
    ready: state === "ready" || state === "disabled",
    cls: state === "failed-open" || state === "failed-closed" ? "bad" : degraded ? "warn" : capabilityClass(state),
    label: state,
    detail: inspection.detail || "Inspection readiness is not available.",
    engineLabel: [inspection.engineName, inspection.engineMode, inspection.engineState].filter(Boolean).join(" "),
  };
}

export function activeDataplaneName(status = {}) {
  return status.dataplane?.activeDataplane || status.runtime?.activeDataplane || "";
}

export function dataplaneNameRequiresEbpf(name = "") {
  const value = String(name || "").toLowerCase();
  return /\b(ebpf|xdp|tc)\b/.test(value);
}

export function ebpfBlocksCurrentDataplane(status = {}, ebpfHost = {}) {
  const state = ebpfHost.state || "unknown";
  if (state === "ready" || state === "active") return false;
  return dataplaneNameRequiresEbpf(activeDataplaneName(status));
}

export function zoneInterfaces(policy = {}) {
  const out = [];
  const seen = new Set();
  for (const zone of policy.zones || []) {
    for (const ifc of zone.interfaces || []) {
      if (!ifc || seen.has(ifc)) continue;
      seen.add(ifc);
      out.push(ifc);
    }
  }
  return out.sort();
}

export function idsEnabled(policy = {}) {
  return Boolean(policy.ids && policy.ids.enabled);
}

export function idsModeLabel(policy = {}) {
  const mode = policy.ids?.mode;
  if (!idsEnabled(policy)) return "disabled";
  if (mode === "IDS_MODE_PREVENT") return "IPS prevent";
  return "IDS detect";
}

export function flowtableCandidateIssues(policy = {}) {
  if (!policy.network?.enableFlowOffload) return [];
  const issues = [];
  if (idsEnabled(policy)) {
    issues.push("Flowtable fast path cannot be staged while IDS/IPS is enabled; offloaded flows can bypass inspection.");
  }
  if (!zoneInterfaces(policy).length) {
    issues.push("Flowtable fast path requires at least one interface assigned to a zone.");
  }
  return issues;
}

export function networkCandidateIssues(policy = {}) {
  const issues = [];
  const network = policy.network || {};
  if (network.mtu && !validMtu(network.mtu)) {
    issues.push(`Global MTU must be 0 or ${MIN_MTU}-${MAX_MTU}.`);
  }
  const seen = new Set();
  for (const item of network.interfaceMtus || []) {
    const name = String(item?.interface || "").trim();
    if (!name) {
      issues.push("Per-interface MTU entries require an interface name.");
      continue;
    }
    if (seen.has(name)) {
      issues.push(`Per-interface MTU for ${name} is duplicated.`);
      continue;
    }
    seen.add(name);
    if (!validMtu(item?.mtu)) {
      issues.push(`MTU for ${name} must be ${MIN_MTU}-${MAX_MTU}.`);
    }
  }
  return [...issues, ...flowtableCandidateIssues(policy)];
}

function validMtu(value) {
  const mtu = Number(value);
  return Number.isInteger(mtu) && mtu >= MIN_MTU && mtu <= MAX_MTU;
}

function formatWhole(value) {
  return Number(value || 0).toLocaleString("en-US", { maximumFractionDigits: 0 });
}

export function dataplanePosture(policy = {}, status = {}) {
  const devices = zoneInterfaces(policy);
  const flow = Boolean(policy.network?.enableFlowOffload);
  const inspected = idsEnabled(policy);
  const baseDataplane = activeDataplaneName(status) || "nftables/conntrack";

  if (flow && inspected) {
    return {
      state: "invalid",
      cls: "bad",
      label: "Invalid candidate",
      summary: "Flowtable fast path conflicts with IDS/IPS.",
      detail: "Offloaded flows can bypass inspection. Disable IDS/IPS or turn off flowtable before commit.",
      action: "Resolve before commit",
      baseDataplane,
      devices,
      accelerated: false,
      inspected: true,
    };
  }

  if (flow && !devices.length) {
    return {
      state: "invalid",
      cls: "bad",
      label: "Missing interfaces",
      summary: "Flowtable fast path needs at least one zone interface.",
      detail: "Assign interfaces to zones before enabling the fast path.",
      action: "Add zone interfaces",
      baseDataplane,
      devices,
      accelerated: false,
      inspected: false,
    };
  }

  if (flow) {
    return {
      state: "accelerated",
      cls: "ok",
    label: "Forwarding acceleration",
    summary: "Established L3/L4 forwarding can use acceleration.",
      detail: `${devices.length} interface${devices.length === 1 ? "" : "s"} eligible: ${devices.join(", ")}.`,
      action: "Benchmark forwarding and keep IDS/IPS disabled on this profile",
      baseDataplane,
      devices,
      accelerated: true,
      inspected: false,
    };
  }

  if (inspected) {
    return {
      state: "inspected",
      cls: "info",
      label: "Inspection path",
      summary: `Traffic is on the ${idsModeLabel(policy)} path.`,
      detail: "Flowtable acceleration is unavailable while IDS/IPS is enabled.",
      action: "Use standard forwarding for inspected profiles",
      baseDataplane,
      devices,
      accelerated: false,
      inspected: true,
    };
  }

  return {
    state: "standard",
    cls: "neutral",
    label: "Standard forwarding",
    summary: "Traffic uses the standard stateful forwarding path.",
    detail: "Enable flowtable only for forwarding profiles that do not require IDS/IPS inspection.",
    action: "Enable fast path for forwarding-only benchmarking",
    baseDataplane,
    devices,
    accelerated: false,
    inspected: false,
  };
}
