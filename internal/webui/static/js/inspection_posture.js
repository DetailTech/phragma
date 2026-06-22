import { inspectionReadiness } from "./dataplane.js";

export const DEGRADED_ENGINE_EVIDENCE_CAPABILITY = "Degraded engine dataplane evidence";

export function currentInspectionPosture(status = {}) {
  const readiness = inspectionReadiness(status);
  const state = readiness.state || "unknown";
  const engineLabel = readiness.engineLabel || "inspection engine unavailable";
  const failureBehavior = enumLabel(readiness.failureBehavior || readiness.failure_behavior || "");
  const inspectionState = enumLabel(readiness.inspectionState || readiness.inspection_state || "");
  const bypassPossible = Boolean(readiness.bypassPossible || readiness.bypass_possible);
  const bypassReason = readiness.bypassReason || readiness.bypass_reason || "";
  const degradedBehavior = readiness.degradedBehavior || readiness.degraded_behavior || "";
  const details = [
    readiness.detail || "Inspection readiness is not available.",
    failureBehavior ? `failure behavior: ${failureBehavior}` : "",
    inspectionState ? `inspection state: ${inspectionState}` : "",
    bypassPossible ? (bypassReason || "bypass is possible under the current inspection posture") : "",
    degradedBehavior,
  ].filter(Boolean);
  return {
    state,
    label: state,
    cls: readiness.cls || postureClass(state),
    engineLabel,
    detail: details.join(" "),
    failureBehavior,
    inspectionState,
    bypassPossible,
    bypassReason,
    degradedBehavior,
    summary: `${state} · ${engineLabel}`,
  };
}

export function degradedEngineEvidence(status = {}, policy = {}) {
  const cap = (status.capabilities || []).find((item) => item.name === DEGRADED_ENGINE_EVIDENCE_CAPABILITY) || {};
  const engines = Array.isArray(status.engines) ? status.engines : [];
  const inspection = currentInspectionPosture(status);
  const engineRows = ["nftables", "suricata", "vector", "proxy"].map((name) => degradedEngineRow(name, status, engines, inspection, policy));
  const degradedRows = engineRows.filter((row) => row.required && row.degraded);
  const limitations = [
    "Runtime status summary only.",
    "No signed field evidence, packet capture proof, remote peer attestation, or production certification claim.",
  ];
  const failMode = inspection.failureBehavior || failureBehaviorFromPolicy(policy);
  const threatProfiles = Array.isArray(policy.securityProfiles) ? policy.securityProfiles.filter(securityProfileHasBlockingIntent) : [];
  const exceptions = Array.isArray(policy.ids?.exceptions) ? policy.ids.exceptions.filter((item) => !item.disabled) : [];
  const impact = [
    policy.ids?.enabled ? `Threat-ID inspection ${inspection.state}; ${failMode || "failure behavior not reported"}.` : "Threat-ID inspection disabled for the running policy.",
    threatProfiles.length ? `${threatProfiles.length} blocking security profile(s) depend on fail-closed inspection posture.` : "No blocking security profile dependency found in policy.",
    exceptions.length ? `${exceptions.length} active false-positive exception(s) require healthy suppression rendering.` : "No active false-positive exceptions found.",
    telemetryPolicyActive(policy) ? "Vector telemetry is required for export evidence." : "Telemetry export is not required by policy.",
    proxyPolicyActive(policy) ? "Proxy/WAF policy requires external proxy runtime proof." : "Proxy/WAF policy is not configured.",
  ];
  const state = cap.state || (degradedRows.length ? "degraded" : "ready");
  return {
    state,
    label: degradedRows.length ? `${degradedRows.length} engine impact${degradedRows.length === 1 ? "" : "s"}` : state,
    cls: degradedRows.some((row) => row.tone === "bad") ? "bad" : degradedRows.length ? "warn" : state === "ready" ? "ok" : "neutral",
    detail: cap.detail || "Bounded multi-engine dataplane evidence is derived from current runtime status.",
    rows: engineRows,
    degradedRows,
    impact,
    limitations,
    failMode,
  };
}

export function inspectionPostureSummary(status = {}) {
  const posture = currentInspectionPosture(status);
  return {
    state: posture.state,
    engine: posture.engineLabel,
    failureBehavior: posture.failureBehavior,
    inspectionState: posture.inspectionState,
    bypassPossible: posture.bypassPossible,
    bypassReason: posture.bypassReason,
    degradedBehavior: posture.degradedBehavior,
    detail: posture.detail,
    scope: "current runtime posture at handoff time; not a per-event telemetry fact",
  };
}

function degradedEngineRow(name, status = {}, engines = [], inspection = {}, policy = {}) {
  if (name === "nftables") {
    const state = status.capabilities?.find((item) => item.name === "Stateful firewall")?.state || "unknown";
    return {
      name,
      required: true,
      state,
      degraded: !readyState(state),
      tone: readyState(state) ? "ok" : "bad",
      impact: "L3/L4 forwarding and policy counters",
    };
  }
  if (name === "suricata") {
    const required = Boolean(policy.ids?.enabled || inspection.engineRequired || inspection.state === "failed-open" || inspection.state === "failed-closed");
    const state = inspection.engineLabel || engineState(findEngine(engines, name));
    const degraded = required && inspection.state !== "ready";
    return {
      name,
      required,
      state: state || inspection.state || "unknown",
      degraded,
      tone: degraded && inspection.bypassPossible ? "bad" : degraded ? "warn" : required ? "ok" : "neutral",
      impact: "Threat-ID detection/prevention and false-positive suppressions",
    };
  }
  if (name === "vector") {
    const required = telemetryPolicyActive(policy);
    const engine = findEngine(engines, name);
    const state = engineState(engine);
    const degraded = required && !readyState(state);
    return { name, required, state, degraded, tone: degraded ? "warn" : required ? "ok" : "neutral", impact: "Telemetry export and evidence forwarding" };
  }
  const required = proxyPolicyActive(policy);
  const engine = findEngine(engines, "proxy") || findEngine(engines, "envoy") || findEngine(engines, "coraza") || engines.find((item) => /proxy|waf|envoy|coraza/i.test([item.name, item.role, item.detail].filter(Boolean).join(" ")));
  const state = engineState(engine);
  const degraded = required && !readyState(state);
  return { name: "proxy", required, state, degraded, tone: degraded ? "warn" : required ? "ok" : "neutral", impact: "Proxy/WAF listener and L7 profile runtime proof" };
}

function findEngine(engines = [], name = "") {
  return engines.find((engine) => String(engine.name || "").toLowerCase() === name);
}

function engineState(engine) {
  if (!engine) return "not-reported";
  return engine.state || "unknown";
}

function readyState(state = "") {
  return state === "ready" || state === "active";
}

function telemetryPolicyActive(policy = {}) {
  const telemetry = policy.telemetry || {};
  if (telemetry.enabled) return true;
  return Array.isArray(telemetry.exports) && telemetry.exports.some((item) => item?.enabled);
}

function proxyPolicyActive(policy = {}) {
  const proxy = policy.proxy || {};
  return Boolean((proxy.virtualServices || proxy.virtual_services || []).length || (proxy.wafPolicies || proxy.waf_policies || []).length);
}

function failureBehaviorFromPolicy(policy = {}) {
  return enumLabel(policy.ids?.failureBehavior || policy.ids?.failure_behavior || "");
}

export function inspectionCoverageForRule(policy = {}, rule = {}) {
  const ids = policy.ids || {};
  const network = policy.network || {};
  const idsEnabled = Boolean(ids.enabled);
  const idsMode = ids.mode || "";
  const failureBehavior = ids.failureBehavior || ids.failure_behavior || "";
  const flowOffload = Boolean(network.enableFlowOffload || network.enable_flow_offload);
  const action = rule.action || "ACTION_ALLOW";
  const blockingProfile = ruleHasBlockingSecurityProfile(policy, rule);

  if (!ruleActive(rule)) {
    return coverageState("disabled", "disabled", "neutral", "Rule is disabled and is not part of live forwarding.");
  }
  if (action === "ACTION_DENY" || action === "ACTION_REJECT") {
    return coverageState("pre-filter-drop", "pre-filter drop", "neutral", "Policy drops before IDS/IPS inspection is needed.");
  }
  if (flowOffload && idsEnabled) {
    return coverageState("bypass-risk", "flowtable + IDS", "bad", "Flowtable acceleration can bypass IDS/IPS for forwarded allow traffic.", true);
  }
  if (idsEnabled && idsMode === "IDS_MODE_PREVENT") {
    if (failureBehavior === "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED") {
      return blockingProfile
        ? coverageState("profile-enforced", "profile enforced", "ok", "Blocking profile intent is protected by inline IPS fail-closed.")
        : coverageState("ips-fail-closed", "IPS fail-closed", "ok", "Inline prevention blocks instead of bypassing if the inspection queue fails.");
    }
    return blockingProfile
      ? coverageState("profile-needs-fail-closed", "profile unsafe", "bad", "Blocking profile intent requires Prevent mode with Fail closed.", true)
      : coverageState("ips-fail-open", "IPS fail-open", "warn", "Inline prevention can bypass traffic if the inspection queue fails.", true);
  }
  if (blockingProfile) {
    return coverageState("profile-needs-ips", "profile inactive", "bad", "Blocking profile intent requires IDS/IPS Prevent with Fail closed.", true);
  }
  if (idsEnabled) {
    return coverageState("ids-detect", "IDS detect", "info", "Traffic is observed by IDS while the firewall action remains authoritative.");
  }
  if (flowOffload) {
    return coverageState("fast-path", "fast path", "neutral", "IDS/IPS is disabled; forwarding can use flowtable acceleration.");
  }
  return coverageState("not-inspected", "not inspected", "warn", "IDS/IPS is disabled for this forwarding path.");
}

export function inspectionCoverageMap(policy = {}, status = {}) {
  const runtime = currentInspectionPosture(status);
  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  const rows = rules.map((rule, index) => {
    const coverage = inspectionCoverageForRule(policy, rule);
    return {
      index,
      name: rule.name || `rule-${index + 1}`,
      action: rule.action || "ACTION_ALLOW",
      fromZones: Array.isArray(rule.fromZones) ? rule.fromZones : [],
      toZones: Array.isArray(rule.toZones) ? rule.toZones : [],
      securityProfiles: Array.isArray(rule.securityProfiles) ? rule.securityProfiles : [],
      coverage,
    };
  });
  const bucketMap = new Map();
  for (const row of rows) {
    const bucket = bucketMap.get(row.coverage.state) || {
      state: row.coverage.state,
      label: row.coverage.label,
      cls: row.coverage.cls,
      detail: row.coverage.detail,
      bypassPossible: row.coverage.bypassPossible,
      count: 0,
      examples: [],
    };
    bucket.count += 1;
    if (bucket.examples.length < 3) bucket.examples.push(row.name);
    bucketMap.set(bucket.state, bucket);
  }
  const buckets = Array.from(bucketMap.values()).sort((a, b) => bucketRank(a) - bucketRank(b) || a.label.localeCompare(b.label));
  const risky = rows.filter((row) => row.coverage.cls === "bad" || row.coverage.bypassPossible);
  const warnings = rows.filter((row) => row.coverage.cls === "warn");
  return {
    totalRules: rows.length,
    activeAllowRules: rows.filter((row) => row.action === "ACTION_ALLOW" && row.coverage.state !== "disabled").length,
    riskCount: risky.length,
    warningCount: warnings.length,
    runtimeBypass: runtime.bypassPossible,
    runtimeState: runtime.state,
    runtimeDetail: runtime.bypassPossible ? (runtime.bypassReason || runtime.degradedBehavior || runtime.detail) : "",
    buckets,
    rows,
    summary: coverageMapSummary(rows, risky, warnings, runtime),
  };
}

function coverageMapSummary(rows = [], risky = [], warnings = [], runtime = {}) {
  if (!rows.length) return { label: "no rules", cls: "neutral", detail: "No candidate security rules are available for inspection coverage review." };
  if (runtime.bypassPossible) return { label: "runtime bypass", cls: "bad", detail: runtime.bypassReason || runtime.degradedBehavior || runtime.detail || "Runtime posture reports bypass risk." };
  if (risky.length) return { label: `${risky.length} risk${risky.length === 1 ? "" : "s"}`, cls: "bad", detail: "Allow paths have inspection bypass or blocking-profile enforcement gaps." };
  if (warnings.length) return { label: `${warnings.length} warning${warnings.length === 1 ? "" : "s"}`, cls: "warn", detail: "Some allow paths are detected-only, fail-open, or not inspected." };
  return { label: "covered", cls: "ok", detail: "No inspection bypass or profile-enforcement gaps were found in candidate rules." };
}

function coverageState(state, label, cls, detail, bypassPossible = false) {
  return { state, label, cls, detail, bypassPossible };
}

function bucketRank(bucket = {}) {
  if (bucket.cls === "bad") return 0;
  if (bucket.cls === "warn") return 1;
  if (bucket.cls === "info") return 2;
  if (bucket.cls === "ok") return 3;
  return 4;
}

function ruleActive(rule = {}) {
  return !rule.disabled;
}

function ruleHasBlockingSecurityProfile(policy = {}, rule = {}) {
  const refs = (rule.securityProfiles || []).filter(Boolean);
  if (!refs.length) return false;
  const profiles = new Map((policy.securityProfiles || []).map((profile) => [profile.name, profile]));
  return refs.some((ref) => securityProfileHasBlockingIntent(profiles.get(ref)));
}

function securityProfileHasBlockingIntent(profile = {}) {
  if (!profile) return false;
  return profile.tlsInspection === "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED" ||
    (profile.urlCategories || []).length > 0 ||
    profile.dnsSecurity === "DNS_SECURITY_MODE_BLOCK_MALICIOUS" ||
    profile.fileSecurity === "FILE_SECURITY_MODE_BLOCK_EXECUTABLES" ||
    profile.fileSecurity === "FILE_SECURITY_MODE_BLOCK_HIGH_RISK";
}

function enumLabel(value = "") {
  return String(value || "")
    .replace(/^IDS_FAILURE_BEHAVIOR_/, "")
    .replace(/^IDS_MODE_/, "")
    .replace(/^EXPLAIN_INSPECTION_STATE_/, "")
    .toLowerCase()
    .replace(/_/g, "-");
}

function postureClass(state) {
  if (state === "ready" || state === "disabled") return "ok";
  if (state === "failed-open" || state === "failed-closed") return "bad";
  if (state === "degraded") return "warn";
  return "neutral";
}
