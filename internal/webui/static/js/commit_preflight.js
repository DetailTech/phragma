// commit_preflight.js - pure commit-review posture decisions.
// The drawer should use the same production-readiness language as Readiness,
// but evaluate the staged candidate so operators see host/runtime blockers
// before applying a policy to the live firewall.

import {
  conntrackCapacity,
  dataplanePosture,
  ebpfHostReadiness,
  flowtableHostReadiness,
  flowtableRuntimeEvidence,
  kernelTuningRollup,
} from "./dataplane.js";
import { dynamicRoutingEnabled, remediationSteps, routingRuntimeEvidence, summarizeReadiness } from "./readiness_model.js";

export function commitRuntimePreflight({ preflight = null, status = null, error = null, draftPolicy = {}, runningPolicy = {}, operation = "commit" } = {}) {
  if (isServerRuntimePreflight(preflight)) {
    return serverRuntimePreflight(preflight, { operation });
  }
  const op = operation === "rollback" ? "rollback" : "commit";
  if (error) {
    return {
      label: "unknown",
      cls: "warn",
      requiresAck: true,
      detail: `Runtime status could not be loaded before ${op}.`,
      items: [{
        id: "runtime-status-unavailable",
        level: "medium",
        badge: "warning",
        title: "Runtime status unavailable",
        detail: error.message || "The status endpoint did not respond.",
      }],
    };
  }
  if (!status) {
    return {
      label: "unknown",
      cls: "warn",
      requiresAck: true,
      detail: `Runtime status could not be loaded before ${op}.`,
      items: [{
        id: "runtime-status-unavailable",
        level: "medium",
        badge: "warning",
        title: "Runtime status unavailable",
        detail: "The status endpoint returned no response.",
      }],
    };
  }

  const policyDp = dataplanePosture(draftPolicy, status);
  const runningDp = dataplanePosture(runningPolicy, status);
  const flowCap = flowtableHostReadiness(status);
  const rawFlowRuntime = flowtableRuntimeEvidence(status);
  const flowRuntime = commitFlowtableRuntimeEvidence(rawFlowRuntime, policyDp, runningDp);
  const ebpfHost = ebpfHostReadiness(status);
  const conntrack = conntrackCapacity(status);
  const tuning = kernelTuningRollup(status);
  const routingRuntime = commitRoutingRuntimeEvidence(status, draftPolicy, runningPolicy);
  const summary = summarizeReadiness(status, policyDp, flowCap, flowRuntime, ebpfHost, conntrack, null, routingRuntime);
  const items = remediationSteps(status, policyDp, flowCap, flowRuntime, ebpfHost, conntrack, tuning, null, routingRuntime);

  if (!items.length && summary.cls === "ok") {
    const dataplane = status.dataplane?.activeDataplane || status.runtime?.activeDataplane || "the configured dataplane";
    return {
      label: "ready",
      cls: "ok",
      requiresAck: false,
      detail: `Runtime is enforcing on ${dataplane}.`,
      items: [],
    };
  }

  const hasHigh = summary.cls === "bad" || items.some((it) => it.level === "high");
  return {
    label: hasHigh ? "not ready" : "warnings",
    cls: hasHigh ? "bad" : "warn",
    requiresAck: true,
    detail: hasHigh ? summary.detail || "Runtime has production blockers." : summary.detail || "Runtime has warnings to review before commit.",
    items,
  };
}

export function serverRuntimePreflight(preflight = {}, { operation = "commit" } = {}) {
  const op = operation === "rollback" || preflight?.operation === "rollback" ? "rollback" : "commit";
  const requiresAck = Boolean(preflight?.requiresAck ?? preflight?.requires_ack);
  const cls = normalizeRuntimeTone(preflight?.cls, requiresAck);
  const items = Array.isArray(preflight?.items) ? preflight.items.map(normalizeRuntimeItem).filter(Boolean) : [];
  const label = String(preflight?.label || (requiresAck ? (cls === "bad" ? "not ready" : "warnings") : "ready")).trim();
  return {
    label: label || (requiresAck ? "warnings" : "ready"),
    cls,
    requiresAck,
    detail: String(preflight?.detail || (requiresAck
      ? `Runtime readiness reported warnings before ${op}.`
      : `Runtime readiness checks passed for ${op}.`)).trim(),
    items,
    warnings: Array.isArray(preflight?.warnings) ? preflight.warnings.map((item) => String(item).trim()).filter(Boolean) : [],
    source: "server",
  };
}

function isServerRuntimePreflight(preflight) {
  return preflight && typeof preflight === "object" && (
    typeof preflight.requiresAck === "boolean" ||
    typeof preflight.requires_ack === "boolean" ||
    Array.isArray(preflight.items)
  );
}

function normalizeRuntimeItem(item = {}) {
  const title = String(item?.title || "").trim();
  const detail = String(item?.detail || "").trim();
  if (!title && !detail) return null;
  return {
    id: String(item?.id || title || "runtime-readiness-warning").trim(),
    level: normalizeRuntimeLevel(item?.level),
    badge: String(item?.badge || "runtime").trim(),
    title: title || "Runtime readiness warning",
    detail,
    href: String(item?.href || "").trim(),
    command: String(item?.command || "").trim(),
  };
}

function normalizeRuntimeTone(cls, requiresAck) {
  const tone = String(cls || "").trim().toLowerCase();
  if (["ok", "warn", "bad", "info"].includes(tone)) return tone;
  return requiresAck ? "warn" : "ok";
}

function normalizeRuntimeLevel(level) {
  const value = String(level || "").trim().toLowerCase();
  if (["high", "medium", "low", "neutral"].includes(value)) return value;
  return "medium";
}

function commitRoutingRuntimeEvidence(status, draftPolicy, runningPolicy) {
  const draftEnabled = dynamicRoutingEnabled(draftPolicy);
  if (!draftEnabled) return routingRuntimeEvidence(status, draftPolicy);
  const runningEnabled = dynamicRoutingEnabled(runningPolicy);
  const live = routingRuntimeEvidence(status, draftPolicy);
  if (runningEnabled || live.state === "active") return live;

  // A candidate that newly enables BGP or OSPF cannot have live neighbor
  // evidence yet. FRR command prerequisites still appear through engine and
  // capability readiness; live adjacency evidence becomes a Readiness and
  // field-evidence gate after commit.
  return {
    ...live,
    state: "active",
    active: true,
    detail: live.detail || "FRR runtime evidence is verified after commit.",
  };
}

function commitFlowtableRuntimeEvidence(flowRuntime, policyDp, runningDp) {
  if (!policyDp?.accelerated) return flowRuntime;
  if (runningDp?.accelerated) return flowRuntime;
  if (flowRuntime?.state === "active") return flowRuntime;

  // A candidate that newly enables flowtable acceleration cannot have live
  // ruleset counters yet. Host readiness is still checked before commit; live
  // runtime evidence becomes a Readiness/benchmark gate after the candidate is
  // applied.
  return {
    ...flowRuntime,
    active: true,
    state: "active",
    label: "pending commit",
    detail: flowRuntime?.detail || "Live flowtable evidence is verified after commit.",
  };
}
