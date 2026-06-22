// performance.js - browser-side benchmark evidence validation. This mirrors
// the ngfwperf/perfreport contract so operators can inspect summary.json
// artifacts without uploading evidence to controld.

export const SCHEMA_VERSION = "phragma.perf.v1";
export const LEGACY_SCHEMA_VERSION = "openngfw.perf.v1";

export const CANONICAL_INSPECTION_STATES = [
  "fully-inspected",
  "partially-inspected",
  "bypassed-by-policy",
  "bypassed-by-engine-health",
  "failed-open",
  "failed-closed",
  "blocked-before-inspection",
  "not-inspected",
];

const CANONICAL = new Set(CANONICAL_INSPECTION_STATES);
const RAW_THROUGHPUT_TOLERANCE = 0.001;
const DEFAULT_DELTA_THRESHOLD_PCT = 5;
const DEFAULT_LATENCY_THRESHOLD_PCT = 10;
const MAX_COMPARISON_TEXT = 240;
const MAX_COMPARISON_FINDINGS = 12;
export const STATUS_ARTIFACT_CANDIDATES = [
  "ngfw-status-active.txt",
  "firewall-status-active.txt",
  "ngfw-status-final.txt",
  "firewall-status-final.txt",
  "ngfw-status.txt",
  "firewall-status.txt",
];
export const NFT_ARTIFACT_CANDIDATES = [
  "nft-openngfw-active.txt",
  "nft-openngfw-final.txt",
  "nft-openngfw.txt",
];
export const PERF_ARTIFACT_LIMITS_BYTES = Object.freeze({
  summary: 2 * 1024 * 1024,
  iperf: 10 * 1024 * 1024,
  status: 2 * 1024 * 1024,
  nft: 2 * 1024 * 1024,
});

export function benchmarkCollectionRunbook() {
  return {
    schemaVersion: "phragma.performance.collection-runbook.v1",
    title: "Benchmark collection runbook",
    custody: "browser-local command handoff; benchmark artifacts are reviewed locally and are not uploaded to controld",
    workflows: [
      {
        id: "local-netns",
        label: "Local netns smoke",
        detail: "Use on one Linux host to prove the harness, summary contract, raw iperf artifact, runtime status capture, and verifier parity.",
        commands: [
          runbookCommand("Check host prerequisites", "make benchmark-netns-check"),
          runbookCommand("Collect local netns evidence", "sudo DURATION=30 PARALLEL=8 make benchmark-netns"),
          runbookCommand("Verify collected run", "go run ./cmd/ngfwperf verify --strict perf/results"),
        ],
        artifacts: ["summary.json", "iperf3.json", "ngfw-status-active.txt", "nft-openngfw-final.txt"],
      },
      {
        id: "three-host",
        label: "Three-host field run",
        detail: "Use for publishable or release evidence after setting client, server, firewall, target, profile, and inspection context in the shell.",
        commands: [
          runbookCommand("Export benchmark context", [
            "export CLIENT_HOST=opc@<client>",
            "export SERVER_HOST=opc@<server>",
            "export FW_HOST=opc@<firewall>",
            "export TARGET_IP=<server-private-ip>",
            "export FW_STATUS_CMD='ngfwctl status'",
            "export FW_NFT_CMD='sudo nft list table inet openngfw'",
            "export BENCH_PROFILE=forwarding-large-flow",
            "export SECURITY_SERVICES=none",
            "export INSPECTION_STATE=not-inspected",
            "export DURATION=60",
            "export PARALLEL=16",
          ].join("\n")),
          runbookCommand("Check three-host prerequisites", "make benchmark-check"),
          runbookCommand("Collect three-host evidence", "make benchmark"),
          runbookCommand("Verify release-grade evidence", "go run ./cmd/ngfwperf verify --strict perf/results"),
        ],
        artifacts: ["summary.json", "iperf3.json", "ngfw-status-active.txt", "nft-openngfw-final.txt"],
      },
    ],
    releaseCommands: [
      runbookCommand("Verify release gate", "make benchmark-verify-release"),
      runbookCommand("Record no-claims release status", "RELEASE_NO_PERFORMANCE_CLAIMS=1 make release-acceptance-status"),
    ],
    guardrails: [
      "Use live status is current posture only; measured-window status must be captured during the benchmark run.",
      "Keep SSH options, private keys, bearer tokens, and workstation paths outside copied evidence packets.",
      "Scope public claims to the loaded raw artifacts, active inspection state, host tuning, conntrack, and nftables evidence.",
    ],
  };
}

export function benchmarkCollectionRunbookText(runbook = benchmarkCollectionRunbook()) {
  const lines = [
    runbook.title || "Benchmark collection runbook",
    runbook.custody || "",
    "",
  ];
  for (const workflow of runbook.workflows || []) {
    lines.push(`${workflow.label}:`);
    lines.push(`  ${workflow.detail}`);
    lines.push(`  artifacts: ${(workflow.artifacts || []).join(", ")}`);
    for (const command of workflow.commands || []) {
      lines.push(`  # ${command.label}`);
      lines.push(indentCommand(command.command || "", "  "));
    }
    lines.push("");
  }
  if (runbook.releaseCommands?.length) {
    lines.push("Release checks:");
    for (const command of runbook.releaseCommands) {
      lines.push(`  # ${command.label}`);
      lines.push(indentCommand(command.command || "", "  "));
    }
    lines.push("");
  }
  if (runbook.guardrails?.length) {
    lines.push("Guardrails:");
    for (const guardrail of runbook.guardrails) lines.push(`- ${guardrail}`);
  }
  return lines.filter((line, index, all) => line || all[index - 1]).join("\n").trim() + "\n";
}

export function detectBenchmarkArtifacts(files = []) {
  const normalized = Array.from(files || [])
    .map((file) => {
      const path = String(file?.webkitRelativePath || file?.path || file?.name || "").replace(/\\/g, "/");
      const name = basename(path || String(file?.name || ""));
      return { file, path, name, lowerName: name.toLowerCase() };
    })
    .filter((item) => item.name);
  const pick = (names) => {
    for (const name of names) {
      const found = normalized.find((item) => item.lowerName === name);
      if (found) return found;
    }
    return null;
  };
  const summary = pick(["summary.json"]);
  const iperf = pick(["iperf3.json"]);
  const status = pick(STATUS_ARTIFACT_CANDIDATES);
  const nft = pick(NFT_ARTIFACT_CANDIDATES);
  const selected = [summary, iperf, status, nft].filter(Boolean);
  const duplicates = duplicateArtifactNames(normalized);
  const sizeProblems = selected
    .map((item) => artifactSizeProblem(item?.file, artifactKind(item?.lowerName)))
    .filter(Boolean);
  return {
    summary,
    iperf,
    status,
    nft,
    runName: runNameFromSelection(summary || selected[0]),
    recognizedCount: selected.length,
    totalCount: normalized.length,
    missing: [
      summary ? "" : "summary.json",
      iperf ? "" : "iperf3.json",
      status ? "" : "status artifact",
      nft ? "" : "nft artifact",
    ].filter(Boolean),
    duplicates,
    sizeProblems,
  };
}

function runbookCommand(label, command) {
  return { label, command: sanitizeRunbookCommand(command) };
}

function sanitizeRunbookCommand(command) {
  return String(command || "")
    .replace(/\/Users\/[^\s"'\\]+/g, "/Users/[redacted]")
    .replace(/\/private\/tmp\/[^\s"'\\]+/g, "/private/tmp/[redacted]")
    .replace(/\/etc\/[^\s"'\\]+/g, "/etc/[redacted]")
    .replace(/\b(token|access_token|api_key|password|secret|client_secret|key)=([^\s"'&]+)/gi, (_, key) => `${key}=[redacted]`);
}

function indentCommand(command, prefix) {
  return String(command || "").split(/\r?\n/).map((line) => prefix + line).join("\n");
}

export function artifactSizeProblem(file, kind) {
  const limit = PERF_ARTIFACT_LIMITS_BYTES[kind];
  const size = Number(file?.size || 0);
  if (!limit || !Number.isFinite(size) || size <= limit) return "";
  return `${artifactLabel(kind)} ${safeArtifactName(file)} is ${formatBytes(size)}, over the ${formatBytes(limit)} limit`;
}

export function statusEvidenceText(status = {}) {
  const runtime = status.runtime || {};
  const dataplane = status.dataplane || {};
  const flowtable = dataplane.flowtable || {};
  const tuning = dataplane.kernelTuning || {};
  const conntrack = dataplane.conntrack || {};
  const inspection = status.inspection || {};
  const lines = ["policy dataplane:"];
  lines.push(`  throughput path: ${value(dataplane.activeDataplane || runtime.activeDataplane || "unknown")}`);
  lines.push(`  inspection:      ${inspectionPolicyLabel(inspection)}`);
  lines.push(`  inspection ready:${value(inspection.state)}`);
  if (inspection.engineName || inspection.engineMode || inspection.engineState) {
    lines.push(`  inspection eng:  ${value(inspection.engineName)} ${value(inspection.engineMode)}/${value(inspection.engineState)}`);
  }
  const failure = idsFailureBehaviorLabel(inspection.failureBehavior);
  if (failure) lines.push(`  fail behavior:   ${failure}`);
  if (inspection.bypassPossible && inspection.bypassReason) {
    lines.push(`  bypass reason:   ${inspection.bypassReason}`);
  }
  if (inspection.degradedBehavior && inspection.state !== "disabled") {
    lines.push(`  degraded mode:   ${inspection.degradedBehavior}`);
  }
  lines.push(`  flowtable host:  ${value(flowtable.hostState)}`);
  lines.push(`  flowtable live:  ${value(flowtable.runtimeState)}`);
  if (tuning.state) lines.push(`  kernel tuning:  ${value(tuning.state)}`);
  const maxEntries = Number(conntrack.maxEntries || 0);
  const currentEntries = Number(conntrack.currentEntries || 0);
  const usagePercent = Number(conntrack.usagePercent || 0);
  if (conntrack.state || maxEntries > 0) {
    if (maxEntries > 0) {
      lines.push(`  state table:    ${value(conntrack.state)} ${Math.trunc(currentEntries)}/${Math.trunc(maxEntries)} entries (${formatStatusPercent(usagePercent)}%)`);
    } else {
      lines.push(`  state table:    ${value(conntrack.state)}`);
    }
  }
  if (flowtable.devices?.length) lines.push(`  flowtable devs:  ${flowtable.devices.join(", ")}`);
  if (Number(flowtable.packets || 0) > 0 || Number(flowtable.bytes || 0) > 0) {
    lines.push(`  flowtable hits:  ${Number(flowtable.packets || 0)} packets / ${Number(flowtable.bytes || 0)} bytes`);
  }
  return lines.join("\n") + "\n";
}

export function validateSummaryText(text, { strict = false, iperfText = "", statusText = "", nftText = "" } = {}) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    return { summary: null, errors: ["invalid JSON: " + e.message], warnings: [], strict, artifacts: {} };
  }
  return validateSummary(parsed, { strict, iperfText, statusText, nftText });
}

export function validateSummary(summary, { strict = false, iperfText = "", statusText = "", nftText = "" } = {}) {
  const errors = [];
  const warnings = [];
  const artifacts = {};
  const required = [
    "schema_version", "generated_at", "profile", "security_services",
    "inspection_state", "target", "duration_seconds", "parallel_streams",
    "tcp_bits_per_second", "tcp_gbps", "tcp_retransmits", "claim_scope",
  ];
  for (const key of required) {
    if (!has(summary, key)) errors.push("missing required field " + key);
  }
  if (summary?.schema_version === LEGACY_SCHEMA_VERSION) {
    warnings.push(`schema_version ${q(LEGACY_SCHEMA_VERSION)} is legacy; prefer ${q(SCHEMA_VERSION)}`);
  } else if (summary?.schema_version !== SCHEMA_VERSION) {
    errors.push(`schema_version = ${q(summary?.schema_version)}, want ${q(SCHEMA_VERSION)}`);
  }
  if (!summary?.generated_at) errors.push("generated_at is required");
  else if (Number.isNaN(Date.parse(summary.generated_at))) errors.push("generated_at must be RFC3339/RFC3339Nano");
  if (!summary?.profile) errors.push("profile is required");
  if (!summary?.security_services) errors.push("security_services is required");
  if (!summary?.inspection_state) errors.push("inspection_state is required");
  else if (!CANONICAL.has(summary.inspection_state)) {
    warnings.push(`inspection_state ${q(summary.inspection_state)} is not canonical`);
  }
  validateSecurityServiceConsistency(summary, errors);
  if (!summary?.target || typeof summary.target !== "object" || Array.isArray(summary.target)) {
    errors.push("target must be an object");
  } else {
    if (!summary.target.ip) errors.push("target.ip is required");
    if (!integerRange(summary.target.port, 1, 65535)) errors.push("target.port must be 1..65535");
  }
  if (!integerMin(summary?.duration_seconds, 1)) errors.push("duration_seconds must be >= 1");
  if (!integerMin(summary?.parallel_streams, 1)) errors.push("parallel_streams must be >= 1");
  if (!finiteNonNegative(summary?.tcp_bits_per_second)) errors.push("tcp_bits_per_second must be a finite non-negative number");
  if (!finiteNonNegative(summary?.tcp_gbps)) errors.push("tcp_gbps must be a finite non-negative number");
  if (!integerMin(summary?.tcp_retransmits, 0)) errors.push("tcp_retransmits must be >= 0");
  if (summary?.ping_avg_ms != null && !finiteNonNegative(summary.ping_avg_ms)) {
    errors.push("ping_avg_ms must be null or a finite non-negative number");
  }
  if (!summary?.claim_scope) errors.push("claim_scope is required");
  if (has(summary, "connection_churn") && !plainObject(summary.connection_churn)) {
    errors.push("connection_churn must be an object when present");
  }
  validateInspectionEvidence(summary, errors, warnings);
  validateHostTuningEvidence(summary, errors, warnings);
  validateConntrackEvidence(summary, errors, warnings);
  validateFlowtableEvidence(summary, errors);
  artifacts.iperf = validateIperfEvidence(summary, iperfText, errors, warnings);
  artifacts.status = validateStatusEvidence(summary, statusText, errors, warnings);
  artifacts.nft = validateNftEvidence(summary, nftText, errors, warnings);
  return { summary, errors, warnings, strict, artifacts };
}

export function evidenceVerdict(result) {
  if (!result || result.errors?.length) return { cls: "bad", label: "invalid", title: "Evidence invalid" };
  if (result.strict && result.warnings?.length) return { cls: "bad", label: "strict fail", title: "Strict gate failed" };
  if (result.warnings?.length) return { cls: "warn", label: "warnings", title: "Evidence accepted with warnings" };
  return { cls: "ok", label: "valid", title: "Evidence valid" };
}

export function benchmarkGate(result) {
  const summary = result?.summary || {};
  const errors = result?.errors || [];
  const warnings = result?.warnings || [];
  const gates = [
    schemaGate(errors, warnings, Boolean(result?.strict)),
    publicationScopeGate(summary),
    inspectionGate(summary.inspection_state),
    hostTuningGate(summary),
    conntrackGate(summary),
    flowtableGate(summary),
  ];
  const cls = errors.length || gates.some((g) => g.cls === "bad")
    ? "bad"
    : warnings.length || gates.some((g) => g.cls === "warn")
      ? "warn"
      : "ok";
  return {
    cls,
    label: cls === "ok" ? "publishable" : cls === "warn" ? "review required" : "blocked",
    title: cls === "ok" ? "Evidence is ready for scoped publication" : cls === "warn" ? "Evidence needs operator review" : "Evidence is not publishable",
    detail: cls === "ok"
      ? "The artifact passes the local contract and carries the required context for its stated scope."
      : cls === "warn"
        ? "The artifact may still be useful internally, but publication or release use needs the listed context or evidence gaps resolved."
        : "Fix the blocking evidence issues before using this artifact for release, publication, or comparison.",
    gates,
  };
}

export function releaseGateSummary(result) {
  const gate = benchmarkGate(result);
  const errors = result?.errors || [];
  const warnings = result?.warnings || [];
  const strict = Boolean(result?.strict);
  const blockers = [];
  const reviewItems = [];
  const seen = new Set();
  const add = (target, item) => {
    const title = String(item.title || "").trim();
    if (!title) return;
    const key = [item.label || "", title, item.detail || ""].join("\n");
    if (seen.has(key)) return;
    seen.add(key);
    target.push({
      label: item.label || "Gate",
      title,
      detail: item.detail || "",
      cls: item.cls || "warn",
    });
  };

  if (errors.length) {
    add(blockers, {
      label: "Contract",
      cls: "bad",
      title: `${errors.length} blocking evidence error${errors.length === 1 ? "" : "s"}`,
      detail: summarizeGateMessages(errors),
    });
  }
  if (strict && warnings.length) {
    add(blockers, {
      label: "Strict",
      cls: "bad",
      title: `${warnings.length} warning${warnings.length === 1 ? "" : "s"} block release mode`,
      detail: summarizeGateMessages(warnings),
    });
  } else if (warnings.length) {
    add(reviewItems, {
      label: "Warnings",
      cls: "warn",
      title: `${warnings.length} warning${warnings.length === 1 ? "" : "s"} need operator review`,
      detail: summarizeGateMessages(warnings),
    });
  }

  for (const item of gate.gates || []) {
    if (item.cls === "bad") {
      add(blockers, item);
    } else if (item.cls === "warn") {
      add(strict ? blockers : reviewItems, {
        ...item,
        cls: strict ? "bad" : "warn",
      });
    }
  }

  const canPublish = blockers.length === 0 && reviewItems.length === 0;
  return {
    cls: blockers.length ? "bad" : reviewItems.length ? "warn" : "ok",
    label: canPublish ? "publishable" : blockers.length ? "blocked" : "review",
    title: canPublish
      ? "Release gate is clean"
      : blockers.length
        ? `${blockers.length} release blocker${blockers.length === 1 ? "" : "s"}`
        : `${reviewItems.length} review item${reviewItems.length === 1 ? "" : "s"}`,
    detail: canPublish
      ? "This benchmark artifact can be used for its stated publishable scope."
      : blockers.length
        ? "Do not use this benchmark for release, publication, or external comparison until the blockers are resolved."
        : "This artifact may support internal review, but publication needs the listed context checked.",
    blockers,
    reviewItems,
  };
}

export function comparePerformanceRuns(baselineResult = {}, candidateResult = {}, opts = {}) {
  const baseline = comparisonRun("baseline", baselineResult);
  const candidate = comparisonRun("candidate", candidateResult);
  const throughput = metricDelta("throughput", "Throughput", "Gbps", baseline.throughputGbps, candidate.throughputGbps, { higherIsBetter: true, thresholdPct: opts.throughputThresholdPct ?? DEFAULT_DELTA_THRESHOLD_PCT });
  const latency = metricDelta("latency", "Latency", "ms", baseline.latencyMs, candidate.latencyMs, { higherIsBetter: false, thresholdPct: opts.latencyThresholdPct ?? DEFAULT_LATENCY_THRESHOLD_PCT });
  const connectionRate = metricDelta("connectionRate", "Connection rate", "cps", baseline.connectionRate, candidate.connectionRate, { higherIsBetter: true, thresholdPct: opts.connectionRateThresholdPct ?? DEFAULT_DELTA_THRESHOLD_PCT });
  const metrics = [throughput, latency, connectionRate];
  const context = comparisonContext(baseline.summary, candidate.summary);
  const strict = Boolean(opts.strict);
  const baselineRelease = releaseGateSummary({ ...baselineResult, strict });
  const candidateRelease = releaseGateSummary({ ...candidateResult, strict });
  const invalidReasons = [
    ...comparisonValidationReasons("baseline", baselineResult, strict),
    ...comparisonValidationReasons("candidate", candidateResult, strict),
  ];
  const regressions = metrics.filter((metric) => metric.state === "bad");
  const improvements = metrics.filter((metric) => metric.state === "ok" && metric.direction === "improvement");
  const reviewMetrics = metrics.filter((metric) => metric.state === "warn");
  const reviewReasons = [
    ...invalidReasons,
    ...context.reviewItems,
    ...(baselineRelease.cls === "ok" ? [] : [`baseline release gate is ${baselineRelease.label}`]),
    ...(candidateRelease.cls === "ok" ? [] : [`candidate release gate is ${candidateRelease.label}`]),
    ...reviewMetrics.map((metric) => `${metric.label} cannot be compared`),
  ];
  const publishableInputs = baselineRelease.cls === "ok" && candidateRelease.cls === "ok" && invalidReasons.length === 0;
  const comparable = publishableInputs && context.cls === "ok" && reviewMetrics.length === 0;
  const cls = invalidReasons.length || regressions.length ? "bad" : !comparable || context.cls !== "ok" ? "warn" : "ok";
  const noClaim = !comparable || cls !== "ok"
    ? {
        state: regressions.length || invalidReasons.length ? "blocked" : "review",
        title: regressions.length
          ? "Do not publish a positive comparison claim with regressions present"
          : invalidReasons.length
            ? "Do not publish a comparison claim from invalid evidence"
            : "Comparison claim needs operator review",
        detail: "Use no-performance-claims mode for releases that publish no throughput, latency, connection-rate, or comparison claims.",
        command: "RELEASE_NO_PERFORMANCE_CLAIMS=1 make benchmark-verify-release",
        reasons: reviewReasons.slice(0, MAX_COMPARISON_FINDINGS),
      }
    : {
        state: "claimable-after-record",
        title: "Comparison claim can move to release evidence after record",
        detail: "Record both selected runs through release evidence before citing the delta externally.",
        command: "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-release-benchmark",
        reasons: [],
      };
  const findings = [
    ...invalidReasons.map((message) => comparisonFinding("bad", "contract", message)),
    ...context.reviewItems.map((message) => comparisonFinding("warn", "context", message)),
    ...metrics.map((metric) => comparisonFinding(metric.state, metric.key, metric.title)),
  ].filter((item) => item.message).slice(0, MAX_COMPARISON_FINDINGS);
  return {
    schemaVersion: "phragma.performance.delta.v1",
    cls,
    label: cls === "ok" ? "claim delta ready" : cls === "bad" ? "regression blocked" : "review required",
    title: cls === "ok"
      ? "Candidate run improves or matches the baseline"
      : regressions.length
        ? `${regressions.length} regression${regressions.length === 1 ? "" : "s"} detected`
        : "Comparison needs review before any claim",
    detail: cls === "ok"
      ? `${improvements.length} improvement${improvements.length === 1 ? "" : "s"} and no regression beyond threshold.`
      : regressions.length
        ? regressions.map((metric) => metric.title).join(" ")
        : noClaim.title,
    thresholds: {
      throughputRegressionPct: opts.throughputThresholdPct ?? DEFAULT_DELTA_THRESHOLD_PCT,
      latencyRegressionPct: opts.latencyThresholdPct ?? DEFAULT_LATENCY_THRESHOLD_PCT,
      connectionRateRegressionPct: opts.connectionRateThresholdPct ?? DEFAULT_DELTA_THRESHOLD_PCT,
    },
    baseline,
    candidate,
    metrics,
    context,
    noClaim,
    findings,
  };
}

export function performanceComparisonPayload(model = {}) {
  return {
    schemaVersion: "phragma.performance.delta-payload.v1",
    comparisonState: safeComparisonText(model.label || ""),
    title: safeComparisonText(model.title || ""),
    detail: safeComparisonText(model.detail || ""),
    thresholds: model.thresholds || {},
    baseline: sanitizeComparisonRun(model.baseline),
    candidate: sanitizeComparisonRun(model.candidate),
    metrics: (model.metrics || []).slice(0, 6).map(sanitizeComparisonMetric),
    noClaim: {
      state: safeComparisonText(model.noClaim?.state || ""),
      title: safeComparisonText(model.noClaim?.title || ""),
      detail: safeComparisonText(model.noClaim?.detail || ""),
      command: safeComparisonText(model.noClaim?.command || ""),
      reasons: (model.noClaim?.reasons || []).slice(0, MAX_COMPARISON_FINDINGS).map(safeComparisonText),
    },
    findings: (model.findings || []).slice(0, MAX_COMPARISON_FINDINGS).map((item) => ({
      cls: safeComparisonText(item.cls || ""),
      label: safeComparisonText(item.label || ""),
      message: safeComparisonText(item.message || ""),
    })),
    custody: "browser-local comparison review; raw benchmark artifacts are not included, uploaded, signed, or retained",
  };
}

export function performanceComparisonPayloadJson(model = {}) {
  return JSON.stringify(performanceComparisonPayload(model), null, 2) + "\n";
}

export function performanceComparisonPayloadText(model = {}) {
  const payload = performanceComparisonPayload(model);
  const lines = [
    "Performance run comparison",
    `state: ${payload.comparisonState}`,
    `baseline: ${runComparisonLabel(payload.baseline)}`,
    `candidate: ${runComparisonLabel(payload.candidate)}`,
    "",
    ...payload.metrics.map((metric) => `- ${metric.label}: ${metric.title}`),
    "",
    `no-claim posture: ${payload.noClaim.title}`,
    `command: ${payload.noClaim.command}`,
  ];
  if (payload.noClaim.reasons.length) {
    lines.push("reasons:");
    for (const reason of payload.noClaim.reasons) lines.push(`- ${reason}`);
  }
  return lines.join("\n").trim() + "\n";
}

export function benchmarkRepairSteps(result) {
  if (!result) return [];
  const summary = result.summary || {};
  const errors = result.errors || [];
  const warnings = result.warnings || [];
  const messages = [...errors, ...warnings];
  const gate = benchmarkGate(result);
  const steps = [];
  const seen = new Set();
  const add = (step) => {
    const title = String(step.title || "").trim();
    if (!title) return;
    const key = [title, step.command || "", step.detail || ""].join("\n");
    if (seen.has(key)) return;
    seen.add(key);
    steps.push({
      level: step.level || "medium",
      badge: step.badge || step.level || "action",
      title,
      detail: step.detail || "",
      command: step.command || "",
    });
  };

  if (errors.length) {
    add({
      level: "high",
      badge: "contract",
      title: "Fix blocking evidence errors",
      detail: `${errors.length} schema, raw-artifact, or consistency error${errors.length === 1 ? "" : "s"} must be corrected before this benchmark can support a release or comparison claim.`,
      command: "ngfwperf verify --strict --publishable perf/results/<run>",
    });
  }

  if (result.strict && warnings.length) {
    add({
      level: "high",
      badge: "strict",
      title: "Resolve strict-gate warnings",
      detail: `${warnings.length} warning${warnings.length === 1 ? "" : "s"} remain. Strict release mode treats warnings as failures.`,
    });
  } else if (warnings.length) {
    add({
      level: "medium",
      badge: "review",
      title: "Review evidence warnings",
      detail: `${warnings.length} warning${warnings.length === 1 ? "" : "s"} remain before this should be used outside local regression work.`,
    });
  }

  if (result.artifacts?.iperf?.state === "missing" && requiresConntrackEvidence(summary)) {
    add({
      level: "high",
      badge: "iperf",
      title: "Load raw iperf3 evidence",
      detail: "Throughput summaries must be traceable to the raw iperf3 JSON from the measured run.",
    });
  }

  if (result.artifacts?.status?.state === "missing" && (summary.inspection_evidence?.status_captured || summary.host_tuning_evidence?.status_captured || summary.conntrack_evidence?.status_captured || summary.flowtable_evidence?.status_captured || requiresConntrackEvidence(summary))) {
    add({
      level: "high",
      badge: "status",
      title: "Load active runtime status",
      detail: "Capture status during benchmark traffic so inspection readiness, state-table pressure, and flowtable runtime state match the summary.",
      command: "ngfwctl status > ngfw-status-active.txt",
    });
  }

  if (result.artifacts?.nft?.state === "missing" && summary.flowtable_evidence?.nft_ruleset_captured) {
    add({
      level: "high",
      badge: "nft",
      title: "Load nftables ruleset evidence",
      detail: "Flowtable claims need the active nftables ruleset showing the fastpath declaration and offload rule.",
      command: "sudo nft list table inet openngfw > nft-openngfw-active.txt",
    });
  }

  if (includesAny(messages, ["does not match iperf3.json", "does not match status artifact", "does not match nftables artifact"])) {
    add({
      level: "high",
      badge: "mismatch",
      title: "Regenerate the summary from the raw artifacts",
      detail: "The loaded summary disagrees with raw benchmark evidence. Rebuild the report from the same run directory instead of editing fields by hand.",
      command: "ngfwperf verify --strict perf/results/<run>",
    });
  }

  if (includesAny(messages, ["flowtable_evidence"])) {
    add({
      level: "high",
      badge: "fast path",
      title: "Prove the flowtable fast path",
      detail: "Flowtable evidence must agree with active runtime status and the loaded nftables ruleset.",
      command: "ngfwctl status > ngfw-status-active.txt && sudo nft list table inet openngfw > nft-openngfw-active.txt",
    });
  }

  if (includesAny(messages, ["inspection_evidence"])) {
    add({
      level: "medium",
      badge: "inspection",
      title: "Capture inspection readiness",
      detail: "Inspection, bypass, failed-open, and failed-closed claims need policy-aware ngfwctl status evidence from the measured window.",
      command: "ngfwctl status > ngfw-status-active.txt",
    });
  }

  for (const item of gate.gates || []) {
    if (item.cls === "ok") continue;
    if (item.label === "Scope") {
      add({
        level: item.cls === "bad" ? "high" : "medium",
        badge: "scope",
        title: "Tighten the claim scope",
        detail: item.detail || "State exactly what environment, policy, services, and inspection state the benchmark proves.",
      });
    }
    if (item.label === "Inspection") {
      add({
        level: "medium",
        badge: "inspection",
        title: "Align the claim with inspection state",
        detail: item.detail || "Forwarding-only, bypassed, failed-open, and partially inspected runs must not be described as prevention throughput.",
      });
    }
    if (item.label === "Host tuning") {
      add({
        level: item.cls === "bad" ? "high" : "medium",
        badge: "tuning",
        title: item.cls === "bad" ? "Apply the throughput tuning profile" : "Capture host-tuning context",
        detail: item.detail || "High-bandwidth benchmarks require kernel forwarding and conntrack tuning evidence from active-load status.",
        command: item.cls === "bad" ? "sudo ngfwctl system tune --profile throughput --write --apply" : "ngfwctl status > ngfw-status-active.txt",
      });
    }
    if (item.label === "State table") {
      add({
        level: item.cls === "bad" ? "high" : "medium",
        badge: "state",
        title: item.cls === "bad" ? "Resolve state-table pressure" : "Capture state-table context",
        detail: item.detail || "State-table pressure affects high-throughput and high-connection-churn benchmark validity.",
        command: item.cls === "bad" ? "sudo ngfwctl system tune --profile throughput --write --apply" : "ngfwctl status > ngfw-status-active.txt",
      });
    }
    if (item.label === "Fast path") {
      add({
        level: item.cls === "bad" ? "high" : "medium",
        badge: "fast path",
        title: "Prove the flowtable fast path",
        detail: item.detail || "Flowtable claims require active runtime evidence and an nftables ruleset containing the fastpath and flow-add rule.",
        command: "ngfwctl status > ngfw-status-active.txt && sudo nft list table inet openngfw > nft-openngfw-active.txt",
      });
    }
  }

  if (!steps.length) {
    add({
      level: "low",
      badge: "ready",
      title: "Archive this evidence with the run artifacts",
      detail: "The summary, raw iperf output, active status, nftables evidence, and report can be retained together for release review.",
      command: "ngfwperf verify --strict --publishable perf/results/<run>",
    });
  }

  return steps.sort((a, b) => levelRank(a.level) - levelRank(b.level));
}

function has(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj || {}, key);
}

function comparisonRun(role, result = {}) {
  const summary = result?.summary || {};
  return {
    role,
    label: safeComparisonText(summary.profile || summary.generated_at || role),
    generatedAt: safeComparisonText(summary.generated_at || ""),
    profile: safeComparisonText(summary.profile || ""),
    securityServices: safeComparisonText(summary.security_services || ""),
    inspectionState: safeComparisonText(summary.inspection_state || ""),
    durationSeconds: finiteNumber(summary.duration_seconds),
    parallelStreams: finiteNumber(summary.parallel_streams),
    targetPort: finiteNumber(summary.target?.port),
    claimScope: safeComparisonText(summary.claim_scope || ""),
    throughputGbps: finiteNumber(summary.tcp_gbps),
    latencyMs: finiteNumber(summary.ping_avg_ms),
    connectionRate: connectionRate(summary),
    summary,
  };
}

function metricDelta(key, label, unit, baseline, candidate, { higherIsBetter, thresholdPct }) {
  if (!Number.isFinite(baseline) || !Number.isFinite(candidate)) {
    return {
      key,
      label,
      unit,
      baseline: Number.isFinite(baseline) ? baseline : null,
      candidate: Number.isFinite(candidate) ? candidate : null,
      absoluteDelta: null,
      percentDelta: null,
      direction: "unknown",
      state: "warn",
      title: `${label} cannot be compared because one run lacks a measured value`,
    };
  }
  const absoluteDelta = candidate - baseline;
  const percentDelta = baseline === 0 ? (candidate === 0 ? 0 : 100) : (absoluteDelta / Math.abs(baseline)) * 100;
  const better = higherIsBetter ? percentDelta > thresholdPct : percentDelta < -thresholdPct;
  const worse = higherIsBetter ? percentDelta < -thresholdPct : percentDelta > thresholdPct;
  const direction = better ? "improvement" : worse ? "regression" : "stable";
  const state = worse ? "bad" : better ? "ok" : "info";
  return {
    key,
    label,
    unit,
    baseline,
    candidate,
    absoluteDelta,
    percentDelta,
    direction,
    state,
    title: `${label} ${directionLabel(direction)} ${formatMetric(candidate, unit)} vs ${formatMetric(baseline, unit)} (${formatSignedPercent(percentDelta)})`,
  };
}

function comparisonContext(baseline = {}, candidate = {}) {
  const reviewItems = [];
  const check = (field, label) => {
    const a = baseline?.[field];
    const b = candidate?.[field];
    if (a !== b) reviewItems.push(`${label} differs: baseline ${valueOrUnknown(a)}, candidate ${valueOrUnknown(b)}`);
  };
  check("profile", "profile");
  check("security_services", "security services");
  check("inspection_state", "inspection state");
  check("duration_seconds", "duration");
  check("parallel_streams", "parallel streams");
  if (JSON.stringify(baseline?.target || {}) !== JSON.stringify(candidate?.target || {})) {
    reviewItems.push(`target differs: baseline ${valueOrUnknown(baseline?.target)}, candidate ${valueOrUnknown(candidate?.target)}`);
  }
  const baselineScope = String(baseline?.claim_scope || "").toLowerCase();
  const candidateScope = String(candidate?.claim_scope || "").toLowerCase();
  if (!baselineScope || !candidateScope) reviewItems.push("both runs need claim_scope before a comparison claim");
  if (baselineScope.includes("do not publish") || candidateScope.includes("do not publish")) {
    reviewItems.push("one or both claim scopes say do not publish");
  }
  if (baselineScope.includes("single-host") !== candidateScope.includes("single-host")) {
    reviewItems.push("single-host regression evidence is being compared with a different benchmark scope");
  }
  return {
    cls: reviewItems.length ? "warn" : "ok",
    title: reviewItems.length ? "Comparison context differs" : "Comparison context matches",
    reviewItems,
  };
}

function comparisonValidationReasons(role, result = {}, strict = false) {
  const reasons = [];
  const errors = Array.isArray(result.errors) ? result.errors : [];
  const warnings = Array.isArray(result.warnings) ? result.warnings : [];
  if (!result.summary) reasons.push(`${role} summary is not loaded`);
  if (errors.length) reasons.push(`${role} has ${errors.length} validation error${errors.length === 1 ? "" : "s"}`);
  if (strict && warnings.length) reasons.push(`${role} has ${warnings.length} strict warning${warnings.length === 1 ? "" : "s"}`);
  return reasons;
}

function comparisonFinding(cls, label, message) {
  return {
    cls: cls === "bad" ? "bad" : cls === "warn" ? "warn" : "info",
    label,
    message: safeComparisonText(message),
  };
}

function sanitizeComparisonRun(run = {}) {
  return {
    role: safeComparisonText(run.role || ""),
    label: safeComparisonText(run.label || ""),
    generatedAt: safeComparisonText(run.generatedAt || ""),
    profile: safeComparisonText(run.profile || ""),
    securityServices: safeComparisonText(run.securityServices || ""),
    inspectionState: safeComparisonText(run.inspectionState || ""),
    durationSeconds: finiteNumberOrNull(run.durationSeconds),
    parallelStreams: finiteNumberOrNull(run.parallelStreams),
    targetPort: finiteNumberOrNull(run.targetPort),
    claimScope: safeComparisonText(run.claimScope || ""),
    throughputGbps: finiteNumberOrNull(run.throughputGbps),
    latencyMs: finiteNumberOrNull(run.latencyMs),
    connectionRate: finiteNumberOrNull(run.connectionRate),
  };
}

function sanitizeComparisonMetric(metric = {}) {
  return {
    key: safeComparisonText(metric.key || ""),
    label: safeComparisonText(metric.label || ""),
    unit: safeComparisonText(metric.unit || ""),
    baseline: finiteNumberOrNull(metric.baseline),
    candidate: finiteNumberOrNull(metric.candidate),
    absoluteDelta: finiteNumberOrNull(metric.absoluteDelta),
    percentDelta: finiteNumberOrNull(metric.percentDelta),
    direction: safeComparisonText(metric.direction || ""),
    state: safeComparisonText(metric.state || ""),
    title: safeComparisonText(metric.title || ""),
  };
}

function connectionRate(summary = {}) {
  const churn = summary?.connection_churn;
  if (!plainObject(churn)) return null;
  for (const key of ["connections_per_second", "connection_rate", "connection_rate_per_second", "attempts_per_second", "successful_per_second", "cps", "rate"]) {
    const value = finiteNumber(churn[key]);
    if (Number.isFinite(value)) return value;
  }
  const attempts = finiteNumber(churn.successful ?? churn.established ?? churn.attempts);
  const duration = finiteNumber(summary.duration_seconds);
  if (Number.isFinite(attempts) && Number.isFinite(duration) && duration > 0) return attempts / duration;
  return null;
}

function finiteNumber(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function finiteNumberOrNull(v) {
  return Number.isFinite(Number(v)) ? Number(v) : null;
}

function directionLabel(direction) {
  if (direction === "improvement") return "improved to";
  if (direction === "regression") return "regressed to";
  return "held at";
}

function formatMetric(value, unit) {
  if (!Number.isFinite(value)) return "n/a";
  const digits = unit === "ms" ? 3 : 3;
  return `${value.toFixed(digits)} ${unit}`;
}

function formatSignedPercent(value) {
  if (!Number.isFinite(value)) return "n/a";
  const sign = value > 0 ? "+" : "";
  return `${sign}${value.toFixed(1)}%`;
}

function valueOrUnknown(value) {
  if (value === undefined || value === null || value === "") return "unknown";
  if (typeof value === "object") return safeComparisonText(JSON.stringify(value));
  return safeComparisonText(value);
}

function safeComparisonText(value) {
  return String(value ?? "")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[redacted-jwt]")
    .replace(/\b(Authorization:\s*Bearer)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 [redacted]")
    .replace(/\b(Bearer)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 [redacted]")
    .replace(/\b(token|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|password|passwd|secret|client[_-]?secret|key)\s*[:=]\s*[^\s"',;}]+/gi, (_, key) => `${key}=[redacted]`)
    .replace(/https?:\/\/[^\s"'<>]+/gi, (raw) => redactComparisonUrl(raw))
    .replace(/(^|[\s"'({=,;])\/(?:var\/lib|var\/log(?:\/openngfw)?|etc\/(?:openngfw|phragma)?|tmp|private\/tmp|var\/folders|private\/var\/folders|home\/[^'"\s,;}]+|Users\/[^'"\s,;}]+|opt\/[^'"\s,;}]+|data\/[^'"\s,;}]+)[^'"\s,;}]*/gi, "$1[server-local path redacted]")
    .slice(0, MAX_COMPARISON_TEXT);
}

function redactComparisonUrl(raw) {
  try {
    const parsed = new URL(raw);
    if (parsed.username || parsed.password) {
      parsed.username = "[redacted]";
      parsed.password = "";
    }
    for (const key of [...parsed.searchParams.keys()]) {
      if (/token|secret|password|passwd|api[_-]?key|key|cookie|auth/i.test(key)) parsed.searchParams.set(key, "[redacted]");
    }
    return parsed.toString();
  } catch {
    return raw.replace(/\/\/[^/\s"']+:[^@\s"']+@/g, "//[redacted]@");
  }
}

function runComparisonLabel(run = {}) {
  const label = run.label || run.profile || run.role || "run";
  const generated = run.generatedAt ? ` @ ${run.generatedAt}` : "";
  return `${label}${generated}`;
}

function q(v) {
  return JSON.stringify(v);
}

function basename(path = "") {
  const value = String(path || "");
  const idx = value.lastIndexOf("/");
  return idx >= 0 ? value.slice(idx + 1) : value;
}

function duplicateArtifactNames(items = []) {
  const recognized = new Set([
    "summary.json",
    "iperf3.json",
    ...STATUS_ARTIFACT_CANDIDATES,
    ...NFT_ARTIFACT_CANDIDATES,
  ]);
  const seen = new Map();
  const duplicates = [];
  for (const item of items) {
    if (!recognized.has(item.lowerName)) continue;
    const list = seen.get(item.lowerName) || [];
    list.push(item.path || item.name);
    seen.set(item.lowerName, list);
  }
  for (const [name, paths] of seen) {
    if (paths.length > 1) duplicates.push(`${name}: ${paths.join(", ")}`);
  }
  return duplicates;
}

function artifactKind(lowerName = "") {
  if (lowerName === "summary.json") return "summary";
  if (lowerName === "iperf3.json") return "iperf";
  if (STATUS_ARTIFACT_CANDIDATES.includes(lowerName)) return "status";
  if (NFT_ARTIFACT_CANDIDATES.includes(lowerName)) return "nft";
  return "";
}

function artifactLabel(kind = "") {
  return {
    summary: "summary.json",
    iperf: "iperf3.json",
    status: "status artifact",
    nft: "nft artifact",
  }[kind] || "artifact";
}

function safeArtifactName(file = {}) {
  return basename(String(file.webkitRelativePath || file.name || "selected artifact").replace(/\\/g, "/"));
}

function formatBytes(bytes) {
  const n = Number(bytes || 0);
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${Math.max(0, Math.trunc(n))} B`;
}

function runNameFromSelection(item) {
  if (!item?.path) return "";
  const parts = item.path.split("/").filter(Boolean);
  if (parts.length < 2) return "";
  return parts[parts.length - 2];
}

function value(v) {
  if (v === undefined || v === null || v === "") return "unknown";
  return String(v);
}

function formatStatusPercent(value) {
  const n = Number(value || 0);
  if (!Number.isFinite(n)) return "0.0";
  if (Math.abs(n) > 0 && Math.abs(n) < 0.1) return n.toFixed(3);
  return n.toFixed(1);
}

function inspectionPolicyLabel(inspection = {}) {
  if (inspection.idsEnabled === false || inspection.state === "disabled") return "disabled";
  if (inspection.idsMode === "IDS_MODE_PREVENT" || inspection.idsMode === 2) return "IPS prevent";
  if (inspection.idsMode === "IDS_MODE_DETECT" || inspection.idsMode === 1) return "IDS detect";
  if (inspection.inspectionState === "fully-inspected") return "IPS prevent";
  if (inspection.inspectionState === "partially-inspected") return "IDS detect";
  return inspection.idsEnabled ? "IDS/IPS enabled" : "disabled";
}

function idsFailureBehaviorLabel(value) {
  if (value === "IDS_FAILURE_BEHAVIOR_FAIL_OPEN" || value === 1) return "fail-open";
  if (value === "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED" || value === 2) return "fail-closed";
  return "";
}

function includesAny(messages, terms) {
  const text = messages.join("\n");
  return terms.some((term) => text.includes(term));
}

function summarizeGateMessages(messages, limit = 3) {
  const selected = messages.slice(0, limit).map((message) => String(message || "").trim()).filter(Boolean);
  const suffix = messages.length > selected.length ? ` ${messages.length - selected.length} more.` : "";
  return selected.join(" ") + suffix;
}

function levelRank(level) {
  if (level === "high") return 0;
  if (level === "medium") return 1;
  return 2;
}

function finiteNonNegative(v) {
  return typeof v === "number" && Number.isFinite(v) && v >= 0;
}

function integerMin(v, min) {
  return Number.isInteger(v) && v >= min;
}

function integerRange(v, min, max) {
  return Number.isInteger(v) && v >= min && v <= max;
}

function plainObject(v) {
  return v != null && typeof v === "object" && !Array.isArray(v);
}

function validateInspectionEvidence(summary, errors, warnings) {
  const present = has(summary, "inspection_evidence");
  if (!present) {
    if (requiresInspectionEvidence(summary)) {
      warnings.push("inspection_evidence is recommended for inspected, bypassed, or failure-mode benchmark claims; policy-aware inspection posture cannot be evaluated");
    }
    return;
  }
  const e = summary?.inspection_evidence;
  if (!plainObject(e)) {
    errors.push("inspection_evidence must be an object when present");
    return;
  }
  if (e.status_captured !== true) errors.push("inspection_evidence.status_captured must be true");
  if (!e.state) errors.push("inspection_evidence.state is required");
  if (!e.inspection_state) {
    errors.push("inspection_evidence.inspection_state is required");
  } else if (!CANONICAL.has(e.inspection_state)) {
    errors.push(`inspection_evidence.inspection_state ${q(e.inspection_state)} is not canonical`);
  } else if (CANONICAL.has(summary?.inspection_state) && e.inspection_state !== summary.inspection_state) {
    errors.push(`inspection_evidence.inspection_state ${q(e.inspection_state)} does not match summary inspection_state ${q(summary.inspection_state)}`);
  }

  switch (summary?.inspection_state) {
    case "fully-inspected":
    case "partially-inspected":
      if (e.state && e.state !== "ready") {
        errors.push(`inspection_evidence.state ${q(e.state)} does not support summary inspection_state ${q(summary.inspection_state)}`);
      }
      break;
    case "failed-open":
      if (e.state && e.state !== "failed-open") errors.push(`inspection_evidence.state ${q(e.state)} does not support failed-open summary`);
      if (e.failure_behavior && e.failure_behavior !== "fail-open") errors.push(`inspection_evidence.failure_behavior ${q(e.failure_behavior)} does not support failed-open summary`);
      break;
    case "failed-closed":
      if (e.state && e.state !== "failed-closed") errors.push(`inspection_evidence.state ${q(e.state)} does not support failed-closed summary`);
      if (e.failure_behavior && e.failure_behavior !== "fail-closed") errors.push(`inspection_evidence.failure_behavior ${q(e.failure_behavior)} does not support failed-closed summary`);
      break;
    case "bypassed-by-engine-health":
      if (e.state === "ready") errors.push("inspection_evidence.state ready does not support bypassed-by-engine-health summary");
      break;
    case "not-inspected":
      if (e.state && e.state !== "disabled") {
        warnings.push(`inspection_evidence.state is ${e.state} while summary inspection_state is not-inspected`);
      }
      break;
  }
}

function validateSecurityServiceConsistency(summary = {}, errors) {
  const state = String(summary?.inspection_state || "");
  const services = String(summary?.security_services || "").trim();
  if (!state || !services || !CANONICAL.has(state)) return;
  if (inspectionStateRequiresServices(state) && !securityServicesMentionInspection(services)) {
    errors.push(`security_services ${q(summary.security_services)} cannot support inspection_state ${q(state)}`);
  }
  if (state === "not-inspected" && securityServicesMentionInspection(services)) {
    errors.push(`security_services ${q(summary.security_services)} conflicts with inspection_state "not-inspected"`);
  }
}

function inspectionStateRequiresServices(state) {
  return ["fully-inspected", "partially-inspected", "failed-open", "failed-closed", "bypassed-by-engine-health"].includes(state);
}

function securityServicesMentionInspection(value = "") {
  const text = String(value || "").trim().toLowerCase();
  if (!text || ["none", "off", "disabled", "n/a", "na", "not-inspected", "forwarding-only", "l3/l4-only"].includes(text)) {
    return false;
  }
  return /(ids|ips|suricata|snort|zeek|threat|app[-_ ]?id|appid|app_id|dpi|inspection|malware|url|tls|waf)/.test(text);
}

function requiresInspectionEvidence(summary = {}) {
  return CANONICAL.has(summary?.inspection_state) && summary.inspection_state !== "not-inspected";
}

function validateConntrackEvidence(summary, errors, warnings) {
  const present = has(summary, "conntrack_evidence");
  if (!present) {
    if (requiresConntrackEvidence(summary)) {
      warnings.push("conntrack_evidence is recommended for throughput or connection-rate benchmarks; state-table capacity cannot be evaluated");
    }
    return;
  }
  const e = summary?.conntrack_evidence;
  if (!plainObject(e)) {
    errors.push("conntrack_evidence must be an object when present");
    return;
  }
  if (e.status_captured !== true) errors.push("conntrack_evidence.status_captured must be true");
  if (!e.state) errors.push("conntrack_evidence.state is required");
  if (!integerMin(e.current_entries, 0)) errors.push("conntrack_evidence.current_entries must be >= 0");
  if (!integerMin(e.max_entries, 0)) errors.push("conntrack_evidence.max_entries must be >= 0");
  if (!finiteNonNegative(e.usage_percent)) errors.push("conntrack_evidence.usage_percent must be a finite non-negative number");
  if (e.max_entries > 0 && e.current_entries > e.max_entries) {
    warnings.push("conntrack_evidence.current_entries exceeds max_entries");
  }
  if (e.state === "warning" || e.state === "degraded") {
    warnings.push(`conntrack_evidence state is ${e.state}; state-table pressure affected the benchmark`);
  }
}

function requiresConntrackEvidence(summary = {}) {
  if (has(summary, "connection_churn")) return true;
  const text = String(`${summary?.profile || ""} ${summary?.claim_scope || ""}`).toLowerCase();
  if (["throughput", "connection", "churn", "conntrack", "gbps", "high-bandwidth", "high bandwidth"].some((term) => text.includes(term))) {
    return true;
  }
  return Number(summary?.tcp_bits_per_second || 0) > 0 || Number(summary?.tcp_gbps || 0) > 0;
}

function validateHostTuningEvidence(summary, errors, warnings) {
  const present = has(summary, "host_tuning_evidence");
  if (!present) {
    if (requiresHostTuningEvidence(summary)) {
      warnings.push("host_tuning_evidence is recommended for high-bandwidth or connection-rate benchmarks; kernel forwarding tuning cannot be evaluated");
    }
    return;
  }
  const e = summary?.host_tuning_evidence;
  if (!plainObject(e)) {
    errors.push("host_tuning_evidence must be an object when present");
    return;
  }
  if (e.status_captured !== true) errors.push("host_tuning_evidence.status_captured must be true");
  if (!e.state) errors.push("host_tuning_evidence.state is required");
  if (e.state && e.state !== "ready") {
    warnings.push(`host_tuning_evidence state is ${e.state}; kernel forwarding tuning affected the benchmark`);
  }
}

function requiresHostTuningEvidence(summary = {}) {
  return requiresConntrackEvidence(summary);
}

function validateFlowtableEvidence(summary, errors) {
  const needsEvidence = String(`${summary?.profile || ""} ${summary?.claim_scope || ""}`).toLowerCase().includes("flowtable");
  const e = summary?.flowtable_evidence;
  if (needsEvidence && !e) {
    errors.push("flowtable_evidence is required for flowtable benchmark profiles");
    return;
  }
  if (!e) return;
  if (!plainObject(e)) {
    errors.push("flowtable_evidence must be an object when present");
    return;
  }
  if (!e.host_state) errors.push("flowtable_evidence.host_state is required");
  if (!e.runtime_state) errors.push("flowtable_evidence.runtime_state is required");
  if (needsEvidence && e.runtime_state && e.runtime_state !== "active") {
    errors.push("flowtable_evidence.runtime_state must be active for flowtable benchmark claims");
  }
  for (const key of ["status_captured", "nft_ruleset_captured", "flowtable_declared", "offload_rule_present"]) {
    if (needsEvidence && e[key] !== true) errors.push(`flowtable_evidence.${key} must be true`);
  }
}

function validateIperfEvidence(summary, text, errors, warnings) {
  const raw = String(text || "").trim();
  if (!raw) {
    if (requiresConntrackEvidence(summary)) {
      warnings.push("raw iperf3.json is not loaded; throughput cannot be traced to raw iperf evidence");
    }
    return { state: "missing", label: "not loaded" };
  }
  let report;
  try {
    report = JSON.parse(raw);
  } catch (e) {
    errors.push("iperf3.json invalid JSON: " + e.message);
    return { state: "invalid", label: "invalid JSON" };
  }
  if (report?.error) {
    errors.push("iperf3.json reports benchmark error: " + report.error);
    return { state: "invalid", label: "error" };
  }
  const measured = chooseThroughput(report);
  if (!finiteNonNegative(measured.bitsPerSecond) || measured.bitsPerSecond <= 0) {
    errors.push("iperf3.json does not contain a positive end.sum_received/sum/sum_sent bits_per_second value");
    return { state: "invalid", label: "missing throughput" };
  }
  const measuredGbps = measured.bitsPerSecond / 1_000_000_000;
  if (!closeRelative(summary?.tcp_bits_per_second, measured.bitsPerSecond, RAW_THROUGHPUT_TOLERANCE)) {
    errors.push(`summary tcp_bits_per_second ${num(summary?.tcp_bits_per_second)} does not match iperf3.json ${num(measured.bitsPerSecond)}`);
  }
  if (!closeRelative(summary?.tcp_gbps, measuredGbps, RAW_THROUGHPUT_TOLERANCE)) {
    errors.push(`summary tcp_gbps ${num(summary?.tcp_gbps, 6)} does not match iperf3.json ${num(measuredGbps, 6)}`);
  }
  const retransmits = iperfRetransmits(report);
  if (Number(summary?.tcp_retransmits) !== retransmits) {
    errors.push(`summary tcp_retransmits ${summary?.tcp_retransmits} does not match iperf3.json ${retransmits}`);
  }
  const host = report?.start?.connecting_to?.host || "";
  const port = Number(report?.start?.connecting_to?.port || 0);
  if (host && host !== summary?.target?.ip) {
    errors.push(`summary target.ip ${q(summary?.target?.ip)} does not match iperf3.json ${q(host)}`);
  }
  if (port > 0 && port !== Number(summary?.target?.port || 0)) {
    errors.push(`summary target.port ${summary?.target?.port} does not match iperf3.json ${port}`);
  }
  const duration = Number(report?.start?.test_start?.duration || 0);
  if (duration > 0 && Math.abs(Number(summary?.duration_seconds || 0) - duration) > 1) {
    errors.push(`summary duration_seconds ${summary?.duration_seconds} does not match iperf3.json ${num(duration, 3)}`);
  }
  const streams = Number(report?.start?.test_start?.num_streams || (Array.isArray(report?.start?.connected) ? report.start.connected.length : 0));
  if (streams > 0 && streams !== Number(summary?.parallel_streams || 0)) {
    errors.push(`summary parallel_streams ${summary?.parallel_streams} does not match iperf3.json ${streams}`);
  }
  return {
    state: "loaded",
    label: "loaded",
    bitsPerSecond: measured.bitsPerSecond,
    gbps: measuredGbps,
    retransmits,
    target: host && port ? `${host}:${port}` : "",
    durationSeconds: duration,
    parallelStreams: streams,
  };
}

function chooseThroughput(report) {
  const end = report?.end || {};
  for (const key of ["sum_received", "sum", "sum_sent"]) {
    const value = Number(end?.[key]?.bits_per_second || 0);
    if (value > 0) return { bitsPerSecond: value };
  }
  return { bitsPerSecond: 0 };
}

function iperfRetransmits(report) {
  const streams = Array.isArray(report?.end?.streams) ? report.end.streams : [];
  const total = streams.reduce((sum, stream) => sum + Number(stream?.sender?.retransmits || 0), 0);
  return total || Number(report?.end?.sum_sent?.retransmits || 0);
}

function closeRelative(got, want, tolerance) {
  const g = Number(got);
  const w = Number(want);
  if (g === w) return true;
  if (!finiteNonNegative(g) || !finiteNonNegative(w)) return false;
  return Math.abs(g - w) / Math.max(Math.abs(w), 1) <= tolerance;
}

function num(v, digits = 3) {
  const n = Number(v);
  return Number.isFinite(n) ? n.toFixed(digits) : String(v);
}

function validateStatusEvidence(summary, text, errors, warnings) {
  const raw = String(text || "").trim();
  const inspection = summary?.inspection_evidence;
  const hostTuning = summary?.host_tuning_evidence;
  const conntrack = summary?.conntrack_evidence;
  const flowtable = summary?.flowtable_evidence;
  if (!raw) {
    if (inspection?.status_captured === true) {
      warnings.push("inspection_evidence.status_captured is true but no raw ngfwctl status artifact is loaded");
    }
    if (hostTuning?.status_captured === true) {
      warnings.push("host_tuning_evidence.status_captured is true but no raw ngfwctl status artifact is loaded");
    }
    if (conntrack?.status_captured === true) {
      warnings.push("conntrack_evidence.status_captured is true but no raw ngfwctl status artifact is loaded");
    }
    if (flowtable?.status_captured === true) {
      warnings.push("flowtable_evidence.status_captured is true but no raw ngfwctl status artifact is loaded");
    }
    return { state: "missing", label: "not loaded" };
  }

  const parsed = parseStatusEvidence(raw);
  if (inspection) validateInspectionStatus(parsed, inspection, errors);
  if (summary?.host_tuning_evidence) validateHostTuningStatus(parsed, summary.host_tuning_evidence, errors);
  if (conntrack) validateConntrackStatus(parsed, conntrack, errors);
  if (flowtable) validateFlowtableStatus(parsed, flowtable, errors);
  return {
    state: "loaded",
    label: "loaded",
    inspection: parsed.inspectionFound ? parsed.inspection : null,
    hostTuning: parsed.hostTuningFound ? parsed.hostTuning : null,
    conntrack: parsed.conntrackFound ? parsed.conntrack : null,
    flowtableHost: parsed.flowHostState || "",
    flowtableRuntime: parsed.flowLiveState || "",
  };
}

function parseStatusEvidence(text) {
  const out = {
    inspectionFound: false,
    inspection: null,
    conntrackFound: false,
    conntrack: null,
    flowHostFound: false,
    flowHostState: "",
    flowLiveFound: false,
    flowLiveState: "",
    hostTuningFound: false,
    hostTuning: null,
  };
  const policy = text.match(/^\s*inspection:\s+(.+?)\s*$/m);
  const readiness = text.match(/^\s*inspection ready:\s*(\S+)/m);
  const engine = text.match(/^\s*inspection eng:\s+(\S+)\s+(\S+)\/(\S+)/m);
  const failure = text.match(/^\s*fail behavior:\s+(\S+)/m);
  const bypass = text.match(/^\s*bypass reason:\s+(.+?)\s*$/m);
  const degraded = text.match(/^\s*degraded mode:\s+(.+?)\s*$/m);
  if (policy || readiness || engine || failure || bypass || degraded) {
    out.inspectionFound = true;
    out.inspection = {
      state: readiness ? readiness[1] : "unknown",
      status_captured: true,
      inspection_state: inspectionStateFromStatus(policy ? policy[1] : "", readiness ? readiness[1] : ""),
    };
    if (engine) {
      out.inspection.engine_name = engine[1];
      out.inspection.engine_mode = engine[2];
      out.inspection.engine_state = engine[3];
    }
    if (failure) out.inspection.failure_behavior = failure[1];
    if (bypass) out.inspection.bypass_reason = bypass[1].trim();
    if (degraded) out.inspection.degraded_behavior = degraded[1].trim();
  }
  const tuning = text.match(/^\s*kernel tuning:\s+(\S+)/m);
  if (tuning) {
    out.hostTuningFound = true;
    out.hostTuning = { state: tuning[1], status_captured: true };
  }
  const conntrack = text.match(/^\s*state table:\s+(\S+)(?:\s+([0-9]+)\/([0-9]+) entries \(([0-9.]+)%\))?/m);
  if (conntrack) {
    out.conntrackFound = true;
    out.conntrack = {
      state: conntrack[1],
      current_entries: Number(conntrack[2] || 0),
      max_entries: Number(conntrack[3] || 0),
      usage_percent: Number(conntrack[4] || 0),
    };
  }
  const host = text.match(/^\s*flowtable host:\s+(\S+)/m);
  if (host) {
    out.flowHostFound = true;
    out.flowHostState = host[1];
  }
  const live = text.match(/^\s*flowtable live:\s+(\S+)/m);
  if (live) {
    out.flowLiveFound = true;
    out.flowLiveState = live[1];
  }
  return out;
}

function inspectionStateFromStatus(policyState, readinessState) {
  const ready = String(readinessState || "").trim().toLowerCase();
  if (ready === "disabled") return "not-inspected";
  if (ready === "failed-open") return "failed-open";
  if (ready === "failed-closed") return "failed-closed";
  if (ready === "degraded" || ready === "unknown") return "bypassed-by-engine-health";
  const policy = String(policyState || "").trim().toLowerCase();
  if (policy.includes("disabled")) return "not-inspected";
  if (policy.includes("ips") || policy.includes("prevent")) return "fully-inspected";
  if (policy.includes("ids") || policy.includes("detect")) return "partially-inspected";
  return "";
}

function validateInspectionStatus(parsed, expected, errors) {
  if (expected.status_captured !== true) return;
  if (!parsed.inspectionFound) {
    errors.push("summary inspection_evidence is present but status artifact has no inspection lines");
    return;
  }
  const got = parsed.inspection || {};
  if (expected.state && expected.state !== got.state) {
    errors.push(`summary inspection_evidence.state ${q(expected.state)} does not match status artifact ${q(got.state)}`);
  }
  if (expected.inspection_state && got.inspection_state && expected.inspection_state !== got.inspection_state) {
    errors.push(`summary inspection_evidence.inspection_state ${q(expected.inspection_state)} does not match status artifact ${q(got.inspection_state)}`);
  }
  for (const key of ["engine_name", "engine_mode", "engine_state", "failure_behavior", "bypass_reason", "degraded_behavior"]) {
    if (expected[key] && got[key] && expected[key] !== got[key]) {
      errors.push(`summary inspection_evidence.${key} ${q(expected[key])} does not match status artifact ${q(got[key])}`);
    }
  }
}

function validateHostTuningStatus(parsed, expected, errors) {
  if (expected.status_captured !== true) return;
  if (!parsed.hostTuningFound) {
    errors.push("summary host_tuning_evidence is present but status artifact has no kernel tuning line");
    return;
  }
  const got = parsed.hostTuning;
  if (expected.state !== got.state) {
    errors.push(`summary host_tuning_evidence.state ${q(expected.state)} does not match status artifact ${q(got.state)}`);
  }
}

function validateConntrackStatus(parsed, expected, errors) {
  if (!parsed.conntrackFound) {
    errors.push("summary conntrack_evidence is present but status artifact has no state table line");
    return;
  }
  const got = parsed.conntrack;
  if (expected.state !== got.state) {
    errors.push(`summary conntrack_evidence.state ${q(expected.state)} does not match status artifact ${q(got.state)}`);
  }
  if (Number(expected.current_entries || 0) !== got.current_entries) {
    errors.push(`summary conntrack_evidence.current_entries ${expected.current_entries} does not match status artifact ${got.current_entries}`);
  }
  if (Number(expected.max_entries || 0) !== got.max_entries) {
    errors.push(`summary conntrack_evidence.max_entries ${expected.max_entries} does not match status artifact ${got.max_entries}`);
  }
  if (Math.abs(Number(expected.usage_percent || 0) - got.usage_percent) > 0.05) {
    errors.push(`summary conntrack_evidence.usage_percent ${num(expected.usage_percent)} does not match status artifact ${num(got.usage_percent)}`);
  }
}

function validateFlowtableStatus(parsed, expected, errors) {
  if (expected.status_captured !== true) return;
  if (!parsed.flowHostFound) {
    errors.push("summary flowtable_evidence is present but status artifact has no flowtable host line");
  } else if (expected.host_state !== parsed.flowHostState) {
    errors.push(`summary flowtable_evidence.host_state ${q(expected.host_state)} does not match status artifact ${q(parsed.flowHostState)}`);
  }
  if (!parsed.flowLiveFound) {
    errors.push("summary flowtable_evidence is present but status artifact has no flowtable live line");
  } else if (expected.runtime_state !== parsed.flowLiveState) {
    errors.push(`summary flowtable_evidence.runtime_state ${q(expected.runtime_state)} does not match status artifact ${q(parsed.flowLiveState)}`);
  }
}

function validateNftEvidence(summary, text, errors, warnings) {
  const raw = String(text || "").trim();
  const flowtable = summary?.flowtable_evidence;
  if (!flowtable) return { state: "not-required", label: "not required" };
  if (!raw) {
    if (flowtable.nft_ruleset_captured === true) {
      warnings.push("flowtable_evidence.nft_ruleset_captured is true but no raw nftables artifact is loaded");
    }
    return { state: "missing", label: "not loaded" };
  }
  const declared = raw.includes("flowtable fastpath");
  const offload = raw.includes("flow add @fastpath");
  if (flowtable.nft_ruleset_captured !== true) {
    errors.push("summary flowtable_evidence.nft_ruleset_captured=false but nftables artifact is loaded");
  }
  if (Boolean(flowtable.flowtable_declared) !== declared) {
    errors.push(`summary flowtable_evidence.flowtable_declared=${Boolean(flowtable.flowtable_declared)} does not match nftables artifact=${declared}`);
  }
  if (Boolean(flowtable.offload_rule_present) !== offload) {
    errors.push(`summary flowtable_evidence.offload_rule_present=${Boolean(flowtable.offload_rule_present)} does not match nftables artifact=${offload}`);
  }
  return { state: "loaded", label: "loaded", flowtableDeclared: declared, offloadRulePresent: offload };
}

function schemaGate(errors, warnings, strict) {
  if (errors.length) {
    return gate("Contract", "bad", "Schema or required evidence failed.", `${errors.length} error(s) must be fixed.`);
  }
  if (strict && warnings.length) {
    return gate("Release gate", "bad", "Strict release verification fails.", `${warnings.length} warning(s) remain.`);
  }
  if (warnings.length) {
    return gate("Release gate", "warn", "Non-strict verification accepts this artifact.", `${warnings.length} warning(s) remain.`);
  }
  return gate("Release gate", "ok", "Strict verification is clean.", "No schema errors or warnings.");
}

function publicationScopeGate(summary) {
  const scope = String(summary?.claim_scope || "").toLowerCase();
  const profile = String(summary?.profile || "").toLowerCase();
  if (!summary?.claim_scope) return gate("Scope", "bad", "Claim scope is missing.", "A benchmark claim must state where it applies.");
  if (scope.includes("do not publish")) {
    return gate("Scope", "warn", "Publication requires the full external context.", summary.claim_scope);
  }
  if (scope.includes("single-host") || scope.includes("not a cloud") || scope.includes("not a nic") || profile.includes("netns")) {
    return gate("Scope", "warn", "Regression evidence only.", "Do not compare this as cloud-NIC or VM-Series-class throughput.");
  }
  if (scope.includes("measured environment only")) {
    return gate("Scope", "warn", "Scoped to the measured environment.", "Publish only with instance shape, NIC mode, policy, services, and inspection state.");
  }
  return gate("Scope", "ok", "Scope is explicit.", summary.claim_scope);
}

function inspectionGate(state) {
  switch (state) {
    case "fully-inspected":
      return gate("Inspection", "ok", "Traffic is labeled fully inspected.", "This can support a threat-prevention throughput claim if the rest of the evidence is complete.");
    case "partially-inspected":
      return gate("Inspection", "warn", "Traffic is partially inspected.", "Describe what was inspected and what was bypassed.");
    case "failed-closed":
      return gate("Inspection", "warn", "Failed-closed behavior evidence.", "Useful failure-mode evidence, not normal throughput evidence.");
    case "failed-open":
      return gate("Inspection", "warn", "Failed-open behavior evidence.", "Do not present as strict prevention throughput.");
    case "bypassed-by-policy":
    case "bypassed-by-engine-health":
      return gate("Inspection", "warn", "Inspection bypass is explicit.", "Useful only when the bypass reason is the intended claim.");
    case "blocked-before-inspection":
      return gate("Inspection", "warn", "Traffic was blocked before inspection.", "This is enforcement evidence, not forwarding throughput evidence.");
    case "not-inspected":
      return gate("Inspection", "warn", "Forwarding-only evidence.", "Do not use this as NGFW threat-prevention or App-ID throughput.");
    default:
      return gate("Inspection", state ? "warn" : "bad", state ? "Inspection state is non-canonical." : "Inspection state is missing.", state || "Use a canonical inspection state.");
  }
}

function hostTuningGate(summary) {
  const e = summary?.host_tuning_evidence;
  if (!e) {
    return requiresHostTuningEvidence(summary)
      ? gate("Host tuning", "warn", "High-bandwidth claim lacks kernel tuning evidence.", "Capture active-load ngfwctl status so forwarding and conntrack sysctl readiness is known.")
      : gate("Host tuning", "ok", "No high-bandwidth or connection-rate claim.", "Host tuning evidence is optional for this artifact.");
  }
  if (e.state === "ready") {
    return gate("Host tuning", "ok", "Kernel tuning is ready.", hostTuningDetail(e));
  }
  return gate("Host tuning", requiresHostTuningEvidence(summary) ? "bad" : "warn", "Kernel tuning was not ready.", hostTuningDetail(e));
}

function conntrackGate(summary) {
  const e = summary?.conntrack_evidence;
  if (!e) {
    return requiresConntrackEvidence(summary)
      ? gate("State table", "warn", "Throughput claim lacks state-table evidence.", "Capture active-load ngfwctl status so conntrack capacity pressure is known.")
      : gate("State table", "ok", "No throughput or connection-rate claim.", "State-table evidence is optional for this artifact.");
  }
  if (e.state === "degraded") {
    return gate("State table", "bad", "State table was degraded.", conntrackDetail(e));
  }
  if (e.state === "warning") {
    return gate("State table", "warn", "State table pressure warning.", conntrackDetail(e));
  }
  return gate("State table", "ok", "State table evidence captured.", conntrackDetail(e));
}

function flowtableGate(summary) {
  const text = `${summary?.profile || ""} ${summary?.claim_scope || ""}`.toLowerCase();
  const claimed = text.includes("flowtable");
  const e = summary?.flowtable_evidence;
  if (!e) {
    return claimed
      ? gate("Fast path", "bad", "Flowtable claim lacks runtime evidence.", "Capture active-load status and nftables ruleset evidence.")
      : gate("Fast path", "ok", "No flowtable claim.", "Fast-path evidence is optional for this artifact.");
  }
  const nftProven = e.nft_ruleset_captured === true && e.flowtable_declared === true && e.offload_rule_present === true;
  if (e.runtime_state === "active" && nftProven) {
    return gate("Fast path", "ok", "Flowtable runtime is proven active.", "Status and nftables evidence agree.");
  }
  return gate(claimed ? "Fast path" : "Fast path", claimed ? "bad" : "warn",
    "Flowtable evidence is incomplete.",
    `runtime=${e.runtime_state || "unknown"}, nft=${nftProven ? "proven" : "incomplete"}`);
}

function conntrackDetail(e) {
  if (e?.max_entries > 0) {
    return `${e.current_entries || 0}/${e.max_entries} entries (${Number(e.usage_percent || 0).toFixed(1)}%).`;
  }
  return e?.state || "captured";
}

function hostTuningDetail(e) {
  if (!e) return "";
  const parts = [e.state || "unknown"];
  if (e.profile) parts.push(`profile ${e.profile}`);
  if (e.config_path) parts.push(e.config_path);
  return parts.join("; ");
}

function gate(label, cls, title, detail) {
  return { label, cls, title, detail };
}
