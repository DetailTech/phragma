import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { artifactSizeProblem, benchmarkCollectionRunbook, benchmarkCollectionRunbookText, benchmarkRepairSteps, comparePerformanceRuns, detectBenchmarkArtifacts, performanceComparisonPayload, performanceComparisonPayloadJson, performanceComparisonPayloadText, releaseGateSummary, statusEvidenceText, validateSummaryText } from "./performance.js";
import { performanceClaimGateWorkbenchModel, performanceEvidenceHandoffPacket, performanceReleaseDecisionModel } from "./views/performance.js";

const performanceViewSource = readFileSync(new URL("./views/performance.js", import.meta.url), "utf8");
assert.match(performanceViewSource, /type: "button", title: "Verify benchmark evidence"/);
assert.match(performanceViewSource, /type: "button", title: "Open Performance API and CLI context"/);
assert.match(performanceViewSource, /openAutomationContext\("#\/performance"\)/);
assert.match(performanceViewSource, /perf-runbook-head/);
assert.doesNotMatch(performanceViewSource, /justifyContent: "space-between"/);
assert.match(performanceViewSource, /title: "Pin performance evidence handoff to investigation case"/);
assert.match(performanceViewSource, /appendInvestigationPacketToActiveServerCase/);
assert.match(performanceViewSource, /api\.addInvestigationCaseEvidence\(id, evidence\)/);
assert.match(performanceViewSource, /activeInvestigationServerCaseHref/);
assert.match(performanceViewSource, /Open active case/);
assert.match(performanceViewSource, /Local browser-only fallback was used/);
assert.match(performanceViewSource, /title: "Copy performance evidence handoff"/);
assert.match(performanceViewSource, /title: "Export performance evidence handoff JSON"/);
assert.match(performanceViewSource, /title: "Compare performance runs"/);
assert.match(performanceViewSource, /title: "Copy performance comparison delta payload"/);
assert.match(performanceViewSource, /title: "Export performance comparison delta JSON"/);
assert.match(performanceViewSource, /kind: "performance-evidence"/);
assert.match(performanceViewSource, /type: "button", title: "Load current runtime status evidence"/);
assert.match(performanceViewSource, /type: "button", title: "Clear loaded benchmark evidence"/);
assert.match(performanceViewSource, /title: `Copy \$\{command\.label\} command`/);
assert.match(performanceViewSource, /"aria-label": `Copy \$\{workflow\.label\} \$\{command\.label\} command`/);
assert.match(performanceViewSource, /title: `Copy \$\{command\.label\} release command`/);
assert.match(performanceViewSource, /type: "button", title: "Copy benchmark collection runbook"/);
assert.match(performanceViewSource, /title: `Copy repair command: \$\{step\.title\}`/);
assert.match(performanceViewSource, /dataset: \{ perfReadinessParity: state \}/);
assert.match(performanceViewSource, /#\/readiness\?packet=release-benchmark/);
assert.match(performanceViewSource, /dataset: \{ perfDecisionState: model\.cls \}/);
assert.match(performanceViewSource, /dataset: \{ perfDecision: item\.key \}/);
assert.match(performanceViewSource, /#\/readiness\?drawer=support-bundle/);
assert.match(performanceViewSource, /#\/readiness\?drawer=release-acceptance/);
assert.match(performanceViewSource, /RELEASE_NO_PERFORMANCE_CLAIMS=1 make benchmark-verify-release/);
assert.match(performanceViewSource, /Do not publish a throughput or comparison claim from this artifact/);
assert.match(performanceViewSource, /make benchmark-verify-release/);
assert.match(performanceViewSource, /does not record backend release evidence/);
assert.match(performanceViewSource, /Publishable claim gate workbench/);
assert.match(performanceViewSource, /api\.releaseAcceptanceStatus\(\)/);
assert.match(performanceViewSource, /dataset: \{ perfClaimWorkbench: model\.releaseDecision\.cls \}/);
assert.match(performanceViewSource, /dataset: \{ perfReleaseBenchmarkStatus: model\.releaseBenchmarkGate\.state \}/);
assert.match(performanceViewSource, /dataset: \{ perfClaimDecision: row\.key \}/);
assert.match(performanceViewSource, /dataset: \{ perfComparisonPacketPreview: "true" \}/);
assert.match(performanceViewSource, /dataset: \{ perfNextCommands: "true" \}/);
assert.match(performanceViewSource, /Copy performance \$\{item\.role\} command/);
assert.match(performanceViewSource, /RELEASE_NO_PERFORMANCE_CLAIMS=1 make release-acceptance-assemble release-acceptance-verify/);

const summary = `{
  "schema_version": "phragma.perf.v1",
  "generated_at": "2026-06-17T05:00:00Z",
  "profile": "cloud-throughput",
  "security_services": "none",
  "inspection_state": "not-inspected",
  "target": {"ip": "10.0.2.20", "port": 5201},
  "duration_seconds": 60,
  "parallel_streams": 4,
  "tcp_bits_per_second": 1000000000,
  "tcp_gbps": 1.0,
  "tcp_retransmits": 7,
  "host_tuning_evidence": {
    "state": "ready",
    "status_captured": true,
    "profile": "throughput"
  },
  "conntrack_evidence": {
    "state": "ready",
    "status_captured": true,
    "current_entries": 25,
    "max_entries": 1048576,
    "usage_percent": 0.002
  },
  "claim_scope": "measured environment only throughput evidence"
}`;

const matchingIperf = `{
  "start": {
    "connecting_to": {"host": "10.0.2.20", "port": 5201},
    "test_start": {"num_streams": 4, "duration": 60}
  },
  "end": {
    "sum_received": {"bits_per_second": 1000000000},
    "sum_sent": {"bits_per_second": 1001000000, "retransmits": 7}
  }
}`;

const matchingStatus = `policy dataplane:
  flowtable host:  inactive
  flowtable live:  inactive
  kernel tuning:  ready
  state table:    ready 25/1048576 entries (0.002%)
`;

const liveStatus = {
  runtime: { activeDataplane: "nftables/conntrack" },
  dataplane: {
    flowtable: { hostState: "inactive", runtimeState: "inactive" },
    kernelTuning: { state: "ready" },
    conntrack: { state: "ready", currentEntries: 25, maxEntries: 1048576, usagePercent: 0.002 },
  },
  inspection: {
    state: "disabled",
    idsEnabled: false,
    idsMode: "IDS_MODE_UNSPECIFIED",
    engineName: "suricata",
    engineMode: "managed",
    engineState: "active",
    failureBehavior: "IDS_FAILURE_BEHAVIOR_UNSPECIFIED",
  },
};

{
  const runbook = benchmarkCollectionRunbook();
  assert.equal(runbook.schemaVersion, "phragma.performance.collection-runbook.v1");
  assert.equal(runbook.workflows.length, 2);
  assert.ok(runbook.workflows.some((workflow) => workflow.id === "local-netns"));
  assert.ok(runbook.workflows.some((workflow) => workflow.id === "three-host"));
  const commands = JSON.stringify(runbook.workflows.flatMap((workflow) => workflow.commands));
  for (const required of [
    "make benchmark-netns-check",
    "sudo DURATION=30 PARALLEL=8 make benchmark-netns",
    "make benchmark-check",
    "make benchmark",
    "go run ./cmd/ngfwperf verify --strict perf/results",
  ]) {
    assert.ok(commands.includes(required), `runbook missing ${required}`);
  }
  const text = benchmarkCollectionRunbookText(runbook);
  assert.match(text, /Benchmark collection runbook/);
  assert.match(text, /browser-local command handoff/);
  assert.match(text, /summary\.json, iperf3\.json, ngfw-status-active\.txt, nft-openngfw-final\.txt/);
  assert.match(text, /make benchmark-verify-release/);
  assert.match(text, /Use live status is current posture only/);
  for (const leaked of [/\/Users\//, /\/private\/tmp\//, /token=/i, /password=/i, /api[_-]?key=/i]) {
    assert.equal(leaked.test(text), false, `runbook leaked ${leaked}`);
  }
}

{
  const text = statusEvidenceText(liveStatus);

  assert.match(text, /throughput path: nftables\/conntrack/);
  assert.match(text, /inspection ready:disabled/);
  assert.match(text, /kernel tuning:\s+ready/);
  assert.match(text, /state table:\s+ready 25\/1048576 entries \(0\.002%\)/);

  const result = validateSummaryText(summary, { iperfText: matchingIperf, statusText: text });
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.warnings, []);
  assert.equal(result.artifacts.status.conntrack.max_entries, 1048576);
  const packet = performanceEvidenceHandoffPacket(result, true, "#/performance");
  assert.equal(packet.schemaVersion, "phragma.investigation.handoff.v1");
  assert.equal(packet.kind, "performance-evidence");
  assert.equal(packet.source.route, "#/performance");
  assert.equal(packet.summary.strictMode, true);
  assert.equal(packet.summary.profile, "cloud-throughput");
  assert.equal(packet.summary.rawStatus, "disabled / ready / ready / inactive");
  assert.equal(packet.summary.releaseEvidenceHref, "#/readiness?packet=release-benchmark");
  assert.equal(packet.summary.supportBundleHref, "#/readiness?drawer=support-bundle");
  assert.equal(packet.summary.noPerformanceClaimsCommand, "RELEASE_NO_PERFORMANCE_CLAIMS=1 make benchmark-verify-release");
  assert.ok(packet.evidence.some((line) => line.includes("claim scope: measured environment only throughput evidence")));
  assert.ok(packet.evidence.some((line) => line.includes("operator decision:")));
  assert.equal(packet.artifacts.operatorDecision.releaseEvidenceHref, "#/readiness?packet=release-benchmark");
  assert.ok(packet.artifacts.operatorDecision.decisions.some((item) => item.key === "support-readiness"));
  assert.equal(packet.artifacts.validation.errors.length, 0);
}

{
  const detected = detectBenchmarkArtifacts([
    { name: "iperf3-warmup.json", webkitRelativePath: "perf/results/run-a/iperf3-warmup.json" },
    { name: "firewall-status-final.txt", webkitRelativePath: "perf/results/run-a/firewall-status-final.txt" },
    { name: "summary.json", webkitRelativePath: "perf/results/run-a/summary.json" },
    { name: "nft-openngfw-final.txt", webkitRelativePath: "perf/results/run-a/nft-openngfw-final.txt" },
    { name: "iperf3.json", webkitRelativePath: "perf/results/run-a/iperf3.json" },
    { name: "firewall-status-active.txt", webkitRelativePath: "perf/results/run-a/firewall-status-active.txt" },
  ]);

  assert.equal(detected.runName, "run-a");
  assert.equal(detected.summary.name, "summary.json");
  assert.equal(detected.iperf.name, "iperf3.json");
  assert.equal(detected.status.name, "firewall-status-active.txt");
  assert.equal(detected.nft.name, "nft-openngfw-final.txt");
  assert.equal(detected.recognizedCount, 4);
  assert.deepEqual(detected.missing, []);
}

{
  const detected = detectBenchmarkArtifacts([
    { name: "summary.json", webkitRelativePath: "run-b/summary.json" },
  ]);

  assert.equal(detected.runName, "run-b");
  assert.equal(detected.recognizedCount, 1);
  assert.deepEqual(detected.missing, ["iperf3.json", "status artifact", "nft artifact"]);
}

{
  const detected = detectBenchmarkArtifacts([
    { name: "summary.json", webkitRelativePath: "perf/results/run-c/summary.json", size: 120 },
    { name: "summary.json", webkitRelativePath: "perf/results/run-c/copy/summary.json", size: 120 },
    { name: "firewall-status-active.txt", webkitRelativePath: "perf/results/run-c/firewall-status-active.txt", size: 80 },
    { name: "firewall-status-active.txt", webkitRelativePath: "perf/results/run-c/old/firewall-status-active.txt", size: 80 },
  ]);

  assert.deepEqual(detected.duplicates, [
    "summary.json: perf/results/run-c/summary.json, perf/results/run-c/copy/summary.json",
    "firewall-status-active.txt: perf/results/run-c/firewall-status-active.txt, perf/results/run-c/old/firewall-status-active.txt",
  ]);
}

{
  assert.equal(artifactSizeProblem({ name: "summary.json", size: 2 * 1024 * 1024 }, "summary"), "");
  assert.match(
    artifactSizeProblem({ name: "iperf3.json", size: 10 * 1024 * 1024 + 1 }, "iperf"),
    /iperf3\.json iperf3\.json is 10\.0 MiB, over the 10\.0 MiB limit/,
  );
  const detected = detectBenchmarkArtifacts([
    { name: "summary.json", webkitRelativePath: "perf/results/run-d/summary.json", size: 2 * 1024 * 1024 + 1 },
  ]);
  assert.equal(detected.sizeProblems.length, 1);
  assert.match(detected.sizeProblems[0], /summary\.json summary\.json is 2\.0 MiB, over the 2\.0 MiB limit/);
}

{
  const result = validateSummaryText(summary, { iperfText: matchingIperf, statusText: matchingStatus });
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.warnings, []);
  assert.equal(result.artifacts.iperf.state, "loaded");
  assert.equal(result.artifacts.status.state, "loaded");
  assert.equal(result.artifacts.iperf.gbps, 1);
  const steps = benchmarkRepairSteps(result);
  assert.ok(steps.every((step) => step.level !== "high"));
  assert.ok(steps.some((step) => step.title === "Tighten the claim scope"));
  assert.ok(steps.some((step) => step.title === "Align the claim with inspection state"));
}

{
  const legacy = validateSummaryText(summary.replace("phragma.perf.v1", "openngfw.perf.v1"), { iperfText: matchingIperf, statusText: matchingStatus });
  assert.deepEqual(legacy.errors, []);
  assert.match(legacy.warnings.join("\n"), /legacy/);
}

{
  const result = validateSummaryText(summary.replace('"inspection_state": "not-inspected"', '"inspection_state": "fully-inspected"'));

  assert.match(result.errors.join("\n"), /security_services "none" cannot support inspection_state "fully-inspected"/);
}

{
  const result = validateSummaryText(summary.replace('"security_services": "none"', '"security_services": "suricata-prevent"'));

  assert.match(result.errors.join("\n"), /security_services "suricata-prevent" conflicts with inspection_state "not-inspected"/);
}

{
  const result = validateSummaryText(summary);
  assert.deepEqual(result.errors, []);
  assert.match(result.warnings.join("\n"), /raw iperf3\.json is not loaded/);
  assert.match(result.warnings.join("\n"), /no raw ngfwctl status artifact is loaded/);
  assert.equal(result.artifacts.iperf.state, "missing");
  assert.equal(result.artifacts.status.state, "missing");
  const steps = benchmarkRepairSteps(result);
  assert.ok(steps.some((step) => step.title === "Load raw iperf3 evidence"));
  assert.ok(steps.some((step) => step.title === "Load active runtime status" && step.command === "ngfwctl status > ngfw-status-active.txt"));
  assert.ok(steps.some((step) => step.title === "Review evidence warnings"));

  const release = releaseGateSummary(result);
  assert.equal(release.cls, "warn");
  assert.equal(release.blockers.length, 0);
  assert.ok(release.reviewItems.some((item) => item.label === "Warnings"));
  assert.ok(release.reviewItems.some((item) => item.label === "Scope"));
  const decision = performanceReleaseDecisionModel(result, false);
  assert.equal(decision.cls, "warn");
  assert.equal(decision.label, "review");
  assert.equal(decision.releaseEvidenceHref, "#/readiness?packet=release-benchmark");
  assert.equal(decision.releaseAcceptanceHref, "#/readiness?drawer=release-acceptance");
  assert.equal(decision.supportBundleHref, "#/readiness?drawer=support-bundle");
  assert.equal(decision.noPerformanceClaimsStatusCommand, "RELEASE_NO_PERFORMANCE_CLAIMS=1 make release-acceptance-status");
  assert.ok(decision.decisions.some((item) => item.key === "external-publication" && item.cls === "bad"));
  assert.ok(decision.decisions.some((item) => item.key === "no-performance-claims" && /no throughput/.test(item.detail)));

  const workbench = performanceClaimGateWorkbenchModel(result, false, {
    checks: [
      {
        name: "release-benchmark",
        state: "missing",
        next_action: "stage publishable benchmark evidence before release notes",
      },
    ],
  });
  assert.equal(workbench.loadedSummary.state, "loaded");
  assert.equal(workbench.releaseDecision.label, "claim review");
  assert.equal(workbench.releaseBenchmarkGate.state, "missing");
  assert.equal(workbench.releaseBenchmarkGate.cls, "bad");
  assert.ok(workbench.claimRows.some((row) => row.key === "external-performance-claim" && row.label === "not safe"));
  assert.ok(workbench.nextCommands.some((item) => item.role === "no claims manifest" && item.command === "RELEASE_NO_PERFORMANCE_CLAIMS=1 make release-acceptance-assemble release-acceptance-verify"));
}

{
  const result = validateSummaryText(summary, { iperfText: `{
    "start": {
      "connecting_to": {"host": "10.0.2.21", "port": 5202},
      "test_start": {"num_streams": 3, "duration": 30}
    },
    "end": {
      "sum_received": {"bits_per_second": 2000000000},
      "sum_sent": {"bits_per_second": 2000000000, "retransmits": 9}
    }
  }` });
  for (const field of ["tcp_bits_per_second", "tcp_gbps", "tcp_retransmits", "target.ip", "target.port", "duration_seconds", "parallel_streams"]) {
    assert.match(result.errors.join("\n"), new RegExp(field.replace(".", "\\.")));
  }
  const steps = benchmarkRepairSteps(result);
  assert.equal(steps[0].title, "Fix blocking evidence errors");
  assert.ok(steps.some((step) => step.title === "Regenerate the summary from the raw artifacts"));

  const release = releaseGateSummary(result);
  assert.equal(release.cls, "bad");
  assert.ok(release.blockers.some((item) => item.label === "Contract" && /blocking evidence errors/.test(item.title)));
  assert.ok(release.blockers.some((item) => /tcp_bits_per_second/.test(item.detail)));
}

const inspectedSummary = `{
  "schema_version": "phragma.perf.v1",
  "generated_at": "2026-06-17T05:00:00Z",
  "profile": "ids-prevent-large-flow",
  "security_services": "suricata-prevent",
  "inspection_state": "fully-inspected",
  "target": {"ip": "10.0.2.20", "port": 5201},
  "duration_seconds": 60,
  "parallel_streams": 4,
  "tcp_bits_per_second": 1000000000,
  "tcp_gbps": 1.0,
  "tcp_retransmits": 7,
  "inspection_evidence": {
    "state": "ready",
    "status_captured": true,
    "inspection_state": "fully-inspected",
    "engine_name": "suricata",
    "engine_mode": "managed",
    "engine_state": "active",
    "failure_behavior": "fail-closed"
  },
  "host_tuning_evidence": {
    "state": "ready",
    "status_captured": true,
    "profile": "throughput"
  },
  "conntrack_evidence": {
    "state": "ready",
    "status_captured": true,
    "current_entries": 25,
    "max_entries": 1048576,
    "usage_percent": 0.002
  },
  "claim_scope": "cloud benchmark with profile context, policy, service, inspection, instance, and NIC details"
}`;

const matchingInspectionStatus = `policy dataplane:
  inspection:      IPS prevent
  inspection ready:ready
  inspection eng:  suricata managed/active
  fail behavior:   fail-closed
  kernel tuning:  ready
  state table:    ready 25/1048576 entries (0.002%)
`;

function iperfFor(bitsPerSecond, retransmits = 7) {
  return `{
    "start": {
      "connecting_to": {"host": "10.0.2.20", "port": 5201},
      "test_start": {"num_streams": 4, "duration": 60}
    },
    "end": {
      "sum_received": {"bits_per_second": ${bitsPerSecond}},
      "sum_sent": {"bits_per_second": ${bitsPerSecond}, "retransmits": ${retransmits}}
    }
  }`;
}

function inspectedRun({ gbps = 1, latency = 0.4, attempts = 6000, claimScope = "cloud benchmark with profile context, policy, service, inspection, instance, and NIC details" } = {}) {
  return JSON.stringify({
    schema_version: "phragma.perf.v1",
    generated_at: "2026-06-17T05:00:00Z",
    profile: "ids-prevent-large-flow",
    security_services: "suricata-prevent",
    inspection_state: "fully-inspected",
    target: { ip: "10.0.2.20", port: 5201 },
    duration_seconds: 60,
    parallel_streams: 4,
    tcp_bits_per_second: gbps * 1_000_000_000,
    tcp_gbps: gbps,
    tcp_retransmits: 7,
    ping_avg_ms: latency,
    connection_churn: { attempts },
    inspection_evidence: {
      state: "ready",
      status_captured: true,
      inspection_state: "fully-inspected",
      engine_name: "suricata",
      engine_mode: "managed",
      engine_state: "active",
      failure_behavior: "fail-closed",
    },
    host_tuning_evidence: {
      state: "ready",
      status_captured: true,
      profile: "throughput",
    },
    conntrack_evidence: {
      state: "ready",
      status_captured: true,
      current_entries: 25,
      max_entries: 1048576,
      usage_percent: 0.002,
    },
    claim_scope: claimScope,
  });
}

{
  const text = statusEvidenceText({
    dataplane: {
      kernelTuning: { state: "ready" },
      conntrack: { state: "ready", currentEntries: 25, maxEntries: 1048576, usagePercent: 0.002 },
    },
    inspection: {
      state: "ready",
      idsEnabled: true,
      idsMode: "IDS_MODE_PREVENT",
      engineName: "suricata",
      engineMode: "managed",
      engineState: "active",
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
    },
  });
  const result = validateSummaryText(inspectedSummary, {
    iperfText: matchingIperf,
    statusText: text,
  });

  assert.deepEqual(result.errors, []);
  assert.equal(result.artifacts.status.inspection.inspection_state, "fully-inspected");
  assert.equal(result.artifacts.status.inspection.failure_behavior, "fail-closed");
}

{
  const result = validateSummaryText(inspectedSummary, {
    iperfText: matchingIperf,
    statusText: matchingInspectionStatus,
  });
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.warnings, []);
  assert.equal(result.artifacts.status.inspection.state, "ready");
  assert.equal(result.artifacts.status.inspection.inspection_state, "fully-inspected");

  const release = releaseGateSummary(result);
  assert.equal(release.cls, "ok");
  assert.equal(release.label, "publishable");
  assert.deepEqual(release.blockers, []);
  assert.deepEqual(release.reviewItems, []);
  const decision = performanceReleaseDecisionModel(result, true);
  assert.equal(decision.cls, "ok");
  assert.equal(decision.label, "record evidence");
  assert.equal(decision.recordCommand, "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-release-benchmark");
  assert.ok(decision.rawArtifactPosture.includes("iperf 1.000 Gbps"));
  assert.ok(decision.decisions.some((item) => item.key === "external-publication" && item.cls === "ok"));
  assert.ok(decision.decisions.some((item) => item.key === "unsupported-scope" && item.cls === "info"));

  const workbench = performanceClaimGateWorkbenchModel(result, true, {
    checks: [
      {
        name: "release-benchmark",
        state: "passed",
        benchmark_summary: "perf/release-results/run-1/summary.json",
      },
    ],
  });
  assert.equal(workbench.releaseDecision.cls, "ok");
  assert.equal(workbench.releaseDecision.label, "claim-safe after record");
  assert.equal(workbench.strictVerifier.label, "valid");
  assert.equal(workbench.releaseBenchmarkGate.label, "passed");
  assert.equal(workbench.releaseBenchmarkGate.meta, "perf/release-results/run-1/summary.json");
  assert.ok(workbench.claimRows.some((row) => row.key === "external-performance-claim" && row.label === "safe after record"));
}

{
  const result = validateSummaryText(inspectedSummary, {
    iperfText: matchingIperf,
    statusText: `policy dataplane:
  inspection:      IPS prevent
  inspection ready:failed-open
  inspection eng:  suricata managed/failed
  fail behavior:   fail-open
  kernel tuning:  ready
  state table:    ready 25/1048576 entries (0.002%)
`,
  });
  for (const field of ["inspection_evidence.state", "inspection_evidence.inspection_state", "engine_state", "failure_behavior"]) {
    assert.match(result.errors.join("\n"), new RegExp(field.replace(".", "\\.")));
  }
  const steps = benchmarkRepairSteps(result);
  assert.ok(steps.some((step) => step.title === "Capture inspection readiness"));
  assert.ok(steps.some((step) => step.title === "Regenerate the summary from the raw artifacts"));
}

const flowtableSummary = `{
  "schema_version": "phragma.perf.v1",
  "generated_at": "2026-06-17T05:00:00Z",
  "profile": "flowtable-forwarding",
  "security_services": "none",
  "inspection_state": "not-inspected",
  "target": {"ip": "10.0.2.20", "port": 5201},
  "duration_seconds": 60,
  "parallel_streams": 4,
  "tcp_bits_per_second": 1000000000,
  "tcp_gbps": 1.0,
  "tcp_retransmits": 7,
  "conntrack_evidence": {
    "state": "ready",
    "status_captured": true,
    "current_entries": 25,
    "max_entries": 1048576,
    "usage_percent": 0.002
  },
  "host_tuning_evidence": {
    "state": "ready",
    "status_captured": true,
    "profile": "throughput"
  },
  "flowtable_evidence": {
    "host_state": "ready",
    "runtime_state": "active",
    "status_captured": true,
    "nft_ruleset_captured": true,
    "flowtable_declared": true,
    "offload_rule_present": true
  },
  "claim_scope": "measured environment only flowtable throughput evidence"
}`;

const matchingFlowtableStatus = `policy dataplane:
  flowtable host:  ready
  flowtable live:  active
  kernel tuning:  ready
  state table:    ready 25/1048576 entries (0.002%)
`;

const matchingNft = `table inet openngfw {
  flowtable fastpath {
    hook ingress priority filter
    devices = { ens4, ens5 }
  }
  chain forward {
    ct state established,related flow add @fastpath counter packets 2 bytes 200 comment "flow-offload"
  }
}`;

{
  const text = statusEvidenceText({
    dataplane: {
      flowtable: { hostState: "ready", runtimeState: "active", devices: ["ens4", "ens5"], packets: 2, bytes: 200 },
      kernelTuning: { state: "ready" },
      conntrack: { state: "ready", currentEntries: 25, maxEntries: 1048576, usagePercent: 0.002 },
    },
    inspection: { state: "disabled", idsEnabled: false },
  });
  const result = validateSummaryText(flowtableSummary, {
    iperfText: matchingIperf,
    statusText: text,
    nftText: matchingNft,
  });

  assert.deepEqual(result.errors, []);
  assert.equal(result.artifacts.status.flowtableRuntime, "active");
}

{
  const result = validateSummaryText(flowtableSummary, {
    iperfText: matchingIperf,
    statusText: matchingFlowtableStatus,
    nftText: matchingNft,
  });
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.warnings, []);
  assert.equal(result.artifacts.status.flowtableRuntime, "active");
  assert.equal(result.artifacts.nft.offloadRulePresent, true);
  assert.ok(benchmarkRepairSteps(result).every((step) => step.level !== "high"));
}

{
  const result = validateSummaryText(flowtableSummary, {
    iperfText: matchingIperf,
    statusText: `policy dataplane:
  flowtable host:  degraded
  flowtable live:  inactive
  kernel tuning:  degraded
  state table:    warning 99/1048576 entries (4.2%)
`,
    nftText: `table inet openngfw {
  chain forward {
    ct state established,related accept
  }
}`,
  });
  for (const field of ["conntrack_evidence.state", "current_entries", "usage_percent", "host_tuning_evidence.state", "host_state", "runtime_state", "flowtable_declared", "offload_rule_present"]) {
    assert.match(result.errors.join("\n"), new RegExp(field.replace(".", "\\.")));
  }
  const steps = benchmarkRepairSteps(result);
  assert.ok(steps.some((step) => step.title === "Prove the flowtable fast path"));
  assert.ok(steps.some((step) => step.title === "Regenerate the summary from the raw artifacts"));
}

{
  const result = validateSummaryText(summary, { strict: true });
  const release = releaseGateSummary(result);

  assert.equal(release.cls, "bad");
  assert.ok(release.blockers.some((item) => item.label === "Strict" && /block release mode/.test(item.title)));
  assert.ok(release.blockers.some((item) => item.label === "Scope"));
  assert.equal(release.reviewItems.length, 0);
}

{
  const baseline = validateSummaryText(inspectedRun({ gbps: 1, latency: 0.4, attempts: 6000 }), {
    iperfText: iperfFor(1_000_000_000),
    statusText: matchingInspectionStatus,
  });
  const candidate = validateSummaryText(inspectedRun({ gbps: 1.12, latency: 0.35, attempts: 6600 }), {
    iperfText: iperfFor(1_120_000_000),
    statusText: matchingInspectionStatus,
  });
  assert.deepEqual(baseline.errors, []);
  assert.deepEqual(candidate.errors, []);
  const comparison = comparePerformanceRuns(baseline, candidate, { strict: true });

  assert.equal(comparison.cls, "ok");
  assert.equal(comparison.label, "claim delta ready");
  assert.ok(comparison.metrics.some((metric) => metric.key === "throughput" && metric.direction === "improvement" && metric.state === "ok"));
  assert.ok(comparison.metrics.some((metric) => metric.key === "latency" && metric.direction === "improvement" && metric.state === "ok"));
  assert.ok(comparison.metrics.some((metric) => metric.key === "connectionRate" && metric.direction === "improvement" && metric.state === "ok"));
  assert.equal(comparison.noClaim.state, "claimable-after-record");
}

{
  const baseline = validateSummaryText(inspectedRun({ gbps: 1, latency: 0.4, attempts: 6000 }), {
    iperfText: iperfFor(1_000_000_000),
    statusText: matchingInspectionStatus,
  });
  const candidate = validateSummaryText(inspectedRun({ gbps: 0.9, latency: 0.5, attempts: 5100 }), {
    iperfText: iperfFor(900_000_000),
    statusText: matchingInspectionStatus,
  });
  const comparison = comparePerformanceRuns(baseline, candidate, { strict: true });

  assert.equal(comparison.cls, "bad");
  assert.equal(comparison.label, "regression blocked");
  assert.ok(comparison.metrics.some((metric) => metric.key === "throughput" && metric.direction === "regression" && metric.state === "bad"));
  assert.ok(comparison.metrics.some((metric) => metric.key === "latency" && metric.direction === "regression" && metric.state === "bad"));
  assert.ok(comparison.metrics.some((metric) => metric.key === "connectionRate" && metric.direction === "regression" && metric.state === "bad"));
  assert.equal(comparison.noClaim.state, "blocked");
  assert.match(comparison.noClaim.title, /Do not publish/);
}

{
  const baseline = validateSummaryText(inspectedRun({ gbps: 1, latency: 0.4, attempts: 6000 }), {
    iperfText: iperfFor(1_000_000_000),
    statusText: matchingInspectionStatus,
  });
  const candidate = validateSummaryText(inspectedRun({
    gbps: 1.1,
    latency: 0.36,
    attempts: 6600,
    claimScope: "measured environment only; do not publish without full profile context token=secret /Users/alice/perf",
  }), {
    iperfText: iperfFor(1_100_000_000),
    statusText: matchingInspectionStatus,
  });
  const comparison = comparePerformanceRuns(baseline, candidate, { strict: true });
  const payload = performanceComparisonPayload(comparison);
  const json = performanceComparisonPayloadJson(comparison);
  const text = performanceComparisonPayloadText(comparison);

  assert.equal(comparison.cls, "warn");
  assert.equal(comparison.noClaim.state, "review");
  assert.ok(comparison.noClaim.reasons.some((reason) => /do not publish/.test(reason)));
  assert.equal(payload.schemaVersion, "phragma.performance.delta-payload.v1");
  assert.equal(payload.metrics.length, 3);
  assert.ok(payload.candidate.claimScope.length <= 240);
  assert.doesNotMatch(json, /token=secret/);
  assert.doesNotMatch(json, /\/Users\/alice/);
  assert.doesNotMatch(text, /token=secret/);
  assert.match(json, /\[redacted\]/);
  assert.match(json, /\[server-local path redacted\]/);
  assert.match(text, /no-claim posture:/);

  const workbench = performanceClaimGateWorkbenchModel(candidate, true, {
    checks: [
      {
        name: "release-benchmark",
        state: "not_applicable",
        detail: "This release publishes no performance claims.",
      },
    ],
  }, comparison);
  assert.match(workbench.comparisonPacket, /Performance run comparison/);
  assert.doesNotMatch(workbench.comparisonPacket, /token=secret/);
  assert.doesNotMatch(workbench.comparisonPacket, /\/Users\/alice/);
  assert.equal(workbench.releaseBenchmarkGate.state, "not_applicable");
  assert.equal(workbench.releaseBenchmarkGate.label, "no claims");
}

{
  const empty = performanceClaimGateWorkbenchModel(null, true, { unavailable: true, detail: "offline" });

  assert.equal(empty.loadedSummary.state, "missing");
  assert.equal(empty.releaseDecision.cls, "info");
  assert.equal(empty.releaseDecision.label, "not loaded");
  assert.equal(empty.releaseBenchmarkGate.state, "unavailable");
  assert.equal(empty.releaseBenchmarkGate.meta, "GET /v1/system/release-acceptance/status");
}
