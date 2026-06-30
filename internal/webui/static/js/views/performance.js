// Performance - local benchmark evidence review. The page validates
// summary.json artifacts in the browser and never sends benchmark data to
// controld.

import { h, icon, clear } from "../core.js";
import { api } from "../api.js";
import { openAutomationContext } from "../automation_context.js";
import { activeInvestigationServerCaseHref, appendInvestigationPacketToActiveServerCase, pinInvestigationPacket } from "../investigation_case.js";
import { buildInvestigationPacket, investigationPacketFilename, investigationPacketJson, investigationPacketText } from "../investigation_packet.js";
import { validateSummaryText, evidenceVerdict, benchmarkGate, benchmarkRepairSteps, releaseGateSummary, detectBenchmarkArtifacts, statusEvidenceText, artifactSizeProblem, benchmarkCollectionRunbook, benchmarkCollectionRunbookText, comparePerformanceRuns, performanceComparisonPayloadJson, performanceComparisonPayloadText, CANONICAL_INSPECTION_STATES } from "../performance.js";
import { pageHead, card, pill, emptyState, toast } from "../ui.js";

export async function render() {
  const root = h("div", { dataset: { perfRoute: "true" } });
  let raw = "";
  let iperfRaw = "";
  let iperfName = "";
  let statusRaw = "";
  let statusName = "";
  let nftRaw = "";
  let nftName = "";
  let runName = "";
  let result = null;
  let compareRaw = "";
  let compareRunName = "";
  let compareResult = null;
  let strict = false;

  const paint = () => {
    clear(root);
    root.appendChild(pageHead("Performance", "Benchmark evidence, inspection state, and claim scope.", [
      h("button", { class: "btn", type: "button", title: "Open Performance API and CLI context", "aria-label": "Open Performance API and CLI context", dataset: { perfAction: "api-cli" }, onclick: () => openAutomationContext("#/performance") },
        h("span", { html: icon("terminal", 16) }), "API / CLI"),
    ]));
    root.appendChild(collectionRunbookCard());
    root.appendChild(h("div", { class: "perf-layout" },
      inputCard(),
      resultCard(result, strict)));
    root.appendChild(comparisonCard());
  };

  const verify = () => {
    result = validateSummaryText(raw, { strict, iperfText: iperfRaw, statusText: statusRaw, nftText: nftRaw });
    paint();
  };

  const inputCard = () => {
    const text = h("textarea", { class: "input perf-json mono", spellcheck: "false", placeholder: "{\n  \"schema_version\": \"phragma.perf.v1\"\n}", dataset: { perfInput: "summary-json" } });
    text.value = raw;
    text.addEventListener("input", () => { raw = text.value; });
    const strictBox = h("input", { type: "checkbox", dataset: { perfToggle: "strict" } });
    strictBox.checked = strict;
    strictBox.addEventListener("change", () => {
      strict = strictBox.checked;
      if (raw.trim()) result = validateSummaryText(raw, { strict, iperfText: iperfRaw, statusText: statusRaw, nftText: nftRaw });
      if (compareRaw.trim() && raw.trim()) compareResult = comparePerformanceRuns(validateSummaryText(compareRaw, { strict }), validateSummaryText(raw, { strict, iperfText: iperfRaw, statusText: statusRaw, nftText: nftRaw }), { strict });
      paint();
    });
    const directory = h("input", { class: "input", type: "file", multiple: true, webkitdirectory: true, dataset: { perfFile: "run-directory" }, onchange: async (e) => {
      await loadRunDirectory(e.target.files || []);
    } });
    const file = h("input", { class: "input", type: "file", accept: "application/json,.json", dataset: { perfFile: "summary" }, onchange: async (e) => {
      const f = e.target.files?.[0];
      if (!f) return;
      const sizeProblem = artifactSizeProblem(f, "summary");
      if (sizeProblem) { toast("Summary not loaded", sizeProblem, "bad"); return; }
      raw = await f.text();
      result = validateSummaryText(raw, { strict, iperfText: iperfRaw, statusText: statusRaw, nftText: nftRaw });
      paint();
      toast("Summary loaded", f.name, "ok");
    } });
    const iperfFile = h("input", { class: "input", type: "file", accept: "application/json,.json", dataset: { perfFile: "iperf" }, onchange: async (e) => {
      const f = e.target.files?.[0];
      if (!f) return;
      const sizeProblem = artifactSizeProblem(f, "iperf");
      if (sizeProblem) { toast("Raw iperf not loaded", sizeProblem, "bad"); return; }
      iperfRaw = await f.text();
      iperfName = f.name;
      if (raw.trim()) result = validateSummaryText(raw, { strict, iperfText: iperfRaw, statusText: statusRaw, nftText: nftRaw });
      paint();
      toast("Raw iperf loaded", f.name, "ok");
    } });
    const statusFile = h("input", { class: "input", type: "file", accept: ".txt,text/plain", dataset: { perfFile: "status" }, onchange: async (e) => {
      const f = e.target.files?.[0];
      if (!f) return;
      const sizeProblem = artifactSizeProblem(f, "status");
      if (sizeProblem) { toast("Status evidence not loaded", sizeProblem, "bad"); return; }
      statusRaw = await f.text();
      statusName = f.name;
      if (raw.trim()) result = validateSummaryText(raw, { strict, iperfText: iperfRaw, statusText: statusRaw, nftText: nftRaw });
      paint();
      toast("Status evidence loaded", f.name, "ok");
    } });
    const nftFile = h("input", { class: "input", type: "file", accept: ".txt,text/plain", dataset: { perfFile: "packet-filter" }, onchange: async (e) => {
      const f = e.target.files?.[0];
      if (!f) return;
      const sizeProblem = artifactSizeProblem(f, "packet-filter");
      if (sizeProblem) { toast("packet filter evidence not loaded", sizeProblem, "bad"); return; }
      nftRaw = await f.text();
      nftName = f.name;
      if (raw.trim()) result = validateSummaryText(raw, { strict, iperfText: iperfRaw, statusText: statusRaw, nftText: nftRaw });
      paint();
      toast("packet filter evidence loaded", f.name, "ok");
    } });
    return card(h("h2", {}, "Benchmark summary"),
      h("div", { class: "perf-run-loader" },
        h("label", { class: "field" },
          h("span", {}, "result directory"),
          directory),
        h("div", { class: "note" },
          "Select a `perf/results/<run>` folder to auto-load summary, iperf3, status, and packet filter evidence.")),
      h("div", { class: "form-grid two" },
        h("label", { class: "field" }, h("span", {}, "summary.json"), file),
        h("label", { class: "field" }, h("span", {}, "iperf3.json"), iperfFile),
        h("label", { class: "field" }, h("span", {}, "status artifact"), statusFile),
        h("label", { class: "field" }, h("span", {}, "packet-filter artifact"), nftFile),
        h("label", { class: "field flex strict-row" }, strictBox, h("span", {}, "Strict verification"))),
      h("label", { class: "field" }, h("span", {}, "JSON"), text),
      h("div", { class: "artifact-strip" },
        runName ? artifactTag("run", `run: ${runName}`) : null,
        artifactTag("iperf", iperfName ? `raw iperf: ${iperfName}` : "raw iperf: not loaded"),
        artifactTag("status", statusName ? `status: ${statusName}` : "status: not loaded"),
        artifactTag("packet-filter", nftName ? `packet-filter: ${nftName}` : "packet-filter: not loaded")),
      h("div", { class: "flex wrap" },
        h("button", { class: "btn primary", type: "button", title: "Verify benchmark evidence", "aria-label": "Verify benchmark evidence", dataset: { perfAction: "verify" }, onclick: verify }, h("span", { html: icon("check", 16) }), "Verify"),
        h("button", { class: "btn", type: "button", title: "Load current runtime status evidence", "aria-label": "Load current runtime status evidence", dataset: { perfAction: "use-live-status" }, onclick: loadLiveStatus }, h("span", { html: icon("refresh", 16) }), "Use live status"),
        h("button", { class: "btn ghost", type: "button", title: "Clear loaded benchmark evidence", "aria-label": "Clear loaded benchmark evidence", dataset: { perfAction: "clear" }, onclick: () => {
          raw = ""; iperfRaw = ""; iperfName = ""; statusRaw = ""; statusName = ""; nftRaw = ""; nftName = ""; runName = ""; result = null; compareResult = null; paint();
        } }, "Clear")),
      h("div", { class: "note", style: { marginTop: "12px" } },
        "Canonical inspection states: ", CANONICAL_INSPECTION_STATES.map((s) => h("span", { class: "tag" }, s))));
  };

  const comparisonCard = () => {
    const baselineText = h("textarea", { class: "input perf-json mono", spellcheck: "false", placeholder: "{\n  \"schema_version\": \"phragma.perf.v1\"\n}", dataset: { perfCompareInput: "baseline-json" } });
    baselineText.value = compareRaw;
    baselineText.addEventListener("input", () => { compareRaw = baselineText.value; });
    const baselineFile = h("input", { class: "input", type: "file", accept: "application/json,.json", dataset: { perfCompareFile: "baseline" }, onchange: async (e) => {
      const f = e.target.files?.[0];
      if (!f) return;
      const sizeProblem = artifactSizeProblem(f, "summary");
      if (sizeProblem) { toast("Baseline not loaded", sizeProblem, "bad"); return; }
      compareRaw = await f.text();
      compareRunName = f.name;
      compareResult = null;
      paint();
      toast("Baseline loaded", f.name, "ok");
    } });
    const model = compareResult;
    return card(h("h2", {}, "Run comparison"),
      h("div", { class: "alert-box info", dataset: { perfComparisonIntro: "true" } },
        h("strong", {}, "Compare a baseline summary with the loaded candidate run."),
        h("div", { class: "note" }, "This computes throughput, latency, and connection-rate deltas in the browser. It does not certify a comparison claim or store raw benchmark artifacts.")),
      h("div", { class: "form-grid two" },
        h("label", { class: "field" }, h("span", {}, "baseline summary.json"), baselineFile),
        h("div", { class: "field" },
          h("span", {}, "candidate summary"),
          h("div", { class: "artifact-strip" },
            artifactTag("candidate", runName ? `loaded: ${runName}` : "candidate: current JSON"),
            artifactTag("baseline", compareRunName ? `baseline: ${compareRunName}` : "baseline: paste or load")))),
      h("label", { class: "field" }, h("span", {}, "Baseline JSON"), baselineText),
      h("div", { class: "flex wrap" },
        h("button", { class: "btn primary", type: "button", title: "Compare performance runs", "aria-label": "Compare performance runs", dataset: { perfAction: "compare-runs" }, onclick: compareRuns }, h("span", { html: icon("diff", 16) }), "Compare"),
        h("button", { class: "btn ghost", type: "button", title: "Clear performance comparison", "aria-label": "Clear performance comparison", dataset: { perfAction: "clear-comparison" }, onclick: () => {
          compareRaw = ""; compareRunName = ""; compareResult = null; paint();
        } }, "Clear comparison")),
      model ? comparisonResultPanel(model) : emptyState("traffic", "No comparison loaded", "Load or paste a baseline summary and compare it to the current candidate run."));
  };

  paint();
  return root;

  async function loadLiveStatus() {
    try {
      const status = await api.status();
      statusRaw = statusEvidenceText(status);
      statusName = "live /v1/system/status";
      if (raw.trim()) result = validateSummaryText(raw, { strict, iperfText: iperfRaw, statusText: statusRaw, nftText: nftRaw });
      paint();
      toast("Live status loaded", "Captured current runtime posture from /v1/system/status.", "ok");
    } catch (e) {
      toast("Live status unavailable", e.message, "bad");
    }
  }

  async function loadRunDirectory(files) {
    const detected = detectBenchmarkArtifacts(files);
    if (detected.duplicates.length) {
      toast("Benchmark run not loaded", `Duplicate artifact names: ${detected.duplicates.join("; ")}`, "bad");
      return;
    }
    if (detected.sizeProblems.length) {
      toast("Benchmark run not loaded", detected.sizeProblems.join("; "), "bad");
      return;
    }
    if (!detected.summary) {
      toast("Benchmark run not loaded", "No summary.json found in the selected directory.", "bad");
      return;
    }
    raw = await detected.summary.file.text();
    iperfRaw = detected.iperf ? await detected.iperf.file.text() : "";
    iperfName = detected.iperf?.name || "";
    statusRaw = detected.status ? await detected.status.file.text() : "";
    statusName = detected.status?.name || "";
    nftRaw = detected["packet-filter"] ? await detected["packet-filter"].file.text() : "";
    nftName = detected["packet-filter"]?.name || "";
    runName = detected.runName || "";
    result = validateSummaryText(raw, { strict, iperfText: iperfRaw, statusText: statusRaw, nftText: nftRaw });
    compareResult = null;
    paint();
    const loaded = detected.recognizedCount;
    const missing = detected.missing.length ? ` Missing: ${detected.missing.join(", ")}.` : "";
    toast("Benchmark run loaded", `${runName || "Selected run"}: ${loaded} artifact(s) detected.${missing}`, detected.missing.length ? "warn" : "ok");
  }

  function compareRuns() {
    if (!compareRaw.trim()) {
      toast("Comparison unavailable", "Load or paste a baseline summary.json first.", "warn");
      return;
    }
    if (!raw.trim()) {
      toast("Comparison unavailable", "Load or paste the candidate summary.json first.", "warn");
      return;
    }
    const baseline = validateSummaryText(compareRaw, { strict });
    const candidate = validateSummaryText(raw, { strict, iperfText: iperfRaw, statusText: statusRaw, nftText: nftRaw });
    result = candidate;
    compareResult = comparePerformanceRuns(baseline, candidate, { strict });
    paint();
    toast("Comparison ready", compareResult.title, compareResult.cls === "bad" ? "bad" : compareResult.cls === "warn" ? "warn" : "ok");
  }
}

function publishableClaimWorkbench(result, strict, releaseAcceptanceStatus, compareResult) {
  const model = performanceClaimGateWorkbenchModel(result, strict, releaseAcceptanceStatus, compareResult);
  return card(h("h2", {}, "Publishable claim gate workbench", h("span", { class: "spacer" }), pill(model.releaseDecision.label, model.releaseDecision.cls)),
    h("div", { class: "readiness-summary perf-claim-workbench " + model.releaseDecision.cls, dataset: { perfClaimWorkbench: model.releaseDecision.cls } },
      h("div", { class: "readiness-mark", html: icon(model.releaseDecision.cls === "bad" ? "block" : model.releaseDecision.cls === "warn" ? "threats" : "check", 30) }),
      h("div", {},
        h("div", { class: "readiness-title" }, model.releaseDecision.title),
        h("div", { class: "readiness-sub" }, model.releaseDecision.detail)),
      h("div", { class: "readiness-score" },
        h("strong", {}, model.strictVerifier.label),
        h("span", {}, "strict verifier"))),
    h("div", { class: "runtime-grid perf-metrics perf-claim-summary", dataset: { perfClaimSummary: model.loadedSummary.state } }, [
      metric("Loaded summary", model.loadedSummary.label),
      metric("Verifier result", model.strictVerifier.title),
      metric("Release benchmark", model.releaseBenchmarkGate.label),
      metric("No-claims path", model.noClaimsDecision.label),
    ]),
    h("div", { class: "alert-box " + model.releaseBenchmarkGate.cls, dataset: { perfReleaseBenchmarkStatus: model.releaseBenchmarkGate.state } },
      h("strong", {}, "Current release-benchmark gate status"),
      h("div", { class: "note" }, model.releaseBenchmarkGate.detail),
      model.releaseBenchmarkGate.meta ? h("code", { class: "mono" }, model.releaseBenchmarkGate.meta) : null),
    h("div", { class: "warning-list compact perf-claim-decision-list" }, model.claimRows.map((row) =>
      h("div", { class: "warning-row " + row.cls, dataset: { perfClaimDecision: row.key } },
        h("div", {}, pill(row.label, row.cls, true)),
        h("div", {},
          h("strong", {}, row.title),
          h("div", { class: "note" }, row.detail))))),
    h("div", { class: "grid cols-2" },
      h("div", { class: "field" },
        h("span", {}, "Redacted comparison packet"),
        model.comparisonPacket
          ? h("textarea", { class: "input perf-json mono", readonly: true, dataset: { perfComparisonPacketPreview: "true" } }, model.comparisonPacket)
          : h("div", { class: "alert-box info", dataset: { perfComparisonPacketPreview: "empty" } },
            h("strong", {}, "No comparison packet ready"),
            h("div", { class: "note" }, "Compare a baseline and candidate run to preview the redacted delta packet before copying or exporting it."))),
      h("div", { class: "perf-next-commands", dataset: { perfNextCommands: "true" } },
        h("strong", {}, "Next commands"),
        h("div", { class: "release-evidence-command-list" }, model.nextCommands.map((item) =>
          h("div", { class: "release-evidence-command-row", dataset: { perfNextCommand: slug(item.role) } },
            h("span", {}, item.role),
            h("code", { class: "mono" }, item.command),
            h("button", { class: "btn sm ghost", type: "button", title: `Copy ${item.role} command`, "aria-label": `Copy performance ${item.role} command`, dataset: { perfAction: "copy-next-command" }, onclick: () => copyCommand(item.command) },
              h("span", { html: icon("copy", 14) }), "Copy")))))));
}

function collectionRunbookCard() {
  const runbook = benchmarkCollectionRunbook();
  return card(h("h2", {}, "Benchmark collection runbook"),
    h("div", { class: "alert-box info", dataset: { perfRunbook: "true" } },
      h("strong", {}, "Collect raw evidence before reviewing claims."),
      h("div", { class: "note" }, runbook.custody)),
    h("div", { class: "grid cols-2 perf-runbook-workflows" }, runbook.workflows.map((workflow) =>
      h("div", { class: "workflow-panel", dataset: { perfRunbookWorkflow: workflow.id } },
        h("div", { class: "flex wrap perf-runbook-head" },
          h("strong", {}, workflow.label),
          pill(`${workflow.commands.length} commands`, "info", true)),
        h("div", { class: "note" }, workflow.detail),
        h("div", { class: "artifact-strip" }, workflow.artifacts.map((artifact) => h("span", { class: "tag" }, artifact))),
        h("div", { class: "warning-list compact" }, workflow.commands.map((command) =>
          h("div", { class: "warning-row info", dataset: { perfRunbookCommand: slug(`${workflow.id}-${command.label}`) } },
            h("div", {}, pill("command", "info", true)),
            h("div", {},
              h("strong", {}, command.label),
              h("pre", { class: "mono perf-command" }, command.command),
              h("button", { class: "btn sm ghost", type: "button", title: `Copy ${command.label} command`, "aria-label": `Copy ${workflow.label} ${command.label} command`, dataset: { perfAction: "copy-runbook-command" }, onclick: () => copyCommand(command.command) },
                h("span", { html: icon("copy", 15) }), "Copy")))))))),
    h("div", { class: "warning-list compact" }, runbook.releaseCommands.map((command) =>
      h("div", { class: "warning-row info", dataset: { perfRunbookRelease: slug(command.label) } },
        h("div", {}, pill("release", "info", true)),
        h("div", {},
          h("strong", {}, command.label),
          h("pre", { class: "mono perf-command" }, command.command),
          h("button", { class: "btn sm ghost", type: "button", title: `Copy ${command.label} release command`, "aria-label": `Copy ${command.label} release command`, dataset: { perfAction: "copy-runbook-release" }, onclick: () => copyCommand(command.command) },
            h("span", { html: icon("copy", 15) }), "Copy"))))),
    h("div", { class: "flex wrap" },
      h("button", { class: "btn", type: "button", title: "Copy benchmark collection runbook", "aria-label": "Copy benchmark collection runbook", dataset: { perfAction: "copy-runbook" }, onclick: () => copyCommand(benchmarkCollectionRunbookText(runbook)) },
        h("span", { html: icon("copy", 15) }), "Copy runbook")),
    h("ul", { class: "compact-list" }, runbook.guardrails.map((item) => h("li", {}, item))));
}

function resultCard(result, strict) {
  if (!result) {
    return datasetCard({ perfVerdict: "empty" },
      h("h2", {}, "Evidence verdict"),
      emptyState("traffic", "No summary loaded", "Benchmark summaries appear here after verification."));
  }
  const verdict = evidenceVerdict(result);
  const gate = benchmarkGate(result);
  const summary = result.summary || {};
  const rows = [
    metric("Profile", summary.profile || "-"),
    metric("Security services", summary.security_services || "-"),
    metric("Inspection", summary.inspection_state || "-"),
    metric("Inspection readiness", inspectionEvidenceLabel(summary.inspection_evidence)),
    metric("Throughput", formatGbps(summary.tcp_gbps)),
    metric("Raw iperf", rawIperfLabel(result.artifacts?.iperf)),
    metric("Raw status", rawStatusLabel(result.artifacts?.status)),
    metric("Raw packet-filter", rawNftLabel(result.artifacts?.["packet-filter"])),
    metric("Retransmits", valueOrDash(summary.tcp_retransmits)),
    metric("Latency", summary.ping_avg_ms == null ? "-" : `${summary.ping_avg_ms} ms`),
    metric("Host tuning", hostTuningLabel(summary.host_tuning_evidence)),
    metric("State table", conntrackLabel(summary.conntrack_evidence)),
    metric("Flowtable", flowtableLabel(summary.flowtable_evidence)),
    metric("Parallel", valueOrDash(summary.parallel_streams)),
    metric("Duration", summary.duration_seconds ? `${summary.duration_seconds}s` : "-"),
  ];
  return datasetCard({ perfVerdict: verdict.cls },
    h("h2", {}, "Evidence verdict", h("span", { class: "spacer" }), pill(verdict.label, verdict.cls)),
    h("div", { class: "readiness-summary perf-verdict " + verdict.cls },
      h("div", { class: "readiness-mark", html: icon(verdict.cls === "bad" ? "block" : "check", 34) }),
      h("div", {},
        h("div", { class: "readiness-title" }, verdict.title),
        h("div", { class: "readiness-sub" }, strict ? "Strict mode treats warnings as failures." : "Warnings do not block non-strict verification.")),
      h("div", { class: "readiness-score" },
        h("strong", {}, String(result.errors.length + result.warnings.length)),
        h("span", {}, "findings"))),
    h("div", { class: "runtime-grid perf-metrics" }, rows),
    h("dl", { class: "kv readiness-kv perf-kv" },
      h("dt", {}, "Generated"), h("dd", { class: "mono" }, summary.generated_at || "-"),
      h("dt", {}, "Target"), h("dd", { class: "mono" }, target(summary.target)),
      h("dt", {}, "Claim scope"), h("dd", {}, summary.claim_scope || "-")),
    performanceHandoffPanel(result, strict),
    gatePanel(gate),
    repairPanel(result),
    findings(result));
}

function comparisonResultPanel(model) {
  return h("div", { class: "perf-comparison", dataset: { perfComparisonState: model.cls } },
    h("div", { class: "readiness-summary perf-comparison-summary " + model.cls },
      h("div", { class: "readiness-mark", html: icon(model.cls === "bad" ? "block" : model.cls === "warn" ? "threats" : "check", 28) }),
      h("div", {},
        h("div", { class: "readiness-title" }, model.title),
        h("div", { class: "readiness-sub" }, model.detail)),
      h("div", { class: "readiness-score" },
        h("strong", {}, model.label),
        h("span", {}, "delta review"))),
    h("div", { class: "runtime-grid perf-metrics" }, [
      metric("Baseline throughput", formatGbps(model.baseline.throughputGbps)),
      metric("Candidate throughput", formatGbps(model.candidate.throughputGbps)),
      metric("Baseline latency", model.baseline.latencyMs == null ? "-" : `${Number(model.baseline.latencyMs).toFixed(3)} ms`),
      metric("Candidate latency", model.candidate.latencyMs == null ? "-" : `${Number(model.candidate.latencyMs).toFixed(3)} ms`),
      metric("Baseline connection rate", formatCps(model.baseline.connectionRate)),
      metric("Candidate connection rate", formatCps(model.candidate.connectionRate)),
    ]),
    h("div", { class: "warning-list compact perf-comparison-list" }, model.metrics.map((item) =>
      h("div", { class: "warning-row " + comparisonClass(item.state), dataset: { perfComparisonMetric: item.key } },
        h("div", {}, pill(item.direction, comparisonClass(item.state), true)),
        h("div", {},
          h("strong", {}, item.title),
          h("div", { class: "note" }, `${item.label}: ${formatSigned(item.absoluteDelta, item.unit)} / ${formatSignedPercent(item.percentDelta)}`))))),
    h("div", { class: "alert-box " + comparisonClass(model.noClaim.state === "claimable-after-record" ? "ok" : model.noClaim.state === "blocked" ? "bad" : "warn"), dataset: { perfComparisonNoClaim: model.noClaim.state } },
      h("strong", {}, model.noClaim.title),
      h("div", { class: "note" }, model.noClaim.detail),
      h("code", {}, model.noClaim.command),
      model.noClaim.reasons?.length ? h("ul", { class: "compact-list" }, model.noClaim.reasons.map((reason) => h("li", {}, reason))) : null),
    h("div", { class: "warning-actions" },
      h("button", { class: "btn sm ghost", type: "button", title: "Copy performance comparison delta payload", "aria-label": "Copy performance comparison delta payload", dataset: { perfAction: "copy-comparison" }, onclick: () => copyPerformanceComparison(model) },
        h("span", { html: icon("copy", 14) }), "Copy delta"),
      h("button", { class: "btn sm ghost", type: "button", title: "Export performance comparison delta JSON", "aria-label": "Export performance comparison delta JSON", dataset: { perfAction: "export-comparison" }, onclick: () => exportPerformanceComparison(model) },
        h("span", { html: icon("download", 14) }), "Export delta JSON")));
}

function performanceHandoffPanel(result, strict = false) {
  const packet = performanceEvidenceHandoffPacket(result, strict);
  return h("div", { class: "perf-handoff alert-box info", dataset: { perfHandoff: "true" } },
    h("strong", {}, "Investigation handoff"),
    h("div", { class: "note" }, "Pin or export this browser-local benchmark verdict with its loaded raw-artifact posture. It does not record release evidence or certify a performance claim."),
    h("div", { class: "warning-actions" },
      h("button", { class: "btn sm", type: "button", title: "Pin performance evidence handoff to investigation case", "aria-label": "Pin performance evidence handoff to investigation case", dataset: { perfAction: "pin-handoff" }, onclick: () => pinPerformanceHandoff(packet) },
        h("span", { html: icon("inbox", 14) }), "Pin to case"),
      h("a", { class: "btn sm ghost", href: activeInvestigationServerCaseHref(), title: "Open active investigation case", "aria-label": "Open active investigation case", dataset: { perfAction: "open-active-case" } },
        h("span", { html: icon("search", 14) }), "Open active case"),
      h("button", { class: "btn sm ghost", type: "button", title: "Copy performance evidence handoff", "aria-label": "Copy performance evidence handoff", dataset: { perfAction: "copy-handoff" }, onclick: () => copyPerformanceHandoff(packet) },
        h("span", { html: icon("copy", 14) }), "Copy handoff"),
      h("button", { class: "btn sm ghost", type: "button", title: "Export performance evidence handoff JSON", "aria-label": "Export performance evidence handoff JSON", dataset: { perfAction: "export-handoff" }, onclick: () => exportPerformanceHandoff(packet) },
        h("span", { html: icon("download", 14) }), "Export JSON")));
}

export function performanceEvidenceHandoffPacket(result = {}, strict = false, route = "#/performance") {
  const summary = result.summary || {};
  const errors = Array.isArray(result.errors) ? result.errors : [];
  const warnings = Array.isArray(result.warnings) ? result.warnings : [];
  const verdict = evidenceVerdict(result);
  const release = releaseGateSummary(result);
  const gate = benchmarkGate(result);
  const decision = performanceReleaseDecisionModel(result, strict);
  const artifacts = result.artifacts || {};
  return buildInvestigationPacket({
    kind: "performance-evidence",
    title: "Performance evidence handoff",
    subject: {
      id: summary.generated_at || summary.profile || "browser-local-benchmark",
      label: summary.profile || "Benchmark evidence",
    },
    summary: {
      verdict: verdict.label,
      verdictState: verdict.cls,
      strictMode: Boolean(strict),
      releaseGate: release.label,
      releaseGateState: release.cls,
      claimUseGate: gate.label,
      claimUseState: gate.cls,
      profile: summary.profile || "",
      securityServices: summary.security_services || "",
      inspectionState: summary.inspection_state || "",
      throughputGbps: typeof summary.tcp_gbps === "number" ? summary.tcp_gbps : "",
      latencyMs: summary.ping_avg_ms ?? "",
      retransmits: summary.tcp_retransmits ?? "",
      durationSeconds: summary.duration_seconds ?? "",
      parallelStreams: summary.parallel_streams ?? "",
      claimScope: summary.claim_scope || "",
      rawIperf: rawIperfLabel(artifacts.iperf),
      rawStatus: rawStatusLabel(artifacts.status),
      rawNft: rawNftLabel(artifacts["packet-filter"]),
      operatorDecision: decision.title,
      releaseDecisionState: decision.cls,
      releaseEvidenceHref: decision.releaseEvidenceHref,
      noPerformanceClaimsCommand: decision.noPerformanceClaimsCommand,
      supportBundleHref: decision.supportBundleHref,
    },
    evidence: [
      `verdict: ${verdict.title}`,
      `release gate: ${release.title}`,
      `claim use: ${gate.title}`,
      `operator decision: ${decision.title}`,
      `release evidence path: ${decision.releaseEvidenceHref}`,
      `no-performance-claims path: ${decision.noPerformanceClaimsCommand}`,
      `support bundle path: ${decision.supportBundleHref}`,
      summary.claim_scope ? `claim scope: ${summary.claim_scope}` : "",
      `raw iperf: ${rawIperfLabel(artifacts.iperf)}`,
      `raw status: ${rawStatusLabel(artifacts.status)}`,
      `raw packet-filter: ${rawNftLabel(artifacts["packet-filter"])}`,
      ...errors.map((message) => `error: ${message}`),
      ...warnings.map((message) => `warning: ${message}`),
    ],
    artifacts: {
      benchmarkSummary: summary,
      validation: {
        errors,
        warnings,
        strictMode: Boolean(strict),
      },
      loadedArtifacts: {
        iperf: artifacts.iperf || {},
        status: artifacts.status || {},
        packetFilter: artifacts["packet-filter"] || {},
      },
      releaseGate: release,
      claimUseGate: gate,
      operatorDecision: decision,
    },
  }, { route });
}

export function performanceReleaseDecisionModel(result = {}, strict = false) {
  const release = releaseGateSummary(result);
  const gate = benchmarkGate(result);
  const summary = result.summary || {};
  const artifacts = result.artifacts || {};
  const errors = Array.isArray(result.errors) ? result.errors : [];
  const warnings = Array.isArray(result.warnings) ? result.warnings : [];
  const publishable = release.cls === "ok" && gate.cls === "ok" && errors.length === 0 && warnings.length === 0;
  const blocked = release.cls === "bad" || gate.cls === "bad" || errors.length > 0 || (strict && warnings.length > 0);
  const cls = publishable ? "ok" : blocked ? "bad" : "warn";
  const inspectionState = String(summary.inspection_state || "unknown");
  const claimScope = String(summary.claim_scope || "").trim();
  const rawPosture = [
    `iperf ${rawIperfLabel(artifacts.iperf)}`,
    `status ${rawStatusLabel(artifacts.status)}`,
    `packet-filter ${rawNftLabel(artifacts["packet-filter"])}`,
  ].join("; ");
  const decisions = [
    {
      key: "external-publication",
      cls: publishable ? "ok" : "bad",
      label: publishable ? "allowed after record" : "not allowed",
      title: publishable ? "Scoped performance claim can move to release evidence" : "Do not publish a throughput or comparison claim from this artifact",
      detail: publishable
        ? "Record the selected run through the release-benchmark evidence target before citing the measured value outside local review."
        : "Use this only for repair or internal review until the release gate and claim-use gate are clean, or remove performance claims from the tag.",
    },
    {
      key: "no-performance-claims",
      cls: publishable ? "info" : "warn",
      label: "release option",
      title: "No-performance-claims mode is explicit",
      detail: "Use only when release notes and the manifest publish no throughput, latency, connection-rate, or comparison claims.",
    },
    {
      key: "support-readiness",
      cls: "info",
      label: "handoff",
      title: "Support bundle and  carry posture, not raw benchmark custody",
      detail: "Preview the support bundle or  release-benchmark packet for operator context; keep raw benchmark artifacts with the measured run.",
    },
    {
      key: "unsupported-scope",
      cls: inspectionState === "fully-inspected" ? "info" : "warn",
      label: "scope",
      title: "Claim only the loaded inspection state",
      detail: claimScope
        ? `Loaded scope: ${claimScope}. Inspection state: ${inspectionState}.`
        : `Inspection state: ${inspectionState}; add a claim_scope before using the benchmark for decisions.`,
    },
  ];
  return {
    cls,
    label: publishable ? "record evidence" : blocked ? "blocked" : "review",
    title: publishable ? "Ready to record scoped release evidence" : blocked ? "Keep release and external claims blocked" : "Operator review required before any claim",
    detail: publishable
      ? "This browser verdict can inform the release-benchmark evidence path, but the release tooling must record durable evidence before publication."
      : blocked
        ? "This benchmark cannot support release notes, comparison claims, or customer-facing throughput statements in its current state."
        : "The artifact may help triage performance, but warnings must be reviewed before any external or release use.",
    releaseEvidenceHref: "",
    releaseAcceptanceHref: "",
    supportBundleHref: "",
    verifyCommand: "make benchmark-verify-release",
    recordCommand: "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-release-benchmark",
    noPerformanceClaimsCommand: "RELEASE_NO_PERFORMANCE_CLAIMS=1 make benchmark-verify-release",
    noPerformanceClaimsStatusCommand: "RELEASE_NO_PERFORMANCE_CLAIMS=1 make release-acceptance-status",
    noPerformanceClaimsManifestCommand: "RELEASE_NO_PERFORMANCE_CLAIMS=1 make release-acceptance-assemble release-acceptance-verify",
    rawArtifactPosture: rawPosture,
    decisions,
  };
}

export function performanceClaimGateWorkbenchModel(result = null, strict = false, releaseAcceptanceStatus = null, compareResult = null) {
  const hasResult = Boolean(result?.summary);
  const summary = result?.summary || {};
  const verdict = result ? evidenceVerdict(result) : { cls: "info", label: "not loaded", title: "No benchmark summary loaded" };
  const release = result ? releaseGateSummary(result) : { cls: "info", label: "not loaded", title: "No local release verifier result", detail: "Load a summary and run strict verification before deciding whether any claim is safe." };
  const decision = performanceReleaseDecisionModel(result || {}, strict);
  const releaseBenchmarkGate = releaseBenchmarkStatusGate(releaseAcceptanceStatus);
  const comparisonPacket = compareResult ? performanceComparisonPayloadText(compareResult) : "";
  const loadedLabel = summary.profile
    ? `${summary.profile} / ${summary.inspection_state || "unknown"} / ${formatGbps(summary.tcp_gbps)}`
    : "not loaded";
  const claimSafe = decision.cls === "ok" && release.cls === "ok";
  const releaseClear = ["passed", "not_applicable"].includes(releaseBenchmarkGate.state);
  return {
    loadedSummary: {
      state: summary.profile ? "loaded" : "missing",
      label: loadedLabel,
      generatedAt: summary.generated_at || "",
      claimScope: summary.claim_scope || "",
    },
    strictVerifier: {
      cls: verdict.cls,
      label: strict ? verdict.label : "strict off",
      title: strict ? verdict.title : "Strict verifier not enabled",
      detail: strict ? release.detail : "Enable Strict release gate to treat warnings as release blockers.",
    },
    releaseBenchmarkGate,
    releaseDecision: {
      cls: !hasResult ? "info" : claimSafe ? "ok" : decision.cls === "bad" ? "bad" : "warn",
      label: !hasResult ? "not loaded" : claimSafe ? "claim-safe after record" : decision.cls === "bad" ? "claim blocked" : "claim review",
      title: !hasResult ? "Load benchmark evidence before deciding claim safety" : claimSafe ? "Loaded benchmark is claim-safe after release evidence is recorded" : decision.title,
      detail: !hasResult
        ? "Select a benchmark run or paste summary.json, then enable strict release verification before using any performance number outside local review."
        : claimSafe
        ? "The browser verifier is clean. Publish only after release-benchmark evidence is recorded and accepted for this source snapshot."
        : decision.detail,
    },
    noClaimsDecision: {
      cls: claimSafe ? "info" : "warn",
      label: claimSafe ? "optional" : "recommended if release ships",
      title: "No-performance-claims release path",
      detail: "Use only when release notes and manifest publish no throughput, latency, connection-rate, benchmark, or comparison claims.",
    },
    claimRows: [
      {
        key: "local-strict-verifier",
        cls: release.cls,
        label: release.cls === "ok" ? "safe" : "not safe",
        title: release.title,
        detail: release.detail || "Strict local verifier result from the loaded benchmark summary and raw artifacts.",
      },
      {
        key: "release-benchmark-status",
        cls: releaseBenchmarkGate.cls,
        label: releaseClear ? "release clear" : "not release clear",
        title: releaseBenchmarkGate.title,
        detail: releaseBenchmarkGate.detail,
      },
      {
        key: "external-performance-claim",
        cls: !hasResult ? "info" : claimSafe ? "ok" : "bad",
        label: !hasResult ? "not evaluated" : claimSafe ? "safe after record" : "not safe",
        title: !hasResult ? "External claim is not evaluated" : claimSafe ? "External claim can be prepared after recording durable evidence" : "External claim is blocked",
        detail: !hasResult
          ? "No loaded benchmark summary is available for claim evaluation."
          : claimSafe
          ? "Keep the claim scoped to the loaded benchmark summary and record it through release-benchmark before publication."
          : "Do not cite throughput, latency, connection-rate, benchmark, or comparison values outside local review from this state.",
      },
      {
        key: "no-performance-claims",
        cls: claimSafe ? "info" : "warn",
        label: "release option",
        title: "Release/no-claims decision remains explicit",
        detail: "If release-benchmark evidence is missing or intentionally omitted, assemble and verify the release with no-performance-claims mode and keep release notes claim-free.",
      },
    ],
    comparisonPacket,
    nextCommands: [
      { role: "verify", command: decision.verifyCommand },
      { role: "record", command: decision.recordCommand },
      { role: "no claims verify", command: decision.noPerformanceClaimsCommand },
      { role: "no claims status", command: decision.noPerformanceClaimsStatusCommand },
      { role: "no claims manifest", command: decision.noPerformanceClaimsManifestCommand },
    ],
  };
}

function releaseBenchmarkStatusGate(status = null) {
  if (!status || status.unavailable) {
    return {
      cls: "warn",
      state: "unavailable",
      label: "status unavailable",
      title: "Release-benchmark gate status unavailable",
      detail: status?.detail || "The release acceptance status endpoint did not return a current release-benchmark gate.",
      meta: "GET /v1/system/release-acceptance/status",
    };
  }
  const check = Array.isArray(status.checks)
    ? status.checks.find((item) => String(item?.name || item?.check || "") === "release-benchmark")
    : null;
  if (!check) {
    return {
      cls: "bad",
      state: "missing",
      label: "missing evidence",
      title: "Release-benchmark check is missing",
      detail: "Release acceptance did not report a release-benchmark check; publishable claims remain blocked.",
      meta: "make benchmark-verify-release or RELEASE_NO_PERFORMANCE_CLAIMS=1 make release-acceptance-status",
    };
  }
  const state = normalizeReleaseState(check.state || check.status);
  const detail = disclosureValue(check.next_action || check.nextAction || check.detail || "");
  const evidencePath = disclosureValue(check.evidence_path || check.evidencePath || check.artifact || "");
  const benchmarkSummary = disclosureValue(check.benchmark_summary || check.benchmarkSummary || "");
  if (state === "passed") {
    return {
      cls: "ok",
      state,
      label: "passed",
      title: "Release-benchmark evidence is accepted",
      detail: detail || "Publishable benchmark release evidence is accepted by the verified release manifest.",
      meta: benchmarkSummary || evidencePath || "release-benchmark evidence passed",
    };
  }
  if (state === "not_applicable") {
    return {
      cls: "ok",
      state,
      label: "no claims",
      title: "Release-benchmark is not applicable",
      detail: detail || "The manifest declares no performance claims; release notes must omit throughput, latency, connection-rate, benchmark, and comparison claims.",
      meta: "release-benchmark not_applicable",
    };
  }
  if (state === "recorded") {
    return {
      cls: "warn",
      state,
      label: "pending manifest",
      title: "Release-benchmark evidence is recorded but not accepted",
      detail: detail || "Assemble and verify release acceptance before treating recorded benchmark evidence as publishable.",
      meta: benchmarkSummary || evidencePath || "release-benchmark evidence recorded",
    };
  }
  return {
    cls: state === "invalid" || state === "missing" || state === "todo" ? "bad" : "warn",
    state: state || "review",
    label: state === "invalid" ? "invalid" : state === "missing" || state === "todo" ? "missing evidence" : state || "review",
    title: state === "invalid" ? "Release-benchmark evidence is invalid" : "Release-benchmark evidence is not accepted",
    detail: detail || "Release acceptance requires a publishable benchmark artifact, or an explicit no-performance-claims manifest before publishing performance claims.",
    meta: benchmarkSummary || evidencePath || "make benchmark-verify-release or assemble with RELEASE_NO_PERFORMANCE_CLAIMS=1",
  };
}

function normalizeReleaseState(state) {
  return String(state || "missing").trim().toLowerCase().replace(/-/g, "_");
}

function disclosureValue(value) {
  return String(value || "")
    .replace(/\/Users\/[^\s"'\\]+/g, "/Users/[redacted]")
    .replace(/\/home\/[^/\s"'\\]+/g, "/home/[redacted]")
    .replace(/\b(token|access_token|api_key|password|secret|client_secret|key)=([^\s"'&]+)/gi, (_, key) => `${key}=[redacted]`);
}

async function pinPerformanceHandoff(packet) {
  try {
    const serverResult = await appendInvestigationPacketToActiveServerCase(packet, {
      appendEvidence: (id, evidence) => api.addInvestigationCaseEvidence(id, evidence),
    });
    if (serverResult.appended) {
      toast("Evidence appended", `Performance evidence appended to ${serverResult.activeCaseId}.`, "ok");
      return;
    }
  } catch (e) {
    try {
      const result = pinInvestigationPacket(packet);
      toast("Server append unavailable", `${result.toastDetail} Local browser-only fallback was used.`, "warn");
    } catch (fallbackError) {
      toast("Pin failed", fallbackError.message || "Performance evidence could not be pinned.", "bad");
    }
    return;
  }
  try {
    const result = pinInvestigationPacket(packet);
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Performance evidence could not be pinned.", "bad");
  }
}

async function copyPerformanceHandoff(packet) {
  try {
    await navigator.clipboard.writeText(investigationPacketText(packet));
    toast("Handoff copied", "Performance evidence copied as plain text.", "ok");
  } catch {
    toast("Copy failed", "Select and copy the performance evidence manually.", "warn");
  }
}

function exportPerformanceHandoff(packet) {
  const blob = new Blob([investigationPacketJson(packet)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: investigationPacketFilename(packet) });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  toast("Handoff exported", "Downloaded browser-local performance evidence handoff JSON.", "ok");
}

async function copyPerformanceComparison(model) {
  try {
    await navigator.clipboard.writeText(performanceComparisonPayloadText(model));
    toast("Delta copied", "Performance comparison delta copied as redacted text.", "ok");
  } catch {
    toast("Copy failed", "Select and copy the performance comparison manually.", "warn");
  }
}

function exportPerformanceComparison(model) {
  const blob = new Blob([performanceComparisonPayloadJson(model)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: "performance-comparison-delta.json" });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  toast("Delta exported", "Downloaded redacted performance comparison delta JSON.", "ok");
}

function releasePanel(release) {
  const items = [
    ...release.blockers.map((item) => ({ ...item, section: "blocker" })),
    ...release.reviewItems.map((item) => ({ ...item, section: "review" })),
  ];
  return h("div", { class: "perf-release", dataset: { perfReleaseState: release.cls } },
    h("div", { class: "readiness-summary perf-release-summary " + release.cls },
      h("div", { class: "readiness-mark", html: icon(release.cls === "bad" ? "block" : release.cls === "warn" ? "threats" : "check", 28) }),
      h("div", {},
        h("div", { class: "readiness-title" }, release.title),
        h("div", { class: "readiness-sub" }, release.detail)),
      h("div", { class: "readiness-score" },
        h("strong", {}, release.label),
        h("span", {}, "release gate"))),
    items.length
      ? h("div", { class: "warning-list perf-release-list" }, items.map((item) =>
        h("div", { class: "warning-row " + item.cls, dataset: { perfGate: slug(item.label || item.title) } },
          h("div", {}, pill(item.section, item.cls, true)),
          h("div", {},
            h("strong", {}, `${item.label}: ${item.title}`),
            item.detail ? h("div", { class: "note" }, item.detail) : null))))
      : h("div", { class: "alert-box ok" }, h("strong", {}, "No release blockers or review items.")));
}

function readinessParityPanel(release) {
  const state = release?.cls || "info";
  const localReady = state === "ok";
  return h("div", {
    class: "alert-box " + state,
    dataset: { perfParity: state },
  },
    h("strong", {}, localReady ? "Matches  release-benchmark input" : " release-benchmark still needs evidence"),
    h("div", { class: "note" },
      localReady
        ? "This browser-local verdict is the same publishable artifact shape that  expects for release-benchmark, but it does not record backend release evidence."
        : " keeps release-benchmark blocked until a publishable benchmark artifact is verified or the release manifest explicitly declares no performance claims."),
    h("div", { class: "warning-actions" },
      h("code", {}, "make benchmark-verify-release")));
}

function releaseDecisionPanel(result, strict) {
  const model = performanceReleaseDecisionModel(result, strict);
  return h("div", { class: "perf-decision alert-box " + model.cls, dataset: { perfDecisionState: model.cls } },
    h("strong", {}, model.title),
    h("div", { class: "note" }, model.detail),
    h("dl", { class: "kv readiness-kv perf-kv" },
      h("dt", {}, "Raw artifacts"), h("dd", {}, model.rawArtifactPosture),
      h("dt", {}, "Verify gate"), h("dd", { class: "mono" }, model.verifyCommand),
      h("dt", {}, "Record evidence"), h("dd", { class: "mono" }, model.recordCommand),
      h("dt", {}, "No claims"), h("dd", { class: "mono" }, model.noPerformanceClaimsCommand)),
    h("div", { class: "warning-list compact perf-decision-list" }, model.decisions.map((item) =>
      h("div", { class: "warning-row " + item.cls, dataset: { perfDecision: item.key } },
        h("div", {}, pill(item.label, item.cls, true)),
        h("div", {},
          h("strong", {}, item.title),
          h("div", { class: "note" }, item.detail))))),
    null);
}

function gatePanel(gate) {
  return h("div", { class: "perf-gates", dataset: { perfGateState: gate.cls } },
    h("div", { class: "readiness-summary perf-gate-summary " + gate.cls },
      h("div", { class: "readiness-mark", html: icon(gate.cls === "bad" ? "block" : gate.cls === "warn" ? "threats" : "check", 28) }),
      h("div", {},
        h("div", { class: "readiness-title" }, gate.title),
        h("div", { class: "readiness-sub" }, gate.detail)),
      h("div", { class: "readiness-score" },
        h("strong", {}, gate.label),
        h("span", {}, "use gate"))),
    h("div", { class: "warning-list perf-gate-list" }, gate.gates.map((item) =>
      h("div", { class: "warning-row " + item.cls, dataset: { perfGate: slug(item.label || item.title) } },
        h("div", {}, pill(item.label, item.cls, true)),
        h("div", {}, h("strong", {}, item.title), item.detail ? h("div", { class: "note" }, item.detail) : null)))));
}

function repairPanel(result) {
  const steps = benchmarkRepairSteps(result);
  return h("div", { class: "perf-actions" },
    h("h3", {}, "Next actions"),
    h("div", { class: "warning-list" }, steps.map((step) =>
      h("div", { class: "warning-row " + actionClass(step.level), dataset: { perfRepairStep: slug(step.title) } },
        h("div", {}, pill(step.badge || step.level || "action", actionClass(step.level), true)),
        h("div", {},
          h("strong", {}, step.title),
          step.detail ? h("div", { class: "note" }, step.detail) : null,
          step.command ? h("div", { class: "warning-actions" },
            h("code", {}, step.command),
            h("button", { class: "btn sm ghost", type: "button", title: `Copy repair command: ${step.title}`, "aria-label": `Copy repair command: ${step.title}`, dataset: { perfAction: "copy-command" }, onclick: () => copyCommand(step.command) }, h("span", { html: icon("copy", 15) }), "Copy")) : null)))));
}

function actionClass(level) {
  if (level === "high") return "bad";
  if (level === "medium") return "warn";
  return "info";
}

async function copyCommand(command) {
  try {
    await navigator.clipboard.writeText(command);
    toast("Command copied", command, "ok");
  } catch {
    toast("Copy failed", "Select and copy the command manually.", "warn");
  }
}

function findings(result) {
  const items = [
    ...result.errors.map((message) => ({ cls: "bad", label: "error", message })),
    ...result.warnings.map((message) => ({ cls: "warn", label: "warning", message })),
  ];
  if (!items.length) {
    return h("div", { class: "alert-box ok" }, h("strong", {}, "No findings."));
  }
  return h("div", { class: "warning-list perf-findings" }, items.map((item) =>
    h("div", { class: "warning-row " + item.cls, dataset: { perfFinding: item.label } },
      h("div", {}, pill(item.label, item.cls, true)),
      h("div", {}, h("strong", {}, item.message)))));
}

function metric(label, value) {
  return h("div", { class: "posture-metric", dataset: { perfMetric: slug(label) } },
    h("span", {}, label),
    h("strong", {}, value));
}

function artifactTag(kind, label) {
  return h("span", { class: "tag", dataset: { perfArtifact: kind } }, label);
}

function datasetCard(dataset, ...children) {
  const node = card(...children);
  Object.assign(node.dataset, dataset || {});
  return node;
}

function slug(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "item";
}

function formatGbps(v) {
  return typeof v === "number" && Number.isFinite(v) ? `${v.toFixed(3)} Gbps` : "-";
}

function valueOrDash(v) {
  return v == null ? "-" : String(v);
}

function formatCps(value) {
  return typeof value === "number" && Number.isFinite(value) ? `${value.toFixed(1)} cps` : "-";
}

function formatSigned(value, unit) {
  if (typeof value !== "number" || !Number.isFinite(value)) return "n/a";
  const sign = value > 0 ? "+" : "";
  return `${sign}${value.toFixed(3)} ${unit}`;
}

function formatSignedPercent(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return "n/a";
  const sign = value > 0 ? "+" : "";
  return `${sign}${value.toFixed(1)}%`;
}

function comparisonClass(state) {
  if (state === "bad" || state === "blocked") return "bad";
  if (state === "warn" || state === "review") return "warn";
  if (state === "ok" || state === "claimable-after-record") return "ok";
  return "info";
}

function flowtableLabel(e) {
  if (!e) return "-";
  const runtime = e.runtime_state || "unknown";
  const packetFilter = e.flowtable_declared && e.offload_rule_present ? "packet filter proven" : "packet filter incomplete";
  return `${runtime} / ${packetFilter}`;
}

function conntrackLabel(e) {
  if (!e) return "-";
  const state = e.state || "unknown";
  if (e.max_entries > 0) {
    return `${state} · ${Number(e.usage_percent || 0).toFixed(1)}%`;
  }
  return state;
}

function hostTuningLabel(e) {
  if (!e) return "-";
  const parts = [e.state || "unknown"];
  if (e.profile) parts.push(e.profile);
  return parts.join(" · ");
}

function inspectionEvidenceLabel(e) {
  if (!e) return "-";
  const parts = [e.state || "unknown"];
  if (e.inspection_state) parts.push(e.inspection_state);
  if (e.engine_state) parts.push(e.engine_state);
  return parts.join(" · ");
}

function rawIperfLabel(e) {
  if (!e || e.state === "missing") return "not loaded";
  if (e.state !== "loaded") return e.label || e.state;
  return `${formatGbps(e.gbps)} · ${e.parallelStreams || "-"} streams`;
}

function rawStatusLabel(e) {
  if (!e || e.state === "missing") return "not loaded";
  if (e.state !== "loaded") return e.label || e.state;
  const inspection = e.inspection ? e.inspection.state : "no inspection";
  const tuning = e.hostTuning ? e.hostTuning.state : "no tuning";
  const ct = e.conntrack ? e.conntrack.state : "no state table";
  const ft = e.flowtableRuntime || "no flowtable";
  return `${inspection} / ${tuning} / ${ct} / ${ft}`;
}

function rawNftLabel(e) {
  if (!e || e.state === "missing") return "not loaded";
  if (e.state === "not-required") return "not required";
  if (e.state !== "loaded") return e.label || e.state;
  return e.flowtableDeclared && e.offloadRulePresent ? "flowtable proven" : "no flowtable proof";
}

function target(t) {
  if (!t) return "-";
  return `${t.ip || "?"}:${t.port || "?"}`;
}
