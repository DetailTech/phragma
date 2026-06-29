import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { buildContentPosture, contentCanaryTelemetryWorkbench, contentPackageDecisionPath, contentPackageInstallGuidance, contentPackagePreviewComparison, contentPromotionDecision, contentQualityWorkbench, contentReadinessActionPlan, contentReadinessEvidenceRefs, effectiveFeedEnabled, normalizeCustomFeed, REQUIRED_CONTENT_QUALITY_EVIDENCE } from "./content_posture.js";
import { contentRegressionCorpusAPIModel, contentRegressionCorpusModel, normalizeIntelRoute, productionEvidenceInventoryModel } from "./views/intel.js";

const feeds = [
  { name: "feodo-tracker", enabled: true, custom: false, allowsCommercialUse: true },
  { name: "spamhaus-drop", enabled: false, custom: false, allowsCommercialUse: false },
  { name: "corp-feed", enabled: true, custom: true, allowsCommercialUse: true },
];

const intelViewSource = readFileSync(new URL("./views/intel.js", import.meta.url), "utf8");

{
  assert.match(intelViewSource, /function openPackageQualityDrawer/);
  assert.match(intelViewSource, /function openCanaryTelemetryDrawer/);
  assert.match(intelViewSource, /function contentCanaryTelemetryPanel/);
  assert.match(intelViewSource, /function canaryTelemetryBody/);
  assert.match(intelViewSource, /function canaryScopeRows/);
  assert.match(intelViewSource, /function falsePositiveTelemetryRows/);
  assert.match(intelViewSource, /function packageQualityBody/);
  assert.match(intelViewSource, /function contentQualityEvidenceInventory/);
  assert.match(intelViewSource, /function productionEvidenceInventoryPanel/);
  assert.match(intelViewSource, /function productionEvidenceInventoryRow/);
  assert.match(intelViewSource, /function contentActionPlanPanel/);
  assert.match(intelViewSource, /function contentPromotionDecisionPanel/);
  assert.match(intelViewSource, /function contentPromotionMiniStrip/);
  assert.match(intelViewSource, /function contentEvidenceSummaryPanel/);
  assert.match(intelViewSource, /function openContentEvidenceDrawer/);
  assert.match(intelViewSource, /function openContentCorpusDrawer/);
  assert.match(intelViewSource, /function contentCorpusBrowserBody/);
  assert.match(intelViewSource, /function packagePreviewComparisonBody/);
  assert.match(intelViewSource, /function previewContentPackageSurface/);
  assert.match(intelViewSource, /contentPackagePreviewComparison/);
  assert.match(intelViewSource, /api\.contentEvidence/);
  assert.match(intelViewSource, /api\.contentCorpus/);
  assert.match(intelViewSource, /api\.compareContentPackage/);
  assert.match(intelViewSource, /api\.previewContentPackage/);
  assert.match(intelViewSource, /inspect-evidence/);
  assert.match(intelViewSource, /browse-corpus/);
  assert.match(intelViewSource, /Persisted regression corpus/);
  assert.match(intelViewSource, /Regression corpus diff/);
  assert.match(intelViewSource, /intelPackagePreview/);
  assert.match(intelViewSource, /intelPackageComparison/);
  assert.match(intelViewSource, /intelCorpusDiff/);
  assert.match(intelViewSource, /Quality gates/);
  assert.match(intelViewSource, /Canary rollout and false-positive telemetry/);
  assert.match(intelViewSource, /contentCanaryTelemetryWorkbench/);
  assert.match(intelViewSource, /contentPromotionDecision/);
  assert.match(intelViewSource, /Promotion and rollback decision handoff/);
  assert.match(intelViewSource, /intelPromotionDecisionPanel/);
  assert.match(intelViewSource, /intelPromotionCommand/);
  assert.match(intelViewSource, /handoff only/);
  assert.match(intelViewSource, /lifecycleAction: "canary"/);
  assert.match(intelViewSource, /lifecycleAction: "install", previewComparison: comparison/);
  assert.match(intelViewSource, /Evidence inventory/);
  assert.match(intelViewSource, /Production evidence inventory/);
  assert.match(intelViewSource, /intelProductionEvidenceInventory/);
  assert.match(intelViewSource, /intelProductionEvidenceSurface/);
  assert.match(intelViewSource, /intelProductionEvidenceCommand/);
  assert.match(intelViewSource, /Operator action plan/);
  assert.match(intelViewSource, /intelContentActionPlan/);
  assert.match(intelViewSource, /intelContentCommand/);
  assert.match(intelViewSource, /Evidence artifact summary/);
  assert.match(intelViewSource, /lifecycleAction: "quality"/);
  assert.match(intelViewSource, /type: "button", title: `Open \$\{surface\.name\} package quality gates`, "aria-label": `Open \$\{surface\.name\} package quality gates`/);
  assert.match(intelViewSource, /dataset: \{ intelContentAction: "canary", intelContentSurface: surface\.kind \}/);
  assert.match(intelViewSource, /dataset: \{ intelContentAction: "open-canary-workbench", intelContentSurface: surface\.kind \}/);
  assert.match(intelViewSource, /dataset: \{ intelContentAction: "close-canary", intelContentSurface: surface\.kind \}/);
  assert.match(intelViewSource, /dataset: \{ intelContentDrawer: "canary", intelContentSurface: surface\.kind \}/);
  assert.match(intelViewSource, /dataset: \{ intelContentAction: "review", intelContentSurface: surface\.kind \}/);
  assert.match(intelViewSource, /dataset: \{ intelContentAction: "install", intelContentSurface: surface\.kind \}/);
  assert.match(intelViewSource, /dataset: \{ intelContentAction: "preview-install", intelContentSurface: surface\.kind \}/);
  assert.match(intelViewSource, /dataset: \{ intelContentAction: "confirm-install", intelContentSurface: surface\.kind \}/);
  assert.match(intelViewSource, /dataset: \{ intelContentAction: "confirm-rollback", intelContentSurface: surface\.kind \}/);
  assert.match(intelViewSource, /dataset: \{ intelContentAction: "api-cli" \}/);
  assert.match(intelViewSource, /dataset: \{ intelContentAction: "pin-handoff" \}/);
  assert.match(intelViewSource, /dataset: \{ intelContentAction: "copy-handoff" \}/);
  assert.match(intelViewSource, /dataset: \{ intelContentAction: "export-handoff" \}/);
  assert.match(intelViewSource, /dataset: \{ intelContentAction: "open-active-case" \}/);
  assert.match(intelViewSource, /appendInvestigationPacketToActiveServerCase/);
  assert.match(intelViewSource, /api\.addInvestigationCaseEvidence\(id, evidence\)/);
  assert.match(intelViewSource, /title: "Refresh threat-intelligence feeds now", "aria-label": "Refresh threat-intelligence feeds now", dataset: \{ intelAction: "refresh-feeds" \}/);
  assert.match(intelViewSource, /title: "Stage threat-intelligence feed refresh interval", "aria-label": "Stage threat-intelligence feed refresh interval", dataset: \{ intelAction: "stage-refresh-interval" \}/);
  assert.match(intelViewSource, /title: "Declare commercial use for threat-intelligence feed governance", "aria-label": "Declare commercial use for threat-intelligence feed governance"/);
  assert.match(intelViewSource, /title: blocked \? `Feed \$\{f\.name\} cannot be enabled for commercial use` : `Enable or disable feed \$\{f\.name\}`/);
  assert.match(intelViewSource, /title: "Add custom threat-intelligence feed", "aria-label": "Add custom threat-intelligence feed", dataset: \{ intelAction: "add-custom-feed" \}/);
  assert.match(intelViewSource, /dataset: \{ intelAction: "edit-custom-feed", intelCustomFeedAction: f\.name \|\| String\(index\) \}/);
  assert.match(intelViewSource, /dataset: \{ intelAction: "delete-custom-feed", intelCustomFeedAction: f\.name \|\| String\(index\) \}/);
  assert.match(intelViewSource, /dataset: \{ intelAction: "cancel-custom-feed" \}/);
  assert.match(intelViewSource, /dataset: \{ intelAction: "save-custom-feed" \}/);
  assert.match(intelViewSource, /dataset: \{ intelContentAction: "inspect-evidence", intelContentSurface: surface\.kind, evidenceType:/);
  assert.match(intelViewSource, /dataset: \{ intelContentAction: "browse-corpus", intelContentSurface: surface\.kind, evidenceType:/);
  assert.match(intelViewSource, /dataset: \{ intelContentAction: "close-evidence", intelContentSurface: surface\.kind \}/);
  assert.match(intelViewSource, /dataset: \{ intelContentAction: "close-corpus", intelContentSurface: surface\.kind \}/);
}

{
  const model = contentRegressionCorpusModel(JSON.stringify({
    evidence_type: "app-regression-corpus",
    package_version: "2.4.1",
    status: "passed",
    samples: [
      {
        id: "corp-admin-login",
        pcap_sha256: "a".repeat(64),
        expected_app: "corp-admin",
        observed_app: "corp-admin",
        verdict: "passed",
      },
      {
        sample_id: "corp-ssh",
        pcapSha256: "b".repeat(64),
        expectedApp: "ssh",
        observedApp: "unknown",
        status: "failed",
      },
      {
        sid: 9000012,
        expected_verdict: "false-positive suppressed",
        observed_verdict: "false-positive suppressed",
        verdict: "passed",
      },
    ],
  }));
  assert.equal(model.type, "app-regression-corpus");
  assert.equal(model.packageVersion, "2.4.1");
  assert.equal(model.sampleCount, 3);
  assert.equal(model.failedSamples, 1);
  assert.deepEqual(model.verdicts, ["failed", "passed"]);
  assert.equal(model.rows[0].id, "corp-admin-login");
  assert.equal(model.rows[0].expected, "corp-admin");
  assert.equal(model.rows[1].observed, "unknown");
  assert.equal(model.rows[2].expected, "SID 9000012");
  assert.match(model.summary, /3 samples loaded/);
}

{
  const model = contentRegressionCorpusModel("{not-json", "pcap-regression-corpus");
  assert.equal(model.type, "pcap-regression-corpus");
  assert.equal(model.sampleCount, 0);
  assert.equal(model.failedSamples, 0);
  assert.match(model.summary, /No sample rows/);
}

{
  const model = contentRegressionCorpusAPIModel({
    evidenceType: "app-regression-corpus",
    packageVersion: "2.4.2",
    status: "passed",
    sampleCount: 2,
    failedSamples: 1,
    verdicts: ["failed", "passed"],
    summary: "2 samples loaded; 1 failing sample reported.",
    samples: [
      {
        id: "corp-admin-login",
        pcapSha256: "a".repeat(64),
        expected: "corp-admin",
        observed: "corp-admin",
        verdict: "passed",
      },
      {
        id: "corp-ssh",
        signatureId: "9000012",
        expected: "ssh",
        observed: "unknown",
        verdict: "failed",
        detail: "classification drift",
      },
    ],
  });
  assert.equal(model.type, "app-regression-corpus");
  assert.equal(model.packageVersion, "2.4.2");
  assert.equal(model.sampleCount, 2);
  assert.equal(model.failedSamples, 1);
  assert.deepEqual(model.verdicts, ["failed", "passed"]);
  assert.equal(model.rows[1].signatureId, "9000012");
  assert.match(model.summary, /2 samples loaded/);
}

{
  assert.equal(effectiveFeedEnabled(feeds[1], { feeds: [{ name: "spamhaus-drop", enabled: true }] }), true);
  assert.equal(effectiveFeedEnabled(feeds[0], { feeds: [{ name: "feodo-tracker", enabled: false }] }), false);
}

{
  const posture = buildContentPosture(feeds, {
    applications: [{ name: "corp-admin" }],
    ids: { exceptions: [{ signatureId: 9000001 }] },
    intel: {
      customFeeds: [{ name: "corp-feed", url: "https://example.com/feed.txt" }],
      feeds: [{ name: "spamhaus-drop", enabled: true }],
      commercialUse: true,
    },
  });

  assert.equal(posture.metrics.appPackage, "local policy");
  assert.equal(posture.metrics.threatPackage, "engine-normalized");
  assert.equal(posture.metrics.feedRegistry, "3/3 enabled");
  assert.equal(posture.metrics.signedPackages, "missing");
  assert.equal(posture.summary.cls, "warn");
  assert.deepEqual(posture.nonCommercialEnabled, ["spamhaus-drop"]);
  assert.ok(posture.blockers.includes("signed manifest"));
  assert.ok(posture.blockers.includes("regression result"));
  assert.ok(posture.blockers.includes("package rollback"));
  assert.ok(posture.blockers.includes("production evidence"));
  assert.ok(posture.blockers.includes("commercial license conflict"));
  assert.equal(posture.rolloutReview.cls, "warn");
  assert.match(posture.rolloutReview.nextAction, /Install signed local content packages/);
  assert.equal(posture.surfaces.length, 3);
  assert.equal(posture.surfaces[0].name, "App-ID catalog");
  assert.match(posture.surfaces[0].detail, /1 custom application/);
  assert.equal(posture.surfaces[2].badge, "blocked");
}

{
  const packages = [
    {
      kind: "app-id",
      name: "Phragma App-ID catalog",
      state: "verified",
      version: "1.2.3",
      source: "local package",
      manifestSha256: "0123456789abcdef",
      manifestPath: "/var/lib/openngfw/content/app-id/manifest.json",
      signatureStatus: "verified",
      regressionStatus: "passed",
      rolloutState: "stable",
      rollbackAvailable: true,
      contentReadiness: {
        scope: "production",
        productionContent: true,
        productionReady: true,
        evidenceStatus: "passed",
        readinessLabel: "production-ready",
        readinessDetail: "Production content evidence is present and passing.",
        evidence: [
          { type: "app-taxonomy", artifact: "evidence/app-taxonomy.json", sha256: "a".repeat(64) },
          { type: "license-review", artifact: "evidence/license-review.json", sha256: "b".repeat(64) },
        ],
        requiredProductionEvidence: ["app-taxonomy", "license-review"],
        blockers: [],
      },
      provenance: [
        { name: "Phragma curated app taxonomy", url: "https://content.example/app-id", license: "Apache-2.0" },
        { name: "Operator overrides", license: "internal" },
      ],
      blockers: [],
    },
    {
      kind: "threat-id",
      name: "Phragma Threat-ID catalog",
      state: "local-only",
      signatureStatus: "missing",
      regressionStatus: "missing",
      rollbackAvailable: false,
      blockers: ["signed manifest", "package rollback"],
    },
    {
      kind: "intel-feeds",
      name: "Threat-intel feed package",
      state: "incomplete",
      signatureStatus: "verified",
      regressionStatus: "missing",
      rollbackAvailable: true,
      blockers: ["regression result"],
    },
  ];
  const posture = buildContentPosture(feeds, { intel: {} }, packages);
  const inventory = productionEvidenceInventoryModel(packages);

  assert.equal(posture.metrics.appPackage, "1.2.3");
  assert.equal(posture.metrics.threatPackage, "local-only");
  assert.equal(posture.metrics.signedPackages, "2/3 verified");
  assert.equal(posture.productionContentReadiness.productionReady, false);
  assert.ok(posture.productionContentReadiness.blockers.some((blocker) => blocker.startsWith("threat-id:")));
  assert.ok(posture.blockers.includes("signed manifest"));
  assert.ok(posture.blockers.includes("package rollback"));
  assert.ok(posture.blockers.includes("regression result"));
  assert.ok(posture.blockers.includes("production evidence"));
  assert.equal(posture.rolloutReview.cls, "bad");
  assert.equal(inventory.status, "missing");
  assert.equal(inventory.rows[0].status, "production-ready");
  assert.equal(inventory.rows[1].status, "missing");
  assert.equal(inventory.rows[2].status, "missing");
  assert.match(posture.rolloutReview.detail, /package gate/);
  assert.equal(posture.surfaces[0].badge, "verified");
  assert.equal(posture.surfaces[0].cls, "ok");
  assert.equal(posture.surfaces[0].version, "1.2.3");
  assert.equal(posture.surfaces[0].source, "local package");
  assert.equal(posture.surfaces[0].manifestSha256, "0123456789abcdef");
  assert.equal(posture.surfaces[0].signatureStatus, "verified");
  assert.equal(posture.surfaces[0].regressionStatus, "passed");
  assert.equal(posture.surfaces[0].rolloutState, "stable");
  assert.deepEqual(posture.surfaces[0].blockers, []);
  assert.equal(posture.surfaces[0].decision.cls, "ok");
  assert.equal(posture.surfaces[0].decision.checks.find((check) => check.key === "signature").cls, "ok");
  assert.equal(posture.surfaces[0].decision.checks.find((check) => check.key === "production-evidence").status, "production-ready");
  assert.equal(posture.surfaces[0].decision.checks.find((check) => check.key === "production-evidence").cls, "ok");
  assert.ok(posture.surfaces[0].evidence.includes("signature:verified"));
  assert.ok(posture.surfaces[0].evidence.includes("rollback-backup:yes"));
  assert.ok(posture.surfaces[0].evidence.includes("content-readiness:production-ready"));
  assert.ok(posture.surfaces[0].fields.some((field) => field.label === "Provenance" && field.value.includes("Apache-2.0")));
  assert.ok(posture.surfaces[0].fields.some((field) => field.label === "Rollback" && field.value === "verified backup" && field.cls === "ok"));
  assert.ok(posture.surfaces[0].fields.some((field) => field.label === "Production evidence" && field.value === "production-ready (2 artifacts)" && field.cls === "ok"));
  assert.equal(posture.surfaces[0].provenance.length, 2);
  assert.equal(posture.surfaces[1].fields.find((field) => field.label === "Signature").cls, "warn");
  assert.equal(posture.surfaces[1].fields.find((field) => field.label === "Rollback").value, "missing");
  assert.equal(posture.surfaces[0].evidence.some((item) => item.includes("/var/lib/openngfw")), false);
}

{
  const inventory = productionEvidenceInventoryModel([
    {
      kind: "app-id",
      version: "1.0.0",
      signatureStatus: "verified",
      blockers: [],
      contentReadiness: {
        scope: "demo-only",
        productionContent: false,
        productionReady: false,
        evidenceStatus: "demo-only",
        readinessLabel: "demo-only",
        requiredProductionEvidence: ["app-taxonomy"],
        evidence: [{ type: "app-taxonomy", artifact: "evidence/app-taxonomy.json", sha256: "a".repeat(64) }],
        blockers: ["production content scope"],
      },
    },
    {
      kind: "threat-id",
      version: "2.0.0",
      signatureStatus: "verified",
      blockers: [],
      contentReadiness: {
        scope: "production",
        productionContent: true,
        productionReady: false,
        evidenceStatus: "incomplete",
        readinessLabel: "production-blocked",
        requiredProductionEvidence: ["threat-taxonomy", "pcap-regression-corpus"],
        evidence: [{ type: "threat-taxonomy", artifact: "evidence/threat-taxonomy.json", sha256: "b".repeat(64) }],
        blockers: ["production evidence:pcap-regression-corpus"],
      },
    },
  ]);
  assert.equal(inventory.status, "production-blocked");
  assert.equal(inventory.rows.find((row) => row.kind === "app-id").status, "demo");
  assert.equal(inventory.rows.find((row) => row.kind === "threat-id").status, "production-blocked");
  assert.equal(inventory.rows.find((row) => row.kind === "intel-feeds").status, "missing");
  assert.ok(inventory.commands.includes("ngfwctl intel content"));
  assert.ok(inventory.commands.some((command) => command.includes("preview app-id")));
  assert.match(inventory.detail, /blocker/);
}

{
  assert.deepEqual(normalizeIntelRoute({ surface: "app-id", drawer: "review" }), {
    surface: "app-id",
    drawer: "review",
  });
  assert.deepEqual(normalizeIntelRoute({ surface: "app-id", drawer: "quality" }), {
    surface: "app-id",
    drawer: "quality",
  });
  assert.deepEqual(normalizeIntelRoute({ surface: "app-id", drawer: "canary" }), {
    surface: "app-id",
    drawer: "canary",
  });
  assert.deepEqual(normalizeIntelRoute({ surface: "threat-id", drawer: "install" }), {
    surface: "threat-id",
    drawer: "install",
  });
  assert.deepEqual(normalizeIntelRoute({ surface: "intel-feeds", drawer: "rollback" }), {
    surface: "intel-feeds",
    drawer: "rollback",
  });
  assert.deepEqual(normalizeIntelRoute({ surface: "bad", drawer: "install" }), {
    surface: "",
    drawer: "",
  });
  assert.deepEqual(normalizeIntelRoute({ surface: "app-id", drawer: "bad" }), {
    surface: "app-id",
    drawer: "",
  });
  assert.deepEqual(normalizeIntelRoute({ drawer: "review" }), {
    surface: "",
    drawer: "",
  });
}

{
  const workbench = contentCanaryTelemetryWorkbench({
    kind: "threat-id",
    name: "Phragma Threat-ID catalog",
    state: "verified",
    version: "3.2.1",
    source: "local package",
    manifestSha256: "0123456789abcdef",
    signatureStatus: "verified",
    regressionStatus: "passed",
    rolloutState: "canary",
    rollbackAvailable: true,
    provenance: [{ name: "Phragma", license: "Apache-2.0" }],
    blockers: [],
    contentReadiness: {
      scope: "production",
      productionContent: true,
      productionReady: true,
      evidenceStatus: "passed",
      readinessLabel: "production-ready",
      rolloutScopes: [
        { name: "branch-east", mode: "alert", exposurePercent: 10, status: "healthy", detail: "WAN branch policy scope" },
        { policyScope: "dmz-observe", verdictMode: "observe", percent: 5, state: "declared" },
      ],
      falsePositiveTelemetry: {
        signals: [
          { label: "New FP reports", count: 0, status: "clean" },
        ],
      },
      evidence: [
        { type: "false-positive-regression", artifact: "evidence/fp-regression.json", sha256: "e".repeat(64) },
      ],
      blockers: [],
    },
  });
  assert.equal(workbench.cls, "ok");
  assert.equal(workbench.metrics.rolloutState, "canary");
  assert.equal(workbench.metrics.canaryScopes, "2");
  assert.equal(workbench.metrics.rollback, "verified backup");
  assert.equal(workbench.scopes[0].name, "branch-east");
  assert.equal(workbench.scopes[0].exposure, "10%");
  assert.ok(workbench.telemetry.signals.some((signal) => signal.label === "False-positive regression evidence" && signal.cls === "ok"));
  assert.match(workbench.boundary, /Browser-local review only/);
}

{
  const workbench = contentCanaryTelemetryWorkbench({
    kind: "app-id",
    name: "Phragma App-ID catalog",
    state: "verified",
    version: "2.9.0",
    source: "local package",
    manifestSha256: "0123456789abcdef",
    signatureStatus: "verified",
    regressionStatus: "passed",
    rolloutState: "stable",
    rollbackAvailable: false,
    provenance: [{ name: "Phragma", license: "Apache-2.0" }],
    blockers: [],
    falsePositiveTelemetry: {
      signals: [
        { label: "Classifier false positives", count: 3, status: "increased", detail: "reviewed queue samples regressed" },
      ],
    },
    contentReadiness: {
      scope: "production",
      productionContent: true,
      productionReady: true,
      evidenceStatus: "passed",
      blockers: [],
    },
  });
  assert.equal(workbench.cls, "bad");
  assert.ok(workbench.blockers.includes("canary scopes"));
  assert.ok(workbench.blockers.includes("rollback backup"));
  assert.equal(workbench.telemetry.signals[0].cls, "bad");
  assert.match(workbench.nextAction, /Hold promotion/);
}

{
  const surface = {
    kind: "app-id",
    name: "Phragma App-ID catalog",
    state: "verified",
    version: "2.4.1",
    source: "local package",
    manifestSha256: "a".repeat(64),
    signatureStatus: "verified",
    regressionStatus: "passed",
    rolloutState: "canary",
    rollbackAvailable: true,
    provenance: [{ name: "Phragma", license: "Apache-2.0" }],
    blockers: [],
    contentReadiness: {
      scope: "production",
      productionContent: true,
      productionReady: true,
      evidenceStatus: "passed",
      requiredProductionEvidence: ["app-taxonomy", "app-regression-corpus", "license-review", "staged-rollout", "rollback-drill"],
      evidence: [
        { type: "app-taxonomy", artifact: "evidence/app-taxonomy.json", sha256: "a".repeat(64) },
        { type: "app-regression-corpus", artifact: "evidence/app-regression.json", sha256: "b".repeat(64) },
        { type: "license-review", artifact: "evidence/license-review.json", sha256: "c".repeat(64) },
        { type: "staged-rollout", artifact: "evidence/staged-rollout.json", sha256: "d".repeat(64) },
        { type: "rollback-drill", artifact: "evidence/rollback-drill.json", sha256: "e".repeat(64) },
      ],
      canaryScopes: [{ name: "branch-east", mode: "observe", exposurePercent: 10, status: "healthy" }],
      falsePositiveTelemetry: { signals: [{ label: "FP queue", count: 0, status: "clean" }] },
      blockers: [],
    },
  };
  const decision = contentPromotionDecision(surface);
  assert.equal(decision.cls, "ok");
  assert.equal(decision.label, "promotion handoff ready");
  assert.equal(decision.blockers.length, 0);
  assert.ok(decision.commands.some((item) => item.command.includes("preview app-id")));
  assert.ok(decision.commands.some((item) => item.command.includes("install app-id")));
  assert.ok(decision.commands.some((item) => item.command.includes("rollback app-id --ack-rollback")));
  assert.match(decision.boundary, /Non-authoritative workflow handoff only/);
}

{
  const decision = contentPromotionDecision({
    kind: "threat-id",
    name: "Phragma Threat-ID catalog",
    state: "verified",
    version: "3.1.0",
    source: "local package",
    manifestSha256: "a".repeat(64),
    signatureStatus: "verified",
    regressionStatus: "failed",
    rolloutState: "canary",
    rollbackAvailable: true,
    provenance: [{ name: "Phragma", license: "Apache-2.0" }],
    blockers: ["regression result"],
    contentReadiness: {
      scope: "production",
      productionContent: true,
      productionReady: false,
      evidenceStatus: "incomplete",
      falsePositiveTelemetry: { signals: [{ label: "False-positive reports", count: 4, status: "increased" }] },
      blockers: ["production evidence"],
    },
  });
  assert.equal(decision.cls, "bad");
  assert.equal(decision.label, "hold promotion");
  assert.ok(decision.blockers.includes("regression failure"));
  assert.ok(decision.blockers.includes("canary or false-positive telemetry"));
  assert.match(decision.nextAction, /Hold promotion/);

  const rollbackDecision = contentPromotionDecision({
    kind: "threat-id",
    name: "Phragma Threat-ID catalog",
    state: "verified",
    version: "3.1.0",
    source: "local package",
    manifestSha256: "a".repeat(64),
    signatureStatus: "verified",
    regressionStatus: "failed",
    rolloutState: "canary",
    rollbackAvailable: true,
    provenance: [{ name: "Phragma", license: "Apache-2.0" }],
    blockers: ["regression result"],
  }, { lifecycleAction: "rollback" });
  assert.equal(rollbackDecision.cls, "warn");
  assert.equal(rollbackDecision.label, "rollback review advised");
  assert.match(rollbackDecision.nextAction, /Review canary false-positive pressure/);
}

{
  const decision = contentPromotionDecision({
    kind: "intel-feeds",
    name: "Threat-intel feed package",
    signatureStatus: "verified",
    regressionStatus: "passed",
    rollbackAvailable: false,
    blockers: [],
  }, { lifecycleAction: "rollback" });
  assert.equal(decision.cls, "bad");
  assert.equal(decision.label, "rollback blocked");
  assert.ok(decision.blockers.includes("rollback backup"));
  assert.match(decision.nextAction, /verified rollback metadata/);
}

{
  const posture = buildContentPosture(feeds, { intel: {} });
  assert.equal(posture.metrics.feedRegistry, "2/3 enabled");
  assert.deepEqual(posture.nonCommercialEnabled, []);
  assert.equal(posture.surfaces[2].badge, "governed");
  assert.equal(posture.rolloutReview.cls, "warn");
}

{
  const evidence = contentReadinessEvidenceRefs({
    evidence: [
      { type: "PCAP Regression Corpus", artifact: "evidence/pcaps/regression.json", sha256: "a".repeat(64), generated_at: "2026-06-17T21:00:00Z" },
      { type: "bad", artifact: "/var/lib/openngfw/secret.json", sha256: "not-a-hash" },
      { type: "url", artifact: "https://example.invalid/evidence.json", sha256: "b".repeat(64) },
      { type: "traversal", artifact: "../evidence/outside.json", sha256: "c".repeat(64) },
    ],
  });
  assert.deepEqual(evidence, [
    {
      type: "pcap-regression-corpus",
      artifact: "evidence/pcaps/regression.json",
      sha256: "a".repeat(64),
      sha256Short: "a".repeat(12),
      generatedAt: "2026-06-17T21:00:00.000Z",
    },
    {
      type: "bad",
      artifact: "",
      sha256: "",
      sha256Short: "",
      generatedAt: "",
    },
    {
      type: "url",
      artifact: "",
      sha256: "b".repeat(64),
      sha256Short: "b".repeat(12),
      generatedAt: "",
    },
    {
      type: "traversal",
      artifact: "",
      sha256: "c".repeat(64),
      sha256Short: "c".repeat(12),
      generatedAt: "",
    },
  ]);
}

{
  const workbench = contentQualityWorkbench({
    kind: "app-id",
    name: "Phragma App-ID catalog",
    state: "verified",
    version: "2.2.0",
    source: "local package",
    manifestSha256: "0123456789abcdef",
    signatureStatus: "verified",
    regressionStatus: "passed",
    rolloutState: "stable",
    rollbackAvailable: true,
    provenance: [{ name: "Phragma", license: "Apache-2.0" }],
    blockers: [],
    contentReadiness: {
      scope: "production",
      productionContent: true,
      productionReady: true,
      evidenceStatus: "passed",
      requiredProductionEvidence: ["app-taxonomy", "confidence-model", "app-regression-corpus"],
      evidence: [
        { type: "app-taxonomy", artifact: "evidence/app-taxonomy.json", sha256: "a".repeat(64) },
        { type: "confidence-model", artifact: "https://example.invalid/model.json", sha256: "b".repeat(64) },
        { type: "app-regression-corpus", artifact: "evidence/app-regression.json", sha256: "c".repeat(64) },
      ],
      blockers: [],
    },
  });
  assert.equal(workbench.cls, "bad");
  assert.equal(workbench.metrics.version, "2.2.0");
  assert.equal(workbench.metrics.requiredEvidence, "2/3");
  assert.ok(workbench.blockers.includes("confidence-model"));
  assert.ok(workbench.gates.some((gate) => gate.key === "package:regression" && gate.cls === "ok"));
  const taxonomyGate = workbench.gates.find((gate) => gate.key === "evidence:app-taxonomy");
  assert.equal(taxonomyGate.cls, "ok");
  assert.equal(taxonomyGate.evidenceRef.artifact, "evidence/app-taxonomy.json");
  assert.equal(taxonomyGate.evidenceRef.sha256, "a".repeat(64));
  assert.ok(workbench.gates.some((gate) => gate.key === "evidence:confidence-model" && gate.cls === "bad" && gate.status === "missing"));
}

{
  assert.ok(REQUIRED_CONTENT_QUALITY_EVIDENCE["threat-id"].includes("pcap-regression-corpus"));
  assert.ok(REQUIRED_CONTENT_QUALITY_EVIDENCE["intel-feeds"].includes("parser-tests"));
  const workbench = contentQualityWorkbench({
    kind: "threat-id",
    name: "Phragma Threat-ID catalog",
    state: "verified",
    version: "3.0.0",
    source: "local package",
    manifestSha256: "0123456789abcdef",
    signatureStatus: "verified",
    regressionStatus: "passed",
    rolloutState: "stable",
    rollbackAvailable: true,
    provenance: [{ name: "Phragma", license: "Apache-2.0" }],
    blockers: [],
    contentReadiness: {
      scope: "production",
      productionContent: true,
      productionReady: false,
      evidenceStatus: "incomplete",
      evidence: [],
      blockers: ["production evidence"],
    },
  });
  assert.equal(workbench.cls, "bad");
  assert.equal(workbench.requiredEvidence.length, REQUIRED_CONTENT_QUALITY_EVIDENCE["threat-id"].length);
  assert.ok(workbench.gates.some((gate) => gate.key === "evidence:pcap-regression-corpus" && gate.cls === "bad"));
}

{
  const plan = contentReadinessActionPlan({
    kind: "threat-id",
    name: "Phragma Threat-ID catalog",
    state: "verified",
    version: "3.0.0",
    source: "local package",
    manifestSha256: "0123456789abcdef",
    signatureStatus: "verified",
    regressionStatus: "passed",
    rolloutState: "stable",
    rollbackAvailable: true,
    provenance: [{ name: "Phragma", license: "Apache-2.0" }],
    blockers: [],
    contentReadiness: {
      scope: "production",
      productionContent: true,
      productionReady: false,
      evidenceStatus: "incomplete",
      requiredProductionEvidence: ["threat-taxonomy", "pcap-regression-corpus"],
      evidence: [
        { type: "threat-taxonomy", artifact: "evidence/threat-taxonomy.json", sha256: "a".repeat(64) },
      ],
      blockers: ["production evidence"],
    },
  });
  assert.equal(plan.cls, "bad");
  assert.ok(plan.missingEvidence.includes("pcap-regression-corpus"));
  assert.ok(plan.commands.some((item) => item.command === "ngfwctl intel content"));
  assert.ok(plan.commands.some((item) => item.command.includes("preview threat-id --source <data-dir>/content-import/threat-id")));
  assert.ok(plan.commands.some((item) => item.command.includes("install threat-id --source <data-dir>/content-import/threat-id")));
  assert.ok(plan.commands.some((item) => item.command.includes("rollback threat-id --ack-rollback")));
}

{
  const plan = contentReadinessActionPlan({
    kind: "app-id",
    name: "Phragma App-ID catalog",
    state: "verified",
    version: "2.4.1",
    source: "local package",
    manifestSha256: "0123456789abcdef",
    signatureStatus: "verified",
    regressionStatus: "passed",
    rolloutState: "stable",
    rollbackAvailable: true,
    provenance: [{ name: "Phragma", license: "Apache-2.0" }],
    blockers: [],
    contentReadiness: {
      scope: "production",
      productionContent: true,
      productionReady: true,
      evidenceStatus: "passed",
      requiredProductionEvidence: ["app-taxonomy", "app-regression-corpus"],
      evidence: [
        { type: "app-taxonomy", artifact: "evidence/app-taxonomy.json", sha256: "a".repeat(64) },
        { type: "app-regression-corpus", artifact: "evidence/app-regression.json", sha256: "b".repeat(64) },
      ],
      blockers: [],
    },
  });
  assert.equal(plan.cls, "ok");
  assert.equal(plan.missingEvidence.length, 0);
  assert.ok(plan.commands.some((item) => item.command.includes("corpus app-id --evidence-type app-regression-corpus")));
  assert.ok(plan.commands.some((item) => item.command.includes("rollback app-id --ack-rollback")));
  assert.equal(plan.commands.some((item) => item.command.includes("install app-id")), false);
}

{
  const readyPackage = (kind) => ({
    kind,
    name: `Phragma ${kind}`,
    state: "verified",
    version: "1.0.0",
    source: "local package",
    manifestSha256: "0123456789abcdef",
    signatureStatus: "verified",
    regressionStatus: "passed",
    rolloutState: "stable",
    rollbackAvailable: true,
    provenance: [{ name: "Phragma", license: "Apache-2.0" }],
    blockers: [],
    contentReadiness: {
      scope: "production",
      productionContent: true,
      productionReady: true,
      evidenceStatus: "passed",
      evidence: [{ type: `${kind}-evidence`, artifact: `evidence/${kind}.json`, sha256: "a".repeat(64) }],
      blockers: [],
    },
  });
  const posture = buildContentPosture(feeds, { intel: {} }, [
    readyPackage("app-id"),
    readyPackage("threat-id"),
    readyPackage("intel-feeds"),
  ]);
  assert.equal(posture.summary.cls, "ok");
  assert.equal(posture.productionContentReadiness.productionReady, true);
  assert.equal(posture.productionContentReadiness.state, "passed");
  assert.deepEqual(posture.productionContentReadiness.blockers, []);
}

{
  const posture = buildContentPosture(feeds, { intel: {} }, [{
    kind: "app-id",
    name: "Phragma App-ID catalog",
    state: "verified",
    version: "2.1.0",
    source: "local package",
    manifestSha256: "0123456789abcdef",
    signatureStatus: "verified",
    regressionStatus: "passed",
    rolloutState: "stable",
    rollbackAvailable: true,
    provenance: [{ name: "Phragma", license: "Apache-2.0" }],
    blockers: [],
    contentReadiness: {
      scope: "production",
      productionContent: true,
      productionReady: true,
      evidenceStatus: "passed",
      evidence: [
        { type: "app-regression-corpus", artifact: "evidence/app-regression.json", sha256: "f".repeat(64) },
      ],
      blockers: [],
    },
  }]);
  const surface = posture.surfaces.find((item) => item.kind === "app-id");
  assert.equal(surface.keyContentReadinessEvidence.appRegressionCorpus.artifact, "evidence/app-regression.json");
  assert.ok(surface.evidence.includes("app-regression-corpus:evidence/app-regression.json"));
  assert.ok(surface.fields.some((field) => field.label === "App-ID regression" && field.value.includes("sha256:")));
}

{
  const posture = buildContentPosture(feeds, { intel: {} }, [{
    kind: "threat-id",
    name: "Phragma Threat-ID catalog",
    state: "verified",
    version: "2.0.0",
    source: "local package",
    manifestSha256: "0123456789abcdef",
    signatureStatus: "verified",
    regressionStatus: "passed",
    rolloutState: "stable",
    rollbackAvailable: true,
    provenance: [{ name: "Phragma", license: "Apache-2.0" }],
    blockers: [],
    contentReadiness: {
      scope: "production",
      productionContent: true,
      productionReady: true,
      evidenceStatus: "passed",
      evidence: [
        { type: "pcap-regression-corpus", artifact: "evidence/pcap-regression.json", sha256: "d".repeat(64) },
        { type: "false-positive-regression", artifact: "evidence/fp-regression.json", sha256: "e".repeat(64) },
      ],
      blockers: [],
    },
  }]);
  const surface = posture.surfaces.find((item) => item.kind === "threat-id");
  assert.equal(surface.contentReadinessEvidence.length, 2);
  assert.equal(surface.keyContentReadinessEvidence.pcapRegressionCorpus.artifact, "evidence/pcap-regression.json");
  assert.equal(surface.keyContentReadinessEvidence.falsePositiveRegression.sha256Short, "e".repeat(12));
  assert.ok(surface.evidence.includes("pcap-regression-corpus:evidence/pcap-regression.json"));
  assert.ok(surface.fields.some((field) => field.label === "PCAP regression" && field.value.includes("sha256:")));
  assert.ok(surface.fields.some((field) => field.label === "False-positive regression" && field.value.includes("evidence/fp-regression.json")));
}

{
  const defensiveDecision = contentPackageDecisionPath({
    kind: "app-id",
    state: "verified",
    source: "local package",
    manifestSha256: "0123456789abcdef",
    signatureStatus: "verified",
    regressionStatus: "passed",
    rolloutState: "stable",
    rollbackAvailable: true,
    provenance: [{ name: "Phragma", license: "Apache-2.0" }],
    blockers: [],
    contentReadiness: {
      scope: "production",
      productionContent: true,
      productionReady: true,
      evidenceStatus: "passed",
      blockers: ["threat-id regression"],
    },
  });
  assert.equal(defensiveDecision.cls, "bad");
  assert.equal(defensiveDecision.checks.find((check) => check.key === "production-evidence").cls, "bad");
}

{
  const demoDecision = contentPackageDecisionPath({
    kind: "app-id",
    state: "verified",
    source: "local package",
    manifestSha256: "0123456789abcdef",
    signatureStatus: "verified",
    regressionStatus: "passed",
    rolloutState: "stable",
    rollbackAvailable: true,
    provenance: [{ name: "Demo", license: "Apache-2.0" }],
    blockers: [],
    contentReadiness: {
      scope: "demo-only",
      productionContent: false,
      productionReady: false,
      evidenceStatus: "demo-only",
      blockers: ["production content scope"],
    },
  });
  assert.equal(demoDecision.cls, "warn");
  assert.equal(demoDecision.checks.find((check) => check.key === "production-evidence").status, "demo-only");
  assert.match(demoDecision.checks.find((check) => check.key === "production-evidence").action, /production-scoped package/);
}

{
  const decision = contentPackageDecisionPath({
    kind: "threat-id",
    state: "invalid",
    signatureStatus: "invalid",
    regressionStatus: "failed",
    blockers: ["signature invalid", "file hash", "production evidence:pcap-regression-corpus"],
  });
  assert.equal(decision.cls, "bad");
  assert.equal(decision.label, "blocked");
  assert.equal(decision.checks.find((check) => check.key === "signature").cls, "bad");
  assert.equal(decision.checks.find((check) => check.key === "hash").cls, "bad");
  assert.equal(decision.checks.find((check) => check.key === "production-evidence").cls, "bad");
  assert.ok(decision.blockers.includes("production evidence"));
  assert.match(decision.nextAction, /verified manifest signature/);
}

{
  const guidance = contentPackageInstallGuidance("app-id");
  assert.equal(guidance.label, "Server-local source directory");
  assert.equal(guidance.placeholder, "<data-dir>/content-import/app-id");
  assert.match(guidance.subtitle, /firewall's content import directory/);
  assert.match(guidance.detail, /configured content import directory/);
  assert.match(guidance.detail, /not a browser upload/);
  assert.match(guidance.detail, /operator workstation/);
  assert.match(guidance.emptySourceMessage, /firewall-server package directory/);
}

{
  const current = {
    kind: "app-id",
    name: "Phragma App-ID catalog",
    state: "verified",
    version: "1.0.0",
    manifestSha256: "a".repeat(64),
    signatureStatus: "verified",
    regressionStatus: "passed",
    rolloutState: "stable",
    rollbackAvailable: true,
    blockers: [],
    contentReadiness: {
      productionReady: true,
      evidenceStatus: "passed",
      evidence: [{ type: "app-taxonomy", artifact: "evidence/app-taxonomy.json", sha256: "a".repeat(64) }],
      blockers: [],
    },
  };
  const preview = {
    kind: "app-id",
    name: "Phragma App-ID catalog",
    state: "verified",
    version: "1.1.0",
    source: "Phragma curated package",
    manifestSha256: "b".repeat(64),
    signatureStatus: "verified",
    regressionStatus: "passed",
    rolloutState: "canary",
    rollbackAvailable: true,
    provenance: [{ name: "Phragma", license: "Apache-2.0" }],
    blockers: [],
    contentReadiness: {
      productionReady: true,
      evidenceStatus: "passed",
      evidence: [{ type: "app-taxonomy", artifact: "evidence/app-taxonomy.json", sha256: "b".repeat(64) }],
      blockers: [],
    },
  };
  const comparison = contentPackagePreviewComparison(current, preview);
  assert.equal(comparison.cls, "ok");
  assert.equal(comparison.kind, "app-id");
  assert.match(comparison.title, /changes installed content/);
  assert.ok(comparison.changedCount >= 3);
  assert.equal(comparison.rows.find((row) => row.key === "version").cls, "ok");
  assert.equal(comparison.rows.find((row) => row.key === "manifest").changed, true);
  assert.equal(comparison.rows.find((row) => row.key === "blockers").preview, "none");
}

{
  const comparison = contentPackagePreviewComparison({
    kind: "threat-id",
    version: "2.0.0",
    manifestSha256: "c".repeat(64),
    signatureStatus: "verified",
    regressionStatus: "passed",
    rollbackAvailable: true,
    blockers: [],
  }, {
    kind: "threat-id",
    state: "invalid",
    version: "1.9.0",
    manifestSha256: "d".repeat(64),
    signatureStatus: "invalid",
    regressionStatus: "failed",
    rollbackAvailable: false,
    blockers: ["signature invalid", "regression result"],
  });
  assert.equal(comparison.cls, "bad");
  assert.match(comparison.title, /blocked/);
  assert.equal(comparison.rows.find((row) => row.key === "version").cls, "warn");
  assert.equal(comparison.rows.find((row) => row.key === "signature").cls, "bad");
  assert.equal(comparison.rows.find((row) => row.key === "blockers").preview, "2 blockers");
}

{
  assert.deepEqual(normalizeCustomFeed({
    name: "corp-feed",
    url: "https://feeds.example.com/blocklist.txt?source=secops",
    description: "SecOps curated",
  }, feeds, []), {
    feed: {
      name: "corp-feed",
      url: "https://feeds.example.com/blocklist.txt?source=secops",
      description: "SecOps curated",
    },
  });

  assert.equal(
    normalizeCustomFeed({ name: "corp-feed", url: "https://user:secret@feeds.example.com/blocklist.txt" }, feeds, []).error,
    "URL must not include userinfo; store feed credentials outside policy.",
  );

  assert.equal(
    normalizeCustomFeed({ name: "corp-feed", url: "https://feeds.example.com/blocklist.txt?access_token=secret" }, feeds, []).error,
    'URL must not include sensitive query parameter "access_token"; store feed credentials outside policy.',
  );

  assert.equal(
    normalizeCustomFeed({ name: "corp-feed", url: "https://feeds.example.com/blocklist.txt?source=secops;api_key=secret" }, feeds, []).error,
    'URL must not include sensitive query parameter "api_key"; store feed credentials outside policy.',
  );

  for (const url of [
    "http://localhost/blocklist.txt",
    "http://127.0.0.1/blocklist.txt",
    "http://10.0.0.8/blocklist.txt",
    "http://169.254.169.254/opc/v2/instance/",
    "http://[::1]/blocklist.txt",
    "http://metadata.google.internal/blocklist.txt",
    "http://feed.local/blocklist.txt",
  ]) {
    assert.equal(
      normalizeCustomFeed({ name: "corp-feed", url }, feeds, []).error,
      "URL must not target loopback, private, link-local, local, or metadata destinations.",
    );
  }
}
