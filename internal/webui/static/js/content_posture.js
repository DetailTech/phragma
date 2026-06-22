// content_posture.js - pure threat content and feed readiness model.
// The Intel view renders this model, and Readiness uses it as a production
// gate so App-ID/Threat-ID/feed package gaps are visible outside one page.

export const REQUIRED_CONTENT_QUALITY_EVIDENCE = Object.freeze({
  "app-id": Object.freeze(["app-taxonomy", "confidence-model", "app-regression-corpus", "license-review", "staged-rollout", "rollback-drill"]),
  "threat-id": Object.freeze(["threat-taxonomy", "pcap-regression-corpus", "false-positive-regression", "license-review", "staged-rollout", "rollback-drill"]),
  "intel-feeds": Object.freeze(["feed-registry", "parser-tests", "license-review", "false-positive-regression", "staged-rollout", "rollback-drill"]),
});

export function contentPackageInstallGuidance(kind = "package") {
  const packageKind = String(kind || "package").trim() || "package";
  return {
    label: "Server-local source directory",
    placeholder: `<data-dir>/content-import/${packageKind}`,
    subtitle: "Promotes a verified package from the firewall's content import directory.",
    detail: "Enter an absolute path under the configured content import directory, or a relative directory name inside it. This is not a browser upload or a path on the operator workstation. The directory must exist on the firewall server and contain manifest.json plus every referenced file.",
    emptySourceMessage: "Enter a firewall-server package directory under the configured content import directory.",
  };
}

export function customFeeds(policy = {}) {
  return policy.intel?.customFeeds || [];
}

export function effectiveFeedEnabled(feed = {}, intelPolicy = {}) {
  const declared = (intelPolicy.feeds || []).find((f) => f.name === feed.name);
  if (declared && typeof declared.enabled === "boolean") return declared.enabled;
  return !!feed.enabled;
}

export function buildContentPosture(feeds = [], policy = {}, contentPackages = [], contentError = "") {
  const intelPolicy = policy.intel || {};
  const effectiveFeeds = feeds.map((feed) => ({ ...feed, effectiveEnabled: effectiveFeedEnabled(feed, intelPolicy) }));
  const enabledFeeds = effectiveFeeds.filter((feed) => feed.effectiveEnabled).length;
  const stagedCustomFeeds = Array.isArray(intelPolicy.customFeeds) ? intelPolicy.customFeeds.length : null;
  const customFeedCount = stagedCustomFeeds == null ? feeds.filter((feed) => feed.custom).length : stagedCustomFeeds;
  const commercialUse = !!intelPolicy.commercialUse;
  const nonCommercialEnabled = effectiveFeeds.filter((feed) => commercialUse && feed.effectiveEnabled && !feed.custom && feed.allowsCommercialUse === false);
  const appObjects = Array.isArray(policy.applications) ? policy.applications.length : 0;
  const threatExceptions = Array.isArray(policy.ids?.exceptions) ? policy.ids.exceptions.length : 0;
  const packageMap = packageByKind(contentPackages);
  const packageDecisions = contentPackages.map((pkg) => contentPackageDecisionPath(pkg));
  const packageBlockers = contentPackages.flatMap((pkg) => pkg.blockers || []);
  const decisionBlockers = packageDecisions.flatMap((decision) => decision.blockers || []);
  const blockers = unique([
    ...(contentPackages.length ? packageBlockers : [
      "signed manifest",
      "package version/hash",
      "regression result",
      "staged rollout",
      "package rollback",
      "production evidence",
    ]),
    ...decisionBlockers,
  ]);
  if (nonCommercialEnabled.length) blockers.push("commercial license conflict");
  if (contentError) blockers.push("content package API");
  const signedVerified = contentPackages.filter((pkg) => pkg.signatureStatus === "verified").length;
  const appPkg = packageMap.get("app-id");
  const threatPkg = packageMap.get("threat-id");
  const feedPkg = packageMap.get("intel-feeds");
  const productionContentReadiness = aggregateProductionContentReadiness(packageMap, contentError);
  const cls = contentError ? "bad" : blockers.length ? "warn" : "ok";

  return {
    metrics: {
      appPackage: packageMetric(appPkg, "local policy"),
      threatPackage: packageMetric(threatPkg, "engine-normalized"),
      feedRegistry: `${enabledFeeds}/${feeds.length} enabled`,
      signedPackages: contentPackages.length ? `${signedVerified}/${contentPackages.length} verified` : "missing",
    },
    summary: {
      cls,
      title: cls === "ok" ? "Content packages verified." : contentError ? "Content package status unavailable." : "Content package controls are incomplete.",
      detail: contentError || (cls === "ok"
        ? "Installed package manifests include verified signatures, hashes, regression results, rollout state, rollback metadata, and provenance."
        : "The API now reports package version, hash, signature, regression, rollout, rollback, and provenance status; missing items remain production blockers."),
    },
    blockers: unique(blockers),
    rolloutReview: contentRolloutReview(packageDecisions, contentError),
    productionContentReadiness,
    commercialUse,
    nonCommercialEnabled: nonCommercialEnabled.map((feed) => feed.name),
    surfaces: [
      packageSurface(appPkg, {
        kind: "app-id",
        name: "App-ID catalog",
        badge: "local",
        cls: "warn",
        detail: `${appObjects} custom application objects plus canonical flow evidence fields. nDPI remains a signal source; Phragma owns taxonomy, confidence, and explanations.`,
        evidence: ["policy.applications[]", "flows.app_id", "flows.app_confidence"],
      }),
      packageSurface(threatPkg, {
        kind: "threat-id",
        name: "Threat-ID catalog",
        badge: "local",
        cls: "warn",
        detail: `${threatExceptions} false-positive exceptions staged through policy. Suricata remains the matching engine; Phragma owns severity, profile context, and evidence.`,
        evidence: ["alerts.threat_id", "alerts.threat_severity", "ids.exceptions[]"],
      }),
      packageSurface(feedPkg, {
        kind: "intel-feeds",
        name: "Threat-intel feeds",
        badge: nonCommercialEnabled.length ? "blocked" : "governed",
        cls: nonCommercialEnabled.length ? "bad" : "info",
        detail: `${enabledFeeds} of ${feeds.length} registry feeds are enabled; ${customFeedCount} custom feeds are staged in policy. License metadata is present; package verification status is reported separately.`,
        evidence: ["feed license", "commercial-use guard", "custom HTTP(S) feeds"],
      }),
    ],
  };
}

export function contentPackageDecisionPath(pkg = {}) {
  const kind = pkg.kind || "package";
  const blockers = Array.isArray(pkg.blockers) ? pkg.blockers : [];
  const blockerText = blockers.join("\n").toLowerCase();
  const hasPackage = !!pkg.kind || !!pkg.name || !!pkg.state || !!pkg.version || blockers.length > 0;
  const isVerified = pkg.state === "verified";
  const checks = [
    contentDecisionCheck({
      key: "signature",
      label: "Signature",
      ok: pkg.signatureStatus === "verified",
      bad: /signature invalid|trusted publisher|signature algorithm/.test(blockerText),
      status: pkg.signatureStatus || "missing",
      blockerMatch: /signed manifest|signature/.test(blockerText),
      action: "Install a package with a verified manifest signature from the trusted content keyring.",
    }),
    contentDecisionCheck({
      key: "hash",
      label: "Hash",
      ok: !!pkg.manifestSha256 && !!pkg.version && !/package version\/hash|semantic version|file hash|file path/.test(blockerText),
      bad: /file hash|file path|manifest parse error|manifest path|package kind/.test(blockerText),
      status: pkg.manifestSha256 ? `sha256:${String(pkg.manifestSha256).slice(0, 12)}` : "missing",
      blockerMatch: /package version\/hash|semantic version|file hash|file path|manifest/.test(blockerText),
      action: "Use a semver package manifest with signed file hashes for every referenced artifact.",
    }),
    contentDecisionCheck({
      key: "provenance",
      label: "Provenance",
      ok: !!pkg.source && Array.isArray(pkg.provenance) && pkg.provenance.length > 0 && !/source identity|provenance/.test(blockerText),
      status: provenanceLabel(pkg.provenance),
      blockerMatch: /source identity|provenance/.test(blockerText),
      action: "Record source identity, named provenance URL, license, and redistribution/commercial-use rights.",
    }),
    contentDecisionCheck({
      key: "regression",
      label: "Regression",
      ok: pkg.regressionStatus === "passed" && !/regression/.test(blockerText),
      bad: pkg.regressionStatus === "failed" || /regression result/.test(blockerText),
      status: pkg.regressionStatus || "missing",
      blockerMatch: /regression/.test(blockerText),
      action: "Run package regression tests with corpus, run time, and zero failed cases recorded in the manifest.",
    }),
    contentDecisionCheck({
      key: "rollout",
      label: "Rollout",
      ok: !!pkg.rolloutState && !/staged rollout/.test(blockerText),
      status: pkg.rolloutState || "missing",
      blockerMatch: /staged rollout/.test(blockerText),
      action: "Declare rollout state and scope before the package can safely change verdicts.",
    }),
    contentDecisionCheck({
      key: "rollback",
      label: "Rollback",
      ok: !!pkg.rollbackAvailable && !/package rollback/.test(blockerText),
      status: pkg.rollbackAvailable ? "verified backup" : "missing",
      blockerMatch: /rollback/.test(blockerText) || !pkg.rollbackAvailable,
      action: "Keep a verified rollback backup and package rollback metadata before promotion.",
    }),
    productionEvidenceCheck(pkg, blockerText, hasPackage, isVerified),
  ];
  const blocking = checks.filter((check) => check.cls === "bad");
  const warnings = checks.filter((check) => check.cls === "warn");
  const cls = blocking.length ? "bad" : warnings.length ? "warn" : "ok";
  const next = blocking[0] || warnings[0] || checks.find((check) => check.key === "rollout") || checks[0];
  return {
    kind,
    cls,
    label: cls === "ok" ? "ready for reviewed rollout" : cls === "bad" ? "blocked" : "review required",
    detail: cls === "ok"
      ? "Package checks report signed identity, hash, provenance, regression, rollout, rollback, and production evidence."
      : `${blocking.length + warnings.length} review item${blocking.length + warnings.length === 1 ? "" : "s"} before production rollout.`,
    nextAction: next?.action || "Review package blockers before changing content.",
    checks,
    blockers: checks.filter((check) => check.cls !== "ok").map((check) => check.blocker),
  };
}

export function contentQualityWorkbench(surface = {}) {
  const kind = surface.kind || "package";
  const decision = surface.decision || contentPackageDecisionPath(surface);
  const readiness = normalizedContentReadiness(surface);
  const evidence = Array.isArray(surface.contentReadinessEvidence)
    ? surface.contentReadinessEvidence
    : contentReadinessEvidenceRefs(readiness);
  const required = requiredContentQualityEvidence(kind, readiness);
  const evidenceByType = new Map(evidence.map((ref) => [ref.type, ref]));
  const packageGates = (decision.checks || []).map((check) => ({
    key: `package:${check.key || safeEvidenceToken(check.label) || "gate"}`,
    group: "Package gate",
    label: check.label || "Package gate",
    status: check.status || "missing",
    cls: check.cls || "warn",
    detail: check.cls === "ok" ? "Reported by the content package API." : check.action || "Resolve this package gate before production rollout.",
    action: check.action || "",
    evidence: "",
  }));
  const evidenceGates = required.map((type) => {
    const ref = evidenceByType.get(type);
    const attached = !!(ref?.artifact && ref?.sha256);
    return {
      key: `evidence:${type}`,
      group: "Required evidence",
      label: contentEvidenceTypeLabel(type),
      status: attached ? "attached" : "missing",
      cls: attached ? "ok" : "bad",
      detail: attached ? contentEvidenceLabel(ref) : `Required ${contentEvidenceTypeLabel(type)} artifact plus sha256 is not attached to the content readiness declaration.`,
      action: attached ? "Keep this artifact with the signed content package evidence bundle." : `Attach ${type} evidence in contentReadiness.evidence before production use.`,
      evidence: attached ? contentEvidenceLabel(ref) : "",
      evidenceRef: attached ? ref : null,
      requiredType: type,
    };
  });
  const gates = [...packageGates, ...evidenceGates];
  const blocking = gates.filter((gate) => gate.cls === "bad");
  const review = gates.filter((gate) => gate.cls === "warn");
  const cls = blocking.length ? "bad" : review.length ? "warn" : "ok";
  const passCount = gates.filter((gate) => gate.cls === "ok").length;
  const missingEvidence = evidenceGates.filter((gate) => gate.cls !== "ok");
  const blockers = unique([
    ...(Array.isArray(surface.blockers) ? surface.blockers : []),
    ...(Array.isArray(decision.blockers) ? decision.blockers : []),
    ...missingEvidence.map((gate) => gate.requiredType),
  ]);
  const nextGate = blocking[0] || review[0] || null;
  return {
    kind,
    label: surface.name || kind,
    cls,
    summary: cls === "ok"
      ? "All package and required-evidence gates report ready for production review."
      : `${blocking.length + review.length} quality gate${blocking.length + review.length === 1 ? "" : "s"} require review before production content use.`,
    nextAction: nextGate?.action || "No quality-gate action required.",
    metrics: {
      version: surface.version || "missing",
      gateScore: `${passCount}/${gates.length}`,
      requiredEvidence: `${evidenceGates.length - missingEvidence.length}/${evidenceGates.length}`,
      blockers: String(blockers.length),
    },
    gates,
    requiredEvidence: required,
    attachedEvidence: evidence,
    blockers,
  };
}

export function contentReadinessActionPlan(surface = {}) {
  const workbench = contentQualityWorkbench(surface);
  const kind = surface.kind || workbench.kind || "package";
  const missingEvidence = (workbench.gates || [])
    .filter((gate) => gate.key?.startsWith("evidence:") && gate.cls !== "ok")
    .map((gate) => gate.requiredType || gate.key.replace(/^evidence:/, ""))
    .filter(Boolean);
  const attachedCorpus = (workbench.attachedEvidence || []).find((ref) => isCorpusEvidenceType(ref.type));
  const packageBlocked = (workbench.gates || []).some((gate) => gate.key?.startsWith("package:") && gate.cls === "bad");
  const needsInstall = packageBlocked || missingEvidence.length > 0 || workbench.cls !== "ok";
  const source = `<data-dir>/content-import/${kind}`;
  const commands = [
    contentActionCommand("Show installed package posture", "ngfwctl intel content"),
  ];
  if (needsInstall) {
    commands.push(
      contentActionCommand("Preview server-local candidate", `ngfwctl intel content preview ${kind} --source ${source}`),
      contentActionCommand("Install after preview review", `ngfwctl intel content install ${kind} --source ${source}`),
    );
  }
  if (attachedCorpus) {
    commands.push(contentActionCommand("Browse attached corpus", `ngfwctl intel content corpus ${kind} --evidence-type ${attachedCorpus.type}`));
  }
  if (surface.rollbackAvailable) {
    commands.push(contentActionCommand("Restore verified backup", `ngfwctl intel content rollback ${kind} --ack-rollback`));
  }
  const blockers = unique([...(workbench.blockers || []), ...missingEvidence]);
  return {
    kind,
    cls: workbench.cls,
    title: workbench.cls === "ok" ? "Production-readiness evidence is inspectable." : "Readiness evidence needs operator action.",
    detail: workbench.cls === "ok"
      ? "Use the evidence and corpus actions to inspect the installed package before approving content rollout."
      : missingEvidence.length
        ? `${missingEvidence.length} required evidence artifact${missingEvidence.length === 1 ? "" : "s"} must be added to the package readiness declaration and re-previewed from the server import directory.`
        : workbench.nextAction,
    nextAction: workbench.nextAction,
    missingEvidence,
    blockers,
    commands,
    evidence: workbench.attachedEvidence || [],
  };
}

export function contentCanaryTelemetryWorkbench(surface = {}) {
  const kind = surface.kind || "package";
  const decision = surface.decision || contentPackageDecisionPath(surface);
  const readiness = normalizedContentReadiness(surface);
  const evidence = Array.isArray(surface.contentReadinessEvidence)
    ? surface.contentReadinessEvidence
    : contentReadinessEvidenceRefs(readiness);
  const scopes = normalizeContentCanaryScopes(surface, readiness);
  const telemetry = normalizeFalsePositiveTelemetry(surface, readiness, evidence);
  const hasRollback = !!surface.rollbackAvailable;
  const packageBlocked = decision.cls === "bad";
  const fpPressure = telemetry.signals.some((signal) => signal.cls === "bad");
  const blockers = unique([
    ...(packageBlocked ? ["package rollout gates"] : []),
    ...(scopes.length ? [] : ["canary scopes"]),
    ...(telemetry.signals.length ? [] : ["false-positive telemetry"]),
    ...(hasRollback ? [] : ["rollback backup"]),
  ]);
  const cls = packageBlocked || fpPressure ? "bad" : blockers.length ? "warn" : "ok";
  const rolloutState = String(surface.rolloutState || readiness?.rolloutState || readiness?.rollout_state || "missing");
  return {
    kind,
    label: surface.name || kind,
    cls,
    title: cls === "ok"
      ? "Canary rollout telemetry is ready for review."
      : cls === "bad"
        ? "Canary rollout is blocked or reporting false-positive pressure."
        : "Canary rollout needs bounded review before promotion.",
    detail: cls === "ok"
      ? "Scope, false-positive telemetry, rollback posture, and package gates are available for operator review."
      : "This workbench is browser-local review of API-reported package fields and does not create signed custody, approval, or promotion authority.",
    nextAction: packageBlocked
      ? decision.nextAction
      : fpPressure
        ? "Hold promotion, inspect false-positive telemetry, and use existing policy exception or rollback workflows."
        : blockers.length
          ? `Resolve ${blockers[0]} before expanding verdict-changing rollout.`
          : "Review candidate impact and existing lifecycle actions before expanding rollout.",
    metrics: {
      rolloutState,
      canaryScopes: String(scopes.length),
      falsePositiveSignals: String(telemetry.signals.length),
      rollback: hasRollback ? "verified backup" : "missing",
    },
    scopes,
    telemetry,
    blockers,
    boundary: "Browser-local review only. Install, rollback, and false-positive exception changes still use existing API and candidate workflows; signed custody and approval enforcement remain hardening work.",
  };
}

export function contentPromotionDecision(surface = {}, opts = {}) {
  const lifecycleAction = String(opts.lifecycleAction || "promotion");
  const quality = opts.quality || contentQualityWorkbench(surface);
  const canary = opts.canary || contentCanaryTelemetryWorkbench(surface);
  const decision = surface.decision || contentPackageDecisionPath(surface);
  const comparison = opts.previewComparison || null;
  const regressionStatus = String(surface.regressionStatus || "").toLowerCase();
  const regressionGate = (quality.gates || []).find((gate) => gate.key === "package:regression");
  const regressionFailed = regressionStatus === "failed" || regressionGate?.cls === "bad";
  const regressionMissing = !regressionStatus || regressionStatus === "missing" || regressionGate?.status === "missing";
  const fpPressure = (canary.telemetry?.signals || []).some((signal) => signal.cls === "bad");
  const sameManifest = !!comparison && (comparison.rows || []).some((row) => row.key === "manifest" && !row.changed && row.current !== "missing");
  const previewBlocked = !!comparison && comparison.cls === "bad";
  const previewNeedsReview = !!comparison && comparison.cls === "warn";
  const qualityBlocked = quality.cls === "bad" || decision.cls === "bad";
  const qualityReview = quality.cls === "warn" || decision.cls === "warn";
  const canaryBlocked = canary.cls === "bad";
  const canaryReview = canary.cls === "warn";
  const rollbackMissing = !surface.rollbackAvailable;
  const blockers = unique([
    ...(qualityBlocked ? ["quality gates"] : []),
    ...(canaryBlocked ? ["canary or false-positive telemetry"] : []),
    ...(regressionFailed ? ["regression failure"] : []),
    ...(regressionMissing ? ["regression result"] : []),
    ...(rollbackMissing ? ["rollback backup"] : []),
    ...(previewBlocked ? ["preview comparison"] : []),
  ]);
  const reviewItems = unique([
    ...(qualityReview ? ["quality gates need review"] : []),
    ...(canaryReview ? ["canary scope or telemetry needs review"] : []),
    ...(previewNeedsReview ? ["preview comparison needs review"] : []),
    ...(sameManifest ? ["preview manifest matches installed content"] : []),
  ]);
  const shouldRollbackReview = regressionFailed || fpPressure || qualityBlocked;
  const blocked = blockers.length > 0;
  const review = !blocked && reviewItems.length > 0;
  const rollbackMode = lifecycleAction === "rollback";
  const cls = rollbackMode
    ? !surface.rollbackAvailable ? "bad" : shouldRollbackReview ? "warn" : "info"
    : blocked ? "bad" : review ? "warn" : "ok";
  const label = rollbackMode
    ? !surface.rollbackAvailable ? "rollback blocked" : shouldRollbackReview ? "rollback review advised" : "rollback available"
    : cls === "ok" ? "promotion handoff ready" : cls === "bad" ? "hold promotion" : "review before promotion";
  const detail = rollbackMode
    ? !surface.rollbackAvailable
      ? "The package API has not reported a verified backup, so rollback cannot be initiated from this workflow."
      : shouldRollbackReview
        ? "Quality, regression, or false-positive signals justify rollback review, but this panel is not an approval authority."
        : "Rollback is available as a lifecycle control; current quality and canary signals do not independently require it."
    : blocked
      ? `${blockers.length} gate${blockers.length === 1 ? "" : "s"} must be resolved before a verdict-changing package promotion handoff is ready.`
      : review
        ? "Promotion is not blocked, but operators should review the listed signals before expanding rollout."
        : "Quality gates, regression posture, canary telemetry, and rollback posture are aligned for a non-authoritative promotion handoff.";
  return {
    kind: surface.kind || quality.kind || canary.kind || "package",
    cls,
    label,
    detail,
    nextAction: rollbackMode
      ? !surface.rollbackAvailable
        ? "Install a package with verified rollback metadata before relying on rollback."
        : shouldRollbackReview
          ? "Review canary false-positive pressure, regression evidence, and package quality gates before invoking rollback."
          : "Keep rollback as an audited recovery option and continue promotion review through existing lifecycle controls."
      : blocked
        ? `Hold promotion and resolve ${blockers[0]}.`
        : review
          ? `Review ${reviewItems[0]} before using the install lifecycle action.`
          : "Use preview, API/CLI context, and existing install lifecycle controls for the final operator action.",
    blockers,
    reviewItems,
    checks: [
      promotionDecisionCheck("quality", "Quality gates", quality.cls, quality.metrics?.gateScore || ""),
      promotionDecisionCheck("regression", "Regression", regressionFailed ? "bad" : regressionMissing ? "warn" : "ok", regressionStatus || regressionGate?.status || "missing"),
      promotionDecisionCheck("canary", "Canary and FP telemetry", canary.cls, `${canary.metrics?.canaryScopes || "0"} scopes / ${canary.metrics?.falsePositiveSignals || "0"} FP signals`),
      promotionDecisionCheck("rollback", "Rollback control", surface.rollbackAvailable ? "ok" : "warn", surface.rollbackAvailable ? "verified backup" : "missing"),
      promotionDecisionCheck("authority", "Authority", "info", "handoff only"),
    ],
    commands: [
      contentActionCommand("Preview candidate package", `ngfwctl intel content preview ${surface.kind || "package"} --source <data-dir>/content-import/${surface.kind || "package"}`),
      contentActionCommand("Promote after review", `ngfwctl intel content install ${surface.kind || "package"} --source <data-dir>/content-import/${surface.kind || "package"}`),
      surface.rollbackAvailable ? contentActionCommand("Rollback if review requires", `ngfwctl intel content rollback ${surface.kind || "package"} --ack-rollback`) : null,
    ].filter(Boolean),
    boundary: "Non-authoritative workflow handoff only. The browser does not mutate policy, approve production content, sign custody, or bypass existing content lifecycle APIs.",
  };
}

function promotionDecisionCheck(key, label, cls, status) {
  return { key, label, cls: cls || "warn", status: status || "missing" };
}

function contentActionCommand(label, command) {
  return { label, command };
}

function isCorpusEvidenceType(type = "") {
  return /(?:regression-corpus|parser-tests|false-positive-regression)/.test(String(type || ""));
}

export function contentPackagePreviewComparison(current = {}, preview = {}) {
  const installed = current && typeof current === "object" ? current : {};
  const candidate = preview && typeof preview === "object" ? preview : {};
  const currentDecision = installed.decision || contentPackageDecisionPath(installed);
  const previewDecision = candidate.decision || contentPackageDecisionPath(candidate);
  const currentReadiness = packageContentReadiness(installed);
  const previewReadiness = packageContentReadiness(candidate);
  const rows = [
    packageComparisonRow("version", "Version", installed.version || "missing", candidate.version || "missing", versionComparisonClass(installed.version, candidate.version)),
    packageComparisonRow("manifest", "Manifest hash", shortContentHash(installed.manifestSha256), shortContentHash(candidate.manifestSha256), manifestComparisonClass(installed.manifestSha256, candidate.manifestSha256)),
    packageComparisonRow("signature", "Signature", installed.signatureStatus || "missing", candidate.signatureStatus || "missing", statusComparisonClass(candidate.signatureStatus, ["verified"], ["invalid", "untrusted", "unsupported"])),
    packageComparisonRow("regression", "Regression", installed.regressionStatus || "missing", candidate.regressionStatus || "missing", statusComparisonClass(candidate.regressionStatus, ["passed"], ["failed"])),
    packageComparisonRow("rollout", "Rollout", installed.rolloutState || "missing", candidate.rolloutState || "missing", candidate.rolloutState ? "info" : "warn"),
    packageComparisonRow("rollback", "Rollback", installed.rollbackAvailable ? "verified backup" : "missing", candidate.rollbackAvailable ? "verified backup" : "missing", candidate.rollbackAvailable ? "ok" : "warn"),
    packageComparisonRow("production-evidence", "Production evidence", productionEvidenceLabel(currentReadiness), productionEvidenceLabel(previewReadiness), productionEvidenceClass(previewReadiness)),
    packageComparisonRow("blockers", "Blockers", blockerCountLabel(installed.blockers), blockerCountLabel(candidate.blockers), blockerComparisonClass(candidate.blockers)),
  ];
  const changed = rows.filter((row) => row.changed);
  const previewCls = previewDecision.cls || "warn";
  const sameManifest = sameNonEmpty(installed.manifestSha256, candidate.manifestSha256);
  const cls = previewCls === "bad" ? "bad" : previewCls === "warn" ? "warn" : sameManifest ? "info" : "ok";
  return {
    kind: candidate.kind || installed.kind || "package",
    cls,
    title: previewComparisonTitle(cls, sameManifest, changed.length),
    detail: previewComparisonDetail(cls, currentDecision, previewDecision, sameManifest, changed.length),
    nextAction: previewDecision.nextAction || "Review previewed package gates before install.",
    changedCount: changed.length,
    rows,
    changedRows: changed,
    currentLabel: packageComparisonLabel(installed),
    previewLabel: packageComparisonLabel(candidate),
  };
}

function normalizedContentReadiness(surface = {}) {
  if (surface.contentReadiness && typeof surface.contentReadiness === "object") return surface.contentReadiness;
  return packageContentReadiness(surface);
}

function normalizeContentCanaryScopes(surface = {}, readiness = null) {
  const raw = firstArray(
    surface.canaryScopes,
    surface.canary_scopes,
    surface.rolloutScopes,
    surface.rollout_scopes,
    surface.rollout?.scopes,
    readiness?.canaryScopes,
    readiness?.canary_scopes,
    readiness?.rolloutScopes,
    readiness?.rollout_scopes,
  );
  return raw.map((scope = {}, index) => {
    const exposure = scope.percent ?? scope.percentage ?? scope.exposurePercent ?? scope.exposure_percent ?? scope.exposure;
    const status = String(scope.status || scope.state || scope.result || "declared").toLowerCase();
    return {
      name: safeOperatorLabel(scope.name || scope.scope || scope.policyScope || scope.policy_scope || `scope-${index + 1}`),
      mode: safeOperatorLabel(scope.mode || scope.verdictMode || scope.verdict_mode || scope.action || "observe"),
      exposure: exposure == null || exposure === "" ? "declared" : `${exposure}%`,
      status,
      cls: statusClass(status, ["ready", "healthy", "passed", "declared", "observe", "canary"], ["failed", "blocked", "rollback"]),
      detail: safeOperatorLabel(scope.detail || scope.description || scope.policy || scope.profile || ""),
    };
  });
}

function normalizeFalsePositiveTelemetry(surface = {}, readiness = null, evidence = []) {
  const raw = surface.falsePositiveTelemetry || surface.false_positive_telemetry || readiness?.falsePositiveTelemetry || readiness?.false_positive_telemetry || {};
  const signals = [];
  const rawSignals = firstArray(raw.signals, raw.items, raw.rows, raw.telemetry);
  for (const item of rawSignals) {
    signals.push(falsePositiveSignal(item));
  }
  for (const [key, label] of [
    ["events", "False-positive events"],
    ["falsePositiveEvents", "False-positive events"],
    ["false_positive_events", "False-positive events"],
    ["exceptions", "Active exceptions"],
    ["regressionFailures", "Regression failures"],
    ["regression_failures", "Regression failures"],
  ]) {
    if (raw[key] == null) continue;
    signals.push(falsePositiveSignal({ label, count: raw[key], status: Number(raw[key]) > 0 ? "review" : "clean" }));
  }
  const fpEvidence = evidence.find((ref) => ref?.type === "false-positive-regression");
  if (fpEvidence) {
    signals.push(falsePositiveSignal({
      label: "False-positive regression evidence",
      status: "attached",
      evidence: fpEvidence.artifact || fpEvidence.sha256Short,
      detail: fpEvidence.sha256Short ? `sha256:${fpEvidence.sha256Short}` : "",
    }));
  }
  const deduped = [];
  const seen = new Set();
  for (const signal of signals) {
    const key = `${signal.label}:${signal.status}:${signal.count}:${signal.evidence}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(signal);
  }
  const pressure = deduped.filter((signal) => signal.cls === "bad").length;
  return {
    cls: pressure ? "bad" : deduped.length ? "ok" : "warn",
    label: pressure ? `${pressure} pressure signal${pressure === 1 ? "" : "s"}` : deduped.length ? "reported" : "not reported",
    signals: deduped,
  };
}

function falsePositiveSignal(item = {}) {
  const status = String(item.status || item.state || item.verdict || "reported").toLowerCase();
  const count = item.count ?? item.events ?? item.sampleCount ?? item.sample_count ?? "";
  const cls = statusClass(status, ["passed", "clean", "attached", "ok", "suppressed", "none"], ["failed", "blocked", "increase", "increased", "critical", "high"]);
  return {
    label: safeOperatorLabel(item.label || item.name || item.type || "False-positive signal"),
    status,
    count: count === "" ? "" : String(count),
    evidence: safeOperatorLabel(item.evidence || item.artifact || item.reference || ""),
    detail: safeOperatorLabel(item.detail || item.summary || item.reason || ""),
    cls,
  };
}

function firstArray(...values) {
  for (const value of values) {
    if (Array.isArray(value)) return value;
  }
  return [];
}

function safeOperatorLabel(value = "") {
  return String(value || "").trim().replace(/\s+/g, " ").slice(0, 160);
}

function statusClass(value = "", okValues = [], badValues = []) {
  const normalized = String(value || "").toLowerCase();
  if (badValues.includes(normalized)) return "bad";
  if (okValues.includes(normalized)) return "ok";
  if (/(fail|block|critical|high|increase)/.test(normalized)) return "bad";
  if (/(pass|clean|ok|attach|ready|healthy)/.test(normalized)) return "ok";
  return "warn";
}

function requiredContentQualityEvidence(kind, readiness = null) {
  const explicit = Array.isArray(readiness?.requiredProductionEvidence)
    ? readiness.requiredProductionEvidence
    : [];
  const defaults = REQUIRED_CONTENT_QUALITY_EVIDENCE[kind] || [];
  return unique([...(explicit.length ? explicit : defaults)].map(safeEvidenceToken).filter(Boolean));
}

function contentEvidenceTypeLabel(type = "") {
  return String(type || "evidence")
    .split(/[-_]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function contentDecisionCheck({ key, label, ok, bad = false, status, blockerMatch, action }) {
  const cls = ok ? "ok" : bad ? "bad" : blockerMatch ? "warn" : "warn";
  return {
    key,
    label,
    status: status || "missing",
    cls,
    blocker: ok ? "" : label.toLowerCase(),
    action,
  };
}

function productionEvidenceCheck(pkg, blockerText, hasPackage, isVerified) {
  const readiness = packageContentReadiness(pkg);
  if (readiness) {
    const blockers = Array.isArray(readiness.blockers) ? readiness.blockers : [];
    if (readiness.productionReady && readiness.evidenceStatus === "passed" && blockers.length === 0) {
      return {
        key: "production-evidence",
        label: "Production evidence",
        status: readiness.readinessLabel || readiness.evidenceStatus || "passed",
        cls: "ok",
        blocker: "",
        action: readiness.readinessDetail || "Production evidence is attached and verified for this package.",
      };
    }
    return {
      key: "production-evidence",
      label: "Production evidence",
      status: readiness.readinessLabel || readiness.evidenceStatus || "incomplete",
      cls: readiness.evidenceStatus === "incomplete" || (readiness.productionReady && blockers.length) ? "bad" : "warn",
      blocker: "production evidence",
      action: readinessAction(readiness, blockers),
    };
  }
  const explicitBlocker = /content readiness|production content|production evidence|verified package/.test(blockerText);
  if (explicitBlocker) {
    return {
      key: "production-evidence",
      label: "Production evidence",
      status: "blocked",
      cls: "bad",
      blocker: "production evidence",
      action: "Attach the required production evidence artifacts and readiness declaration to the content package.",
    };
  }
  if (!hasPackage) {
    return {
      key: "production-evidence",
      label: "Production evidence",
      status: "missing",
      cls: "warn",
      blocker: "production evidence",
      action: "Install a content package that reports production evidence before enabling verdict-changing updates.",
    };
  }
  return {
    key: "production-evidence",
    label: "Production evidence",
    status: isVerified ? "not exposed" : "not ready",
    cls: "warn",
    blocker: "production evidence",
    action: "Review package evidence outside the current API response; this UI will not mark production-ready without explicit evidence.",
  };
}

function readinessAction(readiness, blockers = []) {
  if (readiness.readinessDetail) {
    return readiness.readinessDetail;
  }
  if (readiness.evidenceStatus === "demo-only") {
    return "Install a production-scoped package before using this content for verdict-changing production updates.";
  }
  if (blockers.length) {
    return `Resolve content readiness blocker: ${blockers[0]}.`;
  }
  return "Attach required production evidence artifacts and readiness declaration to the content package.";
}

function contentRolloutReview(decisions, contentError) {
  if (contentError) {
    return {
      cls: "bad",
      label: "status unavailable",
      detail: "The content package API did not return package posture. Do not install, rollback, or promote verdict-changing updates until status is available.",
      nextAction: "Restore /v1/intel/content/packages visibility and re-run package review.",
      blockers: ["content package API"],
    };
  }
  if (!decisions.length) {
    return {
      cls: "warn",
      label: "no packages reported",
      detail: "No package status was returned for App-ID, Threat-ID, or intel-feed content.",
      nextAction: "Install signed local content packages from the firewall import directory.",
      blockers: ["content packages"],
    };
  }
  const blockers = decisions.flatMap((decision) => decision.blockers || []);
  const bad = decisions.filter((decision) => decision.cls === "bad").length;
  const warn = decisions.filter((decision) => decision.cls === "warn").length;
  return {
    cls: bad ? "bad" : warn ? "warn" : "ok",
    label: bad ? `${bad} blocked` : warn ? `${warn} review` : "reviewed",
    detail: blockers.length
      ? `${blockers.length} package gate${blockers.length === 1 ? "" : "s"} need review before production rollout.`
      : "All package rollout gates report ready.",
    nextAction: (decisions.find((decision) => decision.cls !== "ok") || decisions[0])?.nextAction || "No action required.",
    blockers: unique(blockers),
  };
}

function aggregateProductionContentReadiness(packageMap, contentError = "") {
  const kinds = ["app-id", "threat-id", "intel-feeds"];
  if (contentError) {
    return {
      productionReady: false,
      state: "unavailable",
      status: "unavailable",
      detail: "Content package API status is unavailable.",
      meta: "make content-production-readiness-check",
      blockers: ["content package API"],
      packages: [],
    };
  }
  const packages = kinds.map((kind) => packageProductionReadiness(kind, packageMap.get(kind)));
  const blockers = packages.flatMap((pkg) => pkg.blockers);
  const ready = blockers.length === 0 && packages.every((pkg) => pkg.productionReady);
  return {
    productionReady: ready,
    state: ready ? "passed" : "blocked",
    status: ready ? "passed" : "blocked",
    detail: ready
      ? "Production App-ID, Threat-ID, and intel-feed content readiness evidence is explicitly recorded for this release."
      : `${blockers.length} production content blocker${blockers.length === 1 ? "" : "s"} across App-ID, Threat-ID, and intel-feed packages.`,
    meta: ready ? "content-production-readiness passed" : "make content-production-readiness-check",
    blockers: unique(blockers),
    packages,
  };
}

function packageProductionReadiness(kind, pkg) {
  const readiness = packageContentReadiness(pkg);
  if (!pkg) {
    return {
      kind,
      productionReady: false,
      evidenceStatus: "missing",
      blockers: [`${kind}:content package`],
    };
  }
  if (!readiness) {
    return {
      kind,
      productionReady: false,
      evidenceStatus: "not exposed",
      blockers: [`${kind}:content readiness declaration`],
    };
  }
  const blockers = Array.isArray(readiness.blockers) ? readiness.blockers : [];
  const productionReady = readiness.productionReady && readiness.evidenceStatus === "passed" && blockers.length === 0;
  return {
    kind,
    productionReady,
    evidenceStatus: readiness.evidenceStatus || "missing",
    readinessLabel: readiness.readinessLabel || readiness.evidenceStatus || "missing",
    readinessDetail: readiness.readinessDetail || "",
    scope: readiness.scope,
    evidenceCount: readiness.evidence?.length || 0,
    blockers: productionReady
      ? []
      : (blockers.length ? blockers : ["production evidence"]).map((blocker) => `${kind}:${blocker}`),
  };
}

function packageByKind(packages = []) {
  const out = new Map();
  for (const pkg of packages) {
    if (pkg?.kind) out.set(pkg.kind, pkg);
  }
  return out;
}

function packageMetric(pkg, fallback) {
  if (!pkg) return fallback;
  if (pkg.version) return pkg.version;
  return pkg.state || fallback;
}

function packageSurface(pkg, fallback) {
  if (!pkg) return { ...fallback, fields: [], provenance: [], rollbackAvailable: false, decision: contentPackageDecisionPath({ kind: fallback.kind, name: fallback.name }) };
  const decision = contentPackageDecisionPath(pkg);
  const readiness = packageContentReadiness(pkg);
  const readinessEvidence = contentReadinessEvidenceRefs(readiness);
  const evidence = [
    pkg.manifestSha256 ? `sha256:${pkg.manifestSha256.slice(0, 12)}` : null,
    `signature:${pkg.signatureStatus || "missing"}`,
    `regression:${pkg.regressionStatus || "missing"}`,
    `rollout:${pkg.rolloutState || "missing"}`,
    `rollback-backup:${pkg.rollbackAvailable ? "yes" : "no"}`,
    readiness ? `content-readiness:${readiness.readinessLabel || readiness.evidenceStatus || "missing"}` : null,
    ...readinessEvidence.map((ref) => `${ref.type}:${ref.artifact || ref.sha256Short || "attached"}`),
  ].filter(Boolean);
  return {
    kind: pkg.kind || fallback.kind,
    name: pkg.name || fallback.name,
    badge: pkg.state || "unknown",
    cls: packageStateClass(pkg.state),
    version: pkg.version || "",
    source: pkg.source || "",
    manifestSha256: pkg.manifestSha256 || "",
    signatureStatus: pkg.signatureStatus || "",
    regressionStatus: pkg.regressionStatus || "",
    rolloutState: pkg.rolloutState || "",
    canaryScopes: normalizeContentCanaryScopes(pkg, readiness),
    falsePositiveTelemetry: normalizeFalsePositiveTelemetry(pkg, readiness, readinessEvidence),
    blockers: Array.isArray(pkg.blockers) ? [...pkg.blockers] : [],
    contentReadiness: readiness,
    contentReadinessEvidence: readinessEvidence,
    keyContentReadinessEvidence: keyContentReadinessEvidence(readinessEvidence),
    detail: packageDetail(pkg, fallback.detail),
    evidence,
    fields: packageFields(pkg, readinessEvidence),
    provenance: packageProvenance(pkg),
    rollbackAvailable: !!pkg.rollbackAvailable,
    decision,
  };
}

function packageFields(pkg, readinessEvidence = null) {
  const readiness = packageContentReadiness(pkg);
  const evidenceRefs = readinessEvidence || contentReadinessEvidenceRefs(readiness);
  const keyRefs = keyContentReadinessEvidence(evidenceRefs);
  return [
    {
      label: "Source",
      value: pkg.source || "missing",
      cls: pkg.source ? "info" : "warn",
    },
    {
      label: "Provenance",
      value: provenanceLabel(pkg.provenance),
      cls: Array.isArray(pkg.provenance) && pkg.provenance.length ? "ok" : "warn",
    },
    {
      label: "Manifest hash",
      value: pkg.manifestSha256 ? `sha256:${pkg.manifestSha256.slice(0, 12)}` : "missing",
      cls: pkg.manifestSha256 ? "ok" : "warn",
    },
    {
      label: "Signature",
      value: pkg.signatureStatus || "missing",
      cls: signatureEvidenceClass(pkg.signatureStatus),
    },
    {
      label: "Regression",
      value: pkg.regressionStatus || "missing",
      cls: pkg.regressionStatus === "passed" ? "ok" : pkg.regressionStatus === "failed" ? "bad" : "warn",
    },
    {
      label: "Rollout",
      value: pkg.rolloutState || "missing",
      cls: pkg.rolloutState ? "info" : "warn",
    },
    {
      label: "Rollback",
      value: pkg.rollbackAvailable ? "verified backup" : "missing",
      cls: pkg.rollbackAvailable ? "ok" : "warn",
    },
    {
      label: "Production evidence",
      value: productionEvidenceLabel(readiness),
      cls: productionEvidenceClass(readiness),
    },
    keyRefs.appRegressionCorpus ? {
      label: "App-ID regression",
      value: contentEvidenceLabel(keyRefs.appRegressionCorpus),
      cls: "ok",
    } : null,
    keyRefs.pcapRegressionCorpus ? {
      label: "PCAP regression",
      value: contentEvidenceLabel(keyRefs.pcapRegressionCorpus),
      cls: "ok",
    } : null,
    keyRefs.falsePositiveRegression ? {
      label: "False-positive regression",
      value: contentEvidenceLabel(keyRefs.falsePositiveRegression),
      cls: "ok",
    } : null,
  ].filter(Boolean);
}

function packageContentReadiness(pkg = {}) {
  const readiness = pkg.contentReadiness || pkg.content_readiness || null;
  if (!readiness || typeof readiness !== "object") return null;
  return {
    scope: readiness.scope || "",
    productionContent: !!(readiness.productionContent ?? readiness.production_content),
    productionReady: !!(readiness.productionReady ?? readiness.production_ready),
    evidenceStatus: readiness.evidenceStatus || readiness.evidence_status || "",
    readinessLabel: readiness.readinessLabel || readiness.readiness_label || "",
    readinessDetail: readiness.readinessDetail || readiness.readiness_detail || "",
    evidence: contentReadinessEvidenceRefs(readiness),
    rolloutState: readiness.rolloutState || readiness.rollout_state || "",
    rolloutScopes: Array.isArray(readiness.rolloutScopes)
      ? readiness.rolloutScopes
      : Array.isArray(readiness.rollout_scopes) ? readiness.rollout_scopes : [],
    canaryScopes: Array.isArray(readiness.canaryScopes)
      ? readiness.canaryScopes
      : Array.isArray(readiness.canary_scopes) ? readiness.canary_scopes : [],
    falsePositiveTelemetry: readiness.falsePositiveTelemetry || readiness.false_positive_telemetry || null,
    requiredProductionEvidence: Array.isArray(readiness.requiredProductionEvidence)
      ? readiness.requiredProductionEvidence
      : Array.isArray(readiness.required_production_evidence) ? readiness.required_production_evidence : [],
    blockers: Array.isArray(readiness.blockers) ? readiness.blockers : [],
  };
}

export function contentReadinessEvidenceRefs(readiness = {}) {
  const evidence = Array.isArray(readiness?.evidence) ? readiness.evidence : [];
  return evidence.map(contentReadinessEvidenceRef).filter(Boolean);
}

function contentReadinessEvidenceRef(ref = {}) {
  const type = safeEvidenceToken(ref.type || ref.evidenceType || ref.evidence_type);
  const artifact = safeEvidenceArtifact(ref.artifact || ref.path || ref.name);
  const sha256 = safeSha256(ref.sha256 || ref.sha256Hash || ref.sha256_hash);
  const generatedAt = safeTimestamp(ref.generatedAt || ref.generated_at);
  if (!type && !artifact && !sha256) return null;
  return {
    type: type || "evidence",
    artifact,
    sha256,
    sha256Short: sha256 ? sha256.slice(0, 12) : "",
    generatedAt,
  };
}

export function keyContentReadinessEvidence(evidence = []) {
  return {
    appRegressionCorpus: findContentEvidence(evidence, "app-regression-corpus"),
    pcapRegressionCorpus: findContentEvidence(evidence, "pcap-regression-corpus"),
    falsePositiveRegression: findContentEvidence(evidence, "false-positive-regression"),
  };
}

function findContentEvidence(evidence = [], type) {
  return (evidence || []).find((ref) => ref?.type === type) || null;
}

function contentEvidenceLabel(ref = {}) {
  const parts = [];
  if (ref.artifact) parts.push(ref.artifact);
  if (ref.sha256Short) parts.push(`sha256:${ref.sha256Short}`);
  if (ref.generatedAt) parts.push(ref.generatedAt);
  return parts.join(" · ") || ref.type || "attached";
}

function safeEvidenceToken(value = "") {
  return String(value || "").trim().toLowerCase().replace(/[^a-z0-9_.:-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 128);
}

function packageComparisonRow(key, label, current, preview, cls = "info") {
  const left = String(current || "missing");
  const right = String(preview || "missing");
  return { key, label, current: left, preview: right, changed: left !== right, cls: left === right ? "neutral" : cls };
}

function packageComparisonLabel(pkg = {}) {
  if (!pkg || !Object.keys(pkg).length) return "not installed";
  return [pkg.version || pkg.state || "installed", shortContentHash(pkg.manifestSha256)].filter(Boolean).join(" / ");
}

function versionComparisonClass(current = "", preview = "") {
  if (!preview) return "warn";
  const order = compareSemver(preview, current);
  if (order < 0) return "warn";
  if (order > 0) return "ok";
  return "info";
}

function manifestComparisonClass(current = "", preview = "") {
  if (!preview) return "warn";
  if (sameNonEmpty(current, preview)) return "info";
  return "ok";
}

function statusComparisonClass(value = "", okValues = [], badValues = []) {
  const normalized = String(value || "").toLowerCase();
  if (badValues.includes(normalized)) return "bad";
  if (okValues.includes(normalized)) return "ok";
  return "warn";
}

function blockerComparisonClass(blockers = []) {
  return Array.isArray(blockers) && blockers.length ? "bad" : "ok";
}

function blockerCountLabel(blockers = []) {
  const count = Array.isArray(blockers) ? blockers.length : 0;
  return count ? `${count} blocker${count === 1 ? "" : "s"}` : "none";
}

function shortContentHash(value = "") {
  const text = String(value || "").trim();
  return text ? `sha256:${text.slice(0, 12)}` : "";
}

function sameNonEmpty(a = "", b = "") {
  const left = String(a || "").trim();
  const right = String(b || "").trim();
  return !!left && !!right && left === right;
}

function compareSemver(a = "", b = "") {
  const left = semverParts(a);
  const right = semverParts(b);
  if (!left || !right) return 0;
  for (let i = 0; i < 3; i += 1) {
    if (left[i] !== right[i]) return left[i] > right[i] ? 1 : -1;
  }
  return 0;
}

function semverParts(value = "") {
  const match = String(value || "").trim().match(/^(\d+)\.(\d+)\.(\d+)/);
  return match ? match.slice(1).map((part) => Number(part)) : null;
}

function previewComparisonTitle(cls, sameManifest, changedCount) {
  if (cls === "bad") return "Preview package is blocked.";
  if (cls === "warn") return "Preview package needs review.";
  if (sameManifest) return "Preview matches installed content.";
  return changedCount ? "Preview changes installed content." : "Preview is verified.";
}

function previewComparisonDetail(cls, currentDecision, previewDecision, sameManifest, changedCount) {
  if (cls === "bad") return previewDecision.detail || "The previewed package has blocking gates and should not be installed.";
  if (cls === "warn") return previewDecision.detail || "The previewed package has warnings that require operator review before install.";
  if (sameManifest) return "The previewed manifest hash matches the installed package; install would not change content identity.";
  if (changedCount) return `${changedCount} package field${changedCount === 1 ? "" : "s"} differ from installed content. Review the comparison before install.`;
  return currentDecision?.label ? `Installed content is ${currentDecision.label}; preview gates report ready.` : "Preview gates report ready.";
}

function safeEvidenceArtifact(value = "") {
  const text = String(value || "").trim();
  if (!text || text.startsWith("/") || /^[a-z][a-z0-9+.-]*:/i.test(text) || text.includes("..")) return "";
  return text.split(/[\\/]+/).filter(Boolean).join("/").slice(0, 240);
}

function safeSha256(value = "") {
  const text = String(value || "").trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(text) ? text : "";
}

function safeTimestamp(value = "") {
  const text = String(value || "").trim();
  if (!text) return "";
  const date = new Date(text);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString();
}

function productionEvidenceLabel(readiness) {
  if (!readiness) return "not exposed";
  const status = readiness.readinessLabel || readiness.evidenceStatus || "missing";
  const count = readiness.evidence?.length || 0;
  return readiness.productionReady ? `${status} (${count} artifacts)` : status;
}

function productionEvidenceClass(readiness) {
  if (!readiness) return "warn";
  const blockers = Array.isArray(readiness.blockers) ? readiness.blockers : [];
  if (readiness.productionReady && readiness.evidenceStatus === "passed" && blockers.length === 0) return "ok";
  return readiness.evidenceStatus === "incomplete" || (readiness.productionReady && blockers.length) ? "bad" : "warn";
}

function signatureEvidenceClass(status) {
  if (status === "verified") return "ok";
  if (status === "invalid" || status === "untrusted" || status === "unsupported") return "bad";
  return "warn";
}

function packageProvenance(pkg) {
  return (Array.isArray(pkg.provenance) ? pkg.provenance : [])
    .map((item) => ({
      name: item.name || item.url || "source",
      license: item.license || "license missing",
      url: item.url || "",
    }))
    .filter((item) => item.name || item.license || item.url);
}

function provenanceLabel(provenance) {
  const items = packageProvenance({ provenance });
  if (!items.length) return "missing";
  const labels = items.slice(0, 2).map((item) => [item.name, item.license].filter(Boolean).join(" / "));
  return labels.join("; ") + (items.length > 2 ? ` +${items.length - 2}` : "");
}

function packageDetail(pkg, fallback) {
  const parts = [];
  if (pkg.version) parts.push(`version ${pkg.version}`);
  const readiness = packageContentReadiness(pkg);
  if (readiness?.readinessLabel) parts.push(`content-readiness ${readiness.readinessLabel}`);
  if (pkg.source) parts.push(pkg.source);
  if (pkg.blockers?.length) parts.push(`${pkg.blockers.length} blocker${pkg.blockers.length === 1 ? "" : "s"}`);
  return parts.length ? parts.join(" · ") : fallback;
}

function packageStateClass(state) {
  if (state === "verified") return "ok";
  if (state === "invalid") return "bad";
  if (state === "incomplete" || state === "local-only") return "warn";
  return "info";
}

function unique(values = []) {
  const seen = new Set();
  const out = [];
  for (const value of values) {
    if (!value || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}

export function normalizeCustomFeed(raw = {}, registryFeeds = [], existing = [], editingIndex = null) {
  const feed = {
    name: String(raw.name || "").trim().toLowerCase(),
    url: String(raw.url || "").trim(),
    description: String(raw.description || "").trim(),
  };
  if (!feed.name) return { error: "Name is required." };
  if (!/^[a-z0-9]([a-z0-9_-]{0,62}[a-z0-9])?$/.test(feed.name)) return { error: "Name must be lowercase alphanumeric with optional '-' or '_'." };
  if (registryFeeds.some((f) => !f.custom && f.name === feed.name)) return { error: "Name collides with a built-in feed." };
  if (existing.some((f, index) => index !== editingIndex && f.name === feed.name)) return { error: "Name collides with another custom feed." };
  let parsed;
  try { parsed = new URL(feed.url); } catch {
    return { error: "URL must be valid HTTP(S)." };
  }
  if (!["http:", "https:"].includes(parsed.protocol) || !parsed.host) return { error: "URL must be HTTP(S)." };
  if (parsed.username || parsed.password) return { error: "URL must not include userinfo; store feed credentials outside policy." };
  if (customFeedHostBlocked(parsed.hostname)) {
    return { error: "URL must not target loopback, private, link-local, local, or metadata destinations." };
  }
  for (const key of feedURLQueryKeys(parsed.search)) {
    if (sensitiveFeedURLQueryKey(key)) {
      return { error: `URL must not include sensitive query parameter "${key}"; store feed credentials outside policy.` };
    }
  }
  return { feed };
}

function feedURLQueryKeys(search = "") {
  return String(search || "")
    .replace(/^\?/, "")
    .split(/[&;]/)
    .map((part) => part.split("=")[0] || "")
    .map((key) => {
      try { return decodeURIComponent(key.replace(/\+/g, " ")); }
      catch { return key; }
    })
    .filter(Boolean);
}

function sensitiveFeedURLQueryKey(key) {
  const normalized = String(key || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  if ([
    "token",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "password",
    "passwd",
    "secret",
    "clientsecret",
    "key",
    "apikey",
    "apiaccesskey",
    "accesskey",
  ].includes(normalized)) return true;
  return normalized.includes("token") ||
    normalized.includes("password") ||
    normalized.includes("secret") ||
    normalized.includes("apikey") ||
    normalized.includes("accesskey");
}

function customFeedHostBlocked(hostname) {
  const host = String(hostname || "").trim().toLowerCase().replace(/^\[/, "").replace(/\]$/, "").replace(/\.$/, "");
  if (!host) return true;
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return true;
  if (["metadata", "metadata.google.internal", "metadata.oraclecloud.com"].includes(host)) return true;
  if (host.includes("%")) return true;
  const v4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const parts = v4.slice(1).map((part) => Number(part));
    if (parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
    const [a, b] = parts;
    return a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      a >= 224;
  }
  if (host.includes(":")) {
    return host === "::" ||
      host === "::1" ||
      host.startsWith("fe80:") ||
      host.startsWith("fc") ||
      host.startsWith("fd") ||
      host.startsWith("ff");
  }
  return false;
}

export function upsertCustomFeed(policy, feed, index = null) {
  policy.intel ||= {};
  policy.intel.customFeeds ||= [];
  if (index != null) policy.intel.customFeeds[index] = feed;
  else policy.intel.customFeeds.push(feed);
}

export function removeCustomFeed(policy, index) {
  policy.intel ||= {};
  policy.intel.customFeeds ||= [];
  policy.intel.customFeeds.splice(index, 1);
}
