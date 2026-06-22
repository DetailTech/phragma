// support_bundle.js — support-bundle preview helpers plus a browser-side
// compatibility collector. Canonical collection is the server-side
// /v1/system/support-bundle API.

export const SUPPORT_BUNDLE_SCHEMA = "phragma.support.bundle.v1";
export const SUPPORT_BUNDLE_REDACTED = "[redacted]";
export const SUPPORT_BUNDLE_SECTION_LABELS = Object.freeze({
  status: "Runtime status",
  highAvailabilityStatus: "Active/passive HA status",
  identity: "Operator identity",
  runningPolicy: "Running policy",
  candidatePolicy: "Candidate policy",
  candidateStatus: "Candidate status",
  candidateValidation: "Candidate validation",
  runtimeReadinessPreflight: "Runtime readiness preflight",
  versions: "Version history",
  audit: "Audit log",
  auditIntegrity: "Audit integrity",
  alerts: "Threat alerts",
  flows: "Traffic flows",
  sessions: "State table",
  telemetryExportStatus: "Telemetry export status",
  feeds: "Threat-intel feeds",
  contentPackages: "Content packages",
  releaseAcceptanceStatus: "Release acceptance",
});

export function buildSupportBundle({ collectedAt = new Date().toISOString(), results = {}, browser = browserInfo() } = {}) {
  const bundle = {
    schemaVersion: SUPPORT_BUNDLE_SCHEMA,
    collectedAt,
    collector: {
      type: "browser",
      name: "webui",
      version: "",
    },
    browser,
    endpoints: {},
  };
  for (const [name, result] of Object.entries(results || {})) {
    bundle.endpoints[name] = normalizeResult(result);
  }
  bundle.summary = summarizeBundle(bundle);
  return bundle;
}

export function supportBundleFilename(now = new Date()) {
  const stamp = now.toISOString().replace(/[:.]/g, "-");
  return `phragma-support-${stamp}.json`;
}

export function supportBundlePreviewModel(bundle = {}) {
  const endpoints = bundle.endpoints || {};
  const sections = Object.entries(endpoints).map(([name, endpoint]) => supportBundleSection(name, endpoint));
  const failures = sections.filter((section) => !section.ok);
  const redactions = countRedactions(bundle);
  const summary = bundle.summary || {};
  return {
    collectedAt: bundle.collectedAt || "",
    sections,
    failures,
    totals: {
      sections: sections.length,
      included: sections.length - failures.length,
      failed: failures.length,
      redactions,
      contentPackageBlockers: Number(summary.contentPackageBlockers || 0),
    },
    failure: {
      title: failures.length ? `${failures.length} section${failures.length === 1 ? "" : "s"} failed collection.` : "All requested sections collected.",
      detail: failures.length
        ? failures.map((section) => `${section.label}: ${section.detail}`).join("; ")
        : "The previewed payload includes every requested runtime, policy, audit, telemetry, feed, and package section.",
    },
    redaction: {
      title: redactions ? `${redactions} redaction marker${redactions === 1 ? "" : "s"} in payload.` : "No sensitive values detected by the browser redactor.",
      detail: redactions
        ? "Sensitive keys, local appliance paths, bearer tokens, URL credentials, and secret query parameters are replaced before download."
        : "The same redaction pass is still applied before the JSON is made available for export.",
    },
  };
}

export function supportBundlePreviewReport(bundle = {}) {
  const preview = supportBundlePreviewModel(bundle);
  const summary = bundle.summary || {};
  const telemetry = telemetryExportSummary(summary, bundle.endpoints?.telemetryExportStatus?.data);
  const runtimeReadiness = runtimeReadinessPreflightSummary(bundle.endpoints?.runtimeReadinessPreflight?.data);
  const collector = bundle.collector || {};
  const lines = [
    "OpenNGFW support bundle preview",
    `schema=${reportValue(bundle.schemaVersion || SUPPORT_BUNDLE_SCHEMA)}`,
    `collected_at=${reportValue(bundle.collectedAt || "")}`,
    `collector=${reportValue([collector.type || "browser", collector.name || "webui"].filter(Boolean).join("/"))}`,
    `sections=included:${preview.totals.included} failed:${preview.totals.failed} total:${preview.totals.sections}`,
    `redactions=${preview.totals.redactions}`,
    `content_package_blockers=${preview.totals.contentPackageBlockers}`,
    "",
    `runtime=${reportValue(summary.runtimeVersion || "unknown")} dataplane=${reportValue(summary.activeDataplane || "unknown")} running_policy=${reportValue(summary.runningPolicyVersion || "unknown")}`,
    `candidate=validation:${reportValue(summary.candidateValidation || "unknown")} dirty:${summary.candidateDirty === true ? "true" : "false"} changes:${Number(summary.candidateChangeCount || 0)} impact:${reportValue(summary.candidateImpact || "none")}`,
    `runtime_readiness=operation:${reportValue(runtimeReadiness.operation || "commit")} label:${reportValue(runtimeReadiness.label || "unknown")} requires_ack:${runtimeReadiness.requiresAck ? "true" : "false"} items:${Number(runtimeReadiness.itemCount || 0)}`,
    `traffic=flows:${Number(summary.flowCount || 0)} sessions:${Number(summary.sessionCount || 0)} alerts:${Number(summary.alertCount || 0)} feeds:${Number(summary.feedCount || 0)}`,
    `telemetry_export=state:${reportValue(telemetry.state || "unknown")} enabled:${telemetry.enabled === true ? "true" : "false"} vector:${reportValue(telemetry.vectorState || "unknown")} sinks:${Number(telemetry.sinkCount || 0)} observed:${Number(telemetry.observedSinkCount || 0)} clickhouse:${reportValue(telemetry.clickhouseEvidence || "unknown")} warnings:${Number(telemetry.warningCount || 0)}`,
    `content=packages:${Number(summary.contentPackageCount || 0)} verified:${Number(summary.verifiedContentPackages || 0)} blockers:${Number(summary.contentPackageBlockers || 0)}`,
    `release_acceptance=state:${reportValue(summary.releaseAcceptanceState || "unknown")} ready:${summary.releaseAcceptanceReady === true ? "true" : "false"} manifest:${summary.releaseAcceptanceManifestPresent === true ? "present" : "missing"} missing:${Number(summary.releaseAcceptanceMissing || 0)} invalid:${Number(summary.releaseAcceptanceInvalid || 0)} not_applicable:${Number(summary.releaseAcceptanceNotApplicable || 0)} next_actions:${Number(summary.releaseAcceptanceNextActions || 0)} next_commands:${Number(summary.releaseAcceptanceNextCommands || 0)}`,
    `recordability=ready:${summary.releaseAcceptanceRecordabilityReady === true ? "true" : "false"} problems:${Number(summary.releaseAcceptanceRecordabilityProblems || 0)} dirty_source_paths:${Number(summary.releaseAcceptanceDirtySourcePaths || 0) + Number(summary.releaseAcceptanceTruncatedDirtySourceCount || 0)}`,
    `audit=integrity:${reportValue(summary.auditIntegrity || "unknown")} entries:${Number(summary.auditEntryCount || 0)} latest_hash:${reportValue(summary.latestAuditHash || "")}`,
    `warnings=critical:${Number(summary.criticalWarnings || 0)} warning:${Number(summary.warnings || 0)} blocked_engines:${Number(summary.blockedEngines || 0)}`,
  ];
  if (Array.isArray(summary.failedEndpoints) && summary.failedEndpoints.length) {
    lines.push(`failed_endpoints=${summary.failedEndpoints.map(reportValue).join(", ")}`);
  } else {
    lines.push("failed_endpoints=none");
  }
  lines.push("");
  lines.push("sections:");
  for (const section of preview.sections) {
    const redactions = section.redactions ? ` redactions:${Number(section.redactions || 0)}` : "";
    lines.push(`- ${reportValue(section.label || section.name || "Section")}: ${section.ok ? "included" : "failed"} - ${reportValue(section.detail || "no detail")}${redactions}`);
  }
  lines.push("");
  lines.push("notes:");
  lines.push(`- ${reportValue(preview.failure.title)} ${reportValue(preview.failure.detail)}`);
  lines.push(`- ${reportValue(preview.redaction.title)} ${reportValue(preview.redaction.detail)}`);
  lines.push("- Preview export does not create evidence, assemble release acceptance, stage policy, commit policy, or mark external field gates clear.");
  return lines.join("\n").trimEnd() + "\n";
}

function normalizeResult(result) {
  if (result?.status === "fulfilled") {
    return { ok: true, data: redactSensitive(result.value || {}) };
  }
  if (result?.status === "rejected") {
    return { ok: false, error: errorMessage(result.reason) };
  }
  return { ok: true, data: redactSensitive(result || {}) };
}

function supportBundleSection(name, endpoint = {}) {
  const label = SUPPORT_BUNDLE_SECTION_LABELS[name] || titleizeName(name);
  const redactions = countRedactions(endpoint);
  if (!endpoint.ok) {
    return {
      name,
      label,
      ok: false,
      state: "failed",
      tone: "bad",
      detail: endpoint.error || "collection failed",
      redactions,
    };
  }
  return {
    name,
    label,
    ok: true,
    state: "included",
    tone: redactions ? "warn" : "ok",
    detail: sectionDetail(name, endpoint.data || {}),
    redactions,
  };
}

function sectionDetail(name, data) {
  if (name === "status") {
    const dataplane = data.dataplane?.activeDataplane || data.runtime?.activeDataplane || "unknown dataplane";
    return `${data.runtime?.version || "unknown version"} · ${dataplane}`;
  }
  if (name === "highAvailabilityStatus") {
    const ha = data.status || {};
    const sync = ha.sync || {};
    const failover = ha.failover || {};
    const state = [ha.state || "unknown", ha.mode || "", ha.role || ""].filter(Boolean).join(" · ");
    return `${state} · sync ${sync.state || "unknown"} · failover ${failover.eligible ? "eligible" : failover.state || "blocked"}`;
  }
  if (name === "identity") return [data.name || "local", data.role || data.authSource || ""].filter(Boolean).join(" · ") || "identity metadata";
  if (name === "runningPolicy") return data.version ? `policy v${data.version}` : "no running policy returned";
  if (name === "candidatePolicy") return data.policy ? "candidate policy included" : "no candidate policy set";
  if (name === "candidateStatus") return candidateStatusDetail(data);
  if (name === "candidateValidation") return data.valid == null ? "no candidate validation set" : data.valid ? "candidate valid" : "candidate invalid";
  if (name === "runtimeReadinessPreflight") {
    const summary = runtimeReadinessPreflightSummary(data);
    return `${summary.label || "unknown"} · ack ${summary.requiresAck ? "required" : "not required"} · ${summary.itemCount} item${summary.itemCount === 1 ? "" : "s"}`;
  }
  if (name === "auditIntegrity") return data.ok == null ? "integrity unknown" : data.ok ? `${Number(data.entryCount || 0)} entries verified` : "integrity check failed";
  if (name === "telemetryExportStatus") {
    const summary = telemetryExportSummary({}, data);
    return `${summary.state || "unknown"} · vector ${summary.vectorState || "unknown"} · sinks ${summary.sinkCount} · observed ${summary.observedSinkCount} · ClickHouse ${summary.clickhouseEvidence || "unknown"}`;
  }
  if (name === "releaseAcceptanceStatus") {
    const summary = releaseAcceptanceSummary(data.summary || {});
    const next = releaseAcceptanceNextStepSummary(data);
    const recordability = releaseAcceptanceRecordabilitySummary(data.recordability);
    return `${data.state || "unknown"} · missing ${summary.missing} · invalid ${summary.invalid} · not_applicable ${summary.notApplicable} · next actions ${next.actions} · next commands ${next.commands}${releaseAcceptanceRecordabilityDetail(recordability)}`;
  }
  const count = sectionRecordCount(name, data);
  if (count != null) return `${count} ${sectionRecordName(name, count)}`;
  const keys = data && typeof data === "object" ? Object.keys(data).length : 0;
  return keys ? `${keys} field${keys === 1 ? "" : "s"}` : "empty section";
}

function sectionRecordCount(name, data) {
  const key = ({
    versions: "versions",
    audit: "entries",
    alerts: "alerts",
    flows: "flows",
    sessions: "sessions",
    feeds: "feeds",
    contentPackages: "packages",
  })[name];
  if (!key) return null;
  return asArray(data?.[key]).length;
}

function sectionRecordName(name, count) {
  const singular = ({
    versions: "version",
    audit: "audit entry",
    alerts: "alert",
    flows: "flow",
    sessions: "session",
    feeds: "feed",
    contentPackages: "package",
  })[name] || "record";
  return singular + (count === 1 ? "" : "s");
}

function countRedactions(value) {
  if (typeof value === "string") return (value.match(/\[redacted\]/g) || []).length;
  if (Array.isArray(value)) return value.reduce((sum, item) => sum + countRedactions(item), 0);
  if (value && typeof value === "object") {
    return Object.values(value).reduce((sum, item) => sum + countRedactions(item), 0);
  }
  return 0;
}

function titleizeName(name) {
  return String(name || "section")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[-_]+/g, " ")
    .replace(/\b\w/g, (m) => m.toUpperCase());
}

export function redactSensitive(value) {
  if (Array.isArray(value)) return value.map((item) => redactSensitive(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [
      key,
      sensitiveDetailListKey(key)
        ? redactSensitiveDetailList(item)
        : sensitiveCommandKey(key) ? redactSensitiveCommandValue(item)
        : sensitiveKey(key) ? SUPPORT_BUNDLE_REDACTED : redactSensitive(item),
    ]));
  }
  if (typeof value === "string") return redactSensitiveString(value);
  return value;
}

function summarizeBundle(bundle) {
  const status = bundle.endpoints.status?.data || {};
  const runningEndpoint = bundle.endpoints.runningPolicy || {};
  const running = runningEndpoint.data || {};
  const candidateStatus = bundle.endpoints.candidateStatus?.data || {};
  const candidateValidation = bundle.endpoints.candidateValidation || {};
  const validationData = candidateValidation.data || {};
  const alerts = asArray(bundle.endpoints.alerts?.data?.alerts);
  const flows = asArray(bundle.endpoints.flows?.data?.flows);
  const sessionsData = bundle.endpoints.sessions?.data || {};
  const sessions = asArray(sessionsData.sessions);
  const feeds = asArray(bundle.endpoints.feeds?.data?.feeds);
  const contentPackages = asArray(bundle.endpoints.contentPackages?.data?.packages);
  const releaseAcceptance = bundle.endpoints.releaseAcceptanceStatus?.data || {};
  const releaseAcceptanceSummary = releaseAcceptanceSummaryFromEndpoint(releaseAcceptance);
  const releaseAcceptanceNextSteps = releaseAcceptanceNextStepSummary(releaseAcceptance);
  const releaseAcceptanceRecordability = releaseAcceptanceRecordabilitySummary(releaseAcceptance.recordability);
  const telemetryExport = telemetryExportSummary({}, bundle.endpoints.telemetryExportStatus?.data || {});
  const auditIntegrity = bundle.endpoints.auditIntegrity || {};
  const auditIntegrityData = auditIntegrity.data || {};
  const conntrack = status.dataplane?.conntrack || {};
  const warnings = status.warnings || [];
  const criticalWarnings = warnings.filter((w) => w.severity === "critical").length;
  const warningWarnings = warnings.filter((w) => w.severity === "warning").length;
  const engines = status.engines || [];
  const blockedEngines = engines.filter((e) => e.state === "missing-prerequisites" || e.state === "failed").length;
  const failedEndpoints = Object.entries(bundle.endpoints)
    .filter(([, value]) => !value.ok)
    .map(([name]) => name)
    .sort();
  return {
    runtimeVersion: status.runtime?.version || "",
    runningPolicyVersion: runningPolicyVersion(runningEndpoint, running),
    activeDataplane: status.dataplane?.activeDataplane || status.runtime?.activeDataplane || "",
    conntrackState: conntrack.state || "",
    conntrackUsagePercent: Number(conntrack.usagePercent || 0),
    conntrackEntries: Number(conntrack.currentEntries || 0),
    conntrackMaxEntries: Number(conntrack.maxEntries || 0),
    candidateValidation: candidateValidationState(candidateValidation, validationData),
    candidateImpact: impactLabel(validationData.impact?.risk),
    candidateHasCandidate: boolField(candidateStatus, "hasCandidate", "has_candidate"),
    candidateDirty: boolField(candidateStatus, "dirty"),
    candidateRunningVersion: Number(candidateStatus.runningVersion ?? candidateStatus.running_version ?? 0),
    candidateChangeCount: Number(candidateStatus.changeCount ?? candidateStatus.change_count ?? 0),
    sessionState: sessionsData.state || "",
    sessionCount: sessions.length,
    alertCount: alerts.length,
    flowCount: flows.length,
    feedCount: feeds.length,
    enabledFeeds: feeds.filter((f) => f.enabled).length,
    telemetryExportState: telemetryExport.state,
    telemetryExportEnabled: telemetryExport.enabled,
    telemetryExportVectorState: telemetryExport.vectorState,
    telemetryExportSinkCount: telemetryExport.sinkCount,
    telemetryExportObservedSinkCount: telemetryExport.observedSinkCount,
    telemetryExportClickHouseEvidence: telemetryExport.clickhouseEvidence,
    telemetryExportWarnings: telemetryExport.warningCount,
    contentPackageCount: contentPackages.length,
    verifiedContentPackages: contentPackages.filter((pkg) => pkg.state === "verified").length,
    contentPackageBlockers: contentPackages.reduce((sum, pkg) => sum + asArray(pkg.blockers).length, 0),
    releaseAcceptanceState: releaseAcceptance.state || "",
    releaseAcceptanceReady: releaseAcceptance.ready === true,
    releaseAcceptanceManifestPresent: releaseAcceptance.manifestPresent === true || releaseAcceptance.manifest_present === true,
    releaseAcceptanceMissing: releaseAcceptanceSummary.missing,
    releaseAcceptanceInvalid: releaseAcceptanceSummary.invalid,
    releaseAcceptanceNotApplicable: releaseAcceptanceSummary.notApplicable,
    releaseAcceptanceTodo: releaseAcceptanceSummary.todo,
    releaseAcceptanceProblems: asArray(releaseAcceptance.problems).length,
    releaseAcceptanceNextActions: releaseAcceptanceNextSteps.actions,
    releaseAcceptanceNextCommands: releaseAcceptanceNextSteps.commands,
    releaseAcceptanceRecordabilityReady: releaseAcceptanceRecordability.ready,
    releaseAcceptanceRecordabilityProblems: releaseAcceptanceRecordability.problems,
    releaseAcceptanceDirtySourcePaths: releaseAcceptanceRecordability.dirtySourcePaths,
    releaseAcceptanceTruncatedDirtySourceCount: releaseAcceptanceRecordability.truncatedDirtySourceCount,
    auditIntegrity: auditIntegrityState(auditIntegrity, auditIntegrityData),
    auditEntryCount: Number(auditIntegrityData.entryCount || 0),
    latestAuditHash: auditIntegrityData.latestEntryHash || "",
    criticalWarnings,
    warnings: warningWarnings,
    blockedEngines,
    failedEndpoints,
  };
}

function telemetryExportSummary(summary = {}, endpoint = {}) {
  const exports = asArray(endpoint?.exports);
  const clickhouse = endpoint?.clickhouse || {};
  const warningCount = asArray(endpoint?.warnings).length;
  const sinkCount = summary.telemetryExportSinkCount ?? exports.length;
  const observedSinkCount = summary.telemetryExportObservedSinkCount ?? exports.filter((item) => item?.evidenceState === "receiving").length;
  const state = summary.telemetryExportState || endpoint?.state || "";
  const vectorState = summary.telemetryExportVectorState || endpoint?.vector?.state || "";
  const clickhouseEvidence = summary.telemetryExportClickHouseEvidence || clickhouse.evidenceState || (clickhouse.configured ? "configured" : "");
  return {
    state,
    enabled: typeof summary.telemetryExportEnabled === "boolean" ? summary.telemetryExportEnabled : endpoint?.telemetryEnabled === true,
    vectorState,
    sinkCount: Number(sinkCount || 0),
    observedSinkCount: Number(observedSinkCount || 0),
    clickhouseEvidence,
    warningCount: Number(summary.telemetryExportWarnings ?? warningCount ?? 0),
  };
}

function runtimeReadinessPreflightSummary(endpoint = {}) {
  const items = asArray(endpoint?.items);
  return {
    operation: endpoint?.operation || "commit",
    label: endpoint?.label || "",
    requiresAck: endpoint?.requiresAck === true || endpoint?.requires_ack === true,
    itemCount: items.length,
  };
}

function releaseAcceptanceSummaryFromEndpoint(data = {}) {
  if (!data || typeof data !== "object") return { missing: 0, invalid: 0, notApplicable: 0, todo: 0 };
  return releaseAcceptanceSummary(data.summary || {});
}

function releaseAcceptanceSummary(summary = {}) {
  return {
    missing: Number(summary.missing || 0),
    invalid: Number(summary.invalid || 0),
    notApplicable: Number(summary.notApplicable ?? summary.not_applicable ?? 0),
    todo: Number(summary.todo || 0),
  };
}

function releaseAcceptanceNextStepSummary(data = {}) {
  const checks = asArray(data?.checks);
  return checks.reduce((out, check) => {
    if (hasText(check?.nextAction ?? check?.next_action)) out.actions += 1;
    if (hasReleaseAcceptanceNextCommand(check)) out.commands += 1;
    return out;
  }, { actions: 0, commands: 0 });
}

function releaseAcceptanceRecordabilitySummary(recordability = null) {
  if (!recordability || typeof recordability !== "object") {
    return { present: false, ready: false, problems: 0, dirtySourcePaths: 0, truncatedDirtySourceCount: 0 };
  }
  const truncated = Number(recordability.truncatedDirtySourceCount ?? recordability.truncated_dirty_source_count ?? 0);
  return {
    present: true,
    ready: recordability.ready === true,
    problems: asArray(recordability.problems).length,
    dirtySourcePaths: asArray(recordability.dirtySourcePaths ?? recordability.dirty_source_paths).length,
    truncatedDirtySourceCount: Number.isFinite(truncated) && truncated > 0 ? truncated : 0,
  };
}

function releaseAcceptanceRecordabilityDetail(recordability) {
  if (!recordability?.present) return "";
  const state = recordability.ready ? "ready" : "blocked";
  const totalDirty = recordability.dirtySourcePaths + recordability.truncatedDirtySourceCount;
  const dirty = totalDirty ? ` (${totalDirty} dirty source path${totalDirty === 1 ? "" : "s"})` : "";
  return ` · recordability ${state}${dirty}`;
}

function hasReleaseAcceptanceNextCommand(check = {}) {
  const value = check?.nextCommand ?? check?.next_command;
  if (Array.isArray(value)) return value.some(hasText);
  return hasText(value);
}

function hasText(value) {
  return String(value ?? "").trim().length > 0;
}

function auditIntegrityState(endpoint, data) {
  if (endpoint.ok === false) return "unavailable";
  if (!data || Object.keys(data).length === 0) return "unknown";
  return data.ok ? "verified" : "failed";
}

function candidateStatusDetail(data = {}) {
  if (!data || Object.keys(data).length === 0) return "candidate status unavailable";
  const hasCandidate = boolField(data, "hasCandidate", "has_candidate");
  const dirty = boolField(data, "dirty");
  const changeCount = Number(data.changeCount ?? data.change_count ?? 0);
  const runningVersion = Number(data.runningVersion ?? data.running_version ?? 0);
  if (!hasCandidate) return runningVersion ? `no staged candidate · running v${runningVersion}` : "no staged candidate";
  return `${dirty ? "dirty" : "clean"} candidate · ${changeCount} change${changeCount === 1 ? "" : "s"}${runningVersion ? ` · running v${runningVersion}` : ""}`;
}

function boolField(data, ...keys) {
  for (const key of keys) {
    if (typeof data?.[key] === "boolean") return data[key];
  }
  return false;
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function browserInfo() {
  if (typeof navigator === "undefined") return {};
  return {
    userAgent: navigator.userAgent || "",
    language: navigator.language || "",
    platform: navigator.platform || "",
  };
}

function errorMessage(err) {
  if (!err) return "unknown error";
  if (err.message) return redactSensitiveString(err.message);
  return redactSensitiveString(String(err));
}

function sensitiveDetailListKey(key) {
  const normalized = normalizeSensitiveKey(key);
  return ["alloweddirtypaths", "dirtysourcepaths"].includes(normalized);
}

function sensitiveCommandKey(key) {
  const normalized = normalizeSensitiveKey(key);
  return ["command", "nextcommand", "nextcommands"].includes(normalized);
}

function redactSensitiveCommandValue(value) {
  if (Array.isArray(value)) return redactSensitiveCommandList(value);
  return redactSensitive(value);
}

function redactSensitiveCommandList(items) {
  const out = [];
  let redactNext = false;
  for (const item of items) {
    if (typeof item !== "string") {
      out.push(redactSensitive(item));
      redactNext = false;
      continue;
    }
    const redacted = redactSensitiveCommandArg(item, redactNext);
    out.push(redacted.value);
    redactNext = redacted.redactNext;
  }
  return out;
}

function redactSensitiveCommandArg(arg, forceRedact = false) {
  if (forceRedact) return { value: SUPPORT_BUNDLE_REDACTED, redactNext: false };
  const value = String(arg);
  const flag = value.match(/^(-{1,2})([A-Za-z0-9][A-Za-z0-9_-]*)(?:=(.*))?$/);
  if (!flag) return { value: redactSensitiveString(value), redactNext: false };
  const [, prefix, name, assigned] = flag;
  if (sensitiveKey(name) || sensitivePathFlag(name)) {
    if (assigned !== undefined) return { value: `${prefix}${name}=${SUPPORT_BUNDLE_REDACTED}`, redactNext: false };
    return { value, redactNext: true };
  }
  return { value: redactSensitiveString(value), redactNext: false };
}

function sensitivePathFlag(name) {
  const normalized = normalizeSensitiveKey(name);
  return [
    "artifact",
    "artifactpath",
    "bundle",
    "bundlepath",
    "evidence",
    "evidencedir",
    "evidencepath",
    "file",
    "manifest",
    "manifestpath",
    "output",
    "outputdir",
    "outputpath",
    "path",
    "source",
    "sourcepath",
  ].includes(normalized);
}

function redactSensitiveDetailList(value) {
  if (Array.isArray(value)) {
    return value.map((item) => typeof item === "string" ? SUPPORT_BUNDLE_REDACTED : redactSensitive(item));
  }
  if (typeof value === "string") return SUPPORT_BUNDLE_REDACTED;
  return redactSensitive(value);
}

function sensitiveKey(key) {
  const normalized = normalizeSensitiveKey(key);
  if (!normalized) return false;
  if ([
    "authorization",
    "proxyauthorization",
    "cookie",
    "setcookie",
    "token",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "sessiontoken",
    "key",
    "apikey",
    "apiaccesskey",
    "accesskey",
    "clientsecret",
    "password",
    "passwd",
    "credential",
    "psk",
    "pskfile",
    "privatekey",
    "privatekeyfile",
    "datadir",
    "evidencedir",
    "evidencepath",
    "artifactpath",
    "bundlepath",
    "logdir",
    "outputpath",
    "sysctlconfigpath",
    "manifestpath",
    "rollbackpath",
    "restoredrollbackpath",
    "sourcepath",
  ].includes(normalized)) return true;
  return normalized.includes("token") ||
    normalized.includes("password") ||
    normalized.includes("secret") ||
    normalized.includes("credential") ||
    normalized.includes("privatekey") ||
    normalized.includes("apikey") ||
    normalized.includes("clientsecret") ||
    normalized.includes("pskfile") ||
    normalized.includes("secretfile");
}

function normalizeSensitiveKey(key) {
  return String(key || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

function redactSensitiveString(value) {
  return redactSensitiveURLs(String(value))
    .replace(/(authorization\s*:\s*bearer\s+)[^\s"',;]+/gi, `$1${SUPPORT_BUNDLE_REDACTED}`)
    .replace(/(bearer\s+)[A-Za-z0-9._~+/=-]+/gi, `$1${SUPPORT_BUNDLE_REDACTED}`)
    .replace(/(^|[?&\s"',;])((?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|passwd|secret|client[_-]?secret|api[_-]?key|api[_-]?access[_-]?key|access[_-]?key|key|cookie)=)[^&\s"',;]+/gi, `$1$2${SUPPORT_BUNDLE_REDACTED}`)
    .replace(/(^|[\s"',;{])((?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|passwd|secret|client[_-]?secret|api[_-]?key|api[_-]?access[_-]?key|access[_-]?key|key|cookie)\s*:\s*)[^\s"',;]+/gi, `$1$2${SUPPORT_BUNDLE_REDACTED}`)
    .replace(/(^|[\s"',;{])(["']?(?:artifact[_-]?path|bundle[_-]?path|data[_-]?dir|evidence[_-]?(?:dir|path)?|log[_-]?dir|output[_-]?(?:dir|path)?|sysctl[_-]?config[_-]?path|manifest[_-]?path|rollback[_-]?path|restored[_-]?rollback[_-]?path|source[_-]?path|source)["']?\s*[:=]\s*["']?)(\/(?:var\/lib|var\/log(?:\/openngfw)?|etc\/(?:openngfw|phragma)|opt\/(?:openngfw|phragma)|data|tmp|private\/tmp|var\/folders|private\/var\/folders|home\/[^'"\s,;}]+|Users\/[^'"\s,;}]+)[^'"\s,;}]+)/gi, `$1$2${SUPPORT_BUNDLE_REDACTED}`)
    .replace(/(^|[\s"'({=,;])(\/(?:var\/lib|var\/log(?:\/openngfw)?|etc\/(?:openngfw|phragma)|opt\/(?:openngfw|phragma)|data|tmp|private\/tmp|var\/folders|private\/var\/folders|home\/[^'"\s,;}]+|Users\/[^'"\s,;}]+)[^'"\s,;}]+)/gi, `$1${SUPPORT_BUNDLE_REDACTED}`);
}

function redactSensitiveURLs(value) {
  return value.replace(/https?:\/\/[^\s"'<>]+/gi, (raw) => redactSensitiveURL(raw));
}

function redactSensitiveURL(raw) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return raw;
  }
  if (!["http:", "https:"].includes(parsed.protocol) || !parsed.host) return raw;
  let out = raw;
  if (parsed.username || parsed.password) {
    out = out.replace(/^(https?:\/\/)[^/?#\s"'<>@]*@/i, `$1${SUPPORT_BUNDLE_REDACTED}@`);
  }
  const queryStart = out.indexOf("?");
  if (queryStart === -1) return out;
  const fragmentStart = out.indexOf("#", queryStart);
  const queryEnd = fragmentStart === -1 ? out.length : fragmentStart;
  const beforeQuery = out.slice(0, queryStart + 1);
  const query = out.slice(queryStart + 1, queryEnd);
  const fragment = out.slice(queryEnd);
  return beforeQuery + redactSensitiveRawQuery(query) + fragment;
}

function redactSensitiveRawQuery(raw) {
  if (!raw) return raw;
  return raw.split(/([&;])/).map((part, index) => {
    if (index % 2 === 1) return part;
    return redactSensitiveRawQueryPart(part);
  }).join("");
}

function redactSensitiveRawQueryPart(part) {
  const eq = part.indexOf("=");
  const name = eq === -1 ? part : part.slice(0, eq);
  let decodedName = name;
  try {
    decodedName = decodeURIComponent(name.replace(/\+/g, " "));
  } catch {
    decodedName = name;
  }
  if (!sensitiveKey(decodedName)) return part;
  return `${name}=${SUPPORT_BUNDLE_REDACTED}`;
}

function reportValue(value) {
  return redactSensitiveString(String(value ?? "").replace(/\s+/g, " ").trim());
}

function candidateValidationState(endpoint, data) {
  if (!endpoint.ok) return "unavailable";
  if (!data || Object.keys(data).length === 0) return "not-set";
  return data.valid ? "valid" : "invalid";
}

function runningPolicyVersion(endpoint, data) {
  if (endpoint && endpoint.ok === false) return "unavailable";
  if (!data || !data.version) return "none";
  return String(data.version);
}

function impactLabel(risk) {
  if (risk === 3 || risk === "CHANGE_RISK_HIGH") return "high";
  if (risk === 2 || risk === "CHANGE_RISK_MEDIUM") return "medium";
  if (risk === 1 || risk === "CHANGE_RISK_LOW") return "low";
  return "";
}
