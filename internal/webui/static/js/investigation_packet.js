// investigation_packet.js — bounded, browser-independent handoff packets for
// the selected evidence an operator is already reviewing in the WebUI.

import { captureIntegrityStatus } from "./packet_capture.js";

export const INVESTIGATION_PACKET_SCHEMA = "phragma.investigation.handoff.v1";

export const INVESTIGATION_PACKET_LIMITS = Object.freeze({
  maxDepth: 7,
  maxArrayItems: 40,
  maxEvidenceItems: 30,
  maxObjectKeys: 80,
  maxStringChars: 1600,
  maxTextChars: 24000,
});

export function flowHandoffPacket(flow = {}, options = {}) {
  const totalBytes = num(flow.bytesToServer) + num(flow.bytesToClient);
  return buildInvestigationPacket({
    kind: "flow",
    title: "Flow investigation handoff",
    subject: {
      id: flow.flowId || "",
      label: tupleLabel(flow),
      tuple: tuple(flow),
    },
    summary: {
      appId: flow.appId || "",
      appName: flow.appName || "",
      appCategory: flow.appCategory || "",
      appConfidence: num(flow.appConfidence),
      engineSignal: flow.appProtocol || "",
      protocol: protocolLabel(flow.protocol),
      eventPolicy: eventPolicyLabel(flow),
      packets: num(flow.packets),
      bytesToServer: num(flow.bytesToServer),
      bytesToClient: num(flow.bytesToClient),
      totalBytes,
      lastSeen: flow.time || "",
      currentInspectionPosture: packetInspectionPosture(options),
    },
    evidence: flow.appEvidence || [],
    artifacts: { flow },
  }, options);
}

export function sessionHandoffPacket(session = {}, options = {}) {
  return buildInvestigationPacket({
    kind: "session",
    title: "Live session investigation handoff",
    subject: {
      id: options.sessionKey || "",
      label: tupleLabel(session),
      tuple: tuple(session),
      replyTuple: cleanObject({
        srcIp: session.replySrcIp || "",
        srcPort: numberOrBlank(session.replySrcPort),
        destIp: session.replyDestIp || "",
        destPort: numberOrBlank(session.replyDestPort),
      }),
    },
    summary: {
      family: session.family || "",
      protocol: protocolLabel(session.protocol),
      state: session.state || "",
      assured: Boolean(session.assured),
      packets: num(session.packets),
      bytes: num(session.bytes),
      timeoutSeconds: num(session.timeoutSeconds),
      currentInspectionPosture: packetInspectionPosture(options),
    },
    evidence: [
      "live conntrack session",
      session.raw ? `raw conntrack: ${session.raw}` : "",
    ],
    artifacts: { session },
  }, options);
}

export function alertHandoffPacket(alert = {}, options = {}) {
  const contentPackageContext = packetContentPackageContext(options.threatPackage || options.threatPackageSummary || options.contentPackage);
  return buildInvestigationPacket({
    kind: "alert",
    title: "Threat alert investigation handoff",
    subject: {
      id: alert.flowId || alert.threatId || signatureId(alert),
      label: alert.threatName || alert.signature || "Unknown threat",
      tuple: tuple(alert),
    },
    summary: {
      threatId: alert.threatId || "",
      threatName: alert.threatName || alert.signature || "",
      threatCategory: alert.threatCategory || alert.category || "",
      threatSeverity: alert.threatSeverity || severityLabel(alert.severity),
      threatConfidence: num(alert.threatConfidence),
      signatureId: signatureId(alert),
      flowId: alert.flowId || "",
      action: alert.action || "",
      protocol: protocolLabel(alert.protocol),
      eventPolicy: eventPolicyLabel(alert),
      time: alert.time || "",
      currentInspectionPosture: packetInspectionPosture(options),
      contentPackage: contentPackageContext.summary,
    },
    evidence: [
      ...(alert.threatEvidence || []),
      ...contentPackageContext.evidence,
    ],
    artifacts: {
      alert,
      contentPackage: contentPackageContext.artifact,
    },
  }, options);
}

export function auditEntryHandoffPacket(entry = {}, options = {}) {
  const integrity = options.integrity || {};
  const entryHash = entry.entryHash || entry.entry_hash || "";
  const previousHash = entry.previousHash || entry.previous_hash || "";
  const detail = redactPackageString(entry.detail || "");
  return buildInvestigationPacket({
    kind: "audit-entry",
    title: "Audit entry handoff",
    subject: {
      id: String(entry.id || entryHash || entry.time || ""),
      label: entry.action || "audit-entry",
    },
    summary: {
      id: numberOrBlank(entry.id),
      action: entry.action || "",
      actor: entry.actor || "",
      actorRole: entry.actorRole || entry.actor_role || "",
      authSource: entry.authSource || entry.auth_source || "",
      version: numberOrBlank(entry.version),
      time: entry.time || "",
      entryHash,
      previousHash,
      integrityOk: Boolean(integrity.ok),
      integrityEntryCount: num(integrity.entryCount || integrity.entry_count),
      integrityLatestHash: integrity.latestEntryHash || integrity.latest_entry_hash || "",
    },
    evidence: [
      entry.action ? `action: ${entry.action}` : "",
      entry.actor ? `actor: ${entry.actor}${entry.actorRole || entry.actor_role ? ` (${entry.actorRole || entry.actor_role})` : ""}` : "",
      entry.authSource || entry.auth_source ? `auth source: ${entry.authSource || entry.auth_source}` : "",
      entry.version ? `policy version: ${num(entry.version)}` : "",
      entryHash ? `entry hash: ${entryHash}` : "",
      previousHash ? `previous hash: ${previousHash}` : "previous hash: genesis",
      detail ? `detail: ${detail}` : "",
      integrity.detail ? `integrity: ${redactPackageString(integrity.detail)}` : "",
    ],
    artifacts: {
      auditEntry: auditEntryArtifact(entry),
      integrity: cleanObject({
        ok: Boolean(integrity.ok),
        entryCount: num(integrity.entryCount || integrity.entry_count),
        latestEntryHash: integrity.latestEntryHash || integrity.latest_entry_hash || "",
        detail: redactPackageString(integrity.detail || ""),
      }),
    },
  }, options);
}

export function auditLogHandoffPacket(entries = [], options = {}) {
  const integrity = options.integrity || {};
  const request = options.request || {};
  const rows = asArray(entries).map(auditEntryArtifact).slice(0, INVESTIGATION_PACKET_LIMITS.maxArrayItems);
  const actions = uniqueStrings(rows.map((entry) => entry.action).filter(Boolean)).slice(0, 12);
  const latest = rows[0] || {};
  return buildInvestigationPacket({
    kind: "audit-log",
    title: "Filtered audit log handoff",
    subject: {
      id: `audit-log-${rows.length}`,
      label: "Filtered audit log",
    },
    summary: {
      matchedEntries: asArray(entries).length,
      includedEntries: rows.length,
      filters: cleanObject(request),
      actions,
      latestAction: latest.action || "",
      latestEntryHash: latest.entryHash || "",
      integrityOk: Boolean(integrity.ok),
      integrityEntryCount: num(integrity.entryCount || integrity.entry_count),
      integrityLatestHash: integrity.latestEntryHash || integrity.latest_entry_hash || "",
    },
    evidence: [
      `filtered audit entries: ${asArray(entries).length}`,
      `included audit entries: ${rows.length}`,
      actions.length ? `actions: ${actions.join(", ")}` : "",
      latest.entryHash ? `latest included hash: ${latest.entryHash}` : "",
      integrity.detail ? `integrity: ${redactPackageString(integrity.detail)}` : "",
    ],
    artifacts: {
      request: cleanObject(request),
      auditEntries: rows,
      integrity: cleanObject({
        ok: Boolean(integrity.ok),
        entryCount: num(integrity.entryCount || integrity.entry_count),
        latestEntryHash: integrity.latestEntryHash || integrity.latest_entry_hash || "",
        detail: redactPackageString(integrity.detail || ""),
      }),
    },
  }, options);
}

export function governanceApprovalHandoffPacket(review = {}, options = {}) {
  const model = review.model || {};
  const validation = review.validation || {};
  const runtime = review.runtime || {};
  const impact = review.impact || {};
  const diff = review.diff || {};
  const diffPreview = asArray(diff.lines).map((line) => redactPackageString(line?.s || line?.text || "")).filter(Boolean).slice(0, 20);
  const changeSummary = asArray(review.changeSummary || model.changeSummary).map(redactPackageString).slice(0, 12);
  const riskFactors = asArray(model.riskFactors).map(redactPackageString).slice(0, 12);
  const reviewerRoles = asArray(model.reviewerRoles).map(redactPackageString).slice(0, 12);
  return buildInvestigationPacket({
    kind: "governance-approval",
    title: "Governance review packet",
    subject: {
      id: `candidate-v${numberOrBlank(review.runningVersion) || 0}`,
      label: "Changes candidate governance review",
    },
    summary: {
      approvalState: model.state || "",
      approvalLabel: model.approvalLabel || "",
      ticketRequired: Boolean(model.ticketRequired),
      reviewerRoles,
      riskFactors,
      runningVersion: numberOrBlank(review.runningVersion),
      pendingChanges: num(review.changeCount),
      validation: validation?.valid ? "passed" : review.validationError ? "error" : "failed",
      runtime: runtime.label || "",
      runtimeRequiresAck: Boolean(runtime.requiresAck),
      impact: impact.level || "",
      commitReadiness: model.commitReadiness || "",
      diffSource: diff.source || "",
      diffChanged: Boolean(diff.changed),
      custody: model.custodyNote || "Browser-local review packet only; server-side approval enforcement remains hardening work.",
    },
    evidence: [
      `pending changes: ${num(review.changeCount)}`,
      model.approvalLabel ? `approval posture: ${model.approvalLabel}` : "",
      validation?.valid ? "validation: passed" : review.validationError ? `validation error: ${redactPackageString(review.validationError)}` : "validation: failed",
      runtime.label ? `runtime: ${runtime.label}${runtime.requiresAck ? " (acknowledgement required)" : ""}` : "",
      impact.level ? `impact: ${impact.level}` : "",
      ...riskFactors.map((item) => `risk: ${item}`),
      ...reviewerRoles.map((item) => `reviewer role: ${item}`),
      ...changeSummary.map((item) => `change: ${item}`),
      model.custodyNote ? `custody boundary: ${redactPackageString(model.custodyNote)}` : "",
    ],
    artifacts: {
      candidate: cleanObject({
        runningVersion: numberOrBlank(review.runningVersion),
        pendingChanges: num(review.changeCount),
        changeSummary,
      }),
      approval: cleanObject({
        state: model.state || "",
        required: Boolean(model.required),
        label: model.approvalLabel || "",
        reviewerRoles,
        riskFactors,
        ticketRequired: Boolean(model.ticketRequired),
        custodyNote: model.custodyNote || "",
      }),
      validation: cleanObject({
        valid: Boolean(validation?.valid),
        error: redactPackageString(review.validationError || ""),
        issueCount: Array.isArray(validation?.issues) ? validation.issues.length : 0,
        warningCount: Array.isArray(validation?.warnings) ? validation.warnings.length : 0,
      }),
      runtime: cleanObject({
        label: runtime.label || "",
        tone: runtime.cls || "",
        detail: redactPackageString(runtime.detail || ""),
        requiresAck: Boolean(runtime.requiresAck),
        itemCount: Array.isArray(runtime.items) ? runtime.items.length : 0,
      }),
      impact: cleanObject({
        level: impact.level || "",
        itemCount: Array.isArray(impact.items) ? impact.items.length : 0,
        items: asArray(impact.items).map((item) => cleanObject({
          level: item?.level || "",
          title: redactPackageString(item?.title || ""),
          detail: redactPackageString(item?.detail || ""),
        })).slice(0, 20),
      }),
      diff: cleanObject({
        source: diff.source || "",
        fromLabel: redactPackageString(diff.fromLabel || ""),
        toLabel: redactPackageString(diff.toLabel || ""),
        changed: Boolean(diff.changed),
        lineCount: Array.isArray(diff.lines) ? diff.lines.length : 0,
        preview: diffPreview,
      }),
    },
  }, options);
}

export function appIdObservationHandoffPacket(observation = {}, options = {}) {
  const app = observation.suggestedApplication || {};
  return buildInvestigationPacket({
    kind: "app-id-observation",
    title: "App-ID observation handoff",
    subject: {
      id: observation.queueId || observation.sampleFlowId || observation.engineSignal || observation.appId || "",
      label: app.displayName || app.name || observation.appName || observation.appId || "App-ID observation",
      tuple: cleanObject({
        srcIp: observation.sampleSrcIp || "",
        srcPort: numberOrBlank(observation.sampleSrcPort || observation.sample_src_port),
        destIp: observation.sampleDestIp || "",
        destPort: numberOrBlank(observation.destPort),
        protocol: protocolLabel(observation.protocol),
        appId: observation.appId || "",
      }),
    },
    summary: {
      queueId: observation.queueId || "",
      reason: cleanEnum(observation.kind, "APP_ID_OBSERVATION_KIND_") || observation.kind || "",
      reviewAction: options.reviewAction || "",
      evidenceStrength: options.evidenceStrength || "",
      appId: observation.appId || "",
      appName: observation.appName || "",
      appCategory: observation.appCategory || "",
      appConfidence: num(observation.appConfidence),
      engineSignalSource: observation.engineSignalSource || "",
      engineSignal: observation.engineSignal || "",
      protocol: protocolLabel(observation.protocol),
      destPort: numberOrBlank(observation.destPort),
      sampleFlowId: observation.sampleFlowId || "",
      sampleSrcPort: numberOrBlank(observation.sampleSrcPort || observation.sample_src_port),
      appIdPackageVersion: observation.appIdPackageVersion || observation.app_id_package_version || "",
      appIdPackageManifestSha256: observation.appIdPackageManifestSha256 || observation.app_id_package_manifest_sha256 || "",
      runningPolicyVersion: numberOrBlank(observation.runningPolicyVersion),
      policyContext: observation.policyContext || "",
      count: num(observation.count),
      bytes: num(observation.bytes),
      packets: num(observation.packets),
      firstSeen: observation.firstSeen || "",
      lastSeen: observation.lastSeen || "",
      suggestedApplication: app.name || "",
      suggestedCategory: app.category || "",
      suggestedPortHints: applicationPortHints(app),
      currentInspectionPosture: packetInspectionPosture(options),
    },
    evidence: [
      observation.kind ? `reason: ${cleanEnum(observation.kind, "APP_ID_OBSERVATION_KIND_") || observation.kind}` : "",
      observation.engineSignal ? `engine signal: ${observation.engineSignalSource || "engine"}=${observation.engineSignal}` : "",
      observation.appIdPackageVersion || observation.app_id_package_version ? `app-id package version: ${observation.appIdPackageVersion || observation.app_id_package_version}` : "",
      observation.appIdPackageManifestSha256 || observation.app_id_package_manifest_sha256 ? `app-id package manifest sha256: ${observation.appIdPackageManifestSha256 || observation.app_id_package_manifest_sha256}` : "",
      observation.policyContext ? `policy context: ${observation.policyContext}` : "",
      observation.runningPolicyVersion ? `running policy version: ${num(observation.runningPolicyVersion)}` : "",
      ...asArray(observation.appEvidence).map((line) => `app evidence: ${redactPackageString(line)}`),
    ],
    artifacts: {
      observation: appIdObservationArtifact(observation),
    },
  }, options);
}

export function appIdRegressionSampleHandoffPacket(observation = {}, options = {}) {
  const app = observation.suggestedApplication || {};
  const readiness = options.readiness || options.appIdReadiness || {};
  const version = observation.appIdPackageVersion || observation.app_id_package_version || readiness.version || "";
  const manifestSha256 = observation.appIdPackageManifestSha256 || observation.app_id_package_manifest_sha256 || readiness.manifestSha256 || "";
  const blockers = uniqueStrings(readiness.blockers || []);
  const sampleId = appIdRegressionSampleId(observation, readiness);
  const captureSubject = cleanObject({
    flowId: observation.sampleFlowId || "",
    srcIp: observation.sampleSrcIp || "",
    srcPort: numberOrBlank(observation.sampleSrcPort || observation.sample_src_port),
    destIp: observation.sampleDestIp || "",
    destPort: numberOrBlank(observation.destPort),
    protocol: protocolLabel(observation.protocol),
  });
  return buildInvestigationPacket({
    kind: "app-id-regression-sample",
    title: "App-ID regression sample handoff",
    subject: {
      id: sampleId,
      label: app.displayName || app.name || observation.engineSignal || observation.appName || observation.appId || "App-ID regression sample",
      tuple: {
        ...captureSubject,
        appId: observation.appId || "",
      },
    },
    summary: {
      sampleId,
      queueId: observation.queueId || "",
      reviewAction: options.reviewAction || "",
      evidenceStrength: options.evidenceStrength || "",
      sampleFlowId: observation.sampleFlowId || "",
      captureRequirement: "bounded packet capture attached to the App-ID regression corpus",
      packageProductionReady: Boolean(readiness.productionReady),
      packageStatus: readiness.status || "",
      packageState: readiness.packageState || "",
      appIdPackageVersion: version,
      appIdPackageManifestSha256: manifestSha256,
      blockerCount: blockers.length,
      blockers,
      reason: cleanEnum(observation.kind, "APP_ID_OBSERVATION_KIND_") || observation.kind || "",
      appId: observation.appId || "",
      appConfidence: num(observation.appConfidence),
      engineSignalSource: observation.engineSignalSource || "",
      engineSignal: observation.engineSignal || "",
      protocol: protocolLabel(observation.protocol),
      destPort: numberOrBlank(observation.destPort),
      count: num(observation.count),
      bytes: num(observation.bytes),
      packets: num(observation.packets),
      firstSeen: observation.firstSeen || "",
      lastSeen: observation.lastSeen || "",
      suggestedApplication: app.name || "",
      suggestedCategory: app.category || "",
      suggestedPortHints: applicationPortHints(app),
      currentInspectionPosture: packetInspectionPosture(options),
    },
    evidence: [
      "regression sample: preserve this flow as App-ID corpus evidence",
      observation.sampleFlowId ? `sample flow id: ${observation.sampleFlowId}` : "",
      observation.engineSignal ? `engine signal: ${observation.engineSignalSource || "engine"}=${observation.engineSignal}` : "",
      version ? `app-id package version: ${version}` : "",
      manifestSha256 ? `app-id package manifest sha256: ${manifestSha256}` : "",
      readiness.productionReady ? "package readiness: production ready" : "package readiness: not production ready",
      readiness.detail ? `package readiness detail: ${redactPackageString(readiness.detail)}` : "",
      ...blockers.map((blocker) => `package blocker: ${blocker}`),
      app.name ? `suggested App-ID: ${app.name}` : "",
      applicationPortHints(app) ? `suggested port hints: ${applicationPortHints(app)}` : "",
      ...asArray(observation.appEvidence).map((line) => `app evidence: ${redactPackageString(line)}`),
    ],
    artifacts: {
      observation: appIdObservationArtifact(observation),
      appIdReadiness: appIdReadinessArtifact(readiness),
      captureSubject,
    },
  }, options);
}

export function explainHandoffPacket({ query = {}, result = {} } = {}, options = {}) {
  return buildInvestigationPacket({
    kind: "explain",
    title: "Policy explain investigation handoff",
    subject: {
      id: query.flowId || result.flowId || result.matchedRule || "",
      label: tupleLabel(query),
      tuple: tuple(query),
    },
    summary: {
      ...explainSummary(result),
      currentInspectionPosture: packetInspectionPosture(options),
    },
    evidence: explainEvidence(result),
    artifacts: { query, result },
  }, options);
}

export function captureHandoffPacket({ query = {}, result = {}, capturePlan = {}, captureJob = null } = {}, options = {}) {
  const job = captureJob || {};
  const planSource = capturePlan.source || capturePlan.planSource || "";
  const captureState = job.state || (job.id ? "started" : "planned");
  const captureSha256 = job.sha256 || job.sha256_hash || "";
  const captureArtifactId = safeCaptureArtifactId(job.artifactId || job.artifact_id || "");
  const captureFilename = safeCaptureFilename(job.filename || "");
  const integrity = captureIntegrityStatus({
    state: captureState,
    artifactId: captureArtifactId,
    filename: captureFilename,
    bytesWritten: job.bytesWritten ?? job.bytes_written,
    sha256: captureSha256,
    mediaType: job.mediaType || job.media_type || "",
  });
  const auditRoute = captureAuditRoute(captureSha256 || job.id || query.flowId || capturePlan.outputPath || "");
  const artifacts = {
    query,
    capturePlan: capturePlanArtifact(capturePlan),
    result,
  };
  if (captureJob) artifacts.captureJob = captureJobArtifact(captureJob);
  return buildInvestigationPacket({
    kind: "capture",
    title: "Packet capture investigation handoff",
    subject: {
      id: query.flowId || result.flowId || captureArtifactId || captureFilename || capturePathLeaf(capturePlan.outputPath) || "",
      label: tupleLabel(query),
      tuple: tuple(query),
    },
    summary: {
      ...explainSummary(result),
      interface: capturePlan.interface || "",
      bpfFilter: capturePlan.bpfFilter || capturePlan.filter || "",
      outputPath: redactPackageString(capturePlan.outputPath || ""),
      durationSeconds: num(capturePlan.durationSeconds),
      packetCount: num(capturePlan.packetCount),
      snaplenBytes: num(capturePlan.snaplenBytes),
      command: redactPackageString(capturePlan.command || ""),
      planSource,
      captureState,
      captureId: job.id || "",
      artifactId: captureArtifactId,
      filename: captureFilename,
      bytesWritten: num(job.bytesWritten ?? job.bytes_written),
      sha256: captureSha256,
      integrityState: integrity.state,
      integrityDetail: integrity.detail,
      auditRoute,
      exitCode: numberOrBlank(job.exitCode ?? job.exit_code),
      detail: redactPackageString(job.detail || ""),
      startedAt: job.startedAt || job.started_at || "",
      completedAt: job.completedAt || job.completed_at || "",
    },
    evidence: [
      planSource ? `capture plan source: ${planSource}` : "",
      captureState ? `capture state: ${captureState}` : "",
      job.detail ? `capture detail: ${redactPackageString(job.detail)}` : "",
      job.bytesWritten != null || job.bytes_written != null ? `capture bytes written: ${num(job.bytesWritten ?? job.bytes_written)}` : "",
      captureSha256 ? `capture sha256: ${captureSha256}` : "",
      integrity.label ? `capture integrity: ${integrity.label}${integrity.detail ? ` (${integrity.detail})` : ""}` : "",
      auditRoute ? `capture audit route: ${auditRoute}` : "",
      ...(capturePlan.warnings || []).map((line) => `capture warning: ${redactPackageString(line)}`),
      ...explainEvidence(result),
    ],
    artifacts,
  }, options);
}

function capturePlanArtifact(plan = {}) {
  return cleanObject({
    interface: plan.interface || "",
    bpfFilter: plan.bpfFilter || plan.bpf_filter || plan.filter || "",
    outputPath: redactPackageString(plan.outputPath || plan.output_path || ""),
    durationSeconds: num(plan.durationSeconds || plan.duration_seconds),
    packetCount: num(plan.packetCount || plan.packet_count),
    snaplenBytes: num(plan.snaplenBytes || plan.snaplen_bytes),
    command: redactPackageString(plan.command || ""),
    source: plan.source || plan.planSource || "",
    warnings: asArray(plan.warnings).map(redactPackageString),
  });
}

function captureJobArtifact(job = {}) {
  const sha256 = String(job.sha256 || job.sha256Hash || job.sha256_hash || "").trim().toLowerCase();
  return cleanObject({
    id: safeCaptureArtifactId(job.id || ""),
    artifactId: safeCaptureArtifactId(job.artifactId || job.artifact_id || ""),
    filename: safeCaptureFilename(job.filename || ""),
    state: job.state || "",
    detail: redactPackageString(job.detail || ""),
    exitCode: numberOrBlank(job.exitCode ?? job.exit_code),
    bytesWritten: num(job.bytesWritten ?? job.bytes_written),
    sha256: /^[a-f0-9]{64}$/.test(sha256) ? sha256 : "",
    mediaType: job.mediaType || job.media_type || "",
    startedAt: job.startedAt || job.started_at || "",
    completedAt: job.completedAt || job.completed_at || "",
  });
}

function captureAuditRoute(value = "") {
  const query = String(value || "").trim();
  const params = new URLSearchParams();
  params.set("tab", "audit");
  params.set("action", "packet-capture");
  if (query) {
    const leaf = /^[a-f0-9]{64}$/i.test(query) ? query.toLowerCase() : query.split(/[\\/]/).filter(Boolean).pop() || query;
    params.set("query", leaf);
  }
  return "#/changes?" + params.toString();
}

export function natPathHandoffPacket({ flow = {}, running = null, candidate = null, delta = null } = {}, options = {}) {
  const rows = Array.isArray(delta?.rows) ? delta.rows : [];
  const warnings = Array.isArray(delta?.warnings) ? delta.warnings : [];
  return buildInvestigationPacket({
    kind: "nat-path",
    title: "NAT path preview handoff",
    subject: {
      id: tupleLabel(flow),
      label: tupleLabel(flow),
      tuple: {
        ...tuple(flow),
        fromZone: flow.fromZone || "",
        toZone: flow.toZone || "",
      },
    },
    summary: {
      fromZone: flow.fromZone || "",
      toZone: flow.toZone || "",
      protocol: protocolLabel(flow.protocol),
      candidateChanged: Boolean(delta?.changed),
      result: delta?.headline || "",
      tone: delta?.tone || "",
      runningVerdict: explainSummary(running || {}).verdict,
      candidateVerdict: explainSummary(candidate || {}).verdict,
      runningMatchedRule: explainSummary(running || {}).matchedRule || (running?.defaultPolicy ? "default policy" : ""),
      candidateMatchedRule: explainSummary(candidate || {}).matchedRule || (candidate?.defaultPolicy ? "default policy" : ""),
      warningCount: warnings.length,
    },
    evidence: [
      ...(options.previewWarning ? [`preview note: ${options.previewWarning}`] : []),
      ...rows.map((row) => `delta ${row.label}: running=${row.running}; candidate=${row.candidate}${row.changed ? " (changed)" : ""}`),
      ...warnings.map((line) => `warning: ${line}`),
    ],
    artifacts: { flow, running, candidate, delta },
  }, options);
}

export function vpnTunnelHandoffPacket(model = {}, options = {}) {
  const targets = asArray(model.targets).map(vpnTargetArtifact);
  const runtime = model.runtime || {};
  return buildInvestigationPacket({
    kind: "vpn-tunnel",
    title: "VPN tunnel handoff",
    subject: {
      id: model.id || `${model.kind || "vpn"}:${model.name || ""}`,
      label: model.name || model.id || "vpn tunnel",
      tuple: targets[0] ? {
        srcIp: targets[0].srcIp || "",
        destIp: targets[0].destIp || "",
        protocol: protocolLabel(targets[0].protocol || "PROTOCOL_ANY"),
      } : {},
    },
    summary: {
      kind: model.kind || "",
      tunnelType: model.kindLabel || "",
      name: model.name || "",
      interfaceName: model.interfaceName || "",
      peerName: model.peerName || "",
      localEndpoint: model.localEndpoint || "",
      remoteEndpoint: model.remoteEndpoint || "",
      localPrefixCount: asArray(model.localPrefixes).length,
      remotePrefixCount: asArray(model.remotePrefixes).length,
      mode: model.mode || "",
      runtimeState: runtime.state || "not observed",
      runtimeDetail: redactVpnSecretText(runtime.detail || ""),
      latestHandshake: runtime.latestHandshake || "",
      rxBytes: num(runtime.rxBytes),
      txBytes: num(runtime.txBytes),
      pathCount: targets.length,
      secretMaterial: "not exported; file paths and private key material are redacted",
      publicKeyState: model.publicKeyState || "",
    },
    evidence: [
      `tunnel type: ${model.kindLabel || model.kind || "vpn"}`,
      model.interfaceName ? `interface: ${model.interfaceName}` : "",
      model.peerName ? `peer: ${model.peerName}` : "",
      model.localEndpoint ? `local endpoint: ${model.localEndpoint}` : "",
      model.remoteEndpoint ? `remote endpoint: ${model.remoteEndpoint}` : "",
      ...(asArray(model.localPrefixes).map((prefix) => `local prefix: ${prefix}`)),
      ...(asArray(model.remotePrefixes).map((prefix) => `remote prefix: ${prefix}`)),
      model.secretState ? `secret material: ${redactVpnSecretText(model.secretState)}` : "secret material: not exported",
      runtime.state ? `runtime: ${runtime.state}` : "",
      runtime.detail ? `runtime detail: ${redactVpnSecretText(runtime.detail)}` : "",
      runtime.latestHandshake ? `latest handshake: ${runtime.latestHandshake}` : "",
      ...targets.slice(0, 8).map((target) => `path: ${target.localCidr || target.srcIp} -> ${target.remoteCidr || target.destIp}`),
    ],
    artifacts: {
      tunnel: vpnTunnelArtifact(model),
      targets,
    },
  }, options);
}

export function contentPackageLifecycleHandoffPacket(surface = {}, options = {}) {
  const decision = surface.decision || {};
  const checks = asArray(decision.checks).map(contentPackageCheckSummary);
  const readinessEvidence = asArray(surface.contentReadinessEvidence);
  const blockers = uniqueStrings([
    ...asArray(surface.blockers),
    ...asArray(decision.blockers),
    ...checks.filter((check) => check.cls !== "ok").map((check) => check.blocker || check.label),
  ]);
  const lifecycleAction = safeToken(options.lifecycleAction || options.action || "review") || "review";
  return buildInvestigationPacket({
    kind: "content-package-lifecycle",
    title: "Content package lifecycle handoff",
    subject: {
      id: surface.kind || "",
      label: surface.name || surface.kind || "content package",
    },
    summary: {
      lifecycleAction,
      packageKind: surface.kind || "",
      packageState: surface.badge || "",
      version: surface.version || "",
      source: redactPackageString(surface.source || ""),
      manifestSha256: surface.manifestSha256 || "",
      signatureStatus: surface.signatureStatus || "",
      regressionStatus: surface.regressionStatus || "",
      rolloutState: surface.rolloutState || "",
      rollbackAvailable: Boolean(surface.rollbackAvailable),
      decision: decision.label || "",
      decisionClass: decision.cls || "",
      blockerCount: blockers.length,
      checkCount: checks.length,
      readinessEvidenceCount: readinessEvidence.length,
      nextAction: decision.nextAction || "",
    },
    evidence: [
      `lifecycle action: ${lifecycleAction}`,
      decision.label ? `decision: ${decision.label}` : "",
      decision.detail ? `decision detail: ${decision.detail}` : "",
      decision.nextAction ? `next action: ${decision.nextAction}` : "",
      ...checks.map((check) => `check ${check.label}: ${check.status}${check.cls ? ` (${check.cls})` : ""}`),
      ...readinessEvidence.map((ref) => `readiness evidence ${ref.type || "evidence"}: ${contentEvidenceRefLabel(ref)}`),
      ...blockers.map((blocker) => `blocker: ${blocker}`),
    ],
    artifacts: {
      contentPackage: contentPackageArtifact(surface),
      decision: cleanObject({
        label: decision.label || "",
        cls: decision.cls || "",
        detail: decision.detail || "",
        nextAction: decision.nextAction || "",
        checks,
        blockers,
      }),
    },
  }, options);
}

export function buildInvestigationPacket({
  kind = "investigation",
  title = "Investigation handoff",
  subject = {},
  summary = {},
  evidence = [],
  artifacts = {},
} = {}, {
  collectedAt = new Date().toISOString(),
  route = "",
  operatorNote = "",
  custody = {},
} = {}) {
  return {
    schemaVersion: INVESTIGATION_PACKET_SCHEMA,
    kind: safeToken(kind) || "investigation",
    title: boundedString(title),
    collectedAt: timestampString(collectedAt),
    generatedBy: "openngfw-webui",
    source: cleanObject({
      interface: "webui",
      route: redactPackageString(route),
    }),
    custody: custodyEnvelope(custody),
    subject: cleanObject(subject),
    summary: cleanObject(summary),
    evidence: evidenceLines(evidence),
    operatorNote: boundedString(operatorNote),
    artifacts: cleanObject(artifacts),
  };
}

export function investigationPacketJson(packet) {
  return JSON.stringify(cleanObject(packet), null, 2) + "\n";
}

export function investigationPacketText(packet) {
  const p = cleanObject(packet || {});
  const lines = [
    "Phragma investigation handoff",
    `schema=${p.schemaVersion || INVESTIGATION_PACKET_SCHEMA}`,
    `kind=${p.kind || "investigation"}`,
    `collected_at=${p.collectedAt || ""}`,
  ];
  if (p.title) lines.push(`title=${p.title}`);
  if (p.subject?.label) lines.push(`subject=${p.subject.label}`);
  if (p.subject?.id) lines.push(`subject_id=${p.subject.id}`);
  if (p.source?.route) lines.push(`route=${p.source.route}`);
  if (p.operatorNote) lines.push(`operator_note=${p.operatorNote}`);
  if (p.custody) {
    lines.push(`custody_mode=${p.custody.mode || ""}`);
    lines.push(`packet_signed=${p.custody.packetSigned === true}`);
    lines.push(`server_retained=${p.custody.serverRetained === true}`);
    lines.push(`retention_enforced=${p.custody.retentionEnforced === true}`);
  }

  lines.push("", "[summary]");
  const summaryLines = objectLines(p.summary || {});
  lines.push(...(summaryLines.length ? summaryLines : ["none"]));

  lines.push("", "[evidence]");
  const evidence = Array.isArray(p.evidence) ? p.evidence : [];
  lines.push(...(evidence.length ? evidence.map((line) => `- ${line}`) : ["none"]));

  lines.push("", "[artifacts]");
  const artifactKeys = Object.keys(p.artifacts || {});
  lines.push(...(artifactKeys.length ? artifactKeys.map((key) => `- ${key}: included in JSON export`) : ["none"]));

  return truncateText(lines.join("\n") + "\n");
}

export function investigationPacketFilename(packetOrKind = "investigation", now = new Date()) {
  const packet = typeof packetOrKind === "object" && packetOrKind ? packetOrKind : {};
  const kind = safeSlug(typeof packetOrKind === "string" ? packetOrKind : packet.kind || "investigation");
  const subject = subjectSlug(packet);
  const stamp = timestampForFilename(now);
  return `phragma-investigation-${kind}${subject ? "-" + subject : ""}-${stamp}.json`;
}

function custodyEnvelope(custody = {}) {
  const retainedArtifact = redactPackageString(custody.retainedArtifact || custody.retained_artifact || "");
  const boundary = custody.boundary || "Browser-local unsigned handoff packet; not signed custody, legal hold, or proof of retention enforcement.";
  return cleanObject({
    mode: safeToken(custody.mode || "browser-local-unsigned") || "browser-local-unsigned",
    packetSigned: Boolean(custody.packetSigned || custody.packet_signed),
    serverRetained: Boolean(custody.serverRetained || custody.server_retained),
    retentionEnforced: Boolean(custody.retentionEnforced || custody.retention_enforced),
    redactionApplied: custody.redactionApplied === undefined ? true : Boolean(custody.redactionApplied || custody.redaction_applied),
    boundsApplied: custody.boundsApplied === undefined ? true : Boolean(custody.boundsApplied || custody.bounds_applied),
    retainedArtifact,
    retainedArtifactType: safeToken(custody.retainedArtifactType || custody.retained_artifact_type || ""),
    boundary: redactPackageString(boundary),
    hardeningRequired: uniqueStrings([
      ...(asArray(custody.hardeningRequired || custody.hardening_required)),
      "artifact signing",
      "server-side retention policy",
      "legal-hold workflow",
      "RBAC-scoped export custody",
    ]).slice(0, 12).map(redactPackageString),
  });
}

function explainSummary(result = {}) {
  return {
    decision: decisionLabel(result),
    decisionTerms: (result.decisionTerms || []).map((term) => cleanEnum(term, "EXPLAIN_DECISION_TERM_")).filter(Boolean),
    verdict: cleanEnum(result.verdict, "EXPLAIN_VERDICT_"),
    reason: result.reason || "",
    matchedRule: result.matchedRule || "",
    matchedRuleIndex: numberOrBlank(result.matchedRuleIndex),
    defaultPolicy: Boolean(result.defaultPolicy),
    policySource: cleanEnum(result.policySource, "POLICY_SOURCE_"),
    policyVersion: numberOrBlank(result.policyVersion),
    inspectionState: cleanEnum(result.inspectionState, "EXPLAIN_INSPECTION_STATE_"),
    runtimeQueried: Boolean(result.runtimeEvidence?.queried),
    runtimeState: result.runtimeEvidence?.state || "",
    routeMatched: Boolean(result.routeProfile?.matched),
  };
}

function decisionLabel(result = {}) {
  if (result.decisionSummary) return result.decisionSummary;
  const labels = (result.decisionTerms || [])
    .map((term) => cleanEnum(term, "EXPLAIN_DECISION_TERM_").replace(/\bfail open\b/g, "fail-open").replace(/\bfail closed\b/g, "fail-closed"))
    .filter(Boolean);
  return labels.join(", ");
}

function packetInspectionPosture(options = {}) {
  return options.currentInspectionPosture || options.inspectionPosture || null;
}

function explainEvidence(result = {}) {
  return [
    ...(result.evidence || []).map((line) => `evidence: ${line}`),
    ...(result.trace || []).map((line) => `trace: ${line}`),
    ...(result.warnings || []).map((line) => `warning: ${line}`),
    ...(result.runtimeEvidence?.evidence || []).map((line) => `runtime: ${line}`),
    ...(result.runtimeEvidence?.warnings || []).map((line) => `runtime warning: ${line}`),
    ...(result.inspectionProfile?.evidence || []).map((line) => `inspection: ${line}`),
    ...(result.routeProfile?.evidence || []).map((line) => `route: ${line}`),
  ];
}

function contentPackageArtifact(surface = {}) {
  return cleanObject({
    kind: surface.kind || "",
    name: surface.name || "",
    state: surface.badge || "",
    version: surface.version || "",
    source: redactServerLocalPath(surface.source || ""),
    manifestSha256: surface.manifestSha256 || "",
    signatureStatus: surface.signatureStatus || "",
    regressionStatus: surface.regressionStatus || "",
    rolloutState: surface.rolloutState || "",
    rollbackAvailable: Boolean(surface.rollbackAvailable),
    blockers: asArray(surface.blockers).map(redactPackageString),
    evidence: asArray(surface.evidence).map(redactPackageString),
    contentReadinessEvidence: asArray(surface.contentReadinessEvidence).map(contentEvidenceRefArtifact),
    fields: asArray(surface.fields).map((field) => cleanObject({
      label: field?.label || "",
      value: redactPackageString(field?.value || ""),
      cls: field?.cls || "",
    })),
    provenance: asArray(surface.provenance).map((item) => cleanObject({
      name: redactPackageString(item?.name || ""),
      license: redactPackageString(item?.license || ""),
      url: redactPackageString(item?.url || ""),
    })),
  });
}

function vpnTunnelArtifact(model = {}) {
  return cleanObject({
    kind: model.kind || "",
    kindLabel: model.kindLabel || "",
    id: model.id || "",
    name: model.name || "",
    interfaceName: model.interfaceName || "",
    peerName: model.peerName || "",
    localEndpoint: model.localEndpoint || "",
    remoteEndpoint: model.remoteEndpoint || "",
    listenPort: numberOrBlank(model.listenPort),
    localPrefixes: asArray(model.localPrefixes),
    remotePrefixes: asArray(model.remotePrefixes),
    mode: model.mode || "",
    secretState: redactVpnSecretText(model.secretState || ""),
    publicKeyState: model.publicKeyState || "",
    runtime: cleanObject({
      state: model.runtime?.state || "",
      cls: model.runtime?.cls || "",
      detail: redactVpnSecretText(model.runtime?.detail || ""),
      endpoint: model.runtime?.endpoint || "",
      latestHandshake: model.runtime?.latestHandshake || "",
      rxBytes: num(model.runtime?.rxBytes),
      txBytes: num(model.runtime?.txBytes),
    }),
  });
}

function vpnTargetArtifact(target = {}) {
  return cleanObject({
    kind: target.kind || "",
    kindLabel: target.kindLabel || "",
    name: target.name || "",
    tunnelName: target.tunnelName || "",
    ifaceName: target.ifaceName || "",
    peerName: target.peerName || "",
    localCidr: target.localCidr || "",
    remoteCidr: target.remoteCidr || "",
    srcIp: target.srcIp || "",
    destIp: target.destIp || "",
    protocol: protocolLabel(target.protocol || "PROTOCOL_ANY"),
  });
}

function packetContentPackageContext(surface = null) {
  if (!surface) return { summary: null, evidence: [], artifact: null };
  const refs = asArray(surface.contentReadinessEvidence);
  if (surface.available === false && !refs.length) return { summary: null, evidence: [], artifact: null };
  if (!surface.label && !surface.status && !surface.version && !refs.length) return { summary: null, evidence: [], artifact: null };
  const summary = cleanObject({
    kind: surface.kind || "threat-id",
    label: surface.label || "",
    status: surface.status || "",
    version: surface.version || "",
    packageState: surface.packageState || "",
    blockerCount: num(surface.blockerCount),
    readinessEvidenceCount: refs.length,
  });
  return {
    summary,
    evidence: refs.map((ref) => `package readiness ${ref.type || "evidence"}: ${contentEvidenceRefLabel(ref)}`),
    artifact: cleanObject({
      summary,
      contentReadinessEvidence: refs.map(contentEvidenceRefArtifact),
    }),
  };
}

function contentEvidenceRefArtifact(ref = {}) {
  return cleanObject({
    type: safeToken(ref.type || "evidence") || "evidence",
    artifact: redactPackageString(ref.artifact || ""),
    sha256: ref.sha256 || "",
    sha256Short: ref.sha256Short || (ref.sha256 ? String(ref.sha256).slice(0, 12) : ""),
    generatedAt: ref.generatedAt || "",
  });
}

function contentEvidenceRefLabel(ref = {}) {
  const parts = [];
  if (ref.artifact) parts.push(redactPackageString(ref.artifact));
  if (ref.sha256Short || ref.sha256) parts.push(`sha256:${ref.sha256Short || String(ref.sha256).slice(0, 12)}`);
  if (ref.generatedAt) parts.push(ref.generatedAt);
  return parts.join(" | ") || ref.type || "attached";
}

function appIdObservationArtifact(observation = {}) {
  const app = observation.suggestedApplication || {};
  return cleanObject({
    queueId: observation.queueId || "",
    kind: observation.kind || "",
    appId: observation.appId || "",
    appName: observation.appName || "",
    appCategory: observation.appCategory || "",
    appConfidence: num(observation.appConfidence),
    engineSignalSource: observation.engineSignalSource || "",
    engineSignal: observation.engineSignal || "",
    protocol: protocolLabel(observation.protocol),
    destPort: numberOrBlank(observation.destPort),
    sampleSrcIp: observation.sampleSrcIp || "",
    sampleSrcPort: numberOrBlank(observation.sampleSrcPort || observation.sample_src_port),
    sampleDestIp: observation.sampleDestIp || "",
    sampleFlowId: observation.sampleFlowId || "",
    appIdPackageVersion: observation.appIdPackageVersion || observation.app_id_package_version || "",
    appIdPackageManifestSha256: observation.appIdPackageManifestSha256 || observation.app_id_package_manifest_sha256 || "",
    runningPolicyVersion: numberOrBlank(observation.runningPolicyVersion),
    policyContext: observation.policyContext || "",
    count: num(observation.count),
    bytes: num(observation.bytes),
    packets: num(observation.packets),
    firstSeen: observation.firstSeen || "",
    lastSeen: observation.lastSeen || "",
    appEvidence: asArray(observation.appEvidence).map(redactPackageString),
    suggestedApplication: cleanObject({
      name: app.name || "",
      displayName: app.displayName || "",
      category: app.category || "",
      engineSignals: asArray(app.engineSignals).map(redactPackageString),
      ports: app.ports || [],
      description: app.description || "",
    }),
  });
}

function appIdReadinessArtifact(readiness = {}) {
  return cleanObject({
    kind: "app-id",
    productionReady: Boolean(readiness.productionReady),
    status: redactPackageString(readiness.status || ""),
    packageState: redactPackageString(readiness.packageState || ""),
    version: redactPackageString(readiness.version || ""),
    manifestSha256: readiness.manifestSha256 || "",
    blockerCount: asArray(readiness.blockers).length,
    blockers: asArray(readiness.blockers).map(redactPackageString),
    detail: redactPackageString(readiness.detail || ""),
  });
}

function appIdRegressionSampleId(observation = {}, readiness = {}) {
  return uniqueStrings([
    observation.queueId || observation.sampleFlowId || observation.engineSignal || observation.appId || "app-id-observation",
    observation.appIdPackageVersion || observation.app_id_package_version || readiness.version || "package-unversioned",
    observation.appIdPackageManifestSha256 || observation.app_id_package_manifest_sha256 || readiness.manifestSha256 || "",
  ]).join("@");
}

function auditEntryArtifact(entry = {}) {
  return cleanObject({
    id: numberOrBlank(entry.id),
    action: entry.action || "",
    detail: redactPackageString(entry.detail || ""),
    actor: entry.actor || "",
    actorRole: entry.actorRole || entry.actor_role || "",
    authSource: entry.authSource || entry.auth_source || "",
    version: numberOrBlank(entry.version),
    time: entry.time || "",
    entryHash: entry.entryHash || entry.entry_hash || "",
    previousHash: entry.previousHash || entry.previous_hash || "",
  });
}

function contentPackageCheckSummary(check = {}) {
  return cleanObject({
    key: check.key || "",
    label: check.label || "",
    status: redactPackageString(check.status || ""),
    cls: check.cls || "",
    blocker: redactPackageString(check.blocker || ""),
    action: check.action || "",
  });
}

function applicationPortHints(app = {}) {
  const hints = [];
  for (const group of asArray(app.ports)) {
    const protocol = protocolLabel(group?.protocol);
    const ports = asArray(group?.ports)
      .map((port) => {
        const start = numberOrBlank(port?.start);
        const end = numberOrBlank(port?.end);
        if (!start) return "";
        return end && end !== start ? `${start}-${end}` : String(start);
      })
      .filter(Boolean)
      .join(",");
    if (protocol && ports) hints.push(`${protocol}/${ports}`);
  }
  return hints.join(", ");
}

function tuple(source = {}) {
  return cleanObject({
    srcIp: source.srcIp || source.src || "",
    srcPort: numberOrBlank(source.srcPort || source.sport),
    destIp: source.destIp || source.dst || "",
    destPort: numberOrBlank(source.destPort || source.dport),
    protocol: protocolLabel(source.protocol),
    appId: source.appId || source.app || "",
  });
}

function tupleLabel(source = {}) {
  const t = tuple(source);
  const left = endpoint(t.srcIp, t.srcPort);
  const right = endpoint(t.destIp, t.destPort);
  if (left !== "-" || right !== "-") return `${left} -> ${right}`;
  return t.protocol || "selected evidence";
}

function endpoint(ip, port) {
  if (!ip) return "-";
  return port ? `${ip}:${port}` : String(ip);
}

function eventPolicyLabel(event = {}) {
  const version = num(event.policyVersion);
  if (event.policyVersionKnown && version > 0) return `v${version}`;
  return event.policyContext || "unknown";
}

function evidenceLines(lines) {
  return asArray(lines)
    .flatMap((line) => asArray(line).length ? asArray(line) : [line])
    .map((line) => boundedString(line).trim())
    .filter(Boolean)
    .slice(0, INVESTIGATION_PACKET_LIMITS.maxEvidenceItems);
}

function cleanObject(value, depth = 0) {
  if (value == null) return value;
  if (typeof value === "string") return boundedString(value);
  if (typeof value === "number") return Number.isFinite(value) ? value : 0;
  if (typeof value === "boolean") return value;
  if (value instanceof Date) return timestampString(value);
  if (Array.isArray(value)) {
    if (depth >= INVESTIGATION_PACKET_LIMITS.maxDepth) return [];
    return value.slice(0, INVESTIGATION_PACKET_LIMITS.maxArrayItems).map((item) => cleanObject(item, depth + 1));
  }
  if (typeof value !== "object") return String(value);
  if (depth >= INVESTIGATION_PACKET_LIMITS.maxDepth) return {};
  const out = {};
  for (const key of Object.keys(value).sort().slice(0, INVESTIGATION_PACKET_LIMITS.maxObjectKeys)) {
    const cleaned = cleanObject(value[key], depth + 1);
    if (cleaned !== undefined && cleaned !== "") out[key] = cleaned;
  }
  return out;
}

function objectLines(obj, prefix = "") {
  const lines = [];
  for (const [key, value] of Object.entries(obj || {})) {
    const name = prefix ? `${prefix}.${key}` : key;
    if (value == null || value === "") continue;
    if (Array.isArray(value)) {
      lines.push(`${name}=${value.map((item) => primitiveLabel(item)).join(", ")}`);
    } else if (typeof value === "object") {
      lines.push(...objectLines(value, name));
    } else {
      lines.push(`${name}=${primitiveLabel(value)}`);
    }
  }
  return lines;
}

function primitiveLabel(value) {
  if (typeof value === "boolean") return value ? "true" : "false";
  return boundedString(value);
}

function boundedString(value) {
  const text = String(value ?? "");
  if (text.length <= INVESTIGATION_PACKET_LIMITS.maxStringChars) return text;
  return text.slice(0, INVESTIGATION_PACKET_LIMITS.maxStringChars - 24) + "...[truncated]";
}

function truncateText(text) {
  if (text.length <= INVESTIGATION_PACKET_LIMITS.maxTextChars) return text;
  return text.slice(0, INVESTIGATION_PACKET_LIMITS.maxTextChars - 28) + "\n...[handoff truncated]\n";
}

function asArray(value) {
  if (Array.isArray(value)) return value;
  if (value == null || value === "") return [];
  return [value];
}

function uniqueStrings(values = []) {
  const seen = new Set();
  const out = [];
  for (const value of values) {
    const text = redactPackageString(value).trim();
    if (!text || seen.has(text)) continue;
    seen.add(text);
    out.push(text);
  }
  return out;
}

export const contentPackageHandoffPacket = contentPackageLifecycleHandoffPacket;

function redactPackageString(value) {
  return redactServerLocalPath(redactPathFieldNames(redactSecretPairs(redactPackageURLs(boundedString(value)))));
}

function redactVpnSecretText(value) {
  return redactServerLocalPath(redactVpnSecretFields(redactPackageURLs(boundedString(value))));
}

function redactServerLocalPath(value) {
  return boundedString(value).replace(
    /(^|[\s"'({=,;])\/(?:var\/lib|var\/log(?:\/openngfw)?|etc\/(?:openngfw|phragma)|tmp|private\/tmp|var\/folders|private\/var\/folders|home\/[^'"\s,;}]+|Users\/[^'"\s,;}]+|opt\/[^'"\s,;}]+|data\/[^'"\s,;}]+)[^'"\s,;}]*/gi,
    `$1[server-local path redacted]`,
  );
}

function redactPackageURLs(value) {
  return String(value).replace(/https?:\/\/[^\s"'<>]+/gi, (raw) => redactPackageURL(raw));
}

function redactSecretPairs(value) {
  return String(value)
    .replace(/(Authorization:\s*Bearer\s+)(?!\[redacted\])["']?[^"'\s,;}]+["']?/gi, "$1[redacted]")
    .replace(/\bBearer\s+(?!\[redacted\])[A-Za-z0-9._~+/-]{8,}/gi, "Bearer [redacted]")
    .replace(/(^|[?&\s"',;])((?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|passwd|secret|client[_-]?secret|api[_-]?key|api[_-]?access[_-]?key|access[_-]?key|cookie)=)[^&\s"',;]+/gi, "$1$2[redacted]")
    .replace(/(^|[\s"',;{])((?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|passwd|secret|client[_-]?secret|api[_-]?key|api[_-]?access[_-]?key|access[_-]?key|cookie)\s*:\s*)[^\s"',;]+/gi, "$1$2[redacted]");
}

function redactPackageURL(raw) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return raw;
  }
  if (!["http:", "https:"].includes(parsed.protocol) || !parsed.host) return raw;
  if (parsed.username || parsed.password) parsed.username = "[redacted]";
  parsed.password = "";
  for (const key of [...parsed.searchParams.keys()]) {
    if (sensitivePackageQueryKey(key)) parsed.searchParams.set(key, "[redacted]");
  }
  return parsed.toString();
}

function redactPathFieldNames(value) {
  return String(value).replace(
    /\b(?:sourcePath|manifestPath|rollbackPath|restoredRollbackPath)\s*[:=]\s*[^\s"',;}]+/gi,
    "[redacted path field]",
  );
}

function redactVpnSecretFields(value) {
  return String(value).replace(
    /\b(?:privateKey|privateKeyFile|psk|pskFile|preSharedKey|preSharedKeyFile)\s*[:=]\s*[^\s"',;}]+/gi,
    "[redacted vpn secret field]",
  );
}

function sensitivePackageQueryKey(key) {
  const normalized = String(key || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  return [
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
  ].includes(normalized) ||
    normalized.includes("token") ||
    normalized.includes("password") ||
    normalized.includes("secret") ||
    normalized.includes("apikey") ||
    normalized.includes("accesskey");
}

function signatureId(alert = {}) {
  const sid = num(alert.signatureId);
  return sid > 0 ? String(sid) : "";
}

function severityLabel(severity) {
  const n = num(severity);
  if (n === 1) return "critical";
  if (n === 2) return "high";
  if (n === 3) return "medium";
  if (n === 4) return "low";
  return "";
}

function protocolLabel(protocol) {
  return cleanEnum(protocol, "PROTOCOL_").toUpperCase();
}

function cleanEnum(value, prefix) {
  return String(value || "").replace(prefix, "").replaceAll("_", " ").toLowerCase();
}

function numberOrBlank(value) {
  const n = Number(value);
  return Number.isFinite(n) && n !== 0 ? n : "";
}

function num(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function timestampString(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return new Date().toISOString();
  return date.toISOString();
}

function timestampForFilename(value) {
  return timestampString(value).replace(/[:.]/g, "-");
}

function subjectSlug(packet = {}) {
  const id = packet.subject?.id || packet.summary?.flowId || packet.summary?.signatureId || "";
  return safeSlug(id).slice(0, 36);
}

function safeToken(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
}

function safeSlug(value) {
  return safeToken(value).replace(/_+/g, "-") || "";
}

function safeCaptureArtifactId(value) {
  const id = String(value || "").trim();
  if (!id || id.startsWith(".") || id.includes("..") || !/^[A-Za-z0-9_.-]{1,128}$/.test(id)) return "";
  return id;
}

function safeCaptureFilename(value) {
  const raw = String(value || "").trim();
  if (/[\\/]/.test(raw)) return "";
  const name = capturePathLeaf(raw);
  if (!name || name.startsWith(".") || name.includes("..") || !/^[A-Za-z0-9_.-]{1,140}\.pcap$/.test(name)) return "";
  return name;
}

function capturePathLeaf(value) {
  return String(value || "").trim().split(/[\\/]/).filter(Boolean).pop() || "";
}
