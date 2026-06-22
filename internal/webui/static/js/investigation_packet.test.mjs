import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  INVESTIGATION_PACKET_LIMITS,
  INVESTIGATION_PACKET_SCHEMA,
  alertHandoffPacket,
  appIdObservationHandoffPacket,
  appIdRegressionSampleHandoffPacket,
  auditEntryHandoffPacket,
  auditLogHandoffPacket,
  captureHandoffPacket,
  contentPackageLifecycleHandoffPacket,
  explainHandoffPacket,
  flowHandoffPacket,
  investigationPacketFilename,
  investigationPacketJson,
  investigationPacketText,
  natPathHandoffPacket,
  sessionHandoffPacket,
  vpnTunnelHandoffPacket,
} from "./investigation_packet.js";

const collectedAt = "2026-06-17T21:30:15.123Z";

const netvpnViewSource = readFileSync(new URL("./views/netvpn.js", import.meta.url), "utf8");
assert.match(netvpnViewSource, /import \{[^}]*appendInvestigationPacketToActiveServerCase[^}]*pinInvestigationPacket[^}]*\} from "\.\.\/investigation_case\.js";/);
assert.match(netvpnViewSource, /function pinVpnHandoff/);
assert.match(netvpnViewSource, /api\.addInvestigationCaseEvidence\(id, evidence\)/);
assert.match(netvpnViewSource, /Pin to case/);

const intelViewSource = readFileSync(new URL("./views/intel.js", import.meta.url), "utf8");
assert.match(intelViewSource, /pinInvestigationPacket/);
assert.match(intelViewSource, /function pinHandoff/);
assert.match(intelViewSource, /Pin to case/);

{
  const packet = flowHandoffPacket({
    flowId: "eve-flow-42",
    srcIp: "10.0.1.20",
    srcPort: 51515,
    destIp: "10.0.2.20",
    destPort: 443,
    protocol: "TCP",
    appId: "tls",
    appName: "TLS",
    appCategory: "encrypted",
    appConfidence: 94,
    appProtocol: "ssl",
    appEvidence: ["suricata app_proto=ssl", "taxonomy match tls"],
    bytesToServer: 2048,
    bytesToClient: 4096,
    packets: 18,
    policyVersionKnown: true,
    policyVersion: 7,
    time: "2026-06-17T21:29:01Z",
  }, {
    collectedAt,
    route: "#/traffic?mode=flows&flowId=eve-flow-42",
    currentInspectionPosture: {
      state: "failed-open",
      engine: "suricata inline failed",
      bypassPossible: true,
      scope: "current runtime posture at handoff time; not a per-event telemetry fact",
    },
  });

  assert.equal(packet.schemaVersion, INVESTIGATION_PACKET_SCHEMA);
  assert.equal(packet.kind, "flow");
  assert.equal(packet.custody.mode, "browser-local-unsigned");
  assert.equal(packet.custody.packetSigned, false);
  assert.equal(packet.custody.serverRetained, false);
  assert.equal(packet.custody.redactionApplied, true);
  assert.equal(packet.custody.boundsApplied, true);
  assert.match(packet.custody.boundary, /Browser-local unsigned handoff packet/);
  assert.ok(packet.custody.hardeningRequired.includes("artifact signing"));
  assert.equal(packet.subject.id, "eve-flow-42");
  assert.equal(packet.subject.label, "10.0.1.20:51515 -> 10.0.2.20:443");
  assert.equal(packet.summary.totalBytes, 6144);
  assert.equal(packet.summary.eventPolicy, "v7");
  assert.equal(packet.summary.currentInspectionPosture.state, "failed-open");
  assert.equal(packet.summary.currentInspectionPosture.bypassPossible, true);
  assert.deepEqual(packet.evidence, ["suricata app_proto=ssl", "taxonomy match tls"]);

  const text = investigationPacketText(packet);
  assert.match(text, /Phragma investigation handoff/);
  assert.match(text, /kind=flow/);
  assert.match(text, /custody_mode=browser-local-unsigned/);
  assert.match(text, /packet_signed=false/);
  assert.match(text, /server_retained=false/);
  assert.match(text, /totalBytes=6144/);
  assert.match(text, /currentInspectionPosture\.scope=current runtime posture at handoff time/);
  assert.match(text, /- suricata app_proto=ssl/);

  const json = investigationPacketJson(packet);
  assert.equal(JSON.parse(json).artifacts.flow.flowId, "eve-flow-42");
  assert.ok(json.endsWith("\n"));

  assert.equal(
    investigationPacketFilename(packet, new Date(collectedAt)),
    "phragma-investigation-flow-eve-flow-42-2026-06-17T21-30-15-123Z.json",
  );
}

{
  const key = "ct1|ipv4|tcp|10.0.1.20|51515|203.0.113.20|443|203.0.113.20|443|10.0.1.20|51515";
  const packet = sessionHandoffPacket({
    family: "ipv4",
    protocol: "TCP",
    state: "ESTABLISHED",
    assured: true,
    srcIp: "10.0.1.20",
    srcPort: 51515,
    destIp: "203.0.113.20",
    destPort: 443,
    replySrcIp: "203.0.113.20",
    replySrcPort: 443,
    replyDestIp: "10.0.1.20",
    replyDestPort: 51515,
    packets: 42,
    bytes: 32768,
    timeoutSeconds: 431999,
    raw: "tcp 6 431999 ESTABLISHED src=10.0.1.20 dst=203.0.113.20 sport=51515 dport=443 src=203.0.113.20 dst=10.0.1.20 sport=443 dport=51515 [ASSURED]",
  }, {
    collectedAt,
    route: "#/traffic?mode=sessions&sessionKey=ct1%7Cipv4%7Ctcp%7C10.0.1.20%7C51515%7C203.0.113.20%7C443%7C203.0.113.20%7C443%7C10.0.1.20%7C51515",
    sessionKey: key,
    currentInspectionPosture: {
      state: "ready",
      engine: "suricata detect active",
      scope: "current runtime posture at handoff time; not a per-event telemetry fact",
    },
    threatPackageSummary: {
      available: true,
      kind: "threat-id",
      label: "2.0.0 / passed",
      status: "passed",
      version: "2.0.0",
      packageState: "verified",
      blockerCount: 0,
      contentReadinessEvidence: [
        { type: "pcap-regression-corpus", artifact: "evidence/pcap-regression.json", sha256: "a".repeat(64), sha256Short: "a".repeat(12), generatedAt: "2026-06-17T21:00:00.000Z" },
        { type: "false-positive-regression", artifact: "evidence/fp-regression.json", sha256: "b".repeat(64), sha256Short: "b".repeat(12) },
      ],
    },
  });

  assert.equal(packet.kind, "session");
  assert.equal(packet.subject.id, key);
  assert.equal(packet.subject.tuple.srcIp, "10.0.1.20");
  assert.equal(packet.subject.replyTuple.destPort, 51515);
  assert.equal(packet.summary.state, "ESTABLISHED");
  assert.equal(packet.summary.bytes, 32768);
  assert.equal(packet.summary.assured, true);
  assert.ok(packet.evidence.includes("live conntrack session"));
  assert.match(packet.evidence.find((line) => line.startsWith("raw conntrack:")), /ASSURED/);

  const json = JSON.parse(investigationPacketJson(packet));
  assert.equal(json.artifacts.session.raw, packet.artifacts.session.raw);

  const text = investigationPacketText(packet);
  assert.match(text, /kind=session/);
  assert.match(text, /subject_id=ct1\|ipv4\|tcp/);
  assert.match(text, /bytes=32768/);
  assert.match(text, /raw conntrack:/);
}

{
  const packet = alertHandoffPacket({
    threatId: "threat.http.shell",
    threatName: "Suspicious web shell",
    threatCategory: "web-attack",
    threatSeverity: "high",
    threatConfidence: 88,
    signatureId: 2034567,
    flowId: "eve-flow-99",
    srcIp: "198.51.100.10",
    srcPort: 54321,
    destIp: "10.0.2.30",
    destPort: 8080,
    protocol: "TCP",
    action: "blocked",
    threatEvidence: ["signature sid 2034567", "payload matched web-shell rule"],
    time: "2026-06-17T21:28:00Z",
  }, {
    collectedAt,
    currentInspectionPosture: {
      state: "ready",
      engine: "suricata detect active",
      scope: "current runtime posture at handoff time; not a per-event telemetry fact",
    },
    threatPackageSummary: {
      available: true,
      kind: "threat-id",
      label: "2.0.0 / passed",
      status: "passed",
      version: "2.0.0",
      packageState: "verified",
      blockerCount: 0,
      contentReadinessEvidence: [
        { type: "pcap-regression-corpus", artifact: "evidence/pcap-regression.json", sha256: "a".repeat(64), sha256Short: "a".repeat(12), generatedAt: "2026-06-17T21:00:00.000Z" },
        { type: "false-positive-regression", artifact: "evidence/fp-regression.json", sha256: "b".repeat(64), sha256Short: "b".repeat(12) },
      ],
    },
  });

  assert.equal(packet.kind, "alert");
  assert.equal(packet.subject.id, "eve-flow-99");
  assert.equal(packet.subject.label, "Suspicious web shell");
  assert.equal(packet.summary.signatureId, "2034567");
  assert.equal(packet.summary.threatSeverity, "high");
  assert.equal(packet.summary.currentInspectionPosture.state, "ready");
  assert.equal(packet.summary.contentPackage.version, "2.0.0");
  assert.equal(packet.summary.contentPackage.readinessEvidenceCount, 2);
  assert.ok(packet.evidence.includes("signature sid 2034567"));
  assert.ok(packet.evidence.includes("package readiness pcap-regression-corpus: evidence/pcap-regression.json | sha256:aaaaaaaaaaaa | 2026-06-17T21:00:00.000Z"));
  assert.equal(packet.artifacts.contentPackage.contentReadinessEvidence[1].artifact, "evidence/fp-regression.json");
}

{
  const packet = explainHandoffPacket({
    query: {
      srcIp: "10.0.1.20",
      srcPort: 51515,
      destIp: "10.0.2.20",
      destPort: 443,
      protocol: "PROTOCOL_TCP",
      flowId: "eve-flow-42",
    },
    result: {
      verdict: "EXPLAIN_VERDICT_ALLOW",
      reason: "matched allow-web",
      matchedRule: "allow-web",
      matchedRuleIndex: 3,
      policySource: "POLICY_SOURCE_RUNNING",
      policyVersion: 7,
      inspectionState: "EXPLAIN_INSPECTION_STATE_INSPECTED",
      runtimeEvidence: { queried: true, state: "queried" },
      evidence: ["rule allow-web matched"],
    },
  }, {
    collectedAt,
    route: "#/troubleshoot?run=1&flowId=eve-flow-42",
    currentInspectionPosture: {
      state: "failed-open",
      engine: "suricata inline failed",
      bypassPossible: true,
      scope: "current runtime posture at handoff time; not a per-event telemetry fact",
    },
  });

  assert.equal(packet.kind, "explain");
  assert.equal(packet.subject.id, "eve-flow-42");
  assert.equal(packet.summary.currentInspectionPosture.state, "failed-open");
  assert.equal(packet.summary.currentInspectionPosture.bypassPossible, true);
  assert.ok(packet.evidence.includes("evidence: rule allow-web matched"));
  const text = investigationPacketText(packet);
  assert.match(text, /currentInspectionPosture\.scope=current runtime posture at handoff time/);
}

{
  const packet = auditEntryHandoffPacket({
    id: 42,
    action: "content-package-install",
    detail: "sourcePath=/Users/alice/content/app-id url=https://writer:secret@audit.example/install?access_token=secret-token",
    actor: "alice@example.com",
    actorRole: "operator",
    authSource: "oidc-session",
    version: 9,
    time: "2026-06-17T21:27:00Z",
    entryHash: "abcdef0123456789abcdef0123456789",
    previousHash: "0123456789abcdef0123456789abcdef",
  }, {
    collectedAt,
    route: "#/changes?tab=audit&entry=42",
    integrity: {
      ok: true,
      entryCount: 128,
      latestEntryHash: "abcdef0123456789abcdef0123456789",
      detail: "verified through /var/lib/openngfw/audit.log",
    },
  });

  assert.equal(packet.kind, "audit-entry");
  assert.equal(packet.subject.id, "42");
  assert.equal(packet.subject.label, "content-package-install");
  assert.equal(packet.summary.action, "content-package-install");
  assert.equal(packet.summary.integrityOk, true);
  assert.equal(packet.summary.integrityEntryCount, 128);
  assert.equal(packet.artifacts.auditEntry.entryHash, "abcdef0123456789abcdef0123456789");
  assert.ok(packet.evidence.includes("entry hash: abcdef0123456789abcdef0123456789"));
  assert.ok(packet.evidence.includes("previous hash: 0123456789abcdef0123456789abcdef"));

  const json = investigationPacketJson(packet);
  const text = investigationPacketText(packet);
  for (const leaked of ["/Users", "/var/lib", "sourcePath", "writer:secret", "secret-token"]) {
    assert.equal(json.includes(leaked), false, `JSON leaked ${leaked}`);
    assert.equal(text.includes(leaked), false, `text leaked ${leaked}`);
  }
  assert.match(text, /kind=audit-entry/);
  assert.match(text, /integrityOk=true/);
  assert.equal(
    investigationPacketFilename(packet, new Date(collectedAt)),
    "phragma-investigation-audit-entry-42-2026-06-17T21-30-15-123Z.json",
  );
}

{
  const packet = auditLogHandoffPacket([
    {
      id: 43,
      action: "rollback",
      detail: "restored from /var/lib/openngfw/private-state with access_token=secret-token",
      actor: "bob@example.com",
      actorRole: "admin",
      authSource: "local-token",
      version: 10,
      time: "2026-06-17T22:00:00Z",
      entryHash: "11111111111111111111111111111111",
      previousHash: "abcdef0123456789abcdef0123456789",
    },
    {
      id: 42,
      action: "commit",
      detail: "source=/Users/alice/policy.json url=https://writer:secret@audit.example/apply?api_key=secret",
      actor: "alice@example.com",
      actorRole: "operator",
      authSource: "oidc-session",
      version: 9,
      time: "2026-06-17T21:27:00Z",
      entryHash: "abcdef0123456789abcdef0123456789",
      previousHash: "0123456789abcdef0123456789abcdef",
    },
  ], {
    collectedAt,
    route: "#/changes?tab=audit&action=commit&limit=100",
    request: { action: "commit", limit: 100 },
    integrity: {
      ok: true,
      entryCount: 128,
      latestEntryHash: "11111111111111111111111111111111",
      detail: "verified through /var/lib/openngfw/audit.log",
    },
  });

  assert.equal(packet.kind, "audit-log");
  assert.equal(packet.subject.label, "Filtered audit log");
  assert.equal(packet.summary.matchedEntries, 2);
  assert.equal(packet.summary.includedEntries, 2);
  assert.deepEqual(packet.summary.actions, ["rollback", "commit"]);
  assert.equal(packet.summary.integrityOk, true);
  assert.equal(packet.artifacts.auditEntries.length, 2);
  assert.equal(packet.artifacts.request.action, "commit");

  const json = investigationPacketJson(packet);
  const text = investigationPacketText(packet);
  for (const leaked of ["/Users", "/var/lib", "writer:secret", "secret-token", "api_key=secret"]) {
    assert.equal(json.includes(leaked), false, `JSON leaked ${leaked}`);
    assert.equal(text.includes(leaked), false, `text leaked ${leaked}`);
  }
  assert.match(text, /kind=audit-log/);
  assert.match(text, /matchedEntries=2/);
  assert.equal(
    investigationPacketFilename(packet, new Date(collectedAt)),
    "phragma-investigation-audit-log-audit-log-2-2026-06-17T21-30-15-123Z.json",
  );
}

{
  const packet = appIdObservationHandoffPacket({
    queueId: "appid-queue-42",
    kind: "APP_ID_OBSERVATION_KIND_UNKNOWN",
    appId: "unknown",
    appConfidence: 38,
    engineSignalSource: "suricata.app_proto",
    engineSignal: "weird-admin",
    protocol: "TCP",
    destPort: 8443,
    sampleSrcIp: "10.0.1.20",
    sampleSrcPort: 51515,
    sampleDestIp: "10.0.2.20",
    sampleFlowId: "eve-flow-77",
    appIdPackageVersion: "2.4.6",
    appIdPackageManifestSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    runningPolicyVersion: 9,
    policyContext: "running v9",
    count: 8,
    bytes: 65536,
    packets: 120,
    firstSeen: "2026-06-17T21:00:00Z",
    lastSeen: "2026-06-17T21:29:00Z",
    appEvidence: [
      "engine signal suricata.app_proto=weird-admin",
      "sample url https://user:secret@apps.example.local/login?access_token=secret-token&tenant=prod",
    ],
    suggestedApplication: {
      name: "weird-admin",
      displayName: "Weird Admin",
      category: "business-app",
      engineSignals: ["weird-admin"],
      ports: [{ protocol: "PROTOCOL_TCP", ports: [{ start: 8443 }] }],
      description: "Observed repeated admin traffic.",
    },
  }, {
    collectedAt,
    route: "#/traffic?mode=app-id&queueId=appid-queue-42",
    reviewAction: "Save & drop",
    evidenceStrength: "strong",
    currentInspectionPosture: {
      state: "ready",
      engine: "suricata detect active",
      scope: "current runtime posture at handoff time; not a per-event telemetry fact",
    },
  });

  assert.equal(packet.kind, "app-id-observation");
  assert.equal(packet.subject.id, "appid-queue-42");
  assert.equal(packet.subject.label, "Weird Admin");
  assert.equal(packet.subject.tuple.srcPort, 51515);
  assert.equal(packet.subject.tuple.destPort, 8443);
  assert.equal(packet.summary.reason, "unknown");
  assert.equal(packet.summary.reviewAction, "Save & drop");
  assert.equal(packet.summary.evidenceStrength, "strong");
  assert.equal(packet.summary.sampleSrcPort, 51515);
  assert.equal(packet.summary.appIdPackageVersion, "2.4.6");
  assert.equal(packet.summary.appIdPackageManifestSha256, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
  assert.equal(packet.summary.suggestedApplication, "weird-admin");
  assert.equal(packet.summary.suggestedPortHints, "TCP/8443");
  assert.equal(packet.summary.currentInspectionPosture.state, "ready");
  assert.ok(packet.evidence.includes("engine signal: suricata.app_proto=weird-admin"));
  assert.ok(packet.evidence.includes("app-id package version: 2.4.6"));
  assert.equal(packet.artifacts.observation.suggestedApplication.name, "weird-admin");
  assert.equal(packet.artifacts.observation.sampleSrcPort, 51515);
  assert.equal(packet.artifacts.observation.appIdPackageManifestSha256, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

  const json = investigationPacketJson(packet);
  const text = investigationPacketText(packet);
  for (const leaked of ["user:secret", "secret-token"]) {
    assert.equal(json.includes(leaked), false, `JSON leaked ${leaked}`);
    assert.equal(text.includes(leaked), false, `text leaked ${leaked}`);
  }
  assert.match(text, /kind=app-id-observation/);
  assert.match(text, /reviewAction=Save & drop/);
  assert.equal(
    investigationPacketFilename(packet, new Date(collectedAt)),
    "phragma-investigation-app-id-observation-appid-queue-42-2026-06-17T21-30-15-123Z.json",
  );
}

{
  const packet = appIdRegressionSampleHandoffPacket({
    queueId: "appid-queue-42",
    kind: "APP_ID_OBSERVATION_KIND_UNKNOWN",
    appId: "unknown",
    appConfidence: 38,
    engineSignalSource: "suricata.app_proto",
    engineSignal: "weird-admin",
    protocol: "TCP",
    destPort: 8443,
    sampleSrcIp: "10.0.1.20",
    sampleSrcPort: 51515,
    sampleDestIp: "10.0.2.20",
    sampleFlowId: "eve-flow-77",
    appIdPackageVersion: "2.4.6",
    appIdPackageManifestSha256: "f".repeat(64),
    count: 8,
    bytes: 65536,
    packets: 120,
    firstSeen: "2026-06-17T21:00:00Z",
    lastSeen: "2026-06-17T21:29:00Z",
    appEvidence: [
      "engine signal suricata.app_proto=weird-admin",
      "sample url https://user:secret@apps.example.local/login?access_token=secret-token",
    ],
    suggestedApplication: {
      name: "weird-admin",
      displayName: "Weird Admin",
      category: "business-app",
      engineSignals: ["weird-admin"],
      ports: [{ protocol: "PROTOCOL_TCP", ports: [{ start: 8443 }] }],
    },
  }, {
    collectedAt,
    route: "#/traffic?mode=app-id&queueId=appid-queue-42",
    reviewAction: "Define App-ID",
    evidenceStrength: "strong",
    appIdReadiness: {
      explicit: true,
      productionReady: false,
      status: "missing",
      packageState: "verified-demo",
      version: "2.4.6",
      manifestSha256: "f".repeat(64),
      blockers: ["app-regression-corpus", "sourcePath=/var/lib/openngfw/content/app-id/pkg"],
      detail: "missing production evidence under /var/lib/openngfw/content/app-id/pkg",
    },
    currentInspectionPosture: { state: "ready" },
  });

  assert.equal(packet.kind, "app-id-regression-sample");
  assert.match(packet.subject.id, /^appid-queue-42@2\.4\.6@f{64}$/);
  assert.equal(packet.subject.tuple.flowId, "eve-flow-77");
  assert.equal(packet.summary.captureRequirement, "bounded packet capture attached to the App-ID regression corpus");
  assert.equal(packet.summary.packageProductionReady, false);
  assert.equal(packet.summary.packageStatus, "missing");
  assert.equal(packet.summary.packageState, "verified-demo");
  assert.equal(packet.summary.blockerCount, 2);
  assert.equal(packet.summary.blockers[0], "app-regression-corpus");
  assert.equal(packet.summary.suggestedApplication, "weird-admin");
  assert.equal(packet.summary.suggestedPortHints, "TCP/8443");
  assert.equal(packet.artifacts.captureSubject.flowId, "eve-flow-77");
  assert.equal(packet.artifacts.appIdReadiness.blockerCount, 2);
  assert.ok(packet.evidence.includes("regression sample: preserve this flow as App-ID corpus evidence"));
  assert.ok(packet.evidence.includes("package readiness: not production ready"));
  assert.ok(packet.evidence.includes("package blocker: app-regression-corpus"));

  const json = investigationPacketJson(packet);
  const text = investigationPacketText(packet);
  for (const leaked of ["user:secret", "secret-token", "/var/lib/openngfw", "sourcePath="]) {
    assert.equal(json.includes(leaked), false, `JSON leaked ${leaked}`);
    assert.equal(text.includes(leaked), false, `text leaked ${leaked}`);
  }
  assert.match(text, /kind=app-id-regression-sample/);
  assert.match(text, /captureRequirement=bounded packet capture/);
  assert.equal(
    investigationPacketFilename(packet, new Date(collectedAt)),
    "phragma-investigation-app-id-regression-sample-appid-queue-42-2-4-6-fffffffffffffff-2026-06-17T21-30-15-123Z.json",
  );
}

{
  const packet = captureHandoffPacket({
    query: {
      srcIp: "10.0.1.20",
      srcPort: 51515,
      destIp: "10.0.2.20",
      destPort: 443,
      protocol: "PROTOCOL_TCP",
      flowId: "eve-flow-42",
    },
    result: {
      verdict: "EXPLAIN_VERDICT_ALLOWED",
      decisionSummary: "allowed, partially inspected",
      decisionTerms: ["EXPLAIN_DECISION_TERM_ALLOWED", "EXPLAIN_DECISION_TERM_PARTIALLY_INSPECTED"],
      reason: "matched allow-web",
      matchedRule: "allow-web",
      matchedRuleIndex: 3,
      policySource: "POLICY_SOURCE_RUNNING",
      policyVersion: 7,
      inspectionState: "EXPLAIN_INSPECTION_STATE_IDS_DETECT",
      evidence: ["rule allow-web matched tuple"],
      trace: ["checked rule 1", "checked rule 3"],
      runtimeEvidence: { queried: true, state: "ready", evidence: ["one conntrack session matched"] },
    },
    capturePlan: {
      interface: "ens5",
      bpfFilter: "tcp and host 10.0.1.20",
      outputPath: "/var/log/openngfw/pcap/phragma-flow.pcap",
      durationSeconds: 20,
      packetCount: 500,
      snaplenBytes: 256,
      command: "sudo timeout 20s tcpdump ...",
      warnings: ["local preview; server validation pending"],
      source: "server",
    },
    captureJob: {
      id: "pcap-20260617T212800Z",
      artifactId: "phragma-flow-20260617T212800Z",
      filename: "phragma-flow-20260617T212800Z.pcap",
      state: "completed",
      detail: "packet capture completed",
      exitCode: 0,
      bytesWritten: 4096,
      sha256: "c".repeat(64),
      startedAt: "2026-06-17T21:28:00Z",
      completedAt: "2026-06-17T21:28:20Z",
    },
  }, { collectedAt, route: "#/troubleshoot?flowId=eve-flow-42" });

  assert.equal(packet.kind, "capture");
  assert.equal(packet.subject.id, "eve-flow-42");
  assert.equal(packet.summary.decision, "allowed, partially inspected");
  assert.equal(packet.summary.verdict, "allowed");
  assert.equal(packet.summary.interface, "ens5");
  assert.equal(packet.summary.planSource, "server");
  assert.equal(packet.summary.captureState, "completed");
  assert.equal(packet.summary.captureId, "pcap-20260617T212800Z");
  assert.equal(packet.summary.bytesWritten, 4096);
  assert.equal(packet.summary.sha256, "c".repeat(64));
  assert.equal(packet.summary.integrityState, "verifiable");
  assert.match(packet.summary.integrityDetail, /safe identifier/);
  assert.equal(packet.summary.auditRoute, `#/changes?tab=audit&action=packet-capture&query=${"c".repeat(64)}`);
  assert.equal(packet.summary.detail, "packet capture completed");
  assert.equal(packet.subject.tuple.srcIp, "10.0.1.20");
  assert.equal(packet.subject.tuple.srcPort, 51515);
  assert.equal(packet.subject.tuple.destIp, "10.0.2.20");
  assert.equal(packet.subject.tuple.destPort, 443);
  assert.equal(packet.subject.tuple.protocol, "TCP");
  assert.equal(packet.artifacts.query.flowId, "eve-flow-42");
  assert.equal(packet.artifacts.captureJob.state, "completed");
  assert.ok(packet.evidence.includes("capture warning: local preview; server validation pending"));
  assert.ok(packet.evidence.includes("capture state: completed"));
  assert.ok(packet.evidence.includes("capture bytes written: 4096"));
  assert.ok(packet.evidence.includes(`capture sha256: ${"c".repeat(64)}`));
  assert.ok(packet.evidence.some((line) => /^capture integrity: verifiable/.test(line)));
  assert.ok(packet.evidence.includes(`capture audit route: #/changes?tab=audit&action=packet-capture&query=${"c".repeat(64)}`));
  assert.ok(packet.evidence.includes("runtime: one conntrack session matched"));

  const text = investigationPacketText(packet);
  assert.match(text, /bpfFilter=tcp and host 10\.0\.1\.20/);
  assert.match(text, /captureState=completed/);
  assert.match(text, /sha256=cccccccccccc/);
  assert.match(text, /- capture warning: local preview/);
}

{
  const packet = captureHandoffPacket({
    query: { srcIp: "10.0.1.20", destIp: "10.0.2.20", protocol: "PROTOCOL_TCP" },
    capturePlan: { interface: "ens5", filter: "tcp", outputPath: "/var/log/openngfw/pcap/failed.pcap" },
    captureJob: { state: "failed", detail: "tcpdump exited 1", bytes_written: 0 },
  }, { collectedAt, route: "#/troubleshoot?intent=capture" });

  assert.equal(packet.summary.captureState, "failed");
  assert.equal(packet.summary.bytesWritten, 0);
  assert.equal(packet.summary.integrityState, "pending");
  assert.equal(packet.summary.detail, "tcpdump exited 1");
  assert.ok(packet.evidence.includes("capture detail: tcpdump exited 1"));
  assert.equal(packet.artifacts.captureJob.state, "failed");
}

{
  const packet = captureHandoffPacket({
    query: {
      srcIp: "10.0.1.20",
      srcPort: 51515,
      destIp: "10.0.2.20",
      destPort: 443,
      protocol: "PROTOCOL_TCP",
    },
    capturePlan: {
      interface: "ens5",
      filter: "tcp and host 10.0.1.20",
      outputPath: "/var/log/openngfw/pcap/review-needed.pcap",
      command: "sudo tcpdump -w /var/log/openngfw/pcap/review-needed.pcap Authorization: Bearer phr_secret_capture",
      warnings: [
        "review needed: sourcePath=/var/log/openngfw/pcap/review-needed.pcap",
        "query secret https://fw.example.local/capture?access_token=secret-token",
      ],
      source: "server",
    },
    captureJob: {
      id: "pcap-review-needed",
      artifactId: "../../etc/passwd",
      filename: "../unsafe.pcap",
      state: "completed",
      detail: "review needed from /var/log/openngfw/pcap/review-needed.pcap with Authorization: Bearer phr_secret_capture",
      bytesWritten: 2048,
      sha256: "d".repeat(64),
      mediaType: "application/x-secret",
    },
  }, { collectedAt, route: "#/troubleshoot?intent=capture&token=Bearer-secret-token&path=/etc/passwd" });

  assert.equal(packet.summary.integrityState, "review");
  assert.match(packet.summary.integrityDetail, /safe artifact identifier is missing/);
  assert.equal(packet.summary.artifactId, undefined);
  assert.equal(packet.summary.filename, undefined);
  assert.equal(packet.artifacts.captureJob.artifactId, undefined);
  assert.equal(packet.artifacts.captureJob.filename, undefined);
  assert.equal(packet.artifacts.capturePlan.outputPath, "[server-local path redacted]");

  const json = investigationPacketJson(packet);
  const text = investigationPacketText(packet);
  for (const leaked of ["/var/log", "../../etc/passwd", "Bearer phr_secret_capture", "secret-token", "sourcePath="]) {
    assert.equal(json.includes(leaked), false, `JSON leaked ${leaked}`);
    assert.equal(text.includes(leaked), false, `text leaked ${leaked}`);
  }
  assert.match(json, /Bearer \[redacted\]/);
  assert.match(json, /access_token=\[redacted\]/);
  assert.match(text, /capture integrity: review/);
}

{
  const packet = natPathHandoffPacket({
    flow: {
      fromZone: "outside",
      toZone: "dmz",
      srcIp: "198.51.100.10",
      srcPort: 51515,
      destIp: "203.0.113.10",
      destPort: 443,
      protocol: "PROTOCOL_TCP",
    },
    running: {
      verdict: "EXPLAIN_VERDICT_DEFAULT_DROP",
      defaultPolicy: true,
      policySource: "POLICY_SOURCE_RUNNING",
    },
    candidate: {
      verdict: "EXPLAIN_VERDICT_ALLOWED",
      matchedRule: "allow-public-web",
      matchedRuleIndex: 3,
      policySource: "POLICY_SOURCE_CANDIDATE",
      routeProfile: { matched: true },
    },
    delta: {
      changed: true,
      tone: "bad",
      headline: "Candidate changes path behavior",
      rows: [
        { label: "Decision", running: "blocked", candidate: "allowed, fully inspected", changed: true },
        { label: "DNAT", running: "no match", candidate: "public-https", changed: true },
      ],
      warnings: ["candidate route unresolved: no route"],
    },
  }, {
    collectedAt,
    route: "#/nat?fromZone=outside&toZone=dmz&run=1",
    previewWarning: "No candidate policy is staged; candidate preview is using the running baseline.",
  });

  assert.equal(packet.kind, "nat-path");
  assert.equal(packet.subject.label, "198.51.100.10:51515 -> 203.0.113.10:443");
  assert.equal(packet.subject.tuple.fromZone, "outside");
  assert.equal(packet.summary.candidateChanged, true);
  assert.equal(packet.summary.result, "Candidate changes path behavior");
  assert.equal(packet.summary.runningMatchedRule, "default policy");
  assert.equal(packet.summary.candidateMatchedRule, "allow-public-web");
  assert.ok(packet.evidence.includes("delta Decision: running=blocked; candidate=allowed, fully inspected (changed)"));
  assert.ok(packet.evidence.includes("warning: candidate route unresolved: no route"));

  const text = investigationPacketText(packet);
  assert.match(text, /kind=nat-path/);
  assert.match(text, /route=#\/nat\?fromZone=outside&toZone=dmz&run=1/);
  assert.match(text, /candidateChanged=true/);
  assert.equal(JSON.parse(investigationPacketJson(packet)).artifacts.delta.rows.length, 2);
  assert.equal(
    investigationPacketFilename(packet, new Date(collectedAt)),
    "phragma-investigation-nat-path-198-51-100-10-51515---203-0-113-10-4-2026-06-17T21-30-15-123Z.json",
  );
}

{
  const packet = vpnTunnelHandoffPacket({
    kind: "wireguard",
    kindLabel: "WireGuard",
    id: "wireguard:wg0:laptop",
    name: "wg0:laptop",
    interfaceName: "wg0",
    peerName: "laptop",
    localEndpoint: "10.99.0.1/24",
    remoteEndpoint: "198.51.100.8:51820",
    listenPort: 51820,
    localPrefixes: ["10.99.0.1/24"],
    remotePrefixes: ["10.99.0.2/32"],
    mode: "keepalive 25s",
    secretState: "privateKeyFile=/etc/phragma/keys/wg0.key pskFile=/etc/phragma/secrets/site-b.conf",
    publicKeyState: "public key configured",
    runtime: {
      state: "handshook",
      cls: "ok",
      detail: "latest handshake 90s ago using privateKeyFile=/etc/phragma/keys/wg0.key",
      endpoint: "198.51.100.8:51820",
      latestHandshake: "handshake 1m ago",
      rxBytes: 1234,
      txBytes: 5678,
    },
    targets: [{
      kind: "wireguard",
      kindLabel: "WireGuard",
      name: "wg0:laptop",
      ifaceName: "wg0",
      peerName: "laptop",
      localCidr: "10.99.0.1/24",
      remoteCidr: "10.99.0.2/32",
      srcIp: "10.99.0.1",
      destIp: "10.99.0.2",
      protocol: "PROTOCOL_ANY",
    }],
  }, {
    collectedAt,
    route: "#/netvpn?drawer=tunnel&kind=wireguard&iface=wg0&peer=laptop",
  });

  assert.equal(packet.kind, "vpn-tunnel");
  assert.equal(packet.title, "VPN tunnel handoff");
  assert.equal(packet.subject.id, "wireguard:wg0:laptop");
  assert.equal(packet.subject.tuple.srcIp, "10.99.0.1");
  assert.equal(packet.subject.tuple.destIp, "10.99.0.2");
  assert.equal(packet.summary.tunnelType, "WireGuard");
  assert.equal(packet.summary.runtimeState, "handshook");
  assert.equal(packet.summary.pathCount, 1);
  assert.equal(packet.artifacts.targets[0].remoteCidr, "10.99.0.2/32");
  assert.ok(packet.evidence.includes("path: 10.99.0.1/24 -> 10.99.0.2/32"));
  assert.ok(packet.evidence.some((line) => line.includes("[redacted vpn secret field]")));
  assert.equal(packet.source.route, "#/netvpn?drawer=tunnel&kind=wireguard&iface=wg0&peer=laptop");

  const json = investigationPacketJson(packet);
  const text = investigationPacketText(packet);
  for (const leaked of ["/etc/phragma", "privateKeyFile=", "pskFile=", "site-b.conf", "wg0.key"]) {
    assert.equal(json.includes(leaked), false, `JSON leaked ${leaked}`);
    assert.equal(text.includes(leaked), false, `text leaked ${leaked}`);
  }
  assert.equal(
    investigationPacketFilename(packet, new Date(collectedAt)),
    "phragma-investigation-vpn-tunnel-wireguard-wg0-laptop-2026-06-17T21-30-15-123Z.json",
  );
}

{
  const packet = contentPackageLifecycleHandoffPacket({
    kind: "app-id",
    name: "Phragma App-ID catalog",
    badge: "verified",
    version: "1.2.3",
    source: "/var/lib/openngfw/content-import/app-id-package",
    manifestSha256: "0123456789abcdef0123456789abcdef",
    signatureStatus: "verified",
    regressionStatus: "passed",
    rolloutState: "stable",
    rollbackAvailable: true,
    blockers: ["production evidence", "sourcePath=/tmp/operator-upload"],
    evidence: ["sha256:0123456789ab", "rollback-backup:yes"],
    contentReadinessEvidence: [
      { type: "pcap-regression-corpus", artifact: "evidence/pcap-regression.json", sha256: "c".repeat(64), sha256Short: "c".repeat(12) },
      { type: "secret", artifact: "/var/lib/openngfw/content/secret.json", sha256: "d".repeat(64), sha256Short: "d".repeat(12) },
    ],
    fields: [
      { label: "Source", value: "/var/lib/openngfw/content/app-id/manifest.json", cls: "info" },
      { label: "Signature", value: "verified", cls: "ok" },
    ],
    provenance: [
      {
        name: "Curated package",
        license: "Apache-2.0",
        url: "https://writer:secret@content.example/app-id?access_token=secret-token&channel=stable",
      },
    ],
    decision: {
      label: "review required",
      cls: "warn",
      detail: "1 review item before production rollout.",
      nextAction: "Attach production evidence.",
      checks: [
        { key: "signature", label: "Signature", status: "verified", cls: "ok", action: "Reported by API." },
        { key: "production-evidence", label: "Production evidence", status: "not exposed", cls: "warn", blocker: "production evidence", action: "Review package evidence." },
      ],
      blockers: ["production evidence"],
    },
  }, {
    collectedAt,
    route: "#/intel?surface=app-id&drawer=review",
    lifecycleAction: "review",
  });

  assert.equal(packet.kind, "content-package-lifecycle");
  assert.equal(packet.title, "Content package lifecycle handoff");
  assert.equal(packet.subject.id, "app-id");
  assert.equal(packet.summary.lifecycleAction, "review");
  assert.equal(packet.summary.packageKind, "app-id");
  assert.equal(packet.summary.version, "1.2.3");
  assert.equal(packet.summary.signatureStatus, "verified");
  assert.equal(packet.summary.regressionStatus, "passed");
  assert.equal(packet.summary.rolloutState, "stable");
  assert.equal(packet.summary.rollbackAvailable, true);
  assert.equal(packet.summary.decision, "review required");
  assert.equal(packet.summary.blockerCount, 2);
  assert.equal(packet.summary.readinessEvidenceCount, 2);
  assert.ok(packet.evidence.includes("check Signature: verified (ok)"));
  assert.ok(packet.evidence.includes("readiness evidence pcap-regression-corpus: evidence/pcap-regression.json | sha256:cccccccccccc"));
  assert.ok(packet.evidence.includes("blocker: production evidence"));
  assert.equal(packet.source.route, "#/intel?surface=app-id&drawer=review");
  assert.equal(packet.artifacts.contentPackage.fields[0].value, "[server-local path redacted]");
  assert.equal(packet.artifacts.contentPackage.contentReadinessEvidence[1].artifact, "[server-local path redacted]");

  const json = investigationPacketJson(packet);
  const text = investigationPacketText(packet);
  for (const leaked of ["/var/lib", "/tmp", "/Users", "sourcePath", "manifestPath", "rollbackPath", "restoredRollbackPath", "writer", "secret-token"]) {
    assert.equal(json.includes(leaked), false, `JSON leaked ${leaked}`);
    assert.equal(text.includes(leaked), false, `text leaked ${leaked}`);
  }
  assert.equal(
    investigationPacketFilename(packet, new Date(collectedAt)),
    "phragma-investigation-content-package-lifecycle-app-id-2026-06-17T21-30-15-123Z.json",
  );
}

{
  const packet = flowHandoffPacket({
    flowId: "big-flow",
    srcIp: "10.0.1.1",
    destIp: "10.0.2.2",
    appEvidence: Array.from({ length: INVESTIGATION_PACKET_LIMITS.maxEvidenceItems + 10 }, (_, i) => "evidence " + i),
    nested: {
      long: "x".repeat(INVESTIGATION_PACKET_LIMITS.maxStringChars + 100),
    },
  }, { collectedAt });

  assert.equal(packet.evidence.length, INVESTIGATION_PACKET_LIMITS.maxEvidenceItems);
  assert.equal(JSON.parse(investigationPacketJson(packet)).artifacts.flow.appEvidence.length, INVESTIGATION_PACKET_LIMITS.maxArrayItems);
  assert.ok(JSON.parse(investigationPacketJson(packet)).artifacts.flow.nested.long.endsWith("[truncated]"));
  assert.ok(investigationPacketText(packet).length <= INVESTIGATION_PACKET_LIMITS.maxTextChars);
}
