import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { CAPTURE_LIMITS, buildCapturePlan, captureArtifactFilename, captureAuditHash, captureAuditQuery, captureHistoryItems, captureIntegrityStatus, captureMatchesSubject, captureReference, captureReferenceLabel, captureRetentionApiState, captureRetentionSummary, captureSubjectFromSource, matchingCaptureHistoryItems } from "./packet_capture.js";

const troubleshootSource = readFileSync(new URL("./views/troubleshoot.js", import.meta.url), "utf8");
assert.match(troubleshootSource, /type: "button", title: "Copy capture command", "aria-label": "Copy capture command"/);

{
  const plan = buildCapturePlan({
    interface: "ens5",
    protocol: "PROTOCOL_TCP",
    srcIp: "10.0.1.20",
    srcPort: 51515,
    destIp: "10.0.2.20",
    destPort: 443,
    durationSeconds: 30,
    packetCount: 900,
    snaplenBytes: 512,
    label: "flow-check",
    flowId: "eve-flow-42",
    timestamp: "2026-06-17T19:56:00Z",
  });

  assert.equal(plan.interface, "ens5");
  assert.equal(plan.protocol, "tcp");
  assert.equal(plan.durationSeconds, 30);
  assert.equal(plan.packetCount, 900);
  assert.equal(plan.snaplenBytes, 512);
  assert.equal(plan.flowId, "eve-flow-42");
  assert.equal(plan.filter, "tcp and ((src host 10.0.1.20 and src port 51515 and dst host 10.0.2.20 and dst port 443) or (src host 10.0.2.20 and src port 443 and dst host 10.0.1.20 and dst port 51515))");
  assert.match(plan.command, /sudo timeout 30s tcpdump -i 'ens5' -nn -s 512 -c 900/);
  assert.match(plan.command, /phragma-flow-check-20260617T195600Z\.pcap/);
  assert.deepEqual(plan.warnings, []);
}

{
  const plan = buildCapturePlan({
    interface: "eth0;rm -rf /",
    protocol: "udp",
    srcIp: "bad host",
    destIp: "2001:db8::10",
    srcPort: -1,
    destPort: 53,
    durationSeconds: 600,
    packetCount: 0,
    snaplenBytes: 999999,
    label: "dns lookup!",
    timestamp: "2026-06-17T19:56:01Z",
  });

  assert.equal(plan.interface, CAPTURE_LIMITS.defaultInterface);
  assert.equal(plan.durationSeconds, CAPTURE_LIMITS.maxDurationSeconds);
  assert.equal(plan.packetCount, CAPTURE_LIMITS.minPacketCount);
  assert.equal(plan.snaplenBytes, CAPTURE_LIMITS.maxSnaplenBytes);
  assert.equal(plan.filter, "udp and host 2001:db8::10 and port 53");
  assert.match(plan.outputPath, /phragma-dns-lookup-/);
  assert.ok(plan.warnings.some((w) => /Interface is set to any/.test(w)));
  assert.ok(plan.warnings.some((w) => /not fully flow-scoped/.test(w)));
  assert.ok(plan.warnings.some((w) => /not both ports/.test(w)));
  assert.doesNotMatch(plan.command, /rm -rf/);
}

{
  const plan = buildCapturePlan({});

  assert.equal(plan.filter, "ip");
  assert.equal(plan.durationSeconds, CAPTURE_LIMITS.defaultDurationSeconds);
  assert.equal(plan.packetCount, CAPTURE_LIMITS.defaultPacketCount);
  assert.equal(plan.snaplenBytes, CAPTURE_LIMITS.defaultSnaplenBytes);
}

{
  const ref = captureReference({ outputPath: "/var/log/openngfw/pcap/local.pcap" }, {
    id: "pcap-20260618T120000Z",
    state: "completed",
    bytes_written: 4096,
    sha256: "a".repeat(64),
    completed_at: "2026-06-18T12:00:20Z",
  });

  assert.equal(ref.id, "pcap-20260618T120000Z");
  assert.equal(ref.outputPath, "/var/log/openngfw/pcap/local.pcap");
  assert.equal(ref.bytesWritten, 4096);
  assert.equal(ref.sha256Short, "a".repeat(12));
  assert.equal(ref.integrity.state, "verifiable");
  assert.match(captureReferenceLabel(ref), /pcap-20260618T120000Z/);
  assert.match(captureReferenceLabel(ref), /sha256:aaaaaaaaaaaa/);
  assert.match(captureReferenceLabel(ref), /4096 bytes/);
}

{
  const ref = captureReference({}, {
    id: "pcap-no-safe-artifact",
    state: "completed",
    bytes_written: 4096,
    sha256: "a".repeat(64),
  });
  assert.equal(ref.integrity.state, "review");
  assert.match(ref.integrity.detail, /safe artifact identifier is missing/);
}

{
  const ref = captureReference({ outputPath: "/var/log/openngfw/pcap/../secret.pcap" }, {
    id: "pcap-unsafe-artifact",
    state: "completed",
    bytes_written: 4096,
    sha256: "a".repeat(64),
    artifactId: "../../etc/passwd",
    filename: "../secret.pcap",
    downloadPath: "/v1/system/packet-captures/../../etc/passwd/download?access_token=secret-token",
  });

  assert.equal(ref.artifactId, "");
  assert.equal(ref.filename, "");
  assert.equal(ref.downloadPath, "");
  assert.equal(ref.integrity.state, "review");
  assert.match(ref.integrity.detail, /safe artifact identifier is missing/);
  assert.equal(captureReferenceLabel(ref), "pcap-unsafe-artifact · sha256:aaaaaaaaaaaa · 4096 bytes");
}

{
  const ref = captureReference({ outputPath: "/var/log/openngfw/pcap/phragma-flow-20260618T120000Z.pcap" }, {
    id: "pcap-20260618T120000Z",
    state: "completed",
    bytesWritten: "2048",
    artifactId: "phragma-flow-20260618T120000Z",
    downloadPath: "/v1/system/packet-captures/phragma-flow-20260618T120000Z/download",
    filename: "phragma-flow-20260618T120000Z.pcap",
    mediaType: "application/vnd.tcpdump.pcap",
  });

  assert.equal(ref.artifactId, "phragma-flow-20260618T120000Z");
  assert.equal(ref.downloadPath, "/v1/system/packet-captures/phragma-flow-20260618T120000Z/download");
  assert.equal(ref.filename, "phragma-flow-20260618T120000Z.pcap");
  assert.equal(ref.protocol, "ip");
  assert.equal(ref.integrity.state, "incomplete");
  assert.match(ref.integrity.detail, /sha256 digest is not recorded/);
  assert.equal(captureArtifactFilename(ref), "phragma-flow-20260618T120000Z.pcap");
}

{
  const integrity = captureIntegrityStatus({
    state: "completed",
    artifactId: "phragma-flow-20260618T120000Z",
    filename: "phragma-flow-20260618T120000Z.pcap",
    bytesWritten: 2048,
    sha256: "d".repeat(64),
    mediaType: "application/vnd.tcpdump.pcap",
  });
  assert.equal(integrity.state, "verifiable");
  assert.equal(integrity.label, "verifiable");
  assert.equal(integrity.tone, "ok");
  assert.deepEqual(integrity.problems, []);

  const pending = captureIntegrityStatus({ state: "running", artifactId: "phragma-flow" });
  assert.equal(pending.state, "pending");
  assert.match(pending.detail, /not completed/);
}

{
  const retained = captureReference({ outputPath: "/var/log/openngfw/pcap/phragma-retained.pcap" }, {
    artifact_id: "phragma-retained",
    filename: "phragma-retained.pcap",
    retention: {
      state: "PACKET_CAPTURE_RETENTION_STATE_RETAINED",
      retain_until: "2999-07-19T12:00:00Z",
      retention_reason: "incident evidence review",
      case_id: "INC-2026-001",
      updated_at: "2026-06-19T12:00:00Z",
      updated_by: "alice",
    },
  });

  assert.equal(retained.retentionState, "retained");
  assert.equal(retained.retainUntil, "2999-07-19T12:00:00Z");
  assert.equal(retained.retentionReason, "incident evidence review");
  assert.equal(retained.caseId, "INC-2026-001");
  assert.equal(retained.retentionSummary, "expires 2999-07-19");
  assert.equal(retained.retentionTone, "ok");
  assert.equal(captureRetentionApiState("retained"), "PACKET_CAPTURE_RETENTION_STATE_RETAINED");

  const expired = captureReference({}, {
    artifactId: "phragma-expired",
    filename: "phragma-expired.pcap",
    retentionState: "retained",
    retainUntil: "2001-01-01T00:00:00Z",
  });
  assert.equal(expired.retentionSummary, "expired");
  assert.equal(expired.retentionTone, "warn");

  const released = captureReference({}, {
    artifactId: "phragma-released",
    filename: "phragma-released.pcap",
    retention: { state: "released", retentionReason: "case closed", caseId: "INC-2026-002" },
  });
  assert.equal(captureRetentionSummary(released), "released");
  assert.equal(released.retentionTone, "neutral");
}

{
  const ref = captureReference({ outputPath: "/var/log/openngfw/pcap/phragma-safe.pcap" }, {
    artifactId: "phragma-safe",
    filename: "phragma-safe.pcap",
    retention: {
      state: "PACKET_CAPTURE_RETENTION_STATE_RETAINED",
      retainUntil: "2999-07-19T12:00:00Z",
      retentionReason: "Bearer token=secret",
      caseId: "INC/secret",
      updatedBy: "admin/token",
    },
  });

  assert.equal(ref.retentionState, "retained");
  assert.equal(ref.retentionReason, "");
  assert.equal(ref.caseId, "");
  assert.equal(ref.retentionUpdatedBy, "");
}

{
  const ref = captureReference({
    protocol: "PROTOCOL_TCP",
    srcIp: "10.0.1.20",
    srcPort: 51515,
    destIp: "10.0.2.20",
    destPort: 443,
    outputPath: "/var/log/openngfw/pcap/phragma-flow-20260618T120000Z.pcap",
  }, {
    artifactId: "phragma-flow-20260618T120000Z",
    filename: "phragma-flow-20260618T120000Z.pcap",
  });
  const subject = captureSubjectFromSource({
    flowId: "eve-flow-42",
    protocol: "TCP",
    srcIp: "10.0.1.20",
    srcPort: 51515,
    destIp: "10.0.2.20",
    destPort: 443,
  });

  assert.equal(ref.protocol, "tcp");
  assert.equal(ref.srcPort, 51515);
  assert.equal(captureMatchesSubject(ref, subject), true);
  assert.equal(captureMatchesSubject(ref, { ...subject, srcIp: "10.0.9.9" }), false);
  assert.equal(captureMatchesSubject(ref, {
    protocol: "PROTOCOL_TCP",
    srcIp: "10.0.2.20",
    srcPort: 443,
    destIp: "10.0.1.20",
    destPort: 51515,
  }), true);
  assert.equal(captureMatchesSubject({ flowId: "eve-flow-42" }, subject), true);
}

{
  const subject = captureSubjectFromSource({
    flow_id: "eve-flow-raw",
    plan: {
      protocol: "PROTOCOL_UDP",
      src_ip: "10.0.1.20",
      src_port: "53000",
      dest_ip: "10.0.2.53",
      dest_port: "53",
    },
  });

  assert.deepEqual(subject, {
    flowId: "eve-flow-raw",
    protocol: "udp",
    srcIp: "10.0.1.20",
    srcPort: 53000,
    destIp: "10.0.2.53",
    destPort: 53,
  });
}

{
  const items = captureHistoryItems({
    captures: [
      {
        id: "phragma-web-20260618T120000Z",
        state: "completed",
        plan: { outputPath: "/var/log/openngfw/pcap/phragma-web-20260618T120000Z.pcap" },
        sha256: "b".repeat(64),
        bytesWritten: 100,
      },
      {
        id: "bad",
        plan: { outputPath: "/var/log/openngfw/pcap/../secret" },
        filename: "../secret.pcap",
      },
    ],
  });

  assert.equal(items.length, 1);
  assert.equal(items[0].artifactId, "phragma-web-20260618T120000Z");
  assert.equal(items[0].downloadPath, "/v1/system/packet-captures/phragma-web-20260618T120000Z/download");
  assert.equal(items[0].sha256Short, "b".repeat(12));
  assert.equal(items[0].integrity.state, "verifiable");
}

{
  const matches = matchingCaptureHistoryItems({
    captures: [
      {
        id: "match",
        plan: { protocol: "PROTOCOL_UDP", srcIp: "10.0.1.20", srcPort: 53000, destIp: "10.0.2.53", destPort: 53, outputPath: "/var/log/openngfw/pcap/phragma-dns-1.pcap" },
        artifactId: "phragma-dns-1",
      },
      {
        id: "miss",
        plan: { protocol: "PROTOCOL_TCP", srcIp: "10.0.1.20", srcPort: 53000, destIp: "10.0.2.53", destPort: 53, outputPath: "/var/log/openngfw/pcap/phragma-web-1.pcap" },
        artifactId: "phragma-web-1",
      },
    ],
  }, { protocol: "udp", srcIp: "10.0.1.20", srcPort: 53000, destIp: "10.0.2.53", destPort: 53 });

  assert.deepEqual(matches.map((item) => item.id), ["match"]);
}

{
  const ref = captureReference({}, { sha256: "not-a-hash" });
  assert.equal(ref.sha256, "");
  assert.equal(captureReferenceLabel(ref), "capture reference unavailable");
}

{
  assert.equal(captureAuditQuery({ sha256: "a".repeat(64), flowId: "flow-1" }), "a".repeat(64));
  assert.equal(captureAuditQuery({ flowId: "flow-1" }), "flow-1");
  assert.equal(captureAuditQuery({ artifactId: "phragma-flow-20260618T120000Z" }), "phragma-flow-20260618T120000Z");
  assert.equal(captureAuditQuery({ outputPath: "/var/log/openngfw/pcap/phragma-flow.pcap" }), "phragma-flow.pcap");
  assert.equal(captureAuditQuery({ srcIp: "10.0.1.20", srcPort: 51515, destIp: "10.0.2.20", destPort: 443 }), "10.0.1.20 51515 10.0.2.20 443");
  assert.equal(captureAuditHash({ flowId: "eve-flow-42" }), "#/changes?tab=audit&action=packet-capture&query=eve-flow-42");
  assert.equal(captureAuditHash({}), "#/changes?tab=audit&action=packet-capture");
}
