import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { captureEvidenceViewModel } from "./capture_evidence.js";

const captureEvidenceSource = readFileSync("internal/webui/static/js/capture_evidence.js", "utf8");

assert.match(captureEvidenceSource, /type: "button", title: `Download capture artifact \$\{captureArtifactLabel\(ref\)\}`, "aria-label": `Download capture artifact \$\{captureArtifactLabel\(ref\)\}`/);
assert.match(captureEvidenceSource, /dataset: \{ captureAction: "download", sharedControl: "capture-evidence-download" \}/);
assert.match(captureEvidenceSource, /href: captureAuditHash\(ref\), title: `Open audit trail for capture artifact \$\{captureArtifactLabel\(ref\)\}`, "aria-label": `Open audit trail for capture artifact \$\{captureArtifactLabel\(ref\)\}`/);
assert.match(captureEvidenceSource, /dataset: \{ captureAction: "audit", sharedControl: "capture-evidence-audit" \}/);

{
  const model = captureEvidenceViewModel({ captures: [] }, {
    protocol: "TCP",
    srcIp: "10.0.1.20",
    srcPort: 51515,
    destIp: "10.0.2.20",
    destPort: 443,
  });

  assert.equal(model.state, "empty");
  assert.equal(model.total, 0);
  assert.equal(model.matches.length, 0);
  assert.equal(model.subjectLabel, "TCP 10.0.1.20:51515 -> 10.0.2.20:443");
  assert.match(model.message, /No completed capture artifacts/);
}

{
  const model = captureEvidenceViewModel({
    captures: [
      {
        id: "pcap-match",
        state: "completed",
        plan: {
          protocol: "PROTOCOL_TCP",
          srcIp: "10.0.1.20",
          srcPort: 51515,
          destIp: "10.0.2.20",
          destPort: 443,
          outputPath: "/var/log/openngfw/pcap/phragma-web-1.pcap",
          bpfFilter: "tcp and host 10.0.1.20",
        },
        artifactId: "phragma-web-1",
        filename: "phragma-web-1.pcap",
        bytesWritten: 2048,
        sha256: "d".repeat(64),
        retention: {
          state: "PACKET_CAPTURE_RETENTION_STATE_RETAINED",
          retainUntil: "2999-07-19T12:00:00Z",
          retentionReason: "incident evidence review",
          caseId: "INC-2026-001",
        },
      },
      {
        id: "pcap-miss",
        plan: {
          protocol: "PROTOCOL_UDP",
          srcIp: "10.0.9.20",
          srcPort: 53000,
          destIp: "10.0.2.53",
          destPort: 53,
          outputPath: "/var/log/openngfw/pcap/phragma-dns-1.pcap",
        },
        artifactId: "phragma-dns-1",
      },
    ],
  }, {
    protocol: "tcp",
    srcIp: "10.0.1.20",
    srcPort: "51515",
    destIp: "10.0.2.20",
    destPort: "443",
  });

  assert.equal(model.state, "matched");
  assert.equal(model.total, 2);
  assert.equal(model.correlated, 2);
  assert.deepEqual(model.matches.map((item) => item.id), ["pcap-match"]);
  assert.equal(model.matches[0].sha256Short, "d".repeat(12));
  assert.equal(model.matches[0].integrity.state, "verifiable");
  assert.equal(model.matches[0].retentionState, "retained");
  assert.equal(model.matches[0].retentionSummary, "expires 2999-07-19");
  assert.equal(model.matches[0].caseId, "INC-2026-001");
}

{
  const model = captureEvidenceViewModel({
    captures: [
      {
        id: "legacy",
        plan: { outputPath: "/var/log/openngfw/pcap/phragma-legacy-1.pcap" },
        artifactId: "phragma-legacy-1",
      },
    ],
  }, {
    protocol: "tcp",
    srcIp: "10.0.1.20",
    srcPort: 51515,
    destIp: "10.0.2.20",
    destPort: 443,
  });

  assert.equal(model.state, "none");
  assert.equal(model.total, 1);
  assert.equal(model.correlated, 0);
  assert.match(model.message, /do not include tuple metadata/);
}

{
  const model = captureEvidenceViewModel({
    captures: [
      {
        id: "reverse",
        plan: {
          protocol: "PROTOCOL_TCP",
          srcIp: "10.0.2.20",
          srcPort: 443,
          destIp: "10.0.1.20",
          destPort: 51515,
          outputPath: "/var/log/openngfw/pcap/phragma-reverse-1.pcap",
        },
        artifactId: "phragma-reverse-1",
      },
    ],
  }, {
    protocol: "tcp",
    srcIp: "10.0.1.20",
    srcPort: 51515,
    destIp: "10.0.2.20",
    destPort: 443,
  });

  assert.equal(model.state, "matched");
  assert.deepEqual(model.matches.map((item) => item.id), ["reverse"]);
}
