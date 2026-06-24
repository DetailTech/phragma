import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { diagnosticSnapshotText, summarizeDiagnosticSnapshot } from "./diagnostic_console.js";

const diagnosticConsoleSource = readFileSync("internal/webui/static/js/diagnostic_console.js", "utf8");

assert.match(diagnosticConsoleSource, /type: "button",\s+title: "Refresh API diagnostic evidence",\s+"aria-label": "Refresh API diagnostic evidence",\s+dataset: \{ action: "refresh", sharedControl: "diagnostic-refresh" \}/);
assert.match(diagnosticConsoleSource, /type: "button",\s+title: "Copy API diagnostic snapshot",\s+"aria-label": "Copy API diagnostic snapshot",\s+dataset: \{ action: "copy", sharedControl: "diagnostic-copy" \}/);

const fulfilled = (value) => ({ status: "fulfilled", value });
const rejected = (message) => ({ status: "rejected", reason: new Error(message) });

const summary = summarizeDiagnosticSnapshot({
  version: fulfilled({ version: "2.0.0", commit: "abc123" }),
  status: fulfilled({
    runtime: { dryRun: false, tlsEnabled: true, authEnabled: true, uptimeSeconds: 7265 },
    dataplane: { activeDataplane: "nftables" },
    host: { load1: 1.25, load1PerCpu: 0.31, memoryTotalBytes: "17179869184", memoryUsedPercent: 42.5 },
    engines: [
      { name: "suricata", state: "active", detail: "af-packet detect /var/lib/openngfw/private.sock" },
      { name: "vector", state: "degraded", detail: "sink unavailable Bearer secret-token" },
    ],
    routing: {
      frr: {
        state: "active",
        bgpNeighbors: [{ peer: "198.51.100.2", state: "Established" }],
        ospfNeighbors: [{ neighborId: "10.0.0.2", state: "Full/DROther" }],
      },
    },
    vpn: {
      ipsec: {
        state: "active",
        tunnels: [
          { name: "site-b", state: "active", detail: "IKE established with 1/1 installed CHILD SA(s)" },
          { name: "dr-site", state: "waiting", detail: "IKE is established but no installed CHILD SA was reported" },
        ],
      },
      wireguard: {
        state: "active",
        interfaces: [{
          name: "wg0",
          peers: [
            { publicKey: "pubkey1", state: "handshook" },
            { publicKey: "pubkey2", state: "waiting" },
          ],
        }],
      },
    },
    warnings: [{ severity: "warning", message: "Vector sink unavailable /tmp/vector.sock", action: "Check ClickHouse with token=secret" }],
  }),
  identity: fulfilled({ actor: "admin", role: "admin", authSource: "local-users-file", capabilities: ["read", "write"] }),
  releaseAcceptance: fulfilled({
    state: "blocked",
    ready: false,
    manifestPresent: true,
    summary: { passed: 4, recorded: 3, missing: 1, invalid: 0, todo: 2, notApplicable: 1 },
    problems: ["one release gate is missing"],
    manifestPath: "/tmp/should-not-copy.json",
    evidenceDir: "/tmp/should-not-copy",
    checks: [{ name: "proto-verify", evidencePath: "/tmp/should-not-copy/proto.txt", command: ["make", "proto-verify"] }],
  }),
  candidateStatus: fulfilled({
    hasCandidate: true,
    dirty: true,
    runningVersion: 7,
    changeCount: 3,
    changes: [{ section: "rules", added: 1, modified: 1, removed: 1 }],
  }),
  sessions: fulfilled({
    state: "ready",
    sessions: [{ protocol: "TCP", srcIp: "10.0.1.20", srcPort: 51515, destIp: "10.0.2.20", destPort: 443, state: "ESTABLISHED", packets: "12", bytes: "4096", timeoutSeconds: 431 }],
  }),
  audit: fulfilled({
    entries: [{ time: "2026-06-17T20:40:00Z", actor: "admin", action: "commit", version: "7", detail: "baseline from /etc/openngfw/policy.yaml" }],
  }),
}, new Date("2026-06-17T20:45:00Z"));

assert.equal(summary.failures.length, 0);
assert.match(summary.commands[0].rows[0], /version 2\.0\.0/);
assert.match(summary.commands[0].rows[1], /mode enforcing/);
assert.match(summary.commands[1].rows[0], /admin · role admin/);
assert.match(summary.commands[3].rows[0], /frr active · bgp neighbors 1 · ospf neighbors 1/);
assert.match(summary.commands[3].rows[1], /ipsec active · active tunnels 1\/2/);
assert.match(summary.commands[3].rows[2], /wireguard active · handshook peers 1\/2/);
assert.match(summary.commands[4].rows[0], /candidate staged · dirty yes · running v7 · changes 3/);
assert.match(summary.commands[4].rows[1], /rules: \+1 ~1 -1/);
assert.match(summary.commands[5].rows[0], /1 session sample\(s\) · protocols TCP:1 · states ESTABLISHED:1/);
assert.match(summary.commands[5].rows[1], /endpoint values omitted/);
assert.match(summary.commands[6].rows[0], /1 audit sample\(s\) · actions commit:1/);
assert.match(summary.commands[6].rows[1], /actor and detail values omitted/);
assert.match(summary.commands[7].rows[0], /1 runtime warning\(s\) · severities warning:1/);
assert.match(summary.commands[7].rows[1], /warning text and action detail omitted/);

const text = diagnosticSnapshotText(summary);
assert.match(text, /# Phragma diagnostic snapshot/);
assert.match(text, /\$ ngfwctl status/);
assert.match(text, /\$ ngfwctl whoami/);
assert.match(text, /\$ ngfwctl status # routing-vpn/);
assert.doesNotMatch(text, /\$ ngfwctl system release-acceptance-status --json/);
assert.match(text, /\$ ngfwctl policy status --json/);
assert.match(text, /\$ ngfwctl sessions --limit 8/);
assert.doesNotMatch(text, /\$ phragma\b/);
assert.doesNotMatch(text, /should-not-copy|manifestPath|evidenceDir|evidencePath|make proto-verify|site-b|dr-site|pubkey/);
assert.doesNotMatch(text, /10\.0\.1\.20|10\.0\.2\.20|51515|baseline from|\/etc\/openngfw|\/var\/lib\/openngfw|\/tmp\/vector|secret-token|token=secret|Vector sink unavailable|Check ClickHouse/);
assert.match(text, /endpoint values omitted from summary snapshot/);
assert.match(text, /warning text and action detail omitted from summary snapshot/);

const partial = summarizeDiagnosticSnapshot({
  version: rejected("unauthenticated"),
  status: fulfilled({ runtime: { dryRun: true, authEnabled: true }, warnings: [] }),
  identity: rejected("unauthenticated"),
  releaseAcceptance: rejected("release status unavailable"),
  candidateStatus: rejected("candidate status unavailable"),
  sessions: fulfilled({ state: "ready", sessions: [] }),
  audit: fulfilled({ entries: [] }),
}, new Date("2026-06-17T20:46:00Z"));

assert.deepEqual(partial.failures.map((f) => f.name), ["version", "identity", "candidateStatus"]);
assert.match(diagnosticSnapshotText(partial), /\[endpoint failures\]/);
assert.match(diagnosticSnapshotText(partial), /mode dry-run/);
assert.doesNotMatch(diagnosticSnapshotText(partial), /release acceptance endpoint unavailable/);
assert.match(diagnosticSnapshotText(partial), /candidate status endpoint unavailable/);

const noStatus = summarizeDiagnosticSnapshot({
  version: fulfilled({ version: "2.0.0" }),
  status: rejected("status unavailable"),
  identity: rejected("identity unavailable"),
  releaseAcceptance: fulfilled({ ready: true, manifest_present: true, state: "ready", summary: { passed: 1 } }),
  candidateStatus: fulfilled({ has_candidate: false, running_version: "2", change_count: 0 }),
  sessions: fulfilled({ state: "ready", sessions: [] }),
  audit: fulfilled({ entries: [] }),
}, new Date("2026-06-17T20:47:00Z"));

assert.match(diagnosticSnapshotText(noStatus), /mode unknown/);
assert.match(diagnosticSnapshotText(noStatus), /identity endpoint unavailable/);
assert.doesNotMatch(diagnosticSnapshotText(noStatus), /release acceptance|manifest present/);
assert.match(diagnosticSnapshotText(noStatus), /candidate none · dirty no · running v2 · changes 0/);

const pendingManifest = summarizeDiagnosticSnapshot({
  version: fulfilled({ version: "2.0.0" }),
  status: fulfilled({ runtime: { dryRun: false, authEnabled: true, tlsEnabled: true } }),
  identity: fulfilled({ actor: "admin", role: "admin" }),
  releaseAcceptance: fulfilled({
    state: "evidence-pending-manifest",
    ready: false,
    manifest_present: false,
    summary: { recorded: 15, missing: 0, invalid: 0, todo: 0 },
    problems: ["release acceptance manifest release/acceptance.json is missing"],
  }),
  candidateStatus: fulfilled({ has_candidate: false, running_version: "9", change_count: 0 }),
  sessions: fulfilled({ state: "ready", sessions: [] }),
  audit: fulfilled({ entries: [] }),
}, new Date("2026-06-17T20:48:00Z"));

assert.doesNotMatch(diagnosticSnapshotText(pendingManifest), /evidence-pending-manifest|manifest missing/);
assert.doesNotMatch(diagnosticSnapshotText(pendingManifest), /manifest assembly pending|release manifest/);
