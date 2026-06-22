import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  buildComplianceModel,
  complianceReportHandoffPacket,
  complianceReportContextText,
  complianceReportCreateRequest,
  exportFilenameForReport,
  normalizeComplianceRoute,
  normalizeReportSummary,
  redactComplianceText,
} from "./views/compliance.js";

const complianceSource = readFileSync(new URL("./views/compliance.js", import.meta.url), "utf8");
const appSource = readFileSync(new URL("./app.js", import.meta.url), "utf8");

assert.match(appSource, /import \* as compliance from "\.\/views\/compliance\.js";/);
assert.match(appSource, /\{ path: "\/compliance", title: "Compliance", icon: "shield", view: compliance \}/);
assert.match(complianceSource, /api\.complianceReports\(\{ limit: 100 \}\)/);
assert.match(complianceSource, /api\.complianceReport\(report\.id\)/);
assert.match(complianceSource, /api\.createComplianceReport\(req\)/);
assert.match(complianceSource, /api\.exportComplianceReport\(id\)/);
assert.match(complianceSource, /appendInvestigationPacketToActiveServerCase/);
assert.match(complianceSource, /api\.addInvestigationCaseEvidence\(id, evidence\)/);
assert.match(complianceSource, /activeInvestigationServerCaseHref/);
assert.match(complianceSource, /Pin compliance report handoff to investigation case/);
assert.match(complianceSource, /Open active case/);
assert.match(complianceSource, /Local browser-only fallback was used/);
assert.match(complianceSource, /Operational evidence only\. This is not a signed custody artifact, legal-hold record, or proof of retention enforcement\./);

const reports = [
  {
    id: "report-20260622T120000Z-abcdef12",
    generatedAt: "2026-06-22T12:00:00Z",
    generatedBy: "alice.admin@example.mil",
    generatedByRole: "operator",
    profile: "privileged-access",
    profileLabel: "Privileged access",
    title: "Privileged access review",
    unsigned: true,
    signed: false,
    serverStored: true,
    retentionEnforced: false,
    auditEntryCount: 12,
    versionCount: 3,
    systemLogEntryCount: 4,
    latestAuditHash: "hash-1",
    payloadSha256: "a".repeat(64),
    filters: {
      actor: "alice.admin@example.mil",
      query: "token=supersecret /home/opc/report",
    },
  },
  {
    id: "report-20260622T130000Z-fedcba98",
    generated_at: "2026-06-22T13:00:00Z",
    generated_by: "system",
    generated_by_role: "viewer",
    profile: "change-control",
    profile_label: "Change control",
    title: "CAB report",
    unsigned: false,
    signed: true,
    server_stored: true,
    retention_enforced: true,
    audit_entry_count: 5,
    version_count: 2,
    system_log_entry_count: 0,
    payload_sha256: "b".repeat(64),
  },
];

const normalized = normalizeReportSummary(reports[1]);
assert.equal(normalized.generatedAt, "2026-06-22T13:00:00Z");
assert.equal(normalized.profileLabel, "Change control");
assert.equal(normalized.serverStored, true);
assert.equal(normalized.retentionEnforced, true);
assert.equal(normalized.auditEntryCount, 5);

const route = normalizeComplianceRoute({
  profile: "privileged-access",
  status: "retention-gap",
  search: "alice",
  report: "report-20260622T120000Z-abcdef12",
});
assert.deepEqual(route, {
  profile: "privileged-access",
  status: "retention-gap",
  search: "alice",
  report: "report-20260622T120000Z-abcdef12",
});

const model = buildComplianceModel({ schemaVersion: "phragma.compliance.report-api.v1", reports }, route);
assert.equal(model.counts.total, 2);
assert.equal(model.counts.unsigned, 1);
assert.equal(model.counts.signed, 1);
assert.equal(model.counts.retentionGaps, 1);
assert.equal(model.filtered.length, 1);
assert.equal(model.filtered[0].id, "report-20260622T120000Z-abcdef12");
assert.ok(model.caveats.some((item) => item.key === "unsigned" && item.tone === "warn"));
assert.ok(model.caveats.some((item) => item.key === "retention" && /legal hold/.test(item.detail)));

const signedOnly = buildComplianceModel({ reports }, { status: "signed" });
assert.equal(signedOnly.filtered.length, 1);
assert.equal(signedOnly.filtered[0].id, "report-20260622T130000Z-fedcba98");

const req = complianceReportCreateRequest({
  profile: "incident-evidence",
  title: "Incident report",
  auditLimit: "9999",
  versionLimit: "0",
  logLimit: "-1",
  actor: "bob",
  action: "commit",
  version: "42",
  since: "2026-06-22T00:00:00Z",
  until: "2026-06-22T23:59:59Z",
  query: "change window",
});
assert.deepEqual(req, {
  profile: "incident-evidence",
  title: "Incident report",
  auditLimit: 1000,
  versionLimit: 1,
  logLimit: 0,
  actor: "bob",
  action: "commit",
  version: "42",
  since: "2026-06-22T00:00:00Z",
  until: "2026-06-22T23:59:59Z",
  query: "change window",
});

const context = complianceReportContextText(reports[0]);
assert.match(context, /GET \/v1\/compliance\/reports\/report-20260622T120000Z-abcdef12/);
assert.match(context, /ngfwctl compliance reports export report-20260622T120000Z-abcdef12 --output report-20260622T120000Z-abcdef12\.json/);
assert.match(context, /Operational evidence only/);
assert.match(context, /generatedBy=\[redacted-identity\]/);
assert.match(context, /filter\.actor=\[redacted-identity\]/);
assert.match(context, /filter\.query=token=\[redacted\] \[redacted-path\]/);
assert.doesNotMatch(context, /alice\.admin@example\.mil/);
assert.doesNotMatch(context, /supersecret/);
assert.doesNotMatch(context, /\/home\/opc/);

const packet = complianceReportHandoffPacket(reports[0], "#/compliance?report=report-20260622T120000Z-abcdef12");
assert.equal(packet.schemaVersion, "phragma.investigation.handoff.v1");
assert.equal(packet.kind, "compliance-report");
assert.equal(packet.source.route, "#/compliance?report=report-20260622T120000Z-abcdef12");
assert.equal(packet.summary.serverStored, true);
assert.equal(packet.summary.retentionEnforced, false);
assert.match(packet.summary.boundary, /not legal-hold/);
assert.equal(packet.custody.mode, "browser-local-unsigned");
assert.equal(packet.custody.serverRetained, true);
assert.equal(packet.custody.retentionEnforced, false);
assert.equal(packet.custody.packetSigned, false);
assert.equal(packet.custody.retainedArtifact, "/v1/compliance/reports/report-20260622T120000Z-abcdef12/export");
assert.equal(packet.custody.retainedArtifactType, "compliance-report-export");
assert.match(packet.custody.boundary, /WebUI packet is unsigned operational handoff/);
assert.ok(packet.custody.hardeningRequired.includes("signed compliance reports"));
assert.ok(packet.evidence.some((line) => line.includes("handoff_boundary=browser-local packet")));
assert.doesNotMatch(JSON.stringify(packet), /alice\.admin@example\.mil/);
assert.doesNotMatch(JSON.stringify(packet), /supersecret/);
assert.doesNotMatch(JSON.stringify(packet), /\/home\/opc/);

assert.equal(redactComplianceText("Bearer abcdefghijklmnop token=abc password=hunter2 /Users/alice/key"), "Bearer [redacted-token] token=[redacted] password=[redacted] [redacted-path]");
assert.equal(exportFilenameForReport({ id: "report-1" }), "report-1.json");
assert.equal(exportFilenameForReport({ id: "report-1.json" }), "report-1.json");
