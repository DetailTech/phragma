import assert from "node:assert/strict";

import { AUDIT_ACTION_OPTIONS, auditActionClass, auditCliCommandFromRequest, auditComplianceSummary, auditEntryKey, auditHashLabel, auditIntegritySummary, auditReportPacket, auditRequestFromFilters, complianceReportCreateRequest, normalizeAuditFilters, normalizeChangesRouteState, versionRecoveryModel } from "./views/changes.js";

const actions = AUDIT_ACTION_OPTIONS.map(([value]) => value);

for (const action of [
  "set-candidate",
  "stage-threat-exception",
  "commit-intent",
  "commit",
  "commit-failed",
  "rollback-intent",
  "rollback",
  "rollback-failed",
  "system-tune",
  "system-tune-failed",
  "packet-capture",
  "packet-capture-failed",
  "content-package-install-intent",
  "content-package-install",
  "content-package-install-failed",
  "content-package-rollback-intent",
  "content-package-rollback",
  "content-package-rollback-failed",
  "access-local-user-create-intent",
  "access-local-user-create",
  "access-local-user-create-failed",
  "access-local-user-update-intent",
  "access-local-user-update",
  "access-local-user-update-failed",
  "access-local-user-rotate-token-intent",
  "access-local-user-rotate-token",
  "access-local-user-rotate-token-failed",
  "access-local-user-disable-intent",
  "access-local-user-disable",
  "access-local-user-disable-failed",
  "access-oidc-provider-set-intent",
  "access-oidc-provider-set",
  "access-oidc-provider-set-failed",
  "access-oidc-provider-disable-intent",
  "access-oidc-provider-disable",
  "access-oidc-provider-disable-failed",
  "access-saml-provider-set-intent",
  "access-saml-provider-set",
  "access-saml-provider-set-failed",
  "access-saml-provider-disable-intent",
  "access-saml-provider-disable",
  "access-saml-provider-disable-failed",
  "access-session-revoke-intent",
  "access-session-revoke",
  "access-session-revoke-failed",
]) {
  assert.ok(actions.includes(action), `missing audit action option ${action}`);
}

assert.equal(actions[0], "");
assert.equal(new Set(actions).size, actions.length);

assert.equal(auditActionClass("commit"), "ok");
assert.equal(auditActionClass("commit-intent"), "info");
assert.equal(auditActionClass("rollback"), "warn");
assert.equal(auditActionClass("rollback-intent"), "warn");
assert.equal(auditActionClass("set-candidate"), "info");
assert.equal(auditActionClass("stage-threat-exception"), "info");
assert.equal(auditActionClass("system-tune"), "warn");
assert.equal(auditActionClass("packet-capture"), "info");
assert.equal(auditActionClass("content-package-install"), "violet");
assert.equal(auditActionClass("content-package-install-intent"), "violet");
assert.equal(auditActionClass("content-package-rollback"), "warn");
assert.equal(auditActionClass("content-package-rollback-intent"), "warn");
assert.equal(auditActionClass("content-package-install-failed"), "bad");
assert.equal(auditActionClass("access-local-user-create"), "violet");
assert.equal(auditActionClass("access-oidc-provider-set"), "violet");
assert.equal(auditActionClass("access-saml-provider-disable"), "violet");
assert.equal(auditActionClass("access-session-revoke"), "violet");
assert.equal(auditActionClass("access-local-user-disable-failed"), "bad");
assert.equal(auditActionClass("access-saml-provider-set-failed"), "bad");
assert.equal(auditActionClass("unknown-action"), "neutral");

assert.equal(auditHashLabel({ entryHash: "abcdef0123456789" }), "abcdef012345");
assert.equal(auditHashLabel({}), "—");

assert.match(auditIntegritySummary({ ok: true, entryCount: 2, latestEntryHash: "abcdef0123456789", detail: "verified" }), /2 audit entries checked latest abcdef012345/);
assert.match(auditIntegritySummary({ ok: false, detail: "mismatch" }), /0 audit entries checked\. mismatch/);

const req = auditRequestFromFilters({
  query: "rollback",
  actor: "alice@example.com",
  action: "rollback",
  version: "12",
  since: "2026-06-18T08:00",
  until: "2026-06-18T09:00",
  limit: "500",
});
assert.equal(req.query, "rollback");
assert.equal(req.actor, "alice@example.com");
assert.equal(req.action, "rollback");
assert.equal(req.version, "12");
assert.equal(req.limit, 500);
assert.match(req.since, /^2026-06-18T/);
assert.match(req.until, /^2026-06-18T/);
assert.equal(
  auditCliCommandFromRequest(req),
  `ngfwctl audit --limit 500 --actor alice@example.com --action rollback --version 12 --query rollback --since ${req.since} --until ${req.until} --hashes`,
);
assert.equal(auditEntryKey({ id: 42 }), "42");
assert.equal(auditEntryKey({ entryHash: "abcdef 123456" }), "abcdef-123456");
assert.equal(auditEntryKey({ entryHash: "bad\u0000hash" }), "");

assert.deepEqual(auditRequestFromFilters({ limit: "bad" }), { limit: 300 });
assert.equal(normalizeAuditFilters({ action: "access-local-user-create" }).action, "access-local-user-create");
assert.equal(normalizeAuditFilters({ action: "access-session-revoke" }).action, "access-session-revoke");

const hostile = normalizeAuditFilters({
  query: " prod ",
  actor: " alice ",
  action: "unknown-action",
  version: "abc",
  since: "not-a-date",
  until: "2026-06-18T09:00",
  limit: "1000000000",
});
assert.deepEqual(hostile, {
  query: "prod",
  actor: "alice",
  action: "",
  version: "",
  since: "",
  until: "2026-06-18T09:00",
  limit: "300",
  entry: "",
});

const hostileReq = auditRequestFromFilters(hostile);
assert.equal(hostileReq.limit, 300);
assert.equal(hostileReq.query, "prod");
assert.equal(hostileReq.actor, "alice");
assert.equal(hostileReq.action, undefined);
assert.equal(hostileReq.version, undefined);
assert.equal(hostileReq.since, undefined);
assert.match(hostileReq.until, /^2026-06-18T/);

const normalizedReq = auditRequestFromFilters({ action: "commit", version: "0007", limit: "1000" });
assert.deepEqual(normalizedReq, { limit: 1000, action: "commit", version: "7" });

const report = auditReportPacket([
  {
    id: 7,
    action: "commit",
    actor: "alice@example.com",
    actorRole: "admin",
    authSource: "local-token",
    version: 12,
    time: "2026-06-18T09:00:00Z",
    detail: "published candidate /var/lib/openngfw/secret",
    entryHash: "abcdef0123456789",
    previousHash: "1234567890abcdef",
  },
], {
  filters: {
    query: "Bearer secret-token-value",
    actor: "https://user:secret@example.com",
    action: "commit",
    version: "12",
    limit: "bad",
  },
  integrity: {
    ok: true,
    entryCount: 1,
    latestEntryHash: "abcdef0123456789",
    detail: "verified",
  },
  route: "#/changes?tab=audit&query=/etc/passwd&drawer=report",
  generatedAt: "2026-06-18T09:01:00.000Z",
});
assert.equal(report.schemaVersion, "phragma.audit.report.v1");
assert.equal(report.source, "browser-generated");
assert.equal(report.unsigned, true);
assert.equal(report.custody.serverStored, false);
assert.equal(report.custody.signed, false);
assert.equal(report.filters.limit, "300");
assert.equal(report.filters.query, "[redacted]");
assert.equal(report.filters.actor, "[redacted]");
assert.equal(report.request.query.limit, 300);
assert.equal(report.replay.cli, 'ngfwctl audit --limit 300 --actor "[redacted]" --action commit --version 12 --query "[redacted]" --hashes');
assert.equal(report.replay.api, "/v1/audit?limit=300&actor=%5Bredacted%5D&action=commit&version=12&query=%5Bredacted%5D");
assert.equal(report.replay.verifyApi, "GET /v1/audit/verify");
assert.equal(report.integrity.ok, true);
assert.equal(report.compliance.scope, "visible-audit-window");
assert.equal(report.compliance.profile, "operational");
assert.equal(report.compliance.profileLabel, "Operational");
assert.equal(report.compliance.controlCount, 6);
assert.ok(report.compliance.controls.some((control) => control.id === "audit-integrity" && control.status === "passed"));
assert.ok(report.compliance.controls.some((control) => control.id === "profile-coverage" && control.status === "passed"));
assert.ok(report.compliance.controls.some((control) => control.id === "custody-boundary" && control.status === "review"));
assert.equal(report.includedEntryCount, 1);
assert.deepEqual(report.entryHashes, ["abcdef0123456789"]);
assert.equal(report.entries[0].detail, "[redacted]");
assert.doesNotMatch(JSON.stringify(report), /secret-token-value|user:secret|\/etc\/passwd|\/var\/lib\/openngfw/i);
assert.match(report.notes.join("\n"), /not a signed custody artifact/);

const emptyCompliance = auditComplianceSummary([], { ok: false, entryCount: 0, detail: "no entries" });
assert.equal(emptyCompliance.controls.find((control) => control.id === "hash-evidence").status, "passed");
assert.equal(emptyCompliance.controls.find((control) => control.id === "profile-coverage").status, "review");

const changeControlReport = auditReportPacket([{ action: "commit", actor: "bob", version: 8, entryHash: "feedface" }], {
  profile: "change-control",
  integrity: { ok: true, entryCount: 1, detail: "verified" },
});
assert.equal(changeControlReport.compliance.profile, "change-control");
assert.equal(changeControlReport.compliance.profileLabel, "Change control");
assert.equal(changeControlReport.compliance.matchedEntryCount, 1);
assert.ok(changeControlReport.compliance.controls.some((control) => control.id === "profile-coverage" && /1\/1/.test(control.detail)));

const serverCreateRequest = complianceReportCreateRequest("change-control", { action: "commit", version: "12", limit: "500", query: "cab" });
assert.deepEqual(serverCreateRequest, {
  profile: "change-control",
  title: "Change control compliance report",
  auditLimit: 500,
  versionLimit: 100,
  logLimit: 100,
  actor: "",
  action: "commit",
  version: "12",
  since: "",
  until: "",
  query: "cab",
});

assert.deepEqual(
  normalizeChangesRouteState({ tab: "audit", drawer: "report", action: "commit", query: "prod" }),
  { tab: "audit", query: "prod", actor: "", action: "commit", version: "", since: "", until: "", limit: "300", entry: "", drawer: "report" },
);
assert.equal(normalizeChangesRouteState({ tab: "audit", drawer: "unknown" }).drawer, "");

const runningLkg = versionRecoveryModel({
  id: 4,
  action: "commit",
  state: "active",
  lastKnownGood: true,
  artifactSetSha256: "abcdef0123456789",
  activatedAt: "2026-06-18T12:00:00Z",
  artifacts: [{ engine: "nftables", name: "nftables", sizeBytes: 12, sha256: "1234567890abcdef" }],
}, 4);
assert.equal(runningLkg.recoveryLabel, "current last-known-good");
assert.equal(runningLkg.stateClass, "ok");
assert.equal(runningLkg.artifactLabel, "sha256:abcdef012345");
assert.equal(runningLkg.artifacts[0].sha256, "1234567890abcdef");

const failedPrepared = versionRecoveryModel({
  id: 5,
  state: "apply_failed",
  last_known_good: false,
  artifact_set_sha256: "fedcba9876543210",
  state_detail: "runtime apply failed",
}, 4);
assert.equal(failedPrepared.recoveryLabel, "running remains on LKG");
assert.equal(failedPrepared.stateClass, "bad");
assert.equal(failedPrepared.stateDetail, "runtime apply failed");

const rollbackVersion = versionRecoveryModel({ id: 6, state: "active", source_version: 2 }, 6);
assert.equal(rollbackVersion.recoveryLabel, "rollback from v2");
