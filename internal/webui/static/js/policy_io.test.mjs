import assert from "node:assert/strict";

import {
  LEGACY_POLICY_EXPORT_SCHEMA,
  POLICY_EXPORT_SCHEMA,
  SNAPSHOT_RESTORE_REVIEW_SCHEMA,
  normalizeSnapshotDrawer,
  normalizeSnapshotId,
  parsePolicyImportText,
  policyExportEnvelope,
  policyExportFilename,
  redactPacketText,
  replacePolicyDraft,
  snapshotRestoreReviewFilename,
  snapshotRestoreReviewHash,
  snapshotRestoreReviewJson,
  snapshotRestoreReviewPacket,
  snapshotRestoreReviewText,
} from "./policy_io.js";

{
  const policy = { zones: [{ name: "lan" }], rules: [] };
  const exportedAt = "2026-06-17T15:00:00.000Z";
  const envelope = policyExportEnvelope({ source: "running", version: 7, policy, exportedAt });

  assert.equal(envelope.schemaVersion, POLICY_EXPORT_SCHEMA);
  assert.equal(envelope.source, "running");
  assert.equal(envelope.version, "7");
  assert.deepEqual(parsePolicyImportText(JSON.stringify(envelope)), policy);
}

{
  const raw = { zones: [{ name: "wan" }], addresses: [{ name: "public", cidr: "203.0.113.10/32" }] };
  assert.deepEqual(parsePolicyImportText(JSON.stringify(raw)), raw);
}

{
  const policy = { zones: [{ name: "legacy" }], rules: [] };
  const legacyEnvelope = { schemaVersion: LEGACY_POLICY_EXPORT_SCHEMA, policy };
  assert.deepEqual(parsePolicyImportText(JSON.stringify(legacyEnvelope)), policy);
}

{
  assert.throws(
    () => parsePolicyImportText('{"policy":{"constructor":{"polluted":true}}}'),
    /Unsafe key "constructor"/,
  );
}

{
  const draft = { zones: [{ name: "old" }], rules: [{ name: "old-rule" }] };
  replacePolicyDraft(draft, { zones: [{ name: "new" }], services: [] });
  assert.deepEqual(draft, { zones: [{ name: "new" }], services: [] });
}

{
  const name = policyExportFilename("Running Policy", "v42", new Date("2026-06-17T15:00:00.123Z"));
  assert.equal(name, "phragma-running-policy-v42-2026-06-17T15-00-00-123Z.json");
}

{
  assert.equal(normalizeSnapshotId("snap-2026_06.22:01"), "snap-2026_06.22:01");
  assert.equal(normalizeSnapshotId("../etc/passwd"), "");
  assert.equal(normalizeSnapshotDrawer("validate"), "validate");
  assert.equal(normalizeSnapshotDrawer("restore-preview"), "restore-preview");
  assert.equal(normalizeSnapshotDrawer("stage"), "");
  assert.equal(
    snapshotRestoreReviewHash("snap-7", "restore-preview"),
    "#/changes?tab=snapshots&snapshot=snap-7&drawer=restore-preview",
  );
  assert.equal(snapshotRestoreReviewHash("../bad", "restore-preview"), "#/changes?tab=snapshots");
}

{
  const packet = snapshotRestoreReviewPacket({
    snapshot: {
      id: "snap-7",
      source: "running",
      sourceVersion: 42,
      policySha256: "abcdef0123456789",
      createdAt: "2026-06-22T12:00:00Z",
      comment: "before maintenance /var/lib/openngfw/private token=secret-value",
    },
    validation: {
      valid: true,
      issues: ["path /etc/openngfw/private and Bearer supersecrettoken"],
      warnings: [{ detail: "api_key=secret-value" }],
    },
    diff: {
      changed: true,
      lines: [{ text: "- token=secret" }, { text: "+ allow ssh" }],
      fromLabel: "running /Users/alice/policy.json",
      toLabel: "snapshot",
    },
  }, {
    route: "#/changes?tab=snapshots&snapshot=snap-7&drawer=restore-preview",
    generatedAt: "2026-06-22T12:01:00.000Z",
  });

  assert.equal(packet.schemaVersion, SNAPSHOT_RESTORE_REVIEW_SCHEMA);
  assert.equal(packet.unsigned, true);
  assert.equal(packet.custody.serverStored, false);
  assert.equal(packet.custody.signed, false);
  assert.equal(packet.custody.encrypted, false);
  assert.equal(packet.custody.antiReplay, false);
  assert.equal(packet.snapshot.id, "snap-7");
  assert.equal(packet.validation.valid, true);
  assert.equal(packet.diff.changed, true);
  assert.match(packet.replay.previewApi, /stageCandidate":false/);
  assert.match(packet.replay.stageApi, /expectedCandidateRevision/);
  assert.match(packet.candidateMutationBoundary, /No direct candidate mutation/);
  assert.doesNotMatch(snapshotRestoreReviewJson(packet), /supersecrettoken|secret-value|\/etc\/openngfw|\/var\/lib\/openngfw|\/Users\/alice/);
  assert.match(snapshotRestoreReviewText(packet), /Snapshot restore maintenance review/);
}

{
  assert.equal(
    redactPacketText("Authorization: Bearer abcdefghijklmnop /private/tmp/file password=hunter2"),
    "Authorization: Bearer [redacted] [server-local path redacted] password=[redacted]",
  );
  assert.equal(
    snapshotRestoreReviewFilename("snap 7", new Date("2026-06-22T12:00:00.123Z")),
    "phragma-snapshot-restore-review-snap-7-2026-06-22T12-00-00-123Z.json",
  );
}
