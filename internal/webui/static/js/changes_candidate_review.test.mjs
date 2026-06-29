import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { candidateReviewModel, changesLifecycleGuidanceModel, governanceApprovalModel } from "./candidate_review.js";
import { governanceApprovalHandoffPacket } from "./investigation_packet.js";
import { candidatePreservationPacket, commitRevisionRecoveryMessage, normalizeChangesRouteState, normalizeChangesTab, strictUiEvidenceModel } from "./views/changes.js";

const changesSource = readFileSync("internal/webui/static/js/views/changes.js", "utf8");
const candidateReviewSource = readFileSync("internal/webui/static/js/candidate_review.js", "utf8");
const appSource = readFileSync("internal/webui/static/js/app.js", "utf8");
const validationSource = readFileSync("internal/webui/static/js/validation_view.js", "utf8");
assert.match(changesSource, /Commit candidate/);
assert.match(changesSource, /function openCandidateCommitReview/);
assert.match(changesSource, /function openGovernanceApprovalDrawer/);
assert.match(changesSource, /function lifecycleGuidancePanel/);
assert.match(changesSource, /changesLifecycleGuidance/);
assert.match(changesSource, /changesLifecycleRunbook/);
assert.match(changesSource, /copy-lifecycle-runbook/);
assert.match(changesSource, /Copy lifecycle cleanup and preserve runbook/);
assert.match(changesSource, /function candidatePreservationActions/);
assert.match(changesSource, /candidatePreservationPacket: "true"/);
assert.match(changesSource, /function strictUiEvidencePanel/);
assert.match(changesSource, /changesStrictUiEvidence/);
assert.match(changesSource, /Field evidence claim/);
assert.match(changesSource, /not claimed by Changes/);
assert.match(changesSource, /releaseAcceptance, strictEvidence/);
assert.match(changesSource, /candidatePreservationAction: "pin"/);
assert.match(changesSource, /candidatePreservationAction: "copy"/);
assert.match(changesSource, /candidatePreservationAction: "export"/);
assert.match(changesSource, /function pinCandidatePreservation/);
assert.match(changesSource, /function copyCandidatePreservation/);
assert.match(changesSource, /function exportCandidatePreservation/);
assert.match(changesSource, /kind: "candidate-preservation"/);
assert.match(changesSource, /Browser-local packet only; no policy mutation/);
assert.match(changesSource, /strictUiEvidence: strictUiEvidenceArtifact/);
assert.match(changesSource, /fieldEvidenceClaim: "not-claimed-by-changes"/);
assert.match(changesSource, /type: "button", title: "Refresh candidate review"/);
assert.match(changesSource, /title: "Open commit review for the current candidate"/);
assert.match(changesSource, /changesAction: "prepare-approval"/);
assert.match(changesSource, /title: "Prepare governance approval packet"/);
assert.match(changesSource, /changesServerApproval: "true"/);
assert.match(changesSource, /api\.changeApprovals\(\{ candidateRevision: revision, limit: 25 \}\)/);
assert.match(changesSource, /api\.createChangeApproval\(\{/);
assert.match(changesSource, /const reviewedCandidateRevision = String\(session\.candidateRevision/);
assert.match(changesSource, /session\.commit\([^)]*reviewedCandidateRevision/s);
assert.match(changesSource, /changesCommitRecovery: "true"/);
assert.match(changesSource, /Commit uses the candidate revision reviewed when this drawer opened/);
assert.match(changesSource, /Reload candidate state, reopen the diff/);
assert.match(changesSource, /change-approval-create/);
assert.match(changesSource, /backup-snapshot-create/);
assert.match(changesSource, /backup-snapshot-restore-stage/);
assert.match(changesSource, /Appliance snapshots/);
assert.match(changesSource, /function snapshots/);
assert.match(changesSource, /api\.backupSnapshots\(100\)/);
assert.match(changesSource, /api\.createBackupSnapshot\(\{/);
assert.match(changesSource, /api\.validateBackupSnapshot\(snapshot\.id\)/);
assert.match(changesSource, /api\.previewBackupSnapshotRestore\(snapshot\.id/);
assert.match(changesSource, /changesAction: "stage-backup-snapshot"/);
assert.match(changesSource, /function openRoutedSnapshotValidation/);
assert.match(changesSource, /function openRoutedSnapshotRestore/);
assert.match(changesSource, /function maybeOpenSnapshotDrawer/);
assert.match(changesSource, /snapshotRestoreReviewHash\(snapshot\.id/);
assert.match(changesSource, /snapshotRestoreReviewPacket/);
assert.match(changesSource, /snapshotRestoreAction: "copy-packet"/);
assert.match(changesSource, /snapshotRestoreAction: "export-packet"/);
assert.match(changesSource, /changesAction: "copy-snapshot-review-link"/);
{
  const restorePreviewSource = changesSource.slice(
    changesSource.indexOf("function openSnapshotRestorePreview"),
    changesSource.indexOf("function snapshotSummaryPanel"),
  );
  assert.match(restorePreviewSource, /api\.previewBackupSnapshotRestore\(snapshot\.id,\s*\{/);
  assert.match(restorePreviewSource, /stageCandidate: true/);
  assert.doesNotMatch(restorePreviewSource, /api\.setCandidate|session\.apply|replacePolicyDraft/);
}
assert.match(changesSource, /title: "Open candidate diff"/);
assert.match(changesSource, /title: "Discard the current candidate"/);
assert.match(candidateReviewSource, /Discard cleans only the candidate/);
assert.match(changesSource, /title: `Compare version \$\{v\.id\} to running`/);
assert.match(changesSource, /title: `Download version \$\{v\.id\} as JSON`/);
assert.match(changesSource, /title: `Open rollback review for version \$\{v\.id\}`/);
assert.match(changesSource, /governanceApprovalDrawer: "true"/);
assert.doesNotMatch(changesSource, /readinessActionHash/);
assert.match(changesSource, /function runtimePreflightActionRow/);
assert.doesNotMatch(changesSource, /Open this runtime blocker in Readiness/);
assert.match(changesSource, /runtimePreflightActionRow\(it, "candidate"\)/);
assert.match(changesSource, /runtimePreflightActionRow\(it, "rollback"\)/);
assert.match(changesSource, /api\.runtimeReadinessPreflight\(\{ targetPolicy: session\.draft, runningPolicy: session\.running, operation: "commit" \}\)/);
assert.match(changesSource, /api\.runtimeReadinessPreflight\(\{ targetPolicy: target, runningPolicy: session\.running, operation: "rollback" \}\)/);
assert.doesNotMatch(changesSource, /api\.runtimePreflight\(/);
assert.match(changesSource, /commitRuntimePreflight\(\{/);
assert.match(candidateReviewSource, /Rollback re-applies/);
assert.match(candidateReviewSource, /candidate will be cleared/);
assert.match(candidateReviewSource, /Strict UI apply is blocking direct apply fallback/);
assert.match(candidateReviewSource, /WEBUI_SMOKE_REQUIRE_CHANGES_UI_APPLY=1 make webui-enterprise-smoke/);
assert.match(changesSource, /preflight: runtimePreflight/);
assert.match(appSource, /commitRuntimePreflight\(\{/);
assert.match(appSource, /preflight: runtimePreflight/);
assert.match(changesSource, /impact-list impact-list-scroll/);
assert.match(validationSource, /impact-list impact-list-scroll/);
assert.doesNotMatch(validationSource, /class: "impact-list"\s*}/);
assert.doesNotMatch(changesSource, /runtime\.items\.slice\(0,\s*6\)/);
assert.doesNotMatch(appSource, /runtime\.items\.slice\(0,\s*6\)/);
assert.match(changesSource, /decision: "candidate-review"/);
assert.match(changesSource, /decision: "commit-review"/);
assert.match(changesSource, /decision: "rollback-review"/);
assert.match(changesSource, /Audit comment/);
assert.match(changesSource, /session\.commit\(/);
assert.match(changesSource, /ackRuntime/);

assert.equal(normalizeChangesTab(), "candidate");
assert.equal(normalizeChangesTab("candidate"), "candidate");
assert.equal(normalizeChangesTab("versions"), "versions");
assert.equal(normalizeChangesTab("snapshots"), "snapshots");
assert.equal(normalizeChangesTab("audit"), "audit");
assert.equal(normalizeChangesTab("invalid"), "candidate");

{
  const route = normalizeChangesRouteState({ tab: "candidate", drawer: "governance-approval", entry: "audit-1", version: "9" });
  assert.equal(route.tab, "candidate");
  assert.equal(route.drawer, "governance-approval");
  assert.equal(route.entry, "");
  assert.equal(route.version, "");
}

{
  const route = normalizeChangesRouteState({ tab: "candidate", drawer: "rollback" });
  assert.equal(route.tab, "candidate");
  assert.equal(route.drawer, "");
}

{
  const route = normalizeChangesRouteState({ tab: "versions", version: "7", drawer: "diff" });
  assert.equal(route.tab, "versions");
  assert.equal(route.version, "7");
  assert.equal(route.drawer, "diff");
  assert.equal(route.entry, "");
  assert.equal(route.limit, "300");
}

{
  const route = normalizeChangesRouteState({ tab: "versions", version: "0", drawer: "rollback", entry: "audit-1" });
  assert.equal(route.tab, "versions");
  assert.equal(route.version, "");
  assert.equal(route.drawer, "");
  assert.equal(route.entry, "");
}

{
  const route = normalizeChangesRouteState({ tab: "snapshots", version: "7", drawer: "rollback", entry: "audit-1" });
  assert.equal(route.tab, "snapshots");
  assert.equal(route.version, "");
  assert.equal(route.drawer, "");
  assert.equal(route.entry, "");
}

{
  const route = normalizeChangesRouteState({ tab: "snapshots", snapshot: "snap-7", drawer: "restore-preview", version: "7", entry: "audit-1" });
  assert.equal(route.tab, "snapshots");
  assert.equal(route.snapshot, "snap-7");
  assert.equal(route.drawer, "restore-preview");
  assert.equal(route.version, "");
  assert.equal(route.entry, "");
}

{
  const route = normalizeChangesRouteState({ tab: "snapshots", snapshot: "../etc/passwd", drawer: "restore-preview" });
  assert.equal(route.tab, "snapshots");
  assert.equal(route.snapshot, "");
  assert.equal(route.drawer, "");
}

{
  const route = normalizeChangesRouteState({ tab: "snapshots", snapshot: "snap-7", drawer: "validate" });
  assert.equal(route.snapshot, "snap-7");
  assert.equal(route.drawer, "validate");
}

{
  const route = normalizeChangesRouteState({ tab: "audit", version: "9", drawer: "rollback", entry: "audit-1" });
  assert.equal(route.tab, "audit");
  assert.equal(route.version, "9");
  assert.equal(route.drawer, "");
  assert.equal(route.entry, "audit-1");
}

{
  const message = commitRevisionRecoveryMessage("sha256:reviewed", "sha256:current", new Error("expected candidate revision mismatch"));
  assert.match(message, /Candidate changed after this commit review opened/);
  assert.match(message, /Reviewed revision: sha256:reviewed/);
  assert.match(message, /Current revision: sha256:current/);
  assert.match(message, /Reload candidate state, reopen the diff/);
}

{
  const model = strictUiEvidenceModel({
    operation: "commit",
    validation: { valid: true },
    runtime: { label: "ready", cls: "ok", requiresAck: false },
    releaseAcceptance: {
      ready: true,
      state: "ready",
      manifestPresent: true,
      summary: { missing: 0, invalid: 0, todo: 0 },
    },
  });
  assert.equal(model.operation, "commit");
  assert.equal(model.state, "ready");
  assert.equal(model.canClickUiApply, true);
  assert.equal(model.release.ready, false);
  assert.equal(model.release.openCount, 0);
  assert.equal(model.fieldEvidenceHref, "");
  assert.match(model.detail, /not field certification/);
  assert.ok(model.handoff.some((line) => /not treat this panel as ready-runtime field evidence/.test(line)));
}

{
  const model = strictUiEvidenceModel({
    operation: "rollback",
    validation: { valid: true },
    runtime: { label: "warnings", cls: "warn", requiresAck: true },
    releaseAcceptance: {
      ready: false,
      state: "review-needed",
      summary: { missing: 2, invalid: 1, todo: 3, reviewNeeded: 1 },
      recordability: { problems: 4 },
    },
  });
  assert.equal(model.operation, "rollback");
  assert.equal(model.state, "review");
  assert.equal(model.canClickUiApply, true);
  assert.equal(model.runtimeRequiresAck, true);
  assert.equal(model.release.openCount, 0);
  assert.doesNotMatch(model.blockers.join("\n"), /release evidence/);
}

{
  const model = strictUiEvidenceModel({
    validation: { valid: false },
    runtime: { label: "not ready", cls: "bad", requiresAck: false },
    releaseError: new Error("status unavailable"),
  });
  assert.equal(model.state, "blocked");
  assert.equal(model.canClickUiApply, false);
  assert.equal(model.release.available, false);
  assert.ok(model.blockers.includes("validation failed"));
  assert.ok(model.blockers.includes("system preflight blocks UI apply"));
}

{
  const model = candidateReviewModel({
    dirty: false,
    runningVersion: 12,
  });
  assert.equal(model.state, "clean");
  assert.equal(model.validationLabel, "not needed");
  assert.equal(model.commitLabel, "nothing to commit");
  assert.match(model.detail, /v12/);
}

{
  const model = candidateReviewModel({
    candidateUnavailable: true,
    candidateUnavailableMessage: "candidate store unavailable",
  });
  assert.equal(model.state, "blocked");
  assert.equal(model.title, "Candidate unavailable");
  assert.equal(model.validationTone, "bad");
  assert.equal(model.detail, "candidate store unavailable");
}

{
  const model = candidateReviewModel({
    dirty: true,
    changeCount: 2,
    changeSummary: ["1 rule added", "routing modified"],
    validation: { valid: true },
    runtime: { label: "ready", cls: "ok", requiresAck: false },
    impact: { level: "low" },
    diff: { source: "api" },
  });
  assert.equal(model.state, "ready");
  assert.equal(model.validationLabel, "passed");
  assert.equal(model.runtimeLabel, "ready");
  assert.equal(model.commitLabel, "ready");
  assert.equal(model.diffLabel, "server diff");
  assert.match(model.detail, /1 rule added/);
}

{
  const model = candidateReviewModel({
    dirty: true,
    changeCount: 1,
    validation: { valid: true },
    runtime: { label: "warnings", cls: "warn", requiresAck: true },
    impact: { level: "high" },
    diff: { source: "fallback" },
  });
  assert.equal(model.state, "review");
  assert.equal(model.commitLabel, "requires review");
  assert.equal(model.commitTone, "warn");
  assert.equal(model.diffLabel, "local diff");
}

{
  const model = candidateReviewModel({
    dirty: true,
    changeCount: 3,
    validation: { valid: false },
    runtime: { label: "ready", cls: "ok", requiresAck: false },
    impact: { level: "medium" },
  });
  assert.equal(model.state, "blocked");
  assert.equal(model.validationLabel, "failed");
  assert.equal(model.commitLabel, "blocked");
}

{
  const model = candidateReviewModel({
    dirty: true,
    validationError: new Error("validate failed"),
    runtime: { label: "ready", cls: "ok", requiresAck: false },
    impact: { level: "low" },
  });
  assert.equal(model.state, "blocked");
  assert.equal(model.validationLabel, "error");
  assert.equal(model.validationTone, "bad");
}

{
  const model = changesLifecycleGuidanceModel({
    scenario: "candidate",
    candidateDirty: true,
    runningVersion: 8,
  });
  assert.equal(model.scenario, "candidate");
  assert.equal(model.guidanceLabel, "ready for review");
  assert.match(model.consequence, /successful commit/);
  assert.ok(model.commands.includes('ngfwctl commit --message "<reason>"'));
  assert.match(model.custodyNote, /production approval custody/);
}

{
  const model = changesLifecycleGuidanceModel({
    scenario: "discard",
    candidateDirty: true,
    runningVersion: 8,
  });
  assert.equal(model.title, "Discard cleans only the candidate");
  assert.match(model.consequence, /live firewall and version history are unchanged/);
  assert.match(model.operatorDecision, /staged changes should not be preserved/);
}

{
  const model = changesLifecycleGuidanceModel({
    scenario: "rollback",
    candidateDirty: true,
    runningVersion: 9,
    targetVersion: 3,
    runtimeBlocked: true,
  });
  assert.equal(model.guidanceLabel, "candidate will be cleared");
  assert.match(model.title, /v3/);
  assert.match(model.consequence, /new running version, and clears the candidate workspace/);
  assert.ok(model.commands.includes('ngfwctl rollback 3 --message "<reason>"'));
  assert.ok(model.steps.some((step) => /Preserve staged work first/.test(step)));
  assert.ok(model.steps.some((step) => /Discard candidate/.test(step)));
  assert.match(model.custodyNote, /server-side approval custody/);
}

{
  const model = changesLifecycleGuidanceModel({
    scenario: "strict-blocked",
    strictUiApplyRequired: true,
  });
  assert.equal(model.guidanceLabel, "strict UI gate active");
  assert.match(model.consequence, /live firewall is unchanged and the candidate remains staged/);
  assert.ok(model.commands.includes("WEBUI_SMOKE_REQUIRE_CHANGES_UI_APPLY=1 make webui-enterprise-smoke"));
  assert.ok(model.steps.some((step) => /Preserve/.test(step)));
  assert.ok(model.steps.some((step) => /Cleanup/.test(step)));
}

{
  const lifecycle = changesLifecycleGuidanceModel({
    scenario: "rollback",
    candidateDirty: true,
    runningVersion: 9,
    targetVersion: 3,
    runtimeBlocked: true,
  });
  const packet = candidatePreservationPacket({
    lifecycle,
    dirty: true,
    runningVersion: 9,
    changeCount: 2,
    changeSummary: ["rule added", "route changed", "path /home/opc/private token=abc123"],
    validation: { valid: true, issues: [], warnings: [{}] },
    runtime: {
      label: "warnings",
      cls: "warn",
      detail: "runtime warning /tmp/secret",
      requiresAck: true,
      items: [{ level: "medium", badge: "runtime", title: "FRR reload", detail: "BGP may flap password=abc123", href: "#/readiness?action=frr" }],
    },
    impact: { level: "high", items: [{ level: "high", title: "Rollback impact", detail: "policy replacement /var/lib/openngfw/state" }] },
    diff: { source: "api", changed: true, fromLabel: "running policy", toLabel: "version 3", lines: [{ text: "+ allow-web" }, { text: "+ file /Users/alice/private api_key=abc123" }] },
    status: { dirty: true, changeCount: 2, runningVersion: 9, updatedAt: "2026-06-21T12:00:00Z" },
    releaseAcceptance: {
      ready: false,
      state: "review-needed",
      manifestPresent: false,
      summary: { missing: 1, invalid: 2, todo: 3 },
      recordability: { problems: 4 },
    },
    decision: "rollback-review",
    route: "#/changes?tab=versions&version=3&drawer=rollback",
  });
  assert.equal(packet.schemaVersion, "phragma.investigation.handoff.v1");
  assert.equal(packet.kind, "candidate-preservation");
  assert.equal(packet.summary.decision, "rollback-review");
  assert.equal(packet.summary.candidateDirty, true);
  assert.equal(packet.summary.pendingChanges, 2);
  assert.equal(packet.summary.validation, "passed");
  assert.equal(packet.summary.runtimeRequiresAck, true);
  assert.equal(packet.summary.strictUiApply, "strict evidence review");
  assert.equal(packet.summary.releaseAcceptance, "unknown");
  assert.equal(packet.summary.releaseOpenItems, 0);
  assert.equal(packet.summary.diffChanged, true);
  assert.match(packet.summary.status, /dirty; 2 pending changes; running v9/);
  assert.match(packet.summary.custody, /no policy mutation/);
  assert.deepEqual(packet.artifacts.lifecycle.commands, lifecycle.commands);
  assert.equal(packet.artifacts.candidate.status.dirty, true);
  assert.equal(packet.artifacts.validation.warningCount, 1);
  assert.equal(packet.artifacts.runtime.items[0].title, "FRR reload");
  assert.equal(packet.artifacts.strictUiEvidence.fieldEvidenceClaim, "not-claimed-by-changes");
  assert.equal(packet.artifacts.strictUiEvidence.release.openCount, 0);
  assert.equal(packet.artifacts.strictUiEvidence.readinessHref, undefined);
  assert.equal(packet.artifacts.impact.items[0].level, "high");
  assert.equal(packet.artifacts.diff.preview[0], "+ allow-web");
  assert.ok(packet.evidence.some((line) => /operator decision/.test(line)));
  assert.equal(packet.source.route, "#/changes?tab=versions&version=3&drawer=rollback");
  const text = JSON.stringify(packet);
  assert.match(text, /\[server-local path redacted\]/);
  assert.match(text, /not-claimed-by-changes/);
  assert.doesNotMatch(text, /\/home\/opc/);
  assert.doesNotMatch(text, /\/tmp\/secret/);
  assert.doesNotMatch(text, /\/var\/lib\/openngfw/);
  assert.doesNotMatch(text, /\/Users\/alice/);
  assert.doesNotMatch(text, /token=abc123/);
  assert.doesNotMatch(text, /password=abc123/);
  assert.doesNotMatch(text, /api_key=abc123/);
}

{
  const model = governanceApprovalModel({
    dirty: false,
    runningVersion: 42,
  });
  assert.equal(model.state, "clean");
  assert.equal(model.required, false);
  assert.equal(model.approvalLabel, "not needed");
  assert.match(model.detail, /v42/);
}

{
  const model = governanceApprovalModel({
    dirty: true,
    runningVersion: 5,
    changeCount: 2,
    changeSummary: ["address added", "rule updated"],
    validation: { valid: true },
    runtime: { label: "warnings", cls: "warn", requiresAck: true },
    impact: { level: "high" },
    diff: { source: "api", changed: true, lines: [{ t: "add", text: "rule" }] },
  });
  assert.equal(model.state, "approval-required");
  assert.equal(model.ticketRequired, true);
  assert.equal(model.commitReadiness, undefined);
  assert.ok(model.reviewerRoles.includes("Security change approver"));
  assert.ok(model.reviewerRoles.includes("Platform/runtime owner"));
  assert.ok(model.riskFactors.includes("high policy impact"));
}

{
  const model = governanceApprovalModel({
    dirty: true,
    changeCount: 1,
    validationError: new Error("validate failed"),
    runtime: { label: "ready", cls: "ok", requiresAck: false },
    impact: { level: "low" },
  });
  assert.equal(model.state, "blocked");
  assert.equal(model.approvalTone, "bad");
  assert.ok(model.riskFactors.includes("candidate validation unavailable"));
}

{
  const model = governanceApprovalModel({
    dirty: true,
    changeCount: 12,
    changeSummary: ["added /home/opc/private token=abc123"],
    validation: { valid: true },
    runtime: { label: "ready", cls: "ok", requiresAck: false },
    impact: { level: "medium", items: [{ level: "medium", title: "Path /tmp/secret", detail: "password=abc123" }] },
    diff: { source: "fallback", changed: true, lines: [{ t: "add", s: "added /home/opc/private token=abc123" }] },
  });
  const packet = governanceApprovalHandoffPacket({
    model,
    runningVersion: 9,
    changeCount: 12,
    changeSummary: model.changeSummary,
    validation: { valid: true, issues: [], warnings: [] },
    runtime: { label: "ready", cls: "ok", detail: "ready", requiresAck: false, items: [] },
    impact: { level: "medium", items: [{ level: "medium", title: "Path /tmp/secret", detail: "password=abc123" }] },
    diff: { source: "fallback", fromLabel: "running", toLabel: "candidate", changed: true, lines: [{ t: "add", s: "added /home/opc/private token=abc123" }] },
  }, { route: "#/changes?tab=candidate&drawer=governance-approval" });
  assert.equal(packet.schemaVersion, "phragma.investigation.handoff.v1");
  assert.equal(packet.kind, "governance-approval");
  assert.equal(packet.summary.runningVersion, 9);
  assert.equal(packet.summary.ticketRequired, true);
  assert.equal(packet.source.route, "#/changes?tab=candidate&drawer=governance-approval");
  assert.ok(packet.artifacts.diff.preview.length);
  const text = JSON.stringify(packet);
  assert.match(text, /Browser-local approval packet plus server-side approval record/);
  assert.doesNotMatch(text, /\/home\/opc/);
  assert.doesNotMatch(text, /\/tmp\/secret/);
  assert.doesNotMatch(text, /token=abc123/);
  assert.doesNotMatch(text, /password=abc123/);
}
