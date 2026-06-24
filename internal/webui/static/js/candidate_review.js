// candidate_review.js - pure state model for the persistent Changes candidate
// review cockpit.

export function candidateReviewModel({
  dirty = false,
  candidateUnavailable = false,
  candidateUnavailableMessage = "",
  runningVersion = 0,
  changeCount = 0,
  changeSummary = [],
  validation = null,
  validationError = null,
  runtime = null,
  impact = null,
  diff = null,
} = {}) {
  if (candidateUnavailable) {
    return {
      state: "blocked",
      title: "Candidate unavailable",
      detail: candidateUnavailableMessage || "The staged candidate could not be loaded.",
      changeLabel: "unavailable",
      validationLabel: "blocked",
      validationTone: "bad",
      runtimeLabel: "unknown",
      runtimeTone: "warn",
      impactLabel: "unknown",
      impactTone: "warn",
      commitLabel: "blocked",
      commitTone: "bad",
      diffLabel: "unavailable",
    };
  }

  if (!dirty) {
    return {
      state: "clean",
      title: "Candidate matches running policy",
      detail: `Running policy v${runningVersion || 0} has no staged changes.`,
      changeLabel: "clean",
      validationLabel: "not needed",
      validationTone: "neutral",
      runtimeLabel: "not needed",
      runtimeTone: "neutral",
      impactLabel: "none",
      impactTone: "neutral",
      commitLabel: "nothing to commit",
      commitTone: "neutral",
      diffLabel: "no diff",
    };
  }

  const valid = Boolean(validation?.valid);
  const validationLabel = validationError ? "error" : valid ? "passed" : "failed";
  const validationTone = validationError || !valid ? "bad" : "ok";
  const runtimeLabel = runtime?.label || "unknown";
  const runtimeTone = runtime?.cls || "warn";
  const impactLabel = impact?.level || "unknown";
  const impactTone = impactToneFor(impactLabel);
  const runtimeBlocked = runtimeLabel === "not ready" || runtimeTone === "bad";
  const runtimeNeedsAck = Boolean(runtime?.requiresAck);
  const commitBlocked = validationError || !valid || runtimeBlocked;
  const commitLabel = commitBlocked ? "blocked" : runtimeNeedsAck || impactLabel === "high" ? "requires review" : "ready";

  return {
    state: commitBlocked ? "blocked" : runtimeNeedsAck || impactLabel === "high" ? "review" : "ready",
    title: `${Number(changeCount) || 0} pending change${Number(changeCount) === 1 ? "" : "s"}`,
    detail: changeSummary.length ? changeSummary.slice(0, 5).join(", ") : "Candidate differs from running policy.",
    changeLabel: `${Number(changeCount) || 0} change${Number(changeCount) === 1 ? "" : "s"}`,
    validationLabel,
    validationTone,
    runtimeLabel,
    runtimeTone,
    impactLabel,
    impactTone,
    commitLabel,
    commitTone: commitBlocked ? "bad" : commitLabel === "requires review" ? "warn" : "ok",
    diffLabel: diff?.source === "fallback" ? "local diff" : "server diff",
  };
}

export function governanceApprovalModel({
  dirty = false,
  runningVersion = 0,
  changeCount = 0,
  changeSummary = [],
  validation = null,
  validationError = null,
  runtime = null,
  impact = null,
  diff = null,
} = {}) {
  const valid = Boolean(validation?.valid);
  const impactLevel = impact?.level || "unknown";
  const runtimeLabel = runtime?.label || "unknown";
  const runtimeTone = runtime?.cls || "warn";
  const runtimeBlocked = runtimeLabel === "not ready" || runtimeTone === "bad";
  const runtimeNeedsAck = Boolean(runtime?.requiresAck);
  const validationBlocked = Boolean(validationError || !valid);
  const highImpact = impactLevel === "high";
  const mediumImpact = impactLevel === "medium";
  const changeTotal = Number(changeCount) || 0;
  const required = Boolean(dirty);
  const riskFactors = [];
  const reviewerRoles = [];

  if (!required) {
    return {
      state: "clean",
      required: false,
      title: "No approval packet needed",
      detail: `Running policy v${Number(runningVersion) || 0} has no staged changes.`,
      approvalLabel: "not needed",
      approvalTone: "neutral",
      ticketRequired: false,
      reviewerRoles,
      riskFactors,
      changeSummary: [],
      commit: "nothing to commit",
      custodyNote: governanceCustodyNote(),
      diffSummary: summarizeDiff(diff),
    };
  }

  reviewerRoles.push("Firewall policy owner");
  if (validationBlocked) {
    riskFactors.push(validationError ? "candidate validation unavailable" : "candidate validation failed");
    reviewerRoles.push("Security reviewer");
  }
  if (runtimeBlocked || runtimeNeedsAck) {
    riskFactors.push(runtimeBlocked ? "system preflight blocker" : "system preflight acknowledgement required");
    reviewerRoles.push("Platform/runtime owner");
  }
  if (highImpact || mediumImpact) {
    riskFactors.push(`${impactLevel} policy impact`);
    reviewerRoles.push(highImpact ? "Security change approver" : "Peer reviewer");
  }
  if (changeTotal >= 10) {
    riskFactors.push("large candidate change set");
    reviewerRoles.push("Change manager");
  }
  if (!riskFactors.length) riskFactors.push("standard candidate review");

  const state = validationBlocked || runtimeBlocked ? "blocked" : highImpact || runtimeNeedsAck ? "approval-required" : "review";
  return {
    state,
    required,
    title: state === "blocked" ? "Approval packet needs remediation" : state === "approval-required" ? "Approval packet required" : "Approval packet ready",
    detail: approvalDetail({ changeTotal, impactLevel, runtimeLabel, validationBlocked }),
    approvalLabel: state === "blocked" ? "blocked" : state === "approval-required" ? "approval required" : "standard review",
    approvalTone: state === "blocked" ? "bad" : state === "approval-required" ? "warn" : "ok",
    ticketRequired: true,
    reviewerRoles: uniqueStrings(reviewerRoles),
    riskFactors: uniqueStrings(riskFactors),
    changeSummary: changeSummary.slice(0, 8),
    commit: validationBlocked || runtimeBlocked ? "blocked" : runtimeNeedsAck || highImpact ? "requires review" : "ready",
    custodyNote: governanceCustodyNote(),
    diffSummary: summarizeDiff(diff),
  };
}

export function changesLifecycleGuidanceModel({
  scenario = "candidate",
  candidateDirty = false,
  runningVersion = 0,
  targetVersion = 0,
  validationBlocked = false,
  runtimeBlocked = false,
  strictUiApplyRequired = false,
} = {}) {
  const dirty = Boolean(candidateDirty);
  const versionLabel = targetVersion ? `v${Number(targetVersion)}` : "the selected version";
  const runningLabel = runningVersion ? `v${Number(runningVersion)}` : "the current running version";
  const blocked = Boolean(validationBlocked || runtimeBlocked);

  if (scenario === "rollback") {
    return {
      scenario,
      title: `Rollback re-applies ${versionLabel} as a new version`,
      consequence: "A successful rollback validates the historical policy, applies it to the live firewall, writes rollback intent/success audit entries, creates a new running version, and clears the candidate workspace.",
      guidanceTone: dirty ? "warn" : "info",
      guidanceLabel: dirty ? "candidate will be cleared" : "candidate remains clean",
      operatorDecision: dirty
        ? "Export or preserve any staged candidate work before rollback, because rollback activation clears the candidate just like commit."
        : "No staged candidate cleanup is required before rollback.",
      runbookTitle: "Rollback cleanup/preserve runbook",
      steps: [
        dirty ? "Preserve staged work first if it should survive rollback: export the candidate or copy the current diff before applying rollback." : "Confirm the candidate workspace is clean before rollback.",
        `Apply rollback only after validation and runtime preflight are acceptable: ngfwctl rollback ${Number(targetVersion) || "<version>"} --message "<reason>"${blocked ? " --ack-runtime/--ack-risk when the preflight requires it" : ""}.`,
        "After rollback succeeds, verify the new running version and candidate state: ngfwctl policy status and ngfwctl policy diff.",
        "If candidate status is still dirty after a blocked or failed rollback, choose Preserve by leaving it staged, or Cleanup by returning to Changes and selecting Discard candidate.",
      ],
      commands: [
        "ngfwctl policy status",
        `ngfwctl policy show --source version --version ${Number(targetVersion) || "<version>"}`,
        `ngfwctl rollback ${Number(targetVersion) || "<version>"} --message "<reason>"`,
        "ngfwctl policy diff",
      ],
      custodyNote: "This is operator guidance only; server-side approval custody, signed preserve artifacts, and cleanup enforcement remain hardening work.",
    };
  }

  if (scenario === "strict-blocked") {
    return {
      scenario,
      title: "Strict UI apply is blocking direct apply fallback",
      consequence: "The browser smoke gate is intentionally refusing direct API fallback because the runtime is not ready for UI apply. The live firewall is unchanged and the candidate remains staged.",
      guidanceTone: "warn",
      guidanceLabel: strictUiApplyRequired ? "strict UI gate active" : "apply blocked",
      operatorDecision: "Preserve the candidate while fixing system preflight items, or explicitly discard it if the staged change should not proceed.",
      runbookTitle: "Strict-block cleanup/preserve runbook",
      steps: [
        "Preserve: leave the candidate staged and resolve each system preflight item before retrying UI Commit candidate or Roll back.",
        "Cleanup: if the candidate is no longer intended, return to Changes > Candidate and select Discard candidate; this resets candidate to the running policy without changing the live firewall.",
        "Verify either path with candidate status and diff before rerunning strict UI apply evidence.",
      ],
      commands: [
        "ngfwctl policy status",
        "ngfwctl policy validate",
        "ngfwctl policy diff",
        "WEBUI_SMOKE_REQUIRE_CHANGES_UI_APPLY=1 make webui-enterprise-smoke",
      ],
      custodyNote: "This does not implement production custody or approval enforcement; it documents the operator decision boundary around strict UI apply blocking.",
    };
  }

  if (scenario === "discard") {
    return {
      scenario,
      title: "Discard cleans only the candidate",
      consequence: `Discard resets staged edits to match ${runningLabel}; the live firewall and version history are unchanged.`,
      guidanceTone: "warn",
      guidanceLabel: "candidate cleanup",
      operatorDecision: "Use Discard only when staged changes should not be preserved for commit or rollback comparison.",
      runbookTitle: "Discard cleanup runbook",
      steps: [
        "Export or copy candidate diff first if the staged work may be needed later.",
        "Select Discard candidate in Changes > Candidate and confirm the destructive candidate-only reset.",
        "Verify candidate status is clean and the running version did not change.",
      ],
      commands: ["ngfwctl policy status", "ngfwctl policy diff"],
      custodyNote: "Discard is not an approval or retention workflow; signed candidate preservation remains hardening work.",
    };
  }

  return {
    scenario: "candidate",
    title: "Commit promotes the candidate",
    consequence: "A successful commit validates the candidate, applies it to the live firewall, writes commit intent/success audit entries, creates a new running version, and clears the candidate workspace.",
    guidanceTone: blocked ? "warn" : "info",
    guidanceLabel: blocked ? "preserve until ready" : dirty ? "ready for review" : "no staged changes",
    operatorDecision: dirty
      ? "Commit clears the candidate after activation; preserve the diff/export before commit if the staged work needs external review."
      : "No cleanup is needed while the candidate matches running policy.",
    runbookTitle: blocked ? "Blocked commit preserve runbook" : "Commit cleanup/preserve runbook",
    steps: [
      dirty ? "Review validation, system preflight, impact, and diff before commit." : "Stage a candidate before using commit cleanup guidance.",
      blocked ? "Preserve the staged candidate while fixing validation or runtime blockers; do not discard unless the staged change should be abandoned." : "After commit succeeds, verify the new running version and clean candidate status.",
      "If strict UI apply blocks the action, follow the strict-block runbook instead of using direct API fallback.",
    ],
    commands: ["ngfwctl policy status", "ngfwctl policy validate", "ngfwctl policy diff", "ngfwctl commit --message \"<reason>\""],
    custodyNote: "This guidance is browser-local and operational; production approval custody and retention controls remain hardening work.",
  };
}

function impactToneFor(level = "") {
  if (level === "high") return "bad";
  if (level === "medium") return "warn";
  if (level === "low") return "ok";
  return "warn";
}

function approvalDetail({ changeTotal, impactLevel, runtimeLabel, validationBlocked }) {
  const parts = [`${changeTotal} pending change${changeTotal === 1 ? "" : "s"}`];
  if (impactLevel) parts.push(`${impactLevel} impact`);
  if (runtimeLabel) parts.push(`runtime ${runtimeLabel}`);
  if (validationBlocked) parts.push("validation blocked");
  return parts.join("; ");
}

function summarizeDiff(diff = null) {
  return {
    source: diff?.source || "unknown",
    fromLabel: diff?.fromLabel || "",
    toLabel: diff?.toLabel || "",
    changed: Boolean(diff?.changed),
    lineCount: Array.isArray(diff?.lines) ? diff.lines.length : 0,
  };
}

function governanceCustodyNote() {
  return "Browser-local approval packet plus server-side approval record; signed custody, external CAB integration, and separation-of-duties policy remain hardening work.";
}

function uniqueStrings(values = []) {
  const seen = new Set();
  const out = [];
  for (const value of values) {
    const text = String(value || "").trim();
    if (!text || seen.has(text)) continue;
    seen.add(text);
    out.push(text);
  }
  return out;
}
