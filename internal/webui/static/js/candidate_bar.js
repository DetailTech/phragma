export function candidateBarModel(session = {}) {
  const runningVersion = Number(session.runningVersion || 0);
  if (session.candidateUnavailable) {
    return {
      state: "blocked",
      icon: "block",
      title: "Candidate state unavailable",
      detail: session.candidateUnavailableMessage?.() || "Reload candidate state before editing, validating, committing, or discarding.",
      count: 0,
      summary: [],
      runningVersion,
    };
  }

  const count = Number(session.serverChangeCount?.() || 0);
  const summary = Array.isArray(session.serverChangeSummary?.()) ? session.serverChangeSummary() : [];
  if (session.dirty) {
    return {
      state: "dirty",
      icon: "edit",
      title: `${count} pending change${count === 1 ? "" : "s"}`,
      detail: summary.length ? "Staged: " + summary.join(", ") : "Uncommitted candidate - not yet enforced",
      count,
      summary,
      runningVersion,
    };
  }

  return {
    state: "clean",
    icon: "check",
    title: "Policy workspace clean",
    detail: runningVersion > 0
      ? `Running policy v${runningVersion}; candidate matches running policy.`
      : "No running policy is active; stage a baseline before enforcement.",
    count: 0,
    summary: [],
    runningVersion,
  };
}
