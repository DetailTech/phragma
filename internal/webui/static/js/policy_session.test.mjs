import assert from "node:assert/strict";

import { api, ApiError } from "./api.js";
import { session } from "./policy.js";

const originalApi = {
  running: api.running,
  candidate: api.candidate,
  setCandidate: api.setCandidate,
  candidateStatus: api.candidateStatus,
  validate: api.validate,
  commit: api.commit,
};

function resetSession() {
  session.running = {};
  session.runningVersion = 0;
  session.draft = {};
  session.hasCandidate = false;
  session.candidateStatus = null;
  session.candidateRevision = "";
  session.candidateLoadError = null;
}

async function withMockedApi(fn) {
  resetSession();
  try {
    await fn();
  } finally {
    Object.assign(api, originalApi);
    resetSession();
  }
}

const runningPolicy = {
  rules: [{ name: "allow-dns", action: "ACTION_ALLOW", services: ["dns"] }],
  zones: [{ name: "lan" }, { name: "wan" }],
};

await withMockedApi(async () => {
  let candidateCalls = 0;
  let setCandidateCalls = 0;
  let validateCalls = 0;
  let statusRevision = "none:12";
  api.running = async () => ({ version: 12, policy: runningPolicy });
  api.candidate = async () => {
    candidateCalls++;
    throw new ApiError(404, "candidate not found", {});
  };
  api.candidateStatus = async () => ({ hasCandidate: false, dirty: false, changeCount: 0, changes: [], candidateRevision: statusRevision });
  api.setCandidate = async (policy, expectedCandidateRevision) => {
    setCandidateCalls++;
    assert.deepEqual(policy, session.draft);
    assert.equal(expectedCandidateRevision, "none:12");
    statusRevision = "sha256:validated";
    return { candidateRevision: statusRevision };
  };
  api.validate = async () => {
    validateCalls++;
    return { valid: true };
  };

  await session.load();

  assert.equal(session.runningVersion, 12);
  assert.equal(session.candidateUnavailable, false);
  assert.equal(session.candidateLoadError, null);
  assert.equal(session.dirty, false);
  assert.deepEqual(session.draft, runningPolicy);
  assert.equal(candidateCalls, 0);

  const result = await session.validate();
  assert.deepEqual(result, { valid: true });
  assert.equal(setCandidateCalls, 1);
  assert.equal(validateCalls, 1);
  assert.equal(session.candidateRevision, "sha256:validated");
});

await withMockedApi(async () => {
  let setCandidateCalls = 0;
  let statusCalls = 0;
  api.running = async () => ({ version: 12, policy: runningPolicy });
  api.candidate = async () => { throw new ApiError(404, "candidate not found", {}); };
  api.candidateStatus = async () => {
    statusCalls++;
    return { hasCandidate: false, dirty: false, changeCount: 0, changes: [], candidateRevision: "none:12" };
  };
  api.setCandidate = async () => {
    setCandidateCalls++;
    return {};
  };

  await session.load();

  await assert.rejects(
    session.apply((draft) => {
      draft.rules.push({ name: "partial-local-change", action: "ACTION_ALLOW" });
      throw new Error("mutator failed");
    }),
    /mutator failed/,
  );

  assert.equal(setCandidateCalls, 0);
  assert.equal(statusCalls, 1);
  assert.deepEqual(session.draft, runningPolicy);
  assert.equal(session.dirty, false);
});

await withMockedApi(async () => {
  let setCandidateCalls = 0;
  let validateCalls = 0;
  let commitCalls = 0;
  let mutatorCalled = false;
  api.running = async () => ({ version: 12, policy: runningPolicy });
  api.candidate = async () => { throw new ApiError(500, "candidate store unavailable", {}); };
  api.candidateStatus = async () => ({ hasCandidate: true, dirty: true, changeCount: 2, changes: [{ section: "rules", added: 2 }], candidateRevision: "sha256:unavailable" });
  api.setCandidate = async () => { setCandidateCalls++; return {}; };
  api.validate = async () => { validateCalls++; return { valid: true }; };
  api.commit = async () => { commitCalls++; return { version: 13 }; };

  await session.load();

  assert.equal(session.dirty, false);
  assert.equal(session.hasCandidate, false);
  assert.equal(session.candidateUnavailable, true);
  assert.match(session.candidateUnavailableMessage(), /candidate store unavailable/);
  assert.deepEqual(session.draft, runningPolicy);
  assert.deepEqual(session.serverChangeSummary(), []);
  assert.equal(session.serverChangeCount(), 0);

  await assert.rejects(
    session.apply(() => { mutatorCalled = true; }),
    /Cannot stage policy edits; The staged candidate could not be loaded/,
  );
  await assert.rejects(session.validate(), /Cannot validate the candidate/);
  await assert.rejects(session.commit("blocked"), /Cannot commit the candidate/);
  await assert.rejects(session.discard(), /Cannot discard the candidate/);

  assert.equal(mutatorCalled, false);
  assert.equal(setCandidateCalls, 0);
  assert.equal(validateCalls, 0);
  assert.equal(commitCalls, 0);
});

await withMockedApi(async () => {
  const candidatePolicy = {
    ...runningPolicy,
    rules: runningPolicy.rules.concat([{ name: "allow-web", action: "ACTION_ALLOW", services: ["https"] }]),
  };
  api.running = async () => ({ version: 12, policy: runningPolicy });
  api.candidate = async () => ({ policy: candidatePolicy });
  api.candidateStatus = async () => ({ hasCandidate: true, dirty: true, changeCount: 1, changes: [{ section: "rules", added: 1 }], candidateRevision: "sha256:candidate" });

  await session.load();

  assert.equal(session.candidateUnavailable, false);
  assert.equal(session.candidateLoadError, null);
  assert.equal(session.dirty, true);
  assert.equal(session.candidateRevision, "sha256:candidate");
  assert.equal(session.serverChangeCount(), 1);
  assert.deepEqual(session.serverChangeSummary(), ["1 rule added"]);
});

await withMockedApi(async () => {
  const candidatePolicy = {
    ...runningPolicy,
    rules: runningPolicy.rules.concat([{ name: "allow-reviewed", action: "ACTION_ALLOW", services: ["https"] }]),
  };
  let setCandidateCalls = 0;
  let commitExpectedRevision = "";
  api.running = async () => ({ version: 12, policy: runningPolicy });
  api.candidate = async () => ({ policy: candidatePolicy });
  api.candidateStatus = async () => ({ hasCandidate: true, dirty: true, changeCount: 1, changes: [{ section: "rules", added: 1 }], candidateRevision: "sha256:reviewed" });
  api.setCandidate = async () => {
    setCandidateCalls++;
    return { candidateRevision: "sha256:unexpected-restage" };
  };
  api.commit = async (_comment, _ackRisk, _ackRuntime, _approvalId, expectedCandidateRevision) => {
    commitExpectedRevision = expectedCandidateRevision;
    return { version: 13 };
  };

  await session.load();
  const result = await session.commit("reviewed commit", true, true, "9", "sha256:reviewed");

  assert.equal(result.version, 13);
  assert.equal(setCandidateCalls, 0);
  assert.equal(commitExpectedRevision, "sha256:reviewed");
});

await withMockedApi(async () => {
  let setCandidateExpectedRevision = "";
  let statusRevision = "none:12";
  api.running = async () => ({ version: 12, policy: runningPolicy });
  api.candidate = async () => { throw new ApiError(404, "candidate not found", {}); };
  api.candidateStatus = async () => ({ hasCandidate: false, dirty: false, changeCount: 0, changes: [], candidateRevision: statusRevision });
  api.setCandidate = async (_policy, expectedCandidateRevision) => {
    setCandidateExpectedRevision = expectedCandidateRevision;
    statusRevision = "sha256:after-apply";
    return { candidateRevision: statusRevision };
  };

  await session.load();
  await session.apply((draft) => {
    draft.rules.push({ name: "allow-web", action: "ACTION_ALLOW" });
  });

  assert.equal(setCandidateExpectedRevision, "none:12");
  assert.equal(session.candidateRevision, "sha256:after-apply");
});

await withMockedApi(async () => {
  let setCandidateCalls = 0;
  let statusCalls = 0;
  let notified = 0;
  const candidatePolicy = {
    ...runningPolicy,
    rules: runningPolicy.rules.concat([{ name: "allow-web", action: "ACTION_ALLOW", services: ["https"] }]),
  };
  api.running = async () => ({ version: 12, policy: runningPolicy });
  api.candidate = async () => ({ policy: candidatePolicy });
  api.candidateStatus = async () => {
    statusCalls++;
    return { hasCandidate: true, dirty: true, changeCount: 1, changes: [{ section: "rules", added: 1 }], candidateRevision: statusCalls === 1 ? "sha256:loaded" : "sha256:staged" };
  };
  api.setCandidate = async (policy, expectedCandidateRevision) => {
    setCandidateCalls++;
    assert.deepEqual(policy, candidatePolicy);
    assert.equal(expectedCandidateRevision, "sha256:loaded");
    return { candidateRevision: "sha256:staged" };
  };

  const unsubscribe = session.subscribe(() => { notified++; });
  await session.load();
  const before = structuredClone(session.draft);
  const result = await session.stageDraft("run candidate flow check");
  unsubscribe();

  assert.deepEqual(result, { candidateRevision: "sha256:staged" });
  assert.equal(setCandidateCalls, 1);
  assert.equal(statusCalls, 2);
  assert.equal(session.candidateRevision, "sha256:staged");
  assert.deepEqual(session.draft, before);
  assert.equal(session.dirty, true);
  assert.equal(notified, 2);
});

await withMockedApi(async () => {
  api.running = async () => ({ version: 12, policy: runningPolicy });
  api.candidate = async () => ({ policy: runningPolicy });
  api.candidateStatus = async () => ({ hasCandidate: true, dirty: false, changeCount: 0, changes: [] });
  api.setCandidate = async () => {
    throw new Error("unguarded write should not run");
  };

  await session.load();

  await assert.rejects(
    session.apply((draft) => {
      draft.rules.push({ name: "blocked", action: "ACTION_ALLOW" });
    }),
    /candidate revision is unavailable/,
  );
});

await withMockedApi(async () => {
  let setCandidateCalls = 0;
  api.running = async () => ({ version: 12, policy: runningPolicy });
  api.candidate = async () => ({ policy: runningPolicy });
  api.candidateStatus = async () => ({ hasCandidate: true, dirty: false, changeCount: 0, changes: [] });
  api.setCandidate = async () => {
    setCandidateCalls++;
    throw new Error("unguarded write should not run");
  };

  await session.load();

  await assert.rejects(
    session.stageDraft("verify changed rules"),
    /candidate revision is unavailable/,
  );
  assert.equal(setCandidateCalls, 0);
});
