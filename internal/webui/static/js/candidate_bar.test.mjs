import assert from "node:assert/strict";

import { candidateBarModel } from "./candidate_bar.js";

{
  const model = candidateBarModel({
    runningVersion: 7,
    dirty: false,
    serverChangeCount: () => 0,
    serverChangeSummary: () => [],
  });
  assert.equal(model.state, "clean");
  assert.equal(model.icon, "check");
  assert.match(model.title, /clean/);
  assert.match(model.detail, /Running policy v7/);
}

{
  const model = candidateBarModel({
    runningVersion: 7,
    dirty: true,
    serverChangeCount: () => 2,
    serverChangeSummary: () => ["1 rule added", "1 NAT modified"],
  });
  assert.equal(model.state, "dirty");
  assert.equal(model.icon, "edit");
  assert.equal(model.title, "2 pending changes");
  assert.match(model.detail, /1 rule added/);
  assert.match(model.detail, /1 NAT modified/);
}

{
  const model = candidateBarModel({
    runningVersion: 7,
    candidateUnavailable: true,
    candidateUnavailableMessage: () => "candidate store unavailable",
  });
  assert.equal(model.state, "blocked");
  assert.equal(model.icon, "block");
  assert.equal(model.title, "Candidate state unavailable");
  assert.equal(model.detail, "candidate store unavailable");
}
