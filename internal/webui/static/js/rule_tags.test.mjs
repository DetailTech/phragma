import assert from "node:assert/strict";

import { parseRuleContextInput, parseTagInput, ruleMatchContextFromInputs, ruleMatchContextIssues, ruleMatchContextValues, tagIssues } from "./views/rules.js";

assert.deepEqual(parseTagInput("env:prod, owner:secops, pci.zone-1"), ["env:prod", "owner:secops", "pci.zone-1"]);
assert.deepEqual(parseTagInput(" baseline ,, incident-response "), ["baseline", "incident-response"]);

assert.deepEqual(tagIssues(["env:prod", "owner_secops", "pci.zone-1"]), []);
assert.match(tagIssues(["Needs Review"])[0], /invalid/);
assert.match(tagIssues(["needs review"])[0], /invalid/);
assert.match(tagIssues(["env:prod", "env:prod"])[0], /Duplicate/);
assert.match(tagIssues(Array.from({ length: 33 }, (_, i) => `tag-${i}`))[0], /at most 32/);

assert.deepEqual(parseRuleContextInput("alice@example.com, idp/secops ,, posture:edr-healthy"), ["alice@example.com", "idp/secops", "posture:edr-healthy"]);
assert.deepEqual(ruleMatchContextFromInputs({
  users: "alice@example.com",
  groups: "idp/secops, idp/helpdesk",
  devices: "laptop-123",
  postureLabels: "posture:edr-healthy",
}), {
  users: ["alice@example.com"],
  groups: ["idp/secops", "idp/helpdesk"],
  devices: ["laptop-123"],
  postureLabels: ["posture:edr-healthy"],
});
assert.deepEqual(ruleMatchContextValues({ users: ["alice@example.com"], postureLabels: ["posture:edr-healthy"] }), ["alice@example.com", "posture:edr-healthy"]);
assert.deepEqual(ruleMatchContextIssues({ users: ["alice@example.com"], groups: ["idp/secops"], devices: ["laptop-123"], postureLabels: ["posture:edr-healthy"] }), []);
assert.match(ruleMatchContextIssues({ users: ["any"] })[0], /explicit labels/);
assert.match(ruleMatchContextIssues({ groups: ["Domain Users"] })[0], /invalid/);
assert.match(ruleMatchContextIssues({ devices: ["laptop-123", "laptop-123"] })[0], /Duplicate/);
