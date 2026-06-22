import assert from "node:assert/strict";

import { applyBaselinePolicy, policyNeedsBaseline, previewBaselinePolicy } from "./baseline.js";

{
  const policy = {};
  assert.equal(policyNeedsBaseline(policy), true);
  const summary = applyBaselinePolicy(policy, {
    profile: "throughput",
    insideZone: "lan",
    outsideZone: "wan",
    insideInterfaces: "eth1",
    outsideInterfaces: "eth0",
    insideCidr: "10.10.0.0/24",
  });

  assert.equal(policyNeedsBaseline(policy), false);
  assert.deepEqual(policy.zones.map((zone) => zone.name), ["lan", "wan"]);
  assert.equal(policy.network.enableFlowOffload, true);
  assert.equal(policy.network.clampMssToPmtu, true);
  assert.equal(policy.ids.enabled, false);
  assert.equal(policy.hostInput.defaultAction, "ACTION_DENY");
  assert.equal(policy.nat.source[0].masquerade, true);
  assert.ok(policy.rules.some((rule) => rule.name === "allow-lan-to-wan"));
  assert.equal(summary.profile, "throughput");
  assert.ok(summary.network.includes("flowtable fast path"));
  assert.ok(summary.ids.includes("IDS/IPS disabled"));
}

{
  const policy = { network: { enableFlowOffload: true } };
  applyBaselinePolicy(policy, {
    profile: "ids-detect",
    insideCidr: "10.20.0.0/24",
    idsRuleFiles: "emerging.rules, local.rules",
  });

  assert.equal(policy.network.enableFlowOffload, false);
  assert.equal(policy.network.manageNicOffloads, true);
  assert.equal(policy.ids.enabled, true);
  assert.equal(policy.ids.mode, "IDS_MODE_DETECT");
  assert.deepEqual(policy.ids.homeNetworks, ["10.20.0.0/24"]);
  assert.deepEqual(policy.ids.ruleFiles, ["emerging.rules", "local.rules"]);
  assert.equal(policy.ids.failureBehavior, undefined);
}

{
  const policy = { network: { enableFlowOffload: true, manageNicOffloads: true } };
  applyBaselinePolicy(policy, {
    profile: "ips-prevent",
    failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_OPEN",
    idsQueueNum: "7",
  });

  assert.equal(policy.network.enableFlowOffload, false);
  assert.equal(policy.network.manageNicOffloads, false);
  assert.equal(policy.ids.enabled, true);
  assert.equal(policy.ids.mode, "IDS_MODE_PREVENT");
  assert.equal(policy.ids.failureBehavior, "IDS_FAILURE_BEHAVIOR_FAIL_OPEN");
  assert.equal(policy.ids.queueNum, 7);
}

{
  const original = {};
  const preview = previewBaselinePolicy(original, { profile: "ids-detect" });
  assert.equal(original.zones, undefined);
  assert.equal(preview.policy.ids.enabled, true);
  assert.equal(preview.policy.network.enableFlowOffload, undefined);
}
