import assert from "node:assert/strict";
import { applyNetworkProfile, applyNetworkProfileToPolicy, matchingNetworkProfile, networkProfileBlockers } from "./network_profiles.js";

const current = {
  mtu: 0,
  clampMssToPmtu: false,
  manageNicOffloads: true,
  enableFlowOffload: false,
  interfaceMtus: [{ interface: "mgmt0", mtu: 1500 }],
};

const throughput = applyNetworkProfile(current, "throughput");
assert.equal(throughput.mtu, 9000);
assert.equal(throughput.clampMssToPmtu, true);
assert.equal(throughput.manageNicOffloads, false);
assert.equal(throughput.enableFlowOffload, true);
assert.deepEqual(throughput.interfaceMtus, [{ interface: "mgmt0", mtu: 1500 }]);
assert.notEqual(throughput.interfaceMtus, current.interfaceMtus);
assert.equal(matchingNetworkProfile(throughput)?.id, "throughput");

const inspected = applyNetworkProfile(throughput, "inspection");
assert.equal(inspected.mtu, 0);
assert.equal(inspected.manageNicOffloads, true);
assert.equal(inspected.enableFlowOffload, false);
assert.equal(matchingNetworkProfile(inspected)?.id, "inspection");

const unknown = applyNetworkProfile(current, "missing");
assert.deepEqual(unknown, current);
assert.notEqual(unknown, current);
assert.equal(matchingNetworkProfile({ mtu: 9100, clampMssToPmtu: true }), null);

const inspectedPolicy = {
  ids: { enabled: true, mode: "IDS_MODE_PREVENT" },
  network: current,
  rules: [{ name: "allow-web" }],
};
const blocked = applyNetworkProfileToPolicy(inspectedPolicy, "throughput");
assert.equal(blocked.ok, false);
assert.equal(blocked.profile.id, "throughput");
assert.match(blocked.blockers.join("\n"), /requires IDS\/IPS disabled/);
assert.deepEqual(blocked.policy, inspectedPolicy);
assert.notEqual(blocked.policy, inspectedPolicy);
assert.ok(networkProfileBlockers(inspectedPolicy, "throughput").length);

const staged = applyNetworkProfileToPolicy(inspectedPolicy, "inspection");
assert.equal(staged.ok, true);
assert.equal(staged.profile.id, "inspection");
assert.equal(staged.policy.network.enableFlowOffload, false);
assert.equal(staged.policy.network.manageNicOffloads, true);
assert.deepEqual(staged.policy.rules, inspectedPolicy.rules);
assert.notEqual(staged.policy.rules, inspectedPolicy.rules);
assert.deepEqual(inspectedPolicy.network, current);

const forwardingPolicy = { ids: { enabled: false }, network: current };
const fastPath = applyNetworkProfileToPolicy(forwardingPolicy, "throughput");
assert.equal(fastPath.ok, true);
assert.equal(fastPath.policy.network.mtu, 9000);
assert.equal(fastPath.policy.network.enableFlowOffload, true);
assert.equal(fastPath.policy.network.manageNicOffloads, false);

const missingProfile = applyNetworkProfileToPolicy(forwardingPolicy, "missing");
assert.equal(missingProfile.ok, false);
assert.match(missingProfile.blockers.join("\n"), /Unknown network profile/);
