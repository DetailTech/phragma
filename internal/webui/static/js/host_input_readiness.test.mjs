import assert from "node:assert/strict";

import { hostInputManagementCoverage, managementRuleTemplate } from "./host_input_readiness.js";

const status = { runtime: { httpListen: "0.0.0.0:8443" } };
const basePolicy = {
  zones: [{ name: "lan" }, { name: "wan" }],
  addresses: [{ name: "admin-net", cidr: "10.0.0.0/24" }],
  services: [
    { name: "ssh", protocol: "PROTOCOL_TCP", ports: [{ start: 22 }] },
    { name: "webui", protocol: "PROTOCOL_TCP", ports: [{ start: 8443 }] },
    { name: "dns", protocol: "PROTOCOL_UDP", ports: [{ start: 53 }] },
    { name: "all-tcp", protocol: "PROTOCOL_TCP", ports: [] },
  ],
};

{
  const result = hostInputManagementCoverage({ ...basePolicy }, status);
  assert.equal(result.state, "open");
  assert.equal(result.cls, "warn");
  assert.deepEqual(result.requiredServices.map((svc) => svc.port), [22, 8443]);
}

{
  const result = hostInputManagementCoverage({
    ...basePolicy,
    hostInput: { defaultAction: "ACTION_DENY", rules: [] },
  }, status);
  assert.equal(result.state, "lockout");
  assert.equal(result.cls, "bad");
}

{
  const result = hostInputManagementCoverage({
    ...basePolicy,
    hostInput: {
      defaultAction: "ACTION_DENY",
      rules: [{
        name: "allow-management",
        fromZones: ["lan"],
        sourceAddresses: ["admin-net"],
        services: ["ssh", "webui"],
        action: "ACTION_ALLOW",
      }],
    },
  }, status);
  assert.equal(result.state, "covered");
  assert.deepEqual(result.allowRules, ["allow-management"]);
}

{
  const result = hostInputManagementCoverage({
    ...basePolicy,
    hostInput: {
      defaultAction: "ACTION_DENY",
      rules: [{
        name: "allow-any-management",
        services: ["any"],
        action: "ACTION_ALLOW",
      }],
    },
  }, status);
  assert.equal(result.state, "overbroad");
  assert.deepEqual(result.allowRules, ["allow-any-management"]);
}

{
  const result = hostInputManagementCoverage({
    ...basePolicy,
    hostInput: {
      defaultAction: "ACTION_DENY",
      rules: [{
        name: "allow-missing-service",
        fromZones: ["lan"],
        sourceAddresses: ["admin-net"],
        services: ["ssh", "missing-webui"],
        action: "ACTION_ALLOW",
      }],
    },
  }, status);
  assert.equal(result.state, "lockout");
}

{
  const result = hostInputManagementCoverage({
    ...basePolicy,
    hostInput: {
      defaultAction: "ACTION_DENY",
      rules: [{
        name: "allow-unverified",
        fromZones: ["lan"],
        sourceAddresses: ["admin-net"],
        services: ["any", "missing-webui"],
        action: "ACTION_ALLOW",
      }],
    },
  }, status);
  assert.equal(result.state, "unverified");
}

{
  const template = managementRuleTemplate(basePolicy, status);
  assert.equal(template.action, "ACTION_ALLOW");
  assert.equal(template.log, true);
  assert.deepEqual(template.fromZones, ["lan"]);
  assert.deepEqual(template.services, ["ssh", "webui"]);
}
