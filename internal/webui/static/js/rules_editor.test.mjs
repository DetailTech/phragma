import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  addPendingRuleEditorObject,
  applyPendingRuleEditorObjects,
  appRuleIssues,
  parsePorts,
} from "./views/rules.js";

const rulesViewSource = readFileSync(new URL("./views/rules.js", import.meta.url), "utf8");
assert.match(rulesViewSource, /const fieldLabel = String\(opts\.field \|\| "token"\)\.replace/);
assert.match(rulesViewSource, /type: "button",\s+title: `Remove \$\{v\}`,\s+"aria-label": `Remove \$\{v\} from \$\{fieldLabel\}`/);
assert.match(rulesViewSource, /dataset: \{ ruleTokenAction: "remove", ruleTokenField: opts\.field \|\| "", ruleTokenValue: v \}/);
assert.match(rulesViewSource, /supported Suricata signals add managed L7 allow\/drop metadata controls/);

{
  const pending = {};
  const addressOptions = ["existing-host"];
  const name = addPendingRuleEditorObject(pending, "address", {
    name: "web-server",
    cidr: "10.0.2.20/32",
    description: "Created from test.",
  }, addressOptions);

  assert.equal(name, "web-server");
  assert.deepEqual(addressOptions, ["existing-host", "web-server"]);
  assert.deepEqual(pending.addresses, [{
    name: "web-server",
    cidr: "10.0.2.20/32",
    description: "Created from test.",
  }]);

  const draft = { addresses: [{ name: "existing-host", cidr: "10.0.1.10/32" }], services: [] };
  applyPendingRuleEditorObjects(draft, pending);
  assert.deepEqual(draft.addresses.map((item) => item.name), ["existing-host", "web-server"]);
}

{
  const pending = {};
  const appOptions = [];
  const name = addPendingRuleEditorObject(pending, "application", {
    name: "corp-admin",
    displayName: "Corp Admin",
    category: "business-app",
    engineSignals: ["corp-admin"],
    ports: [{ protocol: "PROTOCOL_TCP", ports: [{ start: 8443 }] }],
    description: "Created from test.",
  }, appOptions);

  assert.equal(name, "corp-admin");
  assert.deepEqual(appOptions, ["corp-admin"]);
  assert.equal(appRuleIssues({
    applications: ["corp-admin"],
    services: [],
    action: "ACTION_DENY",
  }, pending.applications).length, 0);
  assert.deepEqual(appRuleIssues({
    applications: ["corp-admin"],
    services: ["https"],
    action: "ACTION_DENY",
  }, pending.applications), [
    "Remove explicit services. The selected App-ID objects supply the enforced TCP/UDP port hints.",
  ]);
  assert.deepEqual(appRuleIssues({
    applications: ["corp-admin"],
    services: [],
    action: "ACTION_ALLOW",
  }, pending.applications), []);

  const draft = { applications: [] };
  applyPendingRuleEditorObjects(draft, pending);
  assert.deepEqual(draft.applications, [{
    name: "corp-admin",
    displayName: "Corp Admin",
    category: "business-app",
    engineSignals: ["corp-admin"],
    ports: [{ protocol: "PROTOCOL_TCP", ports: [{ start: 8443 }] }],
    description: "Created from test.",
  }]);
}

{
  assert.deepEqual(appRuleIssues({
    applications: ["signal-only"],
    services: [],
    action: "ACTION_DENY",
  }, [{
    name: "signal-only",
    category: "business-app",
    engineSignals: ["signal-only"],
    ports: [],
  }]), [
    "Application signal-only has no TCP/UDP port hints; signal-only App-ID enforcement requires IDS/IPS Prevent with Fail closed.",
    "Application signal-only has no supported Suricata App-ID signal (supported: dns, http, ssh, tls).",
  ]);

  assert.deepEqual(appRuleIssues({
    applications: ["signal-only"],
    services: [],
    action: "ACTION_DENY",
  }, [{
    name: "signal-only",
    category: "business-app",
    engineSignals: ["http"],
    ports: [],
  }], {
    ids: { enabled: true, mode: "IDS_MODE_PREVENT", failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED" },
  }), []);

  assert.deepEqual(appRuleIssues({
    applications: ["signal-only"],
    fromZones: ["lan"],
    services: [],
    action: "ACTION_DENY",
  }, [{
    name: "signal-only",
    category: "business-app",
    engineSignals: ["http"],
    ports: [],
  }], {
    ids: { enabled: true, mode: "IDS_MODE_PREVENT", failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED" },
  }), [
    "Signal-only App-ID rules cannot be scoped only by From/To zones; add TCP/UDP port hints or use Source/Destination address scope.",
  ]);

  assert.deepEqual(appRuleIssues({
    applications: ["signal-only"],
    sourceAddresses: ["hq-net"],
    destinationAddresses: ["saas-net"],
    services: [],
    action: "ACTION_DENY",
  }, [{
    name: "signal-only",
    category: "business-app",
    engineSignals: ["http"],
    ports: [],
  }], {
    ids: { enabled: true, mode: "IDS_MODE_PREVENT", failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED" },
  }), []);

  assert.deepEqual(appRuleIssues({
    applications: ["signal-only"],
    services: [],
    action: "ACTION_ALLOW",
  }, [{
    name: "signal-only",
    category: "business-app",
    engineSignals: ["http"],
    ports: [],
  }], {
    ids: { enabled: true, mode: "IDS_MODE_PREVENT", failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED" },
  }), [
    "Application signal-only has no TCP/UDP port hints; signal-only App-ID Allow cannot preserve a bounded nftables forwarding path.",
  ]);
}

{
  const pending = {};
  const serviceOptions = [];
  const ports = parsePorts("443,8000-8010");
  const name = addPendingRuleEditorObject(pending, "service", {
    name: "web-ports",
    protocol: "PROTOCOL_TCP",
    ports,
  }, serviceOptions);

  assert.equal(name, "web-ports");
  assert.deepEqual(serviceOptions, ["web-ports"]);

  const draft = { services: [{ name: "web-ports", protocol: "PROTOCOL_TCP", ports: [{ start: 443 }] }] };
  applyPendingRuleEditorObjects(draft, pending);
  assert.equal(draft.services.length, 1);
  assert.deepEqual(draft.services[0].ports, [{ start: 443 }]);
}
