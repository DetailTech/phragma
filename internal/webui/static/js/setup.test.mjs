import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { previewBaselinePolicy } from "./baseline.js";
import { setupBaselineCliCommand, setupConfigFromQuery, setupRouteHashFromConfig } from "./setup_context.js";
import { SETUP_SCENARIOS, discoveredSetupInterfaces, hostPreparationModel, interfaceAssignmentIssues, restoreSetupRouteState, setupReadinessChecklist, setupScenarioConfig, setupScenarioReview, setupTopologyProof, setupTopologyProofRows, splitInterfaceList } from "./views/setup.js";

const setupViewSource = readFileSync(new URL("./views/setup.js", import.meta.url), "utf8");
const setupCSS = readFileSync(new URL("../css/app.css", import.meta.url), "utf8");
assert.match(setupViewSource, /type: "button",\n        "data-setup-action": "stage"/);
assert.match(setupViewSource, /title: `Select setup profile \$\{profile\.title\}`/);
assert.match(setupViewSource, /title: `Select setup scenario \$\{scenario\.title\}`/);
assert.match(setupViewSource, /setupHostAction: action\.profile/);
assert.match(setupViewSource, /setupInterfaceAction: "inside"/);
assert.match(setupViewSource, /setupInterfaceAction: "outside"/);
assert.match(setupViewSource, /setupSegment: opts\.key/);
assert.match(setupViewSource, /setupSegmentValue: value/);
assert.match(setupViewSource, /type: "button", title: "Open guided setup API and CLI context"/);
assert.match(setupViewSource, /title: `Open \$\{item\.title\} proof`/);
assert.match(setupViewSource, /setupCheckAction: item\.id/);
assert.match(setupViewSource, /class: "setup-checklist-detail"/);
assert.match(setupViewSource, /class: "setup-topology-proof-label"/);
assert.match(setupViewSource, /class: "setup-topology-proof-detail"/);
assert.match(setupCSS, /\.setup-checklist-detail,\n\.setup-topology-proof-label \{[\s\S]*?white-space: normal;[\s\S]*?overflow: visible;[\s\S]*?-webkit-line-clamp: unset;\n\}/);
assert.doesNotMatch(setupCSS, /\.setup-checklist-main span,\n\.settings-panel-link span/);
assert.match(setupViewSource, /restoreSetupRouteState\(ctx\.query \|\| \{\}\)/);
assert.match(setupViewSource, /Object\.assign\(state, restored\)/);
assert.match(setupViewSource, /await session\.apply\(\(draft\) =>/);

{
  const restored = setupConfigFromQuery(new URLSearchParams([
    ["scenario", "custom"],
    ["profile", "ips-prevent"],
    ["insideZone", "corp"],
    ["outsideZone", "internet"],
    ["insideInterfaces", "ens5, ens6"],
    ["outsideInterfaces", "ens4"],
    ["insideCidr", "10.44.0.0/20"],
    ["webuiPort", "9443"],
    ["allowOutbound", "0"],
    ["masquerade", "false"],
    ["hardenHostInput", "true"],
    ["clampMss", "off"],
    ["flowOffload", "yes"],
    ["manageNicOffloads", "1"],
    ["token", "Bearer secret"],
  ]), setupScenarioConfig("cloud-edge"));

  assert.equal(restored.scenario, "custom");
  assert.equal(restored.profile, "ips-prevent");
  assert.equal(restored.insideZone, "corp");
  assert.equal(restored.outsideZone, "internet");
  assert.equal(restored.insideInterfaces, "ens5, ens6");
  assert.equal(restored.outsideInterfaces, "ens4");
  assert.equal(restored.insideCidr, "10.44.0.0/20");
  assert.equal(restored.webuiPort, "9443");
  assert.equal(restored.allowOutbound, false);
  assert.equal(restored.masquerade, false);
  assert.equal(restored.hardenHostInput, true);
  assert.equal(restored.clampMss, false);
  assert.equal(restored.flowOffload, true);
  assert.equal(restored.manageNicOffloads, true);
  assert.equal(restored.token, undefined);
}

{
  const before = restoreSetupRouteState({});
  assert.equal(before.restored, false);

  const result = restoreSetupRouteState({
    scenario: "custom",
    profile: "ids-detect",
    insideZone: "app",
    outsideZone: "db",
    insideInterfaces: "ens7, ens8",
    outsideInterfaces: "ens9",
    insideCidr: "172.16.20.0/24",
    webuiPort: "9443",
    allowOutbound: "yes",
    masquerade: "0",
    hardenHostInput: "1",
    clampMss: "false",
    flowOffload: "0",
    manageNicOffloads: "true",
    mtu: "9000",
  });

  assert.equal(result.restored, true);
  assert.equal(result.config.scenario, "custom");
  assert.equal(result.config.profile, "ids-detect");
  assert.equal(result.config.insideZone, "app");
  assert.equal(result.config.outsideZone, "db");
  assert.equal(result.config.insideInterfaces, "ens7,ens8");
  assert.equal(result.config.outsideInterfaces, "ens9");
  assert.equal(result.config.insideCidr, "172.16.20.0/24");
  assert.equal(result.config.webuiPort, "9443");
  assert.equal(result.config.allowOutbound, true);
  assert.equal(result.config.masquerade, false);
  assert.equal(result.config.hardenHostInput, true);
  assert.equal(result.config.clampMss, false);
  assert.equal(result.config.flowOffload, false);
  assert.equal(result.config.manageNicOffloads, true);
  assert.equal(result.config.mtu, "9000");
  assert.match(setupBaselineCliCommand(result.config), /--inside-zone app/);
  assert.match(setupBaselineCliCommand(result.config), /--inside-interface ens7 --inside-interface ens8/);
  assert.match(setupBaselineCliCommand(result.config), /--masquerade=false/);
}

{
  assert.deepEqual(SETUP_SCENARIOS.map((scenario) => scenario.id), ["cloud-edge", "east-west", "vpn-edge", "ids-tap", "lab"]);
}

{
  const edge = setupScenarioConfig("cloud-edge", { mtu: "9000", idsRuleFiles: "custom.rules", idsQueueNum: "5" });
  assert.equal(edge.scenario, "cloud-edge");
  assert.equal(edge.profile, "throughput");
  assert.equal(edge.masquerade, true);
  assert.equal(edge.flowOffload, true);
  assert.equal(edge.mtu, "");
  assert.equal(edge.idsRuleFiles, "local.rules");
  assert.equal(edge.idsQueueNum, "0");
}

{
  const eastWest = setupScenarioConfig("east-west");
  const preview = previewBaselinePolicy({}, eastWest);
  assert.equal(eastWest.profile, "ids-detect");
  assert.equal(eastWest.masquerade, false);
  assert.equal(eastWest.flowOffload, false);
  assert.equal(eastWest.manageNicOffloads, true);
  assert.equal(preview.policy.ids.enabled, true);
  assert.equal(preview.policy.ids.mode, "IDS_MODE_DETECT");
  assert.equal(Boolean(preview.policy.nat?.source?.length), false);
  assert.match(setupScenarioReview(eastWest).review, /return routes/i);
  assert.match(setupBaselineCliCommand(eastWest), /--masquerade=false/);
  assert.match(setupBaselineCliCommand(eastWest), /--flow-offload=false/);
}

{
  const tap = setupScenarioConfig("ids-tap");
  const preview = previewBaselinePolicy({}, tap);
  assert.equal(tap.allowOutbound, false);
  assert.equal(tap.masquerade, false);
  assert.equal((preview.policy.rules || []).some((rule) => rule.name === "allow-tap-to-monitor"), false);
  assert.equal(Boolean(preview.policy.nat?.source?.length), false);
  assert.equal(preview.policy.hostInput.defaultAction, "ACTION_DENY");
  const command = setupBaselineCliCommand(tap);
  assert.match(command, /--profile ids-detect/);
  assert.match(command, /--inside-zone tap/);
  assert.match(command, /--outside-zone monitor/);
  assert.match(command, /--allow-outbound=false/);
  assert.match(command, /--masquerade=false/);
  assert.match(setupScenarioReview(tap).excluded, /Outbound allow and source NAT are not staged/);
}

{
  const vpn = setupScenarioConfig("vpn-edge");
  const preview = previewBaselinePolicy({}, vpn);
  assert.equal(vpn.masquerade, false);
  assert.equal(vpn.flowOffload, false);
  assert.equal(Boolean(preview.policy.nat?.source?.length), false);
  assert.match(setupScenarioReview(vpn).excluded, /Tunnel peers, private keys, PSKs/);
  assert.doesNotMatch(JSON.stringify(preview.policy), /privateKey|preSharedKey|psk/i);
}

{
  const custom = {
    ...setupScenarioConfig("lab"),
    scenario: "custom",
    insideZone: "corp",
    outsideZone: "internet",
    insideInterfaces: "ens5, ens6",
    outsideInterfaces: "ens4",
    insideCidr: "10.44.0.0/20",
    webuiPort: "9443",
    allowOutbound: true,
    masquerade: false,
    flowOffload: false,
  };
  const command = setupBaselineCliCommand(custom);
  assert.match(command, /--inside-zone corp/);
  assert.match(command, /--inside-interface ens5 --inside-interface ens6/);
  assert.match(command, /--inside-cidr 10.44.0.0\/20/);
  assert.match(command, /--webui-port 9443/);
  assert.match(command, /--masquerade=false/);
  assert.match(setupScenarioReview(custom).fit, /Operator-adjusted baseline/);
  assert.match(setupRouteHashFromConfig(custom), /scenario=custom/);
  assert.match(setupRouteHashFromConfig(custom), /insideZone=corp/);
}

{
  const edge = setupScenarioConfig("cloud-edge");
  const proof = setupTopologyProof(edge, previewBaselinePolicy({}, edge).policy);

  assert.equal(proof.id, "topology-proof");
  assert.equal(proof.cls, "ok");
  assert.match(proof.detail, /Cloud edge handoff checks/);
  assert.equal(proof.href, "#/changes");
  assert.match(proof.cli, /policy validate/);
  assert.deepEqual(proof.proofRows.map((row) => row.key), ["interfaces", "host-input", "outbound-allow", "source-nat", "mss"]);
  assert.equal(proof.proofRows.find((row) => row.key === "source-nat").cls, "ok");
}

{
  const eastWest = setupScenarioConfig("east-west");
  const proof = setupTopologyProof(eastWest, previewBaselinePolicy({}, eastWest).policy);

  assert.equal(proof.cls, "ok");
  assert.match(proof.detail, /return-route proof/);
  assert.equal(proof.href, "#/netvpn?drawer=static-routes");
  assert.equal(proof.action, "Routes");
  assert.equal(proof.proofRows.find((row) => row.key === "return-route").status, "required");
  assert.equal(proof.proofRows.find((row) => row.key === "no-source-nat").cls, "ok");
}

{
  const vpn = setupScenarioConfig("vpn-edge");
  const proof = setupTopologyProof(vpn, previewBaselinePolicy({}, vpn).policy);

  assert.equal(proof.cls, "warn");
  assert.match(proof.detail, /protected-subnet route proof/);
  assert.equal(proof.href, "#/netvpn?drawer=tunnels");
  assert.equal(proof.proofRows.find((row) => row.key === "tunnel-proof").status, "required");
  assert.equal(proof.proofRows.find((row) => row.key === "secret-boundary").cls, "ok");
}

{
  const tap = setupScenarioConfig("ids-tap");
  const proof = setupTopologyProof(tap, previewBaselinePolicy({}, tap).policy);

  assert.equal(proof.cls, "warn");
  assert.match(proof.detail, /mirror\/SPAN visibility/);
  assert.equal(proof.href, "#/troubleshoot?intent=capture&captureContext=setup-tap");
  assert.equal(proof.proofRows.find((row) => row.key === "mirror-proof").status, "required");
  assert.equal(proof.proofRows.find((row) => row.key === "no-forwarding").cls, "ok");
}

{
  const lab = setupScenarioConfig("lab");
  const defaultProof = setupTopologyProof(lab, previewBaselinePolicy({}, lab).policy);
  const customProof = setupTopologyProof({ ...lab, insideCidr: "10.99.0.0/24" }, previewBaselinePolicy({}, { ...lab, insideCidr: "10.99.0.0/24" }).policy);

  assert.equal(defaultProof.cls, "warn");
  assert.match(defaultProof.detail, /documentation CIDR/);
  assert.equal(customProof.cls, "ok");
  assert.equal(defaultProof.proofRows.find((row) => row.key === "lab-cidr").cls, "warn");
  assert.equal(customProof.proofRows.find((row) => row.key === "lab-cidr").cls, "ok");
}

{
  const rows = setupTopologyProofRows({ scenario: "custom", insideInterfaces: "ens5", outsideInterfaces: "ens6" }, { hostInput: { defaultAction: "ACTION_DENY", rules: [{ action: "ACTION_ALLOW", services: ["ssh"] }] } });
  assert.deepEqual(rows.map((row) => row.key), ["interfaces", "host-input", "custom-review"]);
  assert.equal(rows.find((row) => row.key === "interfaces").cls, "ok");
  assert.equal(rows.find((row) => row.key === "custom-review").status, "required");
}

{
  assert.deepEqual(splitInterfaceList(" ens5,ens4, ens5 ,, "), ["ens5", "ens4"]);
}

{
  const interfaces = discoveredSetupInterfaces({
    host: {
      interfaces: [
        { name: "lo", state: "ready", rxBytes: "100", txBytes: "100" },
        { name: "ens5", state: "ready", rxBytes: "2048", txBytes: "4096" },
        { name: "ens4", state: "degraded", detail: "drops observed", rxDrops: "2" },
        { name: "ens5", state: "ready", rxBytes: "1" },
        { name: "" },
      ],
    },
  });

  assert.deepEqual(interfaces.map((iface) => iface.name), ["ens4", "ens5"]);
  assert.equal(interfaces[0].state, "degraded");
  assert.equal(interfaces[0].rxDrops, 2);
  assert.equal(interfaces[1].rxBytes, 2048);
}

{
  const issues = interfaceAssignmentIssues({
    insideInterfaces: "ens5",
    outsideInterfaces: "ens4",
  }, [
    { name: "ens4", state: "ready" },
    { name: "ens5", state: "ready" },
  ]);

  assert.deepEqual(issues, []);
}

{
  const issues = interfaceAssignmentIssues({
    insideInterfaces: "",
    outsideInterfaces: "ens4",
  });

  assert.equal(issues.some((issue) => issue.severity === "bad" && /inside/.test(issue.detail)), true);
}

{
  const issues = interfaceAssignmentIssues({
    insideInterfaces: "ens5, lo",
    outsideInterfaces: "ens5",
  }, [
    { name: "ens5", state: "ready" },
  ]);

  assert.equal(issues.some((issue) => issue.severity === "bad" && /both inside and outside/.test(issue.detail)), true);
  assert.equal(issues.some((issue) => issue.severity === "bad" && /Loopback/.test(issue.detail)), true);
}

{
  const issues = interfaceAssignmentIssues({
    insideInterfaces: "ens5",
    outsideInterfaces: "ens9",
  }, [
    { name: "ens5", state: "degraded", detail: "rx drops observed" },
  ]);

  assert.equal(issues.some((issue) => issue.severity === "warn" && /ens5 is degraded/.test(issue.detail)), true);
  assert.equal(issues.some((issue) => issue.severity === "warn" && /ens9 was not reported/.test(issue.detail)), true);
}

{
  const model = hostPreparationModel(null, "throughput");

  assert.equal(model.statusAvailable, false);
  assert.equal(model.actions.every((action) => action.disabled), true);
  assert.equal(model.actions.find((action) => action.profile === "throughput").primary, true);
}

{
  const model = hostPreparationModel({
    runtime: { dryRun: true },
    dataplane: {
      kernelTuning: { state: "ready", detail: "baseline ready", checks: [] },
      conntrack: { maxEntries: 1048576 },
    },
  }, "ids-detect");

  assert.equal(model.dryRun, true);
  assert.equal(model.baseline.label, "ready");
  assert.equal(model.actions.every((action) => action.disabled), true);
  assert.equal(model.actions.find((action) => action.profile === "throughput").primary, false);
}

{
  const model = hostPreparationModel({
    runtime: { dryRun: false },
    dataplane: {
      kernelTuning: {
        state: "degraded",
        detail: "net.ipv4.ip_forward is off",
        checks: [
          { name: "IPv4 forwarding", key: "net.ipv4.ip_forward", state: "degraded", current: "0", recommended: "1" },
          { name: "IPv6 forwarding", key: "net.ipv6.conf.all.forwarding", state: "ready", current: "1", recommended: "1" },
        ],
      },
      conntrack: { maxEntries: 8388608 },
    },
  }, "throughput");

  assert.equal(model.statusAvailable, true);
  assert.equal(model.baseline.label, "1/2 ready");
  assert.equal(model.throughput.ready, true);
  assert.equal(model.throughput.recommended, true);
  assert.equal(model.actions.find((action) => action.profile === "appliance").label, "Apply host baseline");
  assert.equal(model.actions.find((action) => action.profile === "throughput").primary, true);
  assert.equal(model.actions.every((action) => action.disabled === false), true);
}

{
  const config = {
    profile: "throughput",
    insideZone: "lan",
    outsideZone: "wan",
    insideInterfaces: "ens5",
    outsideInterfaces: "ens4",
    insideCidr: "10.0.0.0/24",
    webuiPort: "8080",
    allowOutbound: true,
    masquerade: true,
    hardenHostInput: true,
    flowOffload: true,
  };
  const preview = previewBaselinePolicy({}, config);
  const checklist = setupReadinessChecklist({
    config,
    policy: preview.policy,
    issues: [],
    hostPreparation: { statusAvailable: true, dryRun: false, baseline: { cls: "ok", detail: "baseline ready" } },
    runtime: { authEnabled: true, tlsEnabled: true },
    oidc: { enabled: true },
    contentPosture: { summary: { cls: "ok", detail: "Content packages verified." } },
    dirty: false,
  });
  const byId = Object.fromEntries(checklist.map((item) => [item.id, item]));

  assert.equal(byId.interfaces.cls, "ok");
  assert.equal(byId["admin-access"].cls, "ok");
  assert.match(byId["admin-access"].detail, /OIDC browser SSO/);
  assert.equal(byId["host-input"].cls, "ok");
  assert.equal(byId["content-updates"].cls, "ok");
  assert.equal(byId["topology-proof"].cls, "info");
  assert.match(byId["topology-proof"].detail, /Custom topology selected/);
  assert.equal(byId.outbound.cls, "ok");
  assert.equal(byId.inspection.cls, "info");
  assert.match(byId.inspection.detail, /throughput-oriented/);
  assert.equal(byId["host-tuning"].cls, "ok");
  assert.equal(byId["candidate-review"].cls, "warn");
  assert.match(byId["candidate-review"].cli, /policy baseline --profile throughput/);
}

{
  const checklist = setupReadinessChecklist({
    config: { profile: "ids-detect", insideZone: "lan", outsideZone: "wan" },
    policy: {
      ids: { enabled: true, mode: "IDS_MODE_DETECT" },
      network: { enableFlowOffload: true },
      hostInput: { defaultAction: "ACTION_ALLOW" },
      rules: [],
      nat: { source: [] },
    },
    issues: [{ severity: "bad", detail: "ens5 cannot be assigned to both inside and outside." }],
    hostPreparation: { statusAvailable: false, dryRun: false, baseline: { cls: "neutral" } },
    runtime: { authEnabled: false, tlsEnabled: false },
    oidc: { enabled: false },
    contentPosture: { summary: { cls: "bad", detail: "Content package status unavailable." } },
  });
  const byId = Object.fromEntries(checklist.map((item) => [item.id, item]));

  assert.equal(byId.interfaces.cls, "bad");
  assert.match(byId.interfaces.detail, /both inside and outside/);
  assert.equal(byId["admin-access"].cls, "bad");
  assert.match(byId["admin-access"].detail, /Enable TLS and authentication/);
  assert.equal(byId["host-input"].cls, "warn");
  assert.equal(byId["content-updates"].cls, "bad");
  assert.equal(byId.outbound.cls, "info");
  assert.equal(byId.inspection.cls, "bad");
  assert.match(byId.inspection.detail, /bypass inspection/);
  assert.equal(byId["host-tuning"].cls, "warn");
  assert.equal(byId["candidate-review"].cls, "bad");
}

{
  const checklist = setupReadinessChecklist({
    config: { profile: "ips-prevent", insideZone: "lan", outsideZone: "wan" },
    policy: {
      ids: { enabled: true, mode: "IDS_MODE_PREVENT", failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_OPEN" },
      network: { enableFlowOffload: false },
      hostInput: { defaultAction: "ACTION_DENY", rules: [{ action: "ACTION_ALLOW", services: ["ssh"] }] },
      rules: [{ action: "ACTION_ALLOW", fromZones: ["lan"], toZones: ["wan"] }],
      nat: { source: [{ masquerade: true }] },
    },
    issues: [{ severity: "warn", detail: "ens9 was not reported by this host." }],
    hostPreparation: { statusAvailable: true, dryRun: true, baseline: { cls: "warn" } },
    runtime: { authEnabled: true, tlsEnabled: false },
    oidc: { enabled: false },
    contentPosture: { summary: { cls: "warn", detail: "The API reports package status, but review items remain." } },
    dirty: true,
  });
  const byId = Object.fromEntries(checklist.map((item) => [item.id, item]));

  assert.equal(byId.interfaces.cls, "warn");
  assert.equal(byId["admin-access"].cls, "warn");
  assert.match(byId["admin-access"].detail, /TLS evidence/);
  assert.equal(byId["content-updates"].cls, "warn");
  assert.equal(byId.inspection.cls, "warn");
  assert.match(byId.inspection.detail, /fail-open/);
  assert.equal(byId["host-tuning"].cls, "warn");
  assert.match(byId["host-tuning"].detail, /Dry-run/);
  assert.equal(byId["candidate-review"].cls, "ok");
  assert.match(byId["candidate-review"].cli, /policy validate/);
}
