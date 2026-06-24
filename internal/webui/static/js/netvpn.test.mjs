import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  bgpFromInputs,
  bgpRuntimeByPeer,
  bgpRuntimeLabel,
  buildWireguardBranchRolloutPlan,
  ipsecRuntimeByTunnel,
  ipsecFromInputs,
  netvpnDynamicRouteState,
  networkPathActiveProofPacket,
  networkPathActiveProofPlan,
  networkPathActiveProofPlanText,
  networkPathProofRequest,
  vpnFieldProofChecklist,
  vpnFieldProofChecklistText,
  netvpnStaticRouteState,
  netvpnTunnelRouteState,
  normalizeNetvpnRoute,
  ospfFromInputs,
  ospfRuntimeLabel,
  ospfRuntimeSummary,
  splitList,
  validAsnValue,
  validCidr,
  validConfigToken,
  validHostPort,
  validIPv4Address,
  validManagedPath,
  validPolicyName,
  validWireguardInterfaceName,
  ipsecPeerTemplate,
  vpnInvestigationTargets,
  vpnPeerTemplateBundle,
  vpnPeerTemplateFilename,
  vpnRuntimeReviewRows,
  vpnSessionsHash,
  vpnTunnelHash,
  vpnTunnelModels,
  vpnTroubleshootHash,
  wireguardEnrollmentBundle,
  wireguardEnrollmentQrFilename,
  wireguardEnrollmentQrSvg,
  wireguardPeerClientTemplate,
  wireguardFromInputs,
  wireguardPeerRuntime,
  wireguardPeerRuntimeLabel,
  wireguardRuntimeByInterface,
} from "./views/netvpn.js";

const input = (value = "") => ({ value });
const toggle = (checked) => ({ checked });
const netvpnSource = readFileSync(new URL("./views/netvpn.js", import.meta.url), "utf8");
const assertSourceIncludes = (snippet) => {
  assert.ok(netvpnSource.includes(snippet), `netvpn.js missing source contract: ${snippet}`);
};

{
  assert.deepEqual(networkPathProofRequest({
    kind: "wireguard",
    srcIp: "10.99.0.1",
    destIp: "10.99.0.2",
    protocol: "PROTOCOL_UDP",
    ifaceName: "wg0",
    peerName: "laptop",
    peerPublicKey: "pubkey1",
  }), {
    srcIp: "10.99.0.1",
    destIp: "10.99.0.2",
    protocol: "PROTOCOL_UDP",
    sourceInterface: "wg0",
    tunnel: {
      kind: "wireguard",
      interface: "wg0",
      peer: "laptop",
      peerPublicKey: "pubkey1",
    },
  });

  assert.deepEqual(networkPathProofRequest({
    kind: "ipsec",
    tunnelName: "site-b",
    name: "site-b",
    srcIp: "10.10.0.1",
    destIp: "10.20.0.1",
    protocol: "PROTOCOL_ANY",
  }), {
    srcIp: "10.10.0.1",
    destIp: "10.20.0.1",
    protocol: "PROTOCOL_ANY",
    tunnel: {
      kind: "ipsec",
      name: "site-b",
    },
  });
  assertSourceIncludes('proofRow("Route table", route.table || "-")');
  assertSourceIncludes('proofRow("VRF/interface identity", pathProofInterfaceIdentity(route, proof.evidence || []))');
  assertSourceIncludes('proofRow("routing service route proof", pathProofFrrEvidence(route, proof.evidence || []))');
  assertSourceIncludes('proofRow("Masquerade egress", pathProofMasqueradeEvidence(route, proof.evidence || []))');
  assertSourceIncludes('proofRow("VPN correlation", vpn.correlation || "-")');
  assertSourceIncludes('proofRow("Mismatches", pathProofMismatchText(proof.mismatches || []) || "none")');
  assertSourceIncludes('proofRow("Limitations", pathProofListText(proof.limitations || []) || "none")');
  assertSourceIncludes('dataset: { netvpnPathProofAction: "copy-api" }');
  assertSourceIncludes('dataset: { netvpnPathProofAction: "copy-cli" }');
  assertSourceIncludes('dataset: { netvpnPathProofAction: "copy-active-plan" }');
  assertSourceIncludes('dataset: { netvpnPathProofAction: "export-active-plan" }');
  assertSourceIncludes('dataset: { netvpnPathProofAction: "pin-active-plan" }');
  assertSourceIncludes('function networkPathProofAPIHandoff');
  assertSourceIncludes('function networkPathProofCLIHandoff');
  assertSourceIncludes('function networkPathActiveProofPacket');
  assertSourceIncludes('no active probe, capture, or session lookup was sent by this UI');
  assertSourceIncludes('dataset: { netvpnActiveProofAcknowledgements: "true" }');
  assertSourceIncludes('remoteAttestationBoundary');
  assertSourceIncludes('exportBoundary');
  assertSourceIncludes('Command and export boundary');
  assertSourceIncludes('Route table and VRF');
  assertSourceIncludes('function pathProofInterfaceIdentity');
  assertSourceIncludes('function pathProofFrrEvidence');
  assertSourceIncludes('function pathProofMasqueradeEvidence');
}

{
  const plan = networkPathActiveProofPlan({
    kind: "wireguard",
    name: "wg0:laptop",
    ifaceName: "wg0",
    peerName: "laptop",
    srcIp: "10.99.0.1",
    destIp: "10.99.0.2",
    protocol: "PROTOCOL_UDP",
  }, {
    state: "degraded",
    route: {
      state: "ready",
      dev: "wg0",
      gateway: "10.99.0.254",
    },
    vpn: {
      state: "handshook",
      interface: "wg0",
      correlation: "peer public key matched",
    },
    mismatches: [{
      severity: "warn",
      subject: "vpn selector",
      detail: "allowed IP covers remote host but runtime transfer counters are zero",
    }],
    limitations: ["/etc/phragma/keys/wg0.key was not inspected"],
  });

  assert.equal(plan.statement.includes("no active probe"), true);
  assert.equal(plan.acknowledgementRequirements.filter((item) => item.required).length, 4);
  assert.ok(plan.acknowledgementRequirements.some((item) => item.key === "not-executed" && /did not execute probes/.test(item.text)));
  assert.ok(plan.acknowledgementRequirements.some((item) => item.key === "bounded-commands" && /timeout, packet-count, and snap-length/.test(item.text)));
  assert.ok(plan.acknowledgementRequirements.some((item) => item.key === "secret-redaction" && /WireGuard key paths/.test(item.text)));
  assert.ok(plan.acknowledgementRequirements.some((item) => item.key === "remote-attestation" && /out of scope/.test(item.text)));
  assert.equal(plan.executionBounds.probeTimeoutSeconds, 8);
  assert.equal(plan.executionBounds.capturePacketCount, 50);
  assert.equal(plan.executionBounds.captureSnapLengthBytes, 160);
  assert.match(plan.remoteAttestationBoundary, /Remote peer identity/);
  assert.match(plan.exportBoundary, /planned commands, redacted passive proof/);
  assert.match(plan.exportBoundary, /raw command output, packet captures/);
  assert.equal(plan.passiveSummary.limitations.includes("[local-path-redacted] was not inspected"), true);
  assert.equal(plan.commands.find((section) => section.key === "bounded-probe").commands[0].includes("nping --udp"), true);
  assert.ok(plan.commands.find((section) => section.key === "bounded-probe").commands.every((cmd) => /timeout \d+/.test(cmd)), "all active-probe commands should be timeout bounded");
  assert.equal(plan.commands.find((section) => section.key === "bounded-capture").commands[0].includes("timeout 20 tcpdump"), true);
  assert.ok(plan.commands.find((section) => section.key === "session-correlation").commands.every((cmd) => /timeout \d+ conntrack/.test(cmd)), "conntrack handoffs should be timeout bounded");
  assert.equal(plan.checklist.find((item) => item.key === "kernel-route").state, "ready");
  assert.equal(plan.checklist.find((item) => item.key === "vrf-interface").state, "verify");
  assert.equal(plan.checklist.find((item) => item.key === "frr").state, "verify");
  assert.equal(plan.checklist.find((item) => item.key === "xfrm").state, "as-needed");
  assert.equal(plan.checklist.find((item) => item.key === "wireguard").state, "required");
  assert.equal(plan.checklist.find((item) => item.key === "remote-attestation").state, "out-of-band");
  assert.ok(plan.checklist.flatMap((item) => item.commands || []).every((cmd) => !cmd || /timeout \d+/.test(cmd)), "checklist command handoffs should be timeout bounded");
  assert.equal(plan.checklist.some((item) => item.key === "strongswan"), false);
  assert.match(plan.nextSteps[0], /verify tunnel selector, XFRM\/IPsec or WireGuard peer state/);
  const text = networkPathActiveProofPlanText(plan);
  assert.match(text, /Recommended operator-run commands only/);
  assert.match(text, /\[required acknowledgements\]/);
  assert.match(text, /bounded-commands/);
  assert.match(text, /\[execution bounds\]/);
  assert.match(text, /captureSnapLengthBytes=160/);
  assert.match(text, /\[remote attestation boundary\]/);
  assert.match(text, /\[export packet boundary\]/);
  assert.match(text, /\$ sudo timeout 8 nping --udp/);
  assert.match(text, /planned-not-executed|not sent|no active probe/i);
  assert.match(text, /raw command output, packet captures/);
  assert.equal(text.includes("/etc/phragma/keys/wg0.key"), false);
  assert.equal(text.includes("/tmp/openngfw-path"), false);
  const packet = networkPathActiveProofPacket({
    kind: "wireguard",
    name: "wg0:laptop",
    ifaceName: "wg0",
    peerName: "laptop",
    srcIp: "10.99.0.1",
    destIp: "10.99.0.2",
    protocol: "PROTOCOL_UDP",
  }, {
    state: "degraded",
    route: { state: "ready", dev: "wg0", gateway: "/etc/phragma/gw-secret" },
    vpn: { state: "handshook", correlation: "privateKeyFile=/etc/phragma/wg.key", matchedTunnel: "wg0" },
    mismatches: [{ severity: "warn", subject: "route", detail: "token=secret /etc/openngfw/path" }],
    limitations: ["/etc/phragma/keys/wg0.key was not inspected"],
    apiHandoff: "Bearer eyJhbGciOiJIUzI1NiJ9.secret.signature",
  }, plan);
  const packetJson = JSON.stringify(packet);
  assert.equal(packetJson.includes("/etc/phragma"), false);
  assert.equal(packetJson.includes("/etc/openngfw"), false);
  assert.equal(packetJson.includes("/tmp/openngfw-path"), false);
  assert.equal(packetJson.includes("privateKeyFile=/etc"), false);
  assert.equal(packetJson.includes("eyJhbGci"), false);
  assert.equal(packet.summary.acknowledgementRequirements, 4);
  assert.equal(packet.summary.exportBoundary, "redacted-plan-only");
  assert.equal(packet.artifacts.executionBounds.captureSnapLengthBytes, 160);
  assert.ok(packet.artifacts.acknowledgementRequirements.some((item) => item.key === "remote-attestation"));
  assert.match(packet.artifacts.remoteAttestationBoundary, /outside this browser packet/);
  assert.match(packet.artifacts.exportBoundary, /planned commands/);
  assert.equal(packet.artifacts.passiveProof.disclosureBoundary.includes("Redacted passive summary only"), true);
}

{
  const plan = networkPathActiveProofPlan({
    kind: "ipsec",
    name: "site-b",
    tunnelName: "site-b",
    srcIp: "10.10.0.1",
    destIp: "10.20.0.1",
    protocol: "PROTOCOL_ANY",
  }, {
    state: "ready",
    route: { state: "ready", dev: "xfrm0" },
    vpn: { state: "active", matchedTunnel: "site-b" },
    mismatches: [],
  });
  assert.equal(plan.commands.find((section) => section.key === "bounded-probe").commands[0].includes("ping -c 3"), true);
  assert.equal(plan.checklist.find((item) => item.key === "strongswan").state, "required");
  assert.equal(plan.checklist.find((item) => item.key === "xfrm").state, "required");
  assert.match(plan.checklist.find((item) => item.key === "strongswan").detail, /traffic selectors/);
  assert.match(plan.acknowledgementRequirements.find((item) => item.key === "secret-redaction").text, /IPsec\/IPsec service key paths/);
  assert.match(networkPathActiveProofPlanText(plan), /No passive mismatches were reported/);
}

{
  assert.match(netvpnSource, /function bgpCard\(root, bgp = \{}\) \{\n  bgp = bgp \|\| \{};/, "BGP card tolerates null policy sections");
  assert.match(netvpnSource, /function ospfCard\(root, ospf = \{}\) \{\n  ospf = ospf \|\| \{};/, "OSPF card tolerates null policy sections");
  assert.match(netvpnSource, /const routeLabel = r\.destination \|\| `route \$\{i \+ 1\}`/);
  assert.match(netvpnSource, /type: "button", title: "Edit", "aria-label": `Edit static route \$\{routeLabel\}`/);
  assert.match(netvpnSource, /type: "button", title: "Delete", "aria-label": `Delete static route \$\{routeLabel\}`/);
  assert.match(netvpnSource, /const tunnelLabel = t\.name \|\| `ipsec-\$\{i \+ 1\}`/);
  assert.match(netvpnSource, /type: "button", title: "Inspect tunnel handoff", "aria-label": `Inspect IPsec tunnel \$\{tunnelLabel\}`/);
  assert.match(netvpnSource, /type: "button", title: "Edit tunnel", "aria-label": `Edit IPsec tunnel \$\{tunnelLabel\}`/);
  assert.match(netvpnSource, /type: "button", title: "Delete tunnel", "aria-label": `Delete IPsec tunnel \$\{tunnelLabel\}`/);
  assert.match(netvpnSource, /const interfaceLabel = w\.name \|\| `wg-\$\{i \+ 1\}`/);
  assert.match(netvpnSource, /type: "button", title: "Edit interface", "aria-label": `Edit WireGuard interface \$\{interfaceLabel\}`/);
  assert.match(netvpnSource, /type: "button", title: "Delete interface", "aria-label": `Delete WireGuard interface \$\{interfaceLabel\}`/);
  assert.match(netvpnSource, /type: "button", title: "Remove neighbor", "aria-label": "Remove BGP neighbor", dataset: \{ netvpnAction: "remove-bgp-neighbor" \}/);
  assert.match(netvpnSource, /type: "button", title: "Remove prefix", "aria-label": "Remove BGP announced prefix", dataset: \{ netvpnAction: "remove-bgp-prefix" \}/);
  assert.match(netvpnSource, /type: "button", title: "Remove area", "aria-label": "Remove OSPF area", dataset: \{ netvpnAction: "remove-ospf-area" \}/);
  assert.match(netvpnSource, /type: "button", title: "Remove peer", "aria-label": "Remove WireGuard peer", dataset: \{ netvpnAction: "remove-wireguard-peer" \}/);
  assert.match(netvpnSource, /type: "button",\s+title: "Inspect tunnel handoff",\s+"aria-label": `Inspect WireGuard tunnel \$\{interfaceLabel\}:\$\{p\.name \|\| "peer"\}`,\s+dataset: \{ netvpnAction: "inspect-wireguard-peer" \}/);
  for (const snippet of [
    'type: "button", title: "Open WireGuard branch rollout", "aria-label": "Open WireGuard branch rollout workflow", dataset: { netvpnAction: "open-wireguard-rollout" }',
    'type: "button", title: "Add static route", "aria-label": "Add static route to candidate", dataset: { netvpnAction: "add-route" }',
    'type: "button", title: "Review route", "aria-label": `Review static route ${routeLabel}`, dataset: { netvpnAction: "review-route" }',
    'type: "button", title: "Configure BGP candidate settings", "aria-label": "Configure BGP candidate settings", dataset: { netvpnAction: "configure-bgp" }',
    'type: "button", title: "Review BGP route context", "aria-label": "Review BGP route context", dataset: { netvpnAction: "review-bgp" }',
    'type: "button", title: "Edit BGP candidate settings", "aria-label": "Edit BGP candidate settings", dataset: { netvpnAction: "configure-bgp" }',
    'type: "button", title: "Disable BGP in candidate", "aria-label": "Disable BGP in candidate", dataset: { netvpnAction: "disable-bgp" }',
    'type: "button", title: "Add BGP neighbor row", "aria-label": "Add BGP neighbor row", dataset: { netvpnAction: "add-bgp-neighbor" }',
    'type: "button", title: "Add BGP announced prefix row", "aria-label": "Add BGP announced prefix row", dataset: { netvpnAction: "add-bgp-prefix" }',
    'type: "button", title: "Cancel BGP configuration", "aria-label": "Cancel BGP configuration", dataset: { netvpnAction: "cancel-bgp" }',
    'type: "button", title: "Stage BGP candidate settings", "aria-label": "Stage BGP candidate settings", dataset: { netvpnAction: "stage-bgp" }',
    'type: "button", title: "Configure OSPF candidate settings", "aria-label": "Configure OSPF candidate settings", dataset: { netvpnAction: "configure-ospf" }',
    'type: "button", title: "Review OSPF route context", "aria-label": "Review OSPF route context", dataset: { netvpnAction: "review-ospf" }',
    'type: "button", title: "Edit OSPF candidate settings", "aria-label": "Edit OSPF candidate settings", dataset: { netvpnAction: "configure-ospf" }',
    'type: "button", title: "Disable OSPF in candidate", "aria-label": "Disable OSPF in candidate", dataset: { netvpnAction: "disable-ospf" }',
    'type: "button", title: "Add OSPF area row", "aria-label": "Add OSPF area row", dataset: { netvpnAction: "add-ospf-area" }',
    'type: "button", title: "Cancel OSPF configuration", "aria-label": "Cancel OSPF configuration", dataset: { netvpnAction: "cancel-ospf" }',
    'type: "button", title: "Stage OSPF candidate settings", "aria-label": "Stage OSPF candidate settings", dataset: { netvpnAction: "stage-ospf" }',
    'type: "button", title: `Inspect tunnel handoff for ${target.name}`, "aria-label": `Inspect tunnel handoff for ${target.name}`, dataset: { netvpnAction: "inspect-tunnel" }',
    'type: "button", title: `Explain candidate path for ${target.name}`, "aria-label": `Explain candidate path for ${target.name}`, dataset: { netvpnAction: "explain-tunnel" }',
    'type: "button", title: `Start packet capture workflow for ${target.name}`, "aria-label": `Start packet capture workflow for ${target.name}`, dataset: { netvpnAction: "capture-tunnel" }',
    'type: "button", title: `Open live sessions for ${target.name}`, "aria-label": `Open live sessions for ${target.name}`, dataset: { netvpnAction: "sessions-tunnel" }',
    'type: "button", title: "Add IPsec tunnel", "aria-label": "Add IPsec tunnel to candidate", dataset: { netvpnAction: "add-ipsec" }',
    'type: "button", title: "Cancel IPsec tunnel edit", "aria-label": "Cancel IPsec tunnel edit", dataset: { netvpnAction: "cancel-ipsec" }',
    'type: "button", title: editing ? "Stage IPsec tunnel changes" : "Stage new IPsec tunnel", "aria-label": editing ? "Stage IPsec tunnel changes to candidate" : "Stage new IPsec tunnel to candidate", dataset: { netvpnAction: "stage-ipsec" }',
    'type: "button", title: "Add WireGuard interface", "aria-label": "Add WireGuard interface to candidate", dataset: { netvpnAction: "add-wireguard" }',
    'type: "button", title: "Add WireGuard peer row", "aria-label": "Add WireGuard peer row", dataset: { netvpnAction: "add-wireguard-peer" }',
    'type: "button", title: "Cancel WireGuard interface edit", "aria-label": "Cancel WireGuard interface edit", dataset: { netvpnAction: "cancel-wireguard" }',
    'type: "button", title: editing ? "Stage WireGuard interface changes" : "Stage new WireGuard interface", "aria-label": editing ? "Stage WireGuard interface changes to candidate" : "Stage new WireGuard interface to candidate", dataset: { netvpnAction: "stage-wireguard" }',
    'type: "button", title: "Copy WireGuard enrollment config", "aria-label": "Copy WireGuard enrollment config", dataset: { netvpnAction: "copy-wireguard-enrollment" }',
    'type: "button", title: "Export WireGuard enrollment config", "aria-label": "Export WireGuard enrollment config", dataset: { netvpnAction: "export-wireguard-enrollment" }',
    'type: "button", title: "Export WireGuard enrollment QR code", "aria-label": "Export WireGuard enrollment QR code", dataset: { netvpnAction: "export-wireguard-enrollment-qr" }',
    'type: "button", title: "Copy VPN peer template", "aria-label": "Copy VPN peer template", dataset: { netvpnAction: "copy-vpn-peer-template" }',
    'type: "button", title: "Export VPN peer template", "aria-label": "Export VPN peer template", dataset: { netvpnAction: "export-vpn-peer-template" }',
    'type: "button", title: "Open VPN tunnel API and CLI context", "aria-label": "Open VPN tunnel API and CLI context", dataset: { netvpnAction: "api-cli" }',
    'type: "button", title: "Pin VPN tunnel handoff to investigation case", "aria-label": "Pin VPN tunnel handoff to investigation case", dataset: { netvpnAction: "pin-vpn-handoff" }',
    'class: "btn ghost", href: activeInvestigationServerCaseHref(), title: "Open active investigation case", "aria-label": "Open active investigation case", dataset: { netvpnAction: "open-active-case" }',
    'type: "button", title: "Copy VPN tunnel handoff", "aria-label": "Copy VPN tunnel handoff", dataset: { netvpnAction: "copy-vpn-handoff" }',
    'type: "button", title: "Export VPN tunnel handoff JSON", "aria-label": "Export VPN tunnel handoff JSON", dataset: { netvpnAction: "export-vpn-handoff" }',
    'type: "button", title: "Cancel WireGuard branch rollout", "aria-label": "Cancel WireGuard branch rollout", dataset: { netvpnAction: "cancel-wireguard-rollout" }',
    'type: "button", title: "Stage WireGuard branch rollout", "aria-label": "Stage WireGuard branch rollout to candidate", dataset: { netvpnAction: "stage-wireguard-rollout" }',
  ]) {
    assertSourceIncludes(snippet);
  }

  assert.match(netvpnSource, /appendInvestigationPacketToActiveServerCase/);
  assert.match(netvpnSource, /api\.addInvestigationCaseEvidence\(id, evidence\)/);

  assert.deepEqual(splitList("10.0.0.0/24, 10.0.1.0/24\n10.0.2.0/24"), [
    "10.0.0.0/24",
    "10.0.1.0/24",
    "10.0.2.0/24",
  ]);
  assert.deepEqual(splitList(" ,\n "), []);
}

{
  assert.equal(validAsnValue("65001"), true);
  assert.equal(validAsnValue("1"), true);
  assert.equal(validAsnValue("4294967295"), true);
  assert.equal(validAsnValue("0"), false);
  assert.equal(validAsnValue("4294967296"), false);
  assert.equal(validAsnValue("65001abc"), false);
  assert.equal(validAsnValue(""), false);

  assert.equal(validIPv4Address("192.0.2.1"), true);
  assert.equal(validIPv4Address("0.0.0.0"), true);
  assert.equal(validIPv4Address("255.255.255.255"), true);
  assert.equal(validIPv4Address("192.0.2.999"), false);
  assert.equal(validIPv4Address("192.0.2.1/32"), false);
  assert.equal(validIPv4Address("2001:db8::1"), false);

  assert.equal(validCidr("10.0.0.0/24"), true);
  assert.equal(validCidr("10.0.0.0/0"), true);
  assert.equal(validCidr("10.0.0.0/32"), true);
  assert.equal(validCidr("2001:db8::/64"), true);
  assert.equal(validCidr("2001:db8:0:1::/64"), true);
  assert.equal(validCidr("10.0.0.0"), false);
  assert.equal(validCidr("10.0.0.0/33"), false);
  assert.equal(validCidr("2001:db8::/129"), false);
  assert.equal(validCidr("2001:db8:::1/64"), false);

  assert.equal(validPolicyName("site-b"), true);
  assert.equal(validPolicyName("site_b1"), true);
  assert.equal(validPolicyName("any"), false);
  assert.equal(validPolicyName("Site-B"), false);
  assert.equal(validPolicyName("-site"), false);
  assert.equal(validConfigToken("203.0.113.1"), true);
  assert.equal(validConfigToken("aes256-sha256-modp2048"), true);
  assert.equal(validConfigToken("203.0.113.1;rm"), false);
  assert.equal(validManagedPath("/etc/phragma/secrets/site-b.conf", ["/etc/phragma/secrets", "/etc/openngfw/secrets"]), true);
  assert.equal(validManagedPath("/etc/phragma/secrets/../site-b.conf", ["/etc/phragma/secrets"]), false);
  assert.equal(validManagedPath("/tmp/site-b.conf", ["/etc/phragma/secrets"]), false);
  assert.equal(validWireguardInterfaceName("wg0"), true);
  assert.equal(validWireguardInterfaceName("wg-branch-01"), true);
  assert.equal(validWireguardInterfaceName("wg/0"), false);
  assert.equal(validWireguardInterfaceName("wireguard-interface-too-long"), false);
  assert.equal(validHostPort("203.0.113.10:51820"), true);
  assert.equal(validHostPort("[2001:db8::1]:51820"), true);
  assert.equal(validHostPort("203.0.113.10"), false);
  assert.equal(validHostPort("203.0.113.10:70000"), false);
}

{
  const next = bgpFromInputs(
    toggle(false),
    input(""),
    input(""),
    [{ address: input(""), remoteAsn: input(""), description: input("draft peer") }],
    [{ cidr: input("10.0.0.0/24") }],
  );
  assert.deepEqual(next, {
    bgp: {
      enabled: false,
      neighbors: [{ address: "", remoteAsn: 0, description: "draft peer" }],
      announceNetworks: ["10.0.0.0/24"],
    },
  });
}

{
  const next = bgpFromInputs(
    toggle(true),
    input("65001"),
    input("192.0.2.1"),
    [
      { address: input(" 198.51.100.2 "), remoteAsn: input("65002"), description: input(" upstream ") },
      { address: input(""), remoteAsn: input(""), description: input("") },
    ],
    [{ cidr: input(" 10.10.0.0/24 ") }],
  );
  assert.deepEqual(next.bgp, {
    enabled: true,
    asn: 65001,
    routerId: "192.0.2.1",
    neighbors: [{ address: "198.51.100.2", remoteAsn: 65002, description: "upstream" }],
    announceNetworks: ["10.10.0.0/24"],
  });
  assert.equal(bgpFromInputs(toggle(true), input("65001"), input("192.0.2.1"), [], []).error, "At least one neighbor is required.");
  assert.equal(
    bgpFromInputs(toggle(true), input("65001"), input("192.0.2.1"), [{ address: input("198.51.100.2"), remoteAsn: input(""), description: input("") }], []).error,
    "Neighbor 198.51.100.2 needs a remote ASN.",
  );
  assert.equal(
    bgpFromInputs(toggle(true), input("65001abc"), input("192.0.2.1"), [{ address: input("198.51.100.2"), remoteAsn: input("65002"), description: input("") }], []).error,
    "Local ASN must be an integer from 1 to 4294967295.",
  );
  assert.equal(
    bgpFromInputs(toggle(true), input("65001"), input("not-ip"), [{ address: input("198.51.100.2"), remoteAsn: input("65002"), description: input("") }], []).error,
    "Router ID must be an IPv4 address.",
  );
  assert.equal(
    bgpFromInputs(toggle(true), input("65001"), input("192.0.2.1"), [{ address: input("198.51.100.999"), remoteAsn: input("65002"), description: input("") }], []).error,
    "Neighbor 198.51.100.999 address must be an IPv4 address.",
  );
  assert.equal(
    bgpFromInputs(toggle(true), input("65001"), input("192.0.2.1"), [{ address: input("198.51.100.2"), remoteAsn: input("65002abc"), description: input("") }], []).error,
    "Neighbor 198.51.100.2 remote ASN must be an integer from 1 to 4294967295.",
  );
  assert.equal(
    bgpFromInputs(toggle(true), input("65001"), input("192.0.2.1"), [{ address: input("198.51.100.2"), remoteAsn: input("65002"), description: input("bad\u0001peer") }], []).error,
    "Neighbor 198.51.100.2 description cannot contain control characters.",
  );
  assert.equal(
    bgpFromInputs(toggle(true), input("65001"), input("192.0.2.1"), [{ address: input("198.51.100.2"), remoteAsn: input("65002"), description: input("") }], [{ cidr: input("10.10.0.0/33") }]).error,
    "Announced prefix 10.10.0.0/33 must be a valid IPv4/IPv6 CIDR.",
  );
}

{
  const runtime = {
    bgpNeighbors: [{
      peer: "198.51.100.2",
      remoteAsn: 65002,
      state: "Established",
      uptime: "00:14:02",
      prefixesReceived: 12,
    }],
    ospfNeighbors: [{
      neighborId: "10.0.0.2",
      interface: "eth1",
      state: "Full/DROther",
      deadTime: "00:00:33",
    }, {
      neighborId: "10.0.0.3",
      interface: "eth2",
      state: "Init",
    }],
  };
  const bgpByPeer = bgpRuntimeByPeer(runtime);
  assert.equal(bgpByPeer.get("198.51.100.2").state, "Established");
  assert.equal(bgpRuntimeLabel(bgpByPeer.get("198.51.100.2")), "Established / AS65002 / 12 pfx / 00:14:02");
  assert.equal(bgpRuntimeLabel(null), "not observed");
  assert.equal(ospfRuntimeSummary(runtime), "1/2 full neighbors");
  assert.equal(ospfRuntimeLabel(runtime.ospfNeighbors[0]), "10.0.0.2 Full/DROther eth1 dead 00:00:33");
}

{
  const targets = vpnInvestigationTargets({
    vpn: {
      ipsecTunnels: [{
        name: "site-b",
        localSubnets: ["10.10.0.0/24"],
        remoteSubnets: ["10.20.0.0/24"],
      }],
      wireguardInterfaces: [{
        name: "wg0",
        address: "10.99.0.1/24",
        peers: [{
          name: "laptop",
          allowedIps: ["10.99.0.2/32", "10.99.1.0/24"],
        }],
      }],
    },
  });

  assert.deepEqual(targets.map((target) => ({
    kind: target.kind,
    name: target.name,
    srcIp: target.srcIp,
    destIp: target.destIp,
    remoteCidr: target.remoteCidr,
  })), [
    { kind: "ipsec", name: "site-b", srcIp: "10.10.0.1", destIp: "10.20.0.1", remoteCidr: "10.20.0.0/24" },
    { kind: "wireguard", name: "wg0:laptop", srcIp: "10.99.0.1", destIp: "10.99.0.2", remoteCidr: "10.99.0.2/32" },
    { kind: "wireguard", name: "wg0:laptop", srcIp: "10.99.0.1", destIp: "10.99.1.1", remoteCidr: "10.99.1.0/24" },
  ]);

  assert.equal(
    vpnTroubleshootHash(targets[0], "capture"),
    "#/troubleshoot?source=POLICY_SOURCE_CANDIDATE&src=10.10.0.1&dst=10.20.0.1&protocol=PROTOCOL_ANY&runtime=1&run=1&intent=capture",
  );
  assert.equal(vpnSessionsHash(targets[1]), "#/traffic?mode=sessions&ip=10.99.0.2&limit=500");
}

{
  assert.deepEqual(normalizeNetvpnRoute({ drawer: "tunnel", kind: "ipsec", name: " site-b " }), {
    drawer: "tunnel",
    kind: "ipsec",
    name: "site-b",
    iface: "",
    peer: "",
    local: "",
    remote: "",
    src: "",
    dst: "",
    protocol: "",
    port: "",
    mode: "",
    engine: "",
  });
  assert.deepEqual(normalizeNetvpnRoute({ drawer: "tunnel", kind: "wireguard", iface: " wg0 ", peer: " laptop " }), {
    drawer: "tunnel",
    kind: "wireguard",
    name: "",
    iface: "wg0",
    peer: "laptop",
    local: "",
    remote: "",
    src: "",
    dst: "",
    protocol: "",
    port: "",
    mode: "",
    engine: "",
  });
  assert.deepEqual(normalizeNetvpnRoute({ drawer: "runtime-review", engine: " FRR;rm -rf " }), {
    drawer: "runtime-review",
    kind: "",
    name: "",
    iface: "",
    peer: "",
    local: "",
    remote: "",
    src: "",
    dst: "",
    protocol: "",
    port: "",
    mode: "",
    engine: "FRRrm-rf",
  });
  assert.deepEqual(normalizeNetvpnRoute({ drawer: "bad", kind: "wireguard", iface: "wg0", peer: "laptop" }), {
    drawer: "",
    kind: "",
    name: "",
    iface: "",
    peer: "",
    local: "",
    remote: "",
    src: "",
    dst: "",
    protocol: "",
    port: "",
    mode: "",
    engine: "",
  });
  assert.deepEqual(netvpnTunnelRouteState({ kind: "wireguard", interfaceName: "wg0", peerName: "laptop" }), {
    drawer: "tunnel",
    kind: "wireguard",
    name: "",
    iface: "wg0",
    peer: "laptop",
    local: "",
    remote: "",
    src: "",
    dst: "",
    protocol: "PROTOCOL_UDP",
    port: "51820",
    mode: "",
    engine: "",
  });
  assert.equal(vpnTunnelHash({ kind: "ipsec", name: "site-b" }), "#/netvpn?drawer=tunnel&kind=ipsec&name=site-b&protocol=PROTOCOL_UDP&port=4500");
  assert.equal(vpnTunnelHash({ kind: "wireguard", iface: "wg0", peer: "laptop" }), "#/netvpn?drawer=tunnel&kind=wireguard&iface=wg0&peer=laptop&protocol=PROTOCOL_UDP&port=51820");
  assert.deepEqual(normalizeNetvpnRoute({ drawer: "route", name: "10.20.0.0/24", mode: "edit" }), netvpnStaticRouteState({ destination: "10.20.0.0/24" }, "edit"));
  assert.deepEqual(normalizeNetvpnRoute({ drawer: "bgp", mode: "edit" }), netvpnDynamicRouteState("bgp", "edit"));
  assert.deepEqual(normalizeNetvpnRoute({ drawer: "ospf" }), netvpnDynamicRouteState("ospf", "review"));
}

{
  const models = vpnTunnelModels({
    vpn: {
      ipsecTunnels: [{
        name: "site-b",
        localAddress: "%any",
        remoteAddress: "203.0.113.1",
        localSubnets: ["10.10.0.0/24"],
        remoteSubnets: ["10.20.0.0/24"],
        pskFile: "/etc/phragma/secrets/site-b.conf",
        initiate: true,
      }],
      wireguardInterfaces: [{
        name: "wg0",
        address: "10.99.0.1/24",
        listenPort: 51820,
        privateKeyFile: "/etc/phragma/keys/wg0.key",
        peers: [{
          name: "laptop",
          publicKey: "pubkey1",
          endpoint: "198.51.100.8:51820",
          allowedIps: ["10.99.0.2/32"],
          persistentKeepalive: 25,
        }],
      }],
    },
  }, {
    vpn: {
      ipsec: {
        state: "active",
        detail: "1 IPsec tunnel(s), 1 with established IKE and 1 installed CHILD SA(s)",
        tunnels: [{
          name: "site-b",
          state: "active",
          detail: "IKE established with 1/1 installed CHILD SA(s)",
          ikeState: "established",
          childSaCount: 1,
          installedChildSaCount: 1,
        }],
      },
      wireguard: {
        state: "active",
        interfaces: [{
          name: "wg0",
          state: "active",
          peerCount: 1,
          activePeerCount: 1,
          peers: [{
            publicKey: "pubkey1",
            state: "handshook",
            detail: "latest handshake 90s ago",
            latestHandshakeUnixSeconds: 1780000000,
            latestHandshakeAgeSeconds: 90,
            rxBytes: 1234,
            txBytes: 5678,
            endpoint: "198.51.100.8:51820",
          }],
        }],
      },
    },
  });
  assert.equal(models.length, 2);
  const ipsec = models.find((model) => model.kind === "ipsec");
  assert.equal(ipsec.name, "site-b");
  assert.equal(ipsec.mode, "initiator");
  assert.equal(ipsec.secretState, "PSK file configured (path redacted)");
  assert.equal(ipsec.targets[0].srcIp, "10.10.0.1");
  assert.equal(ipsec.runtime.state, "active");
  assert.equal(ipsec.runtime.ikeState, "established");
  assert.equal(ipsec.runtime.childSaCount, 1);
  assert.equal(ipsec.runtime.installedChildSaCount, 1);
  const wg = models.find((model) => model.kind === "wireguard");
  assert.equal(wg.name, "wg0:laptop");
  assert.equal(wg.interfaceName, "wg0");
  assert.equal(wg.peerName, "laptop");
  assert.equal(wg.secretState, "private key file configured (path redacted)");
  assert.equal(wg.runtime.state, "handshook");
  assert.equal(wg.runtime.latestHandshake, "handshake 1m ago");
  assert.equal(wg.runtime.rxBytes, 1234);
  assert.equal(wg.targets[0].destIp, "10.99.0.2");
  assert.equal(ipsec.ikeProposal, "");
}

{
  const [ipsec] = vpnTunnelModels({
    staticRoutes: [{ destination: "10.20.0.0/24" }],
    vpn: {
      ipsecTunnels: [{
        name: "site-b",
        localSubnets: ["10.10.0.0/24"],
        remoteSubnets: ["10.20.0.0/24"],
        pskFile: "/etc/phragma/secrets/site-b.conf",
      }],
    },
  }, {
    vpn: {
      ipsec: {
        tunnels: [{
          name: "site-b",
          state: "active",
          detail: "IKE established with 1/1 installed CHILD SA(s)",
        }],
      },
    },
  });
  const checklist = vpnFieldProofChecklist(ipsec, [{ destination: "10.20.0.0/24" }]);
  assert.equal(checklist.find((item) => item.key === "candidate-route").state, "ready");
  assert.match(checklist.find((item) => item.key === "candidate-route").detail, /Confirm the committed kernel route or routing service route separately/);
  assert.equal(checklist.find((item) => item.key === "route-table-vrf").state, "operator-check");
  assert.match(checklist.find((item) => item.key === "route-table-vrf").detail, /route table, preferred source, VRF\/network namespace/);
  assert.equal(checklist.find((item) => item.key === "frr-rib-fib").state, "operator-check");
  assert.equal(checklist.find((item) => item.key === "runtime-status").state, "observed");
  assert.match(checklist.find((item) => item.key === "runtime-status").detail, /not protected-subnet proof/);
  assert.equal(checklist.find((item) => item.key === "xfrm-state").state, "required");
  assert.equal(checklist.find((item) => item.key === "strongswan-runtime").state, "observed");
  assert.match(checklist.find((item) => item.key === "strongswan-runtime").detail, /IKE SA, CHILD SA, traffic selectors/);
  assert.equal(checklist.find((item) => item.key === "secret-custody").state, "placeholder-only");
  assert.equal(checklist.find((item) => item.key === "command-export-boundary").state, "redacted-plan");
  assert.equal(checklist.find((item) => item.key === "remote-attestation").state, "out-of-band");
  const note = vpnFieldProofChecklistText(checklist);
  assert.match(note, /collection handoff only/);
  assert.match(note, /does not claim field evidence/);
  assert.match(note, /route-table, VRF\/interface, routing service, XFRM, WireGuard or IPsec service proof separately/);
  assert.match(note, /remote attestation remains out of band/);
  assert.match(note, /raw command output, captures, local paths, tokens, and secrets stay out/);
  assert.equal(note.includes("/etc/phragma/secrets/site-b.conf"), false);
}

{
  const [wg] = vpnTunnelModels({
    staticRoutes: [],
    vpn: {
      wireguardInterfaces: [{
        name: "wg0",
        address: "10.99.0.1/24",
        privateKeyFile: "/etc/phragma/keys/wg0.key",
        peers: [{
          name: "laptop",
          publicKey: "pubkey1",
          allowedIps: ["10.99.0.2/32"],
        }],
      }],
    },
  }, {});
  const checklist = vpnFieldProofChecklist(wg, []);
  assert.equal(checklist.find((item) => item.key === "candidate-route").state, "review-needed");
  assert.equal(checklist.find((item) => item.key === "runtime-status").state, "not-observed");
  assert.equal(checklist.find((item) => item.key === "xfrm-state").state, "as-needed");
  assert.equal(checklist.find((item) => item.key === "wireguard-runtime").state, "required");
  assert.match(checklist.find((item) => item.key === "wireguard-runtime").detail, /latest handshake, endpoint, allowed IPs/);
  assert.equal(checklist.find((item) => item.key === "candidate-explain").state, "handoff");
  assert.match(vpnFieldProofChecklistText(checklist), /Private keys remain out of band|Secret custody/);
  assert.match(vpnFieldProofChecklistText(checklist), /remote attestation remains out of band/);
  assert.equal(vpnFieldProofChecklistText(checklist).includes("wg0.key"), false);
}

{
  const runtime = {
    tunnels: [
      { name: "site-b", state: "active" },
      { name: "dr-site", state: "waiting" },
    ],
  };
  const byTunnel = ipsecRuntimeByTunnel(runtime);
  assert.equal(byTunnel.get("site-b").state, "active");
  assert.equal(byTunnel.get("dr-site").state, "waiting");
  assert.equal(byTunnel.has("missing"), false);
}

{
  const rows = vpnRuntimeReviewRows({
    staticRoutes: [],
    vpn: {
      ipsecTunnels: [{
        name: "site-b",
        localSubnets: ["10.10.0.0/24"],
        remoteSubnets: ["10.20.0.0/24"],
      }],
      wireguardInterfaces: [{
        name: "wg0",
        address: "10.99.0.1/24",
        peers: [{
          name: "laptop",
          publicKey: "pubkey1",
          allowedIps: ["10.99.0.2/32"],
        }],
      }],
    },
  }, {
    vpn: {
      wireguard: {
        interfaces: [{
          name: "wg0",
          peers: [{ publicKey: "pubkey1", state: "handshook", latestHandshakeUnixSeconds: 1780000000, latestHandshakeAgeSeconds: 601 }],
        }],
      },
    },
  });
  assert.ok(rows.some((row) => row.type === "missing-runtime" && /site-b/.test(row.title)));
  assert.ok(rows.some((row) => row.type === "stale-handshake" && /wg0:laptop/.test(row.title)));
  assert.ok(rows.some((row) => row.type === "missing-route-posture" && row.expected === "10.20.0.0/24"));
  assert.ok(rows.some((row) => row.type === "missing-route-posture" && row.expected === "10.99.0.2/32"));
  const clearRows = vpnRuntimeReviewRows({
    staticRoutes: [
      { destination: "10.20.0.0/24" },
      { destination: "10.99.0.2/32", interface: "wg0" },
    ],
    vpn: {
      ipsecTunnels: [{ name: "site-b", localSubnets: ["10.10.0.0/24"], remoteSubnets: ["10.20.0.0/24"] }],
      wireguardInterfaces: [{ name: "wg0", address: "10.99.0.1/24", peers: [{ name: "laptop", publicKey: "pubkey1", allowedIps: ["10.99.0.2/32"] }] }],
    },
  }, {
    vpn: {
      ipsec: { tunnels: [{ name: "site-b", state: "active" }] },
      wireguard: { interfaces: [{ name: "wg0", peers: [{ publicKey: "pubkey1", state: "handshook", latestHandshakeUnixSeconds: 1780000000, latestHandshakeAgeSeconds: 90 }] }] },
    },
  });
  assert.deepEqual(clearRows, []);
}

{
  const models = vpnTunnelModels({
    vpn: {
      ipsecTunnels: [{
        name: "site-b",
        localAddress: "%any",
        remoteAddress: "203.0.113.1",
        localSubnets: ["10.10.0.0/24"],
        remoteSubnets: ["10.20.0.0/24"],
        pskFile: "/etc/phragma/secrets/site-b.conf",
        ikeProposal: "aes256-sha256-modp2048",
        espProposal: "aes256gcm16-prfsha256-ecp256",
        initiate: true,
      }],
      wireguardInterfaces: [{
        name: "wg0",
        address: "10.99.0.1/24",
        listenPort: 51820,
        privateKeyFile: "/etc/phragma/keys/wg0.key",
        peers: [{
          name: "laptop",
          publicKey: "pubkey1",
          endpoint: "198.51.100.8:51820",
          allowedIps: ["10.99.0.2/32", "10.99.1.0/24"],
          persistentKeepalive: 25,
        }],
      }],
    },
  }, {});
  const wg = models.find((model) => model.kind === "wireguard");
  const wgTemplate = wireguardPeerClientTemplate(wg);
  assert.match(wgTemplate.text, /Phragma WireGuard peer\/client template/);
  assert.match(wgTemplate.text, /# Interface: wg0/);
  assert.match(wgTemplate.text, /# Peer: laptop/);
  assert.match(wgTemplate.text, /PrivateKey = <client-private-key>/);
  assert.match(wgTemplate.text, /PublicKey = <firewall-public-key>/);
  assert.match(wgTemplate.text, /Endpoint = <firewall-public-endpoint>:51820/);
  assert.match(wgTemplate.text, /Address = 10\.99\.0\.2\/32/);
  assert.match(wgTemplate.text, /AllowedIPs = 10\.99\.0\.1\/24/);
  assert.match(wgTemplate.text, /PersistentKeepalive = 25/);
  assert.ok(wgTemplate.warnings.some((warning) => /public endpoint and public key/.test(warning)));
  for (const leaked of ["/etc/phragma", "privateKeyFile", "private_key_file", "wg0.key"]) {
    assert.equal(wgTemplate.text.includes(leaked), false, `WireGuard template leaked ${leaked}`);
  }

  const ipsec = models.find((model) => model.kind === "ipsec");
  const ipsecTemplate = ipsecPeerTemplate(ipsec);
  assert.match(ipsecTemplate.text, /Phragma IPsec peer worksheet/);
  assert.match(ipsecTemplate.text, /site_b \{/);
  assert.match(ipsecTemplate.text, /local_addrs = %any/);
  assert.match(ipsecTemplate.text, /remote_addrs = 203\.0\.113\.1/);
  assert.match(ipsecTemplate.text, /local_ts = 10\.10\.0\.0\/24/);
  assert.match(ipsecTemplate.text, /remote_ts = 10\.20\.0\.0\/24/);
  assert.match(ipsecTemplate.text, /proposals = aes256-sha256-modp2048/);
  assert.match(ipsecTemplate.text, /esp_proposals = aes256gcm16-prfsha256-ecp256/);
  assert.match(ipsecTemplate.text, /start_action = start/);
  assert.match(ipsecTemplate.text, /secret = <shared-secret-out-of-band>/);
  for (const leaked of ["/etc/phragma", "pskFile", "psk_file", "site-b.conf"]) {
    assert.equal(ipsecTemplate.text.includes(leaked), false, `IPsec template leaked ${leaked}`);
  }

  const bundle = vpnPeerTemplateBundle(wg);
  assert.equal(bundle.filename, "wireguard-wg0-laptop.txt");
  assert.match(bundle.text, /PrivateKey = <client-private-key>/);
  assert.equal(vpnPeerTemplateFilename({ kind: "wireguard", interfaceName: "wg0:laptop", peerName: "road user" }, "conf"), "wireguard-wg0-laptop-road-user.conf");

  const enrollment = wireguardEnrollmentBundle(wg, {
    firewallPublicEndpoint: "vpn.example.gov",
    firewallPublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
  });
  assert.equal(enrollment.filename, "wireguard-wg0-laptop-enrollment.conf");
  assert.match(enrollment.text, /Phragma WireGuard enrollment bundle/);
  assert.match(enrollment.text, /QR-ready client configuration/);
  assert.match(enrollment.text, /PrivateKey = <client-private-key>/);
  assert.match(enrollment.text, /PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=/);
  assert.match(enrollment.text, /Endpoint = vpn\.example\.gov:51820/);
  assert.match(enrollment.text, /Address = 10\.99\.0\.2\/32/);
  assert.match(enrollment.text, /AllowedIPs = 10\.99\.0\.1\/24/);
  assert.match(enrollment.text, /PersistentKeepalive = 25/);
  assert.equal(enrollment.warnings.length, 0);
  assert.equal(wireguardEnrollmentQrFilename(enrollment), "wireguard-wg0-laptop-enrollment-qr.svg");
  const enrollmentQr = wireguardEnrollmentQrSvg(enrollment);
  assert.match(enrollmentQr, /^<svg /);
  assert.match(enrollmentQr, /viewBox="0 0 \d+ \d+"/);
  assert.match(enrollmentQr, /WireGuard enrollment QR code/);
  assert.match(enrollmentQr, /QR code containing the WireGuard enrollment configuration/);
  assert.equal(enrollmentQr.includes(enrollment.text), false, "WireGuard QR SVG should not expose the raw config as text");
  for (const leaked of ["/etc/phragma", "/etc/openngfw", "privateKeyFile", "private_key_file", "wg0.key", "Bearer ", "access_token", "pskFile"]) {
    assert.equal(enrollment.text.includes(leaked), false, `WireGuard enrollment leaked ${leaked}`);
    assert.equal(wireguardEnrollmentQrFilename(enrollment).includes(leaked), false, `WireGuard enrollment QR filename leaked ${leaked}`);
    assert.equal(enrollmentQr.includes(leaked), false, `WireGuard enrollment QR SVG leaked ${leaked}`);
  }

  const placeholderEnrollment = wireguardEnrollmentBundle(wg);
  assert.match(placeholderEnrollment.text, /PublicKey = <firewall-public-key>/);
  assert.match(placeholderEnrollment.text, /Endpoint = <firewall-public-endpoint>:51820/);
  assert.ok(placeholderEnrollment.warnings.some((warning) => /public endpoint/.test(warning)));
  assert.ok(placeholderEnrollment.warnings.some((warning) => /public key/.test(warning)));
}

{
  assert.deepEqual(ospfFromInputs(toggle(false), input(""), [{ area: input(""), networks: input("") }]), {
    ospf: { enabled: false, areas: [] },
  });
  const next = ospfFromInputs(toggle(true), input("192.0.2.1"), [
    { area: input("0.0.0.0"), networks: input("10.0.0.0/24\n10.0.1.0/24") },
  ]);
  assert.deepEqual(next.ospf, {
    enabled: true,
    routerId: "192.0.2.1",
    areas: [{ area: "0.0.0.0", networks: ["10.0.0.0/24", "10.0.1.0/24"] }],
  });
  assert.equal(ospfFromInputs(toggle(true), input(""), []).error, "At least one area is required.");
  assert.equal(
    ospfFromInputs(toggle(true), input(""), [{ area: input("0.0.0.0"), networks: input("") }]).error,
    "Area 0.0.0.0 needs at least one network.",
  );
  assert.equal(
    ospfFromInputs(toggle(true), input("not-ip"), [{ area: input("0.0.0.0"), networks: input("10.0.0.0/24") }]).error,
    "OSPF router ID must be an IPv4 address.",
  );
  assert.equal(
    ospfFromInputs(toggle(true), input(""), [{ area: input("bad-area"), networks: input("10.0.0.0/24") }]).error,
    "OSPF area bad-area must use dotted IPv4 format.",
  );
  assert.equal(
    ospfFromInputs(toggle(true), input(""), [{ area: input("0.0.0.0"), networks: input("10.0.0.0/33") }]).error,
    "OSPF network 10.0.0.0/33 must be a valid IPv4/IPv6 CIDR.",
  );
}

{
  const next = ipsecFromInputs(
    input(" site-b "),
    input(""),
    input(" 203.0.113.1 "),
    input("10.10.0.0/24,10.11.0.0/24"),
    input("10.20.0.0/24"),
    input(" /etc/phragma/secrets/site-b.conf "),
    input("aes256-sha256-modp2048"),
    input("aes256gcm16-prfsha256-ecp256"),
    toggle(true),
  );
  assert.deepEqual(next.tunnel, {
    name: "site-b",
    localSubnets: ["10.10.0.0/24", "10.11.0.0/24"],
    remoteSubnets: ["10.20.0.0/24"],
    pskFile: "/etc/phragma/secrets/site-b.conf",
    initiate: true,
    remoteAddress: "203.0.113.1",
    ikeProposal: "aes256-sha256-modp2048",
    espProposal: "aes256gcm16-prfsha256-ecp256",
  });
  assert.equal(
    ipsecFromInputs(input("site-b"), input(""), input("203.0.113.1"), input(""), input("10.20.0.0/24"), input("/etc/phragma/psk"), input(""), input(""), toggle(false)).error,
    "At least one local subnet is required.",
  );
  assert.equal(
    ipsecFromInputs(input("Site-B"), input(""), input("203.0.113.1"), input("10.10.0.0/24"), input("10.20.0.0/24"), input("/etc/phragma/secrets/site-b.conf"), input(""), input(""), toggle(false)).error,
    "Tunnel name must be lowercase alphanumeric with optional '-' or '_' and cannot be 'any'.",
  );
  assert.equal(
    ipsecFromInputs(input("site-b"), input(""), input("203.0.113.1;bad"), input("10.10.0.0/24"), input("10.20.0.0/24"), input("/etc/phragma/secrets/site-b.conf"), input(""), input(""), toggle(false)).error,
    "Remote endpoint contains characters unsafe for engine config.",
  );
  assert.equal(
    ipsecFromInputs(input("site-b"), input(""), input("203.0.113.1"), input("10.10.0.0/33"), input("10.20.0.0/24"), input("/etc/phragma/secrets/site-b.conf"), input(""), input(""), toggle(false)).error,
    "Local subnet 10.10.0.0/33 must be a valid IPv4/IPv6 CIDR.",
  );
  assert.equal(
    ipsecFromInputs(input("site-b"), input(""), input("203.0.113.1"), input("10.10.0.0/24"), input("10.20.0.0/33"), input("/etc/phragma/secrets/site-b.conf"), input(""), input(""), toggle(false)).error,
    "Remote subnet 10.20.0.0/33 must be a valid IPv4/IPv6 CIDR.",
  );
  assert.equal(
    ipsecFromInputs(input("site-b"), input(""), input("203.0.113.1"), input("10.10.0.0/24"), input("10.20.0.0/24"), input("/tmp/site-b.conf"), input(""), input(""), toggle(false)).error,
    "PSK file path must be an absolute managed path under /etc/phragma/secrets or /etc/openngfw/secrets.",
  );
  assert.equal(
    ipsecFromInputs(input("site-b"), input(""), input("203.0.113.1"), input("10.10.0.0/24"), input("10.20.0.0/24"), input("/etc/phragma/secrets/site-b.conf"), input("bad;proposal"), input(""), toggle(false)).error,
    "IKE proposal contains characters unsafe for engine config.",
  );
}

{
  const runtime = {
    state: "active",
    interfaces: [{
      name: "wg0",
      state: "active",
      peerCount: 2,
      activePeerCount: 1,
      peers: [
        { publicKey: "pubkey1", latestHandshakeUnixSeconds: 1780000000, latestHandshakeAgeSeconds: 90, state: "handshook" },
        { publicKey: "pubkey2", latestHandshakeUnixSeconds: 0, state: "waiting" },
      ],
    }],
  };
  const byInterface = wireguardRuntimeByInterface(runtime);
  assert.equal(byInterface.get("wg0").activePeerCount, 1);
  assert.equal(wireguardPeerRuntime(byInterface.get("wg0"), "pubkey1").state, "handshook");
  assert.equal(wireguardPeerRuntime(byInterface.get("wg0"), "missing"), null);
  assert.equal(wireguardPeerRuntimeLabel(wireguardPeerRuntime(byInterface.get("wg0"), "pubkey1")), "handshake 1m ago");
  assert.equal(wireguardPeerRuntimeLabel(wireguardPeerRuntime(byInterface.get("wg0"), "pubkey2")), "waiting");
  assert.equal(wireguardPeerRuntimeLabel(null), "not observed");
}

{
  const result = buildWireguardBranchRolloutPlan({
    staticRoutes: [{ destination: "10.10.0.0/24", interface: "wg-old" }],
    vpn: { wireguardInterfaces: [{ name: "wg-old", address: "10.90.0.1/24", privateKeyFile: "/etc/phragma/keys/wg-old.key", peers: [] }] },
  }, {
    interfaceName: " wg-branch-01 ",
    interfaceAddress: " 10.99.10.1/24 ",
    listenPort: "51820",
    privateKeyFile: " /etc/phragma/keys/wg-branch-01.key ",
    peerName: " branch-01 ",
    publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    endpoint: " 198.51.100.10:51820 ",
    allowedIps: "10.99.10.2/32, 10.120.10.0/24",
    keepalive: "25",
    routeDestination: " 10.120.10.0/24 ",
    routeMetric: "50",
  });
  assert.deepEqual(result.iface, {
    name: "wg-branch-01",
    address: "10.99.10.1/24",
    privateKeyFile: "/etc/phragma/keys/wg-branch-01.key",
    peers: [{
      name: "branch-01",
      publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      endpoint: "198.51.100.10:51820",
      allowedIps: ["10.99.10.2/32", "10.120.10.0/24"],
      persistentKeepalive: 25,
    }],
    listenPort: 51820,
  });
  assert.deepEqual(result.route, {
    destination: "10.120.10.0/24",
    interface: "wg-branch-01",
    metric: 50,
  });
  assert.match(result.warnings.join("\n"), /Firewall public endpoint/);
  assert.equal(buildWireguardBranchRolloutPlan({}, { interfaceName: "wg0" }).error, "Interface address is required.");
  assert.equal(buildWireguardBranchRolloutPlan({}, {
    interfaceName: "wg0",
    interfaceAddress: "10.99.0.1/33",
  }).error, "Interface address must be a valid IPv4/IPv6 CIDR.");
  assert.equal(buildWireguardBranchRolloutPlan({}, {
    interfaceName: "wg0",
    interfaceAddress: "10.99.0.1/24",
    privateKeyFile: "/tmp/wg0.key",
  }).error, "Private key file path must be an absolute managed path under /etc/phragma/keys or /etc/openngfw/keys.");
  assert.equal(buildWireguardBranchRolloutPlan({}, {
    interfaceName: "wg0",
    interfaceAddress: "10.99.0.1/24",
    privateKeyFile: "/etc/phragma/keys/wg0.key",
    peerName: "branch",
    publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    allowedIps: "10.99.0.2/32",
    routeDestination: "10.120.0.0/24",
  }).error, "Allowed IPs must include the routed branch prefix.");
  assert.equal(buildWireguardBranchRolloutPlan({}, {
    interfaceName: "wg0",
    interfaceAddress: "10.99.0.1/24",
    privateKeyFile: "/etc/phragma/keys/wg0.key",
    peerName: "branch",
    publicKey: "not-a-wireguard-key",
    allowedIps: "10.120.0.0/24",
    routeDestination: "10.120.0.0/24",
  }).error, "branch public key must be a base64 32-byte WireGuard key.");
  assert.equal(buildWireguardBranchRolloutPlan({}, {
    interfaceName: "wg0",
    interfaceAddress: "10.99.0.1/24",
    privateKeyFile: "/etc/phragma/keys/wg0.key",
    peerName: "branch",
    publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    endpoint: "203.0.113.10",
    allowedIps: "10.120.0.0/24",
    routeDestination: "10.120.0.0/24",
  }).error, "branch endpoint must be host:port.");
  assert.equal(buildWireguardBranchRolloutPlan({}, {
    interfaceName: "wg0",
    interfaceAddress: "10.99.0.1/24",
    listenPort: "65536",
    privateKeyFile: "/etc/phragma/keys/wg0.key",
    peerName: "branch",
    publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    allowedIps: "10.120.0.0/24",
    routeDestination: "10.120.0.0/24",
  }).error, "Listen port must be an integer from 1 to 65535, or blank.");
  assert.equal(buildWireguardBranchRolloutPlan({
    staticRoutes: [{ destination: "10.120.0.0/24", interface: "wg0" }],
  }, {
    interfaceName: "wg1",
    interfaceAddress: "10.99.1.1/24",
    privateKeyFile: "/etc/phragma/keys/wg1.key",
    peerName: "branch",
    publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    allowedIps: "10.120.0.0/24",
    routeDestination: "10.120.0.0/24",
  }).error, "Static route 10.120.0.0/24 already exists in the candidate.");
  assert.equal(buildWireguardBranchRolloutPlan({
    vpn: { wireguardInterfaces: [{ name: "wg1" }] },
  }, {
    interfaceName: "wg1",
    interfaceAddress: "10.99.1.1/24",
    privateKeyFile: "/etc/phragma/keys/wg1.key",
    peerName: "branch",
    publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    allowedIps: "10.120.0.0/24",
    routeDestination: "10.120.0.0/24",
  }).error, "WireGuard interface wg1 already exists in the candidate.");
}

{
  const next = wireguardFromInputs(
    input(" wg0 "),
    input(" 10.99.0.1/24 "),
    input("51820"),
    input(" /etc/phragma/keys/wg0.key "),
    [
      {
        peerName: input("laptop"),
        publicKey: input("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        endpoint: input("203.0.113.10:51820"),
        allowedIps: input("10.99.0.2/32,10.99.1.0/24"),
        keepalive: input("25"),
      },
    ],
  );
  assert.deepEqual(next.iface, {
    name: "wg0",
    address: "10.99.0.1/24",
    privateKeyFile: "/etc/phragma/keys/wg0.key",
    peers: [{
      name: "laptop",
      publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      endpoint: "203.0.113.10:51820",
      allowedIps: ["10.99.0.2/32", "10.99.1.0/24"],
      persistentKeepalive: 25,
    }],
    listenPort: 51820,
  });
  assert.equal(
    wireguardFromInputs(input("wg0"), input("10.99.0.1/24"), input(""), input("/etc/phragma/keys/wg0.key"), [
      { peerName: input("laptop"), publicKey: input(""), endpoint: input(""), allowedIps: input("10.99.0.2/32"), keepalive: input("") },
    ]).error,
    "laptop needs a public key.",
  );
  assert.equal(
    wireguardFromInputs(input("wg0"), input("10.99.0.1/24"), input(""), input("/etc/phragma/keys/wg0.key"), [
      { peerName: input("laptop"), publicKey: input("not-a-wireguard-key"), endpoint: input(""), allowedIps: input("10.99.0.2/32"), keepalive: input("") },
    ]).error,
    "laptop public key must be a base64 32-byte WireGuard key.",
  );
  assert.equal(
    wireguardFromInputs(input("wg0"), input("10.99.0.1/24"), input(""), input("/etc/phragma/keys/wg0.key"), [
      { peerName: input(""), publicKey: input("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), endpoint: input(""), allowedIps: input(""), keepalive: input("") },
    ]).error,
    "peer needs at least one allowed IP.",
  );
  assert.equal(
    wireguardFromInputs(input("wg/0"), input("10.99.0.1/24"), input(""), input("/etc/phragma/keys/wg0.key"), []).error,
    "Interface name must be 1-15 characters without whitespace, slash, or control characters.",
  );
  assert.equal(
    wireguardFromInputs(input("wg0"), input("10.99.0.1/33"), input(""), input("/etc/phragma/keys/wg0.key"), []).error,
    "Interface address must be a valid IPv4/IPv6 CIDR.",
  );
  assert.equal(
    wireguardFromInputs(input("wg0"), input("10.99.0.1/24"), input("65536"), input("/etc/phragma/keys/wg0.key"), []).error,
    "Listen port must be an integer from 1 to 65535, or blank.",
  );
  assert.equal(
    wireguardFromInputs(input("wg0"), input("10.99.0.1/24"), input(""), input("/tmp/wg0.key"), []).error,
    "Private key file path must be an absolute managed path under /etc/phragma/keys or /etc/openngfw/keys.",
  );
  assert.equal(
    wireguardFromInputs(input("wg0"), input("10.99.0.1/24"), input(""), input("/etc/phragma/keys/wg0.key"), [
      { peerName: input("laptop"), publicKey: input("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), endpoint: input(""), allowedIps: input("10.99.0.2/33"), keepalive: input("") },
    ]).error,
    "laptop allowed IP 10.99.0.2/33 must be a valid IPv4/IPv6 CIDR.",
  );
  assert.equal(
    wireguardFromInputs(input("wg0"), input("10.99.0.1/24"), input(""), input("/etc/phragma/keys/wg0.key"), [
      { peerName: input("laptop"), publicKey: input("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), endpoint: input("203.0.113.10"), allowedIps: input("10.99.0.2/32"), keepalive: input("") },
    ]).error,
    "laptop endpoint must be host:port.",
  );
  assert.equal(
    wireguardFromInputs(input("wg0"), input("10.99.0.1/24"), input(""), input("/etc/phragma/keys/wg0.key"), [
      { peerName: input("laptop"), publicKey: input("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), endpoint: input("203.0.113.10:51820"), allowedIps: input("10.99.0.2/32"), keepalive: input("25abc") },
    ]).error,
    "laptop keepalive must be an integer from 1 to 65535, or blank/0.",
  );
}
