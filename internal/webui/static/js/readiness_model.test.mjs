import assert from "node:assert/strict";

import { dataplaneNameRequiresEbpf, ebpfBlocksCurrentDataplane } from "./dataplane.js";
import { apiContractSourceAcceptanceModel, buildHAEvidencePacket, buildSystemEvidencePacket, dynamicRoutingEnabled, haEvidencePacketReport, haReadiness, readinessActionHash, releaseArtifactWorkbenchModel, releaseEvidenceChecklist, releaseEvidenceCounts, releaseEvidencePacketDefinition, releaseEvidencePacketIds, releaseEvidenceReport, remediationActionId, remediationSteps, routingRuntimeEvidence, summarizeReadiness, systemEvidencePacketReport } from "./readiness_model.js";

const degradedEbpf = {
  state: "degraded",
  degraded: [{ name: "bpftool", state: "degraded" }],
  detail: "missing bpftool",
};

const externalReleaseGateIds = [
  "content-production-readiness",
  "webui-enterprise-smoke",
  "privileged-integration",
  "m3-live-networking",
  "m3-field-evidence",
  "ebpf-ol9-field-evidence",
  "m5-oidc-field-evidence",
  "m5-saml-field-evidence",
];

const externalFieldGateIds = [
  "privileged-integration",
  "m3-live-networking",
  "m3-field-evidence",
  "ebpf-ol9-field-evidence",
  "m5-oidc-field-evidence",
  "m5-saml-field-evidence",
];

const rootlessReleaseGateIds = [
  "proto-verify",
  "deploy-hardening",
  "policy-restore-drill",
  "ha-readiness-recovery",
  "e2e-install",
  "content-package-verification",
  "m5-auth-ui",
  "m5-oidc-provider",
];

const documentedReferencePaths = new Set([
  "docs/RELEASE_ACCEPTANCE.md#approved-evidence-flow",
  "docs/testing-plan.md#phase-3--routing--vpn-m3--gaps-b-c-d",
  "docs/testing-plan.md#phase-5--authnz--ui-m5--gap-f",
  "docs/webui-design.md#settings-and-system-configuration",
]);

const externalReleaseGateEvidencePackets = {
  "content-production-readiness": {
    checkName: "content-production-readiness",
    makeTargets: ["content-production-readiness-check", "release-evidence-content-production-readiness"],
    evidenceDirectory: "release/field-evidence/content-production",
    artifactPath: "release/evidence/content-production-readiness.txt",
    reference: "docs/RELEASE_ACCEPTANCE.md#approved-evidence-flow",
    summary: /production App-ID, Threat-ID, and intel-feed|production content/i,
  },
  "webui-enterprise-smoke": {
    checkName: "webui-enterprise-smoke",
    makeTargets: ["webui-enterprise-smoke", "release-evidence-webui-enterprise-smoke"],
    evidenceDirectory: "release/evidence",
    artifactPath: "release/evidence/webui-enterprise-smoke.txt",
    reference: "docs/RELEASE_ACCEPTANCE.md#approved-evidence-flow",
    summary: /broad WebUI enterprise smoke|current 20-route operator route set|\/compliance|continuation or targeted repair evidence is diagnostic/i,
    commands: [
      "make webui-enterprise-smoke",
      "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-webui-enterprise-smoke",
    ],
  },
  "privileged-integration": {
    checkName: "privileged-integration",
    makeTargets: ["integration-test", "release-evidence-privileged-integration"],
    evidenceDirectory: "release/evidence",
    artifactPath: "release/evidence/privileged-integration.txt",
    reference: "docs/RELEASE_ACCEPTANCE.md#approved-evidence-flow",
    summary: /root Linux host|real engines|live dataplane/i,
  },
  "m3-live-networking": {
    checkName: "m3-live-networking",
    makeTargets: ["m3-live-networking", "release-evidence-m3-live-networking"],
    evidenceDirectory: "release/evidence",
    artifactPath: "release/evidence/m3-live-networking.txt",
    reference: "docs/RELEASE_ACCEPTANCE.md#approved-evidence-flow",
    summary: /static-route forwarding|FRR BGP|WireGuard peer traffic/i,
    commands: [
      "make m3-live-networking-check",
      "sudo make m3-live-networking",
      "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-m3-live-networking",
    ],
  },
  "m3-field-evidence": {
    checkName: "m3-field-evidence",
    makeTargets: ["m3-field-evidence-check", "release-evidence-m3-field-evidence"],
    evidenceDirectory: "release/field-evidence/m3",
    artifactPath: "release/evidence/m3-field-evidence.txt",
    reference: "docs/testing-plan.md#phase-3--routing--vpn-m3--gaps-b-c-d",
    summary: /External BGP peer|IPsec|WireGuard/i,
  },
  "ebpf-ol9-field-evidence": {
    checkName: "ebpf-ol9-field-evidence",
    makeTargets: ["ebpf-ol9-field-evidence-check", "release-evidence-ebpf-ol9-field-evidence"],
    evidenceDirectory: "release/field-evidence/ebpf-ol9",
    artifactPath: "release/evidence/ebpf-ol9-field-evidence.txt",
    reference: "docs/RELEASE_ACCEPTANCE.md#approved-evidence-flow",
    summary: /OL9\/OCI Linux-root|XDP\/tc|renderer scaffold/i,
    commands: [
      "make ebpf-ol9-attach-drill-check",
      "sudo -E EBPF_OL9_ATTACH_IFACE=<disposable-interface> EBPF_OL9_STATUS_JSON_COMMAND='<command that prints /v1/system/status eBPF JSON>' make ebpf-ol9-attach-drill EBPF_OL9_FIELD_EVIDENCE_DIR=release/field-evidence/ebpf-ol9",
      "make ebpf-ol9-field-evidence-check EBPF_OL9_FIELD_EVIDENCE_DIR=release/field-evidence/ebpf-ol9",
      "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-ebpf-ol9-field-evidence EBPF_OL9_FIELD_EVIDENCE_DIR=release/field-evidence/ebpf-ol9",
    ],
  },
  "m5-oidc-field-evidence": {
    checkName: "m5-oidc-field-evidence",
    makeTargets: ["m5-oidc-field-evidence-check", "release-evidence-m5-oidc-field-evidence"],
    evidenceDirectory: "release/field-evidence/oidc",
    artifactPath: "release/evidence/m5-oidc-field-evidence.txt",
    reference: "docs/testing-plan.md#phase-5--authnz--ui-m5--gap-f",
    summary: /real issuer\/client|OIDC|browser SSO/i,
  },
  "m5-saml-field-evidence": {
    checkName: "m5-saml-field-evidence",
    makeTargets: ["m5-saml-field-evidence-check", "release-evidence-m5-saml-field-evidence"],
    evidenceDirectory: "release/field-evidence/saml",
    artifactPath: "release/evidence/m5-saml-field-evidence.txt",
    reference: "docs/RELEASE_ACCEPTANCE.md#approved-evidence-flow",
    summary: /SAML|browser SSO|does not claim live IdP success/i,
    commands: [
      "mkdir -p release/field-evidence/saml/{provider,deployment,browser,rbac,redaction} && printf '%s\\n' 'Copy redacted SAML IdP/SP, ACS, browser, RBAC, and redaction artifacts into release/field-evidence/saml; this command only prepares the bundle directory.'",
      "make m5-saml-field-evidence-check SAML_FIELD_EVIDENCE_DIR=release/field-evidence/saml",
      "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-m5-saml-field-evidence SAML_FIELD_EVIDENCE_DIR=release/field-evidence/saml",
    ],
  },
};

const rootlessReleaseGateEvidencePackets = {
  "proto-verify": {
    checkName: "proto-verify",
    makeTargets: ["proto-verify", "release-evidence-proto-verify"],
    evidenceDirectory: "release/evidence",
    artifactPath: "release/evidence/proto-verify.txt",
    reference: "docs/RELEASE_ACCEPTANCE.md#approved-evidence-flow",
    summary: /protobuf|OpenAPI|proto source/i,
    commands: ["make proto-status", "make proto-verify", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-proto-verify"],
  },
  "deploy-hardening": {
    checkName: "deploy-hardening",
    makeTargets: ["deploy-hardening-check", "release-evidence-deploy-hardening"],
    evidenceDirectory: "release/evidence",
    artifactPath: "release/evidence/deploy-hardening.txt",
    reference: "docs/RELEASE_ACCEPTANCE.md#approved-evidence-flow",
    summary: /static packaged deployment evidence|deploy\/systemd\/controld\.service and deploy\/install\.sh only|does not start controld|runtime hardening/i,
    commands: ["bash release/deploy-hardening-check.sh --check", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-deploy-hardening"],
  },
  "policy-restore-drill": {
    checkName: "policy-restore-drill",
    makeTargets: ["policy-restore-drill-check", "release-evidence-policy-restore-drill"],
    evidenceDirectory: "release/evidence",
    artifactPath: "release/evidence/policy-restore-drill.txt",
    reference: "docs/RELEASE_ACCEPTANCE.md#approved-evidence-flow",
    summary: /policy restore|rollback|last-known-good|LKG/i,
    commands: ["make policy-restore-drill-check", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-policy-restore-drill"],
  },
  "ha-readiness-recovery": {
    checkName: "ha-readiness-recovery",
    makeTargets: ["ha-readiness-recovery-check", "release-evidence-ha-readiness-recovery"],
    evidenceDirectory: "release/evidence",
    artifactPath: "release/evidence/ha-readiness-recovery.txt",
    reference: "docs/RELEASE_ACCEPTANCE.md#approved-evidence-flow",
    summary: /active\/passive HA readiness|control-plane recovery|VIP\/route promotion|fencing|connection-state sync/i,
    commands: ["make ha-readiness-recovery-check", "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-ha-readiness-recovery"],
  },
  "e2e-install": {
    checkName: "e2e-install",
    makeTargets: ["e2e-install", "release-evidence-e2e-install"],
    evidenceDirectory: "release/evidence",
    artifactPath: "release/evidence/e2e-install.txt",
    reference: "docs/RELEASE_ACCEPTANCE.md#approved-evidence-flow",
    summary: /installed-service commit|namespace traffic/i,
  },
};

function byId(items) {
  return Object.fromEntries(items.map((item) => [item.id, item]));
}

function asStringArray(value) {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean);
  if (typeof value === "string" && value.trim()) return [value.trim()];
  return [];
}

function evidencePacketFor(item) {
  for (const key of ["evidencePacket", "releaseEvidence", "evidence", "evidenceRequirement", "packet"]) {
    if (item[key] && typeof item[key] === "object" && !Array.isArray(item[key])) return item[key];
  }

  for (const key of ["checkName", "check", "commands", "command", "makeTargets", "evidencePath", "evidenceDir", "evidenceDirectory", "summary", "evidenceSummary"]) {
    if (item[key] !== undefined) return item;
  }

  assert.fail(`${item.id} evidence packet missing`);
}

function packetString(packet, item, label, keys, { allowItemFallback = false } = {}) {
  for (const key of keys) {
    if (typeof packet[key] === "string" && packet[key].trim()) return packet[key].trim();
  }

  if (allowItemFallback) {
    for (const key of keys) {
      if (typeof item[key] === "string" && item[key].trim()) return item[key].trim();
    }
  }

  assert.fail(`${item.id} ${label} missing`);
}

function packetMakeTargets(packet, item) {
  const explicitTargets = asStringArray(packet.makeTargets || packet.targets || packet.makefileTargets);
  if (explicitTargets.length) return explicitTargets;

  const commands = asStringArray(packet.commands || packet.command || item.commands || item.command);
  assert.ok(commands.length, `${item.id} evidence commands missing`);

  const targets = [];
  for (const command of commands) {
    const match = command.match(/\bmake\s+([A-Za-z0-9_.-]+)/);
    if (match) targets.push(match[1]);
  }

  assert.ok(targets.length, `${item.id} evidence commands should expose Makefile targets`);
  return targets;
}

function evidenceDirectory(path) {
  const normalized = String(path || "").trim();
  if (!normalized.endsWith(".txt")) return normalized;
  return normalized.slice(0, normalized.lastIndexOf("/"));
}

function assertExternalEvidencePacket(item, expected) {
  const packet = evidencePacketFor(item);
  const checkName = packetString(packet, item, "checkName", ["checkName", "check"]);
  const evidencePath = packetString(packet, item, "evidencePath", ["evidencePath", "evidenceDir", "evidenceDirectory"]);
  const artifactPath = packetString(packet, item, "artifactPath", ["artifactPath", "recordPath", "recordArtifactPath"]);
  const reference = packetString(packet, item, "reference", ["reference"], { allowItemFallback: true });
  const summary = packetString(packet, item, "summary", ["summary", "evidenceSummary", "detail"], { allowItemFallback: true });

  assert.equal(checkName, expected.checkName, `${item.id} checkName`);
  assert.deepEqual(packetMakeTargets(packet, item), expected.makeTargets, `${item.id} Makefile targets`);
  assert.equal(evidenceDirectory(evidencePath), expected.evidenceDirectory, `${item.id} evidence directory`);
  assert.equal(artifactPath, expected.artifactPath, `${item.id} artifactPath`);
  assert.equal(reference, expected.reference, `${item.id} reference`);
  assert.match(summary, expected.summary, `${item.id} summary`);
  if (expected.commands) {
    assert.deepEqual(asStringArray(packet.commands), expected.commands, `${item.id} commands`);
  }
}

function assertChecklistItemContract(items) {
  const seenIds = new Set();
  for (const item of items) {
    for (const key of ["id", "title", "detail", "meta", "href"]) {
      assert.equal(typeof item[key], "string", `${item.id || "release evidence item"} ${key} should be a string`);
      assert.ok(item[key].trim(), `${item.id || "release evidence item"} ${key} should be non-empty`);
    }

    assert.ok(!seenIds.has(item.id), `${item.id} should be unique`);
    seenIds.add(item.id);
    assert.ok(item.href.startsWith("#/"), `${item.id} href should be an in-app hash route`);

    if (item.reference !== undefined) {
      assert.equal(typeof item.reference, "string", `${item.id} reference should be a string`);
      assert.ok(documentedReferencePaths.has(item.reference), `${item.id} reference should be documented`);
    }
  }
}

{
  assert.equal(dataplaneNameRequiresEbpf("nftables/conntrack"), false);
  assert.equal(dataplaneNameRequiresEbpf("linux-ebpf-xdp/tc"), true);
  assert.equal(dataplaneNameRequiresEbpf("tc"), true);
  assert.equal(ebpfBlocksCurrentDataplane({ dataplane: { activeDataplane: "nftables/conntrack" } }, degradedEbpf), false);
  assert.equal(ebpfBlocksCurrentDataplane({ dataplane: { activeDataplane: "linux-ebpf-xdp/tc" } }, degradedEbpf), true);
}

{
  assert.equal(dynamicRoutingEnabled({}), false);
  assert.equal(dynamicRoutingEnabled({ routing: { bgp: { enabled: true } } }), true);
  assert.equal(dynamicRoutingEnabled({ routing: { ospf: { enabled: true } } }), true);
  assert.deepEqual(routingRuntimeEvidence({}, {}).state, "not-configured");
  assert.equal(routingRuntimeEvidence({
    routing: {
      frr: {
        state: "waiting",
        detail: "1 BGP neighbor(s), 0 OSPF neighbor(s)",
        bgpNeighbors: [{ peer: "198.51.100.2", state: "Connect" }],
      },
    },
  }, { routing: { bgp: { enabled: true } } }).bgpCount, 1);
}

{
  const routingRuntime = routingRuntimeEvidence({
    routing: {
      frr: {
        state: "waiting",
        detail: "1 BGP neighbor(s), no established sessions",
        bgpNeighbors: [{ peer: "198.51.100.2", state: "Connect" }],
      },
    },
  }, { routing: { bgp: { enabled: true } } });
  const summary = summarizeReadiness(
    { runtime: { activeDataplane: "nftables/conntrack" }, warnings: [], engines: [{ state: "ready" }] },
    { state: "standard" },
    { state: "ready" },
    { state: "inactive" },
    { state: "ready" },
    { state: "ready" },
    null,
    routingRuntime,
  );
  assert.equal(summary.cls, "bad");
  assert.match(summary.detail, /dynamic routing runtime evidence is not active/);

  const steps = remediationSteps(
    { runtime: { activeDataplane: "nftables/conntrack" }, warnings: [], engines: [] },
    { state: "standard" },
    { state: "ready" },
    { state: "inactive" },
    { state: "ready" },
    { state: "ready" },
    {},
    null,
    routingRuntime,
  );
  assert.ok(steps.some((step) => step.title === "Verify FRR dynamic-routing runtime evidence" && step.href === "#/netvpn"));
}

{
  const summary = summarizeReadiness(
    {
      runtime: { activeDataplane: "nftables/conntrack" },
      capabilities: [{ name: "Linux eBPF XDP/tc host readiness", state: "degraded" }],
      warnings: [],
      engines: [{ state: "ready" }],
    },
    { state: "standard" },
    { state: "ready" },
    { state: "inactive" },
    degradedEbpf,
    { state: "ready" },
  );

  assert.equal(summary.cls, "warn");
  assert.equal(summary.title, "Ready with warnings");
  assert.match(summary.detail, /eBPF milestone prerequisite gap/);
}

{
  const summary = summarizeReadiness(
    {
      runtime: { activeDataplane: "linux-ebpf-xdp/tc" },
      capabilities: [{ name: "Linux eBPF XDP/tc host readiness", state: "degraded" }],
      warnings: [],
      engines: [{ state: "ready" }],
    },
    { state: "standard" },
    { state: "ready" },
    { state: "inactive" },
    degradedEbpf,
    { state: "ready" },
  );

  assert.equal(summary.cls, "bad");
  assert.equal(summary.title, "Not production ready");
  assert.match(summary.detail, /eBPF host prerequisites incomplete for the active dataplane/);
}

{
  const status = {
    runtime: { activeDataplane: "nftables/conntrack" },
    warnings: [],
    engines: [{ state: "ready" }],
    highAvailability: {
      state: "degraded",
      mode: "active-passive",
      role: "active",
      nodeId: "fw-a",
      peerId: "fw-b",
      runningPolicyVersion: 9,
      lastKnownGoodVersion: 8,
      lastKnownGoodState: "active",
      sync: { state: "degraded", detail: "peer missing" },
      fencingEvidence: {
        state: "recorded",
        provider: "operator-runbook",
        claim: "peer_power_off_verified",
        peerId: "fw-b",
        evidenceId: "change-1234",
        observedAt: "2026-06-18T11:55:00Z",
        detail: "Read-only external evidence recorded; OpenNGFW did not fence the peer.",
      },
      failover: { state: "planned", eligible: false },
      blockers: ["HA peer address is not configured."],
    },
  };
  const ha = haReadiness(status);
  assert.equal(ha.cls, "bad");
  assert.equal(ha.meta, "mode:active-passive role:active running:v9 lkg:v8");
  assert.match(ha.detail, /HA peer address/);

  const packet = buildHAEvidencePacket(status, { generatedAt: "2026-06-18T12:00:00Z" });
  assert.equal(packet.schema, "phragma.ha.evidence.v1");
  assert.equal(packet.generatedAt, "2026-06-18T12:00:00Z");
  assert.equal(packet.state, "degraded");
  assert.equal(packet.cls, "bad");
  assert.equal(packet.sync.state, "degraded");
  assert.equal(packet.failover.eligible, false);
  assert.equal(packet.fencingEvidence.state, "recorded");
  assert.equal(packet.fencingEvidence.provider, "operator-runbook");
  assert.deepEqual(packet.blockers, ["HA peer address is not configured."]);
  assert.ok(packet.rows.some((row) => row.id === "ha-peer-sync" && row.cls === "bad"));
  assert.ok(packet.rows.some((row) => row.id === "ha-fencing-evidence" && row.cls === "ok" && /provider:operator-runbook/.test(row.meta)));
  assert.ok(packet.rows.some((row) => row.id === "ha-blockers" && row.meta === "peer_address:missing"));
  assert.match(packet.text, /^OpenNGFW high availability evidence packet\n/);
  assert.match(packet.text, /schema=phragma\.ha\.evidence\.v1/);
  assert.match(packet.text, /peer_address=missing/);
  assert.match(packet.text, /failover_eligible=false/);
  assert.match(packet.text, /fencing_evidence_state=recorded/);
  assert.match(packet.text, /fencing_evidence_provider=operator-runbook/);
  assert.match(packet.text, /fencing_evidence_claim=peer_power_off_verified/);
  assert.match(packet.text, /blockers=HA peer address is not configured\./);
  assert.match(haEvidencePacketReport(packet), /transport_evidence_state=not_configured/);
  assert.match(haEvidencePacketReport(packet), /conntrack_sync_state=not_configured/);
  assert.match(haEvidencePacketReport(packet), /note=This packet records HA readiness, peer-fencing, VIP\/GARP\/neighbor, and conntrack-sync evidence status only; it does not execute peer sync or failover, peer fencing, production failover traffic movement, or traffic path proof\./);

  const unavailablePacket = buildHAEvidencePacket({ runtime: { activeDataplane: "nftables/conntrack" } }, { generatedAt: "2026-06-18T12:05:00Z" });
  assert.equal(unavailablePacket.cls, "info");
  assert.equal(unavailablePacket.title, "HA evidence unavailable");
  assert.match(unavailablePacket.detail, /High availability status was not returned/);
  assert.match(unavailablePacket.text, /state=unknown/);
  assert.match(unavailablePacket.text, /peer_address=missing/);
  assert.match(unavailablePacket.text, /fencing_evidence_state=not_recorded/);

  const summary = summarizeReadiness(
    status,
    { state: "standard" },
    { state: "ready" },
    { state: "inactive" },
    { state: "ready" },
    { state: "ready" },
  );
  assert.equal(summary.cls, "bad");
  assert.match(summary.detail, /active\/passive HA readiness is degraded/);

  const steps = remediationSteps(
    status,
    { state: "standard" },
    { state: "ready" },
    { state: "inactive" },
    { state: "ready" },
    { state: "ready" },
  );
  assert.ok(steps.some((step) => step.id === "ha-readiness" && step.title === "Resolve active/passive HA blockers"));
}

{
  const steps = remediationSteps(
    {
      runtime: { dryRun: true, activeDataplane: "nftables/conntrack" },
      warnings: [{ severity: "warning", message: "TLS is disabled", action: "Enable TLS before remote exposure." }],
      engines: [{ name: "suricata", state: "failed", detail: "last exit status 1" }],
    },
    { state: "accelerated", accelerated: true },
    { state: "ready" },
    { state: "inactive", detail: "flowtable counters did not move" },
    { state: "ready" },
    { state: "degraded", detail: "92.5% used" },
    {
      needsAction: true,
      detail: "1 kernel tuning issue",
      remediationCommand: "sudo ngfwctl system tune --write --apply",
      throughputCommand: "sudo ngfwctl system tune --profile throughput --write --apply",
      throughputReady: false,
      throughputDetail: "State table limit 262,144; throughput profile target 4,194,304+.",
    },
  );

  const ids = steps.map((step) => step.id);
  assert.equal(new Set(ids).size, ids.length);
  assert.ok(ids.every(Boolean));
  assert.equal(steps[0].title, "Disable dry-run before production");
  assert.equal(steps[0].id, "dry-run");
  assert.equal(steps[0].level, "high");
  assert.ok(steps.some((step) => step.id === "tls-is-disabled" && step.title === "TLS is disabled"));
  assert.ok(steps.some((step) => step.id === "host-sysctl-baseline" && step.command.includes("system tune --write --apply")));
  assert.ok(steps.some((step) => step.id === "conntrack-pressure" && step.command.includes("--profile throughput")));
  assert.ok(steps.some((step) => step.id === "flowtable-runtime-evidence" && step.command === "ngfwctl status"));
  assert.ok(steps.some((step) => step.id === "engine-suricata" && step.command === "sudo systemctl restart controld"));
  assert.equal(remediationActionId("TLS is disabled"), "tls-is-disabled");
  assert.equal(readinessActionHash("flowtable-runtime-evidence"), "#/readiness?action=flowtable-runtime-evidence");
  assert.equal(readinessActionHash("TLS is disabled"), "#/readiness?action=tls-is-disabled");
  assert.equal(readinessActionHash(""), "#/readiness");
}

{
  const steps = remediationSteps(
    { runtime: { activeDataplane: "nftables/conntrack" }, warnings: [], engines: [{ state: "ready" }] },
    { state: "invalid", accelerated: true, detail: "flowtable conflicts with inspection" },
    { state: "missing", detail: "nft flowtable prerequisites are missing" },
    { state: "inactive" },
    { state: "ready" },
    { state: "ready" },
    { needsAction: false },
  );

  assert.ok(steps.some((step) => step.id === "policy-dataplane-conflict" && step.href === "#/settings?panel=network"));
  assert.ok(steps.some((step) => step.id === "flowtable-host-ready" && step.href === "#/settings?panel=network"));
}

{
  const steps = remediationSteps(
    {
      runtime: { activeDataplane: "nftables/conntrack" },
      capabilities: [{ name: "Linux eBPF XDP/tc host readiness", state: "degraded", detail: "missing bpftool" }],
    },
    { state: "standard", accelerated: false },
    { state: "ready" },
    { state: "inactive" },
    degradedEbpf,
    { state: "ready" },
    {},
  );

  assert.equal(steps.length, 1);
  assert.equal(steps[0].level, "medium");
  assert.equal(steps[0].title, "Track the strategic eBPF readiness gap");
}

{
  const contentPosture = {
    summary: { cls: "warn", detail: "missing content controls" },
    blockers: ["signed manifest", "regression result", "package rollback"],
  };
  const summary = summarizeReadiness(
    {
      runtime: { activeDataplane: "nftables/conntrack" },
      warnings: [],
      engines: [{ state: "ready" }],
      capabilities: [],
    },
    { state: "standard" },
    { state: "ready" },
    { state: "inactive" },
    { state: "ready" },
    { state: "ready" },
    contentPosture,
  );
  const steps = remediationSteps(
    {
      runtime: { activeDataplane: "nftables/conntrack" },
      warnings: [],
      engines: [{ state: "ready" }],
      capabilities: [],
    },
    { state: "standard" },
    { state: "ready" },
    { state: "inactive" },
    { state: "ready" },
    { state: "ready" },
    {},
    contentPosture,
  );

  assert.equal(summary.cls, "bad");
  assert.equal(summary.title, "Not production ready");
  assert.match(summary.detail, /3 content package blocker/);
  assert.ok(steps.some((step) => step.title === "Resolve content package blockers" && step.href === "#/intel"));
}

{
  const items = releaseEvidenceChecklist();
  const gates = byId(items);
  assertChecklistItemContract(items);

  for (const id of externalReleaseGateIds) {
    assert.ok(gates[id], `${id} gate missing`);
    assert.equal(gates[id].cls, "bad");
    assert.notEqual(gates[id].label, "clear");
    assert.ok(gates[id].href, `${id} href missing`);
  }

  assert.match(gates["content-production-readiness"].detail, /demo smoke are not enough/);
  assert.match(gates["webui-enterprise-smoke"].detail, /current 20-route operator route set/);
  assert.match(gates["webui-enterprise-smoke"].detail, /\/compliance/);
  assert.match(gates["webui-enterprise-smoke"].detail, /continuation evidence.*do not record durable release evidence/);
  assert.match(gates["privileged-integration"].detail, /root Linux host/);
  assert.match(gates["m3-live-networking"].detail, /static-route forwarding/);
  assert.match(gates["m3-field-evidence"].detail, /External BGP peer/);
  assert.match(gates["m5-oidc-field-evidence"].detail, /real issuer\/client/);
  assert.match(gates["m5-saml-field-evidence"].detail, /real IdP\/SP metadata/);
  for (const [id, expected] of Object.entries(externalReleaseGateEvidencePackets)) {
    assertExternalEvidencePacket(gates[id], expected);
  }

  const counts = releaseEvidenceCounts(items);
  assert.equal(counts.blocked, 8);
  assert.equal(counts.review, 1);
  assert.equal(counts.clear, 2);
  assert.equal(counts.info, 5);
}

{
  const packetIds = releaseEvidencePacketIds();
  assert.deepEqual(new Set(packetIds), new Set([
    ...externalReleaseGateIds,
    ...rootlessReleaseGateIds,
    "release-benchmark",
  ]));
  assert.equal(new Set(packetIds).size, packetIds.length, "release packet ids should be unique");

  const items = releaseEvidenceChecklist({
    releaseAcceptanceStatus: {
      checks: packetIds.map((name) => ({ name, state: "missing", evidencePath: `release/evidence/${name}.txt` })),
    },
  });
  const packetItems = new Map(items.filter((item) => item.packet).map((item) => [item.id, item]));
  for (const id of packetIds) {
    const definition = releaseEvidencePacketDefinition(id);
    assert.ok(definition, `${id} catalog definition missing`);
    assert.equal(definition.id, id);
    assert.equal(definition.packet.check, id);
    assert.ok(definition.title.trim(), `${id} catalog title missing`);
    assert.ok(definition.endpoints.includes("/v1/system/release-acceptance/status"), `${id} release status endpoint missing`);
    assert.ok(definition.packet.commands.length, `${id} catalog commands missing`);
    assert.ok(packetItems.has(id), `${id} releaseEvidenceChecklist packet missing`);
    assert.deepEqual(packetItems.get(id).packet.commands, definition.packet.commands, `${id} packet commands drifted from catalog`);
  }
  const webuiDefinition = releaseEvidencePacketDefinition("webui-enterprise-smoke");
  assert.match(webuiDefinition.packet.summary, /current 20-route operator route set/);
  assert.match(webuiDefinition.packet.summary, /\/compliance/);
  assert.match(webuiDefinition.packet.summary, /continuation or targeted repair evidence is diagnostic only/);
  assert.deepEqual(webuiDefinition.packet.commands, [
    "make webui-enterprise-smoke",
    "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-webui-enterprise-smoke",
  ]);
  assert.equal(releaseEvidencePacketDefinition("not-a-release-gate"), null);
}

{
  const status = {
    state: "blocked",
    ready: false,
    manifestPresent: true,
    manifestPath: "release/acceptance.json",
    recordability: { staleEvidencePaths: ["release/evidence/webui-enterprise-smoke.txt"] },
    checks: [
      { name: "proto-verify", state: "passed", evidencePath: "release/evidence/proto-verify.txt", artifact: "evidence/proto-verify.txt", detail: "accepted" },
      { name: "deploy-hardening", state: "recorded", evidencePath: "release/evidence/deploy-hardening.txt", detail: "recorded" },
      { name: "webui-enterprise-smoke", state: "invalid", evidencePath: "release/evidence/webui-enterprise-smoke.txt", reviewNeeded: true, problems: ["stale evidence was recorded for a different commit"] },
      { name: "m3-field-evidence", state: "missing", evidencePath: "release/evidence/m3-field-evidence.txt", nextCommand: ["ngfwrelease", "record", "--check", "m3-field-evidence"] },
    ],
  };
  const items = releaseEvidenceChecklist({ releaseAcceptanceStatus: status });
  const model = releaseArtifactWorkbenchModel(items, status);
  const rows = byId(model.rows);

  assert.equal(model.manifestPresent, true);
  assert.equal(rows["proto-verify"].evidenceState, "recorded");
  assert.match(rows["proto-verify"].manifestBinding, /accepted by release\/acceptance\.json/);
  assert.equal(rows["deploy-hardening"].evidenceState, "recorded");
  assert.match(rows["deploy-hardening"].manifestBinding, /manifest verification pending/);
  assert.equal(rows["webui-enterprise-smoke"].evidenceState, "stale");
  assert.equal(rows["webui-enterprise-smoke"].cls, "warn");
  assert.match(rows["webui-enterprise-smoke"].manifestBinding, /not bindable/);
  assert.match(rows["webui-enterprise-smoke"].nextCommand, /release-evidence-webui-enterprise-smoke/);
  assert.equal(rows["m3-field-evidence"].evidenceState, "missing");
  assert.equal(rows["m3-field-evidence"].nextCommand, "ngfwrelease record --check m3-field-evidence");
  assert.equal(rows["m5-saml-field-evidence"].evidenceState, "missing");
  assert.equal(model.counts.recorded, 2);
  assert.ok(model.counts.missing >= 1);
  assert.equal(model.counts.stale, 1);
}

{
  const items = releaseEvidenceChecklist({
    status: { engines: [{ name: "vector", state: "ready", detail: "process running" }] },
    telemetry: {
      enabled: true,
      clickhouseUrl: "https://clickhouse.example:8443",
      database: "openngfw_prod",
      exports: [
        { name: "local-json", enabled: true, type: "TELEMETRY_EXPORT_TYPE_JSON_FILE", target: "/var/log/openngfw/exports/eve.json" },
        { name: "siem-json", enabled: true, type: "TELEMETRY_EXPORT_TYPE_JSON_TCP", target: "siem.example:5514" },
      ],
    },
  });
  const gates = byId(items);
  assertChecklistItemContract(items);
  assert.equal(gates["telemetry-export-proof"].cls, "warn");
  assert.equal(gates["telemetry-export-proof"].label, "prove delivery");
  assert.equal(gates["telemetry-export-proof"].href, "#/settings?panel=telemetry");
  assert.match(gates["telemetry-export-proof"].detail, /export the redacted evidence packet/);
  assert.match(gates["telemetry-export-proof"].meta, /Vector -> ClickHouse \+ 2 exports/);

  const packet = evidencePacketFor(gates["telemetry-export-proof"]);
  assert.equal(packet.check, "telemetry-export-proof");
  assert.equal(packet.evidencePath, "browser-export:phragma.telemetry.evidence.v1");
  assert.ok(packet.commands.some((command) => command === "ngfwctl status"));
  assert.ok(packet.commands.some((command) => /SELECT count\(\) FROM openngfw_prod\.events/.test(command)));
  assert.ok(packet.commands.some((command) => /siem\.example:5514/.test(command)));

  const counts = releaseEvidenceCounts(items);
  assert.equal(counts.review, 2);
}

{
  const items = releaseEvidenceChecklist({
    status: { engines: [{ name: "vector", state: "failed", detail: "process is not running" }] },
    telemetry: { enabled: true },
  });
  const gate = byId(items)["telemetry-export-proof"];
  assert.equal(gate.cls, "bad");
  assert.equal(gate.label, "blocked");
  assert.match(gate.detail, /Vector runtime is failed/);
}

{
  const items = releaseEvidenceChecklist({
    releaseAcceptanceStatus: {
      checks: [
        { name: "proto-verify", state: "missing", evidencePath: "release/evidence/proto-verify.txt" },
        {
          name: "deploy-hardening",
          state: "recorded",
          evidencePath: "release/evidence/deploy-hardening.txt",
          detail: "packaged service hardening recorded.",
        },
        {
          name: "policy-restore-drill",
          state: "recorded",
          evidencePath: "release/evidence/policy-restore-drill.txt",
          detail: "policy restore drill recorded.",
        },
        {
          name: "ha-readiness-recovery",
          state: "recorded",
          evidencePath: "release/evidence/ha-readiness-recovery.txt",
          detail: "HA recovery evidence recorded.",
        },
        {
          name: "e2e-install",
          state: "invalid",
          evidencePath: "release/evidence/e2e-install.txt",
          problems: ["e2e-install evidence stdout must include \"status=passed\""],
        },
        {
          name: "privileged-integration",
          state: "review_needed",
          evidencePath: "release/evidence/privileged-integration.txt",
          detail: "stale remote continuation evidence copied into release/evidence needs review.",
        },
        { name: "content-package-verification", state: "recorded", evidencePath: "release/evidence/content-package-verification.txt" },
        { name: "m5-auth-ui", state: "recorded", evidencePath: "release/evidence/m5-auth-ui.txt" },
        { name: "m5-oidc-provider", state: "recorded", evidencePath: "release/evidence/m5-oidc-provider.txt" },
        { name: "release-benchmark", state: "not_applicable", detail: "No performance claims." },
      ],
    },
  });
  const gates = byId(items);
  assertChecklistItemContract(items);

  for (const id of rootlessReleaseGateIds) {
    assert.ok(gates[id], `${id} rootless gate missing`);
  }
  assert.equal(gates["proto-verify"].cls, "bad");
  assert.equal(gates["proto-verify"].label, "missing evidence");
  assert.equal(gates["proto-verify"].meta, "release/evidence/proto-verify.txt");
  assert.match(gates["proto-verify"].detail, /Functional proto\/OpenAPI generation/);
  assert.equal(gates["proto-verify"].sourceAcceptance.state, "unknown");
  assert.equal(gates["proto-verify"].sourceAcceptance.dirtySourceCount, 0);
  assert.equal(gates["e2e-install"].cls, "bad");
  assert.equal(gates["e2e-install"].label, "invalid");
  assert.match(gates["e2e-install"].detail, /status=passed/);
  assert.equal(gates["privileged-integration"].cls, "warn");
  assert.equal(gates["privileged-integration"].label, "review needed");
  assert.match(gates["privileged-integration"].detail, /needs review/);
  assert.equal(gates["deploy-hardening"].href, "#/settings?panel=access");
  assert.match(gates["deploy-hardening"].packet.summary, /deploy\/systemd\/controld\.service and deploy\/install\.sh only/);
  assert.match(gates["deploy-hardening"].detail, /static service-unit and installer check only/);
  assert.equal(gates["ha-readiness-recovery"].href, "#/readiness?drawer=ha-cockpit");
  assert.equal(gates["m5-auth-ui"].href, "#/settings?panel=access");
  assert.equal(gates["m5-oidc-provider"].href, "#/settings?panel=access");
  for (const id of ["deploy-hardening", "policy-restore-drill", "ha-readiness-recovery", "content-package-verification", "m5-auth-ui", "m5-oidc-provider"]) {
    assert.equal(gates[id].cls, "warn", `${id} should stay pending until release manifest verification`);
    assert.equal(gates[id].label, "pending manifest", `${id} should be pending manifest acceptance`);
  }
  for (const [id, expected] of Object.entries(rootlessReleaseGateEvidencePackets)) {
    assertExternalEvidencePacket(gates[id], expected);
  }

  const report = releaseEvidenceReport(items, { generatedAt: "2026-06-18T12:00:00Z" });
  assert.match(report, /- \[BLOCKED\] proto-verify - Generated API contract/);
  assert.match(report, /- \[BLOCKED\] e2e-install - Install smoke run/);
  assert.match(report, /- \[REVIEW NEEDED\] privileged-integration - Privileged integration and live dataplane/);
  assert.match(report, /- \[REVIEW\] deploy-hardening - Packaged deployment evidence/);
  assert.match(report, /command: bash release\/deploy-hardening-check\.sh --check/);
  assert.match(report, /- \[REVIEW\] ha-readiness-recovery - HA readiness recovery evidence/);
  assert.match(report, /command: make ha-readiness-recovery-check/);
  assert.match(report, /command: sudo -E make e2e-install/);
}

{
  const sourceAcceptance = apiContractSourceAcceptanceModel({
    ready: false,
    dirtySourcePaths: ["api/proto/openngfw/v1/system.proto", "docs/api-spec.yaml"],
    truncatedDirtySourceCount: 3,
    problems: ["working tree has non-allowed source changes"],
  });
  assert.equal(sourceAcceptance.state, "blocked");
  assert.equal(sourceAcceptance.cls, "bad");
  assert.equal(sourceAcceptance.label, "source acceptance pending");
  assert.equal(sourceAcceptance.dirtySourceCount, 2);
  assert.equal(sourceAcceptance.truncatedDirtySourceCount, 3);
  assert.equal(sourceAcceptance.problemCount, 1);
  assert.match(sourceAcceptance.detail, /5? dirty|2 dirty source path/);
  assert.match(sourceAcceptance.detail, /Functional proto\/OpenAPI generation/);
  assert.doesNotMatch(sourceAcceptance.detail, /api\/proto\/openngfw/);

  const items = releaseEvidenceChecklist({
    releaseAcceptanceStatus: {
      recordability: {
        ready: false,
        dirtySourcePaths: ["api/proto/openngfw/v1/system.proto"],
        problems: ["working tree has non-allowed source changes"],
      },
      checks: [{ name: "proto-verify", state: "missing", evidencePath: "release/evidence/proto-verify.txt" }],
    },
  });
  const gate = byId(items)["proto-verify"];
  assert.equal(gate.sourceAcceptance.state, "blocked");
  assert.equal(gate.sourceAcceptance.dirtySourceCount, 1);
  assert.match(gate.packet.summary, /release evidence is not acceptable until/);
}

{
  const cases = [
    {
      name: "content package verification alone",
      contentPosture: {
        summary: { cls: "ok", detail: "signed packages verified" },
        blockers: [],
      },
      cls: "bad",
      label: "field required",
      detail: /record content-production-readiness/,
    },
    {
      name: "non-production readiness metadata",
      contentPosture: {
        summary: { cls: "ok", detail: "signed packages verified" },
        blockers: [],
        productionContentReadiness: { productionReady: false, blockers: [] },
      },
      cls: "bad",
      label: "field required",
      detail: /record content-production-readiness/,
    },
    {
      name: "explicit readiness with blockers",
      contentPosture: {
        summary: { cls: "ok", detail: "signed packages verified" },
        blockers: [],
        productionContentReadiness: { productionReady: true, blockers: ["threat-id regression"] },
      },
      cls: "bad",
      label: "blocked",
      detail: /1 production content blocker/,
    },
    {
      name: "explicit readiness with no blockers",
      contentPosture: {
        summary: { cls: "ok", detail: "signed packages verified" },
        blockers: [],
        productionContentReadiness: {
          productionReady: true,
          blockers: [],
          detail: "Production App-ID, Threat-ID, and intel-feed evidence recorded.",
          meta: "content-production-readiness passed",
        },
      },
      cls: "ok",
      label: "recorded",
      detail: /Production App-ID, Threat-ID, and intel-feed evidence recorded/,
    },
  ];

  for (const testCase of cases) {
    const items = releaseEvidenceChecklist({ contentPosture: testCase.contentPosture });
    const gate = byId(items)["content-production-readiness"];
    assertChecklistItemContract(items);
    assert.equal(gate.cls, testCase.cls, `${testCase.name} cls`);
    assert.equal(gate.label, testCase.label, `${testCase.name} label`);
    assert.match(gate.detail, testCase.detail, `${testCase.name} detail`);
  }
}

{
  const items = releaseEvidenceChecklist({
    summary: { cls: "bad", detail: "content package blocker.", readyEngines: 1, engineCount: 2 },
    status: { runtime: { activeDataplane: "nftables/conntrack" } },
    policyDp: { accelerated: true, baseDataplane: "nftables/conntrack" },
    flowCap: { state: "ready", detail: "host ready" },
    flowRuntime: { state: "inactive", detail: "no live flowtable counters" },
    ebpfHost: { state: "ready" },
    conntrack: { state: "ready", maxEntries: 262144, usagePercent: 0.1 },
    tuning: { needsAction: false, throughputReady: false, throughputDetail: "target 4,194,304+." },
    contentPosture: { summary: { cls: "bad", detail: "signed manifest missing" }, blockers: ["signed manifest"] },
    inspection: { state: "failed-open", cls: "bad", detail: "inspection failed open", engineLabel: "suricata active" },
  });

  const gates = byId(items);
  assertChecklistItemContract(items);
  assert.equal(gates.runtime.label, "blocked");
  assert.equal(gates.content.cls, "bad");
  assert.equal(gates.host.cls, "warn");
  assert.equal(gates.dataplane.cls, "bad");
  assert.match(gates.dataplane.detail, /no live flowtable counters/);
  assert.equal(gates.inspection.cls, "bad");
  assert.equal(gates.performance.href, "#/performance");

  const counts = releaseEvidenceCounts(items);
  assert.equal(counts.blocked, 12);
  assert.equal(counts.review, 1);
  assert.equal(counts.clear, 1);
  assert.equal(counts.info, 2);

  const report = releaseEvidenceReport(items, { generatedAt: "2026-06-18T12:00:00Z" });
  assert.match(report, /^OpenNGFW release evidence summary\n/);
  assert.match(report, /generated_at=2026-06-18T12:00:00Z/);
  assert.match(report, /totals=blocked:12 review:1 clear:1 info:2/);
  assert.match(report, /- \[BLOCKED\] runtime - Production readiness gate/);
  assert.match(report, /detail: content package blocker\./);
  assert.match(report, /- \[BLOCKED\] content-production-readiness - Production content readiness/);
  assert.match(report, /meta: make content-production-readiness-check/);
  assert.match(report, /link: #\/intel/);
  assert.match(report, /reference: docs\/RELEASE_ACCEPTANCE\.md#approved-evidence-flow/);
  assert.match(report, /- \[REVIEW\] host - Host tuning and state table/);
  assert.match(report, /- \[BLOCKED\] privileged-integration - Privileged integration and live dataplane/);
  assert.match(report, /link: #\/readiness/);
  assert.match(report, /reference: docs\/RELEASE_ACCEPTANCE\.md#approved-evidence-flow/);
  assert.match(report, /- \[BLOCKED\] m3-field-evidence - M3 external field evidence/);
  assert.match(report, /link: #\/netvpn/);
  assert.match(report, /reference: docs\/testing-plan\.md#phase-3--routing--vpn-m3--gaps-b-c-d/);
  assert.match(report, /- \[BLOCKED\] ebpf-ol9-field-evidence - eBPF OL9 field evidence/);
  assert.match(report, /evidence_path: release\/field-evidence\/ebpf-ol9/);
  assert.match(report, /command: make ebpf-ol9-field-evidence-check EBPF_OL9_FIELD_EVIDENCE_DIR=release\/field-evidence\/ebpf-ol9/);
  assert.match(report, /- \[BLOCKED\] m5-oidc-field-evidence - OIDC real-provider field evidence/);
  assert.match(report, /link: #\/settings\?panel=access/);
  assert.match(report, /reference: docs\/testing-plan\.md#phase-5--authnz--ui-m5--gap-f/);
  assert.match(report, /- \[BLOCKED\] m5-saml-field-evidence - SAML real-provider field evidence/);
  assert.match(report, /evidence_path: release\/field-evidence\/saml/);
  assert.match(report, /- \[INFO\] performance - Performance publication gate/);
  assert.match(report, /link: #\/performance/);
}

{
  const items = releaseEvidenceChecklist({
    releaseAcceptanceStatus: {
      checks: [{
        name: "release-benchmark",
        state: "not_applicable",
        detail: "This tag publishes no throughput, latency, connection-rate, or comparison claims.",
      }],
    },
  });
  const gates = byId(items);
  assert.equal(gates.performance.cls, "ok");
  assert.equal(gates.performance.label, "no claims");
  assert.match(gates.performance.detail, /publishes no throughput/);
  assert.equal(gates.performance.meta, "release-benchmark not_applicable");

  const report = releaseEvidenceReport(items, { generatedAt: "2026-06-18T12:00:00Z" });
  assert.match(report, /- \[CLEAR\] performance - Performance publication gate/);
  assert.match(report, /detail: This tag publishes no throughput, latency, connection-rate, or comparison claims\./);
  assert.doesNotMatch(report, /release\/evidence\/release-benchmark\.txt/);
  assert.doesNotMatch(report, /perf\/release-results/);
}

{
  const items = releaseEvidenceChecklist({
    releaseAcceptanceStatus: {
      checks: [{
        name: "release-benchmark",
        state: "missing",
        evidence_path: "release/evidence/release-benchmark.txt",
      }],
    },
  });
  const gates = byId(items);
  assert.equal(gates.performance.cls, "bad");
  assert.equal(gates.performance.label, "missing evidence");
  assert.match(gates.performance.detail, /publishable benchmark artifact/);
  assert.equal(gates.performance.meta, "release/evidence/release-benchmark.txt");
}

{
  const items = releaseEvidenceChecklist({
    releaseAcceptanceStatus: {
      checks: [{
        name: "release-benchmark",
        state: "missing",
        evidencePath: "release/evidence/release-benchmark.txt",
      }],
    },
  });
  const gates = byId(items);
  assert.equal(gates.performance.cls, "bad");
  assert.equal(gates.performance.label, "missing evidence");
  assert.equal(gates.performance.meta, "release/evidence/release-benchmark.txt");
}

{
  const items = releaseEvidenceChecklist({
    releaseAcceptanceStatus: {
      checks: [{
        name: "release-benchmark",
        state: "passed",
        evidencePath: "release/evidence/release-benchmark.txt",
        benchmarkSummary: "perf/release-results/run-1/summary.json",
      }],
    },
  });
  const gates = byId(items);
  assert.equal(gates.performance.cls, "ok");
  assert.equal(gates.performance.label, "passed");
  assert.equal(gates.performance.meta, "perf/release-results/run-1/summary.json");
}

{
  const items = releaseEvidenceChecklist({
    releaseAcceptanceStatus: { checks: [] },
  });
  const gates = byId(items);
  assert.equal(gates.performance.cls, "bad");
  assert.equal(gates.performance.label, "missing evidence");
  assert.match(gates.performance.detail, /publishable benchmark artifact/);
  assert.equal(gates["privileged-integration"].cls, "bad");
  assert.match(gates["privileged-integration"].detail, /missing from the release acceptance status report/);
}

{
  const items = releaseEvidenceChecklist({
    releaseAcceptanceStatus: {
      checks: [{
        name: "privileged-integration",
        state: "recorded",
        evidencePath: "release/evidence/privileged-integration.txt",
        detail: "root Linux integration evidence recorded.",
      }],
    },
  });
  const gates = byId(items);
  assert.equal(gates["privileged-integration"].cls, "warn");
  assert.equal(gates["privileged-integration"].label, "pending manifest");
  assert.equal(gates["privileged-integration"].meta, "release/evidence/privileged-integration.txt");
  assert.match(gates["privileged-integration"].detail, /root Linux integration evidence/);
}

{
  const items = releaseEvidenceChecklist({
    releaseAcceptanceStatus: {
      state: "evidence-pending-manifest",
      ready: false,
      manifestPresent: false,
      checks: [{
        name: "release-benchmark",
        state: "recorded",
        evidencePath: "release/evidence/release-benchmark.txt",
        detail: "benchmark evidence recorded.",
      }, {
        name: "proto-verify",
        state: "recorded",
        evidencePath: "release/evidence/proto-verify.txt",
        detail: "proto evidence recorded.",
      }],
    },
  });
  const gates = byId(items);
  assert.equal(gates.performance.cls, "warn");
  assert.equal(gates.performance.label, "pending manifest");
  assert.match(gates.performance.detail, /benchmark evidence recorded|not accepted until/);
  assert.equal(gates["proto-verify"].cls, "warn");
  assert.equal(gates["proto-verify"].label, "pending manifest");

  const report = releaseEvidenceReport(items, { generatedAt: "2026-06-18T12:00:00Z" });
  assert.match(report, /- \[REVIEW\] performance - Performance publication gate/);
  assert.match(report, /- \[REVIEW\] proto-verify - Generated API contract/);
}

{
  const items = releaseEvidenceChecklist({
    releaseAcceptanceStatus: {
      checks: [{
        name: "privileged-integration",
        state: "not_applicable",
        detail: "lab release only",
      }],
    },
  });
  const gates = byId(items);
  assert.equal(gates["privileged-integration"].cls, "warn");
  assert.equal(gates["privileged-integration"].label, "review needed");
  assert.match(gates["privileged-integration"].detail, /normally requires explicit evidence/);
}

{
  const items = releaseEvidenceChecklist({
    summary: { cls: "ok", detail: "ready", readyEngines: 2, engineCount: 2 },
    status: { runtime: { activeDataplane: "nftables/conntrack" } },
    policyDp: { accelerated: true, baseDataplane: "nftables/conntrack" },
    flowCap: { state: "ready" },
    flowRuntime: { state: "active" },
    ebpfHost: { state: "ready" },
    conntrack: { state: "ready", maxEntries: 4194304, usagePercent: 0.01 },
    tuning: { needsAction: false, throughputReady: true },
    contentPosture: {
      summary: { cls: "ok", detail: "signed packages verified" },
      blockers: [],
      productionContentReadiness: {
        productionReady: true,
        blockers: [],
        detail: "Production content evidence recorded.",
        meta: "content-production-readiness passed",
      },
    },
    inspection: { state: "ready", cls: "ok", detail: "inspection active" },
  });

  const gates = byId(items);
  assertChecklistItemContract(items);
  assert.equal(gates.runtime.cls, "ok");
  assert.equal(gates.content.cls, "ok");
  assert.equal(gates["content-production-readiness"].cls, "ok");
  assert.equal(gates.host.cls, "ok");
  assert.equal(gates.dataplane.cls, "ok");
  assert.equal(gates.dataplane.label, "proven");
  assert.equal(gates.inspection.cls, "ok");
  assert.match(gates.support.detail, /without mutating/);
  for (const id of externalFieldGateIds) {
    assert.equal(gates[id].cls, "bad", `${id} should remain unresolved without field evidence`);
    assert.notEqual(gates[id].label, "clear", `${id} should not be clear without field evidence`);
  }

  const counts = releaseEvidenceCounts(items);
  assert.equal(counts.blocked, 7);
  assert.equal(counts.review, 0);
  assert.equal(counts.clear, 7);
  assert.equal(counts.info, 2);
}

{
  const releaseEvidence = releaseEvidenceChecklist({
    summary: { cls: "ok", detail: "ready", readyEngines: 2, engineCount: 2 },
    status: { runtime: { activeDataplane: "nftables/conntrack" } },
    policyDp: { accelerated: true, baseDataplane: "nftables/conntrack" },
    flowCap: { state: "ready" },
    flowRuntime: { state: "active" },
    ebpfHost: { state: "ready" },
    conntrack: { state: "ready", maxEntries: 4194304, usagePercent: 0.01 },
    tuning: { needsAction: false, throughputReady: true },
    contentPosture: {
      summary: { cls: "ok", detail: "signed packages verified" },
      blockers: [],
      productionContentReadiness: {
        productionReady: true,
        blockers: [],
        detail: "Production content evidence recorded.",
        meta: "content-production-readiness passed",
      },
    },
    inspection: { state: "ready", cls: "ok", detail: "inspection active" },
    releaseAcceptanceStatus: {
      checks: [{
        name: "release-benchmark",
        state: "not_applicable",
        detail: "This tag publishes no throughput, latency, connection-rate, or comparison claims.",
      }],
    },
  });
  const gates = byId(releaseEvidence);
  assert.equal(gates.performance.cls, "ok");
  assert.equal(gates.performance.label, "no claims");
  assert.equal(gates["content-production-readiness"].cls, "bad");

  const packet = buildSystemEvidencePacket({
    generatedAt: "2026-06-18T12:30:00Z",
    releaseEvidence,
    status: { runtime: { dryRun: false, tlsEnabled: true, authEnabled: true } },
  });
  assert.equal(packet.state, "blocked");
  assert.deepEqual(packet.unresolvedExternalGateIds, externalReleaseGateIds);
  assert.match(packet.text, /Local system evidence does not close external field gates/);
}

{
  const releaseEvidence = releaseEvidenceChecklist({
    summary: { cls: "ok", detail: "runtime evidence clear", readyEngines: 2, engineCount: 2 },
    status: {
      runtime: {
        dryRun: false,
        tlsEnabled: true,
        authEnabled: true,
        activeDataplane: "nftables/conntrack",
      },
      management: {
        rateLimitEnabled: true,
        rateLimitRequestsPerMinute: 600,
        rateLimitBurst: 60,
        httpMaxBodyBytes: 1048576,
        grpcMaxRecvBytes: 1048576,
        grpcMaxSendBytes: 1048576,
      },
      engines: [
        { name: "suricata", state: "active" },
        { name: "vector", state: "ready" },
      ],
      capabilities: [
        { name: "nftables flowtable", state: "ready" },
        { name: "Linux eBPF XDP/tc host readiness", state: "simulation" },
      ],
    },
    policyDp: { accelerated: true, baseDataplane: "nftables/conntrack" },
    flowCap: { state: "ready" },
    flowRuntime: { state: "active" },
    ebpfHost: { state: "ready" },
    conntrack: { state: "ready", maxEntries: 4194304, usagePercent: 0.01 },
    tuning: { needsAction: false, throughputReady: true },
    contentPosture: {
      summary: { cls: "ok", detail: "signed packages verified" },
      blockers: [],
      productionContentReadiness: {
        productionReady: true,
        blockers: [],
        detail: "Production content evidence recorded.",
        meta: "content-production-readiness passed",
      },
    },
    inspection: { state: "ready", cls: "ok", detail: "inspection active" },
  });
  const packet = buildSystemEvidencePacket({
    generatedAt: "2026-06-18T13:00:00Z",
    releaseEvidence,
    status: {
      runtime: {
        dryRun: false,
        tlsEnabled: true,
        authEnabled: true,
      },
      management: {
        rateLimitEnabled: true,
        rateLimitRequestsPerMinute: 600,
        rateLimitBurst: 60,
        httpMaxBodyBytes: 1048576,
        grpcMaxRecvBytes: 1048576,
        grpcMaxSendBytes: 1048576,
      },
      engines: [
        { name: "suricata", state: "active" },
        { name: "vector", state: "ready" },
      ],
      capabilities: [
        { name: "nftables flowtable", state: "ready" },
        { name: "Linux eBPF XDP/tc host readiness", state: "simulation" },
      ],
    },
  });

  assert.equal(packet.schema, "phragma.system.evidence.v1");
  assert.equal(packet.state, "blocked");
  assert.deepEqual(packet.unresolvedExternalGateIds, ["webui-enterprise-smoke", "privileged-integration", "m3-live-networking", "m3-field-evidence", "ebpf-ol9-field-evidence", "m5-oidc-field-evidence", "m5-saml-field-evidence"]);
  assert.ok(packet.rows.some((row) => row.id === "management-plane" && row.cls === "ok" && /tls:enabled auth:enabled/.test(row.meta)));
  assert.ok(packet.rows.some((row) => row.id === "xdp-tc-readiness" && /renderer:unknown hooks:unknown/.test(row.meta)));
  assert.ok(packet.rows.some((row) => row.id === "ha-readiness-recovery" && /HA readiness recovery release evidence/.test(row.title)));
  assert.ok(packet.rows.some((row) => row.id === "external-release-gates" && row.cls === "bad"));
  assert.match(packet.text, /^OpenNGFW system evidence packet\n/);
  assert.match(packet.text, /generated_at=2026-06-18T13:00:00Z/);
  assert.match(packet.text, /ha-readiness-recovery/);
  assert.match(packet.text, /unresolved_external_gates=webui-enterprise-smoke, privileged-integration, m3-live-networking, m3-field-evidence, ebpf-ol9-field-evidence, m5-oidc-field-evidence, m5-saml-field-evidence/);
  assert.match(packet.text, /Local system evidence does not close external field gates/);
  assert.match(systemEvidencePacketReport(packet), /release_counts=blocked:7 review:0 clear:7 info:2/);
}
