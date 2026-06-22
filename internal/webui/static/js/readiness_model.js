// readiness_model.js - pure posture decisions for the Readiness view.
// Keep this separate from DOM rendering so production-gating semantics are
// testable without a browser.

import { BASELINE_TUNING_COMMAND, EBPF_HOST_CAPABILITY, THROUGHPUT_TUNING_COMMAND, ebpfBlocksCurrentDataplane } from "./dataplane.js";
import { telemetryEvidenceCommands, telemetryReadinessModel } from "./telemetry_settings.js";

const RELEASE_ACCEPTANCE_DOC = "docs/RELEASE_ACCEPTANCE.md#approved-evidence-flow";
const API_CONTRACT_SOURCE_ACCEPTANCE_NOTE = "Functional proto/OpenAPI generation and copy consistency can be validated independently, but proto-verify release evidence is not acceptable until proto inputs, generator config, generated Go/gateway files, normalized OpenAPI output, published docs spec, and bundled WebUI spec are accepted together in source control.";
const M3_FIELD_EVIDENCE_DOC = "docs/testing-plan.md#phase-3--routing--vpn-m3--gaps-b-c-d";
const OIDC_FIELD_EVIDENCE_DOC = "docs/testing-plan.md#phase-5--authnz--ui-m5--gap-f";
const READINESS_ROUTE = "#/readiness";
const INTEL_ROUTE = "#/intel";
const NETVPN_ROUTE = "#/netvpn";
const SETTINGS_ACCESS_ROUTE = "#/settings?panel=access";
const SETTINGS_NETWORK_ROUTE = "#/settings?panel=network";
const SETTINGS_TELEMETRY_ROUTE = "#/settings?panel=telemetry";
const RELEASE_EVIDENCE_DIR = "release/evidence";
const WEBUI_ENTERPRISE_SMOKE_SCOPE = "current 20-route operator route set, including /compliance, across supported viewports";
const CONTENT_PRODUCTION_EVIDENCE_DIR = "release/field-evidence/content-production";
const M3_FIELD_EVIDENCE_DIR = "release/field-evidence/m3";
const EBPF_OL9_FIELD_EVIDENCE_DIR = "release/field-evidence/ebpf-ol9";
const EBPF_OL9_ATTACH_DRILL_COMMAND = `sudo -E EBPF_OL9_ATTACH_IFACE=<disposable-interface> EBPF_OL9_STATUS_JSON_COMMAND='<command that prints /v1/system/status eBPF JSON>' make ebpf-ol9-attach-drill EBPF_OL9_FIELD_EVIDENCE_DIR=${EBPF_OL9_FIELD_EVIDENCE_DIR}`;
const OIDC_FIELD_EVIDENCE_DIR = "release/field-evidence/oidc";
const SAML_FIELD_EVIDENCE_DIR = "release/field-evidence/saml";
const SAML_FIELD_EVIDENCE_PREP_COMMAND = `mkdir -p ${SAML_FIELD_EVIDENCE_DIR}/{provider,deployment,browser,rbac,redaction} && printf '%s\\n' 'Copy redacted SAML IdP/SP, ACS, browser, RBAC, and redaction artifacts into release/field-evidence/saml; this command only prepares the bundle directory.'`;
const EXTERNAL_RELEASE_GATE_IDS = Object.freeze([
  "content-production-readiness",
  "webui-enterprise-smoke",
  "privileged-integration",
  "m3-live-networking",
  "m3-field-evidence",
  "ebpf-ol9-field-evidence",
  "m5-oidc-field-evidence",
  "m5-saml-field-evidence",
]);
const CONTENT_PRODUCTION_PACKET = evidencePacket({
  check: "content-production-readiness",
  evidencePath: CONTENT_PRODUCTION_EVIDENCE_DIR,
  artifactPath: `${RELEASE_EVIDENCE_DIR}/content-production-readiness.txt`,
  summary: "Production App-ID, Threat-ID, and intel-feed content readiness evidence.",
  makeTargets: ["content-production-readiness-check", "release-evidence-content-production-readiness"],
  validateCommand: `make content-production-readiness-check CONTENT_PRODUCTION_EVIDENCE_DIR=${CONTENT_PRODUCTION_EVIDENCE_DIR}`,
  recordCommand: `COMMIT="$(git rev-parse HEAD)" make release-evidence-content-production-readiness CONTENT_PRODUCTION_EVIDENCE_DIR=${CONTENT_PRODUCTION_EVIDENCE_DIR}`,
  reference: RELEASE_ACCEPTANCE_DOC,
});
const PROTO_VERIFY_PACKET = evidencePacket({
  check: "proto-verify",
  evidencePath: RELEASE_EVIDENCE_DIR,
  artifactPath: `${RELEASE_EVIDENCE_DIR}/proto-verify.txt`,
  summary: `Generated protobuf, gRPC gateway, and OpenAPI artifacts match the proto source of record. ${API_CONTRACT_SOURCE_ACCEPTANCE_NOTE}`,
  makeTargets: ["proto-verify", "release-evidence-proto-verify"],
  diagnoseCommand: "make proto-status",
  validateCommand: "make proto-verify",
  recordCommand: "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-proto-verify",
  reference: RELEASE_ACCEPTANCE_DOC,
});
const DEPLOY_HARDENING_PACKET = evidencePacket({
  check: "deploy-hardening",
  evidencePath: RELEASE_EVIDENCE_DIR,
  artifactPath: `${RELEASE_EVIDENCE_DIR}/deploy-hardening.txt`,
  summary: "Static packaged deployment evidence for release review; inspects deploy/systemd/controld.service and deploy/install.sh only, does not start controld, install packages, rotate secrets, prove runtime RBAC, or close later runtime hardening.",
  makeTargets: ["deploy-hardening-check", "release-evidence-deploy-hardening"],
  validateCommand: "bash release/deploy-hardening-check.sh --check",
  recordCommand: "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-deploy-hardening",
  reference: RELEASE_ACCEPTANCE_DOC,
});
const POLICY_RESTORE_DRILL_PACKET = evidencePacket({
  check: "policy-restore-drill",
  evidencePath: RELEASE_EVIDENCE_DIR,
  artifactPath: `${RELEASE_EVIDENCE_DIR}/policy-restore-drill.txt`,
  summary: "Rootless emergency policy restore drill proving rollback validation, audit, LKG metadata, and engine apply.",
  makeTargets: ["policy-restore-drill-check", "release-evidence-policy-restore-drill"],
  validateCommand: "make policy-restore-drill-check",
  recordCommand: "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-policy-restore-drill",
  reference: RELEASE_ACCEPTANCE_DOC,
});
const HA_READINESS_RECOVERY_PACKET = evidencePacket({
  check: "ha-readiness-recovery",
  evidencePath: RELEASE_EVIDENCE_DIR,
  artifactPath: `${RELEASE_EVIDENCE_DIR}/ha-readiness-recovery.txt`,
  summary: "Rootless active/passive HA readiness and control-plane recovery evidence; does not certify VIP/route promotion, fencing, or connection-state sync.",
  makeTargets: ["ha-readiness-recovery-check", "release-evidence-ha-readiness-recovery"],
  validateCommand: "make ha-readiness-recovery-check",
  recordCommand: "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-ha-readiness-recovery",
  reference: RELEASE_ACCEPTANCE_DOC,
});
const E2E_INSTALL_PACKET = evidencePacket({
  check: "e2e-install",
  evidencePath: RELEASE_EVIDENCE_DIR,
  artifactPath: `${RELEASE_EVIDENCE_DIR}/e2e-install.txt`,
  summary: "Disposable Linux host install smoke run proving installed-service commit, allow/deny policy enforcement, and namespace traffic filtering.",
  makeTargets: ["e2e-install", "release-evidence-e2e-install"],
  validateCommand: "sudo make e2e-install",
  recordCommand: "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-e2e-install RELEASE_EVIDENCE_RECORD_FLAGS=--overwrite",
  reference: RELEASE_ACCEPTANCE_DOC,
});
const CONTENT_PACKAGE_PACKET = evidencePacket({
  check: "content-package-verification",
  evidencePath: RELEASE_EVIDENCE_DIR,
  artifactPath: `${RELEASE_EVIDENCE_DIR}/content-package-verification.txt`,
  summary: "Signed demo package verification, install, and rollback mechanics evidence.",
  makeTargets: ["content-package-smoke", "release-evidence-content-package-verification"],
  validateCommand: "make content-package-smoke",
  recordCommand: "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-content-package-verification",
  reference: RELEASE_ACCEPTANCE_DOC,
});
const RELEASE_BENCHMARK_PACKET = evidencePacket({
  check: "release-benchmark",
  evidencePath: RELEASE_EVIDENCE_DIR,
  artifactPath: "",
  summary: "Publishable performance benchmark evidence or explicit no-performance-claims release status.",
  makeTargets: ["benchmark-verify-release", "release-evidence-release-benchmark"],
  validateCommand: "make benchmark-verify-release",
  recordCommand: "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-release-benchmark",
  noClaimsCommand: "RELEASE_NO_PERFORMANCE_CLAIMS=1 make release-acceptance-status",
  reference: RELEASE_ACCEPTANCE_DOC,
});
const PRIVILEGED_INTEGRATION_PACKET = evidencePacket({
  check: "privileged-integration",
  evidencePath: RELEASE_EVIDENCE_DIR,
  artifactPath: `${RELEASE_EVIDENCE_DIR}/privileged-integration.txt`,
  summary: "Root Linux host evidence from real engines and live dataplane paths.",
  makeTargets: ["integration-test", "release-evidence-privileged-integration"],
  validateCommand: "make integration-test",
  recordCommand: "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-privileged-integration",
  reference: RELEASE_ACCEPTANCE_DOC,
});
const M3_LIVE_NETWORKING_PACKET = evidencePacket({
  check: "m3-live-networking",
  evidencePath: RELEASE_EVIDENCE_DIR,
  artifactPath: `${RELEASE_EVIDENCE_DIR}/m3-live-networking.txt`,
  summary: "Privileged Linux host evidence for static-route forwarding, local FRR BGP netns programming, and WireGuard peer traffic.",
  makeTargets: ["m3-live-networking", "release-evidence-m3-live-networking"],
  diagnoseCommand: "make m3-live-networking-check",
  validateCommand: "sudo make m3-live-networking",
  recordCommand: "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-m3-live-networking",
  reference: RELEASE_ACCEPTANCE_DOC,
});
const M3_FIELD_PACKET = evidencePacket({
  check: "m3-field-evidence",
  evidencePath: M3_FIELD_EVIDENCE_DIR,
  artifactPath: `${RELEASE_EVIDENCE_DIR}/m3-field-evidence.txt`,
  summary: "External BGP peer, IPsec SA/protected-subnet traffic, and external WireGuard client field evidence.",
  makeTargets: ["m3-field-evidence-check", "release-evidence-m3-field-evidence"],
  validateCommand: `make m3-field-evidence-check M3_FIELD_EVIDENCE_DIR=${M3_FIELD_EVIDENCE_DIR}`,
  recordCommand: `COMMIT="$(git rev-parse HEAD)" make release-evidence-m3-field-evidence M3_FIELD_EVIDENCE_DIR=${M3_FIELD_EVIDENCE_DIR}`,
  reference: M3_FIELD_EVIDENCE_DOC,
});
const EBPF_OL9_FIELD_PACKET = evidencePacket({
  check: "ebpf-ol9-field-evidence",
  evidencePath: EBPF_OL9_FIELD_EVIDENCE_DIR,
  artifactPath: `${RELEASE_EVIDENCE_DIR}/ebpf-ol9-field-evidence.txt`,
  summary: "OL9/OCI Linux-root XDP/tc attach, status API, renderer scaffold, and cleanup field evidence.",
  makeTargets: ["ebpf-ol9-field-evidence-check", "release-evidence-ebpf-ol9-field-evidence"],
  diagnoseCommand: "make ebpf-ol9-attach-drill-check",
  collectCommand: EBPF_OL9_ATTACH_DRILL_COMMAND,
  validateCommand: `make ebpf-ol9-field-evidence-check EBPF_OL9_FIELD_EVIDENCE_DIR=${EBPF_OL9_FIELD_EVIDENCE_DIR}`,
  recordCommand: `COMMIT="$(git rev-parse HEAD)" make release-evidence-ebpf-ol9-field-evidence EBPF_OL9_FIELD_EVIDENCE_DIR=${EBPF_OL9_FIELD_EVIDENCE_DIR}`,
  reference: RELEASE_ACCEPTANCE_DOC,
});
const OIDC_FIELD_PACKET = evidencePacket({
  check: "m5-oidc-field-evidence",
  evidencePath: OIDC_FIELD_EVIDENCE_DIR,
  artifactPath: `${RELEASE_EVIDENCE_DIR}/m5-oidc-field-evidence.txt`,
  summary: "Redacted, real-provider OIDC browser SSO evidence.",
  makeTargets: ["m5-oidc-field-evidence-check", "release-evidence-m5-oidc-field-evidence"],
  validateCommand: `make m5-oidc-field-evidence-check OIDC_FIELD_EVIDENCE_DIR=${OIDC_FIELD_EVIDENCE_DIR}`,
  recordCommand: `COMMIT="$(git rev-parse HEAD)" make release-evidence-m5-oidc-field-evidence OIDC_FIELD_EVIDENCE_DIR=${OIDC_FIELD_EVIDENCE_DIR}`,
  reference: OIDC_FIELD_EVIDENCE_DOC,
});
const SAML_FIELD_PACKET = evidencePacket({
  check: "m5-saml-field-evidence",
  evidencePath: SAML_FIELD_EVIDENCE_DIR,
  artifactPath: `${RELEASE_EVIDENCE_DIR}/m5-saml-field-evidence.txt`,
  summary: "Redacted, real-provider SAML browser SSO bundle validation; this does not claim live IdP success until captured artifacts validate and release evidence is recorded.",
  makeTargets: ["m5-saml-field-evidence-check", "release-evidence-m5-saml-field-evidence"],
  collectCommand: SAML_FIELD_EVIDENCE_PREP_COMMAND,
  validateCommand: `make m5-saml-field-evidence-check SAML_FIELD_EVIDENCE_DIR=${SAML_FIELD_EVIDENCE_DIR}`,
  recordCommand: `COMMIT="$(git rev-parse HEAD)" make release-evidence-m5-saml-field-evidence SAML_FIELD_EVIDENCE_DIR=${SAML_FIELD_EVIDENCE_DIR}`,
  reference: RELEASE_ACCEPTANCE_DOC,
});
const M5_AUTH_UI_PACKET = evidencePacket({
  check: "m5-auth-ui",
  evidencePath: RELEASE_EVIDENCE_DIR,
  artifactPath: `${RELEASE_EVIDENCE_DIR}/m5-auth-ui.txt`,
  summary: "WebUI syntax, JavaScript tests, hashed local users, RBAC, TLS headers, request limits, rate limiting, and startup guard evidence.",
  makeTargets: ["e2e-auth-runtime-smoke", "release-evidence-m5-auth-ui"],
  validateCommand: "make e2e-auth-runtime-smoke",
  recordCommand: "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-m5-auth-ui",
  reference: RELEASE_ACCEPTANCE_DOC,
});
const M5_OIDC_PROVIDER_PACKET = evidencePacket({
  check: "m5-oidc-provider",
  evidencePath: RELEASE_EVIDENCE_DIR,
  artifactPath: `${RELEASE_EVIDENCE_DIR}/m5-oidc-provider.txt`,
  summary: "Loopback mock-provider OIDC authorization-code session and runtime provider lifecycle smoke evidence.",
  makeTargets: ["e2e-oidc-runtime-smoke", "release-evidence-m5-oidc-provider"],
  validateCommand: "make e2e-oidc-runtime-smoke",
  recordCommand: "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-m5-oidc-provider",
  reference: RELEASE_ACCEPTANCE_DOC,
});
const WEBUI_ENTERPRISE_SMOKE_PACKET = evidencePacket({
  check: "webui-enterprise-smoke",
  evidencePath: RELEASE_EVIDENCE_DIR,
  artifactPath: `${RELEASE_EVIDENCE_DIR}/webui-enterprise-smoke.txt`,
  summary: `Browser-required broad WebUI enterprise smoke across the ${WEBUI_ENTERPRISE_SMOKE_SCOPE}; continuation or targeted repair evidence is diagnostic only until repo-local release evidence is recorded for the accepted source snapshot.`,
  makeTargets: ["webui-enterprise-smoke", "release-evidence-webui-enterprise-smoke"],
  validateCommand: "make webui-enterprise-smoke",
  recordCommand: "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-webui-enterprise-smoke",
  reference: RELEASE_ACCEPTANCE_DOC,
});
const RELEASE_EVIDENCE_PACKET_CATALOG = Object.freeze([
  releaseEvidencePacketCatalogItem("content-production-readiness", "Production content readiness", CONTENT_PRODUCTION_PACKET, { endpoints: ["/v1/system/release-acceptance/status", "/v1/intel/content/packages"] }),
  releaseEvidencePacketCatalogItem("proto-verify", "Generated API contract", PROTO_VERIFY_PACKET, { endpoints: ["/v1/system/release-acceptance/status"] }),
  releaseEvidencePacketCatalogItem("deploy-hardening", "Packaged deployment evidence", DEPLOY_HARDENING_PACKET, { endpoints: ["/v1/system/release-acceptance/status", "/v1/system/status"] }),
  releaseEvidencePacketCatalogItem("policy-restore-drill", "Emergency policy restore drill", POLICY_RESTORE_DRILL_PACKET, { endpoints: ["/v1/system/release-acceptance/status"] }),
  releaseEvidencePacketCatalogItem("ha-readiness-recovery", "HA readiness recovery evidence", HA_READINESS_RECOVERY_PACKET, { endpoints: ["/v1/system/release-acceptance/status", "/v1/system/ha/status"] }),
  releaseEvidencePacketCatalogItem("e2e-install", "Install smoke run", E2E_INSTALL_PACKET, { endpoints: ["/v1/system/release-acceptance/status", "/v1/system/status"] }),
  releaseEvidencePacketCatalogItem("content-package-verification", "Signed content package mechanics", CONTENT_PACKAGE_PACKET, { endpoints: ["/v1/system/release-acceptance/status", "/v1/intel/content/packages"] }),
  releaseEvidencePacketCatalogItem("release-benchmark", "Performance benchmark release gate", RELEASE_BENCHMARK_PACKET, { endpoints: ["/v1/system/release-acceptance/status"] }),
  releaseEvidencePacketCatalogItem("m5-auth-ui", "Auth and WebUI runtime smoke", M5_AUTH_UI_PACKET, { endpoints: ["/v1/system/release-acceptance/status", "/v1/system/status", "/v1/system/identity"] }),
  releaseEvidencePacketCatalogItem("m5-oidc-provider", "OIDC provider runtime smoke", M5_OIDC_PROVIDER_PACKET, { endpoints: ["/v1/system/release-acceptance/status", "/v1/auth/oidc/status"] }),
  releaseEvidencePacketCatalogItem("webui-enterprise-smoke", "WebUI enterprise smoke", WEBUI_ENTERPRISE_SMOKE_PACKET, { endpoints: ["/v1/system/release-acceptance/status"] }),
  releaseEvidencePacketCatalogItem("privileged-integration", "Privileged integration and live dataplane", PRIVILEGED_INTEGRATION_PACKET, { endpoints: ["/v1/system/release-acceptance/status", "/v1/system/status"] }),
  releaseEvidencePacketCatalogItem("m3-live-networking", "M3 live networking", M3_LIVE_NETWORKING_PACKET, { endpoints: ["/v1/system/release-acceptance/status", "/v1/system/status"] }),
  releaseEvidencePacketCatalogItem("m3-field-evidence", "M3 external field evidence", M3_FIELD_PACKET, { endpoints: ["/v1/system/release-acceptance/status", "/v1/system/status"] }),
  releaseEvidencePacketCatalogItem("ebpf-ol9-field-evidence", "eBPF OL9 field evidence", EBPF_OL9_FIELD_PACKET, { endpoints: ["/v1/system/release-acceptance/status", "/v1/system/status"] }),
  releaseEvidencePacketCatalogItem("m5-oidc-field-evidence", "OIDC real-provider field evidence", OIDC_FIELD_PACKET, { endpoints: ["/v1/system/release-acceptance/status", "/v1/auth/oidc/status", "/v1/system/identity"] }),
  releaseEvidencePacketCatalogItem("m5-saml-field-evidence", "SAML real-provider field evidence", SAML_FIELD_PACKET, { endpoints: ["/v1/system/release-acceptance/status", "/v1/auth/saml/status", "/v1/system/identity"] }),
]);

export function releaseEvidencePacketIds() {
  return RELEASE_EVIDENCE_PACKET_CATALOG.map((item) => item.id);
}

export function releaseEvidencePacketDefinition(id = "") {
  const item = RELEASE_EVIDENCE_PACKET_CATALOG.find((candidate) => candidate.id === String(id || "").trim());
  if (!item) return null;
  return {
    ...item,
    endpoints: [...item.endpoints],
    packet: { ...item.packet, makeTargets: [...item.packet.makeTargets], commandItems: [...item.packet.commandItems], commands: [...item.packet.commands] },
  };
}

export function summarizeReadiness(status = {}, policyDp = {}, flowCap = {}, flowRuntime = {}, ebpfHost = {}, conntrack = {}, contentPosture = null, routingRuntime = null) {
  const warnings = status.warnings || [];
  const engines = status.engines || [];
  const caps = status.capabilities || [];
  const critical = warnings.filter((w) => w.severity === "critical").length;
  const warning = warnings.filter((w) => w.severity === "warning").length;
  const blockedEngines = engines.filter((e) => e.state === "missing-prerequisites" || e.state === "failed").length;
  const readyEngines = engines.filter((e) => e.state === "ready" || e.state === "active").length;
  const ebpfBlocked = ebpfBlocksCurrentDataplane(status, ebpfHost);
  const degradedCaps = caps.filter((c) => c.state === "degraded" && (c.name !== EBPF_HOST_CAPABILITY || ebpfBlocked)).length;
  const strategicEbpfGap = Boolean(!ebpfBlocked && ebpfHost && ebpfHost.state && ebpfHost.state !== "ready" && ebpfHost.state !== "active");
  const simulationCaps = caps.filter((c) => c.state === "simulation").length;
  const policyInvalid = policyDp?.state === "invalid";
  const flowCapBlocked = Boolean(policyDp?.accelerated && flowCap && flowCap.state && flowCap.state !== "ready" && flowCap.state !== "active");
  const flowRuntimeBlocked = Boolean(policyDp?.accelerated && flowRuntime && flowRuntime.state && flowRuntime.state !== "active");
  const conntrackBlocked = Boolean(conntrack && conntrack.state === "degraded");
  const contentBlockerCount = Array.isArray(contentPosture?.blockers) ? contentPosture.blockers.length : 0;
  const contentBlocked = Boolean(contentPosture && (contentPosture.summary?.cls === "bad" || contentBlockerCount > 0));
  const routingBlocked = Boolean(routingRuntime?.enabled && routingRuntime?.state && routingRuntime.state !== "active");
  const ha = haReadiness(status);
  const haBlocked = ha.cls === "bad";
  const haReview = ha.cls === "warn";

  if (critical || blockedEngines || degradedCaps || policyInvalid || flowCapBlocked || flowRuntimeBlocked || ebpfBlocked || conntrackBlocked || contentBlocked || routingBlocked || haBlocked) {
    const parts = [
      critical ? `${critical} critical warning(s)` : "",
      blockedEngines ? `${blockedEngines} engine prerequisite issue(s)` : "",
      degradedCaps ? `${degradedCaps} degraded capability issue(s)` : "",
      policyInvalid ? "policy dataplane conflict" : "",
      flowCapBlocked ? "flowtable policy is not host-ready" : "",
      flowRuntimeBlocked ? "flowtable runtime evidence is not active" : "",
      ebpfBlocked ? "eBPF host prerequisites incomplete for the active dataplane" : "",
      conntrackBlocked ? "conntrack state table near capacity" : "",
      contentBlocked ? `${contentBlockerCount || 1} content package blocker(s)` : "",
      routingBlocked ? "dynamic routing runtime evidence is not active" : "",
      haBlocked ? "active/passive HA readiness is degraded" : "",
    ].filter(Boolean);
    return {
      cls: "bad",
      title: "Not production ready",
      detail: parts.join(", ") + ".",
      readyEngines,
      engineCount: engines.length,
    };
  }

  if (warning || simulationCaps || strategicEbpfGap || haReview) {
    const parts = [
      warning ? `${warning} warning(s)` : "",
      simulationCaps ? `${simulationCaps} simulated capability state(s)` : "",
      strategicEbpfGap ? "eBPF milestone prerequisite gap" : "",
      haReview ? "HA readiness requires review" : "",
    ].filter(Boolean);
    return {
      cls: "warn",
      title: "Ready with warnings",
      detail: parts.join(", ") + " should be reviewed before production enforcement.",
      readyEngines,
      engineCount: engines.length,
    };
  }

  return {
    cls: "ok",
    title: "Ready for enforcement",
    detail: "No runtime or content blockers reported by controld.",
    readyEngines,
    engineCount: engines.length,
  };
}

export function remediationSteps(status = {}, policyDp = {}, flowCap = {}, flowRuntime = {}, ebpfHost = {}, conntrack = {}, tuning = {}, contentPosture = null, routingRuntime = null) {
  const steps = [];
  const seen = new Set();
  const seenIds = new Set();
  const add = (step) => {
    const title = String(step.title || "").trim();
    if (!title) return;
    const key = [title, step.command || "", step.href || ""].join("\n");
    if (seen.has(key)) return;
    seen.add(key);
    const baseId = remediationActionId(step.id || title);
    let id = baseId;
    let suffix = 2;
    while (seenIds.has(id)) {
      id = `${baseId}-${suffix}`;
      suffix += 1;
    }
    seenIds.add(id);
    steps.push({
      id,
      level: step.level || "medium",
      badge: step.badge || step.level || "action",
      title,
      detail: step.detail || "",
      command: step.command || "",
      href: step.href || "",
    });
  };

  const runtime = status.runtime || {};
  if (runtime.dryRun) {
    add({
      id: "dry-run",
      level: "high",
      badge: "critical",
      title: "Disable dry-run before production",
      detail: "The daemon is recording policy state but is not changing host firewall enforcement.",
      command: "sudo systemctl restart controld",
    });
  }

  for (const warning of [...(status.warnings || [])].sort((a, b) => severityRank(a.severity) - severityRank(b.severity))) {
    add({
      id: warning.id || warning.code || warning.message || "runtime-warning",
      level: warning.severity === "critical" ? "high" : "medium",
      badge: warning.severity || "warning",
      title: warning.message || "Runtime warning",
      detail: warning.action || "Inspect runtime status before enabling production enforcement.",
      href: "#/readiness",
    });
  }

  if (tuning.needsAction) {
    add({
      id: "host-sysctl-baseline",
      level: "high",
      badge: "host",
      title: "Apply the host sysctl baseline",
      detail: tuning.detail || "Forwarding, reverse-path filtering, conntrack, or backlog settings are below the appliance baseline.",
      command: tuning.remediationCommand || BASELINE_TUNING_COMMAND,
    });
  }

  if (conntrack.state === "degraded") {
    add({
      id: "conntrack-pressure",
      level: "high",
      badge: "state",
      title: "Relieve conntrack pressure",
      detail: conntrack.detail || "State-table pressure is a production blocker for high-throughput or high-connection-churn profiles.",
      command: tuning.throughputCommand || THROUGHPUT_TUNING_COMMAND,
    });
  } else if (policyDp.accelerated && tuning.throughputReady === false) {
    add({
      id: "throughput-headroom",
      level: "medium",
      badge: "throughput",
      title: "Raise throughput state-table headroom",
      detail: tuning.throughputDetail || "Fast-path benchmarking should run with the throughput tuning profile applied.",
      command: tuning.throughputCommand || THROUGHPUT_TUNING_COMMAND,
    });
  }

  if (policyDp.state === "invalid") {
    add({
      id: "policy-dataplane-conflict",
      level: "high",
      badge: "policy",
      title: "Resolve the policy dataplane conflict",
      detail: policyDp.detail || "The running or candidate policy has a dataplane conflict that blocks production readiness.",
      href: SETTINGS_NETWORK_ROUTE,
    });
  }

  if (policyDp.accelerated && flowCap && flowCap.state && flowCap.state !== "ready" && flowCap.state !== "active") {
    add({
      id: "flowtable-host-ready",
      level: "high",
      badge: "host",
      title: "Make the flowtable fast path host-ready",
      detail: flowCap.detail || "The policy requests flowtable acceleration, but host prerequisites are incomplete.",
      href: SETTINGS_NETWORK_ROUTE,
    });
  }

  if (policyDp.accelerated && flowRuntime && flowRuntime.state && flowRuntime.state !== "active") {
    add({
      id: "flowtable-runtime-evidence",
      level: "high",
      badge: "runtime",
      title: "Verify runtime flowtable evidence",
      detail: flowRuntime.detail || "The policy requests flowtable acceleration, but live runtime evidence is not active.",
      command: "ngfwctl status",
    });
  }

  if (routingRuntime?.enabled && routingRuntime.state && routingRuntime.state !== "active") {
    add({
      id: "frr-runtime-evidence",
      level: "high",
      badge: "routing",
      title: "Verify FRR dynamic-routing runtime evidence",
      detail: routingRuntime.detail || "The running policy enables BGP or OSPF, but FRR runtime evidence is not active.",
      command: "ngfwctl status",
      href: NETVPN_ROUTE,
    });
  }

  const ebpfBlocked = ebpfBlocksCurrentDataplane(status, ebpfHost);
  if (ebpfBlocked) {
    add({
      id: "ebpf-host-prerequisites",
      level: "high",
      badge: "eBPF",
      title: "Complete eBPF host prerequisites",
      detail: ebpfHost.detail || "The active dataplane requires eBPF/XDP/tc host prerequisites before production enforcement.",
    });
  } else if (ebpfHost && ebpfHost.state && ebpfHost.state !== "ready" && ebpfHost.state !== "active") {
    add({
      id: "strategic-ebpf-readiness",
      level: "medium",
      badge: "eBPF",
      title: "Track the strategic eBPF readiness gap",
      detail: ebpfHost.detail || "nftables can remain the current renderer, but eBPF/XDP/tc remains a required product milestone.",
    });
  }

  for (const engine of status.engines || []) {
    if (engine.state !== "missing-prerequisites" && engine.state !== "failed") continue;
    add({
      id: `engine-${engine.name || engine.state || "unknown"}`,
      level: "high",
      badge: engine.state || "engine",
      title: `${engine.name || "Engine"} is not ready`,
      detail: engine.detail || engine.role || "Engine prerequisite or supervisor state blocks production readiness.",
      command: engine.state === "failed" ? "sudo systemctl restart controld" : "",
    });
  }

  for (const cap of status.capabilities || []) {
    if (cap.state !== "degraded" && cap.state !== "missing-prerequisites" && cap.state !== "failed") continue;
    if (cap.name === EBPF_HOST_CAPABILITY && !ebpfBlocked) continue;
    add({
      id: `capability-${cap.name || cap.state || "unknown"}`,
      level: cap.state === "failed" || cap.state === "missing-prerequisites" ? "high" : "medium",
      badge: cap.state || "capability",
      title: cap.name || "Capability is degraded",
      detail: cap.detail || "Capability detail is unavailable.",
    });
  }

  const contentBlockers = Array.isArray(contentPosture?.blockers) ? contentPosture.blockers : [];
  if (contentPosture && (contentPosture.summary?.cls === "bad" || contentBlockers.length)) {
    add({
      id: "content-package-blockers",
      level: "high",
      badge: "content",
      title: "Resolve content package blockers",
      detail: contentBlockers.length
        ? `${contentBlockers.length} blocker(s): ${contentBlockers.slice(0, 6).join(", ")}.`
        : contentPosture.summary?.detail || "Content package status is not production ready.",
      href: "#/intel",
    });
  }

  const ha = haReadiness(status);
  if (ha.cls === "bad" || ha.cls === "warn") {
    add({
      id: "ha-readiness",
      level: ha.cls === "bad" ? "high" : "medium",
      badge: "ha",
      title: ha.cls === "bad" ? "Resolve active/passive HA blockers" : "Review HA readiness posture",
      detail: ha.detail || "Review HA status before relying on active/passive recovery.",
      command: "ngfwctl status",
      href: "#/readiness",
    });
  }

  return steps.sort((a, b) => levelRank(a.level) - levelRank(b.level));
}

export function haReadiness(status = {}) {
  const ha = status.highAvailability || status.high_availability || status.ha || {};
  if (!ha || typeof ha !== "object" || !Object.keys(ha).length) {
    return {
      cls: "info",
      label: "unknown",
      state: "unknown",
      mode: "unknown",
      role: "unknown",
      detail: "High availability status was not returned by the system API.",
      meta: "HA status unavailable",
      blockers: [],
    };
  }
  const state = String(ha.state || "").trim().toLowerCase() || "unknown";
  const mode = String(ha.mode || "").trim() || "unknown";
  const role = String(ha.role || "").trim() || "unknown";
  const blockers = asStringArray(ha.blockers);
  const failover = ha.failover || {};
  const sync = ha.sync || {};
  const replication = ha.replication || {};
  const fencingEvidence = normalizeHAFencingEvidence(ha.fencingEvidence || ha.fencing_evidence || {});
  const transportEvidence = normalizeHATransportEvidence(ha.transportEvidence || ha.transport_evidence || {});
  const conntrackSync = normalizeHAConntrackSync(ha.conntrackSync || ha.conntrack_sync || {});
  const cls = state === "ready"
    ? "ok"
    : state === "standalone" || state === "planned"
      ? "warn"
      : "bad";
  const running = Number(ha.runningPolicyVersion || ha.running_policy_version || sync.localVersion || sync.local_version || 0);
  const lkg = Number(ha.lastKnownGoodVersion || ha.last_known_good_version || 0);
  const peer = Number(sync.peerVersion || sync.peer_version || 0);
  const label = state === "standalone" ? "standalone" : state === "ready" ? "ready" : state === "planned" ? "planned" : "blocked";
  const meta = [
    `mode:${mode}`,
    `role:${role}`,
    running ? `running:v${running}` : "",
    lkg ? `lkg:v${lkg}` : "",
    peer ? `peer:v${peer}` : "",
  ].filter(Boolean).join(" ");
  const detail = blockers.length
    ? blockers.slice(0, 3).join(" ")
    : ha.detail || sync.detail || failover.detail || "HA status is present without blockers.";
  return {
    cls,
    label,
    state,
    mode,
    role,
    nodeId: ha.nodeId || ha.node_id || "",
    peerId: ha.peerId || ha.peer_id || "",
    peerAddress: ha.peerAddress || ha.peer_address || "",
    runningPolicyVersion: running,
    lastKnownGoodVersion: lkg,
    lastKnownGoodState: ha.lastKnownGoodState || ha.last_known_good_state || "",
    artifactSet: ha.lastKnownGoodArtifactSetSha256 || ha.last_known_good_artifact_set_sha256 || "",
    sync,
    failover,
    replication,
    fencingEvidence,
    transportEvidence,
    conntrackSync,
    blockers,
    detail,
    meta,
  };
}

function normalizeHATransportEvidence(evidence = {}) {
  const state = String(evidence.state || "").trim() || "not_configured";
  return {
    state,
    claim: evidence.claim || "",
    vip: evidence.vip || "",
    interface: evidence.interface || "",
    routes: Array.isArray(evidence.routes) ? evidence.routes : [],
    garpState: evidence.garpState || evidence.garp_state || "",
    garpDetail: evidence.garpDetail || evidence.garp_detail || "",
    neighborState: evidence.neighborState || evidence.neighbor_state || "",
    neighborDetail: evidence.neighborDetail || evidence.neighbor_detail || "",
    observedAt: evidence.observedAt || evidence.observed_at || "",
    detail: evidence.detail || (state === "promoted"
      ? "Linux-local VIP/route promotion evidence is recorded; traffic path proof remains separate."
      : "No Linux-local HA transport promotion evidence is recorded."),
  };
}

function normalizeHAConntrackSync(evidence = {}) {
  const state = String(evidence.state || "").trim() || "not_configured";
  return {
    state,
    provider: evidence.provider || "",
    claim: evidence.claim || "",
    peerId: evidence.peerId || evidence.peer_id || "",
    evidenceId: evidence.evidenceId || evidence.evidence_id || "",
    observedAt: evidence.observedAt || evidence.observed_at || "",
    detail: evidence.detail || "No conntrack synchronization evidence is recorded for this HA status.",
  };
}

function normalizeHAFencingEvidence(evidence = {}) {
  const state = String(evidence.state || "").trim() || "not_recorded";
  return {
    state,
    provider: evidence.provider || "",
    claim: evidence.claim || "",
    peerId: evidence.peerId || evidence.peer_id || "",
    evidenceId: evidence.evidenceId || evidence.evidence_id || "",
    observedAt: evidence.observedAt || evidence.observed_at || "",
    detail: evidence.detail || (state === "recorded"
      ? "External peer-fencing evidence is recorded for the last local HA role transition."
      : state === "acknowledged_external"
        ? "Peer fencing was acknowledged externally, but provider-backed proof is not recorded."
        : "No peer-fencing evidence is recorded for this HA status."),
  };
}

export function buildHAEvidencePacket(input = {}, opts = {}) {
  const hasEmbeddedHA = Boolean(input?.highAvailability || input?.high_availability || input?.ha);
  const ha = hasEmbeddedHA
    ? haReadiness(input)
    : looksLikeHAObject(input)
      ? haReadiness({ highAvailability: input })
      : haReadiness(input);
  const sync = ha.sync || {};
  const failover = ha.failover || {};
  const fencingEvidence = ha.fencingEvidence || normalizeHAFencingEvidence();
  const transportEvidence = ha.transportEvidence || normalizeHATransportEvidence();
  const conntrackSync = ha.conntrackSync || normalizeHAConntrackSync();
  const blockers = uniqueStrings([
    ...asStringArray(ha.blockers),
    ...asStringArray(sync.blockers),
    ...asStringArray(failover.blockers),
  ]);
  const rows = [
    evidenceRow({
      id: "ha-state",
      cls: ha.cls,
      label: ha.label,
      title: "HA state",
      detail: ha.detail,
      meta: `mode:${ha.mode || "unknown"} role:${ha.role || "unknown"} node:${ha.nodeId || "unknown"} peer:${ha.peerId || "unknown"}`,
    }),
    evidenceRow({
      id: "ha-policy-recovery",
      cls: ha.lastKnownGoodVersion ? "ok" : "bad",
      label: ha.lastKnownGoodVersion ? "lkg present" : "lkg missing",
      title: "Policy recovery metadata",
      detail: ha.lastKnownGoodVersion
        ? `Running policy v${ha.runningPolicyVersion || "unknown"} with last-known-good v${ha.lastKnownGoodVersion}.`
        : "No last-known-good policy version is present.",
      meta: `lkg_state:${ha.lastKnownGoodState || "unknown"} artifact:${ha.artifactSet || "missing"}`,
    }),
    evidenceRow({
      id: "ha-peer-sync",
      cls: haSyncTone(sync),
      label: sync.state || "unknown",
      title: "Peer synchronization",
      detail: sync.detail || "Peer synchronization detail was not returned.",
      meta: `local:v${Number(sync.localVersion || sync.local_version || ha.runningPolicyVersion || 0) || "unknown"} peer:v${Number(sync.peerVersion || sync.peer_version || 0) || "unknown"}`,
    }),
    evidenceRow({
      id: "ha-auto-replication",
      cls: haReplicationTone(ha.replication),
      label: ha.replication?.enabled ? (ha.replication?.state || "enabled") : "disabled",
      title: "Automatic passive replication",
      detail: ha.replication?.detail || "Automatic passive policy replication status was not returned.",
      meta: `last_attempt:${ha.replication?.lastAttemptAt || ha.replication?.last_attempt_at || "none"} last_success:${ha.replication?.lastSuccessAt || ha.replication?.last_success_at || "none"}`,
    }),
    evidenceRow({
      id: "ha-failover",
      cls: failover.eligible ? "ok" : ha.cls === "bad" ? "bad" : "warn",
      label: `${failover.state || "unknown"}${failover.eligible ? " eligible" : ""}`,
      title: "Failover eligibility",
      detail: failover.detail || "Failover detail was not returned.",
      meta: failover.eligible ? "operator failover eligible" : "operator failover blocked",
    }),
    evidenceRow({
      id: "ha-fencing-evidence",
      cls: haFencingEvidenceTone(fencingEvidence),
      label: fencingEvidence.state || "not_recorded",
      title: "Peer fencing evidence",
      detail: fencingEvidence.detail || "Peer fencing evidence was not returned.",
      meta: `provider:${fencingEvidence.provider || "none"} claim:${fencingEvidence.claim || "none"} evidence:${fencingEvidence.evidenceId || "none"}`,
    }),
    evidenceRow({
      id: "ha-transport-evidence",
      cls: haTransportEvidenceTone(transportEvidence),
      label: transportEvidence.state || "not_configured",
      title: "VIP, GARP, and neighbor evidence",
      detail: transportEvidence.detail || "Transport promotion evidence was not returned.",
      meta: `claim:${transportEvidence.claim || "none"} vip:${transportEvidence.vip || "none"} garp:${transportEvidence.garpState || "none"} neighbor:${transportEvidence.neighborState || "none"}`,
    }),
    evidenceRow({
      id: "ha-conntrack-sync",
      cls: haConntrackSyncTone(conntrackSync),
      label: conntrackSync.state || "not_configured",
      title: "Conntrack sync evidence",
      detail: conntrackSync.detail || "Connection-state synchronization evidence was not returned.",
      meta: `provider:${conntrackSync.provider || "none"} claim:${conntrackSync.claim || "none"} evidence:${conntrackSync.evidenceId || "none"}`,
    }),
    evidenceRow({
      id: "ha-blockers",
      cls: blockers.length ? "bad" : ha.cls,
      label: blockers.length ? `${blockers.length} blocker(s)` : "no blockers",
      title: "HA blockers",
      detail: blockers.length ? blockers.join(" ") : "No HA blockers were returned by the system API.",
      meta: ha.peerAddress ? `peer_address:${ha.peerAddress}` : "peer_address:missing",
    }),
  ];
  const packet = {
    schema: "phragma.ha.evidence.v1",
    generatedAt: opts.generatedAt || new Date().toISOString(),
    state: ha.state,
    cls: ha.cls,
    label: ha.label,
    title: ha.cls === "ok"
      ? "HA evidence ready"
      : ha.cls === "warn"
        ? "HA evidence needs review"
        : ha.cls === "bad"
          ? "HA evidence blocked"
          : "HA evidence unavailable",
    detail: ha.detail,
    mode: ha.mode,
    role: ha.role,
    nodeId: ha.nodeId,
    peerId: ha.peerId,
    peerAddress: ha.peerAddress,
    runningPolicyVersion: ha.runningPolicyVersion,
    lastKnownGoodVersion: ha.lastKnownGoodVersion,
    lastKnownGoodState: ha.lastKnownGoodState,
    artifactSet: ha.artifactSet,
    sync: {
      state: sync.state || "",
      detail: sync.detail || "",
      localVersion: Number(sync.localVersion || sync.local_version || 0),
      peerVersion: Number(sync.peerVersion || sync.peer_version || 0),
      localArtifactSetSha256: sync.localArtifactSetSha256 || sync.local_artifact_set_sha256 || "",
      peerArtifactSetSha256: sync.peerArtifactSetSha256 || sync.peer_artifact_set_sha256 || "",
    },
    replication: ha.replication || {},
    fencingEvidence,
    transportEvidence,
    conntrackSync,
    failover: {
      state: failover.state || "",
      eligible: Boolean(failover.eligible),
      detail: failover.detail || "",
    },
    blockers,
    rows,
  };
  packet.text = haEvidencePacketReport(packet);
  return packet;
}

function looksLikeHAObject(value = {}) {
  if (!value || typeof value !== "object") return false;
  return [
    "state",
    "mode",
    "role",
    "nodeId",
    "node_id",
    "peerId",
    "peer_id",
    "peerAddress",
    "peer_address",
    "runningPolicyVersion",
    "running_policy_version",
    "lastKnownGoodVersion",
    "last_known_good_version",
    "lastKnownGoodState",
    "last_known_good_state",
    "lastKnownGoodArtifactSetSha256",
    "last_known_good_artifact_set_sha256",
    "sync",
    "replication",
    "failover",
    "fencingEvidence",
    "fencing_evidence",
    "transportEvidence",
    "transport_evidence",
    "conntrackSync",
    "conntrack_sync",
    "blockers",
  ].some((key) => Object.prototype.hasOwnProperty.call(value, key));
}

export function haEvidencePacketReport(packet = {}) {
  const sync = packet.sync || {};
  const replication = packet.replication || {};
  const failover = packet.failover || {};
  const fencingEvidence = packet.fencingEvidence || {};
  const transportEvidence = packet.transportEvidence || {};
  const conntrackSync = packet.conntrackSync || {};
  const lines = [
    "OpenNGFW high availability evidence packet",
    `schema=${oneLine(packet.schema || "phragma.ha.evidence.v1")}`,
    `generated_at=${oneLine(packet.generatedAt || new Date().toISOString())}`,
    `state=${oneLine(packet.state || "unknown")}`,
    `mode=${oneLine(packet.mode || "unknown")}`,
    `role=${oneLine(packet.role || "unknown")}`,
    `node_id=${oneLine(packet.nodeId || "unknown")}`,
    `peer_id=${oneLine(packet.peerId || "unknown")}`,
    `peer_address=${oneLine(packet.peerAddress || "missing")}`,
    `running_policy_version=${oneLine(packet.runningPolicyVersion ? `v${packet.runningPolicyVersion}` : "unknown")}`,
    `last_known_good=${oneLine(packet.lastKnownGoodVersion ? `v${packet.lastKnownGoodVersion}` : "missing")}`,
    `last_known_good_state=${oneLine(packet.lastKnownGoodState || "unknown")}`,
    `artifact_set=${oneLine(packet.artifactSet || "missing")}`,
    `sync_state=${oneLine(sync.state || "unknown")}`,
    `sync_detail=${oneLine(sync.detail || "unavailable")}`,
    `sync_versions=local:${oneLine(sync.localVersion ? `v${sync.localVersion}` : "unknown")} peer:${oneLine(sync.peerVersion ? `v${sync.peerVersion}` : "unknown")}`,
    `replication_state=${oneLine(replication.state || "unknown")}`,
    `replication_enabled=${replication.enabled ? "true" : "false"}`,
    `replication_last_success=${oneLine(replication.lastSuccessAt || replication.last_success_at || "none")}`,
    `replication_last_error=${oneLine(replication.lastError || replication.last_error || "none")}`,
    `failover_state=${oneLine(failover.state || "unknown")}`,
    `failover_eligible=${failover.eligible ? "true" : "false"}`,
    `failover_detail=${oneLine(failover.detail || "unavailable")}`,
    `fencing_evidence_state=${oneLine(fencingEvidence.state || "not_recorded")}`,
    `fencing_evidence_provider=${oneLine(fencingEvidence.provider || "none")}`,
    `fencing_evidence_claim=${oneLine(fencingEvidence.claim || "none")}`,
    `fencing_evidence_id=${oneLine(fencingEvidence.evidenceId || "none")}`,
    `fencing_evidence_observed_at=${oneLine(fencingEvidence.observedAt || "none")}`,
    `fencing_evidence_detail=${oneLine(fencingEvidence.detail || "unavailable")}`,
    `transport_evidence_state=${oneLine(transportEvidence.state || "not_configured")}`,
    `transport_evidence_claim=${oneLine(transportEvidence.claim || "none")}`,
    `transport_evidence_vip=${oneLine(transportEvidence.vip || "none")}`,
    `transport_evidence_interface=${oneLine(transportEvidence.interface || "none")}`,
    `transport_evidence_routes=${oneLine(asStringArray(transportEvidence.routes).join("; ") || "none")}`,
    `transport_evidence_garp=${oneLine(transportEvidence.garpState || "none")}: ${oneLine(transportEvidence.garpDetail || "unavailable")}`,
    `transport_evidence_neighbor=${oneLine(transportEvidence.neighborState || "none")}: ${oneLine(transportEvidence.neighborDetail || "unavailable")}`,
    `conntrack_sync_state=${oneLine(conntrackSync.state || "not_configured")}`,
    `conntrack_sync_provider=${oneLine(conntrackSync.provider || "none")}`,
    `conntrack_sync_claim=${oneLine(conntrackSync.claim || "none")}`,
    `conntrack_sync_evidence_id=${oneLine(conntrackSync.evidenceId || "none")}`,
    `conntrack_sync_detail=${oneLine(conntrackSync.detail || "unavailable")}`,
    `blockers=${asStringArray(packet.blockers).map(oneLine).join("; ") || "none"}`,
    "source=browser Readiness view; already-loaded /v1/system/status highAvailability object",
    "note=This packet records HA readiness, peer-fencing, VIP/GARP/neighbor, and conntrack-sync evidence status only; it does not execute peer sync or failover, peer fencing, production failover traffic movement, or traffic path proof.",
    "",
  ];
  for (const row of Array.isArray(packet.rows) ? packet.rows : []) {
    lines.push(`- [${evidenceRowState(row).toUpperCase()}] ${oneLine(row.id)} - ${oneLine(row.title)}`);
    if (row.label) lines.push(`  label: ${oneLine(row.label)}`);
    if (row.detail) lines.push(`  detail: ${oneLine(row.detail)}`);
    if (row.meta) lines.push(`  meta: ${oneLine(row.meta)}`);
  }
  return lines.join("\n").trimEnd() + "\n";
}

function haSyncTone(sync = {}) {
  const state = String(sync.state || "").trim().toLowerCase();
  if (state === "ready" || state === "synced" || state === "active") return "ok";
  if (state === "not_configured" || state === "not-configured") return "info";
  if (state === "degraded" || state === "failed") return "bad";
  return "warn";
}

function haReplicationTone(replication = {}) {
  if (!replication?.enabled) return "warn";
  const state = String(replication.state || "").trim().toLowerCase();
  if (state === "replicated" || state === "waiting") return "ok";
  if (state === "blocked" || state === "failed") return "bad";
  return "warn";
}

function haFencingEvidenceTone(evidence = {}) {
  const state = String(evidence.state || "").trim().toLowerCase();
  if (state === "recorded") return "ok";
  if (state === "acknowledged_external" || state === "not_recorded") return "warn";
  if (state === "unavailable") return "bad";
  return "info";
}

function haTransportEvidenceTone(evidence = {}) {
  const state = String(evidence.state || "").trim().toLowerCase();
  if (state === "promoted") return "ok";
  if (state === "unavailable" || state === "degraded") return "bad";
  if (state === "not_configured" || state === "not_performed") return "warn";
  return "info";
}

function haConntrackSyncTone(evidence = {}) {
  const state = String(evidence.state || "").trim().toLowerCase();
  if (state === "synced") return "ok";
  if (state === "degraded" || state === "unavailable") return "bad";
  if (state === "not_configured" || state === "not_performed") return "warn";
  return "info";
}

export function remediationActionId(value = "") {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 72) || "action";
}

export function readinessActionHash(actionId = "") {
  const action = remediationActionId(actionId);
  if (!actionId || !action) return READINESS_ROUTE;
  return `${READINESS_ROUTE}?${new URLSearchParams({ action }).toString()}`;
}

export function dynamicRoutingEnabled(policy = {}) {
  return Boolean(policy?.routing?.bgp?.enabled || policy?.routing?.ospf?.enabled);
}

export function routingRuntimeEvidence(status = {}, policy = {}) {
  const enabled = dynamicRoutingEnabled(policy);
  const frr = status.routing?.frr || {};
  const state = String(frr.state || (enabled ? "unknown" : "not-configured"));
  const bgpNeighbors = frr.bgpNeighbors || frr.bgp_neighbors || [];
  const ospfNeighbors = frr.ospfNeighbors || frr.ospf_neighbors || [];
  return {
    enabled,
    state,
    active: enabled && state === "active",
    detail: frr.detail || (enabled
      ? "FRR runtime posture is not available from system status."
      : "Running policy does not enable BGP or OSPF."),
    bgpNeighbors,
    ospfNeighbors,
    bgpCount: bgpNeighbors.length,
    ospfCount: ospfNeighbors.length,
  };
}

export function releaseEvidenceChecklist({
  summary = {},
  status = {},
  policyDp = {},
  flowCap = {},
  flowRuntime = {},
  ebpfHost = {},
  conntrack = {},
  tuning = {},
  contentPosture = null,
  inspection = {},
  releaseAcceptanceStatus = null,
  telemetry = null,
  telemetryExportStatus = null,
} = {}) {
  const runtimeCls = normalizeTone(summary.cls);
  const contentCls = normalizeTone(contentPosture?.summary?.cls || "warn");
  const contentBlockers = Array.isArray(contentPosture?.blockers) ? contentPosture.blockers : [];
  const hostBlocked = tuning.needsAction || conntrack.state === "degraded";
  const hostWarn = !hostBlocked && tuning.throughputReady === false;
  const accelerated = Boolean(policyDp.accelerated);
  const flowHostReady = flowCap.state === "ready" || flowCap.state === "active";
  const flowRuntimeReady = flowRuntime.state === "active";
  const ebpfBlocked = ebpfBlocksCurrentDataplane(status, ebpfHost);
  const dataplaneBlocked = ebpfBlocked || (accelerated && (!flowHostReady || !flowRuntimeReady));
  const inspectionCls = normalizeInspectionTone(inspection);
  const engineCount = Number(summary.engineCount || 0);
  const readyEngines = Number(summary.readyEngines || 0);
  const productionContentGate = releaseAcceptanceCheckGate(
    releaseAcceptanceStatus,
    "content-production-readiness",
    productionContentReleaseGate(contentPosture),
  );
  const performanceGate = performanceReleaseGate(releaseAcceptanceStatus);
  const ha = haReadiness(status);
  const telemetryGate = telemetryExportProofGate(status, telemetry, telemetryExportStatus);
  const rootlessAcceptanceItems = releaseAcceptanceStatus ? rootlessReleaseGateItems(releaseAcceptanceStatus) : [];
  const privilegedIntegrationGate = releaseAcceptanceCheckGate(releaseAcceptanceStatus, "privileged-integration", {
    cls: "bad",
    label: "field required",
    detail: "Release acceptance still requires privileged-integration evidence from a root Linux host against real engines and live dataplane paths; local WebUI readiness cannot close this artifact.",
    meta: "record privileged-integration in release/evidence",
  });
  const m3LiveGate = releaseAcceptanceCheckGate(releaseAcceptanceStatus, "m3-live-networking", {
    cls: "bad",
    label: "field required",
    detail: "Release acceptance requires privileged M3 live-networking evidence for static-route forwarding, local FRR BGP netns programming, and WireGuard peer traffic.",
    meta: "make m3-live-networking-check",
  });
  const m3FieldGate = releaseAcceptanceCheckGate(releaseAcceptanceStatus, "m3-field-evidence", {
    cls: "bad",
    label: "field required",
    detail: "External BGP peer, IPsec SA/protected-subnet traffic, and external WireGuard client evidence must be captured and validated; local netns M3 checks do not close this release gate.",
    meta: "make m3-field-evidence-check",
  });
  const ebpfOL9FieldGate = releaseAcceptanceCheckGate(releaseAcceptanceStatus, "ebpf-ol9-field-evidence", {
    cls: "bad",
    label: "field required",
    detail: "OL9/OCI Linux-root XDP/tc attach, status API, renderer scaffold, and cleanup evidence must be captured and validated; local host readiness does not close this release gate.",
    meta: "make ebpf-ol9-field-evidence-check",
  });
  const oidcFieldGate = releaseAcceptanceCheckGate(releaseAcceptanceStatus, "m5-oidc-field-evidence", {
    cls: "bad",
    label: "field required",
    detail: "A real issuer/client, public HTTPS callback, browser session, CSRF/role evidence, and proxy posture must be captured; mock OIDC tests or current local session state do not close this gate.",
    meta: "make m5-oidc-field-evidence-check",
  });
  const webUIEnterpriseSmokeGate = releaseAcceptanceCheckGate(releaseAcceptanceStatus, "webui-enterprise-smoke", {
    cls: "bad",
    label: "browser evidence required",
    detail: `Release acceptance requires a broad WebUI enterprise smoke from a browser-capable release host across the ${WEBUI_ENTERPRISE_SMOKE_SCOPE}; targeted route repairs, continuation evidence, and notes do not record durable release evidence or close this gate.`,
    meta: `${RELEASE_EVIDENCE_DIR}/webui-enterprise-smoke.txt`,
  });
  const samlFieldGate = releaseAcceptanceCheckGate(releaseAcceptanceStatus, "m5-saml-field-evidence", {
    cls: "bad",
    label: "field required",
    detail: "A real IdP/SP metadata exchange, public HTTPS ACS, browser session, CSRF/role evidence, and proxy posture must be captured; SAML rollout packets or current local session state do not close this gate.",
    meta: "make m5-saml-field-evidence-check",
  });

  return [
    {
      id: "runtime",
      cls: runtimeCls,
      icon: runtimeCls === "bad" ? "block" : runtimeCls === "warn" ? "threats" : "shield",
      label: runtimeCls === "bad" ? "blocked" : runtimeCls === "warn" ? "review" : "clear",
      title: "Production readiness gate",
      detail: summary.detail || "Runtime production posture has not been summarized yet.",
      meta: engineCount ? `${readyEngines}/${engineCount} engines ready` : "engine evidence unavailable",
      href: "#/readiness",
    },
    ...rootlessAcceptanceItems,
    {
      id: "content",
      cls: contentCls,
      icon: "intel",
      label: contentCls === "bad" ? "blocked" : contentCls === "warn" ? "review" : "verified",
      title: "Content package evidence",
      detail: contentPosture?.summary?.detail || "App-ID, Threat-ID, feed package, signature, regression, and rollback evidence should be reviewed.",
      meta: contentBlockers.length ? `${contentBlockers.length} blocker(s)` : "no package blockers",
      href: "#/intel",
    },
    {
      id: "content-production-readiness",
      cls: productionContentGate.cls,
      icon: "intel",
      label: productionContentGate.label,
      title: "Production content readiness",
      detail: productionContentGate.detail,
      meta: productionContentGate.meta,
      href: productionContentGate.href,
      reference: productionContentGate.reference,
      packet: productionContentGate.packet,
    },
    {
      id: "host",
      cls: hostBlocked ? "bad" : hostWarn ? "warn" : "ok",
      icon: "settings",
      label: hostBlocked ? "blocked" : hostWarn ? "tune" : "ready",
      title: "Host tuning and state table",
      detail: hostBlocked
        ? tuning.detail || conntrack.detail || "Host tuning or conntrack pressure blocks release readiness."
        : hostWarn
          ? tuning.throughputDetail || "Throughput profile is available before publishing high-throughput evidence."
          : "Kernel baseline and conntrack state-table posture are ready.",
      meta: conntrack.maxEntries ? `${conntrack.usagePercent.toFixed(1)}% conntrack` : "conntrack limit unavailable",
      href: "#/readiness",
    },
    {
      id: "dataplane",
      cls: dataplaneBlocked ? "bad" : accelerated ? "ok" : "info",
      icon: "traffic",
      label: dataplaneBlocked ? "missing proof" : accelerated ? "proven" : "standard",
      title: "Dataplane proof",
      detail: dataplaneBlocked
        ? ebpfBlocked
          ? ebpfHost.detail || "The active eBPF dataplane is missing host prerequisites."
          : flowRuntime.detail || flowCap.detail || "Flowtable acceleration needs host readiness and active runtime evidence."
        : accelerated
          ? "Flowtable host readiness and live runtime evidence are present for the accelerated policy."
          : "Flowtable acceleration is not requested; standard dataplane evidence is used for this release posture.",
      meta: accelerated ? `host ${flowCap.state || "unknown"} / runtime ${flowRuntime.state || "unknown"}` : policyDp.baseDataplane || "standard forwarding",
      href: "#/readiness",
    },
    {
      id: "webui-enterprise-smoke",
      cls: webUIEnterpriseSmokeGate.cls,
      icon: "dashboard",
      label: webUIEnterpriseSmokeGate.label,
      title: "WebUI enterprise smoke",
      detail: webUIEnterpriseSmokeGate.detail,
      meta: webUIEnterpriseSmokeGate.meta,
      href: READINESS_ROUTE,
      reference: RELEASE_ACCEPTANCE_DOC,
      packet: WEBUI_ENTERPRISE_SMOKE_PACKET,
    },
    {
      id: "privileged-integration",
      cls: privilegedIntegrationGate.cls,
      icon: "settings",
      label: privilegedIntegrationGate.label,
      title: "Privileged integration and live dataplane",
      detail: privilegedIntegrationGate.detail,
      meta: privilegedIntegrationGate.meta,
      href: READINESS_ROUTE,
      reference: RELEASE_ACCEPTANCE_DOC,
      packet: PRIVILEGED_INTEGRATION_PACKET,
    },
    {
      id: "m3-live-networking",
      cls: m3LiveGate.cls,
      icon: "vpn",
      label: m3LiveGate.label,
      title: "M3 live networking",
      detail: m3LiveGate.detail,
      meta: m3LiveGate.meta,
      href: NETVPN_ROUTE,
      reference: RELEASE_ACCEPTANCE_DOC,
      packet: M3_LIVE_NETWORKING_PACKET,
    },
    {
      id: "ha-readiness",
      cls: ha.cls,
      icon: ha.cls === "bad" ? "block" : "settings",
      label: ha.label,
      title: "Active/passive HA readiness",
      detail: ha.detail,
      meta: ha.meta,
      href: "#/readiness",
    },
    telemetryGate,
    {
      id: "m3-field-evidence",
      cls: m3FieldGate.cls,
      icon: "vpn",
      label: m3FieldGate.label,
      title: "M3 external field evidence",
      detail: m3FieldGate.detail,
      meta: m3FieldGate.meta,
      href: NETVPN_ROUTE,
      reference: M3_FIELD_EVIDENCE_DOC,
      packet: M3_FIELD_PACKET,
    },
    {
      id: "ebpf-ol9-field-evidence",
      cls: ebpfOL9FieldGate.cls,
      icon: "settings",
      label: ebpfOL9FieldGate.label,
      title: "eBPF OL9 field evidence",
      detail: ebpfOL9FieldGate.detail,
      meta: ebpfOL9FieldGate.meta,
      href: READINESS_ROUTE,
      reference: RELEASE_ACCEPTANCE_DOC,
      packet: EBPF_OL9_FIELD_PACKET,
    },
    {
      id: "inspection",
      cls: inspectionCls,
      icon: inspectionCls === "bad" ? "block" : "threats",
      label: inspection.state || "unknown",
      title: "Inspection and failure behavior",
      detail: inspection.detail || inspection.degradedBehavior || "Inspection readiness and fail-open/fail-closed posture are not available.",
      meta: [inspection.engineLabel, inspection.failureBehavior].filter(Boolean).join(" / ") || "engine evidence unavailable",
      href: "#/readiness",
    },
    {
      id: "m5-oidc-field-evidence",
      cls: oidcFieldGate.cls,
      icon: "key",
      label: oidcFieldGate.label,
      title: "OIDC real-provider field evidence",
      detail: oidcFieldGate.detail,
      meta: oidcFieldGate.meta,
      href: SETTINGS_ACCESS_ROUTE,
      reference: OIDC_FIELD_EVIDENCE_DOC,
      packet: OIDC_FIELD_PACKET,
    },
    {
      id: "m5-saml-field-evidence",
      cls: samlFieldGate.cls,
      icon: "key",
      label: samlFieldGate.label,
      title: "SAML real-provider field evidence",
      detail: samlFieldGate.detail,
      meta: samlFieldGate.meta,
      href: SETTINGS_ACCESS_ROUTE,
      reference: RELEASE_ACCEPTANCE_DOC,
      packet: SAML_FIELD_PACKET,
    },
    {
      id: "performance",
      cls: performanceGate.cls,
      icon: "dashboard",
      label: performanceGate.label,
      title: "Performance publication gate",
      detail: performanceGate.detail,
      meta: performanceGate.meta,
      href: performanceGate.href,
    },
    {
      id: "support",
      cls: "ok",
      icon: "download",
      label: "exportable",
      title: "Support bundle evidence",
      detail: "Preview support bundle exports existing status, policy, validation, runtime-readiness preflight, audit, telemetry, session, feed, and content-package evidence without mutating the firewall.",
      meta: "uses existing read APIs",
      href: "#/readiness",
    },
  ].filter(Boolean);
}

function telemetryExportProofGate(status = {}, telemetry = null, telemetryExportStatus = null) {
  if (!telemetryEvidenceRequired(telemetry)) return null;
  const model = telemetryReadinessModel({ status, telemetry, dirty: false, exportStatus: telemetryExportStatus });
  const engineBlocked = model.active && model.engineTone === "bad";
  const observedLocal = model.channels.some((channel) => channel.observed && channel.id !== "json-stream");
  const remoteNeedsProof = model.channels.some((channel) => channel.id === "json-stream" && channel.statusLabel !== "disabled");
  const commands = telemetryEvidenceCommands(model).map((item) => item.command);
  const packet = {
    check: "telemetry-export-proof",
    evidencePath: "browser-export:phragma.telemetry.evidence.v1",
    artifactPath: "",
    summary: "Redacted browser telemetry export evidence packet plus post-commit ClickHouse/file/SIEM verification commands.",
    makeTargets: [],
    commands,
    reference: "docs/webui-design.md#settings-and-system-configuration",
  };
  return {
    id: "telemetry-export-proof",
    cls: engineBlocked ? "bad" : "warn",
    icon: engineBlocked ? "block" : "terminal",
    label: engineBlocked ? "blocked" : observedLocal ? "local observed" : "prove delivery",
    title: "Telemetry and SIEM export proof",
    detail: engineBlocked
      ? `Telemetry is configured, but Vector runtime is ${model.engineState}; resolve Vector before recording sink-delivery evidence.`
      : observedLocal
        ? `Passive status has local export activity; export the redacted evidence packet and add ${remoteNeedsProof ? "SIEM receiver counts plus " : ""}ClickHouse row evidence after a controlled IDS/IPS event.`
        : "Telemetry is configured; export the redacted evidence packet and verify ClickHouse rows, JSON file output, or SIEM listener counts after a controlled IDS/IPS event.",
    meta: model.pipelineLabel || "telemetry export configured",
    href: SETTINGS_TELEMETRY_ROUTE,
    reference: "docs/webui-design.md#settings-and-system-configuration",
    packet,
  };
}

function telemetryEvidenceRequired(telemetry = null) {
  if (!telemetry) return false;
  if (telemetry.enabled === true) return true;
  return Array.isArray(telemetry.exports) && telemetry.exports.some((item) => item?.enabled);
}

function rootlessReleaseGateItems(releaseAcceptanceStatus = null) {
  const apiContractSourceAcceptance = apiContractSourceAcceptanceModel(releaseAcceptanceStatus?.recordability);
  return [
    {
      ...releaseChecklistItemFromGate("proto-verify", "Generated API contract", "#/readiness", PROTO_VERIFY_PACKET, releaseAcceptanceCheckGate(releaseAcceptanceStatus, "proto-verify", {
      cls: "bad",
      label: "missing evidence",
      detail: `Generated API, gRPC gateway, and OpenAPI artifacts must match proto sources. ${API_CONTRACT_SOURCE_ACCEPTANCE_NOTE}`,
      meta: `${RELEASE_EVIDENCE_DIR}/proto-verify.txt`,
      })),
      sourceAcceptance: apiContractSourceAcceptance,
    },
    releaseChecklistItemFromGate("deploy-hardening", "Packaged deployment evidence", SETTINGS_ACCESS_ROUTE, DEPLOY_HARDENING_PACKET, releaseAcceptanceCheckGate(releaseAcceptanceStatus, "deploy-hardening", {
      cls: "bad",
      label: "missing evidence",
      detail: "Packaged deployment evidence must be recorded before release acceptance. This gate is a static service-unit and installer check only; live runtime hardening remains a separate pass.",
      meta: `${RELEASE_EVIDENCE_DIR}/deploy-hardening.txt`,
    })),
    releaseChecklistItemFromGate("policy-restore-drill", "Emergency policy restore drill", "#/readiness", POLICY_RESTORE_DRILL_PACKET, releaseAcceptanceCheckGate(releaseAcceptanceStatus, "policy-restore-drill", {
      cls: "bad",
      label: "missing evidence",
      detail: "Rootless policy rollback, audit, LKG, and engine-apply restore drill evidence must be recorded before release acceptance.",
      meta: `${RELEASE_EVIDENCE_DIR}/policy-restore-drill.txt`,
    })),
    releaseChecklistItemFromGate("ha-readiness-recovery", "HA readiness recovery evidence", "#/readiness?drawer=ha-cockpit", HA_READINESS_RECOVERY_PACKET, releaseAcceptanceCheckGate(releaseAcceptanceStatus, "ha-readiness-recovery", {
      cls: "bad",
      label: "missing evidence",
      detail: "Rootless active/passive HA readiness and control-plane recovery evidence must be recorded before release acceptance.",
      meta: `${RELEASE_EVIDENCE_DIR}/ha-readiness-recovery.txt`,
    })),
    releaseChecklistItemFromGate("e2e-install", "Install smoke run", "#/readiness", E2E_INSTALL_PACKET, releaseAcceptanceCheckGate(releaseAcceptanceStatus, "e2e-install", {
      cls: "bad",
      label: "missing evidence",
      detail: "The privileged install smoke must be recorded from a disposable Linux host after proving installed-service policy enforcement.",
      meta: `${RELEASE_EVIDENCE_DIR}/e2e-install.txt`,
    })),
    releaseChecklistItemFromGate("content-package-verification", "Signed content package mechanics", "#/intel", CONTENT_PACKAGE_PACKET, releaseAcceptanceCheckGate(releaseAcceptanceStatus, "content-package-verification", {
      cls: "bad",
      label: "missing evidence",
      detail: "Signed demo content package verification, install, and rollback mechanics must be recorded.",
      meta: `${RELEASE_EVIDENCE_DIR}/content-package-verification.txt`,
    })),
    releaseChecklistItemFromGate("release-benchmark", "Performance benchmark release gate", "#/performance", RELEASE_BENCHMARK_PACKET, releaseAcceptanceCheckGate(releaseAcceptanceStatus, "release-benchmark", {
      cls: "bad",
      label: "missing evidence",
      detail: "Publishable benchmark release evidence or an explicit no-performance-claims manifest must be recorded before publishing performance claims.",
      meta: `${RELEASE_EVIDENCE_DIR}/release-benchmark.txt`,
    })),
    releaseChecklistItemFromGate("m5-auth-ui", "Auth and WebUI runtime smoke", SETTINGS_ACCESS_ROUTE, M5_AUTH_UI_PACKET, releaseAcceptanceCheckGate(releaseAcceptanceStatus, "m5-auth-ui", {
      cls: "bad",
      label: "missing evidence",
      detail: "Rootless WebUI syntax, JavaScript tests, local auth, RBAC, TLS headers, request limits, rate limiting, and startup guard evidence must be recorded.",
      meta: `${RELEASE_EVIDENCE_DIR}/m5-auth-ui.txt`,
    })),
    releaseChecklistItemFromGate("m5-oidc-provider", "OIDC provider runtime smoke", SETTINGS_ACCESS_ROUTE, M5_OIDC_PROVIDER_PACKET, releaseAcceptanceCheckGate(releaseAcceptanceStatus, "m5-oidc-provider", {
      cls: "bad",
      label: "missing evidence",
      detail: "Loopback mock-provider OIDC authorization-code session evidence must be recorded before release acceptance.",
      meta: `${RELEASE_EVIDENCE_DIR}/m5-oidc-provider.txt`,
    })),
  ];
}

function releaseChecklistItemFromGate(id, title, href, packet, gate = {}) {
  return {
    id,
    cls: gate.cls,
    icon: gate.cls === "ok" ? "check" : gate.cls === "bad" ? "block" : "terminal",
    label: gate.label,
    title,
    detail: gate.detail,
    meta: gate.meta,
    href,
    reference: RELEASE_ACCEPTANCE_DOC,
    packet,
  };
}

function productionContentReleaseGate(contentPosture = null) {
  const readiness = contentPosture?.productionContentReadiness || contentPosture?.contentProductionReadiness || contentPosture?.productionReadiness || null;
  const blockers = Array.isArray(readiness?.blockers) ? readiness.blockers : [];
  const state = String(readiness?.state || readiness?.status || "").toLowerCase();
  const explicitReady = Boolean(readiness && (readiness.productionReady === true || readiness.production_ready === true || state === "passed" || state === "ready" || state === "verified"));

  if (explicitReady && blockers.length === 0) {
    return {
      cls: "ok",
      label: "recorded",
      detail: readiness.detail || "Production App-ID, Threat-ID, and intel-feed content readiness evidence is explicitly recorded for this release.",
      meta: readiness.meta || "content-production-readiness passed",
      href: INTEL_ROUTE,
      reference: RELEASE_ACCEPTANCE_DOC,
      packet: CONTENT_PRODUCTION_PACKET,
    };
  }

  if (readiness && blockers.length) {
    return {
      cls: "bad",
      label: "blocked",
      detail: `${blockers.length} production content blocker(s): ${blockers.slice(0, 6).join(", ")}.`,
      meta: readiness.meta || "make content-production-readiness-check",
      href: INTEL_ROUTE,
      reference: RELEASE_ACCEPTANCE_DOC,
      packet: CONTENT_PRODUCTION_PACKET,
    };
  }

  return {
    cls: "bad",
    label: "field required",
    detail: "Signed package verification and demo smoke are not enough; record content-production-readiness from production App-ID, Threat-ID, and intel-feed evidence before release claims.",
    meta: "make content-production-readiness-check",
    href: INTEL_ROUTE,
    reference: RELEASE_ACCEPTANCE_DOC,
    packet: CONTENT_PRODUCTION_PACKET,
  };
}

function performanceReleaseGate(releaseAcceptanceStatus = null) {
  const check = releaseAcceptanceCheck(releaseAcceptanceStatus, "release-benchmark");
  if (!releaseAcceptanceStatus) {
    return {
      cls: "info",
      label: "local artifact",
      detail: "Load a benchmark run in Performance to verify summary, raw iperf, status, nftables, claim-scope, and publishable release evidence.",
      meta: "browser-only review",
      href: "#/performance",
    };
  }

  const state = normalizeEvidenceState(check?.state || check?.status);
  const evidencePath = releaseAcceptanceCheckField(check, "evidence_path", "evidencePath");
  const benchmarkSummary = releaseAcceptanceCheckField(check, "benchmark_summary", "benchmarkSummary");
  if (state === "not_applicable") {
    return {
      cls: "ok",
      label: "no claims",
      detail: check?.detail || "This release publishes no throughput, latency, connection-rate, or comparison claims; release-benchmark is not applicable.",
      meta: "release-benchmark not_applicable",
      href: "#/performance",
    };
  }
  if (state === "passed") {
    return {
      cls: "ok",
      label: "passed",
      detail: check?.detail || "Publishable benchmark release evidence is accepted by the verified release manifest.",
      meta: benchmarkSummary || evidencePath || check?.artifact || "release-benchmark evidence passed",
      href: "#/performance",
    };
  }
  if (state === "recorded") {
    return {
      cls: "warn",
      label: "pending manifest",
      detail: check?.nextAction || recordedEvidencePendingDetail(check?.detail, "Publishable benchmark evidence"),
      meta: benchmarkSummary || evidencePath || check?.artifact || "release-benchmark evidence recorded",
      href: "#/performance",
    };
  }
  if (state === "missing" || state === "invalid" || state === "todo" || !check) {
    return {
      cls: "bad",
      label: state === "invalid" ? "invalid" : "missing evidence",
      detail: "Release acceptance requires a publishable benchmark artifact, or an explicit no-performance-claims manifest before publishing performance claims.",
      meta: evidencePath || "make benchmark-verify-release or assemble with RELEASE_NO_PERFORMANCE_CLAIMS=1",
      href: "#/performance",
    };
  }

  return {
    cls: "warn",
    label: state || "review",
    detail: check?.detail || "Performance publication gate state requires review before release.",
    meta: evidencePath || "release-benchmark",
    href: "#/performance",
  };
}

function releaseAcceptanceCheckGate(releaseAcceptanceStatus = null, name = "", fallback = {}) {
  if (!releaseAcceptanceStatus) return fallback;
  const check = releaseAcceptanceCheck(releaseAcceptanceStatus, name);
  if (!check) {
    return {
      ...fallback,
      cls: "bad",
      label: "missing evidence",
      detail: `${name} is missing from the release acceptance status report.`,
      meta: fallback.meta || `release/evidence/${name}.txt`,
    };
  }
  const state = normalizeEvidenceState(check.state || check.status);
  const evidencePath = releaseAcceptanceCheckField(check, "evidence_path", "evidencePath");
  const problems = asStringArray(check.problems);
  if (state === "passed") {
    return {
      ...fallback,
      cls: "ok",
      label: "passed",
      detail: check.detail || `${name} release evidence is accepted by the verified release manifest.`,
      meta: evidencePath || check.artifact || `${name} passed`,
    };
  }
  if (state === "recorded") {
    const detail = recordedEvidencePendingDetail(check.detail, `${name} evidence`);
    return {
      ...fallback,
      cls: "warn",
      label: "pending manifest",
      detail: check.nextAction || (name === "deploy-hardening" && fallback.detail ? `${detail} ${fallback.detail}` : detail),
      meta: evidencePath || check.artifact || `${name} recorded`,
    };
  }
  if (state === "review_needed") {
    return {
      ...fallback,
      cls: "warn",
      label: "review needed",
      detail: check.nextAction || problems[0] || check.detail || `${name} evidence needs review before it can be accepted. Regenerate it with ngfwrelease record after source-control acceptance if it is stale, copied, mismatched, reused, or contains skipped-test output.`,
      meta: evidencePath || check.artifact || `${name} review needed`,
    };
  }
  if (state === "not_applicable") {
    if (name !== "release-benchmark") {
      return {
        ...fallback,
        cls: "warn",
        label: "review needed",
        detail: [check.detail, `${name} normally requires explicit evidence.`].filter(Boolean).join(" "),
        meta: `${name} not_applicable`,
      };
    }
    return {
      ...fallback,
      cls: "ok",
      label: "not applicable",
      detail: check.detail || `${name} is marked not_applicable in release acceptance status.`,
      meta: `${name} not_applicable`,
    };
  }
  if (state === "missing" || state === "invalid" || state === "todo" || !state) {
    return {
      ...fallback,
      cls: "bad",
      label: state === "invalid" ? "invalid" : state === "todo" ? "todo" : "missing evidence",
      detail: problems[0] || check.detail || fallback.detail || `${name} release evidence is missing.`,
      meta: evidencePath || fallback.meta || `release/evidence/${name}.txt`,
    };
  }
  return {
    ...fallback,
    cls: "warn",
    label: state || "review",
    detail: check.detail || fallback.detail || `${name} release evidence requires review.`,
    meta: evidencePath || fallback.meta || name,
  };
}

export function apiContractSourceAcceptanceModel(recordability = null) {
  if (!recordability || typeof recordability !== "object") {
    return {
      state: "unknown",
      cls: "warn",
      label: "source acceptance unknown",
      dirtySourceCount: 0,
      problemCount: 0,
      truncatedDirtySourceCount: 0,
      detail: API_CONTRACT_SOURCE_ACCEPTANCE_NOTE,
    };
  }
  const problems = asStringArray(recordability.problems);
  const dirtySourcePaths = asStringArray(recordability.dirtySourcePaths || recordability.dirty_source_paths);
  const truncated = Number(recordability.truncatedDirtySourceCount ?? recordability.truncated_dirty_source_count ?? 0);
  const truncatedDirtySourceCount = Number.isFinite(truncated) && truncated > 0 ? truncated : 0;
  const blocked = !Boolean(recordability.ready) || problems.length > 0 || dirtySourcePaths.length > 0 || truncatedDirtySourceCount > 0;
  const blockerParts = [
    dirtySourcePaths.length ? `${dirtySourcePaths.length} dirty source path(s)` : "",
    truncatedDirtySourceCount ? `${truncatedDirtySourceCount} truncated dirty source path(s)` : "",
    problems.length ? `${problems.length} recordability problem(s)` : "",
  ].filter(Boolean);
  return {
    state: blocked ? "blocked" : "clear",
    cls: blocked ? "bad" : "ok",
    label: blocked ? "source acceptance pending" : "source accepted",
    dirtySourceCount: dirtySourcePaths.length,
    problemCount: problems.length,
    truncatedDirtySourceCount,
    detail: blocked
      ? `${blockerParts.join(", ") || "source-control acceptance is blocked"}. ${API_CONTRACT_SOURCE_ACCEPTANCE_NOTE}`
      : `No source-control recordability blockers were reported. ${API_CONTRACT_SOURCE_ACCEPTANCE_NOTE}`,
  };
}

function releaseAcceptanceCheck(status = null, name = "") {
  const checks = Array.isArray(status?.checks) ? status.checks : [];
  return checks.find((check) => check?.name === name) || null;
}

function releaseAcceptanceCheckField(check = {}, snakeName = "", camelName = "") {
  return check?.[snakeName] || check?.[camelName] || "";
}

function recordedEvidencePendingDetail(detail = "", subject = "Release evidence") {
  const text = String(detail || "").trim();
  const pending = `${subject} is recorded but is not accepted until the release acceptance manifest is assembled and verified.`;
  if (!text) return pending;
  if (/not accepted until/i.test(text)) return text;
  return `${text} ${pending}`;
}

function normalizeEvidenceState(value) {
  return String(value || "").trim().toLowerCase().replace(/-/g, "_");
}

export function releaseEvidenceCounts(items = []) {
  return items.reduce((acc, item) => {
    const cls = normalizeTone(item.cls);
    if (cls === "bad") acc.blocked += 1;
    else if (cls === "warn") acc.review += 1;
    else if (cls === "ok") acc.clear += 1;
    else acc.info += 1;
    return acc;
  }, { blocked: 0, review: 0, clear: 0, info: 0 });
}

export function releaseEvidenceReport(items = [], opts = {}) {
  const counts = releaseEvidenceCounts(items);
  const generatedAt = opts.generatedAt || new Date().toISOString();
  const lines = [
    "OpenNGFW release evidence summary",
    `generated_at=${oneLine(generatedAt)}`,
    `totals=blocked:${counts.blocked} review:${counts.review} clear:${counts.clear} info:${counts.info}`,
    "",
  ];

  for (const item of items) {
    const cls = normalizeTone(item.cls);
    lines.push(`- [${releaseEvidenceReportState(item).toUpperCase()}] ${oneLine(item.id || cls)} - ${oneLine(item.title || "Release evidence")}`);
    if (item.detail) lines.push(`  detail: ${oneLine(item.detail)}`);
    if (item.meta) lines.push(`  meta: ${oneLine(item.meta)}`);
    if (item.href) lines.push(`  link: ${oneLine(item.href)}`);
    if (item.reference) lines.push(`  reference: ${oneLine(item.reference)}`);
    if (item.packet) {
      if (item.packet.check) lines.push(`  check: ${oneLine(item.packet.check)}`);
      if (item.packet.summary) lines.push(`  evidence_summary: ${oneLine(item.packet.summary)}`);
      if (item.packet.evidencePath) lines.push(`  evidence_path: ${oneLine(item.packet.evidencePath)}`);
      if (item.packet.artifactPath) lines.push(`  artifact_path: ${oneLine(item.packet.artifactPath)}`);
      for (const target of asStringArray(item.packet.makeTargets)) {
        lines.push(`  make_target: ${oneLine(target)}`);
      }
      for (const command of releaseEvidencePacketCommands(item.packet)) {
        lines.push(`  command: ${oneLine(command)}`);
      }
    }
  }

  return lines.join("\n").trimEnd() + "\n";
}

export function releaseArtifactWorkbenchModel(items = [], releaseAcceptanceStatus = null) {
  const releaseItems = Array.isArray(items) ? items : [];
  const itemById = new Map(releaseItems.map((item) => [item.id, item]));
  const manifestPresent = Boolean(releaseAcceptanceStatus?.manifestPresent ?? releaseAcceptanceStatus?.manifest_present);
  const manifestPath = releaseAcceptanceStatus?.manifestPath || releaseAcceptanceStatus?.manifest_path || "release/acceptance.json";
  const recordability = releaseAcceptanceStatus?.recordability || {};
  const staleEvidencePaths = asStringArray(recordability.staleEvidencePaths || recordability.stale_evidence_paths);
  const rows = releaseEvidencePacketIds()
    .map((id) => releaseArtifactWorkbenchRow({
      id,
      item: itemById.get(id),
      check: releaseAcceptanceCheck(releaseAcceptanceStatus, id),
      manifestPresent,
      manifestPath,
      staleEvidencePaths,
    }))
    .filter(Boolean);
  const counts = rows.reduce((acc, row) => {
    acc.total += 1;
    if (row.evidenceState === "recorded") acc.recorded += 1;
    else if (row.evidenceState === "missing") acc.missing += 1;
    else if (row.evidenceState === "stale" || row.evidenceState === "invalid") acc.stale += 1;
    if (row.cls === "ok") acc.clear += 1;
    else if (row.cls === "bad") acc.blocked += 1;
    else acc.review += 1;
    return acc;
  }, { total: 0, clear: 0, review: 0, blocked: 0, recorded: 0, missing: 0, stale: 0 });
  return {
    manifestPresent,
    manifestPath,
    state: releaseAcceptanceStatus?.state || (releaseAcceptanceStatus?.ready ? "ready" : "unknown"),
    counts,
    rows,
  };
}

function releaseArtifactWorkbenchRow({ id, item = null, check = null, manifestPresent = false, manifestPath = "", staleEvidencePaths = [] } = {}) {
  const definition = releaseEvidencePacketDefinition(id);
  const packet = item?.packet || definition?.packet || {};
  if (!packet || !id) return null;
  const state = normalizeEvidenceState(check?.state || check?.status || item?.label || "");
  const evidencePath = releaseAcceptanceCheckField(check, "evidence_path", "evidencePath") || packet.evidencePath || item?.meta || "";
  const artifactPath = check?.artifact || packet.artifactPath || "";
  const problems = asStringArray(check?.problems);
  const stale = state === "review_needed" || Boolean(check?.reviewNeeded || check?.review_needed) || releaseEvidenceLooksStale(problems, evidencePath, artifactPath, staleEvidencePaths);
  const evidenceState = stale
    ? "stale"
    : state === "passed" || state === "recorded"
      ? "recorded"
      : state === "invalid"
        ? "invalid"
        : state === "missing" || state === "todo" || !check
          ? "missing"
          : state === "not_applicable"
            ? "not applicable"
            : state || "review";
  const cls = state === "passed"
    ? "ok"
    : evidenceState === "missing" || evidenceState === "invalid"
      ? "bad"
      : stale || state === "recorded" || state === "not_applicable"
        ? "warn"
        : normalizeTone(item?.cls || "warn");
  const next = releaseArtifactNextCommand({ check, packet, evidenceState });
  return {
    id,
    title: item?.title || definition?.title || id,
    cls,
    label: state === "passed" ? "passed" : evidenceState,
    expectedGate: packet.check || id,
    currentStatus: check?.detail || item?.detail || packet.summary || "Release evidence status is not reported.",
    manifestBinding: releaseArtifactManifestBinding({ state, evidenceState, manifestPresent, manifestPath }),
    evidenceState,
    evidencePath,
    artifactPath,
    operatorRoute: item?.href || "",
    packetRoute: `#/readiness?packet=${encodeURIComponent(id)}`,
    nextCommandRole: next.role,
    nextCommand: next.command,
    problems,
  };
}

function releaseEvidenceLooksStale(problems = [], evidencePath = "", artifactPath = "", staleEvidencePaths = []) {
  const haystack = [...asStringArray(problems), evidencePath, artifactPath].join("\n").toLowerCase();
  if (/\bstale\b|mismatch|copied|reused|skipped-test|skipped test|different commit/.test(haystack)) return true;
  const paths = new Set(staleEvidencePaths.map((path) => String(path || "").trim()).filter(Boolean));
  return Boolean((evidencePath && paths.has(evidencePath)) || (artifactPath && paths.has(artifactPath)));
}

function releaseArtifactManifestBinding({ state = "", evidenceState = "", manifestPresent = false, manifestPath = "" } = {}) {
  if (state === "passed") return `accepted by ${manifestPath || "release acceptance manifest"}`;
  if (evidenceState === "recorded") return manifestPresent ? "recorded; manifest verification pending" : "recorded; manifest missing";
  if (evidenceState === "stale") return "not bindable until stale or mismatched evidence is regenerated";
  if (evidenceState === "not applicable") return manifestPresent ? "manifest declares not applicable" : "not applicable; manifest not loaded";
  return manifestPresent ? "not bound in current manifest" : "manifest missing";
}

function releaseArtifactNextCommand({ check = null, packet = {}, evidenceState = "" } = {}) {
  const nextCommand = asStringArray(check?.nextCommand || check?.next_command);
  if (nextCommand.length) return { role: check?.nextAction ? "Next" : "Record", command: nextCommand.join(" ") };
  const commandItems = Array.isArray(packet.commandItems) ? packet.commandItems : [];
  if (evidenceState === "recorded") {
    return { role: "Verify", command: "make release-acceptance-status" };
  }
  if (evidenceState === "stale" || evidenceState === "invalid") {
    const record = commandItems.find((item) => item.role === "Record");
    if (record?.command) return record;
  }
  return commandItems.find((item) => item.role === "Validate") || commandItems[0] || { role: "", command: "" };
}

export function buildSystemEvidencePacket({
  summary = {},
  status = {},
  policyDp = {},
  flowCap = {},
  flowRuntime = {},
  ebpfHost = {},
  conntrack = {},
  tuning = {},
  contentPosture = null,
  inspection = {},
  releaseEvidence = null,
  releaseAcceptanceStatus = null,
  telemetry = null,
  generatedAt = new Date().toISOString(),
} = {}) {
  const releaseItems = Array.isArray(releaseEvidence) && releaseEvidence.length
    ? releaseEvidence
    : releaseEvidenceChecklist({ summary, status, policyDp, flowCap, flowRuntime, ebpfHost, conntrack, tuning, contentPosture, inspection, releaseAcceptanceStatus, telemetry });
  const releaseById = new Map(releaseItems.map((item) => [item.id, item]));
  const releaseCounts = releaseEvidenceCounts(releaseItems);
  const externalGateItems = EXTERNAL_RELEASE_GATE_IDS
    .map((id) => releaseById.get(id))
    .filter(Boolean);
  const externalOpen = externalGateItems
    .filter((item) => normalizeTone(item.cls) !== "ok")
    .map((item) => item.id);
  const telemetryItem = releaseById.get("telemetry-export-proof");
  const rows = [
    releaseItemEvidenceRow(releaseById.get("runtime"), "production-posture", "Production posture"),
    managementEvidenceRow(status),
    releaseItemEvidenceRow(releaseById.get("dataplane"), "dataplane-proof", "Dataplane proof"),
    releaseItemEvidenceRow(releaseById.get("inspection"), "inspection-posture", "Inspection posture"),
    telemetryItem ? releaseItemEvidenceRow(telemetryItem, "telemetry-export-proof", "Telemetry export proof") : null,
    releaseItemEvidenceRow(releaseById.get("host"), "host-state", "Host tuning and state table"),
    releaseItemEvidenceRow(releaseById.get("content"), "content-packages", "Content package posture"),
    releaseItemEvidenceRow(releaseById.get("ha-readiness"), "ha-readiness", "Active/passive HA readiness"),
    releaseItemEvidenceRow(releaseById.get("ha-readiness-recovery"), "ha-readiness-recovery", "HA readiness recovery release evidence"),
    ebpfEvidenceRow(ebpfHost),
    engineEvidenceRow(status.engines),
    capabilityEvidenceRow(status.capabilities),
    externalReleaseGateEvidenceRow(externalGateItems, externalOpen, releaseCounts),
  ].filter(Boolean);
  const state = externalOpen.length || releaseCounts.blocked ? "blocked" : releaseCounts.review ? "review" : "clear";
  const packet = {
    schema: "phragma.system.evidence.v1",
    generatedAt,
    state,
    cls: state === "blocked" ? "bad" : state === "review" ? "warn" : "ok",
    title: state === "clear" ? "System evidence clear" : state === "review" ? "System evidence needs review" : "System evidence blocked",
    detail: externalOpen.length
      ? `${externalOpen.length} external release gate(s) still require recorded field evidence.`
      : state === "blocked"
        ? `${releaseCounts.blocked} release evidence gate(s) are blocked.`
        : state === "review"
          ? `${releaseCounts.review} release evidence gate(s) require review.`
          : "Loaded readiness evidence does not report blocked release gates.",
    releaseEvidenceCounts: releaseCounts,
    externalGateIds: externalGateItems.map((item) => item.id),
    unresolvedExternalGateIds: externalOpen,
    rows,
  };
  packet.text = systemEvidencePacketReport(packet);
  return packet;
}

export function buildEbpfDrillEvidencePacket({
  ebpfHost = {},
  releaseItem = null,
  generatedAt = new Date().toISOString(),
} = {}) {
  const probes = Array.isArray(ebpfHost.probes) ? ebpfHost.probes : [];
  const attachProbes = Array.isArray(ebpfHost.attachProbes) ? ebpfHost.attachProbes : [];
  const attachments = Array.isArray(ebpfHost.attachments) ? ebpfHost.attachments : [];
  const artifacts = Array.isArray(ebpfHost.artifacts) ? ebpfHost.artifacts : [];
  const blockers = uniqueStrings([
    ...asStringArray(ebpfHost.blockers),
    ...probes.filter((probe) => probe?.state && probe.state !== "ready").map((probe) => probe.detail || probe.name || probe.key),
    ...attachProbes.filter((probe) => probe?.state && probe.state !== "ready").map((probe) => probe.detail || probe.name || probe.key),
  ]);
  const packet = releaseItem?.packet || EBPF_OL9_FIELD_PACKET;
  const hostState = ebpfHost.state || "unknown";
  const attachState = ebpfHost.attachState || "unknown";
  const rendererState = ebpfHost.rendererState || "unknown";
  const rows = [
    evidenceRow({
      id: "ebpf-host-prerequisites",
      cls: capabilityTone(hostState),
      label: hostState,
      title: "Host prerequisites",
      detail: ebpfHost.detail || "Linux eBPF XDP/tc host readiness is not available.",
      meta: probes.length ? `${probes.filter((probe) => probe?.state === "ready").length}/${probes.length} host probe(s) ready` : "host probes unavailable",
    }),
    evidenceRow({
      id: "ebpf-attach-drill",
      cls: capabilityTone(attachState),
      label: attachState,
      title: "Attach drill",
      detail: ebpfHost.attachDetail || "No XDP/tc attach drill status has been reported by the system API.",
      meta: attachProbes.length ? `${attachProbes.filter((probe) => probe?.state === "ready").length}/${attachProbes.length} attach probe(s) ready` : "attach probes unavailable",
    }),
    evidenceRow({
      id: "ebpf-renderer-scaffold",
      cls: capabilityTone(rendererState),
      label: rendererState,
      title: "Renderer scaffold",
      detail: ebpfHost.rendererDetail || "The eBPF renderer remains a plan/scaffold while nftables renders the active dataplane.",
      meta: "active_dataplane=nftables/conntrack",
    }),
    evidenceRow({
      id: "ebpf-artifacts",
      cls: artifacts.length ? "ok" : "warn",
      label: artifacts.length ? `${artifacts.length} artifact(s)` : "missing",
      title: "Indexed field artifacts",
      detail: artifacts.length ? "System status returned indexed eBPF field-evidence artifacts." : "No indexed eBPF field-evidence artifacts were returned.",
      meta: artifacts.slice(0, 4).map((artifact) => artifact.name || artifact.path || "artifact").join(", ") || packet.evidencePath,
    }),
    evidenceRow({
      id: "ebpf-attachments",
      cls: attachments.length ? "ok" : "info",
      label: attachments.length ? `${attachments.length} observed` : "none",
      title: "Live attachment inventory",
      detail: attachments.length ? "Status returned live eBPF attachment inventory for review." : "No live attachment inventory is currently reported.",
      meta: "the drill must detach probes and preserve nftables/conntrack",
    }),
    evidenceRow({
      id: "ebpf-release-gate",
      cls: releaseItem ? normalizeTone(releaseItem.cls) : "bad",
      label: releaseItem?.label || "field required",
      title: "Release gate",
      detail: releaseItem?.detail || "OL9/OCI Linux-root XDP/tc attach, status API, renderer scaffold, and cleanup evidence must be captured and validated.",
      meta: releaseItem?.meta || packet.artifactPath,
    }),
  ];
  const state = blockers.length || normalizeTone(releaseItem?.cls) === "bad"
    ? "blocked"
    : normalizeTone(releaseItem?.cls) === "ok" && ["ready", "active"].includes(hostState) && ["ready", "active"].includes(attachState)
      ? "ready"
      : "review";
  const out = {
    schema: "phragma.ebpf.drill-evidence.v1",
    generatedAt,
    state,
    cls: state === "blocked" ? "bad" : state === "ready" ? "ok" : "warn",
    title: state === "ready" ? "eBPF drill evidence ready" : state === "blocked" ? "eBPF drill evidence blocked" : "eBPF drill evidence needs review",
    detail: blockers.length
      ? `${blockers.length} eBPF blocker(s) remain before the OL9 field bundle can be accepted.`
      : "eBPF drill evidence is summarized from already-loaded Readiness status and release-gate metadata.",
    activeDataplane: "nftables/conntrack",
    supportedHooks: asStringArray(ebpfHost.supportedHooks),
    evidenceScope: ebpfHost.evidenceScope || "",
    evidenceCollectedAt: ebpfHost.evidenceCollectedAt || "",
    hostState,
    attachState,
    rendererState,
    blockers,
    probeCount: probes.length,
    attachProbeCount: attachProbes.length,
    attachmentCount: attachments.length,
    artifactCount: artifacts.length,
    releaseCheck: packet.check,
    evidencePath: packet.evidencePath,
    artifactPath: packet.artifactPath,
    commands: releaseEvidencePacketCommands(packet),
    rows,
  };
  out.text = ebpfDrillEvidencePacketReport(out);
  return out;
}

export function ebpfDrillEvidencePacketReport(packet = {}) {
  const lines = [
    "OpenNGFW eBPF OL9 attach-drill evidence packet",
    `schema=${oneLine(packet.schema || "phragma.ebpf.drill-evidence.v1")}`,
    `generated_at=${oneLine(packet.generatedAt || new Date().toISOString())}`,
    `state=${oneLine(packet.state || "unknown")}`,
    `active_dataplane=${oneLine(packet.activeDataplane || "nftables/conntrack")}`,
    `supported_hooks=${asStringArray(packet.supportedHooks).join(", ") || "xdp, tc"}`,
    `host_state=${oneLine(packet.hostState || "unknown")}`,
    `attach_state=${oneLine(packet.attachState || "unknown")}`,
    `renderer_state=${oneLine(packet.rendererState || "unknown")}`,
    `evidence_scope=${oneLine(packet.evidenceScope || "not reported")}`,
    `evidence_collected_at=${oneLine(packet.evidenceCollectedAt || "not reported")}`,
    `release_check=${oneLine(packet.releaseCheck || "ebpf-ol9-field-evidence")}`,
    `evidence_path=${oneLine(packet.evidencePath || EBPF_OL9_FIELD_EVIDENCE_DIR)}`,
    `artifact_path=${oneLine(packet.artifactPath || `${RELEASE_EVIDENCE_DIR}/ebpf-ol9-field-evidence.txt`)}`,
    `blockers=${asStringArray(packet.blockers).map(oneLine).join("; ") || "none"}`,
    `counts=host_probes:${Number(packet.probeCount || 0)} attach_probes:${Number(packet.attachProbeCount || 0)} attachments:${Number(packet.attachmentCount || 0)} artifacts:${Number(packet.artifactCount || 0)}`,
    "source=browser Readiness view; already-loaded /v1/system/status dataplane.ebpf plus release gate metadata",
    "note=This packet does not certify active eBPF dataplane cutover; nftables/conntrack remains the active dataplane.",
    "",
  ];
  for (const command of asStringArray(packet.commands)) {
    lines.push(`command: ${oneLine(command)}`);
  }
  if (packet.commands?.length) lines.push("");
  for (const row of Array.isArray(packet.rows) ? packet.rows : []) {
    lines.push(`- [${evidenceRowState(row).toUpperCase()}] ${oneLine(row.id)} - ${oneLine(row.title)}`);
    if (row.label) lines.push(`  label: ${oneLine(row.label)}`);
    if (row.detail) lines.push(`  detail: ${oneLine(row.detail)}`);
    if (row.meta) lines.push(`  meta: ${oneLine(row.meta)}`);
  }
  return lines.join("\n").trimEnd() + "\n";
}

export function systemEvidencePacketReport(packet = {}) {
  const counts = packet.releaseEvidenceCounts || { blocked: 0, review: 0, clear: 0, info: 0 };
  const unresolved = asStringArray(packet.unresolvedExternalGateIds);
  const lines = [
    "OpenNGFW system evidence packet",
    `schema=${oneLine(packet.schema || "phragma.system.evidence.v1")}`,
    `generated_at=${oneLine(packet.generatedAt || new Date().toISOString())}`,
    `state=${oneLine(packet.state || "unknown")}`,
    `release_counts=blocked:${Number(counts.blocked || 0)} review:${Number(counts.review || 0)} clear:${Number(counts.clear || 0)} info:${Number(counts.info || 0)}`,
    `external_gates=${asStringArray(packet.externalGateIds).join(", ") || "none"}`,
    `unresolved_external_gates=${unresolved.join(", ") || "none"}`,
    "source=browser Readiness view; already-loaded API state only",
    "note=Local system evidence does not close external field gates unless matching release evidence artifacts are recorded.",
    "",
  ];

  for (const row of Array.isArray(packet.rows) ? packet.rows : []) {
    lines.push(`- [${evidenceRowState(row).toUpperCase()}] ${oneLine(row.id)} - ${oneLine(row.title)}`);
    if (row.label) lines.push(`  label: ${oneLine(row.label)}`);
    if (row.detail) lines.push(`  detail: ${oneLine(row.detail)}`);
    if (row.meta) lines.push(`  meta: ${oneLine(row.meta)}`);
  }

  return lines.join("\n").trimEnd() + "\n";
}

function evidencePacket({ check, evidencePath = "", artifactPath = "", summary = "", makeTargets = [], diagnoseCommand = "", collectCommand = "", validateCommand = "", recordCommand = "", noClaimsCommand = "", reference = "" } = {}) {
  const commandItems = [
    diagnoseCommand ? { role: "Diagnose", command: diagnoseCommand } : null,
    collectCommand ? { role: "Collect", command: collectCommand } : null,
    validateCommand ? { role: "Validate", command: validateCommand } : null,
    recordCommand ? { role: "Record", command: recordCommand } : null,
    noClaimsCommand ? { role: "No claims", command: noClaimsCommand } : null,
  ].filter(Boolean);
  const commands = commandItems.map((item) => item.command);
  return {
    check,
    evidencePath,
    artifactPath,
    summary,
    makeTargets,
    diagnoseCommand,
    collectCommand,
    validateCommand,
    recordCommand,
    noClaimsCommand,
    commandItems,
    commands,
    reference,
  };
}

function releaseEvidencePacketCatalogItem(id, title, packet, { endpoints = [] } = {}) {
  return Object.freeze({
    id,
    title,
    endpoints: Object.freeze([...endpoints]),
    packet: Object.freeze({
      ...packet,
      makeTargets: Object.freeze([...(packet.makeTargets || [])]),
      commandItems: Object.freeze([...(packet.commandItems || [])]),
      commands: Object.freeze([...(packet.commands || [])]),
    }),
  });
}

function releaseItemEvidenceRow(item = {}, id, title) {
  return evidenceRow({
    id: id || item.id || "release-evidence",
    cls: normalizeTone(item.cls),
    label: item.label || releaseEvidenceReportState(item),
    title: title || item.title || "Release evidence",
    detail: item.detail || "Release evidence detail is unavailable.",
    meta: item.meta || item.href || "",
  });
}

function managementEvidenceRow(status = {}) {
  const runtime = status.runtime || {};
  const management = status.management || {};
  const observed = ["tlsEnabled", "authEnabled", "dryRun"].some((key) => Object.prototype.hasOwnProperty.call(runtime, key)) ||
    ["rateLimitEnabled", "httpMaxBodyBytes", "grpcMaxRecvBytes"].some((key) => Object.prototype.hasOwnProperty.call(management, key));
  if (!observed) {
    return evidenceRow({
      id: "management-plane",
      cls: "info",
      label: "unknown",
      title: "Management-plane guardrails",
      detail: "Management guardrail evidence was not returned in system status.",
      meta: "TLS/auth/rate-limit posture unavailable",
    });
  }

  const blockers = [];
  if (runtime.dryRun === true) blockers.push("dry-run mode");
  if (runtime.tlsEnabled === false) blockers.push("TLS disabled");
  if (runtime.authEnabled === false) blockers.push("auth disabled");
  const warnings = [];
  if (management.rateLimitEnabled === false) warnings.push("API rate limit disabled");
  if (management.httpMaxBodyBytes === 0) warnings.push("REST body cap disabled");
  if (management.grpcMaxRecvBytes === 0 || management.grpcMaxSendBytes === 0) warnings.push("gRPC message cap disabled");
  const cls = blockers.length ? "bad" : warnings.length ? "warn" : "ok";
  const rate = management.rateLimitEnabled
    ? `${management.rateLimitRequestsPerMinute || 0}/min burst ${management.rateLimitBurst || 0}`
    : "disabled";
  return evidenceRow({
    id: "management-plane",
    cls,
    label: cls === "bad" ? "blocked" : cls === "warn" ? "review" : "guarded",
    title: "Management-plane guardrails",
    detail: blockers.length
      ? blockers.join(", ")
      : warnings.length
        ? warnings.join(", ")
        : "TLS, auth, API rate limiting, and API size guardrails do not report blockers.",
    meta: `tls:${runtime.tlsEnabled === true ? "enabled" : runtime.tlsEnabled === false ? "disabled" : "unknown"} auth:${runtime.authEnabled === true ? "enabled" : runtime.authEnabled === false ? "disabled" : "unknown"} rate:${rate}`,
  });
}

function ebpfEvidenceRow(ebpfHost = {}) {
  const state = ebpfHost.state || "unknown";
  const attach = ebpfHost.attachState || "unknown";
  const renderer = ebpfHost.rendererState || "unknown";
  const hooks = asStringArray(ebpfHost.supportedHooks).join(",") || "unknown";
  const blockers = asStringArray(ebpfHost.blockers);
  const degradedNames = [
    ...(Array.isArray(ebpfHost.degraded) ? ebpfHost.degraded : []).map((probe) => typeof probe === "string" ? probe : probe?.name).filter(Boolean),
    ...(Array.isArray(ebpfHost.attachDegraded) ? ebpfHost.attachDegraded : []).map((probe) => typeof probe === "string" ? probe : probe?.name).filter(Boolean),
  ];
  const cls = state === "ready" || state === "active"
    ? attach === "ready" || attach === "active" || attach === "unknown"
      ? "ok"
      : "warn"
    : state === "unknown"
      ? "info"
      : "warn";
  return evidenceRow({
    id: "xdp-tc-readiness",
    cls,
    label: `host:${state} attach:${attach}`,
    title: "XDP/tc readiness",
    detail: blockers.length
      ? blockers.join(", ")
      : degradedNames.length
        ? degradedNames.join(", ")
        : ebpfHost.detail || "eBPF XDP/tc host and attach readiness evidence is available.",
    meta: `renderer:${renderer} hooks:${hooks}`,
  });
}

function engineEvidenceRow(engines = []) {
  const items = Array.isArray(engines) ? engines : [];
  if (!items.length) {
    return evidenceRow({
      id: "engine-prerequisites",
      cls: "info",
      label: "unknown",
      title: "Engine prerequisites",
      detail: "Engine readiness was not returned in system status.",
      meta: "0 engines reported",
    });
  }
  const blocked = items.filter((engine) => engine.state === "missing-prerequisites" || engine.state === "failed");
  const ready = items.filter((engine) => engine.state === "ready" || engine.state === "active");
  return evidenceRow({
    id: "engine-prerequisites",
    cls: blocked.length ? "bad" : "ok",
    label: blocked.length ? "blocked" : "ready",
    title: "Engine prerequisites",
    detail: blocked.length
      ? blocked.slice(0, 5).map((engine) => `${engine.name || "engine"}:${engine.state}`).join(", ")
      : `${ready.length}/${items.length} engine(s) ready or active.`,
    meta: `${ready.length}/${items.length} ready`,
  });
}

function capabilityEvidenceRow(capabilities = []) {
  const items = Array.isArray(capabilities) ? capabilities : [];
  if (!items.length) {
    return evidenceRow({
      id: "capability-posture",
      cls: "info",
      label: "unknown",
      title: "Capability posture",
      detail: "Runtime capabilities were not returned in system status.",
      meta: "0 capabilities reported",
    });
  }
  const degraded = items.filter((capability) => ["degraded", "missing-prerequisites", "failed"].includes(capability.state));
  const simulated = items.filter((capability) => capability.state === "simulation");
  return evidenceRow({
    id: "capability-posture",
    cls: degraded.length ? "warn" : "ok",
    label: degraded.length ? "review" : "ready",
    title: "Capability posture",
    detail: degraded.length
      ? degraded.slice(0, 5).map((capability) => `${capability.name || "capability"}:${capability.state}`).join(", ")
      : simulated.length
        ? `${simulated.length} simulated capability state(s) require review before broad release claims.`
        : `${items.length} capability record(s) reported without degraded state.`,
    meta: `total:${items.length} degraded:${degraded.length} simulated:${simulated.length}`,
  });
}

function externalReleaseGateEvidenceRow(externalGateItems = [], unresolvedIds = [], releaseCounts = {}) {
  const ids = externalGateItems.map((item) => item.id).filter(Boolean);
  return evidenceRow({
    id: "external-release-gates",
    cls: unresolvedIds.length ? "bad" : "ok",
    label: unresolvedIds.length ? "field required" : "recorded",
    title: "External release gates",
    detail: unresolvedIds.length
      ? `${unresolvedIds.join(", ")} remain required; local system evidence cannot close them.`
      : "External release gates are recorded in the loaded release evidence model.",
    meta: `release evidence counts blocked:${Number(releaseCounts.blocked || 0)} review:${Number(releaseCounts.review || 0)} clear:${Number(releaseCounts.clear || 0)} info:${Number(releaseCounts.info || 0)} gates:${ids.join(", ") || "none"}`,
  });
}

function evidenceRow({ id, cls = "info", label = "", title, detail = "", meta = "" } = {}) {
  return {
    id: oneLine(id || "evidence"),
    cls: normalizeTone(cls),
    label: oneLine(label || evidenceRowState({ cls })),
    title: oneLine(title || "Evidence"),
    detail: oneLine(detail),
    meta: oneLine(meta),
  };
}

function evidenceRowState(row = {}) {
  const cls = normalizeTone(row.cls);
  if (cls === "bad") return "blocked";
  if (cls === "warn") return "review";
  if (cls === "ok") return "clear";
  return "info";
}

function releaseEvidencePacketCommands(packet = {}) {
  if (Array.isArray(packet.commands) && packet.commands.length) return packet.commands.filter(Boolean);
  return [packet.validateCommand, packet.recordCommand].filter(Boolean);
}

function asStringArray(value) {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean);
  if (typeof value === "string" && value.trim()) return [value.trim()];
  return [];
}

function uniqueStrings(values = []) {
  const seen = new Set();
  const out = [];
  for (const value of values) {
    const text = String(value || "").trim();
    if (!text || seen.has(text)) continue;
    seen.add(text);
    out.push(text);
  }
  return out;
}

function releaseEvidenceReportState(item = {}) {
  const cls = normalizeTone(item.cls);
  if (String(item.label || "").toLowerCase().replace(/[_-]+/g, " ") === "review needed") return "review needed";
  if (cls === "bad") return "blocked";
  if (cls === "warn") return "review";
  if (cls === "ok") return "clear";
  return "info";
}

function severityRank(severity) {
  if (severity === "critical") return 0;
  if (severity === "warning") return 1;
  return 2;
}

function levelRank(level) {
  if (level === "high") return 0;
  if (level === "medium") return 1;
  return 2;
}

function normalizeTone(cls) {
  if (cls === "bad" || cls === "warn" || cls === "ok" || cls === "info") return cls;
  return "info";
}

function capabilityTone(state = "") {
  const value = String(state || "").toLowerCase();
  if (value === "ready" || value === "active") return "ok";
  if (value === "degraded" || value === "failed" || value === "missing-prerequisites") return "bad";
  if (value === "warning" || value === "planned" || value === "simulation") return "warn";
  return "info";
}

function oneLine(value) {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}

function normalizeInspectionTone(inspection = {}) {
  const state = inspection.state || "";
  if (state === "failed-open" || state === "failed-closed") return "bad";
  if (inspection.cls === "bad" || inspection.cls === "warn" || inspection.cls === "ok") return inspection.cls;
  if (state === "ready" || state === "disabled") return "ok";
  if (state === "degraded") return "warn";
  return "info";
}
