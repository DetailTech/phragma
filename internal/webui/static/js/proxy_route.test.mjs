import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { normalizeProxyRoute, proxyHash } from "./proxy_route.js";
import { proxyPreviewInvestigationPacket, proxyRuntimeReadinessInvestigationPacket } from "./views/proxy.js";

const proxyViewSource = readFileSync(new URL("./views/proxy.js", import.meta.url), "utf8");

assert.deepEqual(normalizeProxyRoute({ tab: "waf", service: "admin-api", waf: "corp-waf" }), {
  tab: "waf",
  service: "admin-api",
  waf: "corp-waf",
  drawer: "",
});
assert.deepEqual(normalizeProxyRoute({ tab: "bad", drawer: "bytes" }), { tab: "services", service: "", waf: "", drawer: "" });
assert.deepEqual(normalizeProxyRoute({ drawer: "plan" }), { tab: "services", service: "", waf: "", drawer: "plan" });
assert.deepEqual(normalizeProxyRoute({ drawer: "policy" }), { tab: "services", service: "", waf: "", drawer: "policy" });
assert.equal(proxyHash({ tab: "waf", waf: "corp-waf" }), "#/proxy?tab=waf&waf=corp-waf");
assert.equal(proxyHash({ drawer: "plan" }), "#/proxy?drawer=plan");
assert.equal(proxyHash({ drawer: "policy" }), "#/proxy?drawer=policy");

assert.match(proxyViewSource, /dataset: \{ proxyArtifactPreview: "review-only" \}/);
assert.match(proxyViewSource, /Preview is not runtime evidence/);
assert.match(proxyViewSource, /dataset: \{ proxyArtifactAction: "copy-snippet" \}/);
assert.match(proxyViewSource, /dataset: \{ proxyArtifactAction: "download-snippet" \}/);
assert.match(proxyViewSource, /function safePreviewSnippetText\(preview = \{\}\)/);
assert.match(proxyViewSource, /copyText\(safePreviewSnippetText\(preview\)\)/);
assert.match(proxyViewSource, /downloadText\(preview\.filename \|\| "proxy-artifact-preview\.txt", safePreviewSnippetText\(preview\), contentTypeForPreview\(preview\)\)/);
assert.match(proxyViewSource, /appendInvestigationPacketToActiveServerCase/);
assert.match(proxyViewSource, /dataset: \{ proxyArtifactAction: "pin-packet" \}/);
assert.match(proxyViewSource, /api\.addInvestigationCaseEvidence\(id, evidence\)/);
assert.match(proxyViewSource, /activeInvestigationServerCaseHref\(\)/);
assert.match(proxyViewSource, /schemaVersion: "openngfw\.proxy\.artifact-preview\.v1"/);
assert.match(proxyViewSource, /not live listener, WAF enforcement, daemon launch, signing, or traffic cutover evidence/);
assert.match(proxyViewSource, /dataset: \{ proxyAction: "runtime-readiness" \}/);
assert.match(proxyViewSource, /dataset: \{ proxyRuntimeReadiness: "loading" \}/);
assert.match(proxyViewSource, /does not prove active listener traffic, WAF enforcement, release evidence, or Envoy\/Coraza daemon launch/);
assert.match(proxyViewSource, /dataset: \{ proxyRuntimeAction: "pin-packet" \}/);
assert.match(proxyViewSource, /dataset: \{ proxyRuntimeAction: "copy-packet" \}/);
assert.match(proxyViewSource, /dataset: \{ proxyRuntimeAction: "export-packet" \}/);
assert.match(proxyViewSource, /schemaVersion: model\.schemaVersion \|\| "openngfw\.proxy\.runtime-readiness\.v1"/);
assert.match(proxyViewSource, /Active runtime rollout handoff/);
assert.match(proxyViewSource, /dataset: \{ proxyActiveRolloutGate: item\.id \}/);
assert.match(proxyViewSource, /function proxyActiveRolloutChecklist\(model = \{\}\)/);
assert.match(proxyViewSource, /function renderRuntimeArtifactManifest\(model = \{\}\)/);
assert.match(proxyViewSource, /dataset: \{ proxyRuntimeArtifactManifest: manifest\.proxyArtifactPresent \? "proxy-present" : "proxy-missing" \}/);
assert.match(proxyViewSource, /Artifact manifest and hash review/);
assert.match(proxyViewSource, /function renderFunctionalRuntimeProofArtifacts\(model = \{\}\)/);
assert.match(proxyViewSource, /dataset: \{ proxyFunctionalRuntimeProof: "planned-not-executed" \}/);
assert.match(proxyViewSource, /Functional runtime proof artifacts/);
assert.match(proxyViewSource, /function proxyFunctionalRuntimeProofArtifacts\(model = \{\}\)/);
assert.match(proxyViewSource, /function proxyRuntimeArtifactManifest\(validation = \{\}\)/);
assert.match(proxyViewSource, /function normalizedArtifactSha\(artifact = \{\}\)/);
assert.match(proxyViewSource, /artifactManifest: safeRuntimePacketObject\(model\.artifactManifest \|\| \{ artifacts: \[\] \}\)/);
assert.match(proxyViewSource, /functionalProofArtifacts,/);
assert.match(proxyViewSource, /Active daemon boundary/);
assert.match(proxyViewSource, /listener-health/);
assert.match(proxyViewSource, /envoy-coraza-launch/);
assert.match(proxyViewSource, /rollback-controls/);
assert.match(proxyViewSource, /traffic-cutover/);
assert.match(proxyViewSource, /hardening-boundary/);
assert.match(proxyViewSource, /function safeRuntimePacketText\(text = "", limits = \{\}\)/);
assert.match(proxyViewSource, /packetBounds: \{ maxStringChars: 1600, maxTextLines: 40, maxBlockers: 20, maxCommands: 20, maxHandoffLinks: 12, functionalProofArtifacts: 4 \}/);
assert.match(proxyViewSource, /dataset: \{ proxyAction: "policy-coupling" \}/);
assert.match(proxyViewSource, /Traffic policy coupling/);
assert.match(proxyViewSource, /dataset: \{ proxyPolicyCoupling: model\.schemaVersion \}/);
assert.match(proxyViewSource, /schemaVersion: model\.schemaVersion \|\| "openngfw\.proxy\.policy-coupling\.v1"/);
assert.match(proxyViewSource, /candidate-safe review of planned L7 intent against rules, routes, App-ID, and inspection context/);
assert.match(proxyViewSource, /function clearPolicyDrawerRoute\(\)/);
assert.match(proxyViewSource, /dataset: \{ proxyPolicyAction: "copy-packet" \}/);
assert.match(proxyViewSource, /no active listener, traffic cutover, TLS key custody, packet inspection, firewall mutation, route mutation, or WAF enforcement proof/);

const proxyPacket = proxyPreviewInvestigationPacket({
  valid: true,
  status: "Proxy plan validated",
  proxyArtifactPresent: true,
  artifactCount: 2,
  totalBytes: 2048,
  previews: [{
    id: "envoy",
    label: "Envoy listener",
    engine: "envoy",
    source: "validation-render",
    filename: "envoy.yaml",
    language: "yaml",
    redacted: true,
    truncated: true,
    maxChars: 2000,
    maxLines: 40,
    totalChars: 9000,
    totalLines: 120,
    text: "listener: [redacted]",
  }],
  hardeningNotes: ["prove runtime listener separately"],
}, { route: "#/proxy?drawer=plan" });

assert.equal(proxyPacket.schemaVersion, "phragma.investigation.handoff.v1");
assert.equal(proxyPacket.kind, "proxy-waf-preview");
assert.equal(proxyPacket.source.route, "#/proxy?drawer=plan");
assert.equal(proxyPacket.summary.artifactExposure, "bounded redacted snippets");
assert.match(proxyPacket.evidence.join("\n"), /workflow_boundary=no active listener/);
assert.equal(proxyPacket.artifacts.proxyPreview.schemaVersion, "openngfw.proxy.artifact-preview.v1");
assert.equal(proxyPacket.artifacts.proxyPreview.previews[0].text, "listener: [redacted]");

const unsafeProxyPacket = proxyPreviewInvestigationPacket({
  valid: true,
  status: "Proxy plan validated",
  proxyArtifactPresent: true,
  artifactCount: 1,
  totalBytes: 50000,
  previews: [{
    id: "unsafe",
    label: "Unsafe preview",
    engine: "envoy",
    source: "test",
    filename: "envoy.yaml",
    language: "yaml",
    maxChars: 120,
    maxLines: 3,
    text: [
      "authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secret.signature",
      "tls_private_key: /etc/phragma/proxy/key.pem",
      "client_secret=hunter2",
      "extra-line-should-truncate",
    ].join("\n"),
  }],
}, { route: "#/proxy?drawer=plan" });
const unsafeText = unsafeProxyPacket.artifacts.proxyPreview.previews[0].text;
assert.equal(unsafeProxyPacket.artifacts.proxyPreview.previews[0].redacted, true);
assert.equal(unsafeProxyPacket.artifacts.proxyPreview.previews[0].bounds.maxChars, 120);
assert.equal(unsafeText.includes("hunter2"), false);
assert.equal(unsafeText.includes("/etc/phragma/proxy/key.pem"), false);
assert.equal(unsafeText.includes("eyJhbGci"), false);

const runtimePacket = proxyRuntimeReadinessInvestigationPacket({
  schemaVersion: "openngfw.proxy.runtime-readiness.v1",
  readiness: "review",
  label: "review required",
  boundary: "Runtime-readiness review only; does not prove active listener traffic, WAF enforcement, daemon launch, TLS key custody, backend mTLS handshake, HA listener failover, signing custody, or traffic cutover.",
  candidateRevision: "sha256:candidate",
  runningVersion: 9,
  candidateDirty: true,
  proxyChanged: true,
  candidateSummary: { virtualServices: 1, wafPolicies: 1 },
  runningSummary: { virtualServices: 0, wafPolicies: 0 },
  validation: { valid: true, proxyArtifactPresent: true, artifactCount: 1, totalBytes: 440 },
  runtime: { observed: true, state: "ready", proofBoundary: "Context only; not accepted here as active listener traffic proof or daemon launch evidence.", token: "secret-runtime-token" },
  artifactManifest: {
    source: "candidate validation render plan",
    artifactCount: 2,
    totalBytes: 880,
    proxyArtifactPresent: true,
    hashBoundary: "SHA-256 or digest values shown here are validation metadata only; release promotion still requires durable accepted-source evidence.",
    artifacts: [
      { name: "proxy.yaml", engine: "proxy", sizeBytes: 440, sha256: "sha256:" + "b".repeat(64), hashPresent: true, proxy: true },
      { name: "nftables", engine: "nftables", sizeBytes: 440, sha256: "", hashPresent: false, proxy: false },
    ],
  },
  blockers: [{ id: "hardening", title: "Production hardening required", detail: "Active Envoy/Coraza traffic rollout remains separate. client_secret=hunter2" }],
  handoffLinks: [{ label: "Readiness", href: "#/readiness" }],
  reviewCommands: ["ngfwctl system status --json"],
}, { route: "#/proxy" });

assert.equal(runtimePacket.schemaVersion, "phragma.investigation.handoff.v1");
assert.equal(runtimePacket.kind, "proxy-waf-runtime-readiness");
assert.equal(runtimePacket.source.route, "#/proxy");
assert.equal(runtimePacket.summary.readiness, "review");
assert.equal(runtimePacket.summary.candidateRevision, "sha256:candidate");
assert.match(runtimePacket.evidence.join("\n"), /workflow_boundary=no active listener traffic proof/);
assert.match(runtimePacket.evidence.join("\n"), /functional_proof_artifacts=4/);
assert.equal(runtimePacket.artifacts.runtimeReadiness.schemaVersion, "openngfw.proxy.runtime-readiness.v1");
assert.match(runtimePacket.artifacts.runtimeReadiness.redactionBoundary, /No secrets/);
assert.match(runtimePacket.artifacts.runtimeReadiness.redactionBoundary, /traffic samples/);
assert.match(runtimePacket.artifacts.runtimeReadiness.workflow, /does not prove active listener traffic/);
assert.equal(runtimePacket.summary.functionalProofArtifactCount, 4);
assert.deepEqual(runtimePacket.artifacts.runtimeReadiness.functionalProofArtifacts.map((item) => item.id), [
  "proxy-daemon-plan",
  "proxy-listener-plan",
  "proxy-cutover-plan",
  "proxy-rollback-plan",
]);
assert.deepEqual(runtimePacket.artifacts.runtimeReadiness.functionalProofArtifacts.map((item) => item.status), [
  "planned-not-executed",
  "planned-not-executed",
  "planned-not-executed",
  "planned-not-executed",
]);
assert.match(runtimePacket.artifacts.runtimeReadiness.functionalProofArtifacts[0].evidence.join("\n"), /proxyArtifacts=1/);
assert.match(runtimePacket.artifacts.runtimeReadiness.functionalProofArtifacts[1].boundary, /HA listener proof are not claimed/);
assert.match(runtimePacket.artifacts.runtimeReadiness.functionalProofArtifacts[2].boundary, /No production route/);
assert.match(runtimePacket.artifacts.runtimeReadiness.functionalProofArtifacts[3].boundary, /no restore/);
assert.equal(runtimePacket.artifacts.functionalProofArtifacts.length, 4);
assert.deepEqual(runtimePacket.artifacts.runtimeReadiness.activeRolloutChecklist.map((item) => item.id), [
  "listener-health",
  "envoy-coraza-launch",
  "rollback-controls",
  "traffic-cutover",
  "hardening-boundary",
]);
assert.match(runtimePacket.artifacts.runtimeReadiness.activeRolloutChecklist[0].requiredProof, /listener bind/);
assert.match(runtimePacket.artifacts.runtimeReadiness.activeRolloutChecklist[0].requiredProof, /health endpoint response/);
assert.match(runtimePacket.artifacts.runtimeReadiness.activeRolloutChecklist[0].boundary, /active daemon evidence/);
assert.match(runtimePacket.artifacts.runtimeReadiness.activeRolloutChecklist[1].requiredProof, /Coraza ruleset digest/);
assert.match(runtimePacket.artifacts.runtimeReadiness.activeRolloutChecklist[2].requiredProof, /restore command/);
assert.match(runtimePacket.artifacts.runtimeReadiness.activeRolloutChecklist[2].requiredProof, /artifact manifest hash set/);
assert.match(runtimePacket.artifacts.runtimeReadiness.activeRolloutChecklist[3].boundary, /No live packet data/);
assert.match(runtimePacket.artifacts.runtimeReadiness.activeRolloutChecklist[3].requiredProof, /cutover timestamp/);
assert.match(runtimePacket.artifacts.runtimeReadiness.activeRolloutChecklist[4].requiredProof, /TLS key custody/);
assert.match(runtimePacket.artifacts.runtimeReadiness.activeRolloutChecklist[4].requiredProof, /active daemon lifecycle proof/);
assert.equal(runtimePacket.artifacts.runtimeReadiness.artifactManifest.proxyArtifactPresent, true);
assert.equal(runtimePacket.artifacts.runtimeReadiness.artifactManifest.artifacts[0].sha256, "sha256:" + "b".repeat(64));
assert.equal(runtimePacket.artifacts.runtimeReadiness.artifactManifest.artifacts[1].hashPresent, false);
assert.equal(runtimePacket.artifacts.runtimeReadiness.packetBounds.maxBlockers, 20);
assert.equal(runtimePacket.artifacts.runtimeReadiness.packetBounds.functionalProofArtifacts, 4);
assert.equal(JSON.stringify(runtimePacket).includes("hunter2"), false);
assert.equal(JSON.stringify(runtimePacket).includes("secret-runtime-token"), false);
assert.match(JSON.stringify(runtimePacket.artifacts.runtimeReadiness), /\[redacted\]/);
