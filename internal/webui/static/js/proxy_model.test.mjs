import assert from "node:assert/strict";

import {
  boundedArtifactSnippet,
  defaultVirtualService,
  defaultWafPolicy,
  proxyArtifactPreviewModel,
  proxyPlanProofModel,
  proxyPolicyCouplingModel,
  proxyRuntimeReadinessModel,
  proxySummary,
  redactProxyArtifactText,
  validateProxy,
  validBackendUrl,
  validPathPrefix,
} from "./proxy_model.js";

const waf = defaultWafPolicy([]);
const service = defaultVirtualService([], [waf]);
const proxy = { wafPolicies: [waf], virtualServices: [service] };

assert.deepEqual(validateProxy(proxy), []);
assert.deepEqual(proxySummary(proxy), {
  virtualServices: 1,
  enabledServices: 1,
  routes: 1,
  backends: 1,
  wafPolicies: 1,
  attachedWafRoutes: 1,
  plannedOnly: true,
});

assert.equal(validPathPrefix("/api/v1"), true);
assert.equal(validPathPrefix("api"), false);
assert.equal(validPathPrefix("/api/../admin"), false);
assert.equal(validPathPrefix("/api with space"), false);

assert.equal(validBackendUrl("https://api.internal"), true);
assert.equal(validBackendUrl("http://api.internal:8080"), true);
assert.equal(validBackendUrl("https://user:pass@api.internal"), false);
assert.equal(validBackendUrl("https://api.internal/path"), true);
assert.equal(validBackendUrl("https://api.internal?x=1"), false);

{
  const policy = {
    services: [{ name: "web", protocol: "PROTOCOL_TCP", ports: [{ start: 443 }] }],
    applications: [{ name: "corp-admin", ports: [{ protocol: "PROTOCOL_TCP", ports: [{ start: 443 }] }] }],
    securityProfiles: [{ name: "web-inspect", tlsInspection: "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED" }],
    rules: [{
      name: "allow-proxy",
      action: "ACTION_ALLOW",
      services: ["web"],
      applications: ["corp-admin"],
      securityProfiles: ["web-inspect"],
    }],
    staticRoutes: [{ destination: "10.20.30.0/24" }],
    proxy: structuredClone(proxy),
  };
  policy.proxy.virtualServices[0].routes[0].backends[0].url = "https://10.20.30.44";
  const coupling = proxyPolicyCouplingModel(policy);
  assert.equal(coupling.schemaVersion, "openngfw.proxy.policy-coupling.v1");
  assert.equal(coupling.summary.enabledServices, 1);
  assert.equal(coupling.summary.warnings, 0);
  assert.deepEqual(coupling.services[0].serviceRules, ["allow-proxy"]);
  assert.deepEqual(coupling.services[0].appRules, ["allow-proxy"]);
  assert.deepEqual(coupling.services[0].inspectionRules, ["allow-proxy"]);
  assert.ok(coupling.findings.some((finding) => finding.dimension === "security-rule" && /reviewable against allow rule/.test(finding.message)));
  assert.equal(coupling.reviewLinks.some((link) => link.href === "#/rules"), true);
}

{
  const uncoupled = {
    services: [{ name: "web", protocol: "PROTOCOL_TCP", ports: [{ start: 80 }] }],
    rules: [{ name: "allow-web", action: "ACTION_ALLOW", services: ["web"] }],
    staticRoutes: [],
    proxy: structuredClone(proxy),
  };
  uncoupled.proxy.virtualServices[0].routes[0].wafPolicy = "";
  uncoupled.proxy.virtualServices[0].routes[0].backends[0].url = "https://10.99.0.10";
  const coupling = proxyPolicyCouplingModel(uncoupled);
  const messages = coupling.findings.map((finding) => finding.message).join("\n");
  assert.equal(coupling.summary.warnings >= 3, true);
  assert.match(messages, /no enabled allow rule/);
  assert.match(messages, /not tied to an App-ID port hint/);
  assert.match(messages, /No matching allow rule carries an inline inspection/);
  assert.match(messages, /no WAF policy attached/);
  assert.match(messages, /not covered by configured static routes/);
}

{
  const broken = structuredClone(proxy);
  broken.wafPolicies[0].redactRequestBody = false;
  broken.wafPolicies[0].ruleSets[0].sha256 = "bad";
  broken.virtualServices[0].hostnames = ["Admin.EXAMPLE.com"];
  broken.virtualServices[0].routes[0].wafPolicy = "missing";
  broken.virtualServices[0].routes[0].requireMtlsToBackend = false;
  broken.virtualServices[0].routes[0].backends[0].url = "https://user:pass@app.internal";
  const errors = validateProxy(broken).join("\n");
  assert.match(errors, /redact_request_body must be true/);
  assert.match(errors, /sha256 must be a 64-character hex digest/);
  assert.match(errors, /hostname "Admin\.EXAMPLE\.com" must be lowercase/);
  assert.match(errors, /references unknown WAF policy "missing"/);
  assert.match(errors, /require_mtls_to_backend must be true/);
  assert.match(errors, /url must be http\(s\), no credentials, query, or fragment; an optional path is allowed/);
}

{
  const readiness = proxyRuntimeReadinessModel({
    candidateProxy: proxy,
    runningProxy: proxy,
    candidateStatus: { dirty: false, candidateRevision: "sha256:missing-artifact" },
    validation: {
      valid: true,
      renderPlan: {
        artifactCount: 1,
        artifacts: [{ engine: "nftables", name: "nftables", sizeBytes: 120 }],
      },
    },
  });
  assert.equal(readiness.readiness, "blocked");
  assert.equal(readiness.cls, "bad");
  assert.ok(readiness.blockers.some((item) => item.id === "proxy-artifact-missing"));
  assert.equal(readiness.validation.proxyArtifactPresent, false);
}

{
  const readiness = proxyRuntimeReadinessModel({
    candidateProxy: proxy,
    runningProxy: {},
    candidateStatus: { dirty: true, candidateRevision: "sha256:candidate" },
    candidateRevision: "sha256:candidate",
    runningVersion: 7,
    status: { runtime: { proxy: { state: "ready", listenerCount: 2, engine: "envoy" } } },
    validation: {
      valid: true,
      renderPlan: {
        artifactCount: 1,
        totalBytes: 440,
        artifacts: [{ engine: "proxy", name: "proxy", sizeBytes: 440 }],
      },
    },
  });
  assert.equal(readiness.schemaVersion, "openngfw.proxy.runtime-readiness.v1");
  assert.equal(readiness.readiness, "review");
  assert.equal(readiness.cls, "warn");
  assert.equal(readiness.candidateRevision, "sha256:candidate");
  assert.equal(readiness.runningVersion, 7);
  assert.equal(readiness.candidateDirty, true);
  assert.equal(readiness.proxyChanged, true);
  assert.equal(readiness.validation.valid, true);
  assert.equal(readiness.validation.proxyArtifactPresent, true);
  assert.equal(readiness.runtime.state, "ready");
  assert.match(readiness.boundary, /does not prove active listener traffic/);
  assert.match(readiness.runtime.proofBoundary, /not accepted here as active listener traffic proof/);
  assert.ok(readiness.blockers.some((item) => /Active Envoy\/Coraza traffic rollout/.test(item.detail)));
  assert.deepEqual(readiness.handoffLinks.map((link) => link.href), ["#/changes?tab=candidate", "#/readiness", "#/proxy?drawer=plan"]);
}

{
  const readiness = proxyRuntimeReadinessModel({
    candidateProxy: {},
    runningProxy: proxy,
    candidateStatus: { dirty: false },
    validation: { valid: false, errors: ["server says no"] },
  });
  assert.equal(readiness.readiness, "blocked");
  assert.equal(readiness.cls, "bad");
  assert.equal(readiness.hasCandidateProxy, false);
  assert.equal(readiness.hasRunningProxy, true);
  assert.ok(readiness.blockers.some((item) => item.id === "no-candidate-proxy"));
  assert.ok(readiness.blockers.some((item) => item.detail === "server says no"));
  assert.equal(readiness.runtime.state, "not-reported");
}

{
  const proof = proxyPlanProofModel({
    valid: true,
    renderPlan: {
      artifactCount: 3,
      totalBytes: 640,
      artifacts: [
        { engine: "nftables", name: "nftables", sizeBytes: 100 },
        { engine: "proxy", name: "proxy", sizeBytes: 440 },
        { engine: "vector", name: "vector", sizeBytes: 100 },
      ],
    },
  }, proxy);
  assert.equal(proof.status, "server-rendered plan ready");
  assert.equal(proof.cls, "ok");
  assert.equal(proof.proxyArtifactPresent, true);
  assert.equal(proof.proxyArtifact.name, "proxy");
  assert.equal(proof.artifactCount, 3);
  assert.equal(proof.totalBytes, 640);
  assert.ok(proof.hardeningNotes.some((note) => /Active Envoy\/Coraza traffic rollout/.test(note)));
  assert.deepEqual(proof.links.map((link) => link.href), ["#/changes?tab=candidate", "#/readiness"]);
}

{
  const proof = proxyPlanProofModel({
    valid: true,
    renderPlan: {
      artifact_count: 1,
      total_bytes: 120,
      artifacts: [{ engine: "nftables", name: "nftables", size_bytes: 120 }],
    },
  }, {});
  assert.equal(proof.status, "validated without proxy artifact");
  assert.equal(proof.cls, "warn");
  assert.equal(proof.proxyArtifactPresent, false);
  assert.equal(proof.artifacts[0].sizeBytes, 120);
}

{
  const proof = proxyPlanProofModel({
    valid: true,
    renderPlan: {
      artifacts: [{ engine: "proxy", name: "proxy", sizeBytes: 440 }],
    },
  }, proxy);
  assert.equal(proof.previews.length, 2);
  assert.deepEqual(proof.previews.map((preview) => preview.id), ["envoy-bootstrap", "coraza-waf"]);
  assert.match(proof.previews[0].text, /Review-only deterministic preview/);
  assert.match(proof.previews[0].text, /Not live listener evidence/);
  assert.match(proof.previews[0].text, /\[redacted tls_secret_ref\]/);
  assert.doesNotMatch(proof.previews[0].text, /vault:\/\/openngfw\/admin-api/);
  assert.match(proof.previews[1].text, /SecRuleEngine On/);
  assert.match(proof.previews[1].text, /request body retention redacted/);
}

{
  const previews = proxyArtifactPreviewModel({
    valid: true,
    render_plan: {
      artifacts: [{
        engine: "proxy",
        name: "envoy-bootstrap.yaml",
        content_type: "application/x-yaml",
        sha256: "b".repeat(64),
        content: "tls_secret_ref: vault://openngfw/admin-api\nauthorization: Bearer secret-token\nroute: /api\n",
      }],
    },
  }, proxy);
  assert.equal(previews.length, 1);
  assert.equal(previews[0].source, "validation-render");
  assert.equal(previews[0].filename, "envoy-bootstrap.yaml");
  assert.equal(previews[0].language, "yaml");
  assert.equal(previews[0].sha256, "b".repeat(64));
  assert.equal(previews[0].redacted, true);
  assert.match(previews[0].text, /tls_secret_ref: \[redacted\]/);
  assert.match(previews[0].text, /authorization: Bearer \[redacted\]/i);
  assert.doesNotMatch(previews[0].text, /secret-token|vault:\/\/openngfw/);
}

{
  const text = [
    "line 1 token=secret-token",
    "line 2",
    "line 3",
    "line 4",
  ].join("\n");
  const bounded = boundedArtifactSnippet(text, { maxLines: 2, maxChars: 24 });
  assert.equal(bounded.truncated, true);
  assert.equal(bounded.redacted, true);
  assert.match(bounded.text, /\[redacted\]/);
  assert.match(bounded.text, /\[preview truncated\]/);
  assert.doesNotMatch(bounded.text, /secret-token|line 3/);
}

{
  const redacted = redactProxyArtifactText("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\npassword: super-secret");
  assert.equal(redacted.includes("super-secret"), false);
  assert.match(redacted, /\[redacted private key\]/);
  assert.match(redacted, /password: \[redacted\]/);
}
