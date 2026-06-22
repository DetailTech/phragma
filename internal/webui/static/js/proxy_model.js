// Pure Proxy/WAF model helpers for the planned-only L7 policy workspace.
// Mirrors server validation in internal/policy/validate.go.

const NAME_RE = /^[a-z0-9]([a-z0-9_-]{0,62}[a-z0-9])?$/;
const SHA256_RE = /^[A-Fa-f0-9]{64}$/;
const HOSTNAME_RE = /^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

export const PROXY_PLAN_HARDENING_NOTES = Object.freeze([
  "TLS private-key custody and certificate lifecycle are not proven by this plan.",
  "Backend mTLS runtime certificate proof and rotation remain required before active rollout.",
  "WAF ruleset supply-chain custody must be signed and retained before production enforcement.",
  "Request-body privacy controls need server-side retention and redaction custody.",
  "Active Envoy/Coraza traffic rollout, listener health, rollback, and HA traffic proof remain separate readiness work.",
]);

export const PROXY_ARTIFACT_PREVIEW_LIMITS = Object.freeze({
  maxChars: 2400,
  maxLines: 80,
});

export function normalizeProxy(proxy = {}) {
  return {
    virtualServices: Array.isArray(proxy?.virtualServices) ? proxy.virtualServices : [],
    wafPolicies: Array.isArray(proxy?.wafPolicies) ? proxy.wafPolicies : [],
  };
}

export function ensureProxy(policy = {}) {
  if (!policy.proxy || typeof policy.proxy !== "object") policy.proxy = {};
  if (!Array.isArray(policy.proxy.virtualServices)) policy.proxy.virtualServices = [];
  if (!Array.isArray(policy.proxy.wafPolicies)) policy.proxy.wafPolicies = [];
  return policy.proxy;
}

export function proxySummary(proxy = {}) {
  const p = normalizeProxy(proxy);
  const routes = p.virtualServices.flatMap((service) => (service.routes || []).map((route) => ({ service, route })));
  const backends = routes.flatMap(({ route }) => route.backends || []);
  const enabled = p.virtualServices.filter((service) => service.enabled !== false);
  const wafNames = new Set(p.wafPolicies.map((waf) => waf.name).filter(Boolean));
  const attachedWafRoutes = routes.filter(({ route }) => route.wafPolicy && wafNames.has(route.wafPolicy));
  return {
    virtualServices: p.virtualServices.length,
    enabledServices: enabled.length,
    routes: routes.length,
    backends: backends.length,
    wafPolicies: p.wafPolicies.length,
    attachedWafRoutes: attachedWafRoutes.length,
    plannedOnly: true,
  };
}

export function proxyPolicyCouplingModel(policy = {}) {
  const proxy = normalizeProxy(policy.proxy);
  const servicePorts = tcpServicePorts(policy.services || []);
  const appPorts = tcpApplicationPorts(policy.applications || []);
  const inspectionProfiles = inlineInspectionProfileNames(policy.securityProfiles || []);
  const staticRoutes = (policy.staticRoutes || []).map((route) => String(route?.destination || "")).filter(Boolean);
  const findings = [];
  const services = proxy.virtualServices.map((service, serviceIndex) => {
    const listener = service.listener || {};
    const listenerPort = Number(listener.port) || 0;
    const matches = listenerPolicyMatches(policy.rules || [], listenerPort, servicePorts, appPorts, inspectionProfiles);
    const routes = (service.routes || []).map((proxyRoute, routeIndex) => {
      const backendFindings = (proxyRoute.backends || []).map((backend) => backendRouteFinding(service, proxyRoute, backend, staticRoutes)).filter(Boolean);
      if (!proxyRoute.wafPolicy) {
        findings.push(policyFinding("warning", service.name, proxyRoute.name, "waf", "Proxy route has no WAF policy attached; traffic-policy review will not show WAF enforcement intent for this path."));
      }
      findings.push(...backendFindings);
      return {
        name: proxyRoute.name || `route-${routeIndex + 1}`,
        pathPrefix: proxyRoute.pathPrefix || "/",
        wafPolicy: proxyRoute.wafPolicy || "",
        backendCount: Array.isArray(proxyRoute.backends) ? proxyRoute.backends.length : 0,
        backendFindings,
      };
    });
    if (service.enabled !== false) {
      if (!matches.serviceRules.length && !matches.appRules.length) {
        findings.push(policyFinding("warning", service.name, "", "security-rule", `Enabled virtual service listener TCP/${listenerPort} has no enabled allow rule with a matching service or App-ID port hint; review firewall policy before traffic cutover.`));
      } else {
        findings.push(policyFinding("info", service.name, "", "security-rule", `Listener TCP/${listenerPort} is reviewable against allow rule(s): ${[...matches.serviceRules, ...matches.appRules].join(", ")}.`));
      }
      if (!matches.appRules.length) {
        findings.push(policyFinding("info", service.name, "", "app-id", `Listener TCP/${listenerPort} is not tied to an App-ID port hint; WAF intent remains proxy-plan context until App-ID classification evidence is reviewed.`));
      }
      if (!matches.inspectionRules.length) {
        findings.push(policyFinding("warning", service.name, "", "inspection", "No matching allow rule carries an inline inspection security profile; review IDS/inspection posture alongside WAF mode."));
      }
    }
    return {
      name: service.name || `service-${serviceIndex + 1}`,
      enabled: service.enabled !== false,
      listenerPort,
      listener: `${listener.bindAddress || "-"}:${listenerPort || "-"}`,
      hostnames: listFromValue(service.hostnames),
      serviceRules: matches.serviceRules,
      appRules: matches.appRules,
      inspectionRules: matches.inspectionRules,
      routes,
    };
  });
  const warningCount = findings.filter((finding) => finding.severity === "warning").length;
  return {
    schemaVersion: "openngfw.proxy.policy-coupling.v1",
    workflow: "candidate-safe review of Proxy/WAF intent against security rules, routes, App-ID, and inspection; no listener cutover or TLS key custody",
    services,
    findings,
    summary: {
      services: services.length,
      enabledServices: services.filter((service) => service.enabled).length,
      findings: findings.length,
      warnings: warningCount,
      infos: findings.length - warningCount,
    },
    reviewLinks: [
      { label: "Rules", href: "#/rules" },
      { label: "Traffic", href: "#/traffic" },
      { label: "Inspection", href: "#/inspection" },
      { label: "Changes", href: "#/changes?tab=candidate" },
    ],
  };
}

export function validateProxy(proxy = {}) {
  const p = normalizeProxy(proxy);
  const errors = [];
  const wafNames = new Set();
  for (const waf of p.wafPolicies) {
    validateWafPolicy(waf || {}, errors, wafNames);
  }
  const serviceNames = new Set();
  for (const service of p.virtualServices) {
    validateVirtualService(service || {}, errors, wafNames, serviceNames);
  }
  return errors;
}

export function validateWafPolicy(waf = {}, errors = [], seen = new Set()) {
  const ctx = `WAF policy "${waf.name || ""}"`;
  if (!validName(waf.name)) errors.push("WAF policy name is invalid (lowercase alphanumeric, '-', '_', max 64 chars).");
  else if (seen.has(waf.name)) errors.push(`duplicate WAF policy "${waf.name}"`);
  else seen.add(waf.name);
  if (waf.mode !== "WAF_MODE_DETECT" && waf.mode !== "WAF_MODE_BLOCK") errors.push(`${ctx}: mode must be detect or block.`);
  const ruleSets = Array.isArray(waf.ruleSets) ? waf.ruleSets : [];
  if (!ruleSets.length) errors.push(`${ctx}: at least one rule set is required.`);
  const ruleSetNames = new Set();
  for (let i = 0; i < ruleSets.length; i++) {
    const ruleSet = ruleSets[i] || {};
    const rsCtx = `${ctx} rule_set[${i}]`;
    if (!validName(ruleSet.name)) errors.push(`${rsCtx}: name is invalid.`);
    else if (ruleSetNames.has(ruleSet.name)) errors.push(`${rsCtx}: duplicate rule set "${ruleSet.name}".`);
    else ruleSetNames.add(ruleSet.name);
    if (!String(ruleSet.version || "").trim()) errors.push(`${rsCtx}: version is required for provenance.`);
    if (!String(ruleSet.source || "").trim()) errors.push(`${rsCtx}: source is required for provenance.`);
    if (!SHA256_RE.test(String(ruleSet.sha256 || "").trim())) errors.push(`${rsCtx}: sha256 must be a 64-character hex digest.`);
  }
  const limit = Number(waf.requestBodyLimitKb);
  if (!Number.isInteger(limit) || limit < 1 || limit > 1024) errors.push(`${ctx}: request_body_limit_kb must be between 1 and 1024.`);
  if (waf.redactRequestBody !== true) errors.push(`${ctx}: redact_request_body must be true until request-body privacy custody is configured.`);
  return errors;
}

export function validateVirtualService(service = {}, errors = [], wafNames = new Set(), seen = new Set()) {
  const ctx = `virtual service "${service.name || ""}"`;
  if (!validName(service.name)) errors.push("virtual service name is invalid (lowercase alphanumeric, '-', '_', max 64 chars).");
  else if (seen.has(service.name)) errors.push(`duplicate virtual service "${service.name}"`);
  else seen.add(service.name);
  const hostnames = listFromValue(service.hostnames);
  if (!hostnames.length) errors.push(`${ctx}: at least one hostname is required.`);
  const seenHosts = new Set();
  for (const hostname of hostnames) {
    const normalized = String(hostname || "").trim();
    if (!normalized) errors.push(`${ctx}: hostnames cannot contain an empty value.`);
    else if (normalized !== hostname || normalized !== normalized.toLowerCase()) errors.push(`${ctx}: hostname "${hostname}" must be lowercase without surrounding whitespace.`);
    else if (!HOSTNAME_RE.test(normalized)) errors.push(`${ctx}: hostname "${hostname}" is invalid.`);
    else if (seenHosts.has(normalized)) errors.push(`${ctx}: duplicate hostname "${normalized}".`);
    else seenHosts.add(normalized);
  }
  validateListener(service.listener || {}, errors, ctx);
  const routes = Array.isArray(service.routes) ? service.routes : [];
  if (!routes.length) errors.push(`${ctx}: at least one route is required.`);
  const routeNames = new Set();
  for (const route of routes) validateProxyRoute(route || {}, errors, ctx, wafNames, routeNames);
  return errors;
}

export function validateListener(listener = {}, errors = [], ctx = "virtual service") {
  if (!validIp(listener.bindAddress)) errors.push(`${ctx}: listener bind_address "${listener.bindAddress || ""}" is not a valid IP address.`);
  const port = Number(listener.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) errors.push(`${ctx}: listener port ${listener.port || 0} out of range 1-65535.`);
  if (listener.tls === true && !String(listener.tlsSecretRef || "").trim()) errors.push(`${ctx}: listener tls_secret_ref is required when tls is enabled.`);
  return errors;
}

export function validateProxyRoute(route = {}, errors = [], serviceCtx = "virtual service", wafNames = new Set(), seen = new Set()) {
  const ctx = `${serviceCtx} route "${route.name || ""}"`;
  if (!validName(route.name)) errors.push(`${serviceCtx} route name is invalid.`);
  else if (seen.has(route.name)) errors.push(`${serviceCtx}: duplicate route name "${route.name}".`);
  else seen.add(route.name);
  if (!validPathPrefix(route.pathPrefix)) errors.push(`${ctx}: path_prefix "${route.pathPrefix || ""}" must be an absolute clean path.`);
  if (route.wafPolicy && !wafNames.has(route.wafPolicy)) errors.push(`${ctx} references unknown WAF policy "${route.wafPolicy}".`);
  const backends = Array.isArray(route.backends) ? route.backends : [];
  if (!backends.length) errors.push(`${ctx}: at least one backend is required.`);
  const backendNames = new Set();
  let totalWeight = 0;
  for (const backend of backends) {
    validateBackend(backend || {}, errors, ctx, backendNames);
    totalWeight += Number(backend?.weight) || 0;
  }
  if (backends.length && totalWeight <= 0) errors.push(`${ctx}: backend weights must sum to greater than 0.`);
  if (route.requireMtlsToBackend !== true) errors.push(`${ctx}: require_mtls_to_backend must be true until backend transport hardening is configured.`);
  return errors;
}

export function validateBackend(backend = {}, errors = [], ctx = "route", seen = new Set()) {
  if (!validName(backend.name)) errors.push(`${ctx} backend name is invalid.`);
  else if (seen.has(backend.name)) errors.push(`${ctx}: duplicate backend name "${backend.name}".`);
  else seen.add(backend.name);
  if (!validBackendUrl(backend.url)) errors.push(`${ctx} backend "${backend.name || ""}": url must be http(s), no credentials, query, or fragment; an optional path is allowed.`);
  const weight = Number(backend.weight);
  if (!Number.isInteger(weight) || weight < 1) errors.push(`${ctx} backend "${backend.name || ""}": weight must be greater than 0.`);
  return errors;
}

export function proxyRouteState(query = {}) {
  return {
    tab: ["services", "waf"].includes(query.tab) ? query.tab : "services",
    service: cleanToken(query.service),
    waf: cleanToken(query.waf),
    drawer: ["plan", "policy"].includes(query.drawer) ? query.drawer : "",
  };
}

export function proxyPlanProofModel(validation = {}, proxy = {}) {
  const renderPlan = validation?.renderPlan || validation?.render_plan || {};
  const artifacts = Array.isArray(renderPlan.artifacts)
    ? renderPlan.artifacts.map(renderArtifactModel).filter(Boolean)
    : [];
  const proxyArtifact = artifacts.find((artifact) => isProxyArtifact(artifact)) || null;
  const clientErrors = validateProxy(proxy);
  const valid = Boolean(validation?.valid);
  const blocked = !valid || clientErrors.length > 0;
  const artifactPresent = Boolean(proxyArtifact);
  let status = "blocked";
  let cls = "bad";
  if (valid && artifactPresent) {
    status = "server-rendered plan ready";
    cls = "ok";
  } else if (valid) {
    status = "validated without proxy artifact";
    cls = "warn";
  }
  return {
    valid,
    status,
    cls,
    proxyArtifactPresent: artifactPresent,
    proxyArtifact,
    artifacts,
    artifactCount: Number(renderPlan.artifactCount || renderPlan.artifact_count || artifacts.length) || artifacts.length,
    totalBytes: Number(renderPlan.totalBytes || renderPlan.total_bytes || artifacts.reduce((sum, artifact) => sum + artifact.sizeBytes, 0)) || 0,
    previews: proxyArtifactPreviewModel(validation, proxy, artifacts),
    validationErrors: Array.isArray(validation?.errors) ? validation.errors : [],
    clientErrors,
    blocked,
    hardeningNotes: [...PROXY_PLAN_HARDENING_NOTES],
    links: [
      { label: "Changes", href: "#/changes?tab=candidate" },
      { label: "Readiness", href: "#/readiness" },
    ],
  };
}

export function proxyRuntimeReadinessModel({
  candidateProxy = {},
  runningProxy = {},
  candidateStatus = null,
  candidateRevision = "",
  runningVersion = 0,
  status = null,
  validation = null,
} = {}) {
  const candidate = normalizeProxy(candidateProxy);
  const running = normalizeProxy(runningProxy);
  const candidateSummary = proxySummary(candidate);
  const runningSummary = proxySummary(running);
  const clientErrors = validateProxy(candidate);
  const validationErrors = Array.isArray(validation?.errors) ? validation.errors : [];
  const validationValid = validation ? Boolean(validation.valid) : false;
  const plan = validation ? proxyPlanProofModel(validation, candidate) : null;
  const runtime = proxyRuntimeStatusModel(status);
  const candidateDirty = Boolean(candidateStatus?.dirty);
  const proxyChanged = !proxyEquivalent(candidate, running);
  const hasCandidateProxy = candidateSummary.virtualServices > 0 || candidateSummary.wafPolicies > 0;
  const hasRunningProxy = runningSummary.virtualServices > 0 || runningSummary.wafPolicies > 0;
  const blockers = [
    ...clientErrors.map((detail) => runtimeBlocker("candidate-validation", "Candidate proxy validation", detail)),
    ...validationErrors.map((detail) => runtimeBlocker("server-validation", "Server candidate validation", detail)),
  ];
  if (!hasCandidateProxy) blockers.push(runtimeBlocker("no-candidate-proxy", "No candidate Proxy/WAF policy", "Add a virtual service or WAF policy before listener rollout review."));
  if (!validationValid) blockers.push(runtimeBlocker("validation-not-valid", "Candidate validation is not passing", "Run candidate validation and resolve server blockers before rollout readiness review."));
  if (validationValid && !plan?.proxyArtifactPresent) blockers.push(runtimeBlocker("proxy-artifact-missing", "Proxy render artifact missing", "Server validation did not report proxy render-plan metadata for operator review."));
  blockers.push(...PROXY_PLAN_HARDENING_NOTES.map((detail, index) => runtimeBlocker(`hardening-${index + 1}`, "Production hardening required", detail)));
  const hasBlockingValidation = blockers.some((item) => item.id === "candidate-validation" || item.id === "server-validation" || item.id === "validation-not-valid" || item.id === "proxy-artifact-missing");
  const readiness = hasBlockingValidation ? "blocked"
    : !hasCandidateProxy ? "empty"
      : "review";
  const cls = readiness === "blocked" ? "bad" : readiness === "review" ? "warn" : "info";
  return {
    schemaVersion: "openngfw.proxy.runtime-readiness.v1",
    readiness,
    cls,
    label: readiness === "empty" ? "no proxy policy" : readiness === "blocked" ? "blocked" : "review required",
    boundary: "Runtime-readiness review only; does not prove active listener traffic, WAF enforcement, daemon launch, TLS key custody, backend mTLS handshake, HA listener failover, signing custody, or traffic cutover.",
    candidateRevision: String(candidateRevision || candidateStatus?.candidateRevision || ""),
    runningVersion: Number(runningVersion) || 0,
    candidateDirty,
    proxyChanged,
    hasCandidateProxy,
    hasRunningProxy,
    candidateSummary,
    runningSummary,
    validation: {
      checked: Boolean(validation),
      valid: validationValid,
      proxyArtifactPresent: Boolean(plan?.proxyArtifactPresent),
      artifactCount: Number(plan?.artifactCount || 0),
      totalBytes: Number(plan?.totalBytes || 0),
    },
    runtime,
    blockers: dedupeBlockers(blockers),
    handoffLinks: [
      { label: "Changes review", href: "#/changes?tab=candidate" },
      { label: "Readiness", href: "#/readiness" },
      { label: "Proxy plan proof", href: "#/proxy?drawer=plan" },
    ],
    reviewCommands: [
      "ngfwctl policy validate",
      "ngfwctl policy diff",
      "ngfwctl system status --json",
      "ngfwctl commit --reviewed-candidate-revision <candidate-revision>",
    ],
  };
}

export function proxyArtifactPreviewModel(validation = {}, proxy = {}, normalizedArtifacts = null, limits = PROXY_ARTIFACT_PREVIEW_LIMITS) {
  const renderPlan = validation?.renderPlan || validation?.render_plan || {};
  const artifacts = Array.isArray(normalizedArtifacts)
    ? normalizedArtifacts
    : (Array.isArray(renderPlan.artifacts) ? renderPlan.artifacts.map(renderArtifactModel).filter(Boolean) : []);
  const serverPreviews = artifacts
    .map((artifact) => previewFromArtifact(artifact, limits))
    .filter(Boolean);
  if (serverPreviews.length) return serverPreviews;
  return deterministicProxyPreviews(proxy, limits);
}

export function redactProxyArtifactText(text = "") {
  return String(text || "")
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g, "[redacted private key]")
    .replace(/(authorization:\s*(?:bearer|basic)\s+)[^\s"']+/gi, "$1[redacted]")
    .replace(/(client_secret|private_key|password|token|tls_secret_ref|tlsSecretRef)(\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,]+)/gi, "$1$2[redacted]")
    .replace(/\bhttps?:\/\/([^:\s/@]+):([^@\s]+)@/gi, "https://[redacted-credentials]@");
}

export function boundedArtifactSnippet(text = "", limits = PROXY_ARTIFACT_PREVIEW_LIMITS) {
  const maxLines = positiveInt(limits.maxLines, PROXY_ARTIFACT_PREVIEW_LIMITS.maxLines);
  const maxChars = positiveInt(limits.maxChars, PROXY_ARTIFACT_PREVIEW_LIMITS.maxChars);
  const redacted = redactProxyArtifactText(text);
  const lines = redacted.split(/\r?\n/);
  const lineBounded = lines.slice(0, maxLines).join("\n");
  let bounded = lineBounded.length > maxChars ? lineBounded.slice(0, maxChars) : lineBounded;
  bounded = bounded.replace(/\s+$/g, "");
  const truncated = lines.length > maxLines || redacted.length > bounded.length;
  if (truncated) bounded += "\n... [preview truncated]";
  return {
    text: bounded,
    truncated,
    lineCount: Math.min(lines.length, maxLines),
    totalLines: lines.length,
    totalChars: redacted.length,
    maxChars,
    maxLines,
    redacted: redacted !== String(text || ""),
  };
}

export function defaultWafPolicy(existing = []) {
  return {
    name: uniqueName("corp-waf", existing.map((waf) => waf.name)),
    mode: "WAF_MODE_BLOCK",
    requestBodyLimitKb: 128,
    auditLogging: true,
    redactRequestBody: true,
    ruleSets: [{ name: "crs", version: "4.0.0", source: "owasp-crs", sha256: "a".repeat(64) }],
  };
}

export function defaultVirtualService(existing = [], wafPolicies = []) {
  const wafName = wafPolicies[0]?.name || "";
  return {
    name: uniqueName("admin-api", existing.map((service) => service.name)),
    enabled: true,
    hostnames: ["admin.example.com"],
    listener: { bindAddress: "0.0.0.0", port: 443, tls: true, tlsSecretRef: "vault://openngfw/admin-api" },
    routes: [{
      name: "api",
      pathPrefix: "/api",
      wafPolicy: wafName,
      requireMtlsToBackend: true,
      stripPrefix: false,
      backends: [{ name: "api-1", url: "https://api.internal", weight: 100 }],
    }],
  };
}

export function listFromValue(value) {
  if (Array.isArray(value)) return value.map((item) => String(item || "").trim()).filter(Boolean);
  return String(value || "").split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);
}

export function modeLabel(mode = "") {
  if (mode === "WAF_MODE_BLOCK") return "block";
  if (mode === "WAF_MODE_DETECT") return "detect";
  return "unspecified";
}

export function validName(value) {
  return NAME_RE.test(String(value || ""));
}

export function validPathPrefix(value) {
  const path = String(value || "").trim();
  if (!path.startsWith("/") || path.includes(" ")) return false;
  const parts = [];
  for (const part of path.split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") return false;
    parts.push(part);
  }
  return "/" + parts.join("/") === path;
}

export function validBackendUrl(value) {
  try {
    const url = new URL(String(value || "").trim());
    return (url.protocol === "http:" || url.protocol === "https:") &&
      Boolean(url.host) && !url.username && !url.password && !url.search && !url.hash;
  } catch {
    return false;
  }
}

function validIp(value) {
  const text = String(value || "").trim();
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(text)) {
    return text.split(".").every((part) => Number(part) >= 0 && Number(part) <= 255 && String(Number(part)) === String(part));
  }
  return /^[0-9a-f:]+$/i.test(text) && text.includes(":");
}

function uniqueName(base, names = []) {
  const seen = new Set(names.filter(Boolean));
  if (!seen.has(base)) return base;
  for (let i = 2; i < 1000; i++) {
    const next = `${base}-${i}`;
    if (!seen.has(next)) return next;
  }
  return `${base}-${Date.now()}`;
}

function cleanToken(value) {
  return String(value || "").trim().slice(0, 128);
}

function renderArtifactModel(artifact = {}) {
  const engine = cleanToken(artifact.engine || "");
  const name = cleanToken(artifact.name || engine || "");
  if (!engine && !name) return null;
  return {
    engine,
    name,
    sizeBytes: Number(artifact.sizeBytes || artifact.size_bytes || 0) || 0,
    sha256: cleanToken(artifact.sha256 || artifact.sha || ""),
    path: cleanToken(artifact.path || ""),
    contentType: cleanToken(artifact.contentType || artifact.content_type || ""),
    content: typeof artifact.content === "string" ? artifact.content
      : typeof artifact.text === "string" ? artifact.text
        : typeof artifact.preview === "string" ? artifact.preview
          : typeof artifact.snippet === "string" ? artifact.snippet
            : "",
  };
}

function isProxyArtifact(artifact = {}) {
  return artifact.engine === "proxy" || artifact.name === "proxy" || /proxy/i.test(`${artifact.engine} ${artifact.name}`);
}

function previewFromArtifact(artifact = {}, limits = PROXY_ARTIFACT_PREVIEW_LIMITS) {
  if (!artifact.content) return null;
  const snippet = boundedArtifactSnippet(artifact.content, limits);
  return {
    id: cleanToken(artifact.name || artifact.engine || "proxy-artifact"),
    label: artifact.name || artifact.engine || "proxy artifact",
    engine: artifact.engine || "proxy",
    source: "validation-render",
    language: languageForArtifact(artifact),
    filename: filenameForArtifact(artifact),
    sizeBytes: artifact.sizeBytes || snippet.totalChars,
    sha256: artifact.sha256 || "",
    contentType: artifact.contentType || "",
    ...snippet,
  };
}

function deterministicProxyPreviews(proxy = {}, limits = PROXY_ARTIFACT_PREVIEW_LIMITS) {
  const p = normalizeProxy(proxy);
  if (!p.virtualServices.length && !p.wafPolicies.length) return [];
  return [
    {
      id: "envoy-bootstrap",
      label: "Envoy bootstrap snippet",
      engine: "envoy",
      source: "browser-deterministic",
      language: "yaml",
      filename: "envoy-bootstrap.preview.yaml",
      ...boundedArtifactSnippet(renderEnvoySnippet(p), limits),
    },
    {
      id: "coraza-waf",
      label: "Coraza WAF snippet",
      engine: "coraza",
      source: "browser-deterministic",
      language: "text",
      filename: "coraza-waf.preview.conf",
      ...boundedArtifactSnippet(renderCorazaSnippet(p), limits),
    },
  ];
}

function renderEnvoySnippet(proxy = {}) {
  const services = sortedByName(proxy.virtualServices || []);
  const lines = [
    "# Review-only deterministic preview from candidate policy.proxy.",
    "# Not live listener evidence; no Envoy process or traffic cutover is started.",
    "static_resources:",
    "  listeners:",
  ];
  for (const service of services) {
    if (service.enabled === false) continue;
    const listener = service.listener || {};
    lines.push(`    - name: ${quoteYaml("openngfw_" + safeArtifactName(service.name || "service"))}`);
    lines.push("      address:");
    lines.push("        socket_address:");
    lines.push(`          address: ${quoteYaml(listener.bindAddress || "0.0.0.0")}`);
    lines.push(`          port_value: ${Number(listener.port) || 0}`);
    if (listener.tls) lines.push("      tls_context: [redacted tls_secret_ref]");
    lines.push("      route_config:");
    lines.push("        virtual_hosts:");
    lines.push(`          - name: ${quoteYaml("vhost_" + safeArtifactName(service.name || "service"))}`);
    lines.push("            domains:");
    for (const hostname of sortedStrings(listFromValue(service.hostnames))) lines.push(`              - ${quoteYaml(hostname)}`);
    lines.push("            routes:");
    for (const route of sortedByName(service.routes || [])) {
      lines.push("              - match:");
      lines.push(`                  prefix: ${quoteYaml(route.pathPrefix || "/")}`);
      lines.push("                route:");
      lines.push(`                  cluster: ${quoteYaml(clusterPreviewName(service.name, route.name))}`);
      if (route.stripPrefix) lines.push("                  prefix_rewrite: \"/\"");
      if (route.wafPolicy) lines.push(`                typed_per_filter_config.openngfw.coraza.policy: ${quoteYaml(route.wafPolicy)}`);
    }
  }
  lines.push("  clusters:");
  for (const service of services) {
    if (service.enabled === false) continue;
    for (const route of sortedByName(service.routes || [])) {
      lines.push(`    - name: ${quoteYaml(clusterPreviewName(service.name, route.name))}`);
      lines.push("      lb_policy: ROUND_ROBIN");
      for (const backend of sortedByName(route.backends || [])) lines.push(`      endpoint: ${quoteYaml(safeBackendEndpoint(backend.url))}`);
    }
  }
  return lines.join("\n") + "\n";
}

function renderCorazaSnippet(proxy = {}) {
  const lines = [
    "# Review-only deterministic preview from candidate policy.proxy.",
    "# Not live WAF enforcement evidence; Coraza runtime custody remains hardening work.",
  ];
  for (const policy of sortedByName(proxy.wafPolicies || [])) {
    lines.push("");
    lines.push(`# policy: ${policy.name || "unnamed"}`);
    lines.push(policy.mode === "WAF_MODE_BLOCK" ? "SecRuleEngine On" : "SecRuleEngine DetectionOnly");
    lines.push(`SecRequestBodyLimit ${(Number(policy.requestBodyLimitKb) || 0) * 1024}`);
    lines.push(`SecAuditEngine ${policy.auditLogging === false ? "Off" : "RelevantOnly"}`);
    lines.push(`SecRequestBodyAccess ${policy.redactRequestBody === true ? "On # request body retention redacted" : "On # review required: request body is not marked redacted"}`);
    for (const ruleset of sortedByName(policy.ruleSets || [])) {
      lines.push(`# ruleset: ${ruleset.name || "rules"} version=${ruleset.version || "unknown"} source=${ruleset.source || "unknown"} sha256=${ruleset.sha256 || "missing"}`);
    }
  }
  return lines.join("\n") + "\n";
}

function languageForArtifact(artifact = {}) {
  const key = `${artifact.name || ""} ${artifact.contentType || ""}`.toLowerCase();
  if (key.includes("json")) return "json";
  if (key.includes("yaml") || key.includes("yml")) return "yaml";
  if (key.includes("conf") || key.includes("text")) return "text";
  return "text";
}

function filenameForArtifact(artifact = {}) {
  const base = safeArtifactName(artifact.name || artifact.engine || "proxy-artifact").replace(/_/g, "-");
  if (/\.(json|ya?ml|conf|txt)$/i.test(artifact.name || "")) return artifact.name;
  if (artifact.contentType === "application/json") return `${base}.json`;
  if (/yaml/i.test(artifact.contentType || "")) return `${base}.yaml`;
  return `${base}.txt`;
}

function sortedByName(items = []) {
  return [...items].sort((a, b) => String(a?.name || "").localeCompare(String(b?.name || "")));
}

function sortedStrings(items = []) {
  return [...items].map((item) => String(item || "")).sort();
}

function safeArtifactName(value = "") {
  const out = String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  return out || "unnamed";
}

function clusterPreviewName(service = "", route = "") {
  return `cluster_${safeArtifactName(service)}_${safeArtifactName(route)}`;
}

function safeBackendEndpoint(value = "") {
  try {
    const url = new URL(String(value || "").trim());
    return `${url.protocol}//${url.host}`;
  } catch {
    return "[invalid-backend-url]";
  }
}

function quoteYaml(value = "") {
  return JSON.stringify(String(value || ""));
}

function positiveInt(value, fallback) {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

function proxyEquivalent(a = {}, b = {}) {
  return JSON.stringify(normalizeProxy(a)) === JSON.stringify(normalizeProxy(b));
}

function runtimeBlocker(id, title, detail) {
  return { id, title, detail };
}

function dedupeBlockers(items = []) {
  const seen = new Set();
  const out = [];
  for (const item of items) {
    const key = `${item.id}|${item.title}|${item.detail}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

function proxyRuntimeStatusModel(status = null) {
  const runtime = status?.proxy || status?.runtime?.proxy || {};
  const engines = Array.isArray(status?.engines) ? status.engines : [];
  const engine = engines.find((item) => /proxy|envoy|coraza/i.test(`${item?.name || ""} ${item?.engine || ""}`)) || {};
  const listenerCount = Number(runtime.listenerCount || runtime.listener_count || runtime.listeners || 0) || 0;
  const reportedState = cleanToken(runtime.state || runtime.status || engine.state || engine.status || "not-reported");
  const observed = Boolean(status) && (Object.keys(runtime).length > 0 || Object.keys(engine).length > 0);
  return {
    observed,
    state: observed ? reportedState : "not-reported",
    listenerCount,
    engine: cleanToken(engine.name || engine.engine || runtime.engine || "not-reported"),
    detail: observed
      ? "System status exposes proxy-related runtime metadata, but this drawer treats it as context only."
      : "System status does not expose proxy listener runtime evidence.",
    proofBoundary: "Context only; not accepted here as active listener traffic proof or daemon launch evidence.",
  };
}

function tcpServicePorts(services = []) {
  const out = new Map();
  for (const service of services) {
    if (service?.protocol !== "PROTOCOL_TCP") continue;
    const ports = portsFromRanges(service.ports || []);
    if (ports.size) out.set(service.name, ports);
  }
  return out;
}

function tcpApplicationPorts(applications = []) {
  const out = new Map();
  for (const app of applications) {
    const ports = new Set();
    for (const portBlock of app?.ports || []) {
      if (portBlock?.protocol !== "PROTOCOL_TCP") continue;
      for (const port of portsFromRanges(portBlock.ports || [])) ports.add(port);
    }
    if (ports.size) out.set(app.name, ports);
  }
  return out;
}

function portsFromRanges(ranges = []) {
  const ports = new Set();
  for (const range of ranges) {
    const start = Number(range?.start) || 0;
    const end = Number(range?.end) || start;
    if (start < 1 || end < start || end > 65535) continue;
    for (let port = start; port <= end; port++) ports.add(port);
  }
  return ports;
}

function inlineInspectionProfileNames(profiles = []) {
  const names = new Set();
  for (const profile of profiles) {
    if (profileRequiresInlineInspection(profile)) names.add(profile.name);
  }
  return names;
}

function profileRequiresInlineInspection(profile = {}) {
  return profile.tlsInspection === "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED" ||
    (Array.isArray(profile.urlCategories) && profile.urlCategories.length > 0) ||
    profile.dnsSecurity === "DNS_SECURITY_MODE_BLOCK_MALICIOUS" ||
    profile.fileSecurity === "FILE_SECURITY_MODE_BLOCK_EXECUTABLES" ||
    profile.fileSecurity === "FILE_SECURITY_MODE_BLOCK_HIGH_RISK";
}

function listenerPolicyMatches(rules = [], listenerPort = 0, servicePorts = new Map(), appPorts = new Map(), inspectionProfiles = new Set()) {
  const serviceRules = [];
  const appRules = [];
  const inspectionRules = [];
  for (const rule of rules) {
    if (!rule || rule.disabled || rule.action !== "ACTION_ALLOW") continue;
    const serviceMatched = (rule.services || []).some((service) => service === "any" || servicePorts.get(service)?.has(listenerPort));
    const appMatched = (rule.applications || []).some((app) => app === "any" || appPorts.get(app)?.has(listenerPort));
    if (serviceMatched) serviceRules.push(rule.name || rule.id || "allow-rule");
    if (appMatched) appRules.push(rule.name || rule.id || "allow-rule");
    if ((serviceMatched || appMatched) && (rule.securityProfiles || []).some((profile) => inspectionProfiles.has(profile))) {
      inspectionRules.push(rule.name || rule.id || "allow-rule");
    }
  }
  return {
    serviceRules: uniqueList(serviceRules),
    appRules: uniqueList(appRules),
    inspectionRules: uniqueList(inspectionRules),
  };
}

function backendRouteFinding(service = {}, proxyRoute = {}, backend = {}, staticRoutes = []) {
  const host = backendUrlHost(backend.url);
  if (!host) return null;
  if (!isIpv4(host) && !host.includes(":")) {
    return policyFinding("info", service.name, proxyRoute.name, "route", `Backend "${backend.name || "backend"}" uses DNS host "${host}"; static-route proof needs resolver and runtime route evidence before cutover.`);
  }
  if (!staticRoutes.some((cidr) => ipv4InCidr(host, cidr))) {
    return policyFinding("warning", service.name, proxyRoute.name, "route", `Backend "${backend.name || "backend"}" address ${host} is not covered by configured static routes; review connected/default route evidence before cutover.`);
  }
  return null;
}

function backendUrlHost(raw = "") {
  try {
    return new URL(String(raw || "").trim()).hostname;
  } catch {
    return "";
  }
}

function isIpv4(value = "") {
  const parts = String(value).split(".");
  return parts.length === 4 && parts.every((part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function ipv4InCidr(ip = "", cidr = "") {
  if (!isIpv4(ip)) return false;
  const [network, bitsText = "32"] = String(cidr || "").split("/");
  if (!isIpv4(network)) return false;
  const bits = Number(bitsText);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(network) & mask);
}

function ipv4ToInt(ip = "") {
  return ip.split(".").reduce((acc, part) => ((acc << 8) + Number(part)) >>> 0, 0);
}

function policyFinding(severity, service, route, dimension, message) {
  return {
    severity,
    virtualService: service || "",
    route: route || "",
    dimension,
    message,
  };
}

function uniqueList(items = []) {
  return [...new Set(items.filter(Boolean))];
}
