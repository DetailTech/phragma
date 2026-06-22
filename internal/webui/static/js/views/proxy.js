// Proxy/WAF authoring workspace. This stages bounded L7 intent to
// policy.proxy only; it does not claim active proxy enforcement.

import { h, icon, clear } from "../core.js";
import { api } from "../api.js";
import { throwIfAccessDenied } from "../auth_gate.js";
import { activeInvestigationServerCaseHref, appendInvestigationPacketToActiveServerCase, pinInvestigationPacket } from "../investigation_case.js";
import { buildInvestigationPacket } from "../investigation_packet.js";
import { equal, session } from "../policy.js";
import { boundedArtifactSnippet, defaultVirtualService, defaultWafPolicy, ensureProxy, listFromValue, modeLabel, normalizeProxy, proxyPlanProofModel, proxyPolicyCouplingModel, proxyRuntimeReadinessModel, proxySummary, validateProxy } from "../proxy_model.js";
import { normalizeProxyRoute, proxyHash } from "../proxy_route.js";
import { pageHead, card, emptyState, pill, toast, openDrawer, closeDrawer, confirmDialog, labeledCell, responsiveTable } from "../ui.js";

let route = normalizeProxyRoute();

export async function render(ctx = {}) {
  route = normalizeProxyRoute(ctx.query || {});
  const unavailableError = await loadProxySession();
  const root = h("div", { dataset: { proxyWorkspace: "true" } });
  if (unavailableError) {
    paintProxyUnavailable(root, unavailableError);
    return root;
  }
  paint(root);
  if (route.drawer === "plan") {
    queueMicrotask(() => openPlanProofDrawer(root, { routeBacked: true }));
  } else if (route.drawer === "policy") {
    queueMicrotask(() => openPolicyCouplingDrawer(root, { routeBacked: true }));
  }
  return root;
}

async function loadProxySession() {
  const result = await Promise.allSettled([session.load()]);
  throwIfAccessDenied(...result);
  if (result[0].status === "rejected") return result[0].reason;
  if (!session.candidateLoadError) return null;
  throwIfAccessDenied({ status: "rejected", reason: session.candidateLoadError });
  return session.candidateLoadError;
}

function paintProxyUnavailable(root, err) {
  clear(root);
  root.appendChild(pageHead("Proxy / WAF",
    "Planned-only virtual services, WAF policies, route mapping, and backend posture staged through the candidate policy.",
    h("div", { class: "flex wrap" },
      h("button", { class: "btn primary", type: "button", title: "Retry loading Proxy/WAF candidate policy", "aria-label": "Retry loading Proxy/WAF candidate policy", dataset: { proxyAction: "retry-unavailable" }, onclick: retryRouteLoad }, h("span", { html: icon("refresh", 16) }), "Retry"))));
  root.appendChild(routeUnavailablePanel("Proxy / WAF candidate workspace unavailable", err, [
    { label: "Candidate policy", value: "GET /v1/policy?source=POLICY_SOURCE_CANDIDATE", detail: "Loads staged policy.proxy before browser edits." },
    { label: "Candidate status", value: "GET /v1/candidate/status", detail: "Reads dirty state and candidate revision required for guarded proxy writes." },
    { label: "Validate plan", value: "POST /v1/candidate/validate", detail: "Server-side validation renders planned proxy artifacts after candidate state is available." },
    { label: "CLI review", value: "ngfwctl policy show --source candidate --json", detail: "Export the staged proxy policy headlessly before editing." },
    { label: "CLI diff", value: "ngfwctl policy diff", detail: "Compare running and candidate policy before retrying browser edits." },
  ]));
}

function routeUnavailablePanel(title, err, rows = []) {
  return h("section", { class: "alert-box warn", dataset: { routeUnavailable: "proxy" } },
    h("strong", {}, title),
    h("div", { class: "note" }, errorMessage(err) || "The candidate session could not be loaded. Retry after the API is reachable."),
    h("div", { class: "row-actions", style: { marginTop: "12px" } },
      h("button", { class: "btn sm ghost", type: "button", title: "Retry loading this Proxy/WAF route", "aria-label": "Retry loading this Proxy/WAF route", dataset: { proxyAction: "retry-unavailable-inline" }, onclick: retryRouteLoad }, h("span", { html: icon("refresh", 14) }), "Retry"),
      h("a", { class: "btn sm ghost", href: "#/changes?tab=candidate", title: "Open Changes candidate review", "aria-label": "Open Changes candidate review", dataset: { proxyAction: "changes" } }, h("span", { html: icon("changes", 14) }), "Changes"),
      h("a", { class: "btn sm ghost", href: "#/readiness", title: "Open Readiness runtime evidence", "aria-label": "Open Readiness runtime evidence", dataset: { proxyAction: "readiness" } }, h("span", { html: icon("shield", 14) }), "Readiness")),
    responsiveTable(["Context", "Command / endpoint", "Use"], rows.map((row) => h("tr", {},
      labeledCell("Context", row.label),
      labeledCell("Command / endpoint", { class: "mono" }, row.value),
      labeledCell("Use", row.detail))), { className: "proxy-unavailable-context-table" }));
}

function retryRouteLoad() {
  globalThis.dispatchEvent(new Event("hashchange"));
}

function errorMessage(err) {
  return err?.message || String(err || "unknown error");
}

function paint(root) {
  clear(root);
  const proxy = normalizeProxy(session.draft.proxy);
  const summary = proxySummary(proxy);
  const policyCoupling = proxyPolicyCouplingModel(session.draft);
  const errors = validateProxy(proxy);
  root.appendChild(pageHead("Proxy / WAF",
    "Planned-only virtual services, WAF policies, route mapping, and backend posture staged through the candidate policy.",
    h("div", { class: "flex wrap" },
      h("button", { class: "btn", type: "button", title: "Add WAF policy", "aria-label": "Add WAF policy", dataset: { proxyAction: "add-waf" }, onclick: () => openWafEditor(root) }, h("span", { html: icon("plus", 16) }), "Add WAF"),
      h("a", { class: "btn", href: proxyHash({ ...route, drawer: "plan" }), title: "Validate server-rendered Proxy/WAF plan", "aria-label": "Validate server-rendered Proxy/WAF plan", dataset: { proxyAction: "validate-plan" } }, h("span", { html: icon("shield", 16) }), "Validate plan"),
      h("button", { class: "btn", type: "button", title: "Review Proxy/WAF listener rollout readiness", "aria-label": "Review Proxy/WAF listener rollout readiness", dataset: { proxyAction: "runtime-readiness" }, onclick: () => openRuntimeReadinessDrawer(root) }, h("span", { html: icon("terminal", 16) }), "Runtime review"),
      h("a", { class: "btn", href: proxyHash({ ...route, drawer: "policy" }), title: "Review Proxy/WAF relation to traffic policy", "aria-label": "Review Proxy/WAF relation to traffic policy", dataset: { proxyAction: "policy-coupling" } }, h("span", { html: icon("rules", 16) }), "Policy impact"),
      h("button", { class: "btn primary", type: "button", title: "Add virtual service", "aria-label": "Add virtual service", dataset: { proxyAction: "add-service" }, onclick: () => openServiceEditor(root) }, h("span", { html: icon("plus", 16) }), "Add service"))));
  root.appendChild(summaryCard(summary, errors));
  root.appendChild(policyCouplingCard(policyCoupling));
  root.appendChild(tabBar());
  root.appendChild(route.tab === "waf" ? wafPoliciesCard(root, proxy.wafPolicies) : virtualServicesCard(root, proxy));
}

async function openRuntimeReadinessDrawer(root) {
  const body = h("div", { dataset: { proxyRuntimeReadiness: "loading" } },
    h("div", { class: "loading" }, "Validating candidate and reading runtime context..."));
  openDrawer({
    title: "Proxy / WAF runtime-readiness review",
    subtitle: "Operator rollout review only; this does not launch a listener or prove active traffic.",
    width: "820px",
    body,
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close Proxy/WAF runtime review", "aria-label": "Close Proxy/WAF runtime review", dataset: { proxyRuntimeAction: "close" }, onclick: closeDrawer }, "Close"),
      h("a", { class: "btn", href: "#/changes?tab=candidate", title: "Open Changes candidate review", "aria-label": "Open Changes candidate review", dataset: { proxyRuntimeLink: "changes" } }, h("span", { html: icon("changes", 14) }), "Changes"),
      h("a", { class: "btn primary", href: "#/readiness", title: "Open Readiness runtime evidence", "aria-label": "Open Readiness runtime evidence", dataset: { proxyRuntimeLink: "readiness" } }, h("span", { html: icon("shield", 14) }), "Readiness"),
    ],
  });
  try {
    const [validationR, statusR] = await Promise.allSettled([session.validate(), api.status()]);
    const validation = validationR.status === "fulfilled" ? validationR.value : { valid: false, errors: [validationR.reason?.message || String(validationR.reason || "Candidate validation failed.")] };
    const status = statusR.status === "fulfilled" ? statusR.value : null;
    const model = proxyRuntimeReadinessModel({
      candidateProxy: session.draft.proxy,
      runningProxy: session.running.proxy,
      candidateStatus: session.candidateStatus,
      candidateRevision: session.candidateRevision,
      runningVersion: session.runningVersion,
      status,
      validation,
    });
    model.artifactManifest = proxyRuntimeArtifactManifest(validation);
    clear(body);
    body.dataset.proxyRuntimeReadiness = model.readiness;
    body.appendChild(renderRuntimeReadiness(model));
    toast("Proxy runtime review generated", model.label, model.cls === "bad" ? "warn" : "ok");
    if (root?.isConnected) paint(root);
  } catch (err) {
    clear(body);
    body.dataset.proxyRuntimeReadiness = "error";
    body.appendChild(h("div", { class: "alert-box bad" },
      h("strong", {}, "Runtime-readiness review failed."),
      h("div", { class: "note" }, err?.message || String(err || "Unknown runtime-readiness error."))));
    toast("Proxy runtime review error", err?.message || String(err), "bad");
  }
}

function renderRuntimeReadiness(model) {
  const packet = proxyRuntimeReadinessPacket(model);
  const activeChecklist = proxyActiveRolloutChecklist(model);
  return h("div", { class: "proxy-runtime-readiness-body" },
    h("div", { class: "alert-box " + (model.cls === "bad" ? "bad" : model.cls === "warn" ? "warn" : "info") },
      h("strong", {}, `Listener rollout readiness: ${model.label}`),
      h("div", { class: "note" }, model.boundary)),
    h("div", { class: "runtime-grid", style: { marginTop: "12px" } },
      metric("Candidate proxy", `${model.candidateSummary.virtualServices} service(s) / ${model.candidateSummary.wafPolicies} WAF`),
      metric("Running proxy", `${model.runningSummary.virtualServices} service(s) / ${model.runningSummary.wafPolicies} WAF`),
      metric("Candidate revision", model.candidateRevision ? h("span", { class: "mono" }, model.candidateRevision) : "unavailable"),
      metric("Running policy", model.runningVersion ? h("span", { class: "mono" }, `v${model.runningVersion}`) : "unknown"),
      metric("Validation", pill(model.validation.valid ? "valid" : "blocked", model.validation.valid ? "ok" : "bad")),
      metric("Proxy artifact", pill(model.validation.proxyArtifactPresent ? "present" : "missing", model.validation.proxyArtifactPresent ? "ok" : "warn"))),
    h("dl", { class: "kv", style: { marginTop: "12px" } },
      h("dt", {}, "Candidate status"), h("dd", {}, model.candidateDirty ? pill("pending changes", "warn") : pill("matches running", "neutral")),
      h("dt", {}, "Proxy delta"), h("dd", {}, model.proxyChanged ? pill("proxy changed", "warn") : pill("no proxy delta", "neutral")),
      h("dt", {}, "Active daemon boundary"), h("dd", {}, h("strong", {}, "not started here"), h("div", { class: "note" }, "This review reads validation/status context only; it does not launch, restart, reload, or stop Envoy, Coraza, nftables, load balancers, or health probes.")),
      h("dt", {}, "Runtime context"), h("dd", {}, h("span", {}, "reported state: "), pill(model.runtime.state || "not-reported", model.runtime.observed ? "info" : "warn"), h("div", { class: "note" }, "Context only; not accepted as listener traffic proof.")),
      h("dt", {}, "Runtime boundary"), h("dd", {}, model.runtime.proofBoundary)),
    h("div", { class: "impact-section-head" },
      h("strong", {}, "Blockers and required handoffs"),
      h("span", {}, `${model.blockers.length} item(s)`)),
    model.blockers.length ? h("ul", { class: "compact-list", dataset: { proxyRuntimeBlockers: "true" } },
      model.blockers.slice(0, 14).map((item) => h("li", {}, h("strong", {}, item.title), h("div", { class: "note" }, item.detail)))) :
      h("div", { class: "alert-box warn" }, "No blockers were produced, but runtime traffic proof and daemon launch remain outside this drawer."),
    responsiveTable(["Handoff", "Target"], model.handoffLinks.map((link) => h("tr", {},
      labeledCell("Handoff", link.label),
      labeledCell("Target", h("a", { href: link.href }, link.href)))), { className: "proxy-runtime-handoff-table" }),
    responsiveTable(["Review command", "Boundary"], model.reviewCommands.map((command) => h("tr", {},
      labeledCell("Review command", { class: "mono" }, command),
      labeledCell("Boundary", "Operator handoff only; run through existing CLI/API workflow."))), { className: "proxy-runtime-command-table" }),
    renderRuntimeArtifactManifest(model),
    renderFunctionalRuntimeProofArtifacts(model),
    h("div", { class: "impact-section-head" },
      h("strong", {}, "Active runtime rollout handoff"),
      h("span", {}, "planning checklist")),
    h("div", { class: "alert-box warn" },
      h("strong", {}, "No daemon action is started from this drawer."),
      h("div", { class: "note" }, "Use this checklist as the handoff boundary for the active rollout runbook. Listener health, Envoy/Coraza launch, rollback, traffic cutover, and artifact manifest hashes all require external proof before promotion.")),
    responsiveTable(["Gate", "Required proof", "Status"], activeChecklist.map((item) => h("tr", { dataset: { proxyActiveRolloutGate: item.id } },
      labeledCell("Gate", h("strong", {}, item.gate), h("div", { class: "note" }, item.boundary)),
      labeledCell("Required proof", item.requiredProof),
      labeledCell("Status", pill(item.statusLabel, item.statusClass)))), { className: "proxy-active-rollout-table" }),
    h("div", { class: "alert-box warn", style: { marginTop: "12px" } },
      h("strong", {}, "Explicit boundary"),
      h("div", { class: "note" }, "This packet is redacted browser-side review context. It does not prove active listener traffic, WAF enforcement, release evidence, or Envoy/Coraza daemon launch.")),
    h("div", { class: "row-actions", style: { marginTop: "12px" } },
      h("button", { class: "btn sm ghost", type: "button", title: "Pin Proxy/WAF runtime-readiness handoff to the active investigation case", "aria-label": "Pin Proxy/WAF runtime-readiness handoff to the active investigation case", dataset: { proxyRuntimeAction: "pin-packet" }, onclick: () => pinRuntimeReadinessPacket(model) }, h("span", { html: icon("inbox", 14) }), "Pin to case"),
      h("button", { class: "btn sm ghost", type: "button", title: "Copy Proxy/WAF runtime-readiness packet", "aria-label": "Copy Proxy/WAF runtime-readiness packet", dataset: { proxyRuntimeAction: "copy-packet" }, onclick: () => copyRuntimeReadinessPacket(model) }, h("span", { html: icon("copy", 14) }), "Copy packet"),
      h("button", { class: "btn sm ghost", type: "button", title: "Export Proxy/WAF runtime-readiness packet", "aria-label": "Export Proxy/WAF runtime-readiness packet", dataset: { proxyRuntimeAction: "export-packet" }, onclick: () => exportRuntimeReadinessPacket(model) }, h("span", { html: icon("download", 14) }), "Export packet"),
      h("a", { class: "btn sm ghost", href: activeInvestigationServerCaseHref(), title: "Open active investigation case", "aria-label": "Open active investigation case", dataset: { proxyRuntimeAction: "open-active-case" } }, h("span", { html: icon("search", 14) }), "Open active case")),
    h("pre", { class: "mono", style: { maxHeight: "260px", overflow: "auto", whiteSpace: "pre-wrap", overflowWrap: "anywhere", marginTop: "12px" }, dataset: { proxyRuntimePacketPreview: "true" } }, JSON.stringify(packet, null, 2)));
}

function renderRuntimeArtifactManifest(model = {}) {
  const manifest = model.artifactManifest || { artifacts: [] };
  const rows = manifest.artifacts || [];
  return h("section", { class: "proxy-runtime-artifact-manifest", style: { marginTop: "16px" }, dataset: { proxyRuntimeArtifactManifest: manifest.proxyArtifactPresent ? "proxy-present" : "proxy-missing" } },
    h("div", { class: "impact-section-head" },
      h("strong", {}, "Artifact manifest and hash review"),
      h("span", {}, manifest.proxyArtifactPresent ? "proxy artifact reported" : "proxy artifact missing")),
    h("div", { class: "alert-box " + (manifest.proxyArtifactPresent ? "warn" : "bad") },
      h("strong", {}, "Manifest visibility is review evidence, not daemon evidence."),
      h("div", { class: "note" }, "Record each artifact name, engine, size, SHA-256/digest when present, and source validation response before any active rollout. Missing hashes stay release blockers until recorded by release evidence tooling.")),
    rows.length ? responsiveTable(["Artifact", "Engine", "Size", "Hash", "Proxy"], rows.map((artifact) => h("tr", { dataset: { proxyRuntimeArtifact: artifact.name || artifact.engine || "artifact" } },
      labeledCell("Artifact", { class: "mono" }, artifact.name || "artifact"),
      labeledCell("Engine", artifact.engine || "unknown"),
      labeledCell("Size", { class: "mono" }, `${artifact.sizeBytes || 0} bytes`),
      labeledCell("Hash", artifact.sha256 ? h("span", { class: "mono" }, artifact.sha256) : pill("missing hash", "bad")),
      labeledCell("Proxy", artifact.proxy ? pill("yes", "ok") : pill("no", "neutral")))), { className: "proxy-runtime-artifact-table responsive-evidence" }) :
      h("div", { class: "alert-box bad", style: { marginTop: "12px" } }, "Validation did not return artifact metadata for the runtime packet."),
    h("dl", { class: "kv", style: { marginTop: "12px" } },
      h("dt", {}, "Manifest source"), h("dd", {}, manifest.source || "candidate validation render plan"),
      h("dt", {}, "Artifact count"), h("dd", { class: "mono" }, String(manifest.artifactCount || rows.length || 0)),
      h("dt", {}, "Total bytes"), h("dd", { class: "mono" }, String(manifest.totalBytes || 0)),
      h("dt", {}, "Hash boundary"), h("dd", {}, manifest.hashBoundary || "hashes must be confirmed by release evidence tooling before promotion")));
}

function renderFunctionalRuntimeProofArtifacts(model = {}) {
  const proofArtifacts = proxyFunctionalRuntimeProofArtifacts(model);
  return h("section", { class: "proxy-functional-runtime-proof", style: { marginTop: "16px" }, dataset: { proxyFunctionalRuntimeProof: "planned-not-executed" } },
    h("div", { class: "impact-section-head" },
      h("strong", {}, "Functional runtime proof artifacts"),
      h("span", {}, `${proofArtifacts.length} planned fields`)),
    h("div", { class: "alert-box warn" },
      h("strong", {}, "Proof fields are modeled, not executed."),
      h("div", { class: "note" }, "Daemon, listener, cutover, and rollback entries give operators reviewable evidence targets. They are not TLS custody, signing, HA traffic proof, or production rollout evidence.")),
    responsiveTable(["Artifact", "Status", "Evidence", "Boundary"], proofArtifacts.map((item) => h("tr", { dataset: { proxyFunctionalProofArtifact: item.id } },
      labeledCell("Artifact", h("strong", {}, item.kind), h("div", { class: "note" }, item.id)),
      labeledCell("Status", pill(item.status, item.status === "planned-not-executed" ? "warn" : "bad")),
      labeledCell("Evidence", h("ul", { class: "compact-list" }, item.evidence.map((entry) => h("li", {}, entry)))),
      labeledCell("Boundary", item.boundary))), { className: "proxy-functional-runtime-proof-table" }));
}

function summaryCard(summary, errors) {
  const dirty = !equal((session.running || {}).proxy || {}, (session.draft || {}).proxy || {});
  return card(h("h2", {}, "Plan summary", h("span", { class: "spacer" }), pill("planned only", "warn", true)),
    h("div", { class: "alert-box warn" },
      h("strong", {}, "This workspace authors candidate policy only."),
      h("div", { class: "note" }, "Validation renders an Envoy/Coraza-style proxy plan artifact. Running traffic redirection, TLS key custody, backend mTLS proof, and HA listener proof remain separate production work.")),
    h("div", { class: "runtime-grid", style: { marginTop: "12px" } },
      metric("Candidate state", dirty ? pill("pending proxy change", "warn") : pill("matches running", "neutral")),
      metric("Virtual services", String(summary.virtualServices)),
      metric("Routes", String(summary.routes)),
      metric("Backends", String(summary.backends)),
      metric("WAF policies", String(summary.wafPolicies)),
      metric("WAF-attached routes", String(summary.attachedWafRoutes))),
    errors.length ? h("div", { class: "alert-box bad", style: { marginTop: "12px" } },
      h("strong", {}, "Client validation matches server proxy validation."),
      h("ul", {}, errors.slice(0, 8).map((error) => h("li", {}, error))),
      errors.length > 8 ? h("div", { class: "note" }, `${errors.length - 8} more issue(s) hidden.`) : null) : null);
}

function policyCouplingCard(model) {
  const cls = model.summary.warnings ? "warn" : model.summary.findings ? "info" : "neutral";
  return card(h("h2", {}, "Traffic policy coupling", h("span", { class: "spacer" }), pill(model.summary.warnings ? `${model.summary.warnings} review` : "reviewable", cls)),
    h("div", { class: "alert-box " + (model.summary.warnings ? "warn" : "info"), dataset: { proxyPolicyCouplingSummary: "true" } },
      h("strong", {}, "Candidate-safe impact review"),
      h("div", { class: "note" }, "Relates planned virtual services and WAF routes to allow rules, App-ID port hints, static routes, and inspection profiles without launching listeners or handling TLS keys.")),
    h("div", { class: "runtime-grid", style: { marginTop: "12px" } },
      metric("Enabled services", String(model.summary.enabledServices)),
      metric("Findings", String(model.summary.findings)),
      metric("Warnings", String(model.summary.warnings)),
      metric("Review route", h("a", { href: proxyHash({ ...route, drawer: "policy" }), dataset: { proxyPolicyCouplingRoute: "true" } }, "Open impact review"))),
    model.findings.length ? h("ul", { class: "compact-list", style: { marginTop: "12px" } },
      model.findings.slice(0, 4).map((finding) => h("li", {}, h("strong", {}, `${finding.dimension}: `), finding.message)),
      model.findings.length > 4 ? h("li", { class: "note" }, `${model.findings.length - 4} more finding(s) in the route-backed drawer.`) : null) : null);
}

function openPolicyCouplingDrawer(root, { routeBacked = false } = {}) {
  const model = proxyPolicyCouplingModel(session.draft);
  const packet = proxyPolicyCouplingPacket(model);
  openDrawer({
    title: "Proxy / WAF traffic-policy impact",
    subtitle: "candidate-safe review of planned L7 intent against rules, routes, App-ID, and inspection context.",
    width: "860px",
    body: renderPolicyCoupling(model, packet),
    onClose: routeBacked ? clearPolicyDrawerRoute : null,
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close policy impact review", "aria-label": "Close policy impact review", dataset: { proxyPolicyAction: "close" }, onclick: closeDrawer }, "Close"),
      h("button", { class: "btn", type: "button", title: "Copy Proxy/WAF policy impact packet", "aria-label": "Copy Proxy/WAF policy impact packet", dataset: { proxyPolicyAction: "copy-packet" }, onclick: () => copyPolicyCouplingPacket(model) }, h("span", { html: icon("copy", 14) }), "Copy packet"),
      h("a", { class: "btn", href: "#/rules", title: "Open Rules affected by Proxy/WAF policy impact", "aria-label": "Open Rules affected by Proxy/WAF policy impact", dataset: { proxyPolicyLink: "rules" } }, h("span", { html: icon("rules", 14) }), "Rules"),
      h("a", { class: "btn primary", href: "#/traffic", title: "Open Traffic App-ID review for Proxy/WAF policy impact", "aria-label": "Open Traffic App-ID review for Proxy/WAF policy impact", dataset: { proxyPolicyLink: "traffic" } }, h("span", { html: icon("traffic", 14) }), "Traffic"),
    ],
  });
  if (root?.isConnected) paint(root);
}

function renderPolicyCoupling(model, packet) {
  return h("div", { class: "proxy-policy-coupling-body", dataset: { proxyPolicyCoupling: model.schemaVersion } },
    h("div", { class: "alert-box " + (model.summary.warnings ? "warn" : "info") },
      h("strong", {}, model.summary.warnings ? "Policy coupling needs review before cutover." : "Policy coupling is reviewable from the candidate."),
      h("div", { class: "note" }, model.workflow)),
    h("div", { class: "runtime-grid", style: { marginTop: "12px" } },
      metric("Virtual services", String(model.summary.services)),
      metric("Enabled", String(model.summary.enabledServices)),
      metric("Findings", String(model.summary.findings)),
      metric("Warnings", String(model.summary.warnings))),
    responsiveTable(["Service", "Listener", "Rules/App-ID", "Inspection", "Routes"], model.services.map((service) => h("tr", { dataset: { proxyPolicyService: service.name } },
      labeledCell("Service", h("strong", {}, service.name), h("div", { class: "note" }, service.enabled ? "enabled candidate service" : "disabled candidate service")),
      labeledCell("Listener", h("span", { class: "mono" }, service.listener), h("div", { class: "note" }, service.hostnames.join(", ") || "no hostnames")),
      labeledCell("Rules/App-ID", service.serviceRules.length || service.appRules.length ? [
        service.serviceRules.length ? h("div", {}, h("strong", {}, "Service: "), service.serviceRules.join(", ")) : null,
        service.appRules.length ? h("div", {}, h("strong", {}, "App-ID: "), service.appRules.join(", ")) : null,
      ] : pill("no listener allow match", "warn")),
      labeledCell("Inspection", service.inspectionRules.length ? service.inspectionRules.join(", ") : pill("no inline profile match", "warn")),
      labeledCell("Routes", service.routes.length ? service.routes.map((item) => h("div", { class: "note" }, `${item.pathPrefix} -> ${item.backendCount} backend(s), ${item.wafPolicy || "no WAF"}`)) : "none"))), { className: "proxy-policy-coupling-table responsive-evidence" }),
    h("div", { class: "impact-section-head" },
      h("strong", {}, "Validation findings"),
      h("span", {}, `${model.findings.length} item(s)`)),
    model.findings.length ? responsiveTable(["Severity", "Scope", "Dimension", "Finding"], model.findings.map((finding) => h("tr", { dataset: { proxyPolicyFinding: finding.dimension } },
      labeledCell("Severity", pill(finding.severity, finding.severity === "warning" ? "warn" : "info")),
      labeledCell("Scope", [finding.virtualService, finding.route].filter(Boolean).join(" / ") || "proxy"),
      labeledCell("Dimension", finding.dimension),
      labeledCell("Finding", finding.message))), { className: "proxy-policy-findings-table responsive-evidence" }) :
      h("div", { class: "alert-box info" }, "No coupling findings were produced for the current candidate."),
    responsiveTable(["Context", "Route"], model.reviewLinks.map((link) => h("tr", {},
      labeledCell("Context", link.label),
      labeledCell("Route", h("a", { href: link.href }, link.href)))), { className: "proxy-policy-links-table" }),
    h("div", { class: "alert-box warn", style: { marginTop: "12px" } },
      h("strong", {}, "Hardening deferred"),
      h("div", { class: "note" }, "This review does not start active listeners, alter firewall rules, change routes, take TLS key custody, inspect packets, or prove WAF enforcement.")),
    h("pre", { class: "mono", style: { maxHeight: "260px", overflow: "auto", whiteSpace: "pre-wrap", overflowWrap: "anywhere", marginTop: "12px" }, dataset: { proxyPolicyPacketPreview: "true" } }, JSON.stringify(packet, null, 2)));
}

function tabBar() {
  return h("div", { class: "tabs", style: { marginBottom: "16px" } },
    tabLink("services", "Virtual services"),
    tabLink("waf", "WAF policies"),
    h("a", { class: "btn sm ghost", href: "#/changes?tab=candidate", title: "Open candidate review", "aria-label": "Open candidate review", dataset: { proxyAction: "candidate-review" } }, h("span", { html: icon("changes", 14) }), "Candidate review"),
    h("a", { class: "btn sm ghost", href: "#/readiness", title: "Open readiness", "aria-label": "Open readiness", dataset: { proxyAction: "readiness" } }, h("span", { html: icon("shield", 14) }), "Readiness"));
}

async function openPlanProofDrawer(root, { routeBacked = false } = {}) {
  const body = h("div", { dataset: { proxyPlanProof: "loading" } },
    h("div", { class: "loading" }, "Validating candidate and reading server render-plan metadata..."));
  openDrawer({
    title: "Proxy / WAF plan proof",
    subtitle: "Server-side validation only; no listener, redirect, or active traffic rollout is started.",
    width: "760px",
    body,
    onClose: routeBacked ? clearPlanDrawerRoute : null,
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close proxy plan proof", "aria-label": "Close proxy plan proof", dataset: { proxyAction: "close-plan-proof" }, onclick: closeDrawer }, "Close"),
      h("a", { class: "btn", href: "#/changes?tab=candidate", title: "Open Changes candidate review for Proxy/WAF plan", "aria-label": "Open Changes candidate review for Proxy/WAF plan", dataset: { proxyPlanLink: "changes" } }, h("span", { html: icon("changes", 14) }), "Changes"),
      h("a", { class: "btn primary", href: "#/readiness", title: "Open Readiness evidence for Proxy/WAF plan", "aria-label": "Open Readiness evidence for Proxy/WAF plan", dataset: { proxyPlanLink: "readiness" } }, h("span", { html: icon("shield", 14) }), "Readiness"),
    ],
  });

  try {
    const validation = await session.validate();
    const model = proxyPlanProofModel(validation, session.draft.proxy);
    clear(body);
    body.dataset.proxyPlanProof = "ready";
    body.dataset.proxyArtifactPresent = model.proxyArtifactPresent ? "true" : "false";
    body.appendChild(renderPlanProof(model));
    toast(model.proxyArtifactPresent ? "Proxy plan validated" : "Proxy validation complete",
      model.proxyArtifactPresent ? "Server render-plan metadata includes the proxy artifact." : "Validation completed without a proxy artifact in the render plan.",
      model.cls === "ok" ? "ok" : "warn");
    if (root?.isConnected) paint(root);
  } catch (err) {
    clear(body);
    body.dataset.proxyPlanProof = "error";
    body.appendChild(h("div", { class: "alert-box bad" },
      h("strong", {}, "Plan validation failed."),
      h("div", { class: "note" }, err?.message || String(err || "Unknown validation error."))));
    toast("Proxy plan validation error", err?.message || String(err), "bad");
  }
}

function renderPlanProof(model) {
  const errorList = [...(model.clientErrors || []), ...(model.validationErrors || [])];
  return h("div", { class: "proxy-plan-proof-body" },
    h("div", { class: "alert-box " + (model.cls === "ok" ? "ok" : model.cls === "warn" ? "warn" : "bad") },
      h("strong", {}, model.status),
      h("div", { class: "note" }, model.proxyArtifactPresent
        ? "The existing validation API returned proxy render-plan metadata. Artifact bytes remain server-side."
        : "The validation response did not include a proxy artifact. Review whether the candidate contains proxy policy before rollout planning.")),
    h("dl", { class: "kv" },
      h("dt", {}, "Validation"), h("dd", {}, pill(model.valid ? "valid" : "blocked", model.valid ? "ok" : "bad")),
      h("dt", {}, "Proxy artifact"), h("dd", {}, pill(model.proxyArtifactPresent ? "present" : "missing", model.proxyArtifactPresent ? "ok" : "warn")),
      h("dt", {}, "Artifacts"), h("dd", { class: "mono" }, `${model.artifactCount} rendered / ${model.totalBytes} bytes`),
      h("dt", {}, "Artifact exposure"), h("dd", {}, model.previews.length ? "bounded review snippets" : "metadata only")),
    model.artifacts.length ? h("div", { class: "table-wrap flat", style: { marginTop: "12px" } },
      responsiveTable(["Artifact", "Engine", "Size", "Proxy"], model.artifacts.map((artifact) => h("tr", { dataset: { proxyPlanArtifact: artifact.name || artifact.engine || "artifact" } },
        labeledCell("Artifact", { class: "mono" }, artifact.name || "artifact"),
        labeledCell("Engine", {}, artifact.engine || "engine"),
        labeledCell("Size", { class: "mono" }, `${artifact.sizeBytes || 0} bytes`),
        labeledCell("Proxy", {}, artifact === model.proxyArtifact ? pill("yes", "ok") : pill("no", "neutral")))), { className: "proxy-plan-artifact-table" })) :
      h("div", { class: "alert-box warn", style: { marginTop: "12px" } }, "No rendered artifact metadata was returned by validation."),
    errorList.length ? h("div", { class: "alert-box bad", style: { marginTop: "12px" } },
      h("strong", {}, "Blockers"),
      h("ul", {}, errorList.slice(0, 10).map((error) => h("li", {}, error)))) : null,
    h("div", { class: "impact-section-head" },
      h("strong", {}, "Hardening notes"),
      h("span", {}, `${model.hardeningNotes.length} required before active rollout`)),
    h("ul", { class: "compact-list" }, model.hardeningNotes.map((note) => h("li", {}, note))),
    renderArtifactPreviews(model),
    h("div", { class: "row-actions", style: { marginTop: "12px" } },
      model.links.map((link) => h("a", { class: "btn sm ghost", href: link.href, title: `Open ${link.label} for Proxy/WAF plan proof`, "aria-label": `Open ${link.label} for Proxy/WAF plan proof`, dataset: { proxyPlanProofLink: link.label.toLowerCase() } }, link.label))));
}

function renderArtifactPreviews(model) {
  if (!model.previews.length) {
    return h("div", { class: "alert-box warn", style: { marginTop: "12px" } },
      h("strong", {}, "No artifact preview available."),
      h("div", { class: "note" }, "Validation only returned render metadata, and the candidate proxy section is empty."));
  }
  return h("section", { class: "proxy-artifact-preview", style: { marginTop: "16px" }, dataset: { proxyArtifactPreview: "review-only" } },
    h("div", { class: "impact-section-head" },
      h("strong", {}, "Artifact preview"),
      h("span", {}, "review-only, bounded, redacted")),
    h("div", { class: "alert-box warn" },
      h("strong", {}, "Preview is not runtime evidence."),
      h("div", { class: "note" }, "These snippets are for operator review and handoff only. They do not prove an active listener, WAF enforcement, traffic redirection, signing custody, or daemon launch.")),
    model.previews.map((preview) => artifactPreviewPanel(preview)),
    h("div", { class: "row-actions", style: { marginTop: "12px" } },
      h("button", { class: "btn sm ghost", type: "button", title: "Pin bounded Proxy/WAF artifact preview to the active investigation case", "aria-label": "Pin bounded Proxy/WAF artifact preview to the active investigation case", dataset: { proxyArtifactAction: "pin-packet" }, onclick: () => pinPreviewPacket(model) }, h("span", { html: icon("inbox", 14) }), "Pin to case"),
      h("button", { class: "btn sm ghost", type: "button", title: "Copy bounded Proxy/WAF artifact preview packet", "aria-label": "Copy bounded Proxy/WAF artifact preview packet", dataset: { proxyArtifactAction: "copy-packet" }, onclick: () => copyPreviewPacket(model) }, h("span", { html: icon("copy", 14) }), "Copy packet"),
      h("button", { class: "btn sm ghost", type: "button", title: "Export bounded Proxy/WAF artifact preview packet", "aria-label": "Export bounded Proxy/WAF artifact preview packet", dataset: { proxyArtifactAction: "export-packet" }, onclick: () => exportPreviewPacket(model) }, h("span", { html: icon("download", 14) }), "Export packet"),
      h("a", { class: "btn sm ghost", href: activeInvestigationServerCaseHref(), title: "Open active investigation case", "aria-label": "Open active investigation case", dataset: { proxyArtifactAction: "open-active-case" } }, h("span", { html: icon("search", 14) }), "Open active case")));
}

function artifactPreviewPanel(preview) {
  const meta = [
    preview.source === "validation-render" ? "server preview" : "deterministic candidate snippet",
    preview.redacted ? "redacted" : "no secret-like fields found",
    preview.truncated ? `truncated to ${preview.maxLines} lines / ${preview.maxChars} chars` : `${preview.totalLines} lines`,
  ].join(" · ");
  return h("div", { class: "artifact-preview-panel", dataset: { proxyArtifactSnippet: preview.id || preview.filename }, style: { marginTop: "12px" } },
    h("div", { class: "impact-section-head" },
      h("strong", {}, preview.label || preview.filename || "Artifact snippet"),
      h("span", { class: "mono" }, preview.filename || "artifact.txt")),
    h("dl", { class: "kv" },
      h("dt", {}, "Source"), h("dd", {}, preview.source === "validation-render" ? "validation render output" : "candidate-derived fallback"),
      h("dt", {}, "Engine"), h("dd", {}, preview.engine || "proxy"),
      h("dt", {}, "Bounds"), h("dd", {}, meta),
      preview.sha256 ? [h("dt", {}, "SHA256"), h("dd", { class: "mono" }, preview.sha256)] : null),
    h("pre", { class: "mono", style: { maxHeight: "320px", overflow: "auto", whiteSpace: "pre-wrap", overflowWrap: "anywhere", margin: "10px 0" }, dataset: { proxyArtifactPreviewText: preview.id || preview.filename } }, preview.text),
    h("div", { class: "row-actions" },
      h("button", { class: "btn sm ghost", type: "button", title: `Copy ${preview.label || "artifact preview"}`, "aria-label": `Copy ${preview.label || "artifact preview"}`, dataset: { proxyArtifactAction: "copy-snippet" }, onclick: () => copyPreviewSnippet(preview) }, h("span", { html: icon("copy", 14) }), "Copy"),
      h("button", { class: "btn sm ghost", type: "button", title: `Download ${preview.label || "artifact preview"}`, "aria-label": `Download ${preview.label || "artifact preview"}`, dataset: { proxyArtifactAction: "download-snippet" }, onclick: () => downloadPreviewSnippet(preview) }, h("span", { html: icon("download", 14) }), "Download")));
}

async function copyPreviewSnippet(preview) {
  if (await copyText(safePreviewSnippetText(preview))) toast("Artifact preview copied", `${preview.filename || "Snippet"} copied to clipboard.`, "ok");
  else toast("Copy failed", "Select the preview text and copy it manually.", "warn");
}

function downloadPreviewSnippet(preview) {
  downloadText(preview.filename || "proxy-artifact-preview.txt", safePreviewSnippetText(preview), contentTypeForPreview(preview));
  toast("Artifact preview exported", preview.filename || "proxy-artifact-preview.txt", "ok");
}

function safePreviewSnippetText(preview = {}) {
  return boundedArtifactSnippet(preview.text || "", {
    maxChars: Number(preview.maxChars) || undefined,
    maxLines: Number(preview.maxLines) || undefined,
  }).text;
}

async function copyPreviewPacket(model) {
  const packet = proxyPreviewPacket(model);
  if (await copyText(JSON.stringify(packet, null, 2))) toast("Preview packet copied", "Bounded Proxy/WAF preview packet copied to clipboard.", "ok");
  else toast("Copy failed", "Export the packet or copy the preview snippets manually.", "warn");
}

function exportPreviewPacket(model) {
  downloadText("proxy-waf-artifact-preview.json", JSON.stringify(proxyPreviewPacket(model), null, 2) + "\n", "application/json");
  toast("Preview packet exported", "proxy-waf-artifact-preview.json", "ok");
}

async function pinPreviewPacket(model) {
  const packet = proxyPreviewInvestigationPacket(model);
  try {
    const serverResult = await appendInvestigationPacketToActiveServerCase(packet, {
      appendEvidence: (id, evidence) => api.addInvestigationCaseEvidence(id, evidence),
    });
    if (serverResult.appended) {
      toast("Evidence appended", `Proxy/WAF preview evidence appended to ${serverResult.activeCaseId}.`, "ok");
      return;
    }
  } catch {
    try {
      const result = pinInvestigationPacket(packet);
      toast("Server append unavailable", `${result.toastDetail} Local fallback was used.`, "warn");
    } catch (fallbackError) {
      toast("Pin failed", fallbackError.message || "Selected Proxy/WAF preview evidence could not be pinned.", "bad");
    }
    return;
  }
  try {
    const result = pinInvestigationPacket(packet);
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Selected Proxy/WAF preview evidence could not be pinned.", "bad");
  }
}

export function proxyPreviewInvestigationPacket(model = {}, options = {}) {
  const previewPacket = proxyPreviewPacket(model);
  const primary = model.previews?.[0] || {};
  return buildInvestigationPacket({
    kind: "proxy-waf-preview",
    title: "Proxy/WAF artifact preview handoff",
    subject: {
      id: primary.id || primary.filename || "proxy-waf-plan",
      label: model.proxyArtifactPresent ? "Proxy/WAF render-plan artifact" : "Proxy/WAF validation preview",
    },
    summary: {
      validation: model.valid ? "valid" : "blocked",
      status: model.status || "",
      proxyArtifactPresent: Boolean(model.proxyArtifactPresent),
      artifactCount: model.artifactCount || 0,
      totalBytes: model.totalBytes || 0,
      previewCount: model.previews?.length || 0,
      artifactExposure: model.previews?.length ? "bounded redacted snippets" : "metadata only",
      custodyBoundary: "review-only handoff; not active listener, WAF enforcement, daemon launch, signing custody, or traffic cutover evidence",
    },
    evidence: [
      `validation=${model.valid ? "valid" : "blocked"}`,
      `proxy_artifact=${model.proxyArtifactPresent ? "present" : "missing"}`,
      `artifact_count=${model.artifactCount || 0}`,
      `preview_count=${model.previews?.length || 0}`,
      "artifact_preview=bounded redacted review snippets only",
      "workflow_boundary=no active listener, WAF enforcement, daemon launch, signing, or traffic cutover evidence",
    ],
    artifacts: {
      proxyPreview: previewPacket,
      hardeningNotes: model.hardeningNotes || [],
    },
  }, { route: options.route || currentProxyRouteHash() });
}

export function proxyRuntimeReadinessInvestigationPacket(model = {}, options = {}) {
  const runtimePacket = proxyRuntimeReadinessPacket(model);
  return buildInvestigationPacket({
    kind: "proxy-waf-runtime-readiness",
    title: "Proxy/WAF runtime-readiness handoff",
    subject: {
      id: runtimePacket.candidateRevision || "proxy-waf-runtime-readiness",
      label: "Proxy/WAF listener rollout readiness review",
    },
    summary: {
      readiness: model.readiness || "unknown",
      label: runtimePacket.label || "unknown",
      candidateRevision: runtimePacket.candidateRevision || "",
      runningVersion: model.runningVersion || 0,
      candidateDirty: Boolean(model.candidateDirty),
      proxyChanged: Boolean(model.proxyChanged),
      blockerCount: model.blockers?.length || 0,
      functionalProofArtifactCount: runtimePacket.functionalProofArtifacts?.length || 0,
      custodyBoundary: runtimePacket.workflow || "runtime-readiness review only; not active listener traffic proof or daemon launch",
    },
    evidence: [
      `readiness=${model.readiness || "unknown"}`,
      `candidate_revision=${runtimePacket.candidateRevision || "unavailable"}`,
      `running_policy=${model.runningVersion ? `v${model.runningVersion}` : "unknown"}`,
      `candidate_proxy_services=${model.candidateSummary?.virtualServices || 0}`,
      `candidate_waf_policies=${model.candidateSummary?.wafPolicies || 0}`,
      `validation=${model.validation?.valid ? "valid" : "blocked"}`,
      `proxy_artifact=${model.validation?.proxyArtifactPresent ? "present" : "missing"}`,
      `functional_proof_artifacts=${runtimePacket.functionalProofArtifacts?.length || 0}`,
      "workflow_boundary=no active listener traffic proof, WAF enforcement proof, daemon launch, TLS key custody, backend mTLS handshake, HA listener failover, signing custody, or traffic cutover evidence",
    ],
    artifacts: {
      runtimeReadiness: runtimePacket,
      functionalProofArtifacts: runtimePacket.functionalProofArtifacts || [],
      handoffLinks: runtimePacket.handoffLinks || [],
      reviewCommands: runtimePacket.reviewCommands || [],
    },
  }, { route: options.route || currentProxyRouteHash() });
}

function proxyPreviewPacket(model) {
  return {
    schemaVersion: "openngfw.proxy.artifact-preview.v1",
    workflow: "review-only bounded artifact preview; not live listener, WAF enforcement, daemon launch, signing, or traffic cutover evidence",
    validation: {
      valid: model.valid,
      status: model.status,
      proxyArtifactPresent: model.proxyArtifactPresent,
      artifactCount: model.artifactCount,
      totalBytes: model.totalBytes,
    },
    previews: (model.previews || []).map((preview) => {
      const bounded = boundedArtifactSnippet(preview.text || "", {
        maxChars: Number(preview.maxChars) || undefined,
        maxLines: Number(preview.maxLines) || undefined,
      });
      return {
      id: preview.id,
      label: preview.label,
      engine: preview.engine,
      source: preview.source,
      filename: preview.filename,
      language: preview.language,
        redacted: true,
        truncated: Boolean(preview.truncated || bounded.truncated),
        bounds: { maxChars: bounded.maxChars, maxLines: bounded.maxLines, totalChars: bounded.totalChars, totalLines: bounded.totalLines },
        text: bounded.text,
      };
    }),
    hardeningNotes: model.hardeningNotes,
  };
}

function proxyRuntimeReadinessPacket(model = {}) {
  const activeRolloutChecklist = proxyActiveRolloutChecklist(model);
  const functionalProofArtifacts = proxyFunctionalRuntimeProofArtifacts(model);
  return {
    schemaVersion: model.schemaVersion || "openngfw.proxy.runtime-readiness.v1",
    workflow: safeRuntimePacketText(model.boundary || "Runtime-readiness review only; not active listener traffic proof or daemon launch."),
    readiness: model.readiness || "unknown",
    label: safeRuntimePacketText(model.label || "unknown", { maxChars: 240, maxLines: 4 }),
    candidateRevision: safeRuntimePacketText(model.candidateRevision || "", { maxChars: 240, maxLines: 4 }),
    runningVersion: model.runningVersion || 0,
    candidateDirty: Boolean(model.candidateDirty),
    proxyChanged: Boolean(model.proxyChanged),
    candidateSummary: model.candidateSummary || {},
    runningSummary: model.runningSummary || {},
    validation: model.validation || {},
    runtime: safeRuntimePacketObject(model.runtime || {}),
    artifactManifest: safeRuntimePacketObject(model.artifactManifest || { artifacts: [] }),
    functionalProofArtifacts,
    blockers: (model.blockers || []).slice(0, 20).map((item) => ({
      id: safeRuntimePacketText(item.id || "", { maxChars: 120, maxLines: 2 }),
      title: safeRuntimePacketText(item.title || "", { maxChars: 240, maxLines: 4 }),
      detail: safeRuntimePacketText(item.detail || ""),
    })),
    activeRolloutChecklist,
    handoffLinks: (model.handoffLinks || []).slice(0, 12).map((link) => ({
      label: safeRuntimePacketText(link.label || "", { maxChars: 120, maxLines: 2 }),
      href: safeRuntimePacketText(link.href || "", { maxChars: 400, maxLines: 2 }),
    })),
    reviewCommands: (model.reviewCommands || []).slice(0, 20).map((command) => safeRuntimePacketText(command, { maxChars: 400, maxLines: 4 })),
    packetBounds: { maxStringChars: 1600, maxTextLines: 40, maxBlockers: 20, maxCommands: 20, maxHandoffLinks: 12, functionalProofArtifacts: 4 },
    redactionBoundary: "No secrets, artifact bytes beyond bounded previews, live packet data, private keys, daemon output, or traffic samples are included. Runtime packet text is browser-redacted and bounded before copy, export, or pin.",
  };
}

function proxyPolicyCouplingPacket(model = {}) {
  return {
    schemaVersion: model.schemaVersion || "openngfw.proxy.policy-coupling.v1",
    workflow: safeRuntimePacketText(model.workflow || "candidate-safe Proxy/WAF policy coupling review"),
    summary: model.summary || {},
    services: (model.services || []).slice(0, 20).map((service) => ({
      name: safeRuntimePacketText(service.name || "", { maxChars: 160, maxLines: 2 }),
      enabled: Boolean(service.enabled),
      listener: safeRuntimePacketText(service.listener || "", { maxChars: 160, maxLines: 2 }),
      serviceRules: (service.serviceRules || []).slice(0, 12).map((item) => safeRuntimePacketText(item, { maxChars: 160, maxLines: 2 })),
      appRules: (service.appRules || []).slice(0, 12).map((item) => safeRuntimePacketText(item, { maxChars: 160, maxLines: 2 })),
      inspectionRules: (service.inspectionRules || []).slice(0, 12).map((item) => safeRuntimePacketText(item, { maxChars: 160, maxLines: 2 })),
      routes: (service.routes || []).slice(0, 20).map((item) => ({
        name: safeRuntimePacketText(item.name || "", { maxChars: 160, maxLines: 2 }),
        pathPrefix: safeRuntimePacketText(item.pathPrefix || "", { maxChars: 160, maxLines: 2 }),
        wafPolicy: safeRuntimePacketText(item.wafPolicy || "", { maxChars: 160, maxLines: 2 }),
        backendCount: Number(item.backendCount) || 0,
      })),
    })),
    findings: (model.findings || []).slice(0, 40).map((finding) => ({
      severity: safeRuntimePacketText(finding.severity || "", { maxChars: 80, maxLines: 2 }),
      virtualService: safeRuntimePacketText(finding.virtualService || "", { maxChars: 160, maxLines: 2 }),
      route: safeRuntimePacketText(finding.route || "", { maxChars: 160, maxLines: 2 }),
      dimension: safeRuntimePacketText(finding.dimension || "", { maxChars: 80, maxLines: 2 }),
      message: safeRuntimePacketText(finding.message || ""),
    })),
    reviewLinks: (model.reviewLinks || []).slice(0, 12).map((link) => ({
      label: safeRuntimePacketText(link.label || "", { maxChars: 120, maxLines: 2 }),
      href: safeRuntimePacketText(link.href || "", { maxChars: 400, maxLines: 2 }),
    })),
    boundary: "Review context only; no active listener, traffic cutover, TLS key custody, packet inspection, firewall mutation, route mutation, or WAF enforcement proof is included.",
  };
}

function proxyFunctionalRuntimeProofArtifacts(model = {}) {
  const manifest = model.artifactManifest || { artifacts: [] };
  const artifacts = Array.isArray(manifest.artifacts) ? manifest.artifacts : [];
  const proxyArtifacts = artifacts.filter((artifact) => artifact.proxy);
  const hashes = proxyArtifacts
    .map((artifact) => `${artifact.name || artifact.engine || "proxy-artifact"} ${artifact.sha256 || "hash-missing"}`)
    .slice(0, 6);
  const serviceCount = Number(model.candidateSummary?.virtualServices || 0) || 0;
  const wafCount = Number(model.candidateSummary?.wafPolicies || 0) || 0;
  const revision = model.candidateRevision || "candidate-revision-unavailable";
  return [
    {
      id: "proxy-daemon-plan",
      kind: "daemon",
      status: "planned-not-executed",
      evidence: [
        `candidateRevision=${revision}`,
        `proxyArtifacts=${proxyArtifacts.length}`,
        ...hashes,
        "launch command must be captured by the rollout owner",
      ].map((entry) => safeRuntimePacketText(entry, { maxChars: 300, maxLines: 3 })),
      boundary: "No Envoy/Coraza process is started, supervised, reloaded, or stopped by this review.",
    },
    {
      id: "proxy-listener-plan",
      kind: "listener",
      status: "planned-not-executed",
      evidence: [
        `candidateVirtualServices=${serviceCount}`,
        `candidateWafPolicies=${wafCount}`,
        model.runtime?.observed ? `reportedRuntimeState=${model.runtime.state || "unknown"}` : "reportedRuntimeState=not-reported",
        "socket bind, health endpoint, request path, and HA listener evidence must be external",
      ].map((entry) => safeRuntimePacketText(entry, { maxChars: 300, maxLines: 3 })),
      boundary: "Listener intent is review context only; active bind, traffic samples, and HA listener proof are not claimed.",
    },
    {
      id: "proxy-cutover-plan",
      kind: "cutover",
      status: "planned-not-executed",
      evidence: [
        `validation=${model.validation?.valid ? "valid" : "blocked"}`,
        `proxyArtifactPresent=${model.validation?.proxyArtifactPresent ? "true" : "false"}`,
        "approved route, load balancer, NAT, DNS, or client cutover record must be attached externally",
      ].map((entry) => safeRuntimePacketText(entry, { maxChars: 300, maxLines: 3 })),
      boundary: "No production route, load balancer, NAT, DNS, or client traffic cutover is performed.",
    },
    {
      id: "proxy-rollback-plan",
      kind: "rollback",
      status: "planned-not-executed",
      evidence: [
        `runningPolicy=${model.runningVersion ? `v${model.runningVersion}` : "unknown"}`,
        `proxyChanged=${model.proxyChanged ? "true" : "false"}`,
        "previous policy version, artifact hash set, stop or listener withdrawal command, owner, and observation window must be retained by rollout workflow",
      ].map((entry) => safeRuntimePacketText(entry, { maxChars: 300, maxLines: 3 })),
      boundary: "Rollback is a handoff requirement only; no restore, daemon stop, listener withdrawal, or drill evidence is claimed.",
    },
  ];
}

function proxyActiveRolloutChecklist(model = {}) {
  const validationReady = Boolean(model.validation?.valid && model.validation?.proxyArtifactPresent);
  const hasProxy = Boolean((model.candidateSummary?.virtualServices || 0) > 0 || (model.candidateSummary?.wafPolicies || 0) > 0);
  const runtimeObserved = Boolean(model.runtime?.observed);
  const gates = [
    {
      id: "listener-health",
      gate: "Listener health",
      requiredProof: "Per-service host:port listener bind, process owner, readiness probe result, health endpoint response, and timestamped screenshot/log excerpt for every planned virtual service.",
      boundary: "Status context in this drawer is not accepted as listener health proof, process proof, or active daemon evidence.",
      status: runtimeObserved ? "external-proof-required" : "missing-runtime-context",
    },
    {
      id: "envoy-coraza-launch",
      gate: "Envoy/Coraza launch proof",
      requiredProof: "Process manager output, rendered config digest, Coraza ruleset digest, and startup log excerpt captured by the rollout owner.",
      boundary: "Validation proves render-plan metadata only; it does not launch Envoy or Coraza.",
      status: validationReady ? "external-proof-required" : "blocked-by-plan-validation",
    },
    {
      id: "rollback-controls",
      gate: "Rollback controls",
      requiredProof: "Named previous policy version, candidate revision, artifact manifest hash set, restore command, owner, stop/disable listener procedure, and rollback observation window.",
      boundary: "This drawer records the handoff packet; rollback execution remains outside WebUI runtime review.",
      status: model.runningVersion ? "external-proof-required" : "missing-running-policy",
    },
    {
      id: "traffic-cutover",
      gate: "Traffic cutover proof",
      requiredProof: "Approved route/LB/NAT change ID, cutover timestamp, before/after request sample, WAF decision/audit sample, backend success proof, and rollback timer.",
      boundary: "No live packet data or traffic samples are included in copy, export, or pin packets.",
      status: hasProxy ? "external-proof-required" : "no-candidate-proxy",
    },
    {
      id: "hardening-boundary",
      gate: "Current hardening boundary",
      requiredProof: "TLS key custody, backend mTLS handshake, WAF supply-chain signing, request-body privacy custody, HA failover evidence, and active daemon lifecycle proof.",
      boundary: model.boundary || "Runtime-readiness review only; active hardening proof remains outside this drawer.",
      status: "required-before-active-rollout",
    },
  ];
  return gates.map((gate) => ({
    ...gate,
    requiredProof: safeRuntimePacketText(gate.requiredProof),
    boundary: safeRuntimePacketText(gate.boundary),
    statusLabel: activeRolloutStatusLabel(gate.status),
    statusClass: activeRolloutStatusClass(gate.status),
  }));
}

function activeRolloutStatusLabel(status = "") {
  if (status === "blocked-by-plan-validation") return "blocked by validation";
  if (status === "missing-runtime-context") return "runtime context missing";
  if (status === "missing-running-policy") return "running policy unknown";
  if (status === "no-candidate-proxy") return "no candidate proxy";
  if (status === "required-before-active-rollout") return "required";
  return "external proof required";
}

function activeRolloutStatusClass(status = "") {
  if (status === "external-proof-required" || status === "required-before-active-rollout") return "warn";
  return "bad";
}

function safeRuntimePacketText(text = "", limits = {}) {
  return boundedArtifactSnippet(String(text || ""), {
    maxChars: Number(limits.maxChars) || 1600,
    maxLines: Number(limits.maxLines) || 40,
  }).text;
}

function safeRuntimePacketObject(value = {}, depth = 0) {
  if (depth > 4) return "[bounded]";
  if (Array.isArray(value)) return value.slice(0, 20).map((item) => safeRuntimePacketObject(item, depth + 1));
  if (!value || typeof value !== "object") return typeof value === "string" ? safeRuntimePacketText(value) : value;
  const out = {};
  for (const [key, item] of Object.entries(value).slice(0, 40)) {
    const safeKey = safeRuntimePacketText(key, { maxChars: 120, maxLines: 2 });
    out[safeKey] = /secret|token|password|private[_-]?key|authorization/i.test(key) ? "[redacted]" : safeRuntimePacketObject(item, depth + 1);
  }
  return out;
}

function proxyRuntimeArtifactManifest(validation = {}) {
  const renderPlan = validation?.renderPlan || validation?.render_plan || {};
  const rawArtifacts = Array.isArray(renderPlan.artifacts) ? renderPlan.artifacts : [];
  const artifacts = rawArtifacts.map(runtimeManifestArtifact).filter(Boolean).slice(0, 40);
  const totalBytes = Number(renderPlan.totalBytes || renderPlan.total_bytes || artifacts.reduce((sum, artifact) => sum + artifact.sizeBytes, 0)) || 0;
  return {
    source: "candidate validation render plan",
    artifactCount: Number(renderPlan.artifactCount || renderPlan.artifact_count || artifacts.length) || artifacts.length,
    totalBytes,
    proxyArtifactPresent: artifacts.some((artifact) => artifact.proxy),
    hashBoundary: "SHA-256 or digest values shown here are validation metadata only; release promotion still requires durable accepted-source evidence.",
    artifacts,
  };
}

function runtimeManifestArtifact(artifact = {}) {
  if (!artifact || typeof artifact !== "object") return null;
  const engine = safeRuntimePacketText(artifact.engine || artifact.type || "", { maxChars: 120, maxLines: 2 });
  const name = safeRuntimePacketText(artifact.name || artifact.path || artifact.filename || engine || "artifact", { maxChars: 240, maxLines: 2 });
  const sha256 = normalizedArtifactSha(artifact);
  return {
    name,
    engine,
    sizeBytes: Number(artifact.sizeBytes || artifact.size_bytes || artifact.bytes || 0) || 0,
    sha256,
    hashPresent: Boolean(sha256),
    proxy: /proxy|envoy|coraza|waf/i.test(`${engine} ${name}`),
  };
}

function normalizedArtifactSha(artifact = {}) {
  const value = String(artifact.sha256 || artifact.sha_256 || artifact.digest || artifact.hash || "").trim();
  if (/^sha256:[A-Fa-f0-9]{64}$/.test(value)) return value;
  if (/^[A-Fa-f0-9]{64}$/.test(value)) return `sha256:${value.toLowerCase()}`;
  return "";
}

async function copyRuntimeReadinessPacket(model) {
  const packet = proxyRuntimeReadinessPacket(model);
  if (await copyText(JSON.stringify(packet, null, 2))) toast("Runtime packet copied", "Bounded Proxy/WAF runtime-readiness packet copied to clipboard.", "ok");
  else toast("Copy failed", "Export the packet or copy the preview text manually.", "warn");
}

async function copyPolicyCouplingPacket(model) {
  const packet = proxyPolicyCouplingPacket(model);
  if (await copyText(JSON.stringify(packet, null, 2))) toast("Policy impact packet copied", "Proxy/WAF traffic-policy coupling packet copied to clipboard.", "ok");
  else toast("Copy failed", "Select the packet preview and copy it manually.", "warn");
}

function exportRuntimeReadinessPacket(model) {
  downloadText("proxy-waf-runtime-readiness.json", JSON.stringify(proxyRuntimeReadinessPacket(model), null, 2) + "\n", "application/json");
  toast("Runtime packet exported", "proxy-waf-runtime-readiness.json", "ok");
}

async function pinRuntimeReadinessPacket(model) {
  const packet = proxyRuntimeReadinessInvestigationPacket(model);
  try {
    const serverResult = await appendInvestigationPacketToActiveServerCase(packet, {
      appendEvidence: (id, evidence) => api.addInvestigationCaseEvidence(id, evidence),
    });
    if (serverResult.appended) {
      toast("Evidence appended", `Proxy/WAF runtime-readiness handoff appended to ${serverResult.activeCaseId}.`, "ok");
      return;
    }
  } catch {
    try {
      const result = pinInvestigationPacket(packet);
      toast("Server append unavailable", `${result.toastDetail} Local fallback was used.`, "warn");
    } catch (fallbackError) {
      toast("Pin failed", fallbackError.message || "Proxy/WAF runtime-readiness handoff could not be pinned.", "bad");
    }
    return;
  }
  try {
    const result = pinInvestigationPacket(packet);
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Proxy/WAF runtime-readiness handoff could not be pinned.", "bad");
  }
}

function currentProxyRouteHash() {
  if (typeof location !== "undefined" && (location.hash || "").startsWith("#/proxy")) return location.hash;
  return proxyHash(route);
}

async function copyText(text) {
  try {
    if (globalThis.navigator?.clipboard?.writeText) {
      await globalThis.navigator.clipboard.writeText(text);
      return true;
    }
  } catch {}
  try {
    const ta = h("textarea", { style: { position: "fixed", left: "-9999px", top: "0" } }, text);
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand?.("copy");
    ta.remove();
    return Boolean(ok);
  } catch {
    return false;
  }
}

function downloadText(filename, text, type) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function contentTypeForPreview(preview = {}) {
  if (preview.language === "json") return "application/json";
  if (preview.language === "yaml") return "application/x-yaml";
  return "text/plain";
}

function clearPlanDrawerRoute() {
  if (typeof location === "undefined" || !location.hash.startsWith("#/proxy")) return;
  const current = currentRouteStateFromHash();
  if (current.drawer !== "plan") return;
  const next = { ...current, drawer: "" };
  route = next;
  if (typeof history !== "undefined" && history.replaceState) history.replaceState(null, "", proxyHash(next));
  else location.hash = proxyHash(next);
}

function clearPolicyDrawerRoute() {
  if (typeof location === "undefined" || !location.hash.startsWith("#/proxy")) return;
  const current = currentRouteStateFromHash();
  if (current.drawer !== "policy") return;
  const next = { ...current, drawer: "" };
  route = next;
  if (typeof history !== "undefined" && history.replaceState) history.replaceState(null, "", proxyHash(next));
  else location.hash = proxyHash(next);
}

function currentRouteStateFromHash() {
  try {
    const query = location.hash.includes("?") ? location.hash.slice(location.hash.indexOf("?") + 1) : "";
    return normalizeProxyRoute(Object.fromEntries(new URLSearchParams(query).entries()));
  } catch {
    return normalizeProxyRoute(route);
  }
}

function tabLink(tab, label) {
  return h("a", { class: "btn sm " + (route.tab === tab ? "primary" : "ghost"), href: proxyHash({ tab }), title: `Show ${label}`, "aria-label": `Show ${label}`, dataset: { proxyTab: tab } }, label);
}

function virtualServicesCard(root, proxy) {
  const services = proxy.virtualServices || [];
  if (!services.length) {
    return emptyState("globe", "No virtual services", "Add a planned listener, route, and backend set before validating proxy/WAF intent.",
      h("button", { class: "btn primary", type: "button", title: "Add virtual service", "aria-label": "Add virtual service", dataset: { proxyAction: "add-service" }, onclick: () => openServiceEditor(root) }, h("span", { html: icon("plus", 16) }), "Add service"));
  }
  return card(h("h2", {}, "Virtual services", h("span", { class: "spacer" }), pill(`${services.length} planned`, "info")),
    responsiveTable(["Service", "Hostnames", "Listener", "Routes", "Backends", "Actions"], services.map((service, index) => serviceRow(root, service, index, proxy.wafPolicies)), { className: "proxy-services-table" }));
}

function serviceRow(root, service, index, wafPolicies) {
  const listener = service.listener || {};
  const routes = Array.isArray(service.routes) ? service.routes : [];
  const backendCount = routes.reduce((sum, r) => sum + (Array.isArray(r.backends) ? r.backends.length : 0), 0);
  return h("tr", { dataset: { proxyService: service.name || String(index) } },
    labeledCell("Service", h("strong", {}, service.name || `service-${index + 1}`), h("div", { class: "note" }, service.enabled === false ? "disabled in candidate" : "enabled in candidate")),
    labeledCell("Hostnames", (service.hostnames || []).join(", ") || "none"),
    labeledCell("Listener", h("span", { class: "mono" }, `${listener.bindAddress || "-"}:${listener.port || "-"}`), h("div", { class: "note" }, listener.tls ? `TLS ${listener.tlsSecretRef || "missing secret"}` : "cleartext planned")),
    labeledCell("Routes", routes.length ? routes.map((r) => routePill(r, wafPolicies)).reduce((out, item) => out.concat(item, " "), []) : "none"),
    labeledCell("Backends", String(backendCount)),
    labeledCell("Actions", h("div", { class: "flex wrap" },
      h("button", { class: "btn sm ghost", type: "button", title: `Edit ${service.name || "service"}`, "aria-label": `Edit virtual service ${service.name || index + 1}`, dataset: { proxyAction: "edit-service" }, onclick: () => openServiceEditor(root, index) }, h("span", { html: icon("edit", 14) }), "Edit"),
      h("button", { class: "btn sm ghost", type: "button", title: `Clone ${service.name || "service"}`, "aria-label": `Clone virtual service ${service.name || index + 1}`, dataset: { proxyAction: "clone-service" }, onclick: () => cloneService(root, index) }, h("span", { html: icon("copy", 14) }), "Clone"),
      h("button", { class: "btn sm danger", type: "button", title: `Delete ${service.name || "service"}`, "aria-label": `Delete virtual service ${service.name || index + 1}`, dataset: { proxyAction: "delete-service" }, onclick: () => deleteService(root, index) }, h("span", { html: icon("trash", 14) }), "Delete"))));
}

function routePill(route, wafPolicies) {
  const wafKnown = !route.wafPolicy || wafPolicies.some((waf) => waf.name === route.wafPolicy);
  return pill(`${route.pathPrefix || "/"} ${route.wafPolicy || "no-waf"}`, wafKnown && route.requireMtlsToBackend ? "ok" : "warn");
}

function wafPoliciesCard(root, wafs) {
  if (!wafs.length) {
    return emptyState("shield", "No WAF policies", "Add a WAF policy with ruleset provenance before attaching it to planned proxy routes.",
      h("button", { class: "btn primary", type: "button", title: "Add WAF policy", "aria-label": "Add WAF policy", dataset: { proxyAction: "add-waf" }, onclick: () => openWafEditor(root) }, h("span", { html: icon("plus", 16) }), "Add WAF"));
  }
  return card(h("h2", {}, "WAF policies", h("span", { class: "spacer" }), pill(`${wafs.length} planned`, "info")),
    responsiveTable(["Policy", "Mode", "Rulesets", "Body limit", "Audit/body", "Actions"], wafs.map((waf, index) => wafRow(root, waf, index)), { className: "proxy-waf-table" }));
}

function wafRow(root, waf, index) {
  return h("tr", { dataset: { proxyWaf: waf.name || String(index) } },
    labeledCell("Policy", h("strong", {}, waf.name || `waf-${index + 1}`), waf.description ? h("div", { class: "note" }, waf.description) : null),
    labeledCell("Mode", pill(modeLabel(waf.mode), waf.mode === "WAF_MODE_BLOCK" ? "bad" : "warn")),
    labeledCell("Rulesets", (waf.ruleSets || []).map((rs) => `${rs.name || "rules"}@${rs.version || "unknown"}`).join(", ") || "none"),
    labeledCell("Body limit", `${waf.requestBodyLimitKb || 0} KB`),
    labeledCell("Audit/body", `${waf.auditLogging ? "audit" : "no audit"} / ${waf.redactRequestBody ? "redacted" : "not redacted"}`),
    labeledCell("Actions", h("div", { class: "flex wrap" },
      h("button", { class: "btn sm ghost", type: "button", title: `Edit ${waf.name || "WAF"}`, "aria-label": `Edit WAF policy ${waf.name || index + 1}`, dataset: { proxyAction: "edit-waf" }, onclick: () => openWafEditor(root, index) }, h("span", { html: icon("edit", 14) }), "Edit"),
      h("button", { class: "btn sm danger", type: "button", title: `Delete ${waf.name || "WAF"}`, "aria-label": `Delete WAF policy ${waf.name || index + 1}`, dataset: { proxyAction: "delete-waf" }, onclick: () => deleteWaf(root, index) }, h("span", { html: icon("trash", 14) }), "Delete"))));
}

function openWafEditor(root, index = -1) {
  const proxy = normalizeProxy(session.draft.proxy);
  const editing = index >= 0;
  const waf = structuredClone(editing ? proxy.wafPolicies[index] : defaultWafPolicy(proxy.wafPolicies));
  const controls = {
    name: input(waf.name),
    mode: select(["WAF_MODE_BLOCK", "WAF_MODE_DETECT"], waf.mode || "WAF_MODE_BLOCK"),
    requestBodyLimitKb: input(waf.requestBodyLimitKb || 128, "number"),
    auditLogging: checkbox(waf.auditLogging !== false),
    redactRequestBody: checkbox(waf.redactRequestBody === true),
    description: textarea(waf.description || ""),
    ruleSets: textarea((waf.ruleSets || []).map((rs) => [rs.name, rs.version, rs.source, rs.sha256].join("|")).join("\n")),
  };
  const errorBox = h("div", {});
  openDrawer({
    title: editing ? "Edit WAF policy" : "Add WAF policy",
    subtitle: "Stages WAF intent to the candidate only; ruleset provenance is required by server validation.",
    width: "720px",
    body: h("div", {},
      errorBox,
      formGrid(
        field("Name", controls.name),
        field("Mode", controls.mode),
        field("Request body limit KB", controls.requestBodyLimitKb),
        field("Audit logging", controls.auditLogging),
        field("Redact request body", controls.redactRequestBody),
        field("Description", controls.description, "optional operator note")),
      field("Rule sets", controls.ruleSets, "one per line: name|version|source|sha256")),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Cancel WAF edit", "aria-label": "Cancel WAF edit", dataset: { proxyAction: "cancel-waf" }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: "Stage WAF policy", "aria-label": "Stage WAF policy to candidate", dataset: { proxyAction: "stage-waf" }, onclick: () => stageWaf(root, index, controls, errorBox) }, h("span", { html: icon("check", 16) }), "Stage WAF"),
    ],
  });
}

async function stageWaf(root, index, controls, errorBox) {
  const waf = {
    name: controls.name.value.trim(),
    mode: controls.mode.value,
    requestBodyLimitKb: Number(controls.requestBodyLimitKb.value),
    auditLogging: controls.auditLogging.checked,
    redactRequestBody: controls.redactRequestBody.checked,
    description: controls.description.value.trim(),
    ruleSets: parseRuleSets(controls.ruleSets.value),
  };
  const proxy = normalizeProxy(session.draft.proxy);
  const next = structuredClone(proxy);
  if (index >= 0) next.wafPolicies[index] = waf; else next.wafPolicies.push(waf);
  const errors = validateProxy(next);
  if (errors.length) return showErrors(errorBox, errors);
  await stage(root, (draft) => {
    const p = ensureProxy(draft);
    if (index >= 0) p.wafPolicies[index] = waf; else p.wafPolicies.push(waf);
  }, "WAF policy staged");
}

function openServiceEditor(root, index = -1) {
  const proxy = normalizeProxy(session.draft.proxy);
  const editing = index >= 0;
  const service = structuredClone(editing ? proxy.virtualServices[index] : defaultVirtualService(proxy.virtualServices, proxy.wafPolicies));
  const routeLines = (service.routes || []).map(routeToLine).join("\n");
  const controls = {
    name: input(service.name),
    enabled: checkbox(service.enabled !== false),
    hostnames: textarea((service.hostnames || []).join("\n")),
    description: textarea(service.description || ""),
    bindAddress: input(service.listener?.bindAddress || "0.0.0.0"),
    port: input(service.listener?.port || 443, "number"),
    tls: checkbox(service.listener?.tls !== false),
    tlsSecretRef: input(service.listener?.tlsSecretRef || "vault://openngfw/admin-api"),
    routes: textarea(routeLines),
  };
  const errorBox = h("div", {});
  openDrawer({
    title: editing ? "Edit virtual service" : "Add virtual service",
    subtitle: "Routes use line format name|path|wafPolicy|mtls|required stripPrefix|backendName=url=weight,...",
    width: "820px",
    body: h("div", {},
      errorBox,
      formGrid(
        field("Name", controls.name),
        field("Enabled", controls.enabled),
        field("Hostnames", controls.hostnames, "comma or newline separated; lowercase only"),
        field("Description", controls.description),
        field("Bind address", controls.bindAddress),
        field("Port", controls.port),
        field("TLS", controls.tls),
        field("TLS secret ref", controls.tlsSecretRef)),
      field("Routes and backends", controls.routes, "one route per line: route|/path|waf|true|false|backend=https://app.internal=100")),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Cancel service edit", "aria-label": "Cancel service edit", dataset: { proxyAction: "cancel-service" }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: "Stage virtual service", "aria-label": "Stage virtual service to candidate", dataset: { proxyAction: "stage-service" }, onclick: () => stageService(root, index, controls, errorBox) }, h("span", { html: icon("check", 16) }), "Stage service"),
    ],
  });
}

async function stageService(root, index, controls, errorBox) {
  const service = {
    name: controls.name.value.trim(),
    enabled: controls.enabled.checked,
    hostnames: listFromValue(controls.hostnames.value),
    listener: {
      bindAddress: controls.bindAddress.value.trim(),
      port: Number(controls.port.value),
      tls: controls.tls.checked,
      tlsSecretRef: controls.tlsSecretRef.value.trim(),
    },
    routes: parseRoutes(controls.routes.value),
    description: controls.description.value.trim(),
  };
  const proxy = normalizeProxy(session.draft.proxy);
  const next = structuredClone(proxy);
  if (index >= 0) next.virtualServices[index] = service; else next.virtualServices.push(service);
  const errors = validateProxy(next);
  if (errors.length) return showErrors(errorBox, errors);
  await stage(root, (draft) => {
    const p = ensureProxy(draft);
    if (index >= 0) p.virtualServices[index] = service; else p.virtualServices.push(service);
  }, "Virtual service staged");
}

async function cloneService(root, index) {
  const proxy = normalizeProxy(session.draft.proxy);
  const original = proxy.virtualServices[index];
  if (!original) return;
  const copy = structuredClone(original);
  copy.name = `${copy.name || "service"}-copy`.slice(0, 64).replace(/-$/, "");
  await stage(root, (draft) => ensureProxy(draft).virtualServices.push(copy), "Virtual service cloned");
}

async function deleteService(root, index) {
  const service = normalizeProxy(session.draft.proxy).virtualServices[index];
  if (!service) return;
  if (!await confirmDialog({ title: "Delete virtual service", message: `Remove ${service.name || "this service"} from the candidate proxy plan?`, confirmLabel: "Delete", danger: true })) return;
  await stage(root, (draft) => ensureProxy(draft).virtualServices.splice(index, 1), "Virtual service deleted");
}

async function deleteWaf(root, index) {
  const waf = normalizeProxy(session.draft.proxy).wafPolicies[index];
  if (!waf) return;
  if (!await confirmDialog({ title: "Delete WAF policy", message: `Remove ${waf.name || "this WAF"} from the candidate proxy plan? Routes referencing it will need review.`, confirmLabel: "Delete", danger: true })) return;
  await stage(root, (draft) => ensureProxy(draft).wafPolicies.splice(index, 1), "WAF policy deleted");
}

async function stage(root, mutator, title) {
  try {
    await session.apply(mutator);
    toast(title, "Proxy/WAF intent is pending candidate validation and commit review.", "ok");
    closeDrawer({ invokeOnClose: false });
    paint(root);
  } catch (err) {
    toast("Could not stage Proxy/WAF change", err.message || String(err), "bad");
  }
}

function parseRuleSets(value) {
  return String(value || "").split("\n").map((line) => line.trim()).filter(Boolean).map((line) => {
    const [name, version, source, sha256] = line.split("|").map((part) => part.trim());
    return { name, version, source, sha256 };
  });
}

function parseRoutes(value) {
  return String(value || "").split("\n").map((line) => line.trim()).filter(Boolean).map((line) => {
    const [name, pathPrefix, wafPolicy, mtls, strip, backends] = line.split("|").map((part) => part.trim());
    return {
      name,
      pathPrefix,
      wafPolicy,
      requireMtlsToBackend: mtls !== "false",
      stripPrefix: strip === "true",
      backends: parseBackends(backends),
    };
  });
}

function parseBackends(value = "") {
  return String(value || "").split(",").map((part) => part.trim()).filter(Boolean).map((part) => {
    const pieces = part.split("=");
    return { name: pieces[0]?.trim() || "", url: pieces[1]?.trim() || "", weight: Number(pieces[2]) || 0 };
  });
}

function routeToLine(route = {}) {
  return [
    route.name || "api",
    route.pathPrefix || "/api",
    route.wafPolicy || "",
    route.requireMtlsToBackend === false ? "false" : "true",
    route.stripPrefix === true ? "true" : "false",
    (route.backends || []).map((b) => `${b.name || "backend"}=${b.url || "https://app.internal"}=${b.weight || 100}`).join(","),
  ].join("|");
}

function showErrors(errorBox, errors) {
  clear(errorBox);
  errorBox.appendChild(h("div", { class: "alert-box bad", style: { marginBottom: "12px" } },
    h("strong", {}, "Fix validation issues before staging."),
    h("ul", {}, errors.slice(0, 10).map((error) => h("li", {}, error)))));
}

function field(label, control, help = "") {
  return h("label", { class: "field" }, h("span", {}, label), control, help ? h("small", {}, help) : null);
}

function formGrid(...children) {
  return h("div", { class: "grid cols-2", style: { marginBottom: "12px" } }, children);
}

function input(value = "", type = "text") {
  return h("input", { class: "input", type, value: String(value ?? "") });
}

function textarea(value = "") {
  return h("textarea", { class: "input", rows: "4" }, String(value || ""));
}

function checkbox(checked) {
  return h("input", { type: "checkbox", checked });
}

function select(options, value) {
  return h("select", { class: "input" }, options.map((option) => h("option", { value: option, selected: option === value }, option)));
}

function metric(label, value) {
  return h("div", {}, h("strong", {}, value), h("span", {}, label));
}
