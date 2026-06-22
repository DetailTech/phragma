// Policy ▸ Objects — zones, addresses, services, applications, and security profiles. Reusable building
// blocks referenced by rules. All edits stage to the candidate.

import { h, icon, clear } from "../core.js";
import { api } from "../api.js";
import { throwIfAccessDenied } from "../auth_gate.js";
import { openAutomationContext } from "../automation_context.js";
import { fingerprint, session } from "../policy.js";
import { normalizeObjectRoute, objectImpactHash, objectReferenceHash, writeObjectImpactRoute, writeObjectReferenceRoute, writeObjectRoute } from "../object_route.js";
import { pinInvestigationPacket } from "../investigation_case.js";
import { buildInvestigationPacket, investigationPacketFilename, investigationPacketJson, investigationPacketText } from "../investigation_packet.js";
import { settingsPanelHash } from "../settings_route.js";
import { pageHead, emptyState, toast, openDrawer, closeDrawer, confirmDialog, pill, labeledCell, responsiveTable } from "../ui.js";
import * as fmt from "../format.js";
import { natRuleFocusHash } from "./nat.js";
import { parsePorts, ruleInspectionCoverage } from "./rules.js";
import { discoveredSetupInterfaces, splitInterfaceList } from "./setup.js";

let tab = "addresses";
let routeState = normalizeObjectRoute();
let lastOpenedObjectDrawerRoute = "";
let objectStatus = null;
let objectStatusError = null;
let objectStatusLoaded = false;
let objectStatusLoading = false;
let objectStatusRequestSeq = 0;
let objectStatusStaleDropCount = 0;
let objectStatusLastRefreshIgnored = false;
const API_OBJECT_KIND = {
  addresses: "POLICY_OBJECT_KIND_ADDRESS",
  services: "POLICY_OBJECT_KIND_SERVICE",
  applications: "POLICY_OBJECT_KIND_APPLICATION",
  securityProfiles: "POLICY_OBJECT_KIND_SECURITY_PROFILE",
  trafficControls: ["POLICY_OBJECT_KIND_QOS_PROFILE", "POLICY_OBJECT_KIND_ZONE_PROTECTION_PROFILE"],
  zones: "POLICY_OBJECT_KIND_ZONE",
};
let referenceCache = { key: "", refs: null, error: "" };

export async function render(ctx) {
  routeState = normalizeObjectRoute(ctx?.query || {});
  tab = routeState.tab;
  const unavailableError = await loadObjectsSession();
  if (!unavailableError) {
    await loadReferenceCache(tab);
    if (tab === "zones") await loadObjectStatus();
  }
  const root = h("div", {});
  if (unavailableError) {
    paintObjectsUnavailable(root, unavailableError);
    return root;
  }
  paint(root);
  maybeOpenRouteDrawer();
  return root;
}

async function loadObjectsSession() {
  const result = await Promise.allSettled([session.load()]);
  throwIfAccessDenied(...result);
  if (result[0].status === "rejected") return result[0].reason;
  if (!session.candidateLoadError) return null;
  throwIfAccessDenied({ status: "rejected", reason: session.candidateLoadError });
  return session.candidateLoadError;
}

function paintObjectsUnavailable(root, err) {
  clear(root);
  root.appendChild(pageHead("Objects",
    "Named zones, addresses, services, App-ID definitions, security profiles, and traffic-control intent reused across policy and telemetry.",
    h("div", { class: "flex wrap" },
      h("button", { class: "btn", type: "button", title: "Open Objects API and CLI context", "aria-label": "Open Objects API and CLI context", dataset: { objectAction: "api-cli-unavailable" }, onclick: () => openAutomationContext("#/objects") }, h("span", { html: icon("terminal", 16) }), "API / CLI"),
      h("button", { class: "btn primary", type: "button", title: "Retry loading Objects candidate policy", "aria-label": "Retry loading Objects candidate policy", dataset: { objectAction: "retry-unavailable" }, onclick: retryRouteLoad }, h("span", { html: icon("refresh", 16) }), "Retry"))));
  root.appendChild(routeUnavailablePanel("Objects candidate workspace unavailable", err, [
    { label: "Candidate policy", value: "GET /v1/policy?source=POLICY_SOURCE_CANDIDATE", detail: "Loads staged object definitions before browser edits." },
    { label: "Candidate status", value: "GET /v1/candidate/status", detail: "Reads dirty state and candidate revision required for guarded object writes." },
    { label: "CLI review", value: "ngfwctl policy show --source candidate --json", detail: "Export the staged policy headlessly, then review object sections before editing." },
    { label: "CLI diff", value: "ngfwctl policy diff", detail: "Compare running and candidate policy before retrying browser edits." },
  ]));
}

function routeUnavailablePanel(title, err, rows = []) {
  return h("section", { class: "alert-box warn", dataset: { routeUnavailable: "objects" } },
    h("strong", {}, title),
    h("div", { class: "note" }, errorMessage(err) || "The candidate session could not be loaded. Retry after the API is reachable."),
    h("div", { class: "row-actions", style: { marginTop: "12px" } },
      h("button", { class: "btn sm ghost", type: "button", title: "Retry loading this Objects route", "aria-label": "Retry loading this Objects route", dataset: { objectAction: "retry-unavailable-inline" }, onclick: retryRouteLoad }, h("span", { html: icon("refresh", 14) }), "Retry"),
      h("button", { class: "btn sm ghost", type: "button", title: "Open Objects API and CLI context", "aria-label": "Open Objects API and CLI context", dataset: { objectAction: "api-cli-unavailable-inline" }, onclick: () => openAutomationContext("#/objects") }, h("span", { html: icon("terminal", 14) }), "API / CLI"),
      h("a", { class: "btn sm ghost", href: "#/changes?tab=candidate", title: "Open Changes candidate review", "aria-label": "Open Changes candidate review", dataset: { objectAction: "changes" } }, h("span", { html: icon("changes", 14) }), "Changes")),
    responsiveTable(["Context", "Command / endpoint", "Use"], rows.map((row) => h("tr", {},
      labeledCell("Context", row.label),
      labeledCell("Command / endpoint", { class: "mono" }, row.value),
      labeledCell("Use", row.detail))), { className: "objects-unavailable-context-table" }));
}

function retryRouteLoad() {
  globalThis.dispatchEvent(new Event("hashchange"));
}

function errorMessage(err) {
  return err?.message || String(err || "unknown error");
}

function paint(root) {
  clear(root);
  const actions = [
    tab === "applications"
      ? h("button", { class: "btn", type: "button", title: "Review App-ID observations", "aria-label": "Review App-ID observations", dataset: { objectAction: "review-observations", objectKind: tab }, onclick: () => { location.hash = "#/traffic?mode=app-id"; } }, h("span", { html: icon("traffic", 16) }), "Review observations")
      : null,
    h("button", { class: "btn primary", type: "button", title: `Create new ${singular(tab)}`, "aria-label": `Create new ${singular(tab)}`, dataset: { objectAction: "new", objectKind: tab }, onclick: () => editObject(tab, null, root) }, h("span", { html: icon("plus", 16) }), "New " + singular(tab)),
  ].filter(Boolean);
  root.appendChild(pageHead("Objects", "Named zones, addresses, services, App-ID definitions, security profiles, and traffic-control intent reused across policy and telemetry.", actions));

  const seg = h("div", { class: "seg" },
    segBtn("Addresses", "addresses", root), segBtn("Services", "services", root), segBtn("Applications", "applications", root), segBtn("Security profiles", "securityProfiles", root), segBtn("Traffic control", "trafficControls", root), segBtn("Zones", "zones", root));
  root.appendChild(h("div", { class: "toolbar" }, seg));

  const wrap = h("div", { class: "table-wrap" });
  root.appendChild(objectHygienePanel(tab, session.draft));
  if (tab === "zones") root.appendChild(zoneInterfaceInventoryPanel(root));
  root.appendChild(wrap);
  ({ addresses: addrTable, services: svcTable, applications: appTable, securityProfiles: securityProfileTable, trafficControls: trafficControlTable, zones: zoneTable })[tab](wrap, root);
}

function segBtn(label, key, root) {
  const n = key === "trafficControls"
    ? (session.draft.qosProfiles || []).length + (session.draft.zoneProtectionProfiles || []).length
    : (session.draft[key] || []).length;
  return h("button", {
    class: tab === key ? "active" : "",
    type: "button",
    title: `Show ${label} objects`,
    "aria-label": `Show ${label} objects`,
    dataset: { objectTab: key },
    onclick: async () => {
      tab = normalizeObjectRoute({ tab: key }).tab;
      routeState = normalizeObjectRoute({ tab });
      writeObjectRoute(tab);
      await loadReferenceCache(tab);
      if (tab === "zones") await loadObjectStatus();
      paint(root);
    },
  }, `${label} (${n})`);
}
function singular(t) { return { addresses: "address", services: "service", applications: "application", securityProfiles: "security profile", trafficControls: "traffic control profile", zones: "zone" }[t]; }

function rowActions(kind, idx, root, name, extraActions = []) {
  const objectKindLabel = singular(kind) || "object";
  const objectLabel = name || `row ${idx + 1}`;
  return h("div", { class: "flex", style: { justifyContent: "flex-end", gap: "2px" } },
    ...extraActions,
    h("button", { class: "icon-btn", type: "button", title: "Edit", "aria-label": `Edit ${objectKindLabel} ${objectLabel}`, dataset: { objectAction: "edit", objectKind: kind, objectName: name || "" }, onclick: () => editObject(kind, idx, root), html: icon("edit", 16) }),
    h("button", { class: "icon-btn", type: "button", title: "Delete", "aria-label": `Delete ${objectKindLabel} ${objectLabel}`, dataset: { objectAction: "delete", objectKind: kind, objectName: name || "" }, onclick: async () => {
      await loadReferenceCache(kind);
      const refs = referencesFor(kind, name);
      const sourceLabel = referencePolicySource() === "POLICY_SOURCE_CANDIDATE" ? "candidate" : "running";
      const msg = refs.length ? `"${name}" is referenced by ${refs.length} ${sourceLabel} policy reference(s). Delete anyway?` : `Delete "${name}"?`;
      const body = refs.length ? referenceList(refs) : null;
      if (!(await confirmDialog({ title: "Delete " + singular(kind) + "?", message: msg, body, confirmLabel: "Delete", danger: true }))) return;
      try { await session.apply((d) => deleteObjectAt(d, kind, idx)); await loadReferenceCache(kind, true); paint(root); toast("Deleted", "Staged to candidate.", "ok"); }
      catch (e) { toast("Failed", e.message, "bad"); }
    }, html: icon("trash", 16) }));
}

export function objectReferences(policy = {}, kind, name) {
  return objectReferenceRecords(policy, kind, name).map((ref) => `${ref.area}: ${ref.item} (${ref.field})`);
}

export function objectReferenceHandoffPacket({
  kind = "",
  name = "",
  refs = [],
  source = "",
  referenceSource = "",
  route = "",
} = {}, options = {}) {
  const cleanRefs = (Array.isArray(refs) ? refs : []).map((ref) => ({
    area: ref.area || "",
    item: ref.item || "",
    itemId: ref.itemId || ref.item_id || "",
    index: Number(ref.index) || 0,
    field: ref.field || "",
    detail: ref.detail || "",
  }));
  const objectKind = singular(kind || "objects") || "object";
  const objectName = String(name || "").trim();
  const sourceLabel = source || "candidate";
  return buildInvestigationPacket({
    kind: "object-reference-review",
    title: `Object reference review: ${objectName || objectKind}`,
    subject: {
      type: "policy-object",
      id: `${kind || "object"}:${objectName}`,
      label: objectName,
      kind: objectKind,
    },
    summary: {
      object: objectName,
      objectKind,
      policySource: sourceLabel,
      referenceCount: cleanRefs.length,
      referenceSource,
    },
    evidence: [
      `object: ${objectName}`,
      `object kind: ${objectKind}`,
      `policy source: ${sourceLabel}`,
      `reference count: ${cleanRefs.length}`,
      referenceSource ? `reference source: ${referenceSource}` : "",
      ...cleanRefs.map((ref) => `${ref.area}: ${ref.item}${ref.itemId ? ` [${ref.itemId}]` : ""} (${ref.field})${ref.detail ? ` - ${ref.detail}` : ""}`),
    ],
    artifacts: {
      references: cleanRefs,
    },
  }, { ...options, route });
}

export function securityProfileImpactModel(policy = {}, profileName = "", opts = {}) {
  const name = String(profileName || "").trim();
  const profiles = Array.isArray(policy.securityProfiles) ? policy.securityProfiles : [];
  const runningProfiles = Array.isArray(opts.running?.securityProfiles) ? opts.running.securityProfiles : [];
  const profile = profiles.find((item) => item?.name === name) || null;
  const refs = objectReferenceRecords(policy, "securityProfiles", name);
  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  const affectedRules = refs
    .filter((ref) => String(ref.area || "").toLowerCase() === "security rule")
    .map((ref) => {
      const rule = rules[ref.index] || rules.find((item) => item?.name === ref.item) || {};
      const coverage = ruleInspectionCoverage(policy, rule);
      return {
        name: rule.name || ref.item || `#${ref.index + 1}`,
        index: ref.index,
        action: rule.action || "ACTION_ALLOW",
        disabled: Boolean(rule.disabled),
        fromZones: Array.isArray(rule.fromZones) ? rule.fromZones : [],
        toZones: Array.isArray(rule.toZones) ? rule.toZones : [],
        services: Array.isArray(rule.services) ? rule.services : [],
        applications: Array.isArray(rule.applications) ? rule.applications : [],
        coverage,
      };
    });
  const ids = policy.ids || {};
  const failClosedReady = Boolean(ids.enabled) &&
    ids.mode === "IDS_MODE_PREVENT" &&
    (ids.failureBehavior || ids.failure_behavior) === "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED";
  const blockingIntent = securityProfileBlockingIntent(profile);
  const allowRules = affectedRules.filter((rule) => rule.action === "ACTION_ALLOW" && !rule.disabled);
  const workflow = securityProfileWorkflowModel(profile, {
    exists: Boolean(profile),
    affectedRuleCount: affectedRules.length,
    allowRuleCount: allowRules.length,
    blockingIntent,
    failClosedReady,
    candidateOnly: Boolean(profile) && !runningProfiles.some((item) => item?.name === name),
  });
  return {
    profileName: name,
    profile,
    exists: Boolean(profile),
    source: opts.source || "candidate",
    referenceSource: opts.referenceSource || "",
    candidateOnly: Boolean(profile) && !runningProfiles.some((item) => item?.name === name),
    blockingIntent,
    failClosedReady,
    intents: securityProfileIntentSummary(profile),
    workflow,
    posture: workflow.posture,
    blockers: workflow.blockers,
    warnings: workflow.warnings,
    enforcementBoundaries: workflow.enforcementBoundaries,
    controls: workflow.controls,
    references: refs,
    affectedRules,
    affectedRuleCount: affectedRules.length,
    allowRuleCount: allowRules.length,
    dropRuleCount: affectedRules.filter((rule) => rule.action === "ACTION_DENY" || rule.action === "ACTION_REJECT").length,
    blockingAllowRuleCount: blockingIntent ? allowRules.length : 0,
    bypassRiskCount: affectedRules.filter((rule) => rule.coverage?.bypassPossible || rule.coverage?.cls === "bad").length,
  };
}

export function securityProfileImpactHandoffPacket(model = {}, options = {}) {
  const profileName = model.profileName || "";
  const cleanRules = (model.affectedRules || []).map((rule) => ({
    name: rule.name || "",
    index: Number(rule.index) || 0,
    action: rule.action || "",
    disabled: Boolean(rule.disabled),
    fromZones: rule.fromZones || [],
    toZones: rule.toZones || [],
    coverageState: rule.coverage?.state || "",
    coverageLabel: rule.coverage?.label || "",
    coverageDetail: rule.coverage?.detail || "",
  }));
  return buildInvestigationPacket({
    kind: "security-profile-impact",
    title: `Security profile impact: ${profileName}`,
    subject: {
      type: "security-profile",
      id: profileName,
      label: profileName,
      kind: "security profile",
    },
    summary: {
      securityProfile: profileName,
      exists: Boolean(model.exists),
      policySource: model.source || "candidate",
      candidateOnly: Boolean(model.candidateOnly),
      affectedRuleCount: Number(model.affectedRuleCount) || 0,
      allowRuleCount: Number(model.allowRuleCount) || 0,
      blockingAllowRuleCount: Number(model.blockingAllowRuleCount) || 0,
      blockingIntent: Boolean(model.blockingIntent),
      failClosedReady: Boolean(model.failClosedReady),
      bypassRiskCount: Number(model.bypassRiskCount) || 0,
      posture: model.posture?.label || "",
      blockerCount: (model.blockers || []).length,
      warningCount: (model.warnings || []).length,
      enforcementBoundary: (model.enforcementBoundaries || []).join(" "),
    },
    evidence: [
      `security profile: ${profileName}`,
      `object exists: ${model.exists ? "yes" : "no"}`,
      `policy source: ${model.source || "candidate"}`,
      `candidate only: ${model.candidateOnly ? "yes" : "no"}`,
      `affected rules: ${Number(model.affectedRuleCount) || 0}`,
      `blocking intent: ${model.blockingIntent ? "yes" : "no"}`,
      `IPS fail-closed ready: ${model.failClosedReady ? "yes" : "no"}`,
      `TLS: ${model.intents?.tls || "unspecified"}`,
      `URL categories: ${model.intents?.urlCategories?.length ? model.intents.urlCategories.join(", ") : "none"}`,
      `DNS: ${model.intents?.dns || "unspecified"}`,
      `File: ${model.intents?.file || "unspecified"}`,
      `profile posture: ${model.posture?.label || "unknown"}`,
      ...(model.blockers || []).map((item) => `blocker: ${item}`),
      ...(model.warnings || []).map((item) => `warning: ${item}`),
      ...(model.enforcementBoundaries || []).map((item) => `boundary: ${item}`),
      ...cleanRules.map((rule) => `rule: ${rule.name} (${rule.action}) - ${rule.coverageLabel || rule.coverageState}`),
    ],
    artifacts: {
      profile: model.profile || null,
      affectedRules: cleanRules,
      references: model.references || [],
      workflow: model.workflow || null,
    },
  }, options);
}

export function objectRenameReviewModel(policy = {}, kind = "", oldName = "", newName = "", opts = {}) {
  const from = String(oldName || "").trim();
  const to = String(newName || "").trim();
  const refs = from && from !== to ? objectReferenceRecords(policy, kind, from) : [];
  let rewriteCountPreview = 0;
  if (refs.length && from && to && from !== to) {
    const preview = structuredClone(policy || {});
    rewriteCountPreview = rewriteObjectReferences(preview, kind, from, to);
  }
  const duplicate = Boolean(to && objectNameExists(policy, kind, to, Number.isInteger(opts.exceptIndex) ? opts.exceptIndex : -1));
  const groups = objectReferenceGroups(refs);
  return {
    kind,
    objectKind: singular(kind || "objects") || "object",
    oldName: from,
    newName: to,
    refs,
    referenceCount: refs.length,
    rewriteCountPreview,
    affectedAreas: groups.map((group) => group.label),
    groups,
    blockedReason: duplicate ? `${to} already exists in ${singular(kind)} objects.` : "",
  };
}

export function objectReferenceRecords(policy = {}, kind, name) {
  if (!name || name === "any") return [];
  const refs = [];
  const add = (area, item, index, field) => refs.push({
    objectName: name,
    area,
    item: item?.name || "#" + (index + 1),
    itemId: item?.id || "",
    index,
    field,
    detail: referenceDetail(area, field, item),
  });
  const scan = (area, item, index, fields) => {
    for (const field of fields) {
      if (includesRef(item?.[field], name)) add(area, item, index, fieldLabel(field));
    }
  };

  const ruleFields = kind === "zones"
    ? ["fromZones", "toZones"]
    : kind === "addresses"
      ? ["sourceAddresses", "destinationAddresses"]
      : kind === "applications"
        ? ["applications"]
        : kind === "securityProfiles"
          ? ["securityProfiles"]
          : kind === "trafficControls"
            ? ["qosProfile"]
          : ["services"];
  (policy.rules || []).forEach((rule, index) => {
    scan("security rule", rule, index, ruleFields);
  });
  if (kind === "trafficControls") {
    (policy.zones || []).forEach((zone, index) => {
      scan("zone", zone, index, ["zoneProtectionProfile"]);
    });
  }

  const hostInputFields = kind === "zones"
    ? ["fromZones"]
    : kind === "addresses"
      ? ["sourceAddresses"]
      : kind === "services"
        ? ["services"]
        : [];
  (policy.hostInput?.rules || []).forEach((rule, index) => {
    scan("host-input rule", rule, index, hostInputFields);
  });

  const idsExceptionFields = kind === "addresses" ? ["sourceAddress", "destinationAddress"] : [];
  (policy.ids?.exceptions || []).forEach((exception, index) => {
    scan("IDS exception", exception, index, idsExceptionFields);
  });

  const sourceNatFields = kind === "zones"
    ? ["toZone"]
    : kind === "addresses"
      ? ["sourceAddress", "translatedAddress"]
      : [];
  (policy.nat?.source || []).forEach((rule, index) => {
    scan("source NAT", rule, index, sourceNatFields);
  });

  const destinationNatFields = kind === "zones"
    ? ["fromZone"]
    : kind === "addresses"
      ? ["destinationAddress", "translatedAddress"]
      : kind === "services"
        ? ["service"]
        : [];
  (policy.nat?.destination || []).forEach((rule, index) => {
    scan("destination NAT", rule, index, destinationNatFields);
  });

  return refs;
}

export function objectReferenceTarget(ref = {}) {
  const area = String(ref.area || "").trim().toLowerCase();
  const item = String(ref.item || "").trim();
  if (area === "security rule" && item) {
    const params = new URLSearchParams();
    params.set("rule", item);
    return { href: `#/rules?${params.toString()}`, label: "Open rule" };
  }
  if (area === "zone") {
    return { href: "#/objects?tab=zones", label: "Open zones" };
  }
  if (area === "host-input rule") {
    const params = new URLSearchParams({ panel: "host-input" });
    const rule = String(ref.itemId || ref.ruleId || ref.id || ref.item || "").trim();
    if (rule) params.set("rule", rule);
    if (ref.index !== undefined && ref.index !== null && ref.index !== "") params.set("idx", String(ref.index));
    return { href: `#/settings?${params.toString()}`, label: "Open host input" };
  }
  if (area === "ids exception") {
    return { href: "#/threats?view=exceptions", label: "Open exceptions" };
  }
  if (area === "source nat" || area === "destination nat") {
    return { href: natRuleFocusHash(ref), label: area === "source nat" ? "Open source NAT" : "Open destination NAT" };
  }
  return null;
}

export function objectHygieneFindings(policy = {}, kind = "") {
  const checks = kind
    ? [[kind, objectList(policy, kind)]]
    : ["addresses", "services", "applications", "securityProfiles", "trafficControls", "zones"].map((k) => [k, objectList(policy, k)]);
  return checks.flatMap(([k, list]) => {
    if (k === "addresses") return duplicateValueFindings(k, list, addressSignature, "CIDR");
    if (k === "services") return duplicateValueFindings(k, list, serviceSignature, "protocol/ports");
    if (k === "applications") return applicationFindings(list);
    if (k === "securityProfiles") return securityProfileFindings(list);
    if (k === "trafficControls") return trafficControlFindings(policy);
    if (k === "zones") return zoneFindings(list);
    return [];
  });
}

function objectHygienePanel(kind, policy) {
  const findings = objectHygieneFindings(policy, kind);
  if (!findings.length) {
    return h("div", { class: "object-hygiene alert-box ok" },
      h("strong", {}, "Object hygiene clean."),
      h("div", { class: "note" }, `No duplicate ${singular(kind)} definitions or ambiguous reuse detected in the candidate.`));
  }
  return h("div", { class: "object-hygiene alert-box warn" },
    h("div", { class: "flex wrap", style: { justifyContent: "space-between" } },
      h("strong", {}, `${findings.length} object hygiene finding${findings.length === 1 ? "" : "s"}`),
      pill("candidate", "warn")),
    h("div", { class: "note" }, "Review duplicate or ambiguous definitions before commit so rules, NAT, logs, and audit comments stay readable."),
    h("ul", { class: "compact-list" }, findings.slice(0, 5).map((finding) =>
      h("li", {}, h("strong", {}, finding.title), " — ", finding.detail))),
    findings.length > 5 ? h("div", { class: "note" }, `${findings.length - 5} more finding${findings.length === 6 ? "" : "s"} hidden; narrow the object tab to review.`) : null);
}

function objectList(policy = {}, kind = "") {
  if (kind === "trafficControls") {
    return [...(policy.qosProfiles || []), ...(policy.zoneProtectionProfiles || [])];
  }
  return Array.isArray(policy[kind]) ? policy[kind] : [];
}

function duplicateValueFindings(kind, list = [], signatureFn, signatureLabel) {
  const groups = groupBySignature(list, signatureFn);
  return [...groups.entries()]
    .filter(([, items]) => items.length > 1)
    .map(([signature, items]) => ({
      kind,
      severity: "warn",
      title: `Duplicate ${singular(kind)} ${signatureLabel}`,
      detail: `${items.map((item) => item.name || "(unnamed)").join(", ")} share ${signatureLabel.toLowerCase()} ${signature}.`,
      names: items.map((item) => item.name || "").filter(Boolean),
      signature,
    }));
}

function applicationFindings(apps = []) {
  const findings = duplicateValueFindings("applications", apps, applicationPortSignature, "port hints")
    .filter((finding) => finding.signature !== "no-port-hints");
  const noPortHints = apps
    .filter((app) => app?.name && !applicationHasEnforceablePorts(app))
    .map((app) => app.name);
  if (noPortHints.length) {
    findings.push({
      kind: "applications",
      severity: "warn",
      title: "App-ID without port hints",
      detail: `${noPortHints.slice(0, 4).join(", ")} can classify traffic; enforcement requires either TCP/UDP port hints or a supported Suricata signal on a broad Drop rule with IDS/IPS Prevent fail closed.`,
      names: noPortHints,
      signature: "no-port-hints",
    });
  }
  const signalGroups = new Map();
  apps.forEach((app) => {
    (app.engineSignals || []).forEach((signal) => {
      const normalized = normalizeToken(signal);
      if (!normalized) return;
      if (!signalGroups.has(normalized)) signalGroups.set(normalized, []);
      signalGroups.get(normalized).push(app);
    });
  });
  for (const [signal, items] of signalGroups.entries()) {
    const unique = uniqueByName(items);
    if (unique.length < 2) continue;
    findings.push({
      kind: "applications",
      severity: "warn",
      title: "Duplicate App-ID engine signal",
      detail: `${unique.map((item) => item.name || "(unnamed)").join(", ")} all claim engine signal ${signal}.`,
      names: unique.map((item) => item.name || "").filter(Boolean),
      signature: signal,
    });
  }
  return findings;
}

function applicationHasEnforceablePorts(app = {}) {
  return (app.ports || []).some((hint) =>
    (hint.protocol === "PROTOCOL_TCP" || hint.protocol === "PROTOCOL_UDP") &&
    (hint.ports || []).some((port) => Number(port.start) >= 1 && Number(port.start) <= 65535 &&
      (!port.end || (Number(port.end) >= Number(port.start) && Number(port.end) <= 65535))));
}

function securityProfileFindings(profiles = []) {
  const findings = [];
  for (const profile of profiles) {
    if (profile?.tlsInspection === "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED" && !String(profile.description || "").trim()) {
      findings.push({
        kind: "securityProfiles",
        severity: "warn",
        title: "Decryption profile needs intent",
        detail: `${profile.name || "(unnamed)"} declares TLS decryption intent without operator description or external broker prerequisites.`,
        names: [profile.name || ""].filter(Boolean),
        signature: profile.name || "",
      });
    }
    const categories = (profile?.urlCategories || []).map(normalizeToken).filter(Boolean);
    const duplicated = categories.find((category, index) => categories.indexOf(category) !== index);
    if (duplicated) {
      findings.push({
        kind: "securityProfiles",
        severity: "warn",
        title: "Duplicate URL category",
        detail: `${profile.name || "(unnamed)"} repeats URL category ${duplicated}.`,
        names: [profile.name || ""].filter(Boolean),
        signature: duplicated,
      });
    }
  }
  return findings;
}

function trafficControlFindings(policy = {}) {
  const findings = [];
  const qosNames = new Set();
  for (const profile of policy.qosProfiles || []) {
    if (!profile?.name) continue;
    if (qosNames.has(profile.name)) {
      findings.push({
        kind: "trafficControls",
        severity: "warn",
        title: "Duplicate QoS profile",
        detail: `${profile.name} is defined more than once.`,
        names: [profile.name],
        signature: profile.name,
      });
    }
    qosNames.add(profile.name);
    if (Number(profile.guaranteedBandwidthKbps || 0) > Number(profile.maxBandwidthKbps || 0) && Number(profile.maxBandwidthKbps || 0) > 0) {
      findings.push({
        kind: "trafficControls",
        severity: "warn",
        title: "QoS minimum exceeds maximum",
        detail: `${profile.name} guarantees more bandwidth than its configured maximum.`,
        names: [profile.name],
        signature: profile.name,
      });
    }
  }
  const protectionNames = new Set();
  for (const profile of policy.zoneProtectionProfiles || []) {
    if (!profile?.name) continue;
    if (protectionNames.has(profile.name)) {
      findings.push({
        kind: "trafficControls",
        severity: "warn",
        title: "Duplicate zone-protection profile",
        detail: `${profile.name} is defined more than once.`,
        names: [profile.name],
        signature: profile.name,
      });
    }
    protectionNames.add(profile.name);
    if (profile.enabled && !Number(profile.synFloodPps || 0) && !Number(profile.udpFloodPps || 0) &&
      !Number(profile.icmpFloodPps || 0) && !Number(profile.maxConcurrentConnections || 0)) {
      findings.push({
        kind: "trafficControls",
        severity: "warn",
        title: "Zone protection has no threshold",
        detail: `${profile.name} is enabled without a SYN, UDP, ICMP, or connection threshold.`,
        names: [profile.name],
        signature: profile.name,
      });
    }
  }
  return findings;
}

function zoneFindings(zones = []) {
  const groups = new Map();
  zones.forEach((zone) => {
    (zone.interfaces || []).forEach((iface) => {
      const normalized = normalizeToken(iface);
      if (!normalized) return;
      if (!groups.has(normalized)) groups.set(normalized, []);
      groups.get(normalized).push(zone);
    });
  });
  return [...groups.entries()].flatMap(([iface, items]) => {
    const unique = uniqueByName(items);
    if (unique.length > 1) {
      return [{
        kind: "zones",
        severity: "warn",
        title: "Interface assigned to multiple zones",
        detail: `${iface} appears in ${unique.map((zone) => zone.name || "(unnamed)").join(", ")}.`,
        names: unique.map((zone) => zone.name || "").filter(Boolean),
        signature: iface,
      }];
    }
    if (items.length > 1) {
      return [{
        kind: "zones",
        severity: "warn",
        title: "Duplicate zone interface",
        detail: `${iface} is listed more than once in ${items[0].name || "(unnamed)"}.`,
        names: [items[0].name || ""].filter(Boolean),
        signature: iface,
      }];
    }
    return [];
  });
}

function groupBySignature(list = [], signatureFn) {
  const groups = new Map();
  list.forEach((item) => {
    const signature = signatureFn(item);
    if (!signature) return;
    if (!groups.has(signature)) groups.set(signature, []);
    groups.get(signature).push(item);
  });
  return groups;
}

function uniqueByName(items = []) {
  const seen = new Set();
  const out = [];
  for (const item of items) {
    const key = item?.name || JSON.stringify(item || {});
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

function addressSignature(address = {}) {
  return normalizeToken(address.cidr);
}

function serviceSignature(service = {}) {
  return `${service.protocol || "PROTOCOL_UNSPECIFIED"} ${portsSignature(service.ports)}`;
}

function applicationPortSignature(app = {}) {
  const parts = (app.ports || []).map((hint) => `${hint.protocol || "PROTOCOL_UNSPECIFIED"} ${portsSignature(hint.ports)}`).sort();
  return parts.length ? parts.join("; ") : "no-port-hints";
}

function portsSignature(ports = []) {
  if (!ports.length) return "any";
  return ports.map((port) => {
    const start = Number(port.start || 0);
    const end = Number(port.end || 0);
    return end && end !== start ? `${start}-${end}` : String(start);
  }).sort((a, b) => Number(a.split("-")[0]) - Number(b.split("-")[0]) || a.localeCompare(b)).join(",");
}

function normalizeToken(value) {
  return String(value || "").trim().toLowerCase();
}

function includesRef(value, name) {
  return Array.isArray(value) ? value.includes(name) : value === name;
}

function fieldLabel(field) {
  return {
    fromZones: "from zone",
    toZones: "to zone",
    sourceAddresses: "source address",
    destinationAddresses: "destination address",
    applications: "application",
    securityProfiles: "security profile",
    qosProfile: "QoS profile",
    zoneProtectionProfile: "zone protection profile",
    services: "service",
    fromZone: "from zone",
    toZone: "to zone",
    sourceAddress: "source address",
    destinationAddress: "destination address",
    translatedAddress: "translated address",
    service: "service",
  }[field] || field;
}

function referenceDetail(area, field, item) {
  if (area === "destination NAT" && field === "translated address") return "Traffic is translated to this address.";
  if (area === "source NAT" && field === "translated address") return "Egress traffic is translated to this address.";
  if (field === "from zone" || field === "to zone") return "Trust boundary match.";
  if (field === "application") return "Phragma App-ID policy match.";
  if (field === "security profile") return "Layered inspection profile attached to this rule.";
  if (field === "QoS profile") return "Plan-only traffic shaping intent attached to this rule.";
  if (field === "zone protection profile") return "Plan-only DoS/zone-protection intent attached to this zone.";
  if (field === "service") return "L4 protocol or port match.";
  return item?.description || "";
}

function usageCell(kind, name) {
  const refs = referencesFor(kind, name);
  const text = `${refs.length} ref${refs.length === 1 ? "" : "s"}`;
  return h("button", {
    class: "btn sm ghost object-usage-btn",
    type: "button",
    title: refs.length ? "Show object references" : "No object references",
    "aria-label": refs.length ? `Show object references for ${name}` : `No object references for ${name}`,
    dataset: { objectAction: "references", objectKind: kind, objectName: name || "" },
    onclick: async () => { await loadReferenceCache(kind); showReferences(kind, name); },
  }, refs.length ? pill(text, "info") : pill("Unused", "neutral"));
}

function maybeOpenRouteDrawer() {
  if (!routeState.drawer || !routeState.object) return;
  const key = `${routeState.tab}:${routeState.drawer}:${routeState.object}:${referenceCache.key}`;
  if (key === lastOpenedObjectDrawerRoute) return;
  lastOpenedObjectDrawerRoute = key;
  setTimeout(() => {
    if (routeState.drawer === "impact" && routeState.tab === "securityProfiles") {
      showSecurityProfileImpact(routeState.object, { syncRoute: false, routeBacked: true });
      return;
    }
    showReferences(routeState.tab, routeState.object, { syncRoute: false, routeBacked: true });
  }, 0);
}

function clearObjectDrawerRoute() {
  lastOpenedObjectDrawerRoute = "";
  routeState = normalizeObjectRoute({ tab });
  if (typeof location !== "undefined" && (location.hash || "").startsWith("#/objects")) {
    writeObjectRoute(tab);
  }
}

function showReferences(kind, name, opts = {}) {
  const objectName = String(name || "").trim();
  if (!objectName) return;
  const { syncRoute = true, routeBacked = false } = opts;
  if (syncRoute) {
    routeState = normalizeObjectRoute({ tab: kind, drawer: "references", object: objectName });
    writeObjectReferenceRoute(kind, objectName);
  }
  const refs = referencesFor(kind, objectName);
  const exists = objectExists(session.draft, kind, objectName);
  const sourceLabel = referencePolicySource() === "POLICY_SOURCE_CANDIDATE" ? "candidate" : "running";
  const route = objectReferenceHash(kind, objectName);
  const referenceSource = referenceSourceText(kind);
  const packet = objectReferenceHandoffPacket({
    kind,
    name: objectName,
    refs,
    source: sourceLabel,
    referenceSource,
    route,
  });
  const body = h("div", {},
    exists ? null : missingObjectRouteAlert(kind, objectName),
    h("div", { class: "alert-box info" },
      h("strong", {}, objectName),
      h("div", { class: "note" }, refs.length
        ? `${refs.length} ${sourceLabel} policy reference${refs.length === 1 ? "" : "s"} currently point at this ${singular(kind)}.`
        : exists
          ? `No ${sourceLabel} policy references currently point at this ${singular(kind)}.`
          : `No ${sourceLabel} policy references remain for this missing ${singular(kind)}.`),
      h("div", { class: "note" }, referenceSource),
      routeBacked ? h("div", { class: "note" }, "Opened from route-backed object reference state.") : null),
    refs.length ? referenceList(refs) : h("div", { class: "empty compact" },
      h("div", { html: icon("objects", 30) }),
      h("h3", {}, exists ? "No references" : "No remaining references"),
      h("div", {}, exists
        ? `This object can be removed without detaching existing ${sourceLabel} rules or NAT entries.`
        : "The object is not present in the current candidate object table; the route may be stale after a delete or rename.")));
  openDrawer({
    title: "Object references",
    subtitle: sourceLabel[0].toUpperCase() + sourceLabel.slice(1) + " policy usage for " + singular(kind) + ".",
    width: "620px",
    body,
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close object references", "aria-label": "Close object references", dataset: { objectAction: "references-close", objectKind: kind }, onclick: closeDrawer }, "Close"),
      h("button", { class: "btn", type: "button", title: "Pin object reference handoff to case", "aria-label": `Pin object reference handoff for ${objectName} to case`, dataset: { objectAction: "references-pin", objectKind: kind, objectName }, onclick: () => pinObjectReferenceHandoff(packet) }, h("span", { html: icon("inbox", 16) }), "Pin to case"),
      h("button", { class: "btn", type: "button", title: "Copy object reference handoff", "aria-label": `Copy object reference handoff for ${objectName}`, dataset: { objectAction: "references-copy", objectKind: kind, objectName }, onclick: () => copyObjectReferenceHandoff(packet) }, h("span", { html: icon("copy", 16) }), "Copy handoff"),
      h("button", { class: "btn", type: "button", title: "Export object reference handoff JSON", "aria-label": `Export object reference handoff JSON for ${objectName}`, dataset: { objectAction: "references-export", objectKind: kind, objectName }, onclick: () => exportObjectReferenceHandoff(packet) }, h("span", { html: icon("download", 16) }), "Export JSON"),
    ],
    onClose: clearObjectDrawerRoute,
  });
}

function showSecurityProfileImpact(name, opts = {}) {
  const profileName = String(name || "").trim();
  if (!profileName) return;
  const { syncRoute = true, routeBacked = false } = opts;
  if (syncRoute) {
    routeState = normalizeObjectRoute({ tab: "securityProfiles", drawer: "impact", object: profileName });
    writeObjectImpactRoute("securityProfiles", profileName);
  }
  const sourceLabel = referencePolicySource() === "POLICY_SOURCE_CANDIDATE" ? "candidate" : "running";
  const model = securityProfileImpactModel(session.draft, profileName, {
    running: session.running || {},
    source: sourceLabel,
    referenceSource: referenceSourceText("securityProfiles"),
  });
  const route = objectImpactHash("securityProfiles", profileName);
  const packet = securityProfileImpactHandoffPacket(model, { route });
  const body = model.exists ? h("div", {},
    h("div", { class: "alert-box " + (model.bypassRiskCount ? "warn" : "info") },
      h("div", { class: "flex wrap", style: { justifyContent: "space-between" } },
        h("strong", {}, profileName),
        h("span", { class: "flex wrap", style: { gap: "6px" } },
          pill(model.posture?.label || "review", model.posture?.tone || "warn"),
          model.candidateOnly ? pill("candidate only", "warn") : pill(sourceLabel, "info"),
          model.blockingIntent ? pill("blocking intent", "warn") : pill("observe/log", "neutral"),
          model.failClosedReady ? pill("IPS fail-closed", "ok") : pill("IPS posture review", model.blockingIntent ? "bad" : "warn"))),
      h("div", { class: "note" }, `${model.affectedRuleCount} ${sourceLabel} rule${model.affectedRuleCount === 1 ? "" : "s"} currently attach this security profile; ${model.blockingAllowRuleCount} active allow rule${model.blockingAllowRuleCount === 1 ? "" : "s"} inherit blocking inspection intent.`),
      h("div", { class: "note" }, routeBacked ? "Opened from route-backed security profile impact state." : "Impact is computed from candidate policy object references and rule inspection coverage.")),
    securityProfileWorkflowPanel(model.workflow),
    h("div", { class: "metric-grid" },
      metricTile("Affected rules", model.affectedRuleCount),
      metricTile("Active allow", model.allowRuleCount),
      metricTile("Pre-filter drop", model.dropRuleCount),
      metricTile("Review risks", model.bypassRiskCount)),
    h("div", { class: "object-ref-list" },
      h("div", { class: "object-ref-row" },
        h("div", {}, h("strong", {}, "Profile intent"), h("span", {}, model.profile?.description || "Reusable TLS, DNS, URL, and file inspection intent.")),
        h("div", {},
          h("code", {}, model.intents.tls),
          h("span", {}, `URL: ${model.intents.urlCategories.length ? model.intents.urlCategories.join(", ") : "none"}`),
          h("span", {}, `DNS: ${model.intents.dns}`),
          h("span", {}, `File: ${model.intents.file}`)))),
    model.affectedRules.length ? h("div", { class: "object-ref-list" }, model.affectedRules.map(securityProfileImpactRuleRow)) : h("div", { class: "empty compact" },
      h("div", { html: icon("objects", 30) }),
      h("h3", {}, "No affected rules"),
      h("div", {}, "This security profile is defined but not attached to candidate rules."))) : h("div", {},
    missingObjectRouteAlert("securityProfiles", profileName),
    h("div", { class: "empty compact" },
      h("div", { html: icon("objects", 30) }),
      h("h3", {}, "No impact can be computed"),
      h("div", {}, "The requested security profile is not present in the candidate object table. It may have been deleted or renamed.")));
  openDrawer({
    title: "Security profile impact",
    subtitle: "Candidate rule blast radius and fail-closed posture.",
    width: "760px",
    body,
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close security profile impact", "aria-label": "Close security profile impact", dataset: { objectAction: "impact-close", objectKind: "securityProfiles" }, onclick: closeDrawer }, "Close"),
      h("a", { class: "btn", href: "#/inspection", title: "Open Inspection workspace", "aria-label": "Open Inspection workspace", dataset: { objectAction: "impact-open-inspection", objectKind: "securityProfiles", objectName: profileName }, onclick: closeDrawer }, h("span", { html: icon("threats", 16) }), "Open Inspection"),
      h("a", { class: "btn", href: "#/changes?tab=candidate", title: "Open candidate review", "aria-label": "Open candidate review", dataset: { objectAction: "impact-open-candidate", objectKind: "securityProfiles", objectName: profileName }, onclick: closeDrawer }, h("span", { html: icon("changes", 16) }), "Candidate review"),
      h("button", { class: "btn", type: "button", title: "Pin security profile impact to case", "aria-label": `Pin security profile impact for ${profileName} to case`, dataset: { objectAction: "impact-pin", objectKind: "securityProfiles", objectName: profileName }, onclick: () => pinSecurityProfileImpactHandoff(packet) }, h("span", { html: icon("inbox", 16) }), "Pin to case"),
      h("button", { class: "btn", type: "button", title: "Copy security profile impact handoff", "aria-label": `Copy security profile impact handoff for ${profileName}`, dataset: { objectAction: "impact-copy", objectKind: "securityProfiles", objectName: profileName }, onclick: () => copySecurityProfileImpactHandoff(packet) }, h("span", { html: icon("copy", 16) }), "Copy handoff"),
      h("button", { class: "btn", type: "button", title: "Export security profile impact JSON", "aria-label": `Export security profile impact JSON for ${profileName}`, dataset: { objectAction: "impact-export", objectKind: "securityProfiles", objectName: profileName }, onclick: () => exportSecurityProfileImpactHandoff(packet) }, h("span", { html: icon("download", 16) }), "Export JSON"),
      h("button", { class: "btn", type: "button", title: "Open security profile impact API and CLI context", "aria-label": `Open API and CLI context for ${profileName}`, dataset: { objectAction: "security-profile-impact-api-cli" }, onclick: () => openAutomationContext(route) },
        h("span", { html: icon("terminal", 16) }), "API / CLI"),
    ],
    onClose: clearObjectDrawerRoute,
  });
}

function securityProfileImpactRuleRow(rule = {}) {
  const target = objectReferenceTarget({ area: "security rule", item: rule.name, index: rule.index });
  const zones = `${(rule.fromZones || []).join(", ") || "any"} -> ${(rule.toZones || []).join(", ") || "any"}`;
  return h("div", { class: "object-ref-row" },
    h("div", {},
      h("strong", {}, rule.name),
      h("span", {}, `${actionLabel(rule.action)} - ${zones}`)),
    h("div", {},
      pill(rule.coverage?.label || "inspection", rule.coverage?.cls || "neutral", true),
      h("span", {}, rule.coverage?.detail || "Inspection coverage unavailable."),
      target ? h("a", { class: "btn sm ghost", href: target.href, title: `Open ${target.label}`, "aria-label": `Open ${target.label}`, dataset: { objectAction: "impact-open-rule", objectRule: rule.name || "" }, onclick: closeDrawer },
        h("span", { html: icon("arrowRight", 14) }), target.label) : null));
}

function securityProfileWorkflowPanel(workflow = {}) {
  const blockers = workflow.blockers || [];
  const warnings = workflow.warnings || [];
  const issues = [...blockers.map((detail) => ({ detail, tone: "bad", label: "blocker" })), ...warnings.map((detail) => ({ detail, tone: "warn", label: "warning" }))];
  return h("div", { class: "object-ref-list", dataset: { securityProfileWorkflow: "true" } },
    h("div", { class: "object-ref-row" },
      h("div", {},
        h("strong", {}, "Validation posture"),
        h("span", {}, issues.length ? `${blockers.length} blocker${blockers.length === 1 ? "" : "s"} / ${warnings.length} warning${warnings.length === 1 ? "" : "s"}` : "No profile blockers detected.")),
      h("div", {}, pill(workflow.posture?.label || "unknown", workflow.posture?.tone || "neutral", true))),
    issues.length ? h("ul", { class: "compact-list" }, issues.map((issue) =>
      h("li", {}, pill(issue.label, issue.tone, true), " ", issue.detail))) : null,
    ...(workflow.controls || []).map((control) => h("div", { class: "object-ref-row", dataset: { securityProfileControl: control.key } },
      h("div", {},
        h("strong", {}, control.label),
        h("span", {}, control.impact)),
      h("div", {},
        h("code", {}, control.posture || "unspecified"),
        h("span", {}, control.boundary)))),
    h("div", { class: "alert-box info" },
      h("strong", {}, "Enforcement boundary. "),
      (workflow.enforcementBoundaries || []).join(" ")));
}

function missingObjectRouteAlert(kind, objectName) {
  return h("div", { class: "alert-box warn", dataset: { objectRouteMissing: "true", objectKind: kind, objectName: objectName || "" } },
    h("strong", {}, `${singular(kind)[0].toUpperCase()}${singular(kind).slice(1)} not found. `),
    h("div", { class: "note" }, `${objectName} is not present in the current candidate object table. This shared route may be stale after an object was deleted or renamed.`),
    h("a", { class: "btn sm ghost", href: objectKindHashForMissing(kind), title: "Back to Objects", "aria-label": "Back to Objects", dataset: { objectAction: "back-to-objects" }, onclick: closeDrawer },
      h("span", { html: icon("arrowRight", 14) }), "Back to Objects"));
}

function objectKindHashForMissing(kind) {
  return `#/objects?tab=${encodeURIComponent(kind || "addresses")}`;
}

function metricTile(label, value) {
  return h("div", { class: "metric" },
    h("strong", {}, String(value ?? 0)),
    h("span", {}, label));
}

function securityProfileAttachmentStats(policy = {}, profileName = "") {
  const name = String(profileName || "").trim();
  const refs = objectReferenceRecords(policy, "securityProfiles", name).filter((ref) => String(ref.area || "").toLowerCase() === "security rule");
  const allowRuleCount = (policy.rules || []).filter((rule) => Array.isArray(rule.securityProfiles) && rule.securityProfiles.includes(name) && rule.action === "ACTION_ALLOW" && !rule.disabled).length;
  return { affectedRuleCount: refs.length, allowRuleCount };
}

function securityProfileIntentSummary(profile = {}) {
  return {
    tls: securityProfileTlsIntentLabel(profile?.tlsInspection),
    urlCategories: Array.isArray(profile?.urlCategories) ? profile.urlCategories.filter(Boolean) : [],
    dns: dnsSecurityLabel(profile?.dnsSecurity),
    file: fileSecurityLabel(profile?.fileSecurity),
  };
}

export function securityProfileWorkflowModel(profile = {}, opts = {}) {
  const exists = opts.exists ?? Boolean(profile);
  const categories = Array.isArray(profile?.urlCategories) ? profile.urlCategories.map((item) => String(item || "").trim()).filter(Boolean) : [];
  const categoryCheck = validateSecurityProfileUrlCategories(categories);
  const blockingIntent = opts.blockingIntent ?? securityProfileBlockingIntent(profile);
  const failClosedReady = Boolean(opts.failClosedReady);
  const affectedRuleCount = Number(opts.affectedRuleCount) || 0;
  const allowRuleCount = Number(opts.allowRuleCount) || 0;
  const blockers = [];
  const warnings = [];
  if (!exists) blockers.push("Profile is not present in the candidate object table.");
  if (profile?.tlsInspection === "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED" && !String(profile.description || "").trim()) {
    blockers.push("TLS decryption-required intent needs operator purpose plus external broker/certificate prerequisites.");
  }
  blockers.push(...categoryCheck.errors);
  if (blockingIntent && allowRuleCount > 0 && !failClosedReady) {
    blockers.push("Blocking DNS/URL/file/TLS intent on active allow rules requires IDS/IPS Prevent with fail-closed behavior before commit.");
  }
  if (opts.candidateOnly) warnings.push("Profile exists only in the candidate until commit.");
  if (exists && affectedRuleCount === 0) warnings.push("Profile is defined but not attached to any candidate rule.");
  if (profile?.tlsInspection === "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED") {
    warnings.push("TLS decryption remains review-only; this object does not manage CA keys, trust distribution, or a live TLS broker.");
  }
  if (profile?.fileSecurity && profile.fileSecurity !== "FILE_SECURITY_MODE_LOG_ONLY") {
    warnings.push("File blocking is declared policy intent; live file extraction/scanning proof remains hardening.");
  }
  const posture = blockers.length
    ? { state: "blocked", label: "blocked", tone: "bad" }
    : warnings.length
      ? { state: "review", label: "review required", tone: "warn" }
      : blockingIntent
        ? { state: "ready", label: "candidate ready", tone: "ok" }
        : { state: "observe", label: "observe/log", tone: "info" };
  return {
    posture,
    blockers,
    warnings,
    controls: securityProfileControlRows(profile),
    enforcementBoundaries: [
      "Objects stage declarative inspection intent to the candidate policy only.",
      "Rule attachment controls blast radius; commit, renderer support, engine health, and fail-closed posture decide enforcement.",
      "TLS key custody, live TLS interception, URL reputation feeds, DNS sinkhole proof, and file extraction/scanning evidence remain hardening unless separately validated.",
    ],
  };
}

export function validateSecurityProfileUrlCategories(categories = []) {
  const seen = new Set();
  const errors = [];
  for (const raw of categories) {
    const category = String(raw || "").trim();
    const normalized = category.toLowerCase();
    if (!category) continue;
    if (category !== normalized) {
      errors.push(`URL category "${category}" must be lowercase.`);
    }
    if (!/^[a-z0-9][a-z0-9_.:-]{0,63}$/.test(category)) {
      errors.push(`URL category "${category}" must use lowercase alphanumeric, '-', '_', '.', or ':' and be 1-64 characters.`);
    }
    if (seen.has(normalized)) {
      errors.push(`URL category "${category}" is duplicated.`);
    }
    seen.add(normalized);
  }
  return { ok: errors.length === 0, errors };
}

function securityProfileControlRows(profile = {}) {
  const urlCategories = Array.isArray(profile?.urlCategories) ? profile.urlCategories.filter(Boolean) : [];
  return [
    {
      key: "tls",
      label: "TLS / decryption",
      posture: securityProfileTlsIntentLabel(profile?.tlsInspection),
      impact: profile?.tlsInspection === "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED"
        ? "Requires external broker, certificate custody, trust rollout, and fail-closed review."
        : profile?.tlsInspection === "TLS_INSPECTION_MODE_BYPASS"
          ? "Explicitly bypasses TLS inspection intent for attached rules."
          : "Metadata-only inspection intent; no plaintext TLS claim.",
      boundary: "No CA key custody or live MITM is enabled by this object.",
    },
    {
      key: "dns",
      label: "DNS security",
      posture: dnsSecurityLabel(profile?.dnsSecurity),
      impact: profile?.dnsSecurity === "DNS_SECURITY_MODE_BLOCK_MALICIOUS" ? "Blocking intent inherits rule blast radius." : "DNS observations are log-only.",
      boundary: "DNS feed freshness and sinkhole/block proof require separate runtime evidence.",
    },
    {
      key: "url",
      label: "URL categories",
      posture: urlCategories.length ? urlCategories.join(", ") : "none",
      impact: urlCategories.length ? "Attached allow rules inherit URL category review/blocking intent." : "No URL category intent declared.",
      boundary: "URL reputation/content database enforcement is not proven by the object alone.",
    },
    {
      key: "file",
      label: "File security",
      posture: fileSecurityLabel(profile?.fileSecurity),
      impact: profile?.fileSecurity && profile.fileSecurity !== "FILE_SECURITY_MODE_LOG_ONLY" ? "File blocking intent inherits rule blast radius." : "File observations are log-only.",
      boundary: "Live file extraction, detonation, and scanner custody remain hardening.",
    },
  ];
}

function securityProfileBlockingIntent(profile = {}) {
  if (!profile) return false;
  return profile.tlsInspection === "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED" ||
    (profile.urlCategories || []).length > 0 ||
    profile.dnsSecurity === "DNS_SECURITY_MODE_BLOCK_MALICIOUS" ||
    profile.fileSecurity === "FILE_SECURITY_MODE_BLOCK_EXECUTABLES" ||
    profile.fileSecurity === "FILE_SECURITY_MODE_BLOCK_HIGH_RISK";
}

function securityProfileTlsIntentLabel(value = "") {
  if (value === "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED") return "decryption required";
  if (value === "TLS_INSPECTION_MODE_METADATA_ONLY") return "metadata only";
  if (value === "TLS_INSPECTION_MODE_BYPASS") return "bypass";
  return "default";
}

function actionLabel(value = "") {
  if (value === "ACTION_DENY") return "deny";
  if (value === "ACTION_REJECT") return "reject";
  if (value === "ACTION_ALLOW") return "allow";
  return value || "allow";
}

function pinSecurityProfileImpactHandoff(packet) {
  try {
    const result = pinInvestigationPacket(packet);
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Selected security profile impact evidence could not be pinned.", "bad");
  }
}

async function copySecurityProfileImpactHandoff(packet) {
  try {
    await navigator.clipboard.writeText(investigationPacketText(packet));
    toast("Handoff copied", "Security profile impact evidence copied as plain text.", "ok");
  } catch {
    toast("Copy failed", "Select the security profile impact evidence and copy it manually.", "warn");
  }
}

function exportSecurityProfileImpactHandoff(packet) {
  const text = investigationPacketJson(packet);
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: investigationPacketFilename(packet) });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  toast("Handoff exported", "Downloaded security profile impact evidence as JSON.", "ok");
}

function pinObjectReferenceHandoff(packet) {
  try {
    const result = pinInvestigationPacket(packet);
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Selected object reference evidence could not be pinned.", "bad");
  }
}

async function copyObjectReferenceHandoff(packet) {
  try {
    await navigator.clipboard.writeText(investigationPacketText(packet));
    toast("Handoff copied", "Object reference evidence copied as plain text.", "ok");
  } catch {
    toast("Copy failed", "Select the object reference evidence and copy it manually.", "warn");
  }
}

function exportObjectReferenceHandoff(packet) {
  const text = investigationPacketJson(packet);
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: investigationPacketFilename(packet) });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  toast("Handoff exported", "Downloaded object reference evidence as JSON.", "ok");
}

function referenceList(refs) {
  return h("div", { class: "object-ref-list" }, refs.map((ref) =>
    referenceRow(ref)));
}

function referenceRow(ref) {
  const target = objectReferenceTarget(ref);
  return h("div", { class: "object-ref-row" },
    h("div", {},
      h("strong", {}, ref.item),
      ref.itemId ? h("code", { class: "muted", title: "Durable policy item ID" }, ref.itemId) : null,
      h("span", {}, ref.area)),
    h("div", {},
      h("code", {}, ref.field),
      ref.detail ? h("span", {}, ref.detail) : null,
      target ? h("a", { class: "btn sm ghost", href: target.href, title: `Open ${target.label}`, "aria-label": `Open ${target.label}`, dataset: { objectReferenceAction: "open-target" }, onclick: closeDrawer },
        h("span", { html: icon("arrowRight", 14) }), target.label) : null));
}

function securityProfileImpactAction(name) {
  const profileName = name || "security profile";
  return h("button", {
    class: "icon-btn",
    type: "button",
    title: "Review security profile impact",
    "aria-label": `Review security profile impact for ${profileName}`,
    dataset: { objectAction: "impact", objectKind: "securityProfiles", objectName: name || "" },
    onclick: () => showSecurityProfileImpact(name),
    html: icon("threats", 16),
  });
}

function addrTable(wrap, root) {
  const list = session.draft.addresses || [];
  if (!list.length) return void wrap.appendChild(emptyState("objects", "No address objects", "Create named hosts and networks to reuse in rules."));
  wrap.appendChild(table(["Name", "CIDR", "Description", "Usage", ""], list.map((a, i) => h("tr", {},
    labeledCell("Name", h("strong", {}, a.name)),
    labeledCell("CIDR", { class: "mono" }, a.cidr),
    labeledCell("Description", { class: "muted" }, a.description || "—"),
    labeledCell("Usage", usageCell("addresses", a.name)),
    labeledCell("Actions", { class: "cell-actions" }, rowActions("addresses", i, root, a.name))))));
}
function svcTable(wrap, root) {
  const list = session.draft.services || [];
  if (!list.length) return void wrap.appendChild(emptyState("objects", "No service objects", "Define protocol/port matchers to reuse in rules."));
  wrap.appendChild(table(["Name", "Protocol", "Ports", "Description", "Usage", ""], list.map((s, i) => h("tr", {},
    labeledCell("Name", h("strong", {}, s.name)),
    labeledCell("Protocol", fmt.protoLabel(s.protocol)),
    labeledCell("Ports", { class: "mono" }, fmt.portList(s.ports)),
    labeledCell("Description", { class: "muted" }, s.description || "—"),
    labeledCell("Usage", usageCell("services", s.name)),
    labeledCell("Actions", { class: "cell-actions" }, rowActions("services", i, root, s.name))))));
}
function appTable(wrap, root) {
  const list = session.draft.applications || [];
  if (!list.length) return void wrap.appendChild(emptyState("objects", "No application objects", "Define custom Phragma App-ID entries from engine aliases or TCP/UDP port hints."));
  wrap.appendChild(table(["App-ID", "Display", "Category", "Signals", "Ports", "Usage", ""], list.map((a, i) => h("tr", {},
    labeledCell("App-ID", h("strong", {}, a.name)),
    labeledCell("Display", a.displayName || "—"),
    labeledCell("Category", a.category || "—"),
    labeledCell("Signals", { class: "mono" }, (a.engineSignals || []).length ? a.engineSignals.join(", ") : "—"),
    labeledCell("Ports", { class: "mono" }, appPorts(a)),
    labeledCell("Usage", usageCell("applications", a.name)),
    labeledCell("Actions", { class: "cell-actions" }, rowActions("applications", i, root, a.name))))));
}
function securityProfileTable(wrap, root) {
  const list = session.draft.securityProfiles || [];
  if (!list.length) return void wrap.appendChild(emptyState("objects", "No security profiles", "Define reusable TLS, DNS, URL, and file inspection intent to attach to rules."));
  wrap.appendChild(table(["Profile", "Posture", "TLS", "URL categories", "DNS", "File", "Usage", ""], list.map((profile, i) => h("tr", {},
    labeledCell("Profile", h("div", {}, h("strong", {}, profile.name), h("div", { class: "note" }, profile.description || "—"))),
    labeledCell("Posture", securityProfilePostureCell(profile)),
    labeledCell("TLS", securityProfileTlsCell(profile)),
    labeledCell("URL categories", { class: "mono" }, (profile.urlCategories || []).length ? profile.urlCategories.join(", ") : "—"),
    labeledCell("DNS", dnsSecurityLabel(profile.dnsSecurity)),
    labeledCell("File", fileSecurityLabel(profile.fileSecurity)),
    labeledCell("Usage", usageCell("securityProfiles", profile.name)),
    labeledCell("Actions", { class: "cell-actions" }, rowActions("securityProfiles", i, root, profile.name, [securityProfileImpactAction(profile.name)]))))));
}
function trafficControlTable(wrap, root) {
  const qos = session.draft.qosProfiles || [];
  const zoneProfiles = session.draft.zoneProtectionProfiles || [];
  if (!qos.length && !zoneProfiles.length) {
    return void wrap.appendChild(emptyState("traffic", "No traffic-control profiles", "Define QoS shaping and DoS zone-protection intent without claiming live tc/nft enforcement."));
  }
  const rows = [
    ...qos.map((profile, i) => trafficControlRow("qos", profile, i, root)),
    ...zoneProfiles.map((profile, i) => trafficControlRow("zoneProtection", profile, i, root)),
  ];
  wrap.appendChild(table(["Type", "Profile", "Intent", "Runtime posture", "Usage", ""], rows));
}
function trafficControlRow(type, profile, idx, root) {
  const kind = "trafficControls";
  const name = profile.name || "";
  const intent = type === "qos" ? qosProfileSummary(profile) : zoneProtectionSummary(profile);
  const editIdx = `${type}:${idx}`;
  return h("tr", { dataset: { trafficControlType: type, trafficControlName: name } },
    labeledCell("Type", type === "qos" ? "QoS / shaping" : "DoS zone protection"),
    labeledCell("Profile", h("div", {}, h("strong", {}, name), h("div", { class: "note" }, profile.description || "—"))),
    labeledCell("Intent", { class: "mono" }, intent),
    labeledCell("Runtime posture", pill("planned only", "warn", true)),
    labeledCell("Usage", usageCell(kind, name)),
    labeledCell("Actions", { class: "cell-actions" }, rowActions(kind, editIdx, root, name)));
}
function zoneTable(wrap, root) {
  const list = session.draft.zones || [];
  if (!list.length) return void wrap.appendChild(emptyState("objects", "No zones", "Group interfaces into security zones; rules match on zone pairs."));
  const discovered = discoveredSetupInterfaces(objectStatus);
  wrap.appendChild(table(["Name", "Interfaces", "Interface posture", "Zone protection", "Description", "Usage", ""], list.map((z, i) => {
    const review = zoneInterfaceReview(session.draft, z, discovered, { zoneIndex: i });
    return h("tr", { dataset: { zoneRow: z.name || `zone-${i + 1}` } },
    labeledCell("Name", h("strong", {}, z.name)),
    labeledCell("Interfaces", zoneInterfacePills(review)),
    labeledCell("Interface posture", zoneInterfacePostureCell(review)),
    labeledCell("Zone protection", z.zoneProtectionProfile ? h("span", { class: "tag" }, z.zoneProtectionProfile) : h("span", { class: "muted" }, "—")),
    labeledCell("Description", { class: "muted" }, z.description || "—"),
    labeledCell("Usage", usageCell("zones", z.name)),
    labeledCell("Actions", { class: "cell-actions" }, rowActions("zones", i, root, z.name)));
  })));
}

function table(headers, rows) {
  return responsiveTable(headers.map((x) => x === "" ? { label: "", attrs: { class: "actions-col" } } : x), rows);
}

function zoneInterfaceInventoryPanel(root) {
  const summary = objectStatusInventorySummary(objectStatus, objectStatusError, {
    loading: objectStatusLoading,
    staleDropCount: objectStatusStaleDropCount,
    staleIgnored: objectStatusLastRefreshIgnored,
  });
  const discovered = summary.discovered;
  return h("div", { class: "object-zone-inventory alert-box " + summary.tone, dataset: { zoneInventory: "true", zoneInventoryState: summary.state } },
    h("div", { class: "object-zone-inventory-head" },
      h("strong", {}, "Zone interface inventory"),
      pill(summary.label, summary.pillTone)),
    h("div", { class: "note" }, summary.detail),
    summary.staleNotice ? h("div", { class: "note" }, summary.staleNotice) : null,
    discovered.length ? h("div", { class: "object-zone-interface-strip" }, discovered.map((iface) =>
      h("span", { class: "object-zone-interface-chip", dataset: { zoneInterface: iface.name } },
        h("code", {}, iface.name),
        pill(iface.state || "unknown", iface.state && iface.state !== "ready" ? "warn" : "ok", true)))) : null,
    h("button", { class: "btn sm ghost", type: "button", title: "Refresh zone interface inventory", "aria-label": "Refresh zone interface inventory", disabled: objectStatusLoading, dataset: { zoneAction: "refresh-interfaces" }, onclick: async () => {
      const refresh = loadObjectStatus(true);
      paint(root);
      await refresh;
      paint(root);
    } },
      h("span", { html: icon("refresh", 14) }), objectStatusLoading ? "Refreshing" : "Refresh interfaces"));
}

function zoneInterfacePills(review = {}) {
  const rows = review.interfaces || [];
  if (!rows.length) return h("span", { class: "muted" }, "—");
  return h("div", { class: "object-zone-interface-list" }, rows.map((item) =>
    h("span", { class: `object-zone-interface-pill ${item.severity || "ok"}`, title: item.detail || item.name },
      h("code", {}, item.name),
      item.state ? h("small", {}, item.state) : null)));
}

function zoneInterfacePostureCell(review = {}) {
  const issues = review.issues || [];
  const tone = review.severity === "bad" ? "bad" : review.severity === "warn" ? "warn" : "ok";
  const label = review.severity === "bad" ? "blocked" : review.severity === "warn" ? "review" : "ready";
  return h("div", { class: "object-zone-posture", dataset: { zonePosture: label } },
    pill(label, tone, true),
    issues.length ? h("small", {}, issues[0].detail) : h("small", {}, "Assignments are unique and inventory-backed."));
}

function zoneInterfaceEditorPicker(discovered = [], input, onChange) {
  const grid = h("div", { class: "object-zone-interface-picker-grid" });
  const renderRows = () => {
    clear(grid);
    const selected = new Set(zoneInterfaceNames(input.value));
    if (!discovered.length) {
      grid.appendChild(h("div", { class: "note" }, "Live host interface inventory is unavailable; enter interface names manually."));
      return;
    }
    for (const iface of discovered) {
      const active = selected.has(iface.name);
      grid.appendChild(h("button", {
        class: "object-zone-interface-option " + (active ? "active" : ""),
        dataset: { zoneInterfaceOption: iface.name },
        type: "button",
        title: `${active ? "Remove" : "Add"} interface ${iface.name}`,
        "aria-label": `${active ? "Remove" : "Add"} interface ${iface.name}`,
        onclick: () => {
          const names = zoneInterfaceNames(input.value).filter((name) => name !== iface.name);
          if (!active) names.push(iface.name);
          input.value = names.join(", ");
          renderRows();
          onChange();
        },
      },
        h("span", { class: "object-zone-interface-option-main" },
          h("strong", {}, iface.name),
          h("small", {}, zoneInterfaceDetail(iface))),
        pill(iface.state || "unknown", iface.state && iface.state !== "ready" ? "warn" : "ok", true)));
    }
  };
  renderRows();
  return h("div", { class: "object-zone-interface-picker" },
    h("div", { class: "object-zone-interface-picker-head" },
      h("strong", {}, "Host inventory"),
      h("span", {}, discovered.length ? `${discovered.length} selectable` : "manual entry")),
    grid);
}

function zoneInterfaceEditorReview(review = {}) {
  const issues = review.issues || [];
  const severity = review.severity === "bad" ? "bad" : review.severity === "warn" ? "warn" : "ok";
  return h("div", { class: `object-zone-editor-review ${severity}`, dataset: { zoneReview: "editor", zoneReviewSeverity: severity } },
    h("div", { class: "object-zone-editor-review-head" },
      h("strong", {}, severity === "bad" ? "Resolve interface conflicts" : severity === "warn" ? "Review interface posture" : "Interface posture ready"),
      pill(severity === "bad" ? "blocked" : severity === "warn" ? "review" : "ready", severity, true)),
    issues.length
      ? h("div", { class: "setup-issues" }, issues.map((issue) =>
        h("div", { class: `setup-issue ${issue.severity}` },
          h("span", { html: icon(issue.severity === "bad" ? "block" : "clock", 14) }),
          h("span", {}, issue.detail))))
      : h("div", { class: "setup-okline" },
        h("span", { html: icon("check", 14) }),
        h("span", {}, "Assignments are unique. Live inventory is clean for the selected interfaces.")));
}

function zoneDraftWithProposal(policy = {}, idx, zone = {}) {
  const draft = structuredClone(policy || {});
  if (!Array.isArray(draft.zones)) draft.zones = [];
  let zoneIndex = idx;
  if (zoneIndex == null || zoneIndex < 0 || zoneIndex >= draft.zones.length) zoneIndex = draft.zones.length;
  draft.zones[zoneIndex] = zone;
  return { draft, zoneIndex };
}

function editObject(kind, idx, root) {
  const editing = idx != null;
  const slot = trafficControlSlot(idx);
  const obj = kind === "trafficControls"
    ? structuredClone(trafficControlObject(session.draft, slot) || {})
    : editing ? structuredClone(session.draft[kind][idx]) : {};
  let body, save;
  const fld = (l, c, help) => h("label", { class: "field" }, h("span", {}, l, help ? h("span", { class: "help" }, " — " + help) : null), c);

  if (kind === "addresses") {
    const name = inp(obj.name, "web-server"), cidr = inp(obj.cidr, "10.0.0.5/32 or 2001:db8::/64"), desc = inp(obj.description, "");
    body = h("div", {}, fld("Name", name), fld("CIDR", cidr, "host uses /32 or /128"), fld("Description", desc));
    save = (d) => upsert(d, "addresses", idx, { name: val(name), cidr: val(cidr), description: val(desc) }, val(name) && val(cidr));
  } else if (kind === "services") {
    const name = inp(obj.name, "https");
    const proto = h("select", {}, ...["PROTOCOL_TCP", "PROTOCOL_UDP", "PROTOCOL_ICMP", "PROTOCOL_ANY"].map((p) => h("option", { value: p }, fmt.protoLabel(p))));
    proto.value = obj.protocol || "PROTOCOL_TCP";
    const ports = inp(fmt.portList(obj.ports) === "any" ? "" : fmt.portList(obj.ports), "443, 8000-8100");
    body = h("div", {}, fld("Name", name), fld("Protocol", proto), fld("Ports", ports, "comma-separated; ranges with a dash; empty for ICMP/Any"));
    save = (d) => {
      const portCheck = validateObjectPortList(val(ports));
      if (!portCheck.ok) return { ok: false, title: "Service ports invalid", message: portCheck.message, tone: "warn" };
      return upsert(d, "services", idx, { name: val(name), protocol: proto.value, ports: portCheck.ports }, val(name));
    };
  } else if (kind === "applications") {
    const name = inp(obj.name, "corp-admin");
    const displayName = inp(obj.displayName, "Corporate Admin");
    const category = inp(obj.category, "business-app");
    const signals = inp((obj.engineSignals || []).join(", "), "corp-admin, custom-proto");
    const tcpPorts = inp(appProtocolPorts(obj, "PROTOCOL_TCP"), "8443, 9443-9445");
    const udpPorts = inp(appProtocolPorts(obj, "PROTOCOL_UDP"), "5353");
    const desc = inp(obj.description, "");
    body = h("div", {},
      fld("App-ID", name),
      fld("Display name", displayName),
      fld("Category", category),
      fld("Engine signals", signals, "comma-separated Suricata/nDPI-style aliases"),
      fld("TCP ports", tcpPorts, "low-confidence fallback only"),
      fld("UDP ports", udpPorts, "low-confidence fallback only"),
      fld("Description", desc));
    save = (d) => {
      const tcpCheck = validateObjectPortList(val(tcpPorts));
      const udpCheck = validateObjectPortList(val(udpPorts));
      if (!tcpCheck.ok) return { ok: false, title: "TCP ports invalid", message: tcpCheck.message, tone: "warn" };
      if (!udpCheck.ok) return { ok: false, title: "UDP ports invalid", message: udpCheck.message, tone: "warn" };
      const app = {
        name: val(name),
        displayName: val(displayName),
        category: val(category),
        engineSignals: csvList(val(signals)),
        ports: appPortHints(val(tcpPorts), val(udpPorts)),
        description: val(desc),
      };
      return upsert(d, "applications", idx, app, app.name && app.category && (app.engineSignals.length || app.ports.length));
    };
  } else if (kind === "securityProfiles") {
    const name = inp(obj.name, "inspect-standard", { securityProfileField: "name" });
    const tls = h("select", { dataset: { securityProfileField: "tls-inspection" } },
      h("option", { value: "TLS_INSPECTION_MODE_METADATA_ONLY" }, "Metadata only"),
      h("option", { value: "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED" }, "Decryption required (review-only)"),
      h("option", { value: "TLS_INSPECTION_MODE_BYPASS" }, "Bypass"));
    tls.value = obj.tlsInspection || "TLS_INSPECTION_MODE_METADATA_ONLY";
    const urlCategories = inp((obj.urlCategories || []).join(", "), "malware, phishing, newly-registered", { securityProfileField: "url-categories" });
    const dns = h("select", { dataset: { securityProfileField: "dns-security" } },
      h("option", { value: "DNS_SECURITY_MODE_LOG_ONLY" }, "Log only"),
      h("option", { value: "DNS_SECURITY_MODE_BLOCK_MALICIOUS" }, "Block malicious"));
    dns.value = obj.dnsSecurity || "DNS_SECURITY_MODE_LOG_ONLY";
    const file = h("select", { dataset: { securityProfileField: "file-security" } },
      h("option", { value: "FILE_SECURITY_MODE_LOG_ONLY" }, "Log only"),
      h("option", { value: "FILE_SECURITY_MODE_BLOCK_EXECUTABLES" }, "Block executables"),
      h("option", { value: "FILE_SECURITY_MODE_BLOCK_HIGH_RISK" }, "Block high risk"));
    file.value = obj.fileSecurity || "FILE_SECURITY_MODE_LOG_ONLY";
    const desc = inp(obj.description, "Purpose, owner, and TLS broker/certificate prerequisites if decryption is required", { securityProfileField: "description" });
    const workflowPreview = h("div", {});
    const candidateProfile = () => ({
      name: val(name),
      description: val(desc),
      tlsInspection: tls.value,
      urlCategories: csvList(val(urlCategories)),
      dnsSecurity: dns.value,
      fileSecurity: file.value,
    });
    const refreshWorkflowPreview = () => {
      const stats = securityProfileAttachmentStats(session.draft, editing ? obj.name || "" : val(name));
      const profile = candidateProfile();
      clear(workflowPreview);
      workflowPreview.appendChild(securityProfileEditorWorkflowPreview(securityProfileWorkflowModel(profile, {
        exists: true,
        affectedRuleCount: stats.affectedRuleCount,
        allowRuleCount: stats.allowRuleCount,
        blockingIntent: securityProfileBlockingIntent(profile),
        failClosedReady: Boolean(session.draft.ids?.enabled && session.draft.ids?.mode === "IDS_MODE_PREVENT" && (session.draft.ids?.failureBehavior || session.draft.ids?.failure_behavior) === "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED"),
        candidateOnly: !editing,
      })));
    };
    [name, urlCategories, desc].forEach((el) => el.addEventListener("input", refreshWorkflowPreview));
    [tls, dns, file].forEach((el) => el.addEventListener("change", refreshWorkflowPreview));
    body = h("div", { dataset: { securityProfileEditor: "true" } },
      h("div", { class: "alert-box info" },
        h("strong", {}, "Declarative inspection intent. "),
        "This profile is attached to rules for review, diff, audit, and future renderer integrations. It does not enable TLS interception or CA handling by itself."),
      fld("Name", name),
      fld("TLS inspection", tls, "decryption-required is review-only until external broker and certificate lifecycle are configured"),
      fld("URL categories", urlCategories, "comma-separated lowercase category labels"),
      fld("DNS security", dns),
      fld("File security", file),
      fld("Description", desc),
      workflowPreview);
    refreshWorkflowPreview();
    save = (d) => {
      const profile = candidateProfile();
      if (profile.tlsInspection === "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED" && !profile.description) {
        return { ok: false, title: "Description required", message: "Decryption-required profiles need operator intent and external broker/certificate prerequisites.", tone: "warn" };
      }
      const categoryCheck = validateSecurityProfileUrlCategories(profile.urlCategories);
      if (!categoryCheck.ok) return { ok: false, title: "URL categories invalid", message: categoryCheck.errors[0], tone: "warn" };
      return upsert(d, "securityProfiles", idx, profile, profile.name);
    };
  } else if (kind === "trafficControls") {
    const type = slot.type || "qos";
    const typeSel = h("select", { dataset: { trafficControlField: "type" } },
      h("option", { value: "qos" }, "QoS / shaping"),
      h("option", { value: "zoneProtection" }, "DoS zone protection"));
    typeSel.value = type;
    const name = inp(obj.name, type === "zoneProtection" ? "internet-edge-dos" : "voice-priority", { trafficControlField: "name" });
    const desc = inp(obj.description, "", { trafficControlField: "description" });
    const qosFields = h("div", { dataset: { trafficControlSection: "qos" } });
    const dosFields = h("div", { dataset: { trafficControlSection: "zone-protection" } });
    const maxRate = inp(obj.maxBandwidthKbps || "", "50000", { trafficControlField: "max-bandwidth-kbps" });
    const guarantee = inp(obj.guaranteedBandwidthKbps || "", "10000", { trafficControlField: "guaranteed-bandwidth-kbps" });
    const priority = h("select", { dataset: { trafficControlField: "priority" } },
      h("option", { value: "QOS_PRIORITY_LOW" }, "Low"),
      h("option", { value: "QOS_PRIORITY_MEDIUM" }, "Medium"),
      h("option", { value: "QOS_PRIORITY_HIGH" }, "High"),
      h("option", { value: "QOS_PRIORITY_CRITICAL" }, "Critical"));
    priority.value = obj.priority || "QOS_PRIORITY_MEDIUM";
    const dscp = inp(obj.dscpMark || "", "46", { trafficControlField: "dscp-mark" });
    const burst = inp(obj.burstKbytes || "", "1024", { trafficControlField: "burst-kbytes" });
    qosFields.append(
      fld("Max bandwidth Kbps", maxRate, "0-100000000; 0 means no maximum intent"),
      fld("Guaranteed bandwidth Kbps", guarantee, "cannot exceed maximum when maximum is set"),
      fld("Priority", priority),
      fld("DSCP mark", dscp, "0-63; 0 means no marking intent"),
      fld("Burst KiB", burst, "0-1048576"));
    const enabled = toggleField(obj.enabled !== false, () => {}, "zone-protection-enabled");
    const syn = inp(obj.synFloodPps || "", "20000", { trafficControlField: "syn-flood-pps" });
    const udp = inp(obj.udpFloodPps || "", "50000", { trafficControlField: "udp-flood-pps" });
    const icmp = inp(obj.icmpFloodPps || "", "10000", { trafficControlField: "icmp-flood-pps" });
    const conns = inp(obj.maxConcurrentConnections || "", "1000000", { trafficControlField: "max-concurrent-connections" });
    const action = h("select", { dataset: { trafficControlField: "zone-protection-action" } },
      h("option", { value: "ZONE_PROTECTION_ACTION_ALERT" }, "Alert"),
      h("option", { value: "ZONE_PROTECTION_ACTION_DROP" }, "Drop"));
    action.value = obj.action || "ZONE_PROTECTION_ACTION_ALERT";
    const auditLog = toggleField(Boolean(obj.auditLog), () => {}, "zone-protection-audit-log");
    dosFields.append(
      fld("Enabled", enabled),
      fld("Action", action),
      fld("SYN flood pps", syn, "0-10000000"),
      fld("UDP flood pps", udp, "0-10000000"),
      fld("ICMP flood pps", icmp, "0-10000000"),
      fld("Max concurrent connections", conns, "0-100000000"),
      fld("Audit log", auditLog));
    const refreshType = () => {
      qosFields.style.display = typeSel.value === "qos" ? "" : "none";
      dosFields.style.display = typeSel.value === "zoneProtection" ? "" : "none";
    };
    typeSel.onchange = refreshType;
    body = h("div", { dataset: { trafficControlEditor: "true" } },
      h("div", { class: "alert-box info" },
        h("strong", {}, "Plan-only traffic control intent. "),
        "This slice stages bounded QoS and DoS policy intent and render-plan posture; live tc/nft enforcement certification is tracked separately."),
      fld("Type", typeSel),
      fld("Name", name),
      fld("Description", desc),
      qosFields,
      dosFields);
    refreshType();
    save = (d) => {
      const selectedType = typeSel.value === "zoneProtection" ? "zoneProtection" : "qos";
      const common = { name: val(name), description: val(desc) };
      if (selectedType === "qos") {
        const profile = {
          ...common,
          maxBandwidthKbps: wholeNumber(val(maxRate)),
          guaranteedBandwidthKbps: wholeNumber(val(guarantee)),
          priority: priority.value,
          dscpMark: wholeNumber(val(dscp)),
          burstKbytes: wholeNumber(val(burst)),
        };
        const issue = trafficControlProfileIssue("qos", profile);
        if (issue) return { ok: false, title: "QoS profile invalid", message: issue, tone: "warn" };
        return upsertTrafficControl(d, slot, selectedType, profile, profile.name);
      }
      const profile = {
        ...common,
        enabled: enabled.querySelector("input")?.checked ?? true,
        synFloodPps: wholeNumber(val(syn)),
        udpFloodPps: wholeNumber(val(udp)),
        icmpFloodPps: wholeNumber(val(icmp)),
        maxConcurrentConnections: wholeNumber(val(conns)),
        action: action.value,
        auditLog: auditLog.querySelector("input")?.checked ?? false,
      };
      const issue = trafficControlProfileIssue("zoneProtection", profile);
      if (issue) return { ok: false, title: "Zone protection invalid", message: issue, tone: "warn" };
      return upsertTrafficControl(d, slot, selectedType, profile, profile.name);
    };
  } else {
    const name = inp(obj.name, "lan", { zoneField: "name" });
    const ifaces = inp(zoneInterfaceNames(obj.interfaces).join(", "), "eth1, eth2", { zoneField: "interfaces" });
    const desc = inp(obj.description, "", { zoneField: "description" });
    const protection = h("select", { dataset: { zoneField: "zone-protection-profile" } },
      h("option", { value: "" }, "No zone protection"),
      ...(session.draft.zoneProtectionProfiles || []).map((profile) => h("option", { value: profile.name }, profile.name)));
    protection.value = obj.zoneProtectionProfile || "";
    const discovered = discoveredSetupInterfaces(objectStatus);
    const reviewSlot = h("div", {});
    const candidateZone = () => ({ name: val(name), interfaces: zoneInterfaceNames(ifaces.value), description: val(desc), zoneProtectionProfile: protection.value });
    const refreshReview = () => {
      clear(reviewSlot);
      const zone = candidateZone();
      const proposal = zoneDraftWithProposal(session.draft, idx, zone);
      reviewSlot.appendChild(zoneInterfaceEditorReview(zoneInterfaceReview(proposal.draft, zone, discovered, { zoneIndex: proposal.zoneIndex })));
    };
    name.addEventListener("input", refreshReview);
    ifaces.addEventListener("input", refreshReview);
    const picker = zoneInterfaceEditorPicker(discovered, ifaces, refreshReview);
    body = h("div", { dataset: { zoneEditor: "true" } },
      fld("Name", name),
      fld("Interfaces", ifaces, "comma-separated NIC names"),
      picker,
      fld("Zone protection", protection, "plan-only DoS profile; live flood enforcement proof is hardening"),
      fld("Description", desc),
      reviewSlot);
    refreshReview();
    save = (d) => {
      const zone = candidateZone();
      const proposal = zoneDraftWithProposal(d, idx, zone);
      const review = zoneInterfaceReview(proposal.draft, zone, discoveredSetupInterfaces(objectStatus), { zoneIndex: proposal.zoneIndex });
      const blocking = review.issues.find((issue) => issue.severity === "bad");
      if (!zone.name) return false;
      if (blocking) return { ok: false, title: "Interface conflict", message: blocking.detail, tone: "bad" };
      return upsert(d, "zones", idx, zone, true);
    };
  }

  openDrawer({
    title: (editing ? "Edit " : "New ") + singular(kind), subtitle: "Stages to candidate.", width: "480px", body,
    footer: [h("button", { class: "btn ghost", type: "button", title: `Cancel ${singular(kind)} edit`, "aria-label": `Cancel ${singular(kind)} edit`, dataset: { objectAction: "cancel-editor", objectKind: kind }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: `Save ${singular(kind)} to candidate`, "aria-label": `Save ${singular(kind)} to candidate`, dataset: { objectAction: "save-editor", objectKind: kind }, onclick: () => saveObjectEditor(kind, idx, root, save) }, "Save")],
  });
}

async function saveObjectEditor(kind, idx, root, save, opts = {}) {
  const editing = idx != null;
  const current = kind === "trafficControls" && editing
    ? trafficControlObject(session.draft, trafficControlSlot(idx)) || {}
    : editing ? session.draft[kind]?.[idx] || {} : {};
  const oldName = String(current.name || "").trim();
  let previewResult = { ok: true };
  try {
    const probe = structuredClone(session.draft || {});
    previewResult = normalizeObjectEditorSaveResult(save(probe));
  } catch (e) {
    toast("Failed", e.message, "bad");
    return;
  }
  if (!previewResult.ok) {
    toast(previewResult.title || "Missing fields", previewResult.message || "Fill in the required fields.", previewResult.tone || "warn");
    return;
  }
  const newName = String(previewResult.obj?.name || "").trim();
  if (!editing && objectNameExists(session.draft, kind, newName)) {
    toast("Name already exists", `${newName} already exists in ${singular(kind)} objects. Choose a unique name before staging the object.`, "warn");
    return;
  }
  const renamed = editing && oldName && newName && oldName !== newName;
  if (renamed && objectNameExists(session.draft, kind, newName, idx)) {
    toast("Name already exists", `${newName} already exists in ${singular(kind)} objects. Choose a unique name before staging the rename.`, "warn");
    return;
  }
  const renameReview = renamed ? objectRenameReviewModel(session.draft, kind, oldName, newName, { exceptIndex: idx }) : null;
  if (renamed && renameReview?.refs.length && !opts.confirmedRename) {
    openObjectRenameReview({ kind, idx, root, save, model: renameReview });
    return;
  }
  try {
    let saveResult = { ok: true };
    let rewriteCount = 0;
    await session.apply((d) => {
      saveResult = normalizeObjectEditorSaveResult(save(d));
      if (!saveResult.ok) {
        throw new ObjectEditorValidationAbort(saveResult);
      }
      if (saveResult.ok && renamed && opts.confirmedRename) {
        rewriteCount = rewriteObjectReferences(d, kind, oldName, newName);
      }
    });
    await loadReferenceCache(kind, true);
    closeDrawer();
    paint(root);
    toast("Saved", rewriteCount ? `Staged rename and rewrote ${rewriteCount} candidate reference${rewriteCount === 1 ? "" : "s"}.` : "Staged to candidate.", "ok");
  }
  catch (e) {
    if (e instanceof ObjectEditorValidationAbort) {
      toast(e.result.title || "Missing fields", e.result.message || "Fill in the required fields.", e.result.tone || "warn");
      return;
    }
    toast("Failed", e.message, "bad");
  }
}

function openObjectRenameReview({ kind, idx, root, save, model }) {
  const oldName = model.oldName;
  const newName = model.newName;
  openDrawer({
    title: `Rename ${singular(kind)}?`,
    subtitle: "Reviewed candidate reference rewrite.",
    width: "680px",
    body: h("div", { dataset: { objectRenameReview: "true", objectKind: kind, objectOldName: oldName, objectNewName: newName } },
      h("div", { class: "alert-box warn" },
        h("strong", {}, "Referenced object rename. "),
        `${model.referenceCount} candidate policy reference${model.referenceCount === 1 ? "" : "s"} currently point at ${oldName}.`),
      h("dl", { class: "kv compact" },
        h("dt", {}, "Object kind"), h("dd", { class: "mono" }, singular(kind)),
        h("dt", {}, "Current name"), h("dd", { class: "mono" }, oldName),
        h("dt", {}, "New name"), h("dd", { class: "mono" }, newName)),
      h("div", { class: "note" }, "Staging the rename will update the object and rewrite supported candidate references in rules, host-input rules, and NAT entries in the same candidate mutation."),
      h("div", { class: "object-ref-list" }, objectRenameReviewRows(model))),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: `Cancel ${singular(kind)} rename`, "aria-label": `Cancel ${singular(kind)} rename`, dataset: { objectAction: "cancel-rename", objectKind: kind }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: `Stage ${singular(kind)} rename and reference rewrites`, "aria-label": `Stage ${singular(kind)} rename and reference rewrites`, dataset: { objectAction: "confirm-rename", objectKind: kind }, onclick: () => saveObjectEditor(kind, idx, root, save, { confirmedRename: true }) },
        h("span", { html: icon("check", 16) }), "Stage rename"),
    ],
  });
}

function objectRenameReviewRows(model = {}) {
  const groups = model.groups || [];
  if (!groups.length) return [h("div", { class: "empty compact" }, "No supported candidate references need rewriting.")];
  return groups.map((group) => h("div", { class: "object-ref-row", dataset: { objectRenameArea: group.area } },
    h("div", {},
      h("strong", {}, group.label),
      h("small", { class: "muted" }, group.area),
      h("span", {}, `${group.refs.length} reference${group.refs.length === 1 ? "" : "s"}`)),
    h("div", {},
      h("code", {}, group.fields.join(", ")),
      h("span", {}, group.refs.map((ref) => ref.item).join(", ")))));
}

function objectReferenceGroups(refs = []) {
  const map = new Map();
  for (const ref of refs) {
    const area = ref.area || "policy";
    if (!map.has(area)) {
      map.set(area, {
        area,
        label: objectReferenceAreaLabel(area),
        refs: [],
        fields: [],
      });
    }
    const group = map.get(area);
    group.refs.push(ref);
    if (ref.field && !group.fields.includes(ref.field)) group.fields.push(ref.field);
  }
  return [...map.values()].sort((a, b) => a.label.localeCompare(b.label));
}

function objectReferenceAreaLabel(area = "") {
  const normalized = String(area || "").trim().toLowerCase();
  if (normalized === "security rule") return "Security rules";
  if (normalized === "zone") return "Zones";
  if (normalized === "host-input rule") return "Host-input rules";
  if (normalized === "ids exception") return "IDS exceptions";
  if (normalized === "source nat") return "Source NAT";
  if (normalized === "destination nat") return "Destination NAT";
  return area || "Policy";
}

export function rewriteObjectReferences(policy = {}, kind = "", oldName = "", newName = "") {
  const from = String(oldName || "").trim();
  const to = String(newName || "").trim();
  if (!from || !to || from === to) return 0;
  let count = 0;
  const rewriteList = (item, field) => {
    if (!Array.isArray(item?.[field])) return;
    let changed = false;
    item[field] = item[field].map((value) => {
      if (value !== from) return value;
      changed = true;
      return to;
    });
    if (changed) count += 1;
  };
  const rewriteValue = (item, field) => {
    if (!item || item[field] !== from) return;
    item[field] = to;
    count += 1;
  };
  if (kind === "trafficControls") {
    (policy.rules || []).forEach((rule) => rewriteValue(rule, "qosProfile"));
    (policy.zones || []).forEach((zone) => rewriteValue(zone, "zoneProtectionProfile"));
    return count;
  }

  const ruleFields = kind === "zones"
    ? ["fromZones", "toZones"]
    : kind === "addresses"
      ? ["sourceAddresses", "destinationAddresses"]
      : kind === "applications"
        ? ["applications"]
        : kind === "securityProfiles"
          ? ["securityProfiles"]
          : ["services"];
  (policy.rules || []).forEach((rule) => ruleFields.forEach((field) => rewriteList(rule, field)));

  const hostInputFields = kind === "zones"
    ? ["fromZones"]
    : kind === "addresses"
      ? ["sourceAddresses"]
      : kind === "services"
        ? ["services"]
        : [];
  (policy.hostInput?.rules || []).forEach((rule) => hostInputFields.forEach((field) => rewriteList(rule, field)));

  const idsExceptionFields = kind === "addresses" ? ["sourceAddress", "destinationAddress"] : [];
  (policy.ids?.exceptions || []).forEach((exception) => idsExceptionFields.forEach((field) => rewriteValue(exception, field)));

  const sourceNatFields = kind === "zones"
    ? ["toZone"]
    : kind === "addresses"
      ? ["sourceAddress", "translatedAddress"]
      : [];
  (policy.nat?.source || []).forEach((rule) => sourceNatFields.forEach((field) => rewriteValue(rule, field)));

  const destinationNatFields = kind === "zones"
    ? ["fromZone"]
    : kind === "addresses"
      ? ["destinationAddress", "translatedAddress"]
      : kind === "services"
        ? ["service"]
        : [];
  (policy.nat?.destination || []).forEach((rule) => destinationNatFields.forEach((field) => rewriteValue(rule, field)));

  return count;
}

export function objectExists(policy = {}, kind = "", name = "") {
  const target = String(name || "").trim();
  if (!target) return false;
  if (kind === "trafficControls") {
    return (policy.qosProfiles || []).some((item) => item?.name === target) ||
      (policy.zoneProtectionProfiles || []).some((item) => item?.name === target);
  }
  return (policy[kind] || []).some((item) => item?.name === target);
}

function objectNameExists(policy = {}, kind = "", name = "", exceptIndex = -1) {
  const target = String(name || "").trim();
  if (!target) return false;
  if (kind === "trafficControls") {
    const except = trafficControlSlot(exceptIndex);
    return (policy.qosProfiles || []).some((item, index) => !(except.type === "qos" && except.index === index) && item?.name === target) ||
      (policy.zoneProtectionProfiles || []).some((item, index) => !(except.type === "zoneProtection" && except.index === index) && item?.name === target);
  }
  return (policy[kind] || []).some((item, index) => index !== exceptIndex && item?.name === target);
}

function trafficControlSlot(idx) {
  if (typeof idx === "string") {
    const [type, rawIndex] = idx.split(":");
    return { type: type === "zoneProtection" ? "zoneProtection" : type === "qos" ? "qos" : "", index: Number(rawIndex) };
  }
  return { type: "", index: Number(idx) };
}

function trafficControlObject(policy = {}, slot = {}) {
  if (slot.type === "qos") return (policy.qosProfiles || [])[slot.index] || null;
  if (slot.type === "zoneProtection") return (policy.zoneProtectionProfiles || [])[slot.index] || null;
  return null;
}

function upsertTrafficControl(d, slot = {}, type = "qos", profile = {}, valid = true) {
  if (!valid) return false;
  const key = type === "zoneProtection" ? "zoneProtectionProfiles" : "qosProfiles";
  const oldKey = slot.type === "zoneProtection" ? "zoneProtectionProfiles" : slot.type === "qos" ? "qosProfiles" : "";
  if (oldKey && oldKey !== key && Number.isInteger(slot.index)) {
    d[oldKey]?.splice(slot.index, 1);
  }
  if (!d[key]) d[key] = [];
  const sameArrayEdit = oldKey === key && Number.isInteger(slot.index);
  if (sameArrayEdit) d[key][slot.index] = profile; else d[key].push(profile);
  return { ok: true, obj: profile };
}

function deleteObjectAt(d, kind, idx) {
  if (kind === "trafficControls") {
    const slot = trafficControlSlot(idx);
    const key = slot.type === "zoneProtection" ? "zoneProtectionProfiles" : slot.type === "qos" ? "qosProfiles" : "";
    if (key) d[key]?.splice(slot.index, 1);
    return;
  }
  d[kind].splice(idx, 1);
}

function wholeNumber(value) {
  const text = String(value || "").trim();
  if (!text) return 0;
  const n = Number(text);
  return Number.isFinite(n) ? Math.trunc(n) : NaN;
}

function trafficControlProfileIssue(type, profile = {}) {
  if (!profile.name) return "Name is required.";
  if (type === "qos") {
    const max = Number(profile.maxBandwidthKbps || 0);
    const guaranteed = Number(profile.guaranteedBandwidthKbps || 0);
    if (![max, guaranteed, Number(profile.dscpMark || 0), Number(profile.burstKbytes || 0)].every(Number.isFinite)) return "Numeric fields must be whole numbers.";
    if (max < 0 || max > 100000000) return "Max bandwidth must be 0-100000000 Kbps.";
    if (guaranteed < 0 || guaranteed > 100000000) return "Guaranteed bandwidth must be 0-100000000 Kbps.";
    if (max > 0 && guaranteed > max) return "Guaranteed bandwidth cannot exceed max bandwidth.";
    if (Number(profile.dscpMark || 0) < 0 || Number(profile.dscpMark || 0) > 63) return "DSCP mark must be 0-63.";
    if (Number(profile.burstKbytes || 0) < 0 || Number(profile.burstKbytes || 0) > 1048576) return "Burst must be 0-1048576 KiB.";
    if (max === 0 && guaranteed === 0 && Number(profile.dscpMark || 0) === 0) return "Set max bandwidth, guaranteed bandwidth, or DSCP marking intent.";
    return "";
  }
  const values = [profile.synFloodPps, profile.udpFloodPps, profile.icmpFloodPps, profile.maxConcurrentConnections].map((v) => Number(v || 0));
  if (!values.every(Number.isFinite)) return "Numeric fields must be whole numbers.";
  if (values.slice(0, 3).some((v) => v < 0 || v > 10000000)) return "Flood thresholds must be 0-10000000 pps.";
  if (values[3] < 0 || values[3] > 100000000) return "Max concurrent connections must be 0-100000000.";
  if (profile.enabled && values.every((v) => v === 0)) return "Enabled zone protection requires at least one threshold.";
  return "";
}

function qosProfileSummary(profile = {}) {
  return [
    profile.maxBandwidthKbps ? `max ${profile.maxBandwidthKbps} Kbps` : "",
    profile.guaranteedBandwidthKbps ? `min ${profile.guaranteedBandwidthKbps} Kbps` : "",
    profile.priority ? profile.priority.replace(/^QOS_PRIORITY_/, "").toLowerCase() : "",
    profile.dscpMark ? `DSCP ${profile.dscpMark}` : "",
  ].filter(Boolean).join(" · ") || "no bounded shaping intent";
}

function zoneProtectionSummary(profile = {}) {
  return [
    profile.enabled ? "enabled" : "disabled",
    profile.action ? profile.action.replace(/^ZONE_PROTECTION_ACTION_/, "").toLowerCase() : "",
    profile.synFloodPps ? `SYN ${profile.synFloodPps}/s` : "",
    profile.udpFloodPps ? `UDP ${profile.udpFloodPps}/s` : "",
    profile.icmpFloodPps ? `ICMP ${profile.icmpFloodPps}/s` : "",
    profile.maxConcurrentConnections ? `conn ${profile.maxConcurrentConnections}` : "",
  ].filter(Boolean).join(" · ") || "no threshold intent";
}

async function loadObjectStatus(force = false) {
  if (!force && objectStatusLoaded) return;
  const requestSeq = ++objectStatusRequestSeq;
  objectStatusLoading = true;
  objectStatusLastRefreshIgnored = false;
  objectStatusLoaded = true;
  try {
    const nextStatus = await api.status();
    if (requestSeq !== objectStatusRequestSeq) {
      objectStatusStaleDropCount += 1;
      objectStatusLastRefreshIgnored = true;
      return;
    }
    objectStatus = nextStatus;
    objectStatusError = null;
  } catch (e) {
    if (requestSeq !== objectStatusRequestSeq) {
      objectStatusStaleDropCount += 1;
      objectStatusLastRefreshIgnored = true;
      return;
    }
    objectStatus = null;
    objectStatusError = e;
  } finally {
    if (requestSeq === objectStatusRequestSeq) objectStatusLoading = false;
  }
}

export function objectStatusInventorySummary(status = null, error = null, opts = {}) {
  const discovered = discoveredSetupInterfaces(status);
  const loading = Boolean(opts.loading);
  const staleDropCount = Number(opts.staleDropCount) || 0;
  const staleIgnored = Boolean(opts.staleIgnored || staleDropCount);
  if (loading) {
    return {
      state: "refreshing",
      label: "refreshing inventory",
      pillTone: "info",
      tone: "info",
      discovered,
      detail: "Refreshing live host interface inventory. Candidate zone assignments remain editable while the latest response is pending.",
      staleNotice: staleIgnored ? `Ignored ${staleDropCount} stale host inventory response${staleDropCount === 1 ? "" : "s"} from an older refresh.` : "",
    };
  }
  if (error) {
    return {
      state: "unavailable",
      label: "host status unavailable",
      pillTone: "warn",
      tone: "warn",
      discovered,
      detail: "Status is unavailable; manual interface names are still supported, but host inventory warnings may be incomplete.",
      staleNotice: staleIgnored ? `Ignored ${staleDropCount} stale host inventory response${staleDropCount === 1 ? "" : "s"} from an older refresh.` : "",
    };
  }
  if (discovered.length) {
    return {
      state: "ready",
      label: `${discovered.length} host interface${discovered.length === 1 ? "" : "s"} discovered`,
      pillTone: "info",
      tone: "info",
      discovered,
      detail: "Zones now compare candidate interface assignments against live host inventory before commit.",
      staleNotice: staleIgnored ? `Ignored ${staleDropCount} stale host inventory response${staleDropCount === 1 ? "" : "s"} from an older refresh.` : "",
    };
  }
  return {
    state: "empty",
    label: "no live inventory",
    pillTone: "neutral",
    tone: "info",
    discovered,
    detail: "No host interface inventory is loaded; manual interface names are still supported for offline staging.",
    staleNotice: staleIgnored ? `Ignored ${staleDropCount} stale host inventory response${staleDropCount === 1 ? "" : "s"} from an older refresh.` : "",
  };
}

async function loadReferenceCache(kind, force = false) {
  const apiKinds = [].concat(API_OBJECT_KIND[kind] || []);
  if (!apiKinds.length) return;
  const key = referenceCacheKey(kind);
  if (!force && referenceCache.key === key) return;
  try {
    const responses = await Promise.all(apiKinds.map((apiKind) => api.objectReferences({ source: referencePolicySource(), kind: apiKind })));
    referenceCache = {
      key,
      refs: responses.flatMap((data) => data.references || []).map(normalizeAPIReference),
      error: "",
    };
  } catch (e) {
    throwIfAccessDenied({ status: "rejected", reason: e });
    referenceCache = { key, refs: null, error: e.message || String(e) };
  }
}

function referencesFor(kind, name) {
  if (referenceCache.key === referenceCacheKey(kind) && Array.isArray(referenceCache.refs)) {
    return referenceCache.refs.filter((ref) => ref.objectName === name);
  }
  return objectReferenceRecords(session.draft, kind, name);
}

function referencePolicySource() {
  return session.hasCandidate ? "POLICY_SOURCE_CANDIDATE" : "POLICY_SOURCE_RUNNING";
}

function referenceCacheKey(kind) {
  return objectReferenceCacheKey({
    source: referencePolicySource(),
    runningVersion: session.runningVersion,
    draft: session.draft,
    kind,
  });
}

export function objectReferenceCacheKey({ source, runningVersion = 0, draft = {}, kind = "" } = {}) {
  const revision = source === "POLICY_SOURCE_CANDIDATE" ? fingerprint(draft || {}) : `running:${Number(runningVersion) || 0}`;
  return `${source || "POLICY_SOURCE_RUNNING"}|${Number(runningVersion) || 0}|${kind}|${revision}`;
}

function normalizeAPIReference(ref = {}) {
  return {
    objectName: ref.objectName || ref.object_name || "",
    area: ref.area || "",
    item: ref.item || "",
    itemId: ref.itemId || ref.item_id || "",
    index: Number(ref.index) || 0,
    field: ref.field || "",
    detail: ref.detail || "",
  };
}

function referenceSourceText(kind) {
  if (referenceCache.key === referenceCacheKey(kind) && Array.isArray(referenceCache.refs)) {
    return "Reference data from /v1/policy/object-references.";
  }
  return referenceCache.error
    ? "Reference API unavailable; showing local draft scan."
    : "Reference data from local draft scan.";
}

export function zoneInterfaceNames(value = []) {
  if (Array.isArray(value)) return splitInterfaceList(value.join(","));
  return splitInterfaceList(value);
}

export function zoneInterfaceReview(policy = {}, zone = {}, discovered = [], opts = {}) {
  const zoneIndex = Number.isInteger(opts.zoneIndex) ? opts.zoneIndex : -1;
  const names = zoneInterfaceNames(zone.interfaces);
  const known = new Map((Array.isArray(discovered) ? discovered : [])
    .map(normalizeDiscoveredZoneInterface)
    .filter((iface) => iface.name)
    .map((iface) => [interfaceKey(iface.name), iface]));
  const assignments = zoneInterfaceAssignments(policy);
  const interfaces = names.map((name) => {
    const key = interfaceKey(name);
    const assigned = assignments.get(key) || [];
    const otherZones = assigned.filter((item) => item.index !== zoneIndex);
    const iface = known.get(key);
    const issues = [];
    if (key === "lo") {
      issues.push({ severity: "bad", detail: "Loopback cannot be assigned to a security zone." });
    }
    if (otherZones.length) {
      issues.push({ severity: "bad", detail: `${name} is already assigned to ${otherZones.map((item) => item.zoneName).join(", ")}.` });
    }
    if (known.size && key !== "lo") {
      if (!iface) {
        issues.push({ severity: "warn", detail: `${name} was not reported by this host.` });
      } else if (iface.state && iface.state !== "ready") {
        issues.push({ severity: "warn", detail: `${name} is ${iface.state}${iface.detail ? ": " + iface.detail : "."}` });
      }
    }
    return {
      name,
      state: iface?.state || (known.size ? "unknown" : ""),
      detail: iface ? zoneInterfaceDetail(iface) : known.size ? "not present in live host inventory" : "live host inventory unavailable",
      issues,
      severity: zoneInterfaceSeverity(issues),
    };
  });
  const issues = [];
  if (!names.length) issues.push({ severity: "warn", detail: "Assign at least one interface before using this zone for transit policy." });
  for (const item of interfaces) issues.push(...item.issues);
  const uniqueIssues = dedupeZoneInterfaceIssues(issues);
  return {
    interfaces,
    issues: uniqueIssues,
    severity: zoneInterfaceSeverity(uniqueIssues),
    inventoryAvailable: known.size > 0,
  };
}

function normalizeDiscoveredZoneInterface(iface = {}) {
  return {
    name: String(iface?.name || "").trim(),
    state: String(iface?.state || "unknown").trim() || "unknown",
    detail: String(iface?.detail || "").trim(),
    rxBytes: Number(iface?.rxBytes || 0),
    txBytes: Number(iface?.txBytes || 0),
    rxDrops: Number(iface?.rxDrops || 0),
    txDrops: Number(iface?.txDrops || 0),
    rxErrors: Number(iface?.rxErrors || 0),
    txErrors: Number(iface?.txErrors || 0),
  };
}

function zoneInterfaceAssignments(policy = {}) {
  const assignments = new Map();
  (policy.zones || []).forEach((zone, index) => {
    for (const name of zoneInterfaceNames(zone.interfaces)) {
      const key = interfaceKey(name);
      if (!assignments.has(key)) assignments.set(key, []);
      assignments.get(key).push({ index, zoneName: zone.name || `zone #${index + 1}` });
    }
  });
  return assignments;
}

function zoneInterfaceSeverity(issues = []) {
  if (issues.some((issue) => issue.severity === "bad")) return "bad";
  if (issues.some((issue) => issue.severity === "warn")) return "warn";
  return "ok";
}

function zoneInterfaceDetail(iface = {}) {
  const detail = iface.detail || "host interface";
  const counters = [];
  if (iface.rxBytes || iface.txBytes) counters.push(`${fmt.bytes(iface.rxBytes)} in / ${fmt.bytes(iface.txBytes)} out`);
  if (iface.rxDrops || iface.txDrops) counters.push(`${iface.rxDrops + iface.txDrops} drops`);
  if (iface.rxErrors || iface.txErrors) counters.push(`${iface.rxErrors + iface.txErrors} errors`);
  return counters.length ? `${detail} · ${counters.join(" · ")}` : detail;
}

function dedupeZoneInterfaceIssues(issues = []) {
  const seen = new Set();
  const out = [];
  for (const issue of issues) {
    const key = `${issue.severity}|${issue.detail}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(issue);
  }
  return out;
}

function interfaceKey(name) {
  return String(name || "").trim().toLowerCase();
}

function upsert(d, kind, idx, obj, valid) {
  if (!valid) return false;
  if (!d[kind]) d[kind] = [];
  if (idx != null) d[kind][idx] = obj; else d[kind].push(obj);
  return { ok: true, obj };
}

class ObjectEditorValidationAbort extends Error {
  constructor(result = {}) {
    super(result.message || "Object editor validation failed before candidate staging.");
    this.result = result;
  }
}

function normalizeObjectEditorSaveResult(result) {
  if (result && typeof result === "object") {
    return { ok: Boolean(result.ok), ...result };
  }
  return { ok: Boolean(result) };
}

export function validateObjectPortList(value = "") {
  const raw = String(value || "").trim();
  if (!raw) return { ok: true, ports: [] };
  const ports = [];
  for (const token of raw.split(",").map((x) => x.trim()).filter(Boolean)) {
    const parts = token.split("-");
    if (parts.length > 2 || !parts.every((part) => /^[0-9]+$/.test(part))) {
      return { ok: false, ports: [], message: "Use whole TCP/UDP port numbers from 1 to 65535, separated by commas; ranges use start-end." };
    }
    const start = Number(parts[0]);
    const end = parts.length === 2 ? Number(parts[1]) : undefined;
    if (!Number.isInteger(start) || start < 1 || start > 65535) {
      return { ok: false, ports: [], message: "Ports must be whole numbers from 1 to 65535." };
    }
    if (end !== undefined) {
      if (!Number.isInteger(end) || end < 1 || end > 65535 || end < start) {
        return { ok: false, ports: [], message: "Port ranges must stay within 1 to 65535 and end at or above the start port." };
      }
      ports.push({ start, end });
    } else {
      ports.push({ start });
    }
  }
  return { ok: true, ports };
}
function inp(v, ph, dataset = null) { return h("input", { class: "input", value: v || "", placeholder: ph, dataset: dataset || undefined }); }
function val(el) { return el.value.trim(); }

function csvList(value) {
  return value.split(",").map((x) => x.trim()).filter(Boolean);
}

function appPortHints(tcp, udp) {
  const hints = [];
  const tcpPorts = parsePorts(tcp);
  if (tcpPorts.length) hints.push({ protocol: "PROTOCOL_TCP", ports: tcpPorts });
  const udpPorts = parsePorts(udp);
  if (udpPorts.length) hints.push({ protocol: "PROTOCOL_UDP", ports: udpPorts });
  return hints;
}

function appProtocolPorts(app, protocol) {
  const hint = (app.ports || []).find((p) => p.protocol === protocol);
  return hint ? fmt.portList(hint.ports) : "";
}

function appPorts(app) {
  const parts = (app.ports || []).map((p) => `${fmt.protoLabel(p.protocol)} ${fmt.portList(p.ports)}`);
  return parts.length ? parts.join("; ") : "—";
}

function securityProfilePostureCell(profile = {}) {
  const stats = securityProfileAttachmentStats(session.draft, profile.name || "");
  const workflow = securityProfileWorkflowModel(profile, {
    exists: true,
    affectedRuleCount: stats.affectedRuleCount,
    allowRuleCount: stats.allowRuleCount,
    blockingIntent: securityProfileBlockingIntent(profile),
    failClosedReady: Boolean(session.draft.ids?.enabled && session.draft.ids?.mode === "IDS_MODE_PREVENT" && (session.draft.ids?.failureBehavior || session.draft.ids?.failure_behavior) === "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED"),
    candidateOnly: !(session.running.securityProfiles || []).some((item) => item?.name === profile.name),
  });
  return h("div", { dataset: { securityProfilePosture: workflow.posture.state } },
    pill(workflow.posture.label, workflow.posture.tone, true),
    h("div", { class: "note" }, workflow.blockers[0] || workflow.warnings[0] || "Candidate profile has no local blockers."));
}

function securityProfileEditorWorkflowPreview(workflow = {}) {
  return h("div", { class: "alert-box " + (workflow.posture?.tone === "bad" ? "warn" : "info"), dataset: { securityProfileEditorPosture: workflow.posture?.state || "unknown" } },
    h("div", { class: "flex wrap", style: { justifyContent: "space-between" } },
      h("strong", {}, "Candidate posture"),
      pill(workflow.posture?.label || "unknown", workflow.posture?.tone || "neutral", true)),
    workflow.blockers?.length ? h("ul", { class: "compact-list" }, workflow.blockers.map((item) => h("li", {}, pill("blocker", "bad", true), " ", item))) : null,
    workflow.warnings?.length ? h("ul", { class: "compact-list" }, workflow.warnings.slice(0, 3).map((item) => h("li", {}, pill("warning", "warn", true), " ", item))) : null,
    h("div", { class: "note" }, "Staging this profile updates candidate policy only. Runtime proof for TLS key custody, DNS/URL feeds, and file scanning remains separate hardening."));
}

function securityProfileTlsCell(profile = {}) {
  const mode = profile.tlsInspection || "TLS_INSPECTION_MODE_UNSPECIFIED";
  const tone = mode === "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED" ? "warn" : mode === "TLS_INSPECTION_MODE_BYPASS" ? "neutral" : "info";
  return h("div", {},
    pill(tlsInspectionLabel(mode), tone),
    mode === "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED"
      ? h("div", { class: "note" }, "review-only; no CA/MITM runtime is enabled by this object")
      : null);
}

function tlsInspectionLabel(mode = "") {
  if (mode === "TLS_INSPECTION_MODE_METADATA_ONLY") return "metadata only";
  if (mode === "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED") return "decryption required";
  if (mode === "TLS_INSPECTION_MODE_BYPASS") return "bypass";
  return "unspecified";
}

function dnsSecurityLabel(mode = "") {
  if (mode === "DNS_SECURITY_MODE_BLOCK_MALICIOUS") return "block malicious";
  if (mode === "DNS_SECURITY_MODE_LOG_ONLY") return "log only";
  return "unspecified";
}

function fileSecurityLabel(mode = "") {
  if (mode === "FILE_SECURITY_MODE_BLOCK_EXECUTABLES") return "block executables";
  if (mode === "FILE_SECURITY_MODE_BLOCK_HIGH_RISK") return "block high risk";
  if (mode === "FILE_SECURITY_MODE_LOG_ONLY") return "log only";
  return "unspecified";
}
