// Policy ▸ Rules — the primary daily workspace. Search/filter, create,
// edit, duplicate, insert-after, enable/disable, drag-to-reorder, and
// static shadow detection. Every change auto-stages to the candidate.

import { h, icon, clear } from "../core.js";
import { api } from "../api.js";
import { fingerprint, session } from "../policy.js";
import { BASELINE_PROFILES, applyBaselinePolicy, policyNeedsBaseline } from "../baseline.js";
import { natProfileLines, natProfileSummary } from "../explain_profiles.js";
import { objectKindHash, objectReferenceHash } from "../object_route.js";
import { buildHash, readQueryState, writeQueryState } from "../query_state.js";
import { pinInvestigationPacket } from "../investigation_case.js";
import { buildInvestigationPacket, explainHandoffPacket, investigationPacketFilename, investigationPacketJson } from "../investigation_packet.js";
import { settingsPanelHash } from "../settings_route.js";
import { openAutomationContext } from "../automation_context.js";
import { throwIfAccessDenied } from "../auth_gate.js";
import { pageHead, emptyState, pill, toast, openDrawer, closeDrawer, confirmDialog, searchInput, keyboardRowAttrs } from "../ui.js";
import * as fmt from "../format.js";

const DEFAULT_FILTER = { q: "", action: "", zone: "", tag: "", ruleId: "", rule: "", changed: false };
const DEFAULT_DENSITY = "comfortable";
const DEFAULT_GROUP = "none";
const RULE_TABLE_COLUMN_COUNT = 17;
const RULE_TABLE_SCALE_REVIEW_THRESHOLD = 250;
const SERVER_OVERLAP_FINDING_LIMIT = 25;
const MAX_RULE_BULK_TARGETS_LENGTH = 12000;
const DEFAULT_SIMULATOR = {
  source: "",
  fromZone: "",
  toZone: "",
  protocol: "PROTOCOL_TCP",
  appId: "",
  users: "",
  groups: "",
  devices: "",
  postureLabels: "",
  srcIp: "",
  srcPort: "",
  destIp: "",
  destPort: "",
};
const QUERY_DEFAULTS = {
  ...DEFAULT_FILTER,
  simSource: "",
  simFrom: "",
  simTo: "",
  simProtocol: "PROTOCOL_TCP",
  simApp: "",
  simUsers: "",
  simGroups: "",
  simDevices: "",
  simPosture: "",
  simSrc: "",
  simSport: "",
  simDst: "",
  simDport: "",
  density: DEFAULT_DENSITY,
  group: DEFAULT_GROUP,
  drawer: "",
  bulkTag: "",
  bulkTargets: "",
  simRun: false,
  caseKey: "",
  caseAction: "",
  caseKind: "",
};
const QUERY_KEYS = Object.keys(QUERY_DEFAULTS);
const TROUBLESHOOT_HANDOFF_DEFAULTS = Object.freeze({
  source: "",
  fromZone: "",
  toZone: "",
  protocol: "PROTOCOL_TCP",
  app: "",
  src: "",
  sport: "",
  dst: "",
  dport: "",
  run: false,
  intent: "",
});
const TROUBLESHOOT_HANDOFF_KEYS = Object.keys(TROUBLESHOOT_HANDOFF_DEFAULTS);
const REPRESENTATIVE_SOURCE_PORT = "51515";

let filter = { ...DEFAULT_FILTER };
let tableDensity = DEFAULT_DENSITY;
let tableGroup = DEFAULT_GROUP;
let selectedRuleIndexes = new Set();
let runningCounters = new Map();
let countersAvailable = false;
let counterPolicyVersion = 0;
let counterLoadError = "";
let ruleValidationState = {
  loading: false,
  findings: [],
  error: "",
  ranAt: "",
  draftFingerprint: "",
};
let ruleVerificationState = new Map();
let verifyingChangedRules = false;
const simulator = {
  ...DEFAULT_SIMULATOR,
  loading: false,
  result: null,
  error: "",
  runRequested: false,
  autorunKey: "",
};
let routePath = "/rules";
let simulatorQueryActive = false;
let simulatorRouteRun = false;
let caseContext = { caseKey: "", caseAction: "", caseKind: "" };
let autoOpenedRule = "";
let activeRuleReviewDrawer = "";
let routeBulkTag = "";
let routeBulkTargets = "";
let autoOpenedRuleReviewDrawer = "";
let preservingRuleReviewDrawerRoute = false;

export const RULE_REVIEW_DRAWERS = Object.freeze([
  "",
  "verify-changed",
  "bulk-log-on",
  "bulk-log-off",
  "bulk-enable",
  "bulk-disable",
  "bulk-tag-add",
  "bulk-tag-remove",
  "server-overlap-review",
]);

const BULK_REVIEW_DRAWER_ACTIONS = Object.freeze({
  "bulk-log-on": Object.freeze({ kind: "log", log: true }),
  "bulk-log-off": Object.freeze({ kind: "log", log: false }),
  "bulk-enable": Object.freeze({ kind: "disabled", disabled: false }),
  "bulk-disable": Object.freeze({ kind: "disabled", disabled: true }),
});

export function normalizeRuleReviewDrawer(value = "") {
  const text = String(value || "").trim();
  return RULE_REVIEW_DRAWERS.includes(text) ? text : "";
}

export async function render(ctx = {}) {
  routePath = ctx.path || "/rules";
  applyRouteQuery(ctx.query || {});
  autoOpenedRule = "";
  const root = h("div", {});
  await loadRulesWorkbench(root);
  return root;
}

async function loadRulesWorkbench(root) {
  clear(root);
  root.appendChild(h("div", { class: "loading" }, "Loading security rules..."));
  const [sessionResult, statusResult] = await Promise.allSettled([session.load(), api.status()]);
  throwIfAccessDenied(sessionResult, statusResult);
  if (sessionResult.status === "rejected") {
    paintRulesLoadFailure(root, sessionResult.reason);
    return;
  }
  const dataplane = statusResult.status === "fulfilled" ? statusResult.value?.dataplane || {} : {};
  const counters = dataplane.counters || [];
  runningCounters = counterMap(counters);
  countersAvailable = counters.length > 0;
  counterPolicyVersion = Number(dataplane.runningPolicyVersion || 0);
  counterLoadError = statusResult.status === "rejected" ? loadErrorDetail(statusResult.reason, "Runtime status and rule counters are unavailable.") : "";
  rerender(root);
  maybeOpenSelectedRule();
}

function paintRulesLoadFailure(root, err) {
  runningCounters = new Map();
  countersAvailable = false;
  counterPolicyVersion = 0;
  counterLoadError = loadErrorDetail(err, "Candidate policy is unavailable.");
  clear(root);
  root.appendChild(pageHead("Security rules", "Candidate policy unavailable",
    h("div", { class: "flex wrap" },
      h("button", { class: "btn", type: "button", title: "Retry loading security rules", "aria-label": "Retry loading security rules", dataset: { rulesAction: "retry-load" }, onclick: () => loadRulesWorkbench(root) }, h("span", { html: icon("refresh", 16) }), "Retry"),
      h("button", { class: "btn", type: "button", title: "Open Rules API and CLI context", "aria-label": "Open Rules API and CLI context", dataset: { rulesAction: "api-cli" }, onclick: () => openAutomationContext(routePath) }, h("span", { html: icon("terminal", 16) }), "API / CLI"))));
  root.appendChild(rulesUnavailableBanner("Candidate state unavailable.", err));
  root.appendChild(emptyState("rules", "Security rulebase unavailable", "The Rules workspace shell is still available. Retry candidate loading or use API / CLI context to inspect policy state."));
}

function rulesUnavailableBanner(title, err) {
  return h("div", { class: "alert-box bad", dataset: { rulesLoadError: "true" } },
    h("strong", {}, title + " "),
    loadErrorDetail(err, "The candidate policy API did not return data."));
}

function loadErrorDetail(err, fallback) {
  const detail = err?.message || String(err || "");
  return detail || fallback;
}

function rerender(root) {
  clear(root);
  const policy = session.draft || {};
  const rules = policy.rules || [];
  const zones = (session.draft.zones || []).map((z) => z.name);
  const tags = ruleTags(rules);
  const validationSnapshot = ruleValidationSnapshotStatus(ruleValidationState, policy);
  const validationCleanup = validationSnapshot.current ? ruleValidationCleanup(ruleValidationState.findings, rules.length) : ruleValidationCleanup([], rules.length);
  const hygiene = computeRuleHygiene(rules, runningCounters, countersAvailable, policy, validationCleanup);
  const rulebaseMap = rulebaseMapModel(policy, session.running || {}, runningCounters, countersAvailable, validationCleanup);

  root.appendChild(pageHead("Security rules",
    `${rules.filter((r) => !r.disabled).length} active · ${rules.length} total · evaluated top-to-bottom, first match wins`,
    [
      h("button", { class: "btn", ...actionControlAttrs({ rulesAction: "setup-baseline" }, "Set up baseline policy", { onclick: () => openBaselineSetup(root) }) }, h("span", { html: icon("shield", 16) }), "Set up baseline"),
      h("button", { class: "btn primary", ...actionControlAttrs({ rulesAction: "add-rule" }, "Add security rule", { onclick: () => openRuleEditor(null) }) }, h("span", { html: icon("plus", 16) }), "Add rule"),
    ]));
  if (counterLoadError) {
    root.appendChild(h("div", { class: "alert-box warn", dataset: { rulesCounterLoadError: "true" } },
      h("strong", {}, "Runtime counters unavailable. "),
      counterLoadError,
      h("div", { class: "note" }, "Rule editing remains candidate-only; hit counters and running-policy freshness are hidden until runtime status recovers.")));
  }

  // toolbar
  const { el: search } = searchInput("Search name, tag, zone, address, service, app…", (v) => { updateRuleFilter({ q: v.toLowerCase() }); paint(); }, filter.q);
  const actionSel = h("select", { class: "rules-action-filter", title: "Filter rules by action", "aria-label": "Filter rules by action", dataset: { ruleControl: "action-filter" }, onchange: (e) => { updateRuleFilter({ action: e.target.value }); paint(); } },
    opt("", "All actions"), opt("ACTION_ALLOW", "Allow"), opt("ACTION_DENY", "Drop"), opt("ACTION_REJECT", "Reject"));
  const zoneSel = h("select", { class: "rules-zone-filter", title: "Filter rules by zone", "aria-label": "Filter rules by zone", dataset: { ruleControl: "zone-filter" }, onchange: (e) => { updateRuleFilter({ zone: e.target.value }); paint(); } },
    opt("", "All zones"), ...zones.map((z) => opt(z, z)));
  const tagSel = h("select", { class: "rules-tag-filter", title: "Filter rules by tag", "aria-label": "Filter rules by tag", dataset: { ruleControl: "tag-filter" }, onchange: (e) => { updateRuleFilter({ tag: e.target.value }); paint(); } },
    opt("", "All tags"), ...tags.map((tag) => opt(tag, tag)));
  const densitySel = h("select", {
    class: "rules-density-control",
    dataset: { ruleControl: "density" },
    title: "Rule table density",
    "aria-label": "Rule table density",
    onchange: (e) => { tableDensity = normalizeRuleDensity(e.target.value); syncRoute(); paint(); },
  }, opt("comfortable", "Comfortable"), opt("compact", "Compact"));
  const groupSel = h("select", {
    class: "rules-group-control",
    dataset: { ruleControl: "group" },
    title: "Group visible rules",
    "aria-label": "Group visible rules",
    onchange: (e) => {
      tableGroup = normalizeRuleGroup(e.target.value);
      selectedRuleIndexes.clear();
      syncRoute();
      paint();
    },
  }, opt("none", "No grouping"), opt("tag", "Group by tag"), opt("action", "Group by action"), opt("zone", "Group by zones"));
  actionSel.value = filter.action; zoneSel.value = filter.zone; tagSel.value = filter.tag;
  densitySel.value = tableDensity;
  groupSel.value = tableGroup;
  root.appendChild(h("div", { class: "toolbar" }, search,
    h("span", { class: "rules-filter-controls", dataset: { rulesToolbarGroup: "filters" } }, h("span", { class: "muted", html: icon("filter", 16) }), actionSel, zoneSel, tagSel),
    h("span", { class: "rules-view-controls", dataset: { rulesToolbarGroup: "view" } }, h("span", { class: "muted", html: icon("dashboard", 16) }), densitySel, groupSel),
    h("button", {
      class: "btn sm",
      type: "button",
      disabled: ruleValidationState.loading,
      title: "Run server validation and fold rule hygiene findings into the cleanup queue",
      "aria-label": "Validate rule cleanup findings",
      dataset: { rulesAction: "validate-cleanup" },
      onclick: () => validateRuleCleanup(root),
    }, h("span", { html: icon("check", 15) }), ruleValidationState.loading ? "Validating..." : "Validate cleanup"),
    h("span", { class: "spacer" }),
    h("span", { class: "muted" }, countersAvailable ? `Hits are from running policy ${counterPolicyLabel()}.` : "Rule hit counters appear after a Linux commit.")));

  root.appendChild(ruleHygienePanel(hygiene, root, validationSnapshot));
  root.appendChild(flowSimulator(zones, root));
  root.appendChild(rulebaseMapPanel(rulebaseMap, root));

  const tableWrap = h("div", { class: "table-wrap rules-table-wrap" });
  root.appendChild(tableWrap);

  function paint() { renderTable(tableWrap, root); }
  paint();
}

function opt(v, l) { return h("option", { value: v }, l); }

function actionControlAttrs(dataset = {}, label = "", attrs = {}) {
  return {
    type: "button",
    title: label,
    "aria-label": label,
    dataset,
    ...attrs,
  };
}

function updateRuleFilter(patch = {}) {
  filter = { ...filter, ...patch };
  selectedRuleIndexes.clear();
  syncRoute();
}

export function normalizeRuleDensity(value) {
  return value === "compact" ? "compact" : DEFAULT_DENSITY;
}

export function normalizeRuleGroup(value) {
  return ["none", "tag", "action", "zone"].includes(value) ? value : DEFAULT_GROUP;
}

export function ruleChangeModel(runningRules = [], draftRules = []) {
  const running = Array.isArray(runningRules) ? runningRules : [];
  const draft = Array.isArray(draftRules) ? draftRules : [];
  const runningNameCounts = ruleNameCounts(running);
  const draftNameCounts = ruleNameCounts(draft);
  const runningIdCounts = ruleIdCounts(running);
  const draftIdCounts = ruleIdCounts(draft);
  const runningByUniqueId = new Map();
  const runningByUniqueName = new Map();
  running.forEach((rule, idx) => {
    const id = normalizedRuleId(rule);
    if (id && runningIdCounts.get(id) === 1) runningByUniqueId.set(id, idx);
    const name = normalizedRuleName(rule);
    if (name && runningNameCounts.get(name) === 1) runningByUniqueName.set(name, idx);
  });

  const byDraftIndex = new Map();
  const matchedRunning = new Set();
  const counts = { added: 0, modified: 0, moved: 0, removed: 0 };
  draft.forEach((rule, idx) => {
    const match = ruleChangeMatch(rule, idx, running, {
      runningNameCounts,
      draftNameCounts,
      runningIdCounts,
      draftIdCounts,
      runningByUniqueName,
      runningByUniqueId,
      matchedRunning,
    });
    if (match.runningIndex < 0) {
      byDraftIndex.set(idx, ruleChange("added", idx, -1, rule));
      counts.added += 1;
      return;
    }
    matchedRunning.add(match.runningIndex);
    const before = running[match.runningIndex];
    const changedContent = stableRuleString(before) !== stableRuleString(rule);
    const moved = match.runningIndex !== idx;
    if (match.ambiguous || changedContent) {
      byDraftIndex.set(idx, ruleChange("modified", idx, match.runningIndex, rule, before));
      counts.modified += 1;
    } else if (moved) {
      byDraftIndex.set(idx, ruleChange("moved", idx, match.runningIndex, rule, before));
      counts.moved += 1;
    }
  });

  const removed = [];
  running.forEach((rule, idx) => {
    if (matchedRunning.has(idx)) return;
    const item = ruleChange("removed", -1, idx, rule);
    removed.push(item);
    counts.removed += 1;
  });
  return { byDraftIndex, removed, counts, total: counts.added + counts.modified + counts.moved + counts.removed };
}

export function ruleChangeForIndex(model, idx) {
  return model?.byDraftIndex?.get(Number(idx)) || null;
}

export function ruleChangeSummary(model = {}) {
  const counts = {
    added: Number(model.counts?.added || 0),
    modified: Number(model.counts?.modified || 0),
    moved: Number(model.counts?.moved || 0),
    removed: Number(model.counts?.removed || 0),
  };
  const parts = [
    ["added", counts.added],
    ["modified", counts.modified],
    ["moved", counts.moved],
    ["removed", counts.removed],
  ].filter(([, count]) => count > 0).map(([label, count]) => `${count} ${label}`);
  const total = counts.added + counts.modified + counts.moved + counts.removed;
  return { ...counts, total, label: parts.length ? parts.join(" · ") : "No staged rule changes" };
}

function ruleChange(kind, draftIndex, runningIndex, rule = {}, runningRule = null) {
  return {
    kind,
    draftIndex,
    runningIndex,
    name: ruleDisplayName(rule, runningRule),
  };
}

function ruleChangeMatch(rule, idx, running, opts = {}) {
  const {
    runningNameCounts = new Map(),
    draftNameCounts = new Map(),
    runningIdCounts = new Map(),
    draftIdCounts = new Map(),
    runningByUniqueName = new Map(),
    runningByUniqueId = new Map(),
    matchedRunning = new Set(),
  } = opts;
  const id = normalizedRuleId(rule);
  if (id && draftIdCounts.get(id) === 1 && runningIdCounts.get(id) === 1 && runningByUniqueId.has(id)) {
    const runningIndex = runningByUniqueId.get(id);
    return { runningIndex, ambiguous: matchedRunning.has(runningIndex) };
  }

  const name = normalizedRuleName(rule);
  if (name && draftNameCounts.get(name) === 1 && runningNameCounts.get(name) === 1 && runningByUniqueName.has(name)) {
    return { runningIndex: runningByUniqueName.get(name), ambiguous: false };
  }

  const sameIndex = running[idx];
  if (!sameIndex || matchedRunning.has(idx)) return { runningIndex: -1, ambiguous: false };
  const runningName = normalizedRuleName(sameIndex);
  const duplicateSameName = name && runningName === name && (runningNameCounts.get(name) > 1 || draftNameCounts.get(name) > 1);
  const unnamedIndexFallback = !name && !runningName;
  const likelyRename = name && runningName && !runningNameCounts.has(name) && !draftNameCounts.has(runningName);
  if (duplicateSameName || unnamedIndexFallback || likelyRename) {
    return { runningIndex: idx, ambiguous: duplicateSameName };
  }
  return { runningIndex: -1, ambiguous: false };
}

function ruleNameCounts(rules = []) {
  const counts = new Map();
  for (const rule of rules) {
    const name = normalizedRuleName(rule);
    if (!name) continue;
    counts.set(name, (counts.get(name) || 0) + 1);
  }
  return counts;
}

function ruleIdCounts(rules = []) {
  const counts = new Map();
  for (const rule of rules) {
    const id = normalizedRuleId(rule);
    if (!id) continue;
    counts.set(id, (counts.get(id) || 0) + 1);
  }
  return counts;
}

function normalizedRuleId(rule = {}) {
  return String(rule?.id || "").trim();
}

function normalizedRuleName(rule = {}) {
  return String(rule?.name || "").trim();
}

export function ruleRouteTargetState(rule = {}) {
  const ruleId = normalizedRuleId(rule);
  return {
    ruleId,
    rule: ruleId ? "" : normalizedRuleName(rule),
  };
}

export function ruleRouteTargetLabel(rule = {}, idx = -1) {
  const id = normalizedRuleId(rule);
  const name = normalizedRuleName(rule);
  const position = Number.isInteger(idx) && idx >= 0 ? `#${idx + 1}` : "rule";
  return id ? `${name || position} (${id})` : name || position;
}

function ruleMatchesRouteTarget(rule = {}, idx = -1, filterState = filter) {
  const routeRuleId = String(filterState?.ruleId || "").trim();
  if (routeRuleId) return normalizedRuleId(rule) === routeRuleId;
  const routeRuleName = String(filterState?.rule || "").trim();
  return Boolean(routeRuleName && normalizedRuleName(rule) === routeRuleName);
}

function routeRuleTargetKey(filterState = filter) {
  const ruleId = String(filterState?.ruleId || "").trim();
  if (ruleId) return `id:${ruleId}`;
  const ruleName = String(filterState?.rule || "").trim();
  return ruleName ? `name:${ruleName}` : "";
}

function ruleDisplayName(rule = {}, fallbackRule = null) {
  return normalizedRuleName(rule) || normalizedRuleName(fallbackRule || {}) || "(unnamed)";
}

function stableRuleString(value) {
  return JSON.stringify(stableRuleValue(value));
}

function stableRuleValue(value) {
  if (Array.isArray(value)) return value.map(stableRuleValue);
  if (!value || typeof value !== "object") return value;
  return Object.keys(value).sort().reduce((out, key) => {
    if (value[key] !== undefined) out[key] = stableRuleValue(value[key]);
    return out;
  }, {});
}

export function ruleVerificationKey(rule = {}, change = {}) {
  if (!change || !["added", "modified", "moved"].includes(change.kind)) return "";
  return stableRuleString({
    kind: change.kind,
    draftIndex: Number.isInteger(change.draftIndex) ? change.draftIndex : -1,
    runningIndex: Number.isInteger(change.runningIndex) ? change.runningIndex : -1,
    name: normalizedRuleName(rule),
    rule: stableRuleValue(rule || {}),
  });
}

export function ruleVerificationStatus(rule = {}, change = {}, verificationState = new Map()) {
  const key = ruleVerificationKey(rule, change);
  if (!key) return { state: "not-applicable", label: "not applicable", key: "" };
  const record = mapLikeGet(verificationState, key);
  if (!record) return { state: "needed", label: "verify", key };
  if (record.key && record.key !== key) return { state: "stale", label: "stale", key };
  const state = ["verified", "mismatch", "unverifiable", "error"].includes(record.state) ? record.state : "needed";
  const labels = {
    verified: "verified",
    mismatch: "mismatch",
    unverifiable: "needs tuple",
    error: "failed",
    needed: "verify",
  };
  return { ...record, state, label: labels[state] || "verify", key };
}

export function ruleVerificationSummary(changedRows = [], verificationState = new Map(), opts = {}) {
  const rows = Array.isArray(changedRows) ? changedRows : [];
  const out = {
    total: 0,
    verified: 0,
    needed: 0,
    stale: 0,
    mismatch: 0,
    unverifiable: 0,
    error: 0,
    removed: Number(opts.removed || 0),
  };
  rows.forEach(({ rule, change }) => {
    if (!ruleVerificationKey(rule, change)) return;
    out.total += 1;
    const status = ruleVerificationStatus(rule, change, verificationState);
    if (Object.prototype.hasOwnProperty.call(out, status.state)) out[status.state] += 1;
    else out.needed += 1;
  });
  const pending = out.needed + out.stale + out.mismatch + out.unverifiable + out.error;
  out.complete = out.total > 0 && out.verified === out.total;
  out.pending = pending;
  out.label = out.total
    ? `${out.verified}/${out.total} changed verified${pending ? ` · ${pending} needs review` : ""}`
    : out.removed ? `${out.removed} removed rule${out.removed === 1 ? "" : "s"} to review` : "No changed rules to verify";
  return out;
}

function mapLikeGet(mapLike, key) {
  if (!mapLike || !key) return null;
  if (typeof mapLike.get === "function") return mapLike.get(key) || null;
  return mapLike[key] || null;
}

export function normalizeBulkRuleTag(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.:-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, MAX_RULE_TAG_LENGTH);
}

export function rulesFlowCheckRouteState(filterState = {}, simulatorState = {}, opts = {}) {
  const active = opts.active !== false;
  const sim = active ? (simulatorState || {}) : DEFAULT_SIMULATOR;
  const context = opts.caseContext || {};
  return {
    ...DEFAULT_FILTER,
    q: String(filterState.q || "").toLowerCase(),
    action: filterState.action || "",
    zone: filterState.zone || "",
    tag: filterState.tag || "",
    ruleId: safeRouteToken(filterState.ruleId, 160),
    rule: filterState.rule || "",
    changed: Boolean(filterState.changed),
    simSource: sim.source || "",
    simFrom: sim.fromZone || "",
    simTo: sim.toZone || "",
    simProtocol: sim.protocol || DEFAULT_SIMULATOR.protocol,
    simApp: sim.appId || "",
    simUsers: sim.users || "",
    simGroups: sim.groups || "",
    simDevices: sim.devices || "",
    simPosture: sim.postureLabels || "",
    simSrc: sim.srcIp || "",
    simSport: validPortOrEmpty(sim.srcPort),
    simDst: sim.destIp || "",
    simDport: validPortOrEmpty(sim.destPort),
    density: normalizeRuleDensity(opts.density),
    group: normalizeRuleGroup(opts.group),
    drawer: normalizeRuleReviewDrawer(opts.drawer),
    bulkTag: safeRouteToken(opts.bulkTag, MAX_RULE_TAG_LENGTH),
    bulkTargets: safeRouteToken(opts.bulkTargets, MAX_RULE_BULK_TARGETS_LENGTH),
    simRun: Boolean(opts.run),
    caseKey: safeRouteToken(context.caseKey, 320),
    caseAction: safeRouteToken(context.caseAction, 80),
    caseKind: safeRouteToken(context.caseKind, 80),
  };
}

export function rulesFlowCheckHash(path = "/rules", filterState = {}, simulatorState = {}, opts = {}) {
  return buildHash(path || "/rules", rulesFlowCheckRouteState(filterState, simulatorState, opts), QUERY_DEFAULTS, QUERY_KEYS);
}

export function rulesTroubleshootRouteState(simulatorState = {}, opts = {}) {
  const sim = simulatorState || {};
  return {
    source: sim.source || "POLICY_SOURCE_RUNNING",
    fromZone: sim.fromZone || "",
    toZone: sim.toZone || "",
    protocol: sim.protocol || DEFAULT_SIMULATOR.protocol,
    app: sim.appId || "",
    src: sim.srcIp || "",
    sport: validPortOrEmpty(sim.srcPort),
    dst: sim.destIp || "",
    dport: validPortOrEmpty(sim.destPort),
    run: Boolean(opts.run),
    intent: opts.intent === "capture" ? "capture" : "",
  };
}

export function rulesTroubleshootHash(simulatorState = {}, opts = {}) {
  return buildHash("/troubleshoot", rulesTroubleshootRouteState(simulatorState, opts), TROUBLESHOOT_HANDOFF_DEFAULTS, TROUBLESHOOT_HANDOFF_KEYS);
}

export function representativeFlowFromRule(policy = {}, rule = {}, opts = {}) {
  const warnings = [];
  const fromZone = firstConcreteRef(rule.fromZones);
  const toZone = firstConcreteRef(rule.toZones);
  if (!fromZone) warnings.push("Rule has no concrete from-zone.");
  if (!toZone) warnings.push("Rule has no concrete to-zone.");

  const srcRef = firstConcreteRef(rule.sourceAddresses);
  const dstRef = firstConcreteRef(rule.destinationAddresses);
  const srcIp = representativeAddress(policy, srcRef, "source", warnings);
  const destIp = representativeAddress(policy, dstRef, "destination", warnings);

  const service = representativeService(policy, rule, warnings);
  const appId = firstConcreteRef(rule.applications);
  const appHint = representativeApplicationPort(policy, appId, warnings);
  const protocol = service.protocol || appHint.protocol || "PROTOCOL_TCP";
  const destPort = service.destPort || appHint.destPort || "";
  const needsPort = protocol === "PROTOCOL_TCP" || protocol === "PROTOCOL_UDP";
  if (needsPort && !destPort) warnings.push("Rule has no concrete TCP/UDP destination port.");
  const srcPort = needsPort ? REPRESENTATIVE_SOURCE_PORT : "";
  const simulatorState = {
    source: opts.source || "POLICY_SOURCE_CANDIDATE",
    fromZone,
    toZone,
    protocol,
    appId: appId || "",
    srcIp,
    srcPort,
    destIp,
    destPort,
  };
  const missing = [
    !fromZone ? "from-zone" : "",
    !toZone ? "to-zone" : "",
    !srcIp ? "source IP" : "",
    !destIp ? "destination IP" : "",
    needsPort && !destPort ? "destination port" : "",
  ].filter(Boolean);
  return {
    ok: missing.length === 0,
    ruleName: rule.name || "",
    simulator: simulatorState,
    warnings: dedupeText(warnings),
    missing,
  };
}

export function applyBulkRuleDisabled(policy = {}, indexes = [], disabled = false) {
  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  for (const idx of normalizedRuleIndexes(indexes, rules.length)) {
    rules[idx].disabled = Boolean(disabled);
  }
  return policy;
}

export function applyBulkRuleLog(policy = {}, indexes = [], log = true) {
  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  for (const idx of normalizedRuleIndexes(indexes, rules.length)) {
    rules[idx].log = Boolean(log);
  }
  return policy;
}

export function applyHostInputRuleLog(policy = {}, indexes = [], log = true) {
  const rules = Array.isArray(policy.hostInput?.rules) ? policy.hostInput.rules : [];
  for (const idx of normalizedRuleIndexes(indexes, rules.length)) {
    rules[idx].log = Boolean(log);
  }
  return policy;
}

export function ruleValidationCleanup(findings = [], ruleCount = 0) {
  const out = {
    missingLogs: [],
    overlaps: [],
    hostInputMissingLogs: [],
    unusedObjects: [],
    overlapFindings: [],
    overlapFindingLimit: SERVER_OVERLAP_FINDING_LIMIT,
    overlapFindingsMayBeTruncated: false,
    otherRuleFindings: [],
    totalRuleFindings: 0,
    totalFindings: 0,
  };
  for (const finding of Array.isArray(findings) ? findings : []) {
    const code = String(finding?.code || "").trim();
    const fieldPath = String(finding?.fieldPath || finding?.field_path || "").trim();
    const unused = unusedObjectFindingFromValidation(code, fieldPath, finding);
    if (unused) {
      out.unusedObjects.push(unused);
      out.totalFindings += 1;
      continue;
    }
    const ruleIndex = ruleIndexFromFieldPath(fieldPath);
    if (code === "POLICY_HYGIENE_MISSING_HOST_INPUT_LOG") {
      const hostIndex = hostInputRuleIndexFromFieldPath(fieldPath);
      if (hostIndex != null) out.hostInputMissingLogs.push(hostIndex);
      if (hostIndex != null) out.totalFindings += 1;
      continue;
    }
    if (ruleIndex == null || ruleIndex >= ruleCount) continue;
    out.totalRuleFindings += 1;
    out.totalFindings += 1;
    if (code === "POLICY_HYGIENE_MISSING_RULE_LOG") out.missingLogs.push(ruleIndex);
    else if (code === "POLICY_HYGIENE_RULE_OVERLAP") {
      const overlapDetail = parseServerOverlapDetail(finding?.detail);
      out.overlaps.push(ruleIndex);
      out.overlapFindings.push({
        index: ruleIndex,
        code,
        fieldPath: overlapDetail?.result?.fieldPath || fieldPath,
        message: String(finding?.message || "").trim(),
        detail: overlapDetail?.text || String(finding?.detail || "").trim(),
        severity: String(finding?.severity || "").trim(),
        stage: String(finding?.stage || "").trim(),
        serverOverlap: overlapDetail || null,
        overlapPeer: overlapDetail?.peer || null,
        overlapDimensions: Array.isArray(overlapDetail?.dimensions) ? overlapDetail.dimensions : [],
        overlapResult: overlapDetail?.result || null,
        overlapPage: overlapDetail?.page || null,
      });
    }
    else out.otherRuleFindings.push(ruleIndex);
  }
  return {
    ...out,
    missingLogs: normalizedRuleIndexes(out.missingLogs, ruleCount),
    overlaps: normalizedRuleIndexes(out.overlaps, ruleCount),
    overlapFindingsMayBeTruncated: out.overlapFindings.length >= SERVER_OVERLAP_FINDING_LIMIT,
    hostInputMissingLogs: normalizedRuleIndexes(out.hostInputMissingLogs, Number.MAX_SAFE_INTEGER),
    unusedObjects: out.unusedObjects,
    overlapFindings: out.overlapFindings,
    otherRuleFindings: normalizedRuleIndexes(out.otherRuleFindings, ruleCount),
  };
}

export function parseServerOverlapDetail(detail = "") {
  const raw = String(detail || "").trim();
  if (!raw || raw[0] !== "{") return null;
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    const result = parsed.result && typeof parsed.result === "object" ? parsed.result : {};
    if (result.outcome !== "first-match-order-review" || !Number.isFinite(Number(result.ruleIndex)) || !Number.isFinite(Number(result.peerIndex))) {
      return null;
    }
    return {
      text: String(parsed.text || "").trim(),
      peer: parsed.peer && typeof parsed.peer === "object" ? parsed.peer : null,
      dimensions: Array.isArray(parsed.dimensions) ? parsed.dimensions : [],
      result,
      page: parsed.page && typeof parsed.page === "object" ? parsed.page : null,
    };
  } catch {
    return null;
  }
}

export function ruleValidationSnapshotStatus(state = {}, policy = {}) {
  if (!state?.ranAt || !state?.draftFingerprint) {
    return { checked: false, current: false, stale: false, fingerprint: fingerprint(policy || {}) };
  }
  const currentFingerprint = fingerprint(policy || {});
  const current = state.draftFingerprint === currentFingerprint;
  return {
    checked: true,
    current,
    stale: !current,
    fingerprint: currentFingerprint,
    checkedFingerprint: state.draftFingerprint,
  };
}

export function applyBulkRuleTag(policy = {}, indexes = [], rawTag = "", mode = "add") {
  const tag = normalizeBulkRuleTag(rawTag);
  if (!tag) return policy;
  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  for (const idx of normalizedRuleIndexes(indexes, rules.length)) {
    const existing = Array.isArray(rules[idx].tags) ? rules[idx].tags.filter(Boolean) : [];
    if (mode === "remove") {
      rules[idx].tags = existing.filter((item) => item !== tag);
    } else if (!existing.includes(tag)) {
      const next = [...existing, tag].sort((a, b) => a.localeCompare(b));
      if (!tagIssues(next).length) rules[idx].tags = next;
    }
  }
  return policy;
}

export function bulkRuleTagIssues(policy = {}, indexes = [], rawTag = "", mode = "add") {
  const tag = normalizeBulkRuleTag(rawTag);
  if (!tag) return ["Enter a tag label before applying a bulk tag change."];
  const tagProblems = tagIssues([tag]);
  if (tagProblems.length) return tagProblems;
  if (mode === "remove") return [];
  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  const issues = [];
  for (const idx of normalizedRuleIndexes(indexes, rules.length)) {
    const existing = Array.isArray(rules[idx].tags) ? rules[idx].tags.filter(Boolean) : [];
    if (!existing.includes(tag) && tagIssues([...existing, tag]).length) {
      issues.push(`Rule ${rules[idx].name || idx + 1} already has the maximum tag count.`);
    }
  }
  return issues;
}

export function bulkRuleActionPreview(policy = {}, indexes = [], visibleRows = [], action = {}) {
  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  const normalized = normalizedRuleIndexes(indexes, rules.length);
  const visible = new Set((visibleRows || []).map((row) => Number(row?.idx)).filter((idx) => Number.isInteger(idx)));
  const nameCounts = ruleNameCounts(rules);
  const plan = normalizeBulkRuleAction(action);
  const globalIssues = bulkRuleActionGlobalIssues(plan);
  const rows = normalized.map((idx) => {
    const rule = rules[idx] || {};
    const name = rule.name || `Rule ${idx + 1}`;
    const mutation = bulkRuleMutation(rule, plan);
    return {
      index: idx,
      position: idx + 1,
      itemId: normalizedRuleId(rule),
      name,
      action: fmt.ruleAction(rule.action).label,
      tags: normalizedRuleTags(rule),
      visible: visible.has(idx),
      duplicateName: Boolean(!normalizedRuleId(rule) && rule.name && nameCounts.get(rule.name) > 1),
      before: mutation.before,
      after: mutation.after,
      noOp: mutation.noOp,
      issue: globalIssues[0] || mutation.issue || "",
      signature: bulkRuleSnapshotSignature(rule),
    };
  });
  const rowIssues = rows.map((row) => row.issue).filter(Boolean);
  const blockedCount = rows.filter((row) => row.issue).length;
  const noOpCount = rows.filter((row) => !row.issue && row.noOp).length;
  const changeCount = rows.filter((row) => !row.issue && !row.noOp).length;
  return {
    kind: plan.kind,
    mode: plan.mode,
    tag: plan.tag,
    title: plan.title,
    confirmLabel: plan.confirmLabel,
    targetCount: rows.length,
    visibleCount: rows.filter((row) => row.visible).length,
    hiddenCount: rows.filter((row) => !row.visible).length,
    changeCount,
    noOpCount,
    blockedCount,
    issues: dedupeText([...globalIssues, ...rowIssues]),
    identityNotes: ruleIdentityReviewNotes(policy, normalized, visibleRows),
    rows,
  };
}

export function bulkRuleTargetSnapshotToken(preview = {}) {
  const rows = (preview.rows || []).map((row) => ({
    index: Number(row.index),
    position: Number(row.position || row.index + 1),
    itemId: String(row.itemId || ""),
    name: row.name || "",
    signature: row.signature || "",
  })).filter((row) => Number.isInteger(row.index) && row.index >= 0 && row.signature);
  if (!rows.length) return "";
  return encodeRouteJson({ v: 2, rows });
}

export function bulkRuleTargetSnapshotFromToken(token = "") {
  const parsed = decodeRouteJson(token);
  if (!parsed || ![1, 2].includes(Number(parsed.v)) || !Array.isArray(parsed.rows)) return null;
  const rows = parsed.rows.map((row) => ({
    index: Number(row.index),
    position: Number(row.position || Number(row.index) + 1),
    itemId: String(row.itemId || row.item_id || ""),
    name: String(row.name || ""),
    signature: String(row.signature || ""),
  })).filter((row) => Number.isInteger(row.index) && row.index >= 0 && row.signature);
  return rows.length ? { v: Number(parsed.v), rows } : null;
}

export function bulkRuleTargetSnapshotStatus(policy = {}, token = "") {
  const snapshot = bulkRuleTargetSnapshotFromToken(token);
  if (!snapshot) return { ok: true, checked: false, indexes: [], issues: [] };
  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  const idIndex = ruleIdIndex(rules);
  const issues = [];
  const indexes = [];
  for (const row of snapshot.rows) {
    const resolvedIndex = row.itemId && idIndex.get(row.itemId) != null ? idIndex.get(row.itemId) : row.index;
    const current = rules[resolvedIndex];
    if (!current) {
      issues.push(`Rule ${row.position || row.index + 1} is no longer present in the route target snapshot.`);
      continue;
    }
    if (row.itemId && normalizedRuleId(current) !== row.itemId) {
      issues.push(`Rule ${row.name || row.position || row.index + 1} no longer has durable id ${row.itemId}; refresh the route target snapshot and try again.`);
      continue;
    }
    indexes.push(resolvedIndex);
    if (bulkRuleSnapshotSignature(current) !== row.signature) {
      issues.push(`Rule ${row.name || row.position || row.index + 1} changed after this route-backed review opened; refresh the route target snapshot and try again.`);
    }
  }
  return { ok: issues.length === 0, checked: true, indexes: normalizedRuleIndexes(indexes, rules.length), issues: dedupeText(issues) };
}

export function bulkRulePreviewStillCurrent(policy = {}, preview = {}) {
  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  const idIndex = ruleIdIndex(rules);
  const issues = [];
  for (const row of preview.rows || []) {
    const resolvedIndex = row.itemId && idIndex.get(row.itemId) != null ? idIndex.get(row.itemId) : row.index;
    const current = rules[resolvedIndex];
    if (!current) {
      issues.push(`Rule ${row.position} is no longer present.`);
      continue;
    }
    if (row.itemId && normalizedRuleId(current) !== row.itemId) {
      issues.push(`Rule ${row.name || row.position} no longer has durable id ${row.itemId}; refresh the route target snapshot and try again.`);
      continue;
    }
    if (bulkRuleSnapshotSignature(current) !== row.signature) {
      issues.push(`Rule ${row.name || row.position} changed after the review opened; reselect rules and try again.`);
    }
  }
  return { ok: issues.length === 0, issues: dedupeText(issues) };
}

function encodeRouteJson(value = {}) {
  try {
    const json = JSON.stringify(value);
    const bytes = new TextEncoder().encode(json);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  } catch {
    return "";
  }
}

function decodeRouteJson(token = "") {
  try {
    const text = String(token || "").trim();
    if (!text || text.length > MAX_RULE_BULK_TARGETS_LENGTH || !/^[A-Za-z0-9_-]+$/.test(text)) return null;
    const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
}

function normalizeBulkRuleAction(action = {}) {
  if (action.kind === "log") {
    const log = Boolean(action.log);
    return {
      kind: "log",
      log,
      title: log ? "Enable logging on selected rules" : "Disable logging on selected rules",
      confirmLabel: log ? "Stage logging on" : "Stage logging off",
    };
  }
  if (action.kind === "tag") {
    const mode = action.mode === "remove" ? "remove" : "add";
    const tag = normalizeBulkRuleTag(action.tag || action.value);
    return {
      kind: "tag",
      mode,
      tag,
      title: mode === "remove" ? "Remove tag from selected rules" : "Add tag to selected rules",
      confirmLabel: mode === "remove" ? "Stage tag removal" : "Stage tag add",
    };
  }
  const disabled = Boolean(action.disabled);
  return {
    kind: "disabled",
    disabled,
    title: disabled ? "Disable selected rules" : "Enable selected rules",
    confirmLabel: disabled ? "Stage disable" : "Stage enable",
  };
}

function bulkRuleActionGlobalIssues(plan = {}) {
  if (plan.kind !== "tag") return [];
  if (!plan.tag) return ["Enter a tag label before applying a bulk tag change."];
  return tagIssues([plan.tag]);
}

function bulkRuleMutation(rule = {}, plan = {}) {
  if (plan.kind === "log") {
    const current = Boolean(rule.log);
    return {
      before: current ? "logging on" : "logging off",
      after: plan.log ? "logging on" : "logging off",
      noOp: current === plan.log,
    };
  }
  if (plan.kind === "tag") {
    const tags = normalizedRuleTags(rule);
    if (plan.mode === "remove") {
      const next = tags.filter((item) => item !== plan.tag);
      return {
        before: tags.length ? tags.join(", ") : "no tags",
        after: next.length ? next.join(", ") : "no tags",
        noOp: !tags.includes(plan.tag),
      };
    }
    const next = tags.includes(plan.tag) ? tags : [...tags, plan.tag].sort((a, b) => a.localeCompare(b));
    const issues = tagIssues(next);
    return {
      before: tags.length ? tags.join(", ") : "no tags",
      after: issues.length ? "blocked" : next.join(", "),
      noOp: tags.includes(plan.tag),
      issue: tags.includes(plan.tag) ? "" : issues[0] || "",
    };
  }
  const currentDisabled = Boolean(rule.disabled);
  return {
    before: currentDisabled ? "disabled" : "enabled",
    after: plan.disabled ? "disabled" : "enabled",
    noOp: currentDisabled === plan.disabled,
  };
}

function normalizedRuleTags(rule = {}) {
  return (Array.isArray(rule.tags) ? rule.tags : []).filter(Boolean).sort((a, b) => a.localeCompare(b));
}

function ruleIdIndex(rules = []) {
  const counts = ruleIdCounts(rules);
  const out = new Map();
  (Array.isArray(rules) ? rules : []).forEach((rule, idx) => {
    const id = normalizedRuleId(rule);
    if (id && counts.get(id) === 1) out.set(id, idx);
  });
  return out;
}

function bulkRuleSnapshotSignature(rule = {}) {
  return JSON.stringify(stableRuleValue(rule || {}));
}

export function ruleInspectionCoverage(policy = {}, rule = {}) {
  const ids = policy.ids || {};
  const network = policy.network || {};
  const idsEnabled = Boolean(ids.enabled);
  const idsMode = ids.mode || "";
  const failureBehavior = ids.failureBehavior || ids.failure_behavior || "";
  const flowOffload = Boolean(network.enableFlowOffload || network.enable_flow_offload);
  const action = rule.action || "ACTION_ALLOW";
  const blockingProfile = ruleHasBlockingSecurityProfile(policy, rule);

  if (!ruleActive(rule)) {
    return inspectionCoverage("disabled", "disabled", "neutral", "Rule is not enforced while disabled.");
  }
  if (action === "ACTION_DENY" || action === "ACTION_REJECT") {
    return inspectionCoverage("pre-filter-drop", "pre-filter drop", "neutral", "Traffic is stopped by policy before IDS/IPS inspection is needed.");
  }
  if (flowOffload && idsEnabled) {
    return inspectionCoverage("bypass-risk", "flowtable + IDS", "bad", "Flowtable fast path conflicts with IDS/IPS; offloaded flows can bypass inspection.", true);
  }
  if (idsEnabled && idsMode === "IDS_MODE_PREVENT") {
    if (failureBehavior === "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED") {
      if (blockingProfile) {
        return inspectionCoverage("profile-enforced", "profile enforced", "ok", "Blocking security profiles require and use inline IPS fail-closed before this allow verdict.");
      }
      return inspectionCoverage("ips-fail-closed", "IPS fail-closed", "ok", "Inline prevention blocks instead of silently bypassing when the inspection queue fails.");
    }
    if (blockingProfile) {
      return inspectionCoverage("profile-needs-fail-closed", "profile unsafe", "bad", "Blocking security profiles on allow rules require inline IPS fail-closed.", true);
    }
    return inspectionCoverage("ips-fail-open", "IPS fail-open", "warn", "Inline prevention can bypass traffic if the inspection queue fails.", true);
  }
  if (blockingProfile) {
    return inspectionCoverage("profile-needs-ips", "profile inactive", "bad", "Blocking security profiles on allow rules require IDS/IPS Prevent with Fail closed.", true);
  }
  if (idsEnabled) {
    return inspectionCoverage("ids-detect", "IDS detect", "info", "Traffic is observed by IDS; the policy action remains the enforcement verdict.");
  }
  if (flowOffload) {
    return inspectionCoverage("fast-path", "fast path", "neutral", "IDS/IPS is disabled; forwarding-only traffic can use packet filter flowtable acceleration.");
  }
  return inspectionCoverage("not-inspected", "not inspected", "warn", "IDS/IPS is disabled for this policy.");
}

function inspectionCoverage(state, label, cls, detail, bypassPossible = false) {
  return {
    state,
    label,
    cls,
    detail,
    bypassPossible,
    searchText: [state, label, detail, bypassPossible ? "bypass risk fail open" : ""].join(" ").toLowerCase(),
  };
}

function ruleHasBlockingSecurityProfile(policy = {}, rule = {}) {
  const refs = (rule.securityProfiles || []).filter(Boolean);
  if (!refs.length) return false;
  const profiles = new Map((policy.securityProfiles || []).map((profile) => [profile.name, profile]));
  return refs.some((ref) => securityProfileHasBlockingIntent(profiles.get(ref)));
}

function securityProfileHasBlockingIntent(profile = {}) {
  if (!profile) return false;
  return profile.tlsInspection === "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED" ||
    (profile.urlCategories || []).length > 0 ||
    profile.dnsSecurity === "DNS_SECURITY_MODE_BLOCK_MALICIOUS" ||
    profile.fileSecurity === "FILE_SECURITY_MODE_BLOCK_EXECUTABLES" ||
    profile.fileSecurity === "FILE_SECURITY_MODE_BLOCK_HIGH_RISK";
}

function normalizedRuleIndexes(indexes = [], max = 0) {
  return [...new Set(indexes.map((idx) => Number(idx)).filter((idx) => Number.isInteger(idx) && idx >= 0 && idx < max))].sort((a, b) => a - b);
}

function ruleIndexFromFieldPath(path = "") {
  const match = String(path || "").match(/^rules\[(\d+)\](?:\.|$)/);
  if (!match) return null;
  const n = Number(match[1]);
  return Number.isInteger(n) ? n : null;
}

function hostInputRuleIndexFromFieldPath(path = "") {
  const match = String(path || "").match(/^hostInput\.rules\[(\d+)\](?:\.|$)/);
  if (!match) return null;
  const n = Number(match[1]);
  return Number.isInteger(n) ? n : null;
}

function unusedObjectFindingFromValidation(code = "", fieldPath = "", finding = {}) {
  const kindByCode = {
    POLICY_HYGIENE_UNUSED_ADDRESS: "address",
    POLICY_HYGIENE_UNUSED_SERVICE: "service",
    POLICY_HYGIENE_UNUSED_APPLICATION: "application",
  };
  const kind = kindByCode[code];
  if (!kind) return null;
  const match = String(fieldPath || "").match(/^(addresses|services|applications)\[(\d+)\](?:\.|$)/);
  if (!match) return null;
  const index = Number(match[2]);
  if (!Number.isInteger(index) || index < 0) return null;
  return {
    kind,
    index,
    fieldPath,
    code,
    message: String(finding?.message || finding?.detail || "").trim(),
    detail: String(finding?.detail || finding?.message || "").trim(),
  };
}

function ruleTags(rules = []) {
  const tags = new Set();
  for (const rule of rules || []) {
    for (const tag of rule.tags || []) {
      if (tag) tags.add(tag);
    }
  }
  return [...tags].sort((a, b) => a.localeCompare(b));
}

function ruleGroupBucket(rule = {}, group = DEFAULT_GROUP) {
  if (group === "tag") {
    const tag = (rule.tags || []).filter(Boolean).sort((a, b) => a.localeCompare(b))[0] || "untagged";
    return {
      id: "tag:" + tag,
      label: tag === "untagged" ? "Untagged rules" : "Tag: " + tag,
      detail: tag === "untagged" ? "Rules without ownership, lifecycle, or compliance tags." : "Rules carrying this tag.",
    };
  }
  if (group === "action") {
    const action = rule.action || "ACTION_UNSPECIFIED";
    const label = fmt.ruleAction(action).label;
    return {
      id: "action:" + action,
      label: "Action: " + label,
      detail: "Review rules by enforcement verdict.",
    };
  }
  if (group === "zone") {
    const from = groupRefs(rule.fromZones);
    const to = groupRefs(rule.toZones);
    return {
      id: "zone:" + from + ">" + to,
      label: from + " → " + to,
      detail: "Review rules by zone path.",
    };
  }
  return { id: "all", label: "All rules", detail: "Policy order view." };
}

function groupRefs(values = []) {
  const refs = fmt.namesOrAny(values).filter(Boolean);
  return refs.length > 2 ? `${refs.slice(0, 2).join(", ")} +${refs.length - 2}` : refs.join(", ");
}

export function groupRuleRows(rows = [], group = DEFAULT_GROUP) {
  const normalized = normalizeRuleGroup(group);
  if (normalized === "none") return [{ id: "all", label: "All rules", rows: [...rows] }];
  const grouped = new Map();
  for (const row of rows || []) {
    const bucket = ruleGroupBucket(row?.rule || {}, normalized);
    if (!grouped.has(bucket.id)) grouped.set(bucket.id, { ...bucket, rows: [] });
    grouped.get(bucket.id).rows.push(row);
  }
  return [...grouped.values()];
}

export function ruleTableHasActiveFilter(filterState = {}) {
  return Boolean(filterState.q || filterState.action || filterState.zone || filterState.tag || filterState.changed);
}

export function canReorderRuleRows(filterState = {}, selectedCount = 0, group = DEFAULT_GROUP) {
  return !Number(selectedCount || 0) && !ruleTableHasActiveFilter(filterState) && normalizeRuleGroup(group) === DEFAULT_GROUP;
}

export function ruleTableScaleReview(totalRules = 0, visibleRules = 0, selectedRules = 0, filterState = {}, group = DEFAULT_GROUP) {
  const total = Math.max(0, Math.trunc(Number(totalRules) || 0));
  const visible = Math.max(0, Math.trunc(Number(visibleRules) || 0));
  const selected = Math.max(0, Math.trunc(Number(selectedRules) || 0));
  const filtered = ruleTableHasActiveFilter(filterState);
  const grouped = normalizeRuleGroup(group) !== DEFAULT_GROUP;
  const large = total >= RULE_TABLE_SCALE_REVIEW_THRESHOLD || visible >= RULE_TABLE_SCALE_REVIEW_THRESHOLD;
  if (!large && selected < RULE_TABLE_SCALE_REVIEW_THRESHOLD) return null;
  const warnings = [
    "Bulk route targets use durable rule IDs when present and fall back to position/signature for legacy rules.",
  ];
  if (!filtered && visible >= RULE_TABLE_SCALE_REVIEW_THRESHOLD) {
    warnings.push("Narrow the visible set with filters or grouping before staging bulk edits.");
  }
  if (grouped) warnings.push("Grouped views preserve rule order but pause drag reorder.");
  if (selected >= RULE_TABLE_SCALE_REVIEW_THRESHOLD) warnings.push("Review selected-rule count before staging; large bulk edits should be copied as API/CLI context first.");
  warnings.push("Pagination or virtualization must not reuse this selection without refreshing the route, durable IDs, and target list.");
  return {
    state: selected ? "selection-review" : filtered || grouped ? "bounded-review" : "large-rulebase",
    total,
    visible,
    selected,
    filtered,
    grouped,
    warnings,
  };
}

export function ruleLargeRulebasePosture(policy = {}, visibleRows = [], selectedIndexes = [], validationState = {}, validationCleanup = {}, opts = {}) {
  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  const total = rules.length;
  const visibleIndexes = visibleRuleIndexList(visibleRows);
  const visible = new Set(visibleIndexes);
  const selected = normalizedRuleIndexes(selectedIndexes, total);
  const selectedVisible = selected.filter((idx) => visible.has(idx)).length;
  const durableCount = rules.filter((rule) => normalizedRuleId(rule)).length;
  const fallbackCount = Math.max(0, total - durableCount);
  const checkedSnapshot = ruleValidationSnapshotStatus(validationState, policy);
  const overlapMeta = ruleOverlapPagePosture(validationCleanup);
  const targetSnapshot = bulkRuleTargetSnapshotStatus(policy, opts.targetSnapshotToken || "");
  const filtered = ruleTableHasActiveFilter(opts.filter || {});
  const grouped = normalizeRuleGroup(opts.group) !== DEFAULT_GROUP;
  const coverage = [
    "Candidate table counts reflect the current browser candidate snapshot only.",
    "Visible and selected bulk targets use current filters/grouping; hidden selected targets must be reviewed before staging.",
    "Server overlap metadata is bounded by the validation cap and page fields returned with the last candidate validation.",
  ];
  const omitted = [
    "No backend pagination, virtualization retention, signed evidence custody, or cross-page selection authority is claimed here.",
    "Refresh validation after candidate edits; stale overlap metadata is review guidance, not commit proof.",
  ];
  return {
    total,
    visible: visibleIndexes.length,
    hidden: Math.max(0, total - visibleIndexes.length),
    selected: selected.length,
    selectedVisible,
    selectedHidden: Math.max(0, selected.length - selectedVisible),
    filtered,
    grouped,
    durableCount,
    fallbackCount,
    identityMode: fallbackCount ? "mixed" : total ? "durable" : "empty",
    targetSnapshot,
    validationSnapshot: checkedSnapshot,
    overlap: overlapMeta,
    coverage,
    omitted,
  };
}

function ruleOverlapPagePosture(validationCleanup = {}) {
  const findings = Array.isArray(validationCleanup.overlapFindings) ? validationCleanup.overlapFindings : [];
  const firstPage = findings.map((finding) => finding.overlapPage).find(Boolean) || null;
  const limit = Math.max(1, Number(firstPage?.limit || validationCleanup.overlapFindingLimit || SERVER_OVERLAP_FINDING_LIMIT));
  const resultCount = Number(firstPage?.resultCount || findings.length);
  const totalResults = Number(firstPage?.totalResults || findings.length);
  return {
    findingCount: findings.length,
    limit,
    pageKey: firstPage?.pageKey || "",
    resultCount,
    totalResults,
    hasMore: Boolean(firstPage?.hasMore),
    nextOffset: Number(firstPage?.nextOffset || 0),
    mayBeTruncated: Boolean(firstPage?.truncated || validationCleanup.overlapFindingsMayBeTruncated || findings.length >= limit),
  };
}

export function ruleIdentityReviewNotes(policy = {}, indexes = [], visibleRows = [], opts = {}) {
  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  const normalized = normalizedRuleIndexes(indexes, rules.length);
  const visible = new Set((visibleRows || []).map((row) => Number(row?.idx)).filter((idx) => Number.isInteger(idx)));
  const nameCounts = ruleNameCounts(rules);
  const duplicateNames = [...new Set(normalized
    .map((idx) => rules[idx]?.name || "")
    .filter((name, offset) => {
      const idx = normalized[offset];
      return name && !normalizedRuleId(rules[idx]) && nameCounts.get(name) > 1;
    }))];
  const missingIDs = normalized.filter((idx) => !normalizedRuleId(rules[idx])).length;
  const notes = [
    missingIDs
      ? "Rule identity uses durable rule IDs where present; legacy rules without IDs use the current position/signature fallback."
      : "Rule identity uses durable rule IDs plus a stale-content signature guard.",
  ];
  if (duplicateNames.length) {
    notes.push(`Duplicate selected rule names require position review before staging: ${duplicateNames.slice(0, 6).join(", ")}${duplicateNames.length > 6 ? ` +${duplicateNames.length - 6}` : ""}.`);
  }
  if (normalized.some((idx) => !visible.has(idx))) {
    notes.push("Some selected rules are hidden by the current filter or group lens; confirm the hidden targets in this review before staging.");
  }
  if (opts.reorder || normalized.length > 1) {
    notes.push("If targeted rules are duplicated, deleted, or edited after this drawer opens, close it and rebuild the review from the current candidate.");
  }
  if (rules.length >= RULE_TABLE_SCALE_REVIEW_THRESHOLD || normalized.length >= RULE_TABLE_SCALE_REVIEW_THRESHOLD || opts.paginationRisk) {
    notes.push("Do not carry this selection across pagination or virtualization boundaries without refreshing the route, filters, durable IDs, and target list.");
  }
  return dedupeText(notes);
}

function flowSimulator(zones, root) {
  if (!simulator.source) simulator.source = session.dirty ? "POLICY_SOURCE_CANDIDATE" : "POLICY_SOURCE_RUNNING";

  const source = select([
    ["POLICY_SOURCE_RUNNING", "Running"],
    ["POLICY_SOURCE_CANDIDATE", "Candidate"],
  ], simulator.source);
  const fromZone = select([["", "Any from-zone"], ...zones.map((z) => [z, z])], simulator.fromZone);
  const toZone = select([["", "Any to-zone"], ...zones.map((z) => [z, z])], simulator.toZone);
  const protocol = select([
    ["PROTOCOL_TCP", "TCP"],
    ["PROTOCOL_UDP", "UDP"],
    ["PROTOCOL_ICMP", "ICMP"],
    ["PROTOCOL_ANY", "Any IP"],
  ], simulator.protocol);
  const appOptions = (session.draft.applications || []).map((a) => [a.name, a.displayName ? `${a.displayName} (${a.name})` : a.name]);
  const appId = select([["", "No App-ID"], ...appOptions], simulator.appId);
  const users = input("text", simulator.users, "alice@example.com");
  const groups = input("text", simulator.groups, "idp/secops");
  const devices = input("text", simulator.devices, "laptop-123");
  const postureLabels = input("text", simulator.postureLabels, "posture:edr-healthy");
  const srcIp = input("text", simulator.srcIp, "10.0.1.20");
  const srcPort = input("number", simulator.srcPort, "51515");
  const destIp = input("text", simulator.destIp, "10.0.2.20");
  const destPort = input("number", simulator.destPort, "443");
  const resultNode = h("div", { class: "sim-result" });

  const controls = { source, fromZone, toZone, protocol, users, groups, devices, postureLabels, srcIp, srcPort, destIp, destPort };
  controls.appId = appId;
  const form = h("form", { class: "sim-form", onsubmit: (e) => runSimulation(e, controls, resultNode, root) },
    h("div", { class: "sim-fields" },
      field("Source", source),
      field("From", fromZone),
      field("To", toZone),
      field("Protocol", protocol),
      field("App-ID", appId, "optional"),
      field("Users", users, "optional comma list"),
      field("Groups", groups, "optional comma list"),
      field("Devices", devices, "optional comma list"),
      field("Posture", postureLabels, "optional comma list"),
      field("Source IP", srcIp),
      field("Source port", srcPort),
      field("Destination IP", destIp),
      field("Destination port", destPort)),
    h("div", { class: "sim-actions" },
      h("button", { class: "btn primary", type: "submit", title: "Explain this flow against the selected policy", "aria-label": "Explain this flow against the selected policy", dataset: { ruleSimulationAction: "explain" } }, h("span", { html: icon("search", 16) }), "Explain"),
      h("button", { class: "btn ghost", ...actionControlAttrs({ ruleSimulationAction: "troubleshoot" }, "Open Troubleshoot with this flow", { onclick: () => openTroubleshoot(controls) }) },
        h("span", { html: icon("arrowRight", 16) }), "Troubleshoot"),
      h("button", { class: "btn ghost", ...actionControlAttrs({ ruleSimulationAction: "capture-troubleshoot" }, "Open packet capture troubleshooting for this flow", { onclick: () => openTroubleshoot(controls, { run: true, intent: "capture" }) }) },
        h("span", { html: icon("terminal", 16) }), "Capture")));

  paintSimulation(resultNode, root);
  maybeRunSharedSimulation(resultNode, root);
  return h("section", { class: "rule-simulator" },
    h("div", { class: "sim-head" },
      h("div", {},
        h("h2", {}, "Flow check"),
        h("div", { class: "note" }, session.dirty ? "Candidate policy is staged for this check." : "Running policy is the default source.")),
      session.dirty ? pill("candidate staged", "warn", true) : pill("running", "neutral", true)),
    caseCustodyBanner(),
    form,
    resultNode);
}

function caseCustodyBanner() {
  if (!caseContext.caseKey) return null;
  return h("div", {
    class: "case-custody-banner",
    dataset: {
      caseCustody: "true",
      caseKey: caseContext.caseKey,
      caseAction: caseContext.caseAction,
    },
  },
    h("span", { html: icon("inbox", 15) }),
    h("div", {},
      h("strong", {}, "Investigation case handoff"),
      h("span", {}, `${caseContext.caseAction || "case action"} from ${caseContext.caseKind || "pinned evidence"}; staged fixes will be pinned back to the case.`)),
    h("a", { class: "btn sm ghost", href: "#/investigation", title: "Open investigation case", "aria-label": "Open investigation case", dataset: { ruleCaseAction: "open-case" } }, h("span", { html: icon("arrowRight", 14) }), "Open case"));
}

async function runSimulation(e, controls, resultNode, root) {
  e.preventDefault();
  rememberSimulation(controls);
  simulatorQueryActive = true;
  simulatorRouteRun = true;
  syncRoute();
  await evaluateSimulation(resultNode, root);
}

async function evaluateSimulation(resultNode, root) {
  simulator.runRequested = false;
  if (!simulator.srcIp || !simulator.destIp) {
    simulator.error = "Source IP and destination IP are required.";
    simulator.result = null;
    simulator.loading = false;
    paintSimulation(resultNode, root);
    return;
  }

  simulator.error = "";
  simulator.result = null;
  simulator.loading = true;
  paintSimulation(resultNode, root);
  try {
    if (simulator.source === "POLICY_SOURCE_CANDIDATE") {
      await session.stageDraft("run candidate flow check");
    }
    simulator.result = await api.explainFlow(simulationExplainRequest());
  } catch (err) {
    simulator.error = err.message;
    toast("Flow check failed", err.message, "bad");
  } finally {
    simulator.loading = false;
    paintSimulation(resultNode, root);
  }
}

function maybeRunSharedSimulation(resultNode, root) {
  if (!simulator.runRequested || simulator.loading) return;
  const key = JSON.stringify(rulesFlowCheckRouteState(filter, simulator, {
    density: tableDensity,
    group: tableGroup,
    active: simulatorQueryActive,
    run: true,
  }));
  if (simulator.autorunKey === key) return;
  simulator.autorunKey = key;
  queueMicrotask(() => evaluateSimulation(resultNode, root));
}

function rememberSimulation(c) {
  simulator.source = c.source.value;
  simulator.fromZone = c.fromZone.value;
  simulator.toZone = c.toZone.value;
  simulator.protocol = c.protocol.value;
  simulator.appId = c.appId.value;
  simulator.users = c.users.value.trim();
  simulator.groups = c.groups.value.trim();
  simulator.devices = c.devices.value.trim();
  simulator.postureLabels = c.postureLabels.value.trim();
  simulator.srcIp = c.srcIp.value.trim();
  simulator.srcPort = c.srcPort.value.trim();
  simulator.destIp = c.destIp.value.trim();
  simulator.destPort = c.destPort.value.trim();
}

function applyRouteQuery(query = {}) {
  const parsed = readQueryState(query, QUERY_DEFAULTS, QUERY_KEYS);
  filter = {
    q: parsed.q.toLowerCase(),
    action: ["", "ACTION_ALLOW", "ACTION_DENY", "ACTION_REJECT"].includes(parsed.action) ? parsed.action : "",
    zone: parsed.zone,
    tag: parsed.tag,
    ruleId: safeRouteToken(parsed.ruleId, 160),
    rule: parsed.rule || "",
    changed: Boolean(parsed.changed),
  };
  tableDensity = normalizeRuleDensity(parsed.density);
  tableGroup = normalizeRuleGroup(parsed.group);
  activeRuleReviewDrawer = normalizeRuleReviewDrawer(parsed.drawer);
  routeBulkTag = safeRouteToken(parsed.bulkTag, MAX_RULE_TAG_LENGTH);
  routeBulkTargets = safeRouteToken(parsed.bulkTargets, MAX_RULE_BULK_TARGETS_LENGTH);
  selectedRuleIndexes.clear();
  simulatorQueryActive = hasSimulatorQuery(parsed);
  simulatorRouteRun = Boolean(parsed.simRun) && simulatorQueryActive;
  caseContext = {
    caseKey: safeRouteToken(parsed.caseKey, 320),
    caseAction: safeRouteToken(parsed.caseAction, 80),
    caseKind: safeRouteToken(parsed.caseKind, 80),
  };
  Object.assign(simulator, {
    ...DEFAULT_SIMULATOR,
    source: parsed.simSource,
    fromZone: parsed.simFrom,
    toZone: parsed.simTo,
    protocol: ["PROTOCOL_TCP", "PROTOCOL_UDP", "PROTOCOL_ICMP", "PROTOCOL_ANY"].includes(parsed.simProtocol) ? parsed.simProtocol : "PROTOCOL_TCP",
    appId: parsed.simApp,
    users: parsed.simUsers,
    groups: parsed.simGroups,
    devices: parsed.simDevices,
    postureLabels: parsed.simPosture,
    srcIp: parsed.simSrc,
    srcPort: validPortOrEmpty(parsed.simSport),
    destIp: parsed.simDst,
    destPort: validPortOrEmpty(parsed.simDport),
    loading: false,
    result: null,
    error: "",
    runRequested: simulatorRouteRun,
    autorunKey: "",
  });
}

function syncRoute() {
  writeQueryState(routePath, queryState(), QUERY_DEFAULTS, QUERY_KEYS);
}

function queryState() {
  return rulesFlowCheckRouteState(filter, simulator, {
    density: tableDensity,
    group: tableGroup,
    drawer: activeRuleReviewDrawer,
    bulkTag: routeBulkTag,
    bulkTargets: routeBulkTargets,
    active: simulatorQueryActive,
    run: simulatorQueryActive && simulatorRouteRun,
    caseContext,
  });
}

function ruleReviewRouteHash(drawer = activeRuleReviewDrawer, bulkTag = routeBulkTag, bulkTargets = routeBulkTargets) {
  return buildHash(routePath || "/rules", {
    ...queryState(),
    drawer: normalizeRuleReviewDrawer(drawer),
    bulkTag: safeRouteToken(bulkTag, MAX_RULE_TAG_LENGTH),
    bulkTargets: safeRouteToken(bulkTargets, MAX_RULE_BULK_TARGETS_LENGTH),
  }, QUERY_DEFAULTS, QUERY_KEYS);
}

function clearRuleReviewDrawerRoute() {
  if (preservingRuleReviewDrawerRoute) return;
  if (!activeRuleReviewDrawer && !routeBulkTag && !routeBulkTargets) return;
  activeRuleReviewDrawer = "";
  routeBulkTag = "";
  routeBulkTargets = "";
  autoOpenedRuleReviewDrawer = "";
  syncRoute();
}

function closeRuleReviewDrawer() {
  clearRuleReviewDrawerRoute();
  closeDrawer();
}

function refreshRuleReviewDrawer(fn) {
  preservingRuleReviewDrawerRoute = true;
  try {
    fn();
  } finally {
    preservingRuleReviewDrawerRoute = false;
  }
}

function setRuleReviewDrawerRoute(drawer = "", opts = {}) {
  activeRuleReviewDrawer = normalizeRuleReviewDrawer(drawer);
  routeBulkTag = safeRouteToken(opts.bulkTag, MAX_RULE_TAG_LENGTH);
  routeBulkTargets = safeRouteToken(opts.bulkTargets, MAX_RULE_BULK_TARGETS_LENGTH);
  autoOpenedRuleReviewDrawer = "";
  syncRoute();
}

export function ruleReviewContextText(model = {}) {
  const filters = model.filters || {};
  const commands = Array.isArray(model.commands) ? model.commands.filter(Boolean) : [];
  const targets = Array.isArray(model.targets) ? model.targets : [];
  const notes = Array.isArray(model.notes) ? model.notes.filter(Boolean) : [];
  const lines = [
    model.title || "Rules review",
    `Drawer: ${normalizeRuleReviewDrawer(model.drawer) || "manual"}`,
    model.routeHash ? `Route: ${model.routeHash}` : "",
    `Targets: ${Number(model.targetCount || 0)}`,
    model.visibleCount != null ? `Visible targets: ${Number(model.visibleCount || 0)}` : "",
    model.hiddenCount != null ? `Hidden targets: ${Number(model.hiddenCount || 0)}` : "",
    `Will change: ${Number(model.changeCount || 0)}`,
    model.noOpCount != null ? `No-op: ${Number(model.noOpCount || 0)}` : "",
    `Blocked: ${Number(model.blockedCount || 0)}`,
    model.action ? `Action: ${model.action}` : "",
    model.tag ? `Tag: ${model.tag}` : "",
    `Filters: q=${filters.q || ""}; action=${filters.action || ""}; zone=${filters.zone || ""}; tag=${filters.tag || ""}; changed=${filters.changed ? "true" : "false"}`,
    model.group ? `Group: ${model.group}` : "",
    model.density ? `Density: ${model.density}` : "",
    notes.length ? "Notes:" : "",
    ...notes.map((note) => `- ${note}`),
    targets.length ? "Target rules:" : "",
    ...targets.slice(0, 50).map(ruleReviewTargetLine),
    targets.length > 50 ? `- ... ${targets.length - 50} more target rules omitted from clipboard context` : "",
    commands.length ? "Commands:" : "",
    ...commands.map((cmd) => `- ${cmd}`),
  ];
  return lines.filter(Boolean).join("\n");
}

function ruleReviewTargetLine(row = {}) {
  const visibility = row.visible ? "visible" : "hidden";
  const state = row.issue ? "blocked" : row.noOp ? "no-op" : "change";
  const issue = row.issue ? `; issue=${row.issue}` : "";
  const itemId = row.itemId ? ` id=${row.itemId}` : "";
  return `- #${Number(row.position || row.index + 1 || 0)} ${row.name || "(unnamed)"}${itemId} [${visibility}/${state}]: ${row.before || "-"} -> ${row.after || "-"}${issue}`;
}

function bulkRuleReviewContext(preview = {}, action = {}, drawer = "") {
  return {
    title: preview.title,
    drawer,
    routeHash: ruleReviewRouteHash(drawer, preview.tag || routeBulkTag, preview.routeTargetSnapshotToken || routeBulkTargets),
    targetCount: preview.targetCount,
    visibleCount: preview.visibleCount,
    hiddenCount: preview.hiddenCount,
    changeCount: preview.changeCount,
    noOpCount: preview.noOpCount,
    blockedCount: preview.blockedCount,
    action: bulkReviewActionLabel(action),
    tag: preview.tag || "",
    notes: preview.identityNotes || [],
    targets: preview.rows || [],
    commands: ruleCandidateReviewCommands(),
  };
}

export function ruleCandidateReviewCommands(opts = {}) {
  const commands = [
    "ngfwctl policy status --json",
    "ngfwctl policy validate",
    "ngfwctl policy diff",
  ];
  if (opts.explain) {
    commands.push(typeof opts.explain === "string" ? opts.explain : "ngfwctl explain --source candidate --from-zone <zone> --to-zone <zone> --src <ip> --dst <ip> --dport <port>");
  }
  return commands;
}

async function copyRuleReviewContext(model = {}) {
  const text = ruleReviewContextText({
    filters: filter,
    group: tableGroup,
    density: tableDensity,
    ...model,
  });
  try {
    await navigator.clipboard.writeText(text);
    toast("Review context copied", "Route, filters, targets, and validation commands copied.", "ok");
  } catch (err) {
    toast("Copy failed", err.message || "Clipboard is unavailable.", "bad");
  }
}

function hasSimulatorQuery(parsed) {
  return Boolean(parsed.simSource || parsed.simFrom || parsed.simTo || parsed.simApp ||
    parsed.simUsers || parsed.simGroups || parsed.simDevices || parsed.simPosture ||
    parsed.simSrc || parsed.simSport || parsed.simDst || parsed.simDport ||
    (parsed.simProtocol && parsed.simProtocol !== DEFAULT_SIMULATOR.protocol) ||
    parsed.simRun);
}

function validPortOrEmpty(value) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 65535) return "";
  return String(n);
}

function safeRouteToken(value = "", limit = 320) {
  const text = String(value || "").trim();
  if (!text || text.length > limit) return "";
  if (/[\u0000-\u001f\u007f]/.test(text)) return "";
  if (/bearer|token|secret|password|\/var\/|\/etc\/|\/tmp\/|file:/i.test(text)) return "";
  return text;
}

function firstConcreteRef(values = []) {
  const refs = Array.isArray(values) ? values : [values];
  return refs.map((item) => String(item || "").trim()).find((item) => item && item.toLowerCase() !== "any") || "";
}

function representativeAddress(policy = {}, ref = "", role = "address", warnings = []) {
  if (!ref) {
    warnings.push(`Rule has broad ${role} address scope.`);
    return "";
  }
  const obj = (policy.addresses || []).find((item) => item?.name === ref);
  if (!obj) {
    warnings.push(`${role} address object "${ref}" was not found.`);
    return "";
  }
  const cidr = String(obj.cidr || obj.value || "").trim();
  const ip = representativeIP(cidr);
  if (!ip) warnings.push(`${role} address object "${ref}" has no concrete CIDR.`);
  return ip;
}

function representativeService(policy = {}, rule = {}, warnings = []) {
  const ref = firstConcreteRef(rule.services);
  if (!ref) {
    if (!firstConcreteRef(rule.applications)) warnings.push("Rule has broad service scope.");
    return { protocol: "", destPort: "" };
  }
  const obj = (policy.services || []).find((item) => item?.name === ref);
  if (!obj) {
    warnings.push(`service object "${ref}" was not found.`);
    return { protocol: "", destPort: "" };
  }
  const protocol = normalizeProtocol(obj.protocol);
  if (protocol === "PROTOCOL_ICMP") return { protocol, destPort: "" };
  const port = firstPort(obj.ports);
  return { protocol, destPort: port };
}

function representativeApplicationPort(policy = {}, appRef = "", warnings = []) {
  if (!appRef) return { protocol: "", destPort: "" };
  const app = (policy.applications || []).find((item) => item?.name === appRef);
  if (!app) {
    warnings.push(`application object "${appRef}" was not found.`);
    return { protocol: "", destPort: "" };
  }
  const hints = Array.isArray(app.ports) ? app.ports : [];
  for (const hint of hints) {
    const protocol = normalizeProtocol(hint?.protocol);
    const port = firstPort(hint?.ports);
    if ((protocol === "PROTOCOL_TCP" || protocol === "PROTOCOL_UDP") && port) return { protocol, destPort: port };
    if (protocol === "PROTOCOL_ICMP") return { protocol, destPort: "" };
  }
  warnings.push(`application object "${appRef}" has no concrete port hint.`);
  return { protocol: "", destPort: "" };
}

function representativeIP(cidr = "") {
  const value = String(cidr || "").trim();
  if (!value) return "";
  const [addr, prefixText] = value.split("/");
  if (!prefixText) return addr;
  if (addr.includes(":")) return addr;
  const octets = addr.split(".").map((item) => Number(item));
  if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return addr;
  const prefix = Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return addr;
  if (prefix >= 31) return addr;
  const base = (((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3]) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = base & mask;
  return ipv4FromInt((network + 1) >>> 0);
}

function ipv4FromInt(value) {
  return [
    (value >>> 24) & 255,
    (value >>> 16) & 255,
    (value >>> 8) & 255,
    value & 255,
  ].join(".");
}

function normalizeProtocol(value = "") {
  const text = String(value || "").trim().toUpperCase();
  if (text === "TCP") return "PROTOCOL_TCP";
  if (text === "UDP") return "PROTOCOL_UDP";
  if (text === "ICMP") return "PROTOCOL_ICMP";
  if (["PROTOCOL_TCP", "PROTOCOL_UDP", "PROTOCOL_ICMP", "PROTOCOL_ANY"].includes(text)) return text;
  return "PROTOCOL_TCP";
}

function firstPort(ports = []) {
  const list = Array.isArray(ports) ? ports : [];
  for (const port of list) {
    const value = validPortOrEmpty(port?.start ?? port?.port ?? port);
    if (value) return value;
  }
  return "";
}

function dedupeText(values = []) {
  return [...new Set(values.map((item) => String(item || "").trim()).filter(Boolean))];
}

function paintSimulation(node, root) {
  clear(node);
  if (simulator.loading) {
    node.appendChild(h("div", { class: "sim-empty" }, "Evaluating policy…"));
    node.appendChild(ruleSimulationResultActions(root, true));
    return;
  }
  if (simulator.error) {
    node.appendChild(h("div", { class: "alert-box bad" }, simulator.error));
    return;
  }
  if (!simulator.result) {
    node.appendChild(h("div", { class: "sim-empty" }, "No flow evaluated."));
    return;
  }
  const r = simulator.result;
  const profile = r.inspectionProfile;
  const nat = r.natProfile || r.natDecision;
  const route = r.routeProfile;
  node.appendChild(h("div", { class: "sim-summary " + explainVerdictClass(r.verdict) },
    h("div", {},
      h("strong", {}, explainDecisionLabel(r) || explainLabel(r.verdict, "EXPLAIN_VERDICT_")),
      h("span", {}, r.reason || "No reason returned.")),
    pill(explainLabel(r.inspectionState, "EXPLAIN_INSPECTION_STATE_"), explainInspectionClass(r.inspectionState))));
  node.appendChild(ruleSimulationResultActions(root, false));
  node.appendChild(h("div", { class: "sim-detail" },
    h("div", {},
      h("span", {}, "Matched"),
      h("strong", {}, r.matchedRule ? `${r.matchedRule} (#${Number(r.matchedRuleIndex || 0) + 1})` : r.defaultPolicy ? "default policy" : "none")),
    h("div", {},
      h("span", {}, "Source"),
      h("strong", {}, explainLabel(r.policySource, "POLICY_SOURCE_").toLowerCase())),
    profile ? h("div", {},
      h("span", {}, "Inspection"),
      h("strong", {}, profile.idsEnabled ? `${profile.engine || "engine"} / ${explainLabel(profile.idsMode, "IDS_MODE_")}` : "disabled")) : null,
    profile ? h("div", {},
      h("span", {}, "Bypass"),
      h("strong", {}, profile.bypassPossible ? "possible" : "not indicated")) : null,
    nat ? h("div", {},
      h("span", {}, "NAT"),
      h("strong", {}, natProfileSummary(nat))) : null,
    route ? h("div", {},
      h("span", {}, "Route"),
      h("strong", {}, routeLabel(route))) : null,
    route?.nextHop || route?.egressInterface ? h("div", {},
      h("span", {}, "Egress"),
      h("strong", {}, [route.nextHop ? "via " + route.nextHop : "", route.egressInterface ? "dev " + route.egressInterface : ""].filter(Boolean).join(" "))) : null));
  const profileLines = inspectionProfileLines(profile);
  const natLines = natProfileLines(nat);
  const routeLines = routeProfileLines(route);
  if (profileLines.length || natLines.length || routeLines.length || r.evidence?.length || r.trace?.length || r.warnings?.length) {
    node.appendChild(h("div", { class: "sim-evidence" },
      profileLines.length ? simList("Inspection profile", profileLines, profile?.bypassPossible ? "warn" : "", "inspection") : null,
      natLines.length ? simList("NAT decision", natLines, "", "nat") : null,
      routeLines.length ? simList("Route decision", routeLines, route?.matched || !route?.evaluated ? "" : "warn", "route") : null,
      simList("Evidence", r.evidence),
      simList("Trace", r.trace),
      r.warnings?.length ? simList("Warnings", r.warnings, "warn") : null));
  }
}

function ruleSimulationResultActions(root, disabled = false) {
  return h("div", { class: "sim-actions start" },
    h("button", { class: "btn sm primary", ...actionControlAttrs({ ruleSimulationAction: "stage-allow" }, "Stage allow rule from flow check", { disabled, onclick: () => stageRuleFromSimulation("ACTION_ALLOW", root) }) },
      h("span", { html: icon("plus", 15) }), "Stage allow rule"),
    h("button", { class: "btn sm", ...actionControlAttrs({ ruleSimulationAction: "stage-drop" }, "Stage drop rule from flow check", { disabled, onclick: () => stageRuleFromSimulation("ACTION_DENY", root) }) },
      h("span", { html: icon("plus", 15) }), "Stage drop rule"),
    h("button", { class: "btn sm", ...actionControlAttrs({ ruleSimulationAction: "capture" }, "Capture this flow from Troubleshoot", { disabled, onclick: () => openTroubleshootFromCurrentSimulation({ run: true, intent: "capture" }) }) },
      h("span", { html: icon("terminal", 15) }), "Capture"),
    h("button", { class: "btn sm", ...actionControlAttrs({ ruleSimulationAction: "copy-link" }, "Copy flow check link", { disabled, onclick: copyRuleSimulationLink }) },
      h("span", { html: icon("copy", 15) }), "Copy link"),
    h("button", { class: "btn sm", ...actionControlAttrs({ ruleSimulationAction: "pin-handoff" }, "Pin flow check handoff to case", { disabled, onclick: pinRuleSimulationHandoff }) },
      h("span", { html: icon("inbox", 15) }), "Pin to case"),
    h("button", { class: "btn sm", ...actionControlAttrs({ ruleSimulationAction: "export-handoff" }, "Export flow check handoff", { disabled, onclick: exportRuleSimulationHandoff }) },
      h("span", { html: icon("download", 15) }), "Export handoff"));
}

function simulationExplainRequest() {
  const request = {
    policySource: simulator.source,
    version: "0",
    fromZone: simulator.fromZone,
    toZone: simulator.toZone,
    srcIp: simulator.srcIp,
    srcPort: numberOrZero(simulator.srcPort),
    destIp: simulator.destIp,
    destPort: numberOrZero(simulator.destPort),
    protocol: simulator.protocol,
    appId: simulator.appId,
  };
  const matchContext = ruleMatchContextFromInputs({
    users: simulator.users,
    groups: simulator.groups,
    devices: simulator.devices,
    postureLabels: simulator.postureLabels,
  });
  if (Object.keys(matchContext).length) request.matchContext = matchContext;
  return request;
}

function ruleSimulationShareHash(run = true) {
  return rulesFlowCheckHash(routePath, filter, simulator, {
    density: tableDensity,
    group: tableGroup,
    active: true,
    run,
    caseContext,
  });
}

function ruleSimulationShareURL(run = true) {
  const hash = ruleSimulationShareHash(run);
  if (typeof location === "undefined") return hash;
  try {
    const url = new URL(location.href);
    url.hash = hash;
    return url.toString();
  } catch {
    return hash;
  }
}

async function copyRuleSimulationLink() {
  try {
    simulatorQueryActive = true;
    simulatorRouteRun = true;
    syncRoute();
    await navigator.clipboard.writeText(ruleSimulationShareURL(true));
    toast("Flow check link copied", "Reloading the link replays this rulebase explanation.", "ok");
  } catch {
    toast("Copy failed", "Copy the current browser URL after running the flow check.", "warn");
  }
}

function ruleSimulationHandoffPacket() {
  return explainHandoffPacket({
    query: simulationExplainRequest(),
    result: simulator.result,
  }, {
    route: ruleSimulationShareHash(true),
  });
}

function pinRuleSimulationHandoff() {
  if (!simulator.result) return;
  try {
    const result = pinInvestigationPacket(ruleSimulationHandoffPacket());
    toast(result.toastTitle, result.toastDetail, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Selected rulebase explain evidence could not be pinned.", "bad");
  }
}

function exportRuleSimulationHandoff() {
  if (!simulator.result) return;
  const packet = ruleSimulationHandoffPacket();
  const text = investigationPacketJson(packet);
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: investigationPacketFilename(packet) });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  toast("Flow check handoff exported", "Downloaded the rulebase explain result as JSON.", "ok");
}

async function stageRuleFromSimulation(action, root) {
  if (!simulator.srcIp || !simulator.destIp) {
    toast("Flow fields required", "Run a flow check with source and destination IPs first.", "warn");
    return;
  }
  const allow = action === "ACTION_ALLOW";
  try {
    let ruleName = "";
    await session.apply((d) => {
      if (!d.rules) d.rules = [];
      const source = ensureAddressObject(d, simulator.srcIp, "src");
      const destination = ensureAddressObject(d, simulator.destIp, "dst");
      const service = ensureServiceObject(d, simulator.protocol, simulator.destPort);
      const fromZones = simulator.fromZone ? [simulator.fromZone] : ["any"];
      const toZones = simulator.toZone ? [simulator.toZone] : ["any"];
      ruleName = uniqueName(d.rules, sanitizeName(`${allow ? "allow" : "drop"}-${fromZones[0]}-${toZones[0]}-${service}`));
      const rule = {
        id: freshRuleId(d.rules, { name: ruleName }),
        name: ruleName,
        fromZones,
        toZones,
        sourceAddresses: [source],
        destinationAddresses: [destination],
        services: [service],
        action,
        log: true,
        disabled: false,
        description: flowRuleDescription(action),
      };
      d.rules.splice(recommendedInsertIndex(d.rules, simulator.result, action), 0, rule);
    });
    selectedRuleIndexes.clear();
    rerender(root);
    pinCaseRemediationResult(ruleName, action);
    toast(allow ? "Allow rule staged" : "Drop rule staged", `${ruleName} is in the candidate. Validate and commit to enforce.`, "ok");
  } catch (e) {
    toast("Could not stage rule", e.message, "bad");
  }
}

function pinCaseRemediationResult(ruleName = "", action = "") {
  if (!caseContext.caseKey || !ruleName) return;
  try {
    pinInvestigationPacket(candidateRuleRemediationPacket(ruleName, action));
  } catch (e) {
    toast("Case custody pin failed", e.message || "The staged rule was saved, but custody evidence could not be pinned.", "warn");
  }
}

function candidateRuleRemediationPacket(ruleName = "", action = "") {
  const status = session.candidateStatus || {};
  const query = simulationExplainRequest();
  return buildInvestigationPacket({
    kind: "candidate-remediation",
    title: "Candidate rule remediation staged",
    subject: {
      id: ruleName,
      label: `${fmt.ruleAction(action).label} rule staged from case`,
      tuple: {
        srcIp: query.srcIp || "",
        srcPort: query.srcPort || "",
        destIp: query.destIp || "",
        destPort: query.destPort || "",
        protocol: query.protocol || "",
        appId: query.appId || "",
        fromZone: query.fromZone || "",
        toZone: query.toZone || "",
      },
    },
    summary: {
      caseKey: caseContext.caseKey,
      caseAction: caseContext.caseAction,
      caseKind: caseContext.caseKind,
      ruleName,
      action: fmt.ruleAction(action).label,
      candidateDirty: Boolean(status.dirty ?? session.dirty),
      candidateChangeCount: Number(status.changeCount ?? session.serverChangeCount()) || 0,
      changesRoute: "#/changes?tab=candidate",
      sourcePolicy: query.policySource || "",
      matchedRule: simulator.result?.matchedRule || "",
      decision: explainDecisionLabel(simulator.result),
      verdict: explainLabel(simulator.result?.verdict, "EXPLAIN_VERDICT_"),
    },
    evidence: [
      "candidate rule staged from investigation case handoff",
      `case key: ${caseContext.caseKey}`,
      `rule: ${ruleName}`,
      `action: ${fmt.ruleAction(action).label}`,
      `candidate changes: ${Number(status.changeCount ?? session.serverChangeCount()) || 0}`,
      "review in Changes before commit",
    ],
    artifacts: {
      caseContext,
      query,
      result: simulator.result || {},
      candidateStatus: {
        dirty: Boolean(status.dirty ?? session.dirty),
        changeCount: Number(status.changeCount ?? session.serverChangeCount()) || 0,
        changes: Array.isArray(status.changes) ? status.changes.slice(0, 12) : [],
      },
    },
  }, {
    route: "#/changes?tab=candidate",
  });
}

function pinPrefilledCaseRemediation(rule = {}, opts = {}) {
  const context = prefilledCaseContext(opts);
  if (!context.caseKey || !rule.name) return;
  try {
    pinInvestigationPacket(prefilledRuleRemediationPacket(rule, opts, context));
  } catch (e) {
    toast("Case custody pin failed", e.message || "The staged rule was saved, but custody evidence could not be pinned.", "warn");
  }
}

function prefilledCaseContext(opts = {}) {
  const context = opts.caseContext || {};
  return {
    caseKey: safeRouteToken(context.caseKey, 160),
    caseAction: safeRouteToken(context.caseAction, 80),
    caseKind: safeRouteToken(context.caseKind, 80),
    sourceWorkspace: safeRouteToken(context.sourceWorkspace, 40),
    mode: safeRouteToken(context.mode, 80),
    source: context.source && typeof context.source === "object" ? { ...context.source } : {},
  };
}

function prefilledRuleRemediationPacket(rule = {}, opts = {}, context = prefilledCaseContext(opts)) {
  const status = session.candidateStatus || {};
  const action = fmt.ruleAction(rule.action).label;
  const pendingApplications = (opts.pendingApplications || []).filter((app) => app?.name);
  const applicationName = pendingApplications[0]?.name || context.source.appId || (Array.isArray(rule.applications) ? rule.applications[0] : "") || "";
  return buildInvestigationPacket({
    kind: "candidate-remediation",
    title: "Candidate rule remediation staged",
    subject: {
      id: rule.name || context.caseKey,
      label: `${action} rule staged from ${context.sourceWorkspace || "owner workspace"}`,
      tuple: {
        srcIp: context.source.srcIp || "",
        srcPort: context.source.srcPort || "",
        destIp: context.source.destIp || "",
        destPort: context.source.destPort || "",
        protocol: context.source.protocol || "",
        appId: context.source.appId || "",
      },
    },
    summary: {
      caseKey: context.caseKey,
      caseAction: context.caseAction,
      caseKind: context.caseKind,
      sourceWorkspace: context.sourceWorkspace,
      mode: context.mode,
      ruleName: rule.name || "",
      applicationName,
      action,
      pendingApplicationCount: pendingApplications.length,
      candidateDirty: Boolean(status.dirty ?? session.dirty),
      candidateChangeCount: Number(status.changeCount ?? session.serverChangeCount()) || 0,
      changesRoute: "#/changes?tab=candidate",
    },
    evidence: [
      "candidate rule staged from investigation case owner handoff",
      `case key: ${context.caseKey}`,
      context.sourceWorkspace ? `owner workspace: ${context.sourceWorkspace}` : "",
      context.mode ? `mode: ${context.mode}` : "",
      `rule: ${rule.name || ""}`,
      `action: ${action}`,
      `candidate changes: ${Number(status.changeCount ?? session.serverChangeCount()) || 0}`,
      "review in Changes before commit",
    ],
    artifacts: {
      caseContext: context,
      rule,
      application: applicationName ? { name: applicationName } : null,
      pendingApplications,
      candidateStatus: {
        dirty: Boolean(status.dirty ?? session.dirty),
        changeCount: Number(status.changeCount ?? session.serverChangeCount()) || 0,
        changes: Array.isArray(status.changes) ? status.changes.slice(0, 12) : [],
      },
    },
  }, {
    route: "#/changes?tab=candidate",
  });
}

function ensureAddressObject(policy, ip, prefix) {
  const cidr = ipToCidr(ip);
  const existing = (policy.addresses || []).find((a) => a.cidr === cidr);
  if (existing) return existing.name;
  if (!policy.addresses) policy.addresses = [];
  const name = uniqueName(policy.addresses, sanitizeName(`${prefix}-${ip.replace("/", "-")}`));
  policy.addresses.push({
    name,
    cidr,
    description: `Created from Rules flow check for ${ip}.`,
  });
  return name;
}

function ensureServiceObject(policy, protocol, portValue) {
  if (protocol === "PROTOCOL_ANY") return "any";
  if (protocol === "PROTOCOL_ICMP") return ensureProtocolService(policy, "icmp", "PROTOCOL_ICMP");
  const port = numberOrZero(portValue);
  if (!port) return "any";
  const existing = (policy.services || []).find((s) =>
    s.protocol === protocol &&
    (s.ports || []).length === 1 &&
    Number(s.ports[0].start) === port &&
    Number(s.ports[0].end || 0) === 0);
  if (existing) return existing.name;
  if (!policy.services) policy.services = [];
  const name = uniqueName(policy.services, sanitizeName(`${protocol.replace("PROTOCOL_", "").toLowerCase()}-${port}`));
  policy.services.push({
    name,
    protocol,
    ports: [{ start: port }],
    description: `Created from Rules flow check for ${protocol.replace("PROTOCOL_", "").toLowerCase()} destination port ${port}.`,
  });
  return name;
}

function ensureProtocolService(policy, base, protocol) {
  const existing = (policy.services || []).find((s) => s.protocol === protocol && !(s.ports || []).length);
  if (existing) return existing.name;
  if (!policy.services) policy.services = [];
  const name = uniqueName(policy.services, sanitizeName(base));
  policy.services.push({ name, protocol, ports: [], description: "Created from Rules flow check." });
  return name;
}

function recommendedInsertIndex(rules, result, action) {
  const idx = Number(result?.matchedRuleIndex);
  if (result?.matchedRule && Number.isInteger(idx) && idx >= 0 && idx <= rules.length) return idx;
  return action === "ACTION_DENY" ? 0 : rules.length;
}

function flowRuleDescription(action) {
  const proto = explainLabel(simulator.protocol, "PROTOCOL_");
  const port = simulator.destPort ? `:${simulator.destPort}` : "";
  return `Created from Flow check to ${action === "ACTION_ALLOW" ? "allow" : "drop"} ${proto} ${simulator.srcIp} to ${simulator.destIp}${port}.`;
}

function ipToCidr(ip) {
  const value = String(ip || "").trim();
  if (value.includes("/")) return value;
  return value + (value.includes(":") ? "/128" : "/32");
}

function sanitizeName(value) {
  let out = String(value || "rule").toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
  if (!out) out = "rule";
  if (!/^[a-z0-9]/.test(out)) out = "r-" + out;
  out = out.slice(0, 63).replace(/[-_]+$/g, "");
  if (!/[a-z0-9]$/.test(out)) out += "1";
  return out || "rule";
}

function simList(title, lines = [], cls = "", profile = "") {
  const attrs = { class: "sim-list " + cls };
  if (profile) attrs["data-flow-check-profile"] = profile;
  return h("div", attrs,
    h("span", {}, title),
    lines.length ? h("ol", {}, lines.slice(0, 4).map((line) => h("li", {}, line))) : h("div", { class: "note" }, "No entries."));
}

function inspectionProfileLines(p) {
  if (!p) return [];
  const lines = [];
  if (p.failureBehavior) lines.push("failure behavior: " + explainLabel(p.failureBehavior, "IDS_FAILURE_BEHAVIOR_"));
  if (p.flowOffloadEnabled) lines.push("flow offload enabled");
  if (p.bypassReason) lines.push("bypass: " + p.bypassReason);
  if (p.degradedBehavior) lines.push("degraded: " + p.degradedBehavior);
  if (p.inspectionOrder) lines.push("order: " + p.inspectionOrder);
  return lines;
}

function routeLabel(r) {
  if (!r) return "unknown";
  if (!r.evaluated) return "not evaluated";
  if (r.matched) return r.destination || "matched";
  return "unresolved";
}

function routeProfileLines(r) {
  if (!r) return [];
  const lines = [];
  if (r.reason) lines.push(r.reason);
  if (r.source) lines.push("source: " + r.source);
  if (r.destination) lines.push("destination: " + r.destination);
  if (r.metric) lines.push("metric: " + r.metric);
  return lines;
}

function openTroubleshoot(c, opts = {}) {
  rememberSimulation(c);
  simulatorQueryActive = true;
  syncRoute();
  openTroubleshootFromCurrentSimulation(opts);
}

function openTroubleshootFromCurrentSimulation(opts = {}) {
  location.hash = rulesTroubleshootHash(simulator, opts);
}

function input(type, value, placeholder) {
  return h("input", { class: "input", type, value, placeholder, min: type === "number" ? "0" : null, max: type === "number" ? "65535" : null });
}

function select(options, value) {
  const el = h("select", {}, options.map(([v, label]) => h("option", { value: v }, label)));
  el.value = value;
  return el;
}

function numberOrZero(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.trunc(n) : 0;
}

function explainLabel(v, prefix) {
  return String(v || "unspecified").replace(prefix, "").replaceAll("_", " ").toLowerCase();
}

function explainDecisionLabel(result = {}) {
  if (result?.decisionSummary) return result.decisionSummary;
  const terms = Array.isArray(result?.decisionTerms) ? result.decisionTerms : [];
  return terms
    .map((term) => explainLabel(term, "EXPLAIN_DECISION_TERM_").replace(/\bfail open\b/g, "fail-open").replace(/\bfail closed\b/g, "fail-closed"))
    .filter(Boolean)
    .join(", ");
}

function explainVerdictClass(v) {
  if (v === "EXPLAIN_VERDICT_ALLOWED") return "ok";
  if (v === "EXPLAIN_VERDICT_DENIED" || v === "EXPLAIN_VERDICT_REJECTED" || v === "EXPLAIN_VERDICT_DEFAULT_DROP") return "bad";
  return "warn";
}

function explainInspectionClass(v) {
  if (v === "EXPLAIN_INSPECTION_STATE_IDS_DETECT" || v === "EXPLAIN_INSPECTION_STATE_IPS_PREVENT") return "info";
  if (v === "EXPLAIN_INSPECTION_STATE_NOT_INSPECTED") return "warn";
  if (v === "EXPLAIN_INSPECTION_STATE_BLOCKED_BEFORE_INSPECTION") return "neutral";
  return "neutral";
}

function matchFilter(r, idx, shadowedBy, policy = {}, change = null, filterState = filter) {
  if (filterState.changed && !change) return false;
  if (filterState.action && r.action !== filterState.action) return false;
  if (filterState.zone && !(r.fromZones || []).includes(filterState.zone) && !(r.toZones || []).includes(filterState.zone)) return false;
  if (filterState.tag && !(r.tags || []).includes(filterState.tag)) return false;
  if (filterState.q) {
    if (filterState.q === "shadowed") return shadowedBy != null;
    if (filterState.q === "disabled") return !ruleActive(r);
    if (filterState.q === "broad-allow") return ruleActive(r) && ruleAllows(r) && broadRule(r);
    if (filterState.q === "bypass-risk") return ruleActive(r) && ruleAllows(r) && ruleInspectionCoverage(policy, r).bypassPossible;
    if (filterState.q === "missing-log") return ruleActive(r) && r.log !== true;
    if (filterState.q === "server-overlap") return ruleValidationCleanup(ruleValidationState.findings, (session.draft.rules || []).length).overlaps.includes(idx);
    if (filterState.q === "zero-hit") {
      const counter = runningCounters.get("rule:" + (r?.name || ""));
      return countersAvailable && ruleActive(r) && counter && fmt.num(counter.packets) === 0 && fmt.num(counter.bytes) === 0;
    }
    const coverage = ruleInspectionCoverage(policy, r);
    const hay = [r.name, r.description, ...(r.fromZones || []), ...(r.toZones || []),
      ...(r.sourceAddresses || []), ...(r.destinationAddresses || []), ...(r.services || []), ...(r.applications || []), ...(r.securityProfiles || []), r.qosProfile || "", ...(r.tags || []),
      ...ruleMatchContextValues(r.matchContext),
      coverage.label, coverage.detail].join(" ").toLowerCase();
    if (!hay.includes(filterState.q)) return false;
  }
  return true;
}

function visibleRuleRowsForFilter(policy = session.draft || {}, filterState = filter) {
  const rules = policy.rules || [];
  const shadowOf = computeShadows(rules);
  const changeModel = ruleChangeModel(session.running?.rules || [], rules);
  return rules
    .map((rule, idx) => ({ rule, idx, shadowedBy: shadowOf[idx], change: ruleChangeForIndex(changeModel, idx) }))
    .filter(({ rule, idx, shadowedBy, change }) => matchFilter(rule, idx, shadowedBy, policy, change, filterState));
}

function changedCandidateRuleRows(rules = [], changeModel = {}) {
  return (Array.isArray(rules) ? rules : [])
    .map((rule, idx) => ({ rule, idx, change: ruleChangeForIndex(changeModel, idx) }))
    .filter(({ rule, change }) => ruleVerificationKey(rule, change));
}

function renderTable(wrap, root) {
  clear(wrap);
  const policy = session.draft || {};
  const rules = policy.rules || [];
  const changeModel = ruleChangeModel(session.running?.rules || [], rules);
  const changeSummary = ruleChangeSummary(changeModel);
  const validationCleanup = ruleValidationCleanup(ruleValidationState.findings, rules.length);
  const verificationSummary = ruleVerificationSummary(changedCandidateRuleRows(rules, changeModel), ruleVerificationState, {
    removed: changeModel.removed?.length || 0,
  });
  pruneRuleSelection(rules.length);
  wrap.className = "table-wrap rules-table-wrap rules-density-" + tableDensity;
  if (!rules.length) {
    wrap.appendChild(ruleBulkToolbar([], 0, root, { changeSummary, verificationSummary, removedRules: changeModel.removed }));
    wrap.appendChild(emptyState("rules", "No rules yet", "Add your first rule. Rules are evaluated top-to-bottom; the first match wins.",
      h("div", { class: "flex wrap rules-empty-actions" },
        policyNeedsBaseline(session.draft) ? h("button", { class: "btn primary", ...actionControlAttrs({ rulesAction: "setup-baseline-empty" }, "Set up baseline policy", { onclick: () => openBaselineSetup(root) }) }, h("span", { html: icon("shield", 16) }), "Set up baseline") : null,
        h("button", { class: policyNeedsBaseline(session.draft) ? "btn" : "btn primary", ...actionControlAttrs({ rulesAction: "add-rule-empty" }, "Add security rule", { onclick: () => openRuleEditor(null) }) }, h("span", { html: icon("plus", 16) }), "Add rule"))));
    maybeOpenRouteReviewDrawer(root, []);
    return;
  }
  const shadowOf = computeRuleHygiene(rules, runningCounters, countersAvailable, policy).shadowOf;
  const visibleRows = rules
    .map((rule, idx) => ({ rule, idx, shadowedBy: shadowOf[idx], change: ruleChangeForIndex(changeModel, idx) }))
    .filter(({ rule, idx, shadowedBy, change }) => matchFilter(rule, idx, shadowedBy, policy, change, filter));
  const grouped = tableGroup !== DEFAULT_GROUP;
  const reorderEnabled = canReorderRuleRows(filter, selectedRuleIndexes.size, tableGroup);
  wrap.appendChild(ruleBulkToolbar(visibleRows, rules.length, root, { grouped, changeSummary, verificationSummary, removedRules: changeModel.removed }));
  wrap.appendChild(ruleLargeRulebasePosturePanel(ruleLargeRulebasePosture(policy, visibleRows, selectedRuleIndexList(), ruleValidationState, validationCleanup, {
    filter,
    group: tableGroup,
    targetSnapshotToken: routeBulkTargets,
  })));
  const scaleReview = ruleTableScaleReview(rules.length, visibleRows.length, selectedRuleIndexes.size, filter, tableGroup);
  if (scaleReview) wrap.appendChild(ruleTableScaleReviewBanner(scaleReview));
  if (!visibleRows.length) {
    wrap.appendChild(emptyState("search", "No matching rules", "Clear the filters or search for a different rule attribute."));
    maybeOpenRouteReviewDrawer(root, []);
    return;
  }
  const head = h("tr", {},
    h("th", { class: "rules-select-col" }, selectVisibleCheckbox(visibleRows, root)),
    h("th", { class: "rules-index-col" }, "#"),
    h("th", { class: "rules-enabled-col" }, "On"),
    h("th", {}, "Name"),
    h("th", {}, "Tags"),
    h("th", {}, "From → To"),
    h("th", {}, "Source"),
    h("th", {}, "Destination"),
    h("th", {}, "Service"),
    h("th", {}, "App-ID"),
    h("th", {}, "Identity / posture"),
    h("th", {}, "Profiles"),
    h("th", {}, "QoS"),
    h("th", {}, "Inspection"),
    h("th", {}, "Action"),
    h("th", { class: "rules-hits-col" }, "Running hits"),
    h("th", { class: `rules-actions-col ${reorderEnabled ? "reorder-enabled" : ""}` }, ""));
  const body = h("tbody", {});
  for (const group of groupRuleRows(visibleRows, tableGroup)) {
    if (grouped) body.appendChild(ruleGroupRow(group, root));
    group.rows.forEach(({ rule, idx, shadowedBy, change }) => {
      body.appendChild(ruleRow(rule, idx, shadowedBy, root, { reorderEnabled, change, ruleCount: rules.length }));
    });
  }
  wrap.appendChild(h("table", { class: `rules-table ${tableDensity === "compact" ? "compact" : ""}` }, h("thead", {}, head), body));
  if (reorderEnabled) enableDnD(body, root);
  maybeOpenRouteReviewDrawer(root, visibleRows);
}

function ruleTableScaleReviewBanner(model = {}) {
  return h("div", { class: "alert-box info rule-scale-review", dataset: { ruleScaleReview: model.state || "large-rulebase" } },
    h("strong", {}, "Large rulebase review"),
    h("div", { class: "rule-scale-review-counts" },
      `visible=${fmt.num(model.visible || 0)} total=${fmt.num(model.total || 0)} selected=${fmt.num(model.selected || 0)}`),
    h("ul", { class: "rule-scale-review-list" },
      (model.warnings || []).map((warning) => h("li", {}, warning))));
}

function ruleLargeRulebasePosturePanel(model = {}) {
  const validationLabel = !model.validationSnapshot?.checked
    ? "validation not run"
    : model.validationSnapshot.current ? "validation current" : "validation stale";
  const targetLabel = model.targetSnapshot?.checked
    ? model.targetSnapshot.ok ? "target snapshot current" : "target snapshot stale"
    : "no route target snapshot";
  const overlap = model.overlap || {};
  return h("div", { class: "alert-box info rule-large-posture", dataset: { ruleLargePosture: model.identityMode || "empty" } },
    h("div", { class: "rule-scale-review-counts" },
      `total=${fmt.num(model.total || 0)} visible=${fmt.num(model.visible || 0)} hidden=${fmt.num(model.hidden || 0)} selected=${fmt.num(model.selected || 0)}`,
      model.selectedHidden ? ` selected-hidden=${fmt.num(model.selectedHidden)}` : ""),
    h("div", { class: "rule-scale-review-counts" },
      `identity=${model.identityMode || "empty"} durable=${fmt.num(model.durableCount || 0)} fallback=${fmt.num(model.fallbackCount || 0)} - ${targetLabel} - ${validationLabel}`),
    h("div", { class: "rule-scale-review-counts" },
      `overlap-cap=${fmt.num(overlap.limit || SERVER_OVERLAP_FINDING_LIMIT)} findings=${fmt.num(overlap.findingCount || 0)} page=${overlap.pageKey || "none"}${overlap.mayBeTruncated ? " truncated" : ""}${overlap.hasMore ? ` next=${fmt.num(overlap.nextOffset || 0)}` : ""}`),
    h("ul", { class: "rule-scale-review-list" },
      [...(model.coverage || []), ...(model.omitted || [])].map((item) => h("li", {}, item))));
}

function hasActiveRuleFilter() {
  return ruleTableHasActiveFilter(filter);
}

function pruneRuleSelection(ruleCount) {
  selectedRuleIndexes = new Set([...selectedRuleIndexes].filter((idx) => Number.isInteger(idx) && idx >= 0 && idx < ruleCount));
}

function selectedRuleIndexList() {
  return [...selectedRuleIndexes].sort((a, b) => a - b);
}

function visibleRuleIndexList(visibleRows = []) {
  return visibleRows.map(({ idx }) => idx).filter((idx) => Number.isInteger(idx));
}

function maybeOpenRouteReviewDrawer(root, visibleRows = []) {
  const drawer = normalizeRuleReviewDrawer(activeRuleReviewDrawer);
  if (!drawer) return;
  const visibleIndexes = visibleRuleIndexList(visibleRows);
  const routeSnapshot = bulkRuleTargetSnapshotFromToken(routeBulkTargets);
  const routeIndexes = routeSnapshot ? bulkRuleTargetSnapshotStatus(session.draft, routeBulkTargets).indexes : visibleIndexes;
  const key = JSON.stringify({ drawer, tag: routeBulkTag, targets: routeBulkTargets, visibleIndexes, filter, density: tableDensity, group: tableGroup });
  if (autoOpenedRuleReviewDrawer === key) return;
  autoOpenedRuleReviewDrawer = key;
  queueMicrotask(() => {
    if (normalizeRuleReviewDrawer(activeRuleReviewDrawer) !== drawer) return;
    if (drawer === "verify-changed") {
      openChangedRuleVerificationDrawer(root, { routeBacked: true });
      return;
    }
    if (drawer === "server-overlap-review") {
      const cleanup = ruleValidationCleanup(ruleValidationState.findings, (session.draft.rules || []).length);
      const hygiene = computeRuleHygiene(session.draft.rules || [], runningCounters, countersAvailable, session.draft || {}, cleanup);
      const finding = hygiene.findings.find((item) => item.fix === "review-overlap");
      if (finding) openServerOverlapReviewDrawer(root, finding, visibleRows, { routeBacked: true });
      return;
    }
    selectedRuleIndexes = new Set(routeIndexes);
    if (drawer === "bulk-tag-add" || drawer === "bulk-tag-remove") {
      openBulkTagDrawer(drawer === "bulk-tag-remove" ? "remove" : "add", root, visibleRows, {
        routeBacked: true,
        indexes: routeIndexes,
        tag: routeBulkTag || filter.tag || "",
        bulkTargets: routeBulkTargets,
      });
      return;
    }
    openBulkActionReview(BULK_REVIEW_DRAWER_ACTIONS[drawer], root, visibleRows, {
      routeBacked: true,
      indexes: routeIndexes,
      drawer,
      bulkTargets: routeBulkTargets,
    });
  });
}

function selectHygieneRuleSet(finding = {}, root, opts = {}) {
  const ruleCount = (session.draft.rules || []).length;
  const indexes = normalizedRuleIndexes(finding.indexes || [], ruleCount);
  if (!indexes.length) {
    if (finding.filter) setRuleFilter(finding.filter);
    return;
  }
  const nextFilter = { ...DEFAULT_FILTER, ...(finding.filter || {}) };
  filter = nextFilter;
  selectedRuleIndexes = new Set(indexes);
  syncRoute();
  const visibleRows = visibleRuleRowsForFilter(session.draft || {}, nextFilter);
  const targetRoot = root || document.querySelector("#content > div");
  if (targetRoot) rerender(targetRoot);
  if (opts.reviewAction && targetRoot) {
    openBulkActionReview(opts.reviewAction, targetRoot, visibleRows);
    return;
  }
  toast("Rule set selected", `${indexes.length} rule${indexes.length === 1 ? "" : "s"} selected for review.`, "info");
}

function selectVisibleCheckbox(visibleRows, root) {
  const visibleIndexes = visibleRows.map(({ idx }) => idx);
  const selectedVisible = visibleIndexes.filter((idx) => selectedRuleIndexes.has(idx)).length;
  const input = h("input", {
    type: "checkbox",
    title: "Select visible rules",
    "aria-label": "Select visible rules",
    dataset: { ruleSelect: "visible" },
    onclick: (e) => e.stopPropagation(),
    onchange: (e) => {
      if (e.target.checked) visibleIndexes.forEach((idx) => selectedRuleIndexes.add(idx));
      else visibleIndexes.forEach((idx) => selectedRuleIndexes.delete(idx));
      rerender(root);
    },
  });
  input.checked = visibleIndexes.length > 0 && selectedVisible === visibleIndexes.length;
  input.indeterminate = selectedVisible > 0 && selectedVisible < visibleIndexes.length;
  return h("label", { class: "rule-select", title: "Select visible rules" }, input);
}

function ruleBulkToolbar(visibleRows, totalRules, root, opts = {}) {
  const selected = selectedRuleIndexList();
  const selectedVisible = visibleRows.filter(({ idx }) => selectedRuleIndexes.has(idx)).length;
  const filterActive = hasActiveRuleFilter();
  const grouped = Boolean(opts.grouped);
  const changes = opts.changeSummary || ruleChangeSummary();
  const verification = opts.verificationSummary || ruleVerificationSummary();
  const removedRules = Array.isArray(opts.removedRules) ? opts.removedRules : [];
  const detail = selected.length
    ? `${selected.length} selected${selectedVisible !== selected.length ? ` · ${selectedVisible} visible` : ""}`
    : `${visibleRows.length}/${totalRules} visible`;
  return h("div", { class: "rule-bulk-toolbar", dataset: { ruleBulkToolbar: "true" } },
    h("div", {},
      h("strong", {}, "Rule operations"),
      h("span", { class: "muted" }, detail),
      h("span", { class: "rule-change-summary", dataset: { ruleChangeSummary: "true" } }, changes.label),
      changes.total ? h("span", { class: "muted", dataset: { ruleVerificationSummary: "true" } }, verification.label) : null,
      removedRules.length ? h("span", { class: "rule-removed-list", title: removedRules.map((item) => item.name).join(", ") },
        `Removed: ${removedRules.slice(0, 3).map((item) => item.name).join(", ")}${removedRules.length > 3 ? ` +${removedRules.length - 3}` : ""}`) : null,
      filterActive || selected.length || grouped ? h("span", { class: "muted" }, "Drag reorder is paused while filtered, grouped, or selecting.") : null),
    h("div", { class: "rule-bulk-actions" },
      h("label", { class: "rule-change-toggle", title: "Show only added, modified, or moved candidate rules", dataset: { ruleBulkAction: "changed-only" } },
        h("input", {
          type: "checkbox",
          checked: filter.changed,
          disabled: !changes.total && !filter.changed,
          onchange: (e) => {
            updateRuleFilter({ changed: e.target.checked });
            rerender(root);
          },
        }),
        h("span", {}, "Changed only")),
      h("button", { class: "btn sm", ...actionControlAttrs({ ruleBulkAction: "verify-changed" }, "Verify changed rules", { disabled: !verification.total || verifyingChangedRules, onclick: () => {
        setRuleReviewDrawerRoute("verify-changed");
        openChangedRuleVerificationDrawer(root, { routeBacked: true });
      } }) },
        h("span", { html: icon("search", 15) }),
        verifyingChangedRules ? "Verifying..." : "Verify changed"),
      h("button", { class: "btn sm ghost", ...actionControlAttrs({ ruleBulkAction: "select-visible" }, "Select visible rules", { disabled: visibleRows.length === 0, onclick: () => {
        visibleRows.forEach(({ idx }) => selectedRuleIndexes.add(idx));
        rerender(root);
      } }) }, "Select visible"),
      h("button", { class: "btn sm ghost", ...actionControlAttrs({ ruleBulkAction: "clear" }, "Clear selected rules", { disabled: !selected.length, onclick: () => {
        selectedRuleIndexes.clear();
        rerender(root);
      } }) }, "Clear"),
      h("button", { class: "btn sm", ...actionControlAttrs({ ruleBulkAction: "enable" }, "Enable selected rules", { disabled: !selected.length, onclick: () => applyBulkDisabled(false, root, visibleRows) }) },
        h("span", { html: icon("check", 15) }), "Enable"),
      h("button", { class: "btn sm", ...actionControlAttrs({ ruleBulkAction: "disable" }, "Disable selected rules", { disabled: !selected.length, onclick: () => applyBulkDisabled(true, root, visibleRows) }) },
        h("span", { html: icon("block", 15) }), "Disable"),
      h("button", { class: "btn sm", ...actionControlAttrs({ ruleBulkAction: "log-on" }, "Enable logging on selected rules", { disabled: !selected.length, onclick: () => applyBulkLog(true, root, visibleRows) }) },
        h("span", { html: icon("inbox", 15) }), "Log on"),
      h("button", { class: "btn sm", ...actionControlAttrs({ ruleBulkAction: "log-off" }, "Disable logging on selected rules", { disabled: !selected.length, onclick: () => applyBulkLog(false, root, visibleRows) }) },
        h("span", { html: icon("x", 15) }), "Log off"),
      h("button", { class: "btn sm", ...actionControlAttrs({ ruleBulkAction: "add-tag" }, "Add tag to selected rules", { disabled: !selected.length, onclick: () => openBulkTagDrawer("add", root, visibleRows) }) },
        h("span", { html: icon("plus", 15) }), "Add tag"),
      h("button", { class: "btn sm", ...actionControlAttrs({ ruleBulkAction: "remove-tag" }, "Remove tag from selected rules", { disabled: !selected.length, onclick: () => openBulkTagDrawer("remove", root, visibleRows) }) },
        h("span", { html: icon("trash", 15) }), "Remove tag")));
}

function ruleGroupRow(group, root) {
  const indexes = (group.rows || []).map(({ idx }) => idx);
  const selectedCount = indexes.filter((idx) => selectedRuleIndexes.has(idx)).length;
  return h("tr", { class: "rule-group-row", dataset: { rulePosition: "", ruleName: group.label, ruleGroup: group.key || group.label } },
    h("td", { colspan: String(RULE_TABLE_COLUMN_COUNT) },
      h("div", { class: "rule-group-label" },
        groupSelectionCheckbox(indexes, root),
        h("strong", {}, group.label),
        h("span", { class: "muted" }, `${group.rows.length} rule${group.rows.length === 1 ? "" : "s"}`),
        selectedCount ? h("span", { class: "muted" }, `${selectedCount} selected`) : null,
        h("small", {}, group.detail || "Grouped review lens."))));
}

function groupSelectionCheckbox(indexes = [], root) {
  const selectedCount = indexes.filter((idx) => selectedRuleIndexes.has(idx)).length;
  const input = h("input", {
    type: "checkbox",
    title: "Select this visible rule group",
    "aria-label": "Select this visible rule group",
    dataset: { ruleSelect: "group" },
    onclick: (e) => e.stopPropagation(),
    onchange: (e) => {
      if (e.target.checked) indexes.forEach((idx) => selectedRuleIndexes.add(idx));
      else indexes.forEach((idx) => selectedRuleIndexes.delete(idx));
      rerender(root);
    },
  });
  input.checked = indexes.length > 0 && selectedCount === indexes.length;
  input.indeterminate = selectedCount > 0 && selectedCount < indexes.length;
  return h("label", { class: "rule-select", title: "Select this visible group", onclick: (e) => e.stopPropagation() }, input);
}

function applyBulkDisabled(disabled, root, visibleRows = []) {
  openBulkActionReview({ kind: "disabled", disabled }, root, visibleRows, { routeBacked: true });
}

function applyBulkLog(log, root, visibleRows = []) {
  openBulkActionReview({ kind: "log", log }, root, visibleRows, { routeBacked: true });
}

function openChangedRuleVerificationDrawer(root, opts = {}) {
  const changeModel = ruleChangeModel(session.running?.rules || [], session.draft?.rules || []);
  const rows = changedCandidateRuleRows(session.draft?.rules || [], changeModel);
  const summary = ruleVerificationSummary(rows, ruleVerificationState, { removed: changeModel.removed?.length || 0 });
  const drawer = "verify-changed";
  openDrawer({
    title: "Verify changed rules",
    subtitle: `${summary.label} · candidate explain-flow evidence`,
    width: "860px",
    body: ruleVerificationDrawerBody(rows, changeModel),
    footer: [
      h("button", { class: "btn", ...actionControlAttrs({ ruleReviewAction: "copy-context" }, "Copy changed rule verification context", { onclick: () => copyRuleReviewContext({
        title: "Changed rule verification",
        drawer,
        routeHash: ruleReviewRouteHash(drawer),
        targetCount: summary.total,
        changeCount: summary.pending,
        blockedCount: summary.unverifiable + summary.error,
        action: "Verify changed rules against candidate explain-flow",
        notes: [
          "Changed-rule verification uses durable rule IDs when present and candidate explain-flow evidence.",
          "Removed rules, duplicate names, reordered rules, and broad rules without concrete tuples require manual commit-review context.",
        ],
        commands: ruleCandidateReviewCommands({ explain: true }),
      }) }) }, h("span", { html: icon("copy", 16) }), "Copy review context"),
      h("button", { class: "btn ghost", ...actionControlAttrs({ ruleReviewAction: "close" }, "Close changed rule verification drawer", { onclick: closeDrawer }) }, "Close"),
      h("button", { class: "btn primary", ...actionControlAttrs({ ruleVerificationAction: "run" }, "Run changed rule verification", { disabled: !rows.length || verifyingChangedRules, onclick: () => runChangedRuleVerification(root) }) },
        h("span", { html: icon("search", 16) }),
        verifyingChangedRules ? "Verifying..." : "Run verification"),
    ],
    onClose: opts.routeBacked ? clearRuleReviewDrawerRoute : null,
  });
}

function openServerOverlapReviewDrawer(root, finding = {}, visibleRows = [], opts = {}) {
  const reviewModel = serverOverlapReviewModel(session.draft?.rules || [], finding, { visibleRows });
  const rows = reviewModel.rows;
  const indexes = normalizedRuleIndexes(finding.indexes || rows.map((row) => row.index), (session.draft.rules || []).length);
  const visible = new Set(visibleRuleIndexList(visibleRows));
  const overlapMeta = reviewModel.meta;
  const drawer = "server-overlap-review";
  openDrawer({
    title: "Review server rule overlaps",
    subtitle: `${rows.length} server finding${rows.length === 1 ? "" : "s"} · ${overlapMeta.mayBeTruncated ? "backend cap reached" : "first-match order decides verdict"}`,
    width: "860px",
    body: serverOverlapReviewBody(rows, visible, overlapMeta),
    footer: [
      h("button", { class: "btn", ...actionControlAttrs({ ruleReviewAction: "copy-context" }, "Copy server overlap review context", { onclick: () => copyRuleReviewContext({
        title: "Server rule overlap review",
        drawer,
        routeHash: ruleReviewRouteHash(drawer),
        targetCount: rows.length,
        visibleCount: rows.filter((row) => visible.has(row.index)).length,
        hiddenCount: rows.filter((row) => !visible.has(row.index)).length,
        changeCount: 0,
        blockedCount: 0,
        action: "Review server validation overlap findings before candidate cleanup",
        notes: [
          ...serverOverlapReviewNotes(overlapMeta, rows),
          ...ruleIdentityReviewNotes(session.draft || {}, indexes, visibleRows, { paginationRisk: true }),
        ],
        targets: rows.map((row) => ({
          index: row.index,
          position: row.index + 1,
          itemId: normalizedRuleId(row.rule),
          name: row.rule?.name || `Rule ${row.index + 1}`,
          visible: visible.has(row.index),
          before: "server overlap",
          after: `${row.detail || row.message || "review first-match order"}; confidence=${row.impact?.confidence?.label || "unknown"}`,
        })),
        commands: ruleCandidateReviewCommands(),
      }) }) }, h("span", { html: icon("copy", 16) }), "Copy review context"),
      h("button", { class: "btn", ...actionControlAttrs({ ruleOverlapAction: "api-cli" }, "Open API and CLI context for server overlap review", { onclick: () => openAutomationContext(ruleReviewRouteHash(drawer)) }) },
        h("span", { html: icon("terminal", 16) }), "API / CLI"),
      h("button", { class: "btn ghost", ...actionControlAttrs({ ruleOverlapAction: "close" }, "Close server overlap review drawer", { onclick: closeDrawer }) }, "Close"),
      h("button", { class: "btn", ...actionControlAttrs({ ruleOverlapAction: "enable-logging" }, "Enable logging for overlapped rules", { disabled: !indexes.length, onclick: () => openBulkActionReview({ kind: "log", log: true }, root, visibleRows, {
        routeBacked: opts.routeBacked,
        indexes,
        drawer: "bulk-log-on",
      }) }) }, h("span", { html: icon("inbox", 16) }), "Enable logging"),
      h("button", { class: "btn primary", ...actionControlAttrs({ ruleOverlapAction: "add-review-tag" }, "Add review tag to overlapped rules", { disabled: !indexes.length, onclick: () => openBulkTagDrawer("add", root, visibleRows, {
        routeBacked: opts.routeBacked,
        indexes,
        tag: "review:overlap",
      }) }) }, h("span", { html: icon("plus", 16) }), "Add review tag"),
    ],
    onClose: opts.routeBacked ? clearRuleReviewDrawerRoute : null,
  });
}

export function serverOverlapReviewModel(rules = [], finding = {}, opts = {}) {
  const candidateRules = Array.isArray(rules) ? rules : [];
  const visible = new Set(Array.isArray(opts.visibleIndexes)
    ? normalizedRuleIndexes(opts.visibleIndexes, candidateRules.length)
    : visibleRuleIndexList(opts.visibleRows || []));
  const byIndex = new Map((Array.isArray(finding.overlapFindings) ? finding.overlapFindings : []).map((item) => [Number(item.index), item]));
  const indexes = normalizedRuleIndexes(finding.indexes || [...byIndex.keys()], candidateRules.length);
  const rows = indexes.map((index) => {
    const evidence = byIndex.get(index) || {};
    const rule = candidateRules[index] || {};
    const impact = evidence.serverOverlap
      ? serverOverlapImpactForRule(candidateRules, index, evidence)
      : overlapImpactForRule(candidateRules, index, evidence);
    return {
      index,
      rule,
      visible: visible.has(index),
      code: evidence.code || "POLICY_HYGIENE_RULE_OVERLAP",
      fieldPath: evidence.fieldPath || `rules[${index}]`,
      message: evidence.message || "Rule overlaps another rule.",
      detail: evidence.detail || "Policy validation found partial match overlap; first-match order decides the verdict.",
      severity: evidence.severity || "",
      stage: evidence.stage || "",
      overlapResult: evidence.overlapResult || evidence.serverOverlap?.result || null,
      overlapPage: evidence.overlapPage || evidence.serverOverlap?.page || null,
      impact,
      peerRows: impact.peerRows || [],
      sharedDimensions: impact.sharedDimensions || [],
      representativeTuple: impact.representativeTuple || null,
      confidence: impact.confidence || null,
      riskLabels: impact.riskLabels || [],
      primaryRisk: impact.primaryRisk || null,
    };
  });
  return {
    rows,
    meta: serverOverlapReviewMeta(finding, rows),
  };
}

function serverOverlapReviewMeta(finding = {}, rows = []) {
  const firstPage = rows.map((row) => row.overlapPage).find(Boolean) || finding.overlapPage || null;
  const limit = Math.max(1, Number(firstPage?.limit || finding.overlapFindingLimit || SERVER_OVERLAP_FINDING_LIMIT));
  const mayBeTruncated = Boolean(firstPage?.truncated || finding.overlapFindingsMayBeTruncated || rows.length >= limit);
  const confidenceKeys = [...new Set(rows.map((row) => row.impact?.confidence?.key || "unresolved"))];
  return {
    limit,
    mayBeTruncated,
    pageKey: firstPage?.pageKey || "",
    totalResults: Number(firstPage?.totalResults || rows.length),
    resultCount: Number(firstPage?.resultCount || rows.length),
    hasMore: Boolean(firstPage?.hasMore),
    nextOffset: Number(firstPage?.nextOffset || 0),
    confidenceKeys,
    hasServerMetadata: confidenceKeys.includes("server-metadata"),
    hasDetailTextDerived: confidenceKeys.includes("detail-text"),
    hasUnresolvedPeers: confidenceKeys.includes("unresolved"),
  };
}

function serverOverlapReviewNotes(meta = {}, rows = []) {
  const notes = [];
  if (meta.mayBeTruncated) {
    notes.push(`Backend overlap validation returns at most ${meta.limit} findings; this review may be truncated and additional overlaps may exist.`);
  } else {
    notes.push(`Backend overlap validation returned ${rows.length} finding${rows.length === 1 ? "" : "s"} under the current ${meta.limit}-finding cap.`);
  }
  if (meta.hasDetailTextDerived) {
    notes.push("Some peer confidence is detail-text-derived: peer names came from server detail text, while dimensions and risk are recomputed from the current candidate.");
  }
  if (meta.hasServerMetadata) {
    notes.push("Server overlap metadata includes stable result identity, peer identity, dimension results, and bounded page/cap state for this validation run.");
  }
  if (meta.hasUnresolvedPeers) {
    notes.push("Some peers could not be resolved against the current candidate; rerun validation after refreshing candidate state.");
  }
  return notes;
}

export function serverOverlapImpactForRule(rules = [], index = -1, evidence = {}) {
  const result = evidence.overlapResult || evidence.serverOverlap?.result || {};
  const pagePeer = evidence.overlapPeer || evidence.serverOverlap?.peer || {};
  const peerIndex = Number.isFinite(Number(result.peerIndex)) ? Number(result.peerIndex) : Number(pagePeer.index);
  const laterIndex = Number.isFinite(Number(result.ruleIndex)) ? Number(result.ruleIndex) : index;
  const earlier = rules[peerIndex] || { name: result.peerName || pagePeer.name || "", id: result.peerId || pagePeer.id || "", action: result.peerAction || pagePeer.action || "" };
  const later = rules[laterIndex] || rules[index] || { name: result.ruleName || "", id: result.ruleId || "", action: result.ruleAction || "" };
  const dimensions = serverOverlapDimensions(evidence.overlapDimensions || evidence.serverOverlap?.dimensions || []);
  const risks = Array.isArray(result.riskLabels) && result.riskLabels.length ? result.riskLabels : overlapRiskFlags(earlier, later);
  const peer = {
    earlier,
    earlierIndex: Number.isFinite(peerIndex) ? peerIndex : -1,
    later,
    laterIndex: Number.isFinite(laterIndex) ? laterIndex : index,
    evidenceSource: "server-metadata",
    confidence: "high",
    confidenceLabel: "server-provided peer",
    dimensions,
    risks,
    riskLabels: risks.map((risk) => ({ key: risk, label: overlapRiskLabel(risk), cls: overlapRiskClass(risk) })),
    representative: representativeOverlapTuple(earlier, later),
  };
  const peers = [peer];
  const peerRows = peers.map((item) => overlapPeerStructuredRow(item));
  return {
    peers,
    peerRows,
    risks,
    riskLabels: risks.map((risk) => ({ key: risk, label: overlapRiskLabel(risk), cls: overlapRiskClass(risk) })),
    dimensions: dimensions.map((dimension) => dimension.key),
    sharedDimensions: overlapSharedDimensions(peers),
    representativeTuple: peerRows[0]?.representativeTuple || null,
    representativeTuples: peerRows.map((item) => item.representativeTuple).filter(Boolean),
    confidence: { key: "server-metadata", label: "server-provided", detail: "Peer, dimension, result identity, and cap state came from server validation metadata." },
    primaryRisk: overlapPrimaryRisk(risks, later),
    action: overlapRecommendedAction(risks, later, peers),
    result,
    page: evidence.overlapPage || evidence.serverOverlap?.page || null,
  };
}

function serverOverlapDimensions(dimensions = []) {
  const rows = (Array.isArray(dimensions) ? dimensions : []).map((dimension) => serverOverlapDimensionRow(dimension));
  const fromZones = rows.find((row) => row.sourceKey === "from-zones");
  const toZones = rows.find((row) => row.sourceKey === "to-zones");
  const normalized = [];
  if (fromZones || toZones) {
    normalized.push({
      key: "zones",
      label: "Zones",
      value: `${fromZones?.value || "any"} -> ${toZones?.value || "any"}`,
      confidence: "high",
      confidenceLabel: "server-provided dimension",
      evidenceSource: "server-metadata",
      result: [fromZones?.result, toZones?.result].filter(Boolean).join(",") || "overlap",
    });
  }
  for (const row of rows) {
    if (row.sourceKey === "from-zones" || row.sourceKey === "to-zones") continue;
    normalized.push(row);
  }
  return normalized;
}

function serverOverlapDimensionRow(dimension = {}) {
  const sourceKey = String(dimension?.key || "").trim() || "dimension";
  const keyMap = {
    "source-addresses": "source",
    "destination-addresses": "destination",
    services: "service",
    applications: "app-id",
    "security-profiles": "security-profile",
  };
  return {
    key: keyMap[sourceKey] || sourceKey,
    sourceKey,
    label: String(dimension?.label || sourceKey || "Dimension").trim(),
    value: serverOverlapDimensionValue(dimension),
    confidence: "high",
    confidenceLabel: "server-provided dimension",
    evidenceSource: "server-metadata",
    result: String(dimension?.result || "").trim(),
  };
}

function serverOverlapDimensionValue(dimension = {}) {
  const sample = String(dimension?.sample || "").trim();
  if (sample) return sample;
  const peer = Array.isArray(dimension?.peerValues) ? dimension.peerValues.filter(Boolean).join(", ") : "";
  const rule = Array.isArray(dimension?.ruleValues) ? dimension.ruleValues.filter(Boolean).join(", ") : "";
  if (peer && rule && peer !== rule) return `${peer} / ${rule}`;
  return peer || rule || "partial";
}

export function overlapImpactForRule(rules = [], index = -1, evidence = {}) {
  const later = rules[index] || {};
  const peers = [];
  for (let peerIndex = 0; peerIndex < index; peerIndex++) {
    const earlier = rules[peerIndex];
    if (!ruleActive(earlier) || !ruleActive(later) || !rulesOverlapForImpact(earlier, later)) continue;
    peers.push(overlapPeerImpact(earlier, peerIndex, later, index, {
      evidenceSource: "candidate-scan",
      confidence: "high",
      confidenceLabel: "candidate-derived peer",
    }));
  }
  if (!peers.length) {
    const names = overlapPeerNamesFromDetail(evidence.detail || evidence.message || "");
    for (const name of names) {
      const peerIndex = rules.findIndex((rule, idx) => idx !== index && rule?.name === name);
      if (peerIndex >= 0 && rulesOverlapForImpact(rules[peerIndex], later)) {
        peers.push(overlapPeerImpact(rules[peerIndex], peerIndex, later, index, {
          evidenceSource: "detail-text",
          confidence: "medium",
          confidenceLabel: "detail-text-derived peer",
        }));
      }
    }
  }
  const risks = [...new Set(peers.flatMap((peer) => peer.risks))];
  const dimensions = [...new Set(peers.flatMap((peer) => peer.dimensions.map((dimension) => dimension.key)))];
  const confidence = overlapImpactConfidence(peers);
  const peerRows = peers.map((peer) => overlapPeerStructuredRow(peer));
  const riskLabels = risks.map((risk) => ({ key: risk, label: overlapRiskLabel(risk), cls: overlapRiskClass(risk) }));
  const sharedDimensions = overlapSharedDimensions(peers);
  return {
    peers,
    peerRows,
    risks,
    riskLabels,
    dimensions,
    sharedDimensions,
    representativeTuple: peerRows[0]?.representativeTuple || null,
    representativeTuples: peerRows.map((peer) => peer.representativeTuple).filter(Boolean),
    confidence,
    primaryRisk: overlapPrimaryRisk(risks, later),
    action: overlapRecommendedAction(risks, later, peers),
  };
}

function overlapPeerNamesFromDetail(text = "") {
  const matches = String(text || "").match(/([A-Za-z0-9_.:-]+)\s+and\s+([A-Za-z0-9_.:-]+)/);
  return matches ? [matches[1], matches[2]].filter(Boolean) : [];
}

function overlapPeerImpact(earlier = {}, earlierIndex = -1, later = {}, laterIndex = -1, opts = {}) {
  const confidence = opts.confidence || "high";
  const evidenceSource = opts.evidenceSource || "candidate-scan";
  const confidenceLabel = opts.confidenceLabel || "candidate-derived peer";
  const dimensions = overlapDimensions(earlier, later).map((dimension) => ({
    ...dimension,
    confidence,
    confidenceLabel,
    evidenceSource,
  }));
  const risks = overlapRiskFlags(earlier, later);
  return {
    earlier,
    earlierIndex,
    later,
    laterIndex,
    evidenceSource,
    confidence,
    confidenceLabel,
    dimensions,
    risks,
    riskLabels: risks.map((risk) => ({ key: risk, label: overlapRiskLabel(risk), cls: overlapRiskClass(risk) })),
    representative: representativeOverlapTuple(earlier, later),
  };
}

function overlapPeerStructuredRow(peer = {}) {
  const riskLabels = (peer.risks || []).map((risk) => ({ key: risk, label: overlapRiskLabel(risk), cls: overlapRiskClass(risk) }));
  return {
    earlierIndex: peer.earlierIndex,
    laterIndex: peer.laterIndex,
    peerIndex: peer.earlierIndex,
    targetIndex: peer.laterIndex,
    peerName: peer.earlier?.name || `Rule ${Number(peer.earlierIndex) + 1}`,
    targetName: peer.later?.name || `Rule ${Number(peer.laterIndex) + 1}`,
    evidenceSource: peer.evidenceSource || "candidate-scan",
    confidence: peer.confidence || "high",
    confidenceLabel: peer.confidenceLabel || "candidate-derived peer",
    dimensions: (peer.dimensions || []).map((dimension) => ({ ...dimension })),
    sharedDimensions: (peer.dimensions || []).map((dimension) => ({ ...dimension })),
    representativeTuple: peer.representative || null,
    risks: [...(peer.risks || [])],
    riskLabels,
  };
}

function overlapSharedDimensions(peers = []) {
  const byKey = new Map();
  for (const peer of peers) {
    for (const dimension of peer.dimensions || []) {
      if (!byKey.has(dimension.key)) {
        byKey.set(dimension.key, {
          key: dimension.key,
          label: dimension.label,
          values: [],
          confidence: dimension.confidence || peer.confidence || "high",
          confidenceLabel: dimension.confidenceLabel || peer.confidenceLabel || "candidate-derived peer",
          evidenceSource: dimension.evidenceSource || peer.evidenceSource || "candidate-scan",
        });
      }
      const item = byKey.get(dimension.key);
      if (dimension.value && !item.values.includes(dimension.value)) item.values.push(dimension.value);
      if (item.evidenceSource !== "detail-text" && (dimension.evidenceSource || peer.evidenceSource) === "detail-text") {
        item.evidenceSource = "detail-text";
        item.confidence = "medium";
        item.confidenceLabel = "detail-text-derived peer";
      }
    }
  }
  return [...byKey.values()].map((dimension) => ({
    key: dimension.key,
    label: dimension.label,
    value: dimension.values.join(" | ") || "partial",
    confidence: dimension.confidence,
    confidenceLabel: dimension.confidenceLabel,
    evidenceSource: dimension.evidenceSource,
  }));
}

function overlapImpactConfidence(peers = []) {
  if (!peers.length) return { key: "unresolved", label: "peer unresolved", detail: "No current candidate peer could be confirmed from the server finding." };
  if (peers.some((peer) => peer.evidenceSource === "detail-text")) {
    return { key: "detail-text", label: "detail-text-derived", detail: "Peer names came from server detail text; dimensions are recomputed from the current candidate and should be revalidated." };
  }
  return { key: "candidate-scan", label: "candidate-derived", detail: "Peer and dimensions were reconstructed from the current candidate rulebase." };
}

function overlapDimensions(a = {}, b = {}) {
  const dims = [
    ["zones", "Zones", joinOverlapDimension(a.fromZones, b.fromZones) + " -> " + joinOverlapDimension(a.toZones, b.toZones)],
    ["source", "Source", joinOverlapDimension(a.sourceAddresses, b.sourceAddresses)],
    ["destination", "Destination", joinOverlapDimension(a.destinationAddresses, b.destinationAddresses)],
    ["service", "Service", joinOverlapDimension(a.services, b.services)],
    ["app-id", "App-ID", joinOverlapDimension(a.applications, b.applications)],
  ];
  return dims
    .filter(([key]) => {
      if (key === "app-id") return dimsOverlapForImpact(a.applications, b.applications) && (filteredRefs(a.applications).length || filteredRefs(b.applications).length);
      return true;
    })
    .map(([key, label, value]) => ({ key, label, value }));
}

function joinOverlapDimension(a = [], b = []) {
  if (anyToken(a) && anyToken(b)) return "any";
  if (anyToken(a)) return joinPolicyList(b);
  if (anyToken(b)) return joinPolicyList(a);
  const shared = (a || []).filter((item) => (b || []).includes(item));
  return shared.length ? shared.join(", ") : "partial";
}

function overlapRiskFlags(earlier = {}, later = {}) {
  const risks = [];
  const earlierAllows = ruleAllows(earlier);
  const laterAllows = ruleAllows(later);
  const earlierBlocks = ruleBlocks(earlier);
  const laterBlocks = ruleBlocks(later);
  if (earlierAllows && laterBlocks) risks.push("allow-before-deny");
  if (earlierBlocks && laterAllows) risks.push("deny-before-allow");
  if (earlier.action && earlier.action === later.action) risks.push("same-action");
  if (!earlier.log || !later.log) risks.push("log-gap");
  if (JSON.stringify(earlier.securityProfiles || []) !== JSON.stringify(later.securityProfiles || [])) risks.push("profile-mismatch");
  if (filteredRefs(earlier.applications).join("|") !== filteredRefs(later.applications).join("|")) risks.push("app-id-mismatch");
  return risks.length ? risks : ["order-review"];
}

function overlapPrimaryRisk(risks = [], rule = {}) {
  if (risks.includes("allow-before-deny")) return { key: "allow-before-deny", label: "Earlier allow can preempt later block", cls: "bad" };
  if (risks.includes("deny-before-allow")) return { key: "deny-before-allow", label: "Earlier block can preempt later allow", cls: "bad" };
  if (risks.includes("profile-mismatch")) return { key: "profile-mismatch", label: "Inspection intent differs", cls: "warn" };
  if (risks.includes("app-id-mismatch")) return { key: "app-id-mismatch", label: "App-ID scope differs", cls: "warn" };
  if (risks.includes("log-gap")) return { key: "log-gap", label: "Logging gap", cls: "warn" };
  if (risks.includes("same-action")) return { key: "same-action", label: "Duplicate intent", cls: "info" };
  return { key: "order-review", label: ruleAllows(rule) ? "Allow path order review" : "Rule order review", cls: "info" };
}

function overlapRecommendedAction(risks = [], rule = {}, peers = []) {
  if (risks.includes("log-gap")) return "Enable logging on both sides of the overlap before commit.";
  if (risks.includes("allow-before-deny") || risks.includes("deny-before-allow")) return "Review order and run candidate explain-flow for the shared tuple.";
  if (risks.includes("profile-mismatch")) return "Align security profiles or document why inspection differs.";
  if (risks.includes("app-id-mismatch")) return "Confirm App-ID scope and renderer port-hint behavior before commit.";
  if (peers.length > 1) return "Split or narrow match criteria to reduce multi-rule ambiguity.";
  return "Tag for review or narrow the overlapping match.";
}

function representativeOverlapTuple(earlier = {}, later = {}) {
  return {
    fromZones: representativeListValue(earlier.fromZones, later.fromZones),
    toZones: representativeListValue(earlier.toZones, later.toZones),
    sourceAddresses: representativeListValue(earlier.sourceAddresses, later.sourceAddresses),
    destinationAddresses: representativeListValue(earlier.destinationAddresses, later.destinationAddresses),
    services: representativeListValue(earlier.services, later.services),
    applications: representativeListValue(earlier.applications, later.applications),
  };
}

function representativeListValue(a = [], b = []) {
  if (anyToken(a) && anyToken(b)) return "any";
  if (anyToken(a)) return firstPolicyValue(b);
  if (anyToken(b)) return firstPolicyValue(a);
  const shared = (a || []).find((item) => (b || []).includes(item));
  return shared || firstPolicyValue(a) || firstPolicyValue(b) || "any";
}

function firstPolicyValue(items = []) {
  return (Array.isArray(items) ? items : []).find(Boolean) || "";
}

function rulesOverlapForImpact(a = {}, b = {}) {
  if (ruleCoversForOverlapImpact(a, b) || ruleCoversForOverlapImpact(b, a)) return false;
  return dimsOverlapForImpact(a.fromZones, b.fromZones) &&
    dimsOverlapForImpact(a.toZones, b.toZones) &&
    dimsOverlapForImpact(a.sourceAddresses, b.sourceAddresses) &&
    dimsOverlapForImpact(a.destinationAddresses, b.destinationAddresses) &&
    dimsOverlapForImpact(a.services, b.services) &&
    dimsOverlapForImpact(a.applications, b.applications);
}

function ruleCoversForOverlapImpact(a = {}, b = {}) {
  return coversDimForOverlapImpact(a.fromZones, b.fromZones) &&
    coversDimForOverlapImpact(a.toZones, b.toZones) &&
    coversDimForOverlapImpact(a.sourceAddresses, b.sourceAddresses) &&
    coversDimForOverlapImpact(a.destinationAddresses, b.destinationAddresses) &&
    coversDimForOverlapImpact(a.services, b.services) &&
    coversDimForOverlapImpact(a.applications, b.applications);
}

function coversDimForOverlapImpact(a = [], b = []) {
  if (anyToken(a)) return true;
  if (anyToken(b)) return false;
  return (b || []).every((item) => (a || []).includes(item));
}

function dimsOverlapForImpact(a = [], b = []) {
  if (anyToken(a) || anyToken(b)) return true;
  return (a || []).some((item) => (b || []).includes(item));
}

function serverOverlapReviewBody(rows = [], visible = new Set(), meta = {}) {
  const notes = serverOverlapReviewNotes(meta, rows);
  return h("div", { class: "rule-bulk-review rule-overlap-review", dataset: { ruleOverlapReview: "true" } },
    h("div", { class: "alert-box warn" },
      h("strong", {}, "Overlap impact review"),
      h("div", {}, "Policy validation found partial match overlap. Review peer rules, shared dimensions, confidence, and order risk before staging cleanup."),
      h("div", { class: "note", dataset: { ruleOverlapTruncation: meta.mayBeTruncated ? "maybe-truncated" : "under-limit" } },
        meta.mayBeTruncated
          ? `Backend returned the ${meta.limit}-finding maximum; additional overlap findings may exist.`
          : `Backend returned ${rows.length} overlap finding${rows.length === 1 ? "" : "s"} under the ${meta.limit}-finding cap.`),
      notes.slice(1).map((note) => h("div", { class: "note", dataset: { ruleOverlapConfidenceNote: "true" } }, note))),
    rows.length ? h("div", { class: "rule-bulk-review-list" },
      rows.map((row) => serverOverlapReviewItem(row, visible.has(row.index)))) :
      emptyState("filter", "No overlap findings", "Rerun Validate cleanup to refresh server-derived rule overlap findings."));
}

function serverOverlapReviewItem(row = {}, visible = false) {
  const rule = row.rule || {};
  const services = [...(rule.services || []), ...(rule.applications || [])].filter(Boolean);
  const impact = row.impact || {};
  const primary = impact.primaryRisk || { label: "order review", cls: "warn" };
  return h("div", {
    class: "rule-bulk-review-row warn rule-overlap-impact-item",
    dataset: {
      ruleOverlapItem: rule.name || `Rule ${row.index + 1}`,
      ruleIndex: String(row.index),
      ruleOverlapRisk: primary.key || "order-review",
      ruleOverlapResultId: row.overlapResult?.id || "",
      ruleOverlapIdentityKey: row.overlapResult?.identityKey || "",
      ruleOverlapPageKey: row.overlapPage?.pageKey || "",
    },
  },
    h("div", { class: "rule-bulk-review-main" },
      h("div", {},
        h("strong", {}, `#${row.index + 1} ${rule.name || "(unnamed)"}`),
        h("span", { class: "muted" }, visible ? "visible in overlap filter" : "hidden by current view")),
      h("div", { class: "rule-bulk-review-meta" },
        pill(fmt.ruleAction(rule.action).label, "neutral"),
        pill(primary.label, primary.cls || "warn"),
        impact.confidence ? pill(`confidence: ${impact.confidence.label}`, impact.confidence.key === "detail-text" ? "warn" : impact.confidence.key === "unresolved" ? "bad" : "info") : null,
        row.severity ? pill(row.severity, "warn") : null,
        row.stage ? pill(row.stage, "info") : null)),
    h("div", { class: "note" }, row.detail || row.message),
    impact.confidence?.detail ? h("div", { class: "note", dataset: { ruleOverlapConfidence: impact.confidence.key || "unknown" } }, impact.confidence.detail) : null,
    h("div", { class: "rule-overlap-peer-list" },
      (impact.peers || []).length ? impact.peers.map((peer) => overlapPeerRow(peer)) :
        h("div", { class: "note", dataset: { ruleOverlapPeer: "unresolved" } }, "Peer rule could not be resolved from current candidate; rerun validation after refreshing the candidate.")),
    h("div", { class: "rule-overlap-risk-list" },
      (impact.risks || []).map((risk) => pill(overlapRiskLabel(risk), overlapRiskClass(risk), true)).map((node) => {
        node.dataset.ruleOverlapRisk = node.textContent || "";
        return node;
      })),
    h("div", { class: "rule-overlap-action", dataset: { ruleOverlapAction: "recommendation" } }, impact.action || "Review order before commit."),
    h("div", { class: "sim-detail compact" },
      h("div", {}, h("span", {}, "Zones"), h("strong", {}, `${joinPolicyList(rule.fromZones)} -> ${joinPolicyList(rule.toZones)}`)),
      h("div", {}, h("span", {}, "Source"), h("strong", {}, joinPolicyList(rule.sourceAddresses))),
      h("div", {}, h("span", {}, "Destination"), h("strong", {}, joinPolicyList(rule.destinationAddresses))),
      h("div", {}, h("span", {}, "Service / App"), h("strong", {}, joinPolicyList(services))),
      h("div", {}, h("span", {}, "Logging"), h("strong", {}, rule.log ? "enabled" : "disabled"))));
}

function overlapPeerRow(peer = {}) {
  const earlier = peer.earlier || {};
  const later = peer.later || {};
  return h("div", { class: "rule-overlap-peer", dataset: { ruleOverlapPeer: `${peer.earlierIndex}:${peer.laterIndex}`, ruleOverlapPeerConfidence: peer.confidence || "unknown", ruleOverlapPeerSource: peer.evidenceSource || "unknown" } },
    h("div", { class: "rule-overlap-peer-head" },
      h("strong", {}, `#${peer.earlierIndex + 1} ${earlier.name || "(unnamed)"}`),
      h("span", { class: "muted", html: icon("arrowRight", 13) }),
      h("strong", {}, `#${peer.laterIndex + 1} ${later.name || "(unnamed)"}`),
      pill(peer.confidenceLabel || "candidate-derived peer", peer.confidence === "medium" ? "warn" : "info", true)),
    h("div", { class: "rule-overlap-dimensions" }, (peer.dimensions || []).map((dimension) =>
      h("div", { dataset: { ruleOverlapDimension: dimension.key, ruleOverlapDimensionConfidence: dimension.confidence || "unknown", ruleOverlapDimensionSource: dimension.evidenceSource || "unknown" } },
        h("span", {}, dimension.label),
        h("strong", {}, dimension.value)))),
    h("div", { class: "rule-overlap-dimensions compact" },
      h("div", {}, h("span", {}, "Representative"), h("strong", {}, overlapRepresentativeLabel(peer.representative)))));
}

function overlapRepresentativeLabel(rep = {}) {
  const left = `${rep.fromZones || "any"} -> ${rep.toZones || "any"}`;
  const tuple = [rep.sourceAddresses, rep.destinationAddresses, rep.services, rep.applications].filter((item) => item && item !== "any").join(" / ");
  return tuple ? `${left} · ${tuple}` : left;
}

function overlapRiskLabel(risk = "") {
  const labels = {
    "allow-before-deny": "allow before deny",
    "deny-before-allow": "deny before allow",
    "same-action": "same action",
    "log-gap": "log gap",
    "profile-mismatch": "profile mismatch",
    "app-id-mismatch": "App-ID mismatch",
    "order-review": "order review",
  };
  return labels[risk] || risk || "review";
}

function overlapRiskClass(risk = "") {
  if (risk === "allow-before-deny" || risk === "deny-before-allow") return "bad";
  if (risk === "log-gap" || risk === "profile-mismatch" || risk === "app-id-mismatch") return "warn";
  return "info";
}

function joinPolicyList(items = []) {
  const list = Array.isArray(items) ? items.filter(Boolean) : [];
  return list.length ? list.join(", ") : "any";
}

function ruleVerificationDrawerBody(rows = [], changeModel = {}) {
  const summary = ruleVerificationSummary(rows, ruleVerificationState, { removed: changeModel.removed?.length || 0 });
  return h("div", { class: "stack", dataset: { ruleVerificationDrawer: "true" } },
    h("div", { class: summary.pending ? "alert-box warn" : "alert-box ok" },
      h("strong", {}, summary.label),
      h("div", {}, "Each check explains a concrete representative tuple against the staged candidate policy and expects the changed rule to match first.")),
    changeModel.removed?.length ? h("div", { class: "note" },
      `Removed rules are not replayed here because they no longer have candidate tuples: ${changeModel.removed.map((item) => item.name).join(", ")}.`) : null,
    rows.length ? h("div", { class: "rule-verification-list" },
      rows.map(({ rule, idx, change }) => ruleVerificationItem(rule, idx, change))) :
      emptyState("search", "No verifiable changed rules", "Add, edit, or move a rule with concrete zones, address objects, and service or App-ID hints."));
}

function ruleVerificationItem(rule = {}, idx = -1, change = {}) {
  const evidence = representativeFlowFromRule(session.draft || {}, rule, { source: "POLICY_SOURCE_CANDIDATE" });
  const status = ruleVerificationStatus(rule, change, ruleVerificationState);
  const detail = status.detail || status.reason || (evidence.ok ? "Not verified yet." : evidence.warnings[0] || "Representative tuple is incomplete.");
  return h("div", { class: `rule-verification-item ${status.state}`, dataset: { ruleVerificationItem: status.state, ruleName: rule.name || "", ruleIndex: String(idx) } },
    h("div", { class: "rule-verification-head" },
      h("div", { class: "rule-verification-title" },
        h("strong", {}, `${idx + 1}. ${rule.name || "(unnamed)"}`),
        h("span", { class: "muted rule-verification-kind" }, change.kind || "")),
      ruleVerificationBadge(status)),
    h("div", { class: "note" }, detail),
    evidence.ok ? h("div", { class: "sim-detail compact" },
      h("div", {}, h("span", {}, "Tuple"), h("strong", {}, `${evidence.simulator.srcIp} → ${evidence.simulator.destIp}:${evidence.simulator.destPort || "any"}`)),
      h("div", {}, h("span", {}, "Zones"), h("strong", {}, `${evidence.simulator.fromZone} → ${evidence.simulator.toZone}`)),
      h("div", {}, h("span", {}, "Protocol"), h("strong", {}, explainLabel(evidence.simulator.protocol, "PROTOCOL_").toLowerCase())),
      status.matchedRule ? h("div", {}, h("span", {}, "Matched"), h("strong", {}, status.matchedRule)) : null) :
      h("ul", { class: "sim-evidence" }, evidence.warnings.map((warning) => h("li", {}, warning))));
}

function ruleVerificationBadge(status = {}) {
  const classes = {
    verified: "ok",
    mismatch: "bad",
    unverifiable: "warn",
    error: "bad",
    stale: "warn",
    needed: "neutral",
  };
  return h("span", {
    class: `rule-verification-badge ${classes[status.state] || "neutral"}`,
    title: status.verifiedAt ? `Verified ${status.verifiedAt}` : status.detail || status.label,
    dataset: { ruleVerificationState: status.state || "needed" },
  }, status.label || "verify");
}

async function runChangedRuleVerification(root) {
  if (verifyingChangedRules) return;
  const changeModel = ruleChangeModel(session.running?.rules || [], session.draft?.rules || []);
  const rows = changedCandidateRuleRows(session.draft?.rules || [], changeModel);
  if (!rows.length) return;
  verifyingChangedRules = true;
  const routeBacked = activeRuleReviewDrawer === "verify-changed";
  refreshRuleReviewDrawer(() => openChangedRuleVerificationDrawer(root, { routeBacked }));
  try {
    await session.stageDraft("verify changed rules");
    for (const row of rows) {
      const record = await verifyChangedRule(row.rule, row.idx, row.change);
      ruleVerificationState.set(record.key, record);
      refreshRuleReviewDrawer(() => openChangedRuleVerificationDrawer(root, { routeBacked }));
    }
    const summary = ruleVerificationSummary(rows, ruleVerificationState, { removed: changeModel.removed?.length || 0 });
    toast("Changed rules verified", summary.label, summary.pending ? "warn" : "ok");
  } catch (err) {
    toast("Rule verification failed", err.message, "bad");
  } finally {
    verifyingChangedRules = false;
    refreshRuleReviewDrawer(() => openChangedRuleVerificationDrawer(root, { routeBacked }));
    rerender(root);
  }
}

async function verifyChangedRule(rule = {}, idx = -1, change = {}) {
  const key = ruleVerificationKey(rule, change);
  const evidence = representativeFlowFromRule(session.draft || {}, rule, { source: "POLICY_SOURCE_CANDIDATE" });
  if (!evidence.ok) {
    return {
      key,
      state: "unverifiable",
      ruleName: rule.name || "",
      verifiedAt: new Date().toISOString(),
      detail: evidence.warnings[0] || "Representative tuple is incomplete.",
    };
  }
  try {
    const result = await api.explainFlow({
      policySource: "POLICY_SOURCE_CANDIDATE",
      version: "0",
      fromZone: evidence.simulator.fromZone,
      toZone: evidence.simulator.toZone,
      srcIp: evidence.simulator.srcIp,
      srcPort: numberOrZero(evidence.simulator.srcPort),
      destIp: evidence.simulator.destIp,
      destPort: numberOrZero(evidence.simulator.destPort),
      protocol: evidence.simulator.protocol,
      appId: evidence.simulator.appId,
    });
    const matchedRule = String(result?.matchedRule || "");
    const expected = String(rule.name || "");
    const matchedIndex = Number(result?.matchedRuleIndex);
    const sameNamedRule = expected && matchedRule === expected;
    const sameIndexRule = Number.isInteger(matchedIndex) && matchedIndex === idx;
    const verified = sameNamedRule || sameIndexRule;
    return {
      key,
      state: verified ? "verified" : "mismatch",
      ruleName: expected,
      matchedRule,
      matchedRuleIndex: Number.isInteger(matchedIndex) ? matchedIndex : -1,
      verdict: result?.verdict || "",
      verifiedAt: new Date().toISOString(),
      detail: verified
        ? `Candidate flow matched ${matchedRule || `rule #${idx + 1}`}.`
        : `Candidate flow matched ${matchedRule || "default policy"} instead of ${expected || `rule #${idx + 1}`}.`,
    };
  } catch (err) {
    return {
      key,
      state: "error",
      ruleName: rule.name || "",
      verifiedAt: new Date().toISOString(),
      detail: err.message || "Explain-flow failed.",
    };
  }
}

async function stageHostInputRuleLog(indexes = [], log = true, root) {
  const hostRuleCount = (session.draft.hostInput?.rules || []).length;
  const normalized = normalizedRuleIndexes(indexes, hostRuleCount);
  if (!normalized.length) return;
  try {
    await session.apply((d) => applyHostInputRuleLog(d, normalized, log));
    rerender(root);
    toast(log ? "Host-input logging enabled" : "Host-input logging disabled", `${normalized.length} host-input rule${normalized.length === 1 ? "" : "s"} staged to candidate.`, "ok");
  } catch (e) {
    toast("Host-input logging update failed", e.message, "bad");
  }
}

function openBulkTagDrawer(mode, root, visibleRows = [], opts = {}) {
  const indexes = Array.isArray(opts.indexes) ? opts.indexes : selectedRuleIndexList();
  if (!indexes.length) return;
  const drawer = mode === "remove" ? "bulk-tag-remove" : "bulk-tag-add";
  const input = h("input", { class: "input", placeholder: "owner:secops", value: opts.tag ?? filter.tag ?? "", dataset: { ruleBulkTagInput: mode } });
  const previewSlot = h("div", {});
  const rebuildPreview = () => {
    const preview = bulkRuleActionPreview(session.draft, indexes, visibleRows, { kind: "tag", mode, tag: input.value });
    preview.routeTargetSnapshotToken = opts.bulkTargets || routeBulkTargets || bulkRuleTargetSnapshotToken(preview);
    clear(previewSlot);
    previewSlot.appendChild(bulkRuleReviewBody(preview, { compact: true }));
    return preview;
  };
  input.oninput = rebuildPreview;
  const initialPreview = rebuildPreview();
  if (opts.routeBacked) setRuleReviewDrawerRoute(drawer, {
    bulkTag: input.value,
    bulkTargets: initialPreview.routeTargetSnapshotToken,
  });
  openDrawer({
    title: mode === "remove" ? "Remove tag from selected rules" : "Add tag to selected rules",
    subtitle: `${indexes.length} selected rule${indexes.length === 1 ? "" : "s"} · review before staging`,
    width: "760px",
    body: h("div", {},
      h("label", { class: "field" },
        h("span", {}, "Tag"),
        input),
      h("div", { class: "note" }, "Tags are normalized to lowercase labels and staged to the candidate policy after review."),
      previewSlot),
    footer: [
      h("button", { class: "btn", ...actionControlAttrs({ ruleReviewAction: "copy-context" }, `Copy ${mode} tag review context`, { onclick: () => {
        const preview = rebuildPreview() || initialPreview;
        copyRuleReviewContext(bulkRuleReviewContext(preview, { kind: "tag", mode, tag: input.value }, drawer));
      } }) }, h("span", { html: icon("copy", 16) }), "Copy review context"),
      h("button", { class: "btn ghost", ...actionControlAttrs({ ruleReviewAction: "cancel" }, `Cancel ${mode} tag review`, { onclick: closeRuleReviewDrawer }) }, "Cancel"),
      h("button", { class: "btn primary", ...actionControlAttrs({ ruleReviewAction: mode === "remove" ? "remove-tag" : "add-tag" }, mode === "remove" ? "Review and remove selected rule tag" : "Review and add selected rule tag", { onclick: () => stageBulkRuleAction({ kind: "tag", mode, tag: input.value }, rebuildPreview() || initialPreview, root) }) },
        h("span", { html: icon(mode === "remove" ? "trash" : "plus", 16) }),
        mode === "remove" ? "Review and remove" : "Review and add"),
    ],
    onClose: opts.routeBacked ? clearRuleReviewDrawerRoute : null,
  });
}

function openBulkActionReview(action, root, visibleRows = [], opts = {}) {
  const indexes = Array.isArray(opts.indexes) ? opts.indexes : selectedRuleIndexList();
  if (!indexes.length) return;
  const preview = bulkRuleActionPreview(session.draft, indexes, visibleRows, action);
  const drawer = opts.drawer || bulkReviewDrawerForAction(action);
  preview.routeTargetSnapshotToken = opts.bulkTargets || routeBulkTargets || bulkRuleTargetSnapshotToken(preview);
  if (opts.routeBacked) setRuleReviewDrawerRoute(drawer, { bulkTargets: preview.routeTargetSnapshotToken });
  openDrawer({
    title: preview.title,
    subtitle: `${preview.targetCount} selected rule${preview.targetCount === 1 ? "" : "s"} · review before staging`,
    width: "760px",
    body: bulkRuleReviewBody(preview),
    footer: [
      h("button", { class: "btn", ...actionControlAttrs({ ruleReviewAction: "copy-context" }, `Copy ${preview.title} context`, { onclick: () => copyRuleReviewContext({
        ...bulkRuleReviewContext(preview, action, drawer),
      }) }) }, h("span", { html: icon("copy", 16) }), "Copy review context"),
      h("button", { class: "btn ghost", ...actionControlAttrs({ ruleReviewAction: "cancel" }, `Cancel ${preview.title}`, { onclick: closeRuleReviewDrawer }) }, "Cancel"),
      h("button", {
        class: "btn primary",
        ...actionControlAttrs({ ruleReviewAction: "stage" }, preview.confirmLabel, {
          disabled: preview.blockedCount > 0 || preview.changeCount === 0,
          onclick: () => stageBulkRuleAction(action, preview, root),
        }),
      }, h("span", { html: icon("check", 16) }), preview.confirmLabel),
    ],
    onClose: opts.routeBacked ? clearRuleReviewDrawerRoute : null,
  });
}

function bulkReviewDrawerForAction(action = {}) {
  if (action.kind === "log") return action.log ? "bulk-log-on" : "bulk-log-off";
  if (action.kind === "disabled") return action.disabled ? "bulk-disable" : "bulk-enable";
  return "";
}

function bulkReviewActionLabel(action = {}) {
  if (action.kind === "log") return action.log ? "Enable rule logging" : "Disable rule logging";
  if (action.kind === "disabled") return action.disabled ? "Disable rules" : "Enable rules";
  return "Bulk rule review";
}

function bulkRuleReviewBody(preview = {}, opts = {}) {
  return h("div", { class: "rule-bulk-review", dataset: { ruleBulkReview: preview.kind || "bulk" } },
    h("div", { class: "preflight-summary" },
      h("div", {}, h("span", {}, "Selected"), h("strong", {}, String(preview.targetCount || 0))),
      h("div", {}, h("span", {}, "Visible"), h("strong", {}, String(preview.visibleCount || 0))),
      h("div", {}, h("span", {}, "Will change"), h("strong", {}, String(preview.changeCount || 0))),
      h("div", {}, h("span", {}, "No-op / blocked"), h("strong", {}, `${preview.noOpCount || 0} / ${preview.blockedCount || 0}`))),
    preview.hiddenCount ? h("div", { class: "alert-box warn" },
      h("strong", {}, "Hidden selected rules"),
      h("div", { class: "note" }, `${preview.hiddenCount} selected rule${preview.hiddenCount === 1 ? " is" : "s are"} outside the current filter or group lens.`)) : null,
    preview.identityNotes?.length ? h("div", { class: "alert-box info", dataset: { ruleIdentityCaveat: "name-index" } },
      h("strong", {}, "Identity caveat"),
      h("ul", { class: "rule-identity-caveats" }, preview.identityNotes.map((note) => h("li", {}, note)))) : null,
    preview.issues?.length ? h("div", { class: "alert-box bad" },
      h("strong", {}, "Cannot stage yet"),
      h("div", { class: "automation-notes" }, preview.issues.map((issue) => h("div", {}, issue)))) : null,
    h("div", { class: `rule-bulk-review-list ${opts.compact ? "compact" : ""}` },
      (preview.rows || []).map((row) => bulkRuleReviewRow(row))));
}

function bulkRuleReviewRow(row = {}) {
  const state = row.issue ? "blocked" : row.noOp ? "no-op" : "change";
  const tone = row.issue ? "bad" : row.noOp ? "neutral" : "info";
  const label = row.issue ? "Blocked" : row.noOp ? "No change" : "Will change";
  const tagPills = [
    pill(row.action || "Action", "neutral"),
    ...(row.tags || []).slice(0, 4).map((tag) => pill(tag, "neutral")),
    (row.tags || []).length > 4 ? pill(`+${row.tags.length - 4}`, "neutral") : null,
  ].filter(Boolean);
  return h("div", { class: `rule-bulk-review-row ${state}`, dataset: { ruleBulkReviewRule: row.name || "", ruleBulkReviewRuleId: row.itemId || "", ruleBulkReviewState: state } },
    h("div", { class: "rule-bulk-review-main" },
      h("div", {},
        h("strong", {}, `#${row.position} ${row.name}`),
        h("span", { class: "muted" }, [
          row.itemId ? `id ${row.itemId}` : "",
          row.visible ? "visible" : "hidden by current view",
          row.duplicateName ? "duplicate name" : "",
        ].filter(Boolean).join(" · "))),
      h("div", { class: "rule-bulk-review-meta" }, ...tagPills)),
    h("div", { class: "rule-bulk-review-change" },
      h("span", {}, row.before || "—"),
      h("span", { html: icon("arrowRight", 14), "aria-hidden": "true" }),
      h("span", {}, row.after || "—")),
    h("div", { class: "rule-bulk-review-state" },
      pill(label, tone),
      row.issue ? h("small", {}, row.issue) : null));
}

async function stageBulkRuleAction(action = {}, preview = {}, root) {
  const routeTargets = bulkRuleTargetSnapshotStatus(session.draft, preview.routeTargetSnapshotToken || routeBulkTargets);
  if (!routeTargets.ok) {
    toast("Route targets changed", routeTargets.issues[0], "warn");
    return;
  }
  const current = bulkRulePreviewStillCurrent(session.draft, preview);
  if (!current.ok) {
    toast("Selection changed", current.issues[0], "warn");
    return;
  }
  if (preview.issues?.length) {
    toast("Bulk update blocked", preview.issues[0], "warn");
    return;
  }
  if (!preview.changeCount) {
    toast("No rule changes", "The reviewed selection already matches the requested state.", "info");
    return;
  }
  const resolvedIndexes = routeTargets.checked ? routeTargets.indexes : (preview.rows || []).map((row) => row.index);
  const resolvedBySnapshotRow = new Map((preview.rows || []).map((row, offset) => [row, resolvedIndexes[offset] ?? row.index]));
  const indexes = (preview.rows || [])
    .filter((row) => !row.issue && !row.noOp)
    .map((row) => resolvedBySnapshotRow.get(row))
    .filter((idx) => Number.isInteger(idx));
  const plan = normalizeBulkRuleAction(action);
  try {
    if (plan.kind === "log") await session.apply((d) => applyBulkRuleLog(d, indexes, plan.log));
    else if (plan.kind === "tag") await session.apply((d) => applyBulkRuleTag(d, indexes, plan.tag, plan.mode));
    else await session.apply((d) => applyBulkRuleDisabled(d, indexes, plan.disabled));
    selectedRuleIndexes.clear();
    closeDrawer();
    rerender(root);
    toast("Bulk update staged", `${indexes.length} rule${indexes.length === 1 ? "" : "s"} staged to candidate.`, "ok");
  } catch (e) {
    toast("Bulk update failed", e.message, "bad");
  }
}

async function validateRuleCleanup(root) {
  ruleValidationState = { ...ruleValidationState, loading: true, error: "" };
  rerender(root);
  try {
    const validation = await api.validatePolicy(session.draft || {});
    const findings = Array.isArray(validation?.findings) ? validation.findings : [];
    const cleanup = ruleValidationCleanup(findings, (session.draft.rules || []).length);
    ruleValidationState = {
      loading: false,
      findings,
      error: "",
      ranAt: new Date().toISOString(),
      draftFingerprint: fingerprint(session.draft || {}),
    };
    rerender(root);
    toast("Validation cleanup ready", `${cleanup.totalFindings} hygiene finding${cleanup.totalFindings === 1 ? "" : "s"} from server validation.`, cleanup.totalFindings ? "warn" : "ok");
  } catch (e) {
    ruleValidationState = {
      ...ruleValidationState,
      loading: false,
      error: e?.message || String(e || "validation failed"),
    };
    rerender(root);
    toast("Validation cleanup failed", ruleValidationState.error, "bad");
  }
}

function ruleHygienePanel(hygiene, root, validationSnapshot = {}) {
  const status = ruleValidationState.loading
    ? pill("validating", "warn", true)
    : ruleValidationState.error
      ? pill("validation failed", "bad", true)
      : validationSnapshot.stale
        ? pill("server stale", "warn", true)
      : ruleValidationState.ranAt
        ? pill("server checked", "info", true)
        : null;
  const staleNote = validationSnapshot.stale
    ? "Candidate changed after server validation. Rerun Validate cleanup before applying server-backed cleanup findings."
    : "";
  if (!hygiene.findings.length) {
    return h("div", { class: "rule-hygiene ok" },
      h("div", { class: "rule-hygiene-title" },
        h("span", { html: icon("check", 16) }),
        h("strong", {}, "Rule hygiene clean"),
        status),
      h("span", { class: "muted" },
        staleNote
          ? staleNote
          : ruleValidationState.error
          ? `Server validation could not run: ${ruleValidationState.error}`
          : countersAvailable ? "No shadowed, duplicate, broad, missing-log, server-overlap, unused-object, or zero-hit running rules found." : "No static rule hygiene findings found."));
  }
  return h("div", { class: "rule-hygiene warn", dataset: { ruleHygienePanel: "true" } },
    h("div", { class: "rule-hygiene-title" },
      h("span", { html: icon("filter", 16) }),
      h("strong", {}, "Rule cleanup queue"),
      status),
    staleNote ? h("div", { class: "alert-box warn", dataset: { ruleValidationStale: "true" } },
      h("strong", {}, "Server cleanup findings are stale. "),
      h("span", {}, staleNote)) : null,
    ruleValidationState.error ? h("div", { class: "note" }, `Server validation could not run: ${ruleValidationState.error}`) : null,
    h("div", { class: "rule-hygiene-findings" }, hygiene.findings.map((finding) => ruleHygieneFindingChip(finding, root))));
}

function ruleHygieneFindingChip(finding = {}, root) {
  const hasRuleSet = Array.isArray(finding.indexes) && finding.indexes.length > 0 && !finding.settingsPanel;
  const reviewAction = finding.fix === "log-on" ? { kind: "log", log: true } : null;
  const reviewOverlap = finding.fix === "review-overlap";
  const content = [
    pill(finding.count, finding.cls, true),
    h("span", {}, finding.title),
    h("small", {}, finding.detail),
    hasRuleSet && !reviewOverlap ? h("span", {
      class: "btn sm",
      dataset: { ruleHygieneAction: reviewAction ? "review-logging" : "select-set", ruleHygieneTitle: finding.title || "" },
      onclick: (e) => {
        e.stopPropagation();
        selectHygieneRuleSet(finding, root, { reviewAction });
      },
    }, reviewAction ? "Review logging" : "Select set") : null,
    reviewOverlap ? h("span", {
      class: "btn sm",
      dataset: { ruleHygieneAction: "review-overlap", ruleHygieneTitle: finding.title || "" },
      onclick: (e) => {
        e.stopPropagation();
        openServerOverlapReviewFromFinding(finding, root);
      },
    }, "Review overlaps") : null,
    finding.fix === "host-input-log-on" ? h("span", {
      class: "btn sm",
      dataset: { ruleHygieneAction: "stage-host-input-logging", ruleHygieneTitle: finding.title || "" },
      onclick: (e) => {
        e.stopPropagation();
        stageHostInputRuleLog(finding.indexes || [], true, root);
      },
    }, "Stage host-input logging") : null,
    finding.settingsPanel === "host-input" ? h("span", {
      class: "btn sm",
      dataset: { ruleHygieneAction: "open-host-input", ruleHygieneTitle: finding.title || "" },
      onclick: (e) => {
        e.stopPropagation();
        location.hash = settingsPanelHash("host-input");
      },
    }, "Open host input") : null,
    finding.routeHref ? h("span", {
      class: "btn sm",
      dataset: { ruleHygieneAction: "open-route", ruleHygieneRoute: finding.routeHref },
      onclick: (e) => {
        e.stopPropagation();
        location.hash = finding.routeHref;
      },
    }, finding.routeLabel || "Open") : null,
    finding.href ? h("span", { class: "btn sm" }, finding.hrefLabel || "Open objects") : null,
  ];
  if (finding.href && !finding.fix && !finding.settingsPanel) {
    return h("a", { class: "rule-hygiene-chip " + finding.cls, href: finding.href }, content);
  }
  return h("button", {
    class: "rule-hygiene-chip " + (finding.cls || "info"),
    dataset: { ruleHygieneTitle: finding.title || "", ruleHygieneFix: finding.fix || "", ruleHygieneSettingsPanel: finding.settingsPanel || "" },
    onclick: () => finding.filter ? setRuleFilter(finding.filter) : null,
  }, content);
}

export function rulebaseMapModel(policy = {}, running = {}, counters = new Map(), hasCounters = false, validationCleanup = {}) {
  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  const changeModel = ruleChangeModel(running?.rules || [], rules);
  const hygiene = computeRuleHygiene(rules, counters, hasCounters, policy, validationCleanup);
  const issueIndexes = new Set([
    ...hygiene.shadowed,
    ...hygiene.broadAllows,
    ...hygiene.bypassRisk,
    ...hygiene.missingLogs,
    ...hygiene.validationOverlaps,
    ...hygiene.staleZeroHit,
  ]);
  const dependencyTotals = { addresses: 0, services: 0, apps: 0, profiles: 0 };
  const counts = {
    total: rules.length,
    active: 0,
    allow: 0,
    block: 0,
    appRules: 0,
    profiledRules: 0,
    changed: 0,
    review: issueIndexes.size,
    zeroHit: hygiene.staleZeroHit.length,
  };
  const bands = new Map([
    ["allow", rulebaseBand("allow", "Allow paths", "ok", "Permitting traffic")],
    ["block", rulebaseBand("block", "Pre-filter drops", "neutral", "Deny or reject before inspection")],
    ["app-id", rulebaseBand("app-id", "App-ID scoped", "info", "Application objects constrain the match")],
    ["inspection", rulebaseBand("inspection", "Profiled inspection", "info", "Security profiles are attached")],
    ["review", rulebaseBand("review", "Needs review", "warn", "Cleanup, overlap, bypass, logging, or hit evidence")],
    ["disabled", rulebaseBand("disabled", "Disabled", "neutral", "Staged but not active")],
  ]);

  const rows = rules.map((rule, idx) => {
    const activeRule = ruleActive(rule);
    const allowRule = ruleAllows(rule);
    const blockRule = ruleBlocks(rule);
    const apps = filteredRefs(rule.applications);
    const profiles = filteredRefs(rule.securityProfiles);
    const addresses = filteredRefs([...(rule.sourceAddresses || []), ...(rule.destinationAddresses || [])]);
    const services = filteredRefs(rule.services);
    const change = ruleChangeForIndex(changeModel, idx);
    const counter = counters.get("rule:" + (rule?.name || ""));
    const hitState = !hasCounters ? "unavailable" : counter ? (fmt.num(counter.packets) === 0 && fmt.num(counter.bytes) === 0 ? "zero" : "hit") : "missing";
    if (activeRule) counts.active += 1;
    if (activeRule && allowRule) counts.allow += 1;
    if (activeRule && blockRule) counts.block += 1;
    if (apps.length) counts.appRules += 1;
    if (profiles.length) counts.profiledRules += 1;
    if (change) counts.changed += 1;
    dependencyTotals.addresses += addresses.length;
    dependencyTotals.services += services.length;
    dependencyTotals.apps += apps.length;
    dependencyTotals.profiles += profiles.length;

    const issues = rulebaseMapIssues(hygiene, idx);
    const bandKeys = [];
    if (!activeRule) bandKeys.push("disabled");
    else {
      if (allowRule) bandKeys.push("allow");
      if (blockRule) bandKeys.push("block");
      if (apps.length) bandKeys.push("app-id");
      if (profiles.length) bandKeys.push("inspection");
      if (issues.length) bandKeys.push("review");
    }
    for (const key of bandKeys) {
      const band = bands.get(key);
      band.count += 1;
      if (band.examples.length < 3) band.examples.push(rule.name || `#${idx + 1}`);
    }
    return {
      index: idx,
      position: idx + 1,
      name: rule.name || `Rule ${idx + 1}`,
      action: rule.action || "",
      active: activeRule,
      change: change?.kind || "",
      apps,
      profiles,
      dependencies: {
        addresses,
        services,
        apps,
        profiles,
        total: addresses.length + services.length + apps.length + profiles.length,
      },
      hitState,
      issues,
      bandKeys,
    };
  });

  const summary = counts.review
    ? { label: `${counts.review} review item${counts.review === 1 ? "" : "s"}`, cls: "warn" }
    : counts.total
      ? { label: "mapped", cls: "ok" }
      : { label: "empty", cls: "neutral" };
  return {
    counts,
    dependencyTotals,
    rows,
    bands: [...bands.values()].filter((band) => band.count > 0),
    topReviewRows: rows.filter((row) => row.issues.length).slice(0, 5),
    changeSummary: ruleChangeSummary(changeModel),
    summary,
  };
}

function rulebaseBand(key, label, cls, detail) {
  return { key, label, cls, detail, count: 0, examples: [] };
}

function filteredRefs(items = []) {
  return uniqueRefs(items).filter((item) => item !== "any");
}

function uniqueRefs(items = []) {
  return [...new Set((Array.isArray(items) ? items : []).map((item) => String(item || "").trim()).filter(Boolean))];
}

function rulebaseMapIssues(hygiene = {}, idx = -1) {
  const issues = [];
  if ((hygiene.shadowed || []).includes(idx)) issues.push("shadowed");
  if ((hygiene.broadAllows || []).includes(idx)) issues.push("broad allow");
  if ((hygiene.bypassRisk || []).includes(idx)) issues.push("bypass risk");
  if ((hygiene.missingLogs || []).includes(idx)) issues.push("missing log");
  if ((hygiene.validationOverlaps || []).includes(idx)) issues.push("server overlap");
  if ((hygiene.staleZeroHit || []).includes(idx)) issues.push("zero hit");
  return issues;
}

function rulebaseMapPanel(model = {}, root) {
  const counts = model.counts || {};
  const panel = h("section", { class: "rulebase-map", dataset: { rulebaseMap: "true" } },
    h("div", { class: "rulebase-map-head" },
      h("div", {},
        h("h2", {}, "Rulebase map", h("span", { class: "spacer" }), pill(model.summary?.label || "unknown", model.summary?.cls || "neutral", true)),
        h("p", {}, "Order, dependencies, App-ID/profile scope, hit evidence, and cleanup risk for the candidate rulebase.")),
      h("div", { class: "rulebase-map-actions" },
        h("button", { class: "btn sm", ...actionControlAttrs({ rulebaseAction: "filter-changed" }, "Show changed rules", { onclick: () => setRuleFilter({ changed: true }) }) }, h("span", { html: icon("diff", 14) }), "Changed"),
        h("button", { class: "btn sm", ...actionControlAttrs({ rulebaseAction: "filter-bypass" }, "Show inspection bypass risk rules", { onclick: () => setRuleFilter({ q: "bypass-risk" }) }) }, h("span", { html: icon("shield", 14) }), "Bypass"),
        h("button", { class: "btn sm", ...actionControlAttrs({ rulebaseAction: "filter-overlaps" }, "Show server overlap rules", { onclick: () => setRuleFilter({ q: "server-overlap" }) }) }, h("span", { html: icon("filter", 14) }), "Overlaps"))),
    h("div", { class: "automation-session-grid rulebase-map-metrics" },
      rulebaseMetric("rules", counts.total || 0),
      rulebaseMetric("active", counts.active || 0),
      rulebaseMetric("allow paths", counts.allow || 0),
      rulebaseMetric("App-ID scoped", counts.appRules || 0),
      rulebaseMetric("profiled", counts.profiledRules || 0),
      rulebaseMetric("changed", counts.changed || 0)),
    model.bands?.length ? h("div", { class: "rulebase-map-bands" }, model.bands.map((band) => rulebaseMapBand(band))) :
      emptyState("rules", "No rules to map", "Add forwarding rules to see order, dependencies, and review hotspots."),
    model.topReviewRows?.length ? h("div", { class: "rulebase-map-review" },
      h("div", { class: "rulebase-map-subhead" },
        h("strong", {}, "Review hotspots"),
        h("span", {}, `${model.topReviewRows.length} shown`)),
      h("div", { class: "rulebase-map-review-list" }, model.topReviewRows.map((row) => rulebaseMapReviewRow(row, root)))) : null);
  return panel;
}

function rulebaseMetric(label, value) {
  return h("div", {}, h("span", {}, label), h("strong", {}, fmt.num(value)));
}

function rulebaseMapBand(band = {}) {
  return h("button", {
    class: "rulebase-map-band " + (band.cls || "neutral"),
    type: "button",
    dataset: { rulebaseBand: band.key || "" },
    title: band.detail || "",
    "aria-label": `Filter rulebase map band ${band.label || "Band"}`,
    onclick: () => setRuleFilter(rulebaseBandFilter(band.key)),
  },
    h("span", {}, band.label || "Band"),
    h("strong", {}, fmt.num(band.count || 0)),
    h("small", {}, band.examples?.length ? band.examples.join(", ") : band.detail || ""));
}

function rulebaseBandFilter(key = "") {
  if (key === "allow") return { action: "ACTION_ALLOW" };
  if (key === "block") return { action: "ACTION_DENY" };
  if (key === "app-id") return { q: "app-id" };
  if (key === "inspection") return { q: "profile" };
  if (key === "review") return { q: "missing-log" };
  if (key === "disabled") return { q: "disabled" };
  return {};
}

function rulebaseMapReviewRow(row = {}, root) {
  const rule = session.draft?.rules?.[row.index] || {};
  return h("button", {
    class: "rulebase-map-review-row",
    type: "button",
    title: `Open rule ${row.name || row.position} from review hotspot`,
    "aria-label": `Open rule ${row.name || row.position} from review hotspot`,
    dataset: { rulebaseReviewRow: row.name || "", rulebaseReviewIndex: String(row.index) },
    onclick: () => {
      const targetRoot = root || document.querySelector("#content > div");
      if (targetRoot) {
        filter = { ...DEFAULT_FILTER, ...ruleRouteTargetState(rule || row) };
        syncRoute();
        rerender(targetRoot);
      }
      openRuleEditor(row.index, undefined, { preserveSelection: true });
    },
  },
    h("span", {}, `#${row.position}`),
    h("strong", {}, row.name || `Rule ${row.position}`),
    h("small", {}, row.issues.join(" · ")),
    row.change ? pill(row.change, "info") : null,
    row.dependencies?.total ? pill(`${row.dependencies.total} refs`, "neutral") : null);
}

function openServerOverlapReviewFromFinding(finding = {}, root) {
  const indexes = normalizedRuleIndexes(finding.indexes || [], (session.draft.rules || []).length);
  filter = { ...DEFAULT_FILTER, ...(finding.filter || { q: "server-overlap" }) };
  selectedRuleIndexes = new Set(indexes);
  setRuleReviewDrawerRoute("server-overlap-review");
  const targetRoot = root || document.querySelector("#content > div");
  if (targetRoot) {
    rerender(targetRoot);
  }
}

function setRuleFilter(next = {}) {
  filter = { ...DEFAULT_FILTER, ...next };
  selectedRuleIndexes.clear();
  syncRoute();
  const root = document.querySelector("#content > div");
  if (root) rerender(root);
}

function selectRuleByIndex(idx) {
  const rule = (session.draft.rules || [])[idx];
  filter = { ...filter, ...ruleRouteTargetState(rule || {}) };
  syncRoute();
  openRuleEditor(idx, undefined, { preserveSelection: true });
}

function maybeOpenSelectedRule() {
  const targetKey = routeRuleTargetKey(filter);
  if (!targetKey || targetKey === autoOpenedRule || simulatorQueryActive) return;
  const matches = (session.draft.rules || [])
    .map((rule, idx) => ({ rule, idx }))
    .filter(({ rule, idx }) => ruleMatchesRouteTarget(rule, idx, filter));
  if (matches.length !== 1) return;
  autoOpenedRule = targetKey;
  setTimeout(() => openRuleEditor(matches[0].idx, undefined, { preserveSelection: true }), 0);
}

function ruleRow(r, idx, shadowedBy, root, opts = {}) {
  const act = fmt.ruleAction(r.action);
  const counter = runningCounters.get("rule:" + (r.name || ""));
  const coverage = ruleInspectionCoverage(session.draft || {}, r);
  const selected = selectedRuleIndexes.has(idx);
  const routeFocused = ruleMatchesRouteTarget(r, idx, filter);
  const reorderEnabled = opts.reorderEnabled !== false;
  const change = opts.change || null;
  const verification = ruleVerificationStatus(r, change, ruleVerificationState);
  const tr = h("tr", {
    ...keyboardRowAttrs(() => selectRuleByIndex(idx), {
      className: [
        r.disabled ? "row-disabled" : "",
        selected ? "row-selected" : "",
        routeFocused ? "selected-row route-focused-row" : "",
        change ? `rule-change-${change.kind}` : "",
        "clickable",
      ].filter(Boolean).join(" "),
      label: `Open rule ${r.name || idx + 1}`,
    }),
    "aria-current": routeFocused ? "true" : null,
    draggable: reorderEnabled ? "true" : null,
    dataset: { idx, rulePosition: `#${idx + 1}`, ruleName: r.name || "(unnamed)", ruleChange: change?.kind || "unchanged" },
  },
    h("td", { class: "rule-select-cell", "data-label": "Select" }, ruleSelectionCheckbox(idx, root)),
    h("td", { class: "drag-handle", "data-label": "#", title: "Drag to reorder", html: icon("rules", 14) }),
    h("td", { "data-label": "On" }, toggle(!r.disabled, async (on) => {
      try { await session.apply((d) => { d.rules[idx].disabled = !on; }); rerender(root); }
      catch (e) { toast("Could not stage change", e.message, "bad"); }
    })),
    h("td", { "data-label": "Name", onclick: () => selectRuleByIndex(idx) },
      h("div", { class: "rule-name-head" }, h("strong", {}, r.name || h("span", { class: "muted" }, "(unnamed)")),
        ruleChangeBadge(change),
        change ? ruleVerificationBadge(verification) : null,
        r.log ? h("span", { class: "muted", title: "Logging enabled", html: icon("inbox", 13) }) : null,
        shadowedBy != null ? pill("shadowed", "warn") : null),
      r.description ? h("div", { class: "note rule-description" }, r.description) : null),
    h("td", { "data-label": "Tags", onclick: () => selectRuleByIndex(idx) }, tagList(r.tags)),
    h("td", { "data-label": "From → To", onclick: () => selectRuleByIndex(idx) },
      h("span", { class: "rule-zone-path" },
        zoneList(r.fromZones), h("span", { class: "muted", html: icon("arrowRight", 13) }), zoneList(r.toZones))),
    h("td", { "data-label": "Source", onclick: () => selectRuleByIndex(idx) }, refList(r.sourceAddresses)),
    h("td", { "data-label": "Destination", onclick: () => selectRuleByIndex(idx) }, refList(r.destinationAddresses)),
    h("td", { "data-label": "Service", onclick: () => selectRuleByIndex(idx) }, refList(r.services)),
    h("td", { "data-label": "App-ID", onclick: () => selectRuleByIndex(idx) }, refList(r.applications)),
    h("td", { "data-label": "Identity / posture", onclick: () => selectRuleByIndex(idx) }, matchContextList(r.matchContext)),
    h("td", { "data-label": "Profiles", onclick: () => selectRuleByIndex(idx) }, securityProfileList(r.securityProfiles)),
    h("td", { "data-label": "QoS", onclick: () => selectRuleByIndex(idx) }, qosProfileCell(r.qosProfile)),
    h("td", { "data-label": "Inspection", onclick: () => selectRuleByIndex(idx) }, inspectionCoverageCell(coverage)),
    h("td", { "data-label": "Action", onclick: () => selectRuleByIndex(idx) }, pill(act.label, act.cls, true)),
    h("td", { class: "counter-cell", "data-label": "Running hits", onclick: () => selectRuleByIndex(idx) }, counterValue(counter)),
    h("td", { class: "rules-actions-cell", "data-label": "Actions" }, rowMenu(r, idx, root, { reorderEnabled, ruleCount: opts.ruleCount })));
  if (shadowedBy != null) tr.title = `Never matches: fully covered by rule #${shadowedBy + 1} above`;
  return tr;
}

function ruleChangeBadge(change) {
  if (!change) return null;
  const labels = {
    added: "added",
    modified: "modified",
    moved: "moved",
  };
  const label = labels[change.kind];
  if (!label) return null;
  return h("span", {
    class: `rule-change-badge ${change.kind}`,
    title: change.runningIndex >= 0 ? `Running rule #${change.runningIndex + 1}` : "Candidate-only rule",
  }, label);
}

function ruleSelectionCheckbox(idx, root) {
  const rule = session.draft?.rules?.[idx];
  const label = `Select rule ${rule?.name || idx + 1}`;
  const input = h("input", {
    type: "checkbox",
    title: label,
    "aria-label": label,
    dataset: { ruleSelect: "row" },
    onclick: (e) => e.stopPropagation(),
    onchange: (e) => {
      if (e.target.checked) selectedRuleIndexes.add(idx);
      else selectedRuleIndexes.delete(idx);
      rerender(root);
    },
  });
  input.checked = selectedRuleIndexes.has(idx);
  return h("label", { class: "rule-select", onclick: (e) => e.stopPropagation() }, input);
}

function counterMap(counters = []) {
  const out = new Map();
  for (const counter of counters) {
    if (!counter?.comment) continue;
    out.set(counter.comment, counter);
  }
  return out;
}

function counterValue(counter) {
  if (!counter) {
    return h("span", { class: "muted" }, "—");
  }
  const packets = fmt.num(counter.packets);
  const bytes = fmt.num(counter.bytes);
  return h("span", { class: "rule-counter", title: `${packets} packets / ${fmt.bytes(bytes)} matched in running policy ${counterPolicyLabel()}` },
    h("strong", {}, fmt.compactNum(packets)),
    h("span", {}, fmt.bytes(bytes)));
}

function inspectionCoverageCell(coverage) {
  return h("span", {
    class: "rule-inspection " + coverage.cls,
    title: coverage.detail,
    dataset: {
      ruleInspectionState: coverage.state,
      ruleInspectionBypass: coverage.bypassPossible ? "true" : "false",
    },
  },
    pill(coverage.label, coverage.cls, true),
    h("small", {}, coverage.detail));
}

function counterPolicyLabel() {
  return counterPolicyVersion > 0 ? `v${counterPolicyVersion}` : "version unknown";
}

function rowMenu(r, idx, root, opts = {}) {
  const reorderEnabled = Boolean(opts.reorderEnabled);
  const ruleCount = Number(opts.ruleCount || 0);
  const btn = (ico, title, fn, data = {}, attrs = {}) => h("button", {
    class: "icon-btn",
    type: "button",
    title,
    "aria-label": title,
    dataset: data,
    onclick: (e) => { e.stopPropagation(); fn(); },
    html: icon(ico, 16),
    ...attrs,
  });
  const actions = [
    btn("search", "Explain representative flow", () => openRuleEvidence(r, "explain"), { ruleAction: "explain", ruleName: r.name || "" }),
    btn("terminal", "Capture representative flow", () => openRuleEvidence(r, "capture"), { ruleAction: "capture", ruleName: r.name || "" }),
  ];
  if (reorderEnabled) {
    actions.push(
      btn("rules", "Move rule up", () => moveRule(idx, -1, root), { ruleAction: "move-up", ruleName: r.name || "" }, { disabled: idx <= 0 }),
      btn("rules", "Move rule down", () => moveRule(idx, 1, root), { ruleAction: "move-down", ruleName: r.name || "" }, { disabled: idx >= ruleCount - 1 }),
    );
  }
  actions.push(
    btn("edit", "Edit", () => selectRuleByIndex(idx), { ruleAction: "edit", ruleName: r.name || "" }),
    btn("copy", "Duplicate", async () => {
      try { await session.apply((d) => { const c = structuredClone(d.rules[idx]); c.name = uniqueName(d.rules, (c.name || "rule") + "-copy"); assignFreshRuleId(c, d.rules); d.rules.splice(idx + 1, 0, c); }); selectedRuleIndexes.clear(); rerender(root); toast("Rule duplicated", "Staged to candidate with a fresh durable rule ID.", "ok"); }
      catch (e) { toast("Failed", e.message, "bad"); }
    }, { ruleAction: "duplicate", ruleName: r.name || "" }),
    btn("plus", "Insert rule below", () => openRuleEditor(null, idx + 1), { ruleAction: "insert-below", ruleName: r.name || "" }),
    btn("trash", "Delete", async () => {
      if (!(await confirmDialog({ title: "Delete rule?", message: `Delete "${r.name || "this rule"}"? This stages to the candidate; nothing changes on the firewall until you commit.`, confirmLabel: "Delete", danger: true }))) return;
      try { await session.apply((d) => d.rules.splice(idx, 1)); selectedRuleIndexes.clear(); rerender(root); toast("Rule deleted", "Staged to candidate.", "ok"); }
      catch (e) { toast("Failed", e.message, "bad"); }
    }, { ruleAction: "delete", ruleName: r.name || "" }),
  );
  return h("div", { class: "rules-row-actions" }, actions);
}

async function moveRule(idx, delta, root) {
  const from = Number(idx);
  const to = from + Number(delta);
  const rules = session.draft?.rules || [];
  if (!Number.isInteger(from) || !Number.isInteger(to) || from < 0 || to < 0 || from >= rules.length || to >= rules.length) {
    toast("Move unavailable", "Rule is already at the edge of the ordered rulebase.", "warn");
    return;
  }
  const movedName = rules[from]?.name || "rule";
  try {
    await session.apply((d) => {
      const [moved] = d.rules.splice(from, 1);
      d.rules.splice(to, 0, moved);
    });
    selectedRuleIndexes.clear();
    rerender(root);
    toast("Rule moved", `Staged ${movedName} to position #${to + 1}. Rebuild open reviews before staging more changes.`, "ok");
  } catch (e) {
    toast("Move failed", e.message, "bad");
  }
}

function openRuleEvidence(rule = {}, mode = "explain") {
  const evidence = representativeFlowFromRule(session.draft || {}, rule, {
    source: session.dirty ? "POLICY_SOURCE_CANDIDATE" : "POLICY_SOURCE_RUNNING",
  });
  if (!evidence.ok) {
    toast("Representative flow unavailable", evidence.warnings[0] || "Use Flow check to enter concrete tuple fields for this broad rule.", "warn");
    return;
  }
  if (mode === "capture") {
    location.hash = rulesTroubleshootHash(evidence.simulator, { run: true, intent: "capture" });
    return;
  }
  const nextFilter = { ...filter, ...ruleRouteTargetState(rule) };
  location.hash = rulesFlowCheckHash(routePath, nextFilter, evidence.simulator, {
    density: tableDensity,
    group: tableGroup,
    run: true,
  });
}

function zoneList(arr) {
  return h("span", {}, (fmt.namesOrAny(arr)).map((z) => h("span", { class: "tag" }, z)));
}
function refList(arr) {
  const items = fmt.namesOrAny(arr);
  return h("span", {}, items.slice(0, 3).map((x) => h("span", { class: "tag" }, x)),
    items.length > 3 ? h("span", { class: "muted" }, ` +${items.length - 3}`) : null);
}
function securityProfileList(arr) {
  const items = (arr || []).filter(Boolean);
  if (!items.length) return h("span", { class: "muted" }, "none");
  const profileByName = new Map((session.draft.securityProfiles || []).map((profile) => [profile.name, profile]));
  return h("span", { dataset: { ruleProfileList: "true" } }, items.slice(0, 3).map((name) => {
    const profile = profileByName.get(name) || {};
    const decrypt = profile.tlsInspection === "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED";
    return h("span", { class: "tag", title: securityProfileSummary(profile, name) }, decrypt ? `${name} (decrypt intent)` : name);
  }), items.length > 3 ? h("span", { class: "muted" }, ` +${items.length - 3}`) : null);
}

function qosProfileCell(name = "") {
  const ref = String(name || "").trim();
  if (!ref) return h("span", { class: "muted" }, "none");
  const profile = (session.draft.qosProfiles || []).find((item) => item?.name === ref) || {};
  return h("span", { class: "tag", title: qosProfileSummary(profile, ref) }, ref);
}

function qosProfileSummary(profile = {}, fallback = "") {
  if (!profile?.name) return `${fallback || "QoS profile"} is not defined in the candidate.`;
  return [
    profile.maxBandwidthKbps ? `max ${profile.maxBandwidthKbps} Kbps` : "",
    profile.guaranteedBandwidthKbps ? `min ${profile.guaranteedBandwidthKbps} Kbps` : "",
    profile.priority ? profile.priority.replace(/^QOS_PRIORITY_/, "").toLowerCase().replace(/_/g, " ") : "",
    profile.dscpMark ? `DSCP ${profile.dscpMark}` : "",
  ].filter(Boolean).join(" · ") || "plan-only shaping intent";
}

function matchContextList(ctx = {}) {
  const items = ruleMatchContextDisplayItems(ctx);
  if (!items.length) return h("span", { class: "muted" }, "none");
  return h("span", { dataset: { ruleMatchContextList: "true" } },
    items.slice(0, 4).map((item) => h("span", { class: "tag", title: item.title }, item.label)),
    items.length > 4 ? h("span", { class: "muted" }, ` +${items.length - 4}`) : null);
}

export function ruleMatchContextValues(ctx = {}) {
  if (!ctx) return [];
  return [
    ...(ctx.users || []),
    ...(ctx.groups || []),
    ...(ctx.devices || []),
    ...(ctx.postureLabels || []),
  ].filter(Boolean);
}

function ruleMatchContextDisplayItems(ctx = {}) {
  const rows = [
    ["user", ctx?.users || []],
    ["group", ctx?.groups || []],
    ["device", ctx?.devices || []],
    ["posture", ctx?.postureLabels || []],
  ];
  const items = [];
  for (const [kind, values] of rows) {
    for (const value of values || []) {
      if (!value) continue;
      items.push({ label: `${kind}:${value}`, title: "Policy context label; live IdP/MDM lookup is not configured by this rule." });
    }
  }
  return items;
}

function tagList(arr) {
  const items = (arr || []).filter(Boolean);
  if (!items.length) return h("span", { class: "muted" }, "none");
  return h("span", {}, items.slice(0, 3).map((x) => h("span", { class: "tag" }, x)),
    items.length > 3 ? h("span", { class: "muted" }, ` +${items.length - 3}`) : null);
}

function toggle(checked, onChange) {
  const input = h("input", { type: "checkbox", onclick: (e) => e.stopPropagation(), onchange: (e) => onChange(e.target.checked) });
  input.checked = checked;
  return h("label", { class: "switch", onclick: (e) => e.stopPropagation() }, input, h("span", { class: "slider" }));
}

// ---------- Shadow analysis ----------
export function computeRuleHygiene(rules = [], counters = new Map(), hasCounters = false, policy = {}, validationCleanup = {}) {
  const shadowOf = computeShadows(rules);
  const shadowed = [];
  const broadAllows = [];
  const bypassRisk = [];
  const missingLogs = [];
  const validationMissingLogs = normalizedRuleIndexes(validationCleanup.missingLogs || [], rules.length);
  const validationOverlaps = normalizedRuleIndexes(validationCleanup.overlaps || [], rules.length);
  const validationOverlapFindings = Array.isArray(validationCleanup.overlapFindings) ? validationCleanup.overlapFindings : [];
  const validationOverlapFindingLimit = Number(validationCleanup.overlapFindingLimit || SERVER_OVERLAP_FINDING_LIMIT);
  const validationOverlapsMayBeTruncated = Boolean(validationCleanup.overlapFindingsMayBeTruncated || validationOverlapFindings.length >= validationOverlapFindingLimit);
  const hostInputRuleCount = Array.isArray(policy.hostInput?.rules) ? policy.hostInput.rules.length : 0;
  const hostInputMissingLogs = normalizedRuleIndexes(validationCleanup.hostInputMissingLogs || [], hostInputRuleCount);
  const unusedObjects = unusedObjectSummaries(validationCleanup.unusedObjects || [], policy);
  const staleZeroHit = [];
  const nameCounts = new Map();
  rules.forEach((rule, idx) => {
    if (rule?.name) nameCounts.set(rule.name, (nameCounts.get(rule.name) || 0) + 1);
    if (shadowOf[idx] != null) shadowed.push(idx);
    if (ruleActive(rule) && ruleAllows(rule) && broadRule(rule)) broadAllows.push(idx);
    if (ruleActive(rule) && ruleAllows(rule) && ruleInspectionCoverage(policy, rule).bypassPossible) bypassRisk.push(idx);
    if (ruleActive(rule) && rule.log !== true) missingLogs.push(idx);
    const counter = counters.get("rule:" + (rule?.name || ""));
    if (hasCounters && ruleActive(rule) && counter && fmt.num(counter.packets) === 0 && fmt.num(counter.bytes) === 0) {
      staleZeroHit.push(idx);
    }
  });
  const duplicateNames = [...nameCounts.entries()].filter(([, count]) => count > 1).map(([name]) => name);
  const duplicateIndexes = duplicateNames.length
    ? rules.map((rule, idx) => duplicateNames.includes(rule?.name) ? idx : -1).filter((idx) => idx >= 0)
    : [];
  const findings = [];
  if (shadowed.length) {
    findings.push({
      title: "Shadowed rules",
      detail: "Fully covered by earlier rules.",
      count: String(shadowed.length),
      cls: "warn",
      filter: { q: "shadowed" },
      indexes: shadowed,
    });
  }
  if (duplicateNames.length) {
    findings.push({
      title: "Duplicate names",
      detail: "Counters and audit comments become ambiguous.",
      count: String(duplicateNames.length),
      cls: "bad",
      filter: { q: duplicateNames[0] || "" },
      indexes: duplicateIndexes,
    });
  }
  if (broadAllows.length) {
    findings.push({
      title: "Broad allows",
      detail: "Any-to-any active allow paths need review.",
      count: String(broadAllows.length),
      cls: "bad",
      filter: { q: "broad-allow" },
      indexes: broadAllows,
    });
  }
  if (bypassRisk.length) {
    findings.push({
      title: "Bypass-risk allows",
      detail: "Allow paths can bypass inspection under current policy.",
      count: String(bypassRisk.length),
      cls: "bad",
      filter: { q: "bypass-risk" },
      routeHref: "#/inspection",
      routeLabel: "Open inspection",
      indexes: bypassRisk,
    });
  }
  if (missingLogs.length) {
    const confirmed = validationMissingLogs.length ? ` Server validation confirmed ${validationMissingLogs.length}.` : "";
    findings.push({
      title: "Missing logs",
      detail: "Enabled rules without logging reduce investigation evidence." + confirmed,
      count: String(missingLogs.length),
      cls: "warn",
      filter: { q: "missing-log" },
      fix: "log-on",
      indexes: missingLogs,
    });
  }
  if (validationOverlaps.length) {
    findings.push({
      title: "Server rule overlaps",
      detail: "Policy validation found partial match overlap; first-match order decides the verdict.",
      count: String(validationOverlaps.length),
      cls: "warn",
      filter: { q: "server-overlap" },
      fix: "review-overlap",
      indexes: validationOverlaps,
      overlapFindings: validationOverlapFindings.filter((item) => validationOverlaps.includes(Number(item?.index))),
      overlapFindingLimit: validationOverlapFindingLimit,
      overlapFindingsMayBeTruncated: validationOverlapsMayBeTruncated,
    });
  }
  if (hostInputMissingLogs.length) {
    findings.push({
      title: "Host-input missing logs",
      detail: "Management-plane allow rules without logging reduce admin ingress evidence.",
      count: String(hostInputMissingLogs.length),
      cls: "warn",
      fix: "host-input-log-on",
      indexes: hostInputMissingLogs,
      settingsPanel: "host-input",
    });
  }
  for (const item of unusedObjects) {
    findings.push({
      title: item.title,
      detail: item.detail,
      count: String(item.count),
      cls: "info",
      href: item.href,
      objectKind: item.kind,
      names: item.names,
    });
  }
  if (staleZeroHit.length) {
    findings.push({
      title: "Zero-hit running rules",
      detail: "Committed rules with no observed matches.",
      count: String(staleZeroHit.length),
      cls: "info",
      filter: { q: "zero-hit" },
      indexes: staleZeroHit,
    });
  }
  return { shadowOf, shadowed, duplicateNames, duplicateIndexes, broadAllows, bypassRisk, missingLogs, validationMissingLogs, validationOverlaps, validationOverlapFindings, validationOverlapFindingLimit, validationOverlapsMayBeTruncated, hostInputMissingLogs, unusedObjects, staleZeroHit, findings };
}

function unusedObjectSummaries(unusedObjects = [], policy = {}) {
  const byKind = new Map();
  for (const item of Array.isArray(unusedObjects) ? unusedObjects : []) {
    const normalized = unusedObjectModel(item, policy);
    if (!normalized) continue;
    const group = byKind.get(normalized.kind) || [];
    group.push(normalized);
    byKind.set(normalized.kind, group);
  }
  return [...byKind.entries()].map(([kind, items]) => {
    const names = [...new Set(items.map((item) => item.name).filter(Boolean))];
    const label = unusedObjectKindLabel(kind);
    const preview = names.slice(0, 4).join(", ");
    return {
      kind,
      names,
      count: items.length,
      href: names.length === 1 ? objectReferenceHash(kind, names[0]) : objectKindHash(kind),
      title: `Unused ${label}`,
      detail: preview
        ? `${preview}${names.length > 4 ? `, +${names.length - 4} more` : ""} not referenced by candidate policy.`
        : `${items.length} ${label} object${items.length === 1 ? "" : "s"} not referenced by candidate policy.`,
    };
  });
}

function unusedObjectModel(item = {}, policy = {}) {
  const kind = ["address", "service", "application"].includes(item.kind) ? item.kind : "";
  if (!kind || !Number.isInteger(item.index) || item.index < 0) return null;
  const collection = kind === "address" ? policy.addresses : kind === "service" ? policy.services : policy.applications;
  const obj = Array.isArray(collection) ? collection[item.index] : null;
  const detailName = unusedObjectNameFromText(item.detail || item.message || "");
  return {
    ...item,
    kind,
    name: obj?.name || detailName || `${kind}[${item.index}]`,
  };
}

function unusedObjectNameFromText(text = "") {
  const match = String(text || "").trim().match(/^([^,\s]+)\s+is\s+not\s+referenced\b/i);
  return match ? match[1] : "";
}

function unusedObjectKindLabel(kind = "") {
  if (kind === "address") return "addresses";
  if (kind === "service") return "services";
  if (kind === "application") return "applications";
  return "objects";
}

function computeShadows(rules) {
  const out = new Array(rules.length).fill(null);
  for (let i = 0; i < rules.length; i++) {
    if (rules[i].disabled) continue;
    for (let j = 0; j < i; j++) {
      if (rules[j].disabled) continue;
      if (covers(rules[j], rules[i])) { out[i] = j; break; }
    }
  }
  return out;
}
function ruleActive(rule) {
  return rule && !rule.disabled;
}
function ruleAllows(rule) {
  return rule && rule.action === "ACTION_ALLOW";
}
function ruleBlocks(rule) {
  return rule && (rule.action === "ACTION_DENY" || rule.action === "ACTION_REJECT");
}
function anyToken(values) {
  return !values || values.length === 0 || values.includes("any");
}
function broadRule(rule) {
  return anyToken(rule?.fromZones) && anyToken(rule?.toZones) &&
    anyToken(rule?.sourceAddresses) && anyToken(rule?.destinationAddresses) &&
    anyToken(rule?.services);
}
function coversDim(a, b) {
  const aAny = !a || a.length === 0 || a.includes("any");
  if (aAny) return true;
  const bAny = !b || b.length === 0 || b.includes("any");
  if (bAny) return false;
  return b.every((x) => a.includes(x));
}
function covers(a, b) {
  return coversDim(a.fromZones, b.fromZones) && coversDim(a.toZones, b.toZones) &&
    coversDim(a.sourceAddresses, b.sourceAddresses) && coversDim(a.destinationAddresses, b.destinationAddresses) &&
    coversDim(a.services, b.services);
}

function uniqueName(rules, base) {
  const names = new Set(rules.map((r) => r.name));
  if (!names.has(base)) return base;
  let i = 2; while (names.has(base + "-" + i)) i++; return base + "-" + i;
}

export function freshRuleId(rules = [], opts = {}) {
  const existing = new Set((Array.isArray(rules) ? rules : []).map((rule) => normalizedRuleId(rule)).filter(Boolean));
  const base = sanitizeRuleId(opts.name || "rule");
  const seed = sanitizeRuleId(opts.seed || "");
  for (let attempt = 0; attempt < 24; attempt += 1) {
    const suffix = seed && attempt === 0 ? seed : randomRuleIdSuffix();
    const id = `${base}-${suffix}`.slice(0, 80).replace(/-+$/g, "");
    if (id && !existing.has(id)) return id;
  }
  let n = existing.size + 1;
  while (existing.has(`${base}-${n}`)) n += 1;
  return `${base}-${n}`;
}

export function assignFreshRuleId(rule = {}, rules = [], opts = {}) {
  const next = rule && typeof rule === "object" ? rule : {};
  next.id = freshRuleId(rules, { name: next.name || opts.name, seed: opts.seed });
  return next;
}

function sanitizeRuleId(value = "") {
  let out = String(value || "rule").trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  if (!out) out = "rule";
  if (!/^[a-z]/.test(out)) out = "rule-" + out;
  return out.slice(0, 48).replace(/-+$/g, "") || "rule";
}

function randomRuleIdSuffix() {
  const cryptoObj = globalThis.crypto;
  if (cryptoObj?.randomUUID) return cryptoObj.randomUUID().replace(/-/g, "").slice(0, 12);
  if (cryptoObj?.getRandomValues) {
    const bytes = new Uint8Array(6);
    cryptoObj.getRandomValues(bytes);
    return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  return `${Date.now().toString(36)}${Math.floor(Math.random() * 0x1000000).toString(36)}`.slice(0, 12);
}

// ---------- Drag & drop reorder ----------
function enableDnD(tbody, root) {
  let from = null;
  tbody.querySelectorAll("tr").forEach((tr) => {
    tr.addEventListener("dragstart", (e) => {
      if (!e.target?.closest?.(".drag-handle")) {
        from = null;
        e.preventDefault();
        return;
      }
      from = Number(tr.dataset.idx);
      tr.classList.add("dragging");
      e.dataTransfer.effectAllowed = "move";
    });
    tr.addEventListener("dragend", () => { tr.classList.remove("dragging"); tbody.querySelectorAll(".drop-target").forEach((x) => x.classList.remove("drop-target")); });
    tr.addEventListener("dragover", (e) => { e.preventDefault(); tbody.querySelectorAll(".drop-target").forEach((x) => x.classList.remove("drop-target")); tr.classList.add("drop-target"); });
    tr.addEventListener("drop", async (e) => {
      e.preventDefault();
      const to = Number(tr.dataset.idx);
      if (from == null || from === to) return;
      try {
        await session.apply((d) => { const [m] = d.rules.splice(from, 1); d.rules.splice(to, 0, m); });
        selectedRuleIndexes.clear();
        rerender(root);
      } catch (err) { toast("Reorder failed", err.message, "bad"); }
    });
  });
}

function openBaselineSetup(root) {
  let profileId = "throughput";
  const existingZones = session.draft.zones || [];
  const insideName = h("input", { class: "input", value: existingZones.find((z) => z.name === "lan")?.name || "lan" });
  const outsideName = h("input", { class: "input", value: existingZones.find((z) => z.name === "wan")?.name || "wan" });
  const insideIfaces = h("input", { class: "input", value: existingZones.find((z) => z.name === "lan")?.interfaces?.join(", ") || "eth1", placeholder: "eth1, ens4" });
  const outsideIfaces = h("input", { class: "input", value: existingZones.find((z) => z.name === "wan")?.interfaces?.join(", ") || "eth0", placeholder: "eth0, ens3" });
  const insideCidr = h("input", { class: "input", value: "10.0.0.0/24", placeholder: "10.0.0.0/24" });
  const webuiPort = h("input", { class: "input", type: "number", min: "1", max: "65535", value: "8080" });
  const mtu = h("input", { class: "input", type: "number", min: "1280", max: "9600", placeholder: "optional" });
  const outbound = toggleField(true, () => {});
  const masquerade = toggleField(true, () => {});
  const hostInput = toggleField(true, () => {});
  const flowOffload = toggleField(true, () => {});
  const clampMss = toggleField(true, () => {});
  const nicOffloads = toggleField(false, () => {});
  const profileWrap = h("div", { class: "profile-options" });
  const renderProfiles = () => {
    clear(profileWrap);
    BASELINE_PROFILES.forEach((profile) => {
      profileWrap.appendChild(h("button", { class: "profile-option " + (profile.id === profileId ? "active" : ""), ...actionControlAttrs({ ruleBaselineProfile: profile.id }, `Select ${profile.title} baseline posture`, { onclick: () => {
        profileId = profile.id;
        flowOffload.checked = profile.id === "throughput";
        nicOffloads.checked = profile.id === "ids-detect";
        renderProfiles();
      } }) },
        h("span", {}, profile.title),
        h("small", {}, profile.summary)));
    });
  };
  renderProfiles();

  openDrawer({
    title: "Set up baseline policy",
    subtitle: "Stages a candidate only. Validate and commit after reviewing the diff.",
    width: "720px",
    body: h("div", {},
      h("div", { class: "alert-box info" },
        h("strong", {}, "Two-zone starting point."),
        h("div", { class: "note" }, "Creates zones, reusable objects, an outbound rule, optional SNAT, host-input hardening, and the selected inspection or acceleration posture.")),
      h("div", { class: "profile-strip" },
        h("strong", {}, "Baseline posture"),
        profileWrap),
      h("div", { class: "form-grid two" },
        field("Inside zone", insideName),
        field("Outside zone", outsideName),
        field("Inside interfaces", insideIfaces, "comma-separated"),
        field("Outside interfaces", outsideIfaces, "comma-separated"),
        field("Inside network", insideCidr, "CIDR object used by rules"),
        field("WebUI/API port", webuiPort, "host-input management service")),
      h("hr", { class: "divider" }),
      h("div", { class: "grid cols-2" },
        baselineToggle("Allow inside to outside", "Adds a logged outbound allow rule.", outbound),
        baselineToggle("Masquerade to outside", "Adds source NAT for inside clients.", masquerade),
        baselineToggle("Harden host input", "Default drop with inside SSH/WebUI allow.", hostInput),
        baselineToggle("Flowtable fast path", "Accelerates established forwarded flows when IDS/IPS is off.", flowOffload),
        baselineToggle("Clamp TCP MSS", "Avoids blackholes when path MTU changes.", clampMss),
        baselineToggle("Manage IDS NIC offloads", "Useful only when IDS detect mode is enabled.", nicOffloads)),
      field("Global MTU", mtu, "leave blank unless the path supports jumbo frames")),
    footer: [
      h("button", { class: "btn ghost", ...actionControlAttrs({ ruleBaselineAction: "cancel" }, "Cancel baseline setup", { onclick: closeDrawer }) }, "Cancel"),
      h("button", { class: "btn primary", ...actionControlAttrs({ ruleBaselineAction: "stage" }, "Stage baseline policy", { onclick: async () => {
        let summary = null;
        try {
          if (sameSetupName(insideName.value, outsideName.value)) {
            toast("Distinct zones required", "Use different names for inside and outside zones.", "warn");
            return;
          }
          await session.apply((d) => {
            summary = applyBaselinePolicy(d, {
              insideZone: insideName.value,
              outsideZone: outsideName.value,
              insideInterfaces: insideIfaces.value,
              outsideInterfaces: outsideIfaces.value,
              insideCidr: insideCidr.value,
              profile: profileId,
              webuiPort: webuiPort.value,
              mtu: mtu.value,
              allowOutbound: outbound.checked,
              masquerade: masquerade.checked,
              hardenHostInput: hostInput.checked,
              flowOffload: flowOffload.checked,
              clampMss: clampMss.checked,
              manageNicOffloads: nicOffloads.checked,
            });
          });
          closeDrawer();
          rerender(root);
          toast("Baseline staged", baselineSummary(summary), "ok");
        } catch (e) {
          toast("Could not stage baseline", e.message, "bad");
        }
      } }) }, h("span", { html: icon("check", 16) }), "Stage baseline"),
    ],
  });
}

function sameSetupName(a, b) {
  return String(a || "").trim().toLowerCase() === String(b || "").trim().toLowerCase();
}

function baselineToggle(title, detail, control) {
  return h("div", { class: "posture-metric baseline-toggle" },
    h("span", { class: "baseline-toggle-copy" },
      h("strong", {}, title),
      h("span", { class: "note" }, detail)),
    control);
}

function baselineSummary(summary) {
  if (!summary) return "Candidate updated.";
  const parts = [];
  if (summary.zones.length) parts.push(`${summary.zones.length} zones`);
  if (summary.rules.length) parts.push(`${summary.rules.length} rule`);
  if (summary.nat.length) parts.push("SNAT");
  if (summary.hostInput.length) parts.push("host input");
  if (summary.network.length) parts.push(summary.network.join(", "));
  return parts.length ? parts.join(" · ") : "Candidate updated.";
}

// ---------- Rule editor (also used by Threats/Traffic pivots) ----------
export function openRuleEditor(idx, insertAt, opts = {}) {
  const editing = idx != null;
  const base = editing ? structuredClone(session.draft.rules[idx])
    : { name: "", fromZones: [], toZones: [], sourceAddresses: [], destinationAddresses: [], services: [], applications: [], tags: [], action: "ACTION_ALLOW", log: false, disabled: false, description: "", qosProfile: "" };
  if (!editing) delete base.id;
  buildEditor(base, editing, idx, insertAt, opts);
}

// Open the editor for a fully-prefilled new rule (used by Threats/Traffic
// pivots). insertAt places the new rule at a specific index.
export function openRuleEditorPrefilled(rule, insertAt, opts = {}) {
  const base = structuredClone(rule || {});
  delete base.id;
  buildEditor(base, false, null, insertAt, opts);
}

function buildEditor(rule, editing, idx, insertAt, opts = {}) {
  const zoneOpts = (session.draft.zones || []).map((z) => z.name);
  const addrOpts = (session.draft.addresses || []).map((a) => a.name);
  const svcOpts = (session.draft.services || []).map((s) => s.name);
  const pendingApplications = (opts.pendingApplications || []).filter((app) => app?.name).map((app) => ({
    ...app,
    engineSignals: [...(app.engineSignals || [])],
    ports: cloneApplicationPorts(app.ports || []),
  }));
  const appOpts = [...new Set([
    ...(session.draft.applications || []).map((a) => a.name),
    ...pendingApplications.map((a) => a.name),
  ].filter(Boolean))];
  const pendingObjects = { addresses: [], services: [], applications: pendingApplications };
  if (!rule.applications) rule.applications = [];
  if (!rule.securityProfiles) rule.securityProfiles = [];
  if (!rule.tags) rule.tags = [];
  if (!rule.matchContext) rule.matchContext = {};
  if (!rule.qosProfile) rule.qosProfile = "";

  const nameInput = h("input", { class: "input", value: rule.name || "", placeholder: "e.g. allow-lan-to-wan", dataset: { ruleField: "name" }, oninput: (e) => (rule.name = e.target.value.trim()) });
  const actionSel = h("select", { dataset: { ruleField: "action" } }, opt("ACTION_ALLOW", "Allow"), opt("ACTION_DENY", "Drop"), opt("ACTION_REJECT", "Reject (RST/ICMP)"));
  actionSel.value = rule.action; actionSel.onchange = (e) => { rule.action = e.target.value; paintGuards(); };
  const tagsInput = h("input", {
    class: "input",
    value: (rule.tags || []).join(", "),
    placeholder: "env:prod, owner:secops, pci.zone-1",
    dataset: { ruleField: "tags" },
    oninput: (e) => {
      rule.tags = parseTagInput(e.target.value);
      paintGuards();
    },
  });
  const usersInput = h("input", { class: "input", value: (rule.matchContext.users || []).join(", "), placeholder: "alice@example.com", dataset: { ruleField: "match-context-users" }, oninput: (e) => { rule.matchContext.users = parseRuleContextInput(e.target.value); paintGuards(); } });
  const groupsInput = h("input", { class: "input", value: (rule.matchContext.groups || []).join(", "), placeholder: "idp/secops", dataset: { ruleField: "match-context-groups" }, oninput: (e) => { rule.matchContext.groups = parseRuleContextInput(e.target.value); paintGuards(); } });
  const devicesInput = h("input", { class: "input", value: (rule.matchContext.devices || []).join(", "), placeholder: "laptop-123", dataset: { ruleField: "match-context-devices" }, oninput: (e) => { rule.matchContext.devices = parseRuleContextInput(e.target.value); paintGuards(); } });
  const postureInput = h("input", { class: "input", value: (rule.matchContext.postureLabels || []).join(", "), placeholder: "posture:edr-healthy", dataset: { ruleField: "match-context-posture" }, oninput: (e) => { rule.matchContext.postureLabels = parseRuleContextInput(e.target.value); paintGuards(); } });
  const descInput = h("textarea", { class: "input", placeholder: "Why this rule exists (recommended for change tracking)", dataset: { ruleField: "description" }, oninput: (e) => (rule.description = e.target.value) }, rule.description || "");
  const logT = toggleField(rule.log, (v) => (rule.log = v), "log");
  const disT = toggleField(rule.disabled, (v) => (rule.disabled = v), "disabled");
  const tagGuard = h("div", {});
  const contextGuard = h("div", {});
  const appGuard = h("div", {});
  const createAddress = (kind, object) => addPendingRuleEditorObject(pendingObjects, kind, object, addrOpts);
  const createService = (kind, object) => addPendingRuleEditorObject(pendingObjects, kind, object, svcOpts);
  const serviceEditor = tokenEditor(rule.services, svcOpts, { any: true, create: "service", onCreateObject: createService, onChange: paintGuards, field: "services" });
  const appEditor = tokenEditor(rule.applications, appOpts, { any: true, onChange: paintGuards, field: "applications" });
  const securityProfileOpts = (session.draft.securityProfiles || []).map((profile) => profile.name).filter(Boolean);
  const securityProfileEditor = tokenEditor(rule.securityProfiles, securityProfileOpts, { onChange: paintGuards, field: "security-profiles" });
  const qosSel = h("select", { dataset: { ruleField: "qos-profile" }, onchange: (e) => { rule.qosProfile = e.target.value; paintGuards(); } },
    opt("", "No QoS profile"),
    ...(session.draft.qosProfiles || []).map((profile) => opt(profile.name, profile.name)));
  qosSel.value = rule.qosProfile || "";

  const body = h("div", { dataset: { ruleEditor: "true" } },
    field("Name", nameInput, null, "name"),
    field("Tags", tagsInput, "comma-separated; lowercase labels for ownership, environment, compliance, or lifecycle", "tags"),
    tagGuard,
    h("div", { class: "grid cols-2" },
      field("From zones", tokenEditor(rule.fromZones, zoneOpts, { any: true, field: "from-zones" }), null, "from-zones"),
      field("To zones", tokenEditor(rule.toZones, zoneOpts, { any: true, field: "to-zones" }), null, "to-zones")),
    h("div", { class: "grid cols-2" },
      field("Source addresses", tokenEditor(rule.sourceAddresses, addrOpts, { any: true, create: "address", onCreateObject: createAddress, field: "source-addresses" }), null, "source-addresses"),
      field("Destination addresses", tokenEditor(rule.destinationAddresses, addrOpts, { any: true, create: "address", onCreateObject: createAddress, field: "destination-addresses" }), null, "destination-addresses")),
    h("div", { class: "grid cols-2" },
      field("Users", usersInput, "optional context labels; comma-separated", "match-context-users"),
      field("Groups", groupsInput, "optional context labels; comma-separated", "match-context-groups")),
    h("div", { class: "grid cols-2" },
      field("Devices", devicesInput, "optional context labels; comma-separated", "match-context-devices"),
      field("Posture labels", postureInput, "optional context labels; comma-separated", "match-context-posture")),
    contextGuard,
    field("Services", serviceEditor, null, "services"),
    field("Applications", appEditor,
      "allow/drop rules use TCP/UDP port hints; supported IDS/IPS engine App-ID signals add L7 controls when IDS/IPS is Prevent fail closed", "applications"),
    appGuard,
    field("Security profiles", securityProfileEditor,
      "blocking profile intent on allow rules requires IDS/IPS Prevent with Fail closed; TLS decryption, URL databases, and file engines remain separate integrations", "security-profiles"),
    field("QoS profile", qosSel, "plan-only shaping intent; live traffic shaping/packet-filter enforcement proof remains hardening", "qos-profile"),
    field("Action", actionSel, null, "action"),
    h("div", { class: "grid cols-2" },
      field("Log matches", logT, "Record matching connections.", "log"),
      field("Disabled", disT, "Keep the rule but stop enforcing it.", "disabled")),
    field("Description", descInput, null, "description"));
  const saveBtn = h("button", { class: "btn primary", ...actionControlAttrs({ ruleAction: "save-editor" }, editing ? "Save security rule" : "Add security rule", { onclick: () => save() }) }, h("span", { html: icon("check", 16) }), editing ? "Save rule" : "Add rule");
  const saveLabel = editing ? "Save security rule" : "Add security rule";

  openDrawer({
    title: editing ? "Edit rule" : "New rule",
    subtitle: "Changes stage to the candidate — commit to enforce.",
    width: "620px",
    onClose: () => clearRuleSelection(opts),
    body,
    footer: [
      h("button", { class: "btn ghost", ...actionControlAttrs({ ruleAction: "cancel-editor" }, "Cancel rule editor", { onclick: closeDrawer }) }, "Cancel"),
      saveBtn,
    ],
  });
  paintGuards();

  async function save() {
    if (!rule.name) { toast("Name required", "Give the rule a name.", "warn"); return; }
    const issues = editorIssues();
    if (issues.length) {
      paintGuards();
      toast("Rule cannot be staged", issues[0], "warn");
      return;
    }
    try {
      await session.apply((d) => {
        if (!d.rules) d.rules = [];
        if (typeof opts.beforeSave === "function") opts.beforeSave(d, rule);
        applyPendingRuleEditorObjects(d, pendingObjects);
        pruneEmptyRuleMatchContext(rule);
        if (!rule.qosProfile) delete rule.qosProfile;
        if (!editing) assignFreshRuleId(rule, d.rules);
        if (editing) d.rules[idx] = rule;
        else if (insertAt != null) d.rules.splice(insertAt, 0, rule);
        else d.rules.push(rule);
      });
      if (!editing) selectedRuleIndexes.clear();
      if (!editing && opts.caseContext?.caseKey) pinPrefilledCaseRemediation(rule, opts);
      closeDrawer();
      toast(editing ? "Rule saved" : "Rule added", "Staged to candidate.", "ok");
      const root = document.querySelector("#content > div");
      if (location.hash.startsWith("#/rules") && root) rerender(root);
    } catch (e) { toast("Could not stage rule", e.message, "bad"); }
  }

  function editorIssues() {
    return [...tagIssues(rule.tags || []), ...ruleMatchContextIssues(rule.matchContext || {}), ...securityProfileIssues(rule), ...qosProfileIssues(rule), ...appRuleIssues(rule, editorApplications(), session.draft)];
  }

  function paintGuards() {
    if (!appGuard) return;
    const tagProblems = tagIssues(rule.tags || []);
    const contextProblems = ruleMatchContextIssues(rule.matchContext || {});
    const profileProblems = securityProfileIssues(rule);
    const qosProblems = qosProfileIssues(rule);
    const appProblems = appRuleIssues(rule, editorApplications(), session.draft);
    const scoped = hasSpecificRefs(rule.applications);
    clear(tagGuard);
    clear(contextGuard);
    clear(appGuard);
    const issues = [...tagProblems, ...contextProblems, ...profileProblems, ...qosProblems, ...appProblems];
    saveBtn.disabled = issues.length > 0;
    saveBtn.title = issues.length ? issues[0] : saveLabel;
    saveBtn.setAttribute("aria-label", issues.length ? `${saveLabel}: ${issues[0]}` : saveLabel);
    if (tagProblems.length) {
      tagGuard.appendChild(h("div", { class: "alert-box warn" },
        h("strong", {}, "Rule tags cannot be staged. "),
        h("ul", { class: "compact-list" }, ...tagProblems.map((issue) => h("li", {}, issue)))));
    }
    if (contextProblems.length) {
      contextGuard.appendChild(h("div", { class: "alert-box warn" },
        h("strong", {}, "Identity/posture context cannot be staged. "),
        h("ul", { class: "compact-list" }, ...contextProblems.map((issue) => h("li", {}, issue)))));
    } else if (ruleMatchContextValues(rule.matchContext).length) {
      contextGuard.appendChild(h("div", { class: "alert-box info" },
        h("strong", {}, "Policy context only. "),
        "These labels are matched by policy/explain context; live directory, group freshness, MDM posture, and step-up authentication remain hardening integrations."));
    }
    if (appProblems.length) {
      appGuard.appendChild(h("div", { class: "alert-box bad" },
        h("strong", {}, "App-ID rule cannot be staged. "),
        h("ul", { class: "compact-list" }, ...appProblems.map((issue) => h("li", {}, issue)))));
	    } else if (scoped) {
	      const signalOnly = appRuleUsesSignalOnly(rule, editorApplications());
	      appGuard.appendChild(h("div", { class: "alert-box info" },
	        h("strong", {}, "Current App-ID enforcement path. "),
	        signalOnly
	          ? "This signal-only Drop rule is enforced by IDS/IPS engine App-ID signals in IDS/IPS Prevent fail-closed mode; Source/Destination scope is preserved when present."
	          : "This App-ID rule matches the selected object's TCP/UDP port hints, and supported IDS/IPS engine signals add managed L7 allow/drop metadata controls.",
	        " Engine-signal-only App-ID enforcement is a future L7 dataplane milestone."));
	    }
    if (profileProblems.length) {
      appGuard.appendChild(h("div", { class: "alert-box warn" },
        h("strong", {}, "Security profile attachment needs review. "),
        h("ul", { class: "compact-list" }, ...profileProblems.map((issue) => h("li", {}, issue)))));
    }
    if (qosProblems.length) {
      appGuard.appendChild(h("div", { class: "alert-box warn" },
        h("strong", {}, "QoS profile attachment needs review. "),
        h("ul", { class: "compact-list" }, ...qosProblems.map((issue) => h("li", {}, issue)))));
    } else if (rule.qosProfile) {
      appGuard.appendChild(h("div", { class: "alert-box info" },
        h("strong", {}, "Current QoS runtime posture. "),
        "This rule carries bounded shaping intent into validation, diff, and render-plan output; live traffic shaping/packet-filter shaping proof is tracked as hardening."));
    }
  }

  function editorApplications() {
    const byName = new Map();
    for (const app of session.draft.applications || []) {
      if (app?.name) byName.set(app.name, app);
    }
    for (const app of pendingObjects.applications || []) {
      if (app?.name && !byName.has(app.name)) byName.set(app.name, app);
    }
    return [...byName.values()];
  }
}

function clearRuleSelection(opts = {}) {
  if (opts.preserveSelection) {
    filter.ruleId = "";
    filter.rule = "";
    syncRoute();
  }
}

function field(label, control, help, key = "") {
  return h("label", { class: "field", dataset: key ? { ruleFieldWrap: key } : {} }, h("span", {}, label, help ? h("span", { class: "help" }, " — " + help) : null), control);
}
function toggleField(checked, onChange, key = "") {
  const input = h("input", { type: "checkbox", dataset: key ? { ruleField: key } : {}, onchange: (e) => onChange(e.target.checked) });
  input.checked = checked;
  const label = h("label", { class: "switch" }, input, h("span", { class: "slider" }));
  Object.defineProperty(label, "checked", { get: () => input.checked, set: (value) => { input.checked = Boolean(value); } });
  return label;
}

// Chips + add menu. `values` is the live array we mutate. opts.any adds
// "any"; opts.create ("address"|"service") enables inline object creation.
function tokenEditor(values, options, opts = {}) {
  const wrap = h("div", { class: "chips rules-token-editor", dataset: opts.field ? { ruleField: opts.field } : {} });
  const fieldLabel = String(opts.field || "token").replace(/[-_]+/g, " ");
  let creator = null;
  const notify = () => { if (typeof opts.onChange === "function") opts.onChange(values); };
  function repaint() {
    clear(wrap);
    creator = null;
    values.forEach((v, i) => wrap.appendChild(
      h("span", { class: "chip" }, v, h("button", {
        type: "button",
        title: `Remove ${v}`,
        "aria-label": `Remove ${v} from ${fieldLabel}`,
        dataset: { ruleTokenAction: "remove", ruleTokenField: opts.field || "", ruleTokenValue: v },
        onclick: () => { values.splice(i, 1); repaint(); notify(); },
        html: icon("x", 13),
      }))));
    const used = new Set(values);
    const avail = options.filter((o) => !used.has(o));
    const sel = h("select", { class: "rules-token-select" },
      h("option", { value: "" }, "+ add…"),
      opts.any && !used.has("any") ? h("option", { value: "any" }, "any") : null,
      ...avail.map((o) => h("option", { value: o }, o)),
      opts.create ? h("option", { value: "__new__" }, `+ new ${opts.create}…`) : null);
    sel.onchange = () => {
      const v = sel.value;
      if (!v) return;
      if (v === "__new__") {
        sel.value = "";
        if (creator?.isConnected) creator.remove();
        creator = newObject(opts.create, (name, object) => {
          const createdName = typeof opts.onCreateObject === "function"
            ? opts.onCreateObject(opts.create, object, options)
            : name;
          if (!createdName) return;
          if (!values.includes(createdName)) values.push(createdName);
          repaint();
          notify();
        }, {
          nameExists: (name) => ruleObjectNameExists(options, name),
          onCancel: () => { if (creator?.isConnected) creator.remove(); creator = null; },
        });
        wrap.appendChild(creator);
        queueMicrotask(() => creator?.querySelector?.("input")?.focus?.());
        return;
      }
      values.push(v); repaint(); notify();
    };
    wrap.appendChild(sel);
  }
  repaint();
  return wrap;
}

const MAX_RULE_TAG_LENGTH = 64;
const RULE_TAG_RE = /^[a-z0-9][a-z0-9_.:-]{0,63}$/;
const MAX_RULE_TAGS = 32;
const RULE_CONTEXT_RE = /^[a-z0-9][a-z0-9_.:@/-]{0,127}$/;
const MAX_RULE_CONTEXT_VALUES = 64;

export function parseTagInput(value) {
  return String(value || "").split(",").map((part) => part.trim()).filter(Boolean);
}

export function parseRuleContextInput(value) {
  return String(value || "").split(",").map((part) => part.trim()).filter(Boolean);
}

export function ruleMatchContextFromInputs(inputs = {}) {
  const ctx = {};
  const users = parseRuleContextInput(inputs.users);
  const groups = parseRuleContextInput(inputs.groups);
  const devices = parseRuleContextInput(inputs.devices);
  const postureLabels = parseRuleContextInput(inputs.postureLabels);
  if (users.length) ctx.users = users;
  if (groups.length) ctx.groups = groups;
  if (devices.length) ctx.devices = devices;
  if (postureLabels.length) ctx.postureLabels = postureLabels;
  return ctx;
}

export function ruleMatchContextIssues(ctx = {}) {
  const issues = [];
  for (const [field, values] of Object.entries({
    users: ctx?.users || [],
    groups: ctx?.groups || [],
    devices: ctx?.devices || [],
    postureLabels: ctx?.postureLabels || [],
  })) {
    if ((values || []).length > MAX_RULE_CONTEXT_VALUES) {
      issues.push(`${contextFieldLabel(field)} can have at most ${MAX_RULE_CONTEXT_VALUES} values.`);
    }
    const seen = new Set();
    for (const value of values || []) {
      if (value === "any") issues.push(`${contextFieldLabel(field)} must use explicit labels, not any.`);
      else if (!RULE_CONTEXT_RE.test(value)) issues.push(`${contextFieldLabel(field)} value ${value || "(empty)"} is invalid. Use lowercase labels, email-style ids, or provider-scoped ids with a 128-character limit.`);
      else if (seen.has(value)) issues.push(`Duplicate ${contextFieldLabel(field).toLowerCase()} value ${value}.`);
      seen.add(value);
    }
  }
  return issues;
}

function pruneEmptyRuleMatchContext(rule = {}) {
  const ctx = rule.matchContext || {};
  for (const key of ["users", "groups", "devices", "postureLabels"]) {
    if (Array.isArray(ctx[key])) ctx[key] = ctx[key].filter(Boolean);
    if (Array.isArray(ctx[key]) && ctx[key].length === 0) delete ctx[key];
  }
  if (!Object.keys(ctx).length) delete rule.matchContext;
}

function contextFieldLabel(field) {
  if (field === "postureLabels") return "Posture labels";
  return field[0].toUpperCase() + field.slice(1);
}

export function tagIssues(tags = []) {
  const issues = [];
  if ((tags || []).length > MAX_RULE_TAGS) {
    issues.push(`Rules can have at most ${MAX_RULE_TAGS} tags.`);
  }
  const seen = new Set();
  for (const tag of tags || []) {
    if (!RULE_TAG_RE.test(tag)) {
      issues.push(`Tag ${tag || "(empty)"} is invalid. Use lowercase letters, digits, '-', '_', '.', or ':' with a 64-character limit.`);
    } else if (seen.has(tag)) {
      issues.push(`Duplicate tag ${tag}.`);
    }
    seen.add(tag);
  }
  return issues;
}

export function securityProfileIssues(rule) {
  const refs = rule.securityProfiles || [];
  const issues = [];
  const seen = new Set();
  const profiles = new Map((session.draft.securityProfiles || []).map((profile) => [profile.name, profile]));
  let hasBlockingProfile = false;
  for (const ref of refs) {
    if (!ref) issues.push("Security profile references cannot be empty.");
    else if (ref === "any") issues.push("Security profiles must name explicit profile objects, not any.");
    else if (seen.has(ref)) issues.push(`Duplicate security profile ${ref}.`);
    else if (!profiles.has(ref)) issues.push(`Security profile ${ref} does not exist in the candidate.`);
    else if (securityProfileHasBlockingIntent(profiles.get(ref))) hasBlockingProfile = true;
    seen.add(ref);
  }
  const ids = session.draft.ids || {};
  const failClosed = Boolean(ids.enabled) &&
    ids.mode === "IDS_MODE_PREVENT" &&
    (ids.failureBehavior || ids.failure_behavior) === "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED";
  if ((rule.action || "ACTION_ALLOW") === "ACTION_ALLOW" && hasBlockingProfile && !failClosed) {
    issues.push("Blocking security profiles on Allow rules require IDS/IPS Prevent with Fail closed.");
  }
  return issues;
}

export function qosProfileIssues(rule = {}) {
  const ref = String(rule.qosProfile || "").trim();
  if (!ref) return [];
  const profiles = new Set((session.draft.qosProfiles || []).map((profile) => profile.name).filter(Boolean));
  if (ref !== rule.qosProfile) return ["QoS profile must not contain leading or trailing whitespace."];
  if (ref === "any") return ["QoS profile must name an explicit profile object, not any."];
  if (!profiles.has(ref)) return [`QoS profile ${ref} does not exist in the candidate.`];
  return [];
}

function securityProfileSummary(profile = {}, fallback = "") {
  if (!profile?.name) return `${fallback || "profile"} is not defined in the candidate.`;
  const parts = [
    profile.tlsInspection ? profile.tlsInspection.replace(/^TLS_INSPECTION_MODE_/, "").toLowerCase().replace(/_/g, " ") : "",
    profile.dnsSecurity ? profile.dnsSecurity.replace(/^DNS_SECURITY_MODE_/, "").toLowerCase().replace(/_/g, " ") : "",
    profile.fileSecurity ? profile.fileSecurity.replace(/^FILE_SECURITY_MODE_/, "").toLowerCase().replace(/_/g, " ") : "",
    (profile.urlCategories || []).length ? `url: ${(profile.urlCategories || []).join(", ")}` : "",
  ].filter(Boolean);
  return parts.join(" · ") || profile.description || profile.name;
}

function hasSpecificRefs(refs = []) {
  return (refs || []).some((ref) => ref && ref !== "any");
}

export function appRuleIssues(rule, apps = [], policy = {}) {
  if (!hasSpecificRefs(rule.applications)) return [];
  const appByName = new Map((apps || []).map((app) => [app.name, app]));
  const issues = [];
  if (hasSpecificRefs(rule.services)) {
    issues.push("Remove explicit services. The selected App-ID objects supply the enforced TCP/UDP port hints.");
  }
  for (const ref of rule.applications || []) {
    if (!ref || ref === "any") continue;
    const app = appByName.get(ref);
    if (!app) {
      issues.push(`Application ${ref} does not exist in the candidate.`);
      continue;
    }
    if (!hasEnforceableAppPorts(app)) {
      if (rule.action === "ACTION_ALLOW") {
        issues.push(`Application ${ref} has no TCP/UDP port hints; signal-only App-ID Allow cannot preserve a bounded packet filter forwarding path.`);
      }
      if (!idsPreventFailClosed(policy?.ids || {})) {
        issues.push(`Application ${ref} has no TCP/UDP port hints; signal-only App-ID enforcement requires IDS/IPS Prevent with Fail closed.`);
      }
      if (!hasSupportedAppIDSignal(app)) {
        issues.push(`Application ${ref} has no supported IDS/IPS engine App-ID signal (supported: dns, http, ssh, tls).`);
      }
      if (hasSpecificRefs(rule.fromZones) || hasSpecificRefs(rule.toZones)) {
        issues.push("Signal-only App-ID rules cannot be scoped only by From/To zones; add TCP/UDP port hints or use Source/Destination address scope.");
      }
    }
  }
  return issues;
}

function appRuleUsesSignalOnly(rule, apps = []) {
  if (!hasSpecificRefs(rule.applications)) return false;
  const appByName = new Map((apps || []).map((app) => [app.name, app]));
  return (rule.applications || []).some((ref) => {
    if (!ref || ref === "any") return false;
    const app = appByName.get(ref);
    return app && !hasEnforceableAppPorts(app) && hasSupportedAppIDSignal(app);
  });
}

function idsPreventFailClosed(ids = {}) {
  return Boolean(ids.enabled) &&
    ids.mode === "IDS_MODE_PREVENT" &&
    (ids.failureBehavior || ids.failure_behavior) === "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED";
}

function hasSupportedAppIDSignal(app = {}) {
  const supported = new Set(["dns", "http", "ssh", "tls"]);
  return (app.engineSignals || app.engine_signals || []).some((signal) => supported.has(String(signal || "").trim().toLowerCase()));
}

function hasEnforceableAppPorts(app = {}) {
  return (app.ports || []).some((hint) =>
    (hint.protocol === "PROTOCOL_TCP" || hint.protocol === "PROTOCOL_UDP") &&
    (hint.ports || []).some((port) => Number(port.start) >= 1 && Number(port.start) <= 65535 &&
      (!port.end || (Number(port.end) >= Number(port.start) && Number(port.end) <= 65535))));
}

export function addPendingRuleEditorObject(pending = {}, kind = "", object = {}, options = []) {
  const name = String(object.name || "").trim();
  if (!name) return "";
  if (kind === "address") {
    const cidr = String(object.cidr || "").trim();
    if (!cidr) return "";
    const item = { name, cidr };
    if (object.description) item.description = object.description;
    upsertPendingObject(pending, "addresses", item);
  } else if (kind === "service") {
    const item = {
      name,
      protocol: object.protocol || "PROTOCOL_TCP",
      ports: clonePorts(object.ports || []),
    };
    if (object.description) item.description = object.description;
    upsertPendingObject(pending, "services", item);
  } else if (kind === "application") {
    const item = {
      name,
      displayName: object.displayName || "",
      category: object.category || "",
      engineSignals: [...(object.engineSignals || [])],
      ports: cloneApplicationPorts(object.ports || []),
    };
    if (object.description) item.description = object.description;
    upsertPendingObject(pending, "applications", item);
  } else {
    return "";
  }
  if (Array.isArray(options) && !options.includes(name)) options.push(name);
  return name;
}

export function applyPendingRuleEditorObjects(policy = {}, pending = {}) {
  const existingAddresses = new Set((policy.addresses || []).map((item) => item?.name).filter(Boolean));
  for (const address of pending.addresses || []) {
    if (!address?.name || existingAddresses.has(address.name)) continue;
    (policy.addresses ||= []).push({ ...address });
    existingAddresses.add(address.name);
  }
  const existingServices = new Set((policy.services || []).map((item) => item?.name).filter(Boolean));
  for (const service of pending.services || []) {
    if (!service?.name || existingServices.has(service.name)) continue;
    (policy.services ||= []).push({ ...service, ports: clonePorts(service.ports || []) });
    existingServices.add(service.name);
  }
  const existingApplications = new Set((policy.applications || []).map((item) => item?.name).filter(Boolean));
  for (const app of pending.applications || []) {
    if (!app?.name || existingApplications.has(app.name)) continue;
    (policy.applications ||= []).push({ ...app, engineSignals: [...(app.engineSignals || [])], ports: cloneApplicationPorts(app.ports || []) });
    existingApplications.add(app.name);
  }
  return policy;
}

function upsertPendingObject(pending, key, object) {
  const list = pending[key] ||= [];
  const idx = list.findIndex((item) => item?.name === object.name);
  if (idx >= 0) list[idx] = object;
  else list.push(object);
}

function clonePorts(ports = []) {
  return (ports || []).map((port) => ({ ...port }));
}

function cloneApplicationPorts(hints = []) {
  return (hints || []).map((hint) => ({
    ...hint,
    ports: clonePorts(hint.ports || []),
  }));
}

function ruleObjectNameExists(options = [], name = "") {
  const normalized = String(name || "").trim().toLowerCase();
  return Boolean(normalized) && (options || []).some((item) => String(item || "").trim().toLowerCase() === normalized);
}

// Inline object creation stays local to the editor and is staged on rule save.
function newObject(kind, onCreated, opts = {}) {
  const message = h("div", { class: "note inline-object-message", role: "status" });
  const setMessage = (text, tone = "warn") => {
    message.textContent = text;
    message.dataset.tone = tone;
  };
  const cancel = () => {
    if (typeof opts.onCancel === "function") opts.onCancel();
  };
  if (kind === "address") {
    const name = h("input", { class: "input", placeholder: "name (e.g. web-server)" });
    const cidr = h("input", { class: "input", placeholder: "CIDR (e.g. 10.0.0.5/32)" });
    return h("div", { class: "inline-object-creator", dataset: { inlineObjectKind: "address" } },
      h("strong", {}, "New address object"),
      h("div", { class: "grid cols-2" }, field("Name", name), field("CIDR", cidr)),
      message,
      h("div", { class: "inline-object-actions" },
        h("button", { class: "btn ghost sm", ...actionControlAttrs({ ruleInlineObjectAction: "cancel-address" }, "Cancel address object creation", { onclick: cancel }) }, "Cancel"),
        h("button", {
          class: "btn primary sm",
          ...actionControlAttrs({ ruleInlineObjectAction: "create-address" }, "Create address object", { onclick: () => {
            const n = name.value.trim();
            const c = cidr.value.trim();
            if (!n || !c) { setMessage("Name and CIDR are required."); return; }
            if (opts.nameExists?.(n)) { setMessage(`Object ${n} already exists. Select it from the list.`); return; }
            onCreated(n, { name: n, cidr: c, description: "Created from Rules editor." });
          } }),
        }, "Create address")));
  }
  const name = h("input", { class: "input", placeholder: "name (e.g. https)" });
  const proto = h("select", {}, opt("PROTOCOL_TCP", "TCP"), opt("PROTOCOL_UDP", "UDP"), opt("PROTOCOL_ICMP", "ICMP"), opt("PROTOCOL_ANY", "Any"));
  const ports = h("input", { class: "input", placeholder: "ports (e.g. 443, 8000-8100)" });
  return h("div", { class: "inline-object-creator", dataset: { inlineObjectKind: "service" } },
    h("strong", {}, "New service object"),
    field("Name", name),
    h("div", { class: "grid cols-2" }, field("Protocol", proto), field("Ports", ports, "comma-separated; ranges with a dash")),
    message,
    h("div", { class: "inline-object-actions" },
      h("button", { class: "btn ghost sm", ...actionControlAttrs({ ruleInlineObjectAction: "cancel-service" }, "Cancel service object creation", { onclick: cancel }) }, "Cancel"),
      h("button", {
        class: "btn primary sm",
        ...actionControlAttrs({ ruleInlineObjectAction: "create-service" }, "Create service object", { onclick: () => {
          const n = name.value.trim();
          if (!n) { setMessage("Name is required."); return; }
          if (opts.nameExists?.(n)) { setMessage(`Object ${n} already exists. Select it from the list.`); return; }
          onCreated(n, { name: n, protocol: proto.value, ports: parsePorts(ports.value), description: "Created from Rules editor." });
        } }),
      }, "Create service")));
}

export function parsePorts(s) {
  return (s || "").split(",").map((x) => x.trim()).filter(Boolean).map((p) => {
    const [a, b] = p.split("-").map((n) => parseInt(n, 10));
    return b ? { start: a, end: b } : { start: a };
  });
}
