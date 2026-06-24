// policy.js — the editing session. Holds the running policy and a draft;
// every mutation auto-stages to the server *candidate* (PUT /v1/candidate),
// so nothing touches running config until an explicit commit. This is the
// candidate → validate → commit → rollback loop, surfaced in the UI.

import { api } from "./api.js";
import { dataplanePosture } from "./dataplane.js";

function clone(o) { return o ? structuredClone(o) : o; }
function errText(err) { return err?.message || String(err || "unknown error"); }
function isNotFound(err) { return Number(err?.status) === 404; }

// Stable JSON for value equality (sorts object keys).
function stable(v) {
  if (Array.isArray(v)) return "[" + v.map(stable).join(",") + "]";
  if (v && typeof v === "object") {
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + stable(v[k])).join(",") + "}";
  }
  return JSON.stringify(v);
}
export const equal = (a, b) => stable(a) === stable(b);
export const fingerprint = (value) => stable(value);

const RISK_RANK = { low: 1, medium: 2, high: 3 };
const SERVER_CHANGE_LABELS = {
  rules: "rule",
  zones: "zone",
  addresses: "address",
  services: "service",
  applications: "application",
  securityProfiles: "security profile",
  nat: "NAT",
  staticRoutes: "route",
  routing: "routing",
  vpn: "VPN",
  network: "network",
  hostInput: "host input",
  ids: "IDS/IPS",
  intel: "threat intel",
  telemetry: "telemetry",
};

function entryKey(x, i) { return x && x.name != null && x.name !== "" ? "name:" + x.name : "idx:" + i; }
function displayName(x, fallback) { return (x && x.name) || fallback; }
function active(r) { return r && !r.disabled; }
function allow(r) { return r && r.action === "ACTION_ALLOW"; }
function block(r) { return r && (r.action === "ACTION_DENY" || r.action === "ACTION_REJECT"); }
function anyToken(xs) { return !xs || xs.length === 0 || xs.includes("any"); }
function broadRule(r) {
  return anyToken(r.fromZones) && anyToken(r.toZones) && anyToken(r.sourceAddresses) &&
    anyToken(r.destinationAddresses) && anyToken(r.services);
}

function addRisk(items, level, title, detail) {
  items.push({ level, title, detail });
}

function addRuleHygieneImpact(items, rules = []) {
  for (const s of shadowedRules(rules || [])) {
    addRisk(items, "medium", "Shadowed rule",
      `${displayName(rules[s.index], "rule #" + (s.index + 1))} is fully covered by earlier rule ${displayName(rules[s.by], "rule #" + (s.by + 1))}; first-match evaluation will not reach it.`);
  }
  (rules || []).forEach((r, i) => {
    if (active(r) && allow(r) && broadRule(r)) {
      addRisk(items, "high", "Active broad allow rule",
        `${displayName(r, "rule #" + (i + 1))} permits any source to any destination/service; narrow the match or document the exception before production use.`);
    }
  });
}

function shadowedRules(rules = []) {
  const out = [];
  for (let i = 0; i < rules.length; i++) {
    if (!active(rules[i])) continue;
    for (let j = 0; j < i; j++) {
      if (active(rules[j]) && coversRule(rules[j], rules[i])) {
        out.push({ index: i, by: j });
        break;
      }
    }
  }
  return out;
}

function coversRule(a, b) {
  return coversDim(a?.fromZones, b?.fromZones) &&
    coversDim(a?.toZones, b?.toZones) &&
    coversDim(a?.sourceAddresses, b?.sourceAddresses) &&
    coversDim(a?.destinationAddresses, b?.destinationAddresses) &&
    coversDim(a?.services, b?.services);
}

function coversDim(a, b) {
  if (anyToken(a)) return true;
  if (anyToken(b)) return false;
  return (b || []).every((x) => (a || []).includes(x));
}

function listChanges(before = [], after = []) {
  before = before || []; after = after || [];
  const oldMap = new Map(before.map((x, i) => [entryKey(x, i), { value: x, index: i }]));
  const newMap = new Map(after.map((x, i) => [entryKey(x, i), { value: x, index: i }]));
  const out = [];
  for (const [k, n] of newMap) {
    const o = oldMap.get(k);
    if (!o) out.push({ type: "added", key: k, value: n.value, index: n.index });
    else if (!equal(o.value, n.value)) out.push({ type: "modified", key: k, before: o.value, after: n.value, index: n.index });
  }
  for (const [k, o] of oldMap) if (!newMap.has(k)) out.push({ type: "removed", key: k, value: o.value, index: o.index });
  return out;
}

function ruleOrderChanged(before = [], after = []) {
  const names = (xs) => (xs || []).filter((r) => r && r.name).map((r) => r.name).join("\n");
  return names(before) !== names(after) && new Set((before || []).map((r) => r.name)).size === new Set((after || []).map((r) => r.name)).size;
}

function intelDisabled(before, after) {
  const oldFeeds = new Map(((before && before.feeds) || []).map((f) => [f.name, f]));
  return ((after && after.feeds) || []).some((f) => oldFeeds.get(f.name)?.enabled && !f.enabled);
}

function inspectionDisabled(before, after) {
  return before && before.enabled && (!after || !after.enabled);
}

function hostInputDefault(hostInput = {}) {
  return hostInput?.defaultAction || "ACTION_ALLOW";
}

function decryptionRequired(profile = {}) {
  return profile?.tlsInspection === "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED";
}

/**
 * Conservative operator-facing risk summary for staged policy changes.
 * This is not an authorization model; it is a preflight review aid that
 * makes high-impact firewall changes explicit before commit.
 */
export function changeImpact(running = {}, draft = {}) {
  const items = [];

  for (const c of listChanges(running.rules, draft.rules)) {
    const r = c.after || c.value;
    const name = displayName(r, "rule #" + (Number(c.index) + 1));
    if (c.type === "added") {
      if (active(r) && allow(r)) addRisk(items, broadRule(r) ? "high" : "medium", "New active allow rule", `${name} can permit traffic when committed.`);
      else if (active(r) && block(r)) addRisk(items, "medium", "New active blocking rule", `${name} can drop or reject matching traffic.`);
      else addRisk(items, "low", "New disabled rule", `${name} is staged but disabled.`);
    } else if (c.type === "removed") {
      if (active(r) && block(r)) addRisk(items, "high", "Removed active blocking rule", `${name} may expose traffic that was previously dropped.`);
      else if (active(r) && allow(r)) addRisk(items, "medium", "Removed active allow rule", `${name} may interrupt allowed traffic.`);
      else addRisk(items, "low", "Removed disabled rule", name);
    } else if (c.type === "modified") {
      const wasActive = active(c.before), nowActive = active(c.after);
      if ((!wasActive && nowActive && allow(c.after)) || (!allow(c.before) && allow(c.after))) {
        addRisk(items, broadRule(c.after) ? "high" : "medium", "Rule now allows traffic", `${name} changed to an active allow path.`);
      } else if ((allow(c.before) && !allow(c.after)) || (!wasActive && nowActive && block(c.after))) {
        addRisk(items, "high", "Rule can interrupt traffic", `${name} changed toward drop/reject behavior.`);
      } else if (wasActive !== nowActive) {
        addRisk(items, "medium", nowActive ? "Rule enabled" : "Rule disabled", name);
      } else {
        addRisk(items, "medium", "Rule match changed", `${name} changed match criteria, action, logging, or description.`);
      }
    }
  }
  if (ruleOrderChanged(running.rules, draft.rules)) addRisk(items, "medium", "Rule order changed", "Security rules are first-match; order changes can alter verdicts.");
  addRuleHygieneImpact(items, draft.rules);

  for (const c of listChanges(running.zones, draft.zones)) {
    const r = c.after || c.value;
    addRisk(items, "high", `${c.type[0].toUpperCase() + c.type.slice(1)} zone`, displayName(r, "zone #" + (Number(c.index) + 1)));
  }
  for (const c of listChanges(running.addresses, draft.addresses)) {
    const r = c.after || c.value;
    addRisk(items, "medium", `${c.type[0].toUpperCase() + c.type.slice(1)} address object`, displayName(r, "address #" + (Number(c.index) + 1)));
  }
  for (const c of listChanges(running.services, draft.services)) {
    const r = c.after || c.value;
    addRisk(items, "medium", `${c.type[0].toUpperCase() + c.type.slice(1)} service object`, displayName(r, "service #" + (Number(c.index) + 1)));
  }
  for (const c of listChanges(running.applications, draft.applications)) {
    const r = c.after || c.value;
    addRisk(items, "medium", `${c.type[0].toUpperCase() + c.type.slice(1)} application object`, displayName(r, "application #" + (Number(c.index) + 1)));
  }
  for (const c of listChanges(running.securityProfiles, draft.securityProfiles)) {
    const r = c.after || c.value;
    const title = `${c.type[0].toUpperCase() + c.type.slice(1)} security profile`;
    const name = displayName(r, "security profile #" + (Number(c.index) + 1));
    if (decryptionRequired(r)) {
      addRisk(items, "high", title, `${name} declares decryption-required inspection intent; confirm external TLS broker and certificate prerequisites before commit.`);
    } else {
      addRisk(items, "medium", title, `${name} changes layered TLS/DNS/URL/file inspection intent attached to rules.`);
    }
  }

  if (!equal(running.nat, draft.nat)) addRisk(items, "high", "NAT changed", "Source or destination translation can redirect production traffic.");
  if (!equal(running.staticRoutes, draft.staticRoutes)) addRisk(items, "high", "Static routes changed", "Routing changes can redirect or blackhole traffic.");
  if (!equal(running.routing, draft.routing)) addRisk(items, "high", "Dynamic routing changed", "Dynamic routing behavior can change forwarding paths.");
  if (!equal(running.vpn, draft.vpn)) addRisk(items, "high", "VPN changed", "Tunnel, peer, or cryptographic settings changed.");
  if (!equal(running.network, draft.network)) {
    addRisk(items, "high", "Interface/network changed", "Interface ownership, MTU, offload, or forwarding acceleration changed.");
    if (!running.network?.enableFlowOffload && draft.network?.enableFlowOffload) {
      addRisk(items, "high", "Forwarding acceleration enabled", "Established L3/L4 flows can use acceleration; this profile must not use IDS/IPS inspection.");
    } else if (running.network?.enableFlowOffload && !draft.network?.enableFlowOffload) {
      addRisk(items, "medium", "Forwarding acceleration disabled", "Forwarding returns to the standard inspected path.");
    }
  }
  if (!equal(running.hostInput, draft.hostInput)) {
    const before = hostInputDefault(running.hostInput);
    const after = hostInputDefault(draft.hostInput);
    if (before === "ACTION_DENY" && after === "ACTION_ALLOW") {
      addRisk(items, "high", "Host input opened", "Traffic to the firewall appliance changes from default-deny to default-allow.");
    } else if (after === "ACTION_DENY") {
      addRisk(items, "high", "Host input hardened", "Traffic to the firewall appliance is default-deny; confirm management allow rules before commit.");
    } else {
      addRisk(items, "high", "Host input policy changed", "Management-plane access to the firewall appliance changed.");
    }
  }

  if (!equal(running.ids, draft.ids)) {
    for (const c of listChanges(running.ids?.exceptions, draft.ids?.exceptions)) {
      const ex = c.after || c.value;
      const name = displayName(ex, "ids exception #" + (Number(c.index) + 1));
      addRisk(items, "medium", `IDS exception ${c.type}`, `${name} changes false-positive suppression behavior.`);
    }
    if (inspectionDisabled(running.ids, draft.ids)) addRisk(items, "high", "IDS/IPS disabled", "Traffic inspection will stop for this policy.");
    else if (draft.ids?.enabled && draft.ids?.mode === "IDS_MODE_PREVENT") addRisk(items, "high", "IPS prevention changed", "Inline prevention can drop traffic and depends on fail behavior.");
    else addRisk(items, "medium", "IDS detection changed", "Inspection settings changed.");
  }
  const dp = dataplanePosture(draft);
  if (dp.state === "invalid") addRisk(items, "high", dp.summary, dp.detail);
  if (!equal(running.intel, draft.intel)) {
    addRisk(items, intelDisabled(running.intel, draft.intel) ? "high" : "medium", "Threat intel changed", "Feed or content settings changed.");
  }
  if (!equal(running.telemetry, draft.telemetry)) addRisk(items, "low", "Telemetry changed", "Logging or export behavior changed.");

  if (!items.length) addRisk(items, "low", "No material policy risk detected", "The candidate matches the running policy.");
  const level = items.reduce((max, it) => RISK_RANK[it.level] > RISK_RANK[max] ? it.level : max, "low");
  return { level, items };
}

function serverRiskLevel(risk) {
  if (risk === 3 || risk === "CHANGE_RISK_HIGH") return "high";
  if (risk === 2 || risk === "CHANGE_RISK_MEDIUM") return "medium";
  if (risk === 1 || risk === "CHANGE_RISK_LOW") return "low";
  return "";
}

export function normalizeServerImpact(impact) {
  if (!impact || !Array.isArray(impact.items) || !impact.items.length) return null;
  const items = impact.items.map((item) => ({
    level: serverRiskLevel(item.risk) || "low",
    title: item.title || "Policy impact",
    detail: item.detail || "",
  }));
  const level = serverRiskLevel(impact.risk) || items.reduce((max, it) => RISK_RANK[it.level] > RISK_RANK[max] ? it.level : max, "low");
  return { level, items };
}

class Session {
  constructor() {
    this.running = {};
    this.runningVersion = 0;
    this.draft = {};
    this.hasCandidate = false;
    this.candidateStatus = null;
    this.candidateRevision = "";
    this.candidateLoadError = null;
    this._subs = new Set();
  }

  subscribe(fn) { this._subs.add(fn); return () => this._subs.delete(fn); }
  _notify() { this._subs.forEach((fn) => fn(this)); }

  async load() {
    const run = await api.running();
    this.running = run.policy || {};
    this.runningVersion = Number(run.version) || 0;
    let status = null;
    try {
      status = await api.candidateStatus();
      this.candidateStatus = status;
      this.candidateRevision = status?.candidateRevision || "";
    } catch {
      this.candidateStatus = null;
      this.candidateRevision = "";
    }
    if (status?.hasCandidate === false) {
      this.draft = clone(this.running);
      this.hasCandidate = false;
      this.candidateLoadError = null;
      this._notify();
      return;
    }
    try {
      const cand = await api.candidate();
      this.draft = cand.policy || clone(this.running);
      this.hasCandidate = !equal(this.draft, this.running);
      this.candidateLoadError = null;
    } catch (e) {
      if (!isNotFound(e)) {
        this.draft = clone(this.running);
        this.hasCandidate = false;
        this.candidateLoadError = e;
        await this.refreshStatus();
        this._notify();
        return;
      }
      // 404 -> no candidate set yet.
      this.draft = clone(this.running);
      this.hasCandidate = false;
      this.candidateLoadError = null;
    }
    if (!status) await this.refreshStatus();
    this._notify();
  }

  get dirty() { return !equal(this.draft, this.running); }
  get candidateUnavailable() { return Boolean(this.candidateLoadError); }
  candidateUnavailableMessage() {
    if (!this.candidateLoadError) return "";
    return `The staged candidate could not be loaded: ${errText(this.candidateLoadError)}. Reload candidate state before editing, validating, committing, or discarding.`;
  }

  ensureCandidateAvailable(action) {
    const prefix = action ? `Cannot ${action}` : "Cannot modify candidate";
    if (!this.candidateLoadError && this.candidateRevision) return;
    if (!this.candidateLoadError) {
      throw new Error(`${prefix}; candidate revision is unavailable. Reload candidate state before editing, validating, committing, or discarding.`);
    }
    throw new Error(`${prefix}; ${this.candidateUnavailableMessage()}`);
  }

  // Section accessors return the live draft arrays (created if missing).
  list(section) { if (!this.draft[section]) this.draft[section] = []; return this.draft[section]; }

  /** Apply a mutation to the draft and persist it to the server candidate. */
  async apply(mutator) {
    this.ensureCandidateAvailable("stage policy edits");
    const prev = clone(this.draft);
    try {
      mutator(this.draft);
      const res = await api.setCandidate(this.draft, this.candidateRevision);
      this.candidateRevision = res?.candidateRevision || this.candidateRevision;
      this.hasCandidate = this.dirty;
      await this.refreshStatus();
      this._notify();
    } catch (e) {
      this.draft = prev; // roll back local change on mutator or persistence failure
      throw e;
    }
  }

  /** Persist the current draft without applying a new local mutation. */
  async stageDraft(action = "stage the candidate") {
    this.ensureCandidateAvailable(action);
    const res = await api.setCandidate(this.draft, this.candidateRevision);
    this.candidateRevision = res?.candidateRevision || this.candidateRevision;
    this.hasCandidate = this.dirty;
    await this.refreshStatus();
    this._notify();
    return res;
  }

  async discard() {
    this.ensureCandidateAvailable("discard the candidate");
    const res = await api.setCandidate(clone(this.running), this.candidateRevision); // candidate == running ⇒ clean
    this.candidateRevision = res?.candidateRevision || this.candidateRevision;
    this.draft = clone(this.running);
    this.hasCandidate = false;
    await this.refreshStatus();
    this._notify();
  }

  // validate and commit always (re)stage the draft first, so the server
  // candidate matches the local draft even if a pivot or inline-create
  // mutated the draft without going through apply().
  async validate() {
    this.ensureCandidateAvailable("validate the candidate");
    const res = await api.setCandidate(this.draft, this.candidateRevision);
    this.candidateRevision = res?.candidateRevision || this.candidateRevision;
    await this.refreshStatus();
    return api.validate();
  }

  async commit(comment, ackRisk = false, ackRuntime = false, approvalId = "", reviewedCandidateRevision = "") {
    this.ensureCandidateAvailable("commit the candidate");
    let expectedCandidateRevision = String(reviewedCandidateRevision || "").trim();
    if (!expectedCandidateRevision) {
      const setRes = await api.setCandidate(this.draft, this.candidateRevision);
      this.candidateRevision = setRes?.candidateRevision || this.candidateRevision;
      expectedCandidateRevision = this.candidateRevision;
    }
    const res = await api.commit(comment, ackRisk, ackRuntime, approvalId, expectedCandidateRevision);
    await this.load();
    return res;
  }

  /** Human summary of pending changes, e.g. "2 rules, 1 address". */
  changeSummary() {
    const out = [];
    const lists = {
      rules: "rule", zones: "zone", addresses: "address", services: "service", applications: "application", staticRoutes: "route",
    };
    for (const [sec, noun] of Object.entries(lists)) {
      const n = listDelta(this.running[sec], this.draft[sec], sec === "rules");
      if (n) out.push(`${n} ${noun}${n === 1 ? "" : noun.endsWith("s") ? "es" : "s"}`);
    }
    for (const sec of ["nat", "ids", "intel", "routing", "vpn", "network", "hostInput", "telemetry"]) {
      if (!equal(this.running[sec], this.draft[sec])) out.push(SERVER_CHANGE_LABELS[sec] || sec);
    }
    return out;
  }

  changeCount() {
    let n = 0;
    for (const sec of ["rules", "zones", "addresses", "services", "applications", "staticRoutes"]) n += listDelta(this.running[sec], this.draft[sec], sec === "rules");
    for (const sec of ["nat", "ids", "intel", "routing", "vpn", "network", "hostInput", "telemetry"]) if (!equal(this.running[sec], this.draft[sec])) n++;
    return n;
  }

  async refreshStatus() {
    try {
      this.candidateStatus = await api.candidateStatus();
      this.candidateRevision = this.candidateStatus?.candidateRevision || this.candidateRevision;
    } catch {
      this.candidateStatus = null;
    }
  }

  serverChangeCount() {
    if (this.statusMatchesLocal()) {
      const count = Number(this.candidateStatus?.changeCount);
      if (Number.isFinite(count) && (!this.dirty || count > 0)) return count;
    }
    return this.changeCount();
  }

  serverChangeSummary() {
    if (!this.statusMatchesLocal() || !Array.isArray(this.candidateStatus?.changes)) {
      return this.changeSummary();
    }
    const summary = this.candidateStatus.changes.flatMap((change) => serverChangePhrases(change));
    return summary.length || !this.dirty ? summary : this.changeSummary();
  }

  statusMatchesLocal() {
    if (this.candidateLoadError) return false;
    return Boolean(this.candidateStatus) && Boolean(this.candidateStatus.dirty) === this.dirty;
  }
}

// Count entries that differ between two named-object lists (added,
// removed, or modified), keyed by name where available.
function listDelta(a = [], b = [], trackOrder = false) {
  a = a || []; b = b || [];
  const key = (x, i) => (x && x.name != null ? "n:" + x.name : "i:" + i);
  const ma = new Map(a.map((x, i) => [key(x, i), x]));
  const mb = new Map(b.map((x, i) => [key(x, i), x]));
  let n = 0;
  for (const [k, v] of mb) { if (!ma.has(k) || !equal(ma.get(k), v)) n++; }
  for (const k of ma.keys()) { if (!mb.has(k)) n++; }
  if (trackOrder && ma.size === mb.size && [...ma.keys()].every((k) => mb.has(k))) {
    const beforeOrder = a.map((x, i) => key(x, i)).join("\u0000");
    const afterOrder = b.map((x, i) => key(x, i)).join("\u0000");
    if (beforeOrder !== afterOrder) n++;
  }
  return n;
}

function serverChangePhrases(change) {
  const section = change?.section || "";
  const noun = SERVER_CHANGE_LABELS[section] || section || "section";
  const phrases = [];
  addServerChangePhrase(phrases, noun, Number(change?.added) || 0, "added");
  addServerChangePhrase(phrases, noun, Number(change?.modified) || 0, "modified");
  addServerChangePhrase(phrases, noun, Number(change?.removed) || 0, "removed");
  return phrases;
}

function addServerChangePhrase(out, noun, count, verb) {
  if (!count) return;
  const label = count === 1 || noun === "NAT" || noun === "VPN" || noun === "IDS/IPS" ? noun : pluralNoun(noun);
  out.push(`${count} ${label} ${verb}`);
}

function pluralNoun(noun) {
  if (noun.endsWith("y")) return noun.slice(0, -1) + "ies";
  if (noun.endsWith("s")) return noun + "es";
  return noun + "s";
}

/** Pretty unified-ish line diff between running and draft policies. */
export function diffLines(running, draft) {
  const a = JSON.stringify(running, null, 2).split("\n");
  const b = JSON.stringify(draft, null, 2).split("\n");
  // Simple LCS-based line diff (fine for config-sized inputs).
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = m - 1; i >= 0; i--)
    for (let j = n - 1; j >= 0; j--)
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out = [];
  let i = 0, j = 0;
  while (i < m && j < n) {
    if (a[i] === b[j]) { out.push({ t: "ctx", s: a[i] }); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push({ t: "del", s: a[i] }); i++; }
    else { out.push({ t: "add", s: b[j] }); j++; }
  }
  while (i < m) out.push({ t: "del", s: a[i++] });
  while (j < n) out.push({ t: "add", s: b[j++] });
  return out;
}

export const session = new Session();
