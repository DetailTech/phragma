// api.js — typed REST client over the canonical /v1 gateway. Holds the
// bearer token fallback in sessionStorage, while OIDC cookie sessions remain
// the preferred browser auth path. Every mutation is the same candidate/commit
// path the CLI uses.

const TOKEN_KEY = "phragma.token";
const LEGACY_TOKEN_KEY = "openngfw.token";
const CSRF_HEADER = "X-Phragma-CSRF";

let volatileToken = "";
let csrfToken = "";
let csrfRefresh = null;

function browserStorage(name) {
  try { return globalThis[name] || null; } catch { return null; }
}

function storageGet(storage, key) {
  try { return storage?.getItem(key) || ""; } catch { return ""; }
}

function storageSet(storage, key, value) {
  if (!storage) return false;
  try {
    storage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}

function storageRemove(storage, key) {
  try { storage?.removeItem(key); } catch {}
}

function clearPersistentTokens() {
  const local = browserStorage("localStorage");
  storageRemove(local, TOKEN_KEY);
  storageRemove(local, LEGACY_TOKEN_KEY);
}

export function getToken() {
  const session = browserStorage("sessionStorage");
  const local = browserStorage("localStorage");
  const sessionToken = storageGet(session, TOKEN_KEY);
  if (sessionToken) {
    volatileToken = "";
    clearPersistentTokens();
    return sessionToken;
  }
  if (volatileToken) {
    clearPersistentTokens();
    return volatileToken;
  }

  const persistedToken = storageGet(local, TOKEN_KEY) || storageGet(local, LEGACY_TOKEN_KEY);
  clearPersistentTokens();
  if (!persistedToken) return "";

  if (storageSet(session, TOKEN_KEY, persistedToken)) volatileToken = "";
  else volatileToken = persistedToken;
  return persistedToken;
}

export function setToken(t) {
  const token = t ? String(t) : "";
  if (token) {
    if (storageSet(browserStorage("sessionStorage"), TOKEN_KEY, token)) volatileToken = "";
    else volatileToken = token;
  } else {
    volatileToken = "";
    storageRemove(browserStorage("sessionStorage"), TOKEN_KEY);
  }
  clearPersistentTokens();
}

export function setCSRFTokenForTest(t) {
  csrfToken = t ? String(t) : "";
}

export class ApiError extends Error {
  constructor(status, message, body) { super(message); this.status = status; this.body = body; }
}

function isUnsafeMethod(method) {
  return ["POST", "PUT", "PATCH", "DELETE"].includes(String(method || "").toUpperCase());
}

function rememberCSRF(data) {
  const token = data && (data.csrf_token || data.csrfToken);
  if (typeof token === "string") csrfToken = token;
  else if (data?.authenticated === false) csrfToken = "";
}

async function refreshCSRFToken() {
  if (csrfRefresh) return csrfRefresh;
  csrfRefresh = (async () => {
    for (const path of ["/v1/auth/oidc/status", "/v1/auth/saml/status"]) {
      try {
        const res = await fetch(path, { method: "GET", headers: {} });
        const text = await res.text();
        if (!res.ok || !text) continue;
        let data = null;
        try { data = JSON.parse(text); } catch { data = null; }
        rememberCSRF(data);
        if (csrfToken) break;
      } catch {}
    }
    return csrfToken;
  })();
  try {
    return await csrfRefresh;
  } finally {
    csrfRefresh = null;
  }
}

async function req(method, path, body, opts = {}) {
  const headers = {};
  const token = Object.prototype.hasOwnProperty.call(opts, "tokenOverride")
    ? String(opts.tokenOverride || "")
    : getToken();
  if (token) headers["Authorization"] = "Bearer " + token;
  if (!token && isUnsafeMethod(method)) {
    if (!csrfToken) await refreshCSRFToken();
    if (csrfToken) headers[CSRF_HEADER] = csrfToken;
  }
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let data = null;
  if (text) { try { data = JSON.parse(text); } catch { data = { message: text }; } }
  if (!res.ok) {
    const msg = (data && (data.message || data.error)) || `HTTP ${res.status}`;
    throw new ApiError(res.status, msg, data);
  }
  rememberCSRF(data);
  return data || {};
}

async function binaryReq(path, opts = {}) {
  const headers = {};
  const token = Object.prototype.hasOwnProperty.call(opts, "tokenOverride")
    ? String(opts.tokenOverride || "")
    : getToken();
  if (token) headers["Authorization"] = "Bearer " + token;
  const res = await fetch(path, { method: "GET", headers });
  if (!res.ok) {
    const text = await res.text();
    let data = null;
    if (text) { try { data = JSON.parse(text); } catch { data = { message: text }; } }
    const msg = (data && (data.message || data.error)) || `HTTP ${res.status}`;
    throw new ApiError(res.status, msg, data);
  }
  return res.blob();
}

async function stepUpToken(action, comment = "") {
  const resp = await req("POST", "/v1/system/access-administration/step-up", {
    action,
    comment,
    ackStepUp: true,
  });
  return resp.token || "";
}

export const api = {
  version: () => req("GET", "/v1/system/version"),
  status: () => req("GET", "/v1/system/status"),
  telemetryExportStatus: () => req("GET", "/v1/system/telemetry/exports/status"),
  verifyTelemetryExport: (body) => req("POST", "/v1/system/telemetry/exports:verify", body),
  systemLogs: (opts = {}) => {
    const q = queryParams(opts, ["limit", "source", "engine", "severity", "query", "since", "until"]);
    return req("GET", "/v1/system/logs" + (q ? "?" + q : ""));
  },
  runtimeReadinessPreflight: ({ targetPolicy = {}, runningPolicy = {}, operation = "commit" } = {}) =>
    req("POST", "/v1/system/runtime-readiness:check", { targetPolicy, runningPolicy, operation }),
  networkPathProof: (body) => req("POST", "/v1/system/network-path:prove", body),
  validateAutomationReplay: (body) => req("POST", "/v1/system/automation/replay:validate", body),
  highAvailabilityStatus: () => req("GET", "/v1/system/ha/status"),
  pullHighAvailabilityPolicy: (body) => req("POST", "/v1/system/ha/policy:pull", body),
  activateHighAvailabilityFailover: async (body = {}) => {
    const stepUp = await stepUpToken("ha-failover-activate", body.comment || "");
    return req("POST", "/v1/system/ha/failover:activate", { ...body, stepUpToken: stepUp });
  },
  accessAdministration: () => req("GET", "/v1/system/access-administration"),
  createStepUpChallenge: ({ action, comment = "" } = {}) => req("POST", "/v1/system/access-administration/step-up", { action, comment, ackStepUp: true }),
  oidcPreflight: () => req("POST", "/v1/system/access-administration/oidc:preflight", {}),
  oidcProviderConfig: () => req("GET", "/v1/system/access-administration/oidc/config"),
  validateOIDCProviderConfig: (config) => req("POST", "/v1/system/access-administration/oidc/config:validate", { config }),
  setOIDCProviderConfig: async ({ config, comment }) => {
    const stepUp = await stepUpToken("access-oidc-set", comment || "");
    return req("PUT", "/v1/system/access-administration/oidc/config", { config, comment, ackOidcChange: true, stepUpToken: stepUp });
  },
  disableOIDCProvider: async (comment) => {
    const stepUp = await stepUpToken("access-oidc-disable", comment || "");
    return req("POST", "/v1/system/access-administration/oidc/config:disable", { comment, ackDisableOidc: true, stepUpToken: stepUp });
  },
  samlProviderConfig: () => req("GET", "/v1/system/access-administration/saml/config"),
  validateSAMLProviderConfig: (config) => req("POST", "/v1/system/access-administration/saml/config:validate", { config }),
  setSAMLProviderConfig: async ({ config, comment }) => {
    const stepUp = await stepUpToken("access-saml-set", comment || "");
    return req("PUT", "/v1/system/access-administration/saml/config", { config, comment, ackSamlChange: true, stepUpToken: stepUp });
  },
  disableSAMLProvider: async (comment) => {
    const stepUp = await stepUpToken("access-saml-disable", comment || "");
    return req("POST", "/v1/system/access-administration/saml/config:disable", { comment, ackDisableSaml: true, stepUpToken: stepUp });
  },
  createLocalUser: async ({ name, role, comment }) => {
    const stepUp = await stepUpToken("access-local-user-create", comment || "");
    return req("POST", "/v1/system/access-administration/local-users", { name, role, comment, ackLocalUserChange: true, stepUpToken: stepUp });
  },
  updateLocalUser: async (name, { role, comment }) => {
    const stepUp = await stepUpToken("access-local-user-update", comment || "");
    return req("PATCH", `/v1/system/access-administration/local-users/${encodeURIComponent(name)}`, { name, role, comment, ackLocalUserChange: true, stepUpToken: stepUp });
  },
  rotateLocalUserToken: async (name, comment) => {
    const stepUp = await stepUpToken("access-local-user-rotate-token", comment || "");
    return req("POST", `/v1/system/access-administration/local-users/${encodeURIComponent(name)}:rotate-token`, { name, comment, ackRotateToken: true, stepUpToken: stepUp });
  },
  disableLocalUser: async (name, comment) => {
    const stepUp = await stepUpToken("access-local-user-disable", comment || "");
    return req("POST", `/v1/system/access-administration/local-users/${encodeURIComponent(name)}:disable`, { name, comment, ackDisableUser: true, stepUpToken: stepUp });
  },
  revokeAccessSession: (sessionId) => req("POST", `/v1/system/access-administration/sessions/${encodeURIComponent(sessionId)}:revoke`, { ackRevokeSession: true }),
  releaseAcceptanceStatus: () => req("GET", "/v1/system/release-acceptance/status"),
  supportBundle: (opts = {}) => {
    const q = queryParams(opts, ["versionLimit", "auditLimit", "eventLimit"]);
    return req("GET", "/v1/system/support-bundle" + (q ? "?" + q : ""));
  },
  investigationCases: (opts = {}) => {
    const q = queryParams(opts, ["limit", "state"]);
    return req("GET", "/v1/investigation/cases" + (q ? "?" + q : ""));
  },
  investigationCase: (id) => req("GET", `/v1/investigation/cases/${encodeURIComponent(id)}`),
  createInvestigationCase: ({ title = "", packet = {}, evidence = [] } = {}) =>
    req("POST", "/v1/investigation/cases", { title, packet, evidence }),
  updateInvestigationCase: (id, patch = {}) =>
    req("PATCH", `/v1/investigation/cases/${encodeURIComponent(id)}`, patch),
  addInvestigationCaseEvidence: (id, evidence = []) =>
    req("POST", `/v1/investigation/cases/${encodeURIComponent(id)}/evidence`, { evidence }),
  tuneHost: (body) => req("POST", "/v1/system/tune", body),
  authStatus: () => req("GET", "/v1/auth/oidc/status"),
  samlAuthStatus: () => req("GET", "/v1/auth/saml/status"),
  logout: () => req("POST", "/v1/auth/logout"),

  // Policy / candidate / commit
  getPolicy: (source, version) => {
    const q = new URLSearchParams();
    if (source) q.set("source", source);
    if (version) q.set("version", String(version));
    const qs = q.toString();
    return req("GET", "/v1/policy" + (qs ? "?" + qs : ""));
  },
  running: () => req("GET", "/v1/policy?source=POLICY_SOURCE_RUNNING"),
  candidate: () => req("GET", "/v1/policy?source=POLICY_SOURCE_CANDIDATE"),
  versionPolicy: (v) => req("GET", `/v1/policy?source=POLICY_SOURCE_VERSION&version=${v}`),
  setCandidate: (policy, expectedCandidateRevision = "") => {
    const body = { policy };
    if (expectedCandidateRevision) body.expectedCandidateRevision = expectedCandidateRevision;
    return req("PUT", "/v1/candidate", body);
  },
  candidateStatus: () => req("GET", "/v1/candidate/status"),
  validate: () => req("POST", "/v1/candidate/validate", {}),
  validatePolicy: (policy) => req("POST", "/v1/candidate/validate", { policy }),
  natRules: (opts = {}) => {
    const q = queryParams(opts, ["source", "version"]);
    return req("GET", "/v1/policy/nat" + (q ? "?" + q : ""));
  },
  upsertCandidateSourceNat: ({ id = "", rule, expectedCandidateRevision = "", comment = "", reason = "" } = {}) => {
    id = String(id || "").trim();
    const selector = String(id || rule?.name || "").trim();
    const path = id
      ? `/v1/candidate/nat/source/by-id/${encodeURIComponent(selector)}`
      : `/v1/candidate/nat/source/${encodeURIComponent(selector)}`;
    const body = { rule, expectedCandidateRevision, comment };
    if (id) body.id = id;
    if (reason) body.reason = reason;
    return req("PUT", path, body);
  },
  deleteCandidateSourceNat: ({ id = "", name = "", expectedCandidateRevision = "", comment = "", reason = "" } = {}) => {
    id = String(id || "").trim();
    const selector = String(id || name || "").trim();
    const path = id
      ? `/v1/candidate/nat/source/by-id/${encodeURIComponent(selector)}`
      : `/v1/candidate/nat/source/${encodeURIComponent(selector)}`;
    const qs = natDeleteQuery({ expectedCandidateRevision, comment, reason });
    return req("DELETE", path + (qs ? `?${qs}` : ""));
  },
  upsertCandidateDestinationNat: ({ id = "", rule, expectedCandidateRevision = "", comment = "", reason = "" } = {}) => {
    id = String(id || "").trim();
    const selector = String(id || rule?.name || "").trim();
    const path = id
      ? `/v1/candidate/nat/destination/by-id/${encodeURIComponent(selector)}`
      : `/v1/candidate/nat/destination/${encodeURIComponent(selector)}`;
    const body = { rule, expectedCandidateRevision, comment };
    if (id) body.id = id;
    if (reason) body.reason = reason;
    return req("PUT", path, body);
  },
  deleteCandidateDestinationNat: ({ id = "", name = "", expectedCandidateRevision = "", comment = "", reason = "" } = {}) => {
    id = String(id || "").trim();
    const selector = String(id || name || "").trim();
    const path = id
      ? `/v1/candidate/nat/destination/by-id/${encodeURIComponent(selector)}`
      : `/v1/candidate/nat/destination/${encodeURIComponent(selector)}`;
    const qs = natDeleteQuery({ expectedCandidateRevision, comment, reason });
    return req("DELETE", path + (qs ? `?${qs}` : ""));
  },
  createChangeApproval: (body) => req("POST", "/v1/change-approvals", body),
  changeApprovals: (opts = {}) => {
    const q = queryParams(opts, ["candidateRevision", "includeConsumed", "limit"]);
    return req("GET", "/v1/change-approvals" + (q ? "?" + q : ""));
  },
  createBackupSnapshot: ({ source = "POLICY_SOURCE_RUNNING", version = 0, comment = "" } = {}) => {
    const body = { source, comment };
    if (version) body.version = Number(version);
    return req("POST", "/v1/backup/snapshots", body);
  },
  backupSnapshots: (limit = 100) => req("GET", `/v1/backup/snapshots?limit=${limit}`),
  backupSnapshot: (id) => req("GET", `/v1/backup/snapshots/${encodeURIComponent(id)}`),
  validateBackupSnapshot: (id) => req("POST", `/v1/backup/snapshots/${encodeURIComponent(id)}:validate`, {}),
  previewBackupSnapshotRestore: (id, { comment = "", stageCandidate = false, expectedCandidateRevision = "" } = {}) => {
    const body = { comment, stageCandidate };
    if (expectedCandidateRevision) body.expectedCandidateRevision = expectedCandidateRevision;
    return req("POST", `/v1/backup/snapshots/${encodeURIComponent(id)}:restore-preview`, body);
  },
  commit: async (comment, ackRisk = false, ackRuntime = false, approvalId = "", reviewedCandidateRevision = "") => {
    const stepUp = await stepUpToken("commit", comment || "");
    const body = { comment, ackRisk, ackRuntime };
    if (approvalId) body.approvalId = approvalId;
    if (reviewedCandidateRevision) body.reviewedCandidateRevision = reviewedCandidateRevision;
    body.stepUpToken = stepUp;
    return req("POST", "/v1/commit", body);
  },
  rollback: async (version, comment = "", ackRisk = false, ackRuntime = false) => {
    const stepUp = await stepUpToken("rollback", comment || "");
    return req("POST", "/v1/rollback", { version: String(version), comment, ackRisk, ackRuntime, stepUpToken: stepUp });
  },
  objectReferences: (opts = {}) => {
    const q = queryParams(opts, ["source", "version", "kind", "name"]);
    return req("GET", "/v1/policy/object-references" + (q ? "?" + q : ""));
  },
  policyDiff: (opts = {}) => {
    const q = queryParams(opts, ["fromSource", "fromVersion", "toSource", "toVersion"]);
    return req("GET", "/v1/policy/diff" + (q ? "?" + q : ""));
  },
  versions: (limit = 100) => req("GET", `/v1/versions?limit=${limit}`),
  audit: (opts = 200) => {
    const q = new URLSearchParams();
    if (typeof opts === "number") q.set("limit", String(opts));
    else {
      const fields = ["limit", "actor", "action", "version", "since", "until", "query"];
      for (const key of fields) {
        if (opts?.[key]) q.set(key, String(opts[key]));
      }
    }
    const qs = q.toString();
    return req("GET", "/v1/audit" + (qs ? "?" + qs : ""));
  },
  auditVerify: () => req("GET", "/v1/audit/verify"),
  complianceReports: (opts = {}) => {
    const q = queryParams(opts, ["limit"]);
    return req("GET", "/v1/compliance/reports" + (q ? "?" + q : ""));
  },
  complianceReport: (id) => req("GET", `/v1/compliance/reports/${encodeURIComponent(id)}`),
  createComplianceReport: (body = {}) => req("POST", "/v1/compliance/reports", body),
  exportComplianceReport: (id) => binaryReq(`/v1/compliance/reports/${encodeURIComponent(id)}/export`),

  // Fleet / templates
  fleetNodes: () => req("GET", "/v1/fleet/nodes"),
  fleetTemplates: () => req("GET", "/v1/fleet/templates"),
  createFleetTemplate: (body) => req("POST", "/v1/fleet/templates", body),
  validateFleetTemplate: (templateId) => req("POST", `/v1/fleet/templates/${encodeURIComponent(templateId)}:validate`, {}),
  applyPreviewFleetTemplate: (templateId, body = {}) => req("POST", `/v1/fleet/templates/${encodeURIComponent(templateId)}:apply-preview`, body),
  applyPlanFleetTemplate: (templateId, body = {}) => req("POST", `/v1/fleet/templates/${encodeURIComponent(templateId)}:apply-plan`, body),
  applyFleetTemplate: (templateId, body = {}) => req("POST", `/v1/fleet/templates/${encodeURIComponent(templateId)}:apply`, body),
  fleetTemplateResults: (opts = {}) => {
    const q = queryParams(opts, ["templateId"]);
    return req("GET", "/v1/fleet/template-results" + (q ? "?" + q : ""));
  },
  stageCandidateFleetTemplate: (templateId, body = {}) => req("POST", `/v1/fleet/templates/${encodeURIComponent(templateId)}:stage-candidate`, body),

  // Telemetry
  alerts: (opts = 200) => {
    const q = queryParams(opts, ["limit", "srcIp", "destIp", "ip", "protocol", "action", "severity", "threatSeverity", "signatureId", "port", "since", "until", "query", "flowId", "pageCursor"]);
    return req("GET", "/v1/alerts" + (q ? "?" + q : ""));
  },
  flows: (opts = 200) => {
    const q = queryParams(opts, ["limit", "srcIp", "destIp", "ip", "protocol", "app", "port", "since", "until", "query", "flowId", "pageCursor"]);
    return req("GET", "/v1/flows" + (q ? "?" + q : ""));
  },
  appIdObservations: (opts = 100) => {
    const q = queryParams(opts, ["limit", "flowLimit", "confidenceThreshold", "since", "until", "query", "kind", "engineSignal", "protocol", "port", "pageCursor"]);
    return req("GET", "/v1/app-id/observations" + (q ? "?" + q : ""));
  },
  stageAppIdObservation: (queueId, body) => req("POST", `/v1/app-id/observations/${encodeURIComponent(queueId)}:stage`, body),
  stageAppIdRegressionSample: (queueId, body) => req("POST", `/v1/app-id/observations/${encodeURIComponent(queueId)}:stage-regression-sample`, body),
  compareAppIdReplay: (body) => req("POST", "/v1/app-id/replay:compare", body),
  sessions: (opts = 200) => {
    const q = queryParams(opts, ["limit", "srcIp", "destIp", "ip", "protocol", "port", "state", "query", "pageCursor"]);
    return req("GET", "/v1/sessions" + (q ? "?" + q : ""));
  },
  threatExceptions: (opts = {}) => {
    const q = queryParams(opts, ["source", "version"]);
    return req("GET", "/v1/threat-exceptions" + (q ? "?" + q : ""));
  },
  stageThreatException: (body) => req("POST", "/v1/threat-exceptions:stage", body),
  updateThreatException: (name, body) => req("PATCH", `/v1/threat-exceptions/${encodeURIComponent(name)}`, body),
  setThreatExceptionState: (name, body) => req("POST", `/v1/threat-exceptions/${encodeURIComponent(name)}:set-state`, body),
  removeThreatException: (name, reason) => req("POST", `/v1/threat-exceptions/${encodeURIComponent(name)}:remove`, { reason }),
  replayThreatEvidence: (body = {}) => req("POST", "/v1/threat-id/replay:check", body),
  explainFlow: (body) => req("POST", "/v1/explain/flow", body),
  packetCaptures: (opts = 25) => {
    const q = queryParams(opts, ["limit", "flowId"]);
    return req("GET", "/v1/system/packet-captures" + (q ? "?" + q : ""));
  },
  planPacketCapture: (body) => req("POST", "/v1/system/packet-captures/plan", body),
  startPacketCapture: (body) => req("POST", "/v1/system/packet-captures", body),
  downloadPacketCapture: (artifactId) => binaryReq(`/v1/system/packet-captures/${encodeURIComponent(artifactId)}/download`),
  setPacketCaptureRetention: (artifactId, body) => req("POST", `/v1/system/packet-captures/${encodeURIComponent(artifactId)}:set-retention`, body),
  identity: () => req("GET", "/v1/system/identity"),
  identityWithToken: (token) => req("GET", "/v1/system/identity", undefined, { tokenOverride: token }),

  // Intel
  feeds: () => req("GET", "/v1/intel/feeds"),
  contentPackages: () => req("GET", "/v1/intel/content/packages"),
  contentEvidence: (kind, evidenceType) => req("GET", `/v1/intel/content/packages/${encodeURIComponent(kind)}/evidence/${encodeURIComponent(evidenceType)}`),
  contentCorpus: (kind, opts = {}) => {
    const normalized = { ...opts };
    if (opts?.evidenceType && !normalized.evidence_type) normalized.evidence_type = opts.evidenceType;
    const q = queryParams(normalized, ["evidence_type", "query", "verdict", "limit"]);
    return req("GET", `/v1/intel/content/packages/${encodeURIComponent(kind)}/corpus` + (q ? "?" + q : ""));
  },
  previewContentPackage: (kind, sourcePath) => req("POST", `/v1/intel/content/packages/${encodeURIComponent(kind)}/preview`, { sourcePath }),
  compareContentPackage: (kind, sourcePath, evidenceType = "") => req("POST", `/v1/intel/content/packages/${encodeURIComponent(kind)}/compare`, { sourcePath, evidenceType }),
  installContentPackage: async (kind, sourcePath) => {
    const stepUp = await stepUpToken("content-package-install", `Install ${kind} content package`);
    return req("POST", `/v1/intel/content/packages/${encodeURIComponent(kind)}/install`, { sourcePath, stepUpToken: stepUp });
  },
  rollbackContentPackage: async (kind) => {
    const stepUp = await stepUpToken("content-package-rollback", `Rollback ${kind} content package`);
    return req("POST", `/v1/intel/content/packages/${encodeURIComponent(kind)}/rollback`, { ackRollback: true, stepUpToken: stepUp });
  },
  refreshFeeds: () => req("POST", "/v1/intel/refresh", {}),
};

function queryParams(opts, fields) {
  const q = new URLSearchParams();
  if (typeof opts === "number") q.set("limit", String(opts));
  else {
    for (const key of fields) {
      if (opts?.[key]) q.set(key, String(opts[key]));
    }
  }
  return q.toString();
}

function natDeleteQuery({ expectedCandidateRevision = "", comment = "", reason = "" } = {}) {
  const q = new URLSearchParams();
  if (expectedCandidateRevision) q.set("expectedCandidateRevision", String(expectedCandidateRevision));
  if (comment) q.set("comment", String(comment));
  if (reason) q.set("reason", String(reason));
  return q.toString();
}
