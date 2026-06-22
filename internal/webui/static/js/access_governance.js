const ACCESS_GOVERNANCE_WORKFLOWS = [
  { id: "read", label: "Read evidence", requiredRole: "viewer", detail: "Dashboard, policy, telemetry, readiness, and audit evidence." },
  { id: "stage", label: "Stage candidate edits", requiredRole: "operator", detail: "Policy, network, IDS/IPS, telemetry, and host-input candidate changes." },
  { id: "commit", label: "Validate and commit", requiredRole: "operator", detail: "Server validation, preflight review, and live policy apply.", auditActions: ["commit", "commit-intent"] },
  { id: "rollback", label: "Roll back policy", requiredRole: "operator", detail: "Version rollback with audit comment and impact acknowledgement.", auditActions: ["rollback", "rollback-intent"] },
  { id: "host-tune", label: "Tune host runtime", requiredRole: "admin", detail: "Kernel, service, and dataplane host preparation changes.", auditActions: ["system-tune"] },
  { id: "packet-capture", label: "Start packet capture", requiredRole: "admin", detail: "Runtime packet capture jobs and capture file creation.", auditActions: ["packet-capture"] },
  { id: "content-install", label: "Install content package", requiredRole: "admin", detail: "Promote App-ID or Threat-ID content from the firewall import directory.", auditActions: ["content-package-install", "content-package-install-intent", "content-package-install-failed"] },
  { id: "content-rollback", label: "Roll back content package", requiredRole: "admin", detail: "Restore the latest verified content rollback point.", auditActions: ["content-package-rollback", "content-package-rollback-intent"] },
  { id: "access-admin", label: "Administer access", requiredRole: "admin", detail: "Create, rotate, role-change, disable local users, manage OIDC/SAML IdP posture, and revoke browser sessions.", auditActions: ["access-local-user-create", "access-local-user-update", "access-local-user-rotate-token", "access-local-user-disable", "access-oidc-provider-set", "access-oidc-provider-disable", "access-saml-provider-set", "access-saml-provider-disable", "access-session-revoke"] },
];

const ROLE_RANK = { viewer: 1, operator: 2, admin: 3 };
const ACCESS_GOVERNANCE_ROLES = ["viewer", "operator", "admin"];

export function accessGovernanceModel(rt = {}, identity = null, oidc = {}) {
  const hasAdministrationInput = arguments.length >= 4;
  const administration = accessAdministrationModel(rt, oidc, arguments[3], { requested: hasAdministrationInput });
  const localAdmin = Object.prototype.hasOwnProperty.call(rt, "authEnabled") && !rt.authEnabled;
  const role = identity?.role || (localAdmin ? "admin" : "unknown");
  const actor = identity?.actor || (localAdmin ? "local admin mode" : "unverified browser");
  const authSource = identity?.authSource || (localAdmin ? "auth-disabled" : "unknown");
  const capabilitySummary = summarizeCapabilities(identity?.capabilities, localAdmin ? ["read", "write", "admin"] : []);
  const capabilities = capabilitySummary.values;
  const oidcSessionActive = identity?.authSource === "oidc-session" || Boolean(oidc?.authenticated);
  const sessionLabel = oidcSessionActive ? "OIDC active" : oidc?.enabled ? "not signed in" : identity?.actor ? "API token" : localAdmin ? "local" : "unverified";
  const sessionClass = oidcSessionActive || identity?.actor || localAdmin ? "ok" : oidc?.enabled ? "warn" : "neutral";
  const csrfReady = Boolean(oidc?.csrf_token || oidc?.csrfToken);
  const csrfLabel = csrfReady ? "CSRF ready" : oidc?.enabled ? "after sign-in" : "not required";
  const csrfClass = csrfReady || !oidc?.enabled ? "ok" : "warn";
  return {
    actor,
    role,
    authSource,
    capabilities,
    capabilitiesLabel: capabilitySummary.label,
    capabilitySummary,
    sessionLabel,
    sessionClass,
    csrfLabel,
    csrfClass,
    rows: accessGovernanceRows(role),
    roleMatrix: accessRoleWorkflowMatrix(),
    administration,
    adminReadiness: hasAdministrationInput
      ? accessAdminReadiness(rt, identity, oidc, administration)
      : accessAdminReadiness(rt, identity, oidc),
    actorAuditHash: identity?.actor ? accessAuditHash({ actor: identity.actor }) : "",
    authSourceAuditHash: authSource && authSource !== "unknown" ? accessAuditHash({ query: authSource }) : "",
  };
}

export function accessAdminReadiness(rt = {}, identity = null, oidc = {}) {
  if (arguments.length >= 4) {
    const administration = arguments[3]?.normalized
      ? arguments[3]
      : accessAdministrationModel(rt, oidc, arguments[3], { requested: true });
    return administration.available
      ? accessAdministrationReadiness(rt, identity, oidc, administration)
      : unavailableAdministrationReadiness(rt, identity, oidc, administration);
  }

  const authKnown = Object.prototype.hasOwnProperty.call(rt, "authEnabled");
  const authEnabled = authKnown ? !!rt.authEnabled : null;
  const admin = roleAllows(identity?.role || (authEnabled === false ? "admin" : "unknown"), "admin");
  const items = [
    {
      id: "users-roles",
      label: "User and role administration",
      status: "not loaded",
      cls: "warn",
      detail: "Access administration inventory was not loaded for this view.",
      nextAction: "Load GET /v1/system/access-administration with an admin-capable session before production sign-off.",
      evidence: "Settings is using current identity only.",
    },
    {
      id: "sessions",
      label: "Session revocation",
      status: "not loaded",
      cls: "warn",
      detail: "Browser SSO session inventory and revoke posture were not loaded for this view.",
      nextAction: "Load access administration inventory before relying on multi-admin browser SSO operations.",
      evidence: oidc?.enabled ? "OIDC status is visible, but shared browser-session administration data is not loaded." : "OIDC is not enabled.",
    },
    {
      id: "idp-lifecycle",
      label: "IdP lifecycle",
      status: oidc?.enabled ? "status only" : "not configured",
      cls: "warn",
      detail: "OIDC status is visible; load access administration to review SAML runtime posture and provider lifecycle evidence.",
      nextAction: oidc?.enabled
        ? "Run OIDC preflight from Settings and record rollout evidence before production SSO sign-off."
        : "Add IdP configuration, health check, and test-login APIs before production SSO rollout.",
      evidence: oidc?.enabled ? "OIDC status endpoint is reachable." : "No active OIDC provider reported.",
    },
    {
      id: "break-glass",
      label: "Break-glass control",
      status: authEnabled === false ? "auth disabled" : "not exposed",
      cls: authEnabled === false ? "bad" : "warn",
      detail: authEnabled === false
        ? "Authentication is disabled, so every local caller is effectively admin."
        : "No audited local emergency account lifecycle or recovery-code rotation surface is exposed.",
      nextAction: authEnabled === false
        ? "Enable authentication and replace auth-disabled operation with audited break-glass credentials."
        : "Add audited break-glass account and recovery-code lifecycle controls.",
      evidence: authEnabled === false ? "Runtime reports authEnabled=false." : "Runtime identity exposes no break-glass lifecycle state.",
    },
  ];
  const blockers = items.filter((item) => item.cls === "bad");
  const warnings = items.filter((item) => item.cls === "warn");
  return {
    cls: blockers.length ? "bad" : warnings.length ? "warn" : "ok",
    label: blockers.length ? `${blockers.length} blocker${blockers.length === 1 ? "" : "s"}` : warnings.length ? `${warnings.length} review item${warnings.length === 1 ? "" : "s"}` : "ready",
    detail: blockers.length
      ? "Access governance has blocking posture gaps before enterprise multi-admin production."
      : warnings.length
      ? "Access governance has review items before production sign-off."
      : "Access governance administration data is loaded.",
    adminVerified: admin,
    items,
  };
}

export function accessAdministrationUnavailable(reason = {}) {
  return {
    unavailable: true,
    status: Number.isFinite(reason?.status) ? reason.status : null,
    message: errorMessage(reason),
  };
}

export function accessAdministrationModel(rt = {}, oidc = {}, administration = null, opts = {}) {
  const requested = opts.requested !== false;
  if (administration?.normalized) return administration;
  const unavailable = Boolean(administration?.unavailable || administration?.available === false);
  if (!requested || !administration || unavailable) {
    return {
      normalized: true,
      available: false,
      requested,
      readOnly: true,
      source: unavailable ? "unavailable" : "fallback",
      cls: unavailable ? "warn" : "neutral",
      label: unavailable ? "endpoint unavailable" : "not loaded",
      detail: unavailable
        ? unavailableAdministrationDetail(administration)
        : "Access administration endpoint was not loaded.",
      authEnabled: boolOrNull(undefined, runtimeAuthEnabled(rt)),
      localUsers: [],
      oidc: normalizeAccessOidc(null, oidc),
      saml: normalizeAccessSaml(null),
      sessions: normalizeAccessSessions(null),
      breakGlass: normalizeAccessBreakGlass(null, runtimeAuthEnabled(rt)),
      blockers: [],
    };
  }

  const authEnabled = boolOrNull(administration.authEnabled, runtimeAuthEnabled(rt));
  const localUsers = normalizeAccessLocalUsers(administration.localUsers);
  const oidcPosture = normalizeAccessOidc(administration.oidc, oidc);
  const samlPosture = normalizeAccessSaml(administration.saml);
  const sessions = normalizeAccessSessions(administration.sessions);
  const breakGlass = normalizeAccessBreakGlass(administration.breakGlass, authEnabled);
  const blockers = normalizeAccessBlockers(administration.blockers);
  const warnCount = [oidcPosture, samlPosture, sessions, breakGlass].filter((item) => item.cls === "warn").length;
  const badCount = blockers.length + [oidcPosture, samlPosture, sessions, breakGlass].filter((item) => item.cls === "bad").length;
  return {
    normalized: true,
    available: true,
    requested: true,
    readOnly: false,
    source: "endpoint",
    cls: badCount ? "bad" : warnCount ? "warn" : "ok",
    label: blockers.length
      ? `${blockers.length} blocker${blockers.length === 1 ? "" : "s"}`
      : warnCount
      ? `${warnCount} review item${warnCount === 1 ? "" : "s"}`
      : "inventory loaded",
    detail: blockers.length
      ? "Access administration inventory loaded; backend reports access blockers."
      : "Access administration inventory loaded.",
    authEnabled,
    localUsers,
    oidc: oidcPosture,
    saml: samlPosture,
    sessions,
    breakGlass,
    blockers,
  };
}

export function accessGovernanceRows(role = "unknown") {
  return accessGovernanceWorkflows().map((workflow) => ({
    ...workflow,
    allowed: roleAllows(role, workflow.requiredRole),
    roleAccess: accessRoleWorkflowAccess(workflow),
  }));
}

export function accessGovernanceWorkflows() {
  return ACCESS_GOVERNANCE_WORKFLOWS.map((workflow) => ({
    ...workflow,
    auditLinks: accessWorkflowAuditLinks(workflow),
  }));
}

export function accessRoleWorkflowMatrix() {
  return accessGovernanceWorkflows().map((workflow) => ({
    id: workflow.id,
    label: workflow.label,
    requiredRole: workflow.requiredRole,
    roles: accessRoleWorkflowAccess(workflow),
  }));
}

export function roleImpactPreview(currentRole = "unknown", targetRole = "viewer") {
  const current = normalizeRole(currentRole);
  const target = normalizeRole(targetRole);
  const currentKnown = ACCESS_GOVERNANCE_ROLES.includes(current);
  const targetKnown = ACCESS_GOVERNANCE_ROLES.includes(target);
  const workflows = accessGovernanceWorkflows();
  const rows = workflows.map((workflow) => {
    const before = currentKnown && roleAllows(current, workflow.requiredRole);
    const after = targetKnown && roleAllows(target, workflow.requiredRole);
    const change = !before && after
      ? "newly allowed"
      : before && !after
      ? "lost"
      : after
      ? "still allowed"
      : "restricted";
    return {
      id: workflow.id,
      label: workflow.label,
      detail: workflow.detail,
      requiredRole: workflow.requiredRole,
      before,
      after,
      change,
      cls: change === "newly allowed" ? "ok" : change === "lost" ? "bad" : after ? "info" : "neutral",
    };
  });
  const gained = rows.filter((row) => row.change === "newly allowed");
  const lost = rows.filter((row) => row.change === "lost");
  const allowed = rows.filter((row) => row.after);
  const restricted = rows.filter((row) => !row.after);
  const currentRank = currentKnown ? ROLE_RANK[current] : 0;
  const targetRank = targetKnown ? ROLE_RANK[target] : 0;
  const direction = !targetKnown
    ? "invalid"
    : targetRank > currentRank
    ? "escalation"
    : targetRank < currentRank
    ? "demotion"
    : currentKnown
    ? "unchanged"
    : "assignment";
  return {
    currentRole: current,
    targetRole: target,
    currentKnown,
    targetKnown,
    direction,
    cls: !targetKnown ? "warn" : lost.length ? "bad" : gained.length ? "ok" : "neutral",
    label: roleImpactLabel(direction, gained.length, lost.length, allowed.length),
    detail: roleImpactDetail(direction, current, target, gained, lost, allowed, targetKnown),
    gained,
    lost,
    allowed,
    restricted,
    rows,
  };
}

export function oidcPreflightModel(data = null) {
  const checks = normalizeOIDCPreflightChecks(data?.checks);
  const blockers = normalizeStringList(data?.blockers).map((label, idx) => ({
    id: `blocker-${idx + 1}`,
    label: sanitizeOIDCText(label),
    cls: "bad",
  }));
  const warnings = normalizeStringList(data?.warnings).map((label, idx) => ({
    id: `warning-${idx + 1}`,
    label: sanitizeOIDCText(label),
    cls: "warn",
  }));
  const state = textValue(data?.state, blockers.length ? "blocked" : warnings.length ? "review" : checks.length ? "ready" : "unknown").toLowerCase();
  const cls = oidcPreflightClass(state, checks, blockers, warnings);
  const evidence = normalizeStringList(data?.evidence).map(sanitizeOIDCText);
  const oidc = normalizeAccessOidc(data?.oidc, {});
  return {
    normalized: true,
    schemaVersion: textValue(data?.schemaVersion, "openngfw.oidc-preflight.v1"),
    generatedAt: textValue(data?.generatedAt, "not reported"),
    state,
    cls,
    label: textValue(data?.label, state),
    detail: sanitizeOIDCText(textValue(data?.detail, "OIDC preflight did not return a detail string.")),
    oidc,
    checks,
    blockers,
    warnings,
    evidence,
    rows: [
      { label: "State", value: state, cls },
      { label: "Generated", value: textValue(data?.generatedAt, "not reported") },
      { label: "Schema", value: textValue(data?.schemaVersion, "openngfw.oidc-preflight.v1") },
      { label: "Issuer", value: oidc.issuer },
      { label: "Client ID", value: oidc.clientId },
      { label: "Cookie secure", value: oidc.cookieSecure === null ? "unknown" : oidc.cookieSecure ? "yes" : "no", cls: oidc.cookieSecure === false ? "bad" : "ok" },
    ],
  };
}

export function oidcPreflightEvidenceText(model = {}) {
  const m = model?.normalized ? model : oidcPreflightModel(model);
  const lines = [
    `OIDC preflight: ${m.state} (${m.label})`,
    `schema=${m.schemaVersion}`,
    `generated_at=${m.generatedAt}`,
    `issuer=${m.oidc.issuer}`,
    `client_id=${m.oidc.clientId}`,
    `cookie_secure=${m.oidc.cookieSecure === null ? "unknown" : m.oidc.cookieSecure ? "true" : "false"}`,
    "",
    "Checks:",
    ...m.checks.map((check) => `- [${check.cls.toUpperCase()}] ${check.label}: ${check.detail} Evidence: ${check.evidence}`),
  ];
  if (m.blockers.length) {
    lines.push("", "Blockers:", ...m.blockers.map((blocker) => `- ${blocker.label}`));
  }
  if (m.warnings.length) {
    lines.push("", "Warnings:", ...m.warnings.map((warning) => `- ${warning.label}`));
  }
  if (m.evidence.length) {
    lines.push("", "Evidence:", ...m.evidence.map((item) => `- ${item}`));
  }
  return lines.map(sanitizeOIDCText).join("\n");
}

export function oidcRolloutPlan(values = {}, administration = {}, runtimeOidc = {}) {
  const admin = administration?.normalized ? administration : accessAdministrationModel({}, runtimeOidc, administration, { requested: Boolean(administration) });
  const issuer = sanitizeOIDCText(textValue(values.issuer, "")).replace(/\/+$/, "");
  const clientId = sanitizeOIDCText(textValue(values.clientId, ""));
  const redirectUrl = sanitizeOIDCText(textValue(values.redirectUrl, ""));
  const roleClaim = sanitizeOIDCText(textValue(values.roleClaim, "role"));
  const defaultRole = normalizeRole(values.defaultRole || "viewer");
  const scopes = normalizeStringList(values.scopes || "openid,profile,email");
  const trustedProxyCidrs = normalizeStringList(values.trustedProxyCidrs || "");
  const clientSecretFile = sanitizeOIDCText(textValue(values.clientSecretFile, ""));
  const blockers = [];
  const warnings = [];
  const checks = [];
  const addCheck = (id, label, ok, detail, nextAction = "") => {
    const item = {
      id,
      label,
      state: ok ? "ready" : "blocked",
      cls: ok ? "ok" : "bad",
      detail,
      nextAction: nextAction || (ok ? "Keep this setting in the activation runbook." : "Fix this setting before activating OIDC."),
    };
    checks.push(item);
    if (!ok) blockers.push(item.detail);
  };

  const issuerURL = parseAbsoluteURL(issuer);
  const issuerLoopback = Boolean(issuerURL && /^http:$/i.test(issuerURL.protocol) && /^(localhost|127\.0\.0\.1|::1)$/i.test(issuerURL.hostname));
  addCheck("issuer", "Issuer URL", Boolean(issuerURL && (/^https:$/i.test(issuerURL.protocol) || issuerLoopback)),
    issuerURL
      ? issuerLoopback
        ? "Loopback HTTP issuer is accepted for node-local validation only."
        : "Issuer must use HTTPS for production browser SSO."
      : "Issuer URL is required and must be absolute HTTPS.",
    "Use the IdP issuer URL from the discovery document.");
  if (issuerLoopback) {
    warnings.push("Loopback HTTP issuer is valid only for node-local smoke or lab validation.");
  }
  addCheck("client-id", "Client ID", Boolean(clientId), clientId ? "Client ID is present." : "Client ID is required.",
    "Create or select the firewall WebUI application in the IdP.");
  const redirect = parseAbsoluteURL(redirectUrl);
  const redirectLoopback = Boolean(redirect && /^(localhost|127\.0\.0\.1|::1)$/i.test(redirect.hostname));
  addCheck("redirect-url", "Redirect URL", Boolean(redirect && /^https?:$/i.test(redirect.protocol) && redirect.pathname === "/v1/auth/oidc/callback"),
    redirect ? "Redirect URL must point at /v1/auth/oidc/callback." : "Redirect URL is required and must be absolute.",
    "Register the exact callback URL on the IdP application.");
  if (redirect && redirect.protocol === "http:" && !redirectLoopback) {
    blockers.push("OIDC redirect URL must use HTTPS unless the redirect host is loopback.");
    checks.push({
      id: "redirect-https",
      label: "Redirect HTTPS",
      state: "blocked",
      cls: "bad",
      detail: "OIDC redirect URL must use HTTPS unless the redirect host is loopback.",
      nextAction: "Use HTTPS directly or behind a trusted TLS terminator before browser SSO rollout.",
    });
  }
  addCheck("openid-scope", "OpenID scope", scopes.includes("openid"),
    scopes.includes("openid") ? "Scopes include openid." : "Scopes must include openid.",
    "Add openid to the OIDC scopes.");
  addCheck("default-role", "Default role", ["viewer", "operator", "admin"].includes(defaultRole),
    ["viewer", "operator", "admin"].includes(defaultRole) ? `Default role ${defaultRole} is valid.` : "Default role must be viewer, operator, or admin.",
    "Use viewer for least-privilege rollout unless the IdP role claim is proven.");

  const localAdmins = (admin.localUsers || []).filter((user) => user.enabled && user.role === "admin");
  const breakGlassReady = localAdmins.length > 0 && admin.breakGlass?.cls !== "bad";
  if (!breakGlassReady) {
    blockers.push("At least one enabled local admin break-glass credential is required before OIDC rollout.");
  }
  checks.push({
    id: "break-glass",
    label: "Break-glass local admin",
    state: breakGlassReady ? "ready" : "blocked",
    cls: breakGlassReady ? "ok" : "bad",
    detail: breakGlassReady
      ? `${localAdmins.length} enabled local admin credential${localAdmins.length === 1 ? "" : "s"} available.`
      : "No enabled local admin credential is available for emergency recovery.",
    nextAction: breakGlassReady
      ? "Verify the credential is stored in the approved secret manager before rollout."
      : "Create or rotate an enabled local admin before activating OIDC.",
  });

  if (defaultRole === "admin") warnings.push("Default admin role grants broad access when the IdP role claim is absent.");
  if (!clientSecretFile) warnings.push("No client secret file is set; use only for public-client IdP configurations.");
  if (!trustedProxyCidrs.length) warnings.push("No trusted proxy CIDRs are set; forwarded browser scheme/client IP headers will be ignored.");

  const args = [
    ["--oidc-issuer", issuer],
    ["--oidc-client-id", clientId],
    ["--oidc-redirect-url", redirectUrl],
    ["--oidc-role-claim", roleClaim || "role"],
    ["--oidc-default-role", defaultRole || "viewer"],
    ["--oidc-scopes", scopes.join(",")],
    clientSecretFile ? ["--oidc-client-secret-file", clientSecretFile] : null,
    trustedProxyCidrs.length ? ["--trusted-proxy-cidrs", trustedProxyCidrs.join(",")] : null,
  ].filter(Boolean);
  const command = ["controld", ...args.flatMap(([flag, value]) => [flag, shellQuote(value)])].join(" ");
  return {
    normalized: true,
    state: blockers.length ? "blocked" : warnings.length ? "review" : "ready",
    cls: blockers.length ? "bad" : warnings.length ? "warn" : "ok",
    label: blockers.length
      ? `${blockers.length} blocker${blockers.length === 1 ? "" : "s"}`
      : warnings.length
      ? `${warnings.length} review item${warnings.length === 1 ? "" : "s"}`
      : "ready",
    values: { issuer, clientId, redirectUrl, roleClaim, defaultRole, scopes, trustedProxyCidrs, clientSecretFile: clientSecretFile ? "[path set]" : "" },
    checks,
    blockers: blockers.map(sanitizeOIDCText),
    warnings: warnings.map(sanitizeOIDCText),
    command: sanitizeOIDCText(command),
    systemdDropIn: oidcSystemdDropIn(args),
    breakGlassReady,
    localAdminCount: localAdmins.length,
  };
}

export function oidcRolloutInitialValues(oidc = {}) {
  const enabled = Boolean(oidc?.enabled);
  const scopes = normalizeStringList(oidc?.scopes);
  const trustedProxyCidrs = normalizeStringList(oidc?.trustedProxyCidrs || oidc?.trusted_proxy_cidrs);
  const secretConfigured = boolOrNull(oidc?.clientSecretFileConfigured, boolOrNull(oidc?.client_secret_file_configured, false));
  return {
    issuer: enabled ? textValue(oidc?.issuer, "") : "",
    clientId: enabled ? textValue(oidc?.clientId || oidc?.client_id, "") : "",
    redirectUrl: enabled ? textValue(oidc?.redirectUrl || oidc?.redirect_url, "") : "",
    roleClaim: enabled ? textValue(oidc?.roleClaim || oidc?.role_claim, "role") : "role",
    defaultRole: enabled ? normalizeRole(oidc?.defaultRole || oidc?.default_role || "viewer") : "viewer",
    scopes: enabled && scopes.length ? scopes.join(",") : "openid,profile,email",
    trustedProxyCidrs: enabled ? trustedProxyCidrs.join(",") : "",
    clientSecretFile: "",
    clientSecretFilePlaceholder: enabled && secretConfigured
      ? "configured; enter a new server-local path to rotate"
      : "/etc/openngfw/oidc-client-secret",
  };
}

export function oidcRolloutPlanText(plan = {}) {
  const p = plan?.normalized ? plan : oidcRolloutPlan(plan);
  const lines = [
    `OIDC rollout plan: ${p.state} (${p.label})`,
    `issuer=${p.values.issuer || ""}`,
    `client_id=${p.values.clientId || ""}`,
    `redirect_url=${p.values.redirectUrl || ""}`,
    `role_claim=${p.values.roleClaim || ""}`,
    `default_role=${p.values.defaultRole || ""}`,
    `scopes=${formatList(p.values.scopes || [])}`,
    `trusted_proxy_cidrs=${formatList(p.values.trustedProxyCidrs || [])}`,
    `client_secret_file=${p.values.clientSecretFile || "not set"}`,
    `break_glass_local_admins=${p.localAdminCount}`,
    "",
    "Checks:",
    ...p.checks.map((check) => `- [${check.cls.toUpperCase()}] ${check.label}: ${check.detail} Next: ${check.nextAction}`),
  ];
  if (p.blockers.length) lines.push("", "Blockers:", ...p.blockers.map((item) => `- ${item}`));
  if (p.warnings.length) lines.push("", "Warnings:", ...p.warnings.map((item) => `- ${item}`));
  lines.push("", "Activation command:", p.command || "not available");
  lines.push("", "systemd drop-in:", p.systemdDropIn || "not available");
  return lines.map(sanitizeOIDCText).join("\n");
}

export function samlRolloutPlan(values = {}, administration = {}) {
  const admin = administration?.normalized ? administration : accessAdministrationModel({}, {}, administration, { requested: Boolean(administration) });
  const idpEntityId = sanitizeOIDCText(textValue(values.idpEntityId, ""));
  const metadataUrl = sanitizeOIDCText(textValue(values.metadataUrl, ""));
  const ssoUrl = sanitizeOIDCText(textValue(values.ssoUrl, ""));
  const spEntityId = sanitizeOIDCText(textValue(values.spEntityId, ""));
  const acsUrl = sanitizeOIDCText(textValue(values.acsUrl, ""));
  const roleAttribute = sanitizeOIDCText(textValue(values.roleAttribute, "groups"));
  const defaultRole = normalizeRole(values.defaultRole || "viewer");
  const certificateFingerprint = sanitizeOIDCText(textValue(values.certificateFingerprint, ""));
  const checks = [];
  const blockers = [];
  const warnings = [];
  const addCheck = (id, label, ok, detail, nextAction = "") => {
    checks.push({
      id,
      label,
      state: ok ? "ready" : "blocked",
      cls: ok ? "ok" : "bad",
      detail,
      nextAction: nextAction || (ok ? "Keep this setting in the SAML rollout packet." : "Resolve this setting before SAML can be activated."),
    });
    if (!ok) blockers.push(detail);
  };

  const metadata = parseAbsoluteURL(metadataUrl);
  const sso = parseAbsoluteURL(ssoUrl);
  const acs = parseAbsoluteURL(acsUrl);
  addCheck("metadata-or-sso", "Metadata or SSO URL", Boolean((metadata && /^https:$/i.test(metadata.protocol)) || (sso && /^https:$/i.test(sso.protocol))),
    "SAML requires an HTTPS IdP metadata URL or SSO URL.",
    "Export IdP metadata and verify it from the firewall management plane.");
  addCheck("idp-entity", "IdP entity ID", Boolean(idpEntityId), "IdP entity ID is required.",
    "Copy the entityID from the IdP metadata document.");
  addCheck("sp-entity", "SP entity ID", Boolean(spEntityId), "Service-provider entity ID is required.",
    "Reserve the firewall WebUI SP entity ID in the IdP application.");
  addCheck("acs-url", "ACS URL", Boolean(acs && /^https:$/i.test(acs.protocol) && acs.pathname === "/v1/auth/saml/acs"),
    "ACS URL must be HTTPS and point at /v1/auth/saml/acs.",
    "Register the exact assertion-consumer URL on the IdP application.");
  addCheck("role-attribute", "Role attribute", Boolean(roleAttribute), "Role/group attribute is required for RBAC mapping.",
    "Map IdP groups to viewer, operator, and admin roles.");
  addCheck("signing-cert", "Signing certificate", Boolean(certificateFingerprint),
    "IdP signing certificate fingerprint is required for metadata pinning.",
    "Record the SHA-256 fingerprint from the trusted IdP metadata.");

  const localAdmins = (admin.localUsers || []).filter((user) => user.enabled && user.role === "admin");
  const breakGlassReady = localAdmins.length > 0 && admin.breakGlass?.cls !== "bad";
  if (!breakGlassReady) blockers.push("At least one enabled local admin break-glass credential is required before SAML rollout.");
  checks.push({
    id: "break-glass",
    label: "Break-glass local admin",
    state: breakGlassReady ? "ready" : "blocked",
    cls: breakGlassReady ? "ok" : "bad",
    detail: breakGlassReady
      ? `${localAdmins.length} enabled local admin credential${localAdmins.length === 1 ? "" : "s"} available.`
      : "No enabled local admin credential is available for emergency recovery.",
    nextAction: breakGlassReady
      ? "Verify the credential is stored in the approved secret manager before rollout."
      : "Create or rotate an enabled local admin before activating SAML.",
  });
  if (defaultRole === "admin") warnings.push("Default admin role grants broad access when the SAML role attribute is absent.");

  const state = blockers.length ? "blocked" : warnings.length ? "review" : "ready";
  const cls = blockers.length ? "bad" : warnings.length ? "warn" : "ok";
  const label = blockers.length
    ? `${blockers.length} blocker${blockers.length === 1 ? "" : "s"}`
    : warnings.length
    ? `${warnings.length} review item${warnings.length === 1 ? "" : "s"}`
    : "ready";
  return {
    normalized: true,
    state,
    cls,
    label,
    values: { idpEntityId, metadataUrl, ssoUrl, spEntityId, acsUrl, roleAttribute, defaultRole, certificateFingerprint: certificateFingerprint ? "[fingerprint set]" : "" },
    checks,
    blockers: blockers.map(sanitizeOIDCText),
    warnings: warnings.map(sanitizeOIDCText),
    breakGlassReady,
    localAdminCount: localAdmins.length,
    command: "ngfwctl access saml provider validate --metadata-url <https-url> --idp-entity-id <entity-id> --sp-entity-id <entity-id> --acs-url <https-url> --role-attribute <attribute>",
  };
}

export function samlRolloutPlanText(plan = {}) {
  const p = plan?.normalized ? plan : samlRolloutPlan(plan);
  const lines = [
    `SAML rollout plan: ${p.state} (${p.label})`,
    `idp_entity_id=${p.values.idpEntityId || ""}`,
    `metadata_url=${p.values.metadataUrl || ""}`,
    `sso_url=${p.values.ssoUrl || ""}`,
    `sp_entity_id=${p.values.spEntityId || ""}`,
    `acs_url=${p.values.acsUrl || ""}`,
    `role_attribute=${p.values.roleAttribute || ""}`,
    `default_role=${p.values.defaultRole || ""}`,
    `signing_certificate=${p.values.certificateFingerprint || "not set"}`,
    `break_glass_local_admins=${p.localAdminCount}`,
    "",
    "Checks:",
    ...p.checks.map((check) => `- [${check.cls.toUpperCase()}] ${check.label}: ${check.detail} Next: ${check.nextAction}`),
  ];
  if (p.blockers.length) lines.push("", "Blockers:", ...p.blockers.map((item) => `- ${item}`));
  if (p.warnings.length) lines.push("", "Warnings:", ...p.warnings.map((item) => `- ${item}`));
  lines.push("", "Planned validation command:", p.command || "not available");
  return lines.map(sanitizeOIDCText).join("\n");
}

export function accessLifecycleReviewModel(rt = {}, identity = null, oidc = {}, administration = null) {
  const admin = administration?.normalized ? administration : accessAdministrationModel(rt, oidc, administration, { requested: true });
  const readiness = admin.available
    ? accessAdministrationReadiness(rt, identity, oidc, admin)
    : unavailableAdministrationReadiness(rt, identity, oidc, admin);
  const enabledLocalAdmins = (admin.localUsers || []).filter((user) => user.enabled && user.role === "admin");
  const activeSessions = admin.sessions?.activeSessions || [];
  const backendBlockerRows = (admin.blockers || []).map((blocker, idx) => ({
    id: `backend-blocker-${idx + 1}`,
    label: "Backend access blocker",
    state: "blocked",
    cls: "bad",
    detail: blocker.label || String(blocker || "Access blocker reported."),
    nextAction: "Clear the backend-reported access blocker before provider lifecycle changes.",
    evidence: "GET /v1/system/access-administration blockers.",
  }));
  const providerRows = [
    {
      id: "oidc",
      label: "OIDC provider",
      state: admin.oidc?.enabled ? "configured" : "not configured",
      cls: admin.oidc?.enabled ? admin.oidc.cls : "warn",
      detail: admin.oidc?.detail || "OIDC provider posture is not available.",
      nextAction: admin.oidc?.enabled
        ? "Run OIDC preflight, verify cookie/proxy/session posture, then record the provider rollout packet."
        : "Configure and validate OIDC only after at least one local break-glass admin is available.",
      evidence: admin.oidc?.enabled ? admin.oidc.issuer : "OIDC disabled.",
      auditHash: accessAuditHash({ action: "access-oidc-provider-set" }),
    },
    {
      id: "saml",
      label: "SAML provider",
      state: admin.saml?.enabled ? (admin.saml.runtimeAvailable ? "runtime ready" : "runtime pending") : "not configured",
      cls: admin.saml?.enabled ? admin.saml.cls : "warn",
      detail: admin.saml?.detail || "SAML provider posture is not available.",
      nextAction: admin.saml?.enabled
        ? "Run a controlled SAML login, verify role mapping, and capture IdP metadata evidence."
        : "Prepare SAML metadata, SP entity, ACS URL, role mapping, and certificate fingerprint in the SAML rollout drawer.",
      evidence: admin.saml?.enabled ? admin.saml.entityId : "SAML disabled.",
      auditHash: accessAuditHash({ action: "access-saml-provider-set" }),
    },
  ];
  const lifecycleRows = [
    {
      id: "inventory",
      label: "Administration inventory",
      state: admin.available ? "loaded" : "unavailable",
      cls: admin.available ? "ok" : "warn",
      detail: admin.detail || (admin.available ? "Access administration inventory loaded." : "Access administration inventory unavailable."),
      nextAction: admin.available ? "Use this review before provider changes or break-glass rotation." : "Retry with an admin-capable session before production access sign-off.",
      evidence: "GET /v1/system/access-administration",
    },
    ...backendBlockerRows,
    {
      id: "break-glass",
      label: "Break-glass recovery",
      state: admin.breakGlass?.state || "not reported",
      cls: admin.breakGlass?.cls || "warn",
      detail: admin.breakGlass?.detail || "Break-glass posture is not reported.",
      nextAction: admin.breakGlass?.nextAction || "Create or rotate an enabled local admin before IdP changes.",
      evidence: `${enabledLocalAdmins.length} enabled local admin credential${enabledLocalAdmins.length === 1 ? "" : "s"}.`,
    },
    ...providerRows,
    {
      id: "sessions",
      label: "Browser SSO sessions",
      state: admin.sessions?.label || "not reported",
      cls: admin.sessions?.cls || "warn",
      detail: admin.sessions?.detail || "Session inventory is unavailable.",
      nextAction: admin.sessions?.sessionRevocationAvailable
        ? "Review active browser sessions and revoke stale sessions before disruptive IdP changes."
        : "Use provider disable workflows for broad session revocation until per-session revoke is available.",
      evidence: `${activeSessions.length} non-secret active session row${activeSessions.length === 1 ? "" : "s"} loaded.`,
    },
    {
      id: "audit",
      label: "Audit review",
      state: "available",
      cls: "info",
      detail: "Access changes emit local audit actions for user, provider, and session lifecycle events.",
      nextAction: "Filter Changes audit by access-* actions after every provider or break-glass change.",
      evidence: "Changes audit filters are linked from this drawer.",
    },
  ];
  const blockers = lifecycleRows.filter((row) => row.cls === "bad");
  const warnings = lifecycleRows.filter((row) => row.cls === "warn");
  const state = blockers.length ? "blocked" : warnings.length ? "review" : "ready";
  return {
    normalized: true,
    schemaVersion: "phragma.access.lifecycle-review.v1",
    state,
    cls: blockers.length ? "bad" : warnings.length ? "warn" : "ok",
    label: blockers.length ? `${blockers.length} blocker${blockers.length === 1 ? "" : "s"}` : warnings.length ? `${warnings.length} review item${warnings.length === 1 ? "" : "s"}` : "ready",
    detail: blockers.length
      ? "Access lifecycle review has blocking recovery or provider posture gaps."
      : warnings.length
      ? "Access lifecycle review has items to resolve or document before production access sign-off."
      : "Access lifecycle review is ready for provider changes and emergency recovery.",
    actor: identity?.actor || (runtimeAuthEnabled(rt) === false ? "local admin mode" : "unknown"),
    role: identity?.role || (runtimeAuthEnabled(rt) === false ? "admin" : "unknown"),
    authSource: identity?.authSource || (runtimeAuthEnabled(rt) === false ? "auth-disabled" : "unknown"),
    authEnabled: admin.authEnabled,
    adminVerified: readiness.adminVerified,
    localAdminCount: enabledLocalAdmins.length,
    localUserCount: (admin.localUsers || []).length,
    activeSessionCount: activeSessions.length,
    providerRows,
    lifecycleRows,
    readinessItems: readiness.items || [],
    endpoints: accessLifecycleEndpoints(),
    cli: accessLifecycleCli(admin),
    auditLinks: [
      { label: "All access audit", href: accessAuditHash({ query: "access-" }) },
      { label: "OIDC provider audit", href: accessAuditHash({ action: "access-oidc-provider-set" }) },
      { label: "SAML provider audit", href: accessAuditHash({ action: "access-saml-provider-set" }) },
      { label: "Break-glass rotation audit", href: accessAuditHash({ action: "access-local-user-rotate-token", query: "break-glass" }) },
      { label: "Session revoke audit", href: accessAuditHash({ action: "access-session-revoke" }) },
    ],
  };
}

export function accessLifecycleReviewText(review = {}) {
  const r = review?.normalized ? review : accessLifecycleReviewModel({}, null, {}, review);
  const lines = [
    `Access lifecycle review: ${r.state} (${r.label})`,
    `schema=${r.schemaVersion}`,
    `actor=${r.actor}`,
    `role=${r.role}`,
    `auth_source=${r.authSource}`,
    `auth_enabled=${r.authEnabled === null ? "unknown" : r.authEnabled ? "true" : "false"}`,
    `local_users=${r.localUserCount}`,
    `break_glass_local_admins=${r.localAdminCount}`,
    `active_browser_sso_sessions=${r.activeSessionCount}`,
    "",
    "Lifecycle checks:",
    ...r.lifecycleRows.map((row) => `- [${String(row.cls || "neutral").toUpperCase()}] ${row.label}: ${row.state}. ${row.detail} Next: ${row.nextAction} Evidence: ${row.evidence}`),
    "",
    "Public API:",
    ...r.endpoints.map((endpoint) => `- ${endpoint.method} ${endpoint.path}: ${endpoint.purpose}`),
    "",
    "CLI parity:",
    ...r.cli.map((item) => `- ${item}`),
    "",
    "Audit links:",
    ...r.auditLinks.map((link) => `- ${link.label}: ${link.href}`),
  ];
  return lines.map(sanitizeOIDCText).join("\n");
}

function accessLifecycleEndpoints() {
  return [
    { method: "GET", path: "/v1/system/access-administration", purpose: "Read access inventory, providers, local users, sessions, and break-glass posture." },
    { method: "POST", path: "/v1/system/access-administration/oidc:preflight", purpose: "Run OIDC provider/session readiness checks." },
    { method: "PUT", path: "/v1/system/access-administration/oidc/config", purpose: "Save audited OIDC provider config with acknowledgement." },
    { method: "POST", path: "/v1/system/access-administration/oidc/config:disable", purpose: "Disable OIDC provider and revoke OIDC sessions." },
    { method: "PUT", path: "/v1/system/access-administration/saml/config", purpose: "Save audited SAML provider config with acknowledgement." },
    { method: "POST", path: "/v1/system/access-administration/saml/config:disable", purpose: "Disable SAML provider and revoke SAML sessions." },
    { method: "POST", path: "/v1/system/access-administration/local-users/{name}:rotate-token", purpose: "Rotate local or break-glass bearer token and show the new token once." },
    { method: "POST", path: "/v1/system/access-administration/sessions/{sessionId}:revoke", purpose: "Revoke one browser SSO session by non-secret session ID." },
  ];
}

function accessLifecycleCli(admin = {}) {
  const firstAdmin = (admin.localUsers || []).find((user) => user.enabled && user.role === "admin");
  return [
    "ngfwctl access users list",
    "ngfwctl access sessions list",
    "ngfwctl access oidc provider show",
    "ngfwctl access oidc provider validate --issuer <https-url> --client-id <id> --redirect-url <https-url>/v1/auth/oidc/callback",
    "ngfwctl access saml provider show",
    "ngfwctl access saml provider validate --metadata-url <https-url> --idp-entity-id <entity-id> --sp-entity-id <entity-id> --acs-url <https-url>/v1/auth/saml/acs",
    firstAdmin ? `ngfwctl access users rotate-token ${shellQuote(firstAdmin.name)} --comment <ticket> --ack-rotate-token` : "ngfwctl access users create breakglass-admin --role admin --comment <ticket>",
    "ngfwctl access sessions revoke <session-id> --ack-revoke-session",
  ].map(sanitizeOIDCText);
}

export function accessWorkflowAuditLinks(workflow = {}) {
  return (workflow.auditActions || []).map((action) => ({
    action,
    label: auditActionLabel(action),
    href: accessAuditHash({ action }),
  }));
}

export function summarizeCapabilities(values, fallback = []) {
  const normalized = normalizeCapabilities(values, fallback);
  const set = new Set(normalized);
  return {
    values: normalized,
    label: normalized.join(", ") || "none",
    canRead: set.has("read") || set.has("write") || set.has("admin"),
    canWrite: set.has("write") || set.has("admin"),
    canAdmin: set.has("admin"),
  };
}

export function accessAuditHash(filters = {}) {
  const params = new URLSearchParams();
  params.set("tab", "audit");
  for (const key of ["actor", "action", "version", "query", "since", "until"]) {
    const value = filters[key];
    if (value) params.set(key, String(value));
  }
  params.set("limit", String(filters.limit || "300"));
  return "#/changes?" + params.toString();
}

function accessAdministrationReadiness(rt = {}, identity = null, oidc = {}, administration) {
  const authEnabled = boolOrNull(administration.authEnabled, runtimeAuthEnabled(rt));
  const admin = roleAllows(identity?.role || (authEnabled === false ? "admin" : "unknown"), "admin");
  const editableUsers = administration.localUsers.filter((user) => user.editable === true).length;
  const userCount = administration.localUsers.length;
  const blockerItems = administration.blockers.map((blocker, idx) => ({
    id: `backend-blocker-${idx + 1}`,
    label: "Backend blocker",
    status: "blocked",
    cls: "bad",
    detail: blocker.label,
    nextAction: "Clear the backend-reported access blocker before production sign-off.",
    evidence: "GET /v1/system/access-administration blockers.",
  }));
  const items = [
    ...blockerItems,
    {
      id: "users-roles",
      label: "User and role administration",
      status: userCount ? (editableUsers ? "editable workflow" : "read-only inventory") : "no local users",
      cls: userCount ? "ok" : "warn",
      detail: userCount
        ? `${userCount} local user${userCount === 1 ? "" : "s"} reported; ${editableUsers} marked editable.`
        : "No local users are reported by the access administration endpoint.",
      nextAction: editableUsers
        ? "Use Settings to create, rotate, role-change, or disable local users through audited backend workflows."
        : "Use Settings or ngfwctl only for editable rows; otherwise use the approved config path.",
      evidence: "Local user inventory loaded from GET /v1/system/access-administration.",
    },
    {
      id: "sessions",
      label: "Session revocation",
      status: administration.sessions.sessionRevocationAvailable === true ? "revocation available" : "read-only sessions",
      cls: administration.sessions.sessionRevocationAvailable === true ? "ok" : "warn",
      detail: administration.sessions.detail,
      nextAction: administration.sessions.sessionRevocationAvailable === true
        ? "Review active browser SSO sessions and revoke through the audited backend workflow when needed."
        : "Add or enable audited session revoke support before relying on multi-admin browser SSO operations.",
      evidence: administration.sessions.label,
    },
    {
      id: "idp-lifecycle",
      label: "IdP lifecycle",
      status: administration.oidc.enabled ? "configured" : "not configured",
      cls: administration.oidc.cls,
      detail: administration.oidc.detail,
      nextAction: administration.oidc.enabled
        ? "Run OIDC preflight, then review issuer, claims, cookie, scopes, proxy trust, and session capacity before rollout."
        : "Configure OIDC before browser SSO rollout.",
      evidence: administration.oidc.enabled ? administration.oidc.issuer : "OIDC disabled.",
    },
    {
      id: "saml-lifecycle",
      label: "SAML lifecycle",
      status: administration.saml.enabled ? (administration.saml.runtimeAvailable ? "runtime ready" : "runtime pending") : "not configured",
      cls: administration.saml.enabled ? administration.saml.cls : "warn",
      detail: administration.saml.detail,
      nextAction: administration.saml.enabled
        ? (administration.saml.runtimeAvailable
          ? "Run a controlled SAML test login, verify role mapping, and capture IdP evidence before production rollout."
          : "Verify the saved provider exposes a SAML login URL, then run a controlled test login before production rollout.")
        : "Use the SAML rollout drawer to prepare and validate IdP metadata, SP entity, ACS URL, and role mapping.",
      evidence: administration.saml.enabled ? administration.saml.entityId : "SAML provider is not configured.",
    },
    {
      id: "break-glass",
      label: "Break-glass control",
      status: administration.breakGlass.state,
      cls: administration.breakGlass.cls,
      detail: administration.breakGlass.detail,
      nextAction: administration.breakGlass.nextAction,
      evidence: administration.breakGlass.state,
    },
  ];
  return readinessSummary(items, admin, administration.blockers.length
    ? "Access inventory is loaded, but backend blockers remain."
    : "Access inventory and local-user lifecycle controls are loaded for operator review.");
}

function unavailableAdministrationReadiness(rt = {}, identity = null, oidc = {}, administration) {
  const authEnabled = runtimeAuthEnabled(rt);
  const admin = roleAllows(identity?.role || (authEnabled === false ? "admin" : "unknown"), "admin");
  const detail = administration.detail || "Access administration inventory is unavailable.";
  const items = [
    {
      id: "users-roles",
      label: "User and role administration",
      status: "endpoint unavailable",
      cls: "warn",
      detail: "Local user inventory could not be loaded.",
      nextAction: "Retry with an admin-capable session after the backend endpoint is available.",
      evidence: detail,
    },
    {
      id: "sessions",
      label: "Session revocation",
      status: "not loaded",
      cls: "warn",
      detail: "Browser SSO session inventory and revoke posture could not be loaded.",
      nextAction: "Use current-user sign out only until session administration is available.",
      evidence: detail,
    },
    {
      id: "idp-lifecycle",
      label: "IdP lifecycle",
      status: oidc?.enabled ? "status only" : "not configured",
      cls: oidc?.enabled ? "warn" : "neutral",
      detail: oidc?.enabled
        ? "OIDC status is visible, but access administration inventory is unavailable."
        : "OIDC is not enabled and administration inventory is unavailable.",
      nextAction: "Load GET /v1/system/access-administration before production SSO review.",
      evidence: oidc?.enabled ? "OIDC status endpoint is reachable." : "No active OIDC provider reported.",
    },
    {
      id: "break-glass",
      label: "Break-glass control",
      status: "not loaded",
      cls: authEnabled === false ? "bad" : "warn",
      detail: authEnabled === false
        ? "Authentication is disabled; break-glass posture cannot be verified from the endpoint."
        : "Break-glass lifecycle state could not be loaded.",
      nextAction: authEnabled === false
        ? "Enable authentication and verify audited emergency access."
        : "Retry after access administration inventory is available.",
      evidence: detail,
    },
  ];
  return readinessSummary(items, admin, "Access administration inventory is unavailable; Settings is using runtime identity and OIDC status only.");
}

function readinessSummary(items, adminVerified, readyDetail) {
  const blockers = items.filter((item) => item.cls === "bad");
  const warnings = items.filter((item) => item.cls === "warn");
  return {
    cls: blockers.length ? "bad" : warnings.length ? "warn" : "ok",
    label: blockers.length ? `${blockers.length} blocker${blockers.length === 1 ? "" : "s"}` : warnings.length ? `${warnings.length} review item${warnings.length === 1 ? "" : "s"}` : "ready",
    detail: blockers.length
      ? "Access administration has blockers before production sign-off."
      : warnings.length
      ? "Access administration has review items before production sign-off."
      : readyDetail,
    adminVerified,
    items,
  };
}

function normalizeAccessLocalUsers(users = []) {
  if (!Array.isArray(users)) return [];
  return users.map((user, idx) => {
    const name = textValue(user?.name, `local-user-${idx + 1}`);
    const editable = typeof user?.editable === "boolean" ? user.editable : null;
    const enabled = typeof user?.enabled === "boolean" ? user.enabled : true;
    const auditHash = String(user?.auditHash ?? "").trim();
    return {
      name,
      role: normalizeRole(user?.role),
      authSource: textValue(user?.authSource, "local"),
      tokenMaterial: textValue(user?.tokenMaterial, "unknown"),
      editable,
      enabled,
      enabledLabel: enabled ? "enabled" : "disabled",
      enabledCls: enabled ? "ok" : "bad",
      editableLabel: editable === true ? "editable" : editable === false ? "read-only" : "unknown",
      editableCls: editable === true ? "ok" : editable === false ? "neutral" : "warn",
      auditHash,
      auditFingerprint: compactAccessHash(auditHash),
      actorAuditHash: accessAuditHash({ query: `user=${name}` }),
    };
  });
}

function normalizeAccessOidc(data = null, fallback = {}) {
  const enabled = boolOrNull(data?.enabled, boolOrNull(fallback?.enabled, false));
  const cookieSecure = boolOrNull(data?.cookieSecure, null);
  const issuer = textValue(data?.issuer, enabled ? "not reported" : "disabled");
  const clientId = textValue(data?.clientId || data?.client_id, enabled ? "not reported" : "disabled");
  const redirectUrl = textValue(data?.redirectUrl || data?.redirect_url, "");
  const roleClaim = textValue(data?.roleClaim || data?.role_claim, enabled ? "not reported" : "disabled");
  const defaultRole = normalizeRole(data?.defaultRole || data?.default_role);
  const scopes = normalizeStringList(data?.scopes);
  const trustedProxyCidrs = normalizeStringList(data?.trustedProxyCidrs || data?.trusted_proxy_cidrs);
  const sessionTtlSeconds = numberOrNull(data?.sessionTtlSeconds ?? data?.session_ttl_seconds);
  const clientSecretFileConfigured = boolOrNull(data?.clientSecretFileConfigured, boolOrNull(data?.client_secret_file_configured, false));
  const cls = !enabled ? "neutral" : cookieSecure === false ? "warn" : "ok";
  return {
    enabled,
    issuer,
    clientId,
    redirectUrl,
    roleClaim,
    defaultRole,
    cookieSecure,
    scopes,
    trustedProxyCidrs,
    sessionTtlSeconds,
    clientSecretFileConfigured,
    cls,
    label: enabled ? "enabled" : "disabled",
    detail: enabled
      ? `Issuer ${issuer}; default role ${defaultRole}.`
      : "OIDC provider disabled.",
    rows: [
      { label: "Enabled", value: enabled ? "yes" : "no", cls: enabled ? "ok" : "neutral" },
      { label: "Issuer", value: issuer },
      { label: "Client ID", value: clientId },
      { label: "Redirect URL", value: redirectUrl || (enabled ? "not reported" : "disabled") },
      { label: "Role claim", value: roleClaim },
      { label: "Default role", value: defaultRole, cls: roleClass(defaultRole) },
      { label: "Client secret file", value: clientSecretFileConfigured ? "configured" : "not configured", cls: clientSecretFileConfigured ? "ok" : "warn" },
      { label: "Cookie secure", value: cookieSecure === null ? "unknown" : cookieSecure ? "yes" : "no", cls: cookieSecure === false && enabled ? "warn" : "neutral" },
      { label: "Scopes", value: formatList(scopes) },
      { label: "Trusted proxies", value: formatList(trustedProxyCidrs) },
      { label: "Session TTL", value: formatSeconds(sessionTtlSeconds) },
    ],
  };
}

function normalizeAccessSaml(data = null) {
  const enabled = boolOrNull(data?.enabled, false);
  const entityId = textValue(data?.entityId || data?.idpEntityId || data?.idp_entity_id, enabled ? "not reported" : "disabled");
  const metadataUrl = textValue(data?.metadataUrl || data?.metadata_url, "");
  const ssoUrl = textValue(data?.ssoUrl || data?.sso_url, "");
  const spEntityId = textValue(data?.spEntityId || data?.sp_entity_id, "");
  const acsUrl = textValue(data?.acsUrl || data?.acs_url, "");
  const roleAttribute = textValue(data?.roleAttribute || data?.role_attribute, enabled ? "not reported" : "disabled");
  const defaultRole = normalizeRole(data?.defaultRole || data?.default_role);
  const certificateFingerprint = textValue(data?.certificateFingerprint || data?.certificate_fingerprint, "");
  const certificateFingerprintConfigured = boolOrNull(data?.certificateFingerprintConfigured ?? data?.certificate_fingerprint_configured, Boolean(certificateFingerprint));
  const metadataLoaded = boolOrNull(data?.metadataLoaded, null);
  const runtimeAvailable = boolOrNull(data?.runtimeAvailable, false);
  const detail = textValue(data?.detail, "");
  const cls = enabled ? (runtimeAvailable ? "ok" : "warn") : "warn";
  return {
    enabled,
    entityId,
    idpEntityId: entityId,
    metadataUrl,
    ssoUrl,
    spEntityId,
    acsUrl,
    roleAttribute,
    defaultRole,
    certificateFingerprint,
    certificateFingerprintConfigured,
    metadataLoaded,
    runtimeAvailable,
    cls,
    label: enabled ? "configured" : "not configured",
    detail: detail || (enabled
      ? `IdP ${entityId}; role attribute ${roleAttribute}; ${runtimeAvailable ? "runtime ready" : "runtime pending"}.`
      : "SAML provider is not configured."),
    rows: [
      { label: "Enabled", value: enabled ? "yes" : "no", cls: enabled ? "ok" : "warn" },
      { label: "IdP entity", value: entityId },
      { label: "Metadata URL", value: metadataUrl || (enabled ? "not reported" : "disabled") },
      { label: "SSO URL", value: ssoUrl || (enabled ? "not reported" : "disabled") },
      { label: "SP entity", value: spEntityId || (enabled ? "not reported" : "disabled") },
      { label: "ACS URL", value: acsUrl || (enabled ? "not reported" : "disabled") },
      { label: "Role attribute", value: roleAttribute },
      { label: "Default role", value: defaultRole, cls: roleClass(defaultRole) },
      { label: "Signing cert", value: certificateFingerprintConfigured ? "[fingerprint set]" : (enabled ? "not reported" : "disabled") },
      { label: "Metadata loaded", value: metadataLoaded === null ? "unknown" : metadataLoaded ? "yes" : "no", cls: metadataLoaded === false && enabled ? "warn" : "neutral" },
      { label: "Activation", value: runtimeAvailable ? "runtime ready" : "runtime pending", cls: runtimeAvailable ? "ok" : "warn" },
    ],
  };
}

function normalizeAccessSessions(data = null) {
  const active = numberOrNull(data?.oidcActiveSessions);
  const max = numberOrNull(data?.oidcMaxSessions);
  const sessionRevocationAvailable = boolOrNull(data?.sessionRevocationAvailable, null);
  const activeSessions = normalizeActiveSessions(data?.activeSessions);
  const detail = textValue(data?.detail, sessionRevocationAvailable
    ? "Browser SSO session inventory and revocation are available."
    : "Browser SSO session inventory is read-only or not reported.");
  return {
    oidcActiveSessions: active,
    oidcMaxSessions: max,
    sessionRevocationAvailable,
    activeSessions,
    detail,
    cls: sessionRevocationAvailable === true ? "ok" : sessionRevocationAvailable === false ? "warn" : "neutral",
    label: active !== null && max !== null ? `${active}/${max} active` : active !== null ? `${active} active` : "not reported",
    rows: [
      { label: "Browser SSO active", value: active === null ? "unknown" : String(active) },
      { label: "Browser SSO max", value: max === null ? "unknown" : String(max) },
      { label: "Revocation", value: sessionRevocationAvailable === null ? "unknown" : sessionRevocationAvailable ? "available" : "not available", cls: sessionRevocationAvailable === true ? "ok" : sessionRevocationAvailable === false ? "warn" : "neutral" },
      { label: "Detail", value: detail },
    ],
  };
}

function normalizeActiveSessions(values = []) {
  if (!Array.isArray(values)) return [];
  return values.map((session, idx) => {
    const sessionId = textValue(session?.sessionId, `session-${idx + 1}`);
    const secondsUntilExpiry = numberOrNull(session?.secondsUntilExpiry);
    return {
      sessionId,
      sessionFingerprint: compactAccessHash(sessionId),
      actor: textValue(session?.actor, "unknown"),
      role: normalizeRole(session?.role),
      authSource: textValue(session?.authSource, "oidc-session"),
      expiresAt: textValue(session?.expiresAt, "unknown"),
      secondsUntilExpiry,
      expiryLabel: secondsUntilExpiry === null ? "unknown" : formatSeconds(secondsUntilExpiry),
      auditHash: accessAuditHash({ action: "access-session-revoke", query: `session_id=${sessionId}` }),
    };
  });
}

function normalizeAccessBreakGlass(data = null, authEnabled = null) {
  const state = textValue(data?.state, authEnabled === false ? "auth disabled" : "not reported");
  const cls = breakGlassClass(state, authEnabled);
  const detail = textValue(data?.detail, authEnabled === false
    ? "Authentication is disabled; every local caller is effectively admin."
    : "Break-glass posture is not reported.");
  return {
    state,
    cls,
    detail,
    nextAction: textValue(data?.nextAction, cls === "ok" ? "Review emergency access rotation schedule." : "Verify audited break-glass access."),
  };
}

function normalizeAccessBlockers(blockers = []) {
  return normalizeStringList(blockers).map((label, idx) => ({
    id: `blocker-${idx + 1}`,
    label,
    cls: "bad",
  }));
}

function normalizeOIDCPreflightChecks(checks = []) {
  if (!Array.isArray(checks)) return [];
  return checks.map((check, idx) => {
    const cls = oidcPreflightClass(textValue(check?.state, "unknown"), [], [], [], check?.class || check?.cls);
    return {
      id: textValue(check?.id, `check-${idx + 1}`),
      label: textValue(check?.label, `Check ${idx + 1}`),
      state: textValue(check?.state, cls === "bad" ? "blocked" : cls === "warn" ? "review" : "ready"),
      cls,
      detail: sanitizeOIDCText(textValue(check?.detail, "No detail returned.")),
      evidence: sanitizeOIDCText(textValue(check?.evidence, "No evidence returned.")),
      nextAction: sanitizeOIDCText(textValue(check?.nextAction, "Review the OIDC provider and management-plane configuration.")),
    };
  });
}

function oidcPreflightClass(state, checks = [], blockers = [], warnings = [], explicit = "") {
  const cls = String(explicit || "").trim().toLowerCase();
  if (["ok", "warn", "bad", "neutral"].includes(cls)) return cls;
  const value = String(state || "").trim().toLowerCase();
  if (blockers.length || checks.some((check) => check.cls === "bad") || /(blocked|failed|bad|error)/.test(value)) return "bad";
  if (warnings.length || checks.some((check) => check.cls === "warn") || /(review|warn|degraded)/.test(value)) return "warn";
  if (/(ready|ok|passed)/.test(value)) return "ok";
  return "neutral";
}

function sanitizeOIDCText(value) {
  return String(value ?? "")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[redacted-jwt]")
    .replace(/\b(?:oidc|saml)?-?session-sha256:[A-Za-z0-9_-]{16,}\b/gi, "[redacted-session]")
    .replace(/\b(client[_-]?secret|id[_-]?token|access[_-]?token|refresh[_-]?token|session[_-]?id|session|cookie|code)(?:\s*[:=]\s*|\s*%3[dD]\s*)[^,\s;&]+/gi, "$1=[redacted]")
    .replace(/(^|[\s"'({=,;])\/(?:var\/lib|var\/log(?:\/openngfw)?|etc\/(?:openngfw|phragma)|tmp|private\/tmp|var\/folders|private\/var\/folders|home\/[^'"\s,;}]+|Users\/[^'"\s,;}]+)[^'"\s,;}]*/gi, "$1[server-local path redacted]")
    .trim();
}

function parseAbsoluteURL(value) {
  try {
    const url = new URL(String(value || ""));
    return url.protocol && url.hostname ? url : null;
  } catch {
    return null;
  }
}

function shellQuote(value) {
  const text = sanitizeOIDCText(String(value ?? ""));
  if (/^[A-Za-z0-9_./:=,@+-]+$/.test(text)) return text;
  return `'${text.replace(/'/g, "'\"'\"'")}'`;
}

function oidcSystemdDropIn(args = []) {
  const env = args.map(([flag, value]) => `${flag}=${shellQuote(value)}`).join(" ");
  return [
    "[Service]",
    `Environment="PHRAGMA_OIDC_ARGS=${env}"`,
    "ExecStart=",
    "ExecStart=/usr/local/bin/controld $PHRAGMA_OIDC_ARGS",
  ].join("\n");
}

function unavailableAdministrationDetail(administration = {}) {
  const status = administration?.status ? `HTTP ${administration.status}` : "request failed";
  const message = textValue(administration?.message, "access administration endpoint unavailable");
  return `${status}: ${message}`;
}

function errorMessage(reason = {}) {
  if (typeof reason === "string") return reason;
  return String(reason?.message || reason?.error || reason?.body?.message || reason?.body?.error || "access administration endpoint unavailable");
}

function runtimeAuthEnabled(rt = {}) {
  return Object.prototype.hasOwnProperty.call(rt, "authEnabled") ? Boolean(rt.authEnabled) : null;
}

function textValue(value, fallback = "unknown") {
  const text = String(value ?? "").trim();
  return text || fallback;
}

function compactAccessHash(value) {
  const text = String(value ?? "").trim();
  if (!text) return "not reported";
  if (text.length <= 42) return text;
  const split = text.lastIndexOf(":");
  if (split > 0 && text.length - split > 16) {
    const prefix = text.slice(0, split + 1);
    const digest = text.slice(split + 1);
    return `${prefix}${digest.slice(0, 12)}...${digest.slice(-8)}`;
  }
  return `${text.slice(0, 24)}...${text.slice(-12)}`;
}

function boolOrNull(value, fallback = null) {
  if (typeof value === "boolean") return value;
  return fallback;
}

function numberOrNull(value) {
  if (value === null || value === undefined || value === "") return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function normalizeRole(role) {
  const value = textValue(role, "unknown").toLowerCase();
  return ACCESS_GOVERNANCE_ROLES.includes(value) ? value : value;
}

function normalizeStringList(value) {
  const source = Array.isArray(value)
    ? value
    : typeof value === "string"
    ? value.split(/[,\s]+/)
    : [];
  return [...new Set(source.map((item) => String(item || "").trim()).filter(Boolean))];
}

function formatList(values = [], fallback = "none") {
  return values.length ? values.join(", ") : fallback;
}

function formatSeconds(seconds) {
  if (seconds === null) return "unknown";
  if (seconds < 60) return `${seconds}s`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

function roleClass(role) {
  if (role === "admin") return "bad";
  if (role === "operator") return "warn";
  if (role === "viewer") return "info";
  return "neutral";
}

function breakGlassClass(state, authEnabled) {
  const value = String(state || "").toLowerCase();
  if (authEnabled === false || value.includes("auth disabled")) return "bad";
  if (/(ready|configured|enabled|available|ok)/.test(value)) return "ok";
  if (/(blocked|failed|expired|missing)/.test(value)) return "bad";
  return "warn";
}

function normalizeCapabilities(values, fallback = []) {
  const source = Array.isArray(values) ? values : fallback;
  return [...new Set(source.map((value) => String(value || "").trim()).filter(Boolean))];
}

function accessRoleWorkflowAccess(workflow) {
  return Object.fromEntries(ACCESS_GOVERNANCE_ROLES.map((role) => [role, roleAllows(role, workflow.requiredRole)]));
}

function roleAllows(role, requiredRole) {
  return (ROLE_RANK[role] || 0) >= (ROLE_RANK[requiredRole] || 0);
}

function roleImpactLabel(direction, gained, lost, allowed) {
  if (direction === "invalid") return "invalid role";
  if (lost) return `${lost} workflow${lost === 1 ? "" : "s"} removed`;
  if (gained) return `${gained} workflow${gained === 1 ? "" : "s"} added`;
  if (allowed) return `${allowed} workflow${allowed === 1 ? "" : "s"} allowed`;
  return "no workflows allowed";
}

function roleImpactDetail(direction, current, target, gained, lost, allowed, targetKnown) {
  if (!targetKnown) {
    return "Unknown roles are treated as restricted until the backend accepts viewer, operator, or admin.";
  }
  if (direction === "escalation") {
    return `${target} adds ${gained.length} workflow${gained.length === 1 ? "" : "s"} compared with ${current}.`;
  }
  if (direction === "demotion") {
    return `${target} removes ${lost.length} workflow${lost.length === 1 ? "" : "s"} compared with ${current}.`;
  }
  if (direction === "assignment") {
    return `${target} allows ${allowed.length} workflow${allowed.length === 1 ? "" : "s"} for a new local user.`;
  }
  return `${target} keeps the same workflow access.`;
}

function auditActionLabel(action) {
  return String(action || "")
    .split("-")
    .filter(Boolean)
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
}
