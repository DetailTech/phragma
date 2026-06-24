export function isAuthError(err = {}) {
  return err.status === 401 || err.status === 16;
}

export function isPermissionError(err = {}) {
  return err.status === 403 || err.status === 7;
}

export function throwIfAccessDenied(...results) {
  for (const result of results) {
    if (!result || result.status !== "rejected") continue;
    const err = result.reason || result;
    if (isAuthError(err) || isPermissionError(err)) throw err;
  }
}

const SAFE_LOGIN_PATHS = new Set([
  "/",
  "/setup",
  "/rules",
  "/objects",
  "/nat",
  "/threats",
  "/traffic",
  "/troubleshoot",
  "/performance",
  "/intel",
  "/netvpn",
  "/changes",
  "/settings",
]);

export function loginRouteHash(hash = "") {
  let route = String(hash || "").trim();
  if (!route) return "";
  if (route.startsWith("/ui/#")) route = route.slice("/ui/".length);
  if (route.startsWith("#")) route = route.slice(1);
  if (!route.startsWith("/")) route = "/" + route.replace(/^\/+/, "");
  if (route.startsWith("//") || route.includes("\\") || /[\u0000-\u001f\u007f]/.test(route)) return "";
  if (route.includes("#")) return "";

  const [path, ...queryParts] = route.split("?");
  const query = queryParts.join("?");
  if (!SAFE_LOGIN_PATHS.has(path)) return "";
  if (query && /[\s<>"'`\\#]/.test(query)) return "";
  return "#" + path + (query ? "?" + query : "");
}

export function loginReturnPath(hash = "") {
  const route = loginRouteHash(hash);
  return route ? "/ui/" + route : "/ui/";
}

export function oidcLoginTarget(oidc = {}, hash = "") {
  return ssoLoginTarget(oidc, hash);
}

export function samlLoginTarget(saml = {}, hash = "") {
  return ssoLoginTarget(saml, hash);
}

export function ssoLoginTarget(provider = {}, hash = "") {
  const login = provider.loginUrl || provider.login_url || "";
  const runtimeAvailable = provider.runtimeAvailable ?? provider.runtime_available ?? true;
  if (!provider.enabled || !runtimeAvailable || !login) return "";
  const sep = login.includes("?") ? "&" : "?";
  return login + sep + "return=" + encodeURIComponent(loginReturnPath(hash));
}

export function accessTitle(err = {}) {
  if (isPermissionError(err)) return "Access denied";
  return "Authentication required";
}

export function accessDetail(err = {}) {
  if (isPermissionError(err)) {
    return "Your current role cannot access this surface. Sign in with an operator or admin identity, or use a token with the required role.";
  }
  return "Sign in with browser SSO or provide a local API token to continue.";
}

export function oidcAccessPosture(rt = {}, oidc = {}, identity = {}, saml = {}) {
  const authKnown = Object.prototype.hasOwnProperty.call(rt, "authEnabled");
  const authOn = authKnown ? Boolean(rt.authEnabled) : null;
  const oidcOn = Boolean(oidc.enabled);
  const samlOn = Boolean(saml.enabled && (saml.runtimeAvailable ?? saml.runtime_available ?? true));
  const oidcSession = identity?.authSource === "oidc-session" || oidc.authenticated === true;
  const samlSession = identity?.authSource === "saml-session" || saml.authenticated === true;
  const csrfReady = Boolean(oidc.csrf_token || oidc.csrfToken || saml.csrf_token || saml.csrfToken);
  const ssoOn = oidcOn || samlOn;
  const sessionLabel = oidcSession ? "OIDC active" : samlSession ? "SAML active" : "not signed in";
  return [
    {
      id: "runtime-auth",
      label: "Runtime auth",
      value: authKnown ? (authOn ? "required" : "local admin") : "unknown",
      detail: authKnown ? (authOn ? "Protected API and WebUI" : "Auth disabled for this runtime") : "Status not loaded",
      tone: authKnown ? (authOn ? "ok" : "warn") : "neutral",
    },
    {
      id: "browser-sso",
      label: "Browser SSO",
      value: ssoOn ? "configured" : "not configured",
      detail: oidcOn && samlOn ? "OIDC and SAML session cookies" : oidcOn ? "HTTP-only OIDC session cookie" : samlOn ? "HTTP-only SAML session cookie" : "Local token fallback only",
      tone: ssoOn ? "ok" : "neutral",
    },
    {
      id: "session",
      label: "Session",
      value: sessionLabel,
      detail: oidcSession || samlSession ? "Browser actor is verified" : "Use SSO or session token",
      tone: oidcSession || samlSession ? "ok" : (ssoOn ? "warn" : "neutral"),
    },
    {
      id: "mutation-guard",
      label: "Mutation guard",
      value: csrfReady ? "CSRF ready" : (ssoOn ? "after sign-in" : "token scoped"),
      detail: csrfReady ? "X-Phragma-CSRF loaded" : (ssoOn ? "Status endpoint provides token" : "Bearer token bypasses cookie CSRF"),
      tone: csrfReady ? "ok" : (ssoOn ? "warn" : "neutral"),
    },
  ];
}
