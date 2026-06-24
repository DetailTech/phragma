import assert from "node:assert/strict";

import {
  accessDetail,
  accessTitle,
  isAuthError,
  isPermissionError,
  loginRouteHash,
  loginReturnPath,
  oidcAccessPosture,
  oidcLoginTarget,
  samlLoginTarget,
  throwIfAccessDenied,
} from "./auth_gate.js";

assert.equal(isAuthError({ status: 401 }), true);
assert.equal(isAuthError({ status: 403 }), false);
assert.equal(isPermissionError({ status: 403 }), true);
assert.equal(isPermissionError({ status: 401 }), false);

assert.equal(loginReturnPath(""), "/ui/");
assert.equal(loginReturnPath("#/rules"), "/ui/#/rules");
assert.equal(loginReturnPath("/traffic?mode=sessions"), "/ui/#/traffic?mode=sessions");
assert.equal(loginReturnPath("/ui/#/settings"), "/ui/#/settings");
assert.equal(loginReturnPath("#//evil.example/login"), "/ui/");
assert.equal(loginReturnPath("javascript:alert(1)"), "/ui/");
assert.equal(loginReturnPath("#/unknown"), "/ui/");
assert.equal(loginReturnPath("#/settings#nested"), "/ui/");
assert.equal(loginRouteHash("#/readiness"), "");
assert.equal(loginRouteHash("traffic?mode=sessions"), "#/traffic?mode=sessions");
assert.equal(loginRouteHash("#/settings?tab=access"), "#/settings?tab=access");
assert.equal(loginRouteHash("#/settings?panel=access"), "#/settings?panel=access");
assert.equal(loginRouteHash("#/settings?bad=<script>"), "");

assert.equal(
  oidcLoginTarget({ enabled: true, login_url: "/v1/auth/oidc/login" }, "#/settings"),
  "/v1/auth/oidc/login?return=%2Fui%2F%23%2Fsettings",
);
assert.equal(
  oidcLoginTarget({ enabled: true, login_url: "/v1/auth/oidc/login" }, "#/settings?panel=access"),
  "/v1/auth/oidc/login?return=%2Fui%2F%23%2Fsettings%3Fpanel%3Daccess",
);
assert.equal(
  oidcLoginTarget({ enabled: true, loginUrl: "/login?prompt=select_account" }, "#/rules"),
  "/login?prompt=select_account&return=%2Fui%2F%23%2Frules",
);
assert.equal(oidcLoginTarget({ enabled: false, login_url: "/v1/auth/oidc/login" }, "#/settings"), "");
assert.equal(
  samlLoginTarget({ enabled: true, runtime_available: true, login_url: "/v1/auth/saml/login" }, "#/settings?panel=access"),
  "/v1/auth/saml/login?return=%2Fui%2F%23%2Fsettings%3Fpanel%3Daccess",
);
assert.equal(samlLoginTarget({ enabled: true, runtime_available: false, login_url: "/v1/auth/saml/login" }, "#/settings"), "");

assert.equal(accessTitle({ status: 403 }), "Access denied");
assert.equal(accessTitle({ status: 401 }), "Authentication required");
assert.match(accessDetail({ status: 403 }), /current role/);
assert.match(accessDetail({ status: 401 }), /Sign in/);

const activePosture = oidcAccessPosture(
  { authEnabled: true },
  { enabled: true, authenticated: true, csrf_token: "csrf" },
  { actor: "dana", role: "operator", authSource: "oidc-session" },
);
assert.deepEqual(
  activePosture.map((item) => [item.id, item.value, item.tone]),
  [
    ["runtime-auth", "required", "ok"],
    ["browser-sso", "configured", "ok"],
    ["session", "OIDC active", "ok"],
    ["mutation-guard", "CSRF ready", "ok"],
  ],
);

const pendingPosture = oidcAccessPosture({ authEnabled: true }, { enabled: true }, null);
assert.deepEqual(
  pendingPosture.map((item) => [item.id, item.value, item.tone]),
  [
    ["runtime-auth", "required", "ok"],
    ["browser-sso", "configured", "ok"],
    ["session", "not signed in", "warn"],
    ["mutation-guard", "after sign-in", "warn"],
  ],
);

const samlPosture = oidcAccessPosture(
  { authEnabled: true },
  { enabled: false },
  { actor: "sara", role: "admin", authSource: "saml-session" },
  { enabled: true, runtime_available: true, authenticated: true, csrf_token: "csrf" },
);
assert.deepEqual(
  samlPosture.map((item) => [item.id, item.value, item.tone]),
  [
    ["runtime-auth", "required", "ok"],
    ["browser-sso", "configured", "ok"],
    ["session", "SAML active", "ok"],
    ["mutation-guard", "CSRF ready", "ok"],
  ],
);

assert.doesNotThrow(() => throwIfAccessDenied(
  { status: "fulfilled", value: {} },
  { status: "rejected", reason: { status: 500, message: "backend unavailable" } },
));
assert.throws(
  () => throwIfAccessDenied({ status: "rejected", reason: { status: 401, message: "expired" } }),
  (err) => err.status === 401 && err.message === "expired",
);
assert.throws(
  () => throwIfAccessDenied({ status: "rejected", reason: { status: 7, message: "viewer denied" } }),
  (err) => err.status === 7 && err.message === "viewer denied",
);
