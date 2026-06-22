import assert from "node:assert/strict";

import { api, getToken, setCSRFTokenForTest, setToken } from "./api.js";

const TOKEN_KEY = "phragma.token";
const LEGACY_TOKEN_KEY = "openngfw.token";

class MemoryStorage {
  constructor(entries = []) {
    this.items = new Map(entries);
  }

  getItem(key) {
    return this.items.has(key) ? this.items.get(key) : null;
  }

  setItem(key, value) {
    this.items.set(key, String(value));
  }

  removeItem(key) {
    this.items.delete(key);
  }
}

class ThrowingStorage {
  getItem() { throw new Error("storage blocked"); }
  setItem() { throw new Error("storage blocked"); }
  removeItem() { throw new Error("storage blocked"); }
}

function installStorage({ session = new MemoryStorage(), local = new MemoryStorage() } = {}) {
  Object.defineProperty(globalThis, "sessionStorage", { configurable: true, value: session });
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: local });
  setToken("");
  setCSRFTokenForTest("");
  return { session, local };
}

{
  const { session, local } = installStorage();
  local.setItem(TOKEN_KEY, "old-local-token");
  local.setItem(LEGACY_TOKEN_KEY, "legacy-token");

  setToken("session-token");

  assert.equal(session.getItem(TOKEN_KEY), "session-token");
  assert.equal(local.getItem(TOKEN_KEY), null);
  assert.equal(local.getItem(LEGACY_TOKEN_KEY), null);
  assert.equal(getToken(), "session-token");
}

{
  const { session, local } = installStorage();
  session.setItem(TOKEN_KEY, "session-token");
  local.setItem(TOKEN_KEY, "stale-local-token");
  local.setItem(LEGACY_TOKEN_KEY, "legacy-token");

  assert.equal(getToken(), "session-token");
  assert.equal(session.getItem(TOKEN_KEY), "session-token");
  assert.equal(local.getItem(TOKEN_KEY), null);
  assert.equal(local.getItem(LEGACY_TOKEN_KEY), null);
}

{
  const { session, local } = installStorage();
  local.setItem(TOKEN_KEY, "persisted-current-token");
  local.setItem(LEGACY_TOKEN_KEY, "legacy-token");

  assert.equal(getToken(), "persisted-current-token");
  assert.equal(session.getItem(TOKEN_KEY), "persisted-current-token");
  assert.equal(local.getItem(TOKEN_KEY), null);
  assert.equal(local.getItem(LEGACY_TOKEN_KEY), null);
}

{
  const { session, local } = installStorage();
  local.setItem(LEGACY_TOKEN_KEY, "legacy-only-token");

  assert.equal(getToken(), "legacy-only-token");
  assert.equal(session.getItem(TOKEN_KEY), "legacy-only-token");
  assert.equal(local.getItem(LEGACY_TOKEN_KEY), null);
}

{
  const { session, local } = installStorage();
  session.setItem(TOKEN_KEY, "session-token");
  local.setItem(TOKEN_KEY, "local-token");
  local.setItem(LEGACY_TOKEN_KEY, "legacy-token");

  setToken("");

  assert.equal(getToken(), "");
  assert.equal(session.getItem(TOKEN_KEY), null);
  assert.equal(local.getItem(TOKEN_KEY), null);
  assert.equal(local.getItem(LEGACY_TOKEN_KEY), null);
}

{
  const { local } = installStorage({ session: new ThrowingStorage() });
  local.setItem(LEGACY_TOKEN_KEY, "legacy-token");

  assert.equal(getToken(), "legacy-token");
  assert.equal(local.getItem(LEGACY_TOKEN_KEY), null);
  assert.equal(getToken(), "legacy-token");

  setToken("");
  assert.equal(getToken(), "");
}

{
  installStorage();
  setToken("bearer-token");
  const previousFetch = globalThis.fetch;
  const calls = [];
  Object.defineProperty(globalThis, "fetch", {
    configurable: true,
    value: async (path, init) => {
      calls.push({ path, init, body: init.body ? JSON.parse(init.body) : null });
      if (path === "/v1/system/access-administration/step-up") {
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ token: "stepup-storage-token" }),
        };
      }
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({}),
      };
    },
  });

  try {
    await api.createLocalUser({ name: "bob", role: "operator", comment: "add operator" });
    await api.updateLocalUser("bob", { role: "viewer", comment: "reduce role" });
    await api.rotateLocalUserToken("bob", "rotate token");
    await api.disableLocalUser("bob", "remove access");
    await api.setOIDCProviderConfig({ config: { issuer: "https://idp.example.com" }, comment: "configure oidc" });
    await api.disableOIDCProvider("disable oidc");
    assert.deepEqual(calls.map((call) => call.path), [
      "/v1/system/access-administration/step-up",
      "/v1/system/access-administration/local-users",
      "/v1/system/access-administration/step-up",
      "/v1/system/access-administration/local-users/bob",
      "/v1/system/access-administration/step-up",
      "/v1/system/access-administration/local-users/bob:rotate-token",
      "/v1/system/access-administration/step-up",
      "/v1/system/access-administration/local-users/bob:disable",
      "/v1/system/access-administration/step-up",
      "/v1/system/access-administration/oidc/config",
      "/v1/system/access-administration/step-up",
      "/v1/system/access-administration/oidc/config:disable",
    ]);
    assert.equal(calls[0].body.action, "access-local-user-create");
    assert.equal(calls[1].body.ackLocalUserChange, true);
    assert.equal(calls[1].body.stepUpToken, "stepup-storage-token");
    assert.equal(calls[2].body.action, "access-local-user-update");
    assert.equal(calls[3].body.ackLocalUserChange, true);
    assert.equal(calls[4].body.action, "access-local-user-rotate-token");
    assert.equal(calls[5].body.ackRotateToken, true);
    assert.equal(calls[6].body.action, "access-local-user-disable");
    assert.equal(calls[7].body.ackDisableUser, true);
    assert.equal(calls[8].body.action, "access-oidc-set");
    assert.equal(calls[9].body.ackOidcChange, true);
    assert.equal(calls[10].body.action, "access-oidc-disable");
    assert.equal(calls[11].body.ackDisableOidc, true);
    assert.ok(calls.every((call) => call.init.headers.Authorization === "Bearer bearer-token"));
  } finally {
    if (previousFetch) Object.defineProperty(globalThis, "fetch", { configurable: true, value: previousFetch });
    else delete globalThis.fetch;
  }
}

{
  installStorage();
  setToken("runtime-token");
  const previousFetch = globalThis.fetch;
  const calls = [];
  Object.defineProperty(globalThis, "fetch", {
    configurable: true,
    value: async (path, init) => {
      calls.push({ path, init });
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ requiresAck: false, label: "ready", cls: "ok", items: [] }),
      };
    },
  });

  try {
    await api.runtimeReadinessPreflight({
      operation: "rollback",
      targetPolicy: { zones: [{ name: "known-good" }] },
      runningPolicy: { zones: [{ name: "current" }] },
    });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].path, "/v1/system/runtime-readiness:check");
    assert.equal(calls[0].init.method, "POST");
    assert.equal(calls[0].init.headers.Authorization, "Bearer runtime-token");
    assert.equal(calls[0].init.headers["X-Phragma-CSRF"], undefined);
    assert.deepEqual(JSON.parse(calls[0].init.body), {
      targetPolicy: { zones: [{ name: "known-good" }] },
      runningPolicy: { zones: [{ name: "current" }] },
      operation: "rollback",
    });
  } finally {
    if (previousFetch) Object.defineProperty(globalThis, "fetch", { configurable: true, value: previousFetch });
    else delete globalThis.fetch;
  }
}

{
  installStorage();
  setToken("existing-token");
  const previousFetch = globalThis.fetch;
  const calls = [];
  Object.defineProperty(globalThis, "fetch", {
    configurable: true,
    value: async (path, init) => {
      calls.push({ path, init });
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ actor: "candidate", role: "operator" }),
      };
    },
  });

  try {
    const id = await api.identityWithToken("candidate-token");
    assert.equal(id.actor, "candidate");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].path, "/v1/system/identity");
    assert.equal(calls[0].init.headers.Authorization, "Bearer candidate-token");
    assert.equal(getToken(), "existing-token");
  } finally {
    if (previousFetch) Object.defineProperty(globalThis, "fetch", { configurable: true, value: previousFetch });
    else delete globalThis.fetch;
  }
}

{
  installStorage();
  const previousFetch = globalThis.fetch;
  const calls = [];
  Object.defineProperty(globalThis, "fetch", {
    configurable: true,
    value: async (path, init) => {
      calls.push({ path, init });
      if (path === "/v1/auth/oidc/status") {
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ authenticated: true, csrf_token: "csrf-from-status" }),
        };
      }
      if (path === "/v1/system/access-administration/step-up") {
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ token: "csrf-stepup-token" }),
        };
      }
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ version: "1" }),
      };
    },
  });

  try {
    await api.commit("csrf refresh");
    assert.equal(calls.length, 3);
    assert.equal(calls[0].path, "/v1/auth/oidc/status");
    assert.equal(calls[0].init.method, "GET");
    assert.equal(calls[1].path, "/v1/system/access-administration/step-up");
    assert.equal(calls[1].init.method, "POST");
    assert.equal(calls[1].init.headers["X-Phragma-CSRF"], "csrf-from-status");
    assert.equal(calls[1].init.headers.Authorization, undefined);
    assert.equal(calls[2].path, "/v1/commit");
    assert.equal(calls[2].init.method, "POST");
    assert.equal(calls[2].init.headers["X-Phragma-CSRF"], "csrf-from-status");
    assert.equal(calls[2].init.headers.Authorization, undefined);
  } finally {
    if (previousFetch) Object.defineProperty(globalThis, "fetch", { configurable: true, value: previousFetch });
    else delete globalThis.fetch;
  }
}

{
  installStorage();
  setCSRFTokenForTest("cached-csrf");
  const previousFetch = globalThis.fetch;
  const calls = [];
  Object.defineProperty(globalThis, "fetch", {
    configurable: true,
    value: async (path, init) => {
      calls.push({ path, init });
      if (path === "/v1/system/access-administration/step-up") {
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ token: "cached-stepup-token" }),
        };
      }
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({}),
      };
    },
  });

  try {
    await api.rollback(1, "csrf cached");
    assert.equal(calls.length, 2);
    assert.equal(calls[0].path, "/v1/system/access-administration/step-up");
    assert.equal(calls[0].init.headers["X-Phragma-CSRF"], "cached-csrf");
    assert.equal(calls[1].path, "/v1/rollback");
    assert.equal(calls[1].init.headers["X-Phragma-CSRF"], "cached-csrf");
  } finally {
    if (previousFetch) Object.defineProperty(globalThis, "fetch", { configurable: true, value: previousFetch });
    else delete globalThis.fetch;
  }
}

{
  installStorage();
  setToken("bearer-token");
  const previousFetch = globalThis.fetch;
  const calls = [];
  Object.defineProperty(globalThis, "fetch", {
    configurable: true,
    value: async (path, init) => {
      calls.push({ path, init });
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({}),
      };
    },
  });

  try {
    await api.validate();
    assert.equal(calls.length, 1);
    assert.equal(calls[0].path, "/v1/candidate/validate");
    assert.equal(calls[0].init.headers.Authorization, "Bearer bearer-token");
    assert.equal(calls[0].init.headers["X-Phragma-CSRF"], undefined);
  } finally {
    if (previousFetch) Object.defineProperty(globalThis, "fetch", { configurable: true, value: previousFetch });
    else delete globalThis.fetch;
  }
}

{
  installStorage();
  setToken("existing-token");
  const previousFetch = globalThis.fetch;
  Object.defineProperty(globalThis, "fetch", {
    configurable: true,
    value: async () => ({
      ok: false,
      status: 401,
      text: async () => JSON.stringify({ message: "invalid token" }),
    }),
  });

  try {
    await assert.rejects(
      () => api.identityWithToken("bad-token"),
      (err) => err.status === 401 && err.message === "invalid token"
    );
    assert.equal(getToken(), "existing-token");
  } finally {
    if (previousFetch) Object.defineProperty(globalThis, "fetch", { configurable: true, value: previousFetch });
    else delete globalThis.fetch;
  }
}
