import assert from "node:assert/strict";

import { buildHash, readQueryState, writeQueryState } from "./query_state.js";

const defaults = { mode: "flows", q: "", limit: "500", sev: 0, rule: "" };
const keys = Object.keys(defaults);
const sessionDefaults = { mode: "flows", sessionKey: "" };
const sessionKeys = Object.keys(sessionDefaults);
const sessionKey = "ct1|ipv4|tcp|10.0.1.20|51515|203.0.113.20|443|203.0.113.20|443|10.0.1.20|51515";

assert.deepEqual(readQueryState({ mode: "sessions", q: "dns", sev: "2" }, defaults, keys), {
  mode: "sessions",
  q: "dns",
  limit: "500",
  sev: 2,
  rule: "",
});

assert.deepEqual(readQueryState(new URLSearchParams("q=prod&limit=1000&sev=bad"), defaults, keys), {
  mode: "flows",
  q: "prod",
  limit: "1000",
  sev: 0,
  rule: "",
});

assert.equal(buildHash("/traffic", { ...defaults, q: "ssl tls", limit: "1000" }, defaults, keys), "#/traffic?q=ssl+tls&limit=1000");
assert.equal(buildHash("/rules", { ...defaults, rule: "allow-web", sev: 0 }, defaults, keys), "#/rules?rule=allow-web");
assert.equal(buildHash("/traffic", defaults, defaults, keys), "#/traffic");
assert.equal(
  buildHash("/traffic", { mode: "sessions", sessionKey }, sessionDefaults, sessionKeys),
  "#/traffic?mode=sessions&sessionKey=ct1%7Cipv4%7Ctcp%7C10.0.1.20%7C51515%7C203.0.113.20%7C443%7C203.0.113.20%7C443%7C10.0.1.20%7C51515",
);
assert.deepEqual(
  readQueryState(new URLSearchParams("mode=sessions&sessionKey=ct1%7Cipv4%7Ctcp%7C10.0.1.20%7C51515%7C203.0.113.20%7C443%7C203.0.113.20%7C443%7C10.0.1.20%7C51515"), sessionDefaults, sessionKeys),
  { mode: "sessions", sessionKey },
);

let replaced = "";
globalThis.location = { hash: "#/traffic" };
globalThis.history = { replaceState: (_state, _title, url) => { replaced = url; globalThis.location.hash = url; } };

assert.equal(writeQueryState("/traffic", { ...defaults, mode: "sessions", q: "10.0.1.10" }, defaults, keys), "#/traffic?mode=sessions&q=10.0.1.10");
assert.equal(replaced, "#/traffic?mode=sessions&q=10.0.1.10");

delete globalThis.location;
delete globalThis.history;
