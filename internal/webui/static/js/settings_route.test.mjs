import assert from "node:assert/strict";

import {
  SETTINGS_PANELS,
  focusSettingsPanel,
  normalizeSettingsPanel,
  normalizeSettingsState,
  scheduleSettingsPanelFocus,
  settingsPanelHash,
  settingsPanelLinkModel,
  settingsPanelURL,
} from "./settings_route.js";

assert.deepEqual(SETTINGS_PANELS.map((panel) => panel.id), ["telemetry", "network", "host-input", "access"]);

assert.equal(normalizeSettingsPanel("network"), "network");
assert.equal(normalizeSettingsPanel(" telemetry "), "telemetry");
assert.equal(normalizeSettingsPanel("tokens"), "");
assert.deepEqual(normalizeSettingsState({ panel: "network" }), { panel: "network" });
assert.deepEqual(normalizeSettingsState({ panel: "unknown", token: "secret" }), { panel: "" });
assert.deepEqual(normalizeSettingsState({ panel: "", bad: "noise" }), { panel: "" });
assert.deepEqual(normalizeSettingsState(new URLSearchParams("panel=access&token=secret")), { panel: "access" });

assert.equal(settingsPanelHash("host-input"), "#/settings?panel=host-input");
assert.equal(settingsPanelHash("telemetry", "/settings"), "#/settings?panel=telemetry");
assert.equal(settingsPanelHash("invalid"), "#/settings");
assert.equal(settingsPanelHash(""), "#/settings");

assert.equal(
  settingsPanelURL("access", "/settings", { href: "https://fw.example.com/ui/#/rules?filter=old" }),
  "https://fw.example.com/ui/#/settings?panel=access",
);
assert.equal(
  settingsPanelURL("telemetry", "/settings", { href: "https://user:secret@fw.example.com/ui/?token=secret&clickhouse=http://db#/rules?filter=old" }),
  "https://fw.example.com/ui/#/settings?panel=telemetry",
);
assert.equal(
  settingsPanelURL("access", "/settings", { href: "https://operator:token@fw.example.com/ui/?session=secret#/settings?panel=network" }),
  "https://fw.example.com/ui/#/settings?panel=access",
);
assert.equal(settingsPanelURL("network", "/settings", null), "#/settings?panel=network");

const links = settingsPanelLinkModel("host-input", "/settings");
assert.equal(links.length, 4);
assert.equal(links.find((link) => link.id === "host-input").active, true);
assert.equal(links.find((link) => link.id === "host-input").href, "#/settings?panel=host-input");
assert.ok(links.every((link) => !/token|secret|password|clickhouse|source/i.test(link.href)));

{
  const calls = [];
  const target = {
    scrollIntoView(opts) { calls.push(["scroll", opts]); },
    focus(opts) { calls.push(["focus", opts]); },
  };
  const root = {
    querySelectorAll(selector) {
      calls.push(["query", selector]);
      return [
        { dataset: { settingsPanel: "network" } },
        { dataset: { settingsPanel: "telemetry" }, ...target },
      ];
    },
  };
  assert.equal(focusSettingsPanel(root, "telemetry"), true);
  assert.deepEqual(calls, [
    ["query", "[data-settings-panel]"],
    ["focus", { preventScroll: true }],
    ["scroll", { block: "start", behavior: "smooth" }],
  ]);
}

{
  const calls = [];
  const root = {
    querySelectorAll() {
      calls.push("query");
      return [];
    },
  };
  assert.equal(focusSettingsPanel(root, "bad"), false);
  assert.deepEqual(calls, []);
}

{
  const calls = [];
  const root = {
    querySelectorAll(selector) {
      calls.push(["query", selector]);
      return [{
        dataset: { settingsPanel: "network" },
        scrollIntoView(opts) { calls.push(["scroll", opts]); },
        focus(opts) { calls.push(["focus", opts]); },
      }];
    },
  };
  let scheduled = null;
  const didSchedule = scheduleSettingsPanelFocus(root, "network", (fn) => {
    calls.push(["scheduled"]);
    scheduled = fn;
  });
  assert.equal(didSchedule, true);
  assert.deepEqual(calls, [["scheduled"]]);
  scheduled();
  assert.deepEqual(calls.slice(1), [
    ["query", "[data-settings-panel]"],
    ["focus", { preventScroll: true }],
    ["scroll", { block: "start", behavior: "smooth" }],
  ]);
}

{
  let scheduled = false;
  assert.equal(scheduleSettingsPanelFocus({}, "legacy", () => { scheduled = true; }), false);
  assert.equal(scheduled, false);
}
