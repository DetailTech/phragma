import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const settingsViewSource = readFileSync(new URL("./views/settings.js", import.meta.url), "utf8");

function assertControl(selectorPattern, label) {
  assert.match(settingsViewSource, selectorPattern, label);
}

for (const action of [
  "stage",
  "pin-evidence-plan",
  "copy-evidence-plan",
  "export-evidence-json",
  "server-proof",
  "receiver-proof",
]) {
  assertControl(new RegExp(`type: "button"[\\s\\S]{0,520}telemetryAction: "${action}"`), `telemetry ${action} has button semantics`);
  assertControl(new RegExp(`aria-label": "[^"]+"[\\s\\S]{0,520}telemetryAction: "${action}"`), `telemetry ${action} has an aria label`);
  assertControl(new RegExp(`title: [^,]+[\\s\\S]{0,520}telemetryAction: "${action}"`), `telemetry ${action} has a title`);
}

for (const action of ["copy", "export", "pin", "close", "close-server-proof"]) {
  assertControl(new RegExp(`type: "button"[\\s\\S]{0,520}telemetryProofAction: "${action}"`), `telemetry proof ${action} has button semantics`);
  assertControl(new RegExp(`aria-label": "[^"]+"[\\s\\S]{0,520}telemetryProofAction: "${action}"`), `telemetry proof ${action} has an aria label`);
  assertControl(new RegExp(`title: [^,]+[\\s\\S]{0,520}telemetryProofAction: "${action}"`), `telemetry proof ${action} has a title`);
}

assertControl(/type: "button"[\s\S]{0,220}settingsServiceAction: "configure-ids"/, "IDS service configure has button semantics");
assertControl(/title: "Configure IDS\/IPS security service"[\s\S]{0,220}settingsServiceAction: "configure-ids"/, "IDS service configure has a title");
assertControl(/aria-label": "Configure IDS\/IPS security service"[\s\S]{0,220}settingsServiceAction: "configure-ids"/, "IDS service configure has an aria label");
assertControl(/type: "button"[\s\S]{0,180}settingsNetworkAction: "stage"/, "network stage has button semantics");
assertControl(/aria-label": "Stage network settings to candidate"[\s\S]{0,180}settingsNetworkAction: "stage"/, "network stage has an aria label");
assertControl(/title: "Stage network settings"[\s\S]{0,180}settingsNetworkAction: "stage"/, "network stage has a title");
assertControl(/type: "button"[\s\S]{0,260}settingsNetworkProfile: profile\.id[\s\S]{0,180}"aria-label": `Apply \$\{profile\.title\} network profile`/, "network profile buttons have stable selectors and aria labels");

for (const action of [
  "stage-default",
  "add-rule",
  "add-management-allow",
  "cancel-rule",
  "stage-rule",
  "edit-rule",
  "delete-rule",
]) {
  assertControl(new RegExp(`type: "button"[\\s\\S]{0,260}hostInputAction: "${action}"`), `host-input ${action} has button semantics`);
  assertControl(new RegExp(`aria-label": [^,]+[\\s\\S]{0,260}hostInputAction: "${action}"`), `host-input ${action} has an aria label`);
  assertControl(new RegExp(`title: [^,]+[\\s\\S]{0,260}hostInputAction: "${action}"`), `host-input ${action} has a title`);
}
