import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const rulesViewSource = readFileSync(new URL("./views/rules.js", import.meta.url), "utf8");

assert.match(rulesViewSource, /function actionControlAttrs\(dataset = \{\}, label = "", attrs = \{\}\)/);
assert.match(rulesViewSource, /type: "button",\s+title: label,\s+"aria-label": label,\s+dataset/);

for (const action of [
  "setup-baseline",
  "add-rule",
  "validate-cleanup",
]) {
  assert.match(rulesViewSource, new RegExp(`${action}`), `Rules route action ${action} has a stable selector`);
}

for (const action of [
  "action-filter",
  "zone-filter",
  "tag-filter",
  "density",
  "group",
]) {
  assert.match(rulesViewSource, new RegExp(`ruleControl: "${action}"`), `Rules control ${action} has a stable selector`);
}

for (const action of [
  "explain",
  "troubleshoot",
  "capture-troubleshoot",
  "stage-allow",
  "stage-drop",
  "capture",
  "copy-link",
  "pin-handoff",
  "export-handoff",
]) {
  assert.match(rulesViewSource, new RegExp(`ruleSimulationAction: "${action}"`), `Flow-check action ${action} has a stable selector`);
}
assert.match(rulesViewSource, /function explainDecisionLabel\(result = \{\}\)/);
assert.match(rulesViewSource, /EXPLAIN_DECISION_TERM_/);
assert.match(rulesViewSource, /decision: explainDecisionLabel\(simulator\.result\)/);
assert.match(rulesViewSource, /session\.stageDraft\("run candidate flow check"\)/);
assert.match(rulesViewSource, /session\.stageDraft\("verify changed rules"\)/);
assert.doesNotMatch(rulesViewSource, /api\.setCandidate\(session\.draft/);

for (const action of [
  "verify-changed",
  "select-visible",
  "clear",
  "enable",
  "disable",
  "log-on",
  "log-off",
  "add-tag",
  "remove-tag",
]) {
  assert.match(rulesViewSource, new RegExp(`ruleBulkAction: "${action}"`), `Bulk toolbar action ${action} has a stable selector`);
}

assert.match(rulesViewSource, /ruleReviewAction: "close"[\s\S]{0,160}Close changed rule verification drawer/);
assert.match(rulesViewSource, /ruleVerificationAction: "run"[\s\S]{0,120}Run changed rule verification/);
assert.match(rulesViewSource, /ruleOverlapAction: "api-cli"[\s\S]{0,180}Open API and CLI context for server overlap review/);
assert.match(rulesViewSource, /ruleOverlapAction: "enable-logging"[\s\S]{0,180}Enable logging for overlapped rules/);
assert.match(rulesViewSource, /ruleOverlapAction: "add-review-tag"[\s\S]{0,180}Add review tag to overlapped rules/);
assert.match(rulesViewSource, /ruleReviewAction: "stage"[\s\S]{0,180}preview\.confirmLabel/);
assert.match(rulesViewSource, /ruleAction: "cancel-editor"[\s\S]{0,120}Cancel rule editor/);
assert.match(rulesViewSource, /ruleAction: "save-editor"[\s\S]{0,120}editing \? "Save security rule" : "Add security rule"/);
assert.match(rulesViewSource, /ruleBaselineAction: "stage"[\s\S]{0,160}Stage baseline policy/);
assert.match(rulesViewSource, /ruleInlineObjectAction: "create-address"[\s\S]{0,160}Create address object/);
assert.match(rulesViewSource, /ruleInlineObjectAction: "create-service"[\s\S]{0,160}Create service object/);
