import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const rules = readFileSync("internal/webui/static/js/views/rules.js", "utf8");
const css = readFileSync("internal/webui/static/css/app.css", "utf8");

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function sourceWindow(source, pattern, label, before = 360, after = 520) {
  const offset = source.search(pattern);
  assert.notEqual(offset, -1, `${label} stable hook is present`);
  return source.slice(Math.max(0, offset - before), offset + after);
}

function assertActionControl(actionKey, actionValue, label) {
  const hook = new RegExp(`${escapeRegExp(actionKey)}: "${escapeRegExp(actionValue)}"`);
  const block = sourceWindow(rules, hook, `${label} button`);
  assert.match(block, /h\("button"/, `${label} is rendered as a button`);
  if (block.includes("actionControlAttrs(")) {
    assert.match(block, new RegExp(`actionControlAttrs\\(\\{\\s*${escapeRegExp(actionKey)}: "${escapeRegExp(actionValue)}"`), `${label} uses shared button affordance attrs`);
    return;
  }
  assert.match(block, /type: "button"/, `${label} has explicit type=button`);
  assert.match(block, /title:/, `${label} has a visible hover title`);
  assert.match(block, /"aria-label":/, `${label} has an accessible label`);
  assert.match(block, new RegExp(`dataset: \\{\\s*${escapeRegExp(actionKey)}: "${escapeRegExp(actionValue)}"`), `${label} has a stable dataset hook`);
}

function assertDrawerButton(actionKey, actionValue, label) {
  const block = sourceWindow(rules, new RegExp(`${escapeRegExp(actionKey)}: "${escapeRegExp(actionValue)}"`), `${label} drawer button`, 420, 640);
  assert.match(block, /h\("button"/, `${label} drawer action is rendered as a button`);
  assert.match(block, /actionControlAttrs\(/, `${label} drawer action uses shared button affordance attrs`);
}

function assertCss(pattern, label) {
  assert.match(css, pattern, label);
}

assert.match(rules, /function actionControlAttrs\(dataset = \{\}, label = "", attrs = \{\}\) \{\s*return \{\s*type: "button",\s*title: label,\s*"aria-label": label,\s*dataset,/s, "shared Rules button affordance helper sets type, title, aria-label, and dataset hook");

for (const [action, label] of [
  ["setup-baseline", "Set up baseline policy"],
  ["add-rule", "Add security rule"],
  ["validate-cleanup", "Validate rule cleanup findings"],
]) {
  assertActionControl("rulesAction", action, `Rules desktop toolbar ${label}`);
}

assert.match(rules, /const btn = \(ico, title, fn, data = \{\}, attrs = \{\}\) => h\("button", \{\s*class: "icon-btn",\s*type: "button",\s*title,\s*"aria-label": title,\s*dataset: data,/s, "Rules row action button factory sets button type, title, aria-label, and dataset hook");
for (const action of ["explain", "capture", "move-up", "move-down", "edit", "duplicate", "insert-below", "delete"]) {
  const block = sourceWindow(rules, new RegExp(`ruleAction: "${action}"`), `Rules row action ${action}`, 720, 420);
  assert.match(block, /btn\(/, `Rules row action ${action} is created by the row button factory`);
}

for (const [action, label] of [
  ["verify-changed", "Verify changed rules"],
  ["select-visible", "Select visible rules"],
  ["clear", "Clear selected rules"],
  ["enable", "Enable selected rules"],
  ["disable", "Disable selected rules"],
  ["log-on", "Enable logging on selected rules"],
  ["log-off", "Disable logging on selected rules"],
  ["add-tag", "Add tag to selected rules"],
  ["remove-tag", "Remove tag from selected rules"],
]) {
  assertActionControl("ruleBulkAction", action, `Rules bulk toolbar ${label}`);
}

for (const [key, action, label] of [
  ["ruleReviewAction", "copy-context", "Copy rule review context"],
  ["ruleReviewAction", "close", "Close changed rule verification drawer"],
  ["ruleVerificationAction", "run", "Run changed rule verification"],
  ["ruleOverlapAction", "api-cli", "Open server overlap API and CLI context"],
  ["ruleOverlapAction", "close", "Close server overlap review drawer"],
  ["ruleOverlapAction", "enable-logging", "Enable logging for overlapped rules"],
  ["ruleOverlapAction", "add-review-tag", "Add review tag to overlapped rules"],
  ["ruleReviewAction", "cancel", "Cancel bulk rule review"],
  ["ruleReviewAction", "stage", "Stage bulk rule review"],
  ["ruleAction", "cancel-editor", "Cancel rule editor"],
  ["ruleAction", "save-editor", "Save rule editor"],
]) {
  assertDrawerButton(key, action, `Rules drawer ${label}`);
}
assert.match(rules, /actionControlAttrs\(\{ ruleReviewAction: mode === "remove" \? "remove-tag" : "add-tag" \}, mode === "remove" \? "Review and remove selected rule tag" : "Review and add selected rule tag"/, "bulk tag drawer add/remove buttons keep stable hooks, titles, and aria labels through shared attrs");

assertCss(/\.toolbar \{[^}]*display: flex;[^}]*flex-wrap: wrap;[^}]*\}/, "desktop toolbar wraps instead of forcing clipped controls");
assertCss(/\.toolbar > \* \{ min-width: 0; \}/, "desktop toolbar children can shrink within the toolbar");
assertCss(/\.table-wrap \{[^}]*max-width: 100%;[^}]*overflow-x: auto;[^}]*scrollbar-gutter: stable;[^}]*\}/, "desktop table wrapper contains wide Rules tables without page overflow");
assertCss(/\.rules-table \{ min-width: 1320px; \}/, "desktop Rules table keeps stable columns for row affordances");
assertCss(/\.rule-bulk-toolbar \{[^}]*display: flex;[^}]*gap: 12px;[^}]*min-width: 0;[^}]*\}/, "desktop bulk toolbar has stable flex layout");
assertCss(/\.rule-bulk-toolbar > div:first-child \{[^}]*min-width: 0;[^}]*flex-wrap: wrap;[^}]*\}/, "bulk toolbar summary text wraps instead of clipping");
assertCss(/\.rule-bulk-actions \{[^}]*display: flex;[^}]*justify-content: flex-end;[^}]*gap: 8px;[^}]*flex-wrap: wrap;[^}]*min-width: 0;[^}]*\}/, "bulk toolbar actions wrap in desktop context");
assertCss(/\.rules-actions-col \{ width: 120px; text-align: right; \}/, "row action column has stable desktop width");
assertCss(/\.rules-actions-col\.reorder-enabled \{ width: 188px; \}/, "row action column expands when reorder controls are visible");
assertCss(/\.rules-row-actions \{[^}]*max-width: 110px;[^}]*justify-content: flex-end;[^}]*gap: 3px;[^}]*flex-wrap: wrap;[^}]*\}/, "row action icon buttons wrap within the action cell");
assertCss(/\.rules-actions-cell:has\(\.rules-row-actions \.icon-btn:nth-child\(8\)\) \.rules-row-actions \{[^}]*max-width: 145px;[^}]*\}/, "row actions make room when all eight buttons are visible");
assertCss(/\.rules-row-actions \.icon-btn \{ flex: 0 0 34px; width: 34px; height: 34px; min-width: 34px; min-height: 34px; \}/, "row action icon buttons have stable clickable dimensions");
assertCss(/\.btn \{[^}]*min-width: 0;[^}]*max-width: 100%;[^}]*white-space: normal;[^}]*overflow-wrap: anywhere;[^}]*\}/, "text buttons can wrap instead of clipping in their container");
assertCss(/\.drawer \{[^}]*width: min\(560px, 94vw\);[^}]*max-width: 94vw;[^}]*overflow-x: hidden;[^}]*\}/, "Rules drawers stay inside desktop viewport width");
assertCss(/\.drawer \* \{ min-width: 0; \}/, "drawer descendants can shrink inside the drawer");
assertCss(/\.drawer-body \{[^}]*overflow-x: hidden;[^}]*overflow-y: auto;[^}]*\}/, "drawer body prevents horizontal overflow and preserves vertical scrolling");
assertCss(/\.drawer-foot \{[^}]*display: flex;[^}]*flex-wrap: wrap;[^}]*gap: 10px;[^}]*justify-content: flex-end;[^}]*\}/, "drawer footer buttons wrap instead of clipping");
