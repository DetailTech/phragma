import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const rules = readFileSync("internal/webui/static/js/views/rules.js", "utf8");
const css = readFileSync("internal/webui/static/css/app.css", "utf8");

assert.match(rules, /class: "table-wrap rules-table-wrap"/);
assert.match(rules, /class: `rules-table \$\{tableDensity === "compact" \? "compact" : ""\}`/);
assert.match(rules, /class: "rules-select-col"/);
assert.match(rules, /class: "rules-index-col"/);
assert.match(rules, /class: "rules-enabled-col"/);
assert.match(rules, /class: "rules-hits-col"/);
assert.match(rules, /class: `rules-actions-col \$\{reorderEnabled \? "reorder-enabled" : ""\}`/);
assert.match(rules, /class: "rule-name-head"/);
assert.match(rules, /class: "note rule-description"/);
assert.match(rules, /class: "rule-zone-path"/);
assert.match(rules, /class: "rules-actions-cell", "data-label": "Actions"/);
assert.match(rules, /class: "rules-row-actions"/);
assert.match(rules, /class: "flex wrap rules-empty-actions"/);
assert.match(rules, /class: "rules-action-filter"/);
assert.match(rules, /class: "rules-zone-filter"/);
assert.match(rules, /class: "rules-tag-filter"/);
assert.match(rules, /class: "rules-filter-controls", dataset: \{ rulesToolbarGroup: "filters" \}/);
assert.match(rules, /class: "rules-view-controls", dataset: \{ rulesToolbarGroup: "view" \}/);
assert.match(rules, /class: "sim-actions start"/);
assert.match(rules, /class: "rule-verification-head"/);
assert.match(rules, /class: "rule-verification-title"/);
assert.match(rules, /class: "muted rule-verification-kind"/);
assert.match(rules, /class: "posture-metric baseline-toggle"/);
assert.match(rules, /class: "baseline-toggle-copy"/);
assert.match(rules, /class: "chips rules-token-editor"/);
assert.match(rules, /class: "rules-token-select"/);
assert.match(rules, /dataset: opts\.field \? \{ ruleField: opts\.field \} : \{\}/);
assert.match(rules, /const RULE_TABLE_COLUMN_COUNT = 17;/);
assert.match(rules, /Identity \/ posture/);
assert.match(rules, /colspan: String\(RULE_TABLE_COLUMN_COUNT\)/);
assert.doesNotMatch(rules, /h\("th", \{ style:/);
assert.doesNotMatch(rules, /colspan: "15"/);
assert.doesNotMatch(rules, /style: \{ maxWidth: "1(?:50|60|70)px" \}/);
assert.doesNotMatch(rules, /class: "flex", style: \{ gap: "8px" \}/);
assert.doesNotMatch(rules, /class: "sim-actions", style: \{ justifyContent: "flex-start" \}/);
assert.doesNotMatch(rules, /class: "flex wrap", style: \{ justifyContent: "space-between", gap: "8px" \}/);
assert.doesNotMatch(rules, /class: "muted", style: \{ marginLeft: "8px" \}/);
assert.doesNotMatch(rules, /class: "posture-metric flex", style: \{ justifyContent: "space-between", alignItems: "center" \}/);
assert.doesNotMatch(rules, /style: \{ whiteSpace: "normal", textTransform: "none", letterSpacing: "0" \}/);
assert.doesNotMatch(rules, /class: "chips", style: \{ gap: "6px" \}/);
assert.doesNotMatch(rules, /style: \{ width: "auto", minWidth: "120px" \}/);
assert.doesNotMatch(rules, /"data-label": "Actions", style: \{ textAlign: "right" \}/);
assert.doesNotMatch(rules, /style: \{ maxWidth: "260px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" \}/);
assert.doesNotMatch(rules, /style: \{ justifyContent: "flex-end", gap: "2px" \}/);
assert.match(rules, /ruleChangeModel\(session\.running\?\.rules \|\| \[\], rules\)/);
assert.match(rules, /ruleChangeForIndex\(changeModel, idx\)/);
assert.match(rules, /matchFilter\(rule, idx, shadowedBy, policy, change, filter\)/);
assert.match(rules, /dataset: \{ idx, rulePosition: `#\$\{idx \+ 1\}`, ruleName: r\.name \|\| "\((unnamed)\)", ruleChange: change\?\.kind \|\| "unchanged" \}/);
assert.match(rules, /dataset: \{ ruleBulkToolbar: "true" \}/);
assert.match(rules, /dataset: \{ ruleControl: "density" \}/);
assert.match(rules, /"aria-label": "Rule table density"/);
assert.match(rules, /dataset: \{ ruleControl: "group" \}/);
assert.match(rules, /"aria-label": "Group visible rules"/);
assert.match(rules, /dataset: \{ ruleSelect: "visible" \}/);
assert.match(rules, /"aria-label": "Select visible rules"/);
assert.match(rules, /dataset: \{ ruleSelect: "group" \}/);
assert.match(rules, /dataset: \{ ruleSelect: "row" \}/);
assert.match(rules, /const label = `Select rule \$\{rule\?\.name \|\| idx \+ 1\}`/);
assert.match(rules, /ruleGroup: group\.key \|\| group\.label/);
assert.match(rules, /dataset: \{ rulebaseMap: "true" \}/);
assert.match(rules, /dataset: \{ rulebaseBand: band\.key \|\| "" \}/);
assert.match(rules, /dataset: \{ rulebaseReviewRow: row\.name \|\| "", rulebaseReviewIndex: String\(row\.index\) \}/);
assert.match(rules, /dataset: \{ ruleChangeSummary: "true" \}/);
assert.match(rules, /class: "rule-change-toggle"/);
assert.match(rules, /class: `rule-change-badge \$\{change\.kind\}`/);
assert.match(rules, /ruleGroupRow\(group, root\)/);
assert.match(rules, /function groupSelectionCheckbox\(indexes = \[\], root\)/);
assert.match(rules, /aria-label": "Select this visible rule group"/);
assert.match(rules, /e\.target\?\.closest\?\.\("\.drag-handle"\)/);
assert.match(rules, /e\.preventDefault\(\);[\s\S]*return;[\s\S]*from = Number\(tr\.dataset\.idx\)/);
assert.match(rules, /ruleRow\(rule, idx, shadowedBy, root, \{ reorderEnabled, change, ruleCount: rules\.length \}\)/);
assert.match(rules, /rowMenu\(r, idx, root, \{ reorderEnabled, ruleCount: opts\.ruleCount \}\)/);
assert.match(rules, /function moveRule\(idx, delta, root\)/);
assert.match(rules, /type: "button",[\s\S]*title,[\s\S]*"aria-label": title,[\s\S]*dataset: data,[\s\S]*onclick: \(e\) => \{ e\.stopPropagation\(\); fn\(\); \}/);
assert.match(rules, /await session\.apply\(\(d\) => \{[\s\S]*const \[moved\] = d\.rules\.splice\(from, 1\);[\s\S]*d\.rules\.splice\(to, 0, moved\);[\s\S]*\}\)/);

for (const action of ["explain", "capture", "move-up", "move-down", "edit", "duplicate", "insert-below", "delete"]) {
  assert.match(rules, new RegExp(`ruleAction: "${action}"`));
}

for (const label of [
  "Select",
  "#",
  "On",
  "Name",
  "Tags",
  "From → To",
  "Source",
  "Destination",
  "Service",
  "App-ID",
  "Profiles",
  "Inspection",
  "Action",
  "Running hits",
  "Actions",
]) {
  assert.match(rules, new RegExp(`"data-label": "${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
}

assert.match(css, /\.rules-table \{ min-width: 1320px; \}/);
assert.match(css, /\.rules-empty-actions \{ justify-content: center; \}/);
assert.match(css, /\.rules-select-col \{ width: 44px; \}/);
assert.match(css, /\.rules-index-col \{ width: 34px; \}/);
assert.match(css, /\.rules-enabled-col \{ width: 44px; \}/);
assert.match(css, /\.rules-hits-col \{ width: 132px; text-align: right; \}/);
assert.match(css, /\.rules-actions-col \{ width: 120px; text-align: right; \}/);
assert.match(css, /\.rules-actions-col\.reorder-enabled \{ width: 188px; \}/);
assert.match(css, /\.rules-filter-controls,[\s\S]*\.rules-view-controls \{[\s\S]*gap: 8px;[\s\S]*flex-wrap: wrap;/);
assert.match(css, /\.rules-action-filter,[\s\S]*\.rules-zone-filter,[\s\S]*\.rules-density-control \{ max-width: 150px; \}/);
assert.match(css, /\.rules-tag-filter,[\s\S]*\.rules-group-control \{ max-width: 170px; \}/);
assert.match(css, /\.sim-actions\.start \{ justify-content: flex-start; \}/);
assert.match(css, /\.rule-verification-head \{[\s\S]*justify-content: space-between;[\s\S]*gap: 8px;[\s\S]*flex-wrap: wrap;/);
assert.match(css, /\.rule-verification-title \{ min-width: 0; \}/);
assert.match(css, /\.rule-verification-title strong \{ overflow-wrap: anywhere; \}/);
assert.match(css, /\.rule-verification-kind \{ margin-left: 8px; \}/);
assert.match(css, /\.baseline-toggle \{[\s\S]*justify-content: space-between;[\s\S]*align-items: center;[\s\S]*gap: 12px;/);
assert.match(css, /\.baseline-toggle-copy \{[\s\S]*text-transform: none;[\s\S]*white-space: normal;/);
assert.match(css, /\.baseline-toggle-copy strong \{[\s\S]*overflow-wrap: anywhere;/);
assert.match(css, /\.baseline-toggle-copy \.note \{[\s\S]*overflow-wrap: anywhere;/);
assert.match(css, /\.rules-token-editor \{ gap: 6px; min-width: 0; \}/);
assert.match(css, /\.rules-token-select \{ width: auto; min-width: 120px; max-width: 100%; \}/);
assert.match(css, /\.rule-name-head \{/);
assert.match(css, /\.rule-description \{ max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; \}/);
assert.match(css, /\.rule-zone-path \{/);
assert.match(css, /\.rules-actions-cell \{ text-align: right; vertical-align: top; \}/);
assert.match(css, /\.rules-row-actions \{[\s\S]*max-width: 110px;[\s\S]*justify-content: flex-end;[\s\S]*gap: 3px;[\s\S]*flex-wrap: wrap;/);
assert.match(css, /\.rules-actions-cell:has\(\.rules-row-actions \.icon-btn:nth-child\(8\)\) \.rules-row-actions \{[\s\S]*max-width: 145px;/);
assert.match(css, /\.rule-inspection \{/);
assert.match(css, /\.rules-table th:nth-child\(12\), \.rules-table td\[data-label="Inspection"\] \{ min-width: 150px; \}/);
assert.match(css, /\.rule-bulk-toolbar \{/);
assert.match(css, /\.rulebase-map \{/);
assert.match(css, /\.rulebase-map-bands \{/);
assert.match(css, /\.rulebase-map-review-row \{/);
assert.match(css, /\.rule-change-summary, \.rule-removed-list \{/);
assert.match(css, /\.rule-change-toggle \{/);
assert.match(css, /\.rules-table tr\.rule-change-added \{/);
assert.match(css, /\.rule-change-badge\.modified \{/);
assert.match(css, /\.rules-table\.compact th, \.rules-table\.compact td \{/);
assert.match(css, /@media \(max-width: 820px\)[\s\S]*\.rules-table-wrap \{[\s\S]*overflow: visible;/);
assert.match(css, /@media \(max-width: 820px\)[\s\S]*\.rules-table thead \{ display: none; \}/);
assert.match(css, /content: attr\(data-rule-position\) " " attr\(data-rule-name\);/);
assert.match(css, /\.rules-table tbody td::before \{[\s\S]*content: attr\(data-label\);/);
assert.match(css, /\.rules-table tbody td\[data-label\] \{[\s\S]*min-width: 0;/);
assert.match(css, /\.rules-table tbody td\[data-label="Select"\]::before \{ content: none; \}/);
assert.match(css, /@media \(max-width: 820px\)[\s\S]*\.rules-table tbody td\[data-label="Actions"\] \{[\s\S]*display: flex;[\s\S]*justify-content: flex-start;/);
assert.match(css, /@media \(max-width: 820px\)[\s\S]*\.rules-filter-controls,[\s\S]*\.rules-view-controls \{[\s\S]*width: 100%;[\s\S]*align-items: stretch;/);
assert.match(css, /@media \(max-width: 820px\)[\s\S]*\.rules-filter-controls select,[\s\S]*\.rules-view-controls select \{[\s\S]*flex: 1 1 138px;[\s\S]*max-width: none;/);
assert.match(css, /@media \(max-width: 820px\)[\s\S]*\.baseline-toggle \{ align-items: flex-start; \}/);
assert.match(css, /@media \(max-width: 820px\)[\s\S]*\.rules-token-editor \{ align-items: stretch; \}/);
assert.match(css, /@media \(max-width: 820px\)[\s\S]*\.rules-token-select \{[\s\S]*flex: 1 1 150px;[\s\S]*min-width: 0;/);
assert.match(css, /@media \(max-width: 820px\)[\s\S]*\.rules-table \.rule-inspection \{[\s\S]*max-width: 100%;/);
assert.match(css, /@media \(max-width: 820px\)[\s\S]*\.rules-table \.rule-description \{[\s\S]*max-width: 100%;[\s\S]*white-space: normal;/);
assert.match(css, /@media \(max-width: 820px\)[\s\S]*\.rules-table \.rules-row-actions \{[\s\S]*justify-content: flex-start;[\s\S]*gap: 6px;/);
