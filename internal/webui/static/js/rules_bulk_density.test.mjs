import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  applyBulkRuleDisabled,
  applyBulkRuleLog,
  applyBulkRuleTag,
  applyHostInputRuleLog,
  bulkRuleActionPreview,
  bulkRulePreviewStillCurrent,
  bulkRuleTargetSnapshotFromToken,
  bulkRuleTargetSnapshotStatus,
  bulkRuleTargetSnapshotToken,
  bulkRuleTagIssues,
  canReorderRuleRows,
  computeRuleHygiene,
  assignFreshRuleId,
  freshRuleId,
  groupRuleRows,
  normalizeBulkRuleTag,
  normalizeRuleGroup,
  normalizeRuleDensity,
  normalizeRuleReviewDrawer,
  overlapImpactForRule,
  parseServerOverlapDetail,
  representativeFlowFromRule,
  rulebaseMapModel,
  ruleCandidateReviewCommands,
  ruleReviewContextText,
  ruleRouteTargetState,
  ruleChangeForIndex,
  ruleChangeModel,
  ruleChangeSummary,
  ruleIdentityReviewNotes,
  ruleInspectionCoverage,
  ruleLargeRulebasePosture,
  ruleTableScaleReview,
  ruleTableHasActiveFilter,
  ruleVerificationKey,
  ruleVerificationStatus,
  ruleVerificationSummary,
  rulesFlowCheckHash,
  rulesFlowCheckRouteState,
  rulesTroubleshootHash,
  rulesTroubleshootRouteState,
  ruleValidationCleanup,
  ruleValidationSnapshotStatus,
  serverOverlapReviewModel,
  serverOverlapImpactForRule,
  tagIssues,
} from "./views/rules.js";

const rulesViewSource = readFileSync(new URL("./views/rules.js", import.meta.url), "utf8");
assert.match(rulesViewSource, /pinInvestigationPacket/);
assert.match(rulesViewSource, /function ruleSimulationHandoffPacket/);
assert.match(rulesViewSource, /function pinRuleSimulationHandoff/);
assert.match(rulesViewSource, /onclick: pinRuleSimulationHandoff/);
assert.match(rulesViewSource, /Pin to case/);
assert.match(rulesViewSource, /function selectHygieneRuleSet/);
assert.match(rulesViewSource, /selectHygieneRuleSet\(finding, root, \{ reviewAction \}\)/);
assert.match(rulesViewSource, /Review logging/);
assert.match(rulesViewSource, /server-overlap-review/);
assert.match(rulesViewSource, /ruleOverlapReview/);
assert.match(rulesViewSource, /ruleOverlapItem/);
assert.match(rulesViewSource, /ruleOverlapTruncation/);
assert.match(rulesViewSource, /Backend returned the \$\{meta\.limit\}-finding maximum; additional overlap findings may exist\./);
assert.match(rulesViewSource, /ruleOverlapPeerConfidence/);
assert.match(rulesViewSource, /detail-text-derived peer/);
assert.match(rulesViewSource, /Review overlaps/);
assert.match(rulesViewSource, /rule-scale-review/);
assert.match(rulesViewSource, /rule-large-posture/);
assert.match(rulesViewSource, /No backend pagination, virtualization retention, signed evidence custody, or cross-page selection authority is claimed here\./);
assert.match(rulesViewSource, /Bulk route targets use durable rule IDs when present and fall back to position\/signature for legacy rules/);
assert.match(rulesViewSource, /dataset: \{ ruleIdentityCaveat: "name-index" \}/);
assert.match(rulesViewSource, /ruleId/);
assert.match(rulesViewSource, /ruleRouteTargetState/);
assert.match(rulesViewSource, /Staged to candidate with a fresh durable rule ID/);
assert.match(rulesViewSource, /Do not carry this selection across pagination or virtualization boundaries without refreshing the route, filters, durable IDs, and target list/);
assert.doesNotMatch(rulesViewSource, /stageRuleLog\(finding\.indexes/);

assert.equal(normalizeRuleDensity("compact"), "compact");
assert.equal(normalizeRuleDensity("comfortable"), "comfortable");
assert.equal(normalizeRuleDensity("dense"), "comfortable");
assert.equal(normalizeRuleGroup("tag"), "tag");
assert.equal(normalizeRuleGroup("action"), "action");
assert.equal(normalizeRuleGroup("zone"), "zone");
assert.equal(normalizeRuleGroup("rule-group"), "none");
assert.equal(normalizeRuleReviewDrawer("verify-changed"), "verify-changed");
assert.equal(normalizeRuleReviewDrawer("bulk-log-on"), "bulk-log-on");
assert.equal(normalizeRuleReviewDrawer("bulk-tag-remove"), "bulk-tag-remove");
assert.equal(normalizeRuleReviewDrawer("server-overlap-review"), "server-overlap-review");
assert.equal(normalizeRuleReviewDrawer("../../../etc/passwd"), "");

assert.equal(normalizeBulkRuleTag(" Owner:SecOps "), "owner:secops");
assert.equal(normalizeBulkRuleTag("pci zone 1"), "pci-zone-1");
assert.equal(normalizeBulkRuleTag(""), "");
assert.equal(normalizeBulkRuleTag("A".repeat(80)).length, 64);
assert.deepEqual(tagIssues(["a".repeat(64)]), []);
assert.match(tagIssues(["a".repeat(65)])[0], /64-character limit/);

assert.equal(ruleTableHasActiveFilter({}), false);
assert.equal(ruleTableHasActiveFilter({ q: "shadowed" }), true);
assert.equal(ruleTableHasActiveFilter({ action: "ACTION_DENY" }), true);
assert.equal(ruleTableHasActiveFilter({ zone: "dmz" }), true);
assert.equal(ruleTableHasActiveFilter({ tag: "owner:secops" }), true);
assert.equal(ruleTableHasActiveFilter({ changed: true }), true);
assert.equal(ruleTableHasActiveFilter({ rule: "allow-web" }), false);
assert.equal(canReorderRuleRows({}, 0, "none"), true);
assert.equal(canReorderRuleRows({ q: "web" }, 0, "none"), false);
assert.equal(canReorderRuleRows({ changed: true }, 0, "none"), false);
assert.equal(canReorderRuleRows({}, 1, "none"), false);
assert.equal(canReorderRuleRows({}, 0, "tag"), false);
assert.equal(canReorderRuleRows({}, 0, "invalid"), true);

assert.equal(ruleTableScaleReview(20, 20, 0, {}, "none"), null);
{
  const scale = ruleTableScaleReview(300, 300, 0, {}, "none");
  assert.equal(scale.state, "large-rulebase");
  assert.equal(scale.total, 300);
  assert.equal(scale.visible, 300);
  assert.equal(scale.selected, 0);
  assert.equal(scale.filtered, false);
  assert.match(scale.warnings.join("\n"), /Narrow the visible set/);
  assert.match(scale.warnings.join("\n"), /durable rule IDs/);
}
{
  const scale = ruleTableScaleReview(500, 30, 260, { tag: "owner:secops" }, "tag");
  assert.equal(scale.state, "selection-review");
  assert.equal(scale.filtered, true);
  assert.equal(scale.grouped, true);
  assert.match(scale.warnings.join("\n"), /Grouped views preserve rule order/);
  assert.match(scale.warnings.join("\n"), /large bulk edits should be copied as API\/CLI context/);
  assert.match(scale.warnings.join("\n"), /Pagination or virtualization/);
}

assert.deepEqual(rulesFlowCheckRouteState({
  q: "Web",
  action: "ACTION_ALLOW",
  zone: "lan",
  tag: "owner:web",
  changed: true,
}, {
  source: "POLICY_SOURCE_CANDIDATE",
  fromZone: "lan",
  toZone: "dmz",
  protocol: "PROTOCOL_TCP",
  appId: "web-browsing",
  srcIp: "10.0.1.20",
  srcPort: "51515",
  destIp: "10.0.2.20",
  destPort: "443",
}, {
  density: "compact",
  group: "tag",
  drawer: "bulk-tag-add",
  bulkTag: "owner:web",
  run: true,
}), {
  q: "web",
  action: "ACTION_ALLOW",
  zone: "lan",
  tag: "owner:web",
  ruleId: "",
  rule: "",
  changed: true,
  simSource: "POLICY_SOURCE_CANDIDATE",
  simFrom: "lan",
  simTo: "dmz",
  simProtocol: "PROTOCOL_TCP",
  simApp: "web-browsing",
  simUsers: "",
  simGroups: "",
  simDevices: "",
  simPosture: "",
  simSrc: "10.0.1.20",
  simSport: "51515",
  simDst: "10.0.2.20",
  simDport: "443",
  density: "compact",
  group: "tag",
  drawer: "bulk-tag-add",
  bulkTag: "owner:web",
  bulkTargets: "",
  simRun: true,
  caseKey: "",
  caseAction: "",
  caseKind: "",
});

{
  const route = rulesFlowCheckRouteState({}, {
    source: "POLICY_SOURCE_CANDIDATE",
    fromZone: "lan",
    toZone: "dmz",
    users: "alice@example.com",
    groups: "idp/secops",
    devices: "laptop-123",
    postureLabels: "posture:edr-healthy",
    srcIp: "10.0.1.20",
    destIp: "10.0.2.20",
    destPort: "443",
  });
  assert.equal(route.simUsers, "alice@example.com");
  assert.equal(route.simGroups, "idp/secops");
  assert.equal(route.simDevices, "laptop-123");
  assert.equal(route.simPosture, "posture:edr-healthy");
}

assert.equal(rulesFlowCheckHash("/rules", { q: "web" }, {
  source: "POLICY_SOURCE_CANDIDATE",
  fromZone: "lan",
  toZone: "dmz",
  srcIp: "10.0.1.20",
  srcPort: "51515",
  destIp: "10.0.2.20",
  destPort: "443",
  protocol: "PROTOCOL_TCP",
}, { density: "compact", group: "tag", drawer: "bulk-enable", run: true }),
"#/rules?q=web&simSource=POLICY_SOURCE_CANDIDATE&simFrom=lan&simTo=dmz&simSrc=10.0.1.20&simSport=51515&simDst=10.0.2.20&simDport=443&density=compact&group=tag&drawer=bulk-enable&simRun=1");

assert.equal(rulesFlowCheckHash("/rules", { q: "web", ruleId: "rule-allow-api", rule: "allow-api" }, {
  source: "POLICY_SOURCE_CANDIDATE",
  fromZone: "lan",
  toZone: "dmz",
  srcIp: "10.0.1.20",
  srcPort: "51515",
  destIp: "10.0.2.20",
  destPort: "443",
  protocol: "PROTOCOL_TCP",
}, { run: true }),
"#/rules?q=web&ruleId=rule-allow-api&rule=allow-api&simSource=POLICY_SOURCE_CANDIDATE&simFrom=lan&simTo=dmz&simSrc=10.0.1.20&simSport=51515&simDst=10.0.2.20&simDport=443&simRun=1");

assert.deepEqual(ruleRouteTargetState({ id: "rule-allow-api", name: "allow-api" }), { ruleId: "rule-allow-api", rule: "" });
assert.deepEqual(ruleRouteTargetState({ name: "legacy-allow-api" }), { ruleId: "", rule: "legacy-allow-api" });

assert.equal(rulesFlowCheckHash("/rules", { q: "web" }, {
  source: "POLICY_SOURCE_CANDIDATE",
  fromZone: "lan",
  toZone: "dmz",
  srcIp: "10.0.1.20",
  srcPort: "51515",
  destIp: "10.0.2.20",
  destPort: "443",
  protocol: "PROTOCOL_TCP",
}, {
  density: "compact",
  group: "tag",
  run: true,
  caseContext: { caseKey: "alert:flow-77:abc", caseAction: "candidate-rule", caseKind: "alert" },
}),
"#/rules?q=web&simSource=POLICY_SOURCE_CANDIDATE&simFrom=lan&simTo=dmz&simSrc=10.0.1.20&simSport=51515&simDst=10.0.2.20&simDport=443&density=compact&group=tag&simRun=1&caseKey=alert%3Aflow-77%3Aabc&caseAction=candidate-rule&caseKind=alert");

assert.equal(rulesFlowCheckHash("/rules", { changed: true }, {}, { active: false }), "#/rules?changed=1");
assert.equal(rulesFlowCheckHash("/rules", { changed: false }, {}, { active: false }), "#/rules");
assert.equal(rulesFlowCheckHash("/rules", { tag: "pci" }, {}, { active: false, drawer: "bulk-tag-remove", bulkTag: "pci" }), "#/rules?tag=pci&drawer=bulk-tag-remove&bulkTag=pci");
assert.match(rulesFlowCheckHash("/rules", {}, {}, { active: false, drawer: "bulk-log-on", bulkTargets: "abc_123-XYZ" }), /^#\/rules\?drawer=bulk-log-on&bulkTargets=abc_123-XYZ$/);

const reviewCommands = ruleCandidateReviewCommands();
assert.deepEqual(reviewCommands, [
  "ngfwctl policy status --json",
  "ngfwctl policy validate",
  "ngfwctl policy diff",
]);
assert.ok(!reviewCommands.some((command) => /policy validate --source candidate|policy diff --running --candidate/.test(command)));

const explainReviewCommands = ruleCandidateReviewCommands({ explain: true });
assert.ok(explainReviewCommands.includes("ngfwctl explain --source candidate --from-zone <zone> --to-zone <zone> --src <ip> --dst <ip> --dport <port>"));

const reviewContext = ruleReviewContextText({
  title: "Bulk rule review",
  drawer: "bulk-log-on",
  routeHash: "#/rules?drawer=bulk-log-on",
  targetCount: 3,
  visibleCount: 2,
  hiddenCount: 1,
  changeCount: 2,
  noOpCount: 1,
  blockedCount: 0,
  action: "Enable rule logging",
  filters: { q: "web", tag: "owner:web", changed: true },
  targets: [
    { position: 1, itemId: "rule-allow-web", name: "allow-web", visible: true, before: "logging off", after: "logging on" },
    { position: 3, name: "allow-dns", visible: false, before: "logging on", after: "logging on", noOp: true },
  ],
  commands: reviewCommands,
});
assert.match(reviewContext, /Drawer: bulk-log-on/);
assert.match(reviewContext, /Visible targets: 2/);
assert.match(reviewContext, /Hidden targets: 1/);
assert.match(reviewContext, /No-op: 1/);
assert.match(reviewContext, /Target rules:\n- #1 allow-web id=rule-allow-web \[visible\/change\]: logging off -> logging on\n- #3 allow-dns \[hidden\/no-op\]: logging on -> logging on/);
assert.match(reviewContext, /Commands:\n- ngfwctl policy status --json\n- ngfwctl policy validate\n- ngfwctl policy diff/);
assert.doesNotMatch(reviewContext, /policy validate --source candidate|policy diff --running --candidate/);

{
  const running = [
    { name: "old-admin", action: "ACTION_ALLOW" },
    { name: "allow-web", action: "ACTION_ALLOW", fromZones: ["lan"], toZones: ["wan"] },
    { name: "drop-ssh", action: "ACTION_DENY" },
    { name: "allow-dns", action: "ACTION_ALLOW", services: ["dns"] },
  ];
  const draft = [
    { name: "allow-dns", action: "ACTION_ALLOW", services: ["dns"] },
    { name: "drop-ssh", action: "ACTION_DENY" },
    { name: "allow-web", action: "ACTION_ALLOW", fromZones: ["lan"], toZones: ["dmz"] },
    { name: "new-api", action: "ACTION_ALLOW" },
  ];
  const model = ruleChangeModel(running, draft);
  assert.equal(ruleChangeForIndex(model, 0).kind, "moved");
  assert.equal(ruleChangeForIndex(model, 0).runningIndex, 3);
  assert.equal(ruleChangeForIndex(model, 1).kind, "moved");
  assert.equal(ruleChangeForIndex(model, 2).kind, "modified");
  assert.equal(ruleChangeForIndex(model, 3).kind, "added");
  assert.deepEqual(model.removed.map((item) => item.name), ["old-admin"]);
  assert.deepEqual(model.counts, { added: 1, modified: 1, moved: 2, removed: 1 });
  assert.equal(ruleChangeSummary(model).label, "1 added · 1 modified · 2 moved · 1 removed");
}

{
  const duplicateModel = ruleChangeModel([
    { name: "dup", action: "ACTION_ALLOW" },
    { name: "dup", action: "ACTION_DENY" },
  ], [
    { name: "dup", action: "ACTION_ALLOW" },
    { name: "dup", action: "ACTION_DENY" },
  ]);
  assert.equal(ruleChangeForIndex(duplicateModel, 0).kind, "modified");
  assert.equal(ruleChangeForIndex(duplicateModel, 1).kind, "modified");
  assert.equal(duplicateModel.removed.length, 0);

  const renamedModel = ruleChangeModel([{ name: "old-name", action: "ACTION_ALLOW" }], [{ name: "new-name", action: "ACTION_ALLOW" }]);
  assert.equal(ruleChangeForIndex(renamedModel, 0).kind, "modified");
  assert.equal(renamedModel.removed.length, 0);

  const unnamedModel = ruleChangeModel([{ action: "ACTION_REJECT", log: false }], [{ action: "ACTION_REJECT", log: true }]);
  assert.equal(ruleChangeForIndex(unnamedModel, 0).kind, "modified");
}

assert.equal(ruleChangeSummary(ruleChangeModel([], [])).label, "No staged rule changes");

{
  const model = ruleChangeModel([
    { id: "rule-1", name: "old-name", action: "ACTION_ALLOW" },
    { id: "rule-2", name: "move-me", action: "ACTION_DENY" },
  ], [
    { id: "rule-2", name: "move-me", action: "ACTION_DENY" },
    { id: "rule-1", name: "new-name", action: "ACTION_ALLOW" },
  ]);
  assert.equal(ruleChangeForIndex(model, 0).kind, "moved");
  assert.equal(ruleChangeForIndex(model, 0).runningIndex, 1);
  assert.equal(ruleChangeForIndex(model, 1).kind, "modified");
  assert.equal(ruleChangeForIndex(model, 1).runningIndex, 0);
  assert.equal(model.removed.length, 0);
}

{
  const existing = [{ id: "allow-web-fixed", name: "allow-web" }];
  assert.equal(freshRuleId(existing, { name: "Allow API", seed: "fixed" }), "allow-api-fixed");
  const cloned = { id: "source-id", name: "allow-web-copy" };
  assignFreshRuleId(cloned, existing, { seed: "copy" });
  assert.equal(cloned.id, "allow-web-copy-copy");
  assert.notEqual(cloned.id, "source-id");
}

{
  const rule = {
    name: "allow-api",
    action: "ACTION_ALLOW",
    toZones: ["dmz"],
    fromZones: ["lan"],
    services: ["https"],
    destinationAddresses: ["api"],
    sourceAddresses: ["clients"],
  };
  const reordered = {
    services: ["https"],
    sourceAddresses: ["clients"],
    destinationAddresses: ["api"],
    fromZones: ["lan"],
    toZones: ["dmz"],
    action: "ACTION_ALLOW",
    name: "allow-api",
  };
  const added = { kind: "added", draftIndex: 2, runningIndex: -1 };
  const modified = { kind: "modified", draftIndex: 2, runningIndex: 4 };
  const moved = { kind: "moved", draftIndex: 2, runningIndex: 4 };
  assert.equal(ruleVerificationKey(rule, null), "");
  assert.equal(ruleVerificationKey(rule, { kind: "removed", draftIndex: -1, runningIndex: 4 }), "");
  assert.notEqual(ruleVerificationKey(rule, added), "");
  assert.notEqual(ruleVerificationKey(rule, modified), "");
  assert.notEqual(ruleVerificationKey(rule, moved), "");
  assert.equal(ruleVerificationKey(rule, modified), ruleVerificationKey(reordered, modified));
  assert.notEqual(ruleVerificationKey(rule, modified), ruleVerificationKey({ ...rule, log: true }, modified));
  assert.notEqual(ruleVerificationKey(rule, modified), ruleVerificationKey({ ...rule, name: "allow-api-renamed" }, modified));
  assert.notEqual(ruleVerificationKey(rule, modified), ruleVerificationKey(rule, { ...modified, draftIndex: 3 }));
  assert.notEqual(ruleVerificationKey(rule, modified), ruleVerificationKey(rule, { ...modified, runningIndex: 5 }));
  assert.notEqual(ruleVerificationKey(rule, modified), ruleVerificationKey(rule, moved));

  const key = ruleVerificationKey(rule, modified);
  assert.deepEqual(ruleVerificationStatus(rule, modified, new Map()), {
    state: "needed",
    label: "verify",
    key,
  });
  assert.equal(ruleVerificationStatus(rule, modified, new Map([[key, { key, state: "verified", verifiedAt: "now" }]])).label, "verified");
  assert.equal(ruleVerificationStatus(rule, modified, { [key]: { key, state: "mismatch" } }).label, "mismatch");
  assert.equal(ruleVerificationStatus(rule, modified, { [key]: { key, state: "unverifiable" } }).label, "needs tuple");
  assert.equal(ruleVerificationStatus(rule, modified, { [key]: { key, state: "error" } }).label, "failed");
  assert.equal(ruleVerificationStatus(rule, modified, { [key]: { key, state: "unknown" } }).state, "needed");
  assert.equal(ruleVerificationStatus(rule, modified, { [key]: { key: "older", state: "verified" } }).state, "stale");

  const rows = [
    { rule, change: modified },
    { rule: { ...rule, name: "allow-admin" }, change: { kind: "added", draftIndex: 3, runningIndex: -1 } },
    { rule: { ...rule, name: "allow-dns" }, change: { kind: "moved", draftIndex: 4, runningIndex: 1 } },
    { rule: { ...rule, name: "drop-old" }, change: { kind: "removed", draftIndex: -1, runningIndex: 8 } },
  ];
  const secondKey = ruleVerificationKey(rows[1].rule, rows[1].change);
  const thirdKey = ruleVerificationKey(rows[2].rule, rows[2].change);
  const summary = ruleVerificationSummary(rows, {
    [key]: { key, state: "verified" },
    [secondKey]: { key: "previous", state: "verified" },
    [thirdKey]: { key: thirdKey, state: "unverifiable" },
  }, { removed: 1 });
  assert.equal(summary.total, 3);
  assert.equal(summary.verified, 1);
  assert.equal(summary.stale, 1);
  assert.equal(summary.unverifiable, 1);
  assert.equal(summary.needed, 0);
  assert.equal(summary.pending, 2);
  assert.equal(summary.complete, false);
  assert.equal(summary.label, "1/3 changed verified · 2 needs review");
  const complete = ruleVerificationSummary([{ rule, change: modified }], { [key]: { key, state: "verified" } });
  assert.equal(complete.complete, true);
  assert.equal(ruleVerificationSummary([], {}, { removed: 2 }).label, "2 removed rules to review");
}

assert.deepEqual(rulesTroubleshootRouteState({
  source: "POLICY_SOURCE_CANDIDATE",
  fromZone: "lan",
  toZone: "dmz",
  protocol: "PROTOCOL_UDP",
  appId: "dns",
  srcIp: "10.0.1.20",
  srcPort: "51515",
  destIp: "10.0.2.53",
  destPort: "53",
}, { run: true, intent: "capture" }), {
  source: "POLICY_SOURCE_CANDIDATE",
  fromZone: "lan",
  toZone: "dmz",
  protocol: "PROTOCOL_UDP",
  app: "dns",
  src: "10.0.1.20",
  sport: "51515",
  dst: "10.0.2.53",
  dport: "53",
  run: true,
  intent: "capture",
});

assert.equal(rulesTroubleshootHash({
  source: "POLICY_SOURCE_CANDIDATE",
  fromZone: "lan",
  toZone: "dmz",
  protocol: "PROTOCOL_UDP",
  appId: "dns",
  srcIp: "10.0.1.20",
  srcPort: "51515",
  destIp: "10.0.2.53",
  destPort: "53",
}, { run: true, intent: "capture" }),
"#/troubleshoot?source=POLICY_SOURCE_CANDIDATE&fromZone=lan&toZone=dmz&protocol=PROTOCOL_UDP&app=dns&src=10.0.1.20&sport=51515&dst=10.0.2.53&dport=53&run=1&intent=capture");

{
  const policy = {
    addresses: [
      { name: "client", cidr: "10.0.1.20/32" },
      { name: "api", cidr: "10.0.2.20/32" },
    ],
    services: [{ name: "https", protocol: "PROTOCOL_TCP", ports: [{ start: 443 }] }],
  };
  const rule = {
    id: "rule-allow-api",
    name: "allow-api",
    fromZones: ["lan"],
    toZones: ["dmz"],
    sourceAddresses: ["client"],
    destinationAddresses: ["api"],
    services: ["https"],
    action: "ACTION_ALLOW",
  };
  const evidence = representativeFlowFromRule(policy, rule, { source: "POLICY_SOURCE_CANDIDATE" });
  assert.equal(evidence.ok, true);
  assert.deepEqual(evidence.missing, []);
  assert.deepEqual(evidence.simulator, {
    source: "POLICY_SOURCE_CANDIDATE",
    fromZone: "lan",
    toZone: "dmz",
    protocol: "PROTOCOL_TCP",
    appId: "",
    srcIp: "10.0.1.20",
    srcPort: "51515",
    destIp: "10.0.2.20",
    destPort: "443",
  });
  assert.equal(rulesFlowCheckHash("/rules", ruleRouteTargetState(rule), evidence.simulator, { run: true }),
    "#/rules?ruleId=rule-allow-api&simSource=POLICY_SOURCE_CANDIDATE&simFrom=lan&simTo=dmz&simSrc=10.0.1.20&simSport=51515&simDst=10.0.2.20&simDport=443&simRun=1");
  assert.equal(rulesFlowCheckHash("/rules", { rule: "allow-api" }, evidence.simulator, { run: true }),
    "#/rules?rule=allow-api&simSource=POLICY_SOURCE_CANDIDATE&simFrom=lan&simTo=dmz&simSrc=10.0.1.20&simSport=51515&simDst=10.0.2.20&simDport=443&simRun=1");
}

{
  const policy = {
    addresses: [
      { name: "lan-net", cidr: "10.0.1.0/24" },
      { name: "admin", cidr: "10.0.3.8/32" },
    ],
    applications: [{
      name: "corp-admin",
      ports: [{ protocol: "PROTOCOL_TCP", ports: [{ start: 8443 }] }],
    }],
  };
  const rule = {
    name: "block-corp-admin",
    fromZones: ["lan"],
    toZones: ["wan"],
    sourceAddresses: ["lan-net"],
    destinationAddresses: ["admin"],
    applications: ["corp-admin"],
    action: "ACTION_DENY",
  };
  const evidence = representativeFlowFromRule(policy, rule, { source: "POLICY_SOURCE_CANDIDATE" });
  assert.equal(evidence.ok, true);
  assert.equal(evidence.simulator.appId, "corp-admin");
  assert.equal(evidence.simulator.srcIp, "10.0.1.1");
  assert.equal(evidence.simulator.destPort, "8443");
  assert.equal(rulesTroubleshootHash(evidence.simulator, { run: true, intent: "capture" }),
    "#/troubleshoot?source=POLICY_SOURCE_CANDIDATE&fromZone=lan&toZone=wan&app=corp-admin&src=10.0.1.1&sport=51515&dst=10.0.3.8&dport=8443&run=1&intent=capture");
}

{
  const evidence = representativeFlowFromRule({}, {
    name: "allow-any",
    fromZones: ["any"],
    toZones: ["any"],
    sourceAddresses: ["any"],
    destinationAddresses: ["any"],
    services: ["any"],
    action: "ACTION_ALLOW",
  });
  assert.equal(evidence.ok, false);
  assert.deepEqual(evidence.missing, ["from-zone", "to-zone", "source IP", "destination IP", "destination port"]);
  assert.ok(evidence.warnings.some((warning) => /concrete from-zone/.test(warning)));
  assert.ok(evidence.warnings.some((warning) => /broad source address/.test(warning)));
}

{
  const policy = {
    rules: [
      { name: "allow-web", disabled: false, tags: ["prod"] },
      { name: "drop-ssh", disabled: false, tags: [] },
      { name: "allow-dns", disabled: true, tags: ["dns"] },
    ],
  };
  applyBulkRuleDisabled(policy, [2, 0, 99, 0], true);
  assert.equal(policy.rules[0].disabled, true);
  assert.equal(policy.rules[1].disabled, false);
  assert.equal(policy.rules[2].disabled, true);

  applyBulkRuleLog(policy, [0, 1], true);
  assert.equal(policy.rules[0].log, true);
  assert.equal(policy.rules[1].log, true);
  assert.equal(policy.rules[2].log, undefined);
  applyBulkRuleLog(policy, [1], false);
  assert.equal(policy.rules[1].log, false);
}

{
  const policy = {
    rules: [
      { name: "allow-web", tags: ["prod"] },
      { name: "drop-ssh", tags: [] },
      { name: "allow-dns" },
    ],
  };
  applyBulkRuleTag(policy, [0, 1, 2], "Owner:SecOps", "add");
  assert.deepEqual(policy.rules[0].tags, ["owner:secops", "prod"]);
  assert.deepEqual(policy.rules[1].tags, ["owner:secops"]);
  assert.deepEqual(policy.rules[2].tags, ["owner:secops"]);

  applyBulkRuleTag(policy, [0, 2], "owner:secops", "remove");
  assert.deepEqual(policy.rules[0].tags, ["prod"]);
  assert.deepEqual(policy.rules[1].tags, ["owner:secops"]);
  assert.deepEqual(policy.rules[2].tags, []);
}

{
  const fullTags = Array.from({ length: 32 }, (_, i) => `tag-${i}`);
  const policy = {
    rules: [
      { name: "full", tags: fullTags },
      { name: "already-tagged", tags: [...fullTags.slice(0, 31), "owner:secops"] },
    ],
  };
  assert.match(bulkRuleTagIssues(policy, [0], "owner:secops", "add")[0], /maximum tag count/);
  assert.deepEqual(bulkRuleTagIssues(policy, [1], "owner:secops", "add"), []);
  applyBulkRuleTag(policy, [0, 1], "owner:secops", "add");
  assert.equal(policy.rules[0].tags.includes("owner:secops"), false);
  assert.equal(policy.rules[1].tags.includes("owner:secops"), true);
  assert.deepEqual(bulkRuleTagIssues(policy, [0], "owner:secops", "remove"), []);
}

{
  const policy = {
    rules: [
      { id: "rule-allow-web", name: "allow-web", action: "ACTION_ALLOW", disabled: false, log: false, tags: ["prod"] },
      { id: "rule-drop-ssh", name: "drop-ssh", action: "ACTION_DENY", disabled: false, log: true, tags: [] },
      { id: "rule-allow-dns", name: "allow-dns", action: "ACTION_ALLOW", disabled: true, tags: ["dns"] },
    ],
  };
  const preview = bulkRuleActionPreview(policy, [2, 0, 99, 0], [{ idx: 0 }], { kind: "disabled", disabled: true });
  assert.equal(preview.targetCount, 2);
  assert.equal(preview.visibleCount, 1);
  assert.equal(preview.hiddenCount, 1);
  assert.equal(preview.changeCount, 1);
  assert.equal(preview.noOpCount, 1);
  assert.ok(preview.identityNotes.some((note) => /durable rule IDs/.test(note)));
  assert.ok(preview.identityNotes.some((note) => /hidden targets/.test(note)));
  assert.deepEqual(preview.rows.map((row) => [row.index, row.name, row.before, row.after, row.noOp]), [
    [0, "allow-web", "enabled", "disabled", false],
    [2, "allow-dns", "disabled", "disabled", true],
  ]);
  assert.equal(bulkRulePreviewStillCurrent(policy, preview).ok, true);
  const token = bulkRuleTargetSnapshotToken(preview);
  assert.match(token, /^[A-Za-z0-9_-]+$/);
  const snapshot = bulkRuleTargetSnapshotFromToken(token);
  assert.deepEqual(snapshot.rows.map((row) => [row.index, row.position, row.itemId, row.name]), [
    [0, 1, "rule-allow-web", "allow-web"],
    [2, 3, "rule-allow-dns", "allow-dns"],
  ]);
  const currentTargets = bulkRuleTargetSnapshotStatus(policy, token);
  assert.equal(currentTargets.ok, true);
  assert.equal(currentTargets.checked, true);
  assert.deepEqual(currentTargets.indexes, [0, 2]);
  policy.rules = [policy.rules[1], policy.rules[2], policy.rules[0]];
  const movedTargets = bulkRuleTargetSnapshotStatus(policy, token);
  assert.equal(movedTargets.ok, true);
  assert.deepEqual(movedTargets.indexes, [1, 2]);
  assert.equal(bulkRulePreviewStillCurrent(policy, preview).ok, true);
  policy.rules = [policy.rules[2], policy.rules[0], policy.rules[1]];
  policy.rules[0].name = "renamed-web";
  const stale = bulkRulePreviewStillCurrent(policy, preview);
  assert.equal(stale.ok, false);
  assert.match(stale.issues[0], /allow-web changed after the review opened/);
  const staleTargets = bulkRuleTargetSnapshotStatus(policy, token);
  assert.equal(staleTargets.ok, false);
  assert.match(staleTargets.issues[0], /allow-web changed after this route-backed review opened/);
  policy.rules.splice(2, 1);
  const missingTargets = bulkRuleTargetSnapshotStatus(policy, token);
  assert.equal(missingTargets.ok, false);
  assert.ok(missingTargets.issues.some((issue) => /Rule 3 is no longer present/.test(issue)));
  assert.equal(bulkRuleTargetSnapshotStatus(policy, "").checked, false);
}

{
  const policy = {
    rules: [
      { id: "rule-allow-web", name: "allow-web", action: "ACTION_ALLOW", log: false },
      { name: "legacy-dns", action: "ACTION_ALLOW", log: true },
      { id: "rule-drop-ssh", name: "drop-ssh", action: "ACTION_DENY", log: true },
    ],
  };
  const snapshot = bulkRuleActionPreview(policy, [0, 2], [{ idx: 0 }], { kind: "log", log: true });
  const token = bulkRuleTargetSnapshotToken(snapshot);
  const unchecked = ruleValidationSnapshotStatus({}, policy);
  const posture = ruleLargeRulebasePosture(policy, [{ idx: 0 }, { idx: 1 }], [0, 2], {
    ranAt: "2026-06-22T12:00:00.000Z",
    draftFingerprint: unchecked.fingerprint,
  }, {
    overlapFindingLimit: 25,
    overlapFindingsMayBeTruncated: true,
    overlapFindings: [{
      index: 2,
      overlapPage: {
        limit: 25,
        resultCount: 25,
        totalResults: 40,
        truncated: true,
        hasMore: true,
        nextOffset: 25,
        pageKey: "policy-hygiene-rule-overlap:v1",
      },
    }],
  }, {
    filter: { tag: "prod" },
    group: "tag",
    targetSnapshotToken: token,
  });

  assert.equal(posture.total, 3);
  assert.equal(posture.visible, 2);
  assert.equal(posture.hidden, 1);
  assert.equal(posture.selected, 2);
  assert.equal(posture.selectedVisible, 1);
  assert.equal(posture.selectedHidden, 1);
  assert.equal(posture.filtered, true);
  assert.equal(posture.grouped, true);
  assert.equal(posture.durableCount, 2);
  assert.equal(posture.fallbackCount, 1);
  assert.equal(posture.identityMode, "mixed");
  assert.equal(posture.targetSnapshot.checked, true);
  assert.equal(posture.targetSnapshot.ok, true);
  assert.equal(posture.validationSnapshot.current, true);
  assert.equal(posture.overlap.limit, 25);
  assert.equal(posture.overlap.totalResults, 40);
  assert.equal(posture.overlap.hasMore, true);
  assert.equal(posture.overlap.nextOffset, 25);
  assert.equal(posture.overlap.pageKey, "policy-hygiene-rule-overlap:v1");
  assert.equal(posture.overlap.mayBeTruncated, true);
  assert.ok(posture.coverage.some((note) => /current browser candidate snapshot/.test(note)));
  assert.ok(posture.omitted.some((note) => /backend pagination, virtualization retention/.test(note)));
}

{
  const legacyPolicy = {
    rules: [
      { name: "legacy-web", action: "ACTION_ALLOW", log: false },
      { name: "legacy-dns", action: "ACTION_ALLOW", log: true },
    ],
  };
  const preview = bulkRuleActionPreview(legacyPolicy, [0], [{ idx: 0 }], { kind: "log", log: true });
  const token = bulkRuleTargetSnapshotToken(preview);
  const snapshot = bulkRuleTargetSnapshotFromToken(token);
  assert.equal(snapshot.rows[0].itemId, "");
  assert.deepEqual(bulkRuleTargetSnapshotStatus(legacyPolicy, token).indexes, [0]);
  legacyPolicy.rules.reverse();
  const status = bulkRuleTargetSnapshotStatus(legacyPolicy, token);
  assert.equal(status.ok, false);
  assert.match(status.issues[0], /legacy-web changed after this route-backed review opened/);
}

{
  const policy = {
    rules: [
      { name: "dup", action: "ACTION_ALLOW" },
      { name: "unique", action: "ACTION_DENY" },
      { name: "dup", action: "ACTION_DENY" },
    ],
  };
  const notes = ruleIdentityReviewNotes(policy, [0, 2], [{ idx: 0 }], { paginationRisk: true });
  assert.ok(notes.some((note) => /legacy rules without IDs/.test(note)));
  assert.ok(notes.some((note) => /Duplicate selected rule names/.test(note) && /dup/.test(note)));
  assert.ok(notes.some((note) => /hidden targets/.test(note)));
  assert.ok(notes.some((note) => /duplicated, deleted, or edited/.test(note)));
  assert.ok(notes.some((note) => /pagination or virtualization/.test(note)));

  const preview = bulkRuleActionPreview(policy, [0, 2], [{ idx: 0 }], { kind: "log", log: true });
  assert.deepEqual(preview.rows.map((row) => row.duplicateName), [true, true]);
  assert.ok(preview.identityNotes.some((note) => /Duplicate selected rule names/.test(note)));
}

{
  const policy = {
    rules: [
      { id: "rule-dup-a", name: "dup", action: "ACTION_ALLOW" },
      { id: "rule-dup-b", name: "dup", action: "ACTION_DENY" },
    ],
  };
  const notes = ruleIdentityReviewNotes(policy, [0, 1], [{ idx: 0 }, { idx: 1 }]);
  assert.ok(notes.some((note) => /durable rule IDs plus a stale-content signature guard/.test(note)));
  assert.ok(!notes.some((note) => /Duplicate selected rule names/.test(note)));
  const preview = bulkRuleActionPreview(policy, [0, 1], [{ idx: 0 }, { idx: 1 }], { kind: "log", log: true });
  assert.deepEqual(preview.rows.map((row) => row.duplicateName), [false, false]);
}

{
  const fullTags = Array.from({ length: 32 }, (_, i) => `tag-${i}`);
  const policy = {
    rules: [
      { name: "full", action: "ACTION_ALLOW", tags: fullTags },
      { name: "already-tagged", action: "ACTION_DENY", tags: ["owner:secops"] },
      { name: "untagged", action: "ACTION_ALLOW", tags: [] },
    ],
  };
  const preview = bulkRuleActionPreview(policy, [0, 1, 2], [{ idx: 0 }, { idx: 2 }], { kind: "tag", mode: "add", tag: "Owner:SecOps" });
  assert.equal(preview.tag, "owner:secops");
  assert.equal(preview.visibleCount, 2);
  assert.equal(preview.hiddenCount, 1);
  assert.equal(preview.blockedCount, 1);
  assert.equal(preview.noOpCount, 1);
  assert.equal(preview.changeCount, 1);
  assert.match(preview.rows[0].issue, /at most 32 tags/);
  assert.equal(preview.rows[1].noOp, true);
  assert.equal(preview.rows[2].after, "owner:secops");

  const removePreview = bulkRuleActionPreview(policy, [1, 2], [{ idx: 1 }, { idx: 2 }], { kind: "tag", mode: "remove", tag: "owner:secops" });
  assert.equal(removePreview.changeCount, 1);
  assert.equal(removePreview.noOpCount, 1);
  assert.equal(removePreview.rows[0].after, "no tags");
  assert.equal(removePreview.rows[1].noOp, true);
}

{
  const rows = [
    { idx: 0, rule: { name: "allow-web", action: "ACTION_ALLOW", tags: ["prod", "owner:web"], fromZones: ["lan"], toZones: ["dmz"] } },
    { idx: 1, rule: { name: "drop-ssh", action: "ACTION_DENY", tags: [], fromZones: ["wan"], toZones: ["lan"] } },
    { idx: 2, rule: { name: "allow-dns", action: "ACTION_ALLOW", tags: ["prod"], fromZones: ["lan"], toZones: ["wan"] } },
  ];
  assert.deepEqual(groupRuleRows(rows, "none").map((group) => group.rows.map((row) => row.idx)), [[0, 1, 2]]);
  assert.deepEqual(groupRuleRows(rows, "tag").map((group) => [group.label, group.rows.map((row) => row.idx)]), [
    ["Tag: owner:web", [0]],
    ["Untagged rules", [1]],
    ["Tag: prod", [2]],
  ]);
  assert.deepEqual(groupRuleRows(rows, "action").map((group) => [group.label, group.rows.map((row) => row.idx)]), [
    ["Action: Allow", [0, 2]],
    ["Action: Drop", [1]],
  ]);
  assert.deepEqual(groupRuleRows(rows, "zone").map((group) => [group.label, group.rows.map((row) => row.idx)]), [
    ["lan → dmz", [0]],
    ["wan → lan", [1]],
    ["lan → wan", [2]],
  ]);
}

{
  const allow = { name: "allow-web", action: "ACTION_ALLOW", disabled: false };
  const drop = { name: "drop-ssh", action: "ACTION_DENY", disabled: false };

  assert.deepEqual(ruleInspectionCoverage({ ids: { enabled: false } }, allow), {
    state: "not-inspected",
    label: "not inspected",
    cls: "warn",
    detail: "IDS/IPS is disabled for this policy.",
    bypassPossible: false,
    searchText: "not-inspected not inspected ids/ips is disabled for this policy. ",
  });

  assert.equal(ruleInspectionCoverage({ ids: { enabled: false } }, drop).state, "pre-filter-drop");
  assert.equal(ruleInspectionCoverage({}, { ...allow, disabled: true }).state, "disabled");

  const failOpen = ruleInspectionCoverage({
    ids: {
      enabled: true,
      mode: "IDS_MODE_PREVENT",
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_OPEN",
    },
  }, allow);
  assert.equal(failOpen.state, "ips-fail-open");
  assert.equal(failOpen.cls, "warn");
  assert.equal(failOpen.bypassPossible, true);

  const failClosed = ruleInspectionCoverage({
    ids: {
      enabled: true,
      mode: "IDS_MODE_PREVENT",
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
    },
  }, allow);
  assert.equal(failClosed.state, "ips-fail-closed");
  assert.equal(failClosed.cls, "ok");
  assert.equal(failClosed.bypassPossible, false);

  const profiledAllow = { ...allow, securityProfiles: ["block-malicious-dns"] };
  const profilePolicy = {
    securityProfiles: [{ name: "block-malicious-dns", dnsSecurity: "DNS_SECURITY_MODE_BLOCK_MALICIOUS" }],
  };
  const inactiveProfile = ruleInspectionCoverage({ ...profilePolicy, ids: { enabled: false } }, profiledAllow);
  assert.equal(inactiveProfile.state, "profile-needs-ips");
  assert.equal(inactiveProfile.cls, "bad");
  const failOpenProfile = ruleInspectionCoverage({
    ...profilePolicy,
    ids: {
      enabled: true,
      mode: "IDS_MODE_PREVENT",
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_OPEN",
    },
  }, profiledAllow);
  assert.equal(failOpenProfile.state, "profile-needs-fail-closed");
  assert.equal(failOpenProfile.bypassPossible, true);
  const enforcedProfile = ruleInspectionCoverage({
    ...profilePolicy,
    ids: {
      enabled: true,
      mode: "IDS_MODE_PREVENT",
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
    },
  }, profiledAllow);
  assert.equal(enforcedProfile.state, "profile-enforced");
  assert.equal(enforcedProfile.cls, "ok");

  const detect = ruleInspectionCoverage({ ids: { enabled: true, mode: "IDS_MODE_DETECT" } }, allow);
  assert.equal(detect.state, "ids-detect");
  assert.equal(detect.cls, "info");

  const conflict = ruleInspectionCoverage({
    network: { enableFlowOffload: true },
    ids: { enabled: true, mode: "IDS_MODE_PREVENT" },
  }, allow);
  assert.equal(conflict.state, "bypass-risk");
  assert.equal(conflict.cls, "bad");
  assert.equal(conflict.bypassPossible, true);

  const fastPath = ruleInspectionCoverage({ network: { enableFlowOffload: true }, ids: { enabled: false } }, allow);
  assert.equal(fastPath.state, "fast-path");
  assert.equal(fastPath.cls, "neutral");
}

{
  const rules = [
    { name: "allow-web", action: "ACTION_ALLOW", fromZones: ["any"], toZones: ["any"], sourceAddresses: ["any"], destinationAddresses: ["any"], services: ["any"], log: true },
    { name: "drop-ssh", action: "ACTION_DENY", fromZones: ["lan"], toZones: ["wan"], sourceAddresses: ["any"], destinationAddresses: ["any"], services: ["ssh"], log: false },
    { name: "allow-api", action: "ACTION_ALLOW", fromZones: ["lan"], toZones: ["wan"], sourceAddresses: ["inside"], destinationAddresses: ["api"], services: ["https"] },
    { name: "disabled-audit-gap", disabled: true, action: "ACTION_ALLOW", fromZones: ["lan"], toZones: ["wan"], sourceAddresses: ["inside"], destinationAddresses: ["api"], services: ["https"], log: false },
  ];
  const hygiene = computeRuleHygiene(rules, new Map(), false, {
    network: { enableFlowOffload: true },
    ids: { enabled: true, mode: "IDS_MODE_PREVENT", failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_OPEN" },
    addresses: [{ name: "unused-admin-net" }],
    services: [{ name: "unused-admin-ssh" }],
    applications: [{ name: "unused-legacy-app" }],
    hostInput: { rules: [{ name: "allow-admin-ssh", log: false }] },
    rules,
  }, {
    missingLogs: [1, 2],
    overlaps: [2],
    overlapFindings: [{
      index: 2,
      code: "POLICY_HYGIENE_RULE_OVERLAP",
      fieldPath: "rules[2]",
      message: "allow-api overlaps allow-web",
      detail: "allow-api partially overlaps allow-web; first-match order decides verdict.",
      severity: "warn",
      stage: "candidate",
    }],
    hostInputMissingLogs: [0, 99],
    unusedObjects: [
      { kind: "address", index: 0, detail: "unused-admin-net is not referenced by forwarding policy, host-input policy, or NAT." },
      { kind: "service", index: 0, detail: "unused-admin-ssh is not referenced by forwarding policy, host-input policy, or destination NAT." },
      { kind: "application", index: 0, detail: "unused-legacy-app is not referenced by any forwarding rule." },
    ],
  });
  assert.deepEqual(hygiene.bypassRisk, [0, 2]);
  assert.deepEqual(hygiene.missingLogs, [1, 2]);
  assert.deepEqual(hygiene.validationMissingLogs, [1, 2]);
  assert.deepEqual(hygiene.validationOverlaps, [2]);
  assert.deepEqual(hygiene.validationOverlapFindings.map((finding) => finding.detail), ["allow-api partially overlaps allow-web; first-match order decides verdict."]);
  assert.deepEqual(hygiene.hostInputMissingLogs, [0]);
  assert.deepEqual(hygiene.unusedObjects.map((item) => item.kind), ["address", "service", "application"]);
  assert.deepEqual(hygiene.findings.find((finding) => finding.title === "Shadowed rules").indexes, [1, 2]);
  assert.deepEqual(hygiene.findings.find((finding) => finding.title === "Broad allows").indexes, [0]);
  assert.deepEqual(hygiene.findings.find((finding) => finding.title === "Bypass-risk allows").indexes, [0, 2]);
  assert.deepEqual(hygiene.findings.find((finding) => finding.title === "Missing logs").indexes, [1, 2]);
  assert.deepEqual(hygiene.findings.find((finding) => finding.title === "Server rule overlaps").indexes, [2]);
  assert.equal(hygiene.findings.find((finding) => finding.title === "Server rule overlaps").fix, "review-overlap");
  assert.match(hygiene.findings.find((finding) => finding.title === "Server rule overlaps").overlapFindings[0].detail, /first-match order/);
  assert.ok(hygiene.findings.some((finding) => finding.title === "Bypass-risk allows" && finding.filter.q === "bypass-risk"));
  assert.ok(hygiene.findings.some((finding) => finding.title === "Missing logs" && finding.filter.q === "missing-log" && finding.count === "2" && finding.fix === "log-on"));
  assert.ok(hygiene.findings.some((finding) => finding.title === "Server rule overlaps" && finding.filter.q === "server-overlap" && finding.count === "1"));
  assert.ok(hygiene.findings.some((finding) => finding.title === "Host-input missing logs" && finding.fix === "host-input-log-on" && finding.settingsPanel === "host-input" && finding.count === "1"));
  assert.ok(hygiene.findings.some((finding) => finding.title === "Unused addresses" && finding.href === "#/objects?drawer=references&object=unused-admin-net" && finding.detail.includes("unused-admin-net")));
  assert.ok(hygiene.findings.some((finding) => finding.title === "Unused services" && finding.href === "#/objects?tab=services&drawer=references&object=unused-admin-ssh" && finding.detail.includes("unused-admin-ssh")));
  assert.ok(hygiene.findings.some((finding) => finding.title === "Unused applications" && finding.href === "#/objects?tab=applications&drawer=references&object=unused-legacy-app" && finding.detail.includes("unused-legacy-app")));
}

{
  const counters = new Map([
    ["rule:stale-duplicate", { packets: 0, bytes: 0 }],
    ["rule:active", { packets: 12, bytes: 6400 }],
  ]);
  const hygiene = computeRuleHygiene([
    { name: "stale-duplicate", action: "ACTION_ALLOW", log: true },
    { name: "stale-duplicate", action: "ACTION_DENY", log: true },
    { name: "active", action: "ACTION_DENY", log: true },
  ], counters, true, {});
  assert.deepEqual(hygiene.duplicateNames, ["stale-duplicate"]);
  assert.deepEqual(hygiene.duplicateIndexes, [0, 1]);
  assert.deepEqual(hygiene.findings.find((finding) => finding.title === "Duplicate names").indexes, [0, 1]);
  assert.deepEqual(hygiene.staleZeroHit, [0, 1]);
  assert.deepEqual(hygiene.findings.find((finding) => finding.title === "Zero-hit running rules").indexes, [0, 1]);
}

{
  const policy = {
    ids: {
      enabled: true,
      mode: "IDS_MODE_PREVENT",
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_OPEN",
    },
    rules: [
      {
        name: "allow-web",
        action: "ACTION_ALLOW",
        fromZones: ["lan"],
        toZones: ["dmz"],
        sourceAddresses: ["clients"],
        destinationAddresses: ["web"],
        services: ["https"],
        securityProfiles: ["web-profile"],
        log: false,
      },
      {
        name: "drop-admin",
        action: "ACTION_DENY",
        fromZones: ["wan"],
        toZones: ["lan"],
        sourceAddresses: ["any"],
        destinationAddresses: ["admin"],
        applications: ["corp-admin"],
        log: true,
      },
      {
        name: "disabled-legacy",
        disabled: true,
        action: "ACTION_ALLOW",
        fromZones: ["lan"],
        toZones: ["wan"],
        sourceAddresses: ["any"],
        destinationAddresses: ["any"],
        services: ["any"],
      },
    ],
  };
  const running = {
    rules: [
      { name: "allow-web", action: "ACTION_ALLOW", log: true },
      { name: "drop-admin", action: "ACTION_DENY", log: true },
    ],
  };
  const counters = new Map([
    ["rule:allow-web", { packets: 0, bytes: 0 }],
    ["rule:drop-admin", { packets: 9, bytes: 2048 }],
  ]);
  const model = rulebaseMapModel(policy, running, counters, true, {
    missingLogs: [0],
    overlaps: [1],
    overlapFindings: [{ index: 1, detail: "drop-admin overlaps allow-web" }],
  });
  assert.equal(model.counts.total, 3);
  assert.equal(model.counts.active, 2);
  assert.equal(model.counts.allow, 1);
  assert.equal(model.counts.block, 1);
  assert.equal(model.counts.appRules, 1);
  assert.equal(model.counts.profiledRules, 1);
  assert.equal(model.counts.changed, 3);
  assert.equal(model.counts.review, 2);
  assert.equal(model.counts.zeroHit, 1);
  assert.deepEqual(model.dependencyTotals, { addresses: 3, services: 1, apps: 1, profiles: 1 });
  assert.equal(model.summary.label, "2 review items");
  assert.ok(model.bands.some((band) => band.key === "allow" && band.count === 1 && band.examples.includes("allow-web")));
  assert.ok(model.bands.some((band) => band.key === "block" && band.count === 1 && band.examples.includes("drop-admin")));
  assert.ok(model.bands.some((band) => band.key === "app-id" && band.count === 1));
  assert.ok(model.bands.some((band) => band.key === "inspection" && band.count === 1));
  assert.ok(model.bands.some((band) => band.key === "review" && band.count === 2));
  assert.ok(model.bands.some((band) => band.key === "disabled" && band.count === 1));
  assert.deepEqual(model.rows.find((row) => row.name === "allow-web").issues, ["bypass risk", "missing log", "zero hit"]);
  assert.deepEqual(model.rows.find((row) => row.name === "drop-admin").issues, ["server overlap"]);
  assert.equal(model.rows.find((row) => row.name === "drop-admin").hitState, "hit");
  assert.equal(model.rows.find((row) => row.name === "disabled-legacy").active, false);
  assert.deepEqual(model.topReviewRows.map((row) => row.name), ["allow-web", "drop-admin"]);
}

{
  const rules = [
    {
      name: "allow-dmz-web",
      action: "ACTION_ALLOW",
      fromZones: ["lan"],
      toZones: ["dmz"],
      sourceAddresses: ["client-a"],
      destinationAddresses: ["any"],
      services: ["https"],
      securityProfiles: ["profile-detect"],
      log: false,
    },
    {
      name: "drop-specific-client",
      action: "ACTION_DENY",
      fromZones: ["lan"],
      toZones: ["dmz"],
      sourceAddresses: ["any"],
      destinationAddresses: ["web"],
      services: ["https"],
      applications: ["corp-admin"],
      securityProfiles: ["profile-prevent"],
      log: true,
    },
  ];
  const impact = overlapImpactForRule(rules, 1, {
    detail: "allow-dmz-web and drop-specific-client can match some of the same traffic; first-match rule order decides the verdict.",
  });
  assert.equal(impact.peers.length, 1);
  assert.equal(impact.peers[0].earlier.name, "allow-dmz-web");
  assert.equal(impact.primaryRisk.key, "allow-before-deny");
  assert.equal(impact.primaryRisk.cls, "bad");
  assert.ok(impact.risks.includes("allow-before-deny"));
  assert.ok(impact.risks.includes("profile-mismatch"));
  assert.ok(impact.risks.includes("app-id-mismatch"));
  assert.ok(impact.risks.includes("log-gap"));
  assert.deepEqual(impact.peers[0].dimensions.map((dimension) => dimension.key), ["zones", "source", "destination", "service", "app-id"]);
  assert.equal(impact.confidence.key, "candidate-scan");
  assert.equal(impact.peers[0].confidence, "high");
  assert.ok(impact.peers[0].dimensions.every((dimension) => dimension.confidence === "high"));
  assert.match(impact.action, /Enable logging|candidate explain-flow|Review order/);
  assert.equal(impact.peers[0].representative.fromZones, "lan");
  assert.equal(impact.peers[0].representative.toZones, "dmz");
  assert.equal(impact.peers[0].representative.sourceAddresses, "client-a");
  assert.equal(impact.peers[0].representative.destinationAddresses, "web");
  assert.equal(impact.peers[0].representative.services, "https");
  assert.equal(impact.peers[0].representative.applications, "corp-admin");
}

{
  const rules = [
    {
      name: "allow-dmz-web",
      action: "ACTION_ALLOW",
      fromZones: ["lan"],
      toZones: ["dmz"],
      sourceAddresses: ["client-a"],
      destinationAddresses: ["any"],
      services: ["https"],
      securityProfiles: ["profile-detect"],
      log: false,
    },
    {
      name: "drop-specific-client",
      action: "ACTION_DENY",
      fromZones: ["lan"],
      toZones: ["dmz"],
      sourceAddresses: ["any"],
      destinationAddresses: ["web"],
      services: ["https"],
      applications: ["corp-admin"],
      securityProfiles: ["profile-prevent"],
      log: true,
    },
  ];
  const model = serverOverlapReviewModel(rules, {
    indexes: [1],
    overlapFindings: [{
      index: 1,
      detail: "unrelated-a and unrelated-b can match some of the same traffic; first-match rule order decides the verdict.",
      severity: "warn",
      stage: "candidate",
    }],
  }, { visibleIndexes: [1] });
  assert.equal(model.rows.length, 1);
  assert.equal(model.rows[0].visible, true);
  assert.equal(model.rows[0].confidence.key, "candidate-scan");
  assert.equal(model.rows[0].peerRows.length, 1);
  assert.equal(model.rows[0].peerRows[0].evidenceSource, "candidate-scan");
  assert.equal(model.rows[0].peerRows[0].peerName, "allow-dmz-web");
  assert.deepEqual(model.rows[0].sharedDimensions.map((dimension) => dimension.key), ["zones", "source", "destination", "service", "app-id"]);
  assert.deepEqual(model.rows[0].riskLabels.map((risk) => risk.key), ["allow-before-deny", "log-gap", "profile-mismatch", "app-id-mismatch"]);
  assert.equal(model.rows[0].riskLabels.find((risk) => risk.key === "allow-before-deny").label, "allow before deny");
  assert.deepEqual(model.rows[0].representativeTuple, {
    fromZones: "lan",
    toZones: "dmz",
    sourceAddresses: "client-a",
    destinationAddresses: "web",
    services: "https",
    applications: "corp-admin",
  });
  assert.equal(model.meta.hasDetailTextDerived, false);
}

{
  const rules = [
    { name: "earlier-deny", action: "ACTION_DENY", fromZones: ["lan"], toZones: ["wan"], sourceAddresses: ["admin"], destinationAddresses: ["any"], services: ["ssh"], log: true },
    { name: "later-allow", action: "ACTION_ALLOW", fromZones: ["lan"], toZones: ["wan"], sourceAddresses: ["any"], destinationAddresses: ["server"], services: ["ssh"], log: true },
  ];
  const impact = overlapImpactForRule(rules, 1, {
    detail: "earlier-deny and later-allow can match some of the same traffic; first-match rule order decides the verdict.",
  });
  assert.equal(impact.primaryRisk.key, "deny-before-allow");
  assert.ok(impact.risks.includes("deny-before-allow"));
}

{
  const rules = [
    { name: "later-deny", action: "ACTION_DENY", fromZones: ["lan"], toZones: ["dmz"], sourceAddresses: ["client-a"], destinationAddresses: ["any"], services: ["https"], log: true },
    { name: "peer-allow", action: "ACTION_ALLOW", fromZones: ["lan"], toZones: ["dmz"], sourceAddresses: ["any"], destinationAddresses: ["web"], services: ["https"], log: true },
  ];
  const impact = overlapImpactForRule(rules, 0, {
    detail: "peer-allow and later-deny can match some of the same traffic; first-match rule order decides the verdict.",
  });
  assert.equal(impact.peers.length, 1);
  assert.equal(impact.confidence.key, "detail-text");
  assert.match(impact.confidence.detail, /server detail text/);
  assert.equal(impact.peers[0].evidenceSource, "detail-text");
  assert.equal(impact.peers[0].confidence, "medium");
  assert.equal(impact.peers[0].confidenceLabel, "detail-text-derived peer");
  assert.ok(impact.peers[0].dimensions.every((dimension) => dimension.evidenceSource === "detail-text"));
  assert.ok(impact.peers[0].dimensions.every((dimension) => dimension.confidence === "medium"));
}

{
  const rules = [
    { name: "later-deny", action: "ACTION_DENY", fromZones: ["lan"], toZones: ["dmz"], sourceAddresses: ["client-a"], destinationAddresses: ["any"], services: ["https"], log: true },
    { name: "peer-allow", action: "ACTION_ALLOW", fromZones: ["lan"], toZones: ["dmz"], sourceAddresses: ["any"], destinationAddresses: ["web"], services: ["https"], log: true },
  ];
  const model = serverOverlapReviewModel(rules, {
    indexes: [0],
    overlapFindings: [{
      index: 0,
      detail: "peer-allow and later-deny can match some of the same traffic; first-match rule order decides the verdict.",
    }],
  });
  assert.equal(model.rows[0].confidence.key, "detail-text");
  assert.equal(model.rows[0].peerRows[0].evidenceSource, "detail-text");
  assert.equal(model.rows[0].peerRows[0].confidence, "medium");
  assert.equal(model.rows[0].sharedDimensions[0].evidenceSource, "detail-text");
  assert.equal(model.rows[0].sharedDimensions[0].confidence, "medium");
  assert.equal(model.rows[0].riskLabels.find((risk) => risk.key === "allow-before-deny").label, "allow before deny");
  assert.equal(model.meta.hasDetailTextDerived, true);
}

{
  const rules = [
    { name: "allow-all-web", action: "ACTION_ALLOW", fromZones: ["any"], toZones: ["dmz"], sourceAddresses: ["any"], destinationAddresses: ["web"], services: ["https"], applications: [], log: true },
    { name: "allow-client-web", action: "ACTION_ALLOW", fromZones: ["lan"], toZones: ["dmz"], sourceAddresses: ["client-a"], destinationAddresses: ["web"], services: ["https"], applications: ["corp-admin"], log: true },
  ];
  const impact = overlapImpactForRule(rules, 1, {
    detail: "allow-all-web and allow-client-web can match some of the same traffic; first-match rule order decides the verdict.",
  });
  assert.equal(impact.peers.length, 0);
  assert.equal(impact.primaryRisk.key, "order-review");
}

{
  const cleanup = ruleValidationCleanup([
    { code: "POLICY_HYGIENE_MISSING_RULE_LOG", fieldPath: "rules[0].log" },
    { code: "POLICY_HYGIENE_MISSING_RULE_LOG", field_path: "rules[2].log" },
    {
      code: "POLICY_HYGIENE_RULE_OVERLAP",
      fieldPath: "rules[2]",
      message: "overlaps allow-web",
      detail: "allow-api partially overlaps allow-web; first-match order decides verdict.",
      severity: "warn",
      stage: "candidate",
    },
    { code: "POLICY_HYGIENE_MISSING_HOST_INPUT_LOG", fieldPath: "hostInput.rules[0].log" },
    { code: "POLICY_HYGIENE_UNUSED_ADDRESS", fieldPath: "addresses[0]" },
    { code: "POLICY_HYGIENE_MISSING_RULE_LOG", fieldPath: "rules[99].log" },
  ], 4);

  assert.deepEqual(cleanup.missingLogs, [0, 2]);
  assert.deepEqual(cleanup.overlaps, [2]);
  assert.deepEqual(cleanup.overlapFindings.map((finding) => [finding.index, finding.fieldPath, finding.detail]), [[2, "rules[2]", "allow-api partially overlaps allow-web; first-match order decides verdict."]]);
  assert.deepEqual(cleanup.hostInputMissingLogs, [0]);
  assert.deepEqual(cleanup.unusedObjects.map((item) => [item.kind, item.index, item.fieldPath]), [["address", 0, "addresses[0]"]]);
  assert.deepEqual(cleanup.otherRuleFindings, []);
  assert.equal(cleanup.totalRuleFindings, 3);
  assert.equal(cleanup.totalFindings, 5);
  const policy = {
    rules: [
      { name: "allow-web", log: false },
      { name: "drop-ssh", log: false },
      { name: "allow-api", log: false },
    ],
    hostInput: {
      rules: [
        { name: "allow-admin-ssh", log: false },
        { name: "allow-admin-web", log: false },
      ],
    },
  };
  applyBulkRuleLog(policy, cleanup.missingLogs, true);
  assert.equal(policy.rules[0].log, true);
  assert.equal(policy.rules[1].log, false);
  assert.equal(policy.rules[2].log, true);
  applyHostInputRuleLog(policy, [0, 99], true);
  assert.equal(policy.hostInput.rules[0].log, true);
  assert.equal(policy.hostInput.rules[1].log, false);
}

{
  const detail = JSON.stringify({
    text: "allow-web and deny-web can match some of the same traffic; first-match rule order decides the verdict.",
    peer: { index: 0, id: "rule-allow-web", name: "allow-web", action: "ACTION_ALLOW" },
    dimensions: [
      { key: "from-zones", label: "From zones", peerValues: ["lan"], ruleValues: ["lan"], result: "overlap", sample: "lan" },
      { key: "destination-addresses", label: "Destination addresses", peerValues: ["any"], ruleValues: ["web-server"], result: "peer-covers-rule", sample: "web-server" },
    ],
    result: {
      id: "overlap-001-r1-p0",
      index: 0,
      ruleIndex: 1,
      ruleId: "rule-deny-web",
      ruleName: "deny-web",
      ruleAction: "ACTION_DENY",
      peerIndex: 0,
      peerId: "rule-allow-web",
      peerName: "allow-web",
      peerAction: "ACTION_ALLOW",
      outcome: "first-match-order-review",
      riskLabels: ["allow-before-deny", "log-gap"],
      fieldPath: "rules[1]",
      identityKey: "rules[1]:peer[0]:rule-deny-web:rule-allow-web",
    },
    page: {
      offset: 0,
      limit: 25,
      resultIndex: 0,
      resultCount: 1,
      totalResults: 1,
      truncated: false,
      hasMore: false,
      pageKey: "policy-hygiene-rule-overlap:v1",
    },
  });
  const parsed = parseServerOverlapDetail(detail);
  assert.equal(parsed.result.id, "overlap-001-r1-p0");
  assert.equal(parsed.peer.id, "rule-allow-web");
  assert.deepEqual(parsed.dimensions.map((dimension) => dimension.key), ["from-zones", "destination-addresses"]);

  const cleanup = ruleValidationCleanup([{
    code: "POLICY_HYGIENE_RULE_OVERLAP",
    fieldPath: "rules[1]",
    message: "Rules have overlapping match criteria",
    detail,
    severity: "VALIDATION_SEVERITY_WARNING",
    stage: "VALIDATION_STAGE_POLICY_MODEL",
  }], 2);
  assert.equal(cleanup.overlapFindings[0].detail, parsed.text);
  assert.equal(cleanup.overlapFindings[0].overlapPeer.id, "rule-allow-web");
  assert.equal(cleanup.overlapFindings[0].overlapResult.identityKey, "rules[1]:peer[0]:rule-deny-web:rule-allow-web");
  assert.equal(cleanup.overlapFindings[0].overlapPage.pageKey, "policy-hygiene-rule-overlap:v1");

  const rules = [
    { id: "rule-allow-web", name: "allow-web", action: "ACTION_ALLOW", log: false, fromZones: ["lan"], toZones: ["wan"], sourceAddresses: ["any"], destinationAddresses: ["any"], services: ["https"] },
    { id: "rule-deny-web", name: "deny-web", action: "ACTION_DENY", log: true, fromZones: ["lan"], toZones: ["wan"], sourceAddresses: ["any"], destinationAddresses: ["web-server"], services: ["https"] },
  ];
  const impact = serverOverlapImpactForRule(rules, 1, cleanup.overlapFindings[0]);
  assert.equal(impact.confidence.key, "server-metadata");
  assert.equal(impact.peerRows[0].peerName, "allow-web");
  assert.deepEqual(impact.risks, ["allow-before-deny", "log-gap"]);

  const model = serverOverlapReviewModel(rules, {
    indexes: [1],
    overlapFindings: cleanup.overlapFindings,
  });
  assert.equal(model.rows[0].overlapResult.id, "overlap-001-r1-p0");
  assert.equal(model.rows[0].overlapPage.pageKey, "policy-hygiene-rule-overlap:v1");
  assert.equal(model.rows[0].impact.confidence.key, "server-metadata");
  assert.equal(model.meta.hasServerMetadata, true);
  assert.equal(model.meta.pageKey, "policy-hygiene-rule-overlap:v1");
}

{
  const policy = {
    rules: [
      { name: "allow-web", log: false },
      { name: "drop-ssh", log: false },
    ],
  };
  const unchecked = ruleValidationSnapshotStatus({}, policy);
  assert.equal(unchecked.checked, false);
  assert.equal(unchecked.current, false);
  assert.equal(unchecked.stale, false);

  const checked = ruleValidationSnapshotStatus({
    ranAt: "2026-06-20T12:00:00.000Z",
    draftFingerprint: unchecked.fingerprint,
  }, policy);
  assert.equal(checked.checked, true);
  assert.equal(checked.current, true);
  assert.equal(checked.stale, false);

  const stale = ruleValidationSnapshotStatus({
    ranAt: "2026-06-20T12:00:00.000Z",
    draftFingerprint: unchecked.fingerprint,
  }, {
    rules: [
      { name: "allow-web", log: true },
      { name: "drop-ssh", log: false },
    ],
  });
  assert.equal(stale.checked, true);
  assert.equal(stale.current, false);
  assert.equal(stale.stale, true);
  assert.notEqual(stale.fingerprint, stale.checkedFingerprint);
}

{
  const overlapFindings = Array.from({ length: 25 }, (_, idx) => ({
    code: "POLICY_HYGIENE_RULE_OVERLAP",
    fieldPath: `rules[${idx}]`,
    detail: `rule-${idx} and peer-${idx} can match some of the same traffic; first-match rule order decides the verdict.`,
  }));
  const cleanup = ruleValidationCleanup(overlapFindings, 30);
  assert.equal(cleanup.overlapFindingLimit, 25);
  assert.equal(cleanup.overlapFindingsMayBeTruncated, true);
  assert.equal(cleanup.overlapFindings.length, 25);

  const rules = Array.from({ length: 30 }, (_, idx) => ({ name: `rule-${idx}`, action: "ACTION_ALLOW", log: true }));
  const hygiene = computeRuleHygiene(rules, new Map(), false, { rules }, cleanup);
  assert.equal(hygiene.validationOverlapFindingLimit, 25);
  assert.equal(hygiene.validationOverlapsMayBeTruncated, true);
  const overlapFinding = hygiene.findings.find((finding) => finding.title === "Server rule overlaps");
  assert.equal(overlapFinding.overlapFindingLimit, 25);
  assert.equal(overlapFinding.overlapFindingsMayBeTruncated, true);
  const model = serverOverlapReviewModel(rules, overlapFinding);
  assert.equal(model.meta.limit, 25);
  assert.equal(model.meta.mayBeTruncated, true);
}
