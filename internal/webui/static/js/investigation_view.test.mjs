import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const investigationViewSource = readFileSync(new URL("./views/investigation.js", import.meta.url), "utf8");
assert.match(investigationViewSource, /href: "#\/traffic", title: "Open Traffic to pin investigation evidence", "aria-label": "Open Traffic to pin investigation evidence", dataset: \{ investigationAction: "open-traffic-empty" \}/);
assert.match(investigationViewSource, /class: "investigation-action-row", dataset: \{ investigationActionRow: "case-cockpit" \}/);
assert.match(investigationViewSource, /title: action\.detail \|\| action\.label \|\| "Open investigation case action", "aria-label": action\.label \? `Open \$\{action\.label\}` : "Open investigation case action"/);
assert.match(investigationViewSource, /type: "button",\s+title: "Remove from case",\s+"aria-label": `Remove \$\{subject\} from investigation case`/);
assert.match(investigationViewSource, /dataset: \{ investigationCaseAction: "remove", investigationCaseKey: item\.key \|\| "" \}/);
assert.match(investigationViewSource, /activeInvestigationServerCaseId/);
assert.match(investigationViewSource, /setActiveInvestigationServerCaseId/);
assert.match(investigationViewSource, /serverInvestigationCaseItems/);
assert.match(investigationViewSource, /caseEvidencePayloadsFromItems/);
assert.match(investigationViewSource, /evidence: caseEvidencePayloadsFromItems\(items\)/);
assert.match(investigationViewSource, /api\.addInvestigationCaseEvidence\(serverCustodyState\.activeCaseId, caseEvidencePayloadsFromItems\(items\)\)/);
assert.match(investigationViewSource, /dataset: \{ investigationServerAction: "hydrate" \}/);
assert.match(investigationViewSource, /await api\.investigationCase\(id\)/);
assert.match(investigationViewSource, /serverInvestigationCaseItems\(resp\.case \|\| \{\}\)/);
assert.match(investigationViewSource, /dataset: \{\s+investigationSynthesis: "true",\s+investigationSynthesisState: synthesis\.state \|\| "",\s+\}/);
assert.match(investigationViewSource, /className: "investigation-synthesis-table"/);
assert.match(investigationViewSource, /Unsigned synthesis: legal hold, signing, RBAC-scoped export custody, and HA\/fleet replication remain hardening requirements\./);

class FakeText {
  constructor(text) {
    this.nodeType = 3;
    this.textContent = String(text);
  }
}

class FakeElement {
  constructor(tag) {
    this.nodeType = 1;
    this.tag = tag;
    this.children = [];
    this.dataset = {};
    this.style = {};
    this.attributes = {};
    this.className = "";
    this.hidden = false;
    this.isConnected = true;
  }
  appendChild(child) {
    this.children.push(child);
    return child;
  }
  removeChild(child) {
    const index = this.children.indexOf(child);
    if (index >= 0) this.children.splice(index, 1);
    return child;
  }
  replaceChildren(...children) {
    this.children = [];
    for (const child of children.flat()) if (child) this.appendChild(child);
  }
  setAttribute(name, value) {
    this.attributes[name] = String(value);
  }
  addEventListener() {}
  get textContent() {
    return this.children.map((child) => child.textContent || "").join("");
  }
  get firstChild() {
    return this.children[0] || null;
  }
  set innerHTML(value) {
    this.children = [new FakeText(String(value).replace(/<[^>]+>/g, ""))];
  }
}

function collectAttributeValues(node, name, values = []) {
  if (node?.attributes?.[name]) values.push(node.attributes[name]);
  for (const child of node?.children || []) collectAttributeValues(child, name, values);
  return values;
}

function collectDatasetValues(node, name, values = []) {
  if (node?.dataset?.[name]) values.push(node.dataset[name]);
  for (const child of node?.children || []) collectDatasetValues(child, name, values);
  return values;
}

globalThis.document = {
  createElement: (tag) => new FakeElement(tag),
  createTextNode: (text) => new FakeText(text),
  body: new FakeElement("body"),
};

const { flowHandoffPacket, alertHandoffPacket } = await import("./investigation_packet.js");
const { addInvestigationCasePacket, buildInvestigationCasePacket, investigationCaseItems, investigationCaseText, clearInvestigationCase } = await import("./investigation_case.js");
const { normalizeInvestigationRoute, renderInvestigationCase } = await import("./views/investigation.js");
const { api } = await import("./api.js");

function memoryStorage() {
  const data = new Map();
  return {
    getItem: (key) => data.has(key) ? data.get(key) : null,
    setItem: (key, value) => data.set(key, String(value)),
    removeItem: (key) => data.delete(key),
  };
}

const storage = memoryStorage();
clearInvestigationCase({ storage, clearedAt: "2026-06-18T12:00:00.000Z" });
addInvestigationCasePacket(flowHandoffPacket({
  flowId: "flow-42",
  srcIp: "10.0.1.20",
  destIp: "10.0.2.20",
  protocol: "TCP",
}, { route: "#/traffic?flowId=flow-42" }), { storage, pinnedAt: "2026-06-18T12:00:01.000Z" });
addInvestigationCasePacket(alertHandoffPacket({
  flowId: "flow-42",
  threatId: "threat.http.shell",
  threatName: "Suspicious web shell",
}, { route: "#/threats?flowId=flow-42" }), { storage, pinnedAt: "2026-06-18T12:00:02.000Z" });

api.packetCaptures = async (opts = {}) => ({
  captures: [{
    id: `pcap-${opts.flowId || "tuple"}`,
    state: "completed",
    plan: {
      flowId: opts.flowId || "",
      protocol: "PROTOCOL_TCP",
      srcIp: "10.0.1.20",
      destIp: "10.0.2.20",
      outputPath: "/var/log/openngfw/pcap/phragma-flow-42.pcap",
    },
    artifactId: "phragma-flow-42",
    filename: "phragma-flow-42.pcap",
    sha256: "a".repeat(64),
    bytesWritten: 2048,
    retention: {
      state: "PACKET_CAPTURE_RETENTION_STATE_RETAINED",
      retainUntil: "2999-07-19T12:00:00Z",
      retentionReason: "incident evidence review",
      caseId: "INC-2026-001",
    },
  }],
});

const caseItems = investigationCaseItems({ storage });
const node = renderInvestigationCase({ items: caseItems });
await Promise.resolve();
await Promise.resolve();
assert.match(node.textContent, /Investigation/);
assert.match(node.textContent, /2 pinned evidence items/);
assert.match(node.textContent, /Case cockpit/);
assert.match(node.textContent, /Compare cause, policy context, packet proof/);
assert.match(node.textContent, /Multi-evidence fix plan/);
assert.match(node.textContent, /Grouped remediation handoffs/);
assert.match(node.textContent, /Per-flow owner workspaces/);
assert.match(node.textContent, /Threat remediation group/);
assert.match(node.textContent, /Do not mutate running policy directly/);
assert.match(node.textContent, /Remediation planner/);
assert.match(node.textContent, /Candidate-safe pivots derived from pinned evidence/);
assert.match(node.textContent, /Retained synthesis/);
assert.match(node.textContent, /Correlation keys/);
assert.match(node.textContent, /Owner routes/);
assert.match(node.textContent, /Server retained/);
assert.match(node.textContent, /Unsigned synthesis/);
assert.match(node.textContent, /legal hold, signing, RBAC-scoped export custody/);
assert.match(node.textContent, /5\/6 ready/);
assert.match(node.textContent, /Evidence custody/);
assert.match(node.textContent, /export ready/);
assert.match(node.textContent, /Safe routes/);
assert.match(node.textContent, /Capture sources/);
assert.match(node.textContent, /Planner actions/);
assert.match(node.textContent, /Plan allow\/drop rule/);
assert.match(node.textContent, /Stage threat exception/);
assert.match(node.textContent, /Threat alert has no signature ID/);
assert.match(node.textContent, /Promote App-ID evidence/);
assert.match(node.textContent, /Review NAT\/route path/);
assert.match(node.textContent, /Suspicious web shell/);
assert.match(node.textContent, /10\.0\.1\.20 -> 10\.0\.2\.20/);
assert.match(node.textContent, /Threat evidence/);
assert.match(node.textContent, /Explain tuple/);
assert.match(node.textContent, /Capture tuple/);
assert.match(node.textContent, /EvidenceTupleAppVerdictRulePolicyCapture/);
assert.match(node.textContent, /Case capture evidence/);
assert.match(node.textContent, /1 matched/);
assert.match(node.textContent, /aaaaaaaaaaaa/);
assert.match(node.textContent, /expires 2999-07-19/);
assert.match(node.textContent, /INC-2026-001/);
assert.match(node.textContent, /API \/ CLI/);
assert.match(node.textContent, /Server custody/);
assert.match(node.textContent, /Audited server-retained cases/);
assert.match(node.textContent, /browser-local pins remain the fallback/);
assert.match(node.textContent, /Local pins/);
assert.match(node.textContent, /Copy case/);
assert.match(node.textContent, /Export JSON/);
const investigationActions = collectDatasetValues(node, "investigationAction");
assert.ok(investigationActions.includes("api-cli"));
assert.ok(investigationActions.includes("server-refresh"));
assert.ok(investigationActions.includes("server-save"));
assert.ok(collectDatasetValues(node, "investigationServerCustody").includes("true"));
assert.ok(collectDatasetValues(node, "investigationSynthesis").includes("true"));
assert.ok(collectDatasetValues(node, "investigationSynthesisState").includes("needs-review"));
assert.ok(collectDatasetValues(node, "remediationGroups").includes("true"));
assert.ok(collectDatasetValues(node, "remediationGroup").includes("group-1"));
assert.ok(collectDatasetValues(node, "ownerWorkspace").includes("candidate-rule"));
assert.ok(collectDatasetValues(node, "ownerWorkspace").includes("explain"));

const casePacket = buildInvestigationCasePacket(caseItems, { route: "#/investigation" });
assert.equal(casePacket.workbench.synthesis.schemaVersion, "phragma.investigation.synthesis.v1");
assert.equal(casePacket.workbench.synthesis.custody.unsigned, true);
assert.ok(casePacket.workbench.synthesis.custody.hardeningRequired.includes("retention and legal hold enforcement"));
const caseText = investigationCaseText(casePacket);
assert.match(caseText, /\[retained case synthesis\]/);
assert.match(caseText, /boundary=unsigned synthesis; legal hold and signed custody require hardening/);
assert.doesNotMatch(caseText, /Bearer-secret|password|\/etc\/passwd|file:|\/tmp\/pcap/i);

assert.deepEqual(normalizeInvestigationRoute({
  caseKey: caseItems[0].key,
  caseAction: "candidate-rule",
  caseKind: "flow",
}), {
  caseKey: caseItems[0].key,
  caseAction: "candidate-rule",
  caseKind: "flow",
});
assert.deepEqual(normalizeInvestigationRoute({
  caseKey: "token=secret",
  caseAction: "candidate-rule",
  caseKind: "flow",
}), { caseKey: "", caseAction: "", caseKind: "" });

const focusedNode = renderInvestigationCase({
  items: caseItems,
  routeState: {
    caseKey: caseItems[0].key,
    caseAction: "candidate-rule",
    caseKind: "flow",
  },
});
await Promise.resolve();
await Promise.resolve();
assert.match(focusedNode.textContent, /Focused case action: Candidate Rule/);
assert.match(focusedNode.textContent, /Flow evidence:/);
assert.match(focusedNode.textContent, /focused/);
assert.ok(collectDatasetValues(focusedNode, "caseFocusBanner").includes("true"));
assert.ok(collectDatasetValues(focusedNode, "caseFocused").includes("true"));
assert.ok(collectDatasetValues(focusedNode, "caseAction").includes("candidate-rule"));
assert.ok(collectDatasetValues(focusedNode, "caseKind").includes("flow"));
assert.ok(collectAttributeValues(focusedNode, "href").includes("#/traffic?flowId=flow-42"));
assert.doesNotMatch(focusedNode.textContent, /token=|Bearer-secret|\/etc\/passwd|file:/i);

const unsafeRoute = "#/traffic?flowId=legacy-flow&token=Bearer-secret&password=secret&path=/etc/passwd&file=file:/tmp/pcap";
const unsafeStorage = memoryStorage();
addInvestigationCasePacket(flowHandoffPacket({
  flowId: "legacy-flow",
  srcIp: "10.0.1.30",
  destIp: "10.0.2.30",
  protocol: "TCP",
}, { route: unsafeRoute }), { storage: unsafeStorage, pinnedAt: "2026-06-18T12:05:00.000Z" });
const unsafeNode = renderInvestigationCase({ items: investigationCaseItems({ storage: unsafeStorage }) });
await Promise.resolve();
await Promise.resolve();
assert.match(unsafeNode.textContent, /redacted unsafe route/);
assert.match(unsafeNode.textContent, /redaction active/);
assert.doesNotMatch(unsafeNode.textContent, /Bearer-secret|password|\/etc\/passwd|file:|\/tmp\/pcap/i);
for (const href of collectAttributeValues(unsafeNode, "href")) {
  assert.doesNotMatch(href, /Bearer-secret|password|\/etc\/passwd|file:|\/tmp\/pcap/i);
}
