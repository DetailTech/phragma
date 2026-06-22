import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { api, setCSRFTokenForTest, setToken } from "./api.js";

const specText = readFileSync(new URL("../api-spec.yaml", import.meta.url), "utf8");

class MemoryStorage {
  constructor() {
    this.items = new Map();
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

function installStorage() {
  Object.defineProperty(globalThis, "sessionStorage", { configurable: true, value: new MemoryStorage() });
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: new MemoryStorage() });
  setToken("");
  setCSRFTokenForTest("");
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function assertSpecRoute(path, method) {
  specRouteMethodBlock(path, method);
}

function specRouteMethodBlock(path, method) {
  const routeHeader = `  ${path}:\n`;
  const routeStart = specText.indexOf(routeHeader);
  assert.notEqual(routeStart, -1, `api-spec.yaml is missing ${path}`);
  const blockStart = routeStart + routeHeader.length;
  const nextRoute = specText.slice(blockStart).search(/\n  \/v1\/|\ndefinitions:/);
  const block = nextRoute === -1
    ? specText.slice(blockStart)
    : specText.slice(blockStart, blockStart + nextRoute);
  assert.match(block, new RegExp(`^    ${escapeRegExp(method.toLowerCase())}:`, "m"), `api-spec.yaml ${path} is missing ${method}`);
  const methodStart = block.search(new RegExp(`^    ${escapeRegExp(method.toLowerCase())}:`, "m"));
  const afterMethod = block.slice(methodStart);
  const nextMethod = afterMethod.slice(1).search(/\n    (get|post|patch|put|delete):/);
  return nextMethod === -1 ? afterMethod : afterMethod.slice(0, nextMethod + 1);
}

function assertSpecResponses(path, method, expectedCodes) {
  const block = specRouteMethodBlock(path, method);
  const responseBlockStart = block.indexOf("      responses:\n");
  assert.notEqual(responseBlockStart, -1, `api-spec.yaml ${method} ${path} is missing responses`);
  const responseBlock = block.slice(responseBlockStart);
  const codes = Array.from(responseBlock.matchAll(/^        "([0-9]{3})":/gm), (match) => match[1]);
  assert.deepEqual(codes, expectedCodes, `api-spec.yaml ${method} ${path} response codes`);
}

function assertSpecBlockIncludes(path, method, snippets) {
  const block = specRouteMethodBlock(path, method);
  for (const snippet of snippets) {
    assert.ok(block.includes(snippet), `api-spec.yaml ${method} ${path} missing ${snippet}`);
  }
}

function installFetchRecorder({ binary = false } = {}) {
  const previousFetch = Object.getOwnPropertyDescriptor(globalThis, "fetch");
  const calls = [];
  Object.defineProperty(globalThis, "fetch", {
    configurable: true,
    value: async (path, init = {}) => {
      calls.push({
        path,
        init,
        body: init.body === undefined ? undefined : JSON.parse(init.body),
      });
      if (path === "/v1/system/access-administration/step-up") {
        return {
          ok: true,
          status: 200,
          text: async () => JSON.stringify({ token: "stepup-contract-token" }),
        };
      }
      if (binary) {
        return {
          ok: true,
          status: 200,
          blob: async () => ({ type: "application/vnd.tcpdump.pcap", size: 64 }),
        };
      }
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ ok: true }),
      };
    },
  });
  return {
    calls,
    restore() {
      if (previousFetch) Object.defineProperty(globalThis, "fetch", previousFetch);
      else delete globalThis.fetch;
    },
  };
}

async function assertApiContract(contract) {
  const { name, invoke, method, path, body, specPath, binary = false, stepUpAction = "", stepUpComment = "" } = contract;
  installStorage();
  setToken("contract-token");
  const recorder = installFetchRecorder({ binary });
  try {
    await invoke();
    const expectedCalls = stepUpAction ? 2 : 1;
    assert.equal(recorder.calls.length, expectedCalls, `${name} fetch count`);
    let call = recorder.calls[0];
    if (stepUpAction) {
      assert.equal(call.init.method, "POST", `${name} step-up method`);
      assert.equal(call.path, "/v1/system/access-administration/step-up", `${name} step-up path`);
      assert.deepEqual(call.body, { action: stepUpAction, comment: stepUpComment, ackStepUp: true }, `${name} step-up body`);
      assert.equal(call.init.headers.Authorization, "Bearer contract-token", `${name} step-up bearer auth header`);
      assertSpecRoute("/v1/system/access-administration/step-up", "POST");
      call = recorder.calls[1];
    }
    assert.equal(call.init.method, method, `${name} method`);
    assert.equal(call.path, path, `${name} path`);
    if (Object.prototype.hasOwnProperty.call(contract, "body")) {
      const expectedBody = stepUpAction ? { ...body, stepUpToken: "stepup-contract-token" } : body;
      assert.deepEqual(call.body, expectedBody, `${name} body`);
    } else {
      assert.equal(call.init.body, undefined, `${name} should not send a body`);
    }
    assert.equal(call.init.headers.Authorization, "Bearer contract-token", `${name} bearer auth header`);
    assertSpecRoute(specPath || path.split("?")[0], method);
  } finally {
    recorder.restore();
  }
}

await assertApiContract({
  name: "releaseAcceptanceStatus",
  invoke: () => api.releaseAcceptanceStatus(),
  method: "GET",
  path: "/v1/system/release-acceptance/status",
});

await assertApiContract({
  name: "supportBundle",
  invoke: () => api.supportBundle({ versionLimit: 10, auditLimit: 20, eventLimit: 30 }),
  method: "GET",
  path: "/v1/system/support-bundle?versionLimit=10&auditLimit=20&eventLimit=30",
  specPath: "/v1/system/support-bundle",
});

await assertApiContract({
  name: "fleetNodes",
  invoke: () => api.fleetNodes(),
  method: "GET",
  path: "/v1/fleet/nodes",
});

await assertApiContract({
  name: "fleetTemplates",
  invoke: () => api.fleetTemplates(),
  method: "GET",
  path: "/v1/fleet/templates",
});

await assertApiContract({
  name: "createFleetTemplate",
  invoke: () => api.createFleetTemplate({
    name: "edge baseline",
    description: "local template draft",
    scope: "local-appliance",
    labels: ["fleet", "edge"],
    policy: { zones: [{ name: "trust" }, { name: "untrust" }] },
  }),
  method: "POST",
  path: "/v1/fleet/templates",
  body: {
    name: "edge baseline",
    description: "local template draft",
    scope: "local-appliance",
    labels: ["fleet", "edge"],
    policy: { zones: [{ name: "trust" }, { name: "untrust" }] },
  },
});

await assertApiContract({
  name: "validateFleetTemplate",
  invoke: () => api.validateFleetTemplate("tmpl-edge baseline"),
  method: "POST",
  path: "/v1/fleet/templates/tmpl-edge%20baseline:validate",
  specPath: "/v1/fleet/templates/{id}:validate",
  body: {},
});

await assertApiContract({
  name: "applyPreviewFleetTemplate",
  invoke: () => api.applyPreviewFleetTemplate("tmpl-edge/baseline", { expectedCandidateRevision: "sha256:candidate" }),
  method: "POST",
  path: "/v1/fleet/templates/tmpl-edge%2Fbaseline:apply-preview",
  specPath: "/v1/fleet/templates/{id}:apply-preview",
  body: { expectedCandidateRevision: "sha256:candidate" },
});

await assertApiContract({
  name: "applyPlanFleetTemplate",
  invoke: () => api.applyPlanFleetTemplate("tmpl-edge/baseline", {
    expectedCandidateRevision: "sha256:candidate",
    nodes: [{ id: "fw-peer", runtimeState: "ready", runningVersion: "17", haReady: true }],
  }),
  method: "POST",
  path: "/v1/fleet/templates/tmpl-edge%2Fbaseline:apply-plan",
  specPath: "/v1/fleet/templates/{id}:apply-plan",
  body: {
    expectedCandidateRevision: "sha256:candidate",
    nodes: [{ id: "fw-peer", runtimeState: "ready", runningVersion: "17", haReady: true }],
  },
});

await assertApiContract({
  name: "applyFleetTemplate",
  invoke: () => api.applyFleetTemplate("tmpl-edge/baseline", {
    expectedCandidateRevision: "sha256:candidate",
    comment: "bounded local apply",
    nodes: [{ id: "fw-peer", runtimeState: "ready", runningVersion: "17", haReady: true }],
  }),
  method: "POST",
  path: "/v1/fleet/templates/tmpl-edge%2Fbaseline:apply",
  specPath: "/v1/fleet/templates/{id}:apply",
  body: {
    expectedCandidateRevision: "sha256:candidate",
    comment: "bounded local apply",
    nodes: [{ id: "fw-peer", runtimeState: "ready", runningVersion: "17", haReady: true }],
  },
});

await assertApiContract({
  name: "fleetTemplateResults",
  invoke: () => api.fleetTemplateResults({ templateId: "tmpl-edge/baseline" }),
  method: "GET",
  path: "/v1/fleet/template-results?templateId=tmpl-edge%2Fbaseline",
  specPath: "/v1/fleet/template-results",
});

await assertApiContract({
  name: "stageCandidateFleetTemplate",
  invoke: () => api.stageCandidateFleetTemplate("tmpl-edge/baseline", {
    expectedCandidateRevision: "sha256:candidate",
    comment: "stage local template",
  }),
  method: "POST",
  path: "/v1/fleet/templates/tmpl-edge%2Fbaseline:stage-candidate",
  specPath: "/v1/fleet/templates/{id}:stage-candidate",
  body: {
    expectedCandidateRevision: "sha256:candidate",
    comment: "stage local template",
  },
});

await assertApiContract({
  name: "networkPathProof",
  invoke: () => api.networkPathProof({
    srcIp: "10.99.0.1",
    destIp: "10.99.0.2",
    protocol: "PROTOCOL_UDP",
    destPort: 51820,
    sourceInterface: "wg0",
    tunnel: {
      kind: "wireguard",
      interface: "wg0",
      peer: "laptop",
      peerPublicKey: "pubkey1",
    },
  }),
  method: "POST",
  path: "/v1/system/network-path:prove",
  body: {
    srcIp: "10.99.0.1",
    destIp: "10.99.0.2",
    protocol: "PROTOCOL_UDP",
    destPort: 51820,
    sourceInterface: "wg0",
    tunnel: {
      kind: "wireguard",
      interface: "wg0",
      peer: "laptop",
      peerPublicKey: "pubkey1",
    },
  },
});
for (const snippet of [
  "openngfw.v1.NetworkPathMismatch:",
  "mismatches:",
  "limitations:",
  "cliHandoff:",
  "apiHandoff:",
  "correlation:",
]) {
  assert.ok(specText.includes(snippet), `network path proof OpenAPI response schema missing ${snippet}`);
}

await assertApiContract({
  name: "validateAutomationReplay",
  invoke: () => api.validateAutomationReplay({
    schemaVersion: "phragma.webui.automation-replay-validation-request.v1",
    steps: [
      { method: "GET", path: "/v1/candidate/status" },
      { command: "ngfwctl policy validate" },
    ],
    requireAcknowledgements: true,
    requireCandidateRevision: true,
  }),
  method: "POST",
  path: "/v1/system/automation/replay:validate",
  body: {
    schemaVersion: "phragma.webui.automation-replay-validation-request.v1",
    steps: [
      { method: "GET", path: "/v1/candidate/status" },
      { command: "ngfwctl policy validate" },
    ],
    requireAcknowledgements: true,
    requireCandidateRevision: true,
  },
});

await assertApiContract({
  name: "verifyTelemetryExport",
  invoke: () => api.verifyTelemetryExport({
    exportName: "siem-json",
    type: "TELEMETRY_EXPORT_TYPE_JSON_TCP",
    target: "127.0.0.1:5514",
    reason: "settings telemetry verification",
    ackTestEvent: true,
  }),
  method: "POST",
  path: "/v1/system/telemetry/exports:verify",
  body: {
    exportName: "siem-json",
    type: "TELEMETRY_EXPORT_TYPE_JSON_TCP",
    target: "127.0.0.1:5514",
    reason: "settings telemetry verification",
    ackTestEvent: true,
  },
});

await assertApiContract({
  name: "planPacketCapture",
  invoke: () => api.planPacketCapture({
    interface: "ens5",
    filter: "tcp and port 443",
    durationSeconds: 30,
    packetCount: 900,
    snaplenBytes: 512,
  }),
  method: "POST",
  path: "/v1/system/packet-captures/plan",
  body: {
    interface: "ens5",
    filter: "tcp and port 443",
    durationSeconds: 30,
    packetCount: 900,
    snaplenBytes: 512,
  },
});

await assertApiContract({
  name: "startPacketCapture",
  invoke: () => api.startPacketCapture({
    interface: "ens5",
    filter: "tcp and host 10.0.1.20",
    durationSeconds: 15,
    ackCapture: true,
  }),
  method: "POST",
  path: "/v1/system/packet-captures",
  body: {
    interface: "ens5",
    filter: "tcp and host 10.0.1.20",
    durationSeconds: 15,
    ackCapture: true,
  },
});

await assertApiContract({
  name: "downloadPacketCapture",
  invoke: () => api.downloadPacketCapture("pcap id/with spaces"),
  method: "GET",
  path: "/v1/system/packet-captures/pcap%20id%2Fwith%20spaces/download",
  specPath: "/v1/system/packet-captures/{id}/download",
  binary: true,
});

await assertApiContract({
  name: "setPacketCaptureRetention",
  invoke: () => api.setPacketCaptureRetention("pcap id/with spaces", {
    state: "PACKET_CAPTURE_RETENTION_STATE_RETAINED",
    retainUntil: "2026-07-19T12:00:00Z",
    retentionReason: "incident evidence review",
    caseId: "INC-2026-001",
    ackRetentionChange: true,
  }),
  method: "POST",
  path: "/v1/system/packet-captures/pcap%20id%2Fwith%20spaces:set-retention",
  specPath: "/v1/system/packet-captures/{id}:set-retention",
  body: {
    state: "PACKET_CAPTURE_RETENTION_STATE_RETAINED",
    retainUntil: "2026-07-19T12:00:00Z",
    retentionReason: "incident evidence review",
    caseId: "INC-2026-001",
    ackRetentionChange: true,
  },
});

await assertApiContract({
  name: "alerts",
  invoke: () => api.alerts({
    limit: 25,
    ip: "10.0.1.10",
    protocol: "TCP",
    action: "blocked",
    severity: 2,
    threatSeverity: "high",
    signatureId: 9000001,
    port: 8443,
    since: "2026-06-19T08:00:00Z",
    until: "2026-06-19T09:00:00Z",
    query: "probe",
    flowId: "flow-a",
    pageCursor: "25",
  }),
  method: "GET",
  path: "/v1/alerts?limit=25&ip=10.0.1.10&protocol=TCP&action=blocked&severity=2&threatSeverity=high&signatureId=9000001&port=8443&since=2026-06-19T08%3A00%3A00Z&until=2026-06-19T09%3A00%3A00Z&query=probe&flowId=flow-a&pageCursor=25",
  specPath: "/v1/alerts",
});

await assertApiContract({
  name: "flows",
  invoke: () => api.flows({
    limit: 25,
    ip: "10.0.1.10",
    protocol: "TCP",
    app: "ssl",
    port: 443,
    since: "2026-06-19T08:00:00Z",
    until: "2026-06-19T09:00:00Z",
    query: "app evidence",
    flowId: "flow-a",
    pageCursor: "25",
  }),
  method: "GET",
  path: "/v1/flows?limit=25&ip=10.0.1.10&protocol=TCP&app=ssl&port=443&since=2026-06-19T08%3A00%3A00Z&until=2026-06-19T09%3A00%3A00Z&query=app+evidence&flowId=flow-a&pageCursor=25",
  specPath: "/v1/flows",
});

await assertApiContract({
  name: "sessions",
  invoke: () => api.sessions({
    limit: 50,
    srcIp: "10.0.1.10",
    protocol: "TCP",
    port: 443,
    state: "ESTABLISHED",
    query: "admin api",
    pageCursor: "100",
  }),
  method: "GET",
  path: "/v1/sessions?limit=50&srcIp=10.0.1.10&protocol=TCP&port=443&state=ESTABLISHED&query=admin+api&pageCursor=100",
  specPath: "/v1/sessions",
});

await assertApiContract({
  name: "setCandidateWithRevisionGuard",
  invoke: () => api.setCandidate({
    rules: [{ name: "allow-web", action: "ACTION_ALLOW" }],
  }, "sha256:loaded-candidate"),
  method: "PUT",
  path: "/v1/candidate",
  body: {
    policy: {
      rules: [{ name: "allow-web", action: "ACTION_ALLOW" }],
    },
    expectedCandidateRevision: "sha256:loaded-candidate",
  },
});

await assertApiContract({
  name: "natRulesCandidate",
  invoke: () => api.natRules({ source: "POLICY_SOURCE_CANDIDATE" }),
  method: "GET",
  path: "/v1/policy/nat?source=POLICY_SOURCE_CANDIDATE",
  specPath: "/v1/policy/nat",
});

await assertApiContract({
  name: "upsertCandidateSourceNatById",
  invoke: () => api.upsertCandidateSourceNat({
    id: "snat-lan",
    rule: {
      id: "snat-lan",
      name: "lan-egress-renamed",
      toZone: "wan",
      sourceAddress: "inside-net",
      translatedAddress: "wan-ip",
    },
    expectedCandidateRevision: "sha256:loaded-candidate",
    comment: "rename by durable ID",
  }),
  method: "PUT",
  path: "/v1/candidate/nat/source/by-id/snat-lan",
  specPath: "/v1/candidate/nat/source/by-id/{id}",
  body: {
    id: "snat-lan",
    rule: {
      id: "snat-lan",
      name: "lan-egress-renamed",
      toZone: "wan",
      sourceAddress: "inside-net",
      translatedAddress: "wan-ip",
    },
    expectedCandidateRevision: "sha256:loaded-candidate",
    comment: "rename by durable ID",
  },
});

await assertApiContract({
  name: "deleteCandidateSourceNatByName",
  invoke: () => api.deleteCandidateSourceNat({
    name: "legacy egress",
    expectedCandidateRevision: "sha256:loaded-candidate",
    comment: "remove retired egress",
  }),
  method: "DELETE",
  path: "/v1/candidate/nat/source/legacy%20egress?expectedCandidateRevision=sha256%3Aloaded-candidate&comment=remove+retired+egress",
  specPath: "/v1/candidate/nat/source/{name}",
});

await assertApiContract({
  name: "upsertCandidateDestinationNatByName",
  invoke: () => api.upsertCandidateDestinationNat({
    rule: {
      name: "web-dnat",
      fromZone: "wan",
      service: "https",
      destinationAddress: "public-web",
      translatedAddress: "dmz-web",
      translatedPort: 8443,
    },
    expectedCandidateRevision: "sha256:loaded-candidate",
    comment: "stage published service",
  }),
  method: "PUT",
  path: "/v1/candidate/nat/destination/web-dnat",
  specPath: "/v1/candidate/nat/destination/{rule.name}",
  body: {
    rule: {
      name: "web-dnat",
      fromZone: "wan",
      service: "https",
      destinationAddress: "public-web",
      translatedAddress: "dmz-web",
      translatedPort: 8443,
    },
    expectedCandidateRevision: "sha256:loaded-candidate",
    comment: "stage published service",
  },
});

await assertApiContract({
  name: "deleteCandidateDestinationNatById",
  invoke: () => api.deleteCandidateDestinationNat({
    id: "dnat-web",
    expectedCandidateRevision: "sha256:loaded-candidate",
    reason: "remove retired VIP",
  }),
  method: "DELETE",
  path: "/v1/candidate/nat/destination/by-id/dnat-web?expectedCandidateRevision=sha256%3Aloaded-candidate&reason=remove+retired+VIP",
  specPath: "/v1/candidate/nat/destination/by-id/{id}",
});

await assertApiContract({
  name: "createChangeApproval",
  invoke: () => api.createChangeApproval({
    candidateRevision: "sha256:loaded-candidate",
    comment: "CAB approved maintenance window",
    ackRisk: true,
    ackRuntime: true,
  }),
  method: "POST",
  path: "/v1/change-approvals",
  body: {
    candidateRevision: "sha256:loaded-candidate",
    comment: "CAB approved maintenance window",
    ackRisk: true,
    ackRuntime: true,
  },
});

await assertApiContract({
  name: "changeApprovals",
  invoke: () => api.changeApprovals({
    candidateRevision: "sha256:loaded-candidate",
    includeConsumed: true,
    limit: 10,
  }),
  method: "GET",
  path: "/v1/change-approvals?candidateRevision=sha256%3Aloaded-candidate&includeConsumed=true&limit=10",
  specPath: "/v1/change-approvals",
});

await assertApiContract({
  name: "complianceReports",
  invoke: () => api.complianceReports({ limit: 5 }),
  method: "GET",
  path: "/v1/compliance/reports?limit=5",
  specPath: "/v1/compliance/reports",
});

await assertApiContract({
  name: "complianceReport",
  invoke: () => api.complianceReport("report-20260622T120000Z-abcdef12"),
  method: "GET",
  path: "/v1/compliance/reports/report-20260622T120000Z-abcdef12",
  specPath: "/v1/compliance/reports/{id}",
});

await assertApiContract({
  name: "createComplianceReport",
  invoke: () => api.createComplianceReport({
    profile: "change-control",
    title: "CAB window report",
    auditLimit: 300,
    versionLimit: 100,
    logLimit: 100,
    action: "commit",
    version: "12",
  }),
  method: "POST",
  path: "/v1/compliance/reports",
  body: {
    profile: "change-control",
    title: "CAB window report",
    auditLimit: 300,
    versionLimit: 100,
    logLimit: 100,
    action: "commit",
    version: "12",
  },
});
assertSpecBlockIncludes("/v1/compliance/reports", "POST", [
  "Location:",
  "Path of the created retained compliance report.",
]);

await assertApiContract({
  name: "exportComplianceReport",
  invoke: () => api.exportComplianceReport("report-20260622T120000Z-abcdef12"),
  method: "GET",
  path: "/v1/compliance/reports/report-20260622T120000Z-abcdef12/export",
  specPath: "/v1/compliance/reports/{id}/export",
  binary: true,
});
assertSpecBlockIncludes("/v1/compliance/reports/{id}/export", "GET", [
  "Content-Disposition:",
  "Attachment filename for the exported JSON report.",
  "X-Phragma-Payload-Sha256:",
  "SHA-256 digest of the exported retained compliance report payload.",
  "ETag:",
  "Strong entity tag derived from the exported payload SHA-256 digest.",
]);

await assertApiContract({
  name: "investigationCases",
  invoke: () => api.investigationCases({ state: "open", limit: 10 }),
  method: "GET",
  path: "/v1/investigation/cases?limit=10&state=open",
  specPath: "/v1/investigation/cases",
});

await assertApiContract({
  name: "investigationCase",
  invoke: () => api.investigationCase("case-20260622T120000Z-abcdef12"),
  method: "GET",
  path: "/v1/investigation/cases/case-20260622T120000Z-abcdef12",
  specPath: "/v1/investigation/cases/{id}",
});

await assertApiContract({
  name: "createInvestigationCase",
  invoke: () => api.createInvestigationCase({
    title: "Suspicious flow",
    packet: { kind: "flow", summary: { flowId: "flow-1" } },
    evidence: [{ kind: "flow", title: "Flow tuple" }],
  }),
  method: "POST",
  path: "/v1/investigation/cases",
  body: {
    title: "Suspicious flow",
    packet: { kind: "flow", summary: { flowId: "flow-1" } },
    evidence: [{ kind: "flow", title: "Flow tuple" }],
  },
});
assertSpecBlockIncludes("/v1/investigation/cases", "POST", [
  "Location:",
  "Path of the created retained investigation case.",
]);

await assertApiContract({
  name: "updateInvestigationCase",
  invoke: () => api.updateInvestigationCase("case-20260622T120000Z-abcdef12", {
    state: "resolved",
    resolutionNote: "reviewed",
  }),
  method: "PATCH",
  path: "/v1/investigation/cases/case-20260622T120000Z-abcdef12",
  specPath: "/v1/investigation/cases/{id}",
  body: {
    state: "resolved",
    resolutionNote: "reviewed",
  },
});

await assertApiContract({
  name: "addInvestigationCaseEvidence",
  invoke: () => api.addInvestigationCaseEvidence("case-20260622T120000Z-abcdef12", [
    { kind: "alert", title: "Follow-up alert" },
  ]),
  method: "POST",
  path: "/v1/investigation/cases/case-20260622T120000Z-abcdef12/evidence",
  specPath: "/v1/investigation/cases/{id}/evidence",
  body: {
    evidence: [{ kind: "alert", title: "Follow-up alert" }],
  },
});

assertSpecResponses("/v1/investigation/cases", "GET", ["200", "400", "401", "403", "404", "405", "500"]);
assertSpecResponses("/v1/investigation/cases", "POST", ["201", "400", "401", "403", "404", "405", "500"]);
assertSpecResponses("/v1/investigation/cases/{id}", "GET", ["200", "400", "401", "403", "404", "405", "500"]);
assertSpecResponses("/v1/investigation/cases/{id}", "PATCH", ["200", "400", "401", "403", "404", "405", "500"]);
assertSpecResponses("/v1/investigation/cases/{id}/evidence", "POST", ["200", "400", "401", "403", "404", "405", "413", "500"]);
for (const snippet of [
  "openngfw.v1.InvestigationTargetSummary:",
  "target:",
  "$ref: '#/definitions/openngfw.v1.InvestigationTargetSummary'",
  "routeRedacted:",
]) {
  assert.ok(specText.includes(snippet), `investigation target OpenAPI schema missing ${snippet}`);
}

await assertApiContract({
  name: "createBackupSnapshot",
  invoke: () => api.createBackupSnapshot({
    source: "POLICY_SOURCE_RUNNING",
    comment: "pre-maintenance recovery point",
  }),
  method: "POST",
  path: "/v1/backup/snapshots",
  body: {
    source: "POLICY_SOURCE_RUNNING",
    comment: "pre-maintenance recovery point",
  },
});

await assertApiContract({
  name: "backupSnapshots",
  invoke: () => api.backupSnapshots(25),
  method: "GET",
  path: "/v1/backup/snapshots?limit=25",
  specPath: "/v1/backup/snapshots",
});

await assertApiContract({
  name: "backupSnapshot",
  invoke: () => api.backupSnapshot("snap-7"),
  method: "GET",
  path: "/v1/backup/snapshots/snap-7",
  specPath: "/v1/backup/snapshots/{id}",
});

await assertApiContract({
  name: "validateBackupSnapshot",
  invoke: () => api.validateBackupSnapshot("snap-7"),
  method: "POST",
  path: "/v1/backup/snapshots/snap-7:validate",
  body: {},
  specPath: "/v1/backup/snapshots/{id}:validate",
});

await assertApiContract({
  name: "previewBackupSnapshotRestore",
  invoke: () => api.previewBackupSnapshotRestore("snap-7", {
    comment: "restore candidate for CAB review",
    stageCandidate: true,
    expectedCandidateRevision: "sha256:loaded-candidate",
  }),
  method: "POST",
  path: "/v1/backup/snapshots/snap-7:restore-preview",
  body: {
    comment: "restore candidate for CAB review",
    stageCandidate: true,
    expectedCandidateRevision: "sha256:loaded-candidate",
  },
  specPath: "/v1/backup/snapshots/{id}:restore-preview",
});

await assertApiContract({
  name: "commitWithApproval",
  invoke: () => api.commit("approved maintenance", true, true, "7", "sha256:reviewed-candidate"),
  method: "POST",
  path: "/v1/commit",
  stepUpAction: "commit",
  stepUpComment: "approved maintenance",
  body: {
    comment: "approved maintenance",
    ackRisk: true,
    ackRuntime: true,
    approvalId: "7",
    reviewedCandidateRevision: "sha256:reviewed-candidate",
  },
});

await assertApiContract({
  name: "appIdObservations",
  invoke: () => api.appIdObservations({
    limit: 75,
    flowLimit: 1000,
    confidenceThreshold: 65,
    query: "unknown ssl",
    kind: "APP_ID_OBSERVATION_KIND_UNKNOWN",
    engineSignal: "ssl",
    protocol: "TCP",
    port: 8443,
    pageCursor: "200",
  }),
  method: "GET",
  path: "/v1/app-id/observations?limit=75&flowLimit=1000&confidenceThreshold=65&query=unknown+ssl&kind=APP_ID_OBSERVATION_KIND_UNKNOWN&engineSignal=ssl&protocol=TCP&port=8443&pageCursor=200",
  specPath: "/v1/app-id/observations",
});

await assertApiContract({
  name: "stageAppIdRegressionSample",
  invoke: () => api.stageAppIdRegressionSample("qid-1", {
    reason: "reviewed capture",
    pcapSha256: "a".repeat(64),
    expectedApp: "corp-admin",
  }),
  method: "POST",
  path: "/v1/app-id/observations/qid-1:stage-regression-sample",
  specPath: "/v1/app-id/observations/{queueId}:stage-regression-sample",
  body: {
    reason: "reviewed capture",
    pcapSha256: "a".repeat(64),
    expectedApp: "corp-admin",
  },
});

await assertApiContract({
  name: "compareAppIdReplay",
  invoke: () => api.compareAppIdReplay({
    queueId: "qid-1",
    expectedApp: "corp-admin",
    flowLimit: 1000,
    confidenceThreshold: 65,
  }),
  method: "POST",
  path: "/v1/app-id/replay:compare",
  specPath: "/v1/app-id/replay:compare",
  body: {
    queueId: "qid-1",
    expectedApp: "corp-admin",
    flowLimit: 1000,
    confidenceThreshold: 65,
  },
});

await assertApiContract({
  name: "stageAppIdObservation",
  invoke: () => api.stageAppIdObservation("qid/with spaces", {
    mode: "APP_ID_OBSERVATION_STAGE_MODE_DEFINE_AND_RULE",
    reason: "reviewed App-ID observation",
    applicationOverride: {
      name: "corp-admin",
      category: "business",
      risk: "APPLICATION_RISK_MEDIUM",
    },
  }),
  method: "POST",
  path: "/v1/app-id/observations/qid%2Fwith%20spaces:stage",
  specPath: "/v1/app-id/observations/{queueId}:stage",
  body: {
    mode: "APP_ID_OBSERVATION_STAGE_MODE_DEFINE_AND_RULE",
    reason: "reviewed App-ID observation",
    applicationOverride: {
      name: "corp-admin",
      category: "business",
      risk: "APPLICATION_RISK_MEDIUM",
    },
  },
});

await assertApiContract({
  name: "threatExceptions",
  invoke: () => api.threatExceptions({ source: "POLICY_SOURCE_CANDIDATE", version: 7 }),
  method: "GET",
  path: "/v1/threat-exceptions?source=POLICY_SOURCE_CANDIDATE&version=7",
  specPath: "/v1/threat-exceptions",
});

await assertApiContract({
  name: "stageThreatException",
  invoke: () => api.stageThreatException({
    name: "fp-9000001-source",
    reason: "known false positive",
    scope: "THREAT_EXCEPTION_SCOPE_SOURCE",
    sourceIp: "10.0.1.10",
    engineSignals: [{ engine: "suricata", kind: "signature_id", value: "9000001" }],
  }),
  method: "POST",
  path: "/v1/threat-exceptions:stage",
  body: {
    name: "fp-9000001-source",
    reason: "known false positive",
    scope: "THREAT_EXCEPTION_SCOPE_SOURCE",
    sourceIp: "10.0.1.10",
    engineSignals: [{ engine: "suricata", kind: "signature_id", value: "9000001" }],
  },
});

await assertApiContract({
  name: "updateThreatException",
  invoke: () => api.updateThreatException("fp/name 1", {
    exception: { name: "fp-name-1", signatureId: 9000001, sourceAddress: "client-net", description: "updated reason" },
    reason: "ticket sec-123",
    confirmGlobal: false,
  }),
  method: "PATCH",
  path: "/v1/threat-exceptions/fp%2Fname%201",
  body: {
    exception: { name: "fp-name-1", signatureId: 9000001, sourceAddress: "client-net", description: "updated reason" },
    reason: "ticket sec-123",
    confirmGlobal: false,
  },
  specPath: "/v1/threat-exceptions/{name}",
});

await assertApiContract({
  name: "setThreatExceptionState",
  invoke: () => api.setThreatExceptionState("fp/name 1", {
    disabled: true,
    reason: "disable while package is tested",
    confirmGlobal: false,
  }),
  method: "POST",
  path: "/v1/threat-exceptions/fp%2Fname%201:set-state",
  body: {
    disabled: true,
    reason: "disable while package is tested",
    confirmGlobal: false,
  },
  specPath: "/v1/threat-exceptions/{name}:set-state",
});

await assertApiContract({
  name: "removeThreatException",
  invoke: () => api.removeThreatException("fp/name 1", "package fixed false positive"),
  method: "POST",
  path: "/v1/threat-exceptions/fp%2Fname%201:remove",
  body: { reason: "package fixed false positive" },
  specPath: "/v1/threat-exceptions/{name}:remove",
});

await assertApiContract({
  name: "replayThreatEvidence",
  invoke: () => api.replayThreatEvidence({
    recentAlerts: {
      limit: 10,
      query: "exploit",
      signatureId: 9000001,
      action: "blocked",
    },
  }),
  method: "POST",
  path: "/v1/threat-id/replay:check",
  body: {
    recentAlerts: {
      limit: 10,
      query: "exploit",
      signatureId: 9000001,
      action: "blocked",
    },
  },
});

await assertApiContract({
  name: "explainFlow",
  invoke: () => api.explainFlow({
    source: "POLICY_SOURCE_RUNNING",
    flow: {
      srcIp: "10.0.1.20",
      destIp: "10.0.2.20",
      protocol: "TCP",
      destPort: 443,
    },
  }),
  method: "POST",
  path: "/v1/explain/flow",
  body: {
    source: "POLICY_SOURCE_RUNNING",
    flow: {
      srcIp: "10.0.1.20",
      destIp: "10.0.2.20",
      protocol: "TCP",
      destPort: 443,
    },
  },
});

await assertApiContract({
  name: "contentEvidence",
  invoke: () => api.contentEvidence("app/id", "pcap regression"),
  method: "GET",
  path: "/v1/intel/content/packages/app%2Fid/evidence/pcap%20regression",
  specPath: "/v1/intel/content/packages/{kind}/evidence/{evidenceType}",
});

await assertApiContract({
  name: "installContentPackage",
  invoke: () => api.installContentPackage("app/id", "/tmp/content app-id"),
  method: "POST",
  path: "/v1/intel/content/packages/app%2Fid/install",
  stepUpAction: "content-package-install",
  stepUpComment: "Install app/id content package",
  body: { sourcePath: "/tmp/content app-id" },
  specPath: "/v1/intel/content/packages/{kind}/install",
});

await assertApiContract({
  name: "previewContentPackage",
  invoke: () => api.previewContentPackage("app/id", "/tmp/content app-id"),
  method: "POST",
  path: "/v1/intel/content/packages/app%2Fid/preview",
  body: { sourcePath: "/tmp/content app-id" },
  specPath: "/v1/intel/content/packages/{kind}/preview",
});

await assertApiContract({
  name: "rollbackContentPackage",
  invoke: () => api.rollbackContentPackage("threat id"),
  method: "POST",
  path: "/v1/intel/content/packages/threat%20id/rollback",
  stepUpAction: "content-package-rollback",
  stepUpComment: "Rollback threat id content package",
  body: { ackRollback: true },
  specPath: "/v1/intel/content/packages/{kind}/rollback",
});

await assertApiContract({
  name: "revokeAccessSession",
  invoke: () => api.revokeAccessSession("session/id 1"),
  method: "POST",
  path: "/v1/system/access-administration/sessions/session%2Fid%201:revoke",
  body: { ackRevokeSession: true },
  specPath: "/v1/system/access-administration/sessions/{sessionId}:revoke",
});

await assertApiContract({
  name: "oidcPreflight",
  invoke: () => api.oidcPreflight(),
  method: "POST",
  path: "/v1/system/access-administration/oidc:preflight",
  body: {},
});

await assertApiContract({
  name: "logout",
  invoke: () => api.logout(),
  method: "POST",
  path: "/v1/auth/logout",
});
