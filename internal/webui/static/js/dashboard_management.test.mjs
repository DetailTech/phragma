import assert from "node:assert/strict";

class FakeElement {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.style = {};
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }
}

globalThis.document = {
  documentElement: new FakeElement("html"),
  head: new FakeElement("head"),
  createElement: (tag) => new FakeElement(tag),
};
globalThis.getComputedStyle = () => ({
  getPropertyValue: () => "",
});

const {
  dashboardAlertKey,
  dashboardAppSummary,
  dashboardAuditHash,
  dashboardCandidateStatusModel,
  dashboardEngineActionLinks,
  dashboardHash,
  dashboardReleaseGateHash,
  dashboardReleaseReadinessModel,
  dashboardRulesRemediationHash,
  dashboardThreatSeverity,
  dashboardThreatHash,
  dashboardThreatSummary,
  dashboardTelemetryScopeModel,
  dashboardTrafficHash,
  dashboardTroubleshootCompareHash,
  managementPlaneSummary,
} = await import("./views/dashboard.js");

{
  const summary = managementPlaneSummary({
    runtime: { dryRun: false, authEnabled: true, tlsEnabled: true },
    management: {
      rateLimitEnabled: true,
      rateLimitRequestsPerMinute: 600,
      rateLimitBurst: 120,
      rateLimitClientIdentity: "rightmost-untrusted-x-forwarded-for",
      trustedProxyCidrs: ["10.0.0.0/8"],
    },
  }, { actor: "alice", role: "admin", authSource: "local-users-file" });
  assert.equal(summary.cls, "ok");
  assert.match(summary.title, /controls are active/);
  assert.match(summary.detail, /alice \(admin, local-users-file\)/);
  assert.match(summary.detail, /Production certification still depends on the hardening pass/);
}

{
  const summary = managementPlaneSummary({
    runtime: { dryRun: true, authEnabled: false, tlsEnabled: true },
    management: {
      rateLimitEnabled: true,
      rateLimitRequestsPerMinute: 600,
      rateLimitBurst: 120,
      rateLimitClientIdentity: "socket-peer",
      trustedProxyCidrs: [],
    },
  }, {});
  assert.equal(summary.cls, "bad");
  assert.match(summary.detail, /dry-run mode/);
  assert.match(summary.detail, /auth disabled/);
  assert.match(summary.detail, /socket-peer client identity/);
  assert.match(summary.detail, /local admin/);
}

{
  const summary = managementPlaneSummary({
    runtime: { dryRun: false, authEnabled: true, tlsEnabled: true },
    management: {
      rateLimitEnabled: false,
      rateLimitClientIdentity: "rightmost-untrusted-x-forwarded-for",
      trustedProxyCidrs: ["10.0.0.0/8"],
    },
  }, { actor: "bob", role: "operator", authSource: "oidc-session" });
  assert.equal(summary.cls, "warn");
  assert.match(summary.detail, /rate limiting disabled/);
  assert.match(summary.detail, /bob \(operator, oidc-session\)/);
}

{
  assert.equal(dashboardHash("/traffic", { mode: "flows", ip: "10.0.0.5" }), "#/traffic?mode=flows&ip=10.0.0.5");
  assert.equal(dashboardTrafficHash({ app: "TLS" }), "#/traffic?mode=flows&app=TLS");
  assert.equal(dashboardThreatHash({ sev: 2, alert: "flow:abc" }), "#/threats?sev=2&alert=flow%3Aabc");
  assert.equal(dashboardAuditHash({ version: 12 }), "#/changes?tab=audit&limit=300&version=12");
  assert.equal(dashboardReleaseGateHash(), "#/readiness?drawer=release-acceptance");
  assert.equal(dashboardReleaseGateHash("proto-verify"), "#/readiness?packet=proto-verify");
  assert.equal(dashboardRulesRemediationHash(), "#/rules?changed=1&density=compact");
  assert.equal(dashboardTroubleshootCompareHash(), "#/troubleshoot?intent=compare&run=1");
}

{
  const limited = dashboardTelemetryScopeModel(
    { alerts: [{ id: "a1" }, { id: "a2" }], totalMatches: 12, hasMore: true },
    { flows: [{ id: "f1" }], totalMatches: 1, hasMore: false },
  );
  assert.equal(limited.limited, true);
  assert.equal(limited.alertFoot, "2/12 shown");
  assert.equal(limited.flowFoot, "1 shown");
  assert.match(limited.detail, /first page only/);
  assert.match(limited.detail, /Open Traffic or Threats/);

  const complete = dashboardTelemetryScopeModel(
    { alerts: [{ id: "a1" }], totalMatches: 1 },
    { flows: [{ id: "f1" }, { id: "f2" }], totalMatches: 2 },
  );
  assert.equal(complete.limited, false);
  assert.equal(complete.alertFoot, "1 shown");
  assert.equal(complete.flowFoot, "2 shown");
  assert.match(complete.detail, /current result set/);

  const snakeCaseLimited = dashboardTelemetryScopeModel(
    { alerts: [{ id: "a1" }, { id: "a2" }], total_matches: 5, has_more: false },
    { flows: [{ id: "f1" }], total_matches: 1 },
  );
  assert.equal(snakeCaseLimited.limited, true);
  assert.equal(snakeCaseLimited.alertFoot, "2/5 shown");
  assert.match(snakeCaseLimited.detail, /first page only/);
}

{
  const suricata = dashboardEngineActionLinks({ name: "suricata", state: "failed", detail: "eve socket unavailable" });
  assert.deepEqual(suricata.map((link) => link.id), ["readiness", "inspection", "logs"]);
  assert.equal(suricata.find((link) => link.id === "inspection").href, "#/inspection?engine=suricata&state=failed");
  assert.equal(suricata.find((link) => link.id === "logs").href, "#/logs?source=engine&engine=suricata&severity=error&q=eve+socket+unavailable");

  const frr = dashboardEngineActionLinks({ name: "frr-bgp", state: "restarting", detail: "peer session down" });
  assert.deepEqual(frr.map((link) => link.id), ["readiness", "netvpn", "logs"]);
  assert.equal(frr.find((link) => link.id === "netvpn").href, "#/netvpn?drawer=runtime-review&engine=frr-bgp");

  const unknown = dashboardEngineActionLinks({ name: "collector", state: "missing-prerequisites", detail: "binary missing" });
  assert.deepEqual(unknown.map((link) => link.id), ["readiness", "troubleshoot", "logs"]);
  assert.equal(unknown.find((link) => link.id === "troubleshoot").href, "#/troubleshoot?intent=runtime&run=1&engine=collector");
}

{
  assert.equal(dashboardAlertKey({ flowId: "abc123" }), "flow:abc123");
  assert.equal(dashboardAlertKey({
    signatureId: 42,
    srcIp: "10.0.0.5",
    srcPort: 55123,
    destIp: "10.0.0.10",
    destPort: 443,
    time: "2026-06-18T10:00:00Z",
  }), "sid:42:10.0.0.5:55123:10.0.0.10:443:2026-06-18T10:00:00Z");
  assert.equal(dashboardAlertKey({ signatureId: 0 }), "");
}

{
  const summary = dashboardAppSummary({
    appId: "web-browsing",
    appName: "Web browsing",
    appProtocol: "tls",
    protocol: "TCP",
  });
  assert.equal(summary.appId, "web-browsing");
  assert.equal(summary.label, "web-browsing");
  assert.deepEqual(summary.evidence, ["Web browsing", "signal tls", "TCP"]);

  const fallback = dashboardAppSummary({ appProtocol: "dns", protocol: "UDP" });
  assert.equal(fallback.appId, "dns");
  assert.equal(fallback.label, "DNS");
  assert.deepEqual(fallback.evidence, ["UDP"]);
}

{
  const canonical = dashboardThreatSeverity({ threatSeverity: "critical", severity: 3 });
  assert.equal(canonical.label, "Critical");
  assert.equal(canonical.n, 1);
  assert.equal(canonical.cls, "bad");

  const fallback = dashboardThreatSeverity({ severity: 2 });
  assert.equal(fallback.label, "High");
  assert.equal(fallback.n, 2);
}

{
  const summary = dashboardThreatSummary({
    threatId: "phragma.web.shell",
    threatName: "Web shell attempt",
    signatureId: 900001,
    signature: "ET WEB_SERVER Possible shell",
    threatCategory: "web-exploit",
    threatConfidence: 91,
    category: "attempted-admin",
    protocol: "TCP",
  });
  assert.equal(summary.label, "Web shell attempt");
  assert.deepEqual(summary.evidence, [
    "phragma.web.shell",
    "ET WEB_SERVER Possible shell",
    "SID 900001",
    "web-exploit",
    "confidence 91%",
    "attempted-admin",
    "TCP",
  ]);
}

{
  const candidate = dashboardCandidateStatusModel({ hasCandidate: true, dirty: true, changeCount: 2, runningVersion: 7 });
  assert.equal(candidate.dirty, true);
  assert.equal(candidate.changeCount, 2);
  assert.match(candidate.label, /2 pending changes/);
  assert.match(candidate.detail, /before release evidence is recorded/);

  const clean = dashboardCandidateStatusModel({ hasCandidate: false, dirty: false, runningVersion: 8 });
  assert.equal(clean.dirty, false);
  assert.match(clean.detail, /running policy v8/);

  const unavailable = dashboardCandidateStatusModel({}, true);
  assert.equal(unavailable.unavailable, true);
  assert.equal(unavailable.label, "candidate unavailable");
}

{
  const model = dashboardReleaseReadinessModel({
    state: "blocked",
    ready: false,
    manifestPresent: true,
    generatedAt: "2026-06-20T15:00:00Z",
    summary: { passed: 4, recorded: 1, missing: 2, invalid: 1, notApplicable: 1, todo: 3 },
    checks: [
      { name: "proto-verify", state: "passed" },
      { name: "m3-field-evidence", state: "missing", detail: "server path /tmp/secret should not be surfaced", nextAction: "Run a command with arguments that stay in Readiness.", nextCommand: ["make", "m3-field-evidence"] },
    ],
    problems: ["do not render this detailed problem on Dashboard"],
  }, { hasCandidate: true, dirty: true, changeCount: 1 });
  assert.equal(model.stateLabel, "blocked");
  assert.equal(model.cls, "bad");
  assert.equal(model.summary.missing, 2);
  assert.equal(model.summary.notApplicable, 1);
  assert.equal(model.firstGate.id, "m3-field-evidence");
  assert.equal(model.firstGate.href, "#/readiness?packet=m3-field-evidence");
  assert.doesNotMatch(model.firstGate.detail, /\/tmp\/secret|make|arguments/);
  assert.equal(model.candidate.dirty, true);
  assert.equal(model.rulesHref, "#/rules?changed=1&density=compact");
  assert.equal(model.compareHref, "#/troubleshoot?intent=compare&run=1");
}

{
  const model = dashboardReleaseReadinessModel({
    state: "evidence-pending-manifest",
    ready: false,
    manifestPresent: false,
    summary: { passed: 0, recorded: 15, missing: 0, invalid: 0, notApplicable: 0, todo: 0 },
    checks: [{ name: "proto-verify", state: "recorded" }],
    problems: ["release acceptance manifest release/acceptance.json is missing"],
  }, { hasCandidate: false, dirty: false, runningVersion: 9 });
  assert.equal(model.stateLabel, "evidence-pending-manifest");
  assert.equal(model.cls, "warn");
  assert.match(model.title, /manifest assembly is pending/);
  assert.match(model.detail, /All required evidence is recorded/);
  assert.equal(model.firstGate.id, "proto-verify");
  assert.equal(model.firstGate.state, "pending manifest");
  assert.equal(model.firstGate.href, "#/readiness?packet=proto-verify");
  assert.equal(model.candidate.dirty, false);
}

{
  const model = dashboardReleaseReadinessModel({
    state: "unavailable",
    ready: false,
    manifestPresent: false,
    summary: { passed: 0, recorded: 0, missing: 0, invalid: 0, notApplicable: 0, todo: 0 },
    problems: ["HTTP 500 /server/local/path"],
    checks: [],
  }, {}, true);
  assert.equal(model.stateLabel, "unavailable");
  assert.equal(model.cls, "warn");
  assert.match(model.detail, /could not be loaded/);
  assert.doesNotMatch(model.detail, /\/server\/local\/path/);
  assert.equal(model.firstGate, null);
  assert.equal(model.candidate.unavailable, true);
}
