import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { ApiError, api } from "./api.js";
import { buildEbpfDrillEvidencePacket, releaseEvidencePacketDefinition } from "./readiness_model.js";
import { supportBundlePreviewReport } from "./support_bundle.js";
import { classifyReleaseArtifactEvidenceBoundary, collectSupportBundle, ENGINE_READINESS_COLUMNS, engineReadinessRowModel, haFailoverActivationActionState, haFailoverPacketBoundaryModel, haOperationsCockpitModel, haOperationsCockpitReport, haPolicyPullActionState, hostTuningActionState, normalizeReadinessRouteState, proxyGatewayPosture, readinessRouteDrawerKey, redactReadinessDisclosureText, releaseAcceptanceAggregateSummary, releaseAcceptanceFromResult, releaseAcceptanceStatusReport, releaseAcceptanceStatusSummaryReport, releaseAcceptanceStatusViewModel, releaseArtifactCustodyBoundary, releaseEvidencePacketText, routingVpnPostureModel, shouldClearReadinessRouteOnClose, supportBundleErrorModel } from "./views/readiness.js";

const readinessViewSource = readFileSync(new URL("./views/readiness.js", import.meta.url), "utf8");
assert.match(readinessViewSource, /import \{[^}]*pinInvestigationPacket[^}]*\} from "\.\.\/investigation_case\.js";/);
assert.match(readinessViewSource, /appendInvestigationPacketToActiveServerCase/);
assert.match(readinessViewSource, /activeInvestigationServerCaseHref/);
assert.match(readinessViewSource, /api\.addInvestigationCaseEvidence\(id, evidence\)/);
assert.match(readinessViewSource, /Local browser-only fallback was used/);
assert.match(readinessViewSource, /function systemInvestigationHandoffPacket/);
assert.match(readinessViewSource, /function haInvestigationHandoffPacket/);
assert.match(readinessViewSource, /function pinSystemEvidencePacket/);
assert.match(readinessViewSource, /function pinHAEvidencePacket/);
assert.match(readinessViewSource, /#\/readiness\?drawer=system/);
assert.match(readinessViewSource, /#\/readiness\?drawer=ha/);
assert.match(readinessViewSource, /#\/readiness\?drawer=ebpf-drill/);
assert.match(readinessViewSource, /Pin to case/);
assert.match(readinessViewSource, /Open active case/);
assert.match(readinessViewSource, /function releaseEvidenceInlineDetails/);
assert.match(readinessViewSource, /dataset: \{ releaseEvidenceDetail: item\.id \|\| "" \}/);
assert.match(readinessViewSource, /Evidence details/);
assert.match(readinessViewSource, /releaseEvidenceCommandRow\(command\.role, command\.command\)/);
assert.match(readinessViewSource, /function readinessCommandCopyButton/);
assert.match(readinessViewSource, /type: "button"/);
assert.match(readinessViewSource, /"aria-label": copyLabel/);
assert.match(readinessViewSource, /ariaLabel: `Copy \$\{role\.toLowerCase\(\)\} command for \$\{checkName \|\| "release acceptance"\}`/);
assert.match(readinessViewSource, /ariaLabel: `Copy \$\{label\.toLowerCase\(\)\} release evidence command`/);
assert.match(readinessViewSource, /ariaLabel: `Copy \$\{label\.toLowerCase\(\)\} host tuning command`/);
assert.match(readinessViewSource, /releaseAcceptanceCommandCopy/);
assert.match(readinessViewSource, /releaseEvidenceCommandCopy/);
assert.match(readinessViewSource, /function releaseEvidenceInvestigationHandoffPacket/);
assert.match(readinessViewSource, /readinessActionAttrs\("pin-release-evidence-packet", "Pin release evidence packet to case", \{ releaseEvidencePacketAction: "pin"/);
assert.match(readinessViewSource, /readinessActionAttrs\("export-release-evidence-packet", "Export release evidence packet JSON", \{ releaseEvidencePacketAction: "export"/);
assert.match(readinessViewSource, /readinessActionAttrs\("copy-release-evidence-packet", "Copy release evidence packet", \{ releaseEvidencePacketAction: "copy"/);
assert.match(readinessViewSource, /releaseArtifactWorkbenchModel/);
assert.match(readinessViewSource, /function releaseArtifactWorkbench/);
assert.match(readinessViewSource, /dataset: \{ releaseArtifactWorkbench: "true" \}/);
assert.match(readinessViewSource, /Artifact matching workbench/);
assert.match(readinessViewSource, /dataset: \{ releaseArtifactGate: row\.id \|\| "" \}/);
assert.match(readinessViewSource, /dataset: \{ releaseArtifactNextCommand: row\.id \|\| "" \}/);
assert.match(readinessViewSource, /dataset: \{ releaseArtifactAction: "drill"/);
assert.match(readinessViewSource, /dataset: \{ releaseArtifactAction: "copy-command"/);
assert.match(readinessViewSource, /dataset: \{ releaseArtifactAction: "pin-handoff"/);
assert.match(readinessViewSource, /Remote continuation output, templates, and stale artifacts are not accepted-source evidence/);
assert.match(readinessViewSource, /dataset: \{ releaseArtifactEvidenceClass: row\.id \|\| "" \}/);
assert.match(readinessViewSource, /dataset: \{ releaseArtifactCustody: row\.id \|\| "" \}/);
assert.match(readinessViewSource, /signing\/custody hardening/);
assert.match(readinessViewSource, /pinReleaseEvidencePacket\(releaseEvidenceInvestigationHandoffPacket\(item\)\)/);
assert.match(readinessViewSource, /function releaseEvidencePacketCurrentGap/);
assert.match(readinessViewSource, /dataset: \{ releaseEvidenceCurrentGap: item\.id \|\| "" \}/);
assert.match(readinessViewSource, /releaseEvidencePacketRoute\(item\)/);
assert.match(readinessViewSource, /releaseEvidenceOperatorRoute/);
assert.match(readinessViewSource, /releaseAcceptancePacketLink/);
assert.match(readinessViewSource, /#\/readiness\?packet=\$\{encodeURIComponent\(packet\)\}/);
assert.match(readinessViewSource, /releaseAcceptanceOmittedCommandGuidance/);
assert.match(readinessViewSource, /Next commands for omitted checks/);
assert.match(readinessViewSource, /"webui-enterprise-smoke": \[/);
assert.match(readinessViewSource, /make webui-enterprise-smoke/);
assert.match(readinessViewSource, /release-evidence-webui-enterprise-smoke/);
assert.match(readinessViewSource, /releaseEvidencePacketBoundary/);
assert.match(readinessViewSource, /They do not record durable release evidence, assemble a manifest, or make a release gate pass/);
assert.match(readinessViewSource, /durableEvidenceRecorded: false/);
assert.match(readinessViewSource, /function releaseEvidencePacketDisclosureItem/);
assert.match(readinessViewSource, /redactReadinessDisclosureText\(releaseEvidenceReport\(items\)\)/);
assert.match(readinessViewSource, /readinessTuningCommandCopy/);
assert.match(readinessViewSource, /readinessRoutingVpnPosture/);
assert.match(readinessViewSource, /readinessRoutingVpnAction/);
assert.match(readinessViewSource, /Open Routing & VPN/);
assert.match(readinessViewSource, /readinessEbpfEvidenceAction: "drill-handoff"/);
assert.match(readinessViewSource, /readinessEbpfDrillAction: "copy"/);
assert.match(readinessViewSource, /readinessEbpfDrillAction: "export"/);
assert.match(readinessViewSource, /readinessEbpfDrillAction: "pin"/);
assert.match(readinessViewSource, /phragma\.ebpf\.drill-evidence\.v1/);
assert.match(readinessViewSource, /dataset: \{ haPolicyPullField: "comment" \}/);
assert.match(readinessViewSource, /dataset: \{ haPolicyPullAck: "risk" \}/);
assert.match(readinessViewSource, /dataset: \{ haPolicyPullAck: "runtime" \}/);
assert.match(readinessViewSource, /dataset: \{ haPolicyPullSubmit: "resync" \}/);
assert.match(readinessViewSource, /dataset: \{ haFailoverField: "comment" \}/);
assert.match(readinessViewSource, /dataset: \{ haFailoverAck: "failover" \}/);
assert.match(readinessViewSource, /dataset: \{ haFailoverAck: "external-cutover" \}/);
assert.match(readinessViewSource, /dataset: \{ haFailoverAck: "external-fencing" \}/);
assert.match(readinessViewSource, /dataset: \{ haFailoverSubmit: "activate" \}/);
assert.match(readinessViewSource, /dataset: \{ readinessHaPacketBoundary: "true" \}/);
assert.match(readinessViewSource, /dataset: \{ readinessHaOperationsBoundary: "true" \}/);
assert.match(readinessViewSource, /function haInvestigationHandoffPacket/);
assert.match(readinessViewSource, /packetBoundary: boundary/);
assert.match(readinessViewSource, /openReleaseEvidencePacket\(item, \{ routeBacked: `packet:\$\{routeState\.packet\}` \}\)/);
assert.doesNotMatch(readinessViewSource, /routeBacked: desired/);

const readinessModelSource = readFileSync(new URL("./readiness_model.js", import.meta.url), "utf8");
assert.match(readinessModelSource, /const RELEASE_BENCHMARK_PACKET = evidencePacket/);
assert.match(readinessModelSource, /releaseChecklistItemFromGate\("release-benchmark", "Performance benchmark release gate"/);

const SUPPORT_BUNDLE_LIMITS = Object.freeze({ versionLimit: 100, auditLimit: 300, eventLimit: 500 });
const FALLBACK_CALL_NAMES = Object.freeze([
  "running",
  "candidate",
  "status",
  "highAvailabilityStatus",
  "telemetryExportStatus",
  "identity",
  "candidateStatus",
  "validate",
  "runtimeReadinessPreflight",
  "versions",
  "audit",
  "auditVerify",
  "alerts",
  "flows",
  "sessions",
  "feeds",
  "contentPackages",
  "releaseAcceptanceStatus",
]);
const originalApi = Object.fromEntries(Object.entries(api));

async function withMockedApi(fn) {
  try {
    await fn();
  } finally {
    Object.assign(api, originalApi);
  }
}

function record(calls, name, args, value) {
  calls.push({ name, args });
  return value;
}

function installFailingFallback(calls) {
  for (const name of FALLBACK_CALL_NAMES) {
    api[name] = async (...args) => {
      calls.push({ name, args });
      throw new Error(`${name} fallback should not be called`);
    };
  }
}

function installBrowserFallback(calls) {
  api.status = async (...args) => record(calls, "status", args, { runtime: { version: "fallback-runtime" }, engines: [] });
  api.highAvailabilityStatus = async (...args) => record(calls, "highAvailabilityStatus", args, {
    schemaVersion: "phragma.ha.status.v1",
    status: { state: "standalone", mode: "standalone", role: "standalone" },
  });
  api.telemetryExportStatus = async (...args) => record(calls, "telemetryExportStatus", args, {
    schemaVersion: "phragma.telemetry.export.status.v1",
    state: "disabled",
    telemetryEnabled: false,
    vector: { state: "unknown" },
    exports: [],
  });
  api.identity = async (...args) => record(calls, "identity", args, { actor: "operator", role: "admin" });
  api.running = async (...args) => record(calls, "running", args, { version: 42, policy: { rules: [] } });
  api.candidate = async (...args) => {
    calls.push({ name: "candidate", args });
    throw new ApiError(404, "candidate not found", {});
  };
  api.candidateStatus = async (...args) => record(calls, "candidateStatus", args, { hasCandidate: false, dirty: false, runningVersion: 42 });
  api.validate = async (...args) => {
    calls.push({ name: "validate", args });
    throw new ApiError(404, "candidate not found", {});
  };
  api.runtimeReadinessPreflight = async (...args) => record(calls, "runtimeReadinessPreflight", args, {
    schemaVersion: "phragma.runtime-readiness.v1",
    operation: "commit",
    label: "No runtime warnings",
    requiresAck: false,
    items: [],
  });
  api.versions = async (...args) => record(calls, "versions", args, { versions: [{ version: 42 }] });
  api.audit = async (...args) => record(calls, "audit", args, { entries: [] });
  api.auditVerify = async (...args) => record(calls, "auditVerify", args, { ok: true, entryCount: 0 });
  api.alerts = async (...args) => record(calls, "alerts", args, { alerts: [] });
  api.flows = async (...args) => record(calls, "flows", args, { flows: [] });
  api.sessions = async (...args) => record(calls, "sessions", args, { sessions: [] });
  api.feeds = async (...args) => record(calls, "feeds", args, { feeds: [] });
  api.contentPackages = async (...args) => record(calls, "contentPackages", args, { packages: [] });
  api.releaseAcceptanceStatus = async (...args) => record(calls, "releaseAcceptanceStatus", args, { state: "ready", ready: true });
}

function callNames(calls) {
  return calls.map((call) => call.name);
}

{
  const emptyProxy = proxyGatewayPosture({});
  assert.equal(emptyProxy.label, "not configured");
  assert.equal(emptyProxy.hasPolicy, false);

  const plannedProxy = proxyGatewayPosture({
    proxy: {
      wafPolicies: [{
        name: "corp-waf",
        mode: "WAF_MODE_BLOCK",
        redactRequestBody: true,
        ruleSets: [{ name: "crs", version: "4.0.0", source: "owasp-crs", sha256: "a".repeat(64) }],
      }],
      virtualServices: [{
        name: "admin-api",
        enabled: true,
        hostnames: ["admin.example.com"],
        routes: [{
          name: "api",
          pathPrefix: "/api",
          wafPolicy: "corp-waf",
          requireMtlsToBackend: true,
          backends: [{ name: "api-1", url: "https://api.internal", weight: 100 }],
        }],
      }],
    },
  });
  assert.equal(plannedProxy.label, "planned");
  assert.equal(plannedProxy.enabledCount, 1);
  assert.equal(plannedProxy.wafs.length, 1);
  assert.equal(plannedProxy.routes.length, 1);
  assert.ok(plannedProxy.runtimeReadinessArtifacts.some((item) => /planned-not-executed runtime-readiness evidence/.test(item)));
  assert.ok(plannedProxy.blockers.some((item) => /Active Envoy\/Coraza listener execution remains hardening/.test(item)));
  assert.ok(plannedProxy.blockers.some((item) => /Traffic cutover execution remains hardening/.test(item)));
  assert.ok(!plannedProxy.blockers.some((item) => /traffic rollout is not implemented/.test(item)));

  const unsafeProxy = proxyGatewayPosture({
    proxy: {
      wafPolicies: [{ name: "loose-waf", mode: "WAF_MODE_DETECT", redactRequestBody: false, ruleSets: [] }],
      virtualServices: [{ name: "portal", enabled: true, routes: [{ name: "root", pathPrefix: "/", wafPolicy: "missing", requireMtlsToBackend: false }] }],
    },
  });
  assert.equal(unsafeProxy.cls, "bad");
  assert.ok(unsafeProxy.blockers.some((item) => /request body redaction/.test(item)));
  assert.ok(unsafeProxy.blockers.some((item) => /lacks backend mTLS/.test(item)));
}

{
  const raw = [
    "Authorization: Bearer phr_secret_release_token",
    "artifact=/home/opc/oss-ngfw/release/evidence/proto.txt",
    "manifest_path=/tmp/acceptance.json",
    "url=https://user:pass@example.invalid/status?access_token=abc123&safe=ok",
  ].join(" ");
  const redacted = redactReadinessDisclosureText(raw);
  assert.match(redacted, /Bearer \[redacted\]/);
  assert.match(redacted, /\[server-local path redacted\]/);
  assert.match(redacted, /access_token=(?:%5Bredacted%5D|\[redacted\])/);
  assert.doesNotMatch(redacted, /phr_secret_release_token|\/home\/opc|\/tmp\/acceptance|abc123|user:pass/);

  const packetText = releaseEvidencePacketText({
    id: "proto-verify",
    title: "Generated API contract",
    label: "missing evidence",
    meta: "/home/opc/oss-ngfw/release/evidence/proto.txt",
    detail: "record with token=secret-value",
    reference: "docs/RELEASE_ACCEPTANCE.md#approved-evidence-flow",
    packet: {
      check: "proto-verify",
      evidencePath: "/home/opc/oss-ngfw/release/evidence/proto.txt",
      artifactPath: "/tmp/proto.txt",
      summary: "server path /var/lib/openngfw/release and Authorization: Bearer abcdefghijk",
      commandItems: [
        { role: "Validate", command: "make proto-verify TOKEN=abcdef" },
        { role: "Record", command: "COMMIT=abc make release-evidence-proto-verify --artifact /home/opc/proto.txt" },
      ],
      reference: "docs/RELEASE_ACCEPTANCE.md#approved-evidence-flow",
    },
  });
  assert.match(packetText, /OpenNGFW release evidence packet/);
  assert.match(packetText, /\[server-local path redacted\]/);
  assert.doesNotMatch(packetText, /\/home\/opc|\/tmp\/proto|\/var\/lib\/openngfw|Bearer abcdefghijk|TOKEN=abcdef/);

  const routedPacketText = releaseEvidencePacketText({
    id: "m5-oidc-field-evidence",
    title: "OIDC real-provider field evidence",
    label: "missing evidence",
    detail: "real issuer evidence at /home/opc/oidc with token=super-secret",
    meta: "release/field-evidence/oidc",
    href: "#/settings?panel=access&token=abc123",
    packet: {
      check: "m5-oidc-field-evidence",
      evidencePath: "release/field-evidence/oidc",
      artifactPath: "release/evidence/m5-oidc-field-evidence.txt",
      summary: "browser SSO evidence",
      commandItems: [{ role: "Validate", command: "make m5-oidc-field-evidence-check OIDC_FIELD_EVIDENCE_DIR=/home/opc/oidc TOKEN=abcdef" }],
    },
  });
  assert.match(routedPacketText, /current_gap=release\/field-evidence\/oidc/);
  assert.match(routedPacketText, /packet_route=#\/readiness\?packet=m5-oidc-field-evidence/);
  assert.match(routedPacketText, /operator_route=#\/settings\?panel=access&token=\[redacted\]/);
  assert.doesNotMatch(routedPacketText, /\/home\/opc|super-secret|abc123|TOKEN=abcdef/);

  const webuiPacketDefinition = releaseEvidencePacketDefinition("webui-enterprise-smoke");
  const webuiPacketText = releaseEvidencePacketText({
    ...webuiPacketDefinition,
    label: "missing evidence",
    meta: "release/evidence/webui-enterprise-smoke.txt",
  });
  assert.match(webuiPacketText, /current 20-route operator route set/);
  assert.match(webuiPacketText, /\/compliance/);
  assert.match(webuiPacketText, /continuation or targeted repair evidence is diagnostic only/);
  assert.match(webuiPacketText, /boundary=Browser-local copy\/export\/pin only; durable release evidence still requires ngfwrelease\/release tooling record and manifest verification\./);
  assert.match(webuiPacketText, /command \(Validate\): make webui-enterprise-smoke/);
  assert.match(webuiPacketText, /command \(Record\): COMMIT="\$\(git rev-parse HEAD\)" make release-evidence-webui-enterprise-smoke/);
}

{
  const actions = [{ id: "flowtable-host-ready" }, { id: "dry-run" }];

  assert.deepEqual(
    normalizeReadinessRouteState({ action: "flowtable-host-ready" }, actions),
    { drawer: "", packet: "", action: "flowtable-host-ready" },
  );
  assert.deepEqual(
    normalizeReadinessRouteState({ action: "missing-action" }, actions),
    { drawer: "", packet: "", action: "" },
  );
  assert.deepEqual(
    normalizeReadinessRouteState({ drawer: "system", packet: "proto-verify", action: "dry-run" }, actions),
    { drawer: "system", packet: "", action: "" },
  );
  assert.deepEqual(
    normalizeReadinessRouteState({ drawer: "ha", packet: "proto-verify", action: "dry-run" }, actions),
    { drawer: "ha", packet: "", action: "" },
  );
  assert.deepEqual(
    normalizeReadinessRouteState({ drawer: "ebpf-drill", packet: "proto-verify", action: "dry-run" }, actions),
    { drawer: "ebpf-drill", packet: "", action: "" },
  );
  assert.deepEqual(
    normalizeReadinessRouteState({ drawer: "ha-cockpit", packet: "proto-verify", action: "dry-run" }, actions),
    { drawer: "ha-cockpit", packet: "", action: "" },
  );
  assert.deepEqual(
    normalizeReadinessRouteState({ drawer: "support-bundle", packet: "proto-verify", action: "dry-run" }, actions),
    { drawer: "support-bundle", packet: "", action: "" },
  );
  assert.deepEqual(
    normalizeReadinessRouteState({ packet: "proto-verify", action: "dry-run" }, actions),
    { drawer: "", packet: "proto-verify", action: "" },
  );
  assert.deepEqual(
    normalizeReadinessRouteState({ packet: "release-benchmark", action: "dry-run" }, actions),
    { drawer: "", packet: "release-benchmark", action: "" },
  );
  assert.deepEqual(
    normalizeReadinessRouteState({ packet: "webui-enterprise-smoke", action: "dry-run" }, actions),
    { drawer: "", packet: "webui-enterprise-smoke", action: "" },
  );
  assert.deepEqual(
    normalizeReadinessRouteState({ packet: "not-a-release-gate", action: "dry-run" }, actions),
    { drawer: "", packet: "", action: "dry-run" },
  );
  assert.deepEqual(
    normalizeReadinessRouteState({ packet: "../../../etc/passwd", action: "dry-run" }, actions),
    { drawer: "", packet: "", action: "dry-run" },
  );
  assert.equal(readinessRouteDrawerKey({ drawer: "system" }), "system");
  assert.equal(readinessRouteDrawerKey({ drawer: "ha" }), "ha");
  assert.equal(readinessRouteDrawerKey({ drawer: "ebpf-drill" }), "ebpf-drill");
  assert.equal(readinessRouteDrawerKey({ drawer: "ha-cockpit" }), "ha-cockpit");
  assert.equal(readinessRouteDrawerKey({ drawer: "support-bundle" }), "support-bundle");
  assert.equal(readinessRouteDrawerKey({ drawer: "release-acceptance" }), "release-acceptance");
  assert.equal(readinessRouteDrawerKey({ packet: "proto-verify" }), "packet:proto-verify");
  assert.equal(readinessRouteDrawerKey({ packet: "not-a-release-gate" }), "");
  assert.equal(readinessRouteDrawerKey({}), "");
  assert.equal(shouldClearReadinessRouteOnClose("ha", { drawer: "ha" }), true);
  assert.equal(shouldClearReadinessRouteOnClose("ebpf-drill", { drawer: "ebpf-drill" }), true);
  assert.equal(shouldClearReadinessRouteOnClose("ha-cockpit", { drawer: "ha-cockpit" }), true);
  assert.equal(shouldClearReadinessRouteOnClose("ha", { drawer: "system" }), false);
  assert.equal(shouldClearReadinessRouteOnClose("ha", {}), false);
  assert.equal(shouldClearReadinessRouteOnClose("packet:proto-verify", { packet: "proto-verify" }), true);
  assert.equal(shouldClearReadinessRouteOnClose("packet:proto-verify", { packet: "release-benchmark" }), false);
}

{
  const model = releaseAcceptanceStatusViewModel({
    state: "evidence-pending-manifest",
    ready: false,
    manifestPresent: false,
    summary: { passed: 0, recorded: 15, missing: 0, invalid: 0, notApplicable: 0, todo: 0 },
    problems: ["release acceptance manifest release/acceptance.json is missing"],
    checks: [{ name: "proto-verify", state: "recorded" }],
  });
  assert.equal(model.cls, "warn");
  assert.match(model.title, /manifest assembly is pending/);
  assert.match(model.detail, /All required evidence is recorded/);
  assert.doesNotMatch(model.detail, /blocked|manifest missing|problem/);
}

{
  const model = releaseAcceptanceStatusViewModel({
    state: "blocked",
    ready: false,
    manifestPresent: false,
    summary: { passed: 0, recorded: 0, missing: 1, invalid: 0, notApplicable: 0, todo: 0 },
    checks: [{
      name: "proto-verify",
      state: "missing",
      evidencePath: "/home/opc/oss-ngfw/release/evidence/proto-verify.txt",
      nextCommand: ["make", "proto-verify", "TOKEN=abcdef"],
    }],
  });
  const proto = model.checks.find((check) => check.name === "proto-verify");
  assert.ok(proto, "proto-verify check should be modeled");
  assert.deepEqual(proto.nextCommands.map((item) => item.command), [
    "make proto-verify TOKEN=[redacted]",
    "make proto-status",
    "make proto-verify",
    "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-proto-verify",
  ]);
  assert.ok(model.omittedCommandGuidance.some((item) => item.name === "deploy-hardening"), "omitted release gates should expose command guidance");
  assert.ok(model.omittedCommandGuidance.some((item) => item.name === "release-benchmark"), "release-benchmark omitted guidance should be present");
  const omittedWebUI = model.omittedCommandGuidance.find((item) => item.name === "webui-enterprise-smoke");
  assert.ok(omittedWebUI, "webui-enterprise-smoke omitted guidance should be present");
  assert.deepEqual(omittedWebUI.nextCommands.map((item) => item.command), [
    "make webui-enterprise-smoke",
    "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-webui-enterprise-smoke",
  ]);

  const report = redactReadinessDisclosureText(releaseAcceptanceStatusReport(model));
  assert.match(report, /next commands for checks omitted from status report:/);
  assert.match(report, /- deploy-hardening: not reported by status endpoint/);
  assert.match(report, /- webui-enterprise-smoke: not reported by status endpoint/);
  assert.match(report, /command \(Validate\): make webui-enterprise-smoke/);
  assert.match(report, /command \(Record\): COMMIT="\$\(git rev-parse HEAD\)" make release-evidence-webui-enterprise-smoke/);
  assert.match(report, /command \(Validate\): bash release\/deploy-hardening-check\.sh --check/);
  assert.match(report, /command \(Record\): COMMIT="\$\(git rev-parse HEAD\)" make release-evidence-deploy-hardening/);
  assert.match(report, /command \(No claims\): RELEASE_NO_PERFORMANCE_CLAIMS=1 make release-acceptance-status/);
  assert.match(report, /command \(Record\): make proto-verify TOKEN=\[redacted\]/);
  assert.doesNotMatch(report, /\/home\/opc|TOKEN=abcdef/);
}

{
  const model = releaseAcceptanceStatusViewModel({
    state: "blocked",
    ready: false,
    manifestPresent: false,
    manifestPath: "/tmp/openngfw-smoke/release/acceptance.json",
    evidenceDir: "/home/opc/oss-ngfw/release/evidence",
    summary: { missing: 1, invalid: 1, todo: 0, notApplicable: 0 },
    problems: ["manifest missing at /tmp/openngfw-smoke/release/acceptance.json"],
    checks: [{
      name: "webui-enterprise-smoke",
      state: "missing",
      evidencePath: "/home/opc/oss-ngfw/release/evidence/webui-enterprise-smoke.txt",
      detail: "smoke evidence at /tmp/openngfw-webui-smoke/webui-smoke-evidence.json token=release-secret",
      problems: ["stdout references /home/opc/oss-ngfw/release/evidence/webui-enterprise-smoke.txt"],
      nextCommand: ["make", "webui-enterprise-smoke", "TOKEN=release-secret"],
    }],
  });
  const aggregate = releaseAcceptanceAggregateSummary(model);
  assert.equal(aggregate.detail, "1 missing check(s); 1 invalid check(s); manifest missing; 1 problem(s).");
  assert.deepEqual(model.checks.map((check) => check.name), ["webui-enterprise-smoke"]);
  assert.equal(model.checks[0].meta, "[server-local path redacted]");
  assert.match(model.checks[0].detail, /\[server-local path redacted\]/);
  assert.equal(model.checks[0].nextCommands[0].command, "make webui-enterprise-smoke TOKEN=[redacted]");
  assert.doesNotMatch(JSON.stringify({ aggregate, check: model.checks[0] }), /\/home\/opc|\/tmp\/openngfw|release-secret/);

  const summaryReport = releaseAcceptanceStatusSummaryReport(model);
  assert.match(summaryReport, /summary=passed:0 recorded:0 missing:1 invalid:1/);
  assert.match(summaryReport, /note=Summary report intentionally omits manifest paths/);
  assert.doesNotMatch(summaryReport, /\/home\/opc|\/tmp\/openngfw|webui-smoke-evidence|release-secret/);
}

{
  const packet = buildEbpfDrillEvidencePacket({
    ebpfHost: {
      state: "ready",
      detail: "BTF, bpffs, and cgroup v2 present.",
      attachState: "ready",
      attachDetail: "XDP/tc attach drill passed on disposable interface.",
      rendererState: "planned",
      rendererDetail: "Plan-only renderer scaffold.",
      supportedHooks: ["xdp", "tc"],
      evidenceScope: "ol9-oci",
      evidenceCollectedAt: "2026-06-20T12:00:00Z",
      probes: [
        { name: "Kernel BTF", key: "kernel-btf", state: "ready", detail: "present" },
        { name: "bpffs", key: "bpffs", state: "ready", detail: "mounted" },
      ],
      attachProbes: [
        { name: "XDP generic", key: "xdp-attach", state: "ready", detail: "passed" },
        { name: "tc clsact", key: "tc-attach", state: "ready", detail: "passed" },
      ],
      attachments: [{ interface: "openngfw-ebpf0", hook: "xdp", programName: "xdp_probe", state: "ready" }],
      artifacts: [{ name: "manifest", path: "release/field-evidence/ebpf-ol9/drill/manifest.txt", state: "ready", sha256: "a".repeat(64) }],
    },
    releaseItem: {
      cls: "ok",
      label: "recorded",
      detail: "Release evidence recorded.",
      meta: "release/evidence/ebpf-ol9-field-evidence.txt",
    },
    generatedAt: "2026-06-20T12:00:00Z",
  });

  assert.equal(packet.schema, "phragma.ebpf.drill-evidence.v1");
  assert.equal(packet.state, "ready");
  assert.equal(packet.activeDataplane, "nftables/conntrack");
  assert.equal(packet.probeCount, 2);
  assert.equal(packet.attachProbeCount, 2);
  assert.equal(packet.attachmentCount, 1);
  assert.equal(packet.artifactCount, 1);
  assert.match(packet.text, /active_dataplane=nftables\/conntrack/);
  assert.match(packet.text, /make ebpf-ol9-attach-drill/);
  assert.match(packet.text, /does not certify active eBPF dataplane cutover/);
  assert.equal(packet.text.includes("/etc/phragma"), false);
}

{
  const action = hostTuningActionState({ runtime: { dryRun: true } }, "throughput");

  assert.equal(action.profile, "throughput");
  assert.equal(action.label, "throughput profile");
  assert.equal(action.applyLabel, "Apply throughput");
  assert.equal(action.applyDisabled, true);
  assert.match(action.disabledReason, /dry-run mode/);
  assert.match(action.reviewTitle, /Preview only/);
  assert.deepEqual(action.previewBody, { profile: "throughput" });
  assert.deepEqual(action.mutationBody, {
    profile: "throughput",
    write: true,
    apply: true,
    ackHostChange: true,
  });
}

{
  const action = hostTuningActionState({ runtime: { dryRun: false } }, "appliance");

  assert.equal(action.profile, "appliance");
  assert.equal(action.label, "host baseline");
  assert.equal(action.applyLabel, "Apply baseline");
  assert.equal(action.applyDisabled, false);
  assert.equal(action.disabledReason, "");
  assert.match(action.reviewTitle, /Preview the sysctl profile/);
  assert.deepEqual(action.previewBody, { profile: "appliance" });
  assert.deepEqual(action.mutationBody, {
    profile: "appliance",
    write: true,
    apply: true,
    ackHostChange: true,
  });
}

{
  const action = hostTuningActionState({}, "unknown-profile");

  assert.equal(action.profile, "appliance");
  assert.equal(action.applyDisabled, false);
}

{
  const policy = {
    staticRoutes: [{ destination: "10.20.0.0/24", interface: "wg0" }],
    routing: {
      bgp: { enabled: true, neighbors: [{ address: "198.51.100.2", remoteAsn: 65002 }] },
      ospf: { enabled: true, networks: ["10.0.0.0/24"] },
    },
    vpn: {
      ipsecTunnels: [{ name: "site-b", localSubnets: ["10.10.0.0/24"], remoteSubnets: ["10.20.0.0/24"] }],
      wireguardInterfaces: [{ name: "wg0", address: "10.99.0.1/24", peers: [{ name: "laptop", publicKey: "pubkey1", allowedIps: ["10.99.0.2/32"] }] }],
    },
  };
  const status = {
    routing: { frr: { state: "active", bgpNeighbors: [{ peer: "198.51.100.2", state: "Established" }], ospfNeighbors: [{ neighborId: "10.0.0.2", state: "Full/DROther" }] } },
    vpn: {
      ipsec: { state: "active", tunnels: [{ name: "site-b", state: "active", ikeState: "established", childSaCount: 1, installedChildSaCount: 1 }] },
      wireguard: { state: "active", interfaces: [{ name: "wg0", peers: [{ publicKey: "pubkey1", state: "handshook", latestHandshakeAgeSeconds: 90 }] }] },
    },
  };
  const model = routingVpnPostureModel(policy, status);
  assert.equal(model.cls, "ok");
  assert.equal(model.label, "observed");
  assert.equal(model.metrics.staticRoutes, 1);
  assert.equal(model.metrics.tunnelPaths, 2);
  assert.equal(model.metrics.ipsecTunnels, 1);
  assert.equal(model.metrics.wireguardPeers, 1);
  assert.equal(model.rows.find((row) => row.id === "routing-vpn-bgp").tone, "ok");
  assert.equal(model.rows.find((row) => row.id === "routing-vpn-ipsec").state, "active");
  assert.equal(model.rows.find((row) => row.id === "routing-vpn-wireguard").state, "active");
  assert.equal(
    model.firstTunnelHref,
    "#/netvpn?drawer=tunnel&kind=ipsec&name=site-b&local=10.10.0.0%2F24&remote=10.20.0.0%2F24&src=10.10.0.1&dst=10.20.0.1&protocol=PROTOCOL_ANY&port=4500",
  );
}

{
  const policy = {
    routing: { bgp: { enabled: true, neighbors: [{ address: "198.51.100.2" }] } },
    vpn: {
      ipsecTunnels: [{ name: "site-b" }, { name: "dr-site" }],
      wireguardInterfaces: [{ name: "wg0", peers: [{ name: "laptop", publicKey: "pubkey1" }] }],
    },
  };
  const status = {
    routing: { frr: { state: "waiting", detail: "1 BGP neighbor(s), no established sessions", bgpNeighbors: [{ peer: "198.51.100.2", state: "Connect" }] } },
    vpn: {
      ipsec: { state: "active", tunnels: [{ name: "site-b", state: "active", ikeState: "established", childSaCount: 1, installedChildSaCount: 1 }] },
      wireguard: { state: "active", interfaces: [{ name: "wg0", peers: [{ publicKey: "pubkey1", state: "waiting" }] }] },
    },
  };
  const model = routingVpnPostureModel(policy, status);
  assert.equal(model.cls, "warn");
  assert.equal(model.label, "3 review");
  assert.equal(model.rows.find((row) => row.id === "routing-vpn-bgp").state, "waiting");
  assert.equal(model.rows.find((row) => row.id === "routing-vpn-ipsec").state, "waiting");
  assert.equal(model.rows.find((row) => row.id === "routing-vpn-wireguard").state, "waiting");
  assert.equal(model.firstTunnelHref, "#/netvpn?drawer=tunnel&kind=ipsec&name=dr-site&protocol=PROTOCOL_UDP&port=4500");
  assert.equal(JSON.stringify(model).includes("/etc/phragma"), false);
}

{
  assert.equal(haPolicyPullActionState({
    mode: "active-passive",
    role: "passive",
    peerId: "fw-a",
    sync: { peerVersion: 7 },
  }).canPull, true);
  assert.equal(haPolicyPullActionState({
    mode: "active-passive",
    role: "passive",
    peerAddress: "10.0.0.5",
    sync: { peerVersion: 8 },
  }).canPull, true);
  assert.equal(haPolicyPullActionState({ mode: "standalone", role: "standalone" }).canPull, false);
  assert.match(haPolicyPullActionState({ mode: "active-passive", role: "active" }).disabledReason, /passive node/);
  assert.match(haPolicyPullActionState({ mode: "active-passive", role: "passive", sync: {} }).disabledReason, /peer/i);
}

{
  assert.equal(haFailoverActivationActionState({
    mode: "active-passive",
    role: "passive",
    runningPolicyVersion: 6,
    lastKnownGoodVersion: 6,
    sync: { state: "synced" },
    failover: { eligible: true },
  }).canActivate, true);
  assert.equal(haFailoverActivationActionState({ mode: "standalone", role: "standalone" }).canActivate, false);
  assert.match(haFailoverActivationActionState({ mode: "active-passive", role: "active" }).disabledReason, /passive node/);
  assert.match(haFailoverActivationActionState({ mode: "active-passive", role: "passive", failover: { eligible: false, blockers: ["peer heartbeat missing"] } }).disabledReason, /heartbeat/);
}

{
  const model = haOperationsCockpitModel({
    state: "ready",
    cls: "ok",
    mode: "active-passive",
    role: "passive",
    nodeId: "fw-b",
    peerId: "fw-a",
    peerAddress: "10.0.0.5",
    runningPolicyVersion: 6,
    lastKnownGoodVersion: 5,
    lastKnownGoodState: "available",
    artifactSet: "abc1234567890def",
    sync: {
      state: "synced",
      detail: "peer reachable",
      localVersion: 6,
      peerVersion: 6,
      localArtifactSetSha256: "abc1234567890def",
      peerArtifactSetSha256: "abc1234567890def",
    },
    replication: {
      enabled: true,
      state: "replicated",
      detail: "Last automatic replication applied peer policy v6 locally as v6.",
      lastSuccessAt: "2026-06-20T11:59:00Z",
      lastPeerVersion: 6,
      lastLocalVersion: 6,
    },
    failover: {
      state: "ready",
      eligible: true,
      detail: "operator failover controls are ready",
    },
    blockers: [],
  }, { generatedAt: "2026-06-20T12:00:00Z" });

  assert.equal(model.schema, "phragma.ha.operations.v1");
  assert.equal(model.policy.label, "in sync");
  assert.equal(model.pullAction.canPull, true);
  assert.equal(model.activationAction.canActivate, true);
  assert.equal(model.packetBoundary.eligible, true);
  assert.equal(model.packetBoundary.packetOnly, true);
  assert.equal(model.packetBoundary.trafficCutoverExternal, true);
  assert.ok(model.rows.some((row) => row.id === "ha-cockpit-policy-compare" && row.cls === "ok"));
  assert.ok(model.rows.some((row) => row.id === "ha-cockpit-auto-replication" && row.label === "replicated"));
  assert.ok(model.rows.some((row) => row.id === "ha-cockpit-policy-pull" && row.title === "Manual recovery policy pull"));
  assert.ok(model.rows.some((row) => row.id === "ha-cockpit-failover-activation" && row.label === "available"));
  assert.ok(model.rows.some((row) => row.id === "ha-cockpit-packet-boundary" && row.label === "packet only"));
  assert.ok(model.rows.some((row) => row.id === "ha-cockpit-post-activation-review" && row.label === "pending activation"));
  const report = haOperationsCockpitReport(model);
  assert.match(report, /schema=phragma\.ha\.operations\.v1/);
  assert.match(report, /policy_compare=in sync/);
  assert.match(report, /replication_state=replicated/);
  assert.match(report, /mutation_surface=automatic-passive-policy-replication-and-manual-activation/);
  assert.match(report, /activation_available=true/);
  assert.match(report, /packet_boundary=Loaded HA signals can support a failover review packet/);
  assert.match(report, /positive_evidence=running policy v6; last-known-good v5; peer policy sync evidence is synced; server failover preflight reports eligible/);
  assert.match(report, /external_boundaries=peer fencing remains external; VIP\/route movement remains external; connection-state transfer remains external/);
  assert.match(report, /post_activation_review=pending/);
}

{
  const model = haOperationsCockpitModel({
    state: "degraded",
    cls: "warn",
    mode: "active-passive",
    role: "active",
    nodeId: "fw-b",
    peerId: "fw-a",
    runningPolicyVersion: 6,
    lastKnownGoodVersion: 6,
    sync: { state: "degraded", localVersion: 6, peerVersion: 6 },
    failover: {
      state: "blocked",
      eligible: false,
      detail: "Local control-plane role is active after manual activation; post-activation review must verify peer fencing, VIP/route ownership, and traffic cutover outside this API.",
      blockers: ["HA peer role matches local role; active/passive requires opposite roles."],
    },
    blockers: ["HA peer role matches local role; active/passive requires opposite roles."],
  }, { generatedAt: "2026-06-20T12:05:00Z" });
  assert.equal(model.activationAction.canActivate, false);
  assert.equal(model.packetBoundary.eligible, false);
  assert.ok(model.packetBoundary.missingEvidence.includes("server failover preflight is blocked or unavailable"));
  assert.equal(model.postActivationReview, true);
  assert.ok(model.rows.some((row) => row.id === "ha-cockpit-post-activation-review" && row.label === "required" && /peer fencing/.test(row.detail)));
  assert.match(haOperationsCockpitReport(model), /post_activation_review=required/);
}

{
  const boundary = haFailoverPacketBoundaryModel({
    mode: "active-passive",
    role: "passive",
    runningPolicyVersion: 9,
    lastKnownGoodVersion: 9,
    sync: { state: "synced" },
    failover: { eligible: true },
    fencingEvidence: { state: "recorded" },
    transportEvidence: { state: "promoted" },
    conntrackSync: { state: "synced" },
  });
  assert.equal(boundary.schema, "phragma.ha.failover-boundary.v1");
  assert.equal(boundary.eligible, true);
  assert.equal(boundary.peerFencingExternal, false);
  assert.equal(boundary.vipRouteMovementExternal, false);
  assert.equal(boundary.connectionStateTransferExternal, false);
  assert.ok(boundary.positiveEvidence.includes("server failover preflight reports eligible"));
  assert.ok(boundary.externalBoundaries.includes("packet copy/export/pin does not execute failover or certify traffic cutover"));

  const blocked = haFailoverPacketBoundaryModel({
    mode: "active-passive",
    role: "passive",
    sync: { state: "degraded" },
    failover: { eligible: false },
  });
  assert.equal(blocked.eligible, false);
  assert.equal(blocked.packetOnly, true);
  assert.match(blocked.detail, /does not authorize or perform traffic cutover/);
  assert.ok(blocked.missingEvidence.includes("running policy version missing"));
  assert.ok(blocked.externalBoundaries.includes("peer fencing remains external"));
}

{
  assert.deepEqual(ENGINE_READINESS_COLUMNS, ["Engine", "State", "Mode", "Role", "Detail"]);

  const row = engineReadinessRowModel({
    name: "suricata",
    state: "missing-prerequisites",
    mode: "dry-run",
    role: "ids",
    detail: "af-packet support unavailable",
  });

  assert.deepEqual(row.map((cell) => cell.label), ENGINE_READINESS_COLUMNS);
  assert.equal(row.find((cell) => cell.label === "Engine").text, "suricata");
  assert.equal(row.find((cell) => cell.label === "State").badge, "missing-prerequisites");
  assert.equal(row.find((cell) => cell.label === "State").tone, "bad");
  assert.equal(row.find((cell) => cell.label === "Mode").badge, "dry-run");
  assert.equal(row.find((cell) => cell.label === "Mode").tone, "warn");
  assert.equal(row.find((cell) => cell.label === "Role").text, "ids");
  assert.equal(row.find((cell) => cell.label === "Detail").text, "af-packet support unavailable");
}

{
  const model = releaseAcceptanceStatusViewModel({
    state: "blocked",
    manifestPresent: true,
    checks: [
      { name: "release-benchmark", state: "not_applicable", detail: "no performance claims" },
      { name: "privileged-integration", state: "not_applicable", detail: "lab release only" },
      { name: "m5-auth-ui", state: "recorded" },
      { name: "proto-verify", state: "missing" },
      {
        name: "ha-readiness-recovery",
        state: "missing",
        nextAction: "Run the HA readiness recovery check.",
        nextCommand: ["make", "ha-readiness-recovery-check"],
      },
      { name: "content-production-readiness", state: "todo" },
    ],
    recordability: {
      ready: false,
      gitHead: "0123456789abcdef0123456789abcdef01234567",
      recordCommit: "0123456789abcdef0123456789abcdef01234567",
      allowedDirtyPaths: ["release/evidence", "release/field-evidence"],
      dirtySourcePaths: ["?? internal/source.go"],
      problems: ["release source tree has uncommitted changes outside allowed release artifact paths"],
      nextAction: "Commit or stash source changes before recording release evidence.",
    },
  });

  assert.equal(model.summary.recorded, 1);
  assert.equal(model.summary.missing, 2);
  assert.equal(model.summary.notApplicable, 2);
  assert.equal(model.summary.todo, 1);
  assert.equal(model.checks.find((check) => check.name === "release-benchmark").cls, "ok");
  assert.equal(model.checks.find((check) => check.name === "release-benchmark").label, "not applicable");
  assert.equal(model.checks.find((check) => check.name === "privileged-integration").cls, "warn");
  assert.equal(model.checks.find((check) => check.name === "privileged-integration").label, "review needed");
  assert.equal(model.checks.find((check) => check.name === "m5-auth-ui").cls, "warn");
  assert.equal(model.checks.find((check) => check.name === "m5-auth-ui").label, "pending manifest");
  assert.match(model.checks.find((check) => check.name === "m5-auth-ui").detail, /not accepted until/);
  const reviewNeeded = releaseAcceptanceStatusViewModel({
    manifestPresent: true,
    checks: [{ name: "privileged-integration", state: "review_needed" }],
  }).checks[0];
  assert.equal(reviewNeeded.cls, "warn");
  assert.equal(reviewNeeded.label, "review needed");
  assert.match(reviewNeeded.detail || "", /human review|review/);
  const haRecovery = model.checks.find((check) => check.name === "ha-readiness-recovery");
  assert.equal(haRecovery.cls, "bad");
  assert.equal(haRecovery.label, "missing");
  assert.ok(haRecovery.nextCommands.some((cmd) => cmd.role === "Next" && cmd.command === "make ha-readiness-recovery-check"));
  assert.ok(haRecovery.nextCommands.some((cmd) => cmd.role === "Record" && /release-evidence-ha-readiness-recovery/.test(cmd.command)));
  assert.equal(model.recordability.ready, false);
  assert.equal(model.recordability.cls, "bad");
  assert.match(model.recordability.command, /make release-recordability-check/);
  assert.match(model.recordability.detail, /does not create evidence/);
  assert.match(model.recordability.detail, /make any check clear/);
  assert.equal(model.recordability.allowedDirtyPaths[0], "release/evidence");
  assert.equal(model.recordability.dirtySourcePaths[0], "?? internal/source.go");
  assert.deepEqual(model.recordability.staleEvidencePaths, []);
  assert.deepEqual(model.recordability.visibleDirtySourcePaths, ["?? internal/source.go"]);
  assert.equal(model.recordability.omittedDirtySourceCount, 0);

  const report = releaseAcceptanceStatusSummaryReport(model);
  assert.match(report, /OpenNGFW release acceptance summary/);
  assert.match(report, /state=blocked/);
  assert.match(report, /problem_count=0/);
  assert.match(report, /recordability=blocked dirty_source_count=1 stale_evidence_count=0 problem_count=1/);
  assert.match(report, /ha-readiness-recovery: missing/);
  assert.doesNotMatch(report, /release\/evidence|internal\/source\.go|0123456789abcdef|Commit or stash|ha-readiness-recovery-check|release-evidence-ha-readiness-recovery/);
  assert.match(report, /intentionally omits manifest paths, evidence paths, dirty source paths, problem text, and commands/);
}

{
  const accepted = classifyReleaseArtifactEvidenceBoundary({
    id: "proto-verify",
    label: "passed",
    evidenceState: "recorded",
    manifestBinding: "accepted by release/acceptance.json",
    currentStatus: "Evidence is accepted by the verified release acceptance manifest.",
  });
  assert.equal(accepted.label, "accepted-source evidence");
  assert.equal(accepted.tone, "ok");
  assert.match(accepted.detail, /verified release acceptance manifest/);

  const continuation = classifyReleaseArtifactEvidenceBoundary({
    id: "webui-enterprise-smoke",
    label: "recorded",
    evidenceState: "recorded",
    manifestBinding: "recorded; manifest verification pending",
    currentStatus: "Remote continuation validation passed same-snapshot broad desktop smoke.",
  });
  assert.equal(continuation.label, "remote continuation evidence");
  assert.equal(continuation.tone, "warn");
  assert.match(continuation.detail, /repo-local release tooling/);

  const template = classifyReleaseArtifactEvidenceBoundary({
    id: "m5-saml-field-evidence",
    label: "missing",
    evidenceState: "missing",
    currentStatus: "Command only prepares the bundle directory.",
    nextCommand: "mkdir -p release/field-evidence/saml",
  });
  assert.equal(template.label, "template/non-evidence");
  assert.equal(template.tone, "info");
  assert.match(template.detail, /does not satisfy the release gate/);

  const stale = classifyReleaseArtifactEvidenceBoundary({
    id: "privileged-integration",
    label: "stale",
    evidenceState: "stale",
    currentStatus: "Evidence was copied from a different commit.",
    problems: ["stale evidence path release/evidence/privileged-integration.txt"],
  });
  assert.equal(stale.label, "stale evidence");
  assert.equal(stale.tone, "warn");
  assert.match(stale.detail, /Regenerate and record/);

  const custody = releaseArtifactCustodyBoundary({
    id: "proto-verify",
    label: "passed",
    manifestBinding: "accepted by release/acceptance.json",
  });
  assert.equal(custody.label, "hardening-only");
  assert.match(custody.detail, /artifact signing and retained custody controls/);
}

{
  const dirtySourcePaths = Array.from({ length: 11 }, (_, index) => `?? internal/generated-${index}.go`);
  const model = releaseAcceptanceStatusViewModel({
    state: "blocked",
    manifestPresent: true,
    recordability: {
      ready: false,
      dirtySourcePaths,
      problems: ["release source tree has uncommitted changes outside allowed release artifact paths"],
    },
  });

  assert.equal(model.recordability.dirtySourcePaths.length, 11);
  assert.deepEqual(model.recordability.visibleDirtySourcePaths, dirtySourcePaths.slice(0, 8));
  assert.equal(model.recordability.omittedDirtySourceCount, 3);
  assert.equal(model.recordability.truncatedDirtySourceCount, 0);
}

{
  const unavailable = releaseAcceptanceFromResult({
    status: "rejected",
    reason: new ApiError(503, "status backend unavailable", {}),
  });
  const model = releaseAcceptanceStatusViewModel(unavailable);

  assert.equal(model.state, "unavailable");
  assert.equal(model.cls, "bad");
  assert.equal(model.manifestPresent, false);
  assert.match(model.problems[0], /status backend unavailable/);
  assert.match(model.detail, /manifest missing/);
}

{
  const denied = supportBundleErrorModel(new ApiError(403, "permission denied", {}));
  assert.equal(denied.title, "Support bundle access denied");
  assert.equal(denied.tone, "bad");
  assert.match(denied.detail, /operator role/);
  assert.match(denied.command, /ngfwctl support-bundle/);

  const failed = supportBundleErrorModel(new Error("disk full"));
  assert.equal(failed.title, "Support bundle preview failed");
  assert.equal(failed.tone, "warn");
  assert.match(failed.detail, /disk full/);
}

await withMockedApi(async () => {
  const calls = [];
  const serverBundle = {
    schemaVersion: "phragma.support.bundle.server.v1",
    collector: { type: "server", name: "controld" },
    endpoints: {},
    summary: {},
  };
  api.supportBundle = async (...args) => record(calls, "supportBundle", args, serverBundle);
  installFailingFallback(calls);

  const bundle = await collectSupportBundle();

  assert.equal(bundle, serverBundle);
  assert.deepEqual(callNames(calls), ["supportBundle"]);
  assert.deepEqual(calls[0].args[0], SUPPORT_BUNDLE_LIMITS);
});

for (const status of [404, 405, 501]) {
  await withMockedApi(async () => {
    const calls = [];
    api.supportBundle = async (...args) => {
      calls.push({ name: "supportBundle", args });
      throw new ApiError(status, `HTTP ${status}`, {});
    };
    installBrowserFallback(calls);

    const bundle = await collectSupportBundle();

    assert.deepEqual(callNames(calls), ["supportBundle", ...FALLBACK_CALL_NAMES]);
    assert.deepEqual(calls[0].args[0], SUPPORT_BUNDLE_LIMITS);
    assert.equal(bundle.collector.type, "browser");
    assert.equal(bundle.endpoints.status.data.runtime.version, "fallback-runtime");
    assert.equal(bundle.endpoints.highAvailabilityStatus.data.schemaVersion, "phragma.ha.status.v1");
    assert.equal(bundle.endpoints.highAvailabilityStatus.data.status.state, "standalone");
    assert.equal(bundle.endpoints.highAvailabilityStatus.data.status.mode, "standalone");
    assert.equal(bundle.endpoints.highAvailabilityStatus.data.status.role, "standalone");
    assert.equal(bundle.endpoints.runningPolicy.data.version, 42);
    assert.equal(bundle.endpoints.candidatePolicy.ok, true);
    assert.equal(bundle.endpoints.runtimeReadinessPreflight.data.schemaVersion, "phragma.runtime-readiness.v1");
    assert.deepEqual(bundle.summary.failedEndpoints, []);
    const report = supportBundlePreviewReport(bundle);
    assert.equal(bundle.endpoints.telemetryExportStatus.data.schemaVersion, "phragma.telemetry.export.status.v1");
    assert.match(report, /sections=included:18 failed:0 total:18/);
    assert.match(report, /runtime_readiness=operation:commit label:No runtime warnings requires_ack:false items:0/);
    assert.match(report, /telemetry_export=state:disabled enabled:false vector:unknown sinks:0 observed:0/);
    assert.match(report, /- Active\/passive HA status: included - standalone .* sync unknown .* failover blocked/);
    assert.deepEqual(calls.find((call) => call.name === "versions").args, [100]);
    assert.deepEqual(calls.find((call) => call.name === "audit").args, [300]);
    assert.deepEqual(calls.find((call) => call.name === "alerts").args, [500]);
    assert.deepEqual(calls.find((call) => call.name === "flows").args, [500]);
    assert.deepEqual(calls.find((call) => call.name === "sessions").args, [500]);
  });
}

for (const status of [401, 403]) {
  await withMockedApi(async () => {
    const calls = [];
    const authError = new ApiError(status, status === 401 ? "unauthenticated" : "permission denied", {});
    api.supportBundle = async (...args) => {
      calls.push({ name: "supportBundle", args });
      throw authError;
    };
    installFailingFallback(calls);

    await assert.rejects(
      () => collectSupportBundle(),
      (err) => err === authError && err.status === status,
    );

    assert.deepEqual(callNames(calls), ["supportBundle"]);
    assert.deepEqual(calls[0].args[0], SUPPORT_BUNDLE_LIMITS);
  });
}
