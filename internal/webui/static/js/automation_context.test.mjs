import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  API_CONTRACT,
  AUTOMATION_REPLAY_VALIDATION,
  AUTOMATION_CONTEXTS,
  appendAutomationRecording,
  apiContractCurl,
  apiOriginForCopy,
  automationReplayApplyAuthorityRequest,
  automationReplayDryRunRequest,
  automationReplayExecuteRequest,
  automationReplayValidationRequest,
  automationContextText,
  automationRecordingJson,
  automationRecordingRunbookText,
  automationWorkflowSession,
  contextForPath,
  curlForEndpoint,
  emptyAutomationRecording,
  workflowRunbookText,
} from "./automation_context.js";
import { releaseEvidencePacketDefinition, releaseEvidencePacketIds } from "./readiness_model.js";

const automationContextSource = readFileSync("internal/webui/static/js/automation_context.js", "utf8");
assert.match(automationContextSource, /import \{ closeDrawer, openDrawer, toast \}/);
assert.match(automationContextSource, /type: "button", title: "Close API and CLI context"/);
assert.match(automationContextSource, /automationAction: "cancel"/);
assert.match(automationContextSource, /automationAction: "copy-runbook"/);
assert.match(automationContextSource, /automationAction: "copy-context"/);
assert.match(automationContextSource, /automationAction: "copy-api-contract-curl"/);
assert.match(automationContextSource, /automationAction: "copy-endpoint-curl"/);
assert.match(automationContextSource, /automationAction: "copy-cli-command"/);
assert.match(automationContextSource, /automationRecorderAction: "copy-runbook"/);
assert.match(automationContextSource, /automationRecorderAction: "download-runbook"/);
assert.match(automationContextSource, /automationRecorderAction: "validate-replay"/);
assert.match(automationContextSource, /automationAction: "copy-recording-runbook"/);
assert.match(automationContextSource, /type: "button", title: "Start automation recorder"/);
assert.match(automationContextSource, /type: "button", title: "Record current API and CLI view"/);
assert.match(automationContextSource, /type: "button", title: "Copy automation recording shell runbook"/);
assert.match(automationContextSource, /type: "button", title: "Validate automation recording before replay"/);

function assertFlatExplainBodies(label, context, expected = {}) {
  const bodies = context.endpoints
    .filter((endpoint) => endpoint.path === "/v1/explain/flow")
    .map((endpoint) => endpoint.body || "");
  assert.ok(bodies.length, `${label} missing ExplainFlow endpoint body`);
  for (const body of bodies) {
    const parsed = JSON.parse(body);
    assert.ok(parsed.policySource, `${label} ExplainFlow body must use flat policySource`);
    assert.ok(Object.hasOwn(parsed, "srcIp"), `${label} ExplainFlow body must use flat srcIp`);
    assert.ok(Object.hasOwn(parsed, "destIp"), `${label} ExplainFlow body must use flat destIp`);
    assert.equal(Object.hasOwn(parsed, "flow"), false, `${label} ExplainFlow body must not use nested flow`);
    assert.equal(Object.hasOwn(parsed, "source"), false, `${label} ExplainFlow body must not use legacy source`);
    for (const [key, value] of Object.entries(expected)) {
      assert.equal(parsed[key], value, `${label} ExplainFlow ${key}`);
    }
  }
}

function assertFirstFlatExplainBody(label, context, expected = {}) {
  const bodies = context.endpoints
    .filter((endpoint) => endpoint.path === "/v1/explain/flow")
    .map((endpoint) => endpoint.body || "");
  assert.ok(bodies.length, `${label} missing ExplainFlow endpoint body`);
  assertFlatExplainBodies(label, { endpoints: [{ path: "/v1/explain/flow", body: bodies[0] }] }, expected);
}

const routes = [
  "/",
  "/setup",
  "/rules",
  "/objects",
  "/nat",
  "/inspection",
  "/proxy",
  "/threats",
  "/traffic",
  "/logs",
  "/troubleshoot",
  "/performance",
  "/fleet",
  "/compliance",
  "/intel",
  "/netvpn",
  "/readiness",
  "/changes",
  "/settings",
];

for (const route of routes) {
  const context = contextForPath(route);
  assert.equal(context, AUTOMATION_CONTEXTS[route], `missing automation context for ${route}`);
  assert.ok(context.title);
  assert.ok(context.summary);
  assert.ok(context.endpoints.length > 0, `${route} needs REST endpoints`);
  assert.ok(context.cli.length > 0, `${route} needs CLI equivalents`);
  assert.ok(context.endpoints.every((endpoint) => endpoint.path.startsWith("/v1/")), `${route} must expose authenticated REST API paths`);
}

assert.equal(API_CONTRACT.path, "/ui/api-spec.yaml");
assert.equal(API_CONTRACT.aliasPath, "/api-spec.yaml");
assert.match(API_CONTRACT.format, /Swagger 2\.0/);
assert.equal(AUTOMATION_REPLAY_VALIDATION.path, "/v1/system/automation/replay:validate");
assert.equal(AUTOMATION_REPLAY_VALIDATION.method, "POST");
assert.equal(AUTOMATION_REPLAY_VALIDATION.schema, "phragma.automation.replay-validation.v1");
assert.equal(AUTOMATION_REPLAY_VALIDATION.planSchema, "phragma.automation.replay-execution-plan.v1");
assert.equal(AUTOMATION_REPLAY_VALIDATION.resultSchema, "phragma.automation.replay-execution-result.v1");
assert.match(AUTOMATION_REPLAY_VALIDATION.purpose, /audited execute-mode candidate replacement/);
assert.match(AUTOMATION_REPLAY_VALIDATION.purpose, /live\/destructive\/unknown-route replay remains blocked/);

assert.equal(contextForPath("#/rules?x=1").title, AUTOMATION_CONTEXTS["/rules"].title);
assert.equal(contextForPath("/traffic?mode=sessions").title, AUTOMATION_CONTEXTS["/traffic"].title);
assert.match(contextForPath("/unknown").notes[0], /No dedicated automation context/);

const setupTap = contextForPath("#/setup?scenario=ids-tap&profile=ids-detect&insideZone=tap&outsideZone=monitor&insideInterfaces=eth1&outsideInterfaces=eth2&insideCidr=10.30.0.0%2F24&webuiPort=8080&allowOutbound=0&masquerade=0&hardenHostInput=1&clampMss=0&flowOffload=0&manageNicOffloads=1&idsRuleFiles=local.rules");
assert.equal(setupTap.endpoints[0].path, "/v1/system/status");
assert.equal(setupTap.cli[0].command, "ngfwctl policy baseline --profile ids-detect --inside-zone tap --outside-zone monitor --inside-interface eth1 --outside-interface eth2 --inside-cidr 10.30.0.0/24 --webui-port 8080 --allow-outbound=false --masquerade=false --harden-host-input=true --flow-offload=false --clamp-mss=false --manage-nic-offloads=true --ids-rule-file local.rules");
assert.match(setupTap.notes.join("\n"), /scenario ids-tap/);
assert.match(setupTap.notes.join("\n"), /no outbound allow path and no source NAT/);

const setupCustom = contextForPath("#/setup?scenario=custom&profile=throughput&insideZone=corp&outsideZone=wan&insideInterfaces=ens5%2Cens6&outsideInterfaces=ens4&insideCidr=10.44.0.0%2F20&webuiPort=9443&allowOutbound=1&masquerade=0&hardenHostInput=1&clampMss=1&flowOffload=0&manageNicOffloads=0");
assert.equal(setupCustom.cli[0].command, "ngfwctl policy baseline --profile throughput --inside-zone corp --outside-zone wan --inside-interface ens5 --inside-interface ens6 --outside-interface ens4 --inside-cidr 10.44.0.0/20 --webui-port 9443 --allow-outbound=true --masquerade=false --harden-host-input=true --flow-offload=false --clamp-mss=true --manage-nic-offloads=false");
assert.match(setupCustom.notes.join("\n"), /corp -> wan/);

const dashboard = contextForPath("/");
assert.ok(dashboard.endpoints.some((endpoint) => endpoint.path === "/v1/system/status"));
assert.ok(dashboard.endpoints.some((endpoint) => endpoint.path === "/v1/system/identity"));
assert.ok(dashboard.endpoints.some((endpoint) => endpoint.path === "/v1/system/release-acceptance/status"));
assert.ok(dashboard.endpoints.some((endpoint) => endpoint.path === "/v1/candidate/status"));
assert.ok(dashboard.cli.some((item) => item.command === "ngfwctl status"));
assert.ok(dashboard.cli.some((item) => item.command === "ngfwctl whoami"));
assert.ok(dashboard.cli.some((item) => item.command === "ngfwctl status # routing-vpn"));
assert.ok(dashboard.cli.some((item) => item.command === "ngfwctl system release-acceptance-status --json"));
assert.ok(dashboard.cli.some((item) => item.command === "ngfwctl policy status --json"));

const trafficSessionKey = "ct1%7Cipv4%7Ctcp%7C10.0.1.20%7C51515%7C203.0.113.20%7C443%7C203.0.113.20%7C443%7C10.0.1.20%7C51515";
const trafficSessions = contextForPath(`#/traffic?mode=sessions&ip=10.0.1.20&protocol=TCP&sessionState=ESTABLISHED&limit=100&sessionSort=packets&sessionKey=${trafficSessionKey}`);
assert.equal(trafficSessions.routeState.hash, `#/traffic?mode=sessions&ip=10.0.1.20&protocol=TCP&sessionState=ESTABLISHED&limit=100&sessionSort=packets&sessionKey=${trafficSessionKey}`);
assert.equal(trafficSessions.endpoints[0].path, "/v1/sessions?limit=100&ip=10.0.1.20&protocol=TCP&state=ESTABLISHED");
assert.equal(trafficSessions.cli[0].command, "ngfwctl sessions --limit 100 --ip 10.0.1.20 --protocol TCP --state ESTABLISHED");
assert.ok(trafficSessions.endpoints.some((endpoint) => endpoint.path === "/v1/system/status"));
assert.ok(trafficSessions.cli.some((item) => item.command === "ngfwctl status"));
assert.match(trafficSessions.notes[0], /sessionSort=packets/);
assert.match(trafficSessions.notes[0], /sessionKey=ct1\|ipv4\|tcp/);

const trafficFlows = contextForPath("#/traffic?mode=flows&ip=10.0.1.20&protocol=TCP&app=ssl&port=443&flowId=eve-42&limit=100");
assert.equal(trafficFlows.endpoints[0].path, "/v1/flows?limit=100&ip=10.0.1.20&protocol=TCP&app=ssl&port=443&flowId=eve-42");
assert.equal(trafficFlows.cli[0].command, "ngfwctl flows --limit 100 --ip 10.0.1.20 --protocol TCP --app ssl --port 443 --flow-id eve-42");
assert.ok(!trafficFlows.notes.join("\n").includes("flowId=eve-42"));

const trafficAppId = contextForPath("#/traffic?mode=app-id&q=unknown%20dns&observationKind=APP_ID_OBSERVATION_KIND_UNKNOWN&confidenceThreshold=50&limit=50");
assert.equal(trafficAppId.endpoints[0].path, "/v1/app-id/observations?limit=50&flowLimit=1000&confidenceThreshold=50&query=unknown+dns&kind=APP_ID_OBSERVATION_KIND_UNKNOWN");
assert.equal(trafficAppId.cli[0].command, "ngfwctl app-id observations --limit 50 --flow-limit 1000 --confidence-threshold 50 --query \"unknown dns\" --kind unknown");

const trafficAppIdFull = contextForPath("#/traffic?mode=app-id&q=ssl&observationKind=APP_ID_OBSERVATION_KIND_CONFLICTING_EVIDENCE&engineSignal=http&protocol=TCP&port=443&confidenceThreshold=65&flowLimit=2000&limit=100");
assert.equal(trafficAppIdFull.endpoints[0].path, "/v1/app-id/observations?limit=100&flowLimit=2000&confidenceThreshold=65&query=ssl&kind=APP_ID_OBSERVATION_KIND_CONFLICTING_EVIDENCE&engineSignal=http&protocol=TCP&port=443");
assert.equal(trafficAppIdFull.cli[0].command, "ngfwctl app-id observations --limit 100 --flow-limit 2000 --confidence-threshold 65 --query ssl --kind conflicting-evidence --engine-signal http --protocol TCP --port 443");

const trafficAppIdSelected = contextForPath("#/traffic?mode=app-id&queueId=qid-1&confidenceThreshold=70&flowLimit=1000&limit=100");
assert.equal(trafficAppIdSelected.endpoints[0].path, "/v1/app-id/observations?limit=100&flowLimit=1000&confidenceThreshold=70");
assert.equal(trafficAppIdSelected.endpoints[1].path, "/v1/app-id/replay:compare");
assert.match(trafficAppIdSelected.endpoints[1].body, /"queueId": "qid-1"/);
assert.match(trafficAppIdSelected.endpoints[1].body, /"expectedApp": "<expected-app-id>"/);
assert.equal(trafficAppIdSelected.endpoints[2].path, "/v1/app-id/observations/qid-1:stage");
assert.match(trafficAppIdSelected.endpoints[2].body, /"reason": "reviewed App-ID observation"/);
assert.equal(trafficAppIdSelected.endpoints[3].path, "/v1/app-id/observations/qid-1:stage-regression-sample");
assert.match(trafficAppIdSelected.endpoints[3].body, /"pcapSha256": "<capture-sha256>"/);
assert.match(trafficAppIdSelected.endpoints[3].body, /"expectedApp": "<expected-app-id>"/);
assert.equal(trafficAppIdSelected.cli[1].command, "ngfwctl app-id promote qid-1 --reason \"reviewed App-ID observation\" --flow-limit 1000 --confidence-threshold 70");
assert.equal(trafficAppIdSelected.cli[2].command, "ngfwctl app-id promote qid-1 --drop --confirm-drop --reason \"block repeated unknown app\" --flow-limit 1000 --confidence-threshold 70");
assert.equal(trafficAppIdSelected.cli[3].command, "ngfwctl app-id corpus add qid-1 --pcap-sha256 \"<capture-sha256>\" --expected-app \"<expected-app-id>\" --observed-app \"<observed-app-id>\" --reason \"reviewed App-ID observation\" --flow-limit 1000 --confidence-threshold 70");
assert.match(trafficAppIdSelected.notes.join("\n"), /Selected App-ID queue item: qid-1/);

const threatFilters = contextForPath("#/threats?threatSeverity=high&ip=10.0.1.10&signatureId=9000001&flowId=eve-42&limit=100");
assert.equal(threatFilters.endpoints[0].path, "/v1/alerts?limit=100&ip=10.0.1.10&threatSeverity=high&signatureId=9000001&flowId=eve-42");
assert.equal(threatFilters.cli[0].command, "ngfwctl alerts --limit 100 --ip 10.0.1.10 --threat-severity high --signature-id 9000001 --flow-id eve-42");
assert.ok(threatFilters.endpoints.some((endpoint) => endpoint.path === "/v1/system/status"));
assert.ok(threatFilters.cli.some((item) => item.command === "ngfwctl status"));

const logFilters = contextForPath("#/logs?source=engine&engine=suricata&severity=warn&q=degraded&limit=100&entry=abcdef1234567890");
assert.equal(logFilters.endpoints[0].path, "/v1/system/logs?limit=100&source=engine&engine=suricata&severity=warn&query=degraded");
assert.equal(logFilters.cli[0].command, "ngfwctl system logs --limit 100 --source engine --engine suricata --severity warn --query degraded");
assert.match(logFilters.notes.join("\n"), /entry=abcdef1234567890/);
assert.doesNotMatch(JSON.stringify(contextForPath("#/logs?q=/var/log/openngfw/secrets.log&limit=100")), /secrets\.log|\/var\/log/);

const auditFilters = contextForPath("#/changes?tab=audit&actor=alice&action=commit&version=7&query=prod&limit=500");
assert.equal(auditFilters.endpoints[0].path, "/v1/audit?limit=500&actor=alice&action=commit&version=7&query=prod");
assert.equal(auditFilters.cli[0].command, "ngfwctl audit --limit 500 --actor alice --action commit --version 7 --query prod --hashes");

const changesCandidate = contextForPath("#/changes");
assert.equal(changesCandidate.endpoints[0].path, "/v1/candidate/status");
assert.equal(changesCandidate.cli[0].command, "ngfwctl policy status --json");
assert.match(changesCandidate.notes[0], /candidate review/);

const changesInvalidTab = contextForPath("#/changes?tab=unknown");
assert.equal(changesInvalidTab.endpoints[0].path, "/v1/candidate/status");
assert.match(changesInvalidTab.notes[0], /candidate review/);

const changesVersionDiff = contextForPath("#/changes?tab=versions&version=7&drawer=diff");
assert.equal(changesVersionDiff.endpoints[0].path, "/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_VERSION&toVersion=7");
assert.equal(changesVersionDiff.cli[0].command, "ngfwctl policy show --source version --version 7 --json");
assert.match(changesVersionDiff.notes.join("\n"), /Current Changes drawer: diff for version v7/);
assert.match(changesVersionDiff.notes.join("\n"), /route-backed/);

const changesVersionRollback = contextForPath("#/changes?tab=versions&version=7&drawer=rollback");
assert.equal(changesVersionRollback.endpoints[0].path, "/v1/rollback");
assert.equal(changesVersionRollback.endpoints[0].method, "POST");
assert.match(changesVersionRollback.endpoints[0].body, /"version": "7"/);
assert.equal(changesVersionRollback.cli[0].command, "ngfwctl rollback 7 --ack-risk -m \"restore known good\"");
assert.match(changesVersionRollback.notes.join("\n"), /Current Changes drawer: rollback review for version v7/);

const rules = contextForPath("/rules");
assert.ok(rules.endpoints.some((endpoint) => endpoint.method === "PUT" && endpoint.path === "/v1/candidate"));
assert.ok(rules.endpoints.some((endpoint) => endpoint.path === "/v1/candidate/validate"));
assert.ok(rules.endpoints.some((endpoint) => endpoint.path === "/v1/candidate/status"));
assert.ok(rules.endpoints.some((endpoint) => endpoint.path === "/v1/commit"));
assert.ok(rules.endpoints.some((endpoint) => endpoint.path.includes("/v1/policy/diff")));
assert.ok(rules.endpoints.some((endpoint) => endpoint.path === "/v1/explain/flow"));
assert.ok(rules.cli.some((item) => item.command.includes("ngfwctl policy diff")));
assert.deepEqual(rules.workflow.map((step) => step.title), [
  "Inspect baseline",
  "Stage candidate",
  "Check candidate status",
  "Validate candidate",
  "Review diff",
  "Commit candidate",
  "Rollback or discard",
]);
const rulesRunbook = workflowRunbookText(rules, { origin: "https://fw.example.com" });
assert.match(rulesRunbook, /Workflow runbook:/);
assert.match(rulesRunbook, /1\. Inspect baseline/);
assert.match(rulesRunbook, /2\. Stage candidate/);
assert.match(rulesRunbook, /PUT \/v1\/candidate/);
assert.match(rulesRunbook, /POST \/v1\/candidate\/validate/);
assert.match(rulesRunbook, /GET \/v1\/policy\/diff\?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE/);
assert.match(rulesRunbook, /POST \/v1\/commit/);
assert.match(rulesRunbook, /ngfwctl policy status --json/);
assert.match(rulesRunbook, /ngfwctl policy validate/);
assert.match(rulesRunbook, /ngfwctl policy diff/);
assert.match(rulesRunbook, /ngfwctl commit -m "reviewed policy change"/);
assert.match(rulesRunbook, /NGFW_TOKEN_FILE/);
const replayValidationRequest = automationReplayValidationRequest(appendAutomationRecording(emptyAutomationRecording({ origin: "https://fw.example.com" }), rules, { origin: "https://fw.example.com" }), "sha256:candidate");
assert.equal(replayValidationRequest.candidateRevision, "sha256:candidate");
assert.equal(replayValidationRequest.executionMode, "validate");
assert.equal(replayValidationRequest.requireAcknowledgements, true);
assert.equal(replayValidationRequest.requireCandidateRevision, true);
assert.equal(replayValidationRequest.recording.schemaVersion, "phragma.webui.automation-recorder.v1");
assert.ok(replayValidationRequest.recording.steps.length >= 1);
const replayDryRunRequest = automationReplayDryRunRequest(replayValidationRequest.recording, "sha256:candidate");
assert.equal(replayDryRunRequest.executionMode, "dry-run");
assert.equal(replayDryRunRequest.candidateRevision, "sha256:candidate");
const replayAuthorityRequest = automationReplayApplyAuthorityRequest(replayValidationRequest.recording, "sha256:candidate", {
  ackCandidateOnlyReplay: true,
  ackCandidateRevision: true,
  ackReadOnlyReplay: true,
});
assert.equal(replayAuthorityRequest.executionMode, "apply-authority");
assert.equal(replayAuthorityRequest.acknowledgements.ackReplayAuthority, true);
assert.equal(replayAuthorityRequest.acknowledgements.ackReplayNoLiveApply, true);
assert.equal(replayAuthorityRequest.acknowledgements.ackCandidateOnlyReplay, true);
assert.equal(replayAuthorityRequest.acknowledgements.ackCandidateRevision, true);
assert.equal(replayAuthorityRequest.acknowledgements.ackReadOnlyReplay, true);
const replayExecuteRequest = automationReplayExecuteRequest(replayValidationRequest.recording, "sha256:candidate", {
  ackCandidateOnlyReplay: true,
  ackCandidateRevision: true,
});
assert.equal(replayExecuteRequest.executionMode, "execute");
assert.equal(replayExecuteRequest.acknowledgements.ackReplayAuthority, true);
assert.equal(replayExecuteRequest.acknowledgements.ackReplayNoLiveApply, true);
assert.equal(replayExecuteRequest.acknowledgements.ackCandidateOnlyReplay, true);
assert.equal(replayExecuteRequest.acknowledgements.ackCandidateRevision, true);
assert.equal(replayExecuteRequest.requireAcknowledgements, true);
assert.equal(replayExecuteRequest.requireCandidateRevision, true);
const rulesFocused = contextForPath("#/rules?q=missing-log&action=ACTION_ALLOW&zone=lan&tag=owner%3Aweb&changed=1&density=compact&group=tag&simSource=POLICY_SOURCE_CANDIDATE&simFrom=lan&simTo=dmz&simProtocol=PROTOCOL_TCP&simApp=web-browsing&simSrc=10.0.1.20&simSport=51515&simDst=10.0.2.20&simDport=443&simRun=1");
assert.equal(rulesFocused.endpoints[0].method, "POST");
assert.equal(rulesFocused.endpoints[0].path, "/v1/explain/flow");
assert.match(rulesFocused.endpoints[0].body, /"policySource": "POLICY_SOURCE_CANDIDATE"/);
assert.match(rulesFocused.endpoints[0].body, /"appId": "web-browsing"/);
assertFlatExplainBodies("rules", rules, { srcIp: "10.0.1.20", destIp: "10.0.2.20" });
assertFirstFlatExplainBody("rules focused", rulesFocused, {
  policySource: "POLICY_SOURCE_CANDIDATE",
  fromZone: "lan",
  toZone: "dmz",
  srcIp: "10.0.1.20",
  destIp: "10.0.2.20",
});
assert.equal(rulesFocused.cli[0].command, "ngfwctl explain --source candidate --from-zone lan --to-zone dmz --src 10.0.1.20 --sport 51515 --dst 10.0.2.20 --dport 443 --protocol tcp --app-id web-browsing");
assert.ok(rulesFocused.endpoints.some((endpoint) => endpoint.path === "/v1/policy?source=POLICY_SOURCE_CANDIDATE"));
assert.ok(rulesFocused.endpoints.some((endpoint) => endpoint.path === "/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE"));
assert.ok(rulesFocused.cli.some((item) => item.command === "ngfwctl policy show --source candidate --json"));
assert.match(rulesFocused.notes.join("\n"), /density=compact, group=tag, changed-only=on/);
assert.match(rulesFocused.notes.join("\n"), /selected rule indexes are never encoded/);
assert.match(rulesFocused.notes.join("\n"), /pause drag reorder/);
assert.match(rulesFocused.notes.join("\n"), /q=missing-log/);
const rulesOverlapDrawer = contextForPath("#/rules?q=server-overlap&drawer=server-overlap-review&density=compact");
assert.equal(rulesOverlapDrawer.routeState.hash, "#/rules?q=server-overlap&drawer=server-overlap-review&density=compact");
assert.equal(rulesOverlapDrawer.endpoints[0].path, "/v1/policy?source=POLICY_SOURCE_CANDIDATE");
assert.match(rulesOverlapDrawer.endpoints[0].purpose, /server-side overlap peer/);
assert.ok(rulesOverlapDrawer.endpoints.some((endpoint) => endpoint.method === "POST" && endpoint.path === "/v1/candidate/validate" && /server-side overlap/.test(endpoint.purpose)));
assert.ok(rulesOverlapDrawer.endpoints.some((endpoint) => endpoint.path === "/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE"));
assert.equal(rulesOverlapDrawer.cli[0].command, "ngfwctl policy show --source candidate --json");
assert.match(rulesOverlapDrawer.cli[0].purpose, /candidate rule order/);
assert.ok(rulesOverlapDrawer.cli.some((item) => item.command === "ngfwctl policy validate" && /server overlap/.test(item.purpose)));
assert.ok(rulesOverlapDrawer.cli.some((item) => item.command === "ngfwctl policy diff"));
assert.match(rulesOverlapDrawer.notes.join("\n"), /Current Rules drawer: server overlap review/);
assert.match(rulesOverlapDrawer.notes.join("\n"), /first-match order/);
assert.match(rulesOverlapDrawer.notes.join("\n"), /stale findings/);
assert.doesNotMatch(rulesOverlapDrawer.notes.join("\n"), /drawer=server-overlap-review is UI-only/);

const objects = contextForPath("/objects");
assert.ok(objects.endpoints.some((endpoint) => endpoint.path.includes("/v1/policy/object-references")));
const objectServices = contextForPath("#/objects?tab=services");
assert.equal(objectServices.routeState.hash, "#/objects?tab=services");
assert.equal(objectServices.endpoints[0].path, "/v1/policy/object-references?source=POLICY_SOURCE_CANDIDATE&kind=POLICY_OBJECT_KIND_SERVICE");
assert.equal(objectServices.cli[0].command, "ngfwctl policy references --source candidate --kind service");
assert.equal(objectServices.cli[1].command, "ngfwctl policy show --source candidate --json");
assert.match(objectServices.notes.join("\n"), /Current Objects tab: services/);
assert.match(objectServices.notes.join("\n"), /draft values are never encoded/);
const objectReferenceDrawer = contextForPath("#/objects?tab=services&drawer=references&object=https");
assert.equal(objectReferenceDrawer.routeState.hash, "#/objects?tab=services&drawer=references&object=https");
assert.equal(objectReferenceDrawer.endpoints[0].path, "/v1/policy/object-references?source=POLICY_SOURCE_CANDIDATE&kind=POLICY_OBJECT_KIND_SERVICE&name=https");
assert.match(objectReferenceDrawer.endpoints[0].purpose, /for https/);
assert.equal(objectReferenceDrawer.cli[0].command, "ngfwctl policy references --source candidate --kind service --name https");
assert.match(objectReferenceDrawer.cli[0].purpose, /services for https/);
assert.equal(objectReferenceDrawer.cli[1].command, "ngfwctl policy show --source candidate --json");
assert.match(objectReferenceDrawer.notes.join("\n"), /Current Objects drawer: references for https/);
assert.match(objectReferenceDrawer.notes.join("\n"), /route-backed/);
assert.match(objectReferenceDrawer.notes.join("\n"), /draft values are never encoded/);
const objectInvalidTab = contextForPath("#/objects?tab=bad");
assert.equal(objectInvalidTab.endpoints[0].path, "/v1/policy/object-references?source=POLICY_SOURCE_CANDIDATE&kind=POLICY_OBJECT_KIND_ADDRESS");
assert.match(objectInvalidTab.notes.join("\n"), /Current Objects tab: addresses/);
const objectSecurityProfiles = contextForPath("#/objects?tab=securityProfiles");
assert.equal(objectSecurityProfiles.endpoints[0].path, "/v1/policy/object-references?source=POLICY_SOURCE_CANDIDATE&kind=POLICY_OBJECT_KIND_SECURITY_PROFILE");
assert.match(objectSecurityProfiles.notes.join("\n"), /Current Objects tab: securityProfiles/);
const objectTrafficControls = contextForPath("#/objects?tab=trafficControls");
assert.equal(objectTrafficControls.endpoints[0].path, "/v1/policy/object-references?source=POLICY_SOURCE_CANDIDATE&kind=POLICY_OBJECT_KIND_QOS_PROFILE");
assert.equal(objectTrafficControls.endpoints[1].path, "/v1/policy/object-references?source=POLICY_SOURCE_CANDIDATE&kind=POLICY_OBJECT_KIND_ZONE_PROTECTION_PROFILE");
assert.equal(objectTrafficControls.cli[0].command, "ngfwctl policy references --source candidate --kind qos-profile");
assert.equal(objectTrafficControls.cli[1].command, "ngfwctl policy references --source candidate --kind zone-protection-profile");
const objectTrafficControlDrawer = contextForPath("#/objects?tab=trafficControls&drawer=references&object=latency-critical");
assert.equal(objectTrafficControlDrawer.endpoints[0].path, "/v1/policy/object-references?source=POLICY_SOURCE_CANDIDATE&kind=POLICY_OBJECT_KIND_QOS_PROFILE&name=latency-critical");
assert.equal(objectTrafficControlDrawer.endpoints[1].path, "/v1/policy/object-references?source=POLICY_SOURCE_CANDIDATE&kind=POLICY_OBJECT_KIND_ZONE_PROTECTION_PROFILE&name=latency-critical");
assert.equal(objectTrafficControlDrawer.cli[0].command, "ngfwctl policy references --source candidate --kind qos-profile --name latency-critical");
assert.equal(objectTrafficControlDrawer.cli[1].command, "ngfwctl policy references --source candidate --kind zone-protection-profile --name latency-critical");
const objectSecurityProfileImpactDrawer = contextForPath("#/objects?tab=securityProfiles&drawer=impact&object=inspect-standard");
assert.equal(objectSecurityProfileImpactDrawer.routeState.hash, "#/objects?tab=securityProfiles&drawer=impact&object=inspect-standard");
assert.equal(objectSecurityProfileImpactDrawer.endpoints[0].path, "/v1/policy/object-references?source=POLICY_SOURCE_CANDIDATE&kind=POLICY_OBJECT_KIND_SECURITY_PROFILE&name=inspect-standard");
assert.equal(objectSecurityProfileImpactDrawer.endpoints[1].path, "/v1/policy?source=POLICY_SOURCE_CANDIDATE");
assert.equal(objectSecurityProfileImpactDrawer.endpoints[2].path, "/v1/candidate/validate");
assert.equal(objectSecurityProfileImpactDrawer.endpoints[3].path, "/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE");
assert.equal(objectSecurityProfileImpactDrawer.cli[0].command, "ngfwctl policy references --source candidate --kind security-profile --name inspect-standard");
assert.equal(objectSecurityProfileImpactDrawer.cli[1].command, "ngfwctl policy show --source candidate --json");
assert.equal(objectSecurityProfileImpactDrawer.cli[2].command, "ngfwctl policy validate");
assert.equal(objectSecurityProfileImpactDrawer.cli[3].command, "ngfwctl policy diff");
assert.match(objectSecurityProfileImpactDrawer.notes.join("\n"), /security profile impact for inspect-standard/);
assert.match(objectSecurityProfileImpactDrawer.notes.join("\n"), /candidate rule blast radius/);
assert.match(objectSecurityProfileImpactDrawer.notes.join("\n"), /remain hardening evidence/);

const nat = contextForPath("/nat");
assert.match(nat.summary, /Path preview compares running and candidate/);
assert.ok(nat.endpoints.some((endpoint) => endpoint.path === "/v1/explain/flow" && endpoint.body.includes("POLICY_SOURCE_RUNNING")));
assert.ok(nat.endpoints.some((endpoint) => endpoint.path === "/v1/explain/flow" && endpoint.body.includes("POLICY_SOURCE_CANDIDATE")));
assertFlatExplainBodies("nat", nat, { destIp: "203.0.113.10" });
assert.ok(nat.cli.some((item) => item.command.includes("ngfwctl explain --source running")));
assert.ok(nat.cli.some((item) => item.command.includes("ngfwctl explain --source candidate")));
const natPreviewRoute = contextForPath("#/nat?fromZone=untrust&toZone=dmz&protocol=PROTOCOL_TCP&srcIp=198.51.100.55&srcPort=52525&destIp=203.0.113.21&destPort=9443&run=1&caseKey=publish-web-entry");
assert.equal(natPreviewRoute.routeState.hash, "#/nat?fromZone=untrust&toZone=dmz&protocol=PROTOCOL_TCP&srcIp=198.51.100.55&srcPort=52525&destIp=203.0.113.21&destPort=9443&run=1&caseKey=publish-web-entry");
assert.equal(natPreviewRoute.endpoints[0].method, "POST");
assert.equal(natPreviewRoute.endpoints[0].path, "/v1/explain/flow");
assert.equal(natPreviewRoute.endpoints[1].path, "/v1/explain/flow");
assert.match(natPreviewRoute.endpoints[0].body, /"policySource": "POLICY_SOURCE_RUNNING"/);
assert.match(natPreviewRoute.endpoints[1].body, /"policySource": "POLICY_SOURCE_CANDIDATE"/);
assertFirstFlatExplainBody("nat preview route", natPreviewRoute, {
  policySource: "POLICY_SOURCE_RUNNING",
  fromZone: "untrust",
  toZone: "dmz",
  srcIp: "198.51.100.55",
  srcPort: 52525,
  destIp: "203.0.113.21",
  destPort: 9443,
});
assert.ok(natPreviewRoute.cli.some((item) => item.command === "ngfwctl explain --source running --from-zone untrust --to-zone dmz --src 198.51.100.55 --sport 52525 --dst 203.0.113.21 --dport 9443 --protocol tcp"));
assert.ok(natPreviewRoute.cli.some((item) => item.command === "ngfwctl explain --source candidate --from-zone untrust --to-zone dmz --src 198.51.100.55 --sport 52525 --dst 203.0.113.21 --dport 9443 --protocol tcp"));
assert.match(natPreviewRoute.notes.join("\n"), /Current NAT preview tuple: 198\.51\.100\.55:52525 -> 203\.0\.113\.21:9443 tcp/);
assert.match(natPreviewRoute.notes.join("\n"), /caseKey=publish-web-entry/);

const inspection = contextForPath("/inspection");
assert.equal(inspection.title, "Inspection");
assert.ok(inspection.workflow.length > 0);
assert.ok(inspection.endpoints.some((endpoint) => endpoint.path === "/v1/system/status"));
assert.ok(inspection.endpoints.some((endpoint) => endpoint.path === "/v1/intel/content/packages"));
assert.ok(inspection.endpoints.some((endpoint) => endpoint.path === "/v1/alerts?limit=200"));
assert.ok(inspection.cli.some((item) => item.command === "ngfwctl status"));
assert.ok(inspection.cli.some((item) => item.command === "ngfwctl intel content"));
assert.match(inspection.notes.join("\n"), /Suricata detect\/prevent runtime changes after validation and commit/);

const proxy = contextForPath("/proxy");
assert.match(proxy.summary, /runtime-readiness evidence/);
assert.match(proxy.summary, /active listener\/cutover execution remains external/);
assert.ok(proxy.endpoints.some((endpoint) => endpoint.method === "POST" && endpoint.path === "/v1/system/runtime-readiness:check" && /planned-not-executed proxy daemon/.test(endpoint.purpose)));
assert.ok(proxy.cli.some((item) => item.command === "ngfwctl status" && /proxy engine readiness/.test(item.purpose)));
assert.match(proxy.notes.join("\n"), /planned-only/);
assert.match(proxy.notes.join("\n"), /execute listener cutover\/rollback/);
assert.match(proxy.notes.join("\n"), /active traffic proof and packet inspection execution remain hardening/);

const netvpn = contextForPath("/netvpn");
assert.match(netvpn.summary, /staticRoutes/);
assert.match(netvpn.summary, /vpn\.wireguardInterfaces/);
assert.ok(netvpn.endpoints.some((endpoint) => endpoint.path === "/v1/system/status"));
assert.ok(netvpn.endpoints.some((endpoint) => endpoint.path === "/v1/explain/flow" && endpoint.body.includes("POLICY_SOURCE_CANDIDATE")));
assert.ok(netvpn.endpoints.some((endpoint) => endpoint.path.includes("/v1/sessions?protocol=UDP&port=51820")));
assert.ok(netvpn.cli.some((item) => item.command === "ngfwctl status"));
assert.ok(netvpn.cli.some((item) => item.command === "ngfwctl policy route list --source candidate"));
assert.ok(netvpn.cli.some((item) => item.command.includes("ngfwctl policy route add --destination 10.20.0.0/24")));
assert.ok(netvpn.cli.some((item) => item.command === "ngfwctl policy route delete --destination 10.20.0.0/24"));
assert.ok(netvpn.cli.some((item) => item.command.includes("ngfwctl policy show --source candidate --json")));
assert.ok(netvpn.cli.some((item) => item.command.includes("ngfwctl explain --source candidate")));
assert.ok(netvpn.cli.some((item) => item.command.includes("ngfwctl sessions --protocol UDP --port 51820")));
assert.ok(netvpn.cli.some((item) => item.command === "ngfwctl commit -m \"update routing and VPN\""));
assert.match(netvpn.notes.join("\n"), /Secret material never enters policy/);
assert.match(netvpn.notes.join("\n"), /Static routes now have granular CLI operations/);
assert.match(netvpn.notes.join("\n"), /until dedicated granular APIs exist/);
assertFlatExplainBodies("netvpn", netvpn, { fromZone: "lan", toZone: "vpn" });
const netvpnWireguardTunnel = contextForPath("#/netvpn?drawer=tunnel&kind=wireguard&iface=wg0&peer=laptop&local=10.99.0.1/24&remote=10.120.0.0/24&src=10.99.0.1&dst=10.120.0.1&protocol=PROTOCOL_ANY&port=51820");
assert.match(netvpnWireguardTunnel.routeState.hash, /#\/netvpn\?drawer=tunnel&kind=wireguard&iface=wg0&peer=laptop/);
assert.ok(netvpnWireguardTunnel.endpoints.some((endpoint) => endpoint.path === "/v1/system/status"));
assert.ok(netvpnWireguardTunnel.endpoints.some((endpoint) => endpoint.path === "/v1/policy?source=POLICY_SOURCE_CANDIDATE"));
assert.ok(netvpnWireguardTunnel.endpoints.some((endpoint) => endpoint.path === "/v1/explain/flow" && endpoint.body.includes("10.99.0.1") && endpoint.body.includes("10.120.0.1") && endpoint.body.includes("PROTOCOL_ANY")));
assert.ok(netvpnWireguardTunnel.endpoints.some((endpoint) => endpoint.path === "/v1/sessions?protocol=UDP&port=51820&limit=100"));
assert.ok(netvpnWireguardTunnel.cli.some((item) => item.command === "ngfwctl status"));
assert.ok(netvpnWireguardTunnel.cli.some((item) => item.command === "ngfwctl policy show --source candidate --json"));
assert.ok(netvpnWireguardTunnel.cli.some((item) => item.command.includes("ngfwctl explain --source candidate") && item.command.includes("--src 10.99.0.1") && item.command.includes("--dst 10.120.0.1") && item.command.includes("--dport 51820")));
assert.ok(netvpnWireguardTunnel.cli.some((item) => item.command === "ngfwctl sessions --protocol UDP --port 51820 --limit 100"));
assert.match(netvpnWireguardTunnel.notes.join("\n"), /wireguard tunnel wg0:laptop/);
assert.match(netvpnWireguardTunnel.notes.join("\n"), /10\.99\.0\.1\/24 -> 10\.120\.0\.0\/24/);
assert.match(netvpnWireguardTunnel.notes.join("\n"), /secret file paths, private keys, PSKs/);
assertFirstFlatExplainBody("netvpn wireguard tunnel", netvpnWireguardTunnel, { srcIp: "10.99.0.1", destIp: "10.120.0.1", protocol: "PROTOCOL_ANY" });
const netvpnWireguardText = automationContextText(netvpnWireguardTunnel, { origin: "https://fw.example.com" });
assert.match(netvpnWireguardText, /#\/netvpn\?drawer=tunnel&kind=wireguard&iface=wg0&peer=laptop/);
assert.match(netvpnWireguardText, /GET \/v1\/policy\?source=POLICY_SOURCE_CANDIDATE/);
assert.match(netvpnWireguardText, /POST \/v1\/explain\/flow/);
assert.match(netvpnWireguardText, /10\.120\.0\.1/);
assert.match(netvpnWireguardText, /ngfwctl sessions --protocol UDP --port 51820 --limit 100/);
assert.doesNotMatch(netvpnWireguardText, /\/etc\/(?:phragma|openngfw)\/(?:keys|secrets)|privateKey|pskFile|BEGIN PRIVATE KEY|writer:secret/i);
const netvpnIpsecTunnel = contextForPath("#/netvpn?drawer=tunnel&kind=ipsec&name=site-b&local=10.100.1.0/24&remote=10.120.0.0/24&src=10.100.1.1&dst=10.120.0.1&protocol=PROTOCOL_ANY&port=4500");
assert.match(netvpnIpsecTunnel.routeState.hash, /#\/netvpn\?drawer=tunnel&kind=ipsec&name=site-b/);
assert.ok(netvpnIpsecTunnel.endpoints.some((endpoint) => endpoint.path === "/v1/sessions?protocol=UDP&port=4500&limit=100"));
assert.ok(netvpnIpsecTunnel.cli.some((item) => item.command === "ngfwctl sessions --protocol UDP --port 4500 --limit 100"));
assert.match(netvpnIpsecTunnel.notes.join("\n"), /ipsec tunnel site-b/);
assert.match(netvpnIpsecTunnel.notes.join("\n"), /10\.100\.1\.0\/24 -> 10\.120\.0\.0\/24/);
assertFirstFlatExplainBody("netvpn ipsec tunnel", netvpnIpsecTunnel, { srcIp: "10.100.1.1", destIp: "10.120.0.1", protocol: "PROTOCOL_ANY" });

const traffic = contextForPath("/traffic");
assert.ok(traffic.endpoints.some((endpoint) => endpoint.path === "/v1/system/status"));
assert.ok(traffic.cli.some((item) => item.command === "ngfwctl status"));
assert.ok(traffic.cli.some((item) => item.command === "ngfwctl app-id observations --limit 100"));
assertFlatExplainBodies("traffic", traffic, { srcIp: "10.0.1.20", destIp: "10.0.2.20" });

const threats = contextForPath("/threats");
assert.ok(threats.endpoints.some((endpoint) => endpoint.path === "/v1/system/status"));
assert.ok(threats.endpoints.some((endpoint) => endpoint.path === "/v1/threat-exceptions:stage"));
assert.ok(threats.cli.some((item) => item.command === "ngfwctl status"));
assert.ok(threats.cli.some((item) => item.command === "ngfwctl alerts --threat-severity high --limit 50"));
assert.ok(!threats.cli.some((item) => item.command.includes("alerts --severity high")));
const threatExceptions = contextForPath("#/threats?view=exceptions");
assert.equal(threatExceptions.routeState.hash, "#/threats?view=exceptions");
assert.ok(threatExceptions.endpoints.some((endpoint) => endpoint.path === "/v1/threat-exceptions"));
assert.ok(threatExceptions.cli.some((item) => item.command === "ngfwctl threat-exceptions list --source effective"));
assert.match(threatExceptions.notes.join("\n"), /candidate policy only/);
const selectedExceptionName = "fp-9000001-source-10-0-1-10";
const selectedThreatException = contextForPath(`#/threats?view=exceptions&exception=${selectedExceptionName}`);
assert.equal(selectedThreatException.routeState.hash, `#/threats?view=exceptions&exception=${selectedExceptionName}`);
assert.ok(selectedThreatException.endpoints.some((endpoint) => endpoint.method === "PATCH" && endpoint.path === `/v1/threat-exceptions/${selectedExceptionName}`));
assert.ok(selectedThreatException.endpoints.some((endpoint) => endpoint.method === "POST" && endpoint.path === `/v1/threat-exceptions/${selectedExceptionName}:set-state`));
assert.ok(selectedThreatException.endpoints.some((endpoint) => endpoint.method === "POST" && endpoint.path === `/v1/threat-exceptions/${selectedExceptionName}:remove`));
assert.ok(selectedThreatException.endpoints.some((endpoint) => endpoint.path === "/v1/candidate/validate"));
assert.ok(selectedThreatException.endpoints.some((endpoint) => endpoint.path === "/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE"));
assert.ok(selectedThreatException.cli.some((item) => item.command.includes(`ngfwctl threat-exceptions update ${selectedExceptionName}`)));
assert.ok(selectedThreatException.cli.some((item) => item.command.includes(`ngfwctl threat-exceptions disable ${selectedExceptionName}`)));
assert.ok(selectedThreatException.cli.some((item) => item.command.includes(`ngfwctl threat-exceptions enable ${selectedExceptionName}`)));
assert.ok(selectedThreatException.cli.some((item) => item.command.includes(`ngfwctl threat-exceptions remove ${selectedExceptionName}`)));
assert.ok(selectedThreatException.cli.some((item) => item.command === "ngfwctl policy validate"));
assert.ok(selectedThreatException.cli.some((item) => item.command === "ngfwctl policy diff"));
const selectedThreatSession = automationWorkflowSession(selectedThreatException, { origin: "https://fw.example.com" });
assert.equal(selectedThreatSession.schemaVersion, "phragma.webui.workflow-session.v1");
assert.equal(selectedThreatSession.routeState.hash, `#/threats?view=exceptions&exception=${selectedExceptionName}`);
assert.equal(selectedThreatSession.custody.serverStored, false);
assert.equal(selectedThreatSession.custody.signed, false);
assert.ok(selectedThreatSession.endpoints.some((endpoint) => endpoint.path === `/v1/threat-exceptions/${selectedExceptionName}:remove`));
const selectedThreatText = automationContextText(contextForPath("#/threats?view=exceptions&exception=fp-9000001-source-10-0-1-10&token=Bearer-secret-token&path=/etc/passwd"), { origin: "https://fw.example.com" });
assert.match(selectedThreatText, /\/v1\/threat-exceptions\/fp-9000001-source-10-0-1-10:set-state/);
assert.match(selectedThreatText, /ngfwctl threat-exceptions remove fp-9000001-source-10-0-1-10/);
assert.doesNotMatch(selectedThreatText, /Bearer-secret-token|\/etc\/passwd|token =|path =/i);

const troubleshoot = contextForPath("/troubleshoot");
assert.match(troubleshoot.summary, /running-vs-candidate comparison/);
assert.match(troubleshoot.summary, /reviewed remediation/);
assert.ok(troubleshoot.endpoints.some((endpoint) => endpoint.body.includes("POLICY_SOURCE_RUNNING")));
assert.ok(troubleshoot.endpoints.some((endpoint) => endpoint.body.includes("POLICY_SOURCE_CANDIDATE")));
assert.ok(troubleshoot.endpoints.some((endpoint) => endpoint.path === "/v1/system/packet-captures/plan"));
assert.ok(troubleshoot.endpoints.some((endpoint) => endpoint.path === "/v1/system/packet-captures"));
assert.ok(troubleshoot.endpoints.some((endpoint) => endpoint.path === "/v1/system/packet-captures/phragma-web-20260618T121500Z:set-retention"));
assert.ok(troubleshoot.endpoints.some((endpoint) => endpoint.method === "PUT" && endpoint.path === "/v1/candidate"));
const captureStart = troubleshoot.endpoints.find((endpoint) => endpoint.path === "/v1/system/packet-captures");
assert.match(captureStart.body, /"protocol": "PROTOCOL_TCP"/);
assert.match(captureStart.body, /"packetCount": 500/);
assert.doesNotMatch(captureStart.body, /packetLimit/);
const captureRetention = troubleshoot.endpoints.find((endpoint) => endpoint.path === "/v1/system/packet-captures/phragma-web-20260618T121500Z:set-retention");
assert.match(captureRetention.body, /"state": "PACKET_CAPTURE_RETENTION_STATE_RETAINED"/);
assert.match(captureRetention.body, /"ackRetentionChange": true/);
assert.ok(troubleshoot.cli.some((item) => item.command.includes("ngfwctl explain --source running")));
assert.ok(troubleshoot.cli.some((item) => item.command.includes("ngfwctl explain --source candidate")));
assert.ok(troubleshoot.cli.some((item) => item.command.includes("ngfwctl system capture --start --ack-capture")));
assert.ok(troubleshoot.cli.some((item) => item.command.includes("ngfwctl system capture retain")));
assert.ok(troubleshoot.cli.some((item) => item.command.includes("ngfwctl system capture release")));

const exactTroubleshoot = contextForPath("#/troubleshoot?source=POLICY_SOURCE_CANDIDATE&fromZone=lan&toZone=wan&src=10.0.1.20&sport=51515&dst=203.0.113.10&dport=443&protocol=tcp&app=web-browsing&runtime=1&flowId=eve-1&run=1&intent=capture&captureInterface=ens5&captureDuration=30&capturePackets=600&captureSnaplen=1600");
assert.equal(exactTroubleshoot.endpoints[0].path, "/v1/explain/flow");
assert.equal(exactTroubleshoot.endpoints[0].method, "POST");
assert.match(exactTroubleshoot.endpoints[0].body, /"policySource": "POLICY_SOURCE_CANDIDATE"/);
assert.match(exactTroubleshoot.endpoints[0].body, /"srcIp": "10\.0\.1\.20"/);
assert.match(exactTroubleshoot.endpoints[0].body, /"includeRuntime": true/);
assertFlatExplainBodies("troubleshoot", troubleshoot, { srcIp: "10.0.1.20", destIp: "10.0.2.20" });
assertFirstFlatExplainBody("exact troubleshoot", exactTroubleshoot, {
  policySource: "POLICY_SOURCE_CANDIDATE",
  fromZone: "lan",
  toZone: "wan",
  srcIp: "10.0.1.20",
  destIp: "203.0.113.10",
});
assert.equal(exactTroubleshoot.cli[0].command, "ngfwctl explain --source candidate --from-zone lan --to-zone wan --src 10.0.1.20 --sport 51515 --dst 203.0.113.10 --dport 443 --protocol tcp --app-id web-browsing --runtime --flow-id eve-1");
assert.equal(exactTroubleshoot.endpoints[1].path, "/v1/system/packet-captures/plan");
assert.equal(exactTroubleshoot.endpoints[2].path, "/v1/system/packet-captures");
assert.match(exactTroubleshoot.endpoints[1].body, /"interface": "ens5"/);
assert.match(exactTroubleshoot.endpoints[1].body, /"durationSeconds": 30/);
assert.match(exactTroubleshoot.endpoints[1].body, /"packetCount": 600/);
assert.match(exactTroubleshoot.endpoints[1].body, /"snaplenBytes": 1600/);
assert.match(exactTroubleshoot.endpoints[2].body, /"ackCapture": true/);
assert.equal(exactTroubleshoot.cli[1].command, "ngfwctl system capture --interface ens5 --protocol tcp --src 10.0.1.20 --sport 51515 --dst 203.0.113.10 --dport 443 --duration 30 --packets 600 --snaplen 1600 --flow-id eve-1");
assert.equal(exactTroubleshoot.cli[2].command, "ngfwctl system capture --start --ack-capture --interface ens5 --protocol tcp --src 10.0.1.20 --sport 51515 --dst 203.0.113.10 --dport 443 --duration 30 --packets 600 --snaplen 1600 --flow-id eve-1");
assert.match(exactTroubleshoot.notes[0], /run=1/);
assert.match(exactTroubleshoot.notes[1], /packet-capture follow-up/);

const investigation = contextForPath("/investigation");
assert.equal(investigation.title, "Investigation");
assert.ok(investigation.endpoints.some((endpoint) => endpoint.path === "/v1/explain/flow"));
assert.ok(investigation.endpoints.some((endpoint) => endpoint.path === "/v1/system/packet-captures/plan"));
assert.ok(investigation.cli.some((item) => item.command.includes("ngfwctl system capture")));
assert.match(investigation.notes.join("\n"), /browser storage/);
assert.match(investigation.notes.join("\n"), /does not mutate policy directly/);
assertFlatExplainBodies("investigation", investigation, { srcIp: "10.0.1.20", destIp: "10.0.2.20" });

const settings = contextForPath("/settings");
const logout = settings.endpoints.find((endpoint) => endpoint.path === "/v1/auth/logout");
assert.equal(logout.browserOnly, true);
const settingsText = automationContextText(settings, { origin: "https://fw.example.com" });
assert.match(settingsText, /POST \/v1\/auth\/logout - End the current browser SSO session/);
assert.match(settingsText, /browser session: uses the active WebUI cookie and CSRF token/);
assert.doesNotMatch(settingsText, /curl: .*\/v1\/auth\/logout/);
const settingsRunbook = workflowRunbookText(settings, { origin: "https://fw.example.com" });
assert.doesNotMatch(settingsRunbook, /\/v1\/auth\/logout/);
const settingsPanel = contextForPath("#/settings?panel=network");
assert.equal(settingsPanel.routeState.hash, "#/settings?panel=network");
assert.equal(settingsPanel.endpoints[0].path, "/v1/policy?source=POLICY_SOURCE_CANDIDATE");
assert.equal(settingsPanel.cli[0].command, "ngfwctl policy network set --mtu 9000 --clamp-mss on --manage-nic-offloads on");
assert.match(settingsPanel.notes.join("\n"), /Current Settings panel: network/);
const settingsPanelText = automationContextText(settingsPanel, { origin: "https://fw.example.com" });
assert.match(settingsPanelText, /Current view:/);
assert.match(settingsPanelText, /#\/settings\?panel=network/);
assert.match(settingsPanelText, /route filters: panel = network/);
assert.match(settingsPanelText, /Candidate network, zone-interface, MTU, offload, and flowtable settings/);
assert.match(settingsPanelText, /ngfwctl policy network set --mtu 9000/);
assert.match(settingsPanelText, /Workflow runbook:/);
assert.match(settingsPanelText, /Stage candidate/);
assert.match(settingsPanelText, /Rollback or discard/);
assert.match(settingsPanelText, /POST \/v1\/commit/);
const settingsHostInputPanel = contextForPath("#/settings?panel=host-input");
assert.equal(settingsHostInputPanel.routeState.hash, "#/settings?panel=host-input");
assert.ok(settingsHostInputPanel.endpoints.some((endpoint) => endpoint.path === "/v1/policy?source=POLICY_SOURCE_CANDIDATE"));
assert.ok(settingsHostInputPanel.endpoints.some((endpoint) => endpoint.path === "/v1/candidate/validate" && endpoint.method === "POST"));
assert.ok(settingsHostInputPanel.endpoints.some((endpoint) => endpoint.path === "/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE"));
assert.ok(settingsHostInputPanel.cli.some((item) => item.command === "ngfwctl policy show --source candidate --json"));
assert.ok(settingsHostInputPanel.cli.some((item) => item.command === "ngfwctl policy validate"));
assert.ok(settingsHostInputPanel.cli.some((item) => item.command === "ngfwctl policy diff"));
assert.ok(settingsHostInputPanel.cli.some((item) => item.command.includes("--harden-host-input")));
assert.match(settingsHostInputPanel.notes.join("\n"), /Current Settings panel: host-input/);
assert.match(settingsHostInputPanel.notes.join("\n"), /Unsaved host-input form values are not encoded/);
const settingsHostInputText = automationContextText(settingsHostInputPanel, { origin: "https://fw.example.com" });
assert.match(settingsHostInputText, /#\/settings\?panel=host-input/);
assert.match(settingsHostInputText, /POST \/v1\/candidate\/validate - Validate host-input lockout guardrails/);
assert.match(settingsHostInputText, /GET \/v1\/policy\/diff\?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE/);
assert.match(settingsHostInputText, /ngfwctl policy show --source candidate --json/);
assert.match(settingsHostInputText, /ngfwctl policy validate/);
assert.match(settingsHostInputText, /ngfwctl policy diff/);
assert.match(settingsHostInputText, /harden-host-input/);
assert.doesNotMatch(settingsHostInputText, /ACTION_DENY.*admin-net.*ssh.*webui/);
const settingsAccessPanel = contextForPath("#/settings?panel=access");
assert.equal(settingsAccessPanel.endpoints[0].path, "/v1/system/identity");
assert.ok(settingsAccessPanel.endpoints.some((endpoint) => endpoint.path === "/v1/system/access-administration"));
assert.ok(settingsAccessPanel.endpoints.some((endpoint) => endpoint.path === "/v1/system/access-administration/oidc/config" && endpoint.method === "GET"));
assert.ok(settingsAccessPanel.endpoints.some((endpoint) => endpoint.path === "/v1/system/access-administration/oidc/config" && endpoint.method === "PUT"));
assert.ok(settingsAccessPanel.endpoints.some((endpoint) => endpoint.path === "/v1/system/access-administration/oidc/config:validate"));
assert.ok(settingsAccessPanel.endpoints.some((endpoint) => endpoint.path === "/v1/system/access-administration/oidc/config:disable"));
assert.ok(settingsAccessPanel.endpoints.some((endpoint) => endpoint.path === "/v1/system/access-administration/saml/config" && endpoint.method === "GET"));
assert.ok(settingsAccessPanel.endpoints.some((endpoint) => endpoint.path === "/v1/system/access-administration/saml/config" && endpoint.method === "PUT"));
assert.ok(settingsAccessPanel.endpoints.some((endpoint) => endpoint.path === "/v1/system/access-administration/saml/config:validate"));
assert.ok(settingsAccessPanel.endpoints.some((endpoint) => endpoint.path === "/v1/system/access-administration/saml/config:disable"));
assert.ok(settingsAccessPanel.endpoints.some((endpoint) => endpoint.path === "/v1/auth/saml/status"));
assert.ok(settingsAccessPanel.endpoints.some((endpoint) => endpoint.path === "/v1/system/access-administration/local-users"));
assert.ok(settingsAccessPanel.endpoints.some((endpoint) => endpoint.path === "/v1/system/access-administration/local-users/{name}"));
assert.ok(settingsAccessPanel.endpoints.some((endpoint) => endpoint.path === "/v1/system/access-administration/local-users/{name}:rotate-token"));
assert.ok(settingsAccessPanel.endpoints.some((endpoint) => endpoint.path === "/v1/system/access-administration/local-users/{name}:disable"));
assert.ok(settingsAccessPanel.endpoints.some((endpoint) => endpoint.path === "/v1/system/access-administration/sessions/{sessionId}:revoke"));
assert.ok(settingsAccessPanel.endpoints.some((endpoint) => endpoint.path === "/v1/audit?action=access-oidc-provider-set&limit=300"));
assert.ok(settingsAccessPanel.endpoints.some((endpoint) => endpoint.path === "/v1/audit?action=access-saml-provider-set&limit=300"));
assert.equal(settingsAccessPanel.cli[0].command, "ngfwctl whoami");
assert.ok(settingsAccessPanel.cli.some((item) => item.command === "ngfwctl access users list"));
assert.ok(settingsAccessPanel.cli.some((item) => item.command === "ngfwctl access oidc provider show"));
assert.ok(settingsAccessPanel.cli.some((item) => item.command.includes("ngfwctl access oidc provider validate")));
assert.ok(settingsAccessPanel.cli.some((item) => item.command.includes("ngfwctl access oidc provider set")));
assert.ok(settingsAccessPanel.cli.some((item) => item.command === "ngfwctl access oidc provider disable --ack-disable-oidc -m \"disable OIDC provider\""));
assert.ok(settingsAccessPanel.cli.some((item) => item.command === "ngfwctl access saml provider show"));
assert.ok(settingsAccessPanel.cli.some((item) => item.command.includes("ngfwctl access saml provider validate")));
assert.ok(settingsAccessPanel.cli.some((item) => item.command.includes("ngfwctl access saml provider set")));
assert.ok(settingsAccessPanel.cli.some((item) => item.command === "ngfwctl access saml provider disable --ack-disable-saml -m \"disable SAML provider\""));
assert.ok(settingsAccessPanel.cli.some((item) => item.command.includes("ngfwctl access users create breakglass-viewer")));
assert.ok(settingsAccessPanel.cli.some((item) => item.command.includes("ngfwctl access users set-role breakglass-viewer")));
assert.ok(settingsAccessPanel.cli.some((item) => item.command.includes("ngfwctl access users rotate-token breakglass-viewer")));
assert.ok(settingsAccessPanel.cli.some((item) => item.command.includes("ngfwctl access users disable breakglass-viewer")));
assert.ok(settingsAccessPanel.cli.some((item) => item.command === "ngfwctl access sessions list"));
assert.ok(settingsAccessPanel.cli.some((item) => item.command === "ngfwctl access sessions revoke <session-id> --ack-revoke-session"));
assert.ok(settingsAccessPanel.cli.some((item) => item.purpose === "List active browser SSO sessions by non-secret session ID"));
assert.ok(settingsAccessPanel.cli.some((item) => item.purpose === "Force-sign-out one active browser SSO session through the audited API"));
assert.ok(settingsAccessPanel.cli.some((item) => item.command === "ngfwctl audit --action access-local-user-create --hashes"));
assert.ok(settingsAccessPanel.cli.some((item) => item.command === "ngfwctl audit --action access-oidc-provider-set --hashes"));
assert.ok(settingsAccessPanel.cli.some((item) => item.command === "ngfwctl audit --action access-saml-provider-set --hashes"));
assert.match(settingsAccessPanel.notes.join("\n"), /Current Settings panel: access/);
assert.match(settingsAccessPanel.notes.join("\n"), /ngfwctl access sessions/);
assert.match(settingsAccessPanel.notes.join("\n"), /Browser SSO session revoke is available/);
assert.match(settingsAccessPanel.notes.join("\n"), /ngfwctl access oidc provider/);
assert.match(settingsAccessPanel.notes.join("\n"), /ngfwctl access saml provider/);
const settingsAccessPanelText = automationContextText(settingsAccessPanel, { origin: "https://fw.example.com" });
assert.match(settingsAccessPanelText, /PUT \/v1\/system\/access-administration\/oidc\/config/);
assert.match(settingsAccessPanelText, /POST \/v1\/system\/access-administration\/oidc\/config:disable/);
assert.match(settingsAccessPanelText, /PUT \/v1\/system\/access-administration\/saml\/config/);
assert.match(settingsAccessPanelText, /POST \/v1\/system\/access-administration\/saml\/config:disable/);
assert.match(settingsAccessPanelText, /GET \/v1\/auth\/saml\/status/);
assert.match(settingsAccessPanelText, /POST \/v1\/system\/access-administration\/sessions\/\{sessionId\}:revoke/);
assert.match(settingsAccessPanelText, /GET \/v1\/audit\?action=access-saml-provider-set&limit=300/);
assert.match(settingsAccessPanelText, /ngfwctl audit --action access-saml-provider-set --hashes/);
assert.match(settingsAccessPanelText, /Force-sign-out one active browser SSO session by non-secret session ID/);
assert.match(settingsAccessPanelText, /PATCH \/v1\/system\/access-administration\/local-users\/\{name\}/);
assert.doesNotMatch(settingsAccessPanelText, /Bearer phr_|one-time-token|session_secret|password=/i);
assert.doesNotMatch(settingsAccessPanelText, /\/etc\/openngfw\/oidc-client-secret|client_secret=/i);
assert.doesNotMatch(settingsAccessPanelText, /active OIDC browser session|active OIDC browser sessions/i);
assert.doesNotMatch(settingsAccessPanelText, /not implemented|runtime remains pending|activation is explicitly blocked/i);
const settingsTelemetryPanel = contextForPath("#/settings?panel=telemetry");
assert.equal(settingsTelemetryPanel.endpoints[0].path, "/v1/system/telemetry/exports/status");
assert.equal(settingsTelemetryPanel.endpoints[1].path, "/v1/policy?source=POLICY_SOURCE_CANDIDATE");
assert.equal(settingsTelemetryPanel.cli[0].command, "ngfwctl system telemetry-export-status --json");
assert.equal(settingsTelemetryPanel.cli[1].command, "ngfwctl policy show --source candidate --json");
assert.match(settingsTelemetryPanel.notes.join("\n"), /Current Settings panel: telemetry/);
assert.match(settingsTelemetryPanel.notes.join("\n"), /phragma\.telemetry\.evidence\.v1 JSON packet/);
assert.match(settingsTelemetryPanel.notes.join("\n"), /Telemetry evidence Runtime status: ngfwctl status/);
assert.match(settingsTelemetryPanel.notes.join("\n"), /Telemetry evidence Passive export status: ngfwctl system telemetry-export-status --json/);
assert.match(settingsTelemetryPanel.notes.join("\n"), /Telemetry evidence ClickHouse rows:/);
assert.doesNotMatch(settingsTelemetryPanel.routeState.hash, /token|secret|password|api_key/i);

const intel = contextForPath("/intel");
assert.ok(intel.endpoints.some((endpoint) => endpoint.path.includes("/v1/intel/content/packages/app-id/install")));
assert.ok(intel.endpoints.some((endpoint) => endpoint.path.includes("/v1/intel/content/packages/threat-id/rollback")));
assert.ok(intel.cli.some((item) => item.command.includes("ngfwctl intel content install app-id")));
assert.ok(intel.cli.some((item) => item.command.includes("ngfwctl intel content rollback threat-id")));
const intelReview = contextForPath("#/intel?surface=app-id&drawer=review");
assert.equal(intelReview.routeState.hash, "#/intel?surface=app-id&drawer=review");
assert.equal(intelReview.endpoints[0].path, "/v1/intel/content/packages");
assert.equal(intelReview.cli[0].command, "ngfwctl intel content");
assert.match(intelReview.notes.join("\n"), /Current Intel surface: app-id/);
assert.match(intelReview.notes.join("\n"), /Current Intel drawer: review/);
const intelQuality = contextForPath("#/intel?surface=app-id&drawer=quality");
assert.equal(intelQuality.routeState.hash, "#/intel?surface=app-id&drawer=quality");
assert.ok(intelQuality.endpoints.some((endpoint) => endpoint.path === "/v1/intel/content/packages"));
assert.ok(intelQuality.endpoints.some((endpoint) => endpoint.path === "/v1/intel/content/packages/app-id/evidence/app-regression-corpus"));
assert.ok(intelQuality.endpoints.some((endpoint) => endpoint.path === "/v1/intel/content/packages/app-id/corpus?evidence_type=app-regression-corpus&limit=100"));
assert.ok(intelQuality.endpoints.some((endpoint) => endpoint.path === "/v1/intel/content/packages/app-id/compare" && endpoint.method === "POST"));
assert.ok(intelQuality.cli.some((item) => item.command === "ngfwctl intel content"));
assert.ok(intelQuality.cli.some((item) => item.command === "ngfwctl intel content corpus app-id --evidence-type app-regression-corpus --limit 100"));
assert.ok(intelQuality.cli.some((item) => item.command === "ngfwctl intel content compare app-id --source app-id --evidence-type app-regression-corpus"));
assert.match(intelQuality.notes.join("\n"), /Current Intel drawer: quality/);
assert.match(intelQuality.notes.join("\n"), /Compare preview is non-mutating/);
const intelQualityText = automationContextText(intelQuality, { origin: "https://fw.example.com" });
assert.match(intelQualityText, /#\/intel\?surface=app-id&drawer=quality/);
assert.match(intelQualityText, /GET \/v1\/intel\/content\/packages\/app-id\/evidence\/app-regression-corpus/);
assert.match(intelQualityText, /GET \/v1\/intel\/content\/packages\/app-id\/corpus\?evidence_type=app-regression-corpus&limit=100/);
assert.match(intelQualityText, /ngfwctl intel content corpus app-id --evidence-type app-regression-corpus --limit 100/);
assert.match(intelQualityText, /ngfwctl intel content compare app-id --source app-id --evidence-type app-regression-corpus/);
assert.doesNotMatch(intelQualityText, /\/var\/lib|\/tmp|\/Users|manifestPath|rollbackPath|sourcePath:|writer:secret|access_token=secret-token/i);
const intelInstall = contextForPath("#/intel?surface=app-id&drawer=install");
assert.equal(intelInstall.endpoints[0].path, "/v1/intel/content/packages/app-id/install");
assert.equal(intelInstall.endpoints[0].method, "POST");
assert.match(intelInstall.endpoints[0].body, /"sourcePath": "app-id"/);
assert.equal(intelInstall.cli[0].command, "ngfwctl intel content install app-id --source app-id");
assert.match(intelInstall.notes.join("\n"), /server-side and audited/);
const intelRollback = contextForPath("#/intel?surface=threat-id&drawer=rollback");
assert.equal(intelRollback.endpoints[0].path, "/v1/intel/content/packages/threat-id/rollback");
assert.equal(intelRollback.endpoints[0].method, "POST");
assert.match(intelRollback.endpoints[0].body, /"ackRollback": true/);
assert.equal(intelRollback.cli[0].command, "ngfwctl intel content rollback threat-id --ack-rollback");
assert.match(intelRollback.notes.join("\n"), /verified backup/);
for (const context of [intelReview, intelQuality, intelInstall, intelRollback]) {
  const rendered = automationContextText(context, { origin: "https://fw.example.com" });
  assert.doesNotMatch(rendered, /\/var\/lib|\/tmp|\/Users|writer:secret|access_token=secret-token/i);
}

const unsafeRoute = contextForPath("#/traffic?mode=flows&token=Bearer-secret-token&path=/etc/passwd&file=file:/tmp/x&ip=10.0.1.20");
assert.equal(unsafeRoute.routeState.hash, "#/traffic?mode=flows&ip=10.0.1.20");
assert.deepEqual(unsafeRoute.routeState.queryEntries, [["mode", "flows"], ["ip", "10.0.1.20"]]);
const unsafeRouteText = automationContextText(unsafeRoute, { origin: "https://fw.example.com" });
assert.doesNotMatch(unsafeRouteText, /Bearer-secret-token|\/etc\/passwd|file:\/tmp|token =|path =|file =/i);

const trafficSessionPacket = automationWorkflowSession(trafficSessions, { origin: "https://fw.example.com" });
assert.equal(trafficSessionPacket.schemaVersion, "phragma.webui.workflow-session.v1");
assert.equal(trafficSessionPacket.source, "browser-local");
assert.equal(trafficSessionPacket.routeState.hash, `#/traffic?mode=sessions&ip=10.0.1.20&protocol=TCP&sessionState=ESTABLISHED&limit=100&sessionSort=packets&sessionKey=${trafficSessionKey}`);
assert.equal(trafficSessionPacket.apiContract.path, "/ui/api-spec.yaml");
assert.ok(trafficSessionPacket.endpoints.some((endpoint) => endpoint.path === "/v1/sessions?limit=100&ip=10.0.1.20&protocol=TCP&state=ESTABLISHED"));
assert.ok(trafficSessionPacket.endpoints.some((endpoint) => endpoint.curl.includes("https://fw.example.com/v1/sessions?limit=100")));
assert.ok(trafficSessionPacket.cli.some((item) => item.command === "ngfwctl sessions --limit 100 --ip 10.0.1.20 --protocol TCP --state ESTABLISHED"));
assert.equal(trafficSessionPacket.custody.serverStored, false);
assert.equal(trafficSessionPacket.custody.signed, false);

let recording = emptyAutomationRecording({ origin: "https://fw.example.com" });
assert.equal(recording.schemaVersion, "phragma.webui.automation-recorder.v1");
assert.equal(recording.source, "browser-local");
assert.equal(recording.status, "recording");
assert.equal(recording.apiOrigin, "https://fw.example.com");
assert.deepEqual(recording.steps, []);
assert.equal(recording.custody.serverStored, false);
assert.equal(recording.custody.signed, false);
recording = appendAutomationRecording(recording, unsafeRoute, { origin: "https://fw.example.com" });
recording = appendAutomationRecording(recording, rules, { origin: "https://fw.example.com" });
assert.equal(recording.steps.length, 2);
assert.equal(recording.steps[0].step, 1);
assert.equal(recording.steps[0].routeState.hash, "#/traffic?mode=flows&ip=10.0.1.20");
assert.equal(recording.steps[0].session.schemaVersion, "phragma.webui.workflow-session.v1");
assert.ok(recording.steps[0].session.endpoints.some((endpoint) => endpoint.path.includes("/v1/flows")));
assert.ok(recording.steps[0].session.cli.some((item) => item.command.includes("ngfwctl flows")));
assert.equal(recording.steps[1].step, 2);
assert.deepEqual(recording.steps[1].session.workflow.map((step) => step.title), [
  "Inspect baseline",
  "Stage candidate",
  "Check candidate status",
  "Validate candidate",
  "Review diff",
  "Commit candidate",
  "Rollback or discard",
]);
const recordingText = automationRecordingJson(recording);
assert.match(recordingText, /phragma\.webui\.automation-recorder\.v1/);
assert.match(recordingText, /browser-local/);
assert.match(recordingText, /serverStored/);
assert.doesNotMatch(recordingText, /Bearer-secret-token|\/etc\/passwd|file:\/tmp|token =|path =|file =/i);
const recordingRunbook = automationRecordingRunbookText(recording, { origin: "https://fw.example.com" });
assert.match(recordingRunbook, /^#!\/usr\/bin\/env bash/);
assert.match(recordingRunbook, /set -euo pipefail/);
assert.match(recordingRunbook, /PHRAGMA_API_ORIGIN="\$\{PHRAGMA_API_ORIGIN:-https:\/\/fw\.example\.com\}"/);
assert.match(recordingRunbook, /\$\{PHRAGMA_TOKEN:\?Set PHRAGMA_TOKEN/);
assert.match(recordingRunbook, /curl -sk "\$\{PHRAGMA_API_ORIGIN\}\/ui\/api-spec\.yaml"/);
assert.match(recordingRunbook, /# Step 1: Traffic/);
assert.match(recordingRunbook, /# Step 2: Security rules/);
assert.match(recordingRunbook, /curl -sk -H "Authorization: Bearer \$\{PHRAGMA_TOKEN\}".*"\$\{PHRAGMA_API_ORIGIN\}\/v1\/flows\?/);
assert.match(recordingRunbook, /ngfwctl flows/);
assert.match(recordingRunbook, /ngfwctl policy validate/);
assert.match(recordingRunbook, /ngfwctl commit -m/);
assert.match(recordingRunbook, /ngfwctl rollback/);
assert.doesNotMatch(recordingRunbook, /Bearer-secret-token|\/etc\/passwd|file:\/tmp|token =|path =|file =/i);
const browserOnlyRecording = {
  ...recording,
  steps: [{
    ...recording.steps[0],
    session: {
      ...recording.steps[0].session,
      endpoints: [{
        method: "POST",
        path: "/v1/browser-only",
        purpose: "Requires WebUI CSRF context",
        browserOnly: true,
      }],
      cli: [],
      workflow: [],
    },
  }],
};
const browserOnlyRunbook = automationRecordingRunbookText(browserOnlyRecording, { origin: "https://fw.example.com" });
assert.match(browserOnlyRunbook, /Browser-session action skipped: POST \/v1\/browser-only/);
assert.doesNotMatch(browserOnlyRunbook, /Bearer \$\{PHRAGMA_TOKEN\}.*\/v1\/browser-only/);
const emptyRunbook = automationRecordingRunbookText(emptyAutomationRecording({ origin: "https://fw.example.com" }), { origin: "https://fw.example.com" });
assert.match(emptyRunbook, /No recorded views were present/);

const rulesSessionPacket = automationWorkflowSession(rules, { origin: "https://fw.example.com" });
assert.deepEqual(rulesSessionPacket.workflow.map((step) => step.title), [
  "Inspect baseline",
  "Stage candidate",
  "Check candidate status",
  "Validate candidate",
  "Review diff",
  "Commit candidate",
  "Rollback or discard",
]);
assert.ok(rulesSessionPacket.workflow.some((step) => step.endpoints.some((endpoint) => endpoint.path === "/v1/candidate/validate")));

const unsafeSessionJson = JSON.stringify(automationWorkflowSession(unsafeRoute, { origin: "https://writer:secret@fw.example.com" }), null, 2);
assert.doesNotMatch(unsafeSessionJson, /Bearer-secret-token|\/etc\/passwd|file:\/tmp|writer:secret|token =|path =|file =/i);
assert.match(unsafeSessionJson, /https:\/\/\[redacted\]@fw\.example\.com/);

const fleet = contextForPath("#/fleet");
assert.equal(fleet.routeState.hash, "#/fleet");
assert.ok(fleet.endpoints.some((endpoint) => endpoint.path === "/v1/system/status"));
assert.ok(fleet.endpoints.some((endpoint) => endpoint.path === "/v1/system/ha/status"));
assert.ok(fleet.endpoints.some((endpoint) => endpoint.path === "/v1/policy?source=POLICY_SOURCE_RUNNING"));
assert.ok(fleet.endpoints.some((endpoint) => endpoint.path === "/v1/policy?source=POLICY_SOURCE_CANDIDATE"));
assert.ok(fleet.endpoints.some((endpoint) => endpoint.path === "/v1/candidate/status"));
assert.ok(fleet.endpoints.some((endpoint) => endpoint.path === "/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE"));
assert.ok(fleet.endpoints.some((endpoint) => endpoint.path === "/v1/fleet/nodes"));
assert.ok(fleet.endpoints.some((endpoint) => endpoint.path === "/v1/fleet/templates"));
assert.ok(fleet.endpoints.some((endpoint) => endpoint.method === "POST" && endpoint.path === "/v1/fleet/templates/{id}:apply"));
assert.ok(fleet.endpoints.some((endpoint) => endpoint.path === "/v1/fleet/template-results"));
assert.ok(fleet.endpoints.some((endpoint) => endpoint.method === "POST" && endpoint.path === "/v1/fleet/templates/{id}:stage-candidate"));
assert.ok(fleet.endpoints.some((endpoint) => endpoint.path === "/v1/system/support-bundle?versionLimit=100&auditLimit=300&eventLimit=500"));
assert.ok(fleet.cli.some((item) => item.command === "ngfwctl status"));
assert.ok(fleet.cli.some((item) => item.command === "ngfwctl policy status --json"));
assert.ok(fleet.cli.some((item) => item.command === "ngfwctl fleet templates"));
assert.ok(fleet.cli.some((item) => item.command.includes("ngfwctl fleet templates apply ")));
assert.ok(fleet.cli.some((item) => item.command === "ngfwctl fleet templates results"));
assert.ok(fleet.cli.some((item) => item.command === "ngfwctl support-bundle --output-dir ."));
assert.match(fleet.notes.join("\n"), /multi-node discovery/);
assert.match(fleet.notes.join("\n"), /bounded local candidate replacement/);
assert.match(fleet.notes.join("\n"), /retained unsigned per-node results/);
assert.match(fleet.notes.join("\n"), /distributed result storage/);
assert.doesNotMatch(fleet.notes.join("\n"), /does not store server-side templates|does not yet perform .*template application/i);
assert.match(automationContextText(fleet, { origin: "https://fw.example.com" }), /Fleet & templates/);
assert.match(automationContextText(fleet, { origin: "https://fw.example.com" }), /GET \/v1\/fleet\/template-results/);

const compliance = contextForPath("#/compliance?profile=change-control&limit=25");
assert.equal(compliance.routeState.hash, "#/compliance?profile=change-control&limit=25");
assert.match(compliance.summary, /first-class retained unsigned operational report workbench/);
assert.equal(compliance.endpoints[0].path, "/v1/compliance/reports?limit=25");
assert.equal(compliance.endpoints[1].path, "/v1/compliance/reports");
assert.equal(compliance.cli[0].command, "ngfwctl compliance reports list --limit 25");
assert.equal(compliance.cli[1].command, "ngfwctl compliance reports create --profile change-control --audit-limit 300 --version-limit 100 --log-limit 100");
assert.ok(compliance.endpoints.some((endpoint) => endpoint.path === "/v1/compliance/reports/{id}"));
assert.ok(compliance.endpoints.some((endpoint) => endpoint.path === "/v1/compliance/reports/{id}/export"));
assert.ok(compliance.cli.some((item) => item.command === "ngfwctl compliance reports export <report-id> --output report.json"));
assert.match(compliance.notes.join("\n"), /intentionally unsigned/);
assert.match(compliance.notes.join("\n"), /Signing, legal retention, production profile governance/);
const complianceReportId = "report-20260622T120000Z-deadbeef";
const selectedCompliance = contextForPath(`#/compliance?report=${complianceReportId}&profile=incident-evidence&token=Bearer-secret-token&path=/etc/passwd`);
assert.equal(selectedCompliance.routeState.hash, `#/compliance?report=${complianceReportId}&profile=incident-evidence`);
assert.equal(selectedCompliance.endpoints[0].path, `/v1/compliance/reports/${complianceReportId}`);
assert.equal(selectedCompliance.endpoints[1].path, `/v1/compliance/reports/${complianceReportId}/export`);
assert.equal(selectedCompliance.cli[0].command, `ngfwctl compliance reports get ${complianceReportId}`);
assert.equal(selectedCompliance.cli[1].command, `ngfwctl compliance reports export ${complianceReportId} --output ${complianceReportId}.json`);
assert.match(selectedCompliance.notes.join("\n"), /signing, legal hold, and external verification remain hardening work/);
assert.doesNotMatch(automationContextText(selectedCompliance, { origin: "https://fw.example.com" }), /Bearer-secret-token|\/etc\/passwd|token =|path =/i);

const readiness = contextForPath("/readiness");
assert.ok(readiness.endpoints.some((endpoint) => endpoint.path === "/v1/system/status"));
assert.ok(readiness.endpoints.some((endpoint) => endpoint.path === "/v1/system/ha/status"));
assert.ok(readiness.endpoints.some((endpoint) => endpoint.method === "POST" && endpoint.path === "/v1/system/ha/policy:pull"));
assert.ok(readiness.endpoints.some((endpoint) => endpoint.method === "POST" && endpoint.path === "/v1/system/ha/failover:activate"));
assert.ok(readiness.endpoints.some((endpoint) => endpoint.path === "/v1/system/identity"));
assert.ok(readiness.endpoints.some((endpoint) => endpoint.path === "/v1/system/release-acceptance/status"));
assert.ok(readiness.endpoints.some((endpoint) => endpoint.path === "/v1/candidate/status"));
assert.ok(readiness.endpoints.some((endpoint) => endpoint.method === "POST" && endpoint.path === "/v1/system/runtime-readiness:check"));
assert.ok(readiness.endpoints.some((endpoint) => endpoint.path === "/v1/intel/feeds"));
assert.ok(readiness.endpoints.some((endpoint) => endpoint.path === "/v1/intel/content/packages"));
assert.ok(readiness.cli.some((item) => item.command === "ngfwctl system release-acceptance-status --json"));
assert.ok(readiness.cli.some((item) => item.command.includes("ngfwrelease status --json")));
assert.ok(readiness.cli.some((item) => item.command === "make release-acceptance-status RELEASE_NO_PERFORMANCE_CLAIMS=1"));
assert.ok(readiness.cli.some((item) => item.command === "make release-recordability-check COMMIT=<full-commit> VERSION=<tag>"));
assert.ok(readiness.cli.some((item) => item.command.includes("ngfwctl system ha pull-policy --ack-pull")));
assert.ok(readiness.cli.some((item) => item.command.includes("ngfwctl system ha activate-passive --ack-failover")));
assert.ok(readiness.cli.some((item) => item.command.includes("ngfwctl support-bundle")));
assert.ok(readiness.cli.some((item) => item.command === "ngfwctl support-bundle --output-dir ."));
assert.match(readiness.notes.join("\n"), /recordability is human guidance/);
assert.match(readiness.notes.join("\n"), /artifact-matching workbench commands/);
assert.match(readiness.notes.join("\n"), /VIP\/route cutover/);
const readinessSupportBundle = contextForPath("#/readiness?drawer=support-bundle");
assert.equal(readinessSupportBundle.routeState.hash, "#/readiness?drawer=support-bundle");
assert.equal(readinessSupportBundle.endpoints[0].path, "/v1/system/support-bundle?versionLimit=100&auditLimit=300&eventLimit=500");
assert.equal(readinessSupportBundle.cli[0].command, "ngfwctl support-bundle --output-dir .");
assert.match(readinessSupportBundle.notes.join("\n"), /Current Readiness drawer: support-bundle/);
assert.match(readinessSupportBundle.notes.join("\n"), /does not stage policy or close release gates/);
const readinessReleaseAcceptance = contextForPath("#/readiness?drawer=release-acceptance");
assert.equal(readinessReleaseAcceptance.routeState.hash, "#/readiness?drawer=release-acceptance");
assert.equal(readinessReleaseAcceptance.endpoints[0].path, "/v1/system/release-acceptance/status");
assert.equal(readinessReleaseAcceptance.cli[0].command, "ngfwctl system release-acceptance-status --json");
assert.equal(readinessReleaseAcceptance.cli[1].command, "make release-acceptance-status RELEASE_NO_PERFORMANCE_CLAIMS=1");
assert.match(readinessReleaseAcceptance.notes.join("\n"), /Current Readiness drawer: release-acceptance/);
const readinessHA = contextForPath("#/readiness?drawer=ha");
assert.equal(readinessHA.routeState.hash, "#/readiness?drawer=ha");
assert.equal(readinessHA.endpoints[0].path, "/v1/system/ha/status");
assert.equal(readinessHA.endpoints[0].purpose, "Exact active/passive HA status request for the current Readiness drawer");
assert.equal(readinessHA.cli[0].command, "ngfwctl status");
assert.match(readinessHA.cli[0].purpose, /Headless HA posture/);
assert.match(readinessHA.notes.join("\n"), /Current Readiness drawer: HA evidence/);
assert.match(readinessHA.notes.join("\n"), /does not execute peer sync, replication, or failover/);
const readinessHAText = automationContextText(readinessHA, { origin: "https://fw.example.com" });
assert.match(readinessHAText, /Current view:\n- #\/readiness\?drawer=ha/);
assert.match(readinessHAText, /GET \/v1\/system\/ha\/status - Exact active\/passive HA status request/);
assert.match(readinessHAText, /curl .*https:\/\/fw\.example\.com\/v1\/system\/ha\/status/);
assert.match(readinessHAText, /ngfwctl status - Headless HA posture/);
const readinessHACockpit = contextForPath("#/readiness?drawer=ha-cockpit");
assert.equal(readinessHACockpit.routeState.hash, "#/readiness?drawer=ha-cockpit");
assert.equal(readinessHACockpit.endpoints[0].path, "/v1/system/ha/status");
assert.equal(readinessHACockpit.endpoints[1].path, "/v1/system/ha/policy:pull");
assert.equal(readinessHACockpit.endpoints[1].method, "POST");
assert.equal(readinessHACockpit.endpoints[2].path, "/v1/system/ha/failover:activate");
assert.equal(readinessHACockpit.endpoints[2].method, "POST");
assert.equal(readinessHACockpit.cli[0].command, "ngfwctl status");
assert.match(readinessHACockpit.cli[1].command, /ngfwctl system ha pull-policy --ack-pull --ack-risk --ack-runtime/);
assert.match(readinessHACockpit.cli[2].command, /ngfwctl system ha activate-passive --ack-failover --ack-external-cutover --ack-external-fencing/);
assert.match(readinessHACockpit.notes.join("\n"), /Current Readiness drawer: HA operations cockpit/);
assert.match(readinessHACockpit.notes.join("\n"), /acknowledgement, audit comments/);
assert.match(readinessHACockpit.notes.join("\n"), /VIP\/route cutover/);
const readinessHACockpitText = automationContextText(readinessHACockpit, { origin: "https://fw.example.com" });
assert.match(readinessHACockpitText, /Current view:\n- #\/readiness\?drawer=ha-cockpit/);
assert.match(readinessHACockpitText, /POST \/v1\/system\/ha\/policy:pull/);
assert.match(readinessHACockpitText, /POST \/v1\/system\/ha\/failover:activate/);
assert.match(readinessHACockpitText, /ngfwctl system ha pull-policy --ack-pull/);
assert.match(readinessHACockpitText, /ngfwctl system ha activate-passive --ack-failover/);
const readinessProtoPacket = contextForPath("#/readiness?packet=proto-verify");
assert.equal(readinessProtoPacket.endpoints[0].path, "/v1/system/release-acceptance/status");
assert.equal(readinessProtoPacket.cli[0].command, "make proto-status");
assert.match(readinessProtoPacket.notes.join("\n"), /Current Readiness release packet: proto-verify/);
const readinessEbpfPacket = contextForPath("#/readiness?packet=ebpf-ol9-field-evidence");
assert.equal(readinessEbpfPacket.endpoints[0].path, "/v1/system/release-acceptance/status");
assert.equal(readinessEbpfPacket.endpoints[1].path, "/v1/system/status");
assert.deepEqual(readinessEbpfPacket.cli.slice(0, 4).map((item) => item.command), [
  "make ebpf-ol9-attach-drill-check",
  "sudo -E EBPF_OL9_ATTACH_IFACE=<disposable-interface> EBPF_OL9_STATUS_JSON_COMMAND='<command that prints /v1/system/status eBPF JSON>' make ebpf-ol9-attach-drill EBPF_OL9_FIELD_EVIDENCE_DIR=release/field-evidence/ebpf-ol9",
  "make ebpf-ol9-field-evidence-check EBPF_OL9_FIELD_EVIDENCE_DIR=release/field-evidence/ebpf-ol9",
  "COMMIT=\"$(git rev-parse HEAD)\" make release-evidence-ebpf-ol9-field-evidence EBPF_OL9_FIELD_EVIDENCE_DIR=release/field-evidence/ebpf-ol9",
]);
assert.match(readinessEbpfPacket.notes.join("\n"), /Current Readiness release packet: ebpf-ol9-field-evidence/);
assert.match(readinessEbpfPacket.notes.join("\n"), /required_drill_evidence=drill-manifest/);
const readinessReleasePacketIds = releaseEvidencePacketIds();
for (const packetId of readinessReleasePacketIds) {
  const definition = releaseEvidencePacketDefinition(packetId);
  const context = contextForPath(`#/readiness?packet=${packetId}`);
  assert.equal(context.routeState.hash, `#/readiness?packet=${packetId}`);
  assert.equal(context.endpoints[0].path, "/v1/system/release-acceptance/status", `${packetId} release status endpoint`);
  assert.deepEqual(
    context.cli.slice(0, definition.packet.commands.length).map((item) => item.command),
    definition.packet.commands,
    `${packetId} CLI commands should match release packet commands`,
  );
  assert.match(context.notes.join("\n"), new RegExp(`Current Readiness release packet: ${packetId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
  assert.match(automationContextText(context, { origin: "https://fw.example.com" }), new RegExp(`GET /v1/system/release-acceptance/status - Release gate state used by the ${packetId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} readiness packet`));
}
const readinessInvalidPacket = contextForPath("#/readiness?packet=../../etc/passwd&action=dry-run");
assert.equal(readinessInvalidPacket.routeState.hash, "#/readiness?action=dry-run");
assert.deepEqual(readinessInvalidPacket.routeState.queryEntries, [["action", "dry-run"]]);
assert.match(readinessInvalidPacket.notes.join("\n"), /Current Readiness action focus: dry-run/);
const readinessUnknownPacket = contextForPath("#/readiness?packet=not-a-release-gate");
assert.equal(readinessUnknownPacket.routeState.hash, "#/readiness");
assert.deepEqual(readinessUnknownPacket.routeState.queryEntries, []);
const readinessUnsafeReleasePacket = contextForPath("#/readiness?packet=proto-verify&token=Bearer-secret-token&path=/etc/passwd&artifactPath=/var/lib/openngfw/release/acceptance.json&access_token=secret-token");
assert.equal(readinessUnsafeReleasePacket.routeState.hash, "#/readiness?packet=proto-verify");
assert.deepEqual(readinessUnsafeReleasePacket.routeState.queryEntries, [["packet", "proto-verify"]]);
const readinessUnsafeReleaseText = automationContextText(readinessUnsafeReleasePacket, { origin: "https://fw.example.com" });
assert.match(readinessUnsafeReleaseText, /Current Readiness release packet: proto-verify/);
assert.match(readinessUnsafeReleaseText, /used by the proto-verify readiness packet/);
assert.doesNotMatch(readinessUnsafeReleaseText, /Bearer-secret-token|\/etc\/passwd|\/var\/lib\/openngfw|access_token|token =|path =|artifactPath/i);

const changes = contextForPath("/changes");
assert.ok(changes.endpoints.some((endpoint) => endpoint.path.includes("/v1/policy/diff")));
assert.ok(changes.endpoints.some((endpoint) => endpoint.path === "/v1/candidate/status"));
assert.ok(changes.endpoints.some((endpoint) => endpoint.path === "/v1/system/status"));
assert.ok(changes.endpoints.some((endpoint) => endpoint.method === "POST" && endpoint.path === "/v1/system/runtime-readiness:check"));
assert.ok(changes.endpoints.some((endpoint) => endpoint.path === "/v1/commit"));
assert.ok(changes.endpoints.some((endpoint) => endpoint.path === "/v1/rollback"));
assert.ok(changes.cli.some((item) => item.command === "ngfwctl policy validate"));
assert.ok(changes.cli.some((item) => item.command === "ngfwctl policy diff"));
assert.ok(changes.cli.some((item) => item.command === "ngfwctl rollback 7 --ack-risk -m \"restore known good\""));
assert.ok(!changes.cli.some((item) => item.command.includes("rollback --version")));

const text = automationContextText(intel, { origin: "https://fw.example.com" });
assert.match(text, /# Phragma API\/CLI context: Threat intel/);
assert.match(text, /API contract:/);
assert.match(text, /GET \/api-spec\.yaml - Swagger 2\.0 YAML/);
assert.match(text, /curl -sk https:\/\/fw\.example\.com\/api-spec\.yaml/);
assert.match(text, /REST:/);
assert.match(text, /CLI:/);
assert.match(text, /content package/);
assert.match(text, /curl -sk -H "Authorization: Bearer \$\{NGFW_TOKEN:-/);
assert.match(text, /NGFW_TOKEN_FILE:-\/etc\/openngfw\/admin\.token/);
assert.match(text, /https:\/\/fw\.example\.com\/v1\/intel\/feeds/);

const currentText = automationContextText(trafficSessions, { origin: "https://fw.example.com" });
assert.match(currentText, /Current view:/);
assert.match(currentText, /#\/traffic\?mode=sessions/);
assert.match(currentText, /GET \/v1\/sessions\?limit=100&ip=10\.0\.1\.20&protocol=TCP&state=ESTABLISHED/);
assert.match(currentText, /curl .*"https:\/\/fw\.example\.com\/v1\/sessions\?limit=100&ip=10\.0\.1\.20&protocol=TCP&state=ESTABLISHED"/);
assert.doesNotMatch(currentText, /curl [^\n]* https:\/\/fw\.example\.com\/v1\/sessions\?limit=100&ip=/);

assert.equal(apiOriginForCopy({ origin: "https://fw.example.com" }), "https://fw.example.com");
assert.equal(apiOriginForCopy({ origin: "null" }), "https://127.0.0.1:8080");
assert.equal(apiOriginForCopy(null), "https://127.0.0.1:8080");
assert.equal(apiContractCurl({ origin: "https://fw.example.com" }), "curl -sk https://fw.example.com/api-spec.yaml");

const post = curlForEndpoint({ method: "POST", path: "/v1/commit", body: "{ \"comment\": \"x\" }" });
assert.match(post, /^curl -sk -H "Authorization: Bearer \$\{NGFW_TOKEN:-/);
assert.match(post, /NGFW_TOKEN_FILE:-\/etc\/openngfw\/admin\.token/);
assert.match(post, /-H "Content-Type: application\/json"/);
assert.match(post, /-d '\{ "comment": "x" \}'/);
assert.match(post, /-X POST https:\/\/127\.0\.0\.1:8080\/v1\/commit/);

const get = curlForEndpoint({ method: "GET", path: "/v1/system/status" });
assert.doesNotMatch(get, /-X GET/);
assert.match(get, /https:\/\/127\.0\.0\.1:8080\/v1\/system\/status/);

const filteredGet = curlForEndpoint({ method: "GET", path: "/v1/sessions?limit=100&ip=10.0.1.20" }, { origin: "https://fw.example.com" });
assert.match(filteredGet, /"https:\/\/fw\.example\.com\/v1\/sessions\?limit=100&ip=10\.0\.1\.20"/);

const remote = curlForEndpoint({ method: "GET", path: "/v1/system/status" }, { origin: "https://fw.example.com" });
assert.match(remote, /https:\/\/fw\.example\.com\/v1\/system\/status/);
assert.match(remote, /NGFW_TOKEN_FILE/);
