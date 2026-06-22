import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { deriveLogPivotContext, logCapturePlanContext, systemLogHandoffPacket } from "./views/logs.js";

const logsViewSource = readFileSync(new URL("./views/logs.js", import.meta.url), "utf8");
assert.match(logsViewSource, /type: "button", title: "Open system logs API and CLI context"/);
assert.match(logsViewSource, /type: "button", title: "Refresh system logs"/);
assert.match(logsViewSource, /type: "button", title: "Clear system log filters"/);
assert.match(logsViewSource, /type: "button", title: "Copy system log handoff packet"/);
assert.match(logsViewSource, /type: "button", title: "Export system log handoff JSON"/);
assert.match(logsViewSource, /type: "button", title: "Pin system log handoff to investigation case"/);
assert.match(logsViewSource, /title: "Open active investigation case", "aria-label": "Open active investigation case"/);
assert.match(logsViewSource, /type: "button", title: "Close system log drawer"/);
assert.match(logsViewSource, /"aria-label": "Copy system log handoff packet"/);
assert.match(logsViewSource, /appendInvestigationPacketToActiveServerCase/);
assert.match(logsViewSource, /api\.addInvestigationCaseEvidence\(id, evidence\)/);
assert.match(logsViewSource, /title: "Open bounded packet-capture plan in Troubleshoot"/);
assert.match(logsViewSource, /title: "Copy log-derived packet-capture plan handoff"/);
assert.match(logsViewSource, /plan only; start capture remains explicit in Troubleshoot/);
assert.doesNotMatch(logsViewSource, /api\.startPacketCapture/);

const packet = systemLogHandoffPacket({
  id: "abc123",
  timestamp: "2026-06-20T12:03:00Z",
  source: "engine",
  engine: "suricata",
  severity: "warn",
  facility: "suricata",
  file: "suricata.log",
  line: 42,
  message: "suricata engine degraded Bearer [redacted]",
}, { route: "#/logs?source=engine&severity=warn&entry=abc123" });

assert.equal(packet.kind, "system-log");
assert.equal(packet.source.interface, "webui");
assert.equal(packet.source.route, "#/logs?source=engine&severity=warn&entry=abc123");
assert.equal(packet.subject.type, "system-log");
assert.equal(packet.subject.engine, "suricata");
assert.equal(packet.summary.source, "engine");
assert.equal(packet.summary.severity, "warn");
assert.equal(packet.artifacts.log.file, "suricata.log");
assert.equal(packet.artifacts.log.line, 42);
assert.ok(packet.evidence.includes("severity=warn"));
assert.ok(JSON.stringify(packet).includes("Bearer [redacted]"));
assert.ok(!JSON.stringify(packet).includes("/var/log"));

const redactedPacket = systemLogHandoffPacket({
  id: "sec001",
  source: "engine",
  engine: "vector",
  severity: "error",
  file: "/var/log/openngfw/vector.log",
  message: "sink failed Authorization: Bearer super-secret-token token=runtime-secret path=/home/opc/private.json",
}, { route: "#/logs?entry=sec001&token=runtime-secret&path=/var/log/openngfw/vector.log" });
const redactedText = JSON.stringify(redactedPacket) + "\n" + redactedPacket.evidence.join("\n");
assert.match(redactedText, /\[redacted\]/);
assert.match(redactedText, /\[server-local path redacted\]/);
assert.doesNotMatch(redactedText, /super-secret-token|runtime-secret|\/var\/log\/openngfw|\/home\/opc/);

const context = deriveLogPivotContext({
  id: "def456",
  engine: "suricata",
  message: "alert flow_id=920199 src_ip=10.0.1.20 src_port=51515 dest_ip=203.0.113.10 dest_port=443 proto=TCP app_proto=tls signature_id=2010935",
});

assert.equal(context.flowId, "920199");
assert.equal(context.srcIp, "10.0.1.20");
assert.equal(context.srcPort, "51515");
assert.equal(context.destIp, "203.0.113.10");
assert.equal(context.destPort, "443");
assert.equal(context.protocol, "TCP");
assert.equal(context.appId, "tls");
assert.equal(context.signatureId, "2010935");
assert.equal(context.hasDerivedContext, true);
assert.equal(context.hasTrafficContext, true);
assert.equal(context.trafficHash, "#/traffic?mode=flows&ip=10.0.1.20&protocol=TCP&port=443&app=tls&flowId=920199&limit=100");
assert.equal(context.threatsHash, "#/threats?signatureId=2010935&ip=10.0.1.20&protocol=TCP&port=443&flowId=920199&limit=100");
assert.equal(context.troubleshootHash, "#/troubleshoot?source=POLICY_SOURCE_RUNNING&src=10.0.1.20&sport=51515&dst=203.0.113.10&dport=443&protocol=PROTOCOL_TCP&app=tls&flowId=920199&runtime=1");
assert.equal(context.capturePlanHash, "#/troubleshoot?source=POLICY_SOURCE_RUNNING&src=10.0.1.20&sport=51515&dst=203.0.113.10&dport=443&protocol=PROTOCOL_TCP&app=tls&flowId=920199&runtime=1&run=1&intent=capture&captureContext=log-plan&captureInterface=any&captureDuration=20&capturePackets=500&captureSnaplen=256");
assert.equal(context.capturePlan.interface, "any");
assert.equal(context.capturePlan.durationSeconds, 20);
assert.equal(context.capturePlan.packetCount, 500);
assert.equal(context.capturePlan.snaplenBytes, 256);
assert.match(context.capturePlan.filter, /tcp/);
assert.match(context.capturePlan.filter, /10\.0\.1\.20/);
assert.match(context.capturePlan.filter, /203\.0\.113\.10/);
assert.ok(context.capturePlan.warnings.includes("Interface is set to any; prefer the ingress or egress interface when known."));

const contextualPacket = systemLogHandoffPacket({
  id: "def456",
  source: "engine",
  engine: "suricata",
  severity: "warn",
  message: "alert flow_id=920199 src_ip=10.0.1.20 src_port=51515 dest_ip=203.0.113.10 dest_port=443 proto=TCP app_proto=tls signature_id=2010935",
}, { route: "#/logs?entry=def456" });
assert.equal(contextualPacket.summary.flowId, "920199");
assert.equal(contextualPacket.summary.srcIp, "10.0.1.20");
assert.equal(contextualPacket.summary.destIp, "203.0.113.10");
assert.equal(contextualPacket.summary.appId, "tls");
assert.equal(contextualPacket.summary.signatureId, "2010935");
assert.equal(contextualPacket.subject.tuple.flowId, "920199");
assert.equal(contextualPacket.artifacts.flow.flowId, "920199");
assert.equal(contextualPacket.artifacts.flow.destPort, "443");
assert.equal(contextualPacket.artifacts.alert.signatureId, "2010935");
assert.equal(contextualPacket.artifacts.logContext.troubleshootHash, context.troubleshootHash);
assert.equal(contextualPacket.artifacts.logContext.capturePlanHash, context.capturePlanHash);
assert.match(contextualPacket.artifacts.logContext.caseFocusRoute, /#\/investigation\?caseKey=system-log%3A/);
assert.equal(contextualPacket.summary.operatorWorkflow.capturePlanRoute, context.capturePlanHash);
assert.equal(contextualPacket.summary.operatorWorkflow.caseFocusRoute, contextualPacket.artifacts.logContext.caseFocusRoute);
assert.equal(contextualPacket.artifacts.capturePlan.route, context.capturePlanHash);
assert.equal(contextualPacket.artifacts.capturePlan.durationSeconds, 20);
assert.equal(contextualPacket.artifacts.capturePlan.packetCount, 500);
assert.equal(contextualPacket.artifacts.capturePlan.workflow, "plan-only troubleshoot handoff; does not start capture");
assert.equal(contextualPacket.artifacts.operatorWorkflow.caseFocusRoute, contextualPacket.artifacts.logContext.caseFocusRoute);
assert.match(contextualPacket.artifacts.operatorWorkflow.custodyBoundary, /browser-local/);
assert.ok(!Object.hasOwn(contextualPacket.artifacts.capturePlan, "command"));
assert.ok(!Object.hasOwn(contextualPacket.artifacts.capturePlan, "outputPath"));
assert.ok(contextualPacket.evidence.includes("flow_id=920199"));
assert.ok(contextualPacket.evidence.includes("tuple=10.0.1.20:51515 -> 203.0.113.10:443"));
assert.ok(contextualPacket.evidence.some((line) => line.includes("intent=capture")));
assert.ok(contextualPacket.evidence.some((line) => line.startsWith("case_focus_route=#/investigation?")));
assert.ok(contextualPacket.evidence.some((line) => line.includes("workflow_boundary=browser-local")));

const arrowContext = deriveLogPivotContext({
  message: "conntrack tuple UDP 10.0.2.7:5353 -> 10.0.3.8:53",
});
assert.equal(arrowContext.srcIp, "10.0.2.7");
assert.equal(arrowContext.destIp, "10.0.3.8");
assert.equal(arrowContext.srcPort, "5353");
assert.equal(arrowContext.destPort, "53");
assert.equal(arrowContext.troubleshootHash.includes("src=10.0.2.7"), true);
assert.equal(arrowContext.capturePlanHash.includes("intent=capture"), true);

const minimalCapture = logCapturePlanContext({
  srcIp: "10.0.4.10",
  destIp: "10.0.5.20",
  protocol: "",
});
assert.equal(minimalCapture.plan.protocol, "ip");
assert.equal(minimalCapture.plan.filter, "((src host 10.0.4.10 and dst host 10.0.5.20) or (src host 10.0.5.20 and dst host 10.0.4.10))");
assert.equal(minimalCapture.hash, "#/troubleshoot?source=POLICY_SOURCE_RUNNING&src=10.0.4.10&dst=10.0.5.20&runtime=1&run=1&intent=capture&captureContext=log-plan&captureInterface=any&captureDuration=20&capturePackets=500&captureSnaplen=256");
assert.equal(logCapturePlanContext({ srcIp: "10.0.4.10" }), null);
