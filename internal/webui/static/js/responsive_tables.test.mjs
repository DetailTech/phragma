import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const css = readFileSync("internal/webui/static/css/app.css", "utf8");
const ui = readFileSync("internal/webui/static/js/ui.js", "utf8");
const objects = readFileSync("internal/webui/static/js/views/objects.js", "utf8");
const nat = readFileSync("internal/webui/static/js/views/nat.js", "utf8");
const ids = readFileSync("internal/webui/static/js/views/ids.js", "utf8");
const settings = readFileSync("internal/webui/static/js/views/settings.js", "utf8");
const logs = readFileSync("internal/webui/static/js/views/logs.js", "utf8");
const traffic = readFileSync("internal/webui/static/js/views/traffic.js", "utf8");
const threats = readFileSync("internal/webui/static/js/views/threats.js", "utf8");
const netvpn = readFileSync("internal/webui/static/js/views/netvpn.js", "utf8");
const changes = readFileSync("internal/webui/static/js/views/changes.js", "utf8");
const readiness = readFileSync("internal/webui/static/js/views/readiness.js", "utf8");
const intel = readFileSync("internal/webui/static/js/views/intel.js", "utf8");
const dashboard = readFileSync("internal/webui/static/js/views/dashboard.js", "utf8");
const investigation = readFileSync("internal/webui/static/js/views/investigation.js", "utf8");
const fleet = readFileSync("internal/webui/static/js/views/fleet.js", "utf8");
const setup = readFileSync("internal/webui/static/js/views/setup.js", "utf8");

assert.match(ui, /export function labeledCell\b/);
assert.match(ui, /"data-label": label/);
assert.match(ui, /export function responsiveTable\b/);
assert.match(ui, /class: classes\("responsive-evidence", opts\.className\)/);

for (const selector of [
  ".actions-col",
  ".cell-actions",
  ".download-anchor-hidden",
  ".section-head-pad",
  ".surface-zero .table-wrap.flat",
  ".responsive-evidence tbody td.cell-actions",
  ".system-log-table",
  ".system-log-table-wrap",
  ".system-log-time-col",
  ".system-log-message-col",
  ".system-log-message-cell",
  ".system-log-file-cell",
  ".threat-facet",
  ".threat-facet.is-selected",
  ".threats-table",
  ".threat-id-cell",
  ".cell-time",
  ".threats-table .threat-id-cell .note",
  ".intel-feed-registry-wrap",
  ".appid-signal-cell",
]) {
  assert.match(css, new RegExp(selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
}

for (const source of [objects, nat, ids, settings]) {
  assert.match(source, /responsiveTable/);
  assert.match(source, /labeledCell/);
  assert.match(source, /"Actions"/);
}

for (const source of [objects, nat, ids, settings]) {
  assert.doesNotMatch(source, /h\("table", \{\}/);
}

for (const label of ["Name", "CIDR", "Description", "Usage", "App-ID", "Interfaces"]) {
  assert.match(objects, new RegExp(`labeledCell\\("${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
}

for (const label of ["Egress zone", "Source", "Translation", "Ingress zone", "Public destination", "Translated to"]) {
  assert.match(nat, new RegExp(`labeledCell\\("${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
}
assert.match(nat, /responsiveTable\(\["Decision point", "Running", "Candidate"\]/);
assert.match(nat, /\{ className: "nat-path-delta-table" \}/);
for (const label of ["Decision point", "Running", "Candidate"]) {
  assert.match(nat, new RegExp(`labeledCell\\("${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
}
assert.match(nat, /class: "card surface-zero"/);
assert.match(nat, /class: "table-wrap flat"/);
assert.doesNotMatch(nat, /h\("table", \{ class: "responsive-evidence" \}/);

for (const label of ["Threat-ID", "Reason", "Scope object", "Evidence", "Policy state"]) {
  assert.match(ids, new RegExp(`labeledCell\\("${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
}
assert.match(ids, /\{ className: "inspection-coverage-table" \}/);
assert.match(ids, /\{ className: "inspection-exception-table" \}/);
assert.match(ids, /\{ className: "ids-exception-table" \}/);
assert.match(ids, /class: "note inspection-runtime-detail" \}, posture\.detail/);
assert.match(ids, /class: "note inspection-engine-evidence-detail" \}, model\.detail/);
assert.match(css, /\.card > \.note\.inspection-runtime-detail,\n\.card > \.note\.inspection-engine-evidence-detail \{[\s\S]*?white-space: normal;[\s\S]*?overflow: visible;[\s\S]*?-webkit-line-clamp: unset;[\s\S]*?\n\}/);
assert.match(ids, /responsiveTable\(\["Coverage", "Rules", "Examples", "Operator action"\]/);
assert.match(ids, /responsiveTable\(\["Threat-ID", "Scope", "Reason", "Evidence", "Policy state"\]/);
for (const label of ["Coverage", "Rules", "Examples", "Operator action", "Scope"]) {
  assert.match(ids, new RegExp(`labeledCell\\("${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
}

assert.match(setup, /responsiveTable\(\["Check", "Status", "Proof"\]/);
assert.match(setup, /\{ className: "setup-checklist-table" \}/);
for (const label of ["Check", "Status", "Proof"]) {
  assert.match(setup, new RegExp(`labeledCell\\("${label}"`));
}
assert.match(setup, /"data-setup-check": item\.id/);

for (const label of ["Rule", "Source", "Services", "Action"]) {
  assert.match(settings, new RegExp(`labeledCell\\("${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
}
for (const label of ["Browser SSO session", "Actor", "Role", "Expires", "Audit", "Local user", "State", "Token material", "Edit", "Evidence"]) {
  assert.match(settings, new RegExp(`labeledCell\\("${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
}
for (const label of ["Capability", "Status", "Operator note", "Interface", "MTU override", "Posture", "Workflow", "Required role", "Viewer", "Operator", "Admin", "Current", "Check", "Detail", "Next action", "Allowed workflows", "Restricted workflows"]) {
  assert.match(settings, new RegExp(`labeledCell\\("${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
}
for (const className of ["settings-telemetry-capability-table", "settings-interface-mtu-table", "settings-access-inventory-table", "settings-access-governance-table", "settings-oidc-preflight-table", "settings-access-role-preview-table"]) {
  assert.match(settings, new RegExp(`className: "${className}"`));
}
assert.doesNotMatch(settings, /h\("table", \{ class: "responsive-evidence" \}/);
for (const action of ["revoke-session", "update-local-user", "rotate-local-user", "disable-local-user"]) {
  assert.match(settings, new RegExp(`"data-access-action": "${action}"`));
}
assert.match(settings, /class: "actions-col"/);
assert.match(settings, /class: "cell-actions"/);

assert.match(logs, /responsiveTable\(\[/);
assert.match(logs, /\{ className: "system-log-table" \}/);
assert.match(logs, /labeledCell\("Message", \{ class: "system-log-message-cell" \}/);
assert.match(logs, /labeledCell\("File", \{ class: "system-log-file-cell" \}/);
assert.match(logs, /class: "table-wrap system-log-table-wrap"/);
assert.match(logs, /class: "download-anchor-hidden"/);
assert.doesNotMatch(logs, /h\("th", \{ style:/);
assert.doesNotMatch(logs, /style: \{/);
for (const label of ["Time", "Source", "Engine", "Severity", "Message", "File"]) {
  assert.match(logs, new RegExp(`labeledCell\\("${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
}

for (const tableClass of ["traffic-flow-table", "traffic-session-table", "appid-observation-table"]) {
  assert.match(traffic, new RegExp(tableClass));
}
assert.match(traffic, /responsiveTable\(\["App-ID", "Policy", "Proto", "Source", "Destination"/);
assert.match(traffic, /responsiveTable\(\["Proto", "State", "Original", "Reply"/);
assert.match(traffic, /responsiveTable\(\["Review", "Evidence", "Suggested App-ID", "Context"/);
for (const label of ["App-ID", "Policy", "Proto", "Source", "Destination", "To server", "To client", "Packets", "State", "Original", "Reply", "Bytes", "Timeout", "Flags", "Review", "Evidence", "Suggested App-ID", "Context", "Volume", "Next action"]) {
  assert.match(traffic, new RegExp(`labeledCell\\("${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
}
assert.match(traffic, /class: "actions-col"/);
assert.match(traffic, /class: "cell-actions"/);
assert.doesNotMatch(traffic, /h\("table", \{ class: "responsive-evidence traffic-flow-table" \}/);
assert.doesNotMatch(traffic, /h\("table", \{ class: "responsive-evidence traffic-session-table" \}/);
assert.doesNotMatch(traffic, /h\("table", \{ class: "appid-observation-table responsive-evidence" \}/);
assert.doesNotMatch(traffic, /style: \{ textAlign: "right" \}/);

assert.match(threats, /class: "card tight threat-facet"/);
assert.match(threats, /"aria-pressed": state\.sev === n \? "true" : "false"/);
assert.match(threats, /dataset: \{ threatFacet: String\(n\) \}/);
assert.match(threats, /class: "grid cols-4 threat-facet-grid"/);
assert.match(threats, /responsiveTable\(\[\s*\{ label: "Severity", attrs: \{ class: "threat-severity-col" \} \},\s*"Policy",\s*"Threat-ID",\s*"Source",\s*"Destination",\s*"Outcome",\s*\{ label: "Time", attrs: \{ class: "threat-time-col" \} \},\s*\]/);
assert.match(threats, /\{ className: "threats-table" \}/);
assert.match(threats, /responsiveTable\(\["Threat-ID", "Scope", "Reason", "Review", "Policy state", \{ label: "Actions", attrs: \{ class: "actions-col" \} \}\]/);
assert.match(threats, /\{ className: "threat-exception-table" \}/);
assert.match(threats, /labeledCell\("Threat-ID", \{ class: "threat-id-cell" \}/);
assert.match(threats, /class: "muted cell-time"/);
for (const label of ["Severity", "Policy", "Threat-ID", "Source", "Destination", "Outcome", "Time"]) {
  assert.match(threats, new RegExp(`labeledCell\\("${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
}
for (const label of ["Threat-ID", "Scope", "Reason", "Review", "Policy state", "Actions"]) {
  assert.match(threats, new RegExp(`labeledCell\\("${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
}
assert.match(threats, /class: "cell-actions"/);
assert.doesNotMatch(threats, /h\("table", \{ class: "responsive-evidence threats-table" \}/);
assert.doesNotMatch(threats, /h\("table", \{ class: "responsive-evidence" \},\s*h\("thead", \{\}, h\("tr", \{\},\s*h\("th", \{\}, "Threat-ID"\)/);
assert.doesNotMatch(threats, /style: \{ width: "90px" \}/);
assert.doesNotMatch(threats, /style: \{ textAlign: "right" \}/);
assert.doesNotMatch(threats, /maxWidth: "360px", overflow: "hidden"/);

assert.match(netvpn, /responsiveTable/);
assert.match(netvpn, /labeledCell/);
assert.match(netvpn, /class: "card surface-zero"/);
assert.match(netvpn, /class: "table-wrap flat"/);
assert.match(netvpn, /class: "actions-col"/);
assert.match(netvpn, /class: "cell-actions"/);
for (const label of ["Destination", "Via", "Interface", "Metric", "Actions", "Peer", "Runtime", "Tunnel", "Local", "Remote", "Tuple", "Name", "CIDRs", "Mode"]) {
  assert.match(netvpn, new RegExp(`labeledCell\\("${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
}
for (const action of ["edit-route", "delete-route", "inspect-tunnel", "explain-tunnel", "capture-tunnel", "sessions-tunnel", "inspect-ipsec", "edit-ipsec", "delete-ipsec"]) {
  assert.match(netvpn, new RegExp(`netvpnAction: "${action}"`));
}

assert.match(changes, /responsiveTable\(\["Version", "Comment", "Recovery", "Actor", "Time"/);
assert.match(changes, /\{ className: "changes-version-table" \}/);
for (const label of ["Version", "Comment", "Recovery", "Actor", "Time", "Actions"]) {
  assert.match(changes, new RegExp(`labeledCell\\("${label}"`));
}
for (const action of ["diff-version", "export-version", "rollback-version"]) {
  assert.match(changes, new RegExp(`changesAction: "${action}"`));
}
assert.match(changes, /class: "actions-col"/);
assert.match(changes, /class: "cell-actions"/);
assert.match(changes, /class: "flex row-actions"/);
assert.doesNotMatch(changes, /h\("th", \{ style: \{ width: "170px" \}/);
assert.doesNotMatch(changes, /h\("th", \{ style: \{ textAlign: "right", width: "260px" \}/);
assert.match(changes, /responsiveTable\(\["#", "Action", "Detail", "Actor", "Version", "Hash", "Time"\]/);
assert.match(changes, /\{ className: "audit-table" \}/);
assert.match(changes, /dataset: \{ auditEntryRow: auditEntryKey\(e\) \|\| String\(e\.id \|\| ""\) \}/);
for (const label of ["#", "Action", "Detail", "Actor", "Hash"]) {
  assert.match(changes, new RegExp(`labeledCell\\("${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
}
assert.doesNotMatch(changes, /style: \{ maxWidth: "420px" \}/);
assert.doesNotMatch(changes, /style: \{ textAlign: "right" \}/);
assert.doesNotMatch(changes, /h\("table", \{ class: "responsive-evidence audit-table" \}/);

assert.match(readiness, /responsiveTable\(\["Key", "Value", "State", "Detail"\]/);
assert.match(readiness, /\{ className: "readiness-tune-result-table" \}/);
assert.match(readiness, /dataset: \{ readinessTuneResult: item\.key \|\| "" \}/);
assert.match(readiness, /readinessAction: "review-host-baseline"/);
assert.match(readiness, /readinessAction: "review-host-throughput"/);
assert.match(readiness, /responsiveTable\(\["Scope", "Probe", "Key", "State", "Detail"\]/);
assert.match(readiness, /\{ className: "readiness-ebpf-probe-table" \}/);
assert.match(readiness, /responsiveTable\(\["Interface \/ hook", "Program", "State", "Detail"\]/);
assert.match(readiness, /\{ className: "readiness-ebpf-attachment-table" \}/);
assert.match(readiness, /responsiveTable\(\["Artifact", "Path", "State", "Digest"\]/);
assert.match(readiness, /\{ className: "readiness-ebpf-artifact-table" \}/);
assert.match(readiness, /class: "row-actions readiness-ebpf-actions"/);
assert.match(readiness, /class: "release-acceptance-problem-list readiness-ebpf-blockers"/);
assert.doesNotMatch(readiness, /class: "row-actions", style: \{ marginTop: "12px" \}/);
for (const label of ["Key", "Value", "State", "Detail"]) {
  assert.match(readiness, new RegExp(`labeledCell\\("${label}"`));
}
for (const label of ["Scope", "Probe", "Interface / hook", "Program", "Artifact", "Path", "Digest"]) {
  assert.match(readiness, new RegExp(`labeledCell\\("${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
}
assert.doesNotMatch(readiness, /h\("table", \{\},\s*h\("thead", \{\}, h\("tr", \{\},\s*h\("th", \{\}, "Key"\)/);
assert.match(readiness, /responsiveTable\(ENGINE_READINESS_COLUMNS/);
assert.match(readiness, /\{ className: "engine-readiness readiness-engine-table" \}/);
assert.match(readiness, /dataset: \{ readinessEngineRow: e\.name \|\| "engine" \}/);
for (const label of ["Engine", "State", "Mode", "Role", "Detail"]) {
  assert.match(readiness, new RegExp(`label: "${label}"`));
}
assert.match(readiness, /return labeledCell\(cell\.label, attrs,/);
assert.doesNotMatch(readiness, /h\("table", \{ class: "engine-readiness" \}/);

assert.match(intel, /responsiveTable\(\["Sample", "Expected", "Observed", "PCAP hash", "Verdict"\]/);
assert.match(intel, /responsiveTable\(\["Expected", "Observed", "PCAP hash", "Verdict"\]/);
assert.match(intel, /responsiveTable\(\["Change", "Sample", "Current", "Preview"\]/);
assert.match(intel, /responsiveTable\(\["Name", "URL", "Description", \{ label: "Actions", attrs: \{ class: "actions-col" \} \}\]/);
assert.match(intel, /responsiveTable\(\["On", "Feed", "License", "Commercial", "Kind", "Status"\]/);
assert.match(intel, /\{ className: "content-corpus-samples" \}/);
assert.match(intel, /\{ className: "content-evidence-samples" \}/);
assert.match(intel, /\{ className: "content-corpus-diff-samples" \}/);
assert.match(intel, /\{ className: "intel-custom-feed-table" \}/);
assert.match(intel, /\{ className: "intel-feed-registry-table" \}/);
assert.match(intel, /class: "field intel-refresh-interval-field"/);
assert.match(intel, /class: "input intel-refresh-interval-input"/);
assert.match(intel, /dataset: \{ intelCorpusSample: sample\.id \|\| "sample" \}/);
assert.match(intel, /dataset: \{ intelEvidenceSample: sample\.id \|\| sample\.expectedApp \|\| "sample" \}/);
assert.match(intel, /dataset: \{ intelCorpusDiffSample: row\.id \|\| "sample" \}/);
assert.match(intel, /dataset: \{ intelCustomFeed: f\.name \|\| String\(index\) \}/);
assert.match(intel, /dataset: \{ intelFeedRow: f\.name \|\| "" \}/);
assert.match(intel, /dataset: \{ intelFeedToggle: f\.name \|\| "" \}/);
assert.match(intel, /class: "cell-actions"/);
for (const label of ["Sample", "Expected", "Observed", "PCAP hash", "Verdict", "Change", "Current", "Preview", "Name", "URL", "Description", "Actions", "On", "Feed", "License", "Commercial", "Kind", "Status"]) {
  assert.match(intel, new RegExp(`labeledCell\\("${label}"`));
}
assert.doesNotMatch(intel, /h\("table", \{ class: "responsive-evidence content-corpus-samples" \}/);
assert.doesNotMatch(intel, /h\("table", \{ class: "responsive-evidence content-evidence-samples" \}/);
assert.doesNotMatch(intel, /const table = h\("table", \{\},\s*h\("thead", \{\}, h\("tr", \{\},\s*h\("th", \{\}, "Name"\)/);
assert.doesNotMatch(intel, /wrap\.appendChild\(h\("table", \{\}/);
assert.doesNotMatch(intel, /style: \{ maxWidth: "360px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" \}/);
assert.doesNotMatch(intel, /style: \{ maxWidth: "120px" \}/);
assert.doesNotMatch(intel, /style: \{ maxWidth: "340px", marginTop: "14px" \}/);
assert.doesNotMatch(intel, /style: \{ textAlign: "right" \}/);

assert.match(dashboard, /responsiveTable\(\[\s*\{ label: "Capability", attrs: \{ class: "dashboard-engine-name-col" \} \}/);
assert.match(dashboard, /\{ label: "Threat", attrs: \{ class: "dashboard-threat-name-col" \} \}/);
assert.match(dashboard, /\{ label: "Comment", attrs: \{ class: "dashboard-version-comment-col" \} \}/);
assert.match(dashboard, /\{ className: "dashboard-engine-table" \}/);
assert.match(dashboard, /\{ className: "dashboard-threat-table" \}/);
assert.match(dashboard, /\{ className: "dashboard-version-table" \}/);
assert.match(dashboard, /dataset: \{ dashboardEngine: e\.name \|\| "engine" \}/);
assert.match(dashboard, /dataset: \{ dashboardThreat: alert \|\| summary\.label \|\| "threat" \}/);
assert.match(dashboard, /dataset: \{ dashboardVersion: String\(v\.id \|\| ""\) \}/);
assert.match(dashboard, /labeledCell\("Capability", \{ class: "data-clip" \}/);
assert.match(dashboard, /labeledCell\("Source", \{ class: "mono muted data-clip" \}/);
assert.match(dashboard, /labeledCell\("Actor", \{ class: "muted data-clip" \}/);
for (const label of ["Capability", "State", "Detail", "Open", "Severity", "Threat", "Source", "Time", "Version", "Comment", "Actor"]) {
  assert.match(dashboard, new RegExp(`labeledCell\\("${label}"`));
}
assert.doesNotMatch(dashboard, /engines\.length \? h\("table", \{\}/);
assert.doesNotMatch(dashboard, /h\("table", \{\}, h\("tbody", \{\}, top\.map/);
assert.doesNotMatch(dashboard, /h\("table", \{\}, h\("tbody", \{\}, versions\.map/);
assert.doesNotMatch(dashboard, /style: \{ maxWidth: "240px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" \}/);
assert.doesNotMatch(dashboard, /style: \{ maxWidth: "260px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" \}/);

assert.match(investigation, /responsiveTable\(\["Evidence", "Tuple", "App", "Verdict", "Rule", "Policy", "Capture"\]/);
assert.match(investigation, /\{ className: "investigation-compare" \}/);
for (const label of ["Evidence", "Tuple", "App", "Verdict", "Rule", "Policy", "Capture"]) {
  assert.match(investigation, new RegExp(`labeledCell\\("${label}"`));
}
assert.match(css, /@media \(max-width: 820px\)[\s\S]*\.investigation-compare-wrap table \{ min-width: 0; \}/);
assert.doesNotMatch(investigation, /h\("table", \{ class: "investigation-compare" \}/);

assert.match(fleet, /responsiveTable\(\["Appliance", "Role", "Policy", "HA sync", "Runtime"\]/);
assert.match(fleet, /responsiveTable\(\["Template", "State", "Scope", \{ label: "Action", attrs: \{ class: "actions-col" \} \}\]/);
assert.match(fleet, /responsiveTable\(\["Evidence", "Source", "State"\]/);
assert.match(fleet, /\{ className: "fleet-node-table" \}/);
assert.match(fleet, /\{ className: "fleet-template-table" \}/);
assert.match(fleet, /\{ className: "fleet-evidence-table" \}/);
for (const label of ["Appliance", "Role", "Policy", "HA sync", "Runtime", "Template", "State", "Scope", "Action", "Evidence", "Source"]) {
  assert.match(fleet, new RegExp(`labeledCell\\("${label}"`));
}
for (const hook of ["fleetWorkspace", "fleetNode", "fleetTemplate", "fleetEvidence"]) {
  assert.match(fleet, new RegExp(hook));
}
assert.doesNotMatch(fleet, /h\("table", \{\}/);
