// automation_context.js — route-aware API/CLI parity drawer. It keeps the
// WebUI honest by showing the public REST endpoints and ngfwctl commands that
// reproduce or inspect the current screen.

import { api } from "./api.js";
import { h, icon } from "./core.js";
import { normalizeObjectRoute } from "./object_route.js";
import { setupBaselineCliCommand, setupConfigFromQuery, setupContextSummary } from "./setup_context.js";
import { telemetryEvidenceCommands } from "./telemetry_settings.js";
import { closeDrawer, openDrawer, toast } from "./ui.js";

const DEFAULT_API_ORIGIN = "https://127.0.0.1:8080";
const COPY_TOKEN_EXPR = '${NGFW_TOKEN:-$(cat "${NGFW_TOKEN_FILE:-/etc/openngfw/admin.token}" 2>/dev/null)}';
const WORKFLOW_SESSION_SCHEMA = "phragma.webui.workflow-session.v1";
const AUTOMATION_RECORDER_SCHEMA = "phragma.webui.automation-recorder.v1";
const AUTOMATION_RECORDER_KEY = "phragma.webui.automation-recorder.v1";
const SAMPLE_EXPLAIN_RUNNING = explainBody("POLICY_SOURCE_RUNNING");
const SAMPLE_EXPLAIN_CANDIDATE = explainBody("POLICY_SOURCE_CANDIDATE");
const SAMPLE_EXPLAIN_RUNNING_RUNTIME = explainBody("POLICY_SOURCE_RUNNING", { includeRuntime: true });

export const API_CONTRACT = Object.freeze({
  path: "/ui/api-spec.yaml",
  aliasPath: "/api-spec.yaml",
  format: "Swagger 2.0 YAML",
  purpose: "Generated from protobuf and served from the management UI bundle.",
});

export const AUTOMATION_REPLAY_VALIDATION = Object.freeze({
  path: "/v1/system/automation/replay:validate",
  method: "POST",
  schema: "phragma.automation.replay-validation.v1",
  planSchema: "phragma.automation.replay-execution-plan.v1",
  resultSchema: "phragma.automation.replay-execution-result.v1",
  purpose: "Server-side validation, dry-run planning, bounded apply-authority planning, and audited execute-mode candidate replacement for candidate-safe replay only; live/destructive/unknown-route replay remains blocked.",
});

export const AUTOMATION_CONTEXTS = {
  "/": {
    title: "Dashboard",
    summary: "The dashboard is read-only and composes live system, identity, candidate, policy, traffic, threat, version, and feed evidence.",
    endpoints: [
      get("/v1/system/status", "Runtime, dataplane, host, engine, and management posture"),
      get("/v1/system/identity", "Authenticated actor and role shown in management posture"),
      get("/v1/candidate/status", "Candidate dirty-state and change counts used by dashboard remediation pivots"),
      get("/v1/policy?source=POLICY_SOURCE_RUNNING", "Running policy version used for dashboard state"),
      get("/v1/alerts?limit=500", "Recent normalized Threat-ID events"),
      get("/v1/flows?limit=500", "Recent normalized flow and App-ID evidence"),
      get("/v1/versions?limit=8", "Recent committed configuration versions"),
      get("/v1/intel/feeds", "Threat-intelligence feed posture"),
    ],
    cli: [
      cli("ngfwctl status", "Runtime, dataplane, engine, and host posture"),
      cli("ngfwctl whoami", "Authenticated actor and role"),
      cli("ngfwctl status # routing-vpn", "Routing daemon and VPN posture summarized from system status"),
      cli("ngfwctl policy status --json", "Candidate dirty-state and change counts"),
      cli("ngfwctl alerts --limit 50", "Recent Threat-ID events"),
      cli("ngfwctl flows --limit 50", "Recent flow/App-ID evidence"),
      cli("ngfwctl versions --limit 8", "Recent committed versions"),
    ],
    notes: ["Dashboard actions should navigate to candidate, diagnostics, or investigation surfaces before mutation."],
  },
  "/setup": {
    title: "Guided setup",
    summary: "Guided setup stages an ordinary candidate policy and never applies directly to the running firewall.",
    endpoints: [
      get("/v1/system/status", "Host interfaces, runtime mode, and tuning posture"),
      get("/v1/policy?source=POLICY_SOURCE_CANDIDATE", "Current staged candidate"),
      get("/v1/candidate/status", "Candidate dirty-state, section summary, and impact before commit"),
      put("/v1/candidate", "Replace the staged candidate with generated baseline policy", "{ \"policy\": { ... } }"),
      post("/v1/candidate/validate", "Validate the generated baseline and return structured findings plus render plan", "{}"),
      post("/v1/commit", "Publish only after review and audit comment", "{ \"comment\": \"initial baseline\", \"ackRisk\": true, \"ackRuntime\": true }"),
      post("/v1/system/tune", "Optional guarded host tuning from the same setup posture", "{ \"profile\": \"appliance\", \"write\": true, \"apply\": true }"),
    ],
    cli: [
      cli("ngfwctl policy baseline --profile throughput --inside-interface ens5 --outside-interface ens4 --inside-cidr 10.0.2.0/24", "Stage the same baseline model"),
      cli("ngfwctl policy validate", "Validate the staged candidate"),
      cli("ngfwctl policy diff", "Review candidate against running policy"),
      cli("ngfwctl commit --ack-risk -m \"initial baseline\"", "Publish with explicit audit reason"),
      cli("sudo ngfwctl system tune --write --apply", "Apply appliance host tuning when reviewed"),
    ],
    notes: ["Every setup mutation must leave the operator in candidate review before commit."],
  },
  "/rules": policyWorkspace("Security rules", "Rule edits, reordering, App-ID guardrails, flow checks, and staged allow/drop actions all mutate only the candidate.", [
    post("/v1/explain/flow", "Evaluate a flow against running or candidate policy", SAMPLE_EXPLAIN_CANDIDATE),
  ], [
    cli("ngfwctl explain --source candidate --src 10.0.1.20 --dst 10.0.2.20 --protocol tcp --dport 443", "Run the same flow explanation headlessly"),
  ]),
  "/objects": policyWorkspace("Objects", "Address, service, zone, and App-ID object edits are candidate-only policy mutations.", [
    get("/v1/policy/object-references?source=POLICY_SOURCE_CANDIDATE&kind=POLICY_OBJECT_KIND_ADDRESS", "Reverse references for object usage counts, drawers, and delete review"),
  ]),
  "/nat": policyWorkspace("NAT", "SNAT/DNAT changes stage NAT policy plus any generated allow rule through the same candidate workflow. Path preview compares running and candidate policy through ExplainFlow without mutating either side.", [
    post("/v1/explain/flow", "Preview representative NAT path against running policy", "{ \"policySource\": \"POLICY_SOURCE_RUNNING\", \"srcIp\": \"10.0.1.20\", \"destIp\": \"203.0.113.10\", \"destPort\": 443, \"protocol\": \"PROTOCOL_TCP\" }"),
    post("/v1/explain/flow", "Preview the same NAT path against candidate policy", "{ \"policySource\": \"POLICY_SOURCE_CANDIDATE\", \"srcIp\": \"10.0.1.20\", \"destIp\": \"203.0.113.10\", \"destPort\": 443, \"protocol\": \"PROTOCOL_TCP\" }"),
  ], [
    cli("ngfwctl explain --source running --src 10.0.1.20 --dst 203.0.113.10 --protocol tcp --dport 443", "Headless running-side NAT path preview"),
    cli("ngfwctl explain --source candidate --src 10.0.1.20 --dst 203.0.113.10 --protocol tcp --dport 443", "Headless candidate-side NAT path preview"),
  ]),
  "/inspection": policyWorkspace("Inspection", "IDS/IPS profile changes, Threat-ID package gate review, and false-positive exception posture stage through the candidate before runtime IDS/IPS engine behavior changes.", [
    get("/v1/system/status", "Current inspection engine, fail behavior, bypass, and degraded runtime posture"),
    get("/v1/intel/content/packages", "Threat-ID package provenance, regression, rollout, rollback, and production evidence gates"),
    get("/v1/alerts?limit=200", "Threat-ID events used to stage false-positive exceptions"),
  ], [
    cli("ngfwctl status", "Current inspection engine and runtime posture"),
    cli("ngfwctl intel content", "Review Threat-ID package gates before prevention rollout"),
    cli("ngfwctl alerts --limit 100", "Review Threat-ID events before staging false-positive exceptions"),
  ], ["Inspection actions change candidate policy only; IDS/IPS engine detect/prevent runtime changes after validation and commit."]),
  "/netvpn": policyWorkspace("Routing & VPN", "Static route, BGP, OSPF, IPsec, and WireGuard policy edits stage generated engine configuration through the candidate. The edited policy sections are staticRoutes, routing.bgp, routing.ospf, vpn.ipsecTunnels, and vpn.wireguardInterfaces.", [
    get("/v1/system/status", "Runtime interface, route renderer, routing service, IPsec service, WireGuard, and engine posture before path review"),
    post("/v1/explain/flow", "Evaluate a representative tunnel or routed flow against the candidate before commit", "{ \"policySource\": \"POLICY_SOURCE_CANDIDATE\", \"fromZone\": \"lan\", \"toZone\": \"vpn\", \"srcIp\": \"10.0.1.10\", \"destIp\": \"10.20.0.10\", \"destPort\": 51820, \"protocol\": \"PROTOCOL_UDP\" }"),
    get("/v1/sessions?protocol=UDP&port=51820&limit=100", "Live tunnel/session evidence for WireGuard or UDP-encapsulated VPN paths"),
  ], [
    cli("ngfwctl status", "Confirm runtime interfaces, routing engines, and VPN renderer posture"),
    cli("ngfwctl policy route list --source candidate", "List candidate static routes through the granular route CLI"),
    cli("ngfwctl policy route add --destination 10.20.0.0/24 --via 10.0.1.1 --interface lan0 --metric 10", "Stage a static route without replacing the whole policy document"),
    cli("ngfwctl policy route delete --destination 10.20.0.0/24", "Remove one static route from the candidate policy"),
    cli("ngfwctl policy show --source candidate --json", "Export candidate sections staticRoutes, routing.bgp, routing.ospf, vpn.ipsecTunnels, and vpn.wireguardInterfaces"),
    cli("ngfwctl explain --source candidate --from-zone lan --to-zone vpn --src 10.0.1.10 --dst 10.20.0.10 --protocol udp --dport 51820", "Pre-commit routed/tunnel path check"),
    cli("ngfwctl sessions --protocol UDP --port 51820 --limit 100", "Live tunnel/session evidence"),
    cli("ngfwctl commit -m \"update routing and VPN\"", "Publish reviewed route or VPN changes after validate and diff"),
  ], ["Secret material never enters policy; IPsec and WireGuard entries store firewall-local key or secret paths only.", "Static routes now have granular CLI operations. BGP, OSPF, IPsec, and WireGuard still converge through candidate export/edit/set, validation, diff, commit, rollback, and audit until dedicated granular APIs exist."]),
  "/proxy": policyWorkspace("Proxy / WAF", "Virtual-service, WAF policy, route, and backend edits stage only policy.proxy. Validation renders planned proxy/WAF artifacts and traffic-policy impact; active listener/cutover execution remains external to this slice.", [
    get("/v1/policy?source=POLICY_SOURCE_CANDIDATE", "Current staged policy.proxy virtual services and WAF policies"),
    get("/v1/candidate/status", "Candidate revision and change summary used for guarded Proxy/WAF writes"),
    put("/v1/candidate", "Replace the staged candidate with updated policy.proxy", "{ \"policy\": { \"proxy\": { \"virtualServices\": [ ... ], \"wafPolicies\": [ ... ] } }, \"expectedCandidateRevision\": \"sha256:...\" }"),
    post("/v1/candidate/validate", "Validate server-aligned proxy/WAF posture and render the planned proxy artifact", "{}"),
  ], [
    cli("ngfwctl policy show --source candidate --json", "Export the candidate policy.proxy section for review"),
    cli("ngfwctl policy set -f policy.yaml", "Stage edited policy.proxy through the candidate policy document"),
    cli("ngfwctl policy validate", "Validate proxy/WAF names, WAF provenance, planned listener, route, backend, and mTLS requirements"),
    cli("ngfwctl status", "Review current proxy status and degraded runtime impact"),
    cli("ngfwctl policy diff", "Review candidate proxy/WAF changes before commit"),
    cli("ngfwctl commit -m \"update proxy waf plan\"", "Publish reviewed proxy/WAF intent after validation"),
  ], ["This route is planned-only: it does not install proxy/WAF, redirect traffic, store TLS private keys, execute listener cutover/rollback, or prove backend mTLS/HA traffic behavior.", "System preflight can surface proxy blockers and planned-not-executed proof artifacts, but active traffic proof and packet inspection execution remain hardening/backend work."]),
  "/settings": policyWorkspace("Settings", "Network, host-input, telemetry, and auth-adjacent settings either stage policy or call guarded system APIs.", [
    get("/v1/system/identity", "Current actor, role, auth source, and capabilities"),
    get("/v1/auth/oidc/status", "Browser SSO provider posture"),
    browserPost("/v1/auth/logout", "End the current browser SSO session"),
    post("/v1/system/tune", "Guarded host tuning action", "{ \"profile\": \"throughput\", \"write\": true, \"apply\": true }"),
  ], [
    cli("ngfwctl policy network profile throughput", "Stage throughput network profile"),
    cli("ngfwctl policy network set --mtu 9000 --clamp-mss on --manage-nic-offloads on", "Stage lower-level network overrides"),
    cli("sudo ngfwctl system tune --profile throughput --write --apply", "Apply reviewed host tuning"),
    cli("ngfwctl whoami", "Verify the current API actor and role"),
  ]),
  "/threats": {
    title: "Threats",
    summary: "Threats is an investigation and tuning surface over normalized Threat-ID events and candidate-safe exceptions.",
    endpoints: [
      get("/v1/system/status", "Current inspection posture, fail behavior, bypass risk, and engine readiness at investigation time"),
      get("/v1/alerts?limit=200", "Threat-ID events with severity, action, signature, and endpoints"),
      get("/v1/policy?source=POLICY_SOURCE_CANDIDATE", "Candidate IDS/IPS profile and exceptions"),
      post("/v1/threat-exceptions:stage", "Stage one audited false-positive exception", "{ \"threatId\": \"phragma.test\", \"engineSignals\": [{ \"engine\": \"ids-ips\", \"kind\": \"signature_id\", \"value\": \"9000001\" }], \"scope\": \"THREAT_EXCEPTION_SCOPE_SOURCE\", \"sourceIp\": \"10.0.1.10\", \"reason\": \"known lab false positive\" }"),
      put("/v1/candidate", "Stage broader IDS/IPS profile changes", "{ \"policy\": { ... } }"),
      post("/v1/candidate/validate", "Validate threat-profile candidate and return structured findings plus render plan"),
      post("/v1/commit", "Publish profile or exception changes with audit comment", "{ \"comment\": \"tune threat exception\" }"),
    ],
    cli: [
      cli("ngfwctl status", "Current inspection posture and engine readiness"),
      cli("ngfwctl alerts --threat-severity high --limit 50", "Review matching threat events"),
      cli("ngfwctl policy show --source candidate --json", "Export candidate for exception/profile edits"),
      cli("ngfwctl policy set -f policy.yaml", "Stage edited IDS/IPS policy"),
      cli("ngfwctl commit -m \"tune threat exception\"", "Publish reviewed changes"),
    ],
    notes: ["Current inspection posture is handoff-time runtime context, not a substitute for per-event policy version stamps.", "IDS/IPS engine remains an engine; the UI should display Phragma Threat-ID metadata and evidence."],
  },
  "/traffic": {
    title: "Traffic",
    summary: "Traffic combines normalized flow records, live conntrack sessions, and App-ID observation review, then pivots to explain, capture, or candidate-safe policy staging.",
    endpoints: [
      get("/v1/system/status", "Current inspection posture, fail behavior, bypass risk, and engine readiness at investigation time"),
      get("/v1/flows?limit=200", "Recent normalized flow/App-ID evidence"),
      get("/v1/sessions?limit=200", "Live Linux conntrack sessions"),
      get("/v1/app-id/observations?limit=100", "Unknown, low-confidence, and conflicting App-ID evidence queues"),
      post("/v1/app-id/observations/{queueId}:stage", "Re-derive and stage a reviewed App-ID observation through the server-owned candidate path", "{ \"mode\": \"APP_ID_OBSERVATION_STAGE_MODE_DEFINE_ONLY\", \"reason\": \"reviewed App-ID observation\", \"applicationOverride\": { ... } }"),
      post("/v1/explain/flow", "Explain a selected flow tuple", SAMPLE_EXPLAIN_RUNNING),
      post("/v1/system/packet-captures/plan", "Plan a bounded capture from a selected flow", "{ \"interface\": \"ens5\", \"protocol\": \"tcp\", \"srcIp\": \"10.0.1.20\", \"destIp\": \"10.0.2.20\" }"),
      put("/v1/candidate", "Stage custom App-ID objects or review-driven rules", "{ \"policy\": { ... } }"),
    ],
    cli: [
      cli("ngfwctl status", "Current inspection posture and engine readiness"),
      cli("ngfwctl flows --limit 100", "Recent normalized flows"),
      cli("ngfwctl sessions --protocol TCP --limit 100", "Live conntrack sessions"),
      cli("ngfwctl app-id observations --limit 100", "Review App-ID observation queue through the public API"),
      cli("ngfwctl app-id promote <queue-id> --reason \"reviewed App-ID observation\"", "Stage a reviewed queue item through the same server-owned promotion path as the WebUI"),
      cli("ngfwctl explain --source running --src 10.0.1.20 --dst 10.0.2.20 --protocol tcp --dport 443", "Explain selected tuple"),
      cli("ngfwctl system capture --interface ens5 --protocol tcp --src 10.0.1.20 --sport 51515 --dst 10.0.2.20 --dport 443", "Plan equivalent capture"),
    ],
    notes: ["Current inspection posture is handoff-time runtime context, not a substitute for per-event policy version stamps.", "Traffic actions that change policy should stage a candidate rule or App-ID object, not mutate running state.", "Engine app labels are evidence; Phragma owns canonical App-ID."],
  },
  "/logs": {
    title: "System logs",
    summary: "System logs is a read-only workbench over bounded, redacted appliance and engine log files from the configured OpenNGFW log root.",
    endpoints: [
      get("/v1/system/logs?limit=200", "Recent redacted appliance, dataplane, audit, and engine log events"),
      get("/v1/system/logs?source=engine&severity=warn&limit=200", "Engine warning and error events for readiness review"),
      get("/v1/system/status", "Current engine and runtime posture paired with log evidence"),
      get("/v1/audit?limit=200", "Durable audit trail for commit, rollback, capture, and access events when a log row pivots to audit"),
    ],
    cli: [
      cli("ngfwctl system logs --limit 200", "Recent redacted system and engine logs"),
      cli("ngfwctl system logs --source engine --severity warn --limit 200", "Engine warnings for readiness triage"),
      cli("ngfwctl status", "Pair log evidence with current runtime and engine posture"),
      cli("ngfwctl audit --limit 200", "Review durable audit events related to selected log rows"),
    ],
    notes: ["Clients can filter source, engine, severity, time, and query text, but cannot choose filesystem paths.", "System-log exports are operational evidence; retention, custody, and signed export controls remain hardening work."],
  },
  "/investigation": {
    title: "Investigation",
    summary: "Investigation is a browser-local case cockpit over pinned handoff packets; it compares evidence and pivots to public explain, capture, traffic, threat, and audit workflows.",
    endpoints: [
      post("/v1/explain/flow", "Explain a pinned tuple from the case cockpit", SAMPLE_EXPLAIN_RUNNING_RUNTIME),
      post("/v1/system/packet-captures/plan", "Plan a bounded packet capture from a pinned tuple", "{ \"interface\": \"any\", \"protocol\": \"PROTOCOL_TCP\", \"srcIp\": \"10.0.1.20\", \"destIp\": \"10.0.2.20\" }"),
      get("/v1/flows?limit=200", "Review matching flow evidence before staging policy changes"),
      get("/v1/alerts?limit=200", "Review matching Threat-ID evidence before staging exceptions"),
      get("/v1/audit?limit=200", "Review commits, rollbacks, captures, and exception audit entries linked to the case"),
    ],
    cli: [
      cli("ngfwctl explain --source running --src 10.0.1.20 --dst 10.0.2.20 --protocol tcp --dport 443 --runtime", "Explain a pinned tuple headlessly"),
      cli("ngfwctl system capture --interface any --protocol tcp --src 10.0.1.20 --sport 51515 --dst 10.0.2.20 --dport 443", "Plan bounded capture for a pinned tuple"),
      cli("ngfwctl flows --limit 100", "Review matching flow evidence"),
      cli("ngfwctl alerts --limit 100", "Review matching Threat-ID evidence"),
      cli("ngfwctl audit --limit 200", "Review related audit trail"),
    ],
    notes: ["Pinned case packets live in browser storage and are not server-side evidence until copied or exported.", "Investigation actions only pivot to existing explain, capture, traffic, threat, audit, and candidate review workflows; the case cockpit does not mutate policy directly."],
  },
  "/troubleshoot": {
    title: "Troubleshoot",
    summary: "Troubleshoot is the explicit explainability, running-vs-candidate comparison, packet-truth, and reviewed remediation workflow.",
    endpoints: [
      post("/v1/explain/flow", "Explain rule, NAT, route, App-ID, Threat-ID, inspection, bypass, and running config version", SAMPLE_EXPLAIN_RUNNING),
      post("/v1/explain/flow", "Repeat the same tuple against the candidate policy for pre-commit comparison", SAMPLE_EXPLAIN_CANDIDATE),
      post("/v1/system/packet-captures/plan", "Plan a bounded server-side packet capture", "{ \"interface\": \"ens5\", \"protocol\": \"PROTOCOL_TCP\", \"srcIp\": \"10.0.1.20\", \"destIp\": \"10.0.2.20\" }"),
      post("/v1/system/packet-captures", "Start guarded admin-only capture with acknowledgement", "{ \"ackCapture\": true, \"interface\": \"ens5\", \"protocol\": \"PROTOCOL_TCP\", \"durationSeconds\": 20, \"packetCount\": 500 }"),
      post("/v1/system/packet-captures/phragma-web-20260618T121500Z:set-retention", "Retain or release packet capture sidecar evidence metadata with acknowledgement", "{ \"state\": \"PACKET_CAPTURE_RETENTION_STATE_RETAINED\", \"retainUntil\": \"2026-07-19T15:00:00Z\", \"retentionReason\": \"incident review\", \"caseId\": \"IR-2026-001\", \"ackRetentionChange\": true }"),
      put("/v1/candidate", "Stage a reviewed allow/drop remediation rule generated from the explained tuple", "{ \"policy\": { ... } }"),
    ],
    cli: [
      cli("ngfwctl explain --source running --src 10.0.1.20 --dst 10.0.2.20 --protocol tcp --dport 443", "Same flow explanation"),
      cli("ngfwctl explain --source candidate --src 10.0.1.20 --dst 10.0.2.20 --protocol tcp --dport 443", "Candidate-side comparison for the same tuple"),
      cli("ngfwctl system capture --interface ens5 --protocol tcp --src 10.0.1.20 --sport 51515 --dst 10.0.2.20 --dport 443", "Plan bounded capture"),
      cli("ngfwctl system capture --start --ack-capture --interface ens5 --protocol tcp --src 10.0.1.20 --sport 51515 --dst 10.0.2.20 --dport 443", "Start reviewed capture"),
      cli("ngfwctl system capture retain phragma-web-20260618T121500Z --retain-until 2026-07-19T15:00:00Z --reason \"incident review\" --case-id IR-2026-001 --ack-retention-change", "Retain capture evidence metadata through the audited API"),
      cli("ngfwctl system capture release phragma-web-20260618T121500Z --reason \"case closed\" --ack-retention-change", "Release capture retention metadata through the audited API"),
    ],
    notes: ["Capture start is audited and refuses dry-run or broad unscoped requests.", "Capture retention updates only the sidecar metadata and audit trail; pruning, legal hold, and custody controls remain hardening work.", "Stage allow/drop opens the normal Rules drawer; generated objects and the new rule are written only through the candidate policy API after operator review."],
  },
  "/performance": {
    title: "Performance",
    summary: "Performance is a local evidence verifier; it does not invent throughput claims or mutate firewall state.",
    endpoints: [
      get("/v1/system/status", "Runtime status artifact paired with benchmark evidence"),
    ],
    cli: [
      cli("make benchmark-netns-check", "Check one-host Linux netns benchmark prerequisites"),
      cli("sudo DURATION=30 PARALLEL=8 make benchmark-netns", "Collect local netns benchmark artifacts"),
      cli("make benchmark-check", "Check three-host benchmark environment variables and prerequisites"),
      cli("make benchmark", "Collect three-host benchmark artifacts from client, server, and firewall hosts"),
      cli("ngfwperf verify perf/results", "Verify benchmark summary against raw artifacts"),
      cli("make benchmark-verify-release", "Verify benchmark evidence for the release gate"),
      cli("ngfwctl status > ngfw-status-active.txt", "Capture runtime status evidence"),
      cli("sudo nft list table inet openngfw > nft-openngfw-final.txt", "Capture active packet filter ruleset counters on Linux"),
    ],
    notes: ["Performance is a browser-local verifier and runbook surface; benchmark artifacts are not uploaded to controld.", "Use live status is current posture only; measured-window status evidence must be captured during the benchmark run.", "Claims must stay scoped to loaded raw evidence and active inspection state."],
  },
  "/fleet": {
    title: "Fleet & templates",
    summary: "Fleet & templates aggregates the managed appliance, HA posture, candidate drift, content package posture, server-retained local templates, bounded local template apply, and retained per-node result custody.",
    endpoints: [
      get("/v1/system/status", "Managed appliance runtime, dataplane, engine, routing, VPN, and embedded HA posture"),
      get("/v1/system/ha/status", "Active/passive HA role, peer sync, replication, failover, and recovery metadata when configured"),
      get("/v1/system/identity", "Current operator identity and role for fleet posture review"),
      get("/v1/policy?source=POLICY_SOURCE_RUNNING", "Running policy template source and running version"),
      get("/v1/policy?source=POLICY_SOURCE_CANDIDATE", "Candidate policy template source when a staged candidate exists"),
      get("/v1/candidate/status", "Candidate dirty-state, section changes, impact, and policy drift summary"),
      get("/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE", "Running-to-candidate drift details for the managed appliance"),
      get("/v1/versions?limit=100", "Committed version and last-known-good history"),
      get("/v1/intel/feeds", "Feed registry and custom feed posture used by content template review"),
      get("/v1/intel/content/packages", "App-ID, Threat-ID, and feed package posture and rollback posture"),
      get("/v1/fleet/nodes", "Connected local appliance Fleet inventory boundary"),
      get("/v1/fleet/templates", "Server-retained local Fleet template drafts"),
      post("/v1/fleet/templates", "Create a server-retained local Fleet template draft", "{ \"name\": \"edge baseline\", \"policy\": { ... } }"),
      post("/v1/fleet/templates/{id}:validate", "Validate one local Fleet template without mutating candidate or running policy", "{}"),
      post("/v1/fleet/templates/{id}:apply-preview", "Preview local candidate impact with expected candidate revision", "{ \"expectedCandidateRevision\": \"sha256:...\" }"),
      post("/v1/fleet/templates/{id}:apply-plan", "Build bounded local/peer result plan without peer RPC or running-policy apply", "{ \"expectedCandidateRevision\": \"sha256:...\", \"nodes\": [] }"),
      post("/v1/fleet/templates/{id}:apply", "Stage one template to the local candidate and retain per-node bounded result records", "{ \"expectedCandidateRevision\": \"sha256:...\", \"comment\": \"...\", \"nodes\": [] }"),
      get("/v1/fleet/template-results", "Retained local Fleet template apply result records"),
      post("/v1/fleet/templates/{id}:stage-candidate", "Guarded local template stage-to-candidate workflow", "{ \"expectedCandidateRevision\": \"sha256:...\", \"comment\": \"...\" }"),
      get("/v1/system/support-bundle?versionLimit=100&auditLimit=300&eventLimit=500", "Canonical redacted aggregate evidence packet for fleet handoff"),
    ],
    cli: [
      cli("ngfwctl status", "Managed appliance runtime, HA, dataplane, routing, VPN, and engine posture"),
      cli("ngfwctl policy status --json", "Candidate dirty-state and section drift summary"),
      cli("ngfwctl policy show --source running --json", "Export the running policy template source"),
      cli("ngfwctl policy show --source candidate --json", "Export the candidate policy template source when staged"),
      cli("ngfwctl policy validate", "Validate the candidate before treating it as a template target"),
      cli("ngfwctl policy diff", "Review running-to-candidate drift"),
      cli("ngfwctl policy set -f policy.yaml", "Stage an operator-reviewed template import through the existing candidate workflow"),
      cli("ngfwctl versions --limit 100", "Inspect committed version and rollback history"),
      cli("ngfwctl intel content", "Review content packages for App-ID, Threat-ID, and feeds"),
      cli("ngfwctl fleet nodes", "Inspect connected local-appliance Fleet inventory boundary"),
      cli("ngfwctl fleet templates", "List server-retained local Fleet templates"),
      cli("ngfwctl fleet templates validate <id>", "Validate one local Fleet template"),
      cli("ngfwctl fleet templates apply-plan <id>", "Build bounded local/peer apply plan without peer RPC"),
      cli("ngfwctl fleet templates apply <id> --expected-candidate-revision <rev> --comment '<reason>'", "Stage template to local candidate and retain bounded per-node results"),
      cli("ngfwctl fleet templates results", "Inspect retained local Fleet apply result custody records"),
      cli("ngfwctl support-bundle --output-dir .", "Export redacted aggregate posture evidence for handoff"),
    ],
    notes: ["This workspace is scoped to the connected control-plane appliance plus operator-supplied peer rows; it does not perform multi-node discovery or peer fan-out.", "Server-retained local templates can be validated, previewed, staged to the local candidate, and applied only as bounded local candidate replacement with expected revision and retained unsigned per-node results.", "Template changes still complete through candidate validation, diff, commit, audit, and rollback workflows in Changes before running policy changes.", "Fleet membership, template signing/custody, distributed result storage, peer trust, VIP/route cutover, fencing, and connection-state transfer remain hardening/backend work."],
  },
  "/compliance": {
    title: "Compliance reports",
    summary: "Compliance reports is a first-class retained unsigned operational report workbench over bounded audit, version, and system-log state with API and CLI parity.",
    endpoints: [
      get("/v1/compliance/reports?limit=50", "List retained server-side compliance report summaries without payload bytes"),
      post("/v1/compliance/reports", "Generate and retain one unsigned compliance report from bounded audit, version, and system-log state", "{ \"profile\": \"operational\", \"title\": \"monthly firewall operations\", \"auditLimit\": 300, \"versionLimit\": 100, \"logLimit\": 100 }"),
      get("/v1/compliance/reports/{id}", "Inspect one retained compliance report summary"),
      get("/v1/compliance/reports/{id}/export", "Export one retained JSON report artifact with payload digest headers"),
    ],
    cli: [
      cli("ngfwctl compliance reports list --limit 50", "List retained compliance report summaries"),
      cli("ngfwctl compliance reports create --profile operational --title \"monthly firewall operations\" --audit-limit 300 --version-limit 100 --log-limit 100", "Generate and retain an unsigned operational compliance report"),
      cli("ngfwctl compliance reports get <report-id>", "Inspect one retained compliance report summary"),
      cli("ngfwctl compliance reports export <report-id> --output report.json", "Export one retained compliance report JSON artifact"),
    ],
    notes: ["Reports are server-retained and functional operational evidence, but intentionally unsigned.", "Signing, legal retention, production profile governance, export custody, HA/backup retention, scheduling, and external evidence verification remain hardening work.", "Compliance-to-Investigation handoff pins report metadata and export links; immutable evidence references remain hardening."],
  },
  "/intel": {
    title: "Threat intel",
    summary: "Threat intel manages feed policy plus transparent App-ID/Threat-ID content package lifecycle.",
    endpoints: [
      get("/v1/intel/feeds", "Feed registry, custom feeds, license posture, and enabled state"),
      get("/v1/intel/content/packages", "Installed package version, hash, signature, provenance, rollout, regression, and rollback posture"),
      post("/v1/intel/refresh", "Refresh enabled feeds and reprogram blocklists"),
      post("/v1/intel/content/packages/app-id/install", "Install verified server-local App-ID package", "{ \"sourcePath\": \"app-id\" }"),
      post("/v1/intel/content/packages/threat-id/rollback", "Rollback latest verified Threat-ID package backup", "{ \"ackRollback\": true }"),
    ],
    cli: [
      cli("ngfwctl intel feeds", "List feed registry and license posture"),
      cli("ngfwctl intel refresh", "Refresh enabled feeds"),
      cli("ngfwctl intel content", "Show App-ID, Threat-ID, and feed package status"),
      cli("ngfwctl intel content install app-id --source app-id", "Install verified package from <data-dir>/content-import/app-id"),
      cli("ngfwctl intel content rollback threat-id --ack-rollback", "Rollback verified package backup"),
    ],
    notes: ["Content package install sources are firewall-server directories under the configured content import root, not browser uploads or operator workstation paths.", "Content package install and rollback are audited privileged operations, not direct file edits."],
  },
  "/changes": {
    title: "Changes",
    summary: "Changes exposes candidate review, validation, runtime preflight, diffs, import/export, version history, rollback review, and the audit trail.",
    endpoints: [
      get("/v1/candidate/status", "Current staged candidate dirty-state, section summary, and impact"),
      post("/v1/candidate/validate", "Validate current candidate before commit; returns structured findings plus render plan", "{}"),
      get("/v1/system/status", "system preflight and action queue used by candidate commit preflight"),
      get("/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE", "Typed running-to-candidate policy diff"),
      get("/v1/versions?limit=100", "Committed version timeline"),
      get("/v1/audit?limit=200", "Audit entries with actor/action/version filters"),
      get("/v1/policy?source=POLICY_SOURCE_VERSION&version=7", "Historical policy snapshot"),
      get("/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_VERSION&toVersion=7", "Typed running-to-version policy diff"),
      post("/v1/candidate/validate", "Validate imported or rollback target policy before replacing candidate; returns structured findings plus render plan"),
      put("/v1/candidate", "Import policy to candidate only", "{ \"policy\": { ... } }"),
      post("/v1/commit", "Publish reviewed candidate after validation, runtime preflight, and audit comment", "{ \"comment\": \"reviewed policy change\", \"ackRisk\": true, \"ackRuntime\": true }"),
      post("/v1/rollback", "Reviewed rollback to prior version", "{ \"version\": \"7\", \"comment\": \"restore known good\", \"ackRisk\": true, \"ackRuntime\": true }"),
    ],
    cli: [
      cli("ngfwctl policy validate", "Validate current staged candidate"),
      cli("ngfwctl status", "Runtime posture used by candidate commit preflight"),
      cli("ngfwctl policy diff", "Review candidate diff against running policy"),
      cli("ngfwctl commit -m \"reviewed policy change\"", "Publish reviewed candidate with audit reason"),
      cli("ngfwctl versions --limit 100", "List committed versions"),
      cli("ngfwctl audit --limit 200", "List audit entries"),
      cli("ngfwctl policy show --source version --version 7 --json", "Export historical policy"),
      cli("ngfwctl rollback 7 --ack-risk -m \"restore known good\"", "Apply reviewed rollback"),
    ],
    notes: ["Candidate review is the default Changes tab and must pass validation plus runtime preflight before commit.", "Rollback validates the target and runtime posture before touching running state."],
  },
};

function policyWorkspace(title, summary, extraEndpoints = [], extraCli = [], extraNotes = []) {
  return {
    title,
    summary,
    workflow: candidateWorkflow(),
    endpoints: [
      get("/v1/policy?source=POLICY_SOURCE_RUNNING", "Running policy baseline"),
      get("/v1/policy?source=POLICY_SOURCE_CANDIDATE", "Editable candidate policy"),
      get("/v1/candidate/status", "Candidate dirty-state, section summary, and impact before commit"),
      get("/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE", "Typed candidate diff used by GUI, CLI, and automation"),
      put("/v1/candidate", "Stage edited candidate policy", "{ \"policy\": { ... } }"),
      post("/v1/candidate/validate", "Validate candidate and compute impact, structured findings, and render plan", "{}"),
      post("/v1/commit", "Publish after review and audit comment", "{ \"comment\": \"reviewed policy change\", \"ackRisk\": true, \"ackRuntime\": true }"),
      ...extraEndpoints,
    ],
    cli: [
      cli("ngfwctl policy show --source running --json", "Export running policy"),
      cli("ngfwctl policy show --source candidate --json", "Export editable candidate"),
      cli("ngfwctl policy set -f policy.yaml", "Stage edited policy"),
      cli("ngfwctl policy status --json", "Inspect candidate dirty-state, section changes, and impact"),
      cli("ngfwctl policy validate", "Validate staged policy"),
      cli("ngfwctl policy diff", "Review candidate diff"),
      cli("ngfwctl commit -m \"reviewed policy change\"", "Publish with audit reason"),
      ...extraCli,
    ],
    notes: ["GUI edits and CLI edits converge at the same candidate, validation, commit, rollback, and audit APIs.", ...extraNotes],
  };
}

function candidateWorkflow() {
  return [
    workflowStep("Inspect baseline", "Export running and candidate state before editing.", [
      get("/v1/policy?source=POLICY_SOURCE_RUNNING", "Running baseline"),
      get("/v1/policy?source=POLICY_SOURCE_CANDIDATE", "Editable candidate"),
    ], [
      cli("ngfwctl policy show --source running --json", "Export running baseline"),
      cli("ngfwctl policy show --source candidate --json", "Export editable candidate"),
    ]),
    workflowStep("Stage candidate", "Apply reviewed GUI or CLI edits to candidate only.", [
      put("/v1/candidate", "Stage edited candidate policy", "{ \"policy\": { ... } }"),
    ], [
      cli("ngfwctl policy set -f policy.yaml", "Stage edited candidate policy"),
    ]),
    workflowStep("Check candidate status", "Confirm dirty state, section summary, and impact before validation.", [
      get("/v1/candidate/status", "Candidate dirty-state, section summary, and impact"),
    ], [
      cli("ngfwctl policy status --json", "Inspect candidate dirty-state, section summary, and impact"),
    ]),
    workflowStep("Validate candidate", "Run semantic validation and render-plan checks.", [
      post("/v1/candidate/validate", "Validate candidate and compute impact, structured findings, and render plan", "{}"),
    ], [
      cli("ngfwctl policy validate", "Validate staged candidate"),
    ]),
    workflowStep("Review diff", "Compare the candidate against running policy before commit.", [
      get("/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE", "Typed running-to-candidate diff"),
    ], [
      cli("ngfwctl policy diff", "Review candidate diff"),
    ]),
    workflowStep("Commit candidate", "Publish only after validation, runtime review, and an audit reason.", [
      post("/v1/commit", "Publish reviewed candidate after validation and audit comment", "{ \"comment\": \"reviewed policy change\", \"ackRisk\": true, \"ackRuntime\": true }"),
    ], [
      cli("ngfwctl commit -m \"reviewed policy change\"", "Publish reviewed candidate with audit reason"),
    ]),
    workflowStep("Rollback or discard", "Use version rollback for a committed bad change; discard or replace candidate state before leaving review if not committing.", [
      get("/v1/versions?limit=100", "Find the last known good version"),
      post("/v1/rollback", "Reviewed rollback to prior version", "{ \"version\": \"7\", \"comment\": \"restore known good\", \"ackRisk\": true, \"ackRuntime\": true }"),
    ], [
      cli("ngfwctl versions --limit 100", "List committed versions"),
      cli("ngfwctl rollback 7 --ack-risk -m \"restore known good\"", "Apply reviewed rollback to version 7"),
    ]),
  ];
}

function workflowStep(title, purpose, endpoints = [], cliItems = []) {
  return { title, purpose, endpoints, cli: cliItems };
}

function get(path, purpose) { return { method: "GET", path, purpose }; }
function put(path, purpose, body) { return { method: "PUT", path, purpose, body }; }
function patch(path, purpose, body) { return { method: "PATCH", path, purpose, body }; }
function post(path, purpose, body) { return { method: "POST", path, purpose, body }; }
function browserPost(path, purpose) { return { method: "POST", path, purpose, browserOnly: true }; }
function cli(command, purpose) { return { command, purpose }; }

export function contextForPath(path = "/") {
  const route = parseRoute(path);
  const base = AUTOMATION_CONTEXTS[route.path] || {
    title: "Current route",
    summary: "This route is served by the Phragma WebUI and should remain backed by the public REST/gRPC API.",
    endpoints: [get("/v1/system/status", "Runtime status"), get("/v1/policy?source=POLICY_SOURCE_RUNNING", "Running policy")],
    cli: [cli("ngfwctl status", "Runtime status"), cli("ngfwctl policy show --source running", "Running policy")],
    notes: [`No dedicated automation context exists for ${route.path}; add one when the route gains persistent UI.`],
  };
  if (!route.hasRouteState) return base;
  return withRouteState(base, route);
}

function parseRoute(path) {
  const source = String(path || "/").trim() || "/";
  let raw = source;
  const hashIndex = raw.indexOf("#");
  if (hashIndex >= 0) raw = raw.slice(hashIndex + 1);
  const hasRouteState = source.startsWith("#") || source.includes("?") || hashIndex >= 0;
  if (!raw) raw = "/";
  const [pathPart, ...queryParts] = raw.split("?");
  const cleanPath = pathPart ? (pathPart.startsWith("/") ? pathPart : "/" + pathPart) : "/";
  const queryString = queryParts.join("?");
  const query = new URLSearchParams(queryString);
  return {
    path: cleanPath,
    query,
    hash: "#" + cleanPath + (queryString ? "?" + queryString : ""),
    queryEntries: Array.from(query.entries()),
    hasRouteState,
  };
}

function withRouteState(base, route) {
  const context = {
    ...base,
    endpoints: [...(base.endpoints || [])],
    cli: [...(base.cli || [])],
    notes: [...(base.notes || [])],
    workflow: base.workflow ? base.workflow.map((step) => ({
      ...step,
      endpoints: [...(step.endpoints || [])],
      cli: [...(step.cli || [])],
    })) : undefined,
    routeState: {
      hash: sanitizedRouteHash(route),
      path: route.path,
      queryEntries: sanitizedRouteEntries(route.queryEntries, route.path),
    },
  };
  const exact = exactRouteContext(route);
  const exactEndpoints = exact?.endpoints || (exact?.endpoint ? [exact.endpoint] : []);
  const exactCli = exact?.cli ? (Array.isArray(exact.cli) ? exact.cli : [exact.cli]) : [];
  if (exactEndpoints.length) context.endpoints.unshift(...exactEndpoints);
  if (exactCli.length) context.cli.unshift(...exactCli);
  if (exact?.notes?.length) context.notes.unshift(...exact.notes);
  return context;
}

function sanitizedRouteHash(route) {
  const entries = sanitizedRouteEntries(route.queryEntries, route.path);
  const params = new URLSearchParams();
  for (const [key, value] of entries) params.append(key, value);
  const query = params.toString();
  return "#" + route.path + (query ? "?" + query : "");
}

function sanitizedRouteEntries(entries = [], path = "") {
  return entries
    .filter(([key, value]) => routeStateAllowed(key, value))
    .map(([key, value]) => [String(key), safeRouteDisplayValue(value)]);
}

function routeStateAllowed(key, value) {
  const name = String(key || "").toLowerCase();
  if (/(^|[_-])(token|password|passwd|secret|cookie|authorization)($|[_-])/.test(name)) return false;
  if (/^(access|refresh|id|client)[_-]?token$|api[_-]?key|client[_-]?secret/.test(name)) return false;
  const text = String(value || "");
  if (/(^|[/:])(?:etc|tmp|var|Users|home|private)(?:\/|$)|file:/i.test(text)) return false;
  if (/Bearer\s+[A-Za-z0-9._~+/-]{8,}/i.test(text)) return false;
  if (/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/.test(text)) return false;
  return true;
}

function safeRouteDisplayValue(value) {
  const text = String(value || "");
  return routeStateAllowed("value", text) ? text : "[redacted]";
}

function exactRouteContext(route) {
  if (route.path === "/setup") return exactSetupContext(route.query);
  if (route.path === "/rules") return exactRulesContext(route.query);
  if (route.path === "/nat") return exactNatContext(route.query);
  if (route.path === "/traffic") return exactTrafficContext(route.query);
  if (route.path === "/threats") return exactThreatContext(route.query);
  if (route.path === "/changes") return exactChangesContext(route.query);
  if (route.path === "/troubleshoot") return exactTroubleshootContext(route.query);
  if (route.path === "/settings") return exactSettingsContext(route.query);
  if (route.path === "/objects") return exactObjectsContext(route.query);
  if (route.path === "/netvpn") return exactNetvpnContext(route.query);
  if (route.path === "/intel") return exactIntelContext(route.query);
  if (route.path === "/logs") return exactLogsContext(route.query);
  if (route.path === "/compliance") return exactComplianceContext(route.query);
  return null;
}

function exactSetupContext(query) {
  const config = setupConfigFromQuery(query, {
    scenario: "cloud-edge",
    profile: "throughput",
    insideZone: "lan",
    outsideZone: "wan",
    insideInterfaces: "eth1",
    outsideInterfaces: "eth0",
    insideCidr: "10.0.0.0/24",
    webuiPort: "8080",
    allowOutbound: true,
    masquerade: true,
    hardenHostInput: true,
    clampMss: true,
    flowOffload: true,
    manageNicOffloads: false,
    idsRuleFiles: "local.rules",
    idsQueueNum: "0",
    failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
  });
  const cliText = setupBaselineCliCommand(config);
  const summary = setupContextSummary(config);
  return {
    endpoints: [
      get("/v1/system/status", "Host inventory and runtime posture for the selected Guided setup baseline"),
      put("/v1/candidate", `Stage the generated Guided setup candidate for ${summary}`, "{ \"policy\": { \"zones\": [ ... ], \"rules\": [ ... ], \"nat\": { ... } } }"),
      post("/v1/candidate/validate", "Validate the generated setup candidate before commit", "{}"),
    ],
    cli: [
      cli(cliText, "Exact CLI equivalent for the current Guided setup fields"),
      cli("ngfwctl policy validate", "Validate the staged setup candidate"),
      cli("ngfwctl policy diff", "Review the generated baseline before commit"),
    ],
    notes: [
      `Current Guided setup selection: ${summary}.`,
      config.scenario === "ids-tap"
        ? "IDS tap intentionally stages no outbound allow path and no source NAT."
        : config.scenario === "vpn-edge"
          ? "VPN edge does not generate tunnel peers, private keys, PSKs, or enrollment bundles."
          : "Guided setup stages a candidate only; commit still requires Changes review and an audit reason.",
    ],
  };
}

function exactRulesContext(query) {
  const filters = {
    q: routeText(queryValue(query, "q"), 128).toLowerCase(),
    action: choice(queryValue(query, "action"), ["ACTION_ALLOW", "ACTION_DENY", "ACTION_REJECT"], ""),
    zone: routeText(queryValue(query, "zone"), 96),
    tag: routeText(queryValue(query, "tag"), 96),
    rule: routeText(queryValue(query, "rule"), 128),
    changed: booleanRouteValue(queryValue(query, "changed")),
    density: choice(queryValue(query, "density"), ["comfortable", "compact"], "comfortable"),
    group: choice(queryValue(query, "group"), ["none", "tag", "action", "zone"], "none"),
    drawer: choice(queryValue(query, "drawer"), ["server-overlap-review", "bulk-disable", "bulk-enable", "bulk-log", "bulk-tag"], ""),
  };
  const serverOverlapReview = filters.drawer === "server-overlap-review" || filters.q === "server-overlap";
  const exactEndpoints = [
    get("/v1/policy?source=POLICY_SOURCE_CANDIDATE", serverOverlapReview ? "Candidate rulebase backing server-side overlap peer and dimension review" : "Candidate policy backing the current filtered Rules review"),
    get("/v1/candidate/status", "Candidate dirty-state and section impact for the current Rules workspace"),
    post("/v1/candidate/validate", serverOverlapReview ? "Recompute server-side overlap findings for the candidate rulebase before remediation" : "Validate the currently staged rulebase and cleanup findings", "{}"),
    get("/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE", serverOverlapReview ? "Review logging or tag remediation staged from overlap review before commit" : "Running-to-candidate diff for changed-only Rules review"),
  ];
  const exactCli = [
    cli("ngfwctl policy show --source candidate --json", serverOverlapReview ? "Inspect candidate rule order and peer dimensions backing server-side overlap review" : "Inspect the candidate rulebase backing the current Rules review"),
    cli("ngfwctl policy validate", serverOverlapReview ? "Recompute server overlap findings before relying on drawer evidence" : "Validate staged rules before commit"),
    cli("ngfwctl policy diff", serverOverlapReview ? "Review overlap remediation staged from logging or review tags" : "Review running-to-candidate rule changes"),
  ];
  const explain = rulesExplainRequestFromQuery(query);
  if (explain) {
    exactEndpoints.unshift(post("/v1/explain/flow", "Exact Rules Flow check request from the shared route", JSON.stringify(explain, null, 2)));
    exactCli.unshift(cli(cliCommand("ngfwctl explain", [
      ["--source", cliPolicySource(explain.policySource)],
      ["--from-zone", explain.fromZone],
      ["--to-zone", explain.toZone],
      ["--src", explain.srcIp],
      ["--sport", explain.srcPort ? String(explain.srcPort) : ""],
      ["--dst", explain.destIp],
      ["--dport", explain.destPort ? String(explain.destPort) : ""],
      ["--protocol", cliProtocol(explain.protocol)],
      ["--app-id", explain.appId],
    ]), "Exact CLI equivalent for the current Rules Flow check tuple"));
  }
  const notes = [
    ...(serverOverlapReview ? [
      "Current Rules drawer: server overlap review",
      "Server overlap review is route-backed cleanup context for candidate rulebase first-match order; it does not mutate policy until an operator stages logging or review tags.",
      "Server overlap findings come from candidate validation; rerun validation after candidate changes before relying on stale findings.",
    ] : []),
    `Current Rules review: density=${filters.density}, group=${filters.group}, changed-only=${filters.changed ? "on" : "off"}`,
    "Rules filters, grouping, density, selected rule drawer, and bulk selection are browser review state over the candidate policy.",
    "Bulk enable/disable/log/tag actions stage individual candidate rule mutations; selected rule indexes are never encoded in the URL.",
    "Filtered, grouped, changed-only, or selected views pause drag reorder so hidden rules are not moved accidentally.",
    ...uiOnlyNotes(query, ["q", "action", "zone", "tag", "rule", "changed", "density", "group", "drawer", "simRun"], "Rules route state"),
  ];
  return { endpoints: exactEndpoints, cli: exactCli, notes };
}

function exactNatContext(query) {
  const flow = {
    fromZone: routeText(queryValue(query, "fromZone"), 96),
    toZone: routeText(queryValue(query, "toZone"), 96),
    srcIp: routeText(queryValue(query, "srcIp") || queryValue(query, "src"), 96),
    srcPort: validIntText(queryValue(query, "srcPort") || queryValue(query, "sport"), 0, 65535),
    destIp: routeText(queryValue(query, "destIp") || queryValue(query, "dst"), 96),
    destPort: validIntText(queryValue(query, "destPort") || queryValue(query, "dport"), 0, 65535),
    protocol: explainProtocol(queryValue(query, "protocol")),
  };
  if (!flow.srcIp || !flow.destIp || !flow.destPort) return null;
  const running = natExplainBody(flow, "POLICY_SOURCE_RUNNING");
  const candidate = natExplainBody(flow, "POLICY_SOURCE_CANDIDATE");
  const tuple = `${flow.srcIp}:${flow.srcPort || "any"} -> ${flow.destIp}:${flow.destPort} ${cliProtocol(flow.protocol)}`;
  return {
    endpoints: [
      post("/v1/explain/flow", `Exact NAT path preview against running policy for ${tuple}`, JSON.stringify(running, null, 2)),
      post("/v1/explain/flow", `Exact NAT path preview against candidate policy for ${tuple}`, JSON.stringify(candidate, null, 2)),
      get("/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE", "Candidate diff for NAT, security rule, and route changes before commit"),
      get("/v1/candidate/status", "Candidate dirty-state and section impact paired with the NAT preview"),
    ],
    cli: [
      cli(natExplainCli(running), "Replay the current NAT preview tuple against running policy"),
      cli(natExplainCli(candidate), "Replay the current NAT preview tuple against candidate policy"),
      cli("ngfwctl policy diff", "Review running-to-candidate NAT and policy changes"),
    ],
    notes: [
      `Current NAT preview tuple: ${tuple}`,
      "NAT preview route state is exact replay context for ExplainFlow; run, caseKey, caseAction, and caseKind are browser workflow hints, not API fields.",
      "The preview compares running and candidate policy without mutating either side.",
      ...uiOnlyNotes(query, ["run", "caseKey", "caseAction", "caseKind", "nat", "rule", "idx"], "NAT preview route state"),
    ],
  };
}

function natExplainBody(flow, policySource) {
  return {
    policySource,
    version: "0",
    fromZone: flow.fromZone,
    toZone: flow.toZone,
    srcIp: flow.srcIp,
    srcPort: Number(flow.srcPort || 0),
    destIp: flow.destIp,
    destPort: Number(flow.destPort || 0),
    protocol: flow.protocol,
    appId: "",
  };
}

function natExplainCli(body) {
  return cliCommand("ngfwctl explain", [
    ["--source", cliPolicySource(body.policySource)],
    ["--from-zone", body.fromZone],
    ["--to-zone", body.toZone],
    ["--src", body.srcIp],
    ["--sport", body.srcPort ? String(body.srcPort) : ""],
    ["--dst", body.destIp],
    ["--dport", body.destPort ? String(body.destPort) : ""],
    ["--protocol", cliProtocol(body.protocol)],
  ]);
}

function exactIntelContext(query) {
  const surface = choice(queryValue(query, "surface"), ["app-id", "threat-id", "intel-feeds"], "");
  if (!surface) return null;
  const drawer = choice(queryValue(query, "drawer"), ["review", "quality", "install", "rollback"], "review");
  const label = {
    "app-id": "App-ID",
    "threat-id": "Threat-ID",
    "intel-feeds": "feed",
  }[surface] || surface;
  const corpusEvidence = surface === "app-id" ? "app-regression-corpus" : surface === "threat-id" ? "pcap-regression-corpus" : "feed-quality";
  const notes = [
    `Current Intel surface: ${surface}`,
    `Current Intel drawer: ${drawer}`,
    "Intel route state is a handoff target only; source directories, rollback paths, manifests, tokens, and secrets must stay out of the URL.",
  ];
  if (drawer === "install") {
    return {
      endpoint: post(`/v1/intel/content/packages/${surface}/install`, `Install a verified server-local ${label} content package after package review`, `{ "sourcePath": "${surface}" }`),
      cli: cli(`ngfwctl intel content install ${surface} --source ${surface}`, `Install ${label} package from the configured content import root`),
      notes: [...notes, "Install remains server-side and audited; the browser supplies only an import-root-relative package selector."],
    };
  }
  if (drawer === "rollback") {
    return {
      endpoint: post(`/v1/intel/content/packages/${surface}/rollback`, `Rollback ${label} content to the latest verified backup`, `{ "ackRollback": true }`),
      cli: cli(`ngfwctl intel content rollback ${surface} --ack-rollback`, `Rollback ${label} content after operator acknowledgement`),
      notes: [...notes, "Rollback is disabled in the UI until the content API reports a verified backup."],
    };
  }
  if (drawer === "quality") {
    return {
      endpoints: [
        get("/v1/intel/content/packages", `Review installed ${label} package signature, hash, evidence inventory, rollout posture, and blockers`),
        get(`/v1/intel/content/packages/${surface}/evidence/${corpusEvidence}`, `Inspect bounded package-local ${label} quality evidence after manifest hash verification`),
        get(`/v1/intel/content/packages/${surface}/corpus?evidence_type=${corpusEvidence}&limit=100`, `Browse typed ${label} regression corpus rows without parsing raw evidence JSON`),
        post(`/v1/intel/content/packages/${surface}/compare`, `Preview candidate ${label} package quality and corpus diff without installing`, `{ "sourcePath": "${surface}", "evidenceType": "${corpusEvidence}" }`),
      ],
      cli: [
        cli("ngfwctl intel content", `Review ${label} content package posture before lifecycle action`),
        cli(`ngfwctl intel content corpus ${surface} --evidence-type ${corpusEvidence} --limit 100`, `Browse typed ${label} regression corpus rows from verified package-local evidence`),
        cli(`ngfwctl intel content compare ${surface} --source ${surface} --evidence-type ${corpusEvidence}`, `Preview ${label} import quality and corpus diff before install`),
      ],
      notes: [
        ...notes,
        "Quality review uses bounded package-local evidence verified against the manifest; operators should not copy manifest paths or server-local evidence paths into the route.",
        "Compare preview is non-mutating; install remains a separate audited lifecycle action.",
      ],
    };
  }
  return {
    endpoint: get("/v1/intel/content/packages", `Review signature, hash, provenance, regression, rollout, production evidence, and rollback posture for ${label} content`),
    cli: cli("ngfwctl intel content", `Review ${label} content package posture before lifecycle action`),
    notes,
  };
}

function exactComplianceContext(query) {
  const reportId = safeReportId(queryValue(query, "report") || queryValue(query, "reportId") || queryValue(query, "id"));
  const profile = choice(queryValue(query, "profile"), ["operational", "change-control", "privileged-access", "content-lifecycle", "incident-evidence"], "operational");
  const limit = integerRange(queryValue(query, "limit"), 1, 100, 50);
  const notes = [`Current Compliance profile: ${profile}`];
  if (!reportId) {
    return {
      endpoints: [
        get(`/v1/compliance/reports?limit=${limit}`, "Route-filtered retained compliance report summaries"),
        post("/v1/compliance/reports", "Create retained unsigned compliance report for the selected profile", `{ "profile": "${profile}", "auditLimit": 300, "versionLimit": 100, "logLimit": 100 }`),
      ],
      cli: [
        cli(`ngfwctl compliance reports list --limit ${limit}`, "Route-filtered retained compliance report summaries"),
        cli(`ngfwctl compliance reports create --profile ${profile} --audit-limit 300 --version-limit 100 --log-limit 100`, "Create retained unsigned compliance report for the selected profile"),
      ],
      notes,
    };
  }
  return {
    endpoints: [
      get(`/v1/compliance/reports/${reportId}`, "Inspect the selected retained compliance report summary"),
      get(`/v1/compliance/reports/${reportId}/export`, "Export the selected retained compliance report JSON artifact"),
    ],
    cli: [
      cli(`ngfwctl compliance reports get ${reportId}`, "Inspect the selected retained compliance report summary"),
      cli(`ngfwctl compliance reports export ${reportId} --output ${reportId}.json`, "Export the selected retained compliance report JSON artifact"),
    ],
    notes: [`Current Compliance report: ${reportId}`, ...notes, "Report export is retained operational evidence; signing, legal hold, and external verification remain hardening work."],
  };
}

function safeReportId(value) {
  const text = String(value || "").trim();
  return /^report-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$/.test(text) ? text : "";
}

function exactLogsContext(query) {
  const req = {
    limit: choice(queryValue(query, "limit"), ["100", "200", "500"], "200"),
  };
  setIf(req, "source", choice(queryValue(query, "source"), ["system", "engine", "dataplane", "audit"], ""));
  setIf(req, "engine", routeText(queryValue(query, "engine"), 32).toLowerCase().replace(/[^a-z0-9_-]+/g, ""));
  setIf(req, "severity", choice(queryValue(query, "severity"), ["critical", "error", "warn", "notice", "info", "debug"], ""));
  const q = routeText(queryValue(query, "q"), 160);
  setIf(req, "query", routeStateAllowed("q", q) ? q : "");
  setIf(req, "since", localDateTimeToISOString(queryValue(query, "since")));
  setIf(req, "until", localDateTimeToISOString(queryValue(query, "until")));
  const notes = [
    "Current System logs view is read-only evidence from the configured bounded log root; route filters never select filesystem paths.",
    ...uiOnlyNotes(query, ["entry"], "System logs route state"),
  ];
  return {
    endpoint: get(withQuery("/v1/system/logs", req), "Exact filtered system-log request for the current Logs view"),
    cli: cli(cliCommand("ngfwctl system logs", [
      ["--limit", req.limit],
      ["--source", req.source],
      ["--engine", req.engine],
      ["--severity", req.severity],
      ["--query", req.query],
      ["--since", req.since],
      ["--until", req.until],
    ]), "Exact CLI equivalent for the current Logs view"),
    notes,
  };
}

function rulesExplainRequestFromQuery(query) {
  const source = queryValue(query, "simSource");
  const fromZone = queryValue(query, "simFrom");
  const toZone = queryValue(query, "simTo");
  const srcIp = queryValue(query, "simSrc");
  const destIp = queryValue(query, "simDst");
  const srcPort = validIntText(queryValue(query, "simSport"), 1, 65535);
  const destPort = validIntText(queryValue(query, "simDport"), 1, 65535);
  const protocol = explainProtocol(queryValue(query, "simProtocol"));
  const appId = queryValue(query, "simApp");
  const hasTuple = Boolean(source || fromZone || toZone || srcIp || destIp || srcPort || destPort || appId || queryValue(query, "simRun"));
  if (!hasTuple) return null;
  return {
    policySource: explainPolicySource(source),
    version: "0",
    fromZone,
    toZone,
    srcIp,
    srcPort: Number(srcPort || 0),
    destIp,
    destPort: Number(destPort || 0),
    protocol,
    appId,
  };
}

function exactObjectsContext(query) {
  const route = normalizeObjectRoute({
    tab: queryValue(query, "tab"),
    drawer: queryValue(query, "drawer"),
    object: queryValue(query, "object"),
  });
  const tab = route.tab;
  const kind = {
    addresses: "POLICY_OBJECT_KIND_ADDRESS",
    services: "POLICY_OBJECT_KIND_SERVICE",
    applications: "POLICY_OBJECT_KIND_APPLICATION",
    zones: "POLICY_OBJECT_KIND_ZONE",
    securityProfiles: "POLICY_OBJECT_KIND_SECURITY_PROFILE",
    trafficControls: ["POLICY_OBJECT_KIND_QOS_PROFILE", "POLICY_OBJECT_KIND_ZONE_PROTECTION_PROFILE"],
  }[tab];
  const cliKind = {
    addresses: "address",
    services: "service",
    applications: "application",
    zones: "zone",
    securityProfiles: "security-profile",
    trafficControls: ["qos-profile", "zone-protection-profile"],
  }[tab];
  const kinds = [].concat(kind || []);
  const cliKinds = [].concat(cliKind || []);
  const objectName = (route.drawer === "references" || route.drawer === "impact") ? route.object : "";
  const referenceRequests = kinds.map((apiKind) => {
    const req = {
      source: "POLICY_SOURCE_CANDIDATE",
      kind: apiKind,
    };
    if (objectName) req.name = objectName;
    return req;
  });
  const objectLabel = (route.drawer === "references" || route.drawer === "impact") && route.object ? ` for ${route.object}` : "";
  const notes = [
    `Current Objects tab: ${tab}`,
    "Object editor draft values are never encoded in the URL.",
  ];
  if (route.drawer === "references" && route.object) {
    notes.unshift(`Current Objects drawer: references for ${route.object}`);
    notes.push("The object reference drawer is route-backed and can be reopened from incident or cleanup tickets.");
  } else if (route.drawer === "impact" && tab === "securityProfiles" && route.object) {
    notes.unshift(`Current Objects drawer: security profile impact for ${route.object}`);
    notes.push("The security profile impact drawer is route-backed and reviews candidate rule blast radius, blocking intent, and IDS/IPS fail-closed posture.");
    notes.push("TLS broker custody, URL database provenance, DNS sinkhole behavior, and file-inspection engine proof remain hardening evidence; this context is for candidate policy review.");
  } else {
    notes.push("Objects route state selects an object class unless a reference drawer target is present.");
  }
  const impactDrawer = route.drawer === "impact" && tab === "securityProfiles" && route.object;
  const cliItems = cliKinds.map((kindName) =>
    cli(cliCommand("ngfwctl policy references", [["--source", "candidate"], ["--kind", kindName], ["--name", objectName]]), `Exact CLI reverse-reference review for candidate ${tab}${objectLabel}`),
  ).concat([
    cli("ngfwctl policy show --source candidate --json", `Inspect candidate ${tab}${objectLabel} before edit, delete, or reference review`),
  ]);
  if (impactDrawer) {
    cliItems.push(
      cli("ngfwctl policy validate", `Validate candidate before rollout of security profile ${route.object}`),
      cli("ngfwctl policy diff", `Review running-to-candidate diff for rules attaching ${route.object}`),
    );
  }
  const endpoints = referenceRequests.map((req) =>
    get(withQuery("/v1/policy/object-references", req), `Candidate reverse-reference map for the current Objects ${tab} tab${objectLabel}`),
  );
  if (impactDrawer) {
    endpoints.push(
      get("/v1/policy?source=POLICY_SOURCE_CANDIDATE", `Candidate policy containing security profile ${route.object} and affected rules`),
      post("/v1/candidate/validate", `Validate candidate profile rollout for ${route.object} before commit`, "{ \"policy\": { ... } }"),
      get("/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE", `Running-to-candidate diff for security profile ${route.object} rollout review`),
    );
  }
  return {
    endpoints,
    cli: cliItems,
    notes,
  };
}

function exactNetvpnContext(query) {
  const drawer = choice(queryValue(query, "drawer"), ["tunnel", "route", "bgp", "ospf"], "");
  const mode = choice(queryValue(query, "mode"), ["review", "edit"], "review");
  if (drawer === "route") {
    const routeName = routeCidr(queryValue(query, "name"), "") || routeText(queryValue(query, "name"), 96);
    return {
      endpoints: [
        get("/v1/system/status", "Runtime route renderer and interface posture for selected static route context"),
        get("/v1/policy?source=POLICY_SOURCE_CANDIDATE", `Candidate staticRoutes section${routeName ? ` containing ${routeName}` : ""}`),
        post("/v1/candidate/validate", "Validate static route candidate before commit", "{}"),
      ],
      cli: [
        cli("ngfwctl policy route list --source candidate", "List candidate static routes"),
        routeName ? cli(`ngfwctl policy route delete --destination ${routeName}`, "Remove the selected candidate static route when reviewed") : null,
        cli("ngfwctl policy diff", "Review static route changes against running policy"),
        cli("ngfwctl commit -m \"update static route\"", "Publish reviewed static route changes after validation"),
      ].filter(Boolean),
      notes: [
        `Current Routing & VPN drawer: static route ${mode}${routeName ? ` for ${routeName}` : ""}.`,
        "Static route edits use granular route CLI parity; running kernel routes change only after commit.",
      ],
    };
  }
  if (drawer === "bgp" || drawer === "ospf") {
    const label = drawer.toUpperCase();
    return {
      endpoints: [
        get("/v1/system/status", `Passive routing service runtime posture for ${label} route review`),
        get("/v1/policy?source=POLICY_SOURCE_CANDIDATE", `Candidate routing.${drawer} configuration`),
        post("/v1/candidate/validate", `Validate ${label} candidate before commit`, "{}"),
      ],
      cli: [
        cli("ngfwctl status", `Inspect routing service and ${label} runtime posture`),
        cli("ngfwctl policy show --source candidate --json", `Export candidate routing.${drawer} configuration`),
        cli("ngfwctl policy diff", `Review ${label} changes against running policy`),
        cli(`ngfwctl commit -m "update ${drawer}"`, `Publish reviewed ${label} changes after validation`),
      ],
      notes: [
        `Current Routing & VPN drawer: ${label} ${mode}.`,
        "Dynamic routing changes still converge through candidate export/edit/set, validation, diff, commit, rollback, and audit until dedicated granular dynamic-routing APIs exist.",
      ],
    };
  }
  if (drawer !== "tunnel") return null;
  const kind = choice(queryValue(query, "kind"), ["wireguard", "ipsec"], "");
  if (!kind) return null;
  const iface = routeText(queryValue(query, "iface"), 64);
  const peer = routeText(queryValue(query, "peer"), 96);
  const name = routeText(queryValue(query, "name"), 96);
  if (kind === "wireguard" && (!iface || !peer)) return null;
  if (kind === "ipsec" && !name) return null;
  const tunnelLabel = kind === "wireguard" ? `${iface}:${peer}` : name;
  const srcIp = routeIp(queryValue(query, "src"), "10.0.1.10");
  const destIp = routeIp(queryValue(query, "dst"), kind === "wireguard" ? "10.99.0.2" : "10.20.0.10");
  const localCidr = routeCidr(queryValue(query, "local"), "");
  const remoteCidr = routeCidr(queryValue(query, "remote"), "");
  const protocol = routeProtocol(queryValue(query, "protocol"), "PROTOCOL_UDP");
  const cliProtocol = protocol.replace(/^PROTOCOL_/, "").toLowerCase();
  const sessionPort = routePort(queryValue(query, "port"), kind === "wireguard" ? "51820" : "4500");
  const explainBody = JSON.stringify({
    policySource: "POLICY_SOURCE_CANDIDATE",
    fromZone: "lan",
    toZone: "vpn",
    srcIp,
    destIp,
    destPort: Number(sessionPort),
    protocol,
  }, null, 2);
  const pathNote = localCidr || remoteCidr
    ? `Selected representative path: ${localCidr || srcIp} -> ${remoteCidr || destIp} (${srcIp} -> ${destIp}).`
    : `Selected representative path: ${srcIp} -> ${destIp}.`;
  return {
    endpoints: [
      get("/v1/system/status", `Runtime interface, route renderer, and ${kind === "wireguard" ? "WireGuard" : "IPsec"} posture for selected tunnel ${tunnelLabel}`),
      get("/v1/policy?source=POLICY_SOURCE_CANDIDATE", `Candidate Routing & VPN policy containing selected tunnel ${tunnelLabel}`),
      post("/v1/explain/flow", `Candidate path explanation for selected ${kind === "wireguard" ? "WireGuard peer" : "IPsec tunnel"}`, explainBody),
      get(`/v1/sessions?protocol=UDP&port=${sessionPort}&limit=100`, `Live UDP session evidence commonly associated with selected ${kind === "wireguard" ? "WireGuard" : "IPsec"} tunnel`),
    ],
    cli: [
      cli("ngfwctl status", `Inspect runtime Routing & VPN posture before acting on ${tunnelLabel}`),
      cli("ngfwctl policy show --source candidate --json", "Export candidate staticRoutes, routing, and vpn sections for route-backed tunnel review"),
      cli(cliCommand("ngfwctl explain", [["--source", "candidate"], ["--from-zone", "lan"], ["--to-zone", "vpn"], ["--src", srcIp], ["--dst", destIp], ["--protocol", cliProtocol], ["--dport", sessionPort]]),
        "Replay the selected representative candidate tunnel path headlessly"),
      cli(`ngfwctl sessions --protocol UDP --port ${sessionPort} --limit 100`, "Inspect bounded live tunnel/session evidence when runtime data is available"),
    ],
    notes: [
      `Current Routing & VPN drawer: ${kind} tunnel ${tunnelLabel}`,
      pathNote,
      "Route-backed tunnel context is a handoff target only; secret file paths, private keys, PSKs, and endpoint credentials must stay out of copied context.",
      "BGP, OSPF, IPsec, and WireGuard edits still converge through candidate export/edit/set, validation, diff, commit, rollback, and audit until dedicated granular VPN CLIs exist.",
    ],
  };
}

function exactSettingsContext(query) {
  const panel = choice(queryValue(query, "panel"), ["telemetry", "network", "host-input", "access"], "");
  if (!panel) return null;
  const notes = [
    `Current Settings panel: ${panel}`,
    "Settings panel route state is a handoff target only; unsaved form values and secrets are never encoded in the URL.",
  ];
  if (panel === "network") {
    return {
      endpoint: get("/v1/policy?source=POLICY_SOURCE_CANDIDATE", "Candidate network, zone-interface, MTU, offload, and flowtable settings for the current Settings panel"),
      cli: cli("ngfwctl policy network set --mtu 9000 --clamp-mss on --manage-nic-offloads on", "Stage lower-level network overrides from the current Settings panel"),
      notes,
    };
  }
  if (panel === "telemetry") {
    const evidenceCommands = telemetryEvidenceCommands({ telemetry: { enabled: true } })
      .map((item) => `Telemetry evidence ${item.label}: ${item.command}`);
    return {
      endpoints: [
        get("/v1/system/telemetry/exports/status", "Passive running-policy telemetry export posture for the current Settings panel"),
        get("/v1/policy?source=POLICY_SOURCE_CANDIDATE", "Candidate telemetry export settings for the current Settings panel"),
      ],
      cli: [
        cli("ngfwctl system telemetry-export-status --json", "Inspect passive running-policy export posture without sending test events"),
        cli("ngfwctl policy show --source candidate --json", "Inspect candidate telemetry settings before validate/commit"),
      ],
      notes: [...notes, "Telemetry evidence packet: export the redacted phragma.telemetry.evidence.v1 JSON packet from Settings after commit.", ...evidenceCommands],
    };
  }
  if (panel === "host-input") {
    return {
      endpoints: [
        get("/v1/policy?source=POLICY_SOURCE_CANDIDATE", "Candidate host-input default action and management allow rules for the current Settings panel"),
        post("/v1/candidate/validate", "Validate host-input lockout guardrails and policy hygiene before commit", "{}"),
        get("/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE", "Review running-to-candidate host-input changes before commit"),
      ],
      cli: [
        cli("ngfwctl policy show --source candidate --json", "Inspect candidate host-input rules before validate/commit"),
        cli("ngfwctl policy validate", "Validate staged host-input and management access policy"),
        cli("ngfwctl policy diff", "Review running-to-candidate host-input changes"),
        cli("ngfwctl policy baseline --profile throughput --harden-host-input", "Bootstrap a candidate baseline with host-input default-deny and management allow coverage"),
      ],
      notes: [
        ...notes,
        "Default-drop host input must preserve explicit management allow rules before commit review.",
        "Unsaved host-input form values are not encoded in this route or copied context.",
      ],
    };
  }
  return {
    endpoints: [
      get("/v1/system/identity", "Current actor, role, auth source, and capabilities for the Settings access panel"),
      get("/v1/system/access-administration", "RBAC posture, redacted local-user inventory, editable flags, and non-secret OIDC/SAML session inventory"),
      get("/v1/system/access-administration/oidc/config", "Return redacted node-local OIDC provider configuration without secret file paths or secret bytes"),
      post("/v1/system/access-administration/oidc/config:validate", "Validate proposed OIDC provider settings without mutating runtime state", "{ \"config\": { \"issuer\": \"https://idp.example.com\", \"clientId\": \"phragma-web\", \"redirectUrl\": \"https://fw.example.com/v1/auth/oidc/callback\", \"roleClaim\": \"groups\", \"defaultRole\": \"viewer\", \"scopes\": [\"openid\", \"profile\", \"email\"] } }"),
      { method: "PUT", path: "/v1/system/access-administration/oidc/config", purpose: "Persist and activate node-local OIDC provider config through the audited runtime lifecycle", body: "{ \"config\": { \"issuer\": \"https://idp.example.com\", \"clientId\": \"phragma-web\", \"clientSecretFile\": \"[server-local path]\", \"redirectUrl\": \"https://fw.example.com/v1/auth/oidc/callback\", \"roleClaim\": \"groups\", \"defaultRole\": \"viewer\", \"scopes\": [\"openid\", \"profile\", \"email\"] }, \"comment\": \"configure OIDC provider\", \"ackOidcChange\": true }" },
      post("/v1/system/access-administration/oidc/config:disable", "Disable browser SSO provider config and revoke active OIDC sessions while preserving local break-glass access", "{ \"comment\": \"disable OIDC provider\", \"ackDisableOidc\": true }"),
      get("/v1/system/access-administration/saml/config", "Return redacted node-local SAML provider configuration and runtime posture without assertion, RelayState, certificate, or path material"),
      { method: "POST", path: "/v1/system/access-administration/saml/config:validate", purpose: "Validate proposed SAML provider settings without mutating runtime login or sessions", body: "{ \"config\": { \"metadataUrl\": \"https://idp.example.com/metadata\", \"spEntityId\": \"https://fw.example.com/ui\", \"acsUrl\": \"https://fw.example.com/v1/auth/saml/acs\", \"roleAttribute\": \"groups\", \"defaultRole\": \"viewer\" } }" },
      { method: "PUT", path: "/v1/system/access-administration/saml/config", purpose: "Persist and activate node-local SAML provider config through the audited runtime lifecycle", body: "{ \"config\": { \"metadataUrl\": \"https://idp.example.com/metadata\", \"spEntityId\": \"https://fw.example.com/ui\", \"acsUrl\": \"https://fw.example.com/v1/auth/saml/acs\", \"roleAttribute\": \"groups\", \"defaultRole\": \"viewer\" }, \"comment\": \"configure SAML provider\", \"ackSamlChange\": true }" },
      post("/v1/system/access-administration/saml/config:disable", "Disable browser SAML provider config and revoke active SAML sessions while preserving local break-glass access", "{ \"comment\": \"disable SAML provider\", \"ackDisableSaml\": true }"),
      get("/v1/auth/saml/status", "Browser SAML runtime availability, login URL, authenticated actor, and CSRF token for the active browser session"),
      post("/v1/system/access-administration/local-users", "Create one audited local break-glass user; generated token is returned only once in the response", "{ \"name\": \"breakglass-viewer\", \"role\": \"viewer\", \"comment\": \"create break-glass viewer\", \"ackLocalUserChange\": true }"),
      { method: "PATCH", path: "/v1/system/access-administration/local-users/{name}", purpose: "Change one local user's role without accepting token material", body: "{ \"role\": \"operator\", \"comment\": \"update break-glass role\", \"ackLocalUserChange\": true }" },
      post("/v1/system/access-administration/local-users/{name}:rotate-token", "Rotate one local user's token hash; generated token is returned only once in the response", "{ \"comment\": \"rotate break-glass token\", \"ackRotateToken\": true }"),
      post("/v1/system/access-administration/local-users/{name}:disable", "Disable one local user while preserving audit-visible inventory", "{ \"comment\": \"disable break-glass user\", \"ackDisableUser\": true }"),
      post("/v1/system/access-administration/sessions/{sessionId}:revoke", "Force-sign-out one active browser SSO session by non-secret session ID", "{ \"ackRevokeSession\": true }"),
      get("/v1/audit?action=access-local-user-create&limit=300", "Audit trail for local-user administration actions"),
      get("/v1/audit?action=access-oidc-provider-set&limit=300", "Audit trail for OIDC provider configuration changes"),
      get("/v1/audit?action=access-saml-provider-set&limit=300", "Audit trail for SAML provider configuration changes"),
    ],
    cli: [
      cli("ngfwctl whoami", "Verify the current API actor and role for the Settings access panel"),
      cli("ngfwctl access users list", "List redacted local-user inventory"),
      cli("ngfwctl access oidc provider show", "Show redacted runtime OIDC provider config"),
      cli("ngfwctl access oidc provider validate --issuer https://idp.example.com --client-id phragma-web --redirect-url https://fw.example.com/v1/auth/oidc/callback --role-claim groups --default-role viewer --scopes openid,profile,email --trusted-proxy-cidrs 10.0.0.0/8", "Validate OIDC provider settings without mutation"),
      cli("ngfwctl access oidc provider set --issuer https://idp.example.com --client-id phragma-web --client-secret-file [server-local path] --redirect-url https://fw.example.com/v1/auth/oidc/callback --role-claim groups --default-role viewer --scopes openid,profile,email --trusted-proxy-cidrs 10.0.0.0/8 --ack-oidc-change -m \"configure OIDC provider\"", "Persist and activate runtime OIDC provider config through the audited API"),
      cli("ngfwctl access oidc provider disable --ack-disable-oidc -m \"disable OIDC provider\"", "Disable browser SSO and revoke active OIDC sessions through the audited API"),
      cli("ngfwctl access saml provider show", "Show redacted runtime SAML provider config"),
      cli("ngfwctl access saml provider validate --metadata-url https://idp.example.com/metadata --sp-entity-id https://fw.example.com/ui --acs-url https://fw.example.com/v1/auth/saml/acs --role-attribute groups --default-role viewer", "Validate SAML provider settings without mutation"),
      cli("ngfwctl access saml provider set --metadata-url https://idp.example.com/metadata --sp-entity-id https://fw.example.com/ui --acs-url https://fw.example.com/v1/auth/saml/acs --role-attribute groups --default-role viewer --ack-saml-change -m \"configure SAML provider\"", "Persist and activate runtime SAML provider config through the audited API"),
      cli("ngfwctl access saml provider disable --ack-disable-saml -m \"disable SAML provider\"", "Disable browser SAML and revoke active SAML sessions through the audited API"),
      cli("ngfwctl access users create breakglass-viewer --role viewer --ack-local-user-change -m \"create break-glass viewer\"", "Create an audited break-glass viewer and print the one-time token once"),
      cli("ngfwctl access users set-role breakglass-viewer --role operator --ack-local-user-change -m \"update break-glass role\"", "Change a local user's role through the audited API"),
      cli("ngfwctl access users rotate-token breakglass-viewer --ack-rotate-token -m \"rotate break-glass token\"", "Rotate a local user's credential and print the replacement token once"),
      cli("ngfwctl access users disable breakglass-viewer --ack-disable-user -m \"disable break-glass user\"", "Disable a local user through the audited API"),
      cli("ngfwctl access sessions list", "List active browser SSO sessions by non-secret session ID"),
      cli("ngfwctl access sessions revoke <session-id> --ack-revoke-session", "Force-sign-out one active browser SSO session through the audited API"),
      cli("ngfwctl audit --action access-local-user-create --hashes", "Verify access-administration audit entries with integrity hashes"),
      cli("ngfwctl audit --action access-oidc-provider-set --hashes", "Verify OIDC provider lifecycle audit entries with integrity hashes"),
      cli("ngfwctl audit --action access-saml-provider-set --hashes", "Verify SAML provider lifecycle audit entries with integrity hashes"),
    ],
    notes: [
      ...notes,
      "Browser SSO session revoke is available through API, WebUI, and ngfwctl access sessions; the session ID is a non-secret server-side fingerprint.",
      "OIDC provider config save/disable is available through API, WebUI, and ngfwctl access oidc provider; inventory never serializes client secret bytes or server-local secret file paths.",
      "SAML provider config save/disable is available through API, WebUI, and ngfwctl access saml provider; runtime status never serializes SAMLResponse, RelayState contents, certificate material, or server-local paths.",
      "Create and rotate responses may display a one-time token; route state and copied automation context must never include generated token values.",
    ],
  };
}

function exactTrafficContext(query) {
  const mode = choice(queryValue(query, "mode"), ["flows", "sessions", "app-id"], "flows");
  if (mode === "sessions") {
    const req = { limit: choice(queryValue(query, "limit"), ["100", "500", "1000"], "500") };
    setIf(req, "query", queryValue(query, "q"));
    setIf(req, "ip", queryValue(query, "ip"));
    setIf(req, "protocol", choice(queryValue(query, "protocol"), ["TCP", "UDP", "ICMP"], ""));
    setIf(req, "port", validIntText(queryValue(query, "port"), 1, 65535));
    setIf(req, "state", choice(queryValue(query, "sessionState"), ["ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT", "TIME_WAIT", "CLOSE", "UNREPLIED"], ""));
    return {
      endpoint: get(withQuery("/v1/sessions", req), "Exact filtered live-session request for the current Traffic view"),
      cli: cli(cliCommand("ngfwctl sessions", [["--limit", req.limit], ["--query", req.query], ["--ip", req.ip], ["--protocol", req.protocol], ["--port", req.port], ["--state", req.state]]), "Exact CLI equivalent for the current Traffic Sessions view"),
      notes: uiOnlyNotes(query, ["sessionSort", "flowId", "queueId", "sessionKey"], "Traffic route state"),
    };
  }
  if (mode === "app-id") {
    const req = {
      limit: choice(queryValue(query, "limit"), ["50", "100", "250"], "100"),
      flowLimit: validIntText(queryValue(query, "flowLimit"), 1, 1000000) || "1000",
      confidenceThreshold: validIntText(queryValue(query, "confidenceThreshold"), 1, 100) || "70",
    };
    setIf(req, "query", queryValue(query, "q"));
    setIf(req, "kind", choice(queryValue(query, "observationKind"), ["APP_ID_OBSERVATION_KIND_UNKNOWN", "APP_ID_OBSERVATION_KIND_LOW_CONFIDENCE", "APP_ID_OBSERVATION_KIND_CONFLICTING_EVIDENCE"], ""));
    setIf(req, "engineSignal", queryValue(query, "engineSignal"));
    setIf(req, "protocol", choice(queryValue(query, "protocol"), ["TCP", "UDP", "ICMP"], ""));
    setIf(req, "port", validIntText(queryValue(query, "port"), 1, 65535));
    setIf(req, "since", localDateTimeToISOString(queryValue(query, "since")));
    setIf(req, "until", localDateTimeToISOString(queryValue(query, "until")));
    const kind = cliAppIDObservationKind(req.kind);
    const queueId = routeText(queryValue(query, "queueId"), 128);
    const notes = uiOnlyNotes(query, ["observationSort", "queueId", "flowId", "sessionKey"], "Traffic route state");
    if (queueId) {
      notes.push(`Selected App-ID queue item: ${queueId}`);
    }
    const observationEndpoint = get(withQuery("/v1/app-id/observations", req), "Exact filtered App-ID observation request for the current Traffic view");
    const stageBody = {
      mode: "APP_ID_OBSERVATION_STAGE_MODE_DEFINE_ONLY",
      reason: "reviewed App-ID observation",
      flowLimit: Number(req.flowLimit),
      confidenceThreshold: Number(req.confidenceThreshold),
    };
    const regressionBody = {
      reason: "reviewed App-ID observation",
      pcapSha256: "<capture-sha256>",
      expectedApp: "<expected-app-id>",
      observedApp: "<observed-app-id>",
      flowLimit: Number(req.flowLimit),
      confidenceThreshold: Number(req.confidenceThreshold),
    };
    const replayBody = {
      queueId: queueId || "<queue-id>",
      expectedApp: "<expected-app-id>",
      flowLimit: Number(req.flowLimit),
      confidenceThreshold: Number(req.confidenceThreshold),
    };
    setIf(stageBody, "since", req.since);
    setIf(stageBody, "until", req.until);
    setIf(regressionBody, "since", req.since);
    setIf(regressionBody, "until", req.until);
    setIf(replayBody, "since", req.since);
    setIf(replayBody, "until", req.until);
    return {
      endpoint: queueId ? undefined : observationEndpoint,
      endpoints: queueId
        ? [
          observationEndpoint,
          post("/v1/app-id/replay:compare", "Compare the selected App-ID observation as a read-only lab replay report", JSON.stringify(replayBody, null, 2)),
          post(`/v1/app-id/observations/${encodeURIComponent(queueId)}:stage`, "Stage the selected App-ID observation as a candidate object after review", JSON.stringify(stageBody, null, 2)),
          post(`/v1/app-id/observations/${encodeURIComponent(queueId)}:stage-regression-sample`, "Append the selected reviewed observation to the draft App-ID regression corpus", JSON.stringify(regressionBody, null, 2)),
        ]
        : undefined,
      cli: queueId
        ? [
          cli(cliCommand("ngfwctl app-id observations", [["--limit", req.limit], ["--flow-limit", req.flowLimit], ["--confidence-threshold", req.confidenceThreshold], ["--query", req.query], ["--kind", kind], ["--engine-signal", req.engineSignal], ["--protocol", req.protocol], ["--port", req.port], ["--since", req.since], ["--until", req.until]]), "Exact CLI equivalent for the current App-ID observation view"),
          cli(cliCommand("ngfwctl app-id promote " + shellArg(queueId), [["--reason", "reviewed App-ID observation"], ["--flow-limit", req.flowLimit], ["--confidence-threshold", req.confidenceThreshold], ["--since", req.since], ["--until", req.until]]), "Stage the selected observation as a candidate App-ID object"),
          cli(cliCommand("ngfwctl app-id promote " + shellArg(queueId), [["--drop", true], ["--confirm-drop", true], ["--reason", "block repeated unknown app"], ["--flow-limit", req.flowLimit], ["--confidence-threshold", req.confidenceThreshold], ["--since", req.since], ["--until", req.until]]), "Stage the selected observation plus a reviewed candidate drop rule"),
          cli(cliCommand("ngfwctl app-id corpus add " + shellArg(queueId), [["--pcap-sha256", "<capture-sha256>"], ["--expected-app", "<expected-app-id>"], ["--observed-app", "<observed-app-id>"], ["--reason", "reviewed App-ID observation"], ["--flow-limit", req.flowLimit], ["--confidence-threshold", req.confidenceThreshold], ["--since", req.since], ["--until", req.until]]), "Append the selected observation to the draft App-ID regression corpus"),
        ]
        : cli(cliCommand("ngfwctl app-id observations", [["--limit", req.limit], ["--flow-limit", req.flowLimit], ["--confidence-threshold", req.confidenceThreshold], ["--query", req.query], ["--kind", kind], ["--engine-signal", req.engineSignal], ["--protocol", req.protocol], ["--port", req.port], ["--since", req.since], ["--until", req.until]]), "Exact CLI equivalent for the current App-ID observation view"),
      notes,
    };
  }
  const req = { limit: choice(queryValue(query, "limit"), ["100", "500", "1000"], "500") };
  setIf(req, "query", queryValue(query, "q"));
  setIf(req, "ip", queryValue(query, "ip"));
  setIf(req, "protocol", choice(queryValue(query, "protocol"), ["TCP", "UDP", "ICMP"], ""));
  setIf(req, "app", queryValue(query, "app"));
  setIf(req, "port", validIntText(queryValue(query, "port"), 1, 65535));
  setIf(req, "flowId", routeText(queryValue(query, "flowId"), 128));
  setIf(req, "since", localDateTimeToISOString(queryValue(query, "since")));
  setIf(req, "until", localDateTimeToISOString(queryValue(query, "until")));
  return {
    endpoint: get(withQuery("/v1/flows", req), "Exact filtered flow request for the current Traffic view"),
    cli: cli(cliCommand("ngfwctl flows", [["--limit", req.limit], ["--query", req.query], ["--ip", req.ip], ["--protocol", req.protocol], ["--app", req.app], ["--port", req.port], ["--flow-id", req.flowId], ["--since", req.since], ["--until", req.until]]), "Exact CLI equivalent for the current Traffic Flows view"),
    notes: uiOnlyNotes(query, ["sort", "queueId", "sessionKey"], "Traffic route state"),
  };
}

function exactThreatContext(query) {
  if (queryValue(query, "view") === "exceptions") {
    const selected = routeText(queryValue(query, "exception"), 128);
    if (selected) {
      const encoded = encodeURIComponent(selected);
      return {
        endpoints: [
          get("/v1/threat-exceptions", "List candidate and running Threat-ID exception lifecycle records"),
          patch(`/v1/threat-exceptions/${encoded}`, `Stage metadata update for selected threat exception ${selected}`, "{ \"exception\": { \"name\": \"fp-9000001-source\", \"description\": \"reviewed false positive\" }, \"reason\": \"ticket IR-1234\", \"confirmGlobal\": false }"),
          post(`/v1/threat-exceptions/${encoded}:set-state`, `Stage enable or disable state for selected threat exception ${selected}`, "{ \"disabled\": true, \"reason\": \"temporary disable pending review\" }"),
          post(`/v1/threat-exceptions/${encoded}:remove`, `Stage removal for selected threat exception ${selected}`, "{ \"reason\": \"exception no longer required\" }"),
          post("/v1/candidate/validate", "Validate candidate after exception lifecycle changes", "{}"),
          get("/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE", "Review running-to-candidate diff before commit"),
        ],
        cli: [
          cli("ngfwctl threat-exceptions list --source effective", "List effective Threat-ID exceptions"),
          cli(`ngfwctl threat-exceptions update ${shellArg(selected)} --reason "reviewed false positive" --owner secops --ticket-id IR-1234`, "Stage selected exception metadata update"),
          cli(`ngfwctl threat-exceptions disable ${shellArg(selected)} --reason "temporary disable pending review"`, "Stage selected exception disable"),
          cli(`ngfwctl threat-exceptions enable ${shellArg(selected)} --reason "reviewed exception still required"`, "Stage selected exception enable"),
          cli(`ngfwctl threat-exceptions remove ${shellArg(selected)} --reason "exception no longer required"`, "Stage selected exception removal"),
          cli("ngfwctl policy validate", "Validate staged exception lifecycle candidate"),
          cli("ngfwctl policy diff", "Review candidate diff before commit"),
        ],
        notes: [
          `Current Threats view: exception lifecycle detail ${selected}`,
          "Exception lifecycle actions stage candidate policy only; commit with an audit reason is still required before engine behavior changes.",
          "Workflow session packets remain browser-local and unsigned; production custody and retention are hardening work.",
        ],
      };
    }
    return {
      endpoint: get("/v1/threat-exceptions", "List candidate and running Threat-ID exception lifecycle records"),
      cli: cli("ngfwctl threat-exceptions list --source effective", "List effective Threat-ID exceptions"),
      notes: [
        "Current Threats view: exception lifecycle inventory",
        "Exception edits, enable, disable, and removal stage candidate policy only; commit is still required.",
      ],
    };
  }
  const req = { limit: choice(queryValue(query, "limit"), ["100", "500", "1000"], "500") };
  setIf(req, "query", queryValue(query, "q"));
  setIf(req, "ip", queryValue(query, "ip"));
  setIf(req, "protocol", choice(queryValue(query, "protocol"), ["TCP", "UDP", "ICMP"], ""));
  setIf(req, "action", choice(queryValue(query, "action"), ["blocked", "allowed"], ""));
  setIf(req, "severity", validIntText(queryValue(query, "sev"), 1, 4));
  setIf(req, "threatSeverity", choice(queryValue(query, "threatSeverity"), ["critical", "high", "medium", "low", "info"], ""));
  setIf(req, "signatureId", validIntText(queryValue(query, "signatureId"), 1, 2147483647));
  setIf(req, "port", validIntText(queryValue(query, "port"), 1, 65535));
  setIf(req, "flowId", routeText(queryValue(query, "flowId"), 128));
  setIf(req, "since", localDateTimeToISOString(queryValue(query, "since")));
  setIf(req, "until", localDateTimeToISOString(queryValue(query, "until")));
  return {
    endpoint: get(withQuery("/v1/alerts", req), "Exact filtered Threat-ID alert request for the current Threats view"),
    cli: cli(cliCommand("ngfwctl alerts", [["--limit", req.limit], ["--query", req.query], ["--ip", req.ip], ["--protocol", req.protocol], ["--action", req.action], ["--severity", req.severity], ["--threat-severity", req.threatSeverity], ["--signature-id", req.signatureId], ["--port", req.port], ["--flow-id", req.flowId], ["--since", req.since], ["--until", req.until]]), "Exact CLI equivalent for the current Threats view"),
    notes: uiOnlyNotes(query, ["alert"], "Threats route state"),
  };
}

function exactChangesContext(query) {
  const tab = choice(queryValue(query, "tab"), ["candidate", "versions", "audit"], "candidate");
  if (tab === "candidate") {
    return {
      endpoint: get("/v1/candidate/status", "Exact candidate status request for the current Changes review view"),
      cli: cli("ngfwctl policy status --json", "Exact CLI candidate dirty-state and impact equivalent for the current Changes Candidate view"),
      notes: ["Current Changes tab: candidate review", "Candidate review combines /v1/candidate/status, /v1/candidate/validate, /v1/system/status, and running-to-candidate diff before commit."],
    };
  }
  if (tab === "versions") {
    const version = validIntText(queryValue(query, "version"), 1, 2147483647);
    const drawer = version ? choice(queryValue(query, "drawer"), ["diff", "rollback"], "") : "";
    if (drawer === "diff") {
      return {
        endpoint: get(`/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_VERSION&toVersion=${version}`, `Exact running-to-version diff for Changes version v${version}`),
        cli: cli(`ngfwctl policy show --source version --version ${version} --json`, `Export version v${version} for headless diff or rollback review`),
        notes: [`Current Changes drawer: diff for version v${version}`, "The version diff drawer is route-backed and can be reopened from change tickets or audit handoffs."],
      };
    }
    if (drawer === "rollback") {
      return {
        endpoint: post("/v1/rollback", `Reviewed rollback request for Changes version v${version}`, `{ "version": "${version}", "comment": "restore known good", "ackRisk": true, "ackRuntime": true }`),
        cli: cli(`ngfwctl rollback ${version} --ack-risk -m "restore known good"`, `Apply reviewed rollback to version v${version}`),
        notes: [`Current Changes drawer: rollback review for version v${version}`, "Rollback validates the target policy and runtime posture before creating the new live version."],
      };
    }
    return {
      endpoint: get("/v1/versions?limit=100", "Exact version timeline request for the current Changes view"),
      cli: cli("ngfwctl versions --limit 100", "Exact CLI equivalent for the current Changes Versions view"),
      notes: ["Current Changes tab: versions"],
    };
  }
  const req = { limit: choice(queryValue(query, "limit"), ["100", "300", "500", "1000"], "300") };
  setIf(req, "actor", queryValue(query, "actor"));
  setIf(req, "action", queryValue(query, "action"));
  setIf(req, "version", validIntText(queryValue(query, "version"), 1, 2147483647));
  setIf(req, "query", queryValue(query, "query"));
  setIf(req, "since", localDateTimeToISOString(queryValue(query, "since")));
  setIf(req, "until", localDateTimeToISOString(queryValue(query, "until")));
  return {
    endpoint: get(withQuery("/v1/audit", req), "Exact filtered audit-log request for the current Changes view"),
    cli: cli(cliCommand("ngfwctl audit", [["--limit", req.limit], ["--actor", req.actor], ["--action", req.action], ["--version", req.version], ["--query", req.query], ["--since", req.since], ["--until", req.until], ["--hashes", true]]), "Exact CLI equivalent for the current Changes Audit view"),
    notes: ["Current Changes tab: audit"],
  };
}

function exactTroubleshootContext(query) {
  const explain = explainRequestFromQuery(query);
  const endpoints = [post("/v1/explain/flow", "Exact ExplainFlow request for the current Troubleshoot tuple", JSON.stringify(explain, null, 2))];
  const source = cliPolicySource(explain.policySource);
  const cliItems = [cli(cliCommand("ngfwctl explain", [
    ["--source", source],
    ["--version", source === "version" && explain.version !== "0" ? explain.version : ""],
    ["--from-zone", explain.fromZone],
    ["--to-zone", explain.toZone],
    ["--src", explain.srcIp],
    ["--sport", explain.srcPort ? String(explain.srcPort) : ""],
    ["--dst", explain.destIp],
    ["--dport", explain.destPort ? String(explain.destPort) : ""],
    ["--protocol", cliProtocol(explain.protocol)],
    ["--app-id", explain.appId],
    ["--runtime", explain.includeRuntime],
    ["--flow-id", explain.flowId],
  ]), "Exact CLI equivalent for the current Troubleshoot tuple")];
  const notes = uiOnlyNotes(query, ["run", "intent"], "Troubleshoot route state");
  if (queryValue(query, "intent") === "capture") {
    const capture = captureRequestFromTroubleshootQuery(query, explain);
    endpoints.push(
      post("/v1/system/packet-captures/plan", "Exact bounded packet-capture plan for the current Troubleshoot tuple", JSON.stringify(capture, null, 2)),
      post("/v1/system/packet-captures", "Start the same bounded capture after admin acknowledgement", JSON.stringify({ ...capture, ackCapture: true }, null, 2)),
    );
    cliItems.push(
      cli(captureCliCommand(capture, false), "Exact capture-plan CLI equivalent for the current Troubleshoot tuple"),
      cli(captureCliCommand(capture, true), "Exact guarded capture-start CLI equivalent for the current Troubleshoot tuple"),
    );
    notes.push("Current intent requests packet-capture follow-up after explanation; capture planning and guarded start are reproducible through /v1/system/packet-captures.");
  }
  return {
    endpoints,
    cli: cliItems,
    notes,
  };
}

function captureRequestFromTroubleshootQuery(query, explain) {
  const req = {
    interface: routeText(queryValue(query, "captureInterface") || queryValue(query, "interface") || queryValue(query, "iface"), 64) || "any",
    protocol: explain.protocol,
    srcIp: explain.srcIp,
    srcPort: explain.srcPort,
    destIp: explain.destIp,
    destPort: explain.destPort,
    durationSeconds: Number(validIntText(queryValue(query, "captureDuration") || queryValue(query, "durationSeconds") || queryValue(query, "duration"), 1, 3600) || 20),
    packetCount: Number(validIntText(queryValue(query, "capturePackets") || queryValue(query, "packetCount") || queryValue(query, "packets"), 1, 1000000) || 500),
    snaplenBytes: Number(validIntText(queryValue(query, "captureSnaplen") || queryValue(query, "snaplenBytes") || queryValue(query, "snaplen"), 96, 4096) || 256),
  };
  setIf(req, "flowId", explain.flowId);
  return req;
}

function captureCliCommand(req = {}, start = false) {
  return cliCommand("ngfwctl system capture", [
    ["--start", start],
    ["--ack-capture", start],
    ["--interface", req.interface],
    ["--protocol", cliProtocol(req.protocol)],
    ["--src", req.srcIp],
    ["--sport", req.srcPort ? String(req.srcPort) : ""],
    ["--dst", req.destIp],
    ["--dport", req.destPort ? String(req.destPort) : ""],
    ["--duration", req.durationSeconds ? String(req.durationSeconds) : ""],
    ["--packets", req.packetCount ? String(req.packetCount) : ""],
    ["--snaplen", req.snaplenBytes ? String(req.snaplenBytes) : ""],
    ["--flow-id", req.flowId],
  ]);
}

function explainRequestFromQuery(query) {
  return {
    policySource: explainPolicySource(queryValue(query, "source") || queryValue(query, "policySource"), queryValue(query, "version") || queryValue(query, "policyVersion")),
    version: queryValue(query, "version") || queryValue(query, "policyVersion") || "0",
    fromZone: queryValue(query, "fromZone"),
    toZone: queryValue(query, "toZone"),
    srcIp: queryValue(query, "src") || queryValue(query, "srcIp"),
    srcPort: Number(validIntText(queryValue(query, "sport") || queryValue(query, "srcPort"), 1, 65535) || 0),
    destIp: queryValue(query, "dst") || queryValue(query, "destIp"),
    destPort: Number(validIntText(queryValue(query, "dport") || queryValue(query, "destPort"), 1, 65535) || 0),
    protocol: explainProtocol(queryValue(query, "protocol")),
    appId: queryValue(query, "app") || queryValue(query, "appId"),
    includeRuntime: booleanRouteValue(queryValue(query, "runtime")),
    flowId: queryValue(query, "flowId"),
  };
}

function explainBody(policySource, opts = {}) {
  return JSON.stringify({
    policySource,
    version: "0",
    fromZone: "lan",
    toZone: "wan",
    srcIp: "10.0.1.20",
    srcPort: 51515,
    destIp: "10.0.2.20",
    destPort: 443,
    protocol: "PROTOCOL_TCP",
    appId: opts.appId || "",
    includeRuntime: Boolean(opts.includeRuntime),
    flowId: opts.flowId || "",
  }, null, 2);
}

function queryValue(query, key) {
  return String(query.get(key) || "").trim();
}

function setIf(target, key, value) {
  if (value !== undefined && value !== null && value !== "") target[key] = value;
}

function choice(value, allowed, fallback) {
  return allowed.includes(value) ? value : fallback;
}

function validIntText(value, min, max) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) return "";
  return String(n);
}

function integerRange(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) return fallback;
  return n;
}

function routeText(value, maxLength = 128) {
  const text = String(value || "").trim();
  if (!text || text.length > maxLength || /[\u0000-\u001f\u007f]/.test(text)) return "";
  return text;
}

function routeIp(value, fallback = "") {
  const text = String(value || "").trim();
  if (!text || text.length > 64 || !/^[0-9A-Fa-f:.]+$/.test(text)) return fallback;
  return text;
}

function routeCidr(value, fallback = "") {
  const text = String(value || "").trim();
  if (!text || text.length > 80 || !/^[0-9A-Fa-f:./]+$/.test(text)) return fallback;
  return text;
}

function routeProtocol(value, fallback = "PROTOCOL_UDP") {
  const text = String(value || "").trim().toUpperCase();
  if (text === "UDP" || text === "PROTOCOL_UDP") return "PROTOCOL_UDP";
  if (text === "TCP" || text === "PROTOCOL_TCP") return "PROTOCOL_TCP";
  if (text === "ICMP" || text === "PROTOCOL_ICMP") return "PROTOCOL_ICMP";
  if (text === "ANY" || text === "PROTOCOL_ANY") return "PROTOCOL_ANY";
  return fallback;
}

function routePort(value, fallback = "0") {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 65535) return String(fallback || "0");
  return String(n);
}

function explainPolicySource(value, version = "") {
  const v = String(value || "").trim();
  if (v === "POLICY_SOURCE_RUNNING" || v.toLowerCase() === "running") return "POLICY_SOURCE_RUNNING";
  if (v === "POLICY_SOURCE_CANDIDATE" || v.toLowerCase() === "candidate") return "POLICY_SOURCE_CANDIDATE";
  if (v === "POLICY_SOURCE_VERSION" || v.toLowerCase() === "version" || version) return "POLICY_SOURCE_VERSION";
  return "POLICY_SOURCE_RUNNING";
}

function cliPolicySource(value) {
  if (value === "POLICY_SOURCE_CANDIDATE") return "candidate";
  if (value === "POLICY_SOURCE_VERSION") return "version";
  return "running";
}

function explainProtocol(value) {
  const v = String(value || "").trim();
  if (v === "PROTOCOL_TCP" || v.toLowerCase() === "tcp") return "PROTOCOL_TCP";
  if (v === "PROTOCOL_UDP" || v.toLowerCase() === "udp") return "PROTOCOL_UDP";
  if (v === "PROTOCOL_ICMP" || v.toLowerCase() === "icmp") return "PROTOCOL_ICMP";
  if (v === "PROTOCOL_ANY" || v.toLowerCase() === "any" || v.toLowerCase() === "ip") return "PROTOCOL_ANY";
  return "PROTOCOL_TCP";
}

function cliProtocol(value) {
  if (value === "PROTOCOL_UDP") return "udp";
  if (value === "PROTOCOL_ICMP") return "icmp";
  if (value === "PROTOCOL_ANY") return "any";
  return "tcp";
}

function cliAppIDObservationKind(value) {
  if (value === "APP_ID_OBSERVATION_KIND_UNKNOWN") return "unknown";
  if (value === "APP_ID_OBSERVATION_KIND_LOW_CONFIDENCE") return "low-confidence";
  if (value === "APP_ID_OBSERVATION_KIND_CONFLICTING_EVIDENCE") return "conflicting-evidence";
  return "";
}

function booleanRouteValue(value) {
  const v = String(value || "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

function localDateTimeToISOString(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toISOString();
}

function withQuery(path, request) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(request || {})) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const query = params.toString();
  return path + (query ? "?" + query : "");
}

export function cliCommand(base, flags = []) {
  const parts = [base];
  for (const [flag, value] of flags) {
    if (value === undefined || value === null || value === "" || value === false) continue;
    parts.push(flag);
    if (value !== true) parts.push(shellArg(value));
  }
  return parts.join(" ");
}

function shellArg(value) {
  const text = String(value);
  if (/^[A-Za-z0-9_./:@%-]+$/.test(text)) return text;
  return `"${text.replace(/["\\$`]/g, "\\$&")}"`;
}

function uiOnlyNotes(query, keys, label) {
  const entries = keys
    .map((key) => [key, queryValue(query, key)])
    .filter(([, value]) => value)
    .filter(([key, value]) => routeStateAllowed(key, value))
    .map(([key, value]) => [key, safeRouteDisplayValue(value)]);
  if (!entries.length) return [];
  return [`${label} not sent to the REST endpoint: ${entries.map(([key, value]) => `${key}=${value}`).join(", ")}`];
}

export function automationContextText(context, location = globalThis.location) {
  const lines = [`# Phragma API/CLI context: ${context.title}`, context.summary, ""];
  if (context.routeState) {
    lines.push("Current view:", `- ${context.routeState.hash}`);
    if (context.routeState.queryEntries.length) {
      lines.push(`- route filters: ${context.routeState.queryEntries.map(([key, value]) => `${key} = ${value}`).join(", ")}`);
    } else {
      lines.push("- route filters: none");
    }
    lines.push("");
  }
  lines.push(
    "API contract:",
    `- GET ${API_CONTRACT.aliasPath} - ${API_CONTRACT.format}; ${API_CONTRACT.purpose}`,
    `  curl: ${apiContractCurl(location)}`,
    "",
  );
  lines.push(...workflowTextLines(context, location));
  lines.push("REST:");
  for (const endpoint of context.endpoints) {
    lines.push(`- ${endpoint.method} ${endpoint.path} - ${endpoint.purpose}`);
    if (endpoint.browserOnly) {
      lines.push("  browser session: uses the active WebUI cookie and CSRF token; no bearer-token curl is emitted.");
    } else {
      lines.push(`  curl: ${curlForEndpoint(endpoint, location)}`);
    }
  }
  lines.push("", "CLI:");
  for (const item of context.cli) {
    lines.push(`- ${item.command} - ${item.purpose}`);
  }
  if (context.notes?.length) {
    lines.push("", "Notes:", ...context.notes.map((note) => `- ${note}`));
  }
  return lines.join("\n") + "\n";
}

export function automationWorkflowSession(context, location = globalThis.location) {
  return {
    schemaVersion: WORKFLOW_SESSION_SCHEMA,
    capturedAt: new Date().toISOString(),
    source: "browser-local",
    title: sanitizeAutomationText(context.title),
    summary: sanitizeAutomationText(context.summary),
    apiOrigin: sanitizeAutomationText(apiOriginForCopy(location)),
    apiContract: {
      path: API_CONTRACT.path,
      aliasPath: API_CONTRACT.aliasPath,
      format: API_CONTRACT.format,
      purpose: API_CONTRACT.purpose,
    },
    routeState: context.routeState ? {
      hash: sanitizeAutomationText(context.routeState.hash),
      path: sanitizeAutomationText(context.routeState.path),
      queryEntries: (context.routeState.queryEntries || []).map(([key, value]) => [
        sanitizeAutomationText(key),
        sanitizeAutomationText(value),
      ]),
    } : null,
    endpoints: (context.endpoints || []).map((endpoint) => workflowEndpointPacket(endpoint, location)),
    cli: (context.cli || []).map(workflowCliPacket),
    workflow: (context.workflow || []).map((step, index) => ({
      step: index + 1,
      title: sanitizeAutomationText(step.title),
      purpose: sanitizeAutomationText(step.purpose),
      endpoints: (step.endpoints || []).map((endpoint) => workflowEndpointPacket(endpoint, location)),
      cli: (step.cli || []).map(workflowCliPacket),
    })),
    notes: (context.notes || []).map(sanitizeAutomationText),
    custody: {
      mode: "browser-local",
      serverStored: false,
      signed: false,
      hardeningRequired: "Server-side retention, signing, and custody policy are tracked for the hardening pass.",
    },
  };
}

export function emptyAutomationRecording(location = globalThis.location) {
  const now = new Date().toISOString();
  return {
    schemaVersion: AUTOMATION_RECORDER_SCHEMA,
    source: "browser-local",
    status: "recording",
    startedAt: now,
    updatedAt: now,
    apiOrigin: sanitizeAutomationText(apiOriginForCopy(location)),
    steps: [],
    custody: {
      mode: "browser-local",
      serverStored: false,
      signed: false,
      hardeningRequired: "Server-side retention, signing, identity binding, and custody policy are tracked for the hardening pass.",
    },
  };
}

export function appendAutomationRecording(recording, context, location = globalThis.location) {
  const base = normalizeAutomationRecording(recording, location) || emptyAutomationRecording(location);
  const session = automationWorkflowSession(context, location);
  const step = {
    step: (base.steps || []).length + 1,
    capturedAt: session.capturedAt,
    title: session.title,
    routeState: session.routeState,
    endpointCount: session.endpoints.length,
    cliCount: session.cli.length,
    workflowStepCount: session.workflow.length,
    session,
  };
  return {
    ...base,
    status: "recording",
    updatedAt: new Date().toISOString(),
    steps: [...(base.steps || []), step],
  };
}

export function automationRecordingJson(recording) {
  return JSON.stringify(recording, null, 2) + "\n";
}

export function automationRecordingRunbookText(recording, location = globalThis.location) {
  const packet = normalizeAutomationRecording(recording, location) || emptyAutomationRecording(location);
  const apiOrigin = sanitizeAutomationText(packet.apiOrigin || apiOriginForCopy(location));
  const lines = [
    "#!/usr/bin/env bash",
    "set -euo pipefail",
    "",
    "# Phragma browser-local automation runbook.",
    "# Generated from phragma.webui.automation-recorder.v1.",
    "# Unsigned and not server-retained; apply production custody policy before compliance use.",
    `PHRAGMA_API_ORIGIN="\${PHRAGMA_API_ORIGIN:-${apiOrigin}}"`,
    `: "\${PHRAGMA_TOKEN:?Set PHRAGMA_TOKEN to an API bearer token with the required privileges}"`,
    "",
    "echo \"Checking public API contract\"",
    "curl -sk \"${PHRAGMA_API_ORIGIN}/ui/api-spec.yaml\" >/dev/null",
    "",
  ];
  if (!packet.steps?.length) {
    lines.push("echo \"No recorded views were present in this browser-local recording.\"");
    return lines.join("\n") + "\n";
  }
  for (const step of packet.steps) {
    const session = step.session || {};
    lines.push(
      `# Step ${step.step}: ${shellCommentText(step.title || session.title || "Recorded route")}`,
      `# Route: ${shellCommentText(step.routeState?.hash || session.routeState?.hash || "unrecorded")}`,
    );
    const workflow = Array.isArray(session.workflow) ? session.workflow : [];
    for (const workflowStep of workflow) {
      lines.push(`echo ${shellArg(`Step ${step.step}.${workflowStep.step || ""} ${workflowStep.title || "Workflow action"}`)}`);
      for (const endpoint of workflowStep.endpoints || []) {
        lines.push(...runbookEndpointLines(endpoint));
      }
      for (const item of workflowStep.cli || []) {
        lines.push(...runbookCliLines(item));
      }
    }
    for (const endpoint of session.endpoints || []) {
      lines.push(...runbookEndpointLines(endpoint));
    }
    for (const item of session.cli || []) {
      lines.push(...runbookCliLines(item));
    }
    lines.push("");
  }
  lines.push("# End of browser-local runbook.");
  return lines.join("\n") + "\n";
}

function normalizeAutomationRecording(recording, location = globalThis.location) {
  if (!recording || recording.schemaVersion !== AUTOMATION_RECORDER_SCHEMA) return null;
  const steps = Array.isArray(recording.steps) ? recording.steps : [];
  return {
    ...recording,
    source: "browser-local",
    apiOrigin: sanitizeAutomationText(recording.apiOrigin || apiOriginForCopy(location)),
    steps: steps.map((step, index) => ({
      step: index + 1,
      capturedAt: sanitizeAutomationText(step.capturedAt || ""),
      title: sanitizeAutomationText(step.title || step.session?.title || ""),
      routeState: step.routeState || step.session?.routeState || null,
      endpointCount: Number(step.endpointCount || step.session?.endpoints?.length || 0),
      cliCount: Number(step.cliCount || step.session?.cli?.length || 0),
      workflowStepCount: Number(step.workflowStepCount || step.session?.workflow?.length || 0),
      session: step.session || {},
    })),
    custody: {
      mode: "browser-local",
      serverStored: false,
      signed: false,
      hardeningRequired: "Server-side retention, signing, identity binding, and custody policy are tracked for the hardening pass.",
    },
  };
}

function workflowEndpointPacket(endpoint, location) {
  const packet = {
    method: sanitizeAutomationText(endpoint.method),
    path: sanitizeAutomationText(endpoint.path),
    purpose: sanitizeAutomationText(endpoint.purpose),
    browserOnly: Boolean(endpoint.browserOnly),
  };
  if (endpoint.body !== undefined) packet.body = sanitizeAutomationText(endpoint.body);
  if (!endpoint.browserOnly) packet.curl = sanitizeAutomationText(curlForEndpoint(endpoint, location));
  return packet;
}

function workflowCliPacket(item) {
  return {
    command: sanitizeAutomationText(item.command),
    purpose: sanitizeAutomationText(item.purpose),
  };
}

function runbookEndpointLines(endpoint = {}) {
  const method = sanitizeAutomationText(endpoint.method || "GET");
  const path = sanitizeAutomationText(endpoint.path || "/");
  const purpose = sanitizeAutomationText(endpoint.purpose || "Recorded REST action");
  if (endpoint.browserOnly) {
    return [
      `# Browser-session action skipped: ${shellCommentText(method + " " + path + " - " + purpose)}`,
      "# Requires active WebUI cookie and CSRF token; no bearer-token curl is emitted.",
    ];
  }
  const flags = ["-sk", "-H \"Authorization: Bearer ${PHRAGMA_TOKEN}\""];
  if (endpoint.body !== undefined) flags.push("-H \"Content-Type: application/json\"", `-d ${shellArg(endpoint.body)}`);
  if (method !== "GET") flags.push("-X " + method);
  return [
    `# REST: ${shellCommentText(method + " " + path + " - " + purpose)}`,
    `curl ${flags.join(" ")} "\${PHRAGMA_API_ORIGIN}${path}"`,
  ];
}

function runbookCliLines(item = {}) {
  const command = sanitizeAutomationText(item.command || "");
  const purpose = sanitizeAutomationText(item.purpose || "Recorded CLI action");
  if (!command) return [];
  return [
    `# CLI: ${shellCommentText(purpose)}`,
    command,
  ];
}

function shellCommentText(value) {
  return sanitizeAutomationText(value).replace(/[\r\n]+/g, " ").replace(/#/g, "\\#");
}

function automationWorkflowSessionJson(context, location = globalThis.location) {
  return JSON.stringify(automationWorkflowSession(context, location), null, 2) + "\n";
}

function sanitizeAutomationText(value) {
  return String(value ?? "")
    .replace(/(Authorization:\s*Bearer\s+)(?!\$\{|\[redacted\])["']?[^"'\s]+["']?/gi, "$1[redacted]")
    .replace(/\bBearer\s+(?!\$\{|\[redacted\])[A-Za-z0-9._~+/-]{8,}/gi, "Bearer [redacted]")
    .replace(/\b(access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|client[_-]?secret|password)=([^&\s"',;}]+)/gi, "$1=[redacted]")
    .replace(/(https?:\/\/)([^/\s"']+):([^@\s"']+)@/gi, "$1[redacted]@")
    .replace(/\bfile:\S+/gi, "[redacted-path]")
    .replace(/(?:^|[\s"',:])((?:\/etc|\/tmp|\/var|\/Users|\/home|\/private)(?:\/[^\s"',;}]+)?)/g, (match, path) => match.replace(path, "[redacted-path]"));
}

function workflowTextLines(context, location) {
  if (!context.workflow?.length) return [];
  const lines = ["Workflow runbook:"];
  context.workflow.forEach((step, index) => {
    lines.push(`${index + 1}. ${step.title} - ${step.purpose}`);
    for (const endpoint of step.endpoints || []) {
      lines.push(`   REST: ${endpoint.method} ${endpoint.path} - ${endpoint.purpose}`);
      if (endpoint.browserOnly) {
        lines.push("   browser session: uses the active WebUI cookie and CSRF token; no bearer-token curl is emitted.");
      } else {
        lines.push(`   curl: ${curlForEndpoint(endpoint, location)}`);
      }
    }
    for (const item of step.cli || []) {
      lines.push(`   CLI: ${item.command} - ${item.purpose}`);
    }
  });
  lines.push("");
  return lines;
}

export function workflowRunbookText(context, location = globalThis.location) {
  return workflowTextLines(context, location).join("\n") + "\n";
}

export function apiOriginForCopy(location = globalThis.location) {
  const origin = location?.origin;
  return origin && origin !== "null" ? origin : DEFAULT_API_ORIGIN;
}

export function apiContractCurl(location) {
  return `curl -sk ${shellArg(apiOriginForCopy(location) + API_CONTRACT.aliasPath)}`;
}

export function curlForEndpoint(endpoint, location) {
  if (endpoint.browserOnly) return "";
  const flags = ["-sk", `-H "Authorization: Bearer ${COPY_TOKEN_EXPR}"`];
  if (endpoint.body !== undefined) flags.push("-H \"Content-Type: application/json\"", `-d '${endpoint.body}'`);
  if (endpoint.method !== "GET") flags.push("-X " + endpoint.method);
  return `curl ${flags.join(" ")} ${shellArg(apiOriginForCopy(location) + endpoint.path)}`;
}

export function openAutomationContext(path = "/") {
  const context = contextForPath(path);
  const sessionJson = () => automationWorkflowSessionJson(context);
  const recorderJson = () => automationRecordingJson(readAutomationRecording() || emptyAutomationRecording());
  const recorderRunbook = () => automationRecordingRunbookText(readAutomationRecording() || emptyAutomationRecording());
  const body = h("div", { class: "automation-context" },
    h("div", { class: "alert-box info" },
      h("strong", {}, context.title),
      h("div", { class: "note" }, context.summary)),
    routeStateBlock(context),
    apiContractBlock(),
    workflowRunbookBlock(context),
    workflowSessionBlock(context),
    automationRecorderBlock(context, path),
    h("h3", {}, "REST endpoints"),
    h("div", { class: "automation-list" }, context.endpoints.map((endpoint) => endpointRow(endpoint))),
    h("h3", {}, "CLI equivalents"),
    h("div", { class: "automation-list" }, context.cli.map((item) => cliRow(item))),
    context.notes?.length ? h("div", { class: "automation-notes" }, context.notes.map((note) => h("div", {}, note))) : null);
  openDrawer({
    title: "API / CLI context",
    subtitle: "Public automation surface for the current WebUI route.",
    width: "760px",
    body,
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close API and CLI context", "aria-label": "Close API and CLI context", dataset: { automationAction: "cancel" }, onclick: closeDrawer }, "Cancel"),
      context.workflow?.length ? h("button", { class: "btn ghost", type: "button", title: "Copy ordered workflow runbook", "aria-label": "Copy ordered API and CLI workflow runbook", dataset: { automationAction: "copy-runbook" }, onclick: () => copyText(workflowRunbookText(context), "Runbook copied", "Ordered workflow copied as plain text.") },
        h("span", { html: icon("copy", 15) }), "Copy runbook") : null,
      h("button", { class: "btn ghost", type: "button", title: "Copy workflow session JSON", "aria-label": "Copy redacted workflow session JSON", dataset: { automationAction: "copy-session-json" }, onclick: () => copyText(sessionJson(), "Session JSON copied", "Browser-local API/CLI workflow session copied as redacted JSON.") },
        h("span", { html: icon("copy", 15) }), "Copy session JSON"),
      h("button", { class: "btn ghost", type: "button", title: "Download workflow session JSON", "aria-label": "Download redacted workflow session JSON", dataset: { automationAction: "download-session-json" }, onclick: () => downloadText(workflowSessionFilename(), sessionJson(), "application/json") },
        h("span", { html: icon("download", 15) }), "Download JSON"),
      h("button", { class: "btn ghost", type: "button", title: "Copy automation recording JSON", "aria-label": "Copy redacted automation recording JSON", dataset: { automationAction: "copy-recording-json" }, onclick: () => copyText(recorderJson(), "Recording copied", "Browser-local multi-route automation recording copied as redacted JSON.") },
        h("span", { html: icon("copy", 15) }), "Copy recording"),
      h("button", { class: "btn ghost", type: "button", title: "Copy automation recording shell runbook", "aria-label": "Copy automation recording shell runbook", dataset: { automationAction: "copy-recording-runbook" }, onclick: () => copyText(recorderRunbook(), "Runbook copied", "Recorded multi-route API/CLI workflow copied as a shell runbook.") },
        h("span", { html: icon("copy", 15) }), "Copy shell runbook"),
      h("button", { class: "btn ghost", type: "button", title: "Copy API and CLI context", "aria-label": "Copy REST and CLI context", dataset: { automationAction: "copy-context" }, onclick: () => copyText(automationContextText(context), "Context copied", "REST and CLI context copied as plain text.") },
        h("span", { html: icon("copy", 15) }), "Copy context"),
    ].filter(Boolean),
  });
}

function automationRecorderBlock(context, path) {
  const recording = readAutomationRecording();
  const active = recording?.status === "recording";
  const steps = recording?.steps || [];
  const last = steps[steps.length - 1];
  return h("div", {},
    h("h3", {}, "Automation recorder"),
    h("div", { class: "automation-row", dataset: { automationRecorder: "panel" } },
      h("div", { class: "automation-meta" },
        h("span", { class: "pill " + (active ? "ok" : "neutral"), dataset: { automationRecorder: "status" } }, active ? "Recording" : "Stopped"),
        h("code", {}, AUTOMATION_RECORDER_SCHEMA)),
      h("div", { class: "note" }, "Browser-local multi-route recorder for repeatable API/CLI runbooks. It captures redacted route context only; it is not server-stored, signed, or an approval authority."),
      h("div", { class: "automation-session-grid" },
        h("div", {}, h("strong", { dataset: { automationRecorder: "step-count" } }, String(steps.length)), h("span", {}, " recorded views")),
        h("div", {}, h("strong", {}, String((context.endpoints || []).length)), h("span", {}, " current REST endpoints")),
        h("div", {}, h("strong", {}, String((context.cli || []).length)), h("span", {}, " current CLI commands"))),
      last ? h("div", { class: "automation-notes", dataset: { automationRecorder: "last" } },
        h("div", {}, `Last recorded: ${last.title || "route"} ${last.routeState?.hash || ""}`)) : null,
      h("div", { class: "toolbar compact automation-recorder-actions" },
        active
          ? h("button", { class: "btn sm ghost", type: "button", title: "Stop automation recorder", "aria-label": "Stop browser-local automation recorder", dataset: { automationRecorderAction: "stop" }, onclick: () => { stopAutomationRecording(); openAutomationContext(path); } },
            h("span", { html: icon("block", 14) }), "Stop")
          : h("button", { class: "btn sm ghost", type: "button", title: "Start automation recorder", "aria-label": "Start browser-local automation recorder", dataset: { automationRecorderAction: "start" }, onclick: () => { startAutomationRecording(); openAutomationContext(path); } },
            h("span", { html: icon("clock", 14) }), "Start"),
        h("button", { class: "btn sm primary", type: "button", title: "Record current API and CLI view", "aria-label": "Record current API and CLI view", dataset: { automationRecorderAction: "record-view" }, onclick: () => { recordAutomationContext(context); openAutomationContext(path); } },
          h("span", { html: icon("plus", 14) }), "Record this view"),
        h("button", { class: "btn sm ghost", type: "button", title: "Copy automation recording JSON", "aria-label": "Copy redacted automation recording JSON", disabled: !steps.length, dataset: { automationRecorderAction: "copy" }, onclick: () => copyText(automationRecordingJson(recording), "Recording copied", "Recorded API/CLI workflow copied as redacted JSON.") },
          h("span", { html: icon("copy", 14) }), "Copy"),
        h("button", { class: "btn sm ghost", type: "button", title: "Download automation recording JSON", "aria-label": "Download redacted automation recording JSON", disabled: !steps.length, dataset: { automationRecorderAction: "download" }, onclick: () => downloadText(automationRecordingFilename(), automationRecordingJson(recording), "application/json") },
          h("span", { html: icon("download", 14) }), "Download"),
        h("button", { class: "btn sm ghost", type: "button", title: "Copy automation recording shell runbook", "aria-label": "Copy automation recording shell runbook", disabled: !steps.length, dataset: { automationRecorderAction: "copy-runbook" }, onclick: () => copyText(automationRecordingRunbookText(recording), "Runbook copied", "Recorded multi-route API/CLI workflow copied as a shell runbook.") },
          h("span", { html: icon("copy", 14) }), "Copy shell"),
        h("button", { class: "btn sm ghost", type: "button", title: "Download automation recording shell runbook", "aria-label": "Download automation recording shell runbook", disabled: !steps.length, dataset: { automationRecorderAction: "download-runbook" }, onclick: () => downloadText(automationRecordingRunbookFilename(), automationRecordingRunbookText(recording), "text/x-shellscript") },
          h("span", { html: icon("download", 14) }), "Download shell"),
        h("button", { class: "btn sm ghost", type: "button", title: "Validate automation recording before replay", "aria-label": "Validate automation recording before replay", disabled: !steps.length, dataset: { automationRecorderAction: "validate-replay" }, onclick: () => validateAutomationRecordingReplay(recording) },
          h("span", { html: icon("check", 14) }), "Validate replay"),
        h("button", { class: "btn sm ghost", type: "button", title: "Clear automation recording", "aria-label": "Clear browser-local automation recording", disabled: !steps.length && !recording, dataset: { automationRecorderAction: "clear" }, onclick: () => { clearAutomationRecording(); openAutomationContext(path); } },
          "Clear"))));
}

function readAutomationRecording() {
  try {
    return normalizeAutomationRecording(JSON.parse(localStorage.getItem(AUTOMATION_RECORDER_KEY) || "null"));
  } catch {
    return null;
  }
}

function writeAutomationRecording(recording) {
  localStorage.setItem(AUTOMATION_RECORDER_KEY, automationRecordingJson(normalizeAutomationRecording(recording) || recording));
}

function startAutomationRecording() {
  writeAutomationRecording(emptyAutomationRecording());
  toast("Recorder started", "Record route contexts from the API / CLI drawer as you work.", "ok");
}

function stopAutomationRecording() {
  const recording = readAutomationRecording();
  if (!recording) return;
  writeAutomationRecording({ ...recording, status: "stopped", updatedAt: new Date().toISOString() });
  toast("Recorder stopped", `${recording.steps?.length || 0} view${recording.steps?.length === 1 ? "" : "s"} retained in browser storage.`, "ok");
}

function clearAutomationRecording() {
  localStorage.removeItem(AUTOMATION_RECORDER_KEY);
  toast("Recorder cleared", "Browser-local automation recording was removed.", "ok");
}

function recordAutomationContext(context) {
  const recording = appendAutomationRecording(readAutomationRecording(), context);
  writeAutomationRecording(recording);
  toast("View recorded", `${recording.steps.length} API/CLI view${recording.steps.length === 1 ? "" : "s"} in this browser-local recording.`, "ok");
}

export function automationReplayValidationRequest(recording, candidateRevision = "", opts = {}) {
  const packet = normalizeAutomationRecording(recording) || emptyAutomationRecording();
  const body = {
    schemaVersion: "phragma.webui.automation-replay-validation-request.v1",
    recording: packet,
    executionMode: opts.executionMode || "validate",
    requireAcknowledgements: true,
    requireCandidateRevision: true,
  };
  if (opts.acknowledgements) body.acknowledgements = { ...opts.acknowledgements };
  if (candidateRevision) body.candidateRevision = String(candidateRevision);
  return body;
}

export function automationReplayDryRunRequest(recording, candidateRevision = "") {
  return automationReplayValidationRequest(recording, candidateRevision, { executionMode: "dry-run" });
}

export function automationReplayApplyAuthorityRequest(recording, candidateRevision = "", acknowledgements = {}) {
  return automationReplayValidationRequest(recording, candidateRevision, {
    executionMode: "apply-authority",
    acknowledgements: {
      ackReplayAuthority: true,
      ackReplayNoLiveApply: true,
      ...acknowledgements,
    },
  });
}

export function automationReplayExecuteRequest(recording, candidateRevision = "", acknowledgements = {}) {
  return automationReplayValidationRequest(recording, candidateRevision, {
    executionMode: "execute",
    acknowledgements: {
      ackReplayAuthority: true,
      ackReplayNoLiveApply: true,
      ...acknowledgements,
    },
  });
}

async function validateAutomationRecordingReplay(recording) {
  try {
    const report = await api.validateAutomationReplay(automationReplayDryRunRequest(recording));
    const summary = report.summary || {};
    const plan = report.executionPlan || {};
    const unsafe = Number(summary.unsafeMutationCount || 0);
    const missing = Number(summary.missingAcknowledgementCount || 0) + Number(summary.missingRevisionCount || 0) + Number((plan.missingAcks || []).length);
    const blocked = Number(plan.blockedSteps || 0);
    if (summary.blocked || unsafe || missing || blocked) {
      toast("Replay dry-run blocked", `${blocked || unsafe} blocked step${(blocked || unsafe) === 1 ? "" : "s"}; ${missing} missing guardrail${missing === 1 ? "" : "s"}.`, "warn");
    } else {
      toast("Replay dry-run passed", `${summary.executableStepCount || 0} recorded step${summary.executableStepCount === 1 ? "" : "s"} planned without execution.`, "ok");
    }
    return report;
  } catch (err) {
    toast("Replay validation failed", err.message || "Server-side replay validation did not complete.", "bad");
    return null;
  }
}

function workflowSessionBlock(context) {
  const endpointCount = (context.endpoints || []).length;
  const cliCount = (context.cli || []).length;
  const workflowCount = (context.workflow || []).length;
  return h("div", {},
    h("h3", {}, "Workflow session"),
    h("div", { class: "automation-row" },
      h("div", { class: "automation-meta" },
        h("span", { class: "pill info" }, "JSON"),
        h("code", {}, WORKFLOW_SESSION_SCHEMA)),
      h("div", { class: "note" }, "Browser-local redacted handoff packet for this API/CLI route context. It is not server-stored, signed, or retained."),
      h("div", { class: "automation-session-grid" },
        h("div", {}, h("strong", {}, String(endpointCount)), h("span", {}, " REST endpoints")),
        h("div", {}, h("strong", {}, String(cliCount)), h("span", {}, " CLI commands")),
        h("div", {}, h("strong", {}, String(workflowCount)), h("span", {}, " workflow steps"))),
      h("div", { class: "automation-notes" },
        h("div", {}, "Redacts bearer tokens, secret query parameters, URL credentials, and local appliance paths before copy or download."))));
}

function workflowRunbookBlock(context) {
  if (!context.workflow?.length) return null;
  return h("div", {},
    h("h3", {}, "Workflow runbook"),
    h("div", { class: "automation-list" }, context.workflow.map((step, index) => workflowStepRow(step, index))));
}

function workflowStepRow(step, index) {
  return h("div", { class: "automation-row" },
    h("div", { class: "automation-meta" },
      h("span", { class: "pill info" }, `Step ${index + 1}`),
      h("code", {}, step.title)),
    h("div", { class: "note" }, step.purpose),
    step.endpoints?.length ? h("div", { class: "automation-notes" }, step.endpoints.map((endpoint) => (
      h("div", {}, `${endpoint.method} ${endpoint.path} - ${endpoint.purpose}`)
    ))) : null,
    step.cli?.length ? h("div", { class: "automation-notes" }, step.cli.map((item) => (
      h("div", {}, `${item.command} - ${item.purpose}`)
    ))) : null);
}

function apiContractBlock() {
  const command = apiContractCurl();
  return h("div", {},
    h("h3", {}, "API contract"),
    h("div", { class: "automation-row" },
      h("div", { class: "automation-meta" },
        h("span", { class: "pill neutral" }, "YAML"),
        h("code", {}, API_CONTRACT.path)),
      h("div", { class: "note" }, `${API_CONTRACT.format}. ${API_CONTRACT.purpose}`),
      h("pre", { class: "command-box" }, command),
      h("div", { class: "toolbar compact" },
        h("button", { class: "btn sm ghost", type: "button", title: "Copy API contract curl command", "aria-label": "Copy API contract curl command", dataset: { automationAction: "copy-api-contract-curl" }, onclick: () => copyText(command, "curl copied", API_CONTRACT.aliasPath) },
          h("span", { html: icon("copy", 14) }), "Copy curl"),
        h("a", { class: "btn sm ghost", href: API_CONTRACT.path, target: "_blank", rel: "noreferrer", title: "Open bundled OpenAPI specification", "aria-label": "Open bundled OpenAPI specification", dataset: { automationAction: "open-api-contract" } },
          h("span", { html: icon("download", 14) }), "Open spec"))));
}

function routeStateBlock(context) {
  if (!context.routeState) return null;
  const entries = context.routeState.queryEntries || [];
  return h("div", { class: "automation-row" },
    h("div", { class: "automation-meta" },
      h("span", { class: "pill neutral" }, "Current view"),
      h("code", {}, context.routeState.hash)),
    entries.length
      ? h("div", { class: "automation-notes" }, entries.map(([key, value]) => h("div", {}, `${key} = ${value}`)))
      : h("div", { class: "note" }, "No route filters are active."));
}

function endpointRow(endpoint) {
  const command = endpoint.browserOnly ? "" : curlForEndpoint(endpoint);
  return h("div", { class: "automation-row" },
    h("div", { class: "automation-meta" },
      h("span", { class: "pill info" }, endpoint.method),
      h("code", {}, endpoint.path)),
    h("div", { class: "note" }, endpoint.purpose),
    endpoint.body !== undefined ? h("pre", { class: "command-box payload-box" }, endpoint.body) : null,
    endpoint.browserOnly
      ? h("div", { class: "automation-notes" }, h("div", {}, "Browser-session action: uses the active WebUI cookie and CSRF token. Use the Settings sign-out control to end the browser session."))
      : h("pre", { class: "command-box" }, command),
    endpoint.browserOnly ? null : h("button", { class: "btn sm ghost", type: "button", title: `Copy curl for ${endpoint.method} ${endpoint.path}`, "aria-label": `Copy curl command for ${endpoint.method} ${endpoint.path}`, dataset: { automationAction: "copy-endpoint-curl", automationEndpoint: endpoint.path }, onclick: () => copyText(command, "curl copied", endpoint.path) },
      h("span", { html: icon("copy", 14) }), "Copy curl"));
}

function cliRow(item) {
  return h("div", { class: "automation-row" },
    h("div", { class: "automation-meta" },
      h("span", { class: "pill neutral" }, "CLI"),
      h("code", {}, item.command)),
    h("div", { class: "note" }, item.purpose),
    h("button", { class: "btn sm ghost", type: "button", title: "Copy CLI command", "aria-label": `Copy CLI command: ${item.command}`, dataset: { automationAction: "copy-cli-command" }, onclick: () => copyText(item.command, "Command copied", item.purpose) },
      h("span", { html: icon("copy", 14) }), "Copy"));
}

async function copyText(text, title, body) {
  try {
    await navigator.clipboard.writeText(text);
    toast(title, body, "ok");
  } catch {
    toast("Copy failed", "Select the visible command and copy it manually.", "warn");
  }
}

function downloadText(filename, text, type) {
  const blob = new Blob([text], { type: type || "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 500);
  toast("Session JSON downloaded", filename, "ok");
}

function workflowSessionFilename() {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  return `phragma-workflow-session-${stamp}.json`;
}

function automationRecordingFilename() {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  return `phragma-automation-recording-${stamp}.json`;
}

function automationRecordingRunbookFilename() {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  return `phragma-automation-runbook-${stamp}.sh`;
}
