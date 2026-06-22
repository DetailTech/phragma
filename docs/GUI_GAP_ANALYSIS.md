# Phragma GUI Gap Analysis

Status: v0.1 research baseline plus current implementation/open-gap overlay.

Date: 2026-06-17.

Audience: UI maintainers, API designers, security engineers, and future product owners.

Related documents:

- [GUI Research](GUI_RESEARCH.md)
- [GUI Feature Matrix](GUI_FEATURE_MATRIX.md)
- [Hard Requirements](HARD_REQUIREMENTS.md)
- [Build Plan](build-plan.md)

## Executive Read

The GUI opportunity is to beat incumbents on trustworthy operation, not on surface count. Existing firewalls are strong at different things: Palo Alto on App-ID and rule semantics, Fortinet on appliance breadth, Sophos on approachable table actions, OPNsense and pfSense on open diagnostics, WatchGuard on explaining packet filters versus proxies, and Meraki on simplicity. None of the evaluated products appear to make end-to-end explainability, policy-visible bypass, degraded-engine behavior, candidate diff, commit, rollback, and engine evidence feel like one coherent workflow.

Phragma should use that gap as its core identity: the firewall that shows its work.

The sections below preserve the original research framing and citations, then
record current implementation coverage under each gap where applicable. As of
the latest broad desktop smoke pass, the WebUI is no longer a research-only
baseline: the current 20-route canonical set in `make webui-enterprise-smoke`,
including `/proxy` and `/compliance`, passed remotely across the desktop
enterprise viewport. The configured Makefile path list includes `/dashboard` as
an alias for `/`, so the path list has one more entry than the canonical route
count. Tablet/mobile sweeps remain diagnostic unless the release contract is
deliberately changed. Treat the remote result as continuation evidence for this
dirty worktree, not durable release evidence. Release evidence must still be
regenerated and recorded after the source-control state is accepted.
In the table below, `Yes` in Broad smoke coverage means desktop remote
continuation coverage only; durable release evidence is still pending
`release-evidence-webui-enterprise-smoke` on an accepted source snapshot.

## Current Implementation And Open Gaps

| Gap/domain | Current implementation state | Broad smoke coverage | Remaining functional gap | Hardening-only gap |
|---|---|---:|---|---|
| Trustworthy change workflow | Candidate bar, candidate status, validation, typed diff, commit/rollback/import/export review, route-backed snapshot restore validation/preview, revision-bound server approval records, Changes audit, and version history are implemented | Yes: `/changes`, `/rules`, `/setup`, `/settings` | None identified for the functional approval, commit-gating, and snapshot-restore review path | Production CAB policy, signed/server-retained audit and compliance reports, restore anti-replay/signing/encryption, HA approval replication, external ticket integration, and release evidence custody |
| Flow explanation and troubleshooting | Troubleshoot renders an explanation timeline and running-vs-candidate compare with rule, NAT, route, App-ID, inspection, warnings, packet-capture planning, and event-time policy-stamp freshness labels for EVE-derived flow/alert evidence | Yes: `/troubleshoot`, `/traffic`, `/rules`, `/nat` | None identified for the bounded flow/alert event-time policy-stamp display path | Production custody, long-history stamp retention, and signed copied/exported explanation evidence |
| App-ID evidence and unknown-app workflow | Traffic exposes App-ID observations, confidence/evidence, custom App-ID staging, draft regression-sample staging, read-only App-ID lab replay comparison, cluster review with production-corpus and confidence readiness rows, representative port-hint staging gates, reviewed drop-rule staging, and an explicit non-port-hint/L7-only review boundary | Yes: `/traffic`, `/objects`, `/intel` | None identified for the bounded App-ID/L7 readiness and representative port-hint enforcement workflow | True production L7 App-ID enforcement authority, signed corpus custody, PCAP retention/legal hold, dataset provenance, and tamper-evident report custody |
| Threat-ID and false-positive control | Threats and Inspection cover IDS/IPS posture, exception lifecycle, Threat-ID package gates, profile rollout, fail-open/fail-closed visibility, and bounded degraded-engine dataplane evidence across nftables, Suricata, Vector, proxy/WAF, flowtable, and policy-impact posture | Yes: `/threats`, `/inspection`, `/objects`, `/readiness` | None identified for the bounded degraded-engine operator-evidence workflow | Signed field evidence, packet proof, remote attestation, production certification, and richer PCAP regression comparison |
| Rulebase comprehension at scale | Rules includes ordered editing, cleanup queues, rulebase map, grouping/density controls, bulk review, staged-change review, overlap review drawers, structured server overlap peer/dimension/result/cap metadata rendered as operator dimensions, and a bounded large-rulebase posture banner with durable-ID posture, visible/hidden/selected counts, route-target freshness, validation freshness, and overlap cap/page metadata | Yes: `/rules` | None identified for the bounded large-rulebase posture and pagination-identity workflow | Backend pagination, large-rulebase virtualization, cross-page selection authority, retained overlap custody, signed evidence packets, and truncation custody |
| NAT, routing, and policy coupling | NAT supports candidate-only SNAT/DNAT workflows, granular simple-rule API wrappers, by-ID update/delete selectors, publish assist, path preview, and policy/NAT/route handoff links; Net/VPN covers route/tunnel editing, route-table/VRF/FRR/XFRM/WireGuard/strongSwan proof handoff rows, timeout-bounded active-proof planning, redacted passive proof export, explicit remote-attestation boundaries, passive route identity, VRF/interface evidence, FRR route corroboration, masquerade egress observation, and bounded running-vs-candidate static route simulation | Yes: `/nat`, `/netvpn`, `/troubleshoot` | None identified for the bounded static-route simulation and passive proof workflow | Signed path evidence, active probes/capture, dynamic FRR/kernel sampling, remote attestation, SDK cutoff policy for by-ID NAT aliases, and production custody for passive proof exports |
| Proxy/WAF plan authoring | Proxy/WAF has a dedicated workspace for virtual services, listeners, routes, backends, WAF policies, candidate-safe staging, Readiness posture, server plan proof, runtime-readiness review, missing-artifact blocker visibility, bounded/redacted packet previews, active-case Investigation handoff, planned-not-executed daemon/listener/cutover/rollback proof artifacts, and candidate-safe traffic-policy impact analysis | Yes: `/proxy`, `/readiness` in the current 20-route broad continuation sweep | None identified for the bounded Proxy/WAF traffic-policy coupling workflow | TLS key custody, backend mTLS runtime proof, WAF supply-chain custody, request-body privacy custody, active listener/cutover execution, packet inspection execution, HA listener traffic proof, and signed packet/export custody |
| Logs as a workbench | Traffic, Threats, Logs, audit pivots, Net/VPN, Proxy/WAF, Fleet, Readiness, Performance, Compliance, and Investigation support shareable filters, drawers, exports, pins, explain/capture handoffs, candidate-safe remediation planning, server-retained Investigation cases, active-case hydration, append-to-server-case fallback, retained-case synthesis across correlation keys, owner routes, packet proof, server-retention posture, and retained server-record multi-flow synthesis, plus event-time policy-stamp freshness labels for EVE-backed flow/alert evidence | Yes: `/traffic`, `/threats`, `/logs`, `/netvpn`, `/proxy`, `/fleet`, `/readiness`, `/performance`, `/compliance`, `/investigation` | None identified for the bounded retained-case synthesis workflow | Signed exports, retention/custody, long-history stamp custody, production log-source permission evidence, immutable evidence identity, legal hold, RBAC-scoped export custody, external ticket authority |
| Content update transparency | Intel exposes feed posture, package quality gates, source preview, install/rollback, compare, corpus browsing, package-local artifact review, production-evidence inventory states, and active-case Investigation handoff | Yes: `/intel` | None identified for the bounded production-evidence inventory/status workflow | Release-gate custody, signed package/evidence custody, retention, and real production evidence certification |
| First-run onboarding | Guided setup includes scenario presets, checklist, candidate preview, exact `ngfwctl policy baseline` context, and scenario-specific topology proof rows for supported deployment modes | Yes: `/setup` | None identified for the bounded topology-proof checklist workflow | Field-tested supported-topology proof, production install evidence, and release custody |
| Local trust, auth, and audit | Settings covers local users, roles, OIDC/SAML rollout packets, parsed OIDC/SAML field-evidence artifact inventory, not-certified handoff text that lists `status=passed` as a required release-artifact sentinel, session posture, functional step-up controls, advisory RBAC previews, audit reports, and access guardrails | Yes: `/settings`, `/changes`, `/readiness` | None identified for the bounded OIDC/SAML field-run evidence workflow; `status=passed` is release-artifact sentinel guidance, not external certification | External OIDC/SAML provider certification, production IdP/MFA reauth, SAML certificate rollover, secret custody, time-source, audit backpressure, signed provider evidence, signed audit export |
| GUI/API/CLI parity | Route-aware API/CLI drawer, exact REST/CLI examples, ordered runbooks, browser-local workflow-session recorder, server-side replay validation, dry-run planning, bounded apply-authority planning, and audited execute-mode candidate replacement exist; destructive/live/unknown/non-candidate mutations remain blocked | Yes: route-level smoke exercises the context surfaces across multiple domains | None identified for the bounded replay execution workflow | Identity binding, payload signing, retention/legal hold, least-privilege replay scope, approval binding, and custody policy |
| Fleet, HA, and readiness | Readiness and Fleet expose HA/readiness posture, local-appliance template preview, positive runtime evidence orchestration preview, bounded/scrubbed packet export, diff/drift workbench context, system evidence packets, support bundles, active-case handoffs, action queues, bounded multi-node apply-plan with peer inventory and per-node eligibility, and local candidate template apply with retained per-node result custody | Yes: `/readiness`, `/fleet` | None identified for the bounded local template apply/result-custody workflow | Signed fleet/HA evidence, peer RPC/fanout, peer attestation, HA fencing, VIP movement, traffic failover, stale-evidence trend retention, and production custody for scrubbed runtime packets |
| Compliance reports | Compliance exposes retained unsigned operational reports over audit/version/system-log state with create/list/inspect/copy/export API and CLI parity plus active-case Investigation handoff | Yes: `/compliance`, `/changes` | None identified for the unsigned operational report workflow | Signed custody, legal retention, production profile governance, export custody, HA/backup retention, and external evidence verification |

## Best-Of-Breed Inputs

| Area | Reference to borrow | Evidence | Phragma target |
|---|---|---|---|
| App-ID policy semantics | Palo Alto App-ID and security policy docs | [Palo Alto App-ID](https://docs.paloaltonetworks.com/ngfw/administration/app-id), [Palo Alto Security Policy](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/security-policy) | First-party app model with evidence and confidence |
| Rulebase safety | Palo Alto rule usage/audit and Sophos rule-table actions | [Palo Alto Security Policy](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/security-policy), [Sophos Firewall Rules](https://docs.sophos.com/nsg/sophos-firewall/21.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/RulesAndPolicies/FirewallRules/index.html) | Candidate-backed rule editor with semantic diff |
| Open diagnostics | pfSense and OPNsense | [pfSense Firewall](https://docs.netgate.com/pfsense/en/latest/firewall/index.html), [OPNsense Rules](https://docs.opnsense.org/manual/firewall.html) | Raw-enough packet path, logs, state, capture, and inspectability |
| Inspection-path clarity | WatchGuard policy/proxy model | [WatchGuard About Policies](https://www.watchguard.com/help/docs/help-center/en-US/Content/en-US/Fireware/policies/policies_about_c.html) | Flow path that says L3/L4, IDS/IPS, App-ID, proxy/WAF, decryption, bypass |
| Broad appliance operations | Fortinet FortiGate | [Fortinet Getting Started](https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/954635/getting-started), [Fortinet Firewall Policy](https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/656084/firewall-policy) | Integrated policy, health, logs, updates, routing, VPN, NAT |
| Simplicity | Meraki as cited reference; UniFi as low-confidence contrast only | [Meraki MX Firewall Settings](https://documentation.meraki.com/SASE_and_SD-WAN/MX/Design_and_Configure/Configuration_Guides/Firewall_and_Traffic_Shaping/MX_Firewall_Settings) | Guided defaults without reducing expert depth |
| Identity/posture UX | Cloudflare One and Tailscale as contrast references | [Cloudflare One Traffic Policies](https://developers.cloudflare.com/cloudflare-one/traffic-policies/), [Tailscale ACLs](https://tailscale.com/kb/1018/acls) | Future identity/device posture layer over firewall policy |

## Gap 1: Trustworthy Change Workflow

Gap:

Existing products support commits, installs, publishes, or direct applies, but the operator experience is often split across edit screens, logs, config history, and rollback tools. Phragma already requires candidate configuration, validation, diff, commit, rollback, and audit. The GUI must make that the spine of the product.

Current API coverage and follow-on notes:

- Candidate status now exposes candidate presence, dirty state, running-version
  baseline, section changes, and first-party impact through
  `GET /v1/candidate/status`.
- Candidate validation now returns compatibility `errors[]`, structured
  validation/render/engine/impact findings, first-party impact, and a render
  artifact plan through `POST /v1/candidate/validate`; Changes and automation
  contexts fetch live validation for review. Server-retained last-validation
  snapshots remain an optimization/custody hardening item, not a bounded
  functional gap.
- Commit requires an audit reason and returns commit ID, running config version,
  and rollback metadata.
- Rollback exposes snapshot metadata and validates before activation.

| Solution option | Description |
|---|---|
| Conservative v1 | Add a persistent candidate bar with Validate, Diff, Commit, and Rollback actions. Use a modal for commit reason and show audit ID after commit. |
| Open-source-native | Make every config page a candidate workspace. Each change shows generated API object changes, semantic warnings, and links to local audit records. |
| Ambitious best-in-class | Add a change-review cockpit with blast-radius simulation, affected rules/logs/objects, expected engine renders, benchmark-risk notes, and one-click rollback rehearsal. |

## Gap 2: End-To-End Flow Explanation

Gap:

Vendors expose logs, rules, counters, and packet captures, but the complete answer to "why did this flow do that?" is usually assembled manually. Phragma hard requirements make this a non-negotiable GUI centerpiece.

Future API implications:

- Explain API must return rule, NAT, route, app, threat, inspection, bypass, decryption, engine health, fail behavior, config version, and evidence. Current flow explanation returns exact `policyVersion`.
- Logs must carry stable flow IDs and config version. Current flow/session/threat list responses expose query-time `runningPolicyVersion`; EVE-backed flow and alert events preserve `flowId`; and individual events expose `policyVersion` only when the telemetry pipeline stamped the event.

| Solution option | Description |
|---|---|
| Conservative v1 | Add an Explain button from logs and synthetic flow tests that opens a drawer with matched rule, verdict, NAT, route, and inspection state. |
| Open-source-native | Add an explanation timeline showing each decision point, evidence source, engine output, confidence, and linked raw events. |
| Ambitious best-in-class | Add a "prove it" mode that replays a synthetic version of the flow against candidate and running policy, showing side-by-side expected verdict differences. |

Current implementation coverage:

- Troubleshoot now renders a first-class explanation timeline from the existing
  ExplainFlow response, ordering tuple intake, DNAT, policy rule/default
  decision, App-ID evidence, inspection posture, route decision, SNAT, runtime
  correlation, and warnings into a scan-friendly decision chain.
- The existing running-vs-candidate compare remains the side-by-side "prove it"
  surface for synthetic flow replay without mutating running or candidate
  policy. Packet-capture handoff, runtime EVE/conntrack correlation, and
  engine-health context remain linked from the same Troubleshoot result.
- Remaining follow-on work is production custody, long-history retention, and
  signed provenance for copied/exported event-time policy-stamp evidence.

## Gap 3: App-ID Evidence And Unknown-App Workflow

Gap:

Palo Alto sets the bar for application-aware policy, but Phragma cannot rely on nDPI as the product layer. The GUI must show application identity as evidence and confidence, not a magic label.

Current API coverage and follow-on notes:

- App-ID responses expose signal sources, confidence, protocol metadata,
  evidence fields, and custom app references.
- Unknown and low-confidence review is queryable through the App-ID observation
  queue. Remaining work is production L7 authority and signed corpus custody.

| Solution option | Description |
|---|---|
| Conservative v1 | Show app name, confidence, and evidence summary in logs and rule test results. Add a basic custom app form. |
| Open-source-native | Build an unknown-app review queue where users can inspect evidence, create custom apps, add regression samples, and track app package version. |
| Ambitious best-in-class | Add an App-ID lab that clusters unknown traffic, suggests custom app definitions, generates regression tests, and previews policy impact before commit. |

Current implementation coverage:

- Traffic includes an App-ID observation queue for unknown, low-confidence, and
  conflicting application evidence with confidence, signal source, protocol,
  tuple, package context, candidate action guidance, matching-flow pivots,
  capture handoff, and candidate-safe App-ID object/drop-rule staging.
- Reviewed queue items can append draft App-ID regression corpus samples
  through API, CLI, and WebUI. The selected queue API/CLI drawer includes
  `POST /v1/app-id/observations/{queueId}:stage-regression-sample` and
  `ngfwctl app-id corpus add`, and browser smoke proves SHA validation plus
  successful draft sample staging from the observation drawer.
- App-ID lab replay comparison can build a read-only evidence report from a
  selected observation, submitted observation, or submitted corpus sample.
- The latest functional-polish slice adds App-ID cluster review readiness:
  operators can review related observations, move from evidence to a proposed
  custom definition, and enter bounded drop-rule review from the same queue
  without treating the browser workflow as production clustering authority.
  Direct drop staging remains limited to representative port-hint paths;
  signal-only App-ID clusters stay in review-only Suricata/IDS Prevent
  fail-closed guidance.
- True L7 App-ID enforcement, production clustering authority, signed corpus
  custody, PCAP retention/legal hold, dataset provenance, and tamper-evident
  report custody remain follow-on/hardening work.

## Gap 4: Threat-ID And False-Positive Control

Gap:

Threat prevention GUIs often expose signatures and events, but false-positive control, staged rollout, severity/confidence, and explanation are fragmented. Phragma owns Threat-ID metadata and QA, while Suricata remains only the v1 matching engine.

Current API coverage and follow-on notes:

- Threat events carry normalized metadata, severity, confidence, rule source,
  profile, exception context, and PCAP/test reference where available.
- Content package status exposes provenance, staged rollout state, rollback, and
  quality-gate posture. Remaining rollout proof and custody are hardening.

| Solution option | Description |
|---|---|
| Conservative v1 | Add IDS/IPS profile editor, threat logs, severity/confidence fields, and suppress/exception actions with audit reason. |
| Open-source-native | Add staged mode per profile: observe, alert, block. Show false-positive exceptions, package provenance, and regression status in one screen. |
| Ambitious best-in-class | Add a threat tuning workbench that replays PCAPs, compares package versions, estimates block impact, and recommends staged rollout or rollback. |

Current implementation coverage:

- `#/inspection` is a first-class workspace for IDS/IPS profile state, runtime
  inspection posture, Threat-ID package gates, candidate-only rollout actions,
  and false-positive exception posture.
- Objects security-profile impact now functions as a route-backed layered
  inspection rollout workbench. `#/objects?tab=securityProfiles&drawer=impact`
  summarizes affected candidate rules, blocking inspection intent, IDS/IPS
  fail-closed posture, copy/export/pin handoff packets, Open rule pivots, and
  exact API/CLI context for reference review, candidate validation, and
  running-to-candidate diff.
- Profile-required allow traffic now has live fail-closed field evidence on the
  remote Linux validation host: the M2 integration proof commits a blocking DNS
  security profile on an allow rule, verifies fail-closed NFQUEUE and
  profile-inspection nftables markers, preserves allowed-flow reachability, and
  observes Suricata alert evidence on the inspected flow.
- Threats still owns event investigation and exception lifecycle drawers, while
  Inspection gives operators a direct profile and rollout control plane.
- Broader Threat-ID rollout field evidence, stricter inline input validation,
  richer PCAP regression comparison, and TLS/DNS/URL/file engine breadth remain
  hardening/follow-on work.

## Gap 5: Policy-Visible Bypass And Degraded Engines

Gap:

Many products show health and logs, but bypass or degraded inspection can be difficult to see at the policy and flow level. Phragma says silent bypass is a defect.

Future API implications:

- Verdict events need explicit inspection state: fully inspected, partially inspected, bypassed, decrypted, failed-open, failed-closed, or error.
- Engine health state must be queryable at decision time.

| Solution option | Description |
|---|---|
| Conservative v1 | Add global degraded-engine banner, engine health page, and log filters for bypassed, partially inspected, failed-open, and failed-closed flows. |
| Open-source-native | Add policy-level inspection coverage badges that show which rules may bypass under engine degradation and what fail behavior applies. |
| Ambitious best-in-class | Add an inspection coverage map that models live traffic against engine health and highlights blind spots, bypass reasons, and remediation actions. |

Current implementation coverage:

- Rules now shows per-rule inspection coverage states, including IPS
  fail-open and pre-filter-drop posture, and the rule cleanup queue surfaces
  bypass-risk allow paths with a direct Inspection workspace pivot.
- Inspection now has an aggregate candidate coverage map that buckets rules by
  inspection state, counts active allow paths and review items, exposes runtime
  bypass posture, and links operators back to Rules or profile rollout actions.
- Browser smoke proves an IPS prevent fail-open candidate exposes the risky
  allow path, filters to that rule, displays the bypass explanation, pivots to
  Inspection, and does not mutate the running policy.
- Broader degraded-engine dataplane evidence, live Suricata/NFQUEUE fail-open
  behavior, multi-engine fail-closed breadth, and signed field evidence remain
  hardening work.

## Gap 6: Rulebase Comprehension At Scale

Gap:

Large firewall rulebases become difficult because order, objects, NAT, routes, apps, profiles, implicit defaults, and auto-created rules interact. Existing products each expose part of this, but rarely as one coherent reasoning surface.

Future API implications:

- Validator returns structured findings for missing logs, unused objects,
  partial rule overlaps, shadowed rules, broad allows, and risky action
  changes. Deeper overlap taxonomy and remediation suggestions remain
  follow-on API work.
- Rule tags are first-class `rules[].tags` metadata with server-side
  validation; the Rules view supports tag search, tag filtering, display, and
  side-panel editing.
- The Rules workspace now includes URL-backed rule focus, hash-routed drawers,
  density and grouping controls, bulk-selection review, stale-selection guards
  before candidate mutations, and durable forwarding-rule identity. Deeper
  backend pagination, virtualization, and cross-page identity authority remain
  follow-on hardening work.
- Rule hits join to config version through `/v1/system/status.dataplane.runningPolicyVersion`; last-seen metadata remains follow-on telemetry work.

| Solution option | Description |
|---|---|
| Conservative v1 | Add searchable rule table with tags, descriptions, enabled state, hit count, last hit, log enabled, and insert/clone actions. |
| Open-source-native | Add semantic warnings for shadowed rules, broad allows, missing logs, object duplicates, risky fail-open, and unused objects. |
| Ambitious best-in-class | Add a rulebase graph that groups rules by intent, object dependency, hit evidence, risk, and candidate impact, with explainable optimization suggestions. |

Current implementation coverage:

- Rules now includes a candidate rulebase map that groups the ordered rulebase
  into allow, pre-filter drop, App-ID scoped, profiled inspection, review, and
  disabled bands, with examples and filter actions that pivot back into the
  existing ordered table.
- The map reuses the existing cleanup, inspection coverage, hit-counter, and
  staged-change models to show rule counts, active allow paths, App-ID/profile
  scope, changed rules, named dependency totals, zero-hit evidence, and review
  hotspots without introducing a second mutation path.
- Browser smoke proves the map root and expected bands on `/rules` across
  desktop, tablet, and mobile. Focused JS coverage proves changed, App-ID,
  profiled, disabled, overlap, bypass-risk, missing-log, and zero-hit model
  behavior.
- Server-overlap review now has a route-backed overlap-impact drawer that
  resolves candidate peer rules, excludes full-cover/shadow cases, displays
  shared match dimensions, representative overlap tuple, risk flags for order,
  logging, profile, and App-ID differences, and lets operators proceed to
  reviewed logging/tag staging.
- The server-overlap drawer now includes an in-drawer API/CLI action, and the
  route-backed `#/rules?q=server-overlap&drawer=server-overlap-review`
  automation context lists the candidate policy read, candidate validation,
  running-to-candidate diff, and matching `ngfwctl policy show`, `validate`,
  and `diff` commands for first-match review.
- Structured overlap peer/dimension data from server validation and bounded
  large-rulebase posture are implemented. Backend pagination/virtualization,
  cross-page selection authority, retained overlap custody, signed evidence,
  and truncation custody remain follow-on hardening work.

## Gap 7: NAT, Routing, And Policy Coupling

Gap:

NAT and routing side effects often explain "firewall" failures. Sophos and OPNsense both show that NAT/rule interaction needs explicit UX. Phragma explanation must include NAT and route decisions.

Future API implications:

- Explain API must include NAT and route decisions.
- Candidate diff should show policy, NAT, and route impacts together.

| Solution option | Description |
|---|---|
| Conservative v1 | Add linked NAT references in rules and show NAT/route decision in flow explanation. |
| Open-source-native | Add a DNAT/SNAT assistant that generates candidate policy plus NAT changes and previews return path and logging behavior. |
| Ambitious best-in-class | Add a path simulator that compares candidate and running NAT/routing/policy decisions across interfaces, zones, tunnels, and failure states. |

Current implementation coverage:

- NAT includes candidate-only SNAT lifecycle and DNAT publish workflows. The
  DNAT assistant can queue missing address/service objects, stage destination
  NAT, and stage the generated allow rule through the normal candidate policy
  path.
- NAT path preview compares running and candidate `ExplainFlow` output for a
  representative tuple and shows verdict, matched rule, DNAT, SNAT, route, and
  egress deltas. The preview has copy-link, Troubleshoot compare, pin-to-case,
  and JSON handoff export actions with stale-response protection.
- NAT rows now include explicit non-mutating `Preview path` actions for
  existing SNAT and DNAT entries, so operators can rerun path review after
  reload or while auditing a candidate.
- The preview now renders a path-coupling review that points operators to the
  affected policy, NAT, route, Troubleshoot compare, and candidate-diff
  surfaces based on the decisions actually evaluated for the tuple.
- Route-backed NAT previews now expose exact API/CLI context for the current
  tuple, with running and candidate `POST /v1/explain/flow` bodies plus
  matching `ngfwctl explain` commands instead of representative sample values.
- Net/VPN now adds a functional active-proof plan for routes and tunnels with
  timeout-bounded probes, explicit timeout/failure handling, required operator
  acknowledgements, route-table/VRF/FRR/XFRM/WireGuard/strongSwan evidence
  checklist rows, a remote-attestation boundary, and a redacted passive proof
  export for route, tunnel, and observed-evidence handoff. Exported packets
  state that they contain planned commands and redacted passive summaries only,
  not raw command output, captures, local paths, tokens, key paths, PSKs,
  private keys, or remote-host artifacts. This is an operator-ready proof plan
  and evidence packet, not signed production path custody.
- Passive FRR route corroboration, VRF/interface identity, masquerade egress
  observation, bounded static-route simulation, and granular NAT API/CLI
  workflows are implemented. Dynamic FRR/kernel sampling, active probes,
  packet-capture binding, remote attestation, SDK cutoff policy for by-ID NAT
  aliases, production dataplane path certification, and signed custody for
  passive proof exports remain hardening/follow-on work.

Proxy/WAF functional-polish coverage:

- Proxy/WAF now has a runtime-readiness review that ties planned virtual
  services, listeners, routes, backends, WAF policy posture, and readiness
  evidence into one operator handoff surface.
- Missing artifacts are called out as blockers before a rollout is treated as
  ready, and bounded/redacted packet previews support investigation handoff
  without exposing request bodies or secrets in the browser packet.
- Active proxy rollout/runtime health proof, richer traffic-policy integration,
  TLS key custody, backend mTLS runtime proof, WAF supply-chain custody,
  request-body privacy custody, HA listener traffic proof, and signed
  packet/export custody remain hardening/follow-on work.

## Gap 8: Logs As A Workbench, Not A Table

Gap:

Logs are often powerful but disconnected from action. Phragma needs logs to be the gateway to explanation, rule tuning, packet capture, exceptions, object cleanup, and export.

Future API implications:

- Logs need stable filters and links to flow ID, rule ID, app ID, threat ID, config version, and engine source.
- Export settings should be first-class local config.
- Current Traffic, Threats, audit pivots, and Investigation surfaces support
  shareable filters, explain/capture handoffs, evidence packets, rule or object
  pivots, and a candidate-safe remediation planner derived from pinned flow,
  alert, capture, App-ID, NAT/route, settings telemetry/OIDC, Readiness system,
  HA, VPN, object-reference, audit, and content-package evidence. Deeper
  multi-flow fix synthesis and production rule-hit/last-seen telemetry custody
  remain follow-on work.
- `#/logs` now adds a first-class System Logs workbench backed by
  `/v1/system/logs` and `ngfwctl system logs`. It provides bounded server-side
  log reads from the configured log root, redacted system/engine/dataplane/audit
  rows, route-backed filters, saved filters, JSON/CSV evidence export, per-row
  drawers, Investigation pinning, and pivots to Readiness, Changes audit,
  Traffic, and Threats. Log drawers now derive flow, tuple, App-ID, and
  signature context from structured log text, expose exact Traffic/Threats/
  Troubleshoot pivots, and preserve that context in copied/exported/pinned
  Investigation handoff packets so pinned log evidence is capture-ready.
  Retention/custody policy, signed exports, journald integration, and
  production log-source permission evidence remain hardening.

| Solution option | Description |
|---|---|
| Conservative v1 | Add traffic/threat/audit/system log tabs with saved filters, CSV/JSON export, and explain links. |
| Open-source-native | Add log investigation drawers with linked rule/object/NAT/route/app/threat details and suggested next actions. |
| Ambitious best-in-class | Add an investigation workspace that pins multiple flows, compares causes, opens targeted packet captures, and creates candidate policy fixes from evidence. |

## Gap 9: Content Update Transparency

Gap:

Commercial products have mature content update workflows, but Phragma must be transparent, offline-capable, signed, rollbackable, and fully open. This is a GUI differentiator.

Future API implications:

- Content update API must expose package version, signature, hash, provenance, staged rollout state, test result, and rollback metadata.

| Solution option | Description |
|---|---|
| Conservative v1 | Show App-ID and Threat-ID package versions, signature status, install date, and rollback action. |
| Open-source-native | Add provenance, source license, staged rollout, regression status, and offline verification status per package. |
| Ambitious best-in-class | Add a content release dashboard with canary policy scopes, false-positive telemetry, PCAP regression diffs, and emergency rollback workflow. |

Current v2-mixed implementation:

- Intel exposes App-ID, Threat-ID, and intel-feed content posture from the
  package API with signed-manifest, hash, provenance, regression, rollout,
  rollback, and production-evidence checks.
- The `#/intel?surface=<kind>&drawer=quality` drawer presents a read-only
  Content Quality Workbench for package gates and required production evidence
  refs. It now also exposes an operator evidence inventory, highlights attached
  regression corpus artifacts, opens bounded package-local JSON artifacts
  through the Intel API, and summarizes App-ID corpus samples while keeping raw
  JSON available for review. Candidate/content mutation stays on the existing
  install/rollback APIs and exports only redacted lifecycle handoff packets.
- Corpus browsing is now server-typed instead of browser-only JSON parsing:
  `GET /v1/intel/content/packages/{kind}/corpus` returns verified,
  filterable package-local sample rows, and the quality drawer uses that API
  for persisted regression corpus review.
- The install drawer can run a non-mutating package-source preview against a
  directory under the configured content import root before promotion. Preview
  returns the same sanitized verification posture as installed content status
  without writing lifecycle audit entries.
- Package-content comparison is now API-backed: `POST
  /v1/intel/content/packages/{kind}/compare` verifies a server-local import
  candidate and returns installed-vs-preview posture plus regression corpus
  diffs without promotion or lifecycle audit writes. Reviewed corpus ingestion
  from observations is available from API, CLI, and the Traffic App-ID drawer;
  selected queue API/CLI context now includes `:stage-regression-sample` and
  `ngfwctl app-id corpus add`. Custody/retention, signing policy, and real
  signed production evidence remain follow-on hardening work.

## Gap 10: First-Run Onboarding Without Hiding Expert Controls

Gap:

Simple products onboard well but lack expert depth. Enterprise products expose depth but make first-run setup heavy. Phragma needs a safe middle path.

Future API implications:

- Setup API should expose management interface, zones, default policy, update source, local admin/SSO, and sample candidate creation.

Current implementation coverage:

- Guided Setup stages a two-zone baseline through the normal candidate path and now includes a persistent first-run checklist for interface boundaries, TLS/auth/OIDC admin access, host-input exposure, content/update package posture, outbound/NAT posture, inspection mode, host tuning evidence, and candidate review. Checklist actions link to Settings Access, Intel, Readiness, Changes, and API/CLI context instead of committing directly.
- Scenario-driven onboarding is now functionally covered for cloud edge,
  east-west segmentation, VPN edge, IDS tap, and lab mode. Presets fill the
  same reviewable candidate controls, clearly label outbound/NAT/inspection
  posture, and keep VPN secrets and final commit decisions outside the preset
  action.
- The setup candidate preview now includes a deployment-archetype review panel
  with "Use when", "Staged defaults", "Operator review", and "Not staged"
  guidance for each scenario. The API/CLI checklist action carries the current
  setup route state into the context drawer and renders an exact
  `ngfwctl policy baseline` command from the visible scenario, zones,
  interfaces, CIDR, WebUI port, NAT/outbound/host-input/offload/MSS flags, and
  IDS settings.

| Solution option | Description |
|---|---|
| Conservative v1 | Add a first-run wizard for management password, interfaces, zones, default deny posture, update source, and first candidate commit. |
| Open-source-native | Add an onboarding checklist that remains visible after setup and links each step to docs, CLI, API object, and rollback. |
| Ambitious best-in-class | Scenario-driven onboarding now exists for cloud edge, east-west segmentation, VPN edge, IDS tap, and lab mode with archetype-specific guidance and exact setup API/CLI context; remaining follow-on work is field-tested proof of the defaults on supported deployment topologies. |

## Gap 11: Local Trust, Auth, And Audit

Gap:

Enterprise vendors support RBAC/SSO, but local single-node appliances often underinvest in audit clarity. Phragma requires local SAML/OIDC and durable audit logs.

Current API coverage and remaining implications:

- Local users, roles, active OIDC sessions, break-glass posture, identity, session revoke, audit events, OIDC preflight evidence, node-local OIDC rollout planning, and runtime OIDC provider validate/save/disable now have public API/WebUI/CLI coverage.
- Settings now exposes SAML as an explicit access posture item and can prepare a redacted SAML rollout packet with IdP metadata, SP entity, ACS URL, role mapping, break-glass checks, server validation, copy/export/pin actions, API/CLI parity for provider show/validate/set/disable, and browser SAML login/status/ACS runtime through the same opaque session and audited RBAC path as OIDC.
- Settings now includes OIDC/SAML field-evidence handoff packets that can carry
  `status=passed` for the bounded functional evidence gathered by the UI. That
  status is intentionally scoped to field-evidence handoff and does not claim
  real-provider certification, IdP/MFA assurance, certificate lifecycle
  readiness, or secret-custody hardening.
- Browser-local audit export and operational report workflows are now
  functionally covered: filtered logs, per-entry handoffs, and
  `phragma.audit.report.v1` reports include redacted replay metadata, entry
  hashes, integrity context, the correct `GET /v1/audit/verify` verify replay
  route, and pin-to-case wiring. Remaining work in this area is production
  audit custody: signed/server-stored export, retention enforcement,
  report-generation RBAC policy, and field evidence for time-source and
  backpressure behavior. Backend hardening for privileged credential changes
  and real-provider SSO evidence remains separate. The Settings UI now includes
  advisory RBAC role-impact preview for local-user creation and role changes
  plus OIDC and SAML rollout drawers, but those previews intentionally do not
  replace backend authorization, audit, MFA, real-provider certification,
  secret custody, or step-up controls.

| Solution option | Description |
|---|---|
| Conservative v1 | Add local users, roles, OIDC/SAML setup, test login, session list, and audit filters by actor. |
| Open-source-native | Add policy-aware RBAC preview so admins can test what a role can view/change before assigning it. |
| Ambitious best-in-class | Add governance mode with approval gates for risky policy classes, cryptographic audit export, and admin activity replay. |

## Gap 12: GUI/API/CLI Parity

Gap:

Firewalls often drift between GUI, CLI, and API behavior. Phragma explicitly requires the UI and CLI to be clients of the same API.

Future API implications:

- Every GUI mutation should map to a documented public API request.
- Validation errors should be shared across GUI and CLI.

| Solution option | Description |
|---|---|
| Conservative v1 | Add advanced drawers showing object IDs, config version, and API endpoint for each page. |
| Open-source-native | Add "copy as API request" and "copy as CLI command" actions for candidate changes and log queries. |
| Ambitious best-in-class | Add an automation recorder that turns a GUI session into a reproducible API/CLI script with validation and rollback steps. |

Current implementation coverage:

- The global API/CLI context drawer exposes route-aware REST endpoints,
  `ngfwctl` equivalents, the generated API contract, and a copyable ordered
  workflow runbook for policy workspaces.
- The runbook covers the standard candidate lifecycle: inspect baseline, stage
  candidate, check candidate status, validate, review diff, commit with audit
  reason, and rollback/discard review.
- Threat exception lifecycle detail routes now expose selected-record API/CLI
  parity from the drawer, including list, update, enable/disable, remove,
  validate, and diff commands for the current exception route.
- Changes candidate review now includes revision-bound server approval records
  for the current candidate plus a browser-local governance review packet. It
  packages validation, runtime preflight, impact, diff, reviewer-role cues,
  risk factors, copy/export/pin actions, and route-backed reload behavior for
  CAB handoff, and commit gating consumes the matching approval record.
- The API/CLI drawer now includes a browser-local multi-route automation
  recorder. Operators can start/stop/clear recording, append the current
  route-aware workflow-session packet, and copy/download a redacted aggregate
  `phragma.webui.automation-recorder.v1` JSON packet containing route context,
  REST endpoints, CLI commands, and ordered workflow steps. The same recorder
  can now copy/download a shell runbook generated from those multi-route steps,
  including API-contract checks, bearer-token placeholders, REST curls, CLI
  commands, browser-session-only comments, validation, commit, and rollback
  actions where the recorded route exposes them.
- ExplainFlow API examples in Rules, NAT, Routing/VPN, Traffic,
  Troubleshoot, and Investigation API/CLI context now use the flat public
  `ExplainFlowRequest` schema (`policySource`, tuple fields, runtime flags)
  instead of legacy nested flow/source examples; focused JS tests parse the
  bodies and browser smoke proves the copied Troubleshoot context from the
  Traffic capture workflow.
- Fleet & templates is now a first-class local-appliance workspace at `#/fleet`.
  It aggregates the connected appliance, HA posture, candidate drift, content
  package posture, release gates, template rows, operator queue, and evidence
  sources from existing public APIs. Its API/CLI context lists the matching
  status, HA, identity, policy source, candidate status, diff, version,
  content, release acceptance, and support-bundle handoff commands.
- Fleet now previews positive runtime evidence orchestration for the connected
  appliance, can prepare a bounded scrubbed packet for handoff, and supports
  bounded local template apply plus retained per-node result review through the
  current Fleet API/CLI/WebUI paths. Real distributed multi-node orchestration,
  peer RPC/fanout template application, signed retention, and production
  custody remain deferred.
- Changes audit report builder now includes browser-local compliance profiles
  for operational, change-control, privileged-access, content-lifecycle, and
  incident-evidence review. The exported `phragma.audit.report.v1` packet keeps
  normalized/redacted filters, replay commands, audit hashes, integrity status,
  unsigned custody boundaries, and a profile-specific control summary derived
  from the visible audit window.
- Remaining work is the production hardening version of that recorder and
  governance path: persistent server-side retention, signatures, operator
  identity binding, timestamps, custody controls, CAB policy, quorum,
  expiry/revocation, HA replication, and external ticket integration.

## Priority Recommendations

Original build-first baseline, now functionally covered:

- Candidate/change bar.
- Rule table with validation, hit counts, and log/explain links.
- Unified logs with flow explanation.
- Engine health and degraded-mode visibility.
- App-ID evidence and threat-profile basics.

Functional closure now includes the previously listed DNAT/SNAT assistant,
unknown App-ID queue, threat tuning and exception workflow, and packet-capture
handoff from explain/log context. Remaining next work is production hardening:
content package custody/retention, signed field evidence, durable release
evidence recording, and the security/custody pass tracked in
`docs/HARDENING_BACKLOG.md`.

Defer:

- Real distributed multi-node fleet orchestration and peer-fanout template
  application.
- Signed compliance-report custody with retention, RBAC split, scheduling,
  legal hold, external evidence verification, and governance policy.
- Multi-node HA cockpit.
- Server-side governance approval enforcement.
- Server-retained/signed automation recorder with replay validation, identity
  binding, retention, and custody policy.

## Acceptance Checklist

- Every vendor named by the user is covered in [GUI Feature Matrix](GUI_FEATURE_MATRIX.md).
- Added vendors have stated reasons for inclusion.
- Best-of-breed recommendations are cited.
- Phragma hard requirements are mapped to GUI surfaces.
- Each gap above has exactly three options: conservative v1, open-source-native, and ambitious best-in-class.
- Original research API impacts are preserved where useful; current
  implementation coverage and remaining hardening boundaries are documented in
  each gap section.
- No runtime API, control-plane, CLI, dataplane, or WebUI implementation files are changed by this research pass.
