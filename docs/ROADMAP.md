# Phragma Roadmap

Status: Accepted

This file tracks eventual open-source scope. It does not expand v1.

## v1 Boundary

v1 remains the single-node cloud/virtual NGFW defined in [Project Definition](PROJECT_DEFINITION.md) and [ADR-0005](adr/ADR-0005-core-v1-scope.md).

## v2-mixed Implementation Status And Follow-On Queue

This queue records completed bounded functional slices and the remaining
production-hardening follow-ons for the DetailTech-based `v2-mixed` branch. It
does not expand v1 scope; each item must keep nftables as the current Linux
renderer/fallback while moving Phragma toward the product definition.

1. **Runtime-correlated explanation workbench.** Unify Traffic, Threats, and
   Troubleshoot around flow ID, policy version, rule, NAT, route, App-ID,
   Threat-ID, inspection, bypass, engine health, and packet-capture evidence.
   Initial live conntrack evidence, first-class EVE `flow_id` pivots across
   Traffic/Threats/API/CLI/automation handoff, and correlated EVE flow/alert
   rows in Explain runtime evidence are implemented. Troubleshoot now samples
   current inspection/engine health beside live runtime evidence and exports
   that context in Explain handoffs. Packet-capture jobs now carry SHA-256
   artifact references through API, CLI, WebUI, and handoff exports; recent
   capture history and artifact download/retrieval are now surfaced in
   Troubleshoot, and the Investigation case tray now refreshes matching capture
   evidence for pinned flow, alert, explain, capture, and App-ID sample packets.
   Non-destructive retain/release metadata is now admin-controlled from the
   capture workbench and persisted in pcap sidecars; lifecycle pruning, custody,
   and tamper-proof retention remain hardening work.
2. **First-party App-ID observations queue.** Initial API and WebUI support is
   implemented through `/v1/app-id/observations` and Traffic -> App-ID queue:
   recent flow telemetry is grouped into unknown, low-confidence, and
   conflicting evidence review items with candidate-safe promotion into custom
   `applications[]`; signed package readiness is exposed through the Intel API,
   and Traffic gates App-ID drop recommendations on production-ready App-ID
   package evidence. App-ID observation drawers now export and pin
   regression-sample handoff packets that bind the representative sample flow,
   packet-capture requirement, suggested taxonomy, active package version/hash,
   readiness blockers, and inspection posture for corpus review. Intel now
   exposes typed package-local regression corpus browsing and installed-vs-
   candidate corpus diffs through API, CLI, and the quality/install preview UI.
   Reviewed corpus ingestion is now implemented: API, CLI, and the Traffic
   drawer can append a reviewed queue item plus bounded PCAP SHA-256 and
   package context into a draft App-ID regression JSONL artifact for the package
   builder. A bounded live dataplane proof now exists for signal-only HTTP
   App-ID deny with IPS Prevent fail-closed: the M2 privileged netns test proves
   baseline HTTP pass, live NFQUEUE without bypass, generated SID/app-layer
   metadata, EVE blocked alert output, and blocked HTTP flow after the App-ID
   rule is committed. Next add production package custody evidence, signed
   corpus lifecycle, broader App-ID signal and allow/block breadth, and
   durable SID/governance evidence without making Suricata or nDPI the product
   model.
3. **Threat-ID tuning workbench.** Expose normalized Threat-ID metadata,
   severity/confidence, package provenance, false-positive exceptions, staged
   profile posture, and PCAP/regression references. Initial Threat-ID package
   posture is surfaced in the Threats workbench from the shared Intel package
   readiness model; Threats now shows candidate-vs-running IDS profile posture,
   package-level PCAP/false-positive regression refs, and exports those refs in
   alert handoffs. Threats also provides candidate-safe rollout actions for
   Detect, Prevent fail-open, Prevent fail-closed, and Disable, with prevention
   gated on Threat-ID package posture. Threat-ID exception staging, editing,
   listing, and lifecycle actions now carry owner, ticket/change ID, review
   date, expiry, PCAP SHA-256, and regression-reference metadata through the
   API, policy validator, compiler IR, Suricata threshold comments, and Threats
   workbench. Content quality gates can now inspect
   bounded package-local JSON evidence artifacts referenced by signed package
   readiness metadata, browse typed regression corpus rows, and compare
   candidate package corpus diffs before promotion. Next persist production
   package-version custody through release/content evidence without adding a
   separate product model around Suricata.
4. **Auth/admin and audit integrity.** Add public admin APIs for local users,
   OIDC/SAML posture, roles, sessions, and hash-chain/exportable audit without
   exposing secrets or file-layout internals. Content package install/rollback
   RBAC now matches the GUI governance contract as admin-only privileged
   content promotion, and access administration now exposes non-secret active
   OIDC session inventory plus audited admin session revocation in Settings.
   Local users can now be created, role-changed, token-rotated, and disabled
   through audited admin APIs and Settings actions with one-time token return
   and last-admin guardrails. Settings now also includes an access lifecycle
   review for OIDC/SAML provider posture, browser SSO sessions, break-glass
   recovery, API/CLI parity, and access audit handoff. Remaining work is
   real-provider field evidence, production custody, MFA/step-up policy, and
   other hardening controls tracked in the hardening backlog.
5. **eBPF milestone evidence.** Add XDP/tc capability/status, attach probes,
   renderer scaffolding, and OL9/OCI Linux-root validation while preserving
   nftables as the runnable compatibility path. Initial System API/CLI/WebUI
   status now exposes host prerequisites, attach prerequisites, supported hooks,
   optional runtime attachment probes, and indexed field-evidence artifacts.
   A deterministic plan-only eBPF renderer scaffold exists for release evidence,
   and `ebpf-ol9-field-evidence` is an external release gate for OL9/OCI
   Linux-root host prerequisite, XDP/tc attach/detach, status API, renderer
   scaffold, and cleanup proof. The validator enforces kernel BTF, bpffs,
   cgroup v2, and link-inventory evidence in addition to tool, status, attach,
   renderer, cleanup, and redaction artifacts. Readiness now packages the
   current eBPF host, attach-drill, renderer-scaffold, indexed-artifact, and
   release-gate posture into a copy/export/pin handoff packet while explicitly
   preserving `nftables/conntrack` as the active dataplane. Deterministic
   smoke coverage now proves the runtime attachment-probe path across
   `/v1/system/status` and `/readiness` with seeded XDP/tc attachment and
   artifact evidence, while focused CLI tests cover
   `ngfwctl system ebpf-readiness --json`. Live OL9 validation now also proves
   the privileged collector path against a disposable dummy interface: first-
   party XDP/tc probe source generation, `clang` object builds, XDP generic
   attach/detach, tc clsact attach/detach, `bpftool prog show`, cleanup, and
   validated field-evidence bundle output while keeping `nftables/conntrack`
   as the active dataplane. Production dataplane hardening for verifier policy,
   signed object provenance, map lifecycle, attach rollback, traffic safety
   checks, and cutover controls remains deferred.
6. **Commit metadata, LKG, and active/passive HA readiness.** Commit and
   rollback now persist activation state, rendered artifact hashes, rollback
   lineage, and a store-derived last-known-good pointer through the existing
   policy APIs and Changes UI. Emergency restore drill evidence is now a
   rootless release gate covering rollback validation, impact/runtime
   acknowledgements, audit comments, audit-chain coverage, running-pointer
   movement, last-known-good recovery posture, and engine-apply proof. The
   System API, CLI status output, and Readiness UI now expose the first
   active/passive HA readiness contract. The daemon can now poll a peer's
   read-only HA status endpoint and surface heartbeat age, peer policy version,
   peer artifact hash, stale heartbeat, version/hash mismatch, and same-role
   blockers through System API and CLI status. Passive nodes can now run an
   automatic policy-replication loop that applies newer active-peer running
   policy through the same validated/audited HA pull path, reports last
   attempt/success/error in HA status, and surfaces that posture in Readiness.
   Manual activation now stores the preflight peer policy/artifact/failover
   evidence that made activation eligible, rejects same-role peer evidence
   before audit mutation, and exposes post-activation same-role/split-brain
   review in CLI and the Readiness HA cockpit. `ngfwctl system ha status` now
   gives operators a read-only cutover plan from the same readiness evidence.
   Optional Linux-local VIP/route promotion now runs during activation when
   configured, persists a transport claim only after successful `ip` operations,
   and leaves the node passive if promotion fails. A privileged live Linux
   integration test now proves System API activation drives a real dummy
   interface VIP/route promotion and records durable HA/audit/promotion state.
   Next add multi-node traffic cutover evidence, peer fencing, GARP/neighbor
   convergence, and connection-state transfer behind that contract.
7. **Phragma design-system hardening.** Apply the cold HUD design system across
   remaining views. Shared status/tag/card/metric primitives, live-vs-healthy
   color semantics, the focus token, toast/reduced-motion behavior, scrollbar
   treatment, table overflow containment, and responsive table helpers are now
   guarded by WebUI tests. Objects, NAT, IDS exceptions, Host Input, Readiness
   Engine prerequisites, and Readiness XDP/tc evidence now use the responsive
   evidence-table path for dense policy/config review, with the eBPF runtime
   attachment/artifact tables and card spacing pinned by source tests plus
   browser-required desktop/tablet/mobile smoke. Rules table/action layout now
   also owns header sizing, hit/action alignment, row action wrapping, name
   detail truncation, grouped-row column count, and the Profiles/Inspection
   column contract through CSS/source tests plus `/rules` browser smoke.
   Dashboard severity chart/legend layout and swatches now also use CSS-owned
   classes with source tests and `/` browser smoke. Rules toolbar filter/view
   controls now also use CSS-owned select width/grouping classes with `/rules`
   browser smoke. Rules flow-check result actions, changed-rule verification
   rows, and editor token/baseline layout now also use CSS-owned classes with
   `/rules` smoke coverage. Rules row actions and selection controls now also
   have explicit accessible labels plus keyboard-activated `/rules` smoke
   coverage. NAT row, add, save, and delete-review actions now also expose
   explicit accessible labels and button type with `/nat` smoke coverage.
   Net/VPN static-route row actions now also expose contextual labels and button type with `/netvpn` smoke coverage,
   and Net/VPN IPsec/WireGuard tunnel row actions now have the same coverage.
   Settings host-input row actions now also expose contextual labels and button
   type with `/settings` smoke coverage. Objects row actions now also expose
   contextual labels and button type with `/objects` smoke coverage. Troubleshoot
   packet-capture generated-command copy controls now also expose explicit labels
   and button type with `/troubleshoot` smoke coverage. Readiness generated-
   command copy controls now also expose contextual labels and button type with
   `/readiness` smoke coverage. Net/VPN dynamic editor remove controls now also
   expose contextual labels and button type with `/netvpn` smoke coverage.
   Shared toast, drawer, diagnostic console, and Settings panel copy controls
   now also expose explicit button semantics with `/` and `/settings` smoke
   coverage. Investigation case remove, Objects security-profile impact, and
   Rules token-chip remove icon controls now also expose contextual labels,
   explicit button type, and `/investigation`, `/objects`, and `/rules` smoke
   coverage. Shared evidence toolbar copy/export actions now also expose
   contextual labels and explicit button type with `/logs` smoke coverage.
   Traffic flow, session, and App-ID observation row actions now also expose
   contextual labels, explicit button type, and stable action selectors with
   `/traffic` smoke coverage. Settings access lifecycle, local-user,
   break-glass, browser-session revoke, and one-time-token evidence controls now
   also expose contextual labels, explicit button type, and stable access
   selectors with `/settings` smoke coverage. System Logs route and drawer
   handoff controls now also expose contextual labels and explicit button type
   with `/logs` smoke coverage. Shared API/CLI automation-context drawers now
   also expose contextual labels, explicit button type, and stable automation
   action selectors for footer, recorder, endpoint curl, API contract curl, and
   CLI copy controls. Guided Setup stage, preset, host tuning, interface
   assignment, IPS failure behavior, API/CLI checklist, and checklist proof
   controls now also expose contextual labels, explicit button/link semantics,
   and stable setup selectors with `/setup` smoke coverage. Performance
   verifier, live-status, clear, runbook copy, release command copy, and repair
   command copy controls now also expose contextual labels, explicit button
   type, and stable performance selectors with `/performance` smoke coverage.
   Changes candidate-review and version-history actions now also expose
   contextual labels, explicit button/link semantics, and stable Changes
   selectors with `/changes` smoke coverage. Settings SAML/OIDC rollout and
   OIDC preflight evidence controls now also expose contextual labels, explicit
   button semantics, and stable access selectors with `/settings` smoke
   coverage. Threats alert detail, handoff, false-positive staging, and
   exception lifecycle controls now also expose contextual labels, explicit
   button/link semantics, and stable action selectors with `/threats` smoke
   coverage. IDS/Inspection profile actions, Intel package/feed/evidence
   actions, Net/VPN dynamic-routing/tunnel/enrollment/handoff actions, shared
   diagnostic/saved-filter/capture controls, and Settings telemetry/network/
   host-input action controls now also carry explicit operator semantics with
   focused JS coverage and browser-required smoke on their owning routes.
   Generic Objects lifecycle controls, route-backed Objects reference/impact
   state, Net/VPN static-route plus IPsec lifecycle coverage, Fleet to
   Readiness drill-through, Performance to `release-benchmark` release-packet
   parity, and redacted VPN candidate-diff handling now also have focused
   source tests and browser-required desktop/tablet/mobile smoke coverage.
   Next keep validating desktop/tablet/mobile layout while finishing the broader
   keyboard/focus, artifact-currency, and interaction-regression hardening pass.

## Core Eventual Scope

Core eventual remains fully open source. It includes:

- Full L7 proxy, WAF, API gateway, forward proxy, reverse proxy, and TLS termination.
- TLS decryption policy and decryption broker/mirror.
- DNS security, URL filtering engine, file blocking, antivirus integration, DLP engine, and IoT profiling.
- IPsec, WireGuard, remote-access VPN, ZTNA, SD-WAN primitives, QoS, DoS/zone protection, caching, bot management, rate limiting, AI/LLM prompt security, scanning, full packet capture, and TAP/packet-broker functions.
- Active/passive HA pair.
- Fleet management, templates, drift detection, centralized logging, SSO, federated RBAC, compliance reporting, and long-term audit retention.

## Rule

- **HARD REQUIREMENT:** Eventual scope must not distract from v1 or create closed-source feature tiers.
