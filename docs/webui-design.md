# Phragma WebUI — Design & Plan

> Status: v1 design for the management WebUI. This documents the research,
> the design decisions, and the architecture. The UI is a **client of the
> canonical REST/gRPC API** — it holds no server-side state and every
> mutation flows through `candidate → validate → commit → (rollback)`,
> exactly like `ngfwctl` and GitOps. See [`build-plan.md`](build-plan.md)
> §3, §7 (M5), and the WebUI row in §5. The detailed GUI research baseline,
> vendor feature matrix, and gap analysis live in
> [`GUI_RESEARCH.md`](GUI_RESEARCH.md),
> [`GUI_FEATURE_MATRIX.md`](GUI_FEATURE_MATRIX.md), and
> [`GUI_GAP_ANALYSIS.md`](GUI_GAP_ANALYSIS.md).

## Current implementation snapshot

This document started as a v1 design plan, but the current `v2-mixed` WebUI is
well past the research-only stage. The embedded SPA now has route-level
coverage for the main operator workspaces, including Proxy/WAF and Compliance.
Remote continuation validation has included all-viewport broad smoke coverage
for the 20 canonical enterprise routes, and later desktop broad sweeps against
the same integrated worktree. The accepted-source release path is now the
desktop `make webui-enterprise-smoke` evidence gate; tablet/mobile sweeps remain
useful continuation evidence until release policy makes them durable gates.
Those smoke passes are continuation evidence for the current worktree only; they
are not durable release evidence until the accepted source state regenerates and
records release evidence through the repo-local release tooling.

| Route or domain | Current implemented coverage | Smoke status | Remaining functional gap | Hardening-only gap |
|---|---|---:|---|---|
| Dashboard/root (`/`, `/dashboard`) | Runtime posture, management links, policy/version context, flow/threat/change summaries | Covered | None identified for route-level summary rendering | Durable release evidence and route-duration trends |
| Guided setup (`/setup`) | Scenario presets, baseline candidate staging, first-run checklist, scenario topology proof rows, API/CLI command context | Covered | None identified for the bounded topology-proof checklist workflow | Field proof of defaults on supported topologies, production install evidence custody |
| Rules (`/rules`) | Ordered rulebase, cleanup queues, rulebase map, grouping/density/bulk review, structured overlap review, candidate-only mutations, durable-ID posture, visible/hidden/selected counts, validation freshness, cap/page guidance | Covered | None identified for the bounded large-rulebase posture and pagination-identity workflow | Backend pagination, large-rulebase virtualization, cross-page authority, truncation/custody messaging |
| Objects (`/objects`) | Address/service/application/zone/security-profile surfaces, reverse references, profile impact review, bounded TLS/DNS/URL/file control posture and handoffs | Covered | None identified for the bounded security-profile workflow | TLS key custody, URL/DNS/feed proof, live file scanning, signed object/profile evidence custody |
| NAT (`/nat`) and Routing/VPN (`/netvpn`) | SNAT/DNAT candidate lifecycle, granular simple-rule wrappers and by-ID mutation aliases, DNAT publish assist, running-vs-candidate path preview, static route/BGP/OSPF/IPsec/WireGuard candidate editing, passive proof and bounded static-route simulation | Covered | None identified for the bounded NAT/path preview and passive proof workflow | Active probes/capture, dynamic FRR/kernel sampling, remote attestation, signed path evidence, tunnel secret custody |
| Traffic, Threats, Logs (`/traffic`, `/threats`, `/logs`) | Server-filtered evidence workbenches, route-backed drawers, explain/capture pivots, false-positive exceptions, event-time policy-stamp freshness, App-ID/L7 readiness rows, system logs, active-case handoffs | Covered | None identified for bounded App-ID/L7 readiness, retained-case synthesis, and logs workbench workflows | Signed exports, retention/custody, production log-source permission evidence, true production L7/App-ID enforcement authority |
| Inspection (`/inspection`) | IDS/IPS posture, coverage map, profile rollout controls, bypass/fail-open/fail-closed visibility, bounded degraded-engine dataplane evidence | Covered | None identified for the bounded degraded-engine operator-evidence workflow | Signed field evidence, packet proof, remote attestation, production certification, richer PCAP regression comparison |
| Intel/content (`/intel`) | Feed posture, package quality gates, source preview, install/rollback, compare, corpus browsing, production-evidence inventory states, active-case handoff | Covered | None identified for the bounded production-evidence inventory/status workflow | Real signed production evidence, production custody policy, release-gate evidence retention |
| Proxy/WAF (`/proxy`) | Planned-only virtual-service, listener, route, backend, and WAF policy authoring; candidate-safe traffic-policy impact analysis; plan proof; runtime-readiness review with planned-not-executed daemon/listener/cutover/rollback fields | Covered | None identified for the bounded Proxy/WAF traffic-policy coupling and runtime-readiness workflow | TLS key custody, backend mTLS runtime proof, WAF supply-chain custody, active listener/cutover execution, packet inspection execution, HA traffic proof |
| Troubleshoot (`/troubleshoot`) | Explain timeline, running-vs-candidate compare, NAT/route/app/threat/inspection context, bounded static-route simulation, event-time policy-stamp labels, capture planning | Covered | None identified for the bounded flow/alert/route-simulation display path | Production custody, long-history stamp retention, active probe/capture custody, signed copied/exported explanation evidence |
| Investigation (`/investigation`) | Browser-local pinned evidence cockpit plus server-retained case create/list/get/append/update lifecycle, explicit hydrate/open, active-case persistence, broad append-to-active-case handoffs, retained-case synthesis | Covered | None identified for the bounded retained-case synthesis workflow | Retention, signing, RBAC policy, tamper-proof custody, immutable evidence refs, HA replication, legal hold, external ticket authority |
| Readiness (`/readiness`) | Runtime blockers, release acceptance posture, support bundles, artifact-matching workbench, release packet pivots, system/HA/eBPF/release evidence packets, Proxy/WAF plan posture link | Covered | None identified for the bounded release-artifact matching workflow | Accepted-source evidence recording, release artifact signing, stale-evidence guardrails, trend retention, production evidence custody |
| Fleet (`/fleet`) | Local-appliance fleet posture, server-side local template registry, template preview, diff/drift workbench, bounded multi-node apply-plan, local candidate template apply, retained per-node results | Covered | None identified for the bounded local template apply/result-custody workflow | Signed fleet evidence, peer RPC/fanout, peer attestation, distributed apply custody, HA/fleet replication, HA fencing, VIP movement, traffic failover |
| Compliance (`/compliance`) | Retained unsigned operational compliance report workbench with create/list/inspect/copy/export API and CLI parity plus active-case handoff | Covered | None identified for the unsigned operational report workflow | Signed custody, legal retention, production profile governance, export custody, HA/backup retention, external evidence verification |
| Changes (`/changes`) and Settings (`/settings`) | Candidate review, version/audit history, rollback/import/export, revision-bound approval records, local auth, OIDC/SAML rollout packets and field-evidence review, functional step-up controls, guardrails | Covered | None identified for the bounded candidate/access workflow | Production CAB policy, quorum/expiry/revocation, signed audit/compliance reports, secret custody, audit backpressure evidence, real-provider OIDC/SAML certification |
| Performance (`/performance`) | Benchmark artifact review, publishable-claim gates, live status evidence capture, baseline-versus-candidate comparison payloads | Covered | None identified for the bounded publishable-claim gate workflow | Benchmark release custody, signed/server-retained comparison evidence, historical trend retention |
| API/CLI parity | Route-aware context drawer, exact REST/CLI examples, ordered runbooks, browser-local workflow-session recorder, server-side replay validation, dry-run and apply-authority planning, audited execute-mode candidate replacement, and Investigation API spec overlay | Covered through route smoke | None identified for the bounded replay execution workflow | Identity binding, retention, signing, least-privilege replay scope, approval binding, custody policy |

## 0. Phragma design system

The WebUI uses the local Phragma design system as the canonical visual style:
a cold holographic firewall console with a near-black blue canvas, electric
cyan signal color, rounded translucent panel geometry, and evidence-first
hierarchy. The background should stay clean and atmospheric; avoid global HUD
grids or scanline textures behind the working UI.

Implementation guardrails:

- Use **Phragma** as the visible product name and brand. The WebUI shell uses
  the Phragma logomark and wordmark from `internal/webui/static/assets/`.
- Use Chakra Petch for brand, headings, buttons, and table-eyebrow labels; IBM
  Plex Sans for body UI; IBM Plex Mono for IPs, ports, IDs, commands, logs,
  counters, and other machine data. The static WebUI vendors those font files
  under `internal/webui/static/assets/fonts/`; the appliance must not depend on
  external font CDNs at runtime.
- Treat cyan as the live/active/interactive signal color, not as allow. Status
  semantics stay explicit: green = allow/healthy/up, amber = warn/reject or
  degraded, red = drop/threat/down, blue = informational, violet =
  unpublished change.
- Prefer rounded, compact panels and dense evidence surfaces over decorative
  cards. Every screen should feel like an operational firewall console, not a
  marketing dashboard.
- Dense operator controls must remain keyboard-operable: modal surfaces trap
  focus and return it to the opener, icon-only controls carry accessible names,
  secondary chips/options get visible focus states, and mobile topbar controls
  keep stable tap targets.
- Phragma is dark-first, but light mode is a real bright operational theme:
  white/blue-gray surfaces, dark readable text, restrained cyan accents, and
  the same status semantics and evidence-console hierarchy as dark mode.

## 1. What we learned from the incumbents

We reviewed the management UIs of the major firewall products and the
recurring operator complaints (Reddit, vendor forums, product reviews).
The themes are remarkably consistent:

| Product | What operators praise | What they complain about |
|---|---|---|
| **Palo Alto (PAN-OS / Panorama)** | Powerful policy model; granular | GUI is **slow**; reports take forever; dashboard not streamlined; commit is heavyweight. Strata's headline wins were small ergonomics: *insert a rule after the selected one* and *show dependent apps* — i.e. rule-lifecycle friction. |
| **FortiGate (FortiOS)** | Fast when it works; feature-rich | **Cluttered** from feature density; "un-intuitive"; **log viewing is slow/awkward**; GUI/CLI state drift. |
| **pfSense** | Free, capable | **Low contrast / poor accessibility**; unclear what's clickable; **inconsistent buttons**; clunky top-menu navigation; dashboard hangs on a down WAN; no customization; weak mobile. |
| **OPNsense** | **Modern, slicker, consistent** (rewrote on an MVC framework); frequent design updates | Still form-heavy; some settings buried. |
| **Cisco (ASDM / FMC)** | Deep | Java fat-clients hated; FMC **slow deploys**; confusing. |

The 2026-06-17 GUI research refresh adds a stricter product framing:
Phragma's console should be an **evidence console with a policy editor inside
it**, not a dashboard with scattered configuration forms. The design target is
the firewall that shows its work: running version, candidate state,
engine/degraded-mode posture, recent high-signal verdicts, and the shortest
path from evidence to explanation to safe policy change. The formal
best-of-breed map is:

| Capability | Borrow from | Phragma adaptation |
|---|---|---|
| Application-aware policy | Palo Alto App-ID | First-party App-ID evidence/confidence, with nDPI as one signal only |
| Ordered security rulebase | Palo Alto security policy | Rule usage, order, shadow warnings, audit comments, version-linked diffs |
| Rule table usability | Sophos Firewall | Rule groups, clone/insert/drag/filter actions, tied to candidate validation |
| Open-source rule diagnostics | OPNsense | Inspect flow/rule/NAT/route/app/threat/engine state as one explanation path |
| Low-level transparency | pfSense | Keep raw dataplane/log/session/capture truth beside polished explanations |
| Appliance breadth | Fortinet FortiGate | Keep policy, health, logs, updates, routing, VPN, and NAT adjacent/searchable |
| Inspection-path clarity | WatchGuard Fireware | Show L3/L4, IDS/IPS, App-ID, proxy/WAF, decryption, and bypass explicitly |
| Simple cloud dashboard | Meraki MX | Use onboarding/common-task clarity without hiding expert controls |
| GUI/API/CLI parity | OPNsense/Tailscale contrast | Expose public API identity and reproducible CLI/API actions for GUI changes |

**Distilled lessons (what a top-tier UI must do):**

1. **Be fast and legible.** High contrast, obvious affordances, consistent
   buttons, no multi-minute hangs. Perceived speed beats feature count.
2. **Fight clutter with hierarchy and search.** Flat navigation, a global
   command palette (⌘K), and per-table filtering so density never means
   "lost."
3. **Make change management a first-class, *safe*, *visible* workflow.**
   The best-practice change pipeline operators describe by hand
   (request → review → push → document → verify) is exactly our
   `candidate → validate → commit → audit → rollback` loop. We surface it,
   we don't hide it. A persistent "candidate" state bar, an API-backed typed
   diff before commit, reviewed rollback, and a complete audit trail.
4. **Rule-lifecycle ergonomics.** Insert-after, reorder, duplicate,
   enable/disable (disable-don't-delete for troubleshooting), clear naming,
   transient bulk selection/actions for large rulebases, density controls for
   repeated review work, tag/action/zone grouping as review lenses, in-table
   staged-change badges (`added`, `modified`, `moved`) with a `Changed only`
   review lens, and static **shadow/unused detection** so operators can clean
   up. Group headers can select their visible rules, but grouped views remain
   presentation-only:
   enable/disable/log/tag changes still stage individual candidate rule
   mutations. Filtered, grouped, or bulk-selected views pause drag reorder so a
   large-rulebase cleanup cannot accidentally move hidden rules.
5. **Close the observe→act loop.** From a dropped flow or an IDS alert, let
   the operator *pivot directly to a prefilled drop/allow rule*. "Why is
   this traffic dropped?" should be answerable in the UI.
6. **Make logs a workbench, not a table.** Traffic, threat, audit, and system
   evidence must carry stable policy/rule/app/threat/config-version context and
   link to explain, packet capture, candidate changes, exceptions, and export.
7. **Keep packet truth accessible.** A polished explanation is not enough for
   expert users; guardrailed packet capture from flow, rule, interface, or
   explain context becomes a v1 diagnostic requirement. The current
   Troubleshoot view implements the first API-backed step: after an Explain
   result, it asks `/v1/system/packet-captures/plan` for a bounded plan with
   interface, duration, packet count, snaplen, output path, BPF filter, and
   warnings. Admin users can then start the bounded capture through
   `/v1/system/packet-captures`; dry-run nodes, missing acknowledgement, and
   broad unscoped captures are rejected. The copyable command remains a
   break-glass/manual validation path, not the primary product workflow.
8. **Visuals carry the dashboard.** Operators want at-a-glance situational
   awareness: throughput, threats by severity, top talkers, change activity,
   feed/VPN posture — as charts, not walls of text.
9. **Dark-first, responsive, accessible.** Phragma's production skin is a
   high-contrast dark console; any future light mode must be deliberate rather
   than a generic inverted palette.

## 2. Top security-engineer workflows (what we optimize for)

In rough order of daily frequency, and how the UI serves each:

1. **Situational awareness** → **Dashboard**: live tiles + charts built from
   real telemetry (flows, alerts) and policy/version state.
2. **Rule management** (the #1 task) → **Policy ▸ Rules**: searchable,
   filterable table; create/edit in a side panel; reorder; insert-after;
   duplicate; enable/disable; validated `rules[].tags` metadata with search,
   tag filtering, and side-panel editing; and a rule cleanup queue for
   shadowed rules, duplicate names, broad active allows, missing logs, unused
   objects, and zero-hit committed rules. Concrete cleanup findings select the
   affected rule set, and missing-log remediation opens the same reviewed bulk
   drawer used by manual Rule operations before staging candidate changes. Rule
   hit counters and last-hit evidence stay tied to policy version so historical
   logs cannot be mistaken for current policy behavior. Candidate deltas are
   visible in-place: added, modified, and moved rules are badged in the table,
   removed rules are listed in the operations summary, and `Changed only`
   narrows review to staged candidate rows without hiding the removed-rule
   summary. Traffic and Threats currently show the running
   policy version at query time, EVE `flowId` when available, and exact
   per-event policy version when telemetry has stamped it. The
   staged **Flow check** runs `/v1/explain/flow` against the running or
   candidate policy before commit. Flow check can stage an allow or drop rule
   from the evaluated tuple, creating reusable address/service objects as
   needed. Rule editing also exposes Application references for the current
   safe v1 subset: App-ID objects can be used on drop rules and are enforced by
   referenced TCP/UDP port hints, or by supported broad Suricata signal-only
   denies when IDS/IPS is Prevent fail-closed. The editor disables staging and
   explains the server-side guardrail when an operator selects allow-by-App-ID,
   combines services with applications, scopes a signal-only App-ID rule, uses
   unsupported engine signals, or lacks fail-closed inline IPS.
   Everything stages to the candidate. The same workspace offers **Set
   up baseline** for empty or lab policies: two explicit zones, reusable
   management objects, outbound allow, optional masquerade SNAT, host-input
   default drop with a management allow, throughput/IDS/IPS posture selection,
   status-aware inside/outside interface assignment from the host inventory
   when available, and host-preparation controls for the appliance or
   throughput sysctl profile when the daemon is enforcing. Headless operators
   get the same starter model through
   `ngfwctl policy baseline`, which also stages only the candidate, and
   `ngfwctl policy diff` gives the same pre-commit candidate review path outside
   the browser.
3. **Object management** → **Policy ▸ Objects**: zones, addresses, services,
   and applications — reusable, creatable inline where supported. Application
   objects define custom Phragma App-ID aliases and port hints for flow
   classification and drop-rule port-hint enforcement. Each object row shows a
   candidate usage count backed by `GET /v1/policy/object-references`, then
   opens a reference drawer that identifies forwarded rules, host-input rules,
   source NAT entries, destination NAT entries, and the exact field using the
   object. Delete confirmation reuses that same reference list before staging
   removal, with a local draft scan kept only as a browser fallback when the API
   is unavailable. Object tabs are URL-addressable as
   `#/objects?tab=services`, `#/objects?tab=applications`, and
   `#/objects?tab=zones`; unused-object findings in the Rules cleanup queue
   preserve the matching tab so operators land on the object class that needs
   review.
4. **NAT policy** → **NAT**: source NAT and destination NAT tables with
   drawer editors. SNAT supports masquerade or static translated-address mode;
   DNAT uses host address objects and TCP/UDP service objects. Deletes and edits
   stage through candidate/validate/commit like security rules. DNAT can also
   stage the matching translated-destination allow rule so publishing a service
   does not require a second trip to the Rules workspace. Missing host and
   TCP/UDP service objects can be created inline and are staged atomically with
   the NAT edit.
5. **Threat triage** → **Threats**: IDS/IPS alerts with server-side filters
   for severity, action, endpoint, protocol, signature ID, port, time window,
   and text search; severity facets; drill-in; **"drop this source"** pivot;
   and candidate-safe false-positive exceptions with audit reason, scoped
   address object reuse/creation, validation, candidate status, and running-to-
   candidate diff. The stage result links directly into Changes. `#/threats?
   view=exceptions` is the first-class lifecycle workbench for listing,
   editing, disabling, re-enabling, and removing false-positive exceptions via
   candidate-only API calls that return validation and diff evidence; the IDS
   settings editor still shows staged exceptions as candidate-only before
   commit. Suppressions stay in Phragma policy as `ids.exceptions`; the
   Suricata adapter renders the native threshold suppression file only after
   validation and commit. Richer exception metadata such as PCAP/regression
   references, owner, ticket, review date, expiry, and evidence custody policy
   remain hardening/follow-up fields outside the current `IdsException` model.
6. **Traffic visibility / troubleshooting** → **Traffic**: server-filtered
   inspection flows by endpoint, app, protocol, port, time window, and text
   search; live conntrack sessions by endpoint, protocol, port, state, and text
   search; top talkers; and **"explain this flow/session"** / **"create rule
   from this flow/session"** / **"define App-ID from this flow/session"**
   pivots. Flow detail shows App-ID confidence and
   evidence, byte/packet counts, and endpoint metadata in place. Session detail
   shows the current original/reply tuple, counters, timeout, flags, and raw
   conntrack record independent of Suricata EVE flow logging. Operators can
   stage allow or drop rules from the same observed tuple; drop rules are
   inserted at the top and log matches. Operators can also stage custom
   Phragma App-ID definitions from unmapped engine signals or TCP/UDP port
   hints without changing running policy. The same drawer can **Save & drop**:
   it stages the application object and a top drop rule scoped to the observed
   source/destination objects, using only enforceable TCP/UDP port hints. The
   App-ID queue observation drawer can copy or export the selected review item
   as a bounded `phragma.investigation.handoff.v1` packet so unknown-app review
   evidence can be attached to tickets without exposing credential-bearing
   URLs or local package paths.
   **Troubleshoot** accepts a 5-tuple +
   zones and returns the policy verdict, matched rule, NAT evidence, route
   decision, inspection posture, skipped-rule trace, and warnings. The Rules
   page embeds the same explain endpoint for pre-commit checks while editing
   policy, including compact route and inspection-profile summaries.
   **Packet capture** is implemented as a guardrailed diagnostic follow-on from
   this workspace: the UI can launch bounded capture planning from flow,
   session, rule, interface, or explain context with scope, duration,
   byte/storage limits, and capture metadata linked back to the investigation.
7. **Logs and investigations** → **Traffic / Threats / Changes / Readiness**:
   logs are treated as an evidence workbench rather than disconnected tables.
   Shareable hash-query state is required for operator handoff: Traffic,
   Threats, Rules, Readiness, Logs, Intel, Net/VPN, Proxy/WAF, Fleet,
   Performance, Compliance, and Investigation preserve their relevant filters,
   sort/mode context, and selected evidence drawers in the URL while omitting
   default values and secrets. Saved filters, config-version context, explain
   links, export, and candidate-safe next actions are required wherever traffic,
   threat, audit, or system evidence is shown. The WebUI visual smoke now seeds
   deterministic EVE flow and alert evidence, then validates route-backed
   drawers, close cleanup, explain/capture pivots, packet-capture planning,
   candidate-only rule editors, reason-gated false-positive exceptions, and
   active-case append paths across the evidence workbenches. The Investigation
   cockpit also derives a retained-case synthesis and remediation plan from
   browser-local handoffs, legacy payloads, and hydrated server records:
   Explain and capture open Troubleshoot, rule planning opens Rules Flow check
   against the candidate source, threat suppression opens filtered Threats
   evidence, App-ID promotion opens Traffic App-ID review, NAT/routing review
   opens the NAT preview, and Proxy/Fleet/Readiness/Performance/Compliance
   rows append bounded/redacted packets to the active server case with a
   browser-local fallback. Those links are hash-only, secret/path-redacted, and
   do not mutate policy directly. NAT running/candidate path previews and other
   bounded evidence packets can be pinned or exported as case evidence so the
   tuple, owner route, path delta, packet-proof posture, and warnings stay
   attached to the investigation. Immutable evidence references, signing,
   retention/legal hold, RBAC custody, HA replication, and external ticket
   authority remain hardening.
8. **Threat intel and content** → **Intel**: feed posture, license compliance,
   refresh, candidate-safe custom HTTP(S) blocklist feeds, refresh interval
   staging, and transparent App-ID/Threat-ID content package posture. Content
   package UI shows version, signature/hash, provenance, license, install
   time, staged rollout state, regression status, and rollback availability.
   It can preview a verifier-gated server-local package directory before
   promotion, install it, and roll back to the latest verified backup through
   the canonical Intel API. Review, install, and rollback drawers are shareable as
   `#/intel?surface=<kind>&drawer=<action>` and can pin or export a redacted
   content package lifecycle handoff packet for CAB/SecOps review.
9. **Routing & VPN** → candidate-safe static-route, BGP, OSPF, IPsec, and
   WireGuard editing, route-backed tunnel handoffs, path-check pivots, and
   peer-side template/worksheet export with explicit placeholders for secret
   material and out-of-band peer values. Tunnel handoff drawers can pin or
   export VPN evidence without serializing key or PSK file paths.
10. **Change management & compliance** → **Changes / Compliance**: version
   history with diff + rollback review, policy import/export for
   backup/restore, revision-bound approval records, and the full audit log
   (who/what/when) with server-side filters for actor, action, version, time
   window, and text search. The action filter includes policy, host tuning,
   packet capture, and content package lifecycle actions so privileged
   operational mutations are visible without free-text search. Compliance is a
   first-class retained unsigned operational report workbench with
   create/list/inspect/copy/export API and CLI parity plus active-case
   Investigation handoff. Report signing, legal retention, production profile
   governance, export custody, HA/backup retention, and external verification
   remain hardening.
   The global **API / CLI context** drawer exposes the current route's public
   REST endpoints, visible selectable `curl` examples, matching `ngfwctl`
   commands, safety notes, ordered runbooks, server-side replay validation,
   dry-run planning, bounded apply-authority planning, audited execute-mode
   candidate replacement, and a browser-local redacted
   `phragma.webui.workflow-session.v1` JSON packet for handoff. Destructive,
   live, unknown, and non-candidate mutations stay blocked. This closes the
   bounded GUI/API/CLI replay workflow; identity binding, payload signing,
   retention/legal hold, least-privilege replay scope, approval binding, and
   custody policy remain hardening. Evidence tables also copy the exact REST
   request and, where a first-class CLI exists, the exact `ngfwctl` command for
   the active filters; richer production automation custody remains a future
   hardening milestone.
11. **Performance evidence** → **Performance**: browser-side benchmark run
   directory loading, `summary.json` verification, inspection-state review,
   throughput/latency/churn metrics, claim-scope checks, release/no-claims
   posture, and baseline-versus-candidate comparison payloads. Signed or
   server-retained benchmark custody, accepted-source binding, certified public
   comparison claims, and historical trend retention remain hardening.
12. **Global / dataplane settings** → **Settings**: telemetry export,
   operating profiles, MTU/MSS/offloads, flowtable fast path, dataplane
   posture, theme, API token.
13. **Production diagnostics** → **Readiness**: runtime blockers, engine
   prerequisites, dataplane proof, kernel tuning, and a support bundle export
   that captures status, policy, audit, telemetry samples, and feed posture
   without mutating the firewall. Each action-queue blocker has a stable
   `#/readiness?action=<id>` handoff link so commit review, rollback review,
   chatops, and tickets can reopen the exact remediation row.
14. **Fleet templates** → **Fleet**: local-appliance fleet posture, a
   server-side local template registry, template preview, local-appliance
   diff/drift review, bounded multi-node apply-plan with peer inventory and
   per-node eligibility, local candidate template apply, retained unsigned
   per-node result review, and route-backed active-case handoffs. This is not
   distributed fleet orchestration: signed template lifecycle, peer RPC/fanout,
   peer attestation, distributed apply/result custody, HA/fleet replication,
   HA fencing, VIP movement, and traffic failover remain hardening.
15. **Proxy/WAF planning** → **Proxy/WAF**: planned-only virtual service,
   listener, route, backend, and WAF policy authoring with candidate-safe
   staging, plan proof, runtime-readiness review, planned-not-executed
   daemon/listener/cutover/rollback proof fields, bounded redacted packet
   preview, and candidate-safe traffic-policy impact analysis. Readiness
   surfaces proxy plan posture and missing render artifacts without claiming
   traffic is proxied. TLS key custody, backend mTLS runtime proof, WAF
   supply-chain custody, request-body privacy controls, active listener/cutover
   execution, packet inspection execution, HA traffic proof, and production
   rollout certification remain hardening.

## 3. Architecture decision: dependency-free, embedded SPA

The build plan's §5 table pencils in "React + TypeScript (later)." For v1 we
deliberately ship a **framework-free, no-build, single-page app** served as
static files embedded in `controld` via `go:embed`. Rationale:

- **Supply chain.** A firewall is a security product. A no-build UI adds
  **zero npm dependencies** to ship and audit, versus the hundreds a React +
  bundler tree pulls in. This is a feature, not a limitation.
- **Deterministic builds.** `make build` stays the single source of truth.
  No Node toolchain in CI, no committed minified bundles, no separate SBOM
  surface. Aligns with the repo guardrails (CLAUDE.md).
- **Reviewability.** Every byte the browser runs is readable source in the
  repo.
- **It does not cost us quality.** Visual polish comes from CSS and
  hand-crafted SVG, not from a framework. The app uses native ES modules, a
  ~100-line reactive store, and a tiny hash router.

If the project later wants React, the API contract and this UX are the spec;
the migration is mechanical. Nothing here blocks that.

### Layout (`internal/webui/static/`)

```
index.html          # app shell: sidebar, topbar, candidate bar, modals
css/app.css         # design tokens + components (dark/light themes)
js/core.js          # reactive store, hash router, DOM helpers (h/render)
js/api.js           # typed REST client over /v1/*, auth token handling
js/auth_gate.js     # auth-required recovery helpers for OIDC/token login
js/charts.js        # dependency-free SVG charts (area, donut, bars, spark)
js/format.js        # bytes/time/ip formatting, severity maps
js/app.js           # bootstrap: nav, command palette, theme, candidate bar
js/views/*.js       # one module per view (dashboard, rules, objects, …)
```

### Data sources (existing API only — no fabricated metrics)

The UI is built strictly on shipped endpoints; where a chart needs a series,
it is **aggregated client-side from real records**, never invented:

- `GET /v1/system/version`
- `GET /v1/auth/oidc/status`, `GET /v1/auth/oidc/login`,
  `GET /v1/auth/oidc/callback`, `POST /v1/auth/logout` — browser SSO
  discovery, login, callback, and session logout
- `GET /v1/system/access-administration/oidc/config`,
  `POST /v1/system/access-administration/oidc/config:validate`,
  `PUT /v1/system/access-administration/oidc/config`,
  `POST /v1/system/access-administration/oidc/config:disable` — redacted
  node-local OIDC provider lifecycle used by Settings Access and `ngfwctl`
- `GET /v1/policy?source=…&version=…` — running/candidate/historical
- `GET /v1/candidate/status` — candidate presence, dirty-state,
  running-version baseline, section-level change counts, and first-party impact
  metadata for the persistent candidate bar and automation review
- `GET /v1/policy/diff?fromSource=…&fromVersion=…&toSource=…&toVersion=…` —
  stable typed line diffs for candidate review, version comparison, rollback
  review, GUI, CLI, and automation
- `GET /v1/system/identity` — current API actor, role, and capabilities
- `PUT /v1/candidate`, `POST /v1/candidate/validate`, `POST /v1/commit`,
  `POST /v1/rollback`. Commit and rollback requests require a non-empty audit
  comment, must set `ack_risk` for `CHANGE_RISK_HIGH` impact, and must set
  `ack_runtime` when server-side runtime readiness checks report warnings or
  production blockers. `POST
  /v1/candidate/validate` keeps the legacy candidate-validation behavior when
  called with an empty body, and can also accept an unstaged `policy` body for
  import/preflight workflows that must not replace the candidate first.
  Validation responses keep compatibility `errors[]` and add structured
  findings plus a render artifact plan so GUI, CLI, and automation can show
  policy-model, render, engine-validation, and semantic impact evidence.
- `GET /v1/versions`, `GET /v1/audit` with optional actor/action/version,
  time-window, and text-query filters
- `GET /v1/alerts` with optional endpoint/protocol/action/severity/signature,
  port, time-window, and text-query filters
- `GET /v1/flows` with optional endpoint/protocol/app, port, time-window, and
  text-query filters
- `GET /v1/sessions` with optional endpoint/protocol, port, conntrack-state,
  and text-query filters. This is live Linux conntrack state, not historical
  telemetry; it remains useful for forwarding-only and nftables flowtable
  profiles where IDS/App-ID flow records may be intentionally absent.
- `POST /v1/explain/flow`
- `GET /v1/app-id/observations`,
  `POST /v1/app-id/observations/{queueId}:stage`,
  `POST /v1/app-id/observations/{queueId}:stage-regression-sample`, and
  `POST /v1/app-id/replay:compare` — bounded App-ID review, candidate-safe
  staging, draft corpus sample staging, and read-only lab comparison
- `POST /v1/threat-id/replay:check` — bounded Threat-ID tuning replay
- `GET /v1/intel/feeds`, `POST /v1/intel/refresh`
- `GET /v1/intel/content/packages`,
  `GET /v1/intel/content/packages/{kind}/evidence/{evidenceType}`,
  `GET /v1/intel/content/packages/{kind}/corpus`,
  `POST /v1/intel/content/packages/{kind}/preview`,
  `POST /v1/intel/content/packages/{kind}/compare`,
  `POST /v1/intel/content/packages/{kind}/install`, and
  `POST /v1/intel/content/packages/{kind}/rollback` — bounded content package
  quality, evidence, corpus, preview, install, and rollback operations
- `GET /v1/change-approvals` and `POST /v1/change-approvals` — revision-bound
  approval records for candidate review and commit gating
- `POST /v1/system/packet-captures/plan`, `POST /v1/system/packet-captures`,
  `GET /v1/system/packet-captures/{id}/download`, and
  `POST /v1/system/packet-captures/{id}:set-retention` — guardrailed capture
  planning, admin execution, artifact download, and retention-sidecar updates
- `POST /v1/system/network-path:prove` — passive route/VPN proof collection
  with explicit limitations and no active probing by default
- `GET /v1/system/release-acceptance/status` and
  `GET /v1/system/support-bundle` — release recordability posture and redacted
  support-bundle evidence
- `GET /v1/fleet/templates`, `POST /v1/fleet/templates`,
  `POST /v1/fleet/templates/{id}:validate`,
  `POST /v1/fleet/templates/{id}:apply-preview`,
  `POST /v1/fleet/templates/{id}:apply-plan`,
  `POST /v1/fleet/templates/{id}:apply`,
  `GET /v1/fleet/template-results`, and
  `POST /v1/fleet/templates/{id}:stage-candidate` — local template registry,
  validation, bounded apply planning, local candidate apply, retained unsigned
  result review, and guarded candidate staging
- `GET /v1/compliance/reports`, `POST /v1/compliance/reports`,
  `GET /v1/compliance/reports/{id}`, and
  `GET /v1/compliance/reports/{id}/export` — retained unsigned compliance
  report review and export
- `POST /v1/system/automation/replay:validate` — server-side replay
  validation, dry-run and apply-authority planning, and audited bounded
  execute-mode candidate replacement. It does not grant live/destructive
  replay authority.

Policy import/export is intentionally client-side over those same policy
endpoints: export downloads a `phragma.policy.export.v1` JSON envelope
containing a running or historical policy and a `phragma-...json` filename;
import parses Phragma or legacy `openngfw.policy.export.v1` envelopes, REST
policy responses, or raw policy objects and previews them through
`POST /v1/candidate/validate` without replacing the candidate. Import rejects
unsafe object keys before preflight, shows validation status, server impact,
and the running-policy diff, and only then lets the operator stage it through
`PUT /v1/candidate`. It still requires the normal review plus commit path
before it affects the live firewall.

Dashboard charts: throughput/top-talkers from `/v1/flows`; threat timeline +
severity donut from `/v1/alerts`; change activity from `/v1/versions`; object
counts from `/v1/policy`; host load, memory, and interface drop/error posture
from `/v1/system/status.host`; and running policy hit counters from
`/v1/system/status.dataplane.counters`, with `runningPolicyVersion` marking
the committed policy those counters describe. Dashboard and Readiness also
render `/v1/system/status.dataplane.conntrack` so operators can see live
state-table usage versus `nf_conntrack_max` during high-throughput or
high-connection-churn runs. Counter cards and rule-table hit cells are hidden
or empty when the Linux runtime has not installed an `openngfw` nftables table;
the UI does not fabricate security metrics.

Performance is a local evidence review surface, not a control API. Operators
can load a whole benchmark result directory or individual artifacts and see the
same required-field, numeric-range, timestamp, claim-scope, inspection-state,
host-tuning, flowtable, and conntrack-evidence checks enforced by
`ngfwperf verify`. Benchmark data is not uploaded to controld. The page
auto-detects `summary.json`, raw `iperf3.json`, active/final status artifacts,
and nftables evidence where present. It can also capture live `/v1/system/status`
as status evidence during a run, then derives an operator
gate from the same artifact: release-gate cleanliness, publication scope,
inspection posture, kernel tuning readiness, state-table evidence, and fast-path
evidence. This makes forwarding-only, local-regression, failed-open, missing
tuning, and missing-conntrack artifacts visibly scoped instead of letting a raw
throughput number look publishable by itself. The same gate is available from
`ngfwperf verify --publishable` for release automation.

Routing & VPN stages static-route, BGP, OSPF, IPsec, and WireGuard edits
through the candidate before commit. BGP edits cover enable/disable, local ASN,
router ID, neighbors, and announced prefixes; OSPF edits cover enable/disable,
router ID, areas, and advertised networks. IPsec edits cover tunnel endpoints,
traffic selectors, proposals, initiate mode, and a swanctl PSK file path.
WireGuard edits cover interfaces, address, listen port, private-key file path,
peers, allowed IPs, endpoint, and keepalive. Secret material is never stored in
policy; only node-local file paths are staged. FRR, strongSwan, and WireGuard
are updated only after validation and commit.

Dataplane posture is also derived client-side from real API state:
`/v1/system/status` reports the active runtime dataplane, while the running or
draft policy reports `network.enable_flow_offload`, zones/interfaces, and
IDS/IPS state. The Dashboard and Settings views use the same posture model so
operators see whether the policy is on standard forwarding, inspected traffic,
or the nftables flowtable fast path. The UI disables staging and explains the
same invariants the policy validator enforces: flowtable acceleration and
IDS/IPS inspection cannot be enabled together, and flowtable acceleration needs
at least one zone interface.

The Readiness page and `ngfwctl status` also consume `/v1/system/status`
capabilities directly, including the nftables flowtable fast-path precheck.
That capability reports whether the host has the `nft` userspace dependency
needed to validate and apply flowtable policies; kernel/device syntax remains
validated during candidate validation and commit. `ngfwctl status` additionally
fetches the running policy so headless operators see the same policy dataplane
posture as the Readiness page. Supervised child engines such as Suricata and
Vector also report live lifecycle state through the same status path: stopped
engines remain ready until policy enables them, running engines show `active`,
and crash recovery shows `restarting` or `failed` with restart and last-exit
detail. `ngfwctl policy network profile throughput|inspection|edge-vpn` gives
headless operators the same high-level Settings profiles as a safe
candidate-stage path. `ngfwctl policy network set` remains the lower-level path
for global MTU, repeatable per-interface MTU overrides with
`--interface-mtu IFACE=MTU`, MSS clamping, IDS NIC offload management, and
`network.enable_flow_offload`; `--clear-interface-mtus` resets stale overrides
before applying new ones. Neither command commits changes directly.

The same status response includes structured management-plane guardrails:
TLS/auth posture, per-client API rate limit settings, REST body/header caps,
gRPC message caps, HTTP timeouts, and kernel forwarding/conntrack tuning.
Readiness renders those values in the Runtime card and treats disabled
guardrails or degraded host tuning as action-queue warnings. The same Runtime
card shows `/v1/system/status.host` load average, memory use, and interface
drop/error counters so host pressure is visible before and after high-throughput
tests. It also shows `/v1/system/status.dataplane.conntrack` and treats a
degraded state table as a production blocker.

The status response also includes structured Linux/eBPF XDP/tc host readiness.
Readiness renders the eBPF state and the first failed probes beside the running
policy dataplane so operators can distinguish the current nftables/conntrack
renderer from prerequisites for the strategic eBPF dataplane milestone. A
degraded eBPF host-readiness probe is a warning for the current
nftables/conntrack renderer and a blocker only when the active dataplane is an
eBPF/XDP/tc runtime.

Readiness exports the support bundle through the server-side
`/v1/system/support-bundle` endpoint. `ngfwctl support-bundle` exports the
same schema for headless operators and automation.
The bundle uses schema `phragma.support.bundle.v1` and generated
`phragma-support-...json` filenames by default, or under a chosen directory
with `ngfwctl support-bundle --output-dir <dir>`. `ngfwctl support-bundle -o
<path>` is an explicit path override. It is a JSON artifact assembled from the
existing read APIs: status,
identity, running and candidate policy, candidate validation/impact, versions,
audit entries, recent alerts, recent flows, live conntrack sessions, and
threat-intel feed posture. The summary includes dataplane selection,
state-table capacity pressure, candidate validation state, candidate impact
risk, session/flow/alert/feed counts, release acceptance check counts, release
evidence recordability counts, warning totals, unavailable engines, and any
endpoint collection failures. Each endpoint is recorded independently so a
partial outage still produces usable evidence for support or benchmark review.
An appliance with no staged candidate records empty candidate/validation
objects, and a fresh appliance with no committed running policy records
`runningPolicyVersion: "none"` instead of a failed endpoint. The bundle never
includes the browser's stored bearer token or CLI API token. Endpoint payloads
and endpoint errors redact token, password, secret, authorization, cookie,
API-key, private-key, and PSK fields as `[redacted]` before export. Bundle
generation does not create, stage, commit, or rollback policy. The WebUI
preview drawer also renders a copyable redacted support summary that captures
section health, release acceptance counts, recordability state, content
blockers, traffic counts, audit-chain state, and collection notes without
requiring operators to attach the full JSON artifact to a ticket.

Readiness also exposes a **System evidence** packet drawer for change tickets
and operator handoffs. The packet uses schema `phragma.system.evidence.v1` and
is generated only from the page's already-loaded readiness, content, dataplane,
inspection, host-tuning, engine, capability, and release-evidence models. It is
copyable plain text rather than a raw JSON support archive. The packet includes
release evidence counts and unresolved external gate IDs, and it explicitly
states that local system evidence does not close production content,
privileged/live dataplane, M3 field, or real-provider OIDC gates unless the
matching release artifacts are recorded. System and HA evidence drawers can
also wrap the redacted packet in a local `phragma.investigation.handoff.v1`
case item so Readiness blockers can be tracked beside traffic, threat, route,
NAT, audit, VPN, and content evidence without mutating policy.

Intel manages both registry feeds and operator-owned custom feeds through the
same candidate workflow. Custom feeds are plain HTTP(S) blocklists with one IP
or CIDR per line; adding, editing, deleting, or changing the refresh interval
stages policy only. Custom feed URLs cannot embed URL credentials, sensitive
query-token keys, or obvious loopback/private/link-local/local/metadata
destinations; the same baseline egress checks run in browser preflight, policy
validation, and runtime fetch before redirects are followed by the default
client. Enforcement still requires validate/commit and a feed refresh.
Built-in feed licensing remains server-enforced at commit.

Intel also exposes a content-posture panel backed by
`GET /v1/intel/content/packages`. The view reports App-ID, Threat-ID, and
threat-intel feed package state from local manifests under
`<data-dir>/content/*/manifest.json`, including package version, manifest
hash, signature status, provenance, regression status, staged rollout state,
and rollback availability. When manifests are absent or incomplete, the UI
uses the API blockers instead of inventing package versions, signatures, or
install times. A route-backed content quality drawer at
`#/intel?surface=<kind>&drawer=quality` expands each package into package
gates plus required production evidence gates. It shows required-vs-attached
evidence for App-ID taxonomy/confidence/regression, Threat-ID taxonomy/PCAP and
false-positive regression, and intel-feed registry/parser evidence, and it
keeps demo-only or type-only evidence refs blocked until a package-local
artifact and SHA-256 are present. Attached required-evidence gates can inspect
the bounded package-local JSON artifact through
`GET /v1/intel/content/packages/{kind}/evidence/{evidenceType}` after the API
revalidates the artifact path, JSON format, and hash. Package review, quality,
install, and rollback drawers preserve their selected package/action in the
hash route, clear that state on every drawer close path, and provide
copy/export handoff
packets built from whitelisted surface fields. Those handoff packets include
decision checks, blockers, version/hash/signature/provenance/regression/
rollout/rollback status, and the current route, but do not serialize
operator-entered install source paths or server-local manifest/rollback paths.
The same packet can be pinned to the local Investigation case for CAB/SecOps
follow-up without mutating policy or content state.

Settings exposes telemetry export to ClickHouse through Vector using the same
candidate workflow as every other mutation. Browser operators can enable or
disable export, set the ClickHouse HTTP endpoint and database, see Vector
runtime posture from `/v1/system/status`, read passive running-policy export
posture from `/v1/system/telemetry/exports/status`, and stage the resulting
`telemetry.enabled`, `clickhouse_url`, `database`, and JSON export policy fields
without touching the running firewall. The passive endpoint reports configured
ClickHouse, JSON file, and JSON TCP/UDP sinks, Vector posture, running policy
version, and local JSON export file presence/size/mtime without sending test
events or dialing remote receivers; `ngfwctl system telemetry-export-status`
returns the same evidence for terminal operators. The telemetry panel can also
copy a post-commit evidence plan with runtime status, candidate validation,
passive export status, ClickHouse row-count, JSON-file export, and SIEM
listener checks operators need to prove export after a controlled IDS/IPS event,
or export a redacted `phragma.telemetry.evidence.v1` JSON packet for support
handoff and release-evidence review. The same redacted evidence can be pinned
to Investigation as a standard `phragma.investigation.handoff.v1` packet for
CAB/SecOps follow-up. The packet captures pipeline state, Vector posture,
passive status source, configured sinks, evidence sources, checks, commands,
and limitations without serializing ClickHouse credentials, sensitive query
values, or operator token material. Readiness surfaces the same work as a
telemetry export proof gate when running policy has telemetry or export sinks
configured, using passive local observation where available but still requiring
ClickHouse row-count or SIEM receiver proof rather than claiming live sink
delivery from browser state alone. Support bundles include the same
`telemetryExportStatus` endpoint snapshot.

Settings keeps all operator cards visible and uses route state only as a
section focus and handoff aid. `#/settings?panel=telemetry`,
`#/settings?panel=network`, `#/settings?panel=host-input`, and
`#/settings?panel=access` scroll to the matching card, highlight it, preserve
the API/CLI context drawer's current-view state, and can be copied for
handoff. The route never stores unsaved form values, API tokens, source paths,
ClickHouse credentials, OIDC session material, or other secrets.

Settings also exposes the same global network controls for browser operators,
including operating profiles, global MTU, per-interface MTU overrides for zone
interfaces, explicit `interface=mtu` overrides for management or other non-zone
interfaces, MSS clamping, NIC-offload management, and the flowtable fast path.
This matches the headless `ngfwctl policy network profile
throughput|inspection|edge-vpn` and `ngfwctl policy network set --mtu ...
--interface-mtu IFACE=MTU` workflows so mixed-jumbo deployments can be staged
from either surface. It previews the candidate dataplane against host flowtable
readiness before staging the change.
Invalid MTU values, duplicate interface overrides, or invalid flowtable
candidates disable the Stage action and show the exact reason before a server
validation round trip. The preview normalizes unset/default network values so
it only flags a meaningful delta from the running policy.

Settings also owns host-input hardening for traffic destined to the firewall
appliance. Operators can stage a default allow/drop posture and add, edit, or
remove host-input rules for management services without touching forwarded
zone-pair rules. The UI surfaces default-allow host input as an open posture
and default-drop host input as hardened; both paths still require explicit
candidate commit. Default-drop host input is rejected by both server validation
and the Settings UI unless at least one enabled allow rule exists, which keeps
routine WebUI/API/SSH management changes from staging a total appliance
lockout.

Traffic and Dashboard application views use canonical Phragma App-ID fields
from `/v1/flows` first. The raw engine signal remains visible as supporting
evidence, but it is not treated as the product label. Running-policy custom
application definitions apply before built-in taxonomy. Low-confidence port
heuristics show their confidence so operators can distinguish engine-backed
labels from fallback guesses.

Security rules may reference application objects for the safe v1 enforcement
subset. The current dataplane enforces those references only for `ACTION_DENY`
rules: nftables expands TCP/UDP port hints into concrete drop rules, and
IDS/IPS Prevent fail-closed can enforce broad signal-only denies for supported
Suricata app-layer labels. Validation rejects allow-by-App-ID, explicit service
plus application combinations, scoped signal-only denies, unsupported engine
signals, and signal-only deny rules without fail-closed inline IPS.

Traffic session views use `/v1/sessions` and label the source as live
conntrack state. They intentionally do not infer App-ID or Threat-ID from the
state table; session rows are operational evidence for policy pivots and
forwarding/fast-path troubleshooting, while flow rows remain the canonical
App-ID evidence surface.

Troubleshoot explanations now include a Packet capture panel. It keeps packet
truth one click away from the policy explanation without silently escalating to
root-level packet capture. Operators choose an interface, duration, packet
limit, and snaplen; the UI asks the server for a validated bidirectional BPF
filter from the explained flow tuple, shows the generated command and output
path, and can start the capture through the admin-only audited API. The daemon
refuses execution in dry-run mode and refuses broad capture starts without both
source and destination IPs. The copyable command remains visible for older
daemons and break-glass manual validation.

Recent capture rows expose admin-only Retain and Release actions that call the
packet-capture retention API and update only the completed artifact sidecar.
Troubleshoot and Investigation evidence rows show retained/released/expiry
badges plus bounded case and reason metadata; they do not put retention state
into shareable route hashes or pinned packet URLs. Pruning, custody, redaction,
and tamper-proof retention status remain hardening backlog items.

Threats and Dashboard detection views use canonical Phragma Threat-ID fields
from `/v1/alerts` first. Suricata signature ID, signature text, category, and
action remain visible as evidence, but the operator-facing event label,
category, severity, confidence, and evidence list come from Phragma's
normalization layer.

Readiness joins that host posture with the running policy so operators can see
the actual enforced dataplane mode, inspection state, fast-path interfaces, and
host flowtable readiness in one place. It also shows runtime flowtable evidence
from the live `inet openngfw` nftables table through the structured
`dataplane.flowtable` status object, including devices, counters, and proof
flags. A running flowtable policy on a host whose flowtable capability is
degraded, or whose live ruleset lacks active flowtable evidence, is treated as
a production blocker.

Readiness also renders a client-side **Release evidence** strip that reuses the
same status, running-policy, content-posture, inspection, host-tuning,
conntrack, and flowtable models already loaded by the page. The strip is an
operator-facing release checklist, not a new server gate: it points to the
existing Readiness, Intel, and Performance surfaces for runtime blockers,
content package evidence, M3/performance publication review, dataplane proof,
inspection posture, and support-bundle export. Performance evidence remains a
local browser artifact review; the strip only reminds operators where that
publishable evidence is verified. Network/dataplane prerequisites link to
`#/settings?panel=network`, while auth, WebUI runtime smoke, deploy hardening,
and OIDC evidence gates link to `#/settings?panel=access`; those handoffs reuse
the same section-only route contract as Settings and never encode form values
or secrets. The Settings OIDC preflight drawer can pin, copy, or export
redacted rollout evidence without serializing provider secrets or browser
session material. External release gates that cannot be closed by the local WebUI,
such as production content readiness, privileged live dataplane integration,
M3 field evidence, and real-provider OIDC field evidence, expose an inline
**Evidence details** expander plus a compact packet drawer with the exact check
name, release-local evidence path, expected recorder artifact, documentation
reference, and copyable validate/record commands. Operators can inspect every
external gate side by side without leaving the checklist context, or open a
focused packet drawer for one gate. They can also copy a browser-generated
release evidence summary from this strip for a release ticket or change record;
the summary includes those packet details, is derived only from already loaded
page state, and does not mutate the firewall or collect any additional API data.
The Release acceptance status drawer also surfaces the server-reported
recording preflight from `/v1/system/release-acceptance/status`. That
recordability block tells operators whether the current Git checkout is clean
enough for `ngfwrelease record` and provides a copyable `make
release-acceptance-status` preflight command. It is advisory only: it does not
create evidence, assemble or verify the manifest, or mark release checks clear.
The page-level **System evidence** drawer complements that strip by collecting
the current system posture into one copyable handoff without downloading the
full support bundle JSON or overclaiming unresolved field evidence. The **HA
evidence** drawer records active/passive state, peer sync, failover eligibility,
blockers, automatic passive-replication state, and recovery metadata without
executing failover. When automatic passive replication is enabled, the daemon
uses the same validated/audited HA pull path to apply newer active-peer running
policy and the card reports last attempt, success, or error state. The High
availability card keeps a separate guarded **Manual resync** recovery drawer
for passive nodes; it requires an audit comment, calls
`POST /v1/system/ha/policy:pull`, and relies on the server to validate role,
fresh peer heartbeat, peer version, dirty-candidate state, and normal policy
runtime acknowledgements before applying. The support bundle preview can also
be opened directly as
`#/readiness?drawer=support-bundle` so support and CAB tickets can link to the
redacted summary plus JSON export workflow without mutating state.
`#/readiness?drawer=system`, `#/readiness?drawer=ha`,
`#/readiness?drawer=support-bundle`,
`#/readiness?drawer=release-acceptance`, and
`#/readiness?packet=<release-gate-id>` are valid handoff links; runtime
remediation rows also support
`#/readiness?action=<action-id>` for focused action-queue handoffs. Closing a
route-backed drawer through Escape, the scrim, or the close button clears the
query state back to `#/readiness`.

## 4. Editing model (safety first)

The UI never mutates running state directly. The flow mirrors `ngfwctl`:

1. Edits mutate an **in-browser draft** of the policy.
2. "Stage" pushes the draft to the server **candidate** (`PUT /v1/candidate`).
3. A persistent **candidate bar** uses `GET /v1/candidate/status` to show
   "N pending changes" with section-level summaries, **Diff**, **Validate**,
   **Commit** (requires a comment), and **Discard**. Diff and Changes version
   comparison use `GET /v1/policy/diff` so browser, CLI, and automation review
   the same typed evidence.
4. **Validate** surfaces structured server findings and the rendered engine
   artifact plan inline before any commit.
5. **Commit** opens a review drawer before live apply. The drawer validates the
   candidate, shows the server-side impact summary, fetches `/v1/system/status`,
   and evaluates the staged candidate with the same Readiness model used by the
   production diagnostics page. The drawer summarizes dry-run mode, disabled
   guardrails, missing engine prerequisites, degraded host tuning, conntrack
   pressure, eBPF host-prerequisite gaps, and candidate dataplane readiness
   blockers. A candidate that newly enables nftables flowtable acceleration is
   preflighted against host readiness before commit; live flowtable ruleset
   counters become a post-commit Readiness and benchmark-evidence gate once the
   policy is actually applied. High-risk policy impact or non-ready runtime
   posture requires an explicit acknowledgement plus an audit comment before the
   Commit button is enabled. `ack_risk` and `ack_runtime` are enforced
   server-side with the target policy and the currently running policy, so
   direct API clients cannot bypass candidate-specific dataplane readiness
   gates. Changes links each preflight runtime item to the exact
   `#/readiness?action=<id>` blocker while keeping any settings or intel fix
   link as a separate secondary action. `ngfwctl commit` and `ngfwctl rollback`
   print the same impact plus
   target-policy-aware runtime posture and require `--ack-risk` and/or
   `--ack-runtime` for the corresponding headless acknowledgement gates; both
   headless commands also require `--message/-m` for audit context. The same
   impact summary includes candidate policy hygiene for shadowed rules and
   active any-to-any allow rules, while structured validation findings include
   missing rule logs, unused policy objects, and partial rule overlaps. These
   match the Rules cleanup queue instead of leaving those findings as UI-only
   hints. Rules also shows row-level candidate deltas before the commit drawer:
   `added`, `modified`, and `moved` candidate rows are badged, removed running
   rules stay visible in the operations summary, and `Changed only` pauses drag
   reorder like any other filtered review lens. The drawer shows the full impact list in a bounded review pane so
   dense candidates do not hide lower-priority findings.
6. A successful commit applies atomically and records a version; **Changes**
   offers reviewed **rollback** to any prior version. Rollback validates the
   target policy as an unstaged policy, shows server impact, runtime posture,
   and the API-backed running-to-target diff, then requires an audit comment. High-risk
   rollback impact or non-ready runtime posture requires an explicit
   acknowledgement before live apply, and both `ack_risk` and `ack_runtime` are
   enforced by the rollback API for high-risk or runtime-warning targets.
7. **Flow check** in Rules can restage the draft to the candidate, explain a
   tuple before commit, and stage an allow/drop rule from that tuple. Reviewers
   can verify the first-match verdict, inspection posture, NAT evidence, trace,
   warnings, and the proposed rule without leaving the rule workspace.
8. **Guided setup** and **Set up baseline** in Rules stage a complete starter
   candidate from operator-entered zone/interface/CIDR values. They never
   commit directly, and they use the same typed candidate diff, validation, impact
   review, and audit-comment path as hand-written policy edits. Guided setup
   offers throughput, IDS detect, and IPS prevent postures, surfaces host
   baseline plus throughput tuning readiness, and keeps flowtable acceleration
   off whenever inspection is enabled. Guided setup also carries a persistent
   first-run checklist that proves interface boundaries, TLS/auth/OIDC admin
   access, host-input exposure, content/update posture, outbound/NAT posture,
   inspection mode, host tuning evidence, and candidate-review readiness before
   the first commit. `ngfwctl policy baseline` provides the matching headless
   first-run baseline for CLI and automation; `ngfwctl policy diff` provides
   the headless review step.
9. **Import policy** in Changes first parses the JSON backup or raw policy
   object, validates it server-side as an unstaged policy, and shows impact plus
   diff before the **Stage import** action is enabled. Staging replaces only the
   candidate; the running firewall remains unchanged until the normal
   validate/review/commit path succeeds.

This makes the documented change pipeline operators ask for the default path,
and every action lands in the audit log with the authenticated actor.

## 5. TLS

Per the request, the management UI/API is served over **HTTPS with a
self-signed certificate**, generated on first run (ECDSA P-256, SANs for
`localhost`/`127.0.0.1`/`::1` and the host name) and persisted under
`<data-dir>/tls/`. Flags: `--tls` (default on), `--tls-cert`/`--tls-key` to
supply your own. Browsers show the expected "self-signed" warning until an
operator-provided cert is configured. This is a standard TLS server setup —
**not** TLS interception or a MITM CA (which remain a locked, human-only
effort per build plan §9).

Generated self-signed TLS is accepted automatically only on loopback. A
non-loopback listener requires an operator certificate unless the operator
explicitly passes `--allow-public-self-signed-tls` for a temporary lab. That
opt-in keeps the management capability degraded and a critical runtime warning
active because encryption alone does not establish a publicly trusted server
identity. The shipped systemd unit remains loopback-only and never sets this
opt-in.

## 6. Access Model

The Settings view and the route-level access gate support two access paths:

- bearer tokens for CLI, automation, and local users-file RBAC
- OIDC browser SSO through an HTTP-only SameSite session cookie

OIDC sessions are translated to the same bearer-token interceptor path used by
the REST gateway after the browser request proves same origin and supplies the
per-session `X-Phragma-CSRF` value advertised by `/v1/auth/oidc/status`, so role
checks and audit metadata are identical for browser and API clients. The UI does
not store OIDC provider tokens in local storage. If a protected page returns
unauthenticated or permission-rejected, the router renders an in-place access
panel with the OIDC sign-in action when available, a local-token verifier, and
retry. Operators do not need a separate Settings round trip to recover from an
expired session or missing token.

The OIDC sign-in return target is normalized to known WebUI hash routes before
it is sent to `/v1/auth/oidc/login`, so malformed hashes, nested fragments, and
unknown SPA paths fall back to `/ui/` instead of sending the browser back to a
dead route. Settings mirrors the same model as a compact access posture strip:
runtime auth, browser SSO, active session, and mutation guard state are visible
next to the token fallback without adding another API endpoint.

Settings Access also exposes an advisory RBAC role-impact preview. The Access
Governance panel compares viewer, operator, and admin workflow reach, and the
local-user create/update drawers show gained and lost workflows before a role
change is submitted. This is an operator clarity feature; backend
authorization, audit enforcement, IdP role mapping, MFA, and step-up controls
remain separate security requirements. The same panel now has API/WebUI/CLI
parity for the node-local OIDC provider lifecycle: operators can validate,
save, and disable runtime provider configuration through Settings Access or
`ngfwctl access oidc provider ...`; inventory and context copy expose only
redacted secret-file posture, never provider tokens or secret bytes.
The panel also supports SAML provider posture show, validate, save, disable,
redacted rollout packet copy/export/pin, and runtime browser SAML sign-in
through the canonical API and `ngfwctl access saml provider ...`.

## 7. Out of scope for this iteration

- Functional step-up controls are implemented for bounded workflows. Real-
  provider OIDC/SAML certification remains hardening work: provider metadata
  reachability, certificate rollover, trusted-proxy behavior, IdP/MFA-backed
  reauth field proof, and signed evidence custody still need certification.
- Production per-rule-hit and last-seen telemetry custody remains hardening
  work: bounded hit counters exist, but long-retained counter provenance,
  reset/rollover semantics, HA/fleet aggregation, and certified last-seen
  evidence need production controls.
- VPN import parsers, key/PSK generation and rotation, stronger key
  validation, secret custody workflows, and field proof.
