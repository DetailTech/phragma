# Phragma — Build Plan (Claude Code Handoff)

> **Product name:** `Phragma`.
> **Compatibility note:** this branch may still expose `openngfw`/`ngfwctl`
> identifiers in code paths, binaries, schemas, config paths, nftables tables,
> and tests. Rename those only through an explicit migration plan.
> **Audience:** AI coding agents (Claude Code) and human contributors.
> **Status:** v2-mixed build plan. This branch starts from the working DetailTech implementation and applies the stricter Phragma product definition from `docs/PROJECT_DEFINITION.md` and `docs/HARD_REQUIREMENTS.md`. Where those documents conflict with this plan, they win.

This document is implementation guidance for the current branch, not a scope reduction. The imported product definition remains the north star: a 100% open-source, VM-Series-class cloud/virtual NGFW whose product model is owned by Phragma, not by any integrated engine.

-----

## 0a. GUI and brand plan inputs `[LOCKED]`

The WebUI is part of the product model, not a skin over the engines. The
current branch adopts the repo-local 2026-06 GUI review and Phragma design
system direction as canonical inputs for UI work:

- `docs/GUI_RESEARCH.md`, `docs/GUI_FEATURE_MATRIX.md`, and
  `docs/GUI_GAP_ANALYSIS.md` define the enterprise firewall workflows the UI
  must cover: candidate safety, ordered policy operations, evidence-led flow
  explanation, App-ID/Threat-ID ownership, content updates, auth/audit,
  packet truth, and GUI/API/CLI parity.
- `docs/webui-design.md` translates that review into the implementation plan
  for the embedded management console.
- Production WebUI code vendors the required Phragma assets under
  `internal/webui/static/assets/`, uses self-hosted console fonts, and keeps
  the cold holographic HUD console style: near-black blue canvas, electric
  cyan for live/active controls, strict firewall status colors, angular
  compact panels, and monospaced machine evidence.

Visible product naming is **Phragma**. Compatibility identifiers such as
`openngfw`, protobuf package names, Go module paths, system paths, and
`ngfwctl` remain until a deliberate migration plan changes them safely.

-----

## 0. Read this first — the one thing to internalize

**The product is Phragma's policy, verdict, explanation, content, and operations model.**

The control/policy plane is the current working foundation, but it is not permission to become only an engine orchestrator. Phragma uses proven engines behind adapters while owning the policy model, compiler, lifecycle supervisor, API, CLI, telemetry, verdicts, explanations, App-ID and Threat-ID product layers, and benchmark discipline.

So: **integrate engines; do not let engines define the product.** nDPI is a signal source, not App-ID. Suricata is a matching engine, not Threat-ID. nftables is the current real Linux renderer and compatibility path, not the end of the dataplane roadmap.

If you find yourself writing a packet-inspection engine, a routing daemon, or a TLS stack from scratch — **stop and ask a human.** You are off-plan.

-----

## 1. Scope discipline (the hard part)

The vision is large. The *build* must be small and concrete. Scope is tracked as a ledger, not a wish list.

### v1 (build now)

Single-node, cloud-deployable firewall with a real control plane and a product
path to VM-Series-class cloud/virtual NGFW capability:

- Stateful L3/L4 zone-based firewall with nftables/conntrack as the current
  renderer and compatibility/fallback path
- Linux/eBPF XDP/tc dataplane milestone behind the same policy/IR boundary
- NAT (source/dest/static), static routes
- Declarative policy model + candidate/commit/rollback
- gRPC + REST API
- CLI
- IDS/IPS via Suricata (integration, not reimplementation)
- Structured logging + telemetry pipeline
- Dynamic routing (FRR) + IPsec (strongSwan) + WireGuard
- App/protocol visibility with nDPI as one signal source, plus an
  Phragma-owned App-ID taxonomy, evidence, confidence, custom app, and
  regression model
- Suricata-backed IDS/IPS as the v1 matching engine, plus a Phragma-owned
  Threat-ID/profile/explanation layer
- Threat-intel feed enforcement (CrowdSec + federated feeds) with a feed-license registry
- Local-token auth, browser OIDC SSO, local RBAC, complete local audit log
- Embedded management WebUI with dashboard, policy editing, threat/traffic
  pivots, changes view, and HTTPS by default
- Supply-chain hygiene from commit #1 (SBOM, signing, DCO)

### Eventual (designed-for, built later)

HA active/passive (keepalived/conntrackd), L7 (Envoy + Coraza WAF/proxy/API-gateway/LB), ZTNA (OpenZiti), DNS security, full single-node feature parity, fleet management (multi-node control plane), SSO federation/SCIM, compliance evidence/reporting, Linux/eBPF XDP/tc dataplane renderer and agent.

### Later / research

TLS break-and-inspect (see §9 — this is hard and an *eroding* capability), sandboxing/detonation (pluggable interface only in v1), honeypot-sourced intel, active/active HA, VPP/DPDK datapath, multi-tenancy orchestration, AI/LLM prompt security.

### Explicit non-goals

- **Not** claiming full Palo Alto product parity in this initial branch. The design still must not block VM-Series-class virtual/cloud capability.
- **Not** building any inspection/routing/crypto engine from scratch.
- **Not** a hardware appliance.
- **Not** the holder of any certification (see §2).
- **Not** "single-pass like Palo SP3." Independent userspace engines re-parse; that's accepted.

-----

## 2. Strategic & licensing decisions `[LOCKED]`

|Decision     |Detail                                                                                                                                                                                                                                                                               |
|-------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|Openness     |100% open source. No open-core, no enterprise repo, no paid tier.                                                                                                                                                                                                                    |
|License      |**Apache 2.0** for all project code.                                                                                                                                                                                                                                                 |
|Contributions|**DCO** (Developer Certificate of Origin) sign-off, not a CLA. (CLA existed to preserve a relicensing/open-core option that no longer applies.)                                                                                                                                      |
|Governance   |Single-vendor-neutral OSS now; a foundation home is an **asset** under this model and a likely future step (attracts corporate contributors, signals longevity, vehicle for consortium funding). Hold the trademark + GitHub org in the founding entity to protect project integrity.|
|First product|Single-node, cloud-deployable virtual firewall.                                                                                                                                                                                                                                      |
|Wedge        |Cloud-native egress / Kubernetes east-west firewalling + homelab — where eBPF-native, declarative, GitOps management is an *advantage*, not just cheaper.                                                                                                                            |
|Datapath     |nftables/conntrack is the current real Linux renderer and fallback path; Linux/eBPF with XDP/tc is a required strategic milestone; VPP deferred. (See §5.)                                                                                                                          |

### The certification reality (plan around it)

"Taken seriously at enterprise/DoD" means certifications (FIPS 140-3, Common Criteria NDcPP, FedRAMP, DoD APL). **Certifications attach to a funded entity and a specific validated build — not to source code.** A pure community project cannot itself hold them.

What the project **can and must** do:

- Ship **FIPS-ready** code: use a FIPS-validated crypto module (e.g. the validated OpenSSL FIPS provider), support a FIPS mode, never roll custom crypto.
- Ship **STIG-hardenable** code + an OpenSCAP/STIG profile.
- Ship **SBOMs**, signed releases, SLSA provenance, a published CVE/disclosure process.
- Ship **reference architectures** and Terraform/OpenTofu modules.

What is **out of scope** for this code project: holding certificates, ATO sponsorship, 24/7 support. Those belong to a future funded entity (foundation/consortium/services company) that orbits the project. Do not write roadmap items implying the repo becomes certified.

-----

## 3. Architecture `[LOCKED unless noted]`

### Layering

```
                 ┌─────────────────────────────────────────┐
                 │  Clients: CLI · REST · WebUI · GitOps     │
                 └───────────────────┬───────────────────────┘
                                     │ gRPC (canonical) / REST (gateway)
                 ┌───────────────────▼───────────────────────┐
                 │  CONTROL PLANE (your code)                 │
                 │  • Policy model (declarative)              │
                 │  • Candidate/commit/rollback + versioning  │
                 │  • Policy compiler → intermediate repr     │
                 │  • Backend renderers (per engine)          │
                 │  • Engine lifecycle supervisor             │
                 │  • AuthN/Z, audit, telemetry aggregation   │
                 └───────────────────┬───────────────────────┘
                                     │ native config + process control
   ┌─────────────┬─────────────┬─────┴───────┬─────────────┬──────────────┐
   ▼             ▼             ▼             ▼             ▼              ▼
 DATAPATH     IDS/IPS       ROUTING        IPsec         DPI          (later) L7
 nftables/    Suricata      FRR            strongSwan    nDPI          Envoy+Coraza
 conntrack    (separate     (separate      (separate     (separate     (separate
 (kernel)      process)      daemons)       process)      process)      process)
```

### Principles

1. **Control/data-plane separation.** `[LOCKED]`
1. **The canonical API is the seam and the contract.** `[LOCKED]` Define it early, version it, keep it stable. Everything (CLI, UI, GitOps, future fleet controller) is a *client* of this API.
1. **Engines run as separate processes/containers.** `[LOCKED]` Reasons: (a) license isolation — GPL/AGPL engines must never be linked into Apache code; (b) fault isolation; (c) independent lifecycle. You manage them by generating their native config files and supervising their processes.
1. **Policy as declarative data.** `[LOCKED]` One model spans firewall/NAT/routing/VPN/intel. Compiled to an internal intermediate representation, then rendered per backend. Never hand-edit engine configs out of band.
1. **Candidate/commit/rollback is non-negotiable and lives in core.** `[LOCKED]` No change touches a running engine without staged validation, atomic commit, and rollback. This is also the safety guardrail against an agent corrupting a live config.
1. **Tenancy primitives from day one, orchestration later.** `[LOCKED]` Build isolation domains (VRF/netns concepts) into the model even though multi-tenant management is a later milestone.
1. **GitOps-native.** `[RECOMMENDED]` Policy reconcilable from a git repo. This is a genuine differentiator vs incumbents.
1. **What-if simulation.** `[RECOMMENDED — differentiator]` "What would this policy change do?" before commit. Plan the model so this is possible.

-----

## 4. Tech stack `[LOCKED unless noted]`

|Layer                                           |Choice                                                                      |Notes                                                                                              |
|------------------------------------------------|----------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
|Primary language (control plane, CLI, renderers)|**Go**                                                                      |Ecosystem fit (netlink, gRPC, K8s/Cilium/FRR/Envoy adjacency), static binaries, strong concurrency.|
|eBPF datapath milestone                         |Go (`cilium/ebpf`) or Rust (`aya`) `[OPEN]`                                 |Required by the product definition; decide implementation language when the eBPF milestone starts. |
|API contract                                    |**Protobuf + gRPC** canonical; REST via grpc-gateway; OpenAPI generated     |Single source of truth for the model.                                                              |
|Config/state store                              |**SQLite or BoltDB** embedded (single-node) `[OPEN between the two]`        |Candidate/commit maps to versioned records. Git-backed reconciliation layered on top.              |
|Higher-level policy validation                  |OPA/Rego or Cedar `[OPEN]`                                                  |Management-plane validation only — NEVER in the fast path.                                         |
|Telemetry/log shipping                          |**Vector**                                                                  |Collects Suricata EVE JSON + system logs.                                                          |
|Log/event store                                 |**ClickHouse** (default) or OpenSearch `[OPEN]`                             |ClickHouse preferred for volume/cost.                                                              |
|CLI                                             |Go + Cobra                                                                  |—                                                                                                  |
|WebUI                                           |Dependency-free embedded SPA now; React + TypeScript remains optional later |Served from `controld`; all mutations use candidate/commit.                                        |
|Packaging (v1)                                  |Containers + docker-compose / systemd units                                 |The "10-minute install" target.                                                                    |
|Packaging (later)                               |Helm chart, K8s operator                                                    |Operator is a *client* of the API, not the canonical API.                                          |
|Cloud deploy                                    |Terraform / OpenTofu modules + golden images (Packer)                       |Beachhead enablement.                                                                              |
|Supply chain                                    |syft (SBOM), cosign (signing), SLSA provenance, Renovate/Dependabot, DCO bot|From commit #1.                                                                                    |

### Dependency / engine license ledger `[LOCKED — verify before adding anything new]`

Run GPL/AGPL items as **separate, un-linked processes**. Never import their code into Apache modules.

|Engine                 |License                   |Isolation                                                   |
|-----------------------|--------------------------|------------------------------------------------------------|
|Suricata (IDS/IPS)     |GPL-2.0                   |Separate process. Consume EVE JSON.                         |
|FRRouting              |GPL-2.0                   |Separate daemons (already the norm). Config via vtysh/files.|
|strongSwan (IPsec)     |GPL-2.0                   |Separate process. Config via swanctl.                       |
|nDPI                   |LGPL-3.0                  |Separate process recommended.                               |
|WireGuard              |GPL-2.0 (kernel)          |Kernel feature; configure via wg/netlink.                   |
|nftables/conntrack     |GPL-2.0 (kernel/userspace)|Render rulesets; manage via libnftables/CLI.                |
|Envoy + Coraza (later) |Apache-2.0                |Safe to integrate more closely.                             |
|OpenZiti (later)       |Apache-2.0                |Safe.                                                       |
|CrowdSec               |MIT                       |Safe. Integrate; do not rebuild its central infra.          |
|Zeek (optional NSM)    |BSD                       |Safe.                                                       |
|OpenSCAP / STIG content|varies (mostly permissive)|Hardening + compliance profiles.                            |

> **eBPF licensing carve-out (when you reach the eBPF milestone):** many BPF kernel helpers are GPL-gated; a BPF program must declare a GPL-compatible license to use them, and Apache-2.0 is **not** GPLv2-compatible. The eBPF datapath programs specifically may need to be GPL or dual-licensed even though the rest of the project is Apache. Flag to a human before writing them. (Another reason nftables is first.)

-----

## 5. Datapath strategy `[LOCKED]`

**v2-mixed implementation stance: preserve working nftables, require eBPF as a
strategic milestone.**

- nftables/conntrack stays because it is working, stateful, testable, and useful
  as the compatibility/fallback path.
- The branch must not treat nftables as the final dataplane story. Linux/eBPF
  with XDP where available and tc where needed remains a required milestone
  under `docs/HARD_REQUIREMENTS.md`.
- The policy compiler and IR must stay backend-neutral enough for an eBPF/tc
  renderer and agent to be added without replacing the API or product model.
- eBPF work is deliberately not pulled into this first reconciliation branch:
  kernel safety and GPL-helper licensing need focused design review.

**Throughput framing (so nobody panics):** For an NGFW the datapath is *not* the throughput ceiling — the **userspace inspection tier (Suricata/nDPI) is**, and it is CPU-bound regardless of datapath. Forwarding throughput targets (10–40 Gbps) are reachable; threat-prevention throughput is a fraction of that and bounded by inspection. **Benchmark against Palo VM-Series (software), not hardware flagships.** Never assert a throughput number you have not measured (see §10).

**Roadmap:**

1. **nftables/conntrack** — current runnable renderer and fallback path.
1. **eBPF/XDP/tc** — required product milestone behind the same policy model,
   with design focused on safe hook lifecycle, map ownership, inspection-tier
   steering, failure behavior, and licensing.
1. **VPP/DPDK** — deferred further; documented future backend for 100 Gbps+, physical appliances, very-high-CPS. Do not build in v1.

The **datapath abstraction** (control plane compiles to an intermediate representation, then a per-backend renderer) is built in v1 even though only the nftables renderer exists. This is what keeps the architecture from welding to nftables.

-----

## 6. Repository layout `[RECOMMENDED]`

**Monorepo for v1** (easier for an agent to reason about the whole system; atomic cross-cutting changes; single CI). Polyrepo can come later.

```
/api/                 # .proto definitions, generated Go/OpenAPI
/cmd/
  /controld/          # control plane daemon entrypoint
  /ngfwctl/           # CLI entrypoint
/internal/
  /policy/            # declarative model, schema, validation
  /compiler/          # policy -> intermediate representation (IR)
  /renderers/
    /nftables/        # IR -> nftables ruleset (v1)
    /suricata/        # IR -> suricata.yaml + rules selection
    /frr/             # IR -> FRR config
    /strongswan/      # IR -> swanctl config
    /ndpi/            # nDPI integration/config
    /intel/           # feed selection + enforcement wiring
  /engines/           # lifecycle supervision of external processes
  /store/             # config/state, candidate/commit/versioning
  /telemetry/         # log/metric aggregation, Vector config
  /authz/             # local RBAC, OIDC sessions, audit log
  /apiserver/         # gRPC server + REST gateway
/web/                 # React UI (later milestone)
/deploy/
  /compose/           # docker-compose single-node
  /systemd/           # unit files
  /helm/              # (later)
  /terraform/         # OpenTofu/Terraform cloud modules
  /packer/            # golden images
/docs/
/test/
  /unit/
  /integration/       # containerized engines, real traffic
  /e2e/               # 10-minute-install acceptance
  /perf/              # benchmark harness
/CLAUDE.md            # extract conventions + guardrails (§11, §12) here
```

-----

## 7. Milestones `[LOCKED order; scope within is the contract]`

Each milestone has a **Definition of Done (DoD)**. Do not advance until DoD is met and tests pass.

### M0 — Foundation

Scaffolding only. Highly agent-suitable.

- Repo, module layout, Go workspace, lint/format/CI.
- DCO bot, SBOM generation, cosign signing, SLSA provenance in CI.
- Dev environment (devcontainer or Nix).
- Initial `.proto` API skeleton + codegen pipeline.
- `CLAUDE.md` with conventions + guardrails.
- **DoD:** `make build test lint` green in CI; signed artifact + SBOM produced; empty `controld` and `ngfwctl` run and report version.

### M1 — Single-node stateful firewall + control loop ⭐ (proves the architecture)

- Policy model (zones, addresses, services, rules, NAT, static routes) in protobuf + schema validation.
- Config store with candidate/commit/rollback + version history.
- Compiler: policy → IR. Renderer: IR → nftables ruleset.
- Engine supervisor applies/reloads nftables atomically.
- gRPC API + REST gateway + CLI (`ngfwctl policy ...`, `commit`, `rollback`, `show`, `sessions`).
- Live conntrack session visibility through the canonical API/CLI so the
  current nftables/conntrack dataplane remains observable even when IDS/App-ID
  flow telemetry is absent.
- **DoD:** Author a policy in YAML, push via CLI/API, traffic is filtered/NATed correctly, `commit` is atomic, `rollback` restores prior state, every change is in the audit log, and live state-table sessions are visible from API/CLI on a Linux firewall host. Golden-file tests cover policy→nftables rendering.

### M2 — IDS/IPS + telemetry

- Integrate Suricata as a separate process (IDS mode first; inline IPS via dataplane after).
- Renderer manages suricata.yaml + ruleset selection.
- Vector pipeline: Suricata EVE JSON + system logs → ClickHouse.
- Alerts queryable via API/CLI; basic dashboards data available.
- **DoD:** Suricata eval/test traffic produces detections visible via API/CLI; IPS mode drops a known signature; logs are structured and queryable; no engine crash under a sustained test flow.

### M3 — Dynamic routing + VPN

- FRR integration (BGP/OSPF) via the unified model.
- strongSwan (IPsec) + WireGuard via the unified model.
- **DoD:** BGP peering established and routes programmed through the model; IPsec tunnel + WireGuard peer established and managed entirely through policy (no out-of-band engine edits).

### M4 — App-ID foundation + threat intel

- nDPI integration for app/protocol visibility: label flows/logs and provide
  policy-match signals.
- Phragma-owned App-ID foundation: taxonomy, evidence model, confidence
  scoring, custom application definitions, encrypted-traffic heuristics, update
  package format, regression corpus, and the current safe App-ID rule subset:
  deny rules enforced through custom application TCP/UDP port hints, plus broad
  signal-only Suricata denies when IDS/IPS is Prevent fail-closed and the
  signal is in the supported app-layer allowlist.
- CrowdSec integration + federated feeds (ET Open, abuse.ch, Spamhaus) enforced as blocklists.
- **Feed-license registry:** every feed records redistribution/commercial-use/attribution/privacy constraints; enforcement respects them.
- **DoD:** Flows show app/protocol labels in logs; nDPI-derived evidence remains
  distinguishable from Phragma-owned App-ID decisions; a blocklist feed is
  enforced and toggleable; `/v1/app-id/observations` groups unknown,
  low-confidence, and conflicting flow evidence into reviewable queue items;
  the Traffic WebUI can inspect those observations and stage custom
  `applications[]` definitions through the candidate path; App-ID deny rules
  render concrete nftables port-hint drops or managed Suricata signal drops
  for supported broad signal-only deny rules, while unsafe allow-by-App-ID,
  service+application, scoped signal-only, unsupported-signal, and non-fail-
  closed signal-only shapes are rejected; the feed registry blocks
  enabling a feed whose license forbids the intended use.

### M5 — AuthN/Z + WebUI

- Local users-file tokens, browser OIDC and SAML login (single node), local
  RBAC, complete audit log surfaced.
- WebUI: dashboard, logs, policy view, rules/objects editing, threat/traffic
  pivots, live session visibility, command palette, and version/audit history
  through the candidate/commit workflow.
- GUI research from `docs/GUI_RESEARCH.md`, `docs/GUI_FEATURE_MATRIX.md`, and
  `docs/GUI_GAP_ANALYSIS.md` is adopted as the WebUI planning input. The
  branch plan changes from "build screens" to **build an evidence console with
  a policy editor inside it**: running version, candidate state,
  degraded-engine posture, recent verdict evidence, and direct paths from
  logs/flows/threats to explanation, packet capture, candidate fixes, export,
  and rollback.
- Logs become a workbench, not a passive table. Traffic, threat, audit, and
  system evidence must carry stable policy/rule/app/threat/config-version
  context, support saved filters and export, and link to `explain` plus
  candidate-safe next actions.
- Guardrailed packet capture from explain/log/rule/interface context is a v1
  diagnostic requirement. The current branch exposes API-backed plan/start
  endpoints plus `ngfwctl system capture` for bounded host captures, with
  admin-only RBAC, explicit acknowledgement, dry-run refusal, server-generated
  BPF filters, audit entries, scope/duration/packet/snaplen limits, and
  copyable commands for manual fallback or break-glass validation.
- Content-update transparency moves into the WebUI plan: App-ID and Threat-ID
  package status must show version, signature/hash, provenance, source license,
  install time, staged rollout or regression status, and rollback posture as
  the content APIs mature.
- GUI/API/CLI parity is now a visible UX requirement. Advanced drawers should
  expose stable object IDs and relevant public API endpoints now, with
  copy-as-API-request and copy-as-CLI-command actions planned for candidate
  changes and log queries.
- First-run baseline staging is available in the Guided setup and Rules UI
  surfaces plus `ngfwctl policy baseline`, producing ordinary candidate policy
  objects that still require validate/review/commit. The browser and headless
  workflows can stage throughput, IDS detect, or IPS prevent posture and keep
  flowtable acceleration off when inspection is enabled. Headless review includes
  `ngfwctl policy diff`, which compares the staged candidate against running
  policy by default or a selected historical version.
- Network operating profiles for throughput, IDS/IPS inspection, and
  Internet/VPN edge are available in both Settings and
  `ngfwctl policy network profile`, with lower-level overrides still available
  through `ngfwctl policy network set`.
- **DoD:** A user logs in via OIDC, role-gated actions enforced, full
  single-node management achievable via UI, a headless operator can stage and
  diff the same first-run baseline and network profile changes from the CLI,
  logs/flows/threats can pivot into explanation and audited packet-capture
  actions, content/update posture is visible, API object identity is visible
  for GUI mutations, and all UI/CLI configuration mutations flow through
  candidate/commit and appear in the audit log.

### M6+ — Eventual (separate planning when reached)

HA active/passive (keepalived/conntrackd), L7 (Envoy+Coraza), ZTNA (OpenZiti),
DNS security, Linux/eBPF XDP/tc dataplane agent, fleet management, SSO
federation/SCIM, compliance evidence. Each gets its own mini-plan and DoD.

-----

## 8. Testing & validation `[LOCKED]`

- **Unit:** policy model, compiler, validation.
- **WebUI static checks:** `make webui-check` syntax-checks the browser modules
  and runs dependency-free JavaScript regressions for browser-only support-bundle
  behavior.
- **Golden-file:** every renderer (policy/IR → engine config) has golden tests. Renderer changes must show diffs and be reviewed.
- **Integration:** real engines in containers, real traffic (e.g. via network namespaces / scapy / iperf), asserting end-to-end behavior — not mocks.
- **E2E "10-minute install":** an automated test that stands up a single node from scratch in a clean cloud VM / container and reaches a working filtered state. This is a *product requirement*, treat its failure as a release blocker. The current branch provides `make e2e-install-check` for non-destructive CI/static validation and `sudo -E make e2e-install` for the disposable Linux host/VM acceptance run when build/cache environment variables must be preserved.
- **Performance harness:** repeatable benchmarks for forwarding throughput, threat-prevention throughput, connection rate, and latency. The initial harness lives in `perf/` and is run through `make benchmark-check` / `make benchmark`. **All performance claims must come from this harness. Never assert a number you didn't measure.**
- **Host appliance tuning:** install and verify forwarding/conntrack sysctls as a first-class readiness gate. `deploy/install.sh`, `ngfwctl system tune`, `ngfwctl status`, `/v1/system/status`, and the WebUI Readiness page must agree on whether the host kernel baseline is ready. High-bandwidth and connection-churn runs use `OPENNGFW_TUNE_PROFILE=throughput sudo deploy/install.sh` or `sudo ngfwctl system tune --profile throughput --write --apply` before benchmarking.
- **Conntrack capacity telemetry:** `/v1/system/status.dataplane.conntrack`,
  `ngfwctl status`, Dashboard, and Readiness must expose live state-table usage
  versus `nf_conntrack_max`; elevated pressure is a production blocker for
  high-throughput or high-connection-churn profiles.

-----

## 9. TLS break-and-inspect — read before attempting (later/research) `[LOCKED guardrail]`

B&I was listed as "table stakes" in earlier notes. It is also one of the hardest and riskiest features, and a **structurally eroding** one: TLS 1.3, ECH/encrypted ClientHello, and certificate pinning increasingly defeat interception. Plus a MITM CA is a serious trust/security/legal artifact.

Therefore:

- **Do not** implement B&I in v1.
- Prefer **metadata-based** signals first (JA3/JA4(+) fingerprints, SNI where visible, DNS, cert metadata, flow behavior) — these degrade more gracefully.
- When/if B&I is built, it is a **human-supervised** effort (cert lifecycle, CA trust, performance, privacy/legal). An agent must not implement TLS interception or CA handling autonomously.

-----

## 10. Threat intelligence approach `[LOCKED]`

- **Integrate, don't rebuild.** Federate ET Open, abuse.ch (URLhaus/ThreatFox/SSLBL), Spamhaus, and **integrate CrowdSec** for crowdsourced blocklists. CrowdSec's value comes from *their* central consensus/anti-poisoning infrastructure — do not attempt to rebuild that.
- **Feed-license registry is mandatory** (M4): track redistribution, commercial-use, attribution, and privacy constraints per feed; enforcement must respect them.
- **Honeypot/first-party intel** (T-Pot) and **sandbox detonation** (CAPEv2) are *later/research*. In v1, expose only a pluggable **submit-to-sandbox interface** + local hash/file blocking — no detonation infra.
- Right-size expectations: a handful of honeypots is marginal signal; established feeds + CrowdSec carry v1.

-----

## 11. Guardrails for the coding agent `[LOCKED — copy into CLAUDE.md]`

**Stop and ask a human before:**

- Writing any inspection, routing, or crypto **engine** from scratch (you're off-plan — integrate instead).
- Touching **TLS interception, MITM CA, or any crypto implementation**.
- Writing **eBPF/XDP/tc** kernel code (security + GPL-license implications).
- Adding any **GPL/AGPL dependency** or changing the license-isolation boundary.
- Changing **network-exposed authentication** (OIDC/SAML), role mapping, or
  session handling without security review.
- Treating nDPI as the App-ID product or Suricata signatures as the Threat-ID product.
- Weakening the VM-Series-class virtual/cloud target or the no-open-core model.
- Anything that could **delete or overwrite live config** outside the candidate/commit safety path.
- Publishing or hard-coding any **performance/throughput claim** (must come from the §8 harness).
- Security disclosure / CVE handling.

**Always:**

- Keep engine integration as **separate processes**; generate native configs; never link engine code into Apache modules.
- Route every config change through **candidate → validate → commit → (rollback available)**.
- Surface validation impact before live apply in every client; high-risk
  candidates require explicit acknowledgement in both CLI and WebUI paths.
- Write **golden-file tests** for renderers and **integration tests** with real engines.
- Keep bypass, failed-open, failed-closed, partial-inspection, full-inspection,
  and degraded-engine behavior visible in policy and explanations.
- Add **DCO sign-off** to commits; no secrets in the repo; deterministic builds.
- Update **SBOM** when dependencies change.
- Prefer the **smallest correct thing** that advances the current milestone's DoD. Do not pull future-milestone scope forward.

-----

## 12. Coding conventions `[RECOMMENDED]`

- Go: standard layout, `golangci-lint`, table-driven tests.
- Conventional Commits + DCO `Signed-off-by`.
- API-first: change `.proto`, regenerate, then implement.
- Errors are explicit; no silent failures in the commit path.
- Every renderer is pure where possible: `(IR) -> (config bytes)`, easy to golden-test.
- Document *why* at decision points; the code shows *how*.

-----

## 13. Open questions `[OPEN]`

- Project name.
- Embedded store: SQLite vs BoltDB.
- Log store: ClickHouse vs OpenSearch.
- Policy validation: OPA/Rego vs Cedar.
- eBPF language (Go `cilium/ebpf` vs Rust `aya`) — defer to the eBPF milestone.
- Exact first wedge emphasis: K8s east-west vs cloud egress vs homelab (affects M4/M5 priorities).
- Foundation timing and which foundation.

-----

## 14. Engine reference (what each integration is for)

|Engine                       |Role                                                      |Integration                                |
|-----------------------------|----------------------------------------------------------|-------------------------------------------|
|nftables/conntrack           |Stateful L3/L4 dataplane, NAT (v1)                        |Render rulesets; manage via libnftables/CLI|
|Suricata                     |IDS/IPS, app-layer, JA3/JA4, file extraction, EVE JSON    |Separate process; consume EVE JSON         |
|nDPI                         |App/protocol visibility                                   |Separate process                           |
|FRRouting                    |BGP/OSPF/dynamic routing                                  |Separate daemons; config files/vtysh       |
|strongSwan                   |IPsec VPN                                                 |Separate process; swanctl                  |
|WireGuard                    |Modern VPN                                                |Kernel; wg/netlink                         |
|CrowdSec                     |Crowdsourced + curated blocklists                         |Integrate (MIT)                            |
|Vector                       |Log/telemetry shipping                                    |Config-driven pipeline                     |
|ClickHouse/OpenSearch        |Event/log store                                           |Sink for Vector                            |
|Zeek (optional)              |Network security monitoring / rich metadata               |Separate process                           |
|Envoy + Coraza (later)       |Reverse/forward proxy, WAF (OWASP CRS), API gateway, L7 LB|Separate process (Apache)                  |
|OpenZiti (later)             |ZTNA                                                      |Separate (Apache)                          |
|keepalived/conntrackd (later)|HA active/passive + state sync                            |Separate                                   |
|OpenSCAP/STIG (later)        |Hardening + compliance profiles                           |Profiles + scanning                        |
|OpenSSL FIPS provider        |FIPS-ready crypto                                         |Validated module; FIPS mode                |

-----

*End of build plan. Keep this file authoritative; propose changes via PR with rationale.*
