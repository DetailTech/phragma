# OpenNGFW — Build Plan (Claude Code Handoff)

> **Working name:** `OpenNGFW` (placeholder; rename freely, but use ONE consistent module prefix everywhere).
> **Audience:** AI coding agents (Claude Code) and human contributors.
> **Status:** v1.0 build plan. This is a *decisive* document — not a brainstorm. Where it says LOCKED, do not change without a human decision. Where it says OPEN, you have latitude.

**This document deliberately differs from earlier "exploratory" planning.** Earlier notes were intentionally non-prescriptive for human discussion. A coding agent needs the opposite: firm decisions, bounded scope, and explicit acceptance criteria. Treat this file as authoritative.

-----

## 0. Read this first — the one thing to internalize

**The product is the control/policy plane, not the firewall engines and not the datapath.**

The open-source world already has excellent inspection, routing, VPN, and proxy engines (Suricata, FRR, strongSwan, nDPI, Envoy). What it lacks — and the reason pfSense/OPNsense/VyOS aren't taken seriously at enterprise — is a unified, declarative, version-controlled, GitOps-friendly **management plane** with great DX.

So: **you integrate and orchestrate existing engines. You do not rebuild them.** Your code is the policy model, the compiler that renders that model into each engine's native config, the lifecycle supervisor, the API, the CLI, the telemetry pipeline, and (later) the UI.

If you find yourself writing a packet-inspection engine, a routing daemon, or a TLS stack from scratch — **stop and ask a human.** You are off-plan.

-----

## 1. Scope discipline (the hard part)

The vision is large. The *build* must be small and concrete. Scope is tracked as a ledger, not a wish list.

### v1 (build now)

Single-node, cloud-deployable firewall with a real control plane:

- Stateful L3/L4 zone-based firewall (nftables/conntrack renderer)
- NAT (source/dest/static), static routes
- Declarative policy model + candidate/commit/rollback
- gRPC + REST API
- CLI
- IDS/IPS via Suricata (integration, not reimplementation)
- Structured logging + telemetry pipeline
- Dynamic routing (FRR) + IPsec (strongSwan) + WireGuard
- App/protocol **visibility** via nDPI (NOT "App-ID competitive with Palo")
- Threat-intel feed enforcement (CrowdSec + federated feeds) with a feed-license registry
- Local SAML/OIDC auth, local RBAC, complete local audit log
- Read-first WebUI, then policy editing
- Supply-chain hygiene from commit #1 (SBOM, signing, DCO)

### Eventual (designed-for, built later)

HA active/passive (keepalived/conntrackd), L7 (Envoy + Coraza WAF/proxy/API-gateway/LB), ZTNA (OpenZiti), DNS security, full single-node feature parity, fleet management (multi-node control plane), SSO federation/SCIM, compliance evidence/reporting, eBPF/XDP datapath renderer.

### Later / research

TLS break-and-inspect (see §9 — this is hard and an *eroding* capability), sandboxing/detonation (pluggable interface only in v1), honeypot-sourced intel, active/active HA, VPP/DPDK datapath, multi-tenancy orchestration, AI/LLM prompt security.

### Explicit non-goals

- **Not** competing with Palo's entire surface area. Win the cloud-native wedge first.
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
|Datapath     |nftables/conntrack first → eBPF/XDP second → VPP deferred. (See §5.)                                                                                                                                                                                                                 |

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
|eBPF datapath (later milestone)                 |Go (`cilium/ebpf`) or Rust (`aya`) `[OPEN]`                                 |Decide when the eBPF renderer milestone starts, not now.                                           |
|API contract                                    |**Protobuf + gRPC** canonical; REST via grpc-gateway; OpenAPI generated     |Single source of truth for the model.                                                              |
|Config/state store                              |**SQLite or BoltDB** embedded (single-node) `[OPEN between the two]`        |Candidate/commit maps to versioned records. Git-backed reconciliation layered on top.              |
|Higher-level policy validation                  |OPA/Rego or Cedar `[OPEN]`                                                  |Management-plane validation only — NEVER in the fast path.                                         |
|Telemetry/log shipping                          |**Vector**                                                                  |Collects Suricata EVE JSON + system logs.                                                          |
|Log/event store                                 |**ClickHouse** (default) or OpenSearch `[OPEN]`                             |ClickHouse preferred for volume/cost.                                                              |
|CLI                                             |Go + Cobra                                                                  |—                                                                                                  |
|WebUI (later)                                   |React + TypeScript                                                          |Read-first, then editing.                                                                          |
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

**Why nftables first (not eBPF):**

- It is a correct, mature, fully *stateful* firewall today (conntrack, NAT) with stable tooling.
- It lets you build and prove the **entire control plane → compiler → renderer → dataplane loop** — the actual product — without months of kernel datapath engineering.
- It is agent-tractable: rendering a declarative model to an nftables ruleset is a well-bounded codegen problem with golden-file tests.
- It avoids the eBPF-GPL/Apache entanglement at the start.
- nftables/conntrack is what large production Linux firewalls already run — it is not a toy.

**Throughput framing (so nobody panics):** For an NGFW the datapath is *not* the throughput ceiling — the **userspace inspection tier (Suricata/nDPI) is**, and it is CPU-bound regardless of datapath. Forwarding throughput targets (10–40 Gbps) are reachable; threat-prevention throughput is a fraction of that and bounded by inspection. **Benchmark against Palo VM-Series (software), not hardware flagships.** Never assert a throughput number you have not measured (see §10).

**Roadmap:**

1. **nftables/conntrack** — v1.
1. **eBPF/XDP** — a *second renderer* behind the same policy model, added only once benchmarks show nftables is the bottleneck for the target deployment. Focus its design effort on the inspection-tier scaling problem (flow steering via RSS/AF_XDP, multi-core Suricata, fast-path bypass so DPI only sees flows that need it).
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
  /authz/             # local RBAC, OIDC/SAML, audit log
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
- gRPC API + REST gateway + CLI (`ngfwctl policy ...`, `commit`, `rollback`, `show`).
- **DoD:** Author a policy in YAML, push via CLI/API, traffic is filtered/NATed correctly, `commit` is atomic, `rollback` restores prior state, every change is in the audit log. Golden-file tests cover policy→nftables rendering.

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

### M4 — App/protocol visibility + threat intel

- nDPI integration for app/protocol **visibility** (label flows/logs; optional policy match). Explicitly NOT "App-ID parity."
- CrowdSec integration + federated feeds (ET Open, abuse.ch, Spamhaus) enforced as blocklists.
- **Feed-license registry:** every feed records redistribution/commercial-use/attribution/privacy constraints; enforcement respects them.
- **DoD:** Flows show app/protocol labels in logs; a blocklist feed is enforced and toggleable; the feed registry blocks enabling a feed whose license forbids the intended use.

### M5 — AuthN/Z + WebUI

- Local SAML/OIDC login (single node), local RBAC, complete audit log surfaced.
- WebUI: read-first (dashboards, logs, policy view), then policy editing through the candidate/commit workflow.
- **DoD:** A user logs in via OIDC, role-gated actions enforced, full single-node management achievable via UI, all UI changes flow through candidate/commit and appear in the audit log.

### M6+ — Eventual (separate planning when reached)

HA active/passive (keepalived/conntrackd), L7 (Envoy+Coraza), ZTNA (OpenZiti), DNS security, eBPF/XDP renderer, fleet management, SSO federation/SCIM, compliance evidence. Each gets its own mini-plan and DoD.

-----

## 8. Testing & validation `[LOCKED]`

- **Unit:** policy model, compiler, validation.
- **Golden-file:** every renderer (policy/IR → engine config) has golden tests. Renderer changes must show diffs and be reviewed.
- **Integration:** real engines in containers, real traffic (e.g. via network namespaces / scapy / iperf), asserting end-to-end behavior — not mocks.
- **E2E "10-minute install":** an automated test that stands up a single node from scratch in a clean cloud VM / container and reaches a working filtered state. This is a *product requirement*, treat its failure as a release blocker.
- **Performance harness:** repeatable benchmarks for forwarding throughput, threat-prevention throughput, connection rate, and latency. **All performance claims must come from this harness. Never assert a number you didn't measure.**

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
- Writing **eBPF/XDP** kernel code (security + GPL-license implications).
- Adding any **GPL/AGPL dependency** or changing the license-isolation boundary.
- Implementing **network-exposed authentication** (OIDC/SAML) beyond scaffolding without review.
- Anything that could **delete or overwrite live config** outside the candidate/commit safety path.
- Publishing or hard-coding any **performance/throughput claim** (must come from the §8 harness).
- Security disclosure / CVE handling.

**Always:**

- Keep engine integration as **separate processes**; generate native configs; never link engine code into Apache modules.
- Route every config change through **candidate → validate → commit → (rollback available)**.
- Write **golden-file tests** for renderers and **integration tests** with real engines.
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
