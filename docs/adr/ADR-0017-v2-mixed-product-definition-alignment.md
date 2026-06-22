# ADR-0017: Align v2-mixed With The Phragma Product Definition

**Status:** Accepted

## Context

The v2-mixed branch starts from the DetailTech implementation, which contains
substantial working progress: protobuf/gRPC APIs, candidate/commit/rollback,
engine renderers, nftables integration, Suricata integration, routing and VPN
renderers, threat-intel enforcement, RBAC scaffolding, a management WebUI, and
Linux integration tests.

The local Phragma plan defines a stricter product target: a 100% open-source
NGFW for cloud and virtual environments that can credibly target VM-Series-class
capability. It also requires Phragma to own the policy model, verdicts,
explanations, App-ID and Threat-ID product layers, benchmark discipline, and
future Linux/eBPF XDP/tc dataplane direction.

## Decision

Use the DetailTech implementation as the v2-mixed runnable baseline, but make
`docs/PROJECT_DEFINITION.md` and `docs/HARD_REQUIREMENTS.md` the controlling
product documents.

The current nftables renderer remains valid implementation progress and the
compatibility/fallback dataplane path. It does not replace the required
Linux/eBPF XDP/tc dataplane milestone.

nDPI-derived labels remain signal. They do not constitute the Phragma App-ID
product. Suricata remains the v1 matching engine. It does not constitute the
Phragma Threat-ID product.

## Consequences

**Good:**

- Keeps a working codebase instead of restarting from the older lab snapshot.
- Preserves real engine integration and integration-test progress.
- Prevents the project from narrowing into an engine wrapper or a simple
  nftables/nDPI control plane.
- Gives future agents a clear conflict-resolution rule for docs and code.

**Bad:**

- Some current implementation docs describe completed milestones that are only
  foundational under the stricter product definition.
- Future work must reconcile the existing protobuf/API surface with App-ID,
  Threat-ID, eBPF/tc, and benchmark requirements without breaking the runnable
  baseline unnecessarily.

## Alternatives Considered

**Use DetailTech main unchanged.** Rejected because it narrows App-ID, Threat-ID,
and dataplane ambition below the local Phragma hard requirements.

**Restart from the local lab snapshot.** Rejected because the DetailTech branch
contains deeper real-engine progress and a fuller management UI.

**Immediately rewrite toward eBPF and first-party App-ID.** Rejected for this
branch because the safer first step is to preserve the working baseline, lock
the product guardrails, and then implement those milestones deliberately.
