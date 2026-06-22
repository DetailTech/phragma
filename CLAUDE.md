# CLAUDE.md — Phragma conventions & guardrails

For v2-mixed, read the product definition before touching implementation:

1. [`docs/PROJECT_DEFINITION.md`](docs/PROJECT_DEFINITION.md)
2. [`docs/HARD_REQUIREMENTS.md`](docs/HARD_REQUIREMENTS.md)
3. [`docs/build-plan.md`](docs/build-plan.md)

If these documents conflict, `PROJECT_DEFINITION` and `HARD_REQUIREMENTS` win.
The build plan describes how the current DetailTech-derived implementation
advances the product, not a license to narrow the product ambition.

Naming rule: the public product name is **Phragma**. Do not rename module paths,
CLI binaries, schema IDs, service/config paths, nftables tables, or persisted
state from `openngfw`/`ngfwctl` in this branch unless the change includes a
reviewed compatibility and migration plan.

WebUI style rule: production UI work must follow the repo-local Phragma design
direction in `docs/webui-design.md`, `docs/GUI_RESEARCH.md`,
`docs/GUI_FEATURE_MATRIX.md`, and `docs/GUI_GAP_ANALYSIS.md`. The required
static assets live under `internal/webui/static/assets/`. The visible console
is Phragma: cold holographic dark cockpit, cyan for live/active controls,
strict firewall status colors, compact angular panels, and monospace for
machine evidence.

## The one thing to internalize

**Phragma is a real 100% open-source NGFW, not an engine wrapper.** We
integrate and orchestrate existing engines where that is the right engineering
choice, but Phragma owns the user-facing policy model, verdict model,
explanations, App-ID and Threat-ID product layers, audit model, API, CLI, UI,
and benchmark discipline.

nftables, Suricata, FRR, strongSwan, WireGuard, Vector, nDPI, and future
engines are replaceable implementation backends. They must not become the
product model.

## Current milestone

This branch starts from the DetailTech M0–M5 implementation and keeps it as the
runnable backend foundation. Do not describe the branch as VM-Series-class
product parity yet.

Known product gaps before v1 can be called credible under the stricter
definition: Linux/eBPF XDP/tc dataplane milestone, Phragma-owned App-ID and
Threat-ID layers, VM-Series-class benchmark harness, OIDC implementation after
security review, remaining WebUI coverage for routing/VPN/intel editing and
live system-resource telemetry, self-zone/input-chain hardening, GitOps
reconciliation, and complete failure-mode validation.

## Guardrails `[LOCKED]`

**Stop and ask a human before:**

- Writing any inspection, routing, or crypto **engine** from scratch (you're off-plan — integrate instead).
- Touching **TLS interception, MITM CA, or any crypto implementation**.
- Writing **eBPF/XDP** kernel code (security + GPL-license implications).
- Adding any **GPL/AGPL dependency** or changing the license-isolation boundary.
- Implementing **network-exposed authentication** (OIDC/SAML) beyond scaffolding without review.
- Treating nDPI output as the App-ID product, or Suricata signatures as the Threat-ID product.
- Weakening the VM-Series-class cloud/virtual target or the 100% open-source/no-paywall model.
- Anything that could **delete or overwrite live config** outside the candidate/commit safety path.
- Publishing or hard-coding any **performance/throughput claim** (must come from the §8 benchmark harness).
- Security disclosure / CVE handling.

**Always:**

- Keep engine integration as **separate processes**; generate native configs; never link engine code into Apache modules.
- Route every config change through **candidate → validate → commit → (rollback available)**.
- Write **golden-file tests** for renderers and **integration tests** with real engines.
- Keep bypass, failed-open, failed-closed, partial-inspection, and full-inspection behavior visible in policy and explanations.
- Add **DCO sign-off** to commits; no secrets in the repo; deterministic builds.
- Update **SBOM** when dependencies change (CI regenerates it; keep `go.mod` tidy).
- Prefer the **smallest correct thing** that advances the current milestone's DoD.

## Coding conventions

- Go, standard layout. `make build test lint` must pass before any commit.
- `golangci-lint` (config in `.golangci.yml`); table-driven tests.
- Conventional Commits + DCO `Signed-off-by` on every commit.
- **API-first:** change `.proto` under `api/proto/`, run `make proto`
  (regenerates `api/gen/`, which is committed), then implement. CI fails if
  generated code is stale (`make proto-verify`).
- Errors are explicit; no silent failures in the commit path.
- Renderers are pure where possible: `(IR) -> (config bytes)`, golden-testable.
- Document *why* at decision points; the code shows *how*.

## Build targets

| Target | What it does |
|---|---|
| `make build` | Build `controld` + `ngfwctl` into `bin/` with version ldflags |
| `make test` | `go test -race ./...` |
| `make lint` | `golangci-lint run` + `go vet` |
| `make proto` | Lint `.proto` files and regenerate `api/gen/` (pinned buf/protoc-gen-go) |
| `make proto-verify` | Fail if committed generated code is stale |

## Layout

See `docs/build-plan.md` §6 for the full target layout. Currently populated:

- `api/proto/` — canonical protobuf API; `api/gen/` — committed generated Go.
- `cmd/controld/`, `cmd/ngfwctl/` — entrypoints.
- `internal/version/`, `internal/apiserver/`, `internal/cli/`.
- `internal/policy|compiler|renderers|engines|store|telemetry|authz` arrive with M1+.
- `docs/PROJECT_DEFINITION.md`, `docs/HARD_REQUIREMENTS.md`, and `docs/adr/`
  are the imported product-definition and decision baseline for v2-mixed.
