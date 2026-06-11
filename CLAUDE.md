# CLAUDE.md — OpenNGFW conventions & guardrails

The authoritative plan is [`docs/build-plan.md`](docs/build-plan.md). Read it
before making non-trivial changes. This file extracts what an agent (or human)
must follow on every change.

## The one thing to internalize

**The product is the control/policy plane.** We integrate and orchestrate
existing engines (nftables, Suricata, FRR, strongSwan, nDPI, …) — we never
rebuild them. Our code is the policy model, the compiler (policy → IR), the
per-engine renderers (IR → native config), the lifecycle supervisor, the API,
the CLI, and the telemetry pipeline.

## Current milestone

**M0–M5 v1 implementations are complete** (see `docs/testing-plan.md` for
what is machine-verified vs. pending human field testing). Remaining known
work before calling v1 done: OIDC implementation (needs human security
review — scaffold only), policy *editing* in the WebUI, the full React UI,
self-zone/input-chain hardening, GitOps reconciliation, and the §8
performance harness. Milestone order and scope stay locked in
`docs/build-plan.md` §7.

## Guardrails `[LOCKED]`

**Stop and ask a human before:**

- Writing any inspection, routing, or crypto **engine** from scratch (you're off-plan — integrate instead).
- Touching **TLS interception, MITM CA, or any crypto implementation**.
- Writing **eBPF/XDP** kernel code (security + GPL-license implications).
- Adding any **GPL/AGPL dependency** or changing the license-isolation boundary.
- Implementing **network-exposed authentication** (OIDC/SAML) beyond scaffolding without review.
- Anything that could **delete or overwrite live config** outside the candidate/commit safety path.
- Publishing or hard-coding any **performance/throughput claim** (must come from the §8 benchmark harness).
- Security disclosure / CVE handling.

**Always:**

- Keep engine integration as **separate processes**; generate native configs; never link engine code into Apache modules.
- Route every config change through **candidate → validate → commit → (rollback available)**.
- Write **golden-file tests** for renderers and **integration tests** with real engines.
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
