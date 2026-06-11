# OpenNGFW

An open-source, cloud-native next-generation firewall — built as a
**control/policy plane** that integrates and orchestrates proven engines
(nftables, Suricata, FRR, strongSwan, nDPI, …) rather than rebuilding them.

- Declarative policy model with **candidate → validate → commit → rollback**
- Canonical **gRPC API** (REST gateway to follow), CLI-first
- GitOps-friendly, 100% Apache-2.0, DCO contributions
- Supply-chain hygiene from commit #1: SBOM, signed releases, SLSA provenance

**Read [`docs/build-plan.md`](docs/build-plan.md)** — the authoritative scope,
architecture, and milestone plan. Conventions for contributors and coding
agents live in [`CLAUDE.md`](CLAUDE.md).

## Status

**M0 — Foundation.** Scaffolding: build/CI pipeline, canonical API skeleton,
`controld` (control-plane daemon) and `ngfwctl` (CLI) that build, run, and
report version. The policy model, compiler, nftables renderer, and
candidate/commit store land in **M1**.

## Quick start (development)

Requires Go ≥ 1.25 and [golangci-lint](https://golangci-lint.run/) v2.

```sh
make build test lint    # build bin/{controld,ngfwctl}, race tests, lint
./bin/controld --version
./bin/controld &        # serves gRPC on 127.0.0.1:9443
./bin/ngfwctl version --server 127.0.0.1:9443
```

API changes are proto-first: edit `api/proto/`, run `make proto`, commit the
regenerated `api/gen/`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Commits require DCO sign-off
(`git commit -s`) and Conventional Commit messages. Security reports: see
[SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
