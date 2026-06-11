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

**M0–M5 v1 implementations are complete:**

- **M1** — zone-based stateful firewall: policy model, candidate →
  validate → commit → rollback, compiler → IR → nftables renderer,
  NAT, static routes, audit log, gRPC/REST/CLI.
- **M2** — Suricata IDS/IPS (detect + inline prevent) supervised through
  the commit path; Vector → ClickHouse telemetry; alerts via API/CLI.
- **M3** — FRR (BGP/OSPF), strongSwan IPsec, and WireGuard managed
  through the same policy model; secrets stay in operator-owned files.
- **M4** — threat-intel federation with a license-aware feed registry
  enforced at commit time; nftables blocklist sets; app-labeled flows.
- **M5** — local token auth + RBAC (viewer/operator/admin), audited
  actors, read-first web UI at /ui/. OIDC is scaffold-only pending
  security review.

Real-engine integration tests (`make integration-test`) prove filtering,
NAT, rollback, IDS detection, and intel enforcement against live traffic
in network namespaces. Field-test guide: [`docs/testing-plan.md`](docs/testing-plan.md).

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
