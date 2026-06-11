# Contributing to OpenNGFW

Thanks for your interest! Start with [`docs/build-plan.md`](docs/build-plan.md)
— it is the authoritative scope and architecture document — and
[`CLAUDE.md`](CLAUDE.md) for day-to-day conventions.

## Developer Certificate of Origin (DCO)

This project uses the [DCO](https://developercertificate.org/), not a CLA.
Every commit must carry a `Signed-off-by` line matching the commit author:

```
git commit -s
```

CI rejects pull requests containing commits without sign-off.

## License

All contributions are accepted under [Apache-2.0](LICENSE). Do not add
GPL/AGPL **code dependencies** to this repository; GPL-licensed engines
(Suricata, FRR, strongSwan, …) are integrated strictly as separate processes
(see `docs/build-plan.md` §4).

## Workflow

1. Branch from `main`; use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, …).
2. `make build test lint` must pass locally.
3. If you change `.proto` files, run `make proto` and commit the regenerated `api/gen/`.
4. Renderer changes require golden-file test updates; the diff is part of the review.
5. Open a PR with a clear rationale. Changes to LOCKED decisions in the build plan need an explicit human decision, not just a PR.
