# Phragma Release Benchmark Evidence

Place only release-candidate benchmark result directories here. Every directory
used for release notes, external publication, or comparison must contain a
`summary.json` that passes:

```sh
ngfwperf verify --strict --publishable perf/release-results/<run>
```

The release gate reads this directory through `make benchmark-verify-release`.
Prefer staging from `perf/results/` with the guarded command:

```sh
make benchmark-stage-release BENCHMARK_RUN=perf/results/<run>
```

That command runs the strict publishable gate before copying the selected run
here and refuses to overwrite an existing release-evidence directory.
Missing release benchmark summaries fail the gate by default. The only supported
skip is an explicit no-performance-claims release:

```sh
RELEASE_NO_PERFORMANCE_CLAIMS=1 make benchmark-verify-release
```

Use that mode only when the tag publishes no throughput, latency,
connection-rate, or comparison claims. The tagged release acceptance manifest
must also set `no_performance_claims: true` and mark the `release-benchmark`
check `not_applicable` with a detail explaining that no performance claims are
published.

Do not copy local regression, forwarding-only, failed-open, or missing-evidence
runs into this directory. Keep engineering and historical benchmark artifacts
under `perf/results/`; those are validated by `make benchmark-verify` but are
not release publication claims.
