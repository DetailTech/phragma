# OpenNGFW Performance Harness

The benchmark harness is the required source of truth for OpenNGFW throughput,
latency, connection churn, and inspection-cost claims. Ad hoc `iperf3` notes are
useful during debugging, but they are not product evidence unless captured here.

## Harnesses

OpenNGFW carries two benchmark harnesses:

- `perf/netns.sh`: single Linux host, two network namespaces, real product
  `controld` + `ngfwctl`, real nftables rules, and `iperf3` traffic through the
  host namespace acting as the firewall. This is the fastest repeatable smoke
  for forwarding-path performance and commit-path correctness.
- `perf/bench.sh`: three-host SSH harness for cloud or lab VMs. This is the
  required source for any cloud-NIC or VM-Series-class comparison.

## What The Remote Harness Measures

`perf/bench.sh` orchestrates a client VM, server VM, and optional firewall VM
over SSH. It records:

- TCP large-flow throughput from `iperf3 -J`.
- Packet latency from `ping`.
- Basic connection churn using `nc` when available.
- Client/server/firewall host facts.
- `ngfwctl status` from the firewall when `FW_HOST` is set.
- A machine-readable `summary.json` and human-readable `report.md`.

The harness does not configure OpenNGFW policy. The report describes the
currently running policy and the profile labels you provide.

## Quick Local Dataplane Benchmark

Run this on one Linux host with root, nftables, iproute2, iperf3, nc, curl,
python3, and built OpenNGFW binaries:

```sh
make build
sudo make benchmark-netns-check
sudo DURATION=30 PARALLEL=8 make benchmark-netns
```

The local netns harness:

- Creates client/server network namespaces connected through the root namespace.
- Starts `controld` without `--dry-run`.
- Commits a baseline forwarding policy through `ngfwctl`.
- Captures `ngfwctl policy validate`, `ngfwctl status`, and the live
  `nft list table inet openngfw` ruleset before and after the traffic run.
- Runs iperf3, ping, and connection churn through the firewall path.

Each run writes to `perf/results/<timestamp>-local-netns-forwarding/`.

Use this as release smoke evidence and regression tracking. Do not publish it as
a cloud throughput claim: it is a single-host namespace benchmark, not a NIC,
instance-shape, or multi-host data-path measurement.

The local netns harness owns the global `inet openngfw` nftables table for the
duration of the run. It refuses to run when `controld.service` is active or an
existing `inet openngfw` table is present. Use a disposable host. The
`ALLOW_EXISTING_OPENNGFW=1` override is only for intentional destructive lab
runs.

## Minimum Topology

Use three Linux VMs:

- `CLIENT_HOST`: sends benchmark traffic.
- `SERVER_HOST`: runs `iperf3 -s --one-off`.
- `FW_HOST`: optional, runs OpenNGFW and exposes `ngfwctl status`.

Traffic must pass through the firewall dataplane, not a cloud load balancer or
management path. In OCI this usually means client and server private subnet
routes point at the firewall VNIC private IPs, with source/destination check
disabled on the firewall VNICs.

For gdioc2 high-bandwidth testing, use SR-IOV/VFIO-capable shapes where
available. The previous clean baseline in this tenancy used 8-OCPU
`VM.Optimized3.Flex` hosts with local VCN routing.

## Preflight

```sh
export CLIENT_HOST=ubuntu@client
export SERVER_HOST=ubuntu@server
export FW_HOST=ubuntu@firewall
export TARGET_IP=10.0.2.20
export SSH_OPTS='-i ~/.ssh/openngfw-bench -o StrictHostKeyChecking=accept-new'
export FW_STATUS_CMD='NGFW_TOKEN=$NGFW_TOKEN ngfwctl status'

make benchmark-check
```

If you omit `CLIENT_HOST`, `SERVER_HOST`, or `FW_HOST`, preflight only checks the
local commands it can validate.

## Run

Forwarding-only profile:

```sh
export BENCH_PROFILE=forwarding-large-flow
export SECURITY_SERVICES=none
export INSPECTION_STATE=not-inspected
export DURATION=60
export PARALLEL=16

make benchmark
```

IDS detect profile:

```sh
export BENCH_PROFILE=ids-detect-large-flow
export SECURITY_SERVICES=suricata-detect
export INSPECTION_STATE=fully-inspected
export DURATION=60
export PARALLEL=16

make benchmark
```

Each run writes to `perf/results/<timestamp>-<profile>/`.

## Report Contract

Every result directory contains:

- `metadata.json`: run inputs and host labels.
- `summary.json`: normalized result fields, following
  `perf/report.schema.json`. New runs include `inspection_evidence`,
  `flowtable_evidence`, `conntrack_evidence`, and `host_tuning_evidence` from
  the active-load firewall status sample when available, then final status,
  then initial status, plus the captured nftables ruleset. This keeps
  inspection readiness, state-table pressure, and kernel forwarding/conntrack
  tuning tied to the measured window instead of only idle preflight state.
- `report.md`: concise human report.
- `iperf3.json`: raw iperf3 JSON output.
- `ping.txt`: raw ping output.
- `churn.txt`: connection churn output or skip reason.
- `client-facts.txt`, `server-facts.txt`, and optionally firewall facts/status
  before and after the traffic run.
- `firewall-status.txt`, `firewall-status-active.txt`, and
  `firewall-status-final.txt` in three-host runs with `FW_HOST` set: firewall
  posture before, during, and after benchmark traffic.
- `ngfw-status.txt`, `ngfw-status-active.txt`, and `ngfw-status-final.txt` in
  local netns runs: runtime posture before, during, and after benchmark
  traffic.
- `nft-openngfw-final.txt` in local netns runs: final ruleset counters after
  benchmark traffic.

Validate result evidence before citing it:

```sh
make benchmark-verify
./bin/ngfwperf verify --strict perf/results/<run>
./bin/ngfwperf verify --strict --publishable perf/results/<run>
```

`make benchmark-verify` checks every `summary.json` under `perf/results/`.
Strict mode also fails non-canonical inspection-state labels. Historical runs
may warn if they used older labels such as `forwarding-only`; new forwarding
runs should use `not-inspected`.
`--publishable` applies the same publication/use gate shown in the WebUI
Performance page and fails unless the artifact is suitable for scoped
publication or release use. Local namespace, forwarding-only, failed-open, and
missing-evidence artifacts remain useful for engineering, but they should fail
that gate.

Release signing uses a stricter curated path. `make benchmark-verify-release`
checks `perf/release-results/` only. Put a result directory there only when it
is intended for release notes, external publication, or comparison and already
has the evidence required by `ngfwperf verify --strict --publishable`. Prefer
the guarded staging command over a manual copy:

```sh
make benchmark-stage-release BENCHMARK_RUN=perf/results/<run>
make benchmark-verify-release
```

`benchmark-stage-release` validates the selected result with the strict
publishable gate before copying it into `perf/release-results/`, refuses to
overwrite existing staged evidence, and rejects local regression, forwarding-
only, failed-open, or missing-evidence artifacts. If `perf/release-results/`
contains no `summary.json`, the release gate fails by default. Use
`RELEASE_NO_PERFORMANCE_CLAIMS=1` only for a release that will publish no
throughput, latency, connection-rate, or comparison claims, and make the same
intent explicit in `release/acceptance.json` with `no_performance_claims: true`
and a `release-benchmark` check marked `not_applicable`. Do not move
regression-only artifacts from `perf/results/` into `perf/release-results/` to
make a release look faster.

When a `summary.json` sits beside raw `iperf3.json`, `ngfwperf verify` also
checks that the summary throughput, Gbps conversion, retransmit count, target,
duration, and stream count match the raw iperf artifact. Throughput summaries
without adjacent raw iperf evidence remain valid for old copied summaries, but
strict verification records that as a warning.
When status or nftables artifacts are present, the verifier also cross-checks
`inspection_evidence`, `host_tuning_evidence`, and `conntrack_evidence` against
`ngfw-status-active.txt`, `firewall-status-active.txt`, or the final/initial
status fallback, and `flowtable_evidence` against both status and
`nft-openngfw-final.txt`. A raw artifact that contradicts the summary is a hard
verification error.

The WebUI Performance page applies the same browser-side checks when you load
`summary.json`, `iperf3.json`, a status artifact, and an nftables artifact; the
files stay local in the browser and are not uploaded to `controld`.

## Publication Rules

Do not publish or compare a result unless the report includes:

- Cloud/region and instance shape.
- NIC mode and MTU.
- OpenNGFW commit.
- Policy profile.
- Security services enabled.
- Inspection state: fully inspected, partially inspected, bypassed,
  failed-open, failed-closed, or not inspected.
- Inspection readiness evidence: active-load `ngfwctl status` or equivalent
  captured as `inspection_evidence` for inspected, bypassed, failed-open, and
  failed-closed claims.
- Host tuning evidence: active-load `ngfwctl status` or equivalent captured as
  `host_tuning_evidence`, with `kernel tuning: ready` for high-bandwidth and
  connection-rate claims.
- State-table capacity evidence: active-load `ngfwctl status` or equivalent
  captured as `conntrack_evidence` for throughput or connection-rate claims.
- For `network.enable_flow_offload` profiles: `ngfwctl status` showing
  `flowtable live: active` and an `nft list table inet openngfw` capture with
  both `flowtable fastpath` and `flow add @fastpath`.
- Full result directory, not only the throughput number.

Never compare forwarding-only OpenNGFW throughput to a VM-Series profile with
threat prevention enabled. That is not a valid comparison.
