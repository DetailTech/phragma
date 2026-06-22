# Performance And Benchmarks

Phragma v1 is benchmarked against Palo Alto VM-Series-class cloud/virtual NGFW scenarios. It is not benchmarked against physical hardware flagship appliances.

## Benchmark Philosophy

- **HARD REQUIREMENT:** Performance claims must be reproducible.
- **HARD REQUIREMENT:** Benchmarking must include security services, not only L3 forwarding.
- **HARD REQUIREMENT:** The inspection tier is the expected bottleneck. Dataplane forwarding numbers alone do not prove NGFW readiness.
- **HARD REQUIREMENT:** Benchmarks must report whether flows were fully inspected, partially inspected, bypassed, decrypted, or not inspected.

## Benchmark Classes

Required benchmark profiles:

- L3/L4 forwarding without inspection.
- Stateful firewall allow/deny.
- NAT.
- Dynamic routing convergence impact.
- Mixed application traffic.
- TLS-heavy traffic without decryption.
- TLS-heavy traffic with decryption once decryption exists.
- IPS-heavy traffic with realistic rulesets.
- Small-packet traffic.
- Large-flow throughput.
- High connection churn.
- DNS-heavy traffic.
- HTTP/API/WAF traffic through Envoy/Coraza.
- Degraded-engine behavior.

## VM-Series-Class Comparison

Compare Phragma to VM-Series-class virtual firewall deployments by matching:

- Cloud provider.
- Instance size or closest CPU/memory class.
- NIC type and acceleration mode.
- Number of vCPUs dedicated to dataplane and inspection.
- Security services enabled.
- Traffic profile.
- Logging level.

Do not compare a minimal Phragma forwarding-only profile against a VM-Series profile with threat prevention enabled. Such comparisons are invalid.

## Inspection Scaling

The scaling design must account for:

- RSS/multi-queue behavior.
- CPU pinning.
- Flow affinity.
- Suricata worker scaling.
- nDPI/App-ID classifier cost.
- Envoy worker model.
- Backpressure.
- Fast-path bypass after classification where policy permits.
- Hold/drop/bypass behavior while waiting on classification.

**NON-NEGOTIABLE LINE IN THE SAND:** If inspection cannot scale, the product cannot claim NGFW parity, even if packet forwarding is fast.

## Fast Path And Bypass

Fast path is allowed only when policy permits it and the decision is visible.

Required states:

- fully inspected
- partially inspected
- bypassed by policy
- bypassed by engine health state
- failed open
- failed closed
- blocked before inspection

Silent bypass is a defect.

### nftables flowtable fast path

`network.enable_flow_offload` enables the current nftables compatibility
dataplane to install a `flowtable fastpath` for established forwarded flows.
This is useful for high-bandwidth L3/L4 forwarding and NAT profiles where the
policy does not require packet inspection on every packet.

Guardrails:

- The setting is explicit; Phragma must not enable it silently.
- Validation rejects it when IDS/IPS is enabled because offloaded packets can
  bypass inspection.
- Benchmark reports using this mode must label the inspection state as
  `not inspected` or an equally precise non-inspection state.
- Benchmark reports using this mode must include runtime evidence:
  `/v1/system/status` or `ngfwctl status` with
  `dataplane.flowtable.runtime_state`/`flowtable live` set to `active`,
  devices and counters when available, and an `nft list table inet openngfw`
  capture containing both `flowtable fastpath` and `flow add @fastpath`.
- This is not the strategic eBPF/XDP/tc dataplane milestone. It is the current
  Linux compatibility fast path behind the same policy and IR boundary.

### Host appliance tuning

`deploy/install.sh` installs `/etc/sysctl.d/99-openngfw.conf` and applies the
baseline forwarding and high-connection-count kernel settings. On an existing
host, `sudo ngfwctl system tune --write --apply` writes and applies the same
profile without reinstalling engines or the daemon:

- `net.ipv4.ip_forward = 1`
- `net.ipv4.conf.all.rp_filter = 0`
- `net.ipv4.conf.default.rp_filter = 0`
- `net.netfilter.nf_conntrack_max = 1048576`
- `net.core.somaxconn = 4096`

These values are not benchmark claims by themselves. They are the minimum host
posture expected before publishing forwarding or connection-rate evidence. The
API exposes the live check under `/v1/system/status.dataplane.kernel_tuning`;
`ngfwctl status` and the WebUI Readiness page surface the same state.
`ngfwctl system tune` without flags prints the exact profile and makes no
changes.

### eBPF/XDP/tc readiness gate

The strategic Linux/eBPF dataplane is not allowed to be a hidden assumption.
`/v1/system/status.dataplane.ebpf` reports host readiness before any future
XDP/tc program is attached. The readiness probes cover:

- `bpftool`
- `clang`
- `tc`
- `ip`
- kernel BTF at `/sys/kernel/btf/vmlinux`
- bpffs at `/sys/fs/bpf`
- cgroup v2 controller visibility at `/sys/fs/cgroup/cgroup.controllers`

`ngfwctl status` and the WebUI Readiness page show the same state and failed
probe names. A host with degraded eBPF readiness can still run the current
nftables/conntrack renderer, but it cannot be treated as ready for the
strategic XDP/tc dataplane milestone.

### Inspection readiness evidence

`/v1/system/status.inspection` is the canonical runtime posture for IDS/IPS
inspection. It binds the running policy's IDS/IPS mode and failure behavior to
the managed Suricata engine state, then reports one operator-readable state:
`disabled`, `ready`, `degraded`, `failed-open`, `failed-closed`, or `unknown`.

Benchmark and production-readiness evidence must use this object, `ngfwctl
status`, or the WebUI Readiness page to prove whether traffic was not
inspected, detect-only, IPS-prevented, failed open, or failed closed. Raw
Suricata process state alone is not sufficient because the same engine state
has different meaning depending on the running policy's fail behavior.

Benchmark summaries that claim inspected, bypassed, failed-open, or
failed-closed behavior must carry `inspection_evidence` from the measured
window. The verifier compares that object with `ngfwctl status` artifacts so a
summary cannot claim fully inspected prevention throughput when the captured
runtime posture says disabled, degraded, failed open, or failed closed.

## Failure-Mode Benchmarks

Required degraded states:

- control plane unavailable
- Suricata down
- nDPI/App-ID service down
- Envoy down
- FRR down
- log pipeline backpressure
- XDP unavailable
- invalid candidate commit
- rollback under traffic

For each degraded state, record:

- policy behavior
- flow impact
- log output
- explanation output
- recovery behavior

## Acceptance Gates

v1 cannot claim VM-Series-class credibility until it can:

- Install as a cloud/virtual appliance.
- Route and NAT traffic between zones.
- Enforce stateful policy.
- Run IDS/IPS in inline mode.
- Classify applications with evidence and confidence.
- Log and explain every flow decision.
- Survive engine failure according to explicit policy.
- Produce reproducible benchmark reports.

## Benchmark Harness

The v2-mixed branch carries the initial Linux benchmark harness in `perf/`.
Use `sudo make benchmark-netns-check` and `sudo make benchmark-netns` on a
single Linux host for fast local dataplane regression evidence through the real
`controld`/`ngfwctl` commit path and nftables renderer. Use
`make benchmark-check` and `make benchmark` for the full three-host cloud/lab
measurement. Both harnesses record raw `iperf3`, latency, churn, host facts,
`summary.json`, and `report.md` under `perf/results/`.
Local namespace runs also capture `ngfw-status.txt` before benchmark traffic,
`ngfw-status-active.txt` during the measured throughput run, and
`ngfw-status-final.txt` after throughput and churn traffic. Three-host runs
with `FW_HOST` set capture the equivalent `firewall-status.txt`,
`firewall-status-active.txt`, and `firewall-status-final.txt`. Summary
generation prefers active-load status, then final status, then initial status
so conntrack and flowtable evidence reflect the measured window when the CLI
exposes it. New summaries also copy policy-aware inspection posture into
`inspection_evidence`; inspected, bypassed, failed-open, and failed-closed
claims warn or fail strict release verification when that evidence is missing.

Every published throughput, latency, or connection-rate claim must come from a
result directory that follows `perf/report.schema.json` and passes
`make benchmark-verify` or `ngfwperf verify`. Use `ngfwperf verify --strict`
for release gates where non-canonical inspection-state labels should fail. A
number copied from a terminal is not product evidence. The netns harness is
acceptable for regression tracking, but not for cloud-NIC or VM-Series-class
throughput claims. Use `ngfwperf verify --strict --publishable` when preparing
numbers for release notes, external publication, or comparison; that gate fails
scoped local-regression, forwarding-only, failed-open, state-table-degraded, and
missing-evidence artifacts.

Release publication evidence is curated separately from engineering regression
history. `perf/results/` is the durable run archive and may contain local,
historical, or intentionally non-publishable artifacts. `perf/release-results/`
is the only input to `make benchmark-verify-release`; copy a run there only
when the result is intended for release notes or external comparison and passes
`ngfwperf verify --strict --publishable`. If `perf/release-results/` has no
`summary.json`, `make benchmark-verify-release` fails by default. A release may
skip publishable benchmark evidence only when the release is explicitly marked
as publishing no performance claims with `RELEASE_NO_PERFORMANCE_CLAIMS=1` and
the release acceptance manifest also declares `no_performance_claims: true`.
That exception is not a performance result; release notes, marketing copy, and
operator documentation for that tag must not cite throughput, latency, or
connection-rate claims.

Before citing a benchmark summary in release notes or external material, run
`make benchmark-citation-check` or `ngfwperf check-citations <file>`.
`make release-check-rootless` runs the Makefile target so release copy cannot
silently cite unpublishable benchmark artifacts. The check rejects concrete
`perf/results/.../summary.json` citations because that directory is an
engineering archive, not release evidence. Concrete
`perf/release-results/.../summary.json` citations must still load from disk and
pass the strict publishable gate; otherwise the cited claim is treated as
non-release-citable until the benchmark is repaired or removed from the copy.

Tagged releases also require a machine-readable acceptance manifest at
`release/acceptance.json`; see `docs/RELEASE_ACCEPTANCE.md`. The manifest must
record acceptance evidence for `release-benchmark`, or explicitly mark that
check `not_applicable` under no-performance-claims mode with a detail explaining
that no performance claims are being published.

The WebUI Performance page can locally inspect a `summary.json` artifact using
the same evidence contract. Operators can select a whole `perf/results/<run>`
directory and the page auto-loads `summary.json`, `iperf3.json`, the preferred
active/final status artifact, and nftables evidence when present. During an
active run, **Use live status** captures the current `/v1/system/status` posture
as status evidence without leaving the browser. It is an operator review
surface, not a place where benchmark artifacts are uploaded to the daemon.
Operators can also paste or load a second `summary.json` as a baseline and
compare it with the loaded candidate run. The comparison view computes
throughput, latency, and connection-rate deltas, labels regressions, and exports
a bounded redacted browser-local delta payload. That payload is an operator
review aid only: it does not retain cross-run trend history, record release
custody, or certify a comparison claim.
Summaries that include
inspected, bypassed, failed-open, or failed-closed claims should include
`inspection_evidence`, and summaries that include throughput or connection-rate
evidence should also include `conntrack_evidence`; strict release verification
treats missing inspection or state-table evidence as a gate failure. The page
also renders the same publication/use gate as `ngfwperf verify --publishable`
so operators can distinguish release-ready evidence from scoped
local-regression, forwarding-only, failed-open, or missing-evidence artifacts.

## Primary References

- Palo Alto Networks [VM-Series for public clouds](https://www.paloaltonetworks.com/network-security/vm-series-for-public-clouds).
- [Suricata documentation](https://docs.suricata.io/en/).
- [Cilium eBPF datapath documentation](https://docs.cilium.io/en/stable/network/ebpf/index.html).
- [Envoy xDS documentation](https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol.html).
