# Phragma

Phragma is a 100% open-source next-generation firewall effort for cloud and
virtual environments. The v2-mixed branch starts from the working
DetailTech implementation, but the canonical product definition is the stricter
Phragma plan in [`docs/PROJECT_DEFINITION.md`](docs/PROJECT_DEFINITION.md) and
[`docs/HARD_REQUIREMENTS.md`](docs/HARD_REQUIREMENTS.md).

Product naming note: the public product, docs, and WebUI name is **Phragma**.
For this first v2-mixed branch, compatibility identifiers such as Go module
paths, binaries, schema IDs, service/config paths, nftables table names, and
tests may still use `openngfw` or `ngfwctl` until a deliberate migration plan
renames them without breaking the runnable baseline.

The current code is a real control/policy-plane foundation that integrates and
orchestrates proven engines (nftables, Suricata, FRR, strongSwan, WireGuard,
Vector, and related services). That foundation is not the final product
boundary: Phragma owns the policy model, verdicts, explanations, App-ID and
Threat-ID product layers, audit model, API, CLI, UI, and benchmark discipline.

- Declarative policy model with **candidate → validate → commit → rollback**
- Canonical **gRPC API** with REST gateway, CLI, and WebUI clients
- GitOps-friendly, 100% Apache-2.0 first-party code, DCO contributions
- Supply-chain hygiene from commit #1: SBOM, signed releases, SLSA provenance

Read order for contributors and coding agents:

1. [`docs/PROJECT_DEFINITION.md`](docs/PROJECT_DEFINITION.md) — product target
   and non-negotiable project model.
2. [`docs/HARD_REQUIREMENTS.md`](docs/HARD_REQUIREMENTS.md) — constraints that
   override implementation convenience.
3. [`docs/build-plan.md`](docs/build-plan.md) — current implementation plan,
   reconciled with the stricter product definition.
4. [`CLAUDE.md`](CLAUDE.md) — day-to-day agent and contributor guardrails.
5. [`docs/CURRENT_PROGRESS.md`](docs/CURRENT_PROGRESS.md) — move-safe handoff,
   current validation state, and continuation notes.

## Status

**v2-mixed baseline: DetailTech M0–M5 foundation is present, but product parity
is not complete.**

- **M1** — zone-based stateful firewall: policy model, candidate →
  validate → commit → rollback, compiler → IR → nftables renderer,
  NAT, static routes, live conntrack session visibility, host-input appliance
  hardening, audit log, gRPC/REST/CLI.
- **M2** — Suricata IDS/IPS (detect + inline prevent) supervised through
  the commit path; Vector → ClickHouse telemetry; alerts via API/CLI.
- **M3** — FRR (BGP/OSPF), strongSwan IPsec, and WireGuard managed
  through the same policy model; secrets stay in operator-owned files.
- **M4** — threat-intel federation with a license-aware feed registry
  enforced at commit time; nftables blocklist sets; app-labeled flows.
- **M5** — local token auth, browser OIDC SSO, RBAC
  (viewer/operator/admin), audited actors, and a full management web UI at
  `/ui/` with HTTPS by default:
  guided setup, dashboard charts, rules/objects editing through candidate → validate →
  commit, threat and traffic pivots, telemetry export settings, dataplane
  controls, live sessions, command palette, version/audit history, and the
  Phragma design-system shell with local logomark, wordmark, and self-hosted
  console fonts. See
  [`docs/webui-design.md`](docs/webui-design.md).

This is valuable progress, not a waiver of the harder Phragma requirements.
In v2-mixed:

- nftables/conntrack is the current real Linux renderer and compatibility path;
  Linux/eBPF with XDP/tc remains a required strategic dataplane milestone.
- nDPI-style app labels are signal, not the App-ID product.
- Suricata is the v1 matching engine, not the Threat-ID product.
- VM-Series-class cloud/virtual benchmark discipline remains the target.

Real-engine integration tests (`make integration-test`) exercise filtering,
NAT, rollback, IDS detection, and intel enforcement against live traffic in
network namespaces. On macOS, treat those as Linux-root field tests requiring
`nft`, `ip`, `nc`, and optional Suricata; see
[`docs/testing-plan.md`](docs/testing-plan.md).

CLI commits and rollbacks run the same validation and runtime-readiness
preflights as the WebUI. They print the server-side impact summary plus
runtime posture before applying, and both commands require `--message/-m` so
the audit log records operator intent. The API also rejects commit and rollback
requests without a non-empty audit comment, and it rejects high-risk commit or
rollback impact unless the request sets `ack_risk`. The CLI maps that to
`--ack-risk`; dry-run, degraded, or unavailable runtime posture requires
`--ack-runtime` so headless operators cannot skip review by accident.

## Quick start (development)

Requires Go ≥ 1.25.11 and [golangci-lint](https://golangci-lint.run/) v2. The
patch-level floor is intentional so local builds and CI include the supported
Go 1.25 security fixes; Go 1.26 builds must use 1.26.4 or newer.

```sh
make build test lint    # build bin/{controld,ngfwctl}, race tests, lint
make vuln-check         # reachable Go vulnerability scan (pinned scanner)
make e2e-install-check  # non-destructive 10-minute install harness check
./bin/controld --version
./bin/controld --dry-run --allow-unauthenticated-local \
  --data-dir /tmp/phragma-dev --log-dir /tmp/phragma-dev-log &
./bin/ngfwctl version --server 127.0.0.1:9443
```

For a Linux firewall VM, `sudo deploy/install.sh` installs the engine packages,
systemd unit, local API user file, root-readable admin token file at
`/etc/openngfw/admin.token`, and `/etc/sysctl.d/99-openngfw.conf` appliance
baseline. New installs store only `token_hash: sha256:<digest>` entries in
`/etc/openngfw/users.yaml`; existing plaintext `token:` files remain readable
for compatibility but should be rotated. The installer does not print generated
admin tokens; retrieve the first-run token with
`sudo cat /etc/openngfw/admin.token` when you need to export `NGFW_TOKEN`, or
point `ngfwctl` at an operator-readable secret with `--token-file` or
`NGFW_TOKEN_FILE`. `--token-stdin` is also available for secret-manager pipes.
If Vector is not already installed, the installer warns and
continues; install Vector through an approved package manager or pinned,
checksum-verified release artifact before enabling telemetry export. On
installed hosts, `controld.service` uses a strict systemd sandbox: state, logs,
and local config are root-only, home directories are hidden from the service,
and only `/var/lib/openngfw`, `/var/log/openngfw`, `/etc/openngfw`, plus
FRR/swanctl engine drop-in directories are writable. Keep operator-provided
service material under `/etc/openngfw`, not under `/root` or user home
directories. For already-provisioned hosts,
`sudo ngfwctl system tune --write --apply`
installs and applies the same forwarding/conntrack sysctl baseline without
re-running the full installer. `ngfwctl status` and the WebUI Readiness page
report the live kernel forwarding/conntrack tuning state. `ngfwctl sessions` and the Traffic
Sessions view report the live Linux conntrack table for forwarding and
flowtable profiles where IDS flow records may be absent. The same status path
also reports conntrack state-table usage versus `nf_conntrack_max`, so
high-churn or benchmark runs expose capacity pressure before the table fills.
For high-bandwidth or high-connection-churn hosts, install or retune with
`OPENNGFW_TUNE_PROFILE=throughput sudo deploy/install.sh` or
`sudo ngfwctl system tune --profile throughput --write --apply` to raise
conntrack, listen backlog, and device backlog headroom before benchmarking.
`ngfwctl support-bundle` exports the same read-only diagnostic evidence as the
WebUI Readiness bundle for headless support and benchmark review, including
candidate validation and impact when a staged policy exists. Both bundle paths
redact token, password, secret, authorization, cookie, API-key, private-key, and
PSK fields, URL userinfo, and sensitive URL query values before writing JSON.
Telemetry ClickHouse endpoints must be credential-free policy values:
`clickhouse_url` rejects URL userinfo and token/password/secret/key-style query
parameters, and the rendered `vector.yaml` is written service-private (`0600`).

For first-run headless setup, stage a reviewable two-zone baseline instead of
hand-authoring YAML:

```sh
ngfwctl policy baseline \
  --profile throughput \
  --inside-interface ens5 \
  --outside-interface ens4 \
  --inside-cidr 10.0.2.0/24
ngfwctl policy validate
ngfwctl policy diff
ngfwctl commit --ack-risk -m "initial baseline"
```

If `ngfwctl commit` reports runtime readiness warnings, resolve them or repeat
the command with `--ack-runtime` after reviewing the warning text.

The baseline command creates ordinary candidate policy objects: zones, inside
address, SSH/WebUI services, logged outbound allow, optional masquerade SNAT,
host-input default deny with an inside management allow, flowtable fast path,
and MSS clamping. Use flags such as `--flow-offload=false`,
`--harden-host-input=false`, `--masquerade=false`, or `--mtu 9000` to match the
host before validation and commit.

The same command can stage inspected baselines without hand-editing YAML:

```sh
ngfwctl policy baseline --profile ids-detect \
  --inside-interface ens5 --outside-interface ens4 --inside-cidr 10.0.2.0/24

ngfwctl policy baseline --profile ips-prevent \
  --inside-interface ens5 --outside-interface ens4 --inside-cidr 10.0.2.0/24 \
  --ids-failure-behavior fail-closed --ids-queue 0
```

`throughput` keeps IDS/IPS disabled and can use nftables flowtable acceleration.
`ids-detect` and `ips-prevent` enable the existing IDS/IPS policy model, set
HOME_NET/rule-file defaults, and force flowtable acceleration off because
inspection profiles must not bypass packet inspection.
`ngfwctl policy diff` compares the staged candidate to the running policy by
default, or to a historical policy with `--from version --version N`.

For ongoing network posture changes, browser Settings and headless operators
share the same candidate workflow:

```sh
ngfwctl policy network profile throughput   # jumbo MTU + flowtable, IDS/IPS off
ngfwctl policy network profile inspection   # Suricata-safe offload posture
ngfwctl policy network profile edge-vpn     # conservative WAN/tunnel posture
```

The profile command never commits directly. It stages global MTU, MSS clamping,
NIC-offload management, and nftables flowtable posture while preserving
per-interface MTU overrides; use `ngfwctl policy network set` for manual
overrides.

The loopback WebUI/API listener uses a generated self-signed HTTPS certificate
by default. Browse `https://127.0.0.1:8080/ui/` and accept or locally trust that
certificate, or pass `--tls=false` for loopback cleartext debugging only.
Non-loopback listeners require `--tls-cert` and `--tls-key` by default. A
temporary test lab may explicitly acknowledge generated self-signed TLS with
`--allow-public-self-signed-tls`. That acknowledged posture is recorded in the
startup log and does not by itself make runtime status degraded or critical;
authentication remains required, and an operator-provided certificate is still
required for production.
For browser first-run setup, open **Guided setup** to stage a two-zone
throughput, IDS detect, or IPS prevent baseline through the same candidate
review and commit path. When runtime status is available, Guided setup lists
host interfaces from `/v1/system/status` so operators can assign inside and
outside NICs without typing names by hand; manual entry remains available for
offline policy staging. The same view also shows host sysctl baseline and
throughput state-table headroom from `/v1/system/status`, with guarded actions
that call `/v1/system/tune` for the appliance or throughput profile when the
daemon is enforcing rather than dry-run.

Packet capture follows the same API-first operations model. Plan a bounded
capture without touching the host, then start it only with an explicit
acknowledgement:

```sh
ngfwctl system capture --interface ens5 --protocol tcp \
  --src 10.0.1.20 --sport 51515 --dst 10.0.2.20 --dport 443

ngfwctl system capture --start --ack-capture --interface ens5 --protocol tcp \
  --src 10.0.1.20 --sport 51515 --dst 10.0.2.20 --dport 443 \
  --duration 20 --packets 500 --snaplen 256 --label incident-42
```

The server enforces admin RBAC, dry-run refusal, source/destination scope for
starts, duration/packet/snaplen limits, and audit logging. The printed command
is for break-glass/manual validation; API execution does not evaluate it
through a shell.

Production access should enable at least one auth source. Local API tokens use
`--users-file <chmod-600 YAML>` for CLI and automation. Browser SSO can be
enabled with OIDC:

```sh
./bin/controld \
  --users-file /etc/openngfw/users.yaml \
  --oidc-issuer https://idp.example.com/realms/openngfw \
  --oidc-client-id openngfw \
  --oidc-client-secret-file /etc/openngfw/oidc-client-secret \
  --oidc-redirect-url https://fw.example.com/v1/auth/oidc/callback
```

OIDC sessions are server-side and carried by an HTTP-only SameSite cookie; API
tokens remain bearer tokens for non-browser clients. Browser mutations made with
the OIDC cookie must also pass same-origin checks and the per-session
`X-Phragma-CSRF` token returned by `/v1/auth/oidc/status`; bearer-token clients
do not use that browser CSRF header. Use an `https://` `--oidc-redirect-url` for
production browser SSO. The browser session cookie is marked `Secure` from that
public redirect URL, so TLS-terminating reverse proxies are supported even when
the backend REST/WebUI listener is loopback cleartext; non-HTTPS OIDC redirects
are loopback-development only and appear as a critical readiness warning. If an
authenticated WebUI route is opened without a valid session or token, the UI
shows an in-place access panel with OIDC sign-in when configured plus local-token
verification.
Starting `controld` without `--users-file` or OIDC is rejected by default.
For isolated demos only, pass `--allow-unauthenticated-local --dry-run` with
loopback-only `--listen` and `--http-listen`; enforcing mode and wildcard
management binds are refused.
Generated self-signed TLS on a non-loopback REST/WebUI listener is likewise
refused unless `--allow-public-self-signed-tls` is explicit. That acknowledgement
provides encryption but not public CA trust or a guaranteed SAN for the public
endpoint. Use a controlled lab path such as an SSH tunnel or explicit browser
exception, and replace the certificate before production.
The direct gRPC listener is loopback-only in this branch because `ngfwctl` uses
local bearer-token gRPC without transport security. Expose remote management
through the HTTPS WebUI/REST gateway until gRPC TLS/mTLS is implemented.
Audit entries are hash-chained and can be verified through the API, WebUI Audit
tab, or `ngfwctl audit verify`; `ngfwctl audit --hashes` prints shortened entry
and previous hashes for external review.
REST/WebUI/OIDC and direct gRPC requests are rate-limited per client by default
(`--rate-limit-rpm 600 --rate-limit-burst 120`); set
`--rate-limit-rpm 0` only for isolated debugging. REST/WebUI rate limiting keys
clients by socket peer unless the request comes from a CIDR listed in
`--trusted-proxy-cidrs`, in which case the rightmost untrusted valid
`X-Forwarded-For` address is used. The same trusted proxy CIDRs gate
`X-Forwarded-Proto` for OIDC browser CSRF checks when TLS terminates before the
gateway. Configure that flag when placing the gateway behind a reverse proxy or
non-source-preserving load balancer, and configure the proxy to strip or
overwrite untrusted inbound forwarding headers before adding the real client
address and public scheme. Management listeners also ship with
explicit request-size and timeout guardrails:
`--http-max-body-bytes 10485760`, `--http-max-header-bytes 1048576`,
`--grpc-max-recv-bytes 16777216`, and `--grpc-max-send-bytes 16777216`.

API changes are proto-first: edit `api/proto/`, run `make proto`, commit the
regenerated `api/gen/`.

## Product Definition Map

- [Project Definition](docs/PROJECT_DEFINITION.md): mission, target, v1 scope,
  and lines in the sand.
- [Hard Requirements](docs/HARD_REQUIREMENTS.md): constraints that override
  implementation shortcuts.
- [Architecture](docs/ARCHITECTURE.md): target control plane, dataplane,
  inspection, verdict, telemetry, UI, CLI, and API architecture.
- [Component Fit Review](docs/COMPONENT_FIT_REVIEW.md): what reused engines may
  do and what Phragma must own.
- [Performance and Benchmarks](docs/PERFORMANCE_AND_BENCHMARKS.md):
  VM-Series-class benchmark philosophy, failure-mode expectations, and the
  `perf/` harness contract.
- [Threat Intel and Content](docs/THREAT_INTEL_AND_CONTENT.md): App-ID,
  Threat-ID, feed governance, QA, telemetry, and content update expectations.
- [WebUI Design](docs/webui-design.md): current embedded management UI,
  editing model, and HTTPS behavior.
- [Open Source Governance](docs/OPEN_SOURCE_GOVERNANCE.md): 100% OSS model,
  DCO default, and no-entitlement rule.
- [ADRs](docs/adr): durable architecture decisions imported into v2-mixed.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Commits require DCO sign-off
(`git commit -s`) and Conventional Commit messages. Security reports: see
[SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
