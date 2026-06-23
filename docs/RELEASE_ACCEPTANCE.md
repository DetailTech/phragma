# Release Acceptance Evidence

Tagged releases require a machine-readable acceptance manifest at
`release/acceptance.json`. The manifest is part of the release evidence for the
tag, not a planning checklist. Do not create or commit it until the release
candidate has real evidence files for every required check, or a documented
no-performance-claims exception for benchmark evidence.

## Approved Evidence Flow

Prefer the Makefile evidence targets for rootless checks. They wrap
`ngfwrelease record` so every release-local artifact captures the release
commit, command, timestamp, exit code, stdout, stderr, and operator detail in a
structured JSON text file. The recorder writes
`release/evidence/<check>.txt` only when the command exits successfully and
refuses to overwrite existing evidence unless `--overwrite` is set. `COMMIT`
defaults to `git rev-parse HEAD`; pass it explicitly for detached release jobs
or copied worktrees. `RELEASE_EVIDENCE_DIR` defaults to `release/evidence`.
Evidence detail, stdout, and stderr are scanned for unredacted private keys,
PSKs, bearer/JWT/OAuth/API tokens, cookies, CSRF values, client secrets, and
URL credentials before an artifact is accepted. Failed command stderr is
redacted before it is surfaced to the terminal.

Before running the wrapped command, and again before writing the artifact,
`ngfwrelease record` verifies that it is in a readable Git checkout, that
`COMMIT` matches `HEAD`, and that the source tree has no uncommitted changes
outside release artifact locations. The only dirty paths allowed during
recording are the configured `--evidence-dir` under `release/evidence/`,
`release/field-evidence/`, and `perf/release-results/`. Source, docs,
scripts, config, generated API files, and release manifests must be committed
or stashed before recording passing evidence.

Remote validation paths and continuation notes in handoff documents are useful
for engineering continuity, but they are not durable release evidence. A release
gate is satisfied only by a release-local evidence artifact produced through
`ngfwrelease record` and, when a manifest is present, bound by
`release/acceptance.json` with the expected artifact digest and full commit.
Status reports classify stale artifacts, digest mismatches, manifest/evidence
commit mismatches, artifact reuse, and evidence-path boundary failures as
review-needed invalid evidence. Treat that state as an operator review and
regeneration requirement, not as a waiver.

Skip-proof gates must not be satisfied by skipped tests. In particular,
`privileged-integration` evidence must come through the no-skip wrapper, include
the required `privileged_integration_skip_policy=no-skipped-tests` and
`skipped_tests=0` sentinels, and contain no Go test `SKIP` records.

Run the rootless evidence set before assembling `release/acceptance.json`:

```sh
COMMIT="$(git rev-parse HEAD)" make release-evidence-rootless
```

The rootless evidence set intentionally excludes external field checks such as
`m3-field-evidence`, `ebpf-ol9-field-evidence`, and
`m5-oidc-field-evidence` and `m5-saml-field-evidence`. Those checks must be
recorded from the lab, host, or CI job that actually observed the external peer,
tunnel, XDP/tc attach drill, browser, or provider behavior.
It also intentionally excludes `e2e-install`; release evidence for that gate
must come from a disposable Linux host running the installed-service smoke test,
not the static rootless preflight.
It also intentionally excludes `content-production-readiness`; rootless content
smoke output proves demo package mechanics only, not production App-ID,
Threat-ID, or intel-feed readiness.
The rootless evidence set includes `webui-enterprise-smoke`, so run it from a
supported remote browser validation host with Node.js, Playwright, Chromium,
and enough runtime budget for the full desktop enterprise sweep. That artifact
must capture a browser-required broad route sweep, screenshots, and the smoke
manifest for the accepted source snapshot.

Or run the rootless checks individually:

```sh
COMMIT="$(git rev-parse HEAD)" make release-evidence-proto-verify
COMMIT="$(git rev-parse HEAD)" make release-evidence-deploy-hardening
COMMIT="$(git rev-parse HEAD)" make release-evidence-policy-restore-drill
COMMIT="$(git rev-parse HEAD)" make release-evidence-ha-readiness-recovery
COMMIT="$(git rev-parse HEAD)" make release-evidence-content-package-verification
COMMIT="$(git rev-parse HEAD)" make release-evidence-m5-auth-ui
COMMIT="$(git rev-parse HEAD)" make release-evidence-m5-oidc-provider
COMMIT="$(git rev-parse HEAD)" make release-evidence-webui-enterprise-smoke
COMMIT="$(git rev-parse HEAD)" make release-evidence-release-benchmark
```

`release-evidence-proto-verify` only records evidence after `make proto-verify`
proves the API contract is release-clean. That verifier rejects unstaged,
staged, or untracked API contract inputs (`api/proto`, `api/openapi.yaml`,
`buf.yaml`, `buf.gen.yaml`, and `cmd/ngfwopenapi`), plus unstaged, staged, or
untracked generated API outputs and published spec copies.
Use `make proto-status` for a read-only drift breakdown before regenerating or
recording evidence; it also reports tracked, staged, and untracked API contract
inputs that need to be committed with the matching generated outputs. It does
not replace the strict `make proto-verify` gate.
Do not stage generated files merely to satisfy the check; commit the `.proto`
inputs and matching generated outputs together, then record evidence for that
new commit.

During active development, when the tree is intentionally dirty, use the
following commands only as diagnostics. They are expected to report
`recordability: blocked` until all source/API/WebUI/release-tool changes are
accepted as source and only release artifact paths remain dirty:

```sh
COMMIT="$(git rev-parse HEAD)"
make proto-status
go run ./cmd/ngfwrelease recordability \
  --evidence-dir release/evidence \
  --commit "$COMMIT"
go run ./cmd/ngfwrelease status \
  --manifest release/acceptance.json \
  --evidence-dir release/evidence \
  --commit "$COMMIT" \
  --version "$(git describe --tags --always 2>/dev/null || echo dev)" \
  --recordability
make release-recordability-check COMMIT="$COMMIT"
```

For this build pass, the read-only recordability diagnostic should be treated
as useful only if it identifies the exact dirty contract/source blockers. It
must not be used as release evidence and must not be substituted for
`ngfwrelease record` output. In the current `v2-mixed` tree, the next
source-acceptance slice for API recordability is the API contract bundle:
`api/proto/`, `api/openapi.yaml`, `buf.yaml`, `buf.gen.yaml`,
`cmd/ngfwopenapi/`, `api/gen/`, `docs/api-spec.yaml`, and
`internal/webui/static/api-spec.yaml`.

For operator convenience, the same diagnostic sequence is available as:

```sh
COMMIT="$(git rev-parse HEAD)" make release-recordability-diagnostics
```

That target intentionally records no evidence. It runs both `proto-status` and
the strict recordability check, prints both blocker sets, and exits nonzero if
either gate is still blocked.

Release status output, including the machine-readable JSON used by APIs, is an
inventory report over the same acceptance contract as verification. It must not
be interpreted as a waiver system: a template schema, `todo` status,
placeholder timestamp, zero digest, edited manifest row, hand-written note, or
any artifact that is not `phragma.release.evidence.v1` recorder JSON is
reported as `invalid` until real evidence is recorded and the manifest is
assembled for the accepted commit. `not_applicable` is reserved for the
`release-benchmark` no-performance-claims path only; every other check must
have passing recorded evidence before release acceptance can be ready.

## Functional Hardening-Deferred Mode

Full production verification remains strict. `make release-verify` and
`make release-acceptance-verify` continue to require every production
certification gate, except the existing explicit `release-benchmark`
`not_applicable` path for releases that publish no performance claims.

The opt-in functional hardening-deferred mode is only for enterprise
functional acceptance before four production-certification evidence bundles
are complete. The `ngfwrelease status` and `ngfwrelease assemble` functional
contract uses `--functional-hardening-deferred` and may defer only these
checks:

- `content-production-readiness`
- `m3-field-evidence`
- `m5-oidc-field-evidence`
- `m5-saml-field-evidence`

Every other acceptance gate remains mandatory for functional acceptance:
`proto-verify`, `privileged-integration`, `deploy-hardening`,
`policy-restore-drill`, `ha-readiness-recovery`, `e2e-install`,
`content-package-verification`, `release-benchmark` or the explicit
no-performance-claims path, `m3-live-networking`, `ebpf-ol9-field-evidence`,
`m5-auth-ui`, `m5-oidc-provider`, and `webui-enterprise-smoke`.

In this checkout, do not assume production `ngfwrelease verify` accepts a
hardening-deferred manifest unless the CLI help for `verify` explicitly exposes
that flag. Prefer read-only status and assembly workflows for the functional
contract:

```sh
make release-acceptance-status-functional VERSION=<tag> COMMIT=<full-commit>
make release-acceptance-assemble-functional VERSION=<tag> COMMIT=<full-commit> \
  RELEASE_OPERATOR="$USER" \
  RELEASE_EVIDENCE_DIR=release/evidence \
  RELEASE_BENCHMARK_SUMMARY=perf/release-results/<run>/summary.json
```

Those Makefile wrappers are intentionally separate from production targets.
They pass the current `ngfwrelease status` or `assemble`
`--functional-hardening-deferred` contract; they do not weaken
`release-acceptance-status`, `release-acceptance-assemble`,
`release-acceptance-verify`, or `release-verify`.

Record the production content check separately after the signed App-ID,
Threat-ID, and intel-feed package evidence bundle exists:

```sh
make content-production-readiness-check \
  CONTENT_PRODUCTION_EVIDENCE_DIR=release/field-evidence/content-production

COMMIT="$(git rev-parse HEAD)" make release-evidence-content-production-readiness \
  CONTENT_PRODUCTION_EVIDENCE_DIR=release/field-evidence/content-production
```

Record the install smoke gate separately on a disposable Linux host or CI
runner with root, systemd, network namespaces, nftables, and IP forwarding:

```sh
COMMIT="$(git rev-parse HEAD)" make release-evidence-e2e-install
```

`release-evidence-deploy-hardening` records the deploy-hardening preflight:

```sh
bash release/deploy-hardening-check.sh --check

COMMIT="$(git rev-parse HEAD)" make release-evidence-deploy-hardening
```

The first command validates the packaged service/installer posture directly.
The second command is the durable release-evidence path; it wraps the validator
with `ngfwrelease record` and writes `release/evidence/deploy-hardening.txt`
for the current commit.

This static gate fails if the shipped `deploy/systemd/controld.service` or
`deploy/install.sh` drifts toward lab defaults: unauthenticated local mode,
`--tls=false`, dry-run mode, non-loopback management listeners, broad systemd
capabilities, missing systemd sandbox directives, non-root-only state/config
paths, plaintext bootstrap users, or an unguarded remote Vector installer. It
does not start `controld`, install packages, perform live listener exposure,
rotate secrets, prove runtime RBAC, or certify least-privilege command
execution on a production host. This check does not replace `m5-auth-ui`,
`m5-oidc-provider`, `m5-oidc-field-evidence`, `m5-saml-field-evidence`,
`e2e-install`, privileged integration, or the later hardening pass; it prevents
a tag from shipping packaged deploy artifacts whose default posture contradicts
the enterprise release evidence.

`release-evidence-policy-restore-drill` records the rootless emergency policy
restore drill:

```sh
make policy-restore-drill-check
```

This gate proves the non-privileged rollback and restore surface before a tag
can claim operational recovery readiness. It covers version rollback
validation, high-risk impact acknowledgement, runtime-warning acknowledgement,
operator audit comments, hash-chain audit evidence, running-policy pointer
movement, last-known-good posture, and engine-apply calls through the
recording-engine test harness. It does not replace a later live Linux restore
drill with nftables traffic, signed/encrypted restore bundles, retention and
pruning policy, or active/passive failover field evidence.

The recorded validator stdout for `policy-restore-drill` must include these
sentinels:

```text
check=policy-restore-drill
mode=check
restore_drill_scope=policy-version-rollback,validation,impact-ack,runtime-ack,audit-comment,audit-log,running-pointer,last-known-good,engine-apply
automated_tests=TestPolicyRollbackRecordsIntentAuditAndAppliesEngines,TestPolicyRollbackRequiresAckRiskForHighRiskImpact,TestPolicyRollbackRequiresAckRuntimeForRuntimeWarnings,TestPolicyRollbackUsesOperatorComment
restore_surface=PolicyService.Rollback,ngfwctl-rollback-preflight,store-version-history,audit-chain
run_requires=rootless,go-test,temp-boltdb,in-process-policy-server,recording-engine
status=passed
```

`release-evidence-ha-readiness-recovery` records the rootless HA readiness and
control-plane recovery gate:

```sh
make ha-readiness-recovery-check
```

This gate proves active/passive HA status, passive policy pull, automatic
replication bookkeeping, guarded manual activation, CLI parity, daemon peer
source handling, and support-bundle collection through non-privileged test
harnesses. It is intentionally scoped to control-plane recovery evidence. It
does not certify peer mTLS, bearer-token custody/rotation, VIP or route
promotion, peer fencing, split-brain controls, connection-state sync, or live
Linux failover under traffic.

The recorded validator stdout for `ha-readiness-recovery` must include these
sentinels:

```text
check=ha-readiness-recovery
mode=check
ha_recovery_scope=status,passive-policy-pull,automatic-replication,manual-activation,cli-parity,daemon-peer-config,support-bundle
automated_tests=TestSystemHighAvailabilityStatusReportsPeerHeartbeatSync,TestSystemHighAvailabilityStatusDegradesStaleOrSameRolePeer,TestSystemPullHighAvailabilityPolicyAppliesActivePeerPolicy,TestSystemAutomaticHighAvailabilityReplicationAppliesActivePeerPolicy,TestSystemAutomaticHighAvailabilityReplicationRecordsBlockedAttempt,TestSystemActivateHighAvailabilityFailoverPersistsActiveRole,TestSystemSupportBundleCollectsServerBundle,TestPrintStatusShowsHighAvailabilityReadiness,TestSystemHAPullPolicyCallsAPIAndPrintsSummary,TestSystemHAActivatePassiveCallsAPIAndPrintsSummary,TestValidateHAFlags,TestHAPeerSourcesUseExpectedHTTPSRequests,TestSupportBundleCollectorShape
ha_claim_boundary=does_not_certify_vip_route_promotion,peer_fencing,connection_state_sync,live_linux_failover
ha_surface=SystemService.GetHighAvailabilityStatus,PullHighAvailabilityPolicy,RunHighAvailabilityReplicationOnce,ActivateHighAvailabilityFailover,ngfwctl-status,ngfwctl-system-ha,controld-ha-peer-source,support-bundle-highAvailabilityStatus
deferred_field_controls=peer-mtls,peer-token-rotation,vip-route-promotion,peer-fencing,split-brain-policy,conntrack-sync,live-linux-failover
run_requires=rootless,go-test,temp-boltdb,in-process-policy-server,recording-engine,loopback-httptest-peer
status=passed
```

`release-evidence-release-benchmark` records the output of
`make benchmark-verify-release`, which requires a publishable
`perf/release-results/<run>/summary.json` under `RELEASE_PERF_RESULTS`. If the
tag publishes no performance claims, run the same path with
`RELEASE_NO_PERFORMANCE_CLAIMS=1`; the target prints guidance and does not
create `release/evidence/release-benchmark.txt`, because the assembler must
mark that check `not_applicable` instead:

```sh
COMMIT="$(git rev-parse HEAD)" RELEASE_NO_PERFORMANCE_CLAIMS=1 make release-evidence-rootless
```

`release-evidence-content-package-verification` records
`make content-package-smoke`. That smoke creates signed demo App-ID, Threat-ID,
and intel-feed packages in isolated temp directories, verifies signature,
provenance, regression, rollout, and rollback posture, rejects a signed package
with failed regression evidence, and proves rollback restores the previous
verified package. It is demo-only mechanics evidence. It does not certify
production App-ID, Threat-ID, or intel-feed content.

The recorder stores a structured `content_readiness` object for this check:
`scope: demo-only`, `production_content: false`, and
`mechanics_verified: true`, `production_ready: false`, plus the production
evidence still required before any release can claim production content
readiness. Plain
`go test ./internal/contentpkg` output is not accepted as release evidence for
this check; the verifier only accepts the approved smoke wrapper command
prefixes and rejects demo smoke artifacts that omit `content_readiness` or
claim production content readiness.

Production content readiness is checked from signed package status, not from
the smoke artifact. A release can claim production App-ID, Threat-ID, or
intel-feed readiness only when the installed package status for that kind has
`content_readiness.scope=production`, `production_content=true`, and
`production_ready=true`. Required package evidence is kind-specific:

| Package kind | Required signed package evidence |
|---|---|
| `app-id` | `app-taxonomy`, `confidence-model`, `app-regression-corpus`, `license-review`, `staged-rollout`, `rollback-drill` |
| `threat-id` | `threat-taxonomy`, `pcap-regression-corpus`, `false-positive-regression`, `license-review`, `staged-rollout`, `rollback-drill` |
| `intel-feeds` | `feed-registry`, `parser-tests`, `license-review`, `false-positive-regression`, `staged-rollout`, `rollback-drill` |

Each evidence entry must name a package-local artifact, list its SHA-256,
include an RFC3339 `generated_at` timestamp, set `signed=true`, and report
`signature_status=verified`. The release validator reads the release-local
`status.json` file plus the referenced `evidence/*.json` files for each kind;
it does not accept separate `package-status.json` or `manifest.json` inputs for
this gate. Each referenced artifact must use a relative `evidence/*.json` path,
be non-empty valid JSON, have a matching digest, carry an `evidence_type` that
matches the `content_readiness.evidence[].type` entry, and report a passed
`verdict` or `status`.

Normal enterprise release acceptance requires the separate
`content-production-readiness` check before release notes, support statements,
or customer-facing copy can claim production content readiness. That check
validates a release-local evidence bundle rooted at
`release/field-evidence/content-production` by default:

```text
release/field-evidence/content-production/
  app-id/
    status.json
    evidence/
      app-taxonomy.json
      confidence-model.json
      app-regression-corpus.json
      license-review.json
      staged-rollout.json
      rollback-drill.json
  threat-id/
    status.json
    evidence/
      threat-taxonomy.json
      pcap-regression-corpus.json
      false-positive-regression.json
      license-review.json
      staged-rollout.json
      rollback-drill.json
  intel-feeds/
    status.json
    evidence/
      feed-registry.json
      parser-tests.json
      license-review.json
      false-positive-regression.json
      staged-rollout.json
      rollback-drill.json
```

Each `status.json` must be exported from the same verified package status
surface used by `GET /v1/intel/content/packages` and `ngfwctl intel content`
after the signed production package has been installed or staged in the release
lab. The validator requires `kind`, `state=verified`,
`signature_status=verified`, `regression_status=passed`, verified provenance,
staged or verified rollout posture, rollback availability, no blockers,
`content_readiness.scope=production`, `production_content=true`,
`production_ready=true`, the exact `required_production_evidence` set for the
package kind, and package-local `content_readiness.evidence[]` entries whose
artifact paths, SHA-256 values, RFC3339 `generated_at` timestamps,
`signed=true`, `signature_status=verified`, artifact `evidence_type`, and
artifact passed `verdict`/`status` match the files under `evidence/`. Unsigned
operator notes, missing digests, failed evidence verdicts, symlinks, or
evidence paths outside `evidence/` do not satisfy this check.

The recorded validator stdout for `content-production-readiness` must include
reviewer-visible sentinels for all three production content systems:

```text
check=content-production-readiness
mode=check
content_production_scope=app-id,threat-id,intel-feeds
required_content_kinds=app-id,threat-id,intel-feeds
required_app_id_evidence=app-taxonomy,confidence-model,app-regression-corpus,license-review,staged-rollout,rollback-drill
required_threat_id_evidence=threat-taxonomy,pcap-regression-corpus,false-positive-regression,license-review,staged-rollout,rollback-drill
required_intel_feeds_evidence=feed-registry,parser-tests,license-review,false-positive-regression,staged-rollout,rollback-drill
content_readiness=production_content=true,production_ready=true
status=passed
```

`release-evidence-content-production-readiness` records that validator output
as `release/evidence/content-production-readiness.txt` through
`ngfwrelease record`. The recorder artifact must have schema
`phragma.release.evidence.v1`, check name `content-production-readiness`, the
release commit, operator detail, exit code `0`, and the approved command
prefix for the validator. The acceptance manifest then hash-binds that recorder
artifact like every other required check.

To replace evidence for the same release candidate, pass the recorder flag
deliberately:

```sh
COMMIT="$(git rev-parse HEAD)" RELEASE_EVIDENCE_RECORD_FLAGS=--overwrite make release-evidence-proto-verify
```

Privileged, live-networking, and external field-evidence checks must come from
the Linux host, VM, browser lab, or CI job that actually ran or collected the
checks. This macOS workspace cannot honestly generate those artifacts.
`privileged-integration` is recorded manually with `ngfwrelease record`;
use the no-skip wrapper so skipped tests cannot satisfy the gate.
`m3-live-networking` can use the Makefile wrapper on the Linux/root host:

```sh
go run ./cmd/ngfwrelease record \
  --evidence-dir release/evidence \
  --check privileged-integration \
  --commit "$(git rev-parse HEAD)" \
  --detail "root real-engine integration on disposable Linux host" \
  -- make privileged-integration-evidence-check

go run ./cmd/ngfwrelease record \
  --evidence-dir release/evidence \
  --check m3-live-networking \
  --commit "$(git rev-parse HEAD)" \
  --detail "static-route live forwarding, local FRR BGP netns route programming, and WireGuard handshake/peer-traffic validation on disposable Linux host" \
  -- make m3-live-networking
```

The default M3 release command records automated static-route live forwarding
plus local FRR BGP netns route-programming evidence and local netns WireGuard
handshake and peer-traffic evidence. External BGP peers, IPsec, and external
WireGuard client/road-warrior paths are recorded by the separate
`m3-field-evidence` release check. Collect the bundle from the external lab
using the Phase 3 evidence commands, copy the redacted files under a release
field-evidence directory, validate that bundle, then record it:

```sh
make m3-field-evidence-check M3_FIELD_EVIDENCE_DIR=release/field-evidence/m3

go run ./cmd/ngfwrelease record \
  --evidence-dir release/evidence \
  --check m3-field-evidence \
  --commit "$(git rev-parse HEAD)" \
  --detail "external BGP peer, IPsec SA/protected-subnet traffic, and external WireGuard client field evidence bundle from lab <name>" \
  -- make m3-field-evidence-check
```

The validator expects package-like, release-local evidence files for:

- BGP: `show-bgp-summary`, `ip-route-remote-prefix`,
  `frr-running-config`.
- IPsec: `swanctl-list-conns`, `swanctl-list-sas`,
  `swanctl-list-pols`, `ip-xfrm-state`, `ip-xfrm-policy`,
  `protected-subnet-ping`.
- WireGuard: `wg-show`, `client-config-redacted`,
  `external-client-ping`.

Do not imply external protocol coverage from generic `m3-live-networking`
output.

The eBPF milestone gate is external because it requires an OL9/OCI Linux host
with root, bpftool, clang, iproute2, bpffs, cgroup v2, kernel BTF, and live
XDP/tc attach/detach drills. It does not make eBPF the active dataplane;
`nftables/conntrack` remains the production renderer until verifier, object
provenance, map lifecycle, attach rollback, and traffic cutover controls are
implemented. Collect the redacted bundle under
`release/field-evidence/ebpf-ol9`, validate it, then record it:

```sh
make ebpf-ol9-attach-drill-check

sudo -E EBPF_OL9_ATTACH_IFACE=<disposable-interface> \
  EBPF_OL9_STATUS_JSON_COMMAND='<command that prints /v1/system/status eBPF JSON>' \
  make ebpf-ol9-attach-drill EBPF_OL9_FIELD_EVIDENCE_DIR=release/field-evidence/ebpf-ol9

make ebpf-ol9-field-evidence-check EBPF_OL9_FIELD_EVIDENCE_DIR=release/field-evidence/ebpf-ol9

COMMIT="$(git rev-parse HEAD)" make release-evidence-ebpf-ol9-field-evidence \
  EBPF_OL9_FIELD_EVIDENCE_DIR=release/field-evidence/ebpf-ol9
```

`ebpf-ol9-attach-drill-check` is a rootless collector preflight, not release
acceptance evidence. `ebpf-ol9-attach-drill` is intentionally root-only and
refuses to run without an explicit disposable interface. It writes the bundle
that `ebpf-ol9-field-evidence-check` validates and must not be run on an
interface with existing XDP or clsact state.

The expected bundle shape is:

```text
release/field-evidence/ebpf-ol9/
  host/
    os-release.txt
    uname.txt
    oci-instance.txt
    kernel-btf.txt
    bpffs.txt
    cgroup-v2.txt
    link-inventory.txt
  tooling/
    versions.txt
  status/
    ngfwctl-status.txt
    system-status-ebpf.json
  renderer/
    ebpf-plan.txt
  drill/
    manifest.txt
  attach/
    xdp-attach.txt
    xdp-detach.txt
    tc-clsact-attach.txt
    tc-clsact-detach.txt
    bpftool-prog-show.txt
  cleanup/
    post-cleanup.txt
```

The recorded validator stdout for `ebpf-ol9-field-evidence` must include:

```text
check=ebpf-ol9-field-evidence
mode=check
field_evidence_scope=ol9-oci-host,ebpf-host-prereqs,xdp-attach-probe,tc-attach-probe,status-api,renderer-scaffold,cleanup
required_host_evidence=os-release,uname,oci-instance
required_ebpf_prereqs=bpftool,clang,tc,ip,kernel-btf,bpffs,cgroup-v2,link-inventory
required_attach_evidence=xdp-attach,xdp-detach,tc-clsact-attach,tc-clsact-detach,bpftool-program-inspection,cleanup
required_status_evidence=ngfwctl-status,system-status-ebpf-json
required_renderer_evidence=ebpf-render-plan
required_drill_evidence=drill-manifest,probe-source-sha256,probe-object-sha256,attach-detach-command-records
active_dataplane=nftables/conntrack
ebpf_renderer_state=planned
supported_hooks=xdp,tc
xdp_attach_result=passed
tc_attach_result=passed
cleanup_result=passed
ebpf_field_redaction=oci-ocids-redacted,public-ips-redacted,tokens-redacted
redaction_scan=private-key,bearer,api-key,token,url-userinfo,oci-ocid,public-ip
status=passed
```

The `webui-enterprise-smoke` gate records the browser-required broad desktop
WebUI route sweep. It is the formal durable release-evidence model for the
enterprise WebUI smoke runner; previous remote paths, handoff notes, targeted
reruns, and unrecorded tablet/mobile sweeps remain continuation context until
this check is recorded through `ngfwrelease record` for the accepted source
snapshot.

Record it on a remote Linux browser validation host with Node.js, Playwright,
a launchable Chromium browser, and enough runtime budget for the full desktop
route set:

```sh
COMMIT="$(git rev-parse HEAD)" make release-evidence-webui-enterprise-smoke
```

The wrapper records `make webui-enterprise-smoke` and writes
`release/evidence/webui-enterprise-smoke.txt`. The underlying target runs the
full enterprise route list across the desktop viewport by default, requires
Node.js JavaScript checks, requires browser coverage by default, writes
`webui-smoke-evidence.json`, stores screenshot artifacts under the smoke
artifact directory, and fails on unlabeled icon controls, generic operator
actions without stable hooks plus title/ARIA intent, or route-backed drawer
actions without stable accessible affordances. The recorded stdout must include
`webui_js_checks=passed`, `javascript_checks=required`,
`release_smoke_mode=desktop-enterprise`, `browser_required=1`,
`[webui-smoke] browser_coverage=chromium`, `viewport_coverage=desktop`, the
broad evidence policy, `route_coverage=20/20`, passed broad summary, check
count, screenshot count, evidence manifest path, and release-note caveat
stating that broad visual-smoke evidence supports production release only after
source-control acceptance and repo-local release evidence recording.

Additional tablet/mobile sweeps can still be run by overriding
`WEBUI_ENTERPRISE_SMOKE_VIEWPORTS=desktop,tablet,mobile`, but those runs are
not the default accepted-source release record unless the recorded evidence
and this contract are deliberately updated together.

## Approved Assembly Flow

After all required evidence files exist, assemble the manifest from those
existing artifacts:

```sh
go run ./cmd/ngfwrelease assemble \
  --manifest release/acceptance.json \
  --version v2.0.0 \
  --commit "$(git rev-parse HEAD)" \
  --operator "$USER" \
  --evidence-dir release/evidence \
  --benchmark-summary perf/release-results/<run>/summary.json
```

The assembler expects `release/evidence/<check>.txt` for every required check,
computes each `artifact_sha256`, validates the benchmark summary, validates the
finished manifest contract, and refuses to overwrite `release/acceptance.json`
unless `--overwrite` is explicitly set.
Verification parses every evidence artifact and rejects files that were not
produced by `ngfwrelease record`, do not match the manifest check name, have a
non-zero exit code, lack operator detail, or carry a commit different from the
manifest commit. Stable checks also require one of the approved command shapes
below. Evidence-directory and benchmark commands accept only the constrained
release-local path shown for that check.

| Check | Approved release evidence commands |
|---|---|
| `proto-verify` | `make proto-verify` |
| `privileged-integration` | `make privileged-integration-evidence-check`; `bash release/privileged-integration-no-skip.sh`; `sudo /tmp/openngfw-itest -test.v -test.timeout 300s` |
| `deploy-hardening` | `bash release/deploy-hardening-check.sh --check`; `./release/deploy-hardening-check.sh --check`; `make deploy-hardening-check` |
| `policy-restore-drill` | `make policy-restore-drill-check`; `bash release/policy-restore-drill.sh --check` |
| `ha-readiness-recovery` | `make ha-readiness-recovery-check`; `bash release/ha-readiness-recovery.sh --check` |
| `e2e-install` | `bash e2e/install-smoke.sh --run`; `make e2e-install`; `sudo make e2e-install` |
| `content-package-verification` | `make content-package-smoke`; `bash e2e/content-package-smoke.sh --check` |
| `content-production-readiness` | `make content-production-readiness-check`; `bash release/content-production-readiness.sh --evidence-dir release/field-evidence/content-production`; `./release/content-production-readiness.sh --evidence-dir release/field-evidence/content-production` |
| `release-benchmark` | `make benchmark-verify-release`; `go run ./cmd/ngfwperf verify --strict --publishable perf/release-results` |
| `m3-live-networking` | `bash release/m3-live-networking.sh --run`; `./release/m3-live-networking.sh --run`; `make m3-live-networking` |
| `m3-field-evidence` | `bash release/m3-field-evidence.sh --evidence-dir release/field-evidence/m3`; `./release/m3-field-evidence.sh --evidence-dir release/field-evidence/m3`; `make m3-field-evidence-check` |
| `ebpf-ol9-field-evidence` | `make ebpf-ol9-field-evidence-check`; `bash release/ebpf-ol9-field-evidence.sh --evidence-dir release/field-evidence/ebpf-ol9` |
| `m5-oidc-provider` | `make e2e-oidc-runtime-smoke`; `go test -count=1 -run TestOIDCRuntimeSmoke -v ./cmd/controld` |
| `m5-oidc-field-evidence` | `bash release/oidc-field-evidence.sh --evidence-dir release/field-evidence/oidc`; `./release/oidc-field-evidence.sh --evidence-dir release/field-evidence/oidc`; `make m5-oidc-field-evidence-check` |
| `m5-saml-field-evidence` | `bash release/saml-field-evidence.sh --evidence-dir release/field-evidence/saml`; `./release/saml-field-evidence.sh --evidence-dir release/field-evidence/saml`; `make m5-saml-field-evidence-check` |
| `m5-auth-ui` | `make e2e-auth-runtime-smoke` |
| `webui-enterprise-smoke` | `make webui-enterprise-smoke` |

`m3-live-networking-check`, `release/m3-live-networking.sh --check`, and unit
test-only content-package output are preflight or package-local checks, not
release acceptance evidence. `m3-field-evidence` is accepted only when the
recorded stdout proves the bundle covered BGP, IPsec, and WireGuard and ended
with `status=passed`. `ebpf-ol9-field-evidence` is accepted only when the
recorded stdout proves the OL9/OCI XDP/tc attach, status API, renderer
scaffold, cleanup, active `nftables/conntrack` fallback, and redaction bundle
was complete and ended with `status=passed`. `m5-oidc-field-evidence` is
accepted only when the recorded stdout proves the real-provider browser SSO
bundle was complete, redacted, and ended with `status=passed`.
`m5-saml-field-evidence` is accepted only when the recorded stdout proves the
real-provider SAML browser SSO bundle was complete, redacted, and ended with
`status=passed`. `webui-enterprise-smoke` is accepted only when the recorded
stdout proves a browser-required broad enterprise route sweep passed and
reported the smoke manifest plus screenshot count. The approved
content-package smoke is
accepted only as demo-only package mechanics evidence; it must not be described
as production content evidence. Production content evidence is accepted only
through the separate `content-production-readiness` check and must cover
App-ID, Threat-ID, and intel-feed signed package readiness in the same release.

The `deploy-hardening` check records the packaged service/installer posture
validator through `COMMIT="$(git rev-parse HEAD)" make
release-evidence-deploy-hardening`. The wrapped stdout from
`bash release/deploy-hardening-check.sh --check` must include
`required_service_posture=loopback-listeners,authenticated-by-default,no-dev-bypass,systemd-sandbox,capability-bounds`,
`required_installer_posture=root-only,0700-state-log-config,hashed-admin-token,0600-secret-files,unsafe-remote-install-opt-in`,
and `status=passed`. This proves the shipped service unit and installer
defaults, not live host hardening.

The `m5-auth-ui` check records `make e2e-auth-runtime-smoke`. That smoke is the
release evidence for the loopback authenticated management posture: hashed
local-users-file tokens, missing/bad token rejection, admin/viewer RBAC, TLS
serving, HSTS and restrictive browser security headers, request body limits,
trusted-proxy rate limiting, private users-file permissions, and unsafe no-auth
startup rejection. The stdout includes
`auth_runtime_smoke_scope=hashed-local-users,rbac,tls-security-headers,request-limits,rate-limit,unsafe-noauth-startup-guard`,
`auth_runtime_startup_guard=missing-auth-rejected,unauthenticated-local-requires-dry-run`,
and `status=passed` for reviewer traceability. Browser SSO/OIDC protocol
coverage is recorded by the separate `m5-oidc-provider` check.

The `m5-oidc-provider` check records `make e2e-oidc-runtime-smoke`. That smoke
starts `controld` against a loopback mock OIDC provider and drives the full
authorization-code flow through provider discovery, PKCE, ID-token signature
validation, nonce verification, callback return routing, session cookies, CSRF,
and RBAC. It also rejects missing/reused state, nonce mismatch, PKCE exchange
failure, and viewer mutation while proving logout invalidation. The same
rootless gate validates the admin-authenticated runtime provider API, enables a
mock provider without restart, replaces the runtime authenticator, disables the
provider, revokes OIDC sessions, and verifies disabled-provider routing. Its
stdout must include
`oidc_runtime_smoke_scope=provider-discovery,authorization-code-pkce,id-token-verification,nonce,session-cookie,csrf,rbac,runtime-provider-lifecycle`,
`oidc_runtime_negative_scope=missing-state,reused-state,nonce-mismatch,pkce-exchange-failure,logout,viewer-denial`,
`oidc_runtime_provider_lifecycle=api-validate,set,disable,runtime-authenticator-replacement,session-revocation`,
`oidc_runtime_provider=loopback-mock`,
`oidc_runtime_actor=smoke-admin`, and `status=passed`. This is rootless
protocol/session evidence; it does not certify a specific enterprise IdP,
tenant, reverse proxy, or public HTTPS deployment.

Do not use the local `m5-auth-ui` smoke or loopback `m5-oidc-provider` smoke
alone to claim readiness for a specific browser SSO deployment. Normal
enterprise release acceptance now requires the separate
`m5-oidc-field-evidence` and `m5-saml-field-evidence` checks for redacted,
real provider-backed browser SSO evidence. They are intentionally outside
rootless CI because they need a real issuer or IdP, configured client/SP
metadata, public callback or ACS URL, browser session, and deployment proxy
posture.

Collect the redacted provider-backed bundle under `release/field-evidence/oidc`
or another directory under `release/field-evidence/` and validate it before
recording:

```sh
make m5-oidc-field-evidence-check OIDC_FIELD_EVIDENCE_DIR=release/field-evidence/oidc

COMMIT="$(git rev-parse HEAD)" make release-evidence-m5-oidc-field-evidence \
  OIDC_FIELD_EVIDENCE_DIR=release/field-evidence/oidc
```

The expected bundle shape is:

```text
release/field-evidence/oidc/
  provider/
    issuer-client-discovery.txt
    id-token-validation.txt
  deployment/
    public-callback.txt
    client-secret-file-permissions.txt
  browser/
    session-cookie.txt
    missing-state-rejection.txt
    reused-state-rejection.txt
    nonce-mismatch-rejection.txt
    pkce-exchange-failure.txt
    operator-mutation-with-csrf.txt
    missing-csrf-rejection.txt
    cross-origin-rejection.txt
    viewer-mutation-denial.txt
    logout-invalidation.txt
  rbac/
    role-mapping.txt
  redaction/
    identity-redacted.txt
    audit-log-redacted.txt
    support-bundle-redacted.txt
```

If the release uses a public OIDC client with no secret, include a redacted
`client-secret-file-permissions.txt` explaining that no client secret is
configured. Do not replace the file with a missing artifact; the validator uses
the presence of that named file to prove the secret posture was reviewed.

The validator output recorded in `release/evidence/m5-oidc-field-evidence.txt`
must include the bundle-scope sentinels:

```text
field_evidence_scope=real-issuer-client,id-token-validation,https-callback,secret-file,cookie-security,negative-callbacks,rbac,csrf-origin,logout,redaction
oidc_field_evidence_scope=real-provider-backed,browser-sso,authorization-code-pkce,id-token-verification,nonce,session-cookie,csrf,rbac
oidc_field_negative_checks=missing-state,reused-state,nonce-mismatch,pkce-exchange-failure,logout,viewer-denial
oidc_field_redaction=issuer-host-redacted,client-id-redacted,subject-redacted,email-redacted,tokens-redacted,cookies-redacted
required_provider_evidence=issuer-client-discovery,id-token-validation
required_deployment_evidence=public-https-callback,client-secret-file-permissions
required_browser_evidence=session-cookie,missing-state-rejection,reused-state-rejection,nonce-mismatch-rejection,pkce-exchange-failure,operator-mutation-with-csrf,missing-csrf-rejection,cross-origin-rejection,viewer-mutation-denial,logout-invalidation
required_rbac_evidence=viewer,operator,admin
required_redaction_evidence=identity-redacted,audit-log-redacted,support-bundle-redacted,global-secret-scan
redaction_scan=jwt,bearer,oauth-token,cookie,auth-code,client-secret,csrf
status=passed
```

The files must prove successful discovery and ID-token validation for the
configured issuer/client ID, a public HTTPS `/v1/auth/oidc/callback` redirect,
private client-secret file permissions when a secret is used, HttpOnly/SameSite
session cookies with Secure set for HTTPS public redirects, role-claim mapping
into `viewer`, `operator`, or `admin`, an OIDC `operator` mutation that succeeds
only with `X-Phragma-CSRF`, rejection of missing/reused state, nonce mismatch,
PKCE exchange failure, missing-CSRF, or cross-origin cookie
mutations, denial of an OIDC `viewer` mutation, logout invalidation, and
audit/support-bundle output that reports `oidc-session` without exposing
cookies, authorization codes, provider tokens, ID tokens, refresh tokens, or
client secrets.

Collect the redacted SAML provider-backed bundle under
`release/field-evidence/saml` or another directory under
`release/field-evidence/`, then validate it before recording:

```sh
mkdir -p release/field-evidence/saml/{provider,deployment,browser,rbac,redaction}

make m5-saml-field-evidence-check SAML_FIELD_EVIDENCE_DIR=release/field-evidence/saml

COMMIT="$(git rev-parse HEAD)" make release-evidence-m5-saml-field-evidence \
  SAML_FIELD_EVIDENCE_DIR=release/field-evidence/saml
```

This command sequence prepares, validates, and records already captured
redacted artifacts. The validator does not contact the IdP, drive a browser, or
certify live provider success by itself.

The expected bundle shape is:

```text
release/field-evidence/saml/
  provider/
    idp-metadata.txt
    sp-metadata.txt
  deployment/
    public-acs.txt
  browser/
    login-redirect.txt
    assertion-session-cookie.txt
    invalid-signature-rejection.txt
    replayed-assertion-rejection.txt
    missing-relaystate-rejection.txt
    operator-mutation-with-csrf.txt
    missing-csrf-rejection.txt
    cross-origin-rejection.txt
    viewer-mutation-denial.txt
    logout-invalidation.txt
  rbac/
    role-mapping.txt
  redaction/
    identity-redacted.txt
    audit-log-redacted.txt
    support-bundle-redacted.txt
```

The validator output recorded in `release/evidence/m5-saml-field-evidence.txt`
must include the bundle-scope sentinels:

```text
field_evidence_scope=real-idp-metadata,sp-metadata,https-acs,cookie-security,negative-callbacks,rbac,csrf-origin,logout,redaction
saml_field_evidence_scope=real-provider-backed,browser-sso,authn-request,assertion-validation,session-cookie,csrf,rbac
saml_field_negative_checks=invalid-signature,replayed-assertion,missing-relaystate,logout,viewer-denial
saml_field_redaction=idp-entity-redacted,sp-entity-redacted,subject-redacted,email-redacted,assertions-redacted,cookies-redacted
required_provider_evidence=idp-metadata,sp-metadata
required_deployment_evidence=public-https-acs,secure-cookie-posture
required_browser_evidence=login-redirect,assertion-session-cookie,invalid-signature-rejection,replayed-assertion-rejection,missing-relaystate-rejection,operator-mutation-with-csrf,missing-csrf-rejection,cross-origin-rejection,viewer-mutation-denial,logout-invalidation
required_rbac_evidence=viewer,operator,admin
required_redaction_evidence=identity-redacted,audit-log-redacted,support-bundle-redacted,global-secret-scan
redaction_scan=saml-response,relaystate,assertion,x509,private-key,cookie,csrf
status=passed
```

The files must prove SAML IdP metadata review, SP metadata and HTTPS
`/v1/auth/saml/acs` alignment, secure-cookie deployment posture, browser login
redirect, assertion validation, HttpOnly/SameSite/Secure session cookies,
role-attribute mapping into `viewer`, `operator`, or `admin`, a SAML
`operator` mutation that succeeds only with `X-Phragma-CSRF`, rejection of
invalid-signature, replayed-assertion, missing-RelayState, missing-CSRF, or
cross-origin cookie mutations, denial of a SAML `viewer` mutation, logout
invalidation, and audit/support-bundle output that reports `saml-session`
without exposing raw SAML responses, assertions, RelayState values, X.509
certificate bodies, private keys, cookies, or CSRF tokens.

For a tag that publishes no performance claims, omit `--benchmark-summary` and
use:

```sh
go run ./cmd/ngfwrelease assemble \
  --manifest release/acceptance.json \
  --version v2.0.0 \
  --commit "$(git rev-parse HEAD)" \
  --operator "$USER" \
  --evidence-dir release/evidence \
  --no-performance-claims \
  --no-performance-detail "This tag publishes no throughput, latency, connection-rate, or comparison claims."
```

The Makefile wrapper exposes the same flow:

```sh
make release-acceptance-assemble VERSION=<tag> COMMIT=<full-commit> \
  RELEASE_OPERATOR="$USER" \
  RELEASE_EVIDENCE_DIR=release/evidence \
  RELEASE_BENCHMARK_SUMMARY=perf/release-results/<run>/summary.json
```

For a functional hardening-deferred enterprise acceptance, use the separate
functional wrapper for the `ngfwrelease assemble --functional-hardening-deferred`
contract:

```sh
make release-acceptance-assemble-functional VERSION=<tag> COMMIT=<full-commit> \
  RELEASE_OPERATOR="$USER" \
  RELEASE_EVIDENCE_DIR=release/evidence \
  RELEASE_BENCHMARK_SUMMARY=perf/release-results/<run>/summary.json
```

That mode may mark only `content-production-readiness`,
`m3-field-evidence`, `m5-oidc-field-evidence`, and
`m5-saml-field-evidence` as deferred functional hardening. It is not a
production release certificate.

## Verification Commands

Before assembling or while collecting evidence, inspect the current local
inventory:

```sh
make release-acceptance-status VERSION=<tag> COMMIT=<full-commit>
```

`ngfwrelease status` is read-only. It reports which required checks have a
recorded artifact, which artifacts are missing or malformed, whether the
manifest exists, and whether a completed manifest verifies. The Makefile wrapper
also adds `--recordability`, which reports whether the current git checkout is
clean enough for `ngfwrelease record` to write evidence. Source changes outside
`release/evidence/`, `release/field-evidence/`, or `perf/release-results/`
block evidence recording until they are committed or stashed. The status command
does not create evidence and must not be treated as release acceptance. Use
`--json` for the stable machine-readable inventory or `--strict` when a CI job
should fail unless the manifest is fully ready. When `--strict` is combined with
`--recordability`, the command also fails if the checkout is not recordable.
`--recordability` is human output and is intentionally not combined with
`--json`.

The functional inventory wrapper adds the same read-only status and
recordability reporting for the `ngfwrelease status
--functional-hardening-deferred` contract:

```sh
make release-acceptance-status-functional VERSION=<tag> COMMIT=<full-commit>
```

It may report only the four allowed production-certification items as deferred;
missing or invalid eBPF OL9 field evidence, privileged integration, install,
M3 live networking, WebUI enterprise smoke, automated auth/provider gates,
restore/HA/deploy/content-package/proto evidence, or performance evidence
still blocks functional acceptance.

The release workflow runs the rootless gate and then verifies the manifest:

```sh
make release-check-rootless
make release-acceptance-verify VERSION=<tag> COMMIT=<full-commit>
make release-recordability-check VERSION=<tag> COMMIT=<full-commit>
```

`make release-check-rootless` is a preflight gate bundle, not a release
manifest evidence bundle. It includes `make benchmark-verify-release` and checks
locally runnable rootless/static posture, but it does not assemble or certify the
release manifest. Publishable benchmark evidence under `perf/release-results/`
is required by default. It still does not collect
`content-production-readiness`, `m5-oidc-field-evidence`, or
`m5-saml-field-evidence`; record content readiness from the signed production
package evidence bundle and record OIDC/SAML field evidence from the
provider-backed browser lab before assembling and verifying normal release
acceptance. It does run `webui-enterprise-smoke`, so CI or the remote browser
validation host must install Playwright/Chromium and fail closed on missing
browser coverage. If no release benchmark `summary.json`
exists, the gate fails unless the operator explicitly runs the release as
publishing no performance claims:

```sh
RELEASE_NO_PERFORMANCE_CLAIMS=1 make benchmark-verify-release
RELEASE_NO_PERFORMANCE_CLAIMS=1 make release-acceptance-verify VERSION=<tag> COMMIT=<full-commit>
```

That mode is allowed only when the tag publishes no throughput, latency,
connection-rate, or comparison claims.

`make release-verify` runs `proto-verify`, the rootless gate, manifest
verification, and the strict recordability preflight. It is expected to fail
until source changes are committed or stashed and the release evidence/manifest
matches the requested tag and commit.

There is intentionally no `release-verify-functional` production substitute in
this Makefile. Unless `ngfwrelease verify` explicitly exposes a
hardening-deferred flag, production verification remains the only
verifier-backed acceptance path.

## Template Helper

Before a release candidate has evidence, operators can print a deliberately
non-passing manifest shape:

```sh
go run ./cmd/ngfwrelease template
go run ./cmd/ngfwrelease template --output release/acceptance.template.json
```

The helper is for scaffolding only. It is not a release gate, it must not be
renamed to `release/acceptance.json`, and it must not be attached to a tag as
release evidence. It uses `phragma.release.acceptance.v1.template`, `todo`
statuses, zero digests, example artifact paths, and placeholder timestamps so
`ngfwrelease verify` rejects the output until every required check is replaced
with real, hash-bound evidence.

Store captured command output and operator notes under `release/evidence/` only
through `ngfwrelease record`, then create `release/acceptance.json` only for the
actual release candidate. A production release path is satisfied only when the
manifest uses `phragma.release.acceptance.v1`, every required production check
has `status: passed`, every artifact is non-empty recorder JSON for the exact
commit, and the verifier recomputes matching artifact digests. The only accepted
`not_applicable` check is `release-benchmark` in explicit
`RELEASE_NO_PERFORMANCE_CLAIMS=1` mode; all hardening, install, external field,
browser, SSO, and production content checks still require real evidence.

Functional hardening-deferred manifests are separate from production manifests.
They may defer only
`content-production-readiness`, `m3-field-evidence`,
`m5-oidc-field-evidence`, and `m5-saml-field-evidence`; the remaining checks
above still require `passed` evidence or the existing no-performance-claims
handling for `release-benchmark`.

## Manifest Schema

The manifest schema version is `phragma.release.acceptance.v1`.

Required top-level fields:

- `schema_version`: must be `phragma.release.acceptance.v1`.
- `release_version`: release tag or version being signed.
- `commit`: exact 40-character hex release commit. Prefixes are rejected.
- `generated_at`: RFC3339 timestamp.
- `operator`: person or automation account assembling the release evidence.
- `no_performance_claims`: boolean. Set to `true` only for a tag that publishes
  no performance claims.
- `checks`: evidence records for every required acceptance check.

Required check names:

- `proto-verify`
- `privileged-integration`
- `deploy-hardening`
- `policy-restore-drill`
- `ha-readiness-recovery`
- `e2e-install`
- `content-package-verification`
- `content-production-readiness`
- `release-benchmark`
- `m3-live-networking`
- `m3-field-evidence`
- `ebpf-ol9-field-evidence`
- `m5-oidc-provider`
- `m5-oidc-field-evidence`
- `m5-saml-field-evidence`
- `m5-auth-ui`
- `webui-enterprise-smoke`

For normal releases, each required check must have:

- `name`: one of the required check names.
- `status`: `passed`.
- `artifact`: a readable file path under `evidence/`, relative to the manifest
  directory.
- `artifact_sha256`: the SHA-256 digest of that artifact file. The verifier
  recomputes this value and rejects missing, mismatched, or empty evidence
  files.
- `benchmark_summary`: required only for `release-benchmark` on normal
  performance-claiming releases. It must be a repository-relative
  `perf/release-results/<run>/summary.json` path, and that summary must pass
  the strict publishable performance gate.
- `ran_at`: RFC3339 timestamp for the evidence run.
- `detail`: optional context such as host, workflow run, benchmark run, or
  manual validation scope.

The `content-package-verification` evidence artifact must also include
`content_readiness`. For the current rootless smoke this object must say:

- `scope`: `demo-only`.
- `production_content`: `false`.
- `mechanics_verified`: `true`.
- `production_ready`: `false`.
- `required_production_evidence`: the signed production package status,
  corpus, license, rollout, and rollback evidence still needed for App-ID,
  Threat-ID, and intel-feed content.

The corresponding manifest check `detail` must state that this is demo-only
evidence and that it does not certify production content.

The `content-production-readiness` evidence artifact must record
`make content-production-readiness-check` or the approved
`release/content-production-readiness.sh --evidence-dir <dir>` validator
command. Its stdout must include the production readiness sentinels for App-ID,
Threat-ID, intel-feeds, exact required evidence lists, the structured readiness
sentinel, and `status=passed`. Its manifest check `detail` must name the
production package bundle or release lab used to collect the signed evidence.
Do not reuse `content-package-verification` or `make content-package-smoke`
output for this check.

Artifact paths are intentionally relative to `release/acceptance.json` and must
not be absolute, must stay under `evidence/`, must not escape by `..` or
symlink resolution, and must not reuse the same artifact across multiple
checks. Store release-local evidence files under `release/evidence/`, and use
those files to capture command output, operator notes, workflow links, and
benchmark run references.

For `release-benchmark`, set `benchmark_summary` to the selected
`perf/release-results/<run>/summary.json`. The release-local evidence artifact
should include the output from:

```sh
make benchmark-verify-release
```

The actual publishable benchmark summary remains under `perf/release-results/`;
the manifest artifact is the release acceptance evidence file that records what
was verified for the tag.

## No-Performance-Claims Mode

When a tag publishes no performance claims:

- `RELEASE_NO_PERFORMANCE_CLAIMS=1` must be set for the release gate.
- `no_performance_claims` must be `true`.
- The `release-benchmark` check must use `status: not_applicable`.
- The `release-benchmark` check must include `detail` explaining that no
  performance claims are published for the tag.
- The `release-benchmark` check must not reference an evidence artifact in this
  mode and must not set `benchmark_summary`; all other checks still require
  hash-bound evidence artifacts.
- Release notes and external copy must omit throughput, latency,
  connection-rate, and comparison claims.

All other required checks still need real passing evidence.

## Non-Evidence Shape Example

This example shows the required shape only. It is not valid release evidence and
must not be committed as `release/acceptance.json`. It deliberately uses an
example schema, `todo` statuses, zero digests, and placeholder timestamps. Those
values are evidence blockers, not acceptance shortcuts.

```json
{
  "schema_version": "phragma.release.acceptance.v1.example",
  "release_version": "vX.Y.Z",
  "commit": "<release-commit>",
  "generated_at": "YYYY-MM-DDTHH:MM:SSZ",
  "operator": "<operator>",
  "no_performance_claims": false,
  "checks": [
    {
      "name": "proto-verify",
      "status": "todo",
      "artifact": "evidence/proto-verify.txt",
      "artifact_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "ran_at": "YYYY-MM-DDTHH:MM:SSZ",
      "detail": "replace with actual command output"
    },
    {
      "name": "release-benchmark",
      "status": "todo",
      "artifact": "evidence/release-benchmark.txt",
      "artifact_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "benchmark_summary": "perf/release-results/<run>/summary.json",
      "ran_at": "YYYY-MM-DDTHH:MM:SSZ",
      "detail": "replace with selected perf/release-results run and verifier output"
    }
  ]
}
```
