# Release Evidence Directory

This directory is reserved for release acceptance evidence.

Do not add `release/acceptance.json` until there is a real release candidate and
real evidence for the tagged commit. The approved flow is to record evidence
with the Makefile wrappers around `ngfwrelease record`, then assemble the
manifest from existing evidence:

`ngfwrelease record` rejects unredacted secret material in evidence detail,
stdout, and stderr before writing artifacts, and redacts failed-command stderr
before printing it to the terminal.

```sh
COMMIT="$(git rev-parse HEAD)" make release-evidence-rootless
```

This rootless target does not collect external field evidence. Record
`m3-field-evidence`, `ebpf-ol9-field-evidence`, and
`m5-oidc-field-evidence` and `m5-saml-field-evidence` separately from the lab,
browser host, or CI job that actually observed the external peers, tunnels,
OL9/OCI eBPF host prerequisites, XDP/tc attach drills, provider, and browser
SSO behavior. It also does not collect `e2e-install` or
`content-production-readiness`; install release evidence must
come from a disposable Linux host running the installed-service smoke test, and
the rootless content-package smoke remains demo mechanics evidence only. It
does collect `webui-enterprise-smoke`, so run this rootless bundle from a
supported remote browser validation host or CI job with Node.js, Playwright,
Chromium, and enough budget for the full desktop enterprise sweep.

## Enterprise Functional Hardening-Deferred Mode

Production release verification remains strict. `make release-verify` and
`make release-acceptance-verify` still require all production certification
gates, except the established no-performance-claims handling for
`release-benchmark`.

The opt-in functional hardening-deferred contract may defer only four
production-certification items:

- `content-production-readiness`
- `m3-field-evidence`
- `m5-oidc-field-evidence`
- `m5-saml-field-evidence`

Functional acceptance still requires recorded passing evidence for
`proto-verify`, `privileged-integration`, `deploy-hardening`,
`policy-restore-drill`, `ha-readiness-recovery`, `e2e-install`,
`content-package-verification`, `release-benchmark` or explicit
no-performance-claims mode, `m3-live-networking`, `ebpf-ol9-field-evidence`,
`m5-auth-ui`, `m5-oidc-provider`, and `webui-enterprise-smoke`.

Do not claim `ngfwrelease verify` accepts a hardening-deferred manifest unless
the current CLI exposes that flag on `verify`. The Makefile provides separate
status and assemble wrappers for the current `ngfwrelease status` and
`ngfwrelease assemble --functional-hardening-deferred` contract:

```sh
make release-acceptance-status-functional VERSION=<tag> COMMIT=<full-commit>
make release-acceptance-assemble-functional VERSION=<tag> COMMIT=<full-commit> \
  RELEASE_OPERATOR="$USER" \
  RELEASE_EVIDENCE_DIR=release/evidence \
  RELEASE_BENCHMARK_SUMMARY=perf/release-results/<run>/summary.json
```

Those wrappers are not production certification shortcuts and do not change the
strict `release-acceptance-verify` or `release-verify` targets.

Release evidence targets can also be run one at a time. The
`release-evidence-privileged-integration` target is not rootless; run it only on
a Linux host or CI runner with the required dataplane privileges.

```sh
COMMIT="$(git rev-parse HEAD)" make release-evidence-proto-verify
COMMIT="$(git rev-parse HEAD)" make release-evidence-privileged-integration
COMMIT="$(git rev-parse HEAD)" make release-evidence-deploy-hardening
COMMIT="$(git rev-parse HEAD)" make release-evidence-policy-restore-drill
COMMIT="$(git rev-parse HEAD)" make release-evidence-e2e-install
COMMIT="$(git rev-parse HEAD)" make release-evidence-content-package-verification
COMMIT="$(git rev-parse HEAD)" make release-evidence-content-production-readiness
COMMIT="$(git rev-parse HEAD)" make release-evidence-m3-live-networking
COMMIT="$(git rev-parse HEAD)" make release-evidence-m3-field-evidence
COMMIT="$(git rev-parse HEAD)" make release-evidence-ebpf-ol9-field-evidence
COMMIT="$(git rev-parse HEAD)" make release-evidence-m5-auth-ui
COMMIT="$(git rev-parse HEAD)" make release-evidence-m5-oidc-provider
COMMIT="$(git rev-parse HEAD)" make release-evidence-m5-oidc-field-evidence
COMMIT="$(git rev-parse HEAD)" make release-evidence-m5-saml-field-evidence
COMMIT="$(git rev-parse HEAD)" make release-evidence-webui-enterprise-smoke
COMMIT="$(git rev-parse HEAD)" make release-evidence-release-benchmark
```

`release-evidence-proto-verify` requires the API contract to be clean against
the release commit after regeneration. Staged, unstaged, and untracked API
contract inputs (`api/proto`, `api/openapi.yaml`, `buf.yaml`, `buf.gen.yaml`,
and `cmd/ngfwopenapi`) are rejected, as are staged, unstaged, and untracked
generated files/spec copies. This keeps evidence from pointing at a commit that
does not contain both the API inputs and the generated outputs it claims to
verify. Run `make proto-status` for a read-only drift breakdown when this gate
fails.

`release-evidence-privileged-integration` wraps
`make privileged-integration-evidence-check`, which runs the no-skip wrapper
around `make integration-test`, and is not part of the rootless bundle. Run it
only on a Linux host or CI runner that can exercise the nftables, network
namespace, packet capture, and live traffic integration tests without skipping
the privileged coverage it is meant to prove.

Record production content readiness separately after collecting the signed
App-ID, Threat-ID, and intel-feed package evidence bundle:

```sh
make content-production-readiness-check \
  CONTENT_PRODUCTION_EVIDENCE_DIR=release/field-evidence/content-production

COMMIT="$(git rev-parse HEAD)" make release-evidence-content-production-readiness \
  CONTENT_PRODUCTION_EVIDENCE_DIR=release/field-evidence/content-production
```

`release-evidence-deploy-hardening` records the deploy-hardening preflight:

```sh
bash release/deploy-hardening-check.sh --check

COMMIT="$(git rev-parse HEAD)" make release-evidence-deploy-hardening
```

The first command is the static validator. The second command records the same
check through `ngfwrelease record` into
`release/evidence/deploy-hardening.txt`, binding stdout, command, timestamp,
operator detail, and commit to the release evidence artifact.

It statically checks the packaged deployment artifacts only: the shipped
`deploy/systemd/controld.service` and `deploy/install.sh`. The service unit
must keep loopback management listeners, auth-by-default, no `--tls=false` or
unauthenticated dev bypass, no dry-run mode, systemd sandbox directives,
bounded capabilities, and root-only state/config paths. The installer must keep
root-only state/log/config directories, hashed bootstrap users, 0600 secret
files, and an explicit opt-in guard around the legacy remote Vector installer.
This gate does not start `controld`, install packages, expose management
listeners, rotate secrets, prove runtime RBAC, or certify live host hardening.
It is required release evidence for the packaged deployment posture, but it
does not replace `m5-auth-ui`, `m5-oidc-provider`,
`m5-oidc-field-evidence`, `m5-saml-field-evidence`, `e2e-install`, privileged
integration, or the later hardening pass.

The content-package verification smoke is part of `make release-check-rootless`
and can be run directly without production content or root privileges:

```sh
make content-package-smoke
```

It creates signed demo packages in temp directories, installs them into a temp
content data root, verifies provenance, regression, signature, and rollback
behavior, and records the proof in normal `go test -v` output. Release
acceptance requires this output to be recorded through
`make release-evidence-content-package-verification`; package-only unit test
evidence is rejected by `ngfwrelease verify`.

This smoke is demo-only package mechanics evidence. `ngfwrelease record` stores
that boundary as structured `content_readiness` metadata with
`production_content=false` and `production_ready=false`, and `ngfwrelease
verify` rejects stale artifacts that omit the metadata or claim production
content readiness from the demo smoke. Production App-ID, Threat-ID, and
intel-feed content still needs signed package status with
`content_readiness.scope=production`, `production_content=true`, and
`production_ready=true` before release notes can claim production content
readiness.

Field evidence bundle validators require a root `manifest.sha256` file. The
manifest is in ordinary `sha256sum` format and must list every regular evidence
file except itself. Validators reject missing manifest entries, unexpected
entries, digest mismatches, symlinks, path escapes, and any extra regular file
outside the expected bundle policy. For M3 the exact file set follows the
selected `--require` scopes; for eBPF OL9, OIDC field evidence, and content
production readiness it is the full required layout documented by each check.

The package-level production readiness check is intentionally stricter than the
smoke. For each kind, the release validator reads only the release-local
`status.json` and referenced `evidence/*.json` files under that kind directory;
do not provide separate `package-status.json` or `manifest.json` inputs for
this gate. Evidence artifacts must live under `evidence/`, use `.json`
filenames, be non-empty valid JSON, and have matching SHA-256 values and
timestamps in `content_readiness.evidence[]`. The root `manifest.sha256`
separately hash-binds the complete status/evidence file set and rejects
unreferenced notes or partial bundles. The required evidence is kind-specific:

| Package kind | Required evidence types |
|---|---|
| `app-id` | `app-taxonomy`, `confidence-model`, `app-regression-corpus`, `license-review`, `staged-rollout`, `rollback-drill` |
| `threat-id` | `threat-taxonomy`, `pcap-regression-corpus`, `false-positive-regression`, `license-review`, `staged-rollout`, `rollback-drill` |
| `intel-feeds` | `feed-registry`, `parser-tests`, `license-review`, `false-positive-regression`, `staged-rollout`, `rollback-drill` |

The release-level production readiness check is
`content-production-readiness`, not `content-package-verification`. Place the
validator input under `release/field-evidence/content-production` by default:

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

Each `status.json` must come from the installed package status API or
`ngfwctl intel content` after the signed production package has been installed
or staged in the release lab. It must declare the package kind,
`state=verified`, `signature_status=verified`, `regression_status=passed`,
verified provenance, staged or verified rollout posture, rollback
availability, no blockers, `content_readiness.scope=production`,
`production_content=true`, `production_ready=true`,
`required_production_evidence`, and package-local
`content_readiness.evidence[]` entries with matching SHA-256 values and
RFC3339 `generated_at` timestamps. The evidence JSON files must live under
`evidence/`. Unsigned notes, missing digests, symlinks, or files outside
`evidence/` are not release readiness evidence.

The validator output recorded by
`make release-evidence-content-production-readiness` must include:

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

The recorder target writes
`release/evidence/content-production-readiness.txt` through
`ngfwrelease record`. The acceptance manifest hash-binds that recorder artifact
like every other required release check.

GitHub Actions CI runs `make release-check-rootless` with
`RELEASE_NO_PERFORMANCE_CLAIMS=1`, because the ordinary PR/push gate must not
invent publishable benchmark evidence. The tagged release workflow uses the
same no-performance-claims setting by default; a performance-claiming release
must first record real benchmark evidence and change that workflow setting for
the tag.

`make release-check-rootless` also runs `make webui-enterprise-smoke`. That
gate wraps `make webui-check`, requires Node.js plus a launchable Playwright
Chromium browser, defaults to the desktop enterprise viewport, and opens the
canonical WebUI route set in app-navigation order while accepting `/dashboard`
as the Dashboard alias for `/`. It fails on browser console errors, empty
content, generic route failures, horizontal overflow, missing browser coverage,
missing JavaScript checks, unlabeled icon controls, generic operator actions
without stable hooks plus title/ARIA intent, or route-backed drawer actions
without stable accessible affordances. Direct
`node e2e/webui-visual-smoke.mjs` runs may still use targeted or fallback modes
for local debugging, but release-oriented Make targets must exercise the
browser-backed enterprise smoke path.

The CI and tagged release workflows install Node.js plus Playwright Chromium
and set `WEBUI_SMOKE_REQUIRE_BROWSER=1` before running this gate, so those jobs
must exercise the browser-backed visual smoke path rather than the HTTP/static
fallback.
The Playwright install is pinned by `PLAYWRIGHT_VERSION` in the workflows and
uses `NPM_CONFIG_CACHE=.npm-cache` so npm cache writes stay inside the
workspace.

The `m5-auth-ui` release evidence is recorded with
`make release-evidence-m5-auth-ui`, which wraps `make e2e-auth-runtime-smoke`.
That smoke starts the management plane with a temp sha256-hashed local users
file and proves missing/bad token rejection, admin/viewer RBAC, TLS serving,
HSTS and restrictive browser security headers, request body limits,
trusted-proxy rate limiting, private users-file permissions, and startup
rejection for unsafe unauthenticated management modes. Its stdout includes
`auth_runtime_smoke_scope=hashed-local-users,rbac,tls-security-headers,request-limits,rate-limit,unsafe-noauth-startup-guard`,
`auth_runtime_startup_guard=missing-auth-rejected,unauthenticated-local-requires-dry-run`,
and `status=passed` so release reviewers can see the auth posture covered by
the artifact.

The `m5-oidc-provider` release evidence is recorded with
`make release-evidence-m5-oidc-provider`, which wraps
`make e2e-oidc-runtime-smoke`. That smoke starts `controld` against a loopback
mock OIDC provider and proves provider discovery, authorization-code + PKCE,
ID-token signature validation, nonce verification, callback return routing,
session cookies, CSRF enforcement, RBAC, missing/reused state rejection, nonce
mismatch rejection, PKCE exchange-failure rejection, logout invalidation, and
viewer mutation denial. It also proves the admin-authenticated runtime provider
API can validate, enable, hot-swap, disable, and revoke an OIDC provider without
restart. Its stdout includes
`oidc_runtime_smoke_scope=provider-discovery,authorization-code-pkce,id-token-verification,nonce,session-cookie,csrf,rbac,runtime-provider-lifecycle`,
`oidc_runtime_negative_scope=missing-state,reused-state,nonce-mismatch,pkce-exchange-failure,logout,viewer-denial`,
`oidc_runtime_provider_lifecycle=api-validate,set,disable,runtime-authenticator-replacement,session-revocation`,
`oidc_runtime_provider=loopback-mock`,
`oidc_runtime_actor=smoke-admin`, and `status=passed`.

That rootless smoke does not certify a specific enterprise IdP, tenant, reverse
proxy, or public HTTPS deployment. Normal enterprise release acceptance requires
the separate `m5-oidc-field-evidence` check with redacted, real provider-backed
browser SSO evidence from the configured issuer and client.

Copy the provider-backed artifacts under `release/field-evidence/oidc`, then
validate and record the bundle:

```sh
make m5-oidc-field-evidence-check OIDC_FIELD_EVIDENCE_DIR=release/field-evidence/oidc
COMMIT="$(git rev-parse HEAD)" make release-evidence-m5-oidc-field-evidence \
  OIDC_FIELD_EVIDENCE_DIR=release/field-evidence/oidc
```

SAML provider-backed browser SSO uses the same captured-bundle pattern. Prepare
the bundle directory, copy redacted IdP/SP, ACS, browser, RBAC, and redaction
artifacts under `release/field-evidence/saml`, then validate and record the
bundle:

```sh
mkdir -p release/field-evidence/saml/{provider,deployment,browser,rbac,redaction}
make m5-saml-field-evidence-check SAML_FIELD_EVIDENCE_DIR=release/field-evidence/saml
COMMIT="$(git rev-parse HEAD)" make release-evidence-m5-saml-field-evidence \
  SAML_FIELD_EVIDENCE_DIR=release/field-evidence/saml
```

The validator does not contact the IdP or drive a browser. It accepts only a
complete redacted bundle and does not make a live SAML provider claim until the
validated output is recorded as release evidence.

Expected bundle shape:

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

The recorded validator stdout must include the bundle-scope sentinels:

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

The files must prove discovery and ID-token validation for the configured
issuer/client ID, HTTPS public redirect to `/v1/auth/oidc/callback`, private
client-secret file permissions when a secret is used, HttpOnly/SameSite session
cookies with Secure set for HTTPS public redirects, role-claim mapping into
`viewer`/`operator`/`admin`, operator mutation success only with
`X-Phragma-CSRF`, missing-CSRF or cross-origin mutation rejection, viewer
mutation denial, logout invalidation, and `oidc-session` audit/support evidence
with cookies, authorization codes, provider tokens, ID tokens, refresh tokens,
and client secrets redacted. If the deployment uses a public client with no
secret, `client-secret-file-permissions.txt` must state that no secret is
configured rather than being omitted.

Record privileged and live-networking evidence only on the host or CI job that
actually ran those checks, and record external field evidence only from the lab
where those peers, tunnels, provider sessions, and browser paths were observed.
This macOS workspace cannot honestly generate those artifacts.

The M3 live-networking entrypoint has a rootless preflight mode and a
privileged live mode:

```sh
make m3-live-networking-check
sudo make m3-live-networking
COMMIT="$(git rev-parse HEAD)" sudo -E make release-evidence-m3-live-networking
```

`m3-live-networking-check` validates that the release script, M3 policy/test
assets, and M3 live command path are present, and prints the Linux networking
prerequisites that `--run` requires. By default, `m3-live-networking` records
automated static-route live forwarding, local FRR BGP netns route programming,
and local netns WireGuard handshake/peer-traffic evidence from
`TestM3StaticRouteProgramsLiveForwarding`,
`TestM3BGPProgramsKernelRouteFromFRRPeer`, and
`TestM3WireGuardPolicyCreatesInterfaceAndPassesPeerTraffic`. External BGP
peers, IPsec, and external WireGuard client paths are validated separately with
the `m3-field-evidence` release check. The live-networking script fails rather
than recording a skipped or missing live test as release evidence.

The external M3 field-evidence bundle is required for normal release acceptance
and is the evidence source for BGP, IPsec, and external WireGuard completion
claims. Copy redacted command outputs from the external lab under
`release/field-evidence/m3`, then validate and record the bundle:

```sh
make m3-field-evidence-check M3_FIELD_EVIDENCE_DIR=release/field-evidence/m3
COMMIT="$(git rev-parse HEAD)" make release-evidence-m3-field-evidence
```

The expected bundle shape is:

```text
release/field-evidence/m3/
  bgp-external-peer/
    show-bgp-summary.txt
    ip-route-remote-prefix.txt
    frr-running-config.txt
  ipsec-strongswan-sa-traffic/
    swanctl-list-conns.txt
    swanctl-list-sas.txt
    swanctl-list-pols.txt
    ip-xfrm-state.txt
    ip-xfrm-policy.txt
    protected-subnet-ping.txt
  wireguard-external-client/
    wg-show.txt
    client-config-redacted.txt
    external-client-ping.txt
```

The validator rejects missing, empty, symlinked, or pattern-incomplete evidence
and emits `status=passed` only when the BGP, IPsec, and WireGuard evidence
sets are all present.

The OL9 eBPF field-evidence bundle can be collected with a guarded root
attach drill on a disposable OCI interface, then validated and recorded through
the existing release gate:

```sh
make ebpf-ol9-attach-drill-check
sudo -E EBPF_OL9_ATTACH_IFACE=<disposable-interface> \
  EBPF_OL9_STATUS_JSON_COMMAND='<command that prints /v1/system/status eBPF JSON>' \
  make ebpf-ol9-attach-drill EBPF_OL9_FIELD_EVIDENCE_DIR=release/field-evidence/ebpf-ol9
make ebpf-ol9-field-evidence-check EBPF_OL9_FIELD_EVIDENCE_DIR=release/field-evidence/ebpf-ol9
COMMIT="$(git rev-parse HEAD)" make release-evidence-ebpf-ol9-field-evidence
```

The attach drill refuses to run without an explicit interface and fails rather
than detaching pre-existing XDP or clsact state. The release evidence artifact
is still `ebpf-ol9-field-evidence`; the attach drill is the collector for the
redacted bundle under `release/field-evidence/ebpf-ol9`. The validator requires
`drill/manifest.txt` with the collector name, run mode, pass-through probe
source/object SHA-256 values, and `active_dataplane=nftables/conntrack` in
addition to the attach, detach, `bpftool`, status, renderer, and cleanup files.

Record the broader privileged integration check from the Linux host or CI job
that ran it:

```sh
go run ./cmd/ngfwrelease record \
  --evidence-dir release/evidence \
  --check privileged-integration \
  --commit "$(git rev-parse HEAD)" \
  --detail "root real-engine integration on disposable Linux host" \
  -- sudo /tmp/openngfw-itest -test.v -test.timeout 300s
```

For performance-claiming releases, `release-evidence-release-benchmark` records
the benchmark verifier output from `make benchmark-verify-release`.

```sh
go run ./cmd/ngfwrelease assemble \
  --manifest release/acceptance.json \
  --version <tag> \
  --commit "$(git rev-parse HEAD)" \
  --operator "$USER" \
  --evidence-dir release/evidence \
  --benchmark-summary perf/release-results/<run>/summary.json
```

or through Make:

```sh
make release-acceptance-assemble VERSION=<tag> COMMIT=<full-commit> \
  RELEASE_OPERATOR="$USER" \
  RELEASE_EVIDENCE_DIR=release/evidence \
  RELEASE_BENCHMARK_SUMMARY=perf/release-results/<run>/summary.json
```

If the tag publishes no performance claims, do not create
`release/evidence/release-benchmark.txt`; run the rootless path with
`RELEASE_NO_PERFORMANCE_CLAIMS=1` and assemble with the same flag so the
manifest marks `release-benchmark` as `not_applicable`:

```sh
COMMIT="$(git rev-parse HEAD)" RELEASE_NO_PERFORMANCE_CLAIMS=1 make release-evidence-rootless

go run ./cmd/ngfwrelease assemble \
  --manifest release/acceptance.json \
  --version <tag> \
  --commit "$(git rev-parse HEAD)" \
  --operator "$USER" \
  --evidence-dir release/evidence \
  --no-performance-claims \
  --no-performance-detail "This tag publishes no throughput, latency, connection-rate, or comparison claims."
```

or through Make:

```sh
RELEASE_NO_PERFORMANCE_CLAIMS=1 make release-acceptance-assemble \
  VERSION=<tag> COMMIT=<full-commit> \
  RELEASE_OPERATOR="$USER" \
  RELEASE_EVIDENCE_DIR=release/evidence
```

Tagged releases verify that manifest with:

```sh
make release-acceptance-verify VERSION=<tag> COMMIT=<full-commit>
```

Functional hardening-deferred assemblies use the separate wrapper, not the
production verifier:

```sh
make release-acceptance-assemble-functional VERSION=<tag> COMMIT=<full-commit>
```

That path is acceptable only for enterprise functional acceptance and only when
the four deferred items above are the missing production-certification gates.

To inspect evidence collection progress before assembly, run:

```sh
make release-acceptance-status VERSION=<tag> COMMIT=<full-commit>
```

The status command is an inventory report only. The Makefile wrapper includes
the human `--recordability` preflight so operators can see whether the current
git checkout is clean enough for `ngfwrelease record`; only dirty files under
`release/evidence/`, `release/field-evidence/`, and `perf/release-results/` are
allowed during evidence capture. It can show recorded, missing, invalid, and
not-applicable checks and can emit JSON via
`go run ./cmd/ngfwrelease status --json`, but `--recordability` is not combined
with JSON and status output does not replace `release-acceptance-assemble` or
`release-acceptance-verify`.

To scaffold the expected shape without creating passing evidence, run:

```sh
go run ./cmd/ngfwrelease template --output release/acceptance.template.json
```

That template is intentionally rejected by the verifier until the schema,
statuses, timestamps, digests, and artifacts are replaced with real release
evidence. It is a non-evidence planning aid only: do not rename it to
`release/acceptance.json`, attach it to a tag, or treat `todo`, placeholder
timestamps, zero digests, or example artifact paths as satisfying any production
release acceptance check.

The status CLI and its JSON/API-facing report use the same acceptance rules as
verification. A template schema, `todo` status, placeholder timestamp, zero
digest, hand-written note, or any file that is not
`phragma.release.evidence.v1` recorder JSON is reported as `invalid`, not
`passed` and not `not_applicable`. The only explicit `not_applicable` release
path is `release-benchmark` when `RELEASE_NO_PERFORMANCE_CLAIMS=1` /
`--no-performance-claims` is set and the detail says that the tag publishes no
throughput, latency, connection-rate, comparison, or other performance claims.

Normal production release acceptance still requires bounded evidence for each
gate. The static deploy-hardening artifact proves only packaged service and
installer defaults; it does not replace live install evidence, privileged
integration, browser/SSO field evidence, production content readiness, external
M3/eBPF observations, or the later host-hardening pass.

Put release-local evidence files under `release/evidence/` using the required
check names, for example `release/evidence/proto-verify.txt`. `ngfwrelease
assemble` references them from the manifest as paths relative to
`release/acceptance.json`, for example `evidence/proto-verify.txt`. Each
passing check also records `artifact_sha256`; artifact paths must not be
absolute, must stay under `evidence/`, must not escape by symlink resolution,
must not be reused across checks, and must not be empty.
The verifier also parses every artifact as `phragma.release.evidence.v1`
recorder JSON, checks that the recorded check name and commit match the
manifest, requires exit code `0` plus operator detail, and enforces approved
commands for stable checks.

Performance claim evidence is curated separately under `perf/release-results/`.
For performance-claiming releases, the `release-benchmark` check must set
`benchmark_summary` to the selected `perf/release-results/<run>/summary.json`;
the verifier loads that summary and requires the strict publishable performance
gate to pass. The `release-benchmark` manifest artifact should record the
selected run and the output of `make benchmark-verify-release`. If a tag
publishes no performance claims, use `RELEASE_NO_PERFORMANCE_CLAIMS=1`, set
`no_performance_claims: true`, and mark the `release-benchmark` check
`not_applicable` with an explicit detail:

```sh
go run ./cmd/ngfwrelease assemble \
  --manifest release/acceptance.json \
  --version <tag> \
  --commit "$(git rev-parse HEAD)" \
  --operator "$USER" \
  --evidence-dir release/evidence \
  --no-performance-claims \
  --no-performance-detail "This tag publishes no throughput, latency, connection-rate, or comparison claims."
```
