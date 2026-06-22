# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** via
[GitHub Security Advisories](https://github.com/DetailTech/oss-ngfw/security/advisories/new)
for this repository. Do not open public issues for security reports.

We aim to acknowledge reports within 7 days. Coordinated disclosure timelines
are agreed per report; our default is 90 days.

## Scope

Phragma integrates external engines (Suricata, FRR, strongSwan, nftables, ...)
as separate processes. Vulnerabilities in those engines should be reported
upstream; vulnerabilities in how *this project* configures, supervises, or
exposes them belong here.

## Deployment hardening

Keep management listeners on trusted networks. Enable authentication with
`--users-file`, OIDC, or both before exposing the API or WebUI. REST/WebUI/OIDC
and direct gRPC requests are rate-limited per client by default
(`--rate-limit-rpm 600 --rate-limit-burst 120`); disabling rate limits with
`--rate-limit-rpm 0` is for isolated debugging only. If REST/WebUI is served
behind a reverse proxy or non-source-preserving load balancer, set
`--trusted-proxy-cidrs` to the proxy CIDRs; `X-Forwarded-For` and
`X-Forwarded-Proto` are ignored from all other peers. Phragma uses the rightmost
untrusted valid forwarded address as the REST/WebUI rate-limit key, and uses the
trusted forwarded scheme for OIDC browser CSRF same-origin checks, so the proxy
must strip or overwrite untrusted inbound forwarding headers before adding the
real client address and public scheme. Keep the default management-plane size
and timeout caps unless an explicitly tested deployment needs larger policy or
telemetry payloads (`--http-max-body-bytes`, `--http-max-header-bytes`,
`--grpc-max-recv-bytes`, `--grpc-max-send-bytes`, and the `--http-*-timeout`
flags).
Local users files should store `token_hash: sha256:<digest>` entries rather
than plaintext `token:` values. The loader still accepts legacy plaintext token
files to avoid upgrade lockouts, but newly generated installs keep the only
plaintext admin token copy in `/etc/openngfw/admin.token` mode `0600`. Users
files and OIDC client-secret files must be regular private files owned by root
when `controld` runs as root, or by the current daemon user/root for non-root
development runs.
Prefer `ngfwctl --token-file`, `NGFW_TOKEN_FILE`, or `--token-stdin` over
placing bearer tokens in shell history.
The direct gRPC management listener must remain loopback-only until a gRPC
TLS/mTLS transport is added. Remote operators should use the HTTPS WebUI/REST
gateway; `--tls=false` is refused for non-loopback REST listeners.
The gateway sends restrictive browser security headers for both the WebUI and
REST API, including frame denial, no-referrer, cross-origin opener/resource
policy, a no-object/no-frame content security policy, and a permissions policy
that disables browser sensors such as camera, microphone, geolocation, USB, and
serial access. HSTS is sent only when the gateway is serving TLS directly.
For browser SSO, set `--oidc-redirect-url` to the public HTTPS callback URL.
Phragma marks OIDC session cookies `Secure` when that public redirect URL uses
`https://`, even when local REST/WebUI traffic is cleartext on loopback behind a
TLS-terminating reverse proxy. In that topology, the reverse proxy must be listed
in `--trusted-proxy-cidrs` and must set `X-Forwarded-Proto: https`.
Non-HTTPS OIDC redirect URLs are for loopback development only and are reported
as a critical readiness warning. Browser mutations authenticated by the OIDC
cookie must include the same-origin
`X-Phragma-CSRF` value from `/v1/auth/oidc/status`; direct bearer-token API
clients are not coupled to the browser CSRF mechanism.
Rootless release evidence includes `m5-oidc-provider`, a loopback mock-provider
smoke that proves discovery, authorization-code + PKCE, ID-token validation,
nonce verification, session-cookie auth, CSRF enforcement, RBAC mechanics,
negative callback rejection, logout invalidation, and viewer mutation denial.
That smoke is not a certification of a specific enterprise IdP, tenant, reverse
proxy, or public HTTPS deployment. Enterprise release acceptance requires the
separate `m5-oidc-field-evidence` check before release notes claim
deployment-specific OIDC readiness. That check validates a redacted
provider-backed bundle from the real issuer and must emit
`field_evidence_scope=real-issuer-client,...`,
`oidc_field_evidence_scope=real-provider-backed,browser-sso,...`,
`oidc_field_redaction=issuer-host-redacted,client-id-redacted,subject-redacted,email-redacted,tokens-redacted,cookies-redacted`,
and `status=passed`. The bundle must prove the configured issuer and client ID
discover and validate ID tokens, the public redirect URL is HTTPS on
`/v1/auth/oidc/callback`, the client-secret file is private when used, the
session cookie is HttpOnly/SameSite and Secure for HTTPS public redirects, and
provider role claims map to `viewer`, `operator`, or `admin` through the shared
RBAC/audit path. The same evidence must show an OIDC `operator` mutation with
`X-Phragma-CSRF` succeeds, missing-CSRF or cross-origin cookie mutations fail,
an OIDC `viewer` mutation is denied, logout invalidates the browser session,
and support bundles or copied artifacts redact client secrets, cookies,
authorization codes, provider tokens, ID tokens, and refresh tokens.

Unauthenticated management mode is not a production posture. `controld` refuses
to start without `--users-file` or OIDC unless `--allow-unauthenticated-local`
is also paired with `--dry-run` and loopback-only management listeners.

Do not embed ClickHouse credentials in telemetry policy URLs. Phragma rejects
`telemetry.clickhouse_url` values with URL userinfo or token/password/secret/key
query parameters; keep sink credentials in operator-managed engine/runtime
configuration instead. Rendered Vector config is written service-private, and
support bundles redact URL userinfo plus sensitive URL query values.

Privileged host actions such as host tuning and API-started packet capture are
audited. If a mutating action completes but its audit record cannot be written,
the API returns an error instead of reporting a clean success. Treat audit
write failures as production incidents: preserve local logs, export a support
bundle, run `ngfwctl audit verify`, and repair the state database before
continuing operational changes.

The packaged `controld.service` remains root-run because the control plane
programs nftables, routes, WireGuard interfaces, netdev settings, Suricata,
FRR, and strongSwan on a single-node firewall. The unit narrows that privilege
with `UMask=0077`, `NoNewPrivileges=yes`, `PrivateTmp=yes`,
`ProtectHome=yes`, `ProtectSystem=strict`, root-only state/log/config
directories, and a capability allowlist limited to network administration,
raw sockets, and DAC override for package-owned engine configuration files.
The only writable persistent trees are `/var/lib/openngfw`,
`/var/log/openngfw`, `/etc/openngfw`, and the distro-specific FRR/swanctl
drop-in paths used by routing and IPsec orchestration. Keep service secrets,
OIDC material, WireGuard keys, and IPsec snippets under `/etc/openngfw`; paths
under `/root`, `/home`, and `/run/user` are intentionally hidden by systemd.
`MemoryDenyWriteExecute` is explicitly left off because Suricata deployments
commonly use Hyperscan/JIT-capable pattern engines; enabling it is a
site-specific hardening experiment until Suricata runs under its own profile.

## Supply chain

Releases ship with an SBOM (syft), are signed (cosign keyless), and carry SLSA
provenance. Verify before deploying.

Production App-ID, Threat-ID, and intel-feed readiness claims require the
separate `content-production-readiness` release check. The rootless
`content-package-verification` smoke proves demo package mechanics only and
must not be used as production threat-content evidence. Production content
evidence must come from release-local
`release/field-evidence/content-production/<kind>/status.json` files for
`app-id`, `threat-id`, and `intel-feeds`. Each `status.json` must carry
`content_readiness.scope=production`, `production_content=true`,
`production_ready=true`, the exact `required_production_evidence`, and
`content_readiness.evidence[]` entries pointing at matching
`evidence/*.json` files with SHA-256 values and RFC3339 timestamps. The gate
does not accept separate `package-status.json` or `manifest.json` inputs.
Validate it with `make content-production-readiness-check` and record it with
`make release-evidence-content-production-readiness`. The rootless
`release-check-rootless` gate does not satisfy this production field evidence
gate.
