# ADR-0019: Public Generated TLS Runtime Classification

Status: Accepted

Date: 2026-06-30

Supersedes: the runtime `degraded` and `critical` reporting decision in
[`ADR-0018`](ADR-0018-management-tls-trust-posture.md)

## Context

ADR-0018 established the trust boundary for generated self-signed TLS on a
non-loopback management listener: explicit operator acknowledgement, test-only
use, authentication, limited endpoint trust, and exclusion from shipped
packaged units. It also classified that acknowledged posture as degraded with a
critical runtime warning.

An operator who explicitly selects this bounded test posture has already
acknowledged the certificate limitation. Treating that selection as runtime
degradation conflates an intentional test trust choice with service health.

## Decision

- `--allow-public-self-signed-tls` remains an explicit test-only operator
  acknowledgement. Startup logging records use of the exception.
- The acknowledged certificate choice does not by itself make runtime status
  degraded or generate a critical readiness condition.
- The exception does not relax authentication. Generated material remains
  SAN/trust-limited and is not production trust; operators must replace it with
  an endpoint-matching, operator-managed certificate before production.
- Shipped packaged units remain loopback-only, do not enable the exception, and
  must continue to fail the deploy-hardening gate if they include it.
- All other decisions and consequences in ADR-0018 remain in effect.

## Consequences

- Runtime health reflects service and guardrail failures rather than an
  explicitly selected test certificate posture.
- The required flag and startup log preserve operator acknowledgement and
  operational visibility without labeling the test runtime unhealthy.
- Production certificate issuance, endpoint-name matching, private-key custody,
  rotation, and live exposure validation remain release requirements.
