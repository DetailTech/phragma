# ADR-0018: Management TLS Trust Posture

Status: Accepted

Date: 2026-06-29

## Context

Phragma generates a self-signed certificate for loopback WebUI and REST use so
first boot does not require external PKI. A temporary lab may also need direct
non-loopback access before an operator certificate is available. Treating that
case as an unconditional default would hide the missing public trust boundary.

## Decision

- Direct gRPC management remains loopback-only.
- A non-loopback WebUI/REST listener requires an operator-provided
  `--tls-cert` and `--tls-key` by default.
- Generated self-signed TLS on a non-loopback listener requires the explicit
  `--allow-public-self-signed-tls` acknowledgement.
- That opt-in is temporary lab posture: system status stays degraded and emits
  a critical warning. Generated material may not contain a SAN for the public
  endpoint, so operators must use a controlled path such as an SSH tunnel or
  explicit browser exception and replace the certificate before production.
- The shipped systemd unit remains loopback-only, does not set the opt-in, and
  the deploy-hardening gate rejects any packaged unit that does.

This decision covers management-server TLS only. It does not authorize TLS
interception, a MITM CA, or custom cryptographic implementation.

## Consequences

- Temporary public access is possible without weakening authentication,
  cleartext-listener, rate-limit, or request-boundary controls.
- Operators receive an explicit, persistent signal that encryption is present
  but publicly trusted endpoint identity is not.
- Production deployment still requires certificate issuance, endpoint-name
  matching, private-key custody, rotation, and live exposure validation.
