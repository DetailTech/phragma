# ADR-0016: TLS Termination Versus Decryption

Status: Accepted

## Context

Proxy TLS termination and general TLS decryption are often conflated. They have different security, custody, policy, and audit requirements.

## Decision

Milestone 6 covers proxy TLS termination only: server-side certificate handling for inbound traffic to the proxy path.

- **HARD REQUIREMENT:** M6 TLS termination does not imply general MITM TLS decryption.
- **HARD REQUIREMENT:** General TLS decryption, broker, or mirror behavior is future scope.
- **HARD REQUIREMENT:** Future decryption requires separate policy, exception lists, key custody, and audit design.

## Consequences

Agents must not implement decryption behavior while building the M6 proxy path. TLS termination can ship without pretending the full decryption product exists.
