# ADR-0010: Verdict Bus Transport

Status: Accepted

## Context

Phragma needs normalized engine decisions without adding distributed messaging infrastructure to the first single-node appliance.

## Decision

The v1 verdict bus is a local Unix-domain gRPC stream plus a persisted event sink.

The persisted sink may be SQLite or an append-only local log. NATS is not a v1 dependency.

- **HARD REQUIREMENT:** Verdict events use one envelope: flow id, verdict, evidence, engine source, config version, and timestamp.
- **HARD REQUIREMENT:** Policy-class events are never silently dropped.
- **HARD REQUIREMENT:** Under backpressure, telemetry-class events are dropped before policy-class events.
- **HARD REQUIREMENT:** Any dropped telemetry must be counted and visible in platform metrics.

## Consequences

v1 remains locally operable and testable. A future broker can be added behind the same envelope if fleet or HA requirements justify it.
