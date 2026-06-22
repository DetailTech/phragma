# ADR-0015: Phragma Observability

Status: Accepted

## Context

Operators need to know whether Phragma itself is healthy before they interpret traffic telemetry.

## Decision

Phragma exposes Prometheus `/metrics` for its own internals on day 1.

- **HARD REQUIREMENT:** Platform metrics cover Phragma health, queues, drops, store state, engine state, and backpressure.
- **HARD REQUIREMENT:** Traffic telemetry covers flows, verdicts, and inspected events.
- **HARD REQUIREMENT:** Structured logs are JSON.
- **HARD REQUIREMENT:** OTLP is an export path, not a required local dependency.

## Consequences

The appliance can be operated locally without an observability stack. External telemetry integrations can be added without changing the internal health model.
