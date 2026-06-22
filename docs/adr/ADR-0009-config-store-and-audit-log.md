# ADR-0009: Config Store And Audit Log

Status: Accepted

## Context

Candidate configuration, commit, rollback, and audit are core firewall behavior. v1 needs a durable local store without introducing a distributed database.

## Decision

Use SQLite with WAL mode on day 1.

- **HARD REQUIREMENT:** Candidate and running configuration are transactional and stored separately.
- **HARD REQUIREMENT:** A bad candidate must not corrupt running configuration.
- **HARD REQUIREMENT:** Audit events are immutable and append-only.
- **HARD REQUIREMENT:** Rollback is snapshot-based.
- **HARD REQUIREMENT:** Schema migrations are explicit, versioned, forward-only by default, and tested against existing snapshots.
- **HARD REQUIREMENT:** The config store is single-writer.

## Consequences

Single-node v1 stays simple and durable.

Future fleet management may replicate or consume state, but it must not weaken local transaction and audit semantics.
