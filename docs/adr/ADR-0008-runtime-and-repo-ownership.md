# ADR-0008: Runtime And Repo Ownership

Status: Accepted

## Context

Phragma needs clear language ownership before implementation starts. Mixed-language repos are acceptable only when each language has a durable boundary.

## Decision

Phragma uses these runtime defaults:

- **HARD REQUIREMENT:** Go owns the control plane, policy compiler, CLI, and orchestration adapters.
- **HARD REQUIREMENT:** Rust owns the userspace dataplane agent.
- **HARD REQUIREMENT:** C is limited to eBPF and kernel-facing programs. C must not creep into userspace services.
- **HARD REQUIREMENT:** TypeScript and React own the WebUI.
- **HARD REQUIREMENT:** Each top-level implementation directory declares its language, purpose, adapter boundary, and primary owner role.

## Consequences

Language drift becomes a design review issue, not an accidental repo habit.

FFI and generated-code boundaries must be explicit. Dataplane safety work stays in Rust unless kernel-facing eBPF code requires C.
