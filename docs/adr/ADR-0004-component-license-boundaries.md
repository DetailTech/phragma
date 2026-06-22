# ADR-0004: Component License Boundaries

Status: Accepted

## Context

Phragma composes multiple open-source engines with different licenses. Apache 2.0 first-party code may need to interact with GPL, LGPL, AGPL, MIT, BSD, MPL, and other licensed components.

## Decision

Phragma uses explicit component boundaries.

- First-party code should be Apache 2.0 where possible.
- GPL/LGPL components run behind process, service, or adapter boundaries unless legal review approves another design.
- AGPL services are external integrations by default.
- Component licenses are tracked in a registry.
- Release builds include SBOMs.
- eBPF program licensing is reviewed separately.

## Consequences

The project can use mature open-source engines without pretending all code has the same license. Adapter boundaries are both legal and architectural boundaries.

Legal review is required before changing link mode, embedding strategy, or redistribution behavior for sensitive components.
