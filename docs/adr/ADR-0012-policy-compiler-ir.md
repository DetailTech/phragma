# ADR-0012: Policy Compiler IR

Status: Accepted

## Context

Renderer-specific validation creates conflicting answers. Users need one trustworthy plan before running state changes.

## Decision

The policy compiler uses a typed intermediate representation between API policy and backend renderers.

- **HARD REQUIREMENT:** All validation operates on the IR.
- **HARD REQUIREMENT:** Dry-run operates on the IR.
- **HARD REQUIREMENT:** Diff operates on the IR.
- **HARD REQUIREMENT:** Backends are pure functions of IR plus backend capability metadata.
- **HARD REQUIREMENT:** Users see one trustworthy plan diff, not unrelated per-renderer diffs.

## Consequences

Renderer code becomes easier to test and replace. Backend quirks are still visible, but they cannot redefine policy semantics.
