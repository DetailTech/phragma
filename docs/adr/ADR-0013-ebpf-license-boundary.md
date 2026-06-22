# ADR-0013: eBPF License Boundary

Status: Accepted

## Context

Linux eBPF programs may need GPL-compatible licensing for helper access and kernel expectations. That does not mean all userspace dataplane code should become reciprocal-license code.

## Decision

eBPF programs are GPL-compatible, using GPL-2.0-or-later unless legal review directs otherwise.

- **HARD REQUIREMENT:** Userspace dataplane agent code remains Apache 2.0 where possible.
- **HARD REQUIREMENT:** The loader and FFI boundary between userspace and eBPF objects is documented.
- **HARD REQUIREMENT:** SBOMs flag eBPF objects distinctly from Apache userspace artifacts.
- **HARD REQUIREMENT:** GPL-compatible eBPF objects must not create reciprocal license bleed into Apache userspace code.

## Consequences

The project can use Linux eBPF correctly while preserving a clear first-party userspace license boundary.
