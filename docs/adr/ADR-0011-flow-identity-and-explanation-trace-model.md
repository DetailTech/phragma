# ADR-0011: Flow Identity And Explanation Trace Model

Status: Accepted

## Context

Explanations require all engines to describe the same flow. Engine-native IDs are not enough.

## Decision

Canonical flow identity is:

- 5-tuple
- ingress zone
- ingress interface
- running config version
- monotonic flow ID

A trace ID is propagated across dataplane, inspection, logging, and explanation paths.

- **HARD REQUIREMENT:** eBPF attaches or looks up the monotonic flow ID at first classification.
- **HARD REQUIREMENT:** nftables/conntrack state is joined by flow ID and 5-tuple.
- **HARD REQUIREMENT:** Suricata EVE events are joined by flow ID where tagged, then by normalized tuple and time window.
- **HARD REQUIREMENT:** nDPI classification is recorded against the flow ID and trace ID.
- **HARD REQUIREMENT:** Envoy access logs carry the trace ID and are joined back to flow ID.
- **HARD REQUIREMENT:** Explanation data is stored locally and queryable through the public explanation API for its retention window.
- **HARD REQUIREMENT:** Explanation records are written at decision time, queryable by flow ID or flow identity, and expired only by configured retention.

## Consequences

The explanation engine can answer across packet, stateful firewall, IDS/IPS, App-ID, and proxy paths without exposing engine-native models as the product model.
