# ADR-0006: Threat Intel Feed Governance

Status: Accepted

## Context

Threat intelligence quality is a major NGFW differentiator. Phragma should federate open feeds, community telemetry, honeypots, sandbox output, and administrator-provided intelligence. Feed licensing and false positives can create technical, legal, and trust problems.

## Decision

Every feed must have a registry entry before use.

The registry tracks:

- source
- license
- redistribution rights
- attribution requirements
- data type
- update cadence
- confidence
- false-positive risk
- parser
- tests
- owner

Official content updates require parser tests, schema validation, license validation, PCAP regression where applicable, performance impact review, staged rollout, and rollback.

## Consequences

Phragma can build a transparent threat-content pipeline without copying incumbent black-box models. Content release discipline becomes mandatory from the start.
