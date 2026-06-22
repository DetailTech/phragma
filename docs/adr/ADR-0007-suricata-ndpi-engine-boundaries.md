# ADR-0007: Suricata And nDPI Engine Boundaries

Status: Accepted

## Context

Suricata and nDPI are strong open-source components, but neither is a full Palo Alto-class Threat-ID or App-ID product by itself.

Suricata is a matching engine. nDPI is a classifier signal source. Phragma must own the product layers around them.

## Decision

Use Suricata as the v1 IDS/IPS matching engine.

Use nDPI as one v1 App-ID signal source.

Phragma owns:

- App-ID taxonomy
- App-ID evidence and confidence
- custom application definitions
- encrypted-traffic heuristics
- app update packages
- threat metadata
- threat profile compilation
- false-positive controls
- PCAP regression
- exception workflows
- explanations

Do not fork Suricata or nDPI initially. Patch or fork only if measured gaps cannot be solved through adapters, configuration, content, or upstream contribution.

## Consequences

The project gets mature IDS/IPS and DPI foundations without letting those engines define the product. App-ID and Threat-ID quality become first-party Phragma responsibilities.
