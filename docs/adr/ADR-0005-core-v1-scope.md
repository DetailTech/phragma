# ADR-0005: Core v1 Scope

Status: Accepted

## Context

The long-term NGFW scope is large. Without a hard v1 cut, contributors may build disconnected features instead of a credible appliance.

## Decision

Core v1 is a single-node cloud/virtual NGFW.

Required v1 scope:

- local control-plane API
- candidate/commit/rollback
- local audit log
- zone-based firewall
- NAT
- routing integration
- Linux/eBPF dataplane
- Suricata-backed IDS/IPS
- nDPI-assisted App-ID
- verdict bus
- flow logs
- explanation API
- CLI and WebUI for the core workflow
- cloud VM install path
- benchmark harness

Out of v1:

- VPP backend
- physical appliances
- active/active HA
- full fleet management
- Kubernetes-native deployment
- managed sandbox service

## Consequences

The project can make a complete first appliance instead of scattering effort. Eventual features remain open source, but they must not distract from v1.
