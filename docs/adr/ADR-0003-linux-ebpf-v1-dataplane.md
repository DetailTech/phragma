# ADR-0003: Linux/eBPF v1 Dataplane

Status: Accepted

## Context

The project evaluated VPP, eBPF/XDP, and hybrid approaches. v1 targets cloud/virtual NGFW scenarios where operational simplicity, cloud NIC compatibility, and Linux integration matter more than physical-appliance 100 Gbps dataplane optimization.

For an NGFW, the main performance risk is not simple forwarding. It is userspace inspection: IDS/IPS, App-ID, TLS handling, proxying, WAF, file inspection, and logging.

## Decision

v1 uses one dataplane backend: Linux/eBPF.

The backend includes:

- XDP where available for early drop and fast pre-policy.
- tc ingress/egress for broader compatibility.
- nftables/conntrack for stateful firewall and NAT.
- FRR for routing protocols.
- explicit userspace inspection handoff.

XDP is not required for correctness. If native XDP is unavailable, Phragma remains functional through tc and nftables/conntrack.

VPP, DPDK, and AF_XDP are deferred future backend options.

## Consequences

v1 avoids a multi-backend implementation tax. The dataplane abstraction must still exist so future VPP support can be added without rewriting the product model.

eBPF program licensing must be reviewed deliberately because GPL-gated helpers and kernel expectations may affect license choices.
