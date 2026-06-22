# Component Fit Review

This review decides where existing open-source components fit and where Phragma must build first-party product layers.

## Fit Summary

| Component | Fit | Decision |
|---|---:|---|
| Linux/eBPF/XDP/tc | Excellent | Build first-party dataplane agent and eBPF programs. |
| nftables/conntrack | Excellent | Use for stateful firewall and NAT correctness. |
| FRRouting | Excellent | Use for routing; render config through Phragma. |
| Suricata | Excellent as engine | Use as v1 IDS/IPS matching engine, not Threat-ID product. |
| nDPI | Good as signal | Use as App-ID signal source, not App-ID product. |
| Zeek | Good | Use for telemetry and metadata, not inline v1. |
| Envoy | Excellent | Use for L7 proxy, API gateway, and selected transparent/explicit proxy paths. |
| Coraza | Good | Use for WAF through Envoy/proxy path. |
| strongSwan | Excellent | Use for IPsec/IKEv2. |
| WireGuard | Excellent | Use kernel WireGuard for modern tunnels. |
| OpenZiti | Good strategic fit | Use as ZTNA module, not base firewall architecture. |
| zfw | Interesting | Evaluate as reference or optional ZTNA/eBPF component; do not anchor v1 on it. |
| CrowdSec | Good adjunct | Integrate reputation/remediation model; do not make it the threat intel authority. |
| MISP | Good external service | Integrate via API; do not embed in appliance runtime. |
| T-Pot | Good external telemetry | Use for honeypot programs; do not ship as on-box runtime. |
| CAPEv2 | Good external sandbox | Pluggable detonation target; not required local component. |
| OPA/Rego | Limited | Use for config/compliance/control-plane checks, not packet decisions. |
| Cedar | Good for authz | Consider for API/UI authorization, not firewall policy. |

## Product Boundary Rule

**HARD REQUIREMENT:** Phragma owns:

- policy object model
- candidate/commit/rollback
- dataplane agent
- flow identity
- verdict bus
- log schema
- explanation engine
- App-ID taxonomy, confidence, and evidence
- Threat-ID metadata, profile, and QA layer
- UI, CLI, and API

External engines provide specialized functions behind adapters. They do not define the user model.

## Suricata

Fit: strong v1 IDS/IPS matching engine.

Why:

- Suricata is built for IDS, IPS, and network security monitoring.
- It supports app-layer protocol parsing, EVE JSON, file extraction, and rule management through suricata-update.
- It has the maturity needed for a serious v1.

Limits:

- Suricata is not a complete Threat-ID product.
- Rule selection, false-positive control, severity/confidence scoring, staged rollout, exception handling, and explanation are Phragma responsibilities.
- Inline performance depends on CPU, traffic profile, ruleset, flow steering, and bypass logic.

Decision:

- Use Suricata without forking initially.
- Build a first-party Phragma Threat-ID service around it.
- Patch or fork only if regression tests prove an engine gap that cannot be solved externally.

## nDPI

Fit: useful App-ID signal source.

Why:

- nDPI provides deep packet inspection and protocol/application classification.
- It can accelerate v1 App-ID coverage.

Limits:

- nDPI classification is not a full App-ID system.
- Encrypted traffic, QUIC, SaaS/CDN drift, custom apps, and confidence scoring require Phragma product work.

Decision:

- Use nDPI behind an adapter.
- Build first-party Phragma App-ID code around it.
- Combine nDPI with DNS, TLS, QUIC, HTTP, Suricata, future Zeek metadata, destination reputation, and behavioral evidence.

## Linux/eBPF, nftables, And FRR

Fit: best v1 dataplane foundation.

Why:

- Linux/eBPF allows appliance-grade packet handling while staying close to normal Linux operations.
- nftables/conntrack provides mature stateful firewall and NAT behavior.
- FRR provides mature routing protocols and integrates with Linux networking.

Limits:

- Kernel, NIC, cloud driver, and XDP support vary.
- eBPF verifier and helper licensing constraints must be handled intentionally.
- Direct Linux state mutation must be controlled through Phragma renderers.

Decision:

- Use Linux/eBPF as the v1 dataplane backend.
- Treat XDP as an acceleration hook, not a correctness dependency.
- Use FRR rather than building routing protocols.

## Envoy And Coraza

Fit: best v1 L7 path.

Why:

- Envoy has dynamic xDS configuration and mature L4/L7 proxy capabilities.
- Coraza provides a Go WAF with OWASP CRS compatibility and proxy-wasm/Envoy integration paths.

Limits:

- Not all firewall traffic should pass through Envoy.
- WAF rules require tuning and false-positive handling.

Decision:

- Use Envoy/Coraza for explicit L7 paths.
- Normalize WAF/API verdicts into Phragma logs and explanations.

## OpenZiti And zfw

Fit: strong ZTNA direction, not core dataplane.

Why:

- OpenZiti's identity-first service access model fits a modern NGFW better than IP-only VPN thinking.
- zfw shows useful eBPF/firewall integration ideas for Ziti environments.

Limits:

- ZTNA cannot replace the base firewall, routing, NAT, VPN, IDS/IPS, and inspection functions.
- zfw should not become an unexamined v1 dataplane dependency.

Decision:

- Integrate OpenZiti as a ZTNA module.
- Evaluate zfw as reference or optional module after the core dataplane design stabilizes.

## External Intelligence And Sandbox Tools

CrowdSec, MISP, T-Pot, and CAPEv2 are valuable but should not be embedded as required appliance runtime components.

Decision:

- CrowdSec: integrate decisions, reputation signals, and remediation patterns.
- MISP: ingest/export threat intel through APIs; keep it external.
- T-Pot: use for honeypot telemetry programs.
- CAPEv2: support as a submit-to-sandbox target.

## Primary References

- [Suricata documentation](https://docs.suricata.io/en/).
- [nDPI repository](https://github.com/ntop/nDPI).
- [FRRouting documentation](https://docs.frrouting.org/).
- [Envoy xDS documentation](https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol.html).
- [strongSwan documentation](https://docs.strongswan.org/docs/latest/howtos/introduction.html).
- [Cilium eBPF datapath documentation](https://docs.cilium.io/en/stable/network/ebpf/index.html).
- [OWASP Coraza documentation](https://www.coraza.io/docs/).
- [CrowdSec concepts](https://docs.crowdsec.net/docs/concepts).
- [MISP license overview](https://www.misp-project.org/license/).
