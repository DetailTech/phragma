# Phragma Project Definition

Status: v0.1 foundation document.

Audience: human developers, AI coding agents, security engineers, network engineers, and future maintainers.

## Vision

Phragma exists to build a real open-source NGFW: transparent, auditable, cloud-native, automatable, and capable of competing with Palo Alto Networks VM-Series class virtual firewalls on technical capability.

**Phragma** is the product name. The word means barrier or partition, matching
the product's role as the inspectable boundary between networks. Existing
`openngfw` and `ngfwctl` implementation identifiers are compatibility details
for the v2-mixed baseline until a planned migration changes them safely.

The goal is not to imitate pfSense, OPNsense, or VyOS with a nicer UI. The goal is to build a modern firewall platform that owns its policy model, dataplane abstraction, inspection orchestration, verdict pipeline, logs, API, CLI, UI, and operational explanation layer while using mature open-source engines where that is the right engineering choice.

## Locked Project Model

- **HARD REQUIREMENT:** Phragma is 100% open source.
- **HARD REQUIREMENT:** No open-core model is allowed.
- **HARD REQUIREMENT:** No BSL enterprise repository is allowed.
- **HARD REQUIREMENT:** No entitlement checks, license gates, hidden capability flags, or paywalled features are allowed in code, configuration, docs, or tests.
- **HARD REQUIREMENT:** Fleet management, SSO, centralized logging, compliance reporting, curated intelligence tooling, and governance features remain open source when built.

Commercial work may exist around support, training, certified builds, hosted services, deployment assistance, and integration services. Commercial work must not require closing core features.

## Product Target

The v1 product target is a single-node cloud/virtual NGFW installable by one engineer in a lab or cloud tenancy. It should be benchmarked and evaluated against Palo Alto Networks VM-Series class deployments, not physical hardware flagships.

Palo Alto's public VM-Series positioning emphasizes virtual firewall deployment across public clouds and DevOps-integrated provisioning. Phragma v1 must be evaluated in that same cloud/virtual context, not as a 100 Gbps hardware dataplane project.

## Goals

- Build a production-grade single-node firewall before building fleet orchestration.
- Use Linux/eBPF as the v1 dataplane backend.
- Provide stateful zone-based firewalling, NAT, routing, VPN, IDS/IPS, App-ID baseline, L7 proxy/WAF/API gateway path, logs, API, CLI, WebUI, and candidate/commit/rollback.
- Make every packet or flow decision explainable.
- Make policy declarative and versionable.
- Build App-ID and Threat-ID as Phragma product layers, not as thin wrappers around nDPI and Suricata.
- Keep component engines isolated behind adapters for license hygiene, testability, and future replacement.
- Keep a path to federal and regulated environments: signed builds, SBOMs, FIPS strategy, STIG hardening, audit logs, and reproducible release practices.

## Non-Goals For v1

- Physical hardware appliances.
- VPP, DPDK, or AF_XDP dataplane implementation.
- Active/active HA.
- Full fleet management.
- Kubernetes-native cluster firewall deployment.
- A managed malware detonation service.
- Production certifications such as FIPS 140-3 validation, Common Criteria, DoD APL, or FedRAMP authorization.

These are not rejected forever. They are outside the first build target.

## Core v1 Scope

Core v1 means the first credible single-node virtual appliance.

Required v1 capabilities:

- Local control-plane API using versioned gRPC/OpenAPI.
- Candidate configuration, commit, validation, rollback, and local audit log.
- Zone-based stateful firewall policy.
- NAT.
- Static routing and initial FRR-backed dynamic routing integration.
- Linux/eBPF dataplane agent using XDP where available, tc where needed, and nftables/conntrack where appropriate.
- Suricata-backed IDS/IPS adapter.
- nDPI-assisted App-ID service with Phragma-owned taxonomy, evidence, and confidence.
- Flow/event/verdict log model.
- Packet-path explanation MVP.
- CLI and WebUI for one full workflow: configure, commit, inspect, log, explain, rollback.
- Cloud VM install path.
- Benchmark harness and failure-mode tests.

## Roadmap

Eventual scope remains fully open source, but it is not v1 scope.

See [Roadmap](ROADMAP.md).

## Market Capability Expectations

An enterprise NGFW is expected to provide:

- L3/L4 firewalling, zones, NAT, routing, VPN, HA, and traffic shaping.
- App-ID and custom application definitions.
- User-ID and device or posture context.
- IPS, malware, file, URL, DNS, and threat-prevention controls.
- TLS decryption with exception handling.
- WAF, API gateway, reverse proxy, forward proxy, and L7 load balancing where applicable.
- Logs, packet capture, SIEM export, NetFlow/IPFIX/sFlow, dashboards, audit logs, and troubleshooting tools.
- Centralized management, templates, RBAC, SSO, compliance reporting, and config rollback.

Phragma must not hide from this scope. v1 may implement only the first credible slice, but the architecture must not block the rest.

## Line In The Sand

- **NON-NEGOTIABLE LINE IN THE SAND:** A design that cannot explain allow/drop/bypass decisions is unacceptable.
- **NON-NEGOTIABLE LINE IN THE SAND:** A design that makes Suricata or nDPI the user-facing product model is unacceptable.
- **NON-NEGOTIABLE LINE IN THE SAND:** A design that requires XDP for correctness is unacceptable.
- **NON-NEGOTIABLE LINE IN THE SAND:** A design that closes or paywalls features is unacceptable.
- **NON-NEGOTIABLE LINE IN THE SAND:** A design that cannot benchmark against VM-Series-class virtual firewall scenarios is unacceptable.

## Primary References

- Palo Alto Networks [App-ID documentation](https://docs.paloaltonetworks.com/ngfw/administration/app-id).
- Palo Alto Networks [VM-Series for public clouds](https://www.paloaltonetworks.com/network-security/vm-series-for-public-clouds).
- Palo Alto Networks [Panorama overview](https://docs.paloaltonetworks.com/panorama/11-0/panorama-admin/panorama-overview).
