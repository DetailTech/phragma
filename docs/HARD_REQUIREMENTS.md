# Phragma Hard Requirements

This document is the constraint list for human and AI contributors. If an implementation conflicts with this file, the implementation is wrong.

## Project And Licensing

1. **HARD REQUIREMENT:** Phragma is 100% open source.
2. **HARD REQUIREMENT:** There is no open-core model, no BSL enterprise repository, no license enforcement service, no entitlement check, and no paywalled feature.
3. **HARD REQUIREMENT:** First-party code should use Apache 2.0 where possible, but the project may include GPL, LGPL, AGPL-adjacent, or other open-source components through explicit boundaries and documented license review.
4. **HARD REQUIREMENT:** Components with reciprocal licenses must not be silently linked into first-party Apache binaries.
5. **HARD REQUIREMENT:** eBPF program licensing must be treated as a deliberate design and legal review item. Do not assume all dataplane code can be Apache 2.0.
6. **HARD REQUIREMENT:** DCO is the default contribution mechanism. A CLA may be introduced only if legal counsel requires it for explicit IP or patent reasons.

## Product Target

7. **HARD REQUIREMENT:** v1 targets Palo Alto VM-Series cloud/virtual NGFW class capability and performance, not physical hardware flagship throughput.
8. **HARD REQUIREMENT:** v1 must be a credible single-node virtual appliance before fleet management is attempted.
9. **HARD REQUIREMENT:** Fleet management, when built, must remain open source.
10. **HARD REQUIREMENT:** The system must be buildable toward federal and regulated environments: signed builds, SBOMs, FIPS strategy, STIG hardening, audit logs, and reproducible release practices.

## Architecture

11. **HARD REQUIREMENT:** Control plane and dataplane are separate.
12. **HARD REQUIREMENT:** The canonical control-plane API is versioned gRPC/OpenAPI. Kubernetes CRDs or operators may consume this API later but must not become the source of truth.
13. **HARD REQUIREMENT:** v1 uses one dataplane backend: Linux/eBPF.
14. **HARD REQUIREMENT:** v1 Linux/eBPF means XDP plus tc plus nftables/conntrack plus FRR plus userspace inspection handoff.
15. **HARD REQUIREMENT:** XDP is not required for correctness. If native XDP is unavailable, the node must remain functional using tc and nftables/conntrack.
16. **HARD REQUIREMENT:** VPP, DPDK, and AF_XDP are future backend options only. No v1 code may require them.
17. **HARD REQUIREMENT:** Engine service chaining must not define the user model. Phragma owns the policy, verdict, event, and explanation model.

## Policy And Operations

18. **HARD REQUIREMENT:** Security, NAT, routing, decryption, and inspection policy must be expressed as declarative data.
19. **HARD REQUIREMENT:** Candidate configuration, validation, commit, rollback, and audit log are core behavior.
20. **HARD REQUIREMENT:** Every flow decision must be explainable as allowed, blocked, bypassed, partially inspected, fully inspected, decrypted, or failed according to policy.
21. **HARD REQUIREMENT:** Bypass must be policy-visible. Silent bypass is a defect.
22. **HARD REQUIREMENT:** Fail-open and fail-closed behavior must be explicit per policy area and testable under degraded-engine conditions.

## App-ID And Threat-ID

23. **HARD REQUIREMENT:** nDPI is a signal source only. It is not the App-ID product.
24. **HARD REQUIREMENT:** Phragma must own the App-ID taxonomy, evidence model, confidence scoring, custom app definitions, encrypted-traffic heuristics, update package format, and regression corpus.
25. **HARD REQUIREMENT:** Suricata is the v1 matching engine only. It is not the Threat-ID product.
26. **HARD REQUIREMENT:** Phragma must own threat profile compilation, signature metadata, severity and confidence scoring, staged rollout, false-positive controls, exception workflow, PCAP regression, and threat explanations.
27. **HARD REQUIREMENT:** App-ID and Threat-ID quality must be tested against captured traffic and cannot be judged by unit tests alone.

## Availability And Security

28. **HARD REQUIREMENT:** Active/passive HA is the first HA target. Active/active is deferred.
29. **HARD REQUIREMENT:** Local single-node SAML/OIDC is core.
30. **HARD REQUIREMENT:** Local audit logs must be real, durable, and queryable.
31. **HARD REQUIREMENT:** The dataplane must continue applying last-known-good policy if the control plane is degraded.
32. **HARD REQUIREMENT:** A bad candidate configuration must not corrupt the running configuration.
33. **HARD REQUIREMENT:** Secrets, certificates, and signing keys must not be stored in plaintext configuration.
34. **HARD REQUIREMENT:** Commit and rollback APIs must expose artifact hashes, activation state, activation time, rollback lineage, and the current last-known-good marker so operators can prove recovery posture without inspecting local store files.

## Non-Negotiable Lines In The Sand

- A design that cannot explain packet or flow decisions cannot ship.
- A design that cannot benchmark against VM-Series-class cloud firewall scenarios cannot claim v1 parity.
- A design that creates a closed edition or paywall cannot be accepted.
- A design that makes the appliance depend on Kubernetes as the canonical API cannot be accepted.
- A design that makes Suricata, nDPI, Envoy, FRR, or any other engine the policy authority cannot be accepted.
