# Phragma Architecture

Phragma is a controller-driven firewall platform. It owns the policy model and operational experience while delegating specialized functions to mature engines through adapters.

## System View

```text
UI / CLI / API clients
        |
        v
Local control plane API (gRPC/OpenAPI)
        |
        v
Config store -> validator -> candidate/commit/rollback -> audit log
        |
        v
Policy compiler
        |
        +--> Linux/eBPF dataplane renderer
        +--> nftables/conntrack renderer
        +--> FRR renderer
        +--> Suricata profile adapter
        +--> nDPI/App-ID signal adapter
        +--> Envoy/Coraza adapter
        +--> strongSwan/WireGuard adapters
        |
        v
Verdict bus + telemetry pipeline + explanation engine
```

## Control Plane

The control plane owns:

- Public API.
- Authentication and local authorization.
- Config store.
- Candidate, validate, diff, commit, rollback.
- Policy compiler.
- Engine lifecycle and health.
- Audit log.
- Local UI and CLI API surface.

**HARD REQUIREMENT:** The canonical API is versioned gRPC/OpenAPI. Kubernetes CRDs and operators may be built later as API consumers, not as the canonical contract.

## Dataplane Backend

The v1 dataplane backend is Linux/eBPF.

It includes:

- XDP for early drop, coarse classification, counters, and fast pre-policy where supported.
- tc ingress/egress programs for broader Linux compatibility and policy points after initial stack processing.
- nftables/conntrack for stateful firewall, NAT, and boring correctness where it is the right tool.
- FRR for routing protocols and route state.
- Explicit userspace inspection handoff for IDS/IPS, App-ID, L7 proxy, WAF, DNS, URL, and file inspection.

**HARD REQUIREMENT:** XDP is not required for correctness. The product must remain functional with tc and nftables/conntrack fallback.

**HARD REQUIREMENT:** VPP is not a v1 backend. Keep the renderer abstraction clean so VPP can be added later for 100 Gbps+, physical appliances, and high-CPS use cases.

## Inspection Tier

The inspection tier is where most NGFW performance risk lives. The dataplane must steer flows intelligently; it must not blindly force every packet through every engine.

Inspection engines:

- Suricata: IDS/IPS matching engine.
- nDPI: App-ID signal source.
- Zeek: telemetry and protocol metadata, not inline v1.
- Envoy: L7 proxy, API gateway, forward/reverse proxy, and TLS termination path.
- Coraza: WAF engine through Envoy/proxy path.
- strongSwan: IPsec/IKEv2.
- WireGuard: modern tunnel support.
- OpenZiti: ZTNA module.

**HARD REQUIREMENT:** Phragma owns the normalized verdict model. Engine-native events must be adapted into Phragma events before they reach users.

## Policy Compiler

The policy compiler translates declarative policy into backend-specific desired state.

Inputs:

- Interfaces and zones.
- Address, service, user, device, and application objects.
- Security rules.
- NAT rules.
- Routing policy.
- IDS/IPS profiles.
- App-ID profiles.
- L7/WAF/API gateway policy.
- Tunnel policy.
- Logging and fail behavior.

Outputs:

- eBPF maps and program configuration.
- nftables and conntrack rules.
- FRR configuration.
- Suricata rule/profile configuration.
- nDPI/App-ID classifier configuration.
- Envoy xDS resources.
- strongSwan and WireGuard configuration.

The compiler must support dry runs. No renderer may mutate running state before validation succeeds.

## Verdict Bus

The verdict bus normalizes decisions across engines.

Required verdict states:

- allowed
- blocked
- bypassed
- inspected
- partially inspected
- decrypted
- mirrored
- rate-limited
- failed-open
- failed-closed
- error

Verdicts must include:

- flow identity
- policy rule
- source and destination zones
- engine source
- evidence
- confidence where applicable
- timestamp
- running config version

## Explanation Engine

The explanation engine answers: why did this flow do what it did?

It must show:

- matched policy rule
- NAT decision
- route decision
- app identity and evidence
- threat verdicts
- inspection state
- bypass state
- decryption state
- engine health at decision time
- fail-open or fail-closed reason when applicable

`ExplainFlow` returns structured `inspection_profile` and `route_profile`
objects alongside the human-readable evidence and trace. The inspection profile
records IDS/IPS mode, Suricata-as-engine evidence, explicit failure behavior,
flowtable fast-path state, degraded behavior, and the exact bypass reason when a
policy permits inspection bypass. The route profile records static-route
longest-prefix selection for allowed flows and explicitly reports when live
kernel or FRR route state is outside the pure policy explanation.

**HARD REQUIREMENT:** No flow can be silently bypassed or silently dropped without a queryable explanation.

## Dataplane Runtime Evidence

`/v1/system/status`, `ngfwctl status`, Dashboard, and Readiness distinguish two
flowtable facts:

- host readiness: whether the node can validate and apply nftables flowtable
  configuration
- runtime evidence: whether the installed `inet openngfw` ruleset contains the
  `flowtable fastpath` declaration and `flow add @fastpath` rule

The API exposes these facts as structured `dataplane.flowtable` fields:
`host_state`, `runtime_state`, `devices`, `packets`, `bytes`,
`flowtable_declared`, and `offload_rule_present`. The older capability rows
remain as compatibility summaries, but clients should use the structured
dataplane object for automation, readiness gates, and UI rendering.

A running policy with `network.enable_flow_offload` is not considered
production-ready unless host readiness is `ready` or `active` and runtime
evidence is `active`. This prevents a high-throughput profile from silently
falling back to standard forwarding while still being described as accelerated.

## Host-Input Protection

Forwarded zone-pair rules do not implicitly protect traffic destined to the
firewall appliance itself. Phragma models that path explicitly with
`policy.host_input`:

- unset `host_input` preserves the compatibility default of input policy
  `accept`
- `host_input.default_action: ACTION_DENY` renders the nftables input chain as
  default-drop
- loopback and established return traffic are accepted before host-input rules
- named host-input rules match ingress zones, source address objects, services,
  and allow/deny/reject verdicts

This keeps management-plane hardening separate from transit policy while still
using the same candidate, validation, commit, audit, rollback, API, CLI, and UI
control loop.

## Telemetry And Logs

Log classes:

- traffic
- threat
- app
- DNS
- URL
- file
- system
- engine health
- config
- audit
- HA

Exports:

- local API query
- CLI
- WebUI
- syslog
- JSON files or local store
- future NetFlow/IPFIX/sFlow
- future OpenTelemetry/SIEM integrations

## UI And CLI

The UI and CLI are clients of the same API. They must not write engine configuration directly.

Required workflows:

- create candidate config
- validate
- diff
- commit
- rollback
- view traffic logs
- view threat logs
- explain flow
- inspect engine health
- manage local users and SSO

`ngfwctl explain` and the WebUI Troubleshoot/Flow check views consume the same
`ExplainFlow` response. Human-readable CLI output must include the same
inspection and route profile fields as the browser surfaces; JSON output remains
the protobuf response with proto field names.

`/v1/system/identity` and `ngfwctl whoami` report the current API actor, role,
auth source, and coarse capabilities. Local users-file bearer tokens support
CLI and automation. Browser OIDC login uses authorization-code flow with PKCE,
state, nonce, provider ID-token verification, and server-side sessions carried
by HTTP-only SameSite cookies. Browser SAML login uses node-local SAML provider
configuration, IdP-posted assertions, RelayState validation, and the same
server-side session, CSRF, RBAC, and audit path as OIDC.

`/v1/system/status` also reports structured management-plane guardrails:
TLS/auth state, rate-limit settings, REST body/header caps, gRPC message caps,
and HTTP timeout values. These fields are operator posture, not policy state;
Readiness and automation use them to flag disabled guardrails before the
management plane is exposed beyond a trusted network.
An explicitly acknowledged public generated self-signed listener is reported
as degraded with a critical warning until an operator certificate replaces it;
the shipped service remains loopback-only. See
[`ADR-0018`](adr/ADR-0018-management-tls-trust-posture.md).

Version history and audit entries persist actor name, actor role, and auth
source. Older records may only contain actor names, but new privileged actions
must be attributable to the exact RBAC context used at commit time, including
`local-users-file`, `oidc-session`, or `disabled-local`.
