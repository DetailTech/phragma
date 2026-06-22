# Fail Behavior

Status: Accepted

Defaults are policy-area defaults. A specific policy may be stricter, but it must not silently weaken these rules.

| Policy area | Default | Rule |
|---|---|---|
| Control-plane authentication | Fail closed | No mutation or privileged read proceeds when auth cannot be verified. |
| Content update verification | Fail closed | Unsigned, invalid, expired, or unverifiable packages are rejected. |
| Signing key verification | Fail closed | Artifacts without valid trust are not installed or activated. |
| Inline threat prevention block policy | Fail closed | If policy says block on matched threat, degraded enforcement must not silently allow. |
| IDS or telemetry-only threat mode | Fail open | Traffic continues and degraded inspection is logged. |
| nDPI signal collection | Fail open | Missing App-ID signal does not stop L3/L4 forwarding by itself. |
| Zeek telemetry | Fail open | Missing telemetry does not stop forwarding. |
| L3/L4 forwarding when inspection is down | Fail open | Applies only when policy did not require inspection for the flow. |
| Policy-required inspection | Fail closed | If the rule requires inspection to decide, no silent bypass is allowed. |
| Log pipeline backpressure | Preserve policy events | Telemetry-class events drop before policy-class events; dropped telemetry is counted. |

- **HARD REQUIREMENT:** Fail-open and fail-closed behavior must be visible in logs and explanations.
- **HARD REQUIREMENT:** Policy-class events must never be silently dropped.

Inline IDS/IPS prevent mode must declare `ids.failure_behavior` explicitly:

- `IDS_FAILURE_BEHAVIOR_FAIL_OPEN` renders nftables `queue flags bypass` and
  Suricata `fail-open: yes`.
- `IDS_FAILURE_BEHAVIOR_FAIL_CLOSED` omits nftables `bypass` and renders
  Suricata `fail-open: no`.

Detect mode does not accept `failure_behavior`; it is passive telemetry and
therefore fails open by design.

Flow explanations expose this policy explicitly. `/v1/explain/flow` returns an
`/v1/system/status.inspection` reports the running policy's IDS/IPS mode,
failure behavior, Suricata engine state, policy-controlled bypass reason, and
degraded behavior. `ngfwctl status` and the WebUI Readiness page render the
same object so fail-open and fail-closed posture is visible before benchmark or
production use.

`/v1/explain/flow` also returns an `inspection_profile` with the IDS/IPS mode,
failure behavior, degraded behavior, flow-offload state, and any
policy-controlled bypass reason. The Troubleshoot view and rule simulator
render that profile so fail-open, fail-closed, and flowtable fast-path behavior
are not hidden inside engine-native logs.
