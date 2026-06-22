# Phragma Threat Model

Status: Accepted

Scope: the firewall appliance itself. This does not model the threats inside inspected traffic.

## Assets

- Control-plane API and local authorization.
- Running and candidate configuration.
- Local secrets, certificates, and signing keys.
- App-ID and Threat-ID update channel.
- Adapter/plugin execution boundary.
- Logs, verdicts, explanations, and audit events.
- Build artifacts, SBOMs, and release signatures.
- Last-known-good dataplane policy.

## Assumptions

- v1 is a single-node appliance.
- Local admin access is powerful and audited.
- External engines are untrusted enough to require adapters.
- Content updates may arrive offline.

## STRIDE Summary

| Area | Threats | Required controls |
|---|---|---|
| Control-plane API auth | Spoofing, elevation of privilege | Strong local auth, RBAC, OIDC state/nonce/PKCE, HTTP-only SameSite sessions, session auditing, no unauthenticated mutation APIs. |
| Config store | Tampering, repudiation | Transactional candidate/running split, immutable audit events, snapshot rollback. |
| Local secrets and keys | Information disclosure, elevation of privilege | No plaintext secrets in config, file permissions, key separation, rotation path. |
| Content update channel | Tampering, spoofing, supply chain | Signed manifests, SHA-256 hashes, provenance, offline verification, rollback metadata. |
| Adapter/plugin boundary | Elevation of privilege, tampering | Process or service boundaries, least privilege, explicit input/output contracts. |
| Log and audit integrity | Tampering, repudiation | Append-only audit table, event sequence IDs, backpressure visibility, export without mutation. |
| Signing key custody | Spoofing, supply chain | Separate signing roles, documented custody, revocation path, release verification. |
| Degraded dataplane | Denial of service, tampering | Last-known-good policy, explicit fail-open/fail-closed behavior, health events. |
| Build supply chain | Tampering, information disclosure | SBOMs, reproducible release practices, dependency license scanning, signed artifacts. |

## Hard Requirements

- **HARD REQUIREMENT:** Auth, update verification, and signing verification fail closed.
- **HARD REQUIREMENT:** The dataplane continues applying last-known-good policy when the control plane is degraded.
- **HARD REQUIREMENT:** External engines and adapters must not become policy authorities.
- **HARD REQUIREMENT:** Logs and explanations must expose degraded behavior instead of hiding it.
