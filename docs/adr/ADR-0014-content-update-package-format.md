# ADR-0014: Content Update Package Format

Status: Accepted

## Context

App-ID and Threat-ID content must be testable, attributable, rollbackable, and safe to install offline.

## Decision

App-ID and Threat-ID packages use the same content update package format.

- **HARD REQUIREMENT:** Each package has a signed manifest using Ed25519 or a Sigstore-compatible signature.
- **HARD REQUIREMENT:** Content uses semantic content versions.
- **HARD REQUIREMENT:** Each feed entry records provenance.
- **HARD REQUIREMENT:** Package files are covered by SHA-256 hashes.
- **HARD REQUIREMENT:** Rollback metadata is included.
- **HARD REQUIREMENT:** Offline verification is supported.
- **HARD REQUIREMENT:** Staged rollout primitives are part of the manifest.

Local package manifests are installed as:

- `<data-dir>/content/app-id/manifest.json`
- `<data-dir>/content/threat-id/manifest.json`
- `<data-dir>/content/intel-feeds/manifest.json`

The manifest schema version is `phragma.content.package.v1`. Each manifest
declares package `kind`, semantic `version`, `source`, file SHA-256 entries,
Ed25519 signature metadata, provenance entries, regression status, rollout
state, and rollback metadata. `GET /v1/intel/content/packages` exposes the
offline verification result to CLI, WebUI, and support bundles.

Install and rollback actions are explicit API operations, not unmanaged file
mutation. `POST /v1/intel/content/packages/{kind}/install` verifies a
server-local package directory before promotion. `POST
/v1/intel/content/packages/{kind}/rollback` restores the latest verified
backup. CLI and WebUI clients use those APIs; they do not bypass verifier,
backup, or rollback checks.

## Consequences

Content updates become auditable release artifacts, not opaque downloads. Emergency rollback and false-positive control can use the same package metadata.
