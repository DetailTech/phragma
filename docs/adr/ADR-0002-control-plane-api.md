# ADR-0002: Canonical Control Plane API

Status: Accepted

## Context

Phragma needs one stable contract for UI, CLI, local node control, future fleet management, and possible Kubernetes integration. Kubernetes CRDs are attractive but too heavy and too platform-specific to be the canonical single-node API.

## Decision

The canonical control-plane API is versioned gRPC/OpenAPI.

The API owns:

- config CRUD
- candidate/validate/diff/commit/rollback
- policy objects
- engine health
- logs and flow queries
- explanation queries
- local auth and RBAC

Kubernetes CRDs and operators may be built later as API consumers. They are not the source of truth.

## Consequences

Single-node install remains lightweight. Fleet managers, UI, CLI, and operators all use the same API. API compatibility testing becomes mandatory.
