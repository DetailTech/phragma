# Open Source Governance

Phragma is a fully open-source project. The governance model must build trust with contributors, users, governments, and enterprises by keeping the code and feature set open.

## Project Model

- **HARD REQUIREMENT:** 100% open source.
- **HARD REQUIREMENT:** No open-core edition.
- **HARD REQUIREMENT:** No closed enterprise repo.
- **HARD REQUIREMENT:** No paywalled feature.
- **HARD REQUIREMENT:** No entitlement code.
- **HARD REQUIREMENT:** No feature flag whose purpose is commercial restriction.

Commercial services may exist around the project:

- support
- training
- certified builds
- hosted optional services
- integration work
- compliance assistance

Commercial services must not require closing Phragma features.

## Licensing

Default first-party license: Apache 2.0 where possible.

Important nuance:

- Open source does not mean one license.
- Phragma may compose Apache, GPL, LGPL, AGPL-adjacent, MIT, BSD, MPL, and other open-source components.
- Reciprocal-license components must be isolated intentionally.
- License boundaries must be documented before a component becomes required.

## Contribution Model

Default contribution mechanism: Developer Certificate of Origin (DCO).

CLA policy:

- Do not require a CLA by default.
- Introduce a CLA only if legal counsel requires it for explicit IP or patent reasons.
- Do not use a CLA to preserve a future closed relicensing path.

## License Boundary Rules

- Do not statically link reciprocal components into first-party Apache binaries without legal review.
- Prefer process, container, or service boundaries for GPL/LGPL/AGPL-sensitive components.
- Treat AGPL services such as MISP as external integrations unless counsel approves another model.
- Track component licenses in a registry.
- Generate SBOMs for releases.

## Governance Values

- Transparency over opaque content.
- Reproducible builds over trust-me binaries.
- Public issues and design records over private roadmap dependence.
- Open APIs over captive integrations.
- Community benefit over feature gating.

## Required Project Practices

- ADRs for durable technical decisions.
- Public security policy.
- CVE disclosure and response process.
- Signed releases.
- SBOMs.
- Dependency license scanning.
- Threat feed license registry.
- Clear compatibility matrix.
- Clear support status for experimental features.
