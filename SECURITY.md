# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** via
[GitHub Security Advisories](https://github.com/DetailTech/oss-ngfw/security/advisories/new)
for this repository. Do not open public issues for security reports.

We aim to acknowledge reports within 7 days. Coordinated disclosure timelines
are agreed per report; our default is 90 days.

## Scope

OpenNGFW integrates external engines (Suricata, FRR, strongSwan, nftables, …)
as separate processes. Vulnerabilities in those engines should be reported
upstream; vulnerabilities in how *this project* configures, supervises, or
exposes them belong here.

## Supply chain

Releases ship with an SBOM (syft), are signed (cosign keyless), and carry SLSA
provenance. Verify before deploying.
