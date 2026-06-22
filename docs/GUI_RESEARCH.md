# Phragma GUI Research

Status: v0.1 research baseline.

Date: 2026-06-17.

Audience: security engineers, network security engineers, AI coding agents, UI maintainers, and future product maintainers.

Related documents:

- [Project Definition](PROJECT_DEFINITION.md)
- [Hard Requirements](HARD_REQUIREMENTS.md)
- [Architecture](ARCHITECTURE.md)
- [Build Plan](build-plan.md)
- [GUI Feature Matrix](GUI_FEATURE_MATRIX.md)
- [GUI Gap Analysis](GUI_GAP_ANALYSIS.md)

## Executive Read

Phragma should not copy the visual density of legacy firewall consoles. It should copy the operational safeguards that serious firewall operators depend on: explicit policy ordering, object reuse, rule hit context, safe change review, commit history, rollback, and logs that prove what happened. The strongest existing products each solve part of the problem: Palo Alto sets the benchmark for application-aware policy semantics, Fortinet exposes broad firewall operations in one appliance GUI, Sophos makes rule groups and assistants approachable, OPNsense exposes useful rule inspection and live troubleshooting, pfSense keeps low-level firewall diagnostics visible, WatchGuard keeps the packet-filter versus proxy-policy mental model clear, and Meraki shows how simple a dashboard can feel when scope is constrained.

The biggest GUI gap for Phragma is not missing screens. It is trust. A security engineer must be able to answer: what will this change do, why did this flow match, what did the engines see, what was bypassed, and how do I safely return to the last known good state. That maps directly to the existing Phragma hard requirements for candidate configuration, validation, diff, commit, rollback, audit, explainability, policy-visible bypass, explicit fail behavior, and durable logs.

The GUI should be designed as an evidence console with a policy editor inside it, not as a dashboard with scattered configuration forms. The first screen should show node health, running config version, pending candidate state, degraded-engine status, recent high-signal verdicts, and the shortest path to investigate or change policy. The rulebase should behave like a structured review tool: searchable, explainable, testable, diffable, and connected to live evidence. Visual design should be quiet, dense, and precise: tables, split panes, timelines, chips, status badges, and inspection drawers instead of oversized cards or marketing dashboards.

Public user-signal research should influence friction priorities only. Official docs and accessible product documentation are the basis for feature claims. Community reports and forum/reddit style anecdotes tend to agree on recurring firewall GUI pain: rulebase complexity, hidden evaluation order, weak change previews, separate logging contexts, slow or opaque commits, and difficulty tying a log line back to the exact policy object and engine decision. Phragma can compete by making these seams first-class instead of burying them.

## Research Scope

Primary audience:

- Security engineer operating a serious single-node cloud or virtual NGFW.

Secondary audiences:

- Network engineer responsible for routes, NAT, VPN, and high availability.
- Platform engineer automating appliance setup through API and CLI.
- SOC analyst inspecting logs, threat events, and packet path explanations.
- Future fleet or NOC operator. This is not v1 primary scope.
- Small admin. This is a useful contrast audience, but not the core target.

Products evaluated:

- Palo Alto Networks PAN-OS, App-ID, Panorama, and VM-Series context.
- Cisco Secure Firewall Management Center and cloud-delivered firewall management.
- Fortinet FortiGate/FortiOS and FortiView.
- Check Point Quantum/SmartConsole. Public URL access was weaker than other vendors during this pass, so confidence is lower.
- Ubiquiti UniFi Gateway. Public docs were partly blocked by Cloudflare during automated access, so confidence is lower.
- Untangle/Arista Edge Threat Management. Public docs were partly blocked during automated access, so confidence is lower.
- Sophos Firewall.
- SonicWall. Public technical docs were blocked by an automated challenge during this pass, so confidence is lower.
- WatchGuard Fireware.
- pfSense.
- OPNsense and Zenarmor.
- Juniper SRX/J-Web/Security Director. Public docs were difficult to access reliably during this pass, so confidence is lower.
- Cisco Meraki MX.
- Cloudflare One Gateway and Tailscale. These are not firewall appliance peers, but they are useful contrast references for modern policy UX, identity/device posture, and clean cloud-console interaction.

Evidence rules:

- Official vendor docs drive product capability claims.
- Accessible screenshots, docs, and public demo materials drive visual pattern notes.
- Community signal drives friction severity only; it is not used as proof that a product has or lacks a feature.
- If a vendor page was blocked or unstable, the matrix marks confidence as low instead of pretending parity.

## Operator Jobs To Be Done

| Job | Security engineer need | GUI implication | Phragma requirement |
|---|---|---|---|
| Understand current risk fast | Know whether the node is enforcing, degraded, bypassing, or blind | First screen with running config version, engine health, dropped telemetry counters, and degraded behavior | Explain every flow decision; explicit fail-open/fail-closed behavior |
| Safely change policy | Build a candidate, validate it, review the diff, commit with reason, and roll back if needed | Candidate workspace, diff view, validation panel, commit modal with audit reason, rollback browser | Candidate, validation, diff, commit, rollback, audit log |
| Author precise security rules | Express source, destination, user/device, app, service, threat profile, logging, and fail behavior | Dense editable rule table with object pickers, inline warnings, rule hit counters, and test flow action | Declarative security, NAT, routing, decryption, and inspection policy |
| Explain a flow | Start from a log or synthetic test and see exactly why traffic was allowed, blocked, bypassed, or failed | Flow detail drawer with rule, NAT, route, app evidence, threat verdict, inspection path, engine health, and config version | Explanation engine; normalized verdict model |
| Troubleshoot misses | Prove whether rule order, NAT, route, state, DNS/FQDN, app classification, or engine health caused behavior | Rule inspector, packet capture launcher, route/NAT trace, policy test, and live log correlation | Packet-path explanation MVP; logs and telemetry |
| Manage App-ID | Understand app identity, confidence, evidence, custom apps, and unknown/low-confidence behavior | App catalog, app evidence panel, unknown app queue, custom app wizard, regression/test traffic references | Phragma-owned App-ID taxonomy, evidence, confidence, custom apps |
| Manage Threat-ID | Enable IDS/IPS profiles without losing false-positive control | Threat profile editor, staged update view, exception workflow, PCAP regression link, severity/confidence metadata | Phragma-owned Threat-ID metadata, profile, QA, false-positive controls |
| Inspect health and bypass | Know which inspection engines are up and whether traffic was fully inspected, partially inspected, bypassed, decrypted, failed-open, or failed-closed | Engine health console, degraded mode banner, per-flow inspection state, and bypass filters in logs | Policy-visible bypass; explicit fail behavior |
| Export evidence | Send logs and audit events to SIEM or files without losing local query | Local log viewer with saved filters and export targets | Local API query, CLI, WebUI, syslog, JSON/export path |
| Automate responsibly | Do the same work through API and CLI | GUI affordances show API object IDs, config versions, generated diff, and audit trail | UI and CLI use the same public API |

## Existing Product Lessons

### Palo Alto Networks

Palo Alto is the most important functional benchmark for Phragma because App-ID is central to its policy model. The public App-ID docs describe application identification as policy-relevant, risk-aware, and independent of port/protocol evasions, with policy deciding whether an identified application is blocked, allowed, inspected, shaped, or scanned [Palo Alto App-ID](https://docs.paloaltonetworks.com/ngfw/administration/app-id) and [App-ID Overview](https://docs.paloaltonetworks.com/ngfw/administration/app-id/app-id-overview). Palo Alto security policy docs also emphasize ordered rule evaluation, first-match behavior, logging at session start/end, rule usage, audit comments, and comparing rule versions [Palo Alto Security Policy](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/security-policy).

Phragma lesson: make application identity a first-class rule column and evidence object, not a plugin result. Also make rule usage, audit comments, and version comparison default behaviors.

### Cisco Secure Firewall

Cisco's management model is broad and multi-surface: cloud-delivered firewall management, on-premises FMC, device operations, monitoring, analytics, troubleshooting, and access control policy are organized as a large management suite [Cisco Security Cloud Control: Secure Firewall Management](https://docs.manage.security.cisco.com/cdfmc/c_access_control_policies.html).

Phragma lesson: powerful centralized management easily becomes a navigation problem. v1 should avoid fleet-first sprawl. Treat Cisco as a warning about management-plane breadth, while borrowing access-control-policy depth and event investigation concepts later.

### Fortinet FortiGate

Fortinet is a strong appliance GUI reference because FortiOS exposes a wide range of firewall operations inside one admin surface. Its docs cover getting started, policy and objects, firewall policy, NGFW policy, ZTNA, FortiView, FortiManager, FortiAnalyzer, public/private cloud FortiGate variants, and many security services [Fortinet Getting Started](https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/954635/getting-started) [Fortinet Firewall Policy](https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/656084/firewall-policy).

Phragma lesson: breadth matters, but Phragma should avoid a menu forest. The Fortinet pattern to borrow is integrated operations: policy, logs, dashboards, and security fabric signals should be adjacent.

### Check Point

Check Point remains important because SmartConsole is a mature security-management client and the Check Point model strongly separates policy authoring, management, logging, and install/publish workflows. Public access to stable SmartConsole docs was weak in this research pass, so claims here should be treated as lower-confidence until refreshed.

Phragma lesson: the relevant idea is a deliberate policy-management workspace with reviewable changes and operational context, not the exact thick-client model.

### Ubiquiti UniFi Gateway

UniFi is not an enterprise NGFW benchmark, but it is a strong contrast reference for approachability. Its gateway/firewall concepts are packaged for quick comprehension, and the product experience favors simple dashboards and guided configuration. Automated public-doc access was blocked during this pass, so feature-specific claims should be refreshed manually before design implementation.

Phragma lesson: small-admin simplicity should inform onboarding and defaults, but not reduce the depth required by a security engineer.

### Untangle / Arista Edge Threat Management

Untangle's historic value is its app/rack mental model: admins can understand security services as attachable controls rather than buried engine flags. Automated public-doc access was blocked during this pass, so current Arista ETM behavior needs manual refresh.

Phragma lesson: profile stacks can be understandable if they are presented as policy-attached inspection paths with visible outcomes. Avoid making the engines the policy model.

### Sophos Firewall

Sophos has strong UI lessons around rule groups, assistants, icons, and table actions. Its firewall-rule docs describe zone/network rules, source/destination/services/users, linked NAT, web/application/IPS policies, decryption/scanning, zero-day analysis, heartbeat context, rule groups, rule table filters, drag order, cloning, data counters, default drop behavior, and caveats around automatically created rules [Sophos Firewall Rules](https://docs.sophos.com/nsg/sophos-firewall/21.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/RulesAndPolicies/FirewallRules/index.html).

Phragma lesson: borrow assistants and table clarity, especially for DNAT and grouped rules. Be stricter than Sophos about showing policy side effects before commit.

### WatchGuard Fireware

WatchGuard is useful because its docs clearly explain packet-filter policies versus proxy policies. It frames policy as definitions that allow or deny traffic based on source, destination, ports, protocols, logging, notification, and NAT; packet filters inspect header data while proxies inspect content [WatchGuard About Policies](https://www.watchguard.com/help/docs/help-center/en-US/Content/en-US/Fireware/policies/policies_about_c.html).

Phragma lesson: inspection path should be explicit. Users should know whether a rule used L3/L4 handling, IDS/IPS, App-ID, proxy/WAF, decryption, or bypass.

### pfSense

pfSense is a strong reference for low-level firewall transparency, diagnostics, logs, packet flow, aliases, NAT, routing, VPN, and troubleshooting docs. Netgate's firewall docs explicitly frame firewall rules as controls for traffic passing through the firewall and point admins toward logs, filter reload status, packet flow data, and troubleshooting [pfSense Firewall](https://docs.netgate.com/pfsense/en/latest/firewall/index.html).

Phragma lesson: do not hide the packet path. Even when the UI is more modern, expose raw enough troubleshooting state that engineers trust it.

### OPNsense and Zenarmor

OPNsense is a strong open-source GUI reference because its rule docs are transparent about stateful filtering, pass/block/reject, processing order, quick versus non-quick, NAT-before-filter warnings, rule implementations, API migration, rule statistics, live log view, session browser, and packet capture for source-routing troubleshooting [OPNsense Rules](https://docs.opnsense.org/manual/firewall.html). Zenarmor is relevant as a commercial NGFW plugin pattern, but Phragma should not adopt a plugin/paywall split.

Phragma lesson: rule inspect and live log correlation are best-of-breed open-source patterns. Phragma should go further by joining rule, NAT, route, app, threat, engine health, and config version in one explanation.

### Meraki, Cloudflare One, and Tailscale

Meraki is a contrast reference for dashboard simplicity and cloud-managed networking. Its MX firewall docs show a single firewall settings page for Layer 3 and Layer 7 outbound rules, WAN appliance services, port forwarding, 1:1 NAT, 1:Many NAT, application/category blocking, geo-IP, and clear caveats around FQDN and DNS snooping [Meraki MX Firewall Settings](https://documentation.meraki.com/SASE_and_SD-WAN/MX/Design_and_Configure/Configuration_Guides/Firewall_and_Traffic_Shaping/MX_Firewall_Settings).

Cloudflare One and Tailscale are not appliance NGFW peers, but their policy surfaces are useful contrast references for modern identity/device posture and simpler zero-trust policy workflows [Cloudflare One Traffic Policies](https://developers.cloudflare.com/cloudflare-one/traffic-policies/) [Tailscale ACLs](https://tailscale.com/kb/1018/acls).

Phragma lesson: use cloud-console clarity, but keep local appliance trust, offline operation, and no entitlement gates.

## Phragma GUI Requirements

### Functional Requirements

- The WebUI must use only the public control-plane API.
- The WebUI must not write engine configuration directly.
- The first supported workflow must be configure, validate, diff, commit, inspect, explain, and rollback.
- Every mutable configuration area must support candidate state, validation status, diff visibility, commit reason, audit event, and rollback linkage.
- Every policy table must show whether rules are active, disabled, shadowed, unused, newly changed, and tied to logs.
- Logs must be queryable by policy rule, flow identity, verdict state, source/destination zone, app, threat, engine, config version, and inspection state.
- The explanation view must join policy, NAT, route, app evidence, threat verdicts, inspection state, bypass state, decryption state, engine health, and fail-open/fail-closed reason.
- App-ID must expose evidence and confidence. It must not look like a thin nDPI output page.
- Threat-ID must expose metadata, profile, exception, severity/confidence, and false-positive workflow. It must not look like a raw Suricata event page.
- Degraded engine behavior must be visible in health, logs, policy validation, and per-flow explanations.
- Local users and SAML/OIDC must be manageable without turning the GUI into a fleet-management system.

### Visual And Interaction Requirements

- Use a dense workbench layout: persistent sidebar, main table or graph surface, right-side detail drawer, and bottom activity/audit strip where useful.
- Prefer tables, inspectors, split panes, timelines, filters, chips, status badges, and inline diffs over large marketing cards.
- Put config state in the chrome: running version, candidate dirty state, validation status, pending commit, engine degraded state, and rollback availability.
- Make destructive or risky changes explicit: delete, disable, broad allow, fail-open, bypass, decryption exception, content update install, and rollback.
- Provide powerful search and filters everywhere logs or policy tables exceed one screen.
- Keep rule editing fast for experts: keyboard-friendly tables, clone, insert above/below, bulk enable/disable, object reuse, and inline validation.
- Keep onboarding guided without hiding details: first-run wizard should create interfaces/zones, management access, default deny posture, update source, and a sample safe policy.
- Use visual severity consistently: config warnings, validation errors, engine down, inspection bypass, failed-open, failed-closed, and threat verdicts must be visually distinct.
- Do not use a one-note color palette. Security status should not depend on red/green alone.

## Phragma Requirement-To-GUI Surface Map

| Repo requirement | GUI surface |
|---|---|
| Candidate configuration, validation, commit, rollback, audit | Candidate workspace, validation panel, diff viewer, commit modal, rollback timeline, audit log |
| Every flow decision explainable | Logs table, flow detail drawer, explain view, synthetic flow test |
| Bypass must be policy-visible | Policy inspection column, log filters, bypass badge, health banner, explanation path |
| Explicit fail-open/fail-closed behavior | Inspection profile editor, engine health screen, validation warnings, flow explanation |
| nDPI is signal only | App-ID evidence and confidence screen, custom app workflow, unknown app queue |
| Suricata is engine only | Threat profile, exception workflow, normalized threat logs, PCAP regression reference |
| UI and CLI use same API | API object IDs in advanced drawer, generated request preview, shared validation errors |
| Local audit logs real and queryable | Audit search, commit reason, before/after diff links, export |
| SAML/OIDC core | Local auth settings, identity provider setup, test login, break-glass local admin |
| Last-known-good policy under control-plane degradation | Health screen, running policy version, dataplane enforcement status |

## Public User-Signal Themes

These are friction themes observed across public communities, forums, docs feedback patterns, and practitioner discussions. Treat them as research hypotheses until validated with interviews or hands-on testing.

| Theme | Why it matters | GUI response |
|---|---|---|
| Rulebase complexity grows faster than the UI | Dense policies become hard to reason about, especially with objects, NAT, app rules, and implicit defaults | Rule grouping, search, tags, shadow detection, hit counts, policy test, and explanation |
| Change safety is often opaque | Operators fear breaking traffic because commit effect is unclear | Candidate validation, semantic diff, blast-radius preview, and rollback timeline |
| Logs are disconnected from policy editing | Investigations require jumping between logs, objects, NAT, routes, and rules | Log-to-rule deep links and flow explanation drawer |
| Application identity is trusted only when evidence is visible | App-ID is powerful but creates doubt when encrypted or CDN traffic is involved | Evidence, confidence, source signals, unknown app queue |
| Threat prevention creates false-positive anxiety | IPS/WAF/proxy controls can block production traffic unexpectedly | Staged mode, exception workflow, PCAP/replay evidence, profile impact preview |
| Degraded engines are hidden until too late | Engine outages can silently reduce inspection | Engine health tied to policy-visible verdicts and fail behavior |
| Simpler products feel better but stop short | UniFi/Meraki-style simplicity is pleasant but may hide expert detail | Progressive disclosure: simple first screen, expert detail one click away |

## Research Confidence

High confidence:

- Palo Alto App-ID and security policy model, based on accessible official docs.
- Fortinet FortiGate broad appliance management and firewall policy docs.
- Sophos firewall rules, rule groups, linked NAT, and rule-table actions.
- WatchGuard policy and packet-filter/proxy distinction.
- pfSense and OPNsense open-source firewall rules, logs, diagnostics, and rule inspection docs.
- Meraki dashboard firewall settings as a contrast model.

Medium confidence:

- Cisco Secure Firewall management architecture and access-control-policy surface. The docs are accessible but large and spread across cloud-delivered and on-premises management paths.
- Cloudflare One and Tailscale as modern contrast references, not appliance peers.

Low confidence:

- Check Point SmartConsole details. Public doc URL access was unstable in this pass.
- Ubiquiti UniFi Gateway details. Help pages were blocked by an automated challenge during this pass.
- Untangle/Arista ETM details. Public doc access was blocked during this pass.
- SonicWall NSM/SonicOS details. Public technical docs were blocked by an automated challenge during this pass.
- Juniper SRX/J-Web/Security Director details. Public docs were difficult to access reliably in this pass.

## Source Map

Primary official sources used:

- [Palo Alto Networks App-ID](https://docs.paloaltonetworks.com/ngfw/administration/app-id)
- [Palo Alto Networks App-ID Overview](https://docs.paloaltonetworks.com/ngfw/administration/app-id/app-id-overview)
- [Palo Alto Networks Security Policy](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/security-policy)
- [Cisco Security Cloud Control: Secure Firewall Management](https://docs.manage.security.cisco.com/cdfmc/c_access_control_policies.html)
- [Fortinet FortiGate Getting Started](https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/954635/getting-started)
- [Fortinet FortiGate Firewall Policy](https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide/656084/firewall-policy)
- [Sophos Firewall Rules](https://docs.sophos.com/nsg/sophos-firewall/21.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/RulesAndPolicies/FirewallRules/index.html)
- [WatchGuard About Policies](https://www.watchguard.com/help/docs/help-center/en-US/Content/en-US/Fireware/policies/policies_about_c.html)
- [pfSense Firewall](https://docs.netgate.com/pfsense/en/latest/firewall/index.html)
- [OPNsense Rules](https://docs.opnsense.org/manual/firewall.html)
- [Meraki MX Firewall Settings](https://documentation.meraki.com/SASE_and_SD-WAN/MX/Design_and_Configure/Configuration_Guides/Firewall_and_Traffic_Shaping/MX_Firewall_Settings)
- [Cloudflare One Traffic Policies](https://developers.cloudflare.com/cloudflare-one/traffic-policies/)
- [Tailscale ACLs](https://tailscale.com/kb/1018/acls)

Blocked or weak public-source targets to refresh manually:

- Ubiquiti UniFi Gateway firewall and traffic identification help pages.
- Arista Edge Threat Management documentation.
- SonicWall SonicOS/NSM technical docs.
- Check Point SmartConsole and Quantum Security Management docs.
- Juniper SRX/J-Web/Security Director docs.

## Design Brief For Future Ideation

What the GUI should do:

- Let a security engineer safely configure, validate, diff, commit, inspect, explain, and roll back a Phragma single-node virtual appliance.
- Make policy behavior and inspection evidence more trustworthy than incumbent products.
- Treat logs and explanations as primary workflows, not secondary reports.

Visual direction:

- Dense, sober security operations workbench.
- More like a modern observability console plus policy editor than a consumer router dashboard.
- Use restrained typography, high information density, precise status colors, and strong table/detail interactions.

Interactivity target:

- Full interactivity for core v1 workflows: candidate, policy editing, validation, diff, commit, rollback, logs, explain, health.
- Static or staged interactions are acceptable only for future fleet, compliance, and advanced content lifecycle screens.
