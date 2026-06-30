# Current Progress

This file is the move-safe handoff for the `v2-mixed` tree. It records what is
inside this folder, what is intentionally external at runtime, and what still
needs validation.

## 2026-06-29 Firewall Fix Wave

The current candidate branch restores candidate-safety preflight behavior,
hardens management-listener and installer validation, brings the Go lint gate
back to zero findings, retires the customer-facing `/readiness` route from the
canonical WebUI contract, migrates legacy Readiness deep links to their owning
workspaces, and aligns those owner routes with a 19-route enterprise desktop
surface. The WebUI repair pass also fixed content-alias
selection, stale route assertions, enterprise workflow selectors, responsive
operator notes, and the Performance live-status action.

The follow-on security wave permits generated self-signed TLS on a public
REST/WebUI listener only behind the explicit
`--allow-public-self-signed-tls` acknowledgement. That accepted test-only
posture is recorded in startup logs and does not by itself make runtime status
degraded or critical; it remains auth-required, SAN/trust-limited, and
non-production. Packaged deployment defaults remain loopback-only and do not
set the opt-in. The wave also upgrades the patched SAML XML-signature and
HTTP/2 dependency lines, raises the module
toolchain floor to the patched Go 1.25.11 branch, and adds signed SAML negative
regressions before the final validation pass. The rootless release gate now
also runs pinned `govulncheck` 1.5.0. Release validation continues to use Go
1.26.4 on the Oracle Linux host.

Remote continuation validation on source snapshot `8694041` passed the strict
Node.js WebUI checks and a browser-required Chromium sweep of all 19 canonical
routes (`19/19` checks and screenshots). The broad evidence manifest is at
`/var/oled/oss-ngfw-validation/artifacts/8694041-enterprise-desktop-r1/webui-smoke-evidence.json`
on the Oracle Linux validation host. This remains continuation evidence until
the accepted source snapshot is recorded through the repo-local release
evidence tooling.

Performance owns browser-local benchmark artifact review, comparison, and
operator handoff. It does not record or certify release evidence; durable
release-benchmark status remains owned by `ngfwperf`, `ngfwrelease`, and the
repo-local release workflow.

## Move Boundary

`v2-mixed` is a standalone Git worktree rooted at this folder. The firewall
code, generated API surface, WebUI, product definition, GUI design direction,
field-test plans, release gates, hardening backlog, and current progress docs
are intended to move together as one directory.

Repo-local sources of truth:

- Product scope: `docs/PROJECT_DEFINITION.md`, `docs/HARD_REQUIREMENTS.md`,
  `docs/build-plan.md`, `docs/ROADMAP.md`
- GUI and design: `docs/webui-design.md`, `docs/GUI_RESEARCH.md`,
  `docs/GUI_FEATURE_MATRIX.md`, `docs/GUI_GAP_ANALYSIS.md`,
  `internal/webui/static/assets/`
- API contract: `api/proto/`, `api/gen/`, `docs/api-spec.yaml`,
  `internal/webui/static/api-spec.yaml`
- Functional code: `cmd/`, `internal/`, `api/`, `deploy/`, `e2e/`, `perf/`,
  `release/`, `test/`
- Hardening tracker: `docs/HARDENING_BACKLOG.md`

Runtime validation still needs external Linux hosts, engines, kernel modules,
browser/OIDC providers, and field evidence where the docs say so. Those are
runtime test dependencies, not source-tree dependencies.

Validation evidence provenance:

- Entries in this file that cite `/home/opc/...` paths are reported remote
  validation results from the Oracle Linux host used for this build pass. They
  are useful continuation evidence, but they are not the same thing as durable
  repo-recorded release evidence.
- Durable release evidence should be regenerated and recorded through the
  release tooling after source-control acceptance. `release/evidence/` contains
  only the evidence files that are currently present in this checkout.
- The API contract tree is source-control clean on the current candidate
  branch. `proto-verify` still needs to pass on the accepted source snapshot
  before generated API evidence can be recorded for release.
- The latest broad WebUI route sweep is remote continuation evidence, not local
  validation. The dedicated `webui-enterprise-smoke` target requires Node.js
  checks, real Chromium coverage, the desktop viewport, and all 19 canonical
  routes. The Makefile input list also accepts `/dashboard` as an alias for `/`,
  so it contains 20 path entries without increasing canonical coverage.
  Durable evidence must still be recorded through
  `release-evidence-webui-enterprise-smoke` after source-control acceptance.
- Current evidence gap: remote continuation paths cited here do not yet replace
  durable recorded release artifacts for the recent SAML provider lifecycle,
  Traffic/App-ID drawer and route-backed review-drop workflow, telemetry
  pagination/proof workflow, Proxy/WAF workflow, Fleet template staging,
  Fleet CLI parity, Compliance report API/CLI parity, durable forwarding-rule
  identity, privileged step-up controls, Proxy runtime-readiness artifacts, or
  `webui-enterprise-smoke`. Regenerate and record those artifacts after source-
  control acceptance before treating them as release evidence.

- Functional closure integration batch: the current source tree now includes
  all six parallel enterprise-closure slices plus the main-thread setup proof
  slice. Guided Setup renders scenario-specific topology proof rows for the
  supported topology presets. Troubleshoot renders bounded running-vs-candidate
  static route simulation decisions with explicit limitations. Investigation
  server cases include retained multi-flow synthesis over correlation keys,
  owner routes, confidence, packet-proof posture, and candidate-safe owner
  actions. Readiness, Threats, and Inspection expose degraded-engine dataplane
  evidence across bounded runtime inputs and running-policy impact. Proxy/WAF
  includes candidate-safe traffic-policy coupling review through
  `AnalyzeProxyTrafficPolicy` and `#/proxy?drawer=policy`. Replay validation
  has bounded audited execute-mode candidate replacement, while destructive,
  live, unknown, and non-candidate mutations remain blocked. Fleet exposes
  bounded local template apply and retained per-node result custody through
  `POST /v1/fleet/templates/{id}:apply`, `GET /v1/fleet/template-results`,
  CLI parity, and WebUI result review. The combined smoke pass found and fixed
  a real integration gap: `cmd/controld` now mounts
  `/v1/fleet/template-results`, and the OIDC runtime smoke test now exercises
  the current step-up-token flow for runtime provider set/disable mutations.

  Remote-only validation passed after syncing the integrated source to
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/ui-functional-polish-20260622-r1`) with
  Go/npm/Playwright caches under `/var/oled/openngfw-final-functional`:
  focused Go validation for `./cmd/controld`, `./internal/explain`,
  `./internal/apiserver`, `./internal/policy`, `./internal/replayvalidation`,
  `./internal/cli`, `./internal/fleet`, and `./internal/contentpkg`; focused
  WebUI behavior validation for setup, troubleshoot, investigation,
  inspection-posture, proxy, automation-context, fleet, and API contract
  surface tests; and `make webui-check`. Browser-required targeted desktop
  smoke passed for
  `/setup,/troubleshoot,/investigation,/inspection,/threats,/readiness,/proxy,/fleet`
  (`/var/oled/openngfw-final-functional/artifacts/functional-closure-20260622-r2/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=8/20`, `checks=8/8`,
  `screenshots=8`, elapsed `1m15s`). Same-snapshot broad desktop smoke passed
  all canonical enterprise routes
  (`/var/oled/openngfw-final-functional/artifacts/functional-closure-desktop-broad-20260622-r1/webui-smoke-evidence.json`,
  `result=passed`, `mode=broad`, `routeCoverage=20/20`, `checks=20/20`,
  `screenshots=20`, elapsed `7m01s`). This remains remote continuation
  evidence until source-control acceptance and repo-local release evidence
  recording bind it to an accepted manifest. No local functional tests were
  run.

- Second parallel functional closure batch: the current source tree now closes
  the remaining bounded WebUI functional rows that were still listed in the
  GUI matrix after the previous pass. Rules now shows large-rulebase posture
  with durable-ID, visible/hidden/selected, route-target freshness, validation
  freshness, and server-overlap cap/page guidance. Objects now exposes a
  bounded TLS/DNS/URL/file security-profile workflow with posture,
  blockers/warnings, attachment impact, and copy/pin/export handoff. Traffic
  now exposes App-ID/L7 readiness rows for production corpus, confidence,
  representative port-hint staging, reviewed drop-rule staging, and
  non-port-hint/L7-only review boundaries. Readiness now has an artifact
  matching workbench for release gates, manifest binding, stale/missing
  evidence, next commands, and case handoff. Settings Access now supports
  redacted OIDC/SAML field-run evidence import/review and distinguishes
  `certified-by-evidence` field-run completeness from external IdP
  certification. Performance now shows a publishable-claim gate workbench with
  strict verifier state, release/no-claims decision, release-benchmark gate
  posture, safe/not-safe rows, and redacted comparison packet preview. Fleet
  automation context now reflects the current server-retained local template
  APIs, bounded local candidate apply, and retained unsigned per-node results.
  Remote-only validation passed after syncing the integrated source to
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/ui-functional-polish-20260622-r1`) with
  Go/npm/Playwright caches under `/var/oled/openngfw-final-functional`:
  focused WebUI behavior tests for Rules large-rulebase posture, App-ID/L7
  readiness, Readiness artifact matching, Performance publishable claims,
  Objects profile controls, Settings access evidence, Fleet automation context,
  and API contract surface; plus `make webui-check`. Browser-required targeted
  desktop smoke passed for
  `/rules,/traffic,/readiness,/performance,/objects,/settings,/fleet`
  (`/var/oled/openngfw-final-functional/artifacts/functional-closure-batch2-20260622-r1/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=7/20`, `checks=7/7`,
  `screenshots=7`, elapsed `3m45s`). Same-snapshot broad desktop smoke passed
  all canonical enterprise routes
  (`/var/oled/openngfw-final-functional/artifacts/functional-closure-batch2-desktop-broad-20260622-r1/webui-smoke-evidence.json`,
  `result=passed`, `mode=broad`, `routeCoverage=20/20`, `checks=20/20`,
  `screenshots=20`, elapsed `7m01s`). This remains remote continuation
  evidence until source-control acceptance and repo-local release evidence
  recording bind it to an accepted manifest. No local functional tests were
  run. True production App-ID/L7 authority, backend large-rulebase
  pagination/virtualization, TLS key custody, live file scanning, release
  artifact signing, signed provider evidence, external IdP certification, and
  signed benchmark custody remain hardening/follow-on items tracked in
  `docs/HARDENING_BACKLOG.md`.

- Closure audit and documentation parity batch: the current source tree now
  removes stale contradictions between the GUI/product docs and the implemented
  bounded workflows. `docs/webui-design.md`, `docs/GUI_GAP_ANALYSIS.md`,
  `docs/RELEASE_ACCEPTANCE.md`, and `release/README.md` now distinguish remote
  continuation evidence from durable release evidence, treat release acceptance
  templates as non-evidence, describe bounded replay validation/dry-run/apply-
  authority planning plus audited execute-mode candidate replacement, update
  Fleet, Compliance, Investigation, App-ID, Proxy/WAF, NAT, and Rules language
  to the current implemented state, and keep signing, retention, custody,
  active listener/cutover, external certification, distributed fleet, and
  release-recording requirements in hardening. The WebUI automation context now
  exposes current bounded replay, Proxy runtime-readiness, Compliance report,
  Readiness release-evidence, and Fleet retained-result API/CLI context. The
  Settings access test coverage now exercises the OIDC/SAML field-evidence
  parser/model for complete, missing, stale, unsafe, and invalid import
  scenarios without booting the app shell.

  Remote-only validation passed after syncing the integrated source to
  `opc@139.87.66.128`
  (`/var/oled/oss-ngfw-validation/closure-audit-20260622-r1`) with Go/npm/
  Playwright caches under `/var/oled/openngfw-final-functional`: focused WebUI
  tests `settings_access`, `automation_context`, and `readiness_view`; focused
  Go tests for `./internal/replayvalidation` and `./internal/apiserver`; and
  `make webui-check`. Browser-required targeted desktop smoke passed for
  `/settings,/readiness,/proxy,/compliance`
  (`/var/oled/openngfw-final-functional/artifacts/closure-audit-20260622-r1/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=4/20`, `checks=4/4`,
  `screenshots=4`, elapsed `2m08s`). This is remote continuation evidence;
  durable release evidence still requires accepted source and repo-local
  release recording. No local functional tests were run.

- Final polish and acceptance-parity batch: the current source tree now closes
  the late desktop WebUI polish and release-evidence consistency gaps found in
  the closure audit. The Readiness artifact workbench labels accepted-source
  evidence, remote continuation evidence, template/non-evidence, stale
  evidence, and signing/custody hardening boundaries. Release acceptance status
  tests now reject template/todo/placeholder evidence and reject
  `not_applicable` outside benchmark-only evidence paths. Settings Access keeps
  bounded OIDC/SAML field-run evidence functionally complete while leaving
  external IdP certification as hardening. NAT coupling review actions now use
  contextual icon+label buttons with explicit titles, ARIA labels, and stable
  action selectors. The desktop CSS/design-system pass adds missing semantic
  token aliases, stabilizes dense action sizing/wrapping, and flattens nested
  workbench chrome. The visual smoke runner now checks its canonical screen
  route order against the app navigation route order so future desktop
  operator routes cannot silently drift out of browser smoke. Documentation now
  narrows durable rule identity follow-on language to production rule-hit/
  last-seen telemetry custody, removes stale QR-code enrollment out-of-scope
  wording, and tracks rule-hit/last-seen telemetry custody in the hardening
  backlog.

  Remote-only validation passed after syncing the final-polish source to
  `opc@139.87.66.128`
  (`/var/oled/oss-ngfw-validation/closure-audit-20260622-r1`) with Go/npm/
  Playwright caches under `/var/oled/openngfw-final-functional`: focused WebUI
  tests `settings_access`, `readiness_view`, `design_system`, and
  `automation_context`; focused Go validation for
  `./internal/releaseacceptance`; the no-browser desktop smoke self-check for
  route ordering and evidence-policy diagnostics; and `make webui-check`.
  Browser-required targeted desktop smoke passed for
  `/,/nat,/readiness,/settings,/compliance`
  (`/var/oled/openngfw-final-functional/artifacts/final-polish-audit-20260622-r1/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=5/20`, `checks=5/5`,
  `screenshots=5`, elapsed `2m38s`). This is remote continuation evidence;
  durable release evidence still requires accepted source and repo-local
  release recording. No local functional tests were run.

- Desktop enterprise route-affordance closure: the current source tree now
  aligns the `webui-enterprise-smoke` default route order with the app
  navigation order while preserving `/dashboard` as the Dashboard alias for
  `/`. `release-check-rootless` now depends on `webui-enterprise-smoke` instead
  of the generic visual-smoke target, so release-oriented WebUI smoke uses the
  desktop enterprise gate documented in release acceptance. The browser smoke
  now includes a generic visible-action guard for ambiguous operator controls:
  generic labels such as Open, Copy, Apply, Clear, Pin, Review, Stage, and
  Validate must carry stable hooks plus explicit title/ARIA intent. The first
  broad run with that guard intentionally failed every route because the guard
  implementation omitted its computed accessible-intent flag; after repairing
  the guard, a broad run reached 18/20 and exposed stale saved-filter helper
  assumptions for Threats and Traffic. Threats, Traffic, NAT, Compliance, Fleet,
  Proxy/WAF, Readiness, and Settings action controls were tightened with
  contextual labels, titles, ARIA labels, and stable selectors where needed, and
  the saved-filter smoke helper now prefers semantic filter-action selectors
  while preserving label fallback. Documentation now treats Fleet as a bounded
  local-appliance workspace with local template apply/result custody, narrows
  production per-rule-hit/last-seen telemetry to hardening, and records neutral
  palette refinement plus remaining nested-frame conversion as design-system
  hardening.

  Remote-only validation passed after syncing the route-affordance source to
  `opc@139.87.66.128`
  (`/var/oled/oss-ngfw-validation/closure-audit-20260622-r1`) with Go/npm/
  Playwright caches under `/var/oled/openngfw-final-functional`: focused
  syntax checks for the touched WebUI views and smoke runner, the no-browser
  desktop smoke self-check, and `make webui-check`. Browser-required targeted
  desktop repair smoke passed for `/threats,/traffic`
  (`/var/oled/openngfw-final-functional/artifacts/enterprise-route-affordance-targeted-20260622-r1/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=2/20`, `checks=2/2`,
  `screenshots=2`, elapsed `1m07s`). Same-snapshot browser-required broad
  desktop enterprise smoke then passed all canonical routes
  (`/var/oled/openngfw-final-functional/artifacts/enterprise-route-affordance-broad-20260622-r3/webui-smoke-evidence.json`,
  `result=passed`, `mode=broad`, `routeCoverage=20/20`, `checks=20/20`,
	  `screenshots=20`, elapsed `7m01s`). This is remote continuation evidence;
	  durable release evidence still requires accepted source and repo-local
	  release recording. No local functional tests were run.

- Release gate and desktop action-affordance closure: the current source tree
  now aligns the rootless release preflight, release evidence bundle, release
  docs, and workflow contract test around the desktop enterprise WebUI gate.
  `release-check-rootless` now includes `e2e-auth-runtime-smoke` before the OIDC
  runtime smoke, and `release-evidence-rootless` records
  `release-evidence-webui-enterprise-smoke` when run from a supported remote
  browser validation host. `docs/RELEASE_ACCEPTANCE.md`, `release/README.md`,
  `docs/GUI_GAP_ANALYSIS.md`, and `docs/ROADMAP.md` no longer describe bounded
  implemented workflows as missing future work. `#/logs` now renders a
  route-local retry/API context failure state instead of leaving rejected log
  requests to the app shell, and the Dashboard now shows a partial-data warning
  when overview surfaces fail instead of silently reducing failed calls to
  neutral zeroes. The WebUI smoke runner now self-checks the generic-action
  accessibility guard and scans broader operator-control classes, while
  Traffic, Threats, Readiness, and Inspection action controls have explicit
  titles, ARIA labels, and stable hooks for generic desktop labels.

  Remote-only validation passed after syncing this closure set to
  `opc@139.87.66.128`
  (`/var/oled/oss-ngfw-validation/closure-audit-20260622-r1`) with Go/npm/
  Playwright caches under `/var/oled/openngfw-final-functional`: focused
  syntax checks for the touched WebUI views and smoke runner; the no-browser
  desktop smoke self-check; focused Go tests for `./cmd/ngfwrelease` and
  `./internal/releaseacceptance`; and `make webui-check`. Browser-required
  targeted desktop repair smoke passed for `/,/logs,/traffic,/threats,/readiness`
  (`/var/oled/openngfw-final-functional/artifacts/closure-gate-docs-action-20260622-r3/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=5/20`, `checks=5/5`,
  `screenshots=5`, elapsed `1m19s`). A focused `/inspection` repair smoke
  passed after tightening the package-review action
  (`/var/oled/openngfw-final-functional/artifacts/closure-gate-inspection-action-20260622-r1/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=1/20`, `checks=1/1`,
  `screenshots=1`, elapsed `20s`). Same-snapshot browser-required broad desktop
  enterprise smoke then passed all canonical routes
  (`/var/oled/openngfw-final-functional/artifacts/closure-gate-docs-action-broad-20260622-r2/webui-smoke-evidence.json`,
  `result=passed`, `mode=broad`, `routeCoverage=20/20`, `checks=20/20`,
  `screenshots=20`, elapsed `6m58s`). This is remote continuation evidence;
  durable release evidence still requires accepted source and repo-local
  release recording. No local functional tests were run.

- Parallel functional closure slice: the current remote validation copy on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/ui-functional-polish-20260622-r1`) now
  includes five additional enterprise functional closures. NAT simple
  SNAT/DNAT create/update/delete paths use the granular candidate NAT REST
  wrappers, including by-ID selectors and candidate revision guards where no
  compound object or generated publish-rule mutation is required; DELETE calls
  now pass audit/revision metadata through gateway-compatible query parameters.
  Rules server-overlap findings now include structured peer identity, dimension
  overlap results, result identity, risk labels, and cap/page metadata, and the
  desktop drawer renders normalized operator dimensions while preserving server
  metadata. EVE flow and alert parsing now preserves event-time policy version,
  stamp, freshness, and source from direct and nested `phragma`/`openngfw`
  fields, and Traffic/Troubleshoot show honest current/stale/newer/unknown
  policy-stamp labels. Intel content readiness now reports a production
  evidence inventory across App-ID, Threat-ID, and intel-feed packages with
  `missing`, `demo`, `production-blocked`, and `production-ready` states across
  internal status, CLI output, API/WebUI surfaces, and handoff packets.
  Settings access field-evidence handoff now parses OIDC/SAML artifact
  inventory into `passed`, `missing`, `stale`, or `unsafe` states and includes
  `artifact_status` plus `artifact_inventory` in copy/export/pin text while
  keeping real-provider certification deferred.

  Remote-only validation passed after syncing the combined source to the
  Oracle Linux host and keeping Go/npm/Playwright caches under
  `/var/oled/openngfw-final-functional`: focused Go package validation for
  `./internal/telemetry`, `./internal/apiserver`, `./internal/policy`,
  `./internal/cli`, and `./internal/contentpkg`; focused content inventory
  tests for `internal/contentpkg`, `internal/cli`, and `internal/apiserver`;
  focused WebUI tests `api_contract_surface`, `nat_host_input_identity`,
  `nat_path_preview`, `settings_access`, `troubleshoot_view`,
  `traffic_request_state`, `rules_bulk_density`, and `intel_content`; and
  `make webui-check`. Browser-required targeted desktop smoke passed for
  `/nat,/rules,/traffic,/troubleshoot,/intel,/settings` after repairing the
  NAT DELETE gateway contract and Rules overlap dimension hooks
  (`/var/oled/openngfw-final-functional/artifacts/parallel-slices-20260622-r2/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=6/20`, `checks=6/6`,
  `screenshots=6`, elapsed `3m13s`). Same-snapshot broad desktop enterprise
  smoke also passed
  (`/var/oled/openngfw-final-functional/artifacts/parallel-slices-desktop-broad-20260622-r1/webui-smoke-evidence.json`,
  `result=passed`, `mode=broad`, `routeCoverage=20/20`, `checks=20/20`,
  `screenshots=20`, elapsed `7m02s`). This is still remote continuation
  evidence until source-control acceptance and repo-local release evidence
  recording bind it to an accepted manifest. No local functional tests were
  run.

- Functional completion acceleration slice: the current remote validation copy
  on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/ui-functional-polish-20260622-r1`) now
  includes bounded functional progress across five independent enterprise
  gaps. Proxy/WAF render and engine validation now carry daemon, listener,
  cutover, and rollback proof artifacts as explicit `planned-not-executed`
  fields, and the Proxy workbench surfaces that ledger in runtime handoffs.
  Network path proof adds passive live route identity, VRF/interface evidence,
  FRR route corroboration, and masquerade egress observation fields while still
  avoiding active probes, packet capture, peer attestation, or signed custody.
  Fleet adds `POST /v1/fleet/templates/{id}:apply-plan`, per-node eligibility,
  peer-inventory input, stale candidate guards, `ngfwctl fleet templates
  apply-plan`, and WebUI apply-plan review without peer RPC or running-policy
  apply. Automation replay validation now accepts `executionMode` values for
  validate, dry-run, and apply-authority planning, returns a bounded execution
  plan, and blocks commit, rollback, host/runtime apply, packet capture start,
  HA actions, unknown routes, and other destructive/live steps. Investigation
  adds a retained-case synthesis model and desktop panel that reports
  correlation keys, owner-route readiness, server-retention coverage,
  packet-proof coverage, and unsigned/legal-hold/RBAC hardening boundaries.
  The WebUI enterprise smoke release path now requires JavaScript checks,
  Chromium browser coverage, desktop viewport coverage, and broad 20/20 route
  coverage before `ngfwrelease record` can accept WebUI smoke stdout.

  Remote-only validation passed after syncing the current source to the Oracle
  Linux host and using `/var/oled/openngfw-final-functional` for Go temp/cache
  space: `make proto`; focused Go tests for `internal/replayvalidation`,
  `internal/apiserver`, `internal/cli`, `cmd/ngfwopenapi`,
  `internal/renderers/proxy`, `internal/renderers`, `internal/engines`,
  `internal/releaseacceptance`, and `cmd/ngfwrelease`; focused JS syntax and
  behavior tests for Proxy, Net/VPN, Fleet, Investigation, automation-context,
  and API contract surface; `WEBUI_SMOKE_SELF_CHECK=1
  WEBUI_SMOKE_VIEWPORTS=desktop node e2e/webui-visual-smoke.mjs`; and
  `make webui-check`. Browser-required desktop targeted smoke passed for
  `/proxy,/netvpn,/fleet,/investigation,/settings`
  (`/var/oled/openngfw-final-functional/artifacts/functional-slices-desktop-20260622-r1/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=5/20`, `checks=5/5`,
  `screenshots=5`, elapsed `3m12s`). Same-snapshot broad desktop enterprise
  smoke also passed with the tightened release markers
  (`/var/oled/openngfw-final-functional/artifacts/functional-slices-desktop-broad-20260622-r1/webui-smoke-evidence.json`,
  `result=passed`, `mode=broad`, `routeCoverage=20/20`, `checks=20/20`,
  `screenshots=20`, elapsed `6m58s`). This broad pass is still remote
  continuation evidence until source-control acceptance and repo-local release
  evidence recording bind it to an accepted manifest. No local functional tests
  were run.

- Investigation handoff polish slice: the current remote validation copy
  (`/home/opc/oss-ngfw-v2-mixed-work/investigation-handoff-polish-20260622-r1`)
  extends active server-retained Investigation case append with browser-local
  fallback across Net/VPN tunnel handoffs, Proxy/WAF bounded artifact previews,
  Fleet local-template preview/API handoffs, Readiness system/HA/eBPF/release
  packets, Performance comparison packets, and Compliance report handoffs. This
  complements the existing Traffic/Threats/Logs/Intel active-case flows without
  claiming signed custody, legal retention, external ticket integration, or
  release evidence recording. Remote-only validation passed the focused JS
  bundle (`netvpn`, `investigation_packet`, `proxy_route`, `proxy_model`,
  `fleet`, `readiness_model`, `readiness_view`, `performance`, and
  `compliance_view`), `WEBUI_SMOKE_SELF_CHECK=1 node
  e2e/webui-visual-smoke.mjs`, `make webui-check`, targeted browser-required
  smoke for `/netvpn,/proxy,/fleet,/readiness,/performance,/compliance`
  (`result=passed`, `routeCoverage=6/20`, `checks=18/18`, elapsed `5m22s`),
  and the same-snapshot full enterprise smoke above (`routeCoverage=20/20`,
  `checks=60/60`). No local functional tests were run.

- Routing/VPN passive-to-active proof handoff polish slice: Net/VPN tunnel
  handoff checklists now split candidate route posture, route table and
  VRF/interface checks, FRR RIB/FIB review, XFRM policy/state, WireGuard or
  strongSwan runtime proof, bounded Explain/Capture/Sessions pivots, secret
  custody, redacted command/export-packet contents, and remote-attestation
  boundaries into explicit operator decision rows. Active proof packets now
  carry an export boundary stating that exported JSON contains planned commands
  and redacted passive summaries only, not raw command output, packet captures,
  bearer tokens, local paths, key paths, PSKs, private keys, or remote-host
  artifacts. This is still a browser-local proof plan and handoff; it does not
  execute probes, certify remote peers, sign artifacts, or claim production
  dataplane custody. Remote validation passed as part of the integrated final
  parallel-polish batch on `opc@139.87.66.128`; no local functional tests were
  run.

- Desktop enterprise UI functional-polish slice: the current remote validation
  copy on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/ui-functional-polish-20260622-r1`) tightens
  the current operator workflows for the desktop enterprise WebUI. Proxy/WAF
  runtime-readiness now blocks missing proxy render artifacts, uses safer
  review-only wording for reported runtime state, and defensively re-bounds and
  re-redacts preview snippets before direct copy/download and packet
  copy/export/pin handoffs. Fleet
  orchestration preview now requires positive runtime evidence for node
  eligibility, shell-quotes orchestration-preview template/revision CLI
  handoffs, bounds and scrubs orchestration packets, and preserves the
  no-peer-RPC/no-running-apply
  boundary. Traffic App-ID cluster review keeps define/review/drop actions on
  representative candidate-safe paths and distinguishes bounded Suricata
  signal-only review from v1 TCP/UDP port-hint enforcement. Net/VPN active-proof
  planning now wraps copyable commands with explicit timeouts where applicable,
  exports a redacted passive-proof summary instead of raw proof blobs, and keeps
  `activeProofStatus=planned-not-executed`. Settings Access now exposes a
  not-certified OIDC/SAML field-evidence handoff that lists `status=passed` as
  a required release-artifact sentinel, adds certificate-body redaction
  language, counts aggregate browser sessions, and keeps explicit `not
  certified` boundaries. The WebUI smoke runner also supports
  `WEBUI_SMOKE_VIEWPORTS=desktop` so enterprise desktop validation can run
  without spending this pass on tablet/mobile-only repair work.

  Remote-only validation passed: JS syntax checks for `views/proxy.js`,
  `proxy_model.js`, `views/fleet.js`, `views/traffic.js`, `views/netvpn.js`,
  `views/settings.js`, and `e2e/webui-visual-smoke.mjs`; focused WebUI tests
  `proxy_model.test.mjs`, `proxy_route.test.mjs`, `fleet.test.mjs`,
  `appid_observations.test.mjs`, `netvpn.test.mjs`, and
  `settings_access.test.mjs`; `WEBUI_SMOKE_SELF_CHECK=1 node
  e2e/webui-visual-smoke.mjs`; `WEBUI_SMOKE_VIEWPORTS=desktop
  WEBUI_SMOKE_SELF_CHECK=1 node e2e/webui-visual-smoke.mjs`; `make
  webui-check`; and desktop browser-required targeted smoke with
  `WEBUI_SMOKE_VIEWPORTS=desktop WEBUI_SMOKE_PATHS=/proxy,/fleet,/traffic,/netvpn,/settings`
  using the fresh built binary
  `/home/opc/oss-ngfw-smoke-tmp/controld-ui-functional-polish`
  (`/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-ui-functional-polish-desktop-r1/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=5/20`, `checks=5/5`,
  `screenshots=5`, elapsed `3m13s`). No local functional tests were run.
  Production hardening remains tracked under L7 proxy/WAF/API gateway
  hardening, Fleet/template orchestration hardening, App-ID enforcement
	  hardening, Network path proof custody and dataplane depth,
	  Browser/OIDC/SAML production evidence, WebUI handoff/export redaction, WebUI
	  enterprise smoke runtime evidence, and Release evidence provenance and
	  skip-proofing. Tablet/mobile route issues are not treated as blockers for this
	  desktop-focused enterprise pass per the current objective.

- Evidence custody and active-proof follow-on slice: the current remote
  validation copy on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/ui-functional-polish-20260622-r1`) adds a
  shared browser-local custody envelope to investigation handoff packets,
  including unsigned packet status, server-retained artifact pointers where
  applicable, retention-enforcement status, and explicit hardening-required
  fields. Compliance report handoffs now point at the retained server export
  while keeping the WebUI handoff packet explicitly unsigned. The server REST
  overlay now rejects empty Investigation evidence appends, returns
  `413 EVIDENCE_LIMIT_EXCEEDED` for client-controlled evidence overflow without
  mutating the case, validates Compliance report IDs against the documented
  `report-YYYYMMDDTHHMMSSZ-xxxxxxxx` shape, and emits
  `X-Phragma-Payload-Sha256` plus digest `ETag` headers on Compliance report
  export. The same slice folds in App-ID cluster corpus-custody checklist
  metadata, Proxy/WAF active runtime rollout handoff gates, and Net/VPN
  active-proof acknowledgement and execution-bound metadata.

  Remote-only validation passed: JS syntax checks for
  `investigation_packet.js`, `views/compliance.js`, `views/proxy.js`,
  `views/traffic.js`, `views/netvpn.js`, and the focused WebUI tests;
  focused JS tests `investigation_packet.test.mjs`,
  `compliance_view.test.mjs`, `proxy_route.test.mjs`,
  `appid_observations.test.mjs`, and `netvpn.test.mjs`; `go test
  ./internal/apiserver`; `make webui-check`; smoke runner self-check; and
  browser-required desktop targeted smoke for
  `/compliance,/investigation,/proxy,/netvpn,/traffic`
  (`/tmp/openngfw-webui-smoke-custody-active-20260622-r1/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=5/20`, `checks=5/5`,
  `screenshots=5`, elapsed `2m01s`). No local functional tests were run.
  Production hardening remains open for artifact signing, server-retention and
  legal-hold enforcement, RBAC-scoped export custody, signed App-ID corpus
  custody, active proxy listener/cutover proof, remote path attestation, and
  accepted-source release evidence regeneration.

- Final parallel enterprise-polish slice: the current remote validation copy on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/ui-functional-polish-20260622-r1`) now
  includes the returned App-ID, Proxy/WAF, Net/VPN, Fleet/HA, and API-contract
  slices. App-ID cluster review exposes direct-stage eligibility labels,
  production-evidence labels, and review-only boundaries for signal-only and
  non-port-hint paths. Proxy/WAF runtime-readiness adds active daemon boundary
  language, artifact manifest/hash review, and active rollout gates for listener
  health, Envoy/Coraza launch, rollback, traffic cutover, and hardening
  handoff. Net/VPN proof handoff exposes route-table/VRF/FRR/XFRM/WireGuard/
  strongSwan rows plus no-raw-output export boundaries. Fleet adds
  positive-evidence node eligibility, local-template custody fields, and
  no-peer-apply orchestration boundaries. Readiness adds HA/failover packet
  boundary modeling and Investigation packet evidence. The API contract now
  keeps generated OpenAPI, published docs spec, and bundled WebUI spec aligned
  for Investigation case success/error codes, evidence overflow `413`, retained
  target summaries, Compliance create `Location`, Compliance export digest
  headers, and the raw REST export route ownership.

  Remote-only validation passed: focused JS syntax and tests for
  `api_contract_surface`, `proxy_route`, `proxy_model`, `netvpn`,
  `appid_observations`, `fleet`, and `readiness_view`; `go test
  ./cmd/ngfwopenapi -run TestOverlayAddsBrowserAuthRoutes -count=1`; `make
  proto` on the remote host followed by generated-spec checks; `go test
  ./cmd/controld ./internal/apiserver ./internal/cli` with the focused
  Compliance/Investigation/Fleet/NetworkPath/ReleaseAcceptance/System/Proxy/
  App-ID filter; `make webui-check`; and browser-required desktop targeted
  smoke for `/proxy,/netvpn,/traffic,/fleet,/readiness`
  (`/run/user/1000/openngfw-final-polish/artifacts/final-parallel-polish-20260622-r1/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=5/20`, `checks=5/5`,
  `screenshots=5`, elapsed `2m03s`). The first smoke attempt failed before
  browser launch because the remote root filesystem was full during Go linking;
  the passing run used `/run/user/1000` for `TMPDIR`, `GOTMPDIR`, `GOCACHE`,
  and artifacts. A follow-on broad desktop run reached 11/20 routes and then
  failed on `/readiness` because Chromium crashed during screenshot capture, not
  because of a route assertion; the manifest is
  `/run/user/1000/openngfw-final-polish/artifacts/final-parallel-polish-desktop-broad-20260622-r1/webui-smoke-evidence.json`
  (`result=failed`, `checks=11/20`, elapsed `4m44s`). A targeted remainder run
  for `/readiness,/changes,/logs,/settings,/performance,/fleet,/compliance,/investigation,/troubleshoot`
  then passed
  (`/run/user/1000/openngfw-final-polish/artifacts2/final-parallel-polish-desktop-remainder-20260622-r1/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=9/20`, `checks=9/9`,
  `screenshots=9`, elapsed `2m35s`). Treat the targeted smoke evidence as
  diagnostic continuation evidence only; same-snapshot broad release evidence is
  still not recorded for this final parallel-polish source state. No local
  functional tests were run.

## Moving Notes

A filesystem move of the whole `v2-mixed` folder preserves current progress,
including untracked files. A Git-only clone or checkout will not preserve the
current work unless the untracked files are committed or copied separately.

The ignored local cache directories are not source of truth and can be omitted
from a lightweight copy:

- `.cache/`
- `.go-cache/`
- `.gocache/`
- `.gomodcache/`
- `.gopath/`
- `.npm-cache/`
- `.playwright-browsers/`
- `.tmp/`
- `.review*/`
- `node_modules/`
- `bin/`

Historical files under `release/evidence/` may contain the absolute path where
evidence was recorded. Treat those as historical evidence text, not as required
path dependencies. Regenerate release evidence after moving the folder.

## Current Functional State

The branch contains the runnable DetailTech-derived M0-M5 foundation plus the
Phragma product-definition and GUI passes:

- Candidate, validation, commit, rollback, versions, audit, policy diff
- nftables/conntrack renderer and stateful L3/L4 policy model
- NAT, static routes, BGP/OSPF, IPsec, WireGuard, host-input controls
- Suricata IDS/IPS integration and Vector/ClickHouse telemetry path
- Threat-intel feeds, signed content package mechanics, App-ID and Threat-ID
  product-layer scaffolding
- Local users, OIDC browser SSO, RBAC, CSRF, rate limits, support bundles
- Embedded WebUI covering setup, dashboard, rules, objects, NAT, traffic,
  threats, inspection, intel, routing/VPN, proxy/WAF, readiness, changes,
  logs, settings, performance, fleet, compliance, investigation, and troubleshoot

Recent completed slices add release-grade validation coverage and WebUI
operator workflow refinements:

- Commit review revision-binding slice: the current validation copy on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/commit-review-binding-20260622-main-r1`)
  makes `CommitRequest.reviewed_candidate_revision` mandatory and rejects
  commits when the shared candidate revision changed after validation, diff,
  runtime-readiness, approval, or final operator review. The WebUI Changes
  drawer captures the candidate revision when commit review opens, keeps
  approval lookup/create bound to that reviewed revision, avoids restaging the
  candidate during final commit, and shows reload/diff recovery guidance when
  a newer candidate appears. `ngfwctl commit` now fetches the current candidate
  revision by default, accepts `--candidate-revision` and
  `--expected-candidate-revision`, sends the reviewed revision on commit, and
  prints deterministic stale-candidate recovery guidance. The browser smoke
  setup path was updated to pass reviewed revisions for direct API commits so
  the release smoke exercises the production commit contract. Remote-only
  validation passed: `make proto`, `go test ./internal/apiserver
  ./internal/cli -run "Commit|RuntimePreflight|ChangeApproval" -count=1`,
  `go test ./internal/apiserver ./internal/store ./internal/cli -count=1`,
  JS syntax checks for `api.js`, `policy.js`, `views/changes.js`, and
  `e2e/webui-visual-smoke.mjs`, `api_contract_surface.test.mjs`,
  `policy_session.test.mjs`, `changes_candidate_review.test.mjs`, `make
  webui-check`, and targeted browser-required `/changes` smoke
  (`/tmp/openngfw-webui-smoke-enterprise-20260622T123558Z/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=1/19`, `checks=3/3`,
  `screenshots=3`, elapsed `1m35s`). Generated Go/gateway/OpenAPI outputs
  were synced back from the remote validation copy. No local functional tests
  were run. Production hardening remains tracked under Commit review revision
  binding, Governance approval enforcement, Privileged action step-up
  hardening, Candidate workspace integrity, and Release evidence provenance
  and skip-proofing.

- NAT and host-input durable identity slice: the current validation copy on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/nat-hostinput-identity-integrated-20260622-r1`)
  adds additive durable `id` fields to `HostInputRule`, `SourceNat`, and
  `DestinationNat`, plus NAT `matchedRuleId` fields in ExplainFlow. Candidate
  and running persistence now normalize missing, invalid, duplicate, legacy, or
  imported host-input, source-NAT, and destination-NAT IDs into stable
  `host-input-`, `snat-`, and `dnat-` identities on explicit candidate/running
  write paths. Compiler IR carries host-input/SNAT/DNAT IDs, nftables comments
  keep readable names and add `id=...` metadata, and ExplainFlow reports
  matched NAT IDs. `ngfwctl policy nat list` now displays IDs when present and
  preserves legacy empty fallback, while NAT mutation output includes `id=...`
  for durable entries. The NAT WebUI now prefers durable IDs in route focus and
  route-copy payloads, preserves IDs when editing, shows stale/missing target
  guidance, and falls back to legacy name/index links. Settings host-input now
  supports `#/settings?panel=host-input&rule=<id-or-name>&idx=<n>`, preserves
  IDs on edit, shows compact IDs, and can copy durable host-input routes.
  Remote-only validation passed: `make proto`, nftables golden regeneration,
  `go test ./internal/policy ./internal/store ./internal/compiler
  ./internal/explain ./internal/renderers/nftables ./internal/cli -count=1`,
  JS syntax checks for touched NAT/Settings/API/smoke files,
  `nat_host_input_identity.test.mjs`, `api_contract_surface.test.mjs`,
  `object_references.test.mjs`, `settings_route.test.mjs`,
  `settings_action_controls.test.mjs`, `make webui-check`, and targeted
  browser-required `/nat,/settings` smoke
  (`/tmp/openngfw-webui-smoke-enterprise-20260622T124221Z/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=2/19`, `checks=6/6`,
  `screenshots=6`, elapsed `6m34s`). Generated Go/gateway/OpenAPI outputs and
  nftables goldens were synced back from the remote validation copy. No local
  functional tests were run. Production hardening remains tracked under
  Forwarding rule identity custody, Candidate workspace integrity, WebUI
  handoff/export redaction, and Release evidence provenance and skip-proofing.

- Policy item identity follow-ons slice: the current validation copy on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/policy-item-identity-followons-20260622-r1`)
  closes the first follow-on gaps created by durable NAT/host-input IDs. NAT
  candidate mutation now has additive by-ID REST aliases for source and
  destination NAT update/delete under
  `/v1/candidate/nat/{source,destination}/by-id/{id}`. By-ID requests resolve
  strictly by durable ID, reject missing, unknown, duplicate, or mismatched IDs
  without falling back to names, preserve the durable ID across rename, and keep
  existing name-keyed routes compatible. `ngfwctl policy nat` update/delete can
  use `--id`, while delete enforces exactly one selector between `--name` and
  `--id`. Object-reference responses now populate `itemId` for forwarding
  rules, source NAT, destination NAT, and host-input rules; rename/rewrite
  responses retain resolved item IDs; CLI tables include `ITEM ID`; and the
  Objects WebUI preserves item IDs in compact display, route targets, handoff,
  copy, and export payloads with legacy fallback. `DataplaneCounter` now carries
  generic `itemId` parsed from nftables `id=...` metadata for forwarding rules,
  SNAT, DNAT, and host-input counters while preserving forwarding `ruleId`;
  `ngfwctl status` and the Dashboard counter card surface item IDs and include
  NAT/host-input counters. Remote-only validation passed: `make proto`,
  `go test ./internal/apiserver ./internal/cli -run
  "Nat|NAT|ObjectReferences|PolicyReferences|PolicyRenameObject|DataplaneCounters|PrintStatus"
  -count=1`, `go test ./internal/apiserver ./internal/cli -count=1`, JS
  syntax checks for touched Objects/Dashboard/API contract modules,
  `object_references.test.mjs`, `api_contract_surface.test.mjs`, `make
  webui-check`, and targeted browser-required `/objects,/` smoke
  (`/tmp/openngfw-webui-smoke-enterprise-20260622T130344Z/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=2/19`, `checks=6/6`,
  `screenshots=6`, elapsed `3m48s`). Generated Go/gateway/OpenAPI outputs were
  synced back from the remote validation copy. No local functional tests were
  run. Production hardening remains tracked under Forwarding rule identity
  custody, Candidate workspace integrity, WebUI handoff/export redaction,
  Release evidence provenance and skip-proofing, and telemetry/SIEM export
  hardening.

- Integrated identity/workflow polish slice: the current validation copy on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integrated-followons-20260622-r2`)
  composes the policy-item identity work with bounded operator workflow fixes.
  NAT delete/review drawers and copied row context now emit exact by-ID REST
  paths and `ngfwctl policy nat ... --id` commands for durable source and
  destination NAT rows, while preserving name-keyed fallback for legacy rows.
  Rules candidate flow-check and changed-rule verification now restage the
  current draft through guarded `session.stageDraft(...)` instead of directly
  calling `api.setCandidate(session.draft, ...)`, preserving candidate
  revision checks for no-mutation validation flows. Server-retained
  Investigation evidence now stores a bounded target summary (`kind`, `key`,
  `route`, `source`, `title`, `pinnedAt`, `collectedAt`, `addedAt`, and
  `routeRedacted`) derived from browser handoffs or legacy payloads; hydrated
  server records preserve that target marker when appended again. Release
  acceptance API/CLI detail and Readiness packet text now redact server-local
  paths, bearer material, token-like arguments, and credentialed URLs, while
  Dashboard and Diagnostic Console summary surfaces remain aggregate-only.
  The WebUI smoke assertion for object-reference-to-NAT drill-through now
  accepts durable DNAT route tokens while still requiring the selected
  `publish-web-entry` row. Remote-only validation passed: `make proto`,
  `go test ./internal/apiserver ./internal/cli -run
  "Nat|NAT|ObjectReferences|PolicyReferences|PolicyRenameObject|DataplaneCounters|PrintStatus|InvestigationCase|ReleaseAcceptance|SystemReleaseAcceptance"
  -count=1`, `go test ./internal/apiserver ./internal/cli -count=1`,
  JS syntax checks for touched policy/Rules/NAT/Readiness/Dashboard/Diagnostic/
  Investigation/smoke modules, `policy_session.test.mjs`,
  `rules_action_controls.test.mjs`, `nat_host_input_identity.test.mjs`,
  `nat_path_preview.test.mjs`, `readiness_view.test.mjs`,
  `investigation_case.test.mjs`, `investigation_view.test.mjs`,
  `api_contract_surface.test.mjs`, `make webui-check`, repaired targeted
  browser-required `/nat` smoke
  (`/tmp/openngfw-webui-smoke-enterprise-20260622T133530Z/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=1/19`, `checks=3/3`,
  `screenshots=3`, elapsed `1m52s`), and integrated targeted browser-required
  `/,/nat,/rules,/investigation,/readiness` smoke
  (`/tmp/openngfw-webui-smoke-enterprise-20260622T133744Z/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=5/19`, `checks=15/15`,
  `screenshots=15`, elapsed `3m24s`). Generated Go/gateway/OpenAPI outputs
  were synced back from the remote validation copy. No local functional tests
  were run. Production hardening remains tracked under Forwarding rule identity
  custody, Candidate workspace integrity, Investigation case custody, Release
  evidence status disclosure, WebUI enterprise smoke runtime evidence, and
  Release evidence provenance and skip-proofing.

- Parallel enterprise polish slice: the current validation copy on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/final-parallel-polish-20260622-r1`)
  composes the completed parallel worker lanes into one same-snapshot source
  state. The WebUI now has a static candidate-mutation source guard for direct
  `api.setCandidate(...)` and raw `PUT /v1/candidate` calls outside approved
  owners. Rules overlap review exposes structured peer rows, shared
  dimensions, representative tuples, confidence, and risk labels. Traffic
  App-ID review groups queue observations by candidate taxonomy, confidence
  band, and conflict state, with cluster-level copy/pin/export regression
  handoffs while preserving individual observation workflows. Logs and Intel
  can append sanitized handoff evidence to the active server-retained
  Investigation case with browser-local fallback. Network path proof returns
  additive passive route/VPN proof depth, structured mismatches, limitations,
  and copyable API/CLI handoffs; `ngfwctl system network-path prove` is
  read-only and no active probes are sent. Proxy/WAF plan proof shows bounded
  redacted artifact previews and combined preview packets without claiming
  listener health, daemon launch, signing, or traffic cutover. Fleet template
  drawers show local-appliance diff/drift workbench context, changed areas,
  candidate revision, impact rows, and exact API/CLI handoff while preserving
  the no-fan-out/no-running-apply boundary. A first-class `#/compliance`
  workbench lists, creates, inspects, copies, and exports retained unsigned
  compliance reports through existing API/CLI parity. Performance can compare
  a baseline summary with a candidate summary and emit bounded redacted delta
  payloads while keeping public comparison claims behind release evidence.
  Changes snapshot restore supports route-backed validation/restore-preview
  drawers and browser-local maintenance review packets with explicit
  no-direct-candidate-mutation custody boundaries. Remote-only validation
  passed: `make proto`, `go test ./internal/apiserver ./internal/cli -run
  "NetworkPath|SystemNetworkPath|ReleaseAcceptance|InvestigationCase|Compliance|Fleet"
  -count=1`, focused WebUI behavior tests for candidate mutation guard, Rules
  overlap, App-ID clusters, Net/VPN proof, Logs/Intel/Investigation handoffs,
  Proxy previews, Fleet diff/drift, Compliance workbench, Performance
  comparison, snapshot restore, Changes audit, and API contract surface,
  `make webui-check`, repaired targeted browser-required `/proxy` smoke,
  targeted changed-route browser-required
  `/rules,/traffic,/netvpn,/logs,/intel,/proxy,/fleet,/compliance,/performance,/changes`
  smoke (`result=passed`, `mode=targeted`, `routeCoverage=10/20`,
  `checks=30/30`), and a fresh same-snapshot broad browser-required
  `make webui-enterprise-smoke`
  (`/tmp/openngfw-webui-smoke-enterprise-20260622T143407Z/webui-smoke-evidence.json`,
  `result=passed`, `mode=broad`, `routeCoverage=20/20`, `checks=60/60`,
  `screenshots=60`, elapsed `21m22s`). Generated Go/gateway/OpenAPI outputs
  were synced back from the remote validation copy. No local functional tests
  were run. Production hardening remains tracked under Candidate workspace
  integrity, Investigation case custody, Network path proof custody and
  dataplane depth, L7 proxy/WAF/API gateway hardening, Fleet template
  candidate staging custody, Compliance report custody, Performance evidence
  verifier hardening, HA and restore security, WebUI enterprise smoke runtime
  evidence, and Release evidence provenance and skip-proofing.

- Durable forwarding rule identity, Rules route adoption, Fleet CLI parity, and
  Proxy runtime-readiness slice: the current validation copy on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/rule-identity-fleet-rules-20260622-r1`)
  makes forwarding rule IDs server-authoritative for candidate and running
  persistence. Candidate/commit/validation/render paths normalize missing,
  invalid, duplicate, legacy, or imported forwarding rule IDs into stable
  `rule-<label>-<hash>` identities before validation; store audit detail
  records bounded `rule-id-backfill` counts when normalization changes a
  persisted policy. Candidate change summaries now key forwarding-rule changes
  by durable ID, ExplainFlow returns `matchedRuleId`, `ngfwctl explain` prints
  the matched ID, nftables comments carry rule IDs, and dataplane counter
  parsing exposes `ruleId` separately from the operator-facing rule name. The
  Rules WebUI now prefers `ruleId` route state and target snapshots while
  preserving legacy `rule=<name>` links, narrows duplicate-name caveats to
  legacy rules without IDs, and keeps bulk staging bound to refreshed snapshot
  indexes. Fleet gained bounded local-appliance `ngfwctl fleet` commands for
  nodes, templates list/get/create/validate/apply-preview/stage-candidate with
  candidate-revision guard UX and explicit no-fan-out/no-HA-traffic boundary.
  Proxy/WAF gained deterministic runtime-readiness artifacts and a managed
  engine launch-plan validator for Envoy/Coraza plan artifacts without
  registering a live daemon or cutting over traffic. Remote-only validation
  passed: `make proto`, remote-regenerated nftables golden files, `go test
  ./internal/policy ./internal/store ./internal/apiserver ./internal/explain
  ./internal/compiler ./internal/renderers/... ./internal/engines
  ./internal/cli -count=1`, JS syntax checks for changed smoke/Rules files,
  `rules_bulk_density.test.mjs`, `api_contract_surface.test.mjs`, `make
  webui-check`, repaired targeted `/rules` browser smoke
  (`/tmp/openngfw-webui-smoke-enterprise-20260622T115251Z/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=1/19`, `checks=3/3`,
  elapsed `1m00s`), combined targeted
  `/rules,/fleet,/proxy,/traffic,/threats,/troubleshoot,/changes` smoke
  (`/tmp/openngfw-webui-smoke-enterprise-20260622T115415Z/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=7/19`, `checks=21/21`,
  elapsed `5m18s`), and a fresh same-snapshot broad browser-required
  `make webui-enterprise-smoke`
  (`/tmp/openngfw-webui-smoke-enterprise-20260622T115954Z/webui-smoke-evidence.json`,
  `result=passed`, `mode=broad`, `routeCoverage=19/19`, `checks=57/57`,
  `screenshots=57`, elapsed `21m18s`). No local functional tests were run.
  Production hardening remains tracked under Forwarding rule identity custody,
  Candidate workspace integrity, Fleet template candidate staging custody, and
  L7 proxy/WAF/API gateway hardening.

- Compliance API/CLI parity, Fleet stage-to-candidate, and Proxy plan-proof
  slice: the current validation copy on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/compliance-fleet-proxy-20260622-r1`) adds
  a first-class `ComplianceService` protobuf/gRPC/gateway contract for retained
  unsigned compliance reports, generated Go/gateway/OpenAPI outputs, explicit
  OpenAPI overlay schemas for existing browser REST report routes, RBAC method
  registration, and `ngfwctl compliance reports list|get|create|export`. The
  server reuses the retained report store and builder, preserves audit-failure
  rollback, returns export payload SHA-256 on create, and keeps report signing,
  retention, legal hold, and external evidence verification as hardening work.
  Fleet now exposes bounded
  `POST /v1/fleet/templates/{id}:stage-candidate` for server-retained local
  templates. It validates the stored policy, requires
  `expectedCandidateRevision`, rejects stale candidate revisions, writes the
  local candidate with audit in the same store transaction, returns candidate
  revision/status context, and keeps the boundary explicit: no peer fan-out, no
  running-policy apply, no HA traffic control, and no distributed result
  custody. The Fleet WebUI can validate, apply-preview, stage a local template
  to candidate, and link the result drawer to Changes. Proxy/WAF now has a
  route-backed `#/proxy?drawer=plan` workflow that validates the candidate via
  the existing validation API and shows render-plan metadata/artifact presence,
  blocker notes, and Changes/Readiness pivots without exposing artifact bytes
  or claiming active proxy rollout. Remote-only validation passed: `make proto`
  including buf lint and generated OpenAPI copy, `go test ./cmd/ngfwopenapi
  ./internal/apiserver ./internal/cli -count=1`, JS syntax checks for touched
  API/Fleet/Proxy/smoke modules, `api_contract_surface.test.mjs`,
  `fleet.test.mjs`, `proxy_model.test.mjs`, `proxy_route.test.mjs`, `make
  webui-check`, targeted browser-required `/fleet,/proxy` smoke
  (`/tmp/openngfw-webui-smoke-enterprise-20260622T110248Z/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=2/19`, `checks=6/6`,
  elapsed `1m03s`), and a fresh same-snapshot broad browser-required
  `make webui-enterprise-smoke`
  (`/tmp/openngfw-webui-smoke-enterprise-20260622T110508Z/webui-smoke-evidence.json`,
  `result=passed`, `mode=broad`, `routeCoverage=19/19`, `checks=57/57`,
  `screenshots=57`, elapsed `21m19s`). No local functional tests were run.
  Production hardening remains tracked under Audit compliance report custody
  and profile governance, Fleet template candidate staging custody, and L7
  proxy/WAF/API gateway hardening.

- Investigation lifecycle, OpenAPI, and active server-custody slice: the current
  integration copy on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-current-20260622-r3`) now
  supports audited `PATCH /v1/investigation/cases/{id}` lifecycle updates for
  bounded `open`, `investigating`, `resolved`, and `closed` states, sanitized
  resolution notes, resolved actor/timestamp metadata, and audit-failure
  rollback. The OpenAPI overlay now publishes Investigation list/create/get/
  update/append routes and regenerated `docs/api-spec.yaml`,
  `internal/webui/static/api-spec.yaml`, and
  `api/gen/openapi/api-spec.swagger.yaml` from remote `make proto`. The WebUI
  persists the active server case, opens/hydrates retained server evidence back
  into the Investigation workbench, and lets Traffic/Threats append selected
  evidence to the active server case with browser-local fallback. Remote-only
  validation passed: `make proto`, `node --check` for the touched WebUI/smoke
  modules, `go test ./cmd/ngfwopenapi ./internal/apiserver -count=1`, `make
  webui-check`, targeted browser smoke for `/traffic,/threats,/investigation`
  (`/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-investigation-server-20260622T100709Z/webui-smoke-evidence.json`,
  `result=passed`, `routeCoverage=3/19`, `checks=9/9`, elapsed `2m49s`), and a
  fresh same-snapshot broad `WEBUI_SMOKE_REQUIRE_BROWSER=1 make
  webui-enterprise-smoke` (`/tmp/openngfw-webui-smoke-enterprise-20260622T101030Z/webui-smoke-evidence.json`,
  `result=passed`, `mode=broad`, `routeCoverage=19/19`, `checks=57/57`,
  `screenshots=57`, elapsed `20m43s`). No local functional tests were run.
  Production hardening remains tracked under the dedicated Investigation case
  custody row for immutable evidence refs, signing, retention/legal hold, RBAC
  split, HA replication, external IR/CAB integration, tamper resistance, export
  custody, and disclosure parity.

- Enterprise smoke, server custody, and audit rollback slice: the current
  integration copy on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-current-20260622-r3`) passed
  a historical all-viewport remote continuation run across the then-current
  19-route set, including `/proxy`, for desktop, tablet, and mobile. The current
  accepted-source release gate is browser-required desktop
  `make webui-enterprise-smoke` unless `WEBUI_ENTERPRISE_SMOKE_VIEWPORTS` is
  deliberately overridden, and the latest broad route count is now the
  20-route canonical set recorded at the top of this file.
  Manifest:
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-enterprise-rbac-dashboard-20260622T092805Z/webui-smoke-evidence.json`
  (`result=passed`, `mode=broad`, `routeCoverage=19/19`, `checks=57/57`,
  `screenshots=57`, elapsed `20m41s`). Targeted repair evidence for
  `/traffic,/settings,/investigation` also passed with manifest
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-repairs-r20/webui-smoke-evidence.json`
  (`result=passed`, `routeCoverage=3/19`, `checks=9/9`, elapsed `6m17s`).
  The same remote copy passed post-sync focused validation for JavaScript
  syntax, Dashboard telemetry-scope model coverage, Investigation server
  custody view coverage, `make webui-visual-smoke-self-check`, `make
  webui-check`, and Go tests for `./internal/fleet`, `./internal/store`, and
  `./internal/apiserver`. Functional fixes in this slice add audit-failure
  rollback for Fleet template creation, Investigation case create/append, and
  retained compliance report creation; add handler coverage for server-retained
  Investigation create/list/get/append plus redaction/audit behavior; add Fleet
  audit-failure rollback coverage; strengthen Dashboard first-page telemetry
  disclosure coverage; and lock the enterprise smoke route alias/de-duplication
  contract. No local functional tests were run. Durable release evidence,
  signed custody, retention, HA replication, external ticket/CAB integration,
  and accepted-source evidence regeneration remain hardening/release work.

- Network path proof API and Net/VPN workbench slice: `SystemService` now
  exposes read-only `ProveNetworkPath` at
  `POST /v1/system/network-path:prove`, sampling a fixed `ip -j route get`
  lookup for a representative source/destination tuple and correlating passive
  WireGuard or IPsec runtime evidence without sending probe traffic or accepting
  arbitrary command input. The response reports route state, selected device,
  preferred source, passive VPN state, running policy version, evidence labels,
  and warnings such as expected-interface mismatches. Net/VPN now exposes
  operator-facing Prove actions for representative tunnel paths and renders the
  route/VPN/policy evidence in a drawer while preserving Explain, Capture, and
  Sessions pivots. Rule IDs are now carried through compiler IR so existing
  renderer metadata compiles with the current generated policy contract, and
  the Net/VPN visual-smoke dynamic-routing settle wait was extended without
  weakening its required-control assertions. Remote validation on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/network-path-proof-20260622-r1`) passed
  `make proto`, `node --check` for `api.js` and `views/netvpn.js`,
  `netvpn.test.mjs`, `api_contract_surface.test.mjs`, focused Go tests for
  `./internal/apiserver` and `./internal/authz`, `make webui-check`, focused
  remote compiler/nftables renderer tests after the RuleIR ID fix, and targeted
  browser-required `/netvpn` smoke across desktop, tablet, and mobile with
  manifest
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-network-path-proof-r2/webui-smoke-evidence.json`
  (`result=passed`, `routeCoverage=1/18`, `checks=3/3`, elapsed `3m35s`).
  Generated Go/gateway/OpenAPI outputs were synced back from the remote
  validation copy. A narrow local compiler/nftables check was run accidentally
  during diagnosis and is not treated as release or continuation evidence.

- Telemetry pagination and high-volume workbench slice: Flow, Alert, live
  Session, and App-ID observation list contracts now expose `pageCursor`,
  `nextCursor`, `hasMore`, and `totalMatches` so operators can browse filtered
  high-volume telemetry instead of being capped at one fixed result slice. The
  telemetry and conntrack readers implement cursor pages over the filtered
  newest-first recent-tail or live snapshot view, reject malformed cursors at
  the API layer, and preserve existing limit-only callers. The Traffic WebUI
  now carries URL-backed Prev/Next cursor state for Flows, Sessions, and App-ID
  queue views; Threats alert triage carries the same URL-backed paging controls
  and count summaries. API client contract tests now cover cursor query
  propagation for `/v1/flows`, `/v1/alerts`, `/v1/sessions`, and
  `/v1/app-id/observations`, with request-state tests for cursor sanitization.
  Remote validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/telemetry-pagination-20260622-r1`) passed
  `make proto`, focused JS syntax checks for the touched WebUI/API modules,
  `traffic_request_state.test.mjs`, `threats_request_state.test.mjs`,
  `api_contract_surface.test.mjs`, focused Go tests for
  `./internal/telemetry`, `./internal/conntrack`, and `./internal/apiserver`,
  and `make webui-check`. Targeted browser-required smoke for
  `/traffic,/threats` passed across desktop, tablet, and mobile with manifest
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-telemetry-pagination-r1/webui-smoke-evidence.json`
  (`result=passed`, `routeCoverage=2/18`, `checks=6/6`, elapsed `2m33s`).
  `make proto-status` in that rsync validation copy could not complete its
  Git-backed dirty-tree checks because `.git/` was intentionally excluded from
  the copy, but it did report OpenAPI copy consistency
  (`generated -> docs: ok`, `docs -> webui: ok`) and no untracked contract
  inputs/outputs in that copy. No local functional tests were run.

- Parallel enterprise-gap discovery slice: five subagents inspected the next
  independent functional gaps without editing files or running local functional
  tests. At the time, the recommended next implementation slices were
  backend-enforced change governance approvals bound to candidate revision and
  consumed by commit, durable rule IDs carried through policy/API/compiler/
  render metadata and Rules bulk targeting, a read-only
  `/v1/system/network-path:prove` API for kernel route plus VPN tunnel proof,
  server-side investigation case custody with browser-local fallback/import,
  and security profile control preservation into compiler IR plus managed
  Suricata profile rule generation for the first complete layered-control
  enforcement path. Later slices implemented the approval records, passive
  path proof, basic server-retained investigation cases, and security-profile
  IR/Suricata path; durable rule IDs and production custody remain open.
  Hardening-only items identified by those explorations include configurable
  approval policy/quorum, signed approval/case/evidence custody, legal
  retention, step-up auth, HA/cross-node replication, external CAB/ticket
  integration, URL/DNS content taxonomy quality certification, TLS decryption
  CA lifecycle, active path probing, and deeper XFRM/VRF/peer attestation.

- WebUI NetVPN route guard and enterprise-smoke repair slice: the app shell now
  rejects stale async route renders so an older route cannot overwrite the
  current hash route after rapid navigation. The NetVPN view tolerates `null`
  BGP/OSPF policy sections as disabled candidate config instead of throwing
  during render. The WebUI visual smoke NetVPN flow now waits for expected
  action-control contracts, uses forced route reloads after direct candidate
  seeding so the browser session receives the current candidate revision, waits
  for UI completion after dynamic-routing disable actions, and labels drawer
  close diagnostics with drawer/toast state. Remote validation on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/netvpn-route-guard-20260622-r1`) passed
  focused syntax and WebUI checks, targeted `/netvpn` smoke across desktop,
  tablet, and mobile with manifest
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-netvpn-route-guard-r8/webui-smoke-evidence.json`
  (`result=passed`, `routeCoverage=1/18`, `checks=3/3`), adjacent
  `/netvpn,/objects,/readiness,/changes` smoke with manifest
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-netvpn-adjacent-route-guard-r1/webui-smoke-evidence.json`
  (`result=passed`, `routeCoverage=4/18`, `checks=12/12`), and the full
  `make webui-enterprise-smoke` broad route sweep with manifest
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-enterprise-netvpn-route-guard-r1/webui-smoke-evidence.json`
  (`result=passed`, `routeCoverage=18/18`, `checks=54/54`, elapsed `20m43s`).
  A final remote pass also succeeded for `node --check` on the touched WebUI
  and smoke modules, `app_shell_controls.test.mjs`, `netvpn.test.mjs`,
  `make webui-check`, and `make webui-visual-smoke-self-check`. No local
  functional tests were run.

- Candidate revision guard and WebUI release-gate modeling slice: candidate
  status now exposes an optimistic-concurrency `candidateRevision`, and
  `SetCandidate` accepts `expectedCandidateRevision` so browser sessions,
  direct Rules explain/verification restaging, and API clients cannot silently
  replace a candidate that changed after they loaded it. The store rejects
  stale guarded writes atomically before audit/candidate mutation, and the WebUI
  blocks candidate edits when it cannot load a revision token. The release
  acceptance model now includes a formal `webui-enterprise-smoke` check plus
  `release-evidence-webui-enterprise-smoke`, so broad WebUI route coverage can
  be recorded as durable release evidence after source-control acceptance
  instead of remaining only continuation evidence. Rules route-backed bulk
  review links now carry a bounded target snapshot of rule index, display name,
  and signature; reopened bulk drawers target the snapshotted rules rather than
  the current visible filter result, and staging rejects stale or missing route
  targets before `session.apply`. Remote validation on `opc@139.87.66.128`
  first used `/home/opc/oss-ngfw-v2-mixed-work/candidate-revision-20260622-r1`
  to run `make proto`, focused WebUI syntax/API/session checks, and focused Go
  coverage for store, policy API, and release-acceptance WebUI gate modeling.
  The final combined remote snapshot at
  `/home/opc/oss-ngfw-v2-mixed-work/candidate-revision-rules-20260622-r1`
  passed `make proto`, `make webui-check`, and
  `go test ./internal/store ./internal/apiserver ./internal/releaseacceptance -count=1`.
  `make proto-status` still fails as expected because the API contract bundle
  is not source-control accepted, but it reports `generated -> docs: ok` and
  `docs -> webui: ok`. Generated policy service Go/gateway output and OpenAPI
  docs/WebUI specs were synced back from the remote validation copy. No local
  functional tests were run by this continuation pass.

- API contract naming, WebUI context, and recordability diagnostics slice:
  the API contract wording now describes the accepted boundary as an atomic
  proto/generator/generated-spec/docs/WebUI bundle plus maintained auth routes
  registered outside protobuf, instead of implying a proto-only public
  contract. Visible WebUI/API context examples now use the generated public
  camelCase path placeholders (`{queueId}`, `{sessionId}`) while leaving
  grpc-gateway proto annotations on snake_case field names, and the selected
  Threat-ID exception PATCH example now matches the actual
  `{ "exception": {...}, "reason": "...", "confirmGlobal": ... }` request
  shape. `api_contract_surface.test.mjs` now covers
  `api.stageAppIdObservation()` and `api.explainFlow()`, and the release
  diagnostics integration test proves `make release-recordability-diagnostics`
  prints both API-contract and source-tree blocker sets without writing
  evidence. Readiness fallback packet commands now point `e2e-install`
  validation at `sudo make e2e-install` instead of the static preflight target,
  and label `m3-live-networking-check` as a preflight before
  `sudo make m3-live-networking` validation. Remote validation on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/api-contract-20260622-r2`) passed
  `node --check` for the touched WebUI modules, passed the API contract
  surface test with `node --require ./internal/webui/static/js/node_test_polyfills.cjs`,
  passed `make webui-check`, and passed
  `go test -tags integration ./test/integration -run TestReleaseRecordabilityDiagnosticsReportsBothBlockerSetsWithoutEvidence -count=1`.
  The same remote snapshot ran `make proto`; regenerated
  `api/gen/openapi/api-spec.swagger.yaml`, `docs/api-spec.yaml`, and
  `internal/webui/static/api-spec.yaml` were synced back into this worktree.
  `make proto-status` still fails as expected because the API contract bundle
  is not source-control accepted yet, but it reports
  `generated -> docs: ok` and `docs -> webui: ok`. No local functional tests
  were run. A follow-up refreshed remote copy at
  `/home/opc/oss-ngfw-v2-mixed-work/api-contract-20260622-r3` passed
  `node --check internal/webui/static/js/views/readiness.js`,
  `make webui-check`, the API contract surface test, and the release
  diagnostics integration test after the Readiness command-guidance fix.

- GUI documentation and candidate-bar polish slice: the GUI research docs now
  include current implementation overlays that separate smoke-covered WebUI
  surfaces, remaining functional gaps, and hardening-only gaps while preserving
  the original research citations. `docs/webui-design.md`,
  `docs/GUI_FEATURE_MATRIX.md`, and `docs/GUI_GAP_ANALYSIS.md` now state that
  broad WebUI smoke is continuation evidence for the dirty worktree, not
  durable release evidence. The mobile candidate bar now allows wrapped text
  and wrapped action rows with usable mobile tap targets, and the `/changes`
  smoke asserts the dirty/blocked mobile candidate-bar state, action count,
  overflow, wrapping, and button size. Remote validation on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-20260622-docs-recordability-candidatebar-r1`)
  passed `node --check e2e/webui-visual-smoke.mjs`,
  `make webui-visual-smoke-self-check`, `make webui-check`, and
  browser-required targeted `/changes` smoke across desktop, tablet, and
  mobile. The smoke manifest at
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-docs-recordability-candidatebar-r1/webui-smoke-evidence.json`
  reported `result=passed`, `mode=targeted`, `routeCoverage=1/18`, 3/3
  checks, and zero failure records. No local functional tests were run.

- Release recordability diagnostics refresh: a Git-aware remote copy on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/release-recordability-20260622-r1`)
  was used to run `make proto-status` and `make release-recordability-check`
  with remote workspace-local Go caches. `make proto-status` confirmed the
  generated OpenAPI copy chain is internally consistent
  (`api/gen/openapi/api-spec.swagger.yaml` -> `docs/api-spec.yaml` ->
  `internal/webui/static/api-spec.yaml`), but failed as expected because API
  contract inputs and outputs are still modified or untracked. The unrecordable
  set includes modified existing protobuf/generated files and new contract
  inputs/outputs such as `api/openapi.yaml`,
  `api/proto/google/api/httpbody.proto`,
  `api/proto/openngfw/v1/app_service.proto`,
  `api/proto/openngfw/v1/explain_service.proto`,
  `api/proto/openngfw/v1/threat_tuning_service.proto`,
  `cmd/ngfwopenapi/`, new generated `app_service`, `explain_service`, and
  `threat_tuning_service` Go/gateway outputs, plus the published docs/WebUI
  OpenAPI copies. `make release-recordability-check` also failed as designed:
  `ngfwrelease recordability` reported `recordability: blocked`, matching
  `HEAD` and the requested commit but rejecting the source tree because dirty
  paths outside `release/evidence`, `release/field-evidence`, and
  `perf/release-results` remain. This proves the release tooling is providing
  deterministic blocker diagnostics; it does not make release evidence
  recordable until the source tree/API contract bundle is accepted.
  `make release-recordability-diagnostics` now wraps the same diagnostic shape:
  it runs `proto-status` and strict recordability, prints both blocker sets,
  records no evidence, and exits nonzero while either gate is blocked. The
  target was validated on the combined remote snapshot above and failed with
  the expected API-contract and source-tree blockers.

- Integrated WebUI broad-repair and route-contract validation slice: the
  remote failed-route replay for the previous broad failure manifest now passes
  all nine previously failing routes (`/`, `/rules`, `/threats`, `/traffic`,
  `/logs`, `/performance`, `/intel`, `/readiness`, and `/settings`) across
  desktop, tablet, and mobile. The replay manifest at
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-broad-repair-replay-r1/webui-smoke-evidence.json`
  reported `result=passed`, `mode=targeted`, `routeCoverage=9/18`, 27/27
  checks, 27 screenshots, and zero failure records. A follow-on WebUI
  route-contract repair made Dashboard Routing/VPN owner links restore a
  route-backed Net/VPN runtime-review drawer and made Fleet template-preview
  handoff routes restore and close-clean their route-backed drawer. Remote
  validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-20260622-broad-repair-r3`)
  passed `node --check` for the touched Net/VPN, Fleet, Net/VPN test, and
  visual-smoke files, passed `make webui-visual-smoke-self-check`, passed
  `make webui-check`, and passed focused browser-required
  `WEBUI_SMOKE_PATHS=/,/fleet,/netvpn` smoke across desktop, tablet, and mobile
  with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-route-contract-r1`.
  The same remote snapshot then passed the full broad
  `make webui-enterprise-smoke` sweep across all 18 routes and all three
  viewports. The manifest at
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-enterprise-broad-repair-r1/webui-smoke-evidence.json`
  reported `result=passed`, `mode=broad`, `routeCoverage=18/18`, 54/54 checks,
  54 screenshots, and elapsed runtime of 20m51s. This was strong continuation
  evidence for the pre-Proxy 18-route snapshot; the current continuation
  evidence is the later 20-route broad manifest recorded near the top of this
  file. No local functional tests were run.

- Readiness release command disclosure slice: the release acceptance status
  drawer now derives next-command guidance from the release evidence packet
  catalog for blocked checks and for known gates omitted from the status
  endpoint, while keeping the summary report command-free and routing detailed
  text through the existing Readiness redaction policy for server-local paths,
  bearer material, credentialed URLs, and secret-like key/value material.
  Remote validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/readiness-release-command-disclosure-20260622-r1`)
  passed `node --check internal/webui/static/js/views/readiness.js`,
  `node --check internal/webui/static/js/readiness_view.test.mjs`,
  `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/readiness_view.test.mjs`, `make webui-check`, and
  browser-required targeted `/readiness` smoke across desktop, tablet, and
  mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-readiness-release-command-disclosure-r1`.
  No local functional tests were run.

- WebUI broad-smoke replay helper slice: the visual smoke runner can now use
  `WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST=/path/to/webui-smoke-evidence.json` to
  derive a targeted rerun route set from a previous failed broad manifest's
  failed route records and failed route results. The selected routes are
  de-duplicated in canonical route order, the evidence source is reported as
  `WEBUI_SMOKE_REPLAY_FAILURE_MANIFEST`, and the requested-route accounting
  matches the failed route set instead of defaulting back to broad coverage.
  `make webui-visual-smoke-replay-failures` wraps the same behavior with an
  explicit manifest requirement for repair loops. This is targeted repair
  workflow support only; replayed failed-route checks still must be paired with
  a same-snapshot successful broad sweep before any broad-plus-targeted release
  claim. Remote validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-20260622-broad-repair-r1`)
  passed `node --check e2e/webui-visual-smoke.mjs` and
  `make webui-visual-smoke-self-check`. No local functional tests were run.

- Integrated round-seven remote validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-20260621-round7-r1`)
  covered the app-shell accessibility/mobile navigation polish, WebUI smoke
  evidence-readiness diagnostics, release stale-evidence recordability guard,
  release/diagnostic disclosure parity, Object/NAT destination-NAT no-op
  prevention, and Traffic/Threats/Logs route-backed handoff metadata together.
  The combined pass ran `node --check` for `app.js`, `views/traffic.js`,
  `diagnostic_console.js`, `views/nat.js`, and `e2e/webui-visual-smoke.mjs`;
  ran focused shell, diagnostic-console, and object-reference JS tests; ran
  `make webui-visual-smoke-self-check`; and passed `make webui-check` on the
  same remote checkout. Browser-required targeted smoke then passed
  `WEBUI_SMOKE_PATHS=/,/traffic,/threats,/logs,/nat,/readiness` across
  desktop, tablet, and mobile with all 18 route checks passing via Playwright.
  The final smoke manifest at
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-round7-integrated-r1/webui-smoke-evidence.json`
  reported `result=passed`, `mode=targeted`, `routeCoverage=6/18`, zero
  failure records, 18 completed/passed checks, and 18 screenshots. The new
  operator summary identified the slowest routes as NAT, Threats, Traffic,
  Logs, and Dashboard, with no console, HTTP, critical-resource, or overflow
  diagnostics on those route summaries. The remote host required installing
  Playwright into the validation copy and clearing old remote validation
  scratch/cache directories before browser smoke could compile and launch
  `controld`. No local functional tests were run. This remains targeted
  continuation evidence and must still be paired with a same-snapshot broad
  enterprise route sweep plus durable release-evidence recording before any
  broad-plus-targeted production release claim.

- Traffic/Threats/Logs route-backed handoff context slice: Traffic flow,
  session, App-ID observation, and App-ID regression handoff packets now carry
  capture/regression workflow metadata with Troubleshoot capture routes,
  App-ID queue/corpus routes where applicable, focused Investigation case
  routes, bounded capture limits, and explicit browser-local custody notes.
  Threat alert handoffs carry capture, capture-audit, Threat-ID content
  quality, canary, exception-review, candidate-review, and focused
  Investigation routes. System log handoffs attach focused Investigation
  routes to the existing log-derived capture-plan packet context. This remains
  a copy/pin/export operator workflow improvement only: it does not execute
  packet captures, mutate policy, approve false positives, sign corpus
  artifacts, create server-side cases, or record durable release evidence.
  Remote validation for this slice should be performed on
  `opc@139.87.66.128`; no local functional tests were run.

- App shell accessibility and mobile navigation polish slice: the embedded
  WebUI shell now has a skip link to the primary workspace, a focusable
  workspace target, a button-backed mobile navigation scrim, body scroll lock
  while the off-canvas navigation is open, viewport-aware sidebar `aria-hidden`
  state, and resize synchronization so desktop navigation is not hidden after a
  mobile breakpoint transition. This is functional UI ergonomics work only; it
  does not change route business logic, auth, policy mutation, or release
  evidence semantics. Remote validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/app-shell-polish-20260621-r1`) passed
  `node --check internal/webui/static/js/app.js`,
  `node --check internal/webui/static/js/app_shell_controls.test.mjs`, and
  `node internal/webui/static/js/app_shell_controls.test.mjs`. An initial
  broader `make webui-check` on that remote checkout exposed unrelated
  parallel-work failures in `views/traffic.js` and
  `diagnostic_console.test.mjs`; the later integrated round-seven remote pass
  fixed those issues and passed `make webui-check` plus targeted browser smoke.
  No local functional tests were run.

- WebUI enterprise smoke evidence-readiness slice: the visual smoke runner now
  writes an operator-readable manifest summary with runner metadata, requested
  route entries versus canonical selected routes, pass/fail/incomplete check
  counts, screenshot count, elapsed runtime, release-evidence posture, per-route
  duration aggregation, slow-route ranking, and structured failure diagnostics.
  The human output also prints the summary, slowest routes, failed route checks,
  and manifest path so a broad route sweep can be reviewed as release-adjacent
  continuation evidence without hand-parsing every per-viewport record. The
  enterprise smoke target now defaults to a timestamped artifact directory to
  reduce stale-manifest confusion. This improves continuation evidence only;
  CI budget SLAs, cross-run route-duration trend retention, and durable
  release-evidence custody remain hardening work in
  `docs/HARDENING_BACKLOG.md`. Remote validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/webui-smoke-evidence-readiness-r1`)
  passed `node --check e2e/webui-visual-smoke.mjs` and
  `make webui-visual-smoke-self-check`. A remote full-route
  `make webui-enterprise-smoke` completed all 54 planned desktop/tablet/mobile
  checks and wrote
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-enterprise-20260622T002025Z/webui-smoke-evidence.json`,
  proving the new manifest fields and timestamped artifact directory, but the
  broad smoke result was failed: 35 passed checks, 19 failed checks, zero
  incomplete checks, 54 screenshots, and slowest routes of Settings,
  Routing/VPN, Objects, NAT, and Changes. Treat that run as diagnostics only,
  not release-adjacent pass evidence. No local functional tests were run.

- Integrated parallel-round six validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-20260621-parallel-round6-r1`)
  covered the Guided Setup topology proof handoff, Changes strict UI evidence,
  Fleet/HA production-boundary workflow, Intel content promotion decision,
  Settings access lifecycle parity, Performance release-claim drill-through,
  Routing/VPN field-proof checklist, Rules durable identity disclosure,
  Readiness packet consistency, and WebUI visual-smoke diagnostics slices
  together. The combined pass ran `node --check` for all touched WebUI view
  modules and the smoke runner, `make webui-visual-smoke-self-check`, focused
  JS tests for setup, changes candidate review, fleet, Intel content, Settings
  access/route state, Performance, Routing/VPN, Rules bulk density, and
  Readiness view/model behavior, then passed `make webui-check` on the same
  remote checkout. Browser-required targeted smoke then passed
  `WEBUI_SMOKE_PATHS=/setup,/changes,/fleet,/intel,/settings,/performance,/netvpn,/rules,/readiness`
  across desktop, tablet, and mobile with all 27 route checks passing via
  Playwright. The final smoke manifest at
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-parallel-round6-r2/webui-smoke-evidence.json`
  reported `result=passed`, `mode=targeted`, `routeCoverage=9/18`, zero failure
  records, 27 route results, and 27 screenshots. No local functional tests were
  run. This is targeted continuation evidence; it still must be paired with a
  same-snapshot broad sweep and durable release-evidence recording before it is
  treated as production release evidence.

- WebUI visual smoke release diagnostics polish slice: the visual smoke runner
  now records ordered route selection, per-route/per-viewport result objects,
  route diagnostics, failure records, screenshot bindings, remaining checks,
  and broad-vs-targeted release evidence messaging in
  `webui-smoke-evidence.json`. Human failure output now includes mode,
  coverage, route order, missing broad routes, failed route checks, manifest
  path, progress, and the release-evidence caveat without relaxing any route,
  viewport, layout, console, asset, or workflow assertions. A
  `webui-visual-smoke-self-check` Makefile target exercises route ordering,
  de-duplication, unknown-route fail-fast behavior, policy messaging, and broad
  default selection without launching the app. Remote validation on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/run-20260621-settings-auth-lifecycle-parity-r1`)
  passed `node --check e2e/webui-visual-smoke.mjs`, passed
  `make webui-visual-smoke-self-check`, and passed browser-required targeted
  `/settings` smoke across desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-diagnostics-polish-r1`.
  The manifest reported `mode=targeted`, `routeCoverage=1/18`, route order
  `["/settings"]`, three passed route results, zero failure records, and
  screenshots for all three viewports. No local functional tests were run.

- Rules durable identity disclosure polish slice: Rules bulk review now exposes
  an explicit identity caveat in the review drawer and copied review context:
  selections are still current candidate name/position snapshots, duplicate
  selected names require position review, hidden targets must be confirmed
  before staging, and copied handoffs must not be reused across reorder,
  duplicate/rename/delete, pagination, or virtualization boundaries without
  refreshing the route and target list. Duplicate and move row actions now also
  tell operators to rebuild review context after staging. This is functional
  operator disclosure only; durable rule IDs, paginated/virtualized selection
  guarantees, server-side review custody, and audit binding remain hardening.
  Remote validation for this slice should be performed on
  `opc@139.87.66.128`; no local functional tests were run.

- Performance release-claim drill-through polish slice: `#/performance` now
  turns a loaded benchmark verdict into explicit operator decision points for
  scoped external publication, explicit no-performance-claims release handling,
  Readiness `release-benchmark` packet review, release-acceptance status, and
  support-bundle posture preview. The same decision model is included in the
  browser-local `performance-evidence` investigation packet so copied, pinned,
  and exported handoffs carry release/no-claims/support-bundle context without
  implying that the browser recorded durable release evidence or certified
  unsupported throughput. The UI still requires release tooling to record
  publishable benchmark evidence before any release-note or external claim, and
  it keeps warning-only evidence scoped to internal review unless the operator
  repairs or removes the claim. Remote validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-perf-release-claim-drill-r2`) passed
  `node --check internal/webui/static/js/views/performance.js`,
  `node --check internal/webui/static/js/performance.test.mjs`,
  `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/performance.test.mjs`, `make webui-check`, and
  targeted browser-required `WEBUI_SMOKE_REQUIRE_BROWSER=1
  WEBUI_SMOKE_PATHS=/performance make webui-visual-smoke` across desktop,
  tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-performance-release-claim-r1`.
  No local functional tests were run.
  Production hardening remains under Performance evidence verifier hardening,
  Release evidence provenance and skip-proofing, Release evidence status
  disclosure, and Support-bundle runtime-readiness disclosure.

- Routing/VPN field-proof checklist polish slice: selected tunnel drawers now
  include a browser-local field-proof checklist that ties candidate route
  posture, passive FRR/IPsec/WireGuard runtime visibility, route-backed
  Explain/Capture/Sessions handoffs, and placeholder-only secret custody into
  one operator review surface. Copied/exported VPN handoffs carry the same
  non-claiming checklist as an operator note, and enrollment/template copy and
  export wording now states that secret material remains placeholder-only or
  out of band. This improves collection guidance only; it does not claim actual
  protected-subnet reachability, committed FRR/kernel route proof, XFRM state
  proof, production WireGuard route proof, or durable field-evidence custody.
  Remote validation for this slice should be performed on
  `opc@139.87.66.128`; no local functional tests were run.

- Readiness evidence packet consistency polish slice: release packet drawers
  now carry the same current gate status, current-gap detail, operator route,
  and `#/readiness?packet=<gate>` route that the release evidence strip and
  acceptance-status drill-through expose. Copied, exported, and pinned
  `release-evidence` handoffs include the current packet route and operator
  route while still passing packet text, commands, current gap detail, URLs,
  query secrets, bearer material, and server-local paths through the Readiness
  disclosure redactor. This is browser-local drill-through consistency only;
  it does not record durable release evidence, assemble a manifest, make a
  gate pass, or widen direct API/CLI disclosure. Remote validation for this
  slice should be performed on `opc@139.87.66.128`; no local functional tests
  were run. Shared direct API/CLI disclosure contracts, RBAC-scoped detailed
  reports, signed packet custody, retention, and cross-surface parity remain
  hardening work.

- Settings/auth access lifecycle parity polish slice: the Settings Access
  lifecycle drawer now includes explicit operator handoff rows for returning to
  `#/settings?panel=access`, provider lifecycle, break-glass credential
  lifecycle, and browser SSO session lifecycle. The drawer can copy the
  sanitized Access route directly, and copied, exported, and pinned
  `phragma.access.lifecycle-review.v1` evidence now includes route and audit
  continuation context without serializing generated tokens, server-local
  secret paths, full browser-session IDs, SAML assertions, or certificate
  fingerprints. This remains browser-local functional handoff evidence over
  existing audited backend access APIs; step-up authentication, MFA,
  credential hardening, secret-manager custody proof, signed/server-side
  lifecycle custody, and production identity custody remain hardening work.
  Remote validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/run-20260621-settings-auth-lifecycle-parity-r1`)
  passed `node --check` for `views/settings.js`,
  `settings_access.test.mjs`, and `settings_route.test.mjs`; passed
  `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/settings_access.test.mjs`; passed
  `node internal/webui/static/js/settings_route.test.mjs`; passed
  `make webui-check`; and passed browser-required
  `WEBUI_SMOKE_PATHS=/settings` across desktop, tablet, and mobile. The smoke
  evidence manifest was written to
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-settings-auth-lifecycle-parity-r3/webui-smoke-evidence.json`.
  No local functional tests were run.

- Fleet/HA production-boundary workflow polish slice: `#/fleet` now opens with
  an explicit production-boundary band for connected-appliance authority,
  candidate/template import boundaries, HA traffic-control limits, and release
  gate drill-through. Browser-local template previews and copied handoffs now
  state that Fleet is not authoritative fleet inventory, does not store signed
  templates, does not fan out to peers, does not record distributed apply
  results, and does not claim VIP movement, fencing, connection-state transfer,
  election, or failover traffic control. Template context now carries direct HA
  cockpit, HA CLI status, release acceptance packet, and release CLI status
  handoffs where relevant while still routing mutation through Changes and
  Readiness. Remote validation for this slice should be performed on
  `opc@139.87.66.128`; no local functional tests were run. Durable multi-node
  fleet inventory/orchestration, signed template custody, distributed audit,
  and HA traffic controls remain hardening work.

- Changes runtime-ready strict UI evidence polish slice: Changes candidate
  review, commit review, and rollback review now surface a strict UI apply
  evidence panel that combines validation, runtime-readiness preflight, and
  release-acceptance summary posture. The panel exposes direct Readiness pivots
  for release acceptance and runtime field-evidence packets while explicitly
  stating that Changes does not claim ready-runtime field evidence or close
  durable release gates. Candidate preservation packets now include the same
  strict UI apply summary, release open-item counts, and a
  `not-claimed-by-changes` field-evidence marker for operator handoff. Remote
  validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/changes-strict-ui-evidence-r1`) passed
  `node --check internal/webui/static/js/views/changes.js`, `node --check
  internal/webui/static/js/changes_candidate_review.test.mjs`,
  `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/changes_candidate_review.test.mjs`, and
  `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp
  GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`. Targeted
  browser-required `/changes` smoke then passed across desktop, tablet, and
  mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-changes-strict-ui-evidence-r4`.
  The targeted smoke initially hit remote temp disk pressure and then a missing
  copied-worktree browser cache; generated temp artifacts under
  `/home/opc/oss-ngfw-smoke-tmp` were cleaned, `go-tmp` was recreated, and the
  existing `/home/opc/.cache/ms-playwright` browser cache was used for the
  passing run. No local functional tests were run. Production hardening remains
  under Changes lifecycle field hardening, release evidence status disclosure,
  and release evidence provenance/custody.

- Integrated parallel-round five validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-20260621-parallel-round3-r1`)
  covered the Support Bundle release/readiness redaction parity, Readiness
  release-packet drill-through/redaction, Traffic/App-ID capture and regression
  bridge, Threat exception regression bridge, Objects live-interface stale
  refresh guard, and System Logs to Troubleshoot capture-plan follow-through
  slices together. The combined pass ran JS syntax checks for all touched WebUI
  modules/tests, focused JS tests for zone interfaces, App-ID observations,
  Troubleshoot, Logs, Threat exceptions, IDS exceptions, support bundle,
  Readiness view/model, and Go tests for `./internal/supportbundle` plus
  focused support-bundle CLI redaction coverage; all passed. `make webui-check`
  on the same remote checkout passed after integration. Browser-required
  targeted smoke then passed
  `WEBUI_SMOKE_PATHS=/traffic,/threats,/inspection,/logs,/troubleshoot,/objects,/readiness`
  across desktop, tablet, and mobile with all 21 route checks passing via
  Playwright. No local functional tests were run. Artifacts were written under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-parallel-round5-bridges-r3`.
  This is targeted continuation evidence; a later broad sweep and durable
  release-evidence recording are still required after source-control acceptance.

- Support bundle release/readiness redaction parity slice: browser-local support
  bundle collection and preview now preserve runtime-readiness and
  release-acceptance summary counts while redacting secret-bearing command
  arguments, local evidence/artifact/output paths, recordability path lists,
  and path/secret text embedded in readiness items or release next actions. The
  shared Go support-bundle redactor now handles the same command-array shape so
  API/CLI/server bundles do not disclose more than WebUI fallback bundles for
  these fields. This is functional parity for support-bundle disclosure only;
  it does not complete the production release-disclosure contract, RBAC split,
  support-bundle retention policy, or signed custody requirements. Remote
  validation for this slice should be performed on `opc@139.87.66.128`; no
  local functional tests were run.

- Readiness release-packet drill-through/redaction slice: release acceptance
  check rows now expose direct route-backed pivots into the matching
  `#/readiness?packet=<gate>` release packet for known release gates. Release
  evidence summary copy, release-packet copy/export/pin handoffs, packet
  command copy, and support-bundle error details now run through the Readiness
  disclosure redactor so server-local paths, bearer tokens, credentialed URLs,
  and secret-like query or key/value material are replaced before clipboard or
  browser-local handoff surfaces. The detailed release tooling remains
  browser-local and does not record durable evidence, assemble a manifest, or
  make a release gate pass. Remote validation for this slice should be
  performed on `opc@139.87.66.128`; no local functional tests were run.
  Production disclosure parity across direct API/CLI output, RBAC-scoped
  detailed reports, signed custody, and support-bundle retention remains
  hardening work.

- Traffic/App-ID capture and regression bridge slice: selected flow and App-ID
  observation drawers now make the capture, regression-sample, and corpus-review
  next steps explicit. Flow drawers stay browser-local and route operators to
  bounded Troubleshoot packet-capture planning, matching App-ID queue review,
  corpus review, and pin/copy/export handoffs before any candidate workflow.
  App-ID observation drawers add the same bridge and expose draft regression
  sample staging only through the existing reviewed
  `:stage-regression-sample` endpoint, requiring a capture SHA-256 before the
  draft corpus artifact is updated. No direct policy mutation is introduced;
  App-ID promotion/drop remains in the existing candidate-safe workflows.
  Remote validation for this slice should be performed on `opc@139.87.66.128`;
  no local functional tests were run. Production hardening still needs durable
  capture/corpus custody, signed regression artifacts, retention/tamper
  controls, broader App-ID field evidence, and server-side audit policy.

- Threat exception regression bridge slice: Threat alert details and
  false-positive exception rows/details now surface read-only regression,
  PCAP, Threat-ID content quality, and canary false-positive telemetry context.
  Exception records keep PCAP SHA-256 and regression references through the
  IDS/Inspection editor model, and detail actions pivot to packet-capture audit,
  Intel content quality, Intel canary telemetry, and candidate review without
  mutating policy outside existing candidate exception workflows. Remote
  validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/threat-exception-regression-bridge-r1`)
  passed focused `node --check` for `views/threats.js`, `views/ids.js`,
  `threat_exceptions.test.mjs`, and `ids_exceptions.test.mjs`; passed
  `node internal/webui/static/js/threat_exceptions.test.mjs` and
  `node internal/webui/static/js/ids_exceptions.test.mjs`; and passed
  `make webui-check`. No local functional tests were run. Production custody for
  exception evidence, signed false-positive corpora, packet-capture retention,
  canary telemetry storage, and approval/commit gating remain hardening work.

- Objects live-interface stale refresh guard slice: the Objects zone inventory
  panel now treats live host interface refreshes as ordered requests. A newer
  refresh marks the panel as `refreshing`, disables duplicate refresh clicks,
  and discards older `/status` responses that arrive late instead of letting a
  stale host inventory overwrite the latest zone posture review. Operators see
  when stale responses were ignored, while candidate zone editing remains
  manual and candidate-safe if host status is unavailable. Remote validation
  for this slice should be performed on `opc@139.87.66.128`; no local
  functional tests were run. Durable interface identity, rename/hotplug
  handling, VRF/namespace awareness, and production authority for host
  inventory remain hardening work.

- System Logs to packet-capture plan handoff slice: parsed System Log tuples now
  surface a plan-only bounded packet-capture workflow directly in the log
  drawer. The handoff derives source/destination IPs, ports, protocol, App-ID,
  flow ID, and signature context from structured log fields or message text,
  shows the local bounded capture filter and limits, copies a Troubleshoot
  capture-plan handoff, and opens `#/troubleshoot` with `intent=capture`,
  `run=1`, `captureContext=log-plan`, runtime evidence, and bounded capture
  defaults. Troubleshoot preserves that context with a visible "From log plan"
  banner, clamps route-provided capture limits, refreshes only a plan/history,
  and never starts capture from route load; operators still explicitly press
  Start capture. Remote validation for this slice should be performed on
  `opc@139.87.66.128`; no local functional tests were run. Server-side custody,
  retention policy, signed export custody, and production packet-capture
  lifecycle enforcement remain hardening work.

- Guided Setup route-state restore slice: shared `#/setup?...` links now
  restore the Guided Setup scenario, profile, zones, interface assignments,
  inside CIDR, WebUI/API port, MTU, IDS fields, and boolean setup toggles into
  the browser-local setup view through the shared setup route parser. Opening a
  setup link does not stage policy or bypass the candidate workflow; policy
  mutation still occurs only through the normal `Stage setup` action and
  `session.apply` path. Remote validation for this slice should be performed on
  `opc@139.87.66.128`; no local functional tests were run. Supported-topology
  field proof for the default archetypes remains hardening work.

- Guided Setup topology proof handoff slice: the first-run checklist now adds a
  topology-specific proof row for cloud edge, east-west, VPN edge, IDS tap, lab,
  and custom baselines. The row derives its state from the preview policy and
  current setup fields, then routes operators to Changes, Routing & VPN, or
  Troubleshoot evidence workflows with copyable validation/diff commands. It
  does not stage policy, create tunnels, start captures, or bypass the existing
  `Stage setup` -> `session.apply` candidate path. Remote validation for this
  slice should be performed on `opc@139.87.66.128`; no local functional tests
  were run. Supported-topology field proof, mirror/SPAN visibility, protected
  subnet reachability, real return-route behavior, and documentation-CIDR
  replacement evidence remain hardening work.

- Investigation multi-flow grouped remediation synthesis slice: pinned
  Investigation cases now synthesize tuple-grouped remediation handoffs across
  flow, threat, capture, NAT/route, App-ID, and candidate-delta evidence. The
  case model exports per-group owner workspaces with missing-evidence reasons,
  read-only handoff text, and tuple-specific links into Troubleshoot, Threats,
  Traffic/App-ID, NAT, and Rules Flow check; the Investigation cockpit renders
  those grouped plans without mutating policy directly or bypassing candidate
  review. Remote validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/investigation-grouped-remediation-r1`)
  passed `node --check` for `investigation_case.js`,
  `views/investigation.js`, `investigation_case.test.mjs`, and
  `investigation_view.test.mjs`; passed
  `node internal/webui/static/js/investigation_case.test.mjs` and
  `node internal/webui/static/js/investigation_view.test.mjs`; and passed the
  equivalent of `make webui-check` by running all WebUI JS syntax checks and
  every `*.test.mjs` with `node_test_polyfills.cjs`. No local functional tests
  were run. A later server-custody pass added `/v1/investigation/cases`
  create/list/get/add-evidence records with audit hooks and WebUI save/link/
  append controls. Production-grade custody still needs durable evidence
  identity, immutable references, workflow-ticket integration, approvals,
  production retention, and signed handoff custody.

- Intel content promotion workflow/quality gate follow-through slice: `#/intel`
  now links package quality gates, regression state, canary/false-positive
  telemetry, rollback availability, and install-preview comparisons into one
  non-authoritative promotion/rollback decision handoff. The main content rows,
  review, quality, canary, install preview, and rollback drawers now show when
  to hold promotion, continue review, use the existing install lifecycle, or
  review rollback. Handoffs include copyable API/CLI context and investigation
  packet actions but do not mutate policy, approve content, sign custody, or
  bypass the audited content package APIs. Remote validation on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/intel-promotion-gate-r2`) passed
  `node --check internal/webui/static/js/content_posture.js`,
  `node --check internal/webui/static/js/views/intel.js`,
  `node --check internal/webui/static/js/intel_content.test.mjs`,
  `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/intel_content.test.mjs`,
  `make webui-check`, and browser-required targeted
  `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/intel make webui-visual-smoke`
  across desktop, tablet, and mobile. No local functional tests were run.
  Signed custody, durable canary telemetry storage, server-side promotion
  enforcement, approval controls, artifact signing/retention, and production
  evidence certification remain hardening work.

- Intel/content canary telemetry workbench slice: `#/intel` now has a
  route-backed `drawer=canary` workbench for App-ID, Threat-ID, and intel-feed
  packages. The workbench derives bounded rollout scope, false-positive
  telemetry, rollback posture, package gates, and handoff context from existing
  content package/readiness fields, with conservative browser-local fallbacks
  when the API does not report canary scope or false-positive telemetry. It
  does not create signed custody, approval authority, package promotion, or
  false-positive exception mutation; those remain on existing install,
  rollback, and candidate workflows. Production canary telemetry storage,
  server-side approval/custody, signed false-positive corpus retention,
  promotion gates, and broader field evidence remain hardening work. Remote
  validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/intel-content-canary-r1`) passed
  `node --check internal/webui/static/js/content_posture.js`,
  `node --check internal/webui/static/js/views/intel.js`,
  `node --check internal/webui/static/js/intel_content.test.mjs`,
  `node internal/webui/static/js/intel_content.test.mjs`,
  `make webui-check`, and browser-required targeted
  `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/intel make webui-visual-smoke`
  across desktop, tablet, and mobile. No local functional tests were run.

- Rules server-overlap uncertainty slice: the route-backed server-overlap review
  now discloses the backend `maxOverlapFindings` cap and flags cap-sized
  validation results as possibly truncated instead of implying complete overlap
  coverage. Overlap peer reconstruction now labels candidate-derived versus
  detail-text-derived confidence, carries that confidence onto peer and
  dimension rows, and includes the same uncertainty notes in copied review
  context. No backend API contract changes were made; durable rule IDs,
  pagination/virtualization, first-class server overlap peer/dimension metadata,
  server-side review custody, and deeper remediation guidance remain hardening
  work.

- Performance evidence handoff slice: `#/performance` now exposes a page-level
  API/CLI context action and a browser-local `performance-evidence`
  investigation handoff for verified benchmark summaries. The handoff captures
  the visible verdict, raw iperf/status/nft posture, release-benchmark parity,
  claim-use gate, strict-mode state, and findings, then supports Pin to case,
  Copy handoff, and Export JSON without uploading benchmark artifacts or
  recording release evidence. The runbook workflow header now uses a shared CSS
  class instead of inline spacing, and the focused Performance JS test pins the
  handoff schema, route, raw-artifact summary, and action controls. Signed or
  server-retained benchmark evidence custody, retention, replay validation, and
  broader export/redaction policy remain hardening work.

- Dashboard engine owner-pivot slice: the Dashboard engine coverage table now
  exposes stable row-level owner actions for each reported runtime engine.
  Suricata/IDS/IPS engines pivot to Inspection, routing/VPN engines pivot to
  Routing & VPN runtime review, unknown engine failures pivot to Troubleshoot,
  and every row includes Readiness plus filtered System Logs handoffs. The
  route model is exported and covered by the Dashboard management test so
  degraded engine rows are no longer informational dead ends. Production field
  evidence for engine readiness, least-privilege runtime collection, and
  supported-host variance remains hardening work.

- Net/VPN route-backed review and expected-vs-observed slice: Routing & VPN now
  supports URL-backed static-route review/edit plus BGP and OSPF review/edit
  drawers while preserving existing tunnel hash compatibility. The workspace
  also surfaces passive VPN expected-vs-observed rows for configured IPsec or
  WireGuard tunnels with missing runtime observation, stale WireGuard handshake,
  or missing candidate static-route posture for remote prefixes, with pivots to
  Inspect, Explain, and Sessions workflows. The `/netvpn` API/CLI context now
  describes the route-backed static/BGP/OSPF review drawers. Remote validation
  on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/netvpn-route-review-r1`) passed
  `node --check internal/webui/static/js/views/netvpn.js`,
  `node --check internal/webui/static/js/automation_context.js`,
  `node --check internal/webui/static/js/netvpn.test.mjs`,
  `node internal/webui/static/js/netvpn.test.mjs`, and `make webui-check`.
  No local functional tests were run. Real FRR field evidence, secret
  lifecycle/import parsing, key validation/rotation, protected-subnet reachability,
  XFRM/route proof, step-up auth, and deeper duplicate tunnel route-state
  disambiguation remain hardening work.

- Integrated parallel-round follow-up validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-20260621-parallel-round3-r1`)
  covered the Browser SSO API contract parity, Settings access redaction,
  Readiness release-evidence packet actions, Intel refresh-interval layout,
  Rules large-rulebase review, Fleet local template preview, SNAT delete impact
  review, and Net/VPN route-backed review slices together. The combined pass
  ran `go test -count=1 ./cmd/ngfwopenapi ./internal/apiserver`, JS syntax
  checks for every changed WebUI module and the visual smoke runner, focused
  JS tests for Settings access, Readiness model/view, responsive tables, Rules
  bulk/density, Fleet, NAT path preview, and Net/VPN, then `make webui-check`;
  all passed. A browser-required targeted smoke on the same checkout also
  passed `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/rules,/fleet,/nat`
  across desktop, tablet, and mobile with all 9 route checks passing via
  Playwright. No local functional tests were run.

- Source NAT delete impact review slice: deleting a source NAT rule now opens a
  candidate-only impact review drawer before staging removal. The drawer shows
  affected source zones/address scope, egress translation, representative tuple,
  fallback candidate behavior, API/CLI copy handoffs, Troubleshoot pivot,
  preview link, and explicit delete confirmation. Remote validation on
  `opc@139.87.66.128` passed `node --check` for NAT view/preview modules,
  `node internal/webui/static/js/nat_path_preview.test.mjs`,
  `make webui-check`, and browser-required `/nat` smoke across desktop,
  tablet, and mobile. No local functional tests were run. At this earlier
  slice, dependency-scale NAT lookup, durable object/interface/rule identity,
  granular NAT API/CLI operations, server-side review custody, and
  FRR/kernel/VRF-backed dataplane proof were still open; later slices in this
  handoff close the bounded durable-identity, granular NAT, passive proof, and
  large-rulebase posture workflows while retaining production custody,
  dynamic sampling, active proof, and release-evidence hardening.

- Rules large-rulebase scale-review slice: the Rules workspace now surfaces a
  large-rulebase review banner when total, visible, or selected rule counts hit
  enterprise-scale thresholds. The banner exposes visible/total/selected counts,
  warns that bulk selection is still bound to rule position and name until
  durable rule IDs exist, and directs operators to narrow with filters/grouping
  or copy API/CLI context before large bulk edits. It does not hide rows,
  paginate, or claim cross-page selection authority; it makes the current
  functional boundary visible before candidate mutation. Remote validation on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-20260621-parallel-round3-r1`)
  passed `node --check internal/webui/static/js/views/rules.js`,
  `node internal/webui/static/js/rules_bulk_density.test.mjs`, and
  `make webui-check`. No local functional tests were run. Later slices add
  durable-ID posture and structured large-rulebase review; backend
  pagination/virtualization, cross-page selection authority, signed custody,
  and release evidence remain hardening work.

- Fleet local template preview slice: `#/fleet` now has a browser-local
  template preview drawer for each example template row. The drawer compares
  selected template intent against the currently loaded local running posture,
  candidate dirty-state, content readiness, release gates, and HA visibility,
  exposes exact REST and `ngfwctl` context, and copies a Changes handoff that
  directs operators to the existing candidate import/edit, validate, diff,
  commit, audit, and rollback workflow. It does not store templates server-side,
  fan out to peers, approve template apply, or bypass Changes. Remote
  validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/fleet-local-template-preview-r1`) passed
  `node --check internal/webui/static/js/views/fleet.js`,
  `node --check internal/webui/static/js/automation_context.js`,
  `node --check internal/webui/static/js/fleet.test.mjs`,
  `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/fleet.test.mjs`,
  `make webui-check`, and browser-required `/fleet` visual smoke across
  desktop, tablet, and mobile. No local functional tests were run. Durable
  multi-node inventory, node trust, signed template custody, approval policy,
  distributed apply results, and HA traffic controls remain hardening work.

- Readiness release-evidence packet action parity slice: release evidence
  packet drawers now expose explicit `Pin to case`, `Export JSON`, `Copy
  commands`, and `Copy packet` actions with stable selectors. Packet copy,
  export, and pin handoffs now state the browser-local boundary clearly: they
  do not record durable release evidence, assemble a manifest, or make a
  release gate pass. `review_needed` and non-benchmark `not_applicable` release
  checks render consistently as `review needed`, and deploy-hardening remains
  scoped to static packaged deployment evidence for `deploy/systemd/controld.service`
  and `deploy/install.sh`. Remote validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-20260621-parallel-round3-r1`)
  passed `node --check` for Readiness view/model files and tests,
  `node internal/webui/static/js/readiness_model.test.mjs`,
  `node internal/webui/static/js/readiness_view.test.mjs`, and
  `make webui-check`. No local functional tests were run. Server-side approval
  custody, commit gating, signed preservation, stale-evidence quarantine,
  artifact signing, supply-chain provenance, and runtime deploy hardening remain
  hardening work.

- Browser SSO API contract parity slice: the OpenAPI overlay now gives SAML
  browser login and ACS routes SAML-specific `401` descriptions instead of
  reusing OIDC failure copy. The generated OpenAPI output, published docs spec,
  and bundled WebUI spec were regenerated and synced so SAML browser SSO
  redirects no longer publish misleading OIDC error language. Remote validation
  on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-20260621-parallel-round3-r1`)
  passed `go test -count=1 ./cmd/ngfwopenapi`, `make proto`, and
  `go test -count=1 ./internal/apiserver`. No local functional tests were run.

- Settings access evidence redaction and revoke-refresh slice: browser SSO
  session revoke now refreshes access administration without losing the current
  Settings route or stale OIDC/SAML provider state, access evidence packets run
  through defensive JSON redaction before copy/export/pin, and the SAML drawer
  has clearer disabled-runtime rendering for narrow/mobile layouts. Redaction
  now covers JWT-shaped values, raw and URL-encoded token/session keys, session
  fingerprints, and server-local paths in access evidence. Remote validation on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1`)
  passed `node --check internal/webui/static/js/access_governance.js`,
  `node --check internal/webui/static/js/views/settings.js`,
  `node --check internal/webui/static/js/settings_access.test.mjs`,
  `node internal/webui/static/js/settings_access.test.mjs`, and
  `make webui-check`. No local functional tests were run. Real-provider SSO,
  trusted-proxy/browser-CSRF assumptions, MFA/step-up, and signed lifecycle
  custody remain hardening work.

- Intel design-system refresh interval slice: the threat-intelligence refresh
  interval control now uses named `intel-refresh-interval-*` layout classes
  instead of inline max-width/margin styling, and the responsive-table source
  contract pins those classes while rejecting the old inline sizing. Remote
  validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-20260621-parallel-round3-r1`)
  passed `node --check internal/webui/static/js/views/intel.js`,
  `node internal/webui/static/js/responsive_tables.test.mjs`, and
  `make webui-check`. No local functional tests were run.

- WebUI enterprise smoke evidence-policy slice: the broad visual smoke runner
  now prints explicit evidence mode and route coverage for every browser run.
  A default or full-route `WEBUI_SMOKE_PATHS` run is labeled as broad evidence;
  a reduced route plan is labeled targeted and says it must be paired with a
  successful broad sweep for the same source snapshot before the result is
  treated as broad-plus-targeted evidence. Timeout diagnostics now include the
  planned route checks and remaining route labels so a total-timeout sweep is
  not confused with completed broad route evidence. Remote validation for this
  slice should be performed on `opc@139.87.66.128`; no local functional tests
  were run. CI budget SLA, duration trend retention, and release-evidence
  custody policy remain tracked in `docs/HARDENING_BACKLOG.md`.

- Settings OIDC lifecycle stability slice: Settings now fetches the canonical
  OIDC provider config alongside access administration and merges that state
  into the rollout drawer and administration posture. Save/disable refreshes
  pull fresh OIDC/SAML state before repainting, rollout initial values normalize
  redirect URL, trusted proxies, and `clientSecretFileConfigured`, and the
  browser smoke now proves each viewport starts from disabled OIDC state, waits
  for stable disabled samples after disable, and rejects stale prefill from a
  previous viewport. Remote validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-20260621-parallel-round3-r1`)
  passed `node --check internal/webui/static/js/access_governance.js`,
  `node --check internal/webui/static/js/views/settings.js`,
  `node --check e2e/webui-visual-smoke.mjs`,
  `node internal/webui/static/js/settings_access.test.mjs`, `make webui-check`,
  and the exact browser-required route-order proof that previously failed:
  `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/settings,/performance`
  across desktop, tablet, and mobile. All 6 route checks passed via Playwright
  with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-parallel-round3-settings-performance-r1`.
  No local functional tests were run. Real-provider OIDC/SAML field evidence,
  trusted-proxy assumptions, browser-CSRF posture, MFA/step-up, and signed
  lifecycle custody remain hardening work.

- Object/NAT invalid editor candidate-safety slice: Objects service and
  application port editors now reject malformed, out-of-range, and inverted
  ranges before `session.apply` can stage a candidate. The generic Objects save
  path normalizes preview save results and throws a validation abort inside the
  apply callback if a late invalid state is detected, preventing a no-op
  candidate write. NAT inline service creation now validates queued TCP/UDP
  ports, NAT saves preflight queued host/service objects before candidate
  mutation, invalid queued services are not materialized, and unchanged source
  NAT edits return clear operator feedback instead of restaging an identical
  candidate. Focused JS tests pin the object editor pre-apply guard, port
  validation, pending NAT service filtering, and source-NAT no-change feedback
  source contract. Remote validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-20260621-parallel-round3-r1`)
  passed the focused Object reference and NAT path preview JS tests as part of
  the integrated pass for this round. No local functional tests were run.

- Changes candidate preservation packet slice: Changes lifecycle guidance now
  renders one-click browser-local Pin, Copy, and Export JSON actions for a
  `candidate-preservation` investigation packet at candidate review, commit
  review, rollback review, discard-adjacent cleanup guidance, and strict apply
  blocked decision points. The packet captures candidate dirty/status summary,
  pending change summary, validation posture, runtime readiness/ack posture,
  impact, diff source/preview, and the cleanup/preserve runbook context without
  mutating candidate or running policy and without adding a server API. Focused
  Changes JS coverage pins the stable selectors and packet schema. Signed or
  server-retained preservation custody, retention enforcement, commit gating,
  and authoritative cleanup/preserve decisions remain hardening work.

- Deploy-hardening evidence visibility slice: the Readiness release packet now
  labels `deploy-hardening` as packaged deployment evidence instead of implying
  full runtime hardening. The packet exposes the static validator command
  `bash release/deploy-hardening-check.sh --check` and the durable recorder
  command `COMMIT="$(git rev-parse HEAD)" make
  release-evidence-deploy-hardening`, with explicit scope that the gate inspects
  `deploy/systemd/controld.service` and `deploy/install.sh` only. Release docs
  now say the gate does not start `controld`, install packages, rotate secrets,
  prove runtime RBAC, or close privileged integration, install smoke, field
  evidence, or later hardening work. No local functional tests were run for
  this slice; validate from the remote Oracle Linux host with the focused
  Readiness JS model test and `make webui-check`.

- Release status review-needed CLI guidance slice: human-readable
  `ngfwrelease status` output now includes a `review_needed_checks` queue and a
  single `review_needed_next` operator action when stale, mismatched, reused, or
  skipped-test evidence needs review. This keeps the JSON schema stable while
  making text output actionable: regenerate listed evidence with
  `ngfwrelease record` after source-control acceptance, and do not certify
  copied remote continuation evidence as durable release evidence. Remote
  validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-20260621-parallel-round3-r1`)
  passed `go test -count=1 ./internal/releaseacceptance ./cmd/ngfwrelease
  ./internal/cli` as part of the integrated pass for this round. No local
  functional tests were run.

- Changes lifecycle cleanup/preserve guidance slice: Changes candidate review
  and rollback review now expose browser-local lifecycle guidance that explains
  what commit, discard, rollback, and strict UI apply blocking do to the running
  firewall and candidate workspace. Commit and rollback are described as audited
  live apply actions that create a new running version and clear the candidate
  after success; discard is candidate-only cleanup that leaves running policy
  and version history unchanged; strict UI apply blocking preserves the staged
  candidate while readiness blockers are fixed. The guidance includes copyable
  cleanup/preserve runbook steps and exact operator verification commands such
  as `ngfwctl policy status`, `ngfwctl policy validate`, `ngfwctl policy diff`,
  `ngfwctl rollback <version> --message "<reason>"`, and
  `WEBUI_SMOKE_REQUIRE_CHANGES_UI_APPLY=1 make webui-enterprise-smoke`. This is
  not production approval custody: server-side approval records, signed
  candidate preservation artifacts, retention enforcement, and commit gating
  remain tracked in `docs/HARDENING_BACKLOG.md`. Remote validation for this
  slice should cover focused Changes/candidate review JS tests and
  `make webui-check`; no local functional tests were run.

- Logs/Dashboard/Diagnostic design-system hardening slice: Dashboard section
  spacing now uses the shared grid stack instead of inline margins, release
  action rows use the shared `flex wrap` primitive, and Dashboard engine,
  threat, and version tables declare stable responsive column metadata plus
  shared `data-clip`/`data-wrap` cell contracts for dense evidence. System Logs
  rows now use shared mono/muted/truncation cell classes for timestamp, source,
  and engine cells while preserving row activation and drawer routing.
  Diagnostic Console footer navigation now exposes explicit titles,
  `aria-label` text, and stable shared-control hooks for Readiness and Sessions
  links. Source-contract tests pin the Dashboard no-inline-style contract,
  responsive table column metadata, dense cell truncation classes, and
  Diagnostic footer action semantics. Remote validation on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/design-system-hardening-logs-dashboard-diag-r1`)
  passed `node --check internal/webui/static/js/views/dashboard.js`,
  `node --check internal/webui/static/js/views/logs.js`,
  `node --check internal/webui/static/js/diagnostic_console.js`,
  `node internal/webui/static/js/design_system.test.mjs`,
  `node internal/webui/static/js/responsive_tables.test.mjs`, and
  `make webui-check`. No local functional tests were run. The broader
  keyboard/focus audit, route-level interaction regression review, and fresh
  desktop/tablet/mobile browser smoke artifacts remain tracked as hardening
  work rather than claimed complete.

- Release evidence provenance/status disclosure slice: release acceptance
  status now carries explicit provenance disclosures that remote continuation
  notes and copied smoke paths are not durable release evidence until rerun
  through repo-local `ngfwrelease` tooling. Stale artifacts, digest problems,
  manifest/evidence commit mismatches, path-boundary problems, artifact reuse,
  and skipped-test evidence are classified as review-needed invalid evidence
  with regeneration guidance. Privileged integration evidence validation now
  rejects Go test `SKIP` records even when other stdout sentinels are present,
  keeping skip-proof gates from being satisfied by skipped tests. Readiness API
  and CLI automation-context copy now describe release acceptance as summary,
  provenance, and gate-count posture and continue to avoid sensitive local path
  detail in summary copy. Hardening remains tracked for stale-evidence
  quarantine policy, artifact signing, custody/retention controls, and broader
  supply-chain provenance.

- Packet-capture artifact integrity posture slice: packet-capture references
  now derive an operator-visible integrity state from existing capture metadata:
  completed artifacts with a safe artifact ID or filename, nonzero byte count,
  SHA-256 digest, and tcpdump PCAP media type are labeled `verifiable`; completed
  artifacts with partial proof are labeled `review`; incomplete or running jobs
  remain `pending`/`incomplete`. Troubleshoot recent-capture rows, Traffic
  capture-evidence panels, and capture investigation handoff packets now surface
  the same integrity label/detail alongside retention state, hash, size, audit
  route, and download actions without claiming tamper-proof custody or pruning
  enforcement. Remote validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/main-capture-integrity-r1`) passed JS
  syntax checks for packet capture, capture evidence, investigation packets, and
  Troubleshoot; passed `node internal/webui/static/js/packet_capture.test.mjs`,
  `node internal/webui/static/js/capture_evidence.test.mjs`,
  `node internal/webui/static/js/investigation_packet.test.mjs`,
  `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/troubleshoot_view.test.mjs`, and `make webui-check`.
  No local functional tests were run. Production retention enforcement,
  permissions, tamper detection, signing/custody, redaction policy, and pruning
  remain hardening work.

- Explain consumer parity and SAML operator-command parity slice: NAT path
  deltas, NAT investigation handoff packets, and Rules flow simulation now
  prefer `decisionSummary`/`decisionTerms` over raw `EXPLAIN_VERDICT_*` labels
  while retaining legacy verdict fallback. NAT path review language now says
  `Decision` and `Candidate decision`, Investigation explain summaries carry
  both `decision`/`decisionTerms` and the legacy `verdict`, and Rules flow-check
  handoff metadata records the stable decision vocabulary. The SAML field
  evidence Readiness packet now exposes a three-step operator flow to prepare
  the redacted bundle directory, validate it, and record evidence, with explicit
  copy that the preparation command does not run a browser or contact the IdP.
  Remote validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-20260621-consumer-saml-troubleshoot-r1`)
  passed JS syntax checks for NAT path preview, investigation packets, Rules,
  Troubleshoot, readiness model, and Readiness view; passed
  `node internal/webui/static/js/nat_path_preview.test.mjs`,
  `node internal/webui/static/js/investigation_packet.test.mjs`,
  `node internal/webui/static/js/rules_action_controls.test.mjs`,
  `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/troubleshoot_view.test.mjs`,
  `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/readiness_model.test.mjs`,
  `bash -n release/saml-field-evidence.sh`, and
  `go test -count=1 ./internal/releaseacceptance ./cmd/ngfwrelease`. No local
  functional tests were run. A final integrated remote pass on
  `/home/opc/oss-ngfw-v2-mixed-work/integration-20260621-full-parallel-r1`
  additionally covered HA fencing status proto/OpenAPI generation, content
  readiness action plans, Traffic/Threat package-provenance visibility, and
  `make webui-check`: `make proto`,
  `go test -count=1 ./internal/apiserver ./internal/cli ./internal/releaseacceptance ./cmd/ngfwrelease`,
  JS syntax checks for NAT path preview, investigation packets, Rules,
  Troubleshoot, readiness, Intel, Traffic, and Threats, focused JS tests for
  NAT, Investigation, Rules action controls, Troubleshoot, Readiness,
  Intel content, App-ID observations, and Threat exceptions, `bash -n
  release/saml-field-evidence.sh`, and `make webui-check` all passed. Generated
  system proto/OpenAPI artifacts from that final remote `make proto` run were
  synced back into the local tree.

- Troubleshoot route-state cleanup slice: Troubleshoot now carries bounded
  browser-local `caseKey/caseAction/caseKind` metadata through route sync while
  keeping those fields out of Explain API and running-vs-candidate compare
  payloads. Explain and compare requests now use an explicit active-request
  token, so a late compare response cannot repaint the route after a newer
  explain, compare, edit, or clear action supersedes it. Remote validation on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/troubleshoot-route-state-r1`) passed
  `node --check internal/webui/static/js/views/troubleshoot.js` and
  `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/troubleshoot_view.test.mjs`.

- Explain, content-package classification, HA fencing evidence, and SAML
  field-evidence scaffold slice: ExplainFlow now exposes a first-class
  `ExplainDecisionTerm` API vocabulary for the hard-requirement decision terms
  `allowed`, `blocked`, `bypassed`, `partially inspected`, `fully inspected`,
  `decrypted`, `failed`, `fail-open`, and `fail-closed` while preserving the
  existing detailed verdict and inspection enums. The pure policy model
  annotates decision terms for allow/block/inspection/bypass/failure behavior,
  runtime-unavailable evidence adds `failed`, CLI output prints the derived
  decision summary, and Troubleshoot comparison summaries use the stable
  vocabulary with legacy verdict fallback. App-ID flow classification and
  observation workflows now merge verified signed package `app-taxonomy`
  definitions with running-policy definitions, and Threat-ID alert
  normalization can enrich built-in Suricata metadata from verified signed
  package `threat-taxonomy` evidence without changing enforcement. HA manual
  activation gained a read-only fencing-evidence provider contract that rejects
  unproven configured fencing evidence before VIP promotion and persists
  accepted evidence into HA state. HA status, `ngfwctl system ha status`, and
  the Readiness HA card/evidence packet now surface that persisted fencing
  evidence as `not_recorded`, `acknowledged_external`, `recorded`, or
  `unavailable` with provider, claim, evidence ID, observed time, and detail
  while explicitly stating that OpenNGFW records evidence and does not fence
  the peer. Release acceptance now includes a rootless
  `m5-saml-field-evidence` scaffold, Makefile targets, Readiness packet
  wiring, CLI command hints, and a captured-bundle validator for redacted real
  SAML provider browser SSO evidence without claiming a real IdP run. Remote
  validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-20260621-explain-content-ha-r1`)
  passed `make proto`, regenerated and synced
  `api/gen/openngfw/v1/explain_service*.go`,
  `api/gen/openapi/api-spec.swagger.yaml`, `docs/api-spec.yaml`,
  `api/openapi.yaml`, and `internal/webui/static/api-spec.yaml`, then passed
  `go test -count=1 ./internal/explain ./internal/cli ./internal/apiserver ./internal/appid ./internal/contentpkg ./internal/telemetry ./internal/threatid ./cmd/controld ./internal/releaseacceptance ./cmd/ngfwrelease`,
  `go test -tags=integration -count=1 ./test/integration -run "TestReleaseSAMLFieldEvidenceCheck|TestReleaseOIDCFieldEvidenceCheck"`,
  `node --check internal/webui/static/js/views/troubleshoot.js`,
  `node internal/webui/static/js/troubleshoot_view.test.mjs`,
  `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/readiness_model.test.mjs`,
  and `bash -n release/saml-field-evidence.sh`. No local functional tests were
  run. The remote host root filesystem hit 99% usage during proto tool builds;
  disposable Go temp/cache directories and older copied validation worktrees
  were removed, leaving the current integration directory and prior
  `run-20260620-saml-provider-lifecycle-r1` continuation checkout.
- Enterprise WebUI route smoke now has a first-class Makefile target and
  completed full-route validation in one command. `webui-enterprise-smoke`
  preserves caller browser strictness, uses the complete operator route list,
  and raises the total smoke budget to 30 minutes so full desktop/tablet/mobile
  coverage can complete without weakening route assertions. Release-readiness
  pending-manifest states now render as review/warning posture instead of a
  false functional blocker, Dashboard first-gate drill-through points to the
  concrete `proto-verify` packet, and diagnostic copied snapshots disclose
  manifest-pending state explicitly. Dashboard, Changes, and Logs utility
  actions also now carry explicit titles, ARIA labels, button types where
  applicable, and stable action hooks. Remote validation on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1`)
  passed `make webui-enterprise-smoke` with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-enterprise-target-r1`,
  focused Readiness/Dashboard/Diagnostic JS tests, `make webui-check`,
  `go test ./internal/releaseacceptance ./internal/apiserver ./internal/cli ./cmd/ngfwrelease`,
  and browser-required targeted `/`, `/logs`, `/readiness`, and `/changes`
  visual smoke across desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-release-disclosure-route-actions-r1`.
  No local functional tests were run.
- Access, content-readiness, disclosure, and keyboard-focus follow-up slice:
  Settings access browser smoke now exercises the browser SSO session
  revocation workflow, including the confirmation drawer, the
  `/v1/system/access-administration/sessions/{sessionId}:revoke` request,
  refreshed empty-session inventory, and raw-session-data leak checks. The
  release acceptance drawer's generated/copyable report is now summary-only and
  intentionally omits manifest paths, evidence paths, dirty source paths,
  detailed problem text, and commands while preserving the detailed authorized
  operator view in the drawer. Support bundle redaction now masks release
  recordability `allowedDirtyPaths` and `dirtySourcePaths` list values while
  preserving counts. Content package readiness now carries explicit API/CLI/UI
  labels and details that distinguish `production-ready`, `demo-only`,
  `missing-readiness`, and `production-blocked`. Shared drawer/modal focus
  trapping now returns escaped forward Tab focus to the first focusable control
  and escaped Shift+Tab focus to the last control. Remote validation on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1`)
  passed focused JS syntax/source tests, `make webui-check`,
  `go test -count=1 ./internal/contentpkg ./internal/apiserver ./internal/cli ./internal/supportbundle`,
  `go test -tags=integration -count=1 ./test/integration -run TestReleaseContentProductionReadiness`,
  and browser-required `/settings` visual smoke across desktop, tablet, and
  mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-settings-session-revoke-r1`.
  The remote validation checkout is not a Git worktree, so `git diff --check`
  was not available there. No local functional tests were run.
- IDS/Inspection, Intel, Net/VPN, shared diagnostic/saved-filter/capture, and
  Settings network/telemetry/host-input controls now expose explicit operator
  semantics. The pass adds contextual `title` and `aria-label` text, explicit
  button types, and stable selectors for IDS/IPS profile staging, inspection
  profile actions, Intel package/feed/evidence/corpus lifecycle actions,
  Net/VPN dynamic-routing, tunnel path-check, IPsec, WireGuard, enrollment, and
  handoff/template actions, shared diagnostic refresh/copy controls, saved
  filter save/apply/delete controls, capture evidence download/audit controls,
  Settings telemetry evidence and receiver-proof controls, Settings network
  profile/stage controls, and Settings host-input default/rule lifecycle
  controls. Focused JS tests now pin the source contracts, and browser smoke
  verifies the rendered controls across the affected operator workflows.
  Remote validation on `opc@139.87.66.128` passed targeted `node --check`
  commands, the focused JS tests, `make webui-check`, browser-required
  `/threats,/inspection,/intel,/netvpn,/` visual smoke across desktop, tablet,
  and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-action-controls-r1`, and
  browser-required `/settings` visual smoke across desktop, tablet, and mobile
  with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-settings-action-controls-r2`.
- Threats alert and exception lifecycle controls now expose explicit operator
  semantics. Threat detail Explain, Capture, Stage FP, Drop, related-flow,
  capture-audit, and handoff Pin/Copy/Export controls now render explicit
  button/link semantics with contextual `title` and `aria-label` text plus
  stable alert and handoff selectors. Threat exception row, detail, edit,
  disable, enable, remove, and false-positive stage controls carry the same
  semantics while preserving candidate-only lifecycle behavior, required audit
  reasons, and running-policy isolation. The focused Threat exception JS test
  pins the source contract, and `/threats` smoke verifies rendered alert,
  false-positive, exception workbench, and lifecycle drawer controls before
  exercising stage, edit, disable, enable, remove, automation context, and
  redaction workflows. Remote validation on `opc@139.87.66.128` passed
  `node --check` for the changed JS files, the focused Threat exception JS
  test, `make webui-check`, and browser-required `/threats` visual smoke across
  desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-threats-actions-r1`.
- Settings SAML/OIDC rollout controls now expose explicit operator semantics.
  SAML and OIDC rollout drawer close, validate, save, disable, copy, export,
  pin, test-login, runtime-inactive, and OIDC preflight evidence controls now
  render explicit button semantics with contextual `title` and `aria-label`
  text plus stable access selectors where smoke needs to target them. The
  focused Settings access JS test pins the source contract, and `/settings`
  smoke verifies rendered rollout controls in the OIDC and SAML workflows
  before exercising copy, export, pin, save, disable, redaction, and provider
  persistence. Remote validation on `opc@139.87.66.128` passed `node --check`
  for the changed JS files, the focused Settings access JS test,
  `make webui-check`, and browser-required `/settings` visual smoke across
  desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-settings-sso-rollout-actions-r1`.
- Changes candidate and version-history controls now expose explicit operator
  semantics. Refresh review, Commit candidate, Prepare approval, Readiness,
  Open diff, Discard candidate, version Diff, version Export, and version Roll
  back controls now render contextual `title` and `aria-label` text, explicit
  `type="button"` where applicable, and stable Changes selectors. The focused
  Changes candidate-review JS test pins the source contract, and `/changes`
  smoke verifies the rendered candidate and version-history controls during the
  commit/rollback lifecycle. Remote validation on `opc@139.87.66.128` passed
  `node --check` for the changed JS files, the focused Changes candidate-review
  JS test, `make webui-check`, and browser-required `/changes` visual smoke
  across desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-changes-actions-r1`.
- Performance benchmark verifier controls now expose explicit operator
  semantics. Verify, Use live status, Clear, runbook command copy, release
  command copy, full runbook copy, and repair command copy controls now render
  explicit `type="button"` attributes with contextual `title` and `aria-label`
  text while preserving stable `data-perf-action` selectors. The focused
  Performance JS test pins the source contract, and `/performance` smoke
  verifies the rendered route/runbook controls plus dynamically rendered repair
  command controls before exercising directory rejection, strict-gate behavior,
  live-status loading, publishable evidence, mismatch findings, and copy
  workflows. Remote validation on `opc@139.87.66.128` passed `node --check` for
  the changed JS files, the focused Performance JS test, `make webui-check`,
  and browser-required `/performance` visual smoke across desktop, tablet, and
  mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-performance-actions-r1`.
- Guided Setup action controls now expose explicit operator semantics. Stage,
  profile/scenario preset, host tuning, interface assignment, IPS failure
  behavior, API/CLI checklist, and checklist proof controls now render explicit
  button/link semantics with contextual `title` and `aria-label` text plus
  stable setup selectors. The focused Setup JS test pins the source contract,
  and `/setup` smoke verifies the rendered controls before exercising scenario
  presets, API/CLI context, baseline staging, candidate isolation, and review
  routing. Remote validation on `opc@139.87.66.128` passed `node --check` for
  the changed JS files, the focused Setup JS test, `make webui-check`, and
  browser-required `/setup` visual smoke across desktop, tablet, and mobile
  with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-setup-actions-r1`.
- Shared API/CLI automation-context drawers now expose explicit operator
  semantics. Footer actions, automation-recorder controls, API contract curl
  copy, endpoint curl copy, and CLI copy controls now render explicit
  `type="button"` attributes, contextual `title` and `aria-label` text, and
  stable `data-automation-action` or `data-automation-recorder-action` hooks.
  The focused automation-context JS test pins the source contract, and the
  shared browser smoke helper now verifies the rendered drawer controls every
  time a route opens API/CLI context. Remote validation on `opc@139.87.66.128`
  passed `node --check` for the changed JS files, the focused
  automation-context JS test, `make webui-check`, and browser-required `/logs`
  visual smoke across desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-automation-context-actions-r1`.
- System Logs route and drawer handoff controls now expose explicit operator
  semantics. The route-level API/CLI, Refresh, and Clear actions plus the log
  drawer Copy packet, Export JSON, Pin to case, and Close controls now render
  explicit `type="button"` attributes with contextual `title` and `aria-label`
  text while preserving the existing `data-logs-action` and `data-log-action`
  selectors. The focused Logs JS test pins the source contract, and `/logs`
  smoke verifies the rendered route and drawer controls before exercising copy,
  export, pin, saved-filter, routed-entry, and empty-state workflows. Remote
  validation on `opc@139.87.66.128` passed `node --check` for the changed JS
  files, the focused Logs JS test, `make webui-check`, and browser-required
  `/logs` visual smoke across desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-logs-actions-r1`.
- Settings access lifecycle controls now expose explicit operator semantics.
  Access administration actions, lifecycle-review evidence controls, local-user
  lifecycle row actions, browser-session revoke, break-glass rotation, local-user
  drawer submits, and one-time-token evidence controls now render explicit
  `type="button"` attributes, contextual `aria-label` text, and stable access
  selectors where operators or smoke tests need to target the action.
  `settings_access.test.mjs` pins the source contract, and `/settings` smoke
  now verifies the rendered access controls during lifecycle, local-user, and
  break-glass workflows. Remote validation on `opc@139.87.66.128` passed
  `node --check` for the changed JS files, the focused Settings access JS test,
  `make webui-check`, and browser-required `/settings` visual smoke across
  desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-settings-access-actions-r1`.
- Traffic and App-ID high-frequency row actions now have explicit operator
  semantics. Flow, session, and App-ID observation action buttons render
  `type="button"` with contextual `aria-label` text and stable action selectors
  while preserving the existing Explain, App-ID, Allow, Drop, Save & drop,
  Review, Capture, and Flows workflows. The focused App-ID observation JS test
  pins the source contract, and `/traffic` browser smoke verifies rendered row
  controls across the flow, session, and App-ID observation workbenches. Remote
  validation on `opc@139.87.66.128` passed `node --check` for the changed JS
  files, the focused App-ID observation JS test, `make webui-check`, and
  browser-required `/traffic` visual smoke across desktop, tablet, and mobile
  with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-traffic-actions-r1`.
- Shared evidence toolbar actions now have explicit button semantics. The
  reusable Copy link, Copy API, Copy CLI, Export JSON, and Export CSV controls
  now render `type="button"` with context-specific `aria-label` text while
  preserving existing evidence action selectors. The focused evidence-toolbar
  JS test pins the attribute contract, and System Logs browser smoke verifies
  the rendered shared toolbar actions. Remote validation on
  `opc@139.87.66.128` passed `node --check` for the changed JS files, the
  focused evidence-toolbar JS test, `make webui-check`, and browser-required
  `/logs` visual smoke across desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-evidence-toolbar-r1`.
- Investigation, Objects, and Rules high-frequency icon controls now have
  explicit operator semantics. Investigation case remove buttons expose
  `type="button"`, contextual `Remove ... from investigation case` labels, and
  stable case-action selectors without mutating the case during smoke. Objects
  security-profile impact buttons now expose `Review security profile impact`
  titles/labels before opening the route-backed impact drawer. Rules editor
  token-chip remove buttons now expose token/field-specific labels and stable
  `data-rule-token-*` selectors. The Rules App-ID review drawer also restores
  the explicit future L7 dataplane milestone disclosure on both port-hint and
  signal-only App-ID review paths. Remote validation on
  `opc@139.87.66.128` passed `node --check` for the changed JS files, focused
  Investigation/Object/Rules JS tests, `make webui-check`, and browser-required
  `/rules`, `/objects`, and `/investigation` visual smoke across desktop,
  tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-icon-actions-r3`.
- Readiness generated-command copy controls now share an accessibility-safe
  copy button helper. Support-bundle fallback, release acceptance, release
  evidence, and host-tuning command rows now render icon buttons with explicit
  `type="button"`, contextual `aria-label` text, and stable command-copy
  selectors. The focused Readiness view test pins the helper contract, and the
  browser smoke validates release-acceptance command buttons plus host-tuning
  command buttons whenever they are rendered. Remote validation on
  `opc@139.87.66.128` passed `node --check` for the changed JS files,
  the focused Readiness view test, `make webui-check`, and browser-required
  `/readiness` visual smoke across desktop, tablet, and mobile with artifacts
  under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-readiness-command-copy-r1`.
- Routing & VPN dynamic editor remove controls now have explicit button
  semantics. BGP neighbor, BGP announced-prefix, OSPF area, and WireGuard peer
  remove icon buttons now render with `type="button"`, contextual
  `aria-label` text, and stable `data-netvpn-action` selectors. The Net/VPN
  source test pins those contracts, and the existing `/netvpn` browser smoke
  verifies the rendered editor controls inside the BGP, OSPF, and WireGuard
  drawer workflows. Remote validation on `opc@139.87.66.128` passed
  `node --check` for the changed JS files, the focused Net/VPN JS test,
  `make webui-check`, and browser-required `/netvpn` visual smoke across
  desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-netvpn-editor-remove-actions-r2`.
- Shared close/copy controls now have explicit button semantics in the common
  UI primitives and Settings navigation. Toast dismiss, drawer close,
  diagnostic-console close, and Settings panel copy-link icon buttons now
  include explicit `type="button"` plus title/accessible-label coverage where
  applicable. The design-system source test pins those contracts. Remote
  validation on `opc@139.87.66.128` passed `node --check` for the changed JS
  files, the focused design-system test, `make webui-check`, and browser-
  required `/` plus `/settings` visual smoke across desktop, tablet, and mobile
  with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-shared-control-buttons-r2`.
- Rules bulk/group/density controls now have stable operator selectors. The
  Rules toolbar exposes `data-rule-control="density|group"`, selection controls
  expose `data-rule-select="visible|group|row"`, and grouped table headers
  expose `data-rule-group`, so smoke and future automation no longer rely on
  brittle class/text selectors for the core bulk-review workflow. Browser
  smoke now drives density/group controls and bulk toolbar actions through the
  semantic hooks while preserving mobile tap-target, row-action, grouped-review,
  cleanup, changed-rule verification, and candidate-only lifecycle proof.
  Remote validation on `opc@139.87.66.128` passed `node --check` for the smoke
  harness, Rules view, and Rules responsive selector test, `make webui-check`,
  and browser-required `/rules` visual smoke across desktop, tablet, and mobile
  with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-rules-selector-hooks-r1`.
- Inspection coverage map now has stable responsive-table browser proof. The
  coverage map table has a dedicated `inspection-coverage-table` class and the
  visual smoke asserts responsive evidence-table structure, Coverage/Rules/
  Examples/Operator action labels, mobile pseudo-label rendering, and overflow
  containment on `/inspection`. The false-positive exception tables now also
  have stable `inspection-exception-table` and `ids-exception-table` class
  hooks pinned by static responsive-table coverage for the next exception
  lifecycle browser pass. Remote validation on `opc@139.87.66.128` passed
  `node --check` for the smoke harness and IDS/responsive-table files,
  `make webui-check`, and browser-required `/inspection` visual smoke across
  desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-inspection-coverage-table-r1`.
- Settings OIDC provider lifecycle now has browser-required save, reopen, and
  disable proof. The visual smoke starts a loopback OIDC discovery/JWKS
  provider, writes a node-local temporary client-secret file, drives the
  Settings OIDC drawer through validate/copy/export/pin-to-case/save/reopen/disable,
  verifies persisted enabled and disabled state through
  `/v1/system/access-administration/oidc/config`, and asserts that
  `clientSecretFileConfigured` is true while the server-local secret path is
  never serialized back to the browser. The OIDC rollout model now aligns with
  runtime behavior by treating loopback HTTP issuers as lab/smoke review items
  rather than production-ready HTTPS. Remote validation on
  `opc@139.87.66.128` passed `node --check`, `make webui-check`, focused
  `TestOIDCRuntimeSmokeProviderLifecycle`, and browser-required `/settings`
  visual smoke across desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-oidc-provider-lifecycle-r1`
  and `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-oidc-rollout-pin-r1`.
- Guided Setup first-run checklist now uses the shared responsive evidence
  table primitive. The checklist renders explicit Check, Status, and Proof
  cells with mobile `data-label` coverage while preserving stable
  `data-setup-check` selectors and the existing baseline staging workflow.
  Remote validation on `opc@139.87.66.128` passed `node --check`,
  `make webui-check`, and browser-required `/setup` visual smoke across
  desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-setup-checklist-table-r1`.
- Investigation case routes now consume route-backed focus context. Direct
  links such as `#/investigation?caseKey=...&caseAction=candidate-rule&caseKind=flow`
  normalize bounded case custody fields, reject token/local-path shaped query
  values, show a focused case-action banner, mark the matching case row with
  stable `data-case-focused`, `data-case-action`, and `data-case-kind`
  selectors, and preserve a sanitized `Open source workflow` link back to the
  pinned item source route. Remote validation on `opc@139.87.66.128` passed JS
  syntax checks, focused Investigation route/case/view/capture tests,
  `make webui-check`, and browser-required `/investigation` visual smoke across
  desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-investigation-route-focus-r1`.
- Troubleshoot runtime-correlated EVE evidence now uses the shared responsive
  evidence-table primitive. The runtime evidence panel keeps correlated EVE
  flow and alert counts, but renders the bounded flow/alert rows through
  `responsiveTable(...)` with mobile `data-label` cells, stable
  `data-correlated-eve-table`, `data-correlated-eve-row`, and
  `data-correlated-eve-flow-id` selectors, and preserved pivots to the matching
  Traffic and Threats flow routes. Remote validation on `opc@139.87.66.128`
  passed JS syntax checks, the focused `troubleshoot_view.test.mjs`,
  `make webui-check`, and browser-required `/troubleshoot` visual smoke across
  desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-troubleshoot-correlated-eve-table-r1`.
- Routing & VPN tunnel drawers now have exact route-specific API/CLI context
  parity. Tunnel hashes now carry sanitized selected path fields from the
  selected model target (`local`, `remote`, `src`, `dst`, `protocol`, and
  `port`), and sparse direct drawer routes are enriched on reload before API/CLI
  handoff. `#/netvpn?drawer=tunnel&kind=wireguard&iface=wg0&peer=laptop` lists
  candidate policy read, explain-flow preview for the selected representative
  tuple, tunnel-relevant session search, and matching `ngfwctl policy show`,
  `explain`, and `sessions` commands; IPsec tunnel drawers use the same
  route-backed contract with UDP/4500 session context. The drawer-level
  `API / CLI` action lets operators capture the selected tunnel handoff without
  relying on the global toolbar, while the copied context explicitly keeps
  secret file paths, private keys, and PSKs out of route state and clipboard
  output. Remote validation on `opc@139.87.66.128` passed targeted JS syntax and
  automation-context tests, `make webui-check`, and browser-required `/netvpn`
  visual smoke across desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-netvpn-selected-tuple-r1`.
- Intel content quality drawers now have route-accurate API/CLI context parity.
  `#/intel?surface=app-id&drawer=quality` advertises package posture, bounded
  package-local evidence, typed corpus browse, and non-mutating compare-preview
  APIs plus matching `ngfwctl intel content`, `corpus`, and `compare`
  commands. Content lifecycle drawers now include an in-drawer `API / CLI`
  action so review, quality, install, and rollback handoffs do not depend on
  the global toolbar.
- Settings host-input now has route-backed API/CLI context parity proof. The
  `#/settings?panel=host-input` context lists candidate policy read,
  candidate validation, running-to-candidate diff, candidate show, validate,
  diff, and baseline `--harden-host-input` bootstrap commands while explicitly
  keeping unsaved form values out of route/copied context. The `/settings`
  smoke opens this drawer after proving management allow coverage plus
  default-deny host-input staging.
- Inspection now has browser-required API/CLI context proof on its direct
  workspace route. The `/inspection` smoke stages Detect and Disable as
  candidate-only IDS/IPS profile actions, then opens the global API/CLI context
  drawer and verifies the inspection contract: `/v1/system/status`,
  `/v1/intel/content/packages`, `/v1/alerts?limit=200`, `ngfwctl status`,
  `ngfwctl intel content`, `ngfwctl alerts --limit 100`, and the
  Suricata/runtime-after-commit guidance. Remote validation on
  `opc@139.87.66.128` passed `node --check e2e/webui-visual-smoke.mjs`,
  browser-required `/inspection` smoke across desktop, tablet, and mobile, and
  `make webui-check`.
- Inspection now includes a candidate inspection coverage map. The model
  classifies each candidate rule into pre-filter drop, IDS detect, IPS
  fail-open, IPS fail-closed, profile-enforced, not-inspected, flowtable bypass
  risk, or blocking-profile enforcement gaps; the workspace shows rule counts,
  active allow paths, review items, runtime bypass posture, bucket examples,
  and route-backed operator actions back to Rules or Inspection profile
  rollout. Browser smoke proves the map root, counters, responsive containment,
  and survival across candidate-only Detect staging; focused JS tests prove the
  bucket logic for flowtable bypass, profile fail-closed enforcement, and
  runtime failed-open posture.
- Rules now includes a candidate rulebase map above the ordered table. The map
  summarizes total/active rules, allow paths, App-ID-scoped rules, profiled
  inspection rules, staged changes, rule-order bands, named dependency counts,
  hit-evidence posture, and review hotspots from the existing cleanup,
  inspection, counter, and change models. Stable selectors expose
  `data-rulebase-map`, `data-rulebase-band`, and `data-rulebase-review-row`.
  Browser smoke proves the map renders with expected allow/review bands across
  desktop, tablet, and mobile, while focused JS tests prove the aggregate model
  for changed, App-ID, profiled, disabled, overlap, bypass-risk, missing-log,
  and zero-hit rules.
- Server-derived Rules overlap review now computes candidate-side overlap
  impact in the route-backed drawer. The drawer resolves earlier peer rules
  from the current candidate, excludes full-cover/shadow cases to match backend
  partial-overlap semantics, shows shared dimensions, representative overlap
  tuple, action/logging/profile/App-ID risk flags, and an operator
  recommendation before staging logging or review tags. Browser smoke proves
  peer, dimension, risk, and recommendation hooks across desktop, tablet, and
  mobile.
- Threats alert evidence now uses the shared responsive evidence-table
  primitive instead of a hand-built `responsive-evidence` table. Alert rows keep
  stable `data-threat-alert-row` hooks, keyboard activation, severity/time
  column classes, and mobile `data-label` cells through `labeledCell(...)`.
  Remote validation on `opc@139.87.66.128` passed `node --check` for
  `views/threats.js`, the responsive-table JS regression, `make webui-check`,
  and browser-required `/threats` smoke across desktop, tablet, and mobile.
- Objects reference drawers now expose exact route-specific API/CLI context.
  `#/objects?tab=services&drawer=references&object=...` maps to
  `/v1/policy/object-references?source=POLICY_SOURCE_CANDIDATE&kind=...&name=...`
  and `ngfwctl policy references --source candidate --kind ... --name ...`,
  with `policy show` retained as supplemental context. The published-service
  object-reference browser workflow now proves the scoped endpoint and CLI in
  the API/CLI context drawer before pivoting to the referenced NAT rule. Remote
  validation on `opc@139.87.66.128` passed `node --check` for
  `automation_context.js` and `e2e/webui-visual-smoke.mjs`, the focused
  automation-context JS test, `make webui-check`, and browser-required
  `/objects` smoke across desktop, tablet, and mobile.
- Readiness Engine prerequisites now uses the shared responsive evidence-table
  primitive instead of bespoke table/mobile CSS. Engine rows carry stable
  `data-readiness-engine-row` selectors, cells use `labeledCell(...)` so mobile
  labels come from the shared design-system behavior, and the old custom mobile
  `.engine-readiness` row rules were removed. Remote validation on
  `opc@139.87.66.128` passed `node --check` for `views/readiness.js` and
  `e2e/webui-visual-smoke.mjs`; focused responsive-table and readiness-view JS
  tests; `make webui-check`; and browser-required `/readiness` smoke across
  desktop, tablet, and mobile.
- Readiness XDP/tc eBPF evidence now uses the shared responsive evidence-table
  primitive for host prerequisite probes, attach prerequisite probes,
  attachment inventory, and artifact digest rows. The tables expose stable
  `data-readiness-ebpf-table`, `data-readiness-ebpf-probe`,
  `data-readiness-ebpf-attachment`, and `data-readiness-ebpf-artifact` hooks,
  and every mobile cell is labeled through `labeledCell(...)` instead of
  custom row markup. This is a design-system and operator-evidence conversion;
  it does not claim active eBPF dataplane activation, traffic cutover, verifier
  policy, signed object provenance, map lifecycle, or rollback hardening.
  Remote validation on `opc@139.87.66.128` passed `node --check` for
  `views/readiness.js`, `readiness_ebpf_evidence.test.mjs`, and
  `e2e/webui-visual-smoke.mjs`; the focused eBPF evidence JS test;
  `make webui-check`; and browser-required `/readiness` smoke across desktop,
  tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-readiness-ebpf-table-r1`.
- Readiness XDP/tc eBPF design-system contracts now also pin the final
  evidence-card spacing and runtime attachment/artifact responsive-table
  behavior. The eBPF action row and blocker chips use named CSS classes instead
  of inline margin styles, source-level tests assert the attachment and artifact
  table headers/classes/labels, and browser smoke requires runtime attachment
  and artifact tables to carry `responsive-evidence` plus full mobile
  `data-label` coverage. Remote validation on `opc@139.87.66.128` passed
  `node --check` for `views/readiness.js`,
  `responsive_tables.test.mjs`, `readiness_ebpf_evidence.test.mjs`, and
  `e2e/webui-visual-smoke.mjs`; the two focused JS tests with
  `node_test_polyfills.cjs`; `make webui-check`; and browser-required
  `/readiness` smoke with `WEBUI_SMOKE_EBPF_RUNTIME_EVIDENCE=1` across desktop,
  tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-readiness-ebpf-design-r1`.
  The next highest-impact design-system slice from the parallel scan is the
  remaining Rules manual table/action hardening in `views/rules.js`; this eBPF
  polish does not change the active dataplane or any deferred eBPF production
  hardening requirements.
- Rules table/action design-system hardening now moves the main rulebase table's
  header sizing, hit/action alignment, row action wrapping, name-badge spacing,
  description truncation, zone-path spacing, empty-state action centering, and
  grouped-row colspan out of brittle inline styles/magic literals and into named
  CSS/JS contracts. The pass also fixes the Rules inspection column selector to
  column 12 now that Profiles is column 11, and source tests assert the Profiles
  `data-label`, CSS-owned column/action classes, mobile row-action wrapping, and
  named `RULE_TABLE_COLUMN_COUNT`. Remote validation on `opc@139.87.66.128`
  passed `node --check` for `views/rules.js` and
  `rules_table_responsive.test.mjs`; the focused Rules responsive-table JS test
  with `node_test_polyfills.cjs`; `make webui-check`; and browser-required
  `/rules` smoke across desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-rules-table-design-r1`.
  Remaining Rules hardening is broader interaction/focus audit and any future
  conversion of non-table filter/editor inline layout.
- Dashboard severity chart/legend hardening now moves the Threats by severity
  chart layout, legend stacking, and severity swatch color ownership out of
  per-node inline styles and into named design-system classes. The legend links
  expose stable `data-dashboard-severity-legend` hooks, CSS owns the severity
  swatch colors, source tests reject the old inline legend/swatch styles, and
  browser smoke now verifies classed severity links, swatches, mobile tap target
  size, and layout overflow. Remote validation on `opc@139.87.66.128` passed
  `node --check` for `views/dashboard.js`, `design_system.test.mjs`, and
  `e2e/webui-visual-smoke.mjs`; focused design-system and dashboard-management
  JS tests with `node_test_polyfills.cjs`; `make webui-check`; and
  browser-required `/` Dashboard smoke across desktop, tablet, and mobile with
  artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-dashboard-severity-design-r1`.
  The parallel Rules scan identified toolbar inline layout, rule editor
  token/baseline layout, and flow-check/verification rows as the next safe
  non-table design-system cleanup candidates.
- Rules toolbar design-system hardening now moves the filter/action/zone/tag
  select widths and filter/view control-group spacing out of inline styles and
  into named CSS classes. The toolbar exposes stable
  `data-rules-toolbar-group="filters|view"` hooks, source tests reject the old
  select max-width and flex-gap inline snippets, mobile CSS stretches the
  grouped controls without `!important`, and browser smoke verifies the filter
  and view groups, their select counts/classes, and toolbar overflow. Remote
  validation on `opc@139.87.66.128` passed `node --check` for
  `views/rules.js`, `rules_table_responsive.test.mjs`, and
  `e2e/webui-visual-smoke.mjs`; the focused Rules responsive-table JS test with
  `node_test_polyfills.cjs`; `make webui-check`; and browser-required `/rules`
  smoke across desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-rules-toolbar-design-r1`.
  Remaining non-table Rules design-system cleanup is the editor
  token/baseline layout and flow-check/verification rows.
- Rules simulator and changed-rule verification layout hardening now moves the
  flow-check result action alignment and changed-rule verification row header
  spacing out of inline styles and into named CSS classes. The simulator result
  action row uses `.sim-actions.start`, verification rows expose
  `.rule-verification-head`, `.rule-verification-title`, and
  `.rule-verification-kind`, source tests reject the old inline alignment/gap
  snippets, and browser smoke verifies the result action row class/overflow plus
  verification row header/title/kind hooks, badge-state parity, and row overflow.
  Remote validation on `opc@139.87.66.128` passed `node --check` for
  `views/rules.js`, `rules_table_responsive.test.mjs`, and
  `e2e/webui-visual-smoke.mjs`; the focused Rules responsive-table JS test with
  `node_test_polyfills.cjs`; `make webui-check`; and browser-required `/rules`
  smoke across desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-rules-simverify-design-r1`.
  Remaining non-table Rules design-system cleanup is now the editor
  token/baseline layout plus the broader keyboard/focus and interaction
  hardening pass.
- Rules editor token/baseline layout hardening now moves baseline setup toggle
  copy/alignment and rule-editor token chip/select sizing out of inline styles
  and into named CSS classes. The baseline drawer exposes `.baseline-toggle` and
  `.baseline-toggle-copy`, token editors expose `.rules-token-editor` and
  `.rules-token-select`, source tests reject the old inline layout snippets, and
  browser smoke verifies the baseline setup drawer plus new/edit rule token
  editors for overflow across desktop, tablet, and mobile. Remote validation on
  `opc@139.87.66.128` passed `node --check` for `views/rules.js`,
  `rules_table_responsive.test.mjs`, and `e2e/webui-visual-smoke.mjs`; the
  focused Rules responsive-table JS test with `node_test_polyfills.cjs`;
  `make webui-check`; and browser-required `/rules` smoke across desktop,
  tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-rules-editor-design-r1`.
  Remaining Rules design-system hardening is now the broader per-workspace
  keyboard/focus audit, responsive artifact currency, and interaction regression
  pass.
- Rules row-action and selection-control accessibility now has focused
  keyboard proof. The Rules density/group controls, select-visible checkbox,
  row-selection checkboxes, and icon-only row actions now expose explicit
  accessible labels, and row action buttons declare `type="button"` so they do
  not inherit accidental form-submit behavior. Browser smoke now focuses the
  `allow-web` Explain and Capture row actions and activates them with Enter,
  while also asserting the accessible names for density/group and selection
  controls. Remote validation on `opc@139.87.66.128` passed `node --check` for
  `views/rules.js`, `rules_table_responsive.test.mjs`, and
  `e2e/webui-visual-smoke.mjs`; focused Rules responsive-table,
  UI-accessibility, and Rules bulk/density JS tests with
  `node_test_polyfills.cjs`; `make webui-check`; and browser-required `/rules`
  smoke across desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-rules-keyboard-actions-r1`.
  The broader per-workspace keyboard/focus audit and interaction regression
  hardening remain tracked for the hardening pass.
- NAT lifecycle action controls now expose explicit operator semantics. Route
  add, source/destination panel add, source NAT save, destination NAT save,
  source NAT shared confirmation, and destination NAT delete-review controls now
  render explicit `type="button"` attributes with contextual `title` and
  `aria-label` text while preserving stable `data-nat-action` selectors for the
  owner workflows. The focused NAT path-preview JS test pins the source
  contract, and `/nat` smoke verifies rendered add/save/delete controls before
  exercising source NAT add/edit/delete, destination NAT publish, preview,
  object-reference, rename, and cleanup workflows. Remote validation on
  `opc@139.87.66.128` passed `node --check` for the changed JS files, the
  focused NAT path preview JS test, `make webui-check`, and browser-required
  `/nat` visual smoke across desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-nat-actions-r1`.
- NAT row-action accessibility now has focused source and destination workflow
  proof. Source NAT and destination NAT row action buttons now share an explicit
  `type="button"` and `aria-label` contract for Preview path, Edit, and Delete,
  while preserving the existing `data-nat-action` selectors used by the NAT
  lifecycle smoke. Browser smoke now asserts the accessible names and button type
  for edited source NAT rows and published destination NAT rows before exercising
  path preview and delete flows. Remote validation on `opc@139.87.66.128` passed
  `node --check` for `views/nat.js`, `nat_path_preview.test.mjs`, and
  `e2e/webui-visual-smoke.mjs`; focused NAT path preview and object-reference JS
  tests with `node_test_polyfills.cjs`; `make webui-check`; and browser-required
  `/nat` smoke across desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-nat-row-actions-r1`.
- Net/VPN static-route row-action accessibility now has focused rollout proof.
  Static route Edit and Delete icon buttons declare `type="button"` and contextual
  labels such as `Edit static route 10.120.10.0/24`, while preserving the existing
  `data-netvpn-action` selectors. The WireGuard branch-rollout smoke now returns
  to `/netvpn` after staging the branch route and asserts the concrete
  `10.120.10.0/24` route row action labels before candidate review. Remote
  validation on `opc@139.87.66.128` passed `node --check` for `views/netvpn.js`,
  `netvpn.test.mjs`, and `e2e/webui-visual-smoke.mjs`; focused Net/VPN JS tests
  with `node_test_polyfills.cjs`; `make webui-check`; and browser-required
  `/netvpn` smoke across desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-netvpn-route-actions-r1`.
- Net/VPN tunnel row-action accessibility now has focused tunnel-workbench proof.
  IPsec Inspect/Edit/Delete icon buttons declare `type="button"` and contextual
  labels such as `Inspect IPsec tunnel site-b`; WireGuard Edit/Delete icon
  buttons now expose stable `data-netvpn-action` hooks, `type="button"`, and
  contextual labels such as `Edit WireGuard interface wg0`. The tunnel workbench
  smoke seeds concrete `site-b` and `wg0` rows and asserts their rendered action
  labels before opening the WireGuard handoff drawer. Remote validation on
  `opc@139.87.66.128` passed `node --check` for `views/netvpn.js`,
  `netvpn.test.mjs`, and `e2e/webui-visual-smoke.mjs`; focused Net/VPN JS tests
  with `node_test_polyfills.cjs`; `make webui-check`; and browser-required
  `/netvpn` smoke across desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-netvpn-tunnel-actions-r1`.
- Settings host-input row-action accessibility now has focused workflow proof.
  Host-input rule Edit and Delete icon buttons declare `type="button"` and
  contextual labels such as `Edit host-input rule allow-smoke-management`, while
  preserving the existing `data-host-input-action` selectors. The Settings network
  and host-input smoke now stages the `allow-smoke-management` candidate rule,
  verifies the rendered host-input panel, and asserts the concrete row action
  labels before opening the Settings automation context. Remote validation on
  `opc@139.87.66.128` passed `node --check` for `views/settings.js`,
  `settings_access.test.mjs`, and `e2e/webui-visual-smoke.mjs`; focused Settings
  access JS tests with `node_test_polyfills.cjs`; `make webui-check`; and
  browser-required `/settings` smoke across desktop, tablet, and mobile with
  artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-settings-host-input-actions-r1`.
- Objects row-action accessibility now has focused dependency-workflow proof.
  Object Edit and Delete icon buttons declare `type="button"` and contextual
  labels such as `Edit service publish-service-8443`, while preserving the
  existing `data-object-action`, `data-object-kind`, and `data-object-name`
  selectors used by publish-service and dependency-review workflows. The
  publish-service rename smoke now asserts the concrete service row action
  labels before opening the service editor, and the Objects App-ID hygiene smoke
  expectation now matches the current enforcement boundary for TCP/UDP port hints
  or supported Suricata signals. Remote validation on `opc@139.87.66.128` passed
  `node --check` for `views/objects.js`, `object_references.test.mjs`, and
  `e2e/webui-visual-smoke.mjs`; focused object-reference JS tests with
  `node_test_polyfills.cjs`; `make webui-check`; and browser-required `/objects`
  smoke across desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-objects-row-actions-r1`.
- Packet-capture artifact lifecycle now has browser-required proof in
  Troubleshoot. The capture workbench exposes stable selectors for capture
  fields, generated command, warnings, job result, recent artifact history,
  retain/release/download/audit actions, and retention-dialog fields; the
  generated-command copy icon now declares `type="button"` and `aria-label="Copy
  capture command"`; the recent-captures row also renders Flow ID and BPF filter
  metadata when a sidecar contains tuple scope; the shared Investigation
  capture-evidence rows expose the same artifact/action hooks. Visual smoke
  seeds a completed PCAP plus sidecar under the configured log root, validates
  the generated-command copy control, validates that retain-without-reason is
  rejected, records retain metadata, downloads the artifact bytes, releases
  retention metadata, routes to the packet-capture audit search, and restores
  the capture route. Remote validation on `opc@139.87.66.128` passed
  `node --check` for
  `views/troubleshoot.js`, `packet_capture.test.mjs`,
  `troubleshoot_view.test.mjs`, and `e2e/webui-visual-smoke.mjs`; focused
  packet-capture and Troubleshoot view JS tests with `node_test_polyfills.cjs`;
  `make webui-check`; and browser-required `/troubleshoot` smoke across
  desktop, tablet, and mobile with artifacts under
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-troubleshoot-capture-copy-action-r1`.
- SAML provider audit discoverability now has parity with the existing OIDC
  provider and local-user access workflows. Settings Access governance links
  now include `access-saml-provider-set` and
  `access-saml-provider-disable`, Changes audit filters include SAML provider
  set/disable intent/success/failure actions, provider audit actions render with
  the access/governance visual class, and Settings Access API/CLI context now
  includes OIDC/SAML provider audit endpoints plus `ngfwctl audit --action
  access-saml-provider-set --hashes`. The Changes audit table now allows long
  provider action pills to wrap inside mobile responsive rows instead of
  overflowing. Remote validation on `opc@139.87.66.128` passed `node --check`
  for `access_governance.js`, `views/changes.js`, `automation_context.js`, and
  `e2e/webui-visual-smoke.mjs`; focused settings-access, changes-audit, and
  automation-context JS tests; `make webui-check`; and browser-required
  `/settings,/changes` smoke across desktop, tablet, and mobile.
- NAT path preview now ignores stale async running/candidate explain responses.
  Each preview request snapshots the tuple, carries a request id/key, and is
  invalidated whenever route/default/staged preview state changes, so a delayed
  response cannot overwrite the visible tuple or copied/pinned/exported
  evidence. The NAT preview actions now expose stable `data-nat-preview-action`
  selectors and the rendered result carries the current tuple key for browser
  smoke. Performance now also has browser-required API/CLI context proof before
  the benchmark verifier workflow runs, covering local `ngfwperf` verification,
  runtime status capture, nftables evidence capture, copied workflow-session
  JSON, and redaction. Remote validation on `opc@139.87.66.128` passed
  `node --check internal/webui/static/js/views/nat.js`, `node --check
  e2e/webui-visual-smoke.mjs`, `node --require
  ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/nat_path_preview.test.mjs`, `make webui-check`,
  browser-required `/performance` smoke, and browser-required `/nat` smoke
  across desktop, tablet, and mobile.
- The global Diagnostic Console now includes a summary-only Routing/VPN status
  block in its copied `ngfwctl status # routing-vpn` snapshot. The block reports
  FRR state with BGP/OSPF neighbor counts, IPsec active tunnel counts, and
  WireGuard handshook peer counts without copying tunnel names, public keys,
  endpoint values, managed secret paths, or command bodies. Dashboard API/CLI
  context now lists the same routing/VPN status parity command, and Settings
  Access browser smoke now proves the `#/settings?panel=access` API/CLI context
  drawer for OIDC, SAML, local-user, browser SSO session revoke, copied
  workflow-session JSON, command parity, and redaction. Remote validation on
  `opc@139.87.66.128` passed `node --check
  internal/webui/static/js/diagnostic_console.js`, `node --check
  internal/webui/static/js/automation_context.js`, `node --check
  e2e/webui-visual-smoke.mjs`, diagnostic-console and automation-context JS
  tests, `make webui-check`, and browser-required visual smoke for `/` and
  `/settings` across desktop, tablet, and mobile with
  `WEBUI_SMOKE_REQUIRE_BROWSER=1`.
- Support-bundle evidence now captures the canonical runtime-readiness preflight
  used by commit review. Server and CLI/client collectors include a
  `runtimeReadinessPreflight` endpoint derived from running and candidate
  policy, the browser fallback collector does the same when the server bundle
  endpoint is unavailable, and the support-bundle preview/report shows
  operation, acknowledgement requirement, and item count. Readiness and Changes
  automation context now list `POST /v1/system/runtime-readiness:check` beside
  the existing status, validation, diff, commit, and support-bundle contracts.
  Remote validation on `opc@139.87.66.128` passed
  `go test -count=1 ./internal/apiserver -run 'SupportBundle|RuntimeReadiness'`,
  `go test -count=1 ./internal/supportbundle`, changed WebUI `node --check`
  files, support-bundle/readiness/automation-context JS tests,
  `make webui-check`, and `/readiness` browser-required visual smoke across
  desktop, tablet, and mobile.
- `ngfwctl commit` and `ngfwctl rollback` now use the same canonical
  `CheckRuntimeReadiness` server preflight as the WebUI commit path and support
  bundles. The CLI sends the target and running policies to the server before
  apply, maps the response into the existing `runtime:` output and
  `--ack-runtime` gate, and keeps a narrow `Unimplemented` fallback for legacy
  servers that only expose status. Remote validation on `opc@139.87.66.128`
  passed `go test -count=1 ./internal/cli -run
  'Commit|Rollback|RuntimePreflight'`, `go test -count=1 ./internal/apiserver
  -run RuntimeReadiness`, `go test -count=1 ./internal/supportbundle`, and
  `go test -count=1 ./internal/cli`.
- System Logs browser proof now covers saved-filter lifecycle, route-backed
  drawer reload, and no-match empty-state behavior in addition to the existing
  filtered Suricata warning workflow. Saved filters for the `system-logs` scope
  are proven to save/apply/delete without persisting the transient `entry`
  drawer key, `#/logs?...&entry=<id>` reopens the matching log drawer after a
  reload, and the no-match route exposes a stable Readiness action without
  overflow. The shared saved-filter helper now defensively coerces loaded
  presets to arrays before save/delete/refresh operations. Remote validation on
  `opc@139.87.66.128` passed `node --check
  internal/webui/static/js/views/logs.js`, `node --check
  internal/webui/static/js/saved_filters.js`, `node --check
  e2e/webui-visual-smoke.mjs`, `make webui-check`, and `/logs`
  browser-required visual smoke across desktop, tablet, and mobile.
- Threat-ID exception lifecycle now has CLI parity through `ngfwctl
  threat-exceptions list|stage|update|disable|enable|remove`. The commands use
  the server-owned `ThreatTuningService`, preserve existing exception metadata
  during partial updates, require an acknowledgement before active global
  exceptions are staged or kept, and return candidate-only guidance in human
  output while keeping JSON output on proto names. Remote validation on
  `opc@139.87.66.128` passed `go test -count=1 ./internal/cli -run
  ThreatException`, `go test -count=1 ./internal/apiserver -run
  ThreatException`, `go test -count=1 ./internal/cli`, targeted apiserver
  policy-regression tests, and `go test -count=1 ./internal/cli
  ./internal/apiserver`. The apiserver reference-policy fixture now explicitly
  enables IDS Prevent fail-closed when it attaches blocking security profiles to
  allow rules, keeping broad policy tests aligned with the validation contract.
- Server-derived Rules overlap cleanup now has a route-backed review drawer.
  `POLICY_HYGIENE_RULE_OVERLAP` validation findings retain server detail,
  severity, stage, and field path; the Rule cleanup queue exposes `Review
  overlaps`; and `#/rules?q=server-overlap&drawer=server-overlap-review` opens a
  drawer with affected rule order, match dimensions, logging posture, copyable
  review context, and candidate-safe handoffs to existing logging and tag bulk
  review flows. Remote validation on `opc@139.87.66.128` passed `node --check
  internal/webui/static/js/views/rules.js`, `node --check
  e2e/webui-visual-smoke.mjs`, `node --require
  ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/rules_bulk_density.test.mjs`, `make webui-check`,
  and `/rules` browser-required visual smoke across desktop, tablet, and mobile.
- Server-owned App-ID observation promotion through
  `StageAppIdObservation`, REST
  `POST /v1/app-id/observations/{queueId}:stage`,
  `ngfwctl app-id promote QUEUE_ID --reason ... [--drop --confirm-drop]`,
  RBAC, audit detail, candidate validation, candidate status, and diff. Browser
  smoke now seeds a real unknown App-ID queue observation from EVE telemetry,
  opens the route-backed `#/traffic?mode=app-id&queueId=...` observation drawer,
  reviews suggested object/evidence, stages `Save & drop` through the
  server-owned queue endpoint, verifies candidate-only application and drop-rule
  output, and restores the previous candidate. API coverage now also proves
  define-and-drop rejects signal-only applications, wrong TCP hints, and
  protocol-mismatched hints before candidate storage.
- Guided Setup baseline parity now has browser-required proof. The smoke opens
  the first-run setup workbench, verifies profile and checklist controls,
  stages a unique two-zone throughput baseline through the real `Stage setup`
  action, proves zones, address, WebUI service, allow rule, source NAT,
  host-input default deny, flow offload, MSS clamp, and IDS-off posture are
  candidate-only, verifies `Review changes` and API/CLI context parity, then
  restores the previous candidate.
- Guided Setup now includes scenario templates for cloud edge, east-west
  segmentation, VPN edge, IDS tap, and lab mode. Each template populates the
  same candidate-only baseline controls instead of committing directly, keeps
  secret-adjacent VPN material as operator-supplied inputs, and preserves the
  normal `Stage setup` -> candidate review flow. Browser smoke proves the
  scenario selector, IDS tap no-outbound/no-NAT/IDS-detect posture, cloud-edge
  reset behavior, and existing running-policy isolation.
- Intel content package install preview now compares current versus preview
  version, manifest, signature/status, evidence state, content hash, and
  blockers before promotion.
- Investigation is now a first-class evidence workbench in browser-required
  smoke coverage. The seeded case path validates flow, alert, packet-capture,
  App-ID, NAT, audit, and content-package evidence together; the case model
  carries a redacted-route custody marker, redacts server-local paths and
  secret-like strings before rendering/copy/export, and capture handoffs prefer
  flow IDs over output-path basenames for audit pivots. The workbench now also
  synthesizes a multi-evidence fix plan with evidence-readiness chips,
  correlate/capture/candidate/owner-workspace steps, and a candidate-safe
  primary owner action that routes to Rules, Threats, Traffic, or NAT instead
  of mutating policy from Investigation. Owner links carry bounded
  browser-local case metadata, and the Rules flow-check owner path now shows
  case origin, stages through the normal candidate session, pins a
  `candidate-remediation` custody packet back into the case, and proves the
  generated rule is candidate-only before restoring the candidate. Threats and
  Traffic/App-ID owner paths now carry the same custody metadata into
  false-positive exception staging, direct App-ID promotion/drop, and reviewed
  App-ID drop-rule staging through the shared rule editor, pinning
  `candidate-remediation` packets after successful candidate saves. The
  Investigation compare grid now uses the shared responsive evidence-table
  primitives for Evidence, Tuple, App, Verdict, Rule, Policy, and Capture
  columns while preserving the existing `investigation-compare` smoke hook;
  browser smoke verifies responsive classes, labels, mobile labels, and
  overflow on the seeded case route. The case cockpit header now also exposes
  its own `API / CLI` action for `#/investigation`; browser smoke proves the
  drawer and copied workflow-session JSON include explain, packet-capture plan,
  flow, alert, and audit contracts while preserving browser-local custody notes
  and Investigation leak guards.
- Runtime content package readiness now rejects generic valid JSON evidence for
  production claims. Package-local evidence artifacts must be JSON objects with
  a matching evidence type and passed status/verdict; App-ID regression corpus
  evidence must also carry the package version and passing sample records with
  valid PCAP hashes plus expected/observed app IDs.
- Intel content evidence inspection now has browser-required proof. The quality
  drawer renders a required-evidence inventory, highlights the attached
  regression corpus, opens the bounded package-local evidence API from the
  actual Inspect action, summarizes App-ID corpus sample rows, and keeps raw
  JSON available for operator review without exposing server-local paths.
- Intel content corpus browsing is now exposed from the same quality drawer.
  Operators can open attached regression corpus evidence as a filtered sample
  table with package version, failed-sample counts, PCAP hashes, and
  case-handoff actions while still relying on the bounded package-local
  evidence API rather than a new mutable content store.
- Intel content corpus and source-package comparison are now API-backed
  workflows. `GET /v1/intel/content/packages/{kind}/corpus` returns typed,
  filterable corpus rows from verified package-local evidence; `POST
  /v1/intel/content/packages/{kind}/compare` verifies a server-local import
  candidate and returns installed-vs-preview package posture plus regression
  corpus diffs without promotion or lifecycle audit writes. `ngfwctl intel
  content corpus` and `ngfwctl intel content compare` expose the same evidence
  path for automation, and the Intel install preview drawer shows the corpus
  diff beside package gate comparison.
- Reviewed App-ID observations can now be appended to a draft regression
  corpus from API, CLI, and WebUI. `POST
  /v1/app-id/observations/{queueId}:stage-regression-sample` and `ngfwctl
  app-id corpus add QUEUE_ID --pcap-sha256 ... --reason ...` re-derive the
  current queue item, validate the bounded capture hash, preserve expected and
  observed app IDs plus package version/hash context, append
  `app-id/.reviewed-corpus/app-regression-corpus.jsonl`, and write an audit
  entry. The Traffic App-ID drawer exposes the same draft staging action beside
  the handoff packet, and selected queue-item API/CLI context now lists the
  exact `:stage-regression-sample` endpoint plus `ngfwctl app-id corpus add`
  command with placeholder capture/App-ID values instead of server-local
  artifact paths. Browser smoke proves required SHA rejection, successful draft
  sample staging, status rendering, and selected queue context parity across
  desktop, tablet, and mobile. This is package-builder input, not signed
  production content.
- Object/NAT publish-service workflow now stages missing host and TCP/UDP
  service objects transactionally with destination NAT, creates or removes only
  tagged generated matching allow rules, opens a running-vs-candidate NAT path
  preview for the published tuple, links the generated allow rule back into
  Rules, and exposes candidate references from Objects without mutating the
  running policy.
- NAT running-vs-candidate path preview deltas now render through the shared
  responsive evidence-table primitives. The preview keeps its existing
  publish-service handoff actions, Troubleshoot pivot, and Investigation packet
  export/copy behavior while the decision/running/candidate rows use
  `responsiveTable`, `labeledCell`, and the `nat-path-delta-table` hook. Browser
  smoke verifies the seeded published-service delta table, mobile labels, and
  overflow before exercising the existing NAT handoff actions.
- Objects zone interface assignment now has browser-required proof. The smoke
  opens Objects on the Zones tab, verifies live host interface inventory, blocks
  duplicate cross-zone and loopback assignments in the actual zone drawer,
  allows missing-interface warnings to stage for offline/future NIC workflows,
  proves the staged zone exists only in the candidate, and checks the saved row
  exposes review posture without mutating the running policy. Route-backed
  object drawers now also detect stale or nonexistent object links for both
  reference review and security-profile impact review, explaining that the
  shared route may point at a deleted or renamed object instead of presenting it
  as a valid unused object.
- Source NAT lifecycle now has browser-required candidate-only proof. The smoke
  stages a masquerade SNAT, edits it into static SNAT, deletes it, verifies the
  candidate `nat.source` payload after each step, proves the running policy is
  unchanged, and checks that NAT path preview is refreshed for the staged
  outbound tuple before commit.
- Declarative security profiles are now first-class policy objects. The proto,
  generated API surface, validator, candidate-status summaries, object-reference
  endpoint, Objects workbench, and Rules editor support named TLS/DNS/URL/file
  inspection profiles attached to security rules. Browser smoke stages a
  security profile object, attaches it to added/edited rules, verifies
  candidate-only isolation, and confirms candidate status reports the
  `securityProfiles` section. Candidate review now surfaces profile impact,
  including high-risk decryption-required intent, before commit. Blocking
  profile intent on active allow rules is now tied to the real inline IPS path:
  validation requires IDS/IPS Prevent with Fail closed, compilation carries an
  inspection-required bit in rule IR, nftables emits profile-inspection counters
  plus fail-closed rule comments, and the Rules workbench labels safe versus
  unsafe profile posture. Objects now also has a route-backed Security Profile
  Impact Workbench that opens from the security-profile table or
  `drawer=impact`, shows candidate-only blast radius, fail-closed coverage,
  rule pivots, and copy/export/pin investigation handoff. Remote live
  integration now proves a blocking security profile attached to an allow rule
  requires IPS Prevent fail-closed, installs fail-closed NFQUEUE without
  `bypass`, emits profile-inspection nftables evidence, forwards the allowed
  flow, and records a Suricata signature alert for the inspected traffic. TLS
  interception, CA handling, URL category databases, DNS sinkhole behavior,
  file-inspection engines, and per-profile audit/custody still require later
  engine integrations and hardening evidence.
- Traffic Custom App-ID review now lets operators move from a flow/session or
  App-ID observation into a prefilled Rules editor before staging the drop
  rule. The editor carries the pending application dependency, validates the
  bounded App-ID enforcement constraints, keeps services empty for
  App-ID-scoped drop rules, distinguishes port-hint drops from supported broad
  Suricata signal-only denies, and stages the application plus rule only
  through the normal candidate save.
  Objects application hygiene now flags App-ID objects without enforceable
  TCP/UDP port hints so operators can distinguish classifier-only custom apps,
  supported broad Suricata signal-only denies, and apps that can be rendered
  into the current bounded port-hint drop path.
- System logs are now a first-class read-only workbench. The canonical
  `/v1/system/logs` API and `ngfwctl system logs` command expose bounded,
  redacted appliance, dataplane, audit, and engine log events from the
  configured OpenNGFW log root without accepting client-supplied paths. The
  `#/logs` WebUI route adds route-backed filters, saved filters, JSON/CSV
  evidence export, copyable API/CLI context, per-row drawers, Investigation
  handoff packets, and pivots into Readiness, Changes audit, Traffic, and
  Threats. Remote browser-required smoke now proves a seeded Suricata warning
  across desktop, tablet, and mobile: filtered route state, exact API/CLI
  context, redacted row rendering, drawer lifecycle, packet copy, JSON export,
  Investigation pinning, and route cleanup after close.
- Threat-ID false-positive exceptions now have browser-proven lifecycle
  coverage. Visual smoke stages an exception from a threat alert with a required
  operator reason, verifies the IDS editor and Threat exception workbench, then
  drives edit, disable, re-enable, and remove through the same drawers operators
  use. Each lifecycle step verifies candidate status/diff context and confirms
  running policy remains unchanged before commit. The exception inventory table
  now uses the shared responsive evidence-table primitives with a stable
  `threat-exception-table` hook while preserving row activation and
  `data-threat-exception-action` controls; smoke verifies classes, labels,
  mobile label rendering, and overflow before exercising the lifecycle.
- IDS/IPS profile settings now have browser-proven candidate-only coverage from
  the Threats workbench. The IDS drawer exposes stable controls for enable,
  detect/prevent mode, monitor interfaces, home networks, rule files, NFQUEUE,
  failure behavior, and staging. Visual smoke stages Detect, Prevent fail-open,
  Prevent fail-closed, and Disable, reopens the drawer to verify persisted UI
  state, checks the candidate `ids` payload after each step, and confirms the
  running policy is unchanged before commit.
- Inspection is now a first-class WebUI workspace at `#/inspection`. It brings
  IDS/IPS profile state, runtime inspection posture, Threat-ID package gates,
  candidate-only rollout actions, and false-positive exception posture into one
  operator surface instead of requiring operators to enter through Threats.
  Browser smoke opens the direct route, verifies profile/runtime/package/
  exception sections, stages Detect and Disable from the route, and confirms
  running policy isolation.
- Changes route-backed version drawers now preserve `version` query state, so
  `#/changes?tab=versions&version=...&drawer=diff|rollback` opens the intended
  diff or rollback review. Browser smoke now proves candidate review, diff,
  dry-run acknowledged API commit, route-backed version diff, rollback review,
  dry-run acknowledged API rollback, audit evidence, and candidate cleanup
  across desktop, tablet, and mobile. On runtime-ready hosts the same smoke path
  clicks the UI commit/rollback buttons; on dry-run not-ready hosts it verifies
  the UI blocks live apply and uses acknowledged API calls to prove the durable
  lifecycle.
- Changes ready-runtime UI apply proof now has stable browser hooks and an
  opt-in strict smoke gate. The commit candidate action, commit/rollback drawer
  comment, acknowledgement, submit controls, and audit handoff actions expose
  selectors for automation. When `WEBUI_SMOKE_REQUIRE_CHANGES_UI_APPLY=1` is
  set, visual smoke fails instead of falling back to direct API commit/rollback
  calls if the UI buttons are disabled.
- Changes import/export backup workflow now has browser-required restore proof.
  The smoke downloads the real `Export running` policy envelope, downloads the
  committed version-row `Export` artifact, validates the
  `phragma.policy.export.v1` schema, source/version metadata, filename shape,
  committed policy marker, and secret-like text guardrails, imports a modified
  export envelope through `Import to candidate`, proves preview is
  non-mutating, stages the import, verifies the change is candidate-only and
  visible in candidate status/review, and restores the candidate before the
  commit/rollback lifecycle smoke continues.
- Routing & VPN now has a guided WireGuard branch-rollout workflow that stages a
  new interface, peer, and matching static route as one candidate-only action.
  The browser smoke drives the actual drawer, rejects invalid WireGuard public
  key shape before staging, proves the running policy is untouched, opens the
  route-backed tunnel handoff for the newly staged peer, verifies candidate
  Explain/Capture/Sessions pivots, checks peer-template copy/export redaction,
  and now proves a WireGuard enrollment bundle path. The enrollment panel lets
  operators enter the non-secret firewall public endpoint and firewall public
  key, renders an offline SVG QR code from the exact same QR-ready client
  config, and supports copy/export of the text plus SVG QR export with
  `PrivateKey = <client-private-key>` preserved as a placeholder; smoke coverage
  verifies the supplied endpoint/key appear in copied/exported enrollment
  artifacts, the QR preview/export is labeled and bounded on desktop/tablet/mobile,
  and managed key paths, secret field names, bearer/token strings, and real
  private keys do not leak. The direct IPsec and WireGuard editors now also reject
  malformed names, CIDRs, endpoint/config-token values, managed secret/key
  paths, WireGuard endpoint `host:port`, and port/keepalive ranges inline before
  candidate mutation; unit coverage pins parity with policy validation and the
  browser smoke proves invalid direct-editor submissions keep the candidate
  unchanged.
- Routing & VPN dynamic routing editors now have browser-required
  candidate-only proof. The smoke opens the BGP and OSPF drawers, stages a BGP
  local ASN, router ID, neighbor, description, and announced prefix, stages an
  OSPF router ID plus area networks, verifies the candidate `routing.bgp` and
  `routing.ospf` payloads, checks the rendered panels for the staged values,
  proves malformed router ID / area input is rejected inline before candidate
  mutation, while unit coverage verifies ASN, peer address, CIDR, OSPF area,
  and description control-character parity with policy validation,
  stages BGP and OSPF disabled through the confirmation drawers, checks the
  rendered disabled posture plus candidate-edit markers, opens candidate review
  to confirm the dynamic-routing risk explanation, and confirms the running
  policy remains unchanged before commit.
- Routing & VPN evidence tables now use shared responsive table primitives for
  static routes, BGP peer/runtime rows, and tunnel path checks. The converted
  rows carry mobile `data-label` values through `labeledCell`, use shared
  action-column classes instead of per-cell right-alignment styles, and expose
  stable `data-netvpn-action` hooks for route edit/delete and tunnel
  Inspect/Explain/Capture/Sessions actions while preserving the existing
  candidate-only staging and route-pivot behavior.
- Routing & VPN IPsec tunnel rows now use the same shared table primitives as
  the other Net/VPN evidence tables. IPsec name, peer, CIDR, mode, and action
  cells render through `labeledCell`, the action column uses the shared
  `actions-col`/`cell-actions` hooks, and Inspect/Edit/Delete buttons expose
  stable `data-netvpn-action` selectors without changing candidate-only tunnel
  staging behavior.
- Settings telemetry/SIEM export workflow now has browser-required proof. The
  smoke opens the route-backed Telemetry panel, rejects ClickHouse endpoints
  with URL userinfo or sensitive query tokens, stages ClickHouse retention plus
  local JSON file and remote JSON SIEM exports to the candidate only, verifies
  running policy isolation, and exercises telemetry evidence copy, JSON export,
  and Investigation pinning with credential/redaction checks. The Telemetry
  evidence panel now also has an operator-attached SIEM receiver-proof drawer
  for remote JSON streams: operators can enter receiver target/protocol, proof
  window, observed event count, sample event hashes, receiver commands, and
  notes, then copy, export, or pin a redacted evidence packet that explicitly
  records the browser-local unsigned custody boundary and that passive status
  did not dial the SIEM.
- Settings telemetry, network MTU, and access posture inventory tables now use
  shared responsive evidence-table primitives. The Telemetry capability matrix,
  Network per-interface MTU editor, and Access posture inventory render through
  `responsiveTable` and `labeledCell` with stable
  `settings-telemetry-capability-table`, `settings-interface-mtu-table`, and
  `settings-access-inventory-table` hooks, preserving the existing telemetry
  staging, network candidate-only, and access lifecycle workflows. Browser smoke
  verifies classes, labels, mobile labels, and overflow inside the exercised
  route-backed Settings panels.
- Settings access lifecycle now has browser-required authenticated proof. The
  smoke starts `controld` with a temporary private local-users file and admin
  token, opens the route-backed Access panel, validates a node-local OIDC
  rollout drawer with issuer/client/redirect/scope/proxy/secret-file inputs,
  proves break-glass local-admin readiness is part of the rollout decision,
  copies and exports redacted OIDC rollout evidence, and now exposes canonical
  API-backed save/disable controls for the node-local OIDC provider lifecycle
  with required audit comments. `ngfwctl access oidc provider
  show|validate|set|disable` now provides matching CLI coverage for the same
  provider lifecycle. Backend and CLI tests prove provider validation, runtime
  authenticator replacement, access-config persistence, disable,
  session-lookup updates, redacted audit/API responses, ack/comment enforcement,
  and redacted CLI output. The SAML rollout drawer now has audited
  save/disable provider controls too; it preserves prefilled IdP/SP metadata
  posture, keeps certificate fingerprint material write-only after save,
  exposes the disabled-provider control only after persisted configuration, and
  the route-backed Settings smoke verifies save, redacted read-back, reopen
  prefill, disable confirmation, and disabled read-back across desktop, tablet,
  and mobile. The same smoke
  creates a local operator user, verifies the one-time token works, changes the
  role to viewer, rotates the token and proves the old token is rejected,
  disables the user and proves the rotated token is rejected, and checks that
  access inventory and page text do not expose generated bearer tokens.
- Settings access governance tables now use shared responsive table primitives
  for active browser SSO sessions, local user inventory, the access-governance
  workflow matrix, OIDC/SAML/preflight checks, and RBAC role preview. Session
  revoke and local-user role/rotate/disable action cells use shared
  action-column classes while retaining stable `data-access-action` hooks for
  the existing browser lifecycle smoke; mobile rows now get the same
  `labeledCell` treatment as other production workbenches. Browser smoke
  verifies the access governance and role-preview tables on the route-backed
  Access panel plus the rollout preflight table inside the OIDC drawer.
  The shared session administration surface now consistently describes active
  inventory and revoke flows as browser SSO sessions rather than OIDC-only
  sessions, while preserving provider-specific OIDC/SAML lifecycle language
  and compatibility wire fields. The SAML rollout drawer no longer claims
  runtime activation is blocked when the backend reports runtime-ready SAML;
  ready/review plans now guide operators to save the provider and run a
  controlled SAML test login when a login URL is present. Remote validation on
  `139.87.66.128` passed
  focused apiserver/authz/CLI session and provider tests, Settings access and
  automation-context JS tests, `make webui-check`, and Playwright
  `WEBUI_SMOKE_PATHS=/settings` across desktop, tablet, and mobile.
- Settings network and host-input controls now have browser-required candidate
  proof. The smoke seeds a minimal management/LAN policy, applies the
  Internet/VPN edge network profile through the real Settings panel, stages
  per-interface and management-only MTU overrides plus offload posture,
  verifies the change is candidate-only, then opens Host input, proves default
  drop is blocked until SSH/WebUI management coverage exists, stages the
  management allow rule through the real drawer, stages default-deny host input,
  checks the visible coverage posture, and confirms the running policy remains
  untouched.
- API/CLI context is now browser-proven on representative mutable routes. The
  smoke opens the global `API / CLI context` drawer from Settings telemetry and
  Threat exception lifecycle routes, verifies visible route state, REST endpoint
  and `ngfwctl` parity cues, copies the context through the real drawer action,
  and checks both drawer and clipboard text for bearer-token, URL-credential,
  query-secret, and local-path disclosure. The visible route-state label and
  copied route-filter format now match.
- API/CLI context now includes a copyable Workflow runbook for policy workspaces.
  The runbook orders inspect, stage candidate, status, validate, diff, commit,
  and rollback/discard review steps with matching REST and `ngfwctl` commands;
  route state is sanitized before drawer display or clipboard copy. Browser
  smoke proves the runbook from the staged Settings network workflow.
- Filtered Traffic and Threats API/CLI context now has browser-required proof.
  The smoke opens the global API/CLI drawer from flow, session, App-ID queue,
  and Threat-ID alert filter routes and verifies copied REST plus `ngfwctl`
  commands match the active hash state without exposing UI-only sort/selection
  keys as API filters. A future cleanup can extract the duplicated pure
  telemetry request/CLI builders into a shared module; importing the large view
  modules directly into automation context would create an ES module cycle.
- Threat exception lifecycle routes now have selected-record API/CLI parity.
  `#/threats?view=exceptions` exposes the exception inventory endpoint and
  `ngfwctl threat-exceptions list`, while
  `#/threats?view=exceptions&exception=<name>` includes update, enable/disable,
  remove, validate, and diff REST/CLI equivalents. The route-backed exception
  detail drawer exposes its own `API / CLI` action, and browser smoke proves
  copied workflow-session JSON keeps the selected exception route, lifecycle
  endpoints, `ngfwctl threat-exceptions ...` commands, redaction, and unsigned
  browser-local custody boundary across desktop, tablet, and mobile.
- `ngfwctl policy references` now exposes the same reverse object-reference
  blast-radius evidence used by the Objects workbench. Operators can inspect
  zones, addresses, services, applications, and security profiles across
  running, candidate, or versioned policies, with optional JSON output for
  runbooks and automation. The Objects Security Profile Impact Workbench layers
  that reference evidence with rule inspection coverage so operators can review
  affected allow/drop rules and IPS fail-closed posture before commit. Object
  rename review now uses a pure dependency model and grouped drawer rows for
  security rules, host-input rules, IDS exceptions, source NAT, and destination
  NAT before rewriting supported candidate references. The grouped rename rows
  now show both the operator label and canonical policy area key so service
  rename review preserves `security rule` and `destination NAT` dependency
  evidence before candidate rewrite.
- Troubleshoot running-vs-candidate path comparison now has browser-required
  route proof. The smoke stages a candidate-only rule that intentionally flips a
  unique tuple verdict, opens `#/troubleshoot?...&intent=compare&run=1`, verifies
  autorun preserved the tuple fields, confirms verdict and matched-rule deltas
  in the side-by-side compare grid, and proves the running policy is unchanged.
- Performance benchmark evidence review now has browser-required verifier
  coverage. The smoke uploads deterministic summary, raw iperf3, and runtime
  status artifacts through the local-only Performance route, proves duplicate
  directory artifacts and oversized summary/iperf/status/nft artifacts are
  rejected before browser `File.text()` reads, and keeps `ngfwperf` plus
  `internal/perfreport` on matching bounded artifact reads and ambiguous
  status/nft rejection before release verification or staging. It also proves
  summary-only warnings and strict-mode blocking, verifies a publishable
  fully-inspected evidence set with matching throughput/status artifacts,
  checks live `/v1/system/status` evidence labeling, validates mismatched raw
  iperf throughput and target IP are blocked with repair guidance, proves the
  copy buttons for the `ngfwctl status` and `ngfwperf verify` repair commands,
  and confirms Clear returns the verifier to an empty state without API-side
  benchmark data upload. Performance now also includes a benchmark collection
  runbook panel before artifact review. It exposes local netns and three-host
  field workflows, required raw artifacts, measured-window guardrails, release
  benchmark commands, and copyable sanitized command handoffs while keeping the
  boundary explicit: benchmark artifacts are reviewed locally in the browser
  and are not uploaded to `controld`.
- Shared WebUI evidence primitives now cover chart bars and System Logs mobile
  table labels. Horizontal bar charts use shared CSS primitives, CSS custom
  properties for dynamic width/color, and progressbar semantics instead of
  injected style blocks or direct width/background assignment. The System Logs
  evidence table moved fixed desktop widths into CSS classes and now supplies
  `data-label` values for Time, Source, Engine, Severity, Message, and File so
  mobile responsive cards remain self-describing.
- System Logs table rendering now uses the shared `responsiveTable` and
  `labeledCell` primitives instead of hand-rolled table markup, and the log
  export anchor no longer uses inline display styling. Message and file cells
  have dedicated layout hooks, with browser-required proof that filtered log
  rows preserve exact labels, responsive table classes, mobile label rendering,
  and page-level overflow containment.
- Traffic evidence tables now use the shared responsive table primitives for
  flow, session, and App-ID observation rows. The inline action-cell alignment
  was removed in favor of `actions-col` and `cell-actions`, then the hand-built
  table/header/cell markup was replaced with `responsiveTable` and
  `labeledCell` while preserving keyboard row activation, Explain/App-ID/
  Allow/Drop buttons, App-ID observation review actions, and API/CLI context
  parity. Static WebUI tests pin all three table conversions, and browser smoke
  verifies responsive classes, labels, clickable row accessibility, mobile
  labels, and overflow for filtered flows and App-ID observations while
  accepting that live session rows are absent on dry-run hosts without conntrack
  data. The shared API/CLI context drawer also has a footer `Cancel` action so
  selected Traffic/App-ID context review has a predictable non-copy exit path.
- Threats severity facets and alert evidence rows now use shared CSS hooks
  instead of per-node table/facet styles. Severity tiles expose stable
  `data-threat-facet` and `aria-pressed` state, the alert table keeps responsive
  `data-label` values for every cell, and Threat-ID/time alignment is handled
  through `threat-id-cell` and `cell-time` classes with mobile wrapping proof.
- Changes version history now uses the shared responsive evidence-table
  primitives. Version, comment, recovery, actor, time, and action cells render
  through `labeledCell`, the table uses the `changes-version-table` responsive
  class, and Diff/Export/Roll back buttons expose stable `data-changes-action`
  hooks. Browser smoke verifies responsive labels, action tap targets, and
  overflow containment after a real candidate commit.
- Readiness host-tuning preview/apply result drawers now use the shared
  responsive evidence-table primitives. Key, value, state, and detail cells
  render through `labeledCell`, the result table uses the
  `readiness-tune-result-table` responsive class, and the baseline/throughput
  review actions expose stable `data-readiness-action` hooks. Browser smoke
  opens the real baseline preview drawer and verifies responsive labels, mono
  key/value cells, and drawer overflow containment.
- Intel content-package sample drawers now use the shared responsive
  evidence-table primitives. Corpus browser rows, evidence artifact sample
  summaries, and package-preview corpus diffs render through `responsiveTable`
  and `labeledCell`, with stable row hooks for corpus, evidence, and diff
  samples. Browser smoke opens the real content quality/evidence/corpus drawers
  and verifies responsive classes, `data-label` values, row hooks, mobile labels,
  filtering, and drawer overflow containment.
- Intel custom-feed and feed-registry tables now use the shared responsive
  evidence-table primitives. Custom feed rows keep their add/edit/delete action
  hooks while using `intel-custom-feed-table`, `labeledCell`, clipped URL cells,
  and shared action alignment. The main feed registry uses
  `intel-feed-registry-table` with responsive On/feed/license/commercial/kind
  and status cells while preserving built-in feed toggle hooks. Browser smoke
  proves the converted tables during the real feed-governance candidate workflow,
  including row hooks, action cells, mobile labels, and built-in toggle selectors.
- Dashboard compact evidence tables now use the shared responsive
  evidence-table primitives. Engine coverage, recent threats, and recent
  changes render through `responsiveTable` and `labeledCell`, with stable
  `dashboardEngine`, `dashboardThreat`, and `dashboardVersion` row hooks plus
  shared clipped/wrapped cell utilities instead of inline truncation and
  alignment styles. Browser smoke verifies the first-screen Dashboard tables,
  labels, row hooks, and mobile labels while preserving the seeded App-ID and
  threat evidence checks; the smoke also verifies the recent-changes empty state
  when the seeded API has no committed versions to render.
- Changes audit log entries now use the shared responsive evidence-table
  primitives. Audit rows keep keyboard activation and route-backed drawer
  behavior while rendering through `responsiveTable` and `labeledCell`, with
  stable `data-audit-entry-row` hooks, wrapped detail cells, and no inline
  width/alignment styles. Browser smoke verifies the filtered audit table,
  labels, clickable row accessibility, mobile labels, and overflow before
  exercising filtered-log copy/export and route-backed entry drawers.
- Hidden WebUI download anchors now use the shared `download-anchor-hidden`
  utility instead of per-call inline `display: none` styles across evidence
  toolbar exports, API/CLI context downloads, support bundles, policy export,
  investigation handoffs, NAT, Net/VPN, Traffic, Threats, Objects, Changes,
  Readiness, Intel, and Settings export paths. A static WebUI test now rejects
  the old inline hidden-anchor pattern.
- Intel feed governance now has browser-required candidate-only proof. The
  smoke declares commercial use, stages refresh interval changes, adds, edits,
  and deletes a custom feed through the real drawer, toggles a built-in feed,
  verifies candidate status and Changes risk text, and confirms the running
  policy remains unchanged before commit.
- Saved filter lifecycle is now browser-proven for the Traffic, Threats, and
  Changes audit workbenches. The smoke saves workstation-local filter presets,
  verifies persisted state excludes transient drawer/row route keys, reapplies
  the saved filters through the route-backed UI, deletes them, and returns each
  workbench to its baseline route before continuing.
- Changes audit now has browser-required filtered-log export proof. The audit
  workbench can pin, copy, and download a bounded `audit-log` investigation
  packet for the current route-backed filters, including request context,
  included entries, action summary, entry hashes, and audit-integrity state,
  while preserving existing per-entry handoff drawers and redaction checks. It
  also has a browser-local `Audit report builder` drawer for
  `#/changes?tab=audit&drawer=report` that emits
  `phragma.audit.report.v1` JSON with normalized/redacted filters,
  `/v1/audit` replay context, `ngfwctl audit ... --hashes`, integrity summary,
  included entry hashes, bounded visible entries, and an explicit unsigned
  non-custody boundary.
- Changes candidate review now has a browser-local governance review packet for
  `#/changes?drawer=governance-approval`. The packet is derived from the same
  candidate validation, runtime preflight, impact, diff, and change-summary
  evidence used by the commit review, can be pinned/copied/exported as a
  bounded `governance-approval` investigation handoff, and explicitly labels
  server-side approval records, identity enforcement, signed custody, and
  commit gating as hardening work. Browser smoke proves the drawer before
  commit mutates running policy, verifies route reload, leak guards, JSON
  export, plain-text copy, case pinning, and candidate/running non-mutation on
  desktop, tablet, and mobile.
- Active/passive HA policy replication functional coverage has been revalidated
  on the remote Linux host. Apiserver tests prove successful passive-node pull
  from an active peer policy, version metadata, audit records, candidate
  cleanup, dirty-candidate rejection before peer fetch, preservation of
  operator candidate/running state if a candidate is staged during peer fetch,
  and automatic passive replication success/blocker status. `controld` now has
  passive-only automatic replication flags, validates peer URL/token/interval
  requirements, and starts a nonfatal background loop that applies only newer
  active-peer running policy through the same validated/audited HA pull path.
  WebUI checks prove Readiness exposes automatic replication state in the HA
  card, evidence packet, and operations cockpit while retaining manual resync
  as a guarded recovery action. HA status promotes clean active/passive
  evidence to functional `ready`: fresh opposite-role heartbeat, matching
  policy version/artifact evidence, configured peer address, and
  last-known-good metadata produce ready sync and failover-eligible status.
  Missing LKG, stale heartbeat, same-role peers, policy drift, identity
  mismatch, absent peer evidence, or failed replication attempts remain
  degraded/blocking evidence. `ngfwctl status` now includes the HA automatic
  replication state, peer/local replicated version pair, last attempt/success,
  and last error alongside sync/failover state, and the stale pre-replication
  "not implemented" fixture wording is covered by a regression assertion.
- HA manual activation now preserves the server preflight evidence that made
  activation eligible. The durable node-local HA marker records the preflight
  peer policy version, peer artifact hash, failover state, and failover
  eligibility while keeping `fencing_claim` and `transport_claim` as
  `not_performed`. Activation rejects same-role peer evidence before any intent
  or success audit is recorded, and the returned post-activation status exposes
  the expected same-role/split-brain blocker plus an external-control warning.
  `ngfwctl system ha activate-passive` now prints preflight detail,
  post-activation check detail, and post-blockers; the Readiness HA operations
  cockpit includes a `Post-activation split-brain review` row and report field
  so operators can see that peer fencing, VIP/route ownership, traffic cutover,
  and connection-state sync remain outside the API.
- HA readiness and recovery is now a first-class release acceptance gate.
  `make ha-readiness-recovery-check` runs the rootless HA API, CLI, daemon
  peer-source, and support-bundle tests and emits required sentinels for
  control-plane recovery evidence. `make release-evidence-ha-readiness-recovery`
  records the gate through `ngfwrelease`, `ha-readiness-recovery` is part of
  the required acceptance manifest, and the release docs explicitly keep peer
  mTLS, VIP/route promotion, fencing, split-brain controls, connection-state
  sync, and live Linux failover in the hardening/field-evidence boundary.
  Readiness now surfaces the gate in the release-evidence strip, exposes a
  route-backed packet at `#/readiness?packet=ha-readiness-recovery`, includes a
  separate HA recovery row in the system evidence packet, and appends
  validate/record fallback commands in the release acceptance drawer even when
  the backend supplies only a single `next_command`.
- Readiness HA operations cockpit now has exact route-backed API/CLI context
  parity. `#/readiness?drawer=ha-cockpit` prepends HA status, manual
  passive-policy pull, and manual activation REST contracts plus matching
  `ngfwctl status`, `ngfwctl system ha pull-policy`, and
  `ngfwctl system ha activate-passive` commands. The cockpit footer exposes its
  own `API / CLI` action, and browser smoke proves copied workflow-session JSON
  and plain-text context preserve the control-plane-only activation boundary:
  VIP/route cutover, peer fencing, connection-state transfer, and token
  rotation remain outside the functional cockpit and in hardening/field
  evidence.
- `ngfwctl system ha status` is now the focused operator handoff for HA cutover
  evidence. It calls the existing read-only HA status API, prints policy sync,
  automatic replication, heartbeat age, failover eligibility, and peer/artifact
  evidence, then emits an explicit cutover plan. Ready output tells operators to
  run `activate-passive` and verify VIP/route ownership, traffic path, peer
  role, and post-activation HA status; blocked output says not to move VIPs or
  routes until server evidence is eligible. The command is intentionally
  read-only and does not move traffic, fence peers, or synchronize connection
  state.
- HA activation now has an optional Linux-local VIP/route promotion primitive
  for bounded production failover ownership. `internal/engines.HAPromotion`
  applies `ip addr replace` for a configured VIP, optional `ip route replace`
  for one promoted route, optional gratuitous ARP, and a managed state file that
  removes only previously OpenNGFW-owned stale VIP/route entries. `controld`
  exposes `--ha-promote-vip`, `--ha-promote-interface`, and optional
  `--ha-promote-route-*` flags; when configured, the System API runs promotion
  after the HA activation intent audit and before durable active-role
  persistence. Promotion failure leaves the node passive and records only the
  intent audit; promotion success persists
  `transport_claim=linux_local_vip_route_promoted`. Peer fencing, automatic
  election, connection-state sync, and live traffic failover evidence remain
  outside this slice. A privileged disposable-netns smoke on the remote Linux
  validation host proved the exact primitives with `ip addr replace
  192.0.2.10/32 dev ha0` and `ip route replace 198.51.100.0/24 dev ha0 src
  192.0.2.10 metric 50`; full activation-driven traffic failover evidence is
  still deferred.
- HA activation-driven VIP/route promotion now has live Linux integration
  proof. `TestHALiveActivationPromotesVIPAndRoute` creates a disposable dummy
  interface, builds an in-process passive `SystemService` with fresh active-peer
  evidence and a real `engines.HAPromotion`, calls
  `ActivateHighAvailabilityFailover`, and verifies the API response, durable HA
  state, intent/success audit records, kernel VIP, kernel route source/metric,
  and managed `ha-promotion.state`. The proof uses documentation prefixes and
  does not start `controld` or claim peer fencing, automatic election, GARP
  convergence, connection-state transfer, production custody, or multi-node
  traffic cutover.
- App-ID signal-only deny now has live NFQUEUE field proof on the remote Linux
  validation host. The privileged M2 netns integration test first commits an
  IPS Prevent fail-closed baseline and proves HTTP forwarding still returns
  `pong`, then commits a broad `web-browsing` App-ID deny backed by the
  Suricata `http` engine signal and proves the HTTP flow is blocked. The test
  asserts the live nftables table queues to NFQUEUE 0 without `bypass`, the
  generated managed rule carries SID `4200001`, `app-layer-protocol:http`, and
  `openngfw_rule block-web-browsing`, and EVE records a blocked alert for the
  App-ID rule. This proves the supported HTTP signal-only deny path; broader
  App-ID allow/block breadth, first-packet leakage disclosure, NFQUEUE
  saturation/crash behavior, durable SID governance, package/corpus custody,
  and zone/interface parity remain hardening and product-breadth work.
- API/CLI context now has a browser-local multi-route automation recorder. The
  recorder lives inside the route-aware API/CLI drawer, can start/stop/clear in
  browser storage, records the current view as a redacted workflow-session
  packet, and copies/downloads an aggregate
  `phragma.webui.automation-recorder.v1` JSON packet. It intentionally records
  route context, REST endpoints, CLI commands, and workflow steps rather than
  intercepting low-level authenticated API traffic; the packet declares
  browser-local, unsigned, not-server-stored custody.
- Packet-capture lifecycle coverage has been revalidated on the remote Linux
  host. Apiserver tests cover bounded planning, start acknowledgement/dry-run
  rejection, completed capture metadata, list indexing, download safety,
  retention retain/release metadata, validation, sidecar safety, and audit
  behavior. CLI tests cover plan/start/list/download/retain/release request
  shaping and output. A privileged OL9 loopback integration test captured real
  traffic with `tcpdump`, and browser smoke continues to prove Troubleshoot
  capture planning/correlation and WebUI evidence artifacts. Traffic/Threat
  capture pivots now preserve `intent=capture` through Troubleshoot autorun, so
  the global API/CLI context can copy exact `/v1/system/packet-captures/plan`,
  guarded `/v1/system/packet-captures`, and matching `ngfwctl system capture`
  commands for the visible tuple, limits, flow ID, and capture controls.
- Release acceptance status now has direct appliance CLI/API parity. `ngfwctl
  system release-acceptance-status [--json]` reads
  `/v1/system/release-acceptance/status` and prints manifest posture, evidence
  directory, summary counts, recordability advisory, problems, per-check
  status, recorded command, next action, and next command. The Readiness API/CLI
  context drawer now offers the new `ngfwctl` command as the appliance
  equivalent while retaining `make release-acceptance-status` and
  `ngfwrelease` as source-tree release-engineering tools. Disclosure boundaries
  for manifest paths, evidence paths, dirty source paths, and command text
  remain tracked in the hardening backlog.
- Dashboard now has a summary-only release-readiness launchpad backed by
  `/v1/system/release-acceptance/status` plus candidate status. It shows the
  release state, generated freshness, passed/recorded/missing/invalid/todo/not
  applicable counts, first actionable gate link into
  `#/readiness?packet=...`, the Readiness release drawer link, Rules
  changed-only remediation pivot, and dirty-candidate Troubleshoot
  running-vs-candidate compare pivot. The card intentionally does not render
  manifest paths, evidence directories, evidence paths, dirty source paths,
  command arguments, copied full reports, or per-check problem text; that
  summary-only boundary is now tracked in the hardening backlog.
- Dashboard automation context now mirrors the first-screen APIs and CLI
  equivalents that operators need for headless parity: runtime status,
  identity, release-acceptance status, and candidate dirty-state. `ngfwctl
  policy status [--json]` now exposes `/v1/candidate/status` from the CLI,
  including staged/dirty state, running version, section change counts, and
  impact summary.
- The global API Diagnostic Console now has browser-required proof from the
  Dashboard route and command palette. It collects version, runtime status,
  identity, release-acceptance summary, candidate status, sessions, and audit
  through public APIs; renders read-only `ngfwctl` command blocks; supports
  copy, refresh, Escape close, and focus return; and keeps copied diagnostic
  snapshots summary-only for release evidence and candidate state.
- Shared WebUI keyboard and drawer focus behavior now has focused browser
  regression proof. The global command palette is validated for shortcut open,
  input focus, `aria-activedescendant` arrow navigation, Tab containment,
  Escape close, and opener focus return. The shared drawer primitive preserves
  the original opener when one drawer replaces another drawer, exposes
  dialog/modal labeling, traps Tab inside the drawer, closes on Escape, and
  restores focus to the toolbar opener. Targeted browser smoke now covers the
  Dashboard, Rules, Threats, Traffic, and Changes drawer-heavy routes across
  desktop, tablet, and mobile.
- Rules deep links for `#/rules?rule=...` now visibly mark the matching row
  while preserving the existing editor-opening behavior, and mobile rule cards
  wrap long generated object/rule names without widening the viewport.
- Rules manual lifecycle now has browser-required candidate-only proof. The
  smoke drives Add, Edit, Duplicate, Insert below, Delete, drag reorder, and
  explicit Move up/down row actions through the real row controls and editor
  drawer, verifies staged candidate rule payloads and order after each step,
  and confirms the running policy is unchanged before commit.
- Rules review clipboard/runbook context now matches the actual `ngfwctl`
  candidate workflow. Changed-rule verification, bulk tag, and bulk action
  drawers copy `ngfwctl policy status --json`, `ngfwctl policy validate`, and
  `ngfwctl policy diff` instead of obsolete flags; changed-rule verification
  also includes the candidate explain-flow command. Bulk review context now
  includes visible/hidden/no-op/blocked counts plus selected rule positions,
  names, visibility, and before/after intent so operators can paste a concrete
  rule review packet into change records before staging. Browser smoke copies
  both changed-rule and bulk-tag review context, opens a route-backed
  `#/rules?density=compact&group=tag&drawer=bulk-disable` bulk review with the
  selected visible rules restored from URL state, and rejects the invalid
  legacy command forms.
- Rules changed-rule verification smoke now rejects verification execution
  errors instead of accepting any completed state. The cleanup workflow
  requires no `error` items and at least one verified concrete changed rule
  such as `allow-web` or `drop-ssh` before the candidate diff/discard proof
  continues; mismatch or tuple-review results remain visible for operator
  review instead of being hidden by the smoke.
- Rules mobile action-column proof now checks the row action surface directly.
  Browser smoke verifies each visible mobile rule row exposes the expected
  Explain, Capture, Move up/down, Edit, Duplicate, Insert below, and Delete
  icon actions with contained tap targets and no horizontal overflow; the
  responsive source test also pins the stable row-action selectors and mobile
  action-cell layout.
- Traffic selected App-ID observations now expose route-accurate API/CLI
  context directly from the observation drawer. The selected queue-item context
  shows the exact `POST /v1/app-id/observations/{queueId}:stage` endpoint plus
  the matching `ngfwctl app-id promote ...` define-only and reviewed-drop
  commands, and browser smoke proves both the route-level context and the
  in-drawer action without leaking token/path material.
- NAT path preview handoff actions now have browser-required proof from the
  published-service workflow. The smoke clicks Copy link, Pin to case, Export
  handoff, and Open in Troubleshoot; verifies the replay hash, pinned
  `nat-path` case packet, downloaded `phragma.investigation.handoff.v1` JSON,
  and candidate compare route; and checks copied/exported/pinned route text for
  token/path disclosure.
- Rules inspection coverage now has browser-required policy-visible bypass
  proof. The smoke seeds an IPS prevent fail-open candidate, verifies the Rule
  cleanup queue exposes bypass-risk allows, filters to the risky allow path,
  checks the per-rule inspection state and fail-open detail, pivots directly to
  Inspection, and confirms the fail-open candidate does not mutate the running
  policy.
- Shared WebUI row activation and drawer containment were hardened after
  browser-required visual smoke found Threat exception rows that would not open
  from direct row clicks and a prefilled Traffic-to-rule drawer overflow.
- The privileged OL9 integration harness now adapts to Oracle Linux firewalld,
  Nmap Ncat, FRR daemon paths, FRR foreground behavior, and Suricata package
  availability so live dataplane tests exercise the intended paths instead of
  skipping or failing on host-layout differences.

Do not present this as full App-ID allow-by-application dataplane semantics.
Current enforceable App-ID rules remain bounded to the implemented port-hint
drop path. Broader App-ID enforcement is a later dataplane/product milestone.

Supersession note: later App-ID slices added a bounded Suricata signal-only
deny path plus scoped App-ID pass/drop metadata controls and route-backed
Traffic review/drop evidence. The product boundary is still not proxy-grade
allow-by-application enforcement, but the older wording above is narrower than
the current functional surface.

## Validation State

Most recent authoritative validation was run on the remote Oracle Linux host
`opc@139.87.66.128`; full local test suites were intentionally not run because
the active instruction is to validate on Linux only.

Additional remote validation for the release-acceptance CLI/API context parity
slice:

- `node --check internal/webui/static/js/automation_context.js`
- `node internal/webui/static/js/automation_context.test.mjs`
- `go test -count=1 ./internal/cli -run ReleaseAcceptance`
- `make webui-check`
- `TMPDIR=$PWD/.tmp WEBUI_SMOKE_REQUIRE_BROWSER=1
  WEBUI_SMOKE_PATHS=/readiness
  WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-release-acceptance-cli-r2
  make webui-visual-smoke`

Additional remote validation for the Dashboard release-readiness launchpad
slice:

- `node --check internal/webui/static/js/views/dashboard.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node internal/webui/static/js/dashboard_management.test.mjs`
- `make webui-check`
- `TMPDIR=$PWD/.tmp WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/
  WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-dashboard-release-readiness-r1
  make webui-visual-smoke`
- `TMPDIR=$PWD/.tmp WEBUI_SMOKE_REQUIRE_BROWSER=1
  WEBUI_SMOKE_PATHS=/,/readiness,/rules,/troubleshoot
  WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-release-readiness-flow-r1
  make webui-visual-smoke`

Additional remote validation for the Dashboard automation and candidate-status
CLI parity slice:

- `node --check internal/webui/static/js/automation_context.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node internal/webui/static/js/automation_context.test.mjs`
- `go test -count=1 ./internal/cli -run "PolicyStatus|PolicyCommandIncludesStatus"`
- `make webui-check`
- `TMPDIR=$PWD/.tmp WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/
  WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-dashboard-automation-context-r2
  make webui-visual-smoke`

Additional remote validation for the global API Diagnostic Console release and
candidate evidence slice:

- `node --check internal/webui/static/js/diagnostic_console.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node internal/webui/static/js/diagnostic_console.test.mjs`
- `node internal/webui/static/js/command_palette.test.mjs`
- `make webui-check`
- `TMPDIR=$PWD/.tmp WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/
  WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-diagnostic-release-candidate-r1
  make webui-visual-smoke`

Additional remote validation for the shared keyboard/focus workflow slice:

- `node --check internal/webui/static/js/ui.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/ui_accessibility.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-keyboard-focus/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-keyboard-focus/.tmp/openngfw-webui-smoke-keyboard-focus-r1
  make webui-visual-smoke`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-keyboard-focus/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1
  WEBUI_SMOKE_PATHS=/,/traffic,/threats,/rules,/changes
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-keyboard-focus/.tmp/openngfw-webui-smoke-keyboard-focus-routes-r1
  make webui-visual-smoke`

Additional remote validation for the Rules review clipboard/runbook CLI parity
slice:

- `node --check internal/webui/static/js/views/rules.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node internal/webui/static/js/rules_bulk_density.test.mjs`
- `go test -count=1 ./internal/cli -run "PolicyStatus|PolicyCommandIncludesStatus|PolicyDiff"`
- `make webui-check`
- `TMPDIR=$PWD/.tmp WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/rules
  WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-rules-cli-parity-r1
  make webui-visual-smoke`

Additional remote validation for the Rules bulk review-context and mobile
action-column proof slice:

- `node --check internal/webui/static/js/views/rules.js`
- `node --check internal/webui/static/js/rules_bulk_density.test.mjs`
- `node --check internal/webui/static/js/rules_table_responsive.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/rules_bulk_density.test.mjs`
- `node internal/webui/static/js/rules_table_responsive.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-rules-review-context/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/rules
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-rules-review-context/.tmp/openngfw-webui-smoke-rules-review-context-r1
  make webui-visual-smoke`

Additional remote validation for the Rules route-backed bulk review and changed
verification proof slice:

- `node --check internal/webui/static/js/views/rules.js`
- `node --check internal/webui/static/js/rules_bulk_density.test.mjs`
- `node --check internal/webui/static/js/rules_table_responsive.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/rules_bulk_density.test.mjs`
- `node internal/webui/static/js/rules_table_responsive.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-rules-route-bulk/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/rules
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-rules-route-bulk/.tmp/openngfw-webui-smoke-rules-route-bulk-r7
  make webui-visual-smoke`

Additional remote validation for the Traffic App-ID selected API/CLI handoff
slice:

- `node --check internal/webui/static/js/views/traffic.js`
- `node --check internal/webui/static/js/automation_context.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node internal/webui/static/js/automation_context.test.mjs`
- `make webui-check`
- `TMPDIR=$PWD/.tmp WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/traffic
  WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-traffic-appid-context-r1
  make webui-visual-smoke`

Additional remote validation for the NAT path preview handoff action proof
slice:

- `node --check e2e/webui-visual-smoke.mjs`
- `make webui-check`
- `TMPDIR=$PWD/.tmp WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/nat
  WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-nat-preview-handoff-r1
  make webui-visual-smoke`

Passing remote checks from the full remote validation pass before the latest
Investigation workbench slice:

- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 make webui-visual-smoke`
- `make lint`
- `RELEASE_NO_PERFORMANCE_CLAIMS=1 make release-check-rootless`
- privileged `/tmp/openngfw-itest -test.v -test.timeout 420s`, including
  Suricata detect, nftables policy/NAT/rollback, static routing, WireGuard,
  BGP, threat-intel enforcement, network settings, packet capture, proto status
  diagnostics, and release hardening script tests.

Additional remote validation for the latest Investigation workbench slice:

- `node --check internal/webui/static/js/investigation_case.js`
- `node --check internal/webui/static/js/views/investigation.js`
- `node --check internal/webui/static/js/views/rules.js`
- `node --check internal/webui/static/js/views/traffic.js`
- `node --check internal/webui/static/js/views/threats.js`
- `node --check internal/webui/static/js/nat_path_preview.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node internal/webui/static/js/investigation_case.test.mjs`
- `node internal/webui/static/js/investigation_state.test.mjs`
- `node internal/webui/static/js/nat_path_preview.test.mjs`
- `node internal/webui/static/js/rules_bulk_density.test.mjs`
- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-investigation make webui-visual-smoke`

Additional remote validation for the Investigation compare responsive-table
slice:

- `node --check internal/webui/static/js/views/investigation.js`
- `node --check internal/webui/static/js/responsive_tables.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/responsive_tables.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-investigation-compare-table-r1/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/investigation
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-investigation-compare-table-r1/.tmp/openngfw-webui-smoke-investigation-compare-table-r1
  make webui-visual-smoke`

Additional remote validation for the Investigation cockpit API/CLI context
slice on `opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/investigation.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/investigation_view.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/investigation WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-investigation-api-cli-r2 make webui-visual-smoke`

Notes from this slice:

- The smoke opens `[data-investigation-action="api-cli"]`, verifies the
  route-backed API/CLI context drawer, copies workflow-session JSON, copies the
  plain-text context, and applies automation plus Investigation-specific leak
  guards across desktop, tablet, and mobile.
- No new hardening backlog item was added. Existing WebUI handoff/export
  redaction and Investigation/case custody hardening concerns already cover
  production signing, retention, and server-side evidence custody.

Additional remote validation for the runtime content semantic-readiness slice:

- `go test ./internal/contentpkg`
- `go test ./internal/apiserver -run Content`
- `go test -tags integration ./test/integration -run ContentProductionReadiness`
- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-content-semantic make webui-visual-smoke`

Additional remote validation for the Object/NAT publish-service workflow slice:

- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-object-nat-r2 make webui-visual-smoke`

Additional remote validation for the NAT path-delta responsive-table slice:

- `node --check internal/webui/static/js/views/nat.js`
- `node --check internal/webui/static/js/responsive_tables.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/responsive_tables.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-nat-path-delta-table-r1/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/nat
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-nat-path-delta-table-r1/.tmp/openngfw-webui-smoke-nat-path-delta-table-r1
  make webui-visual-smoke`

Additional remote validation for the Source NAT lifecycle slice:

- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/nat WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-snat-lifecycle-r1 make webui-visual-smoke`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-snat-lifecycle-full-r1 make webui-visual-smoke`

Additional remote validation for the Traffic App-ID review-drop-rule slice:

- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-appid-rule-review make webui-visual-smoke`

Additional remote validation for the App-ID observation queue promotion slice:

- `make webui-check`
- `go test ./internal/apiserver -run AppID`
- `go test ./internal/cli -run AppID`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-appid-queue-promotion-r1 make webui-visual-smoke`

Additional remote validation for the App-ID port-hint enforcement and Objects
hygiene slice:

- `node --check internal/webui/static/js/views/objects.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --check internal/webui/static/js/rules_editor.test.mjs`
- `node --check internal/webui/static/js/appid_observations.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/object_references.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/rules_editor.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/appid_observations.test.mjs`
- `go test -count=1 ./internal/apiserver -run "AppIDServerStage"`
- `go test -count=1 ./internal/policy -run "Validate.*application|TestValidate"`
- `node --check internal/webui/static/js/views/traffic.js`
- `node --check internal/webui/static/js/views/rules.js`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/objects WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-objects-appid-hygiene-r1 make webui-visual-smoke`

Additional remote validation for the Guided Setup baseline parity slice:

- `make webui-check`
- `go test ./internal/cli -run "Baseline|NetworkProfile"`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-guided-setup-r1 make webui-visual-smoke`

Additional remote validation for the Guided Setup scenario-template slice:

- `node --check internal/webui/static/js/views/setup.js`
- `node --check internal/webui/static/js/setup.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/setup.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/setup WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-guided-setup-scenarios-r3 make webui-visual-smoke`
- No new hardening backlog item was added. Existing candidate workspace,
  Settings network/host-input, IDS/IPS profile, VPN peer template/secret
  lifecycle, and privileged runtime evidence rows cover the remaining
  production-hardening boundaries exposed by these functional presets.

Additional remote validation for the Guided Setup archetype review and exact
API/CLI context slice on `opc@139.87.66.128`:

- `node --check internal/webui/static/js/setup_context.js`
- `node --check internal/webui/static/js/views/setup.js`
- `node --check internal/webui/static/js/setup.test.mjs`
- `node --check internal/webui/static/js/automation_context.js`
- `node --check internal/webui/static/js/automation_context.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/setup.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/setup WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-setup-archetype-context-r4 make webui-visual-smoke`

Notes from this slice:

- Guided Setup now renders a deployment-archetype review panel for cloud edge,
  east-west segmentation, VPN edge, IDS tap, and lab scenarios. Each scenario
  states when to use it, what defaults are staged, what the operator must
  review, and what is intentionally not staged.
- API/CLI context from the Guided Setup checklist now preserves the current
  setup route state instead of using a static setup route. The drawer shows the
  scenario, zones, interfaces, CIDR, WebUI port, boolean baseline flags, IDS
  rule-file/queue/failure behavior when applicable, and the exact
  `ngfwctl policy baseline` command matching the visible fields.
- Browser smoke proves IDS tap, east-west, and VPN edge scenario copy and field
  defaults across desktop, tablet, and mobile, including overflow checks and the
  setup-specific API/CLI drawer. The first browser rerun exposed a long-copy
  horizontal overflow and a smoke helper call mismatch; both were fixed before
  the passing `r4` run. One failed rerun also hit remote temporary-disk
  pressure before app startup, so only generated smoke/build artifacts under
  `/home/opc/oss-ngfw-smoke-tmp` were removed before retrying.
- A dedicated Guided Setup archetype field-validation row now tracks the
  remaining production-hardening requirement for supported-topology proof of
  these defaults.

Additional remote validation for the Changes lifecycle and route-backed version drawer slice:

- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-changes-lifecycle-r10 make webui-visual-smoke`

Additional remote validation for the Changes version-history responsive-table
slice:

- `node --check internal/webui/static/js/views/changes.js`
- `node --check internal/webui/static/js/responsive_tables.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/responsive_tables.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-changes-version-table/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/changes
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-changes-version-table/.tmp/openngfw-webui-smoke-changes-version-table-r1
  make webui-visual-smoke`

Additional remote validation for the Readiness host-tuning responsive-table
slice:

- `node --check internal/webui/static/js/views/readiness.js`
- `node --check internal/webui/static/js/responsive_tables.test.mjs`
- `node --check internal/webui/static/js/readiness_view.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/responsive_tables.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/readiness_view.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-readiness-tune-table/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/readiness
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-readiness-tune-table/.tmp/openngfw-webui-smoke-readiness-tune-table-r1
  make webui-visual-smoke`

Additional remote validation for the Intel content responsive-table slice:

- `node --check internal/webui/static/js/views/intel.js`
- `node --check internal/webui/static/js/responsive_tables.test.mjs`
- `node --check internal/webui/static/js/intel_content.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/responsive_tables.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/intel_content.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-intel-content-tables/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/intel
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-intel-content-tables/.tmp/openngfw-webui-smoke-intel-content-tables-r1
  make webui-visual-smoke`

Additional remote validation for the Intel feed responsive-table slice:

- `node --check internal/webui/static/js/views/intel.js`
- `node --check internal/webui/static/js/responsive_tables.test.mjs`
- `node --check internal/webui/static/js/intel_content.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/responsive_tables.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/intel_content.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-intel-feed-tables/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/intel
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-intel-feed-tables/.tmp/openngfw-webui-smoke-intel-feed-tables-r1
  make webui-visual-smoke`

Additional remote validation for the Dashboard compact responsive-table slice:

- `node --check internal/webui/static/js/views/dashboard.js`
- `node --check internal/webui/static/js/responsive_tables.test.mjs`
- `node --check internal/webui/static/js/dashboard_management.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/responsive_tables.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/dashboard_management.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-dashboard-tables/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-dashboard-tables/.tmp/openngfw-webui-smoke-dashboard-tables-r1
  make webui-visual-smoke`

Additional remote validation for the Changes audit responsive-table slice:

- `node --check internal/webui/static/js/views/changes.js`
- `node --check internal/webui/static/js/responsive_tables.test.mjs`
- `node --check internal/webui/static/js/changes_audit.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/responsive_tables.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/changes_audit.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-changes-audit-table/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/changes
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-changes-audit-table/.tmp/openngfw-webui-smoke-changes-audit-table-r1
  make webui-visual-smoke`

Additional remote validation for the Changes audit report builder slice on
`opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/changes.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/changes_audit.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/changes WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-changes-audit-report-r2 make webui-visual-smoke`

Notes from this slice:

- The `/changes` browser smoke opens `[data-audit-action="open-report-builder"]`,
  verifies the route-backed report drawer, copies report JSON, exports report
  JSON, reloads `#/changes?tab=audit&drawer=report`, and applies existing
  investigation/export leak guards across desktop, tablet, and mobile.
- The first browser rerun after the export-click robustness fix hit remote disk
  exhaustion during Go build startup. Removing generated remote smoke/build
  cache artifacts under `/home/opc/oss-ngfw-smoke-tmp` freed space and the clean
  rerun passed.
- No new hardening backlog item was added. Existing WebUI handoff/export
  redaction and Audit retention/export custody rows cover production signing,
  retention, custody, report-storage policy, RBAC policy, and cryptographic
  audit export.

Additional remote validation for the Changes governance review packet slice on
`opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/changes.js`
- `node --check internal/webui/static/js/candidate_review.js`
- `node --check internal/webui/static/js/investigation_packet.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/changes_candidate_review.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/changes WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-governance-approval-r3 make webui-visual-smoke`

Notes from this slice:

- The `/changes` browser smoke opens
  `[data-changes-action="prepare-approval"]`, verifies
  `[data-governance-approval-drawer="true"]`, copies plain-text packet output,
  exports `phragma.investigation.handoff.v1` JSON, pins the packet to the
  investigation case, reloads `#/changes?tab=candidate&drawer=governance-approval`,
  applies the existing token/path leak guardrails, and proves candidate/running
  policy snapshots are unchanged across desktop, tablet, and mobile.
- The first two smoke iterations exposed assertion/evidence wording mismatches:
  the functional packet correctly used the broader hardening boundary wording
  and needed a bounded diff preview so the visible drawer carried the seeded
  candidate change. The third browser-required run passed after those fixes.
- Supersession note: a later change-approval pass added functional server-side
  approval records bound to candidate revision, commit-time approval
  consumption, audit creation events, and Changes UI create/list/select support.
  Production CAB policy, quorum, expiry/revocation, signed custody, retention,
  separation of duties, HA replication, external ticket/CAB integration, and
  stronger step-up binding remain hardening work.

Additional remote validation for the Changes backup/restore import-export slice:

- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-changes-backup-restore-r2 make webui-visual-smoke`

Additional remote validation for the Changes version-specific backup/export
proof on `opc@139.87.66.128`:

- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/policy_io.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/changes_candidate_review.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/changes_audit.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/changes WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-changes-version-export-r1 make webui-visual-smoke`

Notes from this slice:

- The Changes lifecycle smoke now clicks the committed version row's `Export`
  action after commit and before rollback, then validates the downloaded
  `source: "version"` envelope, version number, generated
  `phragma-version-v...json` filename, committed policy marker, and secret-like
  text guardrails across desktop, tablet, and mobile.
- No new hardening backlog item was added. Existing Changes lifecycle field
  hardening, WebUI handoff/export redaction, and audit/export custody entries
  cover production custody and signing requirements.

Additional remote validation for the Routing/VPN WireGuard branch-rollout slice:

- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-netvpn-rollout-r1 make webui-visual-smoke`

Additional remote validation for the Routing/VPN dynamic-routing editor slice:

- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/netvpn WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-netvpn-dynamic-routing-r1 make webui-visual-smoke`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-settings-netvpn-full-r1 make webui-visual-smoke`

Additional remote validation for the Routing/VPN responsive-table polish slice:

- `node --check internal/webui/static/js/views/netvpn.js`
- `node --check internal/webui/static/js/responsive_tables.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/responsive_tables.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-netvpn-responsive/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/netvpn
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-netvpn-responsive/.tmp/openngfw-webui-smoke-netvpn-responsive-r1
  make webui-visual-smoke`

Additional remote validation for the Routing/VPN IPsec responsive-table slice:

- `node --check internal/webui/static/js/views/netvpn.js`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/responsive_tables.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/netvpn.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-netvpn-ipsec-table/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/netvpn
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-netvpn-ipsec-table/.tmp/openngfw-webui-smoke-netvpn-ipsec-table-r1
  make webui-visual-smoke`

Additional remote validation for the Routing/VPN IPsec/WireGuard editor-validation slice:

- `node --check internal/webui/static/js/views/netvpn.js`
- `node --check internal/webui/static/js/netvpn.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node internal/webui/static/js/netvpn.test.mjs`
- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/netvpn WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-netvpn-vpn-editor-validation-r1 make webui-visual-smoke`

Additional remote validation for the Routing/VPN WireGuard enrollment bundle slice:

- `node --check internal/webui/static/js/views/netvpn.js`
- `node --check internal/webui/static/js/netvpn.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/netvpn.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-netvpn-enrollment/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/netvpn
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-netvpn-enrollment/.tmp/openngfw-webui-smoke-netvpn-enrollment-r1
  make webui-visual-smoke`

Additional remote validation for the Routing/VPN WireGuard enrollment QR slice:

- `node --check internal/webui/static/js/views/netvpn.js`
- `node --check internal/webui/static/js/qr_code.js`
- `node --check internal/webui/static/js/vendor/qrcode-generator-2.0.4.mjs`
- `node --check internal/webui/static/js/netvpn.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/netvpn.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp WEBUI_SMOKE_REQUIRE_BROWSER=1
  WEBUI_SMOKE_PATHS=/netvpn
  WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-netvpn-enrollment-qr-r1
  make webui-visual-smoke`

Additional remote validation for the Threat-ID exception lifecycle slice:

- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-threat-exception-lifecycle-r1 make webui-visual-smoke`

Additional remote validation for the Threat-ID exception review-metadata slice:

- `go test -count=1 ./internal/apiserver ./internal/policy ./internal/compiler -run "Threat|IDS|Ids"`
- `node --check internal/webui/static/js/views/threats.js`
- `node internal/webui/static/js/threat_exceptions.test.mjs`
- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/threats WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-threat-exception-metadata-r1 make webui-visual-smoke`

Additional remote validation for the Threat-ID exception responsive-table slice:

- `node --check internal/webui/static/js/views/threats.js`
- `node --check internal/webui/static/js/responsive_tables.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/responsive_tables.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/threat_exceptions.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-threat-exception-table-r1/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/threats
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-threat-exception-table-r1/.tmp/openngfw-webui-smoke-threat-exception-table-r1
  make webui-visual-smoke`

Additional remote validation for the IDS/IPS profile settings lifecycle slice:

- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/threats WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-ids-profile-lifecycle-r2 make webui-visual-smoke`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-ids-profile-lifecycle-full-r3 make webui-visual-smoke`

Additional remote validation for the first-class Inspection workspace slice:

- `node --check internal/webui/static/js/views/ids.js`
- `node --check internal/webui/static/js/app.js`
- `node --check internal/webui/static/js/automation_context.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node internal/webui/static/js/automation_context.test.mjs`
- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/inspection WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-inspection-workspace-r1 make webui-visual-smoke`

Additional remote validation for the Inspection coverage map slice:

- `node --check internal/webui/static/js/inspection_posture.js`
- `node --check internal/webui/static/js/inspection_posture.test.mjs`
- `node --check internal/webui/static/js/views/ids.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/inspection_posture.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/inspection WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-inspection-coverage-map-r3 make webui-visual-smoke`
- A first browser attempt expected bucket rows in every viewport, but the
  shared seeded candidate can legitimately have no security rules. The final
  smoke asserts the coverage-map root, counters, empty-state or bucket rows,
  responsive fit, and candidate-only Detect staging; focused model tests cover
  concrete bucket cases.
- No new hardening backlog row was added. Existing IDS/IPS profile hardening
  still covers real Suricata AF_PACKET/NFQUEUE field evidence, package-gate
  consistency, audit intent, and policy-visible bypass proof on supported
  Linux hosts.

Additional remote validation for the Settings telemetry/SIEM export workflow slice:

- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-settings-telemetry-r1 make webui-visual-smoke`

Additional remote validation for the Settings telemetry receiver-proof handoff
slice:

- `node --check internal/webui/static/js/telemetry_settings.js`
- `node --check internal/webui/static/js/views/settings.js`
- `node --check internal/webui/static/js/telemetry_settings.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/telemetry_settings.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp
  GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp
  GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp
  GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp
  GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache
  PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/settings
  WEBUI_SMOKE_SCREEN_TIMEOUT_MS=120000
  WEBUI_SMOKE_TOTAL_TIMEOUT_MS=600000
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-telemetry-receiver-proof-r2
  make webui-visual-smoke`
- The first receiver-proof visual-smoke rerun failed before browser startup
  because the remote validation host had only about 303 MB free and Go build
  temp creation hit `no space left on device`; removing only generated
  `oss-ngfw-smoke-tmp` build/smoke temp artifacts restored enough space for the
  passing rerun.

Additional remote validation for the Settings telemetry/network/access
responsive-table slice:

- `node --check internal/webui/static/js/views/settings.js`
- `node --check internal/webui/static/js/responsive_tables.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/responsive_tables.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-settings-telemetry-network-tables-r1/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/settings
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-settings-telemetry-network-tables-r1/.tmp/openngfw-webui-smoke-settings-telemetry-network-tables-r1
  make webui-visual-smoke`

Additional remote validation for the Settings access lifecycle slice:

- `make webui-check`
- `go test -count=1 -run "Test(AccessAdministrationReportsSafeLoadedLocalInventory|LocalUserLifecycleMutationsAreAuditedAndRefreshAuth|RevokeAccessSessionRequiresSessionIDAckAndExistingSession)$" ./internal/apiserver`
- `go test -count=1 -run "Test(LocalUserLifecycleMutatesPrivateUsersFileAndAuthenticator|RBAC|RBACRoleTableCoversRegisteredRPCs|OIDCSessionInventoryAndRevokeUseNonSecretSessionIDs)$" ./internal/authz`
- `go test -count=1 -run "Test(AccessCommandRegistered|PrintAccessUsersShowsStateWithoutSecrets|PrintLocalUserMutationShowsOneTimeTokenOnlyWhenPresent|RunAccessSessionsListShowsRedactedSessionInventory|RunAccessSessionRevokeRequiresAckAndBuildsRequest)$" ./internal/cli`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-settings-access-lifecycle-r9 make webui-visual-smoke`

Additional remote validation for the Settings access responsive-table polish slice:

- `node --check internal/webui/static/js/views/settings.js`
- `node --check internal/webui/static/js/responsive_tables.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/responsive_tables.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-settings-access-responsive/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/settings
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-settings-access-responsive/.tmp/openngfw-webui-smoke-settings-access-responsive-r1
  make webui-visual-smoke`

Additional remote validation for the Settings access-governance responsive-table
slice:

- `node --check internal/webui/static/js/views/settings.js`
- `node --check internal/webui/static/js/responsive_tables.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/responsive_tables.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-settings-access-governance-tables-r1/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/settings
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-settings-access-governance-tables-r1/.tmp/openngfw-webui-smoke-settings-access-governance-tables-r1
  make webui-visual-smoke`

Additional remote validation for the SAML provider runtime proof-parity slice:

- `make proto`
- `go test -count=1 ./internal/authz ./internal/apiserver ./internal/cli ./cmd/controld -run "SAML|Access"`
- `node --check internal/webui/static/js/automation_context.js`
- `node internal/webui/static/js/automation_context.test.mjs`
- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/settings WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-saml-proof-parity-r1 make webui-visual-smoke`

Additional remote validation for the SAML Settings provider lifecycle parity
slice
(`/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1`;
root filesystem was near full, so smoke and Go temp workspaces used
`/run/user/1000` tmpfs):

- `go test -count=1 -run "^TestSAMLProviderConfigLifecyclePreservesOIDCAndRedacts$" ./internal/apiserver`
- `go test -count=1 -run "^TestRunAccessSAMLSetRequiresAckAndRedactsOutput$" ./internal/cli`
- `go test -count=1 -run "^TestRBACRoleTableCoversRegisteredRPCs$" ./internal/authz`
- `go test -count=1 ./internal/authz ./internal/apiserver ./internal/cli ./cmd/controld -run "SAML|Access"`
- `node --check internal/webui/static/js/views/settings.js`
- `node --check internal/webui/static/js/access_governance.js`
- `node --check internal/webui/static/js/settings_access.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/settings_access.test.mjs`
- `make webui-check`
- `TMPDIR=/run/user/1000/openngfw-saml-smoke
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/settings
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/artifacts/saml-smoke
  make webui-visual-smoke`

Additional remote validation for the Settings browser-SSO session wording and
SAML runtime guidance slice:

- `node --check internal/webui/static/js/views/settings.js`
- `node --check internal/webui/static/js/access_governance.js`
- `node --check internal/webui/static/js/automation_context.js`
- `node --check internal/webui/static/js/settings_access.test.mjs`
- `node --check internal/webui/static/js/responsive_tables.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/settings_access.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/responsive_tables.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`
- `go test -count=1 ./internal/apiserver -run "SAML|Access|Session"`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/settings WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-settings-access-sso-labels-r2 make webui-visual-smoke`

Additional remote validation for the Settings network and host-input workflow slice:

- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/settings WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-settings-network-host-input-r2 make webui-visual-smoke`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-settings-netvpn-full-r1 make webui-visual-smoke`

Additional remote validation for the API/CLI context browser-proof slice:

- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-api-cli-context-r3 make webui-visual-smoke`

Additional remote validation for the API/CLI workflow-runbook slice:

- `node --check internal/webui/static/js/automation_context.js`
- `node internal/webui/static/js/automation_context.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/settings WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-automation-runbook-r1 make webui-visual-smoke`

Additional remote validation for the Threat exception API/CLI context parity
slice:

- `node --check internal/webui/static/js/automation_context.js`
- `node --check internal/webui/static/js/views/threats.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/threat_exceptions.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/threats WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-threat-exception-api-cli-r2 make webui-visual-smoke`

Notes from this slice:

- The `/threats` browser smoke opens the route-backed threat exception detail
  drawer, clicks `[data-threat-exception-action="api-cli"]`, verifies the exact
  `#/threats?view=exceptions&exception=<name>` route, copies workflow-session
  JSON, and checks selected exception update, set-state, remove, validate, and
  diff endpoints plus matching `ngfwctl threat-exceptions` commands.
- The first browser run did not start because generated Go build temp files
  exhausted the remote smoke temp filesystem. Removing only generated
  `/home/opc/oss-ngfw-smoke-tmp/go-build*` and stale smoke artifact directories
  allowed the clean rerun to pass.
- No signed recorder, server-retained session, or custody workflow was added;
  the API/CLI session packet continues to declare browser-local unsigned
  custody.

Additional remote validation for the browser-local API/CLI workflow session
recorder slice:

- `node --check internal/webui/static/js/automation_context.js`
- `node --check internal/webui/static/js/automation_context.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/traffic,/rules WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-automation-recorder-r3 make webui-visual-smoke`
- The first `/traffic,/rules` browser run failed because the recorder smoke
  intentionally left the browser-local recorder active after the Rules route;
  the Traffic route correctly showed `Stop` instead of `Start`. The smoke helper
  now clears the browser-local recorder before each drawer assertion, and the
  rerun passed across desktop, tablet, and mobile.
- Existing WebUI handoff/export redaction hardening now explicitly covers the
  remaining production version of this recorder: server-side retention,
  signing, identity binding, custody policy, and exhaustive cross-surface
  clipboard/download audits.

Additional remote validation for the Troubleshoot running-vs-candidate compare slice:

- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-troubleshoot-compare-r1 make webui-visual-smoke`

Additional remote validation for the Performance benchmark evidence verifier slice:

- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/performance WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-performance-verifier-r2 make webui-visual-smoke`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-performance-verifier-full-r1 make webui-visual-smoke`

Additional remote validation for the Performance repair-command copy proof
slice:

- `node --check e2e/webui-visual-smoke.mjs`
- `make webui-check`
- `TMPDIR=$PWD/.tmp WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/performance
  WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-performance-repair-copy-r1
  make webui-visual-smoke`

Additional remote validation for the Performance artifact guardrail slice:

- `go test ./internal/perfreport`
- `go test ./cmd/ngfwperf`
- `go test ./internal/releaseacceptance`
- `go test ./cmd/ngfwrelease`
- `make benchmark-verify`
- `RELEASE_NO_PERFORMANCE_CLAIMS=1 make benchmark-verify-release`
- `node --check internal/webui/static/js/performance.js`
- `node --check internal/webui/static/js/views/performance.js`
- `node --check internal/webui/static/js/performance.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node internal/webui/static/js/performance.test.mjs`
- `make webui-check`

Additional remote validation for the Performance benchmark collection runbook
slice:

- `node --check internal/webui/static/js/performance.js`
- `node --check internal/webui/static/js/views/performance.js`
- `node --check internal/webui/static/js/performance.test.mjs`
- `node --check internal/webui/static/js/automation_context.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/performance.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs
  internal/webui/static/js/automation_context.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp
  GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp
  GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp
  GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp
  GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache
  PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/performance
  WEBUI_SMOKE_SCREEN_TIMEOUT_MS=120000
  WEBUI_SMOKE_TOTAL_TIMEOUT_MS=600000
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-performance-runbook-r2
  make webui-visual-smoke`
- The first runbook smoke attempt reached all viewports and exposed mobile
  command overflow plus hidden release-command text; both were fixed before the
  passing rerun. A later rerun failed before browser startup because the remote
  Go linker ran out of disk; deleting generated `oss-ngfw-smoke-tmp` Go
  cache/temp artifacts restored enough space for the passing browser-required
  smoke.
- `TMPDIR=$PWD/.tmp WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/performance
  WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-performance-artifact-guardrails-r1
  make webui-visual-smoke`

Additional remote validation for the WebUI hbar/System Logs responsive polish
slice:

- `node --check internal/webui/static/js/charts.js`
- `node --check internal/webui/static/js/views/logs.js`
- `node --check internal/webui/static/js/charts.test.mjs`
- `node --check internal/webui/static/js/responsive_tables.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/charts.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/responsive_tables.test.mjs`
- `make webui-check`
- `TMPDIR=$PWD/.tmp WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/,/logs
  WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-hbars-logs-r1
  make webui-visual-smoke`

Additional remote validation for the System Logs table primitive slice:

- `node --check internal/webui/static/js/views/logs.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/responsive_tables.test.mjs`
- `TMPDIR=$PWD/.tmp WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/logs
  WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-logs-table-primitives-r1
  make webui-visual-smoke`

Additional remote validation for the hidden download-anchor utility and NAT
rename-review regression slice:

- `node --check internal/webui/static/js/download_anchor_hidden.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/download_anchor_hidden.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/responsive_tables.test.mjs`
- `node --check internal/webui/static/js/views/objects.js`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/object_references.test.mjs`
- `TMPDIR=$PWD/.tmp WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/nat
  WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-object-rename-review-r1
  make webui-visual-smoke`
- `TMPDIR=$PWD/.tmp WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/readiness,/rules,/nat,/investigation,/settings
  WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-hidden-download-anchor-r2
  make webui-visual-smoke`

Additional remote validation for the Traffic responsive-table/action-column
polish slice:

- `node --check internal/webui/static/js/views/traffic.js`
- `node --check internal/webui/static/js/automation_context.js`
- `node --check internal/webui/static/js/responsive_tables.test.mjs`
- `node --check internal/webui/static/js/automation_context.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/responsive_tables.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`
- `make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-traffic-responsive-tables-r1/.tmp
  WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/traffic
  WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-traffic-responsive-tables-r1/.tmp/openngfw-webui-smoke-traffic-responsive-tables-r1
  make webui-visual-smoke`

Additional remote validation for the Threats facet/table polish slice:

- `node --check internal/webui/static/js/views/threats.js`
- `node --check internal/webui/static/js/responsive_tables.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/responsive_tables.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/threat_exceptions.test.mjs`
- `make webui-check`
- `TMPDIR=$PWD/.tmp WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/threats
  WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-threats-facet-table-r3
  make webui-visual-smoke`

Additional remote validation for the Intel feed governance slice:

- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/intel WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-intel-feed-governance-r7 make webui-visual-smoke`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-intel-feed-governance-full-r1 make webui-visual-smoke`

Additional remote validation for the active/passive HA policy-pull functional slice:

- `go test ./internal/apiserver -run "HighAvailability|PullHighAvailability"`
- `go test ./internal/cli -run "SystemHA|StatusShowsHighAvailability"`
- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-ha-policy-pull-readiness-r1 make webui-visual-smoke`

Additional remote validation for the active/passive HA manual activation slice:

- `make proto`
- `go test ./internal/apiserver -run "HighAvailability|PullHighAvailability|ActivateHighAvailability"`
- `go test ./internal/cli -run "SystemHA"`
- `node internal/webui/static/js/readiness_view.test.mjs`
- `node internal/webui/static/js/automation_context.test.mjs`
- `make webui-check`
- `WEBUI_SMOKE_PATHS=/readiness WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-ha-activation-r2 make webui-visual-smoke`

Additional remote validation for the active/passive HA automatic policy-replication slice:

- `make proto`
- `go test -count=1 ./internal/apiserver -run "TestSystem.*HighAvailability|TestSystemPullHighAvailabilityPolicy"`
- `go test -count=1 ./cmd/controld -run "TestValidateHAFlags|TestHAPeer"`
- `go test -count=1 ./cmd/controld ./internal/apiserver ./internal/cli -run "HighAvailability|HA|SystemHA|StatusShowsHighAvailability|ValidateHAFlags|HAPeer"`
- `node --check internal/webui/static/js/readiness_model.js`
- `node --check internal/webui/static/js/views/readiness.js`
- `node --check internal/webui/static/js/automation_context.js`
- `node internal/webui/static/js/readiness_view.test.mjs`
- `node internal/webui/static/js/automation_context.test.mjs`
- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/readiness WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-ha-auto-replication-r1 make webui-visual-smoke`

`make proto-verify` could not be completed in the remote validation copy
because that workdir is not a Git checkout; its git-diff based guard failed
before evaluating artifact drift. Direct generated-artifact checks confirmed
`ActivateHighAvailabilityFailover`, the gRPC gateway route, and
`/v1/system/ha/failover:activate` are present in generated Go, docs OpenAPI,
and the bundled WebUI API spec.

Additional remote validation for the HA CLI status replication parity slice
(`/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1`;
source files copied into the existing remote validation tree to avoid consuming
more root filesystem space):

- `TMPDIR=/run/user/1000/openngfw-ha-cli-status go test -count=1 ./internal/cli -run "SystemHA|StatusShowsHighAvailability"`
- `TMPDIR=/run/user/1000/openngfw-ha-cli-status go test -count=1 ./internal/apiserver -run "TestSystem.*HighAvailability|TestSystemPullHighAvailabilityPolicy"`
- `TMPDIR=/run/user/1000/openngfw-ha-cli-status go test -count=1 ./cmd/controld -run "TestValidateHAFlags|TestHAPeer"`
- A recursive stale-HA-wording grep across `internal/cli`, `internal/apiserver`,
  `internal/webui/static/js`, and `docs` returned no matches for the old
  failover-control and peer-transport placeholder phrases.

Additional remote validation for the Readiness HA operations cockpit API/CLI
context slice on `opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/readiness.js`
- `node --check internal/webui/static/js/automation_context.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/readiness_view.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/readiness WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-readiness-ha-cockpit-context-r2 make webui-visual-smoke`

Notes from this slice:

- The `/readiness` browser smoke opens the HA operations cockpit, clicks
  `[data-readiness-action="ha-cockpit-api-cli"]`, verifies the exact
  `#/readiness?drawer=ha-cockpit` context, copies workflow-session JSON, copies
  the plain-text context, and applies automation plus HA-specific leak guards
  across desktop, tablet, and mobile.
- No new hardening backlog item was added. Existing HA and restore security plus
  WebUI handoff/export redaction rows cover peer transport security, VIP/route
  promotion, fencing, connection-state sync, token custody, signing, and
  production custody controls.

Additional remote validation for the HA failover preflight and post-activation
split-brain evidence slice on `opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/readiness.js`
- `node --check internal/webui/static/js/readiness_view.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `go test -count=1 ./internal/apiserver -run 'HighAvailability|ActivateHighAvailability'`
- `go test -count=1 ./internal/cli -run 'HighAvailability|HA|StatusShowsHighAvailability'`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/readiness_view.test.mjs`
- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/readiness WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-ha-post-activation-r3 make webui-visual-smoke`

Notes from this slice:

- Browser-required `/readiness` smoke passed across desktop, tablet, and mobile
  after clearing generated Go build caches from the 99% full validation host.
- The first smoke rerun failed because the remote root filesystem had only
  about 323 MB free and Go compilation reported `no space left on device`;
  only generated `go-build*`, `go-cache`, and failed HA smoke artifact
  directories under `/home/opc/oss-ngfw-smoke-tmp` were removed.

Additional remote validation for the App-ID signal-only live NFQUEUE
enforcement slice on `opc@139.87.66.128`:

- `sudo rm -rf /home/opc/oss-ngfw-smoke-tmp/go-mod` removed the root-owned
  Go module cache created during the combined M2 run; `/` remained tight at
  98% used with about 797 MB free.
- `sudo -E TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache GOFLAGS=-buildvcs=false go test -tags integration -count=1 -v ./test/integration -run '^TestM2AppIDSignalOnlyDenyDropsHTTPInPreventMode$'`
- The focused run passed in 9.050s. Suricata NFQUEUE counters showed the
  baseline accepted 10 and dropped 0 packets, then the App-ID block accepted 3
  and dropped 12 packets.

Additional remote validation for the HA activation-driven VIP/route promotion
slice on `opc@139.87.66.128`:

- `sudo -E TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache GOFLAGS=-buildvcs=false go test -tags integration -count=1 -v ./test/integration -run '^TestHALiveActivationPromotesVIPAndRoute$'`
- The focused run passed in 0.064s after creating a disposable Linux dummy
  interface, activating the passive node through the System API, and verifying
  the promoted VIP, promoted route, durable HA state, audit actions, and
  managed promotion state file.
- The validation host root filesystem remained tight at 98% used with about
  791 MB free after the run.

Additional remote validation for the security-profile required fail-closed
inspection slice on `opc@139.87.66.128`:

- `sudo -E TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache GOFLAGS=-buildvcs=false go test -tags integration -count=1 -v ./test/integration -run '^TestM2SecurityProfileRequiredAllowIsInspectedFailClosed$'`
- The focused run passed in 4.485s. The test commits a DNS-blocking security
  profile attached to the existing allow rule, verifies live nftables
  fail-closed NFQUEUE without `bypass`, verifies profile-inspection and
  `inspection=ips-fail-closed` rule markers, proves baseline TCP reachability,
  and observes the test Suricata signature alert on the inspected allowed flow.
- `sudo -E TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache GOFLAGS=-buildvcs=false go test -tags integration -count=1 -v ./test/integration -run '^(TestM2SuricataDetectEndToEnd|TestM2AppIDSignalOnlyDenyDropsHTTPInPreventMode|TestM2SecurityProfileRequiredAllowIsInspectedFailClosed)$'`
- The combined M2 run passed in 32.074s, keeping the existing Suricata detect
  and App-ID prevent proofs compatible with the new profile-required inspection
  proof. The validation host root filesystem remained tight at 98% used with
  about 790 MB free after the run.

Additional remote validation for the HA readiness/recovery release gate:

- `bash release/ha-readiness-recovery.sh --check`
- `make ha-readiness-recovery-check`
- `go test -count=1 ./internal/releaseacceptance ./cmd/ngfwrelease`
- `go test -count=1 ./internal/apiserver -run 'HighAvailability|SupportBundle'`
- `go test -count=1 ./internal/cli -run 'HighAvailability|HA|StatusShowsHighAvailability'`
- `go test -count=1 ./cmd/controld -run 'ValidateHAFlags|HAPeer'`
- `RELEASE_NO_PERFORMANCE_CLAIMS=1 make release-acceptance-status`

Additional remote validation for the HA recovery Readiness release-evidence UI
slice:

- `node --check internal/webui/static/js/readiness_model.js`
- `node --check internal/webui/static/js/views/readiness.js`
- `node --check internal/webui/static/js/readiness_model.test.mjs`
- `node --check internal/webui/static/js/readiness_view.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs ./internal/webui/static/js/readiness_model.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs ./internal/webui/static/js/readiness_view.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/readiness WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-readiness-ha-recovery-r1 make webui-visual-smoke`
- The validation host needed `npx playwright install chromium` because the
  Playwright package was present but the Chromium/headless-shell payload was
  missing. The host root filesystem remained tight at 98% used, so only
  generated Go temp/cache and failed smoke artifacts were removed before the
  final smoke.

Additional remote validation for the packet-capture lifecycle slice:

- `go test ./internal/apiserver -run "PacketCapture|DownloadPacketCapture|SetPacketCaptureRetention"`
- `go test ./internal/cli -run "SystemCapture"`
- `sudo -E go test -tags integration -count=1 -run TestPacketCaptureStartCapturesLoopbackTraffic -v ./test/integration`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-packet-capture-lifecycle-r1 make webui-visual-smoke`

Additional remote validation for the Troubleshoot capture API/CLI context slice:

- `node --check internal/webui/static/js/views/troubleshoot.js`
- `node --check internal/webui/static/js/automation_context.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node internal/webui/static/js/automation_context.test.mjs`
- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/traffic WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-troubleshoot-capture-context-r4 make webui-visual-smoke`

Additional remote validation for the Rules cleanup remediation slice:

- `make webui-check`
- `go test ./internal/policy -run SemanticFindings`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/rules WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-rules-cleanup-remediation-debug-r4 make webui-visual-smoke`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-rules-cleanup-remediation-r2 make webui-visual-smoke`

Additional remote validation for the Rules manual lifecycle slice:

- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/rules WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-rules-manual-lifecycle-r4 make webui-visual-smoke`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-rules-manual-lifecycle-full-r1 make webui-visual-smoke`
- `TMPDIR=/run/user/1000/openngfw-rules-reorder node --check internal/webui/static/js/views/rules.js`
- `TMPDIR=/run/user/1000/openngfw-rules-reorder node --check e2e/webui-visual-smoke.mjs`
- `TMPDIR=/run/user/1000/openngfw-rules-reorder node internal/webui/static/js/rules_table_responsive.test.mjs`
- `TMPDIR=/run/user/1000/openngfw-rules-reorder make webui-check`
- `TMPDIR=/run/user/1000/openngfw-rules-reorder WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/rules WEBUI_SMOKE_ARTIFACT_DIR=/run/user/1000/openngfw-rules-reorder/artifacts make webui-visual-smoke`

Additional remote validation for the saved-filter lifecycle slice:

- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/traffic,/threats,/changes WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-saved-filters-debug-r4 make webui-visual-smoke`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_ARTIFACT_DIR=/tmp/openngfw-webui-smoke-saved-filters-r1 make webui-visual-smoke`

Additional remote validation for the object-reference CLI parity slice:

- `go test ./internal/cli -run "PolicyReferences|PolicyCommandIncludesObjectReferences"`
- `go test ./internal/apiserver -run "PolicyListObjectReferences"`

Additional remote validation for the Security Profile Impact Workbench slice:

- `node --check internal/webui/static/js/object_route.js`
- `node --check internal/webui/static/js/views/objects.js`
- `node --check internal/webui/static/js/object_references.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node internal/webui/static/js/object_references.test.mjs`
- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/objects WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-security-profile-impact-r1 make webui-visual-smoke`

Additional remote validation for the Objects stale-route review slice:

- `node --check internal/webui/static/js/views/objects.js`
- `node --check internal/webui/static/js/object_references.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node internal/webui/static/js/object_references.test.mjs`
- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/objects WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-objects-stale-route-r1 make webui-visual-smoke`

Additional remote validation for the Objects rename/grouped dependency review slice:

- `node --check internal/webui/static/js/views/objects.js`
- `node --check internal/webui/static/js/object_references.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node internal/webui/static/js/object_references.test.mjs`
- `make webui-check`
- `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/objects WEBUI_SMOKE_ARTIFACT_DIR=$PWD/.tmp/openngfw-webui-smoke-objects-rename-groups-r1 make webui-visual-smoke`

Additional remote validation for the first-party eBPF attach-drill helper and
Readiness field-evidence link slice:

- `go test ./internal/ebpfdrill ./cmd/ngfwebpfdrill`
- `go test -tags integration ./test/integration -run TestReleaseEbpfOL9AttachDrill`
- `bash release/ebpf-ol9-attach-drill.sh --check --evidence-dir /tmp/ebpf-ol9-check-evidence`
- `make ebpf-ol9-attach-drill-check EBPF_OL9_FIELD_EVIDENCE_DIR=/tmp/ebpf-ol9-make-check-evidence`
- `node internal/webui/static/js/readiness_ebpf_evidence.test.mjs`
- `make webui-check`

Additional remote validation for the `ngfwctl system ebpf-readiness` slice:

- `go test ./internal/cli -run "SystemEbpfReadiness|StatusShowsEbpf|HAPull|TelemetryExportStatus"`
- `go test ./internal/cli`
- `go test ./cmd/ngfwctl`

Additional remote validation for the Routing/VPN IPsec runtime-status slice on
`opc@139.87.66.128`:

- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make proto`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache go test -count=1 ./internal/apiserver -run 'IPsec|Swanctl|SystemStatusReportsIPsec'`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache go test -count=1 ./internal/cli -run 'IPsec|WireGuard|StatusShows'`
- `node --check internal/webui/static/js/views/netvpn.js`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/netvpn.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache go test -count=1 ./internal/apiserver ./internal/cli`

Notes from this slice:

- `/v1/system/status` now exposes passive `vpn.ipsec` runtime evidence derived
  from `swanctl --list-sas`: aggregate state/detail plus per-tunnel IKE state
  and installed/total CHILD SA counts.
- `ngfwctl status` now renders IPsec runtime evidence beside WireGuard instead
  of hiding VPN runtime when WireGuard is absent.
- Routing & VPN tunnel handoff drawers now join configured IPsec tunnels to live
  `vpn.ipsec.tunnels[]` evidence and show IKE/CHILD SA posture without exporting
  secret material.
- This is runtime SA evidence only. It does not replace protected-subnet traffic
  proof, XFRM policy/state inspection, expected-vs-observed configured tunnel
  reconciliation, peer/secret lifecycle review, or least-privilege host evidence.

Additional remote validation for the Readiness Routing & VPN posture slice on
`opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/readiness.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/readiness_view.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/netvpn.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/readiness,/netvpn WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-readiness-netvpn-r2 make webui-visual-smoke`

Notes from this slice:

- Readiness now includes a `Routing & VPN posture` panel that summarizes running
  policy plus passive `status.routing` and `status.vpn` evidence for BGP, OSPF,
  IPsec, WireGuard, static routes, and tunnel path checks.
- The panel links directly to `#/netvpn` and, when a configured tunnel needs
  attention, the first affected Net/VPN tunnel drawer route.
- The panel intentionally avoids claims about protected-subnet reachability,
  real FRR peer field proof, strongSwan XFRM state, or production VPN readiness.

Additional remote validation for the Settings host-input API/CLI context slice
on `opc@139.87.66.128`:

- `node --check internal/webui/static/js/automation_context.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/settings WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-settings-host-input-context-r2 make webui-visual-smoke`

Notes from this slice:

- `#/settings?panel=host-input` now advertises the same candidate read,
  candidate validation, running-to-candidate diff, and candidate CLI
  validate/diff/bootstrap path that operators need after staging host-input
  default-deny changes.
- The browser-required Settings smoke proves the context drawer after
  management allow coverage and default-deny staging across desktop, tablet,
  and mobile.
- The first browser smoke attempt aborted while creating the tablet context
  because the remote root filesystem had only about 389 MB free. Removing
  generated `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-*` and
  `/home/opc/oss-ngfw-smoke-tmp/go-build*` artifacts freed space, and the
  rerun passed.

Additional remote validation for the Intel content quality API/CLI context
slice on `opc@139.87.66.128`:

- `node --check internal/webui/static/js/automation_context.js`
- `node --check internal/webui/static/js/views/intel.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/intel WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-intel-quality-context-r3 make webui-visual-smoke`

Notes from this slice:

- `drawer=quality` no longer falls back to generic Intel review context. It now
  lists `/v1/intel/content/packages/{kind}/evidence/{evidenceType}`,
  `/v1/intel/content/packages/{kind}/corpus`, and
  `/v1/intel/content/packages/{kind}/compare` alongside the matching
  `ngfwctl intel content corpus` and `compare` commands.
- The first `/intel` rerun after the assertion fix passed desktop and mobile
  quality context proof, then hit an unrelated tablet feed-governance candidate
  race. After clearing generated remote smoke/build temp artifacts, the clean
  rerun passed desktop, tablet, and mobile.
- No new hardening backlog item was added. Existing content custody/signing and
  WebUI handoff/export redaction hardening rows already cover production
  evidence custody and path/secret disclosure concerns.

Additional remote validation for the Routing & VPN tunnel API/CLI context slice
on `opc@139.87.66.128`:

- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/netvpn WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-netvpn-tunnel-context-r3 make webui-visual-smoke`

Notes from this slice:

- The browser-required Net/VPN smoke proves the in-drawer `API / CLI` button,
  route-specific context text, copied workflow-session JSON, copied CLI/API
  context, and VPN secret/path leak guards across desktop, tablet, and mobile.
- WireGuard tunnel context uses UDP/51820 session search; IPsec tunnel context
  uses UDP/4500 session search.
- No new hardening backlog item was added. Existing VPN peer template/secret
  lifecycle, privileged runtime evidence, and WebUI handoff/export redaction
  rows cover the remaining production hardening work for this area.

Additional remote validation for the Rules rulebase map slice on
`opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/rules.js`
- `node --check internal/webui/static/js/rules_bulk_density.test.mjs`
- `node --check internal/webui/static/js/rules_table_responsive.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/rules_bulk_density.test.mjs`
- `node internal/webui/static/js/rules_table_responsive.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/rules WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-rules-rulebase-map-r1 make webui-visual-smoke`

Notes from this slice:

- The first focused model run failed because the test expected only two changed
  rules and omitted the existing bypass-risk issue. The implementation was
  correct under the existing change and inspection models, so the test now
  asserts the candidate-only disabled addition and bypass-risk hotspot.
- A new `Rulebase comprehension hardening` backlog row tracks durable rule IDs,
  structured overlap peers/dimensions, backend/frontend shadowing alignment,
  overlap truncation handling, pagination/virtualization, and richer profile
  context in the overlap-impact drawer.

Additional remote validation for the Rules overlap-impact drawer slice on
`opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/rules.js`
- `node --check internal/webui/static/js/rules_bulk_density.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/rules_bulk_density.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/rules WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-rules-overlap-impact-r2 make webui-visual-smoke`

Notes from this slice:

- The focused overlap-impact test initially used identical match dimensions,
  which is a full-cover/shadow case rather than the backend's partial-overlap
  contract. The model now excludes full-cover cases with App-ID-aware coverage
  checks, and the test fixtures use true partial overlaps.
- The first browser smoke attempt failed before app startup because the remote
  root filesystem ran out of space while compiling Go dependencies. Only stale
  generated files under `/home/opc/oss-ngfw-smoke-tmp` were removed before the
  successful rerun.
- No new hardening row was added. Existing Rulebase comprehension hardening now
  distinguishes the functional candidate-side overlap-impact drawer from the
  remaining need for structured server overlap peers/dimensions, durable rule
  IDs, truncation handling, and large-rulebase pagination.

Additional remote validation for the Traffic App-ID regression-sample
continuity slice on `opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/traffic.js`
- `node --check internal/webui/static/js/automation_context.js`
- `node --check internal/webui/static/js/appid_observations.test.mjs`
- `node --check internal/webui/static/js/automation_context.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/appid_observations.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/traffic WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-appid-regression-sample-r3 make webui-visual-smoke`

Notes from this slice:

- The first two `/traffic` browser runs failed because the new smoke selector
  had been attached to the App-ID queue summary strip instead of the selected
  observation's regression sample panel. Moving `data-appid-regression-sample-panel`
  to the actual observation drawer panel made the route-level and in-drawer
  proof pass across desktop, tablet, and mobile.
- No new hardening row was added. Existing App-ID enforcement and content
  production readiness hardening rows now explicitly cover selected queue
  corpus API/CLI context, signed corpus custody, draft artifact retention, and
  real L7/App-ID dataplane enforcement.

Additional remote validation for the NAT path-coupling review and row-level
preview slice on `opc@139.87.66.128`:

- `node --check internal/webui/static/js/nat_path_preview.js`
- `node --check internal/webui/static/js/views/nat.js`
- `node --check internal/webui/static/js/nat_path_preview.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/nat_path_preview.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/nat WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-nat-coupling-review-r6 make webui-visual-smoke`

Notes from this slice:

- NAT path preview now derives a path-coupling review from the existing
  running/candidate `ExplainFlow` delta. It surfaces policy, DNAT, SNAT, route,
  egress, Troubleshoot compare, and candidate-diff pivots only when the tuple
  actually evaluates those decision points, so a policy-denied DNAT path does
  not overclaim route evidence.
- Source and destination NAT rows now expose explicit non-mutating `Preview
  path` actions. The source NAT lifecycle smoke proves row-level preview after
  static SNAT edit; the DNAT publish smoke proves row-level destination preview
  and the new coupling review across desktop, tablet, and mobile.
- The first coupling-review browser run failed because the smoke expected a
  route row even though the seeded candidate was denied before routing. Later
  reruns exposed the object-reference automation-context helper's route-state
  sensitivity when closing a drawer before opening API/CLI context; the helper
  now has a preserved-drawer path for that route-backed check. One additional
  run failed before app startup due to remote root filesystem pressure while
  compiling Go dependencies; only stale generated smoke/build artifacts under
  `/home/opc/oss-ngfw-smoke-tmp` were removed before the successful rerun.
- No new hardening row was added. Existing Object/NAT dependency workflow
  hardening now covers live FRR/kernel route evidence, masquerade egress IP
  proof, granular NAT API/CLI, durable identity, VRF/interface posture, and
  production dataplane path-simulation boundaries.

Additional remote validation for the ExplainFlow API/CLI context parity slice
on `opc@139.87.66.128`:

- `node --check internal/webui/static/js/automation_context.js`
- `node --check internal/webui/static/js/automation_context.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/traffic WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-explainflow-context-r1 make webui-visual-smoke`

Notes from this slice:

- Generic Rules, Traffic, Investigation, and Troubleshoot API/CLI context
  examples now use the same flat public `ExplainFlowRequest` shape as the
  route-specific contexts: `policySource`, tuple fields, optional runtime, and
  optional flow ID. The obsolete nested `flow` plus `source` example shape was
  removed.
- Focused JS coverage now parses ExplainFlow bodies for Rules, NAT,
  Routing/VPN, selected tunnel drawers, Traffic, Troubleshoot, exact
  Troubleshoot routes, and Investigation to prove they stay flat and route
  values match the current route state.
- Browser smoke proves the copied Troubleshoot API/CLI context from the seeded
  Traffic capture workflow includes flat `policySource`, `srcIp`, and `destIp`
  fields and excludes legacy nested `flow`/`source` bodies across desktop,
  tablet, and mobile.
- No new hardening row was added. Existing WebUI handoff/export redaction and
  automation-recorder hardening rows cover the remaining production custody,
  signing, retention, operator identity binding, and cross-surface export audit.

Additional remote validation for the System Logs derived-context handoff slice
on `opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/logs.js`
- `node --check internal/webui/static/js/logs.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/logs.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/logs WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-logs-derived-context-r2 make webui-visual-smoke`

Notes from this slice:

- System Logs drawers now derive flow ID, source/destination tuple, protocol,
  App-ID, and signature ID from structured log text and expose exact Traffic,
  Threats, and Troubleshoot pivots when the context is present.
- System-log copy/export/pin handoff packets now preserve the derived tuple in
  `summary`, `subject.tuple`, `artifacts.flow`, `artifacts.alert`, and
  `artifacts.logContext`, so Investigation treats the pinned log as
  capture-ready instead of a raw message-only artifact.
- Browser smoke proves the seeded Suricata warning keeps redaction visible in
  the table, renders derived context in the drawer, exports JSON with flow and
  signature context, pins that context to Investigation storage, and preserves
  exact route pivots across desktop, tablet, and mobile.
- No new hardening row was added. Existing System and engine log custody
  hardening still covers retention/pruning, journald/file permissions, signed
  export/session recording, redaction corpus, high-volume query rate limits,
  source-specific RBAC, and supported-Linux log-location field evidence.

Additional remote validation for the Changes audit verify-replay and
pin-to-case parity slice on `opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/changes.js`
- `node --check internal/webui/static/js/changes_audit.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/changes_audit.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/changes WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-changes-audit-verify-r4 make webui-visual-smoke`

Notes from this slice:

- Browser-generated `phragma.audit.report.v1` packets now advertise the real
  audit-integrity verify route, `GET /v1/audit/verify`, matching the WebUI API
  client, proto annotation, generated gateway, and OpenAPI specs. The report
  drawer also exposes this verify replay value beside the source audit replay
  and CLI replay commands.
- Focused JS coverage now asserts the exact verify replay endpoint so the
  stale `POST /v1/audit:verify` report metadata cannot return silently.
- Changes browser smoke now proves copied/exported report packets carry the
  correct verify replay endpoint, and it also verifies filtered audit-log and
  per-entry audit handoff pin-to-case wiring into Investigation storage with
  existing redaction checks across desktop, tablet, and mobile.
- The first `/changes` rerun failed before app startup because the remote host
  ran out of temporary Go build space. Only generated smoke/build artifacts
  under `/home/opc/oss-ngfw-smoke-tmp` were removed before rerunning. A later
  browser run exposed a mobile timing regression caused by checking audit-entry
  pinning before the established export path; the smoke now preserves the
  existing copy/export order and verifies pinning afterward.
- No new hardening row was added. Existing Audit retention and export custody
  hardening still covers retention, pruning, signing, custody policy,
  server-side report storage, report-generation RBAC policy, and production
  time-source/backpressure evidence.

Additional remote validation for the security-profile impact API/CLI context
slice on `opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/objects.js`
- `node --check internal/webui/static/js/automation_context.js`
- `node --check internal/webui/static/js/automation_context.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/objects WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-security-profile-impact-context-r1 make webui-visual-smoke`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/object_references.test.mjs`

Notes from this slice:

- `#/objects?tab=securityProfiles&drawer=impact&object=...` now has exact
  API/CLI context instead of falling back to generic object reference context.
  The drawer context lists the selected security profile reference query,
  candidate policy read, candidate validation, running-to-candidate diff, and
  matching `ngfwctl policy references`, `policy show`, `policy validate`, and
  `policy diff` commands.
- The Security Profile Impact drawer now has an in-drawer `API / CLI` action,
  so operators can capture blast-radius and rollout review commands without
  relying on the global toolbar. Browser smoke proves the impact drawer,
  copy/pin handoff, exact API/CLI context, redaction, and Open rule route across
  desktop, tablet, and mobile.
- No new hardening row was added. Existing Security profile enforcement
  hardening still covers TLS broker integration, CA/private-key custody, URL
  category provenance, DNS sinkhole behavior, file-inspection engine behavior,
  renderer/runtime parity, and live Suricata/NFQUEUE field evidence.

Additional remote validation for the NAT preview and Rules server-overlap
API/CLI context slice on `opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/rules.js`
- `node --check internal/webui/static/js/automation_context.js`
- `node --check internal/webui/static/js/automation_context.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/nat,/rules WEBUI_SMOKE_SCREEN_TIMEOUT_MS=120000 WEBUI_SMOKE_TOTAL_TIMEOUT_MS=600000 WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-nat-rules-context-r2 make webui-visual-smoke`

Notes from this slice:

- `#/nat?...` routes with concrete preview tuples now produce exact
  running/candidate `POST /v1/explain/flow` bodies and matching
  `ngfwctl explain` commands instead of falling back to the generic NAT sample
  tuple. The `/nat` browser smoke proves the current tuple context after stale
  response suppression across desktop, tablet, and mobile.
- `#/rules?q=server-overlap&drawer=server-overlap-review` now has
  server-overlap-specific API/CLI context for candidate policy review,
  candidate validation, running-to-candidate diff, and matching `ngfwctl`
  commands. The server-overlap drawer also exposes an in-drawer `API / CLI`
  action, and `/rules` browser smoke proves drawer text, copied context, and
  redaction across desktop, tablet, and mobile.
- The first browser-smoke rerun failed only because the assertion expected one
  brittle query-string ordering for the Rules route. The product route kept
  canonical state with `density` before `drawer`; the smoke now checks the
  route components independently.
- No new hardening row was added. Existing Rulebase comprehension hardening
  now covers retained overlap custody, truncation handling,
  pagination/virtualization, cross-page selection authority, and deeper
  remediation guidance. Existing Object/NAT dependency workflow hardening now
  covers SDK cutoff policy for by-ID aliases, signed dataplane evidence
  custody, active proof, and dynamic FRR/kernel route proof.

Additional remote validation for the Fleet & templates operations workspace
slice on `opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/fleet.js`
- `node --check internal/webui/static/js/fleet.test.mjs`
- `node --check internal/webui/static/js/app.js`
- `node --check internal/webui/static/js/automation_context.js`
- `node --check internal/webui/static/js/automation_context.test.mjs`
- `node --check internal/webui/static/js/responsive_tables.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/fleet.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/responsive_tables.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/fleet WEBUI_SMOKE_SCREEN_TIMEOUT_MS=120000 WEBUI_SMOKE_TOTAL_TIMEOUT_MS=600000 WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-fleet-templates-r3 make webui-visual-smoke`

Notes from this slice:

- `#/fleet` is now a first-class Fleet & templates workspace in the app shell
  and command palette. It aggregates the connected appliance, HA posture,
  policy drift, content package posture, release gates, template rows, operator
  queue, and evidence sources from existing public APIs without adding backend
  fleet APIs or pretending multi-node discovery exists.
- The workspace is read-only and explicit about current scope: local
  control-plane appliance plus HA evidence. Candidate/template changes still
  route operators back through Changes, Intel, Routing & VPN, Readiness,
  validation, diff, commit, audit, and rollback.
- `#/fleet` has route-level API/CLI context covering system status, HA status,
  identity, running/candidate policy sources, candidate status, policy diff,
  versions, feeds, content packages, release acceptance, support bundle, and
  matching `ngfwctl` commands. Browser smoke proves the API/CLI drawer and
  redaction across desktop, tablet, and mobile.
- The first `/fleet` smoke run passed UI assertions but failed because an eager
  optional candidate-policy fetch produced a 404 when no candidate existed.
  The view now derives drift from `/v1/candidate/status` and avoids that
  optional fetch; the rerun passed.
- A remote rerun initially hit the known temporary-space issue while compiling
  `controld`. Only generated smoke/build temp under
  `/home/opc/oss-ngfw-smoke-tmp` was removed before rerunning.
- New hardening requirements were tracked under Fleet/template orchestration:
  durable multi-node inventory/enrollment, node trust and peer transport,
  signed template artifacts, fan-out/apply result custody, drift exceptions,
  approval/commit policy, distributed audit retention, and real HA traffic
  controls such as VIP/route cutover, fencing, and connection-state transfer.

Known non-green source-control gate:

- `make proto-status` still reports tracked and untracked API contract drift
  relative to the Git index. Generated OpenAPI copy consistency is OK, but
  release evidence for `proto-verify` cannot be recorded until the proto
  inputs, generator config, OpenAPI normalizer, generated Go/gateway files,
  published docs spec, and bundled WebUI spec are accepted together in source
  control.
- Readiness and `ngfwctl system release-acceptance-status` now make that split
  explicit: functional proto/OpenAPI generation can be validated with
  `make proto-status` and `make proto-verify`, while source-control
  recordability is shown as a separate acceptance blocker for `proto-verify`
  release evidence. The WebUI source-acceptance model exposes blocker counts
  and status without broadening dirty-path disclosure beyond the existing
  detailed release-acceptance drawer rules.

Current remaining blockers before enterprise-ready acceptance (separate from
hardening-only production controls):

- Source-tree recordability is still blocked until the API contract bundle and
  other dirty/untracked source changes are accepted together. Release evidence
  generated from this dirty worktree remains continuation evidence.
- `release/acceptance.json` is still absent in this checkout, and release
  acceptance remains incomplete until required rootless, privileged, field,
  content, auth, benchmark/no-claims, and WebUI enterprise-smoke evidence is
  regenerated through the repo-local release tooling for an accepted source
  snapshot.
- Existing recorded evidence for some gates is stale or invalid and must be
  regenerated through the real required paths, including `e2e-install` and the
  OIDC provider lifecycle sentinels.
- Missing or unaccepted repo-local evidence still needs a clean accepted source
  snapshot plus release-tool recording for the full release gate set. The
  currently absent durable artifacts include `proto-verify`,
  `privileged-integration`, `policy-restore-drill`,
  `ha-readiness-recovery`, `content-production-readiness`,
  `release-benchmark` or the explicit no-performance-claims manifest path,
  `m3-live-networking`, `m3-field-evidence`, `ebpf-ol9-field-evidence`,
  `m5-oidc-field-evidence`, `m5-saml-field-evidence`, and
  `webui-enterprise-smoke`.
- Older pre-closure acceptance snapshots that listed durable rule identity,
  Proxy/WAF runtime readiness, real-provider OIDC/SAML evidence, QoS/DoS proof,
  Fleet orchestration, and DNS/URL/file layered-control work as functional gaps
  have been superseded by the bounded functional slices recorded above. Current
  accepted-source blockers are source-tree recordability, stale or missing
  repo-local release evidence, and final acceptance manifest generation.
  Production custody, certification, scale, active rollout, signing, HA/fleet
  proof, and supply-chain controls remain hardening/follow-on items tracked in
  `docs/HARDENING_BACKLOG.md`.

Threat-intel custom feed egress baseline slice:

- Operator-defined custom feed URLs now use a shared Go guardrail in
  `internal/intel.ValidateFeedURL` before policy validation and runtime fetch.
  It preserves HTTP(S) support for external feeds while rejecting URL userinfo,
  loopback, private, link-local, local, multicast/unspecified, scoped IPv6, and
  known metadata destinations such as `169.254.169.254` and cloud metadata
  hostnames.
- The default feed HTTP client revalidates redirect destinations before
  following them, and fetch errors no longer echo the raw feed URL into logs or
  callers.
- WebUI custom-feed preflight now mirrors the baseline destination block and
  the drawer note tells operators that feed URLs must avoid URL credentials,
  secret query keys, and local/private/metadata destinations.
- Regression coverage was added for unsafe policy URLs, unsafe runtime fetch
  URLs, unsafe redirects, WebUI normalization, and an `/intel` visual-smoke
  negative form assertion for metadata URLs.
- Hardening backlog was narrowed to the remaining production items: explicit
  allowlist governance for exceptional internal feeds, resolver/dial-time DNS
  rebinding defense, TLS policy/exception handling, refresh rate limits,
  response line/parse-cost limits, broader URL redaction audit, durable feed
  IDs, audit intent, and license attestation custody.

Additional remote validation for the threat-intel custom feed egress baseline
slice on `opc@139.87.66.128`:

- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache go test -count=1 ./internal/intel ./internal/policy -run 'TestFetch|TestDefaultHTTPClientRejectsUnsafeRedirect|TestValidateIntelCustomFeedURL'`
- `node --check internal/webui/static/js/content_posture.js`
- `node --check internal/webui/static/js/intel_content.test.mjs`
- `node --check internal/webui/static/js/views/intel.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/intel_content.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/intel WEBUI_SMOKE_SCREEN_TIMEOUT_MS=120000 WEBUI_SMOKE_TOTAL_TIMEOUT_MS=600000 WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-intel-feed-egress-r5 make webui-visual-smoke`

Notes from this validation pass:

- The `/intel` browser-required smoke now proves the existing content
  lifecycle drawers plus the new custom-feed unsafe destination rejection
  across desktop, tablet, and mobile.
- The visual-smoke harness now scopes route readiness checks to the direct
  app-shell loader (`#content > .loading`) instead of any nested component
  spinner, and the Intel API/CLI drawer cleanup now waits for `/intel` after
  closing the Intel quality drawer instead of incorrectly waiting for
  `/readiness`.
- The remote host hit generated Go temp pressure before the final browser run.
  Only generated `/home/opc/oss-ngfw-smoke-tmp/go-build*` directories were
  removed; root free space moved from about 395 MiB to about 1.4 GiB before the
  successful rerun.

Changes compliance-profile report builder slice:

- The browser-local `Audit report builder` now acts as a functional compliance
  report builder for the visible audit window. Operators can select
  Operational, Change control, Privileged access, Content lifecycle, or
  Incident evidence profiles before copying or exporting the unsigned
  `phragma.audit.report.v1` JSON packet.
- The exported packet now includes a `compliance` object with selected profile
  metadata, matched entry counts, control pass/review totals, and
  profile-specific controls for audit integrity, profile coverage, actor
  attribution, change traceability, hash evidence, and custody boundary.
- The drawer renders a compact Compliance coverage review so operators can see
  which controls passed and which require review before handing the packet to
  CAB, SecOps, or audit stakeholders.
- `docs/GUI_GAP_ANALYSIS.md` no longer treats the basic compliance report
  builder as deferred. The deferred scope is now signed/server-retained
  compliance reporting with retention, RBAC, scheduling, and custody policy.
  `docs/HARDENING_BACKLOG.md` keeps those production controls in Audit
  retention and export custody.

Additional remote validation for the Changes compliance-profile report builder
slice on `opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/changes.js`
- `node --check internal/webui/static/js/changes_audit.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/changes_audit.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/changes WEBUI_SMOKE_SCREEN_TIMEOUT_MS=120000 WEBUI_SMOKE_TOTAL_TIMEOUT_MS=600000 WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-changes-compliance-report-r2 make webui-visual-smoke`

Notes from this slice:

- The first browser rerun proved tablet/mobile but caught a desktop audit-entry
  drawer overflow while the drawer slide-in animation was still settling. The
  smoke now waits for the drawer's right edge to settle inside the viewport
  before measuring overflow, which keeps the layout assertion focused on final
  UI geometry rather than animation in-flight state.

Automation recorder shell-runbook slice:

- The browser-local multi-route automation recorder now exports more than the
  aggregate JSON packet. Operators can copy or download a generated shell
  runbook from the recorded `phragma.webui.automation-recorder.v1` steps.
- The runbook is generated client-side from the existing normalized
  workflow-session packets. It emits a bash header, `PHRAGMA_API_ORIGIN` and
  `PHRAGMA_TOKEN` placeholders, an API-contract check, route comments, REST
  `curl` commands, CLI equivalents, and any route workflow steps such as
  validate, diff, commit, and rollback. Browser-session-only endpoints are
  rendered as comments rather than fake bearer-token curls.
- The API/CLI drawer footer also exposes a copy action for the current
  recorder runbook, while the recorder panel exposes copy/download actions for
  the aggregate shell runbook. The existing JSON copy/download path remains
  unchanged.
- This is still browser-local and unsigned. Server-side retention, signatures,
  identity binding, replay validation, retention/custody policy, and governance
  enforcement remain hardening work in `docs/HARDENING_BACKLOG.md`.

Additional remote validation for the automation recorder shell-runbook slice on
`opc@139.87.66.128`:

- `node --check internal/webui/static/js/automation_context.js`
- `node --check internal/webui/static/js/automation_context.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/ WEBUI_SMOKE_SCREEN_TIMEOUT_MS=120000 WEBUI_SMOKE_TOTAL_TIMEOUT_MS=600000 WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-automation-runbook-r3 make webui-visual-smoke`

Notes from this slice:

- The first browser run failed before UI validation because the remote host had
  only about 391 MiB free and Go compilation hit `no space left on device`.
  Only generated `/home/opc/oss-ngfw-smoke-tmp/go-build*` directories and the
  smoke Go cache were removed; root free space increased to about 1.6 GiB
  before the successful rerun.
- The dashboard browser smoke now proves the multi-route recorder path on
  desktop by recording Dashboard, Traffic, Threats, and Settings in one browser
  session, copying the JSON packet, copying the shell runbook, downloading the
  shell runbook, and checking redaction. Tablet and mobile still exercise the
  normal Dashboard API/CLI drawer and recorder one-step path.

After moving, the useful first checks are:

```sh
git status --short
make proto-status
make webui-check
make proto-verify
make test
```

Run privileged and field validation only on an appropriate Linux host:

```sh
make integration-compile
sudo make integration-test
make release-check-rootless
```

Use `docs/testing-plan.md`, `docs/testing-plan-ol9.md`, and
`docs/RELEASE_ACCEPTANCE.md` for the complete field evidence plan.

Bounded Suricata-backed App-ID deny slice:

- Signal-only App-ID deny rules now have a functional L7 enforcement path when
  IDS is enabled in Prevent mode with fail-closed behavior. The initial
  supported engine signals are Suricata app-layer labels `http`, `tls`, `dns`,
  and `ssh`.
- Validation keeps the slice intentionally narrow: signal-only App-ID rules
  must be `ACTION_DENY`, cannot combine explicit services, require IDS Prevent
  plus fail-closed, require at least one supported engine signal, and currently
  require broad any/any scope until Suricata zone/interface/address parity is
  implemented.
- The compiler now preserves App-ID signal metadata, marks signal-only rules as
  L7-only so nftables does not render a broad any-service drop, and emits
  deterministic generated Suricata drop IR entries.
- The Suricata renderer now includes a managed `openngfw-appid.rules` rule file
  and comment-embedded generated `drop` signatures using
  `app-layer-protocol:<signal>`. The Suricata engine extracts those rules before
  validation/apply. It also renders managed classification/reference config
  paths so `suricata -T` does not depend on host-global `/etc/suricata` files.
- This remains bounded deny support, not full App-ID allow/block semantics.
  Durable generated SID allocation, engine-signal governance/version
  compatibility, scoped Suricata rule parity, first-packet leakage behavior,
  NFQUEUE saturation/crash behavior, real traffic field evidence, and complete
  L7/App-ID breadth remain tracked in `docs/HARDENING_BACKLOG.md`.

Additional remote validation for the bounded Suricata-backed App-ID deny slice
on `opc@139.87.66.128`:

- `GOFLAGS=-buildvcs=false go test ./internal/policy ./internal/compiler ./internal/renderers/suricata ./internal/renderers/nftables ./internal/engines`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache GOFLAGS=-buildvcs=false go test ./internal/...`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`

Notes from this slice:

- The first remote `suricata -T` run exposed unprivileged test-host dependence
  on `/etc/suricata/classification.config` and `/etc/suricata/reference.config`.
  The renderer/engine now use managed metadata files under the OpenNGFW Suricata
  rules directory, and the remote renderer test passes with Suricata 7.0.15.

App-ID bounded-deny contract/UI consistency slice:

- Explain-flow now recognizes bounded signal-only App-ID denies when the
  observed `app_id` is either the canonical application name or a supported
  Suricata app-layer signal and IDS/IPS is Prevent fail-closed. Port-hint
  App-ID evidence remains separate and still explains TCP/UDP hint matching.
- The Rules editor now permits signal-only App-ID deny staging only under the
  same functional preconditions as backend validation: Drop action, no explicit
  service refs, supported Suricata signal, broad any/any scope, and IDS/IPS
  Prevent fail-closed in the candidate. The editor copy now distinguishes the
  port-hint path from the Suricata App-ID signal path.
- Objects hygiene and API documentation now describe no-port-hint App-ID
  objects as enforceable only through either TCP/UDP port hints or the bounded
  broad Suricata signal path, rather than saying signal-only enforcement is
  universally future-only.

Additional remote validation for the App-ID bounded-deny contract/UI
consistency slice on `opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/rules.js`
- `node --check internal/webui/static/js/views/objects.js`
- `node --check internal/webui/static/js/rules_editor.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/rules_editor.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache GOFLAGS=-buildvcs=false go test ./internal/explain ./internal/policy ./internal/compiler ./internal/renderers/suricata ./internal/renderers/nftables`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache GOFLAGS=-buildvcs=false go test ./internal/...`

Traffic App-ID signal-only review-drop alignment slice:

- Traffic-origin Custom App-ID review now exposes the bounded signal-only path:
  `Review drop rule` accepts App-ID objects with supported Suricata signals
  (`dns`, `http`, `ssh`, `tls`) even when they have no TCP/UDP port hints, and
  generates a broad App-ID deny rule for the shared Rules editor to validate.
- The generated signal-only review rule intentionally omits source/destination
  address scoping because current Suricata App-ID drop signatures do not yet
  have zone/interface/address parity with nftables. The Rules editor still
  requires IDS/IPS Prevent fail-closed before staging that broad signal-only
  deny.
- One-click queue `Save & drop` remains on the existing server-owned
  `DEFINE_AND_DROP` API path and still requires a TCP/UDP port hint. The UI now
  explains that operators should use `Review drop rule` for supported
  signal-only App-ID denies.
- `docs/webui-design.md`, `docs/build-plan.md`, and `docs/testing-plan.md` now
  describe the bounded signal-only deny path instead of treating every
  engine-signal-only App-ID rule as future-only.

Additional remote validation for the Traffic App-ID signal-only review-drop
alignment slice on `opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/traffic.js`
- `node --check internal/webui/static/js/appid_observations.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/appid_observations.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache GOFLAGS=-buildvcs=false go test ./internal/...`

Troubleshoot explanation timeline slice:

- Troubleshoot now renders a first-class `Explanation timeline` card before the
  detailed runtime, inspection, NAT, route, evidence, trace, and warning cards.
  The timeline turns existing `ExplainFlow` fields into an ordered operator
  decision chain: flow tuple, destination NAT, policy rule/default decision,
  App-ID evidence, inspection posture, route decision, source NAT, runtime
  correlation, and warning review.
- The timeline is browser-local presentation over existing ExplainFlow/runtime
  data. It does not change the public API contract, candidate state, runtime
  engines, packet-capture lifecycle, or the existing running-vs-candidate
  compare behavior.
- `docs/GUI_GAP_ANALYSIS.md` now marks the Gap 2 explanation-timeline surface as
  functionally covered. Deeper event-time policy stamps for all telemetry
  sources and production custody for copied/exported explanation packets remain
  follow-on hardening/evidence work already represented by telemetry/custody
  backlog boundaries.

Additional remote validation for the Troubleshoot explanation timeline slice on
`opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/troubleshoot.js`
- `node --check internal/webui/static/js/troubleshoot_view.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/troubleshoot_view.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/troubleshoot WEBUI_SMOKE_SCREEN_TIMEOUT_MS=120000 WEBUI_SMOKE_TOTAL_TIMEOUT_MS=600000 WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-troubleshoot-timeline-r1 make webui-visual-smoke`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache GOFLAGS=-buildvcs=false go test ./internal/...`

Settings Access lifecycle review slice:

- Settings Access now includes an `Access lifecycle review` drawer alongside
  Configure OIDC, Prepare SAML, OIDC preflight, and local-user actions. The
  drawer combines access inventory availability, backend access blockers,
  break-glass local admin recovery, OIDC/SAML provider posture, active browser
  SSO session counts, audit links, exact public API endpoints, and `ngfwctl`
  parity into one operator handoff.
- The review can be copied, exported as
  `phragma.access.lifecycle-review.v1`, or pinned into Investigation. The
  copied/exported packet uses existing public access APIs only and does not
  mutate provider config, local users, sessions, or candidate policy.
- The model intentionally uses placeholders for session-revoke commands and
  keeps generated tokens, server-local secret paths, SAML assertion material,
  certificate fingerprints, and full browser-session IDs out of copied review
  text. Existing provider save/disable and local-user workflows still require
  backend audit comments and acknowledgement flags.
- `docs/ROADMAP.md` now records the functional IdP/break-glass lifecycle review
  coverage. `docs/HARDENING_BACKLOG.md` keeps real-provider field evidence,
  trusted-proxy/browser-CSRF evidence, MFA/step-up policy, certificate rollover,
  signed/server-side lifecycle evidence custody, and secret custody as hardening
  work.

Additional remote validation for the Settings Access lifecycle review slice on
`opc@139.87.66.128`:

- `node --check internal/webui/static/js/views/settings.js`
- `node --check internal/webui/static/js/access_governance.js`
- `node --check internal/webui/static/js/settings_access.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/settings_access.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache GOFLAGS=-buildvcs=false go test ./internal/apiserver ./internal/cli ./internal/authz`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/settings WEBUI_SMOKE_SCREEN_TIMEOUT_MS=120000 WEBUI_SMOKE_TOTAL_TIMEOUT_MS=600000 WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-access-lifecycle-r1 make webui-visual-smoke`

Readiness eBPF attach-drill handoff slice:

- Readiness now builds a browser-local `phragma.ebpf.drill-evidence.v1` packet
  from the already-loaded eBPF host readiness, attach-drill, renderer scaffold,
  live attachment inventory, indexed artifact, and release-gate metadata. The
  packet is explicit that it does not certify active eBPF dataplane cutover and
  that `nftables/conntrack` remains the active dataplane.
- The XDP/tc readiness card now exposes `Drill handoff`, `Field evidence`, and
  `Copy drill` actions. The drill drawer is route-backed at
  `#/readiness?drawer=ebpf-drill`, can copy the operator evidence text, export
  browser-local JSON, or pin the handoff into Investigation.
- Browser smoke now opens the eBPF drill drawer on `/readiness`, verifies the
  schema, active-dataplane boundary, copy/export/pin actions, and basic
  secret/path leak boundaries while preserving the existing responsive probe
  table checks.
- `docs/ROADMAP.md` now records the functional eBPF handoff coverage and
  leaves runtime attachment probe proof as the next functional validation item.
  `docs/HARDENING_BACKLOG.md` keeps signed/server-side evidence custody,
  verifier/object provenance, map lifecycle, traffic safety, rollback, and
  active eBPF cutover controls in the deferred hardening pass.

Additional remote validation for the Readiness eBPF attach-drill handoff slice
on `opc@139.87.66.128`:

- `node --check internal/webui/static/js/readiness_model.js`
- `node --check internal/webui/static/js/views/readiness.js`
- `node --check internal/webui/static/js/readiness_view.test.mjs`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/readiness_view.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/readiness WEBUI_SMOKE_SCREEN_TIMEOUT_MS=120000 WEBUI_SMOKE_TOTAL_TIMEOUT_MS=600000 WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-readiness-ebpf-drill-r1 make webui-visual-smoke`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache GOFLAGS=-buildvcs=false go test ./internal/ebpfdrill`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make ebpf-ol9-attach-drill-check`

The rootless attach-drill preflight reported `tool_clang=missing` and
`tool_ngfwctl=missing` on the remote host, but `--check` passed because it only
validates static assets and discloses the privileged collector prerequisites.

Readiness eBPF runtime-probe API/UI proof slice:

- The WebUI visual smoke harness now has an opt-in
  `WEBUI_SMOKE_EBPF_RUNTIME_EVIDENCE=1` mode. In that mode it starts the
  temporary dry-run control plane with `--ebpf-runtime-probes`,
  `--ebpf-attach-probe-interfaces openngfw-ebpf0`, and a seeded eBPF artifact
  directory, plus fixture `bpftool`, `clang`, `tc`, and `ip` commands in the
  smoke runtime `PATH`.
- The fixture makes `/v1/system/status` report `runtime-probes` evidence scope,
  attached XDP and tc rows for `openngfw-ebpf0` (`xdp_probe` and
  `tc_ingress`), hashed `manifest.txt` and `ebpf-plan.txt` artifacts, and
  `nftables/conntrack` as the active dataplane.
- The `/readiness` smoke now requires those same attachment and artifact rows
  when the opt-in flag is set, and separately fetches `/v1/system/status` to
  prove the API payload carries the same runtime attachment evidence that the
  UI renders.
- Focused backend and CLI tests still prove the `bpftool net` parser, opt-in
  runtime-probe behavior, and `ngfwctl system ebpf-readiness --json` output
  shape.
- The live OL9 disposable-interface collector path is now validated on
  `opc@139.87.66.128`. The host was prepared with `clang`, repo-built
  `controld` and `ngfwctl` binaries under
  `/home/opc/oss-ngfw-smoke-tmp/ebpf-live-tools`, a root dry-run control plane
  with `--ebpf-runtime-probes`, and a disposable `openngfw-ebpf0` dummy
  interface. `make ebpf-ol9-attach-drill` generated first-party XDP/tc probe
  sources, compiled them with `clang`, attached and detached XDP generic and tc
  clsact programs, inspected loaded programs with `bpftool`, cleaned the link,
  and validated `release/field-evidence/ebpf-ol9-live-r1` while preserving
  `active_dataplane=nftables/conntrack`. The standalone rootless validator then
  passed after the root-owned evidence bundle was chowned back to `opc`.
  Cleanup removed the root `controld` process and deleted `openngfw-ebpf0`.

Additional remote validation for the Readiness eBPF runtime-probe API/UI proof
slice on `opc@139.87.66.128`:

- `node --check e2e/webui-visual-smoke.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache GOFLAGS=-buildvcs=false go test -count=1 ./internal/apiserver ./internal/cli -run 'Ebpf|EBPF|eBPF|SystemEbpf|StatusEbpf'`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_EBPF_RUNTIME_EVIDENCE=1 WEBUI_SMOKE_PATHS=/readiness WEBUI_SMOKE_SCREEN_TIMEOUT_MS=120000 WEBUI_SMOKE_TOTAL_TIMEOUT_MS=600000 WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-ebpf-runtime-probe-r2 make webui-visual-smoke`

Additional remote validation for the live OL9 eBPF disposable-interface
collector proof on `opc@139.87.66.128`:

- `dnf -y install clang` installed the missing compiler package on the remote
  validation host.
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache GOFLAGS=-buildvcs=false go build -o /home/opc/oss-ngfw-smoke-tmp/ebpf-live-tools/controld ./cmd/controld`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache GOFLAGS=-buildvcs=false go build -o /home/opc/oss-ngfw-smoke-tmp/ebpf-live-tools/ngfwctl ./cmd/ngfwctl`
- `PATH=/home/opc/oss-ngfw-smoke-tmp/ebpf-live-tools:$PATH TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make ebpf-ol9-attach-drill-check`
- Started root `controld` with `--dry-run --allow-unauthenticated-local
  --listen 127.0.0.1:9443 --http-listen 127.0.0.1:18080
  --ebpf-runtime-probes --ebpf-attach-probe-interfaces openngfw-ebpf0
  --ebpf-artifact-dir release/field-evidence/ebpf-ol9-live-r1/drill`, then ran
  `sudo ip link add openngfw-ebpf0 type dummy` and `sudo ip link set
  openngfw-ebpf0 up`.
- `sudo -E PATH=/home/opc/oss-ngfw-smoke-tmp/ebpf-live-tools:$PATH TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache EBPF_OL9_ATTACH_IFACE=openngfw-ebpf0 EBPF_OL9_STATUS_JSON_COMMAND='ngfwctl system ebpf-readiness --json' make ebpf-ol9-attach-drill EBPF_OL9_FIELD_EVIDENCE_DIR=release/field-evidence/ebpf-ol9-live-r1`
- `make ebpf-ol9-field-evidence-check EBPF_OL9_FIELD_EVIDENCE_DIR=release/field-evidence/ebpf-ol9-live-r1`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache GOFLAGS=-buildvcs=false go test -count=1 ./internal/ebpfdrill ./cmd/ngfwebpfdrill`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache GOFLAGS=-buildvcs=false go test -count=1 ./internal/apiserver ./internal/cli -run 'Ebpf|EBPF|eBPF|SystemEbpf|StatusEbpf'`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs ./internal/webui/static/js/readiness_ebpf_evidence.test.mjs`
- `go test -tags integration -count=1 ./test/integration -run
  'TestReleaseEbpfOL9AttachDrill|TestReleaseEbpfOL9FieldEvidence'` was not a
  valid check in this remote copy because the integration test helper requires
  `git rev-parse --show-toplevel`, and the remote validation directory is not a
  Git worktree.
- The host remained disk-constrained at 99% used with roughly 540-570 MB free,
  so only generated Go temp/cache, validation binaries, and evidence artifacts
  were used. No local tests were run.

Net/VPN, Objects, Fleet/Readiness/Performance drill-through, and CLI VPN
inventory parity slice:

- `ngfwctl policy vpn list` / `show` now provides redacted running,
  candidate, and versioned VPN inventory. The CLI rejects unused
  `--version` values unless `--source version` is selected, includes source
  metadata in JSON output, redacts managed IPsec PSK and WireGuard private-key
  paths, omits WireGuard peer public keys, and adds peer-level endpoint and
  allowed-IP detail to table output for operator tunnel review.
- Routing & VPN browser smoke now proves candidate-only static-route add,
  edit, delete and valid IPsec add, edit, delete lifecycle, route-backed IPsec
  tunnel handoff from `#/netvpn?drawer=tunnel&kind=ipsec&name=site-smoke`,
  Changes candidate-review visibility, running-policy isolation, and VPN
  secret/path leak guards. The smoke cleanup now restores the pre-existing
  candidate rather than replacing it with running policy.
- Objects browser smoke now proves generic address, application, and security
  profile lifecycle parity: referenced delete review, route-backed references,
  duplicate-name guardrails, add/edit/delete, security-profile impact route
  state, candidate-only mutation, and running-policy isolation. The Objects
  UI now carries explicit button semantics and stable selectors for new,
  reference, editor save/cancel, handoff, impact, and rename-review actions.
- Candidate diff rendering now redacts managed VPN secret-path fields before
  Changes or commit-review surfaces render them, including both server and
  fallback diff lines.
- Fleet, Readiness, and Performance drill-through now proves Fleet links into
  HA cockpit and release acceptance, Readiness HA mutation dialogs are guarded
  and non-destructive by default in visual smoke unless
  `WEBUI_SMOKE_ALLOW_HA_MUTATIONS=1` is set, Performance publishable local
  benchmark evidence links into the Readiness `release-benchmark` packet, and
  Readiness exposes a route-backed `release-benchmark` evidence packet without
  overclaiming browser-local evidence as recorded backend release evidence.

Additional remote validation for this slice on `opc@139.87.66.128`
(`/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1`):

- `node --check e2e/webui-visual-smoke.mjs`
- `node --check internal/webui/static/js/views/objects.js`
- `node --check internal/webui/static/js/views/readiness.js`
- `node --check internal/webui/static/js/views/performance.js`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/object_references.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/readiness_view.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/performance.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/diff_view.test.mjs`
- `go test -count=1 ./internal/cli -run "TestStaticRoutePolicyRequestRejectsInvalidSource|TestReadVPNConfig|TestVPNConfig|TestPrintVPNConfig|TestPolicyCommandIncludesVPNList"`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/netvpn,/objects WEBUI_SMOKE_SCREEN_TIMEOUT_MS=120000 WEBUI_SMOKE_TOTAL_TIMEOUT_MS=600000 WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-netvpn-objects-lifecycle-r5 make webui-visual-smoke`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/fleet,/readiness,/performance WEBUI_SMOKE_SCREEN_TIMEOUT_MS=120000 WEBUI_SMOKE_TOTAL_TIMEOUT_MS=600000 WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-fleet-readiness-performance-drillthrough-r4 make webui-visual-smoke`

No local tests were run. New hardening requirements are covered by existing
VPN peer template/secret lifecycle, Fleet/template orchestration, HA and
restore security, Release evidence status disclosure, Performance evidence
verifier, Object/NAT dependency workflow, and Design-system hardening rows.

App-shell and Investigation route control-semantics slice:

- The static WebUI shell, access gate, candidate bar, runtime-readiness retry,
  pending-diff drawer, validation drawer, and commit-review drawer now expose
  explicit `type="button"` semantics, contextual `title` and `aria-label`
  text, and stable `data-app-action`, `data-candidate-bar-action`,
  `data-runtime-banner-action`, and `data-app-drawer-action` selectors.
- The Investigation route header, focused source workflow, remediation planner,
  case-row open/copy/remove, and copy/export/clear actions now expose stable
  selectors and accessible operator labels while preserving browser-local case
  custody and candidate-safe owner pivots.
- Dashboard management-plane wording now reports active local controls without
  claiming production certification while hardening items remain open.
- `app_shell_controls.test.mjs` pins the source contract, the Dashboard
  management-plane test pins the non-certification wording, and browser smoke
  now requires Investigation header actions to render with explicit button
  semantics.

Additional remote validation for this slice on `opc@139.87.66.128`
(`/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1`):

- `node --check internal/webui/static/js/app.js`
- `node --check internal/webui/static/js/views/investigation.js`
- `node --check internal/webui/static/js/views/dashboard.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/app_shell_controls.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/,/investigation WEBUI_SMOKE_SCREEN_TIMEOUT_MS=120000 WEBUI_SMOKE_TOTAL_TIMEOUT_MS=600000 WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-app-shell-investigation-actions-r1 make webui-visual-smoke`

No local tests were run.

Traffic drawer, Rules action controls, Readiness release-packet parity, release
skip-proofing, and object rename API/CLI parity slice:

- Traffic flow/session/App-ID detail drawers and traffic handoff controls now
  expose explicit drawer action semantics. Drawer footer controls render
  explicit button types, contextual titles and ARIA labels, and stable selectors
  for flow/session close, explain, capture, capture-audit, custom App-ID,
  allow/drop staging, App-ID observation promotion/API/CLI/capture/matching
  flows, regression-sample staging, custom App-ID save/review/drop actions, and
  Pin/Copy/Export handoff actions. Browser smoke now verifies rendered drawer
  and handoff controls, not only row actions.
- Rules toolbar, bulk, flow-check, rulebase-map, review drawer, baseline
  drawer, editor, and inline object controls now carry explicit operator
  semantics with stable selectors. Focused Rules JS tests pin the source
  contract, and `/rules` smoke proves the action controls across desktop,
  tablet, and mobile.
- Readiness release evidence packets now share a catalog that covers every
  `releaseEvidenceChecklist` packet. Readiness route state whitelists packet
  IDs deterministically, and API/CLI automation-context drawers now provide
  packet-specific commands/endpoints for each release gate instead of falling
  back to generic release status for most packets.
- Release acceptance assembly now binds recorded evidence through a manifest-
  relative `evidence/` directory, full 40-character commit identity, and
  source-tree recordability checks before evidence is accepted. The
  `release-benchmark` gate can be marked `not_applicable` only through the
  explicit no-performance-claims path; verification and status commands require
  the matching `--allow-no-performance-claims` acknowledgement, and the
  no-claims detail states that the tag publishes no throughput, latency,
  connection-rate, or comparison claims.
- Privileged integration release evidence now records through
  `release/privileged-integration-no-skip.sh`. The wrapper rejects any skipped
  privileged integration transcript and emits required release-acceptance
  markers including `privileged_integration_skip_policy=no-skipped-tests`,
  `skipped_tests=0`, and `status=passed`.
- Readiness release-packet command drawers now surface the privileged command
  shape for gates that require Linux root, including `sudo make e2e-install`
  and the privileged integration wrapper, but these are copy/runbook commands;
  opening Readiness does not execute privileged host changes or record release
  evidence.
- Policy object rename/reference rewrite now has backend and CLI parity.
  `RenamePolicyObject` stages a candidate-only object rename and rewrites
  candidate references across security rules, host-input, NAT, and IDS
  exception address scopes. `ngfwctl policy rename-object` exposes the same
  workflow for CLI/API automation.

Additional remote validation for this slice on `opc@139.87.66.128`
(`/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1`):

- `node --check internal/webui/static/js/views/traffic.js`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/appid_observations.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/traffic WEBUI_SMOKE_SCREEN_TIMEOUT_MS=120000 WEBUI_SMOKE_TOTAL_TIMEOUT_MS=600000 WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-traffic-drawer-actions-r3 make webui-visual-smoke`
- `node --check internal/webui/static/js/readiness_model.js`
- `node --check internal/webui/static/js/views/readiness.js`
- `node --check internal/webui/static/js/automation_context.js`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/readiness_model.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/readiness_view.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache go test ./internal/releaseacceptance ./cmd/ngfwrelease`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache go test -tags integration -run TestPrivilegedIntegrationWrapper -count=1 -v ./test/integration`
- `node --check internal/webui/static/js/views/rules.js`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/rules_action_controls.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/rules_bulk_density.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/rules_editor.test.mjs`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/rules WEBUI_SMOKE_SCREEN_TIMEOUT_MS=120000 WEBUI_SMOKE_TOTAL_TIMEOUT_MS=600000 WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-rules-action-controls-r2 make webui-visual-smoke`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache go test -count=1 ./internal/apiserver ./internal/cli -run "TestPolicyListObjectReferences|TestPolicyRenameObject|TestRunPolicyRenameObject"`

No local tests were run by the main agent. One object API/CLI worker reported
running local `make proto` in its fork before returning generated files; the
resulting generated/API outputs were treated as untrusted until the synced
remote checkout compiled and passed targeted API/CLI validation. Existing
Design-system, Release evidence provenance and skip-proofing, API contract
source acceptance, Object/NAT dependency workflow, App-ID enforcement, and
Rulebase comprehension hardening rows cover the remaining production hardening
requirements for these slices.

Release manifest, Readiness command, Net/VPN overflow, Fleet, and
Troubleshoot/Investigation action-semantics slice:

- Field evidence bundle validation now requires exact `manifest.sha256`
  regular-file coverage and rejects unsupported non-regular bundle entries,
  including FIFOs/devices/sockets, in addition to symlink escapes, missing
  files, extra files, duplicate entries, and digest mismatches. The shared
  manifest verifier uses a temporary workspace and the release scripts continue
  to emit `manifest_sha256_policy=required,exact-regular-files,no-extra-files`.
- Readiness release-acceptance smoke now accepts the current privileged
  integration evidence workflow. It requires the no-skip validation command and
  verifies either the Makefile recorder target or the direct
  `ngfwrelease record --check privileged-integration -- ...` approved command
  shape instead of the older raw `make integration-test` expectation.
- Net/VPN route-backed tunnel drawers now contain path-check rows and handoff
  actions without horizontal pressure. The browser smoke now reports actionable
  child overflow diagnostics and ignores drawer animation/right-edge geometry
  plus form-control internal scroll width that does not create visible layout
  overflow.
- Fleet API/CLI controls expose explicit button semantics, contextual labels,
  and stable action attributes.
- Troubleshoot clear, explain, compare, stage, handoff, correlated runtime
  pivot, and packet-capture controls now expose explicit operator semantics.
  Investigation empty-state navigation and cockpit actions have route/action
  datasets and accessible labels.

Additional remote validation for this slice on `opc@139.87.66.128`
(`/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1`):

- `bash -n release/manifest-sha256.sh`
- `node --check e2e/webui-visual-smoke.mjs`
- `node --check internal/webui/static/js/views/troubleshoot.js`
- `node --check internal/webui/static/js/views/investigation.js`
- `node internal/webui/static/js/troubleshoot_view.test.mjs`
- `node internal/webui/static/js/investigation_view.test.mjs`
- `go test -tags=integration ./test/integration -run "TestReleaseM3FieldEvidenceCheck(AcceptsCompleteBundle|RejectsBundleSymlinkEscape|RejectsExtraManifestFile|RejectsNonRegularBundleEntry)$" -count=1 -v`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/readiness WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-readiness-privileged-command-r2 make webui-visual-smoke`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/netvpn WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-netvpn-overflow-r5 make webui-visual-smoke`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/troubleshoot,/investigation WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-troubleshoot-investigation-actions-r1 make webui-visual-smoke`
- Broad route sweep:
  `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/,/setup,/dashboard,/rules,/objects,/nat,/traffic,/threats,/inspection,/intel,/netvpn,/readiness,/changes,/logs,/settings,/performance,/fleet,/investigation,/troubleshoot WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-enterprise-route-sweep-r2 make webui-visual-smoke`
  passed every desktop and tablet route and all mobile routes through Changes,
  including Net/VPN and Readiness, then hit the smoke runner's 20-minute total
  runtime limit at final mobile Settings without an assertion failure.
- Follow-up targeted Settings proof:
  `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/settings WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-settings-post-sweep-r1 make webui-visual-smoke`
  passed desktop, tablet, and mobile.

Additional remote validation for the HA fencing evidence operator-surfacing
slice on `opc@139.87.66.128`
(`/home/opc/oss-ngfw-v2-mixed-work/ha-fencing-surfacing-r1`):

- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make proto`
- `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache go test -count=1 ./internal/apiserver ./internal/cli -run "HighAvailability|HA|StatusShowsHighAvailability|FencingEvidence"`
- `node --check internal/webui/static/js/readiness_model.js`
- `node --check internal/webui/static/js/views/readiness.js`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/readiness_model.test.mjs`

No local functional, Go, or browser tests were run. A local `node --check` was
used on `e2e/webui-visual-smoke.mjs` before remote sync; all functional
validation listed above ran on the Linux host. The broad route sweep no longer
reports the prior Readiness command assertion or Net/VPN overflow failures; it
timed out on the runner's total runtime budget at final mobile Settings, then a
targeted Settings run passed. The remaining broad sweep work is runtime-budget
tuning so the full route list can complete in one command, or explicit
broad-plus-targeted evidence if the single-command budget remains too tight.
Remaining hardening is tracked in `docs/HARDENING_BACKLOG.md`, especially stale
release-evidence quarantine, artifact signing/provenance, full keyboard/focus
audit, and production field-evidence custody.

WebUI enterprise smoke runtime-budget reliability slice:

- `e2e/webui-visual-smoke.mjs` now treats `WEBUI_SMOKE_PATHS` as an ordered
  route plan instead of only a filter. The enterprise Makefile target's route
  order now takes effect, so `/settings` runs before the remaining
  Performance/Fleet/Investigation/Troubleshoot routes instead of being pushed
  to the end by the script's built-in screen order.
- The smoke runner now accepts `/dashboard` as an alias for `/`, de-duplicates
  repeated route aliases, and fails fast on unknown `WEBUI_SMOKE_PATHS` entries
  instead of silently dropping them.
- Broad sweeps now log selected route order, total route-check count,
  per-route elapsed checkpoints, and a timeout progress summary with completed
  count, active route, active elapsed time, and recent route durations. Route
  assertions remain unchanged; the change is runtime-budget observability and
  execution ordering only.
- No local functional, Go, browser, or JavaScript validation was run for this
  slice.

Remote validation for this slice on `opc@139.87.66.128`
(`/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1`):

- `node --check e2e/webui-visual-smoke.mjs` passed after syncing the smoke
  runner and docs.
- Bounded route-order probe:
  `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/settings,/performance WEBUI_SMOKE_SCREEN_TIMEOUT_MS=180000 WEBUI_SMOKE_TOTAL_TIMEOUT_MS=900000 WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-runtime-budget-order-r1 node e2e/webui-visual-smoke.mjs`
  proved the selected order was `/settings,/performance` and attempted
  Settings before Performance. The original run exposed Settings OIDC lifecycle
  assertions: desktop disable returned `enabled:true` after the disable
  workflow, and mobile save observed the previous tablet client ID instead of
  the expected mobile client ID. That was an assertion failure, not a total
  runtime timeout; it was later superseded by the Settings OIDC lifecycle
  stability slice above, which passed the same `/settings,/performance`
  browser-required route-order proof across desktop, tablet, and mobile.
- Bounded passing representative run:
  `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache PLAYWRIGHT_BROWSERS_PATH=/home/opc/oss-ngfw-v2-mixed-work/run-20260620-saml-provider-lifecycle-r1/.playwright-browsers WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/performance,/fleet WEBUI_SMOKE_SCREEN_TIMEOUT_MS=180000 WEBUI_SMOKE_TOTAL_TIMEOUT_MS=900000 WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-runtime-budget-order-r2 node e2e/webui-visual-smoke.mjs`
  passed via Playwright across desktop, tablet, and mobile, with the runner
  logging route order `/performance,/fleet` and all 6 route checks completed.

Integrated parallel-round validation on `opc@139.87.66.128`
(`/home/opc/oss-ngfw-v2-mixed-work/integration-20260621-parallel-round2-r1`)
covered the runtime-budget runner, API contract/source-acceptance visibility,
Logs/Dashboard/Diagnostic UI hardening, release-evidence provenance/status
disclosure, and packet-capture integrity posture together. The integrated pass
ran `go test -count=1 ./internal/releaseacceptance ./cmd/ngfwrelease
./internal/cli`, JS syntax checks for the changed WebUI modules and smoke
runner, focused JS tests for packet capture, capture evidence, investigation
packets, Troubleshoot, Readiness, design system, and responsive tables, then
`make webui-check`; all passed. A browser-required representative smoke on the
same integrated checkout reused the existing remote Playwright dependency cache
and passed `WEBUI_SMOKE_PATHS=/performance,/fleet` across desktop, tablet, and
mobile with all 6 route checks completed. No local functional tests were run.

WebUI handoff/export redaction coverage for release provenance and
packet-capture integrity:

- `internal/webui/static/js/investigation_packet.js` now exports packet-capture
  handoff artifacts through a bounded capture-specific shape instead of copying
  raw capture plan/job objects. Capture output paths, copied commands, details,
  warnings, URL query secrets, URL credentials, and bearer tokens are redacted;
  artifact IDs and filenames are retained only when they match safe capture
  identifier rules. Review-needed integrity labels remain visible without
  leaking server-local paths or unsafe artifact IDs.
- `internal/webui/static/js/packet_capture.js` now derives capture download URLs
  only from the normalized safe artifact ID, so caller-provided download paths
  cannot carry traversal segments or query secrets into copied/exported capture
  references.
- Focused JS coverage was added in `investigation_packet.test.mjs`,
  `packet_capture.test.mjs`, and `automation_context.test.mjs` for
  review-needed capture integrity exports, unsafe capture artifact IDs,
  release-packet route context redaction, and bearer/query-secret/path
  disclosure checks.
- No local functional tests were run. Remote validation on `opc@139.87.66.128`
  in
  `/home/opc/oss-ngfw-v2-mixed-work/integration-20260621-parallel-round2-r1`
  passed:
  `node --check internal/webui/static/js/investigation_packet.js`;
  `node --check internal/webui/static/js/packet_capture.js`;
  `node --check internal/webui/static/js/automation_context.js`;
  `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/investigation_packet.test.mjs`;
  `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/packet_capture.test.mjs`;
  `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/automation_context.test.mjs`;
  and
  `TMPDIR=/home/opc/oss-ngfw-smoke-tmp GOTMPDIR=/home/opc/oss-ngfw-smoke-tmp/go-tmp GOCACHE=/home/opc/oss-ngfw-smoke-tmp/go-cache make webui-check`.

Integrated parallel-round validation on `opc@139.87.66.128`
(`/home/opc/oss-ngfw-v2-mixed-work/integration-20260621-parallel-round3-r1`)
covered release status review-needed CLI guidance, deploy-hardening readiness
visibility, Changes cleanup/preserve guidance, Object/NAT invalid-editor
candidate safety, and WebUI handoff/export redaction in one checkout. The
integrated pass ran `go test -count=1 ./internal/releaseacceptance
./cmd/ngfwrelease ./internal/cli`, JS syntax checks for the changed
Objects/NAT/Changes/Readiness/capture/automation modules, focused JS tests for
Object references, NAT path preview, Changes candidate review, Changes audit,
Readiness, investigation packets, packet capture, and automation context, then
`make webui-check`; all passed. After that integrated pass, the Settings/OIDC
lifecycle stability fix was synced into the same remote checkout and validated
with `node --check` for Settings/access governance and the smoke runner,
`node internal/webui/static/js/settings_access.test.mjs`, `make webui-check`,
and the exact browser-required `/settings,/performance` route-order proof that
previously failed. All desktop, tablet, and mobile route checks passed via
Playwright. No local functional tests were run.

Telemetry export server-side proof slice:

- `SystemService.VerifyTelemetryExport` is now exposed as
  `POST /v1/system/telemetry/exports:verify`. The endpoint requires explicit
  `ackTestEvent`, loads the committed/running telemetry policy, selects only an
  enabled configured export by name/type/target, and emits one bounded
  synthetic newline-delimited JSON proof event. JSON-file exports append under
  the configured telemetry export root with symlink, directory, and root-escape
  checks; TCP/UDP exports use a bounded dial/write path. Dry-run telemetry
  configurations return simulation evidence instead of writing or sending.
- The response includes a proof ID, running policy version, export/protocol
  details, byte count, event hash, bounded evidence text, state/detail, and
  warnings for remaining custody gaps. It intentionally labels receiver
  custody, ClickHouse row delivery, and unsigned synthetic event status as
  warnings rather than claiming production attestation.
- RBAC now treats `VerifyTelemetryExport` as admin-only. Focused Go coverage
  proves JSON-file append, TCP send, missing-ack rejection, and unknown-export
  rejection. API contract coverage proves the REST path and WebUI client shape.
- Settings telemetry actions now include `Send test event` when a configured
  export is available. The guarded confirmation calls the server proof API and
  opens a compact proof drawer with export, protocol, target, bytes, event
  hash, evidence, and warnings. Settings action-control tests cover the new
  server-proof and close actions.
- The custom OpenAPI overlay now covers the local Fleet and Compliance JSON
  routes that are implemented outside proto generation, so generated
  `docs/api-spec.yaml`, `internal/webui/static/api-spec.yaml`, and
  `api/gen/openapi/` stay aligned with the API contract surface while the
  proto-backed telemetry endpoint is regenerated.

Remote validation for this slice on `opc@139.87.66.128`
(`/home/opc/oss-ngfw-v2-mixed-work/telemetry-verify-20260622-r1`):

- `make proto`
- `node --check internal/webui/static/js/api.js`
- `node --check internal/webui/static/js/views/settings.js`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/api_contract_surface.test.mjs`
- `node --require ./internal/webui/static/js/node_test_polyfills.cjs internal/webui/static/js/settings_action_controls.test.mjs`
- `go test ./cmd/ngfwopenapi ./internal/apiserver ./internal/authz -run 'TestOverlay|TestVerifyTelemetryExport|TestTelemetryExportStatus|TestTelemetryLocalFileEvidence|TestRBAC|Test.*Route' -count=1`
- `make webui-check`
- Browser-required targeted Settings proof:
  `WEBUI_SMOKE_REQUIRE_BROWSER=1 WEBUI_SMOKE_PATHS=/settings WEBUI_SMOKE_ARTIFACT_DIR=/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-telemetry-verify-r1 make webui-visual-smoke`
  passed desktop, tablet, and mobile. Manifest:
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-telemetry-verify-r1/webui-smoke-evidence.json`.

No local functional, Go, JavaScript, or browser tests were run for this slice.
Remaining hardening is tracked in `docs/HARDENING_BACKLOG.md`: receiver
custody and attestation, ClickHouse/SIEM delivery proof, signed proof packets,
retention/pruning, RBAC split/rate limits for proof actions, replay validation,
TLS/auth policy, and cross-surface redaction parity.

Integrated replay, policy-context, proxy-plan, QoS/DoS, and step-up validation
refresh:

- A fresh remote integrated copy at
  `/home/opc/oss-ngfw-v2-mixed-work/integration-current-20260622-r1` on
  `opc@139.87.66.128` was used to validate the current dirty worktree after the
  replay slices, policy-context slices, traffic-control slices, proxy/WAF plan
  slice, and privileged step-up slice were present together.
- Remote `make proto` passed, then focused JavaScript syntax and contract tests
  passed for API, Traffic, Threats, Objects, Rules, Readiness, automation
  context, step-up token storage, App-ID observations, and Threats request
  state. Focused Go validation passed for `./internal/authz`,
  `./internal/apiserver`, `./internal/replayvalidation`, `./internal/appid`,
  `./internal/threatid`, `./internal/policy`, `./internal/compiler`,
  `./internal/explain`, `./internal/renderers`, `./internal/renderers/proxy`,
  and `./internal/renderers/netdev`; `make webui-check` also passed in that
  remote copy.
- Generated API outputs and docs/WebUI OpenAPI specs were synced back from the
  remote proto run. This is continuation evidence for integration health, not
  durable release evidence; release evidence still needs to be regenerated from
  an accepted source snapshot through repo-local release tooling.

Traffic-control object-kind API parity slice:

- `PolicyObjectKind` now includes concrete `POLICY_OBJECT_KIND_QOS_PROFILE`
  and `POLICY_OBJECT_KIND_ZONE_PROTECTION_PROFILE` enum values. Reverse
  reference and candidate rename flows no longer have to map Objects traffic
  controls to `POLICY_OBJECT_KIND_UNSPECIFIED`.
- `ListObjectReferences` and `RenamePolicyObject` now cover rule
  `qosProfile` attachments and zone `zoneProtectionProfile` attachments. The
  CLI accepts `qos-profile` and `zone-protection-profile`, and the WebUI
  traffic-control references drawer merges the two concrete backend reference
  calls for QoS and zone-protection profiles.
- Remote validation on `opc@139.87.66.128` passed in the worker copy
  `/home/opc/oss-ngfw-v2-mixed-work/qos-zone-object-kinds-20260622-r1` with
  `make proto`, focused apiserver/CLI object-reference tests, syntax checks for
  Objects, automation context, and object route modules, plus focused
  automation/object-route JS tests. The main integration copy
  `/home/opc/oss-ngfw-v2-mixed-work/integration-current-20260622-r1` also
  passed a fresh `make proto`, focused Objects/automation JS checks, focused
  object reference tests, and focused apiserver/CLI object-reference tests.
  Generated API outputs and docs/WebUI specs were synced back from the remote
  proto run.

Proxy/WAF operator workspace slice:

- The WebUI now has a dedicated `#/proxy` workspace for planned-only
  virtual-service and WAF policy authoring. Operators can review proxy plan
  counts, stage WAF policies with ruleset provenance, stage virtual services
  with listeners, routes, backend pools, backend mTLS intent, and WAF
  attachments, and route to Candidate review or Readiness without claiming
  active traffic proxying.
- Proxy/WAF writes go through the existing guarded `session.apply` candidate
  workflow. Client-side validation mirrors the server proxy policy constraints
  for names, WAF modes, ruleset SHA-256 provenance, request-body redaction,
  hostnames, listener TLS secret references, route paths, backend URLs and
  weights, WAF references, and backend mTLS intent. Readiness now links to
  `#/proxy`, and automation/API context includes the planned proxy workflow.
- `/proxy` was added to the app route table, the enterprise WebUI smoke route
  list, and the visual-smoke canonical route list. Remote validation on
  `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/integration-current-20260622-r1`) passed
  `make proto`, focused proxy/readiness/app/automation JavaScript syntax
  checks, proxy model and route tests, app-shell/automation/readiness tests,
  proxy policy/compiler/renderer Go tests, and `make webui-check`. A
  browser-required targeted smoke for `/proxy,/readiness` passed across
  desktop, tablet, and mobile with manifest
  `/home/opc/oss-ngfw-smoke-tmp/openngfw-webui-smoke-proxy-readiness-r2/webui-smoke-evidence.json`
  (`result=passed`, `routeCoverage=2/19`, `checks=6/6`, elapsed `39s`).
  The targeted smoke is continuation/repair evidence only until paired with a
  same-snapshot broad enterprise smoke and recorded through release tooling.
- During browser smoke repair, the HA evidence report wording was tightened to
  explicitly state that browser-local HA evidence "does not execute peer sync
  or failover" while preserving the larger non-mutation boundary.

Privileged action step-up control slice:

- `SystemService.CreateStepUpChallenge` is now exposed as
  `POST /v1/system/access-administration/step-up` for authenticated admin
  callers. The server issues a short-lived, one-time token bound to the actor,
  auth source, and requested action. Disabled local-auth/in-process callers keep
  compatibility for tests and bootstrap paths, but authenticated callers must
  present the token for privileged mutations.
- Step-up enforcement now covers policy commit and rollback, OIDC/SAML provider
  set and disable operations, local-user create/update/token-rotate/disable,
  HA failover activation, and content package install/rollback. The WebUI API
  client requests a matching token immediately before each protected action and
  includes it in the privileged request body.
- RBAC treats challenge creation as admin-only. Focused API contract tests cover
  the new step-up route and protected request bodies, token-storage tests cover
  CSRF propagation through both the challenge and protected mutation requests,
  authz tests cover one-time/action-scoped behavior, and apiserver tests cover
  the guarded mutation paths.
- Remote validation on `opc@139.87.66.128`
  (`/home/opc/oss-ngfw-v2-mixed-work/step-up-controls-20260622-r1`) passed
  `make proto`, `node --check internal/webui/static/js/api.js`,
  `api_contract_surface.test.mjs`, `api_token_storage.test.mjs`, and focused
  Go tests for `./internal/authz` and `./internal/apiserver`. Generated
  Go/gateway/OpenAPI outputs plus docs/WebUI specs were synced back from the
  remote validation copy. The first proto attempt hit remote disk exhaustion
  from stale Go caches; after cache cleanup, validation passed. A local
  JavaScript syntax check was run accidentally during patching and is not
  treated as release or continuation evidence.
- Remaining production hardening is tracked in `docs/HARDENING_BACKLOG.md`:
  IdP/MFA-backed reauthentication, persistent step-up custody, configurable
  policy and expiry, separation-of-duties, signed audit/reporting, HA/fleet
  propagation, and field evidence.

Rules action rail, API recordability, and route-resilience closure:

- Rules dense-row actions now use a bounded two-row desktop action rail instead
  of a non-wrapping horizontal strip. The change preserves every existing
  `data-rule-action` hook and operator action while preventing the 6-action and
  reorder-enabled 8-action rails from overflowing the 120px/188px action
  columns. The WebUI CSS contract tests now assert the capped wrapped rail.
- The hand-authored OpenAPI overlay now emits the implemented Fleet apply-plan,
  apply, and retained-result routes:
  `POST /v1/fleet/templates/{id}:apply-plan`,
  `POST /v1/fleet/templates/{id}:apply`, and
  `GET /v1/fleet/template-results`. The generator tests assert those paths and
  verify that these operations advertise `200` success without the generic
  Fleet `201 Created` response. The generated OpenAPI file, published docs
  spec, and bundled WebUI spec were regenerated from the remote validation copy
  and are byte-identical for this snapshot.
- Release acceptance docs and workflow contracts now match the skip-proof
  privileged integration gate and the desktop enterprise smoke evidence wrapper:
  `privileged-integration` documentation points at
  `make privileged-integration-evidence-check`/the no-skip wrapper instead of
  raw skipped-test-prone commands; the release README documents that wrapper;
  the release workflow contract covers
  `release-evidence-webui-enterprise-smoke`; and generated acceptance-template
  guidance now names the rootless auth/UI and broad desktop enterprise smoke
  evidence commands.
- Threats, Compliance, Readiness, and Intel now preserve route-local shells on
  non-auth API failures. Operators get explicit unavailable banners, retry
  actions, and API/CLI context instead of losing the workspace to the generic
  app error. Existing auth/permission failures still delegate to the auth gate.
- Hardening backlog wording was corrected so active telemetry proof-event
  support and retained Investigation synthesis are credited as bounded
  functional implementations, while production custody, RBAC, signing,
  retention/legal-hold, receiver attestation, HA/fleet replication, and
  external IR/CAB authority remain deferred hardening.

  Remote-only validation passed after syncing the integrated source to
  `opc@139.87.66.128`
  (`/var/oled/oss-ngfw-validation/closure-audit-20260622-r1`) with Go/npm/
  Playwright caches under `/var/oled/openngfw-final-functional`: local static
  hygiene only was run in this checkout (`node --check` for touched WebUI view
  and test files plus `git diff --check`); remote `make proto` regenerated the
  OpenAPI copies, and remote focused checks passed for
  `./cmd/ngfwopenapi`, `./cmd/ngfwrelease`, and
  `./internal/releaseacceptance`. The remote validation copy is not a git
  checkout, so `make proto-status` could prove generated/docs/WebUI copy
  consistency but could not complete git-index recordability checks there.
  Remote `make webui-check` passed. Browser-required targeted desktop smoke
  passed for `/rules,/threats,/compliance,/readiness,/intel`
  (`/var/oled/openngfw-final-functional/artifacts/closure-rules-api-route-resilience-20260622-r1/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=5/20`, `checks=5/5`,
  `screenshots=5`, elapsed `1m19s`). Same-snapshot browser-required broad
  desktop enterprise smoke passed all canonical routes
  (`/var/oled/openngfw-final-functional/artifacts/closure-rules-api-route-resilience-broad-20260622-r1/webui-smoke-evidence.json`,
  `result=passed`, `mode=broad`, `routeCoverage=20/20`, `checks=20/20`,
  `screenshots=20`, elapsed `7m01s`). This is remote continuation evidence;
  durable release evidence still requires source-control acceptance and
  repo-local release evidence recording. No local functional tests were run.

Route resilience, recordability disclosure, and desktop affordance repair:

- Rules, NAT, Objects, Proxy/WAF, Changes, Troubleshoot, Inspection, Threats,
  and Readiness now have route-local unavailable or partial-data behavior for
  the candidate/session-heavy paths exercised by the desktop smoke pass. Rules
  keeps the workspace available when runtime counters/status fail, and shows a
  warning instead of collapsing the route. Non-auth candidate/session failures
  retain route page heads, retry actions, and API/CLI context; auth/permission
  failures still flow through the auth gate.
- Release acceptance recordability now exposes stale evidence paths through
  `ReleaseAcceptanceRecordabilityStatus.stale_evidence_paths`, the apiserver
  mapping, generated Go/gateway files, generated OpenAPI, published
  `docs/api-spec.yaml`, and the bundled WebUI spec. The apiserver test asserts
  the mapped stale-evidence content, and the OpenAPI generator tests now assert
  that the published schema continues to expose `staleEvidencePaths`.
- Fleet OpenAPI status codes now match implemented behavior: non-create Fleet
  routes advertise `200` success only, while `createFleetTemplate` advertises
  `201 Created` only. The generator test covers list, create, validate,
  apply-preview, apply-plan, apply, template-results, and stage-candidate
  blocks.
- Desktop action-affordance coverage was tightened across Threats, Inspection,
  Objects, Readiness, and route-backed Readiness drawers. Generic operator
  actions now carry stable hooks plus title/ARIA intent, and the visual smoke
  route-backed Readiness drawer checks assert footer actions have accessible,
  stable button/link contracts. Rules row action buttons were raised to a
  34px minimum and the CSS/source tests now enforce the larger bounded desktop
  rail.
- GUI/release docs were tightened to state that the accepted WebUI evidence
  path is desktop enterprise smoke. Tablet/mobile sweeps remain diagnostic
  unless the release contract is deliberately changed. Release docs now call
  out the action-affordance and route-backed drawer affordance guards without
  inventing a stdout sentinel the runner does not emit. Hardening notes now
  distinguish retained route-local regression coverage from remaining
  production hardening.

  Remote-only validation passed after syncing the final source to
  `opc@139.87.66.128`
  (`/var/oled/oss-ngfw-validation/closure-audit-20260622-r1`) with Go/npm/
  Playwright caches under `/var/oled/openngfw-final-functional`. The remote
  host root filesystem was full; stale validation caches/artifacts under
  `/var/oled/openngfw-final-functional` were removed, leaving `/var/oled` with
  enough space for browser/build validation. Focused final checks passed:
  OpenAPI spec copies were byte-identical; `docs/api-spec.yaml` contained
  `createFleetTemplate`, `applyPlanFleetTemplate`, and `staleEvidencePaths`;
  `go test ./cmd/ngfwopenapi -run
  "TestOverlayAddsBrowserAuthRoutes|TestPublishedOpenAPISpecIncludesReleaseRecordabilityStaleEvidencePaths"
  -count=1`; and `go test ./internal/apiserver -run
  "TestReleaseAcceptanceStatusMapsRecordability|TestReleaseAcceptanceStatusProtoRedactsServerLocalEvidenceDisclosure"
  -count=1`. Remote WebUI syntax checks for touched views and
  `e2e/webui-visual-smoke.mjs`, `make webui-check`, and
  `WEBUI_SMOKE_SELF_CHECK=1 WEBUI_SMOKE_VIEWPORTS=desktop node
  e2e/webui-visual-smoke.mjs` passed. Browser-required targeted desktop smoke
  passed for
  `/rules,/nat,/objects,/proxy,/changes,/troubleshoot,/inspection,/threats,/readiness`
  (`/var/oled/openngfw-final-functional/artifacts/route-resilience-api-action-20260622-r4/smoke-targeted/webui-smoke-evidence.json`,
  `result=passed`, `mode=targeted`, `routeCoverage=9/20`, `checks=9/9`,
  `screenshots=9`, elapsed `3m05s`). Same-snapshot browser-required broad
  desktop enterprise smoke passed all canonical routes
  (`/var/oled/openngfw-final-functional/artifacts/route-resilience-api-action-20260622-r4/smoke-broad/webui-smoke-evidence.json`,
  `result=passed`, `mode=broad`, `routeCoverage=20/20`, `checks=20/20`,
  `screenshots=20`, elapsed `6m58s`). This is remote continuation evidence;
  durable release evidence still requires source-control acceptance and
  repo-local release evidence recording. No local functional tests were run.

Final closure audit follow-up: the current source tree now fixes the remaining
API/UI/release-readiness issues found by the parallel closure agents. Fleet
OpenAPI create-template status now advertises the implemented `409 Conflict`
while non-create Fleet routes remain `200` success only. `ngfwctl system
release-acceptance-status` now prints stale evidence paths from
`ReleaseAcceptanceRecordabilityStatus`, matching the API, release tooling, and
Readiness workbench. Readiness release-acceptance summary/report output now
counts and shows stale evidence paths without weakening its disclosure
redaction rules. Desktop action-affordance metadata was tightened for NAT path
preview and delete handoffs, Fleet template preview actions, Readiness release
evidence links and fallback close controls, staged inspection profile edit,
runtime blocker fix links, Settings/Traffic/Setup/Net-VPN route pivots, IDS
cancel, automation-context OpenAPI links, and shared confirmation cancel
controls. GUI and progress docs now clarify that broad desktop smoke is remote
continuation evidence until `release-evidence-webui-enterprise-smoke` records
it for an accepted source snapshot, and the current release-evidence blocker
list names the missing durable artifacts explicitly.

Remote-only validation passed after syncing the source to
`opc@139.87.66.128`
(`/var/oled/oss-ngfw-validation/final-closure-20260622-r2`) with Go/npm/
Playwright caches under `/var/oled/openngfw-final-functional`: OpenAPI spec
copies were byte-identical; focused Go tests passed for `./cmd/ngfwopenapi`
and `./internal/cli`; touched WebUI files passed `node --check`; `make
webui-check` passed; and the no-browser smoke self-check passed. `make
proto-status` could prove spec copy consistency but could not complete
git-index checks because this remote validation copy intentionally excludes
`.git`. Browser-required desktop enterprise smoke passed all canonical routes
twice after installing Playwright in the remote validation copy. The final
manifest is
`/var/oled/openngfw-final-functional/artifacts/final-closure-20260622-r2/smoke-broad/webui-smoke-evidence.json`
(`result=passed`, `mode=broad`, `routeCoverage=20/20`, `checks=20/20`,
`screenshots=20`, elapsed `7m02s`). This is remote continuation evidence;
durable release evidence still requires source-control acceptance and
repo-local release evidence recording. No local functional tests were run.

Fleet OpenAPI schema-depth and desktop affordance follow-up: Fleet mutation
request bodies now use named Swagger definitions instead of generic object
bodies. `createFleetTemplate`, `applyPreviewFleetTemplate`,
`applyPlanFleetTemplate`, `applyFleetTemplate`, and
`stageCandidateFleetTemplate` reference concrete request schemas in the
generator plus the generated/published WebUI spec copies. The shared
`FleetApplyPlanNodeInput` schema captures bounded operator-supplied peer rows,
and apply-plan/apply request node arrays are capped at `maxItems: 32`.
Generator tests now assert the Fleet `$ref` bodies, request definitions, and
required fields for create/apply/stage so the contract cannot silently regress
to untyped objects.

The final desktop action-affordance warnings from the parallel UI audit were
cleaned up across Settings, Traffic, Threats, Proxy/WAF, Objects, NAT,
Readiness, and app-level runtime/candidate controls. Visible desktop actions
now carry type/title/ARIA/stable automation hooks consistent with the local
view helpers. A Settings hook collision was also fixed: copy-link controls no
longer reuse `data-settings-panel`, so browser automation and route-state code
select the actual content section rather than a nav action.

Remote-only validation passed after syncing the source to
`opc@139.87.66.128`
(`/var/oled/oss-ngfw-validation/fleet-openapi-20260622-r1`) with caches under
`/var/oled/openngfw-final-functional`: OpenAPI spec copies were byte-identical;
focused Go tests passed for `./cmd/ngfwopenapi` including
`TestPublishedOpenAPISpecIncludesFleetRequestDefinitions`; touched WebUI files
passed `node --check`; and `make webui-check` passed. A broad multi-viewport
diagnostic smoke found non-desktop tablet/mobile layout issues, but the
desktop failure was fixed and the requested enterprise desktop browser smoke
then passed all canonical routes with `WEBUI_SMOKE_VIEWPORTS=desktop`. The
desktop manifest is
`/var/oled/openngfw-final-functional/artifacts/fleet-openapi-20260622-r1/webui-smoke-desktop/webui-smoke-evidence.json`
(`result=passed`, `mode=broad`, `routeCoverage=20/20`, `checks=20/20`,
`screenshots=20`, elapsed `7m01s`). This is still remote continuation
evidence; durable release evidence remains blocked until source-control
acceptance and repo-local release evidence recording for the accepted commit.
