# Threat Intelligence And Content Strategy

Phragma must treat threat intelligence and content as product systems, not as a pile of feeds.

## App-ID

App-ID v1 uses nDPI as a signal source, but Phragma owns the App-ID system.

Required Phragma App-ID responsibilities:

- app taxonomy
- application metadata
- risk scoring
- evidence model
- confidence model
- custom app definitions
- encrypted-traffic heuristics
- DNS, TLS, QUIC, HTTP, Suricata, and future Zeek metadata fusion
- app dependency mapping
- regression corpus
- update package format
- false-positive and false-negative workflow

**HARD REQUIREMENT:** nDPI output must never be exposed as the final App-ID model without Phragma evidence and confidence.

Current v2-mixed implementation:

- `/v1/flows` preserves the engine-native `app_protocol` signal as evidence.
- `/v1/flows` also returns canonical Phragma App-ID fields: `app_id`,
  `app_name`, `app_category`, `app_confidence`, and `app_evidence`.
- The initial taxonomy normalizes common Suricata app-protocol signals and
  uses port heuristics as confirming or conflicting evidence. Port-only
  App-ID promotion is low-confidence and used only when no engine signal is
  present.
- Policy-level `applications[]` objects define custom Phragma App-ID entries
  with display/category metadata, engine-signal aliases, and TCP/UDP port
  hints. `/v1/flows` reads the running policy and applies those definitions
  before the built-in taxonomy.
- Security rules can reference `applications[]` for the current safe v1
  enforcement subset: `ACTION_DENY` rules are rendered as high-speed nftables
  TCP/UDP port-hint blocks, or as broad Suricata-backed signal-only drops when
  IDS/IPS is Prevent fail-closed and the App-ID object uses a supported
  app-layer label. Allow-by-App-ID, scoped L7 App-ID enforcement, and broader
  engine-signal semantics remain future dataplane milestones.
- nDPI is still a future signal source; it must feed the same evidence and
  confidence model rather than replace it.

## Threat-ID

Threat-ID v1 uses Suricata as the matching engine, but Phragma owns the threat-prevention system.

Required Phragma Threat-ID responsibilities:

- threat taxonomy
- signature metadata
- severity and confidence scoring
- rule source ingestion
- profile compiler
- staged rollout
- exception workflow
- false-positive suppression
- PCAP regression tests
- CVE, MITRE ATT&CK, malware family, and exploit metadata where available
- emergency disable and rollback
- explanation integration

**HARD REQUIREMENT:** Suricata alert/drop output must be normalized into Phragma threat events before users consume it.

Current v2-mixed implementation:

- `/v1/alerts` preserves Suricata `signature`, `signature_id`, `category`,
  numeric `severity`, and `action` as engine evidence.
- `/v1/alerts` also returns canonical Phragma Threat-ID fields:
  `threat_id`, `threat_name`, `threat_category`, `threat_severity`,
  `threat_confidence`, and `threat_evidence`.
- The initial taxonomy maps common Suricata signature/category language into
  first-party categories such as `exploit-attempt`, `malware`,
  `credential-attack`, `reconnaissance`, `policy-violation`, and
  `suspicious`.
- `ids.exceptions` is the first false-positive control surface. Operators can
  stage named global or source/destination-scoped suppressions from Threats.
  Each active exception requires an operator reason, a positive engine SID, and
  strict lowercase Threat-ID metadata when present. Review metadata can carry an
  owner, ticket/change ID, review date, expiry date, PCAP SHA-256, and
  regression reference. Phragma blocks duplicate active suppressions for the
  same SID and scope, validation resolves existing address objects, validates
  review dates and PCAP hashes, commit review calls out the exception change,
  and the Suricata adapter renders `openngfw-threshold.config` as an engine
  artifact with review comments.
- `/v1/threat-exceptions:stage` is the first-party API for this workflow. It
  accepts Threat-ID metadata plus structured engine signals, stages only the
  candidate policy, and returns validation, candidate status, and diff context.
  The WebUI exposes the same metadata in the false-positive staging and edit
  drawers, exception inventory, and exception detail view.
- `/v1/threat-id/replay:check` is the bounded operator evidence check for
  Threat-ID samples and recent alert evidence. It re-runs metadata-only
  signature/category/action evidence through the same Threat-ID classifier used
  by `/v1/alerts`, compares expected signature, Threat-ID, and verdict fields
  against observed output, and includes current `/v1/system/status` inspection
  engine availability plus degraded-mode evidence. This is not packet replay,
  malware execution, or IPS certification.
- Full signature metadata packages, PCAP regression, CVE/MITRE enrichment, and
  staged rollout remain future Threat-ID milestones; they must extend the same
  normalized event and exception model instead of replacing it with raw engine
  output.

## Feed Governance

Every feed must have a registry entry before use.

Registry fields:

- feed name
- source URL
- license
- redistribution rights
- commercial-use rights
- attribution requirements
- update frequency
- data type
- confidence level
- expected false-positive risk
- owner
- ingestion parser
- test corpus

**HARD REQUIREMENT:** Do not redistribute third-party feed content unless the feed license permits it.

## Recommended Feed And Signal Categories

- Open rulesets such as Emerging Threats Open where licensing permits.
- abuse.ch projects such as URLhaus, ThreatFox, and SSLBL where terms permit.
- CrowdSec decisions and reputation signals.
- MISP feeds and communities through external integration.
- Local telemetry from opted-in Phragma deployments.
- Honeypot telemetry from T-Pot-style deployments.
- Sandbox verdicts from CAPEv2 or other detonation services.
- Local administrator blocklists and allowlists.

## Crowdsourced Telemetry

Phragma should support opt-in telemetry that strengthens community defense.

Rules:

- Disabled by default.
- Explicit opt in.
- Clear data minimization.
- No payload sharing without separate explicit consent.
- Hash, aggregate, or redact sensitive fields where possible.
- Public schema.
- Local preview of what will be shared.

## Honeypots And Sandboxing

T-Pot and CAPEv2 are external ecosystem services.

Core behavior:

- submit-to-sandbox interface
- file hash and metadata capture
- sandbox verdict ingestion
- honeypot IOC ingestion
- local policy action based on verdicts

Non-goals for v1:

- shipping T-Pot as an on-box runtime
- shipping CAPEv2 as a required local detonation engine
- operating a managed detonation service

## QA And Release Discipline

Content updates must be tested like code.

Required checks:

- parser tests
- schema validation
- duplicate detection
- license validation
- PCAP regression
- false-positive regression
- performance impact estimate
- staged rollout support
- emergency rollback

**NON-NEGOTIABLE LINE IN THE SAND:** Threat content that cannot be tested, explained, rolled back, or license-audited cannot ship as official Phragma content.

## Current Package Status Surface

Phragma reads local content package manifests from:

- `<data-dir>/content/app-id/manifest.json`
- `<data-dir>/content/threat-id/manifest.json`
- `<data-dir>/content/intel-feeds/manifest.json`

The manifest schema version is `phragma.content.package.v1`, aligned with
ADR-0014. The control plane verifies SHA-256 file hashes, Ed25519 manifest
signatures, semantic package versions, provenance, regression status, rollout
state, and rollback metadata without network access. The status API is
`GET /v1/intel/content/packages`; the CLI view is `ngfwctl intel content`; the
WebUI Intel page consumes the same endpoint. Its `rollback_available` field is
operational: it is true only when a verified local backup exists under the
package `.rollback/` directory, not merely because the manifest declares
rollback metadata. Missing or invalid package controls remain production
blockers and are included in support bundles.
Verified packages must include a source identity, provenance entries with
source URL, license, explicit commercial-use and redistribution rights, and
passed regression evidence with corpus name, run timestamp, passing count, and
zero failures.

Operators can review a server-local package before promotion with
`POST /v1/intel/content/packages/{kind}/preview` or
`ngfwctl intel content preview KIND --source SERVER_DIR`. The source path must
resolve under the configured content import directory, for example
`<data-dir>/content-import`, and may be absolute within that root or relative
to it. Preview uses the same trusted keyring, hash, signature, provenance,
regression, rollout, rollback, and production-readiness checks as install, but
it does not copy package files, replace installed content, or write lifecycle
audit entries. Responses use the same sanitized package posture as
`GET /v1/intel/content/packages` and do not expose server-local manifest paths
or operator-entered source paths in WebUI handoff packets.

Operators can browse verified package-local corpus evidence with
`GET /v1/intel/content/packages/{kind}/corpus` or
`ngfwctl intel content corpus KIND`. The API reads the signed package
`content_readiness.evidence[]` reference, verifies the bounded JSON artifact
against the manifest hash, normalizes sample rows, and supports server-side
query, verdict, and limit filters. The kind-specific default corpus evidence
types are `app-regression-corpus`, `pcap-regression-corpus`, and
`parser-tests`.

Operators can compare installed content with a server-local import candidate
before promotion with `POST /v1/intel/content/packages/{kind}/compare` or
`ngfwctl intel content compare KIND --source SERVER_DIR`. Compare verifies the
candidate source under the configured import directory, returns sanitized
installed-vs-preview package posture, and reports regression corpus additions,
removals, changed rows, failed-sample delta, and sample-level diffs. It does
not copy package files, replace installed content, or write lifecycle audit
entries.

Reviewed App-ID observations can be staged as draft regression corpus input
with `POST /v1/app-id/observations/{queueId}:stage-regression-sample` or
`ngfwctl app-id corpus add QUEUE_ID --pcap-sha256 SHA256 --reason REASON`.
The service re-derives the queue item from current telemetry, validates the
bounded PCAP SHA-256, records expected and observed App-ID values plus current
package version/hash context, appends
`app-id/.reviewed-corpus/app-regression-corpus.jsonl` under the configured
content directory, and writes an audit entry. This draft JSONL is package-
builder input only; it is not installed content, signed evidence, or a
production readiness claim until a content package is built, signed, compared,
and installed through the normal content lifecycle.

Package verification and production content readiness are separate machine
checks. A package can be `verified` when its signature, hashes, provenance,
regression, rollout, and rollback controls pass, while still reporting
`content_readiness.production_ready=false`. Demo packages used by
`make content-package-smoke` deliberately set `content_readiness.scope` to
`demo-only` and `production_content=false`. The verifier also emits an
operator-facing `readiness_label` and `readiness_detail` so API, CLI, and
WebUI consumers can distinguish `production-ready`, `demo-only`,
`missing-readiness`, and `production-blocked` package posture without
inferring production use from the package `state`.

The Intel page and `ngfwctl intel content` also surface a production-evidence
inventory model for App-ID, Threat-ID, and intel-feed packages. The inventory
normalizes the package status into four operator states:

| Inventory state | Meaning |
|---|---|
| `missing` | No signed package or no signed production-readiness declaration is installed for the surface. |
| `demo` | A signed package is present, but the manifest explicitly declares demo/lab scope and is not approved for verdict-changing production use. |
| `production-blocked` | A package exists, but signature, regression, rollout, rollback, required evidence, evidence hash, evidence verdict, or package blocker checks prevent production readiness. |
| `production-ready` | The package is signed, required evidence is attached and passing, no readiness blockers remain, and the package is eligible for reviewed production rollout. |

The inventory is derived from the same `GET /v1/intel/content/packages`
payload used by API, CLI, and WebUI consumers; it does not create a separate
trust root. WebUI copy/export/pin handoffs include the inventory as normal
content package fields and evidence. CLI output prints
`production-evidence-inventory` with required and attached evidence counts so
remote validation and change records can distinguish demo or missing content
from production-ready content without inspecting every artifact.

Production content packages must carry a signed manifest `content_readiness`
object. The verifier copies the declaration into package status and checks that
each evidence artifact is a normal package file under `evidence/`, uses a
`.json` filename, is non-empty valid JSON, is listed in `files[]`, has a
matching SHA-256, and has an RFC3339 `generated_at` timestamp. Production
evidence artifacts must be JSON objects whose `type` or `evidence_type`
matches the signed `content_readiness.evidence[].type` entry and whose
`status` or `verdict` is `passed`. App-ID `app-regression-corpus` artifacts
must also name the package version and include at least one passing sample with
a valid PCAP SHA-256, expected app, and observed app. Production
manifests must also declare the exact required evidence set for the package
kind in `required_production_evidence` so the signed manifest is
self-describing:

```json
{
  "files": [
    {
      "path": "apps.json",
      "sha256": "<catalog-sha256>"
    },
    {
      "path": "evidence/app-taxonomy.json",
      "sha256": "<app-taxonomy-sha256>"
    }
  ],
  "content_readiness": {
    "scope": "production",
    "production_content": true,
    "required_production_evidence": [
      "app-taxonomy",
      "confidence-model",
      "app-regression-corpus",
      "license-review",
      "staged-rollout",
      "rollback-drill"
    ],
    "evidence": [
      {
        "type": "app-taxonomy",
        "artifact": "evidence/app-taxonomy.json",
        "sha256": "<app-taxonomy-sha256>",
        "generated_at": "2026-06-18T12:00:00Z"
      }
    ]
  }
}
```

Required production evidence is package-kind specific:

| Package kind | Required `content_readiness.evidence[].type` values |
|---|---|
| `app-id` | `app-taxonomy`, `confidence-model`, `app-regression-corpus`, `license-review`, `staged-rollout`, `rollback-drill` |
| `threat-id` | `threat-taxonomy`, `pcap-regression-corpus`, `false-positive-regression`, `license-review`, `staged-rollout`, `rollback-drill` |
| `intel-feeds` | `feed-registry`, `parser-tests`, `license-review`, `false-positive-regression`, `staged-rollout`, `rollback-drill` |

Release notes, support statements, and customer-facing claims must use the
separate `content_readiness.production_ready` verdict for production App-ID,
Threat-ID, or intel-feed readiness. `State: verified` alone is not enough for a
production content claim.

## Production Content Release Check

Release acceptance treats production content readiness as a separate check from
rootless package mechanics. `make content-package-smoke` proves that signed
demo packages can be verified, installed, rejected on failed regression, and
rolled back. It deliberately keeps `content_readiness.scope=demo-only`,
`production_content=false`, and `production_ready=false`.

Production releases must also pass `content-production-readiness` after signed
App-ID, Threat-ID, and intel-feed packages are installed or staged for the
release. The validator input is release-local and defaults to:

```text
release/field-evidence/content-production/
  app-id/
    status.json
    evidence/*.json
  threat-id/
    status.json
    evidence/*.json
  intel-feeds/
    status.json
    evidence/*.json
```

For each package kind, `status.json` must come from
`GET /v1/intel/content/packages` or `ngfwctl intel content` after the signed
production package has been installed or staged in the release lab. It must
declare the package kind, `state=verified`, `signature_status=verified`,
`regression_status=passed`, verified provenance, staged or verified rollout
posture, rollback availability, no blockers,
`content_readiness.scope=production`, `production_content=true`,
`production_ready=true`, and the exact `required_production_evidence` list for
that kind. Each readiness evidence entry must point to a package-local JSON
file under `evidence/`, include a matching SHA-256 digest, and include an
RFC3339 `generated_at`. Unsigned operator notes cannot replace package-local
evidence.

The required production proof remains package-kind specific:

| Package kind | Required production readiness proof |
|---|---|
| `app-id` | taxonomy, confidence model, App-ID regression corpus, license review, staged rollout, rollback drill |
| `threat-id` | threat taxonomy, PCAP regression corpus, false-positive regression, license review, staged rollout, rollback drill |
| `intel-feeds` | feed registry, parser tests, license review, false-positive regression, staged rollout, rollback drill |

Operators validate and record this check with:

```sh
make content-production-readiness-check \
  CONTENT_PRODUCTION_EVIDENCE_DIR=release/field-evidence/content-production

COMMIT="$(git rev-parse HEAD)" make release-evidence-content-production-readiness \
  CONTENT_PRODUCTION_EVIDENCE_DIR=release/field-evidence/content-production
```

The recorded validator stdout must include the exact release sentinels:

```text
check=content-production-readiness
mode=check
content_production_scope=app-id,threat-id,intel-feeds
required_content_kinds=app-id,threat-id,intel-feeds
required_app_id_evidence=app-taxonomy,confidence-model,app-regression-corpus,license-review,staged-rollout,rollback-drill
required_threat_id_evidence=threat-taxonomy,pcap-regression-corpus,false-positive-regression,license-review,staged-rollout,rollback-drill
required_intel_feeds_evidence=feed-registry,parser-tests,license-review,false-positive-regression,staged-rollout,rollback-drill
content_readiness=production_content=true,production_ready=true
status=passed
```

The recorder target writes
`release/evidence/content-production-readiness.txt`. Release acceptance must
not reuse `release/evidence/content-package-verification.txt` or any rootless
demo smoke output for production content claims.

Package promotion is also server-local and verifier-gated. It is not a browser
upload path and it is not a path on the operator workstation; operators must
place package directories on the firewall host under the configured content
import directory before invoking the API, CLI, or WebUI install action:

- `POST /v1/intel/content/packages/{kind}/install` verifies a source directory
  on the firewall host before copying it into `<data-dir>/content/{kind}`. API
  installs only accept package sources under the configured content import
  directory (`<data-dir>/content-import` in `controld`) after symlink
  resolution. Sources may be absolute paths under that root or relative
  directory names inside it; sources outside that root are rejected with a
  sanitized client error.
- `POST /v1/intel/content/packages/{kind}/rollback` restores the latest
  verified local backup for the package kind. Corrupt or untrusted backup
  directories are ignored and cannot enable the rollback action.
- `ngfwctl intel content install <kind> --source <path>` and
  `ngfwctl intel content rollback <kind> --ack-rollback` use the same API; the
  install `--source` value is a firewall-server directory under the configured
  import root, not a client-local upload path.
- `ngfwctl intel content corpus <kind>` and
  `ngfwctl intel content compare <kind> --source <path>` expose the read-only
  corpus browser and non-mutating candidate corpus diff for automation and CAB
  evidence review.
- `ngfwctl app-id corpus add <queue-id> --pcap-sha256 <sha256> --reason
  <reason>` appends a reviewed App-ID queue item to the draft regression corpus
  for later package-builder input; it does not install or sign content.
- The WebUI Intel page exposes Install and Rollback actions beside the package
  posture evidence. The Install drawer accepts the same server-local source
  directory; it does not upload package files from the browser. Review,
  install, and rollback drawers can be deep-linked with
  `#/intel?surface=<kind>&drawer=<action>` and can copy/export a redacted
  content-package-lifecycle handoff packet for CAB/SecOps review. The packet
  is assembled from the already visible package posture and omits
  operator-entered install source paths plus raw manifest or rollback paths.
- Successful and rejected install/rollback attempts are written to the
  append-only audit log with actor, role, auth source, package kind, version,
  source path or rollback path, and failure reason when present.
- Install and rollback write an intent audit entry before promoting package
  files. If the audit chain cannot be extended, package content is not changed.

Policy feed changes keep the normal candidate workflow: enabling registry
feeds, adding custom feeds, or changing the refresh interval stages candidate
policy and requires validation and commit. Package install and rollback are
operational content lifecycle actions with audit entries, not policy candidate
commits.

Install rejects packages that fail signature, hash, semantic version,
provenance, regression, rollout, rollback, safe path, or reserved metadata path
checks. Package file entries cannot target `manifest.json` or top-level
dot-prefixed metadata directories such as `.rollback`, `.staging`, or `.trust`.
When replacing a verified installed package, Phragma stores the previous version
under the package `.rollback/` directory before promotion.

Rootless release preflight includes `make content-package-smoke`, which runs
`e2e/content-package-smoke.sh --check`. The smoke creates signed demo App-ID,
Threat-ID, and intel-feed packages in Go test temp directories, installs them
into a temp content data root, verifies signature/provenance/regression/rollout
posture, rejects a correctly signed package with failed regression evidence, and
proves rollback restores the previous verified App-ID package. It does not use,
bundle, or imply production threat content.

## Primary References

- Palo Alto Networks [App-ID documentation](https://docs.paloaltonetworks.com/ngfw/administration/app-id).
- [Suricata documentation](https://docs.suricata.io/en/).
- [Suricata rule management](https://docs.suricata.io/en/suricata-8.0.0/rule-management/suricata-update.html).
- [nDPI repository](https://github.com/ntop/nDPI).
- [CrowdSec concepts](https://docs.crowdsec.net/docs/concepts).
- [MISP license overview](https://www.misp-project.org/license/).
