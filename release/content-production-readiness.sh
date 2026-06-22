#!/usr/bin/env bash
set -u -o pipefail

CHECK_NAME="content-production-readiness"
DEFAULT_KINDS="app-id,threat-id,intel-feeds"
REQUIRED_APP_ID_EVIDENCE="app-taxonomy,confidence-model,app-regression-corpus,license-review,staged-rollout,rollback-drill"
REQUIRED_THREAT_ID_EVIDENCE="threat-taxonomy,pcap-regression-corpus,false-positive-regression,license-review,staged-rollout,rollback-drill"
REQUIRED_INTEL_FEEDS_EVIDENCE="feed-registry,parser-tests,license-review,false-positive-regression,staged-rollout,rollback-drill"
BUNDLE_DIR="${CONTENT_PRODUCTION_READINESS_DIR:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

failures=0

# shellcheck source=release/manifest-sha256.sh
. "$SCRIPT_DIR/manifest-sha256.sh"

usage() {
  cat <<'USAGE'
Usage: release/content-production-readiness.sh --bundle-dir <dir>

Validates release-local production content readiness evidence for App-ID,
Threat-ID, and intel-feed packages. This check does not install packages or
run package verification; it rejects partial or demo-only status bundles before
release notes claim production content readiness.

Required bundle layout:
  <dir>/manifest.sha256
  <dir>/app-id/status.json
  <dir>/threat-id/status.json
  <dir>/intel-feeds/status.json

Each status file must prove verified production readiness with signed package
status, production-scoped content_readiness metadata, all required evidence
types, package-local evidence artifacts, passed regression/provenance/rollout/
rollback posture, and no blockers.
USAGE
}

log() {
  printf '%s\n' "$*"
}

ok() {
  log "ok: $*"
}

fail() {
  log "error: $*"
  failures=$((failures + 1))
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --check)
        shift
        ;;
      --bundle-dir|--evidence-dir)
        if [ "$#" -lt 2 ]; then
          fail "$1 requires a value"
          return
        fi
        BUNDLE_DIR="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        fail "unknown argument: $1"
        shift
        ;;
    esac
  done
}

reject_symlinked_bundle() {
  if [ -z "$BUNDLE_DIR" ]; then
    fail "--bundle-dir or CONTENT_PRODUCTION_READINESS_DIR is required"
    return 1
  fi
  if [ -L "$BUNDLE_DIR" ]; then
    fail "content evidence root must not be a symlink: $BUNDLE_DIR"
    return 1
  fi
  if [ ! -d "$BUNDLE_DIR" ]; then
    fail "content evidence root missing: $BUNDLE_DIR"
    return 1
  fi

  local first_link
  if ! first_link="$(find "$BUNDLE_DIR" -type l -print | sed -n '1p')"; then
    fail "unable to scan content evidence bundle for symlinks: $BUNDLE_DIR"
    return 1
  fi
  if [ -n "$first_link" ]; then
    fail "content evidence bundle must not contain symlinks: $first_link"
    return 1
  fi
  return 0
}

manifest_expected_files() {
  printf '%s\n' \
    "app-id/status.json" \
    "app-id/evidence/app-taxonomy.json" \
    "app-id/evidence/confidence-model.json" \
    "app-id/evidence/app-regression-corpus.json" \
    "app-id/evidence/license-review.json" \
    "app-id/evidence/staged-rollout.json" \
    "app-id/evidence/rollback-drill.json" \
    "threat-id/status.json" \
    "threat-id/evidence/threat-taxonomy.json" \
    "threat-id/evidence/pcap-regression-corpus.json" \
    "threat-id/evidence/false-positive-regression.json" \
    "threat-id/evidence/license-review.json" \
    "threat-id/evidence/staged-rollout.json" \
    "threat-id/evidence/rollback-drill.json" \
    "intel-feeds/status.json" \
    "intel-feeds/evidence/feed-registry.json" \
    "intel-feeds/evidence/parser-tests.json" \
    "intel-feeds/evidence/license-review.json" \
    "intel-feeds/evidence/false-positive-regression.json" \
    "intel-feeds/evidence/staged-rollout.json" \
    "intel-feeds/evidence/rollback-drill.json"
}

validate_bundle_json() {
  if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 is required to validate structured content readiness JSON"
    return 1
  fi

  python3 - "$BUNDLE_DIR" <<'PY'
import datetime
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath

root = Path(sys.argv[1])
required = {
    "app-id": ["app-taxonomy", "confidence-model", "app-regression-corpus", "license-review", "staged-rollout", "rollback-drill"],
    "threat-id": ["threat-taxonomy", "pcap-regression-corpus", "false-positive-regression", "license-review", "staged-rollout", "rollback-drill"],
    "intel-feeds": ["feed-registry", "parser-tests", "license-review", "false-positive-regression", "staged-rollout", "rollback-drill"],
}
good_statuses = {"available", "complete", "completed", "passed", "ready", "staged", "verified"}
errors = []


def field(obj, *names):
    if not isinstance(obj, dict):
        return None
    for name in names:
        if name in obj:
            return obj[name]
    return None


def norm(value):
    if value is None:
        return ""
    return str(value).strip().lower()


def quote(value):
    return json.dumps(value)


def string_field(obj, *names):
    value = field(obj, *names)
    if isinstance(value, str):
        return value.strip()
    return ""


def valid_sha256(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value.strip().lower()) is not None


def valid_semver(value):
    return isinstance(value, str) and re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", value.strip()) is not None


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return None


def normalized_string_list(value):
    values = as_list(value)
    if values is None:
        return None
    return [norm(item) for item in values if norm(item)]


def blocker_values(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    return ["<non-list blockers>"]


def require_empty_blockers(kind, label, obj):
    blockers = blocker_values(field(obj, "blockers", "Blockers"))
    if blockers:
        errors.append(f"{kind} {label} blockers must be empty: {', '.join(blockers)}")


def valid_rfc3339_timestamp(value):
    if not isinstance(value, str) or not value.strip():
        return False
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.datetime.fromisoformat(candidate)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def require_status(kind, status, label, expected):
    actual = norm(field(status, label, "".join(part.title() for part in label.split("_"))))
    if actual != expected:
        errors.append(f"{kind} {label} = {quote(actual)}, want {expected}")


def validate_provenance(kind, status):
    explicit = field(status, "provenance_status", "ProvenanceStatus")
    if explicit is not None:
        if norm(explicit) not in good_statuses:
            errors.append(f"{kind} provenance_status = {quote(norm(explicit))}, want verified")
        return

    provenance = as_list(field(status, "provenance", "Provenance"))
    if not provenance:
        errors.append(f"{kind} provenance evidence missing")
        return

    for index, entry in enumerate(provenance):
        if not isinstance(entry, dict):
            errors.append(f"{kind} provenance[{index}] must be an object")
            continue
        if not norm(field(entry, "name", "Name")) or not norm(field(entry, "url", "URL")):
            errors.append(f"{kind} provenance[{index}] must include source name and URL")
        if not norm(field(entry, "license", "License")):
            errors.append(f"{kind} provenance[{index}] must include license")
        if field(entry, "allows_commercial_use", "AllowsCommercialUse") is not True:
            errors.append(f"{kind} provenance[{index}] must allow commercial use")
        if field(entry, "allows_redistribution", "AllowsRedistribution") is not True:
            errors.append(f"{kind} provenance[{index}] must allow redistribution")


def validate_rollout(kind, status):
    rollout = norm(field(status, "rollout_status", "RolloutStatus", "rollout_state", "RolloutState"))
    if rollout not in good_statuses:
        errors.append(f"{kind} rollout status = {quote(rollout)}, want staged or verified")


def validate_rollback(kind, status):
    available = field(status, "rollback_available", "RollbackAvailable")
    if available is not None:
        if available is not True:
            errors.append(f"{kind} rollback_available must be true")
        return
    rollback = norm(field(status, "rollback_status", "RollbackStatus"))
    if rollback not in good_statuses:
        errors.append(f"{kind} rollback status = {quote(rollback)}, want available or verified")


def validate_app_regression_corpus(kind, artifact_json, status):
    if kind != "app-id":
        return

    package_version = string_field(artifact_json, "package_version", "packageVersion")
    if not valid_semver(package_version):
        errors.append(f"{kind} app-regression-corpus package_version must be semver")
    status_version = string_field(status, "version", "Version")
    if not status_version:
        errors.append(f"{kind} status version is required for app-regression-corpus")
    elif package_version and package_version != status_version:
        errors.append(f"{kind} app-regression-corpus package_version = {quote(package_version)}, want status version {quote(status_version)}")

    manifest_sha256 = string_field(artifact_json, "manifest_sha256", "manifestSha256")
    if not valid_sha256(manifest_sha256):
        errors.append(f"{kind} app-regression-corpus manifest_sha256 must be 64 lowercase hex characters")
    status_manifest_sha256 = string_field(status, "manifest_sha256", "manifestSha256")
    if not status_manifest_sha256:
        errors.append(f"{kind} status manifest_sha256 is required for app-regression-corpus")
    elif manifest_sha256 and manifest_sha256.lower() != status_manifest_sha256.lower():
        errors.append(f"{kind} app-regression-corpus manifest_sha256 does not match status manifest_sha256")

    samples = field(artifact_json, "samples", "Samples")
    if not isinstance(samples, list) or not samples:
        errors.append(f"{kind} app-regression-corpus samples must be a non-empty list")
        return

    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            errors.append(f"{kind} app-regression-corpus sample[{index}] must be an object")
            continue
        pcap_sha256 = string_field(sample, "pcap_sha256", "pcapSha256")
        if not valid_sha256(pcap_sha256):
            errors.append(f"{kind} app-regression-corpus sample[{index}] pcap_sha256 missing or invalid")
        if not string_field(sample, "expected_app", "expectedApp"):
            errors.append(f"{kind} app-regression-corpus sample[{index}] expected_app is required")
        if not string_field(sample, "observed_app", "observedApp"):
            errors.append(f"{kind} app-regression-corpus sample[{index}] observed_app is required")
        sample_verdict = norm(field(sample, "verdict", "Verdict", "status", "Status"))
        if sample_verdict != "passed":
            errors.append(f"{kind} app-regression-corpus sample[{index}] verdict/status = {quote(sample_verdict)}, want passed")


def validate_artifact(kind, kind_dir, evidence_type, evidence, status):
    artifact = field(evidence, "artifact", "Artifact")
    if not isinstance(artifact, str) or not artifact.strip():
        errors.append(f"{kind} evidence artifact missing for {evidence_type}")
        return

    artifact_path = PurePosixPath(artifact.strip())
    if artifact_path.is_absolute() or ".." in artifact_path.parts:
        errors.append(f"{kind} evidence artifact path escapes bundle for {evidence_type}: {artifact}")
        return
    if len(artifact_path.parts) < 2 or artifact_path.parts[0] != "evidence" or artifact_path.suffix != ".json":
        errors.append(f"{kind} evidence artifact must be evidence/*.json for {evidence_type}: {artifact}")
        return

    path = kind_dir.joinpath(*artifact_path.parts)
    if path.is_symlink():
        errors.append(f"{kind} evidence artifact must not be a symlink for {evidence_type}: {artifact}")
        return
    if not path.is_file():
        errors.append(f"{kind} evidence artifact missing for {evidence_type}: {artifact}")
        return

    raw = path.read_bytes()
    if not raw.strip():
        errors.append(f"{kind} evidence artifact empty for {evidence_type}: {artifact}")
        return
    try:
        artifact_json = json.loads(raw)
    except json.JSONDecodeError as exc:
        errors.append(f"{kind} evidence artifact is not valid JSON for {evidence_type}: {artifact}: {exc}")
        return
    if not isinstance(artifact_json, dict):
        errors.append(f"{kind} evidence artifact must contain a JSON object for {evidence_type}: {artifact}")
        return

    expected_hash = norm(field(evidence, "sha256", "SHA256"))
    if len(expected_hash) != 64 or any(ch not in "0123456789abcdef" for ch in expected_hash):
        errors.append(f"{kind} evidence sha256 missing or invalid for {evidence_type}")
        return
    actual_hash = hashlib.sha256(raw).hexdigest()
    if actual_hash != expected_hash:
        errors.append(f"{kind} evidence sha256 mismatch for {evidence_type}: {artifact}")

    generated_at = field(evidence, "generated_at", "GeneratedAt")
    if not valid_rfc3339_timestamp(generated_at):
        errors.append(f"{kind} evidence generated_at must be RFC3339 for {evidence_type}")

    if field(evidence, "signed", "Signed") is not True:
        errors.append(f"{kind} evidence artifact must be signed for {evidence_type}")
    evidence_signature = field(evidence, "signature_status", "SignatureStatus")
    if norm(evidence_signature) != "verified":
        errors.append(f"{kind} evidence signature_status = {quote(norm(evidence_signature))} for {evidence_type}, want verified")

    artifact_type = norm(field(artifact_json, "evidence_type", "EvidenceType", "type", "Type"))
    if artifact_type != evidence_type:
        errors.append(f"{kind} evidence artifact evidence_type = {quote(artifact_type)} for {evidence_type}, want {evidence_type}")
    artifact_verdict = norm(field(artifact_json, "verdict", "Verdict", "status", "Status"))
    if artifact_verdict != "passed":
        errors.append(f"{kind} evidence artifact verdict/status = {quote(artifact_verdict)} for {evidence_type}, want passed")
    if kind == "app-id" and evidence_type == "app-regression-corpus":
        validate_app_regression_corpus(kind, artifact_json, status)


def validate_kind(kind):
    kind_dir = root / kind
    if kind_dir.is_symlink():
        errors.append(f"{kind} status directory must not be a symlink: {kind_dir}")
        return
    if not kind_dir.is_dir():
        errors.append(f"{kind} status directory missing: {kind_dir}")
        return

    status_path = kind_dir / "status.json"
    if status_path.is_symlink():
        errors.append(f"{kind} status file must not be a symlink: {status_path}")
        return
    if not status_path.is_file():
        errors.append(f"{kind} status file missing: {status_path}")
        return
    raw = status_path.read_bytes()
    if not raw.strip():
        errors.append(f"{kind} status file empty: {status_path}")
        return
    try:
        status = json.loads(raw)
    except json.JSONDecodeError as exc:
        errors.append(f"{kind} status file is not valid JSON: {exc}")
        return
    if not isinstance(status, dict):
        errors.append(f"{kind} status file must contain a JSON object")
        return

    actual_kind = norm(field(status, "kind", "Kind"))
    if actual_kind != kind:
        errors.append(f"{kind} kind = {quote(actual_kind)}, want {kind}")
    require_status(kind, status, "state", "verified")
    require_status(kind, status, "signature_status", "verified")
    require_status(kind, status, "regression_status", "passed")
    validate_provenance(kind, status)
    validate_rollout(kind, status)
    validate_rollback(kind, status)
    require_empty_blockers(kind, "status", status)

    readiness = field(status, "content_readiness", "ContentReadiness")
    if not isinstance(readiness, dict):
        errors.append(f"{kind} content_readiness is required")
        return

    scope = norm(field(readiness, "scope", "Scope"))
    if scope != "production":
        errors.append(f"{kind} content_readiness.scope = {quote(scope)}, want production")
    if field(readiness, "production_content", "ProductionContent") is not True:
        errors.append(f"{kind} content_readiness.production_content must be true")
    if field(readiness, "production_ready", "ProductionReady") is not True:
        errors.append(f"{kind} content_readiness.production_ready must be true")
    if norm(field(readiness, "evidence_status", "EvidenceStatus")) != "passed":
        errors.append(f"{kind} content_readiness.evidence_status must be passed")
    require_empty_blockers(kind, "content_readiness", readiness)

    required_evidence = normalized_string_list(field(readiness, "required_production_evidence", "RequiredProductionEvidence"))
    expected_evidence = required[kind]
    if required_evidence is None:
        errors.append(f"{kind} content_readiness.required_production_evidence must be a list")
    elif set(required_evidence) != set(expected_evidence):
        missing = [item for item in expected_evidence if item not in required_evidence]
        extra = [item for item in required_evidence if item not in expected_evidence]
        if missing:
            errors.append(f"{kind} required production evidence missing: {','.join(missing)}")
        if extra:
            errors.append(f"{kind} required production evidence has unexpected entries: {','.join(extra)}")

    evidence = as_list(field(readiness, "evidence", "Evidence"))
    if evidence is None:
        errors.append(f"{kind} content_readiness.evidence must be a list")
        return

    by_type = {}
    for index, item in enumerate(evidence):
        if not isinstance(item, dict):
            errors.append(f"{kind} content_readiness.evidence[{index}] must be an object")
            continue
        evidence_type = norm(field(item, "type", "Type"))
        if not evidence_type:
            errors.append(f"{kind} content_readiness.evidence[{index}] type is required")
            continue
        if evidence_type in by_type:
            errors.append(f"{kind} duplicate evidence type: {evidence_type}")
            continue
        by_type[evidence_type] = item

    for evidence_type in expected_evidence:
        item = by_type.get(evidence_type)
        if item is None:
            errors.append(f"{kind} required evidence missing: {evidence_type}")
            continue
        validate_artifact(kind, kind_dir, evidence_type, item, status)

    if not any(message.startswith(kind + " ") for message in errors):
        print(f"ok: {kind} production content status verified")


if root.is_symlink():
    errors.append(f"content evidence root must not be a symlink: {root}")
elif not root.is_dir():
    errors.append(f"content evidence root missing: {root}")
else:
    for path in root.rglob("*"):
        if path.is_symlink():
            errors.append(f"content evidence bundle must not contain symlinks: {path}")
            break
    for kind in required:
        validate_kind(kind)

for message in errors:
    print(f"error: {message}")
sys.exit(1 if errors else 0)
PY
}

main() {
  parse_args "$@"

  log "check=$CHECK_NAME"
  log "mode=check"
  log "content_production_scope=$DEFAULT_KINDS"
  log "required_content_kinds=$DEFAULT_KINDS"
  log "required_app_id_evidence=$REQUIRED_APP_ID_EVIDENCE"
  log "required_threat_id_evidence=$REQUIRED_THREAT_ID_EVIDENCE"
  log "required_intel_feeds_evidence=$REQUIRED_INTEL_FEEDS_EVIDENCE"
  log "content_readiness=production_content=true,production_ready=true"
  log "manifest_sha256_policy=required,exact-regular-files,no-extra-files"

  if [ "$failures" -eq 0 ] && reject_symlinked_bundle; then
    manifest_sha256_verify "$BUNDLE_DIR" $(manifest_expected_files)
    if ! validate_bundle_json; then
      failures=$((failures + 1))
    fi
  fi

  if [ "$failures" -ne 0 ]; then
    log "status=failed"
    exit 1
  fi
  log "status=passed"
}

main "$@"
