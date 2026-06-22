#!/usr/bin/env bash
set -u -o pipefail

CHECK_NAME="m5-saml-field-evidence"
EVIDENCE_DIR="${SAML_FIELD_EVIDENCE_DIR:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

failures=0

# shellcheck source=release/manifest-sha256.sh
. "$SCRIPT_DIR/manifest-sha256.sh"

usage() {
  cat <<'USAGE'
Usage: release/saml-field-evidence.sh --evidence-dir <dir>

Validates a redacted real-provider SAML browser SSO field evidence bundle before
it is recorded as release acceptance evidence. This does not contact the IdP or
run a browser; it checks captured provider, deployment, browser, RBAC, and
redaction artifacts for release-review completeness.

Required bundle layout:
  <dir>/manifest.sha256
  <dir>/provider/idp-metadata.txt
  <dir>/provider/sp-metadata.txt
  <dir>/deployment/public-acs.txt
  <dir>/browser/login-redirect.txt
  <dir>/browser/assertion-session-cookie.txt
  <dir>/browser/invalid-signature-rejection.txt
  <dir>/browser/replayed-assertion-rejection.txt
  <dir>/browser/missing-relaystate-rejection.txt
  <dir>/browser/operator-mutation-with-csrf.txt
  <dir>/browser/missing-csrf-rejection.txt
  <dir>/browser/cross-origin-rejection.txt
  <dir>/browser/viewer-mutation-denial.txt
  <dir>/browser/logout-invalidation.txt
  <dir>/rbac/role-mapping.txt
  <dir>/redaction/identity-redacted.txt
  <dir>/redaction/audit-log-redacted.txt
  <dir>/redaction/support-bundle-redacted.txt
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
      --evidence-dir)
        if [ "$#" -lt 2 ]; then
          fail "--evidence-dir requires a value"
          return
        fi
        EVIDENCE_DIR="$2"
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

require_dir() {
  local path="$1"
  local desc="$2"
  if [ -L "$path" ]; then
    fail "$desc must not be a symlink: $path"
    return 1
  elif [ -d "$path" ]; then
    ok "$desc present"
    return 0
  else
    fail "$desc missing: $path"
    return 1
  fi
}

require_nonempty_file() {
  local path="$1"
  local desc="$2"
  if [ -L "$path" ]; then
    fail "$desc must not be a symlink: $path"
    return 1
  elif [ -f "$path" ] && [ -s "$path" ]; then
    ok "$desc present"
    return 0
  else
    fail "$desc missing or empty: $path"
    return 1
  fi
}

require_file_matches() {
  local path="$1"
  local regex="$2"
  local desc="$3"
  if ! require_nonempty_file "$path" "$desc"; then
    return
  fi
  if grep -Eiq "$regex" "$path"; then
    ok "$desc contains expected evidence"
  else
    fail "$desc missing expected evidence pattern: $regex"
  fi
}

reject_symlink_tree() {
  local found
  found=""
  while IFS= read -r found; do
    break
  done < <(find "$EVIDENCE_DIR" -type l -print 2>/dev/null)
  if [ -n "$found" ]; then
    fail "evidence bundle must not contain symlinks: $found"
  else
    ok "evidence bundle contains no symlinks"
  fi
}

reject_file_secret_pattern() {
  local path="$1"
  local regex="$2"
  local desc="$3"
  if grep -Eiq "$regex" "$path"; then
    fail "$desc appears unredacted in $path"
  fi
}

reject_unredacted_material() {
  local path
  while IFS= read -r path; do
    reject_file_secret_pattern "$path" 'SAMLResponse[[:space:]_"'"'"'-]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9+/=]{80,}' "SAML response"
    reject_file_secret_pattern "$path" 'RelayState[[:space:]_"'"'"'-]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9._~-]{12,}' "SAML RelayState"
    reject_file_secret_pattern "$path" '-----BEGIN[[:space:]]+(RSA |EC |DSA )?PRIVATE KEY-----' "private key"
    reject_file_secret_pattern "$path" '<(saml2?:)?Assertion[^>]*>' "raw SAML assertion"
    reject_file_secret_pattern "$path" '<(ds:)?X509Certificate>[A-Za-z0-9+/=]{80,}</(ds:)?X509Certificate>' "raw X.509 certificate"
    reject_file_secret_pattern "$path" '(^|[[:space:]])Cookie:[^[:cntrl:]]*=[A-Za-z0-9._~+/-]{12,}' "cookie"
    reject_file_secret_pattern "$path" 'Set-Cookie:[^[:cntrl:]]*=[A-Za-z0-9._~+/-]{12,}' "set-cookie value"
    reject_file_secret_pattern "$path" 'saml[-_]?session[[:space:]]*=[[:space:]]*["'"'"']?[A-Za-z0-9._~+/-]{12,}' "SAML session cookie"
    reject_file_secret_pattern "$path" 'X-Phragma-CSRF[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9._~+/-]{12,}' "CSRF token"
  done < <(find "$EVIDENCE_DIR" -type f -print)
}

manifest_expected_files() {
  printf '%s\n' \
    "provider/idp-metadata.txt" \
    "provider/sp-metadata.txt" \
    "deployment/public-acs.txt" \
    "browser/login-redirect.txt" \
    "browser/assertion-session-cookie.txt" \
    "browser/invalid-signature-rejection.txt" \
    "browser/replayed-assertion-rejection.txt" \
    "browser/missing-relaystate-rejection.txt" \
    "browser/operator-mutation-with-csrf.txt" \
    "browser/missing-csrf-rejection.txt" \
    "browser/cross-origin-rejection.txt" \
    "browser/viewer-mutation-denial.txt" \
    "browser/logout-invalidation.txt" \
    "rbac/role-mapping.txt" \
    "redaction/identity-redacted.txt" \
    "redaction/audit-log-redacted.txt" \
    "redaction/support-bundle-redacted.txt"
}

validate_provider_evidence() {
  local dir="$EVIDENCE_DIR/provider"
  if ! require_dir "$dir" "SAML provider evidence directory"; then
    return
  fi

  require_file_matches "$dir/idp-metadata.txt" 'idp_entity_id[[:space:]]*=[[:space:]]*redacted' "SAML IdP entity redaction"
  require_file_matches "$dir/idp-metadata.txt" '(metadata_url|metadata_source)[[:space:]]*=[[:space:]]*(https://[^[:space:]]+|redacted)' "SAML IdP metadata source"
  require_file_matches "$dir/idp-metadata.txt" '(sso_url|single_sign_on_service)[[:space:]]*=[[:space:]]*(https://[^[:space:]]+|redacted)' "SAML IdP SSO URL"
  require_file_matches "$dir/idp-metadata.txt" '(metadata_signature|signing_certificate|certificate_fingerprint)[[:space:]]*=[[:space:]]*(valid|verified|pinned|redacted)' "SAML signing material validation"
  require_file_matches "$dir/sp-metadata.txt" 'sp_entity_id[[:space:]]*=[[:space:]]*(https://[^[:space:]]+|redacted)' "SAML SP entity ID"
  require_file_matches "$dir/sp-metadata.txt" 'acs_url[[:space:]]*=[[:space:]]*https://[^[:space:]]*/v1/auth/saml/acs([[:space:]]|$)' "SAML SP ACS URL"
}

validate_deployment_evidence() {
  local dir="$EVIDENCE_DIR/deployment"
  if ! require_dir "$dir" "SAML deployment evidence directory"; then
    return
  fi

  require_file_matches "$dir/public-acs.txt" 'acs_url[[:space:]]*=[[:space:]]*https://[^[:space:]]*/v1/auth/saml/acs([[:space:]]|$)' "SAML public HTTPS ACS URL"
  require_file_matches "$dir/public-acs.txt" 'public_https[[:space:]]*=[[:space:]]*true' "SAML public ACS HTTPS posture"
  require_file_matches "$dir/public-acs.txt" 'cookie_secure[[:space:]]*=[[:space:]]*true' "SAML secure-cookie deployment posture"
}

validate_browser_evidence() {
  local dir="$EVIDENCE_DIR/browser"
  if ! require_dir "$dir" "SAML browser evidence directory"; then
    return
  fi

  require_file_matches "$dir/login-redirect.txt" '(redirect_status|status)[[:space:]]*=[[:space:]]*(302|303)' "SAML login redirect"
  require_file_matches "$dir/login-redirect.txt" '(saml_request|authn_request)[[:space:]]*=[[:space:]]*(present|redacted)' "SAML AuthnRequest presence"
  require_file_matches "$dir/assertion-session-cookie.txt" 'assertion_validation[[:space:]]*=[[:space:]]*(passed|valid|ok)' "SAML assertion validation"
  require_file_matches "$dir/assertion-session-cookie.txt" 'Set-Cookie:[^[:cntrl:]]*saml[-_]?session[^[:cntrl:]]*HttpOnly' "SAML session cookie HttpOnly posture"
  require_file_matches "$dir/assertion-session-cookie.txt" 'Set-Cookie:[^[:cntrl:]]*saml[-_]?session[^[:cntrl:]]*SameSite=(Lax|Strict|None)' "SAML session cookie SameSite posture"
  require_file_matches "$dir/assertion-session-cookie.txt" 'Set-Cookie:[^[:cntrl:]]*saml[-_]?session[^[:cntrl:]]*Secure' "SAML session cookie Secure posture"
  require_file_matches "$dir/invalid-signature-rejection.txt" '(signature|assertion_signature)[[:space:]_-]*(invalid|rejected)[[:space:]]*=[[:space:]]*true' "SAML invalid-signature callback"
  require_file_matches "$dir/invalid-signature-rejection.txt" 'status[[:space:]]*=[[:space:]]*401' "SAML invalid-signature rejection"
  require_file_matches "$dir/replayed-assertion-rejection.txt" '(assertion|response)[[:space:]_-]*(replayed|duplicate)[[:space:]]*=[[:space:]]*true' "SAML replayed assertion callback"
  require_file_matches "$dir/replayed-assertion-rejection.txt" 'status[[:space:]]*=[[:space:]]*401' "SAML replayed assertion rejection"
  require_file_matches "$dir/missing-relaystate-rejection.txt" 'RelayState[[:space:]]*=[[:space:]]*(missing|absent)' "SAML missing RelayState callback"
  require_file_matches "$dir/missing-relaystate-rejection.txt" 'status[[:space:]]*=[[:space:]]*401' "SAML missing RelayState rejection"
  require_file_matches "$dir/operator-mutation-with-csrf.txt" 'actor_role[[:space:]]*=[[:space:]]*operator' "SAML operator mutation actor"
  require_file_matches "$dir/operator-mutation-with-csrf.txt" 'X-Phragma-CSRF:[[:space:]]*<redacted>' "SAML operator mutation CSRF header"
  require_file_matches "$dir/operator-mutation-with-csrf.txt" 'status[[:space:]]*=[[:space:]]*(200|201|202|204)' "SAML operator mutation success"
  require_file_matches "$dir/missing-csrf-rejection.txt" 'X-Phragma-CSRF[[:space:]]*=[[:space:]]*(missing|absent)' "SAML missing-CSRF request"
  require_file_matches "$dir/missing-csrf-rejection.txt" 'status[[:space:]]*=[[:space:]]*403' "SAML missing-CSRF rejection"
  require_file_matches "$dir/cross-origin-rejection.txt" '(same_origin|origin_allowed)[[:space:]]*=[[:space:]]*false' "SAML cross-origin request"
  require_file_matches "$dir/cross-origin-rejection.txt" 'status[[:space:]]*=[[:space:]]*403' "SAML cross-origin rejection"
  require_file_matches "$dir/viewer-mutation-denial.txt" 'actor_role[[:space:]]*=[[:space:]]*viewer' "SAML viewer mutation actor"
  require_file_matches "$dir/viewer-mutation-denial.txt" 'status[[:space:]]*=[[:space:]]*403' "SAML viewer mutation denial"
  require_file_matches "$dir/logout-invalidation.txt" 'logout_status[[:space:]]*=[[:space:]]*(200|202|204)' "SAML logout request"
  require_file_matches "$dir/logout-invalidation.txt" '(authenticated_after_logout|post_logout_authenticated)[[:space:]]*=[[:space:]]*false' "SAML logout invalidates session"
}

validate_rbac_evidence() {
  local dir="$EVIDENCE_DIR/rbac"
  if ! require_dir "$dir" "SAML RBAC evidence directory"; then
    return
  fi

  require_file_matches "$dir/role-mapping.txt" 'authSource[[:space:]]*=[[:space:]]*saml-session' "SAML shared auth source"
  require_file_matches "$dir/role-mapping.txt" 'role_attribute[[:space:]]*=[[:space:]]*[A-Za-z0-9._:@/-]+' "SAML role attribute"
  require_file_matches "$dir/role-mapping.txt" 'mapped_role[[:space:]]*=[[:space:]]*viewer' "SAML viewer role mapping"
  require_file_matches "$dir/role-mapping.txt" 'mapped_role[[:space:]]*=[[:space:]]*operator' "SAML operator role mapping"
  require_file_matches "$dir/role-mapping.txt" 'mapped_role[[:space:]]*=[[:space:]]*admin' "SAML admin role mapping"
}

validate_redaction_evidence() {
  local dir="$EVIDENCE_DIR/redaction"
  if ! require_dir "$dir" "SAML redaction evidence directory"; then
    return
  fi

  require_file_matches "$dir/identity-redacted.txt" 'idp_entity_id[[:space:]]*=[[:space:]]*redacted' "SAML IdP entity redaction"
  require_file_matches "$dir/identity-redacted.txt" 'sp_entity_id[[:space:]]*=[[:space:]]*redacted' "SAML SP entity redaction"
  require_file_matches "$dir/identity-redacted.txt" 'subject[[:space:]]*=[[:space:]]*redacted' "SAML subject redaction"
  require_file_matches "$dir/identity-redacted.txt" 'email[[:space:]]*=[[:space:]]*redacted' "SAML email redaction"
  require_file_matches "$dir/audit-log-redacted.txt" 'authSource[[:space:]]*=[[:space:]]*saml-session' "SAML audit auth source"
  require_file_matches "$dir/audit-log-redacted.txt" 'cookies[[:space:]]*=[[:space:]]*redacted' "SAML audit cookie redaction"
  require_file_matches "$dir/audit-log-redacted.txt" 'assertions[[:space:]]*=[[:space:]]*redacted' "SAML audit assertion redaction"
  require_file_matches "$dir/audit-log-redacted.txt" 'relaystate[[:space:]]*=[[:space:]]*redacted' "SAML audit RelayState redaction"
  require_file_matches "$dir/support-bundle-redacted.txt" 'cookies[[:space:]]*=[[:space:]]*redacted' "SAML support cookie redaction"
  require_file_matches "$dir/support-bundle-redacted.txt" 'assertions[[:space:]]*=[[:space:]]*redacted' "SAML support assertion redaction"
  require_file_matches "$dir/support-bundle-redacted.txt" 'relaystate[[:space:]]*=[[:space:]]*redacted' "SAML support RelayState redaction"
}

main() {
  parse_args "$@"

  log "check=$CHECK_NAME"
  log "mode=check"
  log "evidence_dir=$EVIDENCE_DIR"
  log "field_evidence_scope=real-idp-metadata,sp-metadata,https-acs,cookie-security,negative-callbacks,rbac,csrf-origin,logout,redaction"
  log "saml_field_evidence_scope=real-provider-backed,browser-sso,authn-request,assertion-validation,session-cookie,csrf,rbac"
  log "saml_field_negative_checks=invalid-signature,replayed-assertion,missing-relaystate,logout,viewer-denial"
  log "saml_field_redaction=idp-entity-redacted,sp-entity-redacted,subject-redacted,email-redacted,assertions-redacted,cookies-redacted"
  log "required_provider_evidence=idp-metadata,sp-metadata"
  log "required_deployment_evidence=public-https-acs,secure-cookie-posture"
  log "required_browser_evidence=login-redirect,assertion-session-cookie,invalid-signature-rejection,replayed-assertion-rejection,missing-relaystate-rejection,operator-mutation-with-csrf,missing-csrf-rejection,cross-origin-rejection,viewer-mutation-denial,logout-invalidation"
  log "required_rbac_evidence=viewer,operator,admin"
  log "required_redaction_evidence=identity-redacted,audit-log-redacted,support-bundle-redacted,global-secret-scan"
  log "manifest_sha256_policy=required,exact-regular-files,no-extra-files"
  log "redaction_scan=saml-response,relaystate,assertion,x509,private-key,cookie,csrf"

  if [ -z "$EVIDENCE_DIR" ]; then
    fail "--evidence-dir or SAML_FIELD_EVIDENCE_DIR is required"
  elif require_dir "$EVIDENCE_DIR" "SAML field evidence root"; then
    reject_symlink_tree
    manifest_sha256_verify "$EVIDENCE_DIR" $(manifest_expected_files)
    reject_unredacted_material
    validate_provider_evidence
    validate_deployment_evidence
    validate_browser_evidence
    validate_rbac_evidence
    validate_redaction_evidence
  fi

  if [ "$failures" -ne 0 ]; then
    log "status=failed"
    exit 1
  fi
  log "status=passed"
}

main "$@"
