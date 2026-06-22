#!/usr/bin/env bash
set -u -o pipefail

CHECK_NAME="m5-oidc-field-evidence"
EVIDENCE_DIR="${OIDC_FIELD_EVIDENCE_DIR:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

failures=0

# shellcheck source=release/manifest-sha256.sh
. "$SCRIPT_DIR/manifest-sha256.sh"

usage() {
  cat <<'USAGE'
Usage: release/oidc-field-evidence.sh --evidence-dir <dir>

Validates a redacted real-provider OIDC browser SSO field evidence bundle before
it is recorded as release acceptance evidence. This does not contact the OIDC
provider or run a browser; it checks that the captured bundle contains the
deployment-specific command and browser outputs needed to support enterprise
OIDC readiness claims.

Required bundle layout:
  <dir>/manifest.sha256
  <dir>/provider/issuer-client-discovery.txt
  <dir>/provider/id-token-validation.txt
  <dir>/deployment/public-callback.txt
  <dir>/deployment/client-secret-file-permissions.txt
  <dir>/browser/session-cookie.txt
  <dir>/browser/missing-state-rejection.txt
  <dir>/browser/reused-state-rejection.txt
  <dir>/browser/nonce-mismatch-rejection.txt
  <dir>/browser/pkce-exchange-failure.txt
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

require_existing_file_matches() {
  local path="$1"
  local regex="$2"
  local desc="$3"
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
    reject_file_secret_pattern "$path" 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' "JWT/OIDC token"
    reject_file_secret_pattern "$path" 'Authorization:[[:space:]]*Bearer[[:space:]]+[A-Za-z0-9._~+/-]{12,}' "bearer token"
    reject_file_secret_pattern "$path" '(access_token|id_token|refresh_token)[[:space:]_"'"'"'-]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9._~+/-]{12,}' "OAuth token"
    reject_file_secret_pattern "$path" '(^|[?&[:space:]])code[[:space:]]*=[[:space:]]*["'"'"']?[A-Za-z0-9._~-]{8,}' "OIDC authorization code"
    reject_file_secret_pattern "$path" '(^|[[:space:]])Cookie:[^[:cntrl:]]*=[A-Za-z0-9._~+/-]{12,}' "cookie"
    reject_file_secret_pattern "$path" 'Set-Cookie:[^[:cntrl:]]*=[A-Za-z0-9._~+/-]{12,}' "set-cookie value"
    reject_file_secret_pattern "$path" 'oidc[-_]?session[[:space:]]*=[[:space:]]*["'"'"']?[A-Za-z0-9._~+/-]{12,}' "OIDC session cookie"
    reject_file_secret_pattern "$path" 'client[_-]?secret[[:space:]_"'"'"'-]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9._~+/-]{8,}' "OIDC client secret"
    reject_file_secret_pattern "$path" 'X-Phragma-CSRF[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9._~+/-]{12,}' "CSRF token"
  done < <(find "$EVIDENCE_DIR" -type f -print)
}

manifest_expected_files() {
  printf '%s\n' \
    "provider/issuer-client-discovery.txt" \
    "provider/id-token-validation.txt" \
    "deployment/public-callback.txt" \
    "deployment/client-secret-file-permissions.txt" \
    "browser/session-cookie.txt" \
    "browser/missing-state-rejection.txt" \
    "browser/reused-state-rejection.txt" \
    "browser/nonce-mismatch-rejection.txt" \
    "browser/pkce-exchange-failure.txt" \
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
  if ! require_dir "$dir" "OIDC provider evidence directory"; then
    return
  fi

  require_file_matches "$dir/issuer-client-discovery.txt" 'issuer[[:space:]]*=[[:space:]]*https://[^[:space:]]+' "OIDC issuer discovery"
  require_file_matches "$dir/issuer-client-discovery.txt" 'client_id[[:space:]]*=[[:space:]]*[A-Za-z0-9._:@/-]+' "OIDC client ID"
  require_file_matches "$dir/issuer-client-discovery.txt" '(discovery_document|openid-configuration)[[:space:]]*=[[:space:]]*(ok|valid|passed)' "OIDC discovery document"
  require_file_matches "$dir/issuer-client-discovery.txt" 'jwks_uri[[:space:]]*=[[:space:]]*https://[^[:space:]]+' "OIDC JWKS discovery"
  require_file_matches "$dir/id-token-validation.txt" 'id_token_validation[[:space:]]*=[[:space:]]*(passed|valid|ok)' "OIDC ID-token validation"
  require_file_matches "$dir/id-token-validation.txt" 'signature[[:space:]]*=[[:space:]]*(valid|verified|passed)' "OIDC ID-token signature validation"
  require_file_matches "$dir/id-token-validation.txt" 'issuer[[:space:]]*=[[:space:]]*(matched|valid|verified|passed)' "OIDC ID-token issuer validation"
  require_file_matches "$dir/id-token-validation.txt" 'audience[[:space:]]*=[[:space:]]*(matched|valid|verified|passed)' "OIDC ID-token audience validation"
  require_file_matches "$dir/id-token-validation.txt" '(expiration|exp)[[:space:]]*=[[:space:]]*(valid|verified|passed)' "OIDC ID-token expiration validation"
}

validate_client_secret_file_permissions() {
  local path="$1"
  if ! require_nonempty_file "$path" "OIDC client-secret file permission evidence"; then
    return
  fi

  if grep -Eiq 'client_secret_used[[:space:]]*=[[:space:]]*false' "$path"; then
    ok "OIDC client-secret file permission evidence states no client secret is used"
    return
  fi

  if ! grep -Eiq 'client_secret_used[[:space:]]*=[[:space:]]*true' "$path"; then
    fail "OIDC client-secret file permission evidence must state client_secret_used=true or false"
    return
  fi

  require_existing_file_matches "$path" '(regular_file|is_regular_file|type)[[:space:]]*=[[:space:]]*(true|regular)' "OIDC client-secret file is regular"
  require_existing_file_matches "$path" 'symlink[[:space:]]*=[[:space:]]*false' "OIDC client-secret file is not symlinked"
  require_existing_file_matches "$path" '(mode|permissions)[[:space:]]*=[[:space:]]*(0?600|-rw-------)' "OIDC client-secret file private mode"
}

validate_deployment_evidence() {
  local dir="$EVIDENCE_DIR/deployment"
  if ! require_dir "$dir" "OIDC deployment evidence directory"; then
    return
  fi

  require_file_matches "$dir/public-callback.txt" 'redirect_url[[:space:]]*=[[:space:]]*https://[^[:space:]]*/v1/auth/oidc/callback([[:space:]]|$)' "OIDC public HTTPS callback URL"
  require_file_matches "$dir/public-callback.txt" 'public_https[[:space:]]*=[[:space:]]*true' "OIDC public callback HTTPS posture"
  validate_client_secret_file_permissions "$dir/client-secret-file-permissions.txt"
}

validate_browser_evidence() {
  local dir="$EVIDENCE_DIR/browser"
  if ! require_dir "$dir" "OIDC browser evidence directory"; then
    return
  fi

  require_file_matches "$dir/session-cookie.txt" 'Set-Cookie:[^[:cntrl:]]*oidc[-_]?session[^[:cntrl:]]*HttpOnly' "OIDC session cookie HttpOnly posture"
  require_file_matches "$dir/session-cookie.txt" 'Set-Cookie:[^[:cntrl:]]*oidc[-_]?session[^[:cntrl:]]*SameSite=(Lax|Strict|None)' "OIDC session cookie SameSite posture"
  require_file_matches "$dir/session-cookie.txt" 'Set-Cookie:[^[:cntrl:]]*oidc[-_]?session[^[:cntrl:]]*Secure' "OIDC session cookie Secure posture"
  require_file_matches "$dir/missing-state-rejection.txt" 'state[[:space:]]*=[[:space:]]*(missing|absent)' "OIDC missing-state callback"
  require_file_matches "$dir/missing-state-rejection.txt" 'status[[:space:]]*=[[:space:]]*401' "OIDC missing-state rejection"
  require_file_matches "$dir/reused-state-rejection.txt" 'state[[:space:]]*=[[:space:]]*(reused|consumed)' "OIDC reused-state callback"
  require_file_matches "$dir/reused-state-rejection.txt" 'status[[:space:]]*=[[:space:]]*401' "OIDC reused-state rejection"
  require_file_matches "$dir/nonce-mismatch-rejection.txt" 'nonce[[:space:]_-]*mismatch[[:space:]]*=[[:space:]]*true' "OIDC nonce-mismatch callback"
  require_file_matches "$dir/nonce-mismatch-rejection.txt" 'status[[:space:]]*=[[:space:]]*401' "OIDC nonce-mismatch rejection"
  require_file_matches "$dir/pkce-exchange-failure.txt" '(pkce|code_verifier)[[:space:]_-]*(exchange_)?failure[[:space:]]*=[[:space:]]*true' "OIDC PKCE exchange failure"
  require_file_matches "$dir/pkce-exchange-failure.txt" 'status[[:space:]]*=[[:space:]]*401' "OIDC PKCE exchange-failure rejection"
  require_file_matches "$dir/operator-mutation-with-csrf.txt" 'actor_role[[:space:]]*=[[:space:]]*operator' "OIDC operator mutation actor"
  require_file_matches "$dir/operator-mutation-with-csrf.txt" 'X-Phragma-CSRF:[[:space:]]*<redacted>' "OIDC operator mutation CSRF header"
  require_file_matches "$dir/operator-mutation-with-csrf.txt" 'status[[:space:]]*=[[:space:]]*(200|201|202|204)' "OIDC operator mutation success"
  require_file_matches "$dir/missing-csrf-rejection.txt" 'X-Phragma-CSRF[[:space:]]*=[[:space:]]*(missing|absent)' "OIDC missing-CSRF request"
  require_file_matches "$dir/missing-csrf-rejection.txt" 'status[[:space:]]*=[[:space:]]*403' "OIDC missing-CSRF rejection"
  require_file_matches "$dir/cross-origin-rejection.txt" '(same_origin|origin_allowed)[[:space:]]*=[[:space:]]*false' "OIDC cross-origin request"
  require_file_matches "$dir/cross-origin-rejection.txt" 'status[[:space:]]*=[[:space:]]*403' "OIDC cross-origin rejection"
  require_file_matches "$dir/viewer-mutation-denial.txt" 'actor_role[[:space:]]*=[[:space:]]*viewer' "OIDC viewer mutation actor"
  require_file_matches "$dir/viewer-mutation-denial.txt" 'status[[:space:]]*=[[:space:]]*403' "OIDC viewer mutation denial"
  require_file_matches "$dir/logout-invalidation.txt" 'logout_status[[:space:]]*=[[:space:]]*(200|202|204)' "OIDC logout request"
  require_file_matches "$dir/logout-invalidation.txt" '(authenticated_after_logout|post_logout_authenticated)[[:space:]]*=[[:space:]]*false' "OIDC logout invalidates session"
}

validate_rbac_evidence() {
  local dir="$EVIDENCE_DIR/rbac"
  if ! require_dir "$dir" "OIDC RBAC evidence directory"; then
    return
  fi

  require_file_matches "$dir/role-mapping.txt" 'authSource[[:space:]]*=[[:space:]]*oidc-session' "OIDC shared auth source"
  require_file_matches "$dir/role-mapping.txt" 'mapped_role[[:space:]]*=[[:space:]]*viewer' "OIDC viewer role mapping"
  require_file_matches "$dir/role-mapping.txt" 'mapped_role[[:space:]]*=[[:space:]]*operator' "OIDC operator role mapping"
  require_file_matches "$dir/role-mapping.txt" 'mapped_role[[:space:]]*=[[:space:]]*admin' "OIDC admin role mapping"
}

validate_redaction_evidence() {
  local dir="$EVIDENCE_DIR/redaction"
  if ! require_dir "$dir" "OIDC redaction evidence directory"; then
    return
  fi

  require_file_matches "$dir/identity-redacted.txt" 'issuer_host[[:space:]]*=[[:space:]]*redacted' "OIDC issuer host redaction"
  require_file_matches "$dir/identity-redacted.txt" 'client_id[[:space:]]*=[[:space:]]*redacted' "OIDC client ID redaction"
  require_file_matches "$dir/identity-redacted.txt" 'subject[[:space:]]*=[[:space:]]*redacted' "OIDC subject redaction"
  require_file_matches "$dir/identity-redacted.txt" 'email[[:space:]]*=[[:space:]]*redacted' "OIDC email redaction"
  require_file_matches "$dir/audit-log-redacted.txt" 'authSource[[:space:]]*=[[:space:]]*oidc-session' "OIDC audit auth source"
  require_file_matches "$dir/audit-log-redacted.txt" 'cookies[[:space:]]*=[[:space:]]*redacted' "OIDC audit cookie redaction"
  require_file_matches "$dir/audit-log-redacted.txt" 'codes[[:space:]]*=[[:space:]]*redacted' "OIDC audit code redaction"
  require_file_matches "$dir/audit-log-redacted.txt" 'tokens[[:space:]]*=[[:space:]]*redacted' "OIDC audit token redaction"
  require_file_matches "$dir/audit-log-redacted.txt" 'client_secrets[[:space:]]*=[[:space:]]*redacted' "OIDC audit client-secret redaction"
  require_file_matches "$dir/support-bundle-redacted.txt" 'cookies[[:space:]]*=[[:space:]]*redacted' "OIDC support cookie redaction"
  require_file_matches "$dir/support-bundle-redacted.txt" 'codes[[:space:]]*=[[:space:]]*redacted' "OIDC support code redaction"
  require_file_matches "$dir/support-bundle-redacted.txt" 'tokens[[:space:]]*=[[:space:]]*redacted' "OIDC support token redaction"
  require_file_matches "$dir/support-bundle-redacted.txt" 'client_secrets[[:space:]]*=[[:space:]]*redacted' "OIDC support client-secret redaction"
}

main() {
  parse_args "$@"

  log "check=$CHECK_NAME"
  log "mode=check"
  log "evidence_dir=$EVIDENCE_DIR"
  log "field_evidence_scope=real-issuer-client,id-token-validation,https-callback,secret-file,cookie-security,negative-callbacks,rbac,csrf-origin,logout,redaction"
  log "oidc_field_evidence_scope=real-provider-backed,browser-sso,authorization-code-pkce,id-token-verification,nonce,session-cookie,csrf,rbac"
  log "oidc_field_negative_checks=missing-state,reused-state,nonce-mismatch,pkce-exchange-failure,logout,viewer-denial"
  log "oidc_field_redaction=issuer-host-redacted,client-id-redacted,subject-redacted,email-redacted,tokens-redacted,cookies-redacted"
  log "required_provider_evidence=issuer-client-discovery,id-token-validation"
  log "required_deployment_evidence=public-https-callback,client-secret-file-permissions"
  log "required_browser_evidence=session-cookie,missing-state-rejection,reused-state-rejection,nonce-mismatch-rejection,pkce-exchange-failure,operator-mutation-with-csrf,missing-csrf-rejection,cross-origin-rejection,viewer-mutation-denial,logout-invalidation"
  log "required_rbac_evidence=viewer,operator,admin"
  log "required_redaction_evidence=identity-redacted,audit-log-redacted,support-bundle-redacted,global-secret-scan"
  log "manifest_sha256_policy=required,exact-regular-files,no-extra-files"
  log "redaction_scan=jwt,bearer,oauth-token,cookie,auth-code,client-secret,csrf"

  if [ -z "$EVIDENCE_DIR" ]; then
    fail "--evidence-dir or OIDC_FIELD_EVIDENCE_DIR is required"
  elif require_dir "$EVIDENCE_DIR" "OIDC field evidence root"; then
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
