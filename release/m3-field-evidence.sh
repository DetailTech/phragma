#!/usr/bin/env bash
set -u -o pipefail

CHECK_NAME="m3-field-evidence"
DEFAULT_REQUIRE="bgp,ipsec,wireguard"
EVIDENCE_DIR="${M3_FIELD_EVIDENCE_DIR:-}"
REQUIRE="${M3_FIELD_EVIDENCE_REQUIRE:-$DEFAULT_REQUIRE}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=release/manifest-sha256.sh
. "$SCRIPT_DIR/manifest-sha256.sh"

failures=0

usage() {
  cat <<'USAGE'
Usage: release/m3-field-evidence.sh --evidence-dir <dir> [--require bgp,ipsec,wireguard]

Validates manually collected M3 external field evidence before it is recorded
as release acceptance evidence. This does not run BGP, IPsec, or WireGuard; it
checks that the field bundle contains the command outputs needed to support
external protocol claims.

Required bundle layout:
  <dir>/manifest.sha256
  <dir>/bgp-external-peer/show-bgp-summary.txt
  <dir>/bgp-external-peer/ip-route-remote-prefix.txt
  <dir>/bgp-external-peer/frr-running-config.txt
  <dir>/ipsec-strongswan-sa-traffic/swanctl-list-conns.txt
  <dir>/ipsec-strongswan-sa-traffic/swanctl-list-sas.txt
  <dir>/ipsec-strongswan-sa-traffic/swanctl-list-pols.txt
  <dir>/ipsec-strongswan-sa-traffic/ip-xfrm-state.txt
  <dir>/ipsec-strongswan-sa-traffic/ip-xfrm-policy.txt
  <dir>/ipsec-strongswan-sa-traffic/protected-subnet-ping.txt
  <dir>/wireguard-external-client/wg-show.txt
  <dir>/wireguard-external-client/client-config-redacted.txt
  <dir>/wireguard-external-client/external-client-ping.txt
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
      --require)
        if [ "$#" -lt 2 ]; then
          fail "--require requires a comma-separated value"
          return
        fi
        REQUIRE="$2"
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

requires_scope() {
  local scope="$1"
  [ "$REQUIRE" = "all" ] && return 0
  case ",$REQUIRE," in
    *",$scope,"*) return 0 ;;
    *) return 1 ;;
  esac
}

required_scopes() {
  if [ "$REQUIRE" = "all" ]; then
    printf '%s\n' "$DEFAULT_REQUIRE"
    return
  fi
  printf '%s\n' "$REQUIRE"
}

validate_required_scopes() {
  if [ -z "$REQUIRE" ]; then
    fail "--require must name at least one scope"
    return
  fi
  if [ "$REQUIRE" = "all" ]; then
    return
  fi
  case "$REQUIRE" in
    ,*|*,|*,,*) fail "--require contains an empty scope: $REQUIRE" ;;
  esac

  local remaining="$REQUIRE"
  while [ -n "$remaining" ]; do
    local scope="${remaining%%,*}"
    if [ -z "$scope" ]; then
      fail "--require contains an empty scope: $REQUIRE"
    else
      case "$scope" in
        bgp|ipsec|wireguard) ;;
        *) fail "unknown --require scope: $scope" ;;
      esac
    fi

    if [ "$remaining" = "$scope" ]; then
      break
    fi
    remaining="${remaining#*,}"
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
    reject_file_secret_pattern "$path" '(^|[[:space:]])PrivateKey[[:space:]]*=[[:space:]]*["'"'"']?[A-Za-z0-9+/=._~-]{20,}' "WireGuard private key"
    reject_file_secret_pattern "$path" '(^|[[:space:]])PresharedKey[[:space:]]*=[[:space:]]*["'"'"']?[A-Za-z0-9+/=._~-]{20,}' "WireGuard preshared key"
    reject_file_secret_pattern "$path" '(^|[[:space:]_:-])(psk|preshared[_-]?key|pre[_-]?shared[_-]?key)[[:space:]_"'"'"'-]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9+/=._~-]{12,}' "IPsec pre-shared key"
    reject_file_secret_pattern "$path" 'Authorization:[[:space:]]*Bearer[[:space:]]+[A-Za-z0-9._~+/-]{12,}' "bearer token"
    reject_file_secret_pattern "$path" '(access_token|api[_-]?key|api[_-]?token)[[:space:]_"'"'"'-]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9._~+/-]{12,}' "API token"
    reject_file_secret_pattern "$path" 'https?://[^[:space:]/:@]+:[^[:space:]@]+@' "URL credentials"
    reject_file_secret_pattern "$path" '-----BEGIN[[:space:]][^-]*(PRIVATE|OPENSSH)[[:space:]]KEY-----' "private key block"
  done < <(find "$EVIDENCE_DIR" -type f -print)
}

manifest_expected_files() {
  if requires_scope bgp; then
    printf '%s\n' \
      "bgp-external-peer/show-bgp-summary.txt" \
      "bgp-external-peer/ip-route-remote-prefix.txt" \
      "bgp-external-peer/frr-running-config.txt"
  fi
  if requires_scope ipsec; then
    printf '%s\n' \
      "ipsec-strongswan-sa-traffic/swanctl-list-conns.txt" \
      "ipsec-strongswan-sa-traffic/swanctl-list-sas.txt" \
      "ipsec-strongswan-sa-traffic/swanctl-list-pols.txt" \
      "ipsec-strongswan-sa-traffic/ip-xfrm-state.txt" \
      "ipsec-strongswan-sa-traffic/ip-xfrm-policy.txt" \
      "ipsec-strongswan-sa-traffic/protected-subnet-ping.txt"
  fi
  if requires_scope wireguard; then
    printf '%s\n' \
      "wireguard-external-client/wg-show.txt" \
      "wireguard-external-client/client-config-redacted.txt" \
      "wireguard-external-client/external-client-ping.txt"
  fi
}

validate_bgp_evidence() {
  local dir="$EVIDENCE_DIR/bgp-external-peer"
  if ! require_dir "$dir" "BGP external-peer evidence directory"; then
    return
  fi
  require_file_matches "$dir/show-bgp-summary.txt" "Established" "BGP peer summary"
  require_file_matches "$dir/ip-route-remote-prefix.txt" "(proto bgp|[[:space:]]bgp[[:space:]]|[[:space:]]via[[:space:]])" "BGP learned route"
  require_file_matches "$dir/frr-running-config.txt" "(router bgp|neighbor .+ remote-as)" "BGP FRR running config"
}

validate_ipsec_evidence() {
  local dir="$EVIDENCE_DIR/ipsec-strongswan-sa-traffic"
  if ! require_dir "$dir" "IPsec strongSwan evidence directory"; then
    return
  fi
  require_file_matches "$dir/swanctl-list-conns.txt" "(local|remote|children)" "IPsec swanctl connection listing"
  require_file_matches "$dir/swanctl-list-sas.txt" "ESTABLISHED" "IPsec established IKE SA"
  require_file_matches "$dir/swanctl-list-sas.txt" "INSTALLED" "IPsec installed CHILD SA"
  require_file_matches "$dir/swanctl-list-pols.txt" "(local|remote|child|in|out)" "IPsec swanctl policy listing"
  require_file_matches "$dir/ip-xfrm-state.txt" "proto[[:space:]]+esp" "IPsec XFRM state"
  require_file_matches "$dir/ip-xfrm-policy.txt" "dir[[:space:]]+(in|out|fwd)" "IPsec XFRM policy"
  require_file_matches "$dir/protected-subnet-ping.txt" "0(\\.0)?% packet loss" "IPsec protected-subnet ping"
}

validate_wireguard_evidence() {
  local dir="$EVIDENCE_DIR/wireguard-external-client"
  if ! require_dir "$dir" "WireGuard external-client evidence directory"; then
    return
  fi
  require_file_matches "$dir/wg-show.txt" "latest handshake" "WireGuard handshake"
  require_file_matches "$dir/wg-show.txt" "transfer" "WireGuard transfer counters"
  require_file_matches "$dir/client-config-redacted.txt" "\\[Peer\\]" "WireGuard redacted client config"
  require_file_matches "$dir/external-client-ping.txt" "0(\\.0)?% packet loss" "WireGuard external-client ping"
}

main() {
  parse_args "$@"
  validate_required_scopes

  log "check=$CHECK_NAME"
  log "mode=check"
  log "evidence_dir=$EVIDENCE_DIR"
  log "field_evidence_scope=$(required_scopes)"
  log "required_bgp_evidence=show-bgp-summary,ip-route-remote-prefix,frr-running-config"
  log "required_ipsec_evidence=swanctl-list-conns,swanctl-list-sas,swanctl-list-pols,ip-xfrm-state,ip-xfrm-policy,protected-subnet-ping"
  log "required_wireguard_evidence=wg-show,client-config-redacted,external-client-ping"
  log "manifest_sha256_policy=required,exact-regular-files,no-extra-files"
  log "m3_field_redaction=wireguard-private-key-redacted,preshared-key-redacted,bearer-tokens-redacted,api-keys-redacted,url-credentials-redacted"
  log "redaction_scan=private-key,psk,bearer,api-key,token,url-userinfo"

  if [ -z "$EVIDENCE_DIR" ]; then
    fail "--evidence-dir or M3_FIELD_EVIDENCE_DIR is required"
  elif require_dir "$EVIDENCE_DIR" "M3 field evidence root"; then
    reject_symlink_tree
    manifest_sha256_verify "$EVIDENCE_DIR" $(manifest_expected_files)
    reject_unredacted_material
    if requires_scope bgp; then
      validate_bgp_evidence
    fi
    if requires_scope ipsec; then
      validate_ipsec_evidence
    fi
    if requires_scope wireguard; then
      validate_wireguard_evidence
    fi
  fi

  if [ "$failures" -ne 0 ]; then
    log "status=failed"
    exit 1
  fi
  log "status=passed"
}

main "$@"
