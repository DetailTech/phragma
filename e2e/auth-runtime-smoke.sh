#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="${WORK_DIR:-}"
SMOKE_PORT_OFFSET=$(( $$ % 1000 ))
DEFAULT_GRPC_PORT=$((31000 + SMOKE_PORT_OFFSET))
DEFAULT_HTTPS_PORT=$((32000 + SMOKE_PORT_OFFSET))
GRPC_LISTEN="${GRPC_LISTEN:-127.0.0.1:${DEFAULT_GRPC_PORT}}"
HTTPS_LISTEN="${HTTPS_LISTEN:-127.0.0.1:${DEFAULT_HTTPS_PORT}}"
RATE_LIMIT_RPM="${RATE_LIMIT_RPM:-60}"
RATE_LIMIT_BURST="${RATE_LIMIT_BURST:-3}"
HTTP_MAX_BODY_BYTES="${HTTP_MAX_BODY_BYTES:-128}"

SERVER_PID=""
REQUEST_ID=10

usage() {
  cat <<'EOF'
OpenNGFW rootless auth/UI runtime smoke.

Usage:
  e2e/auth-runtime-smoke.sh

Starts controld on loopback in dry-run mode with a temp local users file
containing only sha256 token_hash entries, then verifies auth, RBAC, TLS,
security headers, rate limiting, request body limiting, and unsafe no-auth
startup rejection.

Useful environment:
  GRPC_LISTEN=127.0.0.1:19443    override auto-selected gRPC port
  HTTPS_LISTEN=127.0.0.1:18080   override auto-selected HTTPS port
  WORK_DIR=/tmp/path
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }

require_cmds() {
  local missing=0
  for cmd in "$@"; do
    if ! have "$cmd"; then
      echo "missing command: $cmd" >&2
      missing=1
    fi
  done
  return "$missing"
}

make_work_dir() {
  if [ -n "$WORK_DIR" ]; then
    mkdir -p "$WORK_DIR"
  else
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/openngfw-auth-smoke.XXXXXX")"
  fi
  chmod 700 "$WORK_DIR"
}

cleanup() {
  local status=$?
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  if [ "$status" -ne 0 ] && [ -n "${WORK_DIR:-}" ] && [ -f "$WORK_DIR/controld.log" ]; then
    echo "--- controld log ---" >&2
    tail -n 120 "$WORK_DIR/controld.log" >&2 || true
  fi
  if [ -n "${WORK_DIR:-}" ]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

random_token() {
  if have openssl; then
    openssl rand -hex 32
    return
  fi
  dd if=/dev/urandom bs=32 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n'
}

sha256_hex() {
  if have shasum; then
    printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
    return
  fi
  if have sha256sum; then
    printf '%s' "$1" | sha256sum | awk '{print $1}'
    return
  fi
  echo "missing command: shasum or sha256sum" >&2
  return 1
}

write_curl_auth_config() {
  local path="$1"
  local token="$2"
  umask 077
  {
    printf 'header = "Authorization: Bearer %s"\n' "$token"
  } > "$path"
  chmod 600 "$path"
}

require_status() {
  local got="$1"
  local want="$2"
  local label="$3"
  if [ "$got" != "$want" ]; then
    echo "$label: got HTTP $got, want $want" >&2
    if [ -f "${BODY_FILE:-}" ]; then
      sed -n '1,160p' "$BODY_FILE" >&2 || true
    fi
    return 1
  fi
}

require_body_contains() {
  local pattern="$1"
  local label="$2"
  if ! grep -Eq "$pattern" "$BODY_FILE"; then
    echo "$label: response did not match $pattern" >&2
    sed -n '1,160p' "$BODY_FILE" >&2 || true
    return 1
  fi
}

require_header() {
  local header="$1"
  local pattern="$2"
  local label="$3"
  if ! awk -v h="$header" -v p="$pattern" '
    BEGIN { want = tolower(h) ":"; found = 0 }
    index(tolower($0), want) == 1 {
      value = substr($0, length(h) + 2)
      sub(/^[[:space:]]+/, "", value)
      sub(/\r$/, "", value)
      if (value ~ p) found = 1
    }
    END { exit found ? 0 : 1 }
  ' "$HEADERS_FILE"; then
    echo "$label: missing or unexpected $header header" >&2
    sed -n '1,120p' "$HEADERS_FILE" >&2 || true
    return 1
  fi
}

file_mode() {
  local path="$1"
  if stat -c %a "$path" >/dev/null 2>&1; then
    stat -c %a "$path"
    return
  fi
  stat -f %Lp "$path"
}

curl_request() {
  local method="$1"
  local path="$2"
  local config="${3:-}"
  local data_file="${4:-}"
  local xff="${5:-}"
  local follow="${6:-}"
  BODY_FILE="$WORK_DIR/body.txt"
  HEADERS_FILE="$WORK_DIR/headers.txt"
  CURL_ERR_FILE="$WORK_DIR/curl.err"
  : > "$BODY_FILE"
  : > "$HEADERS_FILE"
  : > "$CURL_ERR_FILE"

  if [ -z "$xff" ]; then
    REQUEST_ID=$((REQUEST_ID + 1))
    xff="198.51.100.$REQUEST_ID"
  fi

  local args=(
    -sS -k
    --connect-timeout 2
    --max-time 15
    -o "$BODY_FILE"
    -D "$HEADERS_FILE"
    -w "%{http_code}"
    -X "$method"
    -H "X-Forwarded-For: $xff"
  )
  if [ "$follow" = "follow" ]; then
    args+=(-L)
  fi
  if [ -n "$config" ]; then
    args+=(--config "$config")
  fi
  if [ -n "$data_file" ]; then
    args+=(-H "Content-Type: application/json" --data-binary "@$data_file")
  fi
  args+=("https://$HTTPS_LISTEN$path")

  HTTP_STATUS="$(curl "${args[@]}" 2>"$CURL_ERR_FILE")"
}

wait_for_controld() {
  local config="$1"
  local deadline=$((SECONDS + 60))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
      echo "controld exited before becoming ready" >&2
      return 1
    fi
    if curl_request GET /v1/system/status "$config" "" &&
      [ "$HTTP_STATUS" = "200" ] &&
      grep -Eq '"authEnabled"[[:space:]]*:[[:space:]]*true' "$BODY_FILE"; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for controld on https://$HTTPS_LISTEN" >&2
  if [ -s "$CURL_ERR_FILE" ]; then
    cat "$CURL_ERR_FILE" >&2
  fi
  return 1
}

start_controld() {
  local users_file="$1"
  local data_dir="$WORK_DIR/data"
  local log_dir="$WORK_DIR/log"
  mkdir -p "$data_dir" "$log_dir"

  local cmd_prefix=(env)
  local cmd=()
  if [ -x "$REPO_ROOT/bin/controld" ]; then
    cmd=("$REPO_ROOT/bin/controld")
  else
    require_cmds go
    cmd_prefix+=(GOCACHE="$WORK_DIR/go-cache")
    cmd=(go run ./cmd/controld)
  fi

  (
    cd "$REPO_ROOT"
    "${cmd_prefix[@]}" "${cmd[@]}" \
      --dry-run \
      --listen "$GRPC_LISTEN" \
      --http-listen "$HTTPS_LISTEN" \
      --data-dir "$data_dir" \
      --log-dir "$log_dir" \
      --users-file "$users_file" \
      --rate-limit-rpm "$RATE_LIMIT_RPM" \
      --rate-limit-burst "$RATE_LIMIT_BURST" \
      --trusted-proxy-cidrs "127.0.0.1/32" \
      --http-max-body-bytes "$HTTP_MAX_BODY_BYTES"
  ) >"$WORK_DIR/controld.log" 2>&1 &
  SERVER_PID=$!
}

require_startup_rejected() {
  local label="$1"
  local want="$2"
  shift 2

  local data_dir="$WORK_DIR/startup-reject-$label-data"
  local log_dir="$WORK_DIR/startup-reject-$label-log"
  local output="$WORK_DIR/startup-reject-$label.out"
  mkdir -p "$data_dir" "$log_dir"

  local cmd_prefix=(env)
  local cmd=()
  if [ -x "$REPO_ROOT/bin/controld" ]; then
    cmd=("$REPO_ROOT/bin/controld")
  else
    require_cmds go
    cmd_prefix+=(GOCACHE="$WORK_DIR/go-cache")
    cmd=(go run ./cmd/controld)
  fi

  (
    cd "$REPO_ROOT"
    "${cmd_prefix[@]}" "${cmd[@]}" "$@" \
      --data-dir "$data_dir" \
      --log-dir "$log_dir"
  ) >"$output" 2>&1 &
  local pid=$!
  local deadline=$((SECONDS + 60))
  while kill -0 "$pid" >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
      echo "$label: controld kept running; expected startup rejection" >&2
      sed -n '1,160p' "$output" >&2 || true
      return 1
    fi
    sleep 1
  done

  local status=0
  set +e
  wait "$pid"
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    echo "$label: controld startup succeeded; expected rejection" >&2
    sed -n '1,160p' "$output" >&2 || true
    return 1
  fi
  if ! grep -Fq -- "$want" "$output"; then
    echo "$label: startup rejection did not include expected text: $want" >&2
    sed -n '1,160p' "$output" >&2 || true
    return 1
  fi
}

write_users_file() {
  local users_file="$1"
  local admin_hash="$2"
  local viewer_hash="$3"
  umask 077
  {
    printf 'users:\n'
    printf '  - name: smoke-admin\n'
    printf '    token_hash: sha256:%s\n' "$admin_hash"
    printf '    role: admin\n'
    printf '  - name: smoke-viewer\n'
    printf '    token_hash: sha256:%s\n' "$viewer_hash"
    printf '    role: viewer\n'
  } > "$users_file"
  chmod 600 "$users_file"
}

write_large_body() {
  local path="$1"
  {
    printf '{"padding":"'
    local i=0
    while [ "$i" -lt 256 ]; do
      printf x
      i=$((i + 1))
    done
    printf '"}'
  } > "$path"
}

main() {
  require_cmds curl awk grep sed tail kill
  make_work_dir

  local admin_token viewer_token admin_hash viewer_hash
  admin_token="$(random_token)"
  viewer_token="$(random_token)"
  admin_hash="$(sha256_hex "$admin_token")"
  viewer_hash="$(sha256_hex "$viewer_token")"

  local users_file="$WORK_DIR/users.yaml"
  local admin_curl="$WORK_DIR/admin.curl"
  local viewer_curl="$WORK_DIR/viewer.curl"
  local bad_curl="$WORK_DIR/bad.curl"
  write_users_file "$users_file" "$admin_hash" "$viewer_hash"
  write_curl_auth_config "$admin_curl" "$admin_token"
  write_curl_auth_config "$viewer_curl" "$viewer_token"
  write_curl_auth_config "$bad_curl" "bad-token-for-smoke"
  unset admin_token viewer_token

  require_startup_rejected "missing-auth" "API authentication is required" \
    --dry-run \
    --listen "127.0.0.1:1" \
    --http-listen "127.0.0.1:1"
  require_startup_rejected "noauth-without-dry-run" "--allow-unauthenticated-local requires --dry-run" \
    --allow-unauthenticated-local \
    --listen "127.0.0.1:1" \
    --http-listen "127.0.0.1:1"

  start_controld "$users_file"
  wait_for_controld "$admin_curl"

  curl_request GET /v1/system/status
  require_status "$HTTP_STATUS" 401 "missing token is rejected"

  curl_request GET /v1/system/status "$bad_curl"
  require_status "$HTTP_STATUS" 401 "bad token is rejected"

  curl_request GET /v1/system/identity "$admin_curl"
  require_status "$HTTP_STATUS" 200 "admin identity is accepted"
  require_body_contains '"actor"[[:space:]]*:[[:space:]]*"smoke-admin"' "admin identity"
  require_body_contains '"role"[[:space:]]*:[[:space:]]*"admin"' "admin identity"
  require_body_contains '"authEnabled"[[:space:]]*:[[:space:]]*true' "admin identity"
  require_body_contains '"authSource"[[:space:]]*:[[:space:]]*"local-users-file"' "admin identity"

  curl_request GET /v1/system/status "$admin_curl"
  require_status "$HTTP_STATUS" 200 "admin status is accepted"
  require_body_contains '"runtime"[[:space:]]*:' "system status"
  require_body_contains '"authEnabled"[[:space:]]*:[[:space:]]*true' "system status"
  require_body_contains '"tlsEnabled"[[:space:]]*:[[:space:]]*true' "system status"
  require_body_contains '"dryRun"[[:space:]]*:[[:space:]]*true' "system status"
  require_body_contains '"rateLimitEnabled"[[:space:]]*:[[:space:]]*true' "system status"
  require_body_contains '"rateLimitBurst"[[:space:]]*:[[:space:]]*'"$RATE_LIMIT_BURST" "system status"
  require_body_contains '"httpMaxBodyBytes"[[:space:]]*:[[:space:]]*"?'"$HTTP_MAX_BODY_BYTES"'"?' "system status"

  curl_request GET /v1/system/status "$viewer_curl"
  require_status "$HTTP_STATUS" 200 "viewer read path is allowed"

  local small_body="$WORK_DIR/small.json"
  printf '{}\n' > "$small_body"
  curl_request POST /v1/system/tune "$viewer_curl" "$small_body"
  require_status "$HTTP_STATUS" 403 "viewer admin path is denied"

  curl_request POST /v1/system/tune "$admin_curl" "$small_body"
  require_status "$HTTP_STATUS" 200 "admin admin path is allowed"
  require_body_contains '"profile"[[:space:]]*:' "admin tune preview"

  curl_request GET /ui/
  require_status "$HTTP_STATUS" 200 "WebUI loads over TLS"
  require_body_contains 'Phragma|OpenNGFW|phragma' "WebUI index"
  require_header "Strict-Transport-Security" "max-age=31536000" "TLS posture"
  require_header "X-Content-Type-Options" "nosniff" "security headers"
  require_header "X-Frame-Options" "DENY" "security headers"
  require_header "Content-Security-Policy" "default-src 'self'" "security headers"

  curl_request GET /api-spec.yaml "" "" "" follow
  require_status "$HTTP_STATUS" 200 "API spec loads over TLS"
  require_body_contains 'swagger: "2\.0"' "API spec"
  require_body_contains 'title: Phragma Control Plane API' "API spec"
  require_body_contains 'BearerAuth:' "API spec"
  require_header "Strict-Transport-Security" "max-age=31536000" "API spec TLS posture"
  require_header "Cache-Control" "no-store" "API spec cache posture"
  require_header "X-Content-Type-Options" "nosniff" "API spec security headers"

  local large_body="$WORK_DIR/large.json"
  write_large_body "$large_body"
  curl_request POST /v1/system/tune "$admin_curl" "$large_body"
  require_status "$HTTP_STATUS" 413 "oversized request body is rejected"

  local rate_xff="203.0.113.77"
  local i=0
  while [ "$i" -le "$RATE_LIMIT_BURST" ]; do
    curl_request GET /v1/system/status "" "" "$rate_xff"
    i=$((i + 1))
  done
  require_status "$HTTP_STATUS" 429 "rate limit is enforced"
  require_header "Retry-After" "^[0-9]+$" "rate limit"

  if grep -Eq '^[[:space:]]*token:[[:space:]]+' "$users_file"; then
    echo "users file contains plaintext token entries" >&2
    return 1
  fi
  if [ "$(file_mode "$users_file")" != "600" ]; then
    echo "users file mode is not 600" >&2
    return 1
  fi

  echo "auth_runtime_smoke_scope=hashed-local-users,rbac,tls-security-headers,request-limits,rate-limit,unsafe-noauth-startup-guard"
  echo "auth_runtime_startup_guard=missing-auth-rejected,unauthenticated-local-requires-dry-run"
  echo "status=passed"
  echo "auth runtime smoke passed: https://$HTTPS_LISTEN"
}

main "$@"
