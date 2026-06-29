#!/usr/bin/env bash
set -euo pipefail

MODE="check"

CLIENT_NS="${CLIENT_NS:-ongfw-smoke-client}"
SERVER_NS="${SERVER_NS:-ongfw-smoke-server}"
FW_CLIENT_IF="${FW_CLIENT_IF:-osmc0}"
FW_SERVER_IF="${FW_SERVER_IF:-osms0}"
CLIENT_PEER_IF="${CLIENT_PEER_IF:-csmoke0}"
SERVER_PEER_IF="${SERVER_PEER_IF:-ssmoke0}"
FW_CLIENT_IP="${FW_CLIENT_IP:-10.251.1.1}"
CLIENT_IP="${CLIENT_IP:-10.251.1.2}"
FW_SERVER_IP="${FW_SERVER_IP:-10.251.2.1}"
SERVER_IP="${SERVER_IP:-10.251.2.2}"
CIDR_PREFIX="${CIDR_PREFIX:-24}"
TARGET_PORT="${TARGET_PORT:-18080}"
GRPC_LISTEN="${GRPC_LISTEN:-127.0.0.1:9443}"
HTTPS_LISTEN="${HTTPS_LISTEN:-127.0.0.1:8080}"
RUN_INSTALL="${RUN_INSTALL:-1}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="${WORK_DIR:-/tmp/openngfw-install-smoke}"
POLICY_FILE="$WORK_DIR/policy.yaml"
SERVER_LOG="$WORK_DIR/server.log"

usage() {
  cat <<'EOF'
OpenNGFW 10-minute install smoke test.

Usage:
  e2e/install-smoke.sh --check
  sudo e2e/install-smoke.sh --run

Modes:
  --check  Non-destructive static preflight suitable for CI and macOS.
  --run    Disposable Linux host/VM acceptance test. Installs OpenNGFW unless
           RUN_INSTALL=0, then proves an installed daemon can commit policy and
           filter traffic between two network namespaces.

Useful environment:
  RUN_INSTALL=0       skip deploy/install.sh and test an existing install
  WORK_DIR=/tmp/path  store temporary policy/log files
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --check) MODE="check" ;;
    --run) MODE="run" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
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

check_vector_remote_guard() {
  awk '
    function is_if(line) { return line ~ /^[[:space:]]*if[[:space:]]/ }
    function is_else(line) { return line ~ /^[[:space:]]*else([[:space:]]*|[[:space:]]*#.*)$/ }
    function is_fi(line) { return line ~ /^[[:space:]]*fi([[:space:]]*|[[:space:]]*#.*)$/ }
    function remote_vector(line) {
      return line ~ /sh[.]vector[.]dev/ || line ~ /VECTOR_INSTALLER/ || line ~ /bash[[:space:]]+"[$]VECTOR_INSTALLER"/
    }
    {
      line = $0
      in_unsafe_then = unsafe_depth > 0 && depth >= unsafe_depth && !unsafe_else
      if (remote_vector(line) && line !~ /OPENNGFW_UNSAFE_REMOTE_VECTOR_INSTALL/ && !in_unsafe_then) {
        printf "%s:%d: remote Vector installer logic must stay inside OPENNGFW_UNSAFE_REMOTE_VECTOR_INSTALL=1 branch\n", FILENAME, FNR > "/dev/stderr"
        failed = 1
      }
      if (line ~ /^[[:space:]]*if[[:space:]].*OPENNGFW_UNSAFE_REMOTE_VECTOR_INSTALL.*==[[:space:]]*"1"/) {
        unsafe_depth = depth + 1
        unsafe_else = 0
      }
      if (is_if(line)) depth++
      if (is_else(line) && unsafe_depth > 0 && depth == unsafe_depth) unsafe_else = 1
      if (is_fi(line)) {
        if (unsafe_depth > 0 && depth == unsafe_depth) {
          unsafe_depth = 0
          unsafe_else = 0
        }
        if (depth > 0) depth--
      }
    }
    END { exit failed ? 1 : 0 }
  ' "$1"
}

check_admin_token_not_stdout() {
  awk '
    function token_ref(line) {
      return line ~ /[$][{]ADMIN_TOKEN[}]/ || line ~ /[$]ADMIN_TOKEN([^_[:alnum:]]|$)/
    }
    function command_prints(line) {
      return line ~ /^[[:space:]]*(echo|printf|cat)[[:space:]]/
    }
    function heredoc_marker(line, marker) {
      marker = line
      sub(/^.*<</, "", marker)
      sub(/^[[:space:]]*-?/, "", marker)
      sub(/[[:space:]].*$/, "", marker)
      gsub(/["\047]/, "", marker)
      return marker
    }
    {
      line = $0
      if (in_heredoc) {
        if (line == heredoc_end) {
          in_heredoc = 0
          heredoc_safe = 0
          heredoc_end = ""
          next
        }
        if (!heredoc_safe && token_ref(line)) {
          printf "%s:%d: generated admin token must not be written to stdout heredocs\n", FILENAME, FNR > "/dev/stderr"
          failed = 1
        }
        next
      }
      if (line ~ /<</) {
        in_heredoc = 1
        heredoc_safe = line ~ />/
        heredoc_end = heredoc_marker(line)
      }
      if (token_ref(line) && command_prints(line) && line !~ />/) {
        printf "%s:%d: generated admin token must not be printed to stdout\n", FILENAME, FNR > "/dev/stderr"
        failed = 1
      }
    }
    END { exit failed ? 1 : 0 }
  ' "$1"
}

write_controld_version_stub() {
  local path="$1"
  local commit="$2"
  cat > "$path" <<EOF
#!/usr/bin/env bash
if [ "\${1:-}" = "--version" ]; then
  printf '%s\n' 'Phragma test (commit ${commit})'
  exit 0
fi
exit 2
EOF
  chmod 0755 "$path"
}

write_ngfwctl_version_stub() {
  local path="$1"
  local commit="$2"
  cat > "$path" <<EOF
#!/usr/bin/env bash
if [ "\${1:-}" = "version" ]; then
  printf '%s\n' 'ngfwctl Phragma test (commit ${commit})' >&2
  exit 0
fi
exit 2
EOF
  chmod 0755 "$path"
}

check_prebuilt_binary_pair_commit() (
  set -e

  local pair_dir expected_commit stale_commit
  pair_dir="$(mktemp -d "${TMPDIR:-/tmp}/openngfw-prebuilt-pair.XXXXXX")"
  trap 'rm -rf -- "$pair_dir"' EXIT
  expected_commit="0123456789abcdef0123456789abcdef01234567"
  stale_commit="fedcba9876543210fedcba9876543210fedcba98"

  write_controld_version_stub "$pair_dir/controld" "$expected_commit"
  write_ngfwctl_version_stub "$pair_dir/ngfwctl" "$stale_commit"
  if COMMIT="$expected_commit" BIN_DIR="$pair_dir" \
      "$REPO_ROOT/deploy/install.sh" --check-prebuilt-binaries \
      >"$pair_dir/stale-pair.out" 2>&1; then
    echo "deploy/install.sh accepted a stale ngfwctl paired with a matching controld" >&2
    return 1
  fi
  if ! grep -q '^status=failed$' "$pair_dir/stale-pair.out"; then
    echo "deploy/install.sh did not report a failed stale-pair preflight" >&2
    return 1
  fi

  write_ngfwctl_version_stub "$pair_dir/ngfwctl" "$expected_commit"
  if ! COMMIT="$expected_commit" BIN_DIR="$pair_dir" \
      "$REPO_ROOT/deploy/install.sh" --check-prebuilt-binaries \
      >"$pair_dir/matching-pair.out" 2>&1; then
    echo "deploy/install.sh rejected a prebuilt pair matching the expected commit" >&2
    cat "$pair_dir/matching-pair.out" >&2
    return 1
  fi
  if ! grep -q '^status=passed$' "$pair_dir/matching-pair.out"; then
    echo "deploy/install.sh did not report a passing matching-pair preflight" >&2
    return 1
  fi

  echo "prebuilt_binary_pair_commit_check=passed"
)

unit_setting_values() {
  local unit="$1"
  local key="$2"
  awk -v want_key="$key" '
    /^[[:space:]]*#/ { next }
    index($0, "=") == 0 { next }
    {
      k = substr($0, 1, index($0, "=") - 1)
      v = substr($0, index($0, "=") + 1)
      sub(/^[[:space:]]+/, "", k)
      sub(/[[:space:]]+$/, "", k)
      sub(/^[[:space:]]+/, "", v)
      sub(/[[:space:]]+$/, "", v)
      if (k == want_key) print v
    }
  ' "$unit"
}

require_unit_exact() {
  local unit="$1"
  local key="$2"
  local want="$3"
  if ! unit_setting_values "$unit" "$key" | grep -F -x -q -- "$want"; then
    echo "$unit must set $key=$want" >&2
    return 1
  fi
}

require_unit_word() {
  local unit="$1"
  local key="$2"
  local want="$3"
  if ! unit_setting_values "$unit" "$key" | tr ' ' '\n' | grep -F -x -q -- "$want"; then
    echo "$unit must include $want in $key" >&2
    return 1
  fi
}

forbid_unit_word() {
  local unit="$1"
  local key="$2"
  local forbidden="$3"
  if unit_setting_values "$unit" "$key" | tr ' ' '\n' | grep -F -x -q -- "$forbidden"; then
    echo "$unit must not include broad $key entry: $forbidden" >&2
    return 1
  fi
}

check_systemd_hardening() {
  local unit="$1"
  local failed=0

  require_unit_exact "$unit" UMask 0077 || failed=1
  require_unit_exact "$unit" NoNewPrivileges yes || failed=1
  require_unit_exact "$unit" PrivateTmp yes || failed=1
  require_unit_exact "$unit" ProtectHome yes || failed=1
  require_unit_exact "$unit" ProtectSystem strict || failed=1
  require_unit_exact "$unit" StateDirectory openngfw || failed=1
  require_unit_exact "$unit" StateDirectoryMode 0700 || failed=1
  require_unit_exact "$unit" LogsDirectory openngfw || failed=1
  require_unit_exact "$unit" LogsDirectoryMode 0700 || failed=1
  require_unit_exact "$unit" ConfigurationDirectory openngfw || failed=1
  require_unit_exact "$unit" ConfigurationDirectoryMode 0700 || failed=1
  require_unit_exact "$unit" LockPersonality yes || failed=1
  require_unit_exact "$unit" MemoryDenyWriteExecute no || failed=1
  require_unit_exact "$unit" RestrictRealtime yes || failed=1
  require_unit_exact "$unit" SystemCallArchitectures native || failed=1

  for path in /var/lib/openngfw /var/log/openngfw /etc/openngfw -/etc/frr -/etc/swanctl -/etc/strongswan/swanctl; do
    require_unit_word "$unit" ReadWritePaths "$path" || failed=1
  done
  for broad in / /etc /var /usr /run; do
    forbid_unit_word "$unit" ReadWritePaths "$broad" || failed=1
  done

  for cap in CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH; do
    require_unit_word "$unit" CapabilityBoundingSet "$cap" || failed=1
    require_unit_word "$unit" AmbientCapabilities "$cap" || failed=1
  done
  for cap in CAP_SYS_ADMIN CAP_SYS_MODULE CAP_SYS_PTRACE; do
    forbid_unit_word "$unit" CapabilityBoundingSet "$cap" || failed=1
    forbid_unit_word "$unit" AmbientCapabilities "$cap" || failed=1
  done

  for family in AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET; do
    require_unit_word "$unit" RestrictAddressFamilies "$family" || failed=1
  done

  if ! grep -q 'Hyperscan/JIT' "$unit"; then
    echo "$unit must document why MemoryDenyWriteExecute is relaxed" >&2
    failed=1
  fi
  if ! grep -Eq 'install[[:space:]]+-d[[:space:]]+-m[[:space:]]+0700[[:space:]]+/var/lib/openngfw[[:space:]]+/var/log/openngfw' "$REPO_ROOT/deploy/install.sh"; then
    echo "deploy/install.sh must create /var/lib/openngfw and /var/log/openngfw with mode 0700" >&2
    failed=1
  fi

  return "$failed"
}

check_static() {
  local failed=0
  bash -n "$REPO_ROOT/deploy/install.sh" || failed=1
  bash -n "$0" || failed=1
  if grep -Eq 'bash[[:space:]]+-c[[:space:]]+"\$\(curl|curl[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(bash|sh)' "$REPO_ROOT/deploy/install.sh"; then
    echo "deploy/install.sh must not run a default remote curl-to-shell installer" >&2
    failed=1
  fi
  if grep -Eq '^[[:space:]]*(apt-get|dnf)[[:space:]]+install[^#]*[[:space:]]curl([[:space:]]|$)' "$REPO_ROOT/deploy/install.sh"; then
    echo "deploy/install.sh must not put curl in an unconditional package-manager install transaction" >&2
    failed=1
  fi
  if ! grep -q 'install_missing_command_packages "engine prerequisites"' "$REPO_ROOT/deploy/install.sh"; then
    echo "deploy/install.sh must install only missing engine prerequisite command packages" >&2
    failed=1
  fi
  if ! grep -q 'curl:curl' "$REPO_ROOT/deploy/install.sh"; then
    echo "deploy/install.sh must keep curl as a command-satisfied prerequisite mapping" >&2
    failed=1
  fi
  if ! grep -Eq 'systemctl[[:space:]]+restart[[:space:]]+controld([[:space:]]|$)' "$REPO_ROOT/deploy/install.sh"; then
    echo "deploy/install.sh must restart controld after installing binaries and the systemd unit" >&2
    failed=1
  fi
  if ! grep -q 'binary_matches_commit' "$REPO_ROOT/deploy/install.sh"; then
    echo "deploy/install.sh must reject stale prebuilt binaries when COMMIT is provided" >&2
    failed=1
  fi
  if ! grep -q '^if prebuilt_binary_pair_matches_commit; then$' "$REPO_ROOT/deploy/install.sh"; then
    echo "deploy/install.sh must gate prebuilt reuse on the complete binary pair" >&2
    failed=1
  fi
  if ! grep -q 'make build BIN_DIR="\$BIN_SOURCE_DIR"' "$REPO_ROOT/deploy/install.sh"; then
    echo "deploy/install.sh must rebuild both binaries into the selected binary directory" >&2
    failed=1
  fi
  check_prebuilt_binary_pair_commit || failed=1
  if ! grep -q 'BIN_SOURCE_DIR="${BIN_DIR:-$REPO_ROOT/bin}"' "$REPO_ROOT/deploy/install.sh"; then
    echo "deploy/install.sh must honor BIN_DIR when release evidence redirects build output" >&2
    failed=1
  fi
  check_vector_remote_guard "$REPO_ROOT/deploy/install.sh" || failed=1
  check_admin_token_not_stdout "$REPO_ROOT/deploy/install.sh" || failed=1
  if ! grep -q '/etc/openngfw/admin.token' "$REPO_ROOT/deploy/install.sh"; then
    echo "deploy/install.sh must persist generated admin tokens to /etc/openngfw/admin.token" >&2
    failed=1
  fi
  if ! grep -Eq 'token_hash:[[:space:]]+sha256:[$][{]ADMIN_TOKEN_HASH[}]' "$REPO_ROOT/deploy/install.sh"; then
    echo "deploy/install.sh must store only sha256 token_hash entries in /etc/openngfw/users.yaml" >&2
    failed=1
  fi
  if grep -Eq 'token:[[:space:]]+[$][{]ADMIN_TOKEN[}]' "$REPO_ROOT/deploy/install.sh"; then
    echo "deploy/install.sh must not write generated plaintext tokens to /etc/openngfw/users.yaml" >&2
    failed=1
  fi
  check_systemd_hardening "$REPO_ROOT/deploy/systemd/controld.service" || failed=1
  if grep -R "token printed by the installer" "$REPO_ROOT/docs" "$REPO_ROOT/README.md" >/dev/null 2>&1; then
    echo "installer docs must not tell operators to use a terminal-printed admin token" >&2
    failed=1
  fi
  for path in \
    "$REPO_ROOT/deploy/install.sh" \
    "$REPO_ROOT/deploy/systemd/controld.service" \
    "$REPO_ROOT/docs/testing-plan.md" \
    "$REPO_ROOT/docs/testing-plan-ol9.md"; do
    if [ ! -e "$path" ]; then
      echo "missing required install artifact: $path" >&2
      failed=1
    fi
  done
  return "$failed"
}

if [ "$MODE" = "check" ]; then
  echo "check=e2e-install"
  echo "mode=check"
  echo "install_smoke_scope=static-preflight"
  echo "required_install_artifacts=deploy/install.sh,deploy/systemd/controld.service,docs/testing-plan.md,docs/testing-plan-ol9.md"
  echo "run_requires=linux-root,systemd,network-namespaces,nftables,ip-forwarding"
  if check_static; then
    echo "install smoke static preflight complete"
    echo "status=passed"
    exit 0
  fi
  echo "install smoke static preflight failed"
  echo "status=failed"
  exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
  echo "--run requires Linux" >&2
  exit 1
fi
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "--run requires root on a disposable host or VM" >&2
  exit 1
fi
require_cmds bash systemctl ip sysctl python3 awk sed grep tr jq || exit 1

SERVER_PID=""
OLD_IP_FORWARD="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"
TOKEN=""
TOKEN_FILE="/etc/openngfw/admin.token"

run_quiet() { "$@" >/dev/null 2>&1 || true; }

cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  run_quiet ip netns del "$CLIENT_NS"
  run_quiet ip netns del "$SERVER_NS"
  run_quiet ip link del "$FW_CLIENT_IF"
  run_quiet ip link del "$FW_SERVER_IF"
  sysctl -w "net.ipv4.ip_forward=$OLD_IP_FORWARD" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [ "$RUN_INSTALL" = "1" ]; then
  "$REPO_ROOT/deploy/install.sh"
else
  /usr/local/bin/ngfwctl system tune --write --apply
fi

require_sysctl_exact() {
  local key="$1"
  local want="$2"
  local got
  got="$(sysctl -n "$key")"
  if [ "$got" != "$want" ]; then
    echo "sysctl $key = $got, want $want" >&2
    exit 1
  fi
}

require_sysctl_min() {
  local key="$1"
  local want="$2"
  local got
  got="$(sysctl -n "$key")"
  if [ "$got" -lt "$want" ]; then
    echo "sysctl $key = $got, want >= $want" >&2
    exit 1
  fi
}

require_sysctl_exact net.ipv4.ip_forward 1
require_sysctl_exact net.ipv4.conf.all.rp_filter 0
require_sysctl_exact net.ipv4.conf.default.rp_filter 0
require_sysctl_min net.netfilter.nf_conntrack_max 1048576
require_sysctl_min net.core.somaxconn 4096

require_cmds curl nft || exit 1
for bin in /usr/local/bin/controld /usr/local/bin/ngfwctl; do
  if [ ! -x "$bin" ]; then
    echo "missing installed binary: $bin" >&2
    exit 1
  fi
done
if [ ! -r /etc/openngfw/users.yaml ]; then
  echo "missing /etc/openngfw/users.yaml" >&2
  exit 1
fi
if ! grep -Eq '^[[:space:]]*token_hash:[[:space:]]+sha256:[0-9A-Fa-f]{64}[[:space:]]*$' /etc/openngfw/users.yaml; then
  echo "/etc/openngfw/users.yaml must contain sha256 token_hash entries" >&2
  exit 1
fi
if grep -Eq '^[[:space:]]*token:[[:space:]]+' /etc/openngfw/users.yaml; then
  echo "/etc/openngfw/users.yaml must not contain plaintext token entries" >&2
  exit 1
fi
if [ -r "$TOKEN_FILE" ]; then
  TOKEN="$(tr -d '\r\n' < "$TOKEN_FILE")"
else
  echo "missing readable generated admin token file: $TOKEN_FILE" >&2
  exit 1
fi
if [ -z "$TOKEN" ]; then
  echo "could not read admin token from $TOKEN_FILE" >&2
  exit 1
fi
export NGFW_TOKEN="$TOKEN"

wait_for_controld() {
  for _ in $(seq 1 80); do
    if systemctl is-active --quiet controld &&
       curl -k -fsS -H "Authorization: Bearer $TOKEN" "https://$HTTPS_LISTEN/v1/system/status" >/dev/null 2>&1 &&
       /usr/local/bin/ngfwctl --server "$GRPC_LISTEN" version --remote >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  systemctl status controld --no-pager || true
  echo "controld did not become ready" >&2
  return 1
}

require_installed_commit() {
  if [ -z "${COMMIT:-}" ]; then
    return 0
  fi
  local installed_version
  local client_version
  local remote_version
  installed_version="$(/usr/local/bin/controld --version 2>&1)"
  client_version="$(/usr/local/bin/ngfwctl version 2>&1)"
  remote_version="$(/usr/local/bin/ngfwctl --server "$GRPC_LISTEN" version --remote 2>&1)"
  if ! printf '%s\n' "$installed_version" | grep -Fq -- "$COMMIT"; then
    echo "installed controld binary does not report expected commit $COMMIT" >&2
    printf '%s\n' "$installed_version" >&2
    exit 1
  fi
  if ! printf '%s\n' "$client_version" | grep -Fq -- "$COMMIT"; then
    echo "installed ngfwctl binary does not report expected commit $COMMIT" >&2
    printf '%s\n' "$client_version" >&2
    exit 1
  fi
  if ! printf '%s\n' "$remote_version" | grep '^controld ' | grep -Fq -- "$COMMIT"; then
    echo "running controld service does not report expected commit $COMMIT" >&2
    printf '%s\n' "$remote_version" >&2
    exit 1
  fi
}

setup_topology() {
  cleanup
  trap cleanup EXIT
  mkdir -p "$WORK_DIR"
  ip netns add "$CLIENT_NS"
  ip netns add "$SERVER_NS"

  ip link add "$FW_CLIENT_IF" type veth peer name "$CLIENT_PEER_IF"
  ip link set "$CLIENT_PEER_IF" netns "$CLIENT_NS"
  ip addr add "$FW_CLIENT_IP/$CIDR_PREFIX" dev "$FW_CLIENT_IF"
  ip link set "$FW_CLIENT_IF" up
  ip netns exec "$CLIENT_NS" ip addr add "$CLIENT_IP/$CIDR_PREFIX" dev "$CLIENT_PEER_IF"
  ip netns exec "$CLIENT_NS" ip link set "$CLIENT_PEER_IF" up
  ip netns exec "$CLIENT_NS" ip link set lo up
  ip netns exec "$CLIENT_NS" ip route add default via "$FW_CLIENT_IP"

  ip link add "$FW_SERVER_IF" type veth peer name "$SERVER_PEER_IF"
  ip link set "$SERVER_PEER_IF" netns "$SERVER_NS"
  ip addr add "$FW_SERVER_IP/$CIDR_PREFIX" dev "$FW_SERVER_IF"
  ip link set "$FW_SERVER_IF" up
  ip netns exec "$SERVER_NS" ip addr add "$SERVER_IP/$CIDR_PREFIX" dev "$SERVER_PEER_IF"
  ip netns exec "$SERVER_NS" ip link set "$SERVER_PEER_IF" up
  ip netns exec "$SERVER_NS" ip link set lo up
  ip netns exec "$SERVER_NS" ip route add default via "$FW_SERVER_IP"

  sysctl -w net.ipv4.ip_forward=1 >/dev/null
}

write_policy() {
  local action="$1"
  cat > "$POLICY_FILE" <<EOF
zones:
  - name: untrust
    interfaces: [$FW_CLIENT_IF]
  - name: trust
    interfaces: [$FW_SERVER_IF]
addresses:
  - name: server
    cidr: $SERVER_IP/32
services:
  - name: smoke-tcp
    protocol: PROTOCOL_TCP
    ports:
      - start: $TARGET_PORT
rules:
  - name: smoke-client-to-server
    from_zones: [untrust]
    to_zones: [trust]
    destination_addresses: [server]
    services: [smoke-tcp]
    action: $action
    log: true
EOF
}

step_up_token() {
  local action="$1"
  local comment="$2"
  local body
  local response
  body="$(jq -n --arg action "$action" --arg comment "$comment" '{action: $action, comment: $comment, ackStepUp: true}')"
  response="$(curl -k -fsS \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$body" \
    "https://$HTTPS_LISTEN/v1/system/access-administration/step-up")"
  printf '%s' "$response" | jq -r '.token // ""'
}

commit_policy() {
  local action="$1"
  local comment="install smoke $action"
  local status_json
  local revision
  local approval_json
  local approval_id
  local step_token
  write_policy "$action"
  /usr/local/bin/ngfwctl --server "$GRPC_LISTEN" policy set -f "$POLICY_FILE"
  /usr/local/bin/ngfwctl --server "$GRPC_LISTEN" policy validate
  status_json="$(/usr/local/bin/ngfwctl --server "$GRPC_LISTEN" policy status --json 2>&1)"
  revision="$(printf '%s' "$status_json" | jq -r '.candidateRevision // .candidate_revision // ""')"
  if [ -z "$revision" ] || [ "$revision" = "null" ]; then
    echo "candidate revision missing before install-smoke commit" >&2
    exit 1
  fi
  approval_json="$(/usr/local/bin/ngfwctl --server "$GRPC_LISTEN" policy approvals create \
    --candidate-revision "$revision" \
    --message "install smoke approval $action" \
    --ack-risk \
    --ack-runtime \
    --json 2>&1)"
  approval_id="$(printf '%s' "$approval_json" | jq -r '.approval.id // ""')"
  if [ -z "$approval_id" ] || [ "$approval_id" = "null" ]; then
    echo "approval id missing before install-smoke commit" >&2
    exit 1
  fi
  step_token="$(step_up_token commit "$comment")"
  if [ -z "$step_token" ] || [ "$step_token" = "null" ]; then
    echo "step-up token missing before install-smoke commit" >&2
    exit 1
  fi
  /usr/local/bin/ngfwctl --server "$GRPC_LISTEN" commit \
    --ack-risk \
    --ack-runtime \
    --candidate-revision "$revision" \
    --approval-id "$approval_id" \
    --step-up-token "$step_token" \
    -m "$comment"
}

start_server() {
  cat > "$WORK_DIR/server.py" <<'PY'
import signal
import socket
import sys

port = int(sys.argv[1])
running = True

def stop(_signum, _frame):
    global running
    running = False

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(128)
    srv.settimeout(0.5)
    while running:
        try:
            conn, _addr = srv.accept()
        except socket.timeout:
            continue
        with conn:
            conn.sendall(b"openngfw-smoke\n")
PY
  ip netns exec "$SERVER_NS" python3 "$WORK_DIR/server.py" "$TARGET_PORT" > "$SERVER_LOG" 2>&1 &
  SERVER_PID="$!"
  sleep 0.5
}

client_connect() {
  ip netns exec "$CLIENT_NS" python3 - "$SERVER_IP" "$TARGET_PORT" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
with socket.create_connection((host, port), timeout=2) as sock:
    sock.recv(64)
PY
}

wait_for_controld
require_installed_commit
setup_topology
start_server

commit_policy ACTION_ALLOW
client_connect

commit_policy ACTION_DENY
if client_connect >/dev/null 2>&1; then
  echo "deny policy did not block a new client connection" >&2
  exit 1
fi

curl -k -fsS -H "Authorization: Bearer $TOKEN" "https://$HTTPS_LISTEN/v1/system/status" >/dev/null
/usr/local/bin/ngfwctl --server "$GRPC_LISTEN" status >/dev/null
nft list table inet openngfw >/dev/null

echo "check=e2e-install"
echo "mode=run"
echo "install_smoke_scope=installed-service-policy-enforcement"
echo "required_install_artifacts=deploy/install.sh,deploy/systemd/controld.service,docs/testing-plan.md,docs/testing-plan-ol9.md"
echo "run_requires=linux-root,systemd,network-namespaces,nftables,ip-forwarding"
echo "install smoke passed: installed service committed allow and deny policies and filtered namespace traffic"
echo "status=passed"
