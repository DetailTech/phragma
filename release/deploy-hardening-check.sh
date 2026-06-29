#!/usr/bin/env bash
set -u -o pipefail

CHECK_NAME="deploy-hardening"
SERVICE_UNIT="${OPENNGFW_SERVICE_UNIT:-deploy/systemd/controld.service}"
INSTALLER="${OPENNGFW_INSTALLER:-deploy/install.sh}"

failures=0

usage() {
  cat <<'USAGE'
Usage: release/deploy-hardening-check.sh [--check] [--service-unit <path>] [--installer <path>]

Validates that shipped deployment artifacts keep the enterprise management
plane in a hardened posture. This is a static release preflight: it does not
start controld or install packages.

Optional environment:
  OPENNGFW_SERVICE_UNIT  systemd unit to inspect
  OPENNGFW_INSTALLER     installer script to inspect
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
      --service-unit)
        if [ "$#" -lt 2 ]; then
          fail "--service-unit requires a value"
          return
        fi
        SERVICE_UNIT="$2"
        shift 2
        ;;
      --installer)
        if [ "$#" -lt 2 ]; then
          fail "--installer requires a value"
          return
        fi
        INSTALLER="$2"
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

repo_root() {
  git rev-parse --show-toplevel 2>/dev/null || pwd
}

require_file() {
  local path="$1"
  local desc="$2"
  if [ -L "$path" ]; then
    fail "$desc must not be a symlink: $path"
    return 1
  fi
  if [ -f "$path" ] && [ -s "$path" ]; then
    ok "$desc present"
    return 0
  fi
  fail "$desc missing or empty: $path"
  return 1
}

active_file_matches() {
  local path="$1"
  local regex="$2"
  [ -f "$path" ] || return 1
  awk '/^[[:space:]]*(#|$)/ { next } { print }' "$path" | grep -Eq -- "$regex"
}

require_active_regex() {
  local path="$1"
  local regex="$2"
  local desc="$3"
  if active_file_matches "$path" "$regex"; then
    ok "$desc"
  else
    fail "$path missing required active setting: $desc"
  fi
}

reject_active_regex() {
  local path="$1"
  local regex="$2"
  local desc="$3"
  if active_file_matches "$path" "$regex"; then
    fail "$path contains prohibited active setting: $desc"
  else
    ok "$desc absent"
  fi
}

validate_service_unit() {
  require_file "$SERVICE_UNIT" "controld systemd unit" || return

  require_active_regex "$SERVICE_UNIT" '^ExecStart=/usr/local/bin/controld[[:space:]]*\\?$' "controld ExecStart"
  require_active_regex "$SERVICE_UNIT" '--listen[[:space:]]+127\.0\.0\.1:9443' "gRPC management listener is loopback by default"
  require_active_regex "$SERVICE_UNIT" '--http-listen[[:space:]]+127\.0\.0\.1:8080' "REST/WebUI listener is loopback by default"
  require_active_regex "$SERVICE_UNIT" '--users-file[[:space:]]+/etc/openngfw/users\.yaml' "users file authentication is configured"
  reject_active_regex "$SERVICE_UNIT" '--allow-unauthenticated-local' "unauthenticated local dev bypass"
  reject_active_regex "$SERVICE_UNIT" '--tls=false' "cleartext TLS-disable flag"
  reject_active_regex "$SERVICE_UNIT" '--dry-run' "dry-run mode"

  require_active_regex "$SERVICE_UNIT" '^UMask=0077$' "root-only process umask"
  require_active_regex "$SERVICE_UNIT" '^NoNewPrivileges=yes$' "NoNewPrivileges systemd sandbox"
  require_active_regex "$SERVICE_UNIT" '^PrivateTmp=yes$' "PrivateTmp systemd sandbox"
  require_active_regex "$SERVICE_UNIT" '^ProtectHome=yes$' "ProtectHome systemd sandbox"
  require_active_regex "$SERVICE_UNIT" '^ProtectSystem=strict$' "ProtectSystem=strict systemd sandbox"
  require_active_regex "$SERVICE_UNIT" '^ReadWritePaths=/var/lib/openngfw /var/log/openngfw /etc/openngfw$' "writable paths limited to OpenNGFW state, logs, and config"
  require_active_regex "$SERVICE_UNIT" '^StateDirectoryMode=0700$' "state directory mode is 0700"
  require_active_regex "$SERVICE_UNIT" '^LogsDirectoryMode=0700$' "logs directory mode is 0700"
  require_active_regex "$SERVICE_UNIT" '^ConfigurationDirectoryMode=0700$' "configuration directory mode is 0700"
  require_active_regex "$SERVICE_UNIT" '^CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH$' "capability bounding set is explicit"
  require_active_regex "$SERVICE_UNIT" '^AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH$' "ambient capabilities match bounded firewall operations"
  reject_active_regex "$SERVICE_UNIT" '(^|[[:space:]])CAP_SYS_ADMIN([[:space:]]|$)' "CAP_SYS_ADMIN"
  reject_active_regex "$SERVICE_UNIT" '(^|[[:space:]])CAP_SYS_MODULE([[:space:]]|$)' "CAP_SYS_MODULE"
  reject_active_regex "$SERVICE_UNIT" '(^|[[:space:]])CAP_SYS_PTRACE([[:space:]]|$)' "CAP_SYS_PTRACE"
  require_active_regex "$SERVICE_UNIT" '^RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET$' "address families restricted to management and packet/network control"
  require_active_regex "$SERVICE_UNIT" '^LockPersonality=yes$' "personality changes locked"
  require_active_regex "$SERVICE_UNIT" '^RestrictRealtime=yes$' "realtime scheduling restricted"
  require_active_regex "$SERVICE_UNIT" '^SystemCallArchitectures=native$' "native syscall architecture restriction"
}

validate_installer() {
  require_file "$INSTALLER" "OpenNGFW installer" || return

  require_active_regex "$INSTALLER" '^if \[\[ "\$\{1:-\}" == "--check-prebuilt-binaries" \]\]; then$' "bounded rootless prebuilt-pair probe is explicit"
  require_active_regex "$INSTALLER" 'binary_matches_commit "\$BIN_SOURCE_DIR/controld" --version' "prebuilt controld uses its supported version flag"
  require_active_regex "$INSTALLER" 'binary_matches_commit "\$BIN_SOURCE_DIR/ngfwctl" version' "prebuilt ngfwctl uses its supported version subcommand"
  require_active_regex "$INSTALLER" '^if[[:space:]]+\[\[ \$EUID -ne 0 \]\]' "installer mutations require root"
  require_active_regex "$INSTALLER" 'install -d -m 0700 /var/lib/openngfw /var/log/openngfw' "state and log directories are root-only"
  require_active_regex "$INSTALLER" 'install -d -m 0700 /etc/openngfw /etc/openngfw/secrets /etc/openngfw/keys' "config, secrets, and keys directories are root-only"
  require_active_regex "$INSTALLER" 'ADMIN_TOKEN_FILE="/etc/openngfw/admin\.token"' "bootstrap token path is under /etc/openngfw"
  require_active_regex "$INSTALLER" 'head -c 32 /dev/urandom' "bootstrap token uses kernel randomness"
  require_active_regex "$INSTALLER" 'sha256sum' "bootstrap users file stores a token hash"
  require_active_regex "$INSTALLER" 'token_hash: sha256:' "users file uses sha256 token hash format"
  require_active_regex "$INSTALLER" 'install -m 0600 /dev/null "\$ADMIN_TOKEN_FILE"' "bootstrap token file is created mode 0600"
  require_active_regex "$INSTALLER" 'chmod 600 /etc/openngfw/users\.yaml' "users file is chmod 600"
  require_active_regex "$INSTALLER" 'chmod 600 "\$ADMIN_TOKEN_FILE"' "bootstrap token file is chmod 600"
  require_active_regex "$INSTALLER" 'OPENNGFW_UNSAFE_REMOTE_VECTOR_INSTALL' "remote Vector installer requires explicit unsafe opt-in"
  require_active_regex "$INSTALLER" "curl -fsSL --proto '=https' --tlsv1\\.2 https://sh\\.vector\\.dev" "legacy remote Vector fetch is HTTPS/TLS constrained"
}

main() {
  parse_args "$@"
  cd "$(repo_root)"

  log "check=$CHECK_NAME"
  log "mode=check"
  log "service_unit=$SERVICE_UNIT"
  log "installer=$INSTALLER"
  log "required_service_posture=loopback-listeners,authenticated-by-default,no-dev-bypass,systemd-sandbox,capability-bounds"
  log "required_installer_posture=root-only,0700-state-log-config,hashed-admin-token,0600-secret-files,unsafe-remote-install-opt-in"

  validate_service_unit
  validate_installer

  if [ "$failures" -ne 0 ]; then
    log "status=failed"
    exit 1
  fi
  log "status=passed"
}

main "$@"
