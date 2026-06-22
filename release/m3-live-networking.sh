#!/usr/bin/env bash
set -u -o pipefail

CHECK_NAME="m3-live-networking"
INTEGRATION_PKG="${M3_INTEGRATION_PKG:-./test/integration}"
AUTOMATED_SCOPE="static-route-live-forwarding,bgp-frr-netns-route-programming,wireguard-handshake-peer-traffic"
AUTOMATED_TESTS="TestM3StaticRouteProgramsLiveForwarding TestM3BGPProgramsKernelRouteFromFRRPeer TestM3WireGuardPolicyCreatesInterfaceAndPassesPeerTraffic"
AUTOMATED_TEST_LIST="${AUTOMATED_TESTS// /,}"
MANUAL_FIELD_TESTS="bgp-external-peer,ipsec-strongswan-sa-traffic,wireguard-external-client"
MANUAL_IPSEC_EVIDENCE="swanctl-list-conns,swanctl-list-sas,swanctl-list-pols,ip-xfrm-state,ip-xfrm-policy,protected-subnet-ping"
TEST_REGEX="${M3_LIVE_TEST_REGEX:-^(TestM3StaticRouteProgramsLiveForwarding|TestM3BGPProgramsKernelRouteFromFRRPeer|TestM3WireGuardPolicyCreatesInterfaceAndPassesPeerTraffic)$}"
TEST_TIMEOUT="${M3_LIVE_TIMEOUT:-10m}"
INTEGRATION_BINARY="${M3_INTEGRATION_BINARY:-}"
LIVE_COMMAND="${M3_LIVE_COMMAND:-}"

failures=0

usage() {
  cat <<'USAGE'
Usage: release/m3-live-networking.sh --check|--run

Modes:
  --check  Rootless static/preflight validation. Verifies release assets and
           that the static-route, local FRR BGP, and WireGuard live
           integration tests selected by --run are discoverable. Also verifies
           the release docs include the manual IPsec evidence template required
           before claiming strongSwan SA or protected-subnet traffic evidence.
           External BGP peers, IPsec SAs/traffic, and external WireGuard
           clients remain separate m3-field-evidence release inputs.
  --run    Privileged live evidence mode. Requires Linux root networking
           prerequisites, then runs the configured M3 live command or the
           M3 integration tests.

Optional environment:
  M3_INTEGRATION_PKG      Go integration package (default: ./test/integration)
  M3_LIVE_TEST_REGEX      Go test regex for M3 live tests
                          (default: ^(TestM3StaticRouteProgramsLiveForwarding|TestM3BGPProgramsKernelRouteFromFRRPeer|TestM3WireGuardPolicyCreatesInterfaceAndPassesPeerTraffic)$)
  M3_LIVE_TIMEOUT         Go test or test-binary timeout (default: 10m)
  M3_INTEGRATION_BINARY   Compiled integration test binary to run instead of go test
  M3_LIVE_COMMAND         Explicit privileged M3 command to run instead of the
                          default integration tests. External field evidence
                          must still be recorded through m3-field-evidence.
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

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

require_cmd() {
  if have_cmd "$1"; then
    ok "command found: $1"
  else
    fail "required command not found: $1"
  fi
}

require_path() {
  if [ -e "$1" ]; then
    ok "asset found: $1"
  else
    fail "required asset missing: $1"
  fi
}

require_file_contains() {
  local path="$1"
  local needle="$2"
  local desc="$3"
  if grep -Fq "$needle" "$path"; then
    ok "$desc"
  else
    fail "$path missing required evidence text: $needle"
  fi
}

repo_root() {
  git rev-parse --show-toplevel 2>/dev/null || pwd
}

list_integration_tests() {
  if [ -n "$LIVE_COMMAND" ]; then
    return 0
  fi
  if [ -n "$INTEGRATION_BINARY" ]; then
    "$INTEGRATION_BINARY" -test.list "$TEST_REGEX"
    return $?
  fi
  go test -tags integration -run '^$' -list "$TEST_REGEX" "$INTEGRATION_PKG" | sed -n '/^Test/p'
}

validate_static_assets() {
  require_path "release/m3-live-networking.sh"
  require_path "$INTEGRATION_PKG"
  require_path "test/integration/m3_test.go"
  require_path "docs/testing-plan.md"
  require_path "docs/testing-plan-ol9.md"
  require_path "docs/examples/policy-routing-vpn.yaml"

  if grep -R -q '^//go:build integration' "$INTEGRATION_PKG" 2>/dev/null; then
    ok "integration build-tagged tests present under $INTEGRATION_PKG"
  else
    fail "no //go:build integration tests found under $INTEGRATION_PKG"
  fi

  validate_manual_field_evidence_templates
}

validate_manual_field_evidence_templates() {
  require_file_contains "docs/testing-plan.md" "T3.3 **(C)**" "manual IPsec field-test row present"
  require_file_contains "docs/testing-plan.md" "sudo swanctl --list-conns" "manual IPsec evidence requires swanctl connection listing"
  require_file_contains "docs/testing-plan.md" "sudo swanctl --list-sas" "manual IPsec evidence requires SA listing"
  require_file_contains "docs/testing-plan.md" "sudo swanctl --list-pols" "manual IPsec evidence requires policy listing"
  require_file_contains "docs/testing-plan.md" "sudo ip xfrm state" "manual IPsec evidence requires XFRM state"
  require_file_contains "docs/testing-plan.md" "sudo ip xfrm policy" "manual IPsec evidence requires XFRM policy"
  require_file_contains "docs/testing-plan.md" "ping -c 3" "manual IPsec evidence requires protected-subnet traffic"
  require_file_contains "docs/examples/policy-routing-vpn.yaml" "Manual IPsec field evidence bundle" "example policy documents manual IPsec evidence"
}

validate_run_command_path() {
  if [ -n "$LIVE_COMMAND" ]; then
    ok "M3_LIVE_COMMAND configured"
    log "live_command=$LIVE_COMMAND"
    return
  fi

  if [ -n "$INTEGRATION_BINARY" ]; then
    if [ -x "$INTEGRATION_BINARY" ]; then
      ok "compiled integration binary is executable: $INTEGRATION_BINARY"
    else
      fail "M3_INTEGRATION_BINARY is not executable: $INTEGRATION_BINARY"
      return
    fi
  else
    require_cmd go
  fi

  local listed
  if listed="$(list_integration_tests 2>&1)"; then
    if [ -n "$listed" ]; then
      ok "M3 integration tests matched regex $TEST_REGEX"
      printf '%s\n' "$listed" | sed 's/^/test: /'
      require_release_gate_tests "$listed"
    else
      fail "no M3 live integration tests matched regex $TEST_REGEX"
    fi
  else
    fail "could not list M3 live integration tests with regex $TEST_REGEX: $listed"
  fi
}

require_release_gate_tests() {
  local listed="$1"
  local test
  for test in $AUTOMATED_TESTS; do
    if printf '%s\n' "$listed" | grep -Fxq "$test"; then
      ok "release-gate test selected: $test"
    else
      fail "release gate must include $test or use M3_LIVE_COMMAND for explicit privileged M3 live evidence"
    fi
  done
}

print_live_prerequisites() {
  log "automated_scope=$AUTOMATED_SCOPE"
  log "automated_tests=$AUTOMATED_TEST_LIST"
  log "manual_field_tests=$MANUAL_FIELD_TESTS"
  log "manual_ipsec_evidence=$MANUAL_IPSEC_EVIDENCE"
  log "manual_ipsec_template=docs/testing-plan.md:T3.3,docs/examples/policy-routing-vpn.yaml"
  log "run_requires_os=linux"
  log "run_requires_euid=0"
  log "run_requires_commands=ip,nft,nc,wg,vtysh,zebra,bgpd"
  log "run_requires_kernel=network-namespaces,nftables,ip-forwarding,wireguard,ipv4-kernel-route-table"
  log "run_requires_services=none"
}

check_host_for_run() {
  if [ "$(uname -s)" = "Linux" ]; then
    ok "host OS is Linux"
  else
    fail "--run requires Linux; current OS is $(uname -s)"
  fi

  if [ "$(id -u)" = "0" ]; then
    ok "running as root"
  else
    fail "--run requires root; current euid is $(id -u)"
  fi

  for cmd in ip nft nc wg vtysh zebra bgpd; do
    require_cmd "$cmd"
  done

  check_wireguard_kernel
}

check_wireguard_kernel() {
  local probe="ngfwp$$"
  if [ "${#probe}" -gt 15 ]; then
    probe="ngfwgprobe"
  fi
  if ip link add "$probe" type wireguard >/dev/null 2>&1; then
    ip link del "$probe" >/dev/null 2>&1
    ok "kernel supports WireGuard links"
  else
    fail "kernel does not support WireGuard links (ip link add $probe type wireguard failed)"
  fi
}

run_live_evidence() {
  if [ -n "$LIVE_COMMAND" ]; then
    log "running live M3 command: $LIVE_COMMAND"
    bash -lc "$LIVE_COMMAND"
    return $?
  fi

  local listed
  if ! listed="$(list_integration_tests 2>&1)"; then
    log "$listed"
    log "status=failed"
    log "reason=could not list M3 live integration tests"
    return 1
  fi
  if [ -z "$listed" ]; then
    log "status=failed"
    log "reason=no automated M3 release-gate tests matched regex $TEST_REGEX"
    log "set M3_LIVE_TEST_REGEX to include $AUTOMATED_TEST_LIST or M3_LIVE_COMMAND to a validated lab command"
    return 1
  fi

  log "selected_tests_begin"
  printf '%s\n' "$listed"
  log "selected_tests_end"

  if [ -n "$INTEGRATION_BINARY" ]; then
    log "running compiled integration binary: $INTEGRATION_BINARY -test.v -test.run $TEST_REGEX -test.timeout $TEST_TIMEOUT"
    run_test_command_rejecting_skips "$INTEGRATION_BINARY" -test.v -test.run "$TEST_REGEX" -test.timeout "$TEST_TIMEOUT"
    return $?
  fi

  log "running go integration tests: go test -tags integration -count=1 -v -run $TEST_REGEX -timeout $TEST_TIMEOUT $INTEGRATION_PKG"
  run_test_command_rejecting_skips go test -tags integration -count=1 -v -run "$TEST_REGEX" -timeout "$TEST_TIMEOUT" "$INTEGRATION_PKG"
}

run_test_command_rejecting_skips() {
  local output
  output="$(mktemp "${TMPDIR:-/tmp}/openngfw-m3-live.XXXXXX")" || return 1
  "$@" 2>&1 | tee "$output"
  local rc=${PIPESTATUS[0]}
  if grep -Eq '(^|[[:space:]])--- SKIP: ' "$output"; then
    log "reason=selected M3 live tests reported skipped tests; release evidence must come from executed live checks"
    rm -f "$output"
    return 1
  fi
  rm -f "$output"
  return "$rc"
}

main() {
  if [ "$#" -ne 1 ]; then
    usage
    exit 2
  fi

  local mode="$1"
  case "$mode" in
    --check|--run)
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac

  cd "$(repo_root)"
  log "check=$CHECK_NAME"
  log "mode=${mode#--}"
  log "repo=$(pwd)"
  log "integration_pkg=$INTEGRATION_PKG"
  log "test_regex=$TEST_REGEX"
  print_live_prerequisites

  if [ "$mode" = "--check" ]; then
    validate_static_assets
    validate_run_command_path
    if [ "$failures" -ne 0 ]; then
      log "status=failed"
      exit 1
    fi
    log "status=passed"
    exit 0
  fi

  validate_static_assets
  validate_run_command_path
  check_host_for_run
  if [ "$failures" -ne 0 ]; then
    log "status=failed"
    exit 1
  fi

  run_live_evidence
  rc=$?
  if [ "$rc" -eq 0 ]; then
    log "status=passed"
    exit 0
  fi
  log "status=failed"
  exit "$rc"
}

main "$@"
