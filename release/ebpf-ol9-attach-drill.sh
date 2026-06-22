#!/usr/bin/env bash
set -u -o pipefail

CHECK_NAME="ebpf-ol9-attach-drill"
EVIDENCE_DIR="${EBPF_OL9_FIELD_EVIDENCE_DIR:-release/field-evidence/ebpf-ol9}"
IFACE="${EBPF_OL9_ATTACH_IFACE:-}"
STATUS_JSON_COMMAND="${EBPF_OL9_STATUS_JSON_COMMAND:-}"
NGFW_API_ORIGIN="${NGFW_API_ORIGIN:-}"
BUILD_DIR="${EBPF_OL9_BUILD_DIR:-}"
MODE=""
failures=0

usage() {
  cat <<'USAGE'
Usage: release/ebpf-ol9-attach-drill.sh --check|--run [--evidence-dir <dir>] [--iface <interface>]

Modes:
  --check  Rootless preflight. Verifies release assets and prints the OL9/root
           prerequisites for collecting the eBPF field-evidence bundle.
  --run    Privileged collector. Requires Linux root, an explicit disposable
           interface, go, bpftool, clang, tc, iproute2, bpffs, cgroup v2, kernel
           BTF, ngfwctl status, and /v1/system/status JSON evidence. It compiles
           pass-through XDP/tc probes, attaches and detaches them, then validates
           the resulting ebpf-ol9-field-evidence bundle.

Optional environment:
  EBPF_OL9_FIELD_EVIDENCE_DIR   Evidence bundle root (default: release/field-evidence/ebpf-ol9)
  EBPF_OL9_ATTACH_IFACE         Disposable OL9 interface used for XDP/tc attach drill
  EBPF_OL9_STATUS_JSON_COMMAND  Command that prints /v1/system/status eBPF JSON
  NGFW_API_ORIGIN               If no status command is set, curl this origin's /v1/system/status
  NGFW_TOKEN                    Optional bearer token for NGFW_API_ORIGIN
  NGFW_TOKEN_FILE               Optional file containing bearer token for NGFW_API_ORIGIN
USAGE
}

log() { printf '%s\n' "$*"; }
ok() { log "ok: $*"; }
fail() {
  log "error: $*"
  failures=$((failures + 1))
}

repo_root() {
  git rev-parse --show-toplevel 2>/dev/null || pwd
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

shell_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --check|--run)
        if [ -n "$MODE" ]; then
          fail "mode already set to $MODE"
        fi
        MODE="$1"
        shift
        ;;
      --evidence-dir)
        if [ "$#" -lt 2 ]; then
          fail "--evidence-dir requires a value"
          return
        fi
        EVIDENCE_DIR="$2"
        shift 2
        ;;
      --iface)
        if [ "$#" -lt 2 ]; then
          fail "--iface requires a value"
          return
        fi
        IFACE="$2"
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
  if [ -z "$MODE" ]; then
    fail "--check or --run is required"
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
  local path="$1" needle="$2" desc="$3"
  if [ ! -s "$path" ]; then
    fail "$path missing or empty"
    return
  fi
  if grep -Fq "$needle" "$path"; then
    ok "$desc"
  else
    fail "$path missing required evidence text: $needle"
  fi
}

print_prerequisites() {
  log "field_evidence_check=ebpf-ol9-field-evidence"
  log "evidence_dir=$EVIDENCE_DIR"
  log "run_requires_os=linux"
  log "run_requires_euid=0"
  log "run_requires_interface=explicit-disposable-interface"
  log "run_requires_commands=go,bpftool,clang,tc,ip,findmnt,curl,ngfwctl"
  log "run_requires_kernel=kernel-btf,bpffs,cgroup-v2,xdp-generic,tc-clsact"
  log "run_requires_status_json=EBPF_OL9_STATUS_JSON_COMMAND or NGFW_API_ORIGIN"
  log "active_dataplane=nftables/conntrack"
  log "ebpf_renderer_state=planned"
  log "supported_hooks=xdp,tc"
}

validate_static_assets() {
  require_path "release/ebpf-ol9-attach-drill.sh"
  require_path "release/ebpf-ol9-field-evidence.sh"
  require_path "internal/renderers/ebpf/plan.go"
  require_path "internal/ebpfdrill/probes.go"
  require_path "cmd/ngfwebpfdrill/main.go"
  require_path "docs/RELEASE_ACCEPTANCE.md"
  require_path "docs/testing-plan-ol9.md"
  require_file_contains "release/ebpf-ol9-field-evidence.sh" "xdp_attach_result" "field-evidence validator requires XDP attach evidence"
  require_file_contains "release/ebpf-ol9-field-evidence.sh" "tc_attach_result" "field-evidence validator requires tc attach evidence"
  require_file_contains "release/ebpf-ol9-field-evidence.sh" "active_dataplane=nftables/conntrack" "field-evidence validator preserves nftables active dataplane"
  require_file_contains "internal/ebpfdrill/probes.go" "XDP_PASS" "first-party XDP pass-through probe source is present"
  require_file_contains "internal/ebpfdrill/probes.go" "TC_ACT_OK" "first-party tc pass-through probe source is present"
  require_file_contains "internal/ebpfdrill/probes.go" "ActiveDataplane = \"nftables/conntrack\"" "first-party drill manifest preserves nftables active dataplane"
  require_file_contains "docs/RELEASE_ACCEPTANCE.md" "ebpf-ol9-field-evidence" "release acceptance documents eBPF OL9 evidence"
  require_file_contains "docs/testing-plan-ol9.md" "T-OL9-7" "OL9 test plan documents eBPF field evidence row"
}

print_tooling_state() {
  local cmd
  for cmd in go bpftool clang tc ip findmnt curl ngfwctl; do
    if have_cmd "$cmd"; then
      log "tool_${cmd}=present"
    else
      log "tool_${cmd}=missing"
    fi
  done
}

require_run_prerequisites() {
  if [ -z "$IFACE" ]; then
    fail "EBPF_OL9_ATTACH_IFACE or --iface is required for --run"
  fi
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
  local cmd
  for cmd in go bpftool clang tc ip findmnt curl ngfwctl; do
    if have_cmd "$cmd"; then
      ok "command found: $cmd"
    else
      fail "required command not found: $cmd"
    fi
  done
  if [ -z "$STATUS_JSON_COMMAND" ] && [ -z "$NGFW_API_ORIGIN" ]; then
    fail "EBPF_OL9_STATUS_JSON_COMMAND or NGFW_API_ORIGIN is required for status/system-status-ebpf.json"
  fi
}

prepare_evidence_dirs() {
  mkdir -p \
    "$EVIDENCE_DIR/drill" \
    "$EVIDENCE_DIR/host" \
    "$EVIDENCE_DIR/tooling" \
    "$EVIDENCE_DIR/status" \
    "$EVIDENCE_DIR/renderer" \
    "$EVIDENCE_DIR/attach" \
    "$EVIDENCE_DIR/cleanup"
  chmod 700 "$EVIDENCE_DIR" 2>/dev/null || true
  if [ -z "$BUILD_DIR" ]; then
    BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/openngfw-ebpf-drill.XXXXXX")"
  else
    mkdir -p "$BUILD_DIR"
  fi
  chmod 700 "$BUILD_DIR" 2>/dev/null || true
}

sha256_file() {
  if have_cmd sha256sum; then
    sha256sum "$1" | awk '{print $1}'
  elif have_cmd shasum; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required to hash drill probes"
    printf 'missing'
  fi
}

write_file() {
  local path="$1" body="$2"
  mkdir -p "$(dirname "$path")"
  printf '%s' "$body" > "$path"
  chmod 600 "$path" 2>/dev/null || true
}

run_shell_to_file() {
  local path="$1" desc="$2" command="$3"
  mkdir -p "$(dirname "$path")"
  (
    printf '%s\n' "$desc"
    printf 'command=%s\n' "$command"
    bash -lc "$command"
    rc=$?
    printf 'exit_status=%s\n' "$rc"
    exit "$rc"
  ) > "$path" 2>&1
  local rc=$?
  chmod 600 "$path" 2>/dev/null || true
  if [ "$rc" -eq 0 ]; then
    ok "$desc"
  else
    fail "$desc failed; see $path"
  fi
  return "$rc"
}

redact_stream() {
  sed -E \
    -e 's/ocid1\.[A-Za-z0-9._-]+/[REDACTED_OCI_OCID]/g' \
    -e 's/"publicIp"[[:space:]]*:[[:space:]]*"[^"]+"/"publicIp":"[REDACTED_PUBLIC_IP]"/g' \
    -e 's/"public_ip"[[:space:]]*:[[:space:]]*"[^"]+"/"public_ip":"[REDACTED_PUBLIC_IP]"/g' \
    -e 's/Authorization: Bearer [A-Za-z0-9._~+\/=-]+/Authorization: [REDACTED]/Ig' \
    -e 's/(access_token|refresh_token|token)=([^[:space:]]+)/redacted_\1_field=[REDACTED]/Ig' \
    -e 's#(https?://)[^/@[:space:]]+:[^/@[:space:]]+@#\1[REDACTED]@#g'
}

collect_host_evidence() {
  if [ -r /etc/os-release ]; then
    cp /etc/os-release "$EVIDENCE_DIR/host/os-release.txt"
    chmod 600 "$EVIDENCE_DIR/host/os-release.txt" 2>/dev/null || true
  else
    write_file "$EVIDENCE_DIR/host/os-release.txt" "os_release=missing\n"
    fail "/etc/os-release is not readable"
  fi
  uname -a > "$EVIDENCE_DIR/host/uname.txt" 2>&1 || fail "uname failed"
  chmod 600 "$EVIDENCE_DIR/host/uname.txt" 2>/dev/null || true

  local metadata
  if metadata="$(curl -fsS --noproxy '*' --max-time 2 -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/instance/ 2>/dev/null)"; then
    write_file "$EVIDENCE_DIR/host/oci-instance.txt" "oci_instance=verified\ncloud=oci\nredaction=oci-ocids-redacted,public-ips-redacted\n"
    if printf '%s\n' "$metadata" | grep -Fq '"region"'; then
      printf 'metadata_region=present\n' >> "$EVIDENCE_DIR/host/oci-instance.txt"
    fi
  else
    write_file "$EVIDENCE_DIR/host/oci-instance.txt" "oci_instance=missing\ncloud=unknown\n"
    fail "OCI instance metadata was not reachable"
  fi

  if [ -r /sys/kernel/btf/vmlinux ]; then
    write_file "$EVIDENCE_DIR/host/kernel-btf.txt" "kernel_btf=present\npath=/sys/kernel/btf/vmlinux\n"
  else
    write_file "$EVIDENCE_DIR/host/kernel-btf.txt" "kernel_btf=missing\npath=/sys/kernel/btf/vmlinux\n"
    fail "kernel BTF is not readable at /sys/kernel/btf/vmlinux"
  fi

  if findmnt -n -T /sys/fs/bpf 2>/dev/null | grep -Eq '(^|[[:space:]])bpf([[:space:]]|$)'; then
    write_file "$EVIDENCE_DIR/host/bpffs.txt" "bpffs_mount=mounted\ntype=bpf\npath=/sys/fs/bpf\n$(findmnt -n -T /sys/fs/bpf 2>/dev/null)\n"
  else
    write_file "$EVIDENCE_DIR/host/bpffs.txt" "bpffs_mount=missing\npath=/sys/fs/bpf\n"
    fail "bpffs is not mounted at /sys/fs/bpf"
  fi

  if findmnt -n -T /sys/fs/cgroup 2>/dev/null | grep -Eq '(^|[[:space:]])cgroup2([[:space:]]|$)'; then
    write_file "$EVIDENCE_DIR/host/cgroup-v2.txt" "cgroup_v2=mounted\ntype=cgroup2\npath=/sys/fs/cgroup\n$(findmnt -n -T /sys/fs/cgroup 2>/dev/null)\n"
  else
    write_file "$EVIDENCE_DIR/host/cgroup-v2.txt" "cgroup_v2=missing\npath=/sys/fs/cgroup\n"
    fail "cgroup v2 is not mounted at /sys/fs/cgroup"
  fi

  if ip -d link show dev "$IFACE" > "$EVIDENCE_DIR/host/link-inventory.txt" 2>&1; then
    {
      printf 'link_inventory=verified\n'
      printf 'xdp_candidate_iface=%s\n' "$IFACE"
      printf 'tc_candidate_iface=%s\n' "$IFACE"
    } >> "$EVIDENCE_DIR/host/link-inventory.txt"
  else
    write_file "$EVIDENCE_DIR/host/link-inventory.txt" "link_inventory=missing\nxdp_candidate_iface=$IFACE\ntc_candidate_iface=$IFACE\n"
    fail "interface $IFACE was not found"
  fi
  chmod 600 "$EVIDENCE_DIR/host/link-inventory.txt" 2>/dev/null || true
}

collect_tool_versions() {
  {
    bpftool version 2>&1 || true
    clang --version 2>&1 | sed -n '1,2p' || true
    tc -V 2>&1 || true
    ip -V 2>&1 || true
  } > "$EVIDENCE_DIR/tooling/versions.txt"
  chmod 600 "$EVIDENCE_DIR/tooling/versions.txt" 2>/dev/null || true
}

collect_status_evidence() {
  if ! ngfwctl status > "$EVIDENCE_DIR/status/ngfwctl-status.txt" 2>&1; then
    fail "ngfwctl status failed; see $EVIDENCE_DIR/status/ngfwctl-status.txt"
  else
    ok "ngfwctl status collected"
  fi
  chmod 600 "$EVIDENCE_DIR/status/ngfwctl-status.txt" 2>/dev/null || true

  if [ -n "$STATUS_JSON_COMMAND" ]; then
    if bash -lc "$STATUS_JSON_COMMAND" 2>&1 | redact_stream > "$EVIDENCE_DIR/status/system-status-ebpf.json"; then
      ok "system status eBPF JSON collected from EBPF_OL9_STATUS_JSON_COMMAND"
    else
      fail "EBPF_OL9_STATUS_JSON_COMMAND failed"
    fi
  else
    local token token_file
    token="${NGFW_TOKEN:-}"
    token_file="${NGFW_TOKEN_FILE:-}"
    if [ -z "$token" ] && [ -n "$token_file" ] && [ -r "$token_file" ]; then
      token="$(sed -n '1p' "$token_file")"
    fi
    if [ -n "$token" ]; then
      curl -sk -H "Authorization: Bearer $token" "${NGFW_API_ORIGIN%/}/v1/system/status" 2>&1 | redact_stream > "$EVIDENCE_DIR/status/system-status-ebpf.json"
    else
      curl -sk "${NGFW_API_ORIGIN%/}/v1/system/status" 2>&1 | redact_stream > "$EVIDENCE_DIR/status/system-status-ebpf.json"
    fi
    if [ -s "$EVIDENCE_DIR/status/system-status-ebpf.json" ]; then
      ok "system status JSON collected from NGFW_API_ORIGIN"
    else
      fail "system status JSON from NGFW_API_ORIGIN was empty"
    fi
  fi
  chmod 600 "$EVIDENCE_DIR/status/system-status-ebpf.json" 2>/dev/null || true
}

write_renderer_plan() {
  write_file "$EVIDENCE_DIR/renderer/ebpf-plan.txt" \
"# Phragma eBPF dataplane scaffold plan
state=planned
authoritative_renderer=nftables
supported_hooks=xdp,tc
program_families=xdp-ingress,tc-ingress,tc-egress
map_lifecycle=planned
rollback=planned
verifier_gate=required
source=internal/renderers/ebpf/plan.go
limitations=not-loadable,no-attach-by-controld,no-map-pinning,no-runtime-enforcement
"
}

write_probe_sources() {
  run_shell_to_file "$EVIDENCE_DIR/drill/write-probes.txt" "write first-party eBPF drill probe sources" "go run ./cmd/ngfwebpfdrill write-probes --build-dir $(shell_quote "$BUILD_DIR")"
}

compile_probes() {
  write_probe_sources
  local xdp_src tc_src xdp_obj tc_obj
  xdp_src="$(shell_quote "$BUILD_DIR/xdp_probe.c")"
  tc_src="$(shell_quote "$BUILD_DIR/tc_probe.c")"
  xdp_obj="$(shell_quote "$BUILD_DIR/xdp_probe.o")"
  tc_obj="$(shell_quote "$BUILD_DIR/tc_probe.o")"
  run_shell_to_file "$EVIDENCE_DIR/drill/compile-xdp.txt" "compile XDP probe" "clang -O2 -g -target bpf -c $xdp_src -o $xdp_obj"
  run_shell_to_file "$EVIDENCE_DIR/drill/compile-tc.txt" "compile tc probe" "clang -O2 -g -target bpf -c $tc_src -o $tc_obj"
}

write_drill_manifest() {
  run_shell_to_file "$EVIDENCE_DIR/drill/manifest-generation.txt" "write first-party eBPF drill manifest" "go run ./cmd/ngfwebpfdrill manifest --build-dir $(shell_quote "$BUILD_DIR") --iface $(shell_quote "$IFACE") --output $(shell_quote "$EVIDENCE_DIR/drill/manifest.txt")"
}

ensure_clean_link() {
  if ip -d link show dev "$IFACE" 2>/dev/null | grep -Eq '\bxdp\b.*(id|drv|generic|offload)'; then
    fail "interface $IFACE already has XDP state; use a disposable interface"
  fi
  if tc qdisc show dev "$IFACE" 2>/dev/null | grep -Fq "clsact"; then
    fail "interface $IFACE already has clsact qdisc; use a disposable interface"
  fi
}

cleanup_link() {
  if [ -n "$IFACE" ] && have_cmd ip; then
    ip link set dev "$IFACE" xdpgeneric off >/dev/null 2>&1 || true
  fi
  if [ -n "$IFACE" ] && have_cmd tc; then
    tc filter del dev "$IFACE" ingress >/dev/null 2>&1 || true
    tc qdisc del dev "$IFACE" clsact >/dev/null 2>&1 || true
  fi
}

run_attach_drill() {
  local iface_q xdp_obj tc_obj
  iface_q="$(shell_quote "$IFACE")"
  xdp_obj="$(shell_quote "$BUILD_DIR/xdp_probe.o")"
  tc_obj="$(shell_quote "$BUILD_DIR/tc_probe.o")"

  ensure_clean_link
  if [ "$failures" -ne 0 ]; then
    return
  fi

  trap cleanup_link EXIT
  run_shell_to_file "$EVIDENCE_DIR/attach/xdp-attach.txt" "XDP generic attach drill" "ip link set dev $iface_q xdpgeneric obj $xdp_obj sec xdp && echo xdp_attach_result=passed"
  run_shell_to_file "$EVIDENCE_DIR/attach/tc-clsact-attach.txt" "tc clsact attach drill" "tc qdisc add dev $iface_q clsact && tc filter add dev $iface_q ingress bpf da obj $tc_obj sec tc && echo tc_attach_result=passed"
  run_shell_to_file "$EVIDENCE_DIR/attach/bpftool-prog-show.txt" "bpftool program inspection" "echo programs_inspected=true && bpftool prog show"
  run_shell_to_file "$EVIDENCE_DIR/attach/xdp-detach.txt" "XDP generic detach drill" "ip link set dev $iface_q xdpgeneric off && echo xdp_detach_result=passed"
  run_shell_to_file "$EVIDENCE_DIR/attach/tc-clsact-detach.txt" "tc clsact detach drill" "tc filter del dev $iface_q ingress && tc qdisc del dev $iface_q clsact && echo tc_detach_result=passed"
  trap - EXIT
  cleanup_link

  {
    printf 'cleanup_result=passed\n'
    printf 'active_dataplane=nftables/conntrack\n'
    printf 'interface=%s\n' "$IFACE"
    ip -d link show dev "$IFACE" 2>&1 || true
    tc qdisc show dev "$IFACE" 2>&1 || true
  } > "$EVIDENCE_DIR/cleanup/post-cleanup.txt"
  chmod 600 "$EVIDENCE_DIR/cleanup/post-cleanup.txt" 2>/dev/null || true
}

validate_collected_bundle() {
  bash release/ebpf-ol9-field-evidence.sh --evidence-dir "$EVIDENCE_DIR"
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    ok "collected eBPF OL9 field-evidence bundle validated"
  else
    fail "collected eBPF OL9 field-evidence bundle failed validation"
  fi
}

main() {
  parse_args "$@"
  cd "$(repo_root)"
  log "check=$CHECK_NAME"
  log "mode=${MODE#--}"
  log "repo=$(pwd)"
  print_prerequisites

  validate_static_assets
  print_tooling_state
  if [ "$MODE" = "--check" ]; then
    if [ "$failures" -ne 0 ]; then
      log "status=failed"
      exit 1
    fi
    log "status=passed"
    exit 0
  fi

  require_run_prerequisites
  if [ "$failures" -ne 0 ]; then
    log "status=failed"
    exit 1
  fi

  prepare_evidence_dirs
  collect_host_evidence
  collect_tool_versions
  collect_status_evidence
  write_renderer_plan
  compile_probes
  if [ "$failures" -eq 0 ]; then
    write_drill_manifest
  fi
  if [ "$failures" -eq 0 ]; then
    run_attach_drill
  fi
  if [ "$failures" -eq 0 ]; then
    validate_collected_bundle
  fi
  if [ "$failures" -ne 0 ]; then
    log "status=failed"
    if [ -n "$BUILD_DIR" ] && [ -d "$BUILD_DIR" ] && [ "${EBPF_OL9_BUILD_DIR:-}" = "" ]; then
      rm -rf "$BUILD_DIR"
    fi
    exit 1
  fi
  if [ -n "$BUILD_DIR" ] && [ -d "$BUILD_DIR" ] && [ "${EBPF_OL9_BUILD_DIR:-}" = "" ]; then
    rm -rf "$BUILD_DIR"
  fi
  log "status=passed"
}

main "$@"
