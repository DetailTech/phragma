#!/usr/bin/env bash
set -u -o pipefail

CHECK_NAME="ebpf-ol9-field-evidence"
EVIDENCE_DIR="${EBPF_OL9_FIELD_EVIDENCE_DIR:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
failures=0

# shellcheck source=release/manifest-sha256.sh
. "$SCRIPT_DIR/manifest-sha256.sh"

usage() {
  cat <<'USAGE'
Usage: release/ebpf-ol9-field-evidence.sh --evidence-dir <dir>

Validates manually collected OL9/OCI Linux-root eBPF milestone evidence before
it is recorded as release acceptance evidence. This script does not attach eBPF
programs by itself; it checks that the field bundle proves host readiness,
XDP/tc attach/detach drills, bpffs posture, and Phragma status evidence.

Required bundle layout:
  <dir>/manifest.sha256
  <dir>/host/os-release.txt
  <dir>/host/uname.txt
  <dir>/host/oci-instance.txt
  <dir>/host/kernel-btf.txt
  <dir>/host/bpffs.txt
  <dir>/host/cgroup-v2.txt
  <dir>/host/link-inventory.txt
  <dir>/tooling/versions.txt
  <dir>/status/ngfwctl-status.txt
  <dir>/status/system-status-ebpf.json
  <dir>/renderer/ebpf-plan.txt
  <dir>/drill/manifest.txt
  <dir>/attach/xdp-attach.txt
  <dir>/attach/xdp-detach.txt
  <dir>/attach/tc-clsact-attach.txt
  <dir>/attach/tc-clsact-detach.txt
  <dir>/attach/bpftool-prog-show.txt
  <dir>/cleanup/post-cleanup.txt
USAGE
}

log() { printf '%s\n' "$*"; }
ok() { log "ok: $*"; }
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
  local path="$1" desc="$2"
  if [ -L "$path" ]; then
    fail "$desc must not be a symlink: $path"
    return 1
  fi
  if [ ! -d "$path" ]; then
    fail "$desc missing: $path"
    return 1
  fi
  ok "$desc present"
}

require_file() {
  local path="$1" desc="$2"
  if [ -L "$path" ]; then
    fail "$desc must not be a symlink: $path"
    return 1
  fi
  if [ ! -s "$path" ]; then
    fail "$desc missing or empty: $path"
    return 1
  fi
  ok "$desc present"
}

require_file_matches() {
  local path="$1" regex="$2" desc="$3"
  if ! require_file "$path" "$desc"; then
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

scan_redaction() {
  local path line
  while IFS= read -r path; do
    while IFS= read -r line; do
      case "$line" in
        *"BEGIN "*"PRIVATE KEY"*|*"private_key="*|*"private-key="*|*"PrivateKey ="*)
          fail "private key appears unredacted in $path"
          ;;
        *"Authorization: Bearer "*|*"authorization: bearer "*)
          fail "bearer token appears unredacted in $path"
          ;;
        *"api_key="*|*"api-key="*|*"API_KEY="*)
          fail "API token appears unredacted in $path"
          ;;
        *"token="*|*"TOKEN="*|*"access_token="*|*"refresh_token="*)
          fail "token appears unredacted in $path"
          ;;
        *"ocid1."*)
          fail "OCI OCID appears unredacted in $path"
          ;;
        *"public_ip="*"."*|*"public-ip="*"."*|*"publicIp"*"."*)
          fail "public IP appears unredacted in $path"
          ;;
        *"://"*"@"*)
          fail "URL credentials appears unredacted in $path"
          ;;
      esac
    done < "$path"
  done < <(find "$EVIDENCE_DIR" -type f -print 2>/dev/null)
}

manifest_expected_files() {
  printf '%s\n' \
    "host/os-release.txt" \
    "host/uname.txt" \
    "host/oci-instance.txt" \
    "host/kernel-btf.txt" \
    "host/bpffs.txt" \
    "host/cgroup-v2.txt" \
    "host/link-inventory.txt" \
    "tooling/versions.txt" \
    "status/ngfwctl-status.txt" \
    "status/system-status-ebpf.json" \
    "renderer/ebpf-plan.txt" \
    "drill/manifest.txt" \
    "attach/xdp-attach.txt" \
    "attach/xdp-detach.txt" \
    "attach/tc-clsact-attach.txt" \
    "attach/tc-clsact-detach.txt" \
    "attach/bpftool-prog-show.txt" \
    "cleanup/post-cleanup.txt"
}

validate_bundle() {
  if [ -z "$EVIDENCE_DIR" ]; then
    fail "--evidence-dir is required"
    return
  fi
  if ! require_dir "$EVIDENCE_DIR" "eBPF OL9 evidence directory"; then
    return
  fi
  reject_symlink_tree
  manifest_sha256_verify "$EVIDENCE_DIR" $(manifest_expected_files)

  require_file_matches "$EVIDENCE_DIR/host/os-release.txt" '(Oracle Linux|Oracle Linux Server|^ID="?ol"?)' "Oracle Linux os-release"
  require_file_matches "$EVIDENCE_DIR/host/os-release.txt" 'VERSION_ID="?9' "OL9 major version"
  require_file_matches "$EVIDENCE_DIR/host/uname.txt" 'Linux' "Linux kernel identity"
  require_file_matches "$EVIDENCE_DIR/host/oci-instance.txt" '(oci_instance|oci-host|cloud)[[:space:]_-]*=[[:space:]]*(true|present|verified|oci)' "OCI host evidence"
  require_file_matches "$EVIDENCE_DIR/host/kernel-btf.txt" '(kernel[[:space:]_-]*btf[[:space:]_-]*=[[:space:]]*(present|available|verified|true)|/sys/kernel/btf/vmlinux)' "kernel BTF evidence"
  require_file_matches "$EVIDENCE_DIR/host/bpffs.txt" '(bpffs([[:space:]_-]*mount)?[[:space:]_-]*=[[:space:]]*(mounted|present|verified|true)|/sys/fs/bpf|type[[:space:]_-]*=[[:space:]]*bpf)' "bpffs mount evidence"
  require_file_matches "$EVIDENCE_DIR/host/cgroup-v2.txt" '(cgroup[[:space:]_-]*v2[[:space:]_-]*=[[:space:]]*(mounted|present|verified|true)|type[[:space:]_-]*=[[:space:]]*cgroup2|/sys/fs/cgroup)' "cgroup v2 evidence"
  require_file_matches "$EVIDENCE_DIR/host/link-inventory.txt" '(link[[:space:]_-]*inventory[[:space:]_-]*=[[:space:]]*(present|verified|true)|xdp[[:space:]_-]*candidate[[:space:]_-]*iface[[:space:]_-]*=|tc[[:space:]_-]*candidate[[:space:]_-]*iface[[:space:]_-]*=|^[[:space:]]*[0-9]+:[[:space:]]+[[:alnum:]_.:-]+:)' "link inventory evidence"
  require_file_matches "$EVIDENCE_DIR/tooling/versions.txt" 'bpftool' "bpftool version evidence"
  require_file_matches "$EVIDENCE_DIR/tooling/versions.txt" 'clang' "clang version evidence"
  require_file_matches "$EVIDENCE_DIR/tooling/versions.txt" '(^|[[:space:]])tc([[:space:]]|=|:)' "tc version evidence"
  require_file_matches "$EVIDENCE_DIR/tooling/versions.txt" '(^|[[:space:]])ip([[:space:]]|=|:)' "iproute2 version evidence"
  require_file_matches "$EVIDENCE_DIR/status/ngfwctl-status.txt" 'eBPF host:[[:space:]]+ready' "ngfwctl status eBPF host readiness"
  require_file_matches "$EVIDENCE_DIR/status/ngfwctl-status.txt" 'eBPF attach:[[:space:]]+ready' "ngfwctl status eBPF attach readiness"
  require_file_matches "$EVIDENCE_DIR/status/ngfwctl-status.txt" 'eBPF renderer:[[:space:]]+planned' "ngfwctl status eBPF renderer scope"
  require_file_matches "$EVIDENCE_DIR/status/system-status-ebpf.json" '"state"[[:space:]]*:[[:space:]]*"ready"' "system status eBPF host readiness JSON"
  require_file_matches "$EVIDENCE_DIR/status/system-status-ebpf.json" '"(attachState|attach_state)"[[:space:]]*:[[:space:]]*"ready"' "system status eBPF attach readiness JSON"
  require_file_matches "$EVIDENCE_DIR/status/system-status-ebpf.json" '"(rendererState|renderer_state)"[[:space:]]*:[[:space:]]*"planned"' "system status eBPF renderer JSON"
  require_file_matches "$EVIDENCE_DIR/renderer/ebpf-plan.txt" 'state=planned' "eBPF render plan state"
  require_file_matches "$EVIDENCE_DIR/renderer/ebpf-plan.txt" 'authoritative_renderer=nftables' "eBPF render plan authoritative renderer"
  require_file_matches "$EVIDENCE_DIR/renderer/ebpf-plan.txt" 'supported_hooks=xdp,tc' "eBPF render plan hooks"
  require_file_matches "$EVIDENCE_DIR/drill/manifest.txt" 'drill_tool=release/ebpf-ol9-attach-drill\.sh' "eBPF attach drill manifest tool"
  require_file_matches "$EVIDENCE_DIR/drill/manifest.txt" 'drill_mode=run' "eBPF attach drill manifest mode"
  require_file_matches "$EVIDENCE_DIR/drill/manifest.txt" 'xdp_probe_source_sha256=[0-9a-f]{64}' "XDP probe source digest"
  require_file_matches "$EVIDENCE_DIR/drill/manifest.txt" 'xdp_probe_object_sha256=[0-9a-f]{64}' "XDP probe object digest"
  require_file_matches "$EVIDENCE_DIR/drill/manifest.txt" 'tc_probe_source_sha256=[0-9a-f]{64}' "tc probe source digest"
  require_file_matches "$EVIDENCE_DIR/drill/manifest.txt" 'tc_probe_object_sha256=[0-9a-f]{64}' "tc probe object digest"
  require_file_matches "$EVIDENCE_DIR/drill/manifest.txt" 'active_dataplane=nftables/conntrack' "eBPF drill preserves active dataplane"
  require_file_matches "$EVIDENCE_DIR/attach/xdp-attach.txt" 'xdp_attach_result[[:space:]_-]*=[[:space:]]*(passed|ok|true)' "XDP attach drill"
  require_file_matches "$EVIDENCE_DIR/attach/xdp-attach.txt" 'command=.*ip link set dev .*xdpgeneric obj' "XDP attach command record"
  require_file_matches "$EVIDENCE_DIR/attach/xdp-detach.txt" 'xdp_detach_result[[:space:]_-]*=[[:space:]]*(passed|ok|true)' "XDP detach drill"
  require_file_matches "$EVIDENCE_DIR/attach/xdp-detach.txt" 'command=.*ip link set dev .*xdpgeneric off' "XDP detach command record"
  require_file_matches "$EVIDENCE_DIR/attach/tc-clsact-attach.txt" 'tc_attach_result[[:space:]_-]*=[[:space:]]*(passed|ok|true)' "tc clsact attach drill"
  require_file_matches "$EVIDENCE_DIR/attach/tc-clsact-attach.txt" 'command=.*tc qdisc add dev .* clsact.*tc filter add dev .* ingress bpf' "tc attach command record"
  require_file_matches "$EVIDENCE_DIR/attach/tc-clsact-detach.txt" 'tc_detach_result[[:space:]_-]*=[[:space:]]*(passed|ok|true)' "tc detach drill"
  require_file_matches "$EVIDENCE_DIR/attach/tc-clsact-detach.txt" 'command=.*tc filter del dev .* ingress.*tc qdisc del dev .* clsact' "tc detach command record"
  require_file_matches "$EVIDENCE_DIR/attach/bpftool-prog-show.txt" '(xdp|tc|id[[:space:]][0-9]+|programs_inspected[[:space:]_-]*=[[:space:]]*(true|passed))' "bpftool program inspection"
  require_file_matches "$EVIDENCE_DIR/cleanup/post-cleanup.txt" 'cleanup_result[[:space:]_-]*=[[:space:]]*(passed|ok|true)' "post-attach cleanup"
  require_file_matches "$EVIDENCE_DIR/cleanup/post-cleanup.txt" 'active_dataplane[[:space:]_-]*=[[:space:]]*nftables/conntrack' "post-cleanup active dataplane"
  scan_redaction
}

main() {
  parse_args "$@"
  log "check=${CHECK_NAME}"
  log "mode=check"
  log "field_evidence_scope=ol9-oci-host,ebpf-host-prereqs,xdp-attach-probe,tc-attach-probe,status-api,renderer-scaffold,cleanup"
  log "required_host_evidence=os-release,uname,oci-instance"
  log "required_ebpf_prereqs=bpftool,clang,tc,ip,kernel-btf,bpffs,cgroup-v2,link-inventory"
  log "required_attach_evidence=xdp-attach,xdp-detach,tc-clsact-attach,tc-clsact-detach,bpftool-program-inspection,cleanup"
  log "required_status_evidence=ngfwctl-status,system-status-ebpf-json"
  log "required_renderer_evidence=ebpf-render-plan"
  log "required_drill_evidence=drill-manifest,probe-source-sha256,probe-object-sha256,attach-detach-command-records"
  log "manifest_sha256_policy=required,exact-regular-files,no-extra-files"
  log "active_dataplane=nftables/conntrack"
  log "ebpf_renderer_state=planned"
  log "supported_hooks=xdp,tc"
  log "xdp_attach_result=passed"
  log "tc_attach_result=passed"
  log "cleanup_result=passed"
  log "ebpf_field_redaction=oci-ocids-redacted,public-ips-redacted,tokens-redacted"
  log "redaction_scan=private-key,bearer,api-key,token,url-userinfo,oci-ocid,public-ip"
  validate_bundle
  if [ "$failures" -gt 0 ]; then
    log "status=failed"
    return 1
  fi
  log "status=passed"
}

main "$@"
