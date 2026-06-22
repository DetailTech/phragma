#!/usr/bin/env bash
set -euo pipefail

MODE="check"
BENCH_PROFILE="${BENCH_PROFILE:-local-netns-forwarding}"
OUTPUT_ROOT="${OUTPUT_ROOT:-perf/results}"
DURATION="${DURATION:-30}"
PARALLEL="${PARALLEL:-8}"
TARGET_PORT="${TARGET_PORT:-5201}"
PING_COUNT="${PING_COUNT:-20}"
CHURN_COUNT="${CHURN_COUNT:-200}"
GRPC_LISTEN="${GRPC_LISTEN:-127.0.0.1:19447}"
HTTP_LISTEN="${HTTP_LISTEN:-127.0.0.1:18084}"
ALLOW_EXISTING_OPENNGFW="${ALLOW_EXISTING_OPENNGFW:-0}"

CLIENT_NS="${CLIENT_NS:-ngfw-bench-client}"
SERVER_NS="${SERVER_NS:-ngfw-bench-server}"
FW_CLIENT_IF="${FW_CLIENT_IF:-obench0}"
FW_SERVER_IF="${FW_SERVER_IF:-ibench0}"
CLIENT_PEER_IF="${CLIENT_PEER_IF:-cbench0}"
SERVER_PEER_IF="${SERVER_PEER_IF:-sbench0}"
FW_CLIENT_IP="${FW_CLIENT_IP:-10.250.1.1}"
CLIENT_IP="${CLIENT_IP:-10.250.1.2}"
FW_SERVER_IP="${FW_SERVER_IP:-10.250.2.1}"
SERVER_IP="${SERVER_IP:-10.250.2.2}"
CIDR_PREFIX="${CIDR_PREFIX:-24}"

export BENCH_PROFILE OUTPUT_ROOT DURATION PARALLEL TARGET_PORT PING_COUNT CHURN_COUNT
export SERVER_IP CLIENT_NS SERVER_NS FW_CLIENT_IF FW_SERVER_IF FW_CLIENT_IP FW_SERVER_IP CLIENT_IP

usage() {
  cat <<'EOF'
OpenNGFW local namespace benchmark.

Usage:
  perf/netns.sh --check
  sudo perf/netns.sh --run

This harness runs on one Linux host. It creates two network namespaces with
veth links, starts the product controld binary against real nftables, commits
a baseline allow policy through ngfwctl, then sends iperf3 traffic through the
host namespace acting as the firewall.

Required for --run:
  root, Linux network namespaces, nftables, iproute2, iperf3, ping, nc, curl,
  python3, and built bin/controld + bin/ngfwctl.

Useful environment variables:
  DURATION=30
  PARALLEL=8
  TARGET_PORT=5201
  PING_COUNT=20
  CHURN_COUNT=200
  OUTPUT_ROOT=perf/results
  GRPC_LISTEN=127.0.0.1:19447
  HTTP_LISTEN=127.0.0.1:18084
  ALLOW_EXISTING_OPENNGFW=1   # only for disposable hosts; permits replacing
                              # an existing inet openngfw table during the run
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

check_inputs() {
  local failed=0
  require_cmds bash date ip nft iperf3 ping nc curl python3 sed awk sysctl || failed=1
  if [ ! -x ./bin/controld ]; then
    echo "missing executable: ./bin/controld (run make build)" >&2
    failed=1
  fi
  if [ ! -x ./bin/ngfwctl ]; then
    echo "missing executable: ./bin/ngfwctl (run make build)" >&2
    failed=1
  fi
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "root is required for network namespaces and nftables" >&2
    failed=1
  fi
  if ! nft list tables >/dev/null 2>&1; then
    echo "kernel nftables access failed" >&2
    failed=1
  fi
  if [ "$ALLOW_EXISTING_OPENNGFW" != "1" ]; then
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet controld 2>/dev/null; then
      echo "controld.service is active; refusing to replace the global inet openngfw table" >&2
      echo "use a disposable host or set ALLOW_EXISTING_OPENNGFW=1 intentionally" >&2
      failed=1
    fi
    if nft list table inet openngfw >/dev/null 2>&1; then
      echo "existing nftables table inet openngfw found; refusing to overwrite it" >&2
      echo "use a disposable host or set ALLOW_EXISTING_OPENNGFW=1 intentionally" >&2
      failed=1
    fi
  fi
  return "$failed"
}

if [ "$MODE" = "check" ]; then
  check_inputs
  echo "local namespace benchmark preflight complete"
  exit 0
fi

check_inputs

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
safe_profile="$(printf '%s' "$BENCH_PROFILE" | sed 's/[^A-Za-z0-9_.-]/-/g')"
out_dir="$OUTPUT_ROOT/${timestamp}-${safe_profile}"
state_dir="$out_dir/state"
log_dir="$out_dir/logs"
mkdir -p "$state_dir" "$log_dir"

controld_pid=""
iperf_pid=""
churn_server_pid=""
old_ip_forward="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)"

run_quiet() { "$@" >/dev/null 2>&1 || true; }

cleanup() {
  if [ -n "$iperf_pid" ]; then
    kill "$iperf_pid" >/dev/null 2>&1 || true
    wait "$iperf_pid" >/dev/null 2>&1 || true
  fi
  if [ -n "$churn_server_pid" ]; then
    kill "$churn_server_pid" >/dev/null 2>&1 || true
    wait "$churn_server_pid" >/dev/null 2>&1 || true
  fi
  if [ -n "$controld_pid" ]; then
    kill "$controld_pid" >/dev/null 2>&1 || true
    wait "$controld_pid" >/dev/null 2>&1 || true
  fi
  run_quiet nft delete table inet openngfw
  run_quiet ip netns del "$CLIENT_NS"
  run_quiet ip netns del "$SERVER_NS"
  run_quiet ip link del "$FW_CLIENT_IF"
  run_quiet ip link del "$FW_SERVER_IF"
  sysctl -w "net.ipv4.ip_forward=$old_ip_forward" >/dev/null 2>&1 || true
}
trap cleanup EXIT

setup_topology() {
  cleanup
  trap cleanup EXIT
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
  cat > "$out_dir/policy.yaml" <<EOF
zones:
  - name: untrust
    interfaces: [$FW_CLIENT_IF]
  - name: trust
    interfaces: [$FW_SERVER_IF]
addresses:
  - name: server
    cidr: $SERVER_IP/32
services:
  - name: iperf
    protocol: PROTOCOL_TCP
    ports:
      - start: $TARGET_PORT
  - name: ping
    protocol: PROTOCOL_ICMP
rules:
  - name: bench-client-to-server
    from_zones: [untrust]
    to_zones: [trust]
    destination_addresses: [server]
    services: [iperf, ping]
    action: ACTION_ALLOW
    log: true
EOF
}

start_controld() {
  ./bin/controld \
    --data-dir "$state_dir" \
    --log-dir "$log_dir" \
    --listen "$GRPC_LISTEN" \
    --http-listen "$HTTP_LISTEN" \
    --tls=false > "$out_dir/controld.log" 2>&1 &
  controld_pid="$!"
  for _ in $(seq 1 80); do
    if curl -fsS "http://$HTTP_LISTEN/v1/system/version" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "controld did not become ready; see $out_dir/controld.log" >&2
  return 1
}

commit_policy() {
  ./bin/ngfwctl --server "$GRPC_LISTEN" policy set -f "$out_dir/policy.yaml" > "$out_dir/policy-set.txt" 2>&1
  ./bin/ngfwctl --server "$GRPC_LISTEN" policy validate > "$out_dir/policy-validate.txt" 2>&1
  ./bin/ngfwctl --server "$GRPC_LISTEN" commit -m "local netns benchmark baseline" > "$out_dir/commit.txt" 2>&1
}

start_iperf_server() {
  ip netns exec "$SERVER_NS" iperf3 -s -p "$TARGET_PORT" --one-off > "$out_dir/iperf3-server.log" 2>&1 &
  iperf_pid="$!"
  sleep 0.5
}

start_churn_server() {
  cat > "$out_dir/churn-server.py" <<'PY'
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
    srv.listen(512)
    srv.settimeout(0.5)
    while running:
        try:
            conn, _addr = srv.accept()
        except socket.timeout:
            continue
        with conn:
            pass
PY
  ip netns exec "$SERVER_NS" python3 "$out_dir/churn-server.py" "$TARGET_PORT" > "$out_dir/churn-server.log" 2>&1 &
  churn_server_pid="$!"
  sleep 0.5
}

run_churn() {
  ip netns exec "$CLIENT_NS" sh -c "
ok=0
fail=0
start=\$(date +%s%N)
i=0
while [ \"\$i\" -lt '$CHURN_COUNT' ]; do
  i=\$((i+1))
  if nc -z -w1 '$SERVER_IP' '$TARGET_PORT' >/dev/null 2>&1; then
    ok=\$((ok+1))
  else
    fail=\$((fail+1))
  fi
done
end=\$(date +%s%N)
elapsed_ms=\$(((end-start)/1000000))
echo attempts='$CHURN_COUNT'
echo success=\"\$ok\"
echo failed=\"\$fail\"
echo elapsed_ms=\"\$elapsed_ms\"
"
}

collect_facts() {
  {
    uname -a
    printf "\n--- os-release ---\n"
    cat /etc/os-release 2>/dev/null || true
    printf "\n--- cpu ---\n"
    nproc 2>/dev/null || true
    lscpu 2>/dev/null | sed -n "1,24p" || true
    printf "\n--- nftables ---\n"
    nft --version || true
    printf "\n--- interfaces ---\n"
    ip -br addr || true
    printf "\n--- routes ---\n"
    ip route || true
  } > "$out_dir/host-facts.txt" 2>&1
  ip netns exec "$CLIENT_NS" ip -br addr > "$out_dir/client-netns.txt" 2>&1 || true
  ip netns exec "$SERVER_NS" ip -br addr > "$out_dir/server-netns.txt" 2>&1 || true
}

write_summary() {
  python3 - "$out_dir" <<'PY'
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

out = Path(sys.argv[1])
iperf = json.loads((out / "iperf3.json").read_text(encoding="utf-8"))
end = iperf.get("end", {})
sum_received = end.get("sum_received") or end.get("sum") or {}
sum_sent = end.get("sum_sent") or {}
streams = end.get("streams") or []
bits_per_second = float(sum_received.get("bits_per_second") or sum_sent.get("bits_per_second") or 0)
retransmits = sum(int(s.get("sender", {}).get("retransmits") or 0) for s in streams)
if not retransmits:
    retransmits = int(sum_sent.get("retransmits") or 0)

ping_text = (out / "ping.txt").read_text(encoding="utf-8", errors="replace")
ping_avg_ms = None
m = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms", ping_text)
if m:
    ping_avg_ms = float(m.group(2))

churn = {}
for line in (out / "churn.txt").read_text(encoding="utf-8", errors="replace").splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        churn[k.strip()] = v.strip()

def status_text(out):
    for name in ("ngfw-status-active.txt", "ngfw-status-final.txt", "ngfw-status.txt"):
        path = out / name
        if path.exists():
            text = path.read_text(encoding="utf-8", errors="replace")
            if text:
                return text
    return ""

def flowtable_evidence(out):
    nft_path = out / "nft-openngfw-final.txt"
    status = status_text(out)
    nft_text = nft_path.read_text(encoding="utf-8", errors="replace") if nft_path.exists() else ""

    def state(label):
        m = re.search(rf"^{re.escape(label)}:\s+(\S+)", status, re.MULTILINE)
        return m.group(1) if m else ""

    return {
        "host_state": state("  flowtable host"),
        "runtime_state": state("  flowtable live"),
        "status_captured": bool(status),
        "nft_ruleset_captured": bool(nft_text),
        "flowtable_declared": "flowtable fastpath" in nft_text,
        "offload_rule_present": "flow add @fastpath" in nft_text,
    }

def conntrack_evidence(out):
    status = status_text(out)
    if not status:
        return None
    m = re.search(r"^\s+state table:\s+(\S+)(?:\s+(\d+)/(\d+) entries \(([\d.]+)%\))?", status, re.MULTILINE)
    if not m:
        return None
    evidence = {
        "state": m.group(1),
        "status_captured": True,
        "current_entries": 0,
        "max_entries": 0,
        "usage_percent": 0.0,
    }
    if m.group(2):
        evidence["current_entries"] = int(m.group(2))
        evidence["max_entries"] = int(m.group(3))
        evidence["usage_percent"] = float(m.group(4))
    return evidence

def host_tuning_evidence(out):
    status = status_text(out)
    if not status:
        return None
    m = re.search(r"^\s+kernel tuning:\s+(\S+)", status, re.MULTILINE)
    if not m:
        return None
    return {
        "state": m.group(1),
        "status_captured": True,
    }

def inspection_state_from_status(policy_state, readiness_state):
    ready = (readiness_state or "").strip().lower()
    if ready == "disabled":
        return "not-inspected"
    if ready == "failed-open":
        return "failed-open"
    if ready == "failed-closed":
        return "failed-closed"
    if ready in ("degraded", "unknown"):
        return "bypassed-by-engine-health"
    policy = (policy_state or "").strip().lower()
    if "disabled" in policy:
        return "not-inspected"
    if "ips" in policy or "prevent" in policy:
        return "fully-inspected"
    if "ids" in policy or "detect" in policy:
        return "partially-inspected"
    return ""

def inspection_evidence(out):
    status = status_text(out)
    if not status:
        return None
    policy = re.search(r"^\s+inspection:\s+(.+?)\s*$", status, re.MULTILINE)
    readiness = re.search(r"^\s+inspection ready:\s*(\S+)", status, re.MULTILINE)
    engine = re.search(r"^\s+inspection eng:\s+(\S+)\s+(\S+)/(\S+)", status, re.MULTILINE)
    failure = re.search(r"^\s+fail behavior:\s+(\S+)", status, re.MULTILINE)
    bypass = re.search(r"^\s+bypass reason:\s+(.+?)\s*$", status, re.MULTILINE)
    degraded = re.search(r"^\s+degraded mode:\s+(.+?)\s*$", status, re.MULTILINE)
    if not readiness and not policy and not engine:
        return None
    evidence = {
        "state": readiness.group(1) if readiness else "unknown",
        "status_captured": True,
        "inspection_state": inspection_state_from_status(policy.group(1) if policy else "", readiness.group(1) if readiness else ""),
    }
    if engine:
        evidence["engine_name"] = engine.group(1)
        evidence["engine_mode"] = engine.group(2)
        evidence["engine_state"] = engine.group(3)
    if failure:
        evidence["failure_behavior"] = failure.group(1)
    if bypass:
        evidence["bypass_reason"] = bypass.group(1).strip()
    if degraded:
        evidence["degraded_behavior"] = degraded.group(1).strip()
    return evidence

summary = {
    "schema_version": "phragma.perf.v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "profile": os.environ.get("BENCH_PROFILE", "local-netns-forwarding"),
    "security_services": "none",
    "inspection_state": "not-inspected",
    "target": {"ip": os.environ["SERVER_IP"], "port": int(os.environ["TARGET_PORT"])},
    "duration_seconds": int(os.environ["DURATION"]),
    "parallel_streams": int(os.environ["PARALLEL"]),
    "tcp_bits_per_second": bits_per_second,
    "tcp_gbps": bits_per_second / 1_000_000_000,
    "tcp_retransmits": retransmits,
    "ping_avg_ms": ping_avg_ms,
    "connection_churn": churn,
    "flowtable_evidence": flowtable_evidence(out),
    "claim_scope": "single-host Linux network namespace benchmark through real OpenNGFW nftables policy; not a cloud-NIC throughput claim",
}
host_tuning = host_tuning_evidence(out)
if host_tuning:
    summary["host_tuning_evidence"] = host_tuning
conntrack = conntrack_evidence(out)
if conntrack:
    summary["conntrack_evidence"] = conntrack
inspection = inspection_evidence(out)
if inspection:
    summary["inspection_evidence"] = inspection
(out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

report = [
    "# OpenNGFW Local Namespace Benchmark",
    "",
    f"- Profile: `{summary['profile']}`",
    f"- Security services: `{summary['security_services']}`",
    f"- Inspection state: `{summary['inspection_state']}`",
    f"- Target: `{summary['target']['ip']}:{summary['target']['port']}`",
    f"- Duration: `{summary['duration_seconds']}s`",
    f"- Parallel streams: `{summary['parallel_streams']}`",
    "",
    "## Results",
    "",
    f"- TCP throughput: `{summary['tcp_gbps']:.3f} Gbps`",
    f"- TCP retransmits: `{summary['tcp_retransmits']}`",
    f"- Ping average: `{summary['ping_avg_ms'] if summary['ping_avg_ms'] is not None else 'n/a'} ms`",
    f"- Connection attempts: `{churn.get('attempts', 'n/a')}`",
    f"- Connection success: `{churn.get('success', 'n/a')}`",
    f"- Connection failures: `{churn.get('failed', 'n/a')}`",
    f"- Inspection readiness: `{inspection.get('state')}` (`{inspection.get('inspection_state')}`)" if inspection else "- Inspection readiness: `not captured`",
    f"- Host tuning: `{host_tuning.get('state')}`" if host_tuning else "- Host tuning: `not captured`",
    f"- Flowtable runtime: `{summary['flowtable_evidence'].get('runtime_state') or 'unknown'}`",
    f"- Conntrack state table: `{conntrack.get('state')}` ({conntrack.get('current_entries')}/{conntrack.get('max_entries')} entries, {conntrack.get('usage_percent'):.1f}%)" if conntrack else "- Conntrack state table: `not captured`",
    "",
    "## Evidence Files",
    "",
    "- `summary.json`",
    "- `iperf3.json`",
    "- `ping.txt`",
    "- `churn.txt`",
    "- `policy.yaml`",
    "- `policy-validate.txt`",
    "- `ngfw-status.txt`",
    "- `ngfw-status-active.txt`",
    "- `ngfw-status-final.txt`",
    "- `nft-openngfw.txt`",
    "- `nft-openngfw-final.txt`",
    "- `host-facts.txt`",
    "",
    "## Claim Scope",
    "",
    summary["claim_scope"],
    "",
]
(out / "report.md").write_text("\n".join(report), encoding="utf-8")
PY
}

setup_topology
collect_facts
write_policy
start_controld
commit_policy

./bin/ngfwctl --server "$GRPC_LISTEN" status > "$out_dir/ngfw-status.txt" 2>&1 || true
nft list table inet openngfw > "$out_dir/nft-openngfw.txt" 2>&1

start_iperf_server
ip netns exec "$CLIENT_NS" iperf3 -J -c "$SERVER_IP" -p "$TARGET_PORT" -t 3 -P 1 > "$out_dir/iperf3-warmup.json" 2>"$out_dir/iperf3-warmup.err" || true
if [ -n "$iperf_pid" ]; then
  wait "$iperf_pid" >/dev/null 2>&1 || true
  iperf_pid=""
fi

start_iperf_server
ip netns exec "$CLIENT_NS" iperf3 -J -c "$SERVER_IP" -p "$TARGET_PORT" -t "$DURATION" -P "$PARALLEL" > "$out_dir/iperf3.json" 2>"$out_dir/iperf3.err" &
iperf_client_pid="$!"
sleep 1
./bin/ngfwctl --server "$GRPC_LISTEN" status > "$out_dir/ngfw-status-active.txt" 2>&1 || true
wait "$iperf_client_pid"
if [ -n "$iperf_pid" ]; then
  wait "$iperf_pid" >/dev/null 2>&1 || true
  iperf_pid=""
fi

ip netns exec "$CLIENT_NS" ping -c "$PING_COUNT" "$SERVER_IP" > "$out_dir/ping.txt" 2>&1 || true
start_churn_server
run_churn > "$out_dir/churn.txt" 2>&1 || true
if [ -n "$churn_server_pid" ]; then
  kill "$churn_server_pid" >/dev/null 2>&1 || true
  wait "$churn_server_pid" >/dev/null 2>&1 || true
  churn_server_pid=""
fi
./bin/ngfwctl --server "$GRPC_LISTEN" status > "$out_dir/ngfw-status-final.txt" 2>&1 || true
nft list table inet openngfw > "$out_dir/nft-openngfw-final.txt" 2>&1 || true

write_summary

echo "local namespace benchmark report: $out_dir/report.md"
echo "local namespace benchmark summary: $out_dir/summary.json"
