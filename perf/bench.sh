#!/usr/bin/env bash
set -euo pipefail

MODE="check"
BENCH_PROFILE="${BENCH_PROFILE:-forwarding-large-flow}"
OUTPUT_ROOT="${OUTPUT_ROOT:-perf/results}"
DURATION="${DURATION:-30}"
PARALLEL="${PARALLEL:-8}"
TARGET_PORT="${TARGET_PORT:-5201}"
PING_COUNT="${PING_COUNT:-20}"
CHURN_COUNT="${CHURN_COUNT:-200}"
START_IPERF_SERVER="${START_IPERF_SERVER:-1}"
INSPECTION_STATE="${INSPECTION_STATE:-not-inspected}"
SECURITY_SERVICES="${SECURITY_SERVICES:-none}"
CLIENT_HOST="${CLIENT_HOST:-}"
SERVER_HOST="${SERVER_HOST:-}"
FW_HOST="${FW_HOST:-}"
TARGET_IP="${TARGET_IP:-}"
SSH_BIN="${SSH_BIN:-ssh}"
SSH_OPTS="${SSH_OPTS:-}"
FW_STATUS_CMD="${FW_STATUS_CMD:-ngfwctl status}"
FW_NFT_CMD="${FW_NFT_CMD:-sudo nft list table inet openngfw}"

export BENCH_PROFILE OUTPUT_ROOT DURATION PARALLEL TARGET_PORT PING_COUNT
export CHURN_COUNT START_IPERF_SERVER INSPECTION_STATE SECURITY_SERVICES
export CLIENT_HOST SERVER_HOST FW_HOST TARGET_IP SSH_BIN SSH_OPTS FW_STATUS_CMD FW_NFT_CMD

usage() {
  cat <<'EOF'
OpenNGFW benchmark harness.

Usage:
  perf/bench.sh --check
  perf/bench.sh --run

Required for --run:
  CLIENT_HOST=user@client-vm
  SERVER_HOST=user@server-vm
  TARGET_IP=<server dataplane IP reachable through the firewall>

Optional:
  FW_HOST=user@firewall-vm
  FW_STATUS_CMD='NGFW_TOKEN=... ngfwctl status'
  FW_NFT_CMD='sudo nft list table inet openngfw'
  BENCH_PROFILE=forwarding-large-flow
  SECURITY_SERVICES='ids-detect'
  INSPECTION_STATE='fully-inspected'
  DURATION=30
  PARALLEL=8
  TARGET_PORT=5201
  PING_COUNT=20
  CHURN_COUNT=200
  OUTPUT_ROOT=perf/results
  SSH_OPTS='-i key.pem -o StrictHostKeyChecking=accept-new'
  START_IPERF_SERVER=0

The harness does not configure firewall policy. It measures the currently
running policy and records the declared profile/services in the report.
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

read -r -a SSH_ARGS <<< "$SSH_OPTS"

have() {
  command -v "$1" >/dev/null 2>&1
}

ssh_cmd() {
  local host="$1"
  local command="$2"
  "$SSH_BIN" "${SSH_ARGS[@]}" "$host" "$command"
}

require_local() {
  local missing=0
  for cmd in "$@"; do
    if ! have "$cmd"; then
      echo "missing local command: $cmd" >&2
      missing=1
    fi
  done
  return "$missing"
}

require_remote() {
  local host="$1"
  shift
  local missing=0
  for cmd in "$@"; do
    if ! ssh_cmd "$host" "command -v $cmd >/dev/null 2>&1"; then
      echo "missing remote command on $host: $cmd" >&2
      missing=1
    fi
  done
  return "$missing"
}

check_inputs() {
  local failed=0
  require_local "$SSH_BIN" python3 date mkdir sed awk || failed=1

  if [ -n "$CLIENT_HOST" ]; then
    require_remote "$CLIENT_HOST" iperf3 ping bash date || failed=1
  fi
  if [ -n "$SERVER_HOST" ]; then
    require_remote "$SERVER_HOST" iperf3 bash nohup || failed=1
  fi
  if [ -n "$FW_HOST" ]; then
    if ! ssh_cmd "$FW_HOST" "$FW_STATUS_CMD >/dev/null 2>&1"; then
      echo "firewall status command failed on $FW_HOST: $FW_STATUS_CMD" >&2
      failed=1
    fi
  fi

  return "$failed"
}

if [ "$MODE" = "check" ]; then
  check_inputs
  echo "benchmark preflight complete"
  exit 0
fi

if [ -z "$CLIENT_HOST" ] || [ -z "$SERVER_HOST" ] || [ -z "$TARGET_IP" ]; then
  echo "CLIENT_HOST, SERVER_HOST, and TARGET_IP are required for --run" >&2
  usage >&2
  exit 2
fi

check_inputs

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
safe_profile="$(printf '%s' "$BENCH_PROFILE" | sed 's/[^A-Za-z0-9_.-]/-/g')"
out_dir="$OUTPUT_ROOT/${timestamp}-${safe_profile}"
mkdir -p "$out_dir"

write_metadata() {
  python3 - "$out_dir/metadata.json" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

path = sys.argv[1]
data = {
    "schema_version": "phragma.perf.v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "profile": os.environ.get("BENCH_PROFILE", ""),
    "security_services": os.environ.get("SECURITY_SERVICES", ""),
    "inspection_state": os.environ.get("INSPECTION_STATE", ""),
    "client_host": os.environ.get("CLIENT_HOST", ""),
    "server_host": os.environ.get("SERVER_HOST", ""),
    "firewall_host": os.environ.get("FW_HOST", ""),
    "target_ip": os.environ.get("TARGET_IP", ""),
    "target_port": int(os.environ.get("TARGET_PORT", "5201")),
    "duration_seconds": int(os.environ.get("DURATION", "30")),
    "parallel_streams": int(os.environ.get("PARALLEL", "8")),
    "ping_count": int(os.environ.get("PING_COUNT", "20")),
    "churn_count": int(os.environ.get("CHURN_COUNT", "200")),
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}

remote_facts() {
  local host="$1"
  local label="$2"
  ssh_cmd "$host" 'set -e; uname -a; printf "\n--- os-release ---\n"; cat /etc/os-release 2>/dev/null || true; printf "\n--- cpu ---\n"; nproc 2>/dev/null || true; lscpu 2>/dev/null | sed -n "1,24p" || true; printf "\n--- addresses ---\n"; ip -br addr 2>/dev/null || true; printf "\n--- routes ---\n"; ip route 2>/dev/null || true' > "$out_dir/${label}-facts.txt" 2>&1 || true
}

start_iperf_server() {
  if [ "$START_IPERF_SERVER" = "0" ]; then
    return 0
  fi
  ssh_cmd "$SERVER_HOST" "nohup iperf3 -s -p $TARGET_PORT --one-off > /tmp/openngfw-iperf3-$TARGET_PORT.log 2>&1 &"
  sleep 1
}

run_churn() {
  ssh_cmd "$CLIENT_HOST" "TARGET_IP='$TARGET_IP' TARGET_PORT='$TARGET_PORT' CHURN_COUNT='$CHURN_COUNT' bash -lc '
if ! command -v nc >/dev/null 2>&1; then
  echo skipped=missing-nc
  exit 0
fi
ok=0
fail=0
start=\$(date +%s%N)
i=0
while [ \"\$i\" -lt \"\$CHURN_COUNT\" ]; do
  i=\$((i+1))
  if nc -z -w1 \"\$TARGET_IP\" \"\$TARGET_PORT\" >/dev/null 2>&1; then
    ok=\$((ok+1))
  else
    fail=\$((fail+1))
  fi
done
end=\$(date +%s%N)
elapsed_ms=\$(((end-start)/1000000))
echo attempts=\"\$CHURN_COUNT\"
echo success=\"\$ok\"
echo failed=\"\$fail\"
echo elapsed_ms=\"\$elapsed_ms\"
'"
}

write_metadata
remote_facts "$CLIENT_HOST" "client"
remote_facts "$SERVER_HOST" "server"
if [ -n "$FW_HOST" ]; then
  remote_facts "$FW_HOST" "firewall"
  ssh_cmd "$FW_HOST" "$FW_STATUS_CMD" > "$out_dir/firewall-status.txt" 2>&1 || true
fi

start_iperf_server
ssh_cmd "$CLIENT_HOST" "iperf3 -J -c '$TARGET_IP' -p '$TARGET_PORT' -t 3 -P 1" > "$out_dir/iperf3-warmup.json" 2>"$out_dir/iperf3-warmup.err" || true

start_iperf_server
ssh_cmd "$CLIENT_HOST" "iperf3 -J -c '$TARGET_IP' -p '$TARGET_PORT' -t '$DURATION' -P '$PARALLEL'" > "$out_dir/iperf3.json" 2>"$out_dir/iperf3.err" &
iperf_client_pid="$!"
sleep 1
if [ -n "$FW_HOST" ]; then
  ssh_cmd "$FW_HOST" "$FW_STATUS_CMD" > "$out_dir/firewall-status-active.txt" 2>&1 || true
fi
wait "$iperf_client_pid"

ssh_cmd "$CLIENT_HOST" "ping -c '$PING_COUNT' '$TARGET_IP'" > "$out_dir/ping.txt" 2>&1 || true
run_churn > "$out_dir/churn.txt" 2>&1 || true

if [ -n "$FW_HOST" ]; then
  ssh_cmd "$FW_HOST" "$FW_STATUS_CMD" > "$out_dir/firewall-status-final.txt" 2>&1 || true
  ssh_cmd "$FW_HOST" "$FW_NFT_CMD" > "$out_dir/nft-openngfw-final.txt" 2>&1 || true
fi

python3 - "$out_dir" <<'PY'
import json
import re
import sys
from pathlib import Path

out = Path(sys.argv[1])
meta = json.loads((out / "metadata.json").read_text(encoding="utf-8"))
iperf = json.loads((out / "iperf3.json").read_text(encoding="utf-8"))
end = iperf.get("end", {})
sum_received = end.get("sum_received") or end.get("sum") or {}
sum_sent = end.get("sum_sent") or {}
streams = end.get("streams") or []

bits_per_second = float(sum_received.get("bits_per_second") or sum_sent.get("bits_per_second") or 0)
retransmits = sum(int(s.get("sender", {}).get("retransmits") or 0) for s in streams)
if not retransmits:
    retransmits = int(sum_sent.get("retransmits") or 0)

ping_text = (out / "ping.txt").read_text(encoding="utf-8", errors="replace") if (out / "ping.txt").exists() else ""
ping_avg_ms = None
m = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms", ping_text)
if m:
    ping_avg_ms = float(m.group(2))

churn = {}
churn_text = (out / "churn.txt").read_text(encoding="utf-8", errors="replace") if (out / "churn.txt").exists() else ""
for line in churn_text.splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        churn[k.strip()] = v.strip()

def status_text(out):
    for name in ("firewall-status-active.txt", "firewall-status-final.txt", "firewall-status.txt"):
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

summary = {
    "schema_version": meta["schema_version"],
    "generated_at": meta["generated_at"],
    "profile": meta["profile"],
    "security_services": meta["security_services"],
    "inspection_state": meta["inspection_state"],
    "target": {"ip": meta["target_ip"], "port": meta["target_port"]},
    "duration_seconds": meta["duration_seconds"],
    "parallel_streams": meta["parallel_streams"],
    "tcp_bits_per_second": bits_per_second,
    "tcp_gbps": bits_per_second / 1_000_000_000,
    "tcp_retransmits": retransmits,
    "ping_avg_ms": ping_avg_ms,
    "connection_churn": churn,
    "flowtable_evidence": flowtable_evidence(out),
    "claim_scope": "measured environment only; do not publish without full profile context",
}
host_tuning = host_tuning_evidence(out)
if host_tuning:
    summary["host_tuning_evidence"] = host_tuning
conntrack = conntrack_evidence(out)
if conntrack:
    summary["conntrack_evidence"] = conntrack
(out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

report = [
    "# OpenNGFW Benchmark Report",
    "",
    f"- Profile: `{summary['profile']}`",
    f"- Security services: `{summary['security_services']}`",
    f"- Inspection state: `{summary['inspection_state']}`",
    f"- Target: `{meta['target_ip']}:{meta['target_port']}`",
    f"- Duration: `{meta['duration_seconds']}s`",
    f"- Parallel streams: `{meta['parallel_streams']}`",
    "",
    "## Results",
    "",
    f"- TCP throughput: `{summary['tcp_gbps']:.3f} Gbps`",
    f"- TCP retransmits: `{summary['tcp_retransmits']}`",
    f"- Ping average: `{summary['ping_avg_ms'] if summary['ping_avg_ms'] is not None else 'n/a'} ms`",
]
if churn:
    report.extend([
        f"- Connection attempts: `{churn.get('attempts', 'n/a')}`",
        f"- Connection success: `{churn.get('success', 'n/a')}`",
        f"- Connection failures: `{churn.get('failed', 'n/a')}`",
        f"- Connection churn elapsed: `{churn.get('elapsed_ms', 'n/a')} ms`",
    ])
if conntrack:
    report.append(f"- Conntrack state table: `{conntrack.get('state')}` ({conntrack.get('current_entries')}/{conntrack.get('max_entries')} entries, {conntrack.get('usage_percent'):.1f}%)")
if host_tuning:
    report.append(f"- Host tuning: `{host_tuning.get('state')}`")
report.append(f"- Flowtable runtime: `{summary['flowtable_evidence'].get('runtime_state') or 'unknown'}`")
report.extend([
    "",
    "## Evidence Files",
    "",
    "- `metadata.json`",
    "- `summary.json`",
    "- `iperf3.json`",
    "- `ping.txt`",
    "- `churn.txt`",
    "- `client-facts.txt`",
    "- `server-facts.txt`",
    "- `firewall-facts.txt`, `firewall-status.txt`, `firewall-status-active.txt`, and `firewall-status-final.txt` when `FW_HOST` is set",
    "- `nft-openngfw-final.txt` when `FW_HOST` is set",
    "",
    "## Claim Scope",
    "",
    "This report is evidence for the measured environment only. Do not compare or publish it without profile context, services enabled, instance shape, NIC mode, policy, and inspection state.",
    "",
])
(out / "report.md").write_text("\n".join(report), encoding="utf-8")
PY

echo "benchmark report: $out_dir/report.md"
echo "benchmark summary: $out_dir/summary.json"
