#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: release/privileged-integration-no-skip.sh [-- <command>...]

Runs the privileged integration release gate and rejects evidence when any
integration test is skipped. The default command is:

  make integration-test
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

cmd=(make integration-test)
if [[ "${1:-}" == "--" ]]; then
  shift
  if [[ "$#" -eq 0 ]]; then
    echo "privileged integration wrapper requires a command after --" >&2
    exit 2
  fi
  cmd=("$@")
elif [[ "$#" -gt 0 ]]; then
  echo "unexpected argument: $1" >&2
  usage >&2
  exit 2
fi

tmp="$(mktemp "${TMPDIR:-/tmp}/openngfw-privileged-integration.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

echo "check=privileged-integration"
echo "mode=run"
echo "privileged_integration_scope=nftables,network-namespaces,packet-capture,live-integration"
echo "privileged_integration_skip_policy=no-skipped-tests"
echo "run_requires=linux-root,nftables,iproute2,netcat,tcpdump"
printf 'command='
printf '%q ' "${cmd[@]}"
printf '\n'

set +e
"${cmd[@]}" >"$tmp" 2>&1
rc=$?
set -e

cat "$tmp"

skip_count="$(grep -Ec '^[[:space:]]*--- SKIP:|^[[:space:]]*=== SKIP' "$tmp" || true)"
if [[ "$rc" -ne 0 ]]; then
  echo "status=failed"
  echo "failure=privileged-integration-command-exited-$rc"
  exit "$rc"
fi
if [[ "$skip_count" -ne 0 ]]; then
  echo "status=failed"
  echo "failure=privileged-integration-skipped-tests"
  echo "skipped_tests=$skip_count"
  grep -E '^[[:space:]]*--- SKIP:|^[[:space:]]*=== SKIP' "$tmp" || true
  exit 1
fi
if ! grep -q '^PASS$' "$tmp"; then
  echo "status=failed"
  echo "failure=privileged-integration-missing-pass-marker"
  exit 1
fi

echo "skipped_tests=0"
echo "status=passed"
