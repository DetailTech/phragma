#!/usr/bin/env bash
set -euo pipefail

MODE="check"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="${WORK_DIR:-}"

usage() {
  cat <<'EOF'
OpenNGFW rootless content-package verification smoke.

Usage:
  e2e/content-package-smoke.sh --check

Creates signed demo content packages in Go test temp directories, installs
them into a temp content data root, verifies provenance/regression/signature
posture, rejects a failed-regression package, and proves rollback restores the
previous verified package. This smoke verifies package mechanics only; it does
not certify production App-ID, Threat-ID, or intel-feed content.

Useful environment:
  WORK_DIR=/tmp/path  store a copy of the go test evidence log
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --check) MODE="check" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ "$MODE" != "check" ]; then
  echo "unsupported mode: $MODE" >&2
  exit 2
fi

cd "$REPO_ROOT"

if ! command -v go >/dev/null 2>&1; then
  echo "missing command: go" >&2
  exit 1
fi

if [ -n "$WORK_DIR" ]; then
  mkdir -p "$WORK_DIR"
  LOG_FILE="$WORK_DIR/content-package-smoke.log"
else
  LOG_FILE=""
fi

echo "content-package-smoke: running rootless verifier/install/rollback demo"
echo "content-package-smoke: scope=demo-only production_content=false mechanics_verified=true production_ready=false"
echo "content-package-smoke: required_production_evidence=package-kind-specific signed evidence/*.json artifacts"
if [ -n "$LOG_FILE" ]; then
  go test -count=1 -run '^TestRootlessContentPackageSmoke$' -v ./internal/contentpkg | tee "$LOG_FILE"
  echo "content-package-smoke: evidence log: $LOG_FILE"
else
  go test -count=1 -run '^TestRootlessContentPackageSmoke$' -v ./internal/contentpkg
fi
