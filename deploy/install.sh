#!/usr/bin/env bash
# OpenNGFW single-node installer for Ubuntu 24.04 (tested target: an
# Oracle Cloud VM — see docs/testing-plan.md for the full walkthrough).
#
# Installs engines from the distro, builds controld/ngfwctl from this
# checkout (or uses prebuilt binaries in ./bin), lays out directories,
# and installs the systemd unit. Run as root from the repo root:
#
#   sudo deploy/install.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "[1/6] Engine packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q nftables suricata frr wireguard-tools \
  strongswan-swanctl charon-systemd curl jq

echo "[2/6] Vector (telemetry shipper)"
if ! command -v vector >/dev/null; then
  bash -c "$(curl -fsSL https://sh.vector.dev)" -- -y --prefix /usr/local || \
    echo "WARN: vector install failed; telemetry pipeline will be unavailable until installed"
fi

echo "[3/6] OpenNGFW binaries"
if [[ -x "$REPO_ROOT/bin/controld" && -x "$REPO_ROOT/bin/ngfwctl" ]]; then
  install -m 0755 "$REPO_ROOT/bin/controld" "$REPO_ROOT/bin/ngfwctl" /usr/local/bin/
elif command -v go >/dev/null; then
  (cd "$REPO_ROOT" && make build)
  install -m 0755 "$REPO_ROOT/bin/controld" "$REPO_ROOT/bin/ngfwctl" /usr/local/bin/
else
  echo "ERROR: no prebuilt binaries in ./bin and Go is not installed" >&2
  exit 1
fi

echo "[4/6] Directories"
install -d -m 0755 /var/lib/openngfw /var/log/openngfw
install -d -m 0700 /etc/openngfw /etc/openngfw/secrets /etc/openngfw/keys

echo "[5/6] Local API users"
if [[ ! -f /etc/openngfw/users.yaml ]]; then
  ADMIN_TOKEN="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' )"
  cat > /etc/openngfw/users.yaml <<EOF
users:
  - name: admin
    token: ${ADMIN_TOKEN}
    role: admin
EOF
  chmod 600 /etc/openngfw/users.yaml
  echo "    created /etc/openngfw/users.yaml — admin token: ${ADMIN_TOKEN}"
  echo "    (export NGFW_TOKEN=${ADMIN_TOKEN} for the test plan)"
fi

echo "[6/6] systemd unit"
install -m 0644 "$REPO_ROOT/deploy/systemd/controld.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now controld

echo
echo "OpenNGFW installed. Verify with:"
echo "  systemctl status controld"
echo "  ngfwctl version --remote"
echo "Next: docs/testing-plan.md"
