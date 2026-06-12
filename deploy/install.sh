#!/usr/bin/env bash
# OpenNGFW single-node installer.
#
# Supported targets:
#   - Ubuntu 24.04 / Debian-family (apt)
#   - Oracle Linux 9 / EL9-family: RHEL, Rocky, AlmaLinux (dnf + EPEL)
#
# Installs engines from the distro, builds controld/ngfwctl from this
# checkout (or uses prebuilt binaries in ./bin), lays out directories,
# and installs the systemd unit. Run as root from the repo root:
#
#   sudo deploy/install.sh
#
# OCI walkthroughs: docs/testing-plan.md (Ubuntu) and
# docs/testing-plan-ol9.md (Oracle Linux 9).
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

. /etc/os-release
FAMILY=""
case "${ID}:${ID_LIKE:-}" in
  ubuntu:* | debian:* | *:*debian*) FAMILY=debian ;;
  ol:* | rhel:* | rocky:* | almalinux:* | centos:* | *:*rhel* | *:*fedora*) FAMILY=el ;;
  *)
    echo "ERROR: unsupported distro '${ID}' — supported: Ubuntu/Debian, Oracle Linux 9 / EL9" >&2
    exit 1
    ;;
esac
echo "Detected ${PRETTY_NAME:-$ID} (${FAMILY} family)"

echo "[1/7] Engine packages"
if [[ $FAMILY == debian ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  apt-get install -y -q nftables suricata frr wireguard-tools \
    strongswan-swanctl charon-systemd ethtool curl jq
else
  # Suricata, strongSwan, and wireguard-tools live in EPEL on EL9.
  if [[ $ID == ol ]]; then
    dnf install -y oracle-epel-release-el9
  else
    dnf install -y epel-release
  fi
  dnf install -y nftables frr suricata strongswan wireguard-tools ethtool curl jq tar
fi

echo "[2/7] Host services"
# This node IS the firewall: firewalld would fight the managed ruleset
# (its own nftables tables filter the same hooks). Disable it.
if systemctl is-enabled --quiet firewalld 2>/dev/null || systemctl is-active --quiet firewalld 2>/dev/null; then
  echo "    WARNING: disabling firewalld — OpenNGFW owns this host's packet filtering"
  systemctl disable --now firewalld
fi
# charon must be running for swanctl-based IPsec management (M3).
systemctl enable --now strongswan 2>/dev/null \
  || echo "    note: strongswan service not enabled (fine until you use IPsec)"

echo "[3/7] Vector (telemetry shipper)"
if ! command -v vector >/dev/null; then
  bash -c "$(curl -fsSL https://sh.vector.dev)" -- -y --prefix /usr/local || \
    echo "WARN: vector install failed; telemetry pipeline will be unavailable until installed"
fi

echo "[4/7] OpenNGFW binaries"
if [[ -x "$REPO_ROOT/bin/controld" && -x "$REPO_ROOT/bin/ngfwctl" ]]; then
  install -m 0755 "$REPO_ROOT/bin/controld" "$REPO_ROOT/bin/ngfwctl" /usr/local/bin/
elif command -v go >/dev/null; then
  (cd "$REPO_ROOT" && make build)
  install -m 0755 "$REPO_ROOT/bin/controld" "$REPO_ROOT/bin/ngfwctl" /usr/local/bin/
else
  echo "ERROR: no prebuilt binaries in ./bin and Go is not installed" >&2
  exit 1
fi

echo "[5/7] Directories"
install -d -m 0755 /var/lib/openngfw /var/log/openngfw
install -d -m 0700 /etc/openngfw /etc/openngfw/secrets /etc/openngfw/keys

echo "[6/7] Local API users"
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

echo "[7/7] systemd unit"
install -m 0644 "$REPO_ROOT/deploy/systemd/controld.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now controld

echo
echo "OpenNGFW installed. Verify with:"
echo "  systemctl status controld"
echo "  ngfwctl version --remote"
if [[ $FAMILY == el ]]; then
  echo "Next: docs/testing-plan-ol9.md"
else
  echo "Next: docs/testing-plan.md"
fi
