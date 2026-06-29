#!/usr/bin/env bash
# OpenNGFW single-node installer.
#
# Supported targets:
#   - Ubuntu 24.04 / Debian-family (apt)
#   - Oracle Linux 9 / EL9-family: RHEL, Rocky, AlmaLinux (dnf + EPEL)
#
# Installs engines from the distro, builds controld/ngfwctl from this
# checkout (or uses prebuilt binaries in ./bin), installs Go/make when a
# source build needs them, lays out directories, and installs the systemd
# unit. Run as root from the repo root:
#
#   sudo deploy/install.sh
#
# OCI walkthroughs: docs/testing-plan.md (Ubuntu) and
# docs/testing-plan-ol9.md (Oracle Linux 9).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_SOURCE_DIR="${BIN_DIR:-$REPO_ROOT/bin}"
if [[ "$BIN_SOURCE_DIR" != /* ]]; then
  BIN_SOURCE_DIR="$REPO_ROOT/$BIN_SOURCE_DIR"
fi

binary_matches_commit() {
  local binary="$1"
  if [[ -z "${COMMIT:-}" ]]; then
    return 0
  fi
  [[ -x "$binary" ]] && "$binary" --version 2>/dev/null | grep -q "$COMMIT"
}

prebuilt_binary_pair_matches_commit() {
  [[ -x "$BIN_SOURCE_DIR/controld" && -x "$BIN_SOURCE_DIR/ngfwctl" ]] &&
    binary_matches_commit "$BIN_SOURCE_DIR/controld" &&
    binary_matches_commit "$BIN_SOURCE_DIR/ngfwctl"
}

# Rootless, read-only selection probe used by the install smoke test. Normal
# installation behavior is unchanged; both binaries must pass the same helper
# used by the installer before a prebuilt pair is reused.
if [[ "${1:-}" == "--check-prebuilt-binaries" ]]; then
  echo "check=prebuilt-binary-pair"
  if prebuilt_binary_pair_matches_commit; then
    echo "status=passed"
    exit 0
  fi
  echo "status=failed"
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

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

EL_EXTRA_REPOS=()

pkg_command_missing() {
  local cmd="$1"
  ! command -v "$cmd" >/dev/null 2>&1
}

deb_package_installed() {
  local pkg="$1"
  dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'
}

install_missing_command_packages() {
  local label="$1"
  shift

  local packages=()
  local spec cmd pkg
  for spec in "$@"; do
    cmd="${spec%%:*}"
    pkg="${spec#*:}"
    if pkg_command_missing "$cmd"; then
      packages+=("$pkg")
    fi
  done

  if [[ ${#packages[@]} -eq 0 ]]; then
    echo "    ${label}: all required commands already present"
    return 0
  fi

  echo "    ${label}: installing missing packages: ${packages[*]}"
  if [[ $FAMILY == debian ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -q "${packages[@]}"
  else
    dnf install -y "${EL_EXTRA_REPOS[@]}" "${packages[@]}"
  fi
}

ensure_el_epel_repo() {
  if [[ $ID == ol ]]; then
    if ! dnf repolist all ol9_developer_EPEL 2>/dev/null | grep -q '^ol9_developer_EPEL'; then
      dnf install -y oracle-epel-release-el9
    fi
    # Oracle ships the EPEL repo definition disabled by default on OCI
    # images, so enable it explicitly for the engine package transaction.
    EL_EXTRA_REPOS=(--enablerepo=ol9_developer_EPEL)
  else
    if ! rpm -q epel-release >/dev/null 2>&1; then
      dnf install -y epel-release
    fi
    EL_EXTRA_REPOS=()
  fi
}

install_build_toolchain() {
  if [[ $FAMILY == debian ]]; then
    install_missing_command_packages "build toolchain for source checkout" \
      go:golang-go \
      make:make
  else
    install_missing_command_packages "build toolchain for source checkout" \
      go:golang \
      make:make
  fi
}

echo "[1/8] Engine packages"
if [[ $FAMILY == debian ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  install_missing_command_packages "engine prerequisites" \
    nft:nftables \
    conntrack:conntrack \
    suricata:suricata \
    vtysh:frr \
    wg:wireguard-tools \
    swanctl:strongswan-swanctl \
    ethtool:ethtool \
    curl:curl \
    jq:jq
  if ! deb_package_installed charon-systemd; then
    apt-get install -y -q charon-systemd
  fi
else
  # Suricata, strongSwan, and wireguard-tools live in EPEL on EL9.
  ensure_el_epel_repo
  install_missing_command_packages "engine prerequisites" \
    nft:nftables \
    conntrack:conntrack-tools \
    vtysh:frr \
    suricata:suricata \
    swanctl:strongswan \
    wg:wireguard-tools \
    ethtool:ethtool \
    curl:curl \
    jq:jq \
    tar:tar
fi

echo "[2/8] Host services"
# This node IS the firewall: firewalld would fight the managed ruleset
# (its own nftables tables filter the same hooks). Disable it.
if systemctl is-enabled --quiet firewalld 2>/dev/null || systemctl is-active --quiet firewalld 2>/dev/null; then
  echo "    WARNING: disabling firewalld — OpenNGFW owns this host's packet filtering"
  systemctl disable --now firewalld
fi
# charon must be running for swanctl-based IPsec management (M3).
systemctl enable --now strongswan 2>/dev/null \
  || echo "    note: strongswan service not enabled (fine until you use IPsec)"

echo "[3/8] Vector (telemetry shipper)"
if ! command -v vector >/dev/null; then
  if [[ "${OPENNGFW_UNSAFE_REMOTE_VECTOR_INSTALL:-}" == "1" ]]; then
    echo "    WARNING: OPENNGFW_UNSAFE_REMOTE_VECTOR_INSTALL=1 set"
    echo "    WARNING: running the remote Vector installer as root; use only for legacy lab compatibility"
    VECTOR_INSTALLER="$(mktemp)"
    if curl -fsSL --proto '=https' --tlsv1.2 https://sh.vector.dev -o "$VECTOR_INSTALLER" &&
       bash "$VECTOR_INSTALLER" -- -y --prefix /usr/local; then
      rm -f "$VECTOR_INSTALLER"
    else
      rm -f "$VECTOR_INSTALLER"
      echo "    WARN: vector install failed; telemetry pipeline will be unavailable until installed"
    fi
  else
    echo "    WARN: vector not found; telemetry pipeline will be unavailable until installed"
    echo "    Install Vector through an approved package manager or pinned, checksum-verified release artifact."
    if [[ $FAMILY == debian ]]; then
      echo "    Debian/Ubuntu: configure an approved Vector APT repo or internal mirror, then install a pinned vector package."
    else
      echo "    EL9: configure an approved Vector RPM repo or internal mirror, then install a pinned vector package."
    fi
    echo "    Legacy lab opt-in only: OPENNGFW_UNSAFE_REMOTE_VECTOR_INSTALL=1 sudo deploy/install.sh"
  fi
fi

echo "[4/8] OpenNGFW binaries"
if prebuilt_binary_pair_matches_commit; then
  install -m 0755 "$BIN_SOURCE_DIR/controld" "$BIN_SOURCE_DIR/ngfwctl" /usr/local/bin/
else
  install_build_toolchain
  (cd "$REPO_ROOT" && make build BIN_DIR="$BIN_SOURCE_DIR")
  install -m 0755 "$BIN_SOURCE_DIR/controld" "$BIN_SOURCE_DIR/ngfwctl" /usr/local/bin/
fi

TUNE_PROFILE="${OPENNGFW_TUNE_PROFILE:-appliance}"
echo "[5/8] Host forwarding and throughput sysctls (${TUNE_PROFILE})"
/usr/local/bin/ngfwctl system tune --profile "$TUNE_PROFILE" --write --apply

echo "[6/8] Directories"
install -d -m 0700 /var/lib/openngfw /var/log/openngfw
install -d -m 0700 /etc/openngfw /etc/openngfw/secrets /etc/openngfw/keys

echo "[7/8] Local API users"
ADMIN_TOKEN_FILE="/etc/openngfw/admin.token"
if [[ ! -f /etc/openngfw/users.yaml ]]; then
  ADMIN_TOKEN="$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')"
  ADMIN_TOKEN_HASH="$(printf '%s' "$ADMIN_TOKEN" | sha256sum | awk '{print $1}')"
  cat > /etc/openngfw/users.yaml <<EOF
users:
  - name: admin
    token_hash: sha256:${ADMIN_TOKEN_HASH}
    role: admin
EOF
  install -m 0600 /dev/null "$ADMIN_TOKEN_FILE"
  printf '%s\n' "$ADMIN_TOKEN" > "$ADMIN_TOKEN_FILE"
  chmod 600 /etc/openngfw/users.yaml
  chmod 600 "$ADMIN_TOKEN_FILE"
  echo "    created /etc/openngfw/users.yaml"
  echo "    stored generated admin token in $ADMIN_TOKEN_FILE (mode 0600)"
  echo "    retrieve with: sudo cat $ADMIN_TOKEN_FILE"
  echo '    export for the test plan: export NGFW_TOKEN="$(sudo cat /etc/openngfw/admin.token)"'
else
  echo "    /etc/openngfw/users.yaml already exists; leaving local API users unchanged"
  if [[ -f "$ADMIN_TOKEN_FILE" ]]; then
    echo "    admin token file: $ADMIN_TOKEN_FILE"
  else
    echo "    no admin token file was written because /etc/openngfw/users.yaml already existed"
  fi
fi

echo "[8/8] systemd unit"
install -m 0644 "$REPO_ROOT/deploy/systemd/controld.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable controld
systemctl restart controld

echo
echo "OpenNGFW installed. Verify with:"
echo "  systemctl status controld"
echo "  ngfwctl version --remote"
if [[ $FAMILY == el ]]; then
  echo "Next: docs/testing-plan-ol9.md"
else
  echo "Next: docs/testing-plan.md"
fi
