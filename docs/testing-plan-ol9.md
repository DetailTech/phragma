# Phragma — Oracle Linux 9 Deployment & Test Plan (OCI)

Oracle Linux 9 variant of [`docs/testing-plan.md`](testing-plan.md). The
**test phases (Part 2 of the main plan) apply unchanged** — this document
replaces the deployment walkthrough, lists the EL9 command substitutions,
and adds OL9-specific tests. Read "What is already machine-verified vs.
what needs you" in the main plan first.

The main plan's M3 scope note applies unchanged on OL9: the automated M3
release gate covers static-route live forwarding, local FRR BGP netns
route programming, and the local WireGuard netns handshake/overlay-traffic
test, and its rootless `--check` mode verifies the manual IPsec evidence
template. External BGP peers, IPsec SA/protected-subnet traffic, and
external WireGuard client validation remain the manual Phase 3 field-test
work.

The v2 eBPF milestone also has an OL9-specific external gate:
`ebpf-ol9-field-evidence`. It proves host prerequisites, XDP/tc attach and
detach drills, `/v1/system/status` eBPF fields, the plan-only renderer
scaffold, cleanup, and continued `nftables/conntrack` production fallback. It
does not make eBPF the active dataplane.

> **Why OL9 differs from Ubuntu:** firewalld is enabled by default (it
> would fight the managed ruleset), SELinux is enforcing, the default
> kernel is UEK, several engines come from EPEL instead of the base
> repos, strongSwan's swanctl tree lives under `/etc/strongswan/`, the
> default user is `opc`, and `nc` is nmap's `ncat`. All of these are
> handled below; `deploy/install.sh` auto-detects EL9.

---

## Part 1 — Deploy the test bench on OCI (Oracle Linux 9)

### 1.1 Topology and OCI setup

Identical to the main plan §1.1–§1.2 (same VCN, subnets, route tables,
security lists), with two changes:

- Image: **Oracle Linux 9** (platform image) for all three VMs.
- SSH as **`opc`** instead of `ubuntu`.

Don't forget the two OCI-side requirements that cause silent failures:
**"Skip source/destination check" on all three firewall VNICs**, and the
private-IP route tables steering each subnet through the firewall.

### 1.2 Prepare the client and server VMs

```sh
sudo dnf install -y nmap-ncat iperf3 curl
# server only:
iperf3 -s -D
( while true; do echo pong | ncat -l 8080; done & )
```

If a client/server VM also runs firewalld (OL9 default), either open the
test ports or disable it on the *test* VMs — the bench must measure the
NGFW's filtering, not the endpoints':

```sh
sudo systemctl disable --now firewalld
```

### 1.3 Prepare the firewall VM

```sh
# --- Secondary VNICs (OCI doesn't auto-configure them) -----------------
# Find names with `ip link`; OL9 typically enumerates ens3=mgmt,
# ens5=untrust, ens6=trust (check yours). Use nmcli so it persists:
sudo nmcli con add type ethernet ifname ens5 con-name untrust \
  ipv4.method manual ipv4.addresses 10.0.1.10/24 ipv4.never-default yes
sudo nmcli con add type ethernet ifname ens6 con-name trust \
  ipv4.method manual ipv4.addresses 10.0.2.10/24 ipv4.never-default yes
sudo nmcli con up untrust && sudo nmcli con up trust

# --- Build and install the stack ---------------------------------------
sudo dnf install -y git make          # deploy/install.sh installs Go if needed
git clone https://github.com/DetailTech/oss-ngfw.git && cd oss-ngfw
sudo deploy/install.sh   # detects EL9: EPEL, engines, firewalld off,
                         # strongswan service, binaries, unit, token file
export NGFW_TOKEN="$(sudo cat /etc/openngfw/admin.token)"
sudo make e2e-install RUN_INSTALL=0
```

New installs keep `/etc/openngfw/users.yaml` digest-only with
`token_hash: sha256:<digest>` entries. Use `NGFW_TOKEN_FILE` or
`ngfwctl --token-file` when the token file is readable by the operator process;
use `NGFW_TOKEN` only when a field-test command explicitly needs the exported
token value.

If Vector is not already installed, `deploy/install.sh` warns and continues.
Install Vector through an approved package manager or pinned release before
running telemetry export tests.

The installer **disables firewalld** on this VM by design — Phragma owns
the host's packet filtering, and firewalld's own nftables tables would
filter the same hooks. It also installs `/etc/sysctl.d/99-openngfw.conf`
and applies the appliance forwarding/conntrack baseline; `ngfwctl status`
and the WebUI Readiness page report whether those kernel settings are live.
If this host drifts after install, `sudo ngfwctl system tune --write --apply`
reinstalls and applies the same baseline without rerunning the installer.

### 1.4 Telemetry backend (ClickHouse via podman)

OL9 ships podman, which (unlike Docker) does not flip the iptables
FORWARD policy to DROP — the Docker warning in the Ubuntu plan does not
apply here.

```sh
sudo dnf install -y podman
sudo podman run -d --name clickhouse --restart=always \
  -p 127.0.0.1:8123:8123 -p 127.0.0.1:9000:9000 \
  -v clickhouse-data:/var/lib/clickhouse \
  docker.io/clickhouse/clickhouse-server:24.8
sudo podman exec -i clickhouse clickhouse-client --multiquery \
  < deploy/clickhouse/init.sql
# Make it survive reboots:
sudo podman generate systemd --new --name clickhouse \
  | sudo tee /etc/systemd/system/clickhouse.service >/dev/null
sudo systemctl daemon-reload && sudo systemctl enable clickhouse
```

### 1.5 SELinux note (read before filing bugs)

OL9 enforces SELinux. controld runs from systemd as root and execs the
engines, but the packaged unit also applies a systemd sandbox: the root
filesystem is read-only except `/var/lib/openngfw`, `/var/log/openngfw`,
`/etc/openngfw`, and native FRR/swanctl drop-in directories, and home
directories are hidden. If an engine action fails with a *permission* error
that does not reproduce with `sudo setenforce 0`, capture the denial and
re-enable enforcing:

```sh
sudo ausearch -m avc -ts recent     # collect this output for the report
sudo setenforce 1
```

Leaving SELinux permissive is acceptable **for this bench only**; a
proper policy module is future hardening work.

### 1.6 Baseline policy

Same as main plan §1.4 — only the interface names change (`ens5`/`ens6`
instead of `ens4`/`ens5`).

---

## Part 2 — Test plan

**Run every phase of the main plan's Part 2** (`docs/testing-plan.md`),
applying these substitutions:

| Ubuntu plan says | On OL9 use |
|---|---|
| `nc -z -w2 HOST PORT` | `ncat -z -w2 HOST PORT` (or `timeout 2 bash -c '</dev/tcp/HOST/PORT'`) |
| `echo X \| nc -w2 HOST PORT` | `echo X \| ncat -w2 HOST PORT` |
| `nc -l -p 8080 -q 0` (server loop) | `ncat -l 8080` |
| `apt-get install …` | `dnf install …` (Suricata/strongSwan/wireguard-tools come from EPEL; on Oracle Linux, enable `ol9_developer_EPEL` for those packages) |
| `suricata-update -o …` | same command (`sudo dnf install -y python3-suricata-update` if missing) |
| netplan persistence (T-OPS-2) | already persistent via the `nmcli con add` profiles from §1.3 |
| Docker FORWARD-policy warning | not applicable (podman) |
| `/etc/swanctl/conf.d` (T3.3) | `/etc/strongswan/swanctl/conf.d` — controld auto-detects this; just know where to look |
| client peer install (T3.3) | `sudo dnf install -y oracle-epel-release-el9 && sudo dnf install -y --enablerepo=ol9_developer_EPEL strongswan` |
| FRR daemons file | same path `/etc/frr/daemons`; service name `frr` — unchanged |

Phase 7 (jumbo frames / SR-IOV) applies unchanged — `ethtool` is
installed by the installer, and OL9's `nmcli` profiles from §1.3 don't
fight the managed MTU (the netdev engine re-applies it on every commit
and at boot).

### OL9-specific additions

| ID | Action | Expect |
|----|--------|--------|
| T-OL9-1 | `systemctl is-enabled firewalld` after install | `disabled` — and `sudo nft list tables` shows **no** firewalld tables alongside `inet openngfw` |
| T-OL9-2 | `getenforce` | `Enforcing`, and the full Phase 1–5 run completes without `ausearch -m avc -ts recent` showing openngfw-related denials |
| T-OL9-3 | `sudo modprobe nfnetlink_queue && lsmod \| grep nfnetlink_queue` before T2.4 (IPS prevent) | module loads on UEK — then T2.4 runs as written |
| T-OL9-4 | `sudo modprobe wireguard` before T3.4 | module loads on UEK — then T3.4 runs as written |
| T-OL9-5 | `sudo swanctl --version` and `systemctl is-active strongswan` before T3.3 | swanctl present (EPEL build), charon running; then collect the T3.3 bundle with `sudo swanctl --list-conns`, `sudo swanctl --list-sas`, `sudo swanctl --list-pols`, `sudo ip xfrm state`, `sudo ip xfrm policy`, and protected-subnet `ping -c 3` output before claiming IPsec validation |
| T-OL9-6 | Reboot test (T-OPS-2) | nmcli profiles restore the VNIC IPs, clickhouse.service and controld come back, ruleset live with no manual action |
| T-OL9-7 | Run `make ebpf-ol9-attach-drill-check`, then on an OL9/OCI root host run `sudo -E EBPF_OL9_ATTACH_IFACE=<disposable-interface> EBPF_OL9_STATUS_JSON_COMMAND='<command that prints /v1/system/status eBPF JSON>' make ebpf-ol9-attach-drill`. Collect `release/field-evidence/ebpf-ol9`, including `host/kernel-btf.txt`, `host/bpffs.txt`, `host/cgroup-v2.txt`, `host/link-inventory.txt`, `ngfwctl status`, `GET /v1/system/status` eBPF JSON, `renderer/ebpf-plan.txt`, `drill/manifest.txt` with probe hashes, XDP and tc attach/detach command logs, `bpftool prog show`, and cleanup proof | `make ebpf-ol9-field-evidence-check EBPF_OL9_FIELD_EVIDENCE_DIR=release/field-evidence/ebpf-ol9` prints `status=passed`, `required_ebpf_prereqs=bpftool,clang,tc,ip,kernel-btf,bpffs,cgroup-v2,link-inventory`, `required_drill_evidence=drill-manifest,probe-source-sha256,probe-object-sha256,attach-detach-command-records`, `active_dataplane=nftables/conntrack`, `ebpf_renderer_state=planned`, `xdp_attach_result=passed`, `tc_attach_result=passed`, and redaction sentinels |

### Reporting

Same artifacts as the main plan, plus `ausearch -m avc -ts recent` output
for anything that smells like a permission problem, and `uname -r` (UEK
vs RHCK kernel) for anything involving NFQUEUE or WireGuard.
