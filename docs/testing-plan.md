# OpenNGFW — Oracle Cloud Deployment & Test Plan

This is the human field-test guide for the M1–M5 v1 implementation. It has
two parts: **deploying a test bench on OCI** and a **structured test plan**.

## What is already machine-verified vs. what needs you

Every commit runs unit + golden tests, and `make integration-test` proves
the following against **real engines and real traffic** (also in CI):

- M1: zone filtering, default-drop, DNAT, SNAT, static routes, atomic
  commit, rollback both directions, failed-commit safety, audit
  completeness, kernel ruleset = committed policy.
- M2: Suricata (detect mode) supervised by the commit path detects a
  custom signature in live forwarded traffic; alerts surface via API/CLI.
- M4: an HTTP blocklist feed is enforced in nftables, blocks live
  traffic, toggles off via policy; the feed-license registry rejects a
  commercial deployment enabling `spamhaus-drop`.
- M5: token auth + RBAC enforced over gRPC and REST; audit records actors.
- Boot persistence: the running policy re-applies on daemon restart.
- Rendered configs are validated by the real engine parsers
  (`nft -c`, `suricata -T`, `vtysh -C`).

**What only you can test** (this container lacks kernel modules / second
hosts / systemd):

| # | Area | Why it needs you |
|---|---|---|
| A | **IPS prevent mode** (NFQUEUE inline drop) | needs `nfnetlink_queue` kernel support |
| B | **BGP peering** comes up and routes program | needs a live peer + systemd-run FRR |
| C | **IPsec tunnel** establishes and passes traffic | needs charon under systemd + a peer VM |
| D | **WireGuard handshake** and peer traffic | needs the WireGuard kernel module |
| E | **Vector → ClickHouse** pipeline | Vector not installable in the dev sandbox |
| F | **Web UI in a real browser** | rendered/tested only via curl here |
| G | **Reboot persistence on a real VM** | simulated only (daemon restart + table wipe) |
| H | **Sustained-load stability** (M2 DoD) | needs iperf3 across real NICs |

---

## Part 1 — Deploy the test bench on OCI

### 1.1 Topology

Three VMs in one VCN. The firewall VM routes between two subnets; the
client and server VMs send their traffic through it.

```
                  VCN 10.0.0.0/16
  ┌─────────────────────────────────────────────────────┐
  │  mgmt subnet 10.0.0.0/24  (public, SSH access)      │
  │     fw-mgmt VNIC: 10.0.0.10 (+ public IP)           │
  │                                                     │
  │  untrust subnet 10.0.1.0/24 (private)               │
  │     fw-untrust VNIC: 10.0.1.10                      │
  │     client VM:       10.0.1.20 (route via 10.0.1.10)│
  │                                                     │
  │  trust subnet 10.0.2.0/24 (private)                 │
  │     fw-trust VNIC:   10.0.2.10                      │
  │     server VM:       10.0.2.20 (route via 10.0.2.10)│
  └─────────────────────────────────────────────────────┘
```

### 1.2 OCI setup (console or Terraform)

1. **VCN** `ngfw-test` 10.0.0.0/16 with three subnets as above. mgmt is
   public (internet gateway); untrust/trust private.
2. **Security lists**: open *everything within the VCN* (10.0.0.0/16
   all protocols) on untrust/trust — the NGFW must be what filters, not
   OCI. On mgmt allow SSH (22) from your IP only.
3. **Firewall VM** `ngfw-fw`: Ubuntu 24.04, `VM.Standard.E5.Flex`
   (2 OCPU / 16 GB; A1.Flex works too). Primary VNIC in mgmt; attach two
   secondary VNICs (untrust, trust).
   **Critical:** on *all three* firewall VNICs enable **"Skip source/
   destination check"** — without it OCI drops forwarded packets.
4. **Client VM** `ngfw-client` (10.0.1.20) and **server VM**
   `ngfw-server` (10.0.2.20): Ubuntu 24.04, any small shape, primary
   VNIC in their subnet. Give each a secondary public IP or use the fw
   as a bastion for SSH.
5. **Subnet route tables** (this steers traffic through the NGFW):
   - untrust subnet RT: `10.0.2.0/24 → 10.0.1.10` (private-IP next hop)
   - trust subnet RT: `10.0.1.0/24 → 10.0.2.10`, `0.0.0.0/0 → 10.0.2.10`

### 1.3 Prepare the VMs

On **client** and **server** (the OCI route tables handle inter-subnet
steering; nothing special needed beyond tooling):

```sh
sudo apt-get update && sudo apt-get install -y netcat-openbsd iperf3 curl
# server only:
iperf3 -s -D
( while true; do echo pong | nc -l -p 8080 -q 0; done & )
```

On the **firewall VM**:

```sh
# Bring up the secondary VNICs (OCI doesn't auto-configure them):
#   find names with `ip link`; assume ens4=untrust ens5=trust
sudo ip addr add 10.0.1.10/24 dev ens4 && sudo ip link set ens4 up
sudo ip addr add 10.0.2.10/24 dev ens5 && sudo ip link set ens5 up
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-openngfw.conf

# Install Go (to build) and the stack:
sudo snap install go --classic
git clone https://github.com/DetailTech/oss-ngfw.git && cd oss-ngfw
make build
sudo deploy/install.sh        # engines + binaries + systemd + admin token
export NGFW_TOKEN=<token printed by the installer>

# Telemetry backend (ClickHouse in Docker):
sudo apt-get install -y docker.io docker-compose-v2
# IMPORTANT: Docker sets the legacy iptables FORWARD policy to DROP,
# which silently kills the firewall's *forwarded* traffic (both
# netfilter hooks must accept). Re-allow forwarding after install:
sudo iptables -P FORWARD ACCEPT
echo -e '[Service]\nExecStartPost=/usr/sbin/iptables -P FORWARD ACCEPT' | \
  sudo SYSTEMD_EDITOR=tee systemctl edit docker
sudo docker compose -f deploy/compose/docker-compose.yaml up -d
sudo docker compose -f deploy/compose/docker-compose.yaml exec -T clickhouse \
  clickhouse-client --multiquery < deploy/clickhouse/init.sql
```

Persist the VNIC config with netplan before the reboot test (T-OPS-2).

### 1.4 Baseline policy

Save as `policy.yaml` (adjust interface names to yours):

```yaml
zones:
  - name: untrust
    interfaces: [ens4]
  - name: trust
    interfaces: [ens5]
addresses:
  - name: untrust-net
    cidr: 10.0.1.0/24
  - name: trust-net
    cidr: 10.0.2.0/24
  - name: server
    cidr: 10.0.2.20/32
services:
  - name: echo
    protocol: PROTOCOL_TCP
    ports: [{ start: 8080 }]
  - name: iperf
    protocol: PROTOCOL_TCP
    ports: [{ start: 5201 }]
  - name: ping
    protocol: PROTOCOL_ICMP
rules:
  - name: client-to-server-echo
    from_zones: [untrust]
    to_zones: [trust]
    destination_addresses: [server]
    services: [echo, iperf, ping]
    action: ACTION_ALLOW
    log: true
```

```sh
ngfwctl policy set -f policy.yaml && ngfwctl policy validate && ngfwctl commit -m "baseline"
```

---

## Part 2 — Test plan

Conventions: run `ngfwctl …` on the firewall (with `NGFW_TOKEN` set),
`client$`/`server$` on those VMs. After each phase, skim `ngfwctl audit`.

### Phase 1 — Control loop & filtering (M1)

| ID | Action | Expect |
|----|--------|--------|
| T1.1 | `ngfwctl version --remote` | client + daemon versions |
| T1.2 | Commit baseline policy (above) | `committed version 1` |
| T1.3 | `client$ nc -z -w2 10.0.2.20 8080` | **succeeds** |
| T1.4 | `client$ nc -z -w2 10.0.2.20 22` | **times out** (default drop) |
| T1.5 | `server$ nc -z -w2 10.0.1.20 8080` | **times out** (no trust→untrust rule) |
| T1.6 | Edit policy: remove `echo` from services; set+commit | T1.3 now fails |
| T1.7 | `ngfwctl rollback 1` | T1.3 passes again |
| T1.8 | Set a policy with a typo'd zone name; `ngfwctl policy validate` | validation error names the rule and zone |
| T1.9 | `ngfwctl commit` after 1.8 | commit refused; `client$` traffic **unaffected** |
| T1.10 | Add SNAT (`to_zone: trust, masquerade: true` for untrust-net) + commit; `server$ sudo tcpdump -n port 8080` while client connects | server sees source **10.0.2.10** |
| T1.11 | Add DNAT: address `fw-untrust 10.0.1.10/32`, dnat echo `fw-untrust → server`; `client$ nc -z 10.0.1.10 8080` | reaches the server |
| T1.12 | Add static route `10.0.99.0/24 via 10.0.2.20` + commit; `ip route show 10.0.99.0/24` on fw | route present; remove + commit → gone |
| T1.13 | `ngfwctl versions` and `ngfwctl audit` | every step above present, with your username |
| T1.14 | `sudo nft list table inet openngfw` | rules carry `comment "rule:client-to-server-echo"` etc. |

### Phase 2 — IDS/IPS & telemetry (M2) — includes gaps A, E, H

| ID | Action | Expect |
|----|--------|--------|
| T2.1 | Add to policy: `ids: {enabled: true, mode: IDS_MODE_DETECT, home_networks: [10.0.0.0/16]}` + commit | `systemctl status controld` clean; `pgrep suricata` |
| T2.2 | `echo 'alert tcp any any -> any 8080 (msg:"TEST evil"; content:"EVILSTRING"; sid:9000001; rev:1;)' \| sudo tee /var/lib/openngfw/suricata/rules/local.rules`, re-commit | reload ok |
| T2.3 | `client$ echo EVILSTRING \| nc -w2 10.0.2.20 8080`; then `ngfwctl alerts` | alert sid 9000001, action `allowed` |
| T2.4 **(A)** | Change mode to `IDS_MODE_PREVENT` + commit; repeat T2.3 | connection **drops payload/resets**; alert action `blocked`; benign `pong` traffic still passes (fail-open: stop suricata → traffic flows) |
| T2.5 | `ngfwctl flows` after some traffic | flows listed with app labels (`http`, `tls` if you curl https sites via DNAT, etc.) |
| T2.6 **(E)** | Add `telemetry: {enabled: true}` + commit; generate traffic; `docker compose exec clickhouse clickhouse-client -q "SELECT count() FROM openngfw.events"` | counts grow; `openngfw.alerts` gets rows when T2.3 repeats |
| T2.7 **(H)** | `client$ iperf3 -c 10.0.2.20 -t 300` with IDS detect on | no suricata/controld crash; note (don't publish) the throughput |
| T2.8 | ET Open ruleset: `sudo suricata-update --no-test -o /var/lib/openngfw/suricata/rules` then list the produced file in `ids.rule_files` + commit; `client$ curl http://testmynids.org/uid/index.html` through the fw (needs SNAT/DNS or direct) | GPL-2102498-style alert appears in `ngfwctl alerts` |

### Phase 3 — Routing & VPN (M3) — gaps B, C, D

| ID | Action | Expect |
|----|--------|--------|
| T3.1 **(B)** | On server VM: `apt install frr`, enable bgpd, configure ASN 65002, neighbor 10.0.2.10 remote-as 65001, advertise `192.168.200.0/24`. On fw policy: `routing.bgp {enabled, asn: 65001, router_id: 10.0.2.10, neighbors: [{address: 10.0.2.20, remote_asn: 65002}], announce_networks: [10.0.1.0/24]}` + commit | `sudo vtysh -c 'show bgp summary'` shows Established; `ip route` has `192.168.200.0/24` via bgp |
| T3.2 **(B)** | Remove bgp from policy + commit | peering torn down; FRR daemons file restored to `bgpd=no` |
| T3.3 **(C)** | On client VM install strongswan as peer. On fw: create `/etc/openngfw/secrets/site-test.conf` (`secrets { ike-site-test { secret = "..." } }`), add the `vpn.ipsec_tunnels` block (see `docs/examples/policy-routing-vpn.yaml`) + commit | `sudo swanctl --list-sas` shows the SA; ping across the protected subnets works |
| T3.4 **(D)** | `wg genkey \| sudo tee /etc/openngfw/keys/wg0.key`; add `wireguard_interfaces` block with your laptop's pubkey + commit; configure laptop peer | `sudo wg show` lists the peer with a recent handshake; laptop pings 10.99.0.1 |
| T3.5 **(D)** | Remove the wireguard block + commit | `wg0` interface is gone |

### Phase 4 — Threat intel (M4)

| ID | Action | Expect |
|----|--------|--------|
| T4.1 | `ngfwctl intel feeds` | registry with license columns; spamhaus-drop shows `commercial-use:no` |
| T4.2 | Enable `feodo-tracker` in policy + commit; `ngfwctl intel refresh` | entry count > 0; `sudo nft list set inet openngfw intel4` populated |
| T4.3 | Policy with `commercial_use: true` **and** `spamhaus-drop` enabled; commit | **refused** with the license explanation |
| T4.4 | Custom feed: serve a file containing the client VM IP (`python3 -m http.server` on the server), add as `custom_feeds`, commit + refresh | client traffic through the fw is **dropped**; `ngfwctl audit`/nft counters confirm; remove + commit → restored |
| T4.5 | Wait/trigger a commit and re-run `nft list set …` | sets repopulate after commits (post-commit refresh hook) |

### Phase 5 — AuthN/Z & UI (M5) — gap F

| ID | Action | Expect |
|----|--------|--------|
| T5.1 | Add a `viewer` and an `operator` user to `/etc/openngfw/users.yaml`, restart controld | — |
| T5.2 | `NGFW_TOKEN=<viewer> ngfwctl versions` / `… commit` | read works; commit → `PermissionDenied` |
| T5.3 | `NGFW_TOKEN=<operator> ngfwctl commit -m x` (with a candidate) | works; `ngfwctl audit` shows the operator's **name** |
| T5.4 | No/garbage token | `Unauthenticated` on both gRPC and `curl http://127.0.0.1:8080/v1/policy` |
| T5.5 **(F)** | `ssh -L 8080:127.0.0.1:8080 ubuntu@<fw>` then browse `http://localhost:8080/ui/` | dashboard loads; paste a token; Policy/Versions/Audit/Alerts/Flows/Intel tabs all render real data |
| T5.6 | Check OIDC stance | it is scaffold-only by design (guardrail: needs human security review). Nothing to configure. |

### Phase 6 — Operational (gap G)

| ID | Action | Expect |
|----|--------|--------|
| T-OPS-1 | `sudo systemctl restart controld` | running policy + suricata return automatically (journal: "running policy re-applied at startup") |
| T-OPS-2 | `sudo reboot` the firewall VM (netplan must persist VNIC IPs!) | after boot: ruleset live, T1.3 passes with **no manual action** |
| T-OPS-3 | `sudo journalctl -u controld` | no silent failures; engine exits logged loudly |
| T-OPS-4 | Kill suricata manually (`sudo pkill -9 suricata`) | controld logs "engine process exited unexpectedly"; **note:** auto-restart is not implemented — re-commit to restart (known v1 limitation) |

### Known v1 limitations (expected findings, not bugs)

1. **Input chain is `accept`** — the firewall filters *forwarded* traffic;
   host-input hardening (self zone) is future work. Use OCI security
   lists + SSH-from-your-IP for the bench.
2. **API/UI have no TLS** and bind 127.0.0.1 — reach them via SSH tunnel.
3. Suricata/Vector run as controld children: a crashed engine is logged
   but not auto-restarted; a controld restart restarts everything.
4. Single shared candidate (no per-user candidates).
5. `et-block-ips`/`spamhaus` URLs may rate-limit; the refresh logs and
   keeps other feeds working.
6. Performance numbers from T2.7 are for your eyes — publishing any
   number requires the §8 benchmark harness (not built yet).

### Reporting

For each failed test, grab: the test ID, `ngfwctl audit` tail,
`sudo journalctl -u controld --since -10m`, and (if traffic-related)
`sudo nft list table inet openngfw`. Those four artifacts are enough to
diagnose almost anything in the commit path.
