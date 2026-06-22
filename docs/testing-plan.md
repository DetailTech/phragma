# Phragma — Oracle Cloud Deployment & Test Plan

This is the human field-test guide for the M1–M5 v1 implementation. It has
two parts: **deploying a test bench on OCI** and a **structured test plan**.
This walkthrough targets Ubuntu 24.04; for Oracle Linux 9 use
[`docs/testing-plan-ol9.md`](testing-plan-ol9.md) (same test phases,
EL9-specific deployment and command substitutions).

## What is already machine-verified vs. what needs you

Every commit runs unit + golden tests, and `make integration-test` proves
the following against **real engines and real traffic** (also in CI):

- M1: zone filtering, default-drop, DNAT, SNAT, static routes, atomic
  commit, rollback both directions, failed-commit safety, audit
  completeness, kernel ruleset = committed policy.
- M2: Suricata (detect mode) supervised by the commit path detects a
  custom signature in live forwarded traffic; alerts surface via API/CLI.
- M3 release gate: `release/m3-live-networking.sh --check|--run`
  currently proves policy-managed static-route programming changes live
  forwarding across network namespaces, policy-managed FRR BGP can learn
  a route from a local netns FRR peer and program the kernel route table,
  and policy-managed WireGuard interface creation can handshake with a
  netns peer and pass overlay TCP traffic. The rootless `--check` mode
  also verifies that the IPsec manual evidence template below remains
  present. It does not prove external BGP peers, IPsec SAs/traffic, or
  external WireGuard client deployments.
- M3 external field evidence: `release/m3-field-evidence.sh --evidence-dir
  <dir>` validates the redacted files captured from external BGP, IPsec, and
  WireGuard field tests before those files can be recorded as release
  evidence. It validates evidence shape and key output markers; it does not run
  the peers or tunnels itself.
- M4: an HTTP blocklist feed is enforced in nftables, blocks live
  traffic, toggles off via policy; the feed-license registry rejects a
  commercial deployment enabling `spamhaus-drop`.
- Content package mechanics: `make content-package-smoke` creates signed demo
  App-ID, Threat-ID, and intel-feed packages, verifies package controls,
  rejects failed-regression content, and proves rollback mechanics. This is
  demo-only package verification; it does not prove production
  `content_readiness.production_ready`.
- Production content readiness:
  `release/content-production-readiness.sh --evidence-dir <dir>` validates the
  release-local signed App-ID, Threat-ID, and intel-feed evidence bundle before
  it can be recorded as `content-production-readiness` release evidence. It
  validates each kind's `status.json`, exact
  `required_production_evidence`, referenced `evidence/*.json` SHA-256 values,
  timestamps, and sentinel output; it does not create the content corpus or
  license/rollout/rollback proof itself. It does not consume separate
  `package-status.json` or `manifest.json` inputs for this release gate.
- M5: token auth + RBAC enforced over gRPC and REST; audit records actors.
- M5 OIDC provider field evidence:
  `release/oidc-field-evidence.sh --evidence-dir <dir>` validates the redacted
  files captured from a real provider-backed browser SSO run before those files
  can be recorded as `m5-oidc-field-evidence` release evidence. It validates
  evidence shape and sentinel output; it does not run the IdP or browser flow
  itself.
- M5 SAML provider field evidence:
  `release/saml-field-evidence.sh --evidence-dir <dir>` validates the redacted
  files captured from a real SAML provider-backed browser SSO run before those
  files can be recorded as `m5-saml-field-evidence` release evidence. It
  validates evidence shape and sentinel output; it does not run the IdP or
  browser flow itself.
- Boot persistence: the running policy re-applies on daemon restart.
- Rendered configs are validated by the real engine parsers
  (`nft -c`, `suricata -T`, `vtysh -C`) where available; parser evidence
  is not live external FRR/IPsec peer or tunnel evidence. BGP and
  WireGuard release evidence use local netns peers rather than external
  field paths.
- Packet capture: `StartPacketCapture` drives real `tcpdump` on Linux,
  captures generated traffic into a bounded pcap, and records audit.

**What only you can test** (this container lacks kernel modules / second
hosts / systemd):

Passing `release/m3-live-networking.sh --run` does not close the external
BGP, IPsec, or external WireGuard field gaps below; it supplies automated
static-route live-forwarding evidence, a local FRR BGP netns route-
programming check, and a local WireGuard netns handshake/overlay-traffic
check.

Production content readiness is also outside `make release-check-rootless`.
Collect the release-local bundle as
`release/field-evidence/content-production/<kind>/status.json` plus
`evidence/*.json` for `app-id`, `threat-id`, and `intel-feeds`; do not add
separate `package-status.json` or `manifest.json` inputs for this gate.
Validate and record it with the Makefile targets:

```sh
make content-production-readiness-check \
  CONTENT_PRODUCTION_EVIDENCE_DIR=release/field-evidence/content-production

COMMIT="$(git rev-parse HEAD)" make release-evidence-content-production-readiness \
  CONTENT_PRODUCTION_EVIDENCE_DIR=release/field-evidence/content-production
```

The recorded stdout must include:

```text
check=content-production-readiness
mode=check
content_production_scope=app-id,threat-id,intel-feeds
required_content_kinds=app-id,threat-id,intel-feeds
required_app_id_evidence=app-taxonomy,confidence-model,app-regression-corpus,license-review,staged-rollout,rollback-drill
required_threat_id_evidence=threat-taxonomy,pcap-regression-corpus,false-positive-regression,license-review,staged-rollout,rollback-drill
required_intel_feeds_evidence=feed-registry,parser-tests,license-review,false-positive-regression,staged-rollout,rollback-drill
content_readiness=production_content=true,production_ready=true
status=passed
```

| # | Area | Why it needs you |
|---|---|---|
| A | **IPS prevent mode** (NFQUEUE inline drop) | needs `nfnetlink_queue` kernel support |
| B | **External BGP peering** comes up and routes program | automated netns coverage exists; still needs a real peer + service-managed FRR field path |
| C | **IPsec tunnel** establishes and passes traffic | needs charon under systemd + a peer VM |
| D | **External WireGuard client** handshake and peer traffic | automated netns coverage exists; a laptop or second host still needs field validation |
| E | **Vector → ClickHouse** pipeline | Vector not installable in the dev sandbox |
| F | **Web UI in a real browser** | rendered/tested only via curl here |
| G | **Reboot persistence on a real VM** | simulated only (daemon restart + table wipe) |
| H | **Sustained-load stability** (M2 DoD) | needs iperf3 across real NICs |
| I | **Provider-backed OIDC browser SSO** | needs a real IdP tenant/client, public HTTPS callback, browser session, and deployment proxy posture |
| J | **Production App-ID / Threat-ID / intel-feed readiness** | needs signed production packages plus taxonomy, regression, license, staged-rollout, and rollback evidence for all three package kinds |

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

# Install the stack. deploy/install.sh installs Go/make if it must build
# from source and no prebuilt bin/ artifacts are present.
sudo apt-get install -y git make
git clone https://github.com/DetailTech/oss-ngfw.git && cd oss-ngfw
sudo deploy/install.sh        # engines + binaries + systemd + root-readable admin token file
export NGFW_TOKEN="$(sudo cat /etc/openngfw/admin.token)"
sudo make e2e-install RUN_INSTALL=0

# If Vector is not already installed, deploy/install.sh warns and continues.
# Install Vector through an approved package manager or pinned release before
# running telemetry export tests.

# deploy/install.sh installs /etc/sysctl.d/99-openngfw.conf and applies the
# appliance forwarding/conntrack baseline. ngfwctl status and the WebUI
# Readiness page report whether those kernel settings are live.

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
ngfwctl policy set -f policy.yaml && ngfwctl policy validate && ngfwctl commit --ack-risk -m "baseline"
```

`ngfwctl commit` and `ngfwctl rollback` require `--message/-m`; the comment is
stored with the created version and audit entry. If the CLI reports dry-run,
degraded host posture, missing prerequisites, target dataplane readiness gaps,
or an unavailable status endpoint during commit or rollback preflight, resolve
the runtime issue or add `--ack-runtime` after reviewing the printed warnings.
High-risk policy impact requires `--ack-risk`; runtime readiness warnings
require `--ack-runtime`. The CLI sends those as API `ack_risk` and
`ack_runtime`, and direct API commit/rollback requests without the required
target-policy-aware acknowledgement are rejected before live apply.

---

## Part 2 — Test plan

Conventions: run `ngfwctl …` on the firewall (with `NGFW_TOKEN` set, or
`NGFW_TOKEN_FILE` pointing at an operator-readable secret file), `client$` and
`server$` on those VMs. `/etc/openngfw/users.yaml` should contain
`token_hash: sha256:<digest>` entries; generate a digest with
`printf '%s' "$TOKEN" | sha256sum | awk '{print $1}'` rather than writing new
plaintext `token:` values. After each phase, skim `ngfwctl audit`.

### Phase 1 — Control loop & filtering (M1)

| ID | Action | Expect |
|----|--------|--------|
| T1.1 | `ngfwctl version --remote` | client + daemon versions |
| T1.2 | Commit baseline policy (above) | `committed version 1` |
| T1.3 | `client$ nc -z -w2 10.0.2.20 8080` | **succeeds** |
| T1.4 | `client$ nc -z -w2 10.0.2.20 22` | **times out** (default drop) |
| T1.5 | `server$ nc -z -w2 10.0.1.20 8080` | **times out** (no trust→untrust rule) |
| T1.6 | Edit policy: remove `echo` from services; set+commit | T1.3 now fails |
| T1.7 | `ngfwctl rollback 1 --ack-risk -m "restore v1"`; add `--ack-runtime` only if runtime warnings are printed | rollback target validation, impact, and runtime posture are printed before apply; T1.3 passes again; `ngfwctl audit --action rollback --query "restore v1"` shows the audit comment |
| T1.8 | Set a policy with a typo'd zone name; `ngfwctl policy validate`; repeat headlessly with `curl -sk -H "Authorization: Bearer $NGFW_TOKEN" -H "Content-Type: application/json" -d '{}' https://127.0.0.1:8080/v1/candidate/validate` | validation error names the rule and zone; the API response keeps compatibility `errors[]` and includes structured `findings[]` with `VALIDATION_SEVERITY_ERROR` / `VALIDATION_STAGE_POLICY_MODEL` |
| T1.9 | `ngfwctl commit --ack-risk` after 1.8 | commit refused before live apply; `client$` traffic **unaffected** |
| T1.10 | Add SNAT (`to_zone: trust, masquerade: true` for untrust-net) + commit; `server$ sudo tcpdump -n port 8080` while client connects | server sees source **10.0.2.10** |
| T1.11 | Add DNAT: address `fw-untrust 10.0.1.10/32`, dnat echo `fw-untrust → server`; `client$ nc -z 10.0.1.10 8080` | reaches the server |
| T1.12 | Add static route `10.0.99.0/24 via 10.0.2.20` + commit; `ip route show 10.0.99.0/24` on fw | route present; remove + commit → gone |
| T1.13 | `ngfwctl versions` and `ngfwctl audit`; repeat `ngfwctl audit --action commit`, `ngfwctl audit --actor <user-fragment>`, `ngfwctl audit --version 1`, and `ngfwctl audit --query baseline` | every step above present, with your username, role, and auth source; filtered audit queries return only matching entries |
| T1.14 | `sudo nft list table inet openngfw`; then inspect `curl -sk -H "Authorization: Bearer $NGFW_TOKEN" https://127.0.0.1:8080/v1/system/status \| jq '.dataplane.counters[] \| select(.comment=="rule:client-to-server-echo")'` | rules carry `comment "rule:client-to-server-echo"` etc.; `/v1/system/status.dataplane.counters` aggregates matching packets/bytes by Phragma comment |
| T1.15 | Immediately after a successful T1.3 connection, run `ngfwctl sessions --ip 10.0.2.20 --protocol TCP --port 8080` and `curl -sk -H "Authorization: Bearer $NGFW_TOKEN" 'https://127.0.0.1:8080/v1/sessions?ip=10.0.2.20&protocol=TCP&port=8080'` | live conntrack session output is `ready` and shows the original/reply tuple, packets, bytes, timeout/flags, or `ready` with no rows if the short-lived connection expired before inspection |

### Phase 2 — IDS/IPS & telemetry (M2) — includes gaps A, E, H

| ID | Action | Expect |
|----|--------|--------|
| T2.1 | Add to policy: `ids: {enabled: true, mode: IDS_MODE_DETECT, home_networks: [10.0.0.0/16]}` + commit | `systemctl status controld` clean; `pgrep suricata` |
| T2.2 | `echo 'alert tcp any any -> any 8080 (msg:"TEST evil"; content:"EVILSTRING"; sid:9000001; rev:1;)' \| sudo tee /var/lib/openngfw/suricata/rules/local.rules`, re-commit | reload ok |
| T2.3 | `client$ echo EVILSTRING \| nc -w2 10.0.2.20 8080`; then `ngfwctl alerts --action allowed --signature-id 9000001 --query "TEST evil"` | only the matching sid 9000001 alert is returned, action `allowed` |
| T2.4 **(A)** | Change mode to `IDS_MODE_PREVENT`, set `failure_behavior: IDS_FAILURE_BEHAVIOR_FAIL_OPEN`, commit, repeat the EVILSTRING payload, then run `ngfwctl alerts --action blocked --signature-id 9000001 --query "TEST evil"` | connection **drops payload/resets**; only the matching blocked alert is returned; benign `pong` traffic still passes; stop Suricata → traffic bypasses and the explain output shows fail-open NFQUEUE behavior |
| T2.4b **(A)** | Change only `failure_behavior` to `IDS_FAILURE_BEHAVIOR_FAIL_CLOSED`, commit, stop Suricata, then retry benign traffic | traffic does **not** silently bypass; queue failure blocks/holds traffic and `sudo nft list table inet openngfw` shows the queue rule has no `bypass` flag |
| T2.5 | `ngfwctl flows --ip 10.0.2.20 --protocol TCP --app web --port 8080` after some HTTP-like or TCP/8080 traffic | only matching flows are listed with App-ID labels (`web-browsing`, `ssl` if you curl https sites via DNAT, etc.) |
| T2.5a | With IDS/App-ID flow logging disabled or before EVE flow records arrive, repeat the same traffic and run `ngfwctl sessions --ip 10.0.2.20 --protocol TCP --port 8080` | live sessions remain visible from conntrack even when `/v1/flows` has no historical inspection record |
| T2.5b | Add an `applications[]` object for `corp-admin` with TCP port 8443, commit, generate TCP/8443 traffic without an engine app signal, then run `ngfwctl flows --app corp-admin --port 8443` | the flow shows canonical App-ID `corp-admin`, the configured display/category metadata, confidence `65`, and evidence `custom Phragma port heuristic tcp/8443 -> corp-admin` |
| T2.5c | Add a top-of-policy `ACTION_DENY` rule with `applications: [corp-admin]` and no explicit `services`, validate, commit, then inspect `sudo nft list table inet openngfw` and generate TCP/8443 traffic. Repeat with a broad signal-only App-ID object using supported Suricata signal `http` while IDS/IPS is Prevent fail-closed. | validation accepts the deny-only App-ID rule, nftables renders the application's TCP/UDP port hints as concrete drop rules, and matching port-hint traffic is blocked. The broad signal-only rule renders a managed Suricata App-ID drop and nftables does not emit a broad rule drop. Changing the rule to `ACTION_ALLOW`, combining it with explicit services, scoping a signal-only rule, using an unsupported signal, or using signal-only App-ID without fail-closed IPS is rejected before commit |
| T2.5d | Generate one flow with an unmapped engine app signal, one TCP/443 flow with no engine signal, and one conflicting signal/port flow such as `app_proto=http` on TCP/443; then run `curl -sk -H "Authorization: Bearer $NGFW_TOKEN" 'https://127.0.0.1:8080/v1/app-id/observations?limit=100'` and `ngfwctl app-id observations --limit 100 --flow-limit 1000 --confidence-threshold 70` | observations include `UNKNOWN`, `LOW_CONFIDENCE`, and `CONFLICTING_EVIDENCE` queue items with stable `queueId`, evidence text, confidence, signal source, volume, suggested `Application`, `runningPolicyVersion`, `policyContext`, `scannedFlows`, App-ID package context, and effective confidence threshold; an unmapped signal on TCP/443 remains `unknown` instead of being promoted to `ssl`. CLI and API filters for kind, engine signal, protocol, port, time bounds, query, limit, flow limit, and threshold return the same queue slice |
| T2.6 **(E)** | Add `telemetry: {enabled: true}` + commit; generate traffic; `docker compose exec clickhouse clickhouse-client -q "SELECT count() FROM openngfw.events"` | counts grow; `openngfw.alerts` gets rows when T2.3 repeats |
| T2.7 **(H)** | `client$ iperf3 -c 10.0.2.20 -t 300` with IDS detect on | no suricata/controld crash; note (don't publish) the throughput |
| T2.8 | ET Open ruleset: `sudo suricata-update --no-test -o /var/lib/openngfw/suricata/rules` then list the produced file in `ids.rule_files` + commit; `client$ curl http://testmynids.org/uid/index.html` through the fw (needs SNAT/DNS or direct) | GPL-2102498-style alert appears in `ngfwctl alerts` |

### Phase 3 — Routing & VPN (M3) — gaps B, C, D

Automated release-gate scope: `release/m3-live-networking.sh --run`
selects `TestM3StaticRouteProgramsLiveForwarding`,
`TestM3BGPProgramsKernelRouteFromFRRPeer`, and
`TestM3WireGuardPolicyCreatesInterfaceAndPassesPeerTraffic` by default.
Treat a passing M3 gate as static-route forwarding, local FRR BGP netns,
and local WireGuard netns evidence only: the BGP test starts isolated
FRR `zebra`/`bgpd` daemons from temp config, learns a route from a peer
namespace, verifies the kernel route, and verifies withdrawal after policy
removal. The WireGuard test creates the managed interface from policy,
handshakes with a peer namespace over a veth underlay, passes TCP over the
tunnel, and verifies interface removal after policy withdrawal. `--check`
release-gates the T3.3 IPsec evidence template so IPsec cannot be claimed
from parser/config output alone. Complete T3.1/T3.2 before claiming an
external or service-managed BGP field path; complete T3.3 before claiming
IPsec SA and protected-subnet traffic validation; complete T3.4 when
claiming a real external WireGuard client path. For release evidence, copy the
captured outputs into `release/field-evidence/m3` and run
`make m3-field-evidence-check M3_FIELD_EVIDENCE_DIR=release/field-evidence/m3`
before `make release-evidence-m3-field-evidence`.

Required external evidence bundle:

```text
release/field-evidence/m3/
  bgp-external-peer/
    show-bgp-summary.txt
    ip-route-remote-prefix.txt
    frr-running-config.txt
  ipsec-strongswan-sa-traffic/
    swanctl-list-conns.txt
    swanctl-list-sas.txt
    swanctl-list-pols.txt
    ip-xfrm-state.txt
    ip-xfrm-policy.txt
    protected-subnet-ping.txt
  wireguard-external-client/
    wg-show.txt
    client-config-redacted.txt
    external-client-ping.txt
```

| ID | Action | Expect |
|----|--------|--------|
| T3.1 **(B)** | External field check: on server VM, `apt install frr`, enable bgpd, configure ASN 65002, neighbor 10.0.2.10 remote-as 65001, advertise `192.168.200.0/24`. On fw policy: `routing.bgp {enabled, asn: 65001, router_id: 10.0.2.10, neighbors: [{address: 10.0.2.20, remote_asn: 65002}], announce_networks: [10.0.1.0/24]}` + commit | `sudo vtysh -c 'show bgp summary'` shows Established; `ip route` has `192.168.200.0/24` via bgp |
| T3.2 **(B)** | Remove bgp from policy + commit | external peering is torn down and the learned kernel route is withdrawn; capture `sudo vtysh -c 'show bgp summary'`, `ip route show 192.168.200.0/24`, and the managed FRR config marker before claiming service-managed BGP cleanup |
| T3.3 **(C)** | Manual IPsec field evidence bundle: on client VM install strongSwan as peer. On fw: create `/etc/openngfw/secrets/site-test.conf` (`secrets { ike-site-test { secret = "..." } }`), add the `vpn.ipsec_tunnels` block (see `docs/examples/policy-routing-vpn.yaml`) + commit, then capture `sudo swanctl --list-conns`, `sudo swanctl --list-sas`, `sudo swanctl --list-pols`, `sudo ip xfrm state`, `sudo ip xfrm policy`, and `ping -c 3 <remote-protected-ip>` across the protected subnet. Redact PSK material and public IPs if needed, but keep tunnel names, selectors, SPI presence, and packet counters visible. | `sudo swanctl --list-sas` shows an established IKE/CHILD SA for the managed tunnel; `sudo swanctl --list-pols` and `sudo ip xfrm policy` show the expected local/remote traffic selectors; `sudo ip xfrm state` shows installed state with SPIs; protected-subnet ping succeeds. Do not claim IPsec validation from rendered `swanctl.conf`, secret-file existence, or `swanctl --load-all` success alone. |
| T3.4 **(D)** | For an external-client field test, `wg genkey \| sudo tee /etc/openngfw/keys/wg0.key`; add `wireguard_interfaces` block with your laptop's pubkey + commit; configure laptop peer; open the WebUI tunnel handoff drawer, pin the tunnel evidence to Investigation, and export the handoff | `sudo wg show` lists the peer with a recent handshake; laptop pings 10.99.0.1; pinned VPN evidence is stored as local Investigation `vpn-tunnel` evidence without exporting key or PSK file paths |
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
| T5.1 | Add a `viewer` and an `operator` user to `/etc/openngfw/users.yaml` using `token_hash: sha256:<digest>` entries, restart controld | hashed users load without exposing plaintext tokens in the users file |
| T5.2 | `NGFW_TOKEN=<viewer> ngfwctl versions` / `… commit` | read works; commit → `PermissionDenied` |
| T5.3 | `NGFW_TOKEN=<operator> ngfwctl commit --ack-risk -m x` (with a high-risk candidate); repeat with controld in dry-run mode or a warning posture and then add `--ack-runtime` | validation impact and runtime posture are printed before apply; high-risk impact requires `--ack-risk`; dry-run/degraded/unknown runtime requires `--ack-runtime`; `ngfwctl audit` shows the operator's **name**, **role**, and local users-file auth source |
| T5.3a | Run `ngfwctl commit --ack-risk` and `ngfwctl rollback 1 --ack-risk` without `-m` | both commands fail before dialing/apply with an audit-comment-required error |
| T5.4 | No/garbage token | `Unauthenticated` on both gRPC and `curl -k https://127.0.0.1:8080/v1/policy` |
| T5.5 **(F)** | `ssh -L 8080:127.0.0.1:8080 ubuntu@<fw>` then browse `https://localhost:8080/ui/` (accept the self-signed cert warning). After staging a candidate, click **Validate**, then repeat the status, validation, and diff headlessly with `curl -sk -H "Authorization: Bearer $NGFW_TOKEN" https://127.0.0.1:8080/v1/candidate/status`, `curl -sk -H "Authorization: Bearer $NGFW_TOKEN" -H "Content-Type: application/json" -d '{}' https://127.0.0.1:8080/v1/candidate/validate`, and `curl -sk -H "Authorization: Bearer $NGFW_TOKEN" 'https://127.0.0.1:8080/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE'`. | dashboard loads with live charts and policy counters; ⌘K command palette works; Rules/Objects editing stages a candidate (yellow bar) → Validate → Commit records a version; Validate shows structured findings and the render artifact plan; the status response reports `dirty=true`, the running baseline version, section-level candidate changes, and impact; the validation response includes `findings[]`, `impact`, and `renderPlan.artifacts[]`; the diff response reports a stable typed diff with `changed=true`; Troubleshoot shows the exact policy source/version returned by `/v1/explain/flow`; when **Include live runtime evidence** is selected or Traffic pivots into Troubleshoot, the response includes `runtimeEvidence` with live conntrack state, running policy context, and matching sessions without changing the policy-model verdict; `ngfwctl explain --runtime ...` shows the same runtime evidence. Threats "drop this source" and Traffic "rule from flow/session" plus "App-ID from flow/session" pivots stage candidate changes; Changes shows version diff + rollback review |
| T5.5b **(F)** | Confirm TLS: first run generated `<data-dir>/tls/{cert,key}.pem`; `curl http://127.0.0.1:8080/ui/` is refused (HTTPS only). Inspect `curl -skI https://127.0.0.1:8080/ui/` for `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `Referrer-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, and `Permissions-Policy`. To use your own cert pass `--tls-cert/--tls-key`; `--tls=false` reverts to loopback-only cleartext for debugging and omits HSTS | self-signed HTTPS by default; browser security headers are present on TLS responses |
| T5.5c **(F)** | In Rules, confirm the running-hit column reflects `/v1/system/status.dataplane.counters` and that `/v1/system/status.dataplane.runningPolicyVersion` matches the committed policy. Then create or edit a rule with tags such as `env:prod`, `owner:secops`, and `pci.zone-1`; verify search and the tag filter find that rule; try invalid tags with uppercase or spaces. Next use Flow check to evaluate a denied tuple, pin the explain result to Investigation, click "Stage allow rule", validate, inspect the candidate diff, then discard or commit in a lab. In the rule editor, try App-ID refs with `ACTION_ALLOW`, with explicit services, with a supported broad signal-only application under IDS/IPS Prevent fail-closed, and with unsupported/scoped signal-only attempts | Rule hit cells show running nftables packet/byte counters when available and label the running policy version those counters describe; Dashboard policy counters and `ngfwctl status` show the same counter policy version. Rule tags persist as `rules[].tags`, are visible in the table, participate in search, populate the tag filter, and invalid or duplicate tags are blocked in the UI and rejected by server validation. Flow check pinning creates local Investigation explain evidence without mutating candidate or running policy. UI creates/reuses source/destination address objects and a service object, inserts a rule at the useful position, stages only the candidate, and validation explains any missing fields before commit. The rule editor disables staging and explains the App-ID guardrail before a server validation round trip for allow-by-App-ID, service+application, scoped signal-only, unsupported-signal, and non-fail-closed signal-only attempts while allowing the supported broad Suricata signal-only deny path |
| T5.5c-2 **(F)** | In Rules, create a discardable candidate with a broad active allow above a narrower rule, duplicate one rule name, an active no-log rule, partially overlapping allow/deny rules, and an unused address/service/App-ID object; inspect a committed rule with zero running-hit counters. Add one rule, modify one rule, reorder one rule, and remove one committed rule. Switch to compact density, group by tag, select one group header, toggle `Changed only`, apply Log on or Add tag from the bulk toolbar, click **Review logging** from the Missing logs cleanup finding, validate, inspect candidate diff, then discard | The cleanup queue summarizes shadowed rules, duplicate names, broad active allows, and zero-hit running rules; each concrete chip filters and can select the affected rule set without mutating the candidate, and missing-log remediation opens the reviewed bulk drawer with selected/visible/will-change/no-op counts before staging. Rule rows show staged candidate deltas as `added`, `modified`, or `moved`; removed running rules remain visible in the operations summary; `Changed only` filters to added/modified/moved candidate rows and pauses drag reorder. Grouped Rules views are review lenses: group-header selection targets only visible rules in that group, drag reorder is paused, bulk actions stage individual candidate rule changes through the existing candidate path, and selection clears after mutation. Validate/Review also surfaces shadowed-rule and active broad-allow impact items plus structured validation findings for missing logs, unused objects, and partial overlaps from the server-side candidate analysis. The commit drawer shows the full impact/finding list in bounded review panes |
| T5.5d **(F)** | Start from an empty policy. In Guided setup choose High-throughput edge, IDS detect, and IPS prevent in separate discardable candidates; assign inside/outside interfaces from the live interface inventory when `/v1/system/status.host.interfaces` is available, verify duplicate or missing assignments are blocked, inspect host-preparation baseline and throughput headroom, apply appliance or throughput tuning only on an enforcing lab host, enter inside CIDR, stage, validate, inspect the candidate diff, then discard or commit in a lab. Repeat headless with `ngfwctl policy baseline --profile throughput --inside-interface ens5 --outside-interface ens4 --inside-cidr 10.0.2.0/24`, `ngfwctl policy baseline --profile ids-detect ...`, `ngfwctl policy baseline --profile ips-prevent --ids-failure-behavior fail-closed ...`, `ngfwctl policy validate`, `ngfwctl policy diff`, and `ngfwctl commit --ack-risk -m "initial baseline"` plus `--ack-runtime` only if runtime warnings are printed. | UI and CLI stage zones, inside address object, SSH/WebUI service objects, logged outbound allow, optional masquerade SNAT, host-input default deny with management allow, selected network fast-path settings, and selected IDS/IPS settings without mutating running policy. Guided setup keeps manual interface entry available when status is unavailable, but status-aware setup warns on unknown/degraded host interfaces, disables host tuning in dry-run or when status is unavailable, and uses `/v1/system/tune` for acknowledged host-preparation mutations. All inspection postures keep flowtable acceleration off when inspection is enabled |
| T5.5e **(F)** | In NAT, add source NAT masquerade for inside→outside. Then add destination NAT using inline-created public/internal host objects and an inline-created TCP/UDP service object, keep "Stage matching allow rule" enabled, select the target zone, validate, inspect candidate diff, run NAT path preview, copy the generated `#/nat?...&run=1` link, reload it in a new tab, open the same tuple in Troubleshoot, pin the preview to Investigation, export the handoff JSON, then discard or commit in a lab | UI stages the new objects, `nat.source`, `nat.destination`, and the translated-destination allow rule atomically without mutating running policy; validation explains missing or invalid object references before commit; the NAT preview URL replays the same running/candidate comparison, Troubleshoot receives the same tuple, the pinned Investigation item is available as `nat-path` evidence, and the exported handoff records the tuple, running result, candidate result, delta rows, route, and warnings |
| T5.5f **(F)** | With zone, address, service, and App-ID objects referenced by forwarded rules, host-input rules, source NAT entries, or destination NAT entries, open Policy → Objects and click the Usage chip for each object type. Pin one reference review to Investigation, copy/export the handoff JSON, and repeat headless with `curl -sk -H "Authorization: Bearer $NGFW_TOKEN" 'https://127.0.0.1:8080/v1/policy/object-references?source=POLICY_SOURCE_CANDIDATE&kind=POLICY_OBJECT_KIND_ADDRESS&name=web-server'`. Then try to delete a referenced object and cancel the confirmation. | Object rows show `Unused` or an exact candidate reference count from `/v1/policy/object-references`; the reference drawer lists the referencing policy item and field, including security rules, host-input rules, source NAT, and destination NAT. Pinning creates local Investigation object-reference evidence without mutating candidate or running policy. Delete confirmation shows the same references before staging the delete; cancel leaves the candidate unchanged |
| T5.5g **(F)** | In Changes, export the running policy, export a committed previous version from the version-history row, import one of those JSON envelopes, inspect the import preview, then stage it to the candidate, validate, inspect the diff, and discard | Running and version exports download `phragma.policy.export.v1` JSON envelopes with `phragma-...json` filenames; version exports identify `source: "version"` and the selected version number; import also accepts legacy `openngfw.policy.export.v1` envelopes, rejects malformed or unsafe JSON, validates the unstaged policy through `POST /v1/candidate/validate`, shows validation, impact, and diff before candidate replacement, then replaces only the candidate after **Stage import**; running policy is unchanged until the normal commit path is used |
| T5.5g-2 **(F)** | In Changes, choose a previous version and click Roll back. Inspect the rollback review, enter an audit comment, acknowledge risk if requested, then apply in a lab | Rollback validates the historical policy through `POST /v1/candidate/validate` without replacing the candidate, shows impact, runtime readiness, and running→target diff, requires a comment, then calls `/v1/rollback`; audit and version history preserve the operator comment |
| T5.5h **(F)** | In Readiness, click "Export support bundle"; then call `/v1/system/support-bundle?versionLimit=100&auditLimit=300&eventLimit=500`; then run `ngfwctl support-bundle --output-dir /tmp` and inspect both JSON artifacts. Repeat on a fresh appliance before the first commit. | UI/API and CLI bundles have schema `phragma.support.bundle.v1`; file exports use `phragma-support-...json` generated filenames; bundles include runtime status, dedicated active/passive HA status, passive telemetry export status, identity, running policy, candidate policy, candidate dirty-state/section changes, candidate validation/impact, versions, audit, recent alerts/flows, live sessions, feed posture, content package posture, release acceptance status, and a summary with conntrack state-table pressure, running-policy state, candidate staged-state, candidate validation state, candidate impact, session/flow/alert/feed counts, telemetry export state/vector/sink evidence counts, content package blocker counts, release acceptance check counts, and release evidence recordability counts. `ngfwctl support-bundle -o <path>` is an explicit path override rather than generated-name mode. No staged candidate records empty candidate/validation objects, and no running policy records `runningPolicyVersion: "none"` rather than an endpoint failure; release recordability is advisory checkout preflight metadata only and does not mark a check clear; telemetry export status is passive and does not send test events or dial receivers; no policy mutation, commit, rollback, token exposure, or plaintext token/password/secret/authorization/cookie/API-key/private-key/PSK field exposure occurs; URL userinfo and sensitive URL query values are also replaced with `[redacted]` |
| T5.5h-2 **(F)** | Run two lab nodes with active/passive HA flags, fresh peer heartbeat, and a peer token that can read `/v1/system/ha/status` plus `/v1/policy?source=POLICY_SOURCE_RUNNING`. From the passive node, use Readiness → High availability → Pull policy, then repeat with `ngfwctl system ha pull-policy --ack-pull --ack-risk --ack-runtime -m "replicate from active"` and `POST /v1/system/ha/policy:pull`. Repeat with a dirty local candidate, stale heartbeat, active local role, same-role peer, and peer version not newer than local. | Passive pull refuses unsafe states before policy fetch when possible; success fetches the active peer running policy, validates/renders it locally, records `ha-policy-pull-intent` and `ha-policy-pull` audit entries, applies through the normal durable policy path, clears the candidate, records `sourceVersion` as the peer running version, updates running/LKG metadata, and reports before/after HA status. Active, standalone, stale, same-role, older/equal peer version, missing ack, missing comment, and dirty-candidate cases return failed preconditions without direct store mutation. |
| T5.5i **(F)** | In Changes → Audit log, filter by action, actor, version, time window, and text search. Confirm action choices include policy, host tuning, packet capture, and content package lifecycle actions. | table refreshes from `/v1/audit` server-side filters; Reset restores the latest audit entries without mutating policy; the action dropdown can directly select privileged operational mutations such as `commit-intent`, `rollback-intent`, `system-tune`, `packet-capture`, `content-package-install-intent`, `content-package-install`, `content-package-rollback-intent`, and `content-package-rollback` |
| T5.5i-2 **(F)** | From Dashboard, Rules, Traffic, Troubleshoot, Intel, Readiness, Changes, and Settings, open the topbar **API / CLI context** drawer or the command-palette action. Copy at least one REST `curl` command and one `ngfwctl` command from each representative route. Repeat from `#/settings?panel=network` and `#/settings?panel=telemetry`. | The drawer is route-aware, uses Phragma product branding, lists only public `/v1/...` REST endpoints, shows visible selectable `curl` examples using the current browser origin, supports `NGFW_TOKEN_FILE` as well as `NGFW_TOKEN`, shows matching `ngfwctl` equivalents, and keeps mutating actions on the candidate/validated/audited API path. Troubleshoot includes explain plus packet-capture plan/start/retain/release, Intel includes content package preview/install/rollback with source paths described as server-local directories under `<data-dir>/content-import`, Changes includes rollback/version/audit, Readiness includes status/telemetry-export-status/tuning/support-bundle/HA policy pull equivalents and routes network/auth release follow-ups to `#/settings?panel=network` or `#/settings?panel=access`, and Settings route state reports the current panel without adding form values or secrets; `panel=telemetry` includes both candidate policy and passive `/v1/system/telemetry/exports/status` handoff |
| T5.5j **(F)** | In Intel, add a custom HTTP(S) feed, set a refresh interval, validate, inspect candidate diff, then discard or commit and refresh in a lab. Repeat with URL userinfo such as `https://user:secret@...` and sensitive query parameters such as `access_token`, `api_key`, or `key` | UI stages `intel.custom_feeds` and `refresh_interval_minutes` through the candidate only; invalid names, duplicate feed names, built-in collisions, non-HTTP(S) URLs, URL userinfo, and sensitive URL query parameters are rejected before staging and by server validation |
| T5.5j-2 **(F)** | In Intel, inspect Content posture before and after staging a custom App-ID object, an IDS exception, and a commercial-use feed change in a discardable candidate; open `#/intel?surface=app-id&drawer=review`, `#/intel?surface=app-id&drawer=quality`, `#/intel?surface=threat-id&drawer=quality`, `#/intel?surface=threat-id&drawer=install`, and `#/intel?surface=intel-feeds&drawer=rollback`; pin, copy, and export at least one content package lifecycle handoff. Repeat with `ngfwctl intel content` and `curl -sk -H "Authorization: Bearer $NGFW_TOKEN" https://127.0.0.1:8080/v1/intel/content/packages`. On a lab host with signed fixture packages copied under the firewall server's configured content import directory, preview with `POST /v1/intel/content/packages/app-id/preview`, the Intel page, and `ngfwctl intel content preview app-id --source /var/lib/openngfw/content-import/app-id-package`; then install with the Intel page or `ngfwctl intel content install app-id --source /var/lib/openngfw/content-import/app-id-package`, install a second version, and roll back with `ngfwctl intel content rollback app-id --ack-rollback`. Finally run `ngfwctl audit --action content-package-install-intent`, `ngfwctl audit --action content-package-install`, `ngfwctl audit --action content-package-rollback-intent`, `ngfwctl audit --action content-package-rollback`, and a rejected install with a tampered package. | content posture reports App-ID, Threat-ID, and intel-feed package status from `<data-dir>/content/*/manifest.json`, registry feed counts from effective candidate state, any commercial-use license conflict, and missing signed manifest/package version/regression/staged rollout/rollback controls without inventing package versions or signatures. Package quality drawers show package version, gate score, required evidence score, blockers, package gates, and required production evidence gates for App-ID taxonomy/confidence/regression, Threat-ID taxonomy/PCAP/false-positive regression, and intel-feed registry/parser evidence; sanitized URL, absolute-path, or type-only evidence refs remain missing until a package-local artifact and SHA-256 are attached. Attached required-evidence gates expose an Inspect action that calls `GET /v1/intel/content/packages/{kind}/evidence/{evidenceType}` and renders only bounded, valid, package-local JSON whose hash still matches the manifest reference. Package preview uses the configured server-side content import root, returns sanitized verification posture, does not promote files, does not mutate installed content, does not write lifecycle audit entries, and does not serialize operator-entered install source paths or raw server-local manifest/rollback paths into handoff packets. Package review/quality/install/rollback drawers normalize invalid hash state, clear hash state on close, and pin/export `phragma.investigation.handoff.v1` content-package-lifecycle packets with package kind, decision checks, blockers, version/hash/signature/provenance/regression/rollout/rollback status, and route metadata without operator-entered install source paths or raw server-local manifest/rollback paths. Install source paths are server-local directories under the configured content import directory, not browser uploads or operator-workstation paths. Install rejects unverified packages; first install reports no operational rollback backup, replacing a verified package creates one, and rollback restores the latest verified backup through the same API used by WebUI and CLI. Corrupt or untrusted rollback backups do not enable rollback. Intent audit entries are written before package files are promoted, so a broken audit chain blocks install/rollback before content changes. Success and rejection audit entries include actor, role, auth source, package kind, version or error, source path, and rollback path when applicable |
| T5.5k **(F)** | In Traffic, filter Flows by IP/protocol/app/port/time/search, then switch to Sessions and filter by IP/protocol/port/state/search. Open one flow detail and one session detail, then stage both an allow and a drop rule from observed tuples in separate discardable candidates. From a flow with an unmapped engine signal or a useful TCP/UDP destination port, click "App-ID", save the suggested custom application object, then repeat with "Save & drop"; validate, inspect candidate diff, then discard or commit in a lab | Flow rows refresh from `/v1/flows`; session rows refresh from `/v1/sessions`; flow/session views show query-time running policy version; flow detail shows App-ID confidence/evidence, EVE `flowId` when present, and exact event policy version when the telemetry event was stamped; session detail shows original/reply tuple, counters, timeout, flags, and raw conntrack record; allow/drop pivots create or reuse address/service objects, drop rules log matches and insert at the top; App-ID pivots stage only `applications[]` entries with engine aliases or TCP/UDP port hints and duplicate/invalid values are rejected before staging; "Save & drop" stages the App-ID object plus a top drop rule referencing it, scoped to the observed source/destination objects and relying only on TCP/UDP port hints the current renderer can enforce; all changes stage only to the candidate |
| T5.5k-2 **(F)** | In Traffic, switch to **App-ID queue**, filter by reason/signal/protocol/port/threshold/time/search, open an observation, click **Matching flows**, then return and click **Promote App-ID** and **Promote & drop** in separate discardable candidates. Also use Objects -> Applications -> **Review observations** and Intel -> App-ID package -> **Review observations**. Repeat the exact filter headlessly with `ngfwctl app-id observations --limit 100 --flow-limit 1000 --confidence-threshold 70 --kind unknown --engine-signal dns --protocol TCP --port 443`, then stage reviewed queue items with `ngfwctl app-id promote <queue-id> --reason "define custom App-ID"` and `ngfwctl app-id promote <queue-id> --drop --confirm-drop --reason "block repeated unknown app"`. | App-ID queue refreshes from `/v1/app-id/observations`, uses Phragma design-system status colors (`warn` for unknown/low confidence, `bad` for conflict, no green for reviewable state), shows evidence and suggested object fields in a drawer, Matching flows pivots back to server-side flow filters, promotion reuses the custom App-ID drawer, and all mutations stage only to candidate policy through `POST /v1/app-id/observations/{queueId}:stage`. The server re-derives the selected queue item from EVE plus the effective running App-ID taxonomy, records `stage-app-id-observation` audit detail, returns candidate status, validation, and running-to-candidate diff, and rejects conflict observations, weak/missing evidence, missing drop acknowledgement, and drop requests without matching TCP/UDP port hints. Objects and Intel link into Traffic instead of owning a separate queue. API/CLI context exposes `ngfwctl app-id observations` and `ngfwctl app-id promote` rather than raw curl fallbacks, and the CLI prints policy/package context, scanned flow count, effective threshold, queue ID, sample tuple, suggested application, validation, diff summary, and evidence while `--json` returns the full proto response. |
| T5.5l **(F)** | In Threats, filter by IP/protocol/action/severity/signature/time/search, open an alert with a `signature_id`, stage a source-scoped false-positive exception, inspect the stage-result drawer, open `#/threats?view=exceptions`, open the staged row, then stage edit, disable, re-enable, and remove actions in separate discardable candidates with an audit reason. Open IDS/IPS settings and confirm the staged exception row is candidate-only before commit. Validate, inspect candidate diff, audit entries, and commit review, then discard or commit in a lab. Repeat headlessly with `curl -sk -H "Authorization: Bearer $NGFW_TOKEN" -H "Content-Type: application/json" -d '{"threatId":"phragma.test.web","threatName":"Suspicious test web traffic","engineSignals":[{"engine":"suricata","kind":"signature_id","value":"9000001"}],"scope":"THREAT_EXCEPTION_SCOPE_SOURCE","sourceIp":"10.0.1.10","reason":"known lab false positive"}' https://127.0.0.1:8080/v1/threat-exceptions:stage`, `curl -sk -H "Authorization: Bearer $NGFW_TOKEN" https://127.0.0.1:8080/v1/threat-exceptions`, `PATCH /v1/threat-exceptions/{name}`, `POST /v1/threat-exceptions/{name}:set-state`, and `POST /v1/threat-exceptions/{name}:remove`. | Table refreshes from `/v1/alerts` server-side filters and shows query-time running policy version; alert detail shows Threat-ID confidence/evidence, EVE `flowId` when present, and exact event policy version when the telemetry event was stamped; UI and REST API create/reuse the scoped address object, require an operator reason, block duplicate scoped suppressions, stage `ids.exceptions[]` with signature ID, strict Threat-ID metadata, scope, and reason, return candidate status/validation/diff, show the post-stage exception, address scope, post-commit artifact, candidate status, validation findings, and running-to-candidate diff. The exception workbench lists effective candidate/running state, marks candidate-only and changed exceptions, and stages edit/disable/enable/remove lifecycle actions through dedicated audited APIs without mutating running policy; global create/update/re-enable requires explicit acknowledgement. IDS settings surfaces the same staged exception with candidate state, commit review calls out the IDS exception change, and the Suricata adapter renders `openngfw-threshold.config` only after validation/commit |
| T5.5m **(F)** | Stage any candidate while controld is in dry-run mode or while Readiness has warnings, then click Review & commit. Open at least one runtime item through its Readiness link. Open each external release gate's **Evidence details** expander in Readiness, then open Readiness **System evidence** and **HA evidence** and pin each packet to Investigation. Repeat with a candidate that newly enables flowtable from a standard running policy, with an already-running flowtable policy whose live flowtable evidence is inactive, and from rollback review for a previous version | Commit and rollback review fetch `/v1/system/status`, evaluate the target policy with the Readiness model, show Runtime as not ready or warnings, list the relevant action-queue items, link each runtime item to the exact `#/readiness?action=<id>` blocker, and require acknowledgement plus a comment before the mutating action is enabled. External release gates show inline evidence path, artifact, documentation reference, and copyable validate/record commands while still preserving the focused packet drawer. System and HA evidence drawers pin standard local Investigation packets around the existing redacted evidence text and raw browser-generated packet without closing external release gates or mutating policy. New flowtable candidates preflight host readiness without requiring pre-commit live counters; already-running flowtable policies without active runtime evidence are blocked as not ready. Valid production posture shows Runtime as ready |
| T5.5m-2 **(F)** | From Troubleshoot, generate a packet-capture plan for a fully scoped TCP/UDP flow, copy the `#/troubleshoot?...&intent=capture` route after changing interface/duration/packet/snaplen controls, reload it in a new tab, and export the capture handoff before and after a start attempt. Start from an admin session, refresh Recent captures, set Retain with a future UTC timestamp/reason/case, verify retained/expiry/case display in Troubleshoot and Investigation case evidence, then Release and verify `retain_until` clears while pcap bytes and SHA-256 stay unchanged. Then repeat headless with `ngfwctl system capture --interface <if> --protocol tcp --src <client> --sport <port> --dst <server> --dport <port>`, `ngfwctl system capture retain <artifact-id> --retain-until <future-Z-time> --reason "incident review" --case-id <case> --ack-retention-change`, and `ngfwctl system capture release <artifact-id> --reason "case closed" --ack-retention-change`. On an enforcing Linux firewall host, repeat with `--start --ack-capture`; on a dry-run daemon, try the same start. For machine validation on Linux root hosts, run `go test -tags integration -run TestPacketCaptureStartCapturesLoopbackTraffic ./test/integration`. | UI and CLI both call `/v1/system/packet-captures/plan` and show the same bounded BPF filter, output path, limits, and copyable timeout-wrapped command. Troubleshoot capture links replay the same bounded capture controls and auto-open the capture workflow. Exported capture handoff distinguishes planned-only from started/completed/failed capture state and includes plan source, job detail, bytes written, completed pcap SHA-256, audit-trail link, and the reproducible route without pcap bytes or secrets. Start requires admin RBAC and acknowledgement, rejects dry-run mode and broad unscoped captures, writes the pcap under the configured log directory, returns bytes/status/SHA-256, produces a readable pcap, and records `packet-capture` or `packet-capture-failed` in audit. Retain/release calls `/v1/system/packet-captures/{id}:set-retention`, requires admin RBAC plus acknowledgement, persists only bounded sidecar metadata, records `packet-capture-retention` audit evidence without raw capture path/filter details, and does not rewrite the pcap artifact. |
| T5.5n **(F)** | In Settings, open and copy `#/settings?panel=telemetry`, `#/settings?panel=network`, `#/settings?panel=host-input`, and `#/settings?panel=access`. Then enable Telemetry export, set a ClickHouse HTTP endpoint, database, local JSON export, and remote JSON stream, pin the telemetry evidence plan to Investigation, validate, inspect diff, then discard or commit in a lab. From Settings access, run OIDC preflight and pin/copy/export its evidence. Repeat with `tcp://...`, URL userinfo, `access_token`/`api_key` query parameters, or an uppercase database name | Settings section links scroll, focus, and highlight the matching card while keeping all Settings cards visible; invalid panel state normalizes back to `#/settings`; copied links contain only the panel id and never unsaved form values, API tokens, OIDC state, source paths, ClickHouse credentials, or secrets. Settings stages only `telemetry.enabled`, `clickhouse_url`, `database`, and explicit JSON export sinks through the candidate, shows Vector runtime posture from `/v1/system/status`, reads passive running-policy export posture from `/v1/system/telemetry/exports/status`, and blocks invalid endpoint/database/export values before server validation; telemetry and OIDC evidence pin standard local Investigation packets around already-redacted evidence without adding unsaved form values, provider secrets, session material, or operator tokens. Credential-bearing ClickHouse URLs are rejected, disabling telemetry removes the candidate telemetry section, committed `vector.yaml` is not world-readable (`0600`), and passive status does not send test events or dial remote receivers |
| T5.6 | Start with OIDC enabled: `--oidc-issuer`, `--oidc-client-id`, `--oidc-client-secret-file <chmod 600>`, `--oidc-redirect-url https://<fw>/v1/auth/oidc/callback`, plus a users file for CLI break-glass, then browse a protected UI route without a token/session | `/v1/auth/oidc/status` returns enabled; the UI renders the access panel in place with OIDC and local-token options, preserving the requested hash route as the OIDC return target; Settings also shows "Browser SSO is enabled"; HTTPS public redirect deployments use a `Secure` OIDC session cookie even when TLS terminates before a loopback backend |
| T5.7 | From the access panel or Settings, click Sign in with OIDC; complete IdP login where the configured role claim contains `viewer`, `operator`, or `admin`; inspect `/v1/auth/oidc/status` from the same browser session | `/v1/system/identity` shows the IdP actor, role, and `oidc-session` auth source; browser requests use an HTTP-only SameSite cookie marked `Secure` for HTTPS public redirect URLs; status reports `authenticated: true` and a per-session `csrf_token`; the UI resumes the originally requested route |
| T5.7a | Capture provider-backed negative OIDC evidence: repeat callback attempts with a reused or missing `state`, an invalid or mismatched `nonce`/ID token, and a failed PKCE verifier exchange from the same IdP test client; if TLS terminates at a reverse proxy, repeat the successful login through that proxy with `--trusted-proxy-cidrs` set and with it omitted | invalid callback attempts return `401` without creating a session cookie or audit actor; the successful proxied login still sets a `Secure` SameSite cookie and passes same-origin CSRF checks only when the immediate proxy is trusted and sends `X-Forwarded-Proto: https`; omitting `--trusted-proxy-cidrs` causes the proxy-origin CSRF mutation check to fail rather than trusting spoofed forwarded headers |
| T5.8 | As an OIDC `operator`, stage and commit a harmless policy description change from the UI; repeat the same POST with the OIDC cookie but without `X-Phragma-CSRF`, and again with a mismatched `Origin` | the UI commit succeeds because it sends the status-provided CSRF header; missing CSRF or cross-origin cookie mutation returns `403`; `ngfwctl audit` and Changes show the OIDC actor, role, and `oidc-session` auth source |
| T5.9 | As an OIDC `viewer`, try to commit from the UI | commit is denied by the same RBAC interceptor as local-token users |
| T5.10 | Start with `--rate-limit-rpm 2 --rate-limit-burst 1`; issue repeated `curl -k https://127.0.0.1:8080/v1/auth/oidc/status` or `ngfwctl version` requests from the same client, then repeatedly request embedded WebUI assets such as `/ui/js/app.js` and `/ui/assets/fonts/ibm-plex-sans-v23-latin-400.ttf` | excess API/auth requests return HTTP `429` with `Retry-After` or gRPC `ResourceExhausted`; a different client has a separate bucket; read-only embedded WebUI static assets continue serving and do not consume the API/OIDC rate-limit bucket |
| T5.11 | Start with `--http-max-body-bytes 16 --grpc-max-recv-bytes 1024`; POST an oversized REST policy payload and send an oversized direct gRPC request; inspect `/v1/system/status.management` | REST returns HTTP `413` before handler execution; direct gRPC returns a resource-exhausted/request-too-large error; normal small requests still pass; Readiness shows the active caps |

Provider-backed OIDC browser SSO is release field evidence, not rootless CI.
The loopback `m5-oidc-provider` smoke proves protocol and session mechanics
against a mock provider plus API-driven runtime provider validate/set/disable,
authenticator replacement, and OIDC session revocation; `m5-oidc-field-evidence`
proves the configured real issuer/client, browser, public HTTPS callback, and
proxy posture. Before recording that release check, copy redacted field
artifacts into:

```text
release/field-evidence/oidc/
  provider/
    issuer-client-discovery.txt
    id-token-validation.txt
  deployment/
    public-callback.txt
    client-secret-file-permissions.txt
  browser/
    session-cookie.txt
    missing-state-rejection.txt
    reused-state-rejection.txt
    nonce-mismatch-rejection.txt
    pkce-exchange-failure.txt
    operator-mutation-with-csrf.txt
    missing-csrf-rejection.txt
    cross-origin-rejection.txt
    viewer-mutation-denial.txt
    logout-invalidation.txt
  rbac/
    role-mapping.txt
  redaction/
    identity-redacted.txt
    audit-log-redacted.txt
    support-bundle-redacted.txt
```

The files should preserve enough context to prove the issuer, client ID,
callback URL, role mapping, CSRF result, RBAC result, logout result, and
`oidc-session` audit/source path, while redacting cookies, authorization codes,
provider tokens, ID tokens, refresh tokens, and client secrets. If the
deployment uses a public client with no secret, keep
`client-secret-file-permissions.txt` and state that no client secret is
configured.

Validate and record the bundle from the lab where the browser SSO run happened:

```sh
make m5-oidc-field-evidence-check OIDC_FIELD_EVIDENCE_DIR=release/field-evidence/oidc
COMMIT="$(git rev-parse HEAD)" make release-evidence-m5-oidc-field-evidence \
  OIDC_FIELD_EVIDENCE_DIR=release/field-evidence/oidc
```

Provider-backed SAML browser SSO is also release field evidence, not rootless
CI. Before recording `m5-saml-field-evidence`, copy redacted IdP/SP metadata,
public ACS, browser, RBAC, and redaction artifacts into
`release/field-evidence/saml`, then validate and record the bundle from the lab
where the browser SSO run happened:

```sh
make m5-saml-field-evidence-check SAML_FIELD_EVIDENCE_DIR=release/field-evidence/saml
COMMIT="$(git rev-parse HEAD)" make release-evidence-m5-saml-field-evidence \
  SAML_FIELD_EVIDENCE_DIR=release/field-evidence/saml
```

The OIDC validator output must include the bundle-scope sentinels:

```text
field_evidence_scope=real-issuer-client,id-token-validation,https-callback,secret-file,cookie-security,negative-callbacks,rbac,csrf-origin,logout,redaction
oidc_field_evidence_scope=real-provider-backed,browser-sso,authorization-code-pkce,id-token-verification,nonce,session-cookie,csrf,rbac
oidc_field_negative_checks=missing-state,reused-state,nonce-mismatch,pkce-exchange-failure,logout,viewer-denial
oidc_field_redaction=issuer-host-redacted,client-id-redacted,subject-redacted,email-redacted,tokens-redacted,cookies-redacted
required_provider_evidence=issuer-client-discovery,id-token-validation
required_deployment_evidence=public-https-callback,client-secret-file-permissions
required_browser_evidence=session-cookie,missing-state-rejection,reused-state-rejection,nonce-mismatch-rejection,pkce-exchange-failure,operator-mutation-with-csrf,missing-csrf-rejection,cross-origin-rejection,viewer-mutation-denial,logout-invalidation
required_rbac_evidence=viewer,operator,admin
required_redaction_evidence=identity-redacted,audit-log-redacted,support-bundle-redacted,global-secret-scan
redaction_scan=jwt,bearer,oauth-token,cookie,auth-code,client-secret,csrf
status=passed
```

### Phase 6 — Operational (gap G)

| ID | Action | Expect |
|----|--------|--------|
| T-OPS-1 | `sudo systemctl restart controld` | running policy + suricata return automatically (journal: "running policy re-applied at startup") |
| T-OPS-2 | `sudo reboot` the firewall VM (netplan must persist VNIC IPs!) | after boot: ruleset live, T1.3 passes with **no manual action** |
| T-OPS-3 | `sudo journalctl -u controld` | no silent failures; engine exits logged loudly |
| T-OPS-4 | Kill suricata manually (`sudo pkill -9 suricata`) | controld logs "engine process exited unexpectedly", then performs a bounded auto-restart after the process was stable long enough to pass startup grace; `ngfwctl status` and Readiness show `restarting`, `active`, or `failed` with restart/last-exit detail |
| T-OPS-5 | `ngfwctl status`, `/v1/system/status`, and Readiness after install; if degraded, run `sudo ngfwctl system tune --write --apply` and re-check | kernel tuning is `ready`; `/etc/sysctl.d/99-openngfw.conf` exists; `ip_forward`, reverse-path filtering, conntrack max, and backlog checks match the appliance baseline; `dataplane.conntrack` reports live state-table usage versus `nf_conntrack_max`; a no-flag `ngfwctl system tune` prints the same baseline without changing the host |
| T-OPS-5a | For high-bandwidth or connection-churn validation, run `sudo ngfwctl system tune --profile throughput --write --apply`, apply throughput tuning from Guided setup or Readiness on an enforcing lab host, or install with `OPENNGFW_TUNE_PROFILE=throughput sudo deploy/install.sh`, then re-check `ngfwctl status` and `/v1/system/status` | throughput profile writes larger conntrack, listen backlog, and device backlog headroom; Readiness and Guided setup remain `ready` or improve, and `dataplane.conntrack.max_entries` reflects the raised state-table size before benchmark traffic starts |
| T-OPS-6 | Inspect `/v1/system/status.host`, Dashboard, and Readiness before and after a traffic run | host telemetry reports CPU count, 1/5/15 minute load, load per CPU, memory total/available/used percent, and interface byte/packet/drop/error counters; non-zero interface drops or errors appear as degraded host resource telemetry and action-queue warnings |
| T-OPS-7 | During a connection-churn run, inspect `ngfwctl status` and `curl -sk -H "Authorization: Bearer $NGFW_TOKEN" https://127.0.0.1:8080/v1/system/status \| jq '.dataplane.conntrack'` | state-table usage rises and remains below the warning/degraded thresholds; elevated usage appears in Readiness and the Dashboard runtime posture instead of requiring raw sysctl inspection |

### Phase 7 — Global network settings: jumbo frames & SR-IOV

OCI VCNs support MTU 9000 natively, and on SR-IOV ("hardware-assisted/
VFIO networking") shapes the VNICs appear as ordinary interfaces — zones
reference them by name, nothing else changes.

| ID | Action | Expect |
|----|--------|--------|
| T7.1 | In Settings, stage global MTU `9000`, set one zone-interface MTU override to `1500`, add `mgmt0=1500` as an additional interface override, enable MSS clamp and NIC offload management, validate, inspect diff, then commit in a lab. Headless equivalent: `ngfwctl policy network set --mtu 9000 --clear-interface-mtus --interface-mtu ens5=1500 --interface-mtu mgmt0=1500 --clamp-mss on --manage-nic-offloads on` | UI and CLI stage `network.mtu`, `network.interface_mtus[]` for zone and explicit non-zone interfaces, `clamp_mss_to_pmtu`, and `manage_nic_offloads` through the candidate only; invalid MTU values outside 1280-9600 or duplicate interface overrides disable Stage or return a CLI error; `ip link show` on fw reports the global MTU except the overridden interfaces |
| T7.2 | Set client+server NIC MTU to 9000 too; `client$ ping -M do -s 8972 10.0.2.20` | jumbo ping passes un-fragmented through the firewall |
| T7.3 | `sudo nft list table inet openngfw \| grep maxseg` | `tcp option maxseg size set rt mtu` present |
| T7.4 | From client, fetch something beyond the jumbo segment via a 1500-MTU path (e.g. DNAT out the wan-side 1500 interface) | no PMTUD black-holing — transfer completes (MSS clamped) |
| T7.5 | With IDS detect enabled: `sudo ethtool -k ens5 \| grep -E 'generic-receive\|tcp-segmentation'` | both `off` on monitored interfaces (wire-true frames for Suricata) |
| T7.6 | Repeat T2.3 (EVILSTRING) with jumbo MTU active | alert still fires (capture size follows MTU; check `default-packet-size: 9018` in `/var/lib/openngfw/suricata/suricata.yaml`) |
| T7.7 | On an SR-IOV shape (VFIO networking) re-run T1.3–T1.5 and T7.2 | identical results — interface type is transparent to the policy model |
| T7.8 | Remove the `network:` section + commit | links keep their last MTU/offload values (documented apply-only behavior, not a bug) |

### Phase 8 — Flowtable fast-path runtime evidence

Use this phase only for forwarding profiles with IDS/IPS disabled.

| ID | Action | Expect |
|----|--------|--------|
| T8.1 | In Settings, try to enable `network.enable_flow_offload: true` while IDS/IPS is enabled or before assigning a zone interface; then enable it with at least two zone interfaces, validate, and commit | Settings disables Stage and explains the invalid fast-path candidate before server validation; validation passes only when IDS/IPS is disabled and at least one zone interface exists |
| T8.2 | `ngfwctl status` and `/v1/system/status` | `flowtable host` is `ready` or `active`; `flowtable live` and `dataplane.flowtable.runtime_state` are `active`; devices and counters are present after traffic |
| T8.3 | `sudo nft list table inet openngfw` | ruleset includes `flowtable fastpath` and `flow add @fastpath` |
| T8.4 | Run benchmark traffic, then repeat T8.3; open Performance, select the whole `perf/results/<run>` directory, and click **Use live status** while traffic is active | `flow-offload` rule counters increase; `perf/results/.../ngfw-status-active.txt` or `firewall-status-active.txt`, final status, and `nft-openngfw-final.txt` capture active/post-traffic evidence; Performance auto-loads `summary.json`, `iperf3.json`, status, and nftables artifacts when present, and can replace the status artifact with current `/v1/system/status` evidence; `summary.json` includes `conntrack_evidence` from active-load state-table capacity, and `ngfwperf verify --strict --publishable` fails if throughput evidence omits it |
| T8.5 | Run `ngfwctl sessions --protocol TCP --limit 20` while benchmark connections are active | the state-table view remains available for live operational triage even when IDS/App-ID flow telemetry is intentionally absent from the forwarding-only fast-path profile |
| T8.6 | Browse Readiness | a running flowtable policy without active runtime evidence is shown as a production blocker |
| T8.7 | On the firewall host, inspect `ngfwctl status`, `/v1/system/status.dataplane.ebpf`, and Readiness | eBPF host readiness reports `bpftool`, `clang`, `tc`, `ip`, kernel BTF, bpffs, and cgroup v2 probes; missing probes are warnings/action-queue items; nftables can remain the active renderer while degraded eBPF readiness blocks the strategic XDP/tc milestone |

### Phase 9 — Host-input appliance hardening

Use this phase before exposing the firewall VM management plane beyond a
trusted lab subnet.

| ID | Action | Expect |
|----|--------|--------|
| T9.1 | Add `host_input.default_action: ACTION_DENY` with an explicit allow rule for the management source zone/service, validate, and commit | validation passes; commit installs the host-input policy |
| T9.1a | Add `host_input.default_action: ACTION_DENY` with no enabled `ACTION_ALLOW` host-input rule, then validate | validation fails with a management-lockout error before commit |
| T9.2 | `sudo nft list table inet openngfw` | `chain input` has `policy drop`, loopback and established accepts, the explicit `host-input:<name>` rule, and a `default-input-drop` counter |
| T9.3 | Connect to SSH or WebUI from an allowed management source | connection succeeds |
| T9.4 | Connect to the same service from a non-allowed source or zone | connection is dropped or rejected according to host-input policy |
| T9.5 | Browse Settings → Host input | default action and rule list match the running or staged candidate; edits stage through candidate/commit; trying to stage default-deny without an enabled allow rule shows an immediate warning and opens the rule editor |

### Known v1 limitations (expected findings, not bugs)

1. **API/UI serve HTTPS with a self-signed cert by default** (generated
   under `<data-dir>/tls/`); they bind 127.0.0.1 — reach them via SSH
   tunnel and accept the browser warning, or supply `--tls-cert/--tls-key`.
2. Suricata/Vector run as controld children: stable unexpected exits are
   logged and auto-restarted with a bounded retry budget; fail-fast startup
   exits remain commit/apply failures so bad config is not hidden.
3. Single shared candidate (no per-user candidates).
4. `et-block-ips`/`spamhaus` URLs may rate-limit; the refresh logs and
   keeps other feeds working.
5. Performance numbers from T2.7 are for your eyes. Use
   `sudo make benchmark-netns` on one Linux host for release-regression smoke.
   Publishing any throughput number requires the benchmark harness in `perf/`,
   normally via `make benchmark-check` and `make benchmark` on a Linux
   three-VM bench.

### Reporting

For each failed test, grab: the test ID, `ngfwctl audit` tail,
`sudo journalctl -u controld --since -10m`, and (if traffic-related)
`sudo nft list table inet openngfw`. Those four artifacts are enough to
diagnose almost anything in the commit path.
