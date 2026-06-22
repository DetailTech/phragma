# 2026-06-17 gdioc2 Three-Host Active Phragma Benchmark

This run is cloud-lab evidence for the active Phragma service in `gdioc2`. It
is not a VM-Series parity claim and it is not a strict fail-closed IPS result.

## Environment

- Tenancy/profile: `gdioc2`
- Topology: three OCI VMs with client and server traffic routed through the
  firewall trust/untrust VNICs.
- Client: `vm-client`, `VM.Standard.E5.Flex`, 20 OCPUs, 240 GB RAM, Oracle
  Linux Server 9.7, kernel `6.12.0-202.76.4.1.el9uek.x86_64`
- Firewall: `vm-oss-ngfw`, `VM.Standard.E5.Flex`, 20 OCPUs, 240 GB RAM, Oracle
  Linux Server 9.7, kernel `6.12.0-202.76.4.1.el9uek.x86_64`
- Server: `vm-server`, `VM.Standard.E5.Flex`, 20 OCPUs, 240 GB RAM, Oracle
  Linux Server 9.7, kernel `6.12.0-202.76.4.1.el9uek.x86_64`
- Phragma service: `controld 4a7beae`, commit `4a7beae`, built
  `2026-06-16T15:40:19Z`
- Dataplane renderer: nftables
- IPS path: Suricata NFQUEUE fanout with nftables `queue flags bypass,fanout to
  0-15`
- Raw local artifact directory:
  `perf/results/20260617T025518Z-three-host-active-openngfw/`

## Result

- Profile: `three-host-active-openngfw`
- Security services: `suricata-prevent-nfqueue-fail-open`
- Inspection state: `inline-ips-fail-open`
- Target: `10.0.0.225:5201`
- Duration: 20 seconds
- Parallel streams: 8
- TCP throughput: 19.727 Gbps
- TCP retransmits: 4676
- Ping average: 0.564 ms
- Connection churn: 100 attempts, 100 success, 0 failed, 960 ms

## Evidence Captured

- `metadata.json`
- `summary.json`
- `report.md`
- `iperf3.json`
- `ping.txt`
- `churn.txt`
- `client-facts.txt`
- `server-facts.txt`
- `firewall-facts.txt`
- `firewall-status.txt`
- `firewall-status-final.txt`

The post-run firewall ruleset showed benchmark traffic counted by the Phragma
inline queue rule:

```text
counter packets 3298686 bytes 109162743674 queue flags bypass,fanout to 0-15 comment "ips-inspect"
```

The committed policy also had explicit accept rules for the test server and
port, plus a broad `wideopen` accept fallback. The `wideopen` rule showed zero
packets during the final capture for this test path.

## Scope

This proves that the current lab service can forward a high-throughput
three-host OCI path while the Phragma nftables policy and Suricata NFQUEUE
hook are installed. The result is valid for this measured environment only. It
does not prove fail-closed prevention throughput, adversarial traffic
inspection quality, eBPF/XDP/tc dataplane performance, long-duration stability,
or VM-Series-class feature parity.

This historical run was produced before the three-host harness captured
active-load `firewall-status-active.txt`; newer runs prefer that sample when
building `conntrack_evidence` and flowtable evidence in `summary.json`.
