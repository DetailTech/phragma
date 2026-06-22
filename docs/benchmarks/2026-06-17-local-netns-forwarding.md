# 2026-06-17 Local Namespace Forwarding Benchmark

This run is release-regression evidence for the local Linux dataplane path. It
is not a cloud-NIC, multi-host, or VM-Series comparison result.

## Environment

- Host: `vm-oss-ngfw` in `gdioc2`
- OS: Oracle Linux Server 9.7
- Kernel: `6.12.0-202.76.4.1.el9uek.x86_64`
- CPU visible to guest: 40 vCPU
- Phragma mode: real `controld`, no `--dry-run`
- Dataplane: nftables/conntrack
- Policy path: `ngfwctl policy set` -> `policy validate` -> `commit`
- Benchmark topology: single-host Linux network namespaces, veth links through
  the root namespace acting as the firewall
- Raw local artifact directory:
  `perf/results/20260617T024215Z-local-netns-forwarding/`

## Result

- Profile: `local-netns-forwarding`
- Security services: `none`
- Inspection state: `forwarding-only`
- Duration: 20 seconds
- Parallel streams: 8
- TCP throughput: 5.722 Gbps
- TCP retransmits: 410
- Ping average: 0.188 ms
- Connection churn: 100 attempts, 100 success, 0 failed, 1184 ms

## Evidence Captured

- `summary.json`
- `report.md`
- `iperf3.json`
- `ping.txt`
- `churn.txt`
- `policy.yaml`
- `policy-validate.txt`
- `ngfw-status.txt`
- `nft-openngfw.txt`
- `nft-openngfw-final.txt`
- `host-facts.txt`

The final nftables ruleset showed the committed Phragma policy still installed
after traffic, with no default-drop hits:

```text
iifname "obench0" oifname "ibench0" ip daddr 10.250.2.2 tcp dport 5201 ... counter packets 111 bytes 6660 accept comment "rule:bench-client-to-server"
iifname "obench0" oifname "ibench0" ip daddr 10.250.2.2 meta l4proto icmp ... counter packets 1 bytes 84 accept comment "rule:bench-client-to-server"
counter packets 0 bytes 0 comment "default-drop"
```

## Scope

This proves the benchmark harness can drive real Phragma binaries and real
nftables policy on Linux, and it gives a repeatable local forwarding baseline.
It does not prove cloud dataplane throughput, IDS/IPS inspection throughput,
eBPF/XDP/tc performance, or VM-Series-class parity.

This historical run was produced before the local namespace harness captured
active-load `ngfw-status-active.txt` and post-traffic `ngfw-status-final.txt`;
newer runs prefer those status samples when building `conntrack_evidence` and
flowtable evidence in `summary.json`.
