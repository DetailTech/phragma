import assert from "node:assert/strict";
import { BASELINE_TUNING_COMMAND, THROUGHPUT_CONNTRACK_MIN, THROUGHPUT_TUNING_COMMAND, ebpfHostReadiness, kernelTuningRollup } from "./dataplane.js";

const rollup = kernelTuningRollup({
  dataplane: {
    conntrack: {
      state: "ready",
      maxEntries: 262144,
    },
    kernelTuning: {
      state: "degraded",
      detail: "1 kernel tuning issue(s): Conntrack table ceiling",
      sysctlConfigPath: "/etc/sysctl.d/99-openngfw.conf",
      checks: [
        {
          name: "IPv4 forwarding",
          key: "net.ipv4.ip_forward",
          current: "1",
          recommended: "1",
          state: "ready",
          detail: "required for routed forwarding",
        },
        {
          name: "Conntrack table ceiling",
          key: "net.netfilter.nf_conntrack_max",
          current: "262144",
          recommended: ">=1048576",
          state: "degraded",
          detail: "increase state table headroom",
        },
        {
          name: "Listen backlog",
          key: "net.core.somaxconn",
          recommended: ">=4096",
          state: "unknown",
        },
      ],
    },
  },
});

assert.equal(rollup.state, "degraded");
assert.equal(rollup.cls, "bad");
assert.equal(rollup.readyCount, 1);
assert.equal(rollup.degradedCount, 1);
assert.equal(rollup.unknownCount, 1);
assert.equal(rollup.totalCount, 3);
assert.equal(rollup.needsAction, true);
assert.equal(rollup.configPath, "/etc/sysctl.d/99-openngfw.conf");
assert.equal(rollup.remediationCommand, BASELINE_TUNING_COMMAND);
assert.equal(rollup.baselineCommand, BASELINE_TUNING_COMMAND);
assert.equal(rollup.throughputCommand, THROUGHPUT_TUNING_COMMAND);
assert.equal(rollup.throughputConntrackTarget, THROUGHPUT_CONNTRACK_MIN);
assert.equal(rollup.throughputReady, false);
assert.equal(rollup.throughputCls, "warn");
assert.equal(rollup.throughputLabel, "throughput profile available");
assert.match(rollup.throughputDetail, /262,144/);
assert.match(rollup.throughputDetail, /4,194,304/);
assert.equal(rollup.readinessLabel, "1/3 ready");
assert.equal(rollup.checks[1].cls, "bad");
assert.equal(rollup.checks[2].current, "");

const empty = kernelTuningRollup({});
assert.equal(empty.state, "unknown");
assert.equal(empty.readinessLabel, "unknown");
assert.equal(empty.totalCount, 0);
assert.equal(empty.throughputCls, "neutral");
assert.match(empty.throughputDetail, /unavailable/);

const throughput = kernelTuningRollup({
  dataplane: {
    conntrack: {
      state: "ready",
      maxEntries: THROUGHPUT_CONNTRACK_MIN,
    },
  },
});
assert.equal(throughput.throughputReady, true);
assert.equal(throughput.throughputCls, "ok");
assert.equal(throughput.throughputLabel, "state-table headroom ready");

const ebpf = ebpfHostReadiness({
  dataplane: {
    ebpf: {
      state: "ready",
      detail: "host ready",
      attachState: "ready",
      attachDetail: "attach prerequisites ready",
      attachProbes: [{ name: "XDP attach orchestration", state: "ready" }],
      rendererState: "planned",
      rendererDetail: "plan-only renderer scaffolding",
      supportedHooks: ["xdp", "tc"],
      blockers: [],
      attachments: [{ interface: "ens5", hook: "xdp", state: "attached", programId: "10" }],
      artifacts: [{ name: "ebpf-plan.txt", state: "ready", sha256: "a".repeat(64) }],
      evidenceCollectedAt: "2026-06-18T13:00:00Z",
      evidenceScope: "host-prerequisites,attach-prerequisites,renderer-scaffold,runtime-probes",
    },
  },
});
assert.equal(ebpf.ready, true);
assert.equal(ebpf.attachReady, true);
assert.equal(ebpf.rendererState, "planned");
assert.deepEqual(ebpf.supportedHooks, ["xdp", "tc"]);
assert.equal(ebpf.attachments[0].interface, "ens5");
assert.equal(ebpf.artifacts[0].name, "ebpf-plan.txt");
assert.equal(ebpf.evidenceScope, "host-prerequisites,attach-prerequisites,renderer-scaffold,runtime-probes");

const ebpfSnakeCase = ebpfHostReadiness({
  dataplane: {
    ebpf: {
      state: "degraded",
      attach_state: "degraded",
      attach_detail: "missing bpftool",
      attach_probes: [{ name: "BPF runtime inspection", state: "degraded" }],
      renderer_state: "planned",
      supported_hooks: ["xdp"],
      evidence_collected_at: "2026-06-18T13:00:00Z",
      evidence_scope: "host-prerequisites",
    },
  },
});
assert.equal(ebpfSnakeCase.ready, false);
assert.equal(ebpfSnakeCase.attachReady, false);
assert.equal(ebpfSnakeCase.attachDegraded[0].name, "BPF runtime inspection");
assert.equal(ebpfSnakeCase.rendererState, "planned");
assert.deepEqual(ebpfSnakeCase.supportedHooks, ["xdp"]);
