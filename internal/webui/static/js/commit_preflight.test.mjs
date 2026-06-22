import assert from "node:assert/strict";

import { commitRuntimePreflight } from "./commit_preflight.js";

function readyStatus(overrides = {}) {
  return {
    runtime: { activeDataplane: "nftables/conntrack", dryRun: false, ...(overrides.runtime || {}) },
    dataplane: {
      activeDataplane: "nftables/conntrack",
      kernelTuning: { state: "ready" },
      conntrack: { state: "ready", currentEntries: 25, maxEntries: 1048576, usagePercent: 0.002 },
      flowtable: { hostState: "ready", runtimeState: "inactive", runtimeDetail: "flowtable is not present" },
      ebpf: { state: "ready" },
      ...(overrides.dataplane || {}),
    },
    warnings: overrides.warnings || [],
    capabilities: overrides.capabilities || [],
    engines: overrides.engines || [{ name: "suricata", state: "ready" }],
    routing: overrides.routing || {},
  };
}

const standardPolicy = {
  zones: [{ name: "inside", interfaces: ["ens5"] }, { name: "outside", interfaces: ["ens4"] }],
  network: { enableFlowOffload: false },
};

const flowtablePolicy = {
  ...standardPolicy,
  network: { enableFlowOffload: true },
};

const bgpPolicy = {
  ...standardPolicy,
  routing: {
    bgp: {
      enabled: true,
      asn: 65001,
      routerId: "192.0.2.1",
      neighbors: [{ address: "198.51.100.2", remoteAsn: 65002 }],
    },
  },
};

{
  const result = commitRuntimePreflight({
    preflight: {
      operation: "commit",
      label: "not ready",
      cls: "bad",
      requiresAck: true,
      detail: "Runtime readiness reported 1 warning(s) before commit.",
      items: [{
        id: "dry-run",
        level: "high",
        badge: "runtime",
        title: "Daemon is running in dry-run mode",
        detail: "Remove --dry-run before production enforcement.",
        command: "ngfwctl status",
      }],
      warnings: ["Daemon is running in dry-run mode: Remove --dry-run before production enforcement."],
    },
    status: readyStatus(),
    draftPolicy: standardPolicy,
    runningPolicy: standardPolicy,
  });
  assert.equal(result.source, "server");
  assert.equal(result.label, "not ready");
  assert.equal(result.cls, "bad");
  assert.equal(result.requiresAck, true);
  assert.equal(result.items[0].id, "dry-run");
  assert.equal(result.items[0].command, "ngfwctl status");
}

{
  const result = commitRuntimePreflight({
    preflight: {},
    status: readyStatus({ runtime: { dryRun: true } }),
    draftPolicy: standardPolicy,
    runningPolicy: standardPolicy,
  });
  assert.equal(result.label, "not ready");
  assert.equal(result.cls, "bad");
  assert.equal(result.requiresAck, true);
  assert.equal(result.items[0].id, "dry-run");
}

{
  const result = commitRuntimePreflight({
    preflight: null,
    error: new Error("status endpoint unavailable"),
    operation: "rollback",
  });
  assert.equal(result.label, "unknown");
  assert.equal(result.requiresAck, true);
  assert.match(result.detail, /before rollback/);
}

{
  const result = commitRuntimePreflight({ status: readyStatus(), draftPolicy: standardPolicy, runningPolicy: standardPolicy });
  assert.equal(result.label, "ready");
  assert.equal(result.cls, "ok");
  assert.equal(result.requiresAck, false);
  assert.deepEqual(result.items, []);
}

{
  const result = commitRuntimePreflight({
    status: readyStatus({ runtime: { dryRun: true } }),
    draftPolicy: standardPolicy,
    runningPolicy: standardPolicy,
  });
  assert.equal(result.label, "not ready");
  assert.equal(result.cls, "bad");
  assert.equal(result.requiresAck, true);
  assert.equal(result.items[0].id, "dry-run");
  assert.equal(result.items[0].title, "Disable dry-run before production");
}

{
  const result = commitRuntimePreflight({
    status: readyStatus({
      routing: {
        frr: {
          state: "waiting",
          detail: "1 BGP neighbor(s), no established sessions",
          bgpNeighbors: [{ peer: "198.51.100.2", state: "Connect" }],
        },
      },
    }),
    draftPolicy: bgpPolicy,
    runningPolicy: bgpPolicy,
  });
  assert.equal(result.label, "not ready");
  assert.equal(result.cls, "bad");
  assert.equal(result.requiresAck, true);
  assert.ok(result.items.some((item) => item.id === "frr-runtime-evidence" && item.title === "Verify FRR dynamic-routing runtime evidence"));
}

{
  const result = commitRuntimePreflight({
    status: readyStatus({
      routing: {
        frr: {
          state: "inactive",
          detail: "FRR responded, but no BGP neighbor evidence was returned",
        },
      },
    }),
    draftPolicy: bgpPolicy,
    runningPolicy: standardPolicy,
  });
  assert.equal(result.label, "ready");
  assert.equal(result.requiresAck, false);
}

{
  const result = commitRuntimePreflight({
    status: readyStatus({
      dataplane: { conntrack: { state: "ready", currentEntries: 25, maxEntries: 4194304, usagePercent: 0.001 } },
    }),
    draftPolicy: flowtablePolicy,
    runningPolicy: standardPolicy,
  });
  assert.equal(result.label, "ready");
  assert.equal(result.requiresAck, false);
  assert.deepEqual(result.items, []);
}

{
  const result = commitRuntimePreflight({
    status: readyStatus(),
    draftPolicy: flowtablePolicy,
    runningPolicy: flowtablePolicy,
  });
  assert.equal(result.label, "not ready");
  assert.equal(result.cls, "bad");
  assert.equal(result.requiresAck, true);
  assert.ok(result.items.some((item) => item.id === "flowtable-runtime-evidence" && item.title === "Verify runtime flowtable evidence"));
}

{
  const result = commitRuntimePreflight({
    status: readyStatus({
      dataplane: { flowtable: { hostState: "degraded", hostDetail: "nft userspace dependency is missing", runtimeState: "inactive" } },
    }),
    draftPolicy: flowtablePolicy,
    runningPolicy: standardPolicy,
  });
  assert.equal(result.label, "not ready");
  assert.equal(result.requiresAck, true);
  assert.ok(result.items.some((item) => item.id === "flowtable-host-ready" && item.title === "Make the flowtable fast path host-ready"));
}

{
  const result = commitRuntimePreflight({
    status: readyStatus({
      dataplane: { ebpf: { state: "degraded", detail: "missing bpftool" } },
      capabilities: [{ name: "Linux eBPF XDP/tc host readiness", state: "degraded", detail: "missing bpftool" }],
    }),
    draftPolicy: standardPolicy,
    runningPolicy: standardPolicy,
  });
  assert.equal(result.label, "warnings");
  assert.equal(result.cls, "warn");
  assert.equal(result.requiresAck, true);
  assert.ok(result.items.some((item) => item.id === "strategic-ebpf-readiness" && item.title === "Track the strategic eBPF readiness gap"));
}

{
  const result = commitRuntimePreflight({
    status: readyStatus({
      runtime: { activeDataplane: "linux-ebpf-xdp/tc" },
      dataplane: { activeDataplane: "linux-ebpf-xdp/tc", ebpf: { state: "degraded", detail: "missing bpftool" } },
      capabilities: [{ name: "Linux eBPF XDP/tc host readiness", state: "degraded", detail: "missing bpftool" }],
    }),
    draftPolicy: standardPolicy,
    runningPolicy: standardPolicy,
  });
  assert.equal(result.label, "not ready");
  assert.equal(result.cls, "bad");
  assert.equal(result.requiresAck, true);
  assert.ok(result.items.some((item) => item.id === "ebpf-host-prerequisites" && item.title === "Complete eBPF host prerequisites"));
}

{
  const result = commitRuntimePreflight({ error: new Error("status endpoint unavailable") });
  assert.equal(result.label, "unknown");
  assert.equal(result.requiresAck, true);
  assert.match(result.detail, /before commit/);
  assert.equal(result.items[0].id, "runtime-status-unavailable");
  assert.match(result.items[0].detail, /status endpoint unavailable/);
}

{
  const result = commitRuntimePreflight({
    error: new Error("status endpoint unavailable"),
    operation: "rollback",
  });
  assert.equal(result.label, "unknown");
  assert.equal(result.requiresAck, true);
  assert.match(result.detail, /before rollback/);
}

{
  const result = commitRuntimePreflight({
    status: readyStatus(),
    draftPolicy: flowtablePolicy,
    runningPolicy: flowtablePolicy,
    operation: "rollback",
  });
  assert.equal(result.label, "not ready");
  assert.equal(result.requiresAck, true);
  assert.ok(result.items.some((item) => item.id === "flowtable-runtime-evidence" && item.title === "Verify runtime flowtable evidence"));
}
