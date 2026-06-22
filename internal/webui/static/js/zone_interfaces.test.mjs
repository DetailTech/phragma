import assert from "node:assert/strict";

import { objectStatusInventorySummary, zoneInterfaceNames, zoneInterfaceReview } from "./views/objects.js";

const discovered = [
  { name: "eth0", state: "ready", detail: "uplink", rxBytes: 2048, txBytes: 1024 },
  { name: "eth1", state: "down", detail: "carrier missing" },
  { name: "wan0", state: "ready", detail: "provider edge" },
];

assert.deepEqual(zoneInterfaceNames([" eth0 ", "eth0", "eth2, eth3", ""]), ["eth0", "eth2", "eth3"]);

{
  const policy = {
    zones: [
      { name: "lan", interfaces: ["eth0"] },
      { name: "guest", interfaces: ["eth0", "eth1"] },
    ],
  };
  const review = zoneInterfaceReview(policy, policy.zones[0], discovered, { zoneIndex: 0 });
  assert.equal(review.severity, "bad");
  assert.ok(review.issues.some((issue) => issue.detail === "eth0 is already assigned to guest."));
}

{
  const policy = { zones: [{ name: "inside", interfaces: ["eth0", "eth0"] }] };
  const review = zoneInterfaceReview(policy, policy.zones[0], discovered, { zoneIndex: 0 });
  assert.equal(review.severity, "ok");
  assert.equal(review.interfaces.length, 1);
}

{
  const zone = { name: "loopback", interfaces: ["lo"] };
  const review = zoneInterfaceReview({ zones: [zone] }, zone, discovered, { zoneIndex: 0 });
  assert.equal(review.severity, "bad");
  assert.ok(review.issues.some((issue) => issue.detail === "Loopback cannot be assigned to a security zone."));
}

{
  const zone = { name: "lab", interfaces: ["future0"] };
  const review = zoneInterfaceReview({ zones: [zone] }, zone, discovered, { zoneIndex: 0 });
  assert.equal(review.severity, "warn");
  assert.ok(review.issues.some((issue) => issue.detail === "future0 was not reported by this host."));
}

{
  const zone = { name: "guest", interfaces: ["eth1"] };
  const review = zoneInterfaceReview({ zones: [zone] }, zone, discovered, { zoneIndex: 0 });
  assert.equal(review.severity, "warn");
  assert.ok(review.issues.some((issue) => issue.detail === "eth1 is down: carrier missing"));
}

{
  const zone = { name: "empty", interfaces: [] };
  const review = zoneInterfaceReview({ zones: [zone] }, zone, discovered, { zoneIndex: 0 });
  assert.equal(review.severity, "warn");
  assert.ok(review.issues.some((issue) => issue.detail.includes("Assign at least one interface")));
}

{
  const zone = { name: "offline-staged", interfaces: ["future0"] };
  const review = zoneInterfaceReview({ zones: [zone] }, zone, [], { zoneIndex: 0 });
  assert.equal(review.severity, "ok");
  assert.equal(review.inventoryAvailable, false);
}

{
  const summary = objectStatusInventorySummary({ host: { interfaces: discovered } }, null, {});
  assert.equal(summary.state, "ready");
  assert.equal(summary.label, "3 host interfaces discovered");
  assert.equal(summary.tone, "info");
  assert.equal(summary.staleNotice, "");
  assert.deepEqual(summary.discovered.map((iface) => iface.name), ["eth0", "eth1", "wan0"]);
}

{
  const summary = objectStatusInventorySummary(null, null, { loading: true, staleDropCount: 2 });
  assert.equal(summary.state, "refreshing");
  assert.equal(summary.label, "refreshing inventory");
  assert.match(summary.detail, /latest response is pending/);
  assert.match(summary.staleNotice, /Ignored 2 stale host inventory responses/);
}

{
  const summary = objectStatusInventorySummary(null, new Error("status failed"), { staleIgnored: true, staleDropCount: 1 });
  assert.equal(summary.state, "unavailable");
  assert.equal(summary.pillTone, "warn");
  assert.match(summary.detail, /manual interface names are still supported/);
  assert.match(summary.staleNotice, /Ignored 1 stale host inventory response/);
}
