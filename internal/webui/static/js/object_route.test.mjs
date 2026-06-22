import assert from "node:assert/strict";

import { normalizeObjectName, normalizeObjectRoute, normalizeObjectTab, objectKindHash, objectReferenceHash, objectTabForPolicyKind, objectTabHash } from "./object_route.js";

assert.equal(normalizeObjectTab("services"), "services");
assert.equal(normalizeObjectTab("bad-tab"), "addresses");
assert.equal(normalizeObjectName(" web-server "), "web-server");
assert.deepEqual(normalizeObjectRoute({ tab: "applications" }), { tab: "applications", drawer: "", object: "" });
assert.deepEqual(normalizeObjectRoute({ tab: "unknown" }), { tab: "addresses", drawer: "", object: "" });
assert.deepEqual(normalizeObjectRoute({ tab: "services", drawer: "references", object: "https" }), { tab: "services", drawer: "references", object: "https" });
assert.deepEqual(normalizeObjectRoute({ tab: "services", drawer: "references", object: "" }), { tab: "services", drawer: "", object: "" });
assert.deepEqual(normalizeObjectRoute({ tab: "services", drawer: "edit", object: "https" }), { tab: "services", drawer: "", object: "" });

assert.equal(objectTabForPolicyKind("address"), "addresses");
assert.equal(objectTabForPolicyKind("services"), "services");
assert.equal(objectTabForPolicyKind("app-id"), "applications");
assert.equal(objectTabForPolicyKind("qos-profile"), "trafficControls");
assert.equal(objectTabForPolicyKind("zone-protection-profile"), "trafficControls");
assert.equal(objectTabForPolicyKind("zone"), "zones");
assert.equal(objectTabForPolicyKind("unknown"), "addresses");

assert.equal(objectTabHash("addresses"), "#/objects");
assert.equal(objectTabHash("services"), "#/objects?tab=services");
assert.equal(objectTabHash("applications"), "#/objects?tab=applications");
assert.equal(objectKindHash("service"), "#/objects?tab=services");
assert.equal(objectKindHash("application"), "#/objects?tab=applications");
assert.equal(objectReferenceHash("address", "web-server"), "#/objects?drawer=references&object=web-server");
assert.equal(objectReferenceHash("service", "https"), "#/objects?tab=services&drawer=references&object=https");
assert.equal(objectReferenceHash("application", "corp admin"), "#/objects?tab=applications&drawer=references&object=corp+admin");
assert.equal(objectReferenceHash("service", ""), "#/objects?tab=services");
