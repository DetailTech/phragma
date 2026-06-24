import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { investigationPacketFilename, investigationPacketJson } from "./investigation_packet.js";
import { destinationNatPublishIntentChanged, ensurePendingAddressObjects, ensurePendingServices, focusedNatRuleIndex, natRuleFocusHash, natRuleFocusRouteState, normalizeNatFocusRoute, removeDestinationNatWithPublishRule, removeGeneratedPublishRule, upsertPublishRule, validateNatServicePorts } from "./views/nat.js";
import { objectExists, objectHygieneFindings, objectReferenceCacheKey, objectReferenceHandoffPacket, objectReferenceRecords, objectReferenceTarget, objectReferences, objectRenameReviewModel, rewriteObjectReferences, securityProfileImpactHandoffPacket, securityProfileImpactModel, securityProfileWorkflowModel, validateObjectPortList, validateSecurityProfileUrlCategories } from "./views/objects.js";

const objectsViewSource = readFileSync(new URL("./views/objects.js", import.meta.url), "utf8");
assert.match(objectsViewSource, /pinInvestigationPacket/);
assert.match(objectsViewSource, /function pinObjectReferenceHandoff/);
assert.match(objectsViewSource, /Pin to case/);
assert.match(objectsViewSource, /const objectKindLabel = singular\(kind\) \|\| "object"/);
assert.match(objectsViewSource, /const objectLabel = name \|\| `row \$\{idx \+ 1\}`/);
assert.match(objectsViewSource, /type: "button", title: "Edit", "aria-label": `Edit \$\{objectKindLabel\} \$\{objectLabel\}`/);
assert.match(objectsViewSource, /type: "button", title: "Delete", "aria-label": `Delete \$\{objectKindLabel\} \$\{objectLabel\}`/);
assert.match(objectsViewSource, /if \(!editing && objectNameExists\(session\.draft, kind, newName\)\)/);
assert.match(objectsViewSource, /Choose a unique name before staging the object/);
assert.match(objectsViewSource, /const profileName = name \|\| "security profile"/);
assert.match(objectsViewSource, /type: "button",\s+title: "Review security profile impact",\s+"aria-label": `Review security profile impact for \$\{profileName\}`/);
assert.match(objectsViewSource, /dataset: \{ securityProfileWorkflow: "true" \}/);
assert.match(objectsViewSource, /dataset: \{ securityProfileEditorPosture: workflow\.posture\?\.state \|\| "unknown" \}/);
assert.match(objectsViewSource, /TLS key custody, DNS\/URL feeds, and file scanning remains separate hardening/);
assert.match(objectsViewSource, /type: "button", title: `Create new \$\{singular\(tab\)\}`, "aria-label": `Create new \$\{singular\(tab\)\}`/);
assert.match(objectsViewSource, /dataset: \{ objectAction: "references", objectKind: kind, objectName: name \|\| "" \}/);
assert.match(objectsViewSource, /dataset: \{ objectAction: "references-copy", objectKind: kind, objectName \}/);
assert.match(objectsViewSource, /dataset: \{ objectAction: "references-export", objectKind: kind, objectName \}/);
assert.match(objectsViewSource, /type: "button", title: `Cancel \$\{singular\(kind\)\} edit`, "aria-label": `Cancel \$\{singular\(kind\)\} edit`/);
assert.match(objectsViewSource, /type: "button", title: `Save \$\{singular\(kind\)\} to candidate`, "aria-label": `Save \$\{singular\(kind\)\} to candidate`/);
assert.match(objectsViewSource, /type: "button", title: `Stage \$\{singular\(kind\)\} rename and reference rewrites`, "aria-label": `Stage \$\{singular\(kind\)\} rename and reference rewrites`/);
assert.match(objectsViewSource, /previewResult = normalizeObjectEditorSaveResult\(save\(probe\)\)/);
assert.match(objectsViewSource, /throw new ObjectEditorValidationAbort\(saveResult\)/);
assert.match(objectsViewSource, /Service ports invalid/);

assert.deepEqual(validateObjectPortList("443, 8000-8002"), { ok: true, ports: [{ start: 443 }, { start: 8000, end: 8002 }] });
assert.equal(validateObjectPortList("0").ok, false);
assert.equal(validateObjectPortList("8443-443").ok, false);
assert.equal(validateObjectPortList("abc").ok, false);
assert.equal(validateSecurityProfileUrlCategories(["malware", "newly-registered"]).ok, true);
assert.equal(validateSecurityProfileUrlCategories(["Malware"]).ok, false);
assert.equal(validateSecurityProfileUrlCategories(["malware", "malware"]).ok, false);
assert.equal(validateSecurityProfileUrlCategories(["bad category"]).ok, false);

const policy = {
  rules: [
    {
      id: "rule-allow-web",
      name: "allow-web",
      fromZones: ["lan"],
      toZones: ["wan"],
      sourceAddresses: ["client-net"],
      destinationAddresses: ["web-server"],
      services: ["https"],
      applications: ["corp-admin"],
      securityProfiles: ["inspect-standard"],
      action: "ACTION_ALLOW",
    },
    {
      id: "rule-drop-admin",
      name: "drop-admin",
      fromZones: ["wan"],
      toZones: ["lan"],
      sourceAddresses: ["any"],
      destinationAddresses: ["web-server"],
      services: ["admin-ui"],
    },
  ],
  hostInput: {
    rules: [
      {
        id: "host-input-mgmt-ssh-custom",
        name: "mgmt-ssh",
        fromZones: ["lan"],
        sourceAddresses: ["admin-host"],
        services: ["ssh"],
      },
    ],
  },
  nat: {
    source: [
      {
        id: "snat-lan-egress-custom",
        name: "lan-egress",
        toZone: "wan",
        sourceAddress: "client-net",
        translatedAddress: "wan-ip",
      },
    ],
    destination: [
      {
        id: "dnat-published-web-custom",
        name: "published-web",
        fromZone: "wan",
        destinationAddress: "public-web",
        translatedAddress: "web-server",
        service: "https",
      },
    ],
  },
  ids: {
    enabled: true,
    mode: "IDS_MODE_PREVENT",
    failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
    exceptions: [
      {
        name: "web-server-fp",
        signatureId: 100001,
        sourceAddress: "web-server",
        description: "scope noisy signature to the web server object",
      },
    ],
  },
  securityProfiles: [
    {
      name: "inspect-standard",
      tlsInspection: "TLS_INSPECTION_MODE_METADATA_ONLY",
      dnsSecurity: "DNS_SECURITY_MODE_BLOCK_MALICIOUS",
      urlCategories: ["malware", "phishing"],
      fileSecurity: "FILE_SECURITY_MODE_LOG_ONLY",
      description: "Layered inspection profile for managed web egress.",
    },
  ],
};

assert.deepEqual(referenceKeys("zones", "lan"), [
  "security rule:allow-web:from zone",
  "security rule:drop-admin:to zone",
  "host-input rule:mgmt-ssh:from zone",
]);

assert.deepEqual(referenceKeys("zones", "wan"), [
  "security rule:allow-web:to zone",
  "security rule:drop-admin:from zone",
  "source NAT:lan-egress:to zone",
  "destination NAT:published-web:from zone",
]);

assert.deepEqual(referenceKeys("addresses", "web-server"), [
  "security rule:allow-web:destination address",
  "security rule:drop-admin:destination address",
  "IDS exception:web-server-fp:source address",
  "destination NAT:published-web:translated address",
]);

assert.deepEqual(referenceKeys("addresses", "client-net"), [
  "security rule:allow-web:source address",
  "source NAT:lan-egress:source address",
]);

assert.deepEqual(referenceKeys("services", "https"), [
  "security rule:allow-web:service",
  "destination NAT:published-web:service",
]);

assert.deepEqual(
  objectReferenceRecords(policy, "addresses", "client-net")
    .filter((ref) => ref.area === "source NAT")
    .map((ref) => ref.itemId),
  ["snat-lan-egress-custom"],
);
assert.deepEqual(
  objectReferenceRecords(policy, "addresses", "public-web")
    .filter((ref) => ref.area === "destination NAT")
    .map((ref) => ref.itemId),
  ["dnat-published-web-custom"],
);
assert.deepEqual(
  objectReferenceRecords(policy, "addresses", "admin-host")
    .filter((ref) => ref.area === "host-input rule")
    .map((ref) => ref.itemId),
  ["host-input-mgmt-ssh-custom"],
);

assert.deepEqual(referenceKeys("applications", "corp-admin"), [
  "security rule:allow-web:application",
]);

assert.deepEqual(referenceKeys("securityProfiles", "inspect-standard"), [
  "security rule:allow-web:security profile",
]);
assert.equal(objectExists(policy, "securityProfiles", "inspect-standard"), true);
assert.equal(objectExists(policy, "securityProfiles", "missing-profile"), false);

assert.ok(objectReferences(policy, "addresses", "web-server").includes("destination NAT: published-web (translated address)"));
assert.deepEqual(objectReferenceRecords(policy, "services", "unused"), []);
assert.deepEqual(objectReferenceRecords(policy, "services", ""), []);

{
  const zoneReview = objectRenameReviewModel(policy, "zones", "wan", "internet-edge");
  assert.deepEqual(zoneReview.affectedAreas, ["Destination NAT", "Security rules", "Source NAT"]);
  assert.equal(zoneReview.referenceCount, 4);
  assert.equal(zoneReview.rewriteCountPreview, 4);
  assert.deepEqual(zoneReview.groups.find((group) => group.area === "security rule").fields, ["to zone", "from zone"]);

  const addressReview = objectRenameReviewModel(policy, "addresses", "web-server", "web-server-renamed");
  assert.deepEqual(addressReview.affectedAreas, ["Destination NAT", "IDS exceptions", "Security rules"]);
  assert.equal(addressReview.referenceCount, 4);
  assert.equal(addressReview.rewriteCountPreview, 4);
  assert.equal(addressReview.refs.find((ref) => ref.area === "destination NAT")?.itemId, "dnat-published-web-custom");

  const serviceReview = objectRenameReviewModel(policy, "services", "https", "https-published");
  assert.deepEqual(serviceReview.affectedAreas, ["Destination NAT", "Security rules"]);
  assert.equal(serviceReview.referenceCount, 2);
  assert.equal(serviceReview.rewriteCountPreview, 2);
  assert.ok(serviceReview.groups.some((group) => group.area === "security rule" && group.label === "Security rules"));
  assert.ok(serviceReview.groups.some((group) => group.area === "destination NAT" && group.label === "Destination NAT"));

  const appReview = objectRenameReviewModel(policy, "applications", "corp-admin", "corp-admin-renamed");
  assert.deepEqual(appReview.affectedAreas, ["Security rules"]);
  assert.equal(appReview.referenceCount, 1);
  assert.equal(appReview.rewriteCountPreview, 1);

  const profileReview = objectRenameReviewModel(policy, "securityProfiles", "inspect-standard", "inspect-standard-renamed");
  assert.deepEqual(profileReview.affectedAreas, ["Security rules"]);
  assert.equal(profileReview.referenceCount, 1);
  assert.equal(profileReview.rewriteCountPreview, 1);

  assert.equal(objectRenameReviewModel(policy, "services", "https", "https").referenceCount, 0);
  assert.equal(objectRenameReviewModel(policy, "services", "", "https-new").rewriteCountPreview, 0);
}

{
  const renamed = structuredClone(policy);
  const count = rewriteObjectReferences(renamed, "services", "https", "https-published");
  assert.equal(count, 2);
  assert.deepEqual(renamed.rules[0].services, ["https-published"]);
  assert.equal(renamed.nat.destination[0].service, "https-published");
  assert.deepEqual(renamed.rules[1].services, ["admin-ui"]);
  assert.equal(renamed.hostInput.rules[0].services[0], "ssh");
  assert.deepEqual(referenceKeysForPolicy(renamed, "services", "https-published"), [
    "security rule:allow-web:service",
    "destination NAT:published-web:service",
  ]);
  assert.deepEqual(objectReferenceRecords(renamed, "services", "https"), []);
}

{
  const renamed = structuredClone(policy);
  const count = rewriteObjectReferences(renamed, "addresses", "web-server", "web-server-renamed");
  assert.equal(count, 4);
  assert.deepEqual(renamed.rules[0].destinationAddresses, ["web-server-renamed"]);
  assert.deepEqual(renamed.rules[1].destinationAddresses, ["web-server-renamed"]);
  assert.equal(renamed.ids.exceptions[0].sourceAddress, "web-server-renamed");
  assert.equal(renamed.nat.destination[0].translatedAddress, "web-server-renamed");
  assert.equal(renamed.nat.destination[0].destinationAddress, "public-web");
}

assert.deepEqual(objectReferenceTarget({ area: "security rule", item: "allow web" }), {
  href: "#/rules?rule=allow+web",
  label: "Open rule",
});
assert.deepEqual(objectReferenceTarget({ area: "host-input rule", item: "mgmt-ssh", itemId: "host-input-mgmt-ssh-custom", index: 0 }), {
  href: "#/settings?panel=host-input&rule=host-input-mgmt-ssh-custom&idx=0",
  label: "Open host input",
});
assert.deepEqual(objectReferenceTarget({ area: "host-input rule", item: "legacy-mgmt" }), {
  href: "#/settings?panel=host-input&rule=legacy-mgmt",
  label: "Open host input",
});
assert.deepEqual(objectReferenceTarget({ area: "source NAT", item: "lan-egress", index: 0 }), {
  href: "#/nat?nat=source&rule=lan-egress&idx=0",
  label: "Open source NAT",
});
assert.deepEqual(objectReferenceTarget({ area: "source NAT", item: "lan-egress", itemId: "snat-lan-egress-custom", index: 0 }), {
  href: "#/nat?nat=source&rule=snat-lan-egress-custom&idx=0",
  label: "Open source NAT",
});
assert.deepEqual(objectReferenceTarget({ area: "destination NAT", item: "published web", index: 1 }), {
  href: "#/nat?nat=destination&rule=published+web&idx=1",
  label: "Open destination NAT",
});
assert.equal(objectReferenceTarget({ area: "audit", item: "entry" }), null);

assert.deepEqual(normalizeNatFocusRoute({ nat: "source NAT", rule: " lan-egress ", idx: "0" }), {
  nat: "source",
  rule: "lan-egress",
  idx: "0",
});
assert.deepEqual(normalizeNatFocusRoute({ nat: "bad", rule: "lan-egress", idx: "0" }), {
  nat: "",
  rule: "",
  idx: "",
});
assert.deepEqual(natRuleFocusRouteState({ area: "destination NAT", item: "published web", index: 2 }), {
  nat: "destination",
  rule: "published web",
  idx: "2",
});
assert.equal(
  natRuleFocusHash({ area: "source NAT", item: "lan-egress", index: 0, srcIp: "10.0.0.10" }),
  "#/nat?nat=source&rule=lan-egress&idx=0",
);
assert.equal(
  focusedNatRuleIndex({ nat: "source", rule: "lan-egress", idx: "0" }, "source", [{ name: "other" }, { name: "lan-egress" }]),
  1,
);
assert.equal(
  focusedNatRuleIndex({ nat: "destination", rule: "shared", idx: "1" }, "destination", [{ name: "shared" }, { name: "shared" }]),
  1,
);
assert.equal(focusedNatRuleIndex({ nat: "source", rule: "#1", idx: "0" }, "source", [{}]), 0);
assert.equal(focusedNatRuleIndex({ nat: "source", rule: "lan-egress" }, "destination", [{ name: "lan-egress" }]), -1);

{
  const publishPolicy = {
    rules: [{
      name: "manual-allow",
      fromZones: ["wan"],
      toZones: ["dmz"],
      destinationAddresses: ["web-server"],
      services: ["https"],
      action: "ACTION_ALLOW",
      description: "Operator-owned exception; do not rewrite.",
    }],
  };
  const generated = upsertPublishRule(publishPolicy, {
    name: "published-web",
    fromZone: "wan",
    translatedAddress: "web-server",
    service: "https",
  }, "dmz", "manual-allow");
  assert.equal(generated, "allow-wan-to-dmz-web-server-https");
  assert.equal(publishPolicy.rules[0].name, "manual-allow");
  assert.equal(publishPolicy.rules[0].description, "Operator-owned exception; do not rewrite.");
  assert.equal(publishPolicy.rules[1].name, "allow-wan-to-dmz-web-server-https");
  assert.deepEqual(publishPolicy.rules[1].tags, ["generated:dnat-publish", "dnat:published-web"]);
  assert.equal(removeGeneratedPublishRule(publishPolicy, "manual-allow"), "");
  assert.equal(removeGeneratedPublishRule(publishPolicy, generated), generated);
  assert.equal(publishPolicy.rules.some((rule) => rule.name === generated), false);
  assert.equal(publishPolicy.rules.some((rule) => rule.name === "manual-allow"), true);
}

{
  const dnat = {
    name: "published-web",
    fromZone: "wan",
    destinationAddress: "public-web",
    translatedAddress: "web-server",
    service: "https",
  };
  const publishPolicy = { rules: [] };
  const generated = upsertPublishRule(publishPolicy, dnat, "dmz");
  assert.equal(destinationNatPublishIntentChanged(publishPolicy, dnat, {
    publishAllow: true,
    targetZone: "dmz",
    publishRuleName: generated,
  }), false);
  assert.equal(destinationNatPublishIntentChanged(publishPolicy, dnat, {
    publishAllow: true,
    targetZone: "inside",
    publishRuleName: generated,
  }), true);
  assert.equal(destinationNatPublishIntentChanged(publishPolicy, dnat, {
    publishAllow: false,
    targetZone: "dmz",
    publishRuleName: generated,
  }), true);
  assert.equal(destinationNatPublishIntentChanged({ rules: [] }, dnat, {
    publishAllow: true,
    targetZone: "dmz",
    publishRuleName: "",
  }), true);
  assert.equal(destinationNatPublishIntentChanged({ rules: [] }, dnat, {
    publishAllow: false,
    targetZone: "dmz",
    publishRuleName: "",
  }), false);
}

{
  const publishPolicy = {
    nat: {
      destination: [{
        name: "published-web",
        fromZone: "wan",
        destinationAddress: "public-web",
        translatedAddress: "web-server",
        service: "https",
      }],
    },
    rules: [{
      name: "manual-allow",
      fromZones: ["wan"],
      toZones: ["dmz"],
      destinationAddresses: ["web-server"],
      services: ["https"],
      action: "ACTION_ALLOW",
      description: "Operator-owned exception; do not remove.",
    }],
  };
  const generated = upsertPublishRule(publishPolicy, publishPolicy.nat.destination[0], "dmz");
  const result = removeDestinationNatWithPublishRule(publishPolicy, 0, {
    linkedRuleName: generated,
    removeLinkedRule: true,
  });
  assert.equal(result.removed.name, "published-web");
  assert.equal(result.linkedRuleName, generated);
  assert.equal(result.removedRuleName, generated);
  assert.equal(publishPolicy.nat, undefined);
  assert.equal(publishPolicy.rules.some((rule) => rule.name === generated), false);
  assert.equal(publishPolicy.rules.some((rule) => rule.name === "manual-allow"), true);
}

{
  const pendingPolicy = {
    addresses: [{ name: "web-server", cidr: "10.0.0.10/32", description: "operator-owned" }],
    services: [{ name: "https", protocol: "PROTOCOL_TCP", ports: [{ start: 443 }], description: "operator-owned" }],
  };
  ensurePendingAddressObjects(pendingPolicy, [{ name: "web-server", cidr: "10.0.0.99/32", description: "queued overwrite" }, { name: "public-web", cidr: "203.0.113.10/32" }]);
  ensurePendingServices(pendingPolicy, [
    { name: "https", protocol: "PROTOCOL_TCP", ports: [{ start: 8443 }] },
    { name: "bad-service", protocol: "PROTOCOL_TCP", ports: [{ start: 0 }] },
    { name: "admin-https", protocol: "PROTOCOL_TCP", ports: [{ start: 8443 }] },
  ]);
  assert.deepEqual(pendingPolicy.addresses.find((item) => item.name === "web-server"), { name: "web-server", cidr: "10.0.0.10/32", description: "operator-owned" });
  assert.deepEqual(pendingPolicy.addresses.find((item) => item.name === "public-web"), { name: "public-web", cidr: "203.0.113.10/32" });
  assert.deepEqual(pendingPolicy.services.find((item) => item.name === "https"), { name: "https", protocol: "PROTOCOL_TCP", ports: [{ start: 443 }], description: "operator-owned" });
  assert.equal(pendingPolicy.services.some((item) => item.name === "bad-service"), false);
  assert.deepEqual(pendingPolicy.services.find((item) => item.name === "admin-https"), { name: "admin-https", protocol: "PROTOCOL_TCP", ports: [{ start: 8443 }] });
  assert.deepEqual(validateNatServicePorts("443, 8000-8002"), { ok: true, ports: [{ start: 443 }, { start: 8000, end: 8002 }] });
  assert.equal(validateNatServicePorts("70000").ok, false);
  assert.equal(validateNatServicePorts("8443-443").ok, false);
}

{
  const collectedAt = "2026-06-18T12:00:00.000Z";
  const refs = objectReferenceRecords(policy, "addresses", "web-server");
  const packet = objectReferenceHandoffPacket({
    kind: "addresses",
    name: "web-server",
    refs,
    source: "candidate",
    referenceSource: "Reference data from /v1/policy/object-references.",
    route: "#/objects?drawer=references&object=web-server",
  }, { collectedAt });
  const json = JSON.parse(investigationPacketJson(packet));
  assert.equal(json.kind, "object-reference-review");
  assert.equal(json.subject.id, "addresses:web-server");
  assert.equal(json.summary.objectKind, "address");
  assert.equal(json.summary.referenceCount, 4);
  assert.equal(json.source.route, "#/objects?drawer=references&object=web-server");
  assert.equal(json.artifacts.references[2].area, "IDS exception");
  assert.equal(json.artifacts.references[3].itemId, "dnat-published-web-custom");
  assert.ok(json.evidence.some((line) => line.includes("destination NAT: published-web [dnat-published-web-custom]")));
  assert.equal(
    investigationPacketFilename(packet, new Date(collectedAt)),
    "phragma-investigation-object-reference-review-addresses-web-server-2026-06-18T12-00-00-000Z.json",
  );
}

{
  const collectedAt = "2026-06-20T12:00:00.000Z";
  const model = securityProfileImpactModel(policy, "inspect-standard", {
    source: "candidate",
    running: { securityProfiles: [] },
    referenceSource: "Reference data from /v1/policy/object-references.",
  });
  assert.equal(model.exists, true);
  assert.equal(model.candidateOnly, true);
  assert.equal(model.blockingIntent, true);
  assert.equal(model.failClosedReady, true);
  assert.equal(model.affectedRuleCount, 1);
  assert.equal(model.allowRuleCount, 1);
  assert.equal(model.blockingAllowRuleCount, 1);
  assert.equal(model.affectedRules[0].coverage.state, "profile-enforced");
  assert.equal(model.intents.dns, "block malicious");
  assert.deepEqual(model.intents.urlCategories, ["malware", "phishing"]);
  assert.equal(model.posture.state, "review");
  assert.deepEqual(model.blockers, []);
  assert.ok(model.warnings.some((line) => /candidate until commit/.test(line)));
  assert.equal(model.controls.length, 4);
  assert.ok(model.controls.some((control) => control.key === "tls" && /No CA key custody/.test(control.boundary)));
  assert.ok(model.enforcementBoundaries.some((line) => /candidate policy only/.test(line)));

  const packet = securityProfileImpactHandoffPacket(model, {
    route: "#/objects?tab=securityProfiles&drawer=impact&object=inspect-standard",
    collectedAt,
  });
  const json = JSON.parse(investigationPacketJson(packet));
  assert.equal(json.kind, "security-profile-impact");
  assert.equal(json.subject.id, "inspect-standard");
  assert.equal(json.summary.affectedRuleCount, 1);
  assert.equal(json.summary.blockingAllowRuleCount, 1);
  assert.equal(json.summary.failClosedReady, true);
  assert.equal(json.summary.posture, "review required");
  assert.equal(json.summary.warningCount, 1);
  assert.match(json.summary.enforcementBoundary, /file extraction\/scanning evidence remain hardening/);
  assert.equal(json.source.route, "#/objects?tab=securityProfiles&drawer=impact&object=inspect-standard");
  assert.equal(json.artifacts.affectedRules[0].coverageState, "profile-enforced");
  assert.equal(json.artifacts.workflow.controls.length, 4);
  assert.ok(json.evidence.some((line) => line.includes("rule: allow-web")));
  assert.ok(json.evidence.some((line) => line.includes("boundary: Objects stage declarative inspection intent")));
  assert.equal(
    investigationPacketFilename(packet, new Date(collectedAt)),
    "phragma-investigation-security-profile-impact-inspect-standard-2026-06-20T12-00-00-000Z.json",
  );
}

{
  const workflow = securityProfileWorkflowModel({
    name: "decrypt-block",
    tlsInspection: "TLS_INSPECTION_MODE_DECRYPTION_REQUIRED",
    dnsSecurity: "DNS_SECURITY_MODE_BLOCK_MALICIOUS",
    urlCategories: ["Malware", "Malware"],
    fileSecurity: "FILE_SECURITY_MODE_BLOCK_HIGH_RISK",
  }, {
    exists: true,
    affectedRuleCount: 2,
    allowRuleCount: 2,
    blockingIntent: true,
    failClosedReady: false,
    candidateOnly: true,
  });
  assert.equal(workflow.posture.state, "blocked");
  assert.ok(workflow.blockers.some((line) => /TLS decryption-required intent/.test(line)));
  assert.ok(workflow.blockers.some((line) => /must be lowercase/.test(line)));
  assert.ok(workflow.blockers.some((line) => /requires IDS\/IPS Prevent/.test(line)));
  assert.ok(workflow.warnings.some((line) => /live TLS broker/.test(line)));
  assert.ok(workflow.warnings.some((line) => /live file extraction\/scanning proof/.test(line)));
  assert.deepEqual(workflow.controls.map((control) => control.key), ["tls", "dns", "url", "file"]);
}

{
  const model = securityProfileImpactModel(policy, "missing-profile", {
    source: "candidate",
    running: policy,
  });
  assert.equal(model.exists, false);
  assert.equal(model.affectedRuleCount, 0);
  assert.equal(model.blockingIntent, false);
  assert.equal(model.posture.state, "blocked");
  assert.ok(model.blockers.some((line) => /not present/.test(line)));
  const json = JSON.parse(investigationPacketJson(securityProfileImpactHandoffPacket(model, {
    route: "#/objects?tab=securityProfiles&drawer=impact&object=missing-profile",
    collectedAt: "2026-06-20T12:05:00.000Z",
  })));
  assert.equal(json.summary.exists, false);
  assert.equal(json.summary.blockerCount, 1);
  assert.ok(json.evidence.some((line) => line === "object exists: no"));
}

const candidateKey = objectReferenceCacheKey({
  source: "POLICY_SOURCE_CANDIDATE",
  runningVersion: 7,
  kind: "addresses",
  draft: policy,
});
const changedCandidateKey = objectReferenceCacheKey({
  source: "POLICY_SOURCE_CANDIDATE",
  runningVersion: 7,
  kind: "addresses",
  draft: {
    ...policy,
    rules: [...policy.rules, { name: "new-ref", destinationAddresses: ["web-server"] }],
  },
});
assert.notEqual(candidateKey, changedCandidateKey);

const runningKey = objectReferenceCacheKey({
  source: "POLICY_SOURCE_RUNNING",
  runningVersion: 7,
  kind: "addresses",
  draft: policy,
});
const changedDraftRunningKey = objectReferenceCacheKey({
  source: "POLICY_SOURCE_RUNNING",
  runningVersion: 7,
  kind: "addresses",
  draft: {
    ...policy,
    rules: [...policy.rules, { name: "ignored-draft-change", destinationAddresses: ["web-server"] }],
  },
});
assert.equal(runningKey, changedDraftRunningKey);
assert.notEqual(runningKey, objectReferenceCacheKey({
  source: "POLICY_SOURCE_RUNNING",
  runningVersion: 8,
  kind: "addresses",
  draft: policy,
}));

const hygienePolicy = {
  addresses: [
    { name: "web-a", cidr: "10.0.0.10/32" },
    { name: "web-b", cidr: " 10.0.0.10/32 " },
  ],
  services: [
    { name: "https", protocol: "PROTOCOL_TCP", ports: [{ start: 443 }] },
    { name: "web-tls", protocol: "PROTOCOL_TCP", ports: [{ start: 443, end: 443 }] },
  ],
  applications: [
    { name: "corp-admin", engineSignals: ["corp-admin"], ports: [{ protocol: "PROTOCOL_TCP", ports: [{ start: 8443 }] }] },
    { name: "corp-admin-v2", engineSignals: ["CORP-ADMIN"], ports: [{ protocol: "PROTOCOL_TCP", ports: [{ start: 8443, end: 8443 }] }] },
    { name: "signal-only", engineSignals: ["other"] },
    { name: "signal-only-copy", engineSignals: ["another"] },
  ],
  zones: [
    { name: "lan", interfaces: ["eth1", "eth2"] },
    { name: "guest", interfaces: ["eth2"] },
    { name: "dmz", interfaces: ["eth3", "eth3"] },
  ],
};

{
  const findings = objectHygieneFindings(hygienePolicy, "addresses");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].title, "Duplicate address CIDR");
  assert.deepEqual(findings[0].names, ["web-a", "web-b"]);
}

{
  const findings = objectHygieneFindings(hygienePolicy, "services");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].signature, "PROTOCOL_TCP 443");
}

{
  const findings = objectHygieneFindings(hygienePolicy, "applications");
  assert.equal(findings.some((finding) => finding.title === "Duplicate application port hints"), true);
  assert.equal(findings.some((finding) => finding.title === "Duplicate App-ID engine signal"), true);
  const noPortHints = findings.find((finding) => finding.signature === "no-port-hints");
  assert.equal(noPortHints.title, "App-ID without port hints");
  assert.deepEqual(noPortHints.names, ["signal-only", "signal-only-copy"]);
  assert.match(noPortHints.detail, /TCP\/UDP port hints or a supported IDS\/IPS signal/);
}

{
  const findings = objectHygieneFindings(hygienePolicy, "zones");
  assert.equal(findings.some((finding) => /multiple zones/.test(finding.title) && finding.signature === "eth2"), true);
  assert.equal(findings.some((finding) => /Duplicate zone interface/.test(finding.title) && finding.signature === "eth3"), true);
}

{
  const findings = objectHygieneFindings(hygienePolicy);
  assert.equal(findings.length, 7);
}

function referenceKeys(kind, name) {
  return referenceKeysForPolicy(policy, kind, name);
}

function referenceKeysForPolicy(targetPolicy, kind, name) {
  return objectReferenceRecords(targetPolicy, kind, name).map((ref) => `${ref.area}:${ref.item}:${ref.field}`);
}
