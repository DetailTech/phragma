import assert from "node:assert/strict";

import { natEvidence, natProfileLines, natProfileSummary } from "./explain_profiles.js";

const profile = {
  evidence: ["dnat public-https evidence"],
  destination: {
    evaluated: true,
    matched: true,
    matchedRule: "public-https",
    originalDestinationIp: "203.0.113.10",
    originalDestinationPort: 443,
    translatedDestinationIp: "10.0.2.20",
    translatedDestinationPort: 8443,
    evidence: ["dnat public-https evidence"],
  },
  source: {
    evaluated: true,
    matched: true,
    matchedRule: "trust-snat",
    originalSourceIp: "10.0.1.20",
    translatedSourceIp: "10.0.2.10",
    evidence: ["snat trust-snat evidence"],
  },
};

assert.deepEqual(natProfileLines(profile), [
  "destination NAT public-https: 203.0.113.10:443 -> 10.0.2.20:8443",
  "source NAT trust-snat: 10.0.1.20 -> 10.0.2.10",
]);
assert.equal(natProfileSummary(profile), "DNAT + SNAT");
assert.deepEqual(natEvidence(profile), ["dnat public-https evidence", "snat trust-snat evidence"]);

assert.deepEqual(natProfileLines({
  destination: { evaluated: true, reason: "no destination NAT rule matched before policy evaluation" },
  source: { evaluated: false, reason: "source NAT not evaluated because policy verdict is default_drop" },
}), [
  "destination NAT: no destination NAT rule matched before policy evaluation",
  "source NAT: source NAT not evaluated because policy verdict is default_drop",
]);

assert.deepEqual(natProfileLines({
  source: {
    evaluated: true,
    matched: true,
    matchedRule: "egress-masq",
    originalSourceIp: "10.0.1.20",
    masquerade: true,
  },
}), ["source NAT egress-masq: 10.0.1.20 -> masquerade"]);
