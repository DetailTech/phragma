import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  exceptionPolicyState,
  exceptionEvidenceModel,
  exceptionScope,
  exceptionScopeModel,
  exceptionThreatLabel,
} from "./views/ids.js";

const idsViewSource = readFileSync(new URL("./views/ids.js", import.meta.url), "utf8");
assert.match(idsViewSource, /type: "button", title: "Edit IDS\/IPS inspection profile"/);
assert.match(idsViewSource, /"aria-label": action\.label/);
assert.match(idsViewSource, /type: "button", title: "Stage IDS\/IPS settings"/);
assert.match(idsViewSource, /type: "button", title: `Remove IDS exception \$\{ex\.name \|\| ex\.signatureId \|\| i\}`/);
assert.match(idsViewSource, /type: "button", title: lbl, "aria-label": lbl/);
assert.match(idsViewSource, /function evidenceCell/);
assert.match(idsViewSource, /No PCAP or regression reference/);

const runningException = {
  name: "fp-9000001-source-10-0-1-10",
  signatureId: 9000001,
  threatId: "phragma.test.web",
  description: "known lab false positive",
  sourceAddress: "inside-test-host",
};

assert.deepEqual(exceptionThreatLabel(runningException), {
  threatId: "phragma.test.web",
  signature: "SID 9000001",
  name: "fp-9000001-source-10-0-1-10",
});

assert.deepEqual(exceptionThreatLabel({}), {
  threatId: "—",
  signature: "SID —",
  name: "(unnamed exception)",
});

assert.deepEqual(exceptionScopeModel(runningException), {
  kind: "source",
  object: "inside-test-host",
  detail: "source address object",
});
assert.equal(exceptionScope({ destinationAddress: "outside-web" }), "destination outside-web");
assert.equal(exceptionScope({}), "global");

assert.deepEqual(exceptionEvidenceModel({
  pcapSha256: "A".repeat(64),
  regressionRef: "evidence/fp-regression.json",
}), {
  pcapSha256: "a".repeat(64),
  pcapShort: "a".repeat(16),
  regressionRef: "evidence/fp-regression.json",
  hasEvidence: true,
  label: `pcap ${"a".repeat(16)} · evidence/fp-regression.json`,
});
assert.equal(exceptionEvidenceModel({}).label, "No PCAP or regression reference");

assert.deepEqual(exceptionPolicyState(runningException, { exceptions: [runningException] }), {
  label: "running",
  cls: "ok",
  detail: "Matches the running policy.",
  withDot: true,
});

assert.deepEqual(exceptionPolicyState({
  ...runningException,
  name: "fp-9000001-source-lab-2",
  sourceAddress: "inside-test-host-2",
}, { exceptions: [runningException] }), {
  label: "candidate",
  cls: "violet",
  detail: "Staged only; commit before IDS/IPS engine receives the suppression.",
  withDot: false,
});

assert.deepEqual(exceptionPolicyState({
  ...runningException,
  description: "updated operator reason",
}, { exceptions: [runningException] }), {
  label: "candidate edit",
  cls: "violet",
  detail: "Differs from the running exception until commit.",
  withDot: false,
});

assert.deepEqual(exceptionPolicyState({
  ...runningException,
  disabled: true,
}, { exceptions: [runningException] }), {
  label: "disabled",
  cls: "neutral",
  detail: "Disabled in candidate policy.",
  withDot: false,
});
