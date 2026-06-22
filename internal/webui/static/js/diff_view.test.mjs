import assert from "node:assert/strict";

import { normalizePolicyDiffLines, redactPolicyDiffText } from "./diff_view.js";

const rawLine = '+    "pskFile": "/etc/phragma/secrets/site-smoke.psk",';
const redacted = redactPolicyDiffText(rawLine);

assert.match(redacted, /managedSecretPath/);
assert.match(redacted, /<redacted>/);
assert.doesNotMatch(redacted, /pskFile|psk_file|privateKeyFile|private_key_file|\/etc\/phragma|site-smoke\.psk/);

const normalized = normalizePolicyDiffLines([
  { type: "POLICY_DIFF_LINE_TYPE_ADD", text: '+    "privateKeyFile": "/etc/openngfw/keys/wg0.key",' },
]);

assert.equal(normalized[0].t, "add");
assert.doesNotMatch(normalized[0].s, /privateKeyFile|private_key_file|\/etc\/openngfw|wg0\.key/);
