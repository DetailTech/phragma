import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  focusedNatRuleIndex,
  natMutationContext,
  natRuleFocusHash,
  natRuleFocusRouteState,
} from "./views/nat.js";

const settingsSource = readFileSync(new URL("./views/settings.js", import.meta.url), "utf8");
const natSource = readFileSync(new URL("./views/nat.js", import.meta.url), "utf8");

assert.equal(
  focusedNatRuleIndex(
    { nat: "source", rule: "snat-3f45", idx: "1" },
    "source",
    [{ id: "snat-3f45", name: "renamed-egress" }, { id: "snat-legacy", name: "snat-3f45" }],
  ),
  0,
  "NAT route focus prefers durable IDs over names",
);

assert.equal(
  focusedNatRuleIndex(
    { nat: "destination", rule: "published-web", idx: "1" },
    "destination",
    [{ name: "published-web" }, { name: "published-web" }],
  ),
  1,
  "legacy duplicated NAT names still use idx disambiguation",
);

assert.deepEqual(
  natRuleFocusRouteState({ area: "destination NAT", id: "dnat-7742", item: "published-web", index: 2 }),
  { nat: "destination", rule: "dnat-7742", idx: "2" },
  "NAT route state emits durable ID when available",
);

assert.equal(
  natRuleFocusHash({ area: "source NAT", id: "snat-22", item: "lan-egress", index: 0 }),
  "#/nat?nat=source&rule=snat-22&idx=0",
  "NAT hash is stable for durable ID focused routes",
);

const sourceUpdateById = natMutationContext("source", "update",
  { id: "snat-22", name: "lan-egress", toZone: "outside", masquerade: true },
  { id: "snat-22", name: "lan-egress-renamed", toZone: "outside", sourceAddress: "inside-net", translatedAddress: "egress-ip" });
assert.equal(sourceUpdateById.method, "PUT");
assert.equal(sourceUpdateById.path, "/v1/candidate/nat/source/by-id/snat-22");
assert.equal(sourceUpdateById.selectorKind, "id");
assert.equal(sourceUpdateById.body.id, "snat-22");
assert.equal(sourceUpdateById.body.rule.id, "snat-22");
assert.equal(sourceUpdateById.body.rule.name, "lan-egress-renamed");
assert.match(sourceUpdateById.cli, /ngfwctl policy nat source upsert --id snat-22 --name lan-egress-renamed/);

const destinationDeleteById = natMutationContext("destination", "delete",
  { id: "dnat-77", name: "public-web", fromZone: "outside", service: "https", destinationAddress: "public-web", translatedAddress: "dmz-web" });
assert.equal(destinationDeleteById.method, "DELETE");
assert.equal(destinationDeleteById.path, "/v1/candidate/nat/destination/by-id/dnat-77");
assert.equal(destinationDeleteById.selectorKind, "id");
assert.equal(destinationDeleteById.body, null);
assert.match(destinationDeleteById.cli, /ngfwctl policy nat destination delete --id dnat-77/);
assert.doesNotMatch(destinationDeleteById.cli, /--name/);

const legacySourceDelete = natMutationContext("source", "delete", { name: "legacy egress" });
assert.equal(legacySourceDelete.path, "/v1/candidate/nat/source/legacy%20egress");
assert.equal(legacySourceDelete.selectorKind, "name");
assert.match(legacySourceDelete.cli, /ngfwctl policy nat source delete --name 'legacy egress'/);
assert.doesNotMatch(legacySourceDelete.path, /by-id/);

const legacyDestinationUpdate = natMutationContext("destination", "update",
  { name: "legacy-web" },
  { name: "legacy-web", fromZone: "outside", service: "https", destinationAddress: "public-web", translatedAddress: "dmz-web", translatedPort: 8443 });
assert.equal(legacyDestinationUpdate.path, "/v1/candidate/nat/destination/legacy-web");
assert.equal(legacyDestinationUpdate.selectorKind, "name");
assert.equal(legacyDestinationUpdate.body.rule.translatedPort, 8443);
assert.match(legacyDestinationUpdate.cli, /ngfwctl policy nat destination upsert --name legacy-web --from-zone outside/);
assert.doesNotMatch(legacyDestinationUpdate.cli, /--id/);

assert.match(natSource, /if \(previous\?\.id\) item\.id = previous\.id;/, "NAT editors preserve existing durable IDs");
assert.match(natSource, /api\.upsertCandidateSourceNat/, "Source NAT editor can stage pure NAT changes through the granular API");
assert.match(natSource, /api\.upsertCandidateDestinationNat/, "Destination NAT editor can stage pure NAT changes through the granular API");
assert.match(natSource, /api\.deleteCandidateSourceNat/, "Source NAT delete uses the granular candidate API");
assert.match(natSource, /api\.deleteCandidateDestinationNat/, "Destination NAT delete can use the granular candidate API");
assert.match(natSource, /pendingNatObjectsChange\(session\.draft \|\| \{\}, inputs\.pendingAddresses \|\| \[\], inputs\.pendingServices \|\| \[\]\)/, "Destination NAT keeps full candidate staging for compound object changes");
assert.match(natSource, /dataset: \{ natFocusMissing: "true"/, "NAT route focus exposes stale target guidance");
assert.match(natSource, /Copy durable NAT route and API context/, "NAT rows expose compact durable route and API context copy");
assert.match(natSource, /Copy legacy NAT route and API context/, "NAT rows expose legacy name fallback route and API context copy");

assert.match(settingsSource, /HOST_INPUT_FOCUS_DEFAULTS = Object\.freeze\(\{ panel: "", rule: "", idx: "" \}\)/, "Settings accepts host-input rule focus route state");
assert.match(settingsSource, /hostInputRuleDurableId\(rule\) === wantedRule/, "Host-input focus prefers durable IDs");
assert.match(settingsSource, /if \(existing\.id\) rule\.id = existing\.id;/, "Host-input editor preserves existing durable IDs");
assert.match(settingsSource, /Copy durable host-input route/, "Host-input rows expose compact durable route copy");
assert.match(settingsSource, /dataset: \{ hostInputFocusMissing: "true"/, "Host-input route focus exposes stale target guidance");
