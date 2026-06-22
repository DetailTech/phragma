import assert from "node:assert/strict";

import { interfaceMtuEditorModel, normalizeInterfaceMtus, parseCustomInterfaceMtus } from "./network_settings.js";

{
  const model = interfaceMtuEditorModel(
    {
      interfaceMtus: [
        { interface: "mgmt0", mtu: 1500 },
        { interface: "wan0", mtu: 1500 },
        { interface: "lan0", mtu: 9000 },
        { interface: "ha0", mtu: 9000 },
      ],
    },
    {
      zones: [
        { name: "wan", interfaces: ["wan0"] },
        { name: "lan", interfaces: ["lan0"] },
      ],
    },
  );

  assert.deepEqual(model.rows, [
    { iface: "lan0", mtu: 9000 },
    { iface: "wan0", mtu: 1500 },
  ]);
  assert.equal(model.customText, "ha0=9000\nmgmt0=1500");
}

{
  const model = interfaceMtuEditorModel(
    { interfaceMtus: [{ interface: "mgmt0", mtu: 1500 }] },
    { zones: [{ name: "lan", interfaces: ["lan0"] }] },
  );

  assert.deepEqual(model.rows, [{ iface: "lan0", mtu: "" }]);
  assert.equal(model.customText, "mgmt0=1500");
}

{
  assert.deepEqual(parseCustomInterfaceMtus("mgmt0=1500\nha0 9000,bad-line"), [
    { interface: "mgmt0", mtu: 1500 },
    { interface: "ha0", mtu: 9000 },
    { interface: "bad-line", mtu: 0 },
  ]);
}

{
  assert.deepEqual(normalizeInterfaceMtus([
    { interface: "wan0", mtu: "1500" },
    { interface: "", mtu: 9000 },
    { interface: "lan0", mtu: 0 },
    { interface: "mgmt0", mtu: 9000 },
  ]), [
    { interface: "mgmt0", mtu: 9000 },
    { interface: "wan0", mtu: 1500 },
  ]);
}
