import { zoneInterfaces } from "./dataplane.js";

export function interfaceMtuEditorModel(network = {}, policy = {}) {
  const overrides = new Map(normalizeInterfaceMtus(network.interfaceMtus || [])
    .map((item) => [item.interface, item.mtu]));
  const zoneNames = new Set(zoneInterfaces(policy));
  const rows = [...zoneNames].sort().map((iface) => ({
    iface,
    mtu: overrides.get(iface) || "",
  }));
  const customText = [...overrides.entries()]
    .filter(([iface]) => !zoneNames.has(iface))
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([iface, mtu]) => `${iface}=${mtu}`)
    .join("\n");
  return { rows, customText };
}

export function parseCustomInterfaceMtus(text = "") {
  return String(text || "")
    .split(/\n|,/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const m = line.match(/^([^=\s]+)\s*(?:=|\s+)\s*(\S+)$/);
      if (!m) return { interface: line, mtu: 0 };
      const mtu = parseInt(m[2], 10);
      return { interface: m[1].trim(), mtu: Number.isFinite(mtu) ? mtu : 0 };
    });
}

export function normalizeInterfaceMtus(items = []) {
  return [...items]
    .filter((item) => item?.interface && Number(item.mtu) > 0)
    .map((item) => ({ interface: item.interface, mtu: Number(item.mtu) }))
    .sort((a, b) => a.interface.localeCompare(b.interface));
}
