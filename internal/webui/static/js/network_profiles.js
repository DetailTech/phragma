export const NETWORK_PROFILES = [
  {
    id: "throughput",
    title: "Forwarding throughput",
    detail: "Jumbo MTU, MSS clamp, and forwarding acceleration for L3/L4 forwarding-only policies.",
    requiresInspectionOff: true,
    settings: {
      mtu: 9000,
      clampMssToPmtu: true,
      manageNicOffloads: false,
      enableFlowOffload: true,
    },
  },
  {
    id: "inspection",
    title: "IDS/IPS inspected",
    detail: "Disables forwarding acceleration and manages NIC offloads so IDS/IPS inspection sees real packet frames.",
    settings: {
      mtu: 0,
      clampMssToPmtu: true,
      manageNicOffloads: true,
      enableFlowOffload: false,
    },
  },
  {
    id: "edge-vpn",
    title: "Internet / VPN edge",
    detail: "Standard MTU with TCP MSS clamp for tunnels, mixed peers, and conservative WAN paths.",
    settings: {
      mtu: 1500,
      clampMssToPmtu: true,
      manageNicOffloads: false,
      enableFlowOffload: false,
    },
  },
];

export function applyNetworkProfile(network = {}, profileId) {
  const profile = NETWORK_PROFILES.find((item) => item.id === profileId);
  if (!profile) return structuredClone(network || {});
  return {
    ...(network || {}),
    ...profile.settings,
    interfaceMtus: Array.isArray(network?.interfaceMtus) ? structuredClone(network.interfaceMtus) : [],
  };
}

export function networkProfileBlockers(policy = {}, profileId) {
  const profile = NETWORK_PROFILES.find((item) => item.id === profileId);
  if (!profile) return [`Unknown network profile "${profileId}".`];
  if (profile.requiresInspectionOff && policy?.ids?.enabled) {
    return ["Forwarding throughput profile requires IDS/IPS disabled because acceleration bypasses first-packet inspection after offload."];
  }
  return [];
}

export function applyNetworkProfileToPolicy(policy = {}, profileId) {
  const profile = NETWORK_PROFILES.find((item) => item.id === profileId);
  const blockers = networkProfileBlockers(policy, profileId);
  const next = structuredClone(policy || {});
  if (blockers.length) return { ok: false, profile, blockers, policy: next };
  next.network = applyNetworkProfile(next.network || {}, profileId);
  return { ok: true, profile, blockers: [], policy: next };
}

export function matchingNetworkProfile(network = {}) {
  const normalized = comparableNetworkSettings(network);
  return NETWORK_PROFILES.find((profile) => {
    const expected = comparableNetworkSettings(profile.settings);
    return normalized.mtu === expected.mtu &&
      normalized.clampMssToPmtu === expected.clampMssToPmtu &&
      normalized.manageNicOffloads === expected.manageNicOffloads &&
      normalized.enableFlowOffload === expected.enableFlowOffload;
  }) || null;
}

function comparableNetworkSettings(network = {}) {
  return {
    mtu: Number(network?.mtu) || 0,
    clampMssToPmtu: Boolean(network?.clampMssToPmtu),
    manageNicOffloads: Boolean(network?.manageNicOffloads),
    enableFlowOffload: Boolean(network?.enableFlowOffload),
  };
}
