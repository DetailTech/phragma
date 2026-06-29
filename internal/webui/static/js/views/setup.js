// Guided setup - first-run policy posture builder. The page stages ordinary
// Phragma policy objects through the same candidate path as manual editors.

import { h, icon, clear } from "../core.js";
import { api } from "../api.js";
import { openAutomationContext } from "../automation_context.js";
import { buildContentPosture } from "../content_posture.js";
import { session } from "../policy.js";
import { BASELINE_PROFILES, applyBaselinePolicy, previewBaselinePolicy } from "../baseline.js";
import { kernelTuningRollup } from "../dataplane.js";
import * as fmt from "../format.js";
import { SETUP_ROUTE_KEYS, normalizeSetupConfig, setupBaselineCliCommand, setupConfigFromQuery, setupRouteHashFromConfig } from "../setup_context.js";
import { pageHead, card, pill, toast, confirmDialog, labeledCell, responsiveTable } from "../ui.js";

const state = {
  scenario: "cloud-edge",
  profile: "throughput",
  insideZone: "lan",
  outsideZone: "wan",
  insideInterfaces: "eth1",
  outsideInterfaces: "eth0",
  insideCidr: "10.0.0.0/24",
  webuiPort: "8080",
  mtu: "",
  allowOutbound: true,
  masquerade: true,
  hardenHostInput: true,
  clampMss: true,
  flowOffload: true,
  manageNicOffloads: false,
  idsRuleFiles: "local.rules",
  idsQueueNum: "0",
  failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
};

export const SETUP_SCENARIOS = [
  {
    id: "cloud-edge",
    title: "Cloud edge",
    summary: "Internet edge with SNAT, scoped management, and MSS clamp.",
    guidance: {
      fit: "Public edge gateway for one inside zone reaching the internet through a routed outside interface.",
      staged: "Logged outbound allow, source NAT masquerade, host-input default deny, inside SSH/WebUI allow, MSS clamp, and throughput fast path.",
      review: "Confirm the outside interface is the internet-facing NIC, inside CIDR matches the workload subnet, and TLS/auth are enabled before commit.",
      excluded: "No inbound publish, VPN, or IDS/IPS content rollout is staged by this preset.",
    },
    config: {
      profile: "throughput",
      insideZone: "lan",
      outsideZone: "wan",
      insideInterfaces: "eth1",
      outsideInterfaces: "eth0",
      insideCidr: "10.0.0.0/24",
      webuiPort: "8080",
      allowOutbound: true,
      masquerade: true,
      hardenHostInput: true,
      clampMss: true,
      flowOffload: true,
      manageNicOffloads: false,
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
    },
  },
  {
    id: "east-west",
    title: "East-west",
    summary: "Internal zone boundary with no default SNAT.",
    guidance: {
      fit: "Internal segmentation point between application and data zones where upstream routing already knows both sides.",
      staged: "Logged app-to-db allow posture, IDS detect mode, host-input default deny, management allow, MSS clamp, and NIC offload management.",
      review: "Confirm return routes exist without SNAT and review detection-only inspection evidence before treating this as enforcement.",
      excluded: "Source NAT, internet-edge assumptions, and inline prevention are not staged by this preset.",
    },
    config: {
      profile: "ids-detect",
      insideZone: "app",
      outsideZone: "db",
      insideInterfaces: "eth1",
      outsideInterfaces: "eth2",
      insideCidr: "10.10.0.0/24",
      webuiPort: "8080",
      allowOutbound: true,
      masquerade: false,
      hardenHostInput: true,
      clampMss: true,
      flowOffload: false,
      manageNicOffloads: true,
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
    },
  },
  {
    id: "vpn-edge",
    title: "VPN edge",
    summary: "Branch edge posture without generated tunnel secrets.",
    guidance: {
      fit: "Branch or remote-network edge where protected traffic will later cross a modeled VPN interface.",
      staged: "Branch-to-VPN allow posture, IDS detect mode, host-input default deny, management allow, MSS clamp, and offload management.",
      review: "Create the WireGuard or IPsec tunnel in Routing & VPN, verify protected subnets, and validate routing before commit.",
      excluded: "Tunnel peers, private keys, PSKs, enrollment bundles, and VPN route proofs are intentionally not staged here.",
    },
    config: {
      profile: "ids-detect",
      insideZone: "branch",
      outsideZone: "vpn",
      insideInterfaces: "eth1",
      outsideInterfaces: "wg0",
      insideCidr: "10.20.0.0/24",
      webuiPort: "8080",
      allowOutbound: true,
      masquerade: false,
      hardenHostInput: true,
      clampMss: true,
      flowOffload: false,
      manageNicOffloads: true,
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
    },
  },
  {
    id: "ids-tap",
    title: "IDS tap",
    summary: "Passive inspection with no outbound allow or NAT.",
    guidance: {
      fit: "Passive monitoring deployment where mirrored traffic is observed but the firewall should not forward by default.",
      staged: "IDS detect mode, host-input default deny, management allow, monitor-zone objects, and NIC offload management.",
      review: "Confirm mirror/SPAN cabling and capture visibility; validate that no forwarding or source NAT path is introduced.",
      excluded: "Outbound allow and source NAT are not staged by this preset.",
    },
    config: {
      profile: "ids-detect",
      insideZone: "tap",
      outsideZone: "monitor",
      insideInterfaces: "eth1",
      outsideInterfaces: "eth2",
      insideCidr: "10.30.0.0/24",
      webuiPort: "8080",
      allowOutbound: false,
      masquerade: false,
      hardenHostInput: true,
      clampMss: false,
      flowOffload: false,
      manageNicOffloads: true,
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
    },
  },
  {
    id: "lab",
    title: "Lab mode",
    summary: "Sandbox baseline with explicit management coverage.",
    guidance: {
      fit: "Disposable lab or evaluation subnet where repeatable candidate review matters more than production defaults.",
      staged: "Logged outbound allow, source NAT masquerade, host-input default deny, explicit management allow, and conservative routing defaults.",
      review: "Replace documentation CIDRs and interface names with lab values before staging, then discard or commit only in the lab.",
      excluded: "Production content custody, HA, VPN secrets, and real internet-edge assumptions are not staged by this preset.",
    },
    config: {
      profile: "throughput",
      insideZone: "lab",
      outsideZone: "uplink",
      insideInterfaces: "eth1",
      outsideInterfaces: "eth0",
      insideCidr: "192.0.2.0/24",
      webuiPort: "8080",
      allowOutbound: true,
      masquerade: true,
      hardenHostInput: true,
      clampMss: false,
      flowOffload: false,
      manageNicOffloads: false,
      failureBehavior: "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED",
    },
  },
];

let setupStatus = null;
let setupStatusError = null;
let setupOidcStatus = { enabled: false };
let setupFeeds = [];
let setupContentPackages = [];
let setupContentError = "";

export async function render(ctx = {}) {
  restoreSetupRouteState(ctx.query || {});
  const [sessionResult, statusResult, oidcResult, feedsResult, contentResult] = await Promise.allSettled([
    session.load(),
    api.status(),
    api.authStatus(),
    api.feeds(),
    api.contentPackages(),
  ]);
  if (sessionResult.status !== "fulfilled") throw sessionResult.reason;
  setupStatus = statusResult.status === "fulfilled" ? statusResult.value : null;
  setupStatusError = statusResult.status === "rejected" ? statusResult.reason : null;
  setupOidcStatus = oidcResult.status === "fulfilled" ? oidcResult.value : { enabled: false };
  setupFeeds = feedsResult.status === "fulfilled" ? (feedsResult.value?.feeds || []) : [];
  setupContentPackages = contentResult.status === "fulfilled" ? (contentResult.value?.packages || []) : [];
  setupContentError = contentResult.status === "rejected" ? contentResult.reason?.message || "Content package status unavailable." : contentResult.value?.error || "";
  const root = h("div", {});
  paint(root);
  return root;
}

export function restoreSetupRouteState(query = {}) {
  if (!hasSetupRouteState(query)) return { restored: false, config: { ...state } };
  const restored = normalizeSetupConfig(setupConfigFromQuery(query, state));
  Object.assign(state, restored);
  return { restored: true, config: { ...state } };
}

function hasSetupRouteState(query = {}) {
  const has = (key) => {
    if (query instanceof URLSearchParams) {
      const value = query.get(key);
      return value !== null && value !== "";
    }
    return query?.[key] !== undefined && query?.[key] !== null && query?.[key] !== "";
  };
  return SETUP_ROUTE_KEYS.some(has);
}

function paint(root) {
  clear(root);
  const preview = previewBaselinePolicy(session.draft, state);
  const stats = policyStats(preview.policy);
  const posture = selectedProfile();
  const interfaces = discoveredSetupInterfaces(setupStatus);
  const issues = interfaceAssignmentIssues(state, interfaces);
  const hostPrep = hostPreparationModel(setupStatus, state.profile);
  const contentPosture = buildContentPosture(setupFeeds, preview.policy, setupContentPackages, setupContentError);
  const checklist = setupChecklist({
    config: state,
    policy: preview.policy,
    issues,
    hostPreparation: hostPrep,
    runtime: setupStatus?.runtime || {},
    oidc: setupOidcStatus || {},
    contentPosture,
    dirty: session.dirty,
  });
  const blocked = issues.some((issue) => issue.severity === "bad");

  root.appendChild(pageHead("Guided setup",
    "Stage a reviewed two-zone baseline, then validate and commit from the candidate bar.",
    [
      session.dirty ? h("a", { class: "btn", href: "#/changes", title: "Review guided setup candidate changes", "aria-label": "Review guided setup candidate changes", "data-setup-action": "review-changes" }, h("span", { html: icon("changes", 16) }), "Review changes") : null,
      h("button", {
        class: "btn primary",
        type: "button",
        "data-setup-action": "stage",
        disabled: blocked,
        title: blocked ? issues.find((issue) => issue.severity === "bad")?.detail : "Stage guided setup candidate",
        "aria-label": blocked ? issues.find((issue) => issue.severity === "bad")?.detail : "Stage guided setup candidate",
        onclick: () => stageSetup(root),
      }, h("span", { html: icon("check", 16) }), "Stage setup"),
    ]));

  root.appendChild(h("div", { class: "setup-layout" },
    card(h("h2", {}, "Baseline posture"),
      setupScenarioPanel(root),
      h("div", { class: "profile-options setup-profiles" }, BASELINE_PROFILES.map((profile) =>
        h("button", {
          class: "profile-option " + (profile.id === state.profile ? "active" : ""),
          type: "button",
          title: `Select setup profile ${profile.title}`,
          "aria-label": `Select setup profile ${profile.title}`,
          "data-setup-profile": profile.id,
          onclick: () => selectProfile(profile.id, root),
        },
          h("span", {}, profile.title),
        h("small", {}, profile.summary)))),
      interfaceAssignmentPanel(root, interfaces, setupStatusError, issues),
      hostPreparationPanel(root, hostPrep, setupStatusError),
      h("hr", { class: "divider" }),
      h("div", { class: "form-grid two" },
        textField("Inside zone", "insideZone", "lan", root),
        textField("Outside zone", "outsideZone", "wan", root),
        textField("Inside interfaces", "insideInterfaces", "eth1, ens4", root),
        textField("Outside interfaces", "outsideInterfaces", "eth0, ens3", root),
        textField("Inside network", "insideCidr", "10.0.0.0/24", root),
        textField("WebUI/API port", "webuiPort", "8080", root, "number"),
        textField("Global MTU", "mtu", "optional", root, "number"),
        posture.defaults.inspectionMode !== "off" ? textField("IDS/IPS engine rule files", "idsRuleFiles", "local.rules", root) : null,
        posture.defaults.inspectionMode === "prevent" ? textField("NFQUEUE", "idsQueueNum", "0", root, "number") : null),
      posture.defaults.inspectionMode === "prevent" ? h("div", { class: "setup-fail" },
        h("span", {}, "IPS failure behavior"),
        segment([
          ["IDS_FAILURE_BEHAVIOR_FAIL_CLOSED", "Fail closed"],
          ["IDS_FAILURE_BEHAVIOR_FAIL_OPEN", "Fail open"],
        ], state.failureBehavior, (value) => { state.scenario = "custom"; state.failureBehavior = value; paint(root); }, { key: "failureBehavior", label: "IPS failure behavior" })) : null,
      h("hr", { class: "divider" }),
      h("div", { class: "setup-toggles" },
        toggleRow("Outbound allow rule", "allowOutbound", root, "Logged inside-to-outside allow path."),
        toggleRow("Source NAT", "masquerade", root, "Masquerade inside clients to the outside zone."),
        toggleRow("Host-input hardening", "hardenHostInput", root, "Default-deny management plane with inside SSH/WebUI allow."),
        toggleRow("TCP MSS clamp", "clampMss", root, "Avoid path-MTU blackholes."),
        posture.defaults.inspectionMode === "off" ? toggleRow("Flowtable fast path", "flowOffload", root, "Forwarding acceleration for established flows.") : null,
        posture.defaults.inspectionMode === "detect" ? toggleRow("Manage IDS NIC offloads", "manageNicOffloads", root, "Disable offloads that hide payload from passive inspection.") : null)),

    card(h("h2", {}, "Candidate preview", h("span", { class: "spacer" }), pill(posture.title, posture.id === "throughput" ? "info" : "warn", true)),
      h("div", { class: "runtime-grid setup-metrics" },
        metric("Zones", stats.zones),
        metric("Rules", stats.rules),
        metric("NAT", stats.nat),
        metric("Host input", stats.hostInput),
        metric("IDS/IPS", idsLabel(preview.policy.ids)),
        metric("Fast path", preview.policy.network?.enableFlowOffload ? "enabled" : "off")),
      h("div", { class: "setup-summary" },
        setupScenarioReviewPanel(setupScenarioReview(state)),
        summaryList("Objects", preview.summary.addresses.concat(preview.summary.services)),
        summaryList("Policy", preview.summary.rules.concat(preview.summary.nat)),
        summaryList("Runtime posture", preview.summary.network.concat(preview.summary.ids, preview.summary.hostInput))),
      setupChecklistPanel(checklist),
      h("div", { class: "alert-box " + previewClass(preview.policy) },
        h("strong", {}, previewTitle(preview.policy)),
        h("div", { class: "note" }, previewDetail(preview.policy))))));
}

async function stageSetup(root) {
  if (sameName(state.insideZone, state.outsideZone)) {
    toast("Distinct zones required", "Use different names for inside and outside zones.", "warn");
    return;
  }
  const blockers = interfaceAssignmentIssues(state, discoveredSetupInterfaces(setupStatus)).filter((issue) => issue.severity === "bad");
  if (blockers.length) {
    toast("Interface assignment required", blockers[0].detail, "warn");
    return;
  }
  try {
    let summary = null;
    await session.apply((draft) => {
      summary = applyBaselinePolicy(draft, state);
    });
    const validation = await session.validate();
    paint(root);
    if (validation.valid) {
      toast("Setup staged", setupSummary(summary), "ok");
    } else {
      toast("Setup staged with validation findings", (validation.errors || []).slice(0, 2).join("; "), "warn");
    }
  } catch (e) {
    toast("Could not stage setup", e.message, "bad");
  }
}

function selectProfile(id, root) {
  state.scenario = "custom";
  state.profile = id;
  state.flowOffload = id === "throughput";
  state.manageNicOffloads = id === "ids-detect";
  paint(root);
}

function setupScenarioPanel(root) {
  return h("div", { class: "profile-options setup-scenarios" }, SETUP_SCENARIOS.map((scenario) =>
    h("button", {
      class: "profile-option " + (scenario.id === state.scenario ? "active" : ""),
      type: "button",
      title: `Select setup scenario ${scenario.title}`,
      "aria-label": `Select setup scenario ${scenario.title}`,
      "data-setup-scenario": scenario.id,
      onclick: () => applySetupScenario(scenario.id, root),
    },
      h("span", {}, scenario.title),
      h("small", {}, scenario.summary))));
}

function applySetupScenario(id, root) {
  Object.assign(state, setupScenarioConfig(id, state));
  paint(root);
}

export function setupScenarioConfig(id, current = {}) {
  const scenario = setupScenario(id);
  const next = {
    ...current,
    ...scenario.config,
    scenario: scenario.id,
  };
  next.mtu = scenario.config.mtu || "";
  next.idsRuleFiles = scenario.config.idsRuleFiles || "local.rules";
  next.idsQueueNum = scenario.config.idsQueueNum || "0";
  return next;
}

export function setupScenario(id) {
  return SETUP_SCENARIOS.find((scenario) => scenario.id === id) || SETUP_SCENARIOS[0];
}

export function setupScenarioReview(config = {}) {
  const scenario = SETUP_SCENARIOS.find((item) => item.id === config.scenario);
  if (scenario?.guidance) {
    return {
      id: scenario.id,
      title: scenario.title,
      fit: scenario.guidance.fit,
      staged: scenario.guidance.staged,
      review: scenario.guidance.review,
      excluded: scenario.guidance.excluded,
    };
  }
  const inspection = config.profile === "ids-detect"
    ? "IDS detect mode"
    : config.profile === "ips-prevent"
      ? "IPS prevent mode"
      : "L3/L4 throughput mode";
  const nat = config.masquerade ? "source NAT" : "no source NAT";
  const outbound = config.allowOutbound ? "logged outbound allow" : "no default outbound allow";
  return {
    id: "custom",
    title: "Custom baseline",
    fit: "Operator-adjusted baseline assembled from the current fields and toggles.",
    staged: `${outbound}, ${nat}, ${inspection}, ${config.hardenHostInput ? "host-input default deny" : "host-input unchanged"}, and ${config.clampMss ? "MSS clamp" : "no MSS clamp"}.`,
    review: "Review every generated object, rule, NAT, host-input, and inspection change in Changes before commit.",
    excluded: "Custom edits do not stage VPN secrets, inbound publish rules, signed content custody, or HA behavior.",
  };
}

function selectedProfile() {
  return BASELINE_PROFILES.find((profile) => profile.id === state.profile) || BASELINE_PROFILES[0];
}

function textField(label, key, placeholder, root, type = "text") {
  return h("label", { class: "field" },
    h("span", {}, label),
    h("input", { class: "input", type, value: state[key], placeholder, "data-setup-field": key, onchange: (e) => { state.scenario = "custom"; state[key] = e.target.value; paint(root); } }));
}

function interfaceAssignmentPanel(root, interfaces, error, issues) {
  const assigned = interfaceAssignments(state);
  return h("div", { class: "setup-iface-panel" },
    h("div", { class: "setup-iface-head" },
      h("strong", {}, "Interface assignment"),
      h("span", {}, interfaces.length ? `${interfaces.length} discovered` : error ? "status unavailable" : "none discovered")),
    error ? h("div", { class: "note" }, "Status is unavailable; type interface names manually or retry after the daemon can read host counters.") : null,
    interfaces.length
      ? h("div", { class: "setup-iface-grid" }, interfaces.map((iface) => interfaceChoice(root, iface, assigned)))
      : h("div", { class: "alert-box info setup-inline-alert" },
          h("strong", {}, "No host interface inventory."),
          h("div", { class: "note" }, "Manual interface names are still supported for offline policy staging.")),
    issues.length
      ? h("div", { class: "setup-issues" }, issues.map((issue) =>
          h("div", { class: "setup-issue " + issue.severity },
            h("span", { html: icon(issue.severity === "bad" ? "block" : "settings", 14) }),
            h("span", {}, issue.detail))))
      : h("div", { class: "setup-okline" }, h("span", { html: icon("check", 14) }), "Inside and outside assignments are distinct."));
}

function hostPreparationPanel(root, model, error) {
  return h("div", { class: "setup-host-panel" },
    h("div", { class: "setup-iface-head" },
      h("strong", {}, "Host preparation"),
      h("span", {}, model.dryRun ? "dry-run" : model.statusAvailable ? "live host" : "status unavailable")),
    error ? h("div", { class: "note" }, "Runtime status is unavailable; run the CLI command on the firewall host or retry after status recovers.") : null,
    model.dryRun ? h("div", { class: "alert-box warn setup-inline-alert" },
      h("strong", {}, "Dry-run mode"),
      h("div", { class: "note" }, "This daemon cannot mutate host sysctls; run the command on the target firewall host.")) : null,
    h("div", { class: "setup-host-grid" },
      hostPreparationStatus("Kernel baseline", model.baseline.label, model.baseline.cls, model.baseline.detail),
      hostPreparationStatus("Throughput headroom", model.throughput.label, model.throughput.cls, model.throughput.detail)),
    h("div", { class: "setup-host-actions" }, model.actions.map((action) =>
      h("button", {
        class: "btn sm " + (action.primary ? "primary" : "ghost"),
        type: "button",
        disabled: action.disabled,
        title: action.disabledReason || action.detail,
        "aria-label": action.disabled ? (action.disabledReason || action.detail || action.label) : action.label,
        dataset: { setupHostAction: action.profile },
        onclick: () => applySetupHostTuning(root, action.profile),
      }, h("span", { html: icon(action.profile === "throughput" ? "traffic" : "settings", 16) }), action.label))),
    h("div", { class: "setup-host-commands" },
      hostPreparationCommand("Baseline CLI", model.baseline.command),
      model.throughput.recommended ? hostPreparationCommand("Throughput CLI", model.throughput.command) : null));
}

function hostPreparationStatus(title, label, cls, detail) {
  return h("div", { class: "setup-host-status" },
    h("span", {}, title),
    h("strong", {}, pill(label || "unknown", cls || "neutral", true)),
    h("small", {}, detail || "Status evidence is not available."));
}

function hostPreparationCommand(label, command) {
  return h("div", { class: "setup-host-command" },
    h("span", {}, label),
    h("code", {}, command || "ngfwctl system tune"));
}

async function applySetupHostTuning(root, profile) {
  const throughput = profile === "throughput";
  const label = throughput ? "throughput tuning" : "host baseline";
  const ok = await confirmDialog({
    title: "Apply " + label + "?",
    message: throughput
      ? "This writes the high-bandwidth sysctl profile and applies live kernel values on the firewall host."
      : "This writes the appliance sysctl baseline and applies live kernel values on the firewall host.",
    confirmLabel: throughput ? "Apply throughput" : "Apply baseline",
  });
  if (!ok) return;
  try {
    const resp = await api.tuneHost({ profile, write: true, apply: true, ackHostChange: true });
    toast("Host tuning applied", `${resp.profile || profile} profile applied.`, "ok");
    await refreshSetupStatus();
    paint(root);
  } catch (e) {
    toast("Host tuning failed", e.message, "bad");
  }
}

async function refreshSetupStatus() {
  try {
    setupStatus = await api.status();
    setupStatusError = null;
  } catch (e) {
    setupStatus = null;
    setupStatusError = e;
  }
}

function interfaceChoice(root, iface, assigned) {
  const inInside = assigned.inside.has(iface.name);
  const inOutside = assigned.outside.has(iface.name);
  const health = iface.state && iface.state !== "ready" ? "warn" : "ok";
  return h("div", { class: "setup-iface-row " + (inInside || inOutside ? "active" : "") },
    h("div", { class: "setup-iface-main" },
      h("strong", { class: "mono" }, iface.name),
      pill(iface.state || "unknown", health, true),
      h("small", {}, interfaceDetail(iface))),
    h("div", { class: "setup-iface-actions" },
      h("button", { class: "btn sm " + (inInside ? "primary" : "ghost"), type: "button", title: `Assign ${iface.name} as inside interface`, "aria-label": `Assign ${iface.name} as inside interface`, dataset: { setupInterfaceAction: "inside", setupInterface: iface.name }, onclick: () => toggleInterface(root, iface.name, "inside") }, "Inside"),
      h("button", { class: "btn sm " + (inOutside ? "primary" : "ghost"), type: "button", title: `Assign ${iface.name} as outside interface`, "aria-label": `Assign ${iface.name} as outside interface`, dataset: { setupInterfaceAction: "outside", setupInterface: iface.name }, onclick: () => toggleInterface(root, iface.name, "outside") }, "Outside")));
}

function toggleInterface(root, name, role) {
  state.scenario = "custom";
  const inside = splitInterfaceList(state.insideInterfaces);
  const outside = splitInterfaceList(state.outsideInterfaces);
  if (role === "inside") {
    state.insideInterfaces = toggleInterfaceName(inside, name).join(", ");
    state.outsideInterfaces = outside.filter((item) => item !== name).join(", ");
  } else {
    state.outsideInterfaces = toggleInterfaceName(outside, name).join(", ");
    state.insideInterfaces = inside.filter((item) => item !== name).join(", ");
  }
  paint(root);
}

function toggleInterfaceName(items, name) {
  if (items.includes(name)) return items.filter((item) => item !== name);
  return [...items, name].sort();
}

function toggleRow(title, key, root, detail) {
  const input = h("input", { type: "checkbox", onchange: (e) => { state.scenario = "custom"; state[key] = e.target.checked; paint(root); } });
  input.checked = Boolean(state[key]);
  return h("label", { class: "setup-toggle" },
    h("span", {}, h("strong", {}, title), h("small", {}, detail)),
    h("span", { class: "switch", "data-setup-toggle": key }, input, h("span", { class: "slider" })));
}

function segment(items, active, onChange, opts = {}) {
  return h("div", { class: "seg" }, items.map(([value, label]) =>
    h("button", {
      class: value === active ? "active" : "",
      type: "button",
      title: opts.label ? `Set ${opts.label} to ${label}` : label,
      "aria-label": opts.label ? `Set ${opts.label} to ${label}` : label,
      dataset: opts.key ? { setupSegment: opts.key, setupSegmentValue: value } : {},
      onclick: () => onChange(value),
    }, label)));
}

function metric(label, value) {
  return h("div", { class: "posture-metric" }, h("span", {}, label), h("strong", {}, String(value)));
}

function summaryList(title, items) {
  return h("div", { class: "setup-list" },
    h("span", {}, title),
    items.length ? h("div", {}, items.map((item) => h("span", { class: "tag" }, item))) : h("strong", {}, "No change"));
}

function setupScenarioReviewPanel(review) {
  return h("div", { class: "profile-strip setup-scenario-review", "data-setup-scenario-review": review.id },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Deployment archetype"),
      h("span", {}, review.title)),
    h("div", { class: "setup-scenario-review-grid" },
      setupReviewRow("Use when", review.fit),
      setupReviewRow("Staged defaults", review.staged),
      setupReviewRow("Operator review", review.review),
      setupReviewRow("Not staged", review.excluded)));
}

function setupReviewRow(label, value) {
  return h("div", { class: "setup-scenario-review-row" }, h("span", {}, label), h("strong", {}, value || "-"));
}

function setupChecklistPanel(items = []) {
  const blockers = items.filter((item) => item.cls === "bad").length;
  const warnings = items.filter((item) => item.cls === "warn").length;
  const ready = items.filter((item) => item.cls === "ok").length;
  const label = blockers ? `${blockers} blocker${blockers === 1 ? "" : "s"}` : warnings ? `${warnings} review` : `${ready}/${items.length} ready`;
  return h("div", { class: "setup-checklist-panel" },
    h("div", { class: "setup-checklist-head" },
      h("div", {},
        h("strong", {}, "First-run checklist"),
        h("span", {}, "Proof before candidate review")),
      h("span", { class: "setup-checklist-actions" },
        pill(label, blockers ? "bad" : warnings ? "warn" : "ok", true),
        h("button", { class: "btn sm ghost", type: "button", title: "Open guided setup API and CLI context", "aria-label": "Open guided setup API and CLI context", "data-setup-action": "api-cli", onclick: () => openAutomationContext(setupRouteHashFromConfig(state)) },
          h("span", { html: icon("terminal", 15) }), "API / CLI"))),
    h("div", { class: "setup-checklist table-wrap flat" },
      responsiveTable(["Check", "Status", "Proof"], items.map(setupChecklistRow), { className: "setup-checklist-table" })));
}

function setupChecklistRow(item) {
  return h("tr", { "data-setup-check": item.id },
    labeledCell("Check", { class: "setup-checklist-main" },
      h("span", { class: "setup-checklist-icon", html: icon(itemIcon(item.cls), 15) }),
      h("div", {},
        h("strong", {}, item.title),
        h("span", { class: "setup-checklist-detail" }, item.detail),
        Array.isArray(item.proofRows) && item.proofRows.length
          ? h("div", { class: "setup-topology-proof", dataset: { setupTopologyProof: item.id } },
            item.proofRows.map((row) => h("div", { class: "setup-topology-proof-row", dataset: { setupTopologyProofRow: row.key || "" } },
              pill(row.status || "review", row.cls || "warn", true),
              h("span", { class: "setup-topology-proof-label" }, row.label || "Proof"),
              h("strong", { class: "setup-topology-proof-detail" }, row.detail || "Review required"))))
          : null)),
    labeledCell("Status", {}, pill(setupChecklistStatusLabel(item.cls), item.cls || "neutral", true)),
    labeledCell("Proof", { class: "setup-checklist-proof" },
      item.href ? h("a", {
        class: "btn sm ghost",
        href: item.href,
        title: `Open ${item.title} proof`,
        "aria-label": `Open ${item.title} proof`,
        dataset: { setupCheckAction: item.id },
      }, item.action || "Open") : null,
      item.cli ? h("code", {}, item.cli) : null));
}

function setupChecklistStatusLabel(cls) {
  if (cls === "ok") return "Ready";
  if (cls === "bad") return "Blocked";
  if (cls === "warn") return "Review";
  if (cls === "info") return "Info";
  return "Pending";
}

function itemIcon(cls) {
  if (cls === "ok") return "check";
  if (cls === "bad") return "block";
  if (cls === "warn") return "settings";
  return "settings";
}

function policyStats(policy = {}) {
  return {
    zones: (policy.zones || []).length,
    rules: (policy.rules || []).length,
    nat: (policy.nat?.source || []).length + (policy.nat?.destination || []).length,
    hostInput: policy.hostInput?.defaultAction || "unchanged",
  };
}

function idsLabel(ids = {}) {
  if (!ids.enabled) return "disabled";
  return ids.mode === "IDS_MODE_PREVENT" ? "prevent" : "detect";
}

function previewClass(policy = {}) {
  if (policy.ids?.enabled && policy.network?.enableFlowOffload) return "bad";
  if (policy.ids?.mode === "IDS_MODE_PREVENT") return "warn";
  return "info";
}

function previewTitle(policy = {}) {
  if (policy.ids?.enabled && policy.network?.enableFlowOffload) return "Invalid inspection posture";
  if (policy.ids?.mode === "IDS_MODE_PREVENT") return "Inline prevention selected";
  if (policy.ids?.enabled) return "Detect mode selected";
  return "Forwarding acceleration selected";
}

function previewDetail(policy = {}) {
  if (policy.ids?.enabled && policy.network?.enableFlowOffload) {
    return "Flowtable acceleration must stay off when IDS/IPS is enabled because offloaded packets can bypass inspection.";
  }
  if (policy.ids?.mode === "IDS_MODE_PREVENT") {
    return "NFQUEUE prevention can drop traffic. Review failure behavior and commit impact before applying.";
  }
  if (policy.ids?.enabled) {
    return "Detect mode keeps forwarding path conservative and records inspection evidence without inline drops.";
  }
  return "This profile prioritizes L3/L4 throughput and must not be described as inspected threat-prevention throughput.";
}

function setupSummary(summary) {
  if (!summary) return "Candidate updated.";
  const parts = [];
  if (summary.zones.length) parts.push(`${summary.zones.length} zones`);
  if (summary.rules.length) parts.push(`${summary.rules.length} rule`);
  if (summary.ids.length) parts.push(summary.ids[0]);
  if (summary.network.length) parts.push(summary.network.join(", "));
  return parts.join(" · ") || "Candidate updated.";
}

function sameName(a, b) {
  return String(a || "").trim().toLowerCase() === String(b || "").trim().toLowerCase();
}

export function discoveredSetupInterfaces(status = {}) {
  const seen = new Set();
  return (status?.host?.interfaces || [])
    .map((iface) => ({
      name: String(iface?.name || "").trim(),
      state: String(iface?.state || "unknown").trim() || "unknown",
      detail: String(iface?.detail || "").trim(),
      rxBytes: Number(iface?.rxBytes || 0),
      txBytes: Number(iface?.txBytes || 0),
      rxDrops: Number(iface?.rxDrops || 0),
      txDrops: Number(iface?.txDrops || 0),
      rxErrors: Number(iface?.rxErrors || 0),
      txErrors: Number(iface?.txErrors || 0),
    }))
    .filter((iface) => iface.name && iface.name !== "lo" && !seen.has(iface.name) && seen.add(iface.name))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export function interfaceAssignmentIssues(config = {}, discovered = []) {
  const inside = splitInterfaceList(config.insideInterfaces);
  const outside = splitInterfaceList(config.outsideInterfaces);
  const issues = [];
  if (!inside.length) issues.push({ severity: "bad", detail: "Select at least one inside interface." });
  if (!outside.length) issues.push({ severity: "bad", detail: "Select at least one outside interface." });
  const outsideSet = new Set(outside);
  const overlaps = inside.filter((name) => outsideSet.has(name));
  if (overlaps.length) issues.push({ severity: "bad", detail: `${overlaps.join(", ")} cannot be assigned to both inside and outside.` });
  for (const name of [...inside, ...outside]) {
    if (name === "lo") issues.push({ severity: "bad", detail: "Loopback cannot be used as a firewall transit interface." });
  }
  const known = new Map((discovered || []).map((iface) => [iface.name, iface]));
  if (known.size) {
    for (const name of [...inside, ...outside]) {
      const iface = known.get(name);
      if (!iface) {
        issues.push({ severity: "warn", detail: `${name} was not reported by this host.` });
      } else if (iface.state && iface.state !== "ready") {
        issues.push({ severity: "warn", detail: `${name} is ${iface.state}${iface.detail ? ": " + iface.detail : "."}` });
      }
    }
  }
  return issues;
}

export function hostPreparationModel(status = {}, profileId = "throughput") {
  const source = status || {};
  const statusAvailable = Object.keys(source).length > 0;
  const tuning = kernelTuningRollup(source);
  const dryRun = Boolean(source.runtime?.dryRun);
  const disabledReason = !statusAvailable
    ? "Runtime status is unavailable."
    : dryRun
      ? "Dry-run daemon cannot mutate host sysctls."
      : "";
  const throughputRecommended = profileId === "throughput";
  const baselineNeedsAction = tuning.needsAction || tuning.state === "unknown";
  return {
    statusAvailable,
    dryRun,
    baseline: {
      label: tuning.readinessLabel || tuning.label || tuning.state || "unknown",
      cls: tuning.cls || "neutral",
      detail: tuning.detail || "Kernel forwarding tuning status is not available.",
      command: tuning.baselineCommand,
    },
    throughput: {
      label: tuning.throughputLabel,
      cls: tuning.throughputCls,
      detail: tuning.throughputDetail,
      command: tuning.throughputCommand,
      recommended: throughputRecommended,
      ready: Boolean(tuning.throughputReady),
    },
    actions: [
      {
        profile: "appliance",
        label: baselineNeedsAction ? "Apply host baseline" : "Re-apply baseline",
        detail: "Write and apply the appliance sysctl baseline.",
        disabled: Boolean(disabledReason),
        disabledReason,
        primary: !throughputRecommended && baselineNeedsAction,
      },
      {
        profile: "throughput",
        label: "Apply throughput tuning",
        detail: "Write and apply high-bandwidth sysctl and conntrack headroom.",
        disabled: Boolean(disabledReason),
        disabledReason,
        primary: throughputRecommended,
      },
    ],
  };
}

export function setupChecklist({
  config = {},
  policy = {},
  issues = [],
  hostPreparation = {},
  runtime = {},
  oidc = {},
  contentPosture = null,
  dirty = false,
} = {}) {
  const blockers = (issues || []).filter((issue) => issue.severity === "bad");
  const warnings = (issues || []).filter((issue) => issue.severity === "warn");
  const ids = policy.ids || {};
  const hostInput = policy.hostInput || {};
  const rules = policy.rules || [];
  const sourceNat = policy.nat?.source || [];
  const inspectionEnabled = Boolean(ids.enabled);
  const flowOffload = Boolean(policy.network?.enableFlowOffload);
  const defaultDeny = hostInput.defaultAction === "ACTION_DENY";
  const hostRules = hostInput.rules || [];
  const managementAllow = hostRules.some((rule) => rule.action === "ACTION_ALLOW" && (rule.services || []).length);
  const outboundRule = rules.some((rule) =>
    rule.action === "ACTION_ALLOW" &&
    (rule.fromZones || []).includes(config.insideZone || "lan") &&
    (rule.toZones || []).includes(config.outsideZone || "wan"));
  const masquerade = sourceNat.some((nat) => nat.masquerade === true);
  const hostTuningReady = (hostPreparation.baseline?.cls || "") === "ok";
  const hostTuningUnknown = !hostPreparation.statusAvailable;
  const hostTuningDryRun = Boolean(hostPreparation.dryRun);
  const authEnabled = runtime.authEnabled === true;
  const tlsEnabled = runtime.tlsEnabled === true;
  const oidcEnabled = oidc.enabled === true;
  const adminAccessCls = authEnabled && tlsEnabled ? "ok" : authEnabled || tlsEnabled || oidcEnabled ? "warn" : "bad";
  const contentCls = contentPosture?.summary?.cls || "warn";
  const topologyProof = setupTopologyProof(config, policy, { blockers, warnings, outboundRule, masquerade });
  return [
    {
      id: "interfaces",
      title: "Interface boundary",
      cls: blockers.length ? "bad" : warnings.length ? "warn" : "ok",
      detail: blockers[0]?.detail || warnings[0]?.detail || "Inside and outside interfaces are distinct and ready to stage.",
      cli: "ngfwctl status",
    },
    {
      id: "admin-access",
      title: "Admin access",
      cls: adminAccessCls,
      detail: authEnabled && tlsEnabled
        ? `${oidcEnabled ? "OIDC browser SSO is available and " : ""}TLS and API authentication are enabled.`
        : authEnabled
          ? "API authentication is enabled, but TLS evidence is not enabled for the management surface."
          : tlsEnabled
            ? "TLS is enabled, but API authentication is not enabled for first-run administration."
            : "Enable TLS and authentication before exposing or committing a production appliance.",
      href: "#/settings?panel=access",
      action: "Access",
      cli: "ngfwctl whoami",
    },
    {
      id: "host-input",
      title: "Host-input exposure",
      cls: defaultDeny && managementAllow ? "ok" : "warn",
      detail: defaultDeny && managementAllow
        ? "Host-input default deny includes an explicit inside management allow rule."
        : "Host-input default deny or scoped management access is not enabled in this baseline.",
      href: "#/settings?panel=access",
      action: "Access",
    },
    {
      id: "content-updates",
      title: "Content and update source",
      cls: contentCls === "bad" ? "bad" : contentCls === "ok" ? "ok" : "warn",
      detail: contentPosture?.summary?.detail || "Content package and feed status must be reviewed before production use.",
      href: "#/intel",
      action: "Intel",
      cli: "ngfwctl intel content",
    },
    topologyProof,
    {
      id: "outbound",
      title: "Outbound path",
      cls: outboundRule && masquerade ? "ok" : outboundRule || masquerade ? "warn" : "info",
      detail: outboundRule && masquerade
        ? "Inside-to-outside allow policy and source NAT will be staged together."
        : outboundRule
          ? "Outbound allow is staged without source NAT; confirm upstream routing."
          : masquerade
            ? "Source NAT is staged without an outbound allow rule."
            : "No default outbound allow path will be staged.",
      cli: "ngfwctl policy diff",
    },
    {
      id: "inspection",
      title: "Inspection posture",
      cls: inspectionEnabled && flowOffload ? "bad" : ids.mode === "IDS_MODE_PREVENT" ? "warn" : inspectionEnabled ? "ok" : "info",
      detail: inspectionEnabled && flowOffload
        ? "IDS/IPS and flowtable acceleration conflict because offloaded packets can bypass inspection."
        : ids.mode === "IDS_MODE_PREVENT"
          ? `Inline prevention is staged with ${ids.failureBehavior === "IDS_FAILURE_BEHAVIOR_FAIL_CLOSED" ? "fail-closed" : "fail-open"} behavior.`
          : inspectionEnabled
            ? "IDS detect mode is staged with flowtable acceleration disabled."
            : "IDS/IPS is disabled; this baseline is throughput-oriented L3/L4 forwarding.",
      href: "#/traffic?mode=app-id",
      action: "Evidence",
    },
    {
      id: "host-tuning",
      title: "Host preparation",
      cls: hostTuningReady ? "ok" : hostTuningDryRun || hostTuningUnknown ? "warn" : "bad",
      detail: hostTuningReady
        ? hostPreparation.baseline?.detail || "Kernel baseline tuning is ready."
        : hostTuningDryRun
          ? "Dry-run status cannot prove host sysctl changes on the target firewall."
          : hostTuningUnknown
            ? "Runtime status is unavailable; collect host tuning evidence before production commit."
            : hostPreparation.baseline?.detail || "Kernel baseline tuning needs review before production commit.",
      href: "#/settings",
      action: "Settings",
    },
    {
      id: "candidate-review",
      title: "Candidate review",
      cls: dirty ? "ok" : blockers.length ? "bad" : "warn",
      detail: dirty
        ? "A candidate is staged; validate, diff, and commit with an audit reason."
        : blockers.length
          ? "Resolve setup blockers before staging the first candidate."
          : "Stage setup, then validate, diff, and commit from Changes.",
      href: "#/changes",
      action: "Changes",
      cli: dirty ? "ngfwctl policy validate && ngfwctl policy diff" : setupBaselineCliCommand(config),
    },
  ];
}

export const setupReadinessChecklist = setupChecklist;

export function setupTopologyProof(config = {}, policy = {}, context = {}) {
  const scenario = SETUP_SCENARIOS.find((item) => item.id === config.scenario);
  const inside = splitInterfaceList(config.insideInterfaces);
  const outside = splitInterfaceList(config.outsideInterfaces);
  const rules = policy.rules || [];
  const sourceNat = policy.nat?.source || [];
  const ids = policy.ids || {};
  const insideZone = config.insideZone || "lan";
  const outsideZone = config.outsideZone || "wan";
  const outboundRule = context.outboundRule ?? rules.some((rule) =>
    rule.action === "ACTION_ALLOW" &&
    (rule.fromZones || []).includes(insideZone) &&
    (rule.toZones || []).includes(outsideZone));
  const masquerade = context.masquerade ?? sourceNat.some((nat) => nat.masquerade === true);
  const hasBlockers = Boolean(context.blockers?.length);
  const hasWarnings = Boolean(context.warnings?.length);
  const baseCli = "ngfwctl policy validate && ngfwctl policy diff";
  const mk = (cls, detail, href = "#/changes", action = "Changes", cli = baseCli) => ({
    id: "topology-proof",
    title: "Topology proof",
    cls: hasBlockers ? "bad" : cls,
    detail: hasBlockers ? context.blockers[0].detail : detail,
    proofRows: setupTopologyProofRows(config, policy, context, scenario),
    href,
    action,
    cli,
  });
  if (!scenario) {
    return mk(
      hasWarnings ? "warn" : "info",
      "Custom topology selected; review generated policy, NAT, routing, and host-input scope before commit.",
    );
  }
  if (scenario.id === "cloud-edge") {
    const ready = inside.length && outside.length && outboundRule && masquerade && config.clampMss !== false;
    return mk(
      ready ? (hasWarnings ? "warn" : "ok") : "warn",
      ready
        ? "Cloud edge handoff checks inside/outside split, outbound allow, source NAT, scoped host-input, and MSS clamp for candidate review."
        : "Cloud edge needs inside/outside interfaces, outbound allow, source NAT, and MSS clamp reviewed before commit.",
      "#/changes",
      "Changes",
    );
  }
  if (scenario.id === "east-west") {
    const noNat = !masquerade && sourceNat.length === 0;
    const detectOnly = ids.enabled === true && ids.mode === "IDS_MODE_DETECT";
    return mk(
      noNat && detectOnly ? (hasWarnings ? "warn" : "ok") : "warn",
      noNat && detectOnly
        ? "East-west handoff keeps source NAT off, stages detect-mode inspection, and requires upstream return-route proof before commit."
        : "East-west topology requires no source NAT, detect-mode inspection, and an explicit return-route review.",
      "#/netvpn?drawer=static-routes",
      "Routes",
    );
  }
  if (scenario.id === "vpn-edge") {
    const noNat = !masquerade && sourceNat.length === 0;
    return mk(
      noNat ? "warn" : "bad",
      noNat
        ? "VPN edge stages branch-to-VPN policy only; create tunnel peers and protected-subnet route proof in Routing & VPN before commit."
        : "VPN edge must not introduce source NAT before protected-subnet and tunnel reachability proof exists.",
      "#/netvpn?drawer=tunnels",
      "VPN",
    );
  }
  if (scenario.id === "ids-tap") {
    const passive = !outboundRule && !masquerade && !policy.network?.enableFlowOffload;
    return mk(
      passive ? "warn" : "bad",
      passive
        ? "IDS tap is passive: no outbound allow, no source NAT, and offload stays managed; prove mirror/SPAN visibility before commit."
        : "IDS tap must remain passive with no forwarding allow, no source NAT, and no flow offload.",
      "#/troubleshoot?intent=capture&captureContext=setup-tap",
      "Capture",
    );
  }
  if (scenario.id === "lab") {
    const exampleCidr = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"].includes(String(config.insideCidr || "").trim());
    return mk(
      exampleCidr ? "warn" : "ok",
      exampleCidr
        ? "Lab handoff still uses documentation CIDR space; replace with the lab subnet before staging beyond disposable evaluation."
        : "Lab handoff uses operator-supplied subnet values and keeps changes in the normal candidate review path.",
      "#/changes",
      "Changes",
    );
  }
  return mk("info", "Review generated topology changes before commit.");
}

export function setupTopologyProofRows(config = {}, policy = {}, context = {}, scenario = null) {
  const inside = splitInterfaceList(config.insideInterfaces);
  const outside = splitInterfaceList(config.outsideInterfaces);
  const rules = policy.rules || [];
  const sourceNat = policy.nat?.source || [];
  const ids = policy.ids || {};
  const network = policy.network || {};
  const hostInput = policy.hostInput || {};
  const insideZone = config.insideZone || "lan";
  const outsideZone = config.outsideZone || "wan";
  const outboundRule = context.outboundRule ?? rules.some((rule) =>
    rule.action === "ACTION_ALLOW" &&
    (rule.fromZones || []).includes(insideZone) &&
    (rule.toZones || []).includes(outsideZone));
  const masquerade = context.masquerade ?? sourceNat.some((nat) => nat.masquerade === true);
  const hostDefaultDeny = hostInput.defaultAction === "ACTION_DENY";
  const hostManagementAllow = (hostInput.rules || []).some((rule) => rule.action === "ACTION_ALLOW" && (rule.services || []).length);
  const row = (key, label, ok, detail, opts = {}) => ({
    key,
    label,
    status: ok ? "ready" : opts.status || "review",
    cls: ok ? "ok" : opts.cls || "warn",
    detail,
  });
  const common = [
    row("interfaces", "Interface identity", inside.length > 0 && outside.length > 0 && !inside.some((name) => outside.includes(name)),
      inside.length && outside.length ? `${inside.join(", ")} -> ${outside.join(", ")}` : "Assign distinct inside and outside interfaces."),
    row("host-input", "Management preservation", hostDefaultDeny && hostManagementAllow,
      hostDefaultDeny && hostManagementAllow ? "Default-deny host input includes scoped management allow." : "Review host-input default deny and management allow before commit."),
  ];
  switch (scenario?.id || config.scenario || "custom") {
    case "cloud-edge":
      return [
        ...common,
        row("outbound-allow", "Outbound allow", outboundRule, outboundRule ? `${insideZone} can initiate to ${outsideZone}.` : "Stage or review the inside-to-outside allow rule."),
        row("source-nat", "Source NAT", masquerade, masquerade ? "Masquerade is staged for internet egress." : "Confirm egress return routing if source NAT is disabled."),
        row("mss", "Path MTU", config.clampMss !== false, config.clampMss !== false ? "MSS clamp is staged for edge/VPN safety." : "Review MTU/MSS behavior on the edge path."),
      ];
    case "east-west":
      return [
        ...common,
        row("no-source-nat", "No source NAT", !masquerade && sourceNat.length === 0, !masquerade && sourceNat.length === 0 ? "Segmentation path preserves original source identity." : "Remove source NAT or prove return-routing intent."),
        row("detect-mode", "Inspection mode", ids.enabled === true && ids.mode === "IDS_MODE_DETECT", "IDS detect posture should be reviewed before inline enforcement."),
        row("return-route", "Return route proof", false, "Collect upstream return-route proof in Routing & VPN before production commit.", { status: "required" }),
      ];
    case "vpn-edge":
      return [
        ...common,
        row("no-source-nat", "No source NAT", !masquerade && sourceNat.length === 0, !masquerade && sourceNat.length === 0 ? "Protected-subnet traffic is not hidden by source NAT." : "Remove source NAT before VPN route proof."),
        row("tunnel-proof", "Tunnel proof", false, "Create tunnel peers and prove protected-subnet route posture in Routing & VPN.", { status: "required" }),
        row("secret-boundary", "Secret boundary", true, "Setup does not generate PSKs, private keys, or enrollment bundles."),
      ];
    case "ids-tap":
      return [
        ...common,
        row("no-forwarding", "No forwarding path", !outboundRule && !masquerade, !outboundRule && !masquerade ? "No outbound allow or source NAT is staged." : "Remove forwarding/NAT before treating this as a passive tap."),
        row("offload", "Offload posture", !network.enableFlowOffload, !network.enableFlowOffload ? "Flow offload is disabled for inspection visibility." : "Disable flow offload for passive IDS visibility."),
        row("mirror-proof", "Mirror visibility", false, "Collect mirror/SPAN packet visibility proof from Capture/Troubleshoot.", { status: "required" }),
      ];
    case "lab": {
      const exampleCidr = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"].includes(String(config.insideCidr || "").trim());
      return [
        ...common,
        row("lab-cidr", "Lab CIDR", !exampleCidr, exampleCidr ? "Replace documentation CIDR space before non-disposable use." : `${config.insideCidr} is operator supplied.`),
        row("candidate-only", "Candidate-only", true, "Baseline remains staged until Changes validation and commit."),
      ];
    }
    default:
      return [
        ...common,
        row("custom-review", "Custom review", false, "Review generated policy, NAT, routing, and host-input scope before commit.", { status: "required" }),
      ];
  }
}

export function splitInterfaceList(value = "") {
  const seen = new Set();
  const out = [];
  for (const part of String(value || "").split(",")) {
    const name = part.trim();
    if (!name || seen.has(name)) continue;
    seen.add(name);
    out.push(name);
  }
  return out;
}

function interfaceAssignments(config = {}) {
  return {
    inside: new Set(splitInterfaceList(config.insideInterfaces)),
    outside: new Set(splitInterfaceList(config.outsideInterfaces)),
  };
}

function interfaceDetail(iface) {
  const drops = Number(iface.rxDrops || 0) + Number(iface.txDrops || 0);
  const errors = Number(iface.rxErrors || 0) + Number(iface.txErrors || 0);
  const traffic = `${fmt.bytes(iface.rxBytes)} in / ${fmt.bytes(iface.txBytes)} out`;
  const health = [drops ? `${drops} drops` : "", errors ? `${errors} errors` : ""].filter(Boolean).join(" · ");
  return health ? `${traffic} · ${health}` : traffic;
}
