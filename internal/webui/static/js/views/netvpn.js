// Routing & VPN. Static routes, BGP, OSPF, IPsec, and WireGuard are editable
// through the candidate. Secret material never enters policy; VPN config stores
// only file paths to node-local key/secret files.

import { h, icon, clear } from "../core.js";
import { api } from "../api.js";
import { openAutomationContext } from "../automation_context.js";
import { activeInvestigationServerCaseHref, appendInvestigationPacketToActiveServerCase, pinInvestigationPacket } from "../investigation_case.js";
import { buildInvestigationPacket, vpnTunnelHandoffPacket, investigationPacketFilename, investigationPacketJson, investigationPacketText } from "../investigation_packet.js";
import { equal, session } from "../policy.js";
import { qrCodeCapacity, qrCodeSvg } from "../qr_code.js";
import { buildHash, readQueryState, writeQueryState } from "../query_state.js";
import { pageHead, emptyState, pill, card, toast, openDrawer, closeDrawer, confirmDialog, labeledCell, responsiveTable } from "../ui.js";

export const NETVPN_ROUTE_DEFAULTS = Object.freeze({
  drawer: "",
  kind: "",
  name: "",
  iface: "",
  peer: "",
  local: "",
  remote: "",
  src: "",
  dst: "",
  protocol: "",
  port: "",
  mode: "",
  engine: "",
});
export const NETVPN_ROUTE_KEYS = Object.freeze(Object.keys(NETVPN_ROUTE_DEFAULTS));

let runtimeStatus = {};
let routePath = "/netvpn";
let routeState = normalizeNetvpnRoute();
let lastOpenedTunnelRoute = "";
const IPSEC_SECRET_ROOTS = ["/etc/phragma/secrets", "/etc/openngfw/secrets"];
const WIREGUARD_KEY_ROOTS = ["/etc/phragma/keys", "/etc/openngfw/keys"];

export async function render(ctx = {}) {
  routePath = ctx.path || "/netvpn";
  routeState = normalizeNetvpnRoute(ctx.query || {});
  lastOpenedTunnelRoute = "";
  const [sessionResult, statusResult] = await Promise.allSettled([session.load(), api.status()]);
  if (sessionResult.status === "rejected") throw sessionResult.reason;
  runtimeStatus = statusResult.status === "fulfilled" ? statusResult.value || {} : {};
  const root = h("div", {});
  paint(root);
  maybeOpenRouteBackedDrawer(root);
  return root;
}

function paint(root) {
  clear(root);
  const draft = session.draft || {};
  root.appendChild(pageHead("Routing & VPN", "Static routes, dynamic routing, and VPN are staged through the candidate.",
    [
      h("button", { class: "btn primary", type: "button", title: "Open WireGuard branch rollout", "aria-label": "Open WireGuard branch rollout workflow", dataset: { netvpnAction: "open-wireguard-rollout" }, onclick: () => openWireguardRolloutDrawer(root) }, h("span", { html: icon("vpn", 16) }), "Branch rollout"),
      h("button", { class: "btn", type: "button", title: "Add static route", "aria-label": "Add static route to candidate", dataset: { netvpnAction: "add-route" }, onclick: () => editRoute(root, null) }, h("span", { html: icon("plus", 16) }), "Add route"),
    ]));

  root.appendChild(staticRoutesCard(root));
  root.appendChild(h("div", { style: { height: "16px" } }));
  root.appendChild(h("div", { class: "grid cols-2" }, bgpCard(root, draft.routing?.bgp), ospfCard(root, draft.routing?.ospf)));
  root.appendChild(h("div", { style: { height: "16px" } }));
  root.appendChild(h("div", { class: "grid cols-2" }, ipsecCard(root, draft.vpn?.ipsecTunnels), wireguardCard(root, draft.vpn?.wireguardInterfaces)));
  root.appendChild(h("div", { style: { height: "16px" } }));
  root.appendChild(vpnRuntimeReviewCard(root, draft));
  root.appendChild(h("div", { style: { height: "16px" } }));
  root.appendChild(tunnelPathChecksCard(draft));
}

export function normalizeNetvpnRoute(query = {}) {
  const state = readQueryState(query, NETVPN_ROUTE_DEFAULTS, NETVPN_ROUTE_KEYS);
  const drawer = normalizeNetvpnDrawer(state.drawer);
  if (!drawer) return { ...NETVPN_ROUTE_DEFAULTS };
  const mode = drawer === "tunnel" ? "" : normalizeNetvpnMode(state.mode);
  if (drawer === "runtime-review") {
    return { ...NETVPN_ROUTE_DEFAULTS, drawer, engine: cleanRouteToken(state.engine) };
  }
  if (drawer === "bgp" || drawer === "ospf") return { ...NETVPN_ROUTE_DEFAULTS, drawer, mode };
  if (drawer === "route") {
    const name = cleanRouteCidr(state.name) || cleanRouteToken(state.name);
    return { ...NETVPN_ROUTE_DEFAULTS, drawer, name, mode };
  }
  const kind = normalizeTunnelKind(state.kind);
  if (!kind) return { ...NETVPN_ROUTE_DEFAULTS };
  const pathState = {
    local: cleanRouteCidr(state.local),
    remote: cleanRouteCidr(state.remote),
    src: cleanRouteIp(state.src),
    dst: cleanRouteIp(state.dst),
    protocol: cleanRouteProtocol(state.protocol),
    port: cleanRoutePort(state.port),
  };
  if (kind === "ipsec") {
    const name = cleanRouteToken(state.name);
    if (!name) return { ...NETVPN_ROUTE_DEFAULTS };
    return { ...NETVPN_ROUTE_DEFAULTS, drawer, kind, name, iface: "", peer: "", mode, ...pathState };
  }
  const iface = cleanRouteToken(state.iface);
  const peer = cleanRouteToken(state.peer || state.name);
  if (!iface || !peer) return { ...NETVPN_ROUTE_DEFAULTS };
  return { ...NETVPN_ROUTE_DEFAULTS, drawer, kind, name: "", iface, peer, mode, ...pathState };
}

export function netvpnTunnelRouteState(ref = {}) {
  const kind = normalizeTunnelKind(ref.kind);
  const target = Array.isArray(ref.targets) ? ref.targets[0] || {} : {};
  const pathState = {
    local: cleanRouteCidr(target.localCidr || ref.localCidr || ""),
    remote: cleanRouteCidr(target.remoteCidr || ref.remoteCidr || ""),
    src: cleanRouteIp(target.srcIp || ref.srcIp || ""),
    dst: cleanRouteIp(target.destIp || ref.destIp || ""),
    protocol: cleanRouteProtocol(target.protocol || ref.protocol || (kind ? "PROTOCOL_UDP" : "")),
    port: cleanRoutePort(ref.port || ref.listenPort || (kind === "ipsec" ? 4500 : kind === "wireguard" ? 51820 : "")),
  };
  if (kind === "ipsec") {
    const name = cleanRouteToken(ref.name || ref.tunnelName);
    return name ? { ...NETVPN_ROUTE_DEFAULTS, drawer: "tunnel", kind, name, iface: "", peer: "", mode: "", ...pathState } : { ...NETVPN_ROUTE_DEFAULTS };
  }
  if (kind === "wireguard") {
    const iface = cleanRouteToken(ref.iface || ref.interfaceName || ref.interface);
    const peer = cleanRouteToken(ref.peer || ref.peerName || ref.name);
    return iface && peer ? { ...NETVPN_ROUTE_DEFAULTS, drawer: "tunnel", kind, name: "", iface, peer, mode: "", ...pathState } : { ...NETVPN_ROUTE_DEFAULTS };
  }
  return { ...NETVPN_ROUTE_DEFAULTS };
}

export function netvpnStaticRouteState(route = {}, mode = "review") {
  const name = cleanRouteCidr(route.destination || route.name || "") || cleanRouteToken(route.destination || route.name || "");
  return { ...NETVPN_ROUTE_DEFAULTS, drawer: "route", name, mode: normalizeNetvpnMode(mode) };
}

export function netvpnDynamicRouteState(kind = "", mode = "review") {
  const drawer = normalizeNetvpnDrawer(kind);
  return drawer === "bgp" || drawer === "ospf" ? { ...NETVPN_ROUTE_DEFAULTS, drawer, mode: normalizeNetvpnMode(mode) } : { ...NETVPN_ROUTE_DEFAULTS };
}

export function vpnTunnelHash(ref = {}, path = "/netvpn") {
  return buildHash(path, netvpnTunnelRouteState(ref), NETVPN_ROUTE_DEFAULTS, NETVPN_ROUTE_KEYS);
}

function setNetvpnDrawerState(model) {
  routeState = netvpnTunnelRouteState(model);
  writeQueryState(routePath, routeState, NETVPN_ROUTE_DEFAULTS, NETVPN_ROUTE_KEYS);
}

function setNetvpnRouteState(state) {
  routeState = normalizeNetvpnRoute(state);
  writeQueryState(routePath, routeState, NETVPN_ROUTE_DEFAULTS, NETVPN_ROUTE_KEYS);
}

function clearNetvpnDrawerState() {
  routeState = { ...NETVPN_ROUTE_DEFAULTS };
  lastOpenedTunnelRoute = "";
  if (typeof location !== "undefined" && (location.hash || "").startsWith("#/netvpn")) {
    writeQueryState(routePath, routeState, NETVPN_ROUTE_DEFAULTS, NETVPN_ROUTE_KEYS);
  }
}

function maybeOpenRouteBackedDrawer(root) {
  if (routeState.drawer === "route") {
    const idx = selectedStaticRouteIndex(session.draft || {}, routeState);
    if (routeState.mode === "edit") editRoute(root, idx >= 0 ? idx : null, { sync: false, routeBacked: true });
    else openStaticRouteReviewDrawer(root, idx >= 0 ? idx : null, { sync: false, routeBacked: true });
    return;
  }
  if (routeState.drawer === "bgp") {
    if (routeState.mode === "edit") editBgp(root, { sync: false, routeBacked: true });
    else openDynamicRouteReviewDrawer(root, "bgp", { sync: false, routeBacked: true });
    return;
  }
  if (routeState.drawer === "ospf") {
    if (routeState.mode === "edit") editOspf(root, { sync: false, routeBacked: true });
    else openDynamicRouteReviewDrawer(root, "ospf", { sync: false, routeBacked: true });
    return;
  }
  if (routeState.drawer === "runtime-review") {
    openRuntimeReviewDrawer(root, { sync: false, routeBacked: true, engine: routeState.engine });
    return;
  }
  if (routeState.drawer !== "tunnel") return;
  const model = selectedVpnTunnelModel(session.draft || {}, runtimeStatus, routeState);
  if (!model) return;
  const fullState = netvpnTunnelRouteState(model);
  if (JSON.stringify(fullState) !== JSON.stringify(routeState)) {
    routeState = fullState;
    writeQueryState(routePath, routeState, NETVPN_ROUTE_DEFAULTS, NETVPN_ROUTE_KEYS);
  }
  const key = JSON.stringify(fullState);
  if (key === lastOpenedTunnelRoute) return;
  lastOpenedTunnelRoute = key;
  openVpnTunnelDrawer(model, root, { sync: false, routeBacked: true });
}

function normalizeNetvpnDrawer(value = "") {
  const normalized = String(value || "").trim().toLowerCase();
  return ["tunnel", "route", "bgp", "ospf", "runtime-review"].includes(normalized) ? normalized : "";
}

function normalizeNetvpnMode(value = "") {
  const normalized = String(value || "").trim().toLowerCase();
  return normalized === "edit" ? "edit" : "review";
}

function normalizeTunnelKind(value = "") {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "ipsec" || normalized === "ipsec-tunnel") return "ipsec";
  if (normalized === "wireguard" || normalized === "wg") return "wireguard";
  return "";
}

function cleanRouteToken(value = "") {
  return String(value || "").trim().replace(/[^a-zA-Z0-9_.:-]/g, "").slice(0, 96);
}

function cleanRouteIp(value = "") {
  const text = String(value || "").trim();
  if (!text || text.length > 64 || !/^[0-9A-Fa-f:.]+$/.test(text)) return "";
  return text;
}

function cleanRouteCidr(value = "") {
  const text = String(value || "").trim();
  if (!text || text.length > 80 || !/^[0-9A-Fa-f:./]+$/.test(text)) return "";
  return text;
}

function cleanRouteProtocol(value = "") {
  const text = String(value || "").trim().toUpperCase();
  if (text === "UDP" || text === "PROTOCOL_UDP") return "PROTOCOL_UDP";
  if (text === "TCP" || text === "PROTOCOL_TCP") return "PROTOCOL_TCP";
  if (text === "ICMP" || text === "PROTOCOL_ICMP") return "PROTOCOL_ICMP";
  if (text === "ANY" || text === "PROTOCOL_ANY") return "PROTOCOL_ANY";
  return "";
}

function cleanRoutePort(value = "") {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return "";
  return String(port);
}

// ---------- Static routes (editable) ----------
function staticRoutesCard(root) {
  const routes = session.draft.staticRoutes || [];
  const head = h("div", { class: "card-head" }, h("h2", {}, "Static routes"),
    h("span", { class: "spacer" }), h("span", { class: "hint" }, "the firewall's own routing table"));
  if (!routes.length) {
    return h("div", { class: "card" }, head,
      emptyState("changes", "No static routes", "Add routes the firewall uses to reach networks beyond its directly-connected subnets (e.g. via a cloud subnet gateway).",
        h("button", { class: "btn primary", type: "button", title: "Add static route", "aria-label": "Add static route to candidate", dataset: { netvpnAction: "add-route" }, onclick: () => editRoute(root, null) }, h("span", { html: icon("plus", 16) }), "Add route")));
  }
  const rows = routes.map((r, i) => {
    const routeLabel = r.destination || `route ${i + 1}`;
    return h("tr", {},
    labeledCell("Destination", { class: "mono" }, h("strong", {}, r.destination || "—")),
    labeledCell("Via", { class: "mono" }, r.via || h("span", { class: "muted" }, "—")),
    labeledCell("Interface", { class: "mono" }, r.interface || h("span", { class: "muted" }, "—")),
    labeledCell("Metric", { class: "num" }, r.metric || h("span", { class: "muted" }, "—")),
    labeledCell("Actions", { class: "cell-actions" }, h("div", { class: "flex row-actions" },
      h("button", { class: "icon-btn", type: "button", title: "Review route", "aria-label": `Review static route ${routeLabel}`, dataset: { netvpnAction: "review-route" }, onclick: () => openStaticRouteReviewDrawer(root, i), html: icon("search", 16) }),
      h("button", { class: "icon-btn", type: "button", title: "Edit", "aria-label": `Edit static route ${routeLabel}`, dataset: { netvpnAction: "edit-route" }, onclick: () => editRoute(root, i), html: icon("edit", 16) }),
      h("button", { class: "icon-btn", type: "button", title: "Delete", "aria-label": `Delete static route ${routeLabel}`, dataset: { netvpnAction: "delete-route" }, onclick: () => delRoute(root, i, r), html: icon("trash", 16) }))));
  });
  return h("div", { class: "card surface-zero" },
    h("div", { class: "section-head-pad" }, head),
    h("div", { class: "table-wrap flat" },
      responsiveTable(["Destination", "Via", "Interface", { label: "Metric", attrs: { class: "num" } }, { label: "", attrs: { class: "actions-col" } }], rows)));
}

async function delRoute(root, idx, r) {
  if (!(await confirmDialog({ title: "Delete route?", message: `Remove route to ${r.destination}? Stages to the candidate; the kernel route is removed on commit.`, confirmLabel: "Delete", danger: true }))) return;
  try { await session.apply((d) => d.staticRoutes.splice(idx, 1)); paint(root); toast("Route deleted", "Staged to candidate.", "ok"); }
  catch (e) { toast("Failed", e.message, "bad"); }
}

function selectedStaticRouteIndex(policy = {}, state = {}) {
  const name = cleanRouteCidr(state.name) || cleanRouteToken(state.name);
  if (!name) return -1;
  return (policy.staticRoutes || []).findIndex((route) => route?.destination === name);
}

function openStaticRouteReviewDrawer(root, idx, opts = {}) {
  const route = idx != null && idx >= 0 ? session.draft.staticRoutes?.[idx] : null;
  if (opts.sync !== false) setNetvpnRouteState(netvpnStaticRouteState(route || routeState, "review"));
  openDrawer({
    title: route ? "Static route review" : "Static route review",
    subtitle: route?.destination || routeState.name || "new route",
    width: "560px",
    onClose: clearNetvpnDrawerState,
    body: h("div", { dataset: { netvpnRouteDrawer: "true" } },
      opts.routeBacked ? h("div", { class: "note", style: { marginBottom: "10px" } }, "Opened from route-backed static route state.") : null,
      route ? h("dl", { class: "kv compact" },
        kv("Destination", route.destination || "—"),
        kv("Via", route.via || "on-link"),
        kv("Interface", route.interface || "not pinned"),
        kv("Metric", route.metric || "default"),
        kv("Candidate action", "Rendered to ip route replace on commit")) :
        emptyState("search", "Route not found", "The selected static route is not present in the candidate policy.")),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close static route review", "aria-label": "Close static route review", dataset: { netvpnAction: "close-route-review" }, onclick: closeDrawer }, "Close"),
      route ? h("button", { class: "btn primary", type: "button", title: "Edit static route from review", "aria-label": `Edit static route ${route.destination || "selected route"} from review`, dataset: { netvpnAction: "edit-route-from-review" }, onclick: () => editRoute(root, idx) }, h("span", { html: icon("edit", 16) }), "Edit route") : null,
    ],
  });
}

function editRoute(root, idx, opts = {}) {
  const editing = idx != null;
  const r = editing ? structuredClone(session.draft.staticRoutes[idx]) : {};
  if (opts.sync !== false) setNetvpnRouteState(netvpnStaticRouteState(r, "edit"));
  const dest = inp(r.destination, "10.0.0.192/26  or  0.0.0.0/0");
  const via = inp(r.via, "10.0.0.65  (next-hop IP; blank for on-link)");
  const iface = inp(r.interface, "enp1s0  (optional egress NIC)");
  const metric = h("input", { class: "input", type: "number", min: "0", value: r.metric || "", placeholder: "optional" });

  openDrawer({
    title: editing ? "Edit static route" : "Add static route",
    subtitle: "Rendered to `ip route replace` and applied on commit.",
    width: "520px",
    onClose: clearNetvpnDrawerState,
    body: h("div", {},
      opts.routeBacked ? h("div", { class: "note", style: { marginBottom: "10px" } }, "Opened from route-backed static route edit state.") : null,
      field("Destination prefix", dest, "CIDR; use 0.0.0.0/0 for a default route"),
      field("Via (next hop)", via, "gateway IP reachable on a connected subnet; leave blank for an on-link/interface route"),
      field("Egress interface", iface, "optional; pins the route to a NIC"),
      field("Metric", metric, "optional; lower wins")),
    footer: [h("button", { class: "btn ghost", type: "button", title: "Cancel static route edit", "aria-label": "Cancel static route edit", dataset: { netvpnAction: "cancel-route" }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: editing ? "Save static route changes" : "Stage new static route", "aria-label": editing ? "Save static route changes to candidate" : "Stage new static route to candidate", dataset: { netvpnAction: "stage-route" }, onclick: save }, h("span", { html: icon("check", 16) }), "Save route")],
  });

  async function save() {
    const destV = dest.value.trim();
    if (!destV) { toast("Destination required", "Enter a destination CIDR.", "warn"); return; }
    const route = { destination: destV };
    if (via.value.trim()) route.via = via.value.trim();
    if (iface.value.trim()) route.interface = iface.value.trim();
    const m = parseInt(metric.value, 10);
    if (!isNaN(m) && m > 0) route.metric = m;
    try {
      await session.apply((d) => {
        d.staticRoutes ||= [];
        if (editing) d.staticRoutes[idx] = route; else d.staticRoutes.push(route);
      });
      closeDrawer(); paint(root); toast(editing ? "Route saved" : "Route added", "Staged to candidate.", "ok");
    } catch (e) { toast("Could not stage route", e.message, "bad"); }
  }
}

function field(label, control, help) {
  return h("label", { class: "field" }, h("span", {}, label, help ? h("span", { class: "help" }, " — " + help) : null), control);
}
function inp(v, ph) { return h("input", { class: "input", value: v || "", placeholder: ph }); }

function checkbox(on, opts = {}) {
  const i = h("input", { type: "checkbox", disabled: opts.disabled });
  i.checked = on;
  const l = h("label", { class: "switch" + (opts.disabled ? " disabled" : "") }, i, h("span", { class: "slider" }));
  Object.defineProperty(l, "checked", { get: () => i.checked });
  Object.defineProperty(l, "disabled", { get: () => i.disabled });
  return l;
}

function netvpnSection(section, node) {
  node.dataset.netvpnSection = section;
  return node;
}

// ---------- BGP (editable) / read-only OSPF + VPN ----------
function bgpCard(root, bgp = {}) {
  bgp = bgp || {};
  const frrRuntime = runtimeStatus.routing?.frr || {};
  const runtimeRows = bgpRuntimeRows(frrRuntime);
  const runtimeByPeer = bgpRuntimeByPeer(frrRuntime);
  const dirty = !equal((session.running.routing || {}).bgp || {}, (session.draft.routing || {}).bgp || {});
  const header = h("h2", {}, "BGP", h("span", { class: "spacer" }),
    dirty ? pill("candidate edit", "warn") : null,
    runtimeRows.length || bgp.enabled ? pill("runtime " + (frrRuntime.state || "unknown"), runtimeStateClass(frrRuntime.state)) : null,
    pill(bgp.enabled ? "enabled" : "disabled", bgp.enabled ? "ok" : "neutral"));
  if (!bgp.enabled) return netvpnSection("bgp", card(header,
    runtimeRows.length ? h("div", { class: "note", style: { marginBottom: "10px" } }, frrRuntime.detail || "BGP peers are still visible in the running FRR state.") : null,
    runtimeRows.length ? bgpRuntimeTable(runtimeRows) : null,
    emptyState("globe", "BGP not enabled", "No BGP configuration in the candidate policy.",
      [
        h("button", { class: "btn primary", type: "button", title: "Configure BGP candidate settings", "aria-label": "Configure BGP candidate settings", dataset: { netvpnAction: "configure-bgp" }, onclick: () => editBgp(root) }, h("span", { html: icon("edit", 16) }), "Configure BGP"),
        h("button", { class: "btn", type: "button", title: "Review BGP route context", "aria-label": "Review BGP route context", dataset: { netvpnAction: "review-bgp" }, onclick: () => openDynamicRouteReviewDrawer(root, "bgp") }, h("span", { html: icon("search", 16) }), "Review"),
      ])));
  return netvpnSection("bgp", card(header,
    frrRuntime.detail ? h("div", { class: "note", style: { margin: "0 0 10px" } }, frrRuntime.detail) : null,
    h("dl", { class: "kv", style: { marginBottom: "12px" } },
      h("dt", {}, "Local ASN"), h("dd", { class: "mono" }, bgp.asn || "—"),
      h("dt", {}, "Router ID"), h("dd", { class: "mono" }, bgp.routerId || "—")),
    h("div", { class: "note" }, "Neighbors"),
    (bgp.neighbors || []).length ? responsiveTable(["Peer", "ASN", "Description", "Runtime"], bgp.neighbors.map((n) =>
      h("tr", {},
        labeledCell("Peer", { class: "mono" }, n.address),
        labeledCell("ASN", {}, "AS " + n.remoteAsn),
        labeledCell("Description", { class: "muted" }, n.description || ""),
        labeledCell("Runtime", {}, bgpRuntimeCell(runtimeByPeer.get(n.address || ""))))))
      : h("div", { class: "note" }, "none"),
    bgp.announceNetworks?.length ? h("div", { style: { marginTop: "10px" } }, h("div", { class: "note" }, "Announced"), bgp.announceNetworks.map((x) => h("span", { class: "tag" }, x))) : null,
    h("div", { class: "flex wrap", style: { marginTop: "12px" } },
      h("button", { class: "btn", type: "button", title: "Review BGP route context", "aria-label": "Review BGP route context", dataset: { netvpnAction: "review-bgp" }, onclick: () => openDynamicRouteReviewDrawer(root, "bgp") }, h("span", { html: icon("search", 16) }), "Review"),
      h("button", { class: "btn", type: "button", title: "Edit BGP candidate settings", "aria-label": "Edit BGP candidate settings", dataset: { netvpnAction: "configure-bgp" }, onclick: () => editBgp(root) }, h("span", { html: icon("edit", 16) }), "Edit BGP"),
      h("button", { class: "btn ghost", type: "button", title: "Disable BGP in candidate", "aria-label": "Disable BGP in candidate", dataset: { netvpnAction: "disable-bgp" }, onclick: () => disableBgp(root) }, "Disable"))));
}

function bgpRuntimeTable(rows) {
  return responsiveTable(["Peer", "Runtime"], rows.slice(0, 6).map((row) => h("tr", {},
    labeledCell("Peer", { class: "mono" }, runtimeString(row, "peer")),
    labeledCell("Runtime", {}, bgpRuntimeCell(row)))));
}

function bgpRuntimeCell(peer) {
  if (!peer) return h("span", { class: "muted" }, "not observed");
  return h("div", { class: "flex wrap" },
    pill(runtimeString(peer, "state") || "observed", runtimeStateClass(runtimeString(peer, "state"))),
    runtimeNumber(peer, "prefixesReceived", "prefixes_received") ? h("span", { class: "tag" }, runtimeNumber(peer, "prefixesReceived", "prefixes_received") + " pfx") : null,
    runtimeString(peer, "uptime") ? h("span", { class: "tag" }, runtimeString(peer, "uptime")) : null);
}

function openDynamicRouteReviewDrawer(root, kind, opts = {}) {
  const normalized = kind === "ospf" ? "ospf" : "bgp";
  if (opts.sync !== false) setNetvpnRouteState(netvpnDynamicRouteState(normalized, "review"));
  const frrRuntime = runtimeStatus.routing?.frr || {};
  const policy = normalized === "bgp" ? session.draft.routing?.bgp || {} : session.draft.routing?.ospf || {};
  const title = normalized === "bgp" ? "BGP route review" : "OSPF route review";
  const runtimeSummary = normalized === "bgp"
    ? `${bgpRuntimeRows(frrRuntime).length} BGP neighbor${bgpRuntimeRows(frrRuntime).length === 1 ? "" : "s"} observed`
    : ospfRuntimeSummary(frrRuntime);
  openDrawer({
    title,
    subtitle: "Candidate configuration and passive FRR status",
    width: "640px",
    onClose: clearNetvpnDrawerState,
    body: h("div", { dataset: { netvpnDynamicRouteDrawer: normalized } },
      opts.routeBacked ? h("div", { class: "note", style: { marginBottom: "10px" } }, `Opened from route-backed ${normalized.toUpperCase()} review state.`) : null,
      h("div", { class: "preflight-summary" },
        metricBlock("Candidate", policy.enabled ? "enabled" : "disabled", policy.enabled ? "ok" : "neutral"),
        metricBlock("Runtime", frrRuntime.state || "not observed", runtimeStateClass(frrRuntime.state)),
        metricBlock("Evidence", runtimeSummary, "neutral")),
      normalized === "bgp"
        ? h("dl", { class: "kv compact" },
            kv("Local ASN", policy.asn || "—"),
            kv("Router ID", policy.routerId || "—"),
            kv("Configured neighbors", String((policy.neighbors || []).length)),
            kv("Announced networks", (policy.announceNetworks || []).join(", ") || "none"))
        : h("dl", { class: "kv compact" },
            kv("Router ID", policy.routerId || "—"),
            kv("Configured areas", String((policy.areas || []).length)),
            kv("Runtime neighbors", runtimeSummary)),
      frrRuntime.detail ? h("div", { class: "note", style: { marginTop: "10px" } }, frrRuntime.detail) : null),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: `Close ${normalized.toUpperCase()} review`, "aria-label": `Close ${normalized.toUpperCase()} review`, dataset: { netvpnAction: `close-${normalized}-review` }, onclick: closeDrawer }, "Close"),
      h("button", { class: "btn primary", type: "button", title: `Edit ${normalized.toUpperCase()} from review`, "aria-label": `Edit ${normalized.toUpperCase()} from review`, dataset: { netvpnAction: `edit-${normalized}-from-review` }, onclick: () => normalized === "bgp" ? editBgp(root) : editOspf(root) }, h("span", { html: icon("edit", 16) }), "Edit"),
    ],
  });
}

function editBgp(root, opts = {}) {
  const b = structuredClone(session.draft.routing?.bgp || { enabled: true });
  if (opts.sync !== false) setNetvpnRouteState(netvpnDynamicRouteState("bgp", "edit"));
  const enabled = checkbox(b.enabled !== false);
  enabled.dataset.netvpnBgpField = "enabled";
  const asn = h("input", { class: "input", type: "number", min: "1", max: "4294967295", value: b.asn || "", placeholder: "65001", dataset: { netvpnBgpField: "local-asn" } });
  const routerId = inp(b.routerId, "192.0.2.1");
  routerId.dataset.netvpnBgpField = "router-id";
  const neighbors = h("div", { class: "form-list" });
  const neighborRows = [];
  const announces = h("div", { class: "form-list" });
  const announceRows = [];

  const addNeighbor = (n = {}) => {
    const address = inp(n.address, "198.51.100.2");
    address.dataset.netvpnBgpField = "neighbor-address";
    const remoteAsn = h("input", { class: "input", type: "number", min: "1", max: "4294967295", value: n.remoteAsn || "", placeholder: "65002", dataset: { netvpnBgpField: "neighbor-remote-asn" } });
    const description = inp(n.description, "upstream-router");
    description.dataset.netvpnBgpField = "neighbor-description";
    const rec = { address, remoteAsn, description, row: null };
    rec.row = h("div", { class: "form-row three" },
      field("Neighbor address", address),
      field("Remote ASN", remoteAsn),
      field("Description", description),
      h("button", { class: "icon-btn", type: "button", title: "Remove neighbor", "aria-label": "Remove BGP neighbor", dataset: { netvpnAction: "remove-bgp-neighbor" }, onclick: () => { rec.row.remove(); neighborRows.splice(neighborRows.indexOf(rec), 1); }, html: icon("trash", 16) }));
    neighborRows.push(rec);
    neighbors.appendChild(rec.row);
  };

  const addAnnouncement = (prefix = "") => {
    const cidr = inp(prefix, "10.10.0.0/24");
    cidr.dataset.netvpnBgpField = "announce-prefix";
    const rec = { cidr, row: null };
    rec.row = h("div", { class: "form-row single" },
      field("Announced prefix", cidr),
      h("button", { class: "icon-btn", type: "button", title: "Remove prefix", "aria-label": "Remove BGP announced prefix", dataset: { netvpnAction: "remove-bgp-prefix" }, onclick: () => { rec.row.remove(); announceRows.splice(announceRows.indexOf(rec), 1); }, html: icon("trash", 16) }));
    announceRows.push(rec);
    announces.appendChild(rec.row);
  };

  (b.neighbors || []).forEach(addNeighbor);
  if (!neighborRows.length) addNeighbor();
  (b.announceNetworks || []).forEach(addAnnouncement);

  openDrawer({
    title: "Configure BGP",
    subtitle: "Staged to the candidate and rendered by FRR on commit.",
    width: "760px",
    onClose: clearNetvpnDrawerState,
    body: h("div", { dataset: { netvpnBgpDrawer: "true" } },
      opts.routeBacked ? h("div", { class: "note", style: { marginBottom: "10px" } }, "Opened from route-backed BGP edit state.") : null,
      h("label", { class: "field flex", style: { justifyContent: "space-between" } }, h("span", {}, "Enable BGP"), enabled),
      h("div", { class: "form-grid two" },
        field("Local ASN", asn),
        field("Router ID", routerId)),
      h("div", { class: "divider" }),
      h("div", { class: "flex", style: { justifyContent: "space-between", marginBottom: "8px" } },
        h("strong", {}, "Neighbors"),
        h("button", { class: "btn sm", type: "button", title: "Add BGP neighbor row", "aria-label": "Add BGP neighbor row", dataset: { netvpnAction: "add-bgp-neighbor" }, onclick: () => addNeighbor() }, h("span", { html: icon("plus", 14) }), "Add neighbor")),
      neighbors,
      h("div", { class: "divider" }),
      h("div", { class: "flex", style: { justifyContent: "space-between", marginBottom: "8px" } },
        h("strong", {}, "Announced networks"),
        h("button", { class: "btn sm", type: "button", title: "Add BGP announced prefix row", "aria-label": "Add BGP announced prefix row", dataset: { netvpnAction: "add-bgp-prefix" }, onclick: () => addAnnouncement() }, h("span", { html: icon("plus", 14) }), "Add prefix")),
      announces),
    footer: [h("button", { class: "btn ghost", type: "button", title: "Cancel BGP configuration", "aria-label": "Cancel BGP configuration", dataset: { netvpnAction: "cancel-bgp" }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: "Stage BGP candidate settings", "aria-label": "Stage BGP candidate settings", dataset: { netvpnAction: "stage-bgp" }, onclick: save }, h("span", { html: icon("check", 16) }), "Stage BGP")],
  });

  async function save() {
    const next = bgpFromInputs(enabled, asn, routerId, neighborRows, announceRows);
    if (next.error) { toast("BGP not staged", next.error, "warn"); return; }
    try {
      await session.apply((d) => {
        d.routing ||= {};
        d.routing.bgp = next.bgp;
      });
      closeDrawer(); paint(root); toast("BGP staged", "Commit to update FRR.", "ok");
    } catch (e) { toast("Could not stage BGP", e.message, "bad"); }
  }
}

async function disableBgp(root) {
  if (!(await confirmDialog({ title: "Disable BGP?", message: "BGP will be disabled in the candidate. FRR is updated when the candidate is committed.", confirmLabel: "Disable", danger: true }))) return;
  try {
    await session.apply((d) => {
      d.routing ||= {};
      d.routing.bgp = { ...(d.routing.bgp || {}), enabled: false };
    });
    paint(root); toast("BGP disabled", "Staged to candidate.", "ok");
  } catch (e) { toast("Could not disable BGP", e.message, "bad"); }
}

export function bgpFromInputs(enabled, asn, routerId, neighborRows, announceRows) {
  const on = enabled.checked;
  const bgp = { enabled: on };
  const asnText = asn.value.trim();
  const asnValue = Number(asnText);
  if (validAsnValue(asnText)) bgp.asn = asnValue;
  if (routerId.value.trim()) bgp.routerId = routerId.value.trim();
  bgp.neighbors = neighborRows.map((r) => ({
    address: r.address.value.trim(),
    remoteAsn: validAsnValue(r.remoteAsn.value.trim()) ? Number(r.remoteAsn.value.trim()) : 0,
    remoteAsnText: r.remoteAsn.value.trim(),
    description: r.description.value.trim(),
  })).filter((n) => n.address || n.remoteAsn || n.description);
  bgp.announceNetworks = announceRows.map((r) => r.cidr.value.trim()).filter(Boolean);
  bgp.neighbors = bgp.neighbors.map((n) => {
    const { remoteAsnText, ...neighbor } = n;
    return neighbor;
  });
  if (!on) return { bgp };
  const stagedNeighbors = neighborRows.map((r) => ({
    address: r.address.value.trim(),
    remoteAsnText: r.remoteAsn.value.trim(),
    description: r.description.value.trim(),
  })).filter((n) => n.address || n.remoteAsnText || n.description);
  if (!asnText) return { error: "Local ASN is required." };
  if (!validAsnValue(asnText)) return { error: "Local ASN must be an integer from 1 to 4294967295." };
  if (!bgp.routerId) return { error: "Router ID is required." };
  if (!validIPv4Address(bgp.routerId)) return { error: "Router ID must be an IPv4 address." };
  if (!stagedNeighbors.length) return { error: "At least one neighbor is required." };
  for (let i = 0; i < stagedNeighbors.length; i += 1) {
    const n = stagedNeighbors[i];
    if (!n.address) return { error: "Every neighbor needs an address." };
    if (!validIPv4Address(n.address)) return { error: `Neighbor ${n.address || "#" + (i + 1)} address must be an IPv4 address.` };
    if (!n.remoteAsnText) return { error: `Neighbor ${n.address} needs a remote ASN.` };
    if (!validAsnValue(n.remoteAsnText)) return { error: `Neighbor ${n.address || "#" + (i + 1)} remote ASN must be an integer from 1 to 4294967295.` };
    if (hasControlCharacters(n.description)) return { error: `Neighbor ${n.address} description cannot contain control characters.` };
  }
  for (const prefix of bgp.announceNetworks) {
    if (!validCidr(prefix)) return { error: `Announced prefix ${prefix} must be a valid IPv4/IPv6 CIDR.` };
  }
  return { bgp };
}

export function splitList(value) {
  return String(value || "").split(/[,\n]/).map((x) => x.trim()).filter(Boolean);
}

export function validAsnValue(value) {
  const text = String(value || "").trim();
  if (!/^\d+$/.test(text)) return false;
  const n = Number(text);
  return Number.isInteger(n) && n >= 1 && n <= 4294967295;
}

export function validIPv4Address(value) {
  const text = String(value || "").trim();
  const parts = text.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

export function validCidr(value) {
  const text = String(value || "").trim();
  const parts = text.split("/");
  if (parts.length !== 2 || !/^\d+$/.test(parts[1])) return false;
  const prefix = Number(parts[1]);
  if (validIPv4Address(parts[0])) return prefix >= 0 && prefix <= 32;
  return validIPv6Address(parts[0]) && prefix >= 0 && prefix <= 128;
}

function validIPv6Address(value) {
  const text = String(value || "").trim().toLowerCase();
  if (!text || text.includes(":::") || (text.match(/::/g) || []).length > 1) return false;
  const halves = text.split("::");
  const groups = text.includes("::") ? halves.flatMap((half) => half ? half.split(":") : []) : text.split(":");
  if (groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return false;
  return text.includes("::") ? groups.length < 8 : groups.length === 8;
}

function hasControlCharacters(value) {
  return /[\x00-\x1f\x7f]/.test(String(value || ""));
}

export function validPolicyName(value) {
  const text = String(value || "").trim();
  return text !== "any" && /^[a-z0-9]([a-z0-9_-]{0,62}[a-z0-9])?$/.test(text);
}

export function validConfigToken(value, required = false) {
  const text = String(value || "");
  if (!text) return !required;
  return !/[\s\x00-\x1f\x7f{}"'`#;]/.test(text);
}

export function validManagedPath(value, roots = []) {
  const text = String(value || "").trim();
  if (!text.startsWith("/") || /[\s\x00-\x1f\x7f]/.test(text)) return false;
  const parts = text.split("/");
  if (parts.includes("..") || parts.includes(".")) return false;
  if (text.includes("//") || (text.length > 1 && text.endsWith("/"))) return false;
  return roots.some((root) => text.startsWith(root + "/") && text.length > root.length + 1);
}

export function validWireguardInterfaceName(value) {
  const text = String(value || "").trim();
  return Boolean(text) && text.length <= 15 && !/[\/\s\x00-\x1f\x7f]/.test(text);
}

export function validHostPort(value) {
  const text = String(value || "").trim();
  const bracketed = text.match(/^\[([^\]]+)\]:(\d+)$/);
  const plain = !bracketed ? text.match(/^([^:\s]+):(\d+)$/) : null;
  const host = bracketed?.[1] || plain?.[1] || "";
  const portText = bracketed?.[2] || plain?.[2] || "";
  if (!host || !portText) return false;
  const port = Number(portText);
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

function strictOptionalPort(value) {
  const text = String(value || "").trim();
  if (!text || text === "0") return { ok: true, value: 0 };
  if (!/^\d+$/.test(text)) return { ok: false, value: 0 };
  const port = Number(text);
  return { ok: Number.isInteger(port) && port >= 1 && port <= 65535, value: port };
}

function vpnRuntimeReviewCard(root, policy = {}) {
  const rows = vpnRuntimeReviewRows(policy, runtimeStatus);
  const header = h("h2", {}, "VPN expected vs observed", h("span", { class: "spacer" }),
    rows.length ? pill(`${rows.length} review`, "warn") : pill("clear", "ok"));
  if (!rows.length) return card(header,
    emptyState("check", "No passive VPN drift", "Configured VPN tunnels and peers either have matching runtime evidence or do not expose enough status data for a review row."));
  return card(header,
    h("div", { class: "note", style: { marginBottom: "10px" } },
      "Passive review uses the candidate configuration and current status data only; it does not prove protected-subnet reachability or inspect secrets."),
    h("div", { class: "flex wrap", style: { marginBottom: "10px" } },
      h("button", { class: "btn sm ghost", type: "button", title: "Open route-backed VPN runtime review", "aria-label": "Open route-backed VPN runtime review", dataset: { netvpnAction: "open-runtime-review" }, onclick: () => openRuntimeReviewDrawer(root) }, h("span", { html: icon("search", 14) }), "Runtime review")),
    responsiveTable(["Finding", "Expected", "Observed", { label: "Actions", attrs: { class: "actions-col" } }],
      rows.map((row) => h("tr", {},
        labeledCell("Finding", {}, h("strong", {}, row.title), h("div", { class: "note" }, row.detail)),
        labeledCell("Expected", { class: "mono" }, row.expected || "—"),
        labeledCell("Observed", {}, pill(row.observed || "not observed", row.severity || "warn")),
        labeledCell("Actions", { class: "cell-actions" }, h("div", { class: "flex wrap" },
          row.model ? h("button", { class: "btn sm ghost", type: "button", title: `Inspect ${row.model.name}`, "aria-label": `Inspect VPN review item ${row.model.name}`, dataset: { netvpnAction: "inspect-vpn-review" }, onclick: () => openVpnTunnelDrawer(row.model, root) }, h("span", { html: icon("vpn", 15) }), "Inspect") : null,
          row.target ? h("button", { class: "btn sm ghost", type: "button", title: `Explain ${row.target.name}`, "aria-label": `Explain VPN review item ${row.target.name}`, dataset: { netvpnAction: "explain-vpn-review" }, onclick: () => { location.hash = vpnTroubleshootHash(row.target, "explain"); } }, h("span", { html: icon("search", 15) }), "Explain") : null,
          row.target ? h("button", { class: "btn sm ghost", type: "button", title: `Open sessions for ${row.target.name}`, "aria-label": `Open sessions for VPN review item ${row.target.name}`, dataset: { netvpnAction: "sessions-vpn-review" }, onclick: () => { location.hash = vpnSessionsHash(row.target); } }, h("span", { html: icon("traffic", 15) }), "Sessions") : null))))));
}

function openRuntimeReviewDrawer(root, opts = {}) {
  const engine = cleanRouteToken(opts.engine || routeState.engine || "");
  if (opts.sync !== false) setNetvpnRouteState({ ...NETVPN_ROUTE_DEFAULTS, drawer: "runtime-review", engine });
  const rows = vpnRuntimeReviewRows(session.draft || {}, runtimeStatus);
  const engineRows = runtimeReviewEngineRows(runtimeStatus, engine);
  openDrawer({
    title: "Routing & VPN runtime review",
    subtitle: engine ? `Route-backed review for ${engine}` : "Route-backed review of FRR, IPsec, and WireGuard posture.",
    width: "820px",
    onClose: clearNetvpnDrawerState,
    body: h("div", { class: "stack", dataset: { netvpnRuntimeReview: "true", netvpnRuntimeEngine: engine } },
      opts.routeBacked ? h("div", { class: "callout info" },
        h("strong", {}, "Opened from route state"),
        h("div", { class: "note" }, "Dashboard and copied handoffs can restore this runtime review without mutating candidate policy or claiming field evidence.")) : null,
      h("div", { class: "note" }, "This review compares candidate Routing/VPN intent with current runtime status. It is an operator drill-through surface; protected-subnet traffic, XFRM state, route install proof, and external peer evidence remain field-evidence work."),
      h("div", { class: "grid cols-3" },
        metricBlock("FRR", runtimeStatus.routing?.frr?.state || "not observed", runtimeStateClass(runtimeStatus.routing?.frr?.state)),
        metricBlock("IPsec", runtimeStatus.vpn?.ipsec?.state || "not observed", runtimeStateClass(runtimeStatus.vpn?.ipsec?.state)),
        metricBlock("WireGuard", runtimeStatus.vpn?.wireguard?.state || "not observed", runtimeStateClass(runtimeStatus.vpn?.wireguard?.state))),
      engineRows.length ? h("div", { class: "table-wrap flat" },
        responsiveTable(["Runtime source", "State", "Detail"], engineRows.map((row) => h("tr", { dataset: { netvpnRuntimeSource: row.key } },
          labeledCell("Runtime source", {}, h("strong", {}, row.label)),
          labeledCell("State", {}, pill(row.state || "unknown", runtimeStateClass(row.state))),
          labeledCell("Detail", { class: "data-wrap" }, row.detail || "No detail returned."))), { className: "netvpn-runtime-source-table" })) : null,
      rows.length ? h("div", { class: "table-wrap flat" },
        responsiveTable(["Finding", "Expected", "Observed"], rows.map((row) => h("tr", { dataset: { netvpnRuntimeFinding: row.type || "finding" } },
          labeledCell("Finding", {}, h("strong", {}, row.title), h("div", { class: "note" }, row.detail)),
          labeledCell("Expected", { class: "mono" }, row.expected || "—"),
          labeledCell("Observed", {}, pill(row.observed || "not observed", row.severity || "warn")))), { className: "netvpn-runtime-review-table" })) :
        emptyState("check", "No passive VPN drift", "Candidate VPN posture and runtime status do not expose a passive review finding.")),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close runtime review", "aria-label": "Close runtime review", dataset: { netvpnAction: "close-runtime-review" }, onclick: closeDrawer }, "Close"),
      h("button", { class: "btn", type: "button", title: "Open Routing and VPN API and CLI context", "aria-label": "Open Routing and VPN API and CLI context", dataset: { netvpnAction: "api-cli-runtime-review" }, onclick: () => openAutomationContext(currentRoute()) }, h("span", { html: icon("terminal", 16) }), "API / CLI"),
      h("a", { class: "btn primary", href: "#/troubleshoot?intent=runtime&run=1", title: "Open Troubleshoot runtime workflow", "aria-label": "Open Troubleshoot runtime workflow", onclick: closeDrawer }, h("span", { html: icon("arrowRight", 16) }), "Troubleshoot"),
    ],
  });
}

function runtimeReviewEngineRows(status = {}, selectedEngine = "") {
  const rows = [];
  const frr = status.routing?.frr || {};
  const ipsec = status.vpn?.ipsec || {};
  const wireguard = status.vpn?.wireguard || {};
  rows.push({ key: "frr", label: "FRR routing", state: frr.state || "not observed", detail: frr.detail || ospfRuntimeSummary(frr) });
  rows.push({ key: "ipsec", label: "IPsec", state: ipsec.state || "not observed", detail: ipsec.detail || `${ipsecRuntimeByTunnel(ipsec).size} configured tunnel observation(s)` });
  rows.push({ key: "wireguard", label: "WireGuard", state: wireguard.state || "not observed", detail: wireguard.detail || `${wireguardRuntimeByInterface(wireguard).size} interface observation(s)` });
  const selected = cleanRouteToken(selectedEngine).toLowerCase();
  if (!selected) return rows;
  const matches = rows.filter((row) => row.key.includes(selected) || row.label.toLowerCase().includes(selected));
  return matches.length ? matches : rows;
}

export function vpnRuntimeReviewRows(policy = {}, status = {}) {
  const rows = [];
  const models = vpnTunnelModels(policy, status);
  const staticRoutes = policy.staticRoutes || [];
  for (const model of models) {
    const state = String(model.runtime?.state || "").toLowerCase();
    const notObserved = !state || state === "not observed" || state === "not-configured" || state === "unknown";
    const firstTarget = model.targets?.[0] || null;
    if (notObserved) {
      rows.push({
        type: "missing-runtime",
        title: `${model.kindLabel} ${model.name} missing runtime observation`,
        detail: model.runtime?.detail || "No matching live status row was returned for this configured VPN entry.",
        expected: model.kind === "ipsec" ? "IKE/CHILD SA status" : "WireGuard peer handshake",
        observed: "not observed",
        severity: "warn",
        model,
        target: firstTarget,
      });
    }
    if (model.kind === "wireguard") {
      const handshakeAge = Number(model.runtime?.latestHandshakeAgeSeconds || model.runtime?.handshakeAgeSeconds || 0);
      const stale = handshakeAge >= 300 || state === "waiting";
      if (stale) {
        rows.push({
          type: "stale-handshake",
          title: `WireGuard ${model.name} stale handshake`,
          detail: model.runtime?.latestHandshake || model.runtime?.detail || "Peer is configured but no recent handshake was observed.",
          expected: "handshake under 5m",
          observed: model.runtime?.latestHandshake || model.runtime?.state || "waiting",
          severity: "warn",
          model,
          target: firstTarget,
        });
      }
    }
    for (const target of model.targets || []) {
      if (!target.remoteCidr) continue;
      if (hasCandidateRoutePosture(staticRoutes, target)) continue;
      rows.push({
        type: "missing-route-posture",
        title: `${model.kindLabel} ${model.name} missing route posture`,
        detail: `No candidate static route matched remote prefix ${target.remoteCidr}.`,
        expected: target.remoteCidr,
        observed: "no candidate route",
        severity: "warn",
        model,
        target,
      });
    }
  }
  return rows.slice(0, 24);
}

function hasCandidateRoutePosture(routes = [], target = {}) {
  return routes.some((route) => {
    if (route?.destination !== target.remoteCidr) return false;
    if (target.kind === "wireguard" && route.interface && route.interface !== target.ifaceName) return false;
    return true;
  });
}

function tunnelPathChecksCard(policy = {}) {
  const targets = vpnInvestigationTargets(policy);
  const header = h("h2", {}, "Tunnel path checks", h("span", { class: "spacer" }),
    h("span", { class: "muted" }, targets.length + " target" + (targets.length === 1 ? "" : "s")));
  if (!targets.length) return card(header,
    emptyState("search", "No tunnel paths", "Add IPsec or WireGuard peers with local and remote prefixes to generate path checks."));
  return card(header,
    h("div", { class: "note", style: { marginBottom: "10px" } },
      "Open candidate explanation, bounded packet capture, and live session filters for each tunnel path. These are route-backed collection handoffs, not claimed field evidence."),
    responsiveTable(["Tunnel", "Local", "Remote", "Tuple", { label: "Actions", attrs: { class: "actions-col" } }],
      targets.slice(0, 24).map((target) => h("tr", {},
        labeledCell("Tunnel", {}, h("strong", {}, target.name), h("div", { class: "note" }, target.kindLabel)),
        labeledCell("Local", { class: "mono" }, target.localCidr || target.srcIp || "-"),
        labeledCell("Remote", { class: "mono" }, target.remoteCidr || target.destIp || "-"),
        labeledCell("Tuple", { class: "mono" }, `${target.srcIp || "-"} -> ${target.destIp || "-"}`),
        labeledCell("Actions", { class: "cell-actions" }, h("div", { class: "flex wrap" },
          h("button", { class: "btn sm ghost", type: "button", title: `Inspect tunnel handoff for ${target.name}`, "aria-label": `Inspect tunnel handoff for ${target.name}`, dataset: { netvpnAction: "inspect-tunnel" }, onclick: () => openVpnTunnelDrawer(vpnTunnelModels(session.draft || {}, runtimeStatus).find((model) => sameTunnelModelTarget(model, target)), document.querySelector("#content > div")) }, h("span", { html: icon("vpn", 15) }), "Inspect"),
          h("button", { class: "btn sm ghost", type: "button", title: `Prove server-side path for ${target.name}`, "aria-label": `Prove server-side path for ${target.name}`, dataset: { netvpnAction: "prove-tunnel-path" }, onclick: () => openNetworkPathProofDrawer(target) }, h("span", { html: icon("check", 15) }), "Prove"),
          h("button", { class: "btn sm ghost", type: "button", title: `Explain candidate path for ${target.name}`, "aria-label": `Explain candidate path for ${target.name}`, dataset: { netvpnAction: "explain-tunnel" }, onclick: () => { location.hash = vpnTroubleshootHash(target, "explain"); } }, h("span", { html: icon("search", 15) }), "Explain"),
          h("button", { class: "btn sm ghost", type: "button", title: `Start packet capture workflow for ${target.name}`, "aria-label": `Start packet capture workflow for ${target.name}`, dataset: { netvpnAction: "capture-tunnel" }, onclick: () => { location.hash = vpnTroubleshootHash(target, "capture"); } }, h("span", { html: icon("download", 15) }), "Capture"),
          h("button", { class: "btn sm ghost", type: "button", title: `Open live sessions for ${target.name}`, "aria-label": `Open live sessions for ${target.name}`, dataset: { netvpnAction: "sessions-tunnel" }, onclick: () => { location.hash = vpnSessionsHash(target); } }, h("span", { html: icon("traffic", 15) }), "Sessions")))))));
}

function sameTunnelModelTarget(model = {}, target = {}) {
  if (!model || model.kind !== target.kind) return false;
  if (model.kind === "ipsec") return model.name === (target.tunnelName || target.name);
  return model.interfaceName === target.ifaceName && model.peerName === target.peerName;
}

export function vpnInvestigationTargets(policy = {}) {
  const targets = [];
  for (const tunnel of policy.vpn?.ipsecTunnels || []) {
    const locals = tunnel.localSubnets || [];
    const remotes = tunnel.remoteSubnets || [];
    for (const localCidr of locals.slice(0, 2)) {
      for (const remoteCidr of remotes.slice(0, 4)) {
        targets.push({
          kind: "ipsec",
          kindLabel: "IPsec",
          name: tunnel.name || "ipsec tunnel",
          tunnelName: tunnel.name || "",
          localCidr,
          remoteCidr,
          srcIp: representativeIp(localCidr),
          destIp: representativeIp(remoteCidr),
          protocol: "PROTOCOL_ANY",
        });
      }
    }
  }
  for (const iface of policy.vpn?.wireguardInterfaces || []) {
    const srcIp = representativeIp(iface.address || "");
    for (const peer of iface.peers || []) {
      for (const allowed of (peer.allowedIps || []).slice(0, 4)) {
        targets.push({
          kind: "wireguard",
          kindLabel: "WireGuard",
          name: `${iface.name || "wg"}:${peer.name || "peer"}`,
          ifaceName: iface.name || "",
          peerName: peer.name || "",
          peerPublicKey: peer.publicKey || "",
          localCidr: iface.address || "",
          remoteCidr: allowed,
          srcIp,
          destIp: representativeIp(allowed),
          protocol: "PROTOCOL_ANY",
        });
      }
    }
  }
  return targets.filter((target) => target.srcIp && target.destIp).slice(0, 32);
}

export function vpnTunnelModels(policy = {}, status = {}) {
  const targets = vpnInvestigationTargets(policy);
  const wgRuntime = wireguardRuntimeByInterface(status.vpn?.wireguard || {});
  const ipsecRuntime = ipsecRuntimeByTunnel(status.vpn?.ipsec || {});
  const models = [];
  for (const [index, tunnel] of (policy.vpn?.ipsecTunnels || []).entries()) {
    const name = tunnel.name || `ipsec-${index + 1}`;
    const live = ipsecRuntime.get(name);
    const modelTargets = targets.filter((target) => target.kind === "ipsec" && target.tunnelName === tunnel.name);
    models.push({
      kind: "ipsec",
      kindLabel: "IPsec",
      id: `ipsec:${name}`,
      name,
      index,
      routeState: netvpnTunnelRouteState({ kind: "ipsec", name, targets: modelTargets }),
      localEndpoint: tunnel.localAddress || "%any",
      remoteEndpoint: tunnel.remoteAddress || "",
      localPrefixes: tunnel.localSubnets || [],
      remotePrefixes: tunnel.remoteSubnets || [],
      mode: tunnel.initiate ? "initiator" : "responder",
      secretState: tunnel.pskFile ? "PSK file configured (path redacted)" : "PSK file not configured",
      runtime: {
        state: runtimeString(live, "state") || runtimeString(status.vpn?.ipsec || {}, "state") || "not observed",
        cls: runtimeStateClass(runtimeString(live, "state") || runtimeString(status.vpn?.ipsec || {}, "state")),
        detail: runtimeString(live, "detail") || runtimeString(status.vpn?.ipsec || {}, "detail") || "No live IPsec SA evidence matched this configured tunnel.",
        ikeState: runtimeString(live, "ikeState", "ike_state"),
        childSaCount: runtimeNumber(live, "childSaCount", "child_sa_count"),
        installedChildSaCount: runtimeNumber(live, "installedChildSaCount", "installed_child_sa_count"),
      },
      ikeProposal: tunnel.ikeProposal || "",
      espProposal: tunnel.espProposal || "",
      targets: modelTargets,
    });
  }
  for (const [ifaceIndex, iface] of (policy.vpn?.wireguardInterfaces || []).entries()) {
    const live = wgRuntime.get(iface.name || "");
    for (const [peerIndex, peer] of (iface.peers || []).entries()) {
      const peerName = peer.name || `peer-${peerIndex + 1}`;
      const peerRuntime = wireguardPeerRuntime(live, peer.publicKey);
      const modelTargets = targets.filter((target) => target.kind === "wireguard" && target.ifaceName === iface.name && target.peerName === peer.name);
      models.push({
        kind: "wireguard",
        kindLabel: "WireGuard",
        id: `wireguard:${iface.name || `wg-${ifaceIndex + 1}`}:${peerName}`,
        name: `${iface.name || `wg-${ifaceIndex + 1}`}:${peerName}`,
        interfaceName: iface.name || `wg-${ifaceIndex + 1}`,
        peerName,
        index: peerIndex,
        routeState: netvpnTunnelRouteState({ kind: "wireguard", iface: iface.name || `wg-${ifaceIndex + 1}`, peer: peerName, listenPort: iface.listenPort, targets: modelTargets }),
        localEndpoint: iface.address || "",
        remoteEndpoint: peer.endpoint || "",
        listenPort: iface.listenPort || 0,
        localPrefixes: [iface.address || ""].filter(Boolean),
        remotePrefixes: peer.allowedIps || [],
        mode: peer.persistentKeepalive ? `keepalive ${peer.persistentKeepalive}s` : "on demand",
        secretState: iface.privateKeyFile ? "private key file configured (path redacted)" : "private key file not configured",
        publicKeyState: peer.publicKey ? "public key configured" : "public key missing",
        runtime: {
          state: peerRuntime?.state || live?.state || "not observed",
          cls: runtimeStateClass(peerRuntime?.state || live?.state),
          detail: peerRuntime?.detail || live?.detail || "No live WireGuard peer evidence matched this configured peer.",
          endpoint: peerRuntime?.endpoint || "",
          latestHandshake: wireguardPeerRuntimeLabel(peerRuntime),
          latestHandshakeAgeSeconds: runtimeNumber(peerRuntime, "latestHandshakeAgeSeconds", "latest_handshake_age_seconds"),
          rxBytes: runtimeNumber(peerRuntime, "rxBytes", "rx_bytes"),
          txBytes: runtimeNumber(peerRuntime, "txBytes", "tx_bytes"),
        },
        targets: modelTargets,
      });
    }
  }
  return models;
}

export function vpnPeerTemplateBundle(model = {}) {
  const template = model.kind === "wireguard" ? wireguardPeerClientTemplate(model)
    : model.kind === "ipsec" ? ipsecPeerTemplate(model)
    : {
        title: "VPN peer template",
        text: "# Unsupported VPN tunnel kind\n",
        warnings: ["unsupported tunnel kind"],
      };
  return {
    kind: model.kind || "",
    name: model.name || model.id || "vpn-peer",
    title: template.title,
    filename: vpnPeerTemplateFilename(model),
    text: template.text,
    warnings: template.warnings || [],
  };
}

export function wireguardEnrollmentBundle(model = {}, opts = {}) {
  const warnings = [];
  const clientAddress = (model.remotePrefixes || [])[0] || "<client-tunnel-address>";
  const endpoint = wireguardEnrollmentEndpoint(opts.firewallPublicEndpoint, model.listenPort);
  const firewallPublicKey = safeTemplateValue(opts.firewallPublicKey || "<firewall-public-key>");
  if (!opts.firewallPublicEndpoint) warnings.push("firewall public endpoint is required before client enrollment");
  if (!opts.firewallPublicKey) warnings.push("firewall public key is required before client enrollment");
  if (!model.listenPort && !String(opts.firewallPublicEndpoint || "").includes(":")) {
    warnings.push("firewall listen port is not configured; confirm the endpoint port out of band");
  }
  if (!(model.remotePrefixes || []).length) warnings.push("peer allowed IPs are empty; add the client tunnel address before enrollment");
  const keepalive = wireguardKeepaliveSeconds(model);
  const lines = [
    "# Phragma WireGuard enrollment bundle",
    "# QR-ready client configuration; render this text with a trusted QR tool if needed.",
    `# Interface: ${safeTemplateValue(model.interfaceName || "wg")}`,
    `# Peer: ${safeTemplateValue(model.peerName || model.name || "peer")}`,
    "# Client private key is intentionally placeholder-only; generate it on the client or approved secret system.",
    "",
    "[Interface]",
    "PrivateKey = <client-private-key>",
    `Address = ${safeTemplateValue(clientAddress)}`,
    "",
    "[Peer]",
    `PublicKey = ${firewallPublicKey}`,
    `Endpoint = ${safeTemplateValue(endpoint)}`,
    `AllowedIPs = ${templateList(model.localPrefixes, "<firewall-protected-prefixes>")}`,
  ];
  if (keepalive) lines.push(`PersistentKeepalive = ${keepalive}`);
  lines.push(
    "",
    "# Firewall-side peer AllowedIPs configured in Phragma:",
    `# ${templateList(model.remotePrefixes, "<client-routed-prefixes>")}`,
  );
  return {
    title: "WireGuard enrollment bundle",
    filename: vpnPeerTemplateFilename({
      ...model,
      peerName: `${model.peerName || model.name || "peer"}-enrollment`,
    }, "conf"),
    text: lines.join("\n") + "\n",
    warnings,
  };
}

export function wireguardEnrollmentQrFilename(bundle = {}) {
  const base = String(bundle.filename || "wireguard-enrollment.conf").replace(/\.[^.]+$/, "");
  return `${safeTemplateSlug(base) || "wireguard-enrollment"}-qr.svg`;
}

export function wireguardEnrollmentQrSvg(bundle = {}, opts = {}) {
  return qrCodeSvg(bundle.text || "", {
    title: "WireGuard enrollment QR code",
    alt: "QR code containing the WireGuard enrollment configuration.",
    ...opts,
  });
}

export function wireguardPeerClientTemplate(model = {}) {
  const warnings = [];
  const clientAddress = (model.remotePrefixes || [])[0] || "<client-tunnel-address>";
  const endpoint = `<firewall-public-endpoint>${model.listenPort ? ":" + model.listenPort : ":51820"}`;
  if (!model.listenPort) warnings.push("firewall listen port is not configured; confirm the endpoint port out of band");
  warnings.push("firewall public endpoint and public key are not modeled; replace placeholders before use");
  if (!(model.remotePrefixes || []).length) warnings.push("peer allowed IPs are empty; add the client tunnel address before rollout");
  const keepalive = wireguardKeepaliveSeconds(model);
  const lines = [
    "# Phragma WireGuard peer/client template",
    `# Interface: ${safeTemplateValue(model.interfaceName || "wg")}`,
    `# Peer: ${safeTemplateValue(model.peerName || model.name || "peer")}`,
    model.remoteEndpoint ? `# Firewall-side configured peer endpoint: ${safeTemplateValue(model.remoteEndpoint)}` : "# Firewall-side configured peer endpoint: not set",
    "# Secret material is intentionally placeholder-only.",
    "",
    "[Interface]",
    "PrivateKey = <client-private-key>",
    `Address = ${safeTemplateValue(clientAddress)}`,
    "",
    "[Peer]",
    "PublicKey = <firewall-public-key>",
    `Endpoint = ${safeTemplateValue(endpoint)}`,
    `AllowedIPs = ${templateList(model.localPrefixes, "<firewall-protected-prefixes>")}`,
  ];
  if (keepalive) lines.push(`PersistentKeepalive = ${keepalive}`);
  lines.push(
    "",
    "# Firewall-side peer AllowedIPs configured in Phragma:",
    `# ${templateList(model.remotePrefixes, "<client-routed-prefixes>")}`,
  );
  return {
    title: "WireGuard peer template",
    text: lines.join("\n") + "\n",
    warnings,
  };
}

export function ipsecPeerTemplate(model = {}) {
  const warnings = [];
  if (!model.remoteEndpoint) warnings.push("remote endpoint is not configured");
  if (!(model.localPrefixes || []).length) warnings.push("local traffic selectors are empty");
  if (!(model.remotePrefixes || []).length) warnings.push("remote traffic selectors are empty");
  const startAction = model.mode === "initiator" ? "start" : "trap";
  const lines = [
    "# Phragma IPsec peer worksheet",
    `# Tunnel: ${safeTemplateValue(model.name || "ipsec-tunnel")}`,
    "# PSK material is intentionally placeholder-only and must be exchanged out of band.",
    "",
    "connections {",
    `  ${safeTemplateKey(model.name || "site-peer")} {`,
    `    local_addrs = ${safeTemplateValue(model.localEndpoint || "%any")}`,
    `    remote_addrs = ${safeTemplateValue(model.remoteEndpoint || "<peer-public-ip>")}`,
    model.ikeProposal ? `    proposals = ${safeTemplateValue(model.ikeProposal)}` : "    proposals = <ike-proposal>",
    "    local {",
    "      auth = psk",
    "      id = <local-id>",
    "    }",
    "    remote {",
    "      auth = psk",
    "      id = <remote-id>",
    "    }",
    "    children {",
    "      net {",
    `        local_ts = ${templateList(model.localPrefixes, "<local-cidr>")}`,
    `        remote_ts = ${templateList(model.remotePrefixes, "<remote-cidr>")}`,
    model.espProposal ? `        esp_proposals = ${safeTemplateValue(model.espProposal)}` : "        esp_proposals = <esp-proposal>",
    `        start_action = ${startAction}`,
    "      }",
    "    }",
    "  }",
    "}",
    "",
    "secrets {",
    `  ike-${safeTemplateKey(model.name || "site-peer")} {`,
    "    secret = <shared-secret-out-of-band>",
    "  }",
    "}",
  ];
  return {
    title: "IPsec peer template",
    text: lines.join("\n") + "\n",
    warnings,
  };
}

export function vpnPeerTemplateFilename(model = {}, ext = "txt") {
  const parts = [model.kind || "vpn"];
  if (model.interfaceName || model.peerName) parts.push(model.interfaceName || "", model.peerName || "");
  else parts.push(model.name || model.id || "peer");
  const name = safeTemplateSlug(parts.filter(Boolean).join("-"));
  const suffix = safeTemplateSlug(ext || "txt") || "txt";
  return `${name || "vpn-peer-template"}.${suffix}`;
}

export function selectedVpnTunnelModel(policy = {}, status = {}, route = {}) {
  const normalized = normalizeNetvpnRoute(route);
  if (normalized.drawer !== "tunnel") return null;
  return vpnTunnelModels(policy, status).find((model) => {
    if (normalized.kind !== model.kind) return false;
    if (model.kind === "ipsec") return model.name === normalized.name;
    return model.interfaceName === normalized.iface && model.peerName === normalized.peer;
  }) || null;
}

function openVpnTunnelDrawer(model = null, root = null, opts = {}) {
  if (!model) {
    toast("Tunnel not found", "The selected VPN tunnel or peer is not present in the candidate policy.", "warn");
    return;
  }
  if (opts.sync !== false) setNetvpnDrawerState(model);
  const fieldChecklist = vpnFieldProofChecklist(model, session.draft?.staticRoutes || []);
  const packet = vpnTunnelHandoffPacket(model, {
    route: vpnTunnelHash(model, routePath),
    operatorNote: vpnFieldProofChecklistText(fieldChecklist),
  });
  const template = vpnPeerTemplateBundle(model);
  openDrawer({
    title: `${model.kindLabel} tunnel handoff`,
    subtitle: model.name || model.id,
    width: "700px",
    onClose: clearNetvpnDrawerState,
    body: h("div", { dataset: { netvpnTunnelDrawer: "true" } },
      h("div", { class: "alert-box info" },
        h("strong", {}, "Candidate tunnel context. "),
        "This is a browser-local review handoff; it does not claim protected-subnet field proof. Secret file paths and key material are not exported."),
      opts.routeBacked ? h("div", { class: "note", style: { marginBottom: "10px" } }, "Opened from route-backed tunnel state.") : null,
      h("div", { class: "preflight-summary" },
        metricBlock("Type", model.kindLabel),
        metricBlock("Runtime", model.runtime?.state || "not observed", model.runtime?.cls || "neutral"),
        metricBlock("Local paths", String((model.localPrefixes || []).length)),
        metricBlock("Remote paths", String((model.remotePrefixes || []).length))),
      h("dl", { class: "kv compact" },
        kv("Name", model.name || "—"),
        model.interfaceName ? kv("Interface", model.interfaceName) : null,
        model.peerName ? kv("Peer", model.peerName) : null,
        kv("Local endpoint", model.localEndpoint || "—"),
        kv("Remote endpoint", model.remoteEndpoint || "—"),
        model.listenPort ? kv("Listen port", "udp/" + model.listenPort) : null,
        kv("Mode", model.mode || "—"),
        kv("Secret material", model.secretState || "not exported"),
        model.publicKeyState ? kv("Public key", model.publicKeyState) : null,
        kv("Runtime detail", model.runtime?.detail || "not observed"),
        model.runtime?.ikeState ? kv("IKE state", model.runtime.ikeState) : null,
        model.runtime?.childSaCount || model.runtime?.installedChildSaCount ? kv("CHILD SAs", `${model.runtime.installedChildSaCount || 0}/${model.runtime.childSaCount || 0} installed`) : null,
        model.runtime?.latestHandshake ? kv("Latest handshake", model.runtime.latestHandshake) : null,
        model.runtime?.rxBytes || model.runtime?.txBytes ? kv("Transfer", `${model.runtime.rxBytes || 0} rx / ${model.runtime.txBytes || 0} tx bytes`) : null),
      prefixStrip("Local prefixes", model.localPrefixes),
      prefixStrip("Remote prefixes", model.remotePrefixes),
      vpnFieldProofChecklistPanel(fieldChecklist),
      tunnelPathActions(model),
      model.kind === "wireguard" ? wireguardEnrollmentPanel(model) : null,
      vpnPeerTemplatePanel(template),
      handoffActions(packet)),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close tunnel handoff", "aria-label": "Close tunnel handoff", dataset: { netvpnAction: "close-tunnel-handoff" }, onclick: closeDrawer }, "Close"),
      h("a", { class: "btn", href: "#/changes?tab=candidate", title: "Open candidate change review for this tunnel handoff", "aria-label": "Open candidate change review for this tunnel handoff", dataset: { netvpnAction: "open-candidate-review" }, onclick: closeDrawer }, h("span", { html: icon("changes", 16) }), "Candidate"),
      model.targets?.[0] ? h("a", { class: "btn primary", href: vpnTroubleshootHash(model.targets[0], "explain"), title: `Explain first path for ${model.name || "selected tunnel"}`, "aria-label": `Explain first path for ${model.name || "selected tunnel"}`, dataset: { netvpnAction: "explain-first-path" }, onclick: closeDrawer },
        h("span", { html: icon("search", 16) }), "Explain first path") : null,
    ],
  });
}

export function vpnFieldProofChecklist(model = {}, staticRoutes = []) {
  const targets = model.targets || [];
  const runtimeState = String(model.runtime?.state || "").toLowerCase();
  const runtimeObserved = Boolean(runtimeState && !["not observed", "not-configured", "unknown"].includes(runtimeState));
  const routeTargets = targets.filter((target) => target.remoteCidr);
  const matchedRoutes = routeTargets.filter((target) => hasCandidateRoutePosture(staticRoutes, target));
  const pathCount = targets.length;
  const runtimeLabel = model.kind === "ipsec" ? "strongSwan runtime" : model.kind === "wireguard" ? "WireGuard runtime" : "VPN runtime";
  const firstTarget = targets[0] || {};
  const routeDetail = routeTargets.length
    ? `${matchedRoutes.length}/${routeTargets.length} remote prefix route posture item${routeTargets.length === 1 ? "" : "s"} matched in the candidate.`
    : "No remote prefixes are available for route posture review.";
  const rows = [
    {
      key: "candidate-route",
      label: "Candidate route posture",
      state: routeTargets.length && matchedRoutes.length === routeTargets.length ? "ready" : "review-needed",
      detail: `${routeDetail} Confirm the committed kernel route or FRR route separately before field use.`,
    },
    {
      key: "route-table-vrf",
      label: "Route table and VRF",
      state: "operator-check",
      detail: `Confirm route table, preferred source, VRF/network namespace, and egress interface for ${firstTarget.destIp || firstTarget.remoteCidr || "the remote prefix"} before citing route proof.`,
    },
    {
      key: "frr-rib-fib",
      label: "FRR RIB/FIB",
      state: "operator-check",
      detail: "When BGP or OSPF can own the path, collect FRR route and adjacency output alongside the kernel route; FRR alone is not field proof.",
    },
    {
      key: "runtime-status",
      label: runtimeLabel,
      state: runtimeObserved ? "observed" : "not-observed",
      detail: runtimeObserved
        ? `${model.runtime?.state || "observed"} was reported by passive status. Treat it as runtime visibility, not protected-subnet proof.`
        : `No matching ${runtimeLabel} row is currently observed; collect supported-host status before claiming readiness.`,
    },
    {
      key: "xfrm-state",
      label: "XFRM policy/state",
      state: model.kind === "ipsec" ? "required" : "as-needed",
      detail: model.kind === "ipsec"
        ? "Collect XFRM policy/state and counters for the local and remote traffic selectors before treating IPsec reachability as proven."
        : "Collect XFRM output only when policy routing, IPsec coexistence, or kernel transform state is part of the selected path.",
    },
    model.kind === "ipsec" ? {
      key: "strongswan-runtime",
      label: "strongSwan IKE/CHILD SA",
      state: runtimeObserved ? "observed" : "required",
      detail: "Confirm IKE SA, CHILD SA, traffic selectors, install state, and packet counters; never export PSK material or secret file paths.",
    } : {
      key: "wireguard-runtime",
      label: "WireGuard peer state",
      state: runtimeObserved ? "observed" : "required",
      detail: "Confirm latest handshake, endpoint, allowed IPs, and transfer counters; never export private keys, peer secret paths, or raw key material.",
    },
    {
      key: "candidate-explain",
      label: "Candidate path explain",
      state: pathCount ? "handoff" : "blocked",
      detail: pathCount
        ? "Use the route-backed Explain action for representative source/destination tuples before commit or field validation."
        : "Add local and remote prefixes before a representative explain tuple can be generated.",
    },
    {
      key: "packet-capture",
      label: "Packet capture",
      state: pathCount ? "handoff" : "blocked",
      detail: pathCount
        ? "Use the route-backed Capture action to plan bounded packet capture; capture artifacts and custody remain separate evidence."
        : "Packet-capture handoff needs a representative path tuple.",
    },
    {
      key: "live-sessions",
      label: "Live sessions",
      state: pathCount ? "handoff" : "blocked",
      detail: pathCount
        ? "Use the route-backed Sessions action to inspect conntrack/session filters for the selected remote endpoint."
        : "Session handoff needs a representative remote endpoint.",
    },
    {
      key: "secret-custody",
      label: "Secret custody",
      state: "placeholder-only",
      detail: model.kind === "ipsec"
        ? "PSK material remains out of band; templates keep placeholders and the handoff redacts secret paths."
        : "Private keys remain out of band; enrollment keeps client private keys as placeholders and the handoff redacts key paths.",
    },
    {
      key: "command-export-boundary",
      label: "Command and export boundary",
      state: "redacted-plan",
      detail: "Copied and exported packets contain redacted planned commands and passive summaries only; raw command output, captures, local paths, tokens, and secrets stay out of the browser packet.",
    },
    {
      key: "remote-attestation",
      label: "Remote attestation boundary",
      state: "out-of-band",
      detail: "Remote peer identity, remote command output, remote packet counters, and cryptographic attestation must be collected and signed outside this UI.",
    },
  ];
  return rows;
}

export function vpnFieldProofChecklistText(checklist = []) {
  const rows = (checklist || []).map((item) => `- ${item.label}: ${item.state}; ${item.detail}`);
  return [
    "Routing/VPN field proof checklist is a collection handoff only; it does not claim field evidence.",
    "Collect route-table, VRF/interface, FRR, XFRM, WireGuard or strongSwan proof separately; remote attestation remains out of band.",
    ...rows,
  ].join("\n");
}

function wireguardEnrollmentPanel(model = {}) {
  const endpoint = inp("", model.listenPort ? `vpn.example.gov:${model.listenPort}` : "vpn.example.gov:51820");
  endpoint.dataset.netvpnEnrollmentField = "firewall-public-endpoint";
  const publicKey = h("input", { class: "input mono", placeholder: "base64 firewall public key", dataset: { netvpnEnrollmentField: "firewall-public-key" } });
  const preview = h("pre", { class: "mono", dataset: { netvpnEnrollmentPreview: "true" }, style: templatePreviewStyle() });
  const qrPreview = h("div", { class: "qr-preview", dataset: { netvpnEnrollmentQr: "true" } });
  const warningList = h("ul", { class: "trace-list", dataset: { netvpnEnrollmentWarnings: "true" } });
  const update = () => {
    const bundle = currentWireguardEnrollmentBundle(model, endpoint, publicKey);
    const capacity = qrCodeCapacity(bundle.text || "");
    preview.textContent = bundle.text || "";
    clear(warningList);
    clear(qrPreview);
    for (const warning of [...(bundle.warnings || []), ...(capacity.ok ? [] : [`QR payload is too large for browser-side delivery (${capacity.bytes}/${capacity.maxBytes} bytes).`])]) {
      warningList.appendChild(h("li", {}, warning));
    }
    if (capacity.ok) {
      qrPreview.innerHTML = wireguardEnrollmentQrSvg(bundle);
    } else {
      qrPreview.appendChild(emptyState("download", "QR unavailable", "Reduce the enrollment payload, then export the QR again."));
    }
  };
  endpoint.addEventListener("input", update);
  publicKey.addEventListener("input", update);
  update();
  return h("div", { class: "profile-strip", dataset: { netvpnEnrollmentPanel: "true" } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Enrollment bundle"),
      pill("QR-ready config", "info")),
    h("div", { class: "note" },
      "Enter the firewall public endpoint and firewall public key to produce a client-side WireGuard config. Client private key generation remains outside this UI."),
    h("div", { class: "form-grid two" },
      field("Firewall public endpoint", endpoint, "host:port or IP:port reachable by the client"),
      field("Firewall public key", publicKey, "public key only; never paste the firewall private key")),
    warningList,
    qrPreview,
    preview,
    h("div", { class: "flex wrap", style: { marginTop: "10px" } },
      h("button", { class: "btn", type: "button", title: "Copy WireGuard enrollment config", "aria-label": "Copy WireGuard enrollment config", dataset: { netvpnAction: "copy-wireguard-enrollment" }, onclick: () => copyWireguardEnrollment(currentWireguardEnrollmentBundle(model, endpoint, publicKey)) },
        h("span", { html: icon("copy", 16) }), "Copy enrollment"),
      h("button", { class: "btn", type: "button", title: "Export WireGuard enrollment config", "aria-label": "Export WireGuard enrollment config", dataset: { netvpnAction: "export-wireguard-enrollment" }, onclick: () => exportWireguardEnrollment(currentWireguardEnrollmentBundle(model, endpoint, publicKey)) },
        h("span", { html: icon("download", 16) }), "Export enrollment"),
      h("button", { class: "btn", type: "button", title: "Export WireGuard enrollment QR code", "aria-label": "Export WireGuard enrollment QR code", dataset: { netvpnAction: "export-wireguard-enrollment-qr" }, onclick: () => exportWireguardEnrollmentQr(currentWireguardEnrollmentBundle(model, endpoint, publicKey)) },
        h("span", { html: icon("download", 16) }), "Export QR")));
}

function templatePreviewStyle() {
  return {
    whiteSpace: "pre-wrap",
    overflowWrap: "anywhere",
    maxHeight: "260px",
    overflow: "auto",
    background: "var(--panel-2)",
    border: "1px solid var(--border)",
    borderRadius: "var(--radius)",
    padding: "12px",
  };
}

function currentWireguardEnrollmentBundle(model, endpoint, publicKey) {
  return wireguardEnrollmentBundle(model, {
    firewallPublicEndpoint: endpoint.value.trim(),
    firewallPublicKey: publicKey.value.trim(),
  });
}

function vpnPeerTemplatePanel(template = {}) {
  return h("div", { class: "profile-strip" },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, template.title || "Peer template"),
      template.warnings?.length ? pill(`${template.warnings.length} warning${template.warnings.length === 1 ? "" : "s"}`, "warn") : pill("ready", "ok")),
    h("div", { class: "note" },
      "Copy a peer-side worksheet with placeholders for secret material and values that must be exchanged out of band."),
    template.warnings?.length ? h("ul", { class: "trace-list" }, template.warnings.map((warning) => h("li", {}, warning))) : null,
    h("pre", { class: "mono", style: templatePreviewStyle() }, template.text || ""),
    h("div", { class: "flex wrap", style: { marginTop: "10px" } },
      h("button", { class: "btn", type: "button", title: "Copy VPN peer template", "aria-label": "Copy VPN peer template", dataset: { netvpnAction: "copy-vpn-peer-template" }, onclick: () => copyVpnPeerTemplate(template) }, h("span", { html: icon("copy", 16) }), "Copy template"),
      h("button", { class: "btn", type: "button", title: "Export VPN peer template", "aria-label": "Export VPN peer template", dataset: { netvpnAction: "export-vpn-peer-template" }, onclick: () => exportVpnPeerTemplate(template) }, h("span", { html: icon("download", 16) }), "Export template")));
}

function vpnFieldProofChecklistPanel(checklist = []) {
  return h("div", { class: "profile-strip", dataset: { netvpnFieldProofChecklist: "true" } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Field proof checklist"),
      pill("handoff only", "warn")),
    h("div", { class: "note" },
      "Use this checklist to collect route, FRR/VPN runtime, capture, and session proof. The drawer does not certify field readiness."),
    h("ul", { class: "trace-list" }, checklist.map((item) =>
      h("li", { dataset: { netvpnFieldProofItem: item.key || "" } },
        h("strong", {}, item.label),
        " ",
        pill(item.state || "review", item.state === "ready" || item.state === "observed" ? "ok" : item.state === "blocked" ? "bad" : "warn"),
        h("div", { class: "note" }, item.detail)))));
}

function metricBlock(label, value, cls = "") {
  return h("div", {},
    h("span", {}, label),
    cls ? h("strong", {}, pill(value || "—", cls, true)) : h("strong", {}, value || "—"));
}

function kv(label, value) {
  return [h("dt", {}, label), h("dd", { class: "mono" }, value || "—")];
}

function prefixStrip(label, prefixes = []) {
  return h("div", { class: "profile-strip" },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, label),
      h("span", {}, `${(prefixes || []).length} configured`)),
    prefixes?.length
      ? h("div", { class: "flex wrap" }, prefixes.map((prefix) => h("span", { class: "tag mono" }, prefix)))
      : h("div", { class: "note" }, "No prefixes configured."));
}

function tunnelPathActions(model = {}) {
  const targets = model.targets || [];
  if (!targets.length) {
    return h("div", { class: "profile-strip" },
      h("div", { class: "profile-strip-head" }, h("strong", {}, "Path checks"), pill("none", "warn")),
      h("div", { class: "note" }, "Add local and remote prefixes to generate Troubleshoot and session pivots."));
  }
  return h("div", { class: "profile-strip" },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Path checks"),
      h("span", {}, `${targets.length} representative path${targets.length === 1 ? "" : "s"}`)),
    h("div", { class: "note" }, "Each action opens a candidate-policy explanation, bounded packet-capture workflow, or live conntrack/session filter."),
    h("div", { class: "object-ref-list netvpn-path-list" }, targets.slice(0, 8).map((target) =>
      h("div", { class: "object-ref-row" },
        h("div", {},
          h("strong", {}, `${target.localCidr || target.srcIp} -> ${target.remoteCidr || target.destIp}`),
          h("span", { class: "mono" }, `${target.srcIp || "-"} -> ${target.destIp || "-"}`)),
        h("div", { class: "flex wrap netvpn-path-actions", style: { justifyContent: "flex-end" } },
          h("button", { class: "btn sm ghost", type: "button", title: "Prove server-side path", "aria-label": `Prove server-side path for ${target.name}`, dataset: { netvpnAction: "prove-tunnel-path" }, onclick: () => openNetworkPathProofDrawer(target) },
            h("span", { html: icon("check", 14) }), "Prove"),
          h("a", { class: "btn sm ghost", href: vpnTroubleshootHash(target, "explain"), title: `Explain tunnel path for ${target.name}`, "aria-label": `Explain tunnel path for ${target.name}`, dataset: { netvpnPathAction: "explain" }, onclick: closeDrawer },
            h("span", { html: icon("search", 14) }), "Explain"),
          h("a", { class: "btn sm ghost", href: vpnTroubleshootHash(target, "capture"), title: `Plan packet capture for tunnel path ${target.name}`, "aria-label": `Plan packet capture for tunnel path ${target.name}`, dataset: { netvpnPathAction: "capture" }, onclick: closeDrawer },
            h("span", { html: icon("download", 14) }), "Capture"),
          h("a", { class: "btn sm ghost", href: vpnSessionsHash(target), title: `Open sessions for tunnel path ${target.name}`, "aria-label": `Open sessions for tunnel path ${target.name}`, dataset: { netvpnPathAction: "sessions" }, onclick: closeDrawer },
            h("span", { html: icon("traffic", 14) }), "Sessions"))))));
}

export function networkPathProofRequest(target = {}) {
  const body = {
    srcIp: target.srcIp || "",
    destIp: target.destIp || "",
    protocol: target.protocol || "PROTOCOL_ANY",
  };
  if (target.destPort) body.destPort = Number(target.destPort) || 0;
  if (target.kind === "wireguard" && target.ifaceName) body.sourceInterface = target.ifaceName;
  if (target.kind === "wireguard") {
    body.tunnel = {
      kind: "wireguard",
      interface: target.ifaceName || "",
      peer: target.peerName || "",
      peerPublicKey: target.peerPublicKey || "",
    };
  } else if (target.kind === "ipsec") {
    body.tunnel = {
      kind: "ipsec",
      name: target.tunnelName || target.name || "",
    };
  }
  return body;
}

async function openNetworkPathProofDrawer(target = {}) {
  openDrawer({
    title: "Network path proof",
    subtitle: target.name || "Representative tunnel path",
    width: "760px",
    body: h("div", { class: "stack", dataset: { netvpnPathProof: "loading" } },
      h("div", { class: "loading" }, "Sampling server-side route and VPN runtime proof...")),
    footer: [h("button", { class: "btn ghost", type: "button", title: "Close path proof", "aria-label": "Close path proof", dataset: { netvpnAction: "close-path-proof" }, onclick: closeDrawer }, "Close")],
  });
  try {
    const proof = await api.networkPathProof(networkPathProofRequest(target));
    renderNetworkPathProofDrawer(target, proof);
  } catch (e) {
    renderNetworkPathProofError(target, e);
  }
}

function renderNetworkPathProofDrawer(target = {}, proof = {}) {
  const route = proof.route || {};
  const vpn = proof.vpn || {};
  const activePlan = networkPathActiveProofPlan(target, proof);
  const activePacket = networkPathActiveProofPacket(target, proof, activePlan);
  openDrawer({
    title: "Network path proof",
    subtitle: target.name || "Representative tunnel path",
    width: "820px",
    body: h("div", { class: "stack", dataset: { netvpnPathProof: proof.state || "unknown" } },
      h("div", { class: "alert-box " + proofBoxClass(proof.state) },
        h("strong", {}, proof.state || "unknown"),
        h("div", { class: "note" }, proof.detail || "Server-side proof returned without detail.")),
      h("div", { class: "grid cols-3" },
        metricBlock("Route", route.state || "unknown", runtimeStateClass(route.state)),
        metricBlock("VPN", vpn.state || "not requested", runtimeStateClass(vpn.state)),
        metricBlock("Policy", proof.runningPolicyVersion ? `v${proof.runningPolicyVersion}` : "unknown")),
      h("div", { class: "table-wrap flat" },
        responsiveTable(["Evidence", "Value"], [
          proofRow("Tuple", `${target.srcIp || "-"} -> ${target.destIp || "-"}`),
          proofRow("Route device", route.dev || "-"),
          proofRow("Route gateway", route.gateway || "-"),
          proofRow("Preferred source", route.preferredSource || route.preferred_source || "-"),
          proofRow("Route table", route.table || "-"),
          proofRow("Route protocol", route.protocol || "-"),
          proofRow("VRF/interface identity", pathProofInterfaceIdentity(route, proof.evidence || [])),
          proofRow("FRR route proof", pathProofFrrEvidence(route, proof.evidence || [])),
          proofRow("Masquerade egress", pathProofMasqueradeEvidence(route, proof.evidence || [])),
          proofRow("Route detail", route.detail || "-"),
          proofRow("VPN kind", vpn.kind || target.kind || "-"),
          proofRow("Matched tunnel", vpn.matchedTunnel || vpn.matched_tunnel || vpn.interface || "-"),
          proofRow("VPN correlation", vpn.correlation || "-"),
          proofRow("VPN detail", vpn.detail || "-"),
          proofRow("Mismatches", pathProofMismatchText(proof.mismatches || []) || "none"),
          proofRow("Limitations", pathProofListText(proof.limitations || []) || "none"),
          proofRow("Evidence", pathProofListText(proof.evidence || []) || "-"),
          proofRow("Warnings", (proof.warnings || []).join("; ") || "none"),
        ])),
      h("div", { class: "note" }, "This proof is passive server-side evidence. It does not send active probes, capture packets, attest the remote peer, or create signed custody."),
      networkPathActiveProofPlanPanel(activePlan)),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Close path proof", "aria-label": "Close path proof", dataset: { netvpnAction: "close-path-proof" }, onclick: closeDrawer }, "Close"),
      h("button", { class: "btn ghost", type: "button", title: "Copy network path proof API handoff", "aria-label": "Copy network path proof API handoff", dataset: { netvpnPathProofAction: "copy-api" }, onclick: () => copyNetworkPathProofText("API handoff copied", networkPathProofAPIHandoff(target, proof)) }, h("span", { html: icon("copy", 16) }), "Copy API"),
      h("button", { class: "btn ghost", type: "button", title: "Copy network path proof CLI handoff", "aria-label": "Copy network path proof CLI handoff", dataset: { netvpnPathProofAction: "copy-cli" }, onclick: () => copyNetworkPathProofText("CLI handoff copied", networkPathProofCLIHandoff(target, proof)) }, h("span", { html: icon("copy", 16) }), "Copy CLI"),
      h("button", { class: "btn", type: "button", title: "Copy active proof plan", "aria-label": "Copy active proof plan", dataset: { netvpnPathProofAction: "copy-active-plan" }, onclick: () => copyNetworkPathProofText("Active plan copied", networkPathActiveProofPlanText(activePlan)) }, h("span", { html: icon("copy", 16) }), "Copy plan"),
      h("button", { class: "btn", type: "button", title: "Export active proof plan JSON", "aria-label": "Export active proof plan JSON", dataset: { netvpnPathProofAction: "export-active-plan" }, onclick: () => exportNetworkPathActiveProofPacket(activePacket) }, h("span", { html: icon("download", 16) }), "Export plan"),
      h("button", { class: "btn", type: "button", title: "Pin active proof plan to investigation case", "aria-label": "Pin active proof plan to investigation case", dataset: { netvpnPathProofAction: "pin-active-plan" }, onclick: () => pinNetworkPathActiveProofPacket(activePacket) }, h("span", { html: icon("inbox", 16) }), "Pin plan"),
      h("a", { class: "btn", href: vpnTroubleshootHash(target, "explain"), title: `Explain network path for ${target.name || "selected target"}`, "aria-label": `Explain network path for ${target.name || "selected target"}`, dataset: { netvpnPathProofAction: "explain" }, onclick: closeDrawer }, h("span", { html: icon("search", 16) }), "Explain"),
      h("a", { class: "btn primary", href: vpnTroubleshootHash(target, "capture"), title: `Plan packet capture for ${target.name || "selected target"}`, "aria-label": `Plan packet capture for ${target.name || "selected target"}`, dataset: { netvpnPathProofAction: "capture" }, onclick: closeDrawer }, h("span", { html: icon("download", 16) }), "Capture"),
    ],
  });
}

function renderNetworkPathProofError(target = {}, err = {}) {
  openDrawer({
    title: "Network path proof",
    subtitle: target.name || "Representative tunnel path",
    width: "720px",
    body: h("div", { class: "alert-box bad", dataset: { netvpnPathProof: "error" } },
      h("strong", {}, "Path proof failed"),
      h("div", { class: "note" }, err.message || "The server-side path proof API could not complete.")),
    footer: [h("button", { class: "btn ghost", type: "button", title: "Close path proof", "aria-label": "Close path proof", dataset: { netvpnAction: "close-path-proof" }, onclick: closeDrawer }, "Close")],
  });
}

function proofRow(label, value) {
  return h("tr", {},
    labeledCell("Evidence", {}, h("strong", {}, label)),
    labeledCell("Value", { class: "data-wrap mono" }, value || "-"));
}

function pathProofListText(values = []) {
  return values.filter(Boolean).join("; ");
}

function pathProofMismatchText(mismatches = []) {
  return mismatches.map((m) => `[${m.severity || "info"}] ${m.subject || "proof"}: ${m.detail || "-"}`).join("; ");
}

function pathProofEvidenceValue(evidence = [], key = "") {
  const prefix = `${key}=`;
  const row = (evidence || []).find((item) => String(item || "").startsWith(prefix));
  return row ? String(row).slice(prefix.length) : "";
}

function pathProofInterfaceIdentity(route = {}, evidence = []) {
  const explicit = route.interfaceIdentity || route.interface_identity;
  if (explicit) return explicit;
  const parts = [];
  const dev = route.interfaceName || route.interface_name || route.dev || pathProofEvidenceValue(evidence, "route_interface_identity").replace(/^dev:/, "");
  const ifindex = route.interfaceIndex || route.interface_index || pathProofEvidenceValue(evidence, "route_interface_index");
  const master = route.interfaceMaster || route.interface_master || route.vrf || pathProofEvidenceValue(evidence, "route_interface_master");
  const kind = route.interfaceKind || route.interface_kind || pathProofEvidenceValue(evidence, "route_interface_kind");
  if (dev) parts.push(`dev ${dev}`);
  if (ifindex) parts.push(`ifindex ${ifindex}`);
  if (master) parts.push(`master ${master}`);
  if (kind) parts.push(`kind ${kind}`);
  return parts.join("; ") || "-";
}

function pathProofFrrEvidence(route = {}, evidence = []) {
  const frr = route.frr || {};
  const state = frr.state || pathProofEvidenceValue(evidence, "frr_route_proof");
  const detail = frr.detail || pathProofEvidenceValue(evidence, "frr_route_detail");
  const command = frr.command || pathProofEvidenceValue(evidence, "frr_route_command");
  return [state, detail, command].filter(Boolean).join("; ") || "-";
}

function pathProofMasqueradeEvidence(route = {}, evidence = []) {
  const masquerade = route.masquerade || {};
  const state = masquerade.state || pathProofEvidenceValue(evidence, "masquerade_egress_proof");
  const observed = masquerade.observedEgressSource || masquerade.observed_egress_source || route.preferredSource || route.preferred_source || pathProofEvidenceValue(evidence, "masquerade_egress_observed_source");
  const expected = masquerade.expectedEgressSource || masquerade.expected_egress_source || "";
  return [
    state ? `state ${state}` : "",
    observed ? `observed ${observed}` : "",
    expected ? `expected ${expected}` : "",
  ].filter(Boolean).join("; ") || "-";
}

export function networkPathActiveProofPlan(target = {}, proof = {}) {
  const req = networkPathProofRequest(target);
  const route = proof.route || {};
  const vpn = proof.vpn || {};
  const dev = safeCommandToken(route.dev || req.sourceInterface || target.ifaceName || "<egress-interface>");
  const src = safeCommandToken(req.srcIp || "<source-ip>");
  const dst = safeCommandToken(req.destIp || "<destination-ip>");
  const protocol = String(req.protocol || target.protocol || "PROTOCOL_ANY").toUpperCase();
  const port = Number(req.destPort || target.destPort || target.port || defaultProbePort(target));
  const tcpdumpFilter = `host ${src} and host ${dst}`;
  const captureName = `openngfw-path-${safeTemplateSlug(target.name || target.tunnelName || "proof") || "proof"}.pcap`;
  const probeCommands = [];
  if (protocol === "PROTOCOL_TCP") {
    probeCommands.push(`sudo timeout 8 hping3 -S -c 3 -a ${shellArg(src)} -p ${port || 443} ${shellArg(dst)}`);
  } else if (protocol === "PROTOCOL_UDP") {
    probeCommands.push(`sudo timeout 8 nping --udp -c 3 --source-ip ${shellArg(src)} -p ${port || 33434} ${shellArg(dst)}`);
  } else {
    probeCommands.push(`sudo timeout 8 ping -c 3 -W 2 -I ${shellArg(src)} ${shellArg(dst)}`);
  }
  probeCommands.push(`sudo timeout 5 ip route get ${shellArg(dst)} from ${shellArg(src)}${dev && dev !== "<egress-interface>" ? " oif " + shellArg(dev) : ""}`);
  const captureCommands = [
    `sudo timeout 20 tcpdump -ni ${shellArg(dev)} -c 50 -s 160 -w ${shellArg(captureName)} ${shellArg(tcpdumpFilter)}`,
    `sudo timeout 6 tcpdump -ni ${shellArg(dev)} -c 20 -s 160 ${shellArg(tcpdumpFilter)}`,
  ];
  const sessionCommands = [
    `sudo timeout 8 conntrack -L --orig-src ${shellArg(src)} --orig-dst ${shellArg(dst)} 2>/dev/null | head -50`,
    `sudo timeout 8 conntrack -L --reply-src ${shellArg(dst)} --reply-dst ${shellArg(src)} 2>/dev/null | head -50`,
  ];
  return {
    title: "Network path active-proof plan",
    statement: "Recommended operator-run commands only; no active probe, capture, or session lookup was sent by this UI.",
    acknowledgementRequirements: networkPathActiveProofAcknowledgements(target),
    executionBounds: networkPathActiveProofBounds(),
    remoteAttestationBoundary: "Remote peer identity, remote-host command output, remote packet counters, and cryptographic attestation are outside this browser packet unless separately collected, signed, and attached by the operator.",
    exportBoundary: "Exported packets include planned commands, redacted passive proof, acknowledgements, and checklist metadata only; raw command output, packet captures, bearer tokens, local paths, key paths, PSKs, private keys, and remote-host artifacts are not embedded.",
    tuple: {
      srcIp: src,
      destIp: dst,
      protocol,
      destPort: port || "",
      tunnel: safeTemplateValue(target.name || target.tunnelName || target.ifaceName || "").slice(0, 120),
      kind: safeTemplateSlug(target.kind || ""),
    },
    passiveSummary: {
      state: safeTemplateValue(proof.state || "unknown").slice(0, 80),
      routeState: safeTemplateValue(route.state || "unknown").slice(0, 80),
      routeDevice: safeCommandToken(route.dev || ""),
      vpnState: safeTemplateValue(vpn.state || "not requested").slice(0, 80),
      matchedTunnel: safeTemplateValue(vpn.matchedTunnel || vpn.matched_tunnel || vpn.interface || "").slice(0, 120),
      limitations: boundedLines(proof.limitations || []),
    },
    commands: [
      {
        key: "bounded-probe",
        label: "Bounded active probe",
        detail: "Run from the firewall or approved probe host only; each command is count/timeout bounded.",
        commands: probeCommands,
      },
      {
        key: "bounded-capture",
        label: "Bounded packet capture",
        detail: "Capture headers only by default, with packet count and timeout caps; record custody outside this UI.",
        commands: captureCommands,
      },
      {
        key: "session-correlation",
        label: "Session correlation",
        detail: "Look for conntrack/session rows matching both directions of the planned tuple.",
        commands: sessionCommands,
      },
    ],
    checklist: networkPathActiveProofChecklist(target, proof),
    nextSteps: networkPathMismatchNextSteps(proof.mismatches || [], proof),
  };
}

function networkPathActiveProofChecklist(target = {}, proof = {}) {
  const route = proof.route || {};
  const destination = target.destIp || target.remoteCidr || "<destination>";
  const source = target.srcIp || "<source>";
  const device = route.dev || target.ifaceName || "<egress-interface>";
  const items = [
    {
      key: "kernel-route",
      label: "Kernel route",
      state: route.state === "ready" ? "ready" : "verify",
      detail: `Confirm the kernel route selects ${device} for ${destination} from ${source}, including table and preferred-source behavior.`,
      commands: [
        `sudo timeout 8 ip route get ${shellArg(destination)} from ${shellArg(source)}`,
        `sudo timeout 8 ip -s route show table ${shellArg(route.table || "main")}`,
      ],
    },
    {
      key: "vrf-interface",
      label: "VRF/interface boundary",
      state: "verify",
      detail: "Confirm the expected VRF, network namespace, and interface binding before treating route output as path proof.",
      commands: [
        `sudo timeout 8 ip -d link show ${shellArg(device)}`,
        "sudo timeout 8 ip vrf show",
        "sudo timeout 8 ip netns list",
      ],
    },
    {
      key: "frr",
      label: "FRR RIB/FIB",
      state: "verify",
      detail: `Confirm FRR route selection and adjacency health for ${destination}; FRR output is corroborating evidence, not a replacement for kernel route proof.`,
      commands: [
        `timeout 8 vtysh -c ${shellArg("show ip route " + destination)}`,
        `timeout 8 vtysh -c ${shellArg("show bgp summary")}`,
        `timeout 8 vtysh -c ${shellArg("show ip ospf neighbor")}`,
      ],
    },
    {
      key: "xfrm",
      label: "XFRM policy/state",
      state: target.kind === "ipsec" ? "required" : "as-needed",
      detail: "For IPsec or policy-routing paths, confirm kernel XFRM policy and state match the local and remote selectors, SPIs, and counters.",
      commands: [
        "sudo timeout 8 ip xfrm policy",
        "sudo timeout 8 ip -s xfrm state",
      ],
    },
  ];
  if (target.kind === "wireguard") {
    items.push({
      key: "wireguard",
      label: "WireGuard peer",
      state: "required",
      detail: `Confirm latest handshake, endpoint, and transfer counters for ${target.ifaceName || "<interface>"} / ${target.peerName || "<peer>"}.`,
      commands: [
        `sudo timeout 8 wg show ${shellArg(target.ifaceName || "<interface>")}`,
        `timeout 5 ip route get ${shellArg(target.destIp || "<destination>")} from ${shellArg(target.srcIp || "<source>")} oif ${shellArg(target.ifaceName || "<interface>")}`,
      ],
    });
  }
  if (target.kind === "ipsec") {
    items.push({
      key: "strongswan",
      label: "strongSwan IKE/CHILD SA",
      state: "required",
      detail: `Confirm IKE and CHILD SA state, traffic selectors, and packet counters for ${target.tunnelName || target.name || "<tunnel>"}; do not export PSK material.`,
      commands: [
        `sudo timeout 8 swanctl --list-sas --ike ${shellArg(target.tunnelName || target.name || "<tunnel>")}`,
        "sudo timeout 8 swanctl --list-pols",
        "sudo timeout 8 ip -s xfrm state",
      ],
    });
  }
  items.push({
    key: "remote-attestation",
    label: "Remote attestation boundary",
    state: "out-of-band",
    detail: "Remote peer identity, remote host logs, and cryptographic attestation must be collected and signed outside this UI before they can be cited as remote proof.",
    commands: [],
  }, {
    key: "handoff",
    label: "Handoff custody",
    state: "manual",
    detail: "Copy, export, or pin this plan with passive proof context; attach actual probe/capture artifacts only after they are collected through approved custody.",
    commands: [],
  });
  return items;
}

function networkPathActiveProofAcknowledgements(target = {}) {
  const kind = target.kind === "ipsec" ? "IPsec/strongSwan" : target.kind === "wireguard" ? "WireGuard" : "network";
  return [
    {
      key: "not-executed",
      required: true,
      text: "Acknowledge that this UI only generated a plan; it did not execute probes, captures, conntrack lookups, or remote commands.",
    },
    {
      key: "bounded-commands",
      required: true,
      text: "Acknowledge every operator-run command must keep the displayed timeout, packet-count, and snap-length bounds unless a separate approved test plan records the exception.",
    },
    {
      key: "secret-redaction",
      required: true,
      text: `${kind} key paths, PSKs, private keys, bearer tokens, local filesystem paths, and raw captures must not be embedded in this browser packet.`,
    },
    {
      key: "remote-attestation",
      required: true,
      text: "Acknowledge remote-peer evidence and attestation are out of scope for this packet until separately collected, signed, and attached.",
    },
  ];
}

function networkPathActiveProofBounds() {
  return {
    probeTimeoutSeconds: 8,
    probePacketCount: 3,
    routeLookupTimeoutSeconds: 5,
    captureTimeoutSeconds: 20,
    capturePacketCount: 50,
    captureSnapLengthBytes: 160,
    previewCaptureTimeoutSeconds: 6,
    previewCapturePacketCount: 20,
    sessionLookupTimeoutSeconds: 8,
    maxChecklistItems: 12,
    maxNextSteps: 8,
    maxPacketTextBytes: 24000,
    redaction: [
      "jwt",
      "bearer-token",
      "secret-assignment",
      "private-key-assignment",
      "managed-local-path",
      "psk-path",
    ],
  };
}

function networkPathMismatchNextSteps(mismatches = [], proof = {}) {
  const rows = boundedLines(mismatches.map((m) => `${m.subject || "proof"}: ${m.detail || ""}`));
  if (!rows.length) {
    return [
      "No passive mismatches were reported; run the bounded probe and capture only if active field proof is required.",
      "Compare active probe timestamps with capture and session output before calling the path proven.",
    ];
  }
  return rows.map((row) => {
    const text = row.toLowerCase();
    if (text.includes("route") || text.includes("dev") || text.includes("gateway")) return `${row}; verify static route, FRR route selection, gateway reachability, and reverse path before probing.`;
    if (text.includes("vpn") || text.includes("tunnel") || text.includes("xfrm") || text.includes("sa")) return `${row}; verify tunnel selector, XFRM/IPsec or WireGuard peer state, and endpoint reachability before probing.`;
    if (text.includes("policy") || text.includes("rule")) return `${row}; open candidate Explain and compare running/candidate rule posture before active testing.`;
    return `${row}; resolve or document the mismatch before treating active output as proof.`;
  }).slice(0, 8);
}

function networkPathActiveProofPlanPanel(plan = {}) {
  return h("div", { class: "profile-strip", dataset: { netvpnActiveProofPlan: "true" } },
    h("div", { class: "profile-strip-head" },
      h("strong", {}, "Active-proof plan"),
      pill("not executed", "warn")),
    h("div", { class: "note" }, plan.statement || "Recommended operator-run commands only; this UI did not send probes."),
    h("div", { class: "note" }, plan.remoteAttestationBoundary || ""),
    h("div", { class: "note" }, plan.exportBoundary || ""),
    h("div", { class: "profile-strip", dataset: { netvpnActiveProofAcknowledgements: "true" } },
      h("div", { class: "profile-strip-head" },
        h("strong", {}, "Required acknowledgements"),
        pill(`${(plan.acknowledgementRequirements || []).length} required`, "warn")),
      h("ul", { class: "trace-list" }, (plan.acknowledgementRequirements || []).map((item) =>
        h("li", {},
          h("strong", {}, item.key || "acknowledgement"),
          h("div", { class: "note" }, item.text || ""))))),
    h("div", { class: "grid cols-3" },
      metricBlock("Passive state", plan.passiveSummary?.state || "unknown", proofBoxClass(plan.passiveSummary?.state || "")),
      metricBlock("Route device", plan.passiveSummary?.routeDevice || "not selected"),
      metricBlock("VPN state", plan.passiveSummary?.vpnState || "not requested", runtimeStateClass(plan.passiveSummary?.vpnState || ""))),
    h("div", { class: "table-wrap flat", style: { marginTop: "10px" } },
      responsiveTable(["Step", "Plan"], (plan.commands || []).map((section) => h("tr", {},
        labeledCell("Step", {}, h("strong", {}, section.label || section.key), h("div", { class: "note" }, section.detail || "")),
        labeledCell("Plan", {}, h("pre", { class: "mono", style: templatePreviewStyle() }, (section.commands || []).join("\n") || "manual review")))))),
    h("div", { class: "grid cols-2" },
      h("div", {},
        h("h3", {}, "Follow-up checklist"),
        h("ul", { class: "trace-list" }, (plan.checklist || []).map((item) =>
          h("li", {},
            h("strong", {}, item.label || item.key),
            " ",
            pill(item.state || "review", item.state === "ready" ? "ok" : item.state === "required" || item.state === "verify" ? "warn" : "neutral"),
            h("div", { class: "note" }, item.detail || ""),
            item.commands?.length ? h("pre", { class: "mono", style: templatePreviewStyle() }, item.commands.join("\n")) : null)))),
      h("div", {},
        h("h3", {}, "Mismatch-driven next steps"),
        h("ul", { class: "trace-list" }, (plan.nextSteps || []).map((step) => h("li", {}, step))))));
}

export function networkPathActiveProofPlanText(plan = {}) {
  const lines = [
    plan.title || "Network path active-proof plan",
    plan.statement || "Recommended operator-run commands only; no probes were sent by this UI.",
    "",
    "[required acknowledgements]",
    ...((plan.acknowledgementRequirements || []).map((item) => `- ${item.required ? "required" : "optional"} ${item.key}: ${item.text}`)),
    "",
    "[execution bounds]",
    ...Object.entries(plan.executionBounds || {}).map(([key, value]) => `${key}=${Array.isArray(value) ? value.join(",") : value}`),
    "",
    "[remote attestation boundary]",
    plan.remoteAttestationBoundary || "Remote attestation is outside this packet.",
    "",
    "[export packet boundary]",
    plan.exportBoundary || "Exported packets contain planned commands and redacted passive proof only.",
    "",
    "[tuple]",
    `source=${plan.tuple?.srcIp || ""}`,
    `destination=${plan.tuple?.destIp || ""}`,
    `protocol=${plan.tuple?.protocol || ""}`,
    plan.tuple?.destPort ? `destination_port=${plan.tuple.destPort}` : "",
    plan.tuple?.kind ? `tunnel_kind=${plan.tuple.kind}` : "",
    plan.tuple?.tunnel ? `tunnel=${plan.tuple.tunnel}` : "",
    "",
    "[passive proof]",
    `state=${plan.passiveSummary?.state || "unknown"}`,
    `route=${plan.passiveSummary?.routeState || "unknown"} ${plan.passiveSummary?.routeDevice || ""}`.trim(),
    `vpn=${plan.passiveSummary?.vpnState || "not requested"} ${plan.passiveSummary?.matchedTunnel || ""}`.trim(),
    ...(plan.passiveSummary?.limitations || []).map((item) => `limitation=${item}`),
    "",
    "[recommended commands]",
  ].filter((line) => line !== "");
  for (const section of plan.commands || []) {
    lines.push("", `${section.label || section.key}: ${section.detail || ""}`);
    lines.push(...(section.commands || []).map((cmd) => `$ ${cmd}`));
  }
  lines.push("", "[follow-up checklist]");
  for (const item of plan.checklist || []) {
    lines.push(`- ${item.label || item.key}: ${item.state || "review"}; ${item.detail || ""}`);
    for (const cmd of item.commands || []) lines.push(`  $ ${cmd}`);
  }
  lines.push("", "[mismatch-driven next steps]");
  lines.push(...((plan.nextSteps || []).map((step) => `- ${step}`)));
  return lines.join("\n").slice(0, 24000) + "\n";
}

export function networkPathActiveProofPacket(target = {}, proof = {}, plan = networkPathActiveProofPlan(target, proof)) {
  return buildInvestigationPacket({
    kind: "network-path-active-proof-plan",
    title: "Network path active-proof plan",
    subject: {
      id: `${target.kind || "path"}:${target.name || target.tunnelName || target.ifaceName || target.destIp || "target"}`,
      label: target.name || target.tunnelName || `${target.srcIp || "-"} -> ${target.destIp || "-"}`,
      tuple: plan.tuple || {},
    },
    summary: {
      state: plan.passiveSummary?.state || "unknown",
      routeState: plan.passiveSummary?.routeState || "unknown",
      routeDevice: plan.passiveSummary?.routeDevice || "",
      vpnState: plan.passiveSummary?.vpnState || "not requested",
      activeProofStatus: "planned-not-executed",
      exportBoundary: "redacted-plan-only",
      commandSections: (plan.commands || []).length,
      checklistItems: (plan.checklist || []).length,
      acknowledgementRequirements: (plan.acknowledgementRequirements || []).filter((item) => item.required).length,
      nextSteps: (plan.nextSteps || []).length,
    },
    evidence: [
      "passive network path proof result",
      "active proof plan generated from passive proof",
      "no active probe or capture was sent by the WebUI",
      "export packet contains planned commands and redacted passive proof only",
      "operator acknowledgement required before using active proof output",
      "remote attestation remains out of band",
      ...(plan.nextSteps || []).slice(0, 8),
    ],
    artifacts: {
      target: networkPathProofRequest(target),
      passiveProof: redactedPassiveNetworkPathProof(proof),
      activeProofPlan: plan,
      acknowledgementRequirements: plan.acknowledgementRequirements || [],
      executionBounds: plan.executionBounds || networkPathActiveProofBounds(),
      remoteAttestationBoundary: plan.remoteAttestationBoundary || "",
      exportBoundary: plan.exportBoundary || "",
    },
  }, {
    route: currentRoute(),
    operatorNote: networkPathActiveProofPlanText(plan),
  });
}

async function pinNetworkPathActiveProofPacket(packet) {
  try {
    const serverResult = await appendInvestigationPacketToActiveServerCase(packet, {
      appendEvidence: (id, evidence) => api.addInvestigationCaseEvidence(id, evidence),
    });
    const result = pinInvestigationPacket(packet);
    if (serverResult.appended) {
      toast("Plan pinned to active case", `Active-proof plan was appended to ${serverResult.activeCaseId} and refreshed locally.`, "ok");
      return;
    }
    toast(result.toastTitle, `${result.toastDetail} No active server case was selected.`, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Active-proof plan could not be pinned.", "bad");
  }
}

function exportNetworkPathActiveProofPacket(packet) {
  downloadText(investigationPacketFilename(packet), investigationPacketJson(packet), "application/json");
  toast("Plan exported", "Downloaded active-proof plan JSON without claiming probes were sent.", "ok");
}

function networkPathProofAPIHandoff(target = {}, proof = {}) {
  const handoff = proof.apiHandoff || proof.api_handoff;
  if (handoff) return safeHandoffText(handoff);
  return `POST /v1/system/network-path:prove\n${JSON.stringify(networkPathProofRequest(target), null, 2)}`;
}

function networkPathProofCLIHandoff(target = {}, proof = {}) {
  if (proof.cliHandoff || proof.cli_handoff) return safeHandoffText(proof.cliHandoff || proof.cli_handoff);
  const req = networkPathProofRequest(target);
  const parts = ["ngfwctl", "system", "network-path", "prove", "--src", shellArg(req.srcIp), "--dst", shellArg(req.destIp)];
  if (req.protocol) parts.push("--protocol", shellArg(req.protocol));
  if (req.destPort) parts.push("--dport", String(req.destPort));
  if (req.sourceInterface) parts.push("--source-interface", shellArg(req.sourceInterface));
  if (req.tunnel?.kind) parts.push("--tunnel-kind", shellArg(req.tunnel.kind));
  if (req.tunnel?.name) parts.push("--tunnel-name", shellArg(req.tunnel.name));
  if (req.tunnel?.interface) parts.push("--tunnel-interface", shellArg(req.tunnel.interface));
  if (req.tunnel?.peer) parts.push("--tunnel-peer", shellArg(req.tunnel.peer));
  if (req.tunnel?.peerPublicKey) parts.push("--tunnel-peer-public-key", shellArg(req.tunnel.peerPublicKey));
  return parts.join(" ");
}

function shellArg(value = "") {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function safeCommandToken(value = "") {
  return safeTemplateValue(value || "").replace(/[^\w.:/\-[\]<>]/g, "").slice(0, 120) || "";
}

function boundedLines(values = []) {
  return (values || []).map((value) => safeTemplateValue(typeof value === "string" ? value : JSON.stringify(value || {}))).filter(Boolean).slice(0, 12);
}

function safeHandoffText(value = "") {
  return String(value || "")
    .split(/\r?\n/)
    .map((line) => safeTemplateValue(line).slice(0, 320))
    .filter(Boolean)
    .slice(0, 16)
    .join("\n");
}

function redactedPassiveNetworkPathProof(proof = {}) {
  const route = proof.route || {};
  const vpn = proof.vpn || {};
  return {
    state: safeTemplateValue(proof.state || "unknown").slice(0, 80),
    route: {
      state: safeTemplateValue(route.state || "unknown").slice(0, 80),
      dev: safeCommandToken(route.dev || ""),
      table: safeTemplateValue(route.table || "").slice(0, 80),
      gateway: safeCommandToken(route.gateway || route.via || ""),
    },
    vpn: {
      state: safeTemplateValue(vpn.state || "not requested").slice(0, 80),
      correlation: safeTemplateValue(vpn.correlation || "").slice(0, 160),
      matchedTunnel: safeTemplateValue(vpn.matchedTunnel || vpn.matched_tunnel || vpn.interface || "").slice(0, 120),
    },
    mismatches: (proof.mismatches || []).slice(0, 8).map((mismatch) => ({
      severity: safeTemplateValue(mismatch.severity || "info").slice(0, 24),
      subject: safeTemplateValue(mismatch.subject || "proof").slice(0, 120),
      detail: safeTemplateValue(mismatch.detail || "").slice(0, 280),
    })),
    limitations: boundedLines(proof.limitations || []),
    disclosureBoundary: "Redacted passive summary only; raw command output, local paths, peer secrets, capture artifacts, and custody records are not embedded in this browser packet.",
  };
}

function defaultProbePort(target = {}) {
  if (target.kind === "wireguard") return target.listenPort || 51820;
  if (target.kind === "ipsec") return 4500;
  return 0;
}

async function copyNetworkPathProofText(title, text) {
  try {
    if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(text);
    toast(title, "Network path proof handoff copied.", "ok");
  } catch {
    toast("Copy unavailable", "Select and copy the proof handoff text from this drawer.", "warn");
  }
}

function proofBoxClass(state = "") {
  if (state === "ready") return "ok";
  if (state === "degraded") return "warn";
  if (state === "unavailable") return "bad";
  return "info";
}

function handoffActions(packet) {
  return h("div", { class: "flex wrap netvpn-handoff-actions", style: { marginTop: "16px" } },
    h("button", { class: "btn", type: "button", title: "Open VPN tunnel API and CLI context", "aria-label": "Open VPN tunnel API and CLI context", dataset: { netvpnAction: "api-cli" }, onclick: () => openAutomationContext(currentRoute()) }, h("span", { html: icon("terminal", 16) }), "API / CLI"),
    h("button", { class: "btn", type: "button", title: "Pin VPN tunnel handoff to investigation case", "aria-label": "Pin VPN tunnel handoff to investigation case", dataset: { netvpnAction: "pin-vpn-handoff" }, onclick: () => pinVpnHandoff(packet) }, h("span", { html: icon("inbox", 16) }), "Pin to case"),
    h("a", { class: "btn ghost", href: activeInvestigationServerCaseHref(), title: "Open active investigation case", "aria-label": "Open active investigation case", dataset: { netvpnAction: "open-active-case" } }, h("span", { html: icon("search", 16) }), "Open active case"),
    h("button", { class: "btn", type: "button", title: "Copy VPN tunnel handoff", "aria-label": "Copy VPN tunnel handoff", dataset: { netvpnAction: "copy-vpn-handoff" }, onclick: () => copyVpnHandoff(packet) }, h("span", { html: icon("copy", 16) }), "Copy handoff"),
    h("button", { class: "btn", type: "button", title: "Export VPN tunnel handoff JSON", "aria-label": "Export VPN tunnel handoff JSON", dataset: { netvpnAction: "export-vpn-handoff" }, onclick: () => exportVpnHandoff(packet) }, h("span", { html: icon("download", 16) }), "Export JSON"));
}

function currentRoute() {
  if (typeof location === "undefined") return "#/netvpn";
  return location.hash || "#/netvpn";
}

async function pinVpnHandoff(packet) {
  try {
    const serverResult = await appendInvestigationPacketToActiveServerCase(packet, {
      appendEvidence: (id, evidence) => api.addInvestigationCaseEvidence(id, evidence),
    });
    const result = pinInvestigationPacket(packet);
    if (serverResult.appended) {
      toast("Pinned to active case", `VPN tunnel evidence was appended to ${serverResult.activeCaseId} and refreshed locally.`, "ok");
      return;
    }
    toast(result.toastTitle, `${result.toastDetail} No active server case was selected.`, "ok");
  } catch (e) {
    toast("Pin failed", e.message || "Selected tunnel evidence could not be pinned.", "bad");
  }
}

async function copyVpnPeerTemplate(template = {}) {
  try {
    await navigator.clipboard.writeText(template.text || "");
    toast("Template copied", "Peer-side VPN template copied with secret placeholders.", "ok");
  } catch {
    toast("Copy failed", "Select the template text and copy it manually.", "warn");
  }
}

async function copyWireguardEnrollment(bundle = {}) {
  try {
    await navigator.clipboard.writeText(bundle.text || "");
    toast("Enrollment copied", "WireGuard client config copied with placeholder-only client key material.", "ok");
  } catch {
    toast("Copy failed", "Select the enrollment text and copy it manually.", "warn");
  }
}

function exportWireguardEnrollment(bundle = {}) {
  downloadText(bundle.filename || "wireguard-enrollment.conf", bundle.text || "", "text/plain");
  toast("Enrollment exported", `${bundle.filename || "wireguard-enrollment.conf"} uses placeholder-only client key material.`, "ok");
}

function exportWireguardEnrollmentQr(bundle = {}) {
  try {
    const filename = wireguardEnrollmentQrFilename(bundle);
    downloadText(filename, wireguardEnrollmentQrSvg(bundle), "image/svg+xml");
    toast("Enrollment QR exported", `${filename} encodes placeholder-only client key material.`, "ok");
  } catch (e) {
    toast("QR export failed", e.message || "Enrollment QR could not be generated.", "bad");
  }
}

function exportVpnPeerTemplate(template = {}) {
  downloadText(template.filename || "vpn-peer-template.txt", template.text || "", "text/plain");
  toast("Template exported", template.filename || "vpn-peer-template.txt", "ok");
}

async function copyVpnHandoff(packet) {
  try {
    await navigator.clipboard.writeText(investigationPacketText(packet));
    toast("Handoff copied", "Selected tunnel review handoff copied; field proof still requires route, runtime, capture, and session evidence.", "ok");
  } catch {
    toast("Copy failed", "Select the tunnel evidence and copy it manually.", "warn");
  }
}

function exportVpnHandoff(packet) {
  const text = investigationPacketJson(packet);
  downloadText(investigationPacketFilename(packet), text, "application/json");
  toast("Handoff exported", "Downloaded selected tunnel review handoff JSON without claiming field evidence.", "ok");
}

function downloadText(filename, text, type) {
  const blob = new Blob([text], { type: type || "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function vpnTroubleshootHash(target = {}, intent = "explain") {
  const q = new URLSearchParams();
  q.set("source", "POLICY_SOURCE_CANDIDATE");
  q.set("src", target.srcIp || "");
  q.set("dst", target.destIp || "");
  q.set("protocol", target.protocol || "PROTOCOL_ANY");
  q.set("runtime", "1");
  q.set("run", "1");
  q.set("intent", intent === "capture" ? "capture" : "explain");
  return "#/troubleshoot?" + q.toString();
}

export function vpnSessionsHash(target = {}) {
  const q = new URLSearchParams();
  q.set("mode", "sessions");
  q.set("ip", target.destIp || target.remoteIp || "");
  q.set("limit", "500");
  return "#/traffic?" + q.toString();
}

function wireguardKeepaliveSeconds(model = {}) {
  const match = String(model.mode || "").match(/keepalive\s+(\d+)s/i);
  return match ? Number(match[1]) : 0;
}

function wireguardEnrollmentEndpoint(value = "", listenPort = 0) {
  const raw = safeTemplateValue(value || "");
  if (raw) return raw.includes(":") ? raw : `${raw}:${listenPort || 51820}`;
  return `<firewall-public-endpoint>:${listenPort || 51820}`;
}

function templateList(values = [], fallback = "<value>") {
  const clean = (values || []).map(safeTemplateValue).filter(Boolean);
  return clean.length ? clean.join(", ") : fallback;
}

function safeTemplateValue(value = "") {
  return String(value || "")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[redacted-jwt]")
    .replace(/\b(bearer|token|secret|password|credential|private[_-]?key|api[_-]?key)\s*[:=]\s*[^,\s;&]+/gi, "$1=[redacted]")
    .replace(/\/(?:etc\/(?:phragma|openngfw)|var\/lib|var\/log|tmp|private\/tmp|Users|home)\/[^\s,;}]+/gi, "[local-path-redacted]")
    .replace(/\b(?:privateKeyFile|private_key_file|pskFile|psk_file)\s*[:=]\s*[^\s,;}]+/gi, "[secret-path-redacted]")
    .replace(/[;\n\r]/g, " ")
    .trim();
}

function safeTemplateKey(value = "") {
  return safeTemplateSlug(value).replace(/-/g, "_") || "vpn_peer";
}

function safeTemplateSlug(value = "") {
  return String(value || "").toLowerCase().replace(/[^a-z0-9_.-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80);
}

function representativeIp(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  const [addr, prefixText] = raw.split("/");
  if (!addr.includes(".") || prefixText == null) return addr;
  const prefix = Number(prefixText);
  const octets = addr.split(".").map((part) => Number(part));
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return addr;
  if (prefix >= 32) return addr;
  if (octets[3] === 0) octets[3] = 1;
  else if (octets[3] === 255) octets[3] = 254;
  return octets.join(".");
}

function ospfCard(root, ospf = {}) {
  ospf = ospf || {};
  const frrRuntime = runtimeStatus.routing?.frr || {};
  const neighbors = ospfRuntimeRows(frrRuntime);
  const dirty = !equal((session.running.routing || {}).ospf || {}, (session.draft.routing || {}).ospf || {});
  const header = h("h2", {}, "OSPF", h("span", { class: "spacer" }),
    dirty ? pill("candidate edit", "warn") : null,
    neighbors.length || ospf.enabled ? pill("runtime " + (frrRuntime.state || "unknown"), runtimeStateClass(frrRuntime.state)) : null,
    pill(ospf.enabled ? "enabled" : "disabled", ospf.enabled ? "ok" : "neutral"));
  if (!ospf.enabled) return netvpnSection("ospf", card(header,
    neighbors.length ? ospfRuntimeEvidence(neighbors) : null,
    emptyState("globe", "OSPF not enabled", "No OSPF configuration in the candidate policy.",
      [
        h("button", { class: "btn primary", type: "button", title: "Configure OSPF candidate settings", "aria-label": "Configure OSPF candidate settings", dataset: { netvpnAction: "configure-ospf" }, onclick: () => editOspf(root) }, h("span", { html: icon("edit", 16) }), "Configure OSPF"),
        h("button", { class: "btn", type: "button", title: "Review OSPF route context", "aria-label": "Review OSPF route context", dataset: { netvpnAction: "review-ospf" }, onclick: () => openDynamicRouteReviewDrawer(root, "ospf") }, h("span", { html: icon("search", 16) }), "Review"),
      ])));
  return netvpnSection("ospf", card(header,
    neighbors.length ? ospfRuntimeEvidence(neighbors) : h("div", { class: "note", style: { margin: "0 0 10px" } }, frrRuntime.detail || "No OSPF neighbor evidence returned by FRR."),
    h("dl", { class: "kv", style: { marginBottom: "12px" } }, h("dt", {}, "Router ID"), h("dd", { class: "mono" }, ospf.routerId || "—")),
    h("div", { class: "note" }, "Areas"),
    (ospf.areas || []).length ? (ospf.areas || []).map((a) =>
      h("div", { style: { marginTop: "6px" } },
        h("span", { class: "tag" }, "area " + a.area),
        (a.networks || []).map((n) => h("span", { class: "tag" }, n)))) : h("div", { class: "note" }, "none"),
    h("div", { class: "flex wrap", style: { marginTop: "12px" } },
      h("button", { class: "btn", type: "button", title: "Review OSPF route context", "aria-label": "Review OSPF route context", dataset: { netvpnAction: "review-ospf" }, onclick: () => openDynamicRouteReviewDrawer(root, "ospf") }, h("span", { html: icon("search", 16) }), "Review"),
      h("button", { class: "btn", type: "button", title: "Edit OSPF candidate settings", "aria-label": "Edit OSPF candidate settings", dataset: { netvpnAction: "configure-ospf" }, onclick: () => editOspf(root) }, h("span", { html: icon("edit", 16) }), "Edit OSPF"),
      h("button", { class: "btn ghost", type: "button", title: "Disable OSPF in candidate", "aria-label": "Disable OSPF in candidate", dataset: { netvpnAction: "disable-ospf" }, onclick: () => disableOspf(root) }, "Disable"))));
}

function ospfRuntimeEvidence(neighbors) {
  return h("div", { style: { marginBottom: "10px" } },
    h("div", { class: "note", style: { marginBottom: "6px" } }, ospfRuntimeSummary({ ospfNeighbors: neighbors })),
    h("div", { class: "flex wrap", style: { gap: "4px" } },
      neighbors.slice(0, 6).map((neighbor) => h("span", { class: "tag" }, ospfRuntimeLabel(neighbor))),
      neighbors.length > 6 ? h("span", { class: "tag" }, `${neighbors.length - 6} more`) : null));
}

function editOspf(root, opts = {}) {
  const o = structuredClone(session.draft.routing?.ospf || { enabled: true });
  if (opts.sync !== false) setNetvpnRouteState(netvpnDynamicRouteState("ospf", "edit"));
  const enabled = checkbox(o.enabled !== false);
  enabled.dataset.netvpnOspfField = "enabled";
  const routerId = inp(o.routerId, "192.0.2.1");
  routerId.dataset.netvpnOspfField = "router-id";
  const areas = h("div", { class: "form-list" });
  const areaRows = [];

  const addArea = (a = {}) => {
    const area = inp(a.area, "0.0.0.0");
    area.dataset.netvpnOspfField = "area-id";
    const networks = h("textarea", { class: "input", placeholder: "10.10.0.0/24, 10.20.0.0/24", dataset: { netvpnOspfField: "networks" } }, (a.networks || []).join(", "));
    const rec = { area, networks, row: null };
    rec.row = h("div", { class: "form-row two" },
      field("Area ID", area),
      field("Networks", networks, "comma or newline separated CIDRs"),
      h("button", { class: "icon-btn", type: "button", title: "Remove area", "aria-label": "Remove OSPF area", dataset: { netvpnAction: "remove-ospf-area" }, onclick: () => { rec.row.remove(); areaRows.splice(areaRows.indexOf(rec), 1); }, html: icon("trash", 16) }));
    areaRows.push(rec);
    areas.appendChild(rec.row);
  };

  (o.areas || []).forEach(addArea);
  if (!areaRows.length) addArea();

  openDrawer({
    title: "Configure OSPF",
    subtitle: "Staged to the candidate and rendered by FRR on commit.",
    width: "760px",
    onClose: clearNetvpnDrawerState,
    body: h("div", { dataset: { netvpnOspfDrawer: "true" } },
      opts.routeBacked ? h("div", { class: "note", style: { marginBottom: "10px" } }, "Opened from route-backed OSPF edit state.") : null,
      h("label", { class: "field flex", style: { justifyContent: "space-between" } }, h("span", {}, "Enable OSPF"), enabled),
      field("Router ID", routerId, "optional IPv4 router ID"),
      h("div", { class: "divider" }),
      h("div", { class: "flex", style: { justifyContent: "space-between", marginBottom: "8px" } },
        h("strong", {}, "Areas"),
        h("button", { class: "btn sm", type: "button", title: "Add OSPF area row", "aria-label": "Add OSPF area row", dataset: { netvpnAction: "add-ospf-area" }, onclick: () => addArea() }, h("span", { html: icon("plus", 14) }), "Add area")),
      areas),
    footer: [h("button", { class: "btn ghost", type: "button", title: "Cancel OSPF configuration", "aria-label": "Cancel OSPF configuration", dataset: { netvpnAction: "cancel-ospf" }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: "Stage OSPF candidate settings", "aria-label": "Stage OSPF candidate settings", dataset: { netvpnAction: "stage-ospf" }, onclick: save }, h("span", { html: icon("check", 16) }), "Stage OSPF")],
  });

  async function save() {
    const next = ospfFromInputs(enabled, routerId, areaRows);
    if (next.error) { toast("OSPF not staged", next.error, "warn"); return; }
    try {
      await session.apply((d) => {
        d.routing ||= {};
        d.routing.ospf = next.ospf;
      });
      closeDrawer(); paint(root); toast("OSPF staged", "Commit to update FRR.", "ok");
    } catch (e) { toast("Could not stage OSPF", e.message, "bad"); }
  }
}

async function disableOspf(root) {
  if (!(await confirmDialog({ title: "Disable OSPF?", message: "OSPF will be disabled in the candidate. FRR is updated when the candidate is committed.", confirmLabel: "Disable", danger: true }))) return;
  try {
    await session.apply((d) => {
      d.routing ||= {};
      d.routing.ospf = { ...(d.routing.ospf || {}), enabled: false };
    });
    paint(root); toast("OSPF disabled", "Staged to candidate.", "ok");
  } catch (e) { toast("Could not disable OSPF", e.message, "bad"); }
}

export function ospfFromInputs(enabled, routerId, areaRows) {
  const on = enabled.checked;
  const ospf = { enabled: on };
  if (routerId.value.trim()) ospf.routerId = routerId.value.trim();
  ospf.areas = areaRows.map((r) => ({
    area: r.area.value.trim(),
    networks: splitList(r.networks.value),
  })).filter((a) => a.area || a.networks.length);
  if (!on) return { ospf };
  if (ospf.routerId && !validIPv4Address(ospf.routerId)) return { error: "OSPF router ID must be an IPv4 address." };
  if (!ospf.areas.length) return { error: "At least one area is required." };
  for (let i = 0; i < ospf.areas.length; i += 1) {
    const a = ospf.areas[i];
    if (!a.area) return { error: "Every OSPF area needs an area ID." };
    if (!validIPv4Address(a.area)) return { error: `OSPF area ${a.area || "#" + (i + 1)} must use dotted IPv4 format.` };
    if (!a.networks.length) return { error: `Area ${a.area} needs at least one network.` };
    for (const network of a.networks) {
      if (!validCidr(network)) return { error: `OSPF network ${network} must be a valid IPv4/IPv6 CIDR.` };
    }
  }
  return { ospf };
}

function ipsecCard(root, tunnels) {
  tunnels = tunnels || [];
  const dirty = !equal((session.running.vpn || {}).ipsecTunnels || [], (session.draft.vpn || {}).ipsecTunnels || []);
  const header = h("h2", {}, "IPsec tunnels", h("span", { class: "spacer" }),
    dirty ? pill("candidate edit", "warn") : null,
    h("span", { class: "muted" }, tunnels.length + " configured"));
  if (!tunnels.length) return card(header,
    emptyState("vpn", "No IPsec tunnels", "No strongSwan tunnels in the candidate policy.",
      h("button", { class: "btn primary", type: "button", title: "Add IPsec tunnel", "aria-label": "Add IPsec tunnel to candidate", dataset: { netvpnAction: "add-ipsec" }, onclick: () => editIpsec(root, null) }, h("span", { html: icon("plus", 16) }), "Add tunnel")));
  return card(header,
    responsiveTable(["Name", "Peer", "CIDRs", "Mode", { label: "", attrs: { class: "actions-col" } }],
      tunnels.map((t, i) => {
        const tunnelLabel = t.name || `ipsec-${i + 1}`;
        return h("tr", {},
          labeledCell("Name", {}, h("strong", {}, t.name || "unnamed")),
          labeledCell("Peer", { class: "mono" }, (t.localAddress || "%any") + " ↔ " + (t.remoteAddress || "?")),
          labeledCell("CIDRs", {}, (t.remoteSubnets || []).map((s) => h("span", { class: "tag" }, s))),
          labeledCell("Mode", {}, t.initiate ? pill("initiator", "info") : pill("responder", "neutral")),
          labeledCell("Actions", { class: "cell-actions" }, h("div", { class: "flex row-actions" },
            h("button", { class: "icon-btn", type: "button", title: "Inspect tunnel handoff", "aria-label": `Inspect IPsec tunnel ${tunnelLabel}`, dataset: { netvpnAction: "inspect-ipsec" }, onclick: () => openVpnTunnelDrawer(vpnTunnelModels(session.draft || {}, runtimeStatus).find((model) => model.kind === "ipsec" && model.name === tunnelLabel), root), html: icon("search", 16) }),
            h("button", { class: "icon-btn", type: "button", title: "Edit tunnel", "aria-label": `Edit IPsec tunnel ${tunnelLabel}`, dataset: { netvpnAction: "edit-ipsec" }, onclick: () => editIpsec(root, i), html: icon("edit", 16) }),
            h("button", { class: "icon-btn", type: "button", title: "Delete tunnel", "aria-label": `Delete IPsec tunnel ${tunnelLabel}`, dataset: { netvpnAction: "delete-ipsec" }, onclick: () => delIpsec(root, i, t), html: icon("trash", 16) }))));
      })),
    h("div", { class: "flex wrap", style: { marginTop: "12px" } },
      h("button", { class: "btn", type: "button", title: "Add IPsec tunnel", "aria-label": "Add IPsec tunnel to candidate", dataset: { netvpnAction: "add-ipsec" }, onclick: () => editIpsec(root, null) }, h("span", { html: icon("plus", 16) }), "Add tunnel")));
}

async function delIpsec(root, idx, tunnel) {
  if (!(await confirmDialog({ title: "Delete IPsec tunnel?", message: `Remove ${tunnel.name || "this tunnel"} from the candidate? strongSwan is updated when the candidate is committed.`, confirmLabel: "Delete", danger: true }))) return;
  try {
    await session.apply((d) => {
      d.vpn ||= {};
      d.vpn.ipsecTunnels ||= [];
      d.vpn.ipsecTunnels.splice(idx, 1);
    });
    paint(root); toast("IPsec tunnel deleted", "Staged to candidate.", "ok");
  } catch (e) { toast("Could not delete tunnel", e.message, "bad"); }
}

function editIpsec(root, idx) {
  const editing = idx != null;
  const t = editing ? structuredClone(session.draft.vpn?.ipsecTunnels?.[idx] || {}) : {};
  const name = inp(t.name, "site-b");
  name.dataset.netvpnIpsecField = "name";
  const localAddress = inp(t.localAddress, "%any");
  localAddress.dataset.netvpnIpsecField = "local-address";
  const remoteAddress = inp(t.remoteAddress, "203.0.113.1");
  remoteAddress.dataset.netvpnIpsecField = "remote-address";
  const localSubnets = h("textarea", { class: "input", placeholder: "10.10.0.0/24" }, (t.localSubnets || []).join(", "));
  localSubnets.dataset.netvpnIpsecField = "local-subnets";
  const remoteSubnets = h("textarea", { class: "input", placeholder: "10.20.0.0/24" }, (t.remoteSubnets || []).join(", "));
  remoteSubnets.dataset.netvpnIpsecField = "remote-subnets";
  const pskFile = inp(t.pskFile, "/etc/phragma/secrets/site-b.conf");
  pskFile.dataset.netvpnIpsecField = "psk-file";
  const ikeProposal = inp(t.ikeProposal, "aes256-sha256-modp2048");
  ikeProposal.dataset.netvpnIpsecField = "ike-proposal";
  const espProposal = inp(t.espProposal, "aes256-sha256-modp2048");
  espProposal.dataset.netvpnIpsecField = "esp-proposal";
  const initiate = checkbox(!!t.initiate);
  initiate.dataset.netvpnIpsecField = "initiate";

  openDrawer({
    title: editing ? "Edit IPsec tunnel" : "Add IPsec tunnel",
    subtitle: "PSK material stays in a swanctl secrets file; policy stores only the file path.",
    width: "760px",
    body: h("div", { dataset: { netvpnIpsecDrawer: "true" } },
      h("div", { class: "form-grid two" },
        field("Tunnel name", name),
        field("PSK file", pskFile),
        field("Local endpoint", localAddress, "blank becomes %any"),
        field("Remote endpoint", remoteAddress),
        field("IKE proposal", ikeProposal, "optional"),
        field("ESP proposal", espProposal, "optional")),
      field("Local subnets", localSubnets, "comma or newline separated CIDRs"),
      field("Remote subnets", remoteSubnets, "comma or newline separated CIDRs"),
      h("label", { class: "field flex", style: { justifyContent: "space-between" } }, h("span", {}, "Initiate on load"), initiate)),
    footer: [h("button", { class: "btn ghost", type: "button", title: "Cancel IPsec tunnel edit", "aria-label": "Cancel IPsec tunnel edit", dataset: { netvpnAction: "cancel-ipsec" }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: editing ? "Stage IPsec tunnel changes" : "Stage new IPsec tunnel", "aria-label": editing ? "Stage IPsec tunnel changes to candidate" : "Stage new IPsec tunnel to candidate", dataset: { netvpnAction: "stage-ipsec" }, onclick: save }, h("span", { html: icon("check", 16) }), "Stage tunnel")],
  });

  async function save() {
    const next = ipsecFromInputs(name, localAddress, remoteAddress, localSubnets, remoteSubnets, pskFile, ikeProposal, espProposal, initiate);
    if (next.error) { toast("IPsec not staged", next.error, "warn"); return; }
    const duplicate = (session.draft.vpn?.ipsecTunnels || []).some((tunnel, i) => i !== idx && tunnel?.name === next.tunnel.name);
    if (duplicate) { toast("IPsec not staged", `IPsec tunnel ${next.tunnel.name} already exists in the candidate.`, "warn"); return; }
    try {
      await session.apply((d) => {
        d.vpn ||= {};
        d.vpn.ipsecTunnels ||= [];
        if (editing) d.vpn.ipsecTunnels[idx] = next.tunnel; else d.vpn.ipsecTunnels.push(next.tunnel);
      });
      closeDrawer(); paint(root); toast(editing ? "IPsec saved" : "IPsec added", "Staged to candidate.", "ok");
    } catch (e) { toast("Could not stage IPsec", e.message, "bad"); }
  }
}

export function ipsecFromInputs(name, localAddress, remoteAddress, localSubnets, remoteSubnets, pskFile, ikeProposal, espProposal, initiate) {
  const tunnel = {
    name: name.value.trim(),
    localSubnets: splitList(localSubnets.value),
    remoteSubnets: splitList(remoteSubnets.value),
    pskFile: pskFile.value.trim(),
    initiate: initiate.checked,
  };
  if (localAddress.value.trim()) tunnel.localAddress = localAddress.value.trim();
  if (remoteAddress.value.trim()) tunnel.remoteAddress = remoteAddress.value.trim();
  if (ikeProposal.value.trim()) tunnel.ikeProposal = ikeProposal.value.trim();
  if (espProposal.value.trim()) tunnel.espProposal = espProposal.value.trim();
  if (!tunnel.name) return { error: "Tunnel name is required." };
  if (!validPolicyName(tunnel.name)) return { error: "Tunnel name must be lowercase alphanumeric with optional '-' or '_' and cannot be 'any'." };
  if (!tunnel.remoteAddress) return { error: "Remote endpoint is required." };
  if (!validConfigToken(tunnel.localAddress || "", false)) return { error: "Local endpoint contains characters unsafe for engine config." };
  if (!validConfigToken(tunnel.remoteAddress, true)) return { error: "Remote endpoint contains characters unsafe for engine config." };
  if (tunnel.ikeProposal && !validConfigToken(tunnel.ikeProposal, false)) return { error: "IKE proposal contains characters unsafe for engine config." };
  if (tunnel.espProposal && !validConfigToken(tunnel.espProposal, false)) return { error: "ESP proposal contains characters unsafe for engine config." };
  if (!tunnel.localSubnets.length) return { error: "At least one local subnet is required." };
  for (const cidr of tunnel.localSubnets) {
    if (!validCidr(cidr)) return { error: `Local subnet ${cidr} must be a valid IPv4/IPv6 CIDR.` };
  }
  if (!tunnel.remoteSubnets.length) return { error: "At least one remote subnet is required." };
  for (const cidr of tunnel.remoteSubnets) {
    if (!validCidr(cidr)) return { error: `Remote subnet ${cidr} must be a valid IPv4/IPv6 CIDR.` };
  }
  if (!tunnel.pskFile) return { error: "PSK file path is required." };
  if (!validManagedPath(tunnel.pskFile, IPSEC_SECRET_ROOTS)) return { error: "PSK file path must be an absolute managed path under /etc/phragma/secrets or /etc/openngfw/secrets." };
  return { tunnel };
}

function wireguardCard(root, ifaces) {
  ifaces = ifaces || [];
  const runtime = runtimeStatus.vpn?.wireguard || {};
  const runtimeByInterface = wireguardRuntimeByInterface(runtime);
  const dirty = !equal((session.running.vpn || {}).wireguardInterfaces || [], (session.draft.vpn || {}).wireguardInterfaces || []);
  const header = h("h2", {}, "WireGuard", h("span", { class: "spacer" }),
    dirty ? pill("candidate edit", "warn") : null,
    runtime.state && runtime.state !== "not-configured" ? pill("runtime " + runtime.state, runtimeStateClass(runtime.state)) : null,
    h("span", { class: "muted" }, ifaces.length + " interface" + (ifaces.length === 1 ? "" : "s")));
  if (!ifaces.length) return card(header,
    emptyState("vpn", "No WireGuard interfaces", "No WireGuard interfaces in the candidate policy.",
      [
        h("button", { class: "btn primary", type: "button", title: "Open WireGuard branch rollout", "aria-label": "Open WireGuard branch rollout workflow", dataset: { netvpnAction: "open-wireguard-rollout" }, onclick: () => openWireguardRolloutDrawer(root) }, h("span", { html: icon("vpn", 16) }), "Branch rollout"),
        h("button", { class: "btn", type: "button", title: "Add WireGuard interface", "aria-label": "Add WireGuard interface to candidate", dataset: { netvpnAction: "add-wireguard" }, onclick: () => editWireguard(root, null) }, h("span", { html: icon("plus", 16) }), "Add interface"),
      ]));
  return card(header,
    runtime.detail ? h("div", { class: "note", style: { margin: "0 0 10px" } }, runtime.detail) : null,
    ifaces.map((w, i) => wireguardInterfaceRow(root, w, i, runtimeByInterface.get(w.name || ""))),
    h("div", { class: "flex wrap", style: { marginTop: "12px" } },
      h("button", { class: "btn primary", type: "button", title: "Open WireGuard branch rollout", "aria-label": "Open WireGuard branch rollout workflow", dataset: { netvpnAction: "open-wireguard-rollout" }, onclick: () => openWireguardRolloutDrawer(root) }, h("span", { html: icon("vpn", 16) }), "Branch rollout"),
      h("button", { class: "btn", type: "button", title: "Add WireGuard interface", "aria-label": "Add WireGuard interface to candidate", dataset: { netvpnAction: "add-wireguard" }, onclick: () => editWireguard(root, null) }, h("span", { html: icon("plus", 16) }), "Add interface")));
}

function wireguardInterfaceRow(root, w, i, live) {
  const interfaceLabel = w.name || `wg-${i + 1}`;
  return h("div", { class: "vpn-item" },
    h("div", { class: "flex wrap" },
      h("strong", {}, w.name || "unnamed"),
      h("span", { class: "tag mono" }, w.address || "no address"),
      w.listenPort ? h("span", { class: "tag" }, "udp/" + w.listenPort) : null,
      live ? pill(live.state || "runtime", runtimeStateClass(live.state)) : pill("not observed", "neutral"),
      live ? h("span", { class: "tag" }, `${live.activePeerCount || 0}/${live.peerCount || 0} handshook`) : null,
      h("span", { class: "spacer" }),
      h("button", { class: "icon-btn", type: "button", title: "Edit interface", "aria-label": `Edit WireGuard interface ${interfaceLabel}`, dataset: { netvpnAction: "edit-wireguard" }, onclick: () => editWireguard(root, i), html: icon("edit", 16) }),
      h("button", { class: "icon-btn", type: "button", title: "Delete interface", "aria-label": `Delete WireGuard interface ${interfaceLabel}`, dataset: { netvpnAction: "delete-wireguard" }, onclick: () => delWireguard(root, i, w), html: icon("trash", 16) })),
    h("div", { class: "note", style: { margin: "4px 0" } }, (w.peers || []).length + " configured peer(s)", live?.detail ? " · " + live.detail : ""),
    (w.peers || []).map((p) => {
      const peerRuntime = wireguardPeerRuntime(live, p.publicKey);
      return h("div", { class: "flex wrap", style: { gap: "6px" } },
        h("span", { class: "mono muted" }, (p.name || "peer") + ":"),
        (p.allowedIps || []).map((a) => h("span", { class: "tag" }, a)),
        h("span", { class: "tag" }, wireguardPeerRuntimeLabel(peerRuntime)),
        h("button", {
          class: "btn sm ghost",
          type: "button",
          title: "Inspect tunnel handoff",
          "aria-label": `Inspect WireGuard tunnel ${interfaceLabel}:${p.name || "peer"}`,
          dataset: { netvpnAction: "inspect-wireguard-peer" },
          onclick: () => openVpnTunnelDrawer(vpnTunnelModels(session.draft || {}, runtimeStatus).find((model) =>
            model.kind === "wireguard" && model.interfaceName === interfaceLabel && model.peerName === (p.name || "peer")), root),
        }, h("span", { html: icon("search", 14) }), "Inspect"));
    }));
}

async function delWireguard(root, idx, iface) {
  if (!(await confirmDialog({ title: "Delete WireGuard interface?", message: `Remove ${iface.name || "this interface"} from the candidate? The interface is updated when the candidate is committed.`, confirmLabel: "Delete", danger: true }))) return;
  try {
    await session.apply((d) => {
      d.vpn ||= {};
      d.vpn.wireguardInterfaces ||= [];
      d.vpn.wireguardInterfaces.splice(idx, 1);
    });
    paint(root); toast("WireGuard interface deleted", "Staged to candidate.", "ok");
  } catch (e) { toast("Could not delete interface", e.message, "bad"); }
}

function editWireguard(root, idx) {
  const editing = idx != null;
  const w = editing ? structuredClone(session.draft.vpn?.wireguardInterfaces?.[idx] || {}) : {};
  const name = inp(w.name, "wg0");
  name.dataset.netvpnWireguardField = "name";
  const address = inp(w.address, "10.99.0.1/24");
  address.dataset.netvpnWireguardField = "address";
  const listenPort = h("input", { class: "input", type: "number", min: "0", max: "65535", value: w.listenPort || "", placeholder: "51820" });
  listenPort.dataset.netvpnWireguardField = "listen-port";
  const privateKeyFile = inp(w.privateKeyFile, "/etc/phragma/keys/wg0.key");
  privateKeyFile.dataset.netvpnWireguardField = "private-key-file";
  const peers = h("div", { class: "form-list" });
  const peerRows = [];

  const addPeer = (p = {}) => {
    const peerName = inp(p.name, "laptop");
    peerName.dataset.netvpnWireguardField = "peer-name";
    const publicKey = inp(p.publicKey, "base64 peer public key");
    publicKey.dataset.netvpnWireguardField = "peer-public-key";
    const endpoint = inp(p.endpoint, "203.0.113.10:51820");
    endpoint.dataset.netvpnWireguardField = "peer-endpoint";
    const allowedIps = h("textarea", { class: "input", placeholder: "10.99.0.2/32" }, (p.allowedIps || []).join(", "));
    allowedIps.dataset.netvpnWireguardField = "peer-allowed-ips";
    const keepalive = h("input", { class: "input", type: "number", min: "0", max: "65535", value: p.persistentKeepalive || "", placeholder: "25" });
    keepalive.dataset.netvpnWireguardField = "peer-keepalive";
    const rec = { peerName, publicKey, endpoint, allowedIps, keepalive, row: null };
    rec.row = h("div", { class: "peer-row" },
      h("div", { class: "form-grid two" },
        field("Peer name", peerName),
        field("Endpoint", endpoint, "optional host:port")),
      field("Public key", publicKey),
      field("Allowed IPs", allowedIps, "comma or newline separated CIDRs"),
      field("Keepalive", keepalive, "seconds; 0 disables"),
      h("button", { class: "icon-btn", type: "button", title: "Remove peer", "aria-label": "Remove WireGuard peer", dataset: { netvpnAction: "remove-wireguard-peer" }, onclick: () => { rec.row.remove(); peerRows.splice(peerRows.indexOf(rec), 1); }, html: icon("trash", 16) }));
    peerRows.push(rec);
    peers.appendChild(rec.row);
  };

  (w.peers || []).forEach(addPeer);

  openDrawer({
    title: editing ? "Edit WireGuard interface" : "Add WireGuard interface",
    subtitle: "Private key material stays on disk; policy stores only the key-file path.",
    width: "780px",
    body: h("div", { dataset: { netvpnWireguardDrawer: "true" } },
      h("div", { class: "form-grid two" },
        field("Interface name", name),
        field("Address", address),
        field("Listen port", listenPort, "optional"),
        field("Private key file", privateKeyFile)),
      h("div", { class: "divider" }),
      h("div", { class: "flex", style: { justifyContent: "space-between", marginBottom: "8px" } },
        h("strong", {}, "Peers"),
        h("button", { class: "btn sm", type: "button", title: "Add WireGuard peer row", "aria-label": "Add WireGuard peer row", dataset: { netvpnAction: "add-wireguard-peer" }, onclick: () => addPeer() }, h("span", { html: icon("plus", 14) }), "Add peer")),
      peers),
    footer: [h("button", { class: "btn ghost", type: "button", title: "Cancel WireGuard interface edit", "aria-label": "Cancel WireGuard interface edit", dataset: { netvpnAction: "cancel-wireguard" }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: editing ? "Stage WireGuard interface changes" : "Stage new WireGuard interface", "aria-label": editing ? "Stage WireGuard interface changes to candidate" : "Stage new WireGuard interface to candidate", dataset: { netvpnAction: "stage-wireguard" }, onclick: save }, h("span", { html: icon("check", 16) }), "Stage interface")],
  });

  async function save() {
    const next = wireguardFromInputs(name, address, listenPort, privateKeyFile, peerRows);
    if (next.error) { toast("WireGuard not staged", next.error, "warn"); return; }
    const duplicate = (session.draft.vpn?.wireguardInterfaces || []).some((iface, i) => i !== idx && iface?.name === next.iface.name);
    if (duplicate) { toast("WireGuard not staged", `WireGuard interface ${next.iface.name} already exists in the candidate.`, "warn"); return; }
    try {
      await session.apply((d) => {
        d.vpn ||= {};
        d.vpn.wireguardInterfaces ||= [];
        if (editing) d.vpn.wireguardInterfaces[idx] = next.iface; else d.vpn.wireguardInterfaces.push(next.iface);
      });
      closeDrawer(); paint(root); toast(editing ? "WireGuard saved" : "WireGuard added", "Staged to candidate.", "ok");
    } catch (e) { toast("Could not stage WireGuard", e.message, "bad"); }
  }
}

export function wireguardFromInputs(name, address, listenPort, privateKeyFile, peerRows) {
  const iface = {
    name: name.value.trim(),
    address: address.value.trim(),
    privateKeyFile: privateKeyFile.value.trim(),
    peers: peerRows.map((r) => ({
      name: r.peerName.value.trim(),
      publicKey: r.publicKey.value.trim(),
      endpoint: r.endpoint.value.trim(),
      allowedIps: splitList(r.allowedIps.value),
      persistentKeepalive: strictOptionalPort(r.keepalive.value).ok ? strictOptionalPort(r.keepalive.value).value : 0,
      keepaliveText: r.keepalive.value.trim(),
    })).filter((p) => p.name || p.publicKey || p.endpoint || p.allowedIps.length || p.persistentKeepalive),
  };
  const port = strictOptionalPort(listenPort.value);
  if (port.ok && port.value > 0) iface.listenPort = port.value;
  if (!iface.name) return { error: "Interface name is required." };
  if (!validWireguardInterfaceName(iface.name)) return { error: "Interface name must be 1-15 characters without whitespace, slash, or control characters." };
  if (!iface.address) return { error: "Interface address is required." };
  if (!validCidr(iface.address)) return { error: "Interface address must be a valid IPv4/IPv6 CIDR." };
  if (!port.ok) return { error: "Listen port must be an integer from 1 to 65535, or blank." };
  if (!iface.privateKeyFile) return { error: "Private key file path is required." };
  if (!validManagedPath(iface.privateKeyFile, WIREGUARD_KEY_ROOTS)) return { error: "Private key file path must be an absolute managed path under /etc/phragma/keys or /etc/openngfw/keys." };
  for (const p of iface.peers) {
    const label = p.name || "peer";
    if (!p.publicKey) return { error: `${label} needs a public key.` };
    if (!isLikelyWireguardPublicKey(p.publicKey)) return { error: `${label} public key must be a base64 32-byte WireGuard key.` };
    if (!p.allowedIps.length) return { error: `${label} needs at least one allowed IP.` };
    for (const cidr of p.allowedIps) {
      if (!validCidr(cidr)) return { error: `${label} allowed IP ${cidr} must be a valid IPv4/IPv6 CIDR.` };
    }
    if (p.endpoint) {
      if (!validConfigToken(p.endpoint, false)) return { error: `${label} endpoint contains characters unsafe for engine config.` };
      if (!validHostPort(p.endpoint)) return { error: `${label} endpoint must be host:port.` };
    }
    const keepalive = strictOptionalPort(p.keepaliveText);
    if (!keepalive.ok) return { error: `${label} keepalive must be an integer from 1 to 65535, or blank/0.` };
    delete p.keepaliveText;
  }
  return { iface };
}

function openWireguardRolloutDrawer(root) {
  const controls = {
    interfaceName: inp("wg-branch-01", "wg-branch-01"),
    interfaceAddress: inp("10.99.10.1/24", "10.99.10.1/24"),
    listenPort: h("input", { class: "input", type: "number", min: "0", max: "65535", value: "51820", placeholder: "51820" }),
    privateKeyFile: inp("/etc/phragma/keys/wg-branch-01.key", "/etc/phragma/keys/wg-branch-01.key"),
    peerName: inp("branch-01", "branch-01"),
    publicKey: inp("", "base64 peer public key"),
    endpoint: inp("198.51.100.10:51820", "198.51.100.10:51820"),
    allowedIps: h("textarea", { class: "input", placeholder: "10.99.10.2/32, 10.120.10.0/24" }, "10.99.10.2/32, 10.120.10.0/24"),
    keepalive: h("input", { class: "input", type: "number", min: "0", max: "65535", value: "25", placeholder: "25" }),
    routeDestination: inp("10.120.10.0/24", "10.120.10.0/24"),
    routeVia: inp("", "blank for tunnel interface route"),
    routeMetric: h("input", { class: "input", type: "number", min: "0", value: "50", placeholder: "50" }),
  };
  const preview = h("div", { class: "profile-strip", dataset: { netvpnRolloutPreview: "true" } });
  const refresh = () => renderWireguardRolloutPreview(preview, session.draft || {}, controls);
  for (const control of Object.values(controls)) {
    control.addEventListener?.("input", refresh);
    control.addEventListener?.("change", refresh);
  }
  refresh();

  openDrawer({
    title: "WireGuard branch rollout",
    subtitle: "Stages a tunnel peer and the required static route to the candidate.",
    width: "820px",
    body: h("div", { dataset: { netvpnRolloutDrawer: "true" } },
      h("div", { class: "alert-box info" },
        h("strong", {}, "Candidate-only rollout. "),
        "This stages one WireGuard interface, one peer, and one static route. Running policy is unchanged until commit."),
      h("div", { class: "form-grid two" },
        field("Interface name", controls.interfaceName),
        field("Interface address", controls.interfaceAddress, "firewall tunnel address CIDR"),
        field("Listen port", controls.listenPort, "optional UDP port"),
        field("Private key file", controls.privateKeyFile, "server-local path; not exported")),
      h("div", { class: "divider" }),
      h("strong", {}, "Branch peer"),
      h("div", { class: "form-grid two", style: { marginTop: "10px" } },
        field("Peer name", controls.peerName),
        field("Endpoint", controls.endpoint, "optional public host:port")),
      field("Public key", controls.publicKey),
      field("Allowed IPs", controls.allowedIps, "must include the routed branch prefix"),
      field("Keepalive", controls.keepalive, "seconds; 0 disables"),
      h("div", { class: "divider" }),
      h("strong", {}, "Static route"),
      h("div", { class: "form-grid two", style: { marginTop: "10px" } },
        field("Branch prefix", controls.routeDestination, "route destination staged with this rollout"),
        field("Via", controls.routeVia, "usually blank for WireGuard interface route"),
        field("Metric", controls.routeMetric, "optional; lower wins")),
      preview),
    footer: [
      h("button", { class: "btn ghost", type: "button", title: "Cancel WireGuard branch rollout", "aria-label": "Cancel WireGuard branch rollout", dataset: { netvpnAction: "cancel-wireguard-rollout" }, onclick: closeDrawer }, "Cancel"),
      h("button", { class: "btn primary", type: "button", title: "Stage WireGuard branch rollout", "aria-label": "Stage WireGuard branch rollout to candidate", dataset: { netvpnAction: "stage-wireguard-rollout" }, onclick: () => stageWireguardRollout(root, controls) }, h("span", { html: icon("check", 16) }), "Stage rollout"),
    ],
  });
}

function renderWireguardRolloutPreview(host, policy, controls) {
  clear(host);
  const result = buildWireguardBranchRolloutPlan(policy, wireguardRolloutValues(controls));
  host.appendChild(h("div", { class: "profile-strip-head" },
    h("strong", {}, "Candidate review"),
    result.error ? pill("needs input", "warn") : pill("ready", "ok")));
  if (result.error) {
    host.appendChild(h("div", { class: "note" }, result.error));
    return;
  }
  host.appendChild(h("div", { class: "note" },
    "Stages interface ", h("span", { class: "mono" }, result.iface.name),
    ", peer ", h("span", { class: "mono" }, result.iface.peers[0].name),
    ", and route ", h("span", { class: "mono" }, result.route.destination), "."));
  host.appendChild(h("dl", { class: "kv compact" },
    kv("Interface", `${result.iface.name} ${result.iface.address}`),
    kv("Listen", result.iface.listenPort ? "udp/" + result.iface.listenPort : "not set"),
    kv("Route", `${result.route.destination} -> ${result.route.interface}`),
    kv("Peer allowed IPs", result.iface.peers[0].allowedIps.join(", "))));
  if (result.warnings.length) {
    host.appendChild(h("ul", { class: "trace-list" }, result.warnings.map((warning) => h("li", {}, warning))));
  }
}

async function stageWireguardRollout(root, controls) {
  const result = buildWireguardBranchRolloutPlan(session.draft || {}, wireguardRolloutValues(controls));
  if (result.error) {
    toast("Rollout not staged", result.error, "warn");
    const preview = document.querySelector("[data-netvpn-rollout-preview='true']");
    if (preview) renderWireguardRolloutPreview(preview, session.draft || {}, controls);
    return;
  }
  try {
    await session.apply((d) => {
      d.vpn ||= {};
      d.vpn.wireguardInterfaces ||= [];
      d.staticRoutes ||= [];
      d.vpn.wireguardInterfaces.push(result.iface);
      d.staticRoutes.push(result.route);
    });
    closeDrawer({ invokeOnClose: false });
    paint(root);
    toast("WireGuard rollout staged", "Branch tunnel and route are ready for candidate review.", "ok");
    const model = selectedVpnTunnelModel(session.draft || {}, runtimeStatus, {
      drawer: "tunnel",
      kind: "wireguard",
      iface: result.iface.name,
      peer: result.iface.peers[0].name,
    });
    openVpnTunnelDrawer(model, root);
  } catch (e) {
    toast("Could not stage rollout", e.message, "bad");
  }
}

function wireguardRolloutValues(controls) {
  return {
    interfaceName: controls.interfaceName.value,
    interfaceAddress: controls.interfaceAddress.value,
    listenPort: controls.listenPort.value,
    privateKeyFile: controls.privateKeyFile.value,
    peerName: controls.peerName.value,
    publicKey: controls.publicKey.value,
    endpoint: controls.endpoint.value,
    allowedIps: controls.allowedIps.value,
    keepalive: controls.keepalive.value,
    routeDestination: controls.routeDestination.value,
    routeVia: controls.routeVia.value,
    routeMetric: controls.routeMetric.value,
  };
}

export function buildWireguardBranchRolloutPlan(policy = {}, values = {}) {
  const ifaceName = cleanConfigText(values.interfaceName);
  const ifaceAddress = cleanConfigText(values.interfaceAddress);
  const privateKeyFile = cleanConfigText(values.privateKeyFile);
  const peerName = cleanConfigText(values.peerName);
  const publicKey = cleanConfigText(values.publicKey);
  const endpoint = cleanConfigText(values.endpoint);
  const allowedIps = splitList(values.allowedIps);
  const routeDestination = cleanConfigText(values.routeDestination);
  const routeVia = cleanConfigText(values.routeVia);
  const listenPort = strictOptionalPort(values.listenPort);
  const keepalive = strictOptionalPort(values.keepalive);
  const routeMetric = parsePositiveNumber(values.routeMetric);
  if (!ifaceName) return { error: "Interface name is required." };
  if (!validWireguardInterfaceName(ifaceName)) return { error: "Interface name must be 1-15 characters without whitespace, slash, or control characters." };
  if (!ifaceAddress) return { error: "Interface address is required." };
  if (!validCidr(ifaceAddress)) return { error: "Interface address must be a valid IPv4/IPv6 CIDR." };
  if (!listenPort.ok) return { error: "Listen port must be an integer from 1 to 65535, or blank." };
  if (!privateKeyFile) return { error: "Private key file path is required." };
  if (!validManagedPath(privateKeyFile, WIREGUARD_KEY_ROOTS)) return { error: "Private key file path must be an absolute managed path under /etc/phragma/keys or /etc/openngfw/keys." };
  if (!peerName) return { error: "Peer name is required." };
  if (!publicKey) return { error: `${peerName} needs a public key.` };
  if (!isLikelyWireguardPublicKey(publicKey)) return { error: `${peerName} public key must be a base64 32-byte WireGuard key.` };
  if (!allowedIps.length) return { error: `${peerName} needs at least one allowed IP.` };
  for (const cidr of allowedIps) {
    if (!validCidr(cidr)) return { error: `${peerName} allowed IP ${cidr} must be a valid IPv4/IPv6 CIDR.` };
  }
  if (endpoint) {
    if (!validConfigToken(endpoint, false)) return { error: `${peerName} endpoint contains characters unsafe for engine config.` };
    if (!validHostPort(endpoint)) return { error: `${peerName} endpoint must be host:port.` };
  }
  if (!keepalive.ok) return { error: `${peerName} keepalive must be an integer from 1 to 65535, or blank/0.` };
  if (!routeDestination) return { error: "Branch prefix is required." };
  if (!validCidr(routeDestination)) return { error: "Branch prefix must be a valid IPv4/IPv6 CIDR." };
  if (routeVia && !validConfigToken(routeVia, false)) return { error: "Route via contains characters unsafe for engine config." };
  if (!allowedIps.includes(routeDestination)) return { error: "Allowed IPs must include the routed branch prefix." };
  const existingIfaces = policy.vpn?.wireguardInterfaces || [];
  if (existingIfaces.some((iface) => iface?.name === ifaceName)) {
    return { error: `WireGuard interface ${ifaceName} already exists in the candidate.` };
  }
  if ((policy.staticRoutes || []).some((route) => route?.destination === routeDestination)) {
    return { error: `Static route ${routeDestination} already exists in the candidate.` };
  }
  const peer = { name: peerName, publicKey, endpoint, allowedIps, persistentKeepalive: keepalive.value || 0 };
  if (!peer.endpoint) delete peer.endpoint;
  const iface = { name: ifaceName, address: ifaceAddress, privateKeyFile, peers: [peer] };
  if (listenPort.value) iface.listenPort = listenPort.value;
  const route = { destination: routeDestination, interface: ifaceName };
  if (routeVia) route.via = routeVia;
  if (routeMetric) route.metric = routeMetric;
  const warnings = [
    "Firewall public endpoint and public key are not modeled; peer template keeps placeholders.",
  ];
  if (!endpoint) warnings.push("Peer endpoint is blank; use this only for roaming or NAT-discovered peers.");
  if (!listenPort) warnings.push("Listen port is blank; confirm the host-level WireGuard listener before commit.");
  return { iface, route, warnings };
}

function cleanConfigText(value = "", maxLength = 256) {
  const text = String(value || "").trim();
  if (!text || text.length > maxLength || /[\u0000-\u001f\u007f]/.test(text)) return "";
  return text;
}

function parsePositiveNumber(value) {
  const number = parseInt(value, 10);
  return Number.isFinite(number) && number > 0 ? number : 0;
}

function hasPrefixLength(value = "") {
  return /\/\d{1,3}$/.test(String(value || "").trim());
}

function isLikelyWireguardPublicKey(value = "") {
  return /^[A-Za-z0-9+/]{43}=$/.test(String(value || "").trim());
}

export function wireguardRuntimeByInterface(runtime = {}) {
  const out = new Map();
  for (const iface of runtime.interfaces || []) {
    if (iface?.name) out.set(iface.name, iface);
  }
  return out;
}

export function ipsecRuntimeByTunnel(runtime = {}) {
  const out = new Map();
  for (const tunnel of runtime.tunnels || []) {
    const name = runtimeString(tunnel, "name");
    if (name) out.set(name, tunnel);
  }
  return out;
}

export function bgpRuntimeRows(runtime = {}) {
  return runtime.bgpNeighbors || runtime.bgp_neighbors || [];
}

export function bgpRuntimeByPeer(runtime = {}) {
  const out = new Map();
  for (const peer of bgpRuntimeRows(runtime)) {
    const key = runtimeString(peer, "peer", "address");
    if (key) out.set(key, peer);
  }
  return out;
}

export function bgpRuntimeLabel(peer = null) {
  if (!peer) return "not observed";
  const parts = [runtimeString(peer, "state") || "observed"];
  const asn = runtimeNumber(peer, "remoteAsn", "remote_asn");
  const prefixes = runtimeNumber(peer, "prefixesReceived", "prefixes_received");
  if (asn) parts.push("AS" + asn);
  if (prefixes) parts.push(prefixes + " pfx");
  if (runtimeString(peer, "uptime")) parts.push(runtimeString(peer, "uptime"));
  return parts.join(" / ");
}

export function ospfRuntimeRows(runtime = {}) {
  return runtime.ospfNeighbors || runtime.ospf_neighbors || [];
}

export function ospfRuntimeSummary(runtime = {}) {
  const rows = ospfRuntimeRows(runtime);
  if (!rows.length) return "no OSPF neighbor evidence";
  const full = rows.filter((row) => runtimeString(row, "state").toLowerCase().startsWith("full")).length;
  return `${full}/${rows.length} full neighbor${rows.length === 1 ? "" : "s"}`;
}

export function ospfRuntimeLabel(neighbor = {}) {
  const parts = [runtimeString(neighbor, "neighborId", "neighbor_id") || "neighbor"];
  const state = runtimeString(neighbor, "state");
  if (state) parts.push(state);
  const iface = runtimeString(neighbor, "interface");
  if (iface) parts.push(iface);
  const dead = runtimeString(neighbor, "deadTime", "dead_time");
  if (dead) parts.push("dead " + dead);
  return parts.join(" ");
}

export function wireguardPeerRuntime(iface = {}, publicKey = "") {
  if (!iface || !publicKey) return null;
  return (iface.peers || []).find((peer) => peer.publicKey === publicKey) || null;
}

export function wireguardPeerRuntimeLabel(peer = null) {
  if (!peer) return "not observed";
  if (peer.latestHandshakeUnixSeconds) {
    const age = Number(peer.latestHandshakeAgeSeconds || 0);
    const ageLabel = age < 60 ? `${age}s` : age < 3600 ? `${Math.floor(age / 60)}m` : `${Math.floor(age / 3600)}h`;
    return `handshake ${ageLabel} ago`;
  }
  return peer.state || "waiting";
}

function runtimeStateClass(state) {
  const normalized = String(state || "").toLowerCase();
  if (normalized === "active" || normalized === "handshook" || normalized === "established" || normalized.startsWith("full")) return "ok";
  if (normalized === "waiting" || normalized === "simulation" || normalized === "configured-no-peers") return "warn";
  if (normalized === "degraded" || normalized === "unknown") return "bad";
  return "neutral";
}

function runtimeString(item = {}, ...keys) {
  for (const key of keys) {
    const value = item?.[key];
    if (value == null || value === "") continue;
    return String(value);
  }
  return "";
}

function runtimeNumber(item = {}, ...keys) {
  for (const key of keys) {
    const value = Number(item?.[key] || 0);
    if (Number.isFinite(value) && value > 0) return value;
  }
  return 0;
}
