import { buildHash, readQueryState } from "./query_state.js";

export const SETTINGS_ROUTE_DEFAULTS = Object.freeze({ panel: "" });
export const SETTINGS_ROUTE_KEYS = Object.freeze(["panel"]);

export const SETTINGS_PANELS = Object.freeze([
  Object.freeze({
    id: "telemetry",
    label: "Telemetry",
    title: "Telemetry readiness",
    detail: "Vector, ClickHouse, JSON export",
  }),
  Object.freeze({
    id: "network",
    label: "Network",
    title: "Dataplane network",
    detail: "MTU, MSS, offloads, flowtable",
  }),
  Object.freeze({
    id: "host-input",
    label: "Host input",
    title: "Management-plane input",
    detail: "Default action and allow rules",
  }),
  Object.freeze({
    id: "access",
    label: "Access",
    title: "API access",
    detail: "SSO, tokens, roles, audit",
  }),
]);

const SETTINGS_PANEL_IDS = new Set(SETTINGS_PANELS.map((panel) => panel.id));

export function settingsPanelById(id) {
  return SETTINGS_PANELS.find((panel) => panel.id === id) || null;
}

export function normalizeSettingsPanel(value = "") {
  const panel = String(value || "").trim();
  return SETTINGS_PANEL_IDS.has(panel) ? panel : "";
}

export function normalizeSettingsState(next = {}) {
  const state = readQueryState(next, SETTINGS_ROUTE_DEFAULTS, SETTINGS_ROUTE_KEYS);
  const panel = normalizeSettingsPanel(state.panel);
  return { panel };
}

export const normalizeSettingsRoute = normalizeSettingsState;

export function settingsPanelHash(panelId = "", path = "/settings") {
  return buildHash(path, normalizeSettingsState({ panel: panelId }), SETTINGS_ROUTE_DEFAULTS, SETTINGS_ROUTE_KEYS);
}

export function settingsPanelURL(panelId = "", path = "/settings", locationLike = globalThis.location) {
  const hash = settingsPanelHash(panelId, path);
  if (!locationLike?.href) return hash;
  try {
    const url = new URL(locationLike.href);
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = hash;
    return url.toString();
  } catch {
    return hash;
  }
}

export function settingsPanelShareURL(panelId = "", locationLike = globalThis.location, path = "/settings") {
  return settingsPanelURL(panelId, path, locationLike);
}

export function settingsPanelLinkModel(activePanel = "", path = "/settings") {
  const route = normalizeSettingsState({ panel: activePanel });
  return SETTINGS_PANELS.map((panel) => ({
    ...panel,
    active: panel.id === route.panel,
    href: settingsPanelHash(panel.id, path),
  }));
}

export function focusSettingsPanel(root, panelId, opts = {}) {
  const panel = normalizeSettingsPanel(panelId);
  if (!panel || !root?.querySelectorAll) return false;
  const sections = Array.from(root.querySelectorAll("[data-settings-panel]") || []);
  const target = sections.find((section) => section.dataset?.settingsPanel === panel);
  if (!target) return false;
  const scrollOptions = {
    block: opts.block || "start",
    behavior: opts.behavior || "smooth",
  };
  try {
    target.focus?.({ preventScroll: true });
  } catch {
    target.focus?.();
  }
  target.scrollIntoView?.(scrollOptions);
  return true;
}

export function scheduleSettingsPanelFocus(root, panelId, scheduler = defaultFocusScheduler) {
  const panel = normalizeSettingsPanel(panelId);
  if (!panel) return false;
  scheduler(() => focusSettingsPanel(root, panel));
  return true;
}

function defaultFocusScheduler(fn) {
  if (typeof requestAnimationFrame === "function") return requestAnimationFrame(fn);
  return setTimeout(fn, 0);
}
