import { buildHash, readQueryState, writeQueryState } from "./query_state.js";

export const OBJECT_TABS = Object.freeze(["addresses", "services", "applications", "securityProfiles", "trafficControls", "zones"]);
export const OBJECT_ROUTE_DEFAULTS = Object.freeze({ tab: "addresses", drawer: "", object: "" });
export const OBJECT_ROUTE_KEYS = Object.freeze(["tab", "drawer", "object"]);

const OBJECT_TAB_SET = new Set(OBJECT_TABS);
const OBJECT_DRAWER_SET = new Set(["references", "impact"]);

export function normalizeObjectTab(value = "") {
  const tab = String(value || "").trim();
  return OBJECT_TAB_SET.has(tab) ? tab : OBJECT_ROUTE_DEFAULTS.tab;
}

export function normalizeObjectName(value = "") {
  return String(value || "").trim();
}

export function normalizeObjectRoute(query = {}) {
  const state = readQueryState(query, OBJECT_ROUTE_DEFAULTS, OBJECT_ROUTE_KEYS);
  const drawer = OBJECT_DRAWER_SET.has(state.drawer) ? state.drawer : "";
  const object = drawer ? normalizeObjectName(state.object) : "";
  return {
    tab: normalizeObjectTab(state.tab),
    drawer: object ? drawer : "",
    object,
  };
}

export function objectTabForPolicyKind(kind = "") {
  const normalized = String(kind || "").trim().toLowerCase();
  if (normalized === "address" || normalized === "addresses") return "addresses";
  if (normalized === "service" || normalized === "services") return "services";
  if (normalized === "application" || normalized === "applications" || normalized === "app-id") return "applications";
  if (normalized === "securityprofile" || normalized === "securityprofiles" || normalized === "security-profile" || normalized === "security-profiles") return "securityProfiles";
  if (normalized === "trafficcontrol" || normalized === "trafficcontrols" || normalized === "traffic-control" || normalized === "traffic-controls" || normalized === "qos" || normalized === "qosprofile" || normalized === "qos-profile" || normalized === "zoneprotection" || normalized === "zone-protection" || normalized === "zoneprotectionprofile" || normalized === "zone-protection-profile") return "trafficControls";
  if (normalized === "zone" || normalized === "zones") return "zones";
  return OBJECT_ROUTE_DEFAULTS.tab;
}

export function objectTabHash(tab = "", path = "/objects") {
  return buildHash(path, {
    tab: normalizeObjectTab(tab),
    drawer: "",
    object: "",
  }, OBJECT_ROUTE_DEFAULTS, OBJECT_ROUTE_KEYS);
}

export function objectKindHash(kind = "", path = "/objects") {
  return objectTabHash(objectTabForPolicyKind(kind), path);
}

export function objectReferenceHash(kind = "", name = "", path = "/objects") {
  return objectDrawerHash(kind, name, "references", path);
}

export function objectImpactHash(kind = "", name = "", path = "/objects") {
  return objectDrawerHash(kind, name, "impact", path);
}

function objectDrawerHash(kind = "", name = "", drawer = "", path = "/objects") {
  const object = normalizeObjectName(name);
  if (!object) return objectKindHash(kind, path);
  const normalizedDrawer = OBJECT_DRAWER_SET.has(drawer) ? drawer : "references";
  return buildHash(path, {
    tab: objectTabForPolicyKind(kind),
    drawer: normalizedDrawer,
    object,
  }, OBJECT_ROUTE_DEFAULTS, OBJECT_ROUTE_KEYS);
}

export function writeObjectRoute(tab = "", path = "/objects") {
  return writeQueryState(path, {
    tab: normalizeObjectTab(tab),
    drawer: "",
    object: "",
  }, OBJECT_ROUTE_DEFAULTS, OBJECT_ROUTE_KEYS);
}

export function writeObjectReferenceRoute(kind = "", name = "", path = "/objects") {
  return writeObjectDrawerRoute(kind, name, "references", path);
}

export function writeObjectImpactRoute(kind = "", name = "", path = "/objects") {
  return writeObjectDrawerRoute(kind, name, "impact", path);
}

function writeObjectDrawerRoute(kind = "", name = "", drawer = "", path = "/objects") {
  const object = normalizeObjectName(name);
  if (!object) return writeObjectRoute(objectTabForPolicyKind(kind), path);
  const normalizedDrawer = OBJECT_DRAWER_SET.has(drawer) ? drawer : "references";
  return writeQueryState(path, {
    tab: objectTabForPolicyKind(kind),
    drawer: normalizedDrawer,
    object,
  }, OBJECT_ROUTE_DEFAULTS, OBJECT_ROUTE_KEYS);
}
