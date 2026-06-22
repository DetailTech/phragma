import { buildHash } from "./query_state.js";
import { proxyRouteState } from "./proxy_model.js";

export const PROXY_ROUTE_DEFAULTS = Object.freeze({ tab: "services", service: "", waf: "", drawer: "" });
export const PROXY_ROUTE_KEYS = Object.freeze(["tab", "service", "waf", "drawer"]);

export function normalizeProxyRoute(query = {}) {
  return { ...PROXY_ROUTE_DEFAULTS, ...proxyRouteState(query) };
}

export function proxyHash(state = {}, path = "/proxy") {
  return buildHash(path, { ...PROXY_ROUTE_DEFAULTS, ...state }, PROXY_ROUTE_DEFAULTS, PROXY_ROUTE_KEYS);
}
