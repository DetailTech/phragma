export function readQueryState(query = {}, defaults = {}, keys = Object.keys(defaults)) {
  const source = query instanceof URLSearchParams ? Object.fromEntries(query.entries()) : (query || {});
  const out = { ...defaults };
  for (const key of keys) {
    if (!(key in source)) continue;
    out[key] = coerceQueryValue(source[key], defaults[key]);
  }
  return out;
}

export function buildHash(path, state = {}, defaults = {}, keys = Object.keys(state)) {
  const params = new URLSearchParams();
  for (const key of keys) {
    const value = state[key];
    if (isDefaultValue(value, defaults[key])) continue;
    const serialized = serializeQueryValue(value);
    if (serialized === "") continue;
    params.set(key, serialized);
  }
  const query = params.toString();
  return "#" + (path || "/") + (query ? "?" + query : "");
}

export function writeQueryState(path, state = {}, defaults = {}, keys = Object.keys(state), opts = {}) {
  if (typeof location === "undefined") return "";
  const next = buildHash(path, state, defaults, keys);
  if (location.hash === next) return next;
  if (opts.replace !== false && typeof history !== "undefined" && history.replaceState) {
    history.replaceState(null, "", next);
  } else {
    location.hash = next;
  }
  return next;
}

function coerceQueryValue(value, defaultValue) {
  if (typeof defaultValue === "number") {
    const n = Number(value);
    return Number.isFinite(n) ? n : defaultValue;
  }
  if (typeof defaultValue === "boolean") {
    return value === "1" || value === "true";
  }
  return String(value ?? "");
}

function isDefaultValue(value, defaultValue) {
  if (value == null) return true;
  if (typeof value === "string" && value === "") return true;
  return String(value) === String(defaultValue ?? "");
}

function serializeQueryValue(value) {
  if (typeof value === "boolean") return value ? "1" : "0";
  return String(value ?? "").trim();
}
