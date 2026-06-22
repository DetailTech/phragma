import { h, icon } from "./core.js";
import { toast } from "./ui.js";

const STORAGE_PREFIX = "openngfw.savedFilters.";
const MAX_FILTERS = 24;

export function savedFilterControls({
  scope = "filters",
  state = {},
  defaults = {},
  keys = Object.keys(defaults || {}),
  onApply = async () => {},
} = {}) {
  const select = h("select", { class: "input", dataset: { savedFilterScope: scope, savedFilterControl: "select" } });
  const name = h("input", { class: "input", type: "text", maxlength: "48", placeholder: "Name", dataset: { savedFilterScope: scope, savedFilterControl: "name" } });

  const refresh = (selected = "") => {
    const filters = asSavedFilterArray(loadSavedFilters(scope));
    select.replaceChildren(
      h("option", { value: "" }, filters.length ? "Saved filters" : "No saved filters"),
      ...filters.map((filter) => h("option", { value: filter.name }, filter.name)));
    select.value = filters.some((filter) => filter.name === selected) ? selected : "";
  };

  select.addEventListener("change", () => {
    name.value = select.value;
  });
  refresh();

  return [
    h("label", { class: "field saved-filter-field" }, h("span", {}, "Saved filter"), select),
    h("label", { class: "field saved-filter-field" }, h("span", {}, "Filter name"), name),
    h("button", { class: "btn ghost", type: "button", title: "Save the current filters in this browser", "aria-label": "Save current filters in this browser", dataset: { savedFilterScope: scope, savedFilterAction: "save", sharedControl: "saved-filter-save" }, onclick: () => {
      const entry = saveSavedFilter(scope, name.value || select.value, state, { defaults, keys });
      if (!entry) return toast("Name required", "Enter a short name for this filter.", "warn");
      refresh(entry.name);
      toast("Filter saved", `${entry.name} is available on this workstation.`, "ok");
    } }, h("span", { html: icon("check", 16) }), "Save"),
    h("button", { class: "btn ghost", type: "button", title: "Apply the selected saved filter", "aria-label": "Apply selected saved filter", dataset: { savedFilterScope: scope, savedFilterAction: "apply", sharedControl: "saved-filter-apply" }, onclick: async () => {
      const entry = findSavedFilter(scope, select.value || name.value);
      if (!entry) return toast("Saved filter not found", "Choose a saved filter to apply.", "warn");
      await onApply({ ...defaults, ...entry.state });
    } }, h("span", { html: icon("filter", 16) }), "Apply saved"),
    h("button", { class: "btn ghost", type: "button", title: "Delete the selected saved filter from this browser", "aria-label": "Delete selected saved filter from this browser", dataset: { savedFilterScope: scope, savedFilterAction: "delete", sharedControl: "saved-filter-delete" }, onclick: () => {
      const removed = deleteSavedFilter(scope, select.value || name.value);
      if (!removed) return toast("Saved filter not found", "Choose a saved filter to delete.", "warn");
      name.value = "";
      refresh();
      toast("Filter deleted", `${removed.name} was removed from this workstation.`, "ok");
    } }, h("span", { html: icon("trash", 16) }), "Delete"),
  ];
}

export function loadSavedFilters(scope, storage = browserStorage()) {
  try {
    const parsed = JSON.parse(storage?.getItem(storageKey(scope)) || "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map(normalizeEntry)
      .filter(Boolean)
      .sort((a, b) => a.name.localeCompare(b.name));
  } catch {
    return [];
  }
}

export function findSavedFilter(scope, name, storage = browserStorage()) {
  const wanted = normalizeName(name);
  if (!wanted) return null;
  return loadSavedFilters(scope, storage).find((entry) => entry.name === wanted) || null;
}

export function saveSavedFilter(scope, rawName, state = {}, { defaults = {}, keys = Object.keys(defaults || {}), storage = browserStorage() } = {}) {
  const name = normalizeName(rawName);
  if (!name) return null;
  const entry = {
    name,
    savedAt: new Date().toISOString(),
    state: filterPresetState(state, defaults, keys),
  };
  const others = asSavedFilterArray(loadSavedFilters(scope, storage)).filter((item) => item.name !== name);
  const next = [entry, ...others].slice(0, MAX_FILTERS).sort((a, b) => a.name.localeCompare(b.name));
  try {
    storage?.setItem(storageKey(scope), JSON.stringify(next));
  } catch {
    return null;
  }
  return entry;
}

export function deleteSavedFilter(scope, rawName, storage = browserStorage()) {
  const name = normalizeName(rawName);
  if (!name) return null;
  const existing = asSavedFilterArray(loadSavedFilters(scope, storage));
  const removed = existing.find((entry) => entry.name === name) || null;
  if (!removed) return null;
  try {
    storage?.setItem(storageKey(scope), JSON.stringify(existing.filter((entry) => entry.name !== name)));
  } catch {
    return null;
  }
  return removed;
}

function asSavedFilterArray(value) {
  return Array.isArray(value) ? value : [];
}

export function filterPresetState(state = {}, defaults = {}, keys = Object.keys(defaults || {})) {
  const out = {};
  for (const key of keys) {
    const value = state[key];
    if (value == null) continue;
    if (sameValue(value, defaults[key])) continue;
    if (value === "" || value === false) continue;
    out[key] = value;
  }
  return out;
}

function normalizeEntry(entry = {}) {
  const name = normalizeName(entry.name);
  if (!name || typeof entry.state !== "object" || Array.isArray(entry.state)) return null;
  return {
    name,
    savedAt: String(entry.savedAt || ""),
    state: cleanState(entry.state),
  };
}

function cleanState(state = {}) {
  const out = {};
  for (const [key, value] of Object.entries(state).slice(0, 80)) {
    if (!/^[a-zA-Z][a-zA-Z0-9_-]{0,48}$/.test(key)) continue;
    if (value == null || typeof value === "object") continue;
    out[key] = typeof value === "boolean" ? value : String(value).slice(0, 256);
  }
  return out;
}

function normalizeName(name) {
  return String(name || "").trim().replace(/\s+/g, " ").slice(0, 48);
}

function sameValue(a, b) {
  return String(a ?? "") === String(b ?? "");
}

function storageKey(scope) {
  return STORAGE_PREFIX + String(scope || "filters").replace(/[^a-zA-Z0-9_.:-]+/g, "-");
}

function browserStorage() {
  try {
    return globalThis.localStorage || null;
  } catch {
    return null;
  }
}
