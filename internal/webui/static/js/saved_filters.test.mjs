import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  deleteSavedFilter,
  filterPresetState,
  findSavedFilter,
  loadSavedFilters,
  saveSavedFilter,
} from "./saved_filters.js";

const savedFiltersSource = readFileSync("internal/webui/static/js/saved_filters.js", "utf8");

assert.match(savedFiltersSource, /type: "button", title: "Save the current filters in this browser", "aria-label": "Save current filters in this browser", dataset: \{ savedFilterScope: scope, savedFilterAction: "save", sharedControl: "saved-filter-save" \}/);
assert.match(savedFiltersSource, /type: "button", title: "Apply the selected saved filter", "aria-label": "Apply selected saved filter", dataset: \{ savedFilterScope: scope, savedFilterAction: "apply", sharedControl: "saved-filter-apply" \}/);
assert.match(savedFiltersSource, /type: "button", title: "Delete the selected saved filter from this browser", "aria-label": "Delete selected saved filter from this browser", dataset: \{ savedFilterScope: scope, savedFilterAction: "delete", sharedControl: "saved-filter-delete" \}/);

function memoryStorage(seed = {}) {
  const data = new Map(Object.entries(seed));
  return {
    getItem(key) { return data.has(key) ? data.get(key) : null; },
    setItem(key, value) { data.set(key, String(value)); },
    removeItem(key) { data.delete(key); },
  };
}

{
  const defaults = { q: "", ip: "", protocol: "", limit: "500", alert: "" };
  assert.deepEqual(filterPresetState({
    q: "web shell",
    ip: "",
    protocol: "TCP",
    limit: "500",
    alert: "flow:stale",
  }, defaults, ["q", "ip", "protocol", "limit"]), {
    q: "web shell",
    protocol: "TCP",
  });
}

{
  const storage = memoryStorage();
  const defaults = { q: "", ip: "", protocol: "", limit: "500" };
  const entry = saveSavedFilter("traffic", "  Web Allow  ", {
    q: "ssl",
    ip: "10.0.1.20",
    protocol: "TCP",
    limit: "500",
  }, { defaults, keys: ["q", "ip", "protocol", "limit"], storage });

  assert.equal(entry.name, "Web Allow");
  assert.deepEqual(findSavedFilter("traffic", "Web Allow", storage).state, {
    q: "ssl",
    ip: "10.0.1.20",
    protocol: "TCP",
  });

  saveSavedFilter("traffic", "Web Allow", { q: "dns", protocol: "UDP", limit: "1000" }, {
    defaults,
    keys: ["q", "ip", "protocol", "limit"],
    storage,
  });
  assert.deepEqual(loadSavedFilters("traffic", storage).map((item) => item.name), ["Web Allow"]);
  assert.deepEqual(findSavedFilter("traffic", "Web Allow", storage).state, {
    q: "dns",
    protocol: "UDP",
    limit: "1000",
  });

  const removed = deleteSavedFilter("traffic", "Web Allow", storage);
  assert.equal(removed.name, "Web Allow");
  assert.deepEqual(loadSavedFilters("traffic", storage), []);
}

{
  const storage = memoryStorage({ "openngfw.savedFilters.threats": "{bad json" });
  assert.deepEqual(loadSavedFilters("threats", storage), []);
  assert.equal(saveSavedFilter("threats", "", {}, { storage }), null);
}
