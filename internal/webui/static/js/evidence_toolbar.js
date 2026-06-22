import { h, icon } from "./core.js";
import { toast } from "./ui.js";
import { redactSensitive } from "./support_bundle.js";

export const EVIDENCE_TABLE_SCHEMA = "phragma.evidence.table.v1";

export function evidenceToolbar({
  surface = "evidence",
  title = "Evidence table",
  summary = "",
  request = {},
  rows = [],
  columns = [],
  route = currentRoute(),
  apiPath = "",
  cliCommand = "",
  cliLabel = "Copy CLI",
  jsonLabel = "Export JSON",
  csvLabel = "Export CSV",
} = {}) {
  const currentRows = () => typeof rows === "function" ? rows() : rows;
  const currentRouteValue = () => typeof route === "function" ? route() : (route || currentRoute());
  const currentRequest = () => typeof request === "function" ? request() : request;
  const currentCliCommand = () => typeof cliCommand === "function" ? cliCommand() : cliCommand;
  return h("div", { class: "evidence-toolbar", "aria-label": `${title} evidence actions`, "data-evidence-surface": surface },
    h("div", { class: "evidence-summary" },
      h("strong", {}, title),
      summary ? h("span", {}, summary) : null),
    h("div", { class: "evidence-actions" },
      h("button", { class: "btn sm ghost", type: "button", title: "Copy a link to this filtered view", "aria-label": `Copy ${title} filtered view link`, "data-evidence-action": "copy-link", onclick: () => copyCurrentView(currentRouteValue()) }, h("span", { html: icon("copy", 15) }), "Copy link"),
      h("button", { class: "btn sm ghost", type: "button", title: "Copy the REST request used for this evidence set", "aria-label": `Copy ${title} REST request`, "data-evidence-action": "copy-api", onclick: () => copyAPIRequest(apiPath, currentRequest()) }, h("span", { html: icon("terminal", 15) }), "Copy API"),
      currentCliCommand() ? h("button", { class: "btn sm ghost", type: "button", title: "Copy the ngfwctl command for this evidence set", "aria-label": `Copy ${title} ngfwctl command`, "data-evidence-action": "copy-cli", onclick: () => copyCLICommand(currentCliCommand()) }, h("span", { html: icon("terminal", 15) }), cliLabel) : null,
      h("button", {
        class: "btn sm ghost",
        type: "button",
        title: "Download this evidence set as JSON",
        "aria-label": `Download ${title} as JSON`,
        "data-evidence-action": "export-json",
        onclick: () => downloadText(evidenceFilename(surface, "json"), evidencePayloadJson(evidenceTablePayload({ surface, title, summary, request: currentRequest(), rows: currentRows(), route: currentRouteValue() })), "application/json"),
      }, h("span", { html: icon("download", 15) }), jsonLabel),
      columns.length ? h("button", { class: "btn sm ghost", type: "button", title: "Download visible evidence fields as CSV", "aria-label": `Download ${title} visible fields as CSV`, "data-evidence-action": "export-csv", onclick: () => downloadText(evidenceFilename(surface, "csv"), evidenceRowsCsv(currentRows(), columns), "text/csv") }, h("span", { html: icon("download", 15) }), csvLabel) : null));
}

export function evidenceTablePayload({
  surface = "evidence",
  title = "Evidence table",
  summary = "",
  request = {},
  rows = [],
  route = currentRoute(),
  collectedAt = new Date().toISOString(),
} = {}) {
  const boundedRows = Array.isArray(rows) ? rows.slice(0, 1000) : [];
  return redactEvidence(cleanObject({
    schemaVersion: EVIDENCE_TABLE_SCHEMA,
    surface: safeToken(surface) || "evidence",
    title,
    collectedAt,
    generatedBy: "openngfw-webui",
    source: {
      interface: "webui",
      route: route || "",
    },
    request,
    result: {
      rowCount: Array.isArray(rows) ? rows.length : 0,
      includedRows: boundedRows.length,
    },
    rows: boundedRows,
  }));
}

export function evidencePayloadJson(payload) {
  return JSON.stringify(cleanObject(payload || {}), null, 2) + "\n";
}

export function evidenceRowsCsv(rows = [], columns = []) {
  const cols = normalizeColumns(columns);
  const safeRows = redactEvidence(Array.isArray(rows) ? rows : []);
  const header = cols.map((c) => csvCell(c.label || c.key)).join(",");
  const body = safeRows.map((row) => cols.map((col) => csvCell(columnValue(row, col))).join(","));
  return [header, ...body].join("\n") + "\n";
}

export function apiRequestText(path = "", request = {}) {
  const cleanPath = String(path || "").trim() || "/";
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(request || {})) {
    if (value == null || value === "") continue;
    q.set(key, String(value));
  }
  const qs = q.toString();
  return `GET ${cleanPath}${qs ? "?" + qs : ""}\n`;
}

export function cliRequestText(command = "") {
  const text = String(command || "").trim();
  return text ? `${text}\n` : "";
}

export function evidenceFilename(surface = "evidence", ext = "json", now = new Date()) {
  const stamp = now.toISOString().replace(/[:.]/g, "-");
  return `phragma-${safeSlug(surface)}-evidence-${stamp}.${safeSlug(ext) || "json"}`;
}

async function copyCurrentView(route) {
  const href = absoluteRoute(route || currentRoute());
  if (await copyText(href)) toast("Link copied", "Filtered evidence view copied to clipboard.", "ok");
  else toast("Copy failed", "Select the browser address and copy it manually.", "warn");
}

async function copyAPIRequest(path, request) {
  const text = apiRequestText(path, request);
  if (await copyText(text)) toast("API request copied", "REST request copied to clipboard.", "ok");
  else toast("Copy failed", "Export JSON to inspect the request details.", "warn");
}

async function copyCLICommand(command) {
  const text = cliRequestText(command);
  if (await copyText(text)) toast("CLI command copied", "ngfwctl command copied to clipboard.", "ok");
  else toast("Copy failed", "Copy the visible API/CLI context command manually.", "warn");
}

async function copyText(text) {
  try {
    if (globalThis.navigator?.clipboard?.writeText) {
      await globalThis.navigator.clipboard.writeText(text);
      return true;
    }
  } catch {}
  try {
    if (typeof document === "undefined") return false;
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand?.("copy");
    area.remove();
    return Boolean(ok);
  } catch {
    return false;
  }
}

function downloadText(filename, text, type) {
  if (typeof document === "undefined" || typeof URL === "undefined") return;
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  toast("Evidence exported", `Downloaded ${filename}.`, "ok");
}

function currentRoute() {
  if (typeof location === "undefined") return "";
  return location.hash || "#/";
}

function absoluteRoute(route) {
  const raw = String(route || "");
  if (typeof location === "undefined") return raw;
  if (raw.startsWith("http://") || raw.startsWith("https://")) return raw;
  const path = raw.startsWith("#") ? raw : "#" + raw;
  return `${location.origin}${location.pathname}${path}`;
}

function normalizeColumns(columns = []) {
  return columns.map((col) => {
    if (typeof col === "string") return { key: col, label: col };
    return { key: col.key || "", label: col.label || col.key || "", value: col.value };
  }).filter((col) => col.key || col.value);
}

function columnValue(row, col) {
  if (typeof col.value === "function") return col.value(row);
  return dottedValue(row, col.key);
}

function redactEvidence(value) {
  return redactSensitive(value);
}

function dottedValue(row, path) {
  let cur = row;
  for (const part of String(path || "").split(".").filter(Boolean)) {
    if (cur == null) return "";
    cur = cur[part];
  }
  return cur ?? "";
}

function csvCell(value) {
  if (value == null) value = "";
  if (typeof value === "object") value = JSON.stringify(cleanObject(value));
  const text = String(value);
  if (/[",\n\r]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

function cleanObject(value, depth = 0) {
  if (value == null) return value;
  if (typeof value === "string") return value.length > 1600 ? value.slice(0, 1597) + "..." : value;
  if (typeof value === "number") return Number.isFinite(value) ? value : 0;
  if (typeof value === "boolean") return value;
  if (Array.isArray(value)) {
    if (depth >= 6) return [];
    return value.slice(0, 1000).map((item) => cleanObject(item, depth + 1));
  }
  if (typeof value !== "object") return String(value);
  if (depth >= 6) return {};
  const out = {};
  for (const key of Object.keys(value).slice(0, 80)) out[key] = cleanObject(value[key], depth + 1);
  return out;
}

function safeToken(value) {
  return String(value || "").trim().toLowerCase().replace(/[^a-z0-9_.:-]+/g, "-").replace(/^-+|-+$/g, "");
}

function safeSlug(value) {
  return safeToken(value).replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "") || "evidence";
}
