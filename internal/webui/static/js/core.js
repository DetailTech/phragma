// core.js — tiny dependency-free runtime: hyperscript DOM helper, a
// reactive store, a hash router, and inline SVG icons. No framework.

/** h(tag, attrs?, ...children) -> HTMLElement.
 *  attrs: class, html (innerHTML), style {obj}, on* handlers, data-* via
 *  dataset:{}, everything else setAttribute. Children: nodes, strings,
 *  arrays; null/false/undefined skipped. */
export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs && (typeof attrs !== "object" || attrs.nodeType || Array.isArray(attrs))) {
    children.unshift(attrs); attrs = null;
  }
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "html") el.innerHTML = v;
      else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
      else if (k === "dataset") Object.assign(el.dataset, v);
      else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (v === true) el.setAttribute(k, "");
      else el.setAttribute(k, v);
    }
  }
  append(el, children);
  return el;
}

function append(el, kids) {
  for (const c of kids) {
    if (c == null || c === false || c === true) continue;
    if (Array.isArray(c)) append(el, c);
    else el.appendChild(c.nodeType ? c : document.createTextNode(String(c)));
  }
}

export function frag(...children) { const f = document.createDocumentFragment(); append(f, children); return f; }
export function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }
export function mount(node, ...children) { clear(node); append(node, children); return node; }
export const $ = (sel, root = document) => root.querySelector(sel);

/** Minimal reactive store. */
export class Store {
  constructor(state = {}) { this.state = state; this._subs = new Set(); }
  get(k) { return this.state[k]; }
  set(patch) { Object.assign(this.state, patch); this._subs.forEach((fn) => fn(this.state)); }
  subscribe(fn) { this._subs.add(fn); return () => this._subs.delete(fn); }
}

/** Hash router. Routes registered as path -> async render(ctx). Path may
 *  contain :params. Hash form: #/path/seg?k=v. */
export class Router {
  constructor() { this.routes = []; this.onNavigate = null; }
  add(pattern, handler) {
    const keys = [];
    const rx = new RegExp("^" + pattern.replace(/:[^/]+/g, (m) => { keys.push(m.slice(1)); return "([^/]+)"; }) + "$");
    this.routes.push({ rx, keys, handler, pattern });
    return this;
  }
  current() {
    const raw = location.hash.slice(1) || "/";
    const [path, qs] = raw.split("?");
    const query = Object.fromEntries(new URLSearchParams(qs || ""));
    return { path, query };
  }
  resolve() {
    const { path, query } = this.current();
    for (const r of this.routes) {
      const m = path.match(r.rx);
      if (m) {
        const params = {};
        r.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1])));
        return { route: r, params, query, path };
      }
    }
    return null;
  }
  start(onNavigate) { this.onNavigate = onNavigate; addEventListener("hashchange", () => this._go()); this._go(); }
  _go() { if (this.onNavigate) this.onNavigate(this.resolve()); }
}

export function navigate(hash) {
  if (location.hash === hash) location.hash = hash; // force when same
  else location.hash = hash;
}

// ---- Icons (24x24 stroke, currentColor) ----
const ICONS = {
  dashboard: '<path d="M3 13h8V3H3zM13 21h8V3h-8zM3 21h8v-6H3z"/>',
  rules: '<path d="M4 6h16M4 12h16M4 18h10"/><circle cx="18" cy="18" r="2.4"/>',
  objects: '<path d="M12 3 3 7.5v9L12 21l9-4.5v-9z"/><path d="M3 7.5 12 12l9-4.5M12 12v9"/>',
  nat: '<path d="M4 7h9a4 4 0 0 1 4 4v7"/><path d="m14 15 3 3 3-3"/><path d="M20 7h-9a4 4 0 0 0-4 4v7"/><path d="m10 15-3 3-3-3"/>',
  threats: '<path d="M12 3 4 6v5c0 5 3.5 8.5 8 10 4.5-1.5 8-5 8-10V6z"/><path d="M12 9v4M12 16v.5"/>',
  traffic: '<path d="M4 17l5-5 4 4 7-8"/><path d="M16 8h4v4"/>',
  intel: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 2.5 15.4 0 18M12 3C9.5 5.6 9.5 18.4 12 21"/>',
  vpn: '<path d="M7 11V8a5 5 0 0 1 10 0v3"/><rect x="5" y="11" width="14" height="9" rx="2"/>',
  changes: '<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 4v4h4"/><path d="M12 8v4l3 2"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1.4l2-1.5-2-3.5-2.4 1a7 7 0 0 0-2.4-1.4L13.7 2h-3.4l-.4 2.7A7 7 0 0 0 7.5 6L5.1 5l-2 3.5 2 1.5a7 7 0 0 0 0 2.8l-2 1.5 2 3.5 2.4-1a7 7 0 0 0 2.4 1.4l.4 2.7h3.4l.4-2.7a7 7 0 0 0 2.4-1.4l2.4 1 2-3.5-2-1.5A7 7 0 0 0 19 12z"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3-3"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-3-6.7"/><path d="M21 4v5h-5"/>',
  trash: '<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/>',
  edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="m14 6 4 4"/>',
  block: '<circle cx="12" cy="12" r="9"/><path d="m6 6 12 12"/>',
  arrowRight: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  upload: '<path d="M12 16V4M7 9l5-5 5 5"/><path d="M5 20h14"/>',
  download: '<path d="M12 4v12M7 11l5 5 5-5"/><path d="M5 20h14"/>',
  diff: '<path d="M12 3v18"/><path d="M5 8h4M7 6v4"/><path d="M15 16h4"/>',
  rollback: '<path d="M9 14 4 9l5-5"/><path d="M4 9h11a5 5 0 0 1 0 10h-3"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 2.5 15.4 0 18M12 3C9.5 5.6 9.5 18.4 12 21"/>',
  shield: '<path d="M12 3 4 6v5c0 5 3.5 8.5 8 10 4.5-1.5 8-5 8-10V6z"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  inbox: '<path d="M3 13h5l2 3h4l2-3h5"/><path d="M5 5h14l2 8v6H3v-6z"/>',
  key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m11 12 9-9 1 4-3 1 1 3-4 1z"/>',
  filter: '<path d="M3 5h18l-7 8v6l-4-2v-4z"/>',
  terminal: '<path d="m4 7 5 5-5 5"/><path d="M11 17h9"/>',
};
export function icon(name, size = 18) {
  return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">${ICONS[name] || ""}</svg>`;
}
export function iconEl(name, size = 18) { const s = document.createElement("span"); s.style.display = "inline-flex"; s.innerHTML = icon(name, size); return s.firstChild; }
