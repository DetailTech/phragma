// ui.js — shared UI primitives: toasts, the right-side drawer, confirm
// dialogs, and small presentational helpers used across views.

import { h, mount, clear, icon, $ } from "./core.js";

// ---------- Toasts ----------
export function toast(title, body, kind = "") {
  const host = $("#toasts");
  let closeTimer = null;
  const close = () => {
    if (!el.isConnected || el.classList.contains("closing")) return;
    el.classList.add("closing");
    if (closeTimer) clearTimeout(closeTimer);
    setTimeout(() => el.remove(), motionDelay(180));
  };
  const el = h("div", { class: ["toast", kind].filter(Boolean).join(" ") },
    h("div", {},
      h("div", { class: "t-title" }, title),
      body ? h("div", { class: "t-body" }, body) : null),
    h("button", { class: "t-close", type: "button", title: "Dismiss notification", "aria-label": "Dismiss notification", onClick: close, html: icon("x", 16) }));
  host.appendChild(el);
  closeTimer = setTimeout(close, kind === "bad" ? 8000 : 4500);
  return el;
}

function motionDelay(ms) {
  return globalThis.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches ? 1 : ms;
}

// ---------- Drawer ----------
let drawerOnClose = null;
let drawerReturnFocus = null;
const DRAWER_TITLE_ID = "drawer-title";
const FOCUSABLE = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[tabindex]:not([tabindex='-1'])",
].join(",");

export function openDrawer({ title, subtitle, body, footer, width, onClose }) {
  const scrim = $("#drawer-scrim"), drawer = $("#drawer");
  const replacingOpenDrawer = !drawer.hidden;
  const activeBeforeOpen = document.activeElement;
  const previousReturnFocus = drawerReturnFocus;
  if (!drawer.hidden && drawerOnClose) {
    const previousOnClose = drawerOnClose;
    drawerOnClose = null;
    previousOnClose();
  }
  drawerReturnFocus = replacingOpenDrawer && drawer.contains?.(activeBeforeOpen)
    ? previousReturnFocus
    : activeBeforeOpen;
  drawerOnClose = typeof onClose === "function" ? onClose : null;
  if (width) drawer.style.width = width;
  drawer.setAttribute("role", "dialog");
  drawer.setAttribute("aria-modal", "true");
  drawer.setAttribute("aria-labelledby", DRAWER_TITLE_ID);
  drawer.setAttribute("tabindex", "-1");
  mount(drawer,
    h("div", { class: "drawer-head" },
      h("div", {},
        h("h2", { id: DRAWER_TITLE_ID }, title),
        subtitle ? h("div", { class: "note" }, subtitle) : null),
      h("button", { class: "icon-btn", type: "button", title: "Close dialog", "aria-label": "Close dialog", onClick: closeDrawer, html: icon("x", 20) })),
    h("div", { class: "drawer-body" }, body),
    footer ? h("div", { class: "drawer-foot" }, footer) : null);
  scrim.hidden = false; drawer.hidden = false;
  scrim.onclick = closeDrawer;
  document.addEventListener("keydown", drawerKeydown);
  focusFirstIn(drawer);
}
export function closeDrawer(opts = {}) {
  const invokeOnClose = opts.invokeOnClose !== false;
  $("#drawer-scrim").hidden = true;
  const d = $("#drawer"); d.hidden = true; clear(d); d.style.width = "";
  document.removeEventListener("keydown", drawerKeydown);
  const onClose = drawerOnClose;
  const returnFocus = drawerReturnFocus;
  drawerOnClose = null;
  drawerReturnFocus = null;
  if (invokeOnClose && onClose) onClose();
  if (returnFocus && document.contains(returnFocus) && typeof returnFocus.focus === "function") returnFocus.focus();
}
function drawerKeydown(e) {
  if (e.key === "Escape") { e.preventDefault(); closeDrawer(); return; }
  if (e.key === "Tab") handleFocusTrap(e, $("#drawer"));
}

export function focusableElements(root) {
  if (!root?.querySelectorAll) return [];
  return [...root.querySelectorAll(FOCUSABLE)].filter((el) =>
    !el.closest?.("[hidden]") && el.getAttribute?.("aria-hidden") !== "true");
}

export function handleFocusTrap(e, root, activeElement = document.activeElement) {
  if (e.key !== "Tab" || !root) return false;
  const items = focusableElements(root);
  if (!items.length) {
    e.preventDefault();
    root.focus?.();
    return true;
  }
  const first = items[0], last = items[items.length - 1];
  const focusEscaped = !root.contains?.(activeElement);
  if (e.shiftKey && (activeElement === first || focusEscaped)) {
    e.preventDefault();
    last.focus();
    return true;
  }
  if (!e.shiftKey && focusEscaped) {
    e.preventDefault();
    first.focus();
    return true;
  }
  if (!e.shiftKey && activeElement === last) {
    e.preventDefault();
    first.focus();
    return true;
  }
  return false;
}

function focusFirstIn(root) {
  const first = focusableElements(root)[0] || root;
  first?.focus?.();
}

const INTERACTIVE_ROW_TARGET = "a,button,input,select,textarea,[contenteditable='true'],[role='button'],[role='link']";

function isNestedInteractiveTarget(target, row) {
  const interactive = target?.closest?.(INTERACTIVE_ROW_TARGET);
  return Boolean(interactive && interactive !== row);
}

export function keyboardRowAttrs(onActivate, { className = "clickable", label = "" } = {}) {
  const activate = (e) => {
    if (isNestedInteractiveTarget(e.target, e.currentTarget)) return;
    onActivate(e);
  };
  return {
    class: className,
    role: "button",
    tabindex: "0",
    "aria-label": label || null,
    onclick: activate,
    onkeydown: (e) => {
      if (e.key !== "Enter" && e.key !== " ") return;
      if (isNestedInteractiveTarget(e.target, e.currentTarget)) return;
      e.preventDefault();
      onActivate(e);
    },
  };
}

// ---------- Confirm ----------
export function confirmDialog({ title, message, confirmLabel = "Confirm", danger = false, body }) {
  return new Promise((resolve) => {
    const done = (v) => { closeDrawer(); resolve(v); };
    openDrawer({
      title,
      width: "440px",
      body: h("div", {}, message ? h("p", {}, message) : null, body || null),
      footer: [
        h("button", { class: "btn ghost", type: "button", title: "Cancel confirmation", "aria-label": "Cancel confirmation", dataset: { confirmAction: "cancel" }, onClick: () => done(false) }, "Cancel"),
        h("button", { class: "btn " + (danger ? "danger" : "primary"), type: "button", title: confirmLabel, "aria-label": confirmLabel, onClick: () => done(true) }, confirmLabel),
      ],
    });
  });
}

// ---------- Phragma design-system primitives ----------
const TONE_ALIASES = {
  ok: "allow",
  allow: "allow",
  healthy: "allow",
  up: "allow",
  warn: "reject",
  warning: "reject",
  reject: "reject",
  degraded: "reject",
  bad: "drop",
  drop: "drop",
  threat: "drop",
  down: "drop",
  info: "info",
  blue: "info",
  violet: "change",
  change: "change",
  staged: "change",
  neutral: "neutral",
};

const RULE_ACTIONS = {
  ACTION_ALLOW: { label: "Allow", tone: "allow", action: "allow" },
  ALLOW: { label: "Allow", tone: "allow", action: "allow" },
  ACTION_REJECT: { label: "Reject", tone: "reject", action: "reject" },
  REJECT: { label: "Reject", tone: "reject", action: "reject" },
  ACTION_DENY: { label: "Drop", tone: "drop", action: "drop" },
  DENY: { label: "Drop", tone: "drop", action: "drop" },
  DROP: { label: "Drop", tone: "drop", action: "drop" },
};

function cssName(value, fallback = "neutral") {
  return String(value || fallback).trim().toLowerCase().replace(/[^a-z0-9_-]+/g, "-") || fallback;
}

function phrTone(tone = "neutral") {
  const key = cssName(tone);
  return TONE_ALIASES[key] || key;
}

function classes(...parts) {
  return parts.filter(Boolean).join(" ");
}

export function statusDot(tone = "neutral", label = "", opts = {}) {
  if (label && typeof label === "object" && !label.nodeType) {
    opts = label;
    label = opts.label || "";
  }
  const normalized = phrTone(tone);
  return h("span", {
    class: classes("phr-status-dot", "phr-status-dot--" + normalized, opts.pulse ? "is-pulsing" : "", opts.className),
    title: opts.title || label || null,
    "aria-label": label || null,
    "aria-hidden": label ? null : "true",
  });
}

export function badge(text, tone = "neutral", opts = {}) {
  if (tone && typeof tone === "object" && !tone.nodeType) {
    opts = tone;
    tone = opts.tone || "neutral";
  }
  const normalized = phrTone(tone);
  return h("span", {
    class: classes("phr-badge", "phr-badge--" + normalized, opts.className),
    title: opts.title || null,
    dataset: { tone: normalized },
  }, opts.dot ? statusDot(normalized, "", { className: "pdot", pulse: opts.pulse }) : null, text);
}

export function ruleAction(action, opts = {}) {
  const source = action && typeof action === "object" && !action.nodeType ? action : {};
  const rawAction = source.action || action || opts.action || source.label || opts.label || "neutral";
  const model = RULE_ACTIONS[String(rawAction).toUpperCase()] || {
    label: source.label || opts.label || String(rawAction),
    tone: source.cls || opts.cls || rawAction,
    action: cssName(rawAction),
  };
  const normalized = phrTone(opts.tone || source.tone || model.tone);
  return h("span", {
    class: classes("phr-rule-action", "phr-rule-action--" + normalized, opts.className),
    title: opts.title || null,
    dataset: { action: model.action || normalized },
  }, opts.dot ? statusDot(normalized, "", { className: "pdot", pulse: opts.pulse }) : null, opts.label || source.label || model.label);
}

export function tag(text, opts = {}) {
  if (typeof opts === "string") opts = { tone: opts };
  const normalized = phrTone(opts.tone || "neutral");
  return h("span", {
    class: classes("phr-tag", "phr-tag--" + normalized, opts.className),
    title: opts.title || null,
    dataset: { tone: normalized },
  }, text);
}

export function labeledCell(label, attrs, ...children) {
  if (attrs && (typeof attrs !== "object" || attrs.nodeType || Array.isArray(attrs))) {
    children.unshift(attrs);
    attrs = {};
  }
  return h("td", { ...(attrs || {}), "data-label": label }, ...children);
}

export function tableHeader(label, attrs = {}) {
  return h("th", attrs || {}, label);
}

export function responsiveTable(headers = [], rows = [], opts = {}) {
  const normalized = headers.map((header) => typeof header === "string" ? { label: header } : header);
  return h("table", { class: classes("responsive-evidence", opts.className) },
    h("thead", {}, h("tr", {}, normalized.map((header) => tableHeader(header.label || "", header.attrs || {})))),
    h("tbody", {}, rows));
}

export function metricCard({ label, value, foot, footer, iconName, iconHtml, spark, tone = "neutral", className } = {}) {
  const normalized = phrTone(tone);
  return h("div", { class: classes("card tight stat-tile phr-metric-card", "phr-metric-card--" + normalized, className) },
    iconName ? h("div", { class: "stat-ico", html: icon(iconName, 22) }) : iconHtml ? h("div", { class: "stat-ico", html: iconHtml }) : null,
    h("div", { class: "stat" },
      h("span", { class: "stat-label" }, label || ""),
      h("span", { class: "stat-value" }, value ?? "-"),
      foot || footer ? h("span", { class: "stat-foot" }, foot || footer) : null),
    spark ? h("div", { class: "spark", html: spark }) : null);
}

// ---------- Presentational helpers ----------
export function pill(text, cls = "neutral", withDot = false) {
  return badge(text, cls, { dot: withDot, className: "pill " + cssName(cls) });
}

export function emptyState(iconName, title, sub, action) {
  return h("div", { class: "empty" },
    h("div", { html: icon(iconName, 40) }),
    h("h3", {}, title),
    sub ? h("div", {}, sub) : null,
    action ? h("div", { class: "empty-actions" }, action) : null);
}

export function pageHead(title, sub, actions) {
  return h("div", { class: "page-head" },
    h("div", {},
      h("h1", {}, title),
      sub ? h("div", { class: "sub" }, sub) : null),
    h("div", { class: "spacer" }),
    actions ? h("div", { class: "flex wrap" }, actions) : null);
}

export function searchInput(placeholder, onInput, value = "") {
  const input = h("input", { class: "input", type: "search", placeholder, value, oninput: (e) => onInput(e.target.value) });
  return { el: h("div", { class: "search-input" }, h("span", { html: icon("search", 16) }), input), input };
}

export function tags(list, faint) {
  return (list && list.length ? list : faint ? ["any"] : []).map((t) =>
    tag(t, { className: "tag" }));
}

export function card(titleNode, ...children) {
  return h("div", { class: "card phr-card" },
    titleNode ? h("div", { class: "card-head" }, titleNode) : null, ...children);
}
