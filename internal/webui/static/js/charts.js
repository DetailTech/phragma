// charts.js — dependency-free chart helpers. SVG helpers return markup for
// controlled numeric paths; hbars returns DOM nodes because labels and values
// can be telemetry or policy-derived data. Colors are read from CSS custom
// properties so charts follow the active theme.

function cssVar(name, fallback) {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

let _uid = 0;
const uid = () => "g" + (++_uid);

/** Area / sparkline. points: number[]. Smoothed filled area. */
export function area(points, opts = {}) {
  const w = opts.width || 600, h = opts.height || 160, pad = opts.pad ?? 6;
  const stroke = opts.color || cssVar("--accent", "#38bdf8");
  if (!points || points.length === 0) points = [0];
  if (points.length === 1) points = [points[0], points[0]];
  const max = Math.max(...points, 1), min = Math.min(...points, 0);
  const span = max - min || 1;
  const n = points.length;
  const x = (i) => pad + (i * (w - 2 * pad)) / (n - 1);
  const y = (v) => h - pad - ((v - min) / span) * (h - 2 * pad);
  let d = `M ${x(0)} ${y(points[0])}`;
  for (let i = 1; i < n; i++) {
    const cx = (x(i - 1) + x(i)) / 2;
    d += ` C ${cx} ${y(points[i - 1])} ${cx} ${y(points[i])} ${x(i)} ${y(points[i])}`;
  }
  const g = uid();
  const fill = `${d} L ${x(n - 1)} ${h - pad} L ${x(0)} ${h - pad} Z`;
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" width="100%" height="${h}">
    <defs><linearGradient id="${g}" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="${stroke}" stop-opacity=".35"/>
      <stop offset="1" stop-color="${stroke}" stop-opacity="0"/></linearGradient></defs>
    <path d="${fill}" fill="url(#${g})"/>
    <path d="${d}" fill="none" stroke="${stroke}" stroke-width="2" stroke-linecap="round"/>
  </svg>`;
}

/** Donut. segments: [{value, color, label}]. */
export function donut(segments, opts = {}) {
  const size = opts.size || 180, sw = opts.thickness || 22, r = (size - sw) / 2, c = size / 2;
  const total = segments.reduce((s, x) => s + x.value, 0);
  const C = 2 * Math.PI * r;
  let off = 0;
  const ring = segments
    .filter((s) => s.value > 0)
    .map((s) => {
      const len = (s.value / total) * C;
      const el = `<circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="${s.color}" stroke-width="${sw}"
        stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-off}" transform="rotate(-90 ${c} ${c})"
        stroke-linecap="butt"/>`;
      off += len;
      return el;
    }).join("");
  const track = cssVar("--border", "#243248");
  const center = opts.center != null ? opts.center : total;
  const sub = opts.sub || "total";
  return `<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}">
    <circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="${track}" stroke-width="${sw}"/>
    ${total > 0 ? ring : ""}
    <text x="${c}" y="${c - 2}" text-anchor="middle" dominant-baseline="middle"
      fill="${cssVar("--text", "#fff")}" font-size="${size * 0.2}" font-weight="700">${center}</text>
    <text x="${c}" y="${c + size * 0.14}" text-anchor="middle" fill="${cssVar("--text-dim", "#9ab")}"
      font-size="${size * 0.085}">${sub}</text>
  </svg>`;
}

/** Horizontal bars. items: [{label, value, color?, sub?}]. */
export function hbars(items, opts = {}) {
  if (!items.length) {
    const empty = document.createElement("div");
    empty.className = "note";
    empty.textContent = "No data.";
    return empty;
  }
  const max = Math.max(...items.map((i) => i.value), 1);
  const color = opts.color || cssVar("--accent", "#38bdf8");
  const root = document.createElement("div");
  root.className = "hbars";
  items.forEach((it) => {
    const pct = Math.max(2, (it.value / max) * 100);
    const row = document.createElement("div");
    row.className = "hbar";
    const top = document.createElement("div");
    top.className = "hbar-top";
    const label = document.createElement(it.href ? "a" : "span");
    label.className = "hbar-label";
    label.textContent = it.label ?? "";
    if (it.href) {
      label.href = it.href;
      label.title = "Open filtered workbench";
    }
    const value = document.createElement("span");
    value.className = "hbar-val";
    value.textContent = String(it.valueLabel ?? it.value);
    top.appendChild(label);
    top.appendChild(value);
    const track = document.createElement("div");
    track.className = "hbar-track";
    const fill = document.createElement("div");
    fill.className = "hbar-fill";
    fill.setAttribute("role", "progressbar");
    fill.setAttribute("aria-valuemin", "0");
    fill.setAttribute("aria-valuemax", "100");
    fill.setAttribute("aria-valuenow", String(Math.round(pct)));
    fill.style.setProperty("--hbar-fill-width", `${pct}%`);
    fill.style.setProperty("--hbar-fill-color", safeBarColor(it.color, color));
    track.appendChild(fill);
    row.appendChild(top);
    row.appendChild(track);
    if (it.sub) {
      const sub = document.createElement("div");
      sub.className = "hbar-sub";
      sub.textContent = it.sub;
      row.appendChild(sub);
    }
    root.appendChild(row);
  });
  return root;
}

function safeBarColor(value, fallback) {
  const color = String(value || fallback || "").trim();
  if (/^#[0-9a-fA-F]{3,8}$/.test(color)) return color;
  if (/^rgba?\([\d\s.,%]+\)$/.test(color)) return color;
  if (/^hsla?\([\d\s.,%a-zA-Z-]+\)$/.test(color)) return color;
  if (/^[a-zA-Z]+$/.test(color)) return color;
  return fallback;
}

export const palette = () => [
  cssVar("--bad", "#fb7185"), cssVar("--warn", "#fbbf24"),
  cssVar("--info", "#60a5fa"), cssVar("--text-faint", "#61748f"),
];
