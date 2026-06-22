// format.js — value formatting + label/severity maps shared across views.

export function bytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB", "PB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + " " + u[i];
}

export function num(v) { return Number(v) || 0; } // protojson sends uint64 as strings

export function compactNum(n) {
  n = Number(n) || 0;
  if (n < 1000) return String(n);
  if (n < 1e6) return (n / 1e3).toFixed(n < 1e4 ? 1 : 0) + "k";
  return (n / 1e6).toFixed(1) + "M";
}

export function absTime(iso) { return iso ? new Date(iso).toLocaleString() : "—"; }

export function relTime(iso) {
  if (!iso) return "—";
  const d = (Date.now() - new Date(iso).getTime()) / 1000;
  if (d < 0) return "just now";
  if (d < 60) return Math.floor(d) + "s ago";
  if (d < 3600) return Math.floor(d / 60) + "m ago";
  if (d < 86400) return Math.floor(d / 3600) + "h ago";
  return Math.floor(d / 86400) + "d ago";
}

// Suricata severity: 1 = highest.
const SEV = {
  1: { label: "Critical", cls: "bad", n: 1 },
  2: { label: "High", cls: "warn", n: 2 },
  3: { label: "Medium", cls: "info", n: 3 },
};
export function severity(s) { return SEV[s] || { label: "Low", cls: "neutral", n: 4 }; }

export function alertAction(a) {
  return a === "blocked"
    ? { label: "Dropped", cls: "bad" }
    : { label: "Detected", cls: "warn" };
}

const ACTIONS = {
  ACTION_ALLOW: { label: "Allow", cls: "ok" },
  ACTION_DENY: { label: "Drop", cls: "bad" },
  ACTION_REJECT: { label: "Reject", cls: "warn" },
};
export function ruleAction(a) { return ACTIONS[a] || { label: "—", cls: "neutral" }; }

export const PROTOCOLS = {
  PROTOCOL_TCP: "TCP", PROTOCOL_UDP: "UDP", PROTOCOL_ICMP: "ICMP", PROTOCOL_ANY: "Any",
};
export function protoLabel(p) { return PROTOCOLS[p] || p || "Any"; }

export function portList(ports) {
  if (!ports || !ports.length) return "any";
  return ports.map((p) => (p.end && p.end !== p.start ? `${p.start || 0}-${p.end}` : String(p.start || 0))).join(", ");
}

export function endpoint(ip, port) { return port ? `${ip}:${port}` : ip || "—"; }

export function namesOrAny(arr) {
  if (!arr || !arr.length) return ["any"];
  return arr;
}
