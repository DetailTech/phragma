import { h } from "./core.js";

export function normalizePolicyDiffLines(lines = []) {
  return lines.map((line) => ({
    t: policyDiffLineClass(line.type),
    s: redactPolicyDiffText(line.text || ""),
  }));
}

export function policyDiffLabels(data = {}, fallbackFrom = "running policy", fallbackTo = "candidate") {
  return {
    fromLabel: data.fromLabel || data.from_label || fallbackFrom,
    toLabel: data.toLabel || data.to_label || fallbackTo,
  };
}

export function renderDiffLines(lines = []) {
  return h("div", { class: "diff" }, lines.map((l) =>
    h("div", { class: "dl " + l.t }, h("span", { class: "gutter" }, l.t === "add" ? "+" : l.t === "del" ? "-" : " "), redactPolicyDiffText(l.s))));
}

export function redactPolicyDiffText(value = "") {
  return String(value || "")
    .replace(/"?(?:pskFile|psk_file|privateKeyFile|private_key_file)"?\s*:\s*"[^"]*"/gi, '"managedSecretPath": "<redacted>"')
    .replace(/\/etc\/(?:phragma|openngfw)\/(?:keys|secrets)\/[^\s"',;}]+/gi, "<redacted-managed-secret-path>")
    .replace(/\b(?:pskFile|psk_file|privateKeyFile|private_key_file)\b/gi, "managedSecretPath");
}

function policyDiffLineClass(type) {
  if (type === 2 || type === "POLICY_DIFF_LINE_TYPE_ADD") return "add";
  if (type === 3 || type === "POLICY_DIFF_LINE_TYPE_DELETE") return "del";
  return "ctx";
}
