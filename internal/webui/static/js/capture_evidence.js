import { h, icon, clear } from "./core.js";
import { api } from "./api.js";
import { pill, toast } from "./ui.js";
import * as fmt from "./format.js";
import {
  captureArtifactFilename,
  captureAuditHash,
  captureHistoryItems,
  captureSubjectFromSource,
  matchingCaptureHistoryItems,
} from "./packet_capture.js";

export function captureEvidenceViewModel(resp = {}, source = {}, opts = {}) {
  const subject = captureSubjectFromSource(source);
  const allItems = captureHistoryItems(resp);
  const limit = Number.isInteger(Number(opts.limit)) ? Math.max(1, Number(opts.limit)) : 3;
  const matches = matchingCaptureHistoryItems(resp, subject, { limit });
  const correlatedItems = allItems.filter(hasCaptureTuple);
  const state = matches.length ? "matched" : allItems.length ? "none" : "empty";
  return {
    subject,
    matches,
    total: allItems.length,
    correlated: correlatedItems.length,
    state,
    subjectLabel: captureSubjectLabel(subject),
    message: captureEvidenceMessage(state, allItems.length, correlatedItems.length),
  };
}

export function captureEvidencePanel(source = {}, opts = {}) {
  const root = h("section", {
    class: "capture-evidence",
    dataset: { captureEvidence: "true", captureEvidenceState: "loading" },
  }, captureEvidenceHeader(opts.title || "Packet capture evidence", pill("loading", "info")),
  h("div", { class: "loading compact" }, "Loading recent capture evidence..."));
  queueMicrotask(() => loadCaptureEvidence(root, source, opts));
  return root;
}

async function loadCaptureEvidence(root, source, opts = {}) {
  try {
    const subject = captureSubjectFromSource(source);
    const resp = await api.packetCaptures({ limit: opts.historyLimit || 12, flowId: subject.flowId || "" });
    if (!root.isConnected) return;
    renderCaptureEvidence(root, captureEvidenceViewModel(resp, source, { limit: opts.matchLimit || 3 }), opts);
  } catch (err) {
    if (!root.isConnected) return;
    renderCaptureEvidenceError(root, err, opts);
  }
}

function renderCaptureEvidence(root, model, opts = {}) {
  clear(root);
  root.dataset.captureEvidenceState = model.state;
  root.appendChild(captureEvidenceHeader(opts.title || "Packet capture evidence", captureEvidenceStatus(model)));
  root.appendChild(h("div", { class: "note" }, model.subjectLabel || "Flow tuple unavailable."));
  if (model.matches.length) {
    root.appendChild(h("div", { class: "capture-history-list" }, model.matches.map(captureEvidenceRow)));
    return;
  }
  root.appendChild(h("div", { class: "note capture-evidence-note" }, model.message));
}

function renderCaptureEvidenceError(root, err, opts = {}) {
  const adminOnly = err?.status === 401 || err?.status === 403;
  clear(root);
  root.dataset.captureEvidenceState = adminOnly ? "admin" : "error";
  root.appendChild(captureEvidenceHeader(opts.title || "Packet capture evidence", pill(adminOnly ? "admin" : "error", adminOnly ? "warn" : "bad")));
  root.appendChild(h("div", { class: "note capture-evidence-note" },
    adminOnly ? "Recent capture artifacts require admin access." : `Capture evidence unavailable: ${err?.message || err}`));
}

function captureEvidenceHeader(title, status) {
  return h("div", { class: "capture-evidence-head" },
    h("div", {},
      h("strong", {}, title),
      h("span", {}, "Recent artifacts matched by flow tuple")),
    status);
}

function captureEvidenceStatus(model) {
  if (model.state === "matched") return pill(`${model.matches.length} matched`, "ok");
  if (model.total) return pill("no match", "warn");
  return pill("empty", "info");
}

function captureEvidenceRow(ref) {
  const statusClass = ref.state === "completed" ? "ok" : ref.state === "unavailable" ? "warn" : "info";
  const artifactId = ref.artifactId || ref.id || "";
  return h("div", {
    class: "capture-history-row capture-evidence-row",
    dataset: {
      captureArtifactRow: artifactId,
      captureArtifactId: artifactId,
      captureRetentionState: ref.retentionState || "",
    },
  },
    h("div", { class: "capture-history-main" },
      h("div", { class: "capture-history-title" },
        h("strong", {}, ref.filename || ref.artifactId || ref.id || "capture artifact"),
        pill(ref.state || "indexed", statusClass),
        ref.integrity?.label ? pill(`integrity ${ref.integrity.label}`, ref.integrity.tone) : null,
        ref.retentionSummary ? pill(ref.retentionSummary, ref.retentionTone) : null),
      h("dl", { class: "kv capture-detail" },
        ref.completedAt ? kv("Completed", fmt.absTime(ref.completedAt)) : null,
        ref.integrity?.detail ? kv("Integrity", ref.integrity.detail) : null,
        ref.bytesWritten ? kv("Size", fmt.bytes(ref.bytesWritten)) : null,
        ref.sha256Short ? kv("SHA-256", h("span", { title: ref.sha256 }, ref.sha256Short)) : null,
        ref.retainUntil ? kv("Retain until", fmt.absTime(ref.retainUntil)) : null,
        ref.caseId ? kv("Case", ref.caseId) : null,
        ref.retentionReason ? kv("Retention reason", ref.retentionReason) : null,
        ref.bpfFilter ? kv("Filter", ref.bpfFilter) : null,
        ref.detail ? kv("Detail", ref.detail) : null)),
    h("div", { class: "capture-history-actions" },
      ref.artifactId ? h("button", { class: "btn sm", type: "button", title: `Download capture artifact ${captureArtifactLabel(ref)}`, "aria-label": `Download capture artifact ${captureArtifactLabel(ref)}`, onclick: () => downloadCaptureArtifact(ref), dataset: { captureAction: "download", sharedControl: "capture-evidence-download" } },
        h("span", { html: icon("download", 14) }), "Download") : null,
      h("a", { class: "btn sm ghost", href: captureAuditHash(ref), title: `Open audit trail for capture artifact ${captureArtifactLabel(ref)}`, "aria-label": `Open audit trail for capture artifact ${captureArtifactLabel(ref)}`, dataset: { captureAction: "audit", sharedControl: "capture-evidence-audit" } }, h("span", { html: icon("clock", 14) }), "Audit")));
}

function captureArtifactLabel(ref = {}) {
  return ref.filename || ref.artifactId || ref.id || "capture artifact";
}

async function downloadCaptureArtifact(ref) {
  if (!ref?.artifactId) return;
  try {
    const blob = await api.downloadPacketCapture(ref.artifactId);
    downloadBlob(captureArtifactFilename(ref), blob);
    toast("Capture downloaded", captureArtifactFilename(ref), "ok");
  } catch (err) {
    toast("Download failed", err?.message || String(err || "packet capture download failed"), "bad");
  }
}

function downloadBlob(filename, blob) {
  const url = URL.createObjectURL(blob);
  const a = h("a", { class: "download-anchor-hidden", href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
}

function captureEvidenceMessage(state, total, correlated) {
  if (state === "empty") return "No completed capture artifacts found.";
  if (total && !correlated) return "Recent artifacts are present but do not include tuple metadata. New captures from this build will be correlated here.";
  return "No recent captures match this flow tuple. Use Capture to create bounded evidence.";
}

function captureSubjectLabel(subject = {}) {
  if (!subject.srcIp || !subject.destIp) return "";
  const src = subject.srcPort ? `${subject.srcIp}:${subject.srcPort}` : subject.srcIp;
  const dst = subject.destPort ? `${subject.destIp}:${subject.destPort}` : subject.destIp;
  return `${String(subject.protocol || "ip").toUpperCase()} ${src} -> ${dst}`;
}

function hasCaptureTuple(ref = {}) {
  return Boolean(ref.srcIp && ref.destIp);
}

function kv(k, v) {
  return [h("dt", {}, k), h("dd", { class: "mono" }, v)];
}
