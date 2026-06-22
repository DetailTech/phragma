// Guardrailed packet-capture planner for the WebUI. The canonical server API
// owns validation and execution; this local planner keeps the copyable command
// usable when an operator is offline or reviewing an older daemon.

export const CAPTURE_LIMITS = Object.freeze({
  defaultInterface: "any",
  defaultDurationSeconds: 20,
  minDurationSeconds: 1,
  maxDurationSeconds: 60,
  defaultPacketCount: 500,
  minPacketCount: 1,
  maxPacketCount: 10000,
  defaultSnaplenBytes: 256,
  minSnaplenBytes: 96,
  maxSnaplenBytes: 4096,
  outputDir: "/var/log/openngfw/pcap",
});

export const CAPTURE_MEDIA_TYPE = "application/vnd.tcpdump.pcap";

const IFACE_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
const ADDR_RE = /^[A-Fa-f0-9:.]{2,64}$/;
const LABEL_RE = /^[A-Za-z0-9_.-]{1,48}$/;
const ARTIFACT_RE = /^[A-Za-z0-9_.-]{1,128}$/;
const RETENTION_CASE_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
const PROTOCOLS = new Set(["tcp", "udp", "icmp", "ip"]);

export function buildCapturePlan(input = {}) {
  const warnings = [];
  const iface = normalizeInterface(input.interface || input.iface || CAPTURE_LIMITS.defaultInterface);
  if (iface === CAPTURE_LIMITS.defaultInterface) {
    warnings.push("Interface is set to any; prefer the ingress or egress interface when known.");
  }

  const protocol = normalizeProtocol(input.protocol);
  const srcIp = normalizeAddress(input.srcIp);
  const destIp = normalizeAddress(input.destIp);
  const srcPort = normalizePort(input.srcPort);
  const destPort = normalizePort(input.destPort);
  const durationSeconds = clampInt(input.durationSeconds, CAPTURE_LIMITS.minDurationSeconds, CAPTURE_LIMITS.maxDurationSeconds, CAPTURE_LIMITS.defaultDurationSeconds);
  const packetCount = clampInt(input.packetCount, CAPTURE_LIMITS.minPacketCount, CAPTURE_LIMITS.maxPacketCount, CAPTURE_LIMITS.defaultPacketCount);
  const snaplenBytes = clampInt(input.snaplenBytes, CAPTURE_LIMITS.minSnaplenBytes, CAPTURE_LIMITS.maxSnaplenBytes, CAPTURE_LIMITS.defaultSnaplenBytes);
  const label = normalizeLabel(input.label || "flow");
  const flowId = String(input.flowId || input.flow_id || "").trim();

  if (!srcIp || !destIp) {
    warnings.push("Capture filter is not fully flow-scoped because source or destination IP is missing.");
  }
  if ((protocol === "tcp" || protocol === "udp") && (!srcPort || !destPort)) {
    warnings.push("TCP/UDP capture has a host filter but not both ports; expect more packets.");
  }

  const filter = buildBpfFilter({ protocol, srcIp, srcPort, destIp, destPort });
  const outputPath = `${CAPTURE_LIMITS.outputDir}/phragma-${label}-${captureTimestamp(input.timestamp)}.pcap`;
  const command = [
    `sudo install -d -m 0750 ${shellQuote(CAPTURE_LIMITS.outputDir)}`,
    `sudo timeout ${durationSeconds}s tcpdump -i ${shellQuote(iface)} -nn -s ${snaplenBytes} -c ${packetCount} -w ${shellQuote(outputPath)} ${shellQuote(filter)}`,
  ].join(" && ");

  return {
    interface: iface,
    protocol,
    srcIp,
    srcPort,
    destIp,
    destPort,
    durationSeconds,
    packetCount,
    snaplenBytes,
    flowId,
    outputPath,
    filter,
    command,
    warnings,
  };
}

export function captureReference(plan = {}, job = {}) {
  const capturePlan = job?.plan || plan || {};
  const outputPath = capturePlan?.outputPath || capturePlan?.output_path || "";
  const sha256 = String(job?.sha256 || job?.sha256Hash || job?.sha256_hash || "").trim().toLowerCase();
  const filename = safeCaptureFilename(job?.filename || basename(outputPath));
  const artifactId = safeCaptureArtifactId(job?.artifactId || job?.artifact_id || artifactIdFromFilename(filename));
  const downloadPath = artifactId ? `/v1/system/packet-captures/${artifactId}/download` : "";
  const retention = normalizeCaptureRetention(job);
  return {
    id: job?.id || "",
    flowId: String(job?.flowId || job?.flow_id || capturePlan?.flowId || capturePlan?.flow_id || "").trim(),
    state: job?.state || "",
    detail: job?.detail || "",
    interface: capturePlan?.interface || capturePlan?.iface || "",
    protocol: normalizeProtocol(capturePlan?.protocol),
    srcIp: normalizeAddress(capturePlan?.srcIp || capturePlan?.src_ip),
    srcPort: normalizePort(capturePlan?.srcPort || capturePlan?.src_port),
    destIp: normalizeAddress(capturePlan?.destIp || capturePlan?.dest_ip),
    destPort: normalizePort(capturePlan?.destPort || capturePlan?.dest_port),
    bpfFilter: capturePlan?.bpfFilter || capturePlan?.bpf_filter || capturePlan?.filter || "",
    outputPath,
    artifactId,
    downloadPath,
    filename,
    mediaType: job?.mediaType || job?.media_type || CAPTURE_MEDIA_TYPE,
    bytesWritten: Number(job?.bytesWritten ?? job?.bytes_written ?? 0) || 0,
    sha256: /^[a-f0-9]{64}$/.test(sha256) ? sha256 : "",
    sha256Short: /^[a-f0-9]{64}$/.test(sha256) ? sha256.slice(0, 12) : "",
    startedAt: job?.startedAt || job?.started_at || "",
    completedAt: job?.completedAt || job?.completed_at || "",
    retention,
    retentionState: retention.state,
    retainUntil: retention.retainUntil,
    retentionReason: retention.reason,
    caseId: retention.caseId,
    retentionUpdatedAt: retention.updatedAt,
    retentionUpdatedBy: retention.updatedBy,
    retentionSummary: captureRetentionSummary(retention),
    retentionTone: captureRetentionTone(retention),
    integrity: captureIntegrityStatus({
      state: job?.state || "",
      artifactId,
      filename,
      bytesWritten: Number(job?.bytesWritten ?? job?.bytes_written ?? 0) || 0,
      sha256: /^[a-f0-9]{64}$/.test(sha256) ? sha256 : "",
      mediaType: job?.mediaType || job?.media_type || CAPTURE_MEDIA_TYPE,
    }),
  };
}

export function captureReferenceLabel(ref = {}) {
  const parts = [];
  if (ref.id) parts.push(ref.id);
  if (ref.filename) parts.push(ref.filename);
  if (ref.sha256Short) parts.push(`sha256:${ref.sha256Short}`);
  if (ref.bytesWritten) parts.push(`${ref.bytesWritten} bytes`);
  return parts.join(" · ") || "capture reference unavailable";
}

export function captureIntegrityStatus(ref = {}) {
  const state = String(ref.state || "").trim().toLowerCase();
  const artifactId = safeCaptureArtifactId(ref.artifactId || ref.artifact_id || "");
  const filename = safeCaptureFilename(ref.filename || "");
  const bytesWritten = Number(ref.bytesWritten ?? ref.bytes_written ?? 0) || 0;
  const sha256 = String(ref.sha256 || ref.sha256Hash || ref.sha256_hash || "").trim().toLowerCase();
  const validHash = /^[a-f0-9]{64}$/.test(sha256);
  const mediaType = String(ref.mediaType || ref.media_type || "").trim();
  const completed = state === "completed" || state === "succeeded" || state === "success";
  const problems = [];
  if (!completed) problems.push("capture job is not completed");
  if (!artifactId && !filename) problems.push("safe artifact identifier is missing");
  if (!bytesWritten) problems.push("artifact size is not recorded");
  if (!validHash) problems.push("sha256 digest is not recorded");
  if (mediaType && mediaType !== CAPTURE_MEDIA_TYPE) problems.push("media type is not tcpdump pcap");
  if (!problems.length) {
    return {
      state: "verifiable",
      label: "verifiable",
      tone: "ok",
      detail: "Completed artifact has a safe identifier, nonzero size, and SHA-256 digest.",
      problems: [],
    };
  }
  if (completed && validHash) {
    return {
      state: "review",
      label: "review",
      tone: "warn",
      detail: problems.join("; "),
      problems,
    };
  }
  return {
    state: completed ? "incomplete" : "pending",
    label: completed ? "incomplete" : "pending",
    tone: completed ? "warn" : "info",
    detail: problems.join("; "),
    problems,
  };
}

export function captureHistoryItems(resp = {}) {
  const captures = Array.isArray(resp?.captures) ? resp.captures : [];
  return captures.map((job) => captureReference(job?.plan || {}, job))
    .filter((ref) => ref.artifactId || ref.sha256);
}

export function normalizeCaptureRetention(source = {}) {
  const raw = source?.retention || source || {};
  const state = normalizeRetentionState(raw.state || raw.retentionState || raw.retention_state);
  const retainUntil = safeRetentionTimestamp(raw.retainUntil || raw.retain_until || raw.retentionUntil || raw.retention_until);
  return {
    state,
    retainUntil,
    reason: safeRetentionText(raw.retentionReason || raw.retention_reason || raw.reason, 256, true),
    caseId: safeRetentionCaseId(raw.caseId || raw.case_id),
    updatedAt: safeRetentionTimestamp(raw.updatedAt || raw.updated_at || raw.retentionUpdatedAt || raw.retention_updated_at),
    updatedBy: safeRetentionText(raw.updatedBy || raw.updated_by || raw.retentionUpdatedBy || raw.retention_updated_by, 96, false),
    isRetained: state === "retained",
    isReleased: state === "released",
    isExpired: state === "retained" && retainUntil ? new Date(retainUntil).getTime() <= Date.now() : false,
  };
}

export function captureRetentionSummary(input = {}) {
  const retention = input.retention ? input.retention : input;
  if (retention.state === "released") return "released";
  if (retention.state === "retained") {
    if (retention.isExpired) return "expired";
    if (retention.retainUntil) return `expires ${retention.retainUntil.slice(0, 10)}`;
    return "retained";
  }
  return "";
}

export function captureRetentionTone(input = {}) {
  const retention = input.retention ? input.retention : input;
  if (retention.state === "released") return "neutral";
  if (retention.state === "retained" && retention.isExpired) return "warn";
  if (retention.state === "retained") return "ok";
  return "info";
}

export function captureRetentionApiState(state) {
  const normalized = normalizeRetentionState(state);
  if (normalized === "retained") return "PACKET_CAPTURE_RETENTION_STATE_RETAINED";
  if (normalized === "released") return "PACKET_CAPTURE_RETENTION_STATE_RELEASED";
  return "PACKET_CAPTURE_RETENTION_STATE_UNSPECIFIED";
}

export function captureSubjectFromSource(source = {}) {
  const src = source?.plan ? { ...source.plan, ...source } : source;
  return {
    flowId: String(src.flowId || src.flow_id || src.sampleFlowId || src.sample_flow_id || "").trim(),
    protocol: normalizeProtocol(src.protocol),
    srcIp: normalizeAddress(src.srcIp || src.src_ip || src.src || src.sampleSrcIp || src.sample_src_ip),
    srcPort: normalizePort(src.srcPort || src.src_port || src.sport || src.sampleSrcPort || src.sample_src_port),
    destIp: normalizeAddress(src.destIp || src.dest_ip || src.dst || src.sampleDestIp || src.sample_dest_ip),
    destPort: normalizePort(src.destPort || src.dest_port || src.dport || src.sampleDestPort || src.sample_dest_port),
  };
}

export function captureMatchesSubject(ref = {}, source = {}) {
  const capture = captureSubjectFromSource(ref);
  const subject = captureSubjectFromSource(source);
  if (capture.flowId && subject.flowId && capture.flowId === subject.flowId) return true;
  if (!capture.srcIp || !capture.destIp || !subject.srcIp || !subject.destIp) return false;
  if (!protocolCompatible(capture.protocol, subject.protocol)) return false;
  return tupleMatches(capture, subject, false) || tupleMatches(capture, subject, true);
}

export function matchingCaptureHistoryItems(resp = {}, source = {}, opts = {}) {
  const limit = Number.isInteger(Number(opts.limit)) ? Math.max(1, Number(opts.limit)) : 3;
  return captureHistoryItems(resp)
    .filter((ref) => captureMatchesSubject(ref, source))
    .slice(0, limit);
}

export function captureArtifactFilename(ref = {}) {
  const filename = safeCaptureFilename(ref.filename || basename(ref.outputPath));
  if (filename) return filename;
  if (ref.artifactId) return `${ref.artifactId}.pcap`;
  return "packet-capture.pcap";
}

export function captureAuditHash(source = {}) {
  const q = new URLSearchParams();
  q.set("tab", "audit");
  q.set("action", "packet-capture");
  const query = captureAuditQuery(source);
  if (query) q.set("query", query);
  return "#/changes?" + q.toString();
}

export function captureAuditQuery(source = {}) {
  const sha256 = String(source.sha256 || source.sha256Hash || source.sha256_hash || "").trim().toLowerCase();
  if (/^[a-f0-9]{64}$/.test(sha256)) return sha256;
  if (source.flowId || source.flow_id) return String(source.flowId || source.flow_id).trim();
  if (source.artifactId || source.artifact_id) return String(source.artifactId || source.artifact_id).trim();
  const outputPath = source.outputPath || source.output_path;
  if (outputPath) return String(outputPath).trim().split(/[\\/]/).filter(Boolean).pop() || String(outputPath).trim();
  const src = source.srcIp || source.src || "";
  const dst = source.destIp || source.dst || "";
  if (src && dst) return `${src} ${source.srcPort || source.sport || ""} ${dst} ${source.destPort || source.dport || ""}`.replace(/\s+/g, " ").trim();
  return "";
}

function safeCaptureFilename(v) {
  const raw = String(v || "").trim();
  if (/[\\/]/.test(raw)) return "";
  const name = basename(raw);
  if (!name || name.startsWith(".") || name.includes("..")) return "";
  if (!/^[A-Za-z0-9_.-]{1,140}\.pcap$/.test(name)) return "";
  return name;
}

function safeCaptureArtifactId(v) {
  const id = String(v || "").trim();
  if (!id || id.startsWith(".") || id.includes("..") || !ARTIFACT_RE.test(id)) return "";
  return id;
}

function normalizeRetentionState(v) {
  const raw = String(v || "").trim().toLowerCase().replace(/^packet_capture_retention_state_/, "");
  if (raw === "retained" || raw === "retain") return "retained";
  if (raw === "released" || raw === "release") return "released";
  return "";
}

function safeRetentionTimestamp(v) {
  const raw = String(v || "").trim();
  if (!raw || !/^\d{4}-\d{2}-\d{2}T/.test(raw) || !raw.endsWith("Z")) return "";
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return "";
  return date.toISOString().replace(/\.000Z$/, "Z");
}

function safeRetentionCaseId(v) {
  const raw = String(v || "").trim();
  if (!raw || !RETENTION_CASE_RE.test(raw) || unsafeRetentionText(raw)) return "";
  return raw;
}

function safeRetentionText(v, max, allowSpaces) {
  const raw = String(v || "").trim();
  if (!raw || raw.length > max || unsafeRetentionText(raw)) return "";
  const compact = allowSpaces ? raw.replace(/\s+/g, " ") : raw.replace(/\s+/g, "_");
  return compact.slice(0, max);
}

function unsafeRetentionText(v) {
  const raw = String(v || "");
  const lower = raw.toLowerCase();
  return /[\u0000-\u001f\u007f]/.test(raw) ||
    /[\\/]/.test(raw) ||
    lower.includes("://") ||
    lower.includes("bearer ") ||
    lower.includes("authorization:") ||
    lower.includes("access_token=") ||
    lower.includes("api_key=") ||
    lower.includes("token=") ||
    lower.includes("password=") ||
    lower.includes("secret=");
}

function artifactIdFromFilename(filename) {
  const name = safeCaptureFilename(filename);
  return name ? name.slice(0, -".pcap".length) : "";
}

function basename(v) {
  return String(v || "").trim().split(/[\\/]/).filter(Boolean).pop() || "";
}

function buildBpfFilter({ protocol, srcIp, srcPort, destIp, destPort }) {
  const proto = protocol === "ip" ? "" : protocol;
  if (srcIp && destIp && (protocol === "tcp" || protocol === "udp") && srcPort && destPort) {
    return `${proto} and ((src host ${srcIp} and src port ${srcPort} and dst host ${destIp} and dst port ${destPort}) or (src host ${destIp} and src port ${destPort} and dst host ${srcIp} and dst port ${srcPort}))`;
  }
  const parts = [];
  if (proto) parts.push(proto);
  if (srcIp && destIp) parts.push(`((src host ${srcIp} and dst host ${destIp}) or (src host ${destIp} and dst host ${srcIp}))`);
  else if (srcIp) parts.push(`host ${srcIp}`);
  else if (destIp) parts.push(`host ${destIp}`);
  if ((protocol === "tcp" || protocol === "udp") && srcPort) parts.push(`port ${srcPort}`);
  if ((protocol === "tcp" || protocol === "udp") && destPort && destPort !== srcPort) parts.push(`port ${destPort}`);
  return parts.length ? parts.join(" and ") : "ip";
}

function protocolCompatible(a, b) {
  const left = normalizeProtocol(a);
  const right = normalizeProtocol(b);
  return !left || !right || left === "ip" || right === "ip" || left === right;
}

function tupleMatches(ref, subject, reverse = false) {
  const refSrc = reverse ? ref.destIp : ref.srcIp;
  const refDst = reverse ? ref.srcIp : ref.destIp;
  const refSport = reverse ? ref.destPort : ref.srcPort;
  const refDport = reverse ? ref.srcPort : ref.destPort;
  if (refSrc !== subject.srcIp || refDst !== subject.destIp) return false;
  if (!requiresPorts(ref.protocol, subject.protocol)) return true;
  if (refSport && subject.srcPort && refSport !== subject.srcPort) return false;
  if (refDport && subject.destPort && refDport !== subject.destPort) return false;
  return Boolean(refSport || refDport || subject.srcPort || subject.destPort);
}

function requiresPorts(...protocols) {
  return protocols.map(normalizeProtocol).some((proto) => proto === "tcp" || proto === "udp");
}

function normalizeInterface(v) {
  const iface = String(v || "").trim();
  if (!iface) return CAPTURE_LIMITS.defaultInterface;
  return IFACE_RE.test(iface) ? iface : CAPTURE_LIMITS.defaultInterface;
}

function normalizeProtocol(v) {
  const raw = String(v || "").replace(/^PROTOCOL_/i, "").toLowerCase();
  return PROTOCOLS.has(raw) ? raw : "ip";
}

function normalizeAddress(v) {
  const addr = String(v || "").trim();
  return ADDR_RE.test(addr) ? addr : "";
}

function normalizePort(v) {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 && n <= 65535 ? n : 0;
}

function normalizeLabel(v) {
  const label = String(v || "").trim().replace(/[^A-Za-z0-9_.-]+/g, "-").replace(/^-+|-+$/g, "");
  return LABEL_RE.test(label) ? label : "flow";
}

function captureTimestamp(v) {
  const date = v ? new Date(v) : new Date();
  const safe = Number.isNaN(date.getTime()) ? new Date() : date;
  return safe.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

function clampInt(v, min, max, fallback) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

function shellQuote(v) {
  return "'" + String(v).replaceAll("'", "'\"'\"'") + "'";
}
