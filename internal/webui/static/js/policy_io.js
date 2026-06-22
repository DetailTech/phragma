// policy_io.js — browser-side policy import/export helpers. Import only
// stages to the candidate; validation and commit still happen through the
// canonical policy workflow.

export const POLICY_EXPORT_SCHEMA = "phragma.policy.export.v1";
export const LEGACY_POLICY_EXPORT_SCHEMA = "openngfw.policy.export.v1";
export const SNAPSHOT_RESTORE_REVIEW_SCHEMA = "phragma.snapshot.restore-review.v1";

export function policyExportEnvelope({ source, version, policy, exportedAt = new Date().toISOString() }) {
  if (!plainObject(policy)) throw new Error("Policy export requires a policy object.");
  return {
    schemaVersion: POLICY_EXPORT_SCHEMA,
    exportedAt,
    source: source || "unknown",
    version: version ? String(version) : "",
    policy,
  };
}

export function policyExportFilename(source, version, now = new Date()) {
  const stamp = now.toISOString().replace(/[:.]/g, "-");
  const label = sanitizePart(source || "policy");
  const suffix = version ? `-v${String(version).replace(/^v/i, "")}` : "";
  return `phragma-${label}${suffix}-${stamp}.json`;
}

export function parsePolicyImportText(text) {
  const raw = String(text || "").trim();
  if (!raw) throw new Error("Paste or choose a policy JSON file first.");
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    throw new Error("Invalid JSON: " + e.message);
  }
  const policy = plainObject(parsed?.policy) ? parsed.policy : parsed;
  if (!plainObject(policy) || Array.isArray(policy)) {
    throw new Error("Import must be a policy object or an export envelope with a policy object.");
  }
  assertSafeKeys(policy);
  return structuredClone(policy);
}

export function replacePolicyDraft(draft, policy) {
  if (!plainObject(draft)) throw new Error("Draft policy is unavailable.");
  if (!plainObject(policy)) throw new Error("Imported policy is invalid.");
  for (const key of Object.keys(draft)) delete draft[key];
  for (const [key, value] of Object.entries(policy)) draft[key] = value;
}

export function snapshotRestoreReviewPacket(preview = {}, {
  route = "",
  reviewLink = "",
  generatedAt = new Date().toISOString(),
} = {}) {
  const snapshot = plainObject(preview.snapshot) ? preview.snapshot : {};
  const validation = plainObject(preview.validation) ? preview.validation : {};
  const diff = plainObject(preview.diff) ? preview.diff : {};
  const snapshotId = cleanPacketText(snapshot.id || preview.snapshotId || preview.snapshot_id || "");
  const policyHash = cleanPacketText(snapshot.policySha256 || snapshot.policy_sha256 || "");
  const routeHash = safeRoute(route);
  const linkHash = safeRoute(reviewLink || routeHash || snapshotRestoreReviewHash(snapshotId, "restore-preview"));
  return {
    schemaVersion: SNAPSHOT_RESTORE_REVIEW_SCHEMA,
    generatedAt,
    source: "browser-generated",
    unsigned: true,
    custody: {
      serverStored: false,
      signed: false,
      encrypted: false,
      antiReplay: false,
      note: "Maintenance review packet only; snapshot restore custody, encryption, signing, and anti-replay are not implemented here.",
    },
    snapshot: {
      id: snapshotId,
      source: cleanPacketText(snapshot.source || "running"),
      sourceVersion: Number(snapshot.sourceVersion || snapshot.source_version || 0),
      policySha256: policyHash,
      createdAt: cleanPacketText(snapshot.createdAt || snapshot.created_at || ""),
      comment: redactPacketText(snapshot.comment || ""),
    },
    route: routeHash,
    reviewLink: linkHash,
    validation: {
      valid: Boolean(validation.valid),
      issueCount: Array.isArray(validation.issues) ? validation.issues.length : 0,
      warningCount: Array.isArray(validation.warnings) ? validation.warnings.length : 0,
      issues: sanitizePacketList(validation.issues),
      warnings: sanitizePacketList(validation.warnings),
    },
    diff: {
      changed: Boolean(diff.changed),
      lineCount: Array.isArray(diff.lines) ? diff.lines.length : 0,
      fromLabel: redactPacketText(diff.fromLabel || ""),
      toLabel: redactPacketText(diff.toLabel || ""),
      preview: sanitizePacketList((diff.lines || []).slice(0, 40).map((line) => line.text || line.value || line)),
    },
    replay: {
      validateApi: snapshotId ? `POST /v1/backup/snapshots/${encodeURIComponent(snapshotId)}:validate` : "",
      previewApi: snapshotId ? `POST /v1/backup/snapshots/${encodeURIComponent(snapshotId)}:restore-preview {"stageCandidate":false}` : "",
      stageApi: snapshotId ? `POST /v1/backup/snapshots/${encodeURIComponent(snapshotId)}:restore-preview {"stageCandidate":true,"expectedCandidateRevision":"<current-candidate-revision>"}` : "",
      cli: snapshotId ? `ngfwctl backup snapshot restore-preview ${shellQuote(snapshotId)}` : "",
    },
    candidateMutationBoundary: "No direct candidate mutation is included in this packet; staging must use the existing restore-preview API/session workflow.",
  };
}

export function snapshotRestoreReviewHash(snapshotId = "", drawer = "restore-preview") {
  const id = normalizeSnapshotId(snapshotId);
  const view = normalizeSnapshotDrawer(drawer);
  if (!id || !view) return "#/changes?tab=snapshots";
  const q = new URLSearchParams({ tab: "snapshots", snapshot: id, drawer: view });
  return `#/changes?${q.toString()}`;
}

export function snapshotRestoreReviewJson(packet = {}) {
  return JSON.stringify(packet, null, 2) + "\n";
}

export function snapshotRestoreReviewText(packet = {}) {
  const snapshot = packet.snapshot || {};
  return [
    "Snapshot restore maintenance review",
    `Snapshot: ${snapshot.id || "unknown"}`,
    `Policy hash: ${snapshot.policySha256 ? "sha256:" + snapshot.policySha256.slice(0, 12) : "no policy hash"}`,
    `Review link: ${packet.reviewLink || packet.route || ""}`,
    `Validation: ${packet.validation?.valid ? "passed" : "failed"}`,
    `Diff: ${packet.diff?.changed ? "changed" : "unchanged"}`,
    `Boundary: ${packet.candidateMutationBoundary || ""}`,
  ].filter(Boolean).join("\n") + "\n";
}

export function snapshotRestoreReviewFilename(snapshotId = "", now = new Date()) {
  const stamp = now.toISOString().replace(/[:.]/g, "-");
  return `phragma-snapshot-restore-review-${sanitizePart(snapshotId || "snapshot")}-${stamp}.json`;
}

export function normalizeSnapshotId(value = "") {
  const text = String(value || "").trim();
  return /^[A-Za-z0-9._:-]{1,128}$/.test(text) ? text : "";
}

export function normalizeSnapshotDrawer(value = "") {
  const drawer = String(value || "").trim();
  return drawer === "validate" || drawer === "restore-preview" ? drawer : "";
}

export function redactPacketText(value = "") {
  return cleanPacketText(value)
    .replace(/(^|[\s"'({=,;])\/(?:var\/lib|var\/log(?:\/openngfw)?|etc\/(?:openngfw|phragma)|tmp|private\/tmp|var\/folders|private\/var\/folders|home\/[^'"\s,;}]+|Users\/[^'"\s,;}]+|opt\/[^'"\s,;}]+|data\/[^'"\s,;}]+)[^'"\s,;}]*/gi, "$1[server-local path redacted]")
    .replace(/(Authorization:\s*Bearer\s+)(?!\[redacted\])["']?[^"'\s,;}]+["']?/gi, "$1[redacted]")
    .replace(/\bBearer\s+(?!\[redacted\])[A-Za-z0-9._~+/-]{8,}/gi, "Bearer [redacted]")
    .replace(/(^|[?&\s"',;])((?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|passwd|secret|client[_-]?secret|api[_-]?key|cookie)=)[^&\s"',;]+/gi, "$1$2[redacted]")
    .replace(/(^|[\s"',;{])((?:access[_-]?token|refresh[_-]?token|id[_-]?token|password|passwd|secret|client[_-]?secret|api[_-]?key|cookie)\s*:\s*)[^\s"',;]+/gi, "$1$2[redacted]")
    .slice(0, 1600);
}

function assertSafeKeys(value, path = "$") {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertSafeKeys(item, `${path}[${index}]`));
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      throw new Error(`Unsafe key "${key}" at ${path}.`);
    }
    assertSafeKeys(child, `${path}.${key}`);
  }
}

function sanitizePacketList(items = []) {
  return (Array.isArray(items) ? items : [items])
    .map((item) => redactPacketText(typeof item === "string" ? item : JSON.stringify(item || {})))
    .filter(Boolean)
    .slice(0, 25);
}

function safeRoute(value = "") {
  const text = String(value || "").trim();
  return text.startsWith("#/") && !/[?&](?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|secret|api[_-]?key)=/i.test(text) ? text : "";
}

function shellQuote(value = "") {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

function cleanPacketText(value = "") {
  return String(value || "").replace(/[\u0000-\u001f\u007f]/g, " ").trim();
}

function sanitizePart(value) {
  return String(value || "policy").toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "policy";
}

function plainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
