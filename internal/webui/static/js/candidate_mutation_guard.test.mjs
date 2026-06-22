import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const WEBUI_JS_ROOT = fileURLToPath(new URL(".", import.meta.url));
const REPO_ROOT = path.resolve(WEBUI_JS_ROOT, "../../../..");

const SCAN_ROOTS = [
  WEBUI_JS_ROOT,
  path.join(REPO_ROOT, "e2e"),
];

// Allowed candidate mutation owners:
// - api.js is the only low-level HTTP transport allowed to define PUT /v1/candidate.
// - policy.js Session is the only production WebUI owner allowed to call api.setCandidate.
// - tests and fixtures may assert the API contract or seed state.
// - e2e/webui-visual-smoke.mjs may seed candidate state while exercising browser workflows.
const ALLOWED_MUTATION_OWNERS = new Map([
  ["internal/webui/static/js/api.js", "candidate HTTP transport owner"],
  ["internal/webui/static/js/policy.js", "Session owner; use session.apply(), session.stageDraft(), validate(), discard(), or commit() from route code"],
  ["e2e/webui-visual-smoke.mjs", "WebUI e2e seed helper"],
]);

const GUARDED_PATTERNS = [
  {
    label: "api.setCandidate(...)",
    re: /(?:^|[^\w$])api\s*\.\s*setCandidate\s*\(/g,
    guidance: "Route and component code must stage candidate edits through the policy Session APIs.",
  },
  {
    label: "fetch('/v1/candidate', { method: 'PUT' })",
    re: /fetch\s*\(\s*(['"`])\/v1\/candidate\1\s*,\s*\{[\s\S]{0,1200}?\bmethod\s*:\s*(['"`])[Pp][Uu][Tt]\2/g,
    guidance: "Direct candidate PUTs must stay inside api.js transport or policy.js Session ownership.",
  },
];

function sourceFiles(root) {
  if (!existsSync(root)) return [];
  const out = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    for (const name of readdirSync(dir)) {
      if (name.startsWith("._")) continue;
      const full = path.join(dir, name);
      const stat = statSync(full);
      if (stat.isDirectory()) {
        if (name === "node_modules") continue;
        stack.push(full);
      } else if (/\.(?:js|mjs)$/.test(name)) {
        out.push(full);
      }
    }
  }
  return out.sort();
}

function repoRelative(file) {
  return path.relative(REPO_ROOT, file).split(path.sep).join("/");
}

function lineFor(source, index) {
  return source.slice(0, index).split("\n").length;
}

function isAllowedOwner(rel) {
  if (ALLOWED_MUTATION_OWNERS.has(rel)) return true;
  if (/\.test\.mjs$/.test(rel)) return true;
  return rel.includes("/fixtures/") || rel.includes("/testdata/");
}

const violations = [];

for (const file of SCAN_ROOTS.flatMap(sourceFiles)) {
  const rel = repoRelative(file);
  const source = readFileSync(file, "utf8");
  for (const pattern of GUARDED_PATTERNS) {
    pattern.re.lastIndex = 0;
    for (let match = pattern.re.exec(source); match; match = pattern.re.exec(source)) {
      if (isAllowedOwner(rel)) continue;
      violations.push(`${rel}:${lineFor(source, match.index)}: direct ${pattern.label} is not allowed. ${pattern.guidance}`);
    }
  }
}

assert.equal(
  violations.length,
  0,
  [
    "Candidate mutation source guard failed.",
    "Approved production owners are internal/webui/static/js/api.js transport and internal/webui/static/js/policy.js Session.",
    "Route/view code must call session.apply(), session.stageDraft(), session.validate(), session.discard(), or session.commit().",
    ...violations,
  ].join("\n"),
);
