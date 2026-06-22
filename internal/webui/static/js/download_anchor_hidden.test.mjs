import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const css = readFileSync("internal/webui/static/css/app.css", "utf8");
assert.match(css, /\.download-anchor-hidden\s*\{\s*display:\s*none;\s*\}/);

function jsFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    const stat = statSync(path);
    if (stat.isDirectory()) return jsFiles(path);
    return path.endsWith(".js") ? [path] : [];
  });
}

const files = jsFiles("internal/webui/static/js");
let hiddenAnchorUses = 0;

for (const file of files) {
  const source = readFileSync(file, "utf8");
  assert.doesNotMatch(source, /style:\s*\{\s*display:\s*"none"\s*\}/, `${file} should use .download-anchor-hidden instead of inline display:none`);
  hiddenAnchorUses += (source.match(/class:\s*"download-anchor-hidden"/g) || []).length;
}

assert.ok(hiddenAnchorUses >= 20, "download/export anchors should use the shared hidden-anchor class");
