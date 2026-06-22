import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const appSource = readFileSync(new URL("./app.js", import.meta.url), "utf8");
const indexSource = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const investigationSource = readFileSync(new URL("./views/investigation.js", import.meta.url), "utf8");

function assertSource(source, pattern, label) {
  assert.match(source, pattern, label);
}

function assertControl(source, actionPattern, label) {
  assertSource(source, actionPattern, `${label} selector is present`);
  const start = source.search(actionPattern);
  assert.notEqual(start, -1, `${label} selector offset`);
  const block = source.slice(Math.max(0, start - 280), start + 420);
  assert.match(block, /type: "button"/, `${label} has type=button`);
  assert.match(block, /"aria-label":/, `${label} has aria label`);
  assert.match(block, /title:/, `${label} has title`);
}

for (const id of ["palette-hint", "menu-toggle", "open-palette", "open-diagnostics", "open-automation", "theme-toggle"]) {
  assertSource(indexSource, new RegExp(`<button[^>]+id="${id}"[^>]+type="button"[^>]+aria-label=`), `${id} has app-shell button semantics`);
}

assertSource(indexSource, /<a class="skip-link" href="#content">Skip to workspace<\/a>/, "skip link targets workspace content");
assertSource(indexSource, /<main class="content" id="content" tabindex="-1">/, "workspace target is programmatically focusable");
assertSource(indexSource, /<button class="sidebar-scrim" id="sidebar-scrim" type="button" aria-label="Close navigation menu" hidden><\/button>/, "sidebar scrim has button semantics");
assertSource(appSource, /document\.body\.classList\.toggle\("shell-menu-open", open\)/, "mobile menu locks background scroll");
assertSource(appSource, /\$\(("#sidebar-scrim")\)\.onclick = closeMenu/, "sidebar scrim closes mobile menu");
assertSource(appSource, /sidebar\.setAttribute\("aria-hidden", open \? "false" : "true"\)/, "mobile sidebar exposes aria-hidden state");
assertSource(appSource, /globalThis\.addEventListener\?\.\("resize", \(\) => syncSidebarSemantics\(\)\)/, "sidebar semantics update on viewport changes");
assertSource(appSource, /let routeRenderToken = 0;/, "route renders have a freshness token");
assertSource(appSource, /const renderToken = \+\+routeRenderToken;/, "route render captures the current freshness token");
assertSource(appSource, /if \(renderToken !== routeRenderToken\) return;\n    mount\(content, node\);/, "stale route renders cannot overwrite current content");
assertSource(appSource, /if \(renderToken !== routeRenderToken\) return;\n    if \(isAuthError\(e\) \|\| isPermissionError\(e\)\)/, "stale route errors cannot overwrite current content");
assertSource(appSource, /import \* as proxy from "\.\/views\/proxy\.js";/, "Proxy/WAF route module is imported");
assertSource(appSource, /\{ path: "\/proxy", title: "Proxy \/ WAF", icon: "globe", view: proxy \}/, "Proxy/WAF route is registered");

for (const action of ["retry-access-gate", "use-local-token", "oidc-sign-in"]) {
  assertControl(appSource, new RegExp(`"data-app-action": "${action}"`), `app action ${action}`);
}

for (const action of ["diff", "validate", "discard", "reload", "review-commit"]) {
  assertControl(appSource, new RegExp(`"data-candidate-bar-action": "${action}"`), `candidate bar ${action}`);
}

for (const action of ["retry"]) {
  assertControl(appSource, new RegExp(`"data-runtime-banner-action": "${action}"`), `runtime banner ${action}`);
}

for (const action of [
  "close-diff",
  "review-commit",
  "close-validation",
  "cancel-commit-prep",
  "commit-candidate",
  "cancel-commit-review",
]) {
  assertControl(appSource, new RegExp(`"data-app-drawer-action": "${action}"`), `app drawer ${action}`);
}

for (const action of ["api-cli", "copy-case", "export-case", "clear-case"]) {
  assertControl(investigationSource, new RegExp(`investigationAction: "${action}"`), `investigation ${action}`);
}

for (const action of ["open", "copy", "remove"]) {
  const pattern = new RegExp(`investigationCaseAction: "${action}"`);
  assertSource(investigationSource, pattern, `investigation case ${action} selector is present`);
  const start = investigationSource.search(pattern);
  const block = investigationSource.slice(Math.max(0, start - 320), start + 420);
  assert.match(block, /"aria-label":/, `investigation case ${action} has aria label`);
  assert.match(block, /title:/, `investigation case ${action} has title`);
}
