import assert from "node:assert/strict";
import { readFileSync, statSync } from "node:fs";

const css = readFileSync("internal/webui/static/css/app.css", "utf8");
const html = readFileSync("internal/webui/static/index.html", "utf8");
const app = readFileSync("internal/webui/static/js/app.js", "utf8");
const core = readFileSync("internal/webui/static/js/core.js", "utf8");
const format = readFileSync("internal/webui/static/js/format.js", "utf8");
const traffic = readFileSync("internal/webui/static/js/views/traffic.js", "utf8");
const threats = readFileSync("internal/webui/static/js/views/threats.js", "utf8");
const rules = readFileSync("internal/webui/static/js/views/rules.js", "utf8");
const dashboard = readFileSync("internal/webui/static/js/views/dashboard.js", "utf8");
const settings = readFileSync("internal/webui/static/js/views/settings.js", "utf8");
const authGate = readFileSync("internal/webui/static/js/auth_gate.js", "utf8");
const performance = readFileSync("internal/webui/static/js/performance.js", "utf8");
const ui = readFileSync("internal/webui/static/js/ui.js", "utf8");
const diagnosticConsole = readFileSync("internal/webui/static/js/diagnostic_console.js", "utf8");
const componentFit = readFileSync("docs/COMPONENT_FIT_REVIEW.md", "utf8");
const buildPlan = readFileSync("docs/build-plan.md", "utf8");
const claude = readFileSync("CLAUDE.md", "utf8");
const logomark = readFileSync("internal/webui/static/assets/phragma-logomark.svg", "utf8");
const wordmark = readFileSync("internal/webui/static/assets/phragma-wordmark.svg", "utf8");

const fontFiles = [
  "chakra-petch-v13-latin-500.ttf",
  "chakra-petch-v13-latin-600.ttf",
  "chakra-petch-v13-latin-700.ttf",
  "ibm-plex-sans-v23-latin-400.ttf",
  "ibm-plex-sans-v23-latin-500.ttf",
  "ibm-plex-sans-v23-latin-600.ttf",
  "ibm-plex-sans-v23-latin-700.ttf",
  "ibm-plex-mono-v20-latin-400.ttf",
  "ibm-plex-mono-v20-latin-500.ttf",
  "ibm-plex-mono-v20-latin-600.ttf",
];

assert.equal((css.match(/@font-face/g) || []).length, fontFiles.length);
assert.doesNotMatch(css, /fonts\.(googleapis|gstatic)\.com/);
for (const file of fontFiles) {
  const path = `internal/webui/static/assets/fonts/${file}`;
  assert.match(css, new RegExp(file.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.ok(statSync(path).size > 4096, `${file} should be vendored`);
}

for (const family of ["Chakra Petch", "IBM Plex Sans", "IBM Plex Mono"]) {
  assert.match(css, new RegExp(`font-family: '${family}'`));
}

for (const token of [
  "--ink-950: #050B14",
  "--signal-400: #37C6F4",
  "--green-400: #41D873",
  "--amber-400: #F4B73A",
  "--red-400: #FF6259",
  "--blue-400: #589BFF",
  "--violet-400: #B07BFF",
]) {
  assert.match(css, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
}

for (const token of [
  "--bg-canvas",
  "--surface",
  "--brand",
  "--allow",
  "--reject",
  "--drop",
  "--change",
  "--status-allow",
  "--status-reject",
  "--status-drop",
  "--status-change",
  "--glow-panel",
  "--glow-allow",
  "--glow-drop",
  "--focus",
  "--focus-soft",
  ".phr-hud",
  ".phr-chamfer",
  ".data-clip",
  ".data-wrap",
  ".surface-zero",
  ".empty-actions",
  "--radius-md",
  "--accent-bg",
]) {
  assert.match(css, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
}

assert.match(css, /--brand:\s*var\(--signal-500\)/);
assert.match(css, /--focus:\s*var\(--ring\)/);
assert.doesNotMatch(css, /--brand:\s*var\(--green/);
assert.match(css, /--allow:\s*var\(--green-400\)/);
assert.match(css, /--reject:\s*var\(--amber-400\)/);
assert.match(css, /--drop:\s*var\(--red-400\)/);

for (const helper of ["statusDot", "badge", "ruleAction", "tag", "metricCard"]) {
  assert.match(ui, new RegExp(`export function ${helper}\\b`));
}

for (const helper of ["keyboardRowAttrs", "handleFocusTrap", "focusableElements"]) {
  assert.match(ui, new RegExp(`export function ${helper}\\b`));
}
assert.match(ui, /role", "dialog"/);
assert.match(ui, /"aria-modal", "true"/);
assert.match(ui, /aria-labelledby/);
assert.match(ui, /drawerReturnFocus/);
assert.match(ui, /handleFocusTrap/);
assert.match(ui, /aria-label": "Close dialog"/);
assert.match(ui, /type: "button", title: "Close dialog", "aria-label": "Close dialog"/);
assert.match(ui, /motionDelay\(180\)/);
assert.match(ui, /classList\.add\("closing"\)/);
assert.match(ui, /aria-label": "Dismiss notification"/);
assert.match(ui, /type: "button", title: "Dismiss notification", "aria-label": "Dismiss notification"/);
assert.match(ui, /class: "empty-actions"/);
assert.doesNotMatch(ui, /style: \{ transition: "all/);
assert.doesNotMatch(ui, /style: \{ marginTop: "14px" \}/);

for (const cls of [
  ".phr-status-dot",
  ".phr-badge",
  ".phr-rule-action",
  ".phr-tag",
  ".phr-metric-card",
]) {
  assert.match(css, new RegExp(cls.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(ui, new RegExp(cls.slice(1)));
}

assert.match(ui, /export function pill[\s\S]*return badge/);
assert.match(ui, /export function tags[\s\S]*tag\(t/);
assert.match(ui, /export function card[\s\S]*phr-card/);

assert.match(html, /<title>Phragma<\/title>/);
assert.match(html, /assets\/phragma-logomark\.svg/);
assert.match(html, /assets\/phragma-wordmark\.svg/);
assert.match(html, /role="dialog" aria-modal="true" aria-label="Command palette"/);
assert.match(html, /role="combobox"/);
assert.match(html, /aria-controls="palette-results"/);
assert.match(html, /aria-activedescendant/);
assert.match(html, /id="palette-results" role="listbox"/);
assert.doesNotMatch(html, /OpenNGFW|OSS-NGFW/);
assert.match(logomark, /linearGradient|radialGradient/);
assert.match(wordmark, /PHRAGMA/);
assert.match(wordmark, /fonts\/chakra-petch-v13-latin-700\.ttf/);

assert.match(buildPlan, /Phragma design\s+system/);
assert.match(claude, /WebUI style rule/);
assert.doesNotMatch(componentFit, /openngfw-(threatd|appid)/);

assert.match(performance, /SCHEMA_VERSION = "phragma\.perf\.v1"/);
assert.match(performance, /LEGACY_SCHEMA_VERSION = "openngfw\.perf\.v1"/);
assert.match(app, /role: "option"/);
assert.match(app, /"aria-selected"/);
assert.match(app, /aria-activedescendant/);
assert.match(app, /paletteReturnFocus/);
assert.match(app, /handleFocusTrap\(e, \$\("#palette-scrim"\)\)/);
assert.match(app, /views\/investigation\.js/);
assert.match(app, /path: "\/investigation"/);
assert.match(app, /Open investigation case/);
assert.match(diagnosticConsole, /aria-modal": "true"/);
assert.match(diagnosticConsole, /aria-labelledby": "diagnostic-console-title"/);
assert.match(diagnosticConsole, /diagnosticReturnFocus/);
assert.match(diagnosticConsole, /handleFocusTrap\(e, document\.querySelector\("#diagnostic-console-scrim \.diag-console"\)\)/);
assert.match(diagnosticConsole, /e\.preventDefault\(\)/);
assert.match(diagnosticConsole, /class: "icon-btn diag-close", type: "button", title: "Close", "aria-label": "Close diagnostic console"/);
assert.doesNotMatch(diagnosticConsole, /diagnostic-readiness/);
assert.match(diagnosticConsole, /title: "Open traffic sessions", "aria-label": "Open traffic sessions", dataset: \{ action: "sessions", sharedControl: "diagnostic-sessions" \}/);
assert.match(app, /function setMenuOpen/);
assert.match(app, /classList\.toggle\("menu-open", open\)/);
assert.match(app, /setAttribute\("aria-expanded", open \? "true" : "false"\)/);
assert.match(app, /setAttribute\("aria-controls", "sidebar"\)/);
assert.match(app, /export function renderNotFound/);
assert.match(core, /this\.onNavigate\(this\.resolve\(\)\)/);
assert.match(dashboard, /throwIfAccessDenied\(statusR, identityR, run, alertsR, flowsR, versR, feedsR\)/);
assert.doesNotMatch(dashboard, /style: \{/);
assert.match(dashboard, /class: "grid"[\s\S]*class: "grid cols-3"[\s\S]*class: "grid cols-4"/);
assert.match(dashboard, /class: "flex wrap"/);
assert.match(dashboard, /class: "dashboard-severity-layout"/);
assert.match(dashboard, /class: "dashboard-severity-chart"/);
assert.match(dashboard, /class: "legend dashboard-severity-legend"/);
assert.match(dashboard, /dashboardSeverityLegend: String\(n\)/);
assert.match(dashboard, /class: `sw dashboard-severity-swatch severity-\$\{n\}`/);
assert.doesNotMatch(dashboard, /class: "legend", style: \{ flexDirection: "column", gap: "8px" \}/);
assert.doesNotMatch(dashboard, /class: "sw", style: \{ background: colors\[n\] \}/);
assert.match(css, /\.dashboard-severity-layout \{/);
assert.match(css, /\.dashboard-severity-chart svg \{/);
assert.match(css, /\.dashboard-severity-legend \{/);
assert.match(css, /\.dashboard-severity-swatch\.severity-1 \{ background: var\(--bad\); \}/);
assert.match(css, /\.dashboard-severity-swatch\.severity-4 \{ background: var\(--text-faint\); \}/);
assert.match(settings, /sessionR/);
assert.match(settings, /throwIfAccessDenied\(statusR, identityR, oidcR, sessionR\)/);
assert.match(settings, /accessPosture: "oidc"/);
assert.match(settings, /accessPostureItem: item\.id/);
assert.match(settings, /class: "icon-btn",\s+type: "button",\s+title: "Copy " \+ panel\.label \+ " settings link"/);
assert.match(authGate, /SAFE_LOGIN_PATHS/);
assert.match(authGate, /export function loginRouteHash/);
assert.match(css, /\.access-posture/);
assert.match(css, /\.access-posture-item\.warn/);
assert.match(css, /tr\.clickable:focus-visible/);
assert.match(css, /\.palette-item:focus-visible/);
assert.match(css, /\.release-evidence-item:focus-visible/);
assert.match(css, /\.toast\.closing/);
assert.match(css, /scrollbar-color:/);
assert.match(css, /\*::-webkit-scrollbar-thumb/);
assert.match(css, /\.table-wrap \{[\s\S]*scrollbar-gutter: stable;/);
assert.match(css, /tbody td \{[\s\S]*overflow-wrap: anywhere;/);
assert.match(css, /--radius:\s*14px/);
assert.match(css, /--radius-lg:\s*22px/);
assert.match(css, /--button-radius:\s*999px/);
assert.match(css, /--hud-grid:\s*none/);
assert.match(css, /--scanlines:\s*none/);
assert.match(css, /html\[data-theme="light"\] \{[\s\S]*--bg: #F7FBFF;/);
assert.match(css, /html\[data-theme="light"\] \{[\s\S]*--panel: #FFFFFF;/);
assert.match(css, /html\[data-theme="light"\] \{[\s\S]*--text: #0B1F33;/);
assert.match(css, /html\[data-theme="light"\] \{[\s\S]*--panel-2: #E7F4FB;/);
assert.match(css, /html\[data-theme="light"\] \{[\s\S]*--accent: #007FB3;/);
assert.match(css, /html\[data-theme="light"\] \.sidebar \{[\s\S]*rgba\(255,255,255,\.98\)/);
assert.match(css, /html\[data-theme="light"\] \.brand-name img \{[\s\S]*brightness\(0\)/);
assert.match(css, /html\[data-theme="light"\] \.topbar \{[\s\S]*rgba\(255,255,255,\.90\)/);
assert.match(css, /\.nav a \{[^}]*border-radius: var\(--button-radius\);/);
assert.doesNotMatch(css, /\.nav a\.active \{[^}]*inset 2px 0 0 var\(--accent\)/);
assert.match(css, /\.search-btn \{[^}]*border-radius: var\(--button-radius\);[^}]*white-space: nowrap;/);
assert.match(css, /\.btn \{[^}]*border-radius: var\(--button-radius\);/);
assert.match(css, /\.chip \{[^}]*border-radius: var\(--button-radius\);/);
assert.match(css, /\.icon-btn \{[^}]*min-width: 36px;[^}]*flex: 0 0 36px;/);
assert.match(css, /\.icon-btn svg \{ width: 18px; height: 18px; flex: none; \}/);
assert.match(css, /\.toolbar > \* \{ min-width: 0; \}/);
assert.match(css, /\.toolbar \.btn,[\s\S]*\.dashboard-engine-actions \.btn \{[^}]*white-space: nowrap;[^}]*text-overflow: ellipsis;/);
assert.match(css, /\.card \.card,[\s\S]*\.phr-card \.telemetry-filters \{[^}]*border-color: var\(--border-subtle\);[^}]*box-shadow: none;/);
assert.match(css, /\.table-wrap \{[^}]*border-radius: var\(--radius\);[^}]*scrollbar-gutter: stable;/);
assert.match(css, /\.row-actions \{[^}]*flex-wrap: nowrap;[^}]*max-width: 100%;/);
assert.match(css, /\.row-actions \.icon-btn \{[^}]*flex: 0 0 32px;[^}]*min-height: 32px;/);
assert.match(css, /\.rules-row-actions \{[\s\S]*max-width: 110px;[\s\S]*flex-wrap: wrap;/);
assert.match(css, /\.rules-actions-cell:has\(\.rules-row-actions \.icon-btn:nth-child\(8\)\) \.rules-row-actions \{[\s\S]*max-width: 145px;/);
assert.match(css, /\.rules-row-actions \.icon-btn \{[^}]*flex: 0 0 34px;[^}]*min-height: 34px;/);
assert.match(css, /\.rules-table \.rules-row-actions \{[\s\S]*flex-wrap: wrap;/);
assert.match(css, /\.responsive-evidence \.row-actions \{ justify-content: flex-start; flex-wrap: wrap; \}/);
for (const selector of [
  "a:focus-visible",
  ".btn:focus-visible",
  ".icon-btn:focus-visible",
  ".nav a:focus-visible",
  ".search-btn:focus-visible",
  ".ghost-btn:focus-visible",
  ".profile-option:focus-visible",
  ".rule-hygiene-chip:focus-visible",
  ".chip button:focus-visible",
  ".toast .t-close:focus-visible",
  "summary:focus-visible",
  ".switch input:focus-visible",
]) {
  assert.match(css, new RegExp(selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
}
assert.match(css, /prefers-reduced-motion:\s*reduce/);
assert.match(css, /body \{ background-attachment: scroll; \}/);
assert.match(css, /\.toast\.closing \{ transform: none; \}/);
assert.match(css, /\.evidence-actions \.btn \{ max-width: 100%; \}/);
assert.match(css, /\.diag-console \{[\s\S]*calc\(100vw - 36px\)/);

assert.match(format, /ACTION_DENY: \{ label: "Drop"/);
for (const source of [traffic, threats, rules]) {
  assert.match(source, /keyboardRowAttrs/);
  assert.doesNotMatch(source, /"Block"/);
  assert.doesNotMatch(source, /"Block this source"/);
  assert.doesNotMatch(source, /"Stage deny rule"/);
  assert.doesNotMatch(source, /"Save & block"/);
  assert.doesNotMatch(source, /"Promote & block"/);
}
