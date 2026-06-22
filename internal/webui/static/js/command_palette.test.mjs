import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const app = readFileSync(new URL("./app.js", import.meta.url), "utf8");

assert.match(app, /const PALETTE_VISIBLE_LIMIT = 40/);
assert.match(app, /label: "Open API contract"/);
assert.match(app, /API_CONTRACT\.path/);
assert.match(app, /paletteItems\.slice\(0, PALETTE_VISIBLE_LIMIT\)/);
assert.match(app, /function clampPaletteIndex\(next\)/);
assert.match(app, /Math\.max\(visiblePaletteLength\(\) - 1, 0\)/);
assert.match(app, /ArrowDown"\) \{ e\.preventDefault\(\); paletteActive = clampPaletteIndex\(paletteActive \+ 1\); paintPalette\(\); \}/);
assert.match(app, /ArrowUp"\) \{ e\.preventDefault\(\); paletteActive = clampPaletteIndex\(paletteActive - 1\); paintPalette\(\); \}/);
assert.doesNotMatch(app, /paletteActive = Math\.min\(paletteActive \+ 1, paletteItems\.length - 1\)/);
