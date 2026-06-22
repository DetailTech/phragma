import assert from "node:assert/strict";

import {
  EVIDENCE_TABLE_SCHEMA,
  apiRequestText,
  cliRequestText,
  evidenceToolbar,
  evidenceFilename,
  evidencePayloadJson,
  evidenceRowsCsv,
  evidenceTablePayload,
} from "./evidence_toolbar.js";
import { SUPPORT_BUNDLE_REDACTED } from "./support_bundle.js";

const rows = [
  { id: "one", app: { name: "dns" }, note: "simple", bytes: 42 },
  { id: "two", app: { name: "web,browser" }, note: "quoted \"value\"", bytes: 7 },
];

{
  const payload = evidenceTablePayload({
    surface: "traffic-flows",
    title: "Traffic flows",
    route: "#/traffic?app=dns",
    request: { limit: 500, app: "dns" },
    rows,
    collectedAt: "2026-06-18T12:00:00Z",
  });

  assert.equal(payload.schemaVersion, EVIDENCE_TABLE_SCHEMA);
  assert.equal(payload.surface, "traffic-flows");
  assert.equal(payload.source.route, "#/traffic?app=dns");
  assert.equal(payload.request.app, "dns");
  assert.equal(payload.result.rowCount, 2);
  assert.equal(payload.result.includedRows, 2);
  assert.equal(payload.rows[0].app.name, "dns");
  assert.match(evidencePayloadJson(payload), /phragma\.evidence\.table\.v1/);
}

{
  const payload = evidenceTablePayload({
    surface: "audit-log",
    title: "Audit log",
    request: { query: "source=/Users/alice/openngfw/import.json" },
    rows: [{
      detail: "kind=app-id source='/Users/alice/openngfw/import.json' rollback_path='/var/lib/openngfw/content/app-id/.rollback/app-id-1'",
      logDir: "/var/log/openngfw",
    }],
    collectedAt: "2026-06-18T12:00:00Z",
  });
  const json = evidencePayloadJson(payload);
  assert.equal(payload.request.query.includes("/Users/"), false);
  assert.equal(payload.rows[0].detail.includes("/Users/"), false);
  assert.equal(payload.rows[0].detail.includes("/var/lib/"), false);
  assert.equal(payload.rows[0].logDir, SUPPORT_BUNDLE_REDACTED);
  assert.equal(json.includes("/Users/"), false);
  assert.equal(json.includes("/var/lib/"), false);
}

{
  const csv = evidenceRowsCsv(rows, [
    { key: "id", label: "ID" },
    { key: "app.name", label: "App" },
    { key: "note", label: "Note" },
    { key: "bytes", label: "Bytes" },
  ]);
  assert.equal(csv.split("\n")[0], "ID,App,Note,Bytes");
  assert.match(csv, /two,"web,browser","quoted ""value""",7/);
}

{
  const csv = evidenceRowsCsv([
    { detail: "source=/home/opc/openngfw/import.json", dataDir: "/var/lib/openngfw" },
  ], [
    { key: "detail", label: "Detail" },
    { key: "dataDir", label: "Data dir" },
  ]);
  assert.equal(csv.includes("/home/"), false);
  assert.equal(csv.includes("/var/lib/"), false);
  assert.match(csv, new RegExp(SUPPORT_BUNDLE_REDACTED.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
}

{
  assert.equal(apiRequestText("/v1/flows", { limit: 500, app: "dns", empty: "" }), "GET /v1/flows?limit=500&app=dns\n");
  assert.equal(cliRequestText(" ngfwctl flows --limit 500 "), "ngfwctl flows --limit 500\n");
  assert.equal(cliRequestText(""), "");
  assert.equal(evidenceFilename("traffic flows", "json", new Date("2026-06-18T12:00:00.123Z")), "phragma-traffic-flows-evidence-2026-06-18T12-00-00-123Z.json");
}

{
  class FakeText {
    constructor(text) {
      this.nodeType = 3;
      this.textContent = String(text);
    }
  }
  class FakeElement {
    constructor(tag) {
      this.tag = tag;
      this.nodeType = 1;
      this.children = [];
      this.className = "";
      this.attributes = {};
      this.dataset = {};
      this.style = {};
      this._text = "";
    }
    appendChild(child) {
      this.children.push(child);
      return child;
    }
    setAttribute(key, value) {
      this.attributes[key] = String(value);
    }
    addEventListener() {}
    set innerHTML(value) {
      this._text += String(value);
    }
    get textContent() {
      return this._text + this.children.map((child) => child.textContent || "").join("");
    }
  }
  globalThis.document = {
    createElement: (tag) => new FakeElement(tag),
    createTextNode: (text) => new FakeText(text),
  };

  const withoutCli = evidenceToolbar({ title: "Traffic evidence", apiPath: "/v1/flows" });
  assert.doesNotMatch(withoutCli.textContent, /Copy CLI/);

  const withCli = evidenceToolbar({ title: "Traffic evidence", apiPath: "/v1/flows", cliCommand: "ngfwctl flows --limit 500" });
  assert.match(withCli.textContent, /Copy CLI/);
  const actions = {};
  function collect(node) {
    if (!node) return;
    const action = node.attributes?.["data-evidence-action"] || node.dataset?.evidenceAction || "";
    if (action) actions[action] = node.attributes;
    for (const child of node.children || []) collect(child);
  }
  collect(withCli);
  assert.equal(actions["copy-link"].type, "button");
  assert.equal(actions["copy-link"]["aria-label"], "Copy Traffic evidence filtered view link");
  assert.equal(actions["copy-api"].type, "button");
  assert.equal(actions["copy-api"]["aria-label"], "Copy Traffic evidence REST request");
  assert.equal(actions["copy-cli"].type, "button");
  assert.equal(actions["copy-cli"]["aria-label"], "Copy Traffic evidence ngfwctl command");
  assert.equal(actions["export-json"].type, "button");
  assert.equal(actions["export-json"]["aria-label"], "Download Traffic evidence as JSON");
}
