import assert from "node:assert/strict";

class FakeElement {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.nodeType = 1;
    this.children = [];
    this.style = {
      _props: {},
      setProperty(name, value) {
        this._props[name] = String(value);
      },
      getPropertyValue(name) {
        return this._props[name] || "";
      },
    };
    this.attributes = {};
    this.className = "";
    this._text = "";
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  setAttribute(name, value) {
    this.attributes[name] = String(value);
  }

  getAttribute(name) {
    return this.attributes[name] || "";
  }

  set textContent(value) {
    this._text = String(value);
  }

  get textContent() {
    return this._text + this.children.map((c) => c.textContent || "").join("");
  }
}

globalThis.document = {
  documentElement: new FakeElement("html"),
  head: new FakeElement("head"),
  createElement: (tag) => new FakeElement(tag),
};
globalThis.getComputedStyle = () => ({
  getPropertyValue: () => "",
});

const { hbars } = await import("./charts.js");

function walk(node, out = []) {
  out.push(node);
  for (const child of node.children || []) walk(child, out);
  return out;
}

{
  const malicious = `"><img src=x onerror=alert(1)>`;
  const chart = hbars([{ label: malicious, value: 10, valueLabel: malicious, sub: malicious }]);

  assert.equal(chart.className, "hbars");
  assert.equal(chart.textContent, malicious + malicious + malicious);
  assert.equal(walk(chart).some((node) => node.tagName === "IMG"), false);
  assert.equal(walk(chart).some((node) => "innerHTML" in node), false);
}

{
  const chart = hbars([{ label: "safe", value: 1, color: "url(javascript:alert(1))" }], { color: "#38bdf8" });
  const fill = walk(chart).find((node) => node.className === "hbar-fill");
  assert.equal(fill.style.getPropertyValue("--hbar-fill-color"), "#38bdf8");
  assert.equal(fill.style.getPropertyValue("--hbar-fill-width"), "100%");
  assert.equal(fill.getAttribute("role"), "progressbar");
  assert.equal(fill.getAttribute("aria-valuenow"), "100");
}

{
  const chart = hbars([{ label: "10.0.0.5", value: 42, href: "#/traffic?mode=flows&ip=10.0.0.5" }]);
  const link = walk(chart).find((node) => node.tagName === "A");
  assert.equal(link.className, "hbar-label");
  assert.equal(link.href, "#/traffic?mode=flows&ip=10.0.0.5");
  assert.equal(link.textContent, "10.0.0.5");
}
