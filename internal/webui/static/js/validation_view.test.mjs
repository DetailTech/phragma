import assert from "node:assert/strict";

class FakeElement {
  constructor(tag) {
    this.tagName = String(tag || "").toUpperCase();
    this.nodeType = 1;
    this.children = [];
    this.attributes = {};
    this.dataset = {};
    this.style = {};
    this.className = "";
    this.innerHTML = "";
  }
  appendChild(child) {
    this.children.push(child);
    return child;
  }
  setAttribute(key, value) {
    this.attributes[key] = String(value);
  }
}

class FakeText {
  constructor(text) {
    this.nodeType = 3;
    this.textContent = String(text);
  }
}

globalThis.document = {
  createElement: (tag) => new FakeElement(tag),
  createTextNode: (text) => new FakeText(text),
};

const { renderValidationEvidence, validationErrors } = await import("./validation_view.js");

function walk(node, out = []) {
  out.push(node);
  for (const child of node.children || []) walk(child, out);
  return out;
}

{
  const root = renderValidationEvidence({
    valid: true,
    findings: Array.from({ length: 14 }, (_, i) => ({
      severity: i % 2 ? 2 : 3,
      stage: "VALIDATION_STAGE_RENDER",
      message: `finding ${i}`,
      fieldPath: `rules[${i}]`,
    })),
    renderPlan: {
      artifactCount: 9,
      totalBytes: 900,
      artifacts: Array.from({ length: 9 }, (_, i) => ({ name: `artifact-${i}`, sizeBytes: 100 })),
    },
  });

  const nodes = walk(root);
  assert.equal(nodes.filter((node) => node.className === "impact-list impact-list-scroll").length, 2);
  assert.equal(nodes.filter((node) => node.className === "impact-list").length, 0);
  assert.equal(nodes.filter((node) => /^impact-row/.test(node.className || "")).length, 23);
}

{
  const errors = validationErrors({
    valid: false,
    findings: [{
      severity: "VALIDATION_SEVERITY_ERROR",
      stage: "VALIDATION_STAGE_IMPACT",
      message: "High-risk impact",
      fieldPath: "rules[0]",
      detail: "Commit requires acknowledgement.",
    }],
  });

  assert.equal(errors.length, 1);
  assert.match(errors[0], /High-risk impact/);
  assert.match(errors[0], /rules\[0\]/);
  assert.match(errors[0], /Commit requires acknowledgement/);
}
