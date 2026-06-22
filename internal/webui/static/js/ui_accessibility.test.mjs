import assert from "node:assert/strict";

import { closeDrawer, handleFocusTrap, keyboardRowAttrs, openDrawer } from "./ui.js";

function keyEvent(key, target = rowTarget(), shiftKey = false) {
  return {
    key,
    target,
    shiftKey,
    prevented: false,
    preventDefault() { this.prevented = true; },
  };
}

function rowTarget() {
  return { closest: () => null };
}

function rowRoleTarget(row) {
  return { closest: () => row };
}

function interactiveTarget() {
  return { closest: () => ({ nodeName: "BUTTON" }) };
}

{
  let activated = 0;
  const attrs = keyboardRowAttrs(() => { activated++; }, { label: "Open row" });
  assert.equal(attrs.role, "button");
  assert.equal(attrs.tabindex, "0");
  assert.equal(attrs["aria-label"], "Open row");

  const enter = keyEvent("Enter");
  attrs.onkeydown(enter);
  assert.equal(activated, 1);
  assert.equal(enter.prevented, true);

  const space = keyEvent(" ");
  attrs.onkeydown(space);
  assert.equal(activated, 2);
  assert.equal(space.prevented, true);

  const arrow = keyEvent("ArrowDown");
  attrs.onkeydown(arrow);
  assert.equal(activated, 2);
  assert.equal(arrow.prevented, false);

  attrs.onclick({ target: rowTarget(), currentTarget: null });
  assert.equal(activated, 3);

  const row = { nodeName: "TR" };
  attrs.onclick({ target: rowRoleTarget(row), currentTarget: row });
  assert.equal(activated, 4);
}

{
  let activated = 0;
  const attrs = keyboardRowAttrs(() => { activated++; });
  const enter = { ...keyEvent("Enter", interactiveTarget()), currentTarget: { nodeName: "TR" } };
  attrs.onkeydown(enter);
  attrs.onclick({ target: interactiveTarget(), currentTarget: { nodeName: "TR" } });
  assert.equal(activated, 0);
  assert.equal(enter.prevented, false);
}

function focusable(name) {
  return {
    name,
    focused: 0,
    focus() { this.focused++; },
    closest() { return null; },
    getAttribute() { return null; },
  };
}

function tabEvent(shiftKey = false) {
  return {
    key: "Tab",
    shiftKey,
    prevented: false,
    preventDefault() { this.prevented = true; },
  };
}

{
  const first = focusable("first");
  const last = focusable("last");
  const root = { querySelectorAll: () => [first, last], contains: (el) => el === first || el === last };

  const forward = tabEvent(false);
  assert.equal(handleFocusTrap(forward, root, last), true);
  assert.equal(forward.prevented, true);
  assert.equal(first.focused, 1);

  const backward = tabEvent(true);
  assert.equal(handleFocusTrap(backward, root, first), true);
  assert.equal(backward.prevented, true);
  assert.equal(last.focused, 1);

  const middle = tabEvent(false);
  assert.equal(handleFocusTrap(middle, root, first), false);
  assert.equal(middle.prevented, false);
}

{
  const first = focusable("first");
  const last = focusable("last");
  const outside = focusable("outside");
  const root = { querySelectorAll: () => [first, last], contains: (el) => el === first || el === last };

  const escapedForward = tabEvent(false);
  assert.equal(handleFocusTrap(escapedForward, root, outside), true);
  assert.equal(escapedForward.prevented, true);
  assert.equal(first.focused, 1);

  const escapedBackward = tabEvent(true);
  assert.equal(handleFocusTrap(escapedBackward, root, outside), true);
  assert.equal(escapedBackward.prevented, true);
  assert.equal(last.focused, 1);
}

{
  const root = {
    focused: 0,
    querySelectorAll: () => [],
    focus() { this.focused++; },
  };
  const event = tabEvent(false);
  assert.equal(handleFocusTrap(event, root, null), true);
  assert.equal(event.prevented, true);
  assert.equal(root.focused, 1);
}

function testElement(name) {
  const el = {
    nodeType: 1,
    name,
    hidden: false,
    children: [],
    parentNode: null,
    dataset: {},
    style: {},
    className: "",
    innerHTML: "",
    focused: 0,
    appendChild(child) {
      this.children.push(child);
      if (child && typeof child === "object") child.parentNode = this;
      return child;
    },
    removeChild(child) {
      this.children = this.children.filter((candidate) => candidate !== child);
      if (child && typeof child === "object") child.parentNode = null;
      return child;
    },
    get firstChild() {
      return this.children[0] || null;
    },
    setAttribute(key, value) {
      this[key] = String(value);
    },
    addEventListener(type, handler) {
      this[`on${type}`] = handler;
    },
    querySelectorAll() {
      return [];
    },
    contains(candidate) {
      if (candidate === this) return true;
      return this.children.some((child) => child?.contains?.(candidate));
    },
    closest() {
      return null;
    },
    focus() {
      this.focused++;
      if (globalThis.document) globalThis.document.activeElement = this;
    },
  };
  return el;
}

function installDrawerDom() {
  const scrim = testElement("drawer-scrim");
  const drawer = testElement("drawer");
  const active = testElement("active");
  scrim.hidden = true;
  drawer.hidden = true;
  globalThis.document = {
    activeElement: active,
    createElement: testElement,
    createTextNode(text) {
      return { nodeType: 3, textContent: String(text) };
    },
    addEventListener(type, handler) {
      this[`on${type}`] = handler;
    },
    removeEventListener(type) {
      this[`on${type}`] = null;
    },
    contains(el) {
      return el === active || drawer.contains(el) || scrim.contains(el);
    },
    querySelector(selector) {
      if (selector === "#drawer-scrim") return scrim;
      if (selector === "#drawer") return drawer;
      return null;
    },
  };
  return { active, drawer, scrim };
}

{
  const { active, drawer, scrim } = installDrawerDom();
  let closed = 0;
  openDrawer({ title: "Test drawer", body: "body", onClose: () => { closed++; } });

  assert.equal(drawer.hidden, false);
  assert.equal(scrim.hidden, false);
  assert.equal(drawer.focused, 1);
  closeDrawer();
  assert.equal(drawer.hidden, true);
  assert.equal(scrim.hidden, true);
  assert.equal(closed, 1);
  assert.equal(active.focused, 1);
  assert.equal(globalThis.document.onkeydown, null);
}

{
  const { drawer, scrim } = installDrawerDom();
  let closed = 0;
  openDrawer({ title: "Silent drawer", body: "body", onClose: () => { closed++; } });

  closeDrawer({ invokeOnClose: false });
  assert.equal(drawer.hidden, true);
  assert.equal(scrim.hidden, true);
  assert.equal(closed, 0);
}

{
  const { active, drawer, scrim } = installDrawerDom();
  let closed = 0;
  openDrawer({ title: "Keyboard drawer", body: "body", onClose: () => { closed++; } });

  const event = {
    key: "Escape",
    prevented: false,
    preventDefault() { this.prevented = true; },
  };
  globalThis.document.onkeydown(event);
  assert.equal(event.prevented, true);
  assert.equal(drawer.hidden, true);
  assert.equal(scrim.hidden, true);
  assert.equal(closed, 1);
  assert.equal(active.focused, 1);
  assert.equal(globalThis.document.onkeydown, null);
}

{
  const { active, drawer } = installDrawerDom();
  let firstClosed = 0;
  let secondClosed = 0;
  openDrawer({ title: "First drawer", body: "first", onClose: () => { firstClosed++; } });
  assert.equal(globalThis.document.activeElement, drawer);

  openDrawer({ title: "Second drawer", body: "second", onClose: () => { secondClosed++; } });
  assert.equal(firstClosed, 1);
  assert.equal(drawer.hidden, false);

  closeDrawer();
  assert.equal(secondClosed, 1);
  assert.equal(active.focused, 1);
  assert.equal(globalThis.document.activeElement, active);
}
