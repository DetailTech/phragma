const { deserialize, serialize } = require("node:v8");

if (typeof globalThis.structuredClone !== "function") {
  globalThis.structuredClone = (value) => deserialize(serialize(value));
}
