import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { runInNewContext } from "node:vm";

const appScript = readFileSync(new URL("../src/onionflash/assets/app.js", import.meta.url), "utf8");

function fixture() {
  const nodes = [
    { dataset: { tags: "directory-authority security tor", search: "authority security report" }, hidden: false },
    { dataset: { tags: "release security tor", search: "security release" }, hidden: false },
    { dataset: { tags: "network tor", search: "network observation" }, hidden: false },
  ];
  const buttons = ["all", "security", "directory-authority", "release", "network"].map((topic) => ({
    dataset: { filter: topic },
    attributes: {},
    setAttribute(key, value) { this.attributes[key] = value; },
    classList: { toggle() {} },
    addEventListener(type, callback) { this[type] = callback; },
  }));
  const tools = { hidden: true, querySelectorAll: () => buttons };
  const search = { value: "", addEventListener(type, callback) { this[type] = callback; } };
  const count = { textContent: "" };
  const empty = { hidden: true };
  const elements = { "news-search": search, "news-list": { querySelectorAll: () => nodes }, "result-count": count, "no-results": empty };
  const document = {
    querySelectorAll: () => [],
    querySelector: () => tools,
    getElementById: (id) => elements[id],
  };
  runInNewContext(appScript, {
    document,
    window: { requestAnimationFrame: (callback) => callback() },
  });
  return { nodes, buttons, tools, search, count, empty };
}

test("Security filter includes both authority and release stories with secondary security tags", () => {
  const ui = fixture();
  ui.buttons.find((button) => button.dataset.filter === "security").click();
  assert.deepEqual(ui.nodes.map((node) => node.hidden), [false, false, true]);
  assert.equal(ui.count.textContent, "2 stories");
  assert.equal(ui.empty.hidden, true);
  assert.equal(ui.tools.hidden, false);
});

test("Topic membership combines with search and can return to all stories", () => {
  const ui = fixture();
  ui.buttons.find((button) => button.dataset.filter === "security").click();
  ui.search.value = "release";
  ui.search.input();
  assert.deepEqual(ui.nodes.map((node) => node.hidden), [true, false, true]);
  assert.equal(ui.count.textContent, "1 story");
  ui.search.value = "";
  ui.buttons.find((button) => button.dataset.filter === "all").click();
  assert.deepEqual(ui.nodes.map((node) => node.hidden), [false, false, false]);
  assert.equal(ui.count.textContent, "3 stories");
});

test("Site menu opens and Escape restores focus on story pages without news filters", () => {
  const toggle = {
    hidden: true,
    attributes: { "aria-expanded": "false" },
    getAttribute(key) { return this.attributes[key]; },
    setAttribute(key, value) { this.attributes[key] = value; },
    addEventListener(type, callback) { this[type] = callback; },
    focus() { this.focused = true; },
  };
  const classes = new Set();
  const navigation = {
    classList: { add(name) { classes.add(name); } },
    addEventListener(type, callback) { this[type] = callback; },
  };
  const elements = { "site-nav": navigation, "site-nav-toggle": toggle };
  runInNewContext(appScript, {
    document: {
      querySelectorAll: () => [],
      querySelector: () => null,
      getElementById: (id) => elements[id],
    },
  });
  assert.equal(toggle.hidden, false);
  assert.equal(classes.has("enhanced"), true);
  toggle.click();
  assert.equal(toggle.getAttribute("aria-expanded"), "true");
  toggle.click();
  assert.equal(toggle.getAttribute("aria-expanded"), "false");
  toggle.click();
  navigation.keydown({ key: "Escape" });
  assert.equal(toggle.getAttribute("aria-expanded"), "false");
  assert.equal(toggle.focused, true);
});
