import assert from "node:assert/strict";
import test from "node:test";

test("live refresh warns on failure and clears the warning after reconnecting", async () => {
  class Element {
    constructor(dataset = {}) { this.dataset = dataset; }
  }
  class InputElement extends Element {}
  class SelectElement extends Element {}
  class ButtonElement extends Element {}

  const warning = { hidden: true };
  const page = new Element({ liveEtag: '"initial"', liveIntervalMs: "3000" });
  page.querySelector = () => null;
  const intervals = [];
  const originalGlobals = {
    document: globalThis.document,
    window: globalThis.window,
    HTMLElement: globalThis.HTMLElement,
    HTMLInputElement: globalThis.HTMLInputElement,
    HTMLSelectElement: globalThis.HTMLSelectElement,
    HTMLButtonElement: globalThis.HTMLButtonElement,
  };
  globalThis.HTMLElement = Element;
  globalThis.HTMLInputElement = InputElement;
  globalThis.HTMLSelectElement = SelectElement;
  globalThis.HTMLButtonElement = ButtonElement;
  globalThis.document = {
    hidden: false,
    addEventListener() {},
    querySelector(selector) {
      return {
        "[data-live-page]": page,
        "[data-connection-warning]": warning,
      }[selector] || null;
    },
    querySelectorAll() { return []; },
  };
  let response = () => Promise.reject(new Error("offline"));
  globalThis.window = {
    location: { href: "https://example.invalid/sessions" },
    history: { replaceState() {} },
    addEventListener() {},
    setInterval(callback) { intervals.push(callback); return intervals.length; },
    fetch() { return response(); },
  };
  try {
    await import(`../static/app.js?connection-warning=${Date.now()}`);
    await intervals[1]();
    assert.equal(warning.hidden, false);
    response = () => Promise.resolve({ status: 304 });
    await intervals[1]();
    assert.equal(warning.hidden, true);
  } finally {
    Object.assign(globalThis, originalGlobals);
  }
});
