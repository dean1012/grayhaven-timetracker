import assert from "node:assert/strict";
import test from "node:test";

import {
  isDirtyLiveControl,
  roundedCostCents,
  sessionCostCents,
  shouldDeferLiveReplacement,
  summarizeReportSessions,
} from "../static/report-helpers.mjs";

test("unchanged selects remain refreshable and edited selections defer", () => {
  const control = {
    tagName: "SELECT",
    options: [
      { selected: true, defaultSelected: false },
      { selected: false, defaultSelected: false },
    ],
  };
  assert.equal(isDirtyLiveControl(control), false);
  control.options[0].selected = false;
  control.options[1].selected = true;
  assert.equal(isDirtyLiveControl(control), true);
  control.options[1].defaultSelected = true;
  assert.equal(isDirtyLiveControl(control), false);
});

test("checkbox edits and text drafts defer while hidden tokens do not", () => {
  assert.equal(isDirtyLiveControl({
    type: "checkbox", checked: true, defaultChecked: false, value: "on",
  }), true);
  assert.equal(isDirtyLiveControl({
    type: "checkbox", checked: false, defaultChecked: false, value: "on",
  }), false);
  assert.equal(isDirtyLiveControl({
    type: "text", value: "draft", defaultValue: "",
  }), true);
  assert.equal(isDirtyLiveControl({
    type: "hidden", value: "new-token", defaultValue: "old-token",
  }), false);
});

test("rounds each session amount half up before summing", () => {
  assert.equal(sessionCostCents(60, 5500), 92);
  assert.equal(
    summarizeReportSessions([{ seconds: 60 }, { seconds: 60 }], 5500).costCents,
    184,
  );
});

test("uses exact integer arithmetic for half cent boundaries", () => {
  assert.equal(roundedCostCents(1, 1800), 1);
  assert.equal(roundedCostCents(1, 1799), 0);
  assert.deepEqual(
    summarizeReportSessions([{ seconds: 3600 }, { seconds: 1800 }], 12345),
    {
      rows: [
        { seconds: 3600, costCents: 12345 },
        { seconds: 1800, costCents: 6173 },
      ],
      seconds: 5400,
      costCents: 18518,
    },
  );
});

test("defers a live replacement while work could be lost", () => {
  assert.equal(
    shouldDeferLiveReplacement({ dirty: false, focused: false, openDisclosure: false }),
    false,
  );
  assert.equal(
    shouldDeferLiveReplacement({ dirty: true, focused: false, openDisclosure: false }),
    true,
  );
  assert.equal(
    shouldDeferLiveReplacement({ dirty: false, focused: true, openDisclosure: false }),
    true,
  );
  assert.equal(
    shouldDeferLiveReplacement({ dirty: false, focused: false, openDisclosure: true }),
    true,
  );
  const editorState = { dirty: true, focused: true, openDisclosure: true };
  assert.equal(shouldDeferLiveReplacement(editorState), true);
  editorState.dirty = false;
  editorState.focused = false;
  editorState.openDisclosure = false;
  assert.equal(shouldDeferLiveReplacement(editorState), false);
});

test("running timer refresh updates total, cost, and today's daily row", async () => {
  class Element {
    constructor(dataset = {}) {
      this.dataset = dataset;
      this.textContent = "";
    }
  }
  class SelectElement extends Element {}
  class ButtonElement extends Element {}
  class InputElement extends Element {}

  const totalDuration = new Element();
  const totalCost = new Element();
  const dayDuration = new Element({ baseSeconds: "90" });
  const dayCost = new Element({ baseCostCents: "100" });
  const dayRow = new Element({ pendingDay: new Date().toISOString().slice(0, 10) });
  dayRow.querySelector = (selector) => ({
    "[data-pending-day-duration]": dayDuration,
    "[data-pending-day-cost]": dayCost,
  })[selector] || null;
  const summary = new Element({
    snapshotAt: "2026-01-01T00:00:00Z",
    baseTotalSeconds: "100",
    baseTotalCostCents: "200",
    runningBaseSeconds: "10",
    runningRateCents: "3600",
  });
  summary.querySelector = (selector) => ({
    "[data-pending-total-duration]": totalDuration,
    "[data-pending-total-cost]": totalCost,
  })[selector] || null;
  const daily = new Element({
    pendingTimezone: "UTC",
    snapshotDay: new Date().toISOString().slice(0, 10),
  });
  daily.querySelectorAll = (selector) =>
    selector === "[data-pending-day]" ? [dayRow] : [];
  const intervals = [];
  const storage = new Map();
  let reloads = 0;

  const originalNow = Date.now;
  const originalGlobals = {
    document: globalThis.document,
    window: globalThis.window,
    HTMLElement: globalThis.HTMLElement,
    HTMLSelectElement: globalThis.HTMLSelectElement,
    HTMLButtonElement: globalThis.HTMLButtonElement,
    HTMLInputElement: globalThis.HTMLInputElement,
  };
  Date.now = () => Date.parse("2026-01-01T00:00:05Z");
  globalThis.HTMLElement = Element;
  globalThis.HTMLSelectElement = SelectElement;
  globalThis.HTMLButtonElement = ButtonElement;
  globalThis.HTMLInputElement = InputElement;
  globalThis.document = {
    hidden: false,
    activeElement: null,
    addEventListener() {},
    querySelector(selector) {
      if (selector === "[data-pending-live-summary]") return summary;
      if (selector === "[data-pending-live-daily]") return daily;
      return null;
    },
    querySelectorAll() { return []; },
  };
  globalThis.window = {
    location: {
      href: "https://example.invalid/sessions",
      origin: "https://example.invalid",
      pathname: "/sessions",
      search: "",
      reload() { reloads += 1; },
    },
    sessionStorage: {
      getItem(key) { return storage.get(key) || null; },
      setItem(key, value) { storage.set(key, value); },
    },
    history: { replaceState() {} },
    addEventListener() {},
    setInterval(callback) { intervals.push(callback); return 1; },
    setTimeout() { return 1; },
    clearInterval() {},
  };
  try {
    await import(`../static/app.js?daily-summary=${Date.now()}`);
    assert.equal(totalDuration.textContent, "0:01:45");
    assert.equal(totalCost.textContent, "$2.05");
    assert.equal(dayDuration.textContent, "00:01:35");
    assert.equal(dayCost.textContent, "$1.05");
    daily.dataset.snapshotDay = "2025-12-31";
    intervals[0]();
    intervals[0]();
    assert.equal(reloads, 1);
  } finally {
    Date.now = originalNow;
    Object.assign(globalThis, originalGlobals);
  }
});
