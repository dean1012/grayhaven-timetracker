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
