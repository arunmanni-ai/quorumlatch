import assert from "node:assert/strict";
import test from "node:test";
import { extractDemoEvent } from "../src/extractor.js";

test("explicit readback wins over repeated operation noun", () => {
  const event = extractDemoEvent({
    turnOrder: 2,
    speaker: "B",
    transcript: "Confirm incision on the right knee.",
    observedAt: 2_000,
    observedMono: 2_000
  });
  assert.equal(event?.action, "CONFIRM");
  assert.equal(event?.slots.site, "right knee");
});

test("vague assent never becomes safety evidence", () => {
  const event = extractDemoEvent({
    turnOrder: 2,
    speaker: "B",
    transcript: "Yes, go ahead.",
    observedAt: 2_000,
    observedMono: 2_000
  });
  assert.equal(event, null);
});
