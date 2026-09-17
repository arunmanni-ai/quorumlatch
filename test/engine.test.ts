import assert from "node:assert/strict";
import test from "node:test";
import { DEFAULT_INVARIANT, type SessionState, type VoiceEvent } from "../src/domain.js";
import { evaluateEvent } from "../src/engine.js";

function session(): SessionState {
  return {
    id: "test",
    invariantId: DEFAULT_INVARIANT.id,
    mode: "demo",
    status: "LOCKED",
    policyHash: "test-policy",
    generation: 0,
    expiresAt: Date.now() + 60_000,
    challenge: "amber 42",
    turns: [],
    evidence: {}
  };
}

function event(overrides: Partial<VoiceEvent>): VoiceEvent {
  return {
    turnOrder: 1,
    speaker: "A",
    transcript: "Initiate incision on the right knee",
    observedAt: 1_000,
    observedMono: 1_000,
    action: "INCISION",
    slots: { site: "right knee", challenge: "amber 42" },
    confidence: 0.99,
    evidenceQuote: "incision on the right knee",
    actionEvidence: "incision",
    slotEvidence: { site: "right knee", challenge: "amber 42" },
    extractor: "deterministic-demo",
    ...overrides
  };
}

test("rejects wrong-site command", () => {
  const state = session();
  const result = evaluateEvent(DEFAULT_INVARIANT, state, event({ slots: { site: "left knee", challenge: "amber 42" } }));
  assert.equal(result.type, "REJECTED");
  assert.equal(Object.keys(state.evidence).length, 0);
});

test("requires explicit matching second-speaker readback", () => {
  const state = session();
  assert.equal(evaluateEvent(DEFAULT_INVARIANT, state, event({})).type, "STEP_MATCHED");
  const result = evaluateEvent(
    DEFAULT_INVARIANT,
    state,
    event({
      turnOrder: 2,
      speaker: "B",
      transcript: "Confirm incision on the right knee",
      observedAt: 5_000,
      action: "CONFIRM"
    })
  );
  assert.equal(result.type, "SATISFIED");
  assert.equal(Object.keys(state.evidence).length, 2);
});

test("new initiating command invalidates the old partial quorum", () => {
  const state = session();
  evaluateEvent(DEFAULT_INVARIANT, state, event({}));
  const result = evaluateEvent(DEFAULT_INVARIANT, state, event({ turnOrder: 2, observedAt: 3_000 }));
  assert.equal(result.type, "STEP_MATCHED");
  assert.equal(Object.keys(state.evidence).length, 1);
});
