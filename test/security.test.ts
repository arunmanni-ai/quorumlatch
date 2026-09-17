import assert from "node:assert/strict";
import { createHmac, randomUUID } from "node:crypto";
import test from "node:test";
import type { AssemblyAI } from "assemblyai";
import { DEFAULT_INVARIANT, type SessionState, type VoiceEvent } from "../src/domain.js";
import { evaluateEvent } from "../src/engine.js";
import { extractWithGateway } from "../src/extractor.js";
import { SessionRuntime } from "../src/runtime.js";
import { permitsUnauthenticatedDemo, tokenDigest, tokenMatches, validateInvariant } from "../src/security.js";
import { store } from "../src/store.js";
import { deliverUnlock, isPublicWebhookAddress } from "../src/webhook.js";
import { SignedMockActuator, signedMockActuator } from "../src/mock-actuator.js";

function policy(id: string) {
  const value = structuredClone(DEFAULT_INVARIANT);
  value.id = id;
  return value;
}

function event(state: SessionState, overrides: Partial<VoiceEvent> = {}): VoiceEvent {
  return {
    turnOrder: 1,
    speaker: "A",
    transcript: `Initiate incision on the right knee. Authorization code ${state.challenge}.`,
    observedAt: Date.now(),
    observedMono: 1_000,
    action: "INCISION",
    slots: { site: "right knee", challenge: state.challenge },
    confidence: 0.99,
    evidenceQuote: "incision on the right knee",
    actionEvidence: "incision",
    slotEvidence: { site: "right knee", challenge: state.challenge },
    extractor: "deterministic-demo",
    ...overrides
  };
}

test("capability tokens are compared by digest", () => {
  const expected = tokenDigest("correct horse battery staple 1234");
  assert.equal(tokenMatches("correct horse battery staple 1234", expected), true);
  assert.equal(tokenMatches("wrong", expected), false);
  assert.equal(tokenMatches(undefined, expected), false);
});

test("policy validation rejects a fake quorum using one speaker", () => {
  const value = policy("same-speaker-attack");
  value.steps[1]!.speaker = "A";
  assert.throws(() => validateInvariant(value), /distinct speaker/);
});

test("policy validation rejects arbitrary webhook destinations", () => {
  const value = policy("ssrf-attack");
  value.webhook = { url: "https://127.0.0.1/internal", secret: "x".repeat(32) };
  assert.throws(() => validateInvariant(value), /not in QUORUMLATCH_WEBHOOK_HOSTS/);
});

test("policy validation rejects alternate ports on an allowlisted webhook host", () => {
  const previous = process.env.QUORUMLATCH_WEBHOOK_HOSTS;
  process.env.QUORUMLATCH_WEBHOOK_HOSTS = "receiver.example";
  try {
    const value = policy("alternate-port-attack");
    value.webhook = { url: "https://receiver.example:8443/unlock", secret: "x".repeat(32) };
    assert.throws(() => validateInvariant(value), /default HTTPS port/);
  } finally {
    if (previous === undefined) delete process.env.QUORUMLATCH_WEBHOOK_HOSTS;
    else process.env.QUORUMLATCH_WEBHOOK_HOSTS = previous;
  }
});

test("webhook connection guard blocks private, loopback, mapped, and documentation addresses", () => {
  assert.equal(isPublicWebhookAddress("127.0.0.1", 4), false);
  assert.equal(isPublicWebhookAddress("10.4.3.2", 4), false);
  assert.equal(isPublicWebhookAddress("192.0.2.10", 4), false);
  assert.equal(isPublicWebhookAddress("::1", 6), false);
  assert.equal(isPublicWebhookAddress("::ffff:127.0.0.1", 6), false);
  assert.equal(isPublicWebhookAddress("8.8.8.8", 4), true);
  assert.equal(isPublicWebhookAddress("2606:4700:4700::1111", 6), true);
});

test("signed mock actuator verifies HMAC, TTL, and one-time use", () => {
  const actuator = new SignedMockActuator();
  const secret = "mock-receiver-secret-with-at-least-32-characters";
  const issuedAt = Date.now();
  const body = JSON.stringify({
    type: "quorumlatch.unlock_granted",
    unlockId: randomUUID(),
    sessionId: randomUUID(),
    generation: 1,
    policyHash: "a".repeat(64),
    issuedAt,
    validUntil: issuedAt + 1_000,
    authorization: "ONE_TIME",
    evidenceDigest: "b".repeat(64)
  });
  const signature = createHmac("sha256", secret).update(body).digest("hex");
  actuator.receive(body, `sha256=${signature}`, secret);
  assert.equal(actuator.publicState().status, "UNLOCKED");
  assert.throws(() => actuator.receive(body, `sha256=${signature}`, secret), /replayed capsule/);
  assert.equal(actuator.publicState().status, "LOCKED");
});

test("signed mock actuator rejects forged capsules", () => {
  const actuator = new SignedMockActuator();
  assert.throws(
    () => actuator.receive("{}", `sha256=${"0".repeat(64)}`, "x".repeat(32)),
    /signature/
  );
  assert.equal(actuator.publicState().status, "LOCKED");
});

test("Live delivery sends a signed capsule through the mock receiver contract", async () => {
  const state = store.createSession(DEFAULT_INVARIANT.id, "demo");
  state.mode = "live";
  const first = event(state);
  const second = event(state, {
    turnOrder: 2,
    speaker: "B",
    action: "CONFIRM",
    observedMono: 2_000
  });
  state.evidence["operator-command"] = { ...first, stepId: "operator-command" };
  state.evidence["independent-readback"] = { ...second, stepId: "independent-readback" };
  const invariant = structuredClone(DEFAULT_INVARIANT);
  invariant.webhook = {
    url: "mock://signed-actuator",
    secret: "integrated-mock-receiver-secret-0123456789"
  };
  const receipt = await deliverUnlock(invariant, state, new AbortController().signal, true);
  assert.equal(receipt.delivery, "signed-mock");
  assert.equal(signedMockActuator.publicState().unlockId, receipt.unlockId);
  store.deleteSession(state.id);
});

test("reverse-proxy loopback cannot enable unauthenticated Demo Mode", () => {
  assert.equal(permitsUnauthenticatedDemo("127.0.0.1", "127.0.0.1"), true);
  assert.equal(permitsUnauthenticatedDemo("0.0.0.0", "127.0.0.1"), false);
});

test("prototype-chain step identifiers cannot bypass the first quorum step", () => {
  const value = policy(`reserved-step-${Date.now()}`);
  value.steps[0]!.id = "constructor";
  value.steps[1]!.after = "constructor";
  value.steps[1]!.slots.site = { equals: "right knee" };
  const invariant = validateInvariant(value);
  const state = store.createSession(DEFAULT_INVARIANT.id, "demo");
  const result = evaluateEvent(invariant, state, event(state, {
    speaker: "B",
    action: "CONFIRM",
    slots: { site: "right knee", challenge: state.challenge }
  }));
  assert.equal(result.type, "REJECTED");
  assert.equal(Object.keys(state.evidence).length, 0);
  store.deleteSession(state.id);
});

test("an active session retains an immutable policy snapshot", () => {
  const id = `immutable-${Date.now()}`;
  const first = policy(id);
  store.putInvariant(first);
  const state = store.createSession(id, "demo");
  const second = policy(id);
  second.steps[0]!.slots.site = { equals: "left knee" };
  store.putInvariant(second);
  assert.deepEqual(store.invariantFor(state).steps[0]!.slots.site, { equals: "right knee" });
  store.deleteSession(state.id);
});

test("missing freshness challenge cannot satisfy policy", () => {
  const state = store.createSession(DEFAULT_INVARIANT.id, "demo");
  const result = evaluateEvent(DEFAULT_INVARIANT, state, event(state, { slots: { site: "right knee" } }));
  assert.equal(result.type, "REJECTED");
  assert.equal(Object.keys(state.evidence).length, 0);
  store.deleteSession(state.id);
});

test("a conflicting explicit event clears partial authorization", () => {
  const state = store.createSession(DEFAULT_INVARIANT.id, "demo");
  assert.equal(evaluateEvent(DEFAULT_INVARIANT, state, event(state)).type, "STEP_MATCHED");
  const conflict = event(state, {
    turnOrder: 2,
    speaker: "B",
    action: "CONFIRM",
    slots: { site: "left knee", challenge: state.challenge },
    observedMono: 2_000
  });
  assert.equal(evaluateEvent(DEFAULT_INVARIANT, state, conflict).type, "RESET");
  assert.equal(Object.keys(state.evidence).length, 0);
  store.deleteSession(state.id);
});

test("reset wins over an in-flight authorization", async () => {
  const state = store.createSession(DEFAULT_INVARIANT.id, "demo");
  const runtime = new SessionRuntime(state, store.invariantFor(state));
  await runtime.start();
  await runtime.injectDemoTurn("A", `Initiate incision on the right knee. Authorization code ${state.challenge}.`);
  const pending = runtime.injectDemoTurn("B", `Confirm incision on the right knee. Authorization code ${state.challenge}.`);
  await new Promise((resolve) => setTimeout(resolve, 30));
  runtime.reset("Security test reset");
  await pending;
  assert.equal(state.status, "LOCKED");
  assert.equal(state.receipt, undefined);
  await runtime.close();
  store.deleteSession(state.id);
});

test("reset discards a turn that was queued before the reset", async () => {
  const state = store.createSession(DEFAULT_INVARIANT.id, "demo");
  const runtime = new SessionRuntime(state, store.invariantFor(state));
  await runtime.start();
  const pending = runtime.injectDemoTurn("A", `Initiate incision on the right knee. Authorization code ${state.challenge}.`);
  runtime.reset("Reset before queued work executes");
  await pending;
  assert.equal(Object.keys(state.evidence).length, 0);
  assert.equal(state.status, "LOCKED");
  await runtime.close();
  store.deleteSession(state.id);
});

test("Demo Mode cannot call a configured production webhook", async () => {
  const state = store.createSession(DEFAULT_INVARIANT.id, "demo");
  const unsafePolicy = structuredClone(store.invariantFor(state));
  unsafePolicy.webhook = { url: "https://example.invalid/unlock", secret: "x".repeat(32) };
  const runtime = new SessionRuntime(state, unsafePolicy);
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; throw new Error("Network must not be called"); };
  try {
    await runtime.start();
    await runtime.injectDemoTurn("A", `Initiate incision on the right knee. Authorization code ${state.challenge}.`);
    await runtime.injectDemoTurn("B", `Confirm incision on the right knee. Authorization code ${state.challenge}.`);
    assert.equal(calls, 0);
    assert.equal(state.receipt?.delivery, "simulated");
  } finally {
    globalThis.fetch = originalFetch;
    await runtime.close();
    store.deleteSession(state.id);
  }
});

test("LLM slot values must be present in their own transcript quote", async () => {
  const response = {
    choices: [{ message: { content: JSON.stringify({
      matched: true,
      action: "INCISION",
      action_quote: "incision",
      slots: [
        { name: "site", value: "right knee", evidence_quote: "left knee" },
        { name: "challenge", value: "amber 42", evidence_quote: "amber 42" }
      ],
      confidence: 0.99,
      evidence_quote: "incision on the left knee"
    }) } }]
  };
  const client = { llmGateway: { chatCompletions: async () => response } } as unknown as AssemblyAI;
  await assert.rejects(
    extractWithGateway(client, DEFAULT_INVARIANT, {
      turnOrder: 1,
      speaker: "A",
      transcript: "Initiate incision on the left knee. Authorization code amber 42.",
      observedAt: Date.now(),
      observedMono: 1_000
    }, "amber 42"),
    /not present in its evidence quote/
  );
});

test("LLM action terms must match complete words rather than hostile substrings", async () => {
  const response = {
    choices: [{ message: { content: JSON.stringify({
      matched: true,
      action: "CONFIRM",
      action_quote: "disconfirm",
      slots: [
        { name: "site", value: "right knee", evidence_quote: "right knee" },
        { name: "challenge", value: "amber 42", evidence_quote: "amber 42" }
      ],
      confidence: 0.99,
      evidence_quote: "disconfirm the right knee amber 42"
    }) } }]
  };
  const client = { llmGateway: { chatCompletions: async () => response } } as unknown as AssemblyAI;
  await assert.rejects(
    extractWithGateway(client, DEFAULT_INVARIANT, {
      turnOrder: 2,
      speaker: "B",
      transcript: "I disconfirm the right knee amber 42.",
      observedAt: Date.now(),
      observedMono: 2_000
    }, "amber 42"),
    /allowed explicit action term/
  );
});

test("LLM confidence is independently bounded even if schema enforcement fails", async () => {
  const response = {
    choices: [{ message: { content: JSON.stringify({
      matched: true,
      action: "INCISION",
      action_quote: "incision",
      slots: [],
      confidence: 9,
      evidence_quote: "incision"
    }) } }]
  };
  const client = { llmGateway: { chatCompletions: async () => response } } as unknown as AssemblyAI;
  await assert.rejects(
    extractWithGateway(client, DEFAULT_INVARIANT, {
      turnOrder: 1,
      speaker: "A",
      transcript: "incision",
      observedAt: Date.now(),
      observedMono: 1_000
    }, "amber 42"),
    /violated extraction contract/
  );
});
