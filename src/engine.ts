import type {
  EngineResult,
  InvariantRule,
  Scalar,
  SessionState,
  SlotExpectation,
  StepRule,
  VoiceEvent
} from "./domain.js";

function normalize(value: Scalar): string {
  return String(value)
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s.-]/gu, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export function resetEvidence(session: SessionState, reason?: string): void {
  session.status = "LOCKED";
  session.evidence = Object.create(null) as SessionState["evidence"];
  session.firstMatchAt = undefined;
  session.receipt = undefined;
  session.lastError = reason;
}

function resolveExpectation(
  expectation: SlotExpectation,
  session: SessionState
): Scalar | undefined {
  if ("equals" in expectation) return expectation.equals;
  const [stepId, slotName] = expectation.sameAs.split(".");
  if (!stepId || !slotName) return undefined;
  if (!Object.hasOwn(session.evidence, stepId)) return undefined;
  return session.evidence[stepId]?.slots[slotName];
}

function hasEvidence(session: SessionState, stepId: string): boolean {
  return Object.hasOwn(session.evidence, stepId);
}

function mismatchReason(event: VoiceEvent, step: StepRule, session: SessionState): string | undefined {
  if (event.speaker !== step.speaker) return `Requires Speaker ${step.speaker}`;
  if (event.action !== step.action) return `Expected ${step.action}`;
  if (event.confidence < (step.minConfidence ?? 0.85)) return "Extraction confidence below policy";
  if (step.after && !hasEvidence(session, step.after)) return `Missing prerequisite ${step.after}`;
  for (const [slot, expectation] of Object.entries(step.slots)) {
    const actual = event.slots[slot];
    const expected = resolveExpectation(expectation, session);
    if (actual === undefined) return `Missing explicit ${slot}`;
    if (expected === undefined) return `Cannot resolve expected ${slot}`;
    if (normalize(actual) !== normalize(expected)) {
      return `${slot} mismatch: heard “${actual}”, expected “${expected}”`;
    }
  }
  return undefined;
}

export function evaluateEvent(
  invariant: InvariantRule,
  session: SessionState,
  event: VoiceEvent
): EngineResult {
  if (session.status !== "LOCKED") {
    return { type: "IGNORED", reason: `Session is ${session.status}` };
  }

  const spokenChallenge = event.slots.challenge;
  if (!spokenChallenge || normalize(spokenChallenge) !== normalize(session.challenge)) {
    if (Object.keys(session.evidence).length > 0) resetEvidence(session, "Missing or incorrect session challenge");
    return { type: "REJECTED", reason: "Missing or incorrect session challenge" };
  }

  if (session.firstMatchAt !== undefined && event.observedMono - session.firstMatchAt > invariant.windowMs) {
    resetEvidence(session, "Quorum window expired");
  }

  const first = invariant.steps[0];
  if (!first) return { type: "REJECTED", reason: "Invariant has no steps" };

  // A fresh initiating command invalidates every earlier partial authorization.
  if (
    hasEvidence(session, first.id) &&
    event.speaker === first.speaker &&
    event.action === first.action
  ) {
    resetEvidence(session, "New command superseded the partial quorum");
  }

  const next = invariant.steps.find((step) => !hasEvidence(session, step.id));
  if (!next) return { type: "IGNORED", reason: "Invariant already complete" };

  if (next.after && next.withinMs) {
    const dependency = hasEvidence(session, next.after) ? session.evidence[next.after] : undefined;
    if (dependency && event.observedMono - dependency.observedMono > next.withinMs) {
      resetEvidence(session, `Readback deadline expired for ${next.id}`);
      return { type: "RESET", reason: `Readback deadline expired`, expectedStep: next.id };
    }
  }

  const mismatch = mismatchReason(event, next, session);
  if (mismatch) {
    if (Object.keys(session.evidence).length > 0) {
      resetEvidence(session, `Conflicting safety event: ${mismatch}`);
      return { type: "RESET", reason: `Conflicting safety event: ${mismatch}`, expectedStep: first.id };
    }
    return { type: "REJECTED", reason: mismatch, expectedStep: next.id };
  }

  session.evidence[next.id] = { ...event, stepId: next.id };
  session.firstMatchAt ??= event.observedMono;

  const complete = invariant.steps.every((step) => hasEvidence(session, step.id));
  return complete
    ? { type: "SATISFIED", reason: "Spoken quorum proven", matchedStep: next.id }
    : {
        type: "STEP_MATCHED",
        reason: `Evidence accepted for ${next.id}`,
        matchedStep: next.id,
        expectedStep: invariant.steps.find((step) => !hasEvidence(session, step.id))?.id
      };
}
