import { randomInt, randomUUID } from "node:crypto";
import type { InvariantRule, SessionMode, SessionState } from "./domain.js";
import { DEFAULT_INVARIANT } from "./domain.js";
import { hashPolicy, validateInvariant } from "./security.js";

class MemoryStore {
  readonly invariants = new Map<string, InvariantRule>();
  readonly sessions = new Map<string, SessionState>();
  readonly sessionPolicies = new Map<string, InvariantRule>();

  constructor() {
    const validated = validateInvariant(DEFAULT_INVARIANT);
    this.invariants.set(validated.id, validated);
  }

  putInvariant(rule: InvariantRule): void {
    const validated = validateInvariant(rule);
    this.invariants.set(validated.id, validated);
  }

  createSession(invariantId: string, mode: SessionMode): SessionState {
    const stored = this.invariants.get(invariantId);
    if (!stored) throw new Error("Unknown invariant");
    const policy = structuredClone(stored);
    if (mode === "demo") policy.webhook = undefined;
    const now = Date.now();
    const challengeWords = [
      "amber", "atlas", "cedar", "cobalt", "comet", "delta", "ember", "falcon",
      "harbor", "iris", "juniper", "lumen", "maple", "nova", "onyx", "orbit",
      "panda", "quartz", "river", "sable", "solar", "tango", "thunder", "tulip",
      "umber", "velvet", "willow", "xenon", "yellow", "zephyr", "acorn", "birch"
    ];
    const available = [...challengeWords];
    const challenge = Array.from({ length: 5 }, () => available.splice(randomInt(available.length), 1)[0]).join(" ");
    const state: SessionState = {
      id: randomUUID(),
      invariantId,
      mode,
      status: "LOCKED",
      policyHash: hashPolicy(policy),
      generation: 0,
      expiresAt: now + (mode === "live" ? 30 * 60_000 : 10 * 60_000),
      challenge,
      turns: [],
      evidence: Object.create(null) as SessionState["evidence"]
    };
    this.sessions.set(state.id, state);
    this.sessionPolicies.set(state.id, policy);
    return state;
  }

  invariantFor(session: SessionState): InvariantRule {
    const invariant = this.sessionPolicies.get(session.id);
    if (!invariant) throw new Error("Invariant no longer exists");
    return invariant;
  }

  deleteSession(sessionId: string): void {
    this.sessions.delete(sessionId);
    this.sessionPolicies.delete(sessionId);
  }
}

export const store = new MemoryStore();
