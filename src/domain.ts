export type Scalar = string | number | boolean;

export type SlotExpectation =
  | { equals: Scalar }
  | { sameAs: `${string}.${string}` };

export interface StepRule {
  id: string;
  speaker: string;
  action: string;
  actionTerms: string[];
  description: string;
  slots: Record<string, SlotExpectation>;
  after?: string;
  withinMs?: number;
  minConfidence?: number;
}

export interface InvariantRule {
  id: string;
  name: string;
  version: string;
  windowMs: number;
  unlockTtlMs: number;
  maxSpeakers: number;
  keyterms: string[];
  steps: StepRule[];
  webhook?: {
    url: string;
    secret: string;
  };
}

export interface FinalTurn {
  turnOrder: number;
  speaker: string;
  transcript: string;
  observedAt: number;
  observedMono: number;
}

export interface VoiceEvent extends FinalTurn {
  action: string;
  slots: Record<string, string>;
  confidence: number;
  evidenceQuote: string;
  actionEvidence: string;
  slotEvidence: Record<string, string>;
  extractor: "llm-gateway" | "deterministic-demo";
}

export interface MatchedEvidence extends VoiceEvent {
  stepId: string;
}

export interface UnlockReceipt {
  unlockId: string;
  issuedAt: number;
  validUntil: number;
  evidenceDigest: string;
  delivery: "simulated" | "signed-mock" | "webhook";
}

export type SessionStatus = "LOCKED" | "UNLOCKING" | "UNLOCKED";
export type SessionMode = "demo" | "live";

export interface SessionState {
  id: string;
  invariantId: string;
  mode: SessionMode;
  status: SessionStatus;
  policyHash: string;
  generation: number;
  expiresAt: number;
  challenge: string;
  turns: FinalTurn[];
  evidence: Record<string, MatchedEvidence>;
  firstMatchAt?: number;
  receipt?: UnlockReceipt;
  lastError?: string;
}

export interface EngineResult {
  type: "IGNORED" | "REJECTED" | "RESET" | "STEP_MATCHED" | "SATISFIED";
  reason: string;
  expectedStep?: string;
  matchedStep?: string;
}

export const DEFAULT_INVARIANT: InvariantRule = {
  id: "surgical-site-quorum-v1",
  name: "Two-person surgical-site authorization",
  version: "1.0.0",
  windowMs: 30_000,
  unlockTtlMs: 8_000,
  maxSpeakers: 2,
  keyterms: ["incision", "right knee", "left knee", "confirm"],
  steps: [
    {
      id: "operator-command",
      speaker: "A",
      action: "INCISION",
      actionTerms: ["incision", "incise", "begin procedure"],
      description: "Operator explicitly states the authorized procedure and site.",
      slots: { site: { equals: "right knee" } },
      minConfidence: 0.88
    },
    {
      id: "independent-readback",
      speaker: "B",
      action: "CONFIRM",
      actionTerms: ["confirm", "confirmed", "readback"],
      description: "A second speaker independently repeats the same site.",
      slots: { site: { sameAs: "operator-command.site" } },
      after: "operator-command",
      withinMs: 15_000,
      minConfidence: 0.88
    }
  ]
};
