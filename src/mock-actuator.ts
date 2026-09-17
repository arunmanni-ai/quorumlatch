import { createHmac, timingSafeEqual } from "node:crypto";

interface Capsule {
  type: string;
  unlockId: string;
  sessionId: string;
  generation: number;
  policyHash: string;
  issuedAt: number;
  validUntil: number;
  authorization: string;
  evidenceDigest: string;
}

interface ActuatorState {
  status: "LOCKED" | "UNLOCKED";
  unlockId?: string;
  sessionId?: string;
  policyHash?: string;
  evidenceDigest?: string;
  validUntil?: number;
  lastError?: string;
}

function safeHexEqual(actual: string, expected: string): boolean {
  if (!/^[a-f0-9]{64}$/i.test(actual) || !/^[a-f0-9]{64}$/i.test(expected)) return false;
  const left = Buffer.from(actual, "hex");
  const right = Buffer.from(expected, "hex");
  return left.length === right.length && timingSafeEqual(left, right);
}

function parseCapsule(body: string): Capsule {
  if (Buffer.byteLength(body) > 32 * 1024) throw new Error("Capsule exceeds receiver limit");
  const value: unknown = JSON.parse(body);
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid capsule");
  const capsule = value as Partial<Capsule>;
  if (
    capsule.type !== "quorumlatch.unlock_granted" ||
    typeof capsule.unlockId !== "string" ||
    typeof capsule.sessionId !== "string" ||
    !Number.isInteger(capsule.generation) ||
    typeof capsule.policyHash !== "string" ||
    !/^[a-f0-9]{64}$/i.test(capsule.policyHash) ||
    typeof capsule.issuedAt !== "number" ||
    typeof capsule.validUntil !== "number" ||
    capsule.authorization !== "ONE_TIME" ||
    typeof capsule.evidenceDigest !== "string" ||
    !/^[a-f0-9]{64}$/i.test(capsule.evidenceDigest)
  ) throw new Error("Capsule contract rejected");
  return capsule as Capsule;
}

export class SignedMockActuator {
  private readonly seen = new Map<string, number>();
  private state: ActuatorState = { status: "LOCKED" };
  private relockTimer?: NodeJS.Timeout;

  receive(body: string, signatureHeader: string, secret: string): void {
    const now = Date.now();
    for (const [id, expiry] of this.seen) if (expiry <= now) this.seen.delete(id);
    const match = /^sha256=([a-f0-9]{64})$/i.exec(signatureHeader);
    const expected = createHmac("sha256", secret).update(body).digest("hex");
    if (!match || !safeHexEqual(match[1]!, expected)) {
      this.state = { status: "LOCKED", lastError: "Signature verification failed" };
      throw new Error("Mock actuator rejected the capsule signature");
    }
    const capsule = parseCapsule(body);
    if (capsule.issuedAt > now + 2_000 || capsule.validUntil <= now) {
      this.state = { status: "LOCKED", lastError: "Capsule is not currently valid" };
      throw new Error("Mock actuator rejected an expired or future capsule");
    }
    if (capsule.validUntil - capsule.issuedAt > 60_000) {
      this.state = { status: "LOCKED", lastError: "Capsule TTL exceeds receiver policy" };
      throw new Error("Mock actuator rejected an excessive TTL");
    }
    if (this.seen.has(capsule.unlockId)) {
      this.state = { status: "LOCKED", lastError: "Replay rejected" };
      throw new Error("Mock actuator rejected a replayed capsule");
    }
    this.seen.set(capsule.unlockId, capsule.validUntil);
    this.state = {
      status: "UNLOCKED",
      unlockId: capsule.unlockId,
      sessionId: capsule.sessionId,
      policyHash: capsule.policyHash,
      evidenceDigest: capsule.evidenceDigest,
      validUntil: capsule.validUntil
    };
    if (this.relockTimer) clearTimeout(this.relockTimer);
    this.relockTimer = setTimeout(() => {
      if (this.state.unlockId === capsule.unlockId) this.state = { status: "LOCKED" };
    }, Math.max(0, capsule.validUntil - Date.now()));
    this.relockTimer.unref();
  }

  publicState(): ActuatorState {
    if (this.state.validUntil !== undefined && Date.now() >= this.state.validUntil) {
      this.state = { status: "LOCKED" };
    }
    return { ...this.state };
  }
}

export const signedMockActuator = new SignedMockActuator();
