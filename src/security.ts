import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { InvariantRule, Scalar, SlotExpectation, StepRule } from "./domain.js";

const ID = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;
const SPEAKER = /^[A-Z][A-Z0-9_-]{0,15}$/;

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function tokenDigest(token: string): Buffer {
  return createHash("sha256").update(token).digest();
}

export function tokenMatches(token: string | undefined, expected: Buffer): boolean {
  if (!token) return false;
  const actual = tokenDigest(token);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function bearerToken(header: string | undefined): string | undefined {
  if (!header?.startsWith("Bearer ")) return undefined;
  const token = header.slice(7).trim();
  return token || undefined;
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, item]) => [key, canonical(item)])
    );
  }
  return value;
}

export function hashPolicy(rule: InvariantRule): string {
  const publicRule = structuredClone(rule);
  if (publicRule.webhook) publicRule.webhook.secret = "[transport-secret-redacted]";
  return createHash("sha256").update(JSON.stringify(canonical(publicRule))).digest("hex");
}

function fail(message: string): never {
  throw new Error(`Invalid invariant: ${message}`);
}

function boundedString(value: unknown, name: string, max: number): string {
  if (typeof value !== "string" || !value.trim() || value.length > max) fail(name);
  return value.trim();
}

function boundedNumber(value: unknown, name: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < min || value > max) fail(name);
  return value;
}

function validateExpectation(value: unknown, knownSteps: Map<string, StepRule>, slotName: string): SlotExpectation {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`slot ${slotName}`);
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== 1) fail(`slot ${slotName} expectation`);
  if (keys[0] === "equals") {
    const scalar = record.equals;
    if (!["string", "number", "boolean"].includes(typeof scalar)) fail(`slot ${slotName} scalar`);
    if (typeof scalar === "string" && (!scalar.trim() || scalar.length > 128)) fail(`slot ${slotName} value`);
    return { equals: scalar as Scalar };
  }
  if (keys[0] === "sameAs" && typeof record.sameAs === "string") {
    const [stepId, referencedSlot, extra] = record.sameAs.split(".");
    const referenced = knownSteps.get(stepId!);
    if (extra || !referenced || !referencedSlot || !Object.hasOwn(referenced.slots, referencedSlot)) {
      fail(`slot ${slotName} reference`);
    }
    return { sameAs: `${stepId!}.${referencedSlot}` };
  }
  fail(`slot ${slotName} expectation`);
}

function validateWebhook(webhook: unknown): InvariantRule["webhook"] {
  if (webhook === undefined) return undefined;
  if (!webhook || typeof webhook !== "object" || Array.isArray(webhook)) fail("webhook");
  const record = webhook as Record<string, unknown>;
  const url = boundedString(record.url, "webhook URL", 512);
  const secret = boundedString(record.secret, "webhook secret", 256);
  if (secret.length < 32) fail("webhook secret must contain at least 32 characters");
  if (url === "mock://signed-actuator") {
    if (process.env.QUORUMLATCH_ENABLE_SIGNED_MOCK_RECEIVER !== "true") {
      fail("signed mock receiver is disabled");
    }
    return { url, secret };
  }
  let parsed: URL;
  try { parsed = new URL(url); } catch { fail("webhook URL"); }
  if (parsed!.protocol !== "https:") fail("webhook must use HTTPS");
  if (parsed!.port && parsed!.port !== "443") fail("webhook must use the default HTTPS port");
  if (parsed!.username || parsed!.password || parsed!.hash) fail("webhook URL credentials or fragment");
  const allowlist = new Set(
    (process.env.QUORUMLATCH_WEBHOOK_HOSTS ?? "")
      .split(",")
      .map((host) => host.trim().toLowerCase())
      .filter(Boolean)
  );
  if (!allowlist.has(parsed!.hostname.toLowerCase())) {
    fail("webhook hostname is not in QUORUMLATCH_WEBHOOK_HOSTS");
  }
  return { url: parsed!.toString(), secret };
}

export function validateInvariant(input: unknown): InvariantRule {
  if (!input || typeof input !== "object" || Array.isArray(input)) fail("object");
  const source = input as Record<string, unknown>;
  const id = boundedString(source.id, "id", 64);
  if (!ID.test(id)) fail("id format");
  const name = boundedString(source.name, "name", 120);
  const version = boundedString(source.version, "version", 32);
  const windowMs = boundedNumber(source.windowMs, "windowMs", 1_000, 300_000);
  const unlockTtlMs = boundedNumber(source.unlockTtlMs, "unlockTtlMs", 1_000, 60_000);
  const maxSpeakers = boundedNumber(source.maxSpeakers, "maxSpeakers", 2, 10);
  if (!Number.isInteger(maxSpeakers)) fail("maxSpeakers integer");
  if (!Array.isArray(source.keyterms) || source.keyterms.length > 64) fail("keyterms");
  const keyterms = source.keyterms.map((term, index) => boundedString(term, `keyterm ${index}`, 64));
  if (!Array.isArray(source.steps) || source.steps.length < 2 || source.steps.length > 8) fail("steps");

  const knownSteps = new Map<string, StepRule>();
  const speakers = new Set<string>();
  const steps: StepRule[] = [];
  for (const [index, raw] of source.steps.entries()) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) fail(`step ${index}`);
    const step = raw as Record<string, unknown>;
    const stepId = boundedString(step.id, `step ${index} id`, 64);
    if (!ID.test(stepId) || knownSteps.has(stepId)) fail(`step ${index} id`);
    const speaker = boundedString(step.speaker, `step ${index} speaker`, 16).toUpperCase();
    if (!SPEAKER.test(speaker) || speakers.has(speaker)) fail("every quorum step must use a distinct speaker label");
    speakers.add(speaker);
    const action = boundedString(step.action, `step ${index} action`, 48).toUpperCase();
    if (!ID.test(action)) fail(`step ${index} action format`);
    if (!Array.isArray(step.actionTerms) || step.actionTerms.length < 1 || step.actionTerms.length > 12) {
      fail(`step ${index} actionTerms`);
    }
    const actionTerms = step.actionTerms.map((term, termIndex) =>
      boundedString(term, `step ${index} action term ${termIndex}`, 64).toLowerCase()
    );
    const description = boundedString(step.description, `step ${index} description`, 240);
    if (!step.slots || typeof step.slots !== "object" || Array.isArray(step.slots)) fail(`step ${index} slots`);
    const rawSlots = Object.entries(step.slots as Record<string, unknown>);
    if (rawSlots.length < 1 || rawSlots.length > 8) fail(`step ${index} slots`);
    const slots: Record<string, SlotExpectation> = Object.create(null) as Record<string, SlotExpectation>;
    for (const [slotName, expectation] of rawSlots) {
      if (!ID.test(slotName)) fail(`step ${index} slot name`);
      slots[slotName] = validateExpectation(expectation, knownSteps, slotName);
    }
    const after = step.after === undefined ? undefined : boundedString(step.after, `step ${index} after`, 64);
    if (index > 0 && (!after || !knownSteps.has(after))) fail(`step ${index} must depend on an earlier step`);
    if (index === 0 && after) fail("first step cannot have a dependency");
    const withinMs = step.withinMs === undefined
      ? undefined
      : boundedNumber(step.withinMs, `step ${index} withinMs`, 250, windowMs);
    if (index > 0 && withinMs === undefined) fail(`step ${index} requires withinMs`);
    const minConfidence = step.minConfidence === undefined
      ? 0.88
      : boundedNumber(step.minConfidence, `step ${index} minConfidence`, 0.5, 1);
    const validated: StepRule = {
      id: stepId, speaker, action, actionTerms, description, slots, after, withinMs, minConfidence
    };
    knownSteps.set(stepId, validated);
    steps.push(validated);
  }

  const rule: InvariantRule = {
    id, name, version, windowMs, unlockTtlMs, maxSpeakers, keyterms, steps,
    webhook: validateWebhook(source.webhook)
  };
  return structuredClone(rule);
}

export function isLoopback(address: string | undefined): boolean {
  if (!address) return false;
  const normalized = address.replace(/^::ffff:/, "");
  return normalized === "127.0.0.1" || normalized === "::1";
}

export function permitsUnauthenticatedDemo(bindHost: string, remoteAddress: string | undefined): boolean {
  return isLoopback(bindHost) && isLoopback(remoteAddress);
}
