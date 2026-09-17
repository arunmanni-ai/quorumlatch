import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { lookup as dnsLookup } from "node:dns";
import { request as httpsRequest } from "node:https";
import { BlockList, type LookupFunction } from "node:net";
import type { InvariantRule, SessionState, UnlockReceipt } from "./domain.js";
import { signedMockActuator } from "./mock-actuator.js";

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const processSigningKey = process.env.QUORUMLATCH_RECEIPT_KEY || randomBytes(32).toString("hex");
const blockedWebhookIpv4 = new BlockList();
const blockedWebhookIpv6 = new BlockList();
for (const [network, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 4]
] as const) blockedWebhookIpv4.addSubnet(network, prefix, "ipv4");
for (const [network, prefix] of [
  ["::", 128], ["::1", 128], ["::ffff:0:0", 96], ["64:ff9b:1::", 48], ["100::", 64],
  ["2001:db8::", 32], ["2002::", 16], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8]
] as const) blockedWebhookIpv6.addSubnet(network, prefix, "ipv6");

export function isPublicWebhookAddress(address: string, family: number): boolean {
  if (family === 4) return !blockedWebhookIpv4.check(address, "ipv4");
  if (family === 6) return !blockedWebhookIpv6.check(address, "ipv6");
  return false;
}

const safeWebhookLookup: LookupFunction = (hostname, options, callback) => {
  dnsLookup(hostname, {
    family: options.family,
    hints: options.hints,
    all: true,
    verbatim: true
  }, (error, addresses) => {
    if (error) return callback(error, "", 0);
    if (!addresses.length || addresses.some(({ address, family }) => !isPublicWebhookAddress(address, family))) {
      const denied = new Error("Webhook DNS resolved to a non-public address") as NodeJS.ErrnoException;
      denied.code = "EACCES";
      return callback(denied, "", 0);
    }
    if (options.all) return callback(null, addresses);
    const selected = addresses[0]!;
    callback(null, selected.address, selected.family);
  });
};

async function postWebhook(
  url: string,
  headers: Record<string, string>,
  body: string,
  signal: AbortSignal,
  timeoutMs: number
): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const request = httpsRequest(url, {
      method: "POST",
      headers: { ...headers, "content-length": String(Buffer.byteLength(body)) },
      lookup: safeWebhookLookup,
      agent: false,
      signal
    }, (response) => {
      const status = response.statusCode ?? 0;
      response.on("error", reject);
      response.on("end", () => resolve(status));
      response.resume();
    });
    request.setTimeout(timeoutMs, () => request.destroy(new Error("Webhook request timed out")));
    request.on("error", reject);
    request.end(body);
  });
}

export async function deliverUnlock(
  invariant: InvariantRule,
  session: SessionState,
  signal: AbortSignal,
  allowWebhook: boolean
): Promise<UnlockReceipt> {
  if (signal.aborted) throw new Error("Unlock cancelled");
  const unlockId = randomUUID();
  const issuedAt = Date.now();
  const validUntil = issuedAt + invariant.unlockTtlMs;
  const evidence = invariant.steps.map((step) => {
    const item = session.evidence[step.id];
    if (!item) throw new Error(`Missing committed evidence for ${step.id}`);
    return item;
  });
  const evidenceDigest = createHash("sha256").update(JSON.stringify(evidence)).digest("hex");
  const payload = {
    type: "quorumlatch.unlock_granted",
    unlockId,
    invariantId: invariant.id,
    invariantVersion: invariant.version,
    sessionId: session.id,
    generation: session.generation,
    policyHash: session.policyHash,
    issuedAt,
    validUntil,
    authorization: "ONE_TIME",
    evidenceDigest,
    evidence: evidence.map((item) => ({
      stepId: item.stepId,
      speaker: item.speaker,
      action: item.action,
      slots: item.slots,
      observedAt: item.observedAt,
      turnOrder: item.turnOrder
    }))
  };

  const body = JSON.stringify(payload);
  const signingKey = invariant.webhook?.secret ?? processSigningKey;
  const signature = createHmac("sha256", signingKey).update(body).digest("hex");

  const webhook = invariant.webhook;
  if (allowWebhook && !webhook?.url) {
    throw new Error("Live authorization requires a configured webhook receiver");
  }

  if (!allowWebhook) {
    await pause(360);
    if (signal.aborted || Date.now() >= validUntil) throw new Error("Unlock cancelled or expired");
    return { unlockId, issuedAt, validUntil, evidenceDigest, delivery: "simulated" };
  }
  if (!webhook) throw new Error("Live authorization requires a configured webhook receiver");

  if (webhook.url === "mock://signed-actuator") {
    signedMockActuator.receive(body, `sha256=${signature}`, webhook.secret);
    if (signal.aborted || Date.now() >= validUntil) throw new Error("Unlock expired during mock receiver acknowledgement");
    return { unlockId, issuedAt, validUntil, evidenceDigest, delivery: "signed-mock" };
  }

  let failure = "unknown failure";

  for (let attempt = 1; attempt <= 3; attempt++) {
    if (signal.aborted) throw new Error("Unlock cancelled");
    const remaining = validUntil - Date.now();
    if (remaining <= 500) throw new Error("Unlock expired before delivery acknowledgement");
    try {
      const timeoutMs = Math.min(2_000, remaining - 250);
      const responseStatus = await postWebhook(
        webhook.url,
        {
          "content-type": "application/json",
          "x-quorumlatch-signature": `sha256=${signature}`,
          "x-quorumlatch-issued-at": String(issuedAt),
          "x-quorumlatch-valid-until": String(validUntil),
          "x-quorumlatch-policy-hash": session.policyHash,
          "idempotency-key": unlockId
        },
        body,
        AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]),
        timeoutMs
      );
      if (responseStatus >= 300 && responseStatus < 400) throw new Error("Webhook redirects are forbidden");
      if (responseStatus < 200 || responseStatus >= 300) throw new Error(`Receiver returned ${responseStatus}`);
      if (signal.aborted || Date.now() >= validUntil) throw new Error("Unlock expired during delivery");
      return { unlockId, issuedAt, validUntil, evidenceDigest, delivery: "webhook" };
    } catch (error) {
      if (signal.aborted) throw new Error("Unlock cancelled");
      failure = error instanceof Error ? error.message : "unknown failure";
      if (attempt < 3 && validUntil - Date.now() > 750) await pause(attempt * 150);
    }
  }
  throw new Error(`Unlock delivery failed closed: ${failure}`);
}
