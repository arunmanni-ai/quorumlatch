# QuorumLatch security model

## Trust boundary

The LLM is an untrusted evidence extractor. It cannot issue an authorization verdict. The deterministic engine accepts evidence only when the action term, every slot value, every quote, speaker order, freshness challenge, confidence threshold and temporal constraint pass independently.

The browser is also untrusted. Live control and policy registration require the control-plane credential. Each created session receives a separate random capability, stored only as a SHA-256 digest on the server.

## Webhook receiver contract

A receiver must:

1. Accept only HTTPS requests from the expected QuorumLatch deployment.
2. Verify `x-quorumlatch-signature` over the exact raw request body.
3. Reject an unknown `x-quorumlatch-policy-hash`.
4. Reject when its current time is before `issuedAt` or at/after `validUntil`.
5. Atomically store and reject duplicate `idempotency-key` values.
6. Treat authorization as a lease that expires locally without a relock message.
7. Never execute a Demo Mode capsule; this server never sends one to a webhook.
8. Fail closed when clock synchronization, signature verification or persistence is unavailable.

The optional `mock://signed-actuator` receiver is available only when explicitly enabled. It verifies HMAC, TTL and one-time use in process, exposes no secret, and has no physical-output code path. It is for judging and local integration tests, not production deployment.

## Deployment requirements

- Keep `HOST=127.0.0.1` unless deploying behind an authenticated TLS reverse proxy. Non-loopback startup additionally requires `QUORUMLATCH_TLS_TERMINATED=true`.
- Non-loopback deployments must set exact HTTPS origins in `QUORUMLATCH_ALLOWED_ORIGINS`.
- Use at least 256 bits of randomness for control and receipt keys.
- Configure only exact trusted names in `QUORUMLATCH_WEBHOOK_HOSTS`. Connection-time DNS resolution rejects loopback, private, link-local, reserved, and documentation networks.
- Rotate secrets through a secret manager; never place `.env` in source control.
- Add authenticated device/channel identity before connecting a physical actuator.
- Use an append-only external audit sink for regulated environments.

## Residual assumptions

No software can provide a literal guarantee of zero vulnerabilities. This prototype specifically does not claim biometric speaker identity, certification for medical/industrial control, high-availability persistence, or protection after the host itself is compromised.
