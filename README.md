# QuorumLatch

**No motion without spoken proof.**

![QuorumLatch — temporal voice safety infrastructure](docs/quorumlatch-cover.png)

QuorumLatch is a locked-by-default temporal authorization API. AssemblyAI produces finalized, diarized turns; LLM Gateway extracts strictly grounded evidence; deterministic code alone evaluates the immutable policy snapshot. A successful quorum creates a short-lived authorization capsule.

The default Gateway model is AssemblyAI's account-native `qwen3.5-4b-32k-fast`. Models with native JSON-schema support use strict schema mode; this model receives the same schema in its prompt and every returned field is independently validated and transcript-grounded before the deterministic engine sees it.

## Safe quick start

```bash
cp .env.example .env
npm install
npm run dev
```

Open `http://127.0.0.1:3000`. The default posture is deliberately **loopback-only and Demo-only**. Demo Mode cannot call a webhook, even if code attempts to supply one.

Non-loopback deployment is refused unless a control token is configured, `QUORUMLATCH_TLS_TERMINATED=true` explicitly asserts that a trusted TLS proxy protects the connection, and `QUORUMLATCH_ALLOWED_ORIGINS` lists the exact public HTTPS origins.

To enable Live Mode, add both values to `.env` and register a policy with an HTTPS webhook receiver:

```bash
QUORUMLATCH_CONTROL_TOKEN=<at least 32 random characters>
ASSEMBLYAI_API_KEY=<your key>
```

For the hackathon demo, the built-in signed actuator simulator can exercise the complete capsule contract without controlling hardware:

```bash
QUORUMLATCH_ENABLE_SIGNED_MOCK_RECEIVER=true
QUORUMLATCH_MOCK_RECEIVER_SECRET=<at least 32 random characters>
```

Generate both QuorumLatch secrets with `openssl rand -hex 32`. The simulator independently verifies the capsule HMAC, TTL and idempotency key, exposes its read-only state at `/api/mock-actuator`, and automatically relocks. It is deliberately incapable of physical actuation.

Generate a strong control token with `openssl rand -hex 32`. Click **Switch to live microphone**, then enter that token. It is retained only in page memory and is never put in local storage or a URL.

## Judge path

The interface generates a fresh spoken challenge for every session.

1. Send the wrong-site instruction: deterministic policy rejects it.
2. Send the correct instruction with the challenge: Proof A is accepted.
3. Send vague assent: no safety event is manufactured.
4. Send the explicit second-speaker readback with the challenge: a signed, short-lived simulated capsule is issued.

## Security architecture

- Loopback-only binding by default.
- Separate control-plane credential for Live Mode and policy writes.
- Random per-session capability for every REST and WebSocket operation.
- Capability travels as a WebSocket subprotocol, never in its URL.
- Immutable policy snapshot and SHA-256 policy hash per session.
- Demo/production actuation separation enforced below the API layer.
- Optional signed mock actuator verifies the real receiver contract without physical output.
- Final formatted turns only; mixed-speaker turns fail closed.
- Fresh per-session spoken challenge reduces recorded-audio replay.
- LLM action, slots and evidence quotes are independently transcript-grounded.
- Explicit vetoes and conflicting events clear partial authorization.
- Processing, streaming and queue faults clear partial authorization.
- Reset aborts pending delivery and invalidates its authorization generation.
- Evidence queued before a reset, or still being extracted during one, is discarded.
- Reserved JavaScript object names cannot satisfy or skip quorum steps.
- Live Mode fails closed unless a real webhook receiver is configured.
- Remaining TTL, rather than a fresh TTL, controls local expiration.
- HTTPS-only exact webhook-host allowlist on the default TLS port; redirects and non-public connection-time DNS results are forbidden.
- HMAC signature, timestamp, policy hash and idempotency key on webhooks.
- Bounded request bodies, WebSocket frames, audio rate, queue and session lifetime.
- Automatic transcriber and session cleanup.
- CSP, clickjacking defense, no-referrer policy and restricted browser permissions.

See `SECURITY.md` for the receiver contract and residual trust assumptions.

## Verification

```bash
npm run build
npm test
npm run security:audit
npm audit --omit=dev
```

`security:audit` launches a disposable localhost server and attacks authentication, policy mutation, prototype-chain identifiers, content-type confusion, webhook SSRF, REST capabilities, hostile WebSocket origins, reset races, malformed bodies and the complete authorization flow.

With the secured `.env` configured and the server running, `npm run smoke:live` opens a real `u3-rt-pro` session, obtains a single-use WebSocket ticket, forwards one second of harmless PCM16 silence, and verifies that the signed mock actuator remains locked. It never prints credentials.

## Important boundary

AssemblyAI speaker labels separate voices; they are not biometric identity. A real clinical or industrial deployment must additionally bind each required role to an authenticated device/channel or approved speaker-verification system. This repository is a hardened hackathon prototype, not certified machinery-control software.
