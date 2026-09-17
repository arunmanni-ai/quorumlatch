# QuorumLatch v0.3.0 — Security Audit Record

Date: 17 September 2026  
Release type: Hardened hackathon prototype  
Default operating mode: Loopback-only Demo Mode

## Verdict

The prototype passed its build, unit tests, automated adversarial audit, dependency audit, and a complete browser demo. Every vulnerability identified during the review was addressed before this release was packaged.

This is not a claim that the software is mathematically free of every possible vulnerability. It is not certified for medical, industrial, or other safety-critical deployment.

## Second attacker pass — findings remediated

- **Policy-step bypass:** identifiers inherited from JavaScript's object prototype could appear to be pre-satisfied. Evidence maps and every membership check now use own properties only.
- **Reset/LLM race:** evidence queued before a reset, or returned by the LLM afterward, could be processed under the new generation. Turns are now generation-bound at enqueue time and checked again after extraction.
- **False Live Mode state:** a live session without a webhook could produce a simulated grant. Live authorization now requires and successfully reaches a configured receiver.
- **Content-type confusion:** a cross-origin `text/plain` POST could create local demo sessions without reading the response. Every mutating API call now requires JSON.
- **Semantic substring attack:** an action term such as `confirm` could match hostile words such as `disconfirm`. Action terms now match complete normalized phrases.
- **Webhook SSRF:** host allowlisting alone did not prevent alternate-port access or DNS resolution into private networks. Webhooks now use port 443 and a connection-time validating DNS resolver.
- **Stalled extraction:** an unresponsive LLM operation could block the session queue. Extraction now has a bounded fail-closed deadline.
- **Audio and speaker inconsistencies:** live sessions now have one audio producer, a tighter PCM rate, even-byte PCM16 validation, and turn/word speaker-label consistency checks.
- **Receipt exposure:** transport HMAC signatures are no longer returned to browser clients.

## Security properties verified

- Locked-by-default state machine with short-lived authorization leases.
- Deterministic policy evaluation; the LLM extracts evidence but cannot authorize an action.
- Immutable, hash-pinned policy snapshot for every session.
- Distinct-speaker, ordered-quorum, freshness-challenge, confidence, slot, quote, and timing checks.
- Immediate fail-closed reset on vetoes, contradictions, processing errors, timeouts, and reset races.
- Queued and in-flight LLM evidence is generation-bound and becomes unusable after reset.
- Prototype-chain identifiers cannot create phantom evidence or skip quorum steps.
- Demo Mode cannot dispatch a physical unlock webhook.
- Live Mode cannot claim an unlock without a configured webhook receiver.
- Live Mode and policy mutation require a strong control-plane credential.
- Per-session random capabilities are stored as hashes, not plaintext.
- WebSocket access uses short-lived, single-use tickets with Origin validation and replay rejection.
- WebSocket payload, connection, audio-rate, session-duration, queue, and backpressure limits.
- HTTPS-only webhook destinations restricted by an exact host allowlist and default TLS port, with connection-time rejection of non-public DNS results.
- Signed, expiring, idempotent, data-minimized webhook capsules; redirects are forbidden.
- Hackathon-only signed mock actuator independently verifies capsule HMAC, TTL and one-time use, then automatically relocks without any physical-output path.
- Restrictive browser security headers, clickjacking protection, no-referrer policy, and disabled unnecessary permissions.
- Generic error responses and bounded request bodies reduce information leakage and denial-of-service exposure.

## Automated verification

- TypeScript production build: PASS
- Unit/security tests: PASS — 24 named cases
- Adversarial audit: PASS — 30 security assertions
- Dependency audit: PASS — 0 known production dependency vulnerabilities
- Browser end-to-end demonstration: PASS
- Real AssemblyAI LLM Gateway extraction: PASS
- Real `u3-rt-pro` connection, authenticated WebSocket ticket and PCM16 forwarding: PASS
- Silent Live Mode check left the signed mock actuator `LOCKED`: PASS

The adversarial suite includes unauthorized policy mutation, unauthorized Live Mode, same-speaker takeover, prototype-chain step identifiers, non-JSON cross-origin writes, SSRF registration, hostile WebSocket origins, sequential and concurrent ticket replay, hidden-file probing, oversized frames, missing freshness proof, reset-race attempts, malformed JSON, and oversized HTTP bodies.

## Required production controls

Before connecting any real actuator, add authenticated device/channel identity, independently verify human identity when required, deploy behind authenticated TLS, use managed secrets, persist idempotency and audit records externally, synchronize clocks, and perform an independent penetration test and domain-specific safety certification.

AssemblyAI diarization distinguishes voices within a stream; it does not prove a speaker's legal or biometric identity.
