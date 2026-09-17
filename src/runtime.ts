import { EventEmitter } from "node:events";
import { performance } from "node:perf_hooks";
import { AssemblyAI, type StreamingTranscriber, type TurnEvent } from "assemblyai";
import type { FinalTurn, InvariantRule, SessionState } from "./domain.js";
import { evaluateEvent, resetEvidence } from "./engine.js";
import { extractDemoEvent, extractWithGateway } from "./extractor.js";
import { deliverUnlock } from "./webhook.js";

const VETO_PATTERN = /\b(no|nope|not|never|negative|stop|halt|pause|wait|cancel|abort|wrong|incorrect|correction|disregard|retract|revoke|avoid|without|cannot|can['’]t|shouldn['’]t|wouldn['’]t|do\s+not|don['’]t|must\s+not|hold|stand\s+down|scratch\s+that|instead\s+of|rather\s+than|refrain|prohibited|forbidden|unsafe|belay)\b/i;
const MAX_QUEUED_TURNS = 12;
const MAX_AUDIO_BYTES = 16_000 * 2 * 30 * 60;
const EXTRACTION_TIMEOUT_MS = 8_000;

async function withinDeadline<T>(operation: Promise<T>, milliseconds: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error("Evidence extraction timed out")), milliseconds);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export class SessionRuntime extends EventEmitter {
  private client?: AssemblyAI;
  private transcriber?: StreamingTranscriber;
  private queue: Promise<void> = Promise.resolve();
  private seenTurns = new Set<number>();
  private demoTurnOrder = 0;
  private expiryTimer?: NodeJS.Timeout;
  private activeUnlock?: AbortController;
  private queueDepth = 0;
  private audioBytes = 0;
  private closed = false;

  constructor(readonly state: SessionState, readonly invariant: InvariantRule) {
    super();
  }

  snapshot() {
    return {
      type: "snapshot",
      state: this.publicState(),
      invariant: { ...this.invariant, webhook: this.invariant.webhook ? { configured: true } : undefined }
    };
  }

  publicState() {
    return {
      ...this.state,
      progress: Object.keys(this.state.evidence).length,
      required: this.invariant.steps.length
    };
  }

  private publish(event: Record<string, unknown>) {
    this.emit("event", { at: Date.now(), ...event });
  }

  async start(): Promise<void> {
    if (this.closed || Date.now() >= this.state.expiresAt) throw new Error("Session expired");
    if (this.state.mode === "demo") {
      this.publish({ type: "session.ready", mode: "demo" });
      return;
    }
    const apiKey = process.env.ASSEMBLYAI_API_KEY;
    if (!apiKey) throw new Error("ASSEMBLYAI_API_KEY is not configured");
    this.client = new AssemblyAI({ apiKey });
    this.transcriber = this.client.streaming.transcriber({
      sampleRate: 16_000,
      speechModel: "u3-rt-pro",
      speakerLabels: true,
      maxSpeakers: this.invariant.maxSpeakers,
      formatTurns: true,
      includePartialTurns: true,
      connectTimeout: 10_000,
      maxConnectionRetries: 2,
      connectionRetryDelay: 750,
      keytermsPrompt: [...this.invariant.keyterms, ...this.state.challenge.split(" ")],
      minTurnSilence: 500,
      maxTurnSilence: 1_500
    });
    this.transcriber.on("open", ({ id }) =>
      this.publish({ type: "session.ready", mode: "live", assemblySessionId: id })
    );
    this.transcriber.on("turn", (turn: TurnEvent) => this.onAssemblyTurn(turn));
    this.transcriber.on("error", (error) => {
      this.reset(`Streaming fault: ${error.message}`);
      this.publish({ type: "error", message: error.message, state: this.publicState() });
    });
    await this.transcriber.connect();
  }

  private onAssemblyTurn(turn: TurnEvent): void {
    if (this.closed || Date.now() >= this.state.expiresAt) return;
    this.publish({
      type: turn.end_of_turn ? "turn.finalizing" : "turn.partial",
      speaker: turn.speaker_label ?? "UNKNOWN",
      transcript: turn.transcript,
      turnOrder: turn.turn_order
    });
    if (!turn.end_of_turn || !turn.turn_is_formatted || !turn.transcript.trim()) return;
    if (this.seenTurns.has(turn.turn_order)) return;
    this.seenTurns.add(turn.turn_order);
    if (this.seenTurns.size > 2_048) {
      const oldest = this.seenTurns.values().next().value as number | undefined;
      if (oldest !== undefined) this.seenTurns.delete(oldest);
    }
    const wordSpeakers = new Set(
      ((turn as TurnEvent & { words?: Array<{ speaker?: string }> }).words ?? [])
        .map((word) => word.speaker)
        .filter((speaker): speaker is string => Boolean(speaker))
    );
    if (wordSpeakers.size > 1) {
      this.reset("Multiple speakers detected inside one finalized turn");
      this.publish({ type: "evaluation", result: { type: "RESET", reason: "Mixed-speaker turn rejected" }, state: this.publicState() });
      return;
    }
    const wordSpeaker = wordSpeakers.values().next().value as string | undefined;
    if (wordSpeaker && wordSpeaker !== turn.speaker_label) {
      this.reset("Turn-level and word-level speaker attribution disagreed");
      this.publish({ type: "evaluation", result: { type: "RESET", reason: "Inconsistent speaker attribution rejected" }, state: this.publicState() });
      return;
    }
    const finalTurn: FinalTurn = {
      turnOrder: turn.turn_order,
      speaker: turn.speaker_label ?? "UNKNOWN",
      transcript: turn.transcript,
      observedAt: Date.now(),
      observedMono: performance.now()
    };
    this.enqueue(finalTurn);
  }

  private enqueue(turn: FinalTurn): void {
    if (this.queueDepth >= MAX_QUEUED_TURNS) {
      this.reset("Turn processing queue exceeded safety limit");
      this.publish({ type: "error", message: "Turn queue limit exceeded", state: this.publicState() });
      return;
    }
    const generationAtEnqueue = this.state.generation;
    this.queueDepth += 1;
    this.queue = this.queue.then(() => this.consume(turn, generationAtEnqueue)).catch((error) => {
      const message = error instanceof Error ? error.message : "Turn processing failed";
      this.reset(`Processing fault: ${message}`);
      this.publish({ type: "error", message, state: this.publicState() });
    }).finally(() => { this.queueDepth -= 1; });
  }

  async injectDemoTurn(speaker: string, transcript: string): Promise<void> {
    if (this.state.mode !== "demo") throw new Error("Not a demo session");
    if (this.closed || Date.now() >= this.state.expiresAt) throw new Error("Session expired");
    if (!/^[A-Z][A-Z0-9_-]{0,15}$/.test(speaker)) throw new Error("Invalid speaker label");
    if (!transcript.trim() || transcript.length > 1_000) throw new Error("Invalid transcript");
    const turn: FinalTurn = {
      turnOrder: ++this.demoTurnOrder,
      speaker,
      transcript,
      observedAt: Date.now(),
      observedMono: performance.now()
    };
    this.publish({ type: "turn.final", ...turn });
    this.enqueue(turn);
    await this.queue;
  }

  private async consume(turn: FinalTurn, generationAtEnqueue: number): Promise<void> {
    if (this.closed || generationAtEnqueue !== this.state.generation) return;
    if (Date.now() >= this.state.expiresAt) {
      this.reset("Session expired");
      return;
    }
    this.state.turns.push(turn);
    if (this.state.turns.length > 24) this.state.turns.shift();
    if (!turn.speaker || turn.speaker === "UNKNOWN") {
      if (Object.keys(this.state.evidence).length) this.reset("Speaker attribution became ambiguous");
      this.publish({ type: "evaluation", result: { type: "REJECTED", reason: "Speaker attribution unresolved" }, state: this.publicState() });
      return;
    }
    if (VETO_PATTERN.test(turn.transcript)) {
      this.reset("Explicit stop, correction, or veto detected");
      this.publish({ type: "evaluation", result: { type: "RESET", reason: "Explicit veto invalidated the quorum" }, state: this.publicState() });
      return;
    }
    const event = this.state.mode === "demo"
      ? extractDemoEvent(turn, this.state.challenge)
      : await withinDeadline(
          extractWithGateway(this.client!, this.invariant, turn, this.state.challenge),
          EXTRACTION_TIMEOUT_MS
        );

    if (
      this.closed ||
      generationAtEnqueue !== this.state.generation ||
      Date.now() >= this.state.expiresAt
    ) {
      this.publish({ type: "turn.discarded", reason: "Turn became stale during extraction", state: this.publicState() });
      return;
    }

    if (!event) {
      this.publish({
        type: "extraction.none",
        reason: "No explicit, grounded safety event found",
        state: this.publicState()
      });
      return;
    }

    this.publish({ type: "extraction", event });
    const result = evaluateEvent(this.invariant, this.state, event);
    this.publish({ type: "evaluation", result, state: this.publicState() });
    if (result.type !== "SATISFIED") return;

    this.state.status = "UNLOCKING";
    const generation = this.state.generation;
    const controller = new AbortController();
    this.activeUnlock?.abort();
    this.activeUnlock = controller;
    this.publish({ type: "unlock.pending", state: this.publicState() });
    try {
      const receipt = await deliverUnlock(
        this.invariant,
        this.state,
        controller.signal,
        this.state.mode === "live"
      );
      if (
        controller.signal.aborted ||
        generation !== this.state.generation ||
        this.state.status !== "UNLOCKING" ||
        Date.now() >= receipt.validUntil
      ) throw new Error("Authorization was cancelled or expired before commit");
      this.state.receipt = receipt;
      this.state.status = "UNLOCKED";
      this.publish({ type: "unlock.granted", receipt, state: this.publicState() });
      const remaining = receipt.validUntil - Date.now();
      this.expiryTimer = setTimeout(() => {
        this.reset("Authorization capsule expired; latch returned to safe state");
      }, remaining);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unlock delivery failed";
      if (generation === this.state.generation) this.reset(message);
      this.publish({ type: "unlock.denied", message, state: this.publicState() });
    } finally {
      if (this.activeUnlock === controller) this.activeUnlock = undefined;
    }
  }

  sendAudio(chunk: Buffer): void {
    if (this.closed || !this.transcriber) throw new Error("Live transcriber is not connected");
    if (chunk.byteLength === 0 || chunk.byteLength > 64 * 1024 || chunk.byteLength % 2 !== 0) {
      throw new Error("Invalid PCM16 audio chunk size");
    }
    this.audioBytes += chunk.byteLength;
    if (this.audioBytes > MAX_AUDIO_BYTES) {
      this.reset("Maximum live session audio duration reached");
      throw new Error("Audio duration limit reached");
    }
    // Copy onto an ordinary ArrayBuffer so the SDK never receives a pooled
    // Node Buffer with an unrelated byte offset or SharedArrayBuffer backing.
    this.transcriber.sendAudio(Uint8Array.from(chunk).buffer);
  }

  reset(reason = "Operator reset"): void {
    this.state.generation += 1;
    this.activeUnlock?.abort();
    this.activeUnlock = undefined;
    if (this.expiryTimer) clearTimeout(this.expiryTimer);
    this.expiryTimer = undefined;
    resetEvidence(this.state, reason);
    this.publish({ type: "session.reset", state: this.publicState() });
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.state.generation += 1;
    this.activeUnlock?.abort();
    if (this.expiryTimer) clearTimeout(this.expiryTimer);
    await this.queue;
    await this.transcriber?.close();
    this.removeAllListeners();
  }
}
