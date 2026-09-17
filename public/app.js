const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

let sessionId;
let sessionToken;
let socket;
let currentMode = "demo";
let sessionChallenge;
let eventCount = 0;
let audioContext;
let mediaStream;
let processor;

const ui = {
  core: $("#core-panel"),
  title: $("#verdict-title"),
  kicker: $("#verdict-kicker"),
  reason: $("#verdict-reason"),
  transcript: $("#live-transcript"),
  speaker: $("#speaker-chip"),
  ledger: $("#ledger"),
  count: $("#event-count"),
  receipt: $("#receipt"),
  receiptHash: $("#receipt-hash"),
  mode: $("#mode-badge"),
  connection: $("#connection-label"),
  liveButton: $("#live-button")
};

function timeLabel(timestamp = Date.now()) {
  return new Date(timestamp).toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function addLedger(title, detail, tone = "neutral", timestamp) {
  eventCount += 1;
  ui.count.textContent = `${String(eventCount).padStart(3, "0")} EVENTS`;
  const entry = document.createElement("div");
  entry.className = `ledger-entry ${tone}`;
  entry.innerHTML = `<time>${timeLabel(timestamp)}</time><b></b><p></p>`;
  entry.querySelector("b").textContent = title;
  entry.querySelector("p").textContent = detail;
  ui.ledger.prepend(entry);
}

function updateState(state) {
  const matchedA = Boolean(state.evidence?.["operator-command"]);
  const matchedB = Boolean(state.evidence?.["independent-readback"]);
  $("#step-a").classList.toggle("matched", matchedA);
  $("#step-b").classList.toggle("matched", matchedB);
  $("#step-a .step-state").textContent = matchedA ? "PROVEN" : "WAITING";
  $("#step-b .step-state").textContent = matchedB ? "PROVEN" : "WAITING";
  ui.core.classList.toggle("proof-a-valid", matchedA);
  ui.core.classList.toggle("proof-b-valid", matchedB);
  ui.core.classList.toggle("unlocked", state.status === "UNLOCKED");
  ui.kicker.classList.remove("tone-cyan", "tone-amber");

  if (state.status === "UNLOCKED") {
    ui.title.textContent = "AUTHORIZED";
    ui.kicker.textContent = "SHORT-LIVED GRANT ACTIVE";
    ui.kicker.classList.add("tone-cyan");
    ui.reason.textContent = "Both grounded proofs satisfy the temporal invariant.";
    $("#latch-symbol").textContent = "·";
  } else if (state.status === "UNLOCKING") {
    ui.title.textContent = "VERIFYING";
    ui.kicker.textContent = "ISSUING AUTHORIZATION CAPSULE";
    ui.reason.textContent = "Quorum proven. Signing one-time grant.";
  } else {
    ui.title.textContent = matchedA ? "ARMED" : "LOCKED";
    ui.kicker.textContent = matchedA ? "ONE PROOF REMAINS" : "PHYSICAL OUTPUT INHIBITED";
    if (matchedA) ui.kicker.classList.add("tone-amber");
    ui.reason.textContent = matchedA
      ? "Awaiting an explicit readback from Speaker B."
      : "Awaiting an explicit operator command.";
    $("#latch-symbol").textContent = "×";
  }
}

function handleEvent(event) {
  if (event.type === "snapshot") {
    updateState(event.state);
    ui.connection.textContent = "CAPABILITY VERIFIED";
    return;
  }
  if (event.type === "session.ready") {
    ui.connection.textContent = event.mode === "live" ? "ASSEMBLYAI STREAM ACTIVE" : "SIMULATION READY";
    addLedger("Session armed", `${event.mode.toUpperCase()} mode · fail-closed`, "good", event.at);
  }
  if (event.type === "turn.partial" || event.type === "turn.finalizing" || event.type === "turn.final") {
    ui.speaker.textContent = event.speaker;
    ui.transcript.textContent = event.transcript;
    if (event.type === "turn.final") addLedger(`Speaker ${event.speaker} finalized`, event.transcript, "neutral", event.at);
  }
  if (event.type === "extraction") {
    const slots = Object.entries(event.event.slots).map(([key, value]) => `${key}=${value}`).join(" · ");
    addLedger(`Extracted ${event.event.action}`, slots, "good", event.at);
  }
  if (event.type === "extraction.none") {
    addLedger("No safety event", event.reason, "bad", event.at);
    ui.reason.textContent = event.reason;
  }
  if (event.type === "evaluation") {
    const good = ["STEP_MATCHED", "SATISFIED"].includes(event.result.type);
    addLedger(event.result.type.replaceAll("_", " "), event.result.reason, good ? "good" : "bad", event.at);
    ui.reason.textContent = event.result.reason;
    updateState(event.state);
  }
  if (event.type === "unlock.pending") updateState(event.state);
  if (event.type === "unlock.granted") {
    updateState(event.state);
    ui.receipt.classList.add("issued");
    const ttlSeconds = Math.max(0, Math.ceil((event.receipt.validUntil - event.receipt.issuedAt) / 1000));
    ui.receipt.querySelector("b").textContent = `ISSUED / ${ttlSeconds}s TTL`;
    ui.receiptHash.textContent = `sha256:${event.receipt.evidenceDigest}`;
    addLedger("Unlock grant issued", `${event.receipt.delivery} · expires ${timeLabel(event.receipt.validUntil)}`, "good", event.at);
  }
  if (event.type === "unlock.expired" || event.type === "session.reset") {
    updateState(event.state);
    ui.receipt.classList.remove("issued");
    ui.receipt.querySelector("b").textContent = "NOT ISSUED";
    ui.receiptHash.textContent = "—";
    addLedger("Latch returned safe", event.state.lastError ?? "Authorization cleared", "neutral", event.at);
  }
  if (event.type === "error") addLedger("Processing fault", event.message, "bad", event.at);
  if (event.type === "unlock.denied") addLedger("Unlock denied", event.message, "bad", event.at);
}

async function connectSocket(path, capability) {
  if (socket) socket.close();
  const ticketResponse = await fetch(`/api/sessions/${sessionId}/ws-ticket`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${capability}` },
    body: "{}"
  });
  const ticketResult = await ticketResponse.json();
  if (!ticketResponse.ok) throw new Error(ticketResult.error);
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  socket = new WebSocket(`${protocol}//${location.host}${path}`, ["quorumlatch.v1", `ticket.${ticketResult.ticket}`]);
  socket.binaryType = "arraybuffer";
  socket.onmessage = ({ data }) => handleEvent(JSON.parse(data));
  socket.onclose = () => { ui.connection.textContent = "STREAM DISCONNECTED"; };
}

async function createSession(mode = "demo", controlToken) {
  const headers = { "content-type": "application/json" };
  if (controlToken) headers.authorization = `Bearer ${controlToken}`;
  const response = await fetch("/api/sessions", {
    method: "POST",
    headers,
    body: JSON.stringify({ mode })
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error);
  sessionId = result.sessionId;
  sessionToken = result.sessionToken;
  sessionChallenge = result.state.challenge;
  $("#challenge-code").textContent = sessionChallenge.toUpperCase();
  currentMode = mode;
  ui.mode.textContent = `${mode.toUpperCase()} MODE`;
  await connectSocket(result.streamUrl, sessionToken);
  updateState(result.state);
}

async function inject(speaker, transcript, button) {
  button.disabled = true;
  try {
    const response = await fetch(`/api/sessions/${sessionId}/demo-turn`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${sessionToken}` },
      body: JSON.stringify({ speaker, transcript: `${transcript} Authorization code ${sessionChallenge}.` })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error);
  } catch (error) {
    addLedger("Request failed", error.message, "bad");
  } finally {
    button.disabled = false;
  }
}

function downsampleTo16k(input, inputRate) {
  if (inputRate === 16_000) return input;
  const ratio = inputRate / 16_000;
  const output = new Float32Array(Math.round(input.length / ratio));
  let offset = 0;
  for (let i = 0; i < output.length; i++) {
    const next = Math.round((i + 1) * ratio);
    let sum = 0;
    let count = 0;
    for (; offset < next && offset < input.length; offset++) { sum += input[offset]; count++; }
    output[i] = count ? sum / count : 0;
  }
  return output;
}

function floatToPcm16(float32) {
  const buffer = new ArrayBuffer(float32.length * 2);
  const view = new DataView(buffer);
  float32.forEach((sample, index) => {
    const clipped = Math.max(-1, Math.min(1, sample));
    view.setInt16(index * 2, clipped < 0 ? clipped * 0x8000 : clipped * 0x7fff, true);
  });
  return buffer;
}

async function startLive() {
  try {
    const controlToken = await requestControlToken();
    if (!controlToken) return;
    await stopAudio();
    await createSession("live", controlToken);
    mediaStream = await navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true }
    });
    audioContext = new AudioContext();
    const source = audioContext.createMediaStreamSource(mediaStream);
    processor = audioContext.createScriptProcessor(4096, 1, 1);
    processor.onaudioprocess = (event) => {
      if (socket?.readyState !== WebSocket.OPEN) return;
      const input = event.inputBuffer.getChannelData(0);
      socket.send(floatToPcm16(downsampleTo16k(input, audioContext.sampleRate)));
    };
    source.connect(processor);
    processor.connect(audioContext.destination);
    ui.liveButton.innerHTML = "<span></span> Live microphone active";
    $$(".scenario").forEach((button) => button.disabled = true);
  } catch (error) {
    addLedger("Live Mode unavailable", error.message, "bad");
    await createSession("demo");
  }
}

function requestControlToken() {
  const dialog = $("#control-dialog");
  const input = $("#control-token");
  input.value = "";
  dialog.showModal();
  input.focus();
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => {
      const token = dialog.returnValue === "connect" && input.value.length >= 32 ? input.value : undefined;
      input.value = "";
      resolve(token);
    }, { once: true });
  });
}

async function stopAudio() {
  if (processor) processor.disconnect();
  if (audioContext) await audioContext.close();
  mediaStream?.getTracks().forEach((track) => track.stop());
  processor = undefined; audioContext = undefined; mediaStream = undefined;
}

$$('.scenario').forEach((button) => {
  button.addEventListener("click", () => inject(button.dataset.speaker, button.dataset.text, button));
});

$("#reset-button").addEventListener("click", async () => {
  await fetch(`/api/sessions/${sessionId}/reset`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${sessionToken}` },
    body: "{}"
  });
});

ui.liveButton.addEventListener("click", startLive);

createSession("demo").catch((error) => addLedger("Startup failed", error.message, "bad"));
