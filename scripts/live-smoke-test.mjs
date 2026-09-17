import "dotenv/config";
import WebSocket from "ws";

const baseUrl = process.env.QUORUMLATCH_TEST_URL ?? "http://127.0.0.1:3100";
const controlToken = process.env.QUORUMLATCH_CONTROL_TOKEN;

if (!controlToken) throw new Error("QUORUMLATCH_CONTROL_TOKEN is required");

async function requestJson(path, init = {}) {
  const response = await fetch(`${baseUrl}${path}`, init);
  const body = await response.json();
  if (!response.ok) throw new Error(body.error ?? `Request failed with ${response.status}`);
  return body;
}

const session = await requestJson("/api/sessions", {
  method: "POST",
  headers: {
    "content-type": "application/json",
    authorization: `Bearer ${controlToken}`
  },
  body: JSON.stringify({ mode: "live" })
});

const ticket = await requestJson(`/api/sessions/${session.sessionId}/ws-ticket`, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    authorization: `Bearer ${session.sessionToken}`
  },
  body: "{}"
});

const websocketUrl = new URL(session.streamUrl, baseUrl);
websocketUrl.protocol = websocketUrl.protocol === "https:" ? "wss:" : "ws:";
const eventTypes = new Set();

await new Promise((resolve, reject) => {
  const socket = new WebSocket(
    websocketUrl,
    ["quorumlatch.v1", `ticket.${ticket.ticket}`],
    { origin: baseUrl }
  );
  let opened = false;
  let sentChunks = 0;
  let interval;
  const timeout = setTimeout(() => {
    socket.terminate();
    reject(new Error("WebSocket smoke test timed out"));
  }, 10_000);

  socket.on("message", (raw) => {
    try {
      const event = JSON.parse(raw.toString());
      if (typeof event.type === "string") eventTypes.add(event.type);
    } catch {
      // A malformed server event is ignored here; protocol tests cover parsing.
    }
  });
  socket.on("open", () => {
    opened = true;
    interval = setInterval(() => {
      // 100 ms of 16 kHz mono PCM16 silence. Silence cannot satisfy a policy.
      socket.send(Buffer.alloc(3_200), { binary: true });
      sentChunks += 1;
      if (sentChunks === 10) {
        clearInterval(interval);
        setTimeout(() => socket.close(1000, "smoke complete"), 250);
      }
    }, 100);
  });
  socket.on("error", (error) => {
    clearInterval(interval);
    clearTimeout(timeout);
    reject(error);
  });
  socket.on("close", (code) => {
    clearInterval(interval);
    clearTimeout(timeout);
    if (!opened || code !== 1000) return reject(new Error(`WebSocket closed with ${code}`));
    resolve();
  });
});

const actuator = await requestJson("/api/mock-actuator");
if (actuator.status !== "LOCKED") throw new Error("Silent smoke test unexpectedly unlocked actuator");

console.log(JSON.stringify({
  liveSession: "connected",
  websocket: "authenticated",
  audioForwarding: "10 PCM16 chunks accepted",
  observedEvents: [...eventTypes].sort(),
  mockActuator: actuator.status
}));
