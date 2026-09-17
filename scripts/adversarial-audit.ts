import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import WebSocket from "ws";
import { DEFAULT_INVARIANT } from "../src/domain.js";

const port = 4317;
const base = `http://127.0.0.1:${port}`;
const controlToken = "audit-control-token-0123456789-abcdef";
const child = spawn(process.execPath, ["dist/src/server.js"], {
  cwd: process.cwd(),
  env: { ...process.env, PORT: String(port), HOST: "127.0.0.1", QUORUMLATCH_CONTROL_TOKEN: controlToken, ASSEMBLYAI_API_KEY: "" },
  stdio: ["ignore", "pipe", "pipe"]
});

async function waitUntilReady(): Promise<void> {
  let output = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { output += chunk; });
  for (let attempt = 0; attempt < 50; attempt++) {
    if (output.includes("control plane listening")) return;
    if (child.exitCode !== null) throw new Error(`Audit server exited early: ${output}`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("Audit server did not start");
}

async function request(path: string, options: RequestInit = {}) {
  return fetch(base + path, options);
}

async function json(path: string, method: string, body: unknown, token?: string) {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  const response = await request(path, { method, headers, body: JSON.stringify(body) });
  const payload = await response.json() as Record<string, any>;
  return { response, payload };
}

async function websocketRejected(url: string, protocols?: string[], origin?: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const socket = new WebSocket(url, protocols, origin ? { origin } : undefined);
    const timer = setTimeout(() => reject(new Error("Rejected WebSocket stayed open")), 1_500);
    socket.once("open", () => { clearTimeout(timer); socket.close(); reject(new Error("Unauthorized WebSocket opened")); });
    socket.once("error", () => { clearTimeout(timer); resolve(); });
    socket.once("close", () => { clearTimeout(timer); resolve(); });
  });
}

async function websocketOpens(url: string, protocols: string[], origin: string): Promise<boolean> {
  return await new Promise<boolean>((resolve) => {
    const socket = new WebSocket(url, protocols, { origin });
    const timer = setTimeout(() => { socket.terminate(); resolve(false); }, 1_500);
    socket.once("open", () => { clearTimeout(timer); socket.close(); resolve(true); });
    socket.once("error", () => { clearTimeout(timer); resolve(false); });
    socket.once("close", () => { clearTimeout(timer); resolve(false); });
  });
}

try {
  await waitUntilReady();

  const health = await request("/api/health");
  assert.equal(health.status, 200);
  assert.match(health.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
  assert.equal(health.headers.get("x-frame-options"), "DENY");
  assert.equal(health.headers.get("cache-control"), "no-store");
  assert.equal((await request("/.env")).status, 404);
  assert.equal((await request("/%2e%2e/.env")).status, 404);

  const policyAttack = structuredClone(DEFAULT_INVARIANT);
  policyAttack.id = "attacker-policy";
  policyAttack.steps[1]!.speaker = "A";
  assert.equal((await json("/api/invariants", "POST", policyAttack)).response.status, 401);
  assert.equal((await json("/api/invariants", "POST", policyAttack, controlToken)).response.status, 400);

  const nonJsonCreate = await request("/api/sessions", {
    method: "POST",
    headers: { "content-type": "text/plain" },
    body: "{}"
  });
  assert.equal(nonJsonCreate.status, 415);

  const reservedIdPolicy = structuredClone(DEFAULT_INVARIANT);
  reservedIdPolicy.id = "reserved-id-policy";
  reservedIdPolicy.steps[0]!.id = "constructor";
  reservedIdPolicy.steps[1]!.after = "constructor";
  reservedIdPolicy.steps[1]!.slots.site = { equals: "right knee" };
  assert.equal((await json("/api/invariants", "POST", reservedIdPolicy, controlToken)).response.status, 201);
  const reservedSession = await json(
    "/api/sessions", "POST", { mode: "demo", invariantId: reservedIdPolicy.id }, controlToken
  );
  assert.equal(reservedSession.response.status, 201);
  const reservedTurn = await json(
    `/api/sessions/${reservedSession.payload.sessionId}/demo-turn`,
    "POST",
    {
      speaker: "B",
      transcript: `Confirm incision on the right knee. Authorization code ${reservedSession.payload.state.challenge}.`
    },
    reservedSession.payload.sessionToken
  );
  assert.equal(reservedTurn.payload.state.progress, 0);

  const ssrfAttack = structuredClone(DEFAULT_INVARIANT);
  ssrfAttack.id = "ssrf-policy";
  ssrfAttack.webhook = { url: "https://127.0.0.1/internal", secret: "x".repeat(32) };
  assert.equal((await json("/api/invariants", "POST", ssrfAttack, controlToken)).response.status, 400);

  assert.equal((await json("/api/sessions", "POST", { mode: "live" }, "wrong-token")).response.status, 401);
  assert.equal((await json("/api/sessions", "POST", { mode: "live" }, controlToken)).response.status, 400);

  const created = await json("/api/sessions", "POST", { mode: "demo" });
  assert.equal(created.response.status, 201);
  const sessionId = created.payload.sessionId as string;
  const sessionToken = created.payload.sessionToken as string;
  const challenge = created.payload.state.challenge as string;
  assert.ok(sessionToken.length >= 40);
  assert.ok(challenge);

  assert.equal((await request(`/api/sessions/${sessionId}`)).status, 404);
  assert.equal((await request(`/api/sessions/${sessionId}`, { headers: { authorization: "Bearer wrong" } })).status, 404);
  assert.equal((await request(`/api/sessions/${sessionId}`, { headers: { authorization: `Bearer ${sessionToken}` } })).status, 200);

  const wsUrl = `ws://127.0.0.1:${port}/stream?sessionId=${sessionId}`;
  await websocketRejected(wsUrl, ["quorumlatch.v1"]);
  const ticketResponse = await json(`/api/sessions/${sessionId}/ws-ticket`, "POST", {}, sessionToken);
  const ticket = ticketResponse.payload.ticket as string;
  await websocketRejected(wsUrl, ["quorumlatch.v1", `ticket.${ticket}`], "https://attacker.invalid");
  const socket = new WebSocket(wsUrl, ["quorumlatch.v1", `ticket.${ticket}`], { origin: base });
  await once(socket, "open");
  const [snapshot] = await once(socket, "message");
  assert.equal(JSON.parse(String(snapshot)).type, "snapshot");
  socket.close();
  await websocketRejected(wsUrl, ["quorumlatch.v1", `ticket.${ticket}`], base);

  const raceTicketResponse = await json(`/api/sessions/${sessionId}/ws-ticket`, "POST", {}, sessionToken);
  const raceProtocols = ["quorumlatch.v1", `ticket.${raceTicketResponse.payload.ticket}`];
  const raceResults = await Promise.all([
    websocketOpens(wsUrl, raceProtocols, base),
    websocketOpens(wsUrl, raceProtocols, base)
  ]);
  assert.equal(raceResults.filter(Boolean).length, 1);

  const oversizedTicketResponse = await json(`/api/sessions/${sessionId}/ws-ticket`, "POST", {}, sessionToken);
  const oversizedSocket = new WebSocket(wsUrl, ["quorumlatch.v1", `ticket.${oversizedTicketResponse.payload.ticket}`], { origin: base });
  await once(oversizedSocket, "open");
  oversizedSocket.send(Buffer.alloc(70 * 1024));
  const [oversizedCode] = await once(oversizedSocket, "close");
  assert.equal(oversizedCode, 1009);

  const turn = (speaker: string, transcript: string) => json(
    `/api/sessions/${sessionId}/demo-turn`, "POST", { speaker, transcript }, sessionToken
  );
  const replay = await turn("A", "Initiate incision on the right knee.");
  assert.equal(replay.payload.state.status, "LOCKED");
  assert.equal(Object.keys(replay.payload.state.evidence).length, 0);
  await turn("A", `Initiate incision on the right knee. Authorization code ${challenge}.`);
  await turn("B", "Yes, go ahead.");
  await turn("B", `Confirm incision on the right knee. Authorization code ${challenge}.`);
  const authorized = await request(`/api/sessions/${sessionId}`, { headers: { authorization: `Bearer ${sessionToken}` } });
  const authorizedState = (await authorized.json() as any).state;
  assert.equal(authorizedState.status, "UNLOCKED");
  assert.equal(authorizedState.receipt.delivery, "simulated");

  const race = await json("/api/sessions", "POST", { mode: "demo" });
  const raceId = race.payload.sessionId as string;
  const raceToken = race.payload.sessionToken as string;
  const raceChallenge = race.payload.state.challenge as string;
  const raceTurn = (speaker: string, transcript: string) => json(
    `/api/sessions/${raceId}/demo-turn`, "POST", { speaker, transcript }, raceToken
  );
  await raceTurn("A", `Initiate incision on the right knee. Authorization code ${raceChallenge}.`);
  const pendingGrant = raceTurn("B", `Confirm incision on the right knee. Authorization code ${raceChallenge}.`);
  await new Promise((resolve) => setTimeout(resolve, 30));
  await json(`/api/sessions/${raceId}/reset`, "POST", {}, raceToken);
  await pendingGrant;
  const afterReset = await request(`/api/sessions/${raceId}`, { headers: { authorization: `Bearer ${raceToken}` } });
  const afterResetState = (await afterReset.json() as any).state;
  assert.equal(afterResetState.status, "LOCKED");
  assert.equal(afterResetState.receipt, undefined);

  const malformed = await request("/api/sessions", { method: "POST", headers: { "content-type": "application/json" }, body: "{" });
  assert.equal(malformed.status, 400);
  assert.deepEqual(await malformed.json(), { error: "Malformed request body" });
  const oversized = await request("/api/sessions", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ padding: "x".repeat(40_000) }) });
  assert.equal(oversized.status, 413);

  console.log("Adversarial audit passed: 30 security assertions");
} finally {
  child.kill("SIGTERM");
  await Promise.race([once(child, "exit"), new Promise((resolve) => setTimeout(resolve, 2_000))]);
}
