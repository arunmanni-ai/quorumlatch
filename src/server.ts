import "dotenv/config";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import path from "node:path";
import express, { type NextFunction, type Request, type Response } from "express";
import { WebSocketServer, WebSocket } from "ws";
import { DEFAULT_INVARIANT, type InvariantRule, type SessionMode } from "./domain.js";
import { SessionRuntime } from "./runtime.js";
import { signedMockActuator } from "./mock-actuator.js";
import { bearerToken, isLoopback, permitsUnauthenticatedDemo, randomToken, tokenDigest, tokenMatches } from "./security.js";
import { store } from "./store.js";

interface RuntimeRecord {
  runtime: SessionRuntime;
  capabilityDigest: Buffer;
  sockets: Set<WebSocket>;
  wsTickets: Map<string, number>;
  cleanupTimer?: NodeJS.Timeout;
  expiryTimer: NodeJS.Timeout;
}

const app = express();
const server = createServer(app);
const wss = new WebSocketServer({
  noServer: true,
  maxPayload: 64 * 1024,
  perMessageDeflate: false,
  handleProtocols: (protocols) => protocols.has("quorumlatch.v1") ? "quorumlatch.v1" : false
});
const runtimes = new Map<string, RuntimeRecord>();
const publicDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../public");
const host = process.env.HOST ?? "127.0.0.1";
const port = Number(process.env.PORT ?? 3000);
const controlToken = process.env.QUORUMLATCH_CONTROL_TOKEN;
const controlDigest = controlToken ? tokenDigest(controlToken) : undefined;
const configuredOrigins = new Set(
  (process.env.QUORUMLATCH_ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean)
);
let pendingSessions = 0;
let pendingLiveSessions = 0;

if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("Invalid PORT");
if (controlToken && controlToken.length < 32) throw new Error("QUORUMLATCH_CONTROL_TOKEN must contain at least 32 characters");
if (!isLoopback(host) && !controlDigest) throw new Error("A control token is mandatory when HOST is not loopback");
if (!isLoopback(host) && process.env.QUORUMLATCH_TLS_TERMINATED !== "true") {
  throw new Error("Non-loopback deployment requires QUORUMLATCH_TLS_TERMINATED=true behind a trusted TLS proxy");
}
for (const origin of configuredOrigins) {
  let parsed: URL;
  try { parsed = new URL(origin); } catch { throw new Error("QUORUMLATCH_ALLOWED_ORIGINS contains an invalid origin"); }
  if (parsed.origin !== origin || parsed.protocol !== "https:") {
    throw new Error("QUORUMLATCH_ALLOWED_ORIGINS entries must be exact HTTPS origins without paths");
  }
}
if (!isLoopback(host) && configuredOrigins.size === 0) {
  throw new Error("Non-loopback deployment requires QUORUMLATCH_ALLOWED_ORIGINS");
}
if (process.env.QUORUMLATCH_ENABLE_SIGNED_MOCK_RECEIVER === "true") {
  const secret = process.env.QUORUMLATCH_MOCK_RECEIVER_SECRET;
  if (!secret || secret.length < 32) throw new Error("QUORUMLATCH_MOCK_RECEIVER_SECRET must contain at least 32 characters");
  const mockPolicy = structuredClone(DEFAULT_INVARIANT);
  mockPolicy.webhook = { url: "mock://signed-actuator", secret };
  store.putInvariant(mockPolicy);
}

app.disable("x-powered-by");
app.set("trust proxy", false);
app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "camera=(), geolocation=(), microphone=(self)");
  if (!isLoopback(host)) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  if (req.path.startsWith("/api/")) res.setHeader("Cache-Control", "no-store");
  next();
});
app.use(express.json({ limit: "32kb", strict: true }));

const rateWindows = new Map<string, { startedAt: number; count: number }>();
setInterval(() => {
  const cutoff = Date.now() - 5 * 60_000;
  for (const [key, value] of rateWindows) if (value.startedAt < cutoff) rateWindows.delete(key);
}, 60_000).unref();
function rateLimit(name: string, max: number, windowMs = 60_000) {
  return (req: Request, res: Response, next: NextFunction) => {
    const key = `${name}:${req.socket.remoteAddress ?? "unknown"}`;
    const now = Date.now();
    const current = rateWindows.get(key);
    if (!current || now - current.startedAt >= windowMs) {
      rateWindows.set(key, { startedAt: now, count: 1 });
      return next();
    }
    current.count += 1;
    if (current.count > max) return res.status(429).json({ error: "Rate limit exceeded" });
    next();
  };
}

function hasAdmin(req: Request): boolean {
  return Boolean(controlDigest && tokenMatches(bearerToken(req.header("authorization")), controlDigest));
}

function requireAdmin(req: Request, res: Response, next: NextFunction) {
  if (!controlDigest) return res.status(503).json({ error: "Live control is disabled until QUORUMLATCH_CONTROL_TOKEN is configured" });
  if (!hasAdmin(req)) return res.status(401).json({ error: "Invalid control-plane credential" });
  next();
}

function sessionRecord(req: Request, res: Response): RuntimeRecord | undefined {
  const record = runtimes.get(String(req.params.id ?? ""));
  if (!record) {
    res.status(404).json({ error: "Unknown or expired session" });
    return undefined;
  }
  if (!tokenMatches(bearerToken(req.header("authorization")), record.capabilityDigest)) {
    res.status(404).json({ error: "Unknown or expired session" });
    return undefined;
  }
  return record;
}

async function destroyRuntime(sessionId: string): Promise<void> {
  const record = runtimes.get(sessionId);
  if (!record) return;
  runtimes.delete(sessionId);
  clearTimeout(record.expiryTimer);
  if (record.cleanupTimer) clearTimeout(record.cleanupTimer);
  for (const socket of record.sockets) socket.terminate();
  await record.runtime.close().catch(() => undefined);
  store.deleteSession(sessionId);
}

function scheduleIdleCleanup(sessionId: string, record: RuntimeRecord): void {
  if (record.cleanupTimer) clearTimeout(record.cleanupTimer);
  record.cleanupTimer = setTimeout(() => {
    if (record.sockets.size === 0) void destroyRuntime(sessionId);
  }, 15_000);
}

app.use("/api", rateLimit("api", 180));
app.use("/api", (req, res, next) => {
  if (["POST", "PUT", "PATCH"].includes(req.method) && !req.is("application/json")) {
    return res.status(415).json({ error: "Application JSON is required" });
  }
  next();
});

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, product: "QuorumLatch", authority: "deterministic-policy-engine" });
});

app.get("/api/invariant", (_req, res) => {
  const invariant = store.invariants.get(DEFAULT_INVARIANT.id)!;
  res.json({ ...invariant, webhook: invariant.webhook ? { configured: true } : undefined });
});

app.get("/api/mock-actuator", (_req, res) => {
  if (process.env.QUORUMLATCH_ENABLE_SIGNED_MOCK_RECEIVER !== "true") {
    return res.status(404).json({ error: "Not found" });
  }
  res.json({ receiver: "SIGNED_MOCK_ACTUATOR", ...signedMockActuator.publicState() });
});

app.post("/api/invariants", rateLimit("policy-write", 10), requireAdmin, (req, res) => {
  try {
    store.putInvariant(req.body as InvariantRule);
    res.status(201).json({ id: req.body.id, status: "REGISTERED" });
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : "Invalid invariant" });
  }
});

app.post("/api/sessions", rateLimit("session-create", 12), async (req, res) => {
  let createdSessionId: string | undefined;
  let reservation: SessionMode | undefined;
  try {
    const mode = (req.body?.mode ?? "demo") as SessionMode;
    if (!(mode === "demo" || mode === "live")) throw new Error("Mode must be demo or live");
    const admin = hasAdmin(req);
    if (mode === "live" && !admin) {
      return res.status(controlDigest ? 401 : 503).json({ error: controlDigest ? "Live Mode requires the control-plane credential" : "Live Mode is disabled until QUORUMLATCH_CONTROL_TOKEN is configured" });
    }
    if (mode === "live" && !process.env.ASSEMBLYAI_API_KEY) throw new Error("ASSEMBLYAI_API_KEY is not configured");
    if (mode === "demo" && !permitsUnauthenticatedDemo(host, req.socket.remoteAddress) && !admin) {
      return res.status(403).json({ error: "Unauthenticated Demo Mode is loopback-only" });
    }
    const invariantId = String(req.body?.invariantId ?? DEFAULT_INVARIANT.id);
    if (mode === "demo" && invariantId !== DEFAULT_INVARIANT.id && !admin) {
      return res.status(403).json({ error: "Custom Demo policies require control-plane authorization" });
    }
    const selectedInvariant = store.invariants.get(invariantId);
    if (!selectedInvariant) throw new Error("Unknown invariant");
    if (mode === "live" && !selectedInvariant.webhook) {
      throw new Error("Live Mode requires a configured webhook receiver");
    }
    if (runtimes.size + pendingSessions >= 64) {
      return res.status(503).json({ error: "Active session capacity reached" });
    }
    const activeLiveSessions = [...runtimes.values()].filter((record) => record.runtime.state.mode === "live").length;
    if (mode === "live" && activeLiveSessions + pendingLiveSessions >= 8) {
      return res.status(429).json({ error: "Active Live Mode capacity reached" });
    }
    reservation = mode;
    pendingSessions += 1;
    if (mode === "live") pendingLiveSessions += 1;
    const state = store.createSession(invariantId, mode);
    createdSessionId = state.id;
    const runtime = new SessionRuntime(state, store.invariantFor(state));
    const capability = randomToken();
    await runtime.start();
    const record: RuntimeRecord = {
      runtime,
      capabilityDigest: tokenDigest(capability),
      sockets: new Set(),
      wsTickets: new Map(),
      expiryTimer: setTimeout(() => void destroyRuntime(state.id), state.expiresAt - Date.now())
    };
    runtimes.set(state.id, record);
    scheduleIdleCleanup(state.id, record);
    res.status(201).json({
      sessionId: state.id,
      sessionToken: capability,
      mode,
      streamUrl: `/stream?sessionId=${state.id}`,
      state: runtime.publicState()
    });
  } catch (error) {
    if (createdSessionId) store.deleteSession(createdSessionId);
    res.status(400).json({ error: error instanceof Error ? error.message : "Could not start session" });
  } finally {
    if (reservation) {
      pendingSessions -= 1;
      if (reservation === "live") pendingLiveSessions -= 1;
    }
  }
});

app.get("/api/sessions/:id", (req, res) => {
  const record = sessionRecord(req, res);
  if (record) res.json(record.runtime.snapshot());
});

app.post("/api/sessions/:id/ws-ticket", rateLimit("ws-ticket", 30), (req, res) => {
  const record = sessionRecord(req, res);
  if (!record) return;
  const ticket = randomToken(24);
  const digest = tokenDigest(ticket).toString("hex");
  const now = Date.now();
  for (const [key, expiry] of record.wsTickets) if (expiry <= now) record.wsTickets.delete(key);
  if (record.wsTickets.size >= 5) return res.status(429).json({ error: "Too many pending WebSocket tickets" });
  record.wsTickets.set(digest, now + 30_000);
  res.status(201).json({ ticket, expiresInMs: 30_000 });
});

app.post("/api/sessions/:id/demo-turn", rateLimit("demo-turn", 60), async (req, res) => {
  try {
    const record = sessionRecord(req, res);
    if (!record) return;
    await record.runtime.injectDemoTurn(String(req.body?.speaker ?? ""), String(req.body?.transcript ?? ""));
    res.json({ ok: true, state: record.runtime.publicState() });
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : "Turn failed" });
  }
});

app.post("/api/sessions/:id/reset", rateLimit("reset", 30), (req, res) => {
  const record = sessionRecord(req, res);
  if (!record) return;
  record.runtime.reset();
  res.json({ ok: true, state: record.runtime.publicState() });
});

app.use(express.static(publicDir, { dotfiles: "deny", fallthrough: true, etag: true, maxAge: 0 }));
app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
  const status = typeof error === "object" && error && "status" in error && typeof error.status === "number"
    ? error.status
    : 500;
  res.status(status >= 400 && status < 500 ? status : 500).json({ error: status === 400 ? "Malformed request body" : "Request rejected" });
});

server.on("upgrade", (request, socket, head) => {
  try {
    const url = new URL(request.url ?? "/", "http://localhost");
    if (url.pathname !== "/stream") return socket.destroy();
    const origin = request.headers.origin;
    if (origin) {
      const parsedOrigin = new URL(origin);
      const allowed = configuredOrigins.size > 0
        ? configuredOrigins.has(parsedOrigin.origin)
        : parsedOrigin.host === request.headers.host && ["http:", "https:"].includes(parsedOrigin.protocol);
      if (!allowed) return socket.destroy();
    }
    const sessionId = url.searchParams.get("sessionId") ?? "";
    const record = runtimes.get(sessionId);
    if (!record) return socket.destroy();
    const socketLimit = record.runtime.state.mode === "live" ? 1 : 4;
    if (record.sockets.size >= socketLimit) return socket.destroy();
    const protocols = String(request.headers["sec-websocket-protocol"] ?? "").split(",").map((value) => value.trim());
    const ticket = protocols.find((value) => value.startsWith("ticket."))?.slice(7);
    const ticketKey = ticket ? tokenDigest(ticket).toString("hex") : "";
    const ticketExpiry = record.wsTickets.get(ticketKey);
    if (!protocols.includes("quorumlatch.v1") || !ticketExpiry || ticketExpiry <= Date.now()) return socket.destroy();
    record.wsTickets.delete(ticketKey);
    if (record.cleanupTimer) clearTimeout(record.cleanupTimer);
    wss.handleUpgrade(request, socket, head, (websocket) => {
      (websocket as WebSocket & { sessionId?: string }).sessionId = sessionId;
      wss.emit("connection", websocket, request);
    });
  } catch {
    socket.destroy();
  }
});

wss.on("connection", (socket: WebSocket & { sessionId?: string }) => {
  const sessionId = socket.sessionId!;
  const record = runtimes.get(sessionId);
  if (!record) return socket.close(1008, "Unknown session");
  record.sockets.add(socket);
  let windowStartedAt = Date.now();
  let windowBytes = 0;
  const send = (event: unknown) => {
    if (socket.readyState !== WebSocket.OPEN) return;
    if (socket.bufferedAmount > 1024 * 1024) return socket.close(1008, "Slow consumer");
    socket.send(JSON.stringify(event));
  };
  send(record.runtime.snapshot());
  record.runtime.on("event", send);
  socket.on("message", (data, isBinary) => {
    if (!isBinary || record.runtime.state.mode !== "live") return socket.close(1008, "Binary audio required");
    const now = Date.now();
    if (now - windowStartedAt >= 1_000) { windowStartedAt = now; windowBytes = 0; }
    const size = Buffer.isBuffer(data) ? data.byteLength : (data as ArrayBuffer).byteLength;
    windowBytes += size;
    if (windowBytes > 64 * 1024) return socket.close(1008, "Audio rate exceeded");
    try {
      record.runtime.sendAudio(Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer));
    } catch {
      socket.close(1011, "Audio stream rejected");
    }
  });
  socket.on("error", () => undefined);
  socket.on("close", () => {
    record.runtime.off("event", send);
    record.sockets.delete(socket);
    if (record.sockets.size === 0 && runtimes.get(sessionId) === record) scheduleIdleCleanup(sessionId, record);
  });
});

server.on("error", (error) => {
  console.error(`QuorumLatch server error: ${error.message}`);
  process.exitCode = 1;
});

server.listen(port, host, () => {
  console.log(`QuorumLatch control plane listening on http://${host}:${port}`);
  console.log(controlDigest ? "Live control authentication enabled" : "Demo-only posture: configure QUORUMLATCH_CONTROL_TOKEN to enable Live Mode");
});

async function shutdown(): Promise<void> {
  server.close();
  await Promise.all([...runtimes.keys()].map(destroyRuntime));
}
process.once("SIGINT", () => void shutdown());
process.once("SIGTERM", () => void shutdown());
