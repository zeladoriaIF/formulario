import { createHmac, randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";
import { createReadStream, existsSync, readFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

const root = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(root, "public");
const dataDir = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(root, "data");
const authDbPath = path.join(dataDir, "auth.db");
const responsesDbPath = path.join(dataDir, "responses.db");
const secretPath = path.join(dataDir, "app-secret.key");

const host = process.env.HOST || "127.0.0.1";
const port = Number(process.env.PORT || 8787);
const secureCookie = process.env.NODE_ENV === "production" || process.env.SECURE_COOKIE === "1";
const sessionLifetimeMs = 8 * 60 * 60 * 1000;
const cookieName = "ifusp_session";

if (!existsSync(authDbPath) || !existsSync(secretPath)) {
  console.error("Banco de autenticação ausente. Execute importar-planilha.ps1 antes de iniciar.");
  process.exit(1);
}

await mkdir(dataDir, { recursive: true });
const pepper = readFileSync(secretPath, "utf8").trim();
const db = new DatabaseSync(responsesDbPath);
db.exec(`
  PRAGMA journal_mode = DELETE;
  PRAGMA foreign_keys = ON;
  ATTACH DATABASE '${authDbPath.replaceAll("'", "''")}' AS auth;

  CREATE TABLE IF NOT EXISTS responses (
    submission_id TEXT PRIMARY KEY,
    submitted_date TEXT NOT NULL,
    answers_json TEXT NOT NULL
  );
`);

const sessions = new Map();
const attempts = new Map();

const requiredIds = new Set([
  "q02", "q04", "q05", "q06", "q07", "q08", "q09", "q10",
  "q11", "q12", "q13", "q14", "q16", "q17", "q18", "q19", "q20", "q21",
  "q22", "q23", "q24", "q25", "q26", "q27", "q28", "q29", "q30", "q31",
  "q32", "q33", "q34", "q35", "q36", "q37", "q38", "q39", "q40", "q41",
  "q42", "q43", "q44", "q45"
]);
const allowedIds = new Set(
  Array.from({ length: 48 }, (_, index) => index + 1)
    .filter(number => number !== 1 && number !== 3)
    .map(number => `q${String(number).padStart(2, "0")}`)
);

function normalizeDigits(value) {
  return String(value ?? "").replace(/\D/g, "");
}

function uspLookup(usp) {
  return createHmac("sha256", pepper).update(usp).digest("hex");
}

function verifyPassword(password, salt, expectedHex) {
  const actual = scryptSync(password, salt, 32);
  const expected = Buffer.from(expectedHex, "hex");
  return expected.length === actual.length && timingSafeEqual(actual, expected);
}

function parseCookies(request) {
  const cookies = {};
  for (const part of String(request.headers.cookie || "").split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    cookies[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
  }
  return cookies;
}

function getSession(request) {
  const token = parseCookies(request)[cookieName];
  if (!token) return null;
  const session = sessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(token);
    return null;
  }
  session.expiresAt = Date.now() + sessionLifetimeMs;
  return { token, ...session };
}

function createSession(response, payload) {
  const token = randomBytes(32).toString("base64url");
  sessions.set(token, { ...payload, expiresAt: Date.now() + sessionLifetimeMs });
  const secure = secureCookie ? "; Secure" : "";
  response.setHeader(
    "Set-Cookie",
    `${cookieName}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800${secure}`
  );
}

function clearSession(request, response) {
  const session = getSession(request);
  if (session) sessions.delete(session.token);
  const secure = secureCookie ? "; Secure" : "";
  response.setHeader("Set-Cookie", `${cookieName}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`);
}

function securityHeaders(response) {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
  );
}

function sendJson(response, status, payload) {
  securityHeaders(response);
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Cache-Control", "no-store");
  response.end(JSON.stringify(payload));
}

async function readJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 256 * 1024) throw new Error("PAYLOAD_TOO_LARGE");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

function clientKey(request, login) {
  const address = request.socket.remoteAddress || "unknown";
  return `${address}|${String(login).toLowerCase()}`;
}

function rateLimited(key) {
  const now = Date.now();
  const recent = (attempts.get(key) || []).filter(time => now - time < 15 * 60 * 1000);
  attempts.set(key, recent);
  return recent.length >= 8;
}

function recordFailure(key) {
  const list = attempts.get(key) || [];
  list.push(Date.now());
  attempts.set(key, list);
}

function clearFailures(key) {
  attempts.delete(key);
}

function validateAnswers(answers) {
  if (!answers || typeof answers !== "object" || Array.isArray(answers)) return false;
  const entries = Object.entries(answers);
  if (entries.some(([key]) => !allowedIds.has(key))) return false;
  for (const id of requiredIds) {
    const value = answers[id];
    if (value === undefined || value === null || value === "") return false;
    if (Array.isArray(value) && value.length === 0) return false;
  }
  for (const [, value] of entries) {
    if (Array.isArray(value)) {
      if (value.length > 15 || value.some(item => typeof item !== "string" || item.length > 200)) return false;
    } else if (typeof value === "string") {
      if (value.length > 1200) return false;
    } else if (typeof value === "number") {
      if (!Number.isFinite(value) || value < 0 || value > 10) return false;
    } else if (value !== null) {
      return false;
    }
  }
  return true;
}

function getStatus(request) {
  const session = getSession(request);
  const totalEligible = Number(
    db.prepare("SELECT value FROM auth.metadata WHERE key = 'eligible_count'").get()?.value ||
    db.prepare("SELECT COUNT(*) AS total FROM auth.participants WHERE active = 1").get().total
  );
  const responseCount = Number(db.prepare("SELECT COUNT(*) AS total FROM responses").get().total);
  let alreadyAnswered = false;
  if (session?.role === "participant") {
    alreadyAnswered = Boolean(
      db.prepare("SELECT answered FROM auth.participants WHERE id = ?").get(session.participantId)?.answered
    );
  }
  return { totalEligible, responseCount, role: session?.role || null, alreadyAnswered };
}

function anonymousResponses() {
  return db.prepare(`
    SELECT submission_id, submitted_date, answers_json
    FROM responses
    ORDER BY rowid
  `).all().map(row => ({
    id: row.submission_id,
    submittedAt: row.submitted_date,
    answers: JSON.parse(row.answers_json)
  }));
}

async function handleApi(request, response, pathname) {
  if (request.method === "GET" && pathname === "/api/status") {
    return sendJson(response, 200, getStatus(request));
  }

  if (request.method === "POST" && pathname === "/api/login") {
    const body = await readJson(request);
    const rawLogin = String(body.usp || "").trim();
    const rawPassword = String(body.password || "").trim();

    if (rawLogin.toLowerCase() === "teste" && rawPassword.toLowerCase() === "teste") {
      createSession(response, { role: "demo" });
      return sendJson(response, 200, { ok: true, demo: true, alreadyAnswered: false });
    }

    const usp = normalizeDigits(body.usp);
    const password = normalizeDigits(body.password);
    const key = clientKey(request, usp);
    if (rateLimited(key)) return sendJson(response, 429, { error: "Muitas tentativas. Aguarde 15 minutos." });

    const participant = usp
      ? db.prepare(`
          SELECT id, pass_salt, pass_hash, answered
          FROM auth.participants
          WHERE usp_lookup = ? AND active = 1
        `).get(uspLookup(usp))
      : null;

    if (!participant || password.length !== 3 || !verifyPassword(password, participant.pass_salt, participant.pass_hash)) {
      recordFailure(key);
      return sendJson(response, 401, { error: "Número USP ou senha inválidos." });
    }

    clearFailures(key);
    createSession(response, { role: "participant", participantId: participant.id });
    return sendJson(response, 200, { ok: true, alreadyAnswered: Boolean(participant.answered) });
  }

  if (request.method === "POST" && pathname === "/api/admin/login") {
    const body = await readJson(request);
    const login = String(body.login || "");
    const password = String(body.password || "");
    const key = clientKey(request, login);
    if (rateLimited(key)) return sendJson(response, 429, { error: "Muitas tentativas. Aguarde 15 minutos." });

    const admin = db.prepare("SELECT login, pass_salt, pass_hash FROM auth.admins WHERE login = ?").get(login);
    if (!admin || !verifyPassword(password, admin.pass_salt, admin.pass_hash)) {
      recordFailure(key);
      return sendJson(response, 401, { error: "Login administrativo inválido." });
    }

    clearFailures(key);
    createSession(response, { role: "admin" });
    return sendJson(response, 200, { ok: true });
  }

  if (request.method === "POST" && pathname === "/api/logout") {
    clearSession(request, response);
    return sendJson(response, 200, { ok: true });
  }

  if (request.method === "POST" && pathname === "/api/responses") {
    const session = getSession(request);
    if (session?.role !== "participant" && session?.role !== "demo") {
      return sendJson(response, 401, { error: "Sessão inválida." });
    }
    const body = await readJson(request);
    if (!validateAnswers(body.answers)) return sendJson(response, 400, { error: "Respostas incompletas ou inválidas." });

    if (session.role === "demo") {
      sessions.delete(session.token);
      return sendJson(response, 201, {
        ok: true,
        demo: true,
        responseCount: getStatus(request).responseCount
      });
    }

    const submissionId = randomUUID();
    const submittedDate = new Date().toISOString().slice(0, 10);
    db.exec("BEGIN IMMEDIATE");
    try {
      const participant = db.prepare(`
        SELECT answered FROM auth.participants WHERE id = ? AND active = 1
      `).get(session.participantId);
      if (!participant || participant.answered) {
        db.exec("ROLLBACK");
        return sendJson(response, 409, { error: "Participação já registrada." });
      }

      db.prepare(`
        INSERT INTO responses (submission_id, submitted_date, answers_json)
        VALUES (?, ?, ?)
      `).run(submissionId, submittedDate, JSON.stringify(body.answers));

      const updated = db.prepare(`
        UPDATE auth.participants SET answered = 1 WHERE id = ? AND answered = 0
      `).run(session.participantId);
      if (Number(updated.changes) !== 1) throw new Error("PARTICIPATION_UPDATE_FAILED");
      db.exec("COMMIT");
    } catch (error) {
      try { db.exec("ROLLBACK"); } catch {}
      throw error;
    }

    sessions.delete(session.token);
    return sendJson(response, 201, { ok: true, responseCount: getStatus(request).responseCount });
  }

  if (request.method === "GET" && pathname === "/api/admin/dashboard") {
    const session = getSession(request);
    if (session?.role !== "admin") return sendJson(response, 401, { error: "Sessão administrativa inválida." });
    const status = getStatus(request);
    return sendJson(response, 200, { ...status, responses: anonymousResponses() });
  }

  return sendJson(response, 404, { error: "Rota não encontrada." });
}

function serveStatic(response, pathname) {
  const requested = pathname === "/" ? "index.html" : pathname.slice(1);
  const safeName = path.normalize(requested).replace(/^(\.\.(\/|\\|$))+/, "");
  const filePath = path.join(publicDir, safeName);
  if (!filePath.startsWith(publicDir) || !existsSync(filePath)) {
    response.statusCode = 404;
    return response.end("Não encontrado");
  }
  const extension = path.extname(filePath).toLowerCase();
  const types = {
    ".html": "text/html; charset=utf-8",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8"
  };
  securityHeaders(response);
  response.statusCode = 200;
  response.setHeader("Content-Type", types[extension] || "application/octet-stream");
  response.setHeader("Cache-Control", extension === ".html" ? "no-store" : "public, max-age=86400");
  createReadStream(filePath).pipe(response);
}

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    if (url.pathname.startsWith("/api/")) {
      await handleApi(request, response, url.pathname);
    } else if (request.method === "GET") {
      serveStatic(response, url.pathname);
    } else {
      sendJson(response, 405, { error: "Método não permitido." });
    }
  } catch (error) {
    if (error.message === "PAYLOAD_TOO_LARGE") return sendJson(response, 413, { error: "Conteúdo muito grande." });
    if (error instanceof SyntaxError) return sendJson(response, 400, { error: "JSON inválido." });
    console.error("Erro interno:", error.message);
    sendJson(response, 500, { error: "Erro interno do servidor." });
  }
});

server.listen(port, host, () => {
  console.log(`Pesquisa IFUSP disponível em http://${host}:${port}`);
});
