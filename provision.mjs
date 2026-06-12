import { createHmac, randomBytes, scryptSync } from "node:crypto";
import { mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

const [authDbPath, secretPath] = process.argv.slice(2);

if (!authDbPath || !secretPath) {
  console.error("Uso: node provision.mjs <auth.db> <app-secret.key> [login ADM] [senha ADM]");
  process.exit(1);
}

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);

let payload;
try {
  payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
} catch {
  console.error("Entrada JSON inválida.");
  process.exit(1);
}

const records = payload?.records;
const adminLogin = String(payload?.adminLogin || "");
const adminPassword = String(payload?.adminPassword || "");

if (!Array.isArray(records) || records.length === 0) {
  console.error("A lista de credenciais está vazia.");
  process.exit(1);
}
if (!adminLogin || adminPassword.length < 8) {
  console.error("Credencial administrativa ausente ou muito curta.");
  process.exit(1);
}

await mkdir(path.dirname(authDbPath), { recursive: true });
await mkdir(path.dirname(secretPath), { recursive: true });

if (!existsSync(secretPath)) {
  await writeFile(secretPath, randomBytes(32).toString("hex"), { encoding: "utf8", mode: 0o600 });
  try {
    await chmod(secretPath, 0o600);
  } catch {
    // Windows pode ignorar bits POSIX; o arquivo continua fora da pasta pública.
  }
}

const pepper = (await readFile(secretPath, "utf8")).trim();
if (pepper.length < 32) {
  console.error("O segredo da aplicação é inválido.");
  process.exit(1);
}

function normalizeDigits(value) {
  return String(value ?? "").replace(/\D/g, "");
}

function lookupFor(usp) {
  return createHmac("sha256", pepper).update(usp).digest("hex");
}

function passwordRecord(password) {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, 32).toString("hex");
  return { salt, hash };
}

const normalized = [];
const seen = new Set();

for (const item of records) {
  const usp = normalizeDigits(item.usp);
  let cpf = normalizeDigits(item.cpf);
  if (cpf.length > 0 && cpf.length < 11) cpf = cpf.padStart(11, "0");

  if (usp.length < 5 || usp.length > 10 || cpf.length !== 11) {
    console.error("A base contém um registro inválido.");
    process.exit(1);
  }

  const lookup = lookupFor(usp);
  if (seen.has(lookup)) {
    console.error("A base contém número USP duplicado.");
    process.exit(1);
  }
  seen.add(lookup);

  const password = cpf.slice(0, 3);
  normalized.push({ lookup, ...passwordRecord(password) });
}

const db = new DatabaseSync(authDbPath);
db.exec(`
  PRAGMA journal_mode = DELETE;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS participants (
    id INTEGER PRIMARY KEY,
    usp_lookup TEXT NOT NULL UNIQUE,
    pass_salt TEXT NOT NULL,
    pass_hash TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    answered INTEGER NOT NULL DEFAULT 0 CHECK (answered IN (0, 1))
  );

  CREATE TABLE IF NOT EXISTS admins (
    login TEXT PRIMARY KEY,
    pass_salt TEXT NOT NULL,
    pass_hash TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

const deactivate = db.prepare("UPDATE participants SET active = 0");
const upsert = db.prepare(`
  INSERT INTO participants (usp_lookup, pass_salt, pass_hash, active)
  VALUES (?, ?, ?, 1)
  ON CONFLICT(usp_lookup) DO UPDATE SET
    pass_salt = excluded.pass_salt,
    pass_hash = excluded.pass_hash,
    active = 1
`);
const upsertAdmin = db.prepare(`
  INSERT INTO admins (login, pass_salt, pass_hash)
  VALUES (?, ?, ?)
  ON CONFLICT(login) DO UPDATE SET
    pass_salt = excluded.pass_salt,
    pass_hash = excluded.pass_hash
`);
const setMeta = db.prepare(`
  INSERT INTO metadata (key, value) VALUES (?, ?)
  ON CONFLICT(key) DO UPDATE SET value = excluded.value
`);

db.exec("BEGIN IMMEDIATE");
try {
  deactivate.run();
  for (const item of normalized) {
    upsert.run(item.lookup, item.salt, item.hash);
  }
  const admin = passwordRecord(adminPassword);
  upsertAdmin.run(adminLogin, admin.salt, admin.hash);
  setMeta.run("eligible_count", String(normalized.length));
  setMeta.run("imported_at", new Date().toISOString());
  db.exec("COMMIT");
} catch (error) {
  db.exec("ROLLBACK");
  throw error;
} finally {
  db.close();
}

console.log(JSON.stringify({
  imported: normalized.length,
  adminLogin,
  personalDataWrittenInPlaintext: false
}));
