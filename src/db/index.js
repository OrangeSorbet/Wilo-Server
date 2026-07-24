import Database from "better-sqlite3";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = process.env.WILO_DB_PATH || path.join(__dirname, "../../data/wilo.db");

fs.mkdirSync(path.dirname(dbPath), { recursive: true });

export const db = new Database(dbPath);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

const schema = fs.readFileSync(path.join(__dirname, "schema.sql"), "utf-8");
db.exec(schema);

// No formal migration runner in this repo - guarded ALTER TABLE for columns
// added after a DB already exists on disk (CREATE TABLE IF NOT EXISTS above
// only covers brand-new DBs).
const userColumns = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
if (!userColumns.includes("must_change_password")) {
  db.exec("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0");
}

// Backfill: the "admin" permission id was added to PERMISSIONS after some
// servers were already bootstrapped, so their Owner role (always rank 0 -
// see routes/auth.js's bootstrap route) has grant rows for every permission
// that existed at bootstrap time, but no "admin" row. Without this, those
// Owners can never see the Admin console. Idempotent (role_grants' PK is
// (role_id, permission_id), and this is guarded besides) and a no-op on a
// fresh/empty DB (no roles yet).
const ownerRolesWithoutAdmin = db.prepare(
  `SELECT id FROM roles WHERE rank = 0 AND id NOT IN (
     SELECT role_id FROM role_grants WHERE permission_id = 'admin'
   )`
).all();
if (ownerRolesWithoutAdmin.length) {
  const insertAdminGrant = db.prepare(
    "INSERT INTO role_grants (role_id, permission_id, scopes_json) VALUES (?, 'admin', ?)"
  );
  for (const role of ownerRolesWithoutAdmin) {
    insertAdminGrant.run(role.id, JSON.stringify(["*"]));
  }
}
