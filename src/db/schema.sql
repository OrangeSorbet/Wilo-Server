-- Wilo-Server schema. Normalized per CLAUDE.md's "server stores normalized,
-- not flat" note: roles/grants and invoices/products are real tables, not
-- JSON blobs duplicated per row.

CREATE TABLE IF NOT EXISTS roles (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  rank INTEGER NOT NULL,
  role_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS role_grants (
  role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id TEXT NOT NULL,
  scopes_json TEXT,
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_by TEXT,
  created_at TEXT NOT NULL,
  must_change_password INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS user_roles (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_type TEXT NOT NULL,
  device_fingerprint TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS invoices (
  id TEXT PRIMARY KEY,
  provider_json TEXT,
  receiver_json TEXT,
  invoice_json TEXT,
  totals_json TEXT,
  status TEXT NOT NULL DEFAULT 'SCANNED_UNREVIEWED',
  thumbnail TEXT,
  order_index INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT
);

-- Column set mirrors backend/prompt.txt's products[] schema exactly (same
-- keys the frontend reads via extracted.invoices[0].products[]) - see
-- fieldGroups.js's header comment for why this must stay in sync.
CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY,
  invoice_id TEXT NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
  item_no TEXT,
  item_code TEXT,
  description TEXT,
  hsn_sac TEXT,
  qty TEXT,
  rate TEXT,
  total_base_value TEXT,
  cgst_rate TEXT,
  cgst_value TEXT,
  sgst_rate TEXT,
  sgst_value TEXT,
  total_gst TEXT,
  total_amount TEXT
);

-- Append-only (app-level: no route ever issues UPDATE/DELETE against this
-- table). hash = sha256(row content + prev_hash) -> tamper-evident chain,
-- same guarantee the architecture doc wanted from shard files, as DB rows.
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_user_id TEXT,
  permission_id TEXT NOT NULL,
  target_json TEXT,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
