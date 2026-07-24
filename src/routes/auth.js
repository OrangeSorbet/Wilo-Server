import { Router } from "express";
import crypto from "crypto";
import { db } from "../db/index.js";
import { hashPassword, verifyPassword } from "../crypto.js";
import { getActor, PERMISSIONS, writeAudit } from "../authz.js";
import { requireSession } from "../middleware/requireSession.js";

const router = Router();
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h

function createSession(userId, deviceType, deviceFingerprint) {
  const id = crypto.randomUUID();
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_TTL_MS);
  db.prepare(
    "INSERT INTO sessions (id, user_id, device_type, device_fingerprint, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
  ).run(id, userId, deviceType, deviceFingerprint || null, now.toISOString(), expires.toISOString());
  return { id, expiresAt: expires.toISOString() };
}

function effectivePermissionsOf(actor) {
  return Object.keys(PERMISSIONS).filter(p => actor.effective.has(p));
}

// Owner bootstrap: only callable while the users table is empty. Creates the
// Owner role (rank 0, every permission) + first user. UI-side, this flow
// must show the "no password recovery" warning - that's a frontend concern,
// not this route's, but flagging it here since it's a client-mandated
// requirement from the architecture doc.
// Pre-login check so the desktop UI can hide the "first-run bootstrap"
// checkbox once the server already has users (POST /bootstrap 409s past
// that point, but the UI has no way to know that proactively otherwise).
router.get("/needs-bootstrap", (req, res) => {
  const userCount = db.prepare("SELECT COUNT(*) as c FROM users").get().c;
  res.json({ needsBootstrap: userCount === 0 });
});

router.post("/bootstrap", (req, res) => {
  const userCount = db.prepare("SELECT COUNT(*) as c FROM users").get().c;
  if (userCount > 0) return res.status(409).json({ error: "already bootstrapped" });

  const { username, password, deviceFingerprint } = req.body;
  if (!username || !password) return res.status(400).json({ error: "username and password required" });

  const roleId = crypto.randomUUID();
  db.prepare("INSERT INTO roles (id, name, rank, role_version) VALUES (?, ?, 0, 1)").run(roleId, "Owner");
  const insertGrant = db.prepare("INSERT INTO role_grants (role_id, permission_id, scopes_json) VALUES (?, ?, ?)");
  for (const permissionId of Object.keys(PERMISSIONS)) {
    insertGrant.run(roleId, permissionId, JSON.stringify(["*"]));
  }

  const { salt, hash } = hashPassword(password);
  const userId = crypto.randomUUID();
  db.prepare(
    "INSERT INTO users (id, username, password_salt, password_hash, status, created_by, created_at) VALUES (?, ?, ?, ?, 'active', 'bootstrap', ?)"
  ).run(userId, username, salt, hash, new Date().toISOString());
  db.prepare("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)").run(userId, roleId);

  const actor = getActor(userId);
  const session = createSession(userId, "desktop", deviceFingerprint);
  writeAudit(userId, "auth.bootstrap", { username });
  res.json({ user: { id: userId, username }, session, effectivePermissions: effectivePermissionsOf(actor) });
});

router.post("/login", (req, res) => {
  const { username, password, deviceFingerprint } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user || user.status !== "active" || !verifyPassword(password, user.password_salt, user.password_hash)) {
    // unknown-username attempts have no actor - actor_user_id is null so no
    // failed login goes unrecorded.
    writeAudit(user?.id ?? null, "auth.login.failed", { username });
    return res.status(401).json({ error: "invalid username or password" });
  }

  // one active desktop session per user - a new desktop login supersedes the
  // old one; mobile sessions for the same user are untouched (filtered by device_type).
  const existing = db.prepare("SELECT id FROM sessions WHERE user_id = ? AND device_type = 'desktop'").all(user.id);
  for (const s of existing) db.prepare("DELETE FROM sessions WHERE id = ?").run(s.id);

  const session = createSession(user.id, "desktop", deviceFingerprint);
  const actor = getActor(user.id);
  writeAudit(user.id, "auth.login", { username });
  res.json({
    user: { id: user.id, username: user.username },
    session,
    effectivePermissions: effectivePermissionsOf(actor),
    mustChangePassword: !!user.must_change_password,
  });
});

router.post("/logout", requireSession, (req, res) => {
  db.prepare("DELETE FROM sessions WHERE id = ?").run(req.session.id);
  writeAudit(req.actor.id, "auth.logout", { sessionId: req.session.id });
  res.json({ ok: true });
});

// Self-service password change - the only path that clears
// must_change_password (an admin reset/create sets it, see users.js).
router.post("/change-password", requireSession, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: "currentPassword and newPassword required" });

  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.actor.id);
  if (!verifyPassword(currentPassword, user.password_salt, user.password_hash)) {
    return res.status(401).json({ error: "current password is incorrect" });
  }

  const { salt, hash } = hashPassword(newPassword);
  db.prepare("UPDATE users SET password_salt = ?, password_hash = ?, must_change_password = 0 WHERE id = ?").run(salt, hash, req.actor.id);
  writeAudit(req.actor.id, "auth.change_password", {});
  res.json({ ok: true });
});

router.get("/session", requireSession, (req, res) => {
  const user = db.prepare("SELECT id, username FROM users WHERE id = ?").get(req.actor.id);
  res.json({
    user,
    session: { id: req.session.id, expiresAt: req.session.expires_at },
    effectivePermissions: effectivePermissionsOf(req.actor),
  });
});

export default router;
