import { Router } from "express";
import crypto from "crypto";
import { db } from "../db/index.js";
import { requireSession } from "../middleware/requireSession.js";
import { canAndLog, loadRoles } from "../authz.js";
import { hashPassword } from "../crypto.js";

const router = Router();
router.use(requireSession);

function targetRankOf(userId) {
  const roles = loadRoles();
  const roleIds = db.prepare("SELECT role_id FROM user_roles WHERE user_id = ?").all(userId).map(r => r.role_id);
  const held = roles.filter(r => roleIds.includes(r.id));
  return held.length ? Math.min(...held.map(r => r.rank)) : Infinity;
}

router.get("/", (req, res) => {
  const check = canAndLog(req.actor, "user.read", {});
  if (!check.allowed) return res.status(403).json({ error: check.reason });
  const users = db.prepare("SELECT id, username, status, created_by, created_at FROM users").all();
  const withRoles = users.map(u => ({
    ...u,
    roleIds: db.prepare("SELECT role_id FROM user_roles WHERE user_id = ?").all(u.id).map(r => r.role_id),
  }));
  res.json({ users: withRoles });
});

router.post("/", (req, res) => {
  const { username, password, roleIds = [] } = req.body;
  const roles = loadRoles();
  const held = roles.filter(r => roleIds.includes(r.id));
  const targetRank = held.length ? Math.min(...held.map(r => r.rank)) : Infinity;
  const check = canAndLog(req.actor, "user.create", { targetRank }, { username, roleIds });
  if (!check.allowed) return res.status(403).json({ error: check.reason });

  const { salt, hash } = hashPassword(password);
  const id = crypto.randomUUID();
  db.prepare(
    "INSERT INTO users (id, username, password_salt, password_hash, status, created_by, created_at, must_change_password) VALUES (?, ?, ?, ?, 'active', ?, ?, 1)"
  ).run(id, username, salt, hash, req.actor.id, new Date().toISOString());
  const insertRole = db.prepare("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)");
  for (const roleId of roleIds) insertRole.run(id, roleId);
  res.json({ id });
});

router.put("/:id", (req, res) => {
  const targetRank = targetRankOf(req.params.id);
  const check = canAndLog(req.actor, "user.update", { targetRank }, { id: req.params.id });
  if (!check.allowed) return res.status(403).json({ error: check.reason });

  const { status, roleIds, password } = req.body;
  if (status) db.prepare("UPDATE users SET status = ? WHERE id = ?").run(status, req.params.id);
  if (password) {
    // admin-initiated reset, not the user's own voluntary change - forces a
    // change on next login (see POST /auth/change-password, which clears this).
    const { salt, hash } = hashPassword(password);
    db.prepare("UPDATE users SET password_salt = ?, password_hash = ?, must_change_password = 1 WHERE id = ?").run(salt, hash, req.params.id);
  }
  if (roleIds) {
    db.prepare("DELETE FROM user_roles WHERE user_id = ?").run(req.params.id);
    const insertRole = db.prepare("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)");
    for (const roleId of roleIds) insertRole.run(req.params.id, roleId);
  }
  res.json({ ok: true });
});

router.delete("/:id", (req, res) => {
  const targetRank = targetRankOf(req.params.id);
  const check = canAndLog(req.actor, "user.delete", { targetRank }, { id: req.params.id });
  if (!check.allowed) return res.status(403).json({ error: check.reason });
  // soft-disable only, per architecture doc - login history is never removed
  db.prepare("UPDATE users SET status = 'disabled' WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

export default router;
