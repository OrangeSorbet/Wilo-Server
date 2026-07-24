import { Router } from "express";
import crypto from "crypto";
import { db } from "../db/index.js";
import { requireSession } from "../middleware/requireSession.js";
import { canAndLog, loadRoles } from "../authz.js";
import { PERMISSION_CATALOG } from "../permissionsCatalog.js";
import { FIELD_GROUPS } from "../fieldGroups.js";

const router = Router();
router.use(requireSession);

// Labels aren't sensitive - requireSession only, no permission check, so any
// logged-in client (including the admin UI's role-editor screen) can render
// grant checkboxes without first holding role.read.
router.get("/permissions-catalog", (req, res) => {
  res.json({
    permissions: Object.entries(PERMISSION_CATALOG).map(([id, def]) => ({ id, ...def })),
    fieldGroups: Object.entries(FIELD_GROUPS).map(([id, def]) => ({ id, ...def })),
  });
});

router.get("/", (req, res) => {
  const check = canAndLog(req.actor, "role.read", {});
  if (!check.allowed) return res.status(403).json({ error: check.reason });
  res.json({ roles: loadRoles() });
});

router.post("/", (req, res) => {
  const { name, grants = [] } = req.body;
  // rank is authoritative server-side (not client-supplied) to close the race where
  // two concurrent creates both compute the same client-side "next rank".
  const rank = db.prepare("SELECT COALESCE(MAX(rank), -1) + 1 as nextRank FROM roles").get().nextRank;
  const check = canAndLog(req.actor, "role.create", { targetRank: rank }, { name, rank });
  if (!check.allowed) return res.status(403).json({ error: check.reason });

  const id = crypto.randomUUID();
  db.prepare("INSERT INTO roles (id, name, rank, role_version) VALUES (?, ?, ?, 1)").run(id, name, rank);
  const insertGrant = db.prepare("INSERT INTO role_grants (role_id, permission_id, scopes_json) VALUES (?, ?, ?)");
  for (const g of grants) insertGrant.run(id, g.permissionId, g.scopes ? JSON.stringify(g.scopes) : null);
  res.json({ id });
});

router.put("/:id", (req, res) => {
  const target = db.prepare("SELECT * FROM roles WHERE id = ?").get(req.params.id);
  if (!target) return res.status(404).json({ error: "role not found" });
  const check = canAndLog(req.actor, "role.update", { targetRank: target.rank, targetRoleId: target.id }, { id: target.id });
  if (!check.allowed) return res.status(403).json({ error: check.reason });

  const { name, rank, grants } = req.body;
  db.prepare("UPDATE roles SET name = COALESCE(?, name), rank = COALESCE(?, rank), role_version = role_version + 1 WHERE id = ?")
    .run(name ?? null, rank ?? null, target.id);

  if (grants) {
    db.prepare("DELETE FROM role_grants WHERE role_id = ?").run(target.id);
    const insertGrant = db.prepare("INSERT INTO role_grants (role_id, permission_id, scopes_json) VALUES (?, ?, ?)");
    for (const g of grants) insertGrant.run(target.id, g.permissionId, g.scopes ? JSON.stringify(g.scopes) : null);
  }
  res.json({ ok: true });
});

router.delete("/:id", (req, res) => {
  const target = db.prepare("SELECT * FROM roles WHERE id = ?").get(req.params.id);
  if (!target) return res.status(404).json({ error: "role not found" });
  const check = canAndLog(req.actor, "role.delete", { targetRank: target.rank }, { id: target.id });
  if (!check.allowed) return res.status(403).json({ error: check.reason });

  const holders = db.prepare("SELECT COUNT(*) as c FROM user_roles WHERE role_id = ?").get(target.id).c;
  const { fallbackRoleId } = req.body || {};
  // role.delete is blocked while any user still holds the role, unless a
  // fallback role is supplied for automatic reassignment (per architecture doc).
  if (holders > 0 && !fallbackRoleId) {
    return res.status(400).json({ error: "role still assigned to users, supply fallbackRoleId to reassign" });
  }
  if (holders > 0) {
    db.prepare("UPDATE user_roles SET role_id = ? WHERE role_id = ?").run(fallbackRoleId, target.id);
  }
  db.prepare("DELETE FROM roles WHERE id = ?").run(target.id);
  res.json({ ok: true });
});

// Drag-reorder: rank is derived from list position on the frontend and sent
// here as the new integer rank, never typed in directly by a user.
router.post("/:id/reorder", (req, res) => {
  const { rank } = req.body;
  const target = db.prepare("SELECT * FROM roles WHERE id = ?").get(req.params.id);
  if (!target) return res.status(404).json({ error: "role not found" });
  const check = canAndLog(req.actor, "role.reorder", { targetRank: target.rank, targetRoleId: target.id }, { id: target.id, rank });
  if (!check.allowed) return res.status(403).json({ error: check.reason });

  db.prepare("UPDATE roles SET rank = ?, role_version = role_version + 1 WHERE id = ?").run(rank, target.id);
  res.json({ ok: true });
});

export default router;
