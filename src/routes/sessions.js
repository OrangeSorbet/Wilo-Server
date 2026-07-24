import { Router } from "express";
import { db } from "../db/index.js";
import { requireSession } from "../middleware/requireSession.js";
import { canAndLog, loadRoles } from "../authz.js";

const router = Router();
router.use(requireSession);

router.get("/", (req, res) => {
  const check = canAndLog(req.actor, "session.read", {});
  if (!check.allowed) return res.status(403).json({ error: check.reason });
  res.json({
    sessions: db.prepare(
      "SELECT id, user_id, device_type, device_fingerprint, created_at, expires_at FROM sessions"
    ).all(),
  });
});

router.delete("/:id", (req, res) => {
  const target = db.prepare("SELECT * FROM sessions WHERE id = ?").get(req.params.id);
  if (!target) return res.status(404).json({ error: "session not found" });

  const roles = loadRoles();
  const roleIds = db.prepare("SELECT role_id FROM user_roles WHERE user_id = ?").all(target.user_id).map(r => r.role_id);
  const held = roles.filter(r => roleIds.includes(r.id));
  const targetRank = held.length ? Math.min(...held.map(r => r.rank)) : Infinity;

  // can only revoke sessions of a strictly-lower-rank user, or your own (can() special-cases this)
  const check = canAndLog(req.actor, "session.delete", { targetRank, targetUserId: target.user_id }, { id: target.id });
  if (!check.allowed) return res.status(403).json({ error: check.reason });

  db.prepare("DELETE FROM sessions WHERE id = ?").run(target.id);
  res.json({ ok: true });
});

export default router;
