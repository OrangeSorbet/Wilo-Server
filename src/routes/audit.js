import { Router } from "express";
import crypto from "crypto";
import { db } from "../db/index.js";
import { requireSession } from "../middleware/requireSession.js";
import { canAndLog } from "../authz.js";

const router = Router();
router.use(requireSession);

function sha256(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

// Reproduces the exact body writeAudit() (authz.js) hashed at insert time.
// target_json is JSON.stringify(target ?? null), so a stored "null" is
// ambiguous between an explicit null and an omitted (undefined) target - but
// since JSON.stringify drops object keys whose value is undefined, and every
// current writeAudit call either passes an object or omits the argument
// entirely (never passes null explicitly), a parsed-null target here always
// means the key was omitted from the original hashed body. Match that by
// leaving the key out rather than including it as null.
function recomputeHash(row) {
  const target = row.target_json ? JSON.parse(row.target_json) : null;
  const body = { actorUserId: row.actor_user_id, permissionId: row.permission_id };
  if (target !== null) body.target = target;
  body.created_at = row.created_at;
  body.prevHash = row.prev_hash;
  return sha256(JSON.stringify(body));
}

router.get("/", (req, res) => {
  const check = canAndLog(req.actor, "audit.read", {});
  if (!check.allowed) return res.status(403).json({ error: check.reason });

  const { actorUserId, permissionId, from, to } = req.query;
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
  const offset = parseInt(req.query.offset, 10) || 0;

  const where = [];
  const params = [];
  if (actorUserId) { where.push("a.actor_user_id = ?"); params.push(actorUserId); }
  if (permissionId) { where.push("a.permission_id = ?"); params.push(permissionId); }
  if (from) { where.push("a.created_at >= ?"); params.push(from); }
  if (to) { where.push("a.created_at <= ?"); params.push(to); }
  const whereClause = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const rows = db.prepare(
    `SELECT a.id, a.actor_user_id, u.username as actor_username, a.permission_id, a.target_json, a.created_at
     FROM audit_log a LEFT JOIN users u ON u.id = a.actor_user_id
     ${whereClause}
     ORDER BY a.id DESC LIMIT ? OFFSET ?`
  ).all(...params, limit, offset);
  const total = db.prepare(`SELECT COUNT(*) as c FROM audit_log a ${whereClause}`).get(...params).c;

  res.json({
    total,
    limit,
    offset,
    entries: rows.map(r => ({
      id: r.id,
      actorUserId: r.actor_user_id,
      actorUsername: r.actor_username ?? null,
      permissionId: r.permission_id,
      target: r.target_json ? JSON.parse(r.target_json) : null,
      createdAt: r.created_at,
    })),
  });
});

router.get("/summary", (req, res) => {
  const check = canAndLog(req.actor, "audit.read", {});
  if (!check.allowed) return res.status(403).json({ error: check.reason });

  const days = Math.min(parseInt(req.query.days, 10) || 30, 365);
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

  const perDay = db.prepare(
    `SELECT substr(created_at, 1, 10) as day, COUNT(*) as count
     FROM audit_log WHERE created_at >= ? GROUP BY day ORDER BY day ASC`
  ).all(since);

  const topUsers = db.prepare(
    `SELECT a.actor_user_id as userId, u.username, COUNT(*) as count
     FROM audit_log a LEFT JOIN users u ON u.id = a.actor_user_id
     WHERE a.created_at >= ? AND a.actor_user_id IS NOT NULL
     GROUP BY a.actor_user_id ORDER BY count DESC LIMIT 10`
  ).all(since);

  res.json({ perDay, topUsers });
});

router.get("/verify", (req, res) => {
  const check = canAndLog(req.actor, "audit.read", {});
  if (!check.allowed) return res.status(403).json({ error: check.reason });

  const rows = db.prepare("SELECT * FROM audit_log ORDER BY id ASC").all();
  let prevHash = "0".repeat(64);
  let firstBadRow = null;
  for (const row of rows) {
    const recomputed = recomputeHash(row);
    if (row.prev_hash !== prevHash || recomputed !== row.hash) {
      firstBadRow = { id: row.id, expectedPrevHash: prevHash, storedPrevHash: row.prev_hash, storedHash: row.hash, recomputedHash: recomputed };
      break;
    }
    prevHash = row.hash;
  }

  res.json({ valid: !firstBadRow, checked: rows.length, firstBadRow });
});

export default router;
