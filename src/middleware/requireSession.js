import { db } from "../db/index.js";
import { getActor } from "../authz.js";

export function requireSession(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "missing session token" });

  const session = db.prepare("SELECT * FROM sessions WHERE id = ?").get(token);
  if (!session) return res.status(401).json({ error: "invalid session" });
  if (new Date(session.expires_at).getTime() < Date.now()) {
    db.prepare("DELETE FROM sessions WHERE id = ?").run(token);
    return res.status(401).json({ error: "session expired" });
  }

  const actor = getActor(session.user_id);
  if (!actor) return res.status(401).json({ error: "user not found" });

  req.session = session;
  req.actor = actor;
  next();
}
