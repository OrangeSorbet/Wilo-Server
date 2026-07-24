// Mobile pairing: desktop (already logged in) issues a single-use, short-TTL
// token; phone consumes it to get a "derived" session without ever seeing a
// password. Tokens are ephemeral - in-memory only, never persisted.
import { Router } from "express";
import crypto from "crypto";
import { db } from "../db/index.js";
import { requireSession } from "../middleware/requireSession.js";
import { writeAudit } from "../authz.js";

const router = Router();
const TOKEN_TTL_MS = 2 * 60 * 1000;
const pendingTokens = new Map(); // token -> { userId, expiresAt, consumed }

router.post("/issue", requireSession, (req, res) => {
  if (req.session.device_type !== "desktop") {
    return res.status(403).json({ error: "only a desktop session can issue pairing tokens" });
  }
  const token = crypto.randomUUID();
  pendingTokens.set(token, { userId: req.actor.id, expiresAt: Date.now() + TOKEN_TTL_MS, consumed: false });
  writeAudit(req.actor.id, "auth.pairing.issue", {});
  res.json({ token, expiresIn: TOKEN_TTL_MS });
});

router.post("/consume", (req, res) => {
  const { token, deviceFingerprint } = req.body;
  const entry = pendingTokens.get(token);
  if (!entry || entry.consumed || entry.expiresAt < Date.now()) {
    writeAudit(entry?.userId ?? null, "auth.pairing.consume", { failed: true });
    return res.status(400).json({ error: "invalid or expired pairing token" });
  }
  entry.consumed = true;

  const sessionId = crypto.randomUUID();
  const now = new Date();
  const expires = new Date(now.getTime() + 12 * 60 * 60 * 1000);
  db.prepare(
    "INSERT INTO sessions (id, user_id, device_type, device_fingerprint, created_at, expires_at) VALUES (?, ?, 'mobile', ?, ?, ?)"
  ).run(sessionId, entry.userId, deviceFingerprint || null, now.toISOString(), expires.toISOString());

  const user = db.prepare("SELECT id, username FROM users WHERE id = ?").get(entry.userId);
  writeAudit(entry.userId, "auth.pairing.consume", { sessionId });
  res.json({ user, session: { id: sessionId, expiresAt: expires.toISOString() } });
});

export default router;
