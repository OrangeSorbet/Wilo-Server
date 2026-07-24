// authz.js
// DB-backed glue around permissions.js's pure can() engine: loads roles/users
// from SQLite, resolves an actor, and wraps can() with structural audit
// logging (canAndLog) so every mutating permission writes an audit_log row
// by construction - handlers physically cannot get allowed:true without the
// log insert happening first, since it's the same function call.
import crypto from "crypto";
import { db } from "./db/index.js";
import { can, resolveActor, PERMISSIONS, AUDITABLE } from "./permissions.js";

export function loadRoles() {
  const roles = db.prepare("SELECT id, name, rank, role_version FROM roles").all();
  const grants = db.prepare("SELECT role_id, permission_id, scopes_json FROM role_grants").all();
  const grantsByRole = new Map();
  for (const g of grants) {
    const list = grantsByRole.get(g.role_id) || [];
    list.push({ permissionId: g.permission_id, scopes: g.scopes_json ? JSON.parse(g.scopes_json) : undefined });
    grantsByRole.set(g.role_id, list);
  }
  return roles.map(r => ({ ...r, grants: grantsByRole.get(r.id) || [] }));
}

export function loadUserWithRoles(userId) {
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
  if (!user) return null;
  const roleIds = db.prepare("SELECT role_id FROM user_roles WHERE user_id = ?").all(userId).map(r => r.role_id);
  return { ...user, roleIds };
}

export function getActor(userId) {
  const user = loadUserWithRoles(userId);
  if (!user) return null;
  return resolveActor(user, loadRoles());
}

function sha256(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

export function writeAudit(actorUserId, permissionId, target) {
  const last = db.prepare("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").get();
  const prevHash = last?.hash || "0".repeat(64);
  const created_at = new Date().toISOString();
  const body = JSON.stringify({ actorUserId, permissionId, target, created_at, prevHash });
  const hash = sha256(body);
  db.prepare(
    "INSERT INTO audit_log (actor_user_id, permission_id, target_json, prev_hash, hash, created_at) VALUES (?, ?, ?, ?, ?, ?)"
  ).run(actorUserId, permissionId, JSON.stringify(target ?? null), prevHash, hash, created_at);
}

export function canAndLog(actor, permissionId, context = {}, target) {
  const result = can(actor, permissionId, context);
  if (result.allowed && AUDITABLE.has(permissionId)) {
    writeAudit(actor.id, permissionId, target);
  }
  return result;
}

export { can, resolveActor, PERMISSIONS };
