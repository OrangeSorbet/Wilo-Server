// permissions.js
// Permission registry + one central can() gate. Every enforcement type in the
// architecture doc funnels through can() so rank resolution, scope checks,
// and audit-logging (authz.js's canAndLog) all live in exactly one place
// instead of being duplicated at every route.
//
// Moved from Wilo-Dashboard-Final's electron/permissions.js unchanged - this
// is pure logic over plain objects, no Electron/filesystem dependency, so it
// works identically whether the role/user arrays come from local shard files
// (the old plan) or from SQLite (this server).

export const ENFORCEMENT = {
  SIMPLE: "simple",
  SCOPED: "scoped",
  STATE_GATED: "state-gated",
  RANK_GATED: "rank-gated",
  MACHINE_BOUND: "machine-bound",
};

// Permission id -> enforcement type. Scoped ids are the base id
// ("invoice.read", not "invoice.read.<group>") - the group is data on the
// grant (grant.scopes[]), not a separate literal per group.
export const PERMISSIONS = {
  // Discord-style Administrator bypass: holding this grants every other
  // permission unconditionally (see can()'s short-circuit below). Not itself
  // a mutating action, so it's deliberately excluded from AUDITABLE.
  "admin": ENFORCEMENT.SIMPLE,

  "invoice.create": ENFORCEMENT.SIMPLE,
  "invoice.read": ENFORCEMENT.SCOPED,
  "invoice.update": ENFORCEMENT.SCOPED,
  "invoice.delete": ENFORCEMENT.SIMPLE,
  "invoice.restore": ENFORCEMENT.SIMPLE,
  "invoice.confirm": ENFORCEMENT.STATE_GATED,
  "invoice.reject": ENFORCEMENT.STATE_GATED,
  "invoice.export": ENFORCEMENT.STATE_GATED,

  "role.create": ENFORCEMENT.RANK_GATED,
  "role.read": ENFORCEMENT.SIMPLE,
  "role.update": ENFORCEMENT.RANK_GATED,
  "role.delete": ENFORCEMENT.RANK_GATED,
  "role.assign": ENFORCEMENT.RANK_GATED,
  "role.reorder": ENFORCEMENT.RANK_GATED,

  "user.create": ENFORCEMENT.RANK_GATED,
  "user.read": ENFORCEMENT.SIMPLE,
  "user.update": ENFORCEMENT.RANK_GATED,
  "user.delete": ENFORCEMENT.RANK_GATED,

  "session.read": ENFORCEMENT.SIMPLE,
  "session.delete": ENFORCEMENT.RANK_GATED,

  // out of scope per the original plan's Phase 0 - permission id +
  // enforcement-type registration only, no state machine behind them.
  "host.read": ENFORCEMENT.SIMPLE,
  "host.update": ENFORCEMENT.STATE_GATED,
  "backup.read": ENFORCEMENT.SIMPLE,
  "backup.update": ENFORCEMENT.STATE_GATED,
  "config.read": ENFORCEMENT.SIMPLE,
  "config.update": ENFORCEMENT.MACHINE_BOUND,

  "audit.read": ENFORCEMENT.SIMPLE,

  "network.read": ENFORCEMENT.SIMPLE,
  "network.update": ENFORCEMENT.RANK_GATED,

  "security.read": ENFORCEMENT.SIMPLE,
  "security.update": ENFORCEMENT.RANK_GATED,

  "system.read": ENFORCEMENT.SIMPLE,

  // Pre-auth events - never permission-checked (no actor exists yet), only
  // registered so they can be structurally audit-logged like everything else.
  "auth.bootstrap": ENFORCEMENT.SIMPLE,
  "auth.login": ENFORCEMENT.SIMPLE,
  "auth.login.failed": ENFORCEMENT.SIMPLE,
  "auth.logout": ENFORCEMENT.SIMPLE,
  "auth.pairing.issue": ENFORCEMENT.SIMPLE,
  "auth.pairing.consume": ENFORCEMENT.SIMPLE,
  "auth.change_password": ENFORCEMENT.SIMPLE,
};

// Mutating ids that authz.js's canAndLog() must structurally audit-log.
// Read-only ids (*.read) are excluded.
export const AUDITABLE = new Set([
  "invoice.create", "invoice.update", "invoice.delete", "invoice.restore",
  "invoice.confirm", "invoice.reject", "invoice.export",
  "role.create", "role.update", "role.delete", "role.assign", "role.reorder",
  "user.create", "user.update", "user.delete",
  "session.delete",
  "host.update", "backup.update",
  "config.update", "network.update", "security.update",
  "auth.bootstrap", "auth.login", "auth.login.failed", "auth.logout",
  "auth.pairing.issue", "auth.pairing.consume", "auth.change_password",
]);

// state-gated: which invoice status each permission is legal from. For
// invoice.confirm the value is which tier fired (recorded on the invoice's
// status record by the caller, never encoded as a second permission id).
const STATE_RULES = {
  "invoice.confirm": { SCANNED_UNREVIEWED: "watchman", QA_APPROVED_WATCHMAN: "qa" },
  "invoice.reject": { QA_APPROVED_WATCHMAN: true },
  "invoice.export": { QA_APPROVED_QA: true },
};

// roles: array of { id, rank, grants: [{ permissionId, scopes? }], role_version }
// rank: 0 = highest. Effective set of a role = its own grants unioned with
// every role ranked below it (union-down-the-hierarchy per architecture doc).
export function resolveEffectivePermissions(roleIds, roles) {
  const sorted = [...roles].sort((a, b) => a.rank - b.rank);
  const held = new Set();
  const scopesByPermission = new Map();

  function addGrant(g) {
    held.add(g.permissionId);
    if (PERMISSIONS[g.permissionId] === ENFORCEMENT.SCOPED && g.scopes) {
      const set = scopesByPermission.get(g.permissionId) || new Set();
      g.scopes.forEach(s => set.add(s));
      scopesByPermission.set(g.permissionId, set);
    }
  }

  for (const roleId of roleIds) {
    const idx = sorted.findIndex(r => r.id === roleId);
    if (idx === -1) continue;
    for (let i = idx; i < sorted.length; i++) {
      (sorted[i].grants || []).forEach(addGrant);
    }
  }

  return {
    has: (id) => held.has(id),
    scopesOf: (id) => scopesByPermission.get(id) || new Set(),
  };
}

// Field-group grants share scopesOf(permissionId) with the existing SCOPED
// check, namespaced with a "field:" prefix ("field:provider.basic") so they
// ride along on the same scopes_json array without touching what a bare "*"
// or plain group token means to can()'s SCOPED case. A bare "field:<groupId>"
// token grants the whole group; "field:<groupId>|<path>" (pipe-delimited -
// group ids and paths both already contain dots, so a dot delimiter would be
// ambiguous) grants just that one path within the group.
//
// Returns { all, fullGroups, partialPaths }:
//   all: true if the actor holds a bare "*" scope for this permission (full
//     access, same trigger as today).
//   fullGroups: Set<groupId> of whole groups granted via bare "field:<groupId>".
//   partialPaths: Set<"groupId|path"> of individual paths granted via
//     "field:<groupId>|<path>".
// (already union-down-the-hierarchy, since scopesOf() is built by
// resolveEffectivePermissions() above).
export function effectiveFieldGroups(actor, permissionId) {
  // Admin bypass: mirrors can()'s short-circuit - full unrestricted access to
  // every field group, since scopesOf()/can() aren't consulted for "admin"
  // itself.
  if (actor.effective.has("admin")) return { all: true, fullGroups: new Set(), partialPaths: new Set() };
  const scopes = actor.effective.scopesOf(permissionId);
  if (scopes.has("*")) return { all: true, fullGroups: new Set(), partialPaths: new Set() };

  const fullGroups = new Set();
  const partialPaths = new Set();
  for (const scope of scopes) {
    if (!scope.startsWith("field:")) continue;
    const rest = scope.slice("field:".length);
    const pipeIdx = rest.indexOf("|");
    if (pipeIdx === -1) fullGroups.add(rest);
    else partialPaths.add(rest); // already "groupId|path"
  }
  return { all: false, fullGroups, partialPaths };
}

// Resolves a user's actor context (rank + effective permission set) needed by
// can(). Rank = lowest rank number (highest rank) across their held roles.
export function resolveActor(user, roles) {
  const roleIds = user.roleIds || [];
  const heldRoles = roles.filter(r => roleIds.includes(r.id));
  const rank = heldRoles.length ? Math.min(...heldRoles.map(r => r.rank)) : Infinity;
  return { id: user.id, roleIds, rank, effective: resolveEffectivePermissions(roleIds, roles) };
}

// can(actor, permissionId, context) -> { allowed, reason?, tier? }
// context shape by enforcement type:
//   scoped: { group }
//   state-gated: { currentStatus }
//   rank-gated: { targetRank, targetUserId? } (targetUserId lets session.delete
//     special-case "revoke your own session" before the rank check)
//   machine-bound: { requestOrigin } (stub - see original Phase 0 non-goals)
export function can(actor, permissionId, context = {}) {
  const type = PERMISSIONS[permissionId];
  // Admin bypass: a known permission id is always allowed for an actor
  // holding "admin", skipping the enforcement-type switch entirely. Gated on
  // `type` being defined so an unknown permission id still falls through to
  // the unknown-permission rejection below rather than being bypassed.
  if (type && actor.effective.has("admin")) return { allowed: true };
  if (!type) return { allowed: false, reason: `unknown permission: ${permissionId}` };

  switch (type) {
    case ENFORCEMENT.SIMPLE:
      return actor.effective.has(permissionId)
        ? { allowed: true }
        : { allowed: false, reason: "missing permission" };

    case ENFORCEMENT.SCOPED: {
      if (!actor.effective.has(permissionId)) return { allowed: false, reason: "missing permission" };
      const scopes = actor.effective.scopesOf(permissionId);
      if (scopes.has("*") || (context.group && scopes.has(context.group))) return { allowed: true };
      return { allowed: false, reason: "group not in grant scope" };
    }

    case ENFORCEMENT.STATE_GATED: {
      if (!actor.effective.has(permissionId)) return { allowed: false, reason: "missing permission" };
      const rule = STATE_RULES[permissionId];
      if (!rule) return { allowed: true }; // host.update/backup.update stubs
      const tier = rule[context.currentStatus];
      if (!tier) return { allowed: false, reason: `not legal from status ${context.currentStatus}` };
      return { allowed: true, tier: tier === true ? undefined : tier };
    }

    case ENFORCEMENT.RANK_GATED: {
      if (!actor.effective.has(permissionId)) return { allowed: false, reason: "missing permission" };
      if (permissionId === "session.delete" && context.targetUserId === actor.id) return { allowed: true };
      // Self-target carve-out for role.update/role.reorder ONLY: an actor
      // editing/reordering a role they currently hold would otherwise always
      // fail the strict rank check below (their rank always equals that
      // role's rank, and Owner's own role is rank 0 so 0 < 0 never holds).
      // role.delete/role.create/role.assign/user.* keep the strict check.
      if (
        (permissionId === "role.update" || permissionId === "role.reorder") &&
        context.targetRoleId && actor.roleIds.includes(context.targetRoleId)
      ) return { allowed: true };
      if (context.targetRank === undefined) return { allowed: false, reason: "no target rank in context" };
      if (actor.rank < context.targetRank) return { allowed: true };
      if (context.targetRank === 0) {
        return { allowed: false, reason: "Nothing can be ranked higher than Owner — the Owner role is always rank 0." };
      }
      return { allowed: false, reason: "You can't modify a role ranked equal to or above your own." };
    }

    case ENFORCEMENT.MACHINE_BOUND:
      // stub: everything is "local" until a fingerprint strategy is decided
      return (!context.requestOrigin || context.requestOrigin === "local")
        ? { allowed: true }
        : { allowed: false, reason: "machine fingerprint mismatch (stub)" };

    default:
      return { allowed: false, reason: "unhandled enforcement type" };
  }
}

// ── role_version staleness (the "stale permission cache" gap from the doc) ──
export function snapshotRoleVersions(roleIds, roles) {
  const byId = new Map(roles.map(r => [r.id, r]));
  const snap = {};
  roleIds.forEach(id => { snap[id] = byId.get(id)?.role_version ?? 0; });
  return snap;
}

export function isStale(snapshot, roleIds, roles) {
  const byId = new Map(roles.map(r => [r.id, r]));
  return roleIds.some(id => (byId.get(id)?.role_version ?? 0) !== (snapshot[id] ?? -1));
}
