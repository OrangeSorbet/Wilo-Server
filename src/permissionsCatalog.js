// permissionsCatalog.js
// Human-readable label/description/category for every id in permissions.js's
// PERMISSIONS registry, served over GET /roles/permissions-catalog so an
// admin UI can render role-grant checkboxes without a static frontend copy
// that could drift out of sync with the registry it describes.
import { PERMISSIONS } from "./permissions.js";

export const PERMISSION_CATALOG = {
  "admin": { label: "Administrator", description: "Grants every permission unconditionally, bypassing all other checks — equivalent to holding every permission at once. Use sparingly.", category: "Admin" },

  "invoice.create": { label: "Create invoices", description: "Add a new invoice (manually or via OCR upload).", category: "Invoices" },
  "invoice.read": { label: "Read invoices", description: "View invoices, scoped to granted field groups.", category: "Invoices" },
  "invoice.update": { label: "Update invoices", description: "Edit invoice fields, scoped to granted field groups.", category: "Invoices" },
  "invoice.delete": { label: "Delete invoices", description: "Tombstone (soft-delete) an invoice.", category: "Invoices" },
  "invoice.restore": { label: "Restore invoices", description: "Undo a soft-delete on an invoice.", category: "Invoices" },
  "invoice.confirm": { label: "Confirm invoices", description: "Advance an invoice through review tiers (watchman/QA).", category: "Invoices" },
  "invoice.reject": { label: "Reject invoices", description: "Send an invoice back for re-review.", category: "Invoices" },
  "invoice.export": { label: "Export invoices", description: "Export approved invoices to Excel/CSV.", category: "Invoices" },

  "role.create": { label: "Create roles", description: "Create a new permission role.", category: "Roles" },
  "role.read": { label: "Read roles", description: "View roles and their grants.", category: "Roles" },
  "role.update": { label: "Update roles", description: "Edit a role's name, rank, or grants.", category: "Roles" },
  "role.delete": { label: "Delete roles", description: "Delete a role, reassigning any holders to a fallback role.", category: "Roles" },
  "role.assign": { label: "Assign roles", description: "Assign a role to a user.", category: "Roles" },
  "role.reorder": { label: "Reorder roles", description: "Change a role's rank via drag-reorder.", category: "Roles" },

  "user.create": { label: "Create users", description: "Create a new user account.", category: "Users" },
  "user.read": { label: "Read users", description: "View user accounts and their assigned roles.", category: "Users" },
  "user.update": { label: "Update users", description: "Edit a user's status, roles, or password.", category: "Users" },
  "user.delete": { label: "Delete users", description: "Disable a user account.", category: "Users" },

  "session.read": { label: "Read sessions", description: "View active login sessions.", category: "Sessions" },
  "session.delete": { label: "Revoke sessions", description: "Revoke another user's (or your own) active session.", category: "Sessions" },

  "host.read": { label: "Read host settings", description: "View server host configuration.", category: "Host" },
  "host.update": { label: "Update host settings", description: "Change server host configuration.", category: "Host" },
  "backup.read": { label: "Read backup settings", description: "View backup configuration.", category: "Backup" },
  "backup.update": { label: "Update backup settings", description: "Change backup configuration.", category: "Backup" },
  "config.read": { label: "Read config", description: "View machine-level configuration.", category: "Config" },
  "config.update": { label: "Update config", description: "Change machine-level configuration (machine-bound).", category: "Config" },

  "audit.read": { label: "Read audit log", description: "View and verify the tamper-evident audit log.", category: "Audit" },

  "network.read": { label: "Read network settings", description: "View network configuration.", category: "Network" },
  "network.update": { label: "Update network settings", description: "Change network configuration.", category: "Network" },

  "security.read": { label: "Read security settings", description: "View security configuration.", category: "Security" },
  "security.update": { label: "Update security settings", description: "Change security configuration.", category: "Security" },

  "system.read": { label: "Read system status", description: "View general system status.", category: "System" },

  "auth.bootstrap": { label: "First-run bootstrap", description: "Pre-auth: initial admin account creation on first run.", category: "Auth" },
  "auth.login": { label: "Login", description: "Pre-auth: successful login.", category: "Auth" },
  "auth.login.failed": { label: "Failed login", description: "Pre-auth: failed login attempt.", category: "Auth" },
  "auth.logout": { label: "Logout", description: "Session logout.", category: "Auth" },
  "auth.pairing.issue": { label: "Issue pairing token", description: "Pre-auth: issue a mobile pairing QR token.", category: "Auth" },
  "auth.pairing.consume": { label: "Consume pairing token", description: "Pre-auth: mobile consumes a pairing token to log in.", category: "Auth" },
  "auth.change_password": { label: "Change own password", description: "User changes their own password, clearing any forced-change flag.", category: "Auth" },
};

// Fails loudly (rather than silently under-documenting) if permissions.js
// gains an id this catalog hasn't been updated to describe.
for (const id of Object.keys(PERMISSIONS)) {
  if (!PERMISSION_CATALOG[id]) throw new Error(`permissionsCatalog.js: missing catalog entry for permission id "${id}"`);
}
