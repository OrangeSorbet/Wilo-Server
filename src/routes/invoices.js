import { Router } from "express";
import crypto from "crypto";
import multer from "multer";
import os from "os";
import path from "path";
import fs from "fs";
import { db } from "../db/index.js";
import { requireSession } from "../middleware/requireSession.js";
import { can, canAndLog, writeAudit } from "../authz.js";
import { effectiveFieldGroups } from "../permissions.js";
import { filterInvoiceFields, mergeAllowedFieldUpdates } from "../fieldGroups.js";
import { broadcast } from "../ws.js";
import { runEngine, splitPdfToImages, cleanupPages, runExportEngine } from "../engine.js";

const router = Router();
router.use(requireSession);

const upload = multer({ dest: path.join(os.tmpdir(), "wilo-server-uploads") });

function insertInvoiceFromEngineResult(result, thumbnail) {
  const aiData = result.invoices?.[0] || {};
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const maxOrder = db.prepare("SELECT MAX(order_index) as m FROM invoices").get().m ?? -1;

  db.prepare(
    `INSERT INTO invoices (id, provider_json, receiver_json, invoice_json, totals_json, status, thumbnail, order_index, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, 'SCANNED_UNREVIEWED', ?, ?, ?, ?)`
  ).run(
    id,
    JSON.stringify(aiData.provider ?? {}),
    JSON.stringify(aiData.receiver ?? {}),
    JSON.stringify(aiData.invoice ?? {}),
    JSON.stringify(aiData.totals ?? {}),
    thumbnail ?? null,
    maxOrder + 1,
    now,
    now
  );

  for (const p of aiData.products ?? []) insertProduct(id, p);

  return rowToInvoice(db.prepare("SELECT * FROM invoices WHERE id = ?").get(id));
}

const PRODUCT_FIELDS = [
  "item_no", "item_code", "description", "hsn_sac", "qty", "rate",
  "total_base_value", "cgst_rate", "cgst_value", "sgst_rate", "sgst_value",
  "total_gst", "total_amount",
];

const insertProductStmt = db.prepare(
  `INSERT INTO products (id, invoice_id, ${PRODUCT_FIELDS.join(", ")})
   VALUES (?, ?, ${PRODUCT_FIELDS.map(() => "?").join(", ")})`
);

function insertProduct(invoiceId, p) {
  insertProductStmt.run(crypto.randomUUID(), invoiceId, ...PRODUCT_FIELDS.map(f => p[f] ?? null));
}

function rowToInvoice(row) {
  const products = db.prepare(
    `SELECT ${PRODUCT_FIELDS.join(", ")} FROM products WHERE invoice_id = ?`
  ).all(row.id);
  return {
    id: row.id,
    provider: row.provider_json ? JSON.parse(row.provider_json) : {},
    receiver: row.receiver_json ? JSON.parse(row.receiver_json) : {},
    invoice: row.invoice_json ? JSON.parse(row.invoice_json) : {},
    totals: row.totals_json ? JSON.parse(row.totals_json) : {},
    products,
    status: row.status,
    thumbnail: row.thumbnail,
    _order: row.order_index,
    updated_at: row.updated_at,
  };
}

router.get("/", (req, res) => {
  const check = canAndLog(req.actor, "invoice.read", { group: "*" });
  if (!check.allowed) return res.status(403).json({ error: check.reason });

  const allowedFieldGroups = effectiveFieldGroups(req.actor, "invoice.read");
  const { updated_since } = req.query;
  const rows = updated_since
    ? db.prepare("SELECT * FROM invoices WHERE deleted_at IS NULL AND updated_at > ? ORDER BY order_index").all(updated_since)
    : db.prepare("SELECT * FROM invoices WHERE deleted_at IS NULL ORDER BY order_index").all();
  res.json({ invoices: rows.map(row => filterInvoiceFields(rowToInvoice(row), allowedFieldGroups)) });
});

router.get("/:id/thumb", (req, res) => {
  const row = db.prepare("SELECT thumbnail FROM invoices WHERE id = ?").get(req.params.id);
  if (!row?.thumbnail) return res.status(404).json({ error: "not found" });
  res.json({ thumbnail: row.thumbnail });
});

router.post("/", (req, res) => {
  const check = canAndLog(req.actor, "invoice.create", {});
  if (!check.allowed) return res.status(403).json({ error: check.reason });

  const { provider, receiver, invoice, totals, products = [], thumbnail } = req.body;
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const maxOrder = db.prepare("SELECT MAX(order_index) as m FROM invoices").get().m ?? -1;

  db.prepare(
    `INSERT INTO invoices (id, provider_json, receiver_json, invoice_json, totals_json, status, thumbnail, order_index, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, 'SCANNED_UNREVIEWED', ?, ?, ?, ?)`
  ).run(
    id,
    JSON.stringify(provider ?? {}),
    JSON.stringify(receiver ?? {}),
    JSON.stringify(invoice ?? {}),
    JSON.stringify(totals ?? {}),
    thumbnail ?? null,
    maxOrder + 1,
    now,
    now
  );

  for (const p of products) insertProduct(id, p);

  const result = rowToInvoice(db.prepare("SELECT * FROM invoices WHERE id = ?").get(id));
  broadcast("invoice-added", result);
  res.json(result);
});

router.put("/:id", (req, res) => {
  const row = db.prepare("SELECT * FROM invoices WHERE id = ?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "invoice not found" });

  const { group, currentStatus, action } = req.body;
  let permissionId = "invoice.update";
  let context = { group: group || "*" };
  if (action === "confirm") { permissionId = "invoice.confirm"; context = { currentStatus: currentStatus ?? row.status }; }
  if (action === "reject") { permissionId = "invoice.reject"; context = { currentStatus: currentStatus ?? row.status }; }

  const check = canAndLog(req.actor, permissionId, context, { id: row.id });
  if (!check.allowed) return res.status(403).json({ error: check.reason });

  const { provider, receiver, invoice, totals, products, thumbnail, status, order_index } = req.body;
  const allowedFieldGroups = effectiveFieldGroups(req.actor, "invoice.update");
  const existingInvoice = rowToInvoice(row);
  const merged = mergeAllowedFieldUpdates(existingInvoice, { provider, receiver, invoice, totals, products }, allowedFieldGroups);
  const now = new Date().toISOString();
  db.prepare(
    `UPDATE invoices SET
       provider_json = ?,
       receiver_json = ?,
       invoice_json = ?,
       totals_json = ?,
       thumbnail = COALESCE(?, thumbnail),
       status = COALESCE(?, status),
       order_index = COALESCE(?, order_index),
       updated_at = ?
     WHERE id = ?`
  ).run(
    JSON.stringify(merged.provider),
    JSON.stringify(merged.receiver),
    JSON.stringify(merged.invoice),
    JSON.stringify(merged.totals),
    thumbnail ?? null,
    status ?? null,
    order_index ?? null,
    now,
    row.id
  );

  if (products && merged.products !== existingInvoice.products) {
    db.prepare("DELETE FROM products WHERE invoice_id = ?").run(row.id);
    for (const p of merged.products) insertProduct(row.id, p);
  }

  const updated = rowToInvoice(db.prepare("SELECT * FROM invoices WHERE id = ?").get(row.id));
  broadcast("invoice-updated", { id: row.id, extracted: updated });
  res.json(updated);
});

router.delete("/:id", (req, res) => {
  const row = db.prepare("SELECT * FROM invoices WHERE id = ?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "invoice not found" });
  const check = canAndLog(req.actor, "invoice.delete", {}, { id: row.id });
  if (!check.allowed) return res.status(403).json({ error: check.reason });

  // tombstone only - write path physically never removes a row, permission or not
  db.prepare("UPDATE invoices SET deleted_at = ? WHERE id = ?").run(new Date().toISOString(), row.id);
  broadcast("invoice-deleted", { id: row.id });
  res.json({ ok: true });
});

// GPU/Ollama live on this server machine, so OCR runs here for uploads from
// either client (desktop or mobile) - mirrors electron/main.js's old
// upload-invoice handler, just server-side now.
router.post("/upload-invoice", upload.single("invoice"), async (req, res) => {
  const check = can(req.actor, "invoice.create", {});
  if (!check.allowed) return res.status(403).json({ error: check.reason });
  if (!req.file) return res.status(400).json({ error: "no file uploaded" });

  const filePath = req.file.path;
  const isPdf = req.file.mimetype === "application/pdf" || filePath.endsWith(".pdf");
  let pageFiles = isPdf ? await splitPdfToImages(filePath) : [{ path: filePath, mimetype: req.file.mimetype }];

  try {
    const created = [];
    for (const page of pageFiles) {
      const fileBuffer = fs.readFileSync(page.path);
      const thumbnail = `data:${page.mimetype};base64,${fileBuffer.toString("base64")}`;
      const result = await runEngine(page.path);
      // engine.py swallows its own failures (Ollama down, bad image, model
      // error) and still exits 0 with invoices: [] - without this check that
      // silently inserts a blank invoice row and reports success.
      if (!result.invoices?.length) {
        throw new Error(result.error || "OCR failed - check that Ollama is running and the model is pulled");
      }
      const invoice = insertInvoiceFromEngineResult(result, thumbnail);
      writeAudit(req.actor.id, "invoice.create", { id: invoice.id });
      broadcast("invoice-added", invoice);
      created.push(invoice);
    }
    res.json({ success: true, invoices: created });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    if (isPdf) cleanupPages(pageFiles);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  }
});

function safeFilenamePart(s) {
  return (s || "unknown").replace(/[^a-zA-Z0-9_-]/g, "_");
}

const EXPORT_CONTENT_TYPES = {
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  csv: "text/csv",
  json: "application/json",
};

// Server-side, field-scoped, audited export. invoice.export reuses
// invoice.read's field grants (confirmed design decision, not a new grant
// surface). All three formats (xlsx/csv/json) go through exportengine.py so
// they agree on the same flatten_invoice/flatten_products field set instead
// of Node hand-duplicating a separate (incomplete) flattening for csv.
// Normally only rows SET to QA_APPROVED_QA are exportable (others silently
// excluded, counted in X-Excluded-Count) - actors holding "admin" export
// every non-deleted row regardless of status, no exclusions.
router.post("/export", async (req, res) => {
  const { invoiceIds, format } = req.body;
  if (!["xlsx", "csv", "json"].includes(format)) {
    return res.status(400).json({ error: "format must be xlsx, csv, or json" });
  }

  const check = canAndLog(req.actor, "invoice.export", { currentStatus: "QA_APPROVED_QA" }, { invoiceIds: invoiceIds ?? "all", format });
  if (!check.allowed) return res.status(403).json({ error: check.reason });

  const rows = invoiceIds?.length
    ? invoiceIds.map(id => db.prepare("SELECT * FROM invoices WHERE id = ? AND deleted_at IS NULL").get(id)).filter(Boolean)
    : db.prepare("SELECT * FROM invoices WHERE deleted_at IS NULL").all();

  const candidates = rows.map(rowToInvoice);
  const isAdmin = req.actor.effective.has("admin");
  const eligible = isAdmin ? candidates : candidates.filter(inv => inv.status === "QA_APPROVED_QA");
  const excludedCount = candidates.length - eligible.length;

  const allowedFieldGroups = effectiveFieldGroups(req.actor, "invoice.read");
  const filtered = eligible.map(inv => filterInvoiceFields(inv, allowedFieldGroups));

  const user = db.prepare("SELECT username FROM users WHERE id = ?").get(req.actor.id);
  const role = db.prepare(
    "SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ? ORDER BY r.rank ASC LIMIT 1"
  ).get(req.actor.id);
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = `Wilo_Export_${safeFilenamePart(user?.username)}_${safeFilenamePart(role?.name)}_${timestamp}.${format}`;

  const tempPayloadPath = path.join(os.tmpdir(), `wilo-export-payload-${crypto.randomUUID()}.json`);
  const tempOutputPath = path.join(os.tmpdir(), `wilo-export-output-${crypto.randomUUID()}.${format}`);
  try {
    fs.writeFileSync(tempPayloadPath, JSON.stringify({ invoices: filtered }));
    const result = await runExportEngine(tempPayloadPath, tempOutputPath);
    if (result.error) throw new Error(result.error);

    const buffer = fs.readFileSync(tempOutputPath);
    res.setHeader("X-Excluded-Count", String(excludedCount));
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.setHeader("Content-Type", EXPORT_CONTENT_TYPES[format]);
    res.send(buffer);
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    if (fs.existsSync(tempPayloadPath)) fs.unlinkSync(tempPayloadPath);
    if (fs.existsSync(tempOutputPath)) fs.unlinkSync(tempOutputPath);
  }
});

export default router;
