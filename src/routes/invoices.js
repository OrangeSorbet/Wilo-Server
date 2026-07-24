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

  const insertProduct = db.prepare("INSERT INTO products (id, invoice_id, description, quantity, unit_price) VALUES (?, ?, ?, ?, ?)");
  for (const p of aiData.products ?? []) {
    insertProduct.run(crypto.randomUUID(), id, p.description ?? null, p.quantity ?? null, p.unit_price ?? null);
  }

  return rowToInvoice(db.prepare("SELECT * FROM invoices WHERE id = ?").get(id));
}

function rowToInvoice(row) {
  const products = db.prepare("SELECT description, quantity, unit_price FROM products WHERE invoice_id = ?").all(row.id);
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

  const insertProduct = db.prepare("INSERT INTO products (id, invoice_id, description, quantity, unit_price) VALUES (?, ?, ?, ?, ?)");
  for (const p of products) insertProduct.run(crypto.randomUUID(), id, p.description ?? null, p.quantity ?? null, p.unit_price ?? null);

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
    const insertProduct = db.prepare("INSERT INTO products (id, invoice_id, description, quantity, unit_price) VALUES (?, ?, ?, ?, ?)");
    for (const p of merged.products) insertProduct.run(crypto.randomUUID(), row.id, p.description ?? null, p.quantity ?? null, p.unit_price ?? null);
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

// csv/json export helpers - xlsx goes through exportengine.py instead
// (openpyxl styling/chart, not worth reimplementing in Node). Column set
// mirrors exportengine.py's flatten_invoice so all three formats agree on
// field names; a field-group-redacted key just comes through blank, same as
// the Python side's p.get(key, "").
function flattenForCsv(inv) {
  const p = inv.provider || {}, r = inv.receiver || {}, i = inv.invoice || {}, t = inv.totals || {};
  return {
    provider_name: p.name ?? "", provider_address: p.address ?? "", provider_city: p.city ?? "",
    provider_state: p.state ?? "", provider_country: p.country ?? "", provider_pincode: p.pincode ?? "",
    provider_contact_no: p.contact_no ?? "", provider_pan_no: p.pan_no ?? "", provider_gstin: p.gstin ?? "",
    provider_cin_no: p.cin_no ?? "", provider_tan: p.tan ?? "", provider_email: p.email ?? "",
    provider_bank_name: p.bank_name ?? "", provider_account_no: p.account_no ?? "", provider_ifsc_code: p.ifsc_code ?? "",
    receiver_name: r.name ?? "", receiver_address: r.address ?? "", receiver_city: r.city ?? "",
    receiver_state: r.state ?? "", receiver_country: r.country ?? "", receiver_pincode: r.pincode ?? "",
    receiver_contact_no: r.contact_no ?? "", receiver_pan_no: r.pan_no ?? "", receiver_gstin: r.gstin ?? "",
    receiver_cin_no: r.cin_no ?? "", receiver_tan: r.tan ?? "", receiver_email: r.email ?? "",
    invoice_id: i.invoice_id ?? "", date_of_invoice: i.date_of_invoice ?? "", place_of_supply: i.place_of_supply ?? "",
    vendor_code: i.vendor_code ?? "", due_date: i.due_date ?? "", order_number: i.order_number ?? "", transporter: i.transporter ?? "",
    overall_cgst_rate: t.overall_cgst_rate ?? "", overall_cgst: t.overall_cgst ?? "",
    overall_sgst_rate: t.overall_sgst_rate ?? "", overall_sgst: t.overall_sgst ?? "", overall_total_amount: t.overall_total_amount ?? "",
  };
}

function csvEscape(val) {
  const s = String(val ?? "");
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function toCsv(invoices) {
  const rows = invoices.map(flattenForCsv);
  if (!rows.length) return "";
  const headers = Object.keys(rows[0]);
  const lines = [headers.join(","), ...rows.map(row => headers.map(h => csvEscape(row[h])).join(","))];
  return lines.join("\r\n");
}

function safeFilenamePart(s) {
  return (s || "unknown").replace(/[^a-zA-Z0-9_-]/g, "_");
}

// Server-side, field-scoped, audited export. invoice.export reuses
// invoice.read's field grants (confirmed design decision, not a new grant
// surface) - only rows already SET to QA_APPROVED_QA are exportable; others
// are silently excluded (not an error) and counted in X-Excluded-Count.
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
  const eligible = candidates.filter(inv => inv.status === "QA_APPROVED_QA");
  const excludedCount = candidates.length - eligible.length;

  const allowedFieldGroups = effectiveFieldGroups(req.actor, "invoice.read");
  const filtered = eligible.map(inv => filterInvoiceFields(inv, allowedFieldGroups));

  const user = db.prepare("SELECT username FROM users WHERE id = ?").get(req.actor.id);
  const role = db.prepare(
    "SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ? ORDER BY r.rank ASC LIMIT 1"
  ).get(req.actor.id);
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = `Wilo_Export_${safeFilenamePart(user?.username)}_${safeFilenamePart(role?.name)}_${timestamp}.${format}`;

  res.setHeader("X-Excluded-Count", String(excludedCount));
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);

  if (format === "json") {
    res.setHeader("Content-Type", "application/json");
    return res.send(JSON.stringify({ invoices: filtered }, null, 2));
  }
  if (format === "csv") {
    res.setHeader("Content-Type", "text/csv");
    return res.send(toCsv(filtered));
  }

  // xlsx - only format that spawns Python
  const tempPayloadPath = path.join(os.tmpdir(), `wilo-export-payload-${crypto.randomUUID()}.json`);
  const tempOutputPath = path.join(os.tmpdir(), `wilo-export-output-${crypto.randomUUID()}.xlsx`);
  try {
    fs.writeFileSync(tempPayloadPath, JSON.stringify({ invoices: filtered }));
    const result = await runExportEngine(tempPayloadPath, tempOutputPath);
    if (result.error) throw new Error(result.error);

    const buffer = fs.readFileSync(tempOutputPath);
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    res.send(buffer);
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    if (fs.existsSync(tempPayloadPath)) fs.unlinkSync(tempPayloadPath);
    if (fs.existsSync(tempOutputPath)) fs.unlinkSync(tempOutputPath);
  }
});

export default router;
