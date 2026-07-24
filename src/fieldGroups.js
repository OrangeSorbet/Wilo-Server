// fieldGroups.js
// Field-level permission groups layered on top of the existing SCOPED
// "group" check (permissions.js's can()/scopesOf()). Grants reuse the same
// role_grants.scopes_json array, just with a "field:" prefix so a single
// scopes array can carry both the existing bare group tokens ("*", or a
// plain group string used by the SCOPED check) and these field-group tokens
// side by side without disturbing each other's meaning.
//
// Field list here mirrors the real extraction shape emitted by
// Wilo-Server/backend/prompt.txt / engine.py and read back by
// routes/invoices.js's rowToInvoice() - not the DB columns (those are just
// provider_json/receiver_json/invoice_json/totals_json blobs).
//
// paths: { path, label }[] - path is the exact raw dotted string used in
// "field:<groupId>|<path>" scope tokens (byte-identical to what's stored on
// existing grants, never change it), label is a human-readable name for
// display only in the admin UI - never used in filtering/matching logic.

export const FIELD_GROUPS = {
  "provider.basic": {
    label: "Provider - basic details",
    description: "Provider name, address, and locality fields.",
    paths: [
      { path: "provider.name", label: "Business Name" },
      { path: "provider.address", label: "Address" },
      { path: "provider.city", label: "City" },
      { path: "provider.state", label: "State" },
      { path: "provider.country", label: "Country" },
      { path: "provider.pincode", label: "Pincode" },
    ],
  },
  "provider.contact": {
    label: "Provider - contact details",
    description: "Provider phone and email.",
    paths: [
      { path: "provider.contact_no", label: "Phone Number" },
      { path: "provider.email", label: "Email Address" },
    ],
  },
  "provider.tax_ids": {
    label: "Provider - tax identifiers",
    description: "Provider GSTIN, PAN, CIN, and TAN.",
    paths: [
      { path: "provider.gstin", label: "GSTIN Number" },
      { path: "provider.pan_no", label: "PAN Number" },
      { path: "provider.cin_no", label: "CIN Number" },
      { path: "provider.tan", label: "TAN Number" },
    ],
  },
  "provider.banking": {
    label: "Provider - banking details",
    description: "Provider bank name, account number, and IFSC code.",
    paths: [
      { path: "provider.bank_name", label: "Bank Name" },
      { path: "provider.account_no", label: "Account Number" },
      { path: "provider.ifsc_code", label: "IFSC Code" },
    ],
  },
  "receiver.basic": {
    label: "Receiver - basic details",
    description: "Receiver name, address, and locality fields.",
    paths: [
      { path: "receiver.name", label: "Receiver Name" },
      { path: "receiver.address", label: "Address" },
      { path: "receiver.city", label: "City" },
      { path: "receiver.state", label: "State" },
      { path: "receiver.country", label: "Country" },
      { path: "receiver.pincode", label: "Pincode" },
    ],
  },
  "receiver.contact": {
    label: "Receiver - contact details",
    description: "Receiver phone and email.",
    paths: [
      { path: "receiver.contact_no", label: "Phone Number" },
      { path: "receiver.email", label: "Email Address" },
    ],
  },
  "receiver.tax_ids": {
    label: "Receiver - tax identifiers",
    description: "Receiver GSTIN, PAN, CIN, and TAN.",
    paths: [
      { path: "receiver.gstin", label: "GSTIN Number" },
      { path: "receiver.pan_no", label: "PAN Number" },
      { path: "receiver.cin_no", label: "CIN Number" },
      { path: "receiver.tan", label: "TAN Number" },
    ],
  },
  "invoice.meta": {
    label: "Invoice metadata",
    description: "Invoice id, dates, place of supply, and order/transport references.",
    paths: [
      { path: "invoice.invoice_id", label: "Invoice Number" },
      { path: "invoice.date_of_invoice", label: "Invoice Date" },
      { path: "invoice.place_of_supply", label: "Place of Supply" },
      { path: "invoice.vendor_code", label: "Vendor Code" },
      { path: "invoice.due_date", label: "Due Date" },
      { path: "invoice.order_number", label: "Order Number" },
      { path: "invoice.transporter", label: "Transporter" },
    ],
  },
  "products.line_items": {
    label: "Product line items",
    description: "The full products array - all or nothing.",
    paths: [
      { path: "products", label: "Product Line Items" },
    ],
  },
  "totals.amounts": {
    label: "Totals and tax amounts",
    description: "Overall CGST/SGST rates and the grand total.",
    paths: [
      { path: "totals.overall_cgst_rate", label: "CGST Rate" },
      { path: "totals.overall_cgst", label: "CGST Amount" },
      { path: "totals.overall_sgst_rate", label: "SGST Rate" },
      { path: "totals.overall_sgst", label: "SGST Amount" },
      { path: "totals.overall_total_amount", label: "Grand Total" },
    ],
  },
};

// path ("provider.gstin") -> groupId, built once from the registry above.
const PATH_TO_GROUP = new Map();
for (const [groupId, def] of Object.entries(FIELD_GROUPS)) {
  for (const { path } of def.paths) PATH_TO_GROUP.set(path, groupId);
}

// allowed is permissions.js#effectiveFieldGroups()'s return shape:
// { all: boolean, fullGroups: Set<groupId>, partialPaths: Set<"groupId|path"> }
function isAllowed(allowed, groupId, path) {
  if (allowed.all) return true;
  if (allowed.fullGroups.has(groupId)) return true;
  return allowed.partialPaths.has(`${groupId}|${path}`);
}

// Redaction: strip any field whose group/path isn't granted. Returns a new
// object - never mutates invoiceObj.
export function filterInvoiceFields(invoiceObj, allowed) {
  if (allowed.all) return invoiceObj;

  const result = { ...invoiceObj };
  for (const section of ["provider", "receiver", "invoice", "totals"]) {
    if (!invoiceObj[section] || typeof invoiceObj[section] !== "object") continue;
    const filtered = {};
    for (const [key, value] of Object.entries(invoiceObj[section])) {
      const path = `${section}.${key}`;
      const groupId = PATH_TO_GROUP.get(path);
      if (!groupId || isAllowed(allowed, groupId, path)) filtered[key] = value;
    }
    result[section] = filtered;
  }

  if ("products" in invoiceObj && !isAllowed(allowed, "products.line_items", "products")) {
    delete result.products;
  }

  return result;
}

function mergeSection(sectionName, existingSection, incomingSection, allowed) {
  if (!incomingSection || typeof incomingSection !== "object") return existingSection;
  if (allowed.all) return { ...existingSection, ...incomingSection };

  const merged = { ...existingSection };
  for (const [key, value] of Object.entries(incomingSection)) {
    const path = `${sectionName}.${key}`;
    const groupId = PATH_TO_GROUP.get(path);
    if (!groupId || isAllowed(allowed, groupId, path)) merged[key] = value;
  }
  return merged;
}

// Write-side merge: only fields in granted groups/paths are taken from
// `incoming`, everything else stays as `existing`. products.line_items is
// all-or-nothing (whole array replaced, or whole array kept from existing).
export function mergeAllowedFieldUpdates(existing, incoming, allowed) {
  const result = {
    provider: mergeSection("provider", existing.provider, incoming.provider, allowed),
    receiver: mergeSection("receiver", existing.receiver, incoming.receiver, allowed),
    invoice: mergeSection("invoice", existing.invoice, incoming.invoice, allowed),
    totals: mergeSection("totals", existing.totals, incoming.totals, allowed),
  };

  if (incoming.products !== undefined && isAllowed(allowed, "products.line_items", "products")) {
    result.products = incoming.products;
  } else {
    result.products = existing.products;
  }

  return result;
}
