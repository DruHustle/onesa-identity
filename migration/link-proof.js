// Offline operator utility. The protected proof manifest is prepared from independently verified receipts.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { openStore, uuid } from "../src/store.js";
export function applyProofs(store, issuer, rows) {
  if (
    !Array.isArray(rows) ||
    issuer !== new URL(issuer).origin + "/" ||
    !issuer.startsWith("https://")
  )
    throw Error("Invalid proof manifest");
  return store.atomic(() => {
    let added = 0;
    for (const r of rows) {
      if (
        !uuid(r.id) ||
        r.issuer !== issuer ||
        typeof r.subject !== "string" ||
        !r.subject.trim() ||
        r.subject.length > 512 ||
        !["dual-authentication", "provider-import-receipt"].includes(
          r.method,
        ) ||
        typeof r.receipt !== "string" ||
        !r.receipt.trim() ||
        r.receipt.length > 400
      )
        throw Error("Missing verified ownership evidence");
      const prev = store.lookup(issuer, r.subject);
      if (prev) {
        if (prev.id !== r.id)
          throw Error(
            "Provider subject already belongs to a different account",
          );
        continue;
      }
      store.run(
        "INSERT INTO links VALUES(?,?,?,?)",
        issuer,
        r.subject,
        r.id,
        r.method + ":" + r.receipt,
      );
      if (
        store.one(
          "SELECT 1 FROM sqlite_master WHERE type='table' AND name='migration_discrepancies'",
        )
      )
        store.run(
          "DELETE FROM migration_discrepancies WHERE kind='provider-ownership-proof' AND id=?",
          r.id,
        );
      store.audit("migration", "link-provider", r.id, {
        issuer,
        receipt: r.receipt,
      });
      added++;
    }
    return added;
  });
}
if (
  process.argv[1] &&
  pathToFileURL(process.argv[1]).href === import.meta.url
) {
  process.umask(0o077);
  const [file, issuer, manifest] = process.argv.slice(2);
  if (!file || !issuer || !manifest)
    throw Error("Usage: node migration/link-proof.js DATABASE HTTPS_ISSUER PROOFS.json");
  const store = openStore(file);
  try {
    console.log(
      JSON.stringify({
        added: applyProofs(store, issuer, JSON.parse(readFileSync(manifest))),
      }),
    );
  } finally {
    store.db.close();
  }
}
