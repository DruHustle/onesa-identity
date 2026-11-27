import { pathToFileURL } from "node:url";
import { openStore, platformGrant, uuid } from "../src/store.js";

export function bootstrapPlatformAdministrators(store, issuer, ids, receipt) {
  const provider = typeof issuer === "string" && URL.parse(issuer);
  if (!provider || provider.protocol !== "https:" || provider.origin + "/" !== issuer ||
      ids.length !== 2 || new Set(ids).size !== 2 || !ids.every(uuid) ||
      typeof receipt !== "string" || !receipt.trim() || receipt.length > 400)
    throw Error("A canonical issuer, two distinct stable IDs and an independent approval receipt are required");
  store.atomic(() => {
    if (store.one(
      "SELECT 1 FROM grants g JOIN accounts a USING(id) WHERE g.product=? AND g.role='administrator' AND g.status='active' AND a.status='active'",
      platformGrant,
    )) throw Error("An active platform administrator already exists");
    for (const id of ids) {
      const verified = store.one(
        `SELECT 1 FROM links WHERE id=? AND issuer=? AND
          (evidence='verified-provider-registration' OR evidence LIKE 'dual-authentication:%' OR
           evidence LIKE 'provider-import-receipt:%')`, id, issuer,
      );
      if (!verified || store.activeGrant(id, "identity")?.role !== "administrator")
        throw Error("Both initial administrators must have active Identity access and verified issuer links");
      store.run(
        "INSERT INTO grants VALUES(?,?,'administrator','active') ON CONFLICT(id,product) DO UPDATE SET role='administrator',status='active'",
        id, platformGrant,
      );
      store.run("DELETE FROM sessions WHERE id=?", id);
      store.run("UPDATE accounts SET revision=revision+1 WHERE id=?", id);
      store.audit("bootstrap", "grant", id, {
        kind: "grant", product: platformGrant, role: "administrator", status: "active", receipt,
      });
    }
  });
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.umask(0o077);
  const [file, first, second, receipt] = process.argv.slice(2);
  if (!file || !first || !second || !receipt)
    throw Error("Usage: OIDC_ISSUER=https://issuer.example/ node migration/platform-admin.js DATABASE FIRST_ID SECOND_ID APPROVAL_RECEIPT");
  const store = openStore(file, { existingOnly: true });
  try {
    bootstrapPlatformAdministrators(store, process.env.OIDC_ISSUER, [first, second], receipt);
  } finally {
    store.db.close();
  }
}
