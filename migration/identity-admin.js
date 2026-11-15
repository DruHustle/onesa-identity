// Run from the protected host after verifying the intended person's independent owner authorization.
import { openStore, uuid } from "../src/store.js";

function requireState(condition, message) {
  if (!condition) throw Error(message);
}

export function bootstrapIdentityAdmin(store, issuer, id, receipt) {
  let provider;
  try {
    provider = new URL(issuer);
  } catch {
    throw Error("A canonical configured HTTPS OIDC_ISSUER is required");
  }
  requireState(
    provider.protocol === "https:" &&
      provider.origin + "/" === issuer &&
      !provider.username &&
      !provider.password,
    "A canonical configured HTTPS OIDC_ISSUER is required",
  );
  requireState(
    uuid(id) &&
      typeof receipt === "string" &&
      receipt.trim() &&
      receipt.length <= 400,
    "A stable user ID and bounded approval receipt are required",
  );
  store.atomic(() => {
    // A stale grant on a suspended/rejected account must not prevent the
    // independently authorized replacement administrator from bootstrapping.
    if (
      store.one(
        "SELECT g.id FROM grants g JOIN accounts a USING(id) WHERE g.product='identity' AND g.status='active' AND a.status='active' LIMIT 1",
      )
    )
      throw Error(
        "An active Identity administrator already exists. Use the Identity UI.",
      );
    const linked = store.one(
      `SELECT a.id FROM accounts a
       JOIN links l USING(id)
       WHERE a.id=? AND l.issuer=? AND a.status IN ('active','pending')
         AND (
           l.evidence='verified-provider-registration' OR
           l.evidence LIKE 'dual-authentication:%' OR
           l.evidence LIKE 'provider-import-receipt:%'
         )`,
      id,
      issuer,
    );
    if (!linked)
      throw Error("An independently verified account link for the configured issuer is required");
    store.run(
      "UPDATE accounts SET status='active',revision=revision+1 WHERE id=?",
      id,
    );
    store.run(
      "INSERT INTO grants VALUES(?,'identity','admin','active') ON CONFLICT(id,product) DO UPDATE SET role='admin',status='active'",
      id,
    );
    store.audit("bootstrap", "identity-admin", id, { receipt, issuer });
  });
}

if (
  process.argv[1] &&
  new URL(process.argv[1], "file:").href === import.meta.url
) {
  process.umask(0o077);
  const [file, id, receipt] = process.argv.slice(2);
  const issuer = process.env.OIDC_ISSUER;
  requireState(
    file && issuer && id && receipt,
    "Usage: OIDC_ISSUER=https://issuer.example/ node migration/identity-admin.js DATABASE STABLE_USER_ID APPROVAL_RECEIPT",
  );
  const store = openStore(file);
  try {
    bootstrapIdentityAdmin(store, issuer, id, receipt);
  } finally {
    store.db.close();
  }
}
