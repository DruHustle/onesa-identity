import { statSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { createHash, randomBytes, randomUUID } from "node:crypto";

export const products = {
  identity: ["admin"],
  portal: ["owner", "administrator", "editor", "business", "hr", "viewer"],
  "internal-documents": ["viewer", "editor", "admin"],
  "engineering-documents": ["viewer", "editor", "admin"],
  farmer: ["user", "admin"],
  logistics: ["user", "admin"],
  factory: ["user", "admin"],
  ai: ["user", "admin"],
  drone: ["viewer", "operator", "admin"],
  robot: ["viewer", "operator", "admin"],
  mobile: [
    "admin",
    "operations",
    "support",
    "finance",
    "agent",
    "auditor",
    "customer",
  ],
  pasofi: ["customer", "agent", "support", "admin"],
};
// Self-service requests use the lowest product role. Administrators assign operational roles.
export const accountProducts = new Map([
  ["portal", { name: "Company Portal", role: "viewer" }],
  ["internal-documents", { name: "Internal Documents", role: "viewer" }],
  ["factory", { name: "Smart Factory", role: "user" }],
  ["logistics", { name: "Smart Logistics", role: "user" }],
  ["farmer", { name: "Smart Farmer", role: "user" }],
  ["ai", { name: "Onesa AI Platform", role: "user" }],
  ["drone", { name: "Onesa Drone", role: "viewer" }],
  ["robot", { name: "Onesa Robot", role: "viewer" }],
  ["mobile", { name: "Onesa Mobile", role: "customer" }],
  ["pasofi", { name: "PasoFi", role: "customer" }],
]);
// Staff tools and Identity governance require their own explicit grants.
export const sharedProducts = new Set(["factory", "logistics", "farmer", "ai", "drone", "robot", "mobile", "pasofi"]);
export const configurableAdminRoles = new Set(["factory", "logistics", "farmer"]);

// The immutable account journal is already backed up and replayed with each stable identity.
// A later decision replaces that tier's earlier state. A declined or removed request cannot
// silently reopen through another registration or login.
export function registrations(db, id) {
  const rows = db.prepare("SELECT detail FROM audit WHERE target=? AND action='shared-registration' ORDER BY seq").all(id);
  const result = new Map();
  for (const row of rows) {
    const { tier, status } = JSON.parse(row.detail);
    result.set(tier, status);
  }
  return result;
}
export function sharedRole(product, tiers, adminRoleEnabled) {
  if (product === "portal") return tiers.get("admin") === "active" ? "administrator" : null;
  if (!sharedProducts.has(product)) return null;
  if (tiers.get("admin") === "active") {
    const elevated = !configurableAdminRoles.has(product) || adminRoleEnabled;
    return elevated ? "admin" : accountProducts.get(product).role;
  }
  return tiers.get("user") === "active" ? accountProducts.get(product).role : null;
}

export const uuid = (value) =>
  typeof value === "string" &&
  /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(value);
export const secret = () => randomBytes(32).toString("base64url");
export const digest = (value) =>
  createHash("sha256").update(value).digest("hex");
const auditHash = (previous, row) =>
  digest(JSON.stringify([
    previous,
    row.seq,
    row.at,
    row.actor,
    row.action,
    row.target,
    row.detail,
  ]));
export class Rejected extends Error {}
const check = (condition, message) => {
  if (!condition) throw new Rejected(message);
};

export function openStore(path, { existingOnly = false } = {}) {
  const mounted = existingOnly ? statSync(path, { bigint: true }) : null;
  const uri = existingOnly ? pathToFileURL(path) : null;
  if (uri) uri.searchParams.set("mode", "rw");
  const db = new DatabaseSync(uri ? uri.href : path);
  function currentFile() {
    if (!mounted) return true;
    const current = statSync(path, { bigint: true, throwIfNoEntry: false });
    return current?.dev === mounted.dev && current.ino === mounted.ino;
  }
  if (existingOnly) {
    try {
      const tables = db.prepare("SELECT count(*) AS n FROM sqlite_schema WHERE type='table' AND name IN ('accounts','links','grants','audit')").get();
      if (!currentFile() || tables.n !== 4) throw Error("Expected an existing Onesa Identity policy store");
    } catch (error) {
      db.close();
      throw error;
    }
  }
  db.exec(`PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY, email TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('pending','active','suspended','rejected')),
      revision INTEGER NOT NULL DEFAULT 1);
    CREATE INDEX IF NOT EXISTS accounts_email ON accounts(email COLLATE NOCASE);
    CREATE TABLE IF NOT EXISTS links(issuer TEXT NOT NULL, subject TEXT NOT NULL, id TEXT NOT NULL REFERENCES accounts,
      evidence TEXT NOT NULL, PRIMARY KEY(issuer,subject), UNIQUE(issuer,id));
    CREATE TABLE IF NOT EXISTS grants(id TEXT NOT NULL REFERENCES accounts, product TEXT NOT NULL, role TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('pending','active','revoked','rejected')), PRIMARY KEY(id,product));
    CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT, detail TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS invites(hash TEXT PRIMARY KEY, email TEXT NOT NULL, expires INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS challenges(hash TEXT PRIMARY KEY, state TEXT NOT NULL, nonce TEXT NOT NULL, verifier TEXT NOT NULL, destination TEXT NOT NULL, expires INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS registration_resumes(hash TEXT NOT NULL, state TEXT PRIMARY KEY, destination TEXT NOT NULL, expires INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS registration_resume_browser ON registration_resumes(hash);
    CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY, id TEXT NOT NULL REFERENCES accounts, csrf TEXT NOT NULL, expires INTEGER NOT NULL, mfa_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS recovery_limit(id TEXT PRIMARY KEY REFERENCES accounts, next INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS imports(snapshot TEXT PRIMARY KEY, digest TEXT NOT NULL, watermark INTEGER NOT NULL); `);
  const one = (q, ...a) => db.prepare(q).get(...a);
  const all = (q, ...a) => db.prepare(q).all(...a);
  const run = (q, ...a) => db.prepare(q).run(...a);

  // Upgrade existing audit tables atomically. A partially present chain is
  // rejected rather than silently re-hashed, which could conceal tampering.
  const auditColumns = new Set(all("PRAGMA table_info(audit)").map((row) => row.name));
  const hasPreviousHash = auditColumns.has("prev_hash");
  const hasEntryHash = auditColumns.has("entry_hash");
  if (hasPreviousHash !== hasEntryHash)
    throw Error("Incomplete Identity audit-chain schema");
  if (!hasPreviousHash) {
    db.exec("BEGIN IMMEDIATE");
    try {
      db.exec(
        "ALTER TABLE audit ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''; " +
        "ALTER TABLE audit ADD COLUMN entry_hash TEXT NOT NULL DEFAULT '';",
      );
      let previous = "";
      for (const row of all(
        "SELECT seq,at,actor,action,target,detail FROM audit ORDER BY seq",
      )) {
        const entryHash = auditHash(previous, row);
        run(
          "UPDATE audit SET prev_hash=?,entry_hash=? WHERE seq=?",
          previous,
          entryHash,
          row.seq,
        );
        previous = entryHash;
      }
      db.exec("COMMIT");
    } catch (error) {
      db.exec("ROLLBACK");
      throw error;
    }
  }

  function verifyAuditChain() {
    let previous = "";
    const rows = all(
      "SELECT seq,at,actor,action,target,detail,prev_hash,entry_hash FROM audit ORDER BY seq",
    );
    for (const row of rows) {
      const expected = auditHash(previous, row);
      if (row.prev_hash !== previous || row.entry_hash !== expected)
        throw Error("Identity audit integrity failure at sequence " + row.seq);
      previous = row.entry_hash;
    }
    return { entries: rows.length, head: previous };
  }

  // Verify the source chain in a recovery bundle, then re-chain events onto
  // the restored database's baseline rather than copying incompatible hashes.
  function verifyAuditEvents(events, initialHash) {
    if (!Array.isArray(events) || typeof initialHash !== "string")
      throw Error("Invalid recovery audit chain");
    let previous = initialHash;
    for (const row of events) {
      const expected = auditHash(previous, row);
      if (row.prev_hash !== previous || row.entry_hash !== expected)
        throw Error("Recovery audit chain integrity failure at sequence " + row.seq);
      previous = row.entry_hash;
    }
    return { entries: events.length, head: previous };
  }

  function appendAuditEvent(row) {
    const previousRow = one("SELECT seq,entry_hash FROM audit ORDER BY seq DESC LIMIT 1");
    const seq = (previousRow?.seq ?? 0) + 1;
    if (row.seq !== seq) throw Error("Recovery audit sequence mismatch");
    const previous = previousRow?.entry_hash ?? "";
    const entryHash = auditHash(previous, row);
    return run(
      "INSERT INTO audit(seq,at,actor,action,target,detail,prev_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?)",
      row.seq, row.at, row.actor, row.action, row.target, row.detail, previous, entryHash,
    );
  }

  db.exec(`
    CREATE TRIGGER IF NOT EXISTS audit_append_only_update
      BEFORE UPDATE ON audit
      BEGIN SELECT RAISE(ABORT, 'Identity audit log is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS audit_append_only_delete
      BEFORE DELETE ON audit
      BEGIN SELECT RAISE(ABORT, 'Identity audit log is append-only'); END;
  `);
  verifyAuditChain();
  db.exec("CREATE INDEX IF NOT EXISTS audit_shared_registrations ON audit(target,seq) WHERE action='shared-registration'");

  const audit = (actor, action, id, detail = {}) => {
    const previousRow = one(
      "SELECT seq,entry_hash FROM audit ORDER BY seq DESC LIMIT 1",
    );
    const seq = (previousRow?.seq ?? 0) + 1;
    const at = Date.now();
    const serialized = JSON.stringify(detail);
    const prevHash = previousRow?.entry_hash ?? "";
    const entryHash = auditHash(prevHash, {
      seq,
      at,
      actor,
      action,
      target: id,
      detail: serialized,
    });
    return run(
      "INSERT INTO audit(seq,at,actor,action,target,detail,prev_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?)",
      seq,
      at,
      actor,
      action,
      id,
      serialized,
      prevHash,
      entryHash,
    );
  };
  function atomic(fn) {
    db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      db.exec("COMMIT");
      return result;
    } catch (error) {
      db.exec("ROLLBACK");
      throw error;
    }
  }
  const lookup = (issuer, sub) =>
    one(
      "SELECT accounts.* FROM links JOIN accounts USING(id) WHERE issuer=? AND subject=?",
      issuer,
      sub,
    );
  const activeGrant = (id, product) =>
    one(
      "SELECT role FROM grants JOIN accounts USING(id) WHERE id=? AND product=? AND grants.status='active' AND accounts.status='active'",
      id,
      product,
    );
  function recordRequest(id, tier, existing = true) {
    check(tier === "user" || tier === "admin", "Invalid registration type");
    if (registrations(db, id).has(tier)) return;
    audit(id, "shared-registration", id, { tier, status: "pending" });
    if (existing) run("UPDATE accounts SET revision=revision+1 WHERE id=?", id);
  }
  function requestRegistration(id, tier) {
    return atomic(() => {
      const account = one("SELECT status FROM accounts WHERE id=?", id);
      check(["active", "pending"].includes(account?.status), "Account unavailable");
      recordRequest(id, tier);
    });
  }
  function register(issuer, sub, email, invitation = "", tier) {
    return atomic(() => {
      check(
        typeof email === "string" &&
          email.length <= 254 &&
          /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()),
        "Verified address required",
      );
      const contact = email.trim().toLowerCase();
      const linked = lookup(issuer, sub);
      if (linked) {
        if (linked.email !== contact) {
          // Only the same verified issuer/subject may refresh its contact
          // address. An email collision never transfers another account.
          check(
            !one("SELECT id FROM accounts WHERE email=? COLLATE NOCASE AND id<>?", contact, linked.id),
            "Existing account needs ownership verification",
          );
          run("UPDATE accounts SET email=?,revision=revision+1 WHERE id=?", contact, linked.id);
          audit(linked.id, "verified-email-change", linked.id, {
            previous: linked.email,
            current: contact,
            issuer,
          });
        }
        if (tier && ["active", "pending"].includes(linked.status)) recordRequest(linked.id, tier);
        return lookup(issuer, sub);
      }
      // A legacy address match demands separately verified immutable ownership.
      check(
        !one("SELECT id FROM accounts WHERE email=? COLLATE NOCASE", contact),
        "Existing account needs ownership verification",
      );
      let invite;
      if (invitation) {
        invite = one(
          "DELETE FROM invites WHERE hash=? AND expires>? AND email=? RETURNING email",
          digest(invitation),
          Date.now(),
          contact,
        );
        check(invite, "Invitation expired or unavailable");
      }
      const id = randomUUID();
      run(
        "INSERT INTO accounts(id,email,status) VALUES(?,?,?)",
        id,
        contact,
        "pending",
      );
      run(
        "INSERT INTO links VALUES(?,?,?,?)",
        issuer,
        sub,
        id,
        "verified-provider-registration",
      );
      audit(id, invite ? "accept-invitation" : "register", id, {
        status: "pending",
      });
      if (tier !== undefined) recordRequest(id, tier ?? "user", false);
      return lookup(issuer, sub);
    });
  }
  function invite(actor, email) {
    check(
      typeof email === "string" &&
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) &&
        email.length <= 254,
      "Enter a valid address",
    );
    return atomic(() => {
      const contact = email.trim().toLowerCase();
      // Invitations are for new identities only. Do not create a link that
      // registration can never consume, or let an invitation appear to
      // bypass an existing (including suspended) account's review state.
      check(
        !one("SELECT 1 FROM accounts WHERE email=? COLLATE NOCASE", contact),
        "An account already exists for this address; manage the existing account",
      );
      const token = secret();
      run(
        "DELETE FROM invites WHERE expires<=? OR email=?",
        Date.now(),
        contact,
      );
      run(
        "INSERT INTO invites VALUES(?,?,?)",
        digest(token),
        contact,
        Date.now() + 86400000,
      );
      audit(actor, "invite", null, { email: contact });
      return token;
    });
  }
  function requestAccess(id, product) {
    return atomic(() => {
      const requested = accountProducts.get(product);
      check(requested, "Product unavailable");
      const account = one("SELECT status FROM accounts WHERE id=?", id);
      check(account && ["active", "pending"].includes(account.status), "Account unavailable");
      // A delayed form submission must not replace already approved shared entry with a pending override.
      if (sharedRole(product, registrations(db, id), false)) return;
      // A canonical Documents record would supersede the existing Engineering decision.
      if (product === "internal-documents" &&
          one("SELECT 1 FROM grants WHERE id=? AND product='engineering-documents'", id)) return;
      const inserted = run(
        "INSERT INTO grants(id,product,role,status) VALUES(?,?,?,'pending') ON CONFLICT(id,product) DO NOTHING",
        id, product, requested.role,
      );
      if (inserted.changes) {
        run("UPDATE accounts SET revision=revision+1 WHERE id=?", id);
        audit(id, "request-product-access", id, { product, role: requested.role });
      }
    });
  }
  function change(actor, id, revision, operation) {
    return atomic(() => {
      const current = one("SELECT * FROM accounts WHERE id=?", id);
      check(
        current && current.revision === revision,
        "Account changed; reload before editing",
      );
      if (operation.kind === "status") {
        check(
          ["active", "pending", "suspended", "rejected"].includes(
            operation.status,
          ),
          "Invalid status",
        );
        if (actor === id)
          check(
            operation.status === "active",
            "Self-suspension is unavailable",
          );
        run("UPDATE accounts SET status=? WHERE id=?", operation.status, id);
        if (operation.status !== "active")
          run("DELETE FROM sessions WHERE id=?", id);
      } else if (operation.kind === "registration") {
        check(actor !== id && activeGrant(actor, "identity")?.role === "admin", "Independent Identity administrator required");
        const previous = registrations(db, id).get(operation.tier);
        check(previous && (
          (["pending", "revoked", "rejected"].includes(previous) && operation.status === "active") ||
          (previous === "pending" && operation.status === "rejected") ||
          (previous === "active" && operation.status === "revoked")
        ), "Invalid registration decision");
        audit(actor, "shared-registration", id, { tier: operation.tier, status: operation.status });
        run("UPDATE accounts SET revision=revision+1 WHERE id=?", id);
        return;
      } else if (operation.kind === "review") {
        const requested = accountProducts.get(operation.product);
        check(requested && requested.role === operation.role, "Invalid requested role");
        check(["active", "rejected"].includes(operation.status), "Invalid review decision");
        const result = run(
          "UPDATE grants SET status=? WHERE id=? AND product=? AND role=? AND status='pending'",
          operation.status, id, operation.product, operation.role,
        );
        check(result.changes === 1, "Request changed; reload before reviewing");
      } else if (operation.kind === "grant") {
        check(
          Object.hasOwn(products, operation.product) &&
            products[operation.product].includes(operation.role),
          "Invalid product role",
        );
        check(
          ["active", "revoked"].includes(operation.status),
          "Invalid access state",
        );
        if (actor === id && operation.product === "identity")
          check(operation.status === "active", "Self-removal is unavailable");
        run(
          "INSERT INTO grants VALUES(?,?,?,?) ON CONFLICT(id,product) DO UPDATE SET role=excluded.role,status=excluded.status",
          id,
          operation.product,
          operation.role,
          operation.status,
        );
      } else throw new Rejected("Unknown operation");
      run("UPDATE accounts SET revision=revision+1 WHERE id=?", id);
      audit(actor, operation.kind, id, operation);
    });
  }
  return {
    currentFile,
    db,
    one,
    all,
    run,
    audit,
    verifyAuditChain,
    verifyAuditEvents,
    appendAuditEvent,
    atomic,
    lookup,
    activeGrant,
    register,
    requestAccess,
    requestRegistration,
    invite,
    change,
  };
}
