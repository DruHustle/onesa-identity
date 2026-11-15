import { DatabaseSync } from "node:sqlite";
import { createHash, randomBytes, randomUUID } from "node:crypto";

export const products = {
  identity: ["admin"],
  portal: ["owner", "administrator", "editor", "business", "hr", "viewer"],
  "internal-documents": ["viewer", "editor", "admin"],
  "engineering-documents": ["viewer", "editor", "admin"],
  farmer: ["user"],
  logistics: ["user"],
  factory: ["user"],
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
export const uuid = (value) =>
  typeof value === "string" &&
  /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(value);
export const secret = () => randomBytes(32).toString("base64url");
export const digest = (value) =>
  createHash("sha256").update(value).digest("hex");
export class Rejected extends Error {}
const check = (condition, message) => {
  if (!condition) throw new Rejected(message);
};

export function openStore(path) {
  const db = new DatabaseSync(path);
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
    CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY, id TEXT NOT NULL REFERENCES accounts, csrf TEXT NOT NULL, expires INTEGER NOT NULL, mfa_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS recovery_limit(id TEXT PRIMARY KEY REFERENCES accounts, next INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS imports(snapshot TEXT PRIMARY KEY, digest TEXT NOT NULL, watermark INTEGER NOT NULL); `);
  const one = (q, ...a) => db.prepare(q).get(...a);
  const all = (q, ...a) => db.prepare(q).all(...a);
  const run = (q, ...a) => db.prepare(q).run(...a);
  const audit = (actor, action, id, detail = {}) =>
    run(
      "INSERT INTO audit(at,actor,action,target,detail) VALUES(?,?,?,?,?)",
      Date.now(),
      actor,
      action,
      id,
      JSON.stringify(detail),
    );
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
  function register(issuer, sub, email, invitation = "") {
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
      const token = secret(),
        contact = email.trim().toLowerCase();
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
    db,
    one,
    all,
    run,
    audit,
    atomic,
    lookup,
    activeGrant,
    register,
    invite,
    change,
  };
}
