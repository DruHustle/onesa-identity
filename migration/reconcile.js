import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { openStore, products, digest, uuid } from "../src/store.js";

const check = (ok, msg) => {
  if (!ok) throw Error(msg);
};
function canonical(x) {
  if (Array.isArray(x)) return x.map(canonical);
  if (x && typeof x === "object")
    return Object.fromEntries(
      Object.keys(x)
        .sort()
        .map((k) => [k, canonical(x[k])]),
    );
  return x;
}
function reference(value) {
  return (
    typeof value === "string" && value.trim().length > 0 && value.length <= 400
  );
}
export function applySnapshot(store, key, snapshot, proofs, issuer) {
  check(
    reference(key) &&
      snapshot.version === 1 &&
      Array.isArray(proofs) &&
      [
        "accounts",
        "grants",
        "docs",
        "registrations",
        "drone_memberships",
      ].every((k) => Array.isArray(snapshot[k])),
    "Invalid version or missing inventory",
  );
  check(
    issuer === new URL(issuer).origin + "/" && issuer.startsWith("https://"),
    "Invalid issuer",
  );
  const fingerprint = digest(
    JSON.stringify(canonical([snapshot, proofs, issuer])),
  );
  return store.atomic(() => {
    const prior = store.one("SELECT * FROM imports WHERE snapshot=?", key);
    if (prior) {
      check(
        prior.digest === fingerprint,
        "Snapshot key reused with different data",
      );
      return {
        replay: true,
        watermark: prior.watermark,
        pending: store.all(
          "SELECT kind,id FROM migration_discrepancies ORDER BY kind,id",
        ),
      };
    }
    check(
      !store.one("SELECT 1 FROM imports LIMIT 1"),
      "Additional source snapshots require explicit reconciliation",
    );
    const pending = [],
      ids = new Set();
    let count = 0;
    for (const u of snapshot.accounts) {
      check(
        uuid(u.id) &&
          !ids.has(u.id) &&
          reference(u.email) &&
          ["active", "suspended"].includes(u.status),
        "Conflicting account snapshot",
      );
      check(
        u.role === "member" || products.portal.includes(u.role),
        "Unknown Portal role",
      );
      ids.add(u.id);
      store.run(
        "INSERT INTO accounts(id,email,status) VALUES(?,?,?)",
        u.id,
        u.email.toLowerCase(),
        u.status,
      );
      if (u.role !== "member")
        store.run(
          "INSERT INTO grants VALUES(?,?,?,?)",
          u.id,
          "portal",
          u.role,
          "active",
        );
      // Old global-admin and implicit Farmer rights require an explicit resource-owner disposition.
      if (u.role !== "member")
        pending.push({ kind: "legacy-implicit-access", id: u.id });
    }
    function grant(row) {
      check(
        ids.has(row.id) &&
          Object.hasOwn(products, row.product) &&
          products[row.product].includes(row.role),
        "Conflicting resource grant",
      );
      store.run(
        "INSERT INTO grants VALUES(?,?,?,?)",
        row.id,
        row.product,
        row.role,
        row.status,
      );
    }
    for (const g of snapshot.grants) {
      if ((g.product === "pasofi" && g.role !== "customer") || g.product === "internal-documents") {
        // The Portal export alone cannot prove staff duties or access to other document domains.
        pending.push({kind: "review-product-grant", id: g.id + "/" + g.product});
      } else grant(g);
    }
    for (const d of snapshot.docs) {
      check(
        uuid(d.membership_id) && typeof d.enabled === "boolean",
        "Invalid document membership",
      );
      if (d.id)
        grant({
          id: d.id,
          product: "engineering-documents",
          role: "viewer",
          status: d.enabled ? "active" : "revoked",
        });
      else
        pending.push({
          kind: "unlinked-document-membership",
          id: d.membership_id,
        });
    }
    store.db.exec(
      "CREATE TABLE IF NOT EXISTS legacy_inventory(kind TEXT, id TEXT, record TEXT NOT NULL, PRIMARY KEY(kind,id))",
    );
    for (const [kind, rows] of [
      ["account", snapshot.accounts],
      ["grant", snapshot.grants],
      ["docs", snapshot.docs],
      ["drone", snapshot.drone_memberships],
      ["registration", snapshot.registrations],
    ]) {
      for (const row of rows) {
        const id =
          kind === "grant"
            ? row.id + "/" + row.product
            : kind === "docs"
              ? row.membership_id
              : kind === "drone"
                ? row.user_id + "/" + row.tenant_id
                : row.id;
        check(
          kind === "grant"
            ? ids.has(row.id)
            : kind === "drone"
              ? ids.has(row.user_id) && uuid(row.tenant_id)
              : uuid(id),
          "Invalid source reference",
        );
        store.run(
          "INSERT INTO legacy_inventory VALUES(?,?,?)",
          kind,
          id,
          JSON.stringify(row),
        );
        if (
          kind === "registration" &&
          (!row.user_id || row.state !== "approved")
        )
          pending.push({ kind: "legacy-registration", id });
      }
    }
    const linked = new Set();
    for (const p of proofs) {
      check(
        ids.has(p.id) &&
          !linked.has(p.id) &&
          p.issuer === issuer &&
          reference(p.subject) &&
          ["dual-authentication", "provider-import-receipt"].includes(
            p.method,
          ) &&
          reference(p.receipt),
        "Missing or conflicting ownership proof",
      );
      store.run(
        "INSERT INTO links VALUES(?,?,?,?)",
        issuer,
        p.subject,
        p.id,
        p.method + ":" + p.receipt,
      );
      linked.add(p.id);
      count++;
    }
    for (const id of ids)
      if (!linked.has(id))
        pending.push({ kind: "provider-ownership-proof", id });
    store.db.exec(
      "CREATE TABLE IF NOT EXISTS migration_discrepancies(kind TEXT,id TEXT,PRIMARY KEY(kind,id))",
    );
    for (const item of pending)
      store.run(
        "INSERT INTO migration_discrepancies VALUES(?,?)",
        item.kind,
        item.id,
      );
    store.audit("migration", "snapshot", null, {
      key,
      fingerprint,
      accounts: ids.size,
      links: count,
      pending: pending.length,
    });
    const watermark = store.one("SELECT max(seq) AS seq FROM audit").seq;
    store.run("INSERT INTO imports VALUES(?,?,?)", key, fingerprint, watermark);
    return {
      replay: false,
      watermark,
      accounts: ids.size,
      links: count,
      pending,
    };
  });
}
// Bring a separately restored baseline forward to a frozen cutover watermark.
export function replayDelta(store, bundle) {
  return store.atomic(() => {
    const source = store.one(
      "SELECT * FROM imports WHERE snapshot=?",
      bundle.snapshot,
    );
    check(
      source &&
        source.digest === bundle.fingerprint &&
        source.watermark === bundle.watermark,
      "Restored baseline mismatch",
    );
    check(
      bundle.events.length === 0 ||
        bundle.events.every((e, i) => e.seq === source.watermark + i + 1),
      "Discontinuous change journal",
    );
    const expected = [
      ...new Set(bundle.events.map((e) => e.target).filter(Boolean)),
    ].sort();
    const actual = bundle.changed.map((row) => row.account.id).sort();
    check(
      JSON.stringify(expected) === JSON.stringify(actual),
      "Incomplete changed-account state",
    );
    const existing = store.all(
      "SELECT * FROM audit WHERE seq>? ORDER BY seq",
      source.watermark,
    );
    if (existing.length) {
      check(
        JSON.stringify(existing) === JSON.stringify(bundle.events),
        "Recovery target has divergent writes",
      );
      return { replay: true, accounts: actual.length };
    }
    for (const x of bundle.changed) {
      const a = x.account;
      check(
        uuid(a.id) &&
          typeof a.email === "string" &&
          Number.isInteger(a.revision) &&
          a.revision >= 1,
        "Invalid account state",
      );
      store.run(
        "INSERT INTO accounts(id,email,status,revision) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET email=excluded.email,status=excluded.status,revision=excluded.revision",
        a.id,
        a.email,
        a.status,
        a.revision,
      );
      for (const l of x.links) {
        check(l.id === a.id, "Invalid account link");
        const prior = store.lookup(l.issuer, l.subject);
        check(!prior || prior.id === a.id, "Conflicting provider link");
        if (!prior)
          store.run(
            "INSERT INTO links VALUES(?,?,?,?)",
            l.issuer,
            l.subject,
            l.id,
            l.evidence,
          );
      }
      store.run("DELETE FROM grants WHERE id=?", a.id);
      for (const g of x.grants) {
        check(
          g.id === a.id &&
            Object.hasOwn(products, g.product) &&
            products[g.product].includes(g.role),
          "Invalid recovered grant",
        );
        store.run(
          "INSERT INTO grants VALUES(?,?,?,?)",
          a.id,
          g.product,
          g.role,
          g.status,
        );
      }
    }
    for (const e of bundle.events)
      store.run(
        "INSERT INTO audit VALUES(?,?,?,?,?,?)",
        e.seq,
        e.at,
        e.actor,
        e.action,
        e.target,
        e.detail,
      );
    store.run("DELETE FROM sessions");
    store.run("DELETE FROM invites");
    store.run("DELETE FROM challenges");
    return { replay: false, accounts: actual.length };
  });
}
export function rollbackDelta(store, key) {
  return store.atomic(() => {
    const source = store.one("SELECT * FROM imports WHERE snapshot=?", key);
    check(source, "Unknown snapshot");
    const events = store.all(
      "SELECT * FROM audit WHERE seq>? ORDER BY seq",
      source.watermark,
    );
    const ids = [...new Set(events.map((e) => e.target).filter(Boolean))];
    const changed = ids.map((id) => ({
      account: store.one("SELECT * FROM accounts WHERE id=?", id),
      links: store.all("SELECT * FROM links WHERE id=?", id),
      grants: store.all("SELECT * FROM grants WHERE id=?", id),
    }));
    return {
      version: 1,
      snapshot: key,
      fingerprint: source.digest,
      watermark: source.watermark,
      events,
      changed,
    };
  });
}
if (
  process.argv[1] &&
  pathToFileURL(process.argv[1]).href === import.meta.url
) {
  process.umask(0o077);
  const [mode, dbPath, key, ...args] = process.argv.slice(2);
  check(
    ["apply", "delta", "replay"].includes(mode) && dbPath && key,
    "Usage: apply DB SNAPSHOT_KEY SNAPSHOT_JSON PROOFS_JSON HTTPS_ISSUER or delta DB SNAPSHOT_KEY OUTPUT_JSON or replay DB SNAPSHOT_KEY DELTA_JSON",
  );
  const store = openStore(dbPath);
  if (mode === "apply") {
    const [file, links, issuer] = args;
    const result = applySnapshot(
      store,
      key,
      JSON.parse(readFileSync(file)),
      JSON.parse(readFileSync(links)),
      issuer,
    );
    process.stdout.write(JSON.stringify(result) + "\n");
  } else if (mode === "replay") {
    const bundle = JSON.parse(readFileSync(args[0]));
    check(bundle.snapshot === key, "Incorrect snapshot key");
    console.log(JSON.stringify(replayDelta(store, bundle)));
  } else
    writeFileSync(args[0], JSON.stringify(rollbackDelta(store, key)), {
      mode: 0o600,
      flag: "wx",
    });
  store.db.close();
}
