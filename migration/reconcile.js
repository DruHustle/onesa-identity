import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { openStore, products, configurableAdminRoles, digest, uuid } from "../src/store.js";

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

function captureBaseline(store) {
  store.db.exec(`CREATE TABLE migration_baseline(
    kind TEXT NOT NULL, id TEXT NOT NULL, record TEXT NOT NULL,
    PRIMARY KEY(kind,id)
  )`);
  const inventories = [
    ["account", store.all("SELECT * FROM accounts ORDER BY id"), (row) => row.id],
    ["grant", store.all("SELECT * FROM grants ORDER BY id,product"), (row) => row.id + "/" + row.product],
    ["product-administrator", store.all("SELECT * FROM product_administrators ORDER BY id,product"), (row) => row.id + "/" + row.product],
    ["link", store.all("SELECT * FROM links ORDER BY issuer,subject"), (row) => digest(row.issuer + "\\0" + row.subject)],
  ];
  for (const [kind, rows, key] of inventories)
    for (const row of rows)
      store.run(
        "INSERT INTO migration_baseline VALUES(?,?,?)",
        kind,
        key(row),
        JSON.stringify(canonical(row)),
      );
}

// Compare the restored cutover baseline with an inventory captured inside
// the original import transaction. During an idempotent replay, accounts
// named by the journal are checked against the delta below; every other
// account, grant and provider link must still equal the frozen baseline.
function verifyBaselineIntegrity(store, changedIds = new Set()) {
  check(
    store.one("SELECT 1 FROM sqlite_master WHERE type='table' AND name='migration_baseline'"),
    "Recovery target has no cutover integrity inventory; rebuild it from the protected source snapshot",
  );
  const inventories = [
    {
      kind: "account",
      rows: () => store.all("SELECT * FROM accounts ORDER BY id"),
      key: (row) => row.id,
      owner: (row) => row.id,
    },
    {
      kind: "grant",
      rows: () => store.all("SELECT * FROM grants ORDER BY id,product"),
      key: (row) => row.id + "/" + row.product,
      owner: (row) => row.id,
    },
    {
      kind: "product-administrator",
      rows: () => store.all("SELECT * FROM product_administrators ORDER BY id,product"),
      key: (row) => row.id + "/" + row.product,
      owner: (row) => row.id,
    },
    {
      kind: "link",
      rows: () => store.all("SELECT * FROM links ORDER BY issuer,subject"),
      key: (row) => digest(row.issuer + "\\0" + row.subject),
      owner: (row) => row.id,
    },
  ];
  for (const inventory of inventories) {
    const expected = store
      .all("SELECT id,record FROM migration_baseline WHERE kind=?", inventory.kind)
      .filter((entry) => !changedIds.has(JSON.parse(entry.record).id))
      .map((entry) => ({
        id: entry.id,
        record: JSON.stringify(canonical(JSON.parse(entry.record))),
      }))
      .sort((a, b) => a.id.localeCompare(b.id));
    const actual = inventory
      .rows()
      .filter((row) => !changedIds.has(inventory.owner(row)))
      .map((row) => ({
        id: inventory.key(row),
        record: JSON.stringify(canonical(row)),
      }))
      .sort((a, b) => a.id.localeCompare(b.id));
    check(
      JSON.stringify(actual) === JSON.stringify(expected),
      "Recovery target has divergent " +
        (inventory.kind === "link"
          ? "provider links"
          : "baseline " + inventory.kind + " inventory"),
    );
  }
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
      check(
        store.one("SELECT 1 FROM sqlite_master WHERE type='table' AND name='migration_baseline'"),
        "Cutover predates recovery integrity inventory; rebuild it from the protected source snapshot",
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
      ids = new Set(),
      explicitPortalGrants = new Set(
        snapshot.grants
          .filter((g) => g?.product === "portal")
          .map((g) => g.id),
      );
    let count = 0;
    for (const u of snapshot.accounts) {
      // A legacy snapshot can contain multiple accounts sharing a case-variant
      // address. Do not silently import ambiguous contact ownership or an
      // address that the live registration path would later refuse.
      const email = typeof u.email === "string" ? u.email.trim().toLowerCase() : "";
      // Older Portal rows used "admin"; keep the grant while migrating to the
      // canonical Onesa role name.
      const portalRole = u.role === "admin" ? "administrator" : u.role;
      check(
        uuid(u.id) &&
          !ids.has(u.id) &&
          email.length <= 254 &&
          /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) &&
          !store.one("SELECT 1 FROM accounts WHERE email=? COLLATE NOCASE", email) &&
          ["active", "suspended"].includes(u.status),
        "Conflicting account snapshot",
      );
      check(
        portalRole === "member" || products.portal.includes(portalRole),
        "Unknown Portal role",
      );
      ids.add(u.id);
      store.run(
        "INSERT INTO accounts(id,email,status) VALUES(?,?,?)",
        u.id,
        email,
        u.status,
      );
      if (u.role !== "member" && !explicitPortalGrants.has(u.id))
        store.run(
          "INSERT INTO grants VALUES(?,?,?,?)",
          u.id,
          "portal",
          portalRole,
          ["owner", "administrator"].includes(portalRole) ? "pending" : "active",
        );
      // Old global-admin and implicit Farmer rights require an explicit resource-owner disposition.
      if (portalRole !== "member")
        pending.push({ kind: "legacy-implicit-access", id: u.id });
      if (["owner", "administrator"].includes(portalRole))
        pending.push({ kind: "review-product-grant", id: u.id + "/portal" });
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
    for (const sourceGrant of snapshot.grants) {
      // The canonical role changed from "admin" to "administrator". Normalize
      // the imported row but retain the source snapshot verbatim for recovery.
      const g =
        sourceGrant?.role === "admin"
          ? { ...sourceGrant, role: "administrator" }
          : sourceGrant;
      if (
        (g.product === "pasofi" && g.role !== "customer") ||
        g.product === "internal-documents" ||
        g.product === "identity"
      ) {
        // A Portal export cannot prove staff duties, Identity administration,
        // or access to separately owned document domains.
        pending.push({ kind: "review-product-grant", id: g.id + "/" + g.product });
      } else if (
        (g.product === "portal" && ["owner", "administrator"].includes(g.role)) ||
        (configurableAdminRoles.has(g.product) && g.role === "administrator")
      ) {
        // Legacy elevated roles need an independent decision before issuance.
        pending.push({ kind: "review-product-grant", id: g.id + "/" + g.product });
        grant({ ...g, status: g.status === "active" ? "pending" : g.status });
      } else {
        grant(g);
      }
    }
    // The Portal schema enforces one Engineering membership per Identity
    // account. Reject a corrupted or ambiguous export instead of allowing
    // duplicate ownership to alter the account-level product entitlement.
    const engineeringAccess = new Map();
    for (const d of snapshot.docs) {
      check(
        uuid(d.membership_id) && typeof d.enabled === "boolean",
        "Invalid document membership",
      );
      if (d.id !== null && d.id !== undefined) {
        check(
          ids.has(d.id) && !engineeringAccess.has(d.id),
          "Duplicate Engineering membership owner",
        );
        engineeringAccess.set(d.id, d.enabled);
      } else {
        pending.push({
          kind: "unlinked-document-membership",
          id: d.membership_id,
        });
      }
    }
    for (const [id, enabled] of engineeringAccess) {
      // An explicit managed grant (including a pending or revoked decision)
      // takes precedence over the entitlement inferred from legacy membership.
      if (
        !store.one(
          "SELECT 1 FROM grants WHERE id=? AND product='engineering-documents'",
          id,
        )
      )
        grant({
          id,
          product: "engineering-documents",
          role: "viewer",
          status: enabled ? "active" : "revoked",
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
              ? ids.has(row.user_id) && uuid(row.tenant_id) && products.drone.includes(row.role)
              : uuid(id),
          "Invalid source reference or product role",
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
    captureBaseline(store);
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
// The live proof importer records a journal event and clears the corresponding reminder.
function clearResolvedProofs(store) {
  store.run(`DELETE FROM migration_discrepancies
    WHERE kind='provider-ownership-proof' AND EXISTS (
      SELECT 1 FROM audit JOIN links ON links.id=audit.target
      WHERE audit.action='link-provider' AND audit.target=migration_discrepancies.id
        AND links.issuer=json_extract(audit.detail,'$.issuer')
    )`);
}

// Recovery must not silently preserve an extra provider identity or stale
// ownership receipt from the restored target. A successful replay must have
// precisely the provider links recorded by the frozen source.
function verifyRecoveredLinks(store, changed) {
  const links = store.all(
    "SELECT * FROM links WHERE id=? ORDER BY issuer,subject",
    changed.account.id,
  );
  const expectedLinks = [...changed.links].sort(
    (a, b) => a.issuer.localeCompare(b.issuer) || a.subject.localeCompare(b.subject),
  );
  check(
    JSON.stringify(links) === JSON.stringify(expectedLinks),
    "Recovery target has divergent provider links",
  );
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
    check(bundle.version === 2 && typeof bundle.audit_base_hash === "string",
      "Unsupported or incomplete recovery audit bundle");
    store.verifyAuditEvents(bundle.events, bundle.audit_base_hash);
    const existing = store.all(
      "SELECT * FROM audit WHERE seq>? ORDER BY seq",
      source.watermark,
    );
    verifyBaselineIntegrity(store, existing.length ? new Set(actual) : new Set());
    if (existing.length) {
      const eventContent = (rows) => rows.map(({seq,at,actor,action,target,detail}) =>
        ({seq,at,actor,action,target,detail}));
      check(
        JSON.stringify(eventContent(existing)) === JSON.stringify(eventContent(bundle.events)),
        "Recovery target has divergent writes",
      );
      store.verifyAuditChain();
      // An already replayed journal must not preserve browser credentials or
      // unused invitations that might have been restored from an old backup.
      check(
        !store.one("SELECT 1 FROM accounts GROUP BY email COLLATE NOCASE HAVING count(*)>1 LIMIT 1"),
        "Conflicting recovered contact ownership",
      );
      // A matching audit sequence alone does not prove the restored identity
      // state is intact: direct database drift could change grants or links
      // without appending a journal event.
      for (const x of bundle.changed) {
        check(
          JSON.stringify(store.one("SELECT * FROM accounts WHERE id=?", x.account.id)) ===
            JSON.stringify(x.account),
          "Recovery target has divergent account state",
        );
        verifyRecoveredLinks(store, x);
        const grants = store.all(
          "SELECT * FROM grants WHERE id=? ORDER BY product",
          x.account.id,
        );
        const expectedGrants = [...x.grants].sort(
          (a, b) => a.product.localeCompare(b.product),
        );
        check(JSON.stringify(grants) === JSON.stringify(expectedGrants),
          "Recovery target has divergent grants");
        const administrators = store.all(
          "SELECT * FROM product_administrators WHERE id=? ORDER BY product",
          x.account.id,
        );
        const expectedAdministrators = [...(x.product_administrators || [])].sort(
          (a, b) => a.product.localeCompare(b.product),
        );
        check(JSON.stringify(administrators) === JSON.stringify(expectedAdministrators),
          "Recovery target has divergent product administrators");
      }
      clearResolvedProofs(store);
      store.run("DELETE FROM sessions");
      store.run("DELETE FROM invites");
      store.db.exec("DELETE FROM challenges; DELETE FROM registration_resumes");
      return { replay: true, accounts: actual.length };
    }
    for (const x of bundle.changed) {
      const a = x.account;
      check(
        uuid(a.id) &&
          typeof a.email === "string" &&
          a.email.length <= 254 &&
          /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(a.email) &&
          a.email === a.email.trim().toLowerCase() &&
          ["pending", "active", "suspended", "rejected"].includes(a.status) &&
          Number.isInteger(a.revision) &&
          a.revision >= 1,
        "Invalid recovered account state",
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
      store.run("DELETE FROM product_administrators WHERE id=?", a.id);
      for (const administrator of x.product_administrators || []) {
        check(
          administrator.id === a.id &&
            Object.hasOwn(products, administrator.product) &&
            administrator.status === "active",
          "Invalid recovered product administrator",
        );
        store.run(
          "INSERT INTO product_administrators(id,product,status,revision) VALUES(?,?,?,?)",
          administrator.id,
          administrator.product,
          administrator.status,
          administrator.revision,
        );
      }
    }
    // Initial replay must also detect extra or altered provider links left
    // behind by a restored database. Never keep unverified login ownership.
    for (const x of bundle.changed) verifyRecoveredLinks(store, x);
    // The baseline and the delta must retain unique canonical contacts, even
    // when a protected recovery bundle is corrupted or supplied out of order.
    // Check the final transactional state so two legitimate email swaps are
    // not rejected merely because of the order of account upserts.
    check(
      !store.one("SELECT 1 FROM accounts GROUP BY email COLLATE NOCASE HAVING count(*)>1 LIMIT 1"),
      "Conflicting recovered contact ownership",
    );
    for (const e of bundle.events) store.appendAuditEvent(e);
    // Verify the complete restored chain before the recovery transaction can commit.
    store.verifyAuditChain();
    clearResolvedProofs(store);
    store.run("DELETE FROM sessions");
    store.run("DELETE FROM invites");
    store.db.exec("DELETE FROM challenges; DELETE FROM registration_resumes");
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
      product_administrators: store.all("SELECT * FROM product_administrators WHERE id=?", id),
    }));
    return {
      version: 2,
      snapshot: key,
      fingerprint: source.digest,
      watermark: source.watermark,
      audit_base_hash: store.one("SELECT entry_hash FROM audit WHERE seq=?", source.watermark)?.entry_hash ?? "",
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
