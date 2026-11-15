import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { randomUUID, randomBytes, scryptSync } from "node:crypto";
import { openStore } from "../src/store.js";
import { applySnapshot } from "../migration/reconcile.js";
import {
  prepareLegacyRollback,
  runLegacyRollback,
} from "../migration/legacy-rollback.js";

const migrations = process.env.LEGACY_PORTAL_TEST_MIGRATIONS;
const database = process.env.LEGACY_PORTAL_TEST_URL;
test(
  "reverse projection through the real Portal migrations preserves records and fails closed on old authority shortcuts",
  {
    skip:
      !database || !migrations
        ? "Set a disposable loopback LEGACY_PORTAL_TEST_URL and the Portal migration directory"
        : false,
  },
  () => {
    const target = new URL(database);
    assert.ok(
      ["localhost", "127.0.0.1", "[::1]"].includes(target.hostname) &&
        target.pathname.endsWith("_test"),
    );
    const env = {
      ...process.env,
      PGHOST: target.hostname,
      PGPORT: target.port,
      PGUSER: decodeURIComponent(target.username),
      PGPASSWORD: decodeURIComponent(target.password),
      PGDATABASE: target.pathname.slice(1),
      PGOPTIONS: "-c timezone=UTC",
    };
    const query = (sql) => {
      const r = spawnSync(
        "psql",
        ["-XqAtw", "-v", "ON_ERROR_STOP=1", "-f", "-"],
        { input: sql, encoding: "utf8", env },
      );
      assert.equal(r.status, 0, r.stderr);
      return r.stdout.trim();
    };
    assert.equal(
      query("SELECT count(*) FROM pg_tables WHERE schemaname='public'"),
      "0",
    );
    const files = readdirSync(migrations)
      .filter((f) => /^\d+.*\.sql$/.test(f))
      .sort();
    assert.ok(files.some((f) => f.startsWith("019_")));
    for (const file of files)
      query(
        "BEGIN;\n" + readFileSync(join(migrations, file), "utf8") + "\nCOMMIT;",
      );
    const staff = randomUUID(),
      admin = randomUUID(),
      suspended = randomUUID(),
      held = randomUUID(),
      drone = randomUUID(),
      docsUser = randomUUID(),
      member = randomUUID(),
      memberEnabled = randomUUID(),
      memberDisabled = randomUUID(),
      unrelated = randomUUID(),
      trip = randomUUID(),
      approval = randomUUID(),
      tenant = randomUUID();
    const ids = [staff, admin, suspended, held, drone, docsUser];
    ids.forEach((id, i) =>
      query(`INSERT INTO users(id,email,password_hash,role) VALUES ('${id}','u${i}@example.test','fixture-existing-hash','${["editor", "administrator", "member", "member", "member", "member"][i]}');
    INSERT INTO identity_profiles(user_id,display_name,email_verified_at) VALUES('${id}','Fixture',now())`),
    );
    query(`INSERT INTO identity_product_access(user_id,product,role,status) VALUES('${staff}','robot','operator','active'),('${suspended}','ai','user','active'),('${drone}','drone','admin','active');
    INSERT INTO identity_drone_memberships VALUES('${drone}','${tenant}','operator','Tenant');
    INSERT INTO engineering_memberships(id,email,enabled,access_policy_evidence,approved_by) VALUES
      ('${member}','u0@example.test',true,'legacy-approval','${admin}'),
      ('${memberEnabled}','docs-user@example.test',true,'legacy-approval','${admin}'),
      ('${memberDisabled}','docs-user-disabled@example.test',false,'legacy-approval','${admin}'),
      ('${unrelated}','orphan@example.test',true,'unlinked','${admin}');
    INSERT INTO identity_engineering_links(membership_id,user_id) VALUES
      ('${member}','${staff}'),
      ('${memberEnabled}','${docsUser}'),
      ('${memberDisabled}','${docsUser}');
    INSERT INTO access_registrations(id,email,audience,display_name,state,reviewed_by) VALUES('${approval}','u0@example.test','engineering','Existing','approved','${admin}');
    INSERT INTO engineering_enrollment_accounts VALUES('${approval}','${staff}');
    INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES('session','${staff}','csrf',now()+interval '1 hour');
    INSERT INTO recovery_tokens(token_hash,user_id,expires_at) VALUES('recovery','${suspended}',now()+interval '1 hour');
    INSERT INTO content(id,kind,slug,locale,title,author_id) VALUES('${trip}','page','original','en','Original','${staff}');`);
    const snapshot = JSON.parse(
      query(
        readFileSync(
          new URL("../migration/export-portal.sql", import.meta.url),
          "utf8",
        ),
      ),
    );
    const identity = openStore(":memory:"),
      issuer = "https://auth.fixture.test/";
    try {
      const proofs = ids.map((id) => ({
        id,
        issuer,
        subject: "fixture|" + id,
        method: "dual-authentication",
        receipt: "verified-" + id,
      }));
      applySnapshot(identity, "restore-fixture", snapshot, proofs, issuer);
      const change = (id, operation) =>
        identity.change(
          admin,
          id,
          identity.one("SELECT revision FROM accounts WHERE id=?", id).revision,
          operation,
        );
      const grant = (id, product, role, status) =>
        change(id, { kind: "grant", product, role, status });
      // Canonical refusal overrides active legacy Engineering; keep the approval record itself.
      grant(staff, "internal-documents", "viewer", "revoked");
      grant(staff, "robot", "operator", "revoked");
      grant(staff, "logistics", "user", "active");
      grant(staff, "pasofi", "support", "active");
      change(suspended, { kind: "status", status: "suspended" });
      grant(drone, "drone", "viewer", "active");
      const next = identity.register(issuer, "fixture|new", "new@example.test");
      change(next.id, { kind: "status", status: "active" });
      grant(next.id, "farmer", "user", "active");
      const recovered = identity.register(
        issuer,
        "fixture|recovered",
        "recovered@example.test",
      );
      change(recovered.id, { kind: "status", status: "active" });
      grant(recovered.id, "ai", "user", "active");
      const replacement = "a freshly chosen example password",
        salt = randomBytes(16).toString("hex");
      const passwordHash =
        salt +
        ":" +
        scryptSync(replacement, salt, 64, {
          N: 32768,
          maxmem: 64 * 1024 * 1024,
        }).toString("hex");
      const recovery = [
        {
          id: recovered.id,
          issuer,
          subject: "fixture|recovered",
          receipt: "reauthenticated and recovered under fixture supervision",
          verified_at: "2026-11-14T07:10:00Z",
          password_hash: passwordHash,
        },
      ];
      const fresh = identity.register(
        issuer,
        "fixture|pending",
        "pending@example.test",
      );
      identity.invite(admin, "invitee@example.test");
      const continuity = [staff, admin, suspended, drone, docsUser].map((id) => ({
        id,
        receipt: "custodied-dual-proof-" + id,
      }));
      const plan = prepareLegacyRollback(
        identity.db,
        "restore-fixture",
        snapshot,
        proofs,
        issuer,
        continuity,
        recovery,
      );
      assert.throws(
        () =>
          prepareLegacyRollback(
            identity.db,
            "restore-fixture",
            snapshot,
            proofs,
            issuer,
            continuity,
            [{ ...recovery[0], subject: "fixture|another" }],
          ),
        /does not match/,
      );
      assert.equal(plan.version, 2);
      const obsoletePlan = {
        ...plan,
        version: 1,
        rows: plan.rows.map(({ docs_memberships, ...row }) => row),
      };
      assert.throws(
        () => runLegacyRollback(obsoletePlan, { env }),
        /Unsupported rollback plan/,
      );
      const before = JSON.stringify(snapshot);
      assert.equal(runLegacyRollback(plan, { env }).applied, false);
      assert.equal(
        query(
          "SELECT to_regclass('public.onesa_legacy_rollback_receipts') IS NULL",
        ),
        "t",
      );
      assert.equal(
        JSON.stringify(
          JSON.parse(
            query(
              readFileSync(
                new URL("../migration/export-portal.sql", import.meta.url),
                "utf8",
              ),
            ),
          ),
        ),
        before,
      );
      query(`UPDATE users SET role='hr' WHERE id='${staff}'`);
      assert.throws(
        () => runLegacyRollback(plan, { env, apply: true }),
        /inventory differs/,
      );
      assert.equal(query("SELECT count(*) FROM sessions"), "1");
      query(`UPDATE users SET role='editor' WHERE id='${staff}'`);
      const result = runLegacyRollback(plan, { env, apply: true });
      assert.ok(
        result.issues.some(
          (i) => i.reason === "portal-administrator-would-grant-global-access",
        ),
      );
      assert.ok(
        result.issues.some(
          (i) => i.reason === "drone-membership-would-exceed-product-access",
        ),
      );
      for (const id of [suspended, held, drone, next.id, fresh.id])
        assert.equal(query(`SELECT disabled FROM users WHERE id='${id}'`), "t");
      assert.equal(
        query(
          `SELECT id||'/'||role||'/'||disabled FROM users WHERE id='${staff}'`,
        ),
        staff + "/editor/false",
      );
      assert.equal(
        query(`SELECT role FROM users WHERE id='${admin}'`),
        "member",
      );
      assert.equal(
        query(
          `SELECT role||'/'||status FROM identity_product_access WHERE user_id='${staff}' AND product='farmer'`,
        ),
        "user/revoked",
      );
      assert.equal(
        query(
          `SELECT status FROM identity_product_access WHERE user_id='${staff}' AND product='robot'`,
        ),
        "revoked",
      );
      assert.equal(
        query(
          `SELECT status FROM identity_product_access WHERE user_id='${staff}' AND product='logistics'`,
        ),
        "active",
      );
      assert.equal(
        query(
          `SELECT count(*) FROM identity_product_access WHERE user_id='${staff}' AND product='pasofi' AND status='active'`,
        ),
        "0",
      );
      assert.equal(
        query(
          `SELECT status FROM identity_product_access WHERE user_id='${next.id}' AND product='farmer'`,
        ),
        "active",
      );
      assert.equal(
        query(`SELECT disabled FROM users WHERE id='${recovered.id}'`),
        "f",
      );
      assert.equal(
        query(`SELECT password_hash FROM users WHERE id='${recovered.id}'`),
        passwordHash,
      );
      assert.equal(
        query(
          `SELECT email_verified_at IS NOT NULL FROM identity_profiles WHERE user_id='${recovered.id}'`,
        ),
        "t",
      );
      assert.ok(
        !query(
          "SELECT restricted_manifest::text FROM onesa_legacy_rollback_receipts",
        ).includes(passwordHash),
      );
      assert.equal(
        query("SELECT count(*) FROM engineering_memberships WHERE enabled"),
        "1",
      );
      assert.equal(
        query(`SELECT enabled FROM engineering_memberships WHERE id='${member}'`),
        "f",
      );
      assert.equal(
        query(`SELECT enabled FROM engineering_memberships WHERE id='${memberEnabled}'`),
        "t",
      );
      assert.equal(
        query(`SELECT enabled FROM engineering_memberships WHERE id='${memberDisabled}'`),
        "f",
      );
      assert.equal(
        query(`SELECT enabled FROM engineering_memberships WHERE id='${unrelated}'`),
        "f",
      );
      assert.equal(
        query(`SELECT state FROM access_registrations WHERE id='${approval}'`),
        "approved",
      );
      assert.equal(
        query(`SELECT author_id FROM content WHERE id='${trip}'`),
        staff,
      );
      assert.equal(
        query(
          `SELECT role FROM identity_drone_memberships WHERE user_id='${drone}'`,
        ),
        "operator",
      );
      assert.equal(
        query(
          "SELECT (SELECT count(*) FROM recovery_tokens)+(SELECT count(*) FROM sessions)",
        ),
        "0",
      );
      assert.equal(
        query(`SELECT password_hash FROM users WHERE id='${staff}'`),
        "fixture-existing-hash",
      );
      assert.equal(
        query(
          `SELECT password_hash ~ '^[0-9a-f]{32}:[0-9a-f]{128}$' FROM users WHERE id='${next.id}'`,
        ),
        "t",
      );
      assert.ok(
        query(
          "SELECT restricted_manifest->'rows' FROM onesa_legacy_rollback_receipts",
        ).includes("fixture|new"),
      );
      // Replaying a verified rollback must revoke sessions/reset links again:
      // inventory and credential digests do not cover these ephemeral secrets.
      query(`INSERT INTO sessions(token_hash,user_id,csrf,expires_at)
        VALUES('stale-after-replay','${staff}','csrf',now()+interval '1 hour');
        INSERT INTO recovery_tokens(token_hash,user_id,expires_at)
        VALUES('reset-after-replay','${staff}',now()+interval '1 hour');`);
      assert.equal(query(
        "SELECT (SELECT count(*) FROM sessions)+(SELECT count(*) FROM recovery_tokens)",
      ), "2");
      runLegacyRollback(plan, { env, apply: true });
      assert.equal(query(
        "SELECT (SELECT count(*) FROM sessions)+(SELECT count(*) FROM recovery_tokens)",
      ), "0", "idempotent recovery must not leave a usable old credential");
      assert.equal(
        query("SELECT COUNT(*) FROM onesa_legacy_rollback_receipts"),
        "1",
      );
      query(
        `UPDATE users SET password_hash='outside-change' WHERE id='${staff}'`,
      );
      assert.throws(
        () => runLegacyRollback(plan, { env, apply: true }),
        /diverged/,
      );
      query(
        `UPDATE users SET password_hash='fixture-existing-hash' WHERE id='${staff}'`,
      );
      query(
        `UPDATE identity_product_access SET status='active' WHERE user_id='${staff}' AND product='robot'`,
      );
      assert.throws(
        () => runLegacyRollback(plan, { env, apply: true }),
        /diverged/,
      );
      assert.throws(
        () =>
          prepareLegacyRollback(
            identity.db,
            "restore-fixture",
            { ...snapshot, grants: [] },
            proofs,
            issuer,
            continuity,
          ),
        /does not match/,
      );
    } finally {
      identity.db.close();
    }
  },
);
