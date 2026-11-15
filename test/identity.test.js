import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { openStore, digest, products } from "../src/store.js";
import { createApp } from "../src/web.js";
import { configuration } from "../src/server.js";
import {
  applySnapshot,
  replayDelta,
  rollbackDelta,
} from "../migration/reconcile.js";
import action from "../auth0/post-login.cjs";
import stepUp from "../auth0/step-up.cjs";
import { applyProofs } from "../migration/link-proof.js";
import { bootstrapIdentityAdmin } from "../migration/identity-admin.js";
test("audit chain upgrades legacy rows, blocks mutation and detects tampering", () => {
  const directory = mkdtempSync(join(tmpdir(), "onesa-audit-"));
  const file = join(directory, "identity.sqlite");
  const legacy = new DatabaseSync(file);
  legacy.exec(`
    CREATE TABLE audit(
      seq INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL,
      action TEXT NOT NULL, target TEXT, detail TEXT NOT NULL
    );
    INSERT INTO audit VALUES(7,1700000000000,'legacy','migration',NULL,'{"legacy":true}');
  `);
  legacy.close();

  const store = openStore(file);
  try {
    const upgraded = store.verifyAuditChain();
    assert.equal(upgraded.entries, 1);
    assert.match(upgraded.head, /^[0-9a-f]{64}$/);

    const user = store.register(
      "https://auth.onesa.test/",
      "audit-chain-user",
      "audit-chain@onesa.test",
    );
    store.invite(user.id, "audit-invite@onesa.test");
    assert.equal(store.verifyAuditChain().entries, 3);

    assert.throws(
      () => store.run("UPDATE audit SET detail=? WHERE seq=7", "{}"),
      /append-only/,
    );
    assert.throws(
      () => store.run("DELETE FROM audit WHERE seq=7"),
      /append-only/,
    );

    // Simulate an out-of-band database operator bypassing the application
    // guard. The next integrity check must detect the altered historical row.
    store.db.exec("DROP TRIGGER audit_append_only_update");
    store.run("UPDATE audit SET detail=? WHERE seq=7", '{"tampered":true}');
    assert.throws(
      () => store.verifyAuditChain(),
      /Identity audit integrity failure at sequence 7/,
    );
  } finally {
    store.db.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

const env = {
  origin: "https://identity-admin.onesa.test",
  issuer: "https://auth.onesa.test/",
  clientId: "account-ui",
  policyKey: "controlled-test-key",
  resources: new Map([
    [
      "https://api.docs.onesa.eu",
      { product: "internal-documents", clients: ["docs-web"] },
    ],
    [
      "https://api.farmer.onesa.eu",
      { product: "farmer", clients: ["farmer-web"] },
    ],
  ]),
};

test("resource registry rejects missing, non-HTTPS and ambiguous audiences", () => {
  const base = {
    OIDC_ISSUER: env.issuer,
    IDENTITY_ORIGIN: env.origin,
    OIDC_CLIENT_ID: env.clientId,
    OIDC_CLIENT_SECRET: "controlled-client-secret",
    ACTION_POLICY_KEY: "x".repeat(32),
  };
  const valid = {
    "https://api.docs.onesa.eu": {
      product: "internal-documents",
      clients: ["docs-web"],
    },
  };
  assert.equal(
    configuration({
      ...base,
      RESOURCE_CLIENTS_JSON: JSON.stringify(valid),
    }).resources.get("https://api.docs.onesa.eu").product,
    "internal-documents",
  );
  for (const audience of [
    "",
    "not-a-url",
    "http://api.docs.onesa.eu",
    "https://user:pass@api.docs.onesa.eu",
    "https://api.docs.onesa.eu?forward=1",
    "https://api.docs.onesa.eu#fragment",
  ]) {
    assert.throws(
      () =>
        configuration({
          ...base,
          RESOURCE_CLIENTS_JSON: JSON.stringify({
            [audience]: { product: "farmer", clients: ["farmer-web"] },
          }),
        }),
      /Invalid resource registry/,
      audience,
    );
  }
  assert.throws(
    () =>
      configuration({
        ...base,
        RESOURCE_CLIENTS_JSON: JSON.stringify({
          "https://api.docs.onesa.eu": {
            product: "farmer",
            clients: ["farmer-web", "farmer-web"],
          },
        }),
      }),
    /Invalid resource registry/,
  );
});

async function fixture(t, overrides = {}) {
  const store = openStore(":memory:");
  t.after(() => store.db.close());
  let factor = Date.now(),
    subject = "oidc|identity-admin";
  const defaultRedeem = async () => ({
    iss: env.issuer,
    sub: subject,
    email_verified: true,
    email: subject.split("|")[1] + "@onesa.test",
    "https://onesa.eu/claims/mfa_time": Math.floor(factor / 1000),
  });
  let redeem = defaultRedeem;
  const fake = {
    authorize: async (p) => env.issuer + "authorize?" + new URLSearchParams(p),
    redeem: (...args) => redeem(...args),
  };
  const app = createApp(store, { ...env, ...overrides }, fake);
  const call = (url, method = "GET", body, headers = {}) =>
    app(new Request(env.origin + url, { method, headers, body }));
  async function login(name, returnTo = "/admin", factorTime = Date.now()) {
    subject = "oidc|" + name;
    factor = factorTime;
    const start = await call("/login?return=" + encodeURIComponent(returnTo)),
      params = new URL(start.headers.get("location")).searchParams,
      flow = start.headers.getSetCookie()[0].split(";")[0];
    assert.equal(params.get("code_challenge_method"), "S256");
    assert.ok(params.get("nonce"));
    assert.equal(params.get("redirect_uri"), env.origin + "/callback");
    const response = await call(
      "/callback?code=controlled&state=" + params.get("state"),
      "GET",
      undefined,
      { cookie: flow },
    );
    assert.equal(response.status, 303);
    return {
      cookie: response.headers.getSetCookie()[0].split(";")[0],
      url: response.headers.get("location"),
    };
  }
  const admin = store.register(
    env.issuer,
    "oidc|identity-admin",
    "identity-admin@onesa.test",
  );
  store.change("bootstrap", admin.id, 1, { kind: "status", status: "active" });
  store.change("bootstrap", admin.id, 2, {
    kind: "grant",
    product: "identity",
    role: "admin",
    status: "active",
  });
  return { store, call, login, admin, setRedeem: (next) => { redeem = next ?? defaultRedeem; } };
}
test("Identity UI changes grant, revocation and suspension at next issuance; resources scoped to client/audience", async (t) => {
  const { store, call, login } = await fixture(t),
    a = await login("identity-admin"),
    user = store.register(env.issuer, "auth0|u", "operator@onesa.test");
  assert.equal(a.url, "/admin");
  const adminPage = await call("/admin", "GET", undefined, { cookie: a.cookie });
  // Chromium sends Origin: null for same-origin forms under no-referrer.
  assert.equal(adminPage.headers.get("referrer-policy"), "same-origin");
  const html = await adminPage.text();
  assert.match(html, /Identity administration/);
  const csrf = html.match(/name="csrf" value="([^"]+)"/)[1];
  const mutate = (revision, kind, status, assignment) =>
    call(
      "/admin/change",
      "POST",
      new URLSearchParams({
        id: user.id,
        revision: String(revision),
        csrf,
        kind,
        status,
        assignment,
      }),
      { cookie: a.cookie, origin: env.origin },
    );
  const decision = (
    client = "docs-web",
    audience = "https://api.docs.onesa.eu",
  ) =>
    call(
      "/internal/decision",
      "POST",
      JSON.stringify({ subject: "auth0|u", audience, client }),
      { authorization: "Bearer " + env.policyKey },
    );
  assert.equal((await decision()).status, 403);
  assert.equal((await mutate(1, "status", "active", "")).status, 303);
  assert.equal(
    (await mutate(2, "grant", "active", "engineering-documents/editor")).status,
    303,
  );
  assert.deepEqual(await (await decision()).json(), {
    user_id: user.id,
    product: "engineering-documents",
    roles: ["editor"],
  });
  assert.equal((await decision("farmer-web")).status, 403);
  assert.equal(
    (await decision("farmer-web", "https://api.farmer.onesa.eu")).status,
    403,
  );
  assert.equal(
    (await mutate(2, "grant", "revoked", "engineering-documents/editor"))
      .status,
    409,
  );
  assert.equal(
    (await mutate(3, "grant", "revoked", "engineering-documents/editor"))
      .status,
    303,
  );
  assert.equal((await decision()).status, 403);
  assert.equal((await mutate(4, "grant", "active", "engineering-documents/editor")).status, 303);
  assert.equal((await mutate(5, "grant", "active", "internal-documents/viewer")).status, 303);
  assert.deepEqual(await (await decision()).json(), {user_id:user.id,product:"internal-documents",roles:["viewer"]});
  assert.equal((await mutate(6, "grant", "revoked", "internal-documents/viewer")).status, 303);
  assert.equal((await decision()).status, 403);
  assert.equal((await mutate(7, "status", "suspended", "")).status, 303);
  assert.equal((await decision(env.clientId, "")).status, 403);
});
test("policy decisions reject active grants whose role is not allowed for that product", async (t) => {
  const { store, call } = await fixture(t);
  const user = store.register(env.issuer, "fixture|malformed-farmer-role", "malformed-farmer@onesa.test");
  store.change("test", user.id, 1, { kind: "status", status: "active" });
  // Simulate a malformed legacy/manual row that bypassed store.change().
  store.run(
    "INSERT INTO grants VALUES(?,?,?,?)",
    user.id,
    "farmer",
    "admin",
    "active",
  );
  const response = await call(
    "/internal/decision",
    "POST",
    JSON.stringify({
      subject: "fixture|malformed-farmer-role",
      audience: "https://api.farmer.onesa.eu",
      client: "farmer-web",
    }),
    { authorization: "Bearer " + env.policyKey },
  );
  assert.equal(response.status, 403);
});

test("Portal administrator has no Identity access; stale MFA and forged form denied", async (t) => {
  const { store, call, login } = await fixture(t),
    a = store.register(env.issuer, "oidc|portal", "portal@onesa.test");
  store.change("test", a.id, 1, { kind: "status", status: "active" });
  store.change("test", a.id, 2, {
    kind: "grant",
    product: "portal",
    role: "administrator",
    status: "active",
  });
  const p = await login("portal");
  assert.equal(
    (await call("/admin", "GET", undefined, { cookie: p.cookie })).status,
    403,
  );
  assert.equal(store.activeGrant(a.id, "engineering-documents"), undefined);
  const stale = await login("identity-admin", "/admin", Date.now() - 600000);
  assert.match(
    await (
      await call("/admin", "GET", undefined, { cookie: stale.cookie })
    ).text(),
    /fresh MFA/,
  );
  const aSession = await login("identity-admin");
  assert.equal(
    (
      await call("/admin/invite", "POST", "email=other%40onesa.test", {
        cookie: aSession.cookie,
        origin: "https://other.test",
      })
    ).status,
    403,
  );
});
test("Identity administration rejects an active grant with any role other than admin", async (t) => {
  const { store, call } = await fixture(t);
  const user = store.register(env.issuer, "fixture|malformed-identity-role", "malformed-role@onesa.test");
  store.change("test", user.id, 1, { kind: "status", status: "active" });
  // The SQLite table intentionally cannot encode the JavaScript product-role
  // catalog as a CHECK constraint. Simulate a corrupted or legacy row at the
  // authorization boundary and prove it cannot confer administrator access.
  store.run(
    "INSERT INTO grants VALUES(?,?,?,?)",
    user.id,
    "identity",
    "viewer",
    "active",
  );
  const token = "malformed-identity-role-session";
  store.run(
    "INSERT INTO sessions VALUES(?,?,?,?,?)",
    digest(token),
    user.id,
    "csrf",
    Date.now() + 1800000,
    Date.now(),
  );
  const response = await call("/admin", "GET", undefined, {
    cookie: "__Host-onesa-session=" + token,
  });
  assert.equal(response.status, 403);
  assert.match(await response.text(), /Identity administrator required/);
});

test("administrators cannot invite an address already owned by a pending or suspended account", async (t) => {
  const { store, call, login } = await fixture(t);
  const pending = store.register(env.issuer, "fixture|pending-existing", "pending-existing@onesa.test");
  const suspended = store.register(env.issuer, "fixture|suspended-existing", "suspended-existing@onesa.test");
  store.change("test", suspended.id, 1, { kind: "status", status: "suspended" });
  const admin = await login("identity-admin");
  const adminPage = await call("/admin", "GET", undefined, { cookie: admin.cookie });
  const csrf = (await adminPage.text()).match(/name="csrf" value="([^"]+)"/)[1];

  for (const email of ["PENDING-EXISTING@onesa.test", "SUSPENDED-EXISTING@onesa.test"]) {
    const response = await call(
      "/admin/invite",
      "POST",
      new URLSearchParams({ csrf, email }),
      { cookie: admin.cookie, origin: env.origin },
    );
    assert.equal(response.status, 409);
    assert.match(await response.text(), /An account already exists for this address/);
  }
  assert.equal(store.one("SELECT count(*) AS n FROM invites").n, 0);
  assert.equal(store.one("SELECT count(*) AS n FROM audit WHERE action='invite'").n, 0);
  assert.equal(store.lookup(env.issuer, "fixture|pending-existing").id, pending.id);
  assert.equal(store.lookup(env.issuer, "fixture|suspended-existing").status, "suspended");
});

test("Identity administrator bootstrap requires the configured issuer and ignores stale suspended-admin grants", () => {
  const store = openStore(":memory:");
  try {
    const foreign = store.register(
      "https://attacker.example/",
      "attacker|admin",
      "foreign@onesa.test",
    );
    assert.throws(
      () => bootstrapIdentityAdmin(store, env.issuer, foreign.id, "owner-approval"),
      /configured issuer/,
    );

    const previous = store.register(env.issuer, "auth0|previous-admin", "previous@onesa.test");
    store.change("test", previous.id, 1, { kind: "status", status: "active" });
    store.change("test", previous.id, 2, {
      kind: "grant", product: "identity", role: "admin", status: "active",
    });
    store.change("test", previous.id, 3, { kind: "status", status: "suspended" });

    const malformed = store.register(env.issuer, "auth0|malformed-role", "malformed-role@onesa.test");
    store.change("test", malformed.id, 1, { kind: "status", status: "active" });
    // A non-admin Identity grant must not block recovery bootstrap.
    store.run("INSERT INTO grants VALUES(?,?,?,?)", malformed.id, "identity", "viewer", "active");

    const replacement = store.register(env.issuer, "auth0|replacement-admin", "replacement@onesa.test");
    bootstrapIdentityAdmin(store, env.issuer, replacement.id, "independent-owner-approval");
    assert.equal(store.lookup(env.issuer, "auth0|replacement-admin").status, "active");
    assert.equal(store.activeGrant(replacement.id, "identity").role, "admin");
    assert.equal(store.activeGrant(previous.id, "identity"), undefined);
    assert.throws(
      () => bootstrapIdentityAdmin(store, env.issuer, foreign.id, "second-approval"),
      /active Identity administrator already exists/,
    );
  } finally {
    store.db.close();
  }
});

test("link-proof CLI creates a private SQLite database when run on a protected host", () => {
  const directory = mkdtempSync(join(tmpdir(), "onesa-identity-link-proof-"));
  try {
    const database = join(directory, "identity.sqlite");
    const manifest = join(directory, "proofs.json");
    writeFileSync(manifest, "[]", { mode: 0o600 });
    const script = fileURLToPath(new URL("../migration/link-proof.js", import.meta.url));
    const result = spawnSync(process.execPath, [script, database, env.issuer, manifest], {
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(statSync(database).mode & 0o777, 0o600);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("provider subject proof and one-use invitations preserve account separation", async (t) => {
  const { store } = await fixture(t),
    token = store.invite("test", "new@onesa.test");
  assert.throws(() =>
    store.register(env.issuer, "other", "unknown@onesa.test", token),
  );
  const a = store.register(env.issuer, "new", "new@onesa.test", token);
  assert.equal(a.status, "pending");
  assert.equal(
    store.one("SELECT 1 FROM invites WHERE hash=?", digest(token)),
    undefined,
  );
  assert.throws(
    () => store.register(env.issuer, "different", "NEW@onesa.test"),
    /ownership/,
  );
  assert.equal(store.lookup(env.issuer, "different"), undefined);
});
test("state is single-use and cross-origin return request resolves to account", async (t) => {
  const { call, login } = await fixture(t);
  const r = await login("someone", "https://outside.test/");
  assert.equal(r.url, "/account");
  const response = await call("/callback?code=random&state=absent");
  assert.equal(response.status, 400);
});
test("schema-based import is idempotent; stale snapshot cannot erase post-cutover changes; rollback keeps new memberships and suspensions", () => {
  const x = openStore(":memory:"),
    y = openStore(":memory:");
  try {
    const owner = randomUUID(),
      second = randomUUID(),
      membership_id = randomUUID();
    const snapshot = {
      version: 1,
      accounts: [
        {
          id: owner,
          email: "owner@onesa.test",
          status: "active",
          role: "owner",
        },
        {
          id: second,
          email: "second@onesa.test",
          status: "active",
          role: "member",
        },
      ],
      grants: [
        { id: second, product: "farmer", role: "user", status: "active" },
        { id: owner, product: "pasofi", role: "admin", status: "active" },
      ],
      docs: [{ id: second, membership_id, enabled: true }],
      drone_memberships: [],
      registrations: [],
    };
    const proofs = [
      {
        id: second,
        issuer: env.issuer,
        subject: "provider|second",
        method: "dual-authentication",
        receipt: "verified-receipt-1",
      },
    ];
    for (const s of [x, y]) {
      const r = applySnapshot(s, "pilot", snapshot, proofs, env.issuer);
      assert.equal(r.accounts, 2);
      assert.equal(s.activeGrant(owner, "identity"), undefined);
      assert.equal(s.activeGrant(owner, "pasofi"), undefined);
      assert.equal(s.activeGrant(second, "internal-documents"), undefined);
      assert.equal(s.activeGrant(second, "engineering-documents").role, "viewer");
      assert.equal(
        s.one("SELECT count(*) AS n FROM legacy_inventory WHERE kind='docs'").n,
        1,
      );
      assert.ok(r.pending.some((x) => x.kind === "review-product-grant"));
      assert.ok(r.pending.some((x) => x.kind === "provider-ownership-proof"));
    }
    x.change("test", second, 1, { kind: "status", status: "suspended" });
    const newUser = x.register(env.issuer, "provider|new", "new@onesa.test");
    x.change("test", newUser.id, 1, { kind: "status", status: "active" });
    x.change("test", newUser.id, 2, {
      kind: "grant",
      product: "farmer",
      role: "user",
      status: "active",
    });
    assert.equal(
      applySnapshot(x, "pilot", snapshot, proofs, env.issuer).replay,
      true,
    );
    assert.equal(x.activeGrant(second, "farmer"), undefined);
    assert.throws(
      () => applySnapshot(x, "pilot", snapshot, [], env.issuer),
      /reused/,
    );
    applyProofs(x, env.issuer, [{
      id: owner, issuer: env.issuer, subject: "provider|owner",
      method: "dual-authentication", receipt: "verified-after-cutover",
    }]);
    const delta = rollbackDelta(x, "pilot");
    replayDelta(y, delta);
    assert.equal(y.activeGrant(second, "farmer"), undefined);
    assert.equal(y.activeGrant(newUser.id, "farmer").role, "user");
    assert.equal(y.lookup(env.issuer, "provider|new").id, newUser.id);
    const pending = (store) => applySnapshot(store, "pilot", snapshot, proofs, env.issuer).pending;
    assert.deepEqual(pending(y), pending(x));
    // A target replayed with the earlier release may still have the old proof reminder.
    y.run("INSERT INTO migration_discrepancies VALUES('provider-ownership-proof',?)", owner);
    assert.equal(replayDelta(y, delta).replay, true);
    assert.deepEqual(pending(y), pending(x));
    assert.ok(pending(y).some(row => row.kind === "review-product-grant"));
  } finally {
    x.db.close();
    y.db.close();
  }
});
test("legacy import preserves explicit Portal and Engineering grant decisions over inferred memberships", () => {
  const store = openStore(":memory:");
  try {
    const portalUser = randomUUID(),
      docsUser = randomUUID(),
      identityAdmin = randomUUID(),
      globalAdmin = randomUUID(),
      explicitAdmin = randomUUID();
    const snapshot = {
      version: 1,
      accounts: [
        { id: portalUser, email: "portal@onesa.test", status: "active", role: "owner" },
        { id: docsUser, email: "docs@onesa.test", status: "active", role: "member" },
        { id: identityAdmin, email: "identity-admin@onesa.test", status: "active", role: "member" },
        { id: globalAdmin, email: "global-admin@onesa.test", status: "active", role: "administrator" },
        { id: explicitAdmin, email: "explicit-admin@onesa.test", status: "active", role: "member" },
      ],
      grants: [
        { id: portalUser, product: "portal", role: "editor", status: "active" },
        { id: docsUser, product: "engineering-documents", role: "viewer", status: "revoked" },
        { id: identityAdmin, product: "identity", role: "admin", status: "active" },
        { id: explicitAdmin, product: "portal", role: "administrator", status: "active" },
      ],
      docs: [
        { id: docsUser, membership_id: randomUUID(), enabled: true },
      ],
      registrations: [],
      drone_memberships: [],
    };
    applySnapshot(store, "explicit-grants", snapshot, [], env.issuer);
    assert.equal(store.activeGrant(portalUser, "portal").role, "editor");
    assert.equal(
      store.one("SELECT role,status FROM grants WHERE id=? AND product='portal'", portalUser).role,
      "editor",
    );
    assert.equal(
      store.one("SELECT status FROM grants WHERE id=? AND product='engineering-documents'", docsUser).status,
      "revoked",
    );
    assert.equal(store.activeGrant(docsUser, "engineering-documents"), undefined);
    assert.equal(store.activeGrant(identityAdmin, "identity"), undefined);
    assert.equal(store.activeGrant(globalAdmin, "portal"), undefined);
    assert.equal(
      store.one("SELECT status FROM grants WHERE id=? AND product='portal'", globalAdmin).status,
      "pending",
    );
    assert.equal(store.activeGrant(explicitAdmin, "portal"), undefined);
    assert.equal(
      store.one("SELECT status FROM grants WHERE id=? AND product='portal'", explicitAdmin).status,
      "pending",
    );
    const discrepancies = store.all("SELECT kind,id FROM migration_discrepancies");
    assert.ok(
      discrepancies.some(
        (row) => row.kind === "review-product-grant" && row.id === identityAdmin + "/identity",
      ),
    );
    assert.ok(
      discrepancies.some(
        (row) => row.kind === "review-product-grant" && row.id === explicitAdmin + "/portal",
      ),
    );
    assert.ok(
      discrepancies.some(
        (row) => row.kind === "legacy-implicit-access" && row.id === globalAdmin,
      ),
    );
  } finally {
    store.db.close();
  }
});

test("Auth0 step-up requires MFA only for explicit browser step-up, never refresh-token exchange", async () => {
  const requested = "http://schemas.openid.net/pape/policies/2007/06/multi-factor";
  const calls = [];
  const api = { multifactor: { enable: (...args) => calls.push(args) } };
  await stepUp.onExecutePostLogin(
    { transaction: { protocol: "oidc-basic-profile", acr_values: [requested] } },
    api,
  );
  assert.deepEqual(calls, [["any", { allowRememberBrowser: false }]]);

  calls.length = 0;
  await stepUp.onExecutePostLogin(
    { transaction: { protocol: "oidc-basic-profile", acr_values: "openid " + requested } },
    api,
  );
  assert.deepEqual(calls, [["any", { allowRememberBrowser: false }]]);

  calls.length = 0;
  await stepUp.onExecutePostLogin(
    { transaction: { protocol: "oauth2-refresh-token", acr_values: [requested] } },
    api,
  );
  assert.deepEqual(calls, []);

  await stepUp.onExecutePostLogin(
    { transaction: { protocol: "oidc-basic-profile", acr_values: [] } },
    api,
  );
  assert.deepEqual(calls, []);
});

test("Auth0 Action emits audience-limited claims and factor timestamp, fails closed on network error", async () => {
  const args = {
    client: { client_id: "docs-web" },
    resource_server: { identifier: "https://api.docs.onesa.eu" },
    authentication: {
      methods: [{ name: "mfa", timestamp: new Date().toISOString() }],
    },
    user: { user_id: "test", email_verified: true },
    secrets: {
      POLICY_URL: "https://identity-admin.onesa.test/internal/decision",
      POLICY_ORIGIN: "https://identity-admin.onesa.test",
      POLICY_KEY: "test",
    },
  };
  const original = globalThis.fetch;
  const claims = {};
  let denied = false;
  const api = {
    access: { deny: () => (denied = true) },
    accessToken: { setCustomClaim: (k, v) => (claims[k] = v) },
  };
  try {
    const id = randomUUID();
    globalThis.fetch = async () =>
      Response.json({
        user_id: id,
        roles: ["editor"],
        product: "engineering-documents",
      });
    await action.onExecutePostLogin(args, api);
    assert.equal(claims["https://onesa.eu/claims/user_id"], id);
    assert.deepEqual(claims["https://onesa.eu/claims/products"], [
      "engineering-documents",
    ]);
    assert.ok(claims["https://onesa.eu/claims/mfa_time"]);
    globalThis.fetch = async () => {
      throw Error("Controlled outage");
    };
    await action.onExecutePostLogin(args, api);
    assert.equal(denied, true);
  } finally {
    globalThis.fetch = original;
  }
});

test("Auth0 Action never sends the policy bearer key to a decorated or non-policy URL", async () => {
  const original = globalThis.fetch;
  let requested = false, denied = false;
  globalThis.fetch = async () => {
    requested = true;
    return Response.json({ selfservice: true });
  };
  try {
    const api = { access: { deny: () => (denied = true) } };
    const base = {
      client: { client_id: "account-ui" },
      user: { user_id: "auth0|fixture", email_verified: true },
      secrets: {
        POLICY_URL: "https://identity-admin.onesa.test/internal/decision",
        POLICY_ORIGIN: "https://identity-admin.onesa.test",
        POLICY_KEY: "controlled-policy-key",
      },
    };
    for (const POLICY_URL of [
      "http://identity-admin.onesa.test/internal/decision",
      "https://attacker.invalid/internal/decision",
      "https://identity-admin.onesa.test/collect",
      "https://identity-admin.onesa.test/internal/decision?forward=1",
      "https://user:pass@identity-admin.onesa.test/internal/decision",
    ]) {
      requested = false;
      denied = false;
      await action.onExecutePostLogin(
        { ...base, secrets: { ...base.secrets, POLICY_URL } },
        api,
      );
      assert.equal(denied, true, POLICY_URL);
      assert.equal(requested, false, POLICY_URL);
    }
    requested = false;
    denied = false;
    await action.onExecutePostLogin(
      { ...base, secrets: { ...base.secrets, POLICY_ORIGIN: "https://attacker.invalid" } },
      api,
    );
    assert.equal(denied, true);
    assert.equal(requested, false);
    requested = false;
    denied = false;
    const { POLICY_ORIGIN, ...missingOrigin } = base.secrets;
    await action.onExecutePostLogin(
      { ...base, secrets: missingOrigin },
      api,
    );
    assert.equal(denied, true);
    assert.equal(requested, false);
  } finally {
    globalThis.fetch = original;
  }
});

test("password recovery reports provider timeout as 503 without success audit", async (t) => {
  const { store, call, login } = await fixture(t, {
    connection: "Username-Password-Authentication",
  });
  const user = await login("identity-admin", "/account");
  const account = await call("/account", "GET", undefined, { cookie: user.cookie });
  const csrf = (await account.text()).match(/name="csrf" value="([^"]+)"/)[1];
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });
  globalThis.fetch = async () => { throw new TypeError("provider unavailable"); };
  const result = await call(
    "/account/recovery",
    "POST",
    new URLSearchParams({ csrf }),
    { cookie: user.cookie, origin: env.origin },
  );
  assert.equal(result.status, 503);
  assert.match(await result.text(), /Recovery unavailable/);
  assert.equal(
    store.one("SELECT 1 FROM audit WHERE action='request-password-recovery'"),
    undefined,
  );
  // Ambiguous delivery must not allow repeated password reset messages.
  const retry = await call(
    "/account/recovery",
    "POST",
    new URLSearchParams({ csrf }),
    { cookie: user.cookie, origin: env.origin },
  );
  assert.equal(retry.status, 429);
});

test("unrelated Diaspora Unlocked cannot be assigned an Onesa product role", () => {
  assert.equal(Object.hasOwn(products, "diaspora-unlocked"), false);
  const store = openStore(":memory:");
  try {
    const account = store.register(env.issuer, "oidc|external-test", "external@onesa.test");
    assert.throws(
      () => store.change("admin", account.id, account.revision, {
        kind: "grant", product: "diaspora-unlocked", role: "user", status: "active",
      }),
      /Invalid product role/,
    );
    assert.equal(store.activeGrant(account.id, "diaspora-unlocked"), undefined);
  } finally {
    store.db.close();
  }
});

test("verified email change preserves stable user ID, grants, and audit trail", (t) => {
  const store = openStore(":memory:");
  t.after(() => store.db.close());
  const original = store.register(env.issuer, "oidc|stable", "old@onesa.test");
  store.change("test", original.id, 1, { kind: "status", status: "active" });
  store.change("test", original.id, 2, {
    kind: "grant", product: "farmer", role: "user", status: "active",
  });
  const updated = store.register(env.issuer, "oidc|stable", "NEW@onesa.test");
  assert.equal(updated.id, original.id);
  assert.equal(updated.email, "new@onesa.test");
  assert.equal(store.activeGrant(original.id, "farmer").role, "user");
  assert.equal(store.one("SELECT action FROM audit WHERE action='verified-email-change'").action, "verified-email-change");
  const other = store.register(env.issuer, "oidc|other", "other@onesa.test");
  assert.throws(
    () => store.register(env.issuer, "oidc|stable", "other@onesa.test"),
    /ownership verification/,
  );
  assert.equal(store.lookup(env.issuer, "oidc|stable").email, "new@onesa.test");
  assert.equal(store.lookup(env.issuer, "oidc|other").id, other.id);
  assert.throws(
    () => store.register(env.issuer, "oidc|stable", "not-an-email"),
    /Verified address required/,
  );
  assert.equal(store.lookup(env.issuer, "oidc|stable").email, "new@onesa.test");
});

test("OIDC callback preserves a validated invitation destination", async (t) => {
  const { call } = await fixture(t);
  const invitation = "a".repeat(43);
  const start = await call("/login?invite=" + invitation);
  assert.equal(start.status, 303);
  const params = new URL(start.headers.get("location")).searchParams;
  const flow = start.headers.getSetCookie()[0].split(";")[0];
  const result = await call(
    "/callback?code=controlled&state=" + encodeURIComponent(params.get("state")),
    "GET", undefined, { cookie: flow },
  );
  assert.equal(result.status, 303);
  assert.equal(result.headers.get("location"), "/account?invite=" + invitation);
});

test("legacy import rejects duplicate Engineering membership owners atomically", () => {
  const store = openStore(":memory:");
  try {
    const id = randomUUID();
    const snapshot = {
      version: 1,
      accounts: [
        { id, email: "engineering@onesa.test", status: "active", role: "member" },
      ],
      grants: [],
      docs: [
        { id, membership_id: randomUUID(), enabled: true },
        { id, membership_id: randomUUID(), enabled: false },
      ],
      registrations: [],
      drone_memberships: [],
    };
    assert.throws(
      () => applySnapshot(store, "duplicate-engineering-owner", snapshot, [], env.issuer),
      /Duplicate Engineering membership owner/,
    );
    assert.equal(store.one("SELECT count(*) AS n FROM accounts").n, 0);
    assert.equal(
      store.one("SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name='legacy_inventory'").n,
      0,
    );
    assert.equal(store.one("SELECT count(*) AS n FROM imports").n, 0);
    assert.equal(store.one("SELECT count(*) AS n FROM audit").n, 0);
  } finally {
    store.db.close();
  }
});

test("legacy import rejects ambiguous email ownership atomically and normalizes accepted contacts", () => {
  const store = openStore(":memory:");
  try {
    const first = randomUUID(), second = randomUUID();
    const snapshot = {
      version: 1,
      accounts: [
        { id: first, email: " First@Onesa.Test ", status: "active", role: "member" },
        { id: second, email: "first@onesa.test", status: "active", role: "member" },
      ],
      grants: [], docs: [], registrations: [], drone_memberships: [],
    };
    assert.throws(
      () => applySnapshot(store, "duplicate-contacts", snapshot, [], env.issuer),
      /Conflicting account snapshot/,
    );
    assert.equal(store.one("SELECT count(*) AS n FROM accounts").n, 0);
    assert.equal(store.one("SELECT count(*) AS n FROM imports").n, 0);
    assert.equal(store.one("SELECT count(*) AS n FROM audit").n, 0);
    const existing = store.register(env.issuer, "fixture|existing", "occupied@onesa.test");
    snapshot.accounts[1].email = "OCCUPIED@onesa.test";
    assert.throws(
      () => applySnapshot(store, "existing-contact", snapshot, [], env.issuer),
      /Conflicting account snapshot/,
    );
    assert.deepEqual(store.all("SELECT id FROM accounts").map(row => row.id), [existing.id]);
    assert.equal(store.one("SELECT count(*) AS n FROM imports").n, 0);
    snapshot.accounts[1].email = "second@onesa.test";
    assert.equal(applySnapshot(store, "deduplicated", snapshot, [], env.issuer).accounts, 2);
    assert.equal(store.one("SELECT email FROM accounts WHERE id=?", first).email, "first@onesa.test");
    assert.equal(store.one("SELECT email FROM accounts WHERE id=?", second).email, "second@onesa.test");
  } finally {
    store.db.close();
  }
});

test("legacy import refuses malformed contact addresses without leaving an account", () => {
  for (const email of [
    "not-an-email",
    "missing-domain@example",
    "embedded space@onesa.test",
    "x".repeat(250) + "@onesa.test",
  ]) {
    const store = openStore(":memory:");
    try {
      const snapshot = {
        version: 1,
        accounts: [{ id: randomUUID(), email, status: "active", role: "member" }],
        grants: [], docs: [], registrations: [], drone_memberships: [],
      };
      assert.throws(
        () => applySnapshot(store, "invalid-email", snapshot, [], env.issuer),
        /Conflicting account snapshot/,
      );
      assert.equal(store.one("SELECT count(*) AS n FROM accounts").n, 0);
      assert.equal(store.one("SELECT count(*) AS n FROM imports").n, 0);
    } finally {
      store.db.close();
    }
  }
});

test("legacy import rejects unknown Drone tenant roles atomically", () => {
  const store = openStore(":memory:");
  try {
    const id = randomUUID();
    const snapshot = {
      version: 1,
      accounts: [
        { id, email: "drone-user@onesa.test", status: "active", role: "member" },
      ],
      grants: [],
      docs: [],
      registrations: [],
      drone_memberships: [
        {
          user_id: id,
          tenant_id: randomUUID(),
          role: "superadmin",
          label: "Unexpected elevated role",
        },
      ],
    };
    assert.throws(
      () => applySnapshot(store, "invalid-drone-role", snapshot, [], env.issuer),
      /Invalid source reference or product role/,
    );
    assert.equal(store.one("SELECT count(*) AS n FROM accounts").n, 0);
    assert.equal(
      store.one("SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name='legacy_inventory'").n,
      0,
    );
    assert.equal(store.one("SELECT count(*) AS n FROM imports").n, 0);
    assert.equal(store.one("SELECT count(*) AS n FROM audit").n, 0);
  } finally {
    store.db.close();
  }
});

test("transient OIDC token-exchange failure preserves the one-use invitation for retry", async (t) => {
  const { call, store, setRedeem } = await fixture(t);
  const invitation = store.invite("identity-admin", "new-invitee@onesa.test");
  const start = await call("/register?invite=" + invitation);
  const params = new URL(start.headers.get("location")).searchParams;
  const flow = start.headers.getSetCookie()[0].split(";")[0];

  setRedeem(async () => { throw new Error("temporary token endpoint outage"); });
  const failed = await call(
    "/callback?code=controlled&state=" + encodeURIComponent(params.get("state")),
    "GET", undefined, { cookie: flow },
  );
  assert.equal(failed.status, 503);
  assert.ok((await failed.text()).includes('href="/login?invite=' + invitation + '"'));
  assert.equal(store.one("SELECT count(*) AS n FROM invites").n, 1);
  assert.equal(store.one("SELECT count(*) AS n FROM accounts WHERE email='identity-admin@onesa.test'").n, 1);

  setRedeem(async () => ({
    iss: env.issuer,
    sub: "oidc|new-invitee",
    email_verified: true,
    email: "new-invitee@onesa.test",
  }));
  const retry = await call("/login?invite=" + invitation);
  const retryParams = new URL(retry.headers.get("location")).searchParams;
  const retryFlow = retry.headers.getSetCookie()[0].split(";")[0];
  const completed = await call(
    "/callback?code=controlled&state=" + encodeURIComponent(retryParams.get("state")),
    "GET", undefined, { cookie: retryFlow },
  );
  assert.equal(completed.status, 303);
  assert.equal(completed.headers.get("location"), "/account?invite=" + invitation);
  assert.equal(store.one("SELECT count(*) AS n FROM invites").n, 0);
  assert.equal(store.one("SELECT count(*) AS n FROM accounts WHERE email='identity-admin@onesa.test'").n, 1);
  assert.equal(store.lookup(env.issuer, "oidc|new-invitee").email, "new-invitee@onesa.test");
  assert.equal(store.lookup(env.issuer, "oidc|new-invitee").status, "pending");
});
 
test("provider cancellation retry preserves invitation and restricts return destinations", async (t) => {
  const { call } = await fixture(t);
  const invitation = "b".repeat(43);
  const start = await call("/register?invite=" + invitation);
  const state = new URL(start.headers.get("location")).searchParams.get("state");
  const flow = start.headers.getSetCookie()[0].split(";")[0];
  const cancelled = await call(
    "/callback?error=access_denied&state=" + encodeURIComponent(state),
    "GET", undefined, { cookie: flow },
  );
  assert.equal(cancelled.status, 403);
  const html = await cancelled.text();
  assert.ok(html.includes('href="/login?invite=' + invitation + '"'));
  const restarted = await call("/login?invite=" + invitation);
  const params = new URL(restarted.headers.get("location")).searchParams;
  const retryFlow = restarted.headers.getSetCookie()[0].split(";")[0];
  const success = await call(
    "/callback?code=controlled&state=" + encodeURIComponent(params.get("state")),
    "GET", undefined, { cookie: retryFlow },
  );
  assert.equal(success.status, 303);
  assert.equal(success.headers.get("location"), "/account?invite=" + invitation);

  const malicious = await call("/login?return=" + encodeURIComponent("https://attacker.invalid/"));
  const maliciousParams = new URL(malicious.headers.get("location")).searchParams;
  const maliciousFlow = malicious.headers.getSetCookie()[0].split(";")[0];
  const denied = await call(
    "/callback?error=access_denied&state=" + encodeURIComponent(maliciousParams.get("state")),
    "GET", undefined, { cookie: maliciousFlow },
  );
  assert.ok((await denied.text()).includes('href="/login"'));
});

test("a stale tab does not consume the current browser's sign-in challenge", async (t) => {
  const { call } = await fixture(t);
  const first = await call("/login");
  const current = await call("/login?return=/admin");
  const state = (start) => new URL(start.headers.get("location")).searchParams.get("state");
  const cookie = current.headers.getSetCookie()[0].split(";")[0];
  const finish = (start) => call("/callback?code=controlled&state=" + state(start),
    "GET", undefined, { cookie });
  assert.equal((await finish(first)).status, 400);
  const signedIn = await finish(current);
  assert.equal(signedIn.status, 303);
  assert.equal(signedIn.headers.get("location"), "/admin");
  assert.equal((await finish(current)).status, 400);
});

test("an administrator's status control reflects each persisted account state", async (t) => {
  const { call, login, store } = await fixture(t);
  const user = store.register(env.issuer, "fixture|user", "user@example.test");
  const admin = await login("identity-admin");
  for (const status of ["pending", "active", "suspended", "rejected"]) {
    if (status !== "pending") {
      const { revision } = store.lookup(env.issuer, "fixture|user");
      store.change("test", user.id, revision, { kind: "status", status });
    }
    const page = await call("/admin?id=" + user.id, "GET", undefined, { cookie: admin.cookie });
    const html = await page.text();
    const select = html.match(/Account status<select name="status">(.*?)<\/select>/s)[1];
    assert.deepEqual([...select.matchAll(/<option selected>([^<]+)<\/option>/g)].map(match => match[1]), [status]);
  }
});

test("rollback replay rejects conflicting or malformed account contacts atomically", () => {
  const source = openStore(":memory:");
  const restored = openStore(":memory:");
  try {
    const id = randomUUID();
    const snapshot = {
      version: 1,
      accounts: [{ id, email: "original@onesa.test", status: "active", role: "member" }],
      grants: [], docs: [], registrations: [], drone_memberships: [],
    };
    for (const s of [source, restored])
      applySnapshot(s, "recovery-contacts", snapshot, [], env.issuer);
    const newcomer = source.register(env.issuer, "provider|new", "new@onesa.test");
    const delta = rollbackDelta(source, "recovery-contacts");
    const baseline = restored.one("SELECT max(seq) AS seq FROM audit").seq;
    const tampered = structuredClone(delta);
    tampered.events[0].detail = '{"tampered":true}';
    assert.throws(() => replayDelta(restored, tampered), /Recovery audit chain integrity failure/);
    assert.equal(restored.one("SELECT max(seq) AS seq FROM audit").seq, baseline);

    const collision = structuredClone(delta);
    collision.changed[0].account.email = "original@onesa.test";
    assert.throws(
      () => replayDelta(restored, collision),
      /Conflicting recovered contact ownership/,
    );
    assert.equal(restored.lookup(env.issuer, "provider|new"), undefined);
    assert.equal(restored.one("SELECT max(seq) AS seq FROM audit").seq, baseline);

    for (const email of ["Not-An-Email", " NEW@onesa.test ", "new@onesa.test ", "new user@onesa.test", "new@onesa.test\t"]) {
      const malformed = structuredClone(delta);
      malformed.changed[0].account.email = email;
      assert.throws(
        () => replayDelta(restored, malformed),
        /Invalid recovered account state/,
      );
      assert.equal(restored.lookup(env.issuer, "provider|new"), undefined);
      assert.equal(restored.one("SELECT max(seq) AS seq FROM audit").seq, baseline);
    }
    const result = replayDelta(restored, delta);
    assert.equal(result.replay, false);
    assert.equal(restored.lookup(env.issuer, "provider|new").id, newcomer.id);
    assert.equal(restored.lookup(env.issuer, "provider|new").email, "new@onesa.test");
    assert.doesNotThrow(() => restored.verifyAuditChain());
  } finally {
    source.db.close();
    restored.db.close();
  }
});

test("first recovery replay rejects altered or extra provider links atomically", () => {
  const source = openStore(":memory:");
  const restored = openStore(":memory:");
  try {
    const id = randomUUID();
    const snapshot = {
      version: 1,
      accounts: [{ id, email: "verified@onesa.test", status: "active", role: "member" }],
      grants: [], docs: [], registrations: [], drone_memberships: [],
    };
    const proof = [{
      id, issuer: env.issuer, subject: "provider|verified",
      method: "dual-authentication", receipt: "independently-verified-receipt",
    }];
    for (const store of [source, restored])
      applySnapshot(store, "verified-link-recovery", snapshot, proof, env.issuer);
    source.change("test", id, 1, { kind: "status", status: "suspended" });
    const delta = rollbackDelta(source, "verified-link-recovery");
    const baseline = restored.one("SELECT max(seq) AS seq FROM audit").seq;
    const evidence = restored.one("SELECT evidence FROM links WHERE id=?", id).evidence;

    // Previously initial replay returned success even when a restored link
    // retained different ownership evidence from the recovered source.
    restored.run("UPDATE links SET evidence='unverified' WHERE id=?", id);
    assert.throws(
      () => replayDelta(restored, delta),
      /Recovery target has divergent provider links/,
    );
    assert.equal(restored.one("SELECT status FROM accounts WHERE id=?", id).status, "active");
    assert.equal(restored.one("SELECT max(seq) AS seq FROM audit").seq, baseline);
    restored.run("UPDATE links SET evidence=? WHERE id=?", evidence, id);

    // A second, unauthorized provider identity must not survive failover.
    restored.run(
      "INSERT INTO links VALUES(?,?,?,?)",
      "https://foreign-provider.invalid/", "provider|forged", id, "unverified",
    );
    assert.throws(
      () => replayDelta(restored, delta),
      /Recovery target has divergent provider links/,
    );
    assert.equal(restored.one("SELECT status FROM accounts WHERE id=?", id).status, "active");
    assert.equal(restored.one("SELECT max(seq) AS seq FROM audit").seq, baseline);
    restored.run("DELETE FROM links WHERE issuer=?", "https://foreign-provider.invalid/");

    assert.equal(replayDelta(restored, delta).replay, false);
    assert.equal(restored.lookup(env.issuer, "provider|verified").status, "suspended");
    assert.deepEqual(restored.all("SELECT * FROM links WHERE id=?", id),
      source.all("SELECT * FROM links WHERE id=?", id));
    assert.doesNotThrow(() => restored.verifyAuditChain());
  } finally {
    source.db.close();
    restored.db.close();
  }
});

test("first recovery replay rejects unjournaled drift in unchanged cutover accounts and grants", () => {
  const source = openStore(":memory:");
  const restored = openStore(":memory:");
  try {
    const baselineUser = randomUUID();
    const changedUser = randomUUID();
    const snapshot = {
      version: 1,
      accounts: [
        { id: baselineUser, email: "baseline@onesa.test", status: "active", role: "member" },
        { id: changedUser, email: "changed@onesa.test", status: "active", role: "member" },
      ],
      grants: [
        { id: baselineUser, product: "portal", role: "viewer", status: "active" },
      ],
      docs: [],
      registrations: [],
      drone_memberships: [],
    };
    for (const store of [source, restored])
      applySnapshot(store, "baseline-integrity", snapshot, [], env.issuer);
    source.change("test", changedUser, 1, { kind: "status", status: "suspended" });
    const delta = rollbackDelta(source, "baseline-integrity");

    // A privileged grant altered directly in an unchanged baseline account
    // has no audit event and is not represented by bundle.changed.
    restored.run(
      "UPDATE grants SET role='administrator' WHERE id=? AND product='portal'",
      baselineUser,
    );
    assert.throws(
      () => replayDelta(restored, delta),
      /divergent baseline grant inventory/,
    );
    assert.equal(restored.one("SELECT status FROM accounts WHERE id=?", changedUser).status, "active");
    restored.run(
      "UPDATE grants SET role='viewer' WHERE id=? AND product='portal'",
      baselineUser,
    );

    restored.run(
      "UPDATE accounts SET email='tampered@onesa.test' WHERE id=?",
      baselineUser,
    );
    assert.throws(
      () => replayDelta(restored, delta),
      /divergent baseline account inventory/,
    );
    assert.equal(restored.one("SELECT status FROM accounts WHERE id=?", changedUser).status, "active");
    restored.run(
      "UPDATE accounts SET email='baseline@onesa.test' WHERE id=?",
      baselineUser,
    );

    assert.equal(replayDelta(restored, delta).replay, false);
    assert.equal(restored.one("SELECT status FROM accounts WHERE id=?", changedUser).status, "suspended");
  } finally {
    source.db.close();
    restored.db.close();
  }
});

test("idempotent rollback replay also invalidates restored sessions, invites and challenges", () => {
  const source = openStore(":memory:");
  const restored = openStore(":memory:");
  try {
    const baselineUser = randomUUID();
    const snapshot = {
      version: 1,
      accounts: [{ id: baselineUser, email: "original@onesa.test", status: "active", role: "member" }],
      grants: [{ id: baselineUser, product: "portal", role: "viewer", status: "active" }],
      docs: [], registrations: [], drone_memberships: [],
    };
    for (const s of [source, restored])
      applySnapshot(s, "recovery-expiry", snapshot, [], env.issuer);
    const newcomer = source.register(env.issuer, "provider|fresh", "fresh@onesa.test");
    const delta = rollbackDelta(source, "recovery-expiry");
    assert.equal(replayDelta(restored, delta).replay, false);

    // Even when the changed-account journal has already been replayed, an
    // untouched baseline grant must not be able to acquire new privileges.
    restored.run(
      "UPDATE grants SET role='administrator' WHERE id=? AND product='portal'",
      baselineUser,
    );
    assert.throws(() => replayDelta(restored, delta), /divergent baseline grant inventory/);
    restored.run(
      "UPDATE grants SET role='viewer' WHERE id=? AND product='portal'",
      baselineUser,
    );

    // An idempotent retry must detect unjournaled data drift, not just the
    // fact that an identical audit sequence has already been applied.
    restored.run("UPDATE accounts SET status='active' WHERE id=?", newcomer.id);
    assert.throws(() => replayDelta(restored, delta), /divergent account state/);
    restored.run("UPDATE accounts SET status='pending' WHERE id=?", newcomer.id);

    restored.run("INSERT INTO grants VALUES(?,?,?,?)",
      newcomer.id, "farmer", "user", "active");
    assert.throws(() => replayDelta(restored, delta), /divergent grants/);
    restored.run("DELETE FROM grants WHERE id=?", newcomer.id);

    const evidence = restored.one("SELECT evidence FROM links WHERE id=?", newcomer.id).evidence;
    restored.run("UPDATE links SET evidence='tampered' WHERE id=?", newcomer.id);
    assert.throws(() => replayDelta(restored, delta), /divergent provider links/);
    restored.run("UPDATE links SET evidence=? WHERE id=?", evidence, newcomer.id);

    // Model credentials accidentally reintroduced from a restored backup.
    restored.run("INSERT INTO sessions VALUES(?,?,?,?,?)",
      digest("stale-session"), newcomer.id, "csrf", Date.now() + 600000, 0);
    restored.run("INSERT INTO invites VALUES(?,?,?)",
      digest("stale-invite"), "fresh@onesa.test", Date.now() + 600000);
    restored.run("INSERT INTO challenges VALUES(?,?,?,?,?,?)",
      digest("stale-flow"), "state", "nonce", "verifier", "/account", Date.now() + 600000);
    assert.equal(replayDelta(restored, delta).replay, true);
    for (const table of ["sessions", "invites", "challenges"])
      assert.equal(restored.one(`SELECT count(*) AS n FROM ${table}`).n, 0, table);
    assert.equal(restored.lookup(env.issuer, "provider|fresh").id, newcomer.id);
  } finally {
    source.db.close();
    restored.db.close();
  }
});
