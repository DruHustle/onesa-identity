import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { openStore, digest, products } from "../src/store.js";
import { createApp } from "../src/web.js";
import {
  applySnapshot,
  replayDelta,
  rollbackDelta,
} from "../migration/reconcile.js";
import action from "../auth0/post-login.cjs";
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
async function fixture(t, overrides = {}) {
  const store = openStore(":memory:");
  t.after(() => store.db.close());
  let factor = Date.now(),
    subject = "oidc|identity-admin";
  const fake = {
    authorize: async (p) => env.issuer + "authorize?" + new URLSearchParams(p),
    redeem: async () => ({
      iss: env.issuer,
      sub: subject,
      email_verified: true,
      email: subject.split("|")[1] + "@onesa.test",
      "https://onesa.eu/claims/mfa_time": Math.floor(factor / 1000),
    }),
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
  return { store, call, login, admin };
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
    const delta = rollbackDelta(x, "pilot");
    replayDelta(y, delta);
    assert.equal(y.activeGrant(second, "farmer"), undefined);
    assert.equal(y.activeGrant(newUser.id, "farmer").role, "user");
    assert.equal(y.lookup(env.issuer, "provider|new").id, newUser.id);
    assert.equal(replayDelta(y, delta).replay, true);
  } finally {
    x.db.close();
    y.db.close();
  }
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
