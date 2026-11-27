import test from "node:test";
import assert from "node:assert/strict";
import { openStore } from "../src/store.js";
import { createApp } from "../src/web.js";

const origin = "https://account.onesa.test";
const issuer = "https://auth.onesa.test/";

async function fixture(t, mfaAt = Date.now()) {
  const store = openStore(":memory:");
  t.after(() => store.db.close());
  const account = store.register(issuer, "oidc|closure-member", "member@onesa.test", "", "user");
  store.change("bootstrap", account.id, 1, { kind: "status", status: "active" });
  store.change("bootstrap", account.id, 2, {
    kind: "grant", product: "farmer", role: "user", status: "active",
  });
  const env = {
    origin, issuer, clientId: "account-confidential-client",
    policyKey: "isolated-test-policy-key",
    resources: new Map([["https://api.farmer.onesa.test",
      { product: "farmer", clients: ["farmer-web"] }]]),
  };
  const provider = {
    authorize: async params => issuer + "authorize?" + new URLSearchParams(params),
    redeem: async () => ({
      iss: issuer, sub: "oidc|closure-member",
      email: "member@onesa.test", email_verified: true,
      "https://onesa.eu/claims/mfa_time": Math.floor(mfaAt / 1000),
    }),
  };
  const app = createApp(store, env, provider);
  const call = (path, method = "GET", body, headers = {}) =>
    app(new Request(origin + path, {
      method, headers, ...(body === undefined ? {} : { body }),
    }));
  const start = await call("/login");
  const state = new URL(start.headers.get("location")).searchParams.get("state");
  const flowCookie = start.headers.getSetCookie()[0].split(";")[0];
  const complete = await call("/callback?code=fixture&state=" + state,
    "GET", undefined, { cookie: flowCookie });
  assert.equal(complete.status, 303);
  const cookie = complete.headers.getSetCookie()
    .find(value => value.startsWith("__Host-onesa-session=")).split(";")[0];
  const html = await (await call("/account", "GET", undefined, { cookie })).text();
  const csrf = html.match(/name="csrf" value="([^"]+)"/)[1];
  const request = (confirmation = "DELETE", overrides = {}) => call("/account/delete",
    "POST", new URLSearchParams({ csrf, confirm: confirmation }),
    { cookie, origin, ...overrides });
  return { store, account, call, cookie, csrf, request, html };
}

test("the product link opens account closure after sign-in without requesting deletion", async t => {
  const f = await fixture(t);
  const entry = await f.call("/account/closure");
  assert.equal(entry.status, 303);
  assert.equal(new URL(entry.headers.get("location"), origin).searchParams.get("return"), "/account#account-closure");

  const start = await f.call(entry.headers.get("location"));
  const state = new URL(start.headers.get("location")).searchParams.get("state");
  const flow = start.headers.getSetCookie()[0].split(";")[0];
  const complete = await f.call("/callback?code=fixture&state=" + state,
    "GET", undefined, { cookie: flow });
  assert.equal(complete.headers.get("location"), "/account#account-closure");
  const signedIn = await f.call("/account/closure", "GET", undefined, { cookie: f.cookie });
  assert.equal(signedIn.headers.get("location"), "/account#account-closure");
  assert.match(f.html, /<h2 id="account-closure">Account closure<\/h2>/);
  assert.equal(f.store.one("SELECT count(*) AS n FROM account_deletion_requests").n, 0);
});

test("account closure is MFA and CSRF protected, revokes sessions/grants and queues scoped cleanup", async t => {
  const f = await fixture(t);
  assert.match(f.html, /Request account closure/);
  assert.equal((await f.request("DELETE", { origin: "https://elsewhere.test" })).status, 403);
  assert.equal((await f.call("/account/delete", "POST",
    new URLSearchParams({ csrf: "wrong", confirm: "DELETE" }),
    { origin, cookie: f.cookie })).status, 403);
  assert.equal((await f.request("delete")).status, 400);
  assert.equal(f.store.lookup(issuer, "oidc|closure-member").status, "active");

  const close = await f.request();
  assert.equal(close.status, 200);
  assert.match(await close.text(), /not yet confirmation of complete erasure/);
  assert.ok(close.headers.getSetCookie().some(x => x.startsWith("__Host-onesa-session=") && x.includes("Max-Age=0")));
  assert.equal(f.store.lookup(issuer, "oidc|closure-member").status, "suspended");
  assert.equal(f.store.one("SELECT status FROM grants WHERE id=? AND product='farmer'", f.account.id).status, "revoked");
  assert.equal(f.store.one("SELECT count(*) AS n FROM sessions WHERE id=?", f.account.id).n, 0);
  assert.equal(f.store.one("SELECT status FROM account_deletion_requests WHERE id=?", f.account.id).status, "requested");
  assert.equal(f.store.one("SELECT count(*) AS n FROM account_deletion_outbox WHERE id=? AND status='pending'", f.account.id).n, 12);
  assert.equal(f.store.one("SELECT count(*) AS n FROM audit WHERE action='request-account-deletion' AND target=?", f.account.id).n, 1);
  assert.equal(f.store.verifyAuditChain().entries > 0, true);
  assert.equal((await f.call("/account", "GET", undefined, { cookie: f.cookie })).status, 200);
  assert.match(await (await f.call("/account", "GET", undefined, { cookie: f.cookie })).text(), /<h1>Sign in<\/h1>/);
  const denied = await f.call("/internal/decision", "POST",
    JSON.stringify({ subject: "oidc|closure-member", audience: "https://api.farmer.onesa.test", client: "farmer-web" }),
    { authorization: "Bearer isolated-test-policy-key", "content-type": "application/json" });
  assert.equal(denied.status, 403);
  assert.equal(f.store.requestDeletion(f.account.id).repeated, true);
  assert.equal(f.store.one("SELECT count(*) AS n FROM audit WHERE action='request-account-deletion' AND target=?", f.account.id).n, 1);
  assert.throws(() => f.store.change("bootstrap", f.account.id,
    f.store.lookup(issuer, "oidc|closure-member").revision,
    { kind: "status", status: "active" }), /Account closure pending/);
  assert.throws(() => f.store.register(issuer, "oidc|closure-member",
    "new-address@onesa.test"), /Account unavailable/);
});

test("stale MFA cannot close the account or revoke grants", async t => {
  const f = await fixture(t, Date.now() - 600000);
  const attempted = await f.request();
  assert.equal(attempted.status, 403);
  const body = await attempted.text();
  assert.match(body, /Recent multi-factor verification/);
  assert.match(body, /\/verify-factor\?return=%2Faccount%23account-closure/);
  assert.equal(f.store.lookup(issuer, "oidc|closure-member").status, "active");
  assert.equal(f.store.one("SELECT count(*) AS n FROM account_deletion_requests").n, 0);
});

test("Identity administrators must transfer governance before requesting closure", async t => {
  const f = await fixture(t);
  const current = f.store.lookup(issuer, "oidc|closure-member");
  f.store.change("bootstrap", f.account.id, current.revision, {
    kind: "grant", product: "identity", role: "administrator", status: "active",
  });
  const attempted = await f.request();
  assert.equal(attempted.status, 409);
  assert.match(await attempted.text(), /Transfer Identity administration/);
  assert.equal(f.store.one("SELECT count(*) AS n FROM account_deletion_requests").n, 0);
  assert.equal(f.store.lookup(issuer, "oidc|closure-member").status, "active");
});
