import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { openStore, digest, products, registrations, accountProducts, productAdministratorRequests } from "../src/store.js";
import { createApp } from "../src/web.js";
import { configuration } from "../src/server.js";
import { registrationReturns, returnKey } from "../src/registration-returns.js";
import {
  applySnapshot,
  replayDelta,
  rollbackDelta,
} from "../migration/reconcile.js";
import action from "../auth0/post-login.cjs";
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

test("stored admin grants migrate to administrator and the rename is audited", () => {
  const directory = mkdtempSync(join(tmpdir(), "onesa-role-rename-"));
  const file = join(directory, "identity.sqlite");
  const first = openStore(file);
  const account = first.register(env.issuer, "oidc|legacy-admin", "legacy-admin@onesa.test");
  first.run("UPDATE accounts SET status='active' WHERE id=?", account.id);
  first.run("INSERT INTO grants VALUES(?,?,?,?)", account.id, "identity", "admin", "active");
  first.db.close();
  const migrated = openStore(file);
  try {
    assert.equal(migrated.activeGrant(account.id, "identity").role, "administrator");
    const event = migrated.one("SELECT actor,action,detail FROM audit WHERE target=? ORDER BY seq DESC LIMIT 1", account.id);
    assert.equal(event.actor, "system:administrator-role-migration");
    assert.equal(event.action, "administrator-role-renamed");
    assert.deepEqual(JSON.parse(event.detail), {
      product: "identity", from: "admin", to: "administrator", status: "active",
    });
  } finally {
    migrated.db.close();
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
    role: "administrator",
    status: "active",
  });
  return { store, call, login, admin, setRedeem: (next) => { redeem = next ?? defaultRedeem; } };
}
test("the Onesa Account entry preserves invitations for sign-in and registration", async (t) => {
  const { call, store } = await fixture(t);
  const invitation = store.invite("identity-admin", "invitee@onesa.test");
  const account = await call("/account?invite=" + invitation);
  const html = await account.text();
  assert.match(html, /<h1>Sign in to Onesa<\/h1>/);
  assert.ok(html.includes('href="/login?invite=' + invitation + '"'));
  assert.ok(html.includes('href="/register?invite=' + invitation + '">Create an Onesa account'));
  assert.doesNotMatch(html, /type="password"/);
  for (const [path, hint] of [["/login", null], ["/register", "signup"]]) {
    const start = await call(path + "?invite=" + invitation);
    const location = new URL(start.headers.get("location"));
    assert.equal(location.origin + location.pathname, env.issuer + "authorize");
    assert.equal(location.searchParams.get("screen_hint"), hint);
    assert.equal(location.searchParams.get("code_challenge_method"), "S256");
    assert.equal(location.searchParams.get("redirect_uri"), env.origin + "/callback");
    assert.match(start.headers.getSetCookie()[0], path === "/register" ? /Max-Age=900$/ : /Max-Age=300$/);
  }
});

test("the public Account overview returns a signed-in visitor to the selected feature", async (t) => {
  const { call, login } = await fixture(t);
  for (const path of ["/", "/account"]) {
    const overview = await call(path);
    const html = await overview.text();
    assert.equal(overview.status, 200);
    assert.equal(overview.headers.get("cache-control"), "no-store");
    assert.equal(overview.headers.has("set-cookie"), false);
    assert.match(html, /Company Portal.*Smart Farmer.*PasoFi/);
    assert.doesNotMatch(html, /<form|identity-admin@onesa\.test/);
    for (const section of ["product-access", "account-security"]) {
      const returnPath = "/account#" + section;
      assert.ok(html.includes('href="/login?return=' + encodeURIComponent(returnPath) + '"'));
      const member = await login("overview-member", returnPath);
      assert.equal(member.url, returnPath);
      const account = await call("/account", "GET", undefined, { cookie: member.cookie });
      assert.match(await account.text(), new RegExp('<h2 id="' + section + '">'));
    }
  }
  assert.equal((await login("overview-member", "/account#unrecognized")).url, "/account");
  assert.equal((await login("overview-member", "https://example.test/account#account-security")).url, "/account");
});

test("both registration types return to each registered product and platform without transferring Identity credentials", async t => {
  const registry = registrationReturns("https://auth.onesa.eu");
  // Production Account and the Auth0 provider may use different origins.
  assert.deepEqual([...registrationReturns("https://account.onesa.eu")], [...registry]);
  assert.equal(registry.size, 55);
  assert.equal(registry.get("security/web/user"), "https://security.onesa.eu/?registration=complete");
  assert.equal(registry.get("security/web/admin"), "https://security.onesa.eu/?registration=complete");
  assert.equal(registry.get("portal/web/admin"), "https://portal.onesa.eu/account/registered?audience=admin");
  assert.equal(registry.get("portal/web/admin/infrastructure"), "https://it-infrastructure.onesa.eu/access-requested");
  assert.equal(registry.get("portal/web/user"), "https://portal.onesa.eu/account/registered");
  assert.equal(registry.get("internal-documents/web/user"), "https://docs.internal.onesa.eu/registration/return");
  assert.equal(registry.get("farmer/ios/admin"), "smartfarmer://onesa/registered");
  const { call, setRedeem } = await fixture(t, { registrationReturns: registry });
  setRedeem(async () => ({ iss: env.issuer, sub: "oidc|roundtrip", email: "verified@onesa.test", email_verified: true }));
  for (const [key, exactDestination] of registry) {
    const [product, platform, audience, entry] = key.split("/");
    const query = new URLSearchParams({ product, platform, audience, return_to: "https://different.test/" });
    if (entry) query.set("entry", entry);
    const start = await call("/register?" + query);
    assert.equal(start.status, 303, key);
    const auth = new URL(start.headers.get("location"));
    assert.equal(auth.searchParams.get("redirect_uri"), env.origin + "/callback");
    assert.equal(auth.searchParams.get("code_challenge_method"), "S256");
    assert.equal(auth.searchParams.get("product"), null);
    assert.equal(auth.searchParams.get("entry"), null);
    const cookies = start.headers.getSetCookie().map(c => c.split(";")[0]).join("; ");
    const done = await call("/callback?code=fixture&state=" + auth.searchParams.get("state"), "GET", undefined, { cookie: cookies });
    assert.equal(done.status, 303, key);
    assert.equal(done.headers.get("location"), exactDestination, key);
    assert.ok(done.headers.getSetCookie().some(c => c.startsWith("__Host-onesa-session=")));
    assert.equal((await call("/account/registration/resume", "GET", undefined, { cookie: cookies })).headers.get("location"), "/account");
  }
  assert.equal((await call("/register?product=portal&platform=ios")).status, 503);
  assert.equal((await call("/register?product=unknown")).status, 400);
  assert.equal(registrationReturns("https://staging.onesa.test").size, 0);
  const custom = JSON.stringify({ farmer: { web: "https://pilot.onesa.test/auth/registration/complete" } });
  assert.equal(registrationReturns("https://staging.onesa.test", custom).get(returnKey("farmer", "web", "admin")), "https://pilot.onesa.test/auth/registration/complete");
  for (const [platform, invalid] of [["web", "http://pilot.onesa.test/"], ["ios", "onesamobile://auth/registered"],
      ["ios", "smartfarmer://onesa/callback"], ["ios", "smartfarmer://attacker/registered"],
      ["android", "smartfarmer://onesa.evil.test/registered"],
      ["ios", "smartfarmer://onesa/other-screen"], ["android", "smartfarmer://onesa/registered?next=admin"],
      ["ios", "smartfarmer://onesa/registered#override"], ["ios", "https://attacker.onesa.test/registered"],
      ["web", "https://pilot.onesa.test/entry?code=fixture"]])
    assert.throws(() => registrationReturns(env.origin, JSON.stringify({ farmer: { [platform]: invalid } })));
});

test("only the exact Portal web infrastructure landing can be configured", () => {
  const account = "https://account.onesa.eu";
  const landing = "https://it-infrastructure.onesa.eu/access-requested";
  const approved = JSON.stringify({ portal: { web: { infrastructure: landing } } });
  assert.equal(registrationReturns(account, approved).get("portal/web/admin/infrastructure"), landing);
  for (const [product, platform, destination] of [
    ["portal", "web", "https://other.onesa.test/access-requested"],
    ["portal", "web", landing + "?return=/"],
    ["portal", "web", landing + "#return"],
    ["portal", "web", "https://it-infrastructure.onesa.eu/callback"],
    ["farmer", "web", landing],
    ["portal", "ios", landing],
  ]) {
    const override = JSON.stringify({ [product]: { [platform]: { infrastructure: destination } } });
    assert.throws(() => registrationReturns(account, override));
  }
});

test("a separate Account environment requires its own exact infrastructure landing", () => {
  const configured = destination => JSON.stringify({ portal: { web: { infrastructure: destination } } });
  const stage = "https://infrastructure-staging.onesa.test/access-requested";
  assert.equal(registrationReturns(env.origin, configured(stage)).get("portal/web/admin/infrastructure"), stage);
  for (const invalid of [
    "https://it-infrastructure.onesa.eu/access-requested",
    "http://infrastructure-staging.onesa.test/access-requested",
    stage + "?",
    stage + "#",
    stage + "/",
    stage.replace("https://", "https://person@"),
  ]) assert.throws(() => registrationReturns(env.origin, configured(invalid)));
});

test("infrastructure signup resumes after verified email and requests only pending Portal administrator access", async t => {
  const audience = "https://api.portal.onesa.test";
  const client = "infrastructure-client";
  const resources = new Map(env.resources);
  resources.set(audience, { product: "portal", clients: [client] });
  const { call, store, setRedeem } = await fixture(t, {
    resources, registrationReturns: registrationReturns("https://account.onesa.eu"), verification: {},
  });
  const portal = "/register?product=portal&audience=admin&platform=web";
  const infrastructure = portal + "&entry=infrastructure";
  for (const path of [
    portal + "&entry=",
    portal + "&entry=https%3A%2F%2Fother.onesa.test",
    infrastructure + "&entry=infrastructure",
    "/register?product=portal&audience=user&entry=infrastructure",
    "/register?product=portal&audience=admin&platform=ios&entry=infrastructure",
    "/register?product=farmer&audience=admin&entry=infrastructure",
    "/register?audience=admin&entry=infrastructure",
    "/login?entry=infrastructure",
  ]) {
    const rejected = await call(path);
    assert.equal(rejected.status, 400, path);
    assert.equal(rejected.headers.has("set-cookie"), false, path);
  }

  const jar = new Map();
  async function visit(path) {
    const response = await call(path, "GET", undefined, { cookie: [...jar.values()].join("; ") });
    for (const header of response.headers.getSetCookie()) {
      const pair = header.split(";")[0];
      const key = pair.slice(0, pair.indexOf("="));
      if (header.includes("Max-Age=0")) jar.delete(key);
      else jar.set(key, pair);
    }
    return response;
  }
  async function start(path) {
    const response = await visit(path);
    assert.equal(response.status, 303);
    return new URL(response.headers.get("location")).searchParams.get("state");
  }
  const callback = state => visit("/callback?code=fixture&state=" + state);
  const applicant = { iss: env.issuer, sub: "oidc|infrastructure-applicant", email: "infrastructure@onesa.test" };
  setRedeem(async () => ({ ...applicant, email_verified: false }));
  const beforeVerification = await start(infrastructure);
  const unverified = await callback(beforeVerification);
  assert.equal(unverified.status, 403);
  assert.match(await unverified.text(), /entry=infrastructure&amp;email_verification=resend/);
  assert.equal(store.lookup(env.issuer, applicant.sub), undefined);

  const resumePath = "/account/registration/resume";
  const continuePath = "/login?audience=admin&product=portal&platform=web&entry=infrastructure&email_verification=continue";
  assert.equal((await visit(resumePath)).headers.get("location"), continuePath);
  const portalState = await start(portal);
  const choices = await (await visit(resumePath)).text();
  assert.match(choices, /IT Infrastructure Dashboard · web · admin/);
  assert.match(choices, /Company Portal · web · admin/);
  const resumeState = await start(continuePath);
  setRedeem(async () => ({ ...applicant, email_verified: true }));
  assert.equal((await callback(resumeState)).headers.get("location"), "https://it-infrastructure.onesa.eu/access-requested");
  const account = store.lookup(env.issuer, applicant.sub);
  assert.equal(account.status, "pending");
  assert.deepEqual([...productAdministratorRequests(store.db, account.id)], [["portal", "pending"]]);
  assert.equal(registrations(store.db, account.id).size, 0);
  assert.equal(store.activeProductAdministrator(account.id, "portal"), undefined);
  assert.equal(store.activeGrant(account.id, "portal"), undefined);
  const decision = await call("/internal/decision", "POST", JSON.stringify({ subject: applicant.sub, audience, client }),
    { authorization: "Bearer " + env.policyKey });
  assert.equal(decision.status, 403);
  assert.equal((await callback(portalState)).headers.get("location"), "https://portal.onesa.eu/account/registered?audience=admin");
  assert.equal(store.lookup(env.issuer, applicant.sub).revision, account.revision);
  assert.equal((await visit(resumePath)).headers.get("location"), "/account");
});

test("verification and expired login retry resume the original product across two open registration tabs", async t => {
  const registry = registrationReturns("https://auth.onesa.eu");
  const { call, store, setRedeem } = await fixture(t, {
    registrationReturns: registry, connection: "Onesa-Database",
  });
  let now = Date.now();
  t.mock.method(Date, "now", () => now);
  const jar = new Map();
  function remember(response) {
    for (const header of response.headers.getSetCookie()) {
      const pair = header.split(";")[0];
      const key = pair.slice(0, pair.indexOf("="));
      if (header.includes("Max-Age=0")) jar.delete(key);
      else jar.set(key, pair);
    }
  }
  async function visit(path) {
    const response = await call(path, "GET", undefined, { cookie: [...jar.values()].join("; ") });
    remember(response);
    return response;
  }
  const start = async path => new URL((await visit(path)).headers.get("location")).searchParams.get("state");
  const signIn = state => visit("/callback?code=fixture&state=" + state);
  const farmer = await start("/register?product=farmer&platform=ios&audience=admin");
  const registration = await visit("/register?product=drone");
  const authorize = new URL(registration.headers.get("location"));
  const drone = authorize.searchParams.get("state");
  assert.equal(authorize.searchParams.get("connection"), "Onesa-Database");
  assert.ok(registration.headers.getSetCookie().some(header =>
    header.startsWith("__Host-onesa-flow-" + drone + "=") && header.endsWith("Max-Age=900")));
  const chooser = await visit("/account/registration/resume");
  assert.equal(chooser.status, 200);
  const choices = await chooser.text();
  assert.match(choices, /Smart Farmer · ios · admin/);
  assert.match(choices, /Onesa Drone · web · user/);
  setRedeem(async () => ({ iss: env.issuer, sub: "oidc|pilot", email: "pilot@onesa.test", email_verified: false }));
  const verify = await signIn(farmer);
  assert.equal(verify.status, 403);
  assert.match(await verify.text(), /audience=admin&amp;product=farmer&amp;platform=ios/);
  setRedeem(async () => ({ iss: env.issuer, sub: "oidc|pilot", email: "pilot@onesa.test", email_verified: true }));
  now += 7 * 60 * 1000;
  assert.equal((await signIn(drone)).headers.get("location"), registry.get("drone/web/user"));
  const resumed = await visit("/account/registration/resume?iss=" + encodeURIComponent(env.issuer));
  assert.equal(resumed.headers.get("location"), "/login?audience=admin&product=farmer&platform=ios&email_verification=continue");
  const newState = await start(resumed.headers.get("location"));
  store.run("UPDATE challenges SET expires=0 WHERE state=?", newState);
  const expired = await signIn(newState);
  assert.equal(expired.status, 400);
  assert.match(await expired.text(), /audience=admin&amp;product=farmer&amp;platform=ios/);
  const finalState = await start((await visit("/account/registration/resume")).headers.get("location"));
  assert.equal((await signIn(finalState)).headers.get("location"), registry.get("farmer/ios/admin"));
  const account = store.lookup(env.issuer, "oidc|pilot");
  assert.equal(store.activeGrant(account.id, "drone").role, "viewer");
  assert.equal(store.activeGrant(account.id, "farmer"), undefined);
  assert.deepEqual([...productAdministratorRequests(store.db, account.id)], [["farmer", "pending"]]);
  assert.equal(registrations(store.db, account.id).size, 0);
  assert.equal((await visit("/account/registration/resume")).headers.get("location"), "/account");
});

test("verified product registration grants ordinary access only to the originating self-service product", async t => {
  const resources = new Map(env.resources);
  resources.set("https://api.factory.onesa.test", { product: "factory", clients: ["factory-web"] });
  const { call, store, login, setRedeem, admin } = await fixture(t, {
    resources, registrationReturns: registrationReturns("https://account.onesa.eu"),
  });
  await login("link-only", "/account?product=farmer&enrollment=user");
  const linkOnly = store.lookup(env.issuer, "oidc|link-only");
  assert.equal(store.activeGrant(linkOnly.id, "farmer"), undefined);
  const identity = name => ({ iss: env.issuer, sub: "oidc|" + name, email: name + "@onesa.test", email_verified: true });
  const signup = async (product, name) => {
    setRedeem(async () => identity(name));
    const started = await call("/register?product=" + product);
    const state = new URL(started.headers.get("location")).searchParams.get("state");
    const cookie = started.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
    return call("/callback?code=fixture&state=" + state, "GET", undefined, { cookie });
  };
  const decide = (name, audience, client) => call("/internal/decision", "POST",
    JSON.stringify({ subject: "oidc|" + name, audience, client }), { authorization: "Bearer " + env.policyKey });
  const done = await signup("farmer", "farmer-signup");
  assert.equal(done.headers.get("location"), "https://farmer.onesa.eu/auth/registration/complete");
  const farmer = store.lookup(env.issuer, "oidc|farmer-signup");
  assert.equal(farmer.status, "active");
  assert.deepEqual(await (await decide("farmer-signup", "https://api.farmer.onesa.eu", "farmer-web")).json(),
    { user_id: farmer.id, product: "farmer", roles: ["user"] });
  assert.equal((await decide("farmer-signup", "https://api.factory.onesa.test", "factory-web")).status, 403);
  assert.equal((await decide("farmer-signup", "https://api.docs.onesa.eu", "docs-web")).status, 403);
  assert.deepEqual([...registrations(store.db, farmer.id)], []);
  const cookie = done.headers.getSetCookie().find(value => value.startsWith("__Host-onesa-session=")).split(";")[0];
  const html = await (await call("/account", "GET", undefined, { cookie })).text();
  assert.match(html, /<!--email_off-->farmer-signup@onesa\.test<!--\/email_off-->/);
  assert.match(html, /Smart Farmer<\/strong>[\s\S]*?Approved · user[\s\S]*?Open Smart Farmer/);
  assert.match(html, /<option value="factory">Smart Factory<\/option>/);
  assert.doesNotMatch(html, /href="\/admin"/);
  await signup("farmer", "farmer-signup");
  assert.equal(store.lookup(env.issuer, "oidc|farmer-signup").revision, farmer.revision);
  store.change(admin.id, farmer.id, farmer.revision, { kind: "grant", product: "farmer", role: "user", status: "revoked" });
  await signup("farmer", "farmer-signup");
  assert.equal((await decide("farmer-signup", "https://api.farmer.onesa.eu", "farmer-web")).status, 403);

  assert.equal((await signup("internal-documents", "docs-signup")).status, 303);
  const docs = store.lookup(env.issuer, "oidc|docs-signup");
  assert.equal(docs.status, "pending");
  assert.equal(store.one("SELECT status FROM grants WHERE id=? AND product='internal-documents'", docs.id).status, "pending");
  assert.equal((await decide("docs-signup", "https://api.docs.onesa.eu", "docs-web")).status, 403);

  const old = store.register(env.issuer, "oidc|previous-member", "previous-member@onesa.test");
  store.change(admin.id, old.id, old.revision, { kind: "grant", product: "factory", role: "administrator", status: "active" });
  assert.equal((await signup("farmer", "previous-member")).status, 303);
  assert.equal(store.lookup(env.issuer, "oidc|previous-member").status, "pending");
  assert.equal((await decide("previous-member", "https://api.factory.onesa.test", "factory-web")).status, 403);
});

test("a pending verified account can request a single product's administrator access and get an independent decision", async t => {
  const resources = new Map(env.resources);
  resources.set("https://api.factory.onesa.test", { product: "factory", clients: ["factory-web"] });
  const { call, store, login } = await fixture(t, { resources });
  const member = await login("requesting-admin", "/account", 0);
  const actor = store.lookup(env.issuer, "oidc|requesting-admin");
  const memberHeaders = { cookie: member.cookie, origin: env.origin };
  const account = () => call("/account", "GET", undefined, memberHeaders);
  const html = await (await account()).text();
  assert.match(html, /Request administrator access<\/button>/);
  const csrf = html.match(/name="csrf" value="([^"]+)"/)[1];
  const request = (product, headers = memberHeaders, token = csrf) => call("/account/enrollment", "POST",
    new URLSearchParams({ product, tier: "admin", csrf: token }), headers);
  const expired = await request("farmer", { origin: env.origin });
  assert.equal(expired.status, 401);
  assert.match(await expired.text(), /Sign in to continue/);
  const stale = await request("farmer", memberHeaders, "invalid");
  assert.equal(stale.status, 403);
  assert.match(await stale.text(), /Reload your Onesa account/);
  assert.equal((await request("farmer", { ...memberHeaders, origin: "https://outside.test" })).status, 403);
  assert.equal((await request("identity")).status, 400);
  assert.deepEqual([...productAdministratorRequests(store.db, actor.id)], []);

  const accepted = await request("farmer");
  assert.equal(accepted.status, 303);
  assert.equal(accepted.headers.get("location"), "/account#access-farmer");
  assert.match(await (await account()).text(), /Smart Farmer<\/strong>[\s\S]*?Administrator request pending/);
  assert.equal((await request("farmer")).status, 303);
  assert.deepEqual([...productAdministratorRequests(store.db, actor.id)], [["farmer", "pending"]]);
  assert.equal(store.lookup(env.issuer, "oidc|requesting-admin").revision, actor.revision + 1);
  assert.equal(store.lookup(env.issuer, "oidc|requesting-admin").status, "pending");
  assert.equal((await request("factory")).status, 303);
  const decide = (audience, client) => call("/internal/decision", "POST",
    JSON.stringify({ subject: "oidc|requesting-admin", audience, client }),
    { authorization: "Bearer " + env.policyKey });
  const farmerDecision = () => decide("https://api.farmer.onesa.eu", "farmer-web");
  assert.equal((await farmerDecision()).status, 403);
  assert.equal((await call("/admin?product=farmer", "GET", undefined, memberHeaders)).status, 403);

  function review(headers, csrf, product, status, revision) {
    return call("/admin/change", "POST", new URLSearchParams({
      csrf, product, status, revision, kind: "product-administrator-review", id: actor.id,
    }), headers);
  }
  const currentRevision = () => store.lookup(env.issuer, "oidc|requesting-admin").revision;
  const admin = await login("identity-admin");
  const adminHeaders = { cookie: admin.cookie, origin: env.origin };
  const central = await call("/admin?id=" + actor.id, "GET", undefined, adminHeaders);
  assert.match(await central.text(), /Review Smart Farmer administrator request/);
  const reviewPage = await call("/admin?product=farmer", "GET", undefined, adminHeaders);
  assert.equal(reviewPage.status, 200);
  const reviewHtml = await reviewPage.text();
  assert.match(reviewHtml, /Pending administrator requests[\s\S]*requesting-admin@onesa\.test[\s\S]*Approve administrator access/);
  const adminCsrf = reviewHtml.match(/name="csrf" value="([^"]+)"/)[1];
  const denied = await review(memberHeaders, csrf, "farmer", "active", currentRevision());
  assert.equal(denied.status, 403);
  const oldAdmin = await login("identity-admin", "/admin", Date.now() - 360000);
  const oldHeaders = { cookie: oldAdmin.cookie, origin: env.origin };
  const oldCsrf = store.one("SELECT csrf FROM sessions WHERE hash=?", digest(oldAdmin.cookie.split("=")[1])).csrf;
  assert.equal((await review(oldHeaders, oldCsrf, "farmer", "active", currentRevision())).status, 403);
  const revision = currentRevision();
  assert.equal((await review(adminHeaders, adminCsrf, "farmer", "active", revision)).status, 303);
  assert.equal((await review(adminHeaders, adminCsrf, "farmer", "rejected", revision)).status, 409);
  assert.equal((await review(adminHeaders, adminCsrf, "factory", "rejected", currentRevision())).status, 303);
  assert.equal((await request("factory")).status, 303);
  assert.deepEqual(await (await farmerDecision()).json(),
    { user_id: actor.id, product: "farmer", roles: ["administrator"], require_mfa: true });
  assert.equal((await decide("https://api.factory.onesa.test", "factory-web")).status, 403);
  assert.equal(productAdministratorRequests(store.db, actor.id).get("factory"), "rejected");
  assert.match(await (await account()).text(), /Administrator approved/);
});

test("one verified signup and independent review give product-scoped user or admin access", async t => {
  const resources = new Map([...accountProducts.keys()].map(product =>
    ["https://" + product + ".test", { product, clients: [product], ...(["factory", "farmer", "logistics"].includes(product) ? { sharedAdminRole: "admin" } : {}) }]));
  const { call, store, login, setRedeem, admin } = await fixture(t, { resources });
  const administrator = await login("identity-admin");
  const adminHeaders = { cookie: administrator.cookie, origin: env.origin };
  for (const tier of ["user", "admin"]) {
    const subject = "oidc|new-" + tier;
    const email = "new-" + tier + "@onesa.test";
    const apply = async (verified, route) => {
      setRedeem(async () => ({ iss: env.issuer, sub: subject, email, email_verified: verified }));
      const started = await call(route);
      const state = new URL(started.headers.get("location")).searchParams.get("state");
      return call("/callback?code=fixture&state=" + state, "GET", undefined, {
        cookie: started.headers.getSetCookie()[0].split(";")[0],
      });
    };
    const signup = tier === "user" ? "/register" : "/register?audience=admin";
    const unverified = await apply(false, signup);
    assert.equal(unverified.status, 403);
    const retry = (await unverified.text()).match(/href="(\/login\?audience=[^"]+)"/)[1].replaceAll("&amp;", "&");
    assert.equal(retry, "/login?audience=" + tier + "&email_verification=continue");
    assert.equal(store.lookup(env.issuer, subject), undefined);
    const done = await apply(true, retry);
    assert.equal(done.status, 303);
    assert.equal(done.headers.get("location"), "/account");
    const account = store.lookup(env.issuer, subject);
    assert.equal(registrations(store.db, account.id).get(tier), "pending");
    async function decide(product, client = product) {
      return call("/internal/decision", "POST", JSON.stringify({ subject, audience: "https://" + product + ".test", client }),
        { authorization: "Bearer " + env.policyKey });
    }
    assert.equal((await decide("ai")).status, 403);
    async function change(kind, status) {
      const page = await (await call("/admin?id=" + account.id, "GET", undefined, adminHeaders)).text();
      assert.ok(page.includes('name="tier" value="' + tier + '"'));
      const csrf = page.match(/name="csrf" value="([^"]+)"/)[1];
      const revision = store.lookup(env.issuer, subject).revision;
      return call("/admin/change", "POST", new URLSearchParams({ id: account.id, revision, csrf, kind, tier, status }), adminHeaders);
    }
    assert.equal((await change("status", "active")).status, 303);
    assert.equal((await decide("ai")).status, 403);
    assert.equal((await change("registration", "active")).status, 303);
    assert.equal((await decide("ai", "other-product")).status, 403);
    for (const [product, entry] of accountProducts) {
      const response = await decide(product);
      if (product === "internal-documents" || product === "security" || (product === "portal" && tier === "user")) {
        assert.equal(response.status, 403);
      } else {
        assert.equal(response.status, 200, product);
        const decision = await response.json();
        assert.equal(decision.user_id, account.id);
        assert.deepEqual(decision.roles, [tier === "admin" ? "administrator" : entry.role]);
        assert.equal(Boolean(decision.require_mfa), tier === "admin");
        assert.equal(Boolean(decision.portal_staff_registration), tier === "admin" && product === "portal");
      }
    }
    store.requestAccess(account.id, "ai");
    assert.equal(store.one("SELECT 1 FROM grants WHERE id=? AND product='ai'", account.id), undefined);
    assert.equal((await decide("ai")).status, 200);
    assert.equal(store.activeGrant(account.id, "identity"), undefined);
    const current = () => store.lookup(env.issuer, subject).revision;
    if (tier === "admin") {
      const resource = resources.get("https://factory.test");
      delete resource.sharedAdminRole;
      assert.deepEqual((await (await decide("factory")).json()).roles, ["user"]);
      resource.sharedAdminRole = "admin";
      store.change(admin.id, account.id, current(), { kind: "grant", product: "portal", role: "administrator", status: "active" });
      assert.equal((await (await decide("portal")).json()).portal_staff_registration, undefined);
    }
    store.change(admin.id, account.id, current(), { kind: "grant", product: "drone", role: "viewer", status: "revoked" });
    await apply(true, signup);
    assert.equal((await decide("drone")).status, 403);
    assert.equal((await change("registration", "revoked")).status, 303);
    await apply(true, signup);
    assert.equal(registrations(store.db, account.id).get(tier), "revoked");
    assert.equal((await decide("ai")).status, 403);
  }
  assert.equal((await call("/register?audience=other")).status, 400);
  assert.equal((await call("/register?audience=user&audience=admin")).status, 400);
});

test("self-service requests preserve account ownership and require an independent approval", async (t) => {
  const { call, store, login, admin } = await fixture(t);
  const first = await login("portal-member", "/account");
  const subject = "oidc|portal-member";
  const account = store.lookup(env.issuer, subject);
  const accountPage = () => call("/account", "GET", undefined, { cookie: first.cookie });
  const html = await (await accountPage()).text();
  assert.match(html, /awaiting administrator approval/);
  assert.match(html, /<option value="farmer">Smart Farmer<\/option>/);
  const csrf = html.match(/name="csrf" value="([^"]+)"/)[1];
  const request = (product, token = csrf, origin = env.origin) =>
    call("/account/access", "POST", new URLSearchParams({ product, csrf: token, role: "admin", id: admin.id }),
      { cookie: first.cookie, origin });
  const decide = () => call("/internal/decision", "POST", JSON.stringify({
    subject, audience: "https://api.farmer.onesa.eu", client: "farmer-web",
  }), { authorization: "Bearer " + env.policyKey });

  assert.equal((await request("farmer", "bad-token")).status, 403);
  assert.equal((await request("farmer", csrf, "https://elsewhere.test")).status, 403);
  assert.equal((await request("identity")).status, 400);
  assert.equal((await request("robot")).status, 400);
  const asked = await request("farmer");
  assert.equal(asked.status, 303);
  assert.equal(asked.headers.get("location"), "/account");
  assert.equal((await request("farmer")).status, 303);
  assert.equal(store.lookup(env.issuer, subject).revision, 2);
  assert.equal(store.one("SELECT count(*) AS n FROM audit WHERE action='request-product-access'").n, 1);
  assert.deepEqual({ ...store.one("SELECT role,status FROM grants WHERE id=? AND product='farmer'", account.id) },
    { role: "user", status: "pending" });
  assert.equal(store.one("SELECT 1 FROM grants WHERE id=? AND product='farmer'", admin.id), undefined);
  assert.match(await (await accountPage()).text(), /Smart Farmer<\/strong>[\s\S]*?Awaiting approval/);
  assert.equal((await decide()).status, 403);
  store.change(admin.id, account.id, 2, { kind: "status", status: "active" });
  assert.equal((await decide()).status, 403);
  store.change(admin.id, account.id, 3, { kind: "grant", product: "farmer", role: "user", status: "active" });
  assert.deepEqual(await (await decide()).json(), { user_id: account.id, product: "farmer", roles: ["user"] });
  store.change(admin.id, account.id, 4, { kind: "grant", product: "farmer", role: "user", status: "revoked" });
  assert.equal((await request("farmer")).status, 303);
  assert.equal((await decide()).status, 403);
  assert.equal(store.lookup(env.issuer, subject).revision, 5);
  store.change(admin.id, account.id, 5, { kind: "grant", product: "engineering-documents", role: "viewer", status: "active" });
  assert.equal((await request("internal-documents")).status, 303);
  assert.equal(store.one("SELECT 1 FROM grants WHERE id=? AND product='internal-documents'", account.id), undefined);
  assert.match(await (await accountPage()).text(), /Internal Documents \(Engineering\)/);
  await login("portal-member", "/account");
  assert.equal(store.lookup(env.issuer, subject).id, account.id);
});

test("an administrator reviews each displayed access request with its recorded role", async (t) => {
  const { store, call, login } = await fixture(t);
  const member = store.register(env.issuer, "oidc|member", "member@onesa.test");
  store.requestAccess(member.id, "farmer");
  store.requestAccess(member.id, "internal-documents");
  const admin = await login("identity-admin");
  const headers = { cookie: admin.cookie, origin: env.origin };
  const page = async () => (await call("/admin?id=" + member.id, "GET", undefined, headers)).text();
  function requestForm(html, assignment) {
    const form = [...html.matchAll(/<form\b[^>]*>([\s\S]*?)<\/form>/g)].map(match => match[1])
      .find(markup => markup.includes('name="assignment" value="' + assignment + '"'));
    assert.ok(form?.includes('name="kind" value="review"'));
    const fields = new URLSearchParams();
    for (const input of form.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g))
      fields.set(input[1], input[2]);
    return { fields, form };
  }
  async function submit({ fields, form }, status) {
    assert.ok(form.includes('<button name="status" value="' + status + '">'));
    const body = new URLSearchParams(fields);
    body.set("status", status);
    return call("/admin/change", "POST", body, headers);
  }
  const html = await page();
  assert.match(html, /<select name="assignment" required><option value="" disabled selected>/);
  const farmer = requestForm(html, "farmer/user");
  assert.equal((await submit(farmer, "active")).status, 303);
  assert.equal((await submit(farmer, "rejected")).status, 409);
  const docs = requestForm(await page(), "internal-documents/viewer");
  assert.equal((await submit(docs, "rejected")).status, 303);
  assert.deepEqual(store.all("SELECT product,role,status FROM grants WHERE id=? ORDER BY product", member.id)
    .map(row => ({ ...row })), [
    { product: "farmer", role: "user", status: "active" },
    { product: "internal-documents", role: "viewer", status: "rejected" },
  ]);
  assert.equal(store.lookup(env.issuer, "oidc|member").status, "pending");
  assert.doesNotMatch(await page(), /name="kind" value="review"/);
});

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

test("product administrators manage only their product list and removals preserve ordinary access", async t => {
  const resources = new Map([
    ["https://api.factory.onesa.test", {
      product: "factory",
      clients: ["factory-web"],
      sharedAdminRole: "administrator",
    }],
    ["https://api.ai.onesa.test", { product: "ai", clients: ["ai-web"] }],
  ]);
  const { call, store, login, admin } = await fixture(t, { resources });
  const factoryAdmin = store.register(env.issuer, "oidc|factory-admin", "factory-admin@onesa.test");
  store.change(admin.id, factoryAdmin.id, factoryAdmin.revision, { kind: "status", status: "active" });
  store.change(admin.id, factoryAdmin.id, store.lookup(env.issuer, "oidc|factory-admin").revision,
    { kind: "grant", product: "factory", role: "user", status: "active" });
  store.change(admin.id, factoryAdmin.id, store.lookup(env.issuer, "oidc|factory-admin").revision,
    { kind: "product-administrator", product: "factory", status: "active" }, "factory");

  const member = store.register(env.issuer, "oidc|factory-member", "factory-member@onesa.test");
  store.change(admin.id, member.id, member.revision, { kind: "status", status: "active" });
  store.change(admin.id, member.id, store.lookup(env.issuer, "oidc|factory-member").revision,
    { kind: "grant", product: "factory", role: "user", status: "active" });

  const entry = await call("/admin?product=factory");
  assert.equal(entry.status, 303);
  assert.equal(new URL(entry.headers.get("location"), env.origin).searchParams.get("return"),
    "/admin?product=factory");
  const actor = await login("factory-admin", "/admin?product=factory");
  assert.equal(actor.url, "/admin?product=factory");
  const page = await call(actor.url, "GET", undefined, { cookie: actor.cookie });
  const html = await page.text();
  assert.equal(page.status, 200);
  assert.match(html, /Smart Factory administrators/);
  assert.match(html, /Add administrator/);
  const csrf = html.match(/name="csrf" value="([^"]+)"/)[1];
  const add = await call("/admin/change", "POST", new URLSearchParams({
    csrf,
    kind: "product-administrator",
    product: "factory",
    status: "active",
    email: "factory-member@onesa.test",
  }), { cookie: actor.cookie, origin: env.origin });
  assert.equal(add.status, 303);
  assert.ok(store.activeProductAdministrator(member.id, "factory"));
  assert.equal(store.activeGrant(member.id, "factory").role, "user", "administrator assignment keeps the member grant");
  const audit = store.one("SELECT actor,action,detail FROM audit WHERE target=? ORDER BY seq DESC LIMIT 1", member.id);
  assert.equal(audit.actor, factoryAdmin.id);
  assert.equal(audit.action, "administrator-grant");
  assert.deepEqual(JSON.parse(audit.detail), { product: "factory", role: "administrator", status: "active" });

  const decide = () => call("/internal/decision", "POST", JSON.stringify({
    subject: "oidc|factory-member",
    audience: "https://api.factory.onesa.test",
    client: "factory-web",
  }), { authorization: "Bearer " + env.policyKey });
  const decision = await decide();
  assert.equal(decision.status, 200);
  assert.deepEqual((await decision.json()).roles, ["administrator"]);

  const crossProduct = await call("/admin/change", "POST", new URLSearchParams({
    csrf,
    kind: "product-administrator",
    product: "ai",
    status: "active",
    email: "factory-member@onesa.test",
  }), { cookie: actor.cookie, origin: env.origin });
  assert.equal(crossProduct.status, 403);
  assert.equal(store.activeProductAdministrator(member.id, "ai"), undefined);

  const refreshed = await call("/admin?product=factory", "GET", undefined, { cookie: actor.cookie });
  const refreshedHtml = await refreshed.text();
  const memberRow = refreshedHtml.slice(refreshedHtml.indexOf("factory-member@onesa.test"));
  const fields = new URLSearchParams();
  const firstForm = memberRow.match(/<form\b[^>]*>([\s\S]*?)<\/form>/)?.[1] || "";
  for (const input of firstForm.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g))
    fields.set(input[1], input[2]);
  fields.set("status", "revoked");
  const remove = await call("/admin/change", "POST", fields, { cookie: actor.cookie, origin: env.origin });
  assert.equal(remove.status, 303);
  assert.equal(store.activeProductAdministrator(member.id, "factory"), undefined);
  assert.equal(store.activeGrant(member.id, "factory").role, "user", "removing administrator leaves ordinary access intact");
  assert.deepEqual((await (await decide()).json()).roles, ["user"]);
  assert.equal(store.one("SELECT action FROM audit WHERE target=? ORDER BY seq DESC LIMIT 1", member.id).action,
    "administrator-revoke");

  const centrallyAssigned = store.register(env.issuer, "oidc|central-factory-admin", "central-factory-admin@onesa.test");
  store.change(admin.id, centrallyAssigned.id, centrallyAssigned.revision, { kind: "status", status: "active" });
  store.change(admin.id, centrallyAssigned.id, store.lookup(env.issuer, "oidc|central-factory-admin").revision,
    { kind: "grant", product: "factory", role: "administrator", status: "active" });
  const directPage = await call("/admin?product=factory", "GET", undefined, { cookie: actor.cookie });
  const directHtml = await directPage.text();
  const directRow = directHtml.slice(directHtml.indexOf("central-factory-admin@onesa.test"));
  const directForm = directRow.match(/<form\b[^>]*>([\s\S]*?)<\/form>/)?.[1] || "";
  const directFields = new URLSearchParams();
  for (const input of directForm.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g))
    directFields.set(input[1], input[2]);
  directFields.set("status", "revoked");
  const removeDirect = await call("/admin/change", "POST", directFields, { cookie: actor.cookie, origin: env.origin });
  assert.equal(removeDirect.status, 303);
  assert.equal(store.activeGrant(centrallyAssigned.id, "factory"), undefined);
  assert.equal(store.one("SELECT action FROM audit WHERE target=? ORDER BY seq DESC LIMIT 1", centrallyAssigned.id).action,
    "administrator-revoke");
});

test("scoped product administrator grants survive an audited Identity recovery replay", () => {
  const source = openStore(":memory:");
  const restored = openStore(":memory:");
  try {
    const administrator = randomUUID();
    const snapshot = {
      version: 1,
      accounts: [{ id: administrator, email: "admin@onesa.test", status: "active", role: "member" }],
      grants: [], docs: [], registrations: [], drone_memberships: [],
    };
    for (const store of [source, restored])
      applySnapshot(store, "product-administrator-recovery", snapshot, [], env.issuer);
    source.run("INSERT INTO links VALUES(?,?,?,?)", env.issuer, "provider|product-admin", administrator, "verified");
    source.change("system:test", administrator, 1, {
      kind: "product-administrator", product: "factory", status: "active",
    }, "factory");
    const delta = rollbackDelta(source, "product-administrator-recovery");
    assert.equal(delta.changed[0].product_administrators[0].status, "active");
    replayDelta(restored, delta);
    assert.ok(restored.activeProductAdministrator(administrator, "factory"));
    assert.equal(replayDelta(restored, delta).replay, true);
    restored.run("UPDATE product_administrators SET status='revoked' WHERE id=?", administrator);
    assert.throws(() => replayDelta(restored, delta), /divergent product administrators/);
  } finally {
    source.db.close();
    restored.db.close();
  }
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
    "administrator",
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
      kind: "grant", product: "identity", role: "administrator", status: "active",
    });
    store.change("test", previous.id, 3, { kind: "status", status: "suspended" });

    const malformed = store.register(env.issuer, "auth0|malformed-role", "malformed-role@onesa.test");
    store.change("test", malformed.id, 1, { kind: "status", status: "active" });
    // A non-admin Identity grant must not block recovery bootstrap.
    store.run("INSERT INTO grants VALUES(?,?,?,?)", malformed.id, "identity", "viewer", "active");

    const replacement = store.register(env.issuer, "auth0|replacement-admin", "replacement@onesa.test");
    bootstrapIdentityAdmin(store, env.issuer, replacement.id, "independent-owner-approval");
    assert.equal(store.lookup(env.issuer, "auth0|replacement-admin").status, "active");
    assert.equal(store.activeGrant(replacement.id, "identity").role, "administrator");
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
        { id: owner, product: "pasofi", role: "administrator", status: "active" },
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
    x.requestRegistration(newUser.id, "admin");
    const delta = rollbackDelta(x, "pilot");
    replayDelta(y, delta);
    assert.deepEqual([...registrations(y.db, newUser.id)], [["admin", "pending"]]);
    assert.equal(registrations(y.db, owner).size, 0);
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
        { id: identityAdmin, product: "identity", role: "administrator", status: "active" },
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

test("Account distinguishes a verified OIDC identity with an unverified email from an invalid identity", async (t) => {
  const { store, call, setRedeem } = await fixture(t, { verification: {} });
  async function finish(path, claims) {
    setRedeem(async () => claims);
    const started = await call(path);
    const params = new URL(started.headers.get("location")).searchParams;
    return call("/callback?code=fixture&state=" + params.get("state"), "GET", undefined,
      { cookie: started.headers.getSetCookie()[0].split(";")[0] });
  }
  const identity = { iss: env.issuer, sub: "auth0|fixture", email: "fixture@example.test", email_verified: false };
  const invalid = await finish("/register", { ...identity, sub: "" });
  assert.equal(invalid.status, 502);
  assert.doesNotMatch(await invalid.text(), /Verify your email|Resend verification/);

  const unverified = await finish("/register?audience=admin", identity);
  assert.equal(unverified.status, 403);
  const html = await unverified.text();
  const [, resend] = html.match(/href="([^"]+)">Resend verification email/);
  assert.equal(resend.replaceAll("&amp;", "&"), "/login?audience=admin&email_verification=resend");
  const restarted = await call(resend.replaceAll("&amp;", "&"));
  const params = new URL(restarted.headers.get("location")).searchParams;
  assert.equal(params.get("prompt"), "login");
  assert.equal(params.get("max_age"), "0");
  assert.equal(params.get("onesa_email_verification"), "resend");
  assert.equal(params.get("code_challenge_method"), "S256");
  assert.equal(unverified.headers.has("set-cookie"), false);
  assert.equal(store.lookup(env.issuer, identity.sub), undefined);
});

test("only the Account Action can request one verification email job per subject during the cooldown", async (t) => {
  const verification = { origin: "https://verification-fixture.eu.auth0.com",
    clientId: "dedicated-verification-fixture", clientSecret: "synthetic-secret" };
  const { store, call } = await fixture(t, { verification });
  const subject = "auth0|email-fixture";
  const requests = [];
  let failProvider = false;
  t.mock.method(globalThis, "fetch", async (url, options) => {
    requests.push(url);
    assert.equal(options.redirect, "error");
    if (url === verification.origin + "/oauth/token") {
      assert.deepEqual(JSON.parse(options.body), {
        grant_type: "client_credentials", audience: verification.origin + "/api/v2/",
        scope: "update:users", client_id: verification.clientId, client_secret: verification.clientSecret,
      });
      return Response.json({ token_type: "Bearer", access_token: "synthetic-management-token" });
    }
    assert.equal(url, verification.origin + "/api/v2/jobs/verification-email");
    assert.deepEqual(JSON.parse(options.body), { user_id: subject, client_id: env.clientId });
    if (failProvider) throw Error("provider unavailable");
    return new Response(null, { status: 201 });
  });
  const send = (user = subject, client = env.clientId, token = env.policyKey) =>
    call("/internal/email-verification", "POST", JSON.stringify({ subject: user, client }),
      { authorization: "Bearer " + token });
  assert.equal((await send(subject, env.clientId, "wrong")).status, 401);
  assert.equal((await send(subject, "docs-web")).status, 403);
  assert.equal((await send("fixture@example.test")).status, 403);
  assert.deepEqual(requests, []);
  const outcomes = await Promise.all([send(), send()]);
  assert.deepEqual(outcomes.map(result => result.status).sort(), [202, 429]);
  assert.equal(requests.length, 2);
  assert.equal(store.lookup(env.issuer, subject), undefined);
  assert.equal(store.one("SELECT count(*) AS n FROM sessions").n, 0);
  store.run("UPDATE verification_email_limit SET next=0");
  failProvider = true;
  assert.equal((await send()).status, 503);
  assert.equal((await send()).status, 429);
  assert.equal(requests.length, 4);
});

test("the unverified Auth0 Action only requests email after a fresh password check and always denies access", async (t) => {
  const network = t.mock.method(globalThis, "fetch", async (url, options) => {
    assert.equal(url, env.origin + "/internal/email-verification");
    assert.equal(options.headers.authorization, "Bearer " + env.policyKey);
    assert.equal(options.redirect, "error");
    assert.deepEqual(JSON.parse(options.body), { subject: "auth0|fixture", client: env.clientId });
    return new Response(null, { status: 202 });
  });
  const denied = [];
  const api = { access: { deny: message => denied.push(message) } };
  const event = {
    client: { client_id: env.clientId },
    user: { user_id: "auth0|fixture", email_verified: false },
    connection: { strategy: "auth0" },
    authentication: { methods: [{ name: "pwd", timestamp: new Date().toISOString() }] },
    transaction: { protocol: "oidc-basic-profile", prompt: ["login"] },
    request: { query: { max_age: "0", onesa_email_verification: "resend" } },
    secrets: { ACCOUNT_CLIENT_ID: env.clientId, POLICY_ORIGIN: env.origin,
      POLICY_URL: env.origin + "/internal/decision", POLICY_KEY: env.policyKey },
  };
  for (const override of [
    { client: { client_id: "docs-web" } },
    { resource_server: { identifier: "https://api.docs.onesa.eu" } },
    { authentication: { methods: [] } },
    { transaction: { protocol: "oidc-basic-profile", prompt: ["none"] } },
    { transaction: { protocol: "oauth2-refresh-token" } },
    { request: { query: {} } },
  ])
    await action.onExecutePostLogin({ ...event, ...override }, api);
  assert.equal(network.mock.callCount(), 0);
  assert.equal(denied.length, 6);
  await action.onExecutePostLogin(event, api);
  assert.equal(network.mock.callCount(), 1);
  assert.equal(denied.at(-1), "Onesa email verification request accepted.");
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
  assert.ok((await failed.text()).includes('href="/login?audience=user&amp;invite=' + invitation + '"'));
  assert.equal(store.one("SELECT count(*) AS n FROM invites").n, 1);
  assert.equal(store.one("SELECT count(*) AS n FROM accounts WHERE email='identity-admin@onesa.test'").n, 1);

  setRedeem(async () => ({
    iss: env.issuer,
    sub: "oidc|new-invitee",
    email_verified: true,
    email: "new-invitee@onesa.test",
  }));
  const retry = await call("/login?audience=user&invite=" + invitation);
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
  assert.ok(html.includes('href="/login?audience=user&amp;invite=' + invitation + '"'));
  const restarted = await call("/login?audience=user&invite=" + invitation);
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

test("Account revokes the local session before the optional Auth0 sign-out handoff", async (t) => {
  for (const auth0LogoutEnabled of [false, true]) {
    const { call, login } = await fixture(t, { auth0LogoutEnabled });
    const member = await login("logout-test", "/account");
    const headers = { cookie: member.cookie, origin: env.origin };
    const account = await (await call("/account", "GET", undefined, headers)).text();
    const csrf = account.match(/name="csrf" value="([^"]+)"/)[1];
    const denied = await call("/logout", "POST", new URLSearchParams({ csrf: "invalid" }), headers);
    assert.equal(denied.status, 403);
    const logout = await call("/logout", "POST", new URLSearchParams({ csrf }), headers);
    assert.equal(logout.status, 303);
    assert.equal(logout.headers.getSetCookie().filter(value => value.includes("Max-Age=0")).length, 2);
    if (auth0LogoutEnabled) {
      const destination = new URL(logout.headers.get("location"));
      assert.equal(destination.origin + destination.pathname, env.issuer + "oidc/logout");
      assert.deepEqual(Object.fromEntries(destination.searchParams), {
        client_id: env.clientId, post_logout_redirect_uri: env.origin,
      });
    } else {
      assert.equal(logout.headers.get("location"), "/account");
    }
    const replay = await (await call("/account", "GET", undefined, headers)).text();
    assert.match(replay, /<h1>Sign in to Onesa<\/h1>/);
  }
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

test("Security requires a dedicated audience, explicit Identity grant and separate organization membership", async t => {
  const resource = new Map([["https://security-api.onesa.eu",
    { product: "security", clients: ["security-web"] }]]);
  const { call, store, admin } = await fixture(t, { resources: resource });
  const subject = "oidc|security-member";
  const member = store.register(env.issuer, subject, "security-member@onesa.test", "", "user");
  store.change(admin.id, member.id, member.revision, { kind: "status", status: "active" });
  const decision = (client = "security-web") => call("/internal/decision", "POST",
    JSON.stringify({ subject, audience: "https://security-api.onesa.eu", client }),
    { authorization: "Bearer " + env.policyKey, "content-type": "application/json" });
  assert.equal((await decision()).status, 403, "shared registration does not grant Security access");
  store.requestAccess(member.id, "security");
  assert.deepEqual({ ...store.one(
    "SELECT role,status FROM grants WHERE id=? AND product='security'", member.id) },
    { role: "viewer", status: "pending" });
  assert.equal((await decision()).status, 403, "unapproved viewer requests do not grant access");
  assert.equal((await decision("unregistered-client")).status, 403);
  store.change(admin.id, member.id, store.lookup(env.issuer, subject).revision,
    { kind: "review", product: "security", role: "viewer", status: "active" });
  const accepted = await decision();
  assert.equal(accepted.status, 200);
  assert.deepEqual((await accepted.json()).roles, ["viewer"]);
  store.change(admin.id, member.id, store.lookup(env.issuer, subject).revision,
    { kind: "grant", product: "security", role: "viewer", status: "revoked" });
  assert.equal((await decision()).status, 403);
});


test("explicit Portal and product administrator grants always require MFA", async t => {
  const resources = new Map([
    ["https://api.portal.onesa.test", { product: "portal", clients: ["infrastructure-sso"] }],
    ["https://api.ai.onesa.test", { product: "ai", clients: ["ai-client"] }],
    ["https://api.security.onesa.test", { product: "security", clients: ["security-client"] }],
    ["https://api.factory.onesa.test", { product: "factory", clients: ["factory-client"], sharedAdminRole: "admin" }],
  ]);
  const { call, store, admin } = await fixture(t, { resources });
  const subject = "oidc|explicit-admin-mfa";
  const account = store.register(env.issuer, subject, "explicit-admin-mfa@onesa.test");
  const revision = () => store.lookup(env.issuer, subject).revision;
  store.change("bootstrap", account.id, revision(), { kind: "status", status: "active" });

  function grant(product, role, status = "active") {
    store.change(admin.id, account.id, revision(), { kind: "grant", product, role, status });
  }
  async function decide(product) {
    const [audience, resource] = [...resources].find(([, r]) => r.product === product);
    return call("/internal/decision", "POST",
      JSON.stringify({ subject, audience, client: resource.clients[0] }),
      { authorization: "Bearer " + env.policyKey });
  }
  for (const [product, role] of [
    ["portal", "administrator"],
    ["portal", "owner"],
    ["ai", "administrator"],
    ["security", "owner"],
    ["factory", "administrator"],
  ]) {
    grant(product, role);
    const response = await decide(product);
    assert.equal(response.status, 200, product + "/" + role);
    const decision = await response.json();
    assert.deepEqual(decision.roles, [role]);
    assert.equal(decision.require_mfa, true, product + "/" + role + " must require MFA");
  }
  grant("portal", "viewer");
  const viewer = await decide("portal");
  assert.equal(viewer.status, 200);
  assert.equal((await viewer.json()).require_mfa, undefined, "non-admin viewer must not be promoted");
  grant("portal", "administrator");
  grant("portal", "administrator", "revoked");
  assert.equal((await decide("portal")).status, 403, "revoked Portal grant must fail closed");
  grant("portal", "administrator");
  store.change("bootstrap", account.id, revision(), { kind: "status", status: "suspended" });
  assert.equal((await decide("portal")).status, 403, "suspended administrator must fail closed");
});
