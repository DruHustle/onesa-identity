import test from "node:test";
import assert from "node:assert/strict";
import stepUp from "../auth0/step-up.cjs";
import issuance from "../auth0/post-login.cjs";

const ns = "https://onesa.eu/claims/";
const clientId = "onesa-infrastructure-oidc-client";
const audience = "https://api.portal.onesa.test";
const allowed = { user_id: "c9228273-0b80-4fa9-bdbd-41abf2d14f26", product: "portal", roles: ["administrator"] };

function fixture(changes = {}) {
  const denials = [], challenges = [], enrollments = [], claims = {}, accessClaims = {};
  const event = {
    client: { client_id: clientId },
    user: { user_id: "auth0|infrastructure-test", email_verified: true, enrolledFactors: [{ type: "otp" }] },
    authentication: { methods: [] },
    transaction: { protocol: "oidc-basic-profile", prompt: [], acr_values: [] },
    secrets: {
      POLICY_ORIGIN: "https://identity.onesa.test",
      POLICY_URL: "https://identity.onesa.test/internal/decision",
      POLICY_KEY: "fixture-secret",
      INFRASTRUCTURE_SSO_CLIENT_ID: clientId,
      INFRASTRUCTURE_SSO_AUDIENCE: audience,
    },
    ...changes,
  };
  const api = {
    access: { deny: message => denials.push(message) },
    authentication: { challengeWithAny: factors => challenges.push(factors), enrollWithAny: factors => enrollments.push(factors) },
    idToken: { setCustomClaim: (key, value) => { claims[key] = value; } },
    accessToken: { setCustomClaim: (key, value) => { accessClaims[key] = value; } },
  };
  return { event, api, denials, challenges, enrollments, claims, accessClaims };
}

function recentMfa(f, deltaMs = 0) {
  f.event.authentication.methods = [{ name: "mfa", timestamp: new Date(Date.now() + deltaMs).toISOString() }];
}

test("infrastructure uses only the dedicated client and canonical Portal audience", async t => {
  const requests = [];
  t.mock.method(globalThis, "fetch", async (_url, init) => {
    requests.push(JSON.parse(init.body));
    return Response.json(allowed);
  });
  const f = fixture();
  await stepUp.onExecutePostLogin(f.event, f.api);
  assert.deepEqual(f.challenges, [[{ type: "otp" }]]);
  assert.deepEqual(f.denials, []);
  recentMfa(f);
  await issuance.onExecutePostLogin(f.event, f.api);
  assert.deepEqual(f.denials, []);
  assert.equal(f.claims[ns + "infrastructure_admin"], "approved");
  assert.deepEqual(f.accessClaims[ns + "roles"], ["administrator"]);
  assert.equal(requests.length, 2);
  for (const request of requests)
    assert.deepEqual(request, { subject: f.event.user.user_id, audience, client: clientId });
});

test("revoked, non-administrator and wrong-product grants never produce an infrastructure claim", async t => {
  let decision = allowed;
  t.mock.method(globalThis, "fetch", async () =>
    decision === null ? new Response(null, { status: 403 }) : Response.json(decision));
  const invalid = [
    null,
    { ...allowed, roles: ["editor"] },
    { ...allowed, roles: ["viewer"] },
    { ...allowed, roles: ["administrator", "editor"] },
    { ...allowed, product: "security", roles: ["administrator"] },
    { ...allowed, product: "identity", roles: ["administrator"] },
    { selfservice: true },
  ];
  for (const value of invalid) {
    decision = value;
    const f = fixture();
    await stepUp.onExecutePostLogin(f.event, f.api);
    assert.equal(f.denials.length, 1);
    assert.deepEqual(f.challenges, []);
    recentMfa(f);
    await issuance.onExecutePostLogin(f.event, f.api);
    assert.equal(f.denials.length, 2);
    assert.equal(f.claims[ns + "infrastructure_admin"], undefined);
  }
});

test("explicit owner or administrator grant still requires recent authentic MFA", async t => {
  let decision = { ...allowed, require_mfa: false, roles: ["owner"] };
  t.mock.method(globalThis, "fetch", async () => Response.json(decision));
  for (const ageMs of [-3600000, -301000, 60000]) {
    const f = fixture();
    recentMfa(f, ageMs);
    await issuance.onExecutePostLogin(f.event, f.api);
    assert.equal(f.denials.length, 1);
    assert.equal(f.claims[ns + "infrastructure_admin"], undefined);
  }
  const missing = fixture();
  await issuance.onExecutePostLogin(missing.event, missing.api);
  assert.equal(missing.denials.length, 1);
  const fresh = fixture();
  recentMfa(fresh, -3000);
  await issuance.onExecutePostLogin(fresh.event, fresh.api);
  assert.deepEqual(fresh.denials, []);
  assert.equal(fresh.claims[ns + "infrastructure_admin"], "approved");
  assert.deepEqual(fresh.accessClaims[ns + "roles"], ["owner"]);
});

test("client mismatch, audience mismatch, missing binding and noninteractive grants fail closed", async t => {
  let networkRequests = 0;
  t.mock.method(globalThis, "fetch", async () => {
    networkRequests++;
    return Response.json(allowed);
  });
  const invalid = [
    f => { f.event.resource_server = { identifier: "https://api.other.onesa.test" }; },
    f => { delete f.event.secrets.INFRASTRUCTURE_SSO_AUDIENCE; },
    f => { f.event.secrets.INFRASTRUCTURE_SSO_AUDIENCE = "http://api.portal.onesa.test"; },
    f => { f.event.secrets.INFRASTRUCTURE_SSO_AUDIENCE = "https://api.portal.onesa.test/other"; },
    f => { f.event.transaction.protocol = "oauth2-refresh-token"; },
    f => { f.event.user.email_verified = false; },
  ];
  for (const mutate of invalid) {
    const f = fixture();
    mutate(f);
    recentMfa(f);
    await issuance.onExecutePostLogin(f.event, f.api);
    assert.equal(f.denials.length, 1);
    assert.equal(f.claims[ns + "infrastructure_admin"], undefined);
  }
  const unrelated = fixture();
  unrelated.event.client.client_id = "unrelated-cloudflare-client";
  unrelated.event.resource_server = { identifier: audience };
  recentMfa(unrelated);
  await issuance.onExecutePostLogin(unrelated.event, unrelated.api);
  assert.equal(unrelated.claims[ns + "infrastructure_admin"], undefined);
  assert.deepEqual(unrelated.denials, []);
  assert.ok(networkRequests > 0);
});

test("policy outage does not admit infrastructure administrators", async t => {
  t.mock.method(globalThis, "fetch", async () => { throw Error("unreachable"); });
  const f = fixture();
  await stepUp.onExecutePostLogin(f.event, f.api);
  assert.equal(f.denials.length, 1);
  recentMfa(f);
  await issuance.onExecutePostLogin(f.event, f.api);
  assert.equal(f.denials.length, 2);
  assert.equal(f.claims[ns + "infrastructure_admin"], undefined);
});
