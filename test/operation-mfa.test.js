import test from "node:test";
import assert from "node:assert/strict";
import stepUp from "../auth0/step-up.cjs";
import policy from "../auth0/post-login.cjs";

const mfa = "http://schemas.openid.net/pape/policies/2007/06/multi-factor";
const operation = "urn:onesa:authentication:operation-mfa";
const nonce = "Abcd1234".repeat(6);
const ns = "https://onesa.eu/claims/";
const decision = { user_id: "28994d67-999a-4a13-886b-9fafb2d54fc2", product: "portal", roles: ["administrator"] };

function fixture() {
  const claims = {}, challenges = [], enrollments = [], denials = [];
  const transaction = {
    protocol: "oidc-basic-profile", prompt: ["login"], acr_values: [mfa, operation], metadata: {},
  };
  const event = {
    transaction, request: { query: { nonce, max_age: "0" } },
    user: { user_id: "auth0|test", email_verified: true, enrolledFactors: [{ type: "otp" }] },
    client: { client_id: "portal-client" }, resource_server: { identifier: "https://api.portal.onesa.test" },
    secrets: { POLICY_ORIGIN: "https://identity.onesa.test", POLICY_URL: "https://identity.onesa.test/internal/decision", POLICY_KEY: "fixture" },
    authentication: { methods: [{ name: "mfa", timestamp: new Date(Date.now() - 60000).toISOString() }] },
  };
  const api = {
    access: { deny: reason => denials.push(reason) },
    transaction: { setMetadata: (name, value) => { transaction.metadata[name] = value; } },
    authentication: { challengeWithAny: factors => challenges.push(factors), enrollWithAny: factors => enrollments.push(factors) },
    accessToken: { setCustomClaim: (key, value) => { claims[key] = value; } },
  };
  return { event, transaction, api, claims, challenges, enrollments, denials };
}

test("interactive baseline uses a sequenced challenge or first enrollment and never binds an operation", async t => {
  t.mock.method(globalThis, "fetch", async () => Response.json(decision));
  for (const acr of [[mfa], "openid " + mfa]) {
    const f = fixture();
    f.transaction.acr_values = acr;
    f.transaction.prompt = [];
    await stepUp.onExecutePostLogin(f.event, f.api);
    assert.deepEqual(f.challenges, [[{ type: "otp" }]]);
    assert.deepEqual(f.transaction.metadata, {});
    await policy.onExecutePostLogin(f.event, f.api);
    assert.ok(f.claims[ns + "mfa_time"]);
    assert.equal(f.claims[ns + "operation_mfa_nonce"], undefined);
  }
  const first = fixture();
  first.transaction.acr_values = [mfa];
  first.event.user.enrolledFactors = [{ type: "email" }];
  await stepUp.onExecutePostLogin(first.event, first.api);
  assert.equal(first.challenges.length, 0);
  assert.ok(first.enrollments[0].some(factor => factor.type === "otp"));
  assert.ok(!first.enrollments[0].some(factor => factor.type === "email"));
});

test("operation proof is bound to the original nonce after a completed enrolled challenge", async t => {
  t.mock.method(globalThis, "fetch", async () => Response.json(decision));
  const f = fixture();
  await stepUp.onExecutePostLogin(f.event, f.api);
  assert.deepEqual(f.challenges, [[{ type: "otp" }]]);
  f.event.request.query = { state: "provider-resume" };
  const completedAt = new Date();
  f.event.authentication.methods.push({ name: "mfa", timestamp: completedAt.toISOString() });
  await policy.onExecutePostLogin(f.event, f.api);
  assert.deepEqual(f.denials, []);
  assert.equal(f.claims[ns + "operation_mfa_nonce"], nonce);
  assert.equal(f.claims[ns + "mfa_time"], Math.floor(+completedAt / 1000));
  assert.equal(f.claims[ns + "user_id"], decision.user_id);
});

test("refresh, no MFA and lookalike ACR requests never start a challenge or mint an operation claim", async t => {
  t.mock.method(globalThis, "fetch", async () => Response.json(decision));
  for (const [protocol, acr] of [["oauth2-refresh-token", [operation, mfa]],
    ["oidc-basic-profile", []], ["oidc-basic-profile", mfa + "-unrelated"]]) {
    const f = fixture();
    Object.assign(f.transaction, { protocol, acr_values: acr });
    await stepUp.onExecutePostLogin(f.event, f.api);
    await policy.onExecutePostLogin(f.event, f.api);
    assert.deepEqual(f.challenges, []);
    assert.deepEqual(f.enrollments, []);
    assert.deepEqual(f.transaction.metadata, {});
    assert.equal(f.claims[ns + "operation_mfa_nonce"], undefined);
  }
});

test("operation requires the browser code flow, reauthentication, nonce, and existing enrollment", async () => {
  for (const modify of [
    f => { f.transaction.protocol = "oauth2-password"; },
    f => { f.transaction.prompt = ["none"]; },
    f => { f.transaction.prompt = []; },
    f => { f.transaction.acr_values = [operation]; },
    f => { delete f.event.request.query.max_age; },
    f => { f.event.request.query.max_age = "300"; },
    f => { f.event.request.query.nonce = ["invalid"]; },
    f => { f.event.user.enrolledFactors = []; },
    f => { f.event.user.enrolledFactors = [{ type: "email" }]; },
    f => { f.event.user.enrolledFactors = [{ type: "unsupported" }]; },
    f => { delete f.event.user.enrolledFactors; },
  ]) {
    const f = fixture();
    modify(f);
    await stepUp.onExecutePostLogin(f.event, f.api);
    assert.equal(f.denials.length, 1);
    assert.deepEqual(f.enrollments, []);
    assert.deepEqual(f.challenges, []);
    assert.deepEqual(f.transaction.metadata, {});
  }
});

test("policy refuses cached MFA, future MFA, missing challenge metadata and non-Portal decisions", async t => {
  let outcome = decision;
  t.mock.method(globalThis, "fetch", async () => Response.json(outcome));
  for (const modify of [
    f => { f.event.authentication.methods = []; },
    f => { f.event.authentication.methods.pop(); }, // Only the previous session factor remains.
    f => { f.event.authentication.methods.push({ name: "mfa", timestamp: new Date(Date.now() + 60000).toISOString() }); },
    f => { f.transaction.metadata = {}; },
    f => { f.transaction.metadata.onesa_operation_mfa_minimum = 0; },
    f => { f.transaction.metadata.onesa_operation_mfa_nonce = ""; },
    () => { outcome = { ...decision, product: "farmer" }; },
    () => { outcome = { selfservice: true }; },
  ]) {
    outcome = decision;
    const f = fixture();
    await stepUp.onExecutePostLogin(f.event, f.api);
    f.event.authentication.methods.push({ name: "mfa", timestamp: new Date().toISOString() });
    modify(f);
    await policy.onExecutePostLogin(f.event, f.api);
    assert.equal(f.denials.length, 1);
    assert.deepEqual(f.claims, {});
  }
});

test("provider history from before the operation is rejected even within the same second", async t => {
  t.mock.method(globalThis, "fetch", async () => Response.json(decision));
  const f = fixture();
  f.event.authentication.methods = [{ name: "mfa", timestamp: new Date().toISOString() }];
  await stepUp.onExecutePostLogin(f.event, f.api);
  await policy.onExecutePostLogin(f.event, f.api);
  assert.equal(f.denials.length, 1);
  assert.deepEqual(f.claims, {});
});


test("normal shared-admin login without an ACR challenges before issuing the approved product role", async t => {
  let response = { ...decision, product: "ai", require_mfa: true };
  t.mock.method(globalThis, "fetch", async () => Response.json(response));
  const f = fixture();
  f.transaction.acr_values = [];
  f.transaction.prompt = [];
  f.event.authentication.methods = [];
  await stepUp.onExecutePostLogin(f.event, f.api);
  assert.deepEqual(f.challenges, [[{ type: "otp" }]]);
  await policy.onExecutePostLogin(f.event, f.api);
  assert.equal(f.denials.length, 1);
  assert.deepEqual(f.claims, {});
  f.event.authentication.methods.push({ name: "mfa", timestamp: new Date().toISOString() });
  await policy.onExecutePostLogin(f.event, f.api);
  assert.deepEqual(f.claims[ns + "roles"], ["administrator"]);
  assert.deepEqual(f.claims[ns + "products"], ["ai"]);
  response = { ...decision, roles: ["administrator"], require_mfa: true, portal_staff_registration: true };
  await policy.onExecutePostLogin(f.event, f.api);
  assert.equal(f.claims[ns + "portal_staff_registration"], true);
  const normal = fixture();
  normal.transaction.acr_values = [];
  normal.event.authentication.methods = [];
  response = { ...decision, product: "ai", roles: ["user"] };
  await stepUp.onExecutePostLogin(normal.event, normal.api);
  await policy.onExecutePostLogin(normal.event, normal.api);
  assert.equal(normal.challenges.length, 0);
  assert.deepEqual(normal.claims[ns + "roles"], ["user"]);
});

test("hosted signup requires Auth0's Account client or its exclusively registered code callback", async (t) => {
  const { default: action } = await import("../auth0/pre-registration.cjs");
  const callback = "https://account.onesa.test/callback";
  const transaction = {
    protocol: "oidc-basic-profile",
    redirect_uri: callback,
    requested_scopes: ["openid", "email"],
    response_type: ["code"],
  };
  const event = {
    connection: { id: "con_fixture", name: "Username-Password-Authentication", strategy: "auth0" },
    request: { method: "POST", body: { client_id: "account", redirect_uri: callback } },
    tenant: { id: "onesa-fixture" },
    user: { email: "signup@example.test" },
    secrets: { ACCOUNT_CLIENT_ID: "account", ACCOUNT_CALLBACK_URL: callback },
    transaction,
  };
  const log = t.mock.method(console, "log", () => {});
  for (const [override, reason] of [
    [{ client: { client_id: "account" } }, null],
    [{ client: { client_id: "account" }, transaction: {} }, null],
    [{}, null],
    [{ transaction: { ...transaction, response_type: undefined } }, null],
    [{ client: { client_id: "product", name: "Onesa Account" } }, "account_client_mismatch"],
    [{ transaction: undefined, client: { client_id: "account" } }, "hosted_transaction_missing"],
    [{ transaction: undefined }, "hosted_transaction_missing"],
    [{ transaction: { ...transaction, redirect_uri: "https://product.onesa.test/callback" } }, "account_callback_unconfirmed"],
    [{ transaction: { ...transaction, redirect_uri: callback + "?lookalike=1" } }, "account_callback_unconfirmed"],
    [{ transaction: { ...transaction, protocol: "oauth2-password" } }, "account_callback_unconfirmed"],
    [{ transaction: { ...transaction, response_type: ["token"] } }, "account_callback_unconfirmed"],
    [{ secrets: { ACCOUNT_CLIENT_ID: "account" } }, "account_callback_unconfirmed"],
    [{ secrets: { ACCOUNT_CALLBACK_URL: callback } }, "account_client_unconfigured"],
  ]) {
    const denied = [];
    log.mock.resetCalls();
    await action.onExecutePreUserRegistration({ ...event, ...override },
      { access: { deny: code => denied.push(code) } });
    assert.deepEqual(denied, reason ? ["onesa_account_registration_required"] : []);
    assert.deepEqual(log.mock.calls.map(call => JSON.parse(call.arguments[0])),
      reason ? [{ event: "onesa_signup_entry_denied", reason }] : []);
  }
});
