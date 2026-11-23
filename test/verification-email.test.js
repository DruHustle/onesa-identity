import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { calculatePKCECodeChallenge } from "openid-client";
import { authClient, createApp } from "../src/web.js";
import { openStore, registrations } from "../src/store.js";
import { returnKey } from "../src/registration-returns.js";
import preRegistration from "../auth0/pre-registration.cjs";
import postLogin from "../auth0/post-login.cjs";

test("fresh signup can recover a missing verification email and resume the originating product", async t => {
  const issuer = "https://auth.onesa.test/";
  const origin = "https://account.onesa.test";
  const productReturn = "farmer-fixture://registration/complete";
  const account = { subject: "auth0|verification-fixture", email: "verification@example.test", verified: false };
  const env = {
    issuer, origin, clientId: "account-client", clientSecret: "synthetic-account-secret",
    policyKey: "synthetic-policy-key",
    verification: { origin: "https://fixture.eu.auth0.com", clientId: "mail-client", clientSecret: "synthetic-mail-secret" },
    registrationReturns: new Map([[returnKey("farmer", "ios", "user"), productReturn]]),
    resources: new Map([["https://api.farmer.onesa.test", { product: "farmer", clients: ["farmer-web"] }]]),
  };
  const actionSecrets = { ACCOUNT_CLIENT_ID: env.clientId, POLICY_KEY: env.policyKey,
    POLICY_ORIGIN: origin, POLICY_URL: origin + "/internal/decision" };
  const store = openStore(":memory:");
  t.after(() => store.db.close());
  const keys = await generateKeyPair("RS256", { extractable: true });
  const jwk = { ...await exportJWK(keys.publicKey), kid: "verification-fixture", alg: "RS256" };
  const authorizationCodes = new Map();
  const transport = async (address, options) => {
    const url = new URL(address);
    assert.equal(url.origin, new URL(issuer).origin);
    if (url.pathname === "/.well-known/openid-configuration") return Response.json({
      issuer, authorization_endpoint: issuer + "authorize", token_endpoint: issuer + "oauth/token",
      jwks_uri: issuer + "jwks", response_types_supported: ["code"], subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
    });
    if (url.pathname === "/jwks") return Response.json({ keys: [jwk] });
    assert.equal(url.pathname, "/oauth/token");
    const values = new URLSearchParams(options.body);
    const code = values.get("code");
    const authorized = authorizationCodes.get(code);
    assert.ok(authorized, "only a successful provider transaction creates an authorization code");
    authorizationCodes.delete(code);
    assert.equal(await calculatePKCECodeChallenge(values.get("code_verifier")), authorized.get("code_challenge"));
    assert.equal(values.get("redirect_uri"), origin + "/callback");
    const id_token = await new SignJWT({
      nonce: authorized.get("nonce"), email: account.email, email_verified: account.verified,
    }).setProtectedHeader({ alg: "RS256", kid: jwk.kid }).setIssuer(issuer).setAudience(env.clientId)
      .setSubject(account.subject).setIssuedAt().setExpirationTime("5m").sign(keys.privateKey);
    return Response.json({ access_token: "synthetic", token_type: "Bearer", id_token });
  };
  const app = createApp(store, env, authClient(env, transport));
  const mailbox = [];
  const verificationTickets = new Set();
  t.mock.method(globalThis, "fetch", async (url, options) => {
    const address = String(url);
    if (address.startsWith(origin + "/internal/")) return app(new Request(address, options));
    if (address === env.verification.origin + "/oauth/token") {
      assert.equal(JSON.parse(options.body).client_id, env.verification.clientId);
      return Response.json({ access_token: "synthetic-auth0-management-token", token_type: "Bearer" });
    }
    assert.equal(address, env.verification.origin + "/api/v2/jobs/verification-email");
    assert.deepEqual(JSON.parse(options.body), { user_id: account.subject, client_id: env.clientId });
    const ticket = issuer + "fixture/verify/" + randomUUID();
    verificationTickets.add(ticket);
    mailbox.push({ recipient: account.email, ticket });
    return new Response(null, { status: 201 });
  });

  const cookies = new Map();
  async function visit(path) {
    const response = await app(new Request(origin + path, { headers: { cookie: [...cookies.values()].join("; ") } }));
    for (const header of response.headers.getSetCookie()) {
      const key = header.split("=", 1)[0];
      if (header.includes("Max-Age=0")) cookies.delete(key);
      else cookies.set(key, header.split(";", 1)[0]);
    }
    return response;
  }
  async function enterProvider(path) {
    const response = await visit(path);
    assert.equal(response.status, 303);
    const provider = new URL(response.headers.get("location"));
    assert.equal(provider.origin, new URL(issuer).origin);
    assert.equal(provider.searchParams.get("code_challenge_method"), "S256");
    assert.equal(provider.searchParams.get("prompt"), "login");
    return provider.searchParams;
  }
  async function finishProvider(query) {
    const event = {
      secrets: actionSecrets, client: { client_id: query.get("client_id") },
      user: { user_id: account.subject, email_verified: account.verified },
      connection: { strategy: "auth0" },
      authentication: { methods: [{ name: "pwd", timestamp: new Date().toISOString() }] },
      request: { query: Object.fromEntries(query) },
      transaction: { protocol: "oidc-basic-profile", prompt: [query.get("prompt")] },
    };
    if (query.get("screen_hint") === "signup")
      await preRegistration.onExecutePreUserRegistration(event, { access: { deny: assert.fail } });
    let denial;
    await postLogin.onExecutePostLogin(event, { access: { deny: message => { denial = message; } } });
    const callback = new URLSearchParams({ state: query.get("state") });
    if (denial) {
      callback.set("error", "access_denied");
      callback.set("error_description", denial);
    } else {
      const code = randomUUID();
      authorizationCodes.set(code, query);
      callback.set("code", code);
    }
    return visit("/callback?" + callback);
  }
  function link(html, label) {
    const href = html.match(new RegExp('href="([^"]+)">' + label + "</a>"))?.[1];
    assert.ok(href, label);
    return href.replaceAll("&amp;", "&");
  }

  const signup = await enterProvider("/register?product=farmer&platform=ios&audience=user");
  assert.equal(signup.get("screen_hint"), "signup");
  const verification = await finishProvider(signup);
  assert.equal(verification.status, 403);
  assert.equal(mailbox.length, 0);
  assert.equal(store.lookup(issuer, account.subject), undefined);
  assert.equal(cookies.has("__Host-onesa-session"), false);

  const retry = await enterProvider(link(await verification.text(), "Resend verification email"));
  assert.equal(retry.get("onesa_email_verification"), "resend");
  const queued = await finishProvider(retry);
  assert.equal(queued.status, 403);
  assert.deepEqual(mailbox.map(message => message.recipient), [account.email]);
  assert.equal(cookies.has("__Host-onesa-session"), false);
  assert.equal(store.lookup(issuer, account.subject), undefined);

  const delivered = mailbox.shift();
  assert.equal(new URL(delivered.ticket).origin, new URL(issuer).origin);
  assert.ok(verificationTickets.delete(delivered.ticket), "the provider consumed a one-use verification ticket");
  account.verified = true;
  const continueEntry = new URL(link(await queued.text(), "Continue sign-in"), origin);
  assert.equal(continueEntry.searchParams.get("email_verification"), "continue");
  const resumed = await visit("/account/registration/resume");
  assert.equal(resumed.status, 303);
  const continued = await enterProvider(resumed.headers.get("location"));
  assert.equal(continued.has("onesa_email_verification"), false);
  const signedIn = await finishProvider(continued);
  assert.equal(signedIn.status, 303);
  assert.equal(signedIn.headers.get("location"), productReturn);
  assert.equal(cookies.has("__Host-onesa-session"), true);
  const registered = store.lookup(issuer, account.subject);
  assert.equal(registered.status, "pending");
  assert.equal(registrations(store.db, registered.id).get("user"), "pending");
});
