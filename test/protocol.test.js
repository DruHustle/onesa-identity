import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import {
  randomPKCECodeVerifier,
  calculatePKCECodeChallenge,
} from "openid-client";
import { authClient } from "../src/web.js";

test("OIDC client discovers configuration, exchanges code with PKCE, and verifies signed ID token including nonce", async () => {
  const issuer = "https://auth.onesa.test/",
    origin = "https://identity-admin.onesa.test";
  const env = {
    issuer,
    origin,
    clientId: "identity-ui",
    clientSecret: "controlled-fixture-secret",
  };
  const pair = await generateKeyPair("RS256", { extractable: true }),
    jwk = await exportJWK(pair.publicKey);
  jwk.kid = "fixture";
  const verifier = randomPKCECodeVerifier(),
    challenge = await calculatePKCECodeChallenge(verifier);
  let changedNonce = false,
    incorrectVerifier = false;
  const transport = async (url, options) => {
    const path = new URL(url).pathname;
    if (path === "/.well-known/openid-configuration")
      return Response.json({
        issuer,
        authorization_endpoint: issuer + "authorize",
        token_endpoint: issuer + "oauth/token",
        jwks_uri: issuer + "jwks",
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
      });
    if (path === "/jwks") return Response.json({ keys: [jwk] });
    assert.equal(path, "/oauth/token");
    const body = new URLSearchParams(options.body);
    assert.equal(body.get("grant_type"), "authorization_code");
    if (
      (await calculatePKCECodeChallenge(body.get("code_verifier"))) !==
      challenge
    ) {
      incorrectVerifier = true;
      return Response.json({ error: "invalid_grant" }, { status: 400 });
    }
    const id = await new SignJWT({
      nonce: changedNonce ? "bad-nonce" : "fixture-nonce",
      email_verified: true,
    })
      .setProtectedHeader({ alg: "RS256", kid: "fixture" })
      .setIssuer(issuer)
      .setAudience(env.clientId)
      .setSubject("auth0|example")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(pair.privateKey);
    return Response.json({
      access_token: "synthetic",
      token_type: "Bearer",
      id_token: id,
    });
  };
  const client = authClient(env, transport);
  const u = new URL(
    await client.authorize({
      redirect_uri: origin + "/callback",
      scope: "openid email",
      response_type: "code",
      state: "fixture-state",
      code_challenge: challenge,
      code_challenge_method: "S256",
    }),
  );
  assert.equal(u.origin, new URL(issuer).origin);
  assert.equal(u.searchParams.get("client_id"), env.clientId);
  const callback = new URL(
      origin + "/callback?code=fixture&state=fixture-state",
    ),
    flow = { nonce: "fixture-nonce", state: "fixture-state", verifier };
  assert.equal((await client.redeem(callback, flow)).sub, "auth0|example");
  await assert.rejects(
    client.redeem(callback, { ...flow, verifier: randomPKCECodeVerifier() }),
  );
  assert.equal(incorrectVerifier, true);
  changedNonce = true;
  await assert.rejects(client.redeem(callback, flow));
});
