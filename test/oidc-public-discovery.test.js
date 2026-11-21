import {test} from "node:test";
import assert from "node:assert/strict";
import {ISSUER, META, verifyDiscovery} from "../src/oidc-public-discovery.js";

function fixture(changes = {}, keyChanges = {}) {
  const metadata = {
    issuer: ISSUER,
    authorization_endpoint: ISSUER + "authorize",
    token_endpoint: ISSUER + "oauth/token",
    jwks_uri: ISSUER + ".well-known/jwks.json",
    response_types_supported: ["code"],
    ...changes,
  };
  const keys = {keys: [{kty:"RSA",kid:"fixture",n:"abCd_123",e:"AQAB",use:"sig"}], ...keyChanges};
  const urls = [];
  return {
    urls,
    fetcher: async (url, options) => {
      urls.push(url);
      assert.equal(options.redirect, "manual");
      return Response.json(url === META ? metadata : keys);
    },
  };
}

test("fetches only public metadata and its exact JWKS location", async () => {
  const {urls,fetcher} = fixture();
  const result = await verifyDiscovery(fetcher);
  assert.equal(result.status,"PASS");
  assert.equal(result.issuer,ISSUER);
  assert.equal(result.signingKeys,1);
  assert.deepEqual(urls,[META,ISSUER + ".well-known/jwks.json"]);
});

test("wrong issuer, rogue signing key location, missing authorization code fail closed", async () => {
  for(const modification of [
    {issuer:"https://onesa.eu.auth0.com/"},
    {jwks_uri:"https://attacker.example.net/.well-known/jwks.json"},
    {authorization_endpoint:"http://auth.onesa.eu/authorize"},
    {response_types_supported:["token"]}
  ]) {
    const {fetcher}=fixture(modification);
    await assert.rejects(verifyDiscovery(fetcher));
  }
});

test("invalid or duplicate public signing key IDs are never treated as healthy", async () => {
  for (const changes of [
    {keys: []},
    {keys: [{kid:"bad",kty:"oct",n:"a",e:"AQAB"}]},
    {keys: [{kid:"one",kty:"RSA",n:"AB",e:"AQAB"},{kid:"one",kty:"RSA",n:"CD",e:"AQAB"}]},
  ]) {
    const {fetcher}=fixture({},changes);
    await assert.rejects(verifyDiscovery(fetcher),/invalid_public_signing_keys/);
  }
});

test("redirects and HTML maintenance pages fail without exposing upstream bodies", async () => {
  for (const status of [301,302,403,503]) {
    await assert.rejects(verifyDiscovery(async () => new Response(null,{status})),/http_or_redirect/);
  }
  await assert.rejects(verifyDiscovery(async () => new Response("<html>Sign in</html>",{headers:{"content-type":"text/html"}})),/non_json_response/);
});
