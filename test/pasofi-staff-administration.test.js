import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, SignJWT } from "jose";
import { openStore } from "../src/store.js";
import { pasoFiStaffAdministration } from "../src/pasofi-staff-administration.js";

const issuer = "https://auth.example.test/";
const origin = "https://account.example.test";
const audience = "https://api.pasofi.mobile.onesa.eu";
const ns = "https://onesa.eu/claims/";
const env = { issuer, origin, resources: new Map([[audience, { product: "pasofi", clients: ["pasofi-web"] }]]) };

test("a verified PasoFi administrator can invite and review staff without broadening account access", async t => {
  const directory = mkdtempSync(join(tmpdir(), "onesa-pasofi-admin-"));
  const store = openStore(join(directory, "identity.sqlite"));
  t.after(() => { store.db.close(); rmSync(directory, { force: true, recursive: true }); });
  const admin = store.register(issuer, "auth0|admin", "admin@example.test", "", undefined, null, undefined, true);
  store.run("INSERT INTO grants VALUES(?,?,?,?)", admin.id, "pasofi", "administrator", "active");
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const api = pasoFiStaffAdministration(store, env, publicKey);
  const now = Math.floor(Date.now() / 1000);
  const sign = (claims = {}) => new SignJWT({
    azp: "pasofi-web", [ns + "user_id"]: admin.id, [ns + "products"]: ["pasofi"],
    [ns + "roles"]: ["administrator"], [ns + "mfa_time"]: now, ...claims,
  }).setProtectedHeader({ alg: "RS256" }).setIssuer(issuer).setAudience(audience)
    .setSubject("auth0|admin").setIssuedAt(now).setExpirationTime(now + 299).sign(privateKey);
  const call = (token, body) => api(new Request(origin + "/internal/pasofi/staff-administration", {
    method: body ? "POST" : "GET",
    headers: { authorization: "Bearer " + token, "content-type": "application/json" },
    ...(body ? { body: JSON.stringify(body) } : {}),
  }));
  assert.equal((await call(await sign({ [ns + "roles"]: ["agent"] }))).status, 403);
  assert.equal((await call(await sign({ azp: "unregistered-client" }))).status, 403);
  assert.equal((await call(await sign({ [ns + "mfa_time"]: now - 301 }))).status, 428);
  assert.equal((await call(await sign({ [ns + "products"]: ["portal"] }))).status, 403);

  const token = await sign();
  const invite = await call(token, { action: "invite", email: "seller@example.test" });
  assert.equal(invite.status, 201);
  const link = new URL((await invite.json()).invitationUrl);
  assert.equal(link.origin, origin);
  assert.equal(link.searchParams.get("return"), "/access?product=pasofi&role=agent");
  assert.equal(store.one("SELECT status FROM accounts WHERE email=?", "seller@example.test"), undefined);
  const seller = store.register(issuer, "auth0|seller", "seller@example.test", link.searchParams.get("invite"), undefined, null, undefined, true);
  store.requestProductStaff(seller.id);
  const { requests } = await (await call(token)).json();
  assert.equal(requests.length, 1);
  assert.equal(requests[0].email, "seller@example.test");

  const review = { action: "review", kind: "staff", id: seller.id, revision: requests[0].revision, status: "active" };
  assert.equal((await call(token, { ...review, id: admin.id })).status, 403);
  assert.equal((await call(token, review)).status, 200);
  assert.equal(store.staffRequest(seller.id), "active");
  assert.equal(store.activeGrant(seller.id, "portal"), undefined);
  assert.equal((await call(token, review)).status, 409);

  store.run("UPDATE grants SET status='revoked' WHERE id=? AND product=?", admin.id, "pasofi");
  assert.equal((await call(token)).status, 403);
});
