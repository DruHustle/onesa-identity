import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { configuration } from "../src/server.js";
import { createApp } from "../src/web.js";
import { openStore } from "../src/store.js";

const settings = {
  OIDC_ISSUER: "https://auth.example.test/",
  IDENTITY_ORIGIN: "https://account.example.test",
  OIDC_CLIENT_ID: "account-fixture",
  RESOURCE_CLIENTS_JSON: "{}",
};

test("Oracle credentials are file-backed and startup rejects an ambiguous source", t => {
  const dir = mkdtempSync(join(tmpdir(), "onesa-identity-credentials-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const secret = join(dir, "client");
  const key = join(dir, "policy");
  writeFileSync(secret, "fixture-only\r\n", { mode: 0o600 });
  writeFileSync(key, "k".repeat(40) + "\n", { mode: 0o600 });
  const files = { ...settings, OIDC_CLIENT_SECRET_FILE: secret, ACTION_POLICY_KEY_FILE: key, IDENTITY_STORE_MODE: "existing" };
  const config = configuration(files);
  assert.equal(config.clientSecret, "fixture-only");
  assert.equal(config.policyKey, "k".repeat(40));
  assert.equal(config.requireExistingStore, true);
  assert.throws(() => configuration({ ...files, OIDC_CLIENT_SECRET: "fixture-only" }), /one source/);
  assert.throws(() => configuration({ ...files, IDENTITY_STORE_MODE: "typo" }), /Invalid IDENTITY_STORE_MODE/);
  writeFileSync(secret, "\n");
  assert.throws(() => configuration(files), /Invalid credential file/);
});

test("the production store cannot create a missing database or authorize from a replaced file", async t => {
  const dir = mkdtempSync(join(tmpdir(), "onesa-identity-runtime-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, "policy #1.sqlite");
  const options = { existingOnly: true };
  assert.throws(() => openStore(path, options));
  assert.equal(existsSync(path), false);

  const other = new DatabaseSync(path);
  other.exec("CREATE TABLE unrelated (id INTEGER)");
  other.close();
  assert.throws(() => openStore(path, options), /existing Onesa Identity policy store/);
  rmSync(path);

  // The operator bootstrap/import is explicit. Production only reopens this authority.
  openStore(path).db.close();
  const store = openStore(path, options);
  t.after(() => store.db.close());
  const env = configuration({ ...settings, OIDC_CLIENT_SECRET: "fixture-only", ACTION_POLICY_KEY: "p".repeat(40) });
  const app = createApp(store, env);
  const get = route => app(new Request(env.origin + route));
  assert.deepEqual(await (await get("/readyz")).json(), { service: "onesa-identity", ready: true });
  renameSync(path, join(dir, "removed.sqlite"));
  assert.equal((await get("/readyz")).status, 503);
  writeFileSync(path, "");
  assert.equal((await get("/readyz")).status, 503);
  assert.equal((await get("/account")).status, 503);
  assert.equal((await app(new Request(env.origin + "/internal/decision", {
    method: "POST", headers: { authorization: "Bearer " + env.policyKey },
    body: JSON.stringify({ subject: "fixture", client: env.clientId, audience: "" }),
  }))).status, 503);
  assert.equal((await get("/health")).status, 200);
});
