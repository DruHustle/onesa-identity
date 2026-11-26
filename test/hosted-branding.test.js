import test from "node:test";
import assert from "node:assert/strict";
import { syncBranding } from "../auth0/branding/sync.js";

function tenant(initialTheme) {
  let theme = initialTheme;
  const prompts = new Map();
  const writes = [];
  const request = async (path, method, body) => {
    if (method !== "GET") writes.push([method, path]);
    if (path === "/branding/themes/default") return structuredClone(theme);
    if (path.startsWith("/branding/themes")) {
      theme = { ...structuredClone(body), themeId: "test" };
      return;
    }
    if (method === "GET") return structuredClone(prompts.get(path) ?? {});
    prompts.set(path, structuredClone(body));
  };
  return { prompts, writes, request, current: () => theme };
}

test("installs a new default theme and verifies both login flow types in both languages", async () => {
  const t = tenant(null);
  assert.equal((await syncBranding(t.request)).length, 9);
  assert.deepEqual(t.writes, []);
  await syncBranding(t.request, true);
  assert.deepEqual(t.writes[0], ["POST", "/branding/themes"]);
  assert.equal(t.prompts.get("/prompts/signup-id/custom-text/de")["signup-id"].title, "Konto erstellen");
  assert.deepEqual(await syncBranding(t.request), []);
  const count = t.writes.length;
  await syncBranding(t.request, true);
  assert.equal(t.writes.length, count);
});

test("preserves unmanaged tenant fields and unrelated localized prompt overrides", async () => {
  const t = tenant({ themeId: "test", widget: { extra: true }, fonts: { font_url: "https://example.org/font.woff2" } });
  const path = "/prompts/login/custom-text/en";
  t.prompts.set(path, { login: { forgotPasswordText: "Recover account" }, other: { title: "Keep" } });
  await syncBranding(t.request, true);
  assert.deepEqual(t.writes[0], ["PATCH", "/branding/themes/test"]);
  assert.equal(t.current().widget.extra, true);
  assert.equal(t.current().fonts.font_url, "https://example.org/font.woff2");
  assert.equal(t.prompts.get(path).login.title, "Sign in");
  assert.equal(t.prompts.get(path).login.forgotPasswordText, "Recover account");
  assert.equal(t.prompts.get(path).other.title, "Keep");
  assert.match(t.prompts.get(path).login.description, /\$\{clientName\}/);
});
