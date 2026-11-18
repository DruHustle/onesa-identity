/**
 * Commission the account.onesa.eu Cloudflare ingress only after the existing
 * Oracle Onesa Identity service passes its own readiness and OIDC checks.
 *
 * Run on the Oracle host (the tunnel's origin), not from an unrelated CI host.
 * This does not create a new identity database, import users or issue secrets.
 * By default it only performs preflight; --apply performs a guarded cutover.
 */
import {readFileSync} from "node:fs";
import {pathToFileURL} from "node:url";

const account = "https://account.onesa.eu";
const issuer = "https://auth.onesa.eu";
const cfAccount = "ffe41f6678793e8dcc7f4a1c2f5e60d8";
const tunnel = "bf605976-0d3d-4d5a-9260-7b92ef74af07";
const cfUrl = "https://api.cloudflare.com/client/v4/accounts/" + cfAccount +
  "/cfd_tunnel/" + tunnel + "/configurations";
const hostname = "account.onesa.eu";
const disabled = "http_status:503";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

export function accountRoute(config) {
  assert(config && typeof config === "object" && Array.isArray(config.ingress),
    "Tunnel ingress is missing");
  const found = config.ingress.map((rule, index) => ({rule, index}))
    .filter(({rule}) => rule.hostname === hostname);
  assert(found.length === 1 && !found[0].rule.path,
    "Expected exactly one account hostname rule without a path");
  const last = config.ingress.at(-1);
  assert(last && !last.hostname && last.service === "http_status:404",
    "Unrecognized tunnel fallback: refusing to replace ingress");
  return found[0];
}

export function withAccountService(config, port) {
  assert(Number.isInteger(port) && port >= 1024 && port <= 65535,
    "IDENTITY_HOST_PORT must be an unprivileged TCP port");
  const {rule, index} = accountRoute(config);
  const target = "http://127.0.0.1:" + port;
  assert(rule.service === disabled || rule.service === target,
    "Account is not in the expected maintenance state; refusing overwrite");
  return {...config, ingress: config.ingress.map((entry, i) =>
    i === index ? {...entry, service: target} : entry)};
}

export function authorizeRedirect(location) {
  assert(typeof location === "string" && location.length <= 8192,
    "Missing OIDC authorization redirect");
  const u = new URL(location);
  assert(u.origin === issuer && u.pathname === "/authorize" &&
    u.searchParams.get("redirect_uri") === account + "/callback" &&
    u.searchParams.get("response_type") === "code" &&
    u.searchParams.get("code_challenge_method") === "S256" &&
    /^[A-Za-z0-9_-]{32,128}$/.test(u.searchParams.get("state") || "") &&
    /^[A-Za-z0-9_-]{32,128}$/.test(u.searchParams.get("nonce") || "") &&
    /^[A-Za-z0-9_-]{43,128}$/.test(u.searchParams.get("code_challenge") || "") &&
    !!u.searchParams.get("client_id"),
    "Onesa Account did not start a valid Auth0 Code + PKCE flow");
}

const enrollments = [
  ["user", "farmer", "web"],
  ["admin", "portal", "web"],
  ["user", "pasofi", "ios"],
];

async function fetchChecked(url, options = {}) {
  return fetch(url, {redirect: "manual", signal: AbortSignal.timeout(10000), ...options});
}

export async function verifyAccount(origin, fetcher = fetchChecked) {
  const ready = await fetcher(origin + "/readyz");
  assert(ready.status === 200, "Identity readiness did not return 200");
  const marker = await ready.json();
  assert(marker.service === "onesa-identity" && marker.ready === true,
    "Wrong service or uncommissioned Identity database");
  const page = await fetcher(origin + "/account");
  assert(page.status === 200, "Account landing did not return 200");
  assert((await page.text()).includes("Onesa Account"),
    "Account landing is not served by Onesa Identity");
  const denied = await fetcher(origin + "/internal/decision", {
    method: "POST", headers: {"content-type": "application/json"},
    body: JSON.stringify({subject:"readiness-probe",audience:"",client:""}),
  });
  assert(denied.status === 401, "Identity policy endpoint did not deny an unauthenticated request");
  for (const [tier, product, platform] of enrollments) {
    const query = new URLSearchParams({audience:tier,product,platform});
    const response = await fetcher(origin + "/register?" + query);
    assert(response.status === 303, "Registration entry failed for " + product + "/" + platform + "/" + tier);
    authorizeRedirect(response.headers.get("location"));
  }
}

async function cloudflare(method, token, config) {
  const res = await fetchChecked(cfUrl, {
    method, headers: {authorization:"Bearer " + token,
      ...(config ? {"content-type":"application/json"} : {})},
    ...(config ? {body: JSON.stringify({config})} : {}),
  });
  assert(res.ok, "Cloudflare Tunnel API returned HTTP " + res.status);
  const body = await res.json();
  assert(body.success === true && body.result, "Cloudflare Tunnel API rejected the request");
  return body.result;
}

async function main() {
  assert(process.argv.slice(2).every(x => x === "--apply") &&
    process.argv.slice(2).filter(x => x === "--apply").length <= 1,
    "Only --apply is supported");
  const port = Number(process.env.IDENTITY_HOST_PORT);
  assert(Number.isInteger(port) && port >= 1024 && port <= 65535,
    "IDENTITY_HOST_PORT is required");
  const secretFile = process.env.CLOUDFLARE_API_TOKEN_FILE;
  assert(!(secretFile && process.env.CLOUDFLARE_API_TOKEN),
    "Use either CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_TOKEN_FILE");
  const token = secretFile ?
    readFileSync(secretFile, "utf8").trim() :
    process.env.CLOUDFLARE_API_TOKEN;
  assert(typeof token === "string" && token.length >= 24,
    "A Cloudflare Tunnel Write token is required");
  const local = "http://127.0.0.1:" + port;
  await verifyAccount(local);
  console.log("Local commissioned Onesa Account passed readiness and PKCE preflight");
  const before = await cloudflare("GET", token);
  assert(before.source === "cloudflare", "Tunnel configuration is not remotely managed");
  const proposed = withAccountService(before.config, port);
  if (process.argv[2] !== "--apply") {
    console.log("DRY RUN: account.onesa.eu is eligible for routing to " + local);
    return;
  }
  assert(accountRoute(before.config).rule.service === disabled,
    "Account ingress has already been changed; refusing another cutover");
  await cloudflare("PUT", token, proposed);
  try {
    const updated = await cloudflare("GET", token);
    assert(JSON.stringify(updated.config) === JSON.stringify(proposed),
      "Tunnel did not retain the expected complete ingress configuration");
    await verifyAccount(account);
    const publicIssuer = await fetchChecked(issuer + "/.well-known/openid-configuration");
    assert(publicIssuer.status === 200 &&
      (await publicIssuer.json()).issuer === issuer + "/",
      "Production Auth0 issuer discovery is unavailable");
  } catch (error) {
    // Do not overwrite a newer, independently edited tunnel configuration.
    try {
      const current = await cloudflare("GET", token);
      if (JSON.stringify(current.config) === JSON.stringify(proposed)) {
        await cloudflare("PUT", token, before.config);
        console.error("Cloudflare account ingress rolled back to maintenance");
      } else {
        console.error("Concurrent ingress modification detected; manual incident review required");
      }
    } catch {
      console.error("Rollback could not be verified; manual incident review required");
    }
    throw error;
  }
  console.log("ACTIVE: account.onesa.eu serves Onesa Identity with verified PKCE registration");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    console.error("Account tunnel activation failed: " + error.message);
    process.exitCode = 1;
  });
}
