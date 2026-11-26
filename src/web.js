import * as oidc from "openid-client";
import qrcode from "qrcode-generator";
import { infrastructureEntry, isRegistrationEntry, pasofiHotspotEntry, returnKey } from "./registration-returns.js";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { accountAuthenticator } from "./authenticator.js";
import {
  secret, digest, Rejected, products, accountProducts, registrations,
  productAdministratorRequests, sharedRole, configurableAdminRoles, platformGrant,
} from "./store.js";

const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const compare = (a, b) =>
  typeof a === "string" &&
  typeof b === "string" &&
  timingSafeEqual(Buffer.from(digest(a)), Buffer.from(digest(b)));
const enrollmentCallback = (resource, client, redirectUri) =>
  typeof redirectUri === "string" &&
  resource?.enrollmentCallbacks?.some(callback =>
    callback.redirectUri === redirectUri && (client === undefined || callback.client === client));
const cookie = (name, value, seconds) =>
  "__Host-onesa-" +
  name +
  "=" +
  value +
  "; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=" +
  seconds;
const readCookie = (req, key) =>
  (req.headers.get("cookie") ?? "")
    .split(/;\s*/)
    .find((c) => c.startsWith("__Host-onesa-" + key + "="))
    ?.split("=")[1] ?? "";
const page = (title, body, status = 200, wide = false, administration = false, resume = null) =>
  new Response(`<!doctype html><html lang="en"><head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    ${resume ? '<meta http-equiv="refresh" content="0;url=' + esc(resume) + '">' : ""}
    <title>${esc(title)} · Onesa Account</title>
    <style>
      * { box-sizing: border-box; }
      body { margin: 0; padding: 24px clamp(16px, 5vw, 64px) 48px; background: #F5F8F7; color: #172B4D; font: 1rem/1.55 Arial, Helvetica, sans-serif; }
      header { max-width: 68rem; margin: 0 auto 28px; padding: 8px 0 18px; display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px; border-bottom: 1px solid #D9E6E1; }
      header > a { display: flex; align-items: center; gap: 11px; color: #102B29; font-weight: 700; letter-spacing: -.02em; text-decoration: none; }
      header img { width: 36px; height: 36px; }
      main { margin: auto; max-width: 38rem; padding: clamp(22px, 5vw, 36px); background: #FFFFFF; border: 1px solid #D9E6E1; border-top: 4px solid #00B894; border-radius: 18px; box-shadow: 0 16px 48px rgba(16, 43, 41, .08); overflow-wrap: anywhere; }
      main.wide { max-width: 68rem; }
      h1 { margin: 0 0 16px; color: #102B29; font-size: clamp(1.75rem, 5vw, 2.25rem); line-height: 1.12; letter-spacing: -.045em; }
      h2 { margin: 1.5rem 0 .5rem; font-size: 1.25rem; }
      p { margin: 0 0 1rem; }
      .muted { color: #526B69; }
      article { margin: 1rem 0; padding: 1rem; border: 1px solid #D9E6E1; border-radius: 10px; background: #FBFDFC; }
      .actions, nav { display: flex; flex-wrap: wrap; align-items: center; gap: .75rem 1.25rem; }
      .account-summary, .account-panel { padding: clamp(16px, 3vw, 24px); border: 1px solid #D9E6E1; border-radius: 14px; }
      .account-summary { margin-bottom: 16px; background: #F0F8F5; }
      .account-summary p, .account-panel p:last-child { margin-bottom: 0; }
      .account-summary .muted { margin-top: .55rem; }
      .account-grid { display: grid; grid-template-columns: minmax(0, 3fr) minmax(0, 2fr); align-items: start; gap: 16px; }
      .account-side { display: grid; gap: 16px; }
      .account-panel h2 { margin: 0 0 .6rem; color: #102B29; }
      .account-panel form label { margin: 0; }
      .account-panel .actions { align-items: end; gap: .5rem; }
      .account-panel details summary { padding: .45rem 0; cursor: pointer; color: #365753; }
      .account-panel details[open] summary { margin-bottom: .35rem; }
      .status-pill { display: inline-block; border-radius: 999px; padding: .18rem .62rem; background: #E8EDF3; color: #31445D; font-size: .875rem; font-weight: 700; }
      .status-active { background: #DDF1E7; color: #165440; }
      .status-pending { background: #FFF0D3; color: #6B430C; }
      .products { display: grid; gap: .55rem; padding: 0; margin: .75rem 0 1rem; list-style: none; }
      .products li { display: grid; gap: .35rem; padding: .75rem; border: 1px solid #D9E6E1; border-radius: 10px; }
      .products li:target { border-color: #0B725E; background: #F0F8F5; }
      .product-states { display: flex; flex-wrap: wrap; align-items: center; gap: .35rem; }
      .intranet-areas { display: grid; gap: .5rem; }
      .intranet-area { display: grid; gap: .35rem; padding: .55rem 0 0; border-top: 1px solid #D9E6E1; }
      .account-footer { margin-top: 16px; }
      .authenticator-setup { margin-bottom: 1.5rem; }
      .authenticator-qr { display: block; max-width: min(100%, 260px); height: auto; margin: 0 0 .5rem; image-rendering: pixelated; }
      .authenticator-manual summary { width: fit-content; min-height: 44px; padding: .6rem 0; cursor: pointer; color: #087F68; }
      .authenticator-manual p { margin-bottom: .5rem; }
      .authenticator-verification form { display: grid; gap: .75rem; max-width: 20rem; }
      .authenticator-verification label { margin: 0; gap: .375rem; font-weight: 600; }
      .authenticator-verification input { width: 100%; font-variant-numeric: tabular-nums; }
      .authenticator-verification button { width: 100%; justify-content: center; font-weight: 700; }
      .identity-admin { display: grid; gap: 1.5rem; }
      .identity-admin h2 { margin: 0 0 .65rem; color: #102B29; }
      .identity-admin h3 { margin: 0 0 .5rem; color: #102B29; font-size: 1rem; }
      .identity-admin label { min-width: 0; margin: 0; gap: .35rem; font-weight: 600; }
      .identity-admin :is(input, select) { width: 100%; }
      .identity-admin button { font-weight: 600; }
      .admin-toolbar { display: grid; grid-template-columns: minmax(0, 2fr) minmax(0, 1fr); align-items: start; gap: 1rem; }
      .admin-form form, .admin-search { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: end; gap: .65rem; }
      .admin-panel, .admin-account { border: 1px solid #D9E6E1; border-radius: 12px; background: #FBFDFC; }
      .identity-admin summary { cursor: pointer; }
      .admin-panel > summary { padding: .8rem 1rem; font-weight: 700; color: #102B29; }
      .admin-panel-body { padding: 0 1rem 1rem; }
      .admin-panel-body p:last-child { margin-bottom: 0; }
      .admin-list { display: grid; gap: .6rem; margin: 0; padding: 0; list-style: none; }
      .admin-account > summary { display: grid; grid-template-columns: minmax(0, 1fr) auto auto; align-items: center; gap: .55rem 1rem; padding: .85rem 1rem; }
      .admin-account > summary::-webkit-details-marker { display: none; }
      .admin-account > summary::after { content: ""; width: .5rem; height: .5rem; border: solid #526B69; border-width: 0 2px 2px 0; transform: rotate(45deg); }
      .admin-account[open] > summary::after { transform: rotate(225deg); }
      .admin-account-meta { display: flex; flex-wrap: wrap; gap: .4rem; justify-content: end; }
      .admin-account-body { padding: 1rem; border-top: 1px solid #D9E6E1; background: white; border-radius: 0 0 12px 12px; }
      .admin-account-body > * + * { margin-top: 1rem; }
      .admin-account-body > p { margin-bottom: 0; }
      .admin-detail { display: grid; gap: .6rem; }
      .admin-detail > * { margin: 0; }
      .admin-row { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: .6rem 1rem; padding: .75rem; border: 1px solid #D9E6E1; border-radius: 8px; }
      .admin-row p { margin: 0; }
      .admin-identity { display: grid; gap: .2rem; min-width: 0; }
      .admin-actions { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; }
      .admin-actions button[value="active"] { background: #0B725E; border-color: #0B725E; color: white; }
      .admin-actions button[value="active"]:hover { background: #095C4D; border-color: #095C4D; }
      .admin-actions button[value="deleted"] { color: #8F2934; border-color: #CBA6AB; }
      .admin-actions button[value="deleted"]:hover { background: #FFF3F4; }
      .admin-access form { grid-template-columns: minmax(0, 2fr) minmax(0, 1fr) auto; }
      .admin-audit { max-height: 30rem; overflow: auto; }
      .admin-audit details { border-bottom: 1px solid #D9E6E1; }
      .admin-audit summary { padding: .6rem 0; }
      .admin-audit time { color: #526B69; font-size: .875rem; }
      .admin-audit p { margin: .25rem 0; }
      .admin-audit pre { margin: .5rem 0; white-space: pre-wrap; }
      @media (max-width: 700px) { .admin-toolbar { grid-template-columns: 1fr; } }
      @media (max-width: 460px) {
        .admin-form form, .admin-search { grid-template-columns: 1fr; }
        .admin-account > summary { grid-template-columns: minmax(0, 1fr) auto; }
        .admin-account > summary::after { grid-column: 2; grid-row: 1; }
        .admin-account-meta { grid-column: 1 / -1; justify-content: start; }
      }
      @media (max-width: 700px) { .account-grid { grid-template-columns: 1fr; } }
      label { display: inline-grid; max-width: 100%; margin: .3rem; gap: .2rem; }
      a { color: #087F68; text-underline-offset: 3px; }
      a:hover { color: #065C4E; }
      input, select, button, .primary { max-width: 100%; min-height: 44px; padding: .55rem .75rem; font: inherit; border: 1px solid #9AAEAA; border-radius: 10px; background: white; color: #172B4D; }
      button, .primary { cursor: pointer; }
      .primary { display: inline-flex; align-items: center; background: #0B725E; border-color: #0B725E; color: white; text-decoration: none; }
      .primary:hover { background: #095C4D; border-color: #095C4D; }
      :is(a, button, input, select, summary):focus-visible { outline: 3px solid #00B894; outline-offset: 3px; }
    </style></head><body>
    <header><a href="/account"><img src="https://onesa.eu/brand/icons/v1/onesa-company-180.png" alt="" width="32" height="32">Onesa Account</a>
    <nav aria-label="Account"><a href="/account">My account</a>${administration ? '<a href="/admin">Administration</a>' : ""}</nav></header>
    <main${wide ? ' class="wide"' : ""}><h1>${esc(title)}</h1>${body}</main></body></html>`,
    { status, headers: { "content-type": "text/html; charset=utf-8" } },
  );
const failureReference = () => randomUUID().replace(/-/g, "").slice(0, 12).toUpperCase();
const logSignInFailure = (reference, stage, errorClass = "Error") => {
  const safeClass = typeof errorClass === "string" && /^[A-Za-z0-9_.-]{1,64}$/.test(errorClass) ? errorClass : "Error";
  console.error(JSON.stringify({ event: "identity_sign_in_failed", reference, stage, errorClass: safeClass }));
};
const verificationPage = (destination, env, outcome) => {
  const continueLink = '<a href="' + esc(verificationRetryPath(destination, env.origin)) + '">Continue sign-in</a>';
  const resendLink = '<a class="primary" href="' + esc(verificationRetryPath(destination, env.origin, "resend")) + '">Resend verification email</a>';
  const copy = {
    required: ["Verify your email", "Open the verification email from Onesa Identity, then continue sign-in.", 403],
    accepted: ["Check your inbox", "The email provider accepted the request for a new verification email. Open it to verify your address, then continue sign-in.", 403],
    limited: ["Verification email already requested", "Check your inbox and spam folder. Wait ten minutes before requesting another email.", 429],
    unavailable: ["Verification email unavailable", "Onesa could not confirm the email request. Try again later or contact your Onesa administrator.", 503],
  };
  const [heading, text, status] = copy[outcome];
  const help = env.verification
    ? '<div class="actions">' + (outcome === "required" || outcome === "unavailable" ? resendLink : "") + continueLink + '</div>'
    : '<p>If the email did not arrive, ask your Onesa administrator to resend it.</p>' + continueLink;
  return page(heading, '<p>' + text + '</p>' + help, status);
};
const verificationOutcomes = new Map([
  ["Onesa email verification is required.", "required"],
  ["Onesa email verification request accepted.", "accepted"],
  ["Onesa email verification request is rate limited.", "limited"],
  ["Onesa email verification request unavailable.", "unavailable"],
]);
const signInFailure = (code, description, destination, env) => {
  const outcome = code === "access_denied" && verificationOutcomes.get(description);
  if (outcome) return verificationPage(destination, env, outcome);
  const origin = env.origin;
  const retry = '<a href="' + esc(retryPath(destination, origin)) + '">Try sign-in again</a>';
  const messages = {
    access_denied: ["Access not approved", "Onesa could not approve access for this sign-in. Check that your email is verified, your account is active, and the required product role has been assigned. If you believe this is a mistake, contact your Onesa administrator.", 403],
    login_required: ["Sign-in session expired", "Your sign-in session expired before it could finish. Start again from the product you were trying to access.", 401],
    interaction_required: ["Sign-in needs another step", "The sign-in flow needs you to complete an additional step. Start again and finish any verification or multi-factor prompt.", 401],
    consent_required: ["Authorization needs to be renewed", "Onesa needs you to restart sign-in so it can renew the authorization for this application.", 401],
    temporarily_unavailable: ["Sign-in service temporarily unavailable", "The identity provider is temporarily unable to complete sign-in. Wait a moment, then retry.", 503],
    server_error: ["Sign-in service error", "The identity provider could not complete the request. Retry in a moment. If it keeps happening, contact Onesa support.", 502],
    invalid_request: ["Sign-in request could not be validated", "The sign-in request is incomplete or expired. Return to the product and start sign-in again.", 400],
    invalid_grant: ["Sign-in could not be completed", "The authorization code expired or was already used. Start a fresh sign-in from the product.", 400],
    mfa_required: ["Multi-factor authentication required", "Complete the multi-factor prompt to continue. If no prompt appears, restart sign-in and try again.", 403],
    mfa_enrollment_needed: ["Authenticator setup required", "Set up the required authenticator for your Onesa account, then retry sign-in.", 403],
    account_disabled: ["Onesa account disabled", "This Onesa account is disabled. Contact your Onesa administrator if you believe this is a mistake.", 403],
  };
  const known = Object.hasOwn(messages, code) ? messages[code] : null;
  if (known) {
    let detail = "";
    if (code === "access_denied" && /could not verify a fresh second factor/i.test(description || ""))
      detail = "Onesa could not verify a recent multi-factor check. Sign in again and complete the authenticator prompt.";
    else if (code === "access_denied" && /access is temporarily unavailable|access is unavailable for this application/i.test(description || ""))
      detail = "Onesa access policy is unavailable right now. Wait a moment and retry.";
    return page(known[0], esc(detail || known[1]) + " " + retry, known[2]);
  }
  const reference = failureReference();
  logSignInFailure(reference, "provider_callback", "UnrecognizedOAuthError");
  return page("Sign-in could not be completed", "Onesa received an unexpected sign-in response. Retry from the product. If it happens again, contact support and provide reference <strong>" + reference + "</strong>. " + retry, 502);
};
const redirect = (url, cookies = []) => {
  const headers = new Headers({ location: url });
  for (const c of cookies) headers.append("set-cookie", c);
  return new Response(null, { status: 303, headers });
};
const accountSections = new Set(["#product-access", "#administrator-access", "#account-security", "#account-closure"]);
const retryPath = (destination, origin) => {
  const target = new URL(destination, origin);
  const factorRoute = target.searchParams.get("_factor");
  target.searchParams.delete("_factor");
  target.searchParams.delete("_factor_primary");
  if (factorRoute === "/step-up" || factorRoute === "/verify-factor")
    return factorRoute + "?return=" + encodeURIComponent(target.pathname + target.search + target.hash);
  const invite = target.searchParams.get("invite");
  const tier = target.searchParams.get("enrollment");
  if (tier === "admin" || tier === "user") {
    const query = new URLSearchParams({ audience: tier });
    for (const key of ["invite", "product", "platform", "entry"])
      if (target.searchParams.has(key)) query.set(key, target.searchParams.get(key));
    return "/login?" + query;
  }
  if (invite && /^[A-Za-z0-9_-]{43}$/.test(invite))
    return "/login?invite=" + encodeURIComponent(invite);
  if (target.pathname === "/account" && accountSections.has(target.hash))
    return "/login?return=" + encodeURIComponent("/account" + target.hash);
  return target.pathname === "/admin"
    ? "/login?return=" + encodeURIComponent(
        "/admin" + (target.searchParams.has("product")
          ? "?product=" + encodeURIComponent(target.searchParams.get("product"))
          : ""),
      )
    : "/login";
};
const verificationRetryPath = (destination, origin, action = "continue") => {
  const retry = new URL(retryPath(destination, origin), origin);
  retry.searchParams.set("email_verification", action);
  return retry.pathname + retry.search;
};
const hidden = (key, value) =>
  '<input type="hidden" name="' + key + '" value="' + esc(value) + '">';
const post = (path, csrf, body) =>
  '<form method="post" action="' +
  path +
  '">' +
  hidden("csrf", csrf) +
  body +
  "</form>";
const options = (items, selected) =>
  items.map((item) =>
    (item === selected ? "<option selected>" : "<option>") + esc(item) + "</option>"
  ).join("");
const accessLabels = { pending: "Awaiting approval", active: "Approved", revoked: "Access removed", rejected: "Request declined" };
const administratorLabels = {
  pending: "Administrator request pending",
  active: "Administrator approved",
  rejected: "Administrator request declined",
  revoked: "Administrator access removed",
};
const pill = (status, label) => '<span class="status-pill status-' + esc(status) + '">' + esc(label) + "</span>";
const intranet = new Map([["portal", "Portal"], ["internal-documents", "Internal documents"]]);
const intranetName = "Onesa Intranet";
const adminLabel = value => value === "hr" ? "HR" : value.charAt(0).toUpperCase() + value.slice(1).replaceAll("-", " ");
const adminEmail = email => "<!--email_off-->" + esc(email) + "<!--/email_off-->";
const deleteRequestButton = '<button name="status" value="deleted">Delete request</button>';
const adminProductName = product => {
  if (intranet.has(product)) return intranetName + " · " + intranet.get(product);
  if (product === "identity") return "Onesa Identity";
  if (product === "engineering-documents") return "Engineering Documents";
  return accountProducts.get(product)?.name || adminLabel(product);
};
const auditDate = new Intl.DateTimeFormat("en-GB", {
  dateStyle: "medium", timeStyle: "short", timeZone: "UTC",
});
const presentedProducts = (entries) => new Map(Array.from(entries, ([product, entry]) =>
  intranet.has(product) ? ["intranet", { name: intranetName }] : [product, entry]));
const productSelect = (label, entries) =>
  '<label>' + esc(label) + '<select name="product" required><option value="" disabled selected>Choose a product</option>' +
  Array.from(presentedProducts(entries), ([product, { name }]) => '<option value="' + esc(product) + '">' + esc(name) + "</option>").join("") +
  "</select></label>";
const mfaClaim = "https://onesa.eu/claims/mfa_time";
const freshFactor = (factor, now) => Number.isSafeInteger(factor) &&
  factor > 0 && factor <= now && now - factor <= 300000;
function factorVerification(title, destination, message, status = 403) {
  return page(title, '<p>' + esc(message) + '</p><p><a class="primary" href="' +
    esc(destination) + '">Verify with your authenticator</a></p>', status);
}
function authenticatorSetup(email, key) {
  if (!key) return "";
  const account = encodeURIComponent(email.replaceAll(":", " "));
  const qr = qrcode(0, "M");
  qr.addData("otpauth://totp/Onesa:" + account + "?secret=" + key + "&issuer=Onesa");
  qr.make();
  return '<div class="authenticator-setup">' +
    '<p>Open your authenticator app, add an account, and scan this QR code. Then enter the six-digit code it shows.</p>' +
    '<img class="authenticator-qr" src="' + qr.createDataURL(5) + '" alt="Onesa authenticator setup QR code">' +
    '<details class="authenticator-manual"><summary>Enter a setup key instead</summary>' +
    '<p>Add a time-based account called Onesa using this key.</p>' +
    '<p><code aria-label="Authenticator setup key">' + esc(key) + '</code></p></details></div>';
}
async function sendVerificationEmail(verification, subject, accountClient) {
  const options = {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(5000),
  };
  const response = await fetch(verification.origin + "/oauth/token", {
    ...options,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      grant_type: "client_credentials",
      audience: verification.origin + "/api/v2/",
      scope: "update:users",
      client_id: verification.clientId,
      client_secret: verification.clientSecret,
    }),
  });
  if (!response.ok) return false;
  const { access_token, token_type } = await response.json();
  if (typeof access_token !== "string" || !/^[A-Za-z0-9._~-]{16,16384}$/.test(access_token) ||
      typeof token_type !== "string" || token_type.toLowerCase() !== "bearer")
    return false;
  const job = await fetch(verification.origin + "/api/v2/jobs/verification-email", {
    ...options,
    headers: { authorization: "Bearer " + access_token, "content-type": "application/json" },
    body: JSON.stringify({ user_id: subject, client_id: accountClient }),
  });
  return job.ok;
}
export function authClient(env, transport) {
  let configured;
  async function get() {
    if (!configured) {
      const result = await oidc.discovery(
        new URL(env.issuer),
        env.clientId,
        {
          client_secret: env.clientSecret,
          id_token_signed_response_alg: "RS256",
        },
        undefined,
        transport ? { [oidc.customFetch]: transport } : undefined,
      );
      oidc.enableNonRepudiationChecks(result);
      configured = result;
    }
    return configured;
  }
  return {
    async authorize(args) {
      return oidc.buildAuthorizationUrl(await get(), args).href;
    },
    async redeem(url, challenge) {
      const tokens = await oidc.authorizationCodeGrant(await get(), url, {
        expectedNonce: challenge.nonce,
        expectedState: challenge.state,
        pkceCodeVerifier: challenge.verifier,
        idTokenExpected: true,
        ...factorAge(challenge.destination, env.origin),
      });
      return tokens.claims();
    },
  };
}
function factorAge(destination, origin) {
  const params = new URL(destination, origin).searchParams;
  if (!params.has("_factor")) return {};
  return { maxAge: params.get("_factor_primary") === "reuse" ? 1800 : 300 };
}
export function createApp(store, env, client = authClient(env)) {
  const authenticator = env.authenticatorKey ? accountAuthenticator(store, env.authenticatorKey) : null;
  const pasoFiFactorPath = "/account/pasofi-authenticator";
  const sessionLookup = `SELECT s.*,a.email,a.status AS state FROM sessions s JOIN accounts a USING(id)
    WHERE hash=? AND expires>? AND a.status IN ('active','pending')`;
  const returns = env.registrationReturns ?? new Map();
  function browserResumes(req) {
    return store.all("SELECT state,destination FROM registration_resumes WHERE hash=? AND expires>? ORDER BY expires DESC",
      digest(readCookie(req, "registration")), Date.now());
  }
  const connectedProducts = new Set(Array.from(env.resources.values(), item => item.product));
  const requestedProducts = product => product === "intranet"
    ? [...intranet.keys()].filter(scope => connectedProducts.has(scope))
    : connectedProducts.has(product) && accountProducts.has(product) ? [product] : [];
  const adminEnabled = new Set(Array.from(env.resources.values())
    .filter(resource => ["admin", "administrator"].includes(resource.sharedAdminRole))
    .map(resource => resource.product));
  function productPanels(session) {
    const tiers = registrations(store.db, session.id);
    const decisions = new Map(store.all(
      "SELECT product,status,role FROM grants WHERE id=?", session.id,
    ).map(row => [row.product, row]));
    const administrators = new Set(store.all(
      "SELECT product FROM product_administrators WHERE id=? AND status='active'", session.id,
    ).map(row => row.product));
    const requests = productAdministratorRequests(store.db, session.id);
    const rows = [];
    const intranetAreas = [];
    const additionalAccess = [];
    const additionalAdministrator = [];
    for (const [product, { name }] of accountProducts) {
      const legacy = product === "internal-documents" && decisions.get("engineering-documents");
      let decision = decisions.get(product) || legacy;
      const connected = connectedProducts.has(product);
      const inherited = connected && sharedRole(product, tiers, adminEnabled.has(product));
      if (!decision && inherited) decision = { status: "active", role: inherited };
      const administrator = administrators.has(product) ||
        (decision?.status === "active" && ["administrator", "owner"].includes(decision.role));
      const request = administrator ? "active" : requests.get(product);
      const entry = [product, { name }];
      if (connected && !decision && !administrator) additionalAccess.push(entry);
      if (connected && !request) additionalAdministrator.push(entry);
      if (!decision && !request) continue;
      const label = legacy && !decisions.has(product) ? "Internal Documents (Engineering)" : intranet.get(product) || name;
      const states = [];
      if (decision && (!administrator || !["administrator", "owner"].includes(decision.role))) {
        const status = decision.status === "active" && session.state === "pending" ? "pending" : decision.status;
        const copy = status === "active" ? "Approved · " + decision.role :
          status === decision.status ? accessLabels[status] : "Waiting for account approval";
        states.push(pill(status, copy));
      }
      if (request) states.push(request === "active" && session.state === "pending"
        ? pill("pending", "Administrator access waiting for account approval")
        : pill(request, administratorLabels[request]));
      const destination = returns.get(returnKey(product, "web", administrator ? "admin" : "user"));
      const open = connected && session.state === "active" && destination &&
        (administrator || decision?.status === "active")
        ? '<a href="' + esc(destination) + '">Open ' + esc(intranet.get(product) || name) + '</a>' : "";
      const summary = '<strong>' + esc(label) + '</strong>' +
        '<div class="product-states">' + states.join("") + "</div>" + open;
      if (intranet.has(product)) intranetAreas.push('<div class="intranet-area" id="access-' + esc(product) + '">' + summary + '</div>');
      else rows.push('<li id="access-' + esc(product) + '">' + summary + "</li>");
    }
    if (intranetAreas.length) rows.unshift('<li id="access-intranet"><strong>' + intranetName +
      '</strong><div class="intranet-areas">' + intranetAreas.join("") + '</div></li>');
    const accountAccess = '<section class="account-panel" aria-labelledby="product-access"><h2 id="product-access">Product access</h2>' +
      (rows.length ? '<ul class="products">' + rows.join("") + '</ul>' : '<p>No product access requests yet.</p>') +
      (additionalAccess.length ? post("/account/access", session.csrf, '<div class="actions">' +
        productSelect("Additional product", additionalAccess) + "<button>Request access</button></div>") : "") +
      (tiers.size ? '<details><summary>Earlier Onesa registration requests</summary>' +
        [...tiers].map(([tier, status]) => "<p>" + (tier === "admin" ? "Administrator" : "User") + " · " +
          esc(accessLabels[status]) + "</p>").join("") + "</details>" : "") + "</section>";
    const administratorAccess = '<section class="account-panel" aria-labelledby="administrator-access">' +
      '<h2 id="administrator-access">Administrator access</h2><p>Choose the product you need to administer. A reviewer must approve your request.</p>' +
      (additionalAdministrator.length ? post("/account/enrollment", session.csrf, hidden("tier", "admin") +
        '<div class="actions">' + productSelect("Product", additionalAdministrator) +
        "<button>Request administrator access</button></div>") :
        '<p>See your administrator access status under <a href="#product-access">Product access</a>.</p>') + "</section>";
    return { accountAccess, administratorAccess };
  }
  async function handle(req) {
    const url = new URL(req.url),
      p = url.pathname,
      method = req.method;
    if (url.origin !== env.origin) return page("Unknown origin", "", 400);
    if (p === "/health" && method === "GET")
      return Response.json({ status: "ok" });
    if (!store.currentFile())
      return new Response(null, { status: 503 });
    if (p === "/readyz" && method === "GET") {
      store.one("SELECT id FROM accounts LIMIT 1");
      return Response.json({ service: "onesa-identity", ready: true });
    }
    if (p === "/internal/email-verification" && method === "POST") {
      if (!compare(req.headers.get("authorization"), "Bearer " + env.policyKey))
        return new Response(null, { status: 401 });
      const { subject, client: requester } = await req.json();
      if (requester !== env.clientId || typeof subject !== "string" ||
          !/^auth0\|[A-Za-z0-9_-]{1,128}$/.test(subject))
        return new Response(null, { status: 403 });
      if (!env.verification) return new Response(null, { status: 503 });
      const account = store.lookup(env.issuer, subject);
      if (account && ["suspended", "rejected"].includes(account.status))
        return new Response(null, { status: 403 });
      const now = Date.now();
      const claimed = store.atomic(() => {
        store.run("DELETE FROM verification_email_limit WHERE next<=?", now);
        return store.run("INSERT OR IGNORE INTO verification_email_limit VALUES (?,?)",
          digest(subject), now + 600000).changes;
      });
      if (!claimed) return new Response(null, { status: 429 });
      try {
        if (await sendVerificationEmail(env.verification, subject, env.clientId))
          return new Response(null, { status: 202 });
      } catch {
        // Delivery is ambiguous after an upstream timeout. Retain the cooldown.
      }
      return new Response(null, { status: 503 });
    }
    if (["/internal/pasofi-authenticator/start", "/internal/pasofi-authenticator/finish"].includes(p) && method === "POST") {
      if (!authenticator || !compare(req.headers.get("authorization"), "Bearer " + env.policyKey))
        return new Response(null, { status: 401 });
      const { subject, clientId, audience, receipt, state, continuation, allowEnrollment } = await req.json();
      const resource = env.resources.get(audience);
      const actor = typeof subject === "string" && subject.length <= 512 && store.lookup(env.issuer, subject);
      if (!actor || actor.status !== "active" || !resource?.clients.includes(clientId) ||
          (resource.product !== "pasofi" &&
            !(resource.platformAdmin === true && store.activeGrant(actor.id, platformGrant)?.role === "administrator")))
        return new Response(null, { status: 403 });
      const now = Date.now();
      if (p.endsWith("/start"))
        return Response.json({ ticket: authenticator.startPasoFi(actor.id, clientId, audience, now, continuation, allowEnrollment) });
      if ((receipt !== undefined && (typeof receipt !== "string" || !/^[\w-]{43}$/.test(receipt))) ||
          typeof state !== "string" || !/^[\w.~\-]{16,1024}$/.test(state))
        return new Response(null, { status: 403 });
      const proof = authenticator.finishPasoFi(actor.id, clientId, audience, state, receipt, now);
      return proof ? Response.json({ mfaTime: Math.floor(proof.verified_at / 1000) }) : new Response(null, { status: 403 });
    }
    if (p === pasoFiFactorPath && ["GET", "POST"].includes(method)) {
      if (!authenticator) return page("Authenticator unavailable", '<a href="/account">Open Onesa Account</a>', 503);
      const now = Date.now();
      if (method === "GET" && url.searchParams.has("ticket")) {
        const ticket = url.searchParams.get("ticket");
        const state = url.searchParams.get("state") ?? "";
        if (url.searchParams.getAll("ticket").length === 1 && url.searchParams.getAll("state").length === 1 &&
            /^[\w-]{43}$/.test(ticket) && /^[\w.~\-]{16,1024}$/.test(state)) {
          const browser = authenticator.bindPasoFi(ticket, state, now);
          if (browser) return redirect(pasoFiFactorPath, [cookie("pasofi-authenticator", browser, 300)]);
        }
        return page("Staff sign-in expired", '<a href="https://pasofi.mobile.onesa.eu/#staff">Return to PasoFi Staff</a>', 400);
      }
      const browser = readCookie(req, "pasofi-authenticator");
      const flow = authenticator.showPasoFi(browser, now);
      if (!flow) return page("Staff sign-in expired", '<a href="https://pasofi.mobile.onesa.eu/#staff">Return to PasoFi Staff</a>', 400);
      const isPasoFi = env.resources.get(flow.audience)?.product === "pasofi";
      const productName = isPasoFi ? "PasoFi" : "your app";
      if (!flow.enrolled && !flow.setupKey) {
        if (!isPasoFi) return page("Start a fresh sign-in",
          "<p>Return to the app where you started and sign in again to set up your authenticator.</p>", 403);
        if (flow.continuation === "state") return page("Start a fresh PasoFi sign-in",
          '<p>Confirm your Onesa sign-in from PasoFi before adding an authenticator.</p><a class="primary" href="https://pasofi.mobile.onesa.eu/#staff">Return to PasoFi Staff</a>', 403);
        return page("Set up your authenticator first",
          '<p>Set up your authenticator in Onesa Account with the same account you use for PasoFi Staff.</p><a class="primary" href="/account#account-security">Open account security</a>', 403);
      }
      let feedback = "";
      if (method === "POST") {
        const input = new URLSearchParams(await req.text());
        if (req.headers.get("origin") !== env.origin || !compare(input.get("csrf"), flow.csrf))
          return page("Verification request expired", isPasoFi
            ? '<a href="https://pasofi.mobile.onesa.eu/#staff">Return to PasoFi Staff</a>'
            : "<p>Return to the app where you started and sign in again.</p>", 403);
        const outcome = authenticator.verifyPasoFi(browser, input.get("code") ?? "", now);
        if (outcome.status === "verified") {
          const next = new URL("/continue", env.issuer);
          next.searchParams.set("state", outcome.state);
          if (!outcome.receipt) {
            // Chromium applies the verification form's CSP to its HTTP
            // redirects. A new document starts the provider return as a GET.
            const response = page("Returning to " + productName,
              '<p>Your authenticator was verified.</p>' +
              '<a class="primary" rel="noreferrer" href="' + esc(next.href) + '">Continue to ' + productName + '</a>',
              200, false, false, next.href);
            response.headers.set("referrer-policy", "no-referrer");
            response.headers.append("set-cookie", cookie("pasofi-authenticator", "", 0));
            return response;
          }
          const response = page("Authenticator verified",
            '<form method="post" action="' + esc(next.href) + '">' +
            hidden("onesa_factor_receipt", outcome.receipt) +
            '<button class="primary">Continue to ' + (isPasoFi ? "PasoFi Staff" : "your app") + '</button></form>');
          response.headers.set("referrer-policy", "no-referrer");
          response.headers.append("set-cookie", cookie("pasofi-authenticator", "", 0));
          return response;
        }
        if (outcome.status === "limited") return page("Wait before trying again",
          '<p>Too many codes were entered. Start a fresh staff sign-in after ten minutes.</p>', 429);
        feedback = '<p role="alert">That code could not be verified. Check the current code in your authenticator app.</p>';
      }
      return page(flow.setupKey ? (isPasoFi ? "Set up your PasoFi authenticator" : "Set up your authenticator")
        : (isPasoFi ? "Verify PasoFi staff sign-in" : "Verify administrator sign-in"),
        '<p>Verifying <strong><!--email_off-->' + esc(flow.email) + '<!--/email_off--></strong></p>' +
        authenticatorSetup(flow.email, flow.setupKey) + feedback + '<div class="authenticator-verification">' +
        post(pasoFiFactorPath, flow.csrf,
          '<label>Six-digit code<input name="code" required pattern="[0-9]{6}" maxlength="6" inputmode="numeric" autocomplete="one-time-code"></label>' +
          '<button class="primary">Verify and continue</button>') + '</div>', feedback ? 400 : 200);
    }
    if (p === "/internal/signup-entry" && method === "POST") {
      if (!compare(req.headers.get("authorization"), "Bearer " + env.policyKey))
        return new Response(null, { status: 401 });
      const { client, redirectUri } = await req.json();
      const registered = [...env.resources.values()].some(resource => enrollmentCallback(resource, client, redirectUri));
      return new Response(null, { status: registered ? 204 : 403 });
    }
    if (p === "/internal/decision" && method === "POST") {
      if (!compare(req.headers.get("authorization"), "Bearer " + env.policyKey))
        return new Response(null, { status: 401 });
      const { subject, audience, client: clientId, enrollment } = await req.json();
      if (typeof subject !== "string" || subject.length > 512 || !subject)
        return new Response(null, { status: 403 });
      let actor = store.lookup(env.issuer, subject);
      if (actor && ["suspended", "rejected"].includes(actor.status))
        return new Response(null, { status: 403 });
      if (
        clientId === env.clientId &&
        (!audience || audience === new URL("userinfo", env.issuer).href)
      )
        return Response.json({ selfservice: true });
      const resource = env.resources.get(audience);
      if (!resource || !resource.clients.includes(clientId))
        return new Response(null, { status: 403 });
      let product = resource.product;
      const platformAdministrator = resource.platformAdmin === true &&
        store.activeGrant(actor?.id ?? "", platformGrant)?.role === "administrator";
      if (platformAdministrator) return Response.json({
        user_id: actor.id, product, roles: ["administrator"], platform_administrator: true, require_mfa: true,
      });
      if (enrollment?.verified === true && enrollment.protocol === "oidc-basic-profile" &&
          enrollmentCallback(resource, clientId, enrollment.redirectUri) &&
          (!actor || !store.one("SELECT 1 FROM grants WHERE id=? AND product=?", actor.id, product))) {
        try {
          actor = store.register(env.issuer, subject, enrollment.email, "", "user", product,
            { client: clientId, subject });
        } catch (error) {
          if (error instanceof Rejected) return new Response(null, { status: 403 });
          throw error;
        }
      }
      if (actor?.status !== "active") return new Response(null, { status: 403 });
      // An explicit canonical decision, including removal, supersedes legacy membership.
      if (product === "internal-documents" &&
          !store.one("SELECT 1 FROM grants WHERE id=? AND product=?", actor.id, product)) {
        product = "engineering-documents";
      }
      const explicit = store.one("SELECT role,status FROM grants WHERE id=? AND product=?", actor.id, product);
      const managedAdministrator = store.activeProductAdministrator(actor.id, product);
      const assignedRole = explicit
        ? (explicit.status === "active" && explicit.role)
        : sharedRole(product, registrations(store.db, actor.id),
          ["admin", "administrator"].includes(resource.sharedAdminRole));
      const role = managedAdministrator ? "administrator" : assignedRole;
      if (!role || !products[product]?.includes(role) ||
          (!managedAdministrator && role === "administrator" && configurableAdminRoles.has(product) &&
            !["admin", "administrator"].includes(resource.sharedAdminRole)))
        return new Response(null, { status: 403 });
      return Response.json({
        user_id: actor.id,
        product,
        roles: [role],
        ...(product === "portal" && role === "administrator" &&
          (!explicit || managedAdministrator && productAdministratorRequests(store.db, actor.id).get("portal") === "active")
          ? { portal_staff_registration: true } : {}),
        // Every privileged role requires recent MFA, including explicit grants.
        // An explicit product grant must never downgrade the authentication
        // requirements of the identical role inherited through registration.
        ...(["administrator", "owner"].includes(role) ||
          (resource.enrollmentCallbacks && product === "pasofi" && ["agent", "support"].includes(role))
          ? { require_mfa: true } : {}),
      });
    }
    if (p === "/account/registration/resume" && method === "GET") {
      const resumes = browserResumes(req);
      if (resumes.length === 1) return redirect(verificationRetryPath(resumes[0].destination, env.origin));
      if (resumes.length > 1) return page("Continue registration", "<ul>" + resumes.map(({ destination }) => {
        const target = new URL(destination, env.origin).searchParams;
        const entry = target.get("entry");
        const productName = entry === infrastructureEntry ? "IT Infrastructure Dashboard"
          : entry === pasofiHotspotEntry ? "PasoFi hotspot" : accountProducts.get(target.get("product"))?.name;
        const label = productName + " · " + target.get("platform") + " · " + target.get("enrollment");
        return '<li><a href="' + esc(verificationRetryPath(destination, env.origin)) + '">' + esc(label) + "</a></li>";
      }).join("") + "</ul>");
      return redirect("/account");
    }
    const login = [
      "/login",
      "/register",
      "/step-up",
      "/verify-factor",
    ].includes(p);
    if (login && method === "GET") {
      const token = secret(),
        state = oidc.randomState(),
        nonce = oidc.randomNonce(),
        verifier = oidc.randomPKCECodeVerifier();
      const requestedReturn = url.searchParams.get("return") || (p === "/step-up" ? "/admin" : "/account");
      const returnUrl = new URL(requestedReturn, env.origin);
      const requestedProduct = returnUrl.searchParams.get("product") || "";
      let destination = returnUrl.origin === env.origin && returnUrl.pathname === "/admin" &&
        (!requestedProduct || Object.hasOwn(products, requestedProduct))
          ? "/admin" + (requestedProduct ? "?product=" + encodeURIComponent(requestedProduct) : "")
          : "/account";
      if (returnUrl.origin === env.origin && returnUrl.pathname === "/account" && accountSections.has(returnUrl.hash))
        destination += returnUrl.hash;
      const invitation = url.searchParams.get("invite");
      if (invitation && /^[\w-]{43}$/.test(invitation))
        destination = "/account?invite=" + invitation;
      const entry = url.searchParams.get("entry");
      const hotspot = entry === pasofiHotspotEntry;
      if (p === "/register" || (p === "/login" && (url.searchParams.has("audience") || entry !== null))) {
        const tier = url.searchParams.get("audience") ?? "user";
        if (!["user", "admin"].includes(tier) || url.searchParams.getAll("audience").length > 1)
          return page("Choose a registration type", '<a href="/account">Return to Onesa Account</a>', 400);
        const stored = new URL(hotspot ? "/account" : destination, env.origin);
        stored.searchParams.set("enrollment", tier);
        if (url.searchParams.has("product") || url.searchParams.has("platform") || entry !== null) {
          const product = url.searchParams.get("product"), platform = url.searchParams.get("platform") ?? "web";
          if (!accountProducts.has(product) || !["web", "ios", "android"].includes(platform) ||
              url.searchParams.getAll("product").length !== 1 || url.searchParams.getAll("platform").length > 1 ||
              (entry !== null && (url.searchParams.getAll("entry").length !== 1 ||
                !isRegistrationEntry(product, platform, tier, entry))))
            return page("Unknown registration entry", '<a href="/account">Continue to Onesa Account</a>', 400);
          if (!returns.has(returnKey(product, platform, tier, entry)) ||
              (hotspot && !connectedProducts.has(product)))
            return page("Product registration unavailable", "The return to your product has not been configured.", 503);
          stored.searchParams.set("product", product);
          stored.searchParams.set("platform", platform);
          if (entry !== null) stored.searchParams.set("entry", entry);
        }
        destination = stored.pathname + stored.search;
      }
      const params = {
        response_type: "code",
        redirect_uri: env.origin + "/callback",
        scope: "openid email profile",
        state,
        nonce,
        code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
        code_challenge_method: "S256",
      };
      if (p === "/register") {
        params.screen_hint = "signup";
        params.prompt = "login";
        if (env.connection) params.connection = env.connection;
      }
      const emailVerification = p === "/login" ? url.searchParams.get("email_verification") : null;
      if (emailVerification === "continue" || (emailVerification === "resend" && env.verification)) {
        params.prompt = "login";
        params.max_age = "0";
        if (emailVerification === "resend") params.onesa_email_verification = "resend";
      }
      if (p === "/step-up" || p === "/verify-factor") {
        const now = Date.now();
        const sessionHash = digest(readCookie(req, "session"));
        const signedIn = authenticator && store.one(sessionLookup, sessionHash, now);
        if (signedIn?.state === "active" && authenticator.enrolled(signedIn.id)) {
          const attempt = authenticator.start(sessionHash, signedIn.id, destination, now);
          return redirect("/account/authenticator", [cookie("authenticator", attempt, 300)]);
        }
        const reuse = signedIn?.state === "active" && url.searchParams.get("confirm_sign_in") !== "1";
        params.prompt = reuse ? "none" : "login";
        params.max_age = reuse ? "1800" : "0";
        params.acr_values =
          "http://schemas.openid.net/pape/policies/2007/06/multi-factor";
        const target = new URL(destination, env.origin);
        target.searchParams.set("_factor", p);
        if (reuse) target.searchParams.set("_factor_primary", "reuse");
        destination = target.pathname + target.search + target.hash;
      }
      const location = await client.authorize(params);
      // A first signup can wait for the inbox inside the hosted transaction.
      const flowSeconds = p === "/register" ? 900 : 300;
      const cookies = [cookie("flow-" + state, token, flowSeconds)];
      const started = store.atomic(() => {
        const target = new URL(destination, env.origin);
        const productEnrollment = target.searchParams.has("enrollment") && target.searchParams.has("product");
        const resumes = productEnrollment ? browserResumes(req) : [];
        // Resume the hotspot flow only in the browser holding its registration receipt.
        if (hotspot && p === "/login" &&
            !resumes.some(resume => resume.destination === destination))
          return false;
        const now = Date.now();
        store.run("DELETE FROM challenges WHERE expires<=?", now);
        store.run("INSERT INTO challenges VALUES(?,?,?,?,?,?)",
          digest(token), state, nonce, verifier, destination, now + flowSeconds * 1000);
        if (productEnrollment) {
          const resume = resumes.length ? readCookie(req, "registration") : secret();
          const browserHash = digest(resume);
          store.run("DELETE FROM registration_resumes WHERE expires<=? OR (hash=? AND destination=?)", now, browserHash, destination);
          store.run("INSERT INTO registration_resumes VALUES(?,?,?,?)", browserHash, state, destination, now + 86400000);
          cookies.push(cookie("registration", resume, 86400));
        }
        return true;
      });
      if (!started) return page("Start PasoFi hotspot registration", "Open registration from the PasoFi hotspot to continue.", 400);
      return redirect(location, cookies);
    }
    if (p === "/callback" && method === "GET") {
      const state = url.searchParams.get("state") || "";
      const stateCookie = /^[A-Za-z0-9_-]{32,128}$/.test(state) && readCookie(req, "flow-" + state);
      const flow = store.one(
        "DELETE FROM challenges WHERE hash=? AND state=? AND expires>? RETURNING *",
        digest(stateCookie || readCookie(req, "flow")),
        state,
        Date.now(),
      );
      if (!flow) {
        const resume = browserResumes(req).find(candidate => candidate.state === state);
        const retry = resume ? retryPath(resume.destination, env.origin) : "/login";
        return page("Sign-in expired", '<a href="' + esc(retry) + '">Start sign-in again</a>', 400);
      }
      const oauthError = url.searchParams.get("error");
      if (["login_required","interaction_required","consent_required"].includes(oauthError) &&
          new URL(flow.destination, env.origin).searchParams.get("_factor_primary") === "reuse") {
        const retry = new URL(retryPath(flow.destination, env.origin), env.origin);
        retry.searchParams.set("confirm_sign_in", "1");
        return page("Confirm your Onesa sign-in",
          '<p>Before you add your first authenticator, Onesa needs to confirm your password once.</p><a class="primary" href="' +
          esc(retry.pathname + retry.search) + '">Confirm sign-in</a>', 401);
      }
      if (oauthError)
        return signInFailure(
          oauthError,
          url.searchParams.get("error_description") || "",
          flow.destination,
          env,
        );
      let identity;
      try {
        identity = await client.redeem(url, flow);
      } catch (error) {
        // Do not expose provider details or credentials in the browser.
        const reference = failureReference();
        logSignInFailure(reference, "token_exchange_or_oidc_validation", error?.name || "Error");
        return page(
          "Onesa could not complete sign-in",
          "The identity provider response could not be verified or exchanged. Start again from the product. If this continues, contact support and provide reference <strong>" + reference + "</strong>. <a href=\"" + esc(retryPath(flow.destination, env.origin)) + "\">Try sign-in again</a>",
          503,
        );
      }
      if (
        identity?.iss !== env.issuer || typeof identity.sub !== "string" || !identity.sub ||
        identity.sub.length > 512
      )
        return page(
          "Sign-in could not be completed",
          'The identity provider returned an invalid response. <a href="' +
            esc(retryPath(flow.destination, env.origin)) +
            '">Try sign-in again</a>',
          502,
        );
      if (identity.email_verified !== true)
        return verificationPage(flow.destination, env, "required");
      const target = new URL(flow.destination, env.origin);
      const requiresFactor = target.searchParams.has("_factor");
      target.searchParams.delete("_factor");
      target.searchParams.delete("_factor_primary");
      const now = Date.now();
      const factor = identity[mfaClaim] * 1000;
      const factorVerified = Number.isSafeInteger(identity[mfaClaim]) && freshFactor(factor, now);
      const startedAt = Math.floor((flow.expires - 300000) / 1000) * 1000;
      if (requiresFactor && (!factorVerified || factor < startedAt)) {
        const sessionHash = digest(readCookie(req, "session"));
        const previous = store.one(sessionLookup, sessionHash, now);
        const verified = store.lookup(env.issuer, identity.sub);
        if (authenticator && previous && verified?.id === previous.id && previous.state === "active") {
          const attempt = authenticator.start(sessionHash, previous.id, target.pathname + target.search + target.hash, now);
          const cookies = [cookie("authenticator", attempt, 300)];
          if (stateCookie) cookies.push(cookie("flow-" + state, "", 0));
          return redirect("/account/authenticator", cookies);
        }
        return factorVerification(
          "Second factor not verified",
          retryPath(flow.destination, env.origin),
          "Onesa sign-in did not confirm an authenticator check. Open My account and sign in with the account you want to verify.",
        );
      }
      const product = target.searchParams.get("product");
      const tier = target.searchParams.get("enrollment");
      const destination = product && tier && returns.get(returnKey(
        product, target.searchParams.get("platform"), tier, target.searchParams.get("entry"),
      ));
      if (product && tier && !destination)
        return page("Product registration unavailable", "The product return is no longer configured.", 503);
      const user = store.register(
        env.issuer,
        identity.sub,
        identity.email,
        target.searchParams.get("invite") || "",
        tier,
        destination ? product : null,
      );
      target.searchParams.delete("enrollment");
      if (["suspended", "rejected"].includes(user.status))
        return page("Account access is disabled", "This Onesa account is currently suspended or its access request was declined. Contact your Onesa administrator if you believe this is a mistake.", 403);
      const session = secret(),
        csrf = secret();
      store.run("DELETE FROM sessions WHERE expires<=?", now);
      store.run(
        "INSERT INTO sessions VALUES(?,?,?,?,?)",
        digest(session),
        user.id,
        csrf,
        now + 1800000,
        factorVerified ? factor : 0,
      );
      const cookies = [cookie("session", session, 1800)];
      if (stateCookie) cookies.push(cookie("flow-" + state, "", 0));
      if (digest(readCookie(req, "flow")) === flow.hash) cookies.push(cookie("flow", "", 0));
      if (destination) {
        const consumed = store.run("DELETE FROM registration_resumes WHERE hash=? AND state=?",
          digest(readCookie(req, "registration")), flow.state);
        if (consumed.changes && !browserResumes(req).length) cookies.push(cookie("registration", "", 0));
      }
      return redirect(destination || (target.pathname + target.search + target.hash), cookies);
    }
    const sessionHash = digest(readCookie(req, "session"));
    const session = store.one(sessionLookup, sessionHash, Date.now());
    if (p === "/account/authenticator" && ["GET", "POST"].includes(method)) {
      if (!authenticator || !session || session.state !== "active")
        return page("Sign in to verify your identity", '<a href="/account">Open My account</a>', 403);
      const token = readCookie(req, "authenticator");
      const now = Date.now();
      const view = authenticator.view(token, sessionHash, session.id, now);
      if (!view) return page("Verification expired", '<a href="/account#account-security">Start a fresh verification</a>', 400);
      if (view.locked) return page("Wait before trying again", '<p>Too many codes were entered. Wait ten minutes, then start a fresh verification.</p><a href="/account#account-security">Return to account security</a>', 429);
      let feedback = "";
      if (method === "POST") {
        const input = new URLSearchParams(await req.text());
        if (req.headers.get("origin") !== env.origin || !compare(input.get("csrf"), session.csrf))
          return page("Verification request expired", '<a href="/account#account-security">Return to account security</a>', 403);
        const result = authenticator.verify(token, sessionHash, session.id, input.get("code") ?? "", now);
        if (result.status === "verified") return redirect(result.destination, [
          cookie("session", result.session, 1800), cookie("authenticator", "", 0),
        ]);
        feedback = '<p role="alert">That code could not be verified. Check the current code in your authenticator app.</p>';
      }
      return page(view.setupKey ? "Set up your authenticator" : "Enter your authenticator code",
        '<p>Verifying <strong><!--email_off-->' + esc(session.email) + '<!--/email_off--></strong></p>' +
        authenticatorSetup(session.email, view.setupKey) + feedback +
        '<div class="authenticator-verification">' + post("/account/authenticator", session.csrf,
          '<label>Six-digit code<input name="code" required inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6"></label>' +
          '<button class="primary">Verify and continue</button>') + '</div>', feedback ? 400 : 200);
    }
    if (p === "/account/closure" && method === "GET") {
      const destination = "/account#account-closure";
      return redirect(session ? destination : "/login?return=" + encodeURIComponent(destination));
    }
    if (p === "/" || p === "/account" || p === "/admin") {
      if (method !== "GET") return new Response(null, { status: 405 });
      if (!session) {
        if (p === "/admin") {
          const product = url.searchParams.get("product");
          return redirect("/login?return=" + encodeURIComponent(
            "/admin" + (product ? "?product=" + encodeURIComponent(product) : ""),
          ));
        }
        const invite = url.searchParams.get("invite");
        const suffix = invite && /^[\w-]{43}$/.test(invite) ? "?invite=" + encodeURIComponent(invite) : "";
        return page(
          "Sign in",
          '<div class="actions"><a class="primary" href="/login' + suffix + '">Sign in</a>' +
          '<a href="/register' + suffix + '">Create account</a></div>',
        );
      }
      if (p !== "/admin") {
        const panels = productPanels(session);
        const active = session.state === "active";
        return page(
          "Your Onesa account",
          '<div class="account-summary"><div class="actions"><strong><!--email_off-->' +
            esc(session.email) + '<!--/email_off--></strong>' +
            pill(session.state, active ? "Account active" : "Account pending") +
            '</div><p class="muted">Email verified</p>' +
            (active ? "" : '<p class="muted">Your account is awaiting administrator approval.</p>') + '</div>' +
            '<div class="account-grid">' + panels.accountAccess + '<div class="account-side">' + panels.administratorAccess +
            '<section class="account-panel" aria-labelledby="account-security"><h2 id="account-security">Account security</h2>' +
            '<p><a href="/verify-factor?return=%2Faccount%23account-security">Set up or verify a second factor</a></p>' +
            (env.connection
              ? post(
                  "/account/recovery",
                  session.csrf,
                  "<button>Send password reset email</button>",
                )
              : "<p>Use Forgot password on the sign-in screen to recover your password.</p>") +
            '</section><section class="account-panel" aria-labelledby="account-closure"><h2 id="account-closure">Account closure</h2>' +
            '<details><summary>Close your Onesa account</summary>' +
            '<p>Closure immediately suspends access and starts account and product-data cleanup. Onesa verifies cleanup separately and retains records as required by law.</p>' +
            post("/account/delete", session.csrf,
              '<div class="actions"><label>Type DELETE to confirm<input name="confirm" required autocomplete="off" spellcheck="false"></label>' +
              '<button>Request account closure</button></div>') +
            '</details></section></div></div><div class="account-footer">' +
            post("/logout", session.csrf, env.auth0LogoutEnabled ? "<button>Sign out</button>" : "<button>Sign out here</button>") + '</div>',
          200, true, store.activeGrant(session.id, "identity")?.role === "administrator",
        );
      }
    }
    let form;
    if (method === "POST") {
      const section = p === "/account/enrollment" ? "#administrator-access" :
        p === "/account/access" ? "#product-access" :
        p === "/account/delete" ? "#account-closure" : "#account-security";
      const back = "/account" + section;
      const accountAction = p.startsWith("/account/") || p === "/logout";
      if (!session && accountAction)
        return page("Sign in to continue", '<p>Your Onesa Account session has ended.</p><a class="primary" href="/login?return=' +
          encodeURIComponent(back) + '">Sign in again</a>', 401);
      const formDenied = () => accountAction
        ? page("Reload your Onesa account", '<p>Onesa could not verify this form. Open your account and submit the request again.</p>' +
          '<a class="primary" href="' + back + '">Return to your account</a>', 403)
        : new Response(null, { status: 403 });
      if (!session || req.headers.get("origin") !== env.origin) return formDenied();
      form = new URLSearchParams(await req.text());
      if (!compare(form.get("csrf"), session.csrf)) return formDenied();
      if (p === "/account/enrollment") {
        const product = form.get("product");
        const requested = requestedProducts(product);
        if (form.getAll("product").length > 1 || form.getAll("tier").length !== 1 ||
            (product !== null && (!requested.length || form.get("tier") !== "admin")))
          return page("Choose a product", '<a href="/account#administrator-access">Return to administrator access</a>', 400);
        store.requestRegistration(session.id, form.get("tier"), ...requested);
        return redirect(product ? "/account#access-" + product : "/account");
      }
      if (p === "/account/access") {
        const product = form.get("product");
        const requested = requestedProducts(product);
        if (form.getAll("product").length !== 1 || !requested.length)
          return page("Product unavailable", '<a href="/account">Return to your account</a>', 400);
        store.requestAccess(session.id, ...requested);
        return redirect("/account");
      }
      if (p === "/account/delete") {
        if (form.getAll("confirm").length !== 1 || form.get("confirm") !== "DELETE")
          return page("Confirmation required", "Enter DELETE exactly to request account closure.", 400);
        if (!freshFactor(session.mfa_at, Date.now()))
          return page("Verify your identity",
            '<p>Recent multi-factor verification is required before closing your account.</p>' +
            '<a href="/verify-factor?return=%2Faccount%23account-closure">Verify a second factor</a>', 403);
        store.requestDeletion(session.id);
        const result = page("Account closure requested",
          "<p>Your Onesa account access has been suspended. Your request is recorded for credential-provider and product-data cleanup. Some records may be retained where required by law. The request is not yet confirmation of complete erasure.</p>");
        result.headers.append("set-cookie", cookie("session", "", 0));
        result.headers.append("set-cookie", cookie("registration", "", 0));
        return result;
      }
      if (p === "/account/recovery" && env.connection) {
        const recoveryNow = Date.now();
        const claimed = store.run(
          "INSERT INTO recovery_limit VALUES(?,?) ON CONFLICT(id) DO UPDATE SET next=excluded.next WHERE recovery_limit.next<=?",
          session.id,
          recoveryNow + 60000,
          recoveryNow,
        ).changes;
        if (!claimed)
          return page(
            "Reset requested",
            "Check your inbox before requesting another email.",
            429,
          );
        let delivered = false;
        try {
          const r = await fetch(
            new URL("/dbconnections/change_password", env.issuer),
            {
              method: "POST",
              redirect: "error",
              signal: AbortSignal.timeout(5000),
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                client_id: env.clientId,
                email: session.email,
                connection: env.connection,
              }),
            },
          );
          delivered = r.ok;
        } catch {
          // Provider timeout or network failure must not become a generic 400.
        }
        if (!delivered) {
          // A timeout has an ambiguous delivery outcome. Retain the rate
          // limit so repeated requests cannot flood the recipient's inbox.
          return page(
            "Recovery unavailable",
            "The recovery provider could not confirm this request. Retry from the sign-in screen.",
            503,
          );
        }
        store.audit(session.id, "request-password-recovery", session.id);
        return page(
          "Check your inbox",
          "Use the password reset message to choose a new password.",
        );
      }
      if (p === "/logout") {
        store.atomic(() => {
          store.run("DELETE FROM sessions WHERE hash=?", session.hash);
          store.run("DELETE FROM registration_resumes WHERE hash=?", digest(readCookie(req, "registration")));
        });
        const expiredCookies = [cookie("session", "", 0), cookie("registration", "", 0)];
        if (!env.auth0LogoutEnabled) return redirect("/account", expiredCookies);
        const provider = new URL("oidc/logout", env.issuer);
        provider.search = new URLSearchParams({
          client_id: env.clientId,
          post_logout_redirect_uri: env.origin,
        });
        return redirect(provider.href, expiredCookies);
      }
    }
    if (!["/admin", "/admin/change", "/admin/invite"].includes(p))
      return page("Page unavailable", "", 404);
    const identityGrant = session && store.activeGrant(session.id, "identity");
    const scopeProduct = (method === "POST" ? form?.get("product") : url.searchParams.get("product")) || "";
    if (scopeProduct && !Object.hasOwn(products, scopeProduct))
      return page("Product unavailable", "", 404);
    const scopedGrant = session && scopeProduct
      ? store.activeGrant(session.id, scopeProduct)
      : null;
    const platformAdministrator = session && store.activeGrant(session.id, platformGrant)?.role === "administrator";
    const globalAdministrator = identityGrant?.role === "administrator" || platformAdministrator;
    const canManageProduct = Boolean(
      scopedGrant && ["administrator", "owner"].includes(scopedGrant.role) ||
      session && scopeProduct && store.activeProductAdministrator(session.id, scopeProduct),
    );
    if (!session || (scopeProduct ? !(globalAdministrator || canManageProduct) : !globalAdministrator))
      return page("Identity administrator required", "", 403);
    if (!freshFactor(session.mfa_at, Date.now()))
      return factorVerification(
        "Verify your identity",
        "/step-up?return=" + encodeURIComponent(scopeProduct ? "/admin?product=" + scopeProduct : "/admin"),
        authenticator
          ? "Enter a code from your authenticator app. If this is your first verification, follow the setup instructions."
          : "To open administration, sign in again and complete the authenticator prompt. If this is your first verification, follow the setup instructions.",
      );
    if (p === "/admin" && method === "GET") {
      if (scopeProduct) {
        const administrators = store.all(
          "SELECT a.id,a.email,a.revision,a.status,CASE WHEN pa.status='active' THEN pa.status ELSE g.status END AS product_status,CASE WHEN pa.status='active' THEN 'Product administrator' ELSE 'Identity grant' END AS source FROM accounts a LEFT JOIN product_administrators pa ON pa.id=a.id AND pa.product=? AND pa.status='active' LEFT JOIN grants g ON g.id=a.id AND g.product=? AND g.role='administrator' AND g.status='active' WHERE a.status='active' AND (pa.id IS NOT NULL OR g.id IS NOT NULL) ORDER BY a.email",
          scopeProduct,
          scopeProduct,
        );
        const list = administrators.map((user) => {
          const action = user.product_status === "active"
            ? post("/admin/change", session.csrf,
                hidden("kind", "product-administrator") + hidden("product", scopeProduct) +
                hidden("id", user.id) + hidden("revision", user.revision) +
                hidden("status", "revoked") + "<button>Remove administrator</button>")
            : "<span>Managed by Identity</span>";
          return '<li class="admin-row"><div class="admin-identity"><strong>' + adminEmail(user.email) +
            '</strong><span class="muted">' + esc(user.source) + "</span></div>" + action + "</li>";
        }).join("");
        const productName = adminProductName(scopeProduct);
        const requests = store.all(
          `SELECT a.id,a.email,a.revision FROM accounts a
            JOIN audit e ON e.seq=(
              SELECT seq FROM audit WHERE target=a.id AND action='product-administrator-request'
                AND json_extract(detail,'$.product')=? ORDER BY seq DESC LIMIT 1
            )
            WHERE a.status IN ('active','pending') AND json_extract(e.detail,'$.status')='pending'
            ORDER BY a.email`,
          scopeProduct,
        );
        const reviews = requests.map(user => '<li class="admin-row"><strong>' + adminEmail(user.email) + "</strong>" +
          (session.id === user.id ? '<span>Another administrator must review this request.</span>' :
            post("/admin/change", session.csrf, hidden("kind", "product-administrator-review") +
              hidden("product", scopeProduct) + hidden("id", user.id) + hidden("revision", user.revision) +
              '<div class="admin-actions"><button name="status" value="active">Approve administrator access</button>' +
              '<button name="status" value="rejected">Decline request</button>' + deleteRequestButton +
              '</div>')) + "</li>").join("");
        return page(
          productName + " administrators",
          '<div class="identity-admin">' +
            (globalAdministrator ? '<a href="/admin">Identity administration</a>' : "") +
            (reviews ? '<section><h2>Pending administrator requests</h2><ul class="admin-list">' + reviews + "</ul></section>" : "") +
            '<section><h2>Current administrators</h2>' +
            (list ? '<ul class="admin-list">' + list + "</ul>" : "<p>No administrators assigned.</p>") + "</section>" +
            '<details class="admin-panel admin-form"><summary>Add an administrator</summary><div class="admin-panel-body">' +
            post("/admin/change", session.csrf,
              hidden("kind", "product-administrator") + hidden("product", scopeProduct) + hidden("status", "active") +
              '<label>Verified Onesa account email<input type="email" name="email" required autocomplete="off"></label>' +
              '<button class="primary">Add administrator</button>') + "</div></details></div>",
          200, true, globalAdministrator,
        );
      }
      const id = url.searchParams.get("id") || "";
      const search = (url.searchParams.get("q") || "").trim().slice(0, 254);
      const users = id
        ? store.all("SELECT * FROM accounts WHERE id=?", id)
        : search
          ? store.all("SELECT * FROM accounts WHERE id=? OR instr(lower(email),lower(?))>0 ORDER BY email LIMIT 201", search.toLowerCase(), search)
          : store.all("SELECT * FROM accounts ORDER BY email LIMIT 201");
      const openAccount = Boolean((id || search) && users.length === 1);
      const assignments = Object.entries(products).map(([product, roles]) => {
        const name = adminProductName(product);
        return '<optgroup label="' + esc(name) + '">' +
          roles.map(role => '<option value="' + esc(product + "/" + role) + '">' +
            esc(name + " · " + adminLabel(role)) + "</option>").join("") + "</optgroup>";
      }).join("");
      const pendingAccounts = [], otherAccounts = [];
      for (const user of users.slice(0, 200)) {
        const base = hidden("id", user.id) + hidden("revision", user.revision);
        const grants = store.all("SELECT product,role,status FROM grants WHERE id=? ORDER BY product", user.id);
        const registrationsByTier = [...registrations(store.db, user.id)];
        const administratorRequests = [...productAdministratorRequests(store.db, user.id)]
          .filter(([, status]) => status === "pending");
        const accessRequests = grants.filter(grant =>
          grant.status === "pending" && accountProducts.get(grant.product)?.role === grant.role);
        const reviewCount = accessRequests.length + administratorRequests.length +
          (session.id === user.id ? 0 : registrationsByTier.filter(([, status]) => status === "pending").length);
        const registrationRows = registrationsByTier.map(([tier, status]) => {
          const title = tier === "admin" ? "Shared administrator registration" : "Shared user registration";
          const row = '<div class="admin-row"><strong>' + title + "</strong>" + pill(status, adminLabel(status));
          if (session.id === user.id) return row + "</div>";
          const buttons = status === "active" ? '<button name="status" value="revoked">Remove access</button>'
            : '<button name="status" value="active">Approve registration</button>' +
              (status === "pending" ? '<button name="status" value="rejected">Decline</button>' + deleteRequestButton : "");
          return post("/admin/change", session.csrf, base + hidden("kind", "registration") + hidden("tier", tier) +
            row + '<div class="admin-actions">' + buttons + "</div></div>");
        }).join("");
        const requestRows = accessRequests.map(grant => post("/admin/change", session.csrf,
          base + hidden("kind", "review") + hidden("assignment", grant.product + "/" + grant.role) +
          '<div class="admin-row"><div class="admin-identity"><strong>' + esc(adminProductName(grant.product)) +
          '</strong><span class="muted">' + esc(adminLabel(grant.role)) + ' access request</span></div>' +
          '<div class="admin-actions"><button name="status" value="active">Approve</button>' +
          '<button name="status" value="rejected">Decline</button>' + deleteRequestButton + "</div></div>",
        )).join("") + administratorRequests.map(([product]) =>
          '<p class="admin-row"><a href="/admin?product=' + esc(product) + '">Review ' +
          esc(adminProductName(product)) + " administrator request</a></p>",
        ).join("");
        const grantRows = grants.map(grant =>
          '<li class="admin-row"><div class="admin-identity"><strong>' +
          esc(grant.product === platformGrant ? "Platform access" : adminProductName(grant.product)) +
          '</strong><span class="muted">' + esc(adminLabel(grant.role)) + "</span></div>" +
          pill(grant.status, adminLabel(grant.status)) + "</li>",
        ).join("");
        const account = '<li><details class="admin-account"' + (openAccount ? " open" : "") + ">" +
          '<summary><strong>' + adminEmail(user.email) + '</strong><span class="admin-account-meta">' +
          pill(user.status, adminLabel(user.status)) +
          (reviewCount ? pill("pending", reviewCount + (reviewCount === 1 ? " pending request" : " pending requests")) : "") +
          '</span></summary><div class="admin-account-body">' +
          '<p class="muted">Onesa user ID <code>' + esc(user.id) + "</code></p>" +
          (registrationRows || requestRows ? '<section class="admin-detail"><h3>Requests and registration</h3>' + registrationRows + requestRows + "</section>" : "") +
          (grantRows ? '<section><h3>Product access</h3><ul class="admin-list">' + grantRows + "</ul></section>" : "") +
          (platformAdministrator && session.id !== user.id && user.status === "active" ?
            post("/admin/change", session.csrf, base + hidden("kind", "platform-administrator") +
              (grants.some(grant => grant.product === platformGrant && grant.status === "active")
                ? '<button name="status" value="revoked">Remove platform administrator</button>'
                : '<button name="status" value="active">Grant platform administrator</button>')) : "") +
          '<details class="admin-panel admin-form"><summary>Manage account status</summary><div class="admin-panel-body">' +
          post("/admin/change", session.csrf, base + hidden("kind", "status") +
            '<label>Account status<select name="status">' +
            options(["active", "suspended", "pending", "rejected"], user.status) +
            "</select></label><button>Update account</button>") + "</div></details>" +
          '<details class="admin-panel admin-form admin-access"><summary>Manage product access</summary><div class="admin-panel-body">' +
          post("/admin/change", session.csrf, base + hidden("kind", "grant") +
            '<label>Product and role<select name="assignment" required><option value="" disabled selected>Choose a product and role</option>' +
            assignments + '</select></label><label>Access<select name="status">' +
            options(["active", "revoked"]) + "</select></label><button>Update access</button>") +
          "</div></details></div></details></li>";
        (reviewCount ? pendingAccounts : otherAccounts).push(account);
      }
      const history = store.all("SELECT * FROM audit ORDER BY seq DESC LIMIT 100").map(event => {
        const date = new Date(event.at);
        const action = ["shared-registration", "product-administrator-request", "review"].includes(event.action) &&
          JSON.parse(event.detail).status === "deleted" ? "Request deleted" : adminLabel(event.action);
        return '<li><details><summary>' + esc(action) + ' · <time datetime="' +
          esc(date.toISOString()) + '">' + esc(auditDate.format(date)) + " UTC</time></summary>" +
          "<p>Actor <code>" + esc(event.actor) + "</code></p><p>Target <code>" + esc(event.target) +
          "</code></p><pre>" + esc(event.detail) + "</pre></details></li>";
      }).join("");
      return page(
        "Identity administration",
        '<div class="identity-admin"><div class="admin-toolbar">' +
          '<form class="admin-search" action="/admin"><label>Find by email or Onesa user ID<input type="search" name="q" maxlength="254" value="' +
          esc(id || search) + '"></label><button class="primary">Find</button></form>' +
          '<details class="admin-panel admin-form"><summary>Create invitation</summary><div class="admin-panel-body">' +
          post("/admin/invite", session.csrf,
            '<label>Invitation email<input type="email" required name="email"></label><button>Create invitation</button>') +
          "</div></details></div>" +
          (id || search ? '<a href="/admin">Show all accounts</a>' : "") +
          (pendingAccounts.length ? '<section><h2>Pending requests</h2><ul class="admin-list">' + pendingAccounts.join("") + "</ul></section>" : "") +
          (otherAccounts.length ? "<section><h2>" + (pendingAccounts.length ? "Other accounts" : "Accounts") +
            '</h2><ul class="admin-list">' + otherAccounts.join("") + "</ul></section>" : "") +
          (!users.length ? '<p class="muted">No matching accounts.</p>' : "") +
          (users.length > 200 ? '<p class="muted">Showing the first 200 accounts. Use search to find a specific account.</p>' : "") +
          '<details class="admin-panel"><summary>Recent audit history</summary><div class="admin-panel-body admin-audit">' +
          (history ? '<ol class="admin-list">' + history + "</ol>" : '<p class="muted">No audit events recorded.</p>') +
          "</div></details></div>",
        200, true, true,
      );
    }
    if (p === "/admin/invite" && method === "POST") {
      const token = store.invite(session.id, form.get("email"));
      return page(
        "Invitation created",
        "<p>Share this one-time link with the intended recipient. It expires in 24 hours.</p><code>" +
          esc(env.origin + "/register?invite=" + token) +
          "</code>",
      );
    }
    if (p === "/admin/change" && method === "POST") {
      const scope = scopeProduct;
      if (form.get("kind") === "product-administrator-review" && scope) {
        store.change(session.id, form.get("id"), Number(form.get("revision")), {
          kind: "product-administrator-review",
          product: scope,
          status: form.get("status"),
        }, scope);
        return redirect("/admin?product=" + encodeURIComponent(scope));
      }
      if (form.get("kind") === "product-administrator") {
        if (!scope) return page("Choose a product", '<a href="/admin">Return to Identity administration</a>', 400);
        let targetId = form.get("id");
        let targetRevision = Number(form.get("revision"));
        if (form.get("status") === "active") {
          const email = String(form.get("email") || "").trim().toLowerCase();
          const target = store.one(
            "SELECT a.id,a.revision FROM accounts a JOIN links l ON l.id=a.id AND l.issuer=? WHERE a.email=? COLLATE NOCASE AND a.status='active' LIMIT 1",
            env.issuer,
            email,
          );
          if (!target)
            throw new Rejected("Register and verify this address with Onesa first, then activate the account before granting administrator access.");
          targetId = target.id;
          targetRevision = target.revision;
        }
        store.change(session.id, targetId, targetRevision, {
          kind: "product-administrator",
          product: scope,
          status: form.get("status"),
        }, scope);
        return redirect("/admin?product=" + encodeURIComponent(scope));
      }
      const [product, role] = (form.get("assignment") || "").split("/");
      store.change(session.id, form.get("id"), Number(form.get("revision")), {
        kind: form.get("kind"),
        ...(form.get("kind") === "registration" ? { tier: form.get("tier") } : {}),
        product,
        role,
        status: form.get("status"),
      }, scope || null);
      return redirect(scope
        ? "/admin?product=" + encodeURIComponent(scope)
        : "/admin?id=" + encodeURIComponent(form.get("id")));
    }
    return new Response(null, { status: 405 });
  }
  return async (req) => {
    let response;
    try {
      response = await handle(req);
    } catch (e) {
      if (e instanceof Rejected) {
        response = page("Request needs review", esc(e.message), 409);
      } else {
        const reference = failureReference();
        logSignInFailure(reference, "request_handler", e?.name || "Error");
        response = page(
          "Onesa could not complete this request",
          "A server-side error interrupted the request. Retry from the application where you started. If it continues, contact support and provide reference <strong>" + reference + "</strong>.",
          503,
        );
      }
    }
    response.headers.set("cache-control", "no-store");
    const requestUrl = new URL(req.url);
    const staffVerification = requestUrl.pathname === pasoFiFactorPath;
    const accountVerification = requestUrl.pathname === "/account/authenticator";
    if (!response.headers.has("referrer-policy")) {
      const staffEntry = staffVerification && requestUrl.searchParams.has("ticket");
      response.headers.set("referrer-policy", staffEntry ? "no-referrer" : "same-origin");
    }
    response.headers.set("x-content-type-options", "nosniff");
    response.headers.set(
      "content-security-policy",
      "default-src 'none'; img-src https://onesa.eu/brand/icons/v1/onesa-company-180.png" +
      (accountVerification || staffVerification ? " data:" : "") + "; style-src 'unsafe-inline'; form-action 'self'" +
      (staffVerification ? " " + new URL(env.issuer).origin : "") + "; frame-ancestors 'none'; base-uri 'none'",
    );
    return response;
  };
}
