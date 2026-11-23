import * as oidc from "openid-client";
import { returnKey } from "./registration-returns.js";
import { randomUUID, timingSafeEqual } from "node:crypto";
import { secret, digest, Rejected, products, accountProducts, registrations, sharedRole, configurableAdminRoles } from "./store.js";

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
const page = (title, body, status = 200, wide = false) =>
  new Response(`<!doctype html><html lang="en"><head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
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
      .actions, nav, .products li { display: flex; flex-wrap: wrap; align-items: center; gap: .75rem 1.25rem; }
      .products { padding: 0; list-style: none; }
      .products li { justify-content: space-between; padding: .7rem 0; border-bottom: 1px solid #d4dce5; }
      label { display: inline-grid; max-width: 100%; margin: .3rem; gap: .2rem; }
      a { color: #087F68; text-underline-offset: 3px; }
      a:hover { color: #065C4E; }
      input, select, button, .primary { max-width: 100%; min-height: 44px; padding: .55rem .75rem; font: inherit; border: 1px solid #9AAEAA; border-radius: 10px; background: white; color: #172B4D; }
      button, .primary { cursor: pointer; }
      .primary { display: inline-flex; align-items: center; background: #0B725E; border-color: #0B725E; color: white; text-decoration: none; }
      .primary:hover { background: #095C4D; border-color: #095C4D; }
      :is(a, button, input, select):focus-visible { outline: 3px solid #00B894; outline-offset: 3px; }
    </style></head><body>
    <header><a href="/account"><img src="https://onesa.eu/brand/icons/v1/onesa-company-180.png" alt="" width="32" height="32">Onesa Account</a>
    <nav aria-label="Account"><a href="/account">My account</a><a href="/admin">Administration</a></nav></header>
    <main${wide ? ' class="wide"' : ""}><h1>${esc(title)}</h1>${body}</main></body></html>`,
    { status, headers: { "content-type": "text/html; charset=utf-8" } },
  );
const failureReference = () => randomUUID().replace(/-/g, "").slice(0, 12).toUpperCase();
const logSignInFailure = (reference, stage, errorClass = "Error") => {
  const safeClass = typeof errorClass === "string" && /^[A-Za-z0-9_.-]{1,64}$/.test(errorClass) ? errorClass : "Error";
  console.error(JSON.stringify({ event: "identity_sign_in_failed", reference, stage, errorClass: safeClass }));
};
const signInFailure = (code, description, destination, origin) => {
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
const accountSections = new Set(["#product-access", "#account-security"]);
const retryPath = (destination, origin) => {
  const target = new URL(destination, origin);
  const invite = target.searchParams.get("invite");
  const tier = target.searchParams.get("enrollment");
  if (tier === "admin" || tier === "user") {
    const query = new URLSearchParams({ audience: tier });
    for (const key of ["invite", "product", "platform"])
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
const mfaClaim = "https://onesa.eu/claims/mfa_time";
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
      });
      return tokens.claims();
    },
  };
}
export function createApp(store, env, client = authClient(env)) {
  const returns = env.registrationReturns ?? new Map();
  function browserResumes(req) {
    return store.all("SELECT state,destination FROM registration_resumes WHERE hash=? AND expires>? ORDER BY expires DESC",
      digest(readCookie(req, "registration")), Date.now());
  }
  const connectedProducts = new Set(Array.from(env.resources.values(), item => item.product));
  const adminEnabled = new Set(Array.from(env.resources.values())
    .filter(resource => ["admin", "administrator"].includes(resource.sharedAdminRole))
    .map(resource => resource.product));
  function productAccess(session) {
    const tiers = registrations(store.db, session.id);
    const decisions = new Map(store.all(
      "SELECT product,status,role FROM grants WHERE id=?", session.id,
    ).map(row => [row.product, row]));
    const statusLabels = { pending: "Awaiting approval", active: "Approved", revoked: "Access removed", rejected: "Request declined" };
    const rows = [];
    for (const [product, { name }] of accountProducts) {
      const legacy = product === "internal-documents" && decisions.get("engineering-documents");
      let decision = decisions.get(product) || legacy;
      const inherited = connectedProducts.has(product) && sharedRole(product, tiers, adminEnabled.has(product));
      if (!decision && inherited) decision = { status: "active", role: inherited };
      if (!decision && !connectedProducts.has(product)) continue;
      const label = legacy && !decisions.has(product) ? "Internal Documents (Engineering)" : name;
      let control;
      if (decision) {
        control = '<span>' + esc(statusLabels[decision.status]) +
          (decision.status === "active" ? ' · ' + esc(decision.role) : '') + '</span>';
      } else {
        control = post("/account/access", session.csrf, hidden("product", product) +
          '<button aria-label="Request access to ' + esc(name) + '">Request access</button>');
      }
      rows.push("<li><strong>" + esc(label) + "</strong>" + control + "</li>");
    }
    return '<h2 id="product-access">Product access</h2>' +
      (rows.length ? '<ul class="products">' + rows.join("") + '</ul>' : '<p>No products are available to request yet.</p>');
  }
  function registrationPanel(session) {
    const states = registrations(store.db, session.id);
    const labels = { pending: "Awaiting review", active: "Approved", rejected: "Declined", revoked: "Access removed" };
    return "<h2>Onesa registration</h2>" + ["user", "admin"].map(tier => {
      const title = tier === "admin" ? "Administrator" : "User";
      return states.has(tier) ? "<p>" + title + " · " + esc(labels[states.get(tier)]) + "</p>" :
        post("/account/enrollment", session.csrf, hidden("tier", tier) + "<button>Request " + title.toLowerCase() + " registration</button>");
    }).join("");
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
    if (p === "/internal/decision" && method === "POST") {
      if (!compare(req.headers.get("authorization"), "Bearer " + env.policyKey))
        return new Response(null, { status: 401 });
      const { subject, audience, client: clientId } = await req.json();
      if (typeof subject !== "string" || subject.length > 512 || !subject)
        return new Response(null, { status: 403 });
      const actor = store.lookup(env.issuer, subject);
      if (actor && ["suspended", "rejected"].includes(actor.status))
        return new Response(null, { status: 403 });
      if (
        clientId === env.clientId &&
        (!audience || audience === new URL("userinfo", env.issuer).href)
      )
        return Response.json({ selfservice: true });
      const resource = env.resources.get(audience);
      if (!actor || !resource || !resource.clients.includes(clientId))
        return new Response(null, { status: 403 });
      let product = resource.product;
      // An explicit canonical decision, including removal, supersedes legacy membership.
      if (product === "internal-documents" &&
          !store.one("SELECT 1 FROM grants WHERE id=? AND product=?", actor.id, product)) {
        product = "engineering-documents";
      }
      if (actor.status !== "active") return new Response(null, { status: 403 });
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
        ...(!explicit && product === "portal" && role === "administrator" ? { portal_staff_registration: true } : {}),
        // Every privileged role requires recent MFA, including explicit grants.
        // An explicit product grant must never downgrade the authentication
        // requirements of the identical role inherited through registration.
        ...(["administrator", "owner"].includes(role)
          ? { require_mfa: true } : {}),
      });
    }
    if (p === "/account/registration/resume" && method === "GET") {
      const resumes = browserResumes(req);
      if (resumes.length === 1) return redirect(retryPath(resumes[0].destination, env.origin));
      if (resumes.length > 1) return page("Continue registration", "<ul>" + resumes.map(({ destination }) => {
        const target = new URL(destination, env.origin).searchParams;
        const label = accountProducts.get(target.get("product"))?.name + " · " + target.get("platform") + " · " + target.get("enrollment");
        return '<li><a href="' + esc(retryPath(destination, env.origin)) + '">' + esc(label) + "</a></li>";
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
      if (p === "/register" || (p === "/login" && url.searchParams.has("audience"))) {
        const tier = url.searchParams.get("audience") ?? "user";
        if (!["user", "admin"].includes(tier) || url.searchParams.getAll("audience").length > 1)
          return page("Choose a registration type", '<a href="/account">Return to Onesa Account</a>', 400);
        const stored = new URL(destination, env.origin);
        stored.searchParams.set("enrollment", tier);
        if (url.searchParams.has("product") || url.searchParams.has("platform")) {
          const product = url.searchParams.get("product"), platform = url.searchParams.get("platform") ?? "web";
          if (!accountProducts.has(product) || !["web", "ios", "android"].includes(platform) ||
              url.searchParams.getAll("product").length !== 1 || url.searchParams.getAll("platform").length > 1)
            return page("Unknown registration entry", '<a href="/account">Continue to Onesa Account</a>', 400);
          if (!returns.has(returnKey(product, platform, tier)))
            return page("Product registration unavailable", "The return to your product has not been configured.", 503);
          stored.searchParams.set("product", product);
          stored.searchParams.set("platform", platform);
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
      if (p === "/register") params.screen_hint = "signup";
      if (p === "/step-up" || p === "/verify-factor") {
        params.prompt = "login";
        params.max_age = "0";
        params.acr_values =
          "http://schemas.openid.net/pape/policies/2007/06/multi-factor";
      }
      const location = await client.authorize(params);
      const cookies = [cookie("flow", token, 300)];
      store.atomic(() => {
        const now = Date.now();
        store.run("DELETE FROM challenges WHERE expires<=?", now);
        store.run("INSERT INTO challenges VALUES(?,?,?,?,?,?)", digest(token), state, nonce, verifier, destination, now + 300000);
        if (new URL(destination, env.origin).searchParams.has("product")) {
          const resume = browserResumes(req).length ? readCookie(req, "registration") : secret();
          const browserHash = digest(resume);
          store.run("DELETE FROM registration_resumes WHERE expires<=? OR (hash=? AND destination=?)", now, browserHash, destination);
          store.run("INSERT INTO registration_resumes VALUES(?,?,?,?)", browserHash, state, destination, now + 86400000);
          cookies.push(cookie("flow-" + state, token, 300), cookie("registration", resume, 86400));
        }
      });
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
      if (oauthError)
        return signInFailure(
          oauthError,
          url.searchParams.get("error_description") || "",
          flow.destination,
          env.origin,
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
        identity?.iss !== env.issuer ||
        identity.email_verified !== true ||
        !identity.sub ||
        typeof identity.sub !== "string"
      )
        return page(
          "Verify your email",
          'Use the verification message from Onesa Identity, then sign in again. <a href="' +
            esc(retryPath(flow.destination, env.origin)) +
            '">Continue sign-in</a>',
          403,
        );
      const target = new URL(flow.destination, env.origin);
      const product = target.searchParams.get("product");
      const destination = product && target.searchParams.has("enrollment") && returns.get(returnKey(product, target.searchParams.get("platform"),
        target.searchParams.get("enrollment")));
      if (product && target.searchParams.has("enrollment") && !destination)
        return page("Product registration unavailable", "The product return is no longer configured.", 503);
      const user = store.register(
        env.issuer,
        identity.sub,
        identity.email,
        target.searchParams.get("invite") || "",
        target.searchParams.get("enrollment"),
      );
      target.searchParams.delete("enrollment");
      if (["suspended", "rejected"].includes(user.status))
        return page("Account access is disabled", "This Onesa account is currently suspended or its access request was declined. Contact your Onesa administrator if you believe this is a mistake.", 403);
      const session = secret(),
        csrf = secret(),
        now = Date.now();
      const factor =
        Number.isSafeInteger(identity[mfaClaim]) &&
        identity[mfaClaim] * 1000 <= now
          ? identity[mfaClaim] * 1000
          : 0;
      store.run("DELETE FROM sessions WHERE expires<=?", now);
      store.run(
        "INSERT INTO sessions VALUES(?,?,?,?,?)",
        digest(session),
        user.id,
        csrf,
        now + 1800000,
        factor,
      );
      const cookies = [cookie("session", session, 1800)];
      if (digest(readCookie(req, "flow")) === flow.hash) cookies.push(cookie("flow", "", 0));
      if (destination) {
        const consumed = store.run("DELETE FROM registration_resumes WHERE hash=? AND state=?",
          digest(readCookie(req, "registration")), flow.state);
        cookies.push(cookie("flow-" + state, "", 0));
        if (consumed.changes && !browserResumes(req).length) cookies.push(cookie("registration", "", 0));
      }
      return redirect(destination || (target.pathname + target.search + target.hash), cookies);
    }
    const session = store.one(
      "SELECT s.*,a.email,a.status AS state FROM sessions s JOIN accounts a USING(id) WHERE hash=? AND expires>? AND a.status IN ('active','pending')",
      digest(readCookie(req, "session")),
      Date.now(),
    );
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
        const featureSignIn = (section) => suffix ? "/login" + suffix : "/login?return=" + encodeURIComponent("/account" + section);
        return page(
          "Sign in to Onesa",
          '<p class="muted">Use one Onesa account across your approved products. Create an account, verify your email, and request access to the products you need.</p>' +
          '<div class="actions"><a class="primary" href="/login' + suffix + '">Sign in to Onesa</a>' +
          '<a href="/register' + suffix + '">Create an Onesa account</a>' +
          '<a href="/register?audience=admin' + (suffix ? '&amp;' + suffix.slice(1) : '') + '">Request administrator registration</a></div>' +
          '<section aria-labelledby="access-overview"><h2 id="access-overview">Product access</h2>' +
          '<p>Check your access and request approval for another product. For example, a Smart Farmer request can show “Awaiting approval” while an administrator reviews it.</p>' +
          '<p>' + Array.from(accountProducts.values(), ({ name }) => esc(name)).join(" · ") + '</p>' +
          '<a href="' + featureSignIn("#product-access") + '">Sign in to manage product access</a></section>' +
          '<section aria-labelledby="security-overview"><h2 id="security-overview">Account security</h2>' +
          '<p>Set up or verify a second sign-in factor and find password recovery options.</p>' +
          '<a href="' + featureSignIn("#account-security") + '">Sign in to manage account security</a></section>',
        );
      }
      if (p !== "/admin")
        return page(
          "Your Onesa account",
          "<p>" +
            esc(session.email) +
            " · " +
            esc(session.state) +
            '</p>' +
            (session.state === "pending" ? '<p>Your account is awaiting administrator approval.</p>' : '') +
            registrationPanel(session) + productAccess(session) +
            '<h2 id="account-security">Account security</h2><p><a href="/verify-factor">Verify or enroll a second factor</a></p>' +
            (env.connection
              ? post(
                  "/account/recovery",
                  session.csrf,
                  "<button>Send password reset email</button>",
                )
              : "<p>Use Forgot password on the sign-in screen to recover your password.</p>") +
            '<h2>Account closure</h2>' +
            '<p>Request closure of your Onesa account. This immediately suspends central access and queues credential and product-data cleanup. Completion of downstream erasure is separately verified; applicable legal retention still applies.</p>' +
            post("/account/delete", session.csrf,
              '<label>Type DELETE to confirm <input name="confirm" required autocomplete="off" spellcheck="false"></label>' +
              '<button>Request account closure</button>') +
            post("/logout", session.csrf, "<button>Sign out here</button>"),
        );
    }
    let form;
    if (method === "POST") {
      if (!session || req.headers.get("origin") !== env.origin)
        return new Response(null, { status: 403 });
      form = new URLSearchParams(await req.text());
      if (!compare(form.get("csrf"), session.csrf))
        return new Response(null, { status: 403 });
      if (p === "/account/enrollment") {
        store.requestRegistration(session.id, form.get("tier"));
        return redirect("/account");
      }
      if (p === "/account/access") {
        const product = form.get("product");
        if (!connectedProducts.has(product) || !accountProducts.has(product))
          return page("Product unavailable", '<a href="/account">Return to your account</a>', 400);
        store.requestAccess(session.id, product);
        return redirect("/account");
      }
      if (p === "/account/delete") {
        if (form.getAll("confirm").length !== 1 || form.get("confirm") !== "DELETE")
          return page("Confirmation required", "Enter DELETE exactly to request account closure.", 400);
        if (!session.mfa_at || Date.now() - session.mfa_at > 300000 ||
            session.mfa_at > Date.now())
          return page("Verify your identity",
            '<p>Recent multi-factor verification is required before closing your account.</p>' +
            '<a href="/verify-factor">Verify a second factor</a>', 403);
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
        store.run("DELETE FROM sessions WHERE hash=?", session.hash);
        store.run("DELETE FROM registration_resumes WHERE hash=?", digest(readCookie(req, "registration")));
        return redirect("/account", [cookie("session", "", 0), cookie("registration", "", 0)]);
      }
    }
    if (!["/admin", "/admin/change", "/admin/invite"].includes(p))
      return page("Page unavailable", "", 404);
    const identityGrant = session && store.activeGrant(session.id, "identity");
    const scopeProduct = url.searchParams.get("product") || form?.get("product") || "";
    if (scopeProduct && !Object.hasOwn(products, scopeProduct))
      return page("Product unavailable", "", 404);
    const scopedGrant = session && scopeProduct
      ? store.activeGrant(session.id, scopeProduct)
      : null;
    const globalAdministrator = identityGrant?.role === "administrator";
    const canManageProduct = Boolean(
      scopedGrant && ["administrator", "owner"].includes(scopedGrant.role) ||
      session && scopeProduct && store.activeProductAdministrator(session.id, scopeProduct),
    );
    if (!session || (scopeProduct ? !(globalAdministrator || canManageProduct) : !globalAdministrator))
      return page("Identity administrator required", "", 403);
    if (!session.mfa_at || Date.now() - session.mfa_at > 300000)
      return page(
        "Verify your identity",
        '<a href="/step-up?return=' + encodeURIComponent(scopeProduct
          ? "/admin?product=" + scopeProduct
          : "/admin") + '">Continue with fresh MFA</a>',
        403,
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
          return "<li><strong>" + esc(user.email) + "</strong> · " + esc(user.source) + " " + action + "</li>";
        }).join("");
        const productName = accountProducts.get(scopeProduct)?.name || scopeProduct;
        return page(
          productName + " administrators",
          "<p>Manage administrator access for " + esc(productName) + ". Only active, verified Onesa accounts can be added. Changes are recorded in the Identity audit log.</p>" +
            "<ul>" + (list || "<li>No administrators assigned.</li>") + "</ul>" +
            post("/admin/change", session.csrf,
              hidden("kind", "product-administrator") + hidden("product", scopeProduct) + hidden("status", "active") +
              '<label>Verified Onesa account email<input type="email" name="email" required autocomplete="off"></label>' +
              '<button>Add administrator</button>') +
            '<p><a href="/admin">Identity administration</a></p>',
        );
      }
      const users = store.all(
        "SELECT * FROM accounts ORDER BY email LIMIT 201",
      );
      const search = url.searchParams.get("id") || "";
      const shown = search
        ? store.all("SELECT * FROM accounts WHERE id=?", search)
        : users.slice(0, 200);
      const panels = shown
        .map((u) => {
          const base = hidden("id", u.id) + hidden("revision", u.revision);
          const enrollmentReviews = [...registrations(store.db, u.id)].map(([tier, status]) => {
            const title = tier === "admin" ? "Shared administrator registration" : "Shared user registration";
            if (session.id === u.id) return "<p>" + title + " · " + esc(status) + "</p>";
            const buttons = status === "active" ? '<button name="status" value="revoked">Remove access</button>'
              : '<button name="status" value="active">Approve registration</button>' +
                (status === "pending" ? ' <button name="status" value="rejected">Decline</button>' : '');
            return post("/admin/change", session.csrf, base + hidden("kind", "registration") + hidden("tier", tier) +
              "<fieldset><legend>" + title + " · " + esc(status) + "</legend>" + buttons + "</fieldset>");
          }).join("");
          const grants = store.all("SELECT product,role,status FROM grants WHERE id=? ORDER BY product", u.id);
          const reviews = grants.filter(g =>
            g.status === "pending" && accountProducts.get(g.product)?.role === g.role,
          ).map(g => post("/admin/change", session.csrf,
            base + hidden("kind", "review") + hidden("assignment", g.product + "/" + g.role) +
            "<fieldset><legend>" + esc(accountProducts.get(g.product).name) + " · " + esc(g.role) +
            ' access request</legend><button name="status" value="active">Approve</button> ' +
            '<button name="status" value="rejected">Decline</button></fieldset>',
          )).join("");
          return (
            "<article><h2>" +
            esc(u.email) +
            "</h2><p><code>" +
            esc(u.id) +
            "</code> · " +
            esc(u.status) +
            "</p><p>" +
            grants.map(g => [g.product, g.role, g.status].map(esc).join(" / ")).join(", ") +
            "</p>" +
            post(
              "/admin/change",
              session.csrf,
              base +
                hidden("kind", "status") +
                '<label>Account status<select name="status">' +
                options(["active", "suspended", "pending", "rejected"], u.status) +
                "</select></label><button>Update account</button>",
            ) +
            enrollmentReviews + reviews +
            post(
              "/admin/change",
              session.csrf,
              base +
                hidden("kind", "grant") +
                '<label>Product and role<select name="assignment" required>' +
                '<option value="" disabled selected>Choose a product and role</option>' +
                options(
                  Object.entries(products).flatMap(([product, roles]) =>
                    roles.map((r) => product + "/" + r),
                  ),
                ) +
                '</select></label><label>Access<select name="status">' +
                options(["active", "revoked"]) +
                "</select></label><button>Update access</button>",
            ) +
            "</article>"
          );
        })
        .join("");
      const history = store
        .all("SELECT * FROM audit ORDER BY seq DESC LIMIT 100")
        .map(
          (a) =>
            "<li>" +
            esc(new Date(a.at).toISOString()) +
            " · " +
            esc(a.actor) +
            " · " +
            esc(a.action) +
            " · " +
            esc(a.target) +
            " " +
            esc(a.detail) +
            "</li>",
        )
        .join("");
      return page(
        "Identity administration",
        post(
          "/admin/invite",
          session.csrf,
          '<label>Invitation email<input type="email" required name="email"></label><button>Create invitation</button>',
        ) +
          '<form><label>Find by Onesa user ID<input name="id" value="' +
          esc(search) +
          '"></label><button>Find</button></form>' +
          panels +
          "<h2>Recent audit history</h2><ol>" +
          history +
          "</ol>",
        200, true,
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
      const scope = form.get("product") || "";
      if (form.get("kind") === "product-administrator") {
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
    response.headers.set("referrer-policy", "same-origin");
    response.headers.set("x-content-type-options", "nosniff");
    response.headers.set(
      "content-security-policy",
      "default-src 'none'; img-src https://onesa.eu/brand/icons/v1/onesa-company-180.png; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    );
    return response;
  };
}
