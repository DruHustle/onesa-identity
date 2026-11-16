import * as oidc from "openid-client";
import { timingSafeEqual } from "node:crypto";
import { secret, digest, Rejected, products, accountProducts } from "./store.js";

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
      body { margin: 0; padding: 24px clamp(16px, 5vw, 64px) 48px; background: #f5f7fa; color: #10263e; font: 1rem/1.55 Arial, Helvetica, sans-serif; }
      header { max-width: 68rem; margin: 0 auto 36px; display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px; }
      header > a { display: flex; align-items: center; gap: 10px; color: #10263e; font-weight: 600; text-decoration: none; }
      header img { width: 32px; height: 32px; }
      main { margin: auto; max-width: 38rem; padding: clamp(22px, 5vw, 36px); background: white; border: 1px solid #d4dce5; border-radius: 16px; overflow-wrap: anywhere; }
      main.wide { max-width: 68rem; }
      h1 { margin: 0 0 16px; font-size: clamp(1.75rem, 5vw, 2.25rem); line-height: 1.12; letter-spacing: -.045em; }
      h2 { margin: 1.5rem 0 .5rem; font-size: 1.25rem; }
      p { margin: 0 0 1rem; }
      .muted { color: #56677b; }
      article { margin: 1rem 0; padding: 1rem; border: 1px solid #d4dce5; border-radius: 6px; }
      .actions, nav, .products li { display: flex; flex-wrap: wrap; align-items: center; gap: .75rem 1.25rem; }
      .products { padding: 0; list-style: none; }
      .products li { justify-content: space-between; padding: .7rem 0; border-bottom: 1px solid #d4dce5; }
      label { display: inline-grid; max-width: 100%; margin: .3rem; gap: .2rem; }
      a { color: #1a51ac; text-underline-offset: 3px; }
      input, select, button, .primary { max-width: 100%; min-height: 44px; padding: .55rem .75rem; font: inherit; border: 1px solid #6e7d90; border-radius: 6px; background: white; color: #10263e; }
      button, .primary { cursor: pointer; }
      .primary { display: inline-flex; align-items: center; background: #2366d1; border-color: #2366d1; color: white; text-decoration: none; }
      :is(a, button, input, select):focus-visible { outline: 2px solid #2366d1; outline-offset: 3px; }
    </style></head><body>
    <header><a href="/account"><img src="https://onesa.eu/brand/icons/v1/onesa-company-180.png" alt="" width="32" height="32">Onesa Account</a>
    <nav aria-label="Account"><a href="/account">My account</a><a href="/admin">Administration</a></nav></header>
    <main${wide ? ' class="wide"' : ""}><h1>${esc(title)}</h1>${body}</main></body></html>`,
    { status, headers: { "content-type": "text/html; charset=utf-8" } },
  );
const redirect = (url, cookies = []) => {
  const headers = new Headers({ location: url });
  for (const c of cookies) headers.append("set-cookie", c);
  return new Response(null, { status: 303, headers });
};
const retryPath = (destination, origin) => {
  const target = new URL(destination, origin);
  const invite = target.searchParams.get("invite");
  if (invite && /^[A-Za-z0-9_-]{43}$/.test(invite))
    return "/login?invite=" + encodeURIComponent(invite);
  return target.pathname === "/admin" ? "/login?return=%2Fadmin" : "/login";
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
  const connectedProducts = new Set(Array.from(env.resources.values(), item => item.product));
  function productAccess(session) {
    const decisions = new Map(store.all(
      "SELECT product,status,role FROM grants WHERE id=?", session.id,
    ).map(row => [row.product, row]));
    const statusLabels = { pending: "Awaiting approval", active: "Approved", revoked: "Access removed", rejected: "Request declined" };
    const rows = [];
    for (const [product, { name }] of accountProducts) {
      const legacy = product === "internal-documents" && decisions.get("engineering-documents");
      const decision = decisions.get(product) || legacy;
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
    return rows.length ? '<h2>Product access</h2><ul class="products">' + rows.join("") + '</ul>' : '';
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
      const grant = store.activeGrant(actor.id, product);
      if (!grant || !products[product]?.includes(grant.role))
        return new Response(null, { status: 403 });
      return Response.json({
        user_id: actor.id,
        product,
        roles: [grant.role],
      });
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
      let destination =
        url.searchParams.get("return") === "/admin" || p === "/step-up"
          ? "/admin"
          : "/account";
      const invitation = url.searchParams.get("invite");
      if (invitation && /^[\w-]{43}$/.test(invitation))
        destination = "/account?invite=" + invitation;
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
      store.run("DELETE FROM challenges WHERE expires<=?", Date.now());
      store.run(
        "INSERT INTO challenges VALUES(?,?,?,?,?,?)",
        digest(token),
        state,
        nonce,
        verifier,
        destination,
        Date.now() + 300000,
      );
      return redirect(location, [cookie("flow", token, 300)]);
    }
    if (p === "/callback" && method === "GET") {
      const flow = store.one(
        "DELETE FROM challenges WHERE hash=? AND state=? AND expires>? RETURNING *",
        digest(readCookie(req, "flow")),
        url.searchParams.get("state"),
        Date.now(),
      );
      if (!flow)
        return page(
          "Sign-in expired",
          '<a href="/login">Start sign-in again</a>',
          400,
        );
      if (url.searchParams.get("error")) {
        return page(
          "Sign-in unavailable",
          '<a href="' + retryPath(flow.destination, env.origin) + '">Try again</a>',
          403,
        );
      }
      let identity;
      try {
        identity = await client.redeem(url, flow);
      } catch {
        // The challenge is one-use and has already been consumed. Preserve a
        // valid invitation in a safe local retry link if token exchange or
        // OIDC verification fails transiently.
        return page(
          "Sign-in temporarily unavailable",
          '<a href="' + retryPath(flow.destination, env.origin) + '">Try again</a>',
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
            retryPath(flow.destination, env.origin) +
            '">Continue sign-in</a>',
          403,
        );
      const target = new URL(flow.destination, env.origin);
      const user = store.register(
        env.issuer,
        identity.sub,
        identity.email,
        target.searchParams.get("invite") || "",
      );
      if (["suspended", "rejected"].includes(user.status))
        return page("Account unavailable", "", 403);
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
      return redirect(target.pathname + target.search, [
        cookie("session", session, 1800),
        cookie("flow", "", 0),
      ]);
    }
    const session = store.one(
      "SELECT s.*,a.email,a.status AS state FROM sessions s JOIN accounts a USING(id) WHERE hash=? AND expires>? AND a.status IN ('active','pending')",
      digest(readCookie(req, "session")),
      Date.now(),
    );
    if (p === "/" || p === "/account" || p === "/admin") {
      if (method !== "GET") return new Response(null, { status: 405 });
      if (!session) {
        if (p === "/admin") return redirect("/login?return=/admin");
        const invite = url.searchParams.get("invite");
        const suffix = invite && /^[\w-]{43}$/.test(invite) ? "?invite=" + encodeURIComponent(invite) : "";
        return page(
          "Sign in to Onesa",
          '<p class="muted">Use your existing Onesa account to access your approved products.</p>' +
          '<div class="actions"><a class="primary" href="/login' + suffix + '">Sign in to Onesa</a>' +
          '<a href="/register' + suffix + '">Create an Onesa account</a></div>',
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
            productAccess(session) +
            '<h2>Account security</h2><p><a href="/verify-factor">Verify or enroll a second factor</a></p>' +
            (env.connection
              ? post(
                  "/account/recovery",
                  session.csrf,
                  "<button>Send password reset email</button>",
                )
              : "<p>Use Forgot password on the sign-in screen to recover your password.</p>") +
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
      if (p === "/account/access") {
        const product = form.get("product");
        if (!connectedProducts.has(product) || !accountProducts.has(product))
          return page("Product unavailable", '<a href="/account">Return to your account</a>', 400);
        store.requestAccess(session.id, product);
        return redirect("/account");
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
        return redirect("/account", [cookie("session", "", 0)]);
      }
    }
    if (!["/admin", "/admin/change", "/admin/invite"].includes(p))
      return page("Page unavailable", "", 404);
    const identityGrant = session && store.activeGrant(session.id, "identity");
    if (!session || identityGrant?.role !== "admin")
      return page("Identity administrator required", "", 403);
    if (!session.mfa_at || Date.now() - session.mfa_at > 300000)
      return page(
        "Verify your identity",
        '<a href="/step-up">Continue with fresh MFA</a>',
        403,
      );
    if (p === "/admin" && method === "GET") {
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
          const grants = store
            .all(
              "SELECT product,role,status FROM grants WHERE id=? ORDER BY product",
              u.id,
            )
            .map((g) => [g.product, g.role, g.status].map(esc).join(" / "))
            .join(", ");
          return (
            "<article><h2>" +
            esc(u.email) +
            "</h2><p><code>" +
            esc(u.id) +
            "</code> · " +
            esc(u.status) +
            "</p><p>" +
            grants +
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
            post(
              "/admin/change",
              session.csrf,
              base +
                hidden("kind", "grant") +
                '<label>Product and role<select name="assignment">' +
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
      const [product, role] = (form.get("assignment") || "").split("/");
      store.change(session.id, form.get("id"), Number(form.get("revision")), {
        kind: form.get("kind"),
        product,
        role,
        status: form.get("status"),
      });
      return redirect("/admin?id=" + encodeURIComponent(form.get("id")));
    }
    return new Response(null, { status: 405 });
  }
  return async (req) => {
    let response;
    try {
      response = await handle(req);
    } catch (e) {
      response =
        e instanceof Rejected
          ? page("Request needs review", esc(e.message), 409)
          : page(
              "Identity temporarily unavailable",
              "Retry from the application where you started.",
              503,
            );
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
