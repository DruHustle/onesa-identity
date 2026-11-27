import { createRemoteJWKSet, jwtVerify } from "jose";
import { Rejected } from "./store.js";

const audience = "https://api.pasofi.mobile.onesa.eu";
const product = "pasofi";
const claims = "https://onesa.eu/claims/";
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const requestKinds = {
  staff: { kind: "product-staff-review", states: ["active", "rejected", "revoked"] },
  administrator: { kind: "product-administrator-review", states: ["active", "rejected"] },
};
const error = (code, status) => Response.json({ error: code }, { status });

export function pasoFiStaffAdministration(store, env, keys = createRemoteJWKSet(new URL(".well-known/jwks.json", env.issuer))) {
  const resource = env.resources.get(audience);
  return async (request) => {
    if (!["GET", "POST"].includes(request.method)) return error("method_not_allowed", 405);
    if (resource?.product !== product) return error("staff_administration_unavailable", 503);
    const authorization = request.headers.get("authorization") ?? "";
    if (authorization.length > 16400 || !/^Bearer [\w-]+\.[\w-]+\.[\w-]+$/.test(authorization))
      return error("staff_mfa_required", 401);

    let payload;
    try {
      ({ payload } = await jwtVerify(authorization.slice(7), keys, {
        issuer: env.issuer, audience, algorithms: ["RS256"], requiredClaims: ["sub", "iat", "exp"],
      }));
    } catch {
      return error("staff_mfa_required", 401);
    }
    const role = payload[claims + "roles"];
    const scope = payload[claims + "products"];
    const factor = payload[claims + "mfa_time"];
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.sub !== "string" || payload.sub.length > 512 ||
        !Number.isSafeInteger(payload.iat) || payload.iat > now || payload.exp <= payload.iat ||
        !resource.clients.includes(payload.azp) || payload.exp - payload.iat > 300 ||
        !Array.isArray(scope) || scope.length !== 1 || scope[0] !== product ||
        !Array.isArray(role) || role.length !== 1 || !["admin", "administrator"].includes(role[0]))
      return error("admin_required", 403);
    if (!Number.isSafeInteger(factor) || factor <= 0 || factor > now || now - factor >= 300)
      return error("staff_mfa_required", 428);

    let body;
    if (request.method === "POST") {
      if (!request.headers.get("content-type")?.startsWith("application/json"))
      return error("invalid_staff_request", 400);
      try { body = await request.json(); }
      catch { return error("invalid_staff_request", 400); }
      if (!body || typeof body !== "object" || Array.isArray(body)) return error("invalid_staff_request", 400);
    }
    const actor = store.lookup(env.issuer, payload.sub);
    if (actor?.status !== "active" || actor.id !== payload[claims + "user_id"] ||
        (!store.activeProductAdministrator(actor.id, product) && store.activeGrant(actor.id, product)?.role !== "administrator"))
      return error("admin_required", 403);

    if (request.method === "GET") {
      const requests = store.all(`SELECT a.id, a.email, a.revision,
        CASE e.action WHEN 'product-staff-request' THEN 'staff' ELSE 'administrator' END AS kind,
        json_extract(e.detail,'$.status') AS status
        FROM accounts a JOIN audit e ON e.seq IN (
          SELECT max(seq) FROM audit WHERE target=a.id
            AND action IN ('product-staff-request','product-administrator-request')
            AND json_extract(detail,'$.product')=? GROUP BY action
        ) WHERE a.status IN ('active','pending') AND (
          json_extract(e.detail,'$.status')='pending' OR
          (e.action='product-staff-request' AND json_extract(e.detail,'$.status')='active')
        ) ORDER BY status DESC, a.email`, product);
      return Response.json({ requests });
    }

    try {
      if (body.action === "invite" && typeof body.email === "string" && body.email.trim().length <= 254) {
        const token = store.invite(actor.id, body.email.trim());
        const invitation = new URL("/register", env.origin);
        invitation.search = new URLSearchParams({ invite: token, return: "/access?product=pasofi&role=agent" });
        return Response.json({ invitationUrl: invitation.href }, { status: 201 });
      }
      const operation = typeof body.kind === "string" && Object.hasOwn(requestKinds, body.kind) ? requestKinds[body.kind] : null;
      if (body.action !== "review" || !operation || typeof body.id !== "string" || !uuid.test(body.id) ||
          !Number.isSafeInteger(body.revision) || body.revision < 1 || !operation.states.includes(body.status))
        return error("invalid_staff_request", 400);
      if (body.id === actor.id) return error("independent_reviewer_required", 403);
      store.change(actor.id, body.id, body.revision, { kind: operation.kind, product, status: body.status }, product);
      return Response.json({ saved: true });
    } catch (failure) {
      if (failure instanceof Rejected) return Response.json({ error: "staff_review_conflict", detail: failure.message }, { status: 409 });
      throw failure;
    }
  };
}
