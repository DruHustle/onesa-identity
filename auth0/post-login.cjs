// Install in a dedicated Onesa Auth0 tenant, including refresh-token exchanges.
/**
 * Infrastructure applications authorize against the existing Portal resource.
 * Cloudflare Access and the Portainer owner client have independent bindings.
 */
function infrastructureAudience(event) {
  const secrets = event.secrets || {};
  const id = event.client?.client_id;
  const access = Boolean(id && id === secrets.INFRASTRUCTURE_SSO_CLIENT_ID);
  const portainer = Boolean(id && id === secrets.PORTAINER_SSO_CLIENT_ID);
  if (!access && !portainer)
    return { infrastructure: false, audience: event.resource_server?.identifier || "" };
  if (typeof id !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(id))
    throw Error("Invalid infrastructure client binding");
  if (portainer && (access || !secrets.PORTAINER_SSO_OWNER_SUB ||
      event.user?.user_id !== secrets.PORTAINER_SSO_OWNER_SUB ||
      event.resource_server?.identifier))
    throw Error("Invalid Portainer owner binding");
  const value = secrets.INFRASTRUCTURE_SSO_AUDIENCE;
  const url = new URL(value);
  if (url.protocol !== "https:" || value !== url.origin ||
      url.username || url.password || url.search || url.hash ||
      (event.resource_server?.identifier && event.resource_server.identifier !== value))
    throw Error("Invalid infrastructure audience");
  return { infrastructure: true, portainer, audience: value };
}

async function verificationDenial(event, policyOrigin, policyKey) {
  if (!event.secrets.ACCOUNT_CLIENT_ID ||
      event.client?.client_id !== event.secrets.ACCOUNT_CLIENT_ID ||
      event.client.client_id === event.secrets.INFRASTRUCTURE_SSO_CLIENT_ID ||
      event.client.client_id === event.secrets.PORTAINER_SSO_CLIENT_ID ||
      event.resource_server?.identifier ||
      event.transaction?.protocol !== "oidc-basic-profile")
    return "Onesa access is unavailable for this application.";

  const subject = event.user?.user_id;
  const query = event.request?.query;
  const now = Date.now();
  const freshPassword = (event.authentication?.methods || []).some(method => {
    const timestamp = Date.parse(method.timestamp);
    return method.name === "pwd" && timestamp <= now && now - timestamp <= 300000;
  });
  if (event.connection?.strategy !== "auth0" || !freshPassword ||
      query?.onesa_email_verification !== "resend" || !event.transaction.prompt?.includes("login") ||
      (query.max_age !== "0" && query.max_age !== 0) ||
      typeof subject !== "string" || !/^auth0\|[A-Za-z0-9_-]{1,128}$/.test(subject))
    return "Onesa email verification is required.";

  try {
    const response = await fetch(policyOrigin + "/internal/email-verification", {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(6500),
      headers: { authorization: "Bearer " + policyKey, "content-type": "application/json" },
      body: JSON.stringify({ subject, client: event.client.client_id }),
    });
    if (response.status === 202) return "Onesa email verification request accepted.";
    if (response.status === 429) return "Onesa email verification request is rate limited.";
  } catch {
    // A retry never grants access when the email provider is unavailable.
  }
  return "Onesa email verification request unavailable.";
}

// POLICY_URL and POLICY_KEY belong in the Action secret store.
async function applyPolicy(event, api, continuing = false) {
  const deny = () =>
    api.access.deny("Onesa access is unavailable for this application.");
  const { POLICY_URL, POLICY_ORIGIN, POLICY_KEY } = event.secrets || {};
  if (
    !POLICY_URL ||
    !POLICY_ORIGIN ||
    !POLICY_KEY
  )
    return deny();
  let decision, policyOrigin, resourceAudience;
  let infrastructure = false;
  let portainer = false;
  try {
    const url = new URL(POLICY_URL);
    const origin = new URL(POLICY_ORIGIN);
    // POLICY_KEY is a bearer credential. Require a separately configured,
    // canonical HTTPS origin as well as the one exact endpoint; a path-only
    // check would still leak the key if POLICY_URL named an attacker host.
    if (
      origin.protocol !== "https:" ||
      origin.username ||
      origin.password ||
      origin.pathname !== "/" ||
      origin.search ||
      origin.hash ||
      url.origin !== origin.origin ||
      url.pathname !== "/internal/decision" ||
      url.search ||
      url.hash ||
      url.username ||
      url.password
    )
      return deny();
    if (event.user?.email_verified !== true)
      return api.access.deny(await verificationDenial(event, origin.origin, POLICY_KEY));
    const audience = infrastructureAudience(event);
    policyOrigin = origin.origin;
    resourceAudience = audience.audience;
    infrastructure = audience.infrastructure;
    portainer = audience.portainer === true;
    const enrollment = !continuing && !infrastructure &&
      event.transaction?.protocol === "oidc-basic-profile" &&
      typeof event.transaction.redirect_uri === "string" && typeof event.user.email === "string"
      ? {
          verified: true,
          protocol: event.transaction.protocol,
          redirectUri: event.transaction.redirect_uri,
          email: event.user.email,
        }
      : undefined;
    const result = await fetch(url, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(3500),
      headers: {
        authorization: "Bearer " + POLICY_KEY,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        subject: event.user.user_id,
        audience: audience.audience,
        client: event.client.client_id,
        enrollment,
      }),
    });
    if (!result.ok) return deny();
    decision = await result.json();
  } catch {
    return deny();
  }
  const ns = "https://onesa.eu/claims/";
  if (infrastructure && (
    event.transaction?.protocol !== "oidc-basic-profile" ||
    decision?.product !== "portal" ||
    !Array.isArray(decision.roles) ||
    decision.roles.length !== 1 ||
    !["administrator", "owner"].includes(decision.roles[0])
  )) return deny();
  const transaction = event.transaction || {};
  const requested = Array.isArray(transaction.acr_values)
    ? transaction.acr_values
    : String(transaction.acr_values || "").split(/\s+/).filter(Boolean);
  if (decision.product === "pasofi" && requested.includes("urn:onesa:authentication:pasofi-customer") &&
      transaction.protocol !== "oauth2-refresh-token") {
    // A customer transaction can only lose privileges. The staff entry
    // still requires its own authorization and fresh authenticator proof.
    if (continuing || requested.length !== 1 || transaction.protocol !== "oidc-basic-profile" ||
        !decision.user_id || !Array.isArray(decision.roles) || decision.roles.length !== 1 ||
        !["customer", "admin", "administrator"].includes(decision.roles[0])) return deny();
    api.accessToken.setCustomClaim(ns + "user_id", decision.user_id);
    api.accessToken.setCustomClaim(ns + "products", ["pasofi"]);
    api.accessToken.setCustomClaim(ns + "roles", ["customer"]);
    return;
  }
  // Token issuance time is not evidence of a fresh factor.
  const observed = (event.authentication?.methods || [])
    .filter((m) => m.name === "mfa")
    .map((m) => Date.parse(m.timestamp))
    .filter(Number.isFinite);
  const latest = observed.length ? Math.max(...observed) : 0;
  const pasoFiRenewal = decision.product === "pasofi" && decision.platform_administrator !== true &&
    event.transaction?.protocol === "oauth2-refresh-token";
  let mfaTime = !pasoFiRenewal && latest > 0 && latest <= Date.now() ? Math.floor(latest / 1000) : 0;
  const now = Math.floor(Date.now() / 1000);
  const localProductFactor = (decision.product === "pasofi" || decision.platform_administrator === true) &&
    decision.require_mfa === true &&
    event.transaction?.protocol === "oidc-basic-profile";
  if (continuing || (localProductFactor &&
      (decision.platform_administrator === true || !mfaTime || now - mfaTime >= 300))) {
    if (!localProductFactor || !continuing && !api.redirect?.canRedirect()) return deny();
    const body = { subject: event.user.user_id, clientId: event.client.client_id, audience: resourceAudience };
    const phase = continuing ? "finish" : "start";
    if (continuing) {
      body.receipt = event.request?.body?.onesa_factor_receipt;
      body.state = event.request?.query?.state ?? event.request?.body?.state;
      if ((body.receipt !== undefined && typeof body.receipt !== "string") || typeof body.state !== "string") return deny();
    } else {
      body.continuation = "state";
      body.allowEnrollment = (event.authentication?.methods || []).some(method => {
        const authenticated = Date.parse(method.timestamp);
        return method.name === "pwd" && authenticated <= Date.now() && Date.now() - authenticated <= 300000;
      });
    }
    try {
      const response = await fetch(policyOrigin + "/internal/pasofi-authenticator/" + phase, {
        method: "POST", redirect: "error", signal: AbortSignal.timeout(3500),
        headers: { authorization: "Bearer " + POLICY_KEY, "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!response.ok) return deny();
      const proof = await response.json();
      if (!continuing) {
        if (typeof proof.ticket !== "string" || !/^[\w-]{43}$/.test(proof.ticket)) return deny();
        return api.redirect.sendUserTo(policyOrigin + "/account/pasofi-authenticator", { query: { ticket: proof.ticket } });
      }
      if (!Number.isSafeInteger(proof.mfaTime) || proof.mfaTime > now || now - proof.mfaTime >= 300) return deny();
      mfaTime = proof.mfaTime;
    } catch {
      return deny();
    }
  }
  if (!pasoFiRenewal && (decision.require_mfa === true || infrastructure) &&
      (!mfaTime || mfaTime > Math.floor(Date.now() / 1000) ||
       Math.floor(Date.now() / 1000) - mfaTime > 300)) return deny();
  const operation = transaction.protocol !== "oauth2-refresh-token" &&
    requested.includes("urn:onesa:authentication:operation-mfa");
  if (operation) {
    const metadata = transaction.metadata || {};
    const nonce = metadata.onesa_operation_mfa_nonce;
    const minimum = metadata.onesa_operation_mfa_minimum;
    if (transaction.protocol !== "oidc-basic-profile" || decision.product !== "portal" ||
        !mfaTime || !Number.isSafeInteger(minimum) || minimum <= 0 || latest < minimum ||
        typeof nonce !== "string" || !/^[A-Za-z0-9_-]{32,128}$/.test(nonce)) return deny();
  }
  if (decision.selfservice === true) {
    if (mfaTime) api.idToken.setCustomClaim(ns + "mfa_time", mfaTime);
    return;
  }
  if (!decision.user_id || !decision.product || !Array.isArray(decision.roles))
    return deny();
  // Portainer uses standard UserInfo for its separately provisioned owner.
  if (portainer) return;
  // Cloudflare evaluates this signed ID-token claim; email or a normal Portal
  // session is never sufficient. No implicit grant or self-service decision.
  if (infrastructure) {
    if (!api.idToken?.setCustomClaim) return deny();
    api.idToken.setCustomClaim(ns + "infrastructure_admin", "approved");
  }
  if (mfaTime) api.accessToken.setCustomClaim(ns + "mfa_time", mfaTime);
  if (decision.platform_administrator === true && decision.require_mfa === true && mfaTime &&
      decision.roles.length === 1 && decision.roles[0] === "administrator")
    api.accessToken.setCustomClaim(ns + "platform_administrator", true);
  if (decision.portal_staff_registration === true && decision.product === "portal" &&
      decision.require_mfa === true && decision.roles.length === 1 && decision.roles[0] === "administrator")
    api.accessToken.setCustomClaim(ns + "portal_staff_registration", true);
  if (operation)
    api.accessToken.setCustomClaim(ns + "operation_mfa_nonce", transaction.metadata.onesa_operation_mfa_nonce);
  for (const [name, value] of Object.entries({
    user_id: decision.user_id,
    products: [decision.product],
    roles: decision.roles,
  }))
    api.accessToken.setCustomClaim(ns + name, value);
}

exports.onExecutePostLogin = async function (event, api) { return applyPolicy(event, api); };
exports.onContinuePostLogin = async function (event, api) { return applyPolicy(event, api, true); };
