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
exports.onExecutePostLogin = async (event, api) => {
  const deny = () =>
    api.access.deny("Onesa access is unavailable for this application.");
  const { POLICY_URL, POLICY_ORIGIN, POLICY_KEY } = event.secrets || {};
  if (
    !POLICY_URL ||
    !POLICY_ORIGIN ||
    !POLICY_KEY
  )
    return deny();
  let decision;
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
    infrastructure = audience.infrastructure;
    portainer = audience.portainer === true;
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
  // Token issuance time is not evidence of a fresh factor.
  const observed = (event.authentication?.methods || [])
    .filter((m) => m.name === "mfa")
    .map((m) => Date.parse(m.timestamp))
    .filter(Number.isFinite);
  const latest = observed.length ? Math.max(...observed) : 0;
  const mfaTime = latest > 0 && latest <= Date.now() ? Math.floor(latest / 1000) : 0;
  if ((decision.require_mfa === true || infrastructure) &&
      (!mfaTime || mfaTime > Math.floor(Date.now() / 1000) ||
       Math.floor(Date.now() / 1000) - mfaTime > 300)) return deny();
  const transaction = event.transaction || {};
  const requested = Array.isArray(transaction.acr_values)
    ? transaction.acr_values
    : String(transaction.acr_values || "").split(/\s+/);
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
};
