// Bind immediately before post-login.cjs so the policy Action observes the completed challenge.
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
  return { infrastructure: true, audience: value };
}

const mfaAcr = "http://schemas.openid.net/pape/policies/2007/06/multi-factor";
const operationAcr = "urn:onesa:authentication:operation-mfa";
const enrollmentTypes = ["otp", "webauthn-platform", "webauthn-roaming", "push-notification", "phone"];
const challengeTypes = [...enrollmentTypes, "recovery-code", "email"];

function values(input) {
  if (Array.isArray(input)) return input;
  return typeof input === "string" ? input.split(/\s+/) : [];
}

async function needsSharedMfa(event, customerEntry) {
  const { POLICY_URL, POLICY_ORIGIN, POLICY_KEY } = event.secrets || {};
  const audience = infrastructureAudience(event);
  if (!audience.audience || !event.user?.email_verified ||
      !POLICY_URL || !POLICY_ORIGIN || !POLICY_KEY) return false;
  const now = Date.now();
  if ((event.authentication?.methods || []).some(method => {
    const timestamp = Date.parse(method.timestamp);
    return method.name === "mfa" && timestamp <= now && now - timestamp <= 300000;
  })) return false;
  const origin = new URL(POLICY_ORIGIN);
  if (origin.protocol !== "https:" || origin.username || origin.password ||
      ![origin.origin, origin.origin + "/"].includes(POLICY_ORIGIN) ||
      POLICY_URL !== origin.origin + "/internal/decision") throw Error("Invalid policy origin");
  const response = await fetch(POLICY_URL, {
    method: "POST", redirect: "error", signal: AbortSignal.timeout(3500),
    headers: { authorization: "Bearer " + POLICY_KEY, "content-type": "application/json" },
    body: JSON.stringify({ subject: event.user.user_id, audience: audience.audience, client: event.client.client_id }),
  });
  if (!response.ok) {
    if (audience.infrastructure) throw Error("Infrastructure authorization refused");
    return false; // The issuance Action makes the authoritative decision after MFA.
  }
  const decision = await response.json();
  if (audience.infrastructure) {
    // An explicitly granted Portal owner/administrator is the only principal
    // eligible for infrastructure MFA; editor, viewer and pending are denied.
    if (decision.product !== "portal" || !Array.isArray(decision.roles) ||
        decision.roles.length !== 1 || !["administrator", "owner"].includes(decision.roles[0]))
      throw Error("Infrastructure administrator grant required");
    return true; // An explicit admin grant still requires a fresh second factor.
  }
  if (customerEntry && decision.product === "pasofi") return false;
  return decision.require_mfa === true;
}

exports.onExecutePostLogin = async (event, api) => {
  const transaction = event.transaction || {};
  const requested = values(transaction.acr_values);
  const operation = requested.includes(operationAcr);
  if (transaction.protocol === "oauth2-refresh-token") return;
  if (!operation && !requested.includes(mfaAcr)) {
    const customerEntry = transaction.protocol === "oidc-basic-profile" &&
      requested.length === 1 && requested[0] === "urn:onesa:authentication:pasofi-customer";
    try { if (!await needsSharedMfa(event, customerEntry)) return; }
    catch { return api.access.deny("Onesa access is temporarily unavailable."); }
  }

  const deny = () => api.access.deny("Onesa could not verify a fresh second factor.");
  const prompts = values(transaction.prompt);
  if (!["oidc-basic-profile", "oidc-hybrid-profile", "oidc-implicit-profile"].includes(transaction.protocol) ||
      prompts.includes("none")) return deny();
  const enrolled = event.user?.enrolledFactors;
  if (!Array.isArray(enrolled)) return deny();
  const types = new Set(enrolled.map(factor => factor.type));
  const factors = challengeTypes.filter(type => types.has(type)).map(type => ({ type }));

  if (operation) {
    const query = event.request?.query || {};
    if (transaction.protocol !== "oidc-basic-profile" || !requested.includes(mfaAcr) ||
        !prompts.includes("login") || (query.max_age !== "0" && query.max_age !== 0) ||
        typeof query.nonce !== "string" || !/^[A-Za-z0-9_-]{32,128}$/.test(query.nonce) ||
        !factors.some(factor => factor.type !== "email")) return deny();

    // Auth0 can replace request.query when it resumes after the factor prompt.
    // Keep the binding in this transaction only, never in app/user/session metadata.
    const priorTimes = (event.authentication?.methods || [])
      .filter(method => method.name === "mfa")
      .map(method => Date.parse(method.timestamp)).filter(Number.isFinite);
    const minimumTime = Math.max(Math.floor(Date.now() / 1000) * 1000,
      ...priorTimes.map(timestamp => timestamp + 1));
    api.transaction.setMetadata("onesa_operation_mfa_nonce", query.nonce);
    api.transaction.setMetadata("onesa_operation_mfa_minimum", minimumTime);
  }

  // Email can appear automatically for verified addresses without an MFA enrollment.
  if (factors.some(factor => factor.type !== "email")) {
    api.authentication.challengeWithAny(factors);
  } else if (!enrolled.some(factor => factor.type !== "email")) {
    api.authentication.enrollWithAny(enrollmentTypes.map(type => ({ type })));
  } else {
    return deny();
  }
};
