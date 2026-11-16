// Bind immediately before post-login.cjs so the policy Action observes the completed challenge.
const mfaAcr = "http://schemas.openid.net/pape/policies/2007/06/multi-factor";
const operationAcr = "urn:onesa:authentication:operation-mfa";
const enrollmentTypes = ["otp", "webauthn-platform", "webauthn-roaming", "push-notification", "phone"];
const challengeTypes = [...enrollmentTypes, "recovery-code", "email"];

function values(input) {
  if (Array.isArray(input)) return input;
  return typeof input === "string" ? input.split(/\s+/) : [];
}

exports.onExecutePostLogin = async (event, api) => {
  const transaction = event.transaction || {};
  const requested = values(transaction.acr_values);
  const operation = requested.includes(operationAcr);
  if (!operation && !requested.includes(mfaAcr)) return;
  if (transaction.protocol === "oauth2-refresh-token") return;

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
