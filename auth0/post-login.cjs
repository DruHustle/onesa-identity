// Install in a dedicated Onesa Auth0 tenant, including refresh-token exchanges.
// POLICY_URL and POLICY_KEY belong in the Action secret store.
exports.onExecutePostLogin = async (event, api) => {
  const deny = () =>
    api.access.deny("Onesa access is unavailable for this application.");
  const { POLICY_URL, POLICY_ORIGIN, POLICY_KEY } = event.secrets || {};
  if (
    !POLICY_URL ||
    !POLICY_ORIGIN ||
    !POLICY_KEY ||
    event.user?.email_verified !== true
  )
    return deny();
  let decision;
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
        audience: event.resource_server?.identifier || "",
        client: event.client.client_id,
      }),
    });
    if (!result.ok) return deny();
    decision = await result.json();
  } catch {
    return deny();
  }
  const ns = "https://onesa.eu/claims/";
  // Token issuance time is not evidence of a fresh factor.
  const observed = (event.authentication?.methods || [])
    .filter((m) => m.name === "mfa")
    .map((m) => Date.parse(m.timestamp))
    .filter(Number.isFinite);
  const latest = observed.length ? Math.max(...observed) : 0;
  const mfaTime = latest > 0 && latest <= Date.now() ? Math.floor(latest / 1000) : 0;
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
  if (mfaTime) api.accessToken.setCustomClaim(ns + "mfa_time", mfaTime);
  if (operation)
    api.accessToken.setCustomClaim(ns + "operation_mfa_nonce", transaction.metadata.onesa_operation_mfa_nonce);
  for (const [name, value] of Object.entries({
    user_id: decision.user_id,
    products: [decision.product],
    roles: decision.roles,
  }))
    api.accessToken.setCustomClaim(ns + name, value);
};
