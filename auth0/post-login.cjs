// Install in a dedicated Onesa Auth0 tenant, including refresh-token exchanges.
// POLICY_URL and POLICY_KEY belong in the Action secret store.
exports.onExecutePostLogin = async (event, api) => {
  const deny = () =>
    api.access.deny("Onesa access is unavailable for this application.");
  const { POLICY_URL, POLICY_KEY } = event.secrets || {};
  if (!POLICY_URL || !POLICY_KEY || event.user?.email_verified !== true) return deny();
  let decision;
  try {
    const url = new URL(POLICY_URL);
    // This secret is sent as a bearer credential. Refuse URL decorations or
    // paths other than the documented private policy endpoint so a typo or
    // injected query/redirect target cannot forward the key to another route.
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      url.pathname !== "/internal/decision"
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
  const mfaTime = observed.length
    ? Math.floor(Math.max(...observed) / 1000)
    : 0;
  if (decision.selfservice === true) {
    if (mfaTime) api.idToken.setCustomClaim(ns + "mfa_time", mfaTime);
    return;
  }
  if (!decision.user_id || !decision.product || !Array.isArray(decision.roles))
    return deny();
  if (mfaTime) api.accessToken.setCustomClaim(ns + "mfa_time", mfaTime);
  for (const [name, value] of Object.entries({
    user_id: decision.user_id,
    products: [decision.product],
    roles: decision.roles,
  }))
    api.accessToken.setCustomClaim(ns + name, value);
};
