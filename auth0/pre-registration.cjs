// Bind to Auth0 Pre User Registration for the Onesa database/passwordless connections.
async function registeredApplication(event, transaction) {
  const { POLICY_ORIGIN, POLICY_KEY } = event.secrets || {};
  if (!POLICY_ORIGIN || !POLICY_KEY || transaction.protocol !== "oidc-basic-profile" ||
      typeof transaction.redirect_uri !== "string" ||
      (transaction.response_type !== undefined &&
        (!Array.isArray(transaction.response_type) ||
          transaction.response_type.length !== 1 || transaction.response_type[0] !== "code"))) return false;
  try {
    const origin = new URL(POLICY_ORIGIN);
    if (origin.protocol !== "https:" || ![origin.origin, origin.origin + "/"].includes(POLICY_ORIGIN))
      return false;
    const response = await fetch(origin.origin + "/internal/signup-entry", {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(3500),
      headers: { authorization: "Bearer " + POLICY_KEY, "content-type": "application/json" },
      body: JSON.stringify({ client: event.client?.client_id, redirectUri: transaction.redirect_uri }),
    });
    return response.status === 204;
  } catch {
    return false;
  }
}

exports.onExecutePreUserRegistration = async (event, api) => {
  const { ACCOUNT_CLIENT_ID, ACCOUNT_CALLBACK_URL } = event.secrets || {};
  const transaction = event.transaction;
  let reason;
  if (!ACCOUNT_CLIENT_ID) {
    reason = "account_client_unconfigured";
  } else if (!transaction || typeof transaction !== "object" || Array.isArray(transaction)) {
    reason = "hosted_transaction_missing";
  } else if (event.client?.client_id === ACCOUNT_CLIENT_ID) {
    return;
  } else if (
    event.client?.client_id === undefined &&
    ACCOUNT_CALLBACK_URL &&
    transaction.redirect_uri === ACCOUNT_CALLBACK_URL &&
    transaction.protocol === "oidc-basic-profile" &&
    (transaction.response_type === undefined ||
      (Array.isArray(transaction.response_type) &&
        transaction.response_type.length === 1 && transaction.response_type[0] === "code"))
  ) {
    // Auth0 validates this redirect against the initiating application's
    // allowlist. Configure it only when this exact URL is unique to Account.
    return;
  } else if (await registeredApplication(event, transaction)) {
    return;
  } else if (event.client?.client_id !== undefined) {
    reason = "account_client_mismatch";
  } else {
    reason = "account_callback_unconfirmed";
  }
  console.log(JSON.stringify({ event: "onesa_signup_entry_denied", reason }));
  return api.access.deny("onesa_account_registration_required", "Registration is unavailable from this application.");
};
