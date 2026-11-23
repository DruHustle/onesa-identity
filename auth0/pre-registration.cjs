// Bind to Auth0 Pre User Registration for the Onesa database/passwordless connections.
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
  } else if (event.client?.client_id !== undefined) {
    reason = "account_client_mismatch";
  } else if (
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
  } else {
    reason = "account_callback_unconfirmed";
  }
  console.log(JSON.stringify({ event: "onesa_signup_entry_denied", reason }));
  return api.access.deny("onesa_account_registration_required", "Start registration in Onesa Account.");
};
