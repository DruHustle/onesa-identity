// Bind to Auth0 Pre User Registration for the Onesa database/passwordless connections.
exports.onExecutePreUserRegistration = async (event, api) => {
  const accountClient = event.secrets?.ACCOUNT_CLIENT_ID;
  if (!accountClient || event.client?.client_id !== accountClient || !event.transaction)
    return api.access.deny("onesa_account_registration_required", "Start registration in Onesa Account.");
};
