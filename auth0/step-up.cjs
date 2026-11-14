// Bind before post-login.cjs. The later Action reads provider-recorded factor time.
exports.onExecutePostLogin = async (event, api) => {
  if (event.transaction?.protocol === 'oauth2-refresh-token') return;
  const requested=event.transaction?.acr_values || [];
  if(requested.includes('http://schemas.openid.net/pape/policies/2007/06/multi-factor')) {
    api.multifactor.enable('any',{allowRememberBrowser:false});
  }
};
