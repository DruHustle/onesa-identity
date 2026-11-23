# Onesa Portal admin SSO for infrastructure consoles

This integration is **not active merely because the source files are merged**.
Production cutover is fail-closed and requires an approved Auth0 client,
role-claim readback, Cloudflare Access policy, and real-browser qualification.
Never substitute an email allowlist for the live Portal administrator grant.

## Protected destinations

- `https://it-infrastructure.onesa.eu` — private infrastructure directory
- `https://portainer.onesa.eu` — private Portainer / Kubernetes UI

These applications remain independently authenticated at the edge. Portainer
must keep its separate administrator authorization and must not expose an
unprotected Kubernetes or management port.

## Authentication contract

1. Create a dedicated confidential **Regular Web Application** in the existing
   Onesa Auth0 tenant for Cloudflare Access. Its exact permitted callback is
   `https://andrewgotora.cloudflareaccess.com/cdn-cgi/access/callback`.
   Use Authorization Code with PKCE. Do not reuse a frontend/native client,
   publish its secret, or enable broad wildcard callbacks.
2. Register that new Auth0 client ID under the *existing* Portal resource in
   `RESOURCE_CLIENTS_JSON` in the protected Onesa Identity production
   environment. The resource must have `product: "portal"`; the canonical
   audience is the **existing production Portal audience** (for example,
   `https://api.portal.onesa.eu`, only if that exact audience is actually
   configured). An unknown client or audience must be denied.
3. Add to **both** Auth0 Actions (`auth0/step-up.cjs` first, then
   `auth0/post-login.cjs`) these Action secrets:
   - `INFRASTRUCTURE_SSO_CLIENT_ID`: exact new confidential client ID.
   - `INFRASTRUCTURE_SSO_AUDIENCE`: exact canonical HTTPS Portal audience from
     the resource registry. Must be its origin only (no path or query).
   Keep existing `POLICY_URL`, `POLICY_ORIGIN`, and `POLICY_KEY` secrets in
   the Auth0 Action store; do not commit or print their values.
4. The Actions use the same live `/internal/decision` service already used
   by Onesa products. They require **active Portal `administrator` or
   `owner` role**, the exact client and audience, verified email, a valid
   interactive browser flow, and recent completed MFA. Otherwise they deny
   token issuance. Only after these checks may the dedicated client's
   ID token receive the claim:
   `https://onesa.eu/claims/infrastructure_admin = "approved"`.
   Normal Onesa product clients must never receive the claim.
5. Add a **Generic OIDC** identity provider in Cloudflare Access for the
   Auth0 tenant's public discovery endpoints. Register the same exact
   Cloudflare callback in Auth0, and configure Cloudflare's OIDC Claim
   extraction for `https://onesa.eu/claims/infrastructure_admin`. Store
   the confidential Auth0 client secret only in the provider's encrypted
   configuration, not in Cloudflare Workers, public Vercel variables, Git,
   or client-side code.
6. In **both** Cloudflare Access self-hosted applications, select *only*
   this OIDC provider. The Allow policy must have an **OIDC Claim**
   requirement for the exact `infrastructure_admin=approved` value,
   and must not have an independent email-only or Cloudflare-account-only
   bypass. Keep independent TOTP/security-key MFA and bounded sessions.
   Test an unapproved account before removing the temporary owner-only
   policy. The claim requirement, issuer, and role binding must be proven
   in a real authentication flow before switching any production routes.
7. After enforcing both policies, revoke previous Access sessions so a
   previously admitted Cloudflare-account login cannot continue under its
   old cookie. An administrator removal affects subsequent issuance but
   does not automatically revoke already issued Cloudflare Access cookies;
   use Access session revocation on urgent removal.

## Portainer application sign-in

Portainer uses a separate confidential Regular Web Application with its exact
HTTPS callback. Keep it on the same canonical Onesa issuer and owner login
connection as Cloudflare Access so both applications can reuse the Auth0 session.
Allow Authorization Code and only the scopes needed for OIDC UserInfo. Configure
neither a product API audience nor refresh tokens on the Portainer client.

Register that client under the existing Portal resource in `RESOURCE_CLIENTS_JSON`.
Set `PORTAINER_SSO_CLIENT_ID` and `PORTAINER_SSO_OWNER_SUB` in both Actions. Use
the owner’s verified Auth0 subject and the existing `INFRASTRUCTURE_SSO_AUDIENCE`.
The Actions require the exact owner subject, an active Portal administrator or
owner grant, verified email, and recent MFA. Portainer receives the standard OIDC
profile. Infrastructure and product access claims stay with their respective
clients.

Pre-provision the verified owner in Portainer and leave automatic user, team,
and admin provisioning disabled. Verify the original administrator can still
reach Portainer through the private management route before choosing OAuth.
Keep the existing Access recovery path until the owner passes the complete
Onesa and Portainer sign-in in a fresh browser, and ordinary accounts are denied.
On rollback, restore Internal authentication using the original administrator,
then restore the previous Access configuration if it changed.

## Launch acceptance

Test on a fresh browser without existing Access cookies, before cutover:

- Approved Portal administrator with authentic Auth0 MFA: allowed by Access,
  then separately authorized by Portainer.
- Ordinary Portal member, editor, viewer, pending admin, suspended/disabled
  account, non-Portal app admin, invalid grant, unverified email: denied.
- Removed Portal admin grant: denied on fresh token issuance; independently
  revoke any previously issued Access session.
- No MFA, expired MFA, simulated Auth0 Policy endpoint outage, incorrect client
  ID or audience: denied, no infrastructure claim.
- Both custom domains, callback and logout; no alternative `workers.dev`,
  direct port or hostname bypass.

The automated regression suite in `test/infrastructure-sso.test.js` tests
Action claim issuance boundaries. It is **not** proof of hosted tenant and
Cloudflare policy activation. Keep the previous owner-only Access policy
until all browser tests have passed.
