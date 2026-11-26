# Product sign-in

Web backends can share a confidential OAuth client and native apps can share a
public client. Each app starts Authorization Code with S256, state, nonce and
its API audience. The provider returns to the app's exact allowlisted callback.
The app restores the initiating screen. Create account uses the same flow with
`screen_hint=signup`.

Identity's resource registry binds each audience to a product and allowed
clients. A self-service resource can opt in with `enrollmentCallbacks`, an
array of `{ "client": "...", "redirectUri": "https://app.example.test/callback" }`
entries. Each callback is unique across the registry and must also be in the
provider allowlist. Use the same policy origin and credential for the
pre-registration and login Actions. A verified interactive transaction binds
the provider subject to an Identity ID and issues the starting product's
ordinary role. Existing grants, revocations and account status remain
authoritative. Staff tools and all privileged roles require approval.

Product APIs validate the access token's issuer, audience, expiry and RS256
signature. The signed `user_id`, `products` and `roles` claims identify the
account and the permitted product role. Staff and admin entry requires a
second factor. Sensitive operations require a fresh factor in the appropriate
authorization context.

The session target is a five-minute access token and rotating refresh tokens
with a 30-day idle and absolute limit. A refresh rechecks the existing grant
and cannot enroll an account. Web backends keep tokens encrypted server-side
behind an opaque secure cookie. Native clients use platform-protected
credentials or an opaque session with server-side token storage. Sign-out
clears the local session, revokes the refresh token and ends the provider
session at an allowlisted return URL.
