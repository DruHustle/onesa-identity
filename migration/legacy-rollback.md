# Roll back to the legacy Portal issuer

Use this tool to reconcile an isolated restore while both authorities are fenced against sign-in, token issuance and account or permission writes. Keep the old issuer fenced if preflight, projection, or acceptance fails. Independently issued product tokens can remain usable until their expiry. Drain or revoke those tokens at the product before reopening an issuer.

## Inputs

- A consistent, frozen copy of the active Identity database, including its final committed SQLite WAL. An SQLite backup taken after quiescing writers is suitable. The adapter opens it read-only.
- The original private `export-portal.sql` snapshot, the verified provider-link proof manifest, the issuer URL and the stable snapshot key used at cutover. The import fingerprint must match. Use UTC and the same export script on both sides.
- A separate Portal PostgreSQL restore containing the original credentials, profiles, policies, memberships and approvals, through Portal migration 019 or later. Supply the target through standard libpq connection settings such as `PGSERVICE` and `PGPASSFILE`. Restrict access to the restoration role and isolate the replica from production.
- Optional private credential dispositions. Never infer proof from an email match. Every existing active account with independently confirmed continuity of its **complete legacy credential set**, including password, enrolled MFA, backup codes and any legacy Engineering credential, may have one record in the continuity file. Each record contains `id` and the protected custody `receipt`. Verify the frozen credential backup, current possession and absence of intervening credential resets or compromise. Accounts without this evidence stay disabled unless recovery below applies.

For a new or changed credential, obtain fresh provider reauthentication, a verified contact address and independent stable-ID evidence through the supervised recovery process. Have the user establish a new Portal password under that process. Use the Portal scrypt encoder to produce a salted verifier inside the protected environment. A recovery row contains `id`, `issuer`, `subject`, `receipt`, `verified_at` in ISO 8601, and `password_hash`. The adapter checks the account is active, the issuer and subject match the Identity database, and the address agrees with any original Portal account. It installs the replacement verifier, clears old MFA factors and backup codes, and keeps the legacy Engineering membership disabled pending separate qualification. Complete Portal MFA reenrollment through its normal credential flow and verify it before release. A new user without a recovery record keeps the same UUID, a disabled Portal account, and an unusable verifier. A suspended or rejected account cannot be enabled by recovery. Credentials and receipt files require private custody, restricted permissions and a retention plan. Do not log them or pass credential values on a shell command line.

## Rehearsal and cutover

Run the two commands on the offline recovery host. Preview executes the same database operations as apply and rolls the transaction back. Omit optional manifests if none have been verified. Use an empty JSON array for continuity if supplying only recovery.

```sh
node migration/legacy-rollback.js preview frozen-identity.sqlite CUTOVER_KEY portal-snapshot.json provider-proofs.json https://auth.onesa.eu/ continuity.json recovery.json
node migration/legacy-rollback.js apply   frozen-identity.sqlite CUTOVER_KEY portal-snapshot.json provider-proofs.json https://auth.onesa.eu/ continuity.json recovery.json
```

The machine-readable result includes the final journal sequence, manifest digest, held account count and ID-scoped discrepancies. The adapter compares the original Portal inventory with the restored target under database locks, checks the continuity of the post-cutover audit journal and projects all accounts, including baseline accounts whose old roles implied more access than their managed grants. It transfers representable product grants, revocations and account status without changing content owners, tenant memberships, approval records or purchases. Legacy registration entries retain their original evidence. New provider subjects, approvals, changed roles, original journal events and outstanding discrepancies are retained in the restricted PostgreSQL receipt. Use the current product-owned databases for document ACLs, orders and purchases.

Portal's legacy owner and administrator roles confer global power. Their managed Portal grant is retained for review and their legacy role becomes member. A staff account without an explicit Farmer decision receives a revoked Farmer row to suppress implicit access. The adapter disables an account if its legacy Drone tenant membership would exceed its managed grant. Its original tenant rows remain available for owner reconciliation. The legacy Engineering membership can remain enabled only under its existing linked viewer approval and account credential continuity. An explicit canonical Internal Documents refusal suppresses the legacy Engineering fallback. Higher or new document permissions, Diaspora Unlocked, noncustomer PasoFi roles and Identity administration require their owning service to restore or reconcile them. Outstanding invitations are reissued by the appropriate owner. Reports and receipt data are private.

Cutover invalidates Portal sessions, OIDC records and grants, email challenges, sign-in links and recovery tokens. Confirm every affected product requires reauthentication. Identical retries use the saved receipt and verify both the policy projection and a salted digest of the resulting credential state. Changed snapshots, conflicting contact ownership, a different input manifest, target policy drift or credential drift stop the operation. For an updated recovery disposition, rebuild a fresh isolated target from the protected baseline and rerun with the updated manifests. Do not delete receipts to force a replay. Reconcile held accounts with their owners and check the original and new account IDs, grants, document bookmarks, memberships and purchases before directing traffic.

## Automated test

Use a new, empty loopback PostgreSQL database whose name ends in `_test` and the checked-out Portal migration directory. The test applies the real migrations, seeds synthetic records, runs previews and commits, and exercises conflicting retries. No production data is required.

```sh
LEGACY_PORTAL_TEST_URL="$TEST_DATABASE_URL" LEGACY_PORTAL_TEST_MIGRATIONS=/path/to/onesa-company-portal-backend/migrations node --test test/legacy-rollback.test.js
```
