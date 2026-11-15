// Offline projection into a separately restored Portal database. psql owns one transaction.
import { DatabaseSync } from "node:sqlite";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { digest, openStore, products, uuid } from "../src/store.js";
import { applySnapshot } from "./reconcile.js";

function requireState(value, message) {
  if (!value) throw new Error(message);
}
const productRoles = {
  ai: ["user", "admin"],
  robot: ["viewer", "operator", "admin"],
  drone: ["viewer", "operator", "admin"],
  farmer: ["user"],
  logistics: ["user"],
  factory: ["user"],
  mobile: products.mobile,
  pasofi: ["customer"],
};
function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, stable(value[key])]),
    );
  return value;
}
const json = (value) => JSON.stringify(stable(value));
function credentialMap(rows) {
  requireState(Array.isArray(rows), "Invalid credential continuity manifest");
  const receipts = new Map();
  for (const row of rows) {
    requireState(
      uuid(row.id) &&
        typeof row.receipt === "string" &&
        row.receipt.trim() &&
        row.receipt.length <= 400 &&
        !receipts.has(row.id),
      "Invalid or duplicate credential continuity proof",
    );
    receipts.set(row.id, row.receipt);
  }
  return receipts;
}
// Inputs are protected owner attestations, collected while the restored issuer is offline.
// A replacement hash was set by the user after provider reauthentication and stable-ID review.
function recoveryMap(rows) {
  requireState(Array.isArray(rows), "Invalid held-account recovery manifest");
  const recovered = new Map();
  for (const row of rows) {
    requireState(
      uuid(row.id) &&
        !recovered.has(row.id) &&
        typeof row.issuer === "string" &&
        typeof row.subject === "string" &&
        row.subject &&
        typeof row.receipt === "string" &&
        row.receipt.trim() &&
        row.receipt.length <= 400 &&
        typeof row.verified_at === "string" &&
        Number.isFinite(Date.parse(row.verified_at)) &&
        /^[0-9a-f]{32}:[0-9a-f]{128}$/.test(row.password_hash),
      "Invalid or duplicate held-account recovery proof",
    );
    recovered.set(row.id, row);
  }
  return recovered;
}
export function prepareLegacyRollback(
  db,
  key,
  snapshot,
  proofs,
  issuer,
  credentials = [],
  recoveries = [],
) {
  const checkStore = openStore(":memory:");
  let fingerprint;
  try {
    applySnapshot(checkStore, key, snapshot, proofs, issuer);
    fingerprint = checkStore.one(
      "SELECT digest FROM imports WHERE snapshot=?",
      key,
    ).digest;
  } finally {
    checkStore.db.close();
  }
  const continuity = credentialMap(credentials),
    recover = recoveryMap(recoveries);
  requireState(
    [...recover.keys()].every((id) => !continuity.has(id)),
    "Duplicate credential dispositions",
  );
  db.exec("BEGIN");
  try {
    const baseline = db
      .prepare("SELECT * FROM imports WHERE snapshot=?")
      .get(key);
    requireState(
      baseline?.digest === fingerprint,
      "Snapshot, proof manifest or issuer does not match cutover",
    );
    const events = db
      .prepare("SELECT * FROM audit WHERE seq>? ORDER BY seq")
      .all(baseline.watermark);
    requireState(
      events.every((event, i) => event.seq === baseline.watermark + i + 1),
      "Incomplete post-cutover journal",
    );
    const legacy = new Map(snapshot.accounts.map((a) => [a.id, a]));
    const all = db.prepare("SELECT * FROM accounts ORDER BY id").all();
    const ids = new Set(all.map((a) => a.id));
    requireState(
      [
        ...legacy.keys(),
        ...continuity.keys(),
        ...recover.keys(),
        ...events.map((e) => e.target).filter(Boolean),
      ].every((id) => ids.has(id)),
      "Missing baseline account, journal target or credential owner",
    );
    const emails = new Set();
    const issues = [];
    const rows = all.map((account) => {
      const { id, email, status } = account;
      requireState(
        uuid(id) &&
          typeof email === "string" &&
          /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) &&
          email === email.toLowerCase() &&
          !emails.has(email),
        "Conflicting contact address or invalid account at stable ID " + id,
      );
      emails.add(email);
      requireState(
        ["pending", "active", "suspended", "rejected"].includes(status),
        "Invalid account status at " + id,
      );
      const source = legacy.get(id);
      const links = db
        .prepare("SELECT * FROM links WHERE id=? ORDER BY issuer,subject")
        .all(id);
      const grants = db
        .prepare("SELECT * FROM grants WHERE id=? ORDER BY product")
        .all(id);
      const report = (reason) => issues.push({ id, reason });
      const linked = links.some(
        (link) => link.issuer === issuer && link.subject && link.evidence,
      );
      requireState(
        source ||
          events.some(
            (e) =>
              e.target === id &&
              ["register", "accept-invitation"].includes(e.action),
          ),
        "Missing new-account journal evidence for " + id,
      );
      requireState(
        grants.every(
          (g) =>
            Object.hasOwn(products, g.product) &&
            products[g.product].includes(g.role) &&
            ["pending", "active", "revoked", "rejected"].includes(g.status),
        ),
        "Invalid grant for " + id,
      );
      const index = new Map(grants.map((g) => [g.product, g]));
      const recovery = recover.get(id);
      if (recovery) {
        requireState(
          status === "active" &&
            (!source || source.email === email) &&
            recovery.issuer === issuer &&
            links.some(
              (l) =>
                l.issuer === issuer &&
                l.subject === recovery.subject &&
                l.evidence,
            ),
          "Recovery does not match an active account and verified provider identity at " +
            id,
        );
      }
      let enabled = status === "active";
      if (
        enabled &&
        !recovery &&
        (!source || !linked || !continuity.has(id) || source.email !== email)
      ) {
        enabled = false;
        report("credential-reauthentication-required");
      }
      if (source && source.email !== email)
        report("contact-change-requires-independent-verification");
      const portal = index.get("portal");
      let role = portal?.status === "active" ? portal.role : "member";
      if (["owner", "administrator"].includes(role)) {
        role = "member";
        report("portal-administrator-would-grant-global-access");
      }
      const access = [];
      for (const g of grants) {
        if (productRoles[g.product]?.includes(g.role)) {
          access.push({ product: g.product, role: g.role, status: g.status });
        } else if (!["portal", "engineering-documents"].includes(g.product)) {
          if (g.status === "active" || g.status === "pending")
            report("unrepresented-product-or-role/" + g.product + "/" + g.role);
        }
      }
      // Legacy verified Portal staff inherit Farmer without an explicit decision.
      if (role !== "member" && !access.some((g) => g.product === "farmer"))
        access.push({ product: "farmer", role: "user", status: "revoked" });
      const memberships = snapshot.docs.filter((d) => d.id === id);
      const oldDocs = index.get("engineering-documents"),
        canonical = index.get("internal-documents");
      const docGrant = oldDocs?.status === "active";
      const docsAllowed = Boolean(
        enabled &&
        docGrant &&
        oldDocs.role === "viewer" &&
        (!canonical || canonical.status === "active") &&
        !recovery,
      );
      // Keep the decision per legacy membership ID. Collapsing these into
      // one account-level boolean can accidentally enable a disabled
      // membership (or disable a separate enabled one) during rollback.
      const docsMemberships = memberships.map((membership) => ({
        membership_id: membership.membership_id,
        enabled: docsAllowed && membership.enabled,
      }));
      if (recovery && docGrant && memberships.some((m) => m.enabled))
        report("engineering-credential-reverification-required");
      if (
        docGrant &&
        (!memberships.some((m) => m.enabled) || oldDocs.role !== "viewer")
      )
        report("engineering-membership-needs-document-owner");
      if (docGrant && canonical && canonical.status !== "active")
        report("legacy-engineering-suppressed-by-canonical-decision");
      // Tenant roles are local records. Legacy publishes them without applying a grant-role ceiling.
      const drone = index.get("drone"),
        rank = ["viewer", "operator", "admin"];
      if (
        enabled &&
        snapshot.drone_memberships.some(
          (m) =>
            m.user_id === id &&
            (drone?.status !== "active" ||
              rank.indexOf(m.role) > rank.indexOf(drone.role)),
        )
      ) {
        enabled = false;
        report("drone-membership-would-exceed-product-access");
      }
      return {
        account,
        links,
        grants,
        credential_receipt: recovery?.receipt ?? continuity.get(id) ?? null,
        recovered_at: recovery?.verified_at ?? null,
        existing: Boolean(source),
        enabled,
        role,
        access,
        docs_memberships: docsMemberships,
        docs: docsMemberships.some((membership) => membership.enabled),
      };
    });
    for (const d of snapshot.docs)
      if (!d.id && d.enabled)
        issues.push({
          id: d.membership_id,
          reason: "unlinked-engineering-membership-disabled",
        });
    if (events.some((e) => e.action === "invite"))
      issues.push({ id: null, reason: "reissue-outstanding-invitations" });
    return {
      version: 2,
      key,
      fingerprint,
      watermark: baseline.watermark,
      through: events.at(-1)?.seq ?? baseline.watermark,
      events,
      rows,
      issues,
      snapshot,
      recovery_hashes: Object.fromEntries(
        [...recover]
          .filter(([, r]) => r.password_hash)
          .map(([id, r]) => [id, r.password_hash]),
      ),
    };
  } finally {
    db.exec("ROLLBACK");
  }
}

const exportSource = readFileSync(
  new URL("./export-portal.sql", import.meta.url),
  "utf8",
);
const select = exportSource.slice(
  exportSource.indexOf("SELECT jsonb_build_object"),
  exportSource.lastIndexOf(";\nCOMMIT"),
);
requireState(
  select.startsWith("SELECT jsonb_build_object") && !select.includes(";"),
  "Unexpected Portal export query",
);
const sqlJson = (object) =>
  "convert_from(decode('" +
  Buffer.from(json(object)).toString("base64") +
  "','base64'),'UTF8')::jsonb";

export function runLegacyRollback(
  plan,
  { apply = false, env = process.env } = {},
) {
  // Version 2 carries a per-membership decision. Never apply an older
  // account-wide docs boolean, which can re-enable a disabled sibling record.
  requireState(
    plan?.version === 2 &&
      Array.isArray(plan.rows) &&
      plan.rows.every((row) => Array.isArray(row.docs_memberships)),
    "Unsupported rollback plan; regenerate it with the current Identity code",
  );
  const input = sqlJson(plan);
  const hash = digest(json(plan));
  const sql = `\\set ON_ERROR_STOP on
BEGIN ISOLATION LEVEL SERIALIZABLE;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='120s';
SET LOCAL search_path=pg_catalog,public;
SET LOCAL TimeZone='UTC';
SELECT pg_advisory_xact_lock(286997644129);
LOCK TABLE public.users, public.identity_profiles, public.identity_product_access, public.engineering_memberships,
 public.identity_engineering_links, public.identity_drone_memberships, public.access_registrations,
 public.engineering_enrollment_accounts IN SHARE ROW EXCLUSIVE MODE;
CREATE TEMP TABLE work ON COMMIT DROP AS SELECT ${input} AS p;
CREATE TEMP VIEW target_snapshot AS ${select};
CREATE TABLE IF NOT EXISTS public.onesa_legacy_rollback_receipts(
 snapshot_key text PRIMARY KEY, manifest_sha text NOT NULL, after_sha text NOT NULL, through_seq integer NOT NULL,
 restricted_manifest jsonb NOT NULL, security_salt uuid NOT NULL, security_sha text NOT NULL, projected_at timestamptz NOT NULL DEFAULT now());
REVOKE ALL ON public.onesa_legacy_rollback_receipts FROM PUBLIC;
CREATE TEMP VIEW credential_state AS SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]'::jsonb) AS state FROM (
 SELECT u.id,u.password_hash,u.mfa_secret,u.mfa_pending,u.enroll_hash,
 (SELECT jsonb_agg(code_hash ORDER BY code_hash) FROM public.mfa_recovery WHERE user_id=u.id) AS recovery,
 (SELECT ec.password_hash FROM public.engineering_credentials ec JOIN public.identity_engineering_links l USING(membership_id) WHERE l.user_id=u.id) AS docs
 FROM public.users u) t;
DO $project$
DECLARE
 plan jsonb := (SELECT p FROM work); original jsonb := (SELECT * FROM target_snapshot);
 old public.onesa_legacy_rollback_receipts%ROWTYPE; x jsonb; a jsonb; g jsonb; uid uuid; state_hash text; salt uuid:=gen_random_uuid();
BEGIN
 state_hash:=encode(sha256(convert_to(original::text,'UTF8')),'hex');
 SELECT * INTO old FROM public.onesa_legacy_rollback_receipts WHERE snapshot_key=plan->>'key';
 IF FOUND THEN
   IF old.manifest_sha!='${hash}' OR old.after_sha!=state_hash OR old.security_sha!=(SELECT encode(sha256(convert_to(old.security_salt::text||state::text,'UTF8')),'hex') FROM credential_state) THEN RAISE EXCEPTION 'Rollback receipt or target diverged; keep restored issuer offline'; END IF;
   -- A verified idempotent retry can still be run against a restored target
   -- containing stale login or recovery credentials. These are outside the
   -- inventory and credential fingerprints, so always invalidate them again.
   DELETE FROM public.sessions; DELETE FROM public.identity_sessions; DELETE FROM public.identity_grant_sessions;
   DELETE FROM public.identity_records; DELETE FROM public.engineering_identity_records;
   DELETE FROM public.engineering_email_challenges; DELETE FROM public.access_links; DELETE FROM public.recovery_tokens;
   DELETE FROM public.identity_registration_links;
   IF to_regclass('public.portal_login_transactions') IS NOT NULL THEN EXECUTE 'DELETE FROM public.portal_login_transactions'; END IF;
   RETURN;
 END IF;
 IF EXISTS(SELECT 1 FROM public.onesa_legacy_rollback_receipts) THEN RAISE EXCEPTION 'Target already holds another rollback'; END IF;
 IF original IS DISTINCT FROM plan->'snapshot' THEN RAISE EXCEPTION 'Restored Portal inventory differs from original cutover snapshot; keep issuer offline'; END IF;
 FOR x IN SELECT value FROM jsonb_array_elements(plan->'rows') LOOP
   a:=x->'account'; uid:=(a->>'id')::uuid;
   IF (x->>'existing')::boolean THEN
     UPDATE public.users SET disabled=NOT (x->>'enabled')::boolean,role=x->>'role',
       password_hash=coalesce(plan->'recovery_hashes'->>(uid::text),password_hash),
       mfa_pending=NULL,enroll_hash=NULL,enroll_expires=NULL WHERE id=uid;
   ELSE
     -- Two random values in the legacy scrypt encoding. No usable credential exists.
     INSERT INTO public.users(id,email,password_hash,role,disabled) VALUES(uid,a->>'email',
       coalesce(plan->'recovery_hashes'->>(uid::text),replace(gen_random_uuid()::text,'-','')||':'||encode(sha512(convert_to(gen_random_uuid()::text,'UTF8')),'hex')),x->>'role',NOT (x->>'enabled')::boolean);
   END IF;
   IF x->>'recovered_at' IS NOT NULL THEN
     -- Provider proof establishes the person. Unverified pre-cutover recovery factors must not survive a credential replacement.
     IF plan->'recovery_hashes' ? (uid::text) THEN
       UPDATE public.users SET mfa_secret=NULL,mfa_last_step=-1 WHERE id=uid;
       DELETE FROM public.mfa_recovery WHERE user_id=uid;
     END IF;
     INSERT INTO public.identity_profiles(user_id,display_name,email_verified_at) VALUES(uid,'Onesa account',(x->>'recovered_at')::timestamptz)
       ON CONFLICT(user_id) DO UPDATE SET email_verified_at=coalesce(public.identity_profiles.email_verified_at,excluded.email_verified_at);
   END IF;
   -- Preserve historical approval metadata and revisions for grants that agree.
   UPDATE public.identity_product_access t SET status='revoked',revision=t.revision+1,updated_at=now(),reviewed_by=NULL
    WHERE t.user_id=uid AND t.status<>'revoked' AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(x->'access') v WHERE v->>'product'=t.product);
   FOR g IN SELECT value FROM jsonb_array_elements(x->'access') LOOP
     INSERT INTO public.identity_product_access AS t(user_id,product,role,status) VALUES(uid,g->>'product',g->>'role',g->>'status')
       ON CONFLICT(user_id,product) DO UPDATE SET role=excluded.role,status=excluded.status,revision=t.revision+1,updated_at=now(),reviewed_by=NULL
       WHERE (t.role,t.status) IS DISTINCT FROM (excluded.role,excluded.status);
   END LOOP;
   FOR g IN SELECT value FROM jsonb_array_elements(coalesce(x->'docs_memberships','[]'::jsonb)) LOOP
     UPDATE public.engineering_memberships m
       SET enabled=(g->>'enabled')::boolean,revision=m.revision+1
       WHERE m.id=(g->>'membership_id')::uuid
         AND m.enabled IS DISTINCT FROM (g->>'enabled')::boolean;
   END LOOP;
 END LOOP;
 UPDATE public.engineering_memberships m SET enabled=false,revision=m.revision+1
 WHERE enabled AND NOT EXISTS(SELECT 1 FROM public.identity_engineering_links l WHERE l.membership_id=m.id);
 DELETE FROM public.sessions; DELETE FROM public.identity_sessions; DELETE FROM public.identity_grant_sessions;
 DELETE FROM public.identity_records; DELETE FROM public.engineering_identity_records;
 DELETE FROM public.engineering_email_challenges; DELETE FROM public.access_links; DELETE FROM public.recovery_tokens;
 DELETE FROM public.identity_registration_links;
 IF to_regclass('public.portal_login_transactions') IS NOT NULL THEN EXECUTE 'DELETE FROM public.portal_login_transactions'; END IF;
 SELECT encode(sha256(convert_to(s::text,'UTF8')),'hex') INTO state_hash FROM target_snapshot t(s);
 INSERT INTO public.onesa_legacy_rollback_receipts(snapshot_key,manifest_sha,after_sha,through_seq,restricted_manifest,security_salt,security_sha)
 VALUES(plan->>'key','${hash}',state_hash,(plan->>'through')::integer,plan-'snapshot'-'recovery_hashes',salt,
   (SELECT encode(sha256(convert_to(salt::text||state::text,'UTF8')),'hex') FROM credential_state));
END $project$;
${apply ? "COMMIT" : "ROLLBACK"};\n`;
  const result = spawnSync("psql", ["-X", "-q", "-w", "-f", "-"], {
    input: sql,
    encoding: "utf8",
    env,
    maxBuffer: 4 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const known = [
      "Rollback receipt or target diverged",
      "Target already holds another rollback",
      "Restored Portal inventory differs",
    ];
    const cause =
      known.find((text) => String(result.stderr).includes(text)) ??
      "Database rejected the transaction";
    throw Error(
      "Legacy rollback stopped: " +
        cause +
        ". Keep the restored issuer offline.",
    );
  }
  return {
    applied: apply,
    manifest_sha: hash,
    through: plan.through,
    accounts: plan.rows.length,
    held: plan.rows.filter((r) => !r.enabled).length,
    issues: plan.issues,
  };
}

if (
  process.argv[1] &&
  pathToFileURL(process.argv[1]).href === import.meta.url
) {
  process.umask(0o077);
  const [mode, source, key, snapshot, proofs, issuer, continuity, recovery] =
    process.argv.slice(2);
  requireState(
    ["preview", "apply"].includes(mode) && issuer,
    "Usage: preview|apply FROZEN_IDENTITY_DB KEY SNAPSHOT.json PROOFS.json ISSUER [CREDENTIAL_CONTINUITY.json] [RECOVERY.json]; target via libpq PG* environment",
  );
  const db = new DatabaseSync(source, { readOnly: true }),
    read = (f) => JSON.parse(readFileSync(f, "utf8"));
  try {
    const plan = prepareLegacyRollback(
      db,
      key,
      read(snapshot),
      read(proofs),
      issuer,
      continuity ? read(continuity) : [],
      recovery ? read(recovery) : [],
    );
    console.log(
      JSON.stringify(runLegacyRollback(plan, { apply: mode === "apply" })),
    );
  } finally {
    db.close();
  }
}
