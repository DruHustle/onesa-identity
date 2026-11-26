import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { pathToFileURL } from "node:url";
import { openStore, products, configurableAdminRoles, sharedProducts } from "./store.js";
import { createApp } from "./web.js";
import { infrastructureEntry, registrationReturns, returnKey } from "./registration-returns.js";

const hostname = url => url.hostname.replace(/\.$/, "");
const productionIdentityHosts = ["account.onesa.eu", "auth.onesa.eu", "onesa.eu.auth0.com"];

function stagingRegistrationReturns(issuer, account, override) {
  const productionAccount = "https://account.onesa.eu";
  const productionHosts = new Set([...productionIdentityHosts, "portainer.onesa.eu"]);
  for (const target of registrationReturns(productionAccount).values()) {
    const url = new URL(target);
    if (url.protocol === "https:") productionHosts.add(hostname(url));
  }
  if (hostname(issuer) === hostname(account) ||
      [issuer, account].some(url => productionHosts.has(hostname(url))))
    throw Error("Staging requires separate nonproduction issuer and Account hosts");

  const returns = registrationReturns(account.origin, override);
  const landing = returns.get(returnKey("portal", "web", "admin", infrastructureEntry));
  if (!landing || [hostname(issuer), hostname(account)].includes(hostname(new URL(landing))))
    throw Error("Staging requires a separate Infrastructure registration landing");
  for (const target of returns.values()) {
    const url = new URL(target);
    if (url.protocol !== "https:" || productionHosts.has(hostname(url)))
      throw Error("Staging registration returns require nonproduction HTTPS hosts");
  }
  return returns;
}

export function configuration(env) {
  const required = (k) => {
    if (!env[k]) throw Error(k + " is required");
    return env[k];
  };
  function credential(key) {
    const path = env[key + "_FILE"];
    if (!path) return required(key);
    if (env[key]) throw Error("Set only one source for " + key);
    const value = readFileSync(path, "utf8").replace(/\r?\n$/, "");
    if (!value || /[\r\n\0]/.test(value)) throw Error("Invalid credential file for " + key);
    return value;
  }
  const storeMode = env.IDENTITY_STORE_MODE ?? "create";
  if (!["create", "existing"].includes(storeMode)) throw Error("Invalid IDENTITY_STORE_MODE");
  const isStaging = env.IDENTITY_ENVIRONMENT === "staging";
  if (isStaging && storeMode !== "existing") throw Error("Staging requires a commissioned store");
  const issuer = new URL(required("OIDC_ISSUER")),
    origin = new URL(required("IDENTITY_ORIGIN"));
  for (const u of [issuer, origin])
    if (
      u.protocol !== "https:" ||
      u.username ||
      u.password ||
      u.search ||
      u.hash ||
      u.pathname !== "/"
    )
      throw Error("Expected HTTPS origin");
  const returns = isStaging
    ? stagingRegistrationReturns(issuer, origin, env.REGISTRATION_RETURNS_JSON)
    : registrationReturns(origin.origin, env.REGISTRATION_RETURNS_JSON);
  const resources = new Map(),
    catalog = JSON.parse(required("RESOURCE_CLIENTS_JSON"));
  const clientId = required("OIDC_CLIENT_ID");
  const enrollmentReturns = new Set([origin.origin + "/callback"]);
  for (const [audience, resource] of Object.entries(catalog)) {
    let endpoint;
    try {
      if (typeof audience !== "string" || !audience || audience.trim() !== audience)
        throw Error("Invalid audience");
      endpoint = new URL(audience);
    } catch {
      throw Error("Invalid resource registry");
    }
    if (
      endpoint.protocol !== "https:" ||
      endpoint.username ||
      endpoint.password ||
      endpoint.search ||
      endpoint.hash ||
      !resource ||
      typeof resource !== "object" ||
      Array.isArray(resource) ||
      !Object.hasOwn(products, resource.product) ||
      resource.product === "identity" ||
      (resource.sharedAdminRole !== undefined &&
        (!configurableAdminRoles.has(resource.product) ||
          !["admin", "administrator"].includes(resource.sharedAdminRole))) ||
      !Array.isArray(resource.clients) ||
      !resource.clients.length ||
      resource.clients.some(
        (c) =>
          typeof c !== "string" ||
          !c ||
          c.trim() !== c ||
          c.length > 256,
      ) ||
      new Set(resource.clients).size !== resource.clients.length
    )
      throw Error("Invalid resource registry");
    if (resource.enrollmentCallbacks !== undefined) {
      if (!sharedProducts.has(resource.product) || !Array.isArray(resource.enrollmentCallbacks) ||
          !resource.enrollmentCallbacks.length)
        throw Error("Invalid application enrollment registry");
      for (const callback of resource.enrollmentCallbacks) {
        const destination = typeof callback?.redirectUri === "string" && URL.parse(callback.redirectUri);
        if (!destination || destination.protocol !== "https:" || destination.href !== callback.redirectUri ||
            destination.username || destination.password || destination.search || destination.hash ||
            destination.hostname === origin.hostname || destination.hostname === issuer.hostname ||
            callback.client === clientId || !resource.clients.includes(callback.client) ||
            enrollmentReturns.has(destination.href))
          throw Error("Invalid application enrollment registry");
        enrollmentReturns.add(destination.href);
      }
    }
    resources.set(audience, resource);
  }
  const policyKey = credential("ACTION_POLICY_KEY");
  if (policyKey.length < 32)
    throw Error("ACTION_POLICY_KEY must be high entropy");
  let verification;
  if (env.AUTH0_VERIFICATION_ORIGIN || env.AUTH0_VERIFICATION_CLIENT_ID ||
      env.AUTH0_VERIFICATION_CLIENT_SECRET || env.AUTH0_VERIFICATION_CLIENT_SECRET_FILE) {
    const management = new URL(required("AUTH0_VERIFICATION_ORIGIN"));
    const verificationClientId = required("AUTH0_VERIFICATION_CLIENT_ID");
    if (management.protocol !== "https:" || !management.hostname.endsWith(".auth0.com") ||
        management.pathname !== "/" || management.port || management.username ||
        management.password || management.search || management.hash ||
        verificationClientId === clientId)
      throw Error("Expected the Auth0 tenant origin and a separate email verification client");
    if (isStaging && productionIdentityHosts.includes(hostname(management)))
      throw Error("Staging requires a separate email verification tenant");
    verification = {
      origin: management.origin,
      clientId: verificationClientId,
      clientSecret: credential("AUTH0_VERIFICATION_CLIENT_SECRET"),
    };
  }
  const authenticatorKey = env.IDENTITY_AUTHENTICATOR_KEY_FILE ? credential("IDENTITY_AUTHENTICATOR_KEY") : undefined;
  if (authenticatorKey && !/^[a-fA-F0-9]{64}$/.test(authenticatorKey))
    throw Error("Expected a 256-bit authenticator encryption key");
  return {
    issuer: issuer.href,
    origin: origin.origin,
    clientId,
    clientSecret: credential("OIDC_CLIENT_SECRET"),
    requireExistingStore: storeMode === "existing",
    resources,
    registrationReturns: returns,
    policyKey,
    connection: env.AUTH0_DATABASE_CONNECTION,
    auth0LogoutEnabled: env.AUTH0_LOGOUT_ENABLED === "true",
    verification,
    authenticatorKey: authenticatorKey ? Buffer.from(authenticatorKey, "hex") : undefined,
  };
}

if (
  process.argv[1] &&
  pathToFileURL(process.argv[1]).href === import.meta.url
) {
  process.umask(0o077);
  const env = configuration(process.env);
  if (!process.env.IDENTITY_DATABASE)
    throw Error("IDENTITY_DATABASE is required");
  const store = openStore(process.env.IDENTITY_DATABASE, { existingOnly: env.requireExistingStore }),
    app = createApp(store, env);
  createServer(async (incoming, out) => {
    try {
      const chunks = [];
      let bytes = 0;
      for await (const chunk of incoming) {
        bytes += chunk.length;
        if (bytes > 16384) {
          out.writeHead(413).end();
          return;
        }
        chunks.push(chunk);
      }
      const path = incoming.url || "/";
      if (!path.startsWith("/") || path.startsWith("//")) {
        out.writeHead(400).end();
        return;
      }
      const response = await app(
        new Request(env.origin + path, {
          method: incoming.method,
          headers: incoming.headers,
          ...(["GET", "HEAD"].includes(incoming.method)
            ? {}
            : { body: Buffer.concat(chunks) }),
        }),
      );
      const headers = Object.fromEntries(response.headers.entries());
      if (response.headers.has("set-cookie"))
        headers["set-cookie"] = response.headers.getSetCookie();
      out
        .writeHead(response.status, headers)
        .end(Buffer.from(await response.arrayBuffer()));
    } catch {
      out.writeHead(400).end();
    }
  }).listen(Number(process.env.PORT || 8080), "0.0.0.0");
}
