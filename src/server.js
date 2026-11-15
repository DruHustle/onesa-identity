import { createServer } from "node:http";
import { pathToFileURL } from "node:url";
import { openStore, products } from "./store.js";
import { createApp } from "./web.js";

export function configuration(env) {
  const required = (k) => {
    if (!env[k]) throw Error(k + " is required");
    return env[k];
  };
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
  const resources = new Map(),
    catalog = JSON.parse(required("RESOURCE_CLIENTS_JSON"));
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
    resources.set(audience, resource);
  }
  const policyKey = required("ACTION_POLICY_KEY");
  if (policyKey.length < 32)
    throw Error("ACTION_POLICY_KEY must be high entropy");
  return {
    issuer: issuer.href,
    origin: origin.origin,
    clientId: required("OIDC_CLIENT_ID"),
    clientSecret: required("OIDC_CLIENT_SECRET"),
    resources,
    policyKey,
    connection: env.AUTH0_DATABASE_CONNECTION,
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
  const store = openStore(process.env.IDENTITY_DATABASE),
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
