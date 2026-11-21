// Public, credential-free issuer continuity test for the Onesa Auth0 domain.
const ISSUER = "https://auth.onesa.eu/";
const META = ISSUER + ".well-known/openid-configuration";
export {ISSUER, META};

async function jsonAt(fetcher, url) {
  let response;
  try {
    response = await fetcher(url, {
      method: "GET", redirect: "manual", cache: "no-store",
      signal: AbortSignal.timeout(6000), headers: {Accept: "application/json"},
    });
  } catch {
    throw Error("network_or_timeout");
  }
  if (response.status !== 200) {
    await response.body?.cancel().catch(() => {});
    throw Error("http_or_redirect");
  }
  if (!/^application\/json(?:;|$)/i.test(response.headers.get("content-type") || "") || !response.body) {
    await response.body?.cancel().catch(() => {});
    throw Error("non_json_response");
  }
  const reader = response.body.getReader();
  const parts = [];
  let size = 0;
  try {
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 32768) {await reader.cancel(); throw Error("oversized_json");}
      parts.push(value);
    }
  } catch {
    throw Error("invalid_or_truncated_json");
  } finally {
    reader.releaseLock();
  }
  try {
    return JSON.parse(Buffer.concat(parts).toString("utf8"));
  } catch {
    throw Error("invalid_or_truncated_json");
  }
}

export async function verifyDiscovery(fetcher = fetch) {
  const metadata = await jsonAt(fetcher, META);
  if (metadata?.issuer !== ISSUER) throw Error("issuer_mismatch");
  for (const name of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) {
    const value = metadata?.[name];
    if (typeof value !== "string" || !value.startsWith(ISSUER) || new URL(value).origin !== new URL(ISSUER).origin)
      throw Error("unapproved_" + name);
  }
  if (!Array.isArray(metadata.response_types_supported) || !metadata.response_types_supported.includes("code"))
    throw Error("authorization_code_not_advertised");
  const keys = await jsonAt(fetcher, metadata.jwks_uri);
  if (!Array.isArray(keys?.keys) || !keys.keys.length ||
      keys.keys.some(k => !k || k.kty !== "RSA" || typeof k.kid !== "string" ||
        !/^[A-Za-z0-9._-]{1,128}$/.test(k.kid) ||
        typeof k.n !== "string" || typeof k.e !== "string" ||
        !/^[A-Za-z0-9_-]+$/.test(k.n) || !/^[A-Za-z0-9_-]+$/.test(k.e) ||
        (k.use !== undefined && k.use !== "sig")) ||
      new Set(keys.keys.map(k => k.kid)).size !== keys.keys.length)
    throw Error("invalid_public_signing_keys");
  return {service:"auth0-custom-domain",issuer:ISSUER,status:"PASS",
    discoveryValid:true, signingKeys:keys.keys.length};
}
