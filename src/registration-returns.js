import { accountProducts } from "./store.js";

const productsWithApps = {
  ai:       ["https://platform.onesa.eu/auth/continue?registration=complete", "onesaai://account/registered"],
  drone:    ["https://drone.onesa.eu/?registration=complete", "onesadrone://account/registered"],
  robot:    ["https://robot.onesa.eu/console?registration=complete", "onesarobot://account/registered"],
  farmer:   ["https://farmer.onesa.eu/auth/registration/complete", "smartfarmer://onesa/registered"],
  factory:  ["https://factory.onesa.eu/#/login?registration=complete", "eu.onesa.factory://signin/registered"],
  logistics:["https://logistics.onesa.eu/#/login?registration=complete", "eu.onesa.logistics://signin/registered"],
  mobile:   ["https://mobile.onesa.eu/account/?registration=complete", "onesamobile://auth/registered"],
  pasofi:   ["https://pasofi.mobile.onesa.eu/?registration=complete", "com.onesa.pasofi.identity://login/registered"],
};

const production = Object.fromEntries(Object.entries(productsWithApps).map(([product, [web, app]]) =>
  [product, { web, ios: app, android: app }]));
production.portal = { web: { user: "https://portal.onesa.eu/account/registered",
  admin: "https://portal.onesa.eu/account/registered?audience=admin" } };
production["internal-documents"] = { web: "https://docs.internal.onesa.eu/registration/return" };
// Security is web-only and requires an explicit Identity grant and a separate
// organization membership; it does not inherit shared user/admin access.
production.security = { web: "https://security.onesa.eu/?registration=complete" };

// Auth0 remains the issuer on auth.onesa.eu. A DNS-only provider domain
// must not be intercepted by the application; use the separate Account origin.
const productionAccountOrigins = new Set(["https://account.onesa.eu", "https://auth.onesa.eu"]);

const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
export const returnKey = (product, platform, tier) => [product, platform, tier].join("/");
export function registrationReturns(origin, override) {
  const entries = override ? JSON.parse(override) : productionAccountOrigins.has(origin) ? production : {};
  if (!object(entries)) throw Error("Invalid registration return registry");
  const results = new Map();
  for (const [product, platforms] of Object.entries(entries)) {
    if (!accountProducts.has(product) || !object(platforms)) throw Error("Unknown registration return product");
    for (const [platform, target] of Object.entries(platforms)) {
      if (!["web", "ios", "android"].includes(platform) || (platform !== "web" && !Object.hasOwn(productsWithApps, product)))
        throw Error("Unsupported registration return platform");
      const tiers = typeof target === "string" ? { user: target, admin: target } : target;
      if (!object(tiers)) throw Error("Invalid registration return destinations");
      for (const [tier, raw] of Object.entries(tiers)) {
        if (!["user", "admin"].includes(tier) || typeof raw !== "string" || raw.trim() !== raw)
          throw Error("Invalid registration return destination");
        const url = new URL(raw);
        const native = platform !== "web" && url.protocol === new URL(productsWithApps[product][1]).protocol;
        if ((!native && url.protocol !== "https:") || !url.hostname || url.username || url.password ||
            /(^|\/)callback(?:\/|$)/i.test(url.pathname) ||
            ["code", "state", "access_token", "id_token", "refresh_token"].some(key => url.searchParams.has(key)))
          throw Error("Expected a registered product landing or application link");
        results.set(returnKey(product, platform, tier), url.href);
      }
    }
  }
  return results;
}
