// Read-only public HTTP audit. This does not create accounts or prove signup.
import { writeFile, appendFile } from "node:fs/promises";
import { registrationReturns } from "../src/registration-returns.js";

const account = "https://account.onesa.eu";
const provider = "https://auth.onesa.eu";
const targets = registrationReturns(account);
const products = [
  ["onesa-company-portal", "portal", ["web"]],
  ["onesa-security", "security", ["web"]],
  ["onesa-documents", "internal-documents", ["web"]],
  ...[["smart-farmer","farmer"],["smart-logistics","logistics"],["smart-factory","factory"],
      ["onesa-mobile","mobile"],["onesa-ai-platform","ai"],["onesa-drone","drone"],
      ["onesa-robot","robot"],["pasofi","pasofi"]].map(([repo,product]) => [repo,product,["web","ios","android"]]),
];
const cases = [
  ["onesa-identity", "Auth0 issuer", "issuer", provider + "/.well-known/openid-configuration"],
  ["onesa-identity", "Account UI", "account", account + "/account"],
  ["onesa-identity", "Account sign in", "authorize", account + "/login"],
  ...products.flatMap(([repo,product,platforms]) =>
    ["user","admin"].map(tier =>
      [repo, "Account registration " + product + "/" + tier, "register",
       account + "/register?" + new URLSearchParams({audience:tier, product, platform:"web"})])),
  ...["user", "admin"].map(tier =>
    ["onesa-company-portal", "Portal " + tier + " signup", "portal", "https://portal.onesa.eu/account/register?audience=" + tier]),
  ["onesa-documents", "Public Docs", "page", "https://docs.onesa.eu/"],
  ["onesa-documents", "Internal Docs gate", "private", "https://docs.internal.onesa.eu/"],
  ...products.filter(([,product])=>product!=="portal"&&product!=="internal-documents")
    .map(([repo,product]) => [repo,"Web registration return",product === "security" ? "private" : "page",targets.get(product + "/web/user")]),
];
const registeredNative = products.flatMap(([repo,product,platforms]) =>
  platforms.filter(platform => platform !== "web").flatMap(platform =>
    ["user","admin"].map(tier => {
      const uri=targets.get(product + "/" + platform + "/" + tier);
      return {repository:"DruHustle/"+repo,surface:"Registered "+platform+" return "+tier,
        status:null,result:uri && /^[a-z][a-z0-9+.-]*:\/\//.test(uri) ? "STATIC-ONLY" : "NO-GO",
        evidence:uri ? "Registered native deep link; installed-app return not verified" : "Missing deep link"};
    })));

async function probe([repo,surface,kind,url]) {
  const row = { repository: "DruHustle/" + repo, surface, status: null, result: "NO-GO", evidence: "NETWORK_ERROR" };
  try {
    let response = await fetch(url, {
      redirect: "manual", signal: AbortSignal.timeout(12000),
      headers: {accept:"text/html,application/json;q=0.8,*/*;q=0.5", "user-agent":"OnesaRegistrationPreflight/1.0"},
    });
    // Next.js may emit a 307 trailing-slash redirect. Follow only the
    // approved local signup page, never a provider/auth code redirect.
    if (kind === "portal" && [301,302,303,307,308].includes(response.status)) {
      let next = null;
      try { next = new URL(response.headers.get("location"), url); } catch {}
      if (next?.origin === "https://portal.onesa.eu" && /^\/account\/register\/?$/.test(next.pathname)) {
        response = await fetch(next, { redirect:"manual",signal:AbortSignal.timeout(12000) });
      }
    }
    row.status = response.status;
    let accepted = false;
    if (kind === "issuer") {
      const document = response.status === 200 ? await response.json().catch(() => null) : null;
      accepted = document?.issuer === provider + "/";
      row.evidence = accepted ? "Issuer verified" : "Issuer metadata invalid or unavailable";
    } else if (kind === "account") {
      const html = response.status === 200 ? await response.text() : "";
      accepted = response.status === 200 && html.includes("Onesa Account");
      row.evidence = accepted ? "Account UI served" : "Account UI unavailable";
    } else if (kind === "register" || kind === "authorize") {
      let next = null;
      try { next = new URL(response.headers.get("location"), url); } catch {}
      accepted = [302,303].includes(response.status) && next?.origin === provider &&
        /\/authorize$/.test(next.pathname) &&
        next.searchParams.get("redirect_uri") === account + "/callback" &&
        next.searchParams.get("code_challenge_method") === "S256" &&
        next.searchParams.has("state") && next.searchParams.has("nonce");
      row.evidence = accepted ? "Auth0 Code + PKCE start; no account created" : "No approved Auth0 PKCE redirect";
     } else if (kind === "private") {
      accepted = [302,303,307,308,401,403].includes(response.status);
      row.evidence = accepted ? "Unauthenticated access gated; authorized access not verified" : "Internal Documents did not enforce an expected access gate";
    } else if (kind === "portal") {
      const html = response.status === 200 ? await response.text() : "";
      accepted = response.status === 200 && html.includes("Continue to Onesa Identity") &&
        !html.includes("Registration is temporarily unavailable");
      row.evidence = accepted ? "Managed signup handoff rendered" : "Managed signup handoff missing";
    } else {
      accepted = response.status >= 200 && response.status < 400;
      row.evidence = accepted ? "HTTP entry only; browser/signup not verified" : "Web return unavailable";
    }
    if (response.status >= 500) {
      const server = response.headers.get("server")?.slice(0, 60) ?? "unknown";
      const ray = response.headers.get("cf-ray")?.slice(0, 80) ?? "none";
      row.evidence += `; upstream error; server=${server}; ray=${ray}`;
    }
    row.result = accepted ? (kind === "page" ? "ENTRY-ONLY" : "REACHABLE") : "NO-GO";
  } catch (error) {
    const cause = error?.cause?.code;
    row.evidence = error?.name === "TimeoutError" ? "TIMEOUT" :
      typeof cause === "string" && /^[A-Z_]+$/.test(cause) ? cause : "NETWORK_ERROR";
  }
  return row;
}
const checks = [];
for (let i=0;i<cases.length;i+=4) checks.push(...await Promise.all(cases.slice(i,i+4).map(probe)));
checks.push(...registeredNative);
const blocked = checks.filter(x=>["NO-GO","NOT-IMPLEMENTED"].includes(x.result)).length;
const report = {checked_at:new Date().toISOString(), scope:"PUBLIC HTTP ONLY; NOT FULL SIGNUP ACCEPTANCE",
  overall: blocked ? "NO-GO" : "ENTRY-ONLY (NOT RELEASE GO)", blocked, checks,
  not_tested:["Verified-email signup","Password reset delivery","Account deletion downstream acknowledgements","Administrator approval/MFA","Installed iOS and Android returns","Per-product data ACLs"]};
await writeFile("registration-preflight.json",JSON.stringify(report,null,2)+"
");
const lines=["## Onesa registration public HTTP preflight — "+report.overall,"",
  "This **does not** certify account creation, email verification, admin approval or installed-app return.","",
  "| Repository | Surface | HTTP | Result | Evidence |","|---|---|---:|---|---|",
  ...checks.map(r=>"| "+r.repository+" | "+r.surface+" | "+(r.status??"—")+" | **"+r.result+"** | "+r.evidence+" |"),""];
const summary=lines.join("
");
console.log(summary);
if(process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY,summary+"
");
if(blocked) console.log("::warning::Portfolio registration NO-GO: "+blocked+" unavailable or unimplemented checks");
if(process.env.STRICT_LIVE_SMOKE==="1"&&blocked)process.exitCode=1;
