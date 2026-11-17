// Read-only public HTTP audit. This does not create accounts or prove signup.
import { writeFile, appendFile } from "node:fs/promises";
import { registrationReturns } from "../src/registration-returns.js";

const account = "https://account.onesa.eu";
const provider = "https://auth.onesa.eu";
const targets = registrationReturns(account);
const cases = [
  ["onesa-identity", "Auth0 issuer", "issuer", provider + "/.well-known/openid-configuration"],
  ["onesa-identity", "Account UI", "account", account + "/account"],
  ...["portal", "farmer"].flatMap(product => ["user", "admin"].map(tier =>
    [product === "portal" ? "onesa-company-portal" : "smart-farmer",
     "Account registration " + product + "/" + tier, "register",
     account + "/register?audience=" + tier + "&product=" + product + "&platform=web"])),
  ...["user", "admin"].map(tier =>
    ["onesa-company-portal", "Portal " + tier + " signup", "portal", "https://portal.onesa.eu/account/register?audience=" + tier]),
  ["onesa-documents", "Public Docs", "page", "https://docs.onesa.eu/"],
  ["onesa-documents", "Internal Docs return", "page", targets.get("internal-documents/web/user")],
  ...[["smart-farmer","farmer"],["smart-logistics","logistics"],["smart-factory","factory"],
      ["onesa-mobile","mobile"],["onesa-ai-platform","ai"],["onesa-drone","drone"],
      ["onesa-robot","robot"],["pasofi","pasofi"]]
    .map(([repo,product]) => [repo,"Web registration return","page",targets.get(product + "/web/user")]),
];
async function probe([repo,surface,kind,url]) {
  const row = { repository: "DruHustle/" + repo, surface, status: null, result: "NO-GO", evidence: "NETWORK_ERROR" };
  try {
    const response = await fetch(url, {
      redirect: "manual", signal: AbortSignal.timeout(12000),
      headers: {accept:"text/html,application/json;q=0.8,*/*;q=0.5", "user-agent":"OnesaRegistrationPreflight/1.0"},
    });
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
    } else if (kind === "register") {
      let next = null;
      try { next = new URL(response.headers.get("location"), url); } catch {}
      accepted = [302,303].includes(response.status) && next?.origin === provider &&
        /\/authorize$/.test(next.pathname) &&
        next.searchParams.get("redirect_uri") === account + "/callback" &&
        next.searchParams.get("code_challenge_method") === "S256" &&
        next.searchParams.has("state") && next.searchParams.has("nonce");
      row.evidence = accepted ? "Auth0 Code + PKCE start; no account created" : "No approved Auth0 PKCE redirect";
    } else if (kind === "portal") {
      const html = response.status === 200 ? await response.text() : "";
      accepted = response.status === 200 && html.includes("Continue to Onesa Identity") &&
        !html.includes("Registration is temporarily unavailable");
      row.evidence = accepted ? "Managed signup handoff rendered" : "Managed signup handoff missing";
    } else {
      accepted = response.status >= 200 && response.status < 400;
      row.evidence = accepted ? "HTTP entry only; browser/signup not verified" : "Web return unavailable";
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
checks.push({repository:"DruHustle/onesa-security",surface:"Signup application",status:null,result:"NOT-IMPLEMENTED",evidence:"Empty repository; no testable application"});
const blocked = checks.filter(x=>["NO-GO","NOT-IMPLEMENTED"].includes(x.result)).length;
const report = {checked_at:new Date().toISOString(), scope:"PUBLIC HTTP ONLY; NOT FULL SIGNUP ACCEPTANCE",
  overall: blocked ? "NO-GO" : "ENTRY-ONLY (NOT RELEASE GO)", blocked, checks,
  not_tested:["Verified-email signup","Administrator approval/MFA","Installed iOS and Android returns","Per-product data ACLs"]};
await writeFile("registration-preflight.json",JSON.stringify(report,null,2)+"\n");
const lines=["## Onesa registration public HTTP preflight — "+report.overall,"",
  "This **does not** certify account creation, email verification, admin approval or installed-app return.","",
  "| Repository | Surface | HTTP | Result | Evidence |","|---|---|---:|---|---|",
  ...checks.map(r=>"| "+r.repository+" | "+r.surface+" | "+(r.status??"—")+" | **"+r.result+"** | "+r.evidence+" |"),""];
const summary=lines.join("\n");
console.log(summary);
if(process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY,summary+"\n");
if(blocked) console.log("::warning::Portfolio registration NO-GO: "+blocked+" unavailable or unimplemented checks");
if(process.env.STRICT_LIVE_SMOKE==="1"&&blocked)process.exitCode=1;
