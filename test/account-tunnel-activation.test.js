import test from "node:test";
import assert from "node:assert/strict";
import {accountRoute, authorizeRedirect, withAccountService, verifyAccount, enrollments} from
  "../scripts/activate-account-tunnel.mjs";

const input = () => ({ingress: [
  {hostname:"portal-api.onesa.eu",service:"http://127.0.0.1:18300"},
  {hostname:"account.onesa.eu",service:"http_status:503"},
  {service:"http_status:404"},
]});

test("changes only the reviewed Account rule and preserves all other tunnel ingress", () => {
  const before = input();
  const after = withAccountService(before,18600);
  assert.equal(accountRoute(after).rule.service,"http://127.0.0.1:18600");
  assert.deepEqual(before,input(),"does not mutate the Cloudflare snapshot");
  assert.deepEqual(after.ingress[0],before.ingress[0]);
  assert.deepEqual(after.ingress[2],before.ingress[2]);
  assert.equal(withAccountService(after,18600).ingress[1].service,
    "http://127.0.0.1:18600");
});

test("refuses to hijack another service, ambiguous rule or missing terminal fallback", () => {
  const stale = input();
  stale.ingress[1].service="http://127.0.0.1:18300";
  assert.throws(()=>withAccountService(stale,18600),/expected maintenance state/i);
  const duplicate=input();
  duplicate.ingress.splice(1,0,{hostname:"account.onesa.eu",service:"http_status:503"});
  assert.throws(()=>withAccountService(duplicate,18600),/exactly one/);
  const other=input();
  other.ingress.pop();
  assert.throws(()=>withAccountService(other,18600),/fallback/);
  for (const port of [-1,0,22,65536,3.14,"18600",NaN])
    assert.throws(()=>withAccountService(input(),port),/unprivileged TCP port/);
});

const redirect = (opts={}) => {
  const url = new URL("https://auth.onesa.eu/authorize");
  for (const [key,value] of Object.entries({
    client_id:"account-confidential-client",response_type:"code",
    redirect_uri:"https://account.onesa.eu/callback",
    state:"s".repeat(43),nonce:"n".repeat(43),
    code_challenge:"c".repeat(43),code_challenge_method:"S256",...opts,
  })) url.searchParams.set(key,value);
  return url.href;
};

test("pins the exact issuer, callback and S256 challenge", () => {
  assert.doesNotThrow(()=>authorizeRedirect(redirect()));
  for (const value of [
    redirect({redirect_uri:"https://evil.invalid/callback"}),
    redirect({redirect_uri:"https://auth.onesa.eu/callback"}),
    redirect({code_challenge_method:"plain"}),
    redirect({state:"short"}),
    redirect({nonce:"short"}),
    redirect({response_type:"token"}),
    redirect({client_id:""}),
    redirect().replace("auth.onesa.eu","attacker.invalid"),
  ]) assert.throws(()=>authorizeRedirect(value),/PKCE flow/);
});

test("preflight checks commissioned store, anonymous policy denial and product returns", async () => {
  const origin = "http://127.0.0.1:18600";
  const seen=[];
  const fake=async (url, options={}) => {
    const u=new URL(url);
    seen.push([u.pathname,u.search,options.method || "GET"]);
    if (u.pathname==="/readyz")return Response.json({service:"onesa-identity",ready:true});
    if (u.pathname==="/account")return new Response("Onesa Account");
    if (u.pathname==="/internal/decision")return new Response(null,{status:401});
    if (u.pathname==="/register")return new Response(null,{status:303,headers:{location:redirect()}});
    throw Error("Unrecognized request");
  };
  await verifyAccount(origin,fake);
  assert.equal(enrollments.length,36);
  assert.equal(seen.length,enrollments.length+3);
  const entries=seen.filter(x=>x[0]==="/register").map(x=>new URLSearchParams(x[1]));
  assert.equal(entries.length,enrollments.length);
  assert.deepEqual(entries.map(q=>[q.get("audience"),q.get("product"),q.get("platform")]), enrollments);
  const products=["ai","drone","robot","farmer","factory","logistics","mobile","pasofi"];
  for(const product of products){
    for(const platform of ["web","ios","android"]){
      assert.ok(entries.some(q=>q.get("product")===product&&q.get("platform")===platform&&q.get("audience")==="user"));
    }
    assert.ok(entries.some(q=>q.get("product")===product&&q.get("platform")==="web"&&q.get("audience")==="admin"));
  }
  assert.ok(entries.some(q=>q.get("product")==="portal"&&q.get("audience")==="admin"));
  assert.ok(entries.some(q=>q.get("product")==="internal-documents"));
  assert.ok(entries.some(q=>q.get("product")==="security"));
  assert.ok(seen.some(x=>x[0]==="/internal/decision"&&x[2]==="POST"));
});

test("preflight rejects one broken registration route even when the others work", async () => {
  const origin="http://127.0.0.1:18600";
  const fake=async url=>{
    const u=new URL(url);
    if(u.pathname==="/readyz")return Response.json({service:"onesa-identity",ready:true});
    if(u.pathname==="/account")return new Response("Onesa Account");
    if(u.pathname==="/internal/decision")return new Response(null,{status:401});
    if(u.pathname==="/register")return u.searchParams.get("product")==="robot"
      && u.searchParams.get("platform")==="android"
      ? new Response("Native route missing",{status:404})
      : new Response(null,{status:303,headers:{location:redirect()}});
    throw Error("Unrecognized request");
  };
  await assert.rejects(()=>verifyAccount(origin,fake),/Registration entry failed for robot\/android\/user/);
});

test("preflight refuses a different service, missing Account UI, or unprotected policy API", async () => {
  const base="http://127.0.0.1:18600";
  await assert.rejects(()=>verifyAccount(base,async()=>Response.json({
    service:"portal",ready:true
  })),/Wrong service/);
  await assert.rejects(()=>verifyAccount(base,async url=>
    url.endsWith("/readyz")?Response.json({service:"onesa-identity",ready:true}):
    new Response("wrong service")),/Account landing/);
  await assert.rejects(()=>verifyAccount(base,async url=>
    url.endsWith("/readyz")?Response.json({service:"onesa-identity",ready:true}):
    url.endsWith("/account")?new Response("Onesa Account"):
    new Response("unprotected policy")),/policy endpoint/);
});
