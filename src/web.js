import * as oidc from 'openid-client';
import { timingSafeEqual } from 'node:crypto';
import { secret, digest, Rejected, products } from './store.js';

const esc = value => String(value ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const compare = (a,b) => typeof a==='string' && typeof b==='string' && timingSafeEqual(Buffer.from(digest(a)),Buffer.from(digest(b)));
const cookie = (name,value,seconds) => '__Host-onesa-'+name+'='+value+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age='+seconds;
const readCookie = (req,key) => (req.headers.get('cookie')??'').split(/;\s*/).find(c=>c.startsWith('__Host-onesa-'+key+'='))?.split('=')[1]??'';
const page = (title,body,status=200) => new Response('<!doctype html><html lang="en"><meta charset=utf-8><meta name=viewport content="width=device-width, initial-scale=1"><title>'+esc(title)+' · Onesa Identity</title><style>body{font:1rem/1.5 system-ui;max-width:68rem;margin:2rem auto;padding:0 1rem;color:#132a35;background:#f8fafb}main,article{background:white;padding:1rem;border:1px solid #cfdae0;border-radius:.5rem;margin-bottom:1rem}label{display:inline-grid;margin:.3rem;gap:.2rem}button,input,select{font:inherit;padding:.4rem}nav{margin:1rem 0}code{overflow-wrap:anywhere}</style><header>Onesa Identity</header><nav><a href="/account">My account</a> · <a href="/admin">Administration</a></nav><main><h1>'+esc(title)+'</h1>'+body+'</main></html>',{status,headers:{'content-type':'text/html; charset=utf-8'}});
const redirect = (url,cookies=[]) => { const headers=new Headers({location:url}); for(const c of cookies) headers.append('set-cookie',c); return new Response(null,{status:303,headers}); };
const hidden=(key,value)=>'<input type="hidden" name="'+key+'" value="'+esc(value)+'">';
const post=(path,csrf,body)=>'<form method="post" action="'+path+'">'+hidden('csrf',csrf)+body+'</form>';
const options=items=>items.map(x=>'<option>'+esc(x)+'</option>').join('');
const mfaClaim='https://onesa.eu/claims/mfa_time';
export function authClient(env,transport) {
  let configured;
  async function get() {
    if (!configured) {
      const result=await oidc.discovery(new URL(env.issuer),env.clientId,{client_secret:env.clientSecret,id_token_signed_response_alg:'RS256'},undefined,transport ? {[oidc.customFetch]:transport}:undefined);
      oidc.enableNonRepudiationChecks(result);
      configured=result;
    }
    return configured;
  }
  return {
    async authorize(args){return oidc.buildAuthorizationUrl(await get(),args).href;},
    async redeem(url,challenge){const tokens=await oidc.authorizationCodeGrant(await get(),url,{
      expectedNonce:challenge.nonce,expectedState:challenge.state,pkceCodeVerifier:challenge.verifier,idTokenExpected:true});
      return tokens.claims();},
  };
}
export function createApp(store,env,client=authClient(env)){
  async function handle(req){
    const url=new URL(req.url), p=url.pathname, method=req.method;
    if(url.origin!==env.origin) return page('Unknown origin','',400);
    if(p==='/health'&&method==='GET') return Response.json({status:'ok'});
    if(p==='/internal/decision'&&method==='POST'){
      if(!compare(req.headers.get('authorization'),'Bearer '+env.policyKey)) return new Response(null,{status:401});
      const {subject,audience,client:clientId}=await req.json();
      if(typeof subject!=='string'||subject.length>512||!subject) return new Response(null,{status:403});
      const actor=store.lookup(env.issuer,subject);
      if(actor && ['suspended','rejected'].includes(actor.status)) return new Response(null,{status:403});
      if(clientId===env.clientId && (!audience || audience===new URL('userinfo',env.issuer).href)) return Response.json({selfservice:true});
      const resource=env.resources.get(audience);
      if(!actor || !resource || !resource.clients.includes(clientId)) return new Response(null,{status:403});
      const grant=store.activeGrant(actor.id,resource.product);
      if(!grant) return new Response(null,{status:403});
      return Response.json({user_id:actor.id,product:resource.product,roles:[grant.role]});
    }
    const login=['/login','/register','/step-up','/verify-factor'].includes(p);
    if(login&&method==='GET'){
      const token=secret(), state=oidc.randomState(), nonce=oidc.randomNonce(), verifier=oidc.randomPKCECodeVerifier();
      let destination=url.searchParams.get('return')==='/admin' || p==='/step-up'?'/admin':'/account';
      const invitation=url.searchParams.get('invite');
      if(invitation && /^[\w-]{43}$/.test(invitation)) destination='/account?invite='+invitation;
      const params={response_type:'code',redirect_uri:env.origin+'/callback',scope:'openid email profile',state,nonce,code_challenge:await oidc.calculatePKCECodeChallenge(verifier),code_challenge_method:'S256'};
      if(p==='/register') params.screen_hint='signup';
      if(p==='/step-up'||p==='/verify-factor'){params.prompt='login'; params.max_age='0'; params.acr_values='http://schemas.openid.net/pape/policies/2007/06/multi-factor';}
      const location=await client.authorize(params);
      store.run('DELETE FROM challenges WHERE expires<=?',Date.now());
      store.run('INSERT INTO challenges VALUES(?,?,?,?,?,?)',digest(token),state,nonce,verifier,destination,Date.now()+300000);
      return redirect(location,[cookie('flow',token,300)]);
    }
    if(p==='/callback'&&method==='GET'){
      const flow=store.one('DELETE FROM challenges WHERE hash=? AND expires>? RETURNING *',digest(readCookie(req,'flow')),Date.now());
      if(!flow || !compare(flow.state,url.searchParams.get('state'))) return page('Sign-in expired','<a href="/login">Start sign-in again</a>',400);
      if(url.searchParams.get('error')) return page('Sign-in unavailable','<a href="/login?return='+encodeURIComponent(flow.destination)+'">Try again</a>',403);
      const identity=await client.redeem(url,flow);
      if(identity?.iss!==env.issuer || identity.email_verified!==true || !identity.sub || typeof identity.sub!=='string') return page('Verify your email','Use the verification message from Onesa Identity, then sign in again.',403);
      const target=new URL(flow.destination,env.origin);
      const user=store.register(env.issuer,identity.sub,identity.email,target.searchParams.get('invite')||'');
      if(['suspended','rejected'].includes(user.status)) return page('Account unavailable','',403);
      const session=secret(),csrf=secret(), now=Date.now();
      const factor=Number.isSafeInteger(identity[mfaClaim]) && identity[mfaClaim]*1000<=now ? identity[mfaClaim]*1000:0;
      store.run('DELETE FROM sessions WHERE expires<=?',now);
      store.run('INSERT INTO sessions VALUES(?,?,?,?,?)',digest(session),user.id,csrf,now+1800000,factor);
      return redirect(target.pathname,[cookie('session',session,1800),cookie('flow','',0)]);
    }
    const session=store.one('SELECT s.*,a.email,a.status AS state FROM sessions s JOIN accounts a USING(id) WHERE hash=? AND expires>? AND a.status IN (\'active\',\'pending\')',digest(readCookie(req,'session')),Date.now());
    if(p==='/'||p==='/account' || p==='/admin'){
      if(method!=='GET') return new Response(null,{status:405});
      if(!session){
        if(p==='/admin') return redirect('/login?return=/admin');
        return page('Your Onesa account','<a href="/login">Sign in with Onesa</a> · <a href="/register">Register</a>');
      }
      if(p!=='/admin') return page('Your Onesa account','<p>'+esc(session.email)+' · '+esc(session.state)+'</p><p><a href="/verify-factor">Verify or enroll a second factor</a></p>'+(env.connection?post('/account/recovery',session.csrf,'<button>Send password reset email</button>'):'<p>Use Forgot password on the sign-in screen to recover your password.</p>')+post('/logout',session.csrf,'<button>Sign out here</button>'));
    }
    let form;
    if(method==='POST'){
      if(!session || req.headers.get('origin')!==env.origin) return new Response(null,{status:403});
      form=new URLSearchParams(await req.text());
      if(!compare(form.get('csrf'),session.csrf)) return new Response(null,{status:403});
      if(p==='/account/recovery' && env.connection){
        const claimed=store.run('INSERT INTO recovery_limit VALUES(?,?) ON CONFLICT(id) DO UPDATE SET next=excluded.next WHERE recovery_limit.next<=?',session.id,Date.now()+60000,Date.now()).changes;
        if(!claimed) return page('Reset requested','Check your inbox before requesting another email.',429);
        const r=await fetch(new URL('/dbconnections/change_password',env.issuer),{method:'POST',redirect:'error',signal:AbortSignal.timeout(5000),headers:{'content-type':'application/json'},body:JSON.stringify({client_id:env.clientId,email:session.email,connection:env.connection})});
        if(!r.ok) return page('Recovery unavailable','Retry from the sign-in screen.',503);
        store.audit(session.id,'request-password-recovery',session.id);
        return page('Check your inbox','Use the password reset message to choose a new password.');
      }
      if(p==='/logout'){store.run('DELETE FROM sessions WHERE hash=?',session.hash);return redirect('/account',[cookie('session','',0)]);}
    }
    if(!['/admin','/admin/change','/admin/invite'].includes(p)) return page('Page unavailable','',404);
    if(!session || !store.activeGrant(session.id,'identity')) return page('Identity administrator required','',403);
    if(!session.mfa_at || Date.now()-session.mfa_at>300000) return page('Verify your identity','<a href="/step-up">Continue with fresh MFA</a>',403);
    if(p==='/admin' && method==='GET'){
      const users=store.all('SELECT * FROM accounts ORDER BY email LIMIT 201');
      const search=url.searchParams.get('id')||'';
      const shown=search?store.all('SELECT * FROM accounts WHERE id=?',search):users.slice(0,200);
      const panels=shown.map(u=>{
        const base=hidden('id',u.id)+hidden('revision',u.revision);
        const grants=store.all('SELECT product,role,status FROM grants WHERE id=? ORDER BY product',u.id).map(g=>[g.product,g.role,g.status].map(esc).join(' / ')).join(', ');
        return '<article><h2>'+esc(u.email)+'</h2><p><code>'+esc(u.id)+'</code> · '+esc(u.status)+'</p><p>'+grants+'</p>'+
          post('/admin/change',session.csrf,base+hidden('kind','status')+'<label>Account status<select name="status">'+options(['active','suspended','pending','rejected'])+'</select></label><button>Update account</button>')+
          post('/admin/change',session.csrf,base+hidden('kind','grant')+'<label>Product and role<select name="assignment">'+options(Object.entries(products).flatMap(([product,roles])=>roles.map(r=>product+'/'+r)))+'</select></label><label>Access<select name="status">'+options(['active','revoked'])+'</select></label><button>Update access</button>')+'</article>';
      }).join('');
      const history=store.all('SELECT * FROM audit ORDER BY seq DESC LIMIT 100').map(a=>'<li>'+esc(new Date(a.at).toISOString())+' · '+esc(a.actor)+' · '+esc(a.action)+' · '+esc(a.target)+' '+esc(a.detail)+'</li>').join('');
      return page('Identity administration',post('/admin/invite',session.csrf,'<label>Invitation email<input type="email" required name="email"></label><button>Create invitation</button>')+'<form><label>Find by Onesa user ID<input name="id" value="'+esc(search)+'"></label><button>Find</button></form>'+panels+'<h2>Recent audit history</h2><ol>'+history+'</ol>');
    }
    if(p==='/admin/invite'&&method==='POST'){
      const token=store.invite(session.id,form.get('email'));
      return page('Invitation created','<p>Share this one-time link with the intended recipient. It expires in 24 hours.</p><code>'+esc(env.origin+'/register?invite='+token)+'</code>');
    }
    if(p==='/admin/change'&&method==='POST'){
      const [product,role]=(form.get('assignment')||'').split('/');
      store.change(session.id,form.get('id'),Number(form.get('revision')),{kind:form.get('kind'),product,role,status:form.get('status')});
      return redirect('/admin?id='+encodeURIComponent(form.get('id')));
    }
    return new Response(null,{status:405});
  }
  return async req=>{
    let response;
    try{response=await handle(req);}
    catch(e){response=e instanceof Rejected? page('Request needs review',esc(e.message),409):page('Identity temporarily unavailable','Retry from the application where you started.',503);}
    response.headers.set('cache-control','no-store');response.headers.set('referrer-policy','no-referrer');
    response.headers.set('x-content-type-options','nosniff');
    response.headers.set('content-security-policy',"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    return response;
  };
}
