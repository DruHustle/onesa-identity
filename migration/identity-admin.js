// Run from the protected host after verifying the intended person's independent owner authorization.
import { openStore,uuid } from '../src/store.js';
process.umask(0o077);
const [file,id,receipt]=process.argv.slice(2);
if(!file || !uuid(id) || !receipt?.trim()) throw Error('Usage: node migration/identity-admin.js DATABASE STABLE_USER_ID APPROVAL_RECEIPT');
const s=openStore(file);
s.atomic(()=>{
  if(s.one("SELECT id FROM grants WHERE product='identity' AND status='active'")) throw Error('An Identity administrator already exists. Use the Identity UI.');
  if(!s.one("SELECT id FROM accounts JOIN links USING(id) WHERE id=? AND status IN ('active','pending')",id)) throw Error('An independently linked account is required');
  s.run("UPDATE accounts SET status='active',revision=revision+1 WHERE id=?",id);
  s.run("INSERT INTO grants VALUES(?,'identity','admin','active')",id);
  s.audit('bootstrap','identity-admin',id,{receipt});
});
s.db.close();
