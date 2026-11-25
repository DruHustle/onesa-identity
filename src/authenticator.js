import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { digest, secret } from "./store.js";

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const validity = 300000;
const limitWindow = 600000;

function base32(key) {
  let output = "", bits = 0, value = 0;
  for (const byte of key) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += alphabet[(value >> bits) & 31];
    }
  }
  if (bits) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

export function authenticatorCode(key, counter) {
  const time = Buffer.alloc(8);
  time.writeBigUInt64BE(BigInt(counter));
  const hash = createHmac("sha1", key).update(time).digest();
  const offset = hash.at(-1) & 15;
  return String((hash.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, "0");
}

export function accountAuthenticator(store, key) {
  function seal(secretKey, accountId) {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(Buffer.from("onesa-account-authenticator:" + accountId));
    return Buffer.concat([iv, cipher.update(secretKey), cipher.final(), cipher.getAuthTag()]).toString("base64url");
  }
  function open(ciphertext, accountId) {
    const bytes = Buffer.from(ciphertext, "base64url");
    const cipher = createDecipheriv("aes-256-gcm", key, bytes.subarray(0, 12));
    cipher.setAAD(Buffer.from("onesa-account-authenticator:" + accountId));
    cipher.setAuthTag(bytes.subarray(-16));
    return Buffer.concat([cipher.update(bytes.subarray(12, -16)), cipher.final()]);
  }

  function load(token, sessionHash, accountId, now) {
    return store.one(`SELECT f.hash,f.destination,f.enrollment,f.attempts,
      a.ciphertext,a.last_counter,l.failures AS total_failures
      FROM account_authenticator_flows f JOIN sessions s ON s.hash=f.session_hash
      LEFT JOIN account_authenticators a ON a.id=s.id
      LEFT JOIN account_authenticator_limits l ON l.id=s.id AND l.ends_at>?
      WHERE f.hash=? AND s.hash=? AND s.id=? AND f.expires>? AND s.expires>?`,
    now, digest(token), sessionHash, accountId, now, now);
  }
  function matchCode(ciphertext, accountId, previous, code, now) {
    if (!/^\d{6}$/.test(code)) return;
    const key = open(ciphertext, accountId);
    const current = Math.floor(now / 30000);
    return [current, current - 1, current + 1].find(counter => counter > (previous ?? -1) &&
      timingSafeEqual(Buffer.from(authenticatorCode(key, counter)), Buffer.from(code)));
  }
  function recordFailure(id, now) {
    store.run(`INSERT INTO account_authenticator_limits VALUES(?,?,1) ON CONFLICT(id) DO UPDATE SET
      failures=CASE WHEN ends_at>? THEN failures+1 ELSE 1 END,
      ends_at=CASE WHEN ends_at>? THEN ends_at ELSE excluded.ends_at END`, id, now + limitWindow, now, now);
  }
  return {
    start(sessionHash, accountId, destination, now) {
      const token = secret();
      const existing = store.one("SELECT 1 FROM account_authenticators WHERE id=?", accountId);
      const enrollment = existing ? null : seal(randomBytes(20), accountId);
      store.run("DELETE FROM account_authenticator_flows WHERE expires<=?", now);
      store.run("INSERT INTO account_authenticator_flows(hash,session_hash,destination,expires,enrollment) VALUES(?,?,?,?,?)",
        digest(token), sessionHash, destination, now + validity, enrollment);
      return token;
    },
    view(token, sessionHash, accountId, now) {
      const flow = load(token, sessionHash, accountId, now);
      if (!flow) return null;
      return { locked: flow.attempts >= 5 || (flow.total_failures ?? 0) >= 10,
        setupKey: !flow.ciphertext && flow.enrollment ? base32(open(flow.enrollment, accountId)) : null };
    },
    verify(token, sessionHash, accountId, code, now) {
      return store.atomic(() => {
        const flow = load(token, sessionHash, accountId, now);
        if (!flow) return { status: "expired" };
        if (flow.attempts >= 5 || (flow.total_failures ?? 0) >= 10) return { status: "limited" };
        if (!/^\d{6}$/.test(code)) return { status: "invalid" };
        const approved = matchCode(flow.ciphertext ?? flow.enrollment, accountId, flow.last_counter, code, now);
        if (approved === undefined) {
          store.run("UPDATE account_authenticator_flows SET attempts=attempts+1 WHERE hash=?", flow.hash);
          recordFailure(accountId, now);
          return { status: "invalid" };
        }
        if (flow.ciphertext)
          store.run("UPDATE account_authenticators SET last_counter=? WHERE id=?", approved, accountId);
        else {
          store.run("INSERT INTO account_authenticators VALUES(?,?,?,?)", accountId, flow.enrollment, approved, now);
          store.audit(accountId, "authenticator-enrolled", accountId, {});
        }
        store.run("DELETE FROM account_authenticator_limits WHERE id=?", accountId);
        const session = secret();
        store.run("DELETE FROM sessions WHERE hash=?", sessionHash);
        store.run("INSERT INTO sessions VALUES(?,?,?,?,?)", digest(session), accountId, secret(), now + 1800000, now);
        return { status: "verified", destination: flow.destination, session };
      });
    },
    startPasoFi(id, client, audience, now) {
      const ticket = secret();
      store.run("DELETE FROM pasofi_authenticator_flows WHERE expires<=?", now);
      store.run("INSERT INTO pasofi_authenticator_flows(ticket_hash,id,client,audience,expires) VALUES(?,?,?,?,?)",
        digest(ticket), id, client, audience, now + validity);
      return ticket;
    },
    bindPasoFi(ticket, state, now) {
      const browser = secret();
      const updated = store.run(`UPDATE pasofi_authenticator_flows SET browser_hash=?,state=?,csrf=?
        WHERE ticket_hash=? AND expires>? AND browser_hash IS NULL`,
      digest(browser), state, secret(), digest(ticket), now);
      return updated.changes ? browser : null;
    },
    showPasoFi(browser, now) {
      return store.one(`SELECT f.id,f.csrf,a.email,p.ciphertext IS NOT NULL AS enrolled
        FROM pasofi_authenticator_flows f JOIN accounts a ON a.id=f.id AND a.status='active'
        LEFT JOIN account_authenticators p ON p.id=f.id
        WHERE f.browser_hash=? AND f.expires>? AND f.verified_at IS NULL`, digest(browser), now);
    },
    verifyPasoFi(browser, code, now) {
      return store.atomic(() => {
        const flow = store.one(`SELECT f.id,f.state,f.attempts,p.ciphertext,p.last_counter,l.failures
          FROM pasofi_authenticator_flows f JOIN account_authenticators p ON p.id=f.id
          JOIN accounts a ON a.id=f.id AND a.status='active'
          LEFT JOIN account_authenticator_limits l ON l.id=f.id AND l.ends_at>?
          WHERE f.browser_hash=? AND f.expires>? AND f.verified_at IS NULL`, now, digest(browser), now);
        if (!flow) return {status:"expired"};
        if (flow.attempts >= 5 || (flow.failures ?? 0) >= 10) return {status:"limited"};
        if (!/^\d{6}$/.test(code)) return {status:"invalid"};
        const approved = matchCode(flow.ciphertext, flow.id, flow.last_counter, code, now);
        if (approved === undefined) {
          store.run("UPDATE pasofi_authenticator_flows SET attempts=attempts+1 WHERE browser_hash=?", digest(browser));
          recordFailure(flow.id, now);
          return {status:"invalid"};
        }
        const receipt = secret();
        store.run("UPDATE account_authenticators SET last_counter=? WHERE id=?", approved, flow.id);
        store.run("DELETE FROM account_authenticator_limits WHERE id=?", flow.id);
        store.run("UPDATE pasofi_authenticator_flows SET verified_at=?,receipt_hash=? WHERE browser_hash=?", now,digest(receipt),digest(browser));
        return {status:"verified",state:flow.state,receipt};
      });
    },
    finishPasoFi(id, client, audience, state, receipt, now) {
      return store.one(`DELETE FROM pasofi_authenticator_flows WHERE id=? AND client=? AND audience=?
        AND state=? AND receipt_hash=? AND verified_at>? AND expires>? RETURNING verified_at`,
      id, client, audience, state, digest(receipt), now-validity, now);
    },
  };
}
