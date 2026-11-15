// ============================================================
//  Cloudflare Worker: "Forgot password" alert + one-time login code
//
//  Routes (POST, body = JSON sent as text/plain):
//    /forgot     {type:'phone'|'email', value:'...'}   -> sends a Telegram alert to the owner
//    /otp-login  {type, value, code}                   -> checks the one-time code, returns {token}
//
//  Variables to set in Cloudflare (Settings -> Variables and Secrets):
//    TG_TOKEN      Telegram bot token            (Secret)
//    TG_CHAT       Telegram chat id of the owner (Text)
//    FB_PROJECT    Firebase project id           (Text)   e.g. zoon-store
//    FB_EMAIL      service account client_email  (Text)
//    FB_KEY        service account private_key   (Secret) paste the whole value from the JSON
//    ALLOW_ORIGIN  optional, your site origin    (Text)   e.g. https://yourname.github.io
// ============================================================

const AUD = 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit';
const enc = new TextEncoder();
const hits = new Map(); // best-effort rate limit (per Worker instance)
let tokCache = { tok: '', exp: 0 };

function b64u(buf) {
  const b = new Uint8Array(buf); let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
const b64uStr = (str) => b64u(enc.encode(str));

function pemToBuf(pem) {
  const raw = atob(String(pem).replace(/\\n/g, '\n').replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''));
  const u = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) u[i] = raw.charCodeAt(i);
  return u.buffer;
}

async function signJwt(claims, env) {
  const key = await crypto.subtle.importKey('pkcs8', pemToBuf(env.FB_KEY), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const head = b64uStr(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const body = b64uStr(JSON.stringify(claims));
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(head + '.' + body));
  return head + '.' + body + '.' + b64u(sig);
}

async function sha256hex(str) {
  const d = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, '0')).join('');
}

function same(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function accessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  if (tokCache.tok && tokCache.exp > now + 60) return tokCache.tok;
  const jwt = await signJwt({ iss: env.FB_EMAIL, scope: 'https://www.googleapis.com/auth/datastore', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 }, env);
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + jwt
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('oauth');
  tokCache = { tok: j.access_token, exp: now + 3300 };
  return j.access_token;
}

const FS = (env) => 'https://firestore.googleapis.com/v1/projects/' + env.FB_PROJECT + '/databases/(default)/documents';

function variants(type, v) {
  v = String(v || '').trim();
  if (type === 'email') return [...new Set([v, v.toLowerCase()])];
  const d = v.replace(/\D/g, ''), t = d.replace(/^0+/, '');
  return [...new Set([v, d, t, '0' + t, '+' + d].filter(Boolean))];
}

async function findUser(env, type, value) {
  const tok = await accessToken(env);
  for (const val of variants(type, value)) {
    const r = await fetch(FS(env) + ':runQuery', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' },
      body: JSON.stringify({ structuredQuery: { from: [{ collectionId: 'users' }], where: { fieldFilter: { field: { fieldPath: type }, op: 'EQUAL', value: { stringValue: val } } }, limit: 1 } })
    });
    const j = await r.json();
    const d = Array.isArray(j) && j.find((x) => x.document);
    if (d) {
      const f = d.document.fields || {};
      return { uid: d.document.name.split('/').pop(), name: (f.name || {}).stringValue || '', phone: (f.phone || {}).stringValue || '', email: (f.email || {}).stringValue || '' };
    }
  }
  return null;
}

async function tg(env, text) {
  if (!env.TG_TOKEN || !env.TG_CHAT) return;
  try {
    await fetch('https://api.telegram.org/bot' + env.TG_TOKEN + '/sendMessage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: env.TG_CHAT, text })
    });
  } catch (e) { /* ignore */ }
}

function limited(key, max) {
  const now = Date.now(), win = 10 * 60 * 1000;
  const a = (hits.get(key) || []).filter((t) => now - t < win);
  if (a.length >= max) { hits.set(key, a); return true; }
  a.push(now); hits.set(key, a);
  if (hits.size > 500) hits.clear();
  return false;
}

async function forgot(env, body) {
  const type = body.type === 'email' ? 'email' : 'phone';
  const value = String(body.value || '').trim().slice(0, 80);
  if (value.length < 5) return false;
  let u = null;
  try { if (env.FB_KEY) u = await findUser(env, type, value); } catch (e) { /* ignore */ }
  const when = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  const lines = ['🔑 طلب نسيان كلمة المرور', '', (type === 'email' ? '✉️ الايميل المكتوب: ' : '📱 الرقم المكتوب: ') + value];
  if (u) {
    lines.push('', '✅ الحساب موجود:', '👤 ' + u.name, '📱 ' + u.phone, '✉️ ' + u.email);
  } else {
    lines.push('', '⚠️ ما لقيت حساب بهالمعلومة (ممكن أخطأ بالكتابة)');
  }
  lines.push('', '⏰ ' + when, '', 'تأكد منه أول، وبعدين ولّد له رمز من لوحة التحكم ← 🔑 رمز مؤقت.');
  await tg(env, lines.join('\n'));
  return true;
}

async function otpLogin(env, body) {
  const type = body.type === 'email' ? 'email' : 'phone';
  const code = String(body.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (code.length < 6 || code.length > 16) return null;
  const u = await findUser(env, type, body.value);
  if (!u) return null;
  const tok = await accessToken(env);
  const docUrl = FS(env) + '/otps/' + encodeURIComponent(u.uid);
  const auth = { Authorization: 'Bearer ' + tok };
  const r = await fetch(docUrl, { headers: auth });
  if (r.status !== 200) return null;
  const d = await r.json(), f = d.fields || {};
  const hash = (f.hash || {}).stringValue || '';
  const exp = Number((f.exp || {}).integerValue || (f.exp || {}).doubleValue || 0);
  const att = Number((f.attempts || {}).integerValue || 0);
  const kill = () => fetch(docUrl, { method: 'DELETE', headers: auth });
  if (!hash || exp < Date.now() || att >= 5) { await kill(); return null; }
  if (!same(await sha256hex(u.uid + ':' + code), hash)) {
    if (att + 1 >= 5) await kill();
    else await fetch(docUrl + '?updateMask.fieldPaths=attempts', { method: 'PATCH', headers: { ...auth, 'Content-Type': 'application/json' }, body: JSON.stringify({ fields: { attempts: { integerValue: String(att + 1) } } }) });
    return null;
  }
  await kill(); // one time only
  const now = Math.floor(Date.now() / 1000);
  const token = await signJwt({ iss: env.FB_EMAIL, sub: env.FB_EMAIL, aud: AUD, iat: now, exp: now + 3600, uid: u.uid }, env);
  await tg(env, '✅ زبون دخل بالرمز المؤقت: ' + u.name + ' (' + u.phone + ')');
  return token;
}

export default {
  async fetch(req, env) {
    const origin = env.ALLOW_ORIGIN || '*';
    const cors = { 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Vary': 'Origin' };
    const out = (text, status = 200, type = 'text/plain') => new Response(text, { status, headers: { ...cors, 'Content-Type': type + '; charset=utf-8' } });
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (req.method !== 'POST') return out('use POST', 405);
    let body;
    try { body = JSON.parse(await req.text()); } catch (e) { return out('bad', 400); }
    const path = new URL(req.url).pathname;
    const ip = req.headers.get('CF-Connecting-IP') || 'x';
    try {
      if (path.endsWith('/forgot')) {
        if (limited('f:' + ip, 3)) return out('slow', 429);
        return (await forgot(env, body)) ? out('ok') : out('bad', 400);
      }
      if (path.endsWith('/otp-login')) {
        if (!env.FB_KEY || !env.FB_EMAIL || !env.FB_PROJECT) return out('not-configured', 500);
        if (limited('o:' + ip, 10)) return out('slow', 429);
        const token = await otpLogin(env, body);
        return token ? out(JSON.stringify({ token }), 200, 'application/json') : out('invalid', 401);
      }
    } catch (e) {
      return out('error', 500);
    }
    return out('not found', 404);
  }
};
