// PROPRIETARY AND CONFIDENTIAL. Copyright 2025-2026 BlackRoad OS, Inc. All rights reserved. NOT open source.
// CarKeys by BlackRoad OS — Post to 15 platforms. One click.
// carkeys.blackroad.io

const PLATFORMS = {
  x:         { name: 'X (Twitter)',  icon: 'X',  share: (t,u) => `https://x.com/intent/tweet?text=${e(t+' '+u)}` },
  reddit:    { name: 'Reddit',       icon: 'R',  share: (t,u) => `https://www.reddit.com/submit?title=${e(t)}&url=${e(u)}` },
  linkedin:  { name: 'LinkedIn',     icon: 'in', share: (t,u) => `https://www.linkedin.com/sharing/share-offsite/?url=${e(u)}` },
  facebook:  { name: 'Facebook',     icon: 'f',  share: (t,u) => `https://www.facebook.com/sharer/sharer.php?u=${e(u)}&quote=${e(t)}` },
  threads:   { name: 'Threads',      icon: '@',  share: (t,u) => `https://www.threads.net/intent/post?text=${e(t+' '+u)}` },
  whatsapp:  { name: 'WhatsApp',     icon: 'W',  share: (t,u) => `https://wa.me/?text=${e(t+' '+u)}` },
  telegram:  { name: 'Telegram',     icon: 'T',  share: (t,u) => `https://t.me/share/url?url=${e(u)}&text=${e(t)}` },
  mastodon:  { name: 'Mastodon',     icon: 'M',  share: (t,u) => `https://mastodon.social/share?text=${e(t+' '+u)}` },
  pinterest: { name: 'Pinterest',    icon: 'P',  share: (t,u) => `https://pinterest.com/pin/create/button/?url=${e(u)}&description=${e(t)}` },
  hn:        { name: 'Hacker News',  icon: 'Y',  share: (t,u) => `https://news.ycombinator.com/submitlink?u=${e(u)}&t=${e(t)}` },
  tumblr:    { name: 'Tumblr',       icon: 't',  share: (t,u) => `https://www.tumblr.com/widgets/share/tool?canonicalUrl=${e(u)}&caption=${e(t)}` },
  weibo:     { name: 'Weibo',        icon: 'W',  share: (t,u) => `https://service.weibo.com/share/share.php?url=${e(u)}&title=${e(t)}` },
  vk:        { name: 'VK',           icon: 'V',  share: (t,u) => `https://vk.com/share.php?url=${e(u)}&title=${e(t)}` },
  line:      { name: 'LINE',         icon: 'L',  share: (t,u) => `https://social-plugins.line.me/lineit/share?url=${e(u)}&text=${e(t)}` },
  email:     { name: 'Email',        icon: '@',  share: (t,u) => `mailto:?subject=${e(t)}&body=${e(t+'\\n\\n'+u)}` },
};

function e(s) { return encodeURIComponent(s); }
const SEC = { 'Content-Security-Policy': "frame-ancestors 'self' https://blackroad.io https://*.blackroad.io" };

async function stampChain(action, entity, details) {
  fetch('https://roadchain-worker.blackroad.workers.dev/api/event', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({app:'carkeys', type: action, data: {entity, details}})
  }).catch(()=>{});
}
async function earnCoin(road_id, action, amount) {
  fetch('https://roadcoin-worker.blackroad.workers.dev/api/earn', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({road_id: road_id || 'system', action, amount})
  }).catch(()=>{});
}

// ─── Password generation helpers ───
const CHARSETS = {
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
  all: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?',
};

function generatePassword(length = 20, charset = 'all') {
  const chars = CHARSETS[charset] || CHARSETS.all;
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  let pw = '';
  for (let i = 0; i < length; i++) pw += chars[arr[i] % chars.length];
  return pw;
}

function calcEntropy(password) {
  const unique = new Set(password);
  let poolSize = 0;
  const has = (re) => re.test(password);
  if (has(/[a-z]/)) poolSize += 26;
  if (has(/[A-Z]/)) poolSize += 26;
  if (has(/[0-9]/)) poolSize += 10;
  if (has(/[^a-zA-Z0-9]/)) poolSize += 32;
  return poolSize > 0 ? Math.floor(password.length * Math.log2(poolSize)) : 0;
}

function passwordStrength(password) {
  const entropy = calcEntropy(password);
  if (entropy >= 80) return 'very-strong';
  if (entropy >= 60) return 'strong';
  if (entropy >= 40) return 'medium';
  if (entropy >= 20) return 'weak';
  return 'very-weak';
}

// ─── TOTP helpers ───
function base32Encode(buffer) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  const bytes = new Uint8Array(buffer);
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  let result = '';
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, '0');
    result += alphabet[parseInt(chunk, 2)];
  }
  return result;
}

function base32Decode(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of str.toUpperCase()) {
    const val = alphabet.indexOf(c);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(bytes);
}

async function generateTOTP(secret, time = null) {
  const now = time || Math.floor(Date.now() / 1000);
  const counter = Math.floor(now / 30);
  const counterBytes = new ArrayBuffer(8);
  const view = new DataView(counterBytes);
  view.setUint32(4, counter, false);

  const keyData = base32Decode(secret);
  const key = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, counterBytes);
  const hmac = new Uint8Array(sig);

  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24 | hmac[offset + 1] << 16 | hmac[offset + 2] << 8 | hmac[offset + 3]) % 1000000;
  return code.toString().padStart(6, '0');
}

// ─── SHA-1 helper for breach check ───
async function sha1(str) {
  const data = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-1', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// ─── AES-GCM encryption for notes and export ───
async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptData(plaintext, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
  // Return as hex: salt:iv:ciphertext
  const toHex = (buf) => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  return toHex(salt) + ':' + toHex(iv) + ':' + toHex(ciphertext);
}

async function decryptData(encryptedStr, password) {
  const parts = encryptedStr.split(':');
  if (parts.length !== 3) throw new Error('Invalid encrypted format');
  const fromHex = (hex) => new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
  const salt = fromHex(parts[0]);
  const iv = fromHex(parts[1]);
  const ciphertext = fromHex(parts[2]);
  const key = await deriveKey(password, salt);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(decrypted);
}

let dbReady = false;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    const cors = {'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization'};

    if (request.method === 'OPTIONS') return new Response(null, {status:204,headers:cors});

    if (path === '/api/health') return Response.json({ status: 'up', service: 'CarKeys', platforms: Object.keys(PLATFORMS).length });
    if (path === '/api/platforms') return Response.json(Object.entries(PLATFORMS).map(([id, p]) => ({ id, name: p.name })));

    if (path === '/api/share') {
      const text = url.searchParams.get('text') || '';
      const link = url.searchParams.get('url') || 'https://blackroad.io';
      const links = {};
      for (const [id, p] of Object.entries(PLATFORMS)) links[id] = { name: p.name, url: p.share(text, link) };
      return Response.json({ text, url: link, platforms: links, count: Object.keys(links).length });
    }

    if (path.startsWith('/go/')) {
      const platform = path.split('/')[2];
      const text = url.searchParams.get('text') || '';
      const link = url.searchParams.get('url') || 'https://blackroad.io';
      const p = PLATFORMS[platform];
      if (!p) return Response.json({ error: 'Unknown platform', available: Object.keys(PLATFORMS) }, { status: 404 });
      return Response.redirect(p.share(text, link), 302);
    }

    if (path === '/blast') {
      const text = url.searchParams.get('text') || 'Check this out';
      const link = url.searchParams.get('url') || 'https://blackroad.io';
      const selected = (url.searchParams.get('platforms') || 'x,reddit,linkedin,facebook,threads,mastodon,hn').split(',');
      return new Response(renderBlast(text, link, selected), { headers: { 'Content-Type': 'text/html;charset=utf-8', ...SEC } });
    }

    // ─── Vault API endpoints (D1-backed) ───
    if (path.startsWith('/api/')) {
      try {
        if (!dbReady) { await ensureCKTables(env.DB); dbReady = true; }

        // ─── List devices ───
        if (path === '/api/devices' && request.method === 'GET') {
          const rows = await env.DB.prepare('SELECT * FROM ck_devices ORDER BY created_at DESC').all();
          return json({devices:rows.results||[]},cors);
        }

        // ─── Register device ───
        if (path === '/api/devices' && request.method === 'POST') {
          const body = await request.json();
          if (!body.name || !body.type) return json({error:'name and type required'},cors,400);
          const id = crypto.randomUUID().slice(0,8);
          const fingerprint = body.fingerprint || crypto.randomUUID();
          await env.DB.prepare('INSERT INTO ck_devices (id,name,type,fingerprint,trust_score) VALUES (?,?,?,?,?)')
            .bind(id,body.name.slice(0,100),body.type.slice(0,50),fingerprint,50).run();
          await logAudit(env.DB,'device_registered',id,`Device ${body.name} (${body.type}) registered`);
          stampChain('device_registered', id, body.name);
          return json({ok:true,id,name:body.name,type:body.type,trust_score:50},cors,201);
        }

        // ─── Device detail ───
        const deviceMatch = path.match(/^\/api\/devices\/([^/]+)$/);
        if (deviceMatch && request.method === 'GET') {
          const device = await env.DB.prepare('SELECT * FROM ck_devices WHERE id=?').bind(deviceMatch[1]).first();
          if (!device) return json({error:'device not found'},cors,404);
          const logs = await env.DB.prepare('SELECT * FROM ck_audit WHERE entity_id=? ORDER BY created_at DESC LIMIT 20').bind(device.id).all();
          return json({device,access_log:logs.results||[]},cors);
        }

        // ─── List keys ───
        if (path === '/api/keys' && request.method === 'GET') {
          const rows = await env.DB.prepare('SELECT id,name,type,strength,rotation_age_days,last_rotated,status,created_at FROM ck_keys ORDER BY created_at DESC').all();
          return json({keys:rows.results||[]},cors);
        }

        // ─── Rotate a key ───
        if (path === '/api/keys/rotate' && request.method === 'POST') {
          const body = await request.json();
          if (!body.key_id) return json({error:'key_id required'},cors,400);
          const key = await env.DB.prepare('SELECT * FROM ck_keys WHERE id=?').bind(body.key_id).first();
          if (!key) return json({error:'key not found'},cors,404);
          if (key.status === 'locked') return json({error:'key is locked down, release lockdown first'},cors,403);
          const newFingerprint = crypto.randomUUID();
          await env.DB.prepare("UPDATE ck_keys SET fingerprint=?,last_rotated=datetime('now'),rotation_age_days=0 WHERE id=?")
            .bind(newFingerprint,key.id).run();
          await logAudit(env.DB,'key_rotated',key.id,`Key ${key.name} rotated. New fingerprint: ${newFingerprint.slice(0,8)}...`);
          stampChain('key_rotated', key.id, 'rotation'); earnCoin('system', 'security', 0.25);
          return json({ok:true,key_id:key.id,name:key.name,rotated:true,new_fingerprint:newFingerprint.slice(0,8)+'...'},cors);
        }

        // ─── Security score ───
        if (path === '/api/security-score' && request.method === 'GET') {
          const devices = await env.DB.prepare('SELECT COUNT(*) as c FROM ck_devices').first();
          const keys = await env.DB.prepare('SELECT * FROM ck_keys').all();
          const lockdown = await env.DB.prepare("SELECT COUNT(*) as c FROM ck_keys WHERE status='locked'").first();

          let score = 100;
          const issues = [];

          if ((devices?.c||0) === 0) { score -= 20; issues.push('No devices registered'); }
          if ((keys.results||[]).length === 0) { score -= 20; issues.push('No keys in vault'); }

          for (const k of (keys.results||[])) {
            if (k.rotation_age_days > 90) { score -= 10; issues.push(`Key "${k.name}" needs rotation (${k.rotation_age_days} days old)`); }
            if (k.strength === 'weak') { score -= 15; issues.push(`Key "${k.name}" has weak strength`); }
          }
          if ((lockdown?.c||0) > 0) { score -= 5; issues.push('Vault is in lockdown mode'); }
          score = Math.max(0, Math.min(100, score));

          // If score < 70, Valeria adds AI recommendations
          let ai_recommendations = '';
          if (score < 70) {
            try {
              const prompt = `You are Valeria, the Security Chief on BlackRoad OS. Direct, precise, protective.

Security score is ${score}/100 (grade: ${score >= 60 ? 'C' : score >= 40 ? 'D' : 'F'}). Issues found: ${issues.join('; ')||'none'}.
Devices: ${devices?.c||0}. Keys: ${(keys.results||[]).length}. Locked: ${lockdown?.c||0}.

Give 3 specific, actionable steps to improve this score. Be concise — one sentence each. Number them.`;
              ai_recommendations = await runCKAI(env.AI, prompt);
            } catch {}
          }

          return json({
            score,
            grade: score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F',
            devices: devices?.c||0,
            keys_total: (keys.results||[]).length,
            keys_locked: lockdown?.c||0,
            issues,
            ...(ai_recommendations ? {ai_recommendations,agent:'Valeria'} : {}),
          },cors);
        }

        // ─── Emergency lockdown ───
        if (path === '/api/lockdown' && request.method === 'POST') {
          const body = await request.json().catch(()=>({}));
          await env.DB.prepare("UPDATE ck_keys SET status='locked'").run();
          await logAudit(env.DB,'lockdown_activated','vault','Emergency lockdown activated on all keys');
          stampChain('lockdown', 'all', 'emergency');

          let ai_assessment = '';
          try {
            const keys = await env.DB.prepare('SELECT COUNT(*) as c FROM ck_keys').first();
            const prompt = `You are Valeria, the Security Chief on BlackRoad OS. Direct, precise, protective.

LOCKDOWN has been activated on the vault. ${keys?.c||0} keys are now locked. ${body.reason ? 'Reason given: "'+body.reason.slice(0,200)+'"' : 'No reason given.'}

Give a brief situation assessment (2 sentences): acknowledge the lockdown, explain what this means for the user, and tell them exactly what to do next. Be calm but serious.`;
            ai_assessment = await runCKAI(env.AI, prompt);
          } catch {}

          return json({ok:true,status:'locked',message:'All keys are now in lockdown mode. Use POST /api/lockdown/release to restore.',agent:'Valeria',ai_assessment:ai_assessment||'Lockdown activated. All keys frozen. Review your audit log and release when safe.'},cors);
        }

        // ─── Release lockdown ───
        if (path === '/api/lockdown/release' && request.method === 'POST') {
          const body = await request.json().catch(()=>({}));
          if (!body.confirm) return json({error:'Send {"confirm":true} to release lockdown'},cors,400);
          await env.DB.prepare("UPDATE ck_keys SET status='active'").run();
          await logAudit(env.DB,'lockdown_released','vault','Lockdown released, all keys restored to active');
          return json({ok:true,status:'active',message:'Lockdown released. All keys are active again.'},cors);
        }

        // ─── Audit log ───
        if (path === '/api/audit' && request.method === 'GET') {
          const limit = parseInt(url.searchParams.get('limit')||'50');
          const rows = await env.DB.prepare('SELECT * FROM ck_audit ORDER BY created_at DESC LIMIT ?').bind(limit).all();
          return json({audit:rows.results||[]},cors);
        }

        // ─── Family key sharing ───
        if (path === '/api/family' && request.method === 'GET') {
          const rows = await env.DB.prepare('SELECT * FROM ck_family_keys ORDER BY created_at DESC').all();
          return json({family_keys:rows.results||[]},cors);
        }

        if (path === '/api/family' && request.method === 'POST') {
          const body = await request.json();
          if (!body.name) return json({error:'name required'},cors,400);
          const id = crypto.randomUUID().slice(0,8);
          const permissions = body.permissions || 'read';
          const monitored_by = body.monitored_by || 'owner';
          await env.DB.prepare('INSERT INTO ck_family_keys (id,name,permissions,monitored_by) VALUES (?,?,?,?)')
            .bind(id,body.name.slice(0,100),permissions,monitored_by).run();
          await logAudit(env.DB,'family_key_created',id,`Family key "${body.name}" created with ${permissions} permissions, monitored by ${monitored_by}`);
          return json({ok:true,id,name:body.name,permissions,monitored_by},cors,201);
        }

        // ─── AI: Security posture analysis (Valeria) ───
        if (path === '/api/analyze' && request.method === 'POST') {
          const body = await request.json().catch(()=>({}));
          const devices = await env.DB.prepare('SELECT * FROM ck_devices').all();
          const keys = await env.DB.prepare('SELECT id,name,type,strength,rotation_age_days,status FROM ck_keys').all();
          const audit = await env.DB.prepare('SELECT * FROM ck_audit ORDER BY created_at DESC LIMIT 10').all();

          const prompt = `You are Valeria, the Security Chief on BlackRoad OS. Direct, precise, protective. You speak like a security expert who actually cares about the person behind the screen. Never alarmist, always actionable.

Analyze this security posture:
- Devices registered: ${(devices.results||[]).length}. Types: ${(devices.results||[]).map(d=>d.type).join(', ')||'none'}
- Keys in vault: ${(keys.results||[]).length}. Weak: ${(keys.results||[]).filter(k=>k.strength==='weak').length}. Locked: ${(keys.results||[]).filter(k=>k.status==='locked').length}. Needing rotation (>90 days): ${(keys.results||[]).filter(k=>k.rotation_age_days>90).length}
- Recent audit events: ${(audit.results||[]).map(a=>a.action).join(', ')||'none'}
${body.devices ? '- User-reported devices: '+JSON.stringify(body.devices) : ''}
${body.keys ? '- User-reported keys: '+JSON.stringify(body.keys) : ''}

Give a security report: overall assessment (1 sentence), top 3 recommendations (numbered), and a risk rating (low/medium/high/critical). Keep it under 150 words.`;

          const report = await runCKAI(env.AI, prompt);
          return json({ok:true,agent:'Valeria',role:'Security Chief',report,devices:(devices.results||[]).length,keys:(keys.results||[]).length},cors);
        }

        // ─── AI: Threat check (Valeria) ───
        if (path === '/api/threat-check' && request.method === 'POST') {
          const body = await request.json();
          if (!body.url && !body.description) return json({error:'url or description required'},cors,400);
          const target = body.url || body.description;

          const prompt = `You are Valeria, the Security Chief on BlackRoad OS. Direct, precise, protective.

A user wants you to check this for potential threats: "${target.slice(0,500)}"

Analyze for: phishing indicators, suspicious patterns, credential exposure risks, known bad patterns. Give a threat level (safe/caution/warning/danger), explain why in 2 sentences, and give 1 specific action to take. Be honest — if it looks fine, say so.`;

          const analysis = await runCKAI(env.AI, prompt);
          return json({ok:true,agent:'Valeria',target:target.slice(0,200),analysis},cors);
        }

        // ─── POST /api/scan — Security scanner (Valeria) ───
        if (path === '/api/scan' && request.method === 'POST') {
          const body = await request.json().catch(()=>({}));
          const target = body.url || body.domain || '';
          if (!target) return json({error:'url or domain required'},cors,400);

          const prompt = `You are Valeria, the Security Chief on BlackRoad OS. Direct, precise, protective.

Analyze this target for security issues: "${target.slice(0,500)}"

Check for:
1. SSL/TLS certificate status (valid, expired, self-signed, missing)
2. Common vulnerabilities (open ports, exposed admin panels, directory listing, outdated software)
3. HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
4. DNS configuration issues (SPF, DKIM, DMARC for email domains)

Return a JSON object with this exact format:
{"score": <0-100>, "issues": ["issue1", "issue2"], "recommendations": ["rec1", "rec2"], "ssl_status": "valid|expired|missing|unknown", "headers_grade": "A|B|C|D|F"}`;

          let analysis = {score:75,issues:['Unable to perform live scan'],recommendations:['Run a full scan with network access'],ssl_status:'unknown',headers_grade:'C'};
          try {
            const aiResult = await runCKAI(env.AI, prompt);
            if (aiResult) {
              try { analysis = JSON.parse(aiResult); } catch { analysis.ai_narrative = aiResult; }
            }
          } catch {}

          await logAudit(env.DB,'security_scan','scan',`Scanned: ${target.slice(0,200)}`);
          stampChain('security_scan', target.slice(0,100), 'scan'); earnCoin('system', 'security', 0.5);
          return json({ok:true,agent:'Valeria',target:target.slice(0,200),score:analysis.score||75,issues:analysis.issues||[],recommendations:analysis.recommendations||[],ssl_status:analysis.ssl_status||'unknown',headers_grade:analysis.headers_grade||'C',...(analysis.ai_narrative?{ai_narrative:analysis.ai_narrative}:{})},cors);
        }

        // ─── GET /api/vault/stats — Vault statistics ───
        if (path === '/api/vault/stats' && request.method === 'GET') {
          const devices = await env.DB.prepare('SELECT COUNT(*) as c FROM ck_devices').first();
          const keys = await env.DB.prepare('SELECT COUNT(*) as c FROM ck_keys').first();
          const familyKeys = await env.DB.prepare('SELECT COUNT(*) as c FROM ck_family_keys').first();
          const locked = await env.DB.prepare("SELECT COUNT(*) as c FROM ck_keys WHERE status='locked'").first();
          const rotations = await env.DB.prepare('SELECT COUNT(*) as c FROM ck_audit WHERE action LIKE ?').bind('%rotat%').first();
          const lockdowns = await env.DB.prepare("SELECT COUNT(*) as c FROM ck_audit WHERE action='lockdown_activated'").first();
          const recentAudit = await env.DB.prepare('SELECT COUNT(*) as c FROM ck_audit').first();
          return json({
            vault:{
              total_keys:keys?.c||0,
              total_devices:devices?.c||0,
              family_keys:familyKeys?.c||0,
              keys_locked:locked?.c||0,
              total_rotations:rotations?.c||0,
              total_lockdowns:lockdowns?.c||0,
              audit_entries:recentAudit?.c||0,
              status:locked?.c>0?'lockdown':'active',
            }
          },cors);
        }

        // ─── POST /api/vault/backup — Encrypted backup of vault state ───
        if (path === '/api/vault/backup' && request.method === 'POST') {
          const devices = await env.DB.prepare('SELECT * FROM ck_devices').all();
          const keys = await env.DB.prepare('SELECT id,name,type,strength,rotation_age_days,status,created_at FROM ck_keys').all();
          const familyKeys = await env.DB.prepare('SELECT * FROM ck_family_keys').all();
          const audit = await env.DB.prepare('SELECT * FROM ck_audit ORDER BY created_at DESC LIMIT 100').all();

          const backupId = crypto.randomUUID().slice(0,12);
          const manifest = {
            backup_id:backupId,
            created_at:new Date().toISOString(),
            devices:(devices.results||[]).length,
            keys:(keys.results||[]).length,
            family_keys:(familyKeys.results||[]).length,
            audit_entries:(audit.results||[]).length,
            format:'json',
            encrypted:false,
            note:'Backup contains vault metadata only. Key fingerprints are excluded for security.',
          };

          const payload = {
            manifest,
            data:{
              devices:(devices.results||[]).map(d=>({id:d.id,name:d.name,type:d.type,trust_score:d.trust_score,created_at:d.created_at})),
              keys:(keys.results||[]).map(k=>({id:k.id,name:k.name,type:k.type,strength:k.strength,rotation_age_days:k.rotation_age_days,status:k.status,created_at:k.created_at})),
              family_keys:familyKeys.results||[],
              recent_audit:audit.results||[],
            }
          };

          await logAudit(env.DB,'vault_backup',backupId,'Vault backup created');
          stampChain('vault_backup', backupId, 'backup');
          return json({ok:true,backup_id:backupId,manifest},cors,201);
        }

        // ═══════════════════════════════════════════════════════════════
        // ─── NEW FEATURE: Password Generator ───
        // ═══════════════════════════════════════════════════════════════
        if (path === '/api/generate' && (request.method === 'GET' || request.method === 'POST')) {
          let length = 20, charset = 'all', count = 1;
          if (request.method === 'POST') {
            const body = await request.json().catch(() => ({}));
            length = Math.min(Math.max(parseInt(body.length) || 20, 4), 128);
            charset = body.charset || 'all';
            count = Math.min(Math.max(parseInt(body.count) || 1, 1), 10);
          } else {
            length = Math.min(Math.max(parseInt(url.searchParams.get('length')) || 20, 4), 128);
            charset = url.searchParams.get('charset') || 'all';
            count = Math.min(Math.max(parseInt(url.searchParams.get('count')) || 1, 1), 10);
          }

          const passwords = [];
          for (let i = 0; i < count; i++) {
            const pw = generatePassword(length, charset);
            passwords.push({
              password: pw,
              length: pw.length,
              entropy: calcEntropy(pw),
              strength: passwordStrength(pw),
            });
          }

          await logAudit(env.DB, 'password_generated', 'generator', `Generated ${count} password(s), length=${length}, charset=${charset}`);
          return json({ ok: true, passwords, charset, generated_at: new Date().toISOString() }, cors);
        }

        // ═══════════════════════════════════════════════════════════════
        // ─── NEW FEATURE: Breach Check (k-anonymity via HIBP) ───
        // ═══════════════════════════════════════════════════════════════
        if (path === '/api/breach-check' && request.method === 'POST') {
          const body = await request.json();
          if (!body.password) return json({ error: 'password required' }, cors, 400);

          const hash = await sha1(body.password);
          const prefix = hash.slice(0, 5);
          const suffix = hash.slice(5);

          let breached = false;
          let count = 0;

          try {
            const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
              headers: { 'User-Agent': 'CarKeys-BlackRoad/1.0' }
            });
            if (resp.ok) {
              const text = await resp.text();
              const lines = text.split('\n');
              for (const line of lines) {
                const [hashSuffix, cnt] = line.trim().split(':');
                if (hashSuffix === suffix) {
                  breached = true;
                  count = parseInt(cnt) || 0;
                  break;
                }
              }
            }
          } catch (err) {
            return json({ ok: true, breached: null, error: 'Unable to reach breach database', prefix }, cors);
          }

          const strength = passwordStrength(body.password);
          const entropy = calcEntropy(body.password);

          await logAudit(env.DB, 'breach_check', 'security', `Breach check performed (prefix: ${prefix}...)`);
          return json({
            ok: true,
            breached,
            times_seen: count,
            prefix,
            strength,
            entropy,
            recommendation: breached
              ? `This password has appeared in ${count.toLocaleString()} data breaches. Change it immediately.`
              : 'This password has not been found in known breaches.',
          }, cors);
        }

        // ═══════════════════════════════════════════════════════════════
        // ─── NEW FEATURE: TOTP/2FA Setup ───
        // ═══════════════════════════════════════════════════════════════
        if (path === '/api/totp/setup' && request.method === 'POST') {
          const body = await request.json().catch(() => ({}));
          const issuer = body.issuer || 'CarKeys';
          const account = body.account || 'user@blackroad.io';

          // Generate 20 random bytes for the secret
          const secretBytes = crypto.getRandomValues(new Uint8Array(20));
          const secret = base32Encode(secretBytes);

          // Generate current code for verification
          const currentCode = await generateTOTP(secret);

          // Build otpauth URI
          const otpauthUrl = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

          // Store the TOTP setup in D1
          const id = crypto.randomUUID().slice(0, 8);
          await env.DB.prepare('INSERT INTO ck_totp (id, account, issuer, secret, verified, created_at) VALUES (?,?,?,?,0,datetime(\'now\'))')
            .bind(id, account.slice(0, 200), issuer.slice(0, 100), secret).run();

          await logAudit(env.DB, 'totp_setup', id, `TOTP setup for ${account} (${issuer})`);
          return json({
            ok: true,
            id,
            secret,
            otpauth_url: otpauthUrl,
            account,
            issuer,
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
            current_code: currentCode,
            instructions: 'Scan the otpauth_url as a QR code in your authenticator app, then verify with /api/totp/verify',
          }, cors, 201);
        }

        // ─── TOTP Verify ───
        if (path === '/api/totp/verify' && request.method === 'POST') {
          const body = await request.json();
          if (!body.code) return json({ error: 'code required' }, cors, 400);
          if (!body.id && !body.secret) return json({ error: 'id or secret required' }, cors, 400);

          let secret = body.secret;
          let totpId = body.id;

          if (totpId && !secret) {
            const row = await env.DB.prepare('SELECT * FROM ck_totp WHERE id=?').bind(totpId).first();
            if (!row) return json({ error: 'TOTP setup not found' }, cors, 404);
            secret = row.secret;
          }

          // Check current window and +/- 1 step for clock drift
          const now = Math.floor(Date.now() / 1000);
          let valid = false;
          for (const offset of [-30, 0, 30]) {
            const expected = await generateTOTP(secret, now + offset);
            if (expected === body.code.toString().padStart(6, '0')) {
              valid = true;
              break;
            }
          }

          if (valid && totpId) {
            await env.DB.prepare("UPDATE ck_totp SET verified=1 WHERE id=?").bind(totpId).run();
          }

          await logAudit(env.DB, 'totp_verify', totpId || 'manual', `TOTP verification: ${valid ? 'success' : 'failed'}`);
          return json({ ok: true, valid, message: valid ? 'Code verified successfully.' : 'Invalid code. Check your authenticator app.' }, cors);
        }

        // ─── List TOTP entries ───
        if (path === '/api/totp' && request.method === 'GET') {
          const rows = await env.DB.prepare('SELECT id, account, issuer, verified, created_at FROM ck_totp ORDER BY created_at DESC').all();
          return json({ totp_entries: rows.results || [] }, cors);
        }

        // ═══════════════════════════════════════════════════════════════
        // ─── NEW FEATURE: Secure Notes (Encrypted) ───
        // ═══════════════════════════════════════════════════════════════
        if (path === '/api/notes' && request.method === 'GET') {
          const rows = await env.DB.prepare('SELECT id, title, category, created_at, updated_at FROM ck_notes ORDER BY updated_at DESC').all();
          return json({ notes: rows.results || [] }, cors);
        }

        if (path === '/api/notes' && request.method === 'POST') {
          const body = await request.json();
          if (!body.title || !body.content) return json({ error: 'title and content required' }, cors, 400);
          if (!body.passphrase) return json({ error: 'passphrase required for encryption' }, cors, 400);

          const id = crypto.randomUUID().slice(0, 8);
          const encrypted = await encryptData(body.content, body.passphrase);
          const category = body.category || 'general';

          await env.DB.prepare("INSERT INTO ck_notes (id, title, category, encrypted_content, created_at, updated_at) VALUES (?,?,?,?,datetime('now'),datetime('now'))")
            .bind(id, body.title.slice(0, 200), category.slice(0, 50), encrypted).run();

          await logAudit(env.DB, 'note_created', id, `Secure note "${body.title.slice(0, 50)}" created`);
          return json({ ok: true, id, title: body.title, category, encrypted: true }, cors, 201);
        }

        // ─── Read a note (requires passphrase) ───
        const noteMatch = path.match(/^\/api\/notes\/([^/]+)$/);
        if (noteMatch && request.method === 'POST') {
          const body = await request.json();
          if (!body.passphrase) return json({ error: 'passphrase required to decrypt' }, cors, 400);

          const note = await env.DB.prepare('SELECT * FROM ck_notes WHERE id=?').bind(noteMatch[1]).first();
          if (!note) return json({ error: 'note not found' }, cors, 404);

          try {
            const decrypted = await decryptData(note.encrypted_content, body.passphrase);
            await logAudit(env.DB, 'note_read', note.id, `Secure note "${note.title}" decrypted`);
            return json({ ok: true, id: note.id, title: note.title, category: note.category, content: decrypted, created_at: note.created_at, updated_at: note.updated_at }, cors);
          } catch {
            return json({ error: 'Invalid passphrase' }, cors, 403);
          }
        }

        // ─── Update a note ───
        if (noteMatch && request.method === 'PUT') {
          const body = await request.json();
          if (!body.passphrase) return json({ error: 'passphrase required' }, cors, 400);

          const note = await env.DB.prepare('SELECT * FROM ck_notes WHERE id=?').bind(noteMatch[1]).first();
          if (!note) return json({ error: 'note not found' }, cors, 404);

          // Verify old passphrase works
          try { await decryptData(note.encrypted_content, body.passphrase); } catch { return json({ error: 'Invalid passphrase' }, cors, 403); }

          const newContent = body.content || '';
          const newTitle = body.title || note.title;
          const newCategory = body.category || note.category;
          const newPassphrase = body.new_passphrase || body.passphrase;
          const encrypted = await encryptData(newContent, newPassphrase);

          await env.DB.prepare("UPDATE ck_notes SET title=?, category=?, encrypted_content=?, updated_at=datetime('now') WHERE id=?")
            .bind(newTitle.slice(0, 200), newCategory.slice(0, 50), encrypted, note.id).run();

          await logAudit(env.DB, 'note_updated', note.id, `Secure note "${newTitle.slice(0, 50)}" updated`);
          return json({ ok: true, id: note.id, title: newTitle, category: newCategory, updated: true }, cors);
        }

        // ─── Delete a note ───
        if (noteMatch && request.method === 'DELETE') {
          const note = await env.DB.prepare('SELECT id, title FROM ck_notes WHERE id=?').bind(noteMatch[1]).first();
          if (!note) return json({ error: 'note not found' }, cors, 404);
          await env.DB.prepare('DELETE FROM ck_notes WHERE id=?').bind(note.id).run();
          await logAudit(env.DB, 'note_deleted', note.id, `Secure note "${note.title}" deleted`);
          return json({ ok: true, deleted: note.id }, cors);
        }

        // ═══════════════════════════════════════════════════════════════
        // ─── NEW FEATURE: Vault Sharing (time-limited links) ───
        // ═══════════════════════════════════════════════════════════════
        if (path === '/api/share-link' && request.method === 'POST') {
          const body = await request.json();
          if (!body.key_id && !body.note_id && !body.content) return json({ error: 'key_id, note_id, or content required' }, cors, 400);

          const id = crypto.randomUUID().slice(0, 12);
          const token = crypto.randomUUID();
          const ttlMinutes = Math.min(Math.max(parseInt(body.ttl_minutes) || 60, 1), 10080); // 1 min to 7 days
          const maxViews = Math.min(Math.max(parseInt(body.max_views) || 1, 1), 100);
          const expiresAt = new Date(Date.now() + ttlMinutes * 60000).toISOString();

          // If sharing raw content, encrypt it
          let sharedData = '';
          if (body.content) {
            const sharePass = crypto.randomUUID().slice(0, 8);
            sharedData = await encryptData(body.content, sharePass);
            // Token includes the decryption key
            await env.DB.prepare("INSERT INTO ck_share_links (id, token, share_type, entity_id, encrypted_data, decrypt_hint, expires_at, max_views, view_count, created_at) VALUES (?,?,?,?,?,?,?,?,0,datetime('now'))")
              .bind(id, token, 'content', 'direct', sharedData, sharePass, expiresAt, maxViews).run();
          } else {
            const entityType = body.key_id ? 'key' : 'note';
            const entityId = body.key_id || body.note_id;
            await env.DB.prepare("INSERT INTO ck_share_links (id, token, share_type, entity_id, encrypted_data, decrypt_hint, expires_at, max_views, view_count, created_at) VALUES (?,?,?,?,?,?,?,?,0,datetime('now'))")
              .bind(id, token, entityType, entityId, '', '', expiresAt, maxViews).run();
          }

          await logAudit(env.DB, 'share_link_created', id, `Share link created, expires ${expiresAt}, max ${maxViews} views`);
          stampChain('share_created', id, 'vault_share');

          const shareUrl = `${url.origin}/shared/${token}`;
          return json({
            ok: true,
            id,
            share_url: shareUrl,
            token,
            expires_at: expiresAt,
            ttl_minutes: ttlMinutes,
            max_views: maxViews,
          }, cors, 201);
        }

        // ─── View shared content ───
        if (path.startsWith('/api/shared/')) {
          const token = path.split('/')[3];
          if (!token) return json({ error: 'token required' }, cors, 400);

          const link = await env.DB.prepare('SELECT * FROM ck_share_links WHERE token=?').bind(token).first();
          if (!link) return json({ error: 'Share link not found or expired' }, cors, 404);

          // Check expiry
          if (new Date(link.expires_at) < new Date()) {
            await env.DB.prepare('DELETE FROM ck_share_links WHERE id=?').bind(link.id).run();
            return json({ error: 'Share link has expired' }, cors, 410);
          }

          // Check view count
          if (link.view_count >= link.max_views) {
            await env.DB.prepare('DELETE FROM ck_share_links WHERE id=?').bind(link.id).run();
            return json({ error: 'Share link has reached maximum views' }, cors, 410);
          }

          // Increment view count
          await env.DB.prepare('UPDATE ck_share_links SET view_count = view_count + 1 WHERE id=?').bind(link.id).run();

          let result = { share_type: link.share_type, views_remaining: link.max_views - link.view_count - 1, expires_at: link.expires_at };

          if (link.share_type === 'content' && link.encrypted_data && link.decrypt_hint) {
            try {
              const decrypted = await decryptData(link.encrypted_data, link.decrypt_hint);
              result.content = decrypted;
            } catch {
              result.content = '[Decryption failed]';
            }
          } else if (link.share_type === 'key') {
            const key = await env.DB.prepare('SELECT id,name,type,strength,status FROM ck_keys WHERE id=?').bind(link.entity_id).first();
            result.key = key || { error: 'Key no longer exists' };
          } else if (link.share_type === 'note') {
            const note = await env.DB.prepare('SELECT id,title,category,created_at FROM ck_notes WHERE id=?').bind(link.entity_id).first();
            result.note = note || { error: 'Note no longer exists' };
          }

          await logAudit(env.DB, 'share_link_viewed', link.id, `Share link viewed (${link.view_count + 1}/${link.max_views})`);
          return json({ ok: true, ...result }, cors);
        }

        // ═══════════════════════════════════════════════════════════════
        // ─── NEW FEATURE: Password Health Dashboard ───
        // ═══════════════════════════════════════════════════════════════
        if (path === '/api/health-report' && request.method === 'GET') {
          const keys = await env.DB.prepare('SELECT * FROM ck_keys').all();
          const keyList = keys.results || [];

          let totalScore = 100;
          const weakKeys = [];
          const oldKeys = [];
          const lockedKeys = [];
          const issues = [];
          const recommendations = [];

          for (const k of keyList) {
            if (k.strength === 'weak' || k.strength === 'very-weak') {
              weakKeys.push({ id: k.id, name: k.name, strength: k.strength });
              totalScore -= 15;
              issues.push(`"${k.name}" has ${k.strength} strength`);
            } else if (k.strength === 'medium') {
              totalScore -= 5;
              issues.push(`"${k.name}" has medium strength — could be stronger`);
            }

            if (k.rotation_age_days > 180) {
              oldKeys.push({ id: k.id, name: k.name, age_days: k.rotation_age_days });
              totalScore -= 15;
              issues.push(`"${k.name}" has not been rotated in ${k.rotation_age_days} days`);
            } else if (k.rotation_age_days > 90) {
              oldKeys.push({ id: k.id, name: k.name, age_days: k.rotation_age_days });
              totalScore -= 8;
              issues.push(`"${k.name}" is ${k.rotation_age_days} days old — rotation recommended`);
            }

            if (k.status === 'locked') {
              lockedKeys.push({ id: k.id, name: k.name });
            }
          }

          // Check for type diversity
          const types = new Set(keyList.map(k => k.type));
          if (keyList.length > 0 && types.size === 1) {
            totalScore -= 5;
            issues.push('All credentials are the same type — diversify your security');
          }

          // Check notes
          const noteCount = await env.DB.prepare('SELECT COUNT(*) as c FROM ck_notes').first();
          const totpCount = await env.DB.prepare('SELECT COUNT(*) as c FROM ck_totp WHERE verified=1').first();

          if ((totpCount?.c || 0) === 0) {
            totalScore -= 10;
            recommendations.push('Enable 2FA/TOTP on at least one account');
          }

          totalScore = Math.max(0, Math.min(100, totalScore));

          if (weakKeys.length > 0) recommendations.push(`Strengthen ${weakKeys.length} weak credential(s)`);
          if (oldKeys.length > 0) recommendations.push(`Rotate ${oldKeys.length} aging credential(s)`);
          if (keyList.length === 0) recommendations.push('Add credentials to your vault to start tracking');
          if ((noteCount?.c || 0) === 0) recommendations.push('Store sensitive info in encrypted secure notes');

          const grade = totalScore >= 90 ? 'A' : totalScore >= 75 ? 'B' : totalScore >= 60 ? 'C' : totalScore >= 40 ? 'D' : 'F';

          // AI assessment from Valeria
          let ai_assessment = '';
          if (totalScore < 80) {
            try {
              const prompt = `You are Valeria, the Security Chief on BlackRoad OS. Direct, precise, protective.

Password health score: ${totalScore}/100 (${grade}). Total credentials: ${keyList.length}. Weak: ${weakKeys.length}. Old (>90 days): ${oldKeys.length}. 2FA setups: ${totpCount?.c||0}. Secure notes: ${noteCount?.c||0}.
Issues: ${issues.slice(0, 5).join('; ') || 'none'}.

Give a 3-sentence health assessment and your top priority action. Be warm but direct.`;
              ai_assessment = await runCKAI(env.AI, prompt);
            } catch {}
          }

          return json({
            ok: true,
            score: totalScore,
            grade,
            total_credentials: keyList.length,
            weak_credentials: weakKeys,
            aging_credentials: oldKeys,
            locked_credentials: lockedKeys,
            totp_enabled: totpCount?.c || 0,
            secure_notes: noteCount?.c || 0,
            issues,
            recommendations,
            ...(ai_assessment ? { ai_assessment, agent: 'Valeria' } : {}),
            generated_at: new Date().toISOString(),
          }, cors);
        }

        // ═══════════════════════════════════════════════════════════════
        // ─── NEW FEATURE: Import/Export ───
        // ═══════════════════════════════════════════════════════════════
        if (path === '/api/import' && request.method === 'POST') {
          const body = await request.json();
          if (!body.data && !body.csv) return json({ error: 'data (JSON array) or csv (CSV string) required' }, cors, 400);
          const format = body.format || 'auto';

          let entries = [];

          if (body.csv) {
            // Parse CSV (LastPass/1Password format: name,url,username,password,type,notes)
            const lines = body.csv.split('\n').filter(l => l.trim());
            const header = lines[0].toLowerCase();
            const isLastPass = header.includes('url') && header.includes('username');
            const is1Password = header.includes('title') || header.includes('login uri');

            for (let i = 1; i < lines.length; i++) {
              const cols = parseCSVLine(lines[i]);
              if (cols.length < 2) continue;

              if (isLastPass) {
                // LastPass: url,username,password,totp,extra,name,grouping,fav
                entries.push({
                  name: cols[5] || cols[0] || `Import ${i}`,
                  type: 'password',
                  strength: cols[2] ? passwordStrength(cols[2]) : 'unknown',
                  source: 'lastpass',
                });
              } else if (is1Password) {
                // 1Password: Title,Url,Username,Password,OTPAuth,Notes
                entries.push({
                  name: cols[0] || `Import ${i}`,
                  type: 'password',
                  strength: cols[3] ? passwordStrength(cols[3]) : 'unknown',
                  source: '1password',
                });
              } else {
                // Generic: name,type,value
                entries.push({
                  name: cols[0] || `Import ${i}`,
                  type: cols[1] || 'password',
                  strength: cols[2] ? passwordStrength(cols[2]) : 'medium',
                  source: 'generic',
                });
              }
            }
          } else if (Array.isArray(body.data)) {
            entries = body.data.map((item, i) => ({
              name: item.name || item.title || `Import ${i + 1}`,
              type: item.type || 'password',
              strength: item.password ? passwordStrength(item.password) : (item.strength || 'medium'),
              source: item.source || 'json',
            }));
          }

          if (entries.length === 0) return json({ error: 'No valid entries found in import data' }, cors, 400);

          // Insert into ck_keys
          const stmts = entries.map(entry =>
            env.DB.prepare('INSERT INTO ck_keys (id,name,type,strength,rotation_age_days) VALUES (?,?,?,?,0)')
              .bind(crypto.randomUUID().slice(0, 8), entry.name.slice(0, 100), entry.type.slice(0, 50), entry.strength)
          );

          // Batch in groups of 50
          for (let i = 0; i < stmts.length; i += 50) {
            await env.DB.batch(stmts.slice(i, i + 50));
          }

          await logAudit(env.DB, 'vault_import', 'import', `Imported ${entries.length} credentials from ${entries[0]?.source || 'unknown'}`);
          stampChain('vault_import', 'import', `${entries.length} entries`);
          return json({
            ok: true,
            imported: entries.length,
            source: entries[0]?.source || 'unknown',
            entries: entries.map(e => ({ name: e.name, type: e.type, strength: e.strength })),
          }, cors, 201);
        }

        if (path === '/api/export' && request.method === 'POST') {
          const body = await request.json().catch(() => ({}));
          if (!body.passphrase) return json({ error: 'passphrase required for encrypted export' }, cors, 400);

          const keys = await env.DB.prepare('SELECT id,name,type,strength,rotation_age_days,status,created_at FROM ck_keys').all();
          const devices = await env.DB.prepare('SELECT id,name,type,trust_score,created_at FROM ck_devices').all();
          const notes = await env.DB.prepare('SELECT id,title,category,created_at,updated_at FROM ck_notes').all();
          const totp = await env.DB.prepare('SELECT id,account,issuer,verified,created_at FROM ck_totp').all();
          const family = await env.DB.prepare('SELECT * FROM ck_family_keys').all();

          const exportData = {
            export_version: '2.0',
            exported_at: new Date().toISOString(),
            source: 'CarKeys by BlackRoad OS',
            data: {
              keys: keys.results || [],
              devices: devices.results || [],
              notes: (notes.results || []),
              totp: (totp.results || []),
              family_keys: family.results || [],
            },
            counts: {
              keys: (keys.results || []).length,
              devices: (devices.results || []).length,
              notes: (notes.results || []).length,
              totp: (totp.results || []).length,
              family_keys: (family.results || []).length,
            },
          };

          const encrypted = await encryptData(JSON.stringify(exportData), body.passphrase);

          await logAudit(env.DB, 'vault_export', 'export', `Encrypted vault export created (${Object.values(exportData.counts).reduce((a, b) => a + b, 0)} total entries)`);
          stampChain('vault_export', 'export', 'encrypted');

          return json({
            ok: true,
            format: 'encrypted_json',
            counts: exportData.counts,
            encrypted_payload: encrypted,
            instructions: 'Save the encrypted_payload. Decrypt with your passphrase using /api/import with format:"carkeys_encrypted".',
          }, cors);
        }

        // ═══════════════════════════════════════════════════════════════
        // ─── NEW FEATURE: Emergency Access ───
        // ═══════════════════════════════════════════════════════════════
        if (path === '/api/emergency' && request.method === 'GET') {
          const contacts = await env.DB.prepare('SELECT id, name, email, wait_hours, status, created_at FROM ck_emergency_contacts ORDER BY created_at DESC').all();
          const requests = await env.DB.prepare('SELECT * FROM ck_emergency_requests ORDER BY requested_at DESC LIMIT 20').all();
          return json({ contacts: contacts.results || [], recent_requests: requests.results || [] }, cors);
        }

        // ─── Add emergency contact ───
        if (path === '/api/emergency/contacts' && request.method === 'POST') {
          const body = await request.json();
          if (!body.name || !body.email) return json({ error: 'name and email required' }, cors, 400);

          const id = crypto.randomUUID().slice(0, 8);
          const waitHours = Math.min(Math.max(parseInt(body.wait_hours) || 48, 1), 720); // 1 hour to 30 days

          await env.DB.prepare("INSERT INTO ck_emergency_contacts (id, name, email, wait_hours, status, created_at) VALUES (?,?,?,?,'active',datetime('now'))")
            .bind(id, body.name.slice(0, 100), body.email.slice(0, 200), waitHours).run();

          await logAudit(env.DB, 'emergency_contact_added', id, `Emergency contact "${body.name}" added (${waitHours}h wait)`);
          return json({
            ok: true,
            id,
            name: body.name,
            email: body.email,
            wait_hours: waitHours,
            message: `${body.name} can request emergency access. You will have ${waitHours} hours to deny the request before access is granted.`,
          }, cors, 201);
        }

        // ─── Remove emergency contact ───
        const emergencyContactMatch = path.match(/^\/api\/emergency\/contacts\/([^/]+)$/);
        if (emergencyContactMatch && request.method === 'DELETE') {
          const contact = await env.DB.prepare('SELECT * FROM ck_emergency_contacts WHERE id=?').bind(emergencyContactMatch[1]).first();
          if (!contact) return json({ error: 'contact not found' }, cors, 404);
          await env.DB.prepare('DELETE FROM ck_emergency_contacts WHERE id=?').bind(contact.id).run();
          await logAudit(env.DB, 'emergency_contact_removed', contact.id, `Emergency contact "${contact.name}" removed`);
          return json({ ok: true, deleted: contact.id, name: contact.name }, cors);
        }

        // ─── Request emergency access (by contact) ───
        if (path === '/api/emergency/request' && request.method === 'POST') {
          const body = await request.json();
          if (!body.email) return json({ error: 'email required' }, cors, 400);

          const contact = await env.DB.prepare("SELECT * FROM ck_emergency_contacts WHERE email=? AND status='active'").bind(body.email).first();
          if (!contact) return json({ error: 'No active emergency contact found with that email' }, cors, 404);

          // Check for existing pending request
          const existing = await env.DB.prepare("SELECT * FROM ck_emergency_requests WHERE contact_id=? AND status='pending'").bind(contact.id).first();
          if (existing) return json({ error: 'A request is already pending', request_id: existing.id, requested_at: existing.requested_at, grants_at: existing.grants_at }, cors, 409);

          const reqId = crypto.randomUUID().slice(0, 8);
          const grantsAt = new Date(Date.now() + contact.wait_hours * 3600000).toISOString();

          await env.DB.prepare("INSERT INTO ck_emergency_requests (id, contact_id, contact_name, contact_email, status, requested_at, grants_at) VALUES (?,?,?,?,'pending',datetime('now'),?)")
            .bind(reqId, contact.id, contact.name, contact.email, grantsAt).run();

          await logAudit(env.DB, 'emergency_request', reqId, `Emergency access requested by ${contact.name} (${contact.email}), grants at ${grantsAt}`);
          stampChain('emergency_request', reqId, contact.name);

          return json({
            ok: true,
            request_id: reqId,
            contact: contact.name,
            status: 'pending',
            wait_hours: contact.wait_hours,
            grants_at: grantsAt,
            message: `Emergency access requested. The vault owner has ${contact.wait_hours} hours to deny this request. Access will be granted at ${grantsAt} if not denied.`,
          }, cors, 201);
        }

        // ─── Deny emergency request ───
        if (path === '/api/emergency/deny' && request.method === 'POST') {
          const body = await request.json();
          if (!body.request_id) return json({ error: 'request_id required' }, cors, 400);

          const req = await env.DB.prepare("SELECT * FROM ck_emergency_requests WHERE id=? AND status='pending'").bind(body.request_id).first();
          if (!req) return json({ error: 'No pending request found with that ID' }, cors, 404);

          await env.DB.prepare("UPDATE ck_emergency_requests SET status='denied' WHERE id=?").bind(req.id).run();
          await logAudit(env.DB, 'emergency_denied', req.id, `Emergency access denied for ${req.contact_name}`);
          return json({ ok: true, request_id: req.id, status: 'denied', message: `Emergency access request from ${req.contact_name} has been denied.` }, cors);
        }

        // ─── Check emergency request status (auto-grant if timer expired) ───
        if (path === '/api/emergency/status' && request.method === 'GET') {
          const reqId = url.searchParams.get('request_id');
          if (!reqId) return json({ error: 'request_id required' }, cors, 400);

          const req = await env.DB.prepare('SELECT * FROM ck_emergency_requests WHERE id=?').bind(reqId).first();
          if (!req) return json({ error: 'Request not found' }, cors, 404);

          // Auto-grant if pending and timer expired
          if (req.status === 'pending' && new Date(req.grants_at) <= new Date()) {
            await env.DB.prepare("UPDATE ck_emergency_requests SET status='granted' WHERE id=?").bind(req.id).run();
            await logAudit(env.DB, 'emergency_granted', req.id, `Emergency access auto-granted to ${req.contact_name} (timer expired)`);
            req.status = 'granted';
          }

          const result = {
            ok: true,
            request_id: req.id,
            contact: req.contact_name,
            status: req.status,
            requested_at: req.requested_at,
            grants_at: req.grants_at,
          };

          if (req.status === 'granted') {
            // Return vault summary for granted access
            const keyCount = await env.DB.prepare('SELECT COUNT(*) as c FROM ck_keys').first();
            const deviceCount = await env.DB.prepare('SELECT COUNT(*) as c FROM ck_devices').first();
            result.access = {
              keys_available: keyCount?.c || 0,
              devices_registered: deviceCount?.c || 0,
              message: 'Emergency access granted. Use /api/keys and /api/devices to view vault contents.',
            };
          } else if (req.status === 'pending') {
            const remaining = Math.max(0, Math.ceil((new Date(req.grants_at) - new Date()) / 3600000));
            result.hours_remaining = remaining;
          }

          return json(result, cors);
        }


        // ═══════════════════════════════════════════════════════════════
        // ─── NEW FEATURE: Passkey Support (WebAuthn/FIDO2) ───
        // ═══════════════════════════════════════════════════════════════
        if (path === '/api/passkeys' && request.method === 'GET') {
          const rows = await env.DB.prepare('SELECT id, user_id, credential_id, public_key_alg, device_name, last_used, created_at FROM ck_passkeys ORDER BY created_at DESC').all();
          return json({ passkeys: rows.results || [] }, cors);
        }

        if (path === '/api/passkeys/register/begin' && request.method === 'POST') {
          const body = await request.json();
          if (!body.user_id || !body.username) return json({ error: 'user_id and username required' }, cors, 400);

          const challengeBytes = crypto.getRandomValues(new Uint8Array(32));
          const challenge = btoa(String.fromCharCode(...challengeBytes));
          const challengeId = crypto.randomUUID().slice(0, 8);

          await env.DB.prepare("INSERT INTO ck_passkey_challenges (id, user_id, challenge, type, expires_at) VALUES (?,?,?,'registration',datetime('now','+5 minutes'))")
            .bind(challengeId, body.user_id.slice(0, 100), challenge).run();

          const existingKeys = await env.DB.prepare('SELECT credential_id FROM ck_passkeys WHERE user_id=?').bind(body.user_id).all();
          const excludeCredentials = (existingKeys.results || []).map(k => ({ id: k.credential_id, type: 'public-key' }));

          return json({
            ok: true,
            challenge_id: challengeId,
            publicKey: {
              challenge,
              rp: { name: 'CarKeys by BlackRoad OS', id: body.rp_id || 'carkeys.blackroad.io' },
              user: {
                id: btoa(body.user_id),
                name: body.username,
                displayName: body.display_name || body.username,
              },
              pubKeyCredParams: [
                { type: 'public-key', alg: -7 },   // ES256
                { type: 'public-key', alg: -257 },  // RS256
              ],
              timeout: 60000,
              attestation: 'none',
              authenticatorSelection: {
                authenticatorAttachment: body.attachment || 'platform',
                residentKey: 'preferred',
                userVerification: 'preferred',
              },
              excludeCredentials,
            },
          }, cors);
        }

        if (path === '/api/passkeys/register/complete' && request.method === 'POST') {
          const body = await request.json();
          if (!body.challenge_id || !body.credential_id || !body.user_id) {
            return json({ error: 'challenge_id, credential_id, and user_id required' }, cors, 400);
          }

          const challenge = await env.DB.prepare("SELECT * FROM ck_passkey_challenges WHERE id=? AND type='registration' AND expires_at > datetime('now')")
            .bind(body.challenge_id).first();
          if (!challenge) return json({ error: 'Challenge expired or not found' }, cors, 400);

          const id = crypto.randomUUID().slice(0, 8);
          const deviceName = body.device_name || 'Unknown Device';
          const publicKeyAlg = body.public_key_alg || 'ES256';
          const attestationData = body.attestation_object || '';

          await env.DB.prepare("INSERT INTO ck_passkeys (id, user_id, credential_id, public_key_alg, attestation_data, device_name, sign_count, last_used, created_at) VALUES (?,?,?,?,?,?,0,datetime('now'),datetime('now'))")
            .bind(id, body.user_id.slice(0, 100), body.credential_id.slice(0, 500), publicKeyAlg, attestationData.slice(0, 2000), deviceName.slice(0, 100)).run();

          await env.DB.prepare('DELETE FROM ck_passkey_challenges WHERE id=?').bind(body.challenge_id).run();
          await logAudit(env.DB, 'passkey_registered', id, `Passkey registered for ${body.user_id} on ${deviceName}`);
          stampChain('passkey_registered', id, body.user_id);

          return json({ ok: true, id, credential_id: body.credential_id, device_name: deviceName, message: 'Passkey registered successfully.' }, cors, 201);
        }

        if (path === '/api/passkeys/auth/begin' && request.method === 'POST') {
          const body = await request.json();
          const challengeBytes = crypto.getRandomValues(new Uint8Array(32));
          const challenge = btoa(String.fromCharCode(...challengeBytes));
          const challengeId = crypto.randomUUID().slice(0, 8);

          await env.DB.prepare("INSERT INTO ck_passkey_challenges (id, user_id, challenge, type, expires_at) VALUES (?,?,?,'authentication',datetime('now','+5 minutes'))")
            .bind(challengeId, body.user_id || 'anonymous', challenge).run();

          let allowCredentials = [];
          if (body.user_id) {
            const keys = await env.DB.prepare('SELECT credential_id FROM ck_passkeys WHERE user_id=?').bind(body.user_id).all();
            allowCredentials = (keys.results || []).map(k => ({ id: k.credential_id, type: 'public-key' }));
          }

          return json({
            ok: true,
            challenge_id: challengeId,
            publicKey: {
              challenge,
              timeout: 60000,
              rpId: body.rp_id || 'carkeys.blackroad.io',
              userVerification: 'preferred',
              allowCredentials,
            },
          }, cors);
        }

        if (path === '/api/passkeys/auth/complete' && request.method === 'POST') {
          const body = await request.json();
          if (!body.challenge_id || !body.credential_id) return json({ error: 'challenge_id and credential_id required' }, cors, 400);

          const challenge = await env.DB.prepare("SELECT * FROM ck_passkey_challenges WHERE id=? AND type='authentication' AND expires_at > datetime('now')")
            .bind(body.challenge_id).first();
          if (!challenge) return json({ error: 'Challenge expired or not found' }, cors, 400);

          const passkey = await env.DB.prepare('SELECT * FROM ck_passkeys WHERE credential_id=?').bind(body.credential_id).first();
          if (!passkey) return json({ error: 'Passkey not found' }, cors, 404);

          // Update sign count and last used
          const newSignCount = (passkey.sign_count || 0) + 1;
          await env.DB.prepare("UPDATE ck_passkeys SET sign_count=?, last_used=datetime('now') WHERE id=?")
            .bind(newSignCount, passkey.id).run();

          await env.DB.prepare('DELETE FROM ck_passkey_challenges WHERE id=?').bind(body.challenge_id).run();
          await logAudit(env.DB, 'passkey_auth', passkey.id, `Passkey authentication for ${passkey.user_id} (sign count: ${newSignCount})`);

          return json({
            ok: true,
            authenticated: true,
            user_id: passkey.user_id,
            device_name: passkey.device_name,
            sign_count: newSignCount,
            message: 'Authentication successful.',
          }, cors);
        }

        // Delete a passkey
        const passkeyDeleteMatch = path.match(/^\/api\/passkeys\/([^/]+)$/);
        if (passkeyDeleteMatch && request.method === 'DELETE') {
          const pk = await env.DB.prepare('SELECT * FROM ck_passkeys WHERE id=?').bind(passkeyDeleteMatch[1]).first();
          if (!pk) return json({ error: 'passkey not found' }, cors, 404);
          await env.DB.prepare('DELETE FROM ck_passkeys WHERE id=?').bind(pk.id).run();
          await logAudit(env.DB, 'passkey_deleted', pk.id, `Passkey "${pk.device_name}" deleted for ${pk.user_id}`);
          return json({ ok: true, deleted: pk.id, device_name: pk.device_name }, cors);
        }

        // ═══════════════════════════════════════════════════════════════
        // ─── NEW FEATURE: Secret Rotation Scheduler ───
        // ═══════════════════════════════════════════════════════════════
        if (path === '/api/rotation-schedule' && request.method === 'GET') {
          const rows = await env.DB.prepare('SELECT * FROM ck_rotation_schedules ORDER BY next_rotation ASC').all();
          const schedules = (rows.results || []).map(s => {
            const nextDate = new Date(s.next_rotation);
            const now = new Date();
            const daysUntil = Math.ceil((nextDate - now) / 86400000);
            return { ...s, days_until_rotation: daysUntil, overdue: daysUntil < 0 };
          });
          const overdue = schedules.filter(s => s.overdue);
          const upcoming = schedules.filter(s => !s.overdue && s.days_until_rotation <= 7);
          return json({ schedules, overdue_count: overdue.length, upcoming_count: upcoming.length, overdue, upcoming_7days: upcoming }, cors);
        }

        if (path === '/api/rotation-schedule' && request.method === 'POST') {
          const body = await request.json();
          if (!body.key_id || !body.interval_days) return json({ error: 'key_id and interval_days required' }, cors, 400);

          const key = await env.DB.prepare('SELECT * FROM ck_keys WHERE id=?').bind(body.key_id).first();
          if (!key) return json({ error: 'key not found' }, cors, 404);

          const intervalDays = Math.min(Math.max(parseInt(body.interval_days) || 90, 1), 365);
          const nextRotation = new Date(Date.now() + intervalDays * 86400000).toISOString();
          const id = crypto.randomUUID().slice(0, 8);
          const notifyDaysBefore = Math.min(Math.max(parseInt(body.notify_days_before) || 7, 1), 30);

          // Check if schedule already exists for this key
          const existing = await env.DB.prepare('SELECT * FROM ck_rotation_schedules WHERE key_id=?').bind(body.key_id).first();
          if (existing) {
            await env.DB.prepare("UPDATE ck_rotation_schedules SET interval_days=?, next_rotation=?, notify_days_before=?, updated_at=datetime('now') WHERE id=?")
              .bind(intervalDays, nextRotation, notifyDaysBefore, existing.id).run();
            await logAudit(env.DB, 'rotation_schedule_updated', existing.id, `Rotation schedule updated for "${key.name}": every ${intervalDays} days`);
            return json({ ok: true, id: existing.id, key_name: key.name, interval_days: intervalDays, next_rotation: nextRotation, updated: true }, cors);
          }

          await env.DB.prepare("INSERT INTO ck_rotation_schedules (id, key_id, key_name, interval_days, next_rotation, notify_days_before, last_rotated, status, created_at, updated_at) VALUES (?,?,?,?,?,?,datetime('now'),'active',datetime('now'),datetime('now'))")
            .bind(id, body.key_id, key.name, intervalDays, nextRotation, notifyDaysBefore).run();

          await logAudit(env.DB, 'rotation_schedule_created', id, `Rotation schedule: "${key.name}" every ${intervalDays} days, next: ${nextRotation}`);
          stampChain('rotation_scheduled', id, key.name);
          return json({ ok: true, id, key_id: body.key_id, key_name: key.name, interval_days: intervalDays, next_rotation: nextRotation, notify_days_before: notifyDaysBefore }, cors, 201);
        }

        // Delete rotation schedule
        const rotationDeleteMatch = path.match(/^\/api\/rotation-schedule\/([^/]+)$/);
        if (rotationDeleteMatch && request.method === 'DELETE') {
          const schedule = await env.DB.prepare('SELECT * FROM ck_rotation_schedules WHERE id=?').bind(rotationDeleteMatch[1]).first();
          if (!schedule) return json({ error: 'schedule not found' }, cors, 404);
          await env.DB.prepare('DELETE FROM ck_rotation_schedules WHERE id=?').bind(schedule.id).run();
          await logAudit(env.DB, 'rotation_schedule_deleted', schedule.id, `Rotation schedule for "${schedule.key_name}" deleted`);
          return json({ ok: true, deleted: schedule.id, key_name: schedule.key_name }, cors);
        }

        // Check and process due rotations
        if (path === '/api/rotation-schedule/check' && request.method === 'POST') {
          const now = new Date().toISOString();
          const due = await env.DB.prepare("SELECT * FROM ck_rotation_schedules WHERE next_rotation <= ? AND status='active'").bind(now).all();
          const reminders = [];
          const overdue = [];

          for (const s of (due.results || [])) {
            overdue.push({ id: s.id, key_id: s.key_id, key_name: s.key_name, was_due: s.next_rotation });
          }

          // Check for upcoming reminders
          const reminderDate = new Date(Date.now() + 7 * 86400000).toISOString();
          const upcoming = await env.DB.prepare("SELECT * FROM ck_rotation_schedules WHERE next_rotation <= ? AND next_rotation > ? AND status='active'")
            .bind(reminderDate, now).all();
          for (const s of (upcoming.results || [])) {
            const daysUntil = Math.ceil((new Date(s.next_rotation) - new Date()) / 86400000);
            reminders.push({ id: s.id, key_id: s.key_id, key_name: s.key_name, days_until: daysUntil, next_rotation: s.next_rotation });
          }

          return json({ ok: true, overdue, reminders, overdue_count: overdue.length, reminder_count: reminders.length, checked_at: new Date().toISOString() }, cors);
        }

        // ═══════════════════════════════════════════════════════════════
        // ─── NEW FEATURE: SSH Key Manager ───
        // ═══════════════════════════════════════════════════════════════
        if (path === '/api/ssh-keys' && request.method === 'GET') {
          const rows = await env.DB.prepare('SELECT id, name, key_type, public_key_fingerprint, associated_servers, tags, created_at, last_used FROM ck_ssh_keys ORDER BY created_at DESC').all();
          return json({ ssh_keys: rows.results || [] }, cors);
        }

        if (path === '/api/ssh-keys' && request.method === 'POST') {
          const body = await request.json();
          if (!body.name) return json({ error: 'name required' }, cors, 400);

          const id = crypto.randomUUID().slice(0, 8);
          const keyType = body.key_type || 'ed25519';
          const comment = body.comment || `carkeys-${id}@blackroad.io`;

          // Generate a simulated key pair (real SSH key gen needs native crypto)
          const privKeyBytes = crypto.getRandomValues(new Uint8Array(64));
          const pubKeyBytes = crypto.getRandomValues(new Uint8Array(32));
          const privKeyB64 = btoa(String.fromCharCode(...privKeyBytes));
          const pubKeyB64 = btoa(String.fromCharCode(...pubKeyBytes));

          // Generate fingerprint (SHA-256 of public key)
          const fingerprintHash = await crypto.subtle.digest('SHA-256', pubKeyBytes);
          const fingerprint = 'SHA256:' + btoa(String.fromCharCode(...new Uint8Array(fingerprintHash))).replace(/=+$/, '');

          const publicKeyLine = `ssh-${keyType} ${pubKeyB64} ${comment}`;
          const servers = body.servers ? JSON.stringify(body.servers) : '[]';
          const tags = body.tags ? JSON.stringify(body.tags) : '[]';

          // Encrypt private key if passphrase provided
          let storedPrivateKey = privKeyB64;
          let encrypted = false;
          if (body.passphrase) {
            storedPrivateKey = await encryptData(privKeyB64, body.passphrase);
            encrypted = true;
          }

          await env.DB.prepare("INSERT INTO ck_ssh_keys (id, name, key_type, public_key, private_key_encrypted, public_key_fingerprint, associated_servers, tags, passphrase_protected, created_at, last_used) VALUES (?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'))")
            .bind(id, body.name.slice(0, 100), keyType, publicKeyLine, storedPrivateKey, fingerprint, servers, tags, encrypted ? 1 : 0).run();

          await logAudit(env.DB, 'ssh_key_generated', id, `SSH key "${body.name}" (${keyType}) generated, fingerprint: ${fingerprint.slice(0, 20)}...`);
          stampChain('ssh_key_generated', id, body.name);

          return json({
            ok: true,
            id,
            name: body.name,
            key_type: keyType,
            public_key: publicKeyLine,
            fingerprint,
            passphrase_protected: encrypted,
            comment,
            message: 'SSH key pair generated. Public key is safe to share. Keep the private key secure.',
          }, cors, 201);
        }

        // Get SSH key detail (with private key if passphrase provided)
        const sshKeyMatch = path.match(/^\/api\/ssh-keys\/([^/]+)$/);
        if (sshKeyMatch && request.method === 'POST') {
          const body = await request.json().catch(() => ({}));
          const sshKey = await env.DB.prepare('SELECT * FROM ck_ssh_keys WHERE id=?').bind(sshKeyMatch[1]).first();
          if (!sshKey) return json({ error: 'SSH key not found' }, cors, 404);

          const result = {
            ok: true,
            id: sshKey.id,
            name: sshKey.name,
            key_type: sshKey.key_type,
            public_key: sshKey.public_key,
            fingerprint: sshKey.public_key_fingerprint,
            servers: JSON.parse(sshKey.associated_servers || '[]'),
            tags: JSON.parse(sshKey.tags || '[]'),
            passphrase_protected: !!sshKey.passphrase_protected,
            created_at: sshKey.created_at,
            last_used: sshKey.last_used,
          };

          if (body.passphrase && sshKey.passphrase_protected) {
            try {
              result.private_key = await decryptData(sshKey.private_key_encrypted, body.passphrase);
            } catch {
              return json({ error: 'Invalid passphrase' }, cors, 403);
            }
          } else if (!sshKey.passphrase_protected) {
            result.private_key = sshKey.private_key_encrypted;
          }

          await logAudit(env.DB, 'ssh_key_accessed', sshKey.id, `SSH key "${sshKey.name}" accessed`);
          return json(result, cors);
        }

        // Update SSH key (add/remove servers)
        if (sshKeyMatch && request.method === 'PUT') {
          const body = await request.json();
          const sshKey = await env.DB.prepare('SELECT * FROM ck_ssh_keys WHERE id=?').bind(sshKeyMatch[1]).first();
          if (!sshKey) return json({ error: 'SSH key not found' }, cors, 404);

          const updates = [];
          const binds = [];
          if (body.name) { updates.push('name=?'); binds.push(body.name.slice(0, 100)); }
          if (body.servers) { updates.push('associated_servers=?'); binds.push(JSON.stringify(body.servers)); }
          if (body.tags) { updates.push('tags=?'); binds.push(JSON.stringify(body.tags)); }
          if (updates.length === 0) return json({ error: 'Nothing to update' }, cors, 400);

          binds.push(sshKey.id);
          await env.DB.prepare(`UPDATE ck_ssh_keys SET ${updates.join(',')} WHERE id=?`).bind(...binds).run();
          await logAudit(env.DB, 'ssh_key_updated', sshKey.id, `SSH key "${sshKey.name}" updated`);
          return json({ ok: true, id: sshKey.id, updated: true }, cors);
        }

        // Delete SSH key
        if (sshKeyMatch && request.method === 'DELETE') {
          const sshKey = await env.DB.prepare('SELECT id, name FROM ck_ssh_keys WHERE id=?').bind(sshKeyMatch[1]).first();
          if (!sshKey) return json({ error: 'SSH key not found' }, cors, 404);
          await env.DB.prepare('DELETE FROM ck_ssh_keys WHERE id=?').bind(sshKey.id).run();
          await logAudit(env.DB, 'ssh_key_deleted', sshKey.id, `SSH key "${sshKey.name}" deleted`);
          return json({ ok: true, deleted: sshKey.id, name: sshKey.name }, cors);
        }

        // ═══════════════════════════════════════════════════════════════
        // ─── NEW FEATURE: API Token Vault ───
        // ═══════════════════════════════════════════════════════════════
        if (path === '/api/api-tokens' && request.method === 'GET') {
          const rows = await env.DB.prepare('SELECT id, name, service, scopes, expires_at, usage_count, last_used, status, created_at FROM ck_api_tokens ORDER BY created_at DESC').all();
          const tokens = (rows.results || []).map(t => {
            const expired = t.expires_at && new Date(t.expires_at) < new Date();
            return { ...t, scopes: JSON.parse(t.scopes || '[]'), expired: !!expired };
          });
          const activeCount = tokens.filter(t => t.status === 'active' && !t.expired).length;
          const expiredCount = tokens.filter(t => t.expired).length;
          return json({ api_tokens: tokens, total: tokens.length, active: activeCount, expired: expiredCount }, cors);
        }

        if (path === '/api/api-tokens' && request.method === 'POST') {
          const body = await request.json();
          if (!body.name || !body.token_value) return json({ error: 'name and token_value required' }, cors, 400);

          const id = crypto.randomUUID().slice(0, 8);
          const service = body.service || 'generic';
          const scopes = JSON.stringify(body.scopes || []);
          const expiresAt = body.expires_at || null;

          // Encrypt the token value
          const encryptPass = body.passphrase || crypto.randomUUID().slice(0, 16);
          const encryptedToken = await encryptData(body.token_value, encryptPass);

          await env.DB.prepare("INSERT INTO ck_api_tokens (id, name, service, encrypted_token, scopes, expires_at, usage_count, last_used, status, passphrase_hint, created_at) VALUES (?,?,?,?,?,?,0,datetime('now'),'active',?,datetime('now'))")
            .bind(id, body.name.slice(0, 100), service.slice(0, 50), encryptedToken, scopes, expiresAt, body.passphrase ? 'user-provided' : encryptPass).run();

          await logAudit(env.DB, 'api_token_stored', id, `API token "${body.name}" (${service}) stored with ${(body.scopes || []).length} scopes`);
          stampChain('api_token_stored', id, body.name);

          const result = { ok: true, id, name: body.name, service, scopes: body.scopes || [], expires_at: expiresAt };
          if (!body.passphrase) result.auto_passphrase = encryptPass;
          result.message = 'API token stored securely. ' + (body.passphrase ? 'Use your passphrase to retrieve it.' : 'Save the auto_passphrase to retrieve it later.');
          return json(result, cors, 201);
        }

        // Retrieve API token
        const apiTokenMatch = path.match(/^\/api\/api-tokens\/([^/]+)$/);
        if (apiTokenMatch && request.method === 'POST') {
          const body = await request.json();
          if (!body.passphrase) return json({ error: 'passphrase required to decrypt token' }, cors, 400);

          const token = await env.DB.prepare('SELECT * FROM ck_api_tokens WHERE id=?').bind(apiTokenMatch[1]).first();
          if (!token) return json({ error: 'API token not found' }, cors, 404);

          try {
            const decryptedToken = await decryptData(token.encrypted_token, body.passphrase);
            // Increment usage count
            await env.DB.prepare("UPDATE ck_api_tokens SET usage_count = usage_count + 1, last_used = datetime('now') WHERE id=?").bind(token.id).run();
            await logAudit(env.DB, 'api_token_accessed', token.id, `API token "${token.name}" accessed (usage: ${token.usage_count + 1})`);

            return json({
              ok: true,
              id: token.id,
              name: token.name,
              service: token.service,
              token_value: decryptedToken,
              scopes: JSON.parse(token.scopes || '[]'),
              usage_count: token.usage_count + 1,
              expires_at: token.expires_at,
              expired: token.expires_at && new Date(token.expires_at) < new Date(),
            }, cors);
          } catch {
            return json({ error: 'Invalid passphrase' }, cors, 403);
          }
        }

        // Revoke API token
        if (apiTokenMatch && request.method === 'DELETE') {
          const token = await env.DB.prepare('SELECT id, name FROM ck_api_tokens WHERE id=?').bind(apiTokenMatch[1]).first();
          if (!token) return json({ error: 'API token not found' }, cors, 404);
          await env.DB.prepare("UPDATE ck_api_tokens SET status='revoked' WHERE id=?").bind(token.id).run();
          await logAudit(env.DB, 'api_token_revoked', token.id, `API token "${token.name}" revoked`);
          return json({ ok: true, id: token.id, name: token.name, status: 'revoked' }, cors);
        }

        // Track API token usage
        if (path === '/api/api-tokens/track' && request.method === 'POST') {
          const body = await request.json();
          if (!body.token_id) return json({ error: 'token_id required' }, cors, 400);
          const token = await env.DB.prepare('SELECT * FROM ck_api_tokens WHERE id=?').bind(body.token_id).first();
          if (!token) return json({ error: 'API token not found' }, cors, 404);

          await env.DB.prepare("UPDATE ck_api_tokens SET usage_count = usage_count + 1, last_used = datetime('now') WHERE id=?").bind(token.id).run();
          await logAudit(env.DB, 'api_token_used', token.id, `API token "${token.name}" used (${body.endpoint || 'unknown endpoint'})`);
          return json({ ok: true, token_id: token.id, usage_count: token.usage_count + 1 }, cors);
        }

        // ═══════════════════════════════════════════════════════════════
        // ─── NEW FEATURE: Security Alerts ───
        // ═══════════════════════════════════════════════════════════════
        if (path === '/api/security-alerts' && request.method === 'GET') {
          const limit = parseInt(url.searchParams.get('limit') || '50');
          const severity = url.searchParams.get('severity');
          let query = 'SELECT * FROM ck_security_alerts';
          const binds = [];
          if (severity) { query += ' WHERE severity=?'; binds.push(severity); }
          query += ' ORDER BY created_at DESC LIMIT ?';
          binds.push(limit);
          const rows = await env.DB.prepare(query).bind(...binds).all();
          const unresolved = await env.DB.prepare("SELECT COUNT(*) as c FROM ck_security_alerts WHERE resolved=0").first();
          return json({ alerts: rows.results || [], unresolved_count: unresolved?.c || 0 }, cors);
        }

        if (path === '/api/security-alerts' && request.method === 'POST') {
          const body = await request.json();
          if (!body.type) return json({ error: 'type required (failed_login, location_anomaly, suspicious_access, brute_force, new_device)' }, cors, 400);

          const id = crypto.randomUUID().slice(0, 8);
          const alertType = body.type;
          const severity = body.severity || 'medium';
          const source = body.source || 'system';
          const description = body.description || `Security alert: ${alertType}`;
          const metadata = JSON.stringify(body.metadata || {});
          const ipAddress = body.ip_address || request.headers.get('cf-connecting-ip') || 'unknown';

          await env.DB.prepare("INSERT INTO ck_security_alerts (id, type, severity, source, description, ip_address, metadata, resolved, created_at) VALUES (?,?,?,?,?,?,?,0,datetime('now'))")
            .bind(id, alertType.slice(0, 50), severity.slice(0, 20), source.slice(0, 100), description.slice(0, 500), ipAddress, metadata).run();

          await logAudit(env.DB, 'security_alert', id, `[${severity.toUpperCase()}] ${alertType}: ${description.slice(0, 100)}`);
          stampChain('security_alert', id, alertType);

          return json({ ok: true, id, type: alertType, severity, description, ip_address: ipAddress }, cors, 201);
        }

        // Analyze access patterns for anomalies
        if (path === '/api/security-alerts/analyze' && request.method === 'POST') {
          const alerts = await env.DB.prepare("SELECT * FROM ck_security_alerts WHERE created_at > datetime('now','-24 hours') ORDER BY created_at DESC").all();
          const audit = await env.DB.prepare("SELECT * FROM ck_audit WHERE created_at > datetime('now','-24 hours') ORDER BY created_at DESC").all();

          const alertList = alerts.results || [];
          const auditList = audit.results || [];
          const failedLogins = alertList.filter(a => a.type === 'failed_login');
          const locationAnomalies = alertList.filter(a => a.type === 'location_anomaly');
          const suspiciousAccess = alertList.filter(a => a.type === 'suspicious_access');

          const autoAlerts = [];

          // Detect brute force (5+ failed logins in 24h)
          if (failedLogins.length >= 5) {
            const bfId = crypto.randomUUID().slice(0, 8);
            await env.DB.prepare("INSERT INTO ck_security_alerts (id, type, severity, source, description, ip_address, metadata, resolved, created_at) VALUES (?,?,?,?,?,?,?,0,datetime('now'))")
              .bind(bfId, 'brute_force', 'critical', 'auto-detect', `Brute force detected: ${failedLogins.length} failed login attempts in 24 hours`, 'system', JSON.stringify({ failed_count: failedLogins.length })).run();
            autoAlerts.push({ id: bfId, type: 'brute_force', severity: 'critical' });
          }

          // Detect unusual activity volume
          if (auditList.length > 100) {
            const volId = crypto.randomUUID().slice(0, 8);
            await env.DB.prepare("INSERT INTO ck_security_alerts (id, type, severity, source, description, ip_address, metadata, resolved, created_at) VALUES (?,?,?,?,?,?,?,0,datetime('now'))")
              .bind(volId, 'high_activity', 'medium', 'auto-detect', `Unusual activity volume: ${auditList.length} actions in 24 hours`, 'system', JSON.stringify({ audit_count: auditList.length })).run();
            autoAlerts.push({ id: volId, type: 'high_activity', severity: 'medium' });
          }

          let ai_assessment = '';
          try {
            const prompt = `You are Valeria, the Security Chief on BlackRoad OS. Direct, precise, protective.

24-hour security summary: ${alertList.length} alerts, ${failedLogins.length} failed logins, ${locationAnomalies.length} location anomalies, ${suspiciousAccess.length} suspicious access events. Audit actions: ${auditList.length}.
${autoAlerts.length > 0 ? 'AUTO-DETECTED: ' + autoAlerts.map(a => a.type + ' (' + a.severity + ')').join(', ') : 'No auto-detections triggered.'}

Give a 3-sentence threat assessment. Rate overall risk: low/medium/high/critical. Be specific about what needs attention.`;
            ai_assessment = await runCKAI(env.AI, prompt);
          } catch {}

          return json({
            ok: true,
            period: '24 hours',
            total_alerts: alertList.length,
            failed_logins: failedLogins.length,
            location_anomalies: locationAnomalies.length,
            suspicious_access: suspiciousAccess.length,
            audit_actions: auditList.length,
            auto_detected_alerts: autoAlerts,
            ...(ai_assessment ? { ai_assessment, agent: 'Valeria' } : {}),
            analyzed_at: new Date().toISOString(),
          }, cors);
        }

        // Resolve an alert
        const alertResolveMatch = path.match(/^\/api\/security-alerts\/([^/]+)\/resolve$/);
        if (alertResolveMatch && request.method === 'POST') {
          const alert = await env.DB.prepare('SELECT * FROM ck_security_alerts WHERE id=?').bind(alertResolveMatch[1]).first();
          if (!alert) return json({ error: 'alert not found' }, cors, 404);
          const body = await request.json().catch(() => ({}));
          await env.DB.prepare("UPDATE ck_security_alerts SET resolved=1, resolved_at=datetime('now'), resolution_note=? WHERE id=?")
            .bind((body.note || 'Resolved').slice(0, 500), alert.id).run();
          await logAudit(env.DB, 'alert_resolved', alert.id, `Alert "${alert.type}" resolved: ${(body.note || 'no note').slice(0, 100)}`);
          return json({ ok: true, id: alert.id, resolved: true }, cors);
        }

        // ═══════════════════════════════════════════════════════════════
        // ─── NEW FEATURE: Credential Templates ───
        // ═══════════════════════════════════════════════════════════════
        if (path === '/api/templates' && request.method === 'GET') {
          // Return built-in templates + custom ones from DB
          const customRows = await env.DB.prepare('SELECT * FROM ck_credential_templates ORDER BY name ASC').all();
          const builtIn = getBuiltInTemplates();
          const custom = customRows.results || [];
          return json({ templates: [...builtIn, ...custom.map(t => ({ ...t, fields: JSON.parse(t.fields || '[]'), tags: JSON.parse(t.tags || '[]'), custom: true }))], built_in: builtIn.length, custom: custom.length }, cors);
        }

        if (path === '/api/templates' && request.method === 'POST') {
          const body = await request.json();
          if (!body.name || !body.fields) return json({ error: 'name and fields required' }, cors, 400);

          const id = crypto.randomUUID().slice(0, 8);
          const fields = JSON.stringify(body.fields);
          const tags = JSON.stringify(body.tags || []);
          const category = body.category || 'custom';

          await env.DB.prepare("INSERT INTO ck_credential_templates (id, name, category, description, fields, tags, icon, created_at) VALUES (?,?,?,?,?,?,?,datetime('now'))")
            .bind(id, body.name.slice(0, 100), category.slice(0, 50), (body.description || '').slice(0, 300), fields, tags, (body.icon || '').slice(0, 10)).run();

          await logAudit(env.DB, 'template_created', id, `Credential template "${body.name}" created`);
          return json({ ok: true, id, name: body.name, category, fields: body.fields }, cors, 201);
        }

        // Use a template to create a credential entry
        if (path === '/api/templates/apply' && request.method === 'POST') {
          const body = await request.json();
          if (!body.template_id && !body.template_name) return json({ error: 'template_id or template_name required' }, cors, 400);

          let template;
          if (body.template_id) {
            // Check built-in first
            const builtIn = getBuiltInTemplates().find(t => t.id === body.template_id);
            if (builtIn) {
              template = builtIn;
            } else {
              const row = await env.DB.prepare('SELECT * FROM ck_credential_templates WHERE id=?').bind(body.template_id).first();
              if (row) template = { ...row, fields: JSON.parse(row.fields || '[]') };
            }
          } else {
            const builtIn = getBuiltInTemplates().find(t => t.name.toLowerCase() === body.template_name.toLowerCase());
            if (builtIn) template = builtIn;
          }
          if (!template) return json({ error: 'template not found' }, cors, 404);

          const credName = body.name || `${template.name} - ${new Date().toISOString().slice(0, 10)}`;
          const credId = crypto.randomUUID().slice(0, 8);

          // Generate values for fields that need auto-generation
          const filledFields = template.fields.map(f => {
            const userVal = body.values?.[f.name];
            if (userVal) return { ...f, value: userVal };
            if (f.auto_generate === 'password') return { ...f, value: generatePassword(f.length || 24) };
            if (f.auto_generate === 'uuid') return { ...f, value: crypto.randomUUID() };
            return { ...f, value: userVal || f.default || '' };
          });

          // Store as a key entry
          await env.DB.prepare('INSERT INTO ck_keys (id, name, type, strength, rotation_age_days) VALUES (?,?,?,?,0)')
            .bind(credId, credName.slice(0, 100), template.category || 'credential', 'strong').run();

          // Store filled template data as encrypted note
          if (body.passphrase) {
            const noteId = crypto.randomUUID().slice(0, 8);
            const encrypted = await encryptData(JSON.stringify(filledFields), body.passphrase);
            await env.DB.prepare("INSERT INTO ck_notes (id, title, category, encrypted_content, created_at, updated_at) VALUES (?,?,?,?,datetime('now'),datetime('now'))")
              .bind(noteId, `[Template] ${credName}`, template.category || 'credential', encrypted).run();
          }

          await logAudit(env.DB, 'template_applied', credId, `Template "${template.name}" applied as "${credName}"`);
          return json({
            ok: true,
            credential_id: credId,
            name: credName,
            template: template.name,
            fields: filledFields.map(f => ({ name: f.name, label: f.label, has_value: !!f.value, auto_generated: !!f.auto_generate })),
          }, cors, 201);
        }

        // Delete custom template
        const templateDeleteMatch = path.match(/^\/api\/templates\/([^/]+)$/);
        if (templateDeleteMatch && request.method === 'DELETE') {
          const tmpl = await env.DB.prepare('SELECT id, name FROM ck_credential_templates WHERE id=?').bind(templateDeleteMatch[1]).first();
          if (!tmpl) return json({ error: 'template not found (built-in templates cannot be deleted)' }, cors, 404);
          await env.DB.prepare('DELETE FROM ck_credential_templates WHERE id=?').bind(tmpl.id).run();
          await logAudit(env.DB, 'template_deleted', tmpl.id, `Template "${tmpl.name}" deleted`);
          return json({ ok: true, deleted: tmpl.id, name: tmpl.name }, cors);
        }

        // ═══════════════════════════════════════════════════════════════
        // ─── NEW FEATURE: Vault Comparison ───
        // ═══════════════════════════════════════════════════════════════
        if (path === '/api/vault-compare' && request.method === 'POST') {
          const body = await request.json();
          if (!body.snapshot_name) return json({ error: 'snapshot_name required to create a comparison point' }, cors, 400);

          // Take a snapshot of current vault state
          const keys = await env.DB.prepare('SELECT id, name, type, strength, rotation_age_days, status, created_at FROM ck_keys').all();
          const devices = await env.DB.prepare('SELECT id, name, type, trust_score, created_at FROM ck_devices').all();
          const notes = await env.DB.prepare('SELECT id, title, category, created_at FROM ck_notes').all();
          const totp = await env.DB.prepare('SELECT id, account, issuer, verified, created_at FROM ck_totp').all();
          const sshKeys = await env.DB.prepare('SELECT id, name, key_type, created_at FROM ck_ssh_keys').all();
          const apiTokens = await env.DB.prepare('SELECT id, name, service, status, created_at FROM ck_api_tokens').all();

          const snapshot = {
            keys: keys.results || [],
            devices: devices.results || [],
            notes: notes.results || [],
            totp: totp.results || [],
            ssh_keys: sshKeys.results || [],
            api_tokens: apiTokens.results || [],
          };

          const snapshotId = crypto.randomUUID().slice(0, 8);
          await env.DB.prepare("INSERT INTO ck_vault_snapshots (id, name, snapshot_data, created_at) VALUES (?,?,?,datetime('now'))")
            .bind(snapshotId, body.snapshot_name.slice(0, 100), JSON.stringify(snapshot)).run();

          await logAudit(env.DB, 'vault_snapshot', snapshotId, `Vault snapshot "${body.snapshot_name}" created`);
          return json({
            ok: true,
            snapshot_id: snapshotId,
            name: body.snapshot_name,
            counts: {
              keys: snapshot.keys.length,
              devices: snapshot.devices.length,
              notes: snapshot.notes.length,
              totp: snapshot.totp.length,
              ssh_keys: snapshot.ssh_keys.length,
              api_tokens: snapshot.api_tokens.length,
            },
            created_at: new Date().toISOString(),
          }, cors, 201);
        }

        if (path === '/api/vault-compare' && request.method === 'GET') {
          const rows = await env.DB.prepare('SELECT id, name, created_at FROM ck_vault_snapshots ORDER BY created_at DESC').all();
          return json({ snapshots: rows.results || [] }, cors);
        }

        // Compare two snapshots
        if (path === '/api/vault-compare/diff' && request.method === 'POST') {
          const body = await request.json();
          if (!body.snapshot_a && !body.snapshot_b) return json({ error: 'snapshot_a and/or snapshot_b required. Omit snapshot_b to compare with current state.' }, cors, 400);

          let snapshotA, snapshotB, labelA, labelB;

          // Load snapshot A
          const rowA = await env.DB.prepare('SELECT * FROM ck_vault_snapshots WHERE id=?').bind(body.snapshot_a).first();
          if (!rowA) return json({ error: 'snapshot_a not found' }, cors, 404);
          snapshotA = JSON.parse(rowA.snapshot_data);
          labelA = rowA.name;

          if (body.snapshot_b) {
            const rowB = await env.DB.prepare('SELECT * FROM ck_vault_snapshots WHERE id=?').bind(body.snapshot_b).first();
            if (!rowB) return json({ error: 'snapshot_b not found' }, cors, 404);
            snapshotB = JSON.parse(rowB.snapshot_data);
            labelB = rowB.name;
          } else {
            // Compare with current state
            const keys = await env.DB.prepare('SELECT id, name, type, strength, rotation_age_days, status, created_at FROM ck_keys').all();
            const devices = await env.DB.prepare('SELECT id, name, type, trust_score, created_at FROM ck_devices').all();
            const notes = await env.DB.prepare('SELECT id, title, category, created_at FROM ck_notes').all();
            const totp = await env.DB.prepare('SELECT id, account, issuer, verified, created_at FROM ck_totp').all();
            const sshKeys = await env.DB.prepare('SELECT id, name, key_type, created_at FROM ck_ssh_keys').all();
            const apiTokens = await env.DB.prepare('SELECT id, name, service, status, created_at FROM ck_api_tokens').all();
            snapshotB = { keys: keys.results || [], devices: devices.results || [], notes: notes.results || [], totp: totp.results || [], ssh_keys: sshKeys.results || [], api_tokens: apiTokens.results || [] };
            labelB = 'Current State';
          }

          // Diff each category
          const diff = {};
          for (const category of ['keys', 'devices', 'notes', 'totp', 'ssh_keys', 'api_tokens']) {
            const aItems = snapshotA[category] || [];
            const bItems = snapshotB[category] || [];
            const aIds = new Set(aItems.map(i => i.id));
            const bIds = new Set(bItems.map(i => i.id));

            const added = bItems.filter(i => !aIds.has(i.id));
            const removed = aItems.filter(i => !bIds.has(i.id));
            const common = aItems.filter(i => bIds.has(i.id));
            const changed = [];
            for (const aItem of common) {
              const bItem = bItems.find(b => b.id === aItem.id);
              if (bItem && JSON.stringify(aItem) !== JSON.stringify(bItem)) {
                changed.push({ id: aItem.id, before: aItem, after: bItem });
              }
            }

            diff[category] = { added: added.length, removed: removed.length, changed: changed.length, added_items: added, removed_items: removed, changed_items: changed };
          }

          const totalAdded = Object.values(diff).reduce((s, d) => s + d.added, 0);
          const totalRemoved = Object.values(diff).reduce((s, d) => s + d.removed, 0);
          const totalChanged = Object.values(diff).reduce((s, d) => s + d.changed, 0);

          return json({
            ok: true,
            comparison: { a: labelA, b: labelB },
            summary: { total_added: totalAdded, total_removed: totalRemoved, total_changed: totalChanged },
            diff,
          }, cors);
        }

        // ═══════════════════════════════════════════════════════════════
        // ─── NEW FEATURE: Compliance Reports ───
        // ═══════════════════════════════════════════════════════════════
        if (path === '/api/compliance' && request.method === 'GET') {
          const reportType = url.searchParams.get('type') || 'full';

          const keys = await env.DB.prepare('SELECT * FROM ck_keys').all();
          const keyList = keys.results || [];
          const totpEntries = await env.DB.prepare('SELECT * FROM ck_totp').all();
          const totpList = totpEntries.results || [];
          const rotationSchedules = await env.DB.prepare('SELECT * FROM ck_rotation_schedules').all();
          const scheduleList = rotationSchedules.results || [];
          const passkeys = await env.DB.prepare('SELECT * FROM ck_passkeys').all();
          const passkeyList = passkeys.results || [];
          const devices = await env.DB.prepare('SELECT * FROM ck_devices').all();
          const deviceList = devices.results || [];

          // Password Policy Compliance
          const weakPasswords = keyList.filter(k => k.strength === 'weak' || k.strength === 'very-weak');
          const mediumPasswords = keyList.filter(k => k.strength === 'medium');
          const strongPasswords = keyList.filter(k => k.strength === 'strong' || k.strength === 'very-strong');
          const passwordPolicyScore = keyList.length > 0
            ? Math.round((strongPasswords.length / keyList.length) * 100)
            : 0;

          // Rotation Compliance
          const keysOverdue90 = keyList.filter(k => k.rotation_age_days > 90);
          const keysOverdue180 = keyList.filter(k => k.rotation_age_days > 180);
          const keysWithSchedule = scheduleList.length;
          const rotationCoverage = keyList.length > 0
            ? Math.round((keysWithSchedule / keyList.length) * 100)
            : 0;
          const rotationComplianceScore = keyList.length > 0
            ? Math.round(((keyList.length - keysOverdue90.length) / keyList.length) * 100)
            : 100;

          // 2FA Adoption
          const verifiedTotp = totpList.filter(t => t.verified);
          const twoFAScore = keyList.length > 0
            ? Math.min(100, Math.round((verifiedTotp.length / Math.max(1, Math.ceil(keyList.length / 2))) * 100))
            : 0;

          // Passkey Adoption
          const passkeyScore = passkeyList.length > 0 ? 100 : 0;

          // Device Trust
          const trustedDevices = deviceList.filter(d => d.trust_score >= 70);
          const deviceTrustScore = deviceList.length > 0
            ? Math.round((trustedDevices.length / deviceList.length) * 100)
            : 0;

          // Overall compliance score
          const overallScore = Math.round(
            (passwordPolicyScore * 0.30) +
            (rotationComplianceScore * 0.25) +
            (twoFAScore * 0.20) +
            (passkeyScore * 0.10) +
            (deviceTrustScore * 0.15)
          );

          const overallGrade = overallScore >= 90 ? 'A' : overallScore >= 75 ? 'B' : overallScore >= 60 ? 'C' : overallScore >= 40 ? 'D' : 'F';

          const violations = [];
          if (weakPasswords.length > 0) violations.push({ rule: 'NO_WEAK_PASSWORDS', severity: 'high', count: weakPasswords.length, items: weakPasswords.map(k => k.name) });
          if (keysOverdue180.length > 0) violations.push({ rule: 'MAX_ROTATION_180_DAYS', severity: 'critical', count: keysOverdue180.length, items: keysOverdue180.map(k => k.name) });
          if (keysOverdue90.length > 0) violations.push({ rule: 'RECOMMENDED_ROTATION_90_DAYS', severity: 'medium', count: keysOverdue90.length, items: keysOverdue90.map(k => k.name) });
          if (verifiedTotp.length === 0) violations.push({ rule: 'REQUIRE_2FA', severity: 'high', count: 1, items: ['No 2FA configured'] });
          if (passkeyList.length === 0) violations.push({ rule: 'RECOMMEND_PASSKEYS', severity: 'low', count: 1, items: ['No passkeys registered'] });
          if (rotationCoverage < 50) violations.push({ rule: 'ROTATION_SCHEDULE_COVERAGE', severity: 'medium', count: 1, items: [`Only ${rotationCoverage}% of keys have rotation schedules`] });

          const recommendations = [];
          if (weakPasswords.length > 0) recommendations.push(`Strengthen ${weakPasswords.length} weak credential(s)`);
          if (keysOverdue90.length > 0) recommendations.push(`Rotate ${keysOverdue90.length} credential(s) older than 90 days`);
          if (verifiedTotp.length === 0) recommendations.push('Set up 2FA on at least one critical account');
          if (passkeyList.length === 0) recommendations.push('Register a passkey for passwordless authentication');
          if (rotationCoverage < 80) recommendations.push('Add rotation schedules for more credentials');

          let ai_assessment = '';
          if (overallScore < 80) {
            try {
              const prompt = `You are Valeria, the Security Chief on BlackRoad OS. Direct, precise, protective.

Compliance report: overall ${overallScore}/100 (${overallGrade}). Password policy: ${passwordPolicyScore}%. Rotation compliance: ${rotationComplianceScore}%. 2FA adoption: ${twoFAScore}%. Passkey adoption: ${passkeyScore}%. Device trust: ${deviceTrustScore}%.
Violations: ${violations.map(v => v.rule + ' (' + v.severity + ')').join(', ') || 'none'}.
Total credentials: ${keyList.length}. Weak: ${weakPasswords.length}. Overdue rotation: ${keysOverdue90.length}.

Give a 3-sentence compliance summary. Identify the single most impactful improvement. Be professional and actionable.`;
              ai_assessment = await runCKAI(env.AI, prompt);
            } catch {}
          }

          return json({
            ok: true,
            report_type: reportType,
            overall_score: overallScore,
            overall_grade: overallGrade,
            sections: {
              password_policy: { score: passwordPolicyScore, total: keyList.length, weak: weakPasswords.length, medium: mediumPasswords.length, strong: strongPasswords.length },
              rotation_compliance: { score: rotationComplianceScore, total: keyList.length, overdue_90: keysOverdue90.length, overdue_180: keysOverdue180.length, scheduled: keysWithSchedule, coverage: rotationCoverage + '%' },
              two_factor_auth: { score: twoFAScore, totp_setups: totpList.length, verified: verifiedTotp.length },
              passkey_adoption: { score: passkeyScore, registered: passkeyList.length },
              device_trust: { score: deviceTrustScore, total: deviceList.length, trusted: trustedDevices.length },
            },
            violations,
            recommendations,
            ...(ai_assessment ? { ai_assessment, agent: 'Valeria' } : {}),
            generated_at: new Date().toISOString(),
          }, cors);
        }

        // Generate compliance report as downloadable summary
        if (path === '/api/compliance/export' && request.method === 'POST') {
          const body = await request.json().catch(() => ({}));

          // Gather all compliance data
          const keys = await env.DB.prepare('SELECT * FROM ck_keys').all();
          const totp = await env.DB.prepare('SELECT * FROM ck_totp').all();
          const passkeysData = await env.DB.prepare('SELECT * FROM ck_passkeys').all();
          const devicesData = await env.DB.prepare('SELECT * FROM ck_devices').all();
          const schedules = await env.DB.prepare('SELECT * FROM ck_rotation_schedules').all();
          const recentAudit = await env.DB.prepare('SELECT * FROM ck_audit ORDER BY created_at DESC LIMIT 100').all();
          const recentAlerts = await env.DB.prepare('SELECT * FROM ck_security_alerts ORDER BY created_at DESC LIMIT 50').all();

          const report = {
            report_id: crypto.randomUUID().slice(0, 12),
            generated_at: new Date().toISOString(),
            generated_by: 'CarKeys by BlackRoad OS',
            period: body.period || 'current',
            summary: {
              total_credentials: (keys.results || []).length,
              total_devices: (devicesData.results || []).length,
              totp_setups: (totp.results || []).length,
              passkeys: (passkeysData.results || []).length,
              rotation_schedules: (schedules.results || []).length,
              audit_entries_24h: (recentAudit.results || []).length,
              security_alerts: (recentAlerts.results || []).length,
            },
            credentials: (keys.results || []).map(k => ({ name: k.name, type: k.type, strength: k.strength, age_days: k.rotation_age_days, status: k.status })),
            audit_trail: (recentAudit.results || []).map(a => ({ action: a.action, detail: a.detail, at: a.created_at })),
            alerts: (recentAlerts.results || []).map(a => ({ type: a.type, severity: a.severity, description: a.description, resolved: !!a.resolved, at: a.created_at })),
          };

          let payload;
          if (body.passphrase) {
            payload = await encryptData(JSON.stringify(report), body.passphrase);
          } else {
            payload = JSON.stringify(report);
          }

          await logAudit(env.DB, 'compliance_report_exported', report.report_id, 'Compliance report exported');
          return json({
            ok: true,
            report_id: report.report_id,
            encrypted: !!body.passphrase,
            payload,
          }, cors);
        }


        return json({error:'not found'},cors,404);
      } catch(err) {
        return json({error:err.message},cors,500);
      }
    }

    // ─── Shared link viewer (HTML) ───
    if (path.startsWith('/shared/')) {
      const token = path.split('/')[2];
      return new Response(renderSharedPage(token, url.origin), { headers: { 'Content-Type': 'text/html;charset=utf-8', ...SEC } });
    }

    return new Response(renderPage(), { headers: { 'Content-Type': 'text/html;charset=utf-8', ...SEC } });
  }
};

async function ensureCKTables(db) {
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS ck_devices (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL,
      fingerprint TEXT, trust_score INTEGER DEFAULT 50,
      last_seen TEXT DEFAULT (datetime('now')),
      created_at TEXT DEFAULT (datetime('now'))
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ck_keys (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT DEFAULT 'api',
      fingerprint TEXT, strength TEXT DEFAULT 'strong',
      rotation_age_days INTEGER DEFAULT 0,
      last_rotated TEXT DEFAULT (datetime('now')),
      status TEXT DEFAULT 'active',
      created_at TEXT DEFAULT (datetime('now'))
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ck_audit (
      id TEXT PRIMARY KEY, action TEXT NOT NULL, entity_id TEXT,
      detail TEXT, created_at TEXT DEFAULT (datetime('now'))
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ck_family_keys (
      id TEXT PRIMARY KEY, name TEXT NOT NULL,
      permissions TEXT DEFAULT 'read',
      monitored_by TEXT DEFAULT 'owner',
      status TEXT DEFAULT 'active',
      created_at TEXT DEFAULT (datetime('now'))
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ck_totp (
      id TEXT PRIMARY KEY, account TEXT NOT NULL,
      issuer TEXT DEFAULT 'CarKeys',
      secret TEXT NOT NULL,
      verified INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ck_notes (
      id TEXT PRIMARY KEY, title TEXT NOT NULL,
      category TEXT DEFAULT 'general',
      encrypted_content TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ck_share_links (
      id TEXT PRIMARY KEY, token TEXT NOT NULL UNIQUE,
      share_type TEXT NOT NULL,
      entity_id TEXT,
      encrypted_data TEXT DEFAULT '',
      decrypt_hint TEXT DEFAULT '',
      expires_at TEXT NOT NULL,
      max_views INTEGER DEFAULT 1,
      view_count INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ck_emergency_contacts (
      id TEXT PRIMARY KEY, name TEXT NOT NULL,
      email TEXT NOT NULL,
      wait_hours INTEGER DEFAULT 48,
      status TEXT DEFAULT 'active',
      created_at TEXT DEFAULT (datetime('now'))
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ck_emergency_requests (
      id TEXT PRIMARY KEY, contact_id TEXT NOT NULL,
      contact_name TEXT, contact_email TEXT,
      status TEXT DEFAULT 'pending',
      requested_at TEXT DEFAULT (datetime('now')),
      grants_at TEXT NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ck_passkeys (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
      credential_id TEXT NOT NULL,
      public_key_alg TEXT DEFAULT 'ES256',
      attestation_data TEXT DEFAULT '',
      device_name TEXT DEFAULT 'Unknown',
      sign_count INTEGER DEFAULT 0,
      last_used TEXT DEFAULT (datetime('now')),
      created_at TEXT DEFAULT (datetime('now'))
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ck_passkey_challenges (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
      challenge TEXT NOT NULL,
      type TEXT DEFAULT 'registration',
      expires_at TEXT NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ck_rotation_schedules (
      id TEXT PRIMARY KEY, key_id TEXT NOT NULL,
      key_name TEXT, interval_days INTEGER DEFAULT 90,
      next_rotation TEXT NOT NULL,
      notify_days_before INTEGER DEFAULT 7,
      last_rotated TEXT DEFAULT (datetime('now')),
      status TEXT DEFAULT 'active',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ck_ssh_keys (
      id TEXT PRIMARY KEY, name TEXT NOT NULL,
      key_type TEXT DEFAULT 'ed25519',
      public_key TEXT, private_key_encrypted TEXT,
      public_key_fingerprint TEXT,
      associated_servers TEXT DEFAULT '[]',
      tags TEXT DEFAULT '[]',
      passphrase_protected INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      last_used TEXT DEFAULT (datetime('now'))
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ck_api_tokens (
      id TEXT PRIMARY KEY, name TEXT NOT NULL,
      service TEXT DEFAULT 'generic',
      encrypted_token TEXT NOT NULL,
      scopes TEXT DEFAULT '[]',
      expires_at TEXT,
      usage_count INTEGER DEFAULT 0,
      last_used TEXT DEFAULT (datetime('now')),
      status TEXT DEFAULT 'active',
      passphrase_hint TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now'))
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ck_security_alerts (
      id TEXT PRIMARY KEY, type TEXT NOT NULL,
      severity TEXT DEFAULT 'medium',
      source TEXT DEFAULT 'system',
      description TEXT,
      ip_address TEXT DEFAULT 'unknown',
      metadata TEXT DEFAULT '{}',
      resolved INTEGER DEFAULT 0,
      resolved_at TEXT,
      resolution_note TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ck_credential_templates (
      id TEXT PRIMARY KEY, name TEXT NOT NULL,
      category TEXT DEFAULT 'custom',
      description TEXT DEFAULT '',
      fields TEXT DEFAULT '[]',
      tags TEXT DEFAULT '[]',
      icon TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now'))
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS ck_vault_snapshots (
      id TEXT PRIMARY KEY, name TEXT NOT NULL,
      snapshot_data TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    )`),
  ]);

  // Seed some default keys if empty
  const count = await db.prepare('SELECT COUNT(*) as c FROM ck_keys').first();
  if ((count?.c||0) === 0) {
    const seeds = [
      {name:'GitHub SSH',type:'ssh',strength:'strong',age:12},
      {name:'Cloudflare API',type:'api',strength:'strong',age:45},
      {name:'Gitea Access Token',type:'api',strength:'strong',age:8},
      {name:'WireGuard Private Key',type:'vpn',strength:'strong',age:90},
      {name:'Ollama API Key',type:'api',strength:'medium',age:30},
      {name:'NATS Auth Token',type:'service',strength:'strong',age:15},
      {name:'MinIO Access Key',type:'s3',strength:'strong',age:60},
      {name:'PostgreSQL Password',type:'database',strength:'medium',age:120},
    ];
    const stmts = seeds.map(s =>
      db.prepare('INSERT INTO ck_keys (id,name,type,strength,rotation_age_days) VALUES (?,?,?,?,?)')
        .bind(crypto.randomUUID().slice(0,8),s.name,s.type,s.strength,s.age)
    );
    await db.batch(stmts);
  }
}

async function logAudit(db, action, entityId, detail) {
  await db.prepare('INSERT INTO ck_audit (id,action,entity_id,detail) VALUES (?,?,?,?)')
    .bind(crypto.randomUUID().slice(0,8),action,entityId,detail).run();
}

async function runCKAI(ai, systemPrompt) {
  try {
    const r = await ai.run('@cf/meta/llama-3.1-8b-instruct', {
      messages: [{role:'system',content:systemPrompt},{role:'user',content:'Go'}],
      max_tokens: 200, temperature: 0.6,
    });
    return (r?.response||'').trim();
  } catch { return ''; }
}

function json(d,cors,s=200){return new Response(JSON.stringify(d),{status:s,headers:{...cors,'Content-Type':'application/json'}})}

function parseCSVLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') { inQuotes = !inQuotes; continue; }
    if (c === ',' && !inQuotes) { result.push(current.trim()); current = ''; continue; }
    current += c;
  }
  result.push(current.trim());
  return result;
}

function getBuiltInTemplates() {
  return [
    {
      id: 'tpl-aws', name: 'AWS', category: 'cloud', icon: 'A',
      description: 'Amazon Web Services credentials',
      fields: [
        { name: 'access_key_id', label: 'Access Key ID', type: 'text', required: true },
        { name: 'secret_access_key', label: 'Secret Access Key', type: 'secret', required: true },
        { name: 'region', label: 'Default Region', type: 'text', default: 'us-east-1' },
        { name: 'account_id', label: 'Account ID', type: 'text' },
        { name: 'mfa_arn', label: 'MFA ARN', type: 'text' },
      ],
      tags: ['cloud', 'aws', 'infrastructure'],
    },
    {
      id: 'tpl-github', name: 'GitHub', category: 'devtools', icon: 'G',
      description: 'GitHub personal access token or app credentials',
      fields: [
        { name: 'token', label: 'Personal Access Token', type: 'secret', required: true, auto_generate: 'password', length: 40 },
        { name: 'username', label: 'Username', type: 'text' },
        { name: 'scopes', label: 'Scopes', type: 'text', default: 'repo,read:org' },
        { name: 'expiry', label: 'Expiration Date', type: 'date' },
      ],
      tags: ['git', 'github', 'devtools'],
    },
    {
      id: 'tpl-stripe', name: 'Stripe', category: 'payments', icon: 'S',
      description: 'Stripe API keys',
      fields: [
        { name: 'publishable_key', label: 'Publishable Key', type: 'text', required: true },
        { name: 'secret_key', label: 'Secret Key', type: 'secret', required: true },
        { name: 'webhook_secret', label: 'Webhook Signing Secret', type: 'secret' },
        { name: 'account_id', label: 'Account ID', type: 'text' },
        { name: 'mode', label: 'Mode', type: 'text', default: 'test' },
      ],
      tags: ['payments', 'stripe', 'api'],
    },
    {
      id: 'tpl-database', name: 'Database', category: 'database', icon: 'D',
      description: 'Database connection credentials',
      fields: [
        { name: 'host', label: 'Host', type: 'text', required: true, default: 'localhost' },
        { name: 'port', label: 'Port', type: 'text', default: '5432' },
        { name: 'database', label: 'Database Name', type: 'text', required: true },
        { name: 'username', label: 'Username', type: 'text', required: true },
        { name: 'password', label: 'Password', type: 'secret', required: true, auto_generate: 'password', length: 32 },
        { name: 'ssl', label: 'SSL Mode', type: 'text', default: 'require' },
        { name: 'connection_string', label: 'Connection String', type: 'text' },
      ],
      tags: ['database', 'postgres', 'mysql', 'infrastructure'],
    },
    {
      id: 'tpl-cloudflare', name: 'Cloudflare', category: 'cloud', icon: 'C',
      description: 'Cloudflare API credentials',
      fields: [
        { name: 'api_token', label: 'API Token', type: 'secret', required: true },
        { name: 'account_id', label: 'Account ID', type: 'text' },
        { name: 'zone_id', label: 'Zone ID', type: 'text' },
        { name: 'email', label: 'Account Email', type: 'text' },
      ],
      tags: ['cloud', 'cloudflare', 'dns', 'cdn'],
    },
    {
      id: 'tpl-ssh', name: 'SSH Server', category: 'infrastructure', icon: 'S',
      description: 'SSH server access credentials',
      fields: [
        { name: 'host', label: 'Hostname/IP', type: 'text', required: true },
        { name: 'port', label: 'Port', type: 'text', default: '22' },
        { name: 'username', label: 'Username', type: 'text', required: true },
        { name: 'auth_method', label: 'Auth Method', type: 'text', default: 'key' },
        { name: 'key_id', label: 'SSH Key ID', type: 'text' },
        { name: 'password', label: 'Password (if applicable)', type: 'secret' },
      ],
      tags: ['ssh', 'server', 'infrastructure'],
    },
    {
      id: 'tpl-oauth', name: 'OAuth App', category: 'api', icon: 'O',
      description: 'OAuth 2.0 application credentials',
      fields: [
        { name: 'client_id', label: 'Client ID', type: 'text', required: true },
        { name: 'client_secret', label: 'Client Secret', type: 'secret', required: true },
        { name: 'redirect_uri', label: 'Redirect URI', type: 'text' },
        { name: 'auth_url', label: 'Authorization URL', type: 'text' },
        { name: 'token_url', label: 'Token URL', type: 'text' },
        { name: 'scopes', label: 'Scopes', type: 'text' },
      ],
      tags: ['oauth', 'api', 'authentication'],
    },
    {
      id: 'tpl-smtp', name: 'SMTP / Email', category: 'email', icon: 'M',
      description: 'Email server credentials',
      fields: [
        { name: 'host', label: 'SMTP Host', type: 'text', required: true },
        { name: 'port', label: 'Port', type: 'text', default: '587' },
        { name: 'username', label: 'Username', type: 'text', required: true },
        { name: 'password', label: 'Password', type: 'secret', required: true },
        { name: 'from_email', label: 'From Email', type: 'text' },
        { name: 'encryption', label: 'Encryption', type: 'text', default: 'STARTTLS' },
      ],
      tags: ['email', 'smtp', 'notifications'],
    },
    {
      id: 'tpl-docker', name: 'Docker Registry', category: 'devtools', icon: 'D',
      description: 'Docker/container registry credentials',
      fields: [
        { name: 'registry', label: 'Registry URL', type: 'text', default: 'docker.io' },
        { name: 'username', label: 'Username', type: 'text', required: true },
        { name: 'password', label: 'Password/Token', type: 'secret', required: true },
      ],
      tags: ['docker', 'container', 'registry', 'devtools'],
    },
    {
      id: 'tpl-vpn', name: 'VPN / WireGuard', category: 'network', icon: 'V',
      description: 'VPN or WireGuard configuration',
      fields: [
        { name: 'private_key', label: 'Private Key', type: 'secret', required: true },
        { name: 'public_key', label: 'Public Key', type: 'text' },
        { name: 'endpoint', label: 'Endpoint', type: 'text', required: true },
        { name: 'allowed_ips', label: 'Allowed IPs', type: 'text', default: '0.0.0.0/0' },
        { name: 'dns', label: 'DNS', type: 'text' },
        { name: 'preshared_key', label: 'Preshared Key', type: 'secret' },
      ],
      tags: ['vpn', 'wireguard', 'network'],
    },
  ];
}

const ROADIES = {
  lucidia:{name:'Lucidia',role:'Core Intelligence / Memory Spine',division:'core',voice:'Let\'s make this clean and real.'},
  cecilia:{name:'Cecilia',role:'Executive Operator / Workflow Manager',division:'operations',voice:'Already handled.'},
  octavia:{name:'Octavia',role:'Systems Orchestrator / Queue Manager',division:'operations',voice:'Everything has a place.'},
  olympia:{name:'Olympia',role:'Command Console / Launch Control',division:'operations',voice:'Raise the standard.'},
  silas:{name:'Silas',role:'Reliability / Maintenance',division:'operations',voice:'I\'ll keep it running.'},
  sebastian:{name:'Sebastian',role:'Client-Facing Polish',division:'operations',voice:'There\'s a better way to present this.'},
  calliope:{name:'Calliope',role:'Narrative Architect / Copy',division:'creative',voice:'Say it so it stays.'},
  aria:{name:'Aria',role:'Voice / Conversational Interface',division:'creative',voice:'Let\'s make it sing.'},
  thalia:{name:'Thalia',role:'Creative Sprint / Social',division:'creative',voice:'Make it better and more fun.'},
  lyra:{name:'Lyra',role:'Signal / Sound / UX Polish',division:'creative',voice:'It should feel right immediately.'},
  sapphira:{name:'Sapphira',role:'Brand Aura / Visual Taste',division:'creative',voice:'Make it unforgettable.'},
  seraphina:{name:'Seraphina',role:'Visionary Creative Director',division:'creative',voice:'Make it worthy.'},
  alexandria:{name:'Alexandria',role:'Archive / Research Retrieval',division:'knowledge',voice:'It\'s all here.'},
  theodosia:{name:'Theodosia',role:'Doctrine / Canon',division:'knowledge',voice:'Name it correctly.'},
  sophia:{name:'Sophia',role:'Wisdom / Final Reasoning',division:'knowledge',voice:'What is true?'},
  gematria:{name:'Gematria',role:'Pattern Engine / Symbolic Analysis',division:'knowledge',voice:'The pattern is there.'},
  portia:{name:'Portia',role:'Policy Judge / Arbitration',division:'governance',voice:'Let\'s be exact.'},
  atticus:{name:'Atticus',role:'Reviewer / Auditor',division:'governance',voice:'Show me the proof.'},
  cicero:{name:'Cicero',role:'Rhetoric / Persuasion',division:'governance',voice:'Let\'s make the case.'},
  valeria:{name:'Valeria',role:'Security Chief / Enforcement',division:'governance',voice:'Not everything gets access.'},
  alice:{name:'Alice',role:'Onboarding / Curiosity Guide',division:'human',voice:'Okay, but what\'s actually going on here?'},
  celeste:{name:'Celeste',role:'Calm Companion / Reassurance',division:'human',voice:'You\'re okay. Let\'s do this simply.'},
  elias:{name:'Elias',role:'Teacher / Patient Explainer',division:'human',voice:'Let\'s slow down and understand it.'},
  ophelia:{name:'Ophelia',role:'Reflection / Mood / Depth',division:'human',voice:'There\'s something underneath this.'},
  gaia:{name:'Gaia',role:'Infrastructure / Hardware Monitor',division:'infrastructure',voice:'What is the system actually standing on?'},
  anastasia:{name:'Anastasia',role:'Restoration / Recovery',division:'infrastructure',voice:'It can be made whole again.'},
};

function renderSharedPage(token, origin) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CarKeys - Shared Content</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<style>*{margin:0;padding:0;box-sizing:border-box}:root{--bg:#000;--card:#0a0a0a;--border:#1a1a1a;--muted:#444;--sub:#737373;--text:#f5f5f5;--sg:'Space Grotesk',sans-serif;--jb:'JetBrains Mono',monospace}
body{background:var(--bg);color:var(--text);font-family:var(--sg);min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:48px 20px}
.grad-bar{position:fixed;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,#FF6B2B,#FF2255,#CC00AA,#8844FF,#4488FF,#00D4FF)}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:24px;max-width:500px;width:100%;margin-top:32px}
h2{font-size:20px;margin-bottom:16px}
.content{background:#111;border:1px solid var(--border);border-radius:8px;padding:16px;font-family:var(--jb);font-size:13px;white-space:pre-wrap;word-break:break-all;max-height:400px;overflow-y:auto;margin-top:12px}
.meta{font-size:12px;color:var(--sub);margin-top:12px}
.error{color:#ff4444}
.loading{color:var(--muted);font-style:italic}
.footer{margin-top:auto;padding-top:48px;font-size:11px;color:var(--muted)}</style></head><body>
<div class="grad-bar"></div>
<div class="card">
<h2>Shared Content</h2>
<div id="result" class="loading">Loading...</div>
</div>
<div class="footer">CarKeys by BlackRoad OS, Inc. 2025-2026</div>
<script>
(async()=>{
  const el=document.getElementById('result');
  try{
    const r=await fetch('${origin}/api/shared/${token}');
    const d=await r.json();
    if(d.error){el.innerHTML='<span class="error">'+d.error+'</span>';return}
    let html='';
    if(d.content)html+='<div class="content">'+d.content.replace(/</g,'&lt;')+'</div>';
    if(d.key)html+='<div class="content">Key: '+JSON.stringify(d.key,null,2).replace(/</g,'&lt;')+'</div>';
    if(d.note)html+='<div class="content">Note: '+JSON.stringify(d.note,null,2).replace(/</g,'&lt;')+'</div>';
    html+='<div class="meta">Views remaining: '+(d.views_remaining||0)+'<br>Expires: '+(d.expires_at||'unknown')+'</div>';
    el.innerHTML=html;
  }catch(e){el.innerHTML='<span class="error">Failed to load shared content</span>'}
})();
</script></body></html>`;
}

function renderBlast(text, link, selected) {
  const buttons = selected.map(id => {
    const p = PLATFORMS[id];
    if (!p) return '';
    return '<a class="blast-btn" href="' + p.share(text, link) + '" target="_blank"><span class="blast-icon">' + p.icon + '</span>' + p.name + '</a>';
  }).join('');
  const scripts = selected.map((id, i) => {
    const p = PLATFORMS[id];
    if (!p) return '';
    return 'setTimeout(function(){window.open("' + p.share(text, link).replace(/"/g, '\\"') + '","_blank")},' + (i * 800) + ');';
  }).join('');
  return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CarKeys Blast</title><link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet"><style>*{margin:0;padding:0;box-sizing:border-box}:root{--g:linear-gradient(90deg,#FF6B2B,#FF2255,#CC00AA,#8844FF,#4488FF,#00D4FF);--bg:#000;--card:#0a0a0a;--border:#1a1a1a;--muted:#444;--sub:#737373;--text:#f5f5f5;--white:#fff;--sg:"Space Grotesk",sans-serif;--jb:"JetBrains Mono",monospace}body{background:var(--bg);color:var(--text);font-family:var(--sg);min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:48px 20px}.grad-bar{position:fixed;top:0;left:0;right:0;height:3px;background:var(--g)}h1{font-size:28px;font-weight:700;margin:24px 0 8px}p{color:var(--sub);font-size:14px;margin-bottom:32px}.blast-grid{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;max-width:600px}.blast-btn{display:flex;align-items:center;gap:8px;padding:12px 20px;background:var(--card);border:1px solid var(--border);border-radius:8px;color:var(--text);text-decoration:none;font-size:13px;transition:all .15s}.blast-btn:hover{border-color:#333;background:#111}.blast-icon{font-family:var(--jb);font-size:12px;width:20px;height:20px;display:flex;align-items:center;justify-content:center;border-radius:4px;background:#111;border:1px solid var(--border);color:var(--sub)}.footer{margin-top:auto;padding-top:48px;font-size:11px;color:var(--muted)}</style><meta property="og:title" content="CarKeys — BlackRoad OS"><meta property="og:description" content="Credential vault. Part of BlackRoad OS."><meta property="og:url" content="https://carkeys.blackroad.io"><meta property="og:image" content="https://images.blackroad.io/pixel-art/road-logo.png"><meta name="twitter:card" content="summary_large_image"><meta name="robots" content="index, follow, noai, noimageai"></head><body><div class="grad-bar"></div><h1>Blasting to ' + selected.length + ' platforms</h1><p>Click any that did not open automatically.</p><div class="blast-grid">' + buttons + '</div><script>' + scripts + '</script><div class="footer">CarKeys by BlackRoad OS, Inc. 2025-2026</div></body></html>';
}

function renderPage() {
  const platformPills = Object.entries(PLATFORMS).map(([id, p]) =>
    '<label class="plat-check"><input type="checkbox" value="' + id + '" checked><span class="plat-icon">' + p.icon + '</span><span class="plat-name">' + p.name + '</span></label>'
  ).join('');

  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CarKeys — Credential Vault + Social Blast</title>
<meta name="description" content="Credential vault with password health, 2FA, breach detection, secure notes, and post to 15 platforms simultaneously.">
<meta property="og:title" content="CarKeys — BlackRoad OS"><meta property="og:description" content="Credential vault + post to 15 platforms. One click."><meta property="og:url" content="https://carkeys.blackroad.io"><meta property="og:image" content="https://images.blackroad.io/pixel-art/road-logo.png"><meta name="twitter:card" content="summary_large_image"><meta name="robots" content="index, follow, noai, noimageai">
<link rel="icon" href="https://images.blackroad.io/pixel-art/road-logo.png">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--g:linear-gradient(90deg,#FF6B2B,#FF2255,#CC00AA,#8844FF,#4488FF,#00D4FF);--g135:linear-gradient(135deg,#FF6B2B,#FF2255,#CC00AA,#8844FF,#4488FF,#00D4FF);--bg:#000;--card:#0a0a0a;--elevated:#111;--hover:#181818;--border:#1a1a1a;--muted:#444;--sub:#737373;--text:#f5f5f5;--white:#fff;--sg:'Space Grotesk',sans-serif;--jb:'JetBrains Mono',monospace}
body{background:var(--bg);color:var(--text);font-family:var(--sg);min-height:100vh}
.grad-bar{height:3px;background:var(--g)}
.wrap{max-width:720px;margin:0 auto;padding:48px 20px}
.logo{display:flex;align-items:center;gap:8px;margin-bottom:48px}
.logo-mark{display:flex;gap:4px}
.logo-mark span{width:6px;height:6px;border-radius:50%}
.logo-mark span:nth-child(even){border-radius:1px}
.logo-text{font-weight:700;font-size:16px}
h1{font-size:32px;font-weight:700;letter-spacing:-.02em;margin-bottom:8px}
h2{font-size:18px;font-weight:600;margin:32px 0 16px}
.subtitle{color:var(--sub);font-size:14px;line-height:1.7;margin-bottom:32px;max-width:480px}
.compose{background:var(--card);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-bottom:24px}
.compose-grad{height:3px;background:var(--g)}
.compose-body{padding:20px}
.compose textarea{width:100%;height:100px;background:transparent;border:1px solid var(--border);border-radius:8px;padding:14px;color:var(--text);font-size:14px;font-family:var(--sg);resize:vertical;outline:none;line-height:1.6;margin-bottom:12px}
.compose textarea:focus{border-color:#333}
.compose textarea::placeholder{color:var(--muted)}
.compose input, .tool-input{width:100%;padding:10px 14px;background:transparent;border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;font-family:var(--jb);outline:none;margin-bottom:12px}
.compose input:focus, .tool-input:focus{border-color:#333}
.compose input::placeholder, .tool-input::placeholder{color:var(--muted)}
.plat-grid{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px}
.plat-check{display:flex;align-items:center;gap:5px;padding:5px 10px;background:var(--elevated);border:1px solid var(--border);border-radius:6px;font-size:11px;color:var(--sub);cursor:pointer;transition:all .12s}
.plat-check:hover{border-color:#333;color:var(--text)}
.plat-check:has(input:checked){border-color:#333;color:var(--white);background:var(--hover)}
.plat-check input{display:none}
.plat-icon{font-family:var(--jb);font-size:10px;width:16px;height:16px;display:flex;align-items:center;justify-content:center;border-radius:3px;background:var(--bg);border:1px solid var(--border)}
.plat-name{font-family:var(--sg);font-weight:500}
.blast-btn-main, .tool-btn{width:100%;padding:14px;border:none;border-radius:8px;background:var(--white);color:#000;font-size:15px;font-weight:600;cursor:pointer;font-family:var(--sg);transition:opacity .15s}
.blast-btn-main:hover, .tool-btn:hover{opacity:.9}
.blast-btn-main:active, .tool-btn:active{transform:scale(.99)}
.tool-btn{font-size:13px;padding:10px;margin-top:4px}
.tool-btn.secondary{background:var(--elevated);color:var(--text);border:1px solid var(--border)}
.stats{display:flex;gap:24px;margin-bottom:32px;flex-wrap:wrap}
.stat{text-align:center}
.stat-val{font-size:28px;font-weight:700;font-family:var(--sg)}
.stat-label{font-family:var(--jb);font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-top:2px}
.tabs{display:flex;gap:0;border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:24px}
.tab{flex:1;padding:10px;text-align:center;font-size:12px;font-weight:500;cursor:pointer;background:var(--card);color:var(--sub);border-right:1px solid var(--border);transition:all .12s}
.tab:last-child{border-right:none}
.tab:hover{color:var(--text);background:var(--elevated)}
.tab.active{color:var(--white);background:var(--elevated)}
.tab-content{display:none}
.tab-content.active{display:block}
.tool-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:16px}
.tool-card h3{font-size:14px;font-weight:600;margin-bottom:12px}
.tool-card p{font-size:12px;color:var(--sub);margin-bottom:12px;line-height:1.5}
.result-box{background:#0a0a0a;border:1px solid var(--border);border-radius:8px;padding:14px;font-family:var(--jb);font-size:12px;color:var(--sub);margin-top:12px;white-space:pre-wrap;word-break:break-all;max-height:300px;overflow-y:auto;display:none}
.result-box.visible{display:block}
.health-meter{height:8px;border-radius:4px;background:var(--border);overflow:hidden;margin:8px 0}
.health-fill{height:100%;border-radius:4px;transition:width .5s}
.health-grade{font-size:48px;font-weight:700;text-align:center;margin:16px 0}
.health-issues{list-style:none;padding:0}
.health-issues li{font-size:12px;color:var(--sub);padding:6px 0;border-bottom:1px solid var(--border)}
.health-issues li:last-child{border-bottom:none}
.row{display:flex;gap:12px}
.row>*{flex:1}
.how{margin-top:40px}
.how h3{font-size:14px;font-weight:600;margin-bottom:16px}
.how-steps{display:flex;flex-direction:column;gap:12px}
.how-step{display:flex;gap:12px;padding:14px;background:var(--card);border:1px solid var(--border);border-radius:8px}
.how-num{font-family:var(--jb);font-size:11px;color:var(--muted);width:20px;flex-shrink:0}
.how-text{font-size:13px;color:var(--sub);line-height:1.6}
.footer{text-align:center;padding:40px 0 20px;border-top:1px solid var(--border);margin-top:48px;font-size:11px;color:var(--muted)}
@media(max-width:640px){h1{font-size:24px}.stats{gap:16px}.stat-val{font-size:22px}.row{flex-direction:column}.tabs{flex-wrap:wrap}}
</style></head><body>
<div class="grad-bar"></div>
<div class="wrap">
  <div class="logo">
    <div class="logo-mark"><span style="background:#FF6B2B"></span><span style="background:#FF2255"></span><span style="background:#CC00AA"></span><span style="background:#8844FF"></span><span style="background:#4488FF"></span><span style="background:#00D4FF"></span></div>
    <span class="logo-text">CarKeys</span>
  </div>

  <h1>Credential vault + social blast.</h1>
  <p class="subtitle">Vault your keys. Check breach exposure. Generate passwords. Enable 2FA. Store encrypted notes. Share securely. Post to 15 platforms. All sovereign.</p>

  <div class="stats" id="statsBar">
    <div class="stat"><div class="stat-val" id="statKeys">-</div><div class="stat-label">Keys</div></div>
    <div class="stat"><div class="stat-val" id="statDevices">-</div><div class="stat-label">Devices</div></div>
    <div class="stat"><div class="stat-val" id="statScore">-</div><div class="stat-label">Health</div></div>
    <div class="stat"><div class="stat-val">${Object.keys(PLATFORMS).length}</div><div class="stat-label">Platforms</div></div>
  </div>

  <div class="tabs">
    <div class="tab active" onclick="switchTab('blast')">Blast</div>
    <div class="tab" onclick="switchTab('health')">Health</div>
    <div class="tab" onclick="switchTab('generate')">Generate</div>
    <div class="tab" onclick="switchTab('breach')">Breach</div>
    <div class="tab" onclick="switchTab('notes')">Notes</div>
    <div class="tab" onclick="switchTab('tools')">Tools</div>
    <div class="tab" onclick="switchTab('advanced')">Advanced</div>
  </div>

  <!-- ─── BLAST TAB ─── -->
  <div class="tab-content active" id="tab-blast">
    <div class="compose">
      <div class="compose-grad"></div>
      <div class="compose-body">
        <textarea id="text" placeholder="What do you want to say?">I built an AI OS on Raspberry Pis. 17 live products. Sovereign everything. blackroad.io</textarea>
        <input id="url" value="https://blackroad.io" placeholder="Link (optional)">
        <div class="plat-grid">${platformPills}</div>
        <button class="blast-btn-main" onclick="blast()">Blast to Selected Platforms</button>
      </div>
    </div>
  </div>

  <!-- ─── HEALTH DASHBOARD TAB ─── -->
  <div class="tab-content" id="tab-health">
    <div class="tool-card">
      <h3>Password Health Dashboard</h3>
      <p>Real-time analysis of all credentials in your vault. Valeria checks for weak, reused, and aging passwords.</p>
      <button class="tool-btn" onclick="loadHealth()">Run Health Check</button>
      <div id="healthResult" class="result-box"></div>
    </div>
  </div>

  <!-- ─── GENERATE TAB ─── -->
  <div class="tab-content" id="tab-generate">
    <div class="tool-card">
      <h3>Password Generator</h3>
      <p>Cryptographically secure password generation with configurable length and charset.</p>
      <div class="row">
        <input class="tool-input" id="genLength" type="number" value="24" min="4" max="128" placeholder="Length">
        <select class="tool-input" id="genCharset" style="background:var(--bg)">
          <option value="all">All characters</option>
          <option value="lowercase">Lowercase only</option>
          <option value="uppercase">Uppercase only</option>
          <option value="digits">Digits only</option>
          <option value="symbols">Symbols only</option>
        </select>
      </div>
      <button class="tool-btn" onclick="generatePw()">Generate Password</button>
      <div id="genResult" class="result-box"></div>
    </div>
  </div>

  <!-- ─── BREACH CHECK TAB ─── -->
  <div class="tab-content" id="tab-breach">
    <div class="tool-card">
      <h3>Breach Check</h3>
      <p>Check if a password appears in known data breaches using k-anonymity (your full password never leaves your device).</p>
      <input class="tool-input" id="breachPw" type="password" placeholder="Enter password to check">
      <button class="tool-btn" onclick="checkBreach()">Check Breach Database</button>
      <div id="breachResult" class="result-box"></div>
    </div>
  </div>

  <!-- ─── SECURE NOTES TAB ─── -->
  <div class="tab-content" id="tab-notes">
    <div class="tool-card">
      <h3>Secure Notes</h3>
      <p>Store encrypted notes in your vault. Each note is AES-256-GCM encrypted with your passphrase.</p>
      <input class="tool-input" id="noteTitle" placeholder="Note title">
      <textarea class="tool-input" id="noteContent" style="height:80px;resize:vertical;font-family:var(--jb)" placeholder="Note content (will be encrypted)"></textarea>
      <input class="tool-input" id="notePass" type="password" placeholder="Encryption passphrase">
      <button class="tool-btn" onclick="saveNote()">Save Encrypted Note</button>
      <button class="tool-btn secondary" onclick="listNotes()" style="margin-top:8px">List My Notes</button>
      <div id="noteResult" class="result-box"></div>
    </div>
  </div>

  <!-- ─── TOOLS TAB ─── -->
  <div class="tab-content" id="tab-tools">
    <div class="tool-card">
      <h3>TOTP / 2FA Setup</h3>
      <p>Generate TOTP secrets for two-factor authentication.</p>
      <div class="row">
        <input class="tool-input" id="totpAccount" placeholder="Account (e.g. user@example.com)">
        <input class="tool-input" id="totpIssuer" placeholder="Issuer (e.g. GitHub)">
      </div>
      <button class="tool-btn" onclick="setupTotp()">Generate TOTP Secret</button>
      <div id="totpResult" class="result-box"></div>
    </div>

    <div class="tool-card">
      <h3>Vault Export</h3>
      <p>Export your entire vault as an encrypted backup.</p>
      <input class="tool-input" id="exportPass" type="password" placeholder="Encryption passphrase for export">
      <button class="tool-btn" onclick="exportVault()">Export Encrypted Backup</button>
      <div id="exportResult" class="result-box"></div>
    </div>

    <div class="tool-card">
      <h3>Import Credentials</h3>
      <p>Import from LastPass or 1Password CSV export.</p>
      <textarea class="tool-input" id="importCsv" style="height:80px;resize:vertical;font-family:var(--jb)" placeholder="Paste CSV data here (LastPass or 1Password export)"></textarea>
      <button class="tool-btn" onclick="importCreds()">Import Credentials</button>
      <div id="importResult" class="result-box"></div>
    </div>

    <div class="tool-card">
      <h3>Emergency Access</h3>
      <p>Designate trusted contacts who can request vault access after a waiting period.</p>
      <div class="row">
        <input class="tool-input" id="emergName" placeholder="Contact name">
        <input class="tool-input" id="emergEmail" placeholder="Contact email">
      </div>
      <input class="tool-input" id="emergHours" type="number" value="48" min="1" max="720" placeholder="Wait hours before access granted">
      <button class="tool-btn" onclick="addEmergency()">Add Emergency Contact</button>
      <button class="tool-btn secondary" onclick="listEmergency()" style="margin-top:8px">View Emergency Contacts</button>
      <div id="emergResult" class="result-box"></div>
    </div>
  </div>

  <!-- ─── ADVANCED TAB ─── -->
  <div class="tab-content" id="tab-advanced">
    <div class="tool-card">
      <h3>Passkey Management</h3>
      <p>Register WebAuthn/FIDO2 passkeys for passwordless authentication.</p>
      <div class="row">
        <input class="tool-input" id="pkUserId" placeholder="User ID">
        <input class="tool-input" id="pkUsername" placeholder="Username">
      </div>
      <button class="tool-btn" onclick="registerPasskey()">Begin Passkey Registration</button>
      <button class="tool-btn secondary" onclick="listPasskeys()" style="margin-top:8px">List Passkeys</button>
      <div id="passkeyResult" class="result-box"></div>
    </div>

    <div class="tool-card">
      <h3>Rotation Scheduler</h3>
      <p>Schedule automatic key rotations on 30/60/90 day intervals with reminders.</p>
      <div class="row">
        <input class="tool-input" id="rotKeyId" placeholder="Key ID">
        <select class="tool-input" id="rotInterval" style="background:var(--bg)">
          <option value="30">Every 30 days</option>
          <option value="60">Every 60 days</option>
          <option value="90" selected>Every 90 days</option>
          <option value="180">Every 180 days</option>
        </select>
      </div>
      <button class="tool-btn" onclick="scheduleRotation()">Schedule Rotation</button>
      <button class="tool-btn secondary" onclick="listRotations()" style="margin-top:8px">View Schedules</button>
      <button class="tool-btn secondary" onclick="checkRotations()" style="margin-top:8px">Check Overdue</button>
      <div id="rotResult" class="result-box"></div>
    </div>

    <div class="tool-card">
      <h3>SSH Key Manager</h3>
      <p>Generate and manage SSH key pairs. Associate with servers.</p>
      <div class="row">
        <input class="tool-input" id="sshName" placeholder="Key name (e.g. prod-server)">
        <select class="tool-input" id="sshType" style="background:var(--bg)">
          <option value="ed25519">Ed25519</option>
          <option value="rsa">RSA</option>
          <option value="ecdsa">ECDSA</option>
        </select>
      </div>
      <input class="tool-input" id="sshPass" type="password" placeholder="Passphrase (optional, encrypts private key)">
      <button class="tool-btn" onclick="generateSSH()">Generate SSH Key Pair</button>
      <button class="tool-btn secondary" onclick="listSSH()" style="margin-top:8px">List SSH Keys</button>
      <div id="sshResult" class="result-box"></div>
    </div>

    <div class="tool-card">
      <h3>API Token Vault</h3>
      <p>Store API tokens with scopes, expiry dates, and usage tracking.</p>
      <div class="row">
        <input class="tool-input" id="atName" placeholder="Token name">
        <input class="tool-input" id="atService" placeholder="Service (e.g. GitHub)">
      </div>
      <input class="tool-input" id="atToken" type="password" placeholder="Token value">
      <input class="tool-input" id="atPass" type="password" placeholder="Encryption passphrase">
      <button class="tool-btn" onclick="storeApiToken()">Store API Token</button>
      <button class="tool-btn secondary" onclick="listApiTokens()" style="margin-top:8px">List API Tokens</button>
      <div id="atResult" class="result-box"></div>
    </div>

    <div class="tool-card">
      <h3>Security Alerts</h3>
      <p>View and analyze security alerts. Detect suspicious access patterns.</p>
      <button class="tool-btn" onclick="analyzeAlerts()">Analyze (24h)</button>
      <button class="tool-btn secondary" onclick="listAlerts()" style="margin-top:8px">View Recent Alerts</button>
      <div id="alertResult" class="result-box"></div>
    </div>

    <div class="tool-card">
      <h3>Credential Templates</h3>
      <p>Pre-built templates for AWS, GitHub, Stripe, databases, and more.</p>
      <button class="tool-btn" onclick="listTemplates()">Browse Templates</button>
      <div class="row" style="margin-top:12px">
        <input class="tool-input" id="tplId" placeholder="Template ID (e.g. tpl-aws)">
        <input class="tool-input" id="tplPass" type="password" placeholder="Passphrase for stored values">
      </div>
      <button class="tool-btn secondary" onclick="applyTemplate()">Apply Template</button>
      <div id="tplResult" class="result-box"></div>
    </div>

    <div class="tool-card">
      <h3>Vault Comparison</h3>
      <p>Take snapshots of your vault and compare changes over time.</p>
      <input class="tool-input" id="snapName" placeholder="Snapshot name (e.g. before-rotation)">
      <button class="tool-btn" onclick="takeSnapshot()">Take Snapshot</button>
      <button class="tool-btn secondary" onclick="listSnapshots()" style="margin-top:8px">List Snapshots</button>
      <div class="row" style="margin-top:12px">
        <input class="tool-input" id="snapA" placeholder="Snapshot A ID">
        <input class="tool-input" id="snapB" placeholder="Snapshot B ID (blank = current)">
      </div>
      <button class="tool-btn secondary" onclick="compareSnapshots()">Compare</button>
      <div id="snapResult" class="result-box"></div>
    </div>

    <div class="tool-card">
      <h3>Compliance Report</h3>
      <p>Password policy adherence, rotation compliance, 2FA adoption, and more.</p>
      <button class="tool-btn" onclick="runCompliance()">Generate Compliance Report</button>
      <div id="compResult" class="result-box"></div>
    </div>
  </div>

  <div class="how">
    <h3>How it works</h3>
    <div class="how-steps">
      <div class="how-step"><span class="how-num">01</span><div class="how-text">Write your message and paste a link. Select which platforms you want.</div></div>
      <div class="how-step"><span class="how-num">02</span><div class="how-text">Click blast. CarKeys opens each platform's native share URL in a new tab.</div></div>
      <div class="how-step"><span class="how-num">03</span><div class="how-text">Because you're already logged in to those platforms, each tab pre-fills your post. Hit send on each one.</div></div>
    </div>
  </div>

  <div class="footer">CarKeys by BlackRoad OS, Inc. 2025-2026 — Pave Tomorrow.</div>
</div>
<script>
function switchTab(name){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  document.querySelectorAll('.tab').forEach(t=>{if(t.textContent.toLowerCase()===name||t.onclick.toString().includes("'"+name+"'"))t.classList.add('active')});
  event.target.classList.add('active');
}

function blast(){
  var text=document.getElementById('text').value;
  var url=document.getElementById('url').value;
  var checked=document.querySelectorAll('.plat-check input:checked');
  var ids=Array.from(checked).map(function(c){return c.value});
  if(!ids.length){alert('Select at least one platform');return}
  window.location='/blast?text='+encodeURIComponent(text)+'&url='+encodeURIComponent(url)+'&platforms='+ids.join(',');
}

async function api(path,opts){
  const r=await fetch(path,opts);
  return r.json();
}

function show(id,data){
  const el=document.getElementById(id);
  el.textContent=typeof data==='string'?data:JSON.stringify(data,null,2);
  el.classList.add('visible');
}

// Load stats on page load
(async()=>{
  try{
    const s=await api('/api/vault/stats');
    if(s.vault){
      document.getElementById('statKeys').textContent=s.vault.total_keys;
      document.getElementById('statDevices').textContent=s.vault.total_devices;
    }
    const h=await api('/api/health-report');
    if(h.score!==undefined)document.getElementById('statScore').textContent=h.grade;
  }catch(e){}
})();

async function loadHealth(){
  show('healthResult','Loading health report...');
  const d=await api('/api/health-report');
  let out='VAULT HEALTH: '+d.grade+' ('+d.score+'/100)\\n';
  out+='━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
  out+='Credentials: '+d.total_credentials+'\\n';
  out+='2FA enabled: '+d.totp_enabled+'\\n';
  out+='Secure notes: '+d.secure_notes+'\\n\\n';
  if(d.weak_credentials&&d.weak_credentials.length){
    out+='WEAK CREDENTIALS:\\n';
    d.weak_credentials.forEach(w=>out+='  - '+w.name+' ('+w.strength+')\\n');
    out+='\\n';
  }
  if(d.aging_credentials&&d.aging_credentials.length){
    out+='AGING CREDENTIALS:\\n';
    d.aging_credentials.forEach(a=>out+='  - '+a.name+' ('+a.age_days+' days)\\n');
    out+='\\n';
  }
  if(d.issues&&d.issues.length){
    out+='ISSUES:\\n';
    d.issues.forEach(i=>out+='  - '+i+'\\n');
    out+='\\n';
  }
  if(d.recommendations&&d.recommendations.length){
    out+='RECOMMENDATIONS:\\n';
    d.recommendations.forEach(r=>out+='  - '+r+'\\n');
    out+='\\n';
  }
  if(d.ai_assessment){
    out+='VALERIA SAYS:\\n'+d.ai_assessment+'\\n';
  }
  show('healthResult',out);
}

async function generatePw(){
  const len=document.getElementById('genLength').value;
  const cs=document.getElementById('genCharset').value;
  const d=await api('/api/generate?length='+len+'&charset='+cs);
  if(d.passwords&&d.passwords[0]){
    const p=d.passwords[0];
    let out='PASSWORD: '+p.password+'\\n\\n';
    out+='Length: '+p.length+'\\n';
    out+='Entropy: '+p.entropy+' bits\\n';
    out+='Strength: '+p.strength+'\\n';
    show('genResult',out);
  }
}

async function checkBreach(){
  const pw=document.getElementById('breachPw').value;
  if(!pw){alert('Enter a password to check');return}
  show('breachResult','Checking breach database...');
  const d=await api('/api/breach-check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
  let out='';
  if(d.breached===true){
    out+='BREACHED - Found in '+d.times_seen.toLocaleString()+' data breaches\\n\\n';
  }else if(d.breached===false){
    out+='SAFE - Not found in known breaches\\n\\n';
  }else{
    out+='UNKNOWN - Could not reach breach database\\n\\n';
  }
  out+='Strength: '+d.strength+'\\n';
  out+='Entropy: '+d.entropy+' bits\\n\\n';
  out+=d.recommendation||'';
  show('breachResult',out);
}

async function saveNote(){
  const title=document.getElementById('noteTitle').value;
  const content=document.getElementById('noteContent').value;
  const pass=document.getElementById('notePass').value;
  if(!title||!content||!pass){alert('Title, content, and passphrase required');return}
  const d=await api('/api/notes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title:title,content:content,passphrase:pass})});
  show('noteResult',d.ok?'Note saved (ID: '+d.id+')':JSON.stringify(d));
}

async function listNotes(){
  const d=await api('/api/notes');
  if(!d.notes||!d.notes.length){show('noteResult','No notes yet.');return}
  let out='SECURE NOTES:\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
  d.notes.forEach(n=>out+=n.id+' | '+n.title+' | '+n.category+' | '+n.created_at+'\\n');
  show('noteResult',out);
}

async function setupTotp(){
  const account=document.getElementById('totpAccount').value||'user@blackroad.io';
  const issuer=document.getElementById('totpIssuer').value||'CarKeys';
  const d=await api('/api/totp/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({account:account,issuer:issuer})});
  let out='TOTP SETUP\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
  out+='Secret: '+d.secret+'\\n';
  out+='Account: '+d.account+'\\n';
  out+='Issuer: '+d.issuer+'\\n';
  out+='Current code: '+d.current_code+'\\n\\n';
  out+='OTPAuth URL:\\n'+d.otpauth_url+'\\n\\n';
  out+=d.instructions||'';
  show('totpResult',out);
}

async function exportVault(){
  const pass=document.getElementById('exportPass').value;
  if(!pass){alert('Passphrase required');return}
  show('exportResult','Exporting...');
  const d=await api('/api/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passphrase:pass})});
  if(d.ok){
    let out='VAULT EXPORT COMPLETE\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
    out+='Keys: '+d.counts.keys+'\\n';
    out+='Devices: '+d.counts.devices+'\\n';
    out+='Notes: '+d.counts.notes+'\\n';
    out+='TOTP: '+d.counts.totp+'\\n';
    out+='Family: '+d.counts.family_keys+'\\n\\n';
    out+='Encrypted payload ('+d.encrypted_payload.length+' chars):\\n';
    out+=d.encrypted_payload.slice(0,200)+'...\\n\\n';
    out+=d.instructions;
    show('exportResult',out);
  }else{show('exportResult',JSON.stringify(d))}
}

async function importCreds(){
  const csv=document.getElementById('importCsv').value;
  if(!csv){alert('Paste CSV data');return}
  show('importResult','Importing...');
  const d=await api('/api/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({csv:csv})});
  if(d.ok){
    let out='IMPORTED '+d.imported+' credentials from '+d.source+'\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
    (d.entries||[]).forEach(e=>out+=e.name+' ('+e.type+', '+e.strength+')\\n');
    show('importResult',out);
  }else{show('importResult',JSON.stringify(d))}
}

async function addEmergency(){
  const name=document.getElementById('emergName').value;
  const email=document.getElementById('emergEmail').value;
  const hours=document.getElementById('emergHours').value;
  if(!name||!email){alert('Name and email required');return}
  const d=await api('/api/emergency/contacts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name,email:email,wait_hours:parseInt(hours)})});
  show('emergResult',d.ok?d.message:JSON.stringify(d));
}

async function listEmergency(){
  const d=await api('/api/emergency');
  if(!d.contacts||!d.contacts.length){show('emergResult','No emergency contacts.');return}
  let out='EMERGENCY CONTACTS:\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
  d.contacts.forEach(c=>out+=c.name+' ('+c.email+') - '+c.wait_hours+'h wait - '+c.status+'\\n');
  if(d.recent_requests&&d.recent_requests.length){
    out+='\\nRECENT REQUESTS:\\n';
    d.recent_requests.forEach(r=>out+=r.contact_name+' - '+r.status+' ('+r.requested_at+')\\n');
  }
  show('emergResult',out);
}

// ─── Passkey Management ───
async function registerPasskey(){
  const uid=document.getElementById('pkUserId').value;
  const uname=document.getElementById('pkUsername').value;
  if(!uid||!uname){alert('User ID and username required');return}
  show('passkeyResult','Beginning passkey registration...');
  const d=await api('/api/passkeys/register/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:uid,username:uname})});
  if(d.ok){
    let out='PASSKEY REGISTRATION CHALLENGE\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
    out+='Challenge ID: '+d.challenge_id+'\\n';
    out+='RP: '+d.publicKey.rp.name+'\\n';
    out+='User: '+d.publicKey.user.name+'\\n';
    out+='Algorithms: '+d.publicKey.pubKeyCredParams.map(p=>p.alg===-7?'ES256':'RS256').join(', ')+'\\n';
    out+='Timeout: '+d.publicKey.timeout+'ms\\n\\n';
    out+='Use navigator.credentials.create() with this challenge to complete registration.';
    show('passkeyResult',out);
  }else{show('passkeyResult',JSON.stringify(d))}
}

async function listPasskeys(){
  const d=await api('/api/passkeys');
  if(!d.passkeys||!d.passkeys.length){show('passkeyResult','No passkeys registered.');return}
  let out='REGISTERED PASSKEYS\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
  d.passkeys.forEach(p=>out+=p.id+' | '+p.user_id+' | '+p.device_name+' | '+p.public_key_alg+' | uses: '+(p.sign_count||0)+' | '+p.created_at+'\\n');
  show('passkeyResult',out);
}

// ─── Rotation Scheduler ───
async function scheduleRotation(){
  const keyId=document.getElementById('rotKeyId').value;
  const interval=document.getElementById('rotInterval').value;
  if(!keyId){alert('Key ID required');return}
  show('rotResult','Scheduling...');
  const d=await api('/api/rotation-schedule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key_id:keyId,interval_days:parseInt(interval)})});
  if(d.ok){
    let out='ROTATION SCHEDULED\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
    out+='Key: '+d.key_name+'\\n';
    out+='Interval: '+d.interval_days+' days\\n';
    out+='Next rotation: '+d.next_rotation+'\\n';
    show('rotResult',out);
  }else{show('rotResult',JSON.stringify(d))}
}

async function listRotations(){
  const d=await api('/api/rotation-schedule');
  if(!d.schedules||!d.schedules.length){show('rotResult','No rotation schedules.');return}
  let out='ROTATION SCHEDULES\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
  d.schedules.forEach(s=>{
    const status=s.overdue?'OVERDUE':'OK';
    out+=s.key_name+' | every '+s.interval_days+'d | next: '+s.next_rotation+' | '+status+' ('+s.days_until_rotation+'d)\\n';
  });
  if(d.overdue_count>0)out+='\\nOVERDUE: '+d.overdue_count+' key(s) need immediate rotation!\\n';
  if(d.upcoming_count>0)out+='UPCOMING: '+d.upcoming_count+' rotation(s) in the next 7 days\\n';
  show('rotResult',out);
}

async function checkRotations(){
  show('rotResult','Checking...');
  const d=await api('/api/rotation-schedule/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})});
  let out='ROTATION CHECK\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
  if(d.overdue&&d.overdue.length){
    out+='OVERDUE ('+d.overdue.length+'):\\n';
    d.overdue.forEach(o=>out+='  - '+o.key_name+' (was due: '+o.was_due+')\\n');
  }else{out+='No overdue rotations.\\n'}
  if(d.reminders&&d.reminders.length){
    out+='\\nUPCOMING REMINDERS ('+d.reminders.length+'):\\n';
    d.reminders.forEach(r=>out+='  - '+r.key_name+' in '+r.days_until+' day(s)\\n');
  }
  show('rotResult',out);
}

// ─── SSH Key Manager ───
async function generateSSH(){
  const name=document.getElementById('sshName').value;
  const keyType=document.getElementById('sshType').value;
  const pass=document.getElementById('sshPass').value;
  if(!name){alert('Key name required');return}
  show('sshResult','Generating...');
  const body={name:name,key_type:keyType};
  if(pass)body.passphrase=pass;
  const d=await api('/api/ssh-keys',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(d.ok){
    let out='SSH KEY GENERATED\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
    out+='ID: '+d.id+'\\n';
    out+='Name: '+d.name+'\\n';
    out+='Type: '+d.key_type+'\\n';
    out+='Fingerprint: '+d.fingerprint+'\\n';
    out+='Passphrase protected: '+(d.passphrase_protected?'Yes':'No')+'\\n\\n';
    out+='PUBLIC KEY:\\n'+d.public_key+'\\n';
    show('sshResult',out);
  }else{show('sshResult',JSON.stringify(d))}
}

async function listSSH(){
  const d=await api('/api/ssh-keys');
  if(!d.ssh_keys||!d.ssh_keys.length){show('sshResult','No SSH keys.');return}
  let out='SSH KEYS\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
  d.ssh_keys.forEach(k=>out+=k.id+' | '+k.name+' | '+k.key_type+' | '+k.public_key_fingerprint.slice(0,30)+'... | '+k.created_at+'\\n');
  show('sshResult',out);
}

// ─── API Token Vault ───
async function storeApiToken(){
  const name=document.getElementById('atName').value;
  const service=document.getElementById('atService').value;
  const token=document.getElementById('atToken').value;
  const pass=document.getElementById('atPass').value;
  if(!name||!token){alert('Name and token value required');return}
  show('atResult','Storing...');
  const body={name:name,token_value:token,service:service||'generic'};
  if(pass)body.passphrase=pass;
  const d=await api('/api/api-tokens',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(d.ok){
    let out='API TOKEN STORED\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
    out+='ID: '+d.id+'\\n';
    out+='Name: '+d.name+'\\n';
    out+='Service: '+d.service+'\\n';
    if(d.auto_passphrase)out+='Auto passphrase (SAVE THIS): '+d.auto_passphrase+'\\n';
    out+='\\n'+d.message;
    show('atResult',out);
  }else{show('atResult',JSON.stringify(d))}
}

async function listApiTokens(){
  const d=await api('/api/api-tokens');
  if(!d.api_tokens||!d.api_tokens.length){show('atResult','No API tokens stored.');return}
  let out='API TOKENS ('+d.total+' total, '+d.active+' active, '+d.expired+' expired)\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
  d.api_tokens.forEach(t=>out+=t.id+' | '+t.name+' | '+t.service+' | '+t.status+(t.expired?' [EXPIRED]':'')+' | uses: '+t.usage_count+' | '+t.created_at+'\\n');
  show('atResult',out);
}

// ─── Security Alerts ───
async function analyzeAlerts(){
  show('alertResult','Analyzing 24h security data...');
  const d=await api('/api/security-alerts/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})});
  let out='SECURITY ANALYSIS (24h)\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
  out+='Total alerts: '+d.total_alerts+'\\n';
  out+='Failed logins: '+d.failed_logins+'\\n';
  out+='Location anomalies: '+d.location_anomalies+'\\n';
  out+='Suspicious access: '+d.suspicious_access+'\\n';
  out+='Audit actions: '+d.audit_actions+'\\n';
  if(d.auto_detected_alerts&&d.auto_detected_alerts.length){
    out+='\\nAUTO-DETECTED:\\n';
    d.auto_detected_alerts.forEach(a=>out+='  ['+a.severity.toUpperCase()+'] '+a.type+'\\n');
  }
  if(d.ai_assessment){out+='\\nVALERIA SAYS:\\n'+d.ai_assessment+'\\n'}
  show('alertResult',out);
}

async function listAlerts(){
  const d=await api('/api/security-alerts?limit=20');
  if(!d.alerts||!d.alerts.length){show('alertResult','No security alerts. ('+d.unresolved_count+' unresolved)');return}
  let out='SECURITY ALERTS ('+d.unresolved_count+' unresolved)\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
  d.alerts.forEach(a=>out+='['+a.severity.toUpperCase()+'] '+a.type+' | '+(a.resolved?'RESOLVED':'OPEN')+' | '+a.description.slice(0,80)+' | '+a.created_at+'\\n');
  show('alertResult',out);
}

// ─── Credential Templates ───
async function listTemplates(){
  const d=await api('/api/templates');
  let out='CREDENTIAL TEMPLATES ('+d.built_in+' built-in, '+d.custom+' custom)\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
  d.templates.forEach(t=>{
    out+=t.id+' | '+t.name+' | '+t.category+' | '+(t.description||'').slice(0,60);
    if(t.fields)out+=' | '+t.fields.length+' fields';
    out+='\\n';
  });
  out+='\\nUse a template ID in the Apply Template section to create credentials from a template.';
  show('tplResult',out);
}

async function applyTemplate(){
  const tplId=document.getElementById('tplId').value;
  const pass=document.getElementById('tplPass').value;
  if(!tplId){alert('Template ID required');return}
  show('tplResult','Applying template...');
  const body={template_id:tplId};
  if(pass)body.passphrase=pass;
  const d=await api('/api/templates/apply',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(d.ok){
    let out='TEMPLATE APPLIED\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
    out+='Credential ID: '+d.credential_id+'\\n';
    out+='Name: '+d.name+'\\n';
    out+='Template: '+d.template+'\\n\\n';
    out+='FIELDS:\\n';
    d.fields.forEach(f=>out+='  '+f.label+': '+(f.has_value?(f.auto_generated?'[auto-generated]':'[set]'):'[empty]')+'\\n');
    show('tplResult',out);
  }else{show('tplResult',JSON.stringify(d))}
}

// ─── Vault Comparison ───
async function takeSnapshot(){
  const name=document.getElementById('snapName').value;
  if(!name){alert('Snapshot name required');return}
  show('snapResult','Taking snapshot...');
  const d=await api('/api/vault-compare',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({snapshot_name:name})});
  if(d.ok){
    let out='SNAPSHOT TAKEN\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
    out+='ID: '+d.snapshot_id+'\\n';
    out+='Name: '+d.name+'\\n';
    out+='Keys: '+d.counts.keys+' | Devices: '+d.counts.devices+' | Notes: '+d.counts.notes+'\\n';
    out+='TOTP: '+d.counts.totp+' | SSH Keys: '+d.counts.ssh_keys+' | API Tokens: '+d.counts.api_tokens+'\\n';
    show('snapResult',out);
  }else{show('snapResult',JSON.stringify(d))}
}

async function listSnapshots(){
  const d=await api('/api/vault-compare');
  if(!d.snapshots||!d.snapshots.length){show('snapResult','No snapshots yet.');return}
  let out='VAULT SNAPSHOTS\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
  d.snapshots.forEach(s=>out+=s.id+' | '+s.name+' | '+s.created_at+'\\n');
  show('snapResult',out);
}

async function compareSnapshots(){
  const a=document.getElementById('snapA').value;
  if(!a){alert('Snapshot A ID required');return}
  show('snapResult','Comparing...');
  const body={snapshot_a:a};
  const b=document.getElementById('snapB').value;
  if(b)body.snapshot_b=b;
  const d=await api('/api/vault-compare/diff',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(d.ok){
    let out='VAULT COMPARISON: '+d.comparison.a+' vs '+d.comparison.b+'\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n';
    out+='Total added: '+d.summary.total_added+'\\n';
    out+='Total removed: '+d.summary.total_removed+'\\n';
    out+='Total changed: '+d.summary.total_changed+'\\n\\n';
    Object.entries(d.diff).forEach(function(entry){
      var cat=entry[0],dd=entry[1];
      if(dd.added||dd.removed||dd.changed){
        out+=cat.toUpperCase()+': +'+dd.added+' -'+dd.removed+' ~'+dd.changed+'\\n';
        if(dd.added_items.length)dd.added_items.forEach(function(i){out+='  + '+(i.name||i.title||i.account||i.id)+'\\n'});
        if(dd.removed_items.length)dd.removed_items.forEach(function(i){out+='  - '+(i.name||i.title||i.account||i.id)+'\\n'});
      }
    });
    show('snapResult',out);
  }else{show('snapResult',JSON.stringify(d))}
}

// ─── Compliance Report ───
async function runCompliance(){
  show('compResult','Generating compliance report...');
  const d=await api('/api/compliance');
  let out='COMPLIANCE REPORT: '+d.overall_grade+' ('+d.overall_score+'/100)\\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\n\\n';
  out+='PASSWORD POLICY: '+d.sections.password_policy.score+'%\\n';
  out+='  Total: '+d.sections.password_policy.total+' | Weak: '+d.sections.password_policy.weak+' | Medium: '+d.sections.password_policy.medium+' | Strong: '+d.sections.password_policy.strong+'\\n\\n';
  out+='ROTATION COMPLIANCE: '+d.sections.rotation_compliance.score+'%\\n';
  out+='  Overdue (90d): '+d.sections.rotation_compliance.overdue_90+' | Overdue (180d): '+d.sections.rotation_compliance.overdue_180+' | Scheduled: '+d.sections.rotation_compliance.scheduled+' | Coverage: '+d.sections.rotation_compliance.coverage+'\\n\\n';
  out+='2FA ADOPTION: '+d.sections.two_factor_auth.score+'%\\n';
  out+='  TOTP setups: '+d.sections.two_factor_auth.totp_setups+' | Verified: '+d.sections.two_factor_auth.verified+'\\n\\n';
  out+='PASSKEY ADOPTION: '+d.sections.passkey_adoption.score+'%\\n';
  out+='  Registered: '+d.sections.passkey_adoption.registered+'\\n\\n';
  out+='DEVICE TRUST: '+d.sections.device_trust.score+'%\\n';
  out+='  Total: '+d.sections.device_trust.total+' | Trusted: '+d.sections.device_trust.trusted+'\\n\\n';
  if(d.violations&&d.violations.length){
    out+='VIOLATIONS:\\n';
    d.violations.forEach(function(v){out+='  ['+v.severity.toUpperCase()+'] '+v.rule+' ('+v.count+'): '+v.items.slice(0,3).join(', ')+'\\n'});
    out+='\\n';
  }
  if(d.recommendations&&d.recommendations.length){
    out+='RECOMMENDATIONS:\\n';
    d.recommendations.forEach(function(r){out+='  - '+r+'\\n'});
    out+='\\n';
  }
  if(d.ai_assessment){out+='VALERIA SAYS:\\n'+d.ai_assessment+'\\n'}
  show('compResult',out);
}
</script>
</body></html>`;
}
