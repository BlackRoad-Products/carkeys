export interface Env { STORE: KVNamespace; DB: D1Database; SERVICE_NAME: string; VERSION: string; }
const SVC = "carkeys";
function json(d: unknown, s = 200) { return new Response(JSON.stringify(d,null,2),{status:s,headers:{"Content-Type":"application/json","Access-Control-Allow-Origin":"*","X-BlackRoad-Service":SVC}}); }
async function track(env: Env, req: Request, path: string) { const cf=(req as any).cf||{}; env.DB.prepare("INSERT INTO analytics(subdomain,path,country,ua,ts)VALUES(?,?,?,?,?)").bind(SVC,path,cf.country||"",req.headers.get("User-Agent")?.slice(0,150)||"",Date.now()).run().catch(()=>{}); }

function genKey(prefix="brk"): string {
  const bytes=new Uint8Array(24);crypto.getRandomValues(bytes);
  return prefix+"_"+Array.from(bytes).map(b=>b.toString(16).padStart(2,"0")).join("");
}

function page(): Response {
  const html=`<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CarKeys — API Key Vault</title>
<meta name="description" content="API key generation, access control, and validation for BlackRoad OS.">
<link rel="canonical" href="https://carkeys.blackroad.io/">
<meta property="og:title" content="CarKeys — API Key Vault">
<meta property="og:description" content="API key generation, access control, and validation for BlackRoad OS.">
<meta property="og:url" content="https://carkeys.blackroad.io/">
<meta property="og:type" content="website">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebApplication","name":"CarKeys","url":"https://carkeys.blackroad.io/","description":"API key generation, access control, and validation for BlackRoad OS.","applicationCategory":"SecurityApplication","publisher":{"@type":"Organization","name":"BlackRoad OS, Inc.","url":"https://blackroad.io"}}</script>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#030303;--card:#0a0a0a;--border:#111;--text:#f0f0f0;--sub:#444;--gold:#FF6B2B;--grad:linear-gradient(135deg,#FF6B2B,#FF6B2B)}
html,body{min-height:100vh;background:var(--bg);color:var(--text);font-family:'Space Grotesk',sans-serif}
.grad-bar{height:2px;background:var(--grad)}
.wrap{max-width:900px;margin:0 auto;padding:32px 20px}
h1{font-size:2rem;font-weight:700;background:var(--grad);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}
.sub{font-size:.75rem;color:var(--sub);font-family:'JetBrains Mono',monospace;margin-bottom:28px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px}
.ct{font-size:.65rem;color:var(--sub);text-transform:uppercase;letter-spacing:.08em;font-family:'JetBrains Mono',monospace;margin-bottom:14px}
label{display:block;font-size:.7rem;color:var(--sub);font-family:'JetBrains Mono',monospace;margin-bottom:5px;margin-top:10px;text-transform:uppercase}
input,select{width:100%;padding:9px 12px;background:#0d0d0d;border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:.82rem;outline:none}
input:focus,select:focus{border-color:var(--gold)}
.btn{margin-top:14px;padding:10px 20px;background:var(--gold);color:#000;border:none;border-radius:7px;cursor:pointer;font-weight:700;font-size:.85rem;width:100%}
.key-display{background:#050505;border:1px solid var(--border);border-radius:6px;padding:12px;font-family:'JetBrains Mono',monospace;font-size:.75rem;color:var(--gold);word-break:break-all;margin-top:10px;display:none}
.key-list{display:flex;flex-direction:column;gap:6px}
.key-item{background:#0d0d0d;border:1px solid var(--border);border-radius:7px;padding:10px 12px;display:flex;align-items:center;justify-content:space-between}
.key-name{font-size:.82rem;font-weight:600}
.key-meta{font-size:.65rem;color:var(--sub);font-family:'JetBrains Mono',monospace;margin-top:3px}
.key-preview{font-size:.68rem;font-family:'JetBrains Mono',monospace;color:#333}
.key-del{padding:3px 10px;background:rgba(255,34,85,.1);border:1px solid rgba(255,34,85,.2);border-radius:4px;cursor:pointer;font-size:.65rem;color:#FF2255;transition:all .15s}
.key-del:hover{background:rgba(255,34,85,.2)}
.scope-grid{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.scope{padding:4px 10px;background:#0d0d0d;border:1px solid var(--border);border-radius:4px;font-size:.68rem;cursor:pointer;color:var(--sub);font-family:'JetBrains Mono',monospace;transition:all .15s;user-select:none}
.scope.on{border-color:var(--gold);color:var(--gold)}
.stats-row{display:flex;gap:16px;margin-bottom:20px}
.stat{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px;flex:1;text-align:center}
.stat-n{font-size:1.6rem;font-weight:700;color:#e0e0e0}
.stat-l{font-size:.65rem;color:var(--sub);font-family:'JetBrains Mono',monospace;margin-top:3px}
@media(max-width:600px){.grid{grid-template-columns:1fr}}
</style></head><body>
<div class="grad-bar"></div>
<div class="wrap">
<h1>CarKeys</h1>
<div class="sub">carkeys.blackroad.io · api key vault · access control</div>
<div class="stats-row">
  <div class="stat"><div class="stat-n" id="s-total">0</div><div class="stat-l">total keys</div></div>
  <div class="stat"><div class="stat-n" id="s-active">0</div><div class="stat-l">active</div></div>
  <div class="stat"><div class="stat-n" id="s-scopes">4</div><div class="stat-l">scope types</div></div>
</div>
<div class="grid">
  <div class="card">
    <div class="ct">Generate Key</div>
    <label>Name / Label</label>
    <input type="text" id="k-name" placeholder="e.g. roadie-agent, pi-alice">
    <label>Owner</label>
    <input type="text" id="k-owner" placeholder="e.g. alexa, agent:lucidia">
    <label>Scopes</label>
    <div class="scope-grid">
      <div class="scope on" onclick="this.className='scope'+(this.className.includes('on')?'':' on')">read</div>
      <div class="scope" onclick="this.className='scope'+(this.className.includes('on')?'':' on')">write</div>
      <div class="scope" onclick="this.className='scope'+(this.className.includes('on')?'':' on')">admin</div>
      <div class="scope" onclick="this.className='scope'+(this.className.includes('on')?'':' on')">agent</div>
    </div>
    <label>Expires</label>
    <select id="k-expires"><option value="365">1 year</option><option value="90">90 days</option><option value="30">30 days</option><option value="7">7 days</option><option value="0">Never</option></select>
    <button class="btn" onclick="generate()">Generate Key</button>
    <div class="key-display" id="key-out"></div>
  </div>
  <div class="card">
    <div class="ct">Active Keys</div>
    <div class="key-list" id="key-list">Loading...</div>
  </div>
</div>
</div>
<script src="https://cdn.blackroad.io/br.js"></script>
<script>
async function generate(){
  var name=document.getElementById('k-name').value.trim()||'unnamed';
  var owner=document.getElementById('k-owner').value.trim()||'anonymous';
  var scopes=Array.from(document.querySelectorAll('.scope.on')).map(el=>el.textContent);
  var expires=parseInt(document.getElementById('k-expires').value);
  var r=await fetch('/api/keys',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,owner,scopes,expires_days:expires})});
  var d=await r.json();
  var out=document.getElementById('key-out');
  out.style.display='block';
  out.textContent=d.key;
  loadKeys();
}
async function loadKeys(){
  var r=await fetch('/api/keys');var d=await r.json();
  var n=d.keys?.length||0;
  document.getElementById('s-total').textContent=n;
  document.getElementById('s-active').textContent=d.keys?.filter(function(k){return k.active}).length||0;
  var list=document.getElementById('key-list');
  if(!n){list.innerHTML='<div style="color:var(--sub);font-size:.8rem;padding:12px">No keys yet. Generate one →</div>';return;}
  list.innerHTML=d.keys.map(function(k){return'<div class="key-item"><div><div class="key-name">'+k.name+'</div><div class="key-meta">'+k.owner+' · '+k.scopes?.join(',')+' · '+new Date(k.created_at).toLocaleDateString()+'</div><div class="key-preview">'+k.key_preview+'</div></div><button class="key-del" onclick="del(\''+k.id+'\')">Revoke</button></div>';}).join('');
}
async function del(id){if(!confirm('Revoke this key?'))return;await fetch('/api/keys/'+id,{method:'DELETE'});loadKeys();}
loadKeys();
</script>
</body></html>`;
  return new Response(html,{headers:{"Content-Type":"text/html;charset=UTF-8"}});
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if(req.method==="OPTIONS")return new Response(null,{status:204,headers:{"Access-Control-Allow-Origin":"*"}});
    const url=new URL(req.url);const path=url.pathname;const parts=path.split("/").filter(Boolean);
    track(env,req,path);
    if(path==="/health")return json({service:SVC,status:"ok",version:env.VERSION,ts:Date.now()});
    if(path==="/api/keys"&&req.method==="GET"){
      const list=await env.STORE.list({prefix:"key:"});
      const keys=await Promise.all(list.keys.map(async k=>{const v=await env.STORE.get(k.name);if(!v)return null;const d=JSON.parse(v);return{...d,key_preview:d.key?.slice(0,16)+"...",key:undefined};}));
      return json({keys:keys.filter(Boolean)});
    }
    if(path==="/api/keys"&&req.method==="POST"){
      const b=await req.json() as any;
      const id=crypto.randomUUID();const key=genKey("brk");
      const now=Date.now();const expires=b.expires_days>0?now+b.expires_days*86400000:null;
      const entry={id,name:b.name,owner:b.owner,scopes:b.scopes||["read"],key,created_at:now,expires_at:expires,active:true};
      const ttl=b.expires_days>0?b.expires_days*86400:undefined;
      await env.STORE.put(`key:${id}`,JSON.stringify(entry),ttl?{expirationTtl:ttl}:{});
      return json({ok:true,id,key,name:b.name,scopes:b.scopes});
    }
    if(parts[0]==="api"&&parts[1]==="keys"&&parts[2]&&req.method==="DELETE"){
      const raw=await env.STORE.get(`key:${parts[2]}`);
      if(!raw)return json({error:"Not found"},404);
      const d=JSON.parse(raw);d.active=false;
      await env.STORE.put(`key:${parts[2]}`,JSON.stringify(d));
      return json({ok:true});
    }
    if(path==="/api/validate"&&req.method==="POST"){
      const {key}=await req.json() as {key:string};
      const list=await env.STORE.list({prefix:"key:"});
      for(const k of list.keys){const v=await env.STORE.get(k.name);if(!v)continue;const d=JSON.parse(v);if(d.key===key&&d.active){return json({valid:true,owner:d.owner,scopes:d.scopes,name:d.name});}}
      return json({valid:false},401);
    }
    return page();
  }
};
