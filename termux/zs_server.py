#!/usr/bin/env python3
"""ZeroSpecter Viewer & Runner (Termux).

سيرفر محلي بدون مكتبات خارجية:
  - يعرض تقارير ZeroSpecter (JSON) بواجهة عربية للموبايل
  - يشغّل الفحص من الواجهة بعد تأكيد صريح للتفويض
  - يستمع على 127.0.0.1 فقط

التشغيل:  python zs_server.py      ثم افتح  http://127.0.0.1:8765
"""
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOME = Path.home()
REPORTS = Path(os.environ.get("ZS_REPORTS", str(HOME / ".zerospecter" / "reports"))).expanduser()
ZS_HOME = Path(os.environ.get("ZS_HOME", str(HOME / "zerospecter"))).expanduser()
PORT = int(os.environ.get("PORT", "8765"))
HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}

ID_RE = re.compile(r"^[A-Za-z0-9]{6,32}$")
TARGET_RE = re.compile(r"^https?://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:\d{1,5})?(/[^\s]*)?$")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
MODULES = ["infra", "origin", "files", "dirs", "params", "tech", "vuln"]


# ---------------------------------------------------------------- reports
def load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def find(scan_id, ext):
    if not ID_RE.match(scan_id):
        return None
    for p in REPORTS.glob(f"*_{scan_id}.{ext}"):
        return p
    return None


def list_scans():
    out = []
    if not REPORTS.is_dir():
        return out
    files = sorted(REPORTS.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    for p in files:
        d = load(p)
        if not isinstance(d, dict):
            continue
        s = d.get("summary") or {}
        sev = s.get("severity_counts") or {}
        sid = p.stem.rsplit("_", 1)[-1]
        out.append({
            "id": sid,
            "target": s.get("target", p.stem),
            "started_at": s.get("started_at") or d.get("generated_at"),
            "duration": s.get("duration_seconds"),
            "completed": s.get("completed"),
            "interrupted": s.get("interrupted"),
            "severity": sev,
            "has_html": find(sid, "html") is not None,
        })
    return out


# ---------------------------------------------------------------- runner
class Run:
    lock = threading.Lock()
    proc = None
    target = ""
    started = 0.0
    ended = None
    code = None
    log = deque(maxlen=400)


def running():
    return Run.proc is not None and Run.proc.poll() is None


def pump(proc):
    try:
        for raw in proc.stdout:
            line = ANSI_RE.sub("", raw).replace("\r", "").rstrip()
            if line.strip():
                Run.log.append(line[:400])
    except Exception:
        pass
    code = proc.wait()
    with Run.lock:
        if Run.proc is proc:
            Run.code = code
            Run.ended = time.time()


def start_run(target, modules):
    if not ZS_HOME.is_dir():
        return False, f"مجلد الأداة غير موجود: {ZS_HOME}"
    with Run.lock:
        if running():
            return False, "في فحص شغّال حالياً"
        cmd = [sys.executable, "-c", "from zerospecter.cli import main; main()", target,
               "--yes", "--i-have-authorization", "--no-ui", "--no-open",
               "--formats", "json,html,csv,sarif"]
        if modules and modules != ["all"]:
            cmd += ["-m", ",".join(modules)]
        env = dict(os.environ, PYTHONPATH=str(ZS_HOME), PYTHONUNBUFFERED="1", NO_COLOR="1")
        try:
            proc = subprocess.Popen(cmd, cwd=str(ZS_HOME), env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, errors="replace",
                                    start_new_session=True)
        except OSError as e:
            return False, f"تعذّر تشغيل الأداة: {e}"
        Run.proc, Run.target, Run.started, Run.ended, Run.code = proc, target, time.time(), None, None
        Run.log.clear()
        Run.log.append(f"$ فحص {target}")
    threading.Thread(target=pump, args=(proc,), daemon=True).start()
    return True, ""


def stop_run():
    with Run.lock:
        if not running():
            return False
        try:
            os.killpg(Run.proc.pid, signal.SIGTERM)
        except Exception:
            Run.proc.terminate()
        return True


def run_status():
    return {
        "running": running(),
        "target": Run.target,
        "started": Run.started,
        "ended": Run.ended,
        "now": time.time(),
        "code": Run.code,
        "log": list(Run.log)[-120:],
    }


# ---------------------------------------------------------------- http
MANIFEST = {
    "name": "ZeroSpecter", "short_name": "ZeroSpecter", "start_url": "/", "display": "standalone",
    "background_color": "#0b0d12", "theme_color": "#0b0d12",
    "icons": [{"src": "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 96 96'%3E%3Crect width='96' height='96' rx='22' fill='%23ff4d6d'/%3E%3Ctext x='48' y='64' font-size='54' text-anchor='middle' fill='white'%3EZ%3C/text%3E%3C/svg%3E",
               "sizes": "any", "type": "image/svg+xml"}],
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def json(self, obj, code=200):
        self.send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    # حماية من مواقع خارجية تحاول تكلّم السيرفر المحلي (DNS rebinding / CSRF)
    def host_ok(self):
        return self.headers.get("Host", "") in HOSTS

    def write_ok(self):
        origin = self.headers.get("Origin")
        if origin and origin.replace("http://", "", 1) not in HOSTS:
            return False
        return self.headers.get("X-ZS") == "1"

    def do_GET(self):
        if not self.host_ok():
            return self.json({"error": "forbidden"}, 403)
        path = self.path.split("?", 1)[0]
        if path == "/":
            return self.send(200, PAGE, "text/html; charset=utf-8")
        if path == "/manifest.json":
            return self.json(MANIFEST)
        if path == "/api/scans":
            return self.json(list_scans())
        if path == "/api/run":
            return self.json(run_status())
        m = re.match(r"^/api/scan/([A-Za-z0-9]+)$", path)
        if m:
            p = find(m.group(1), "json")
            d = load(p) if p else None
            return self.json(d) if d is not None else self.json({"error": "not found"}, 404)
        m = re.match(r"^/report/([A-Za-z0-9]+)\.html$", path)
        if m:
            p = find(m.group(1), "html")
            if p:
                return self.send(200, p.read_bytes(), "text/html; charset=utf-8")
        self.send(404, "not found", "text/plain")

    def do_POST(self):
        if not self.host_ok() or not self.write_ok():
            return self.json({"error": "forbidden"}, 403)
        path = self.path.split("?", 1)[0]
        try:
            n = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(n) or b"{}") if 0 <= n <= 4096 else None
        except Exception:
            data = None
        if not isinstance(data, dict):
            return self.json({"error": "طلب غير صالح"}, 400)

        if path == "/api/run":
            target = str(data.get("target", "")).strip()
            if data.get("authorized") is not True:
                return self.json({"error": "لازم تأكّد التفويض قبل الفحص"}, 400)
            if not TARGET_RE.match(target):
                return self.json({"error": "رابط الهدف غير صالح (لازم يبدأ بـ http:// أو https://)"}, 400)
            mods = data.get("modules") or ["all"]
            if not isinstance(mods, list) or not all(m == "all" or m in MODULES for m in mods):
                return self.json({"error": "وحدات غير صالحة"}, 400)
            mods = ["all"] if "all" in mods else mods
            ok, msg = start_run(target, mods)
            return self.json({"ok": True} if ok else {"error": msg}, 200 if ok else 409)

        if path == "/api/run/stop":
            return self.json({"ok": stop_run()})
        self.json({"error": "not found"}, 404)


PAGE = r"""<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0b0d12">
<link rel="manifest" href="/manifest.json">
<title>ZeroSpecter</title>
<style>
:root{--bg:#0b0d12;--card:#151922;--card2:#1c2230;--txt:#e8ecf3;--mut:#8b93a7;--line:#252c3b;
--critical:#ff4d6d;--high:#ff8a4c;--medium:#ffc857;--low:#4cc9f0;--info:#7b8cff;--ok:#3ddc97;--acc:#ff4d6d}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Tahoma,sans-serif;
padding-bottom:calc(76px + env(safe-area-inset-bottom))}
header{position:sticky;top:0;z-index:5;background:rgba(11,13,18,.9);backdrop-filter:blur(10px);
padding:14px 16px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:10px}
header h1{font-size:17px;margin:0;flex:1}
header .back{background:none;border:0;color:var(--txt);font-size:22px;padding:0 4px;display:none}
main{padding:16px;max-width:720px;margin:0 auto}
.view{animation:in .28s ease}
@keyframes in{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:14px;margin-bottom:12px}
a.card{display:block;color:inherit;text-decoration:none;transition:transform .15s,background .15s}
a.card:active{transform:scale(.98);background:var(--card2)}
.ltr{direction:ltr;unicode-bidi:isolate;text-align:left;word-break:break-all}
.mut{color:var(--mut);font-size:13px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.sp{justify-content:space-between}
.chip{border-radius:999px;padding:2px 10px;font-size:12px;font-weight:600;border:1px solid currentColor}
.c-critical{color:var(--critical)}.c-high{color:var(--high)}.c-medium{color:var(--medium)}
.c-low{color:var(--low)}.c-info{color:var(--info)}.c-ok{color:var(--ok)}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:12px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:14px}
.stat b{display:block;font-size:26px}
.bar{display:flex;height:10px;border-radius:99px;overflow:hidden;background:var(--card2);margin:10px 0}
.bar i{display:block;transition:width .6s}
h2{font-size:15px;margin:18px 0 10px;color:var(--mut);font-weight:600}
.f{border-inline-start:4px solid var(--info);padding-inline-start:10px}
.f.critical{border-color:var(--critical)}.f.high{border-color:var(--high)}
.f.medium{border-color:var(--medium)}.f.low{border-color:var(--low)}
pre{background:#0a0c10;border:1px solid var(--line);border-radius:12px;padding:12px;overflow:auto;
font-size:12px;direction:ltr;text-align:left;max-height:360px;white-space:pre-wrap;word-break:break-all}
button.btn,a.btn{background:var(--acc);color:#fff;border:0;border-radius:12px;padding:12px 16px;font:inherit;
font-weight:600;text-decoration:none;display:inline-block;text-align:center}
button.btn:disabled{opacity:.4}
button.ghost{background:var(--card2);color:var(--txt)}
.lbl{display:block;margin:12px 0 6px;color:var(--mut);font-size:13px}
.inp{width:100%;padding:12px;border-radius:12px;border:1px solid var(--line);background:var(--bg);color:var(--txt);font:inherit}
.mb{background:var(--card2);color:var(--mut);border:1px solid var(--line);border-radius:999px;padding:6px 12px;font:inherit;font-size:13px}
.mb.on{background:var(--acc);color:#fff;border-color:var(--acc)}
.chk{display:flex;gap:10px;align-items:flex-start;margin:16px 0;padding:12px;border:1px solid var(--line);border-radius:12px;background:var(--card2)}
.chk input{width:22px;height:22px;margin:2px 0 0;flex:none;accent-color:var(--acc)}
nav{position:fixed;bottom:0;inset-inline:0;background:rgba(21,25,34,.95);backdrop-filter:blur(12px);
border-top:1px solid var(--line);display:flex;padding-bottom:env(safe-area-inset-bottom)}
nav a{flex:1;text-align:center;padding:10px 0 8px;color:var(--mut);text-decoration:none;font-size:12px}
nav a b{display:block;font-size:20px;font-weight:400}
nav a.on{color:var(--acc)}
.empty{text-align:center;color:var(--mut);padding:50px 10px}
</style>
</head>
<body>
<header><button class="back" id="back">&rarr;</button><h1 id="title">ZeroSpecter</h1><button class="btn ghost" id="reload" style="padding:8px 14px">تحديث</button></header>
<main id="app"></main>
<nav>
<a href="#/" id="n-home"><b>&#9632;</b>الرئيسية</a>
<a href="#/run" id="n-run"><b>&#9654;</b>فحص</a>
<a href="#/history" id="n-hist"><b>&#9776;</b>السجل</a>
<a href="#/about" id="n-about"><b>&#9432;</b>عن التطبيق</a>
</nav>
<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const SEV=['critical','high','medium','low','info'];
const SEVAR={critical:'حرجة',high:'عالية',medium:'متوسطة',low:'منخفضة',info:'معلومة'};
const MODS=[['all','الكل'],['infra','البنية'],['origin','المصدر'],['files','ملفات حساسة'],['dirs','مجلدات'],['params','باراميترات'],['tech','تقنيات'],['vuln','فحص الويب']];
const CODES={0:'اكتمل الفحص',1:'انتهى بخطأ',2:'خطأ بالإعدادات',3:'التفويض ناقص',130:'تم إيقاف الفحص',143:'تم إيقاف الفحص','-15':'تم إيقاف الفحص'};
const app=$('#app');
let cache=null,timer=null,sel=new Set(['all']);

async function api(p){const r=await fetch(p);if(!r.ok)throw new Error(r.status);return r.json()}
async function post(p,b){const r=await fetch(p,{method:'POST',headers:{'Content-Type':'application/json','X-ZS':'1'},body:JSON.stringify(b||{})});
  const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||r.status);return j}
const fdate=s=>{if(!s)return '';try{return new Date(s).toLocaleString('ar',{dateStyle:'medium',timeStyle:'short'})}catch(e){return s}};
const fdur=s=>s==null?'':(s>=60?Math.floor(s/60)+'د '+Math.round(s%60)+'ث':Math.round(s)+'ث');

function chips(sev){
  const x=SEV.filter(k=>sev&&sev[k]).map(k=>`<span class="chip c-${k}">${SEVAR[k]} ${sev[k]}</span>`).join('');
  return x||'<span class="chip c-ok">لا ثغرات</span>';
}
function bar(sev){
  const t=SEV.reduce((a,k)=>a+(sev[k]||0),0);
  if(!t)return '';
  return '<div class="bar">'+SEV.map(k=>sev[k]?`<i style="width:${sev[k]/t*100}%;background:var(--${k})"></i>`:'').join('')+'</div>';
}
function show(html,title,back){
  if(timer){clearInterval(timer);timer=null}
  app.innerHTML='<div class="view">'+html+'</div>';
  $('#title').textContent=title||'ZeroSpecter';
  $('#back').style.display=back?'block':'none';
  window.scrollTo(0,0);
}
function setNav(k){[['h','n-home'],['r','n-run'],['s','n-hist'],['a','n-about']].forEach(([a,id])=>$('#'+id).className=a===k?'on':'')}
async function scans(force){if(!cache||force)cache=await api('/api/scans');return cache}

async function home(){
  setNav('h');
  const list=await scans();
  if(!list.length)return show('<div class="empty">ما في تقارير لسا.<br><br><a class="btn" href="#/run">ابدأ أول فحص</a></div>','ZeroSpecter');
  const tot={};list.forEach(s=>SEV.forEach(k=>tot[k]=(tot[k]||0)+((s.severity||{})[k]||0)));
  const targets=new Set(list.map(s=>s.target)).size;
  show(`<div class="grid">
    <div class="stat"><b>${list.length}</b><span class="mut">عدد الفحوصات</span></div>
    <div class="stat"><b>${targets}</b><span class="mut">أهداف مختلفة</span></div></div>
   <div class="card"><div class="mut">مجموع النتائج حسب الخطورة</div>${bar(tot)}<div class="row">${chips(tot)}</div></div>
   <h2>آخر فحص</h2>${scanCard(list[0])}
   <h2>أحدث الفحوصات</h2>${list.slice(1,6).map(scanCard).join('')}`,'ZeroSpecter');
}
function scanCard(s){
  return `<a class="card" href="#/scan/${esc(s.id)}">
   <div class="row sp"><b class="ltr">${esc(s.target)}</b>
   <span class="chip ${s.completed?'c-ok':'c-medium'}">${s.completed?'مكتمل':'غير مكتمل'}</span></div>
   <div class="mut" style="margin:4px 0 8px">${fdate(s.started_at)} &middot; ${fdur(s.duration)}</div>
   <div class="row">${chips(s.severity)}</div></a>`;
}
async function history(){
  setNav('s');
  const list=await scans();
  show(list.length?`<input id="q" class="inp ltr" placeholder="بحث بالهدف..." style="margin-bottom:12px">
   <div id="hl">${list.map(scanCard).join('')}</div>`:'<div class="empty">السجل فاضي</div>','السجل');
  const q=$('#q');if(q)q.oninput=()=>{const v=q.value.toLowerCase();$('#hl').innerHTML=list.filter(s=>(s.target||'').toLowerCase().includes(v)).map(scanCard).join('')};
}
function findingHTML(f){
  const sev=String(f.severity||'info').toLowerCase();
  const title=f.title||f.label||f.name||f.id||'نتيجة';
  const desc=f.description||f.detail||f.summary||'';
  const where=f.url||f.target||f.location||f.path||'';
  const skip=['severity','title','label','name','description','detail','summary','url','target','location','path'];
  const rest={};Object.keys(f).forEach(k=>{if(!skip.includes(k))rest[k]=f[k]});
  return `<div class="card f ${esc(sev)}"><div class="row sp"><b>${esc(title)}</b><span class="chip c-${esc(sev)}">${esc(SEVAR[sev]||sev)}</span></div>
   ${where?`<div class="mut ltr">${esc(where)}</div>`:''}${desc?`<p style="margin:8px 0">${esc(desc)}</p>`:''}
   ${Object.keys(rest).length?`<details><summary class="mut">تفاصيل</summary><pre>${esc(JSON.stringify(rest,null,2))}</pre></details>`:''}</div>`;
}
async function scan(id){
  setNav('s');
  const d=await api('/api/scan/'+id);
  const s=d.summary||{};
  const sev=s.severity_counts||{};
  const mods=(s.modules||[]).map(m=>`<div class="card"><div class="row sp"><b>${esc(m.title||m.name)}</b>
    <span class="chip ${m.status==='completed'?'c-ok':'c-medium'}">${esc(m.status)}</span></div>
    <div class="mut">نتائج: ${m.findings??0} &middot; طلبات: ${m.requests??0} &middot; ${fdur(m.duration_seconds)}</div></div>`).join('');
  const skipped=(s.coverage||{}).skipped||{};
  const sk=Object.keys(skipped).map(k=>`<div class="card"><b class="ltr">${esc(k)}</b><div class="mut">${esc(skipped[k])}</div></div>`).join('');
  const fl=Array.isArray(d.findings)?d.findings:[];
  await scans();
  const hasHtml=(cache||[]).find(x=>x.id===id&&x.has_html);
  show(`<div class="card"><b class="ltr">${esc(s.target)}</b>
    <div class="mut" style="margin:4px 0">${fdate(s.started_at)} &middot; ${fdur(s.duration_seconds)}</div>
    ${bar(sev)}<div class="row">${chips(sev)}</div>
    ${s.interrupted?'<p class="c-medium">الفحص انقطع قبل ما يكتمل.</p>':''}
    ${hasHtml?`<p><a class="btn" href="/report/${esc(id)}.html">التقرير الأصلي</a></p>`:''}</div>
    ${fl.length?`<h2>النتائج (${fl.length})</h2>${fl.map(findingHTML).join('')}`:''}
    <h2>الوحدات</h2>${mods||'<div class="mut">لا يوجد</div>'}
    ${sk?`<h2>وحدات تم تخطيها</h2>${sk}`:''}
    <h2>البيانات الخام</h2><details class="card"><summary>عرض JSON</summary><pre>${esc(JSON.stringify(d,null,2).slice(0,60000))}</pre></details>`,'تفاصيل الفحص',true);
}

/* ---------- فحص جديد ---------- */
function drawMods(){
  $('#mods').innerHTML=MODS.map(([k,l])=>`<button type="button" class="mb ${sel.has(k)?'on':''}" data-k="${k}">${l}</button>`).join('');
}
function renderRun(st){
  const box=$('#runbox');
  if(!st.started){box.style.display='none';return}
  box.style.display='block';
  const el=Math.round(((st.ended||st.now)-st.started));
  $('#rst').textContent=st.running?('جاري الفحص... '+fdur(el)):(CODES[st.code]||('انتهى (رمز '+st.code+')'));
  $('#rst').className=st.running?'c-medium':(st.code===0?'c-ok':'c-high');
  $('#stop').style.display=st.running?'inline-block':'none';
  $('#rtg').textContent=st.target;
  const lg=$('#rlog');const atEnd=lg.scrollTop+lg.clientHeight>=lg.scrollHeight-20;
  lg.textContent=st.log.join('\n');if(atEnd)lg.scrollTop=lg.scrollHeight;
  $('#go').dataset.busy=st.running?'1':'';
  check();
}
async function poll(){
  try{
    const st=await api('/api/run');renderRun(st);
    if(!st.running&&timer){clearInterval(timer);timer=null;cache=null;
      if(st.started&&st.code===0){const l=await scans(true);if(l.length)$('#rlink').innerHTML=`<a class="btn" href="#/scan/${esc(l[0].id)}">عرض النتيجة</a>`}}
  }catch(e){}
}
function check(){
  const v=($('#tg')||{}).value||'';
  const ok=/^https?:\/\/\S+$/i.test(v.trim())&&$('#auth').checked&&!$('#go').dataset.busy;
  $('#go').disabled=!ok;
}
async function runView(){
  setNav('r');
  show(`<div class="card">
   <label class="lbl" for="tg">رابط الهدف</label>
   <input id="tg" class="inp ltr" placeholder="https://example.com" inputmode="url" autocapitalize="off" autocomplete="off" spellcheck="false">
   <label class="lbl">الوحدات</label><div class="row" id="mods"></div>
   <label class="chk"><input type="checkbox" id="auth"><span>أؤكد أني أملك هذا الموقع أو معي إذن كتابي بفحصه. الفحص بدون إذن ممنوع قانونياً.</span></label>
   <button class="btn" id="go" disabled style="width:100%">ابدأ الفحص</button>
   <p id="err" style="color:var(--critical);margin:10px 0 0"></p></div>
   <div class="card" id="runbox" style="display:none">
    <div class="row sp"><b id="rst">...</b><button class="btn ghost" id="stop" style="display:none;padding:8px 14px">إيقاف</button></div>
    <div class="mut ltr" id="rtg" style="margin:4px 0 10px"></div><pre id="rlog"></pre><p id="rlink"></p></div>`,'فحص جديد');
  drawMods();
  $('#mods').onclick=e=>{const k=e.target.dataset&&e.target.dataset.k;if(!k)return;
    if(k==='all')sel=new Set(['all']);else{sel.delete('all');sel.has(k)?sel.delete(k):sel.add(k);if(!sel.size)sel=new Set(['all'])}drawMods()};
  $('#tg').oninput=check;$('#auth').onchange=check;
  $('#go').onclick=async()=>{
    $('#err').textContent='';$('#go').disabled=true;
    try{await post('/api/run',{target:$('#tg').value.trim(),modules:[...sel],authorized:$('#auth').checked});
      $('#rlink').innerHTML='';timer=setInterval(poll,2000);poll()}
    catch(e){$('#err').textContent=e.message;check()}};
  $('#stop').onclick=async()=>{try{await post('/api/run/stop')}catch(e){}poll()};
  try{const st=await api('/api/run');renderRun(st);if(st.running)timer=setInterval(poll,2000)}catch(e){}
}

/* ---------- عن التطبيق ---------- */
function about(){
  setNav('a');
  show(`<div class="card"><b>ZeroSpecter</b><div class="mut">واجهة موبايل لأداة ZeroSpecter</div>
   <p>النسخة المعدّلة والواجهة: <b>Youssef</b></p>
   <p class="mut">الأداة الأصلية مفتوحة المصدر بترخيص MIT:<br><span class="ltr">github.com/AlmunharifHamoudi/zerospecter</span></p></div>
   <div class="card"><b>استخدام مسؤول</b>
   <p class="mut" style="margin:6px 0 0">استخدم الأداة فقط على مواقع تملكها أو معك إذن كتابي بفحصها. المستخدم هو المسؤول عن استخدامه.</p></div>
   <h2>ترخيص الأداة الأصلية</h2>
   <pre style="direction:ltr">MIT License

Copyright (c) 2026 ZeroSpecter Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.</pre>`,'عن التطبيق');
}

async function route(){
  const h=location.hash||'#/';
  try{
    if(h.startsWith('#/scan/'))await scan(h.slice(7));
    else if(h==='#/history')await history();
    else if(h==='#/run')await runView();
    else if(h==='#/about')about();
    else await home();
  }catch(e){show('<div class="empty">تعذّر تحميل البيانات.<br><span class="mut">'+esc(e.message)+'</span></div>')}
}
$('#back').onclick=()=>history.length>1?history.back():(location.hash='#/history');
$('#reload').onclick=async()=>{cache=null;await route()};
addEventListener('hashchange',route);
route();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    print(f"ZeroSpecter  ->  http://127.0.0.1:{PORT}")
    print(f"التقارير: {REPORTS}")
    print(f"الأداة:   {ZS_HOME}")
    try:
        ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        pass
