#!/usr/bin/env python3
"""ZeroSpecter Viewer & Runner (Termux).

سيرفر محلي بدون مكتبات خارجية:
  - يشغّل الفحص من الواجهة بعد تأكيد صريح للتفويض
  - كل فحص يُحفظ بمجلد  ZeroSpecter/log N  فيه ملفات التقرير الأربعة
  - يعرض النتائج بواجهة عربية/إنجليزية
  - يستمع على 127.0.0.1 فقط

التشغيل:  python zs_server.py      ثم افتح  http://127.0.0.1:8765
"""
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = "1.1"
HOME = Path.home()
PORT = int(os.environ.get("PORT", "8765"))
HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
ZS_HOME = Path(os.environ.get("ZS_HOME", str(HOME / "zerospecter"))).expanduser()
REPORTS = Path(os.environ.get("ZS_REPORTS", str(HOME / ".zerospecter" / "reports"))).expanduser()  # قديم
RUN_TMP = Path(os.environ.get("ZS_TMP", str(HOME / ".zs_run"))).expanduser()

ID_RE = re.compile(r"^[A-Za-z0-9]{6,32}$")
LOG_RE = re.compile(r"^log (\d+)$")
TARGET_RE = re.compile(r"^https?://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:\d{1,5})?(/[^\s]*)?$")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
MODULES = ["infra", "origin", "files", "dirs", "params", "tech", "vuln"]


def pick_logs():
    """مكان حفظ اللوغات: ذاكرة الجوال إذا تيرمكس معه إذن، وإلا مجلد تيرمكس."""
    env = os.environ.get("ZS_LOGS")
    if env:
        return Path(env).expanduser()
    for base in (Path("/sdcard"), HOME / "storage" / "shared"):
        try:
            if base.is_dir() and os.access(base, os.W_OK):
                return base / "ZeroSpecter"
        except OSError:
            pass
    return HOME / "ZeroSpecter"


LOGS = pick_logs()


# ---------------------------------------------------------------- reports
def load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def log_dirs():
    out = []
    try:
        if LOGS.is_dir():
            for d in LOGS.iterdir():
                m = LOG_RE.match(d.name)
                if m and d.is_dir():
                    out.append((int(m.group(1)), d))
    except OSError:
        pass
    return out


def find(scan_id, ext):
    if not ID_RE.match(scan_id):
        return None
    for _, d in sorted(log_dirs(), reverse=True):
        for p in d.glob(f"*_{scan_id}.{ext}"):
            return p
    if REPORTS.is_dir():
        for p in REPORTS.glob(f"*_{scan_id}.{ext}"):
            return p
    return None


def list_scans():
    items = []
    for n, d in log_dirs():
        items += [(n, p) for p in d.glob("*.json")]
    if REPORTS.is_dir():
        items += [(None, p) for p in REPORTS.glob("*.json")]
    items.sort(key=lambda x: x[1].stat().st_mtime, reverse=True)
    out, seen = [], set()
    for n, p in items:
        sid = p.stem.rsplit("_", 1)[-1]
        if sid in seen:
            continue
        d = load(p)
        if not isinstance(d, dict):
            continue
        seen.add(sid)
        s = d.get("summary") or {}
        out.append({
            "id": sid,
            "log": n,
            "target": s.get("target", p.stem),
            "started_at": s.get("started_at") or d.get("generated_at"),
            "duration": s.get("duration_seconds"),
            "completed": s.get("completed"),
            "interrupted": s.get("interrupted"),
            "severity": s.get("severity_counts") or {},
            "has_html": find(sid, "html") is not None,
        })
    return out


def public_scan(d):
    """نشيل أي حقول تعريفية من البيانات الخام قبل ما نعرضها."""
    if isinstance(d, dict):
        return {k: v for k, v in d.items() if str(k).lower() != "modder"}
    return d


# ---------------------------------------------------------------- runner
class Run:
    lock = threading.Lock()
    proc = None
    target = ""
    started = 0.0
    ended = None
    code = None
    logname = None
    log = deque(maxlen=400)


def running():
    return Run.proc is not None and Run.ended is None


def finalize(started):
    """ينقل ملفات التقرير لمجلد  log N  بذاكرة الجوال."""
    global LOGS
    files = [p for p in RUN_TMP.glob("*") if p.is_file()] if RUN_TMP.is_dir() else []
    if not files and REPORTS.is_dir():  # إذا الأداة تجاهلت -o
        files = [p for p in REPORTS.glob("*") if p.is_file() and p.stat().st_mtime >= started - 2]
    if not files:
        Run.log.append("! الأداة ما طلّعت ملفات تقرير")
        return None
    try:
        LOGS.mkdir(parents=True, exist_ok=True)
        probe = LOGS / ".w"
        probe.write_text("1")
        probe.unlink()
    except OSError:
        LOGS = HOME / "ZeroSpecter"
        LOGS.mkdir(parents=True, exist_ok=True)
        Run.log.append("! ما قدرت أكتب بذاكرة الجوال (شغّل termux-setup-storage). انحفظ بمجلد تيرمكس: ~/ZeroSpecter")
    n = max([x for x, _ in log_dirs()] or [0]) + 1
    dest = LOGS / f"log {n}"
    dest.mkdir()
    for p in files:
        shutil.copy2(p, dest / p.name)
    shutil.rmtree(RUN_TMP, ignore_errors=True)
    Run.log.append(f"✔ انحفظ: {dest}")
    return f"log {n}"


def pump(proc):
    try:
        for raw in proc.stdout:
            line = ANSI_RE.sub("", raw).replace("\r", "").rstrip()
            if line.strip():
                Run.log.append(line[:400])
    except Exception:
        pass
    code = proc.wait()
    name = None
    try:
        name = finalize(Run.started)
    except Exception as e:
        Run.log.append(f"! تعذّر حفظ اللوغ: {e}")
    with Run.lock:
        if Run.proc is proc:
            Run.code, Run.logname, Run.ended = code, name, time.time()


def start_run(target, modules):
    if not ZS_HOME.is_dir():
        return False, f"مجلد الأداة غير موجود: {ZS_HOME}"
    with Run.lock:
        if running():
            return False, "في فحص شغّال حالياً"
        shutil.rmtree(RUN_TMP, ignore_errors=True)
        RUN_TMP.mkdir(parents=True, exist_ok=True)
        cmd = [sys.executable, "-c", "from zerospecter.cli import main; main()", target,
               "--yes", "--i-have-authorization", "--no-ui", "--no-open",
               "--formats", "json,html,csv,sarif", "-o", str(RUN_TMP)]
        if modules and modules != ["all"]:
            cmd += ["-m", ",".join(modules)]
        env = dict(os.environ, PYTHONPATH=str(ZS_HOME), PYTHONUNBUFFERED="1", NO_COLOR="1")
        try:
            proc = subprocess.Popen(cmd, cwd=str(ZS_HOME), env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, errors="replace",
                                    start_new_session=True)
        except OSError as e:
            return False, f"تعذّر تشغيل الأداة: {e}"
        Run.proc, Run.target, Run.started = proc, target, time.time()
        Run.ended, Run.code, Run.logname = None, None, None
        Run.log.clear()
        Run.log.append(f"$ {target}")
    threading.Thread(target=pump, args=(proc,), daemon=True).start()
    return True, ""


def stop_run():
    with Run.lock:
        if not running() or Run.proc.poll() is not None:
            return False
        proc = Run.proc
    try:
        os.killpg(proc.pid, signal.SIGINT)  # Ctrl+C: الأداة بتحفظ تقرير جزئي
    except Exception:
        proc.terminate()

    def hard():
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                proc.kill()
    threading.Timer(8, hard).start()
    return True


def run_status():
    return {
        "running": running(),
        "target": Run.target,
        "started": Run.started,
        "ended": Run.ended,
        "now": time.time(),
        "code": Run.code,
        "log_name": Run.logname,
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
        if path == "/api/info":
            return self.json({"version": VERSION, "logs": str(LOGS), "tool": ZS_HOME.is_dir()})
        if path == "/api/scans":
            return self.json(list_scans())
        if path == "/api/run":
            return self.json(run_status())
        m = re.match(r"^/api/scan/([A-Za-z0-9]+)$", path)
        if m:
            p = find(m.group(1), "json")
            d = load(p) if p else None
            return self.json(public_scan(d)) if d is not None else self.json({"error": "not found"}, 404)
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
            return self.json({"error": "bad request"}, 400)

        if path == "/api/run":
            target = str(data.get("target", "")).strip()
            if data.get("authorized") is not True:
                return self.json({"error": "authorization required"}, 400)
            if not TARGET_RE.match(target):
                return self.json({"error": "invalid target (http:// or https://)"}, 400)
            mods = data.get("modules") or ["all"]
            if not isinstance(mods, list) or not all(m == "all" or m in MODULES for m in mods):
                return self.json({"error": "invalid modules"}, 400)
            mods = ["all"] if "all" in mods else mods
            ok, msg = start_run(target, mods)
            return self.json({"ok": True} if ok else {"error": msg}, 200 if ok else 409)

        if path == "/api/run/stop":
            return self.json({"ok": stop_run()})
        self.json({"error": "not found"}, 404)


PAGE = r"""<!doctype html>
<html lang="ar" dir="rtl" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0b0d12">
<link rel="manifest" href="/manifest.json">
<title>ZeroSpecter</title>
<style>
:root{--bg:#0b0d12;--card:#151922;--card2:#1c2230;--txt:#e8ecf3;--mut:#8b93a7;--line:#252c3b;--pre:#0a0c10;
--hdr:rgba(11,13,18,.92);--nav:rgba(21,25,34,.96);
--critical:#ff4d6d;--high:#ff8a4c;--medium:#ffc857;--low:#4cc9f0;--info:#7b8cff;--ok:#3ddc97;--acc:#ff4d6d}
:root[data-theme=light]{--bg:#f4f6fa;--card:#fff;--card2:#eef1f7;--txt:#161b26;--mut:#5d667a;--line:#dde2ec;--pre:#f0f3f9;
--hdr:rgba(244,246,250,.94);--nav:rgba(255,255,255,.97);
--critical:#d6264a;--high:#d9650f;--medium:#a87a00;--low:#1b8db3;--info:#4a5be0;--ok:#16915f;--acc:#e0294f}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Tahoma,sans-serif;
padding-bottom:calc(76px + env(safe-area-inset-bottom))}
header{position:sticky;top:0;z-index:5;background:var(--hdr);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.hrow{padding:14px 16px;display:flex;align-items:center;gap:10px}
header h1{font-size:17px;margin:0;flex:1}
.back{background:none;border:0;color:var(--txt);font-size:22px;padding:0 4px;display:none}
#runbar{display:none;align-items:center;gap:10px;padding:9px 16px;font-size:14px;font-weight:600;color:#fff;background:var(--acc);text-decoration:none}
#runbar.done{background:var(--ok)}
#runbar .t{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.spin{width:16px;height:16px;border:3px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;animation:sp .8s linear infinite;flex:none}
.spin.big{width:20px;height:20px;border-color:var(--line);border-top-color:var(--acc)}
@keyframes sp{to{transform:rotate(360deg)}}
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
.chip{border-radius:999px;padding:2px 10px;font-size:12px;font-weight:600;border:1px solid currentColor;white-space:nowrap}
.c-critical{color:var(--critical)}.c-high{color:var(--high)}.c-medium{color:var(--medium)}
.c-low{color:var(--low)}.c-info{color:var(--info)}.c-ok{color:var(--ok)}
.tiles{display:grid;grid-template-columns:repeat(5,1fr);gap:6px;margin:12px 0 4px}
.tile{background:var(--card2);border:1px solid var(--line);border-radius:12px;padding:8px 2px;text-align:center;color:var(--txt);font:inherit}
.tile b{display:block;font-size:20px;line-height:1.2}
.tile span{font-size:11px}
.tile.on{outline:2px solid currentColor}
h2{font-size:15px;margin:18px 0 10px;color:var(--mut);font-weight:600}
.f{border-inline-start:4px solid var(--info)}
.f.critical{border-color:var(--critical)}.f.high{border-color:var(--high)}
.f.medium{border-color:var(--medium)}.f.low{border-color:var(--low)}
.k{font-size:12px;color:var(--mut);margin:12px 0 4px;font-weight:600}
.v{margin:0;word-break:break-word}
pre{background:var(--pre);border:1px solid var(--line);border-radius:12px;padding:10px;overflow:auto;margin:0;
font-size:12px;direction:ltr;text-align:left;max-height:260px;white-space:pre-wrap;word-break:break-all}
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
.seg{display:flex;gap:8px}
.seg button{flex:1;padding:12px;border-radius:12px;border:1px solid var(--line);background:var(--card2);color:var(--txt);font:inherit;font-weight:600}
.seg button.on{background:var(--acc);border-color:var(--acc);color:#fff}
.kv{display:flex;justify-content:space-between;gap:12px;padding:8px 0;border-bottom:1px solid var(--line)}
.kv:last-child{border:0}
nav{position:fixed;bottom:0;inset-inline:0;background:var(--nav);backdrop-filter:blur(12px);
border-top:1px solid var(--line);display:flex;padding-bottom:env(safe-area-inset-bottom)}
nav a{flex:1;text-align:center;padding:10px 0 8px;color:var(--mut);text-decoration:none;font-size:12px}
nav a b{display:block;font-size:20px;font-weight:400}
nav a.on{color:var(--acc)}
.empty{text-align:center;color:var(--mut);padding:50px 10px}
details summary{cursor:pointer}
</style>
</head>
<body>
<header>
 <div class="hrow"><button class="back" id="back"></button><h1 id="title">ZeroSpecter</h1><button class="btn ghost" id="reload" style="padding:8px 14px"></button></div>
 <a id="runbar" href="#/"></a>
</header>
<main id="app"></main>
<nav>
 <a href="#/" id="n-scan"><b>&#9654;</b><span></span></a>
 <a href="#/history" id="n-hist"><b>&#9776;</b><span></span></a>
 <a href="#/settings" id="n-set"><b>&#9881;</b><span></span></a>
</nav>
<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const LS={get(k,d){try{return localStorage.getItem(k)||d}catch(e){return d}},set(k,v){try{localStorage.setItem(k,v)}catch(e){}}};
let lang=LS.get('zs_lang','ar'),theme=LS.get('zs_theme','dark');
if(lang!=='ar'&&lang!=='en')lang='ar';if(theme!=='dark'&&theme!=='light')theme='dark';

const I={
ar:{nav_scan:'فحص',nav_hist:'السجل',nav_set:'الإعدادات',reload:'تحديث',t_scan:'فحص جديد',t_hist:'السجل',t_set:'الإعدادات',t_det:'تفاصيل الفحص',
 target:'رابط الهدف',mods:'الوحدات',m_all:'الكل',m_infra:'البنية',m_origin:'المصدر',m_files:'ملفات حساسة',m_dirs:'مجلدات',m_params:'باراميترات',m_tech:'تقنيات',m_vuln:'فحص الويب',
 auth:'أؤكد أني أملك هذا الموقع أو معي إذن كتابي بفحصه. الفحص بدون إذن ممنوع قانونياً.',start:'ابدأ الفحص',stop:'إيقاف',
 bar_run:'الفحص بدأ وجاري',bar_done:'انتهى الفحص، اضغط لعرض النتيجة',running:'جاري الفحص...',
 s_done:'اكتمل الفحص',s_stop:'تم إيقاف الفحص',s_err:'انتهى بخطأ',s_cfg:'خطأ بالإعدادات',s_auth:'التفويض ناقص',saved:'انحفظ بـ',toast:'بدأ الفحص',view:'عرض النتيجة',
 search:'بحث بالهدف...',empty_hist:'ما في فحوصات بعد',done:'مكتمل',incomplete:'غير مكتمل',interrupted:'الفحص انقطع قبل ما يكتمل.',orig:'التقرير الأصلي',
 findings:'النتائج',no_find:'ما في نتائج بهالفحص.',sev_critical:'حرجة',sev_high:'عالية',sev_medium:'وسط',sev_low:'منخفضة',sev_info:'معلومة',
 f_loc:'الموقع',f_ev:'الدليل',f_fix:'طريقة الحل',f_tip:'نصيحة عامة',f_more:'تفاصيل إضافية',f_none:'غير متوفر',
 modules_h:'الوحدات',skipped_h:'وحدات تم تخطيها',raw_h:'البيانات الخام',raw_show:'عرض JSON',req:'طلبات',res:'نتائج',
 lang:'اللغة',theme:'المظهر',dark:'غامق',light:'فاتح',info:'معلومات التطبيق',ver:'الإصدار',desc:'واجهة موبايل لفحص الأمان، بتشتغل مع أداة ZeroSpecter على تيرمكس.',
 store:'مكان حفظ اللوغات',tool:'الأداة',tool_ok:'موجودة',tool_no:'غير موجودة',resp_h:'استخدام مسؤول',
 resp:'استخدم التطبيق فقط على مواقع تملكها أو معك إذن كتابي بفحصها. المستخدم مسؤول عن استخدامه.',err:'تعذّر تحميل البيانات.',m:'د',s:'ث'},
en:{nav_scan:'Scan',nav_hist:'History',nav_set:'Settings',reload:'Refresh',t_scan:'New scan',t_hist:'History',t_set:'Settings',t_det:'Scan details',
 target:'Target URL',mods:'Modules',m_all:'All',m_infra:'Infra',m_origin:'Origin',m_files:'Sensitive files',m_dirs:'Directories',m_params:'Parameters',m_tech:'Technology',m_vuln:'Web checks',
 auth:'I confirm I own this site or have written permission to test it. Testing without permission is illegal.',start:'Start scan',stop:'Stop',
 bar_run:'Scan started and running',bar_done:'Scan finished, tap to view the result',running:'Scanning...',
 s_done:'Scan completed',s_stop:'Scan stopped',s_err:'Finished with an error',s_cfg:'Configuration error',s_auth:'Missing authorization',saved:'Saved in',toast:'Scan started',view:'View result',
 search:'Search by target...',empty_hist:'No scans yet',done:'Completed',incomplete:'Incomplete',interrupted:'The scan was interrupted before it finished.',orig:'Original report',
 findings:'Findings',no_find:'No findings in this scan.',sev_critical:'Critical',sev_high:'High',sev_medium:'Medium',sev_low:'Low',sev_info:'Info',
 f_loc:'Location',f_ev:'Evidence',f_fix:'How to fix',f_tip:'General tip',f_more:'More details',f_none:'Not available',
 modules_h:'Modules',skipped_h:'Skipped modules',raw_h:'Raw data',raw_show:'Show JSON',req:'requests',res:'findings',
 lang:'Language',theme:'Appearance',dark:'Dark',light:'Light',info:'App info',ver:'Version',desc:'A mobile front-end for security scanning, working with the ZeroSpecter tool on Termux.',
 store:'Logs folder',tool:'Tool',tool_ok:'Found',tool_no:'Not found',resp_h:'Responsible use',
 resp:'Use this app only on sites you own or have written permission to test. You are responsible for how you use it.',err:'Could not load data.',m:'m',s:'s'}
};
const t=k=>(I[lang][k]!==undefined?I[lang][k]:(I.ar[k]!==undefined?I.ar[k]:k));
const SEV=['critical','high','medium','low','info'];
const MODS=['all','infra','origin','files','dirs','params','tech','vuln'];
const STOPPED=[130,143,-2,-9,-15];

/* نصائح عامة حسب نوع الثغرة (تظهر فقط إذا الأداة ما كتبت حلاً) */
const TIPS=[
 [/xss|cross.?site script/i,'رمّز (escape) كل مدخل يظهر بالصفحة، وفعّل Content-Security-Policy، وتحقّق من المدخلات.','Escape all user input rendered in pages, enable a Content-Security-Policy, and validate inputs.'],
 [/sql/i,'استخدم استعلامات مهيّأة (Prepared Statements) ولا تدمج مدخلات المستخدم بالاستعلام مباشرة.','Use prepared statements and never concatenate user input into queries.'],
 [/lfi|traversal|inclusion|path/i,'امنع استخدام مدخلات المستخدم بمسارات الملفات، واعتمد قائمة بيضاء للملفات المسموحة.','Never use user input in file paths; allow only a whitelist of files.'],
 [/redirect/i,'تحقق من وجهة التحويل واسمح فقط بنطاقات معروفة.','Validate redirect targets and allow only known domains.'],
 [/ssrf/i,'امنع الطلبات للعناوين الداخلية، واعتمد قائمة بيضاء للوجهات.','Block requests to internal addresses and whitelist allowed destinations.'],
 [/csrf/i,'استخدم رموز CSRF وخاصية SameSite للكوكيز.','Use CSRF tokens and SameSite cookies.'],
 [/cors/i,'لا تسمح بـ * مع بيانات الاعتماد، وحدّد النطاقات الموثوقة فقط.','Do not allow * with credentials; list trusted origins only.'],
 [/cookie/i,'فعّل Secure وHttpOnly وSameSite على الكوكيز.','Set Secure, HttpOnly and SameSite on cookies.'],
 [/header|hsts|x-frame|csp|content-security|clickjack/i,'أضف ترويسات الأمان المفقودة (HSTS، X-Frame-Options، CSP، X-Content-Type-Options).','Add the missing security headers (HSTS, X-Frame-Options, CSP, X-Content-Type-Options).'],
 [/ssl|tls|cert|https/i,'استخدم TLS 1.2+ وشهادة صالحة، وفعّل إعادة التوجيه لـ HTTPS.','Use TLS 1.2+ with a valid certificate and redirect HTTP to HTTPS.'],
 [/listing|index of|autoindex/i,'عطّل عرض محتويات المجلدات (directory listing) بإعدادات السيرفر.','Disable directory listing in the server configuration.'],
 [/\.env|\.git|backup|config|sensitive|exposed|secret|leak|\.bak|dump/i,'شيل الملفات الحساسة والنسخ الاحتياطية من مجلد الموقع العام، وامنع الوصول إليها، وغيّر أي مفاتيح أو كلمات سر ظهرت.','Remove sensitive files and backups from the web root, block access to them, and rotate any exposed keys or passwords.'],
 [/banner|version|server|disclos|fingerprint/i,'أخفِ أرقام الإصدارات ومعلومات السيرفر من الترويسات والصفحات.','Hide version numbers and server details from headers and pages.'],
 [/admin|login|panel|auth/i,'قيّد الوصول للوحة الإدارة (IP محدد أو VPN) وفعّل مصادقة قوية وحد المحاولات.','Restrict admin panels (IP allow-list or VPN), enforce strong authentication and rate limiting.']
];
const TIP_DEFAULT=['حدّث البرمجيات للأحدث، وقيّد الوصول، وراجع الإعدادات المرتبطة بهذه النتيجة.','Update software, restrict access, and review the settings related to this finding.'];

const app=$('#app');
let cache=null,info={},gstate=null,tickBase=0,tickAt=0,sel=new Set(['all']),fsev=null,curScan=null;

async function api(p){const r=await fetch(p);if(!r.ok)throw new Error(r.status);return r.json()}
async function post(p,b){const r=await fetch(p,{method:'POST',headers:{'Content-Type':'application/json','X-ZS':'1'},body:JSON.stringify(b||{})});
 const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||r.status);return j}
const fdate=s=>{if(!s)return '';try{return new Date(s).toLocaleString(lang==='ar'?'ar':'en-GB',{dateStyle:'medium',timeStyle:'short'})}catch(e){return s}};
const fdur=s=>s==null?'':(s>=60?Math.floor(s/60)+t('m')+' '+Math.round(s%60)+t('s'):Math.round(s)+t('s'));

function applyLook(){
 const h=document.documentElement;h.lang=lang;h.dir=lang==='ar'?'rtl':'ltr';h.dataset.theme=theme;
 $('meta[name=theme-color]').content=theme==='dark'?'#0b0d12':'#f4f6fa';
 $('#back').textContent=lang==='ar'?'→':'←';
 $('#reload').textContent=t('reload');
 $('#n-scan span').textContent=t('nav_scan');$('#n-hist span').textContent=t('nav_hist');$('#n-set span').textContent=t('nav_set');
 drawBar();
}
function setNav(k){[['scan','n-scan'],['hist','n-hist'],['set','n-set']].forEach(([a,id])=>$('#'+id).className=a===k?'on':'')}
function show(html,title,back){
 app.innerHTML='<div class="view">'+html+'</div>';
 $('#title').textContent=title||'ZeroSpecter';
 $('#back').style.display=back?'block':'none';
 window.scrollTo(0,0);
}
function sevName(k){return t('sev_'+k)}
function chips(sev){
 const x=SEV.filter(k=>sev&&sev[k]).map(k=>`<span class="chip c-${k}">${sevName(k)} ${sev[k]}</span>`).join('');
 return x||'<span class="chip c-ok">0</span>';
}
async function scans(force){if(!cache||force)cache=await api('/api/scans');return cache}

/* ---------- شريط الفحص (يظهر بكل الصفحات) ---------- */
let doneUntil=0;
function drawBar(){
 const b=$('#runbar');const st=gstate;
 if(st&&st.running){
  b.className='';b.style.display='flex';b.href='#/';
  b.innerHTML=`<span class="spin"></span><span class="t">${esc(t('bar_run'))}: <span class="ltr" style="display:inline">${esc(st.target)}</span></span><span class="tm">${fdur(elapsed())}</span>`;
 }else if(Date.now()<doneUntil){
  b.className='done';b.style.display='flex';b.href='#/history';
  b.innerHTML=`<span>&#10004;</span><span class="t">${esc(t('bar_done'))}</span>`;
 }else{b.style.display='none'}
}
function elapsed(){return gstate?(tickBase+(Date.now()-tickAt)/1000):0}
setInterval(()=>{
 if(gstate&&gstate.running){const a=document.querySelector('.tm');if(a)a.textContent=fdur(elapsed());const c=$('#rtm');if(c)c.textContent=fdur(elapsed())}
 else if(doneUntil&&Date.now()>=doneUntil){doneUntil=0;drawBar()}
},1000);

async function gpoll(){
 try{
  const st=await api('/api/run');const was=gstate&&gstate.running;
  gstate=st;tickBase=(st.ended||st.now)-st.started;tickAt=Date.now();
  if(was&&!st.running){cache=null;doneUntil=Date.now()+20000}
  drawBar();renderRun();
 }catch(e){}
}
setInterval(gpoll,2000);

/* ---------- فحص جديد ---------- */
function drawMods(){
 $('#mods').innerHTML=MODS.map(k=>`<button type="button" class="mb ${sel.has(k)?'on':''}" data-k="${k}">${t('m_'+k)}</button>`).join('');
}
function check(){
 const tg=$('#tg');if(!tg)return;
 const ok=/^https?:\/\/\S+$/i.test(tg.value.trim())&&$('#auth').checked&&!(gstate&&gstate.running);
 $('#go').disabled=!ok;
}
function renderRun(){
 const box=$('#runbox');if(!box)return;check();
 const st=gstate;if(!st||!st.started){box.style.display='none';return}
 box.style.display='block';
 let head;
 if(st.running)head=`<span class="spin big"></span><b class="c-medium">${t('running')}</b><span class="mut" id="rtm">${fdur(elapsed())}</span>`;
 else{
  const k=st.code===0?'s_done':STOPPED.includes(st.code)?'s_stop':st.code===2?'s_cfg':st.code===3?'s_auth':'s_err';
  head=`<b class="${st.code===0?'c-ok':'c-high'}">${st.code===0?'&#10004; ':''}${t(k)}</b>`;
 }
 $('#rhead').innerHTML=head;
 $('#stop').style.display=st.running?'inline-block':'none';
 $('#rtg').textContent=st.target;
 $('#rsave').textContent=(!st.running&&st.log_name)?`${t('saved')}: ${st.log_name}`:'';
 const lg=$('#rlog');const atEnd=lg.scrollTop+lg.clientHeight>=lg.scrollHeight-20;
 lg.textContent=st.log.join('\n');if(atEnd)lg.scrollTop=lg.scrollHeight;
 $('#rlink').innerHTML=(!st.running&&st.log_name)?`<a class="btn" href="#/last">${t('view')}</a>`:'';
}
async function scanView(){
 setNav('scan');
 show(`<div class="card">
  <label class="lbl" for="tg">${t('target')}</label>
  <input id="tg" class="inp ltr" placeholder="https://example.com" inputmode="url" autocapitalize="off" autocomplete="off" spellcheck="false">
  <label class="lbl">${t('mods')}</label><div class="row" id="mods"></div>
  <label class="chk"><input type="checkbox" id="auth"><span>${t('auth')}</span></label>
  <button class="btn" id="go" disabled style="width:100%">${t('start')}</button>
  <p id="err" style="color:var(--critical);margin:10px 0 0"></p></div>
  <div class="card" id="runbox" style="display:none">
   <div class="row sp"><div class="row" id="rhead"></div><button class="btn ghost" id="stop" style="display:none;padding:8px 14px">${t('stop')}</button></div>
   <div class="mut ltr" id="rtg" style="margin:6px 0 10px"></div><pre id="rlog"></pre>
   <p class="mut" id="rsave" style="margin:10px 0 0"></p><p id="rlink" style="margin:10px 0 0"></p></div>`,t('t_scan'));
 drawMods();
 $('#mods').onclick=e=>{const k=e.target.dataset&&e.target.dataset.k;if(!k)return;
  if(k==='all')sel=new Set(['all']);else{sel.delete('all');sel.has(k)?sel.delete(k):sel.add(k);if(!sel.size)sel=new Set(['all'])}drawMods()};
 $('#tg').oninput=check;$('#auth').onchange=check;
 $('#go').onclick=async()=>{
  $('#err').textContent='';$('#go').disabled=true;
  try{
   await post('/api/run',{target:$('#tg').value.trim(),modules:[...sel],authorized:$('#auth').checked});
   try{navigator.vibrate&&navigator.vibrate(80)}catch(e){}
   try{window.Android&&Android.toast&&Android.toast(t('toast'))}catch(e){}
   await gpoll();window.scrollTo(0,0);
  }catch(e){$('#err').textContent=e.message;check()}};
 $('#stop').onclick=async()=>{try{await post('/api/run/stop')}catch(e){}gpoll()};
 await gpoll();
}

/* ---------- السجل ---------- */
function scanCard(s){
 return `<a class="card" href="#/scan/${esc(s.id)}">
  <div class="row sp"><b class="ltr">${esc(s.target)}</b>
  <span class="chip ${s.completed?'c-ok':'c-medium'}">${s.completed?t('done'):t('incomplete')}</span></div>
  <div class="mut" style="margin:4px 0 8px">${s.log?'log '+s.log+' &middot; ':''}${fdate(s.started_at)} &middot; ${fdur(s.duration)}</div>
  <div class="row">${chips(s.severity)}</div></a>`;
}
async function history(){
 setNav('hist');
 const list=await scans(true);
 show(list.length?`<input id="q" class="inp ltr" placeholder="${esc(t('search'))}" style="margin-bottom:12px"><div id="hl">${list.map(scanCard).join('')}</div>`
  :`<div class="empty">${t('empty_hist')}</div>`,t('t_hist'));
 const q=$('#q');if(q)q.oninput=()=>{const v=q.value.toLowerCase();$('#hl').innerHTML=list.filter(s=>(s.target||'').toLowerCase().includes(v)).map(scanCard).join('')};
}

/* ---------- تفاصيل فحص ---------- */
const pick=(o,ks)=>{for(const k of ks){if(o[k]!=null&&o[k]!=='')return [k,o[k]]}return [null,'']};
const txt=v=>typeof v==='object'?JSON.stringify(v,null,2):String(v);
function normSev(v){v=String(v||'info').toLowerCase();if(v.startsWith('crit'))return 'critical';if(v==='informational')return 'info';if(v==='moderate')return 'medium';return SEV.includes(v)?v:'info'}
function tipFor(s){for(const [re,ar,en] of TIPS){if(re.test(s))return lang==='ar'?ar:en}return lang==='ar'?TIP_DEFAULT[0]:TIP_DEFAULT[1]}
function findingHTML(f){
 const used=new Set(['severity']);
 const [kt,title]=pick(f,['title','name','label','vuln_type','type','category','check','rule','rule_id','id','kind']);if(kt)used.add(kt);
 const [kc,cat]=pick(f,['type','category','kind','check','vuln_type']);
 const [kl,loc]=pick(f,['url','target','location','path','endpoint','uri']);if(kl)used.add(kl);
 const [kp,par]=pick(f,['parameter','param']);if(kp)used.add(kp);
 const [ke,ev]=pick(f,['evidence','proof','detail','details','match','matched','signature','snippet','indicator','reason']);if(ke)used.add(ke);
 const [kf,fix]=pick(f,['remediation','fix','solution','recommendation','mitigation','how_to_fix','advice','remedy']);if(kf)used.add(kf);
 const [kd,desc]=pick(f,['description','summary','message']);if(kd)used.add(kd);
 const sev=normSev(f.severity);
 const tstr=txt(title||'finding');
 const sub=(kc&&txt(cat)!==tstr)?`<div class="mut">${esc(txt(cat))}</div>`:'';
 const rest={};Object.keys(f).forEach(k=>{if(!used.has(k)&&String(k).toLowerCase()!=='modder')rest[k]=f[k]});
 const na=`<span class="mut">${t('f_none')}</span>`;
 const where=loc?esc(txt(loc))+(par?` <span class="mut">(${esc(txt(par))})</span>`:''):na;
 const evHTML=ev!==''?`<pre>${esc(txt(ev)).slice(0,2500)}</pre>`:na;
 const fixHTML=fix!==''?`<p class="v" dir="auto">${esc(txt(fix))}</p>`
  :`<p class="v" dir="auto">${esc(tipFor(tstr+' '+txt(cat||'')+' '+txt(loc||'')))} <span class="mut">(${t('f_tip')})</span></p>`;
 return `<div class="card f ${sev}"><div class="row sp"><b dir="auto">${esc(tstr)}</b><span class="chip c-${sev}">${sevName(sev)}</span></div>${sub}
  ${desc?`<p class="v" dir="auto" style="margin-top:8px">${esc(txt(desc))}</p>`:''}
  <div class="k">${t('f_loc')}</div><div class="ltr v">${where}</div>
  <div class="k">${t('f_ev')}</div>${evHTML}
  <div class="k">${t('f_fix')}</div>${fixHTML}
  ${Object.keys(rest).length?`<details style="margin-top:10px"><summary class="mut">${t('f_more')}</summary><pre style="margin-top:8px">${esc(JSON.stringify(rest,null,2))}</pre></details>`:''}</div>`;
}
function drawFindings(){
 const d=curScan;if(!d)return;
 const all=(Array.isArray(d.findings)?d.findings:[]).slice().sort((a,b)=>SEV.indexOf(normSev(a.severity))-SEV.indexOf(normSev(b.severity)));
 const fl=fsev?all.filter(f=>normSev(f.severity)===fsev):all;
 $('#fl').innerHTML=fl.length?fl.map(findingHTML).join(''):`<div class="empty">${t('no_find')}</div>`;
 document.querySelectorAll('.tile').forEach(e=>e.classList.toggle('on',e.dataset.k===fsev));
}
async function scanView2(id){
 setNav('hist');
 if(id==='last'){const l=await scans(true);if(!l.length){location.hash='#/history';return}id=l[0].id}
 const d=await api('/api/scan/'+id);curScan=d;fsev=null;
 const s=d.summary||{};
 const fl=Array.isArray(d.findings)?d.findings:[];
 let sev=Object.assign({},s.severity_counts||{});
 if(!SEV.some(k=>sev[k])&&fl.length){sev={};fl.forEach(f=>{const k=normSev(f.severity);sev[k]=(sev[k]||0)+1})}
 const mods=(s.modules||[]).map(m=>`<div class="card"><div class="row sp"><b>${esc(m.title||m.name)}</b>
  <span class="chip ${m.status==='completed'?'c-ok':'c-medium'}">${esc(m.status)}</span></div>
  <div class="mut">${t('res')}: ${m.findings??0} &middot; ${t('req')}: ${m.requests??0} &middot; ${fdur(m.duration_seconds)}</div></div>`).join('');
 const skipped=(s.coverage||{}).skipped||{};
 const sk=Object.keys(skipped).map(k=>`<div class="card"><b class="ltr">${esc(k)}</b><div class="mut">${esc(skipped[k])}</div></div>`).join('');
 const l=await scans();const meta=l.find(x=>x.id===id)||{};
 show(`<div class="card"><b class="ltr">${esc(s.target)}</b>
  <div class="mut" style="margin:4px 0">${meta.log?'log '+meta.log+' &middot; ':''}${fdate(s.started_at)} &middot; ${fdur(s.duration_seconds)}</div>
  <div class="tiles">${SEV.map(k=>`<button class="tile c-${k}" data-k="${k}"><b>${sev[k]||0}</b><span>${sevName(k)}</span></button>`).join('')}</div>
  ${s.interrupted?`<p class="c-medium" style="margin:8px 0 0">${t('interrupted')}</p>`:''}
  ${meta.has_html?`<p style="margin:12px 0 0"><a class="btn" href="/report/${esc(id)}.html">${t('orig')}</a></p>`:''}</div>
  <h2>${t('findings')} (${fl.length})</h2><div id="fl"></div>
  <h2>${t('modules_h')}</h2>${mods||'<div class="mut">-</div>'}
  ${sk?`<h2>${t('skipped_h')}</h2>${sk}`:''}
  <h2>${t('raw_h')}</h2><details class="card"><summary>${t('raw_show')}</summary><pre style="margin-top:10px">${esc(JSON.stringify(d,null,2).slice(0,60000))}</pre></details>`,t('t_det'),true);
 document.querySelectorAll('.tile').forEach(e=>e.onclick=()=>{fsev=fsev===e.dataset.k?null:e.dataset.k;drawFindings()});
 drawFindings();
}

/* ---------- الإعدادات ---------- */
async function settings(){
 setNav('set');
 try{info=await api('/api/info')}catch(e){}
 show(`<div class="card"><div class="k" style="margin-top:0">${t('lang')}</div>
   <div class="seg" id="sl"><button data-v="ar" class="${lang==='ar'?'on':''}">العربية</button><button data-v="en" class="${lang==='en'?'on':''}">English</button></div>
   <div class="k">${t('theme')}</div>
   <div class="seg" id="st"><button data-v="dark" class="${theme==='dark'?'on':''}">${t('dark')}</button><button data-v="light" class="${theme==='light'?'on':''}">${t('light')}</button></div></div>
  <h2>${t('info')}</h2>
  <div class="card"><b>ZeroSpecter</b><p class="mut" style="margin:4px 0 8px">${t('desc')}</p>
   <div class="kv"><span>${t('ver')}</span><b class="ltr">${esc(info.version||'')}</b></div>
   <div class="kv"><span>${t('tool')}</span><b class="${info.tool?'c-ok':'c-high'}">${info.tool?t('tool_ok'):t('tool_no')}</b></div>
   <div class="kv"><span>${t('store')}</span><b class="ltr" style="font-size:13px;text-align:end">${esc(info.logs||'')}</b></div></div>
  <div class="card"><b>${t('resp_h')}</b><p class="mut" style="margin:6px 0 0">${t('resp')}</p></div>`,t('t_set'));
 $('#sl').onclick=e=>{const v=e.target.dataset&&e.target.dataset.v;if(!v)return;lang=v;LS.set('zs_lang',v);applyLook();settings()};
 $('#st').onclick=e=>{const v=e.target.dataset&&e.target.dataset.v;if(!v)return;theme=v;LS.set('zs_theme',v);applyLook();settings()};
}

async function route(){
 const h=location.hash||'#/';
 try{
  if(h.startsWith('#/scan/'))await scanView2(h.slice(7));
  else if(h==='#/last')await scanView2('last');
  else if(h==='#/history')await history();
  else if(h==='#/settings')await settings();
  else await scanView();
 }catch(e){show(`<div class="empty">${t('err')}<br><span class="mut">${esc(e.message)}</span></div>`)}
}
$('#back').onclick=()=>history.length>1?history.back():(location.hash='#/history');
$('#reload').onclick=async()=>{cache=null;await route()};
addEventListener('hashchange',route);
applyLook();route();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    print(f"ZeroSpecter {VERSION}  ->  http://127.0.0.1:{PORT}")
    print(f"اللوغات: {LOGS}")
    if not str(LOGS).startswith("/sdcard") and "storage" not in str(LOGS):
        print("تنبيه: لحفظ اللوغات بذاكرة الجوال نفّذ:  termux-setup-storage  وبعدين أعد تشغيل السيرفر")
    print(f"الأداة:   {ZS_HOME}")
    try:
        ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        pass
