#!/usr/bin/env python3
"""WebScout Viewer & Runner (Termux).

Local server with no external libraries:
  - Starts scans from the UI after explicit authorization is confirmed
  - Each scan is saved to a WebScout/log N folder with its four report files
  - Shows results in an Arabic/English UI
  - Listens on 127.0.0.1 only

Run:  python zs_server.py      then open  http://127.0.0.1:8765
"""
import base64
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = "1.2"
HOME = Path.home()
PORT = int(os.environ.get("PORT", "8765"))
HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
ZS_HOME = Path(os.environ.get("ZS_HOME", str(HOME / "webscout-engine"))).expanduser()
REPORTS = Path(os.environ.get("ZS_REPORTS", str(HOME / ".webscout" / "reports"))).expanduser()  # fallback folder, used only if -o is ignored
RUN_TMP = Path(os.environ.get("ZS_TMP", str(HOME / ".zs_run"))).expanduser()

ID_RE = re.compile(r"^[A-Za-z0-9]{6,32}$")
LOG_RE = re.compile(r"^log (\d+)$")
TARGET_RE = re.compile(r"^https?://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:\d{1,5})?(/[^\s]*)?$")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
MODULES = ["infra", "origin", "files", "dirs", "params", "tech", "vuln"]
DEV_KEY = HOME / ".webscout-dev" / "license_private.pem"  # exists only on the developer's phone
DEV_FEATURES = {"deep"}
DEVICE_RE = re.compile(r"^[0-9a-f]{8,32}$")
NAME_RE = re.compile(base64.b64decode(b"VmxQXzEyfEFsbXVuaGFyaWZcdyp8TW9kZGVyfFlvdXNzZWZ8WmVyb1NwZWN0ZXJ8emVyb3NwZWN0ZXI=").decode(), re.I)  # encoded: keeps the words out of plain text
CATCH_PORTS = (47931, 51337, 39119)
HIDDEN_KEYS = {"developer", base64.b64decode(b"bW9kZGVy").decode()}  # internal fields never shown


def pick_logs():
    """Log location: phone storage if Termux has permission, otherwise the Termux folder."""
    env = os.environ.get("ZS_LOGS")
    if env:
        return Path(env).expanduser()
    for base in (Path("/sdcard"), HOME / "storage" / "shared"):
        try:
            if base.is_dir() and os.access(base, os.W_OK):
                return base / "WebScout"
        except OSError:
            pass
    return HOME / "WebScout"


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
    """Strip internal fields from the raw data before serving it."""
    if not isinstance(d, dict):
        return d
    out = {k: v for k, v in d.items() if str(k).lower() not in HIDDEN_KEYS}
    # The raw file nests findings under report.modules[].findings; flatten them for the UI.
    if not isinstance(out.get("findings"), list):
        flat = []
        for mod in (out.get("report") or {}).get("modules") or []:
            for f in mod.get("findings") or []:
                g = dict(f)
                g.setdefault("module", mod.get("title") or mod.get("name") or "")
                flat.append(g)
        out["findings"] = flat
    return out


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
    catch_all = False


def running():
    return Run.proc is not None and Run.ended is None


def scrub(obj):
    """Remove the developer field and author names from every string in a report."""
    if isinstance(obj, dict):
        return {k: scrub(v) for k, v in obj.items() if str(k).lower() not in HIDDEN_KEYS}
    if isinstance(obj, list):
        return [scrub(x) for x in obj]
    if isinstance(obj, str):
        return NAME_RE.sub("", obj)
    return obj


def sanitize_reports(files, catch_all):
    """Remove author names; if the site accepts all ports, mark port findings as unreliable."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for p in files:
        try:
            if p.suffix == ".json":
                data = scrub(json.loads(p.read_text(encoding="utf-8")))
                for mod in (data.get("report", {}).get("modules") or []):
                    for f in mod.get("findings") or []:
                        if catch_all and f.get("check") == "exposed-service":
                            f["severity"] = "info"
                            f["catch_all"] = True
                            f["impact"] = "Unreliable result: the site accepts connections on all ports."
                        sev = f.get("severity", "info")
                        counts[sev] = counts.get(sev, 0) + 1
                    for o in mod.get("observations") or []:
                        if catch_all and o.get("kind") == "port":
                            o["severity"] = "info"
                if isinstance(data.get("summary"), dict) and catch_all:
                    data["summary"]["severity_counts"] = counts
                p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            elif p.suffix == ".html":
                html = p.read_text(encoding="utf-8")
                html = re.sub(r"<p>\s*Developed by.*?</p>", "", html, flags=re.S)
                p.write_text(NAME_RE.sub("", html), encoding="utf-8")
            elif p.suffix in (".csv", ".sarif"):
                p.write_text(NAME_RE.sub("", p.read_text(encoding="utf-8")), encoding="utf-8")
        except Exception:
            pass


def scrub_old_reports():
    """Startup cleanup: strip author names from reports saved before this version."""
    for _, d in log_dirs():
        try:
            sanitize_reports([p for p in d.iterdir() if p.is_file()], False)
        except OSError:
            pass


def finalize(started):
    """Move report files into a log N folder on phone storage."""
    global LOGS
    files = [p for p in RUN_TMP.glob("*") if p.is_file()] if RUN_TMP.is_dir() else []
    if not files and REPORTS.is_dir():  # if the scanner ignored -o
        files = [p for p in REPORTS.glob("*") if p.is_file() and p.stat().st_mtime >= started - 2]
    if not files:
        Run.log.append("! The scanner produced no report files")
        return None
    try:
        LOGS.mkdir(parents=True, exist_ok=True)
        probe = LOGS / ".w"
        probe.write_text("1")
        probe.unlink()
    except OSError:
        LOGS = HOME / "WebScout"
        LOGS.mkdir(parents=True, exist_ok=True)
        Run.log.append("! Could not write to phone storage (run termux-setup-storage). Saved in the Termux folder: ~/WebScout")
    n = max([x for x, _ in log_dirs()] or [0]) + 1
    dest = LOGS / f"log {n}"
    dest.mkdir()
    sanitize_reports(files, Run.catch_all)
    for p in files:
        shutil.copy2(p, dest / p.name)
    shutil.rmtree(RUN_TMP, ignore_errors=True)
    Run.log.append(f"✔ Saved: {dest}")
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
        Run.log.append(f"! Could not save log: {e}")
    with Run.lock:
        if Run.proc is proc:
            Run.code, Run.logname, Run.ended = code, name, time.time()


def catch_all_check(target):
    """Probe a few random ports; if most accept, the site accepts everything and port results are unreliable."""
    from urllib.parse import urlparse
    import socket
    host = urlparse(target).hostname or target
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return False
    hits = 0
    for port in CATCH_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=2):
                hits += 1
        except Exception:
            pass
    return hits >= 2


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


_cpu_prev = None
GPU_PATHS = ["/sys/class/kgsl/kgsl-3d0/gpu_busy_percentage", "/sys/class/misc/mali0/device/utilization",
             "/sys/devices/platform/mali.0/utilization", "/sys/kernel/gpu/gpu_busy"]

def read_file(p):
    try:
        return Path(p).read_text().strip()
    except Exception:
        return None

def sys_stats():
    global _cpu_prev
    cpu = None
    try:
        parts = [int(x) for x in Path("/proc/stat").read_text().splitlines()[0].split()[1:]]
        idle = parts[3] + parts[4]
        total = sum(parts)
        if _cpu_prev:
            dt, di = total - _cpu_prev[0], idle - _cpu_prev[1]
            cpu = round(100 * (1 - di / dt), 1) if dt > 0 else None
        _cpu_prev = (total, idle)
    except Exception:
        pass
    ram = None
    try:
        mi = {l.split(":")[0]: int(l.split()[1]) for l in Path("/proc/meminfo").read_text().splitlines()}
        ram = round(100 * (1 - mi["MemAvailable"] / mi["MemTotal"]), 1)
    except Exception:
        pass
    gpu = None
    for p in GPU_PATHS:
        v = read_file(p)
        if v and v.rstrip("%").isdigit():
            gpu = int(v.rstrip("%"))
            break
    cores = os.cpu_count() or 1
    if cpu is None:
        cpu = min(100.0, round(os.getloadavg()[0] / cores * 100, 1))
    return {"cpu": cpu, "ram": ram, "gpu": gpu, "cores": cores, "load": round(os.getloadavg()[0], 2)}

def make_key(data):
    """Create an activation key "WS1.<payload>.<signature>" signed with the developer's private key."""
    device = str(data.get("device", "")).strip().lower()
    if not DEVICE_RE.match(device):
        return None, "invalid device id"
    days = data.get("days", 0)
    if not isinstance(days, int) or isinstance(days, bool) or not 0 <= days <= 3650:
        return None, "invalid duration"
    feats = data.get("features", [])
    if not isinstance(feats, list) or not all(f in DEV_FEATURES for f in feats):
        return None, "invalid features"
    if not DEV_KEY.is_file():
        return None, "private key not found on this device (run termux/make_dev_key.sh)"
    exp = int(time.time()) + days * 86400 if days else 0
    body = json.dumps({"d": device, "e": exp, "f": sorted(set(feats))}, separators=(",", ":")).encode()
    payload = b64url(body)
    try:
        r = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(DEV_KEY)],
                           input=payload.encode(), capture_output=True, timeout=20)
    except Exception as e:
        return None, f"signing failed: {e}"
    if r.returncode or not r.stdout:
        return None, "signing failed"
    return f"WS1.{payload}.{b64url(r.stdout)}", None


LIC_PUB = Path(__file__).resolve().parent / "license_pub.b64"
_pem_cache = None

def _pub_pem():
    """Public key (DER base64 from make_dev_key.sh) converted to PEM for openssl. None if missing."""
    global _pem_cache
    if _pem_cache is None and LIC_PUB.is_file():
        try:
            der = base64.b64decode(LIC_PUB.read_text().strip())
            r = subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER", "-outform", "PEM"],
                               input=der, capture_output=True, timeout=20)
            if r.returncode == 0 and r.stdout:
                _pem_cache = r.stdout
        except Exception:
            pass
    return _pem_cache

def lic_ok(key, device):
    """True when this device may run a deep scan: the developer's own device, or a valid VIP key bound to this device."""
    if DEV_KEY.is_file():
        return True
    pem = _pub_pem()
    if not pem or not key or not device:
        return False
    try:
        parts = key.strip().split(".")
        if len(parts) != 3 or parts[0] != "WS1":
            return False
        payload = parts[1].encode()
        sig = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
        body = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except Exception:
        return False
    if str(body.get("d", "")).lower() != device.strip().lower():
        return False
    exp = body.get("e", 0)
    if exp and time.time() > exp:
        return False
    if "deep" not in (body.get("f") or []):
        return False
    with tempfile.TemporaryDirectory() as td:
        pf, sf = Path(td) / "pub.pem", Path(td) / "sig.bin"
        pf.write_bytes(pem)
        sf.write_bytes(sig)
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(pf), "-signature", str(sf)],
                           input=payload, capture_output=True, timeout=20)
    return r.returncode == 0


def start_run(target, modules, deep=False):
    if not ZS_HOME.is_dir():
        return False, f"Scanner folder not found: {ZS_HOME}"
    with Run.lock:
        if running():
            return False, "A scan is already running"
        shutil.rmtree(RUN_TMP, ignore_errors=True)
        RUN_TMP.mkdir(parents=True, exist_ok=True)
        cmd = [sys.executable, "-c", "from webscout_engine.cli import main; main()", target,
               "--yes", "--i-have-authorization", "--no-ui", "--no-open",
               "--formats", "json,html,csv,sarif", "--live", "-o", str(RUN_TMP)]
        # All scans: normal profile (not stealth) and a longer timeout for slow sites
        cmd += ["--arsenal-profile", "normal", "--timeout", "15"]
        if deep:
            # Constants set by the server, not the browser: a safe maximum
            cmd += ["--depth", "4", "--threads", "20", "--rate", "25", "--active-forms"]
            modules = ["all"]
        if modules and modules != ["all"]:
            cmd += ["-m", ",".join(modules)]
        env = dict(os.environ, PYTHONPATH=str(ZS_HOME), PYTHONUNBUFFERED="1", NO_COLOR="1")
        try:
            proc = subprocess.Popen(cmd, cwd=str(ZS_HOME), env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, errors="replace",
                                    start_new_session=True)
        except OSError as e:
            return False, f"Could not start the scanner: {e}"
        Run.proc, Run.target, Run.started = proc, target, time.time()
        Run.ended, Run.code, Run.logname = None, None, None
        Run.log.clear()
        Run.log.append(f"$ {target}")
        Run.catch_all = catch_all_check(target)
        if Run.catch_all:
            Run.log.append("⚠ The site accepts connections on all ports; port results are unreliable (possible false positives)")
    threading.Thread(target=pump, args=(proc,), daemon=True).start()
    return True, ""


def stop_run():
    with Run.lock:
        if not running() or Run.proc.poll() is not None:
            return False
        proc = Run.proc
    try:
        os.killpg(proc.pid, signal.SIGINT)  # Ctrl+C: the scanner saves a partial report
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


def progress_of(lines):
    text = "\n".join(lines)
    req = None
    for m in re.finditer(r"requests?\D{0,4}(\d+)", text, re.I):
        req = int(m.group(1))
    done = total = None
    for m in re.finditer(r"(\d+)\s*/\s*(\d+)\s*tasks?", text, re.I):
        done, total = int(m.group(1)), int(m.group(2))
    pct = None
    for m in re.finditer(r"(\d{1,3}(?:\.\d)?)\s*%", text):
        v = float(m.group(1))
        if 0 <= v <= 100:
            pct = v
    return {"req": req, "done": done, "total": total, "pct": pct}


SEV_RE = re.compile(r"CRITICAL\s+(\d+)\s+HIGH\s+(\d+)\s+MEDIUM\s+(\d+)\s+LOW\s+(\d+)\s+INFO\s+(\d+)")
PROBE_RE = re.compile(r"^\s*(GET|POST|PUT|HEAD|OPTIONS|DELETE|PATCH)\s+(\S+)\s+(\d{3}|-)\s+(\d+)", re.M)


def live_of(lines):
    """Read the latest frame from the scanner: severity, tasks, requests and recent probes."""
    text = "\n".join(lines)
    out = {"sev": None, "probes": None, "tasks": None, "total": None, "recent": []}
    last = None
    for m in SEV_RE.finditer(text):
        last = m
    if last:
        out["sev"] = dict(zip(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], map(int, last.groups())))
    for m in re.finditer(r"probes sent\s+(\d+)", text, re.I):
        out["probes"] = int(m.group(1))
    for m in re.finditer(r"(\d+)\s*/\s*(\d+)\s*tasks?", text, re.I):
        out["tasks"], out["total"] = int(m.group(1)), int(m.group(2))
    out["recent"] = [f"{m.group(1)} {m.group(2)[:60]} {m.group(3)}" for m in PROBE_RE.finditer(text)][-6:]
    return out


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
        "progress": progress_of(list(Run.log)[-300:]),
        "live": live_of(list(Run.log)[-400:]),
    }


# ---------------------------------------------------------------- http
MANIFEST = {
    "name": "WebScout", "short_name": "WebScout", "start_url": "/", "display": "standalone",
    "background_color": "#0b0d12", "theme_color": "#0b0d12",
    "icons": [{"src": "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 96 96'%3E%3Crect width='96' height='96' rx='22' fill='%23ff4d6d'/%3E%3Ctext x='48' y='64' font-size='54' text-anchor='middle' fill='white'%3EZ%3C/text%3E%3C/svg%3E",
               "sizes": "any", "type": "image/svg+xml"}],
}


def delete_scans(ids):
    wanted = set(ids)
    removed = set()
    dirs = [d for _, d in log_dirs()]
    if REPORTS.is_dir():
        dirs.append(REPORTS)
    for d in dirs:
        try:
            files = [p for p in d.iterdir() if p.is_file()]
        except OSError:
            continue
        for p in files:
            m = re.match(r"^.*_([A-Za-z0-9]+)\.[A-Za-z]+$", p.name)
            if m and m.group(1) in wanted:
                try:
                    p.unlink()
                    removed.add(m.group(1))
                except OSError:
                    pass
    for _, d in log_dirs():
        try:
            if not any(d.iterdir()):
                d.rmdir()
        except OSError:
            pass
    return len(removed)


REPORT_CSS = """<style>
html,body{background:#000!important;color:#f0f0f5}
body{padding-bottom:40px}
section,.card,.panel,.box,.module,.finding,[class*="card"],[class*="panel"]{background:#101017!important;border:1px solid #24243a!important;border-radius:16px!important}
table{display:block;max-width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch;border-collapse:collapse;background:transparent!important}
thead,tbody{display:table;width:100%;min-width:0}
tr{display:table-row}
th,td{vertical-align:top;white-space:nowrap;padding:8px 8px;text-align:start}
td.wrap,th.wrap{white-space:normal;overflow-wrap:break-word;word-break:normal;width:auto}
td{width:1%}
th{font-size:12px;letter-spacing:.5px;color:#9a9ab0}
td{line-height:1.5}
code,kbd{background:#0c0c14;border:1px solid #2a2a40;border-radius:8px;padding:2px 6px;white-space:pre-wrap;word-break:break-all;line-height:1.9;box-decoration-break:clone;-webkit-box-decoration-break:clone;font-size:.92em}
pre{background:#0c0c14;border:1px solid #2a2a40;border-radius:12px;padding:10px 12px;white-space:pre-wrap;word-break:break-all;max-width:100%;overflow:auto}
.zs-tip{margin-top:12px;padding:12px 14px;border:1px solid #2a2a40;border-radius:12px;background:#0c0c14;color:#c9c9d8;line-height:1.7}
.zs-tip b{color:#ffb3c1;margin-inline-end:6px}
img,svg{max-width:100%;height:auto}
.live{margin-top:12px}.lrow{display:flex;flex-wrap:wrap;gap:6px}.lchip{border:1px solid var(--line,#24243a);border-radius:999px;padding:3px 10px;font-size:13px}.lprobes{font-size:12px;line-height:1.5;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
</style>"""


REPORT_LABELS_JS = r"""
const MAP={'critical':'حرجة','high':'عالية','medium':'متوسطة','low':'منخفضة','info':'معلومة','CRITICAL':'حرجة','HIGH':'عالية','MEDIUM':'متوسطة','LOW':'منخفضة','INFO':'معلومة',
'expand all':'توسيع الكل','collapse all':'طي الكل','Findings':'النتائج','Evidence':'الدليل','Impact':'الأثر','Remediation':'طريقة المعالجة','Finding ID':'معرّف النتيجة',
'Scan type':'نوع الفحص','References':'المراجع','Evidence, impact and remediation':'الدليل والأثر والمعالجة','confidence':'الثقة','check':'الفحص','verification':'التحقق',
'module':'الوحدة','observed':'ملاحظ','active':'نشط','passive':'سلبي','status':'الحالة','Status':'الحالة','Type':'النوع','ID':'المعرّف','Module':'الوحدة','Requests':'الطلبات',
'Duration':'المدة','Started':'بدأ','Generated':'أُنشئ','Scan ID':'معرّف الفحص','Severity distribution':'توزيع الخطورة','Module coverage':'تغطية الوحدات','Modules':'الوحدات',
'SECURITY ASSESSMENT REPORT':'تقرير تقييم الأمن','Security Assessment Report':'تقرير تقييم الأمن','INTERRUPTED':'انقطع','COMPLETED':'مكتمل','SKIPPED':'تم التخطي','CANCELLED':'أُلغي',
'cancelled':'أُلغي','completed':'مكتمل','skipped':'تم التخطي','interrupted':'انقطع','FINDINGS':'نتيجة','findings':'نتيجة','Infrastructure Reconnaissance':'استطلاع البنية التحتية',
'Origin IP Discovery':'اكتشاف عنوان IP الأصلي','Sensitive File Discovery':'اكتشاف الملفات الحساسة','Directory and Content Discovery':'اكتشاف المجلدات والمحتوى',
'Hidden Parameter Discovery':'اكتشاف المعاملات المخفية','Technology-Specific Probes':'فحوصات خاصة بالتقنيات','Web Security Assessment':'تقييم أمن الويب',
'A module listed as skipped did not run, and its reason is shown. This scan is not complete coverage of every category unless every module reports completed.':'الوحدة المتخطاة لم تعمل، وسبب تخطيها موضّح. هذا الفحص لا يغطي كل الفئات إلا إذا أكملت كل الوحدات.',
'Search findings, endpoints, checks':'ابحث في النتائج والمسارات والفحوصات'};
const KEYS=Object.keys(MAP).sort((a,b)=>b.length-a.length);
function esc2(x){return x.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}
function trAr(str){
 const k=str.trim();
 if(MAP[k]!==undefined)return str.replace(k,MAP[k]);
 let out=str;
 KEYS.forEach(function(key){
  if(key.length<2)return;
  var re=new RegExp('(^|[^A-Za-z])'+esc2(key)+'(?![A-Za-z])','g');
  out=out.replace(re,function(all,pre){return pre+MAP[key]});
 });
 return out;
}
(function(){
 var ar=true;try{ar=(localStorage.getItem('zs_lang')||'ar')==='ar'}catch(e){}
 function titleOf(el){var n=el;while(n&&n!==document.body){var s=n.previousElementSibling;while(s){var h=(s.matches&&s.matches('h1,h2,h3,h4'))?s:(s.querySelector&&s.querySelector('h1,h2,h3,h4'));if(h&&h.textContent.trim())return h.textContent;s=s.previousElementSibling}n=n.parentElement}return ''}
 function tipFor(s){
  for(var i=0;i<TIPS.length;i++){if(TIPS[i][0].test(s))return ar?TIPS[i][1]:TIPS[i][2]}
  return ar?TIP_DEFAULT[0]:TIP_DEFAULT[1];
 }
 document.querySelectorAll('body *').forEach(function(e){
  if(e.children.length!==0)return;
  var k=e.textContent.trim();
  if(k!=='Remediation')return;
  var row=e.parentElement;var t=titleOf(row)||'';
  var box=document.createElement('div');box.className='zs-tip';
  box.innerHTML='<b>'+(ar?'نصيحة عامة':'General tip')+':</b>'+tipFor(t);
  (row.parentElement||row).insertBefore(box,row.nextSibling);
 });
 if(ar){
  document.documentElement.lang='ar';document.documentElement.dir='rtl';
  var w=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT,null);
  var nodes=[];while(w.nextNode())nodes.push(w.currentNode);
  nodes.forEach(function(nd){
   if(!nd.parentElement||/SCRIPT|STYLE/.test(nd.parentElement.tagName))return;
   var v=nd.nodeValue;if(!v.trim())return;
   nd.nodeValue=trAr(v);
  });
  document.querySelectorAll('td').forEach(function(td){if(td.textContent.trim().length>30)td.classList.add('wrap')});
  document.querySelectorAll('input[placeholder]').forEach(function(i){var p=i.getAttribute('placeholder');if(MAP[p])i.setAttribute('placeholder',MAP[p])});
 }
})();
"""

def report_script():
    m = re.search(r"const TIPS=\[.*?\];\s*const TIP_DEFAULT=.*?\];", PAGE, re.S)
    tips = m.group(0) if m else "const TIPS=[];const TIP_DEFAULT=['','']; "
    return "<script>" + tips + REPORT_LABELS_JS + "</script>"


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

    # Protection against external sites trying to reach the local server (DNS rebinding / CSRF)
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
            return self.json({"version": VERSION, "logs": str(LOGS), "tool": ZS_HOME.is_dir(), "dev": DEV_KEY.is_file()})
        if path == "/api/stats":
            return self.json(sys_stats())
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
                html = p.read_text(encoding="utf-8", errors="replace")
                html = html.replace("</head>", REPORT_CSS + "</head>", 1) if "</head>" in html else REPORT_CSS + html
                tail = report_script()
                html = html.replace("</body>", tail + "</body>", 1) if "</body>" in html else html + tail
                return self.send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        self.send(404, "not found", "text/plain")

    def do_POST(self):
        if not self.host_ok() or not self.write_ok():
            return self.json({"error": "forbidden"}, 403)
        path = self.path.split("?", 1)[0]
        try:
            n = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(n) or b"{}") if 0 <= n <= 200000 else None
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
            if data.get("deep") is True and not lic_ok(self.headers.get("X-ZS-Lic", ""), self.headers.get("X-ZS-Dev", "")):
                return self.json({"error": "deep scan needs a VIP license"}, 403)
            mods = data.get("modules") or ["all"]
            if not isinstance(mods, list) or not all(m == "all" or m in MODULES for m in mods):
                return self.json({"error": "invalid modules"}, 400)
            mods = ["all"] if "all" in mods else mods
            ok, msg = start_run(target, mods, deep=data.get("deep") is True)
            return self.json({"ok": True} if ok else {"error": msg}, 200 if ok else 409)

        if path == "/api/scans/delete":
            ids = data.get("ids")
            if not isinstance(ids, list) or not ids or len(ids) > 1000 or not all(isinstance(i, str) and ID_RE.match(i) for i in ids):
                return self.json({"error": "invalid ids"}, 400)
            return self.json({"deleted": delete_scans(ids)})
        if path == "/api/run/stop":
            return self.json({"ok": stop_run()})
        if path == "/api/dev/keygen":
            key, err = make_key(data)
            return self.json({"key": key} if key else {"error": err}, 200 if key else 400)
        self.json({"error": "not found"}, 404)


PAGE = r"""<!doctype html>
<html lang="ar" dir="rtl" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0b0d12">
<link rel="manifest" href="/manifest.json">
<title>WebScout</title>
<style>
:root{--bg:#000;--card:#0b0b0e;--card2:#15151a;--txt:#f4f4f7;--mut:#8b8b97;--line:#1d1d23;--pre:#040405;--hdr:rgba(0,0,0,.82);--nav:rgba(8,8,10,.92);--critical:#ff3b5c;--high:#ff8a4c;--medium:#ffc857;--low:#4cc9f0;--info:#8f9bff;--ok:#2ee6a0;--acc:#ff3b5c}
:root[data-theme=light]{--bg:#f4f5f8;--card:#ffffff;--card2:#eceef4;--txt:#11141c;--mut:#5d6578;--line:#e0e4ec;--pre:#eef1f6;--hdr:rgba(244,245,248,.9);--nav:rgba(255,255,255,.96);--critical:#d6264a;--high:#d9650f;--medium:#a87a00;--low:#1b8db3;--info:#4a5be0;--ok:#16915f;--acc:#e0294f}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{background:var(--bg)}
body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Tahoma,sans-serif;padding-bottom:calc(84px + env(safe-area-inset-bottom))}
header{position:sticky;top:0;z-index:5;background:var(--hdr);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}
.hrow{padding:14px 16px;display:flex;align-items:center;gap:10px}
header h1{font-size:17px;margin:0;flex:1;font-weight:700;letter-spacing:.2px}
.back{background:none;border:0;color:var(--txt);font-size:22px;padding:0 4px;display:none}
#runbar{display:none;align-items:center;gap:10px;padding:10px 16px;font-size:14px;font-weight:600;color:#fff;background:var(--acc);text-decoration:none}
#runbar.done{background:var(--ok)}
#runbar .t{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.spin{width:16px;height:16px;border:2.5px solid rgba(255,255,255,.35);border-top-color:#fff;border-radius:50%;animation:sp .8s linear infinite;flex:none}
.spin.big{width:20px;height:20px;border-color:var(--line);border-top-color:var(--acc)}
@keyframes sp{to{transform:rotate(360deg)}}
main{padding:18px 16px;max-width:720px;margin:0 auto}
.view{animation:in .3s cubic-bezier(.2,.7,.2,1)}
@keyframes in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:16px;margin-bottom:12px}
a.card{display:block;color:inherit;text-decoration:none;transition:transform .15s,background .15s}
a.card:active{transform:scale(.985);background:var(--card2)}
.sc{cursor:pointer}
.sc.picked{border-color:var(--acc);box-shadow:0 0 0 1px var(--acc) inset}
.ck{width:22px;height:22px;border-radius:7px;border:1.5px solid var(--mut);display:inline-flex;align-items:center;justify-content:center;font-size:13px;flex:none;color:#fff}
.ck.on{background:var(--acc);border-color:var(--acc)}
.ltr{direction:ltr;unicode-bidi:isolate;text-align:left;word-break:break-all}
.mut{color:var(--mut);font-size:13px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.sp{justify-content:space-between}
.chip{border-radius:999px;padding:3px 10px;font-size:12px;font-weight:600;border:1px solid currentColor;white-space:nowrap;background:transparent}
.c-critical{color:var(--critical)}.c-high{color:var(--high)}.c-medium{color:var(--medium)}
.c-low{color:var(--low)}.c-info{color:var(--info)}.c-ok{color:var(--ok)}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:12px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:16px}
.stat b{display:block;font-size:28px;font-weight:700;letter-spacing:-.5px}
.bar{display:flex;height:8px;border-radius:99px;overflow:hidden;background:var(--card2);margin:12px 0}
.bar i{display:block;height:100%;min-width:0;background:linear-gradient(90deg,#ff4d6d,#ff8fa3);transition:width .6s}
.wait .bar i{background:linear-gradient(90deg,#0ea5e9,#38bdf8);box-shadow:0 0 10px rgba(56,189,248,.6)}
.sbar .bar{height:6px;margin:0}
.sbar .bar i{background:linear-gradient(90deg,#0ea5e9,#38bdf8)}
.tiles{display:grid;grid-template-columns:repeat(5,1fr);gap:6px;margin:14px 0 4px}
.tile{background:var(--card2);border:1px solid var(--line);border-radius:14px;padding:10px 2px;text-align:center;color:var(--txt);font:inherit;cursor:pointer}
.tile b{display:block;font-size:20px;line-height:1.2}
.tile span{font-size:11px}
.tile.on{outline:2px solid currentColor}
h2{font-size:12px;margin:22px 0 10px;color:var(--mut);font-weight:600;letter-spacing:.6px;text-transform:uppercase}
.f{border-inline-start:3px solid var(--info)}
.f.critical{border-color:var(--critical)}.f.high{border-color:var(--high)}
.f.medium{border-color:var(--medium)}.f.low{border-color:var(--low)}
.k{font-size:12px;color:var(--mut);margin:14px 0 4px;font-weight:600}
.v{margin:0;word-break:break-word}
pre{background:var(--pre);border:1px solid var(--line);border-radius:12px;padding:12px;overflow:auto;margin:0;font-size:12px;direction:ltr;text-align:left;max-height:260px;white-space:pre-wrap;word-break:break-all}
button.btn,a.btn{background:var(--acc);color:#fff;border:0;border-radius:12px;padding:12px 16px;font:inherit;font-weight:600;text-decoration:none;display:inline-block;text-align:center;cursor:pointer}
button.btn:disabled{opacity:.35;cursor:default}
button.ghost{background:var(--card2);color:var(--txt);border:1px solid var(--line)}
.danger{background:#e5484d;color:#fff}
.sm{padding:8px 12px;font-size:13px;border-radius:10px}
.lbl{display:block;margin:14px 0 6px;color:var(--mut);font-size:13px}
.inp{width:100%;padding:12px 14px;border-radius:12px;border:1px solid var(--line);background:var(--card2);color:var(--txt);font:inherit;outline:none}
.inp:focus{border-color:var(--acc)}
.toolbar{display:flex;gap:8px;margin-bottom:14px}
.toolbar .inp{flex:1;min-width:0}
.mb{background:var(--card2);color:var(--mut);border:1px solid var(--line);border-radius:999px;padding:6px 12px;font:inherit;font-size:13px;cursor:pointer}
.mb.on{background:var(--acc);color:#fff;border-color:var(--acc)}
.chk{display:flex;gap:12px;align-items:flex-start;margin:18px 0;padding:14px;border:1px solid var(--line);border-radius:14px;background:var(--card)}
.chk input{width:22px;height:22px;margin:2px 0 0;flex:none;accent-color:var(--acc)}
.seg{display:flex;gap:8px}
.seg button{flex:1;padding:12px;border-radius:12px;border:1px solid var(--line);background:var(--card2);color:var(--txt);font:inherit;font-weight:600;cursor:pointer}
.seg button.on{background:var(--acc);border-color:var(--acc);color:#fff}
.kv{display:flex;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid var(--line)}
.kv:last-child{border:0}
nav{position:fixed;bottom:0;inset-inline:0;background:var(--nav);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border-top:1px solid var(--line);display:flex;padding-bottom:env(safe-area-inset-bottom);z-index:6}
nav a{flex:1;text-align:center;padding:10px 0 9px;color:var(--mut);text-decoration:none;font-size:12px;transition:color .15s}
nav a b{display:block;font-size:19px;font-weight:400;line-height:1.3}
nav a.on{color:var(--acc)}
#sbar{display:none;position:fixed;bottom:80px;inset-inline:12px;z-index:7;background:var(--card2);border:1px solid var(--line);border-radius:16px;padding:10px 12px;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;box-shadow:0 12px 32px rgba(0,0,0,.5)}
#sbar.on{display:flex}
.scrim{position:fixed;inset:0;background:rgba(0,0,0,.65);display:flex;align-items:center;justify-content:center;padding:20px;z-index:20}
.dlg{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:20px;width:100%;max-width:360px;animation:in .2s}
.toast{position:fixed;bottom:96px;inset-inline:0;margin-inline:auto;width:max-content;max-width:90%;background:var(--card2);border:1px solid var(--line);padding:10px 16px;border-radius:12px;z-index:30;font-size:14px;animation:in .2s}
.empty{text-align:center;color:var(--mut);padding:60px 10px}
details summary{cursor:pointer}
.wait{text-align:center;padding:8px 4px 4px}
.ring{position:relative;width:150px;height:150px;margin:6px auto 14px}
.ring svg{transform:rotate(-90deg);width:100%;height:100%}
.ring.spin svg{animation:rsp 1.2s linear infinite}
@keyframes rsp{from{transform:rotate(-90deg)}to{transform:rotate(270deg)}}
.rb{fill:none;stroke:var(--card2);stroke-width:8}
.rf{fill:none;stroke:var(--acc);stroke-width:8;stroke-linecap:round;transition:stroke-dasharray .6s}
.ring b{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:26px}
.wt{color:var(--mut);margin-bottom:14px;word-break:break-all;font-size:14px}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:14px}
.stat2{background:var(--card2);border:1px solid var(--line);border-radius:14px;padding:10px 4px}
.stat2 span{display:block;font-size:11px;color:var(--mut)}
.stat2 b{font-size:15px}
.wait .bar{margin:0}
.bar.ind i{width:30%!important;animation:ind 1.4s ease-in-out infinite}
@keyframes ind{0%{margin-inline-start:-30%}100%{margin-inline-start:100%}}

.chk.locked{opacity:.6;cursor:not-allowed}.chk.locked span{text-decoration:line-through;text-decoration-color:#ff4d6d;text-decoration-thickness:2px;color:var(--critical)}.vip{font-style:normal;margin-inline-start:auto;font-size:12px;color:#ff8fa3;border:1px solid #ff4d6d;border-radius:999px;padding:2px 8px;white-space:nowrap}
.energy{position:relative;width:170px;height:170px;margin:8px auto 10px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:radial-gradient(circle,rgba(56,189,248,.12),transparent 70%);box-shadow:0 0 26px rgba(56,189,248,.45),inset 0 0 26px rgba(56,189,248,.35);}
.energy::after{content:"";position:absolute;inset:-10px;border-radius:50%;border:3px solid transparent;border-top-color:#38bdf8;border-right-color:rgba(56,189,248,.35);box-shadow:0 0 18px rgba(56,189,248,.6);animation:spin 1.2s linear infinite}
.shield{width:50px;height:50px;fill:rgba(56,189,248,.18);stroke:#38bdf8;stroke-width:1.6;filter:drop-shadow(0 0 6px #38bdf8);animation:shieldblink 1.4s ease-in-out infinite}
.ring-pct{text-align:center;font-size:22px;font-weight:700;color:#38bdf8;margin:-2px 0 10px;font-variant-numeric:tabular-nums}
.sysgrid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-top:12px}.sbar .sl{display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px}.sbar .sl b{color:#38bdf8;font-variant-numeric:tabular-nums}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes shieldblink{0%,100%{opacity:1}50%{opacity:.15}}
</style>
</head>
<body>
<header>
 <div class="hrow"><button class="back" id="back"></button><h1 id="title">WebScout</h1><button class="btn ghost" id="reload" style="padding:8px 14px"></button></div>
 <a id="runbar" href="#/"></a>
</header>
<main id="app"></main>
<div id="sbar"></div>
<div id="modal"></div>
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
ar:{vip_only:'هذه الميزة لأعضاء VIP فقط',gpu_na:'قراءة GPU غير متاحة على هذا الجهاز',need_lic:'يحتاج ترخيص',dev:'خيارات المطور',t_dev:'خيارات المطور',dev_dev:'معرّف الجهاز',dev_days:'مدة الصلاحية (أيام)',dev_forever:'بدون انتهاء',dev_feat:'الميزات المفعّلة',dev_f_deep:'فحص عميق وشامل',dev_gen:'توليد المفتاح',dev_key:'مفتاح التفعيل',dev_copy:'نسخ المفتاح',dev_fail:'فشل التوليد',dev_hint:'معرّف الجهاز بيظهر للمستخدم بشاشة التفعيل.',select:'تحديد',cancel:'إلغاء',all:'الكل',delete:'حذف',deleted:'تم الحذف',no_match:'لا توجد نتائج',selected:'محدّد',delete_sel:'حذف المحدد',delete_all:'حذف الكل',confirm_sel:'سيتم حذف الفحوصات المحددة نهائياً من الهاتف. هل أنت متأكد؟',confirm_all:'سيتم حذف جميع الفحوصات نهائياً من الهاتف. هل أنت متأكد؟',sure:'تأكيد الحذف',nav_scan:'فحص',nav_hist:'السجل',nav_set:'الإعدادات',reload:'تحديث',t_scan:'فحص جديد',t_hist:'السجل',t_set:'الإعدادات',t_det:'تفاصيل الفحص',
 target:'رابط الهدف',mods:'الوحدات',m_all:'الكل',m_infra:'البنية التحتية',m_origin:'المصدر',m_files:'الملفات الحساسة',m_dirs:'المجلدات',m_params:'المعاملات',m_tech:'التقنيات',m_vuln:'فحص الويب',
 auth:'أؤكد أنني أملك هذا الموقع أو لدي إذن كتابي بفحصه. الفحص دون إذن ممنوع قانونياً.',start:'ابدأ الفحص',stop:'إيقاف',
 bar_run:'الفحص جارٍ',bar_done:'اكتمل الفحص، اضغط لعرض النتيجة',running:'جارٍ الفحص...',
 s_done:'اكتمل الفحص',s_stop:'تم إيقاف الفحص',s_err:'انتهى بخطأ',s_cfg:'خطأ في الإعدادات',s_auth:'التفويض ناقص',saved:'حُفظ في',toast:'بدأ الفحص',view:'عرض النتيجة',elapsed:'الوقت',attempts:'المحاولات',eta:'الوقت المتبقي',eta_calc:'غير معروف',log:'سجل التنفيذ',deep:'فحص عميق وشامل (أبطأ، يغطي كل شي، ومحدود بمعدل آمن)',tasks:'المهام',probes:'الطلبات',st_completed:'مكتمل',st_cancelled:'أُلغي',st_skipped:'تم التخطي',st_interrupted:'انقطع',st_failed:'فشل',st_error:'خطأ',st_running:'جارٍ',
 search:'البحث بالهدف...',empty_hist:'لا توجد فحوصات بعد',done:'مكتمل',incomplete:'غير مكتمل',interrupted:'انقطع الفحص قبل اكتماله.',orig:'التقرير الأصلي',
 findings:'النتائج',no_find:'لا توجد نتائج لهذا الفحص.',sev_critical:'حرجة',sev_high:'عالية',sev_medium:'متوسطة',sev_low:'منخفضة',sev_info:'معلومة',
 f_loc:'الموقع',f_ev:'الدليل',f_fix:'طريقة المعالجة',f_tip:'نصيحة عامة',f_more:'تفاصيل إضافية',f_none:'غير متوفر',
 modules_h:'الوحدات',skipped_h:'وحدات تم تخطّيها',raw_h:'البيانات الخام',raw_show:'عرض JSON',req:'طلبات',res:'نتائج',
 lang:'اللغة',theme:'المظهر',dark:'داكن',light:'فاتح',info:'معلومات التطبيق',ver:'الإصدار',desc:'واجهة هاتف لفحص الأمان، تعمل مع أداة WebScout على تيرمكس.',
 store:'مكان حفظ السجلات',tool:'الأداة',tool_ok:'موجودة',tool_no:'غير موجودة',resp_h:'الاستخدام المسؤول',
 resp:'استخدم التطبيق على مواقع تملكها أو لديك إذن كتابي بفحصها فقط. المستخدم مسؤول عن استخدامه.',err:'تعذّر تحميل البيانات.',m:'د',s:'ث'},
en:{vip_only:'This feature is for VIP users only',gpu_na:'GPU usage is not exposed on this device',need_lic:'needs license',dev:'Developer options',t_dev:'Developer options',dev_dev:'Device ID',dev_days:'Validity (days)',dev_forever:'No expiry',dev_feat:'Enabled features',dev_f_deep:'Deep full scan',dev_gen:'Generate key',dev_key:'Activation key',dev_copy:'Copy key',dev_fail:'Generation failed',dev_hint:'The device ID is shown to the user on the activation screen.',select:'Select',cancel:'Cancel',all:'All',delete:'Delete',deleted:'Deleted',no_match:'No matches',selected:'Selected',delete_sel:'Delete selected',delete_all:'Delete all',confirm_sel:'The selected scans will be permanently deleted from your phone. Are you sure?',confirm_all:'All scans will be permanently deleted from your phone. Are you sure?',sure:'Confirm deletion',nav_scan:'Scan',nav_hist:'History',nav_set:'Settings',reload:'Refresh',t_scan:'New scan',t_hist:'History',t_set:'Settings',t_det:'Scan details',
 target:'Target URL',mods:'Modules',m_all:'All',m_infra:'Infra',m_origin:'Origin',m_files:'Sensitive files',m_dirs:'Directories',m_params:'Parameters',m_tech:'Technology',m_vuln:'Web checks',
 auth:'I confirm I own this site or have written permission to test it. Testing without permission is illegal.',start:'Start scan',stop:'Stop',
 bar_run:'Scan started and running',bar_done:'Scan finished, tap to view the result',running:'Scanning...',
 s_done:'Scan completed',s_stop:'Scan stopped',s_err:'Finished with an error',s_cfg:'Configuration error',s_auth:'Missing authorization',saved:'Saved in',toast:'Scan started',view:'View result',elapsed:'Elapsed',attempts:'Attempts',eta:'Time left',eta_calc:'Unknown',log:'Scan log',deep:'Deep full scan (slower, covers everything, capped at a safe rate)',tasks:'Tasks',probes:'Requests',st_completed:'Completed',st_cancelled:'Cancelled',st_skipped:'Skipped',st_interrupted:'Interrupted',st_failed:'Failed',st_error:'Error',st_running:'Running',
 search:'Search by target...',empty_hist:'No scans yet',done:'Completed',incomplete:'Incomplete',interrupted:'The scan was interrupted before it finished.',orig:'Original report',
 findings:'Findings',no_find:'No findings in this scan.',sev_critical:'Critical',sev_high:'High',sev_medium:'Medium',sev_low:'Low',sev_info:'Info',
 f_loc:'Location',f_ev:'Evidence',f_fix:'How to fix',f_tip:'General tip',f_more:'More details',f_none:'Not available',
 modules_h:'Modules',skipped_h:'Skipped modules',raw_h:'Raw data',raw_show:'Show JSON',req:'requests',res:'findings',
 lang:'Language',theme:'Appearance',dark:'Dark',light:'Light',info:'App info',ver:'Version',desc:'A mobile front-end for security scanning, working with the WebScout tool on Termux.',
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
 [/\.env|\.git|backup|config|sensitive|secret|leak|\.bak|dump/i,'شيل الملفات الحساسة والنسخ الاحتياطية من مجلد الموقع العام، وامنع الوصول إليها، وغيّر أي مفاتيح أو كلمات سر ظهرت.','Remove sensitive files and backups from the web root, block access to them, and rotate any exposed keys or passwords.'],
 [/redis|mongo|elastic|memcache|couch|postgres|mysql|mariadb|oracle|mssql/i,'قيّد الوصول للمنفذ بجدار ناري أو قائمة مسموح بها، وفعّل المصادقة، ولا تخلي قاعدة البيانات ظاهرة على الإنترنت.','Restrict the port with a firewall or allow-list, enable authentication, and never expose databases to the internet.'],
 [/smb|netbios|rdp|microsoft-ds|port 445|port 139|port 3389/i,'عطّل مشاركة الملفات والخدمات البعيدة على الإنترنت، واحجب هذه المنافذ عن الشبكات الخارجية.','Disable file sharing and remote services on the internet and block these ports from external networks.'],
 [/telnet|\bftp\b/i,'استبدل Telnet وFTP ببروتوكولات مشفّرة مثل SSH وSFTP، وامنع كلمات السر الضعيفة.','Replace Telnet and FTP with encrypted protocols such as SSH and SFTP, and block weak passwords.'],
 [/alternate|8080|8000|8888|http proxy|port 80\b/i,'أغلق المنافذ غير المستخدمة، وإذا الخدمة لازم تكون ظاهرة، خلّيها خلف HTTPS وقيّد الوصول إليها.','Close unused ports; if the service must be reachable, put it behind HTTPS and restrict access.'],
 [/banner|version|server|disclos|fingerprint/i,'أخفِ أرقام الإصدارات ومعلومات السيرفر من الترويسات والصفحات.','Hide version numbers and server details from headers and pages.'],
 [/admin|login|panel|auth/i,'قيّد الوصول للوحة الإدارة (IP محدد أو VPN) وفعّل مصادقة قوية وحد المحاولات.','Restrict admin panels (IP allow-list or VPN), enforce strong authentication and rate limiting.']
];
const TIP_DEFAULT=['حدّث البرمجيات للأحدث، وقيّد الوصول، وراجع الإعدادات المرتبطة بهذه النتيجة.','Update software, restrict access, and review the settings related to this finding.'];

const MODT={'Infrastructure Reconnaissance':'استطلاع البنية التحتية','Origin IP Discovery':'اكتشاف عنوان IP الأصلي','Sensitive File Discovery':'اكتشاف الملفات الحساسة','Directory and Content Discovery':'اكتشاف المجلدات والمحتوى','Hidden Parameter Discovery':'اكتشاف المعاملات المخفية','Technology-Specific Probes':'فحوصات خاصة بالتقنيات','Web Security Assessment':'تقييم أمن الويب'};
function modTitle(x){return (lang==='ar'&&MODT[x])?MODT[x]:x}
function stLabel(x){const k='st_'+x;return I[lang][k]!==undefined?I[lang][k]:x}
const app=$('#app');
let cache=null,info={},gstate=null,tickBase=0,tickAt=0,sel=new Set(['all']),fsev=null,curScan=null;

function licFeatures(){try{const a=JSON.parse(window.Android&&Android.features?Android.features():'[]');return Array.isArray(a)?a:[]}catch(e){return []}}
async function api(p){const r=await fetch(p);if(!r.ok)throw new Error(r.status);return r.json()}
async function post(p,b){const lk=(window.Android&&Android.licenseKey)?Android.licenseKey():'';const di=(window.Android&&Android.deviceId)?Android.deviceId():'';const r=await fetch(p,{method:'POST',headers:{'Content-Type':'application/json','X-ZS':'1','X-ZS-Lic':lk||'','X-ZS-Dev':di||''},body:JSON.stringify(b||{})});
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
function show(html,title,back){ selMode=false; $('#sbar').innerHTML=''; $('#sbar').classList.remove('on');
 app.innerHTML='<div class="view">'+html+'</div>';
 $('#title').textContent=title||'WebScout';
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
  if(b.dataset.k!=='run'){b.dataset.k='run';
   b.innerHTML=`<span class="spin"></span><span class="t">${esc(t('bar_run'))}: <span class="ltr" style="display:inline">${esc(st.target)}</span></span>`;}
 }else if(Date.now()<doneUntil){
  b.className='done';b.style.display='flex';b.href='#/history';
  if(b.dataset.k!=='done'){b.dataset.k='done';
   b.innerHTML=`<span>&#10004;</span><span class="t">${esc(t('bar_done'))}</span>`;}
 }else{b.style.display='none';b.dataset.k=''}
}
function elapsed(){return gstate?(tickBase+(Date.now()-tickAt)/1000):0}
setInterval(()=>{
 if(gstate&&gstate.running){const a=document.querySelector('.tm');if(a)a.textContent=fdur(elapsed());const c=$('#rtm');if(c)c.textContent=fdur(elapsed());const w=$('#wtm');if(w)w.textContent=fdur(elapsed())}
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
function waitVals(st){
 const p=st.progress||{};
 const pct=p.pct!=null?p.pct:(p.total?Math.round(p.done/p.total*100):null);
 return {pct:pct};
}
const bar=(id,v)=>`<div class="sbar"><div class="sl"><span>${id}</span><b id="sv_${id}">${v==null?'—':v+'%'}</b></div><div class="bar"><i id="si_${id}" style="width:${v==null?0:v}%"></i></div></div>`;
function waitHTML(st){
 const v=waitVals(st);
 return `<div class="wait">
  <div class="energy" id="wring"><svg class="shield" viewBox="0 0 24 24"><path d="M12 2 4 5v6c0 5 3.5 9 8 11 4.5-2 8-6 8-11V5z"/></svg></div>
  <div class="ring-pct" id="wpct">${v.pct!=null?Math.round(v.pct)+'%':''}</div>
  <div class="sysgrid">${bar('CPU',null)}${bar('GPU',null)}${bar('RAM',null)}</div>
  <p class="mut" id="snote" style="text-align:center;margin:6px 0 0;font-size:12px"></p>
 </div>`;
}
let statBusy=false,statLast=0;
async function pollStats(){
 if(statBusy||Date.now()-statLast<900)return;statBusy=true;statLast=Date.now();
 try{
  const s=await api('/api/stats');
  const put=(k,v)=>{const b=$('#sv_'+k),i=$('#si_'+k);if(b)b.textContent=v==null?'—':v+'%';if(i)i.style.width=(v==null?0:Math.min(100,v))+'%'};
  put('CPU',s.cpu);put('RAM',s.ram);put('GPU',s.gpu);
  const n=$('#snote');if(n)n.textContent=(s.gpu==null?t('gpu_na'):'')+(s.cores?' · '+s.cores+' cores':'');
 }catch(e){}
 finally{statBusy=false}
}
function liveHTML(st){return ''}
function updateLive(st){}
function updateWait(st){
 const v=waitVals(st);
 const e=$('#wpct');if(e){const tx=v.pct!=null?Math.round(v.pct)+'%':'';if(e.textContent!==tx)e.textContent=tx}
  pollStats();
}
function renderRun(){
 const box=$('#runbox');if(!box)return;check();
 const st=gstate;if(!st||!st.started){box.style.display='none';return}
 box.style.display='block';
 let head;
 if(st.running)head=`<span class="spin big"></span><b class="c-medium">${t('running')}</b>`;
 else{
  const k=st.code===0?'s_done':STOPPED.includes(st.code)?'s_stop':st.code===2?'s_cfg':st.code===3?'s_auth':'s_err';
  head=`<b class="${st.code===0?'c-ok':'c-high'}">${st.code===0?'&#10004; ':''}${t(k)}</b>`;
 }
 const hk=st.running?'r':'d'+st.code;
 if(box.dataset.hk!==hk){$('#rhead').innerHTML=head;box.dataset.hk=hk}
 if(st.running){
  if($('#wpct'))updateWait(st);else $('#rwait').innerHTML=waitHTML(st);
  updateLive(st);
 }else if($('#rwait').innerHTML){$('#rwait').innerHTML=''}
 $('#stop').style.display=st.running?'inline-block':'none';
 $('#rtg').textContent=st.running?'':st.target;
 $('#rsave').textContent=(!st.running&&st.log_name)?`${t('saved')}: ${st.log_name}`:'';
 const lg=$('#rlog');if(lg){const atEnd=lg.scrollTop+lg.clientHeight>=lg.scrollHeight-20;lg.textContent=st.log.join('\n');if(atEnd)lg.scrollTop=lg.scrollHeight}
 $('#rlink').innerHTML=(!st.running&&st.log_name)?`<a class="btn" href="#/last">${t('view')}</a>`:'';
}
async function scanView(){
 setNav('scan');
 try{info=await api('/api/info')}catch(e){}
 const canDeep=licFeatures().includes('deep');
 show(`<div class="card">
  <label class="lbl" for="tg">${t('target')}</label>
  <input id="tg" class="inp ltr" placeholder="https://example.com" inputmode="url" autocapitalize="off" autocomplete="off" spellcheck="false">
  <label class="lbl">${t('mods')}</label><div class="row" id="mods"></div>
  <label class="chk${canDeep?'':' locked'}" id="deeplbl"><input type="checkbox" id="deep"${canDeep?'':' disabled'}><span>${t('deep')}</span>${canDeep?'':'<em class="vip">&#128274; VIP</em>'}</label>
  <label class="chk"><input type="checkbox" id="auth"><span>${t('auth')}</span></label>
  <button class="btn" id="go" disabled style="width:100%">${t('start')}</button>
  <p id="err" style="color:var(--critical);margin:10px 0 0"></p></div>
  <div class="card" id="runbox" style="display:none">
   <div class="row sp"><div class="row" id="rhead"></div><button class="btn ghost" id="stop" style="display:none;padding:8px 14px">${t('stop')}</button></div>
   <div class="mut ltr" id="rtg" style="margin:6px 0 10px"></div><div id="rwait"></div>${info.dev?'<details style="margin-top:10px"><summary class="mut">'+t('log')+'</summary><pre id="rlog"></pre></details>':''}
   <p class="mut" id="rsave" style="margin:10px 0 0"></p><p id="rlink" style="margin:10px 0 0"></p></div>`,t('t_scan'));
 drawMods();
 $('#mods').onclick=e=>{const k=e.target.dataset&&e.target.dataset.k;if(!k)return;
  if(k==='all')sel=new Set(['all']);else{sel.delete('all');sel.has(k)?sel.delete(k):sel.add(k);if(!sel.size)sel=new Set(['all'])}drawMods()};
 $('#tg').oninput=check;$('#auth').onchange=check;
 $('#go').onclick=async()=>{
  $('#err').textContent='';$('#go').disabled=true;
  try{
   await post('/api/run',{target:$('#tg').value.trim(),modules:[...sel],authorized:$('#auth').checked,deep:$('#deep').checked&&canDeep});
   try{navigator.vibrate&&navigator.vibrate(80)}catch(e){}
   try{window.Android&&Android.toast&&Android.toast(t('toast'))}catch(e){}
   await gpoll();window.scrollTo(0,0);
  }catch(e){$('#err').textContent=e.message;check()}};
 $('#stop').onclick=async()=>{try{await post('/api/run/stop')}catch(e){}gpoll()};
 await gpoll();
}

/* ---------- السجل ---------- */
let selMode=false, selIds=new Set(), hList=[];
function scanCard(s){
 const on=selIds.has(s.id);
 const pad=selMode?'padding-inline-start:30px':'';
 const pre=selMode?`<span class="ck ${on?'on':''}">${on?'&#10003;':''}</span>`:'';
 const body=`<div class="row sp"><div class="row" style="gap:10px;min-width:0">${pre}<b class="ltr">${esc(s.target)}</b></div>
  <span class="chip ${s.completed?'c-ok':'c-medium'}">${s.completed?t('done'):t('incomplete')}</span></div>
  <div class="mut" style="margin:6px 0 10px;${pad}">${s.log?'log '+s.log+' &middot; ':''}${fdate(s.started_at)} &middot; ${fdur(s.duration)}</div>
  <div class="row" style="${pad}">${chips(s.severity)}</div>`;
 return selMode
  ? `<div class="card sc ${on?'picked':''}" data-id="${esc(s.id)}">${body}</div>`
  : `<a class="card" href="#/scan/${esc(s.id)}">${body}</a>`;
}
function drawList(){
 const v=(($('#q')||{}).value||'').toLowerCase();
 const items=hList.filter(s=>(s.target||'').toLowerCase().includes(v));
 $('#hl').innerHTML=items.length?items.map(scanCard).join(''):`<div class="empty">${t('no_match')}</div>`;
}
function bar2(){
 const b=$('#sbar');
 if(!selMode||!hList.length){b.innerHTML='';b.classList.remove('on');return}
 b.classList.add('on');
 b.innerHTML=`<span class="mut">${t('selected')}: <b>${selIds.size}</b></span>
  <div class="row" style="gap:6px;justify-content:flex-end">
  <button class="btn ghost sm" id="sall">${t('all')}</button>
  <button class="btn danger sm" id="sdel"${selIds.size?'':' disabled'}>${t('delete_sel')}</button>
  <button class="btn danger sm" id="sdelall">${t('delete_all')}</button></div>`;
 $('#sall').onclick=()=>{hList.forEach(s=>selIds.add(s.id));drawList();bar2()};
 $('#sdel').onclick=()=>confirmDel([...selIds],t('confirm_sel'));
 $('#sdelall').onclick=()=>confirmDel(hList.map(s=>s.id),t('confirm_all'));
}
function confirmDel(ids,msg){
 const m=$('#modal');
 m.innerHTML=`<div class="scrim" id="scrim"><div class="dlg"><b>${t('sure')}</b>
  <p class="mut" style="margin:8px 0 18px">${esc(msg)}</p>
  <div class="row" style="justify-content:flex-end;gap:8px"><button class="btn ghost" id="no">${t('cancel')}</button>
  <button class="btn danger" id="yes">${t('delete')}</button></div></div></div>`;
 $('#no').onclick=()=>{m.innerHTML=''};
 $('#scrim').onclick=e=>{if(e.target.id==='scrim')m.innerHTML=''};
 $('#yes').onclick=async()=>{
  $('#yes').disabled=true;
  try{
   const r=await post('/api/scans/delete',{ids});
   m.innerHTML='';
   toast(t('deleted')+': '+r.deleted);
   cache=null;
   await history();
  }catch(e){m.innerHTML='';toast(e.message)}
 };
}
function toast(msg){const d=document.createElement('div');d.className='toast';d.textContent=msg;document.body.appendChild(d);setTimeout(()=>d.remove(),2600)}
async function history(){
 setNav('hist');
 hList=await scans(true);
 selMode=false;selIds=new Set();
 show(hList.length?`<div class="toolbar"><input id="q" class="inp ltr" placeholder="${esc(t('search'))}"><button class="btn ghost sm" id="selT">${t('select')}</button></div><div id="hl"></div>`
  :`<div class="empty">${t('empty_hist')}</div>`,t('t_hist'));
 if(!hList.length)return;
 drawList();
 $('#q').oninput=drawList;
 $('#selT').onclick=()=>{selMode=!selMode;selIds=new Set();$('#selT').textContent=selMode?t('cancel'):t('select');drawList();bar2()};
 $('#hl').onclick=e=>{
  if(!selMode)return;
  const c=e.target.closest('.sc');if(!c)return;
  const id=c.dataset.id;selIds.has(id)?selIds.delete(id):selIds.add(id);
  drawList();bar2();
 };
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
 const rest={};Object.keys(f).forEach(k=>{if(!used.has(k))rest[k]=f[k]});
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
 const mods=(s.modules||[]).map(m=>`<div class="card"><div class="row sp"><b>${esc(modTitle(m.title||m.name))}</b>
  <span class="chip ${m.status==='completed'?'c-ok':'c-medium'}">${esc(stLabel(m.status))}</span></div>
  <div class="mut">${t('res')}: ${m.findings??0} &middot; ${t('req')}: ${m.requests??0} &middot; ${fdur(m.duration_seconds)}</div></div>`).join('');
 const skipped=(s.coverage||{}).skipped||{};
 const sk=Object.keys(skipped).map(k=>`<div class="card"><b class="ltr">${esc(k)}</b><div class="mut">${esc(skipped[k])}</div></div>`).join('');
 const l=await scans();const meta=l.find(x=>x.id===id)||{};
 show(`<div class="card"><b class="ltr">${esc(s.target)}</b>
  <div class="mut" style="margin:4px 0">${meta.log?'log '+meta.log+' &middot; ':''}${fdate(s.started_at)} &middot; ${fdur(s.duration_seconds)}</div>
  ${s.interrupted?`<p class="c-medium" style="margin:8px 0 0">${t('interrupted')}</p>`:''}
  ${meta.has_html?`<p style="margin:12px 0 0"><a class="btn" href="/report/${esc(id)}.html">${t('orig')}</a></p>`:''}</div>
  <h2>${t('findings')}</h2><div id="fl"></div>
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
  ${info.dev?`<div class="card"><button class="btn ghost" id="devbtn" style="width:100%">${t('dev')}</button></div>`:''}
  <h2>${t('info')}</h2>
  <div class="card"><b>WebScout</b><p class="mut" style="margin:4px 0 8px">${t('desc')}</p>
   <div class="kv"><span>${t('ver')}</span><b class="ltr">${esc(info.version||'')}</b></div>
   <div class="kv"><span>${t('tool')}</span><b class="${info.tool?'c-ok':'c-high'}">${info.tool?t('tool_ok'):t('tool_no')}</b></div>
   <div class="kv"><span>${t('store')}</span><b class="ltr" style="font-size:13px;text-align:end">${esc(info.logs||'')}</b></div></div>
  <div class="card"><b>${t('resp_h')}</b><p class="mut" style="margin:6px 0 0">${t('resp')}</p></div>`,t('t_set'));
 $('#sl').onclick=e=>{const v=e.target.dataset&&e.target.dataset.v;if(!v)return;lang=v;LS.set('zs_lang',v);applyLook();settings()};
 $('#st').onclick=e=>{const v=e.target.dataset&&e.target.dataset.v;if(!v)return;theme=v;LS.set('zs_theme',v);applyLook();settings()};
 if(info.dev)$('#devbtn').onclick=()=>{location.hash='#/dev'};
}

async function devView(){
 setNav('set');
 show(`<div class="card">
  <label class="lbl" for="dev_d">${t('dev_dev')}</label>
  <input id="dev_d" class="inp ltr" placeholder="0123456789abcdef" autocomplete="off" spellcheck="false">
  <label class="lbl">${t('dev_days')}</label>
  <select id="dev_days" class="inp"><option value="7">7</option><option value="30" selected>30</option><option value="90">90</option><option value="365">365</option><option value="0">${t('dev_forever')}</option></select>
  <label class="lbl">${t('dev_feat')}</label>
  <label class="chk"><input type="checkbox" id="dev_f_deep" checked><span>${t('dev_f_deep')}</span></label>
  <p class="mut" style="margin:10px 0">${t('dev_hint')}</p>
  <button class="btn" id="dev_go" style="width:100%">${t('dev_gen')}</button>
  <p id="dev_err" style="color:var(--critical);margin:10px 0 0"></p>
  <div id="dev_out"></div></div>`,t('t_dev'),true);
 $('#dev_go').onclick=async()=>{
  $('#dev_err').textContent='';$('#dev_out').innerHTML='';
  try{
   const r=await post('/api/dev/keygen',{device:$('#dev_d').value.trim().toLowerCase(),days:Number($('#dev_days').value),features:$('#dev_f_deep').checked?['deep']:[]});
   $('#dev_out').innerHTML=`<div class="k">${t('dev_key')}</div><pre class="ltr" id="dev_key">${esc(r.key)}</pre><button class="btn ghost" id="dev_copy" style="width:100%">${t('dev_copy')}</button>`;
   $('#dev_copy').onclick=()=>{try{Android.copy(r.key)}catch(e){try{navigator.clipboard.writeText(r.key)}catch(e2){}}};
  }catch(e){$('#dev_err').textContent=t('dev_fail')+': '+e.message}
 };
}

async function route(){
 const h=location.hash||'#/';
 try{
  if(h.startsWith('#/scan/'))await scanView2(h.slice(7));
  else if(h==='#/last')await scanView2('last');
  else if(h==='#/history')await history();
  else if(h==='#/settings')await settings();
  else if(h==='#/dev'){if(info.dev)await devView();else await settings()}
  else await scanView();
 }catch(e){show(`<div class="empty">${t('err')}<br><span class="mut">${esc(e.message)}</span></div>`)}
}
document.addEventListener('click',e=>{const l=e.target.closest&&e.target.closest('#deeplbl.locked');if(l){e.preventDefault();const er=document.getElementById('err');if(er)er.textContent=t('vip_only')}});
$('#back').onclick=()=>history.length>1?history.back():(location.hash='#/history');
$('#reload').onclick=async()=>{cache=null;await route()};
addEventListener('hashchange',route);
applyLook();route();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    scrub_old_reports()
    print(f"WebScout {VERSION}  ->  http://127.0.0.1:{PORT}")
    print(f"Logs: {LOGS}")
    if not str(LOGS).startswith("/sdcard") and "storage" not in str(LOGS):
        print("Warning: to save logs to phone storage run:  termux-setup-storage  then restart the server")
    print(f"Scanner:   {ZS_HOME}")
    try:
        ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        pass
