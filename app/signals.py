"""Local detection heuristics + Authenticode (Phase B).

- Authenticode / publisher via PowerShell -File authenticode.ps1 -Path <argv> (cached by path+mtime+size; never -Command interpolate)
- Heuristics: suspicious paths, first-seen (in-memory), beacon-ish, odd lineage,
  unusual ports, new listeners
- VirusTotal stub lives in intel.vt_enabled (False)

Phase C: first-seen / new-listener / beacon wire through history.py (SQLite) with in-memory cache in front.
"""
from __future__ import annotations

import os
import re
import statistics
import subprocess
import threading
import time
try:
    from ps51_env import clean_ps51_env
except Exception:  # pragma: no cover
    def clean_ps51_env(base=None):
        import os as _os
        e = dict(base if base is not None else _os.environ)
        e.pop("PSModulePath", None)
        return e

from collections import defaultdict, deque
from typing import Any

import psutil

try:
    import exe_hash as tw_exe_hash
except Exception:  # pragma: no cover
    tw_exe_hash = None  # type: ignore
try:
    import allow_memory as tw_allow
except Exception:  # pragma: no cover
    tw_allow = None  # type: ignore

try:
    import history as tw_history
except Exception:  # pragma: no cover
    tw_history = None  # type: ignore

try:
    import risk as tw_risk
except Exception:  # pragma: no cover
    tw_risk = None  # type: ignore

# --- VirusTotal stub reference (do not enable) ------------------------------
# See intel.vt_enabled = False — "VT upload/query blocked until owner GO".

_auth_lock = threading.RLock()
_auth_cache: dict[str, dict[str, Any]] = {}  # key path|mtime -> result
_auth_inflight: set[str] = set()
_auth_queue: deque[str] = deque()
_auth_worker_started = False

_sig_lock = threading.RLock()
# first-seen: connection key / process key -> first wall time this session
_seen_conn_keys: dict[str, float] = {}
_seen_pids: dict[int, float] = {}
_session_start = time.time()
# beacon: (remote_ip, remote_port) -> deque of appearance timestamps (not every poll)
_beacon_hits: dict[tuple[Any, ...], deque[float]] = defaultdict(lambda: deque(maxlen=24))
# remotes present on previous attach_signals pass (for appearance-edge detection)
_prev_beacon_remotes: set[tuple[str, int]] = set()
# listeners seen this session
_known_listeners: set[tuple[str | None, int | None]] = set()
_listeners_primed = False
# Tier 0: rotating IPs in one ASN (proc -> asn -> ip -> last_seen_ts); time-windowed
_asn_rot_hits: dict[str, dict[str, dict[str, float]]] = {}
_asn_rot_ts: dict[str, float] = {}
ASN_ROT_WINDOW_SEC = 600.0  # ~10 min (not lifetime)
ASN_ROT_THRESHOLD = 8
ASN_ROT_THRESHOLD_SOFT = 16  # Valid-signed known-good cloud publishers
_ASN_SOFT_PUBLISHERS = (
    "microsoft", "anthropic", "anysphere", "google", "amazon", "apple",
    "mozilla", "github", "cloudflare", "openai", "cursor",
)

# Beacon thresholds (also documented in NOTES.md):
# - Observation = remote:port newly present vs previous poll (not "still connected")
# - Need >= BEACON_MIN_INTERVALS intervals (BEACON_MIN_INTERVALS+1 appearances)
# - Mean interval in [BEACON_MEAN_MIN, BEACON_MEAN_MAX] seconds
# - Low jitter: pstdev <= max(BEACON_JITTER_FLOOR, BEACON_JITTER_FRAC * mean)
BEACON_MIN_INTERVALS = 4
BEACON_MIN_INTERVALS_SOFT = 8  # Valid-signed known cloud publishers
BEACON_MEAN_MIN = 5.0
BEACON_MEAN_MAX = 900.0
BEACON_JITTER_FLOOR = 1.5
BEACON_JITTER_FRAC = 0.25

# Well-known / common service ports (conservative allow set)
_WELL_KNOWN_ALLOW = {
    20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 135, 137, 138, 139, 143,
    161, 162, 389, 443, 445, 465, 514, 587, 636, 993, 995, 1433, 1521, 3306,
    3389, 5432, 5900, 8080, 8443, 853, 1900, 5353, 5223, 5228, 8000, 8888,
    27017, 6379, 11211, 500, 4500, 1701, 1723, 1194, 51820,
    # Common Windows service / discovery listeners (Review 4)
    5040, 5355, 5357, 3702, 7680, 5985, 5986, 47001, 2869,
    # TrafficWatch / desk local helpers
    8765, 8766, 8767,
}
_EPHEMERAL_MIN = 49152
# Conservatively "malware-ish" / odd high ports sometimes abused (label unusual only)
_UNUSUAL_HINT_PORTS = {
    4444, 5555, 6666, 6667, 31337, 12345, 27374, 54321, 1337, 2222, 4443,
    8081, 8889, 9999, 10000, 65535,
}
# Windows service + app listeners that are never "unusual" as listeners
_WIN_SERVICE_LISTEN_PORTS = frozenset({
    135, 139, 445, 3389, 5985, 5986, 47001, 2869, 5353, 1900,
    5040, 5355, 5357, 3702, 7680,
})
_APP_LISTEN_ALLOW = frozenset({8765, 8766, 8767})

_SUSPICIOUS_PATH_RES = [
    re.compile(r"(?i)\\temp\\"),
    re.compile(r"(?i)\\tmp\\"),
    re.compile(r"(?i)\\appdata\\local\\temp\\"),
    re.compile(r"(?i)\\users\\[^\\]+\\downloads\\"),
    re.compile(r"(?i)\\\$recycle\.bin\\"),
    re.compile(r"(?i)\\recycle\.bin\\"),
    re.compile(r"(?i)\\programdata\\[^\\]+\\[^\\]+\.exe$"),
    re.compile(r"(?i)\\appdata\\roaming\\[^\\]+\\[^\\]+\.exe$"),
    re.compile(r"(?i)\\appdata\\local\\[^\\]+\\[^\\]+\.exe$"),
]

_SCRIPT_PARENTS = {
    "wscript.exe",
    "cscript.exe",
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
}

_NET_CLIENTISH = {
    "curl.exe",
    "wget.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "powershell.exe",
    "pwsh.exe",
    "python.exe",
    "pythonw.exe",
    "node.exe",
    "cmd.exe",
}



_SYSTEM_LISTENER_NAMES = frozenset({
    "svchost.exe", "system", "[system]", "idle", "registry",
    "services.exe", "lsass.exe", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "fontdrvhost.exe", "dwm.exe", "memory compression",
    "spoolsv.exe", "searchindexer.exe", "searchprotocolhost.exe",
    "runtimebroker.exe", "sihost.exe", "taskhostw.exe", "dllhost.exe",
    "conhost.exe", "dashost.exe", "wudfhost.exe", "securityhealthservice.exe",
    "msmpeng.exe", "nissrv.exe", "shellexperiencehost.exe",
})


def _asn_soft_publisher(auth: dict[str, Any] | None) -> bool:
    """Valid-signed known cloud/OS publishers: higher ASN-rotation threshold."""
    if not auth or auth.get("signed") is not True:
        return False
    pub = (auth.get("publisher") or "").strip().lower()
    if not pub:
        return False
    return any(x in pub for x in _ASN_SOFT_PUBLISHERS)


def _skip_new_listener(r: dict[str, Any], pid, lport, auth: dict[str, Any] | None = None) -> bool:
    """Skip ephemeral/system listeners; keep unexpected user-app listeners.

    Valid-signed apps: skip loopback ephemeral listens (port >= 49152 on
    127.0.0.1/::1) so claude.exe/msedge local high ports do not flood.
    All-interface ephemeral (0.0.0.0/::) is NOT skipped here (ux44); those
    soft-coalesce via port_class ephemeral-any + lower severity instead.
    """
    try:
        p = int(pid) if pid is not None else -1
    except (TypeError, ValueError):
        p = -1
    if p in (0, 4):
        return True
    pname = (r.get("process") or r.get("name") or "").strip().lower()
    bare = pname[:-4] if pname.endswith(".exe") else pname
    sys_bares = {x[:-4] if x.endswith(".exe") else x for x in _SYSTEM_LISTENER_NAMES}
    if pname in _SYSTEM_LISTENER_NAMES or bare in sys_bares or bare + ".exe" in _SYSTEM_LISTENER_NAMES:
        return True
    if bare == "svchost" or pname in ("svchost.exe", "svchost"):
        return True
    try:
        port_i = int(lport) if lport is not None else -1
    except (TypeError, ValueError):
        port_i = -1
    # Valid-signed: collapse/skip loopback ephemeral local binds
    if (
        auth
        and auth.get("signed") is True
        and port_i >= _EPHEMERAL_MIN
        and _is_localhost_bind(r.get("local_ip"))
    ):
        return True
    return False


def _conn_key(r: dict[str, Any]) -> str:
    return (
        f"{r.get('proto')}|{r.get('pid')}|{r.get('local_ip')}:{r.get('local_port')}|"
        f"{r.get('remote_ip')}:{r.get('remote_port')}|{r.get('status')}"
    )


def _auth_cache_key(path: str, mtime: float, size: int) -> str:
    return f"{path}|{mtime:.3f}|{size}"


def _auth_file_meta(path: str) -> tuple[float, int]:
    try:
        st = os.stat(path)
        return float(st.st_mtime), int(st.st_size)
    except OSError:
        return 0.0, 0


def _auth_timeout_for_size(size: int) -> float:
    """Background-worker timeout scales with exe size (not used on snapshot path)."""
    if size > 100 * 1024 * 1024:
        return 30.0
    if size > 10 * 1024 * 1024:
        return 20.0
    return 8.0


_AUTH_HELPER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "authenticode.ps1")


def _authenticode_argv(path: str) -> list[str]:
    """Build argv for Authenticode lookup. Path is a separate argv element (never concatenated into -Command)."""
    return [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        _AUTH_HELPER,
        "-Path",
        path,
    ]


# Legacy name kept for grep; real limits come from _auth_timeout_for_size (+ retry 30s).
_AUTH_TIMEOUT_SEC = 8.0
_AUTH_RETRY_TIMEOUT_SEC = 30.0
_auth_allowed = False  # desktop enables after first window; never block boot
_auth_timeout_retries: dict[str, int] = {}  # path -> completed timeout attempts (max 1 retry)




def set_auth_allowed(on: bool) -> None:
    """Allow Authenticode PowerShell after the live UI is up."""
    global _auth_allowed
    _auth_allowed = bool(on)
    if _auth_allowed:
        # ux46: do not block phase-2 / first poll_loop on PS self-test (up to 15s)
        try:
            threading.Thread(
                target=selftest_authenticode,
                name="tw-auth-selftest",
                daemon=True,
            ).start()
        except Exception:
            pass


def _is_cloud_path(path: str) -> bool:
    """OneDrive / iCloud / Dropbox / CloudStorage placeholders hang Get-AuthenticodeSignature."""
    p = (path or "").replace("/", "\\").lower()
    markers = (
        "\\onedrive",
        "\\icloud",
        "\\dropbox",
        "\\google drive",
        "\\cloudstorage\\",
        "\\box\\",
    )
    return any(m in p for m in markers)


def _kill_process_tree(pid: int) -> None:
    if not pid:
        return
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
            timeout=4,
            creationflags=flags,
        )
    except Exception:
        pass
    try:
        os.kill(pid, 9)
    except OSError:
        pass


def _run_authenticode(path: str, timeout_sec: float | None = None) -> dict[str, Any]:
    """Windows: PowerShell Get-AuthenticodeSignature via static -File helper. Best-effort."""
    out: dict[str, Any] = {
        "signed": None,
        "status": "unknown",
        "publisher": None,
        "issuer": None,
        "expired": None,
        "error": None,
    }
    if os.name != "nt":
        out["status"] = "unsupported"
        out["error"] = "Authenticode only on Windows"
        return out
    if not path:
        out["status"] = "missing"
        return out
    if _is_cloud_path(path):
        out["status"] = "skipped"
        out["error"] = "cloud path"
        return out
    if not os.path.isfile(path):
        out["status"] = "missing"
        return out
    if timeout_sec is None:
        _mtime, size = _auth_file_meta(path)
        timeout_sec = _auth_timeout_for_size(size)
    proc = None
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.Popen(
            _authenticode_argv(path),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=clean_ps51_env(),
            creationflags=flags,
        )
        stdout, stderr = proc.communicate(timeout=float(timeout_sec))
        if proc.returncode != 0:
            out["error"] = (stderr or stdout or "powershell failed")[:200]
            out["status"] = "error"
            return out
        import json

        raw = (stdout or "").strip()
        if not raw:
            out["status"] = "error"
            out["error"] = "empty signature response"
            return out
        data = json.loads(raw)
        status = str(data.get("Status") or "Unknown")
        out["status"] = status
        out["publisher"] = data.get("Publisher")
        out["issuer"] = data.get("Issuer")
        out["expired"] = bool(data.get("Expired")) if data.get("Expired") is not None else None
        out["signed"] = status.lower() == "valid"
        if status.lower() == "notsigned":
            out["signed"] = False
        elif status.lower() in ("unknownerror", "hashmismatch", "nottrusted", "skipped"):
            out["signed"] = False
        return out
    except subprocess.TimeoutExpired:
        if proc is not None:
            _kill_process_tree(proc.pid)
            try:
                proc.kill()
            except Exception:
                pass
            try:
                proc.communicate(timeout=1)
            except Exception:
                pass
        out["status"] = "timeout"
        out["error"] = "lookup timed out"
        return out
    except Exception as e:
        if proc is not None:
            _kill_process_tree(proc.pid)
        out["status"] = "error"
        out["error"] = str(e)[:200]
        return out


_auth_selftest_done = False


def _flush_print(*args, **kwargs):
    """print with flush so self-test lines show under redirected stdout."""
    kwargs.setdefault("flush", True)
    print(*args, **kwargs)


def selftest_authenticode(log=_flush_print) -> bool:
    """One-shot check that Get-AuthenticodeSignature works under clean PS 5.1 env.

    Returns True if Valid/usable; logs one clear warning and returns False otherwise.
    Safe to call repeatedly (runs once).
    """
    global _auth_selftest_done
    if _auth_selftest_done:
        return True
    _auth_selftest_done = True
    if os.name != "nt":
        return True
    probe = r"C:\Windows\System32\notepad.exe"
    if not os.path.isfile(probe):
        probe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    if not os.path.isfile(probe):
        try:
            log("WARNING: Authenticode self-test skipped (no probe exe)")
        except Exception:
            pass
        return False
    try:
        result = _run_authenticode(probe, timeout_sec=15.0)
        status = str((result or {}).get("status") or "")
        signed = (result or {}).get("signed")
        if signed is True or status.lower() == "valid":
            try:
                log("Authenticode self-test: Get-AuthenticodeSignature OK (Valid)")
            except Exception:
                pass
            return True
        err = (result or {}).get("error") or status or "unknown"
        try:
            log(
                "WARNING: Get-AuthenticodeSignature unavailable or failed "
                f"({err!s}). Signature checks may show unverified; "
                "ensure PSModulePath is not polluting powershell.exe 5.1 "
                "(ux45 clean_ps51_env)."
            )
        except Exception:
            pass
        return False
    except Exception as e:
        try:
            log("WARNING: Get-AuthenticodeSignature self-test error: " + str(e)[:160])
        except Exception:
            pass
        return False


def _auth_worker() -> None:
    while True:
        path = None
        with _auth_lock:
            if _auth_queue:
                path = _auth_queue.popleft()
            else:
                _auth_inflight.clear()  # nothing pending
        if not path:
            time.sleep(0.35)
            continue
        mtime, size = _auth_file_meta(path)
        key = _auth_cache_key(path, mtime, size)
        with _auth_lock:
            prior_timeouts = int(_auth_timeout_retries.get(path, 0))
        if prior_timeouts > 0:
            timeout_sec = _AUTH_RETRY_TIMEOUT_SEC
        else:
            timeout_sec = _auth_timeout_for_size(size)
        result = _run_authenticode(path, timeout_sec=timeout_sec)
        result["path"] = path
        result["mtime"] = mtime
        result["size"] = size
        result["checked_at"] = time.time()
        result["timeout_sec"] = timeout_sec
        st = (result.get("status") or "").lower()
        with _auth_lock:
            if st == "timeout":
                # Do NOT permanently cache first timeout; retry once with longer limit.
                n = int(_auth_timeout_retries.get(path, 0)) + 1
                _auth_timeout_retries[path] = n
                if n <= 1:
                    result["status"] = "checking"
                    result["error"] = "lookup timed out; retrying"
                    # Soft marker only (UI: checking). Re-queue for retry.
                    _auth_inflight.discard(path)
                    if path not in _auth_inflight:
                        _auth_inflight.add(path)
                        _auth_queue.append(path)
                    time.sleep(0.15)
                    continue
                # Second timeout: surface failure (cacheable).
                result["status"] = "timeout"
                result["error"] = "lookup timed out after retry"
                _auth_cache[key] = result
                _auth_inflight.discard(path)
                _auth_timeout_retries.pop(path, None)
            else:
                # Successful Valid/NotSigned/skipped/error/etc. — cache permanently.
                _auth_cache[key] = result
                _auth_inflight.discard(path)
                _auth_timeout_retries.pop(path, None)
        time.sleep(0.05)  # be gentle


def _ensure_auth_worker() -> None:
    global _auth_worker_started
    if _auth_worker_started:
        return
    _auth_worker_started = True
    threading.Thread(target=_auth_worker, name="tw-auth-worker", daemon=True).start()


# Soft ceiling for UI "checking" while queued/running/retrying (worker owns real timeout).
# Must exceed size-scaled attempt + one retry (8-30s + 30s) plus queue wait.
_AUTH_PENDING_TIMEOUT_SEC = 120.0
_auth_pending_since: dict[str, float] = {}


def get_authenticode(path: str | None, *, enqueue: bool = True) -> dict[str, Any] | None:
    """Return cached Authenticode info; optionally enqueue async lookup.

    Snapshot path stays non-blocking. Queued/running/retrying -> status "checking".
    Timeout is not permanently cached until after one longer retry fails.
    """
    if not path:
        return None
    checking = {
        "signed": None,
        "status": "checking",
        "publisher": None,
        "issuer": None,
        "expired": None,
        "path": path,
    }
    if not _auth_allowed:
        return checking
    if _is_cloud_path(path):
        return {
            "signed": None,
            "status": "skipped",
            "publisher": None,
            "issuer": None,
            "expired": None,
            "path": path,
            "error": "cloud path",
        }
    _ensure_auth_worker()
    mtime, size = _auth_file_meta(path)
    if mtime == 0.0 and size == 0 and not os.path.isfile(path):
        return {
            "signed": None,
            "status": "missing",
            "publisher": None,
            "issuer": None,
            "expired": None,
            "path": path,
        }
    key = _auth_cache_key(path, mtime, size)
    now = time.time()
    with _auth_lock:
        hit = _auth_cache.get(key)
        if hit:
            st = (hit.get("status") or "").lower()
            # Never treat a stale timeout soft-marker as final if somehow present.
            if st == "timeout" and int(_auth_timeout_retries.get(path, 0)) < 1:
                # Should not be cached; fall through to re-enqueue.
                _auth_cache.pop(key, None)
            else:
                _auth_pending_since.pop(path, None)
                return dict(hit)
        # Soft UI ceiling after worker + retry window; do NOT permanently cache
        # until worker recorded a post-retry timeout (hit path above).
        started = _auth_pending_since.get(path)
        if started is not None and (now - started) >= _AUTH_PENDING_TIMEOUT_SEC:
            # Still checking from UI POV if worker may be mid-retry; only surface
            # unverified when a final timeout is in cache. Keep enqueued.
            if enqueue and path not in _auth_inflight:
                _auth_inflight.add(path)
                _auth_queue.append(path)
            return dict(checking)
        if enqueue and path not in _auth_inflight:
            _auth_inflight.add(path)
            _auth_queue.append(path)
            _auth_pending_since.setdefault(path, now)
        elif path not in _auth_pending_since:
            _auth_pending_since[path] = now
    return dict(checking)


def publisher_hint(auth: dict[str, Any] | None) -> str:
    """Short Authenticode label for list rows.

    Language rules: checking while queued/running/retrying; unverified only after
    real failure; no-exe / system → unknown (never fake unverified).
    """
    if not auth:
        return "unknown"
    st = (auth.get("status") or "").lower()
    if st in ("pending", "checking"):
        return "checking"
    if st in ("timeout", "error"):
        return "unverified"
    if st == "notsigned":
        return "unsigned"
    if st in ("missing", "unsupported", "unknown", "system"):
        return "unknown" if st != "system" else "system"
    if auth.get("signed") is True:
        pub = (auth.get("publisher") or "").strip()
        if not pub:
            return "signed"
        # Shorten common Microsoft
        low = pub.lower()
        if "microsoft" in low:
            return "Microsoft"
        if len(pub) > 28:
            return pub[:26] + "…"
        return pub
    if st == "skipped":
        return "unknown"
    # Any residual failure-ish status → unverified (no network/CDN language)
    if st in ("unknownerror", "hashmismatch", "nottrusted"):
        return "unverified" if st == "unknownerror" else st
    return st or "unknown"


def authenticode_display(auth: dict[str, Any] | None) -> dict[str, str]:
    """UI-facing Authenticode copy: checking -> unverified; never network-fail wording."""
    if not auth:
        return {"label": "unknown", "detail": ""}
    st = (auth.get("status") or "").lower()
    if st in ("pending", "checking"):
        return {"label": "checking", "detail": "Authenticode lookup in progress"}
    if st in ("timeout", "error"):
        return {"label": "unverified", "detail": "Signature could not be verified"}
    if st == "notsigned":
        return {"label": "unsigned", "detail": "Executable is not Authenticode-signed"}
    if auth.get("signed") is False and st not in ("valid",):
        return {"label": "unverified", "detail": "Signature could not be verified"}
    if auth.get("signed") is True:
        pub = (auth.get("publisher") or "").strip() or "signed"
        return {"label": "signed", "detail": pub}
    if st == "missing":
        return {"label": "unknown", "detail": "Executable path unavailable"}
    if st in ("unsupported",):
        return {"label": "unknown", "detail": "Authenticode only on Windows"}
    return {"label": publisher_hint(auth), "detail": st or ""}


def _suspicious_path(path: str | None) -> bool:
    if not path:
        return False
    for rx in _SUSPICIOUS_PATH_RES:
        if rx.search(path):
            return True
    return False


# Cleared at the start of each attach_signals() — cache per-PID for one snapshot.
_snap_exe_cache: dict[int, str | None] = {}
_snap_parent_cache: dict[int, str | None] = {}
_snap_proc_cache: dict[int, Any] = {}


def _snap_process(pid: int) -> Any | None:
    """Reuse one psutil.Process handle per PID for the duration of build_snapshot."""
    cached = _snap_proc_cache.get(pid)
    if cached is not None:
        return cached
    try:
        p = psutil.Process(pid)
        _snap_proc_cache[pid] = p
        return p
    except (psutil.Error, OSError, ValueError):
        return None


def _parent_name(pid: int | None) -> str | None:
    if not pid:
        return None
    if pid in _snap_parent_cache:
        return _snap_parent_cache[pid]
    name: str | None = None
    try:
        p = _snap_process(int(pid))
        if p is None:
            _snap_parent_cache[pid] = None
            return None
        ppid = p.ppid()
        if not ppid:
            _snap_parent_cache[pid] = None
            return None
        parent = _snap_process(int(ppid))
        name = parent.name() if parent is not None else None
    except (psutil.Error, OSError, ValueError):
        name = None
    _snap_parent_cache[pid] = name
    return name


def _exe_for_pid(pid: int | None) -> str | None:
    if not pid:
        return None
    if pid in _snap_exe_cache:
        return _snap_exe_cache[pid]
    path: str | None = None
    try:
        p = _snap_process(int(pid))
        path = p.exe() if p is not None else None
    except (psutil.Error, OSError, ValueError):
        path = None
    _snap_exe_cache[pid] = path
    return path


def _normalize_bind_ip(ip: str | None) -> str:
    if not ip:
        return ""
    s = str(ip).strip().lower()
    if s.startswith("::ffff:"):
        s = s[7:]
    return s


def _is_localhost_bind(ip: str | None) -> bool:
    s = _normalize_bind_ip(ip)
    return s in ("127.0.0.1", "::1", "localhost")


def _is_any_interface_bind(ip: str | None) -> bool:
    """All-interface / unspecified bind (0.0.0.0 / :: / empty)."""
    s = _normalize_bind_ip(ip)
    if not s:
        return True
    return s in ("0.0.0.0", "::", "*", "[::]")


def _is_exposed_bind(ip: str | None) -> bool:
    """True when listener is bound on all-interfaces or non-loopback (LAN-exposed)."""
    s = _normalize_bind_ip(ip)
    if not s:
        return False
    if s in ("0.0.0.0", "::", "*", "[::]"):
        return True
    if _is_localhost_bind(s):
        return False
    return True


def _unusual_port(
    port: int | None,
    *,
    as_listener: bool = False,
    local_ip: str | None = None,
) -> bool:
    """Unusual remote/listen port heuristic (Review 4: exposure-aware listeners)."""
    if port is None:
        return False
    if port in _WELL_KNOWN_ALLOW:
        return False
    if as_listener:
        # Ephemeral listeners are normal Windows dynamic binds — never unusual.
        if port >= _EPHEMERAL_MIN:
            return False
        if port in _WIN_SERVICE_LISTEN_PORTS or port in _APP_LISTEN_ALLOW:
            return False
        # Only flag remaining unusual listeners when LAN-exposed (not localhost-only).
        if not _is_exposed_bind(local_ip):
            return False
        if port in _UNUSUAL_HINT_PORTS:
            return True
        if port > 1024:
            return True
        return False
    # Outbound / client: skip ephemeral client ports; keep hint + uncommon service ports.
    if port >= _EPHEMERAL_MIN:
        return False
    if port in _UNUSUAL_HINT_PORTS:
        return True
    if 1024 < port < _EPHEMERAL_MIN and port not in _WELL_KNOWN_ALLOW:
        if port in _UNUSUAL_HINT_PORTS or port >= 10000:
            return True
    return False


def _is_beacon_intervals(intervals: list[float]) -> bool:
    if len(intervals) < BEACON_MIN_INTERVALS:
        return False
    try:
        mean = statistics.mean(intervals)
        if mean < BEACON_MEAN_MIN or mean > BEACON_MEAN_MAX:
            return False
        sd = statistics.pstdev(intervals)
        return sd <= max(BEACON_JITTER_FLOOR, BEACON_JITTER_FRAC * mean)
    except statistics.StatisticsError:
        return False


def _beacon_flagged_remotes(current: set[tuple[str, int]], now: float) -> set[tuple[str, int]]:
    """Record appearance-edge observations; return remotes that match beacon rule.

    A persistent always-present connection is NOT a beacon. Only remote:port that
    disappears and reappears (or first appears after being absent) creates an
    observation timestamp. Uses history.note_beacon_observation when available.
    """
    global _prev_beacon_remotes
    flagged: set[tuple[str, int]] = set()
    appeared = current - _prev_beacon_remotes
    with _sig_lock:
        for rip, rport in appeared:
            key = (rip, int(rport))
            hist_flag = False
            if tw_history:
                try:
                    hist_flag = bool(tw_history.note_beacon_observation(rip, int(rport), now))
                except Exception:
                    hist_flag = False
            dq = _beacon_hits[key]
            dq.append(now)
            intervals = [dq[i] - dq[i - 1] for i in range(1, len(dq))]
            if hist_flag or _is_beacon_intervals(intervals):
                flagged.add(key)
                if tw_history and intervals:
                    try:
                        tw_history.note_beacon_interval(f"{rip}|{rport}", intervals[-1])
                    except Exception:
                        pass
        _prev_beacon_remotes = set(current)
    return flagged


def attach_signals(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Annotate each connection with signals[] and auth hint fields. Fast path."""
    # Per-snapshot PID caches (exe/parent/Process). Profile note: repeated
    # psutil.Process(pid) per row was a major cost vs POLL_SECONDS=1.5.
    _snap_exe_cache.clear()
    _snap_parent_cache.clear()
    _snap_proc_cache.clear()
    global _listeners_primed, _seen_conn_keys, _seen_pids
    now = time.time()
    # Collect current listeners
    current_listeners: set[tuple[str | None, int | None]] = set()
    for r in rows:
        if (r.get("status") or "").upper() == "LISTEN" or r.get("direction") == "listen":
            current_listeners.add((r.get("local_ip"), r.get("local_port")))

    with _sig_lock:
        if not _listeners_primed:
            _known_listeners.update(current_listeners)
            # Seed history for existing listeners quietly (no new_listener storm)
            if tw_history:
                try:
                    tw_history.init()
                    for lip, lp in current_listeners:
                        if lp is not None:
                            # find a pid later in loop; seed port-only via listen_first_seen
                            tw_history.listen_first_seen(lp, None)
                except Exception:
                    pass
            _listeners_primed = True
            new_listeners = set()
        else:
            new_listeners = current_listeners - _known_listeners
            _known_listeners.update(current_listeners)

    # Prefetch exe paths + parent names + enqueue auth (dedupe per PID/path)
    exe_by_pid: dict[int, str | None] = {}
    auth_by_path: dict[str, dict[str, Any] | None] = {}
    for r in rows:
        pid = r.get("pid")
        if not pid or pid in exe_by_pid:
            continue
        exe = _exe_for_pid(pid)
        exe_by_pid[pid] = exe
        _parent_name(pid)  # warm parent cache once per PID
        if exe and exe not in auth_by_path:
            auth_by_path[exe] = get_authenticode(exe, enqueue=True)

    # Appearance-edge beacon detection across this poll vs previous
    current_beacon_remotes: set[tuple[str, int]] = set()
    for r in rows:
        rip0 = r.get("remote_ip")
        rport0 = r.get("remote_port")
        if rip0 and rport0 is not None and (r.get("status") or "").upper() == "ESTABLISHED":
            current_beacon_remotes.add((rip0, int(rport0)))
    beacon_flagged = _beacon_flagged_remotes(current_beacon_remotes, now)

    for r in rows:
        signals: list[dict[str, Any]] = []
        pid = r.get("pid")
        exe = exe_by_pid.get(pid) if pid else None
        if exe:
            auth = auth_by_path.get(exe)
        else:
            # System / access-denied / no path: never fake "unverified"
            pname = (r.get("process") or r.get("name") or "").strip().lower()
            st = "system" if pname in ("system", "[system]", "idle", "registry") else "unknown"
            auth = {
                "signed": None,
                "status": st,
                "publisher": None,
                "issuer": None,
                "expired": None,
                "path": None,
            }
        r["exe"] = exe
        r["authenticode"] = auth
        r["publisher_hint"] = publisher_hint(auth)

        # first-seen (in-memory + history SQLite across restarts)
        ck = _conn_key(r)
        with _sig_lock:
            if ck not in _seen_conn_keys:
                _seen_conn_keys[ck] = now
                hist_prev = None
                if tw_history and r.get("remote_ip"):
                    try:
                        hist_prev = tw_history.remote_first_seen(
                            r.get("remote_ip"), r.get("remote_port")
                        )
                    except Exception:
                        hist_prev = None
                if now - _session_start > 8 and hist_prev is None:
                    signals.append(
                        {
                            "id": "first_seen",
                            "label": "first-seen",
                            "severity": "info",
                            "detail": "New remote endpoint (persisted history)",
                        }
                    )
            if pid and pid not in _seen_pids:
                _seen_pids[pid] = now
                exe_path = exe
                hist_proc = None
                if tw_history and exe_path:
                    try:
                        hist_proc = tw_history.process_first_seen(exe_path, pid)
                    except Exception:
                        hist_proc = None
                if now - _session_start > 8 and hist_proc is None:
                    signals.append(
                        {
                            "id": "new_process",
                            "label": "new process",
                            "severity": "info",
                            "detail": f"PID {pid} / path first seen (persisted history)",
                        }
                    )
                elif now - _session_start > 8 and not exe_path:
                    signals.append(
                        {
                            "id": "new_process",
                            "label": "new process",
                            "severity": "info",
                            "detail": f"PID {pid} first seen this session",
                        }
                    )

        # suspicious path
        if _suspicious_path(exe):
            detail = "Process path looks temporary / Downloads / odd AppData"
            if auth and auth.get("signed") is False:
                detail += "; unsigned"
                signals.append(
                    {
                        "id": "suspicious_path",
                        "label": "odd path",
                        "severity": "medium",
                        "detail": detail,
                    }
                )
            else:
                signals.append(
                    {
                        "id": "suspicious_path",
                        "label": "odd path",
                        "severity": "low",
                        "detail": detail,
                    }
                )

        # unsigned in weird folder already covered; bare unsigned as mild hint on non-system
        if auth and auth.get("status", "").lower() == "notsigned" and exe:
            low = exe.lower()
            if "\\windows\\" not in low and "\\program files" not in low:
                if not any(s["id"] == "suspicious_path" for s in signals):
                    signals.append(
                        {
                            "id": "unsigned",
                            "label": "unsigned",
                            "severity": "low",
                            "detail": "Executable is not Authenticode-signed",
                        }
                    )

        # odd lineage
        pname = (r.get("process") or "").lower()
        parent = _parent_name(pid)
        if parent:
            r["parent_process"] = parent
            pl = parent.lower()
            if pl in _SCRIPT_PARENTS and (pname in _NET_CLIENTISH or r.get("remote_ip")):
                # office/script hosting a net client — best-effort
                if pl in {
                    "wscript.exe",
                    "cscript.exe",
                    "mshta.exe",
                    "winword.exe",
                    "excel.exe",
                    "powerpnt.exe",
                } or (
                    pl in {"powershell.exe", "pwsh.exe", "cmd.exe"}
                    and pname in {"curl.exe", "wget.exe", "certutil.exe", "bitsadmin.exe"}
                ):
                    signals.append(
                        {
                            "id": "odd_lineage",
                            "label": "odd parent",
                            "severity": "medium",
                            "detail": f"Parent {parent} → {r.get('process')}",
                        }
                    )

        # unusual ports
        rip = r.get("remote_ip")
        rport = r.get("remote_port")
        lport = r.get("local_port")
        is_listen = (r.get("status") or "").upper() == "LISTEN" or r.get("direction") == "listen"
        if is_listen and _unusual_port(lport, as_listener=True, local_ip=r.get("local_ip")):
            signals.append(
                {
                    "id": "unusual_port",
                    "label": "unusual listen",
                    "severity": "low",
                    "detail": f"Listening on uncommon port {lport}",
                }
            )
        elif rip and _unusual_port(rport, as_listener=False):
            signals.append(
                {
                    "id": "unusual_port",
                    "label": "unusual port",
                    "severity": "low",
                    "detail": f"Remote port {rport} not in common allow set",
                }
            )

        # new listeners (session delta + history across restarts)
        if is_listen and (r.get("local_ip"), lport) in new_listeners:
            if _skip_new_listener(r, pid, lport, auth):
                # Seed history quietly; no alert for system/ephemeral listeners
                if tw_history:
                    try:
                        tw_history.listen_first_seen(lport, pid)
                    except Exception:
                        pass
            else:
                hist_listen = None
                if tw_history:
                    try:
                        hist_listen = tw_history.listen_first_seen(lport, pid)
                    except Exception:
                        hist_listen = None
                if hist_listen is None:
                    try:
                        port_i2 = int(lport) if lport is not None else -1
                    except (TypeError, ValueError):
                        port_i2 = -1
                    # ux44: Valid-signed ephemeral all-interface -> soft class + prefer low sev
                    ephemeral_any = bool(
                        auth
                        and auth.get("signed") is True
                        and port_i2 >= _EPHEMERAL_MIN
                        and _is_any_interface_bind(r.get("local_ip"))
                    )
                    sev = (
                        "high"
                        if (lport and _unusual_port(lport, as_listener=True, local_ip=r.get("local_ip")))
                        else "info"
                    )
                    if ephemeral_any:
                        # Prefer lower severity (often disappears within seconds)
                        sev = "info"
                    _proto = (r.get("proto") or "TCP").upper()
                    if _proto not in ("TCP", "UDP"):
                        _proto = "TCP"
                    detail = f"{_proto} LISTEN :{lport} first seen (persisted history)"
                    if ephemeral_any:
                        detail += " [ephemeral-any]"
                    sig: dict[str, Any] = {
                        "id": "new_listener",
                        "label": "new listen",
                        "severity": sev,
                        "detail": detail,
                    }
                    if ephemeral_any:
                        sig["port_class"] = "ephemeral-any"
                    signals.append(sig)
                    if tw_history:
                        try:
                            tw_history.record_event(
                                "new_listener",
                                {
                                    "port": lport,
                                    "pid": pid,
                                    "process": r.get("process"),
                                    "port_class": "ephemeral-any" if ephemeral_any else None,
                                },
                            )
                        except Exception:
                            pass

        # beacon-ish: appearance-edge cadence for this remote:port (not every poll)
        if rip and rport and (rip, int(rport)) in beacon_flagged:
            if (r.get("status") or "").upper() == "ESTABLISHED":
                soft_b = _asn_soft_publisher(auth)
                emit_beacon = True
                need = BEACON_MIN_INTERVALS
                # Valid cloud publishers: longer observation before soft-flood fires
                if soft_b:
                    need = BEACON_MIN_INTERVALS_SOFT
                    with _sig_lock:
                        dq_b = _beacon_hits.get((rip, int(rport)))
                        n_int = (len(dq_b) - 1) if dq_b else 0
                    if n_int < BEACON_MIN_INTERVALS_SOFT:
                        emit_beacon = False
                if emit_beacon:
                    signals.append(
                        {
                            "id": "beacon",
                            "label": "beacon-ish",
                            "severity": "medium",
                            "detail": (
                                f"Repeating {rip}:{rport} at regular intervals "
                                f"(>= {need} intervals, low jitter; not always-on)"
                                + (" (soft-pub)" if soft_b else "")
                            ),
                        }
                    )
                    if tw_history:
                        try:
                            tw_history.record_event(
                                "beacon",
                                {"ip": rip, "port": rport, "pid": pid, "process": r.get("process")},
                            )
                        except Exception:
                            pass

        # Review 3 inbound-visibility: public remote hitting us
        if (
            (r.get("direction") or "") == "inbound"
            and rip
            and not r.get("private_remote")
        ):
            known = False
            if tw_history and lport is not None:
                try:
                    known = int(lport) in tw_history.known_listen_ports()
                except Exception:
                    known = False
            basis = (r.get("direction_basis") or "")
            if basis == "confirmed":
                known = True
            sev = "medium" if known else "high"
            detail = (
                f"Public remote {rip} inbound to local :{lport}"
                + (" (confirmed listener)" if basis == "confirmed" else " (guessed direction)")
                + ("; local port not in listener history" if not known else "")
            )
            signals.append(
                {
                    "id": "public_inbound",
                    "label": "public inbound",
                    "severity": sev,
                    "detail": detail,
                }
            )
            if tw_history:
                try:
                    tw_history.record_event(
                        "public_inbound",
                        {"ip": rip, "port": lport, "pid": pid, "basis": basis, "severity": sev},
                    )
                except Exception:
                    pass

        # Tier 0: SHA-256 + new_binary_network / hash_changed_same_publisher
        sha_info = None
        if tw_exe_hash and exe:
            try:
                sha_info = tw_exe_hash.get_hash(exe)
            except Exception:
                sha_info = None
        if sha_info:
            r["exe_sha256"] = sha_info.get("sha256")
            r["exe_sha256_short"] = sha_info.get("short")
            pub = (auth or {}).get("publisher") if auth else None
            try:
                changed = tw_exe_hash.note_path_hash(exe, sha_info.get("sha256"), pub)
            except Exception:
                changed = None
            has_net = bool(r.get("remote_ip")) and not r.get("private_remote")
            if has_net:
                seen_net = False
                try:
                    seen_net = tw_exe_hash.hash_seen_with_network(sha_info.get("sha256"))
                except Exception:
                    seen_net = False
                if not seen_net and now - _session_start > 8:
                    signals.append(
                        {
                            "id": "new_binary_network",
                            "label": "new binary net",
                            "severity": "medium",
                            "detail": f"SHA-256 {sha_info.get('short')} first network access",
                        }
                    )
                try:
                    tw_exe_hash.note_network_hash(sha_info.get("sha256"))
                except Exception:
                    pass
            if changed:
                signals.append(
                    {
                        "id": "hash_changed_same_publisher",
                        "label": "hash changed",
                        "severity": "high",
                        "detail": (
                            f"Same path/publisher, hash {changed.get('prev_short')} -> "
                            f"{changed.get('short')}"
                        ),
                    }
                )
            r["trust_key"] = tw_exe_hash.trust_tuple(
                exe, pub, sha_info.get("sha256")
            )

        # Tier 0: many short connections to rotating IPs in one ASN (time window)
        geo = r.get("geo") if isinstance(r.get("geo"), dict) else {}
        asn = (geo or {}).get("asn")
        rip = r.get("remote_ip")
        if asn and rip and not r.get("private_remote") and exe:
            pk = (exe or "").lower()
            bucket = _asn_rot_hits.setdefault(pk, {}).setdefault(str(asn), {})
            bucket[str(rip)] = now
            _asn_rot_ts[pk] = now
            # Prune IPs outside the window (lifetime sets caused alert floods)
            cutoff = now - ASN_ROT_WINDOW_SEC
            for ip_old, ts_old in list(bucket.items()):
                if ts_old < cutoff:
                    bucket.pop(ip_old, None)
            # Occasional prune of idle procs
            if len(_asn_rot_ts) > 200:
                dead = [k for k, t in _asn_rot_ts.items() if t < cutoff]
                for k in dead[:80]:
                    _asn_rot_ts.pop(k, None)
                    _asn_rot_hits.pop(k, None)
            soft = _asn_soft_publisher(auth)
            thr = ASN_ROT_THRESHOLD_SOFT if soft else ASN_ROT_THRESHOLD
            hosting = (geo or {}).get("hosting")
            n_ips = len(bucket)
            # Soft publishers: suppress lone ASN rotation unless hosting + high count
            if n_ips >= thr and (hosting or n_ips >= thr + 4):
                if soft and not hosting and n_ips < ASN_ROT_THRESHOLD_SOFT + 4:
                    pass
                else:
                    signals.append(
                        {
                            "id": "asn_rotating",
                            "label": "ASN rotating IPs",
                            "severity": "medium",
                            "detail": (
                                f"{n_ips} remotes in {asn} (~{int(ASN_ROT_WINDOW_SEC/60)}m)"
                                + (" (hosting)" if hosting else "")
                                + (" (soft-pub)" if soft else "")
                            ),
                        }
                    )

        # Tier 0 allow-memory note (age 30d)
        if tw_allow and rip and r.get("remote_port") is not None and not r.get("private_remote"):
            try:
                tw_allow.note(
                    exe=exe,
                    name=r.get("process"),
                    sha=(sha_info or {}).get("sha256") if sha_info else None,
                    asn=asn,
                    host=r.get("hostname"),
                    ip=rip,
                    port=r.get("remote_port"),
                )
            except Exception:
                pass

        # Tier 0 combination scoring: one combined alert instead of a pile
        ids_now = {str(s.get("id")) for s in signals}
        newish = bool(ids_now & {"new_binary_network", "hash_changed_same_publisher", "new_process"})
        untrusted_id = bool(ids_now & {"unsigned", "suspicious_path"}) or (
            auth and auth.get("signed") is False
        )
        bad_hood = bool(
            (r.get("intel") or {}).get("hit")
            or (ids_now & {"baseline_depart", "asn_rotating"})
            or (geo or {}).get("hosting") and "asn_rotating" in ids_now
        )
        weird = bool(ids_now & {"beacon", "unusual_port", "doh_unusual", "exfil_ish"})
        ctx_break = bool(
            ids_now & {"net_context_change", "config_drift"}
            or (r.get("net_context") or {}).get("untrusted")
        )
        stack = sum(1 for x in (newish, untrusted_id, bad_hood, weird, ctx_break) if x)
        # Require strong stack (4+) OR (new unsigned binary + 2 more) to keep R4 FP quiet
        if stack >= 4 or (newish and untrusted_id and stack >= 3):
            drop = {
                "new_binary_network", "unsigned", "suspicious_path",
                "unusual_port", "new_process", "first_seen",
            }
            # Keep hash_changed as its own high signal; drop the noisy stack pieces
            signals = [s for s in signals if s.get("id") not in drop]
            if stack >= 3:
                signals.insert(
                    0,
                    {
                        "id": "combined_threat",
                        "label": "combined threat",
                        "severity": "high",
                        "detail": (
                            "Stacked: "
                            + ", ".join(
                                n for n, f in (
                                    ("new", newish),
                                    ("untrusted-id", untrusted_id),
                                    ("bad-neighbourhood", bad_hood),
                                    ("weird-shape", weird),
                                    ("context-break", ctx_break),
                                ) if f
                            )
                        ),
                    },
                )

        # Cap signals so UI does not flood
        r["signals"] = signals[:8]

    # prune old seen keys occasionally
    with _sig_lock:
        if len(_seen_conn_keys) > 20000:
            cutoff = now - 3600
            _seen_conn_keys = {k: v for k, v in _seen_conn_keys.items() if v >= cutoff}
        live_pids = {r.get("pid") for r in rows if r.get("pid")}
        _seen_pids = {k: v for k, v in _seen_pids.items() if k in live_pids}

    # Review 3 Step 2: deterministic 0–100 risk (see risk.py / NOTES.md)
    if tw_risk is not None:
        try:
            rows = tw_risk.attach_risk(rows)
        except Exception:
            for r in rows:
                r.setdefault("risk", 0)
                r.setdefault("risk_process", 0)
    else:
        for r in rows:
            r.setdefault("risk", 0)
            r.setdefault("risk_process", 0)

    return rows


def enrich_process_detail(detail: dict[str, Any]) -> dict[str, Any]:
    """Add Authenticode + path signals to /api/process/<pid> payload."""
    exe = detail.get("exe")
    if exe:
        auth = get_authenticode(exe, enqueue=True)
    else:
        auth = {
            "signed": None,
            "status": "unknown",
            "publisher": None,
            "issuer": None,
            "expired": None,
            "path": None,
        }
    # If checking, try a short sync wait once for inspect UX (max ~1.2s)
    def _auth_busy(a):
        return (a.get("status") or "").lower() in ("pending", "checking")
    if auth and _auth_busy(auth) and exe:
        deadline = time.time() + 1.2
        while time.time() < deadline:
            time.sleep(0.15)
            auth2 = get_authenticode(exe, enqueue=False)
            if auth2 and not _auth_busy(auth2):
                auth = auth2
                break
    detail["authenticode"] = auth
    detail["publisher_hint"] = publisher_hint(auth)
    if tw_exe_hash and exe:
        try:
            hi = tw_exe_hash.get_hash(exe)
            if hi:
                detail["exe_sha256"] = hi.get("sha256")
                detail["exe_sha256_short"] = hi.get("short")
        except Exception:
            pass
    sigs: list[dict[str, Any]] = []
    if _suspicious_path(exe):
        sigs.append(
            {
                "id": "suspicious_path",
                "label": "odd path",
                "severity": "medium" if (auth and auth.get("signed") is False) else "low",
                "detail": exe,
            }
        )
    if auth and (auth.get("status") or "").lower() == "notsigned":
        sigs.append({"id": "unsigned", "label": "unsigned", "severity": "low", "detail": "Not Authenticode-signed"})
    # ux44: suppress when Authenticode Valid (timestamped cert may be expired)
    if auth and auth.get("expired") and (auth.get("status") or "").lower() != "valid":
        sigs.append({"id": "sig_expired", "label": "sig expired", "severity": "medium", "detail": "Signer cert expired"})
    parent = None
    try:
        if detail.get("ppid"):
            parent = psutil.Process(int(detail["ppid"])).name()
    except Exception:
        pass
    if parent:
        detail["parent_process"] = parent
    detail["signals"] = sigs
    # Baseline process risk from path/auth signals (snapshot may overwrite with max)
    if tw_risk is not None:
        try:
            detail["risk"] = tw_risk.score_from_signals(
                sigs, authenticode=auth
            )
        except Exception:
            detail["risk"] = 0
    else:
        detail["risk"] = 0
    return detail
