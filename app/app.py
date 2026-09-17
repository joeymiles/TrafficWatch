"""TrafficWatch - local-only live traffic map for Windows.

Binds 127.0.0.1 only. No telemetry.
"""
from __future__ import annotations

import argparse
import os
import functools
import hmac
import secrets
import subprocess
import sys
import webbrowser
import csv
import io
import threading
import time
from typing import Any, Callable

import preflight as _tw_preflight
_tw_preflight.ensure_imports(mode="server")

from flask import Flask, Response, jsonify, redirect, render_template, request
from flask_socketio import SocketIO, join_room

import connections
import dns_lookup
import dns_log
import helper_ipc
import dns_detect
import firewall
import geoip_lookup
import baseline
import history
import intel
import signals
import doh_detect
import net_context
import config_drift
import allow_memory
import exe_hash

HOST = "127.0.0.1"
PORT = 8767
POLL_SECONDS = 1.5

# Desktop-show token (start.ps1 POST /api/desktop/show). NEVER injected into HTML/JSON.
DESKTOP_SHOW_TOKEN = secrets.token_urlsafe(32)
TW_CSRF = DESKTOP_SHOW_TOKEN  # alias for show-token file only; never in HTTP bodies
TW_TOKEN_HEADER = "X-TW-Token"
TW_TOKEN_QUERY = "tw_token"
TW_SESSION_COOKIE = "TW_SESSION"

_DATA_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data"))
_DESKTOP_SHOW_TOKEN_PATH = os.path.join(_DATA_DIR, "desktop_show_token.txt")

# Server-side sessions and single-use tickets (in-memory, per process).
_sessions: dict[str, float] = {}
_boot_tickets: dict[str, float] = {}
_pair_codes: dict[str, float] = {}
_authed_sids: set[str] = set()
_sess_lock = threading.RLock()
_BOOT_TTL_SEC = 120.0
_PAIR_TTL_SEC = 300.0
_SESSION_TTL_SEC = 12 * 3600.0


def _purge_expired_locked(now: float) -> None:
    for store, ttl in (
        (_sessions, _SESSION_TTL_SEC),
        (_boot_tickets, _BOOT_TTL_SEC),
        (_pair_codes, _PAIR_TTL_SEC),
    ):
        dead = [k for k, exp in store.items() if exp <= now]
        for k in dead:
            store.pop(k, None)


def create_session() -> str:
    sid = secrets.token_urlsafe(32)
    with _sess_lock:
        _purge_expired_locked(time.time())
        _sessions[sid] = time.time() + _SESSION_TTL_SEC
    return sid


def create_boot_ticket() -> str:
    ticket = secrets.token_urlsafe(32)
    with _sess_lock:
        _purge_expired_locked(time.time())
        _boot_tickets[ticket] = time.time() + _BOOT_TTL_SEC
    return ticket


def create_pair_code() -> str:
    code = secrets.token_urlsafe(12)
    with _sess_lock:
        _purge_expired_locked(time.time())
        _pair_codes[code] = time.time() + _PAIR_TTL_SEC
    return code


def consume_boot_ticket(ticket: str | None) -> bool:
    if not ticket:
        return False
    now = time.time()
    with _sess_lock:
        exp = _boot_tickets.pop(ticket, None)
    return bool(exp and exp > now)


def consume_pair_code(code: str | None) -> bool:
    if not code:
        return False
    now = time.time()
    with _sess_lock:
        exp = _pair_codes.pop(code, None)
    return bool(exp and exp > now)


def _session_valid(session_id: str | None) -> bool:
    if not session_id:
        return False
    now = time.time()
    with _sess_lock:
        exp = _sessions.get(session_id)
        if not exp or exp <= now:
            _sessions.pop(session_id, None)
            return False
        _sessions[session_id] = now + _SESSION_TTL_SEC
        return True


def _set_session_cookie(resp: Response, session_id: str) -> None:
    resp.set_cookie(
        TW_SESSION_COOKIE,
        session_id,
        httponly=True,
        samesite="Strict",
        path="/",
        max_age=int(_SESSION_TTL_SEC),
        secure=False,
    )


def _restrict_acl(path: str, *, directory: bool = False) -> None:
    """Owner + SYSTEM + Administrators only (best-effort)."""
    if os.name != "nt" or not path:
        return
    try:
        user = os.environ.get("USERNAME") or os.getlogin()
        grant = "(OI)(CI)F" if directory else "F"
        subprocess_mod = __import__("subprocess")
        subprocess_mod.run(
            [
                "icacls",
                path,
                "/inheritance:r",
                "/grant:r",
                f"{user}:{grant}",
                "/grant:r",
                f"SYSTEM:{grant}",
                "/grant:r",
                f"*S-1-5-32-544:{grant}",
            ],
            capture_output=True,
            timeout=8,
            creationflags=getattr(subprocess_mod, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        pass


def write_desktop_show_token() -> str:
    """Persist per-launch show token for start.ps1 (ASCII file, owner ACL)."""
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        _restrict_acl(_DATA_DIR, directory=True)
        with open(_DESKTOP_SHOW_TOKEN_PATH, "w", encoding="ascii", newline="\n") as f:
            f.write(DESKTOP_SHOW_TOKEN)
        _restrict_acl(_DESKTOP_SHOW_TOKEN_PATH, directory=False)
        return DESKTOP_SHOW_TOKEN
    except OSError:
        return DESKTOP_SHOW_TOKEN


def _desktop_show_token_ok(token: str | None) -> bool:
    if not token:
        return False
    if hmac.compare_digest(token, DESKTOP_SHOW_TOKEN):
        return True
    try:
        with open(_DESKTOP_SHOW_TOKEN_PATH, "r", encoding="ascii") as f:
            disk = (f.read() or "").strip()
        if disk and hmac.compare_digest(token, disk):
            return True
    except OSError:
        pass
    return False


ALLOWED_ORIGINS = [
    f"http://127.0.0.1:{PORT}",
    f"http://localhost:{PORT}",
]

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_urlsafe(32)
socketio = SocketIO(
    app,
    cors_allowed_origins=ALLOWED_ORIGINS,
    async_mode="threading",
)

_state_lock = threading.RLock()
_runtime: dict[str, Any] = {
    "home": None,
    "geo_meta": None,
    "admin_limited": False,
    "last_snapshot": None,
    "_snapshot_warming": False,
    "running": True,
    "home_override": None,
    "desktop": False,
}

# Distinguishes this process from a peer that already bound :PORT.
INSTANCE_ID = secrets.token_urlsafe(8)
_runtime["instance_id"] = INSTANCE_ID
_runtime["pid"] = os.getpid()


def _host_allowed(host_header: str | None) -> bool:
    """Allow only loopback Host values (optional :port)."""
    if not host_header:
        return False
    raw = host_header.strip().lower()
    # Strip port; bracket IPv6 [::1]:8767
    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            return False
        host = raw[1:end]
        rest = raw[end + 1 :]
        if rest and not rest.startswith(":"):
            return False
    elif ":" in raw:
        # hostname:port (IPv4 / name) - take last split only for single colon
        host, _, port = raw.rpartition(":")
        if not host or not port.isdigit():
            return False
    else:
        host = raw
    return host in ("127.0.0.1", "localhost", "::1")


def _token_from_request() -> str | None:
    """X-TW-Token header only (desktop/show). Not a session cookie."""
    h = request.headers.get(TW_TOKEN_HEADER) or request.headers.get("X-Tw-Token")
    if h:
        return h.strip()
    return None


def _session_from_request() -> str | None:
    c = request.cookies.get(TW_SESSION_COOKIE)
    if c:
        return c.strip()
    return None


def _session_ok() -> bool:
    return _session_valid(_session_from_request())


def _token_ok(token: str | None) -> bool:
    """Session cookie is the only general auth. X-TW-Token is desktop/show only."""
    return _session_valid(token) if token else _session_ok()


def require_host_only(fn: Callable):
    """Decorator: reject non-loopback Host (no session). Boot/pair/desktop-show."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not _host_allowed(request.headers.get("Host")):
            return jsonify({"ok": False, "error": "forbidden host"}), 403
        return fn(*args, **kwargs)

    return wrapper


def require_localhost(fn: Callable):
    """Decorator: loopback Host + session cookie on every route."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not _host_allowed(request.headers.get("Host")):
            return jsonify({"ok": False, "error": "forbidden host"}), 403
        if not _session_ok():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return fn(*args, **kwargs)

    return wrapper


def require_mutate_auth(fn: Callable):
    """Same as require_localhost (cookie session on mutate routes)."""
    return require_localhost(fn)


def _socket_host_ok() -> bool:
    try:
        return _host_allowed(request.headers.get("Host"))
    except Exception:
        return False


def _socket_session_ok() -> bool:
    return _session_ok()


def _socket_token_ok(data: Any) -> bool:
    """Socket events: session cookie (handshake already rejected if missing)."""
    if _socket_session_ok():
        return True
    sid = getattr(request, "sid", None)
    return bool(sid and sid in _authed_sids)


def is_loopback_bind(host: str) -> bool:
    h = (host or "").strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h in ("127.0.0.1", "localhost", "::1")


def enrich_lite(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Geo from existing cache only (no MMDB miss fill / download / IPinfo)."""
    out = []
    for r in rows:
        geo = None
        rip = r.get("remote_ip")
        if rip:
            try:
                geo = geoip_lookup.lookup_cached(rip)
            except Exception:
                geo = None
        item = dict(r)
        item["geo"] = geo
        if geo and geo.get("resolvable"):
            item["country"] = geo.get("country")
            item["country_code"] = geo.get("country_code")
            item["city"] = geo.get("city")
            item["lat"] = geo.get("lat")
            item["lon"] = geo.get("lon")
        else:
            item["country"] = (geo or {}).get("country") or (
                "Private" if r.get("private_remote") else "-"
            )
            item["country_code"] = (geo or {}).get("country_code")
            item["city"] = (geo or {}).get("city")
            item["lat"] = None
            item["lon"] = None
        item["asn"] = (geo or {}).get("asn")
        item["org"] = (geo or {}).get("org")
        item["hosting"] = (geo or {}).get("hosting")
        out.append(item)
    return out


def enrich(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for r in rows:
        geo = None
        rip = r.get("remote_ip")
        if rip:
            geo = geoip_lookup.lookup(rip)
        item = dict(r)
        item["geo"] = geo
        if geo and geo.get("resolvable"):
            item["country"] = geo.get("country")
            item["country_code"] = geo.get("country_code")
            item["city"] = geo.get("city")
            item["lat"] = geo.get("lat")
            item["lon"] = geo.get("lon")
        else:
            item["country"] = (geo or {}).get("country") or (
                "Private" if r.get("private_remote") else "-"
            )
            item["country_code"] = (geo or {}).get("country_code")
            item["city"] = (geo or {}).get("city")
            item["lat"] = None
            item["lon"] = None
        # Tier 0 ASN fields (empty when no IPinfo)
        item["asn"] = (geo or {}).get("asn")
        item["org"] = (geo or {}).get("org")
        item["hosting"] = (geo or {}).get("hosting")
        out.append(item)
    return out


def effective_home() -> dict[str, Any]:
    with _state_lock:
        ov = _runtime.get("home_override")
        if ov and ov.get("lat") is not None and ov.get("lon") is not None:
            return ov
        return _runtime.get("home") or geoip_lookup.ASSUMED_HOME


def build_lite_snapshot() -> dict[str, Any]:
    """Fast first paint: connections + names + direction + IPs/ports + cached geo.

    No Authenticode, intel fetch, reverse DNS, hashing, config drift, or helper.
    Emits via the regular "snapshot" event (snapshot.lite=true).
    """
    t0 = time.perf_counter()
    rows, admin_limited = connections.collect_connections(include_udp=True)
    try:
        rows = connections.attach_rates(rows)
    except Exception:
        pass
    try:
        rows = connections.attach_helper_tcp(rows)
    except Exception:
        pass
    rows = enrich_lite(rows)
    home = effective_home()
    try:
        sys_rates = connections.system_rates()
    except Exception:
        sys_rates = {}
    try:
        talkers = connections.top_talkers(rows, n=5)
    except Exception:
        talkers = []
    try:
        rst = connections.rates_status(rows)
    except Exception:
        rst = {"per_conn_available": False, "helper_tcp": False, "helper_needed": True}
    snap = {
        "ts": time.time(),
        "lite": True,
        "phase": "lite",
        "admin_limited": admin_limited,
        "count": len(rows),
        "connections": rows,
        "home": home,
        "net_context": {},
        "intel_hits": 0,
        "vt_enabled": bool(getattr(intel, "vt_enabled", False)),
        "dns_log": {"ok": False, "limited": True, "message": "DNS log: warming up"},
        "rates": {
            "system_in": sys_rates.get("bytes_in_rate"),
            "system_out": sys_rates.get("bytes_out_rate"),
            "source": "lite",
            "per_conn_available": bool(rst.get("per_conn_available")),
            "helper_tcp": bool(rst.get("helper_tcp")),
            "helper_needed": bool(rst.get("helper_needed")),
        },
        "top_talkers": talkers,
    }
    with _state_lock:
        _runtime["admin_limited"] = admin_limited
        # Only seed last_snapshot if none yet (do not clobber a richer snap)
        if not _runtime.get("last_snapshot"):
            _runtime["last_snapshot"] = snap
        _runtime["_lite_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return snap


def build_snapshot() -> dict[str, Any]:
    # Cadence profile (rough): collect+name-cache ~dominant previously when
    # _safe_proc_name/_exe_for_pid/_parent_name re-created psutil.Process per row.
    # With per-PID caches in connections/signals, target interval ~1.5-2s.
    t0 = time.perf_counter()
    rows, admin_limited = connections.collect_connections(include_udp=True)
    t_collect = time.perf_counter()
    rows = connections.attach_rates(rows)
    try:
        rows = connections.attach_helper_tcp(rows)
    except Exception:
        pass
    rows = enrich(rows)
    rows = dns_lookup.attach_hostnames(rows)
    # Attach DNS-Client queries BEFORE intel so domain lists can match dns_queries
    try:
        rows = dns_log.attach_dns_queries(rows)
    except Exception:
        pass
    # Phase B: local intel match (hostname + dns_queries + IP) + heuristics
    rows = intel.attach_intel(rows)
    rows = signals.attach_signals(rows)
    # Review 3 Step 4: DNS rare/burst (best-effort; no-op if DNS log limited)
    try:
        rows = dns_detect.attach_dns_signals(rows)
        # Re-score after DNS signals
        import risk as tw_risk
        rows = tw_risk.attach_risk(rows)
    except Exception:
        pass
    # Review 3 Step 3: per-program baseline after intel/signals/risk
    try:
        rows = baseline.attach_baseline(rows)
    except Exception:
        pass
    # Tier 0: DoH/DoT, network context, config drift, allow-memory prune
    try:
        rows = doh_detect.attach_doh_signals(rows)
    except Exception:
        pass
    net_ctx = {}
    try:
        rows, net_ctx = net_context.attach_context(rows)
    except Exception:
        net_ctx = {}
    try:
        rows = config_drift.attach_drift(rows)
    except Exception:
        pass
    try:
        import risk as tw_risk2
        rows = tw_risk2.attach_risk(rows)
    except Exception:
        pass
    try:
        allow_memory.prune()
    except Exception:
        pass
    # Record intel / baseline events for weekly summary (session-deduped)
    try:
        seen_ev = _runtime.setdefault("_week_ev_keys", set())
        for r in rows:
            intel_b = r.get("intel") or {}
            if intel_b.get("hit"):
                ek = "intel|" + str(r.get("remote_ip") or "")
                if ek not in seen_ev:
                    seen_ev.add(ek)
                    history.record_event(
                        "intel_hit",
                        {
                            "ip": r.get("remote_ip"),
                            "lists": (intel_b.get("lists") or [])[:4],
                            "pid": r.get("pid"),
                        },
                    )
            for s in r.get("signals") or []:
                sid = s.get("id")
                if sid in ("baseline_depart", "exfil_ish"):
                    ek = f"{sid}|{r.get('pid')}|{(s.get('detail') or '')[:40]}"
                    if ek in seen_ev:
                        continue
                    seen_ev.add(ek)
                    history.record_event(sid, {"pid": r.get("pid"), "detail": (s.get("detail") or "")[:160]})
        if len(seen_ev) > 5000:
            _runtime["_week_ev_keys"] = set(list(seen_ev)[-2000:])
    except Exception:
        pass
    # Tiny non-blocking history + baseline batch (WAL); ignore failures
    try:
        history.flush()
    except Exception:
        pass
    try:
        baseline.flush()
    except Exception:
        pass
    sys_rates = connections.system_rates()
    talkers = connections.top_talkers(rows, n=5)
    try:
        rst = connections.rates_status(rows)
    except Exception:
        rst = {"per_conn_available": False, "helper_tcp": False, "helper_needed": True}
    home = effective_home()
    intel_hits = sum(1 for r in rows if (r.get("intel") or {}).get("hit"))
    try:
        dns_meta = dns_log.snapshot_meta()
    except Exception:
        dns_meta = {"ok": False, "limited": True, "message": "DNS log: unavailable"}
    snap = {
        "ts": time.time(),
        "admin_limited": admin_limited,
        "count": len(rows),
        "connections": rows,
        "home": home,
        "net_context": net_ctx,
        "intel_hits": intel_hits,
        "vt_enabled": bool(getattr(intel, "vt_enabled", False)),
        "dns_log": dns_meta,
        "rates": {
            "system_in": sys_rates.get("bytes_in_rate"),
            "system_out": sys_rates.get("bytes_out_rate"),
            "source": (
                "system: psutil.net_io_counters (NIC totals); "
                "per-row: helper_tcp when live helper on; else process/NIC EMA, not disk"
            ),
            "per_conn_available": bool(rst.get("per_conn_available")),
            "helper_tcp": bool(rst.get("helper_tcp")),
            "helper_needed": bool(rst.get("helper_needed")),
        },
        "top_talkers": talkers,
    }
    with _state_lock:
        _runtime["admin_limited"] = admin_limited
        _runtime["last_snapshot"] = snap
        n = int(_runtime.get("_snap_prof_n", 0)) + 1
        _runtime["_snap_prof_n"] = n
        if n <= 3 or n % 40 == 0:
            # One-line rough profile (collect vs rest); avoids per-poll spam
            _runtime["_snap_prof_last"] = {
                "collect_ms": round((t_collect - t0) * 1000, 1),
                "total_ms": round((time.perf_counter() - t0) * 1000, 1),
                "rows": len(rows),
            }
    return snap


def poll_loop() -> None:
    save_counter = 0
    while _runtime.get("running", True):
        try:
            snap = build_snapshot()
            socketio.emit("snapshot", snap, to="authed")
            save_counter += 1
            if save_counter % 20 == 0:
                geoip_lookup.save_disk_cache()
        except Exception as e:
            socketio.emit("error", {"message": str(e)}, to="authed")
        socketio.sleep(POLL_SECONDS)


@app.route("/")
def index():
    if not _host_allowed(request.headers.get("Host")):
        return jsonify({"ok": False, "error": "forbidden host"}), 403
    boot = (request.args.get("boot") or "").strip()
    if boot:
        if consume_boot_ticket(boot):
            resp = redirect("/")
            _set_session_cookie(resp, create_session())
            return resp
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    if not _session_ok():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return render_template("index.html", port=PORT)


@app.route("/pair")
@require_host_only
def pair_get():
    code = (request.args.get("code") or "").strip()
    if consume_pair_code(code):
        resp = redirect("/")
        _set_session_cookie(resp, create_session())
        return resp
    return jsonify({"ok": False, "error": "unauthorized"}), 401


@app.route("/api/pair", methods=["POST"])
@require_host_only
def api_pair():
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or request.args.get("code") or "").strip()
    if consume_pair_code(code):
        resp = jsonify({"ok": True})
        _set_session_cookie(resp, create_session())
        return resp
    return jsonify({"ok": False, "error": "unauthorized"}), 401


@app.route("/api/session")
@require_localhost
def api_session():
    """Authenticated session probe. Never returns a token."""
    return jsonify({"ok": True, "auth": "cookie"})


@app.route("/api/boot-ready.js")
@require_host_only
def boot_ready_js():
    """Splash (html= origin) polls this as a script src. No CORS. Navigates WebView2."""
    if not _runtime.get("desktop"):
        return Response("/* not desktop */", status=403, mimetype="application/javascript")
    ticket = create_boot_ticket()
    url = "http://127.0.0.1:%s/?boot=%s" % (PORT, ticket)
    body = "window.location.replace(%r);\n" % url
    resp = Response(body, mimetype="application/javascript")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/boot-ping")
@require_host_only
def boot_ping():
    """Localhost, no cookie. Used by desktop wait_ready / single-instance.

    Must not leak geo/home/intel. wait_ready treats a different pid as a peer
    (never as self-ready).
    """
    return jsonify(
        {
            "ok": True,
            "pid": os.getpid(),
            "instance_id": _runtime.get("instance_id") or INSTANCE_ID,
            "desktop": bool(_runtime.get("desktop")),
        }
    )


@app.route("/api/health")
@require_localhost
def health():
    with _state_lock:
        return jsonify(
            {
                "ok": True,
                "port": PORT,
                "admin_limited": _runtime.get("admin_limited"),
                "geo": _runtime.get("geo_meta"),
                "home": effective_home(),
                "desktop": bool(_runtime.get("desktop")),
                "vt_enabled": bool(getattr(intel, "vt_enabled", False)),
                "dns_log": dns_log.status(),
            }
        )


@app.route("/api/quit", methods=["POST"])
@require_mutate_auth
def api_quit():
    """Desktop-only: close process after a short delay (frees :8767)."""
    if not _runtime.get("desktop"):
        return jsonify({"ok": False, "error": "quit only available in desktop mode"}), 403

    def _die():
        time.sleep(0.35)
        _runtime["running"] = False
        try:
            socketio.stop()
        except Exception:
            pass
        import os as _os

        _os._exit(0)

    threading.Thread(target=_die, name="tw-quit", daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/uninstall", methods=["POST"])
@require_mutate_auth
def api_uninstall():
    """Windows desktop only: launch app/uninstall.ps1 (it asks, elevates, warns before deleting data, and stops the app)."""
    if not _runtime.get("desktop"):
        return jsonify({"ok": False, "error": "uninstall only available in desktop mode"}), 403
    if not sys.platform.startswith("win"):
        return jsonify({"ok": False, "error": "uninstall script is Windows-only"}), 400
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uninstall.ps1")
    if not os.path.isfile(script):
        return jsonify({"ok": False, "error": "uninstall.ps1 missing"}), 500
    ps = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    try:
        subprocess.Popen(
            [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", script],
            env=firewall.clean_ps51_env(),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "DETACHED_PROCESS", 0),
            close_fds=True,
        )
    except OSError as exc:
        print(f"  Uninstall launch failed: {exc}", flush=True)
        return jsonify({"ok": False, "error": "could not start uninstaller"}), 500
    # The uninstaller stops this app itself, only after the user confirms in its window.
    print("  Uninstall launched", flush=True)
    return jsonify({"ok": True})


@app.route("/api/desktop/show", methods=["POST"])
@require_host_only
def api_desktop_show():
    """Bring desktop window to front (single-instance relaunch).

    POST only (blocks img-tag GET). Requires X-TW-Token matching CSRF or
    data/desktop_show_token.txt (written for start.ps1).
    """
    if not _desktop_show_token_ok(_token_from_request()):
        return jsonify({"ok": False, "error": "invalid or missing token"}), 401
    if not _runtime.get("desktop"):
        return jsonify({"ok": False, "error": "not desktop mode"}), 403
    fn = _runtime.get("desktop_show_fn")
    shown = False
    if callable(fn):
        try:
            shown = bool(fn())
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc), "shown": False}), 500
    return jsonify({"ok": True, "shown": shown})



def _warming_snapshot() -> dict[str, Any]:
    """Empty 200 response while first lite/full seed is in flight."""
    return {
        "ok": True,
        "phase": "warming",
        "lite": True,
        "ts": time.time(),
        "count": 0,
        "connections": [],
        "home": effective_home(),
        "admin_limited": bool(_runtime.get("admin_limited")),
        "net_context": {},
        "intel_hits": 0,
        "vt_enabled": bool(getattr(intel, "vt_enabled", False)),
        "dns_log": {"ok": False, "limited": True, "message": "DNS log: warming up"},
        "rates": {"system_in": None, "system_out": None, "source": "warming"},
        "top_talkers": [],
    }


def _snapshot_for_request() -> dict[str, Any]:
    """Serve last_snapshot, else cheap lite, else warming. NEVER full build_snapshot().

    Concurrent first hits: only one thread runs build_lite_snapshot(); others get warming [].
    """
    with _state_lock:
        snap = _runtime.get("last_snapshot")
        if snap:
            return snap
        if _runtime.get("_snapshot_warming"):
            return _warming_snapshot()
        _runtime["_snapshot_warming"] = True
    try:
        with _state_lock:
            snap = _runtime.get("last_snapshot")
            if snap:
                return snap
        return build_lite_snapshot()
    except Exception:
        return _warming_snapshot()
    finally:
        with _state_lock:
            _runtime["_snapshot_warming"] = False


@app.route("/api/snapshot")
@require_localhost
def api_snapshot():
    # ux39: never run full build_snapshot() on the request path (was ~10s).
    snap = _snapshot_for_request()
    return jsonify(snap)


@app.route("/api/home", methods=["GET", "POST"])
def api_home():
    """Get or override home lat/lon (server-side; UI also persists in localStorage)."""
    if request.method == "GET":
        if not _host_allowed(request.headers.get("Host")):
            return jsonify({"ok": False, "error": "forbidden host"}), 403
        if not _session_ok():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return jsonify(effective_home())
    # POST mutate
    if not _host_allowed(request.headers.get("Host")):
        return jsonify({"ok": False, "error": "forbidden host"}), 403
    if not _session_ok():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    try:
        lat = float(data["lat"])
        lon = float(data["lon"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"ok": False, "error": "lat/lon required"}), 400
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return jsonify({"ok": False, "error": "lat/lon out of range"}), 400
    label = data.get("label") or f"Custom home ({lat:.4f}, {lon:.4f})"
    home = {
        "ip": data.get("ip"),
        "lat": lat,
        "lon": lon,
        "city": data.get("city") or "",
        "region": data.get("region") or "",
        "country": data.get("country") or "",
        "country_code": data.get("country_code"),
        "org": None,
        "asn": None,
        "source": "user_override",
        "label": label,
    }
    with _state_lock:
        _runtime["home_override"] = home
    socketio.emit("home", home, to="authed")
    return jsonify({"ok": True, "home": home})


@app.route("/api/home/detect", methods=["POST"])
@require_mutate_auth
def api_home_detect():
    """Opt-in public IP lookup. Default is off; never log city/coords."""
    home = geoip_lookup.detect_public_home()
    if home.get("source") == "ipapi.co":
        with _state_lock:
            _runtime["home"] = home
            _runtime["home_override"] = None
        socketio.emit("home", home, to="authed")
        return jsonify({"ok": True, "home": home})
    return jsonify({"ok": False, "error": "lookup unavailable", "home": home}), 502


@app.route("/api/home/reset", methods=["POST"])
@require_mutate_auth
def api_home_reset():
    with _state_lock:
        _runtime["home_override"] = None
        home = _runtime.get("home") or geoip_lookup.ASSUMED_HOME
    socketio.emit("home", home, to="authed")
    return jsonify({"ok": True, "home": home})


@app.route("/api/export.csv")
@require_mutate_auth
def api_export_csv():
    with _state_lock:
        snap = _runtime.get("last_snapshot")
    if not snap:
        snap = {"connections": []}
    buf = io.StringIO()
    fields = [
        "direction",
        "direction_basis",
        "process",
        "pid",
        "proto",
        "status",
        "local_ip",
        "local_port",
        "remote_ip",
        "remote_port",
        "hostname",
        "dns_queries",
        "country",
        "city",
        "lat",
        "lon",
        "bytes_in_rate",
        "bytes_out_rate",
        "bytes_in_rate_share",
        "bytes_out_rate_share",
        "conn_bytes_in",
        "conn_bytes_out",
        "duration_ms",
        "rate_source",
        "intel_hit",
        "intel_lists",
        "intel_severity",
        "signals",
        "publisher_hint",
    ]

    def _csv_cell(val: Any) -> Any:
        """Neutralize CSV formula injection on text cells; stringify lists."""
        if val is None:
            return ""
        if isinstance(val, (list, tuple)):
            val = ";".join(str(x) for x in val)
        if isinstance(val, bool):
            return val
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            return val
        s = str(val)
        if s and s[0] in ("=", "+", "-", "@"):
            return "'" + s
        return s

    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for c in snap.get("connections") or []:
        intel_b = c.get("intel") or {}
        sigs = c.get("signals") or []
        row = {
            "direction": c.get("direction"),
            "direction_basis": c.get("direction_basis"),
            "process": c.get("process"),
            "pid": c.get("pid"),
            "proto": c.get("proto"),
            "status": c.get("status"),
            "local_ip": c.get("local_ip"),
            "local_port": c.get("local_port"),
            "remote_ip": c.get("remote_ip"),
            "remote_port": c.get("remote_port"),
            "hostname": c.get("hostname"),
            "dns_queries": c.get("dns_queries") or [],
            "country": c.get("country"),
            "city": c.get("city"),
            "lat": c.get("lat"),
            "lon": c.get("lon"),
            "bytes_in_rate": c.get("bytes_in_rate"),
            "bytes_out_rate": c.get("bytes_out_rate"),
            "bytes_in_rate_share": c.get("bytes_in_rate_share"),
            "bytes_out_rate_share": c.get("bytes_out_rate_share"),
            "conn_bytes_in": c.get("conn_bytes_in"),
            "conn_bytes_out": c.get("conn_bytes_out"),
            "duration_ms": c.get("duration_ms"),
            "rate_source": c.get("rate_source"),
            "intel_hit": bool(intel_b.get("hit")),
            "intel_lists": intel_b.get("lists") or [],
            "intel_severity": intel_b.get("severity"),
            "signals": [s.get("id") or s.get("label") for s in sigs if isinstance(s, dict)],
            "publisher_hint": c.get("publisher_hint"),
        }
        w.writerow({k: _csv_cell(row.get(k)) for k in fields})
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=trafficwatch-snapshot.csv"},
    )


@app.route("/api/export/save", methods=["POST"])
@require_mutate_auth
def api_export_save():
    """Write snapshot CSV under data/exports (pywebview cannot download attachments)."""
    with _state_lock:
        snap = _runtime.get("last_snapshot")
    if not snap:
        snap = {"connections": []}
    # Reuse the GET builder by calling the same route logic via a second buffer
    buf = io.StringIO()
    fields = [
        "direction",
        "direction_basis",
        "process",
        "pid",
        "proto",
        "status",
        "local_ip",
        "local_port",
        "remote_ip",
        "remote_port",
        "hostname",
        "dns_queries",
        "country",
        "city",
        "lat",
        "lon",
        "bytes_in_rate",
        "bytes_out_rate",
        "bytes_in_rate_share",
        "bytes_out_rate_share",
        "intel_hit",
        "intel_lists",
        "intel_severity",
        "signals",
        "publisher_hint",
    ]

    def _csv_cell(val: Any) -> Any:
        if val is None:
            return ""
        if isinstance(val, (list, tuple)):
            val = ";".join(str(x) for x in val)
        if isinstance(val, bool):
            return val
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            return val
        s = str(val)
        if s and s[0] in ("=", "+", "-", "@"):
            return "'" + s
        return s

    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for c in snap.get("connections") or []:
        intel_b = c.get("intel") or {}
        sigs = c.get("signals") or []
        row = {
            "direction": c.get("direction"),
            "direction_basis": c.get("direction_basis"),
            "process": c.get("process"),
            "pid": c.get("pid"),
            "proto": c.get("proto"),
            "status": c.get("status"),
            "local_ip": c.get("local_ip"),
            "local_port": c.get("local_port"),
            "remote_ip": c.get("remote_ip"),
            "remote_port": c.get("remote_port"),
            "hostname": c.get("hostname"),
            "dns_queries": c.get("dns_queries") or [],
            "country": c.get("country"),
            "city": c.get("city"),
            "lat": c.get("lat"),
            "lon": c.get("lon"),
            "bytes_in_rate": c.get("bytes_in_rate"),
            "bytes_out_rate": c.get("bytes_out_rate"),
            "bytes_in_rate_share": c.get("bytes_in_rate_share"),
            "bytes_out_rate_share": c.get("bytes_out_rate_share"),
            "conn_bytes_in": c.get("conn_bytes_in"),
            "conn_bytes_out": c.get("conn_bytes_out"),
            "duration_ms": c.get("duration_ms"),
            "rate_source": c.get("rate_source"),
            "intel_hit": bool(intel_b.get("hit")),
            "intel_lists": intel_b.get("lists") or [],
            "intel_severity": intel_b.get("severity"),
            "signals": [s.get("id") or s.get("label") for s in sigs if isinstance(s, dict)],
            "publisher_hint": c.get("publisher_hint"),
        }
        w.writerow({k: _csv_cell(row.get(k)) for k in fields})
    out_dir = os.path.join(_DATA_DIR, "exports")
    os.makedirs(out_dir, exist_ok=True)
    name = time.strftime("trafficwatch-snapshot-%Y%m%d-%H%M%S.csv")
    path = os.path.join(out_dir, name)
    text = buf.getvalue()
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    return jsonify({
        "ok": True,
        "path": path,
        "filename": name,
        "bytes": len(text.encode("utf-8")),
    })


@app.route("/api/process/<int:pid>")
@require_localhost
def api_process_detail(pid: int):
    with _state_lock:
        snap = _runtime.get("last_snapshot")
    rows = (snap or {}).get("connections") or []
    detail = connections.process_detail(pid, rows)
    detail = signals.enrich_process_detail(detail)
    # Prefer aggregate process risk from live snapshot rows (Review 3 Step 2)
    pid_risks = [
        int(c.get("risk") or 0)
        for c in rows
        if c.get("pid") == pid
    ]
    if pid_risks:
        detail["risk"] = max(pid_risks)
        detail["risk_process"] = max(
            int(c.get("risk_process") or 0) for c in rows if c.get("pid") == pid
        )
    else:
        detail.setdefault("risk", 0)
        detail["risk_process"] = int(detail.get("risk") or 0)
    return jsonify(detail)


@app.route("/api/process/<int:pid>/cmdline/reveal", methods=["POST"])
@require_mutate_auth
def api_process_cmdline_reveal(pid: int):
    """Authenticated reveal of current cmdline. Not persisted."""
    return jsonify(connections.process_cmdline_raw(pid))


@app.route("/api/process/<int:pid>/kill", methods=["POST"])
@require_mutate_auth
def api_process_kill(pid: int):
    data = request.get_json(silent=True) or {}
    force = bool(data.get("force"))
    confirm_pid = data.get("confirm_pid")
    confirm_name = data.get("confirm_name")
    try:
        confirm_pid_i = int(confirm_pid)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "confirm_pid required"}), 400
    if confirm_pid_i != pid:
        return jsonify({"ok": False, "error": "confirm_pid does not match URL pid"}), 400
    if not confirm_name:
        return jsonify({"ok": False, "error": "confirm_name required"}), 400
    result = connections.kill_process(pid, force=force, confirm_name=str(confirm_name))
    status = 200 if result.get("ok") else (403 if result.get("blocked") or result.get("access_denied") else 400)
    return jsonify(result), status




def intel_hits_from_snapshot(snap: dict[str, Any] | None, *, cap: int = 200) -> list[dict[str, Any]]:
    """Current-snapshot intel matches only (never dump list IOCs). Cap for UI."""
    hits: list[dict[str, Any]] = []
    if not snap:
        return hits
    for c in snap.get("connections") or []:
        intel_b = c.get("intel") or {}
        if not intel_b.get("hit"):
            continue
        hits.append(
            {
                "remote_ip": c.get("remote_ip"),
                "remote_port": c.get("remote_port"),
                "process": c.get("process"),
                "pid": c.get("pid"),
                "lists": list(intel_b.get("lists") or [])[:8],
                "severity": intel_b.get("severity"),
                "hostname": c.get("hostname"),
            }
        )
        if len(hits) >= cap:
            break
    return hits


def intel_status_payload() -> dict[str, Any]:
    """Summary + current hits for Threat intel modal (ux29)."""
    st = intel.status()
    lists_out: list[dict[str, Any]] = []
    for s in st.get("sources") or []:
        entries = (
            int(s.get("count_ips") or 0)
            + int(s.get("count_cidrs") or 0)
            + int(s.get("count_domains") or 0)
        )
        lists_out.append(
            {
                "id": s.get("id"),
                "name": s.get("name") or s.get("id"),
                "entries": entries,
                "updated_at": s.get("fetched_at") or s.get("mtime"),
                "severity": s.get("severity"),
                "cached": bool(s.get("cached")),
                "error": s.get("error"),
            }
        )
    with _state_lock:
        snap = _runtime.get("last_snapshot")
    hits = intel_hits_from_snapshot(snap, cap=200)
    return {
        "ok": True,
        "lists": lists_out,
        "refreshing": bool(st.get("refreshing")),
        "last_refresh": st.get("last_refresh_ok"),
        "last_refresh_attempt": st.get("last_refresh_attempt"),
        "cache_dir": st.get("dir") or getattr(intel, "INTEL_DIR", None),
        "counts": st.get("counts") or {},
        "hits": hits,
        "hit_count": len(hits),
        "hits_capped": len(hits) >= 200,
        "vt_enabled": bool(st.get("vt_enabled")),
        "attribution": st.get("attribution") or [],
        "interval_hours": st.get("interval_hours"),
    }

@app.route("/api/intel")
@require_localhost
def api_intel():
    """Threat-intel cache status (Host-checked; read-only)."""
    return jsonify(intel.status())



@app.route("/api/intel/status")
@require_localhost
def api_intel_status():
    """Threat-intel modal summary: list meta + current snapshot hits only."""
    try:
        return jsonify(intel_status_payload())
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)[:200]}), 500


@app.route("/api/intel/refresh", methods=["POST"])
@require_mutate_auth
def api_intel_refresh():
    """Manual refresh of threat-intel lists (Host + X-TW-Token)."""
    # Run refresh in background so UI is not blocked; return current+queued status
    def _do():
        try:
            intel.refresh(force=True)
        except Exception:
            pass

    threading.Thread(target=_do, name="tw-intel-manual", daemon=True).start()
    st = intel.status()
    st["refresh_started"] = True
    return jsonify(st)



@app.route("/api/history/summary")
@require_localhost
def api_history_summary():
    """History DB counts / oldest first-seen (Host-checked)."""
    try:
        return jsonify(history.summary())
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)[:200]}), 500


@app.route("/api/history/clear", methods=["POST"])
@require_mutate_auth
def api_history_clear():
    try:
        return jsonify(history.clear_all())
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)[:200]}), 500


@app.route("/api/history/retention", methods=["POST"])
@require_mutate_auth
def api_history_retention():
    data = request.get_json(silent=True) or {}
    try:
        days = float(data.get("days"))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "days required"}), 400
    try:
        return jsonify(history.set_retention_days(days))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)[:200]}), 500




@app.route("/api/alerts")
@require_localhost
def api_alerts_list():
    """Seed client alert store from history.sqlite."""
    try:
        include = str(request.args.get("all") or "") in ("1", "true", "yes")
        rows = history.list_alerts(include_terminal=include)
        return jsonify({"ok": True, "alerts": rows})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "alerts": []}), 500


@app.route("/api/alerts/upsert", methods=["POST"])
@require_mutate_auth
def api_alerts_upsert():
    """Persist one or more alerts from the client store."""
    data = request.get_json(silent=True) or {}
    items = data.get("alerts") if isinstance(data.get("alerts"), list) else None
    if items is None and data.get("id"):
        items = [data]
    if not items:
        return jsonify({"ok": False, "error": "alerts required"}), 400
    n = 0
    for it in items[:200]:
        if not isinstance(it, dict):
            continue
        aid = str(it.get("id") or "").strip()
        if not aid:
            continue
        try:
            history.upsert_alert(
                aid,
                first_seen=it.get("first_seen"),
                last_seen=it.get("last_seen"),
                count=int(it.get("count") or 1),
                state=str(it.get("state") or "active"),
                payload=it.get("payload") if isinstance(it.get("payload"), dict) else {},
            )
            n += 1
        except Exception:
            continue
    try:
        history.flush()
    except Exception:
        pass
    return jsonify({"ok": True, "n": n})


@app.route("/api/alerts/ack", methods=["POST"])
@require_mutate_auth
def api_alerts_ack():
    data = request.get_json(silent=True) or {}
    aid = str(data.get("id") or "").strip()
    if not aid:
        return jsonify({"ok": False, "error": "id required"}), 400
    ok = history.set_alert_state(aid, "ack")
    return jsonify({"ok": bool(ok)})


@app.route("/api/alerts/mute", methods=["POST"])
@require_mutate_auth
def api_alerts_mute():
    data = request.get_json(silent=True) or {}
    aid = str(data.get("id") or "").strip()
    if not aid:
        return jsonify({"ok": False, "error": "id required"}), 400
    ok = history.set_alert_state(aid, "muted")
    return jsonify({"ok": bool(ok)})


@app.route("/api/summary/weekly")
@require_localhost
def api_summary_weekly():
    """Last 7 days rollup from SQLite (Host-checked). Empty-state if history young."""
    try:
        days = float(request.args.get("days") or 7)
    except (TypeError, ValueError):
        days = 7.0
    days = max(1.0, min(days, 21.0))
    try:
        return jsonify(history.weekly_summary(days=days))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)[:200]}), 500


@app.route("/api/baseline/summary")
@require_localhost
def api_baseline_summary():
    """Baseline learning|ready chip data (Host-checked)."""
    try:
        return jsonify(baseline.summary())
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)[:200], "state": "unavailable"}), 500


@app.route("/api/dns/status")
@require_localhost
def api_dns_status():
    """DNS-Client log visibility status (Host-checked)."""
    try:
        return jsonify(dns_log.status())
    except Exception as e:
        return jsonify({"ok": False, "limited": True, "error": str(e)[:200]}), 200


@app.route("/api/dns")
@require_localhost
def api_dns():
    """Recent DNS queries (helper stream or 20s poll). Capped. Auth required."""
    try:
        return jsonify(dns_log.api_payload(limit=200))
    except Exception as e:
        return jsonify({"ok": False, "limited": True, "queries": [], "error": str(e)[:200]}), 200


@app.route("/api/helper/enable", methods=["POST"])
@require_mutate_auth
def api_helper_enable():
    """Consent MessageBox + UAC start of elevated DNS helper. Never auto-UAC."""
    try:
        return jsonify(helper_ipc.start_with_consent())
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)[:200]}), 200




@app.route("/api/net-context")
@require_localhost
def api_net_context():
    try:
        return jsonify(net_context.current())
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)[:200]}), 200


@app.route("/api/net-context/trust", methods=["POST"])
@require_mutate_auth
def api_net_context_trust():
    data = request.get_json(silent=True) or {}
    return jsonify(net_context.set_trust(str(data.get("name_hash") or ""), str(data.get("state") or "")))


@app.route("/api/doh/status")
@require_localhost
def api_doh_status():
    try:
        return jsonify(doh_detect.status())
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)[:200]}), 200


@app.route("/api/config-drift/status")
@require_localhost
def api_config_drift_status():
    try:
        return jsonify(config_drift.status())
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)[:200]}), 200

@app.route("/api/firewall/rules")
@require_localhost
def api_firewall_rules():
    """List TrafficWatch-created firewall rules (Host-checked)."""
    try:
        return jsonify(firewall.list_rules())
    except Exception as e:
        return jsonify({"ok": False, "rules": [], "error": str(e)[:200]}), 200


@app.route("/api/firewall/block", methods=["POST"])
@require_mutate_auth
def api_firewall_block():
    """Block a remote IP via Windows Firewall. Requires typed confirm_ip."""
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    confirm_ip = (data.get("confirm_ip") or "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "ip required"}), 400
    if not confirm_ip:
        return jsonify({"ok": False, "error": "confirm_ip required"}), 400
    if confirm_ip != ip:
        return jsonify({"ok": False, "error": "confirm_ip does not match ip"}), 400
    also_in = data.get("also_inbound")
    also_inbound = True if also_in is None else bool(also_in)
    minutes = data.get("minutes")
    if minutes is not None:
        try:
            minutes = int(minutes)
        except (TypeError, ValueError):
            minutes = 10
    result = firewall.block_ip(ip, also_inbound=also_inbound, minutes=minutes)
    if result.get("ok"):
        try:
            history.record_event("firewall_block", {"ip": ip, "rules": result.get("rules")})
            history.flush()
        except Exception:
            pass
        return jsonify(result), 200
    status = 400
    if result.get("need_admin"):
        status = 403
    if result.get("refused"):
        status = 400
    return jsonify(result), status


@app.route("/api/firewall/unblock", methods=["POST"])
@require_mutate_auth
def api_firewall_unblock():
    """Remove TrafficWatch block rules for an IP. Requires typed confirm_ip."""
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    confirm_ip = (data.get("confirm_ip") or "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "ip required"}), 400
    if not confirm_ip:
        return jsonify({"ok": False, "error": "confirm_ip required"}), 400
    if confirm_ip != ip:
        return jsonify({"ok": False, "error": "confirm_ip does not match ip"}), 400
    result = firewall.unblock_ip(ip)
    if result.get("ok"):
        try:
            history.record_event("firewall_unblock", {"ip": ip, "removed": result.get("removed")})
            history.flush()
        except Exception:
            pass
        return jsonify(result), 200
    status = 403 if result.get("need_admin") else 400
    return jsonify(result), status


@socketio.on("connect")
def on_connect():
    if not _socket_host_ok():
        return False
    if not _socket_session_ok():
        return False
    sid = getattr(request, "sid", None)
    try:
        join_room("authed")
    except Exception:
        pass
    if sid:
        _authed_sids.add(sid)
    with _state_lock:
        snap = _runtime.get("last_snapshot")
        geo_meta = _runtime.get("geo_meta")
    home = effective_home()
    target = sid or "authed"
    if snap:
        socketio.emit("snapshot", snap, to=target)
    socketio.emit(
        "hello",
        {
            "home": home,
            "geo": geo_meta,
            "poll_seconds": POLL_SECONDS,
            "version": 2,
        },
        to=target,
    )


@socketio.on("disconnect")
def on_disconnect():
    sid = getattr(request, "sid", None)
    if sid:
        _authed_sids.discard(sid)


@socketio.on("request_snapshot")
def on_request_snapshot():
    if not _socket_host_ok() or not _socket_token_ok(None):
        return
    sid = getattr(request, "sid", None)
    # ux39: emit cached/lite/warming only — never sync full build_snapshot()
    socketio.emit("snapshot", _snapshot_for_request(), to=sid or "authed")


@socketio.on("set_home")
def on_set_home(data):
    if not _socket_host_ok():
        return
    if not _socket_token_ok(data):
        return
    try:
        lat = float(data["lat"])
        lon = float(data["lon"])
    except (KeyError, TypeError, ValueError):
        return
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return
    home = {
        "lat": lat,
        "lon": lon,
        "city": data.get("city") or "",
        "region": data.get("region") or "",
        "country": data.get("country") or "",
        "source": "user_override",
        "label": data.get("label") or f"Custom home ({lat:.4f}, {lon:.4f})",
    }
    with _state_lock:
        _runtime["home_override"] = home
    socketio.emit("home", home, to="authed")


@app.after_request
def _security_headers(resp: Response):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self' ws://127.0.0.1:8767 ws://localhost:8767; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    path = request.path or ""
    if path.startswith("/api/") or path == "/":
        resp.headers["Cache-Control"] = "no-store"
    return resp


def _open_app_window(url: str) -> None:
    """Browser-mode fallback: prefer an Edge app window (no tabs/address bar), else default browser."""
    if sys.platform.startswith("win"):
        for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
            edge = os.path.join(base or "", "Microsoft", "Edge", "Application", "msedge.exe")
            if base and os.path.isfile(edge):
                try:
                    subprocess.Popen([edge, f"--app={url}"], close_fds=True)
                    return
                except OSError:
                    break
    webbrowser.open(url)


def main() -> None:

    parser = argparse.ArgumentParser(description="TrafficWatch local traffic map")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--browser", action="store_true", help="Open browser to UI")
    parser.add_argument("--no-geo-download", action="store_true", help="Skip MMDB download attempt")
    args = parser.parse_args()
    import applog
    applog.install()
    # Authenticode stays off until after first (lite) snapshot — same as desktop.

    if not is_loopback_bind(args.host):
        print(
            f"ERROR: Refusing to bind non-loopback host {args.host!r}. "
            "TrafficWatch is localhost-only (127.0.0.1 / localhost / ::1). "
            "Do not use 0.0.0.0 or a LAN address.",
            flush=True,
        )
        raise SystemExit(2)
    applog.write_pid_file()

    print("TrafficWatch starting.")
    print(f"  Binding {args.host}:{args.port} (localhost only)")
    geo_meta = geoip_lookup.init_geo(allow_download=not args.no_geo_download)
    if args.no_geo_download and not geo_meta.get("mmdb_ok"):
        print("  GeoIP MMDB missing; map pins will be limited.")
    else:
        print(f"  GeoIP: {geo_meta.get('mmdb_msg')}")
    home = geo_meta.get("home") or geoip_lookup.ASSUMED_HOME
    _runtime["home"] = home
    _runtime["geo_meta"] = geo_meta
    print(f"  Home: {home.get('source') or 'assumed'} (location not logged)")

    # Phase B: load intel cache + background refresh (must not block splash / first snapshot)
    try:
        intel.start_background()
        print(f"  Intel: cache dir {intel.INTEL_DIR} (vt_enabled={intel.vt_enabled})")
    except Exception as exc:
        print(f"  Intel: start failed (continuing): {exc}")

    # Phase C: SQLite history + DNS-Client log (best-effort background)
    try:
        history.init()
        print(f"  History: {history.DB_PATH}")
    except Exception as exc:
        print(f"  History: init failed (continuing): {exc}")
    try:
        baseline.init()
        print("  Baseline: per-program ~7d (ASN via IPinfo when available)")
    except Exception as exc:
        print(f"  Baseline: init failed (continuing): {exc}")
    try:
        exe_hash.init()
        allow_memory.init()
        net_context.init()
        print("  Tier0: exe_hash + allow_memory + net_context ready")
    except Exception as exc:
        print(f"  Tier0 init failed (continuing): {exc}")
    try:
        firewall.start_expiry_timer(60.0)
        print("  Firewall: timed-rule expiry timer started")
    except Exception as exc:
        print(f"  Firewall expiry timer failed (continuing): {exc}")
    try:
        ipb = (geo_meta or {}).get("ipinfo_blocked") or (geo_meta or {}).get("ipinfo_msg")
        if (geo_meta or {}).get("ipinfo_blocked") == "BLOCKED_IPINFO_TOKEN":
            print("  IPinfo: BLOCKED_IPINFO_TOKEN (ASN fields empty until token)")
        elif (geo_meta or {}).get("ipinfo_ok"):
            print(f"  IPinfo: {(geo_meta or {}).get('ipinfo_msg')}")
        else:
            print(f"  IPinfo: {ipb}")
    except Exception:
        pass
    try:
        dns_log.start_background()
        print("  DNS log: background reader started (degrades if no access)", flush=True)
    except Exception as exc:
        print(f"  DNS log: start failed (continuing): {exc}", flush=True)

    # Phase 2: do NOT block listening on full build_snapshot(). Serve lite first;
    # enrichment (geo miss, DNS, intel, Authenticode, signals, baseline) rides
    # later full snapshots without stretching the 1.5s steady-state cadence.
    def _phase2_boot() -> None:
        try:
            socketio.sleep(0.05)
            lite = build_lite_snapshot()
            socketio.emit("snapshot", lite, to="authed")
            ms = _runtime.get("_lite_ms")
            print(f"  Lite snapshot: {lite.get('count', 0)} rows in {ms}ms (phase=lite)", flush=True)
        except Exception as exc:
            print(f"  Lite snapshot failed (continuing): {exc}", flush=True)
        try:
            import signals as _signals
            _signals.set_auth_allowed(True)
            print("  Authenticode: background worker enabled", flush=True)
        except Exception:
            pass
        poll_loop()

    socketio.start_background_task(_phase2_boot)

    pair_code = create_pair_code()
    pair_url = f"http://{args.host}:{args.port}/pair?code={pair_code}"
    print("  Browser pairing (one-time, expires ~5 min):")
    print(f"    {pair_url}")
    print("  POST /api/pair with the code sets an HttpOnly cookie; no token in JSON.")
    print("  Phase 2: socketio starting immediately (lite snapshot in background)", flush=True)

    if args.browser:
        threading.Timer(1.2, lambda: _open_app_window(pair_url)).start()

    try:
        socketio.run(
            app,
            host=args.host,
            port=args.port,
            allow_unsafe_werkzeug=True,
            use_reloader=False,
        )
    except TypeError:
        socketio.run(app, host=args.host, port=args.port, use_reloader=False)


if __name__ == "__main__":
    main()