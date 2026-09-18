"""Unelevated named-pipe client for the TrafficWatch elevated DNS+TCP helper.

The Flask/pywebview process must NEVER host ETW. This module:
  - shows a one-time consent MessageBox
  - starts helper\\tw_helper.ps1 via UAC (Start-Process -Verb RunAs -File)
  - reads JSON lines into bounded rings (DNS + TCP)
  - degrades (never crashes) if the helper is missing

Pipe: TrafficWatch-helper  DACL: current user + SYSTEM (set by helper).
Timed opens only (_open_pipe_timed / WaitNamedPipe) -- never block Flask/UAC.
"""
from __future__ import annotations

import json
import os
import subprocess
try:
    from ps51_env import clean_ps51_env
except Exception:  # pragma: no cover
    def clean_ps51_env(base=None):
        import os as _os
        e = dict(base if base is not None else _os.environ)
        e.pop("PSModulePath", None)
        return e
import threading
import time
from collections import deque
from typing import Any

ROOT = os.path.dirname(os.path.abspath(__file__))
HELPER_PS1 = os.path.join(ROOT, "helper", "tw_helper.ps1")
PIPE_NAME = "TrafficWatch-helper"
PIPE_PATH = r"\\.\pipe\TrafficWatch-helper"

CONSENT_TITLE = "TrafficWatch - Enable live DNS + TCP?"
CONSENT_TEXT = (
    "Live DNS and TCP direction/bytes need a one-time admin helper so "
    "TrafficWatch can read Windows DNS Client and TCP network events (ETW) "
    "in real time, attach process names to queries, and confirm "
    "outbound/inbound with per-connection byte totals.\n\n"
    "The helper runs elevated and talks only over a private named pipe "
    "(current user + SYSTEM). It returns parsed fields only "
    "(DNS name/status/results/PID; TCP open/bytes/close with "
    "direction, 4-tuple, bytes_in/out, duration). It never sends payloads "
    "or raw ETW.\n\n"
    "Windows will prompt for administrator consent (UAC).\n\n"
    "Yes = start the helper now (DNS + TCP).\n"
    "No = keep the 20-second DNS poll and port-guess direction (no live bytes)."
)

RING_MAX = 200
TCP_RING_MAX = 400
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

_lock = threading.RLock()
_events: deque[dict[str, Any]] = deque(maxlen=RING_MAX)
_tcp_events: deque[dict[str, Any]] = deque(maxlen=TCP_RING_MAX)
# Latest flow snapshot by 4-tuple key and by pid|remote|rport
_tcp_flows: dict[str, dict[str, Any]] = {}
_state: dict[str, Any] = {
    "connected": False,
    "elevated": False,
    "dns": False,
    "log_enabled": False,
    "last_error": None,
    "dns_events_count": 0,
    "pipe": PIPE_NAME,
    "limited": True,
    "tcp": False,
    "tcp_limited": True,
    "tcp_events_count": 0,
    "tcp_error": None,
    "tcp_source": "none",
    "storm_trips": 0,
}
_stop = threading.Event()
_reader_started = False
_fp = None  # binary pipe file
_write_lock = threading.Lock()


def _set_error(msg: str | None) -> None:
    with _lock:
        _state["last_error"] = msg


def status() -> dict[str, Any]:
    with _lock:
        return {
            "connected": bool(_state["connected"]),
            "elevated": bool(_state["elevated"]),
            "dns": bool(_state["dns"]),
            "log_enabled": bool(_state["log_enabled"]),
            "last_error": _state["last_error"],
            "dns_events_count": int(_state["dns_events_count"] or 0),
            "pipe": PIPE_NAME,
            "limited": (not _state["connected"]) or (not _state["dns"]),
            "tcp": bool(_state["tcp"]),
            "tcp_limited": bool(_state["tcp_limited"]) or (not _state["tcp"]),
            "tcp_events_count": int(_state["tcp_events_count"] or 0),
            "tcp_error": _state["tcp_error"],
            "tcp_source": _state.get("tcp_source") or "none",
            "storm_trips": int(_state.get("storm_trips") or 0),
        }


def drain_events() -> list[dict[str, Any]]:
    """Pop currently buffered DNS helper events (caller owns them)."""
    out: list[dict[str, Any]] = []
    with _lock:
        while _events:
            out.append(_events.popleft())
    return out


def drain_tcp_events() -> list[dict[str, Any]]:
    """Pop buffered TCP helper events."""
    out: list[dict[str, Any]] = []
    with _lock:
        while _tcp_events:
            out.append(_tcp_events.popleft())
    return out


def peek_events(limit: int = 80) -> list[dict[str, Any]]:
    with _lock:
        items = list(_events)
    if limit > 0:
        items = items[-limit:]
    return items


def tcp_flow_index() -> dict[str, dict[str, Any]]:
    """Copy of latest TCP flows keyed by 4-tuple and pid|remote|port."""
    with _lock:
        return dict(_tcp_flows)


def tcp_flows_list(limit: int = 200) -> list[dict[str, Any]]:
    with _lock:
        items = list(_tcp_flows.values())
    if limit > 0 and len(items) > limit:
        items = items[-limit:]
    return items


def _flow_keys(obj: dict[str, Any]) -> list[str]:
    lip = str(obj.get("local_ip") or "")
    lport = obj.get("local_port")
    rip = str(obj.get("remote_ip") or "")
    rport = obj.get("remote_port")
    pid = obj.get("pid")
    return [
        f"{lip}|{lport}|{rip}|{rport}",
        f"|{lport}|{rip}|{rport}",
        f"{pid}|{rip}|{rport}",
        f"{pid}|{rip}|",
    ]


def _ingest_tcp(obj: dict[str, Any]) -> None:
    """Update flow index + ring. Called under _lock."""
    _tcp_events.append(obj)
    _state["tcp_events_count"] = int(_state["tcp_events_count"] or 0) + 1
    kind = str(obj.get("kind") or "")
    keys = _flow_keys(obj)
    primary = keys[0]
    prev = _tcp_flows.get(primary) or {}
    row = dict(prev)
    for k in (
        "dir",
        "pid",
        "proc",
        "local_ip",
        "local_port",
        "remote_ip",
        "remote_port",
        "bytes_out",
        "bytes_in",
        "duration_ms",
        "ts",
    ):
        if obj.get(k) is not None or k in ("bytes_out", "bytes_in"):
            if k in obj:
                row[k] = obj.get(k)
    row["kind"] = kind or row.get("kind")
    row["updated"] = time.time()
    if kind == "close":
        row["closed"] = True
    for k in keys:
        if not k or k.count("|") < 2:
            continue
        if k in ("|||", "|None|None|None", "None|None|None"):
            continue
        _tcp_flows[k] = row
    if len(_tcp_flows) > 1200:
        ordered = sorted(_tcp_flows.items(), key=lambda kv: float(kv[1].get("updated") or 0))
        for drop_k, _ in ordered[:400]:
            _tcp_flows.pop(drop_k, None)


def _current_user_sid() -> str:
    if os.name != "nt":
        return ""
    try:
        completed = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=_CREATE_NO_WINDOW,
        )
        line = (completed.stdout or "").strip().replace('"', "")
        if "," in line:
            sid = line.split(",")[-1].strip()
            if sid.startswith("S-1-"):
                return sid
    except Exception:
        pass
    return ""


def _ps_single(s: str) -> str:
    return "'" + (s or "").replace("'", "''") + "'"


def _message_box_yes_no(text: str, title: str) -> str:
    """Return 'yes', 'no', or 'error'. ASCII MessageBox; never raises."""
    if os.name != "nt":
        return "error"
    try:
        import ctypes

        MB_YESNO = 0x04
        MB_ICONQUESTION = 0x20
        MB_SETFOREGROUND = 0x00010000
        MB_TOPMOST = 0x00040000
        IDYES = 6
        IDNO = 7
        r = ctypes.windll.user32.MessageBoxW(
            None,
            text,
            title,
            MB_YESNO | MB_ICONQUESTION | MB_SETFOREGROUND | MB_TOPMOST,
        )
        if r == IDYES:
            return "yes"
        if r == IDNO:
            return "no"
        return "no"
    except Exception:
        return "error"


def _wait_named_pipe(timeout_sec: float = 0.15) -> bool:
    """False immediately if the pipe does not exist. Never wait forever."""
    if os.name != "nt":
        return False
    try:
        import ctypes

        WaitNamedPipeW = ctypes.windll.kernel32.WaitNamedPipeW
        WaitNamedPipeW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
        WaitNamedPipeW.restype = ctypes.c_int
        ms = max(1, min(int(timeout_sec * 1000), 1500))
        return bool(WaitNamedPipeW(PIPE_PATH, ms))
    except Exception:
        return False


def _open_pipe():
    return open(PIPE_PATH, "r+b", buffering=0)


def _open_pipe_timed(timeout_sec: float = 0.5):
    """open() on a wedged pipe can block forever. Bound it with a daemon thread."""
    holder: dict = {"fp": None, "err": None}

    def _run() -> None:
        try:
            holder["fp"] = _open_pipe()
        except Exception as exc:
            holder["err"] = exc

    th = threading.Thread(target=_run, name="tw-pipe-open", daemon=True)
    th.start()
    th.join(max(0.05, float(timeout_sec)))
    if th.is_alive():
        return None
    return holder.get("fp")


def _close_pipe() -> None:
    global _fp
    with _lock:
        _state["connected"] = False
        _state["tcp"] = False
        fp = _fp
        _fp = None
    if fp is not None:
        try:
            fp.close()
        except Exception:
            pass


def send_op(op: str) -> bool:
    """Write one allow-listed JSON op line. Ignore unknown locally too."""
    if op not in ("ping", "status", "dns_start", "dns_stop", "tcp_start", "tcp_stop", "shutdown"):
        return False
    with _lock:
        fp = _fp
        connected = bool(_state["connected"])
    if not connected or fp is None:
        return False
    try:
        line = json.dumps({"op": op}, separators=(",", ":")) + "\n"
        with _write_lock:
            fp.write(line.encode("utf-8"))
            fp.flush()
        return True
    except Exception as e:
        _set_error(str(e)[:160])
        _close_pipe()
        return False


def _ingest_line(raw: str) -> None:
    raw = (raw or "").strip()
    if not raw:
        return
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return
    if not isinstance(obj, dict):
        return
    t = obj.get("t")
    with _lock:
        if t == "dns":
            _events.append(obj)
            _state["dns_events_count"] = int(_state["dns_events_count"] or 0) + 1
        elif t == "tcp":
            _ingest_tcp(obj)
        elif t == "status":
            _state["elevated"] = bool(obj.get("elevated", True))
            _state["dns"] = bool(obj.get("dns"))
            _state["log_enabled"] = bool(obj.get("log_enabled"))
            _state["limited"] = bool(obj.get("limited"))
            _state["tcp"] = bool(obj.get("tcp"))
            _state["tcp_limited"] = bool(obj.get("tcp_limited", not obj.get("tcp")))
            if obj.get("tcp_source"):
                _state["tcp_source"] = str(obj.get("tcp_source"))
            if obj.get("tcp_error"):
                _state["tcp_error"] = str(obj.get("tcp_error"))[:300]
            if obj.get("storm_trips") is not None:
                try:
                    _state["storm_trips"] = int(obj.get("storm_trips") or 0)
                except (TypeError, ValueError):
                    pass
            if obj.get("last_error"):
                _state["last_error"] = str(obj.get("last_error"))[:160]
            if obj.get("events") is not None:
                try:
                    n = int(obj.get("events") or 0)
                    if n > int(_state["dns_events_count"] or 0):
                        _state["dns_events_count"] = n
                except (TypeError, ValueError):
                    pass
            if obj.get("tcp_events") is not None:
                try:
                    n = int(obj.get("tcp_events") or 0)
                    if n > int(_state["tcp_events_count"] or 0):
                        _state["tcp_events_count"] = n
                except (TypeError, ValueError):
                    pass
        elif t == "pong":
            pass
        elif t == "ok" and obj.get("op") == "dns_start":
            _state["dns"] = bool(obj.get("ok", True))
            _state["limited"] = bool(obj.get("limited", False))
            if "tcp" in obj:
                _state["tcp"] = bool(obj.get("tcp"))
            if "tcp_limited" in obj:
                _state["tcp_limited"] = bool(obj.get("tcp_limited"))
        elif t == "ok" and obj.get("op") == "tcp_start":
            _state["tcp"] = bool(obj.get("ok", True))
            _state["tcp_limited"] = bool(obj.get("limited", False))
            if obj.get("source"):
                _state["tcp_source"] = str(obj.get("source"))


def _reader_loop() -> None:
    """Stay connected; reconnect quietly if the helper is still up."""
    buf = b""
    while not _stop.is_set():
        with _lock:
            fp = _fp
            connected = bool(_state["connected"])
        if not connected or fp is None:
            try_connect(timeout=0.15)
            _stop.wait(1.0)
            continue
        try:
            chunk = os.read(fp.fileno(), 4096)
            if not chunk:
                _close_pipe()
                buf = b""
                _stop.wait(0.5)
                continue
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    _ingest_line(line.decode("utf-8", errors="replace"))
                except Exception:
                    pass
        except Exception as e:
            _set_error(str(e)[:160])
            _close_pipe()
            buf = b""
            _stop.wait(0.5)


def _ensure_reader() -> None:
    global _reader_started
    with _lock:
        if _reader_started:
            return
        _reader_started = True
    threading.Thread(target=_reader_loop, name="tw-helper-ipc", daemon=True).start()


def try_connect(timeout: float = 1.5) -> bool:
    """Connect if the helper pipe exists. Never prompts UAC. Never raises."""
    global _fp
    if os.name != "nt":
        return False
    with _lock:
        if _state["connected"] and _fp is not None:
            return True
    if not os.path.isfile(HELPER_PS1):
        _set_error("helper script missing")
        return False
    try:
        wait_s = min(max(0.05, float(timeout)), 1.5)
        if not _wait_named_pipe(wait_s):
            return False
        fp = _open_pipe_timed(min(0.5, wait_s + 0.2))
        if fp is None:
            _set_error("pipe open timed out (helper absent or wedged)")
            return False
        with _lock:
            _fp = fp
            _state["connected"] = True
            _state["elevated"] = True
            _state["last_error"] = None
        _ensure_reader()
        try:
            send_op("status")
            send_op("dns_start")
            send_op("tcp_start")
        except Exception:
            pass
        return True
    except Exception as e:
        _set_error(str(e)[:160])
        _close_pipe()
        return False


def start_with_consent() -> dict[str, Any]:
    """MessageBox then UAC-launch the helper. No = stay on 20s poll."""
    if os.name != "nt":
        return {"ok": False, "error": "Windows only"}
    if try_connect(timeout=0.6):
        return {"ok": True, "already": True, "connected": True, "pipe": PIPE_NAME}
    if not os.path.isfile(HELPER_PS1):
        return {"ok": False, "error": "helper script missing"}

    choice = _message_box_yes_no(CONSENT_TEXT, CONSENT_TITLE)
    if choice != "yes":
        if choice == "error":
            return {"ok": False, "error": "could not show consent dialog"}
        return {
            "ok": False,
            "declined": True,
            "error": "User declined live DNS+TCP helper; using 20s poll",
        }

    sid = _current_user_sid()
    args = [
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-WindowStyle",
        "Hidden",
        "-File",
        HELPER_PS1,
        "-ParentPid",
        str(os.getpid()),
    ]
    if sid:
        args += ["-ClientSid", sid]
    ps = (
        "Start-Process -FilePath powershell.exe -Verb RunAs -WindowStyle Hidden "
        "-ArgumentList " + ",".join(_ps_single(a) for a in args)
    )
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=120,
            env=clean_ps51_env(),
            creationflags=_CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "UAC prompt timed out"}
    except Exception as e:
        return {"ok": False, "error": str(e)[:160]}

    err = ((completed.stderr or "") + " " + (completed.stdout or "")).strip()
    low = err.lower()
    if completed.returncode != 0:
        if "canceled" in low or "cancelled" in low or "1223" in low:
            return {"ok": False, "cancelled": True, "error": "UAC cancelled"}
        return {"ok": False, "error": (err or f"exit {completed.returncode}")[:200]}

    deadline = time.time() + 12.0
    while time.time() < deadline:
        if try_connect(timeout=1.0):
            return {"ok": True, "launched": True, "connected": True, "pipe": PIPE_NAME}
        time.sleep(0.4)
    return {
        "ok": True,
        "launched": True,
        "connected": False,
        "error": "helper started; pipe not up yet",
        "pipe": PIPE_NAME,
    }


def start_background() -> None:
    """Kick a daemon reader. Never UAC. Never block the caller on the pipe."""
    _ensure_reader()


__all__ = [
    "PIPE_NAME",
    "CONSENT_TITLE",
    "CONSENT_TEXT",
    "status",
    "drain_events",
    "drain_tcp_events",
    "peek_events",
    "tcp_flow_index",
    "tcp_flows_list",
    "try_connect",
    "start_with_consent",
    "start_background",
    "send_op",
]
