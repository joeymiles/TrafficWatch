"""Windows DNS-Client visibility (Phase C + Tier 1 phase-1).

Prefer the elevated helper stream (process-linked queries) when connected.
Fall back to a throttled 20s Get-WinEvent poll when the helper is down.
Without admin / helper / channel access, degrades: status limited, never crashes.

Phase-1 signals (in-memory, no extra deps): per-process NXDOMAIN bursts and
unique-name rate. TCP "connected to IP never resolved" is parked (hook only).
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
from collections import defaultdict, deque
from typing import Any

REFRESH_SEC = 20.0
MAX_EVENTS = 200
SNAPSHOT_QUERIES = 80
CACHE_TTL = 90.0
NX_BURST_N = 8
NX_BURST_SEC = 30.0
UNIQUE_RATE_SEC = 60.0

_lock = threading.RLock()
_state: dict[str, Any] = {
    "ok": False,
    "limited": True,
    "live": False,
    "message": "DNS log: not yet queried",
    "queries": deque(maxlen=MAX_EVENTS),  # {name, ip, pid, proc, nxdomain, ts, status, results}
    "by_ip": {},  # ip -> [names]
    "by_name": {},  # lower name -> [ips]
    "resolved_ips": set(),
    "last_query_at": 0.0,
    "error": None,
    "source": "none",
}
_nx_by_pid: dict[Any, deque] = defaultdict(lambda: deque(maxlen=64))
_name_window: deque = deque(maxlen=400)
_worker_started = False


def _helper_mod():
    try:
        import helper_ipc

        return helper_ipc
    except Exception:
        return None


def _now() -> float:
    return time.time()


def _normalize(ev: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(ev, dict):
        return None
    name = (ev.get("name") or ev.get("QueryName") or ev.get("Name") or "")
    name = str(name).strip().rstrip(".")
    results = ev.get("results")
    ips: list[str] = []
    if isinstance(results, list):
        for x in results:
            s = str(x or "").strip()
            if s and s not in ips:
                ips.append(s)
    ip = (ev.get("ip") or ev.get("Address") or ev.get("IPAddress") or ev.get("Ip") or "")
    ip = str(ip).strip()
    if ip and ip not in ips:
        ips.insert(0, ip)
    ts = ev.get("ts") or ev.get("TimeCreated")
    pid = ev.get("pid")
    try:
        pid = int(pid) if pid is not None and str(pid).strip() != "" else None
    except (TypeError, ValueError):
        pid = None
    proc = ev.get("proc") or ev.get("process") or None
    if proc:
        proc = str(proc)
    nx = bool(ev.get("nxdomain"))
    status = ev.get("status")
    if not name and not ips:
        return None
    return {
        "name": name or None,
        "ip": (ips[0] if ips else None),
        "results": ips,
        "pid": pid,
        "proc": proc,
        "nxdomain": nx,
        "status": status,
        "ts": ts,
        "source": ev.get("source") or "helper",
    }


def _rebuild_indexes_locked() -> None:
    by_ip: dict[str, list[str]] = {}
    by_name: dict[str, list[str]] = {}
    resolved: set[str] = set()
    for ev in _state["queries"]:
        name = ev.get("name")
        ips = list(ev.get("results") or [])
        if ev.get("ip") and ev["ip"] not in ips:
            ips.append(ev["ip"])
        for ip in ips:
            if not ip:
                continue
            resolved.add(ip)
            if name:
                by_ip.setdefault(ip, [])
                if name not in by_ip[ip]:
                    by_ip[ip].append(name)
                ln = name.lower()
                by_name.setdefault(ln, [])
                if ip not in by_name[ln]:
                    by_name[ln].append(ip)
        if name and not ips:
            by_name.setdefault(name.lower(), [])
    _state["by_ip"] = by_ip
    _state["by_name"] = by_name
    _state["resolved_ips"] = resolved


def _note_signals_locked(row: dict[str, Any]) -> None:
    now = _now()
    pid = row.get("pid")
    if row.get("nxdomain") and pid is not None:
        dq = _nx_by_pid[pid]
        dq.append(now)
        while dq and (now - dq[0]) > NX_BURST_SEC:
            dq.popleft()
    name = row.get("name")
    if name:
        _name_window.append((now, name.lower()))
        while _name_window and (now - _name_window[0][0]) > UNIQUE_RATE_SEC:
            _name_window.popleft()


def _signals_locked() -> dict[str, Any]:
    now = _now()
    bursts: list[dict[str, Any]] = []
    for pid, dq in list(_nx_by_pid.items()):
        while dq and (now - dq[0]) > NX_BURST_SEC:
            dq.popleft()
        if len(dq) >= NX_BURST_N:
            proc = None
            for ev in reversed(_state["queries"]):
                if ev.get("pid") == pid:
                    proc = ev.get("proc")
                    break
            bursts.append({"pid": pid, "proc": proc, "count": len(dq)})
    while _name_window and (now - _name_window[0][0]) > UNIQUE_RATE_SEC:
        _name_window.popleft()
    unique = len({n for _, n in _name_window})
    return {
        "nxdomain_bursts": bursts[:12],
        "unique_names_1m": unique,
        "unique_name_rate": unique,
    }


def ingest_helper_event(ev: dict[str, Any]) -> dict[str, Any] | None:
    """Public: push one parsed helper (or simulated) DNS event. Never raises."""
    try:
        row = _normalize(ev)
        if not row:
            return None
        row["source"] = row.get("source") or "helper"
        with _lock:
            _state["queries"].append(row)
            _note_signals_locked(row)
            # cheap index update
            name = row.get("name")
            for ip in list(row.get("results") or []) + ([row["ip"]] if row.get("ip") else []):
                if not ip:
                    continue
                _state["resolved_ips"].add(ip)
                if name:
                    _state["by_ip"].setdefault(ip, [])
                    if name not in _state["by_ip"][ip]:
                        _state["by_ip"][ip].append(name)
                    ln = name.lower()
                    _state["by_name"].setdefault(ln, [])
                    if ip not in _state["by_name"][ln]:
                        _state["by_name"][ln].append(ip)
            if name and not row.get("results") and not row.get("ip"):
                _state["by_name"].setdefault(name.lower(), [])
            _state["ok"] = True
            _state["live"] = True
            _state["limited"] = False
            _state["source"] = "helper"
            _state["message"] = f"DNS log: live ({len(_state['queries'])} queries)"
            _state["error"] = None
            _state["last_query_at"] = time.time()
        return row
    except Exception:
        return None


def ingest_helper_events(events: list[dict[str, Any]]) -> int:
    n = 0
    for ev in events or []:
        if ingest_helper_event(ev):
            n += 1
    return n


def resolved_ips() -> set[str]:
    """Phase-2 hook: IPs observed in DNS results (in-memory)."""
    with _lock:
        return set(_state.get("resolved_ips") or [])


def ip_never_resolved(ip: str) -> bool:
    """Phase-2 hook (not wired to TCP). True if live DNS has never seen this IP."""
    raw = (ip or "").strip()
    if not raw:
        return False
    with _lock:
        live = bool(_state.get("live"))
        resolved = _state.get("resolved_ips") or set()
    if not live:
        return False
    return raw not in resolved


def status() -> dict[str, Any]:
    helper = {}
    mod = _helper_mod()
    if mod is not None:
        try:
            helper = mod.status()
        except Exception:
            helper = {"connected": False, "last_error": "helper status failed"}
    with _lock:
        live = bool(_state["live"]) and bool(helper.get("connected"))
        limited = (not live) and bool(_state["limited"])
        if helper.get("connected") and helper.get("dns"):
            live = True
            limited = False
        msg = _state["message"]
        if live:
            msg = f"DNS log: live ({len(_state['queries'])} queries)"
        elif helper.get("connected") is False:
            if _state["ok"] and not _state["limited"]:
                msg = _state["message"]
            else:
                msg = _state["message"] if _state["message"] else "DNS log: limited"
        sig = _signals_locked()
        return {
            "ok": bool(_state["ok"]) or live,
            "limited": limited if not live else False,
            "live": live,
            "message": msg,
            "query_count": len(_state["queries"]),
            "last_query_at": _state["last_query_at"],
            "error": _state["error"],
            "source": "helper" if live else _state["source"],
            "helper": helper,
            "signals": sig,
        }


def snapshot_meta() -> dict[str, Any]:
    st = status()
    with _lock:
        q = list(_state["queries"])[-SNAPSHOT_QUERIES:]
    st["queries"] = q
    return st


def api_payload(limit: int = 200) -> dict[str, Any]:
    cap = max(1, min(int(limit or 200), MAX_EVENTS))
    st = status()
    with _lock:
        q = list(_state["queries"])[-cap:]
    st["ok"] = True
    st["queries"] = q
    return st


def _parse_events(raw: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    raw = (raw or "").strip()
    if not raw:
        return out
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return out
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return out
    for item in data:
        if not isinstance(item, dict):
            continue
        name = (item.get("QueryName") or item.get("Name") or "").strip().rstrip(".")
        ip = (item.get("Address") or item.get("IPAddress") or item.get("Ip") or "").strip()
        ts = item.get("TimeCreated") or item.get("ts")
        if not name and not ip:
            continue
        out.append(
            {
                "name": name or None,
                "ip": ip or None,
                "ts": ts,
                "pid": None,
                "proc": None,
                "nxdomain": False,
                "status": item.get("Id"),
                "results": [ip] if ip else [],
                "source": "poll",
            }
        )
    return out


def _fetch_win_events() -> tuple[bool, str, list[dict[str, Any]]]:
    """Return (ok, message, events). ok=False means limited / denied."""
    if os.name != "nt":
        return False, "DNS log: Windows only", []
    ps = r"""
$ErrorActionPreference = 'Stop'
try {
  $log = 'Microsoft-Windows-DNS-Client/Operational'
  $ev = @()
  try {
    $ev = @(Get-WinEvent -LogName $log -MaxEvents 120 -ErrorAction Stop |
      Where-Object { $_.Id -in 3008,3009,3010,3018,3019,3020 } |
      Select-Object -First 80)
  } catch {
    if ($_.Exception.Message -notmatch 'No events were found') { throw }
  }
  if (-not $ev -or $ev.Count -eq 0) {
    try {
      $ev = @(Get-WinEvent -LogName $log -MaxEvents 40 -ErrorAction Stop)
    } catch {
      if ($_.Exception.Message -match 'No events were found') {
        Write-Output '[]'
        exit 0
      }
      throw
    }
  }
  $rows = @()
  foreach ($e in $ev) {
    $xml = [xml]$e.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) {
      if ($d.Name) { $data[$d.Name] = [string]$d.'#text' }
    }
    $q = $data['QueryName']; if (-not $q) { $q = $data['Name'] }
    $addr = $data['Address']; if (-not $addr) { $addr = $data['IPAddress'] }
    if (-not $addr) { $addr = $data['IpAddress'] }
    if (-not $q -and -not $addr) { continue }
    $rows += [pscustomobject]@{
      QueryName = $q
      Address = $addr
      TimeCreated = $e.TimeCreated.ToUniversalTime().ToString('o')
      Id = $e.Id
    }
  }
  if ($rows.Count -eq 0) { Write-Output '[]'; exit 0 }
  $rows | ConvertTo-Json -Compress -Depth 4
} catch {
  Write-Output ('__TW_DNS_ERR__' + $_.Exception.Message)
  exit 1
}
"""
    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                ps,
            ],
            capture_output=True,
            text=True,
            timeout=12,
            env=clean_ps51_env(),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        out = (completed.stdout or "").strip()
        err = (completed.stderr or "").strip()
        if out.startswith("__TW_DNS_ERR__") or completed.returncode != 0:
            msg = out.replace("__TW_DNS_ERR__", "", 1).strip() or err or "access denied"
            return False, f"DNS log: limited ({msg[:120]})", []
        events = _parse_events(out)
        if not events:
            return True, "DNS log: ok (no recent query events)", []
        return True, f"DNS log: {len(events)} recent queries", events
    except subprocess.TimeoutExpired:
        return False, "DNS log: limited (timeout)", []
    except Exception as e:
        return False, f"DNS log: limited ({str(e)[:120]})", []


def refresh(force: bool = False) -> dict[str, Any]:
    """Fallback poll. Skipped while helper is connected (unless force)."""
    mod = _helper_mod()
    helper_on = False
    if mod is not None:
        try:
            helper_on = bool(mod.status().get("connected"))
        except Exception:
            helper_on = False
        if helper_on:
            try:
                ingest_helper_events(mod.drain_events())
            except Exception:
                pass
            try:
                mod.drain_tcp_events()
            except Exception:
                pass
            if not force:
                return status()
    now = time.time()
    with _lock:
        if not force and (now - float(_state["last_query_at"] or 0)) < REFRESH_SEC:
            return status()
        _state["last_query_at"] = now
    ok, message, events = _fetch_win_events()
    with _lock:
        if not helper_on:
            _state["queries"].clear()
            for ev in events[:MAX_EVENTS]:
                ev = dict(ev)
                ev["source"] = "poll"
                _state["queries"].append(ev)
            _rebuild_indexes_locked()
            _state["ok"] = ok
            _state["limited"] = not ok
            _state["live"] = False
            _state["message"] = message
            _state["source"] = "poll"
            _state["error"] = None if ok else message
            _state["last_query_at"] = time.time()
    return status()


def _pull_helper() -> bool:
    mod = _helper_mod()
    if mod is None:
        return False
    try:
        st = mod.status()
        if not st.get("connected"):
            try:
                mod.try_connect(timeout=0.2)
                st = mod.status()
            except Exception:
                pass
        if not st.get("connected"):
            return False
        ingest_helper_events(mod.drain_events())
        try:
            mod.drain_tcp_events()
        except Exception:
            pass
        with _lock:
            _state["live"] = True
            _state["limited"] = False
            _state["ok"] = True
            _state["source"] = "helper"
            if not _state["queries"]:
                _state["message"] = "DNS log: live (no recent queries)"
        return True
    except Exception:
        return False


def _worker() -> None:
    time.sleep(1.5)
    mod = _helper_mod()
    if mod is not None:
        try:
            mod.start_background()
        except Exception:
            pass
    while True:
        try:
            if _pull_helper():
                time.sleep(0.5)
                continue
            refresh(force=True)
        except Exception:
            pass
        time.sleep(REFRESH_SEC)


def start_background() -> None:
    global _worker_started
    with _lock:
        if _worker_started:
            return
        _worker_started = True
    threading.Thread(target=_worker, name="tw-dns-log", daemon=True).start()


def attach_dns_queries(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach recent DNS query names onto connections when IP/hostname matches."""
    with _lock:
        by_ip = dict(_state["by_ip"])
        queries = list(_state["queries"])
    for r in rows:
        names: list[str] = []
        rip = r.get("remote_ip")
        if rip and rip in by_ip:
            names.extend(by_ip[rip])
        host = (r.get("hostname") or "").strip().rstrip(".").lower()
        if host:
            for ev in queries:
                q = (ev.get("name") or "").strip().rstrip(".").lower()
                if q and (q == host or host.endswith("." + q) or q.endswith("." + host)):
                    if ev.get("name") and ev["name"] not in names:
                        names.append(ev["name"])
        if names:
            r["dns_queries"] = names[:5]
    return rows


def queries() -> list[dict[str, Any]]:
    """Copy of recent DNS query events (best-effort)."""
    with _lock:
        return list(_state.get("queries") or [])
