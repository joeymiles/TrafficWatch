"""Live TCP/UDP connection polling via psutil (Windows-friendly).

Rates (documented for UI/NOTES):
- System totals: psutil.net_io_counters() on all NICs (bytes sent/recv delta / dt).
  These are true interface counters — closest to "real" up/down.
- Per-process network: Process.net_io_counters() when available (bytes sent/recv).
  On Windows this is often missing — then per-process network rates are None
  (exfil_ish skips rather than using disk write_bytes).
- Disk IO (io_counters write_bytes) may still be collected as proc_write_bytes but
  is NOT used for bytes_out_rate / exfil (Review 4).
- Per-row share: process network rate divided by live connection count when known.
- Helper TCP (elevated): per-connection bytes_in/out + duration when Status -> Enable live DNS
  has started the helper; direction_basis becomes confirmed (connect/accept).
- EMA smoothing (~0.35) so the UI does not jump wildly between polls.
"""
from __future__ import annotations

import re
import socket
import time
from typing import Any

import psutil

# Windows ephemeral range (IANA dynamic) + common high ports
_EPHEMERAL_MIN = 49152
_WELL_KNOWN_MAX = 1023

# EMA alpha for rate smoothing (higher = more responsive, lower = smoother)
_EMA_ALPHA = 0.35

_prev_proc_io: dict[int, tuple[float, int, int]] = {}
_ema_proc: dict[int, tuple[float, float]] = {}  # pid -> (in_rate, out_rate)
_prev_sys_io: tuple[float, int, int] | None = None
_ema_sys: tuple[float, float] = (0.0, 0.0)  # (in_rate, out_rate)


def _safe_proc_name(pid: int | None, cache: dict[int, str] | None = None) -> str:
    if not pid or pid <= 0:
        return "?"
    if cache is not None and pid in cache:
        return cache[pid]
    try:
        name = psutil.Process(pid).name()
    except (psutil.Error, ValueError, OSError):
        name = "?"
    if cache is not None:
        cache[pid] = name
    return name


def _family_name(family: int) -> str:
    if family == socket.AF_INET:
        return "IPv4"
    if family == socket.AF_INET6:
        return "IPv6"
    return str(family)


def _is_private_or_local(ip: str) -> bool:
    if not ip:
        return True
    ip = ip.split("%")[0]  # strip IPv6 zone
    if ip in ("127.0.0.1", "::1", "0.0.0.0", "::", "*"):
        return True
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("169.254."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return True
        except (ValueError, IndexError):
            pass
    if ip.startswith("fc") or ip.startswith("fd") or ip.startswith("fe80"):
        return True
    return False


def _collect_listening_ports(conns: list) -> set[tuple[str | None, int | None]]:
    """Local (ip, port) pairs that are LISTEN — used for inbound heuristic."""
    listening: set[tuple[str | None, int | None]] = set()
    for c in conns:
        try:
            status = (c.status or "").upper() if hasattr(c, "status") and c.status else ""
            if status != "LISTEN":
                continue
            laddr = c.laddr
            if not laddr:
                continue
            lip = getattr(laddr, "ip", None) or (laddr[0] if laddr else None)
            lport = getattr(laddr, "port", None) or (laddr[1] if laddr and len(laddr) > 1 else None)
            if lip and str(lip).startswith("::ffff:"):
                lip = str(lip)[7:]
            listening.add((lip, lport))
            # Also match by port alone (any interface)
            listening.add((None, lport))
        except Exception:
            continue
    return listening


def _infer_direction(
    *,
    proto: str,
    status: str,
    lip: str | None,
    lport: int | None,
    rip: str | None,
    rport: int | None,
    listening: set[tuple[str | None, int | None]],
) -> tuple[str, str]:
    """Inbound / outbound / listen heuristic.

    Returns (direction, basis) where basis is:
      - confirmed: remote hit a known local LISTEN port this snapshot
      - guess: port / private heuristics (no matching listener)
      - listen: local LISTEN / no remote
    """
    if not rip:
        return "listen", "listen"

    # Remote connected to a port we are listening on -> inbound (confirmed)
    if (lip, lport) in listening or (None, lport) in listening:
        return "inbound", "confirmed"

    # Privileged local port + non-ephemeral remote often means we are the server
    if lport is not None and lport <= _WELL_KNOWN_MAX:
        if rport is None or rport >= _EPHEMERAL_MIN or rport > _WELL_KNOWN_MAX:
            return "inbound", "guess"

    # Local ephemeral + remote set -> classic client outbound
    if lport is not None and lport >= _EPHEMERAL_MIN and rip:
        return "outbound", "guess"

    # Local high port (1024-49151) with remote well-known -> likely outbound client
    if lport is not None and lport > _WELL_KNOWN_MAX and rip:
        if rport is not None and rport <= _WELL_KNOWN_MAX:
            return "outbound", "guess"
        if rport is not None and rport >= _EPHEMERAL_MIN:
            if lport >= 10000:
                return "outbound", "guess"

    # Private remote while local is public-ish -> treat as inbound (LAN peer)
    if rip and _is_private_or_local(rip) and lip and not _is_private_or_local(lip):
        return "inbound", "guess"

    return "outbound", "guess"


def collect_connections(include_udp: bool = True) -> tuple[list[dict[str, Any]], bool]:
    """Return a snapshot of network connections with process names."""
    seen: set[tuple] = set()
    rows: list[dict[str, Any]] = []
    admin_limited = False

    try:
        conns = list(psutil.net_connections(kind="inet"))
    except (psutil.AccessDenied, PermissionError):
        admin_limited = True
        conns = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                meth = getattr(proc, "net_connections", None) or proc.connections
                for c in meth(kind="inet"):
                    conns.append(c)
            except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError):
                continue

    listening = _collect_listening_ports(conns)
    # Per-snapshot PID name cache (avoid psutil.Process() per row when pid repeats)
    name_by_pid: dict[int, str] = {}

    # Process network totals (preferred) + disk IO (unused for exfil; Review 4)
    proc_io: dict[int, dict[str, int | None]] = {}
    for proc in psutil.process_iter(["pid"]):
        try:
            entry: dict[str, int | None] = {
                "read_bytes": None,
                "write_bytes": None,
                "net_bytes_recv": None,
                "net_bytes_sent": None,
                "network_ok": 0,
            }
            try:
                io = proc.io_counters()
                if io is not None and hasattr(io, "read_bytes"):
                    entry["read_bytes"] = int(getattr(io, "read_bytes", 0) or 0)
                    entry["write_bytes"] = int(getattr(io, "write_bytes", 0) or 0)
            except (psutil.Error, AttributeError, OSError):
                pass
            # True network counters when psutil exposes them (often missing on Windows)
            try:
                nio = getattr(proc, "net_io_counters", None)
                if callable(nio):
                    net = nio()
                else:
                    net = None
                if net is not None:
                    entry["net_bytes_recv"] = int(getattr(net, "bytes_recv", 0) or 0)
                    entry["net_bytes_sent"] = int(getattr(net, "bytes_sent", 0) or 0)
                    entry["network_ok"] = 1
            except (psutil.Error, AttributeError, OSError, TypeError):
                pass
            proc_io[proc.pid] = entry
        except (psutil.Error, AttributeError, OSError):
            continue

    for c in conns:
        try:
            status = (c.status or "").upper() if hasattr(c, "status") and c.status else "NONE"
            family = _family_name(c.family)
            laddr = c.laddr
            raddr = c.raddr
            if not laddr:
                continue
            lip = getattr(laddr, "ip", None) or (laddr[0] if laddr else None)
            lport = getattr(laddr, "port", None) or (laddr[1] if laddr and len(laddr) > 1 else None)
            rip = None
            rport = None
            if raddr:
                rip = getattr(raddr, "ip", None) or (raddr[0] if raddr else None)
                rport = getattr(raddr, "port", None) or (raddr[1] if raddr and len(raddr) > 1 else None)

            if rip and str(rip).startswith("::ffff:"):
                rip = str(rip)[7:]
            if lip and str(lip).startswith("::ffff:"):
                lip = str(lip)[7:]

            proto = "TCP"
            if c.type == socket.SOCK_DGRAM:
                proto = "UDP"
                if not status or status == "NONE":
                    status = "UDP"

            pid = c.pid
            key = (proto, lip, lport, rip, rport, pid, status)
            if key in seen:
                continue
            seen.add(key)

            direction, direction_basis = _infer_direction(
                proto=proto,
                status=status,
                lip=lip,
                lport=lport,
                rip=rip,
                rport=rport,
                listening=listening,
            )

            io = proc_io.get(pid or -1, {})
            # Tier 0: UDP/443 labelled QUIC; count as HTTPS-class for rules
            proto_label = proto
            https_class = False
            if proto == "UDP" and (rport == 443 or lport == 443):
                proto_label = "QUIC"
                https_class = True
            elif proto == "TCP" and (rport in (443, 8443) or lport in (443, 8443)):
                https_class = True
            elif proto == "TCP" and rport == 80:
                https_class = False
            rows.append(
                {
                    "proto": proto,
                    "proto_label": proto_label,
                    "https_class": https_class,
                    "status": status,
                    "family": family,
                    "local_ip": lip,
                    "local_port": lport,
                    "remote_ip": rip,
                    "remote_port": rport,
                    "pid": pid,
                    "process": _safe_proc_name(pid, name_by_pid),
                    "direction": direction,
                    "direction_basis": direction_basis,
                    "private_remote": _is_private_or_local(rip or ""),
                    "proc_read_bytes": io.get("read_bytes"),
                    "proc_write_bytes": io.get("write_bytes"),
                    "proc_net_bytes_recv": io.get("net_bytes_recv"),
                    "proc_net_bytes_sent": io.get("net_bytes_sent"),
                    "network_out_ok": bool(io.get("network_ok")),
                }
            )
        except Exception:
            continue

    return rows, admin_limited


def _ema(prev: float, raw: float, alpha: float = _EMA_ALPHA) -> float:
    if prev <= 0:
        return raw
    return alpha * raw + (1.0 - alpha) * prev



# Helper TCP flow EMA: 4-tuple -> (ts, bytes_in, bytes_out)
_prev_helper_flow: dict[str, tuple[float, int, int]] = {}
_ema_helper_flow: dict[str, tuple[float, float]] = {}
_ema_helper_proc: dict[int, tuple[float, float]] = {}


def _helper_tcp_match(row: dict[str, Any], flows: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    """Best-effort match helper TCP flow to a psutil connection row."""
    if not flows:
        return None
    lip = row.get("local_ip")
    lport = row.get("local_port")
    rip = row.get("remote_ip")
    rport = row.get("remote_port")
    pid = row.get("pid")
    candidates = [
        f"{lip}|{lport}|{rip}|{rport}",
        f"|{lport}|{rip}|{rport}",
        f"{pid}|{rip}|{rport}",
    ]
    for k in candidates:
        hit = flows.get(k)
        if hit and not hit.get("closed"):
            return hit
    if pid and rip:
        soft = f"{pid}|{rip}|"
        hit = flows.get(soft)
        if hit and not hit.get("closed"):
            if rport is None or hit.get("remote_port") in (None, rport):
                return hit
    return None


def attach_helper_tcp(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge elevated-helper TCP flows into connection rows.

    connect -> outbound confirmed; accept -> inbound confirmed.
    Attach conn_bytes_in/out, duration_ms, helper rate EMA when present.
    Never raises; helper missing => unchanged (direction stays guess).
    """
    global _prev_helper_flow, _ema_helper_flow, _ema_helper_proc
    try:
        import helper_ipc

        try:
            helper_ipc.drain_tcp_events()
        except Exception:
            pass
        flows = helper_ipc.tcp_flow_index()
        st = helper_ipc.status()
    except Exception:
        for r in rows:
            r.setdefault("helper_tcp", False)
        return rows

    helper_on = bool(st.get("connected")) and bool(st.get("tcp"))
    now = time.time()
    proc_out: dict[int, float] = {}
    proc_in: dict[int, float] = {}

    for r in rows:
        r.setdefault("conn_bytes_in", None)
        r.setdefault("conn_bytes_out", None)
        r.setdefault("duration_ms", None)
        r.setdefault("helper_tcp", False)
        if (r.get("proto") or "").upper() != "TCP":
            continue
        if not helper_on:
            continue
        hit = _helper_tcp_match(r, flows)
        if not hit:
            continue
        r["helper_tcp"] = True
        direction = hit.get("dir")
        if direction == "accept":
            r["direction"] = "inbound"
            r["direction_basis"] = "confirmed"
        elif direction == "connect":
            r["direction"] = "outbound"
            r["direction_basis"] = "confirmed"
        try:
            bi = hit.get("bytes_in")
            bo = hit.get("bytes_out")
            if bi is not None:
                r["conn_bytes_in"] = int(bi)
            if bo is not None:
                r["conn_bytes_out"] = int(bo)
        except (TypeError, ValueError):
            pass
        if hit.get("duration_ms") is not None:
            try:
                r["duration_ms"] = int(hit.get("duration_ms"))
            except (TypeError, ValueError):
                pass

        key = f"{r.get('local_ip')}|{r.get('local_port')}|{r.get('remote_ip')}|{r.get('remote_port')}"
        try:
            bi = int(r.get("conn_bytes_in") or 0)
            bo = int(r.get("conn_bytes_out") or 0)
        except (TypeError, ValueError):
            continue
        prev = _prev_helper_flow.get(key)
        raw_in = raw_out = None
        if prev:
            pt, pbi, pbo = prev
            dt = now - pt
            if dt > 0.2:
                raw_in = max(0.0, (bi - pbi) / dt)
                raw_out = max(0.0, (bo - pbo) / dt)
        _prev_helper_flow[key] = (now, bi, bo)
        if raw_in is not None:
            ein_p, eout_p = _ema_helper_flow.get(key, (0.0, 0.0))
            ein = _ema(ein_p, raw_in)
            eout = _ema(eout_p, raw_out or 0.0)
            _ema_helper_flow[key] = (ein, eout)
            r["bytes_in_rate"] = ein
            r["bytes_out_rate"] = eout
            r["bytes_in_rate_share"] = ein
            r["bytes_out_rate_share"] = eout
            r["rate_source"] = "helper_tcp"
            r["network_out_ok"] = True
            pid = r.get("pid")
            if pid:
                proc_in[pid] = proc_in.get(pid, 0.0) + ein
                proc_out[pid] = proc_out.get(pid, 0.0) + eout

    for pid, eout in proc_out.items():
        ein = proc_in.get(pid, 0.0)
        _ema_helper_proc[pid] = (ein, eout)

    live_keys = {
        f"{r.get('local_ip')}|{r.get('local_port')}|{r.get('remote_ip')}|{r.get('remote_port')}"
        for r in rows
        if r.get("helper_tcp")
    }
    _prev_helper_flow = {k: v for k, v in _prev_helper_flow.items() if k in live_keys}
    _ema_helper_flow = {k: v for k, v in _ema_helper_flow.items() if k in live_keys}
    return rows


def system_rates() -> dict[str, float | None]:
    """Smoothed NIC-level total up/down (bytes/sec)."""
    global _prev_sys_io, _ema_sys
    now = time.time()
    try:
        io = psutil.net_io_counters()
        rb = int(io.bytes_recv)
        wb = int(io.bytes_sent)
    except Exception:
        return {
            "bytes_in_rate": _ema_sys[0] or None,
            "bytes_out_rate": _ema_sys[1] or None,
        }

    raw_in = raw_out = 0.0
    if _prev_sys_io is not None:
        pt, pr, pw = _prev_sys_io
        dt = now - pt
        if dt > 0.2:
            raw_in = max(0.0, (rb - pr) / dt)
            raw_out = max(0.0, (wb - pw) / dt)
            _ema_sys = (_ema(_ema_sys[0], raw_in), _ema(_ema_sys[1], raw_out))
    _prev_sys_io = (now, rb, wb)
    return {
        "bytes_in_rate": _ema_sys[0],
        "bytes_out_rate": _ema_sys[1],
    }


def attach_rates(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach smoothed per-process NETWORK rates + per-connection share estimates.

    Review 4: use Process.net_io_counters when present. Never feed disk write_bytes
    into bytes_out_rate / exfil. If network counters missing (common on Windows),
    leave rates None (exfil_ish skips).
    """
    now = time.time()
    global _prev_proc_io, _ema_proc

    pid_counts: dict[int, int] = {}
    for r in rows:
        pid = r.get("pid")
        if pid:
            pid_counts[pid] = pid_counts.get(pid, 0) + 1

    for r in rows:
        pid = r.get("pid")
        # Preserve helper_tcp rates if already attached
        if r.get("rate_source") == "helper_tcp" and (
            r.get("bytes_out_rate") is not None or r.get("bytes_in_rate") is not None
        ):
            continue
        r["bytes_in_rate"] = None
        r["bytes_out_rate"] = None
        r["bytes_in_rate_share"] = None
        r["bytes_out_rate_share"] = None
        r["rate_source"] = "none"
        if pid is None:
            continue

        # Prefer real network counters (process); helper_tcp handled above
        rb = r.get("proc_net_bytes_recv")
        wb = r.get("proc_net_bytes_sent")
        network_ok = bool(r.get("network_out_ok")) and rb is not None and wb is not None
        if not network_ok:
            # Do NOT fall back to disk io_counters write_bytes for outbound rate
            continue

        raw_in = raw_out = None
        prev = _prev_proc_io.get(pid)
        if prev:
            pt, pr, pw = prev
            dt = now - pt
            if dt > 0.2:
                raw_in = max(0.0, (int(rb) - pr) / dt)
                raw_out = max(0.0, (int(wb) - pw) / dt)

        _prev_proc_io[pid] = (now, int(rb), int(wb))

        if raw_in is None:
            if pid in _ema_proc:
                ein, eout = _ema_proc[pid]
                r["bytes_in_rate"] = ein
                r["bytes_out_rate"] = eout
                r["rate_source"] = "process_net_ema"
                r["network_out_ok"] = True
            continue

        ein_prev, eout_prev = _ema_proc.get(pid, (0.0, 0.0))
        ein = _ema(ein_prev, raw_in)
        eout = _ema(eout_prev, raw_out)
        _ema_proc[pid] = (ein, eout)
        r["bytes_in_rate"] = ein
        r["bytes_out_rate"] = eout
        r["rate_source"] = "process_net_ema"
        r["network_out_ok"] = True
        n = max(1, pid_counts.get(pid, 1))
        r["bytes_in_rate_share"] = ein / n
        r["bytes_out_rate_share"] = eout / n

    live = {r.get("pid") for r in rows if r.get("pid")}
    _prev_proc_io = {k: v for k, v in _prev_proc_io.items() if k in live}
    _ema_proc = {k: v for k, v in _ema_proc.items() if k in live}
    return rows


def top_talkers(rows: list[dict[str, Any]], n: int = 5) -> list[dict[str, Any]]:
    """Aggregate by process using smoothed rates; prefer helper_tcp when present.

    Returns [] when no real per-process rates exist (UI shows helper-needed, not 0 B/s).
    """
    by_pid: dict[int, dict[str, Any]] = {}
    for r in rows:
        pid = r.get("pid")
        if not pid:
            continue
        bi = r.get("bytes_in_rate")
        bo = r.get("bytes_out_rate")
        if bi is None and bo is None:
            continue
        src = r.get("rate_source") or "none"
        if pid not in by_pid:
            by_pid[pid] = {
                "pid": pid,
                "process": r.get("process") or "?",
                "bytes_in_rate": 0.0,
                "bytes_out_rate": 0.0,
                "connections": 0,
                "rate_source": src,
            }
        by_pid[pid]["connections"] += 1
        if src == "helper_tcp":
            by_pid[pid]["rate_source"] = "helper_tcp"
            by_pid[pid]["bytes_in_rate"] += float(bi or 0.0)
            by_pid[pid]["bytes_out_rate"] += float(bo or 0.0)
        elif by_pid[pid].get("rate_source") != "helper_tcp":
            # process_net_ema is already per-PID; keep latest
            by_pid[pid]["bytes_in_rate"] = float(bi or 0.0)
            by_pid[pid]["bytes_out_rate"] = float(bo or 0.0)
            by_pid[pid]["rate_source"] = src

    ranked = sorted(
        by_pid.values(),
        key=lambda x: (x["bytes_in_rate"] or 0) + (x["bytes_out_rate"] or 0),
        reverse=True,
    )
    ranked = [
        x for x in ranked
        if (x.get("bytes_in_rate") or 0) + (x.get("bytes_out_rate") or 0) > 0.5
    ]
    return ranked[:n]


def rates_status(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Whether per-connection rates are available (for UI helper-needed chip)."""
    helper = False
    any_rate = False
    for r in rows:
        if r.get("rate_source") == "helper_tcp":
            helper = True
        if r.get("bytes_in_rate") is not None or r.get("bytes_out_rate") is not None:
            any_rate = True
    return {
        "per_conn_available": any_rate,
        "helper_tcp": helper,
        "helper_needed": (not any_rate),
    }


# --- Process inspect / kill (desktop UI) ---------------------------------

_CRITICAL_PIDS = {0, 4}
_CRITICAL_NAMES = {
    "system",
    "registry",
    "idle",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "svchost.exe",
    "fontdrvhost.exe",
    "dwm.exe",
    "memory compression",
}


def is_critical_process(pid: int | None, name: str | None = None) -> tuple[bool, str]:
    """Return (blocked, reason). Hard-block OS-critical PIDs/names."""
    if pid is None:
        return True, "missing PID"
    if pid in _CRITICAL_PIDS:
        return True, f"PID {pid} is a critical system process"
    n = (name or _safe_proc_name(pid) or "").strip().lower()
    if n in _CRITICAL_NAMES:
        return True, f"{name or n} is a protected system process"
    # bare names without .exe
    bare = n[:-4] if n.endswith(".exe") else n
    if bare in {x[:-4] if x.endswith(".exe") else x for x in _CRITICAL_NAMES}:
        return True, f"{name or n} is a protected system process"
    return False, ""



# --- Command-line redaction (never persist secrets) ----------------------

_CMDLINE_MASK = "********"
_NEXT_SECRET_FLAGS = {
    "--password", "-password", "--pass", "-pass",
    "--token", "-token", "--api-key", "-api-key", "--apikey", "-apikey",
    "--secret", "-secret", "--access-token", "-access-token",
    "--authorization", "-authorization",
}
_EQ_SECRET_RE = re.compile(
    r"(?i)((?:--?)?(?:password|pass(?:word)?|token|api[-_]?key|secret|access[-_]?token|authorization)|(?:password|token|key|secret|authorization))=\S*"
)
_BEARER_RE = re.compile(r"(?i)\b(?:Authorization:\s*\S+(?:\s+\S+)?|Bearer\s+\S+)")
_URL_USERPASS_RE = re.compile(r"(://)([^/@\s]+):([^/@\s]+)@")
_LONG_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_LONG_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")


def _redact_token_text(s: str) -> tuple[str, bool]:
    """Mask secret-like substrings inside one argv token."""
    if not s:
        return s, False
    orig = s
    s = _URL_USERPASS_RE.sub(r"\1\2:" + _CMDLINE_MASK + "@", s)
    s = _BEARER_RE.sub(lambda m: ("Authorization: " if m.group(0).lower().startswith("authorization") else "Bearer ") + _CMDLINE_MASK, s)

    def _eq_sub(m: re.Match) -> str:
        return m.group(1) + "=" + _CMDLINE_MASK

    s = _EQ_SECRET_RE.sub(_eq_sub, s)
    s = _LONG_HEX_RE.sub(_CMDLINE_MASK, s)
    s = _LONG_B64_RE.sub(_CMDLINE_MASK, s)
    return s, s != orig


def redact_cmdline(parts: list | str | None) -> tuple[list | None, bool]:
    """Return (redacted argv list, did_redact). Never returns raw secrets."""
    if parts is None:
        return None, False
    if isinstance(parts, str):
        tokens = [parts]
    else:
        tokens = [str(x) for x in parts]
    out: list[str] = []
    did = False
    consume_next = False
    for tok in tokens:
        if consume_next:
            out.append(_CMDLINE_MASK)
            did = True
            consume_next = False
            continue
        low = tok.strip().lower()
        if low in _NEXT_SECRET_FLAGS:
            out.append(tok)
            consume_next = True
            continue
        new, changed = _redact_token_text(tok)
        if changed:
            did = True
        out.append(new)
    if consume_next:
        # flag with no value; nothing extra to mask
        pass
    return out, did


def process_cmdline_raw(pid: int) -> dict:
    """Reveal current cmdline for an authenticated caller. Never persist."""
    info = {"ok": False, "pid": pid, "cmdline": None, "persisted": False, "error": None}
    try:
        p = psutil.Process(pid)
        info["cmdline"] = p.cmdline()
        info["ok"] = True
        info["name"] = p.name()
    except psutil.NoSuchProcess:
        info["error"] = "process not found"
    except psutil.AccessDenied:
        info["error"] = "access denied (full command line needs process-level rights; do not run the whole app as administrator)"
    except Exception as e:
        info["error"] = str(e)[:200]
    return info


def _windows_version_info(exe: str | None) -> dict[str, str | None]:
    """Best-effort CompanyName / FileDescription via Win32 version resources."""
    out: dict[str, str | None] = {"company": None, "description": None, "product": None}
    if not exe:
        return out
    try:
        import ctypes
        from ctypes import wintypes

        version = ctypes.WinDLL("version")
        get_size = version.GetFileVersionInfoSizeW
        get_size.argtypes = [wintypes.LPCWSTR, wintypes.LPDWORD]
        get_size.restype = wintypes.DWORD
        get_info = version.GetFileVersionInfoW
        get_info.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID]
        get_info.restype = wintypes.BOOL
        ver_query = version.VerQueryValueW
        ver_query.argtypes = [
            wintypes.LPVOID,
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.UINT),
        ]
        ver_query.restype = wintypes.BOOL

        dummy = wintypes.DWORD(0)
        size = get_size(exe, ctypes.byref(dummy))
        if not size:
            return out
        buf = ctypes.create_string_buffer(size)
        if not get_info(exe, 0, size, buf):
            return out

        # Translation block
        lptr = ctypes.c_void_p()
        lsize = wintypes.UINT(0)
        if not ver_query(buf, r"\VarFileInfo\Translation", ctypes.byref(lptr), ctypes.byref(lsize)):
            return out
        if not lptr.value or lsize.value < 4:
            return out
        lang, codepage = ctypes.cast(lptr, ctypes.POINTER(wintypes.WORD))[0], ctypes.cast(
            lptr, ctypes.POINTER(wintypes.WORD)
        )[1]

        def _query(key: str) -> str | None:
            spath = rf"\StringFileInfo\{lang:04x}{codepage:04x}\{key}"
            sptr = ctypes.c_void_p()
            ssize = wintypes.UINT(0)
            if not ver_query(buf, spath, ctypes.byref(sptr), ctypes.byref(ssize)):
                return None
            if not sptr.value:
                return None
            return ctypes.wstring_at(sptr) or None

        out["company"] = _query("CompanyName")
        out["description"] = _query("FileDescription")
        out["product"] = _query("ProductName")
    except Exception:
        pass
    return out


def process_detail(pid: int, connection_rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Inspect a process: path, user, start time, publisher, related connections."""
    blocked, reason = is_critical_process(pid)
    info: dict[str, Any] = {
        "ok": True,
        "pid": pid,
        "critical": blocked,
        "critical_reason": reason or None,
        "name": None,
        "exe": None,
        "cmdline": None,
        "cmdline_redacted": False,
        "cmdline_can_reveal": False,
        "username": None,
        "create_time": None,
        "create_time_iso": None,
        "ppid": None,
        "status": None,
        "company": None,
        "description": None,
        "product": None,
        "bytes_in_rate": None,
        "bytes_out_rate": None,
        "connections": [],
        "destinations": [],
        "error": None,
    }
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            info["name"] = p.name()
            try:
                info["exe"] = p.exe()
            except (psutil.AccessDenied, psutil.Error):
                info["exe"] = None
            try:
                raw_cmd = p.cmdline()
                redacted, did_redact = redact_cmdline(raw_cmd)
                info["cmdline"] = redacted
                info["cmdline_redacted"] = bool(did_redact)
                info["cmdline_can_reveal"] = True
            except (psutil.AccessDenied, psutil.Error):
                info["cmdline"] = None
                info["cmdline_redacted"] = False
                info["cmdline_can_reveal"] = False
            try:
                info["username"] = p.username()
            except (psutil.AccessDenied, psutil.Error):
                info["username"] = None
            try:
                ct = p.create_time()
                info["create_time"] = ct
                info["create_time_iso"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ct))
            except (psutil.AccessDenied, psutil.Error):
                pass
            try:
                info["ppid"] = p.ppid()
            except (psutil.AccessDenied, psutil.Error):
                pass
            try:
                info["status"] = p.status()
            except (psutil.AccessDenied, psutil.Error):
                pass
        # Re-check critical with real name
        blocked2, reason2 = is_critical_process(pid, info.get("name"))
        info["critical"] = blocked2
        info["critical_reason"] = reason2 or None
        ver = _windows_version_info(info.get("exe"))
        info.update(ver)
    except psutil.NoSuchProcess:
        info["ok"] = False
        info["error"] = "process not found"
        return info
    except psutil.AccessDenied:
        info["error"] = "access denied (some details need process-level rights; keep the main app unelevated)"
        info["name"] = info["name"] or _safe_proc_name(pid)
    except Exception as e:
        info["ok"] = False
        info["error"] = str(e)
        return info

    rows = connection_rows or []
    related = [r for r in rows if r.get("pid") == pid]
    info["connections"] = related
    if related:
        info["bytes_in_rate"] = related[0].get("bytes_in_rate")
        info["bytes_out_rate"] = related[0].get("bytes_out_rate")
        info["name"] = info["name"] or related[0].get("process")

    # Destination summary
    dest: dict[str, dict[str, Any]] = {}
    for r in related:
        rip = r.get("remote_ip") or "(none)"
        key = f"{rip}|{r.get('country') or ''}"
        if key not in dest:
            dest[key] = {
                "remote_ip": r.get("remote_ip"),
                "hostname": r.get("hostname"),
                "country": r.get("country"),
                "city": r.get("city"),
                "count": 0,
                "ports": [],
            }
        dest[key]["count"] += 1
        rp = r.get("remote_port")
        if rp is not None and rp not in dest[key]["ports"]:
            dest[key]["ports"].append(rp)
    info["destinations"] = sorted(dest.values(), key=lambda d: d["count"], reverse=True)
    return info


def kill_process(pid: int, *, force: bool = False, confirm_name: str | None = None) -> dict[str, Any]:
    """Terminate (graceful) or kill (force) a process with critical-process guards."""
    name = _safe_proc_name(pid)
    blocked, reason = is_critical_process(pid, name)
    if blocked:
        return {"ok": False, "error": reason, "blocked": True, "pid": pid, "name": name}

    if confirm_name is not None:
        want = confirm_name.strip().lower()
        have = (name or "").strip().lower()
        if want and have and want != have and want != have.replace(".exe", ""):
            # also allow exact pid-only confirm via empty check elsewhere
            if want not in (have, have.replace(".exe", ""), f"{have} ({pid})".lower()):
                return {
                    "ok": False,
                    "error": f"confirm name mismatch (expected {name})",
                    "pid": pid,
                    "name": name,
                }

    try:
        p = psutil.Process(pid)
        real_name = p.name()
        blocked2, reason2 = is_critical_process(pid, real_name)
        if blocked2:
            return {"ok": False, "error": reason2, "blocked": True, "pid": pid, "name": real_name}
        if force:
            p.kill()
            action = "killed"
        else:
            p.terminate()
            action = "terminated"
        gone = False
        try:
            p.wait(timeout=2.5)
            gone = True
        except psutil.TimeoutExpired:
            if force:
                gone = False
            else:
                # graceful timed out — caller may retry with force
                gone = False
        except psutil.NoSuchProcess:
            gone = True
        return {
            "ok": True,
            "pid": pid,
            "name": real_name,
            "action": action,
            "gone": gone or (not psutil.pid_exists(pid)),
            "force": force,
        }
    except psutil.NoSuchProcess:
        return {"ok": True, "pid": pid, "name": name, "action": "already_gone", "gone": True}
    except psutil.AccessDenied:
        return {
            "ok": False,
            "error": "Access denied. Ending this process may need a separate elevated helper. Do not run the whole app as administrator.",
            "pid": pid,
            "name": name,
            "access_denied": True,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "pid": pid, "name": name}

