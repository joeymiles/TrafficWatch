"""Async reverse-DNS cache — never blocks the poll loop."""
from __future__ import annotations

import socket
import threading
from typing import Any

_cache: dict[str, str | None] = {}
_inflight: set[str] = set()
_lock = threading.Lock()
_MAX = 4000


def get_cached(ip: str | None) -> str | None:
    if not ip:
        return None
    with _lock:
        return _cache.get(ip)


def _worker(ip: str) -> None:
    name: str | None = None
    try:
        host, _alias, _addrs = socket.gethostbyaddr(ip)
        name = host
    except Exception:
        name = None
    with _lock:
        if len(_cache) > _MAX:
            # drop arbitrary oldest-ish half
            for k in list(_cache.keys())[: _MAX // 2]:
                _cache.pop(k, None)
        _cache[ip] = name
        _inflight.discard(ip)


def request(ip: str | None) -> str | None:
    """Return cached hostname if any; kick off async resolve otherwise."""
    if not ip:
        return None
    with _lock:
        if ip in _cache:
            return _cache[ip]
        if ip in _inflight:
            return None
        _inflight.add(ip)
    t = threading.Thread(target=_worker, args=(ip,), daemon=True, name=f"rdns-{ip}")
    t.start()
    return None


def attach_hostnames(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for r in rows:
        rip = r.get("remote_ip")
        if not rip or r.get("private_remote"):
            r["hostname"] = None
            continue
        cached = get_cached(rip)
        if cached is not None:
            r["hostname"] = cached
        else:
            r["hostname"] = None
            request(rip)
    return rows

