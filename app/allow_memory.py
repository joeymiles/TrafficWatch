"""Per-program allow memory with aging (Tier 0).

Entries: (proc identity, ASN/host, port) expire after 30 days unused.
Used to soften first-seen noise when a destination was recently allowed.
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from typing import Any

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.normpath(os.path.join(ROOT, "..", "data"))
DB_PATH = os.path.join(DATA_DIR, "allow_memory.sqlite")

AGE_DAYS = 30
AGE_SEC = AGE_DAYS * 86400.0

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None
_mem: dict[tuple[str, str, int], float] = {}  # (proc, dest, port) -> last_ts
_initialized = False


def _connect() -> sqlite3.Connection:
    global _conn
    os.makedirs(DATA_DIR, exist_ok=True)
    if _conn is None:
        c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=5.0)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        _conn = c
    return _conn


def init() -> None:
    global _initialized
    with _lock:
        if _initialized:
            return
        c = _connect()
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS allow_mem (
                proc_id TEXT NOT NULL,
                dest_key TEXT NOT NULL,
                port INTEGER NOT NULL,
                first_ts REAL NOT NULL,
                last_ts REAL NOT NULL,
                PRIMARY KEY (proc_id, dest_key, port)
            );
            CREATE INDEX IF NOT EXISTS idx_allow_last ON allow_mem(last_ts);
            """
        )
        c.commit()
        cutoff = time.time() - AGE_SEC
        c.execute("DELETE FROM allow_mem WHERE last_ts < ?", (cutoff,))
        c.commit()
        for row in c.execute(
            "SELECT proc_id, dest_key, port, last_ts FROM allow_mem "
            "ORDER BY last_ts DESC LIMIT 20000"
        ):
            _mem[(row["proc_id"], row["dest_key"], int(row["port"]))] = float(row["last_ts"])
        _initialized = True


def _proc_id(exe: str | None, name: str | None, sha: str | None) -> str:
    if sha:
        path = (exe or "").strip().lower()
        return f"{path}|{sha[:16]}"
    path = (exe or "").strip().lower()
    if path:
        return path
    return f"name:{(name or '').strip().lower()}"


def _dest_key(asn: str | None, host: str | None, ip: str | None) -> str:
    if asn and str(asn).strip():
        return f"asn:{str(asn).strip()}"
    if host and str(host).strip():
        return f"host:{str(host).strip().lower()[:200]}"
    if ip:
        return f"ip:{ip}"
    return "unknown"


def note(
    *,
    exe: str | None,
    name: str | None,
    sha: str | None,
    asn: str | None,
    host: str | None,
    ip: str | None,
    port: int | None,
) -> None:
    if port is None:
        return
    init()
    try:
        port_i = int(port)
    except (TypeError, ValueError):
        return
    pid = _proc_id(exe, name, sha)
    dk = _dest_key(asn, host, ip)
    now = time.time()
    key = (pid, dk, port_i)
    with _lock:
        _mem[key] = now
        try:
            c = _connect()
            c.execute(
                """
                INSERT INTO allow_mem(proc_id, dest_key, port, first_ts, last_ts)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(proc_id, dest_key, port) DO UPDATE SET last_ts=excluded.last_ts
                """,
                (pid, dk, port_i, now, now),
            )
            c.commit()
        except Exception:
            pass


def is_allowed(
    *,
    exe: str | None,
    name: str | None,
    sha: str | None,
    asn: str | None,
    host: str | None,
    ip: str | None,
    port: int | None,
) -> bool:
    if port is None:
        return False
    init()
    try:
        port_i = int(port)
    except (TypeError, ValueError):
        return False
    pid = _proc_id(exe, name, sha)
    dk = _dest_key(asn, host, ip)
    key = (pid, dk, port_i)
    with _lock:
        ts = _mem.get(key)
        if ts is None:
            return False
        if time.time() - ts > AGE_SEC:
            _mem.pop(key, None)
            return False
        return True


def prune() -> int:
    init()
    cutoff = time.time() - AGE_SEC
    with _lock:
        dead = [k for k, ts in _mem.items() if ts < cutoff]
        for k in dead:
            _mem.pop(k, None)
        try:
            c = _connect()
            cur = c.execute("DELETE FROM allow_mem WHERE last_ts < ?", (cutoff,))
            c.commit()
            return int(cur.rowcount or 0) + len(dead)
        except Exception:
            return len(dead)


def summary() -> dict[str, Any]:
    init()
    with _lock:
        return {"ok": True, "entries": len(_mem), "age_days": AGE_DAYS}
