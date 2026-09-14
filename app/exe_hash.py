"""SHA-256 of executables, cached by path+mtime+size (Tier 0).

Never uploads hashes. Cache lives under data/ (sqlite). Signals:
  - new_binary_network: hash never seen with network access
  - hash_changed_same_publisher: same path/signer, different hash
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import time
from typing import Any

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.normpath(os.path.join(ROOT, "..", "data"))
DB_PATH = os.path.join(DATA_DIR, "exe_hash.sqlite")

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None
_mem: dict[str, dict[str, Any]] = {}
_initialized = False
_path_last: dict[str, dict[str, Any]] = {}


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
            CREATE TABLE IF NOT EXISTS exe_hash (
                cache_key TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                mtime REAL NOT NULL,
                size INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                checked_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS hash_network (
                sha256 TEXT PRIMARY KEY,
                first_net_ts REAL NOT NULL,
                last_net_ts REAL NOT NULL,
                hit_count INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS path_hash_hist (
                path TEXT NOT NULL,
                publisher TEXT NOT NULL DEFAULT '',
                sha256 TEXT NOT NULL,
                first_ts REAL NOT NULL,
                last_ts REAL NOT NULL,
                PRIMARY KEY (path, sha256)
            );
            CREATE INDEX IF NOT EXISTS idx_exe_hash_path ON exe_hash(path);
            """
        )
        c.commit()
        for row in c.execute(
            "SELECT cache_key, path, mtime, size, sha256, checked_at FROM exe_hash "
            "ORDER BY checked_at DESC LIMIT 8000"
        ):
            _mem[row["cache_key"]] = {
                "path": row["path"],
                "mtime": float(row["mtime"]),
                "size": int(row["size"]),
                "sha256": row["sha256"],
                "checked_at": float(row["checked_at"]),
            }
        for row in c.execute(
            "SELECT path, publisher, sha256, last_ts FROM path_hash_hist "
            "ORDER BY last_ts DESC LIMIT 4000"
        ):
            p = (row["path"] or "").lower()
            if p and p not in _path_last:
                _path_last[p] = {
                    "sha256": row["sha256"],
                    "publisher": row["publisher"] or "",
                    "last_ts": float(row["last_ts"]),
                }
        _initialized = True


def _cache_key(path: str, mtime: float, size: int) -> str:
    return f"{path.lower()}|{mtime:.3f}|{size}"


def _hash_file(path: str) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def get_hash(path: str | None) -> dict[str, Any] | None:
    """Return {sha256, short, mtime, size} for path; compute+cache on miss."""
    if not path:
        return None
    init()
    try:
        st = os.stat(path)
    except OSError:
        return None
    mtime = float(st.st_mtime)
    size = int(st.st_size)
    key = _cache_key(path, mtime, size)
    with _lock:
        hit = _mem.get(key)
        if hit:
            sha = hit["sha256"]
            return {
                "sha256": sha,
                "short": sha[:12],
                "mtime": mtime,
                "size": size,
                "cached": True,
            }
    sha = _hash_file(path)
    if not sha:
        return None
    now = time.time()
    with _lock:
        _mem[key] = {
            "path": path,
            "mtime": mtime,
            "size": size,
            "sha256": sha,
            "checked_at": now,
        }
        try:
            c = _connect()
            c.execute(
                """
                INSERT INTO exe_hash(cache_key, path, mtime, size, sha256, checked_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET checked_at=excluded.checked_at
                """,
                (key, path, mtime, size, sha, now),
            )
            c.commit()
        except Exception:
            pass
    return {
        "sha256": sha,
        "short": sha[:12],
        "mtime": mtime,
        "size": size,
        "cached": False,
    }


def hash_seen_with_network(sha: str | None) -> bool:
    if not sha:
        return False
    init()
    with _lock:
        try:
            c = _connect()
            row = c.execute(
                "SELECT 1 FROM hash_network WHERE sha256=?", (sha,)
            ).fetchone()
            return row is not None
        except Exception:
            return False


def note_network_hash(sha: str | None) -> None:
    if not sha:
        return
    init()
    now = time.time()
    with _lock:
        try:
            c = _connect()
            c.execute(
                """
                INSERT INTO hash_network(sha256, first_net_ts, last_net_ts, hit_count)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(sha256) DO UPDATE SET
                    last_net_ts=excluded.last_net_ts,
                    hit_count=hash_network.hit_count + 1
                """,
                (sha, now, now),
            )
            c.commit()
        except Exception:
            pass


def note_path_hash(
    path: str | None, sha: str | None, publisher: str | None
) -> dict[str, Any] | None:
    """Record path+publisher+hash. Return change info if hash changed same publisher."""
    if not path or not sha:
        return None
    init()
    pub = (publisher or "").strip()
    pl = path.lower()
    now = time.time()
    changed = None
    with _lock:
        prev = _path_last.get(pl)
        if prev and prev.get("sha256") and prev["sha256"] != sha:
            prev_pub = (prev.get("publisher") or "").strip()
            if prev_pub.lower() == pub.lower() or (not prev_pub and not pub):
                changed = {
                    "prev_sha256": prev["sha256"],
                    "prev_short": prev["sha256"][:12],
                    "sha256": sha,
                    "short": sha[:12],
                    "publisher": pub,
                }
        _path_last[pl] = {"sha256": sha, "publisher": pub, "last_ts": now}
        try:
            c = _connect()
            c.execute(
                """
                INSERT INTO path_hash_hist(path, publisher, sha256, first_ts, last_ts)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(path, sha256) DO UPDATE SET
                    last_ts=excluded.last_ts,
                    publisher=excluded.publisher
                """,
                (pl, pub, sha, now, now),
            )
            c.commit()
        except Exception:
            pass
    return changed


def trust_tuple(path: str | None, publisher: str | None, sha: str | None) -> str:
    """Canonical trust key: path + signer + hash."""
    p = (path or "").strip().lower()
    s = (publisher or "").strip().lower()
    h = (sha or "").strip().lower()
    return f"{p}|{s}|{h}"
