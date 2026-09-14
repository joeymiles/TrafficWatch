"""SQLite history for first-seen / remotes / listeners (Phase C).

Persists across restarts. In-memory cache in front; batch writes so snapshot
poll never blocks more than a tiny write. No personal home-street data.
"""
from __future__ import annotations

import hashlib
import json
import re
import os
import sqlite3
import threading
import time
from typing import Any

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.normpath(os.path.join(ROOT, "..", "data"))
DB_PATH = os.path.join(DATA_DIR, "history.sqlite")

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None
_initialized = False

# In-memory front caches (seeded from DB)
_proc_first: dict[str, float] = {}  # path -> first_ts
_remote_first: dict[tuple[str, int | None], float] = {}  # (ip, port) -> first_ts
_listen_first: dict[tuple[int, int | None], float] = {}  # (port, pid) -> first_ts
_beacon_intervals: dict[str, list[float]] = {}
_beacon_obs: dict[tuple[str, int], list[float]] = {}  # (ip, port) -> appearance timestamps

# Retention: prune events older than this many days on flush occasionally
RETENTION_DAYS = 21

# Pending batch upserts
_pending_procs: dict[str, tuple[int | None, float, float]] = {}  # path -> (pid, first, last)
_pending_remotes: dict[tuple[str, int | None], tuple[float, float, int]] = {}  # -> (first, last, delta)
_pending_listens: dict[tuple[int, int | None], float] = {}  # -> first_ts
_pending_events: list[tuple[float, str, str]] = []
_pending_alerts: dict[str, tuple[float, float, int, str, str]] = {}  # id -> (first, last, count, state, payload)
_flush_count = 0
_prune_counter = 0


def _connect() -> sqlite3.Connection:
    global _conn
    os.makedirs(DATA_DIR, exist_ok=True)
    if _conn is None:
        c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=5.0)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA temp_store=MEMORY")
        _conn = c
    return _conn


def init() -> None:
    """Create schema and seed in-memory caches from disk. Idempotent, fast."""
    global _initialized
    with _lock:
        if _initialized:
            return
        c = _connect()
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS seen_process (
                path TEXT PRIMARY KEY,
                pid INTEGER,
                first_ts REAL NOT NULL,
                last_ts REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS seen_remote (
                ip TEXT NOT NULL,
                port INTEGER,
                first_ts REAL NOT NULL,
                last_ts REAL NOT NULL,
                count INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (ip, port)
            );
            CREATE TABLE IF NOT EXISTS seen_listen (
                port INTEGER NOT NULL,
                pid INTEGER,
                first_ts REAL NOT NULL,
                PRIMARY KEY (port, pid)
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                kind TEXT NOT NULL,
                payload TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
            CREATE INDEX IF NOT EXISTS idx_remote_last ON seen_remote(last_ts);

            -- Review 3 Step 3: per-program baseline (~7d window, 21d retention)
            CREATE TABLE IF NOT EXISTS baseline_proc (
                proc_key TEXT PRIMARY KEY,
                first_ts REAL NOT NULL,
                last_ts REAL NOT NULL,
                sample_count INTEGER NOT NULL DEFAULT 0,
                ready INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS baseline_dest (
                proc_key TEXT NOT NULL,
                dest_kind TEXT NOT NULL,
                dest_value TEXT NOT NULL,
                first_ts REAL NOT NULL,
                last_ts REAL NOT NULL,
                hit_count INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (proc_key, dest_kind, dest_value)
            );
            CREATE TABLE IF NOT EXISTS baseline_upload (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proc_key TEXT NOT NULL,
                ts REAL NOT NULL,
                bytes_out_rate REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_baseline_upload_proc_ts
                ON baseline_upload(proc_key, ts);
            CREATE INDEX IF NOT EXISTS idx_baseline_dest_proc
                ON baseline_dest(proc_key);
            CREATE INDEX IF NOT EXISTS idx_baseline_upload_ts
                ON baseline_upload(ts);

            -- Alert store (client-mirrored; survives restart / weekly)
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                count INTEGER NOT NULL DEFAULT 1,
                state TEXT NOT NULL DEFAULT 'active',
                payload TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_last ON alerts(last_seen);
            CREATE INDEX IF NOT EXISTS idx_alerts_state ON alerts(state);
            """
        )
        c.commit()
        for row in c.execute(
            "SELECT path, first_ts FROM seen_process ORDER BY last_ts DESC LIMIT 5000"
        ):
            _proc_first[row["path"]] = float(row["first_ts"])
        for row in c.execute(
            "SELECT ip, port, first_ts FROM seen_remote ORDER BY last_ts DESC LIMIT 8000"
        ):
            _remote_first[(row["ip"], row["port"])] = float(row["first_ts"])
        for row in c.execute(
            "SELECT port, pid, first_ts FROM seen_listen ORDER BY first_ts DESC LIMIT 3000"
        ):
            _listen_first[(int(row["port"]), row["pid"])] = float(row["first_ts"])
        _initialized = True
    try:
        _restrict_data_acl()
    except Exception:
        pass
    try:
        scrub_stored_cmdlines()
    except Exception:
        pass


def _norm_port(port: int | None) -> int:
    return int(port) if port is not None else -1


def process_first_seen(path: str | None, pid: int | None = None) -> float | None:
    """Return prior first_ts if path was seen before; None if brand new. Queues upsert."""
    if not path:
        return None
    init()
    now = time.time()
    with _lock:
        prev = _proc_first.get(path)
        if prev is not None:
            old = _pending_procs.get(path)
            first = old[1] if old else prev
            _pending_procs[path] = (pid, first, now)
            return prev
        _proc_first[path] = now
        _pending_procs[path] = (pid, now, now)
        return None


def remote_first_seen(ip: str | None, port: int | None) -> float | None:
    """Return prior first_ts if remote seen before; None if new. Queues upsert."""
    if not ip:
        return None
    init()
    now = time.time()
    key = (ip, _norm_port(port))
    with _lock:
        prev = _remote_first.get(key)
        if prev is not None:
            old = _pending_remotes.get(key)
            if old:
                _pending_remotes[key] = (old[0], now, old[2] + 1)
            else:
                _pending_remotes[key] = (prev, now, 1)
            return prev
        _remote_first[key] = now
        _pending_remotes[key] = (now, now, 1)
        return None


def listen_first_seen(port: int | None, pid: int | None = None) -> float | None:
    """Return prior first_ts if this listen was seen across restarts; None if new.

    Also treats same port (any pid) as known so restart does not re-fire new_listener.
    """
    if port is None:
        return None
    init()
    now = time.time()
    key = (int(port), pid)
    with _lock:
        prev = _listen_first.get(key)
        if prev is not None:
            return prev
        port_hits = [v for (p, _), v in _listen_first.items() if p == int(port)]
        _listen_first[key] = now
        _pending_listens[key] = now
        if port_hits:
            return min(port_hits)
        return None


def record_event(kind: str, payload: dict[str, Any] | None = None) -> None:
    init()
    with _lock:
        clean = _sanitize_payload(payload or {})
        _pending_events.append(
            (time.time(), kind, json.dumps(clean if isinstance(clean, dict) else {}, separators=(",", ":")))
        )


def note_beacon_interval(key: str, interval: float) -> None:
    with _lock:
        lst = _beacon_intervals.setdefault(key, [])
        lst.append(interval)
        if len(lst) > 24:
            del lst[:-24]


def note_beacon_observation(ip: str, port: int, ts: float | None = None) -> bool:
    """Record a remote:port *appearance* timestamp; return True if beacon thresholds met.

    Call only on appearance edges (absent -> present), not every poll while connected.
    Thresholds mirror signals.py: >=4 intervals, mean 5-900s, low jitter.
    """
    import statistics

    if not ip or port is None:
        return False
    init()
    now = float(ts if ts is not None else time.time())
    key = (ip, int(port))
    with _lock:
        lst = _beacon_obs.setdefault(key, [])
        # Ignore duplicate/near-duplicate observations (< 3s) from flaky edges
        if lst and (now - lst[-1]) < 3.0:
            return False
        lst.append(now)
        if len(lst) > 24:
            del lst[:-24]
        if len(lst) < 5:
            return False
        intervals = [lst[i] - lst[i - 1] for i in range(1, len(lst))]
        if len(intervals) < 4:
            return False
        try:
            mean = statistics.mean(intervals)
            if mean < 5.0 or mean > 900.0:
                return False
            sd = statistics.pstdev(intervals)
            return sd <= max(1.5, 0.25 * mean)
        except statistics.StatisticsError:
            return False


def prune_old(days: float | None = None) -> int:
    """Delete events older than retention window. Returns rows deleted."""
    init()
    days = RETENTION_DAYS if days is None else float(days)
    cutoff = time.time() - (days * 86400.0)
    with _lock:
        c = _connect()
        cur = c.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        n = cur.rowcount if cur.rowcount is not None else 0
        # Also drop very stale remotes not seen in retention window
        cur2 = c.execute("DELETE FROM seen_remote WHERE last_ts < ?", (cutoff,))
        n2 = cur2.rowcount if cur2.rowcount is not None else 0
        # Baseline retention (same 21-day window)
        cur3 = c.execute("DELETE FROM baseline_upload WHERE ts < ?", (cutoff,))
        n3 = cur3.rowcount if cur3.rowcount is not None else 0
        cur4 = c.execute("DELETE FROM baseline_dest WHERE last_ts < ?", (cutoff,))
        n4 = cur4.rowcount if cur4.rowcount is not None else 0
        # Drop proc rows not seen in retention window
        cur5 = c.execute("DELETE FROM baseline_proc WHERE last_ts < ?", (cutoff,))
        n5 = cur5.rowcount if cur5.rowcount is not None else 0
        cur6 = c.execute("DELETE FROM alerts WHERE last_seen < ?", (cutoff,))
        n6 = cur6.rowcount if cur6.rowcount is not None else 0
        c.commit()
    return int(n) + int(n2) + int(n3) + int(n4) + int(n5) + int(n6)


def flush(max_events: int = 200) -> int:
    """Batch-write pending rows. Safe from poll loop. Returns rows touched."""
    global _flush_count
    init()
    with _lock:
        procs = dict(_pending_procs)
        remotes = dict(_pending_remotes)
        listens = dict(_pending_listens)
        events = _pending_events[:max_events]
        alerts = dict(_pending_alerts)
        _pending_procs.clear()
        _pending_remotes.clear()
        _pending_listens.clear()
        del _pending_events[: len(events)]
        _pending_alerts.clear()
    if not (procs or remotes or listens or events or alerts):
        return 0
    n = 0
    try:
        with _lock:
            c = _connect()
            if procs:
                c.executemany(
                    """
                    INSERT INTO seen_process(path, pid, first_ts, last_ts)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(path) DO UPDATE SET
                        pid=excluded.pid,
                        last_ts=excluded.last_ts
                    """,
                    [(p, pid, first, last) for p, (pid, first, last) in procs.items()],
                )
                n += len(procs)
            if remotes:
                c.executemany(
                    """
                    INSERT INTO seen_remote(ip, port, first_ts, last_ts, count)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(ip, port) DO UPDATE SET
                        last_ts=excluded.last_ts,
                        count=seen_remote.count + excluded.count
                    """,
                    [
                        (ip, port, first, last, delta)
                        for (ip, port), (first, last, delta) in remotes.items()
                    ],
                )
                n += len(remotes)
            if listens:
                c.executemany(
                    """
                    INSERT INTO seen_listen(port, pid, first_ts)
                    VALUES (?, ?, ?)
                    ON CONFLICT(port, pid) DO NOTHING
                    """,
                    [((port), pid, first) for (port, pid), first in listens.items()],
                )
                n += len(listens)
            if events:
                c.executemany(
                    "INSERT INTO events(ts, kind, payload) VALUES (?, ?, ?)",
                    events,
                )
                n += len(events)
            if alerts:
                c.executemany(
                    """
                    INSERT INTO alerts(id, first_seen, last_seen, count, state, payload)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        first_seen=MIN(alerts.first_seen, excluded.first_seen),
                        last_seen=excluded.last_seen,
                        count=excluded.count,
                        state=excluded.state,
                        payload=excluded.payload
                    """,
                    [
                        (aid, first, last, count, state, payload)
                        for aid, (first, last, count, state, payload) in alerts.items()
                    ],
                )
                n += len(alerts)
            c.commit()
            _flush_count += 1
            if _flush_count % 40 == 0:  # ~once per minute at 1.5s poll
                try:
                    prune_old()
                except Exception:
                    pass
    except Exception:
        with _lock:
            for p, v in procs.items():
                _pending_procs.setdefault(p, v)
            for k, v in remotes.items():
                _pending_remotes.setdefault(k, v)
            for k, v in listens.items():
                _pending_listens.setdefault(k, v)
            _pending_events[0:0] = events
            for k, v in alerts.items():
                _pending_alerts.setdefault(k, v)
        return 0
    return n



def upsert_alert(
    alert_id: str,
    *,
    first_seen: float | None = None,
    last_seen: float | None = None,
    count: int = 1,
    state: str = "active",
    payload: dict[str, Any] | None = None,
) -> None:
    """Queue alert upsert for history.sqlite (id is stable client identity)."""
    if not alert_id:
        return
    init()
    now = time.time()
    first = float(first_seen if first_seen is not None else now)
    last = float(last_seen if last_seen is not None else now)
    st = state if state in ("active", "stale", "ack", "muted") else "active"
    blob = json.dumps(_sanitize_payload(payload or {}) if isinstance(payload, dict) else {}, separators=(",", ":"))
    with _lock:
        prev = _pending_alerts.get(alert_id)
        if prev:
            first = min(prev[0], first)
            count = max(int(count), int(prev[2]))
        _pending_alerts[alert_id] = (first, last, int(count), st, blob)


def set_alert_state(alert_id: str, state: str) -> bool:
    """Set alert state immediately (ack/muted) and queue flush."""
    if not alert_id:
        return False
    init()
    st = state if state in ("active", "stale", "ack", "muted") else "ack"
    now = time.time()
    with _lock:
        c = _connect()
        row = c.execute(
            "SELECT first_seen, last_seen, count, payload FROM alerts WHERE id=?",
            (alert_id,),
        ).fetchone()
        if row:
            first, last, count, payload = (
                float(row["first_seen"]),
                float(row["last_seen"]),
                int(row["count"]),
                row["payload"] or "{}",
            )
        else:
            pend = _pending_alerts.get(alert_id)
            if not pend:
                return False
            first, last, count, _, payload = pend
        _pending_alerts[alert_id] = (first, last, count, st, payload if isinstance(payload, str) else json.dumps(payload or {}))
        # Also write immediately for UX reliability
        c.execute(
            """
            INSERT INTO alerts(id, first_seen, last_seen, count, state, payload)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                last_seen=excluded.last_seen,
                count=excluded.count,
                state=excluded.state,
                payload=excluded.payload
            """,
            (alert_id, first, last, count, st, payload if isinstance(payload, str) else json.dumps(payload or {})),
        )
        c.commit()
        _pending_alerts.pop(alert_id, None)
    return True


def list_alerts(*, include_terminal: bool = False, max_age_sec: float = 86400.0) -> list[dict[str, Any]]:
    """Return persisted alerts for client seed (newest last_seen first)."""
    init()
    cutoff = time.time() - float(max_age_sec)
    with _lock:
        c = _connect()
        if include_terminal:
            rows = c.execute(
                "SELECT id, first_seen, last_seen, count, state, payload FROM alerts "
                "WHERE last_seen >= ? ORDER BY last_seen DESC LIMIT 500",
                (cutoff,),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT id, first_seen, last_seen, count, state, payload FROM alerts "
                "WHERE last_seen >= ? AND state IN ('active','stale') "
                "ORDER BY last_seen DESC LIMIT 500",
                (cutoff,),
            ).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        try:
            payload = json.loads(row["payload"] or "{}")
        except Exception:
            payload = {}
        out.append(
            {
                "id": row["id"],
                "first_seen": float(row["first_seen"]),
                "last_seen": float(row["last_seen"]),
                "count": int(row["count"]),
                "state": row["state"],
                "payload": payload,
            }
        )
    return out


def prune_alerts(max_age_sec: float = 14 * 86400.0) -> int:
    init()
    cutoff = time.time() - float(max_age_sec)
    with _lock:
        c = _connect()
        cur = c.execute("DELETE FROM alerts WHERE last_seen < ?", (cutoff,))
        c.commit()
        return int(cur.rowcount or 0)


def summary() -> dict[str, Any]:
    """Counts / oldest first-seen for UI footnote or chip."""
    init()
    with _lock:
        c = _connect()
        try:
            n_proc = c.execute("SELECT COUNT(*) FROM seen_process").fetchone()[0]
            n_remote = c.execute("SELECT COUNT(*) FROM seen_remote").fetchone()[0]
            n_listen = c.execute("SELECT COUNT(*) FROM seen_listen").fetchone()[0]
            n_events = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            try:
                n_bl_proc = c.execute("SELECT COUNT(*) FROM baseline_proc").fetchone()[0]
                n_bl_dest = c.execute("SELECT COUNT(*) FROM baseline_dest").fetchone()[0]
                n_bl_up = c.execute("SELECT COUNT(*) FROM baseline_upload").fetchone()[0]
            except Exception:
                n_bl_proc = n_bl_dest = n_bl_up = 0
            oldest = c.execute(
                "SELECT MIN(first_ts) FROM ("
                "SELECT first_ts FROM seen_process "
                "UNION ALL SELECT first_ts FROM seen_remote "
                "UNION ALL SELECT first_ts FROM seen_listen)"
            ).fetchone()[0]
        except Exception as e:
            return {"ok": False, "error": str(e)[:200], "db": DB_PATH}
        pending = {
            "procs": len(_pending_procs),
            "remotes": len(_pending_remotes),
            "listens": len(_pending_listens),
            "events": len(_pending_events),
        }
    return {
        "ok": True,
        "db": DB_PATH,
        "counts": {
            "processes": int(n_proc or 0),
            "remotes": int(n_remote or 0),
            "listens": int(n_listen or 0),
            "events": int(n_events or 0),
            "baseline_proc": int(n_bl_proc or 0),
            "baseline_dest": int(n_bl_dest or 0),
            "baseline_upload": int(n_bl_up or 0),
        },
        "oldest_first_seen": float(oldest) if oldest is not None else None,
        "pending": pending,
        "retention_days": RETENTION_DAYS,
    }



def weekly_summary(days: float = 7.0) -> dict[str, Any]:
    """Last N days rollup for Weekly summary UI (Review 3 Step 4).

    Empty-state friendly when history is young (< 1h of data).
    """
    init()
    now = time.time()
    cutoff = now - float(days) * 86400.0
    with _lock:
        c = _connect()
        try:
            oldest = c.execute(
                "SELECT MIN(first_ts) FROM ("
                "SELECT first_ts FROM seen_process "
                "UNION ALL SELECT first_ts FROM seen_remote "
                "UNION ALL SELECT first_ts FROM seen_listen)"
            ).fetchone()[0]
            age_sec = (now - float(oldest)) if oldest is not None else 0.0
            young = oldest is None or age_sec < 3600.0

            unique_remotes = c.execute(
                "SELECT COUNT(*) FROM seen_remote WHERE last_ts >= ? OR first_ts >= ?",
                (cutoff, cutoff),
            ).fetchone()[0]
            new_remotes = c.execute(
                "SELECT COUNT(*) FROM seen_remote WHERE first_ts >= ?",
                (cutoff,),
            ).fetchone()[0]
            new_listeners = c.execute(
                "SELECT COUNT(*) FROM seen_listen WHERE first_ts >= ?",
                (cutoff,),
            ).fetchone()[0]
            # Events by kind in window
            event_rows = c.execute(
                "SELECT kind, COUNT(*) AS n FROM events WHERE ts >= ? GROUP BY kind",
                (cutoff,),
            ).fetchall()
            events_by_kind = {str(r[0]): int(r[1]) for r in event_rows}
            intel_hits = int(
                events_by_kind.get("intel_hit", 0)
                + events_by_kind.get("intel", 0)
            )
            baseline_departures = int(
                events_by_kind.get("baseline_depart", 0)
                + events_by_kind.get("exfil_ish", 0)
            )
            dns_flags = int(
                events_by_kind.get("dns_rare", 0)
                + events_by_kind.get("dns_burst", 0)
            )
            # Top processes by outbound (baseline_upload avg rate)
            # Network-only epoch: review4 stopped feeding disk write_bytes (~2026-09-13 22:00 UTC)
            NETWORK_UPLOAD_EPOCH = 1757800800.0
            top_out = []
            try:
                for r in c.execute(
                    "SELECT proc_key, AVG(bytes_out_rate), COUNT(*), MAX(bytes_out_rate), "
                    "MIN(ts), SUM(CASE WHEN ts < ? THEN 1 ELSE 0 END) "
                    "FROM baseline_upload WHERE ts >= ? "
                    "GROUP BY proc_key ORDER BY AVG(bytes_out_rate) DESC LIMIT 10",
                    (NETWORK_UPLOAD_EPOCH, cutoff),
                ):
                    samples = int(r[2] or 0)
                    stale_n = int(r[5] or 0)
                    stale = samples > 0 and stale_n >= max(1, samples // 2)
                    top_out.append({
                        "proc_key": r[0],
                        "avg_out_bps": float(r[1] or 0),
                        "samples": samples,
                        "max_out_bps": float(r[3] or 0),
                        "stale_disk_era": bool(stale),
                        "label": "stale (disk-era)" if stale else "network",
                    })
            except Exception:
                top_out = []
            # Recent new listeners detail
            listener_samples = []
            try:
                for r in c.execute(
                    "SELECT port, pid, first_ts FROM seen_listen WHERE first_ts >= ? "
                    "ORDER BY first_ts DESC LIMIT 15",
                    (cutoff,),
                ):
                    listener_samples.append(
                        {"port": r[0], "pid": r[1], "first_ts": float(r[2])}
                    )
            except Exception:
                pass
        except Exception as e:
            return {
                "ok": False,
                "error": str(e)[:200],
                "db": DB_PATH,
                "days": days,
            }
    return {
        "ok": True,
        "db": DB_PATH,
        "days": float(days),
        "cutoff_ts": cutoff,
        "now_ts": now,
        "young": bool(young),
        "age_hours": round(age_sec / 3600.0, 2) if oldest is not None else 0.0,
        "empty_hint": (
            "History is still young — keep TrafficWatch running to build the weekly view."
            if young
            else None
        ),
        "unique_remotes": int(unique_remotes or 0),
        "new_remotes": int(new_remotes or 0),
        "new_listeners": int(new_listeners or 0),
        "intel_hits": intel_hits,
        "baseline_departures": baseline_departures,
        "dns_flags": dns_flags,
        "events_by_kind": events_by_kind,
        "top_processes_outbound": top_out,
        "new_listener_samples": listener_samples,
        "note": (
            "Outbound rates from baseline_upload (network EMA / helper TCP; disk write_bytes not used after review4). "
            "Samples mostly from before the network-only epoch are labeled stale (disk-era). "
            "Intel/baseline event counts reflect recorded events only."
        ),
    }



def _ssid_hash_short(name: str) -> str:
    """Same sha256 as net_context._hash_name; UI uses first 16 hex chars."""
    raw = (name or "").strip().encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def _redact_ssid_text(v2: str) -> str:
    """Replace plain SSID mentions with hash when name extractable, else redacted."""
    if "SSID hash " in v2:
        return v2

    def _paren(m: re.Match) -> str:
        name = (m.group(1) or "").strip()
        if not name or name.lower() in ("redacted",):
            return "(SSID redacted)"
        if name.lower().startswith("hash "):
            return m.group(0)
        return f"(SSID hash {_ssid_hash_short(name)})"

    v2 = re.sub(r"(?i)\(\s*SSID\s+([^)]+)\)", _paren, v2)

    def _bare(m: re.Match) -> str:
        name = (m.group(1) or "").strip()
        if not name or name.lower() in ("redacted",):
            return "SSID redacted"
        if name.lower().startswith("hash "):
            return m.group(0)
        return f"SSID hash {_ssid_hash_short(name)}"

    v2 = re.sub(r"(?i)SSID\s+([A-Za-z0-9 _.-]{1,64})", _bare, v2)
    return v2


def _sanitize_payload(payload: Any) -> Any:
    """Never persist command lines, plain SSIDs, or obvious secret fields."""
    if not isinstance(payload, dict):
        return payload
    out = {}
    for k, v in payload.items():
        lk = str(k).lower()
        if "cmdline" in lk or lk in ("command_line", "commandline", "cmd_line"):
            continue
        if lk in ("wifi_ssid", "ssid", "network_name", "wlan_ssid"):
            continue
        if lk in ("signal_detail", "detail") and isinstance(v, str):
            out[k] = _redact_ssid_text(v)
            continue
        if isinstance(v, dict):
            out[k] = _sanitize_payload(v)
            continue
        if isinstance(v, list):
            out[k] = [_sanitize_payload(x) if isinstance(x, dict) else x for x in v]
            continue
        out[k] = v
    return out


def scrub_stored_cmdlines() -> int:
    """Strip cmdline-like keys from stored event/alert payloads. No secret dump."""
    init()
    n = 0
    with _lock:
        c = _connect()
        for table, col in (("events", "payload"), ("alerts", "payload")):
            try:
                rows = c.execute(f"SELECT rowid, {col} FROM {table}").fetchall()
            except Exception:
                continue
            for row in rows:
                raw = row[1]
                if not raw or "cmdline" not in str(raw).lower():
                    continue
                try:
                    data = json.loads(raw)
                except Exception:
                    continue
                cleaned = _sanitize_payload(data)
                if cleaned != data:
                    c.execute(f"UPDATE {table} SET {col}=? WHERE rowid=?", (json.dumps(cleaned, separators=(",", ":")), row[0]))
                    n += 1
        if n:
            c.commit()
    return n


def set_retention_days(days: float) -> dict[str, Any]:
    global RETENTION_DAYS
    days = max(1.0, min(float(days), 365.0))
    RETENTION_DAYS = days
    try:
        prune_old(days)
    except Exception:
        pass
    return {"ok": True, "retention_days": RETENTION_DAYS}


def clear_all() -> dict[str, Any]:
    """Wipe persisted history tables and in-memory caches. Schema kept."""
    init()
    tables = (
        "seen_process",
        "seen_remote",
        "seen_listen",
        "events",
        "baseline_proc",
        "baseline_dest",
        "baseline_upload",
        "alerts",
    )
    with _lock:
        c = _connect()
        for table in tables:
            try:
                c.execute(f"DELETE FROM {table}")
            except Exception:
                pass
        c.commit()
        _proc_first.clear()
        _remote_first.clear()
        _listen_first.clear()
        _beacon_intervals.clear()
        _beacon_obs.clear()
        _pending_procs.clear()
        _pending_remotes.clear()
        _pending_listens.clear()
        _pending_events.clear()
        _pending_alerts.clear()
    return {"ok": True, "cleared": True}


def _restrict_data_acl() -> None:
    if os.name != "nt":
        return
    try:
        import subprocess
        user = os.environ.get("USERNAME") or os.getlogin()
        subprocess.run(
            [
                "icacls",
                DATA_DIR,
                "/inheritance:r",
                "/grant:r",
                f"{user}:(OI)(CI)F",
                "/grant:r",
                "SYSTEM:(OI)(CI)F",
                "/grant:r",
                "*S-1-5-32-544:(OI)(CI)F",
            ],
            capture_output=True,
            timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        pass


def known_listen_ports() -> set[int]:
    init()
    with _lock:
        return {p for (p, _) in _listen_first}
