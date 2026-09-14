"""Per-program ~7-day baseline + conservative departure / exfil-ish signals (Review 3 Step 3).

Uses history.sqlite (WAL) via history.py. Observes destinations + process-level
upload rates (psutil Process.io_counters EMA — NOT per-TCP bytes). ASN is weak
with DB-IP City Lite (no ASN field); baseline prefers country + remote-IP /24.
"""
from __future__ import annotations

import ipaddress
import statistics
import threading
import time
from collections import defaultdict, deque
from typing import Any

try:
    import history as tw_history
except Exception:  # pragma: no cover
    tw_history = None  # type: ignore

try:
    import risk as tw_risk
except Exception:  # pragma: no cover
    tw_risk = None  # type: ignore

# --- Learning / alert thresholds (documented in NOTES.md) -------------------
LEARNING_MIN_AGE_SEC = 7 * 86400.0  # ~7 days (Review 4)
LEARNING_MIN_SAMPLES = 400  # floor; ready requires BOTH age AND samples
UPLOAD_WINDOW_SEC = 7 * 86400.0  # median over ~7 days of samples
UPLOAD_RETENTION_SEC = 21 * 86400.0
EXFIL_MULTIPLIER = 4.0  # >4x median outbound rate
EXFIL_STREAK = 3  # consecutive polls above threshold
EXFIL_ABS_FLOOR = 50_000.0  # bytes/sec — ignore tiny absolute rates
EXFIL_MEDIAN_FLOOR = 500.0  # bytes/sec — need a meaningful baseline median
DEST_MIN_KNOWN = 2  # need a few known dest classes before departure alerts

_BROWSER_PROCS = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
    "brave.exe", "opera.exe", "safari.exe", "chromium.exe",
})

# CDN / cloud hostname suffixes — do not fire baseline_depart on new /24 alone
_CDN_HOST_SUFFIXES = (
    "cloudfront.net", "googlevideo.com", "amazonaws.com", "github.com",
    "githubusercontent.com", "akamaitechnologies.com", "akamai.net", "akamaiedge.net",
    "microsoft.com", "windows.com", "office.com", "office.net", "live.com",
    "azure.com", "azure.net", "trafficmanager.net", "google.com", "gstatic.com",
    "googleusercontent.com", "youtube.com", "ytimg.com", "apple.com", "icloud.com",
    "facebook.com", "fbcdn.net", "cloudflare.com", "fastly.net", "edgekey.net",
    "edgesuite.net", "doubleclick.net", "googleapis.com", "gvt1.com",
    "windowsupdate.com", "msn.com", "bing.com",
)


def _is_browser_or_cdn(row: dict[str, Any]) -> bool:
    pname = (row.get("process") or "").lower()
    if pname in _BROWSER_PROCS:
        return True
    host = (row.get("hostname") or "").strip().lower().rstrip(".")
    if host:
        for suf in _CDN_HOST_SUFFIXES:
            if host == suf or host.endswith("." + suf):
                return True
    return False


_lock = threading.RLock()
_initialized = False

# In-memory front caches (seeded from DB)
_proc: dict[str, dict[str, Any]] = {}  # proc_key -> {first_ts, last_ts, sample_count, ready}
_dests: dict[str, set[tuple[str, str]]] = defaultdict(set)  # proc_key -> {(kind, value)}
_upload_recent: dict[str, deque[tuple[float, float]]] = {}  # proc_key -> deque[(ts, rate)]
_exfil_streak: dict[str, int] = defaultdict(int)

# Pending batch writes
_pending_procs: dict[str, tuple[float, float, int, int]] = {}  # key -> (first, last, samples, ready)
_pending_dests: dict[tuple[str, str, str], tuple[float, float, int]] = {}  # -> (first, last, delta)
_pending_uploads: list[tuple[str, float, float]] = []  # (proc_key, ts, rate)


def _proc_key(exe: str | None, name: str | None) -> str | None:
    path = (exe or "").strip()
    if path:
        return path.lower()
    n = (name or "").strip()
    if n:
        return f"name:{n.lower()}"
    return None


def _is_public_country(code: str | None, country: str | None) -> bool:
    cc = (code or "").strip().upper()
    if len(cc) == 2 and cc.isalpha():
        return True
    c = (country or "").strip().lower()
    if not c or c in ("-", "private", "private/local", "unknown", "n/a"):
        return False
    return True


def _ip24(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        parts = str(addr).split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    # IPv6: /48 coarse class
    try:
        net = ipaddress.ip_network(f"{addr}/48", strict=False)
        return str(net)
    except Exception:
        return None


def _asn_value(geo: dict[str, Any] | None) -> str | None:
    """ASN is weak with City Lite — use asn or org only when present locally."""
    if not geo:
        return None
    asn = geo.get("asn")
    if asn is not None and str(asn).strip():
        return str(asn).strip()[:80]
    org = geo.get("org")
    if org is not None and str(org).strip():
        return f"org:{str(org).strip()[:80]}"
    return None


def init() -> None:
    """Ensure history schema (incl. baseline tables) + seed caches. Idempotent."""
    global _initialized
    if tw_history is None:
        return
    with _lock:
        if _initialized:
            return
        tw_history.init()
        c = tw_history._connect()
        # Seed process meta
        for row in c.execute(
            "SELECT proc_key, first_ts, last_ts, sample_count, ready "
            "FROM baseline_proc ORDER BY last_ts DESC LIMIT 8000"
        ):
            _proc[row["proc_key"]] = {
                "first_ts": float(row["first_ts"]),
                "last_ts": float(row["last_ts"]),
                "sample_count": int(row["sample_count"] or 0),
                "ready": bool(row["ready"]),
            }
        for row in c.execute(
            "SELECT proc_key, dest_kind, dest_value FROM baseline_dest "
            "ORDER BY last_ts DESC LIMIT 30000"
        ):
            _dests[row["proc_key"]].add((row["dest_kind"], row["dest_value"]))
        # Recent upload samples (last 7d) for median
        cutoff = time.time() - UPLOAD_WINDOW_SEC
        for row in c.execute(
            "SELECT proc_key, ts, bytes_out_rate FROM baseline_upload "
            "WHERE ts >= ? ORDER BY ts DESC LIMIT 80000",
            (cutoff,),
        ):
            pk = row["proc_key"]
            dq = _upload_recent.setdefault(pk, deque(maxlen=2000))
            # Insert oldest-first later; we DESC so appendleft
            dq.appendleft((float(row["ts"]), float(row["bytes_out_rate"])))
        _initialized = True


def _is_ready(meta: dict[str, Any], now: float) -> bool:
    raw_first = meta.get("first_ts")
    try:
        first = float(raw_first) if raw_first is not None else float(now)
    except (TypeError, ValueError):
        first = float(now)
    age = now - first
    samples = int(meta.get("sample_count") or 0)
    ok = age >= LEARNING_MIN_AGE_SEC and samples >= LEARNING_MIN_SAMPLES
    if meta.get("ready") and not ok:
        # Demote premature Review-3 ready until both thresholds met
        meta["ready"] = False
    return ok


def _queue_proc(pk: str, first: float, last: float, samples: int, ready: bool) -> None:
    _pending_procs[pk] = (first, last, samples, 1 if ready else 0)


def _queue_dest(pk: str, kind: str, value: str, now: float) -> None:
    key = (pk, kind, value)
    old = _pending_dests.get(key)
    if old:
        _pending_dests[key] = (old[0], now, old[2] + 1)
    else:
        # first_ts: if already known in memory, keep memory first; else now
        first = now
        _pending_dests[key] = (first, now, 1)


def _observe_dests(pk: str, row: dict[str, Any], now: float, ready: bool) -> list[dict[str, Any]]:
    """Update destination baseline; return departure signals if ready."""
    signals: list[dict[str, Any]] = []
    if row.get("private_remote"):
        return signals
    rip = row.get("remote_ip")
    if not rip:
        return signals

    known = _dests[pk]
    prior_country = sum(1 for k, _ in known if k == "country")
    prior_ip24 = sum(1 for k, _ in known if k == "ip24")
    new_kinds: list[tuple[str, str, str]] = []  # kind, value, label

    cc = (row.get("country_code") or "").strip().upper() or None
    country = row.get("country")
    if _is_public_country(cc, country):
        val = cc or str(country)
        kind = "country"
        if (kind, val) not in known:
            new_kinds.append((kind, val, f"new country {val}"))
            known.add((kind, val))
        _queue_dest(pk, kind, val, now)

    asn = _asn_value(row.get("geo") if isinstance(row.get("geo"), dict) else None)
    if asn:
        kind = "asn"
        if (kind, asn) not in known:
            new_kinds.append((kind, asn, f"new ASN/org {asn}"))
            known.add((kind, asn))
        _queue_dest(pk, kind, asn, now)

    ip_class = _ip24(rip)
    if ip_class:
        kind = "ip24"
        if (kind, ip_class) not in known:
            new_kinds.append((kind, ip_class, f"new remote class {ip_class}"))
            known.add((kind, ip_class))
        _queue_dest(pk, kind, ip_class, now)

    # Always record exact IP for history (not used for departure alone)
    if ("ip", str(rip)) not in known:
        known.add(("ip", str(rip)))
    _queue_dest(pk, "ip", str(rip), now)

    host = (row.get("hostname") or "").strip().lower()
    if host and host not in ("-", "n/a"):
        if ("host", host[:200]) not in known:
            known.add(("host", host[:200]))
        _queue_dest(pk, "host", host[:200], now)

    if not ready:
        return signals

    # Departure only after baseline ready and enough prior dest classes
    for kind, val, label in new_kinds:
        if kind == "country":
            if prior_country < DEST_MIN_KNOWN:
                continue
            signals.append(
                {
                    "id": "baseline_depart",
                    "label": "baseline depart",
                    "severity": "medium",
                    "detail": label,
                }
            )
        elif kind == "asn":
            signals.append(
                {
                    "id": "baseline_depart",
                    "label": "baseline depart",
                    "severity": "medium",
                    "detail": label,
                }
            )
        elif kind == "ip24":
            if prior_ip24 < DEST_MIN_KNOWN:
                continue
            # Review 4: skip /24 departures for browsers / well-known CDN hostnames
            if _is_browser_or_cdn(row):
                continue
            # Tier 0: prefer ASN depart over /24 — if ASN known on this row, skip /24-only
            if _asn_value(row.get("geo") if isinstance(row.get("geo"), dict) else None):
                continue
            # Prefer country/ASN; only fire /24 when another new class also present this pass
            other_new = [k for k, _, _ in new_kinds if k in ("country", "asn")]
            if not other_new:
                continue
            signals.append(
                {
                    "id": "baseline_depart",
                    "label": "baseline depart",
                    "severity": "medium",
                    "detail": label + " (with country/ASN change)",
                }
            )
    return signals

def _observe_upload(pk: str, rate: float | None, now: float, ready: bool) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    if rate is None:
        return signals
    try:
        rate_f = float(rate)
    except (TypeError, ValueError):
        return signals
    if rate_f < 0:
        rate_f = 0.0

    dq = _upload_recent.setdefault(pk, deque(maxlen=2000))
    dq.append((now, rate_f))
    _pending_uploads.append((pk, now, rate_f))

    if not ready:
        _exfil_streak[pk] = 0
        return signals

    # Median of samples in last 7 days
    cutoff = now - UPLOAD_WINDOW_SEC
    samples = [r for (t, r) in dq if t >= cutoff]
    if len(samples) < 20:
        _exfil_streak[pk] = 0
        return signals
    try:
        med = float(statistics.median(samples))
    except statistics.StatisticsError:
        _exfil_streak[pk] = 0
        return signals

    if med < EXFIL_MEDIAN_FLOOR:
        _exfil_streak[pk] = 0
        return signals

    if rate_f >= EXFIL_ABS_FLOOR and rate_f > (EXFIL_MULTIPLIER * med):
        _exfil_streak[pk] = int(_exfil_streak.get(pk, 0)) + 1
    else:
        _exfil_streak[pk] = 0

    if _exfil_streak[pk] >= EXFIL_STREAK:
        signals.append(
            {
                "id": "exfil_ish",
                "label": "exfil-ish",
                "severity": "medium",
                "detail": (
                    f"Outbound ~{rate_f:.0f} B/s > {EXFIL_MULTIPLIER:.0f}x "
                    f"median {med:.0f} B/s for {_exfil_streak[pk]} polls "
                    "(network outbound EMA / NIC; disk write_bytes not used)"
                ),
            }
        )
    return signals


def attach_baseline(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Observe per-process destinations + upload; attach baseline signals; refresh risk."""
    if tw_history is None:
        for r in rows:
            r.setdefault("baseline", {"state": "unavailable"})
        return rows
    init()
    now = time.time()

    # Aggregate one upload sample per process key this poll
    by_pk: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rate_by_pk: dict[str, float] = {}
    for r in rows:
        pk = _proc_key(r.get("exe"), r.get("process"))
        if not pk:
            continue
        by_pk[pk].append(r)
        # Prefer network outbound EMA only (Review 4: never disk write_bytes)
        src = (r.get("rate_source") or "")
        # Prefer helper TCP per-connection outbound when present (true network bytes).
        # Skip disk-mixed process_io_ema. If helper down / no network counters: br=None
        # (do not fall back to disk write_bytes).
        if src == "helper_tcp":
            br = r.get("bytes_out_rate")
        elif src in ("process_net_ema", "nic_share", "network"):
            br = r.get("bytes_out_rate")
        elif src == "process_io_ema":
            # Disk-mixed IO - do not feed exfil
            br = None
        else:
            br = r.get("bytes_out_rate") if r.get("network_out_ok") else None
        if br is not None:
            try:
                val = float(br)
            except (TypeError, ValueError):
                continue
            if src == "helper_tcp":
                rate_by_pk[pk] = float(rate_by_pk.get(pk, 0.0)) + val
                rate_by_pk["__helper__" + pk] = 1.0
            elif ("__helper__" + pk) not in rate_by_pk:
                rate_by_pk[pk] = val

    # Drop internal helper markers from rate map
    rate_by_pk = {k: v for k, v in rate_by_pk.items() if not str(k).startswith("__helper__")}

    with _lock:
        for pk, group in by_pk.items():
            meta = _proc.get(pk)
            if meta is None:
                meta = {
                    "first_ts": now,
                    "last_ts": now,
                    "sample_count": 0,
                    "ready": False,
                }
                _proc[pk] = meta
            meta["sample_count"] = int(meta.get("sample_count") or 0) + 1
            meta["last_ts"] = now
            ready = _is_ready(meta, now)
            meta["ready"] = ready
            _queue_proc(
                pk,
                float(meta["first_ts"]),
                float(meta["last_ts"]),
                int(meta["sample_count"]),
                ready,
            )

            state = "ready" if ready else "learning"
            depart_sigs: list[dict[str, Any]] = []
            for r in group:
                # Observe each public remote once per row
                ds = _observe_dests(pk, r, now, ready)
                # Deduplicate signal ids per process this poll
                for s in ds:
                    if not any(x.get("id") == s.get("id") and x.get("detail") == s.get("detail") for x in depart_sigs):
                        depart_sigs.append(s)

            up_sigs = _observe_upload(pk, rate_by_pk.get(pk), now, ready)

            for r in group:
                r["baseline"] = {
                    "state": state,
                    "proc_key": pk,
                    "sample_count": int(meta["sample_count"]),
                    "asn_weak": False,  # Tier 0: IPinfo Lite when token present
                }
                if not ready:
                    # Soft marker only — not an alert
                    continue
                existing = list(r.get("signals") or [])
                # Cap room: keep prior, append baseline (dedupe by id)
                have = {str(s.get("id")) for s in existing}
                for s in depart_sigs + up_sigs:
                    if s["id"] in have:
                        continue
                    existing.append(s)
                    have.add(s["id"])
                r["signals"] = existing[:8]

    # Re-score risk so baseline signals affect 0-100
    if tw_risk is not None:
        try:
            rows = tw_risk.attach_risk(rows)
        except Exception:
            pass
    return rows


def flush(max_uploads: int = 500) -> int:
    """Batch-write pending baseline rows. Safe from poll loop."""
    if tw_history is None:
        return 0
    init()
    with _lock:
        procs = dict(_pending_procs)
        dests = dict(_pending_dests)
        uploads = _pending_uploads[:max_uploads]
        _pending_procs.clear()
        _pending_dests.clear()
        del _pending_uploads[: len(uploads)]
    if not (procs or dests or uploads):
        return 0
    n = 0
    try:
        with _lock:
            c = tw_history._connect()
            if procs:
                c.executemany(
                    """
                    INSERT INTO baseline_proc(proc_key, first_ts, last_ts, sample_count, ready)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(proc_key) DO UPDATE SET
                        last_ts=excluded.last_ts,
                        sample_count=excluded.sample_count,
                        ready=excluded.ready
                    """,
                    [
                        (pk, first, last, samples, ready)
                        for pk, (first, last, samples, ready) in procs.items()
                    ],
                )
                n += len(procs)
            if dests:
                c.executemany(
                    """
                    INSERT INTO baseline_dest(proc_key, dest_kind, dest_value, first_ts, last_ts, hit_count)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(proc_key, dest_kind, dest_value) DO UPDATE SET
                        last_ts=excluded.last_ts,
                        hit_count=baseline_dest.hit_count + excluded.hit_count
                    """,
                    [
                        (pk, kind, val, first, last, delta)
                        for (pk, kind, val), (first, last, delta) in dests.items()
                    ],
                )
                n += len(dests)
            if uploads:
                c.executemany(
                    "INSERT INTO baseline_upload(proc_key, ts, bytes_out_rate) VALUES (?, ?, ?)",
                    uploads,
                )
                n += len(uploads)
            c.commit()
    except Exception:
        with _lock:
            for pk, v in procs.items():
                _pending_procs.setdefault(pk, v)
            for k, v in dests.items():
                _pending_dests.setdefault(k, v)
            _pending_uploads[0:0] = uploads
        return 0
    return n


def summary() -> dict[str, Any]:
    """UI chip: baseline learning|ready counts (Host-checked via app route)."""
    if tw_history is None:
        return {"ok": False, "error": "history unavailable", "state": "unavailable"}
    init()
    now = time.time()
    with _lock:
        n = len(_proc)
        n_ready = sum(1 for m in _proc.values() if _is_ready(m, now))
        n_learn = n - n_ready
        pending = {
            "procs": len(_pending_procs),
            "dests": len(_pending_dests),
            "uploads": len(_pending_uploads),
        }
        # Overall chip state: ready if any process ready, else learning if any, else idle
        if n_ready > 0 and n_learn == 0:
            state = "ready"
        elif n_ready > 0:
            state = "mixed"
        elif n > 0:
            state = "learning"
        else:
            state = "learning"
        try:
            c = tw_history._connect()
            n_dest = c.execute("SELECT COUNT(*) FROM baseline_dest").fetchone()[0]
            n_up = c.execute("SELECT COUNT(*) FROM baseline_upload").fetchone()[0]
        except Exception:
            n_dest, n_up = 0, 0
    return {
        "ok": True,
        "state": state,
        "asn_weak": False,  # Tier 0: IPinfo Lite when token present
        "asn_note": "Tier 0: ASN from IPinfo Lite when token/MMDB present; else country + /24. Prefer ASN depart over /24.",
        "upload_note": "Upload baseline prefers helper TCP outbound when live helper is on; else process/NIC network EMA; skips exfil_ish if only disk write_bytes.",
        "thresholds": {
            "learning_min_age_sec": LEARNING_MIN_AGE_SEC,
            "learning_min_samples": LEARNING_MIN_SAMPLES,
            "exfil_multiplier": EXFIL_MULTIPLIER,
            "exfil_streak": EXFIL_STREAK,
        },
        "counts": {
            "processes": n,
            "learning": n_learn,
            "ready": n_ready,
            "dests": int(n_dest or 0),
            "upload_samples": int(n_up or 0),
        },
        "pending": pending,
    }
