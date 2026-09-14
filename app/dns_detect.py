# -*- coding: utf-8 -*-
"""DNS detection heuristics (Review 3 Step 4 + Review 4 FP hardening).

Uses dns_log.py recent queries: newly seen domains, high-entropy/DGA-ish labels,
rare TLDs, bursty unique names attributed to one process via IP join.
Conservative labels: dns_rare, dns_burst. Degrades silently if DNS log limited.
"""
from __future__ import annotations

import json
import math
import os
import re
import threading
import time
from collections import defaultdict, deque
from typing import Any

try:
    import dns_log as tw_dns_log
except Exception:  # pragma: no cover
    tw_dns_log = None  # type: ignore

try:
    import history as tw_history
except Exception:  # pragma: no cover
    tw_history = None  # type: ignore

# Abuse-heavy TLDs only (Review 4: removed info/site/online/club/work/biz/website/space/fun)
_RARE_TLDS = frozenset({
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "buzz", "icu",
    "click", "link", "loan", "men", "date", "download", "stream", "gdn",
})

# Common / expected TLDs - never flag solely for TLD
_COMMON_TLDS = frozenset({
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "uk", "de",
    "fr", "jp", "au", "ca", "us", "eu", "ch", "nl", "se", "no", "fi", "dk",
    "be", "at", "pl", "es", "it", "pt", "br", "mx", "in", "kr", "sg", "nz",
    "ie", "cz", "app", "dev", "cloud", "ai", "ms", "azure", "amazon", "aws",
    "info", "site", "online", "club", "work", "biz", "website", "space", "fun",
})

# Major cloud/CDN suffixes — never dga/rare when hostname endswith these
_ALLOW_SUFFIXES = (
    "cloudfront.net",
    "googlevideo.com",
    "compute.amazonaws.com",
    "amazonaws.com",
    "github.com",
    "githubusercontent.com",
    "akamaitechnologies.com",
    "akamai.net",
    "akamaiedge.net",
    "microsoft.com",
    "windows.com",
    "office.com",
    "office.net",
    "live.com",
    "azure.com",
    "azure.net",
    "trafficmanager.net",
    "cloudapp.azure.com",
    "google.com",
    "gstatic.com",
    "googleusercontent.com",
    "youtube.com",
    "ytimg.com",
    "apple.com",
    "icloud.com",
    "facebook.com",
    "fbcdn.net",
    "cloudflare.com",
    "fastly.net",
    "edgekey.net",
    "edgesuite.net",
    "doubleclick.net",
    "googleapis.com",
    "gvt1.com",
    "msftconnecttest.com",
    "windowsupdate.com",
    "msn.com",
    "bing.com",
    "skype.com",
    "teams.microsoft.com",
)

_BROWSER_NAMES = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
    "brave.exe", "opera.exe", "safari.exe", "chromium.exe",
})

_LABEL_RE = re.compile(r"^[a-z0-9\-]+$", re.I)
_HEXISH_RE = re.compile(r"^[a-f0-9]{12,}$", re.I)
# IP-encoding / CDN hyphen-digit labels (ec2-54-12-34-56, a23-45-67-89, r4---sn-...)
_IP_ENCODE_RE = re.compile(
    r"(?i)^(?:"
    r"[a-z]{0,6}\d{1,3}(?:-\d{1,3}){2,}\w*"  # a23-45-67-89... or ec2-54-12-34-56
    r"|r\d+-{2,}sn-[a-z0-9\-]+"              # r4---sn-...
    r"|[a-z]*\d+[a-z]*-\d+-\d+-\d+(?:-\d+)?"  # general hyphenated digit quads
    r")$"
)
_CONSONANT_RUN_RE = re.compile(r"[bcdfghjklmnpqrstvwxyz]{5,}", re.I)

# Burst: raise threshold; exclude browsers (Review 4)
_BURST_WINDOW_SEC = 120.0
_BURST_MIN_UNIQUE = 20
_BURST_MIN_NEWISH = 5
_ENTROPY_MIN_LEN = 14
_ENTROPY_THRESHOLD = 3.8  # Shannon bits/char; not used alone

_DATA_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data"))
_SEEN_PATH = os.path.join(_DATA_DIR, "dns_seen.json")
_SEEN_CAP = 12000
_SEEN_SAVE_EVERY = 40

_lock = threading.RLock()
_seen_domains: dict[str, float] = {}  # lower FQDN -> first seen wall time
_session_start = time.time()
_recent_domains: deque[tuple[float, str]] = deque(maxlen=2000)
_last_event_ts: dict[str, float] = {}
_seen_dirty = 0
_seen_loaded = False


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    s = s.lower()
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _tld(name: str) -> str:
    parts = name.rstrip(".").lower().split(".")
    if len(parts) < 2:
        return ""
    return parts[-1]


def _registrable_hint(name: str) -> str:
    """Best-effort eTLD+1-ish (last two labels)."""
    parts = [p for p in name.rstrip(".").lower().split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return parts[0] if parts else name.lower()


def _is_allowlisted(name: str) -> bool:
    low = name.rstrip(".").lower()
    if not low:
        return False
    for suf in _ALLOW_SUFFIXES:
        if low == suf or low.endswith("." + suf):
            return True
    return False


def _is_ip_encode_label(label: str) -> bool:
    if not label:
        return False
    if _IP_ENCODE_RE.match(label):
        return True
    # Digit/hyphen heavy CDN-style labels
    digits = sum(1 for c in label if c.isdigit())
    hyphens = label.count("-")
    if hyphens >= 2 and digits >= 4 and len(label) >= 8:
        return True
    if "---" in label:
        return True
    return False


def _is_dga_ish(name: str) -> bool:
    """Stricter DGA: long label + (hex OR consonant runs); not entropy alone; skip allowlist/IP-encode."""
    low = name.rstrip(".").lower()
    if not low or _is_allowlisted(low):
        return False
    parts = [p for p in low.split(".") if p]
    if not parts:
        return False
    label = parts[0]
    if _is_ip_encode_label(label):
        return False
    if len(label) < _ENTROPY_MIN_LEN:
        return False
    if not _LABEL_RE.match(label):
        return False
    # Hex-only long labels still ok if not allowlisted
    if _HEXISH_RE.match(label.replace("-", "")) or _HEXISH_RE.match(label):
        return True
    # Require consonant runs AND long label; entropy alone is insufficient
    if _CONSONANT_RUN_RE.search(label) and len(label) >= _ENTROPY_MIN_LEN:
        # Digits-heavy alone on CDN-like labels already skipped above
        digits = sum(1 for c in label if c.isdigit())
        if digits >= max(8, len(label) // 2) and "-" in label:
            return False
        return True
    return False


def _is_rare_tld(name: str) -> bool:
    if _is_allowlisted(name):
        return False
    t = _tld(name)
    if not t or t in _COMMON_TLDS:
        return False
    return t in _RARE_TLDS


def _ensure_seen_loaded() -> None:
    global _seen_loaded, _seen_domains
    if _seen_loaded:
        return
    _seen_loaded = True
    try:
        with open(_SEEN_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            cleaned: dict[str, float] = {}
            for k, v in data.items():
                try:
                    cleaned[str(k).lower()] = float(v)
                except (TypeError, ValueError):
                    continue
            # Cap on load
            if len(cleaned) > _SEEN_CAP:
                items = sorted(cleaned.items(), key=lambda kv: kv[1], reverse=True)[:_SEEN_CAP]
                cleaned = dict(items)
            _seen_domains.update(cleaned)
    except Exception:
        pass


def _save_seen() -> None:
    global _seen_dirty
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        with _lock:
            items = sorted(_seen_domains.items(), key=lambda kv: kv[1], reverse=True)[:_SEEN_CAP]
            payload = dict(items)
        tmp = _SEEN_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, _SEEN_PATH)
        _seen_dirty = 0
    except Exception:
        pass


def _note_domain(name: str, now: float) -> bool:
    """Return True if newly seen (persisted across restarts via dns_seen.json)."""
    global _seen_dirty
    key = name.rstrip(".").lower()
    if not key or "." not in key:
        return False
    _ensure_seen_loaded()
    with _lock:
        if key in _seen_domains:
            return False
        _seen_domains[key] = now
        _recent_domains.append((now, key))
        _seen_dirty += 1
        if len(_seen_domains) > _SEEN_CAP + 2000:
            cutoff = now - 14 * 86400
            dead = [k for k, t in _seen_domains.items() if t < cutoff]
            for k in dead[:5000]:
                _seen_domains.pop(k, None)
            if len(_seen_domains) > _SEEN_CAP:
                keep = sorted(_seen_domains.items(), key=lambda kv: kv[1], reverse=True)[:_SEEN_CAP]
                _seen_domains.clear()
                _seen_domains.update(keep)
        do_save = _seen_dirty >= _SEEN_SAVE_EVERY
    if do_save:
        _save_seen()
    return True


def _queries_snapshot() -> tuple[bool, list[dict[str, Any]]]:
    if tw_dns_log is None:
        return False, []
    try:
        st = tw_dns_log.status()
        q = tw_dns_log.queries() if hasattr(tw_dns_log, "queries") else []
        return bool(st.get("ok")), list(q or [])
    except Exception:
        return False, []


def analyze_queries() -> dict[str, Any]:
    """Refresh domain memory from dns_log; return flagged domain sets."""
    _ensure_seen_loaded()
    ok, queries = _queries_snapshot()
    now = time.time()
    rare: dict[str, str] = {}  # domain -> reason
    new_count = 0
    for ev in queries:
        name = (ev.get("name") or "").strip().rstrip(".")
        if not name or "." not in name:
            continue
        low = name.lower()
        if _is_allowlisted(low):
            _note_domain(low, now)  # learn but never rare
            continue
        is_new = _note_domain(low, now)
        if is_new:
            new_count += 1
        reasons: list[str] = []
        if is_new and (now - _session_start) > 30:
            reasons.append("newly-seen")
        if _is_dga_ish(low):
            reasons.append("high-entropy")
        if _is_rare_tld(low):
            reasons.append("rare-tld")
        if "high-entropy" in reasons or "rare-tld" in reasons:
            rare[low] = "+".join(reasons)
        elif "newly-seen" in reasons and _is_rare_tld(low):
            rare[low] = "newly-seen+rare-tld"
        elif "newly-seen" in reasons and len(low.split(".")[0]) >= 20 and _is_dga_ish(low):
            rare[low] = "newly-seen+long-label"
    return {
        "ok": ok,
        "rare": rare,
        "new_count": new_count,
        "query_count": len(queries),
    }


def _burst_pids(rows: list[dict[str, Any]]) -> dict[int, list[str]]:
    """PIDs with many distinct dns query names (excludes browsers)."""
    by_pid: dict[int, set[str]] = defaultdict(set)
    browser_pids: set[int] = set()
    for r in rows:
        pid = r.get("pid")
        if pid is None:
            continue
        pname = (r.get("process") or "").lower()
        if pname in _BROWSER_NAMES:
            browser_pids.add(int(pid))
            continue
        for n in r.get("dns_queries") or []:
            if n:
                by_pid[int(pid)].add(str(n).lower().rstrip("."))
        host = (r.get("hostname") or "").lower().rstrip(".")
        if host and "." in host:
            by_pid[int(pid)].add(host)
    return {
        pid: sorted(names)
        for pid, names in by_pid.items()
        if pid not in browser_pids and len(names) >= _BURST_MIN_UNIQUE
    }


def attach_dns_signals(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add dns_rare / dns_burst signals onto connection rows. No-op if DNS limited empty."""
    try:
        analysis = analyze_queries()
    except Exception:
        return rows
    rare = analysis.get("rare") or {}
    burst = _burst_pids(rows)

    now = time.time()
    with _lock:
        recent = [(t, d) for t, d in _recent_domains if now - t <= _BURST_WINDOW_SEC]
    recent_names = {d for _, d in recent}

    for r in rows:
        signals = list(r.get("signals") or [])
        existing = {str(s.get("id")) for s in signals}
        names: list[str] = []
        for n in r.get("dns_queries") or []:
            if n:
                names.append(str(n).lower().rstrip("."))
        host = (r.get("hostname") or "").lower().rstrip(".")
        if host:
            names.append(host)

        # dns_rare — exact or child-of-flagged only (never parent-over-match)
        if "dns_rare" not in existing:
            hit_name = None
            hit_reason = None
            for n in names:
                if _is_allowlisted(n):
                    continue
                if n in rare:
                    hit_name = n
                    hit_reason = rare[n]
                    break
                for rn, reason in rare.items():
                    # Child of flagged FQDN only: n endswith '.'+rn — NEVER rn endswith '.'+n
                    if n == rn or n.endswith("." + rn):
                        hit_name = rn
                        hit_reason = reason
                        break
                if hit_name:
                    break
            if hit_name:
                sev = "medium" if ("high-entropy" in (hit_reason or "") or "rare-tld" in (hit_reason or "")) else "low"
                signals.append({
                    "id": "dns_rare",
                    "label": "dns_rare",
                    "severity": sev,
                    "detail": f"Unusual DNS name {hit_name} ({hit_reason})",
                })
                existing.add("dns_rare")
                _maybe_event("dns_rare", {"name": hit_name, "reason": hit_reason, "pid": r.get("pid")})

        # dns_burst
        pid = r.get("pid")
        pname = (r.get("process") or "").lower()
        if (
            pid is not None
            and pname not in _BROWSER_NAMES
            and "dns_burst" not in existing
            and int(pid) in burst
        ):
            blist = burst[int(pid)]
            newish = [n for n in blist if n in recent_names or n in rare]
            rareish = [n for n in blist if _is_rare_tld(n) or _is_dga_ish(n)]
            if len(blist) >= _BURST_MIN_UNIQUE and (
                len(newish) >= _BURST_MIN_NEWISH or len(rareish) >= 3
            ):
                signals.append({
                    "id": "dns_burst",
                    "label": "dns_burst",
                    "severity": "medium",
                    "detail": (
                        f"Bursty unique DNS names from PID {pid} "
                        f"({len(blist)} distinct; e.g. {', '.join(blist[:3])})"
                    ),
                })
                existing.add("dns_burst")
                _maybe_event("dns_burst", {"pid": pid, "count": len(blist), "sample": blist[:5]})

        r["signals"] = signals[:8]
    return rows


def _maybe_event(kind: str, payload: dict[str, Any]) -> None:
    if tw_history is None:
        return
    key = f"{kind}|{payload.get('name') or payload.get('pid')}"
    now = time.time()
    with _lock:
        last = _last_event_ts.get(key, 0.0)
        if now - last < 300:
            return
        _last_event_ts[key] = now
    try:
        tw_history.record_event(kind, payload)
    except Exception:
        pass
