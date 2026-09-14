"""Threat-intel list cache + matcher (Phase B).

Fetches well-known free IP/domain lists into data/intel/, matches remote
endpoints, never crashes the app on network failure (falls back to cache).

Refresh: first boot (background) + every 12h, or POST /api/intel/refresh.
VirusTotal: stub only — vt_enabled = False (no hash upload / query until owner GO).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# --- VirusTotal stub (Phase B) ----------------------------------------------
# VT upload/query blocked until owner GO. Do not set True or call VT APIs.
vt_enabled = False

ROOT = os.path.dirname(os.path.abspath(__file__))
INTEL_DIR = os.path.join(ROOT, "data", "intel")
META_PATH = os.path.join(INTEL_DIR, "meta.json")

REFRESH_INTERVAL_SEC = 12 * 3600  # conservative; do not hammer third parties
FETCH_TIMEOUT = 25
USER_AGENT = "Mozilla/5.0"

# Sources: free plain-text lists suitable for local matching.
# License notes live in NOTES.md (Spamhaus DROP = spam blocking / personal local use).
SOURCES: list[dict[str, Any]] = [
    {
        "id": "feodo_ip",
        "name": "abuse.ch Feodo Tracker IP blocklist",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "kind": "ip_lines",
        "severity": "high",
        "attribution": "https://feodotracker.abuse.ch/ — CC0 / free for non-commercial",
    },
    {
        "id": "feodo_recommended",
        "name": "abuse.ch Feodo Tracker IP (recommended)",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "kind": "ip_lines",
        "severity": "high",
        "attribution": "https://feodotracker.abuse.ch/ — recommended C2 list; SSLBL IP list deprecated 2025-01-03 so not used",
    },
    {
        "id": "urlhaus_hosts",
        "name": "abuse.ch URLhaus hostfile",
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "kind": "hosts",
        "severity": "high",
        "attribution": "https://urlhaus.abuse.ch/ — CC0",
    },
    {
        "id": "spamhaus_drop",
        "name": "Spamhaus DROP",
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "kind": "cidr_lines",
        "severity": "medium",
        "attribution": "https://www.spamhaus.org/drop/ — DROP for spam blocking; personal/local use only",
    },
    {
        "id": "spamhaus_edrop",
        "name": "Spamhaus EDROP",
        "url": "https://www.spamhaus.org/drop/edrop.txt",
        "kind": "cidr_lines",
        "severity": "medium",
        "attribution": "https://www.spamhaus.org/drop/ — EDROP extension; personal/local use only",
    },
    # Review 4: official ThreatFox recent IP:port CSV (not GitHub mirror; not full dump)
    {
        "id": "threatfox_ip",
        "name": "ThreatFox recent IP-port (abuse.ch)",
        "url": "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
        "kind": "threatfox_csv",
        "severity": "high",
        "attribution": "ThreatFox / abuse.ch — https://threatfox.abuse.ch/export/csv/ip-port/recent/ (no Auth-Key; recent export only)",
        "max_bytes": 4000000,
    },
    {
        "id": "tor_exits",
        "name": "Tor Project bulk exit list",
        "url": "https://check.torproject.org/torbulkexitlist",
        "kind": "ip_lines",
        "severity": "medium",
        "attribution": "https://check.torproject.org/torbulkexitlist - Tor Project exit relays; personal/local use",
        "max_bytes": 2000000,
    },
    {
        "id": "spamhaus_dropv6",
        "name": "Spamhaus DROPv6",
        "url": "https://www.spamhaus.org/drop/dropv6.txt",
        "kind": "cidr_lines",
        "severity": "medium",
        "attribution": "https://www.spamhaus.org/drop/ - DROPv6 IPv6; personal/local use only",
        "max_bytes": 2000000,
    },
]

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
_CIDR_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)/(?:3[0-2]|[12]?\d)\b"
)
_HOST_RE = re.compile(
    r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([A-Za-z0-9_.\-]+)\s*$",
    re.IGNORECASE,
)

_lock = threading.RLock()
_ips: set[str] = set()
_cidrs: list = []  # IPv4Network | IPv6Network
_domains: set[str] = set()  # lowercased hostnames
_by_source: dict[str, dict[str, object]] = {}
_source_status: dict[str, dict[str, Any]] = {}
_last_refresh_ok: float | None = None
_last_refresh_attempt: float | None = None
_refreshing = False
_started = False


def _ensure_dir() -> None:
    try:
        os.makedirs(INTEL_DIR, exist_ok=True)
    except OSError:
        pass


def _cache_path(source_id: str) -> str:
    return os.path.join(INTEL_DIR, f"{source_id}.txt")


def _load_meta() -> dict[str, Any]:
    try:
        with open(META_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_meta(meta: dict[str, Any]) -> None:
    _ensure_dir()
    try:
        tmp = META_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        os.replace(tmp, META_PATH)
    except OSError:
        pass


def _fetch_text(url: str) -> tuple[str | None, str | None]:
    """Return (text, error). Never raises."""
    try:
        req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/plain,*/*"})
        with urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            raw = resp.read()
        # Some lists are latin-1 / utf-8
        try:
            return raw.decode("utf-8"), None
        except UnicodeDecodeError:
            return raw.decode("latin-1", errors="replace"), None
    except HTTPError as e:
        return None, f"HTTP {e.code}"
    except URLError as e:
        return None, f"URL error: {e.reason}"
    except Exception as e:
        return None, str(e)


_IPV6_CIDR_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}/(?:12[0-8]|1[01]\d|[1-9]?\d)\b"
)
_IPV6_ADDR_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b"
)

def _parse_source(kind: str, text: str) -> tuple[set[str], list[str], set[str]]:
    """Return (ips, cidr_strs, domains)."""
    ips: set[str] = set()
    cidrs: list[str] = []
    domains: set[str] = set()
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith(";"):
            continue
        # DROP format: "1.2.3.0/24 ; SBL..."
        if ";" in s and kind == "cidr_lines":
            s = s.split(";", 1)[0].strip()
        if kind == "hosts":
            m = _HOST_RE.match(s)
            if m:
                host = m.group(1).lower().rstrip(".")
                if host and host not in ("localhost", "local"):
                    domains.add(host)
                    # also try extracting embedded IPs rarely present
                continue
            # fallback: bare domain lines
            if " " not in s and "/" not in s and _IP_RE.fullmatch(s) is None:
                if "." in s and not s.startswith("#"):
                    domains.add(s.lower().rstrip("."))
            continue
        if kind == "cidr_lines":
            m = _CIDR_RE.search(s)
            if m:
                cidrs.append(m.group(0))
                continue
            m6 = _IPV6_CIDR_RE.search(s)
            if m6:
                cidrs.append(m6.group(0))
                continue
            m2 = _IP_RE.search(s)
            if m2:
                ips.add(m2.group(0))
                continue
            m6a = _IPV6_ADDR_RE.search(s)
            if m6a and ":" in m6a.group(0):
                ips.add(m6a.group(0))
            continue
        if kind == "threatfox_csv":
            # CSV with quoted fields; skip # comments. Extract first IPv4 in the row.
            # Typical: "ioc","id","..." or ip:port in a field — take IP only.
            if s.startswith('"') or "," in s:
                # Strip quotes loosely and scan for IPv4
                for m in _IP_RE.finditer(s.replace('"', '')):
                    ips.add(m.group(0))
                    break
            else:
                for m in _IP_RE.finditer(s):
                    ips.add(m.group(0))
                    break
            continue
        # ip_lines (and default)
        for m in _IP_RE.finditer(s):
            ips.add(m.group(0))
        for m in _CIDR_RE.finditer(s):
            cidrs.append(m.group(0))
        for m in _IPV6_CIDR_RE.finditer(s):
            cidrs.append(m.group(0))
        for m in _IPV6_ADDR_RE.finditer(s):
            if ":" in m.group(0) and "/" not in m.group(0):
                ips.add(m.group(0))
    return ips, cidrs, domains


def _rebuild_indexes() -> None:
    """Load all cached source files into memory sets (per-source + merged)."""
    global _ips, _cidrs, _domains, _by_source
    ips: set[str] = set()
    cidr_nets: list = []  # IPv4Network | IPv6Network
    domains: set[str] = set()
    by_source: dict[str, dict[str, object]] = {}
    meta = _load_meta()
    sources_meta = meta.get("sources") or {}

    for src in SOURCES:
        sid = src["id"]
        path = _cache_path(sid)
        st: dict[str, Any] = {
            "id": sid,
            "name": src["name"],
            "url": src["url"],
            "severity": src["severity"],
            "cached": False,
            "fetched_at": None,
            "count_ips": 0,
            "count_cidrs": 0,
            "count_domains": 0,
            "error": None,
        }
        entry_ips: set[str] = set()
        entry_cidrs: list = []  # IPv4Network | IPv6Network
        entry_domains: set[str] = set()
        if not os.path.isfile(path):
            prev = sources_meta.get(sid) or {}
            st["error"] = prev.get("error") or "no cache yet"
            _source_status[sid] = st
            by_source[sid] = {"ips": entry_ips, "cidrs": entry_cidrs, "domains": entry_domains, "severity": src["severity"]}
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text_body = f.read()
            pip, pcidrs, pdom = _parse_source(src["kind"], text_body)
            entry_ips = set(pip)
            entry_domains = set(pdom)
            for c in pcidrs:
                try:
                    entry_cidrs.append(ipaddress.ip_network(c, strict=False))
                except ValueError:
                    continue
            ips |= entry_ips
            domains |= entry_domains
            cidr_nets.extend(entry_cidrs)
            st["cached"] = True
            st["count_ips"] = len(entry_ips)
            st["count_cidrs"] = len(entry_cidrs)
            st["count_domains"] = len(entry_domains)
            prev = sources_meta.get(sid) or {}
            st["fetched_at"] = prev.get("fetched_at")
            st["error"] = prev.get("error")
            try:
                st["mtime"] = os.path.getmtime(path)
            except OSError:
                pass
        except Exception as e:
            st["error"] = str(e)
        _source_status[sid] = st
        by_source[sid] = {
            "ips": entry_ips,
            "cidrs": entry_cidrs,
            "domains": entry_domains,
            "severity": src["severity"],
        }

    with _lock:
        _ips = ips
        _cidrs = cidr_nets
        _domains = domains
        _by_source = by_source



def refresh(*, force: bool = False) -> dict[str, Any]:
    """Fetch all sources; on failure keep previous cache. Never raises."""
    global _refreshing, _last_refresh_ok, _last_refresh_attempt
    with _lock:
        if _refreshing:
            return status()
        _refreshing = True
    _ensure_dir()
    _last_refresh_attempt = time.time()
    meta = _load_meta()
    sources_meta: dict[str, Any] = dict(meta.get("sources") or {})
    any_ok = False
    results: dict[str, Any] = {}

    try:
        for src in SOURCES:
            sid = src["id"]
            text, err = _fetch_text(src["url"])
            entry: dict[str, Any] = {
                "id": sid,
                "name": src["name"],
                "url": src["url"],
                "ok": False,
                "error": err,
                "fetched_at": None,
            }
            if text is not None and len(text) > 0:
                raw_bytes = len(text.encode("utf-8", errors="replace"))
                max_b = int(src.get("max_bytes") or 0)
                if max_b and raw_bytes > max_b:
                    entry["error"] = f"skipped oversized ({raw_bytes} > {max_b} bytes)"
                    sources_meta[sid] = {
                        **(sources_meta.get(sid) or {}),
                        "error": entry["error"],
                        "last_attempt": time.time(),
                    }
                    results[sid] = entry
                    continue
                path = _cache_path(sid)
                try:
                    tmp = path + ".tmp"
                    with open(tmp, "w", encoding="utf-8") as f:
                        f.write(text)
                    os.replace(tmp, path)
                    entry["ok"] = True
                    entry["error"] = None
                    entry["fetched_at"] = time.time()
                    entry["bytes"] = len(text.encode("utf-8", errors="replace"))
                    any_ok = True
                    sources_meta[sid] = {
                        "fetched_at": entry["fetched_at"],
                        "error": None,
                        "url": src["url"],
                        "name": src["name"],
                    }
                except OSError as e:
                    entry["error"] = f"write failed: {e}"
                    sources_meta[sid] = {
                        **(sources_meta.get(sid) or {}),
                        "error": entry["error"],
                    }
            else:
                # keep last cache; record error
                sources_meta[sid] = {
                    **(sources_meta.get(sid) or {}),
                    "error": err or "empty response",
                    "last_attempt": time.time(),
                }
            results[sid] = entry

        meta["sources"] = sources_meta
        meta["last_refresh_attempt"] = _last_refresh_attempt
        if any_ok:
            _last_refresh_ok = time.time()
            meta["last_refresh_ok"] = _last_refresh_ok
        _save_meta(meta)
        _rebuild_indexes()
    finally:
        with _lock:
            _refreshing = False

    out = status()
    out["results"] = results
    out["forced"] = force
    return out


def status() -> dict[str, Any]:
    with _lock:
        return {
            "ok": True,
            "vt_enabled": vt_enabled,
            "dir": INTEL_DIR,
            "last_refresh_ok": _last_refresh_ok,
            "last_refresh_attempt": _last_refresh_attempt,
            "refreshing": _refreshing,
            "interval_hours": REFRESH_INTERVAL_SEC / 3600,
            "counts": {
                "ips": len(_ips),
                "cidrs": len(_cidrs),
                "domains": len(_domains),
            },
            "sources": list(_source_status.values()) or [
                {
                    "id": s["id"],
                    "name": s["name"],
                    "url": s["url"],
                    "severity": s["severity"],
                    "cached": False,
                }
                for s in SOURCES
            ],
            "attribution": [s["attribution"] for s in SOURCES],
        }


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
        return bool(
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_unspecified
            or addr.is_multicast
            or addr.is_reserved
        )
    except ValueError:
        return True


def match(
    ip: str | None,
    hostname: str | None = None,
    domains: list[str] | None = None,
) -> dict[str, Any]:
    """Match remote IP/hostname/dns_queries against loaded lists. Never flags private IPs.

    Note: IP/CIDR lists support IPv4 and IPv6 (DROPv6). Domain lists match hostname
    and any attached dns_queries names.
    """
    empty = {"hit": False, "lists": [], "severity": None}
    extra = [d for d in (domains or []) if d]
    if not ip and not hostname and not extra:
        return empty
    lists: list[str] = []
    severities: list[str] = []

    with _lock:
        by_source = dict(_by_source)

    if ip and not _is_private(ip):
        clean = ip.split("%")[0]
        try:
            addr = ipaddress.ip_address(clean)
        except ValueError:
            addr = None
        for sid, bucket in by_source.items():
            hit = False
            if clean in bucket.get("ips", set()):  # type: ignore[arg-type]
                hit = True
            elif addr is not None:
                for net in bucket.get("cidrs", []):  # type: ignore[assignment]
                    try:
                        if addr in net:
                            hit = True
                            break
                    except Exception:
                        continue
            if hit:
                lists.append(sid)
                severities.append(str(bucket.get("severity") or "high"))

    names_to_check: list[str] = []
    if hostname:
        h0 = hostname.lower().rstrip(".")
        if h0:
            names_to_check.append(h0)
    for d in extra:
        dn = str(d).lower().rstrip(".")
        if dn and dn not in names_to_check:
            names_to_check.append(dn)

    for host in names_to_check:
        for sid, bucket in by_source.items():
            domain_set = bucket.get("domains") or set()
            hit_dom = False
            if host in domain_set:  # type: ignore[operator]
                hit_dom = True
            else:
                parts = host.split(".")
                for i in range(len(parts) - 1):
                    suffix = ".".join(parts[i:])
                    if suffix in domain_set:  # type: ignore[operator]
                        hit_dom = True
                        break
            if hit_dom:
                if sid not in lists:
                    lists.append(sid)
                severities.append(str(bucket.get("severity") or "high"))

    if not lists:
        return empty
    sev = "high" if "high" in severities else ("medium" if "medium" in severities else "low")
    return {"hit": True, "lists": sorted(set(lists)), "severity": sev}



def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def attach_intel(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for r in rows:
        rip = r.get("remote_ip")
        if r.get("private_remote") or not rip:
            r["intel"] = {"hit": False, "lists": [], "severity": None}
            continue
        r["intel"] = match(rip, r.get("hostname"), domains=list(r.get("dns_queries") or []))
    return rows


def _maybe_periodic_refresh() -> None:
    while True:
        time.sleep(60)
        try:
            last = _last_refresh_ok or 0.0
            if time.time() - last >= REFRESH_INTERVAL_SEC:
                refresh(force=False)
        except Exception:
            pass


def start_background() -> None:
    """Lazy start: load cache immediately, fetch in background (non-blocking)."""
    global _started, _last_refresh_ok
    if _started:
        return
    _started = True
    _ensure_dir()
    meta = _load_meta()
    _last_refresh_ok = meta.get("last_refresh_ok")
    _rebuild_indexes()

    def _boot():
        try:
            # Always attempt a refresh on first boot if never succeeded, else if stale
            need = True
            if _last_refresh_ok and (time.time() - float(_last_refresh_ok)) < REFRESH_INTERVAL_SEC:
                need = False
            # If we have no cache at all, always fetch
            if not any(os.path.isfile(_cache_path(s["id"])) for s in SOURCES):
                need = True
            if need:
                refresh(force=False)
        except Exception:
            pass

    threading.Thread(target=_boot, name="tw-intel-boot", daemon=True).start()
    threading.Thread(target=_maybe_periodic_refresh, name="tw-intel-periodic", daemon=True).start()
