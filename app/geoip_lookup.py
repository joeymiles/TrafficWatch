"""Offline-first GeoIP lookup with local MMDB + JSON cache.

Prefers DB-IP City Lite (free for personal / non-commercial use).
Downloads once into ./data/ if missing. No API key required.
"""
from __future__ import annotations

import gzip
import os
import json
import shutil
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
CACHE_PATH = DATA_DIR / "geo_cache.json"
MMDB_PATH = DATA_DIR / "dbip-city-lite.mmdb"
GEO_SKIP_PATH = DATA_DIR / "geo.skip"
_allow_download = True

IPINFO_MMDB_PATH = DATA_DIR / "ipinfo_lite.mmdb"
IPINFO_TOKEN_FILE = DATA_DIR / "ipinfo.token"
IPINFO_MAX_BYTES = 80_000_000  # hard size limit
IPINFO_URL = "https://ipinfo.io/data/ipinfo_lite.mmdb"
IPINFO_ATTR = "IPinfo Lite (https://ipinfo.io/lite) — CC BY-SA 4.0"

_HOSTING_ORG_HINTS = (
    "amazon", "aws", "google", "gcp", "microsoft", "azure", "digitalocean",
    "hetzner", "ovh", "linode", "akamai", "cloudflare", "fastly", "vultr",
    "oracle cloud", "oci", "alibaba", "tencent", "contabo", "scaleway",
    "hostinger", "choopa", "leaseweb", "rackspace", "softlayer", "ibm cloud",
)

_ipinfo_reader = None
_ipinfo_status: dict = {"ok": False, "blocked": None, "msg": None}

# Neutral fallback pin when public-IP detect is off/fails. Not a residence.
# User can set a real home pin in the UI. Contiguous-US geographic center.
ASSUMED_HOME = {
    "ip": None,
    "lat": 39.8283,
    "lon": -98.5795,
    "city": None,
    "region": None,
    "country": "United States",
    "country_code": "US",
    "org": None,
    "asn": None,
    "source": "assumed_home",
    "label": "Home (set in UI)",
}

# In-memory cache: ip -> result dict
_cache: dict[str, dict[str, Any]] = {}
_reader = None
_reader_error: str | None = None


def _month_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def load_disk_cache() -> None:
    global _cache
    ensure_data_dir()
    if CACHE_PATH.exists():
        try:
            _cache = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        except Exception:
            _cache = {}


def save_disk_cache() -> None:
    ensure_data_dir()
    try:
        # Cap cache size
        items = list(_cache.items())
        if len(items) > 5000:
            items = items[-4000:]
            _cache.clear()
            _cache.update(items)
        CACHE_PATH.write_text(json.dumps(_cache), encoding="utf-8")
    except Exception:
        pass



def geo_download_allowed() -> bool:
    """False when the user declined MMDB download or data/geo.skip exists."""
    if not _allow_download:
        return False
    try:
        if GEO_SKIP_PATH.exists():
            return False
    except Exception:
        pass
    return True


def set_allow_download(allowed: bool) -> None:
    global _allow_download
    _allow_download = bool(allowed)


def download_dbip_lite(force: bool = False) -> tuple[bool, str]:
    """Download free DB-IP City Lite MMDB for the current month (or fall back)."""
    ensure_data_dir()
    present = MMDB_PATH.exists() and not force and MMDB_PATH.stat().st_size > 1_000_000
    if present:
        return True, f"Already present: {MMDB_PATH}"
    if not geo_download_allowed():
        return False, "GeoIP download skipped (--no-geo-download or data/geo.skip)"

    month = _month_stamp()
    # Try current month then previous month
    candidates = [
        f"https://download.db-ip.com/free/dbip-city-lite-{month}.mmdb.gz",
    ]
    # previous month
    y, m = map(int, month.split("-"))
    if m == 1:
        prev = f"{y-1}-12"
    else:
        prev = f"{y}-{m-1:02d}"
    candidates.append(f"https://download.db-ip.com/free/dbip-city-lite-{prev}.mmdb.gz")

    last_err = ""
    for url in candidates:
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".mmdb.gz") as tmp:
                tmp_path = Path(tmp.name)
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=120) as resp, open(tmp_path, "wb") as out:
                shutil.copyfileobj(resp, out)
            # decompress
            out_path = MMDB_PATH.with_suffix(".mmdb.tmp")
            with gzip.open(tmp_path, "rb") as gz, open(out_path, "wb") as out:
                shutil.copyfileobj(gz, out)
            out_path.replace(MMDB_PATH)
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass
            return True, f"Downloaded {url} -> {MMDB_PATH}"
        except Exception as e:
            last_err = str(e)
            continue
    return False, f"DB-IP download failed: {last_err}"


def open_reader() -> tuple[bool, str]:
    global _reader, _reader_error
    if _reader is not None:
        return True, "ok"
    try:
        import geoip2.database

        if not MMDB_PATH.exists():
            if not geo_download_allowed():
                _reader_error = "MMDB missing; download skipped"
                return False, _reader_error
            ok, msg = download_dbip_lite()
            if not ok:
                _reader_error = msg
                return False, msg
        _reader = geoip2.database.Reader(str(MMDB_PATH))
        _reader_error = None
        return True, "opened"
    except Exception as e:
        _reader_error = str(e)
        return False, str(e)


def _from_mmdb(ip: str) -> dict[str, Any] | None:
    if _reader is None:
        return None
    try:
        rec = _reader.city(ip)
        lat = rec.location.latitude
        lon = rec.location.longitude
        if lat is None or lon is None:
            return {
                "ip": ip,
                "lat": None,
                "lon": None,
                "city": rec.city.name,
                "region": rec.subdivisions.most_specific.name if rec.subdivisions else None,
                "country": rec.country.name,
                "country_code": rec.country.iso_code,
                "org": None,
                "asn": None,
                "source": "dbip",
                "resolvable": False,
            }
        return {
            "ip": ip,
            "lat": float(lat),
            "lon": float(lon),
            "city": rec.city.name,
            "region": rec.subdivisions.most_specific.name if rec.subdivisions else None,
            "country": rec.country.name,
            "country_code": rec.country.iso_code,
            "org": None,
            "asn": None,
            "source": "dbip",
            "resolvable": True,
        }
    except Exception:
        return None



def resolve_ipinfo_token() -> str | None:
    """Token from env IPINFO_TOKEN / IPINFO_LITE_TOKEN or data/ipinfo.token. Never invent."""
    for key in ("IPINFO_TOKEN", "IPINFO_LITE_TOKEN"):
        v = (os.environ.get(key) or "").strip()
        if v:
            return v
    try:
        if IPINFO_TOKEN_FILE.exists():
            raw = IPINFO_TOKEN_FILE.read_text(encoding="utf-8").strip()
            if raw and not raw.startswith("#"):
                return raw.splitlines()[0].strip()
    except Exception:
        pass
    return None


def hosting_heuristic(org: str | None) -> bool | None:
    if not org:
        return None
    low = org.lower()
    return any(h in low for h in _HOSTING_ORG_HINTS)


def download_ipinfo_lite(force: bool = False) -> tuple[bool, str]:
    """Download IPinfo Lite MMDB if token present. HTTPS official, size limits, generic UA."""
    global _ipinfo_status
    ensure_data_dir()
    token = resolve_ipinfo_token()
    if not token:
        _ipinfo_status = {
            "ok": False,
            "blocked": "BLOCKED_IPINFO_TOKEN",
            "msg": "No IPINFO_TOKEN / IPINFO_LITE_TOKEN / data/ipinfo.token — ASN download skipped",
        }
        return False, "BLOCKED_IPINFO_TOKEN"
    if IPINFO_MMDB_PATH.exists() and not force and IPINFO_MMDB_PATH.stat().st_size > 100_000:
        _ipinfo_status = {"ok": True, "blocked": None, "msg": f"present {IPINFO_MMDB_PATH.name}"}
        return True, f"Already present: {IPINFO_MMDB_PATH}"

    url = f"{IPINFO_URL}?token={token}"
    prev_size = IPINFO_MMDB_PATH.stat().st_size if IPINFO_MMDB_PATH.exists() else 0
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with tempfile.NamedTemporaryFile(delete=False, suffix=".mmdb") as tmp:
            tmp_path = Path(tmp.name)
        written = 0
        with urllib.request.urlopen(req, timeout=120) as resp, open(tmp_path, "wb") as out:
            while True:
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > IPINFO_MAX_BYTES:
                    try:
                        tmp_path.unlink(missing_ok=True)
                    except Exception:
                        pass
                    _ipinfo_status = {"ok": False, "blocked": None, "msg": "size limit exceeded"}
                    return False, "IPinfo download exceeded size limit"
                out.write(chunk)
        # Sanity: if previous exists and new size swings wildly, keep previous
        if prev_size > 100_000:
            ratio = written / prev_size if prev_size else 1.0
            if ratio < 0.4 or ratio > 2.5:
                try:
                    tmp_path.unlink(missing_ok=True)
                except Exception:
                    pass
                _ipinfo_status = {
                    "ok": True,
                    "blocked": None,
                    "msg": f"kept previous cache (size swing {prev_size}->{written})",
                }
                return True, _ipinfo_status["msg"]
        Path(tmp_path).replace(IPINFO_MMDB_PATH)
        _ipinfo_status = {"ok": True, "blocked": None, "msg": f"Downloaded ipinfo_lite ({written} bytes)"}
        return True, _ipinfo_status["msg"]
    except Exception as e:
        _ipinfo_status = {"ok": False, "blocked": None, "msg": str(e)[:200]}
        return False, f"IPinfo download failed: {e}"


def open_ipinfo_reader() -> tuple[bool, str]:
    global _ipinfo_reader, _ipinfo_status
    if _ipinfo_reader is not None:
        return True, "ok"
    if not IPINFO_MMDB_PATH.exists():
        ok, msg = download_ipinfo_lite()
        if not ok:
            return False, msg
    try:
        import geoip2.database
        _ipinfo_reader = geoip2.database.Reader(str(IPINFO_MMDB_PATH))
        _ipinfo_status = {"ok": True, "blocked": None, "msg": "opened", "attribution": IPINFO_ATTR}
        return True, "opened"
    except Exception as e:
        _ipinfo_status = {"ok": False, "blocked": None, "msg": str(e)[:200]}
        return False, str(e)


def _from_ipinfo(ip: str) -> dict[str, Any]:
    """Best-effort ASN/org from IPinfo Lite (fields stay empty if unavailable).

    IPinfo Lite is a custom MMDB (bundle_location_lite); geoip2 typed methods
    do not apply — read via the underlying maxminddb reader.
    """
    empty = {"asn": None, "org": None, "as_domain": None, "as_name": None, "hosting": None}
    if _ipinfo_reader is None:
        return empty
    try:
        db = getattr(_ipinfo_reader, "_db_reader", None)
        rec = None
        if db is not None:
            try:
                rec = db.get(ip)
            except Exception:
                rec = None
        if rec is None:
            # Fallback: maxminddb open (should be rare)
            try:
                import maxminddb
                with maxminddb.open_database(str(IPINFO_MMDB_PATH)) as mdb:
                    rec = mdb.get(ip)
            except Exception:
                return empty
        if not isinstance(rec, dict):
            return empty
        asn = rec.get("asn") or rec.get("as")
        as_name = rec.get("as_name") or rec.get("asn_name")
        as_domain = rec.get("as_domain") or rec.get("asn_domain")
        org = as_name or rec.get("org")
        if asn is not None and not str(asn).upper().startswith("AS"):
            try:
                asn = f"AS{int(asn)}"
            except Exception:
                asn = str(asn)
        elif asn is not None:
            asn = str(asn)
        org_s = str(org).strip() if org else None
        return {
            "asn": asn,
            "org": org_s,
            "as_domain": str(as_domain).strip() if as_domain else None,
            "as_name": str(as_name).strip() if as_name else None,
            "hosting": hosting_heuristic(org_s),
        }
    except Exception:
        return empty



def ipinfo_status() -> dict:
    return dict(_ipinfo_status)


def lookup_cached(ip: str | None) -> dict[str, Any] | None:
    """Return geo only from existing memory/disk cache (or cheap private).

    Lite snapshot path: no MMDB open/download, no IPinfo upgrade, no miss fill.
    """
    if not ip:
        return None
    if ip in _cache:
        return _cache[ip]
    try:
        from connections import _is_private_or_local
        if _is_private_or_local(ip):
            result = {
                "ip": ip,
                "lat": None,
                "lon": None,
                "city": None,
                "region": None,
                "country": "Private/Local",
                "country_code": None,
                "org": None,
                "asn": None,
                "source": "private",
                "resolvable": False,
                "private": True,
            }
            _cache[ip] = result
            return result
    except Exception:
        pass
    return None


def lookup(ip: str | None) -> dict[str, Any]:
    if not ip:
        return {"ip": ip, "resolvable": False, "private": True, "source": "none"}
    if ip in _cache:
        hit = _cache[ip]
        # Tier 0: upgrade cached rows missing ASN once IPinfo Lite is available
        if (
            not hit.get("private")
            and not hit.get("asn")
            and (_ipinfo_reader is not None or IPINFO_MMDB_PATH.exists())
        ):
            if _ipinfo_reader is None:
                try:
                    open_ipinfo_reader()
                except Exception:
                    pass
            extra = _from_ipinfo(ip)
            if extra.get("asn") or extra.get("org"):
                hit = dict(hit)
                if extra.get("asn"):
                    hit["asn"] = extra["asn"]
                if extra.get("org") and not hit.get("org"):
                    hit["org"] = extra["org"]
                hit["as_name"] = extra.get("as_name")
                hit["as_domain"] = extra.get("as_domain")
                hit["hosting"] = extra.get("hosting")
                hit["asn_source"] = "ipinfo_lite"
                _cache[ip] = hit
        return hit

    # private / local
    from connections import _is_private_or_local

    if _is_private_or_local(ip):
        result = {
            "ip": ip,
            "lat": None,
            "lon": None,
            "city": None,
            "region": None,
            "country": "Private/Local",
            "country_code": None,
            "org": None,
            "asn": None,
            "source": "private",
            "resolvable": False,
            "private": True,
        }
        _cache[ip] = result
        return result

    if _reader is None:
        open_reader()

    result = _from_mmdb(ip)
    if result is None:
        result = {
            "ip": ip,
            "lat": None,
            "lon": None,
            "city": None,
            "region": None,
            "country": "Unknown",
            "country_code": None,
            "org": None,
            "asn": None,
            "source": "miss",
            "resolvable": False,
            "private": False,
        }
    else:
        result["private"] = False

    # Tier 0: merge IPinfo Lite ASN/org when available (fields stay empty if no token/DB)
    if not result.get("private"):
        if _ipinfo_reader is None:
            try:
                open_ipinfo_reader()
            except Exception:
                pass
        extra = _from_ipinfo(ip)
        if extra.get("asn") and not result.get("asn"):
            result["asn"] = extra["asn"]
        if extra.get("org") and not result.get("org"):
            result["org"] = extra["org"]
        result["as_name"] = extra.get("as_name") or result.get("as_name")
        result["as_domain"] = extra.get("as_domain") or result.get("as_domain")
        host_h = extra.get("hosting")
        if host_h is None:
            host_h = hosting_heuristic(result.get("org"))
        result["hosting"] = host_h
        if _ipinfo_status.get("ok"):
            result["asn_source"] = "ipinfo_lite"
        else:
            result["asn_source"] = result.get("asn_source") or None

    _cache[ip] = result
    return result


# Offline approximate home (#68): a well-known city for the PC's Windows time zone.
# No network call and nothing personal: the time zone id is read locally and only a
# public city center is used. Unknown zones keep the US-center fallback.
_TZ_CITY = {
    "US Eastern Standard Time": ("Indianapolis area", 39.7684, -86.1581),
    "Eastern Standard Time": ("US Eastern", 40.7128, -74.0060),
    "Central Standard Time": ("US Central", 41.8781, -87.6298),
    "Mountain Standard Time": ("US Mountain", 39.7392, -104.9903),
    "US Mountain Standard Time": ("Arizona", 33.4484, -112.0740),
    "Pacific Standard Time": ("US Pacific", 34.0522, -118.2437),
    "Alaskan Standard Time": ("Alaska", 61.2181, -149.9003),
    "Hawaiian Standard Time": ("Hawaii", 21.3069, -157.8583),
    "Atlantic Standard Time": ("Atlantic Canada", 44.6488, -63.5752),
    "GMT Standard Time": ("UK / Ireland", 51.5074, -0.1278),
    "W. Europe Standard Time": ("Western Europe", 52.5200, 13.4050),
    "Romance Standard Time": ("France / Benelux", 48.8566, 2.3522),
    "Central European Standard Time": ("Central Europe", 52.2297, 21.0122),
    "India Standard Time": ("India", 28.6139, 77.2090),
    "China Standard Time": ("China", 39.9042, 116.4074),
    "Tokyo Standard Time": ("Japan", 35.6762, 139.6503),
    "AUS Eastern Standard Time": ("Australia East", -33.8688, 151.2093),
}


def _windows_tz_id() -> str | None:
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class _DTZI(ctypes.Structure):
            _fields_ = [
                ("Bias", wintypes.LONG),
                ("StandardName", wintypes.WCHAR * 32),
                ("StandardDate", wintypes.WORD * 8),
                ("StandardBias", wintypes.LONG),
                ("DaylightName", wintypes.WCHAR * 32),
                ("DaylightDate", wintypes.WORD * 8),
                ("DaylightBias", wintypes.LONG),
                ("TimeZoneKeyName", wintypes.WCHAR * 128),
                ("DynamicDaylightTimeDisabled", wintypes.BOOLEAN),
            ]

        info = _DTZI()
        if ctypes.windll.kernel32.GetDynamicTimeZoneInformation(ctypes.byref(info)) == 0xFFFFFFFF:
            return None
        return info.TimeZoneKeyName or None
    except Exception:
        return None


def approximate_home() -> dict[str, Any]:
    """Home without any network lookup: time-zone city if known, else ASSUMED_HOME."""
    tz = _windows_tz_id()
    hit = _TZ_CITY.get(tz or "")
    if not hit:
        return dict(ASSUMED_HOME)
    name, lat, lon = hit
    return {
        "ip": None,
        "lat": lat,
        "lon": lon,
        "city": None,
        "region": None,
        "country": None,
        "country_code": None,
        "org": None,
        "asn": None,
        "source": "timezone",
        "label": f"Approx. home ({name}, from time zone)",
    }


def detect_public_home() -> dict[str, Any]:
    """Optional one-shot public IP geo (no key). Falls back to approximate_home()."""
    home = approximate_home()
    try:
        req = urllib.request.Request(
            "https://ipapi.co/json/",
            headers={"User-Agent": "Mozilla/5.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        lat = data.get("latitude")
        lon = data.get("longitude")
        if lat is not None and lon is not None:
            home = {
                "ip": data.get("ip"),
                "lat": float(lat),
                "lon": float(lon),
                "city": data.get("city") or "Unknown",
                "region": data.get("region") or data.get("region_code"),
                "country": data.get("country_name") or data.get("country"),
                "country_code": data.get("country_code") or data.get("country"),
                "org": data.get("org"),
                "asn": data.get("asn"),
                "source": "ipapi.co",
                "label": f"Detected home ({data.get('city') or 'public IP'})",
            }
            return home
    except Exception:
        pass
    return home


def init_geo(detect_home: bool = False, allow_download: bool = True) -> dict[str, Any]:
    """Load MMDB. Public IP lookup is opt-in (detect_home=False by default).

    allow_download=False or data/geo.skip must run BEFORE any MMDB download.
    Soft-missing MMDB is OK (list works, fewer arcs).
    """
    set_allow_download(allow_download)
    load_disk_cache()
    ok, msg = open_reader()
    ip_ok, ip_msg = open_ipinfo_reader()
    home = detect_public_home() if detect_home else approximate_home()
    return {
        "mmdb_ok": ok,
        "mmdb_msg": msg,
        "mmdb_path": str(MMDB_PATH) if MMDB_PATH.exists() else None,
        "ipinfo_ok": ip_ok,
        "ipinfo_msg": ip_msg,
        "ipinfo_path": str(IPINFO_MMDB_PATH) if IPINFO_MMDB_PATH.exists() else None,
        "ipinfo_attribution": IPINFO_ATTR if ip_ok else None,
        "ipinfo_blocked": _ipinfo_status.get("blocked"),
        "cache_size": len(_cache),
        "home": home,
        "error": _reader_error,
    }
