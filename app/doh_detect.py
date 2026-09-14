"""DoH/DoT detection (Tier 0): flag 443/853 to known resolver IPs.

Excludes browsers and svchost/dnscache. Best-effort read of HKLM DoHPolicy
and per-adapter DoH (no admin required for read). Signal: doh_unusual.
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
from typing import Any

# Known public DoH/DoT resolver IPs (small local list)
KNOWN_RESOLVER_IPS = frozenset({
    # Cloudflare
    "1.1.1.1", "1.0.0.1",
    "2606:4700:4700::1111", "2606:4700:4700::1001",
    # Google
    "8.8.8.8", "8.8.4.4",
    "2001:4860:4860::8888", "2001:4860:4860::8844",
    # Quad9
    "9.9.9.9", "149.112.112.112",
    "2620:fe::fe", "2620:fe::9",
    # Extra small local list
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "94.140.14.14", "94.140.15.15",  # AdGuard
    "76.76.2.0", "76.76.10.0",  # Control D (common anycast)
})

_BROWSER = frozenset({
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
    "brave.exe", "opera.exe", "safari.exe", "chromium.exe",
    "vivaldi.exe", "waterfox.exe",
})
_DNS_CLIENT = frozenset({"svchost.exe", "dnscache", "dns.exe"})

_DOT_PORTS = frozenset({853})
_DOH_PORTS = frozenset({443, 853})

_lock = threading.RLock()
_policy_cache: dict[str, Any] = {"ts": 0.0, "data": {}}
_POLICY_TTL = 120.0


def _norm_ip(ip: str | None) -> str:
    if not ip:
        return ""
    s = str(ip).strip().lower()
    if s.startswith("::ffff:"):
        s = s[7:]
    return s


def is_known_resolver(ip: str | None) -> bool:
    return _norm_ip(ip) in KNOWN_RESOLVER_IPS


def _excluded_process(name: str | None) -> bool:
    n = (name or "").strip().lower()
    if n in _BROWSER or n in _DNS_CLIENT:
        return True
    return False


def read_doh_policy() -> dict[str, Any]:
    """Best-effort Windows DoH policy (no admin). Cached briefly."""
    now = time.time()
    with _lock:
        if now - float(_policy_cache.get("ts") or 0) < _POLICY_TTL:
            return dict(_policy_cache.get("data") or {})
    out: dict[str, Any] = {
        "doh_policy": None,
        "adapters": [],
        "ok": False,
        "error": None,
    }
    if os.name != "nt":
        out["error"] = "Windows only"
        with _lock:
            _policy_cache["ts"] = now
            _policy_cache["data"] = out
        return out
    ps = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{ doh_policy = $null; adapters = @() }
try {
  $v = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'DoHPolicy' -ErrorAction SilentlyContinue
  if ($null -ne $v -and $null -ne $v.DoHPolicy) { $o.doh_policy = [int]$v.DoHPolicy }
} catch {}
try {
  $adapters = Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 -ErrorAction SilentlyContinue
  foreach ($a in @($adapters)) {
    $iface = $a.InterfaceAlias
    $servers = @($a.ServerAddresses)
    $doh = $null
    try {
      $nr = Get-NetIPInterface -InterfaceAlias $iface -ErrorAction SilentlyContinue | Select-Object -First 1
      $dohPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$($a.InterfaceIndex)\DohConfiguration"
      # best-effort; may be empty without admin
    } catch {}
    $o.adapters += [pscustomobject]@{
      alias = [string]$iface
      servers = $servers
    }
  }
} catch {}
$o | ConvertTo-Json -Compress -Depth 4
"""
    try:
        completed = subprocess.run(
            [
                "powershell.exe", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", ps,
            ],
            capture_output=True,
            text=True,
            timeout=12,
            env=clean_ps51_env(),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        raw = (completed.stdout or "").strip()
        if raw:
            data = json.loads(raw)
            if isinstance(data, dict):
                out["doh_policy"] = data.get("doh_policy")
                out["adapters"] = data.get("adapters") or []
                out["ok"] = True
    except Exception as e:
        out["error"] = str(e)[:160]
    with _lock:
        _policy_cache["ts"] = now
        _policy_cache["data"] = out
    return dict(out)


def attach_doh_signals(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flag non-browser connections to known DoH/DoT resolvers on 443/853."""
    for r in rows:
        rip = r.get("remote_ip")
        rport = r.get("remote_port")
        if not rip or rport is None:
            continue
        try:
            port = int(rport)
        except (TypeError, ValueError):
            continue
        if port not in _DOH_PORTS:
            continue
        if not is_known_resolver(rip):
            continue
        pname = r.get("process")
        if _excluded_process(pname):
            continue
        # Skip private/local
        if r.get("private_remote"):
            continue
        kind = "DoT" if port in _DOT_PORTS else "DoH/HTTPS"
        detail = f"{kind} to known resolver {rip}:{port} from {pname or '?'}"
        sig = {
            "id": "doh_unusual",
            "label": "unusual DoH/DoT",
            "severity": "medium",
            "detail": detail,
        }
        existing = list(r.get("signals") or [])
        if not any(s.get("id") == "doh_unusual" for s in existing):
            existing.append(sig)
            r["signals"] = existing[:8]
        r["doh_flag"] = True
    return rows


def status() -> dict[str, Any]:
    pol = read_doh_policy()
    return {
        "ok": True,
        "resolver_count": len(KNOWN_RESOLVER_IPS),
        "policy": pol,
    }
