"""Network context (Tier 0): profile, SSID, interface, VPN, default route.

Store names HASHED (sha256); show plaintext only in UI.
Owner marks Trusted/Untrusted (persist). Signal: net_context_change.
"""
from __future__ import annotations

import hashlib
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

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.normpath(os.path.join(ROOT, "..", "data"))
TRUST_PATH = os.path.join(DATA_DIR, "net_trust.json")

_VPN_HINTS = (
    "tap", "tun", "wintun", "wireguard", "openvpn", "nordlynx",
    "vpn", "cisco anyconnect", "globalprotect", "forticlient",
    "warp", "tailscale", "zerotier", "hamachi",
)

_lock = threading.RLock()
_last: dict[str, Any] = {}
_last_fp: str | None = None
_trust: dict[str, str] = {}  # name_hash -> trusted|untrusted
_initialized = False
_POLL_MIN = 15.0
_last_poll = 0.0


def _hash_name(name: str | None) -> str:
    raw = (name or "").strip().encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def init() -> None:
    global _initialized, _trust
    with _lock:
        if _initialized:
            return
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.path.isfile(TRUST_PATH):
            try:
                data = json.loads(open(TRUST_PATH, encoding="utf-8").read())
                if isinstance(data, dict):
                    _trust = {
                        str(k): ("trusted" if v == "trusted" else "untrusted")
                        for k, v in data.items()
                        if v in ("trusted", "untrusted")
                    }
            except Exception:
                _trust = {}
        _initialized = True


def _save_trust() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    try:
        with open(TRUST_PATH, "w", encoding="utf-8") as f:
            json.dump(_trust, f, indent=0)
    except Exception:
        pass


def set_trust(name_hash: str, state: str) -> dict[str, Any]:
    init()
    st = "trusted" if state == "trusted" else "untrusted"
    h = (name_hash or "").strip().lower()
    if not h or len(h) < 16:
        return {"ok": False, "error": "name_hash required"}
    with _lock:
        _trust[h] = st
        _save_trust()
    return {"ok": True, "name_hash": h, "state": st}


def _is_vpn_name(name: str | None) -> bool:
    n = (name or "").lower()
    return any(h in n for h in _VPN_HINTS)


def _poll_windows() -> dict[str, Any]:
    ps = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{
  profiles = @()
  wifi_ssid = $null
  interfaces = @()
  default_route = $null
  vpn = @()
}
try {
  foreach ($p in @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)) {
    $o.profiles += [pscustomobject]@{
      name = [string]$p.Name
      iface = [string]$p.InterfaceAlias
      category = [string]$p.NetworkCategory
      ipv4 = [string]$p.IPv4Connectivity
      ipv6 = [string]$p.IPv6Connectivity
    }
  }
} catch {}
try {
  $wifi = netsh wlan show interfaces 2>$null | Select-String '^\s*SSID\s*:' | Select-Object -First 1
  if ($wifi) {
    $o.wifi_ssid = (($wifi.ToString() -split ':',2)[1]).Trim()
  }
} catch {}
try {
  foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })) {
    $o.interfaces += [pscustomobject]@{
      name = [string]$a.Name
      type = [string]$a.InterfaceDescription
      media = [string]$a.MediaType
      status = [string]$a.Status
    }
  }
} catch {}
try {
  $r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
  if ($r) {
    $o.default_route = [pscustomobject]@{
      iface = [string]$r.InterfaceAlias
      next_hop = [string]$r.NextHop
      metric = [int]$r.RouteMetric
    }
  }
} catch {}
$o | ConvertTo-Json -Compress -Depth 5
"""
    out: dict[str, Any] = {
        "ok": False,
        "profiles": [],
        "wifi_ssid": None,
        "interfaces": [],
        "default_route": None,
        "vpn_ifaces": [],
        "error": None,
    }
    if os.name != "nt":
        out["error"] = "Windows only"
        return out
    try:
        completed = subprocess.run(
            [
                "powershell.exe", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-Command", ps,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            env=clean_ps51_env(),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        raw = (completed.stdout or "").strip()
        if not raw:
            out["error"] = (completed.stderr or "empty")[:160]
            return out
        data = json.loads(raw)
        if not isinstance(data, dict):
            out["error"] = "bad json"
            return out
        profiles = data.get("profiles") or []
        if isinstance(profiles, dict):
            profiles = [profiles]
        ifaces = data.get("interfaces") or []
        if isinstance(ifaces, dict):
            ifaces = [ifaces]
        vpn = []
        for iface in ifaces:
            nm = (iface.get("name") or "") + " " + (iface.get("type") or "")
            if _is_vpn_name(nm):
                vpn.append(iface.get("name"))
        out.update({
            "ok": True,
            "profiles": profiles,
            "wifi_ssid": data.get("wifi_ssid"),
            "interfaces": ifaces,
            "default_route": data.get("default_route"),
            "vpn_ifaces": vpn,
        })
    except Exception as e:
        out["error"] = str(e)[:160]
    return out


def _fingerprint(ctx: dict[str, Any]) -> str:
    parts = [
        str(ctx.get("wifi_ssid") or ""),
        str((ctx.get("default_route") or {}).get("iface") or ""),
        ",".join(sorted(ctx.get("vpn_ifaces") or [])),
        ",".join(sorted(
            (p.get("name") or "") + ":" + (p.get("category") or "")
            for p in (ctx.get("profiles") or [])
            if isinstance(p, dict)
        )),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:24]


def _ui_view(raw: dict[str, Any]) -> dict[str, Any]:
    """Plaintext for UI + hashed names for storage/API trust."""
    profiles_ui = []
    for p in raw.get("profiles") or []:
        if not isinstance(p, dict):
            continue
        name = p.get("name") or ""
        nh = _hash_name(name)
        profiles_ui.append({
            "name": name,
            "name_hash": nh,
            "iface": p.get("iface"),
            "category": p.get("category"),
            "trust": _trust.get(nh),
        })
    ssid = raw.get("wifi_ssid")
    ssid_hash = _hash_name(ssid) if ssid else None
    primary_hash = ssid_hash or (profiles_ui[0]["name_hash"] if profiles_ui else None)
    trust_state = _trust.get(primary_hash) if primary_hash else None
    return {
        "ok": raw.get("ok"),
        "wifi_ssid": ssid,
        "wifi_ssid_hash": ssid_hash,
        "profiles": profiles_ui,
        "interfaces": [
            {
                "name": i.get("name"),
                "type": i.get("type"),
                "media": i.get("media"),
                "vpn_like": _is_vpn_name((i.get("name") or "") + " " + (i.get("type") or "")),
            }
            for i in (raw.get("interfaces") or [])
            if isinstance(i, dict)
        ],
        "default_route": raw.get("default_route"),
        "vpn_ifaces": raw.get("vpn_ifaces") or [],
        "primary_hash": primary_hash,
        "trust": trust_state,
        "untrusted": trust_state == "untrusted",
        "error": raw.get("error"),
    }


def poll(*, force: bool = False) -> tuple[dict[str, Any], bool]:
    """Return (ui_context, changed). Throttled."""
    global _last, _last_fp, _last_poll
    init()
    now = time.time()
    with _lock:
        if not force and _last and (now - _last_poll) < _POLL_MIN:
            return dict(_last), False
    raw = _poll_windows()
    ui = _ui_view(raw)
    fp = _fingerprint(raw)
    changed = False
    with _lock:
        if _last_fp is not None and fp != _last_fp:
            changed = True
        _last_fp = fp
        _last = ui
        _last_poll = now
    ui["changed"] = changed
    ui["fp"] = fp
    return dict(ui), changed


def current() -> dict[str, Any]:
    init()
    with _lock:
        if _last:
            return dict(_last)
    ui, _ = poll(force=True)
    return ui



def _machine_alert_row(signals: list[dict[str, Any]]) -> dict[str, Any]:
    """Synthetic row so machine-wide signals do not attach to unrelated apps."""
    return {
        "process": "(system)",
        "name": "(system)",
        "exe": "(system)",
        "pid": 0,
        "remote_ip": None,
        "remote_port": None,
        "local_ip": None,
        "local_port": None,
        "direction": "system",
        "status": "-",
        "proto": "TCP",
        "private_remote": True,
        "signals": list(signals)[:8],
        "lat": None,
        "lon": None,
    }

def attach_context(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Attach net_context to snapshot; emit net_context_change on switch."""
    ctx, changed = poll()
    if changed:
        ssid_h = ctx.get("wifi_ssid_hash") or ""
        # Privacy: never put plain SSID into alert/event detail (hash only, same as net_trust)
        sig = {
            "id": "net_context_change",
            "label": "network change",
            "severity": "medium",
            "detail": (
                f"Network context changed"
                + (f" (SSID hash {ssid_h[:16]})" if ssid_h else "")
                + (f"; VPN: {', '.join(ctx.get('vpn_ifaces') or [])}" if ctx.get("vpn_ifaces") else "")
            ),
        }
        # Machine-level carrier — not under unrelated app connection rows
        carrier = None
        for r in rows:
            if r.get("exe") == "(system)" and r.get("pid") == 0 and r.get("direction") == "system":
                carrier = r
                break
        if carrier is None:
            carrier = _machine_alert_row([])
            rows.append(carrier)
        existing = list(carrier.get("signals") or [])
        if not any(s.get("id") == "net_context_change" for s in existing):
            existing.append(sig)
            carrier["signals"] = existing[:8]
    for r in rows:
        r["net_context"] = {
            "trust": ctx.get("trust"),
            "untrusted": bool(ctx.get("untrusted")),
            "vpn": bool(ctx.get("vpn_ifaces")),
            "fp": ctx.get("fp"),
        }
    return rows, ctx
