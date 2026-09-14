"""Config drift poll ~60s (Tier 0).

Tracks DNS servers, WinINET/WinHTTP proxy, hosts file hash, adapters,
firewall profile on/off + rule count. Each change = alert before/after
(no secrets). Signal: config_drift.
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
STATE_PATH = os.path.join(DATA_DIR, "config_drift_state.json")
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"

_lock = threading.RLock()
_prev: dict[str, Any] | None = None
_last_poll = 0.0
_POLL_SEC = 60.0
_pending_alerts: list[dict[str, Any]] = []


def _hosts_hash() -> str | None:
    try:
        data = open(HOSTS_PATH, "rb").read()
        return hashlib.sha256(data).hexdigest()
    except OSError:
        return None


def _snapshot_windows() -> dict[str, Any]:
    ps = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{
  dns = @()
  adapters = @()
  winhttp_proxy = $null
  wininet_proxy = $null
  fw_profiles = @()
  fw_rule_count = $null
}
try {
  foreach ($a in @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
    $o.dns += [pscustomobject]@{
      alias = [string]$a.InterfaceAlias
      servers = @($a.ServerAddresses)
    }
  }
} catch {}
try {
  foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue)) {
    $o.adapters += [pscustomobject]@{
      name = [string]$a.Name
      status = [string]$a.Status
      mac = [string]$a.MacAddress
    }
  }
} catch {}
try {
  $wh = netsh winhttp show proxy 2>$null | Out-String
  if ($wh) {
    # Redact: only presence / Direct / named server host (no creds in winhttp usually)
    $line = ($wh -split "`n" | Where-Object { $_ -match 'Proxy Server|Direct access' } | Select-Object -First 2) -join '; '
    $o.winhttp_proxy = $line.Trim()
  }
} catch {}
try {
  $ie = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
  if ($ie) {
    $en = [int]($ie.ProxyEnable)
    $srv = [string]($ie.ProxyServer)
    # strip any user:pass@ if somehow present
    if ($srv -match '@') { $srv = ($srv -split '@')[-1] }
    $o.wininet_proxy = "enable=$en; server=$srv"
  }
} catch {}
try {
  foreach ($p in @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
    $o.fw_profiles += [pscustomobject]@{
      name = [string]$p.Name
      enabled = [bool]$p.Enabled
    }
  }
  $o.fw_rule_count = @(Get-NetFirewallRule -ErrorAction SilentlyContinue).Count
} catch {}
$o | ConvertTo-Json -Compress -Depth 5
"""
    out: dict[str, Any] = {
        "dns": [],
        "adapters": [],
        "winhttp_proxy": None,
        "wininet_proxy": None,
        "fw_profiles": [],
        "fw_rule_count": None,
        "hosts_hash": _hosts_hash(),
        "ok": False,
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
            timeout=25,
            env=clean_ps51_env(),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        raw = (completed.stdout or "").strip()
        if raw:
            data = json.loads(raw)
            if isinstance(data, dict):
                for k in ("dns", "adapters", "winhttp_proxy", "wininet_proxy",
                          "fw_profiles", "fw_rule_count"):
                    if k in data:
                        out[k] = data[k]
                out["ok"] = True
        else:
            out["error"] = (completed.stderr or "empty")[:160]
    except Exception as e:
        out["error"] = str(e)[:160]
    out["hosts_hash"] = _hosts_hash()
    return out


def _canon(snap: dict[str, Any]) -> dict[str, Any]:
    """Comparable subset (no secrets)."""
    dns = []
    for d in snap.get("dns") or []:
        if isinstance(d, dict):
            dns.append({
                "alias": d.get("alias"),
                "servers": sorted(d.get("servers") or []),
            })
    adapters = sorted(
        (a.get("name") or "") + ":" + (a.get("status") or "")
        for a in (snap.get("adapters") or [])
        if isinstance(a, dict)
    )
    fw = sorted(
        (p.get("name") or "") + ":" + str(bool(p.get("enabled")))
        for p in (snap.get("fw_profiles") or [])
        if isinstance(p, dict)
    )
    return {
        "dns": dns,
        "adapters": adapters,
        "winhttp_proxy": snap.get("winhttp_proxy"),
        "wininet_proxy": snap.get("wininet_proxy"),
        "fw_profiles": fw,
        "fw_rule_count": snap.get("fw_rule_count"),
        "hosts_hash": snap.get("hosts_hash"),
    }


def _diff(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    changes = []
    for key in ("dns", "adapters", "winhttp_proxy", "wininet_proxy",
                "fw_profiles", "fw_rule_count", "hosts_hash"):
        b = before.get(key)
        a = after.get(key)
        if b != a:
            # redact-ish: shorten hashes
            def _fmt(v: Any) -> str:
                if key == "hosts_hash" and isinstance(v, str) and len(v) > 16:
                    return v[:12] + "..."
                s = json.dumps(v, sort_keys=True) if not isinstance(v, str) else v
                if s and len(s) > 240:
                    return s[:237] + "..."
                return s or ""

            changes.append({
                "field": key,
                "before": _fmt(b),
                "after": _fmt(a),
            })
    return changes


def poll(*, force: bool = False) -> list[dict[str, Any]]:
    """Return new drift alerts (may be empty). Throttled to ~60s."""
    global _prev, _last_poll
    now = time.time()
    with _lock:
        if not force and (now - _last_poll) < _POLL_SEC and _prev is not None:
            out = list(_pending_alerts)
            _pending_alerts.clear()
            return out
        _last_poll = now
    snap = _snapshot_windows()
    canon = _canon(snap)
    alerts: list[dict[str, Any]] = []
    with _lock:
        if _prev is not None:
            changes = _diff(_prev, canon)
            for ch in changes:
                alerts.append({
                    "id": "config_drift",
                    "label": "config drift",
                    "severity": "medium",
                    "detail": (
                        f"{ch['field']}: {ch['before']} -> {ch['after']}"
                    ),
                    "field": ch["field"],
                    "before": ch["before"],
                    "after": ch["after"],
                })
        else:
            # seed from disk if present
            try:
                if os.path.isfile(STATE_PATH):
                    old = json.loads(open(STATE_PATH, encoding="utf-8").read())
                    if isinstance(old, dict):
                        changes = _diff(old, canon)
                        for ch in changes:
                            alerts.append({
                                "id": "config_drift",
                                "label": "config drift",
                                "severity": "medium",
                                "detail": (
                                    f"{ch['field']}: {ch['before']} -> {ch['after']}"
                                ),
                                "field": ch["field"],
                                "before": ch["before"],
                                "after": ch["after"],
                            })
            except Exception:
                pass
        _prev = canon
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(STATE_PATH, "w", encoding="utf-8") as f:
                json.dump(canon, f)
        except Exception:
            pass
        _pending_alerts.extend(alerts)
        out = list(_pending_alerts)
        _pending_alerts.clear()
        return out



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

def attach_drift(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts = poll()
    if not alerts:
        return rows
    # Machine-level carrier for config_drift — not under unrelated app rows
    carrier = None
    for r in rows:
        if r.get("exe") == "(system)" and r.get("pid") == 0 and r.get("direction") == "system":
            carrier = r
            break
    if carrier is None:
        carrier = _machine_alert_row([])
        rows.append(carrier)
    existing = list(carrier.get("signals") or [])
    for a in alerts[:3]:
        if not any(
            s.get("id") == "config_drift" and s.get("detail") == a.get("detail")
            for s in existing
        ):
            existing.append({
                "id": a["id"],
                "label": a["label"],
                "severity": a["severity"],
                "detail": a["detail"],
            })
    carrier["signals"] = existing[:8]
    return rows


def status() -> dict[str, Any]:
    with _lock:
        return {
            "ok": True,
            "has_baseline": _prev is not None,
            "last_poll": _last_poll,
            "poll_sec": _POLL_SEC,
        }
