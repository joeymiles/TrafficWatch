"""One-click Windows Firewall block for TrafficWatch (Phase C).

Creates explicit outbound (and optional inbound) block rules named
TrafficWatch-block-<ip>. Never enables default-deny. Requires Host + token
+ typed confirm at the HTTP layer (app.py). Refuses private/loopback/multicast.

Security: IPs are validated (ipaddress, no zone id / % / shell metacharacters)
before any subprocess. PowerShell is invoked only via -File + separate argv
params (never -Command with interpolated strings).
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone, timedelta
import os
import re
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

RULE_PREFIX = "TrafficWatch-block-"

TIMED_DESC_PREFIX = "TrafficWatch timed block; expires="
TIMED_MINUTES_DEFAULT = 10
_cleanup_started = False


def _expiry_iso(minutes: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_expiry_from_description(desc: str | None) -> datetime | None:
    if not desc:
        return None
    m = re.search(r"expires=([0-9T:\-]+Z)", desc)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


_HELPER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firewall_rule.ps1")
_lock = threading.RLock()

# Reject zone ids and shell metacharacters before any subprocess
_UNSAFE_IP_CHARS = re.compile(r"[%`$;&|<>(){}\[\]\\\"'!*\s,]")


def validate_ip(ip: str) -> tuple[bool, str]:
    """Public helper for routes/tests. Rejects %, zone ids, metacharacters."""
    return _is_blockable_ip(ip)


def _is_blockable_ip(ip: str) -> tuple[bool, str]:
    raw = (ip or "").strip()
    if not raw:
        return False, "ip required"
    if "%" in raw:
        return False, "invalid ip (zone id / % not allowed)"
    if _UNSAFE_IP_CHARS.search(raw):
        return False, "invalid ip (metacharacters not allowed)"
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return False, "invalid ip"
    # Zone/scope IDs are not representable in ip_address(); belt-and-suspenders
    if "%" in str(addr):
        return False, "invalid ip (zone id / % not allowed)"
    if addr.is_loopback:
        return False, "refusing loopback"
    if addr.is_private:
        return False, "refusing private address"
    if addr.is_multicast:
        return False, "refusing multicast"
    if addr.is_link_local:
        return False, "refusing link-local"
    if addr.is_unspecified:
        return False, "refusing unspecified"
    if addr.is_reserved:
        return False, "refusing reserved address"
    return True, ""


def rule_name_for_ip(ip: str, direction: str = "out") -> str:
    d = "out" if direction == "out" else "in"
    # Rule names only contain our prefix + sanitized IP (colons -> safe for display)
    safe = ip.replace(":", "_")
    return f"{RULE_PREFIX}{d}-{safe}"


def _run_helper(argv_tail: list[str], timeout: float = 20.0) -> tuple[int, str, str]:
    """Run firewall_rule.ps1 with argv list only (no -Command string build)."""
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        _HELPER,
        *argv_tail,
    ]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=clean_ps51_env(),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return completed.returncode, (completed.stdout or "").strip(), (completed.stderr or "").strip()
    except subprocess.TimeoutExpired:
        return 1, "", "timeout"
    except Exception as e:
        return 1, "", str(e)[:200]


def block_ip(ip: str, *, also_inbound: bool = True, minutes: int | None = None) -> dict[str, Any]:
    """Create outbound (+ optional inbound) block rules for a public IP."""
    if os.name != "nt":
        return {"ok": False, "error": "firewall block is Windows-only"}
    ok, reason = _is_blockable_ip(ip)
    if not ok:
        return {"ok": False, "error": reason, "refused": True}
    ip = ip.strip()
    names = [rule_name_for_ip(ip, "out")]
    if also_inbound:
        names.append(rule_name_for_ip(ip, "in"))

    created: list[str] = []
    errors: list[str] = []
    with _lock:
        directions = [("Outbound", names[0])]
        if also_inbound:
            directions.append(("Inbound", names[1]))
        desc = "TrafficWatch one-click block (user confirmed)"
        if minutes is not None:
            try:
                mins = int(minutes)
            except (TypeError, ValueError):
                mins = TIMED_MINUTES_DEFAULT
            mins = max(1, min(mins, 24 * 60))
            desc = f"{TIMED_DESC_PREFIX}{_expiry_iso(mins)}"
        for direction, name in directions:
            code, out, err = _run_helper(
                [
                    "-Action",
                    "block",
                    "-Name",
                    name,
                    "-RemoteAddress",
                    ip,
                    "-Direction",
                    direction,
                    "-Description",
                    desc,
                ]
            )
            text = (out or err or "").lower()
            if code == 0 and ("created" in text or "exists" in text):
                created.append(name)
            else:
                msg = err or out or f"exit {code}"
                low = msg.lower()
                if "access is denied" in low or "unauthorized" in low or "access denied" in low:
                    return {
                        "ok": False,
                        "error": "Access denied. Firewall changes need a separate elevated helper. Do not run the whole app as administrator.",
                        "need_admin": True,
                        "partial": created,
                    }
                errors.append(msg[:240])

    if not created and errors:
        return {"ok": False, "error": errors[0], "need_admin": "access" in errors[0].lower()}
    return {
        "ok": True,
        "ip": ip,
        "rules": created,
        "undo": (
            f"Remove via TrafficWatch Unblock, or Remove-NetFirewallRule "
            f"-DisplayName '{rule_name_for_ip(ip, 'out')}' (and inbound twin if present)"
        ),
        "errors": errors or None,
    }


def unblock_ip(ip: str) -> dict[str, Any]:
    if os.name != "nt":
        return {"ok": False, "error": "firewall unblock is Windows-only"}
    ok, reason = _is_blockable_ip(ip)
    # Allow unblock of previously blocked public IPs; still reject garbage / %
    if not ok:
        # Refuse invalid / metachar / % always; also refuse if clearly malformed
        if "invalid" in reason or "required" in reason or "%" in reason or "metachar" in reason:
            return {"ok": False, "error": reason, "refused": True}
        # For private/etc still allow attempting remove of TW-named rules if IP form is clean
        raw = (ip or "").strip()
        if not raw or "%" in raw or _UNSAFE_IP_CHARS.search(raw):
            return {"ok": False, "error": reason or "invalid ip", "refused": True}
        try:
            ipaddress.ip_address(raw)
        except ValueError:
            return {"ok": False, "error": "invalid ip", "refused": True}
    ip = ip.strip()
    names = [rule_name_for_ip(ip, "out"), rule_name_for_ip(ip, "in")]
    removed: list[str] = []
    errors: list[str] = []
    with _lock:
        for name in names:
            code, out, err = _run_helper(["-Action", "unblock", "-Name", name])
            text = (out or "").lower()
            if code == 0 and "removed" in text:
                removed.append(name)
            elif "missing" in text:
                continue
            else:
                msg = err or out or f"exit {code}"
                if "access" in msg.lower() and "denied" in msg.lower():
                    return {
                        "ok": False,
                        "error": "Access denied. Removing firewall rules needs a separate elevated helper. Do not run the whole app as administrator.",
                        "need_admin": True,
                        "partial": removed,
                    }
                errors.append(msg[:240])
    if not removed and not errors:
        return {"ok": False, "error": "no TrafficWatch rules found for that IP", "ip": ip}
    if not removed and errors:
        return {"ok": False, "error": errors[0]}
    return {"ok": True, "ip": ip, "removed": removed, "errors": errors or None}


def list_rules() -> dict[str, Any]:
    """List firewall rules created by TrafficWatch (DisplayName prefix)."""
    if os.name != "nt":
        return {"ok": True, "rules": [], "message": "Windows only"}
    code, out, err = _run_helper(["-Action", "list", "-Prefix", RULE_PREFIX], timeout=25.0)
    if code != 0:
        msg = err or out or "failed to list rules"
        limited = "access" in msg.lower() and "denied" in msg.lower()
        return {
            "ok": False,
            "rules": [],
            "error": msg[:240],
            "need_admin": limited,
            "limited": limited,
        }
    import json

    raw = (out or "").strip() or "[]"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"ok": True, "rules": [], "raw": raw[:200]}
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        data = []
    return {"ok": True, "rules": data, "prefix": RULE_PREFIX}



def cleanup_expired_rules() -> dict[str, Any]:
    """Remove timed TrafficWatch rules whose description expiry has passed."""
    if os.name != "nt":
        return {"ok": True, "removed": [], "message": "Windows only"}
    listed = list_rules()
    if not listed.get("ok"):
        return {"ok": False, "removed": [], "error": listed.get("error")}
    now = datetime.now(timezone.utc)
    removed: list[str] = []
    errors: list[str] = []
    for rule in listed.get("rules") or []:
        name = rule.get("name") or ""
        desc = rule.get("description") or rule.get("desc") or ""
        # list helper may not include description — query via helper description field if present
        if not desc and "expires=" not in name:
            # Re-fetch via list includes description after ps1 patch
            pass
        exp = _parse_expiry_from_description(desc)
        if exp is None:
            continue
        if exp <= now:
            code, out, err = _run_helper(["-Action", "unblock", "-Name", name])
            text_o = (out or "").lower()
            if code == 0 and ("removed" in text_o or "missing" in text_o):
                removed.append(name)
            else:
                errors.append((err or out or name)[:200])
    return {"ok": True, "removed": removed, "errors": errors or None}


def start_expiry_timer(interval_sec: float = 60.0) -> None:
    """Startup + periodic cleanup of timed firewall rules (survives crash via desc expiry).

    ux39: do NOT run cleanup_expired_rules() on the caller/listen path (~1.7s PS).
    Start the tw-fw-expiry thread first; first cleanup runs at the top of _loop().
    """
    global _cleanup_started
    if _cleanup_started:
        return
    _cleanup_started = True

    def _loop() -> None:
        # First cleanup immediately inside the thread (crash-safety within ~1-2s of start).
        while True:
            try:
                cleanup_expired_rules()
            except Exception:
                pass
            time.sleep(interval_sec)

    threading.Thread(target=_loop, name="tw-fw-expiry", daemon=True).start()
