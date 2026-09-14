"""Deterministic 0–100 risk scores for TrafficWatch connections / processes.

Formula (documented in NOTES.md — Review 3 Step 2). Additive, capped at 100.
Weights are intentional and stable so sorting stays predictable across polls.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

# --- Weights (tune carefully; keep NOTES.md in sync) ------------------------
INTEL_HIGH = 70
INTEL_MEDIUM = 55
INTEL_OTHER = 40
BEACON = 20
SUSPICIOUS_PATH = 18
UNSIGNED_ODD_PATH = 10  # combo bonus when unsigned + odd path
NEW_LISTENER_HIGH = 15
NEW_LISTENER = 10
UNUSUAL_PORT = 10
ODD_LINEAGE = 8
SIG_EXPIRED = 8
FIRST_SEEN = 5  # first_seen or new_process
BASELINE_DEPART = 20  # new country/ASN/remote-class vs ready baseline
EXFIL_ISH = 25  # outbound rate well above process median (conservative)
DNS_RARE = 12
DNS_BURST = 15
PUBLIC_INBOUND = 18  # medium; elevated when listener history unknown
PUBLIC_INBOUND_HIGH = 28
NEW_BINARY_NETWORK = 18
HASH_CHANGED = 22
DOH_UNUSUAL = 12
NET_CONTEXT_CHANGE = 10
CONFIG_DRIFT = 10
ASN_ROTATING = 16
COMBINED_THREAT = 45  # one stacked alert; suppresses pile-up
UNTRUSTED_NET_MULT = 1.15  # mild bump when network marked untrusted


def score_connection(row: dict[str, Any]) -> int:
    """Compute 0–100 risk for one connection row (intel + signals)."""
    score = 0
    intel = row.get("intel") or {}
    if intel.get("hit"):
        sev = str(intel.get("severity") or "").lower()
        if sev == "high":
            score += INTEL_HIGH
        elif sev == "medium":
            score += INTEL_MEDIUM
        else:
            score += INTEL_OTHER

    sigs = list(row.get("signals") or [])
    by_id = {str(s.get("id") or ""): s for s in sigs}
    ids = set(by_id.keys())

    if "beacon" in ids:
        score += BEACON
    if "suspicious_path" in ids:
        score += SUSPICIOUS_PATH
        # unsigned + odd path combo (also if Authenticode says not signed)
        auth = row.get("authenticode") or {}
        unsigned = (
            "unsigned" in ids
            or str(auth.get("status") or "").lower() == "notsigned"
            or auth.get("signed") is False
        )
        if unsigned:
            score += UNSIGNED_ODD_PATH
    elif "unsigned" in ids:
        # bare unsigned without odd path — mild (half of combo)
        score += 5

    if "new_listener" in ids:
        sev = str((by_id.get("new_listener") or {}).get("severity") or "").lower()
        score += NEW_LISTENER_HIGH if sev == "high" else NEW_LISTENER
    if "unusual_port" in ids:
        score += UNUSUAL_PORT
    if "odd_lineage" in ids:
        score += ODD_LINEAGE
    if "sig_expired" in ids:
        score += SIG_EXPIRED
    if "first_seen" in ids or "new_process" in ids:
        score += FIRST_SEEN
    if "baseline_depart" in ids:
        score += BASELINE_DEPART
    if "exfil_ish" in ids:
        score += EXFIL_ISH
    if "dns_rare" in ids:
        score += DNS_RARE
    if "dns_burst" in ids:
        score += DNS_BURST
    if "public_inbound" in ids:
        sev = str((by_id.get("public_inbound") or {}).get("severity") or "").lower()
        score += PUBLIC_INBOUND_HIGH if sev == "high" else PUBLIC_INBOUND

    if "new_binary_network" in ids:
        score += NEW_BINARY_NETWORK
    if "hash_changed_same_publisher" in ids:
        score += HASH_CHANGED
    if "doh_unusual" in ids:
        score += DOH_UNUSUAL
    if "net_context_change" in ids:
        score += NET_CONTEXT_CHANGE
    if "config_drift" in ids:
        score += CONFIG_DRIFT
    if "asn_rotating" in ids:
        score += ASN_ROTATING
    if "combined_threat" in ids:
        # Prefer single combined score; do not double-count stack pieces heavily
        score = max(score, COMBINED_THREAT)
        # Soft-cap: if combined present, ignore stacking past 70 unless intel high
        if "intel" not in str(intel).lower() or not (intel or {}).get("hit"):
            score = min(score, 70)

    # Untrusted network context: mild multiplier (R4 FP stays quiet on trusted/home)
    nc = row.get("net_context") or {}
    if nc.get("untrusted") and score > 0:
        score = int(min(100, round(score * UNTRUSTED_NET_MULT)))

    if score < 0:
        score = 0
    if score > 100:
        score = 100
    return int(score)


def score_from_signals(
    signals: list[dict[str, Any]] | None,
    *,
    intel: dict[str, Any] | None = None,
    authenticode: dict[str, Any] | None = None,
) -> int:
    """Score a synthetic row (e.g. process inspect) from signals / intel."""
    return score_connection(
        {
            "signals": signals or [],
            "intel": intel or {},
            "authenticode": authenticode,
        }
    )


def attach_risk(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Set numeric ``risk`` (0–100) per connection and ``risk_process`` (max for PID)."""
    for r in rows:
        r["risk"] = score_connection(r)

    by_pid: dict[Any, int] = defaultdict(int)
    for r in rows:
        pid = r.get("pid")
        if pid is None:
            continue
        by_pid[pid] = max(by_pid[pid], int(r.get("risk") or 0))

    for r in rows:
        pid = r.get("pid")
        if pid is None:
            r["risk_process"] = int(r.get("risk") or 0)
        else:
            r["risk_process"] = int(by_pid.get(pid, r.get("risk") or 0))
    return rows
