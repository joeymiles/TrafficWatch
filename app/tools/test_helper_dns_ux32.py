"""Unit-smoke for Tier 1 phase-1 helper IPC + dns_log fields. No UAC."""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def test_ascii_helper_ps1() -> None:
    path = os.path.join(ROOT, "helper", "tw_helper.ps1")
    raw = open(path, "rb").read()
    assert raw, "tw_helper.ps1 empty"
    bad = [i for i, b in enumerate(raw) if b > 127]
    assert not bad, f"non-ASCII at offsets {bad[:8]}"
    for needle, label in (
        (b"\xe2\x80\x94", "emdash"),
        (b"\xe2\x80\x93", "endash"),
        (b"\xe2\x80\x9c", "smart-lq"),
        (b"\xe2\x80\x9d", "smart-rq"),
        (b"\xe2\x80\x98", "smart-ls"),
        (b"\xe2\x80\x99", "smart-rs"),
    ):
        assert needle not in raw, label
    text = raw.decode("ascii")
    assert "TrafficWatch-helper" in text
    assert "dns_start" in text and "shutdown" in text
    assert "Everyone" not in text
    print("ascii helper: ok")


def test_consent_and_pipe_constants() -> None:
    import helper_ipc

    assert helper_ipc.PIPE_NAME == "TrafficWatch-helper"
    assert "one-time admin helper" in helper_ipc.CONSENT_TEXT
    assert "ETW" in helper_ipc.CONSENT_TEXT
    assert "20-second poll" in helper_ipc.CONSENT_TEXT
    st = helper_ipc.status()
    assert st["connected"] is False
    assert "dns_events_count" in st
    print("helper_ipc constants: ok", st)


def test_ingest_dns_fields() -> None:
    import dns_log

    row = dns_log.ingest_helper_event(
        {
            "t": "dns",
            "pid": 4242,
            "proc": "chrome",
            "name": "example.com",
            "status": "0",
            "nxdomain": False,
            "results": ["93.184.216.34"],
            "ts": "2026-09-14T01:00:00Z",
        }
    )
    assert row is not None
    assert row["pid"] == 4242
    assert row["proc"] == "chrome"
    assert row["name"] == "example.com"
    assert row["ip"] == "93.184.216.34"
    nx = dns_log.ingest_helper_event(
        {
            "t": "dns",
            "pid": 4242,
            "proc": "chrome",
            "name": "no-such-tw-test.invalid",
            "status": "9003",
            "nxdomain": True,
            "results": [],
            "ts": "2026-09-14T01:00:01Z",
        }
    )
    assert nx and nx["nxdomain"] is True
    qs = dns_log.queries()
    assert qs, "queries empty after ingest"
    last = qs[-1]
    assert last["pid"] == 4242 and last["proc"] == "chrome"
    names = {q.get("name") for q in qs}
    assert "example.com" in names
    meta = dns_log.snapshot_meta()
    assert "queries" in meta and "helper" in meta
    payload = dns_log.api_payload(limit=80)
    assert len(payload["queries"]) <= 200
    assert "93.184.216.34" in dns_log.resolved_ips()
    print("dns_log ingest fields: ok", "n=", len(qs))


def main() -> int:
    test_ascii_helper_ps1()
    test_consent_and_pipe_constants()
    test_ingest_dns_fields()
    print("ALL SMOKE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
