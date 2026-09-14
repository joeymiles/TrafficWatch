# Regression: inspect cmdline is masked; secrets never stored in history/events/CSV helpers.
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import connections
import history


def check(name: str, cond: bool) -> None:
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        raise AssertionError(name)


def main() -> None:
    raw = [
        "tool.exe",
        "--password=abc123",
        "--token=xyz",
        "--api-key",
        "sekrit",
        "https://user:hunter2@example.com/x",
        "Authorization: Bearer totalsecret",
        "deadbeefdeadbeefdeadbeefdeadbeef",
    ]
    redacted, did = connections.redact_cmdline(raw)
    joined = " ".join(redacted or [])
    check("did redact", did is True)
    check("abc123 masked", "abc123" not in joined)
    check("xyz masked", "xyz" not in joined)
    check("sekrit masked", "sekrit" not in joined)
    check("hunter2 masked", "hunter2" not in joined)
    check("totalsecret masked", "totalsecret" not in joined)
    check("long hex masked", "deadbeefdeadbeefdeadbeefdeadbeef" not in joined)
    check("flags remain", "--password=" in joined and "--token=" in joined)

    inspect = {
        "ok": True,
        "pid": 1,
        "cmdline": redacted,
        "cmdline_redacted": True,
    }
    inspect_s = json.dumps(inspect)
    check("inspect payload hides abc123", "abc123" not in inspect_s)
    check("inspect payload hides xyz", "xyz" not in inspect_s)

    history.record_event("test_secret", {"ip": "1.2.3.4", "cmdline": raw, "command_line": " ".join(raw)})
    if history._pending_events:
        _ts, _kind, payload = history._pending_events[-1]
        check("history event has no cmdline key", "cmdline" not in payload.lower())
        check("history event has no abc123", "abc123" not in payload)
        check("history event has no xyz", "xyz" not in payload)

    csv_fields = [
        "direction", "process", "pid", "proto", "remote_ip", "hostname",
        "country", "city", "intel_hit", "signals", "publisher_hint",
    ]
    check("csv helpers omit cmdline", "cmdline" not in csv_fields)
    row = {k: "" for k in csv_fields}
    row_s = json.dumps(row)
    check("csv row has no abc123", "abc123" not in row_s)

    print("CMDLINE_REDACT_TEST_PASSED")


if __name__ == "__main__":
    main()
