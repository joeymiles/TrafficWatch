# Regression: bracketed filename must not report a Valid neighbor signature.
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import signals


def check(name: str, cond: bool) -> None:
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        raise AssertionError(name)


def main() -> None:
    td = tempfile.mkdtemp(prefix="tw-auth-")
    try:
        bracket = os.path.join(td, "evil[1].txt")
        with open(bracket, "wb") as f:
            f.write(b"unsigned placeholder")
        neighbor = os.path.join(td, "evil1.exe")
        py = sys.executable
        if os.path.isfile(py):
            try:
                shutil.copy2(py, neighbor)
            except OSError:
                neighbor = ""

        # Same helper the app uses (PowerShell -File authenticode.ps1 -Path <argv>).
        got = signals._run_authenticode(bracket)
        status = str(got.get("status") or "").lower()
        publisher = got.get("publisher")
        check("bracketed status is not Valid", status != "valid")
        check("bracketed signed is not True", got.get("signed") is not True)
        if neighbor and os.path.isfile(neighbor):
            nb = signals._run_authenticode(neighbor)
            nb_pub = nb.get("publisher")
            if nb.get("signed") and nb_pub:
                check("bracketed publisher is not neighbor publisher", publisher != nb_pub)
        print("AUTHENTICODE_LITERAL_TEST_PASSED")
    finally:
        shutil.rmtree(td, ignore_errors=True)


if __name__ == "__main__":
    main()
