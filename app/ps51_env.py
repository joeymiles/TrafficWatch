"""Windows PowerShell 5.1 spawn environment hygiene (ux45).

When TrafficWatch is launched from pwsh (PowerShell 7+), child powershell.exe
(5.1) inherits PSModulePath that points at PS7 module paths. That breaks loading
Microsoft.PowerShell.Security, so Get-AuthenticodeSignature fails and every
signature check returns status error / unverified.

Also: simply removing PSModulePath is NOT enough in every host (some parents
already lack a usable path and 5.1 does not rebuild defaults). Always set
PSModulePath to Windows PowerShell 5.1 module directories.

Use clean_ps51_env() for every powershell.exe helper spawn.
"""
from __future__ import annotations

import os
from typing import Mapping, MutableMapping


def _ps51_module_path() -> str:
    """Windows PowerShell 5.1 default module search path (user + system)."""
    sys32 = os.environ.get("SystemRoot", r"C:\Windows")
    program = os.environ.get("ProgramFiles", r"C:\Program Files")
    user_docs = os.path.join(
        os.path.expanduser("~"),
        "Documents",
        "WindowsPowerShell",
        "Modules",
    )
    return ";".join(
        [
            user_docs,
            os.path.join(program, "WindowsPowerShell", "Modules"),
            os.path.join(sys32, "System32", "WindowsPowerShell", "v1.0", "Modules"),
        ]
    )


def clean_ps51_env(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return env for powershell.exe 5.1 with PSModulePath reset to 5.1 defaults."""
    env: dict[str, str] = dict(base if base is not None else os.environ)
    env["PSModulePath"] = _ps51_module_path()
    return env


def apply_ps51_env(env: MutableMapping[str, str]) -> MutableMapping[str, str]:
    """In-place reset of PSModulePath to PS 5.1 defaults; returns same mapping."""
    env["PSModulePath"] = _ps51_module_path()
    return env