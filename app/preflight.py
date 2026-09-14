"""TrafficWatch missing-dep preflight (stdlib only).

Imported by desktop.py / app.py before Flask/webview so a bare
python3 launch prints a short hint instead of only a stack dump.
start.sh uses linux_webview_ok() to pick desktop vs browser.
"""
from __future__ import annotations

import importlib
import sys

_SERVER_MODS = ("flask", "flask_socketio", "psutil")
_DESKTOP_MODS = ("webview", "flask", "flask_socketio", "psutil")

_HINT = """\
TrafficWatch is missing a Python package ({name}).
Create a venv and install dependencies, then retry:

  python3 -m venv .venv
  .venv/bin/pip install -r requirements.txt
  ./start.sh
"""

_LINUX_GUI = """\
Desktop window needs a Linux WebView backend (pip pywebview is not enough).

  Debian/Ubuntu:
    sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.1
  Fedora:
    sudo dnf install python3-gobject gtk3 webkit2gtk4.1
  Or Qt: pip install qtpy PyQt5  (plus system Qt)

start.sh falls back to app.py + the system browser when this is missing.
"""


def _missing(names: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    for name in names:
        try:
            importlib.import_module(name)
        except ImportError:
            out.append(name)
    return out


def print_import_hint(name: str) -> None:
    text = _HINT.format(name=name).rstrip()
    print(text, file=sys.stderr)


def print_linux_gui_hint() -> None:
    print(_LINUX_GUI.rstrip(), file=sys.stderr)


def ensure_imports(mode: str = "server") -> None:
    names = _DESKTOP_MODS if mode == "desktop" else _SERVER_MODS
    miss = _missing(names)
    if not miss:
        return
    print_import_hint(miss[0])
    raise SystemExit(1)


def linux_webview_ok() -> bool:
    """True when pywebview can load a GTK or Qt backend."""
    if _missing(("webview",)):
        return False
    for name in ("gi", "qtpy"):
        try:
            importlib.import_module(name)
            return True
        except ImportError:
            continue
    return False


if __name__ == "__main__":
    mode = "desktop" if "--desktop" in sys.argv else "server"
    if "--probe-gui" in sys.argv:
        raise SystemExit(0 if linux_webview_ok() else 1)
    ensure_imports(mode)
    print("preflight ok")
