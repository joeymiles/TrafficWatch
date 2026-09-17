"""TrafficWatch desktop shell - pywebview hosting local Flask/Socket.IO.

Opens a native window immediately with a dark splash (so double-click is not
a blank wait), starts Flask/GeoIP in the background, then navigates to the
live UI when /api/health is ready. Closing the window or Quit stops the server.

Review 3 Step 4: optional system-tray minimize (pystray) - restore / quit still
calls hard_exit so :8767 is freed.
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import preflight as _tw_preflight
_tw_preflight.ensure_imports(mode="desktop")

import webview

import json

from app import (
    HOST,
    INSTANCE_ID,
    PORT,
    _runtime,
    app,
    build_lite_snapshot,
    build_snapshot,
    create_boot_ticket,
    poll_loop,
    socketio,
    write_desktop_show_token,
)
import geoip_lookup

URL = f"http://{HOST}:{PORT}/"

# Shown instantly in the native window before Flask/GeoIP are ready.
# Logo is inlined from static/trafficwatch-icon.svg (Flask /static not up yet).
_SPLASH_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>TrafficWatch</title>
  <style>
    html, body {{ height: 100%; margin: 0; }}
    body {{
      font-family: "Segoe UI", system-ui, sans-serif;
      background: radial-gradient(1000px 500px at 30% -10%, #152238 0%, #0b0f17 55%);
      color: #e6edf7;
      display: flex;
      align-items: center;
      justify-content: center;
    }}
    .card {{
      text-align: center;
      padding: 2rem 2.5rem;
      background: #121826;
      border: 1px solid #243049;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.45);
      max-width: 28rem;
    }}
    .logo {{
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto;
    }}
    .logo img, .logo svg {{
      width: 56px;
      height: 56px;
      display: block;
    }}
    h1 {{ margin: 0.5rem 0 0.25rem; font-size: 1.25rem; letter-spacing: 0.02em; }}
    p {{ margin: 0.35rem 0; color: #8b9bb4; font-size: 0.9rem; }}
    #status {{ color: #5eead4; font-size: 0.85rem; margin-top: 0.75rem; }}
    .spin {{
      width: 36px; height: 36px; margin: 1.1rem auto 0;
      border: 3px solid #243049; border-top-color: #5eead4;
      border-radius: 50%; animation: tw 0.85s linear infinite;
    }}
    @keyframes tw {{ to {{ transform: rotate(360deg); }} }}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">{logo}</div>
    <h1>TrafficWatch is starting.</h1>
    <p>Loading connections &amp; GeoIP.</p>
    <p class="tw-motto" style="font-size:0.72rem;color:#6b7c94;margin-top:0.65rem;line-height:1.35;">local-first, metadata first — paranoid on purpose, pragmatic about it.</p>
    <div class="spin" aria-hidden="true"></div>
    <p id="status">Opening local server.</p>
  </div>
  <script>
    (function () {{
      var el = document.getElementById("status");
      setTimeout(function () {{
        if (el) el.textContent = "Still loading.";
      }}, 8000);
      // html= splash cannot rely on Python load_url (WebView2 other thread).
      // Script src works without CORS; retries until Flask answers.
      var n = 0;
      function inject() {{
        n += 1;
        var s = document.createElement("script");
        s.src = "http://127.0.0.1:8767/api/boot-ready.js?n=" + n + "&t=" + Date.now();
        s.onerror = function () {{ setTimeout(inject, 250); }};
        document.head.appendChild(s);
      }}
      inject();
    }})();
  </script>
</body>
</html>
"""


def build_splash_html() -> str:
    """Build splash HTML with inline SVG icon (no /static dependency)."""
    svg_path = Path(__file__).resolve().parent / "static" / "trafficwatch-icon.svg"
    logo = ""
    try:
        raw = svg_path.read_text(encoding="utf-8")
        raw = raw.strip()
        if raw.startswith("<?xml"):
            raw = raw.split("?>", 1)[-1].strip()
        # Drop width/height attrs so CSS .logo svg sizing wins; keep viewBox.
        raw = raw.replace(' width="256"', "").replace(' height="256"', "")
        logo = raw
    except Exception:
        logo = (
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" aria-hidden="true">'
            '<rect width="64" height="64" rx="14" fill="#121826" stroke="#5eead4"/>'
            '<text x="32" y="40" text-anchor="middle" fill="#5eead4" '
            'font-family="Segoe UI,sans-serif" font-size="18">TW</text></svg>'
        )
    return _SPLASH_TEMPLATE.format(logo=logo)


# Cached at import for error-path string replace compatibility.
SPLASH_HTML = build_splash_html()

_tray_icon = None
_tray_lock = threading.Lock()
_main_window = None


_BOOT_TRACE = os.path.join(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")), "last-boot-trace.txt")


def _boot_log(msg: str) -> None:
    line = time.strftime("%H:%M:%S") + " " + msg
    print("  " + msg, flush=True)
    try:
        os.makedirs(os.path.dirname(_BOOT_TRACE), exist_ok=True)
        with open(_BOOT_TRACE, "a", encoding="ascii", newline="\n") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _bootstrap(no_geo_download: bool = False, snapshot: bool = True) -> None:
    print("TrafficWatch desktop starting...")
    print(f"  Binding {HOST}:{PORT}")
    geo_meta = geoip_lookup.init_geo(allow_download=not no_geo_download)
    if no_geo_download and not geo_meta.get("mmdb_ok"):
        print("  GeoIP MMDB missing; map pins will be limited.")
    else:
        print(f"  GeoIP: {geo_meta.get('mmdb_msg')}")
    home = geo_meta.get("home") or geoip_lookup.ASSUMED_HOME
    _runtime["home"] = home
    _runtime["geo_meta"] = geo_meta
    _runtime["desktop"] = True
    _runtime["running"] = True
    write_desktop_show_token()
    print(f"  Home: {home.get('source') or 'assumed'} (location not logged)")
    try:
        import intel as _intel
        _intel.start_background()
        print(f"  Intel: cache dir {_intel.INTEL_DIR} (vt_enabled={_intel.vt_enabled})")
    except Exception as exc:
        print(f"  Intel: start failed (continuing): {exc}")
    try:
        import history as _history
        _history.init()
        print(f"  History: {_history.DB_PATH}")
    except Exception as exc:
        print(f"  History: init failed (continuing): {exc}")
    try:
        import baseline as _baseline
        _baseline.init()
        print("  Baseline: per-program ~7d init")
    except Exception as exc:
        print(f"  Baseline: init failed (continuing): {exc}")
    try:
        import dns_log as _dns_log
        _dns_log.start_background()
        print("  DNS log: background reader started (degrades if no access)")
    except Exception as exc:
        print(f"  DNS log: start failed (continuing): {exc}")
    try:
        import helper_ipc as _helper_ipc
        _helper_ipc.start_background()  # daemon reader only; never blocks boot
        print("  Helper: pipe TrafficWatch-helper (connect in background; Status: Enable live DNS)")
    except Exception as exc:
        print(f"  Helper: start skipped (continuing): {exc}")
    _boot_log("light-init done")
    if snapshot:
        _boot_log("lite snapshot begin")
        try:
            lite = build_lite_snapshot()
            socketio.emit("snapshot", lite, to="authed")
            _boot_log("lite snapshot done")
        except Exception as exc:
            _boot_log("lite snapshot failed: " + str(exc)[:120])
        try:
            import signals as _signals
            _signals.set_auth_allowed(True)
        except Exception:
            pass
        socketio.start_background_task(poll_loop)
        _boot_log("poll_loop started")


def _run_server() -> None:
    try:
        socketio.run(
            app,
            host=HOST,
            port=PORT,
            allow_unsafe_werkzeug=True,
            use_reloader=False,
        )
    except TypeError:
        socketio.run(app, host=HOST, port=PORT, use_reloader=False)


def _boot_ping() -> dict | None:
    """Hit THIS machine's :PORT boot-ping. None if nothing is listening."""
    url = f"http://{HOST}:{PORT}/api/boot-ping"
    try:
        with urllib.request.urlopen(url, timeout=1.2) as resp:
            if getattr(resp, "status", 200) != 200:
                return None
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return {"ok": True, "pid": None, "auth_required": True, "legacy": True}
        return None
    except Exception:
        return None


def wait_ready(timeout: float = 45.0) -> bool:
    """True only when THIS process owns :PORT (boot-ping pid == os.getpid()).

    A 401 on /api/health is NOT self-ready: that is how a peer looks without
    a cookie. Dual-instance used to steal the port and leave splash up.
    """
    deadline = time.time() + timeout
    my_pid = os.getpid()
    while time.time() < deadline:
        data = _boot_ping()
        if data and data.get("ok"):
            peer_pid = data.get("pid")
            inst = data.get("instance_id")
            if peer_pid is None and data.get("legacy"):
                _boot_log("boot-ping legacy 401 (peer or old build)")
                time.sleep(0.25)
                continue
            try:
                peer_pid_i = int(peer_pid)
            except (TypeError, ValueError):
                peer_pid_i = -1
            if peer_pid_i == my_pid and inst == INSTANCE_ID:
                return True
            if peer_pid_i > 0 and peer_pid_i != my_pid:
                _boot_log("boot-ping PEER pid=%s (self=%s)" % (peer_pid_i, my_pid))
                return False
        time.sleep(0.25)
    return False


def hard_exit(code: int = 0) -> None:
    """Stop poll loop and kill the process so the port is always released."""
    # os._exit skips atexit, so drop our pid record first (tray/socketio stop below can end the process early).
    try:
        import applog
        applog.remove_pid_file()
    except Exception:
        pass
    _runtime["running"] = False
    global _tray_icon
    with _tray_lock:
        icon = _tray_icon
        _tray_icon = None
    if icon is not None:
        try:
            icon.stop()
        except Exception:
            pass
    try:
        socketio.stop()
    except Exception:
        pass
    # Daemon Flask/Werkzeug threads may ignore soft stop; force-exit frees :8767.
    os._exit(code)


def _load_tray_image(icon_path: str):
    try:
        from PIL import Image
        img = Image.open(icon_path)
        # pystray prefers RGBA
        if img.mode != "RGBA":
            img = img.convert("RGBA")
        return img
    except Exception:
        try:
            from PIL import Image
            return Image.new("RGBA", (64, 64), (94, 234, 212, 255))
        except Exception:
            return None


def _start_tray(icon_path: str) -> bool:
    """Start pystray tray icon (Windows). Returns False if unavailable.

    Must never raise: caller is inside desktop bootstrap, and an
    uncaught tray error would hard_exit the just-opened window.
    """
    global _tray_icon
    if os.name != "nt":
        return False
    try:
        import pystray
        from pystray import MenuItem as Item
    except Exception as exc:
        print(f"  Tray: pystray unavailable ({exc})")
        return False
    try:
        image = _load_tray_image(icon_path)
        if image is None:
            print("  Tray: could not load icon image")
            return False

        def on_show(icon, item):  # noqa: ARG001
            w = _main_window
            if w is None:
                return
            try:
                w.restore()
            except Exception:
                pass
            try:
                w.show()
            except Exception:
                pass
            try:
                w.restore()
            except Exception:
                pass

        def on_quit(icon, item):  # noqa: ARG001
            # Same path as DesktopApi.quit / bridge (includes 2s watchdog).
            _schedule_quit()

        menu = pystray.Menu(
            Item("Show TrafficWatch", on_show, default=True),
            Item("Quit", on_quit),
        )
        icon = pystray.Icon("TrafficWatch", image, "TrafficWatch", menu)

        def _run():
            global _tray_icon
            with _tray_lock:
                _tray_icon = icon
            try:
                icon.run()
            except Exception as exc:
                print(f"  Tray: run ended ({exc})")
            finally:
                with _tray_lock:
                    if _tray_icon is icon:
                        _tray_icon = None

        threading.Thread(target=_run, name="tw-tray", daemon=True).start()
        print("  Tray: pystray started (Show / Quit)")
        return True
    except Exception as exc:
        print(f"  Tray: skipped ({exc})")
        return False



_instance_lock_fp = None
_instance_mutex = None


def _acquire_instance_lock() -> bool:
    """True if this process is the single desktop instance."""
    global _instance_lock_fp, _instance_mutex
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.argtypes = [
            wintypes.LPVOID,
            wintypes.BOOL,
            wintypes.LPCWSTR,
        ]
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        name = "Local\\TrafficWatch-desktop-%s" % PORT
        handle = kernel32.CreateMutexW(None, True, name)
        if not handle:
            return False
        already = ctypes.get_last_error() == 183  # ERROR_ALREADY_EXISTS
        if already:
            kernel32.CloseHandle(handle)
            return False
        _instance_mutex = handle
        return True
    path = os.path.join(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")), "desktop.lock")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fp = open(path, "a+", encoding="ascii")
    try:
        import fcntl

        fcntl.flock(fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fp.close()
        return False
    fp.seek(0)
    fp.truncate()
    fp.write(str(os.getpid()))
    fp.flush()
    _instance_lock_fp = fp
    return True


def _health_peer() -> dict | None:
    """Return boot-ping JSON if another TW already serves :PORT, else None."""
    data = _boot_ping()
    if not data or not data.get("ok"):
        return None
    return data


def _request_peer_show() -> bool:
    """Ask running desktop instance to restore/show its window (POST + token)."""
    url = f"http://{HOST}:{PORT}/api/desktop/show"
    token = ""
    try:
        tok_path = os.path.join(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")), "desktop_show_token.txt")
        with open(tok_path, "r", encoding="ascii") as f:
            token = (f.read() or "").strip()
    except OSError:
        token = ""
    headers = {"X-TW-Token": token} if token else {}
    try:
        req = urllib.request.Request(url, method="POST", data=b"", headers=headers)
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            import json as _json
            data = _json.loads(resp.read().decode("utf-8", errors="replace"))
            return bool(data.get("ok"))
    except Exception:
        return False


def _show_main_window() -> bool:
    """Restore/show the pywebview window (tray Show + single-instance)."""
    w = _main_window
    if w is None:
        return False
    for attr in ("restore", "show", "restore"):
        try:
            getattr(w, attr)()
        except Exception:
            pass
    return True


def _do_quit() -> None:
    """Stop tray, destroy windows, then hard_exit. Safe off the JS bridge thread."""
    global _tray_icon
    with _tray_lock:
        icon = _tray_icon
        _tray_icon = None
    if icon is not None:
        try:
            icon.stop()
        except Exception:
            pass
    try:
        for w in list(webview.windows):
            try:
                w.destroy()
            except Exception:
                pass
    except Exception:
        pass
    hard_exit(0)


def _schedule_quit() -> bool:
    """Return immediately; run _do_quit shortly after (avoids WebView2 bridge deadlock)."""
    try:
        threading.Timer(0.05, _do_quit).start()
    except Exception:
        try:
            _do_quit()
        except Exception:
            hard_exit(0)
        return True

    def _watchdog() -> None:
        hard_exit(0)

    try:
        threading.Timer(2.0, _watchdog).start()
    except Exception:
        pass
    return True


class DesktopApi:
    """JS bridge: window.pywebview.api.quit() / minimize_to_tray()"""

    def quit(self) -> bool:
        """Schedule process exit off the bridge thread; return immediately."""
        return _schedule_quit()

    def reveal(self, path: str = "") -> bool:
        """Open Explorer on a path under data/ (exports, intel cache, etc.)."""
        raw = os.path.abspath(str(path or ""))
        data_root = os.path.abspath(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")))
        if not raw.startswith(data_root + os.sep) and raw != data_root:
            return False
        target = raw if os.path.isdir(raw) else os.path.dirname(raw)
        if not os.path.isdir(target):
            return False
        try:
            if sys.platform.startswith("win"):
                os.startfile(target)  # noqa: S606
            else:
                import subprocess
                subprocess.Popen(["xdg-open", target])
            return True
        except Exception:
            return False

    def minimize_to_tray(self) -> bool:
        """Hide main window; process keeps running with tray icon."""
        w = _main_window
        if w is None:
            return False
        try:
            w.hide()
            return True
        except Exception:
            try:
                w.minimize()
                return True
            except Exception:
                return False


def main() -> None:
    global _main_window
    parser = argparse.ArgumentParser(description="TrafficWatch desktop app")
    parser.add_argument("--no-geo-download", action="store_true")
    parser.add_argument("--width", type=int, default=1400)
    parser.add_argument("--height", type=int, default=900)
    parser.add_argument(
        "--fullscreen",
        action="store_true",
        help="True exclusive fullscreen (default is maximized)",
    )
    parser.add_argument(
        "--no-tray",
        action="store_true",
        help="Disable system-tray minimize (pystray)",
    )
    args = parser.parse_args()
    import applog
    applog.install()
    if sys.platform.startswith("win"):
        # Own taskbar identity so the window groups as TrafficWatch, not pythonw.
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("TrafficWatch.Desktop")
        except Exception as exc:
            print(f"  AppUserModelID not set: {exc}", flush=True)

    # Named mutex first (covers the race where Flask is not up yet).
    if not _acquire_instance_lock():
        shown = _request_peer_show()
        print(
            f"TrafficWatch already running (mutex; show_requested={shown}). "
            "Exiting this launch."
        )
        raise SystemExit(0)
    applog.write_pid_file()

    # Backup: port already serving (stale mutex-less peer).
    peer = _health_peer()
    if peer and peer.get("ok"):
        peer_pid = peer.get("pid")
        try:
            peer_pid_i = int(peer_pid)
        except (TypeError, ValueError):
            peer_pid_i = -1
        if peer_pid_i > 0 and peer_pid_i != os.getpid():
            shown = _request_peer_show()
            print(
                f"TrafficWatch already running on {HOST}:{PORT} pid={peer_pid_i} "
                f"(show_requested={shown}). Exiting this launch."
            )
            raise SystemExit(0)
        if peer.get("desktop") is False:
            print(
                f"ERROR: port {PORT} is in use by a non-desktop TrafficWatch server.",
                file=sys.stderr,
            )
            raise SystemExit(2)

    api = DesktopApi()
    _runtime["desktop_show_fn"] = _show_main_window
    _runtime["desktop"] = True
    write_desktop_show_token()

    # html= splash cannot navigate to http://127.0.0.1 (WebView2 data-origin +
    # load_url from a background thread). Start Flask first, then open the
    # window ON the live boot URL so there is no splash to get stuck on.
    icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "trafficwatch.ico")
    try:
        os.makedirs(os.path.dirname(_BOOT_TRACE), exist_ok=True)
        with open(_BOOT_TRACE, "w", encoding="ascii", newline="\n") as f:
            f.write(time.strftime("%H:%M:%S") + " main start pid=%s\n" % os.getpid())
    except Exception:
        pass
    _bootstrap(no_geo_download=args.no_geo_download, snapshot=False)
    _boot_log("starting flask")
    server = threading.Thread(target=_run_server, name="tw-flask", daemon=True)
    server.start()
    if not wait_ready():
        ping = _boot_ping() or {}
        peer_pid = ping.get("pid")
        try:
            peer_pid_i = int(peer_pid)
        except (TypeError, ValueError):
            peer_pid_i = -1
        if peer_pid_i > 0 and peer_pid_i != os.getpid():
            _boot_log("port owned by peer pid=%s; show+exit" % peer_pid_i)
            try:
                _request_peer_show()
            except Exception:
                pass
            raise SystemExit(0)
        print("ERROR: Flask did not become ready on", URL, file=sys.stderr)
        _boot_log("flask never ready")
        raise SystemExit(1)
    ticket = create_boot_ticket()
    boot_url = f"{URL}?boot={ticket}"
    _boot_log("flask ready; create_window url")
    window = webview.create_window(
        title="TrafficWatch",
        url=boot_url,
        width=args.width,
        height=args.height,
        min_size=(900, 600),
        background_color="#0b0f17",
        js_api=api,
        maximized=not args.fullscreen,
        fullscreen=bool(args.fullscreen),
    )
    _main_window = window

    def _deferred_snapshot() -> None:
        try:
            time.sleep(0.35)
            _boot_log("lite snapshot begin")
            lite = build_lite_snapshot()
            try:
                socketio.emit("snapshot", lite, to="authed")
            except Exception:
                pass
            _boot_log(
                "lite snapshot done rows=%s ms=%s"
                % (lite.get("count"), _runtime.get("_lite_ms"))
            )
        except Exception as snap_exc:
            print("ERROR: lite snapshot failed (UI already up):", snap_exc, file=sys.stderr)
            _boot_log("lite snapshot failed: " + str(snap_exc)[:160])
        try:
            import signals as _signals
            _signals.set_auth_allowed(True)
            _boot_log("authenticode enabled")
        except Exception as auth_exc:
            _boot_log("authenticode enable skipped: " + str(auth_exc)[:120])
        try:
            socketio.start_background_task(poll_loop)
            _boot_log("poll_loop started (full enrichment)")
        except Exception as poll_exc:
            _boot_log("poll_loop start failed: " + str(poll_exc)[:120])

    threading.Thread(target=_deferred_snapshot, name="tw-snap", daemon=True).start()
    if not args.no_tray:
        try:
            _start_tray(icon_path)
        except Exception as exc:
            print(f"  Tray: skipped ({exc})")

    def _on_closing() -> bool:
        # Allow close; hard_exit follows webview.start return. Tray Quit also destroys.
        return True

    try:
        window.events.closing += _on_closing
    except Exception:
        pass

    # Minimize-to-tray: when user minimizes, hide to tray if available
    def _on_minimized():
        if args.no_tray:
            return
        with _tray_lock:
            has_tray = _tray_icon is not None
        if has_tray:
            try:
                window.hide()
            except Exception:
                pass

    try:
        if hasattr(window.events, "minimized"):
            window.events.minimized += _on_minimized
    except Exception:
        pass

    # Persist WebView2 localStorage (guide, filters, tabs) across launches.
    storage_path = os.path.join(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")), "webview"
    )
    os.makedirs(storage_path, exist_ok=True)
    def _start_webview() -> None:
        # Windows: Edge WebView2 first, then whatever pywebview finds.
        # Linux/mac: skip edgechromium (not present); GTK/Qt auto.
        kwargs = {
            "icon": icon_path,
            "private_mode": False,
            "storage_path": storage_path,
        }
        if sys.platform.startswith("win"):
            try:
                webview.start(gui="edgechromium", **kwargs)
                return
            except Exception:
                webview.start(**kwargs)
                return
        webview.start(**kwargs)

    try:
        _start_webview()
    except Exception as exc:
        if sys.platform.startswith("win"):
            raise
        print("ERROR: Linux desktop window failed:", exc, file=sys.stderr)
        _tw_preflight.print_linux_gui_hint()
        print("Falling back to system browser.", flush=True)
        try:
            import webbrowser
            if not wait_ready():
                try:
                    _bootstrap(no_geo_download=args.no_geo_download)
                    threading.Thread(target=_run_server, name="tw-flask", daemon=True).start()
                    wait_ready()
                except Exception as boot_exc:
                    print("ERROR: browser fallback could not start server:", boot_exc, file=sys.stderr)
                    hard_exit(1)
            ticket = create_boot_ticket()
            webbrowser.open(f"{URL}?boot={ticket}")
            print(f"  Browser: {URL}?boot=... (leave this process running)")
            try:
                while True:
                    time.sleep(3600)
            except KeyboardInterrupt:
                hard_exit(0)
        except SystemExit:
            raise
        except Exception as fb_exc:
            print("ERROR: browser fallback failed:", fb_exc, file=sys.stderr)
            hard_exit(1)

    print("Window closed - shutting down backend...")
    hard_exit(0)


if __name__ == "__main__":
    main()
