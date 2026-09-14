#!/bin/sh
# TrafficWatch Linux launcher (counterpart to start.ps1).
# ASCII only -- no em dashes or smart quotes.
# First-run asks consent before pip, IPinfo signup, MMDB download, or browser fallback.
# Healthy installs (venv + packages already present) launch without those prompts.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
APP="$ROOT/app"
if [ ! -d "$APP" ]; then
  echo "ERROR: app/ folder missing - expected application code under app/" >&2
  exit 1
fi

echo "=== TrafficWatch ==="
echo "Folder: $ROOT"

DATA="$ROOT/data"
mkdir -p "$DATA"
IPINFO_TOKEN_FILE="$DATA/ipinfo.token"
IPINFO_SKIP="$DATA/ipinfo.skip"
GEO_SKIP="$DATA/geo.skip"
GEO_MMDB="$DATA/dbip-city-lite.mmdb"

ask_yes() {
  msg=$1
  echo "$msg"
  if [ ! -t 0 ]; then
    echo "No TTY: treating as No (will not pip, download, or open signup)."
    return 1
  fi
  printf "[y/N] "
  ans=""
  read -r ans || return 1
  case "$ans" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

if command -v python3 >/dev/null 2>&1; then
  PY3=python3
elif command -v python >/dev/null 2>&1; then
  PY3=python
else
  echo "ERROR: TrafficWatch needs Python 3.10+ on PATH." >&2
  echo "Install it with your package manager (e.g. sudo apt install python3 python3-venv python3-pip)." >&2
  echo "TrafficWatch will not download Python for you." >&2
  exit 1
fi

if ! "$PY3" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"; then
  echo "ERROR: Python 3.10+ required (found $("$PY3" -c "import sys; print(sys.version.split()[0])"))." >&2
  echo "TrafficWatch will not download Python for you." >&2
  exit 1
fi

VENV="$ROOT/.venv"
VPY="$VENV/bin/python"

need_venv=0
need_pip=1
if [ ! -x "$VPY" ]; then
  need_venv=1
else
  if "$VPY" -c "import flask, flask_socketio, psutil" >/dev/null 2>&1; then
    need_pip=0
  fi
fi

if [ "$need_venv" -eq 1 ] || [ "$need_pip" -eq 1 ]; then
  if ! ask_yes "TrafficWatch needs Python packages (Flask, psutil, pywebview, and others in requirements.txt). OK to create a local .venv and run pip install -r requirements.txt? This uses the network once. No = the app will not start until packages are installed."; then
    echo "Skipped package install. Later:"
    echo "  python3 -m venv .venv"
    echo "  .venv/bin/pip install -r requirements.txt"
    echo "  ./start.sh"
    exit 1
  fi
  if [ "$need_venv" -eq 1 ]; then
    echo "Creating venv..."
    "$PY3" -m venv "$VENV"
  fi
  if [ ! -x "$VPY" ]; then
    echo "ERROR: .venv/bin/python missing after create." >&2
    exit 1
  fi
  echo "Installing requirements (you agreed)..."
  "$VPY" -m pip install -r "$APP/requirements.txt" -q
  if ! "$VPY" -c "import pystray" >/dev/null 2>&1; then
    if ! "$VPY" -m pip install "pystray>=0.19.0" -q >/dev/null 2>&1; then
      echo "Optional tray (pystray) skipped - window/browser will still open."
    fi
  fi
fi

have_ipinfo=0
if [ -n "${IPINFO_TOKEN:-}" ] || [ -n "${IPINFO_LITE_TOKEN:-}" ]; then
  have_ipinfo=1
fi
if [ -s "$IPINFO_TOKEN_FILE" ]; then
  have_ipinfo=1
fi
if [ "$have_ipinfo" -eq 0 ] && [ ! -f "$IPINFO_SKIP" ]; then
  if ask_yes "Optional: IPinfo Lite improves ASN/org labels on the globe (free Lite token; stop if a card is required). Set it up now? Yes opens https://ipinfo.io/signup so you can paste a token. Skip = ASN stays empty. Token is stored only in data/ipinfo.token on this PC. Never emailed."; then
    if command -v xdg-open >/dev/null 2>&1; then
      xdg-open "https://ipinfo.io/signup" >/dev/null 2>&1 || true
    elif command -v sensible-browser >/dev/null 2>&1; then
      sensible-browser "https://ipinfo.io/signup" >/dev/null 2>&1 || true
    else
      echo "Open https://ipinfo.io/signup in a browser, then paste the token."
    fi
    printf "Paste IPinfo Lite token (blank = skip): "
    tok=""
    if [ -t 0 ]; then
      stty -echo 2>/dev/null || true
      read -r tok || tok=""
      stty echo 2>/dev/null || true
      echo
    fi
    # trim CR
    tok=$(printf '%s' "$tok" | tr -d '\r')
    if [ -n "$tok" ]; then
      umask 077
      printf '%s\n' "$tok" > "$IPINFO_TOKEN_FILE"
      echo "IPinfo token saved to data/ipinfo.token"
    else
      printf 'skipped\n' > "$IPINFO_SKIP"
      echo "IPinfo skipped. ASN fields stay empty until data/ipinfo.token exists."
    fi
  else
    printf 'skipped\n' > "$IPINFO_SKIP"
    echo "IPinfo skipped. ASN fields stay empty until data/ipinfo.token exists."
  fi
fi

NO_GEO=0
if [ -f "$GEO_MMDB" ]; then
  NO_GEO=0
elif [ -f "$GEO_SKIP" ]; then
  NO_GEO=1
else
  if ask_yes "Optional: download the free DB-IP City Lite map database (personal / non-commercial use) into data/ so remotes can pin on the globe. OK to download on first start? No = launch without the download (list still works; fewer arcs)."; then
    NO_GEO=0
  else
    printf 'skipped\n' > "$GEO_SKIP"
    NO_GEO=1
  fi
fi

MODE=auto
EXTRA=""
for arg in "$@"; do
  case "$arg" in
    --server|--no-browser)
      echo "Note: app.py has no --no-browser flag (default is already no browser)."
      echo "      Use ./start.sh --server for server-only, or --browser to force the browser."
      MODE=server
      ;;
    --browser)
      MODE=browser
      ;;
    --desktop)
      MODE=desktop
      ;;
    *)
      EXTRA="$EXTRA $arg"
      ;;
  esac
done

if [ "$NO_GEO" -eq 1 ]; then
  EXTRA="$EXTRA --no-geo-download"
fi

have_display=0
if [ -n "${DISPLAY-}" ] || [ -n "${WAYLAND_DISPLAY-}" ]; then
  have_display=1
fi

gui_ok=0
if [ "$have_display" -eq 1 ] && "$VPY" "$APP/preflight.py" --probe-gui; then
  gui_ok=1
fi

run_desktop() {
  echo "Launching desktop window (desktop.py)..."
  cd "$APP" && exec "$VPY" desktop.py $EXTRA
}

run_browser() {
  echo "Starting server and opening the system browser."
  cd "$APP" && exec "$VPY" app.py --browser $EXTRA
}

run_server() {
  echo "Starting server only (no window, no browser)."
  echo "Default is already no browser; open the printed /pair URL yourself."
  cd "$APP" && exec "$VPY" app.py $EXTRA
}

maybe_browser_fallback() {
  if ask_yes "Desktop window needs python3-gi + WebKitGTK (or Qt). pip pywebview alone is not enough. Debian/Ubuntu: sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.1. Fedora: sudo dnf install python3-gobject gtk3 webkit2gtk4.1. Open TrafficWatch in the system browser instead?"; then
    run_browser
  else
    echo "Skipped browser fallback. Install the GTK/WebKit or Qt packages, then ./start.sh again. Or: ./start.sh --server"
    exit 1
  fi
}

case "$MODE" in
  desktop)
    if [ "$gui_ok" -eq 1 ]; then
      run_desktop
    else
      maybe_browser_fallback
    fi
    ;;
  browser)
    cd "$APP" && exec "$VPY" app.py --browser $EXTRA
    ;;
  server)
    run_server
    ;;
  *)
    if [ "$gui_ok" -eq 1 ]; then
      run_desktop
    else
      maybe_browser_fallback
    fi
    ;;
esac
