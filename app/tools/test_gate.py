"""Shared TrafficWatch TEST-PORT gate (Claude + Prototype).

Not product code. Do not import from app.py / desktop.py / signals.py.

Why (ux46, 2026-09-14): Claude's pre-launch check treated HTTP 401 from
/api/health as "port free". Unauthenticated /api/health is 401 by design, so
a live TW looked idle. Windows then allowed a second bind; pair POST hit the
other server. Prototype's verify tail was the occupant.

Rules (all three, every launch):
  1. ANY HTTP answer from the test port (200/301/401/403/404/5xx/...) = in use.
     401 is a live TW without a cookie, NOT a free port.
     Timeouts / connection-refused are not HTTP answers (some Windows hosts
     drop SYNs to unused localhost ports instead of RST).
  2. Assert no TCP LISTEN owner before launching a test server (psutil and/or
     Get-NetTCPConnection). Bind-only checks are NOT enough: Windows
     SO_REUSEADDR can succeed on an occupied 8767. Successful TCP connect
     also counts as occupied.
  3. After exact-PID kill, wait POST_KILL_GAP_SEC before reusing the port
     (LISTEN / TIME_WAIT teardown). Never image-name kills. Never kill
     protected PIDs (from TW_PROTECTED_PIDS env, comma-separated; default empty).

CLI:
  python tools/test_gate.py check [--host 127.0.0.1] [--port 8767]
  python tools/test_gate.py wait  [--host 127.0.0.1] [--port 8767] [--timeout 15]
  python tools/test_gate.py kill  --pid N [N ...] [--gap 1.5]
  python tools/test_gate.py selftest

Import from a sibling tools script:
  import importlib.util, pathlib
  p = pathlib.Path(__file__).resolve().parent / "test_gate.py"
  spec = importlib.util.spec_from_file_location("tw_test_gate", p)
  g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
  g.assert_port_clear()
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8767
POST_KILL_GAP_SEC = 1.5
# Exact-PID kill must never hit protected PIDs. Default empty; set via TW_PROTECTED_PIDS
# (comma-separated integers), e.g. TW_PROTECTED_PIDS=1234,5678
def _protected_pids() -> frozenset[int]:
    raw = (os.environ.get("TW_PROTECTED_PIDS") or "").strip()
    if not raw:
        return frozenset()
    out: set[int] = set()
    for part in raw.split(","):
        s = part.strip()
        if s.isdigit():
            out.add(int(s))
    return frozenset(out)


PROTECTED_PIDS = _protected_pids()
PROBE_PATHS = ("/api/health", "/")
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_occupies(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, timeout: float = 1.2) -> tuple[bool, str]:
    """True when ANY HTTP answer (incl. 401/403) comes back from host:port."""
    last = "no HTTP answer"
    for path in PROBE_PATHS:
        url = f"http://{host}:{int(port)}{path}"
        try:
            req = urllib.request.Request(url, method="GET")
            with _NO_PROXY.open(req, timeout=timeout) as resp:
                code = int(getattr(resp, "status", 200) or 200)
            return True, f"HTTP {code} {path}"
        except urllib.error.HTTPError as e:
            return True, f"HTTP {int(e.code)} {path}"
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            last = f"no HTTP ({type(reason).__name__}: {reason})"
            continue
        except (TimeoutError, socket.timeout):
            last = "no HTTP (timeout)"
            continue
        except OSError as e:
            last = f"no HTTP (OSError {e})"
            continue
    return False, last


def tcp_accepted(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, timeout: float = 0.6) -> bool:
    """True only if TCP connect succeeds (something accepted). Timeout/refused = False."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, int(port)))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def listen_pids(port: int = DEFAULT_PORT) -> list[int]:
    """PIDs with a TCP LISTEN socket on the port (empty = none)."""
    found: set[int] = set()
    try:
        import psutil  # type: ignore

        for c in psutil.net_connections(kind="tcp"):
            st = str(getattr(c, "status", "") or "").upper().replace("CONN_", "")
            if st != "LISTEN":
                continue
            laddr = c.laddr
            lp = getattr(laddr, "port", None)
            if lp is None and isinstance(laddr, (tuple, list)) and len(laddr) >= 2:
                lp = laddr[1]
            if int(lp or 0) != int(port):
                continue
            if c.pid:
                found.add(int(c.pid))
    except Exception:
        pass
    if sys.platform == "win32":
        try:
            cmd = (
                f"Get-NetTCPConnection -LocalPort {int(port)} -State Listen "
                "-ErrorAction SilentlyContinue | "
                "Select-Object -ExpandProperty OwningProcess"
            )
            out = subprocess.check_output(
                ["powershell.exe", "-NoProfile", "-Command", cmd],
                text=True,
                timeout=8,
                stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                s = line.strip()
                if s.isdigit():
                    found.add(int(s))
        except Exception:
            pass
    return sorted(found)


def port_status(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> dict:
    occ, why = http_occupies(host, port)
    owners = listen_pids(port)
    accepted = False if (occ or owners) else tcp_accepted(host, port)
    in_use = bool(occ or owners or accepted)
    if in_use and not occ and accepted:
        why = "TCP connect succeeded (no HTTP body yet)"
    return {
        "host": host,
        "port": int(port),
        "in_use": in_use,
        "http": why,
        "listen_pids": owners,
        "tcp_accepted": accepted,
        "free": not in_use,
    }


def assert_port_clear(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> dict:
    """Raise SystemExit unless HTTP is silent AND no LISTEN owner AND no TCP accept."""
    st = port_status(host, port)
    if not st["free"]:
        raise SystemExit(
            "test_gate: port {port} in use ({http}); LISTEN pids={pids}".format(
                port=st["port"], http=st["http"], pids=st["listen_pids"]
            )
        )
    return st


def wait_port_clear(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    timeout: float = 15.0,
    poll: float = 0.25,
) -> dict:
    deadline = time.time() + float(timeout)
    last: dict | None = None
    while time.time() < deadline:
        last = port_status(host, port)
        if last["free"]:
            return last
        time.sleep(poll)
    raise SystemExit(
        "test_gate: port {port} still in use after {t}s ({http}); LISTEN pids={pids}".format(
            port=port,
            t=timeout,
            http=(last or {}).get("http"),
            pids=(last or {}).get("listen_pids"),
        )
    )


def kill_exact(
    pids: list[int],
    gap_sec: float = POST_KILL_GAP_SEC,
    protected: frozenset[int] = PROTECTED_PIDS,
) -> dict:
    """Kill only the given PIDs, then wait gap_sec before the caller reuses a port."""
    killed: list[int] = []
    skipped: list[str] = []
    for raw in pids:
        pid = int(raw)
        if pid in protected:
            raise SystemExit(f"test_gate: refusing to kill protected PID {pid}")
        if pid <= 0:
            raise SystemExit(f"test_gate: invalid pid {pid}")
        try:
            if sys.platform == "win32":
                r = subprocess.run(
                    ["taskkill", "/PID", str(pid), "/F"],
                    capture_output=True,
                    timeout=8,
                    text=True,
                )
                if r.returncode not in (0, 128):
                    skipped.append(f"{pid}: {r.stderr.strip() or r.stdout.strip() or r.returncode}")
                else:
                    killed.append(pid)
            else:
                os.kill(pid, 15)
                killed.append(pid)
        except Exception as e:
            skipped.append(f"{pid}: {e}")
    gap = max(0.0, float(gap_sec))
    if gap:
        time.sleep(gap)
    return {"killed": killed, "skipped": skipped, "gap_sec": gap}


def _selftest() -> int:
    """Prove 401 counts as occupied; LISTEN owner blocks; kill+gap frees. Uses :18767."""
    host = "127.0.0.1"
    port = 18767
    st = port_status(host, port)
    if not st["free"]:
        print("SELFTEST SKIP: :18767 already in use", json.dumps(st))
        return 2
    server = r"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(401)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"unauth")
    def log_message(self, *args):
        pass
port = int(os.environ["TW_GATE_PORT"])
HTTPServer(("127.0.0.1", port), H).serve_forever()
"""
    env = os.environ.copy()
    env["TW_GATE_PORT"] = str(port)
    proc = subprocess.Popen(
        [sys.executable, "-c", server],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    kid = int(proc.pid)
    try:
        deadline = time.time() + 8
        occupied = False
        why = ""
        while time.time() < deadline:
            occ, why = http_occupies(host, port)
            owners = listen_pids(port)
            if occ or owners or tcp_accepted(host, port):
                occupied = occ
                break
            time.sleep(0.1)
        owners = listen_pids(port)
        st_busy = port_status(host, port)
        if st_busy["free"]:
            raise SystemExit(
                f"selftest: 401 server not seen as in use (http={why} listen={owners} kid={kid})"
            )
        if occupied and "401" not in why:
            raise SystemExit(f"selftest: expected HTTP 401, got {why}")
        if occupied:
            print("selftest HTTP-any:", why, "LISTEN", owners, "PASS")
        else:
            if not owners and not st_busy.get("tcp_accepted"):
                raise SystemExit("selftest: no HTTP 401, no LISTEN, no TCP accept")
            print("selftest LISTEN/tcp (HTTP filtered):", why, "LISTEN", owners, "PASS")
        kill_exact([kid], gap_sec=POST_KILL_GAP_SEC)
        kid = 0
        wait_port_clear(host, port, timeout=8)
        print("selftest kill+gap freed :%s PASS" % port)
        return 0
    finally:
        if kid:
            try:
                kill_exact([kid], gap_sec=0.3)
            except Exception:
                pass
        try:
            proc.wait(timeout=3)
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="TrafficWatch shared test-port gate")
    sub = p.add_subparsers(dest="cmd", required=True)
    pc = sub.add_parser("check", help="print JSON status; exit 1 if in use")
    pw = sub.add_parser("wait", help="block until free or timeout")
    pk = sub.add_parser("kill", help="exact-PID kill then gap")
    sub.add_parser("selftest", help="401-as-occupied + kill-gap on :18767")
    for sp in (pc, pw):
        sp.add_argument("--host", default=DEFAULT_HOST)
        sp.add_argument("--port", type=int, default=DEFAULT_PORT)
    pw.add_argument("--timeout", type=float, default=15.0)
    pk.add_argument("--pid", type=int, nargs="+", required=True)
    pk.add_argument("--gap", type=float, default=POST_KILL_GAP_SEC)
    args = p.parse_args(argv)
    if args.cmd == "check":
        st = port_status(args.host, args.port)
        print(json.dumps(st))
        return 0 if st["free"] else 1
    if args.cmd == "wait":
        st = wait_port_clear(args.host, args.port, timeout=args.timeout)
        print(json.dumps(st))
        return 0
    if args.cmd == "kill":
        info = kill_exact(args.pid, gap_sec=args.gap)
        print(json.dumps(info))
        return 0
    if args.cmd == "selftest":
        return _selftest()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
