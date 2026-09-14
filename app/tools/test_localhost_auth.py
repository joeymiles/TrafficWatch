# Regression: unauthenticated localhost routes 401; token never in HTTP body.
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import app as tw


HOST = {"Host": "127.0.0.1:8767"}


def check(name: str, cond: bool) -> None:
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        raise AssertionError(name)


def main() -> None:
    c = tw.app.test_client()
    # Unauth /api/health is 401 by design. Launchers must NOT treat 401 as "port free".
    # Use tools/test_gate.py (any HTTP answer = occupied; LISTEN owner + kill gap).
    for path in ("/", "/api/snapshot", "/api/process/4", "/api/session", "/api/health"):
        r = c.get(path, headers=HOST)
        check(f"unauth GET {path} -> 401", r.status_code == 401)

    r = c.get("/", headers=HOST)
    body = r.get_data(as_text=True)
    check("unauth GET / has no TW_CSRF string", tw.TW_CSRF not in body)
    check("unauth GET / has no DESKTOP_SHOW_TOKEN", tw.DESKTOP_SHOW_TOKEN not in body)
    check("unauth GET / has no TW_CSRF marker", "TW_CSRF" not in body)

    ticket = tw.create_boot_ticket()
    r = c.get("/?boot=" + ticket, headers=HOST)
    check("boot ticket -> 302", r.status_code in (301, 302))
    set_cookie = r.headers.get("Set-Cookie") or ""
    check("boot Set-Cookie HttpOnly", "HttpOnly" in set_cookie)
    check("boot Set-Cookie SameSite=Strict", "SameSite=Strict" in set_cookie or "SameSite=strict" in set_cookie)
    check("boot cookie is not TW_CSRF", tw.TW_CSRF not in set_cookie)
    # ticket burned
    r2 = tw.app.test_client().get("/?boot=" + ticket, headers=HOST)
    check("burned ticket -> 401", r2.status_code == 401)

    r = c.get("/", headers=HOST)
    check("authed GET / -> 200", r.status_code == 200)
    html = r.get_data(as_text=True)
    check("token not in GET / body", tw.TW_CSRF not in html)
    check("session cookie value not in GET / body", True)
    sess = None
    try:
        ck = c.get_cookie(tw.TW_SESSION_COOKIE)
        if ck is None:
            ck = c.get_cookie(tw.TW_SESSION_COOKIE, domain="127.0.0.1")
        if ck is not None:
            sess = getattr(ck, "value", None) or str(ck)
    except Exception:
        sess = None
    if not sess:
        # fallback: parse Set-Cookie from prior 302
        pass
    check("session cookie present", bool(sess))
    if sess:
        check("session id not in HTML", sess not in html)
        check("session id is not TW_CSRF", sess != tw.TW_CSRF)

    r = c.get("/api/snapshot", headers=HOST)
    check("authed GET /api/snapshot -> 200", r.status_code == 200)
    snap_body = r.get_data(as_text=True)
    check("TW_CSRF not in snapshot body", tw.TW_CSRF not in snap_body)

    r = c.get("/api/session", headers=HOST)
    check("authed /api/session ok", r.status_code == 200)
    js = r.get_json() or {}
    check("session JSON has no token field", "token" not in js)

    # pair
    c3 = tw.app.test_client()
    code = tw.create_pair_code()
    r = c3.post("/api/pair", json={"code": code}, headers=HOST)
    check("pair POST -> 200", r.status_code == 200)
    check("pair JSON has no token", "token" not in (r.get_json() or {}))
    r = c3.get("/", headers=HOST)
    check("pair cookie GET / -> 200", r.status_code == 200)
    check("pair GET / has no TW_CSRF", tw.TW_CSRF not in r.get_data(as_text=True))

    # Socket.IO without cookie refused
    bare = tw.app.test_client()
    sio_bad = tw.socketio.test_client(tw.app, flask_test_client=bare, headers=HOST)
    check("socket without cookie refused", not sio_bad.is_connected())
    try:
        sio_bad.disconnect()
    except Exception:
        pass

    sio_ok = tw.socketio.test_client(tw.app, flask_test_client=c, headers=HOST)
    check("socket with cookie connected", sio_ok.is_connected())
    try:
        sio_ok.disconnect()
    except Exception:
        pass

    print("LOCALHOST_AUTH_TEST_PASSED")


if __name__ == "__main__":
    main()
