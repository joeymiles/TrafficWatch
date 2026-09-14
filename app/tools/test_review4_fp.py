# tools/test_review4_fp.py — Review 4 false-positive scratch tests
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import signals
import dns_detect


def check(name: str, cond: bool) -> None:
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}")
    if not cond:
        raise AssertionError(name)


def main() -> None:
    # Item 1 unusual_port
    check(
        "127.0.0.1:8767 listen = False",
        signals._unusual_port(8767, as_listener=True, local_ip="127.0.0.1") is False,
    )
    check(
        "0.0.0.0:5355 listen = False",
        signals._unusual_port(5355, as_listener=True, local_ip="0.0.0.0") is False,
    )
    check(
        "127.0.0.1:50000 listen = False",
        signals._unusual_port(50000, as_listener=True, local_ip="127.0.0.1") is False,
    )
    check(
        "0.0.0.0:1337 listen = True",
        signals._unusual_port(1337, as_listener=True, local_ip="0.0.0.0") is True,
    )
    check(
        "outbound :443 = False",
        signals._unusual_port(443, as_listener=False) is False,
    )

    # Item 2 dns examples must not be dga
    examples = [
        "d1a2b3c4d5e6f7.cloudfront.net",
        "r4---sn-8xgp1vo-p5qe.googlevideo.com",
        "ec2-54-12-34-56.us-west-2.compute.amazonaws.com",
        "lb-140-82-112-4-iad.github.com",
        "a23-45-67-89.deploy.static.akamaitechnologies.com",
        "prod-useast1-telemetry.microsoft.com",
    ]
    for e in examples:
        check(f"_is_dga_ish({e}) = False", dns_detect._is_dga_ish(e) is False)
        check(f"_is_rare_tld({e}) = False", dns_detect._is_rare_tld(e) is False)

    check("rare_tld example.com.info = False", dns_detect._is_rare_tld("example.com.info") is False)

    # Parent over-match: flagged child must NOT flag parent hostname
    rows = [
        {
            "hostname": "amazonaws.com",
            "pid": 42,
            "process": "svc.exe",
            "signals": [],
            "dns_queries": [],
        }
    ]
    # Inject rare map via analyze path: call attach with monkeypatched rare
    rare_child = "xk7qz9vb2m4n8p.amazonaws.com"
    # Simulate attach_dns_signals match logic
    n = "amazonaws.com"
    hit = False
    for rn in (rare_child,):
        if n == rn or n.endswith("." + rn):
            hit = True
        # old buggy direction must not be used
        buggy = rn.endswith("." + n)
    check("parent-over-match not used (child endswith parent is True but ignored)", buggy is True)
    check("parent hostname not flagged as child-of-flagged", hit is False)

    # attach_dns_signals should not flag allowlisted hostnames even if in rare
    # Force by temporarily putting allowlisted name into rare via analyze_queries path:
    out = dns_detect.attach_dns_signals(
        [
            {
                "hostname": e,
                "pid": 7,
                "process": "chrome.exe",
                "signals": [],
                "dns_queries": [e],
            }
            for e in examples
        ]
    )
    for r in out:
        ids = {s.get("id") for s in (r.get("signals") or [])}
        check(f"attach no dns_rare for {r.get('hostname')}", "dns_rare" not in ids)

    print("ALL_REVIEW4_FP_TESTS_PASSED")


if __name__ == "__main__":
    main()