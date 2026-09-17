"""Capped runtime log for TrafficWatch (data/logs/trafficwatch.log).

The desktop app runs under pythonw with no console, so print() output and
uncaught errors were lost after boot. install() tees stdout/stderr into a
rotating file (1 MB x 3), quiets per-request access logs, and redacts
one-time pair codes and tokens before anything reaches disk.
"""
from __future__ import annotations

import logging
import os
import re
import sys
import threading
from logging.handlers import RotatingFileHandler

_DATA_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data"))
LOG_DIR = os.path.join(_DATA_DIR, "logs")
LOG_PATH = os.path.join(LOG_DIR, "trafficwatch.log")

_REDACT = [
    (re.compile(r"(?i)([?&](?:code|tw_token|token|ticket)=)[^&\s\"']+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(x-tw-token\s*[:=]\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(bearer\s+)\S+"), r"\1[REDACTED]"),
]

_installed = False
_lock = threading.Lock()


def redact(text: str) -> str:
    for pat, repl in _REDACT:
        text = pat.sub(repl, text)
    return text


class _RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact(record.getMessage())
            record.args = ()
        except Exception:
            pass
        return True


class _StreamToLog:
    """File-like object: forwards complete lines to a logger, and to the original stream if any."""

    def __init__(self, logger: logging.Logger, level: int, original) -> None:
        self._logger = logger
        self._level = level
        self._original = original
        self._buf = ""

    def write(self, s) -> int:
        if not isinstance(s, str):
            s = str(s)
        if self._original is not None:
            try:
                self._original.write(s)
            except Exception:
                pass
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            line = line.rstrip()
            if line:
                self._logger.log(self._level, line)
        return len(s)

    def flush(self) -> None:
        if self._original is not None:
            try:
                self._original.flush()
            except Exception:
                pass

    def isatty(self) -> bool:
        return False


def install() -> str | None:
    """Idempotent. Returns the log path, or None if the log could not be opened."""
    global _installed
    with _lock:
        if _installed:
            return LOG_PATH
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            handler = RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        except Exception:
            return None
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        handler.addFilter(_RedactFilter())
        # A failing handler must not print to stderr: stderr is tee'd back into logging.
        logging.raiseExceptions = False
        root = logging.getLogger()
        root.addHandler(handler)
        if root.level > logging.INFO or root.level == logging.NOTSET:
            root.setLevel(logging.INFO)
        # Per-request access lines are noise, not useful app logs.
        logging.getLogger("werkzeug").setLevel(logging.WARNING)
        logging.getLogger("engineio.server").setLevel(logging.WARNING)
        logging.getLogger("socketio.server").setLevel(logging.WARNING)

        out_logger = logging.getLogger("tw.stdout")
        err_logger = logging.getLogger("tw.stderr")
        sys.stdout = _StreamToLog(out_logger, logging.INFO, sys.stdout)
        sys.stderr = _StreamToLog(err_logger, logging.WARNING, sys.stderr)

        def _excepthook(exc_type, exc, tb):
            logging.getLogger("tw").critical("Uncaught exception", exc_info=(exc_type, exc, tb))

        def _thread_excepthook(args):
            logging.getLogger("tw").error(
                "Uncaught exception in thread %s",
                getattr(args.thread, "name", "?"),
                exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
            )

        sys.excepthook = _excepthook
        threading.excepthook = _thread_excepthook
        _installed = True
        logging.getLogger("tw").info("TrafficWatch log started (pid %s)", os.getpid())
        return LOG_PATH


PID_PATH = os.path.join(_DATA_DIR, "app.pid")


def write_pid_file() -> None:
    """Record this app process for the uninstaller (the launcher starts desktop.py by relative path,
    so its command line does not contain the install folder)."""
    import atexit
    import json

    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        with open(PID_PATH, "w", encoding="ascii") as f:
            json.dump({"pid": os.getpid(), "exe": sys.executable}, f)
    except Exception as exc:
        logging.getLogger("tw").warning("pid file not written: %s", exc)
        return

    atexit.register(remove_pid_file)


def remove_pid_file() -> None:
    """Delete app.pid only if it still names this process."""
    import json

    try:
        with open(PID_PATH, encoding="ascii") as f:
            if json.load(f).get("pid") == os.getpid():
                os.remove(PID_PATH)
    except Exception:
        pass
