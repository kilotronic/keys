"""The canary harness's watch inside a Python process: every child started, every file opened for
writing. Uses audit hooks (PEP 578), so nothing in keys has to cooperate.

In the test process the harness calls `watch(sink)` around each step. In a `keys` process
started from a real shell, sitecustomize calls `install_from_env()`, which appends one JSON line
per event to $KEYS_CANARY_HOOK_LOG for the harness to read afterwards.

Standard library only: it is imported by sitecustomize before anything else exists.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from collections.abc import Callable
from typing import Any, cast

Sink = Callable[[dict[str, Any]], None]

_sink: Sink | None = None
_busy = threading.local()
_installed = False
WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC


def _text(x: object) -> str:
    if isinstance(x, bytes):
        return x.decode(errors="replace")
    return str(x)


def _argv(args: object) -> list[str]:
    if isinstance(args, (str, bytes, os.PathLike)):
        return [_text(os.fspath(args))]  # type: ignore[arg-type]
    if isinstance(args, (list, tuple)):
        return [_text(os.fspath(a) if isinstance(a, os.PathLike) else a) for a in args]  # type: ignore[arg-type]
    return [_text(args)]


def _env(env: object) -> dict[str, str]:
    if env is None:
        return dict(os.environ)
    if isinstance(env, dict):
        return {_text(k): _text(v) for k, v in env.items()}  # type: ignore[misc]
    return {}


def _hook(event: str, args: tuple[Any, ...]) -> None:
    sink = _sink
    if sink is None or getattr(_busy, "on", False):
        return
    _busy.on = True
    try:
        if event == "subprocess.Popen":
            executable, argv, _cwd, env = args
            sink(
                {
                    "event": "spawn",
                    "program": _text(executable),
                    "argv": _argv(argv),
                    "env": _env(env),
                }
            )
        elif event in ("os.exec", "os.posix_spawn"):
            path, argv, env = args
            sink({"event": "spawn", "program": _text(path), "argv": _argv(argv), "env": _env(env)})
        elif event == "os.spawn":
            _mode, path, argv, env = args
            sink({"event": "spawn", "program": _text(path), "argv": _argv(argv), "env": _env(env)})
        elif event == "os.system":
            sink(
                {
                    "event": "spawn",
                    "program": "sh",
                    "argv": ["sh", "-c", _text(args[0])],
                    "env": _env(None),
                }
            )
        elif event == "open":
            path, mode, flags = args
            if isinstance(path, int) or path is None:
                return
            writing = (mode is not None and any(c in str(mode) for c in "wax+")) or (
                isinstance(flags, int) and flags & WRITE_FLAGS
            )
            if writing and isinstance(path, (str, bytes, os.PathLike)):
                name = _text(os.fspath(cast("str | bytes", path)))
                sink({"event": "write", "path": os.path.abspath(name)})
    finally:
        _busy.on = False


def _install() -> None:
    global _installed
    if not _installed:
        sys.addaudithook(_hook)
        _installed = True


def watch(sink: Sink | None) -> None:
    """Send this process's events to sink, or stop with None."""
    global _sink
    _install()
    _sink = sink


def install_from_env() -> None:
    log = os.environ.get("KEYS_CANARY_HOOK_LOG")
    if not log:
        return
    sys.dont_write_bytecode = True

    def sink(row: dict[str, Any]) -> None:
        with open(log, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")

    watch(sink)
