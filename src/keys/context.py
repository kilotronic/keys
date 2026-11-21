"""What every command shares: its streams, environment and clock, and its error type."""

from __future__ import annotations

import datetime
import os
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

EXIT_OK, EXIT_FAIL, EXIT_UNKNOWN, EXIT_USAGE, EXIT_INTERNAL = 0, 1, 2, 3, 4
EXIT_WAITING = 5  # keys rotate is waiting for the owner: a paste, or a click on a page


class UsageError(Exception):
    """A mistake in how keys was called or configured. Its message never holds a value."""


def _today() -> datetime.date:
    return datetime.date.today()


@dataclass
class Context:
    """What a command reads from and writes to; tests swap in their own."""

    stdout: IO[str] = field(default_factory=lambda: sys.stdout)
    stderr: IO[str] = field(default_factory=lambda: sys.stderr)
    stdin: IO[str] = field(default_factory=lambda: sys.stdin)
    environ: Mapping[str, str] = field(default_factory=lambda: os.environ)
    today: Callable[[], datetime.date] = _today
    # The HTTPS client keys check uses; None is the real one (keys.probes.send).
    send: Callable[..., Any] | None = None
    # How keys waits between looks at a deployment; tests make it instant.
    sleep: Callable[[float], None] = time.sleep

    def say(self, line: str) -> None:
        print(line, file=self.stdout, flush=True)

    def warn(self, line: str) -> None:
        print(line, file=self.stderr, flush=True)

    def cwd(self) -> Path:
        return Path.cwd()
