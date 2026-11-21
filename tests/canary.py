"""The canary harness (`keys-canary`): run a keys command with a planted fake value, and fail if
the value shows up anywhere it should not.

It watches stdout and stderr (the context's streams and the real ones), the text of any
exception that escapes, every child process's argv (children are fakes on PATH that record what
they were started with), every file under a temporary home, temp directory and working directory,
and, for `shell()`, the history of a real interactive zsh that ran the command.

The value is searched for as sent and in the forms a leak usually takes: base64 (padded or not,
URL-safe, and shifted inside a longer encoded string as Basic auth does), hex, URL encoding, JSON
escaping, and any 12-character piece. A hint (first 8 and last 4) is allowed: keys prints one for
provider-issued keys by design.

Every value here is made up. Nothing in this harness touches a real 1Password or a real service.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import traceback
from collections.abc import Callable, Generator, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, quote_plus

import pytest

from keys import cli

# Made up. Holds + / = " \ so that every encoding below differs from the raw form.
CANARY = 'kc_7Qm+Xv/Lr2"J8\\pW=3nTb5Hz9Ys4Ue6Kd'
PIECE = 12  # the longest run of the value's characters allowed in output (the hint shows 8)
FAKE_CHILD = Path(__file__).with_name("fake_child.py")
FAKE_PROGRAMS = ("op", "gh", "railway", "az", "gcloud", "security", "pbcopy")


class LeakError(AssertionError):
    """The planted value reached a channel it must never reach."""


def forms(value: str) -> dict[str, bytes]:
    """The value as sent and in each encoded form a leak usually takes, by name."""
    raw = value.encode()
    out: dict[str, bytes] = {
        "raw": raw,
        "hex": raw.hex().encode(),
        "hex-upper": raw.hex().upper().encode(),
        "url": quote(value, safe="").encode(),
        "url-path": quote(value).encode(),
        "url-plus": quote_plus(value).encode(),
        "json": json.dumps(value)[1:-1].encode(),
        "json-ascii": json.dumps(value, ensure_ascii=True)[1:-1].encode(),
        "repr": repr(value)[1:-1].encode(),
    }
    for shift in range(3):
        # The characters that depend only on the value, whatever came before it.
        start = (shift * 8 + 5) // 6
        for name, enc in (("base64", base64.b64encode), ("base64-url", base64.urlsafe_b64encode)):
            text = enc(b"\0" * shift + raw).rstrip(b"=")
            out[f"{name}-shift{shift}"] = text[start : len(text) - 2]
    return {k: v for k, v in out.items() if v}


def pieces(value: str) -> set[bytes]:
    raw = value.encode()
    return {raw[i : i + PIECE] for i in range(len(raw) - PIECE + 1)}


def find_leak(value: str, data: bytes) -> str | None:
    """The name of the first form of value found in data, or None."""
    for name, needle in forms(value).items():
        if needle in data:
            return name
    for piece in pieces(value):
        if piece in data:
            return "piece"
    return None


@dataclass
class Child:
    prog: str
    argv: list[str]
    stdin: str


@dataclass
class Result:
    code: int
    stdout: str
    stderr: str
    children: list[Child] = field(default_factory=lambda: list[Child]())


class Canary:
    """One planted value, one temporary home; `run`, `call` and `shell` check every channel."""

    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch, value: str = CANARY) -> None:
        self.value = value
        self.monkeypatch = monkeypatch
        self.home = root / "home"
        self.tmp = root / "tmp"
        self.work = root / "work"
        self.bin = root / "harness" / "bin"
        self.state = root / "harness" / "state"
        for d in (self.home, self.tmp, self.work, self.bin, self.state):
            d.mkdir(parents=True)
        self.db_path = self.state / "fake-db.json"
        self.log_path = self.state / "children.jsonl"
        self.db: dict[str, Any] = {"values": {}, "fail": {}, "items": [], "create_fail": None}
        self._save_db()
        for prog in FAKE_PROGRAMS:
            self._install_fake(prog)
        self._install_keys()
        self.planted: dict[Path, str] = {}
        self.extra_values: list[str] = []

    # ------------------------------------------------------------------ setting the scene

    def _install_fake(self, prog: str) -> None:
        path = self.bin / prog
        path.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE_CHILD}" {prog} "$@"\n')
        path.chmod(0o755)

    def _install_keys(self) -> None:
        path = self.bin / "keys"
        path.write_text(f'#!/bin/sh\nexec "{sys.executable}" -m keys "$@"\n')
        path.chmod(0o755)

    def _save_db(self) -> None:
        self.db_path.write_text(json.dumps(self.db))

    def op_value(self, ref: str, value: str) -> None:
        """The fake op answers `op read ref` with value."""
        self.db["values"][ref] = value
        if value != self.value:
            self.extra_values.append(value)
        self._save_db()

    def op_fail(self, ref: str, code: int = 1, stderr: str | None = None) -> None:
        """The fake op fails `op read ref`; by default its error text holds the canary."""
        self.db["fail"][ref] = {"code": code, "stderr": stderr or f"[ERROR] {self.value}"}
        self._save_db()

    def op_items(self, items: list[dict[str, Any]]) -> None:
        """What the fake `op item list --format json` prints."""
        self.db["items"] = items
        self._save_db()

    def op_create_fails(self, code: int = 1) -> None:
        self.db["create_fail"] = {"code": code, "stderr": f"[ERROR] {self.value}"}
        self._save_db()

    def plant(self, rel: str, text: str) -> Path:
        """A file under the temporary home that is allowed to hold the value, while unchanged."""
        path = self.home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        self.planted[path] = _digest(path.read_bytes())
        return path

    def unplant(self, path: Path) -> None:
        """A planted file the command is expected to change (scrub): checked like any other."""
        self.planted.pop(path, None)

    def environ(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        env = {
            "HOME": str(self.home),
            "TMPDIR": str(self.tmp),
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "KEYS_FAKE_DB": str(self.db_path),
            "KEYS_FAKE_LOG": str(self.log_path),
        }
        return {**env, **(extra or {})}

    def children(self) -> list[Child]:
        if not self.log_path.exists():
            return []
        rows = [json.loads(line) for line in self.log_path.read_text().splitlines() if line]
        return [Child(r["prog"], r["argv"], r["stdin"]) for r in rows]

    def history(self) -> str:
        path = self.home / ".zsh_history"
        return path.read_text(errors="replace") if path.exists() else ""

    # ------------------------------------------------------------------ running

    def run(
        self,
        argv: Sequence[str],
        *,
        stdin: str = "",
        env: dict[str, str] | None = None,
        **ctx: Any,
    ) -> Result:
        """keys <argv>, in process, through cli.main with the harness's context."""

        def step(c: cli.Context) -> int:
            return cli.main(list(argv), ctx=c)

        return self.call(step, stdin=stdin, env=env, **ctx)

    def call(
        self,
        step: Callable[[cli.Context], int],
        *,
        stdin: str = "",
        env: dict[str, str] | None = None,
        **ctx: Any,
    ) -> Result:
        """Any step that takes a context, with every channel watched."""
        self.log_path.unlink(missing_ok=True)
        environ = self.environ(env)
        out, err = io.StringIO(), io.StringIO()
        real_out, real_err = io.StringIO(), io.StringIO()
        context = cli.Context(
            stdout=out, stderr=err, stdin=io.StringIO(stdin), environ=environ, **ctx
        )
        escaped: str | None = None
        code = -1
        with self._isolated(environ), self._real_streams(real_out, real_err):
            try:
                code = step(context)
            except BaseException:
                escaped = traceback.format_exc()
        result = Result(code, out.getvalue() + real_out.getvalue(), err.getvalue(), [])
        result.stderr += real_err.getvalue()
        result.children = self.children()
        self._check(result, escaped=escaped)
        if escaped is not None:
            raise AssertionError("keys let an exception escape (its text held no value)")
        return result

    def shell(self, command: str, *, env: dict[str, str] | None = None) -> Result:
        """command, typed into a real interactive zsh whose history file is in the temporary home.

        zsh records commands read from stdin by an interactive shell (not ones given with -c),
        so this is the history an agent's shell would keep.
        """
        if shutil.which("zsh") is None:
            pytest.fail("zsh is needed for the canary's shell-history check")
        self.log_path.unlink(missing_ok=True)
        (self.home / ".zshrc").write_text(
            f"HISTFILE={shlex.quote(str(self.home / '.zsh_history'))}\n"
            "HISTSIZE=1000\nSAVEHIST=1000\nPS1=''\nPROMPT=''\nRPROMPT=''\nPROMPT_EOL_MARK=''\n"
            "unsetopt BEEP\nsetopt INC_APPEND_HISTORY\n"
        )
        exit_file = self.state / "exit"
        exit_file.unlink(missing_ok=True)
        script = (
            f"{{ {command} ; }} </dev/null\nprint -r -- $? >| {shlex.quote(str(exit_file))}\nexit\n"
        )
        environ = self.environ({"ZDOTDIR": str(self.home), **(env or {})})
        proc = subprocess.run(
            ["zsh", "-i"],
            input=script,
            capture_output=True,
            text=True,
            env=environ,
            cwd=self.work,
            timeout=120,
            check=False,
        )
        code = int(exit_file.read_text().strip()) if exit_file.exists() else -1
        result = Result(code, proc.stdout, proc.stderr, self.children())
        self._check(result, escaped=None)
        return result

    @contextlib.contextmanager
    def _isolated(self, environ: dict[str, str]) -> Generator[None]:
        with self.monkeypatch.context() as m:
            for k, v in environ.items():
                m.setenv(k, v)
            m.setattr(tempfile, "tempdir", str(self.tmp))
            m.chdir(self.work)
            yield

    @contextlib.contextmanager
    def _real_streams(self, out: io.StringIO, err: io.StringIO) -> Generator[None]:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            yield

    # ------------------------------------------------------------------ checking

    def secrets(self) -> list[str]:
        return [self.value, *self.extra_values]

    def _check(self, result: Result, *, escaped: str | None) -> None:
        for value in self.secrets():
            channels: list[tuple[str, bytes]] = [
                ("stdout", result.stdout.encode()),
                ("stderr", result.stderr.encode()),
            ]
            if escaped is not None:
                channels.append(("exception", escaped.encode()))
            channels += [(f"argv of {c.prog}", "\0".join(c.argv).encode()) for c in result.children]
            for name, data in channels:
                form = find_leak(value, data)
                if form:
                    raise LeakError(f"the planted value reached {name} ({form} form)")
            for path in self._files():
                data = path.read_bytes()
                if self.planted.get(path) == _digest(data):
                    continue
                form = find_leak(value, data)
                if form:
                    raise LeakError(f"the planted value reached file {path} ({form} form)")

    def _files(self) -> Iterator[Path]:
        for root in (self.home, self.tmp, self.work):
            for dirpath, _, names in os.walk(root):
                for name in names:
                    path = Path(dirpath, name)
                    if path.is_file() and not path.is_symlink():
                        yield path


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
