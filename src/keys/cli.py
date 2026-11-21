"""The `keys` command line: one parser, one top-level error handler.

Every command prints only names, kinds, fingerprints, dates and verdicts. The handler at the
bottom turns any error into one line naming its type, never its text or attributes, since an
error from a failed child or request can carry the value it was handling.
"""

from __future__ import annotations

import argparse
import datetime
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import IO, TYPE_CHECKING, NoReturn

if TYPE_CHECKING:
    from _typeshed import SupportsWrite

EXIT_OK, EXIT_FAIL, EXIT_UNKNOWN, EXIT_USAGE, EXIT_INTERNAL = 0, 1, 2, 3, 4


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

    def say(self, line: str) -> None:
        print(line, file=self.stdout, flush=True)

    def warn(self, line: str) -> None:
        print(line, file=self.stderr, flush=True)


class _Parser(argparse.ArgumentParser):
    """argparse, writing to the context's streams and raising instead of exiting.

    argparse quotes the arguments it refuses; a value typed by mistake would be printed back,
    so each argument is replaced by <arg> in its messages.
    """

    ctx: Context
    argv: Sequence[str]

    def _print_message(self, message: str, file: SupportsWrite[str] | None = None) -> None:
        if message:
            stream = self.ctx.stderr if file is sys.stderr else self.ctx.stdout
            stream.write(message)

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        if message:
            self.ctx.stderr.write(message)
        raise _Exit(status)

    def error(self, message: str) -> NoReturn:
        for arg in sorted(self.argv, key=len, reverse=True):
            if len(arg) > 1:
                message = message.replace(arg, "<arg>")
        raise UsageError(f"{message}\nusage: see `keys {self.prog.split()[-1]} --help`")


class _Exit(Exception):
    def __init__(self, status: int) -> None:
        super().__init__()
        self.status = status


def _parser(ctx: Context, argv: Sequence[str]) -> _Parser:
    def make(**kwargs: object) -> _Parser:
        p = _Parser(**kwargs)  # type: ignore[arg-type]
        p.ctx, p.argv = ctx, argv
        return p

    top = make(
        prog="keys",
        description="Credentials without their values: list, check, scan, scrub and create.",
    )
    sub = top.add_subparsers(dest="command", metavar="<command>", parser_class=_Parser)

    def add(name: str, help_text: str) -> _Parser:
        p = sub.add_parser(name, help=help_text, description=help_text)
        p.ctx, p.argv = ctx, argv
        return p

    add("list", "every credential in the mapping file: fingerprint, expiry, lifetime, problems")
    add("check", "ask a service whether a key works, without printing the key")
    add("scan", "search transcripts, history and logs for known values and secret shapes")
    add("scrub", "replace found values in one file with a marker, in place")
    add("new", "make an empty 1Password item for a credential and its mapping entry")
    return top


def run(argv: Sequence[str], ctx: Context) -> int:
    args = _parser(ctx, argv).parse_args(list(argv))
    command: str | None = args.command
    if command is None:
        raise UsageError("usage: keys <command> [options]; `keys --help` lists the commands")
    raise UsageError(f"keys {command} is not built yet")


def main(argv: Sequence[str] | None = None, ctx: Context | None = None) -> int:
    """Run one command. Never raises; never prints a traceback or an error's text."""
    ctx = ctx or Context()
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        return run(argv, ctx)
    except _Exit as e:
        return EXIT_OK if e.status == 0 else EXIT_USAGE
    except UsageError as e:
        ctx.warn(f"keys: {e}")
        return EXIT_USAGE
    except KeyboardInterrupt:
        ctx.warn("keys: interrupted")
        return 130
    except Exception as e:
        ctx.warn(f"keys: stopped by an unexpected {type(e).__name__}; nothing more is shown")
        return EXIT_INTERNAL


def entry() -> NoReturn:
    sys.exit(main())
