"""The `keys` command line: one parser, one top-level error handler.

Every command prints only names, kinds, fingerprints, dates and verdicts. The handler at the
bottom turns any error into one line naming its type, never its text or attributes, since an
error from a failed child or request can carry the value it was handling.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import TYPE_CHECKING, NoReturn

if TYPE_CHECKING:
    from _typeshed import SupportsWrite

from keys import agent, checking, creating, fpcmd, listing, rotating, scanning, syncing
from keys.context import (
    EXIT_INTERNAL,
    EXIT_OK,
    EXIT_USAGE,
    Context,
    UsageError,
)
from keys.mapping import MappingError

__all__ = ["Context", "UsageError", "main"]


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
        description=(
            "Credentials without their values: list, check, scan, scrub, create, sync and rotate."
        ),
    )
    sub = top.add_subparsers(dest="command", metavar="<command>", parser_class=_Parser)

    def add(name: str, help_text: str) -> _Parser:
        p = sub.add_parser(name, help=help_text, description=help_text)
        p.ctx, p.argv = ctx, argv
        return p

    listing.configure(
        add("list", "every credential in the mapping file: fingerprint, expiry, lifetime, problems")
    )
    checking.configure(add("check", "ask a service whether a key works, without printing the key"))
    scanning.configure_scan(
        add("scan", "search transcripts, history and logs for known values and secret shapes")
    )
    scanning.configure_scrub(
        add("scrub", "replace found values in one file with a marker, in place")
    )
    creating.configure(
        add("new", "make an empty 1Password item for a credential and its mapping entry")
    )
    syncing.configure(add("sync", "write 1Password's value to every target in the mapping file"))
    fpcmd.configure_fp(
        add("fp", "a credential's keyed fingerprint, and its hint for a provider's key")
    )
    fpcmd.configure_leaks(
        add("leaks", "each leaked value in a gitleaks report, by fingerprint, never the value")
    )
    rotating.configure(add("rotate", "replace a credential end to end: make, store, sync, revoke"))
    agent.configure_install(
        add(
            "install-key",
            "copy a GitHub App key from 1Password into the keychain (off a Mac, a file), once",
        )
    )
    agent.configure_has_key(
        add("has-key", "exit 0 when this machine holds an App's key install-key wrote, else 1")
    )
    agent.configure_gh(
        add("gh", "run gh as the agents' GitHub App, with a token minted for the call")
    )
    agent.configure_git(
        add("git-credential", "answer git's credential requests for github.com as the App")
    )
    return top


def run(argv: Sequence[str], ctx: Context) -> int:
    args = _parser(ctx, argv).parse_args(list(argv))
    command: str | None = args.command
    if command is None:
        raise UsageError("usage: keys <command> [options]; `keys --help` lists the commands")
    if command == "list":
        return listing.run(args, ctx)
    if command == "check":
        return checking.run(args, ctx)
    if command == "scan":
        return scanning.scan(args, ctx)
    if command == "scrub":
        return scanning.scrub(args, ctx)
    if command == "new":
        return creating.run(args, ctx)
    if command == "sync":
        return syncing.run(args, ctx)
    if command == "fp":
        return fpcmd.fp(args, ctx)
    if command == "leaks":
        return fpcmd.report(args, ctx)
    if command == "rotate":
        return rotating.run(args, ctx)
    try:
        if command == "install-key":
            return agent.install(args, ctx)
        if command == "has-key":
            return agent.has_key(args, ctx)
        if command == "gh":
            return agent.gh(args, ctx)
        if command == "git-credential":
            return agent.git_credential(args, ctx)
    except agent.AgentError as e:
        return agent.handle(e, ctx)
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
    except MappingError as e:
        for problem in e.problems:
            ctx.warn(f"keys: {problem}")
        return EXIT_USAGE
    except KeyboardInterrupt:
        ctx.warn("keys: interrupted")
        return 130
    except Exception as e:
        ctx.warn(f"keys: stopped by an unexpected {type(e).__name__}; nothing more is shown")
        return EXIT_INTERNAL


def entry() -> NoReturn:
    sys.exit(main())
