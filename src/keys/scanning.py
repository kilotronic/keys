"""keys scan and keys scrub: the transcript and backup check.

scan searches the places an agent's or a shell's words are kept, all of them backed up and
outliving any key: Claude's folders (transcripts, typed-prompt history, file history, shell
snapshots, debug logs), Claude's temp and scratch folders, the Claude desktop app's logs and
support folder, Cursor's agent folders, shell history, and saved terminal state.

Two passes over each line: every credential in the mapping file, read in memory from 1Password
and searched for as sent and in its encoded forms (which catches what no pattern can: random
signing secrets, UUID-shaped tokens); then pattern rules for secret shapes. A finding names the
file, the line and the credential, or the rule, and never the text it matched.

scrub replaces the same matches in one file with a marker, in place, and prints only how many.
Nobody opens the file to redact it by hand, which would copy the value into a new transcript.
"""

from __future__ import annotations

import argparse
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from keys import forms, listing, mapping
from keys.context import EXIT_FAIL, EXIT_OK, EXIT_UNKNOWN, Context, UsageError
from keys.op import Op, OpError
from keys.secret import Secret

MARKER = b"[removed by keys scrub]"
MIN_LENGTH = 8  # a value shorter than this would match all over; it is not searched for

# Under the home folder.
HOME_PATHS = [
    ".claude",
    "Library/Logs/Claude",
    "Library/Application Support/Claude",
    ".cursor",
    "Library/Application Support/Cursor/User",
    ".zsh_history",
    ".zhistory",
    ".bash_history",
    ".history",
    ".zsh_sessions",
    ".bash_sessions",
    ".local/share/fish/fish_history",
    ".python_history",
    ".node_repl_history",
    "Library/Saved Application State/com.apple.Terminal.savedState",
    "Library/Saved Application State/com.googlecode.iterm2.savedState",
    "Library/Application Support/iTerm2/SavedState",
    ".tmux/logs",
]
HOME_GLOBS = ["tmux-*.log"]
TEMP_GLOB = "claude*"  # Claude's temp and scratchpad folders, in each temp root


def _rule(pattern: str) -> re.Pattern[bytes]:
    return re.compile(pattern.encode())


# Secret shapes. Each matches a whole token; what it matched is never shown.
PATTERNS: dict[str, re.Pattern[bytes]] = {
    "github-token": _rule(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})"),
    "anthropic-key": _rule(r"\bsk-ant-[a-z]{3,6}\d{2}-[A-Za-z0-9_-]{40,}"),
    "openai-key": _rule(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}"),
    "slack-token": _rule(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    "slack-webhook": _rule(
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"
    ),
    "aws-access-key": _rule(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "google-api-key": _rule(r"\bAIza[0-9A-Za-z_-]{35}"),
    "private-key": _rule(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"),
    "1password-service-account": _rule(r"\bops_eyJ[A-Za-z0-9_-]{40,}"),
    "stripe-key": _rule(r"\b[sr]k_live_[A-Za-z0-9]{20,}"),
}


def configure_scan(p: argparse.ArgumentParser) -> None:
    listing.add_mapping_flag(p)
    p.add_argument(
        "--tmp-root",
        action="append",
        metavar="DIR",
        help="a temp folder holding Claude's folders (default: $TMPDIR, /tmp, /private/tmp)",
    )
    p.add_argument("--path", action="append", metavar="PATH", help="also scan this file or folder")
    p.add_argument("--patterns-only", action="store_true", help="skip 1Password: shapes only")
    p.add_argument("--paths", action="store_true", help="list the places scanned, and stop")


def configure_scrub(p: argparse.ArgumentParser) -> None:
    listing.add_mapping_flag(p)
    p.add_argument("file", help="the file to scrub, as keys scan named it")
    p.add_argument("--patterns-only", action="store_true", help="skip 1Password: shapes only")


@dataclass(frozen=True)
class Needle:
    label: str  # "app-mail (known value)" or "looks like github-token"
    forms: tuple[bytes, ...] = ()
    pattern: re.Pattern[bytes] | None = None

    def found(self, line: bytes) -> bool:
        if self.pattern is not None:
            return self.pattern.search(line) is not None
        return any(f in line for f in self.forms)

    def replace(self, data: bytes) -> tuple[bytes, int]:
        if self.pattern is not None:
            return self.pattern.subn(MARKER, data)
        count = 0
        for f in self.forms:
            count += data.count(f)
            data = data.replace(f, MARKER)
        return data, count


def needles(
    args: argparse.Namespace, ctx: Context, notes: list[str], patterns_only: bool
) -> tuple[list[Needle], bool]:
    """What to search for, and whether every known value could be read."""
    found: list[Needle] = []
    complete = True
    if not patterns_only:
        m = listing.load(args, ctx)
        op = Op(ctx.environ)
        for c in m.credentials:
            try:
                value = op.read(c.value_ref)
            except OpError as e:
                notes.append(
                    f"could not read {c.name} from 1Password ({e}): its value was not searched"
                )
                complete = False
                continue
            found.extend(_known(c, value, notes))
    found.extend(Needle(f"looks like {name}", pattern=p) for name, p in PATTERNS.items())
    return found, complete


def _known(c: mapping.Credential, value: Secret, notes: list[str]) -> list[Needle]:
    if len(value.reveal().strip()) < MIN_LENGTH:
        notes.append(f"{c.name} is too short to search for")
        return []
    return [Needle(f"{c.name} (known value)", forms=tuple(forms.forms(value)))]


def scan_roots(args: argparse.Namespace, ctx: Context) -> list[Path]:
    home = Path(ctx.environ.get("HOME", "~")).expanduser()
    roots = [home / p for p in HOME_PATHS]
    for g in HOME_GLOBS:
        roots.extend(sorted(home.glob(g)))
    tmp_roots: list[str] = args.tmp_root or [
        ctx.environ.get("TMPDIR", ""),
        "/tmp",  # noqa: S108 - read, never written
        "/private/tmp",
    ]
    seen: set[Path] = set()
    for t in tmp_roots:
        if not t:
            continue
        base = Path(t)
        try:
            real = base.resolve()
        except OSError:
            continue
        if real in seen:
            continue
        seen.add(real)
        roots.extend(sorted(base.glob(TEMP_GLOB)))
    extra: list[str] = getattr(args, "path", None) or []
    roots.extend(Path(p).expanduser() for p in extra)
    return roots


def shown(path: Path, home: Path) -> str:
    try:
        return "~/" + str(path.relative_to(home))
    except ValueError:
        return str(path)


def files(roots: list[Path]) -> Iterator[Path]:
    for root in roots:
        if root.is_symlink():
            continue
        if root.is_file():
            yield root
        elif root.is_dir():
            for dirpath, dirnames, names in os.walk(root):
                dirnames.sort()
                for name in sorted(names):
                    p = Path(dirpath, name)
                    if p.is_file() and not p.is_symlink():
                        yield p


def scan(args: argparse.Namespace, ctx: Context) -> int:
    home = Path(ctx.environ.get("HOME", "~")).expanduser()
    roots = scan_roots(args, ctx)
    if args.paths:
        for r in roots:
            ctx.say(shown(r, home) + ("" if r.exists() else " (not there)"))
        return EXIT_OK
    notes: list[str] = []
    found, complete = needles(args, ctx, notes, args.patterns_only)
    count = findings = unreadable = 0
    for path in files(roots):
        count += 1
        try:
            with path.open("rb") as f:
                for number, line in enumerate(f, 1):
                    for n in found:
                        if n.found(line):
                            findings += 1
                            ctx.say(f"{shown(path, home)}:{number}: {n.label}")
        except OSError:
            unreadable += 1
    for note in notes:
        ctx.say(f"note: {note}")
    tail = f", {unreadable} unreadable" if unreadable else ""
    ctx.say(f"keys scan: {count} files, {findings} findings{tail}")
    if findings:
        return EXIT_FAIL
    return EXIT_OK if complete else EXIT_UNKNOWN


def scrub(args: argparse.Namespace, ctx: Context) -> int:
    path = Path(args.file).expanduser()
    if not path.is_absolute():
        path = ctx.cwd() / path
    if not path.is_file() or path.is_symlink():
        raise UsageError("no such file (or not a plain file)")
    notes: list[str] = []
    found, complete = needles(args, ctx, notes, args.patterns_only)
    data = path.read_bytes()
    total = 0
    for n in sorted(found, key=lambda n: -max((len(f) for f in n.forms), default=0)):
        data, k = n.replace(data)
        total += k
    if total:
        # Written next to the file and moved over it: the new content holds no value, and a
        # crash leaves the original, not half a file.
        tmp = path.with_name(f".{path.name}.keys-scrub")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, path.stat().st_mode & 0o777)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)
    for note in notes:
        ctx.say(f"note: {note}")
    ctx.say(f"keys scrub: replaced {total}")
    return EXIT_OK if complete else EXIT_UNKNOWN
