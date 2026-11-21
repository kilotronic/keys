"""keys scan and keys scrub: the transcript and backup check.

scan searches the places an agent's or a shell's words are kept, all of them backed up and
outliving any key: Claude's folders and settings (transcripts, typed-prompt history, file
history, shell snapshots, debug and MCP logs), Claude's temp and scratch folders, the Claude
desktop app's logs and support folder, Cursor's agent folders, shell history, and saved terminal
state. Caches and disk images are skipped.

Two passes over each file, read in overlapping pieces so a long file without newlines costs no
more memory than any other: every credential in the mapping file, read in memory from 1Password
and searched for as sent and in its encoded forms (which catches what no pattern can: random
signing secrets, UUID-shaped tokens); then pattern rules for secret shapes. The encoded forms
include base64 wrapped across lines and any backslash escaping (JSON, JSON inside JSON, shell
history), found by also searching with line breaks or backslashes removed. A finding names the
file, the line and the credential, or the rule, and never the text it matched; a file name that
itself holds a value or a secret shape is withheld.

scrub replaces the same matches in one text file with a marker, in place, and prints only how
many. Nobody opens the file to redact it by hand, which would copy the value into a new
transcript.
"""

from __future__ import annotations

import argparse
import bisect
import os
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from keys import forms, listing
from keys.context import EXIT_FAIL, EXIT_OK, EXIT_UNKNOWN, Context, UsageError
from keys.op import Op, OpError
from keys.secret import Secret

MARKER = b"[removed by keys scrub]"
MIN_LENGTH = 8  # a value shorter than this would match all over; it is not searched for
CHUNK = 1 << 20

# Under the home folder.
HOME_PATHS = [
    ".claude",
    ".claude.json",
    ".claude.json.backup",
    "Library/Caches/claude-cli-nodejs",
    "Library/Logs/Claude",
    "Library/Application Support/Claude",
    ".cursor",
    "Library/Application Support/Cursor/User/workspaceStorage",
    "Library/Application Support/Cursor/User/globalStorage",
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
# Folders that hold caches, disk images or other people's code, not anyone's words.
SKIP_NAMES = {
    "vm_bundles",
    "Cache",
    "Code Cache",
    "GPUCache",
    "DawnCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "node_modules",
}
SKIP_UNDER_HOME = [".cursor/extensions"]


def _rule(pattern: str, flags: int = 0) -> re.Pattern[bytes]:
    return re.compile(pattern.encode(), flags)


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
# What scrub removes for a shape whose match is only its start: the whole block.
SCRUB_PATTERNS: dict[str, re.Pattern[bytes]] = {
    **PATTERNS,
    "private-key": _rule(
        r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----.*?-----END (?:[A-Z]+ )*PRIVATE KEY-----",
        re.DOTALL,
    ),
}
# A whole line of base64, tried once per line start (so linear, even with no newlines at all).
BASE64_LINE = re.compile(rb"^[A-Za-z0-9+/=_-]{4,}\r?$", re.MULTILINE)
BASE64_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")


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


# ---------------------------------------------------------------------------- what to look for


class Searcher:
    """Every known value's forms and every shape, compiled once. Holds values, so its repr
    shows none of them."""

    def __init__(self, known: list[tuple[str, Secret]], patterns: dict[str, re.Pattern[bytes]]):
        self.labels: dict[bytes, str] = {}  # form -> label, searched as sent
        self.wrapped: dict[bytes, str] = {}  # base64 forms, searched with line breaks removed
        self.escaped: dict[bytes, str] = {}  # forms searched with backslashes removed
        for name, value in known:
            label = f"{name} (known value)"
            for v in {value.reveal(), value.reveal().strip()}:
                s = Secret(v)
                for f in forms.forms(s):
                    self.labels.setdefault(f, label)
                for f in forms.base64_forms(s):
                    self.wrapped.setdefault(f, label)
                bare = v.encode().replace(b"\\", b"")
                if len(bare) >= MIN_LENGTH:
                    self.escaped.setdefault(bare, label)
        self.patterns = patterns
        self.longest = max((len(f) for f in [*self.labels, *self.escaped]), default=0) + 256
        self._known = _alternation(self.labels)
        self._wrapped = _alternation(self.wrapped)
        self._escaped = _alternation(self.escaped)

    def __repr__(self) -> str:
        return f"Searcher({len(self.labels)} forms, {len(self.patterns)} patterns)"

    def spans(self, data: bytes) -> Iterator[tuple[int, int, str]]:
        """(start, end, label) of each match in data, as offsets into data."""
        if self._known is not None:
            for m in self._known.finditer(data):
                yield m.start(), m.end(), self.labels[m.group()]
        if self._wrapped is not None:
            # Only blocks of base64 lines can hold wrapped base64; squeeze just those.
            for a, b in _base64_blocks(data):
                squeezed, back = _squeeze(data[a:b], (b"\r", b"\n"))
                for m in self._wrapped.finditer(squeezed):
                    yield a + back(m.start()), a + back(m.end() - 1) + 1, self.wrapped[m.group()]
        if self._escaped is not None and b"\\" in data:
            squeezed, back = _squeeze(data, (b"\\",))
            for m in self._escaped.finditer(squeezed):
                yield back(m.start()), back(m.end() - 1) + 1, self.escaped[m.group()]
        for name, regex in self.patterns.items():
            for m in regex.finditer(data):
                yield m.start(), m.end(), f"looks like {name}"

    def holds(self, text: bytes) -> bool:
        return next(self.spans(text), None) is not None


def _alternation(table: dict[bytes, str]) -> re.Pattern[bytes] | None:
    """One regex for every literal, built as a trie so the engine branches on each byte
    instead of trying every literal at every position (a plain alternation of a few hundred
    literals runs at a few MB/s). Longer literals win where one is a prefix of another."""
    if not table:
        return None
    trie: dict[int, Any] = {}
    for literal in table:
        node = trie
        for b in literal:
            node = node.setdefault(b, {})
        node[-1] = True
    return re.compile(_trie_regex(trie))


def _trie_regex(node: dict[int, Any]) -> bytes:
    ends = -1 in node
    branches = [
        re.escape(bytes([b])) + _trie_regex(child) for b, child in sorted(node.items()) if b != -1
    ]
    if not branches:
        return b""
    body = branches[0] if len(branches) == 1 else b"(?:" + b"|".join(branches) + b")"
    if ends:
        return b"(?:" + body + b")?"
    return body


def _base64_blocks(data: bytes) -> Iterator[tuple[int, int]]:
    """(start, end) of each run of two or more consecutive whole base64 lines."""
    start = end = -1
    lines = 0
    for m in BASE64_LINE.finditer(data):
        if lines and m.start() == end + 1:
            end, lines = m.end(), lines + 1
            continue
        if lines > 1:
            yield start, end
        start, end, lines = m.start(), m.end(), 1
    if lines > 1:
        yield start, end


def _squeeze(data: bytes, drop: tuple[bytes, ...]) -> tuple[bytes, Callable[[int], int]]:
    """data without the bytes in drop, and a map from an offset in it back to one in data."""
    if not any(d in data for d in drop):
        return data, lambda i: i
    removed = sorted(m.start() for d in drop for m in re.finditer(re.escape(d), data))
    adjusted = [pos - k for k, pos in enumerate(removed)]
    out = data
    for d in drop:
        out = out.replace(d, b"")

    def back(i: int) -> int:
        return i + bisect.bisect_right(adjusted, i)

    return out, back


def searcher(
    args: argparse.Namespace,
    ctx: Context,
    notes: list[str],
    patterns: dict[str, re.Pattern[bytes]],
) -> tuple[Searcher, bool]:
    """What to search for, and whether every known value could be read."""
    known: list[tuple[str, Secret]] = []
    complete = True
    if not args.patterns_only:
        m = listing.load(args, ctx)
        op = Op(ctx.environ)
        for c in m.credentials:
            try:
                value = op.read(c.value_ref)
            except OpError as e:
                notes.append(f"could not read {c.name} from 1Password ({e}): not searched for")
                complete = False
                continue
            if len(value.reveal().strip()) < MIN_LENGTH:
                notes.append(f"{c.name} is too short to search for")
                continue
            known.append((c.name, value))
    return Searcher(known, patterns), complete


# ---------------------------------------------------------------------------- where to look


def scan_roots(args: argparse.Namespace, ctx: Context) -> list[Path]:
    home = Path(ctx.environ.get("HOME", "~")).expanduser()
    roots = [home / p for p in HOME_PATHS]
    for g in HOME_GLOBS:
        roots.extend(sorted(home.glob(g)))
    if ctx.environ.get("HISTFILE"):
        roots.append(Path(ctx.environ["HISTFILE"]).expanduser())
    if ctx.environ.get("ZDOTDIR"):
        roots.append(Path(ctx.environ["ZDOTDIR"]).expanduser() / ".zsh_history")
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
    for p in extra:
        path = Path(p).expanduser()
        roots.append(path if path.is_absolute() else ctx.cwd() / path)
    unique: list[Path] = []
    for r in roots:
        if r not in unique:
            unique.append(r)
    return unique


def _clean(part: str) -> str:
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in part)


def shown(path: Path, home: Path, s: Searcher | None = None) -> str:
    """path for printing: under ~/ when it can be, control characters escaped, and any part
    that holds a value or a secret shape withheld."""
    try:
        parts, prefix = path.relative_to(home).parts, "~/"
    except ValueError:
        parts, prefix = path.parts, ""
    out = [
        "<name withheld>" if s is not None and s.holds(os.fsencode(part)) else _clean(part)
        for part in parts
    ]
    text = "/".join(out)
    return prefix + text if prefix else ("/" + text.lstrip("/") if path.is_absolute() else text)


def files(roots: list[Path], home: Path, problems: list[int]) -> Iterator[tuple[Path, Path]]:
    """(path to show, path to read) for each file. A root that is a symlink is followed; links
    inside are not. An unreadable folder adds to problems."""
    skip = {(home / s).resolve() for s in SKIP_UNDER_HOME if (home / s).exists()}

    def refuse(_e: OSError) -> None:
        problems[0] += 1

    for root in roots:
        if not root.exists():
            continue
        real = root.resolve()
        if real.is_file():
            yield root, real
            continue
        for dirpath, dirnames, names in os.walk(real, onerror=refuse):
            here = Path(dirpath)
            dirnames[:] = sorted(
                d
                for d in dirnames
                if d not in SKIP_NAMES and (here / d) not in skip and not (here / d).is_symlink()
            )
            for name in sorted(names):
                p = here / name
                if p.is_file() and not p.is_symlink():
                    yield root / p.relative_to(real), p


def findings_in(path: Path, s: Searcher) -> Iterator[tuple[int, str]]:
    """(line, label) of each finding, read in overlapping pieces; each pair once."""
    seen: set[tuple[int, str]] = set()
    lines_before = 0
    carry = b""
    with path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK)
            data = carry + chunk
            last = not chunk
            cut = len(data) if last else max(0, len(data) - s.longest)
            for start, _end, label in s.spans(data):
                if start >= cut:
                    continue
                key = (lines_before + data.count(b"\n", 0, start) + 1, label)
                if key not in seen:
                    seen.add(key)
                    yield key
            if last:
                return
            lines_before += data.count(b"\n", 0, cut)
            carry = data[cut:]


# ---------------------------------------------------------------------------- commands


def scan(args: argparse.Namespace, ctx: Context) -> int:
    home = Path(ctx.environ.get("HOME", "~")).expanduser()
    roots = scan_roots(args, ctx)
    if args.paths:
        for r in roots:
            ctx.say(shown(r, home) + ("" if r.exists() else " (not there)"))
        return EXIT_OK
    notes: list[str] = []
    s, complete = searcher(args, ctx, notes, PATTERNS)
    count = findings = 0
    problems = [0]
    for show, real in files(roots, home, problems):
        count += 1
        try:
            for number, label in findings_in(real, s):
                findings += 1
                ctx.say(f"{shown(show, home, s)}:{number}: {label}")
        except OSError:
            problems[0] += 1
    for note in notes:
        ctx.say(f"note: {note}")
    tail = f", {problems[0]} unreadable" if problems[0] else ""
    ctx.say(f"keys scan: {count} files, {findings} findings{tail}")
    if findings:
        return EXIT_FAIL
    return EXIT_OK if complete and not problems[0] else EXIT_UNKNOWN


def _widen(data: bytes, start: int, end: int) -> tuple[int, int]:
    """A match inside a base64 run grows to the whole run, so no edge of the value is left."""
    if not all(b in BASE64_CHARS for b in data[start:end]):
        return start, end
    while start > 0 and data[start - 1] in BASE64_CHARS:
        start -= 1
    while end < len(data) and data[end] in BASE64_CHARS:
        end += 1
    return start, end


def scrub(args: argparse.Namespace, ctx: Context) -> int:
    path = Path(args.file).expanduser()
    if not path.is_absolute():
        path = ctx.cwd() / path
    if not path.is_file() or path.is_symlink():
        raise UsageError("no such file (or not a plain file)")
    data = path.read_bytes()
    stamp = path.stat().st_mtime_ns
    if b"\0" in data[:65536]:
        raise UsageError(
            "not a text file: keys will not rewrite it, since that would break it; rotate the "
            "key, and delete the file if nothing needs it"
        )
    notes: list[str] = []
    s, complete = searcher(args, ctx, notes, SCRUB_PATTERNS)
    spans = sorted(_widen(data, a, b) for a, b, _ in s.spans(data))
    merged: list[list[int]] = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    if merged:
        out = bytearray()
        pos = 0
        for a, b in merged:
            out += data[pos:a] + MARKER
            pos = b
        out += data[pos:]
        if path.stat().st_mtime_ns != stamp:
            raise UsageError(
                "the file changed while keys read it; close what writes to it and rerun"
            )
        # The same file, rewritten in place: a copy moved over it would leave a program still
        # writing to the old one with the value in it.
        with path.open("r+b") as f:
            f.write(out)
            f.truncate()
            f.flush()
            os.fsync(f.fileno())
    for note in notes:
        ctx.say(f"note: {note}")
    ctx.say(f"keys scrub: replaced {len(merged)}")
    if merged:
        ctx.say("close any session still writing to it, and rotate the key: backups hold it")
    return EXIT_OK if complete else EXIT_UNKNOWN
