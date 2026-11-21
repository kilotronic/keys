"""Does this text look like a value? One answer, for every place keys asks.

keys never repeats or writes text that could be a credential pasted into the wrong place: a flag
bound for the mapping file, a field name in a mapping error, a file name in a scan finding, an
error code from a service. Each of those asks here. A text looks like a value when it holds:

- a control or unprintable character (it could also forge a line of output);
- a secret shape (SHAPES: GitHub, Anthropic, OpenAI, Slack, AWS, Google, Stripe, 1Password
  service-account tokens, private keys);
- a UUID (Railway tokens are UUIDs);
- a run of 24 or more characters with no space that mixes letters and digits, outside a plain
  link (random keys look like this; words and links do not).

The callers add what only they know: a near miss of a real field name, a dash-separated part
longer than a name's, the known values a scan reads from 1Password.
"""

from __future__ import annotations

import re


def _rule(pattern: str, flags: int = 0) -> re.Pattern[bytes]:
    return re.compile(pattern.encode(), flags)


# Secret shapes. Each matches a whole token; what it matched is never shown.
SHAPES: dict[str, re.Pattern[bytes]] = {
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

UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
CANONICAL_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
LONG_RUN = re.compile(r"[^\s]{24,}")
URL = re.compile(r"https?://[A-Za-z0-9.-]+(?:/[A-Za-z0-9._~%/-]*)?(?:#[A-Za-z0-9_-]*)?")
NAME_PART = 16  # a dash-separated part of a credential's name is never longer
CODE = re.compile(r"[A-Za-z0-9_.:-]{1,60}")  # what a machine-readable error code may hold
KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,31}")  # a TOML key keys will name in an error


def unprintable(text: str) -> bool:
    return any(not c.isprintable() or 0xD800 <= ord(c) <= 0xDFFF for c in text)


def _mixed(run: str) -> bool:
    return any(c.isalpha() for c in run) and any(c.isdigit() for c in run)


def _shaped(text: str) -> bool:
    data = text.encode()
    return any(p.search(data) for p in SHAPES.values())


def looks_like_value(text: str) -> bool:
    """Whether text could be, or hold, a credential's value."""
    if unprintable(text):
        return True
    if _shaped(text) or UUID.search(text):
        return True
    return any(_mixed(run) for run in LONG_RUN.findall(URL.sub(" ", text)))


def name_looks_like_value(name: str) -> bool:
    """A credential's name: also refused when a dash-separated part is longer than a word."""
    return looks_like_value(name) or any(len(part) > NAME_PART for part in name.split("-"))


def file_name_looks_like_value(part: str) -> bool:
    """One part of a file's path, for a scan finding. The long-run rule applies to each piece
    between - _ and . (a path's pieces are words, dates and short ids). A canonical lower-case
    UUID, alone or before an extension, is how Claude names its sessions and file history, and
    is named, as it always was; a known value in it is still caught by the scan's own check."""
    if unprintable(part) or _shaped(part):
        return True
    stem = part.split(".", 1)[0]
    rest = part[len(stem) :]
    if CANONICAL_UUID.fullmatch(stem) and not looks_like_value(rest):
        return False
    if UUID.search(part):
        return True
    return any(len(piece) >= 24 and _mixed(piece) for piece in re.split(r"[-_.]", part))


def plain_code(code: str) -> bool:
    """Whether a service's error code may be shown: short, plain characters, no value shape."""
    return bool(CODE.fullmatch(code)) and not looks_like_value(code)


def plain_key(key: str) -> bool:
    """Whether a field name in the mapping file may be named in an error."""
    return bool(KEY.fullmatch(key)) and not looks_like_value(key)
