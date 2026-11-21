"""Does this text look like a value? One answer, for every place keys asks.

keys never repeats or writes text that could be a credential pasted into the wrong place: a flag
bound for the mapping file, a field name in a mapping error, a file name in a scan finding, an
error code from a service. Each of those asks here. A text looks like a value when it holds:

- a control or unprintable character (it could also forge a line of output);
- a secret shape (SHAPES: GitHub, Anthropic, OpenAI, Slack, AWS, Google, Stripe, 1Password
  service-account tokens, private keys);
- a UUID (Railway tokens are UUIDs);
- a run of 24 or more characters with no space that mixes letters and digits (random keys look
  like this; words do not). In a link, the host is not held to this, but each piece of its
  path, query and fragment is.

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

UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
LONG = 24  # a run this long with no space, mixing letters and digits, is a key's shape
RUN = re.compile(r"[^\s]+")
LINK_HOST = re.compile(r"https?://[A-Za-z0-9.-]+")
COMMIT = re.compile(r"[0-9a-f]{40}")  # a git commit id: a folder name, never a key
NAME_PART = 16  # a dash-separated part of a credential's name is never longer
CODE = re.compile(r"[A-Za-z0-9_.:-]{1,60}")  # what a machine-readable error code may hold
KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,31}")  # a TOML key keys will name in an error


def unprintable(text: str) -> bool:
    return any(not c.isprintable() or 0xD800 <= ord(c) <= 0xDFFF for c in text)


def _long_mixed(run: str) -> bool:
    return len(run) >= LONG and any(c.isalpha() for c in run) and any(c.isdigit() for c in run)


def _shaped(text: str) -> bool:
    data = text.encode()
    return any(p.search(data) for p in SHAPES.values())


def _pieces(text: str) -> list[str]:
    """The runs the long-run rule looks at: words split on white space, and a link split at
    each / # ? & = after its host (a link's host is a name; each piece of its path, query
    and fragment is held to the same rule as any other run)."""
    out: list[str] = []
    for run in RUN.findall(text):
        host = LINK_HOST.match(run)
        if host:
            out += re.split(r"[/#?&=]", run[host.end() :])
        else:
            out.append(run)
    return out


def looks_like_value(text: str) -> bool:
    """Whether text could be, or hold, a credential's value."""
    if unprintable(text) or _shaped(text) or UUID.search(text):
        return True
    return any(_long_mixed(piece) for piece in _pieces(text))


def name_looks_like_value(name: str) -> bool:
    """A credential's name: also refused when a dash-separated part is longer than a word."""
    return looks_like_value(name) or any(len(part) > NAME_PART for part in name.split("-"))


def file_name_looks_like_value(part: str, *, random_ok: bool = False) -> bool:
    """One part of a file's path, for a scan finding. Paths are made of words, dates, UUIDs and
    commit ids joined by - _ and ., so the long-run rule applies to each piece between those,
    and a UUID or a 40-digit commit id counts as plain. A known value in a name is still caught
    by the scan's own check, which reads the values from 1Password. random_ok skips the
    long-run rule, for a folder the system names at random (macOS's per-user temp folder)."""
    if unprintable(part) or _shaped(part):
        return True
    return not random_ok and any(
        _long_mixed(piece) and not COMMIT.fullmatch(piece) for piece in re.split(r"[-_.]", part)
    )


def plain_code(code: str) -> bool:
    """Whether a service's error code may be shown: short, plain characters, no value shape."""
    return bool(CODE.fullmatch(code)) and not looks_like_value(code)


def plain_key(key: str) -> bool:
    """Whether a field name in the mapping file may be named in an error."""
    return bool(KEY.fullmatch(key)) and not looks_like_value(key)
