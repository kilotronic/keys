"""A gitleaks report, read without showing what it found.

A report made without --redact holds each leaked value (its Secret, Match and Line fields).
keys reads it in memory for two things: `keys leaks`, one line per distinct leaked value named by
its keyed fingerprint, and the `gitleaks:<report.json>#<fingerprint>` key source, which hands
one leaked value to `keys check` so a leaked key can be proved dead without anyone handling it.
Only the fingerprint, the rule, file names, counts, a commit id and dates are printed; any of
those that looks like a value, or holds a piece of a leaked one, is withheld.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from keys import forms, looks
from keys.context import Context, UsageError
from keys.fingerprint import fingerprint
from keys.secret import Secret

REDACTED = "REDACTED"  # what gitleaks --redact puts in place of each value
FP_PREFIX = re.compile(r"[0-9a-f]{1,8}")
RULE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
COMMIT = re.compile(r"[0-9a-f]{7,40}")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
WITHHELD = "<name withheld>"
NOT_A_REPORT = "that is not a gitleaks JSON report (a list of findings, each with its Secret)"


@dataclass(frozen=True)
class Finding:
    rule: str
    secret: Secret  # as gitleaks found it, a trailing line break dropped
    file: str
    commit: str
    date: str


def load(path_text: str, ctx: Context) -> list[Finding]:
    """The findings in a report. Errors never name the path, which could be a value typed in
    the wrong place, nor anything the file holds."""
    path = Path(path_text).expanduser()
    path = path if path.is_absolute() else ctx.cwd() / path
    try:
        doc: object = json.loads(path.read_bytes())
    except OSError as e:
        raise UsageError(f"cannot read the gitleaks report ({type(e).__name__})") from None
    except ValueError:
        raise UsageError(NOT_A_REPORT) from None
    if not isinstance(doc, list):
        raise UsageError(NOT_A_REPORT)
    out: list[Finding] = []
    for raw in cast(list[object], doc):
        if not isinstance(raw, dict):
            raise UsageError(NOT_A_REPORT)
        row = cast(dict[str, Any], raw)
        secret = row.get("Secret")
        match = row.get("Match", "")
        if not isinstance(secret, str) or not isinstance(match, str):
            raise UsageError(NOT_A_REPORT)
        if secret == REDACTED or secret.endswith("...") or (match and secret not in match):
            # --redact puts REDACTED in place of each value, --redact=N keeps a start and
            # adds "...": fingerprints of either would name nothing, and a check would say DEAD.
            raise UsageError(
                "that report was made with --redact, so it holds no values to fingerprint; "
                "run gitleaks again without it, and delete the report after"
            )
        secret = secret.rstrip("\r\n")  # one fingerprint, whichever command reads it
        if not secret:
            continue
        out.append(
            Finding(
                _text(row.get("RuleID")),
                Secret(secret),
                _text(row.get("File")),
                _text(row.get("Commit")),
                _text(row.get("Date")),
            )
        )
    return out


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def from_report(spec: str, fp_key: Secret, ctx: Context) -> Secret:
    """The one leaked value in report whose keyed fingerprint starts with the given digits."""
    report, _, prefix = spec.rpartition("#")
    prefix = prefix.lower()
    if not report or not FP_PREFIX.fullmatch(prefix):
        raise UsageError(
            "gitleaks: takes gitleaks:<report.json>#<fingerprint>: the fp: digits keys leaks "
            "prints, not gitleaks's own Fingerprint field"
        )
    values = {
        f.secret
        for f in load(report, ctx)
        if fingerprint(fp_key, f.secret).startswith(prefix) and f.secret
    }
    if not values:
        raise UsageError("no leaked value has that fingerprint in that report")
    if len(values) > 1:
        raise UsageError(f"{len(values)} leaked values have that fingerprint; give more digits")
    return values.pop()


def _holds(text: str, secrets: list[Secret]) -> bool:
    return any(forms.holds_piece(text, s) for s in secrets)


def _plain_file(name: str, secrets: list[Secret]) -> str:
    """name, or <name withheld> for the whole of it when it holds a leaked value (one with a
    / in it spans folders), else for each part that holds one or looks like a value."""
    if _holds(name, secrets) or looks.unprintable(name):
        return WITHHELD
    parts = [
        WITHHELD if looks.file_name_looks_like_value(part) or _holds(part, secrets) else part
        for part in name.split("/")
    ]
    return "/".join(parts) or "-"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def lines(findings: list[Finding], fp_key: Secret) -> list[str]:
    """One line per distinct leaked value, earliest first."""
    secrets = list(dict.fromkeys(f.secret for f in findings))
    groups: dict[Secret, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.secret, []).append(f)

    def first_date(fs: list[Finding]) -> str:
        return min((f.date[:10] for f in fs if DATE.fullmatch(f.date[:10])), default="9999")

    out: list[str] = []
    for secret, fs in sorted(groups.items(), key=lambda kv: first_date(kv[1])):
        rules = sorted({f.rule for f in fs})
        rule = ",".join(
            r
            if RULE.fullmatch(r) and not looks.looks_like_value(r) and not _holds(r, secrets)
            else "<rule withheld>"
            for r in rules
        )
        files = sorted({f.file for f in fs})
        more = f" (+{len(files) - 1} more)" if len(files) > 1 else ""
        dates = sorted(f.date[:10] for f in fs if DATE.fullmatch(f.date[:10]))
        commits = {f.commit for f in fs if f.commit}
        earliest = min(fs, key=lambda f: f.date[:10] if DATE.fullmatch(f.date[:10]) else "9999")
        plain = COMMIT.fullmatch(earliest.commit) and not _holds(earliest.commit, secrets)
        commit = earliest.commit[:8] if plain else "-"
        span = f"{dates[0]}..{dates[-1]}" if dates else "-"
        if not commits and not dates:
            where = ", not in git"  # gitleaks dir or --no-git: no commit, no date
        else:
            where = f" in {_plural(len(commits), 'commit')}, first {commit}, {span}"
        out.append(
            f"fp:{fingerprint(fp_key, secret)}  {rule}  {_plain_file(files[0], secrets)}{more}  "
            f"{_plural(len(fs), 'finding')}{where}"
        )
    return out
