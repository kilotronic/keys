"""keys list: every credential in the mapping file, its fingerprint, expiry and lifetime, and
what is wrong with it. Exit 1 when anything is; this is the nightly check's core.

It reads only the mapping file: no 1Password, no provider. Text fields (owner, kept_because)
are never printed, so a value pasted into one by mistake goes no further.
"""

from __future__ import annotations

import argparse
import datetime
from dataclasses import dataclass, field
from pathlib import Path

from keys import mapping
from keys.context import EXIT_FAIL, EXIT_OK, Context

MAX_DAYS = 180  # no credential lives longer (the design's ceiling)
DUE_DAYS = 120  # the nightly check opens an issue from this age
DUE_LEFT = MAX_DAYS - DUE_DAYS


def configure(p: argparse.ArgumentParser) -> None:
    add_mapping_flag(p)


def add_mapping_flag(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--mapping",
        metavar="PATH",
        help="the mapping file (default: $KEYS_MAPPING, else ./keys.toml)",
    )


def mapping_path(args: argparse.Namespace, ctx: Context) -> Path:
    flag: str | None = args.mapping
    chosen = flag or ctx.environ.get("KEYS_MAPPING") or "keys.toml"
    path = Path(chosen).expanduser()
    return path if path.is_absolute() else ctx.cwd() / path


@dataclass
class Row:
    credential: mapping.Credential
    days_left: int | None = None
    lifetime: int | None = None
    problems: list[str] = field(default_factory=lambda: list[str]())
    warnings: list[str] = field(default_factory=lambda: list[str]())


def assess(c: mapping.Credential, today: datetime.date) -> Row:
    row = Row(c)
    age = (today - c.rotated).days if c.rotated else None
    if c.expires is None:
        row.problems.append("no expiry")
    else:
        row.days_left = (c.expires - today).days
        if c.rotated:
            row.lifetime = (c.expires - c.rotated).days
        if row.days_left < 0:
            row.problems.append(f"expired {-row.days_left} days ago")
        if row.lifetime is not None and row.lifetime > MAX_DAYS:
            row.problems.append(f"lifetime {row.lifetime} days, over {MAX_DAYS}")
        elif row.days_left > MAX_DAYS:
            row.problems.append(f"expires in {row.days_left} days, over {MAX_DAYS}")
    if age is not None and age > MAX_DAYS:
        row.problems.append(f"rotated {age} days ago, over {MAX_DAYS}")
    if not c.kept_because.strip():
        row.problems.append("no kept_because")
    if not row.problems:
        if age is not None and age >= DUE_DAYS:
            row.warnings.append(f"due: rotated {age} days ago")
        elif row.days_left is not None and row.days_left <= DUE_LEFT:
            row.warnings.append(f"due: expires in {row.days_left} days")
    return row


def _cell(value: object) -> str:
    return "-" if value is None or value == "" else str(value)


def run(args: argparse.Namespace, ctx: Context) -> int:
    m = mapping.load(mapping_path(args, ctx))
    today = ctx.today()
    rows = [assess(c, today) for c in m.credentials]
    table = [["NAME", "KIND", "FP", "EXPIRES", "LEFT", "LIFETIME", "NOTES"]]
    for r in rows:
        c = r.credential
        table.append(
            [
                c.name,
                c.kind,
                f"fp:{c.fp}" if c.fp else "-",
                _cell(c.expires.isoformat() if c.expires else None),
                _cell(r.days_left),
                _cell(r.lifetime),
                "; ".join(r.problems + r.warnings),
            ]
        )
    widths = [max(len(row[i]) for row in table) for i in range(len(table[0]) - 1)]
    for line in table:
        cells = [cell.ljust(w) for cell, w in zip(line, widths, strict=False)] + [line[-1]]
        ctx.say("  ".join(cells).rstrip())

    kept = len(rows)
    failing = sum(1 for r in rows if r.problems)
    noun = "credential" if kept == 1 else "credentials"
    summary = f"{kept} {noun} kept"
    over_budget = m.kept_budget is not None and kept > m.kept_budget
    if over_budget:
        summary += f", over the budget of {m.kept_budget}"
    elif m.kept_budget is not None:
        summary += f" (budget {m.kept_budget})"
    summary += f", {failing} with problems" if failing else ", no problems"
    ctx.say("")
    ctx.say(summary)
    return EXIT_FAIL if failing or over_budget else EXIT_OK
