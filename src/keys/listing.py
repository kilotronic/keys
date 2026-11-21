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
from keys.kinds import KINDS

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


def mapping_path(args: argparse.Namespace, ctx: Context) -> tuple[Path, str]:
    """The mapping file, and what errors call it. A path the owner typed or set is never
    printed: it could be a value pasted into the wrong place."""
    flag: str | None = args.mapping
    env = ctx.environ.get("KEYS_MAPPING")
    if flag:
        chosen, shown = flag, "the mapping file named by --mapping"
    elif env:
        chosen, shown = env, "the mapping file named by $KEYS_MAPPING"
    else:
        chosen, shown = "keys.toml", "./keys.toml"
    path = Path(chosen).expanduser()
    return (path if path.is_absolute() else ctx.cwd() / path), shown


def load(args: argparse.Namespace, ctx: Context) -> mapping.Mapping:
    path, shown = mapping_path(args, ctx)
    return mapping.load(path, shown)


@dataclass
class Row:
    credential: mapping.Credential
    days_left: int | None = None
    lifetime: int | None = None
    expires: datetime.date | None = None
    from_rotation: bool = False
    problems: list[str] = field(default_factory=lambda: list[str]())
    warnings: list[str] = field(default_factory=lambda: list[str]())


def assess(c: mapping.Credential, today: datetime.date) -> Row:
    """What is wrong with c today. On its expiry day a credential counts as expired."""
    row = Row(c)
    age = (today - c.rotated).days if c.rotated else None
    expires = c.expires
    if expires is None and c.rotated and not KINDS[c.kind].can_expire:
        expires = c.rotated + datetime.timedelta(days=MAX_DAYS)
        row.expires, row.from_rotation = expires, True
        row.warnings.append("expiry from rotation")
    else:
        row.expires = expires
    if expires is None:
        row.problems.append("no expiry" if KINDS[c.kind].can_expire else "no rotation date")
    else:
        row.days_left = (expires - today).days
        if c.rotated:
            row.lifetime = (expires - c.rotated).days
        if row.days_left < 0:
            row.problems.append(f"expired {-row.days_left} days ago")
        elif row.days_left == 0:
            row.problems.append("expires today")
        if row.lifetime is not None and row.lifetime < 0:
            row.problems.append("rotated after it expired")
        elif row.lifetime is not None and row.lifetime > MAX_DAYS:
            row.problems.append(f"lifetime {row.lifetime} days, over {MAX_DAYS}")
        elif row.days_left > MAX_DAYS:
            row.problems.append(f"expires in {row.days_left} days, over {MAX_DAYS}")
    if age is not None and age < 0:
        row.problems.append("rotated date is in the future")
    elif age is not None and age > MAX_DAYS:
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
    return EXIT_FAIL if report(load(args, ctx), ctx) else EXIT_OK


def report(m: mapping.Mapping, ctx: Context) -> int:
    """Print the table and its summary; return how many problems it found (a credential with
    problems counts once, as do going over the budget and an empty file)."""
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
                _cell(r.expires.isoformat() if r.expires else None),
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
    if not rows:
        summary = "no credentials in the mapping file: an empty or cut-short file is a problem"
    ctx.say("")
    ctx.say(summary)
    return failing + int(over_budget) + int(not rows)
