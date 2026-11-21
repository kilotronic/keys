"""keys sync <name> | --all: 1Password's value to every target in the mapping file.

The value is read from 1Password in process and handed to each target's CLI on its stdin, never
its argv. Railway variables are staged without a deploy, then each Railway service is redeployed
once and waited for. One line per target: the credential, the target, the value's keyed
fingerprint and what happened. The first failure stops the sync and says how many targets were
written before it.

A value whose fingerprint differs from the one the mapping file records is refused without
--force: 1Password was changed outside keys rotate, and writing it could replace a good value at
every target. --dry-run reads no value: it names each target and whether it can be reached.
"""

from __future__ import annotations

import argparse

from keys import listing, mapping, targets
from keys.checking import read_fp_key
from keys.context import EXIT_FAIL, EXIT_OK, Context, UsageError
from keys.fingerprint import fingerprint
from keys.op import Op, OpError
from keys.secret import Secret


def configure(p: argparse.ArgumentParser) -> None:
    p.add_argument("name", nargs="?", help="the credential to sync")
    p.add_argument("--all", action="store_true", help="every credential in the mapping file")
    p.add_argument(
        "--dry-run", action="store_true", help="name each target and check it can be reached"
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="write even when the value differs from the fingerprint the mapping file records",
    )
    p.add_argument("--no-deploy", action="store_true", help="stage Railway variables only")
    p.add_argument(
        "--fp-key",
        metavar="SOURCE",
        help="where the fingerprint secret comes from (default: $KEYS_FP_KEY)",
    )
    listing.add_mapping_flag(p)


def chosen(args: argparse.Namespace, m: mapping.Mapping) -> list[mapping.Credential]:
    name: str | None = args.name
    if bool(name) == bool(args.all):
        raise UsageError("give a credential's name or --all")
    if args.all:
        return m.credentials
    found = [c for c in m.credentials if c.name == name]
    if not found:
        # Not echoed: a value typed in place of the name would be printed back.
        raise UsageError("no credential by that name in the mapping file")
    return found


def _plural(n: int) -> str:
    return f"{n} target was" if n == 1 else f"{n} targets were"


def run(args: argparse.Namespace, ctx: Context) -> int:
    m = listing.load(args, ctx)
    creds = chosen(args, m)
    plan = [(c, targets.adapters(c, ctx.environ)) for c in creds]  # every field checked first
    if args.dry_run:
        return _dry_run(plan, ctx)

    fp_key = read_fp_key(args.fp_key, ctx)
    op = Op(ctx.environ)
    values: list[tuple[mapping.Credential, list[targets.Adapter], Secret, str]] = []
    for c, ads in plan:
        if not ads:
            ctx.say(f"{c.name}: no targets")
            continue
        try:
            value = op.read(c.value_ref)
        except OpError as e:
            raise UsageError(f"could not read {c.name} from 1Password: {e}") from None
        if not value.reveal().strip():
            raise UsageError(f"{c.name}: its 1Password value is empty; paste it there first")
        values.append((c, ads, value, fingerprint(fp_key, value)))

    differs = [(c, fp) for c, _, _, fp in values if c.fp and c.fp != fp]
    for c, fp in differs:
        line = f"{c.name}: 1Password's value is fp:{fp}, but the mapping file records fp:{c.fp}"
        if not args.force:
            ctx.warn(f"keys: {line}; nothing was written. Rerun with --force to write it anyway")
        else:
            ctx.say(f"note: {line}; written anyway (--force): record it or fix the mapping file")
    if differs and not args.force:
        return EXIT_FAIL

    written = 0
    railway: dict[tuple[str, ...], targets.Railway] = {}
    for c, ads, value, fp in values:
        for a in ads:
            try:
                a.write(value, fp)
            except targets.TargetError as e:
                ctx.warn(
                    f"keys: {c.name}: stopped at {a.describe()}: {e}; "
                    f"{_plural(written)} written before it"
                )
                return EXIT_FAIL
            written += 1
            ctx.say(f"{c.name}  {a.describe()}  fp:{fp}  written")
            if isinstance(a, targets.Railway):
                railway.setdefault(a.scope(), a)

    for r in railway.values():
        if args.no_deploy:
            ctx.say(f"{r.service_label()}: staged, not redeployed (--no-deploy)")
            continue
        try:
            r.redeploy(ctx.sleep)
        except targets.TargetError as e:
            ctx.warn(f"keys: {e}; its variables are staged, and the old deployment still runs")
            return EXIT_FAIL
        ctx.say(f"{r.service_label()}: deployed")
    noun = "target" if written == 1 else "targets"
    creds = "credential" if len(values) == 1 else "credentials"
    ctx.say(f"keys sync: {written} {noun} written for {len(values)} {creds}")
    return EXIT_OK


def _dry_run(plan: list[tuple[mapping.Credential, list[targets.Adapter]]], ctx: Context) -> int:
    seen: dict[tuple[str, ...], dict[str, targets.Present] | targets.TargetError] = {}
    failed = 0
    for c, ads in plan:
        if not ads:
            ctx.say(f"{c.name}: no targets")
        fp = f"fp:{c.fp}" if c.fp else "-"
        for a in ads:
            if a.scope() not in seen:
                try:
                    seen[a.scope()] = a.listing()
                except targets.TargetError as e:
                    seen[a.scope()] = e
            found = seen[a.scope()]
            if isinstance(found, targets.TargetError):
                failed += 1
                ctx.say(f"{c.name}  {a.describe()}  {fp}  cannot reach: {found}")
                continue
            there = "present" if a.name in found else "not there yet"
            ctx.say(f"{c.name}  {a.describe()}  {fp}  would write ({there})")
    ctx.say("keys sync --dry-run: nothing was read from 1Password or written")
    return EXIT_FAIL if failed else EXIT_OK
