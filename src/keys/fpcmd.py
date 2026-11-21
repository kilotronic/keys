"""keys fp and keys leaks: name a value, or a report's leaked values, by keyed fingerprint.

    keys fp <name>              the mapped credential's value, read from 1Password in memory
    keys fp --key <source>      any key (op://, kv://, env:, stdin, gitleaks:)
    keys leaks <report.json>    each distinct value a gitleaks report holds

Only `fp:` and, for a key a provider issued, the hint its console shows are printed.
"""

from __future__ import annotations

import argparse

from keys import checking, leaks, listing
from keys.context import EXIT_FAIL, EXIT_OK, Context, UsageError
from keys.fingerprint import fingerprint, hint
from keys.kinds import KINDS
from keys.op import Op, OpError

FP_USAGE = "keys fp <name> or keys fp --key <source> [--hint]"


def configure_fp(p: argparse.ArgumentParser) -> None:
    p.add_argument("name", nargs="?", help="a credential in the mapping file")
    p.add_argument("--key", metavar="SOURCE", help=f"or any key: {checking.KEY_SOURCES}")
    p.add_argument(
        "--hint",
        action="store_true",
        help="with --key: also the start and end its provider's console shows (only for a key "
        "a provider issued, never one keys generated)",
    )
    p.add_argument("--fp-key", metavar="SOURCE", help="the fingerprint secret ($KEYS_FP_KEY)")
    listing.add_mapping_flag(p)


def configure_leaks(p: argparse.ArgumentParser) -> None:
    p.add_argument("report", help="a gitleaks JSON report made without --redact")
    p.add_argument("--fp-key", metavar="SOURCE", help="the fingerprint secret ($KEYS_FP_KEY)")


def fp(args: argparse.Namespace, ctx: Context) -> int:
    name: str | None = args.name
    source: str | None = args.key
    if (name is None) == (source is None) or (args.hint and source is None):
        raise UsageError(FP_USAGE)
    if source is not None:
        if source == "stdin" and (args.fp_key or ctx.environ.get("KEYS_FP_KEY")) == "stdin":
            raise UsageError("the key and the fingerprint key cannot both come from stdin")
        fp_key = checking.read_fp_key(args.fp_key, ctx)
        key = checking.read_key(source, ctx, fp_key=fp_key)
        shown = hint(key) if args.hint else ""
        ctx.say(f"fp:{fingerprint(fp_key, key)}" + (f" {shown}" if shown else ""))
        return EXIT_OK
    m = listing.load(args, ctx)
    found = [c for c in m.credentials if c.name == name]
    if not found:
        # Not repeated: a value typed in place of a name would be printed back.
        raise UsageError("no credential by that name in the mapping file")
    c = found[0]
    if KINDS[c.kind].runtime:
        raise UsageError(f"{c.name}: a {c.kind} has no 1Password value; keys check --deep reads it")
    fp_key = checking.read_fp_key(args.fp_key, ctx)
    try:
        value = Op(ctx.environ).read(c.value_ref)
    except OpError as e:
        raise UsageError(f"could not read {c.name} from 1Password: {e}") from None
    mine = fingerprint(fp_key, value)
    shown = hint(value) if KINDS[c.kind].provider_issued else ""
    ident = f"fp:{mine}" + (f" {shown}" if shown else "")
    if not c.fp:
        verdict, code = "no fp in the mapping file", EXIT_OK
    elif c.fp == mine:
        verdict, code = "matches the mapping file", EXIT_OK
    else:
        verdict, code = f"differs from the mapping file's fp:{c.fp}", EXIT_FAIL
    ctx.say(f"{c.name} {c.kind} {ident}: {verdict}")
    return code


def report(args: argparse.Namespace, ctx: Context) -> int:
    findings = leaks.load(args.report, ctx)
    fp_key = checking.read_fp_key(args.fp_key, ctx)
    out = leaks.lines(findings, fp_key)
    for line in out:
        ctx.say(line)
    values = "leaked value" if len(out) == 1 else "leaked values"
    found = "finding" if len(findings) == 1 else "findings"
    ctx.say(f"keys leaks: {len(out)} {values} in {len(findings)} {found}")
    return EXIT_FAIL if out else EXIT_OK
