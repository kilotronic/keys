"""keys check --all [--deep]: is every credential where the mapping file says, and current?

--all is the nightly CI check. It never starts 1Password and needs no fingerprint key: it prints
what `keys list` prints, then for each target whether the secret is there (by name, from
metadata only), for GitHub whether it was updated after the credential's rotation date (GitHub
cannot be read back), and for Key Vault and Secret Manager whether the fingerprint tag or label
keys wrote equals the mapping file's. It also names any secret at a mapped scope that no mapping
row names. Railway is skipped: any listing of its variables holds their values.

--deep (on the Mac) adds what needs values, read in process and never shown: each 1Password
value's keyed fingerprint against the mapping file's, each Railway variable's against
1Password's, each tag against the real value, and every 1Password item tagged keys, which must
be in the mapping file and updated within 180 days.

One line per target or finding: the credential, the target and the verdict; then a summary.
Exit 1 on any problem (a scope that cannot be listed is one: a check that cannot look must not
pass), 3 for a usage error.
"""

from __future__ import annotations

import argparse
import datetime

from keys import listing, looks, mapping, targets
from keys.checking import fp_key_variable, read_fp_key
from keys.context import EXIT_FAIL, EXIT_OK, Context, UsageError
from keys.fingerprint import fingerprint
from keys.op import Op, OpError
from keys.secret import Secret

WITHHELD = "<name withheld>"
Listing = dict[str, targets.Present] | targets.TargetError


def _date(text: str) -> datetime.date | None:
    try:
        return datetime.date.fromisoformat(text[:10])
    except ValueError:
        return None


def _shown(name: str) -> str:
    """A name read from a store, for printing: withheld when it is not a plain secret name or
    looks like a value."""
    plain = mapping.SECRET_NAME.fullmatch(name) is not None
    return name if plain and not looks.looks_like_value(name) else WITHHELD


def _scope_text(a: targets.Adapter) -> str:
    return a.describe().rsplit(" ", 1)[0]


class _Report:
    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx
        self.problems = 0

    def ok(self, who: str, where: str, verdict: str) -> None:
        self.ctx.say(f"{who}  {where}  {verdict}")

    def bad(self, who: str, where: str, verdict: str) -> None:
        self.problems += 1
        self.ok(who, where, verdict)


def run(args: argparse.Namespace, ctx: Context) -> int:
    deep: bool = args.deep
    hidden = fp_key_variable(args.fp_key, ctx)
    environ = {k: v for k, v in ctx.environ.items() if k != hidden}
    fp_key = read_fp_key(args.fp_key, ctx) if deep else None  # --all never needs one
    m = listing.load(args, ctx)
    plan = [(c, targets.adapters(c, environ)) for c in m.credentials]  # fields checked first
    today = ctx.today()

    list_code = listing.run(args, ctx)
    report = _Report(ctx)
    report.problems += sum(1 for c in m.credentials if listing.assess(c, today).problems)
    over = m.kept_budget is not None and len(m.credentials) > m.kept_budget
    report.problems += int(over) + int(not m.credentials)
    ctx.say("")

    op = Op(environ)
    cache: dict[tuple[str, ...], Listing] = {}
    mapped: dict[tuple[str, ...], set[str]] = {}
    scopes: dict[tuple[str, ...], targets.Adapter] = {}
    for c, ads in plan:
        real = _deep_value(c, op, fp_key, report) if fp_key is not None else None
        for a in ads:
            mapped.setdefault(a.scope(), set()).add(a.name)
            if isinstance(a, targets.Railway):
                if fp_key is None:
                    ctx.say(f"{c.name}  {a.describe()}  skipped: Railway is checked with --deep")
                else:
                    _railway(c, a, fp_key, real, report)
                continue
            scopes.setdefault(a.scope(), a)
            if a.scope() not in cache:
                try:
                    cache[a.scope()] = a.listing()
                except targets.TargetError as e:
                    cache[a.scope()] = e
            found = cache[a.scope()]
            if isinstance(found, targets.TargetError):
                report.bad(c.name, a.describe(), f"cannot list: {found}")
                continue
            present = found.get(a.name)
            if present is None:
                report.bad(c.name, a.describe(), "not there")
            elif isinstance(a, targets.AzureKeyVault | targets.GcpSecret):
                _tagged(c, a, present, real, report)
            else:
                _updated(c, a, present, report)

    for scope, a in scopes.items():
        found = cache.get(scope)
        if not isinstance(found, dict):
            continue
        for name in sorted(found):
            if name not in mapped.get(scope, set()) and name not in m.ignore_unmapped:
                report.bad("-", _scope_text(a), f"{_shown(name)}: not in the mapping file")

    if fp_key is not None:
        _items(m, op, today, report)

    n = len(m.credentials)
    t = sum(len(ads) for _, ads in plan)
    found_text = (
        "no problems"
        if not report.problems
        else f"{report.problems} problem" + ("" if report.problems == 1 else "s")
    )
    noun = "credential" if n == 1 else "credentials"
    ctx.say(f"keys check --{'deep' if deep else 'all'}: {n} {noun}, {t} targets, {found_text}")
    return EXIT_FAIL if report.problems or list_code != EXIT_OK else EXIT_OK


def _deep_value(c: mapping.Credential, op: Op, fp_key: Secret, report: _Report) -> str | None:
    """The keyed fingerprint of c's 1Password value, compared with the mapping file's."""
    try:
        value = targets.normalise(op.read(c.value_ref), c.name)
    except OpError as e:
        report.bad(c.name, "1Password", f"cannot read: {e}")
        return None
    except UsageError as e:
        report.bad(c.name, "1Password", str(e))
        return None
    if not value.reveal():
        report.bad(c.name, "1Password", "the value is empty")
        return None
    fp = fingerprint(fp_key, value)
    if not c.fp:
        report.ok(c.name, "1Password", f"fp:{fp}; note: the mapping file records no fingerprint")
    elif c.fp != fp:
        report.bad(c.name, "1Password", f"fp:{fp}, but the mapping file records fp:{c.fp}")
    else:
        report.ok(c.name, "1Password", f"fp:{fp} matches the mapping file")
    return fp


def _updated(
    c: mapping.Credential, a: targets.Adapter, present: targets.Present, report: _Report
) -> None:
    """A GitHub secret cannot be read back, so its update date stands for the value."""
    updated = _date(present.updated_at)
    if c.rotated and updated and updated < c.rotated:
        report.bad(
            c.name,
            a.describe(),
            f"updated {updated.isoformat()}, before it was rotated on {c.rotated.isoformat()}",
        )
    else:
        report.ok(c.name, a.describe(), "present")


def _tagged(
    c: mapping.Credential,
    a: targets.Adapter,
    present: targets.Present,
    real: str | None,
    report: _Report,
) -> None:
    word = "tag" if isinstance(a, targets.AzureKeyVault) else "label"
    if not present.fp:
        report.bad(c.name, a.describe(), f"present, no fingerprint {word}")
    elif real is not None and present.fp != real:
        report.bad(
            c.name,
            a.describe(),
            f"fingerprint {word} fp:{present.fp}, 1Password's value is fp:{real}",
        )
    elif c.fp and present.fp != c.fp:
        report.bad(
            c.name,
            a.describe(),
            f"fingerprint {word} fp:{present.fp}, the mapping file records fp:{c.fp}",
        )
    elif not c.fp and real is None:
        report.ok(c.name, a.describe(), "present; no fingerprint in the mapping file to compare")
    else:
        report.ok(c.name, a.describe(), f"present, fingerprint {word} matches")


def _railway(
    c: mapping.Credential,
    a: targets.Railway,
    fp_key: Secret,
    real: str | None,
    report: _Report,
) -> None:
    try:
        value = a.read()
    except targets.TargetError as e:
        report.bad(c.name, a.describe(), f"cannot list: {e}")
        return
    if value is None:
        report.bad(c.name, a.describe(), "not there")
        return
    fp = fingerprint(fp_key, Secret(value.reveal().rstrip("\n")))
    del value
    if real is None:
        report.ok(c.name, a.describe(), f"present (fp:{fp}); 1Password's value not compared")
    elif fp != real:
        report.bad(c.name, a.describe(), f"value differs from 1Password (fp:{fp})")
    else:
        report.ok(c.name, a.describe(), "present, value matches 1Password")


def _items(m: mapping.Mapping, op: Op, today: datetime.date, report: _Report) -> None:
    """Every 1Password item tagged keys: in the mapping file, and updated within 180 days, which
    catches an item rotated by hand."""
    try:
        items = op.items_tagged("keys")
    except OpError as e:
        report.bad("-", "1Password", f"cannot list the items tagged keys: {e}")
        return
    known = {(c.vault.casefold(), c.item_title.casefold()) for c in m.credentials}
    for item in items:
        vault, title = item["vault"], item["title"]
        plain = not (looks.looks_like_value(vault) or looks.looks_like_value(title))
        where = f"1Password {vault}/{title}" if plain else f"1Password {WITHHELD}"
        if (vault.casefold(), title.casefold()) not in known:
            report.bad("-", where, "tagged keys, not in the mapping file")
        updated = _date(item["updated_at"])
        if updated is None:
            report.bad("-", where, "no update date")
        elif (today - updated).days > listing.MAX_DAYS:
            age = (today - updated).days
            report.bad("-", where, f"not updated in {age} days, over {listing.MAX_DAYS}")
