"""keys rotate for secrets the app owns, kept only at their targets: no 1Password item.

    generated          a random value (a signing key, a job's key, a datastore password with
                       no database step): made here, staged at each Railway target, each
                       service redeployed once and read back, then each GitHub target set
    postgres-password  the same, but the database learns the new password first: an ALTER
                       over the old URL (a SCRAM verifier, so the server never sees the
                       password), then the new URL must connect, before anything restarts

Several names rotate together (`keys rotate jwt-secret secret-key`): every value is staged
first, then each service is redeployed once, in the order the credentials' `redeploy` lists.

A signing key can keep the old value working for a while: `--keep-previous` stages the current
value in the target's `previous` variable before the new one, and `--end-overlap` deletes that
variable and redeploys. Taken from the old Railway rotation script, with generic names.

Values move only on stdin (Railway, GitHub) or in psql's PGPASSWORD; only fingerprints print.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import hmac
import os
import re
import secrets
import urllib.parse

from keys import listing, mapping, proc, rotators, targets
from keys.checking import fp_key_variable, read_fp_key
from keys.context import EXIT_FAIL, EXIT_OK, Context, UsageError
from keys.fingerprint import fingerprint
from keys.secret import Secret

OVERLAP_DAYS = 30
PG_USER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")
ALTER_SQL = "ALTER USER \"{user}\" WITH PASSWORD :'verifier';\n"


class RuntimeStop(Exception):
    """A step failed; the message says what is left and what to run, never a value."""


def make_value(form: str) -> Secret:
    """A new value: hex or URL-safe base64 of this many random bytes (`hex32`)."""
    kind, size = re.fullmatch(r"(hex|urlsafe)(\d+)", form).groups()  # type: ignore[union-attr]
    n = int(size)
    return Secret(secrets.token_hex(n) if kind == "hex" else secrets.token_urlsafe(n))


def scram_verifier(password: Secret, salt: bytes | None = None, iterations: int = 4096) -> str:
    """What psql's \\password sends: the server stores this and never sees the password."""
    salt = salt or os.urandom(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.reveal().encode(), salt, iterations)
    stored = hashlib.sha256(hmac.new(salted, b"Client Key", "sha256").digest()).digest()
    server = hmac.new(salted, b"Server Key", "sha256").digest()

    def b64(b: bytes) -> str:
        return base64.b64encode(b).decode()

    return f"SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored)}:{b64(server)}"


def psql_target(url: Secret) -> tuple[str, str, Secret]:
    """(the URL without its password, the user, the password) from a database URL."""
    u = urllib.parse.urlsplit(url.reveal())
    userinfo, at, host = u.netloc.rpartition("@")
    user = urllib.parse.unquote(userinfo.split(":", 1)[0]) if at else ""
    netloc = f"{userinfo.split(':', 1)[0]}@{host}" if at else host
    bare = urllib.parse.urlunsplit(u._replace(netloc=netloc))
    return bare, user, Secret(urllib.parse.unquote(u.password or ""))


def stored_form(t: mapping.Target, value: Secret) -> Secret:
    """What a target holds: the value, or with `store = "sha256"` its hex digest."""
    if t.store == "sha256":
        return Secret(hashlib.sha256(value.reveal().encode()).hexdigest())
    return value


class Runtime:
    def __init__(
        self,
        args: argparse.Namespace,
        ctx: Context,
        creds: list[mapping.Credential],
        environ: dict[str, str],
    ) -> None:
        self.args, self.ctx, self.creds, self.environ = args, ctx, creds, environ
        self.today = ctx.today()
        self.fp_key = Secret("")
        self.ads = {c.name: targets.adapters(c, environ) for c in creds}
        for c in creds:
            for i, a in enumerate(self.ads[c.name]):
                if a.target.field:
                    raise UsageError(f"{c.name}.target[{i}].field: a {c.kind} has no item")
                if c.kind == "postgres-password" and not isinstance(a, targets.Railway):
                    raise UsageError(f"{c.name}.target[{i}]: a postgres-password goes to Railway")
            if c.kind == "postgres-password" and not any(
                isinstance(a, targets.Railway) for a in self.ads[c.name]
            ):
                raise UsageError(f"{c.name}: a postgres-password needs its Railway target")

    def say(self, line: str) -> None:
        self.ctx.say(line)

    def fp(self, value: Secret) -> str:
        return fingerprint(self.fp_key, value)

    def railway(self, c: mapping.Credential) -> list[targets.Railway]:
        return [a for a in self.ads[c.name] if isinstance(a, targets.Railway)]

    def sibling(self, a: targets.Railway, variable: str) -> targets.Railway:
        """Another variable in the same Railway service and environment."""
        fields = {**a.target.fields, "variable": variable}
        t = mapping.Target("railway", fields, {})
        return targets.Railway(t, self.environ, a.where)

    # ------------------------------------------------------------------ preflight

    def preflight(self) -> None:
        """Every target reachable, and each GitHub Environment admitting main only."""
        check = rotators.Rotator("generated", "")
        for c in self.creds:
            from keys.rotating import Rotation  # the same checks as every rotation

            r = Rotation(self.args, self.ctx, c, check, None, self.ads[c.name], self.environ)
            problems = r.preflight_targets()
            if problems:
                raise RuntimeStop(f"{c.name}: {'; '.join(problems)}; nothing was changed")

    # ------------------------------------------------------------------ the run

    def go(self) -> int:
        self.fp_key = read_fp_key(self.args.fp_key, self.ctx)
        self.preflight()
        if self.args.end_overlap:
            return self.end_overlap()
        keep = bool(self.args.keep_previous)
        if keep:
            self.check_overlap()
        new: dict[str, Secret] = {}
        staged: list[str] = []
        try:
            for c in self.creds:
                value = make_value(
                    c.generate or ("hex24" if c.kind == "postgres-password" else "hex32")
                )
                new[c.name] = value
                if c.kind == "postgres-password":
                    self.alter(c, value)
                self.stage(c, value, keep)
                staged.append(c.name)
            self.redeploy()
            for c in self.creds:
                self.read_back(c, new[c.name])
            for c in self.creds:
                self.github(c, new[c.name])
        except (RuntimeStop, targets.TargetError) as e:
            raise RuntimeStop(f"{e}; {self.hint(staged, keep)}") from None
        for c in self.creds:
            self.record(c, new[c.name])
        if keep:
            ends = self.today + datetime.timedelta(days=OVERLAP_DAYS)
            names = " ".join(c.name for c in self.creds)
            self.say(
                f"the old value still verifies until you end the overlap on {ends.isoformat()}: "
                f"keys rotate {names} --end-overlap"
            )
        self.say(
            f"keys rotate: {', '.join(c.name for c in self.creds)} rotated; commit the mapping file"
        )
        return EXIT_OK

    def hint(self, staged: list[str], keep: bool) -> str:
        names = " ".join(c.name for c in self.creds)
        if not staged:
            return "nothing was staged: fix the cause and rerun"
        if keep:
            return (
                "the new values may be staged and live, with the old ones kept; do not rerun "
                "(it would refuse): redeploy by hand, then end the overlap in "
                f"{OVERLAP_DAYS} days with keys rotate {names} --end-overlap"
            )
        return (
            f"new values for {', '.join(staged)} may be staged, and may be live: rerun keys "
            f"rotate {names} now, which makes and stages fresh ones"
        )

    # ------------------------------------------------------------------ overlap

    def check_overlap(self) -> None:
        """--keep-previous: each Railway target with `previous` holds a current value, and no
        overlap is running (the previous variable unset, or equal to the current value, left
        by a run that stopped before staging the new one)."""
        for c in self.creds:
            for a in self.railway(c):
                if not a.target.previous:
                    continue
                current = a.read()
                if current is None or not current.reveal():
                    raise RuntimeStop(
                        f"{c.name}: {a.describe()} is not set, so there is no old value to keep; "
                        "nothing was changed"
                    )
                held = self.sibling(a, a.target.previous).read()
                if held is not None and held.reveal() and held != current:
                    raise RuntimeStop(
                        f"{c.name}: {a.target.previous} is set and differs: an overlap is still "
                        f"running; end it first with keys rotate {c.name} --end-overlap; nothing "
                        "was changed"
                    )

    def end_overlap(self) -> int:
        """Delete each `previous` variable that is set, then redeploy each service once, either
        way: a run whose redeploy failed after the delete left the app on the old value."""
        found = False
        for c in self.creds:
            for a in self.railway(c):
                if not a.target.previous:
                    continue
                found = True
                old = self.sibling(a, a.target.previous)
                try:
                    there = old.read()
                    if there is not None:
                        old.delete()
                        self.say(f"{c.name}: {a.target.previous} deleted ({a.service_label()})")
                    else:
                        self.say(f"{c.name}: {a.target.previous} is not set: no overlap to end")
                except targets.TargetError as e:
                    raise RuntimeStop(f"{e}; the old value may still verify: rerun now") from None
        if not found:
            raise UsageError("no target of these keeps a previous value (previous = ...)")
        try:
            self.redeploy()
        except targets.TargetError as e:
            raise RuntimeStop(f"{e}; the old value may still verify: rerun now") from None
        return EXIT_OK

    # ------------------------------------------------------------------ the steps

    def stage(self, c: mapping.Credential, value: Secret, keep: bool) -> None:
        """Each Railway target, staged without a deploy; with keep, the current value goes to
        `previous` first; without, a `previous` left from an overlap is deleted."""
        for a in self.railway(c):
            if keep and a.target.previous:
                current = a.read()
                if current is not None:
                    self.sibling(a, a.target.previous).write(current, "")
                    self.say(f"{c.name}: {a.target.previous} staged (the old value)")
            shown = stored_form(a.target, value)
            a.write(shown, "")
            self.say(f"{c.name}: {a.describe()} staged fp:{self.fp(shown)}")
            if not keep and a.target.previous:
                old = self.sibling(a, a.target.previous)
                if old.read() is not None:
                    old.delete()
                    self.say(f"{c.name}: {a.target.previous} deleted")

    def services(self) -> list[targets.Railway]:
        """Each Railway service once: the credentials' `redeploy` order first, then the rest
        in target order."""
        by_name: dict[tuple[str, ...], targets.Railway] = {}
        for c in self.creds:
            for a in self.railway(c):
                by_name.setdefault(a.scope(), a)
        order: list[targets.Railway] = []
        for c in self.creds:
            base = next(iter(self.railway(c)), None)
            for service in c.redeploy:
                if base is None:
                    raise UsageError(f"{c.name}.redeploy: it has no Railway target to name them by")
                fields = {**base.target.fields, "service": service}
                a = targets.Railway(mapping.Target("railway", fields, {}), self.environ, base.where)
                if a.scope() not in {o.scope() for o in order}:
                    order.append(a)
        for a in by_name.values():
            if a.scope() not in {o.scope() for o in order}:
                order.append(a)
        return order

    def redeploy(self) -> None:
        for a in self.services():
            self.say(f"{a.service_label()}: redeploying")
            a.redeploy(self.ctx.sleep)
            self.say(f"{a.service_label()}: deployed")

    def read_back(self, c: mapping.Credential, value: Secret) -> None:
        for a in self.railway(c):
            got = a.read()
            want = self.fp(stored_form(a.target, value))
            fp = self.fp(Secret(got.reveal().rstrip("\n"))) if got is not None else ""
            del got
            if fp != want:
                raise RuntimeStop(f"{c.name}: {a.describe()} does not read back as the new value")
            self.say(f"{c.name}: {a.describe()} reads back fp:{want}")

    def github(self, c: mapping.Credential, value: Secret) -> None:
        """GitHub targets last: the app already runs the new value, so a failure here strands
        a job that uses it, never a sign-in."""
        for a in self.ads[c.name]:
            if isinstance(a, targets.Railway):
                continue
            shown = stored_form(a.target, value)
            a.write(shown, self.fp(shown))
            self.say(f"{c.name}: {a.describe()} set fp:{self.fp(shown)}")

    def alter(self, c: mapping.Credential, value: Secret) -> None:
        """The database learns the new password over the old URL, then the new URL (once the
        password is staged, Railway derives it) must connect. An ALTER can commit and still
        report failure, so any failure from here prints how to recover."""
        pg = self.railway(c)[0]
        url_at = self.sibling(pg, c.url_variable)
        old_url = url_at.read()
        if old_url is None:
            raise RuntimeStop(f"{c.name}: {url_at.describe()} is not set; nothing was changed")
        bare, user, password = psql_target(old_url)
        if not PG_USER.fullmatch(user):
            raise RuntimeStop(f"{c.name}: the database URL's user is not a plain name")
        try:
            self.psql(
                bare, password, ALTER_SQL.format(user=user), {"verifier": scram_verifier(value)}
            )
            self.say(f"{c.name}: the database holds the new password")
        except RuntimeStop as e:
            raise RuntimeStop(f"{e}; {self.stranded(pg)}") from None
        try:
            pg.write(value, "")
        except targets.TargetError as e:
            raise RuntimeStop(f"{e}; {self.stranded(pg)}") from None
        self.say(f"{c.name}: {pg.describe()} staged fp:{self.fp(value)}")
        new_url = url_at.read()
        if new_url is None:
            raise RuntimeStop(f"{c.name}: {url_at.describe()} is gone; {self.stranded(pg)}")
        bare, _, password = psql_target(new_url)
        if self.psql(bare, password, "select 1;\n").strip() != "1":
            raise RuntimeStop(f"{c.name}: the database did not accept the new password")
        self.say(f"{c.name}: the new password connects")

    def psql(
        self, url: str, password: Secret, sql: str, variables: dict[str, str] | None = None
    ) -> str:
        """psql with the password in PGPASSWORD and `\\set` lines on stdin, so no value is on
        its command line."""
        for v in (variables or {}).values():
            if "'" in v or "\\" in v:
                raise RuntimeStop("a psql variable holds a quote or a backslash")
        sets = "".join(f"\\set {k} '{v}'\n" for k, v in (variables or {}).items())
        env = proc.child_env(self.environ, names={"PGSSLMODE", "PGSSLROOTCERT"})
        env["PGPASSWORD"] = password.reveal()
        try:
            done = proc.run(["psql", url, "-v", "ON_ERROR_STOP=1", "-qtA"], env, stdin=sets + sql)
        except proc.ChildError as e:
            raise RuntimeStop(str(e)) from None
        if done.code != 0:
            raise RuntimeStop(f"psql exited {done.code}")
        return done.stdout

    def stranded(self, pg: targets.Railway) -> str:
        service, environment = pg.f("service"), pg.f("environment")
        return (
            "the database may now hold a password Railway does not; set it to what Railway "
            "holds, from inside the container, where local sign-ins need none: copy "
            f"POSTGRES_PASSWORD from the {service} service's variables in the dashboard, run "
            f"railway ssh --service {service} --environment {environment}, then "
            "psql -U postgres -c '\\password postgres' and paste it at the prompt there"
        )

    def record(self, c: mapping.Credential, value: Secret) -> None:
        from keys import files
        from keys.rotating import set_entry  # the same line-for-line edit as every rotation

        fp = self.fp(value)
        path, _ = listing.mapping_path(self.args, self.ctx)
        path = path.resolve() if path.is_symlink() else path
        values: dict[str, str | None] = {"fp": f'"{fp}"', "rotated": self.today.isoformat()}
        try:
            files.replace(path, set_entry(path.read_text(encoding="utf-8"), c.name, values))
        except (OSError, ValueError) as e:
            raise RuntimeStop(
                f"{c.name}: rotated, but the mapping file could not be written "
                f'({type(e).__name__}): set fp = "{fp}", rotated = {self.today.isoformat()} '
                "by hand"
            ) from None
        self.say(f"{c.name}: recorded fp:{fp}, rotated {self.today.isoformat()}")


def run(args: argparse.Namespace, ctx: Context, creds: list[mapping.Credential]) -> int:
    if args.dry_run or args.now:
        raise UsageError("--dry-run and --now are for credentials with a 1Password item")
    if args.keep_previous and args.end_overlap:
        raise UsageError("--keep-previous and --end-overlap exclude each other")
    hidden = fp_key_variable(args.fp_key, ctx)
    environ = {k: v for k, v in ctx.environ.items() if k != hidden}
    r = Runtime(args, ctx, creds, environ)
    try:
        return r.go()
    except RuntimeStop as e:
        ctx.warn(f"keys: {e}")
        return EXIT_FAIL
