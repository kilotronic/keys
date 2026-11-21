"""keys rotate <name>: replace a credential end to end, in the design's eight steps.

    1 preflight  the mapping parses, every target can be reached, each GitHub Environment
                 admits main only, the 1Password item (and the minting key) can be read
    2 create     mint the new key and save it at once in the item's `pending` field; or, with no
                 create API, open the provider's pre-filled page and the item, and wait for the
                 owner's paste into `pending` (rerun to continue)
    3 probe      the new key must work (and, where the provider says, expire within 180 days)
    4 store      the current key moves to `previous`, the new one to the main field
    5 sync       to every target, on each CLI's stdin
    6 verify     each target uses it: a GitHub secret's date moved and its workflow passes,
                 Railway redeployed, Key Vault and Secret Manager carry its fingerprint
    7 revoke     the old key, by API or on the provider's page (rerun after the click), then
                 probe it and expect it dead
    8 record     fp, rotated and expires in the mapping file; `previous` cleared

Where it stands lives in the item's `keys_step` field, so a rerun resumes where the last run
stopped. Until step 7 the old key still works: a failure in steps 5 or 6 puts it back at every
target already changed and in 1Password, and revokes the new one. After step 7 nothing is
rolled back. Every line names the credential, the step, the target and fingerprints; never a
value, and never a program's or a provider's own text.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import json
import re
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from keys import appjwt, files, listing, looks, mapping, probes, proc, rotators, targets
from keys.checking import fp_key_variable, read_fp_key
from keys.context import EXIT_FAIL, EXIT_OK, EXIT_WAITING, Context, UsageError
from keys.fingerprint import fingerprint
from keys.kinds import KINDS
from keys.op import Op, OpError, fields, set_fields
from keys.secret import Secret

STEP = "keys_step"  # where a rotation stands, kept in the item (not secret)
EXPIRES = "keys_expires"  # the new key's expiry, from the provider, until it is recorded
PENDING, PREVIOUS = "pending", "previous"
PENDING_ID, PREVIOUS_ID = "pending_id", "previous_id"
# A new key a rollback could not revoke: the next run revokes it before anything else.
UNREVOKED_ID = "unrevoked_id"
ASKED = "keys_asked"  # the day keys asked for a paste or a download
AWAITING, CREATED, STORED, VERIFIED, REVOKED = (
    "awaiting-paste",
    "pending",
    "stored",
    "verified",
    "revoked",
)
STEPS = dict(
    enumerate(["preflight", "create", "probe", "store", "sync", "verify", "revoke", "record"], 1)
)
DOWNLOAD_LIMIT = 64 * 1024  # an RSA key's PEM is a few kB
MIN_PEM = 200  # shorter than any RSA key's PEM: a download still arriving
PROBE_TRIES = 3  # a fresh key can take a few seconds to authenticate
PROBE_WAIT_S = 5
RUN_LOOKS = 6  # looks for the run a dispatch started
WATCH_TIMEOUT_S = 3600
WORKFLOW = re.compile(r"[A-Za-z0-9_.-]{1,100}\.ya?ml")
PLAIN_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


REVOKED_NEW = "the new key was revoked"


class StepError(Exception):
    """A step failed; the message names it and what was left, never a value."""

    def __init__(self, step: int, text: str) -> None:
        super().__init__(f"{step} {STEPS[step]}: {text}")


def configure(p: argparse.ArgumentParser) -> None:
    p.add_argument("name", help="the credential to rotate")
    p.add_argument(
        "--dry-run", action="store_true", help="check what can be checked and print the plan"
    )
    p.add_argument(
        "--now",
        action="store_true",
        help="rotate a kind that keeps one key at a time, which means a short outage",
    )
    p.add_argument(
        "--fp-key",
        metavar="SOURCE",
        help="where the fingerprint secret comes from (default: $KEYS_FP_KEY)",
    )
    listing.add_mapping_flag(p)


def _find(m: mapping.Mapping, name: str, what: str) -> mapping.Credential:
    for c in m.credentials:
        if c.name == name:
            return c
    raise UsageError(f"no credential by that name in the mapping file ({what})")


def run(args: argparse.Namespace, ctx: Context) -> int:
    m = listing.load(args, ctx)
    c = _find(m, args.name, "the name given")
    rot = rotators.ROTATORS.get(c.kind)
    if rot is None:
        raise UsageError(f"keys cannot rotate a {c.kind} yet; it can rotate {_kinds()}")
    if KINDS[c.kind].single_key and not args.now:
        raise UsageError(
            f"a {c.kind} has one key at a time, so rotating it means a short outage; rerun "
            "with --now when that is fine"
        )
    minter: mapping.Credential | None = None
    if rot.mints:
        if not c.minted_by:
            raise UsageError(f"{c.name}: set minted_by to the credential whose key mints it")
        minter = _find(m, c.minted_by, "minted_by")
        if minter.name == c.name:
            raise UsageError(f"{c.name}: minted_by must name another credential")
    hidden = fp_key_variable(args.fp_key, ctx)
    environ = {k: v for k, v in ctx.environ.items() if k != hidden}
    ads = targets.adapters(c, environ)  # every target field checked before anything runs
    for i, a in enumerate(ads):
        wf = a.target.verify.get("workflow")
        if wf is not None:
            if not isinstance(a, targets.GitHubRepo | targets.GitHubEnv):
                raise UsageError(f"{c.name}.target[{i}].verify: a workflow needs a repo target")
            if not WORKFLOW.fullmatch(wf) or looks.looks_like_value(wf.rsplit(".", 1)[0]):
                raise UsageError(f"{c.name}.target[{i}].verify.workflow: a workflow file name")
    r = Rotation(args, ctx, c, rot, minter, ads, environ)
    try:
        return r.dry_run() if args.dry_run else r.go()
    except StepError as e:
        ctx.warn(f"keys: {c.name}: {e}")
        return EXIT_FAIL


def _kinds() -> str:
    return ", ".join(sorted(rotators.ROTATORS))


class Rotation:
    def __init__(
        self,
        args: argparse.Namespace,
        ctx: Context,
        c: mapping.Credential,
        rot: rotators.Rotator,
        minter: mapping.Credential | None,
        ads: list[targets.Adapter],
        environ: Mapping[str, str],
    ) -> None:
        self.args, self.ctx, self.c, self.rot = args, ctx, c, rot
        self.minter, self.ads, self.environ = minter, ads, environ
        self.op = Op(environ)
        self.today = ctx.today()
        self.key_name = f"{c.name} {self.today.isoformat()}"
        self.send: rotators.Send = ctx.send or probes.send
        self.before: dict[tuple[str, ...], dict[str, targets.Present]] = {}
        self.fp_key = Secret("")
        self.grant = rotators.Grant(Secret(""))
        self.item: dict[str, Any] = {}
        self.deployed: set[tuple[str, ...]] = set()  # Railway scopes redeployed with the new key
        self.ran: list[str] = []  # workflows dispatched with the new key

    # ------------------------------------------------------------------ helpers

    def say(self, step: int, text: str) -> None:
        self.ctx.say(f"{self.c.name}: {step} {STEPS[step]}: {text}")

    def fp(self, value: Secret) -> str:
        return fingerprint(self.fp_key, value)

    @property
    def minter_value(self) -> Secret:
        return self.grant.value

    def api(self, *values: Secret) -> rotators.Api:
        """The provider client; an error code holding a piece of any key in play (the minting
        key, these, and every concealed value of the item) is dropped, and an id pasted with
        one of them is refused."""
        f = self.fields() if self.item else {}
        held = [Secret(f[k]) for k in (self.c.field, PENDING, PREVIOUS) if f.get(k)]
        return rotators.Api(self.send, [self.minter_value, *values, *held])

    def fields(self) -> dict[str, str]:
        return fields(self.item)

    def save(self, step: int, values: dict[str, str], after: str = "") -> None:
        """These fields set on the item as 1Password holds it now, in one edit. If another run
        moved the item on since this one last saw it, nothing is saved."""
        tail = f"; {after}" if after else ""
        expected = self.fields().get(STEP, "")
        try:
            fresh = self.op.item_get(self.c.vault, self.c.item_title)
        except OpError as e:
            raise StepError(step, f"{e}{tail}") from None
        if fields(fresh).get(STEP, "") != expected:
            raise StepError(
                step,
                "another keys rotate changed the item meanwhile, so this run saved nothing; "
                "let that one finish",
            )
        set_fields(fresh, values, {self.c.field, PENDING, PREVIOUS})
        try:
            self.op.item_edit(self.c.vault, fresh)
        except OpError as e:
            raise StepError(step, f"{e}{tail}") from None
        self.item = fresh

    def reload(self) -> None:
        try:
            self.item = self.op.item_get(self.c.vault, self.c.item_title)
        except OpError as e:
            raise UsageError(f"could not read {self.c.name}'s 1Password item: {e}") from None

    def gh(self, step: int, what: str, argv: list[str], timeout: int = proc.TIMEOUT_S) -> str:
        env = proc.child_env(self.environ, names=targets.ENV_NAMES["gh"])
        try:
            done = proc.run(argv, env, timeout=timeout)
        except proc.ChildError as e:
            raise StepError(step, str(e)) from None
        if done.code != 0:
            raise StepError(step, f"gh exited {done.code} {what}")
        return done.stdout

    def open(self, url: str, what: str) -> None:
        """Open a page for the owner; with no `open` here, print where it is."""
        env = proc.child_env(self.environ)
        try:
            done = proc.run(["open", url], env)
            ok = done.code == 0
        except proc.ChildError:
            ok = False
        if not ok:
            self.ctx.say(f"open {what}: {url}")

    def open_item(self) -> None:
        item_id = str(self.item.get("id", ""))
        vault = cast(dict[str, Any], self.item.get("vault") or {})
        vault_id = str(vault.get("id", ""))
        if PLAIN_ID.fullmatch(item_id) and PLAIN_ID.fullmatch(vault_id):
            self.open(f"onepassword://view-item/?v={vault_id}&i={item_id}", "the 1Password item")

    def options(self, key_id: str) -> probes.Options | None:
        """What the probe needs besides the key (its id, the account), or None when the item
        does not hold it plainly."""
        try:
            return self.rot.probe_options(self.fields(), key_id)
        except rotators.RotateError:
            return None

    def probe_once(self, value: Secret, key_id: str = "") -> tuple[str, str, probes.Answer]:
        opts = self.options(key_id)
        if opts is None:
            return probes.UNKNOWN, "the item's ids are not plain ids", probes.Answer(0, "")
        return probes.check_answer(probes.PROVIDERS[self.rot.probe], value, opts, self.send)

    def probe(self, value: Secret, key_id: str = "") -> tuple[str, str, probes.Answer]:
        verdict, reason, answer = "", "", probes.Answer(0, "")
        for attempt in range(PROBE_TRIES):
            verdict, reason, answer = self.probe_once(value, key_id)
            if verdict == probes.WORKS or attempt == PROBE_TRIES - 1:
                break
            self.ctx.sleep(PROBE_WAIT_S)
        return verdict, reason, answer

    def revoke_page(self) -> str:
        try:
            return self.rot.revoke_url(self.c, self.fields())
        except rotators.RotateError:
            return ""

    # ------------------------------------------------------------------ 1 preflight

    def main_only(self, repo: str, environment: str) -> None:
        base = f"repos/{repo}/environments/{environment}"
        what = f"reading the {environment} Environment of {repo}"

        def read(path: str) -> dict[str, Any]:
            try:
                out = self.gh(1, what, ["gh", "api", path])
            except StepError:
                raise StepError(
                    1,
                    f"could not read the {environment} Environment of {repo}: it must exist and "
                    "admit main only",
                ) from None
            try:
                doc: object = json.loads(out)
            except ValueError:
                doc = None
            return cast(dict[str, Any], doc) if isinstance(doc, dict) else {}

        rule = cast(dict[str, Any], read(base).get("deployment_branch_policy") or {})
        allowed: list[tuple[object, object]] = []
        if rule.get("custom_branch_policies") and not rule.get("protected_branches"):
            got = cast(
                list[Any], read(f"{base}/deployment-branch-policies").get("branch_policies") or []
            )
            allowed = [
                (cast(dict[str, Any], p).get("name"), cast(dict[str, Any], p).get("type", "branch"))
                for p in got
                if isinstance(p, dict)
            ]
        if allowed != [("main", "branch")]:
            raise StepError(
                1,
                f"the {environment} Environment of {repo} admits more than main; limit it to "
                "main, then rerun",
            )

    def preflight_targets(self) -> list[str]:
        """Every target scope listed once, every Environment checked; problems, as lines."""
        problems: list[str] = []
        for a in self.ads:
            if a.scope() not in self.before:
                try:
                    self.before[a.scope()] = a.listing()
                except targets.TargetError as e:
                    problems.append(f"cannot reach {a.describe()}: {e}")
            if isinstance(a, targets.GitHubEnv):
                try:
                    self.main_only(a.f("repo"), a.f("environment"))
                except StepError as e:
                    problems.append(str(e).split(": ", 1)[1])
        return problems

    # ------------------------------------------------------------------ dry run

    def dry_run(self) -> int:
        c, rot = self.c, self.rot
        problems = self.preflight_targets()
        for cred in [c, *([self.minter] if self.minter else [])]:
            try:
                titles = {t.casefold() for t in self.op.item_titles(cred.vault)}
            except OpError as e:
                problems.append(f"could not list {cred.name}'s vault: {e}")
                continue
            if cred.item_title.casefold() not in titles:
                problems.append(f"{cred.name}'s 1Password item is not in its vault")
        say = self.ctx.say
        say(f"{c.name}: the plan (dry run)")
        found = "; ".join(problems) if problems else "every target reachable, items found"
        say(f"  1 preflight: {found}")
        if rot.mints and self.minter:
            say(f"  2 create: mint {self.key_name!r} with {self.minter.name}'s key, into pending")
        else:
            say(
                f"  2 create: open the provider's page for {self.key_name!r}; you paste it into "
                "the item's pending field, then rerun"
            )
        say(f"  3 probe: the new key at {rot.probe}, expecting it to work")
        say("  4 store: the new key into the main field, the old one into previous")
        for a in self.ads:
            say(f"  5 sync: {a.describe()}")
        say("  6 verify: each target uses it (dates, fingerprints, deploys, workflows)")
        how = "by API" if rot.revokes_by_api else "on the provider's page, after your click"
        say(f"  7 revoke: the old key {how}, then probe it, expecting it dead")
        say("  8 record: fp, rotated and expires in the mapping file")
        say("keys rotate --dry-run: nothing was changed")
        return EXIT_FAIL if problems else EXIT_OK

    # ------------------------------------------------------------------ the run

    def go(self) -> int:
        c = self.c
        self.fp_key = read_fp_key(self.args.fp_key, self.ctx)
        problems = self.preflight_targets()
        if problems:
            raise StepError(1, "; ".join(problems))
        self.reload()
        if self.minter:
            try:
                item = self.op.item_get(self.minter.vault, self.minter.item_title)
            except OpError as e:
                raise UsageError(f"could not read {self.minter.name} from 1Password: {e}") from None
            got = fields(item)
            value = Secret(got.pop(self.minter.field, "").strip())
            if not value:
                raise UsageError(f"{self.minter.name}: its 1Password value is empty")
            self.grant = rotators.Grant(value, got)
        f = self.fields()
        step = f.get(STEP, "")
        if not step and (f.get(PENDING) or f.get(PREVIOUS)):
            raise StepError(
                1,
                "the item holds a pending or previous value keys did not leave there; clear "
                "those fields in the 1Password app, then rerun",
            )
        self.expires_field(1)  # a hand-edited value there stops the run before any save
        if not step:
            self.check_item(f)
        if f.get(UNREVOKED_ID):
            self.revoke_stray(f[UNREVOKED_ID])
        self.say(1, f"{len(self.ads)} targets reachable" + (", resuming" if step else ""))
        if step == "":
            if self.rot.mints:
                self.create()
            else:
                return self.ask_paste()
        elif step == AWAITING:
            took = not f.get(PENDING, "").strip() and self.take_download()
            if not took and self.fields().get(PENDING, "").strip():
                self.leftover_downloads()
            if not took and not self.fields().get(PENDING, "").strip():
                self.ctx.say(f"{c.name}: 2 create: still waiting for the paste")
                return self.ask_paste()
            if not took:
                self.clear_clipboard()
            self.save(2, {STEP: CREATED})
        if self.fields().get(STEP) == CREATED:
            self.store(self.check_new())
        if self.fields().get(STEP) == STORED:
            self.sync_and_verify()
        if self.fields().get(STEP) == VERIFIED:
            waiting = self.revoke_old()
            if waiting:
                return EXIT_WAITING
        if self.fields().get(STEP) == REVOKED:
            self.record()
            return EXIT_OK
        raise StepError(1, "the item's keys_step field holds something keys did not write")

    def check_item(self, f: dict[str, str]) -> None:
        """Before a fresh rotation: an old key keys can revoke has its id; with no old key (the
        first value), no target holds the secret yet, since there is nothing to put back."""
        id_field = self.rot.id_field
        if f.get(self.c.field, "").strip():
            if self.rot.revokes_by_api and id_field and not f.get(id_field, "").strip():
                raise StepError(
                    1,
                    f"the item's {id_field} field is empty: fill it with the current key's id "
                    "(keys revokes the old key by it), then rerun",
                )
            return
        there = [a.describe() for a in self.ads if a.name in self.before.get(a.scope(), {})]
        if there:
            raise StepError(
                1,
                f"the item holds no key, but {', '.join(there)} already holds one: paste the "
                "current key into the item first, so a rollback can put it back",
            )

    def revoke_stray(self, key_id: str) -> None:
        """A new key an earlier rollback could not revoke goes before anything else."""
        try:
            key_id = rotators.ident(self.fields(), UNREVOKED_ID, [self.minter_value])
            self.rot.revoke(self.api(), self.grant, self.fields(), key_id)
        except rotators.RotateError as e:
            if e.status != 404:
                raise StepError(
                    1,
                    f"a key an earlier run made is still live and could not be revoked ({e}); "
                    "rerun, or delete it by hand and clear the item's unrevoked_id field",
                ) from None
        self.save(1, {UNREVOKED_ID: ""})
        self.say(1, "revoked the key an earlier rollback left live")

    # ------------------------------------------------------------------ 2 create

    def create(self) -> None:
        if self.minter is None:  # run() refuses a mint kind without one
            raise StepError(2, "no minting credential")
        try:
            new = self.rot.mint(self.api(), self.grant, self.fields(), self.key_name, self.today)
        except rotators.RotateError as e:
            raise StepError(2, f"{e}; nothing was changed") from None
        values = {
            PENDING: new.value.reveal(),
            PENDING_ID: new.ident,
            EXPIRES: new.expires.isoformat() if new.expires else "",
            STEP: CREATED,
        }
        try:
            self.save(2, values)
        except StepError as e:
            gone = self.revoke_new(new.value, new.ident)
            raise StepError(
                2, f"{str(e).split(': ', 1)[1]}; {gone}; nothing else changed"
            ) from None
        self.say(2, f"made {self.key_name!r} fp:{self.fp(new.value)}, saved as pending")

    def ask_paste(self) -> int:
        c = self.c
        try:
            page = self.rot.create_page(c, self.fields(), self.key_name)
        except rotators.RotateError as e:
            raise UsageError(f"{c.name}: {e}") from None
        if self.fields().get(STEP) != AWAITING:
            self.save(
                2, {PENDING: "", PENDING_ID: "", STEP: AWAITING, ASKED: self.today.isoformat()}
            )
        self.open(page, "the page that makes the new key")
        download = self.rot.download(self.fields()) is not None
        if not download:  # a downloaded key is never pasted, so the item stays closed
            self.open_item()
        repos = sorted({r for a in self.ads for r in _repos(a)})
        say = self.ctx.say
        if download:
            say(f"{c.name}: 2 create: waiting for you, in the browser:")
            say("  on the page just opened, generate a private key; the browser saves it to")
            say("  Downloads. Do not open the file: the next run moves it into the item's")
            say("  pending field and deletes it")
            say(f"  then run: keys rotate {c.name}")
            return EXIT_WAITING
        say(f"{c.name}: 2 create: waiting for you, in the browser and 1Password:")
        say(f"  make the new key on the page just opened: {self.key_name!r}, 180 days or less")
        if repos:
            say(f"  repository access, only these: {', '.join(repos)}")
        say("  copy it and paste it into the pending field of the 1Password item just opened")
        say("  (never into a terminal or a chat); keep clipboard history and Universal")
        say("  Clipboard off meanwhile")
        say(f"  then run: keys rotate {c.name}")
        return EXIT_WAITING

    def downloads(self) -> list[Path]:
        """The files in ~/Downloads named as the provider names this key's download, dated on or
        after the day keys asked for it (an older one is an earlier key, maybe the live one).
        Links are left alone: deleting one would leave the file it points at."""
        pattern = self.rot.download(self.fields())
        home = self.environ.get("HOME", "")
        if pattern is None or not home:
            return []
        asked = self.fields().get(ASKED, "") or self.today.isoformat()
        found: list[Path] = []
        try:
            for p in (Path(home) / "Downloads").iterdir():
                dated = re.search(r"\.(\d{4}-\d{2}-\d{2})\.", p.name)
                if not pattern.fullmatch(p.name) or not dated or dated.group(1) < asked:
                    continue
                if not p.is_symlink() and p.is_file():
                    found.append(p)
        except OSError:
            return []
        return found

    def take_download(self) -> bool:
        """For a key the provider hands out only as a file (a GitHub App key): the one new file
        of its name in ~/Downloads moved into the item's pending field, then deleted, so no copy
        stays on disk. Its content is never printed; neither is anything but a count."""
        found = self.downloads()
        if not found:
            return False
        if len(found) > 1:
            raise StepError(
                2,
                f"{len(found)} downloaded keys for this App are in Downloads; delete all but the "
                "newest (keys reads none of them), then rerun",
            )
        path = found[0]
        try:
            with path.open("rb") as f:
                data = f.read(DOWNLOAD_LIMIT + 1)
            text = Secret(data.decode("utf-8"))
        except (OSError, ValueError):
            raise StepError(2, "could not read the downloaded key; rerun") from None
        if len(data) > DOWNLOAD_LIMIT:
            raise StepError(2, "the downloaded file is too large to be a key; delete it, rerun")
        if not appjwt.is_rsa_key(text):
            if len(data) < MIN_PEM:  # a browser makes the file before the key arrives in it
                raise StepError(2, "wait for the download to finish, then rerun")
            raise StepError(
                2, "the downloaded file is not an RSA private key; delete it, then rerun"
            )
        self.save(2, {PENDING: text.reveal()}, "the downloaded key is still in Downloads")
        self.say(2, f"took the downloaded key {self.rot.describe(text)} into the pending field")
        del text
        self.remove_download(path)
        return True

    def remove_download(self, path: Path) -> None:
        try:
            path.unlink()
        except OSError:
            self.say(2, "delete the downloaded key file in Downloads: keys could not")
            return
        self.say(2, "deleted the downloaded file")

    def leftover_downloads(self) -> None:
        """A run that saved the download but stopped before deleting it: the file holding
        exactly the pending key goes now."""
        pending = Secret(self.fields().get(PENDING, ""))
        for path in self.downloads():
            try:
                with path.open("rb") as f:
                    same = Secret(f.read(DOWNLOAD_LIMIT).decode("utf-8")) == pending
            except (OSError, ValueError):
                continue
            if same:
                self.remove_download(path)

    def clear_clipboard(self) -> None:
        try:
            proc.run(["pbcopy"], proc.child_env(self.environ), stdin="")
        except proc.ChildError:
            self.ctx.say(f"{self.c.name}: clear the clipboard: copy something else")

    # ------------------------------------------------------------------ 3 probe, 4 store

    def check_new(self) -> str:
        """Probe the pending key; its expiry (ISO date or empty) when it passes."""
        f = self.fields()
        value = targets.normalise(Secret(f.get(PENDING, "")), self.c.name)
        current = Secret(f.get(self.c.field, "").rstrip("\n"))
        if current and value == current:  # never revoked: it is the live key
            self.save(3, {PENDING: "", PENDING_ID: "", EXPIRES: "", STEP: ""})
            raise StepError(
                3,
                "the pending value is the current key, not a new one; pending cleared, nothing "
                "else changed: make a new key and rerun",
            )
        verdict, reason, answer = self.probe(value, f.get(PENDING_ID, ""))
        problem = ""
        expires = self.expires_field(3)
        if verdict == probes.UNKNOWN:
            raise StepError(
                3,
                f"cannot tell whether the new key works ({reason}); it stays in the item's "
                "pending field and nothing else changed: rerun",
            )
        if verdict != probes.WORKS:
            problem = f"the new key does not work: {verdict} ({reason})"
        elif KINDS[self.c.kind].can_expire:
            found = self.rot.expiry(answer)
            if found is None and not expires:
                problem = "the provider shows no expiry for the new key"
            elif found is not None:
                expires = found.isoformat()
        if not problem and expires:
            left = (datetime.date.fromisoformat(expires) - self.today).days
            if left > rotators.MAX_DAYS:
                problem = f"the new key expires in {left} days, over {rotators.MAX_DAYS}"
        if problem:
            gone = self.revoke_new(value, f.get(PENDING_ID, ""))
            self.save(3, {PENDING: "", PENDING_ID: "", EXPIRES: "", STEP: ""})
            raise StepError(3, f"{problem}; {gone}; pending cleared, nothing else changed")
        self.say(3, f"the new key fp:{self.fp(value)} works ({reason})")
        return expires

    def expires_field(self, step: int) -> str:
        """The item's keys_expires field: empty or a date keys wrote."""
        text = self.fields().get(EXPIRES, "")
        if text:
            try:
                datetime.date.fromisoformat(text)
            except ValueError:
                raise StepError(
                    step, "the item's keys_expires field holds something keys did not write"
                ) from None
        return text

    def store(self, expires: str) -> None:
        f = self.fields()
        c = self.c
        value = targets.normalise(Secret(f[PENDING]), c.name)
        values = {
            c.field: value.reveal(),
            PREVIOUS: f.get(c.field, ""),
            PENDING: "",
            PENDING_ID: "",
            STEP: STORED,
            EXPIRES: expires,
        }
        if self.rot.id_field:
            values |= {
                self.rot.id_field: f.get(PENDING_ID, ""),
                PREVIOUS_ID: f.get(self.rot.id_field, ""),
            }
        self.save(
            4,
            values,
            "the new key is still in the item's pending field; rerun to continue",
        )
        self.say(4, "1Password holds the new key, the old one as previous")

    # ------------------------------------------------------------------ 5 sync, 6 verify

    def delivered(self, a: targets.Adapter, old: bool) -> Secret:
        """What target a receives: the key, or (with `field = ...`) a non-secret field of the
        item, such as a Twilio key's SID; the old one's or the new one's."""
        f, c = self.fields(), self.c
        name = a.target.field
        if not name:
            return targets.normalise(Secret(f.get(PREVIOUS if old else c.field, "")), c.name)
        if old and name == self.rot.id_field:
            return targets.normalise(Secret(f.get(PREVIOUS_ID, "")), c.name)
        return targets.normalise(Secret(f.get(name, "")), c.name)

    def sync_and_verify(self) -> None:
        written: list[targets.Adapter] = []
        fps: dict[int, str] = {}
        for i, a in enumerate(self.ads):
            value = self.delivered(a, old=False)
            if not value:
                self.rollback(5, a, f"the item's {a.target.field} field is empty", written)
            fps[i] = fp = self.fp(value)
            # Counted before the write: one that failed may still have landed (a timeout), and
            # writing the old key back to a target that never changed does no harm.
            written.append(a)
            try:
                a.write(value, fp)
            except targets.TargetError as e:
                self.rollback(5, a, str(e), written)
            self.say(5, f"{a.describe()} fp:{fp}")
        # Each Railway service is redeployed once, after its variables read back right; a
        # workflow runs with the new key and may deploy it, so it goes last: a failure elsewhere
        # rolls back before anything was dispatched.
        later = [i for i, a in enumerate(self.ads) if a.target.verify.get("workflow")]
        order = [i for i in range(len(self.ads)) if i not in later]
        services: dict[tuple[str, ...], targets.Railway] = {}
        for i in order:
            a = self.ads[i]
            try:
                self.verify(a, fps[i])
            except targets.TargetError as e:
                self.rollback(6, a, str(e), written)
            if isinstance(a, targets.Railway):
                services.setdefault(a.scope(), a)
        for a in services.values():
            try:
                a.redeploy(self.ctx.sleep)
            except targets.TargetError as e:
                if a.requested:  # accepted, so it may go live with the new key after all
                    self.deployed.add(a.scope())
                self.rollback(6, a, str(e), written)
            self.deployed.add(a.scope())
            self.say(6, f"{a.service_label()} deployed")
        for i in later:
            a = self.ads[i]
            try:
                self.verify(a, fps[i])
            except targets.TargetError as e:
                self.rollback(6, a, str(e), written)
            except StepError as e:
                self.rollback(6, a, str(e).split(": ", 1)[1], written)
        self.save(6, {STEP: VERIFIED}, "every target uses the new key; rerun to continue")

    def verify(self, a: targets.Adapter, fp: str) -> None:
        if isinstance(a, targets.Railway):
            value = a.read()  # in memory; only its fingerprint is kept
            got = self.fp(Secret(value.reveal().rstrip("\n"))) if value is not None else ""
            del value
            if got != fp:
                raise targets.TargetError("the variable does not read back as the new key")
            self.say(6, f"{a.describe()} reads back fp:{fp}")
            return
        now = a.listing().get(a.name)
        if now is None:
            raise targets.TargetError("the secret is not there after the sync")
        if isinstance(a, targets.AzureKeyVault | targets.GcpSecret):
            if now.fp != fp:
                raise targets.TargetError("its fingerprint tag does not name the new key")
            self.say(6, f"{a.describe()} carries fp:{fp}")
            return
        then = self.before.get(a.scope(), {}).get(a.name)
        if then is not None and then.updated_at and not now.updated_at > then.updated_at:
            raise targets.TargetError("GitHub shows no update after the sync")
        wf = a.target.verify.get("workflow")
        if wf and isinstance(a, targets.GitHubRepo | targets.GitHubEnv):
            self.ran.append(f"{a.f('repo')} {wf}")
            self.run_workflow(a.f("repo"), wf)
            self.say(6, f"{a.describe()} updated; {wf} passed")
        else:
            self.say(6, f"{a.describe()} updated")

    def _runs(self, repo: str, wf: str) -> list[int]:
        argv = ["gh", "run", "list", "--repo", repo, "--workflow", wf, "--limit", "20"]
        out = self.gh(6, "listing runs", [*argv, "--json", "databaseId,event,headBranch"])
        try:
            rows = cast(list[Any], json.loads(out or "[]"))
        except ValueError:
            rows = []
        return [
            int(cast(dict[str, Any], r)["databaseId"])
            for r in rows
            if isinstance(r, dict)
            and cast(dict[str, Any], r).get("event") == "workflow_dispatch"
            and cast(dict[str, Any], r).get("headBranch") == "main"
            and isinstance(cast(dict[str, Any], r).get("databaseId"), int)
        ]

    def run_workflow(self, repo: str, wf: str) -> None:
        """Dispatch the workflow once on main and watch that run once."""
        seen = set(self._runs(repo, wf))
        self.gh(
            6,
            "dispatching the workflow",
            ["gh", "workflow", "run", wf, "--repo", repo, "--ref", "main"],
        )
        run_id = None
        for attempt in range(RUN_LOOKS):
            fresh = [r for r in self._runs(repo, wf) if r not in seen]
            if fresh:
                run_id = fresh[0]
                break
            if attempt < RUN_LOOKS - 1:
                self.ctx.sleep(PROBE_WAIT_S)
        if run_id is None:
            raise StepError(6, f"the run {wf} was dispatched, but keys could not find it")
        argv = ["gh", "run", "watch", str(run_id), "--repo", repo, "--interval", "60"]
        self.gh(
            6, f"watching {wf}: the run did not pass", [*argv, "--exit-status"], WATCH_TIMEOUT_S
        )

    def rollback(
        self, step: int, at: targets.Adapter, why: str, written: list[targets.Adapter]
    ) -> None:
        """Put the old key back where the new one went, in 1Password too, and revoke the new
        one. Always raises."""
        f = self.fields()
        c = self.c
        old = targets.normalise(Secret(f.get(PREVIOUS, "")), c.name)
        new = Secret(f.get(c.field, ""))
        fp_old = self.fp(old) if old else ""
        stuck: list[str] = []
        notes: list[str] = []
        if old:
            for a in written:
                back = self.delivered(a, old=True)
                try:
                    a.write(back, self.fp(back))
                except targets.TargetError:
                    sent = self.fp(self.delivered(a, old=False))
                    if a is not at or self.landed(a, sent) is not False:
                        stuck.append(a.describe())
            for a in {a.scope(): a for a in written if isinstance(a, targets.Railway)}.values():
                try:
                    a.redeploy(self.ctx.sleep)
                except targets.TargetError:
                    if a.scope() in self.deployed:  # it runs the new key, about to be revoked
                        stuck.append(f"{a.describe()} (redeploy)")
                    else:  # the deployment from before the rotation still runs
                        notes.append(f"redeploy {a.service_label()} by hand when you can")
        else:
            notes.append("there was no old key, so the targets keep the new one, now revoked")
        if self.ran:
            notes.append(
                f"{', '.join(self.ran)} ran with the new key: run it again once this is fixed"
            )
        head = f"failed at {at.describe()}: {why}"
        if stuck:
            raise StepError(
                step,
                f"{head}; the old key could not be put back at {', '.join(stuck)}, so 1Password "
                "keeps the new key (the old one as previous): rerun to finish the rotation",
            )
        values = {c.field: old.reveal(), PREVIOUS: "", PENDING: "", PENDING_ID: "", STEP: ""}
        new_id = f.get(self.rot.id_field, "") if self.rot.id_field else ""
        if self.rot.id_field:
            values |= {self.rot.id_field: f.get(PREVIOUS_ID, ""), PREVIOUS_ID: ""}
        if self.rot.revokes_by_api and new_id:
            values[UNREVOKED_ID] = new_id  # kept until the revoke below goes through
        try:
            self.save(step, values)
        except StepError as e:
            raise StepError(
                step,
                f"{head}; every target holds the old key again, but 1Password could not be "
                f"put back ({str(e).split(': ', 1)[1]}): the old key is in its previous field",
            ) from None
        gone = self.revoke_new(new, new_id)
        if UNREVOKED_ID in values and gone == REVOKED_NEW:
            with contextlib.suppress(StepError):
                self.save(step, {UNREVOKED_ID: ""})
        where = f"the old key fp:{fp_old}" if old else "no key (as before)"
        tail = "".join(f"; {n}" for n in notes)
        raise StepError(
            step,
            f"{head}; rolled back: every target and 1Password hold {where} again; {gone}{tail}",
        )

    def landed(self, a: targets.Adapter, fp_new: str) -> bool | None:
        """Whether a write that failed reached the target after all: the secret's date moved,
        its fingerprint tag names the new key, or (Railway) it holds the new key. None when
        keys cannot tell."""
        try:
            if isinstance(a, targets.Railway):
                value = a.read()
                return value is not None and self.fp(Secret(value.reveal().rstrip("\n"))) == fp_new
            now = a.listing().get(a.name)
        except targets.TargetError:
            return None
        then = self.before.get(a.scope(), {}).get(a.name)
        if isinstance(a, targets.AzureKeyVault | targets.GcpSecret):
            return now is not None and now.fp == fp_new
        if now is None:
            return False
        if then is None or not then.updated_at or not now.updated_at:
            return None
        return now.updated_at != then.updated_at

    # ------------------------------------------------------------------ revoking

    def revoke_new(self, value: Secret, key_id: str) -> str:
        """Revoke a new key that will not be used; what happened, as a phrase."""
        if self.rot.revokes_by_api and key_id:
            try:
                self.rot.revoke(self.api(value), self.grant, self.fields(), key_id)
            except rotators.RotateError as e:
                return (
                    f"the new key could not be revoked ({e}): the next keys rotate revokes it, "
                    f"or delete {self.key_name!r} by hand"
                )
            return REVOKED_NEW
        page = self.revoke_page()
        if page:
            self.open(page, "the page to revoke the new key")
        which = self.rot.describe(value) or repr(self.key_name)
        return f"delete the new key {which} on the page just opened"

    def revoke_old(self) -> bool:
        """Revoke the old key and see it refused. True when waiting for the owner's click."""
        f = self.fields()
        old = targets.normalise(Secret(f.get(PREVIOUS, "")), self.c.name)
        new = targets.normalise(Secret(f.get(self.c.field, "")), self.c.name)
        # The new key is what every target holds now; if it stopped working (the owner deleted
        # the wrong one), the old one must not go too.
        verdict, reason, _ = self.probe(new, f.get(self.rot.id_field, ""))
        if verdict != probes.WORKS:
            raise StepError(
                7,
                f"the new key no longer works ({verdict}, {reason}), and every target holds it; "
                "the old key stays in 1Password's previous field: make a new key and rerun",
            )
        if not old:
            self.save(7, {STEP: REVOKED}, "rerun to record it")
            self.say(7, "there was no old key to revoke")
            return False
        fp_old = self.fp(old)
        keep = (
            "the old key stays in 1Password's previous field; nothing is broken: rerun to try again"
        )
        if self.rot.revokes_by_api:
            # Always sent, even if the old key already probes dead (a probe can be refused for
            # other reasons); a rerun after a revoke that went through gets a 404, which counts.
            try:
                key_id = rotators.ident(f, PREVIOUS_ID, [old, self.minter_value])
                self.rot.revoke(self.api(old), self.grant, f, key_id)
            except rotators.RotateError as e:
                if e.status != 404:
                    raise StepError(
                        7, f"the old key fp:{fp_old} was not revoked: {e}; {keep}"
                    ) from None
            verdict, reason, _ = self.probe_dead(old, f.get(PREVIOUS_ID, ""))
            if verdict == probes.UNKNOWN:
                raise StepError(
                    7, f"cannot tell whether the old key fp:{fp_old} is dead ({reason}); {keep}"
                )
            if verdict != probes.DEAD:
                raise StepError(
                    7, f"the old key fp:{fp_old} still works after the revoke ({reason}); {keep}"
                )
        else:
            verdict, reason, _ = self.probe_once(old, f.get(PREVIOUS_ID, ""))
            if verdict == probes.WORKS:
                self.open(self.revoke_page(), "the page to revoke the old key")
                which = self.rot.describe(old)
                keep_new = self.rot.describe(new)
                if which:  # a key with no name on the provider's page: by its fingerprint
                    line = f"delete the old key {which} (keep {keep_new})"
                else:
                    line = f"delete the old key (the one not named {self.key_name!r})"
                self.ctx.say(
                    f"{self.c.name}: 7 revoke: waiting for you: {line} on the page just opened, "
                    f"then run: keys rotate {self.c.name}"
                )
                return True
            if verdict != probes.DEAD:
                raise StepError(
                    7, f"cannot tell whether the old key fp:{fp_old} is dead ({reason}); {keep}"
                )
        self.save(7, {STEP: REVOKED}, "the old key is revoked; rerun to record it")
        self.say(7, f"the old key fp:{fp_old} is refused now ({reason})")
        return False

    def probe_dead(self, value: Secret, key_id: str = "") -> tuple[str, str, probes.Answer]:
        got = ("", "", probes.Answer(0, ""))
        for attempt in range(PROBE_TRIES):
            got = self.probe_once(value, key_id)
            if got[0] == probes.DEAD or attempt == PROBE_TRIES - 1:
                break
            self.ctx.sleep(PROBE_WAIT_S)
        return got

    # ------------------------------------------------------------------ 8 record

    def record(self) -> None:
        c = self.c
        f = self.fields()
        new = targets.normalise(Secret(f[c.field]), c.name)
        fp = self.fp(new)
        expires = self.expires_field(8) if KINDS[c.kind].can_expire else ""
        values: dict[str, str | None] = {
            "fp": json.dumps(fp),
            "rotated": self.today.isoformat(),
            "expires": expires or None,
        }
        path, _ = listing.mapping_path(self.args, self.ctx)
        path = path.resolve() if path.is_symlink() else path
        by_hand = f'fp = "{fp}", rotated = {self.today.isoformat()}' + (
            f", expires = {expires}" if expires else ""
        )
        try:
            text = path.read_text(encoding="utf-8")
            new_text = set_entry(text, c.name, values)
            files.replace(path, new_text)
        except (OSError, ValueError) as e:
            raise StepError(
                8,
                f"could not write the mapping file ({type(e).__name__}); rerun to record it, or "
                f"set {by_hand} for {c.name} by hand",
            ) from None
        self.save(
            8,
            {PREVIOUS: "", PREVIOUS_ID: "", EXPIRES: "", STEP: ""},
            "the mapping file is recorded; rerun to clear the item's previous field",
        )
        self.say(
            8,
            f"fp:{fp}, rotated {self.today.isoformat()}"
            + (f", expires {expires}" if expires else ""),
        )
        for a in self.ads:
            self.ctx.say(f"{c.name}  {a.describe()}  fp:{fp}  in use")
        self.ctx.say(f"keys rotate: {c.name} rotated; commit the mapping file")


def _repos(a: targets.Adapter) -> list[str]:
    if isinstance(a, targets.GitHubRepo | targets.GitHubEnv):
        return [a.f("repo")]
    if isinstance(a, targets.GitHubOrg):
        repos = a.target.fields.get("repos", [])
        org = a.f("org")
        return [f"{org}/{r}" for r in (repos if isinstance(repos, list) else [repos])]
    return []


# ---------------------------------------------------------------------------- the mapping file

CRED_HEADER = re.compile(r"^\s*\[\[\s*credential\s*\]\]\s*(#.*)?$")
ANY_HEADER = re.compile(r"^\s*\[")


def set_entry(text: str, name: str, values: dict[str, str | None]) -> str:
    """text with these top-level keys of credential `name` set (a TOML literal) or removed
    (None). Everything else stays byte for byte; the result must parse to the same file apart
    from these keys, or ValueError."""
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if CRED_HEADER.match(line)]
    name_line = re.compile(rf"^\s*name\s*=\s*{re.escape(json.dumps(name))}\s*(#.*)?$")
    for n, start in enumerate(starts):
        end = starts[n + 1] if n + 1 < len(starts) else len(lines)
        head_end = next((i for i in range(start + 1, end) if ANY_HEADER.match(lines[i])), end)
        if not any(name_line.match(lines[i].rstrip("\r\n")) for i in range(start + 1, head_end)):
            continue
        head = lines[start + 1 : head_end]
        for key, literal in values.items():
            pattern = re.compile(rf"^\s*{key}\s*=")
            at = next((i for i, line in enumerate(head) if pattern.match(line)), None)
            if at is not None:
                if literal is None:
                    del head[at]
                else:
                    head[at] = f"{key} = {literal}\n"
            elif literal is not None:
                last = max(
                    (
                        i
                        for i, line in enumerate(head)
                        if line.strip() and not line.lstrip().startswith("#")
                    ),
                    default=-1,
                )
                if last >= 0 and not head[last].endswith("\n"):
                    head[last] += "\n"
                head.insert(last + 1, f"{key} = {literal}\n")
        out = "".join(lines[: start + 1] + head + lines[head_end:])
        _same_apart_from(text, out, name, values)
        return out
    raise ValueError("credential not found")


def _same_apart_from(before: str, after: str, name: str, values: dict[str, str | None]) -> None:
    old = tomllib.loads(before)
    new = tomllib.loads(after)
    for doc in (old, new):
        for entry in cast(list[dict[str, Any]], doc.get("credential", [])):
            if entry.get("name") == name:
                for key in values:
                    entry.pop(key, None)
    if old != new:
        raise ValueError("the edit would change more than the rotation's fields")
    mapping.parse(tomllib.loads(after), Path("keys.toml"))
    found = next(e for e in tomllib.loads(after)["credential"] if e.get("name") == name)
    for key, literal in values.items():
        if literal is not None and key not in found:
            raise ValueError("the edit did not take")
