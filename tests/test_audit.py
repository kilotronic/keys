"""keys check --all [--deep]: every credential's targets, by name and metadata only, and on the
Mac the real fingerprints too.

--all is the nightly CI check: it never starts op and needs no fingerprint key. --deep reads
each value from 1Password in process (and Railway's variables), and lists the 1Password items
tagged keys. Every case runs through the canary harness.
"""

from __future__ import annotations

import datetime
import plistlib
from pathlib import Path

import pytest

from keys.fingerprint import fingerprint
from keys.secret import Secret
from tests.canary import CANARY, Canary

FP_KEY = "fp-key-made-up-for-tests-0123456789"
FP = fingerprint(Secret(FP_KEY), Secret(CANARY))
ITEM = "op://Automation/generic app-mail"
ENV = {"FPK": FP_KEY, "KEYS_FP_KEY": "env:FPK"}
TODAY = datetime.date(2026, 11, 21)
OTHER = "other-value-made-up-" + "q8" * 6

TARGETS = """
[[credential.target]]
type = "github-actions"
repo = "owner/app"
secret = "MAIL_KEY"

[[credential.target]]
type = "github-actions-env"
repo = "owner/app"
environment = "production"
secret = "MAIL_KEY"

[[credential.target]]
type = "azure-key-vault"
vault = "app-kv"
secret = "mail-key"

[[credential.target]]
type = "gcp-secret"
project = "app-prod"
secret = "mail-key"

[[credential.target]]
type = "railway"
project = "proj"
service = "app"
environment = "production"
variable = "MAIL_API_KEY"
"""


def write_mapping(c: Canary, *, fp: str = FP, extra_top: str = "", body: str = TARGETS) -> None:
    head = extra_top + (
        f'[[credential]]\nname = "app-mail"\nkind = "generic"\nitem = "{ITEM}"\n'
        'kept_because = "no OIDC"\nrotated = 2026-11-01\n'
    )
    if fp:
        head += f'fp = "{fp}"\n'
    (c.work / "keys.toml").write_text(head + body)


def all_present(c: Canary, *, railway_value: str = CANARY, env: bool = True) -> None:
    after = "2026-11-02T10:00:00Z"
    c.target_put("gh:owner/app:MAIL_KEY", CANARY, updated_at=after)
    if env:
        c.target_put("gh:owner/app:env:production:MAIL_KEY", CANARY, updated_at=after)
    c.target_put("az:app-kv:mail-key", CANARY, updated_at=after, tags={"keys-fp": FP})
    c.target_put("gcp:app-prod:mail-key", CANARY, labels={"keys-fp": FP})
    c.target_put("railway:proj:app:production:MAIL_API_KEY", railway_value)


@pytest.fixture
def c(canary: Canary) -> Canary:
    canary.watch(FP_KEY)
    canary.op_value(f"{ITEM}/credential", CANARY)
    return canary


def check(c: Canary, *extra: str) -> tuple[int, str, str]:
    result = c.run(["check", "--all", *extra], env=ENV, today=lambda: TODAY)
    return result.code, result.stdout, result.stderr


def ops(c: Canary) -> list[list[str]]:
    return [ch.argv for ch in c.children() if ch.prog == "op"]


# ---------------------------------------------------------------------------- --all (CI)


def test_all_clean_needs_no_1password_and_skips_railway(c: Canary) -> None:
    write_mapping(c)
    all_present(c)
    code, out, err = check(c)
    assert code == 0, out + err
    assert ops(c) == []  # KEYS_FP_KEY is set, and still op never starts
    assert not [ch for ch in c.children() if ch.prog == "railway"]
    assert "github-actions owner/app MAIL_KEY  present" in out
    assert "azure-key-vault app-kv mail-key  present, fingerprint tag matches" in out
    assert "railway app/production MAIL_API_KEY  skipped: Railway is checked with --deep" in out
    assert "keys check --all: 1 credential, 5 targets, no problems" in out


def test_a_missing_target_fails(c: Canary) -> None:
    write_mapping(c)
    all_present(c, env=False)
    code, out, _ = check(c)
    assert code == 1
    assert "github-actions-env owner/app env:production MAIL_KEY  not there" in out
    assert "1 problem" in out


def test_a_github_secret_older_than_the_rotation_fails(c: Canary) -> None:
    write_mapping(c)
    all_present(c)
    c.target_put("gh:owner/app:MAIL_KEY", CANARY, updated_at="2026-10-15T00:00:00Z")
    code, out, _ = check(c)
    assert code == 1
    assert "MAIL_KEY  updated 2026-10-15, before it was rotated on 2026-11-01" in out


def test_a_fingerprint_tag_that_differs_fails(c: Canary) -> None:
    write_mapping(c)
    all_present(c)
    c.target_put("az:app-kv:mail-key", CANARY, tags={"keys-fp": "0badc0de"})
    c.target_put("gcp:app-prod:mail-key", CANARY, labels={})
    code, out, _ = check(c)
    assert code == 1
    assert "mail-key  fingerprint tag fp:0badc0de, the mapping file records fp:" + FP in out
    assert "gcp-secret app-prod mail-key  present, no fingerprint label" in out


def test_an_unmapped_secret_at_a_mapped_scope_fails_unless_ignored(c: Canary) -> None:
    write_mapping(c)
    all_present(c)
    c.target_put("gh:owner/app:STRAY_TOKEN", OTHER)
    code, out, _ = check(c)
    assert code == 1
    assert "-  github-actions owner/app  STRAY_TOKEN: not in the mapping file" in out
    write_mapping(c, extra_top='ignore_unmapped = ["STRAY_TOKEN"]\n\n')
    code, out, _ = check(c)
    assert code == 0, out
    assert "STRAY_TOKEN" not in out


def test_an_unmapped_name_shaped_like_a_value_is_withheld(c: Canary) -> None:
    write_mapping(c)
    all_present(c)
    shaped = "AB12" + "cd34EF56" * 4
    c.target_put(f"gh:owner/app:{shaped}", OTHER)
    c.watch(shaped)
    code, out, _ = check(c)
    assert code == 1
    assert "<name withheld>: not in the mapping file" in out


def test_a_scope_that_cannot_be_listed_fails_and_shows_no_error_text(c: Canary) -> None:
    write_mapping(c)
    all_present(c)
    c.child_fails(["gh", "secret", "list"], code=4)  # its error text holds the canary
    code, out, _ = check(c)
    assert code == 1
    assert "cannot list: gh exited 4 listing secrets" in out


def test_list_problems_fail_the_check_too(c: Canary) -> None:
    (c.work / "keys.toml").write_text(
        f'[[credential]]\nname = "app-mail"\nkind = "generic"\nitem = "{ITEM}"\n'
        "rotated = 2026-01-01\n"
    )
    code, out, _ = check(c)
    assert code == 1
    assert "no kept_because" in out
    assert ops(c) == []


def test_all_and_a_service_together_is_a_usage_error(c: Canary) -> None:
    write_mapping(c)
    result = c.run(["check", "github", "--all"], env=ENV)
    assert result.code == 3


def test_all_through_a_real_shell(c: Canary) -> None:
    write_mapping(c)
    all_present(c)
    result = c.shell("keys check --all", env=ENV)
    assert "present" in result.stdout
    assert not [ch for ch in c.children() if ch.prog == "op"]


# ---------------------------------------------------------------------------- --deep (Mac)


def test_deep_clean(c: Canary) -> None:
    write_mapping(c)
    all_present(c)
    c.op_items([tagged("generic app-mail", "2026-11-01T00:00:00Z")])
    code, out, err = check(c, "--deep")
    assert code == 0, out + err
    assert f"app-mail  1Password  fp:{FP} matches the mapping file" in out
    assert "railway app/production MAIL_API_KEY  present, value matches 1Password" in out
    assert ["op", "item", "list", "--tags", "keys", "--format", "json"] in ops(c)


def test_deep_a_railway_value_that_differs_fails(c: Canary) -> None:
    write_mapping(c)
    all_present(c, railway_value=OTHER)
    c.op_items([tagged("generic app-mail", "2026-11-01T00:00:00Z")])
    code, out, _ = check(c, "--deep")
    assert code == 1
    assert "MAIL_API_KEY  value differs from 1Password (fp:" in out


def test_deep_a_1password_value_that_differs_from_the_mapping_fails(c: Canary) -> None:
    write_mapping(c, fp="0badc0de")
    all_present(c)
    c.target_put("az:app-kv:mail-key", CANARY, tags={"keys-fp": "0badc0de"})
    c.target_put("gcp:app-prod:mail-key", CANARY, labels={"keys-fp": "0badc0de"})
    c.op_items([tagged("generic app-mail", "2026-11-01T00:00:00Z")])
    code, out, _ = check(c, "--deep")
    assert code == 1
    assert f"app-mail  1Password  fp:{FP}, but the mapping file records fp:0badc0de" in out
    # the tag matches the mapping file but not the real value
    assert f"mail-key  fingerprint tag fp:0badc0de, 1Password's value is fp:{FP}" in out


def test_deep_an_old_or_unmapped_1password_item_fails(c: Canary) -> None:
    write_mapping(c)
    all_present(c)
    c.op_items(
        [
            tagged("generic app-mail", "2026-03-01T00:00:00Z"),
            tagged("generic forgotten", "2026-11-01T00:00:00Z"),
        ]
    )
    code, out, _ = check(c, "--deep")
    assert code == 1
    assert "1Password Automation/generic app-mail  not updated in 265 days, over 180" in out
    assert "1Password Automation/generic forgotten  tagged keys, not in the mapping file" in out


def test_deep_a_1password_failure_shows_only_the_exit_code(c: Canary) -> None:
    write_mapping(c)
    all_present(c)
    c.op_fail(f"{ITEM}/credential", code=6)  # its error text holds the canary
    c.op_items([tagged("generic app-mail", "2026-11-01T00:00:00Z")])
    code, out, _ = check(c, "--deep")
    assert code == 1
    assert "app-mail  1Password  cannot read: op exited 6 reading a value" in out


def test_deep_needs_a_fingerprint_key(c: Canary) -> None:
    write_mapping(c)
    result = c.run(["check", "--deep"], today=lambda: TODAY)
    assert result.code == 3
    assert "fingerprint key" in result.stderr
    assert not c.children()


def test_deep_through_a_real_shell(c: Canary) -> None:
    write_mapping(c)
    all_present(c)
    c.op_items([tagged("generic app-mail", "2026-11-01T00:00:00Z")])
    result = c.shell("keys check --deep", env=ENV)
    assert "value matches 1Password" in result.stdout


def tagged(title: str, updated: str) -> dict[str, object]:
    return {
        "id": title.replace(" ", "-"),
        "title": title,
        "vault": {"name": "Automation"},
        "tags": ["keys"],
        "updated_at": updated,
    }


# ---------------------------------------------------------------------------- the daily scan


def test_the_launchd_plist_runs_keys_scan_daily() -> None:
    path = Path(__file__).parent.parent / "launchd" / "com.kilotronic.keys-scan.plist"
    plist = plistlib.loads(path.read_bytes())
    args = plist["ProgramArguments"]
    assert "keys scan" in " ".join(args)
    assert set(plist["StartCalendarInterval"]) <= {"Hour", "Minute", "Weekday"}
    assert "Library/Logs/keys" in plist["StandardOutPath"]
    assert plist["Label"] == "com.kilotronic.keys-scan"
