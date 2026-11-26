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
    assert "keys check --all: 1 credential, 5 targets (1 skipped), no problems" in out


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
    assert result.code == 0, result.stdout + result.stderr
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
    assert result.code == 0, result.stdout + result.stderr
    assert "value matches 1Password" in result.stdout


def tagged(title: str, updated: str) -> dict[str, object]:
    return {
        "id": title.replace(" ", "-"),
        "title": title,
        "vault": {"name": "Automation"},
        "tags": ["keys"],
        "updated_at": updated,
    }


# ---------------------------------------------------------------------------- review fixes

GH_ONLY = """
[[credential.target]]
type = "github-actions"
repo = "owner/app"
secret = "mail_key"
"""


def test_github_names_compare_without_case(c: Canary) -> None:
    write_mapping(c, body=GH_ONLY, extra_top='ignore_unmapped = ["stray_token"]\n\n')
    c.target_put("gh:owner/app:MAIL_KEY", CANARY, updated_at="2026-11-02T00:00:00Z")
    c.target_put("gh:owner/app:STRAY_TOKEN", OTHER)
    code, out, _ = check(c)
    assert code == 0, out
    assert "MAIL_KEY: not in the mapping file" not in out
    assert "github-actions owner/app mail_key  present" in out


TWO_OWNERS = """
[[credential.target]]
type = "github-actions"
repo = "owner/app"
secret = "MAIL_KEY"

[[credential.target]]
type = "github-actions-env"
repo = "other-org/site"
environment = "production"
secret = "MAIL_KEY"

[[credential.target]]
type = "github-actions-org"
org = "other-org"
secret = "MAIL_KEY"
visibility = "private"
"""
TOKEN_OWNER = "token-for-owner-made-up"
TOKEN_OTHER = "token-for-other-org-made-up"


def two_owners(c: Canary) -> None:
    write_mapping(c, body=TWO_OWNERS)
    after = "2026-11-02T10:00:00Z"
    c.target_put("gh:owner/app:MAIL_KEY", CANARY, updated_at=after)
    c.target_put("gh:other-org/site:env:production:MAIL_KEY", CANARY, updated_at=after)
    c.target_put("gh:org:other-org:MAIL_KEY", CANARY, updated_at=after)
    c.set_db("gh_tokens", {"owner": TOKEN_OWNER, "other-org": TOKEN_OTHER})


def test_each_github_owner_is_listed_with_its_own_token(c: Canary) -> None:
    # An App's installation token reaches one owner's repos, so a check across two owners
    # takes a token per owner: KEYS_GH_TOKEN_<OWNER>, upper case, dashes as underscores.
    two_owners(c)
    env = {"GH_TOKEN": TOKEN_OWNER, "KEYS_GH_TOKEN_OTHER_ORG": TOKEN_OTHER}
    result = c.run(["check", "--all"], env={**ENV, **env}, today=lambda: TODAY)
    assert result.code == 0, result.stdout + result.stderr
    assert "github-actions-env other-org/site env:production MAIL_KEY  present" in result.stdout
    assert "github-actions-org other-org MAIL_KEY  present" in result.stdout
    for text in (result.stdout, result.stderr):
        assert TOKEN_OWNER not in text
        assert TOKEN_OTHER not in text
    for ch in c.children():  # gh gets the chosen token as GH_TOKEN, never the keys variable
        if ch.prog == "gh":
            assert "GH_TOKEN" in ch.env
            assert not [n for n in ch.env if n.startswith("KEYS_GH_TOKEN_")]


def test_an_owner_with_no_token_of_its_own_uses_gh_token(c: Canary) -> None:
    two_owners(c)
    env = {"GH_TOKEN": TOKEN_OWNER}
    result = c.run(["check", "--all"], env={**ENV, **env}, today=lambda: TODAY)
    assert result.code == 1
    assert "github-actions owner/app MAIL_KEY  present" in result.stdout
    assert "other-org/site env:production MAIL_KEY  cannot list: gh exited 1" in result.stdout


def test_an_owner_token_overrides_gh_token_for_that_owner_only(c: Canary) -> None:
    two_owners(c)
    env = {
        "GH_TOKEN": TOKEN_OTHER,
        "KEYS_GH_TOKEN_OWNER": TOKEN_OWNER,
        "GITHUB_TOKEN": "another-token-made-up",
    }
    result = c.run(["check", "--all"], env={**ENV, **env}, today=lambda: TODAY)
    assert result.code == 0, result.stdout + result.stderr
    listings = [ch for ch in c.children() if ch.argv[:3] == ["gh", "secret", "list"]]
    owner = [ch for ch in listings if "owner/app" in ch.argv]
    assert owner
    assert all("GITHUB_TOKEN" not in ch.env for ch in owner)  # only the chosen one


def test_key_vault_names_compare_without_case(c: Canary) -> None:
    body = (
        '[[credential.target]]\ntype = "azure-key-vault"\nvault = "app-kv"\nsecret = "Mail-Key"\n'
    )
    write_mapping(c, body=body)
    c.target_put("az:app-kv:mail-key", CANARY, tags={"keys-fp": FP})
    code, out, _ = check(c)
    assert code == 0, out


def test_a_github_secret_with_no_date_or_a_credential_with_no_rotation_fails(c: Canary) -> None:
    write_mapping(c, body=GH_ONLY)
    c.target_put("gh:owner/app:MAIL_KEY", CANARY, updated_at="")
    code, out, _ = check(c)
    assert code == 1
    assert "mail_key  present, but GitHub gives no update date to compare" in out
    (c.work / "keys.toml").write_text(
        f'[[credential]]\nname = "app-mail"\nkind = "generic"\nitem = "{ITEM}"\n'
        'kept_because = "no OIDC"\n' + GH_ONLY
    )
    c.target_put("gh:owner/app:MAIL_KEY", CANARY, updated_at="2026-11-02T00:00:00Z")
    code, out, _ = check(c)
    assert code == 1
    assert "mail_key  present, but no rotation date to compare with" in out


def test_a_tagged_target_with_no_mapping_fp_fails(c: Canary) -> None:
    write_mapping(c, fp="")
    all_present(c)
    code, out, _ = check(c)
    assert code == 1
    assert "mail-key  the mapping file records no fingerprint to compare with the tag" in out


@pytest.mark.parametrize(("updated", "ok"), [("2026-10-31T23:30:00Z", True), ("2026-10-30", False)])
def test_the_github_date_allows_one_day_for_time_zones(c: Canary, updated: str, ok: bool) -> None:
    write_mapping(c, body=GH_ONLY)
    c.target_put("gh:owner/app:MAIL_KEY", CANARY, updated_at=updated)
    code, out, _ = check(c)
    assert (code == 0) is ok, out


def test_a_disabled_or_expired_key_vault_secret_is_not_present(c: Canary) -> None:
    body = (
        '[[credential.target]]\ntype = "azure-key-vault"\nvault = "app-kv"\nsecret = "mail-key"\n'
    )
    write_mapping(c, body=body)
    c.target_put("az:app-kv:mail-key", CANARY, tags={"keys-fp": FP}, enabled=False)
    code, out, _ = check(c)
    assert code == 1
    assert "mail-key  disabled at the target" in out
    c.target_put(
        "az:app-kv:mail-key", CANARY, tags={"keys-fp": FP}, expires="2026-11-01T00:00:00+00:00"
    )
    code, out, _ = check(c)
    assert code == 1
    assert "mail-key  expired at the target" in out


def test_a_managed_key_vault_secret_is_not_unmapped(c: Canary) -> None:
    body = (
        '[[credential.target]]\ntype = "azure-key-vault"\nvault = "app-kv"\nsecret = "mail-key"\n'
    )
    write_mapping(c, body=body)
    c.target_put("az:app-kv:mail-key", CANARY, tags={"keys-fp": FP})
    c.target_put("az:app-kv:tls-cert", OTHER, managed=True)
    code, out, _ = check(c)
    assert code == 0, out


def test_a_credential_with_only_railway_is_named_in_ci(c: Canary) -> None:
    body = (
        '[[credential.target]]\ntype = "railway"\nproject = "proj"\nservice = "app"\n'
        'environment = "production"\nvariable = "MAIL_API_KEY"\n'
    )
    write_mapping(c, body=body)
    code, out, _ = check(c)
    assert code == 0, out
    assert "app-mail  -  note: no target checked without --deep" in out
    assert "1 targets (1 skipped)" not in out
    assert "1 target (1 skipped)" in out


def test_all_with_expect_is_a_usage_error(c: Canary) -> None:
    write_mapping(c)
    result = c.run(["check", "--all", "--expect", "works"], env=ENV)
    assert result.code == 3
    assert not c.children()


def test_all_never_starts_op_even_with_an_op_fingerprint_key(c: Canary) -> None:
    write_mapping(c)
    all_present(c)
    result = c.run(
        ["check", "--all"],
        env={"KEYS_FP_KEY": "op://Automation/fp/credential"},
        today=lambda: TODAY,
    )
    assert result.code == 0, result.stdout
    assert ops(c) == []


def test_an_empty_mapping_fails_all(c: Canary) -> None:
    (c.work / "keys.toml").write_text("")
    code, out, _ = check(c)
    assert code == 1
    assert "keys check --all: 0 credentials, 0 targets, 1 problem" in out


@pytest.mark.parametrize(
    ("words", "shown"),
    [
        (["az", "keyvault", "secret", "list"], "cannot list: az exited 4 listing secrets"),
        (["gcloud", "secrets", "list"], "cannot list: gcloud exited 4 listing secrets"),
    ],
)
def test_a_vault_or_project_that_cannot_be_listed_fails(
    c: Canary, words: list[str], shown: str
) -> None:
    write_mapping(c)
    all_present(c)
    c.child_fails(words, code=4)
    code, out, _ = check(c)
    assert code == 1
    assert shown in out


def test_a_listing_keys_cannot_read_fails_and_shows_none_of_it(c: Canary) -> None:
    write_mapping(c)
    all_present(c)
    c.child_prints(["gh", "secret", "list"], f"not json {CANARY}")
    code, out, _ = check(c)
    assert code == 1
    assert "cannot list: gh printed something keys cannot read" in out


def test_deep_another_railway_value_never_shows(c: Canary) -> None:
    write_mapping(c)
    all_present(c)
    c.target_put("railway:proj:app:production:OTHER_KEY", OTHER)
    c.op_items([tagged("generic app-mail", "2026-11-01T00:00:00Z")])
    code, out, _ = check(c, "--deep")
    assert code == 0, out
    assert "OTHER_KEY" not in out  # Railway variables are not checked for unmapped names


@pytest.mark.parametrize("how", ["fails", "unreadable"])
def test_deep_a_railway_listing_that_fails_is_a_problem(c: Canary, how: str) -> None:
    write_mapping(c)
    all_present(c)
    c.op_items([tagged("generic app-mail", "2026-11-01T00:00:00Z")])
    if how == "fails":
        c.child_fails(["railway", "variable", "list"], code=5)
        shown = "cannot list: railway exited 5 listing variables"
    else:
        c.child_prints(["railway", "variable", "list"], "{" + CANARY)
        shown = "cannot list: railway printed something keys cannot read"
    code, out, _ = check(c, "--deep")
    assert code == 1
    assert shown in out


def test_deep_an_item_list_that_fails_is_a_problem(c: Canary) -> None:
    write_mapping(c)
    all_present(c)
    c.op_list_fails(code=7)
    code, out, _ = check(c, "--deep")
    assert code == 1
    assert "cannot list the items tagged keys: op exited 7 listing items" in out


def test_deep_a_mapped_item_not_tagged_keys_fails(c: Canary) -> None:
    write_mapping(c)
    all_present(c)
    c.op_items([])
    code, out, _ = check(c, "--deep")
    assert code == 1
    assert "app-mail  1Password  the item is not tagged keys" in out


def test_deep_railway_falls_back_to_the_mapping_fp_when_1password_fails(c: Canary) -> None:
    write_mapping(c)
    all_present(c, railway_value=OTHER)
    c.op_fail(f"{ITEM}/credential", code=6)
    c.op_items([tagged("generic app-mail", "2026-11-01T00:00:00Z")])
    code, out, _ = check(c, "--deep")
    assert code == 1
    assert "MAIL_API_KEY  value differs from the mapping file (fp:" in out


# ---------------------------------------------------------------------------- the daily scan

PLIST = Path(__file__).parent.parent / "launchd" / "com.kilotronic.keys-scan.plist"


def test_the_launchd_plist_runs_keys_scan_daily_without_asking_for_touch_id() -> None:
    plist = plistlib.loads(PLIST.read_bytes())
    assert plist["Label"] == "com.kilotronic.keys-scan"
    args = plist["ProgramArguments"]
    assert args[0].startswith("/Users/OWNER/")
    assert args[0].endswith("/keys")
    assert args[1:] == ["scan", "--patterns-only"]
    assert set(plist["StartCalendarInterval"]) == {"Hour", "Minute"}
    env = plist["EnvironmentVariables"]
    assert env["KEYS_MAPPING"].startswith("/")
    path = env["PATH"].split(":")
    assert "/usr/bin" in path
    assert all(p.startswith("/") for p in path)
    for key in ("StandardOutPath", "StandardErrorPath"):
        assert plist[key] == "/Users/OWNER/Library/Logs/keys/scan.log"


def test_the_plist_holds_only_absolute_paths_launchd_can_use() -> None:
    text = PLIST.read_text()
    assert "~" not in text.replace("<!--", "").split("-->")[-1]
    assert "$HOME" not in text
    assert "${" not in text
    plist = plistlib.loads(PLIST.read_bytes())
    strings = [*plist["ProgramArguments"][:1], plist["StandardOutPath"]]
    strings += list(plist["EnvironmentVariables"].values())
    assert all(s.startswith("/") for s in strings)
