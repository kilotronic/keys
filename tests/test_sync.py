"""keys sync: 1Password's value to every target in the mapping, on each child's stdin only.

Every case runs through the canary harness: the value may reach a target's write command on its
stdin, byte for byte, and nowhere else (argv, environment, streams, files, history).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from keys import targets
from keys.fingerprint import fingerprint
from keys.mapping import Target
from keys.secret import Secret
from tests.canary import CANARY, Canary

FP_KEY = "fp-key-made-up-for-tests-0123456789"
FP = fingerprint(Secret(FP_KEY), Secret(CANARY))
ITEM = "op://Automation/generic app-mail"
ENV = {"FPK": FP_KEY, "KEYS_FP_KEY": "env:FPK"}

ALL_TARGETS = """
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
type = "github-actions-org"
org = "kilo"
secret = "MAIL_KEY"
repos = ["app", "web"]

[[credential.target]]
type = "railway"
project = "proj"
service = "app"
environment = "production"
variable = "MAIL_API_KEY"

[[credential.target]]
type = "azure-key-vault"
vault = "app-kv"
secret = "mail-key"

[[credential.target]]
type = "gcp-secret"
project = "app-prod"
secret = "mail-key"
"""

KEYS = [
    "gh:owner/app:MAIL_KEY",
    "gh:owner/app:env:production:MAIL_KEY",
    "gh:org:kilo:MAIL_KEY",
    "railway:proj:app:production:MAIL_API_KEY",
    "az:app-kv:mail-key",
    "gcp:app-prod:mail-key",
]


def write_mapping(
    c: Canary, body: str = ALL_TARGETS, *, fp: str = "", name: str = "app-mail"
) -> Path:
    head = (
        f'[[credential]]\nname = "{name}"\nkind = "generic"\nitem = "{ITEM}"\n'
        'kept_because = "no OIDC"\n'
    )
    if fp:
        head += f'fp = "{fp}"\n'
    path = c.work / "keys.toml"
    text = path.read_text() + "\n" if path.exists() else ""
    path.write_text(text + head + body)
    return path


@pytest.fixture
def c(canary: Canary) -> Canary:
    canary.watch(FP_KEY)
    canary.op_value(f"{ITEM}/credential", CANARY)
    canary.target_put("gcp:app-prod:mail-key", "old-value-made-up-0001", labels={})
    return canary


def writes(c: Canary) -> list[list[str]]:
    """Every child that writes a target: the ones allowed a value on stdin."""
    from tests.canary import stdin_ok

    return [ch.argv for ch in c.children() if stdin_ok(ch.argv) and ch.prog != "op"]


def test_sync_writes_the_value_to_every_target_on_stdin_only(c: Canary) -> None:
    write_mapping(c)
    result = c.run(["sync", "app-mail"], env=ENV)
    assert result.code == 0, result.stderr
    for key in KEYS:
        got = c.target(key)
        assert got is not None, key
        assert got["value"] == CANARY, key
    stdin_children = [ch for ch in c.children() if ch.stdin]
    assert all(ch.stdin == CANARY for ch in stdin_children)
    assert len(stdin_children) == len(KEYS)
    assert c.target("az:app-kv:mail-key")["tags"] == {"keys-fp": FP}  # type: ignore[index]
    assert c.target("gcp:app-prod:mail-key")["labels"] == {"keys-fp": FP}  # type: ignore[index]
    lines = [line for line in result.stdout.splitlines() if line.startswith("app-mail")]
    assert len(lines) == len(KEYS)
    assert all(f"fp:{FP}" in line and "written" in line for line in lines)
    assert "keys sync: 6 targets written" in result.stdout


def test_the_org_secret_goes_to_its_repos_or_to_private_repos(c: Canary) -> None:
    write_mapping(c)
    c.run(["sync", "app-mail"], env=ENV)
    org = c.target("gh:org:kilo:MAIL_KEY")
    assert org is not None
    assert (org["visibility"], org["repos"]) == ("selected", "app,web")
    (c.work / "keys.toml").unlink()
    write_mapping(
        c, '[[credential.target]]\ntype = "github-actions-org"\norg = "k2"\nsecret = "S"\n'
    )
    c.run(["sync", "app-mail"], env=ENV)
    org = c.target("gh:org:k2:S")
    assert org is not None
    assert (org["visibility"], org["repos"]) == ("private", "")


def test_railway_is_staged_without_deploying_then_redeployed_once(c: Canary) -> None:
    body = ALL_TARGETS + (
        '\n[[credential.target]]\ntype = "railway"\nproject = "proj"\nservice = "app"\n'
        'environment = "production"\nvariable = "MAIL_KEY_TWO"\n'
    )
    write_mapping(c, body)
    result = c.run(["sync", "app-mail"], env=ENV)
    assert result.code == 0, result.stderr
    got = c.target("railway:proj:app:production:MAIL_API_KEY")
    assert got is not None
    assert got["skip_deploys"] is True
    assert len(c.deploys("railway:proj:app:production:")) == 2  # d0, then one redeploy
    redeploys = [ch for ch in c.children() if ch.argv[:2] == ["railway", "redeploy"]]
    assert len(redeploys) == 1
    assert "app (production): deployed" in result.stdout


def test_a_failed_deploy_fails_the_sync_and_names_the_service(c: Canary) -> None:
    write_mapping(c)
    c.set_db("deploy_status", "FAILED")
    result = c.run(["sync", "app-mail"], env=ENV)
    assert result.code == 1
    assert "app (production)" in result.stderr
    assert "FAILED" in result.stderr


def test_no_deploy_skips_the_redeploy(c: Canary) -> None:
    write_mapping(c)
    result = c.run(["sync", "app-mail", "--no-deploy"], env=ENV)
    assert result.code == 0, result.stderr
    assert not [ch for ch in c.children() if ch.argv[:2] == ["railway", "redeploy"]]
    assert "not redeployed" in result.stdout


def test_a_gcp_secret_that_is_not_there_yet_is_created(c: Canary) -> None:
    write_mapping(c, '[[credential.target]]\ntype = "gcp-secret"\nproject = "p2"\nsecret = "new"\n')
    result = c.run(["sync", "app-mail"], env=ENV)
    assert result.code == 0, result.stderr
    created = [ch.argv for ch in c.children() if ch.argv[1:3] == ["secrets", "create"]]
    assert len(created) == 1
    got = c.target("gcp:p2:new")
    assert got is not None
    assert got["value"] == CANARY
    assert got["labels"] == {"keys-fp": FP}


def test_all_syncs_every_credential(c: Canary) -> None:
    write_mapping(c, '[[credential.target]]\ntype = "github-actions"\nrepo = "o/a"\nsecret = "A"\n')
    other = "op://Automation/generic second"
    second = "second-value-made-up-" + "x7" * 6
    c.op_value(f"{other}/credential", second)
    path = c.work / "keys.toml"
    path.write_text(
        path.read_text()
        + f'\n[[credential]]\nname = "second"\nkind = "generic"\nitem = "{other}"\n'
        + 'kept_because = "x"\n[[credential.target]]\ntype = "github-actions"\n'
        + 'repo = "o/b"\nsecret = "B"\n'
    )
    result = c.run(["sync", "--all"], env=ENV)
    assert result.code == 0, result.stderr
    assert c.target("gh:o/a:A")["value"] == CANARY  # type: ignore[index]
    assert c.target("gh:o/b:B")["value"] == second  # type: ignore[index]


def test_sync_through_a_real_shell(c: Canary) -> None:
    write_mapping(c)
    result = c.shell("keys sync app-mail", env=ENV)
    assert result.code == 0, result.stderr
    assert c.target("gh:owner/app:MAIL_KEY")["value"] == CANARY  # type: ignore[index]


def test_dry_run_reads_no_value_and_writes_nothing(c: Canary) -> None:
    write_mapping(c)
    c.target_put("railway:proj:app:production:MAIL_API_KEY", "railway-held-made-up-" + "q9" * 6)
    c.target_put("gh:owner/app:MAIL_KEY", "unused")
    result = c.run(["sync", "app-mail", "--dry-run"])  # no fingerprint key needed either
    assert result.code == 0, result.stderr
    assert not [ch for ch in c.children() if ch.argv[:2] == ["op", "read"]]
    assert not writes(c)
    assert not [ch for ch in c.children() if ch.argv[:2] == ["railway", "redeploy"]]
    lines = [line for line in result.stdout.splitlines() if line.startswith("app-mail")]
    assert len(lines) == len(KEYS)
    assert all("would write" in line for line in lines)
    assert "github-actions owner/app MAIL_KEY" in result.stdout
    gh_line = next(line for line in lines if "github-actions owner/app MAIL_KEY" in line)
    assert "present" in gh_line
    az_line = next(line for line in lines if "azure-key-vault" in line)
    assert "not there yet" in az_line


def test_dry_run_fails_when_a_target_cannot_be_reached(c: Canary) -> None:
    write_mapping(c)
    c.child_fails(["az", "keyvault", "secret", "list"], code=3)
    result = c.run(["sync", "app-mail", "--dry-run"])
    assert result.code == 1
    assert "az exited 3" in result.stdout + result.stderr


def test_a_1password_failure_writes_nothing_and_shows_no_text(c: Canary) -> None:
    write_mapping(c)
    c.op_fail(f"{ITEM}/credential", code=6)  # its error text holds the canary
    result = c.run(["sync", "app-mail"], env=ENV)
    assert result.code == 3
    assert "op exited 6" in result.stderr
    assert not writes(c)


def test_an_empty_value_is_refused(c: Canary) -> None:
    write_mapping(c)
    c.op_value(f"{ITEM}/credential", "")
    result = c.run(["sync", "app-mail"], env=ENV)
    assert result.code == 3
    assert "empty" in result.stderr
    assert not writes(c)


def test_a_failed_write_stops_and_names_what_was_written(c: Canary) -> None:
    write_mapping(c)
    c.child_fails(["railway", "variable", "set"], code=5)  # its error text holds the canary
    result = c.run(["sync", "app-mail"], env=ENV)
    assert result.code == 1
    assert "railway exited 5" in result.stderr
    assert "3 targets were written before it" in result.stderr
    assert c.target("az:app-kv:mail-key") is None  # after the failure: not attempted
    assert not [ch for ch in c.children() if ch.argv[:2] == ["railway", "redeploy"]]


def test_a_value_that_differs_from_the_recorded_fingerprint_needs_force(c: Canary) -> None:
    write_mapping(c, fp="0badf00d")
    result = c.run(["sync", "app-mail"], env=ENV)
    assert result.code == 1
    assert f"fp:{FP}" in result.stderr
    assert "fp:0badf00d" in result.stderr
    assert "--force" in result.stderr
    assert not writes(c)
    result = c.run(["sync", "app-mail", "--force"], env=ENV)
    assert result.code == 0, result.stderr
    assert c.target("gh:owner/app:MAIL_KEY")["value"] == CANARY  # type: ignore[index]
    assert "fp:0badf00d" in result.stdout


def test_a_matching_recorded_fingerprint_syncs(c: Canary) -> None:
    write_mapping(c, fp=FP)
    assert c.run(["sync", "app-mail"], env=ENV).code == 0


@pytest.mark.parametrize(
    ("argv", "env", "message"),
    [
        (["sync"], ENV, "a credential's name or --all"),
        (["sync", "app-mail", "--all"], ENV, "a credential's name or --all"),
        (["sync", "no-such"], ENV, "no credential by that name"),
        (["sync", CANARY], ENV, "no credential by that name"),
        (["sync", "app-mail"], {}, "fingerprint key"),
    ],
)
def test_usage_errors_start_nothing(
    c: Canary, argv: list[str], env: dict[str, str], message: str
) -> None:
    write_mapping(c)
    result = c.run(argv, env=env)
    assert result.code == 3
    assert message in result.stderr
    assert not writes(c)


def test_a_credential_with_no_targets_says_so(c: Canary) -> None:
    write_mapping(c, "")
    result = c.run(["sync", "app-mail"], env=ENV)
    assert result.code == 0, result.stderr
    assert "app-mail: no targets" in result.stdout


SHAPED = "Zx81QwAbCdEf" * 3  # made up: a long run of letters and digits, as keys are


@pytest.mark.parametrize(
    "body",
    [
        f'[[credential.target]]\ntype = "github-actions"\nrepo = "o/a"\nsecret = "{SHAPED}"\n',
        f'[[credential.target]]\ntype = "github-actions"\nrepo = "o/{SHAPED}"\nsecret = "A"\n',
        '[[credential.target]]\ntype = "github-actions"\nrepo = "o/a"\nsecret = "A B"\n',
        '[[credential.target]]\ntype = "railway"\nservice = "s"\nenvironment = "--yes"\n'
        'variable = "A"\n',
        '[[credential.target]]\ntype = "azure-key-vault"\nvault = "v"\nsecret = '
        + json.dumps(CANARY)
        + "\n",
    ],
)
def test_a_target_field_that_is_not_a_plain_name_is_refused_and_not_shown(
    c: Canary, body: str
) -> None:
    c.watch(SHAPED)
    path = write_mapping(c, body)
    c.plant(path, path.read_text())  # holds the value, as a mistake would: unchanged is fine
    result = c.run(["sync", "app-mail"], env=ENV)
    assert result.code == 3
    assert "target[0]" in result.stderr
    assert not c.children()


def test_a_variable_outside_the_allowed_prefixes_never_reaches_a_child(c: Canary) -> None:
    write_mapping(c)
    # The harness fails the run if the planted value reaches any child's environment.
    result = c.run(["sync", "app-mail"], env={**ENV, "MY_TOKEN": CANARY})
    assert result.code == 0, result.stderr


# ---------------------------------------------------------------------------- the adapters


def _listing(c: Canary, t: Target) -> dict[str, Any]:
    out: dict[str, Any] = {}

    def step(ctx: Any) -> int:
        out.update(targets.adapter(t, ctx.environ, "t").listing())
        return 0

    c.call(step)
    return out


def test_listing_names_each_secret_with_its_date_and_fingerprint_tag(c: Canary) -> None:
    c.target_put("az:kv:a", "made-up-held-value-1", tags={"keys-fp": "1a2b3c4d"})
    found = _listing(c, Target("azure-key-vault", {"vault": "kv", "secret": "a"}, {}))
    assert set(found) == {"a"}
    assert found["a"].fp == "1a2b3c4d"
    assert found["a"].updated_at
    c.target_put("gh:o/r:env:prod:X", "made-up-held-value-2")
    found = _listing(
        c, Target("github-actions-env", {"repo": "o/r", "environment": "prod", "secret": "X"}, {})
    )
    assert set(found) == {"X"}
    assert found["X"].updated_at == "2026-01-01T00:00:00Z"


def test_a_railway_listing_keeps_names_only(c: Canary) -> None:
    held = "railway-held-made-up-" + "z3" * 6
    c.target_put("railway::s:e:V", held)
    found = _listing(
        c, Target("railway", {"service": "s", "environment": "e", "variable": "V"}, {})
    )
    assert set(found) == {"V"}
    assert held not in repr(found)
