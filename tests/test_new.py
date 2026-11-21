"""keys new <kind> <name>: an empty 1Password item with the right fields and tags, and the
matching mapping entry. The item goes to op as JSON on stdin; nothing is a field=value argument.
"""

from __future__ import annotations

import json
import tomllib
from typing import Any

import pytest

from keys.kinds import KINDS
from tests.canary import CANARY, Canary

ARGS = ["--vault", "Automation", "--kept-because", "the provider has no OIDC sign-in"]


def created(c: Canary) -> dict[str, Any]:
    creates = [ch for ch in c.children() if ch.argv[:3] == ["op", "item", "create"]]
    assert len(creates) == 1
    assert creates[0].argv == ["op", "item", "create", "--vault", "Automation", "-"]
    return json.loads(creates[0].stdin)


def mapping(c: Canary) -> dict[str, Any]:
    return tomllib.loads((c.work / "keys.toml").read_text())


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_each_kind_makes_its_item_and_entry(canary: Canary, kind: str) -> None:
    result = canary.run(["new", kind, "app-thing", *ARGS])
    assert result.code == 0, result.stderr
    item = created(canary)
    assert item["title"] == f"{kind} app-thing"
    assert item["category"] == "API_CREDENTIAL"
    assert item["tags"] == ["keys", kind]
    fields = {f["label"]: f for f in item["fields"]}
    assert fields["credential"]["type"] == "CONCEALED"
    assert fields["credential"]["value"] == ""
    for name in KINDS[kind].fields:
        assert fields[name]["type"] == "STRING"
        assert fields[name]["value"] == ""
    entry = mapping(canary)["credential"][0]
    assert entry == {
        "name": "app-thing",
        "kind": kind,
        "item": f"op://Automation/{kind} app-thing",
        "kept_because": "the provider has no OIDC sign-in",
    }
    assert f"made the 1Password item {kind} app-thing" in result.stdout
    assert "paste the value" in result.stdout


def test_it_appends_to_an_existing_mapping_and_keeps_it_valid(canary: Canary) -> None:
    before = '# my credentials\n[[credential]]\nname = "old"\nkind = "generic"\nitem = "op://V/i"\n'
    (canary.work / "keys.toml").write_text(before)
    result = canary.run(["new", "generic", "fresh", *ARGS, "--owner", "owner"])
    assert result.code == 0, result.stderr
    text = (canary.work / "keys.toml").read_text()
    assert text.startswith(before)
    names = [c["name"] for c in mapping(canary)["credential"]]
    assert names == ["old", "fresh"]
    assert mapping(canary)["credential"][1]["owner"] == "owner"


def test_a_reason_with_quotes_stays_valid_toml(canary: Canary) -> None:
    result = canary.run(
        ["new", "generic", "q", "--vault", "Automation", "--kept-because", 'no "OIDC" \\ yet']
    )
    assert result.code == 0, result.stderr
    assert mapping(canary)["credential"][0]["kept_because"] == 'no "OIDC" \\ yet'


def test_a_name_already_in_the_mapping_is_refused(canary: Canary) -> None:
    (canary.work / "keys.toml").write_text(
        '[[credential]]\nname = "dup"\nkind = "generic"\nitem = "op://V/i"\n'
    )
    result = canary.run(["new", "generic", "dup", *ARGS])
    assert result.code == 3
    assert "dup is already in the mapping file" in result.stderr
    assert not canary.children()


def test_an_item_already_in_the_vault_is_refused(canary: Canary) -> None:
    canary.op_items([{"id": "x", "title": "generic dup", "vault": {"name": "Automation"}}])
    result = canary.run(["new", "generic", "dup", *ARGS])
    assert result.code == 3
    assert "already has an item named generic dup" in result.stderr
    assert [ch.argv[:3] for ch in canary.children()] == [["op", "item", "list"]]
    assert not (canary.work / "keys.toml").exists()


def test_a_failed_create_prints_only_the_exit_code_and_writes_no_entry(canary: Canary) -> None:
    canary.op_create_fails(code=5)  # op's error text holds the canary
    result = canary.run(["new", "generic", "app", *ARGS])
    assert result.code == 3
    assert "op exited 5 creating the item" in result.stderr
    assert not (canary.work / "keys.toml").exists()


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["new", "no-such-kind", "a", *ARGS], "invalid choice"),
        (["new", "generic", "Bad Name", *ARGS], "name must be lower-case letters"),
        (["new", "generic", CANARY, *ARGS], "name must be lower-case letters"),
        (["new", "generic", "a", "--vault", "a/b", "--kept-because", "x"], "vault name"),
        (["new", "generic", "a", "--vault", "V"], "--kept-because"),
        (["new", "generic", "a", "--vault", "V", "--kept-because", "  "], "--kept-because"),
    ],
)
def test_bad_arguments(canary: Canary, argv: list[str], message: str) -> None:
    result = canary.run(argv)
    assert result.code == 3
    assert message in result.stderr
    assert not canary.children()


def test_a_broken_mapping_is_refused_before_anything_is_made(canary: Canary) -> None:
    (canary.work / "keys.toml").write_text('[[credential]]\nname = "a"\n')
    result = canary.run(["new", "generic", "b", *ARGS])
    assert result.code == 3
    assert not canary.children()


def test_new_through_a_real_shell(canary: Canary) -> None:
    result = canary.shell(
        "keys new cloudflare-token deploy --vault Automation --kept-because 'no OIDC for deploys'"
    )
    assert result.code == 0, result.stderr
    assert created(canary)["title"] == "cloudflare-token deploy"
    assert mapping(canary)["credential"][0]["name"] == "deploy"


# ---------------------------------------------------------------------------- review fixes

ALNUM_RUN = ("Zx81Qw" + "AbCdEf") * 3  # made up: one long run of letters and digits, as keys are


@pytest.mark.parametrize(
    "argv",
    [
        ["new", "generic", "a", "--vault", "V", "--kept-because", CANARY],
        ["new", "generic", "a", "--vault", "V", "--kept-because", ALNUM_RUN],
        ["new", "generic", "a", "--vault", "V", "--kept-because", f"because {ALNUM_RUN}"],
        ["new", "generic", "a", "--vault", "V", "--kept-because", "x y", "--owner", CANARY],
        ["new", "generic", "a", "--vault", ALNUM_RUN, "--kept-because", "x y"],
        ["new", "generic", "a", "--vault", "V", "--kept-because", "x\x7fy z"],
    ],
)
def test_a_value_in_a_text_flag_is_refused_before_anything_is_made(
    canary: Canary, argv: list[str]
) -> None:
    canary.watch(ALNUM_RUN)
    result = canary.run(argv)
    assert result.code == 3, result.stdout
    assert not canary.children()
    assert not (canary.work / "keys.toml").exists()


@pytest.mark.parametrize("how", ["flag", "env"])
def test_a_missing_mapping_named_by_flag_or_env_is_not_created(canary: Canary, how: str) -> None:
    argv = ["new", "generic", "a", *ARGS]
    env: dict[str, str] = {}
    if how == "flag":
        argv += ["--mapping", "elsewhere.toml"]
    else:
        env = {"KEYS_MAPPING": "elsewhere.toml"}
    result = canary.run(argv, env=env)
    assert result.code == 3
    assert "does not exist" in result.stderr
    assert not canary.children()
    assert not (canary.work / "elsewhere.toml").exists()


def test_a_title_that_differs_only_in_case_is_a_duplicate(canary: Canary) -> None:
    canary.op_items([{"id": "x", "title": "Generic Dup", "vault": {"name": "Automation"}}])
    result = canary.run(["new", "generic", "dup", *ARGS])
    assert result.code == 3
    assert "already has an item named" in result.stderr


def test_an_item_already_used_by_another_entry_is_refused(canary: Canary) -> None:
    (canary.work / "keys.toml").write_text(
        '[[credential]]\nname = "other"\nkind = "generic"\nitem = "op://Automation/generic dup"\n'
    )
    result = canary.run(["new", "generic", "dup", *ARGS])
    assert result.code == 3
    assert "other already uses that item" in result.stderr
    assert not canary.children()


def test_a_failed_item_list_makes_nothing(canary: Canary) -> None:
    canary.op_list_fails(code=4)
    result = canary.run(["new", "generic", "a", *ARGS])
    assert result.code == 3
    assert "op exited 4 listing items" in result.stderr
    assert [ch.argv[:3] for ch in canary.children()] == [["op", "item", "list"]]
    assert not (canary.work / "keys.toml").exists()


def test_a_create_that_failed_but_saved_says_so_and_can_add_the_entry_only(canary: Canary) -> None:
    canary.op_create_fails(code=1, saved=True)
    result = canary.run(["new", "generic", "a", *ARGS])
    assert result.code == 3
    assert "the item is in 1Password" in result.stderr
    assert "--entry-only" in result.stderr
    result = canary.run(["new", "generic", "a", *ARGS, "--entry-only"])
    assert result.code == 0, result.stderr
    assert mapping(canary)["credential"][0]["name"] == "a"
    assert not [ch for ch in canary.children() if ch.argv[:3] == ["op", "item", "create"]]


def test_entry_only_needs_the_item_to_exist(canary: Canary) -> None:
    result = canary.run(["new", "generic", "a", *ARGS, "--entry-only"])
    assert result.code == 3
    assert "no item named generic a" in result.stderr


def test_a_mapping_that_cannot_be_written_is_reported_with_the_item_made(canary: Canary) -> None:
    (canary.work / "keys.toml").write_text("")
    canary.work.chmod(0o500)
    try:
        result = canary.run(["new", "generic", "a", *ARGS])
    finally:
        canary.work.chmod(0o700)
    assert result.code == 3
    assert "made the 1Password item generic a, but could not add it" in result.stderr


def test_the_item_json_holds_nothing_planted(canary: Canary) -> None:
    canary.run(["new", "generic", "a", *ARGS])
    assert CANARY not in json.dumps(created(canary))
