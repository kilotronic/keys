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
