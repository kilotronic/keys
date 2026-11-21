"""The mapping file: names, items, targets and dates, never values; errors name the field only."""

from __future__ import annotations

import datetime
import re
from pathlib import Path

import pytest

from keys import mapping
from tests.canary import CANARY

Q = f"'{CANARY}'"  # a TOML literal string: the canary holds " and \

GOOD = """
kept_budget = 3

[[credential]]
name = "app-resend"
kind = "generic"
item = "op://Vault/generic app-resend"
owner = "owner"
kept_because = "Resend has no OIDC sign-in"
fp = "1a2b3c4d"
rotated = 2026-11-01
expires = 2027-04-30

[[credential.target]]
type = "railway"
service = "app"
environment = "production"
variable = "RESEND_API_KEY"
verify = { health = "production" }

[[credential.target]]
type = "github-actions-env"
repo = "owner/app"
environment = "deploy"
secret = "RESEND_API_KEY"

[[credential]]
name = "ci-app-key"
kind = "github-app-key"
item = "op://Vault/github-app-key ci-app-key"
kept_because = "GitHub has no keyless App sign-in"
"""


def load(tmp_path: Path, text: str) -> mapping.Mapping:
    path = tmp_path / "keys.toml"
    path.write_text(text)
    return mapping.load(path)


def errors(tmp_path: Path, text: str) -> str:
    with pytest.raises(mapping.MappingError) as e:
        load(tmp_path, text)
    message = str(e.value)
    assert CANARY not in message
    return message


def test_a_good_file_loads(tmp_path: Path) -> None:
    m = load(tmp_path, GOOD)
    assert m.kept_budget == 3
    assert [c.name for c in m.credentials] == ["app-resend", "ci-app-key"]
    c = m.credentials[0]
    assert (c.kind, c.vault, c.item_title, c.field) == (
        "generic",
        "Vault",
        "generic app-resend",
        "credential",
    )
    assert c.value_ref == "op://Vault/generic app-resend/credential"
    assert c.rotated == datetime.date(2026, 11, 1)
    assert c.expires == datetime.date(2027, 4, 30)
    assert c.fp == "1a2b3c4d"
    assert [t.type for t in c.targets] == ["railway", "github-actions-env"]
    assert c.targets[0].fields["variable"] == "RESEND_API_KEY"
    assert c.targets[0].verify == {"health": "production"}
    assert m.credentials[1].kept_because == "GitHub has no keyless App sign-in"
    assert m.credentials[1].targets == []


def test_a_missing_file_names_the_path(tmp_path: Path) -> None:
    with pytest.raises(mapping.MappingError, match=r"no mapping file at .*nope\.toml"):
        mapping.load(tmp_path / "nope.toml")


def test_bad_toml_names_the_line_not_the_text(tmp_path: Path) -> None:
    message = errors(tmp_path, f'[[credential]]\nname = "a"\nfp = {CANARY}\n')
    assert "line 3" in message


@pytest.mark.parametrize(
    ("snippet", "where"),
    [
        (f"expires = {Q}", r"credential\[0\] \(a\)\.expires: must be a date"),
        (f"rotated = {Q}", r"credential\[0\] \(a\)\.rotated: must be a date"),
        (f"fp = {Q}", r"credential\[0\] \(a\)\.fp: must be 8 lower-case hex digits"),
        (f"owner = [{Q}]", r"credential\[0\] \(a\)\.owner: must be text"),
        (f"kept_because = {{ x = {Q} }}", r"\.kept_because: must be text"),
        (f"field = {Q}", r"\.field: must be a 1Password field label"),
        (f"value = {Q}", r"credential\[0\] \(a\): unknown field value"),
        (f"{Q} = 1", r"credential\[0\] \(a\): an unknown field"),
    ],
)
def test_a_bad_field_is_named_and_its_value_is_not_echoed(
    tmp_path: Path, snippet: str, where: str
) -> None:
    text = f'[[credential]]\nname = "a"\nkind = "generic"\nitem = "op://V/generic a"\n{snippet}\n'
    assert re.search(where, errors(tmp_path, text))


@pytest.mark.parametrize(
    ("line", "where"),
    [
        (f"name = {Q}", r"credential\[0\]\.name: must be lower-case letters"),
        (f"kind = {Q}", r"credential\[0\] \(a\)\.kind: must be one of"),
        (f"item = {Q}", r"\.item: must be op://<vault>/<item>"),
        ('item = "op://V/item/field"', r"\.item: must be op://<vault>/<item>"),
    ],
)
def test_bad_required_fields(tmp_path: Path, line: str, where: str) -> None:
    fields = {"name": 'name = "a"', "kind": 'kind = "generic"', "item": 'item = "op://V/i"'}
    fields[line.split(" ")[0]] = line
    text = "[[credential]]\n" + "\n".join(fields.values()) + "\n"
    assert re.search(where, errors(tmp_path, text))


def test_missing_required_fields_are_each_named(tmp_path: Path) -> None:
    message = errors(tmp_path, '[[credential]]\nowner = "x"\n')
    for f in ("name", "kind", "item"):
        assert f"credential[0].{f}: missing" in message


def test_duplicate_names(tmp_path: Path) -> None:
    one = '[[credential]]\nname = "a"\nkind = "generic"\nitem = "op://V/i"\n'
    assert "credential[1] (a).name: also used by credential[0]" in errors(tmp_path, one + one)


@pytest.mark.parametrize(
    ("target", "where"),
    [
        (f"type = {Q}", r"target\[0\]\.type: must be one of"),
        ('type = "railway"\nservice = "s"', r"target\[0\]\.environment: missing"),
        ('type = "github-actions"\nrepo = "o/r"', r"target\[0\]\.secret: missing"),
        (
            f'type = "github-actions"\nrepo = "o/r"\nsecret = "S"\nbody = {Q}',
            r"target\[0\]: unknown field body",
        ),
        (
            f'type = "github-actions"\nrepo = "o/r"\nsecret = [{Q}]',
            r"target\[0\]\.secret: must be text",
        ),
        (
            f'type = "gcp-secret"\nproject = "p"\nsecret = "s"\nverify = {Q}',
            r"target\[0\]\.verify: must be a table",
        ),
    ],
)
def test_bad_targets(tmp_path: Path, target: str, where: str) -> None:
    text = (
        '[[credential]]\nname = "a"\nkind = "generic"\nitem = "op://V/i"\n'
        f"[[credential.target]]\n{target}\n"
    )
    assert re.search(where, errors(tmp_path, text))


def test_unknown_top_level_and_bad_budget(tmp_path: Path) -> None:
    assert ": unknown field secrets" in errors(tmp_path, f"secrets = {Q}\n")
    assert "kept_budget: must be a whole number" in errors(tmp_path, f"kept_budget = {Q}\n")


def test_every_error_is_reported_at_once(tmp_path: Path) -> None:
    message = errors(tmp_path, '[[credential]]\nname = "a"\n[[credential]]\nname = "b"\n')
    assert message.count("missing") == 4
