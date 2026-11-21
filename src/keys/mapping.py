"""The mapping file: every credential, its 1Password item and its targets. Never a value.

    kept_budget = 3                       # optional: most kept credentials allowed

    [[credential]]
    name = "app-resend"
    kind = "generic"                      # see keys.kinds
    item = "op://<vault>/<item title>"    # vault and item, no field
    field = "credential"                  # optional: the item's value field
    owner = "owner"                       # optional
    kept_because = "why it cannot be removed yet"
    fp = "1a2b3c4d"                       # keyed fingerprint, written by keys rotate
    rotated = 2026-11-21
    expires = 2027-05-20

    [[credential.target]]
    type = "railway"
    service = "app"
    environment = "production"
    variable = "RESEND_API_KEY"
    verify = { health = "production" }

A validation error names the field (`credential[0] (app-resend).expires: must be a date`) and
never repeats what the field held: a value pasted into the wrong place would be printed back.
"""

from __future__ import annotations

import dataclasses
import datetime
import re
import tomllib
from collections.abc import Iterable
from collections.abc import Mapping as AnyMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from keys import looks
from keys.kinds import KINDS, VALUE_FIELD

NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
FP = re.compile(r"^[0-9a-f]{8}$")
LABEL = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_ .-]{0,63}$")
ITEM = re.compile(r"^op://([^/]+)/([^/]+)$")

TOP_FIELDS = {"credential", "kept_budget", "ignore_unmapped"}
SECRET_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,254}$")
CREDENTIAL_FIELDS = {
    "name",
    "kind",
    "item",
    "field",
    "owner",
    "kept_because",
    "fp",
    "rotated",
    "expires",
    "target",
    "minted_by",
    "permissions",
}
# A GitHub token's permission levels, as its pre-filled creation page takes them.
LEVELS = {"read", "write", "admin"}
# Target type: (required fields, optional fields), besides `type` and `verify`.
TARGETS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "github-actions": (("repo", "secret"), ()),
    "github-actions-env": (("repo", "environment", "secret"), ()),
    "github-actions-org": (("org", "secret"), ("repos", "visibility")),
    "railway": (("service", "environment", "variable"), ("project",)),
    "azure-key-vault": (("vault", "secret"), ()),
    "gcp-secret": (("project", "secret"), ()),
}


class MappingError(Exception):
    """One line per problem, each naming a field, never its content."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("\n".join(problems))
        self.problems = problems


@dataclass(frozen=True)
class Target:
    type: str
    fields: dict[str, str | list[str]]
    verify: dict[str, str]


@dataclass(frozen=True)
class Credential:
    name: str
    kind: str
    vault: str
    item_title: str
    field: str = VALUE_FIELD
    owner: str = ""
    kept_because: str = ""
    fp: str = ""
    rotated: datetime.date | None = None
    expires: datetime.date | None = None
    targets: list[Target] = dataclasses.field(default_factory=lambda: list[Target]())
    minted_by: str = ""  # the credential (by name) whose key mints this one
    permissions: dict[str, str] = dataclasses.field(default_factory=lambda: dict[str, str]())

    @property
    def item(self) -> str:
        return f"op://{self.vault}/{self.item_title}"

    @property
    def value_ref(self) -> str:
        """The secret reference `op read` takes for this credential's value."""
        return f"{self.item}/{self.field}"


@dataclass(frozen=True)
class Mapping:
    path: Path
    credentials: list[Credential]
    kept_budget: int | None = None
    # Secret names at a mapped scope that are not credentials (keys check --all names the rest).
    ignore_unmapped: tuple[str, ...] = ()


def _distance(a: str, b: str) -> int:
    row = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        prev, row[0] = row[0], i
        for j, cb in enumerate(b, 1):
            prev, row[j] = row[j], min(row[j] + 1, row[j - 1] + 1, prev + (ca != cb))
    return row[-1]


def _unknown(where: str, key: str, known: Iterable[str]) -> str:
    # A value pasted as a key would be printed back, and many keys look like field names; so
    # name the key only when it is a near miss of a real field (a typo).
    near = looks.plain_key(key) and any(_distance(key, k) <= 2 for k in known)
    return f"{where}: unknown field {key}" if near else f"{where}: an unknown field"


def _text(where: str, value: object, problems: list[str]) -> str:
    if isinstance(value, str):
        return value
    problems.append(f"{where}: must be text")
    return ""


def _date(where: str, value: object, problems: list[str]) -> datetime.date | None:
    if isinstance(value, datetime.date) and not isinstance(value, datetime.datetime):
        return value
    problems.append(f"{where}: must be a date (YYYY-MM-DD, unquoted)")
    return None


def _target(where: str, raw: object, problems: list[str]) -> Target | None:
    if not isinstance(raw, dict):
        problems.append(f"{where}: must be a table")
        return None
    t = cast(dict[str, Any], raw)
    kind = t.get("type")
    if not isinstance(kind, str) or kind not in TARGETS:
        problems.append(f"{where}.type: must be one of {', '.join(TARGETS)}")
        return None
    required, optional = TARGETS[kind]
    allowed = {"type", "verify", *required, *optional}
    fields: dict[str, str | list[str]] = {}
    for key in t:
        if key not in allowed:
            problems.append(_unknown(where, key, allowed))
    for key in required:
        if key not in t:
            problems.append(f"{where}.{key}: missing")
        else:
            fields[key] = _text(f"{where}.{key}", t[key], problems)
    for key in optional:
        if key not in t:
            continue
        value = t[key]
        if key == "repos":
            items = cast(list[object], value) if isinstance(value, list) else None
            if items is None or not all(isinstance(r, str) for r in items):
                problems.append(f"{where}.{key}: must be a list of text")
            else:
                fields[key] = [cast(str, r) for r in items]
        else:
            fields[key] = _text(f"{where}.{key}", value, problems)
    verify: dict[str, str] = {}
    if "verify" in t:
        if not isinstance(t["verify"], dict):
            problems.append(f"{where}.verify: must be a table")
        else:
            for k, v in cast(dict[str, object], t["verify"]).items():
                if not looks.plain_key(k):
                    problems.append(f"{where}.verify: a key that is not a plain name")
                elif isinstance(v, str):
                    verify[k] = v
                else:
                    problems.append(f"{where}.verify: each value must be text")
    return Target(kind, fields, verify)


def _credential(
    i: int, raw: object, seen: dict[str, int], problems: list[str]
) -> Credential | None:
    where = f"credential[{i}]"
    if not isinstance(raw, dict):
        problems.append(f"{where}: must be a table ([[credential]])")
        return None
    c = cast(dict[str, Any], raw)
    before = len(problems)

    name = c.get("name")
    if name is None:
        problems.append(f"{where}.name: missing")
    elif not isinstance(name, str) or not NAME.fullmatch(name):
        problems.append(f"{where}.name: must be lower-case letters, digits and dashes")
        name = None
    elif looks.name_looks_like_value(name):
        # Never repeated back: a value pasted as a name would be printed in every error.
        problems.append(f"{where}.name: looks like a value; give it a short descriptive name")
        name = None
    else:
        where = f"{where} ({name})"
        if name in seen:
            problems.append(f"{where}.name: also used by credential[{seen[name]}]")
        else:
            seen[name] = i

    for key in c:
        if key not in CREDENTIAL_FIELDS:
            problems.append(_unknown(where, key, CREDENTIAL_FIELDS))

    kind = c.get("kind")
    if kind is None:
        problems.append(
            f"credential[{i}].kind: missing" if name is None else f"{where}.kind: missing"
        )
    elif not isinstance(kind, str) or kind not in KINDS:
        problems.append(f"{where}.kind: must be one of {', '.join(KINDS)}")

    vault = title = ""
    item = c.get("item")
    if item is None:
        problems.append(f"{where}.item: missing")
    else:
        m = ITEM.fullmatch(item) if isinstance(item, str) else None
        if m is None:
            problems.append(f"{where}.item: must be op://<vault>/<item>, with no field")
        else:
            vault, title = m.group(1), m.group(2)

    value_field = VALUE_FIELD
    if "field" in c:
        value_field = _text(f"{where}.field", c["field"], problems)
        if value_field and not LABEL.fullmatch(value_field):
            problems.append(f"{where}.field: must be a 1Password field label")
    owner = _text(f"{where}.owner", c["owner"], problems) if "owner" in c else ""
    kept = (
        _text(f"{where}.kept_because", c["kept_because"], problems) if "kept_because" in c else ""
    )
    fp = ""
    if "fp" in c:
        fp = c["fp"] if isinstance(c["fp"], str) else ""
        if not FP.fullmatch(fp):
            problems.append(f"{where}.fp: must be 8 lower-case hex digits")
    rotated = _date(f"{where}.rotated", c["rotated"], problems) if "rotated" in c else None
    minted_by = ""
    if "minted_by" in c:
        minted_by = c["minted_by"] if isinstance(c["minted_by"], str) else ""
        if not NAME.fullmatch(minted_by) or looks.name_looks_like_value(minted_by):
            problems.append(f"{where}.minted_by: must be another credential's name")
    permissions: dict[str, str] = {}
    if "permissions" in c:
        if not isinstance(c["permissions"], dict):
            problems.append(f'{where}.permissions: must be a table, like {{ contents = "read" }}')
        else:
            for k, v in cast(dict[str, object], c["permissions"]).items():
                if not looks.plain_key(k):
                    problems.append(f"{where}.permissions: a key that is not a plain name")
                elif v not in LEVELS:
                    problems.append(f"{where}.permissions: each must be read, write or admin")
                else:
                    permissions[k] = cast(str, v)
    expires = _date(f"{where}.expires", c["expires"], problems) if "expires" in c else None

    targets: list[Target] = []
    raw_targets: object = c.get("target", [])
    if not isinstance(raw_targets, list):
        problems.append(f"{where}.target: must be [[credential.target]] tables")
    else:
        for j, rt in enumerate(cast(list[object], raw_targets)):
            t = _target(f"{where}.target[{j}]", rt, problems)
            if t:
                targets.append(t)

    if len(problems) > before or not isinstance(name, str) or not isinstance(kind, str):
        return None
    return Credential(
        name=name,
        kind=kind,
        vault=vault,
        item_title=title,
        field=value_field,
        owner=owner,
        kept_because=kept,
        fp=fp,
        rotated=rotated,
        expires=expires,
        targets=targets,
        minted_by=minted_by,
        permissions=permissions,
    )


def parse(doc: AnyMapping[str, Any], path: Path) -> Mapping:
    problems: list[str] = []
    for key in doc:
        if key not in TOP_FIELDS:
            problems.append(_unknown("mapping file", key, TOP_FIELDS))
    budget = doc.get("kept_budget")
    if budget is not None and (type(budget) is not int or budget < 0):
        problems.append("kept_budget: must be a whole number, 0 or more")
        budget = None
    ignore: list[str] = []
    raw_ignore: object = doc.get("ignore_unmapped", [])
    items = cast(list[object], raw_ignore) if isinstance(raw_ignore, list) else None
    if items is None or not all(
        isinstance(n, str) and SECRET_NAME.fullmatch(n) and not looks.looks_like_value(n)
        for n in items
    ):
        problems.append("ignore_unmapped: must be a list of secret names")
    else:
        ignore = [cast(str, n) for n in items]
    raw: object = doc.get("credential", [])
    credentials: list[Credential] = []
    if not isinstance(raw, list):
        problems.append("credential: must be [[credential]] tables")
    else:
        seen: dict[str, int] = {}
        for i, rc in enumerate(cast(list[object], raw)):
            c = _credential(i, rc, seen, problems)
            if c:
                credentials.append(c)
    if problems:
        raise MappingError(problems)
    return Mapping(path, credentials, budget, tuple(ignore))


def load(path: Path, shown: str | None = None) -> Mapping:
    """The mapping file at path. Errors call it `shown` (default: the path itself), since a
    path typed or set by the owner could be a value pasted into the wrong place."""
    name = shown or str(path)
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        raise MappingError([f"no mapping file at {name}"]) from None
    except OSError as e:
        raise MappingError([f"cannot read {name} ({type(e).__name__})"]) from None
    try:
        doc = tomllib.loads(data.decode("utf-8"))
    except UnicodeDecodeError:
        raise MappingError([f"{name}: not UTF-8 text"]) from None
    except tomllib.TOMLDecodeError as e:
        # The decoder's message can quote the text it choked on; keep only where.
        m = re.search(r"line (\d+), column (\d+)", str(e))
        at = f" at line {m.group(1)}, column {m.group(2)}" if m else ""
        raise MappingError([f"{name}: not valid TOML{at}"]) from None
    return parse(doc, path)
