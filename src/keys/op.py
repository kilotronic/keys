"""The one place keys talks to 1Password: the `op` command line, signed in on the owner's Mac.

Values come back on op's stdout, captured here, and go to op only on stdin as item JSON. op's
own error text is never shown: it can name what it was handling. Tests swap op for a fake.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, cast

from keys import proc
from keys.secret import Secret


class OpError(Exception):
    """op failed; the message names the step and op's exit code only."""


class Op:
    def __init__(self, environ: Mapping[str, str]) -> None:
        self.environ = environ

    def _run(self, what: str, argv: list[str], stdin: str | None = None) -> str:
        try:
            done = proc.run(argv, proc.child_env(self.environ, ("OP_",)), stdin=stdin)
        except proc.ChildError as e:
            raise OpError(f"1Password CLI: {e}") from None
        if done.code != 0:
            raise OpError(f"op exited {done.code} {what}")
        return done.stdout

    def read(self, ref: str) -> Secret:
        """The value at an op:// secret reference."""
        return Secret(self._run("reading a value", ["op", "read", "--no-newline", ref]))

    def item_titles(self, vault: str) -> list[str]:
        """The titles of the items in vault (op lists no field values)."""
        out = self._run(
            "listing items", ["op", "item", "list", "--vault", vault, "--format", "json"]
        )
        try:
            items = cast(list[dict[str, Any]], json.loads(out or "[]"))
        except ValueError:
            raise OpError("op item list printed something keys cannot read") from None
        return [str(i.get("title", "")) for i in items]

    def item_create(self, vault: str, item: dict[str, Any]) -> None:
        """A new item, from JSON on stdin, never field=value arguments."""
        self._run(
            "creating the item",
            ["op", "item", "create", "--vault", vault, "-"],
            stdin=json.dumps(item),
        )

    def items_tagged(self, tag: str) -> list[dict[str, str]]:
        """Each item with tag: its vault, title and last update (op lists no field values)."""
        out = self._run("listing items", ["op", "item", "list", "--tags", tag, "--format", "json"])
        try:
            items = cast(list[dict[str, Any]], json.loads(out or "[]"))
        except ValueError:
            raise OpError("op item list printed something keys cannot read") from None
        rows: list[dict[str, str]] = []
        for i in items:
            vault = cast(dict[str, Any], i.get("vault") or {})
            rows.append(
                {
                    "vault": str(vault.get("name", "")),
                    "title": str(i.get("title", "")),
                    "updated_at": str(i.get("updated_at", "")),
                }
            )
        return rows

    def item_get(self, vault: str, title: str) -> dict[str, Any]:
        """The item, fields and values, parsed in process (op's JSON holds concealed values;
        nothing of it is ever printed)."""
        out = self._run(
            "reading the item", ["op", "item", "get", title, "--vault", vault, "--format", "json"]
        )
        try:
            item = json.loads(out)
        except ValueError:
            raise OpError("op item get printed something keys cannot read") from None
        if not isinstance(item, dict):
            raise OpError("op item get printed something keys cannot read")
        found = cast(dict[str, Any], item)
        if not isinstance(found.get("fields"), list):
            raise OpError("op item get printed something keys cannot read")
        return found

    def item_edit(self, vault: str, item: dict[str, Any]) -> None:
        """The item replaced by item, sent as JSON on stdin (never field=value arguments)."""
        self._run(
            "saving the item",
            ["op", "item", "edit", str(item["id"]), "--vault", vault],
            stdin=json.dumps(item),
        )


def fields(item: dict[str, Any]) -> dict[str, str]:
    """An item's fields, label to value."""
    out: dict[str, str] = {}
    for f in cast(list[Any], item.get("fields", [])):
        if isinstance(f, dict):
            d = cast(dict[str, Any], f)
            out[str(d.get("label", ""))] = str(d.get("value") or "")
    return out


def set_fields(item: dict[str, Any], values: dict[str, str], concealed: set[str]) -> None:
    """Set each field of item by label, adding a missing one (concealed when named so)."""
    rows = cast(list[dict[str, Any]], item["fields"])
    by_label = {str(f.get("label", "")): f for f in rows}
    for label, value in values.items():
        if label in by_label:
            by_label[label]["value"] = value
            if label in concealed:  # a field made by hand as plain text holds a key concealed
                by_label[label]["type"] = "CONCEALED"
        else:
            kind = "CONCEALED" if label in concealed else "STRING"
            row = {"id": label, "label": label, "type": kind, "value": value}
            rows.append(row)
            by_label[label] = row
