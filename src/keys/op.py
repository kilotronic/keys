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
