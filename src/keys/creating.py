"""keys new <kind> <name>: an empty 1Password item for a credential, and its mapping entry.

The item is an API Credential titled `<kind> <name>`, tagged `keys` and the kind, with an empty
concealed `credential` field for the value and the kind's other (non-secret) fields, also empty.
It goes to op as JSON on stdin. The owner then pastes the first value into that item in the
1Password app, never into a terminal or a chat.
"""

from __future__ import annotations

import argparse
import json
import re
from typing import Any

from keys import listing, mapping
from keys.context import EXIT_OK, Context, UsageError
from keys.kinds import KINDS, VALUE_FIELD
from keys.op import Op, OpError

VAULT = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}")


def configure(p: argparse.ArgumentParser) -> None:
    p.add_argument("kind", choices=sorted(KINDS), help="the kind of credential")
    p.add_argument("name", help="its name: lower-case letters, digits and dashes")
    p.add_argument("--vault", required=True, help="the 1Password vault for the item")
    p.add_argument(
        "--kept-because", required=True, metavar="TEXT", help="why it cannot be removed yet"
    )
    p.add_argument("--owner", help="who owns it (optional)")
    listing.add_mapping_flag(p)


def _toml(text: str) -> str:
    # A JSON string is a valid TOML basic string.
    return json.dumps(text, ensure_ascii=False)


def item_json(kind: str, name: str) -> dict[str, Any]:
    fields: list[dict[str, str]] = [
        {
            "id": "notesPlain",
            "type": "STRING",
            "purpose": "NOTES",
            "label": "notesPlain",
            "value": f"Managed by keys. Paste the value into the {VALUE_FIELD} field.",
        },
        {"id": VALUE_FIELD, "type": "CONCEALED", "label": VALUE_FIELD, "value": ""},
    ]
    fields += [{"id": f, "type": "STRING", "label": f, "value": ""} for f in KINDS[kind].fields]
    return {
        "title": f"{kind} {name}",
        "category": "API_CREDENTIAL",
        "tags": ["keys", kind],
        "fields": fields,
    }


def run(args: argparse.Namespace, ctx: Context) -> int:
    kind: str = args.kind
    name: str = args.name
    vault: str = args.vault
    reason: str = args.kept_because
    if not mapping.NAME.fullmatch(name):
        raise UsageError("the name must be lower-case letters, digits and dashes")
    if not VAULT.fullmatch(vault):
        raise UsageError("that is not a vault name keys accepts (letters, digits, - _ . space)")
    if not reason.strip():
        raise UsageError("--kept-because must say why the credential cannot be removed yet")
    path, shown = listing.mapping_path(args, ctx)
    if path.exists():
        existing = mapping.load(path, shown)
        if any(c.name == name for c in existing.credentials):
            raise UsageError(f"{name} is already in the mapping file")
    title = f"{kind} {name}"
    op = Op(ctx.environ)
    try:
        if title in op.item_titles(vault):
            raise UsageError(f"the vault {vault} already has an item named {title}")
        op.item_create(vault, item_json(kind, name))
    except OpError as e:
        raise UsageError(str(e)) from None

    entry = [
        "",
        "[[credential]]",
        f"name = {_toml(name)}",
        f"kind = {_toml(kind)}",
        f"item = {_toml(f'op://{vault}/{title}')}",
    ]
    if args.owner:
        entry.append(f"owner = {_toml(args.owner)}")
    entry.append(f"kept_because = {_toml(reason)}")
    before = path.read_text(encoding="utf-8") if path.exists() else ""
    text = "\n".join(entry[1:]) + "\n"
    if before:
        text = ("" if before.endswith("\n") else "\n") + "\n" + text
    try:
        with path.open("a", encoding="utf-8") as f:
            f.write(text)
    except OSError as e:
        raise UsageError(
            f"made the 1Password item {title}, but could not add it to the mapping file "
            f"({type(e).__name__}); add it by hand"
        ) from None
    mapping.load(path, shown)  # what was written must load
    ctx.say(f"made the 1Password item {title} in {vault}, and added {name} to the mapping file")
    ctx.say(
        f"next: paste the value into its {VALUE_FIELD} field in the 1Password app (never a "
        "terminal or a chat)"
    )
    return EXIT_OK
