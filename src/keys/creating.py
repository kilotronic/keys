"""keys new <kind> <name>: an empty 1Password item for a credential, and its mapping entry.

The item is an API Credential titled `<kind> <name>`, tagged `keys` and the kind, with an empty
concealed `credential` field for the value and the kind's other (non-secret) fields, also empty.
It goes to op as JSON on stdin. The owner then pastes the first value into that item in the
1Password app, never into a terminal or a chat.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
import tomllib
from pathlib import Path
from typing import Any

from keys import listing, looks, mapping
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
    p.add_argument(
        "--entry-only",
        action="store_true",
        help="the item is already in 1Password: add only the mapping entry",
    )
    listing.add_mapping_flag(p)


def _toml(text: str) -> str:
    # A JSON string is a TOML basic string; ASCII-only escapes every character TOML forbids raw.
    return json.dumps(text, ensure_ascii=True)


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


OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,63}")


def _refuse_value(flag: str, text: str) -> None:
    """Text bound for the mapping file (a committed file) or the screen must not look like a
    value pasted into the wrong flag. The text is never repeated back."""
    if looks.unprintable(text):
        raise UsageError(f"{flag} holds a control or unprintable character")
    if looks.looks_like_value(text):
        raise UsageError(f"{flag} holds something shaped like a key; nothing was made")


def run(args: argparse.Namespace, ctx: Context) -> int:
    kind: str = args.kind
    name: str = args.name
    vault: str = args.vault
    reason: str = args.kept_because
    owner: str | None = args.owner
    _refuse_value("the name", name)
    if looks.name_looks_like_value(name):
        raise UsageError("the name looks like a value; give it a short descriptive name")
    if not mapping.NAME.fullmatch(name):
        raise UsageError("the name must be lower-case letters, digits and dashes")
    _refuse_value("--vault", vault)
    if not VAULT.fullmatch(vault):
        raise UsageError("that is not a vault name keys accepts (letters, digits, - _ . space)")
    _refuse_value("--kept-because", reason)
    if not reason.strip():
        raise UsageError("--kept-because must say why the credential cannot be removed yet")
    if owner is not None:
        _refuse_value("--owner", owner)
        if not OWNER.fullmatch(owner):
            raise UsageError("--owner takes a handle: letters, digits, . _ @ -")

    path, shown = listing.mapping_path(args, ctx)
    path = path.resolve() if path.is_symlink() else path  # write through a link, not over it
    title = f"{kind} {name}"
    if path.exists():
        before = path.read_text(encoding="utf-8")
        existing = mapping.load(path, shown)
        for c in existing.credentials:
            if c.name == name:
                raise UsageError(f"{name} is already in the mapping file")
            if c.item.casefold() == f"op://{vault}/{title}".casefold():
                raise UsageError(f"{c.name} already uses that item")
    elif args.mapping or ctx.environ.get("KEYS_MAPPING"):
        # Only ./keys.toml is ever created: a path given by flag or environment could be a value.
        raise UsageError(f"{shown} does not exist; keys creates only ./keys.toml")
    else:
        before = ""

    def new_text(item_title: str) -> str:
        entry = ["[[credential]]", f"name = {_toml(name)}", f"kind = {_toml(kind)}"]
        entry.append(f"item = {_toml(f'op://{vault}/{item_title}')}")
        if owner:
            entry.append(f"owner = {_toml(owner)}")
        entry.append(f"kept_because = {_toml(reason)}")
        text = before + ("" if not before or before.endswith("\n") else "\n")
        return text + ("\n" if before else "") + "\n".join(entry) + "\n"

    try:
        mapping.parse(tomllib.loads(new_text(title)), path)  # it must load, before op is touched
    except (tomllib.TOMLDecodeError, mapping.MappingError):
        raise UsageError("the new mapping entry would not load; nothing was made") from None

    op = Op(ctx.environ)
    try:
        found = {t.casefold(): t for t in op.item_titles(vault)}
        real_title = found.get(title.casefold())
        if args.entry_only and real_title is None:
            raise UsageError(f"that vault has no item named {title}")
        if not args.entry_only:
            if real_title is not None:
                raise UsageError(f"that vault already has an item named {title}")
            try:
                op.item_create(vault, item_json(kind, name))
            except OpError as e:
                if title.casefold() in {t.casefold() for t in op.item_titles(vault)}:
                    raise UsageError(
                        f"{e}, but the item is in 1Password; rerun with --entry-only to add "
                        "its mapping entry"
                    ) from None
                raise
            real_title = title
    except OpError as e:
        raise UsageError(str(e)) from None
    text = new_text(real_title or title)

    made = "found" if args.entry_only else "made"
    now = path.read_text(encoding="utf-8") if path.exists() else ""
    if now != before:
        raise UsageError(
            f"{made} the 1Password item {title}, but the mapping file changed while 1Password "
            "was asked; rerun with --entry-only to add its entry"
        )
    try:
        _replace(path, text)
    except OSError as e:
        raise UsageError(
            f"{made} the 1Password item {title}, but could not add it to the mapping file "
            f"({type(e).__name__}); rerun with --entry-only"
        ) from None
    ctx.say(f"{made} the 1Password item {title}, and added {name} to the mapping file")
    if not args.entry_only:
        ctx.say(
            f"next: paste the value into its {VALUE_FIELD} field in the 1Password app (never a "
            "terminal or a chat)"
        )
    return EXIT_OK


def _replace(path: Path, text: str) -> None:
    """The mapping file, replaced whole: written beside it under a fresh name, then moved over
    it, keeping its permissions, and the folder synced so the move survives a power cut."""
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".keys-new")
    tmp = Path(name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        folder = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(folder)
        finally:
            os.close(folder)
    finally:
        tmp.unlink(missing_ok=True)
