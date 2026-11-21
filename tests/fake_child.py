"""A stand-in for op, gh and the other programs keys starts, for the canary harness.

It records how it was started (program and argv) in KEYS_FAKE_LOG before doing anything else,
then what was piped to it, and answers from KEYS_FAKE_DB, which the harness writes. Only
`op read`, `op item list` and `op item create` have answers; anything else exits 64, so a test
notices a call it did not expect.

op reads its stdin only when given `-`, as the real one does; the other fakes read whatever is
piped to them within a moment, so a test can see what reached, say, the clipboard.
"""

from __future__ import annotations

import json
import os
import select
import sys
import uuid
from typing import Any

# op flags that take a value, so the value is not mistaken for a word.
OP_VALUE_FLAGS = {
    "--account",
    "--vault",
    "--format",
    "--tags",
    "--categories",
    "--fields",
    "--template",
    "--out-file",
    "--session",
    "--config",
}


def _log(row: dict[str, Any]) -> None:
    with open(os.environ["KEYS_FAKE_LOG"], "a", encoding="utf-8") as log:
        log.write(json.dumps(row) + "\n")


def _read_stdin(wait: float) -> str:
    if sys.stdin.isatty():
        return ""
    ready, _, _ = select.select([sys.stdin], [], [], wait)
    return sys.stdin.read() if ready else ""


def words_and_flags(argv: list[str]) -> tuple[list[str], dict[str, str | bool]]:
    words: list[str] = []
    flags: dict[str, str | bool] = {}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "-":
            words.append(a)
        elif a.startswith("--") and "=" in a:
            k, _, v = a.partition("=")
            flags[k] = v
        elif a in OP_VALUE_FLAGS and i + 1 < len(argv):
            flags[a] = argv[i + 1]
            i += 1
        elif a.startswith("-"):
            flags[a] = True
        else:
            words.append(a)
        i += 1
    return words, flags


def main(prog: str, argv: list[str]) -> int:
    me = uuid.uuid4().hex
    _log({"id": me, "prog": prog, "argv": [prog, *argv]})
    words, flags = words_and_flags(argv)
    stdin = ""
    if prog != "op" or "-" in words:
        stdin = _read_stdin(2.0 if "-" in words else 0.5)
        _log({"id": me, "stdin": stdin})
    with open(os.environ["KEYS_FAKE_DB"], encoding="utf-8") as f:
        db: dict[str, Any] = json.load(f)
    if prog != "op":
        print(f"fake {prog}: no answer for this call", file=sys.stderr)
        return 64
    if words[:1] == ["read"] and len(words) == 2:
        ref = words[1]
        if ref in db["fail"]:
            print(db["fail"][ref]["stderr"], file=sys.stderr)
            return int(db["fail"][ref]["code"])
        if ref not in db["values"]:
            print(f'[ERROR] could not read secret "{ref}": not found', file=sys.stderr)
            return 1
        value: str = db["values"][ref]
        no_newline = "--no-newline" in flags or "-n" in flags
        sys.stdout.write(value if no_newline else value + "\n")
        return 0
    if words[:2] == ["item", "list"]:
        lfail = db.get("list_fail")
        if lfail:
            print(lfail["stderr"], file=sys.stderr)
            return int(lfail["code"])
        vault = flags.get("--vault")
        items = [i for i in db["items"] if vault is None or i["vault"]["name"] == vault]
        print(json.dumps(items))
        return 0
    if words[:2] == ["item", "create"]:
        fail = db.get("create_fail")
        if fail and fail.get("saved"):
            item = json.loads(stdin)
            vault_name = flags.get("--vault")
            db["items"].append(
                {"id": "saved", "title": item["title"], "vault": {"name": vault_name}}
            )
            with open(os.environ["KEYS_FAKE_DB"], "w", encoding="utf-8") as out:
                json.dump(db, out)
        if fail:
            print(fail["stderr"], file=sys.stderr)
            return int(fail["code"])
        print(json.dumps({"id": "fakeitemid"}))
        return 0
    print("fake op: no answer for this call", file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2:]))
