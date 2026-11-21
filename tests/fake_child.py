"""A stand-in for op, gh and the other programs keys starts, for the canary harness.

It records how it was started (program, argv, stdin) in KEYS_FAKE_LOG, and answers from
KEYS_FAKE_DB, which the harness writes. Only `op read`, `op item list` and `op item create` have
answers; anything else exits 64, so a test notices a call it did not expect.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any


def main(prog: str, argv: list[str]) -> int:
    stdin = "" if sys.stdin.isatty() else sys.stdin.read()
    with open(os.environ["KEYS_FAKE_LOG"], "a", encoding="utf-8") as log:
        log.write(json.dumps({"prog": prog, "argv": [prog, *argv], "stdin": stdin}) + "\n")
    with open(os.environ["KEYS_FAKE_DB"], encoding="utf-8") as f:
        db: dict[str, Any] = json.load(f)
    if prog != "op":
        print(f"fake {prog}: no answer for this call", file=sys.stderr)
        return 64
    words = [a for a in argv if not a.startswith("--")]
    if words[:1] == ["read"] and len(words) == 2:
        ref = words[1]
        if ref in db["fail"]:
            print(db["fail"][ref]["stderr"], file=sys.stderr)
            return int(db["fail"][ref]["code"])
        if ref not in db["values"]:
            print(f'[ERROR] could not read secret "{ref}": not found', file=sys.stderr)
            return 1
        value: str = db["values"][ref]
        sys.stdout.write(value if "--no-newline" in argv else value + "\n")
        return 0
    if words[:2] == ["item", "list"]:
        vault = argv[argv.index("--vault") + 1] if "--vault" in argv else None
        items = [i for i in db["items"] if vault is None or i["vault"]["name"] == vault]
        print(json.dumps(items))
        return 0
    if words[:2] == ["item", "create"]:
        fail = db.get("create_fail")
        if fail:
            print(fail["stderr"], file=sys.stderr)
            return int(fail["code"])
        print(json.dumps({"id": "fakeitemid"}))
        return 0
    print("fake op: no answer for this call", file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2:]))
