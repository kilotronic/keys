"""A stand-in for op, gh and the other programs keys starts, for the canary harness.

It records how it was started (program and argv) in KEYS_FAKE_LOG before doing anything else,
then what was piped to it, and answers from KEYS_FAKE_DB, which the harness writes. Only
`op read`, `op item list` and `op item create` have answers, and for the targets keys syncs to:
`gh secret set|list`, `railway variable set|list`, `railway deployment list`, `railway redeploy`,
`az keyvault secret set|list` and `gcloud secrets create|versions add|update|list`. What a
target is given is kept in the fake DB under a key (see `target_key`), so a test can read back
exactly what each target received. Anything else exits 64, so a test notices a call it did not
expect. `child_fail` in the DB makes a call whose words start with given ones fail.

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
    # gh
    "--repo",
    "--env",
    "--org",
    "--visibility",
    "--repos",
    "--json",
    "--app",
    # railway
    "--service",
    "--environment",
    "--project",
    # az
    "--vault-name",
    "--name",
    "--file",
    "--query",
    "--output",
    "-o",
    # gcloud
    "--update-labels",
    "--labels",
    "--replication-policy",
}


def _log(row: dict[str, Any]) -> None:
    with open(os.environ["KEYS_FAKE_LOG"], "a", encoding="utf-8") as log:
        log.write(json.dumps(row) + "\n")


def _read_stdin(wait: float) -> str:
    if sys.stdin.isatty():
        return ""
    ready, _, _ = select.select([sys.stdin], [], [], wait)
    # Bytes, decoded as UTF-8: what keys sent, with no newline translation or locale.
    return sys.stdin.buffer.read().decode("utf-8", errors="replace") if ready else ""


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
        elif a.startswith("-") and a != "-":
            flags[a] = True
        else:
            words.append(a)
        i += 1
    return words, flags


def main(prog: str, argv: list[str]) -> int:
    me = uuid.uuid4().hex
    os.environ["KEYS_FAKE_ID"] = me
    _log({"id": me, "prog": prog, "argv": [prog, *argv], "env": sorted(os.environ)})
    words, flags = words_and_flags(argv)
    stdin = ""
    if prog != "op" or "-" in words:
        stdin = _read_stdin(2.0 if "-" in words else 0.5)
        _log({"id": me, "stdin": stdin})
    with open(os.environ["KEYS_FAKE_DB"], encoding="utf-8") as f:
        db: dict[str, Any] = json.load(f)
    for odd in db.get("child_print", []):
        if [prog, *words][: len(odd["words"])] == odd["words"]:
            print(odd["stdout"])
            return 0
    for fail in db.get("child_fail", []):
        if [prog, *words][: len(fail["words"])] == fail["words"]:
            print(fail.get("stderr", ""), file=sys.stderr)
            return int(fail["code"])
    if prog == "az" and words[:3] == ["keyvault", "secret", "show"]:
        return _az_show(db, argv)
    if prog != "op":
        code = targets(prog, words, flags, stdin, db)
        if code is None:
            print(f"fake {prog}: no answer for this call", file=sys.stderr)
            return 64
        _save(db)
        return code
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
        tag = flags.get("--tags")
        items = [i for i in db["items"] if vault is None or i["vault"]["name"] == vault]
        items = [i for i in items if tag is None or tag in i.get("tags", [])]
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
        item = json.loads(stdin)
        db["items"].append(
            {"id": "made", "title": item["title"], "vault": {"name": flags.get("--vault")}}
        )
        with open(os.environ["KEYS_FAKE_DB"], "w", encoding="utf-8") as out:
            json.dump(db, out)
        print(json.dumps({"id": "fakeitemid"}))
        return 0
    print("fake op: no answer for this call", file=sys.stderr)
    return 64


def _save(db: dict[str, Any]) -> None:
    with open(os.environ["KEYS_FAKE_DB"], "w", encoding="utf-8") as out:
        json.dump(db, out)


def _flag(flags: dict[str, str | bool], name: str) -> str:
    v = flags.get(name, "")
    return v if isinstance(v, str) else ""


def target_key(prog: str, flags: dict[str, str | bool], name: str) -> str:
    """Where the fake keeps what one target was given."""
    if prog == "gh":
        if _flag(flags, "--org"):
            return f"gh:org:{_flag(flags, '--org')}:{name}"
        env = _flag(flags, "--env")
        return f"gh:{_flag(flags, '--repo')}:" + (f"env:{env}:" if env else "") + name
    if prog == "railway":
        scope = [_flag(flags, f) for f in ("--project", "--service", "--environment")]
        return "railway:" + ":".join(scope) + f":{name}"
    if prog == "az":
        return f"az:{_flag(flags, '--vault-name')}:{name}"
    return f"gcp:{_flag(flags, '--project')}:{name}"


def _labels(text: str) -> dict[str, str]:
    return dict(p.split("=", 1) for p in text.split(",") if "=" in p)


def _put(db: dict[str, Any], key: str, value: str, **meta: Any) -> None:
    _log({"id": os.environ.get("KEYS_FAKE_ID", ""), "target": key})
    store: dict[str, Any] = db.setdefault("targets", {})
    db["clock"] = int(db.get("clock", 0)) + 1
    entry = store.setdefault(key, {})
    entry.update(value=value, updated_at=f"2026-11-21T00:00:{db['clock']:02d}Z", **meta)
    entry["writes"] = int(entry.get("writes", 0)) + 1


def _under(db: dict[str, Any], prefix: str) -> dict[str, dict[str, Any]]:
    store: dict[str, dict[str, Any]] = db.get("targets", {})
    return {
        k[len(prefix) :]: v
        for k, v in store.items()
        if k.startswith(prefix) and ":" not in k[len(prefix) :]
    }


def targets(
    prog: str, words: list[str], flags: dict[str, str | bool], stdin: str, db: dict[str, Any]
) -> int | None:
    w = [prog, *words]
    if w[:3] == ["gh", "secret", "set"] and len(w) == 4:
        meta = {"visibility": _flag(flags, "--visibility"), "repos": _flag(flags, "--repos")}
        # gh trims a value read from stdin of its trailing line breaks.
        _put(db, target_key("gh", flags, w[3]), stdin.rstrip("\r\n"), **meta)
        return 0
    if w[:3] == ["gh", "secret", "list"]:
        prefix = target_key("gh", flags, "")
        rows = [{"name": n, "updatedAt": v["updated_at"]} for n, v in _under(db, prefix).items()]
        print(json.dumps(rows))
        return 0
    if w[:3] == ["railway", "variable", "set"] and len(w) == 4 and "--stdin" in flags:
        _put(db, target_key("railway", flags, w[3]), stdin, skip_deploys="--skip-deploys" in flags)
        return 0
    if w[:3] == ["railway", "variable", "list"] and "--json" in flags:
        prefix = target_key("railway", flags, "")
        print(json.dumps({n: v["value"] for n, v in _under(db, prefix).items()}))
        return 0
    if w[:3] == ["railway", "deployment", "list"]:
        key = "deploys:" + target_key("railway", flags, "")
        first = [{"id": "d0", "status": "SUCCESS"}]
        history = db.setdefault("deploys", {}).setdefault(key, first)
        for d in history:  # a deployment in flight finishes after its number of looks
            if "polls" in d:
                d["polls"] -= 1
                if d["polls"] <= 0:
                    d["status"] = "SUCCESS"
                    del d["polls"]
        print(json.dumps(history))
        return 0
    if w[:2] == ["railway", "redeploy"]:
        key = "deploys:" + target_key("railway", flags, "")
        deploys: dict[str, list[dict[str, str]]] = db.setdefault("deploys", {})
        history = deploys.setdefault(key, [{"id": "d0", "status": "SUCCESS"}])
        history.insert(0, {"id": f"d{len(history)}", "status": db.get("deploy_status", "SUCCESS")})
        return 0
    if w[:4] == ["az", "keyvault", "secret", "set"] and _flag(flags, "--file") == "/dev/stdin":
        name = _flag(flags, "--name")
        # az reads the file in text mode, which folds a CR LF into LF.
        value = stdin.replace("\r\n", "\n")
        _put(db, target_key("az", flags, name), value, tags=_labels(_flag(flags, "--tags")))
        return 0
    if w[:4] == ["az", "keyvault", "secret", "list"]:
        vault = _flag(flags, "--vault-name")
        rows = [
            {
                "id": f"https://{vault}.vault.azure.net/secrets/{n}",
                "name": n,
                "tags": v.get("tags", {}),
                "attributes": {
                    "updated": v["updated_at"],
                    "enabled": v.get("enabled", True),
                    "expires": v.get("expires"),
                },
                "managed": v.get("managed"),
            }
            for n, v in _under(db, target_key("az", flags, "")).items()
        ]
        print(json.dumps(rows))
        return 0
    gcp = target_key("gcloud", flags, w[-1] if len(w) > 2 else "")
    if w[:4] == ["gcloud", "secrets", "versions", "add"] and _flag(flags, "--data-file") == "-":
        store: dict[str, Any] = db.get("targets", {})
        if gcp not in store:
            return 1  # Secret Manager needs the secret before a version
        _put(db, gcp, stdin, labels=store[gcp].get("labels", {}))
        return 0
    if w[:3] == ["gcloud", "secrets", "create"] and _flag(flags, "--data-file") == "-":
        _put(db, gcp, stdin, labels=_labels(_flag(flags, "--labels")))
        return 0
    if w[:3] == ["gcloud", "secrets", "update"]:
        store = db.get("targets", {})
        if gcp not in store:
            return 1
        store[gcp].setdefault("labels", {}).update(_labels(_flag(flags, "--update-labels")))
        return 0
    if w[:3] == ["gcloud", "secrets", "list"]:
        rows = [
            {"name": f"projects/123/secrets/{n}", "labels": v.get("labels", {})}
            for n, v in _under(db, target_key("gcloud", flags, "")).items()
        ]
        print(json.dumps(rows))
        return 0
    return None


def _az_show(db: dict[str, Any], argv: list[str]) -> int:
    """`az keyvault secret show --vault-name V --name N --query value --output json|tsv`: the
    value as az prints it (a JSON string, or null; or the text and a newline), from the values
    the harness set for kv://V/N."""
    flags = dict(zip(argv[3::2], argv[4::2], strict=False))
    ref = f"kv://{flags.get('--vault-name')}/{flags.get('--name')}"
    if ref in db["fail"]:
        sys.stdout.write(db["fail"][ref].get("stdout", ""))
        print(db["fail"][ref]["stderr"], file=sys.stderr)
        return int(db["fail"][ref]["code"])
    if ref not in db["values"] or flags.get("--query") != "value":
        print("fake az: (SecretNotFound) not found", file=sys.stderr)
        return 3
    if flags.get("--output") == "json":
        print(json.dumps(db["values"][ref], indent=2))
    else:
        sys.stdout.write(f"{db['values'][ref]}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2:]))
