"""The canary harness (`keys-canary`): run a keys command with a planted fake value, and fail if
the value shows up anywhere it should not.

What it watches, for `run`/`call` (in this process) and `shell` (a real interactive zsh):

- stdout and stderr: the context's streams, Python's, and file descriptors 1 and 2, so a child
  that inherits the terminal is caught too;
- the text of any exception that escapes (which also fails the test on its own);
- every child process, recorded when it starts by an audit hook (`canary_hook.py`): its argv
  and environment must not hold the value, and its program must be one of the harness's fakes
  on PATH; data piped to a child is allowed only for 1Password's item writes and each target's
  write command (`gh secret set`, `railway variable set`, `az keyvault secret set`,
  `gcloud secrets versions add` and `gcloud secrets create`);
- every file opened for writing: none may be under the temp folder or outside the temporary home
  and working folder, and after the run no file there may hold the value, unless the test
  planted it and it is unchanged;
- for `shell`, the zsh history file, written by an interactive shell that read the command.

The value is searched for as sent and in the forms a leak usually takes: base64 (padded or not,
URL-safe, shifted inside a longer encoded string as Basic auth does, and wrapped across lines),
hex, URL encoding (either case of escape), JSON escaping, its unkeyed SHA-256, SHA-1 and MD5,
any 9-character piece, and any 12-character piece of an encoded form. A hint (first 8 and last
4) is allowed only when the test says the value is provider-issued, as keys prints one only then.

Every value here is made up. Nothing in this harness touches a real 1Password or a real service.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import traceback
from collections.abc import Callable, Generator, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote, quote_plus

import pytest

from keys import cli
from tests import canary_hook

# Made up. Holds + / = " \ ~ ? and a space so that every encoding below differs from the raw form,
# and its base64 holds + and / at every alignment, so URL-safe base64 differs too.
CANARY = 'kc_7Qm~?~Xv+/Lr2 "J8\\pW=3n~?~?Tb5Hz9Ys4Ue6Kd'
PIECE = 9  # a run of this many of the value's characters is a leak (the hint shows 8)
ENCODED_PIECE = 12
HERE = Path(__file__).parent
FAKE_CHILD = HERE / "fake_child.py"
FAKE_PROGRAMS = ("op", "gh", "railway", "az", "gcloud", "security", "pbcopy", "open")
# The only children that may be handed a value on stdin: 1Password's item writes and each
# target's write command, matched on their leading words (so `az keyvault secret show` is not).
STDIN_OK = (
    ("op", "item", "create"),
    ("op", "item", "edit"),
    ("gh", "secret", "set"),
    ("railway", "variable", "set"),
    ("az", "keyvault", "secret", "set"),
    ("gcloud", "secrets", "versions", "add"),
    ("gcloud", "secrets", "create"),
)


# A write that would print what it sends (debug, verbose or HTTP logging) is never allowed one.
NOISY_FLAGS = ("--debug", "--verbose", "--verbosity", "--log-http", "--trace")


def stdin_ok(argv: Sequence[str]) -> bool:
    if any(a.split("=", 1)[0] in NOISY_FLAGS for a in argv):
        return False
    words = tuple(a for a in argv if not a.startswith("-"))
    return any(words[: len(ok)] == ok for ok in STDIN_OK)


ITEM_WRITES = STDIN_OK[:2]  # op item create and edit take item JSON, checked like any channel


class LeakError(AssertionError):
    """The planted value reached a channel it must never reach."""


def _lower_escapes(text: str) -> str:
    return re.sub(r"%[0-9A-F]{2}", lambda m: m.group().lower(), text)


def forms(value: str, *, hint_ok: bool = False) -> dict[str, bytes]:
    """The value as sent and in each encoded form a leak usually takes, by name."""
    raw = value.encode()
    out: dict[str, bytes] = {
        "raw": raw,
        "hex": raw.hex().encode(),
        "hex-upper": raw.hex().upper().encode(),
        "url": quote(value, safe="").encode(),
        "url-lower": _lower_escapes(quote(value, safe="")).encode(),
        "url-path": quote(value).encode(),
        "url-plus": quote_plus(value).encode(),
        "url-plus-lower": _lower_escapes(quote_plus(value)).encode(),
        "json": json.dumps(value)[1:-1].encode(),
        "json-ascii": json.dumps(value, ensure_ascii=True)[1:-1].encode(),
        "repr": repr(value)[1:-1].encode(),
    }
    for shift in range(3):
        # The characters that depend only on the value, whatever came before or after it.
        start = (shift * 8 + 5) // 6
        for name, enc in (("base64", base64.b64encode), ("base64-url", base64.urlsafe_b64encode)):
            text = enc(b"\0" * shift + raw).rstrip(b"=")
            out[f"{name}-shift{shift}"] = text[start : len(text) - 2]
    out["sha256"] = hashlib.sha256(raw).hexdigest().encode()
    out["sha1"] = hashlib.sha1(raw).hexdigest().encode()  # noqa: S324 - a leak to look for
    out["md5"] = hashlib.md5(raw).hexdigest().encode()  # noqa: S324 - a leak to look for
    out["sha256-prefix"] = out["sha256"][:8]  # the unkeyed fingerprint keys no longer prints
    if not hint_ok:
        out["hint"] = f"{value[:8]}…{value[-4:]}".encode()
    seen: set[bytes] = set()
    unique: dict[str, bytes] = {}
    for k, v in out.items():
        if v and v not in seen:
            seen.add(v)
            unique[k] = v
    return unique


ENCODED_FOR_PIECES = ("hex", "hex-upper", "url", "url-path", "json", "base64-shift0")


def find_leak(value: str, data: bytes, *, hint_ok: bool = False) -> str | None:
    """The name of the first form of value found in data, or None."""
    unwrapped = data.replace(b"\r", b"").replace(b"\n", b"")
    found = forms(value, hint_ok=hint_ok)
    for name, needle in found.items():
        if needle in data or needle in unwrapped:
            return name
    raw = value.encode()
    for i in range(len(raw) - PIECE + 1):
        if raw[i : i + PIECE] in data:
            return "piece"
    for name in ENCODED_FOR_PIECES:
        enc = found.get(name)
        if enc is None:
            continue
        for i in range(len(enc) - ENCODED_PIECE + 1):
            if enc[i : i + ENCODED_PIECE] in data:
                return f"piece of {name}"
    return None


def unmetafy(data: bytes) -> bytes:
    """zsh's history file writes some bytes as 0x83 then the byte xor 0x20; undo that."""
    out = bytearray()
    it = iter(data)
    for b in it:
        if b == 0x83:
            nxt = next(it, None)
            if nxt is not None:
                out.append(nxt ^ 0x20)
        else:
            out.append(b)
    return bytes(out)


@dataclass
class Child:
    prog: str
    argv: list[str]
    stdin: str
    env: list[str] = field(default_factory=lambda: list[str]())  # names only
    target: str = ""  # the fake target a write landed on (see fake_child.target_key)


@dataclass
class Result:
    code: int
    stdout: str
    stderr: str
    children: list[Child] = field(default_factory=lambda: list[Child]())


class Canary:
    """One planted value, one temporary home; `run`, `call` and `shell` check every channel."""

    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch, value: str = CANARY) -> None:
        self.value = value
        self.provider_issued = False  # True allows the 8+4 hint, as keys prints for such keys
        self.monkeypatch = monkeypatch
        self.root = root
        self.home = root / "home"
        self.tmp = root / "tmp"
        self.work = root / "work"
        self.bin = root / "harness" / "bin"
        self.state = root / "harness" / "state"
        self.py = root / "harness" / "py"
        for d in (self.home, self.tmp, self.work, self.bin, self.state, self.py):
            d.mkdir(parents=True)
        self.db_path = self.state / "fake-db.json"
        self.log_path = self.state / "children.jsonl"
        self.hook_log = self.state / "hook.jsonl"
        self.db: dict[str, Any] = {"values": {}, "fail": {}, "items": [], "create_fail": None}
        self._save_db()
        for prog in FAKE_PROGRAMS:
            self._install_fake(prog)
        self._install_python("keys", "-m keys")
        self._install_python("keys-python", "")
        (self.py / "sitecustomize.py").write_text(
            "import sys\n"
            f"sys.path.insert(0, {str(HERE)!r})\n"
            "import canary_hook\n"
            "sys.path.pop(0)\n"
            "canary_hook.install_from_env()\n"
        )
        self.planted: dict[Path, str] = {}
        self.extra_values: list[str] = []
        # Values no target may ever receive (a minting key): a write of one fails the test.
        self.never_written: list[str] = []

    # ------------------------------------------------------------------ setting the scene

    def _install_fake(self, prog: str) -> None:
        # The fakes are not watched themselves: their own log writes are the harness's.
        path = self.bin / prog
        path.write_text(
            "#!/bin/sh\n"
            f'KEYS_FAKE_DB="{self.db_path}" KEYS_FAKE_LOG="{self.log_path}" '
            f'exec env -u PYTHONPATH -u KEYS_CANARY_HOOK_LOG "{sys.executable}" "{FAKE_CHILD}" '
            f'{prog} "$@"\n'
        )
        path.chmod(0o755)

    def _install_python(self, name: str, args: str) -> None:
        # keys, and the interpreter it runs, with the canary's watch loaded by sitecustomize.
        path = self.bin / name
        path.write_text(
            "#!/bin/sh\n"
            f'PYTHONPATH="{self.py}" KEYS_CANARY_HOOK_LOG="{self.hook_log}" '
            f'PYTHONDONTWRITEBYTECODE=1 exec "{sys.executable}" {args} "$@"\n'
        )
        path.chmod(0o755)

    def _save_db(self) -> None:
        self.db_path.write_text(json.dumps(self.db))

    def op_value(self, ref: str, value: str) -> None:
        """The fake op answers `op read ref` with value; a value other than the canary is
        watched for too."""
        self._load_db()
        self.db["values"][ref] = value
        if value != self.value and value not in self.extra_values:
            self.extra_values.append(value)
        self._save_db()

    def watch(self, value: str) -> None:
        """Another made-up value to watch for, besides the canary."""
        if value != self.value and value not in self.extra_values:
            self.extra_values.append(value)

    def op_fail(self, ref: str, code: int = 1, stderr: str | None = None) -> None:
        """The fake op fails `op read ref`; by default its error text holds the canary."""
        self._load_db()
        self.db["fail"][ref] = {"code": code, "stderr": stderr or f"[ERROR] {self.value}"}
        self._save_db()

    def kv_value(self, vault: str, name: str, value: str | None) -> None:
        """The fake az answers `az keyvault secret show` for vault/name with value (None: a
        secret with no value, which az prints as null)."""
        ref = f"kv://{vault}/{name}"
        if value is None:
            self.db["values"][ref] = None
            self._save_db()
        else:
            self.op_value(ref, value)

    def kv_fail(self, vault: str, name: str, code: int = 1, *, stdout: bool = False) -> None:
        """The fake az fails to show vault/name; its error text holds the canary, and with
        stdout it also prints the canary on its stdout before failing."""
        self.op_fail(f"kv://{vault}/{name}", code)
        self.db["fail"][f"kv://{vault}/{name}"]["stdout"] = self.value if stdout else ""
        self._save_db()

    def op_items(self, items: list[dict[str, Any]]) -> None:
        """What the fake `op item list --format json` prints."""
        self._load_db()
        self.db["items"] = items
        self._save_db()

    def op_create_fails(self, code: int = 1, *, saved: bool = False) -> None:
        """The fake `op item create` fails; with saved, the item is listed afterwards anyway,
        as when op times out after the server saved it."""
        self._load_db()
        self.db["create_fail"] = {"code": code, "stderr": f"[ERROR] {self.value}", "saved": saved}
        self._save_db()

    def op_list_fails(self, code: int = 1) -> None:
        self._load_db()
        self.db["list_fail"] = {"code": code, "stderr": f"[ERROR] {self.value}"}
        self._save_db()

    def child_prints(self, words: list[str], stdout: str) -> None:
        """A fake child whose program and leading words are these prints stdout and exits 0
        (an answer keys cannot read)."""
        self._load_db()
        self.db.setdefault("child_print", []).append({"words": words, "stdout": stdout})
        self._save_db()

    def child_fails(
        self, words: list[str], code: int = 1, *, skip: int = 0, after: bool = False
    ) -> None:
        """A fake child whose program and leading words are these fails with code, after the
        first `skip` such calls succeed; its error text holds the canary. With `after`, a
        target call takes effect first and then fails (a write that timed out but landed)."""
        self._load_db()
        self.db.setdefault("child_fail", []).append(
            {
                "words": words,
                "code": code,
                "stderr": f"error: {self.value}",
                "skip": skip,
                "after": after,
            }
        )
        self._save_db()

    def clear_child_fails(self) -> None:
        self.set_db("child_fail", [])

    CONCEALED = ("credential", "pending", "previous")

    def op_item(self, vault: str, title: str, fields: dict[str, str]) -> str:
        """A 1Password item with these fields (label: value), as `op item get --format json`
        prints it; the concealed ones are watched. Returns its id."""
        self._load_db()
        ident = f"item{len(self.db['items']) + 1}"
        rows = [
            {
                "id": label,
                "label": label,
                "type": "CONCEALED" if label in self.CONCEALED else "STRING",
                "value": value,
            }
            for label, value in fields.items()
        ]
        self.db["items"].append(
            {
                "id": ident,
                "title": title,
                "category": "API_CREDENTIAL",
                "vault": {"id": f"v-{vault.lower()}", "name": vault},
                "fields": rows,
            }
        )
        for label, value in fields.items():
            if label in self.CONCEALED and value:
                self.watch(value)
        self._save_db()
        return ident

    def op_fields(self, vault: str, title: str) -> dict[str, str]:
        """An item's fields now, by label."""
        self._load_db()
        for item in self.db["items"]:
            if item["vault"]["name"] == vault and item["title"] == title and "fields" in item:
                return {f["label"]: f.get("value") or "" for f in item["fields"]}
        raise KeyError(title)

    def op_set_field(self, vault: str, title: str, label: str, value: str) -> None:
        """What the owner does in the 1Password app: paste value into a field."""
        self._load_db()
        for item in self.db["items"]:
            if item["vault"]["name"] == vault and item["title"] == title and "fields" in item:
                for f in item["fields"]:
                    if f["label"] == label:
                        f["value"] = value
                        break
                else:
                    item["fields"].append(
                        {"id": label, "label": label, "type": "CONCEALED", "value": value}
                    )
        self.watch(value)
        self._save_db()

    def gh_api(self, path: str, answer: Any) -> None:
        """What the fake `gh api <path>` prints (absent: it fails as a 404 does)."""
        self._load_db()
        self.db.setdefault("gh_api", {})[path] = answer
        self._save_db()

    def gh_main_only(self, repo: str, environment: str, branches: list[str] | None = None) -> None:
        """A GitHub Environment whose deployments are limited to these branches (main)."""
        base = f"repos/{repo}/environments/{environment}"
        rule = {"protected_branches": False, "custom_branch_policies": True}
        self.gh_api(base, {"name": environment, "deployment_branch_policy": rule})
        policies = [{"name": b, "type": "branch"} for b in (branches or ["main"])]
        self.gh_api(f"{base}/deployment-branch-policies", {"branch_policies": policies})

    def target_put(self, key: str, value: str, **meta: Any) -> None:
        """A secret already at a target, under the fake's key (see fake_child.target_key):
        `gh:<repo>:<name>`, `gh:<repo>:env:<env>:<name>`, `gh:org:<org>:<name>`,
        `railway:<project>:<service>:<environment>:<name>`, `az:<vault>:<name>`,
        `gcp:<project>:<name>`."""
        self._load_db()
        entry = {"value": value, "updated_at": "2026-01-01T00:00:00Z", "writes": 0, **meta}
        self.db.setdefault("targets", {})[key] = entry
        self.watch(value)
        self._save_db()

    def target(self, key: str) -> dict[str, Any] | None:
        """What the fake target under key holds now (value, updated_at, writes, tags, ...)."""
        self._load_db()
        found: dict[str, Any] | None = self.db.get("targets", {}).get(key)
        return found

    def deploys(self, key: str) -> list[dict[str, str]]:
        """A Railway scope's deployments, newest first; key is `railway:<p>:<s>:<e>:`."""
        self._load_db()
        found: list[dict[str, str]] = self.db.get("deploys", {}).get(f"deploys:{key}", [])
        return found

    def set_db(self, name: str, value: Any) -> None:
        self._load_db()
        self.db[name] = value
        self._save_db()

    def _load_db(self) -> None:
        self.db = json.loads(self.db_path.read_text())

    def plant(self, rel: str | Path, text: str) -> Path:
        """A file allowed to hold the value while unchanged: under the temporary home when
        relative, anywhere the harness watches when absolute."""
        path = self.home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        self.planted[path] = _digest(path.read_bytes())
        return path

    def unplant(self, path: Path) -> None:
        """A planted file the command is expected to change (scrub): checked like any other."""
        self.planted.pop(path, None)

    def environ(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        env = {
            "HOME": str(self.home),
            "TMPDIR": str(self.tmp),
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "LANG": "C.UTF-8",
        }
        return {**env, **(extra or {})}

    def children(self) -> list[Child]:
        """Every fake child, in the order it started, with what was piped to it."""
        if not self.log_path.exists():
            return []
        started: dict[str, Child] = {}
        for line in self.log_path.read_text().splitlines():
            row = json.loads(line)
            if "argv" in row:
                started[row["id"]] = Child(row["prog"], row["argv"], "", row.get("env", []))
            elif row["id"] in started and "target" in row:
                started[row["id"]].target = row["target"]
            elif row["id"] in started:
                started[row["id"]].stdin = row["stdin"]
        return list(started.values())

    def history(self) -> str:
        path = self.home / ".zsh_history"
        return unmetafy(path.read_bytes()).decode(errors="replace") if path.exists() else ""

    # ------------------------------------------------------------------ running

    def run(
        self,
        argv: Sequence[str],
        *,
        stdin: str = "",
        env: dict[str, str] | None = None,
        **ctx: Any,
    ) -> Result:
        """keys <argv>, in process, through cli.main with the harness's context."""

        def step(c: cli.Context) -> int:
            return cli.main(list(argv), ctx=c)

        return self.call(step, stdin=stdin, env=env, **ctx)

    def call(
        self,
        step: Callable[[cli.Context], int],
        *,
        stdin: str = "",
        env: dict[str, str] | None = None,
        **ctx: Any,
    ) -> Result:
        """Any step that takes a context, with every channel watched."""
        self.log_path.unlink(missing_ok=True)
        environ = self.environ(env)
        out, err = io.StringIO(), io.StringIO()
        real_out, real_err = io.StringIO(), io.StringIO()
        context = cli.Context(
            stdout=out, stderr=err, stdin=io.StringIO(stdin), environ=environ, **ctx
        )
        events: list[dict[str, Any]] = []
        escaped: str | None = None
        code = -1
        with (
            self._fd_capture() as fds,
            self._isolated(environ),
            contextlib.redirect_stdout(real_out),
            contextlib.redirect_stderr(real_err),
        ):
            canary_hook.watch(events.append)
            try:
                code = step(context)
            except KeyboardInterrupt:
                raise
            except BaseException:
                escaped = traceback.format_exc()
            finally:
                canary_hook.watch(None)
        fd_out, fd_err = fds
        result = Result(
            code,
            out.getvalue() + real_out.getvalue() + fd_out(),
            err.getvalue() + real_err.getvalue() + fd_err(),
        )
        result.children = self.children()
        self._check(result, events, escaped=escaped)
        if escaped is not None:
            raise AssertionError(f"keys let an exception escape (no value in it):\n{escaped}")
        return result

    def shell(self, command: str, *, env: dict[str, str] | None = None) -> Result:
        """command, typed into a real interactive zsh whose history file is in the temporary home.

        zsh records commands read from stdin by an interactive shell (not ones given with -c),
        so this is the history an agent's shell would keep. `keys` there runs with the same
        audit-hook watch, through sitecustomize. The exit code is the command's, or -1 when the
        command ended the shell itself (exit, exec).
        """
        if shutil.which("zsh") is None:
            pytest.fail("zsh is needed for the canary's shell-history check")
        self.log_path.unlink(missing_ok=True)
        self.hook_log.unlink(missing_ok=True)
        (self.home / ".zshrc").write_text(
            f"HISTFILE={shlex.quote(str(self.home / '.zsh_history'))}\n"
            "HISTSIZE=1000\nSAVEHIST=1000\nPS1=''\nPROMPT=''\nRPROMPT=''\nPROMPT_EOL_MARK=''\n"
            "unsetopt BEEP\nsetopt INC_APPEND_HISTORY\n"
        )
        exit_file = self.state / "exit"
        exit_file.unlink(missing_ok=True)
        script = (
            f"{{ {command} ; }} </dev/null\nprint -r -- $? >| {shlex.quote(str(exit_file))}\nexit\n"
        )
        environ = self.environ({"ZDOTDIR": str(self.home), **(env or {})})
        proc = subprocess.run(
            ["zsh", "-i"],
            input=script,
            capture_output=True,
            text=True,
            env=environ,
            cwd=self.work,
            timeout=120,
            check=False,
        )
        code = int(exit_file.read_text().strip()) if exit_file.exists() else -1
        result = Result(code, proc.stdout, proc.stderr, self.children())
        events: list[dict[str, Any]] = []
        if self.hook_log.exists():
            events = [json.loads(x) for x in self.hook_log.read_text().splitlines() if x]
        self._check(result, events, escaped=None)
        return result

    @contextlib.contextmanager
    def _isolated(self, environ: dict[str, str]) -> Generator[None]:
        """The step's environment is exactly environ: nothing real reaches it or its children."""
        with self.monkeypatch.context() as m:
            for k in list(os.environ):
                if k not in environ:
                    m.delenv(k)
            for k, v in environ.items():
                m.setenv(k, v)
            m.setattr(tempfile, "tempdir", str(self.tmp))
            m.setattr(sys, "dont_write_bytecode", True)
            m.chdir(self.work)
            yield

    @contextlib.contextmanager
    def _fd_capture(self) -> Generator[tuple[Callable[[], str], Callable[[], str]]]:
        """File descriptors 1 and 2 point at files in the harness's own folder for the step."""
        files = [(self.state / "fd1").open("w+b"), (self.state / "fd2").open("w+b")]
        saved = [os.dup(1), os.dup(2)]
        texts = ["", ""]
        for stream in (sys.stdout, sys.stderr, sys.__stdout__, sys.__stderr__):
            if stream is not None:
                stream.flush()
        os.dup2(files[0].fileno(), 1)
        os.dup2(files[1].fileno(), 2)
        try:
            yield (lambda: texts[0]), (lambda: texts[1])
        finally:
            for stream in (sys.__stdout__, sys.__stderr__):
                if stream is not None:
                    with contextlib.suppress(ValueError, OSError):
                        stream.flush()
            os.dup2(saved[0], 1)
            os.dup2(saved[1], 2)
            for i, f in enumerate(files):
                os.close(saved[i])
                f.seek(0)
                texts[i] = f.read().decode(errors="replace")
                f.close()

    # ------------------------------------------------------------------ checking

    def _held(self, children: list[Child]) -> list[str]:
        """Every value 1Password held during the run: the canary, op_values, the items' fields
        now, and every field an item write sent (a rotation moves values between fields)."""
        self._load_db()
        held = [self.value, *self.db.get("values", {}).values()]
        for item in self.db.get("items", []):
            held += [str(f.get("value") or "") for f in item.get("fields", [])]
        for c in children:
            words = tuple(a for a in c.argv if not a.startswith("-"))
            if any(words[: len(w)] == w for w in ITEM_WRITES) and c.stdin:
                with contextlib.suppress(ValueError, KeyError, TypeError):
                    sent = json.loads(c.stdin)
                    held += [str(f.get("value") or "") for f in sent["fields"]]
        return [v for v in held if v]

    def _expected_write(self, data: str, held: list[str]) -> bool:
        """A target write carries exactly one value 1Password held (the canary, an op_value or
        an item field), as read or with its trailing line breaks removed (keys's one change)."""
        if any(data in (v, v.rstrip("\n")) for v in self.never_written):
            return False
        return any(data in (v, v.rstrip("\n")) for v in held)

    def secrets(self) -> list[str]:
        return [self.value, *self.extra_values]

    def _leak(self, value: str, data: bytes) -> str | None:
        return find_leak(value, data, hint_ok=self.provider_issued)

    def _check(self, result: Result, events: list[dict[str, Any]], *, escaped: str | None) -> None:
        channels: list[tuple[str, bytes]] = [
            ("stdout", result.stdout.encode()),
            ("stderr", result.stderr.encode()),
        ]
        if escaped is not None:
            channels.append(("exception", escaped.encode()))
        held = self._held(result.children)
        for c in result.children:
            words = tuple(a for a in c.argv if not a.startswith("-"))
            if not stdin_ok(c.argv) or any(words[: len(w)] == w for w in ITEM_WRITES):
                if not stdin_ok(c.argv):
                    channels.append((f"stdin of {c.prog}", c.stdin.encode()))
                else:
                    channels += _plain_fields(c.stdin)
            elif c.stdin and not self._expected_write(c.stdin, held):
                raise LeakError(f"the stdin of {c.prog} is not exactly one value 1Password holds")
            channels.append((f"argv of {c.prog}", "\0".join(c.argv).encode()))
        for e in events:
            if e["event"] == "spawn":
                prog = self._program(e)
                channels.append((f"argv of {prog}", "\0".join(e["argv"]).encode()))
                env_text = "\0".join(f"{k}={v}" for k, v in e["env"].items())
                channels.append((f"environment of {prog}", env_text.encode()))
            elif e["event"] == "write":
                self._check_write(Path(e["path"]))
                channels.append(("a file name", os.fsencode(self._relative(Path(e["path"])))))
        for value in self.secrets():
            for name, data in channels:
                form = self._leak(value, data)
                if form:
                    raise LeakError(f"the planted value reached {name} ({form} form)")
            for path in self._names():
                form = self._leak(value, os.fsencode(path.relative_to(self.root)))
                if form and path not in self.planted:
                    raise LeakError(f"the planted value reached a file name ({form} form)")
            for path in self._files():
                form = self._leak(value, os.fsencode(path.relative_to(self.root)))
                if form and path not in self.planted:
                    raise LeakError(f"the planted value reached a file name ({form} form)")
                data = path.read_bytes()
                if self.planted.get(path) == _digest(data):
                    continue
                if path.name == ".zsh_history":
                    data = unmetafy(data)
                form = self._leak(value, data)
                if form:
                    raise LeakError(f"the planted value reached file {path} ({form} form)")

    def _program(self, event: dict[str, Any]) -> str:
        """The started program's name; fails unless it is one of the harness's fakes."""
        program = str(event["program"])
        if program in ("None", ""):
            program = str(event["argv"][0])
        path = str(event["env"].get("PATH", ""))
        found = program if "/" in program else shutil.which(program, path=path)
        resolved = Path(found).resolve() if found else None
        if resolved is None or resolved.parent != self.bin.resolve():
            raise LeakError(f"keys started {program}, which is not one of the harness's fakes")
        return resolved.name

    def _check_write(self, path: Path) -> None:
        if str(path) == os.devnull:
            return
        p = path.resolve()
        if _under(p, self.tmp.resolve()):
            raise LeakError(f"keys wrote a temp file ({p})")
        if not (_under(p, self.home.resolve()) or _under(p, self.work.resolve())):
            raise LeakError(f"keys wrote outside the watched folders ({p})")

    def _relative(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.root.resolve()))
        except ValueError:
            return str(path)

    def _names(self) -> Iterator[Path]:
        """Every folder and link under the watched roots, by name."""
        for root in (self.home, self.tmp, self.work):
            for dirpath, dirnames, names in os.walk(root):
                for name in [*dirnames, *names]:
                    p = Path(dirpath, name)
                    if p.is_dir() or p.is_symlink():
                        yield p

    def _files(self) -> Iterator[Path]:
        def refuse(e: OSError) -> None:
            raise LeakError(f"the harness cannot read {e.filename}, so cannot check it")

        for root in (self.home, self.tmp, self.work):
            for dirpath, _, names in os.walk(root, onerror=refuse):
                for name in names:
                    path = Path(dirpath, name)
                    if path.is_symlink() or not path.is_file():
                        continue
                    try:
                        path.read_bytes()
                    except OSError as e:
                        refuse(e)
                    yield path


def _plain_fields(stdin: str) -> list[tuple[str, bytes]]:
    """The fields of an item write that are not concealed, and its other parts: a value may
    sit only in a concealed field."""
    try:
        doc: object = json.loads(stdin)
    except ValueError:
        doc = None
    if not isinstance(doc, dict):
        return [("an op item write keys sent", stdin.encode())]
    item = cast(dict[str, Any], doc)
    out: list[tuple[str, bytes]] = []
    for raw in cast(list[Any], item.get("fields") or []):
        f = cast(dict[str, Any], raw) if isinstance(raw, dict) else {}
        if f.get("type") != "CONCEALED":
            out.append((f"plain field {f.get('label')!r} of an op item write", str(f).encode()))
    rest = {k: v for k, v in item.items() if k != "fields"}
    out.append(("the rest of an op item write", json.dumps(rest).encode()))
    return out


def _under(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
