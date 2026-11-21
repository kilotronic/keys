"""The canary harness catches a planted value on every channel it watches.

Each test here runs a deliberately leaky step through the harness and expects it to fail, naming
the channel and, for encodings, the form. If the harness misses one of these, every later
command's canary test means less.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from collections.abc import Callable
from pathlib import Path

import pytest

from keys.cli import Context
from tests.canary import CANARY, Canary, LeakError, forms, unmetafy

Step = Callable[[Context], int]


def leaky_print(text: str) -> Step:
    def step(ctx: Context) -> int:
        ctx.say(text)
        return 0

    return step


def test_a_clean_command_passes(canary: Canary) -> None:
    result = canary.run(["--help"])
    assert result.code == 0
    assert "list" in result.stdout


def test_the_canary_exercises_every_encoding() -> None:
    raw = CANARY.encode()
    for shift in range(3):
        std = base64.b64encode(b"\0" * shift + raw)
        assert b"+" in std[3:-3]
        assert b"/" in std[3:-3]
    f = forms(CANARY)
    names = ["raw", "url", "url-path", "url-plus", "json"]
    assert len({f[n] for n in names}) == len(names)
    for shift in range(3):
        assert f[f"base64-shift{shift}"] != f[f"base64-url-shift{shift}"]


V = CANARY
URL = urllib.parse.quote(V, safe="")
SHIFTED = base64.b64encode(b"user:" + V.encode()).decode()
MIME = base64.encodebytes(V.encode() * 3).decode()  # wrapped at 76 characters


@pytest.mark.parametrize(
    ("text", "form"),
    [
        (V, "raw"),
        (base64.b64encode(V.encode()).decode(), "base64-shift0"),
        (base64.urlsafe_b64encode(V.encode()).decode(), "base64-url-shift0"),
        (base64.b64encode(V.encode()).decode().rstrip("="), "base64-shift0"),
        (SHIFTED, "base64-shift2"),  # Basic auth: user:secret encoded together
        (MIME, "base64-shift0"),
        (V.encode().hex(), "hex"),
        (V.encode().hex().upper(), "hex-upper"),
        (V.encode()[:20].hex(), "piece of hex"),
        (urllib.parse.quote(V, safe=""), "url"),
        (
            re.sub(r"%[0-9A-F]{2}", lambda m: m.group().lower(), urllib.parse.quote(V, safe="")),
            "url-lower",
        ),
        (urllib.parse.quote(V), "url-path"),
        (urllib.parse.quote_plus(V), "url-plus"),
        (json.dumps(V)[1:-1], "json"),
        (hashlib.sha256(V.encode()).hexdigest(), "sha256"),
        (hashlib.sha256(V.encode()).hexdigest()[:8], "sha256-prefix"),
        (hashlib.sha1(V.encode()).hexdigest(), "sha1"),  # noqa: S324 - the leak being caught
        (hashlib.md5(V.encode()).hexdigest(), "md5"),  # noqa: S324 - the leak being caught
        (V[3:12], "piece"),
        (f"{V[:8]}…{V[-4:]}", "hint"),
    ],
)
def test_every_form_on_stdout_is_caught_by_name(canary: Canary, text: str, form: str) -> None:
    with pytest.raises(LeakError, match=rf"stdout \({form} form\)"):
        canary.call(leaky_print(f"token is {text}."))


def test_three_short_pieces_are_caught(canary: Canary) -> None:
    with pytest.raises(LeakError, match="piece"):
        canary.call(leaky_print(f"{V[:9]} {V[9:18]} {V[18:27]}"))


def test_a_hint_is_allowed_only_for_a_provider_issued_value(canary: Canary) -> None:
    canary.provider_issued = True
    canary.call(leaky_print(f"{V[:8]}…{V[-4:]}"))


def test_stderr_is_caught(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        ctx.warn(canary.value)
        return 1

    with pytest.raises(LeakError, match="stderr"):
        canary.call(step)


@pytest.mark.parametrize("how", ["print", "dunder", "fd"])
def test_the_real_streams_are_caught(canary: Canary, how: str) -> None:
    def step(ctx: Context) -> int:
        if how == "print":
            print(canary.value)
        elif how == "dunder":
            assert sys.__stdout__ is not None
            sys.__stdout__.write(canary.value)
            sys.__stdout__.flush()
        else:
            os.write(2, canary.value.encode())
        return 0

    with pytest.raises(LeakError, match=r"stdout|stderr"):
        canary.call(step)


def test_a_child_writing_to_the_inherited_terminal_is_caught(canary: Canary) -> None:
    canary.op_value("op://V/i/credential", canary.value)

    def step(ctx: Context) -> int:
        subprocess.run(["op", "read", "op://V/i/credential"], check=False, stdin=subprocess.DEVNULL)
        return 0

    with pytest.raises(LeakError, match="stdout"):
        canary.call(step)


def test_exception_text_is_caught(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        raise ValueError(f"bad key {canary.value}")

    with pytest.raises(LeakError, match="exception"):
        canary.call(step)


def test_a_clean_exception_still_fails_and_keeps_its_traceback(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        raise ValueError("nothing secret")

    with pytest.raises(AssertionError, match="ValueError: nothing secret"):
        canary.call(step)


def test_the_real_environment_is_gone(canary: Canary, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "outside")

    def step(ctx: Context) -> int:
        assert "OP_SERVICE_ACCOUNT_TOKEN" not in os.environ
        assert dict(os.environ) == dict(ctx.environ)
        return 0

    canary.call(step)
    assert os.environ["OP_SERVICE_ACCOUNT_TOKEN"] == "outside"


def test_a_file_in_the_temporary_home_is_caught(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        (Path(ctx.environ["HOME"]) / ".cache.json").write_text(json.dumps({"k": canary.value}))
        return 0

    with pytest.raises(LeakError, match=r"file .*\.cache\.json"):
        canary.call(step)


def test_any_temp_file_is_caught_even_deleted_and_clean(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        with tempfile.NamedTemporaryFile("w") as f:
            f.write("nothing secret")
        return 0

    with pytest.raises(LeakError, match="temp file"):
        canary.call(step)


def test_a_write_outside_the_watched_folders_is_caught(canary: Canary, tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"

    def step(ctx: Context) -> int:
        fd = os.open(outside, os.O_WRONLY | os.O_CREAT)
        os.close(fd)
        return 0

    with pytest.raises(LeakError, match="outside the watched folders"):
        canary.call(step)


def test_a_file_in_the_working_directory_is_caught(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        Path("notes.txt").write_text(canary.value)
        return 0

    with pytest.raises(LeakError, match=r"file .*notes\.txt"):
        canary.call(step)


def test_an_unreadable_folder_fails_the_scan(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        d = canary.home / "locked"
        d.mkdir()
        (d / "f").write_text(canary.value)
        d.chmod(0)
        return 0

    try:
        with pytest.raises(LeakError, match="cannot read"):
            canary.call(step)
    finally:
        (canary.home / "locked").chmod(0o700)


def test_child_argv_is_caught(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        subprocess.run(["op", "item", "edit", "x", f"credential={canary.value}"], check=False)
        return 0

    with pytest.raises(LeakError, match="argv of op"):
        canary.call(step)


def test_a_program_that_is_not_a_fake_is_caught(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        subprocess.run(["/bin/echo", "hello"], check=False, capture_output=True)
        return 0

    with pytest.raises(LeakError, match="not one of the harness's fakes"):
        canary.call(step)


def test_a_background_child_is_caught_when_it_starts(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        def later() -> None:
            subprocess.run(["op", "x", canary.value], check=False, capture_output=True)

        t = threading.Thread(target=later)
        t.start()
        t.join()
        return 0

    with pytest.raises(LeakError, match="argv of op"):
        canary.call(step)


def test_a_child_environment_is_caught(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        env = {**ctx.environ, "OP_X": canary.value}
        subprocess.run(["op", "item", "list"], env=env, check=False, capture_output=True)
        return 0

    with pytest.raises(LeakError, match="environment of op"):
        canary.call(step)


def test_an_inherited_environment_holding_the_value_is_caught(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        subprocess.run(["op", "item", "list"], check=False, capture_output=True)
        return 0

    with pytest.raises(LeakError, match="environment of op"):
        canary.call(step, env={"K": canary.value})


def test_child_stdin_is_allowed_for_op_item_create_only(canary: Canary) -> None:
    def create(ctx: Context) -> int:
        subprocess.run(
            ["op", "item", "create", "--vault", "V", "-"],
            input=canary.value,
            text=True,
            check=False,
            capture_output=True,
        )
        return 0

    result = canary.call(create)
    assert result.children[0].argv == ["op", "item", "create", "--vault", "V", "-"]
    assert result.children[0].stdin == canary.value

    def clipboard(ctx: Context) -> int:
        subprocess.run(["pbcopy"], input=canary.value, text=True, check=False, capture_output=True)
        return 0

    with pytest.raises(LeakError, match="stdin of pbcopy"):
        canary.call(clipboard)


def test_a_planted_file_left_alone_is_allowed_and_a_copy_is_caught(canary: Canary) -> None:
    planted = canary.plant(".claude/projects/p/s.jsonl", json.dumps({"text": canary.value}) + "\n")
    canary.call(leaky_print("fine"))

    def step(ctx: Context) -> int:
        Path(ctx.environ["HOME"], "copy.jsonl").write_bytes(planted.read_bytes())
        return 0

    with pytest.raises(LeakError, match=r"file .*copy\.jsonl"):
        canary.call(step)


def test_a_planted_file_changed_but_still_holding_the_value_is_caught(canary: Canary) -> None:
    planted = canary.plant("h.txt", f"a {canary.value}\n")

    def step(ctx: Context) -> int:
        planted.write_text(planted.read_text() + "more\n")
        return 0

    with pytest.raises(LeakError, match=r"file .*h\.txt"):
        canary.call(step)


def test_shell_history_is_written_and_checked(canary: Canary) -> None:
    result = canary.shell("keys --help")
    assert result.code == 0
    assert "keys --help" in canary.history()
    with pytest.raises(LeakError, match=r"\.zsh_history"):
        canary.shell(f"true {canary.value!r}")


def test_zsh_history_bytes_are_decoded() -> None:
    # zsh writes bytes 0x83-0x9f and above as 0x83 followed by the byte xor 0x20.
    assert unmetafy(b"a\x83\xa3b") == b"a\x83b"


def test_the_keys_process_in_a_shell_is_watched_too(canary: Canary) -> None:
    # keys-python is the interpreter the keys wrapper runs, with the same watch loaded. Only the
    # watch sees a child's environment or a program that is not a fake.
    env_leak = (
        "import os, subprocess; "
        f"subprocess.run(['op', 'item', 'list'], env={{**os.environ, 'X': {canary.value!r}}})"
    )
    with pytest.raises(LeakError, match="environment of op"):
        canary.shell(f"keys-python -c {shlex.quote(env_leak)}")
    not_fake = "import subprocess; subprocess.run(['/bin/echo', 'hi'])"
    with pytest.raises(LeakError, match="not one of the harness's fakes"):
        canary.shell(f"keys-python -c {shlex.quote(not_fake)}")
    temp = "import tempfile; tempfile.TemporaryFile().close()"
    with pytest.raises(LeakError, match="temp file"):
        canary.shell(f"keys-python -c {shlex.quote(temp)}")


def test_shell_runs_a_real_child_with_the_fake_op(canary: Canary) -> None:
    canary.op_value("op://Vault/item/credential", canary.value)
    result = canary.shell("op read --no-newline op://Vault/item/credential | wc -c")
    assert result.stdout.strip() == str(len(canary.value.encode()))
    assert result.children[0].argv == ["op", "read", "--no-newline", "op://Vault/item/credential"]


def test_the_fake_op_reads_flags_with_values(canary: Canary) -> None:
    canary.op_value("op://V/i/credential", "a-made-up-value")

    def step(ctx: Context) -> int:
        out = subprocess.run(
            ["op", "read", "--account", "acct", "-n", "op://V/i/credential"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert (out.returncode, out.stdout) == (0, "a-made-up-value")
        return 0

    canary.call(step)


def test_the_harness_runs_in_its_own_home(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        assert ctx.environ["HOME"] == str(canary.home)
        assert os.environ["HOME"] == str(canary.home)
        assert tempfile.gettempdir() == str(canary.tmp)
        assert Path.cwd() == canary.work
        return 0

    canary.call(step)


def test_a_file_named_after_the_value_is_caught(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        (canary.work / canary.value.replace("/", "_")[:20]).write_text("clean")
        return 0

    with pytest.raises(LeakError, match="file name"):
        canary.call(step)
