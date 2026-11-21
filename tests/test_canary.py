"""The canary harness catches a planted value on every channel it watches.

Each test here runs a deliberately leaky step through the harness and expects it to fail, naming
the channel. If the harness misses one of these, every later command's canary test means less.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
import urllib.parse
from pathlib import Path

import pytest

from keys.cli import Context
from tests.canary import Canary, LeakError


def leaky_print(text: str):
    def step(ctx: Context) -> int:
        ctx.say(text)
        return 0

    return step


def test_a_clean_command_passes(canary: Canary) -> None:
    result = canary.run(["--help"])
    assert result.code == 0
    assert "list" in result.stdout


@pytest.mark.parametrize(
    "form",
    [
        "raw",
        "base64",
        "base64-url",
        "base64-unpadded",
        "base64-inside",
        "hex",
        "hex-upper",
        "url",
        "url-plus",
        "json",
        "piece",
    ],
)
def test_every_encoded_form_on_stdout_is_caught(canary: Canary, form: str) -> None:
    v = canary.value
    text = {
        "raw": v,
        "base64": base64.b64encode(v.encode()).decode(),
        "base64-url": base64.urlsafe_b64encode(v.encode()).decode(),
        "base64-unpadded": base64.b64encode(v.encode()).decode().rstrip("="),
        # Basic auth: user:secret encoded together, so the value's base64 is shifted.
        "base64-inside": base64.b64encode(b"user:" + v.encode()).decode(),
        "hex": v.encode().hex(),
        "hex-upper": v.encode().hex().upper(),
        "url": urllib.parse.quote(v, safe=""),
        "url-plus": urllib.parse.quote_plus(v),
        "json": json.dumps(v)[1:-1],
        "piece": v[3:15],
    }[form]
    with pytest.raises(LeakError, match="stdout"):
        canary.call(leaky_print(f"token is {text}."))


def test_hint_sized_pieces_are_allowed(canary: Canary) -> None:
    v = canary.value
    canary.call(leaky_print(f"{v[:8]}…{v[-4:]}"))


def test_stderr_is_caught(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        ctx.warn(canary.value)
        return 1

    with pytest.raises(LeakError, match="stderr"):
        canary.call(step)


def test_real_stdout_is_caught_too(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        print(canary.value)
        return 0

    with pytest.raises(LeakError, match="stdout"):
        canary.call(step)


def test_exception_text_is_caught(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        raise ValueError(f"bad key {canary.value}")

    with pytest.raises(LeakError, match="exception"):
        canary.call(step)


def test_a_file_in_the_temporary_home_is_caught(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        (Path(ctx.environ["HOME"]) / ".cache.json").write_text(json.dumps({"k": canary.value}))
        return 0

    with pytest.raises(LeakError, match=r"file .*\.cache\.json"):
        canary.call(step)


def test_a_temp_file_is_caught(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(canary.value)
        return 0

    with pytest.raises(LeakError, match="file"):
        canary.call(step)


def test_a_file_in_the_working_directory_is_caught(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        Path("notes.txt").write_text(canary.value)
        return 0

    with pytest.raises(LeakError, match=r"file .*notes\.txt"):
        canary.call(step)


def test_child_argv_is_caught(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        subprocess.run(
            ["op", "item", "edit", "x", f"credential={canary.value}"],
            env=dict(ctx.environ),
            check=False,
            capture_output=True,
        )
        return 0

    with pytest.raises(LeakError, match="argv of op"):
        canary.call(step)


def test_child_stdin_is_allowed(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        subprocess.run(
            ["op", "item", "create", "--vault", "V", "-"],
            env=dict(ctx.environ),
            input=canary.value,
            text=True,
            check=False,
            capture_output=True,
        )
        return 0

    result = canary.call(step)
    assert result.children[0].argv == ["op", "item", "create", "--vault", "V", "-"]
    assert result.children[0].stdin == canary.value


def test_a_planted_file_left_alone_is_allowed_and_a_copy_is_caught(canary: Canary) -> None:
    planted = canary.plant(".claude/projects/p/s.jsonl", f'{{"text": "{canary.value}"}}\n')
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
        canary.shell(f"true {canary.value}")


def test_shell_runs_a_real_child_with_the_fake_op(canary: Canary) -> None:
    canary.op_value("op://Vault/item/credential", canary.value)
    result = canary.shell("op read --no-newline op://Vault/item/credential | wc -c")
    assert result.stdout.strip() == str(len(canary.value.encode()))
    assert result.children[0].argv == ["op", "read", "--no-newline", "op://Vault/item/credential"]


def test_the_harness_runs_in_its_own_home(canary: Canary) -> None:
    def step(ctx: Context) -> int:
        assert ctx.environ["HOME"] == str(canary.home)
        assert os.environ["HOME"] == str(canary.home)
        assert tempfile.gettempdir() == str(canary.tmp)
        assert Path.cwd() == canary.work
        return 0

    canary.call(step)
