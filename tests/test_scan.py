"""keys scan and keys scrub: find known values and secret shapes in transcripts, history and
logs; report file, line and credential by name; replace them in place on request.

The planted files hold the canary on purpose. The harness allows that while they are unchanged,
and checks that nothing else (output, children, other files) ever holds it.
"""

from __future__ import annotations

import base64
import json
import urllib.parse
from pathlib import Path
from typing import Any

import pytest

from tests.canary import CANARY, Canary

MAPPING = """
[[credential]]
name = "app-mail"
kind = "generic"
item = "op://Vault/generic app-mail"
kept_because = "x"

[[credential]]
name = "deploy-token"
kind = "cloudflare-token"
item = "op://Vault/cloudflare-token deploy-token"
kept_because = "x"
"""
OTHER = "made-up-second-value-7Hq2Lx9Rw4"  # the second credential's fake value
# Secret-shaped, made up, and built here so no token-shaped string sits in the source.
GH_SHAPED = "gh" + "p_" + "Zx81Qw" * 6


@pytest.fixture
def c(canary: Canary) -> Canary:
    canary.plant(canary.work / "keys.toml", MAPPING)
    canary.op_value("op://Vault/generic app-mail/credential", CANARY)
    canary.op_value("op://Vault/cloudflare-token deploy-token/credential", OTHER)
    canary.watch(GH_SHAPED)
    return canary


def scan(c: Canary, *extra: str) -> tuple[int, str, str]:
    result = c.run(["scan", "--tmp-root", str(c.tmp), *extra])
    return result.code, result.stdout, result.stderr


def test_a_clean_home_passes(c: Canary) -> None:
    c.plant(".claude/projects/p/s.jsonl", '{"text": "hello"}\n')
    code, out, _ = scan(c)
    assert code == 0, out
    assert "0 findings" in out


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        (".claude/projects/p/s.jsonl", json.dumps({"text": f"key {CANARY} here"})),
        (".claude/history.jsonl", json.dumps({"display": CANARY})),
        (".claude/file-history/x/1", CANARY),
        (".claude/shell-snapshots/snap.sh", f"export K={urllib.parse.quote(CANARY)}"),
        (".claude/debug/log.txt", base64.b64encode(b"user:" + CANARY.encode()).decode()),
        ("Library/Logs/Claude/main.log", CANARY.encode().hex()),
        ("Library/Application Support/Claude/state.json", json.dumps(CANARY)),
        (".cursor/projects/p/agent-transcripts/t.txt", CANARY),
        (".zsh_history", f": 1:0;echo {CANARY}"),
        (".bash_history", f"echo {CANARY}"),
        (".zsh_sessions/abc.history", CANARY),
        ("Library/Saved Application State/com.apple.Terminal.savedState/data.data", CANARY),
        ("Library/Application Support/iTerm2/SavedState/x", CANARY),
        ("tmux-session.log", CANARY),
    ],
)
def test_a_known_value_is_found_by_file_line_and_name(c: Canary, rel: str, text: str) -> None:
    c.plant(rel, f"first line\nsecond line\n{text}\n")
    code, out, _ = scan(c)
    assert code == 1, out
    assert f"~/{rel}:3: app-mail (known value)" in out


def test_a_claude_temp_folder_is_scanned(c: Canary) -> None:
    c.plant(c.tmp / "claude-501" / "scratch" / "notes.md", f"{CANARY}\n")
    code, out, _ = scan(c)
    assert code == 1
    assert "claude-501/scratch/notes.md:1: app-mail (known value)" in out


def test_folders_outside_the_list_are_not_scanned(c: Canary) -> None:
    c.plant("Documents/notes.txt", CANARY)
    code, out, _ = scan(c)
    assert code == 0, out


def test_an_extra_path_can_be_given(c: Canary) -> None:
    c.plant("Documents/notes.txt", CANARY)
    code, out, _ = scan(c, "--path", str(c.home / "Documents"))
    assert code == 1
    assert "~/Documents/notes.txt:1: app-mail (known value)" in out


def test_two_credentials_and_a_pattern(c: Canary) -> None:
    c.plant(".claude/projects/p/s.jsonl", f"{OTHER}\nnothing\n{GH_SHAPED} and {CANARY}\n")
    code, out, _ = scan(c)
    assert code == 1
    assert "~/.claude/projects/p/s.jsonl:1: deploy-token (known value)" in out
    assert "~/.claude/projects/p/s.jsonl:3: app-mail (known value)" in out
    assert "~/.claude/projects/p/s.jsonl:3: looks like github-token" in out
    assert "3 findings" in out


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("private-key", "-----BEGIN OPENSSH " + "PRIVATE KEY-----"),
        ("slack-token", "xo" + "xb-" + "1234567890-" + "abcdefABCDEF1234"),
        ("aws-access-key", "AK" + "IA" + "QWERTYUIOPASDFGH"),
        ("anthropic-key", "sk-" + "ant-api03-" + "Zx81Qw" * 15),
        ("1password-service-account", "op" + "s_eyJ" + "Zx81Qw" * 10),
    ],
)
def test_pattern_rules(c: Canary, name: str, text: str) -> None:
    c.watch(text)
    c.plant(".claude/x.txt", text + "\n")
    code, out, _ = scan(c)
    assert code == 1
    assert f"~/.claude/x.txt:1: looks like {name}" in out


def test_patterns_only_skips_1password(c: Canary) -> None:
    c.plant(".claude/x.txt", f"{CANARY}\n{GH_SHAPED}\n")
    code, out, _ = scan(c, "--patterns-only")
    assert code == 1
    assert "app-mail" not in out
    assert "looks like github-token" in out
    assert not c.children()


def test_a_value_1password_cannot_give_is_named_and_the_scan_is_incomplete(c: Canary) -> None:
    c.op_fail("op://Vault/generic app-mail/credential", code=6)  # its error text holds the canary
    code, out, err = scan(c)
    assert code == 2
    assert "could not read app-mail from 1Password (op exited 6" in out + err


def test_a_short_value_is_not_searched_and_says_so(c: Canary) -> None:
    c.op_value("op://Vault/generic app-mail/credential", "q7Z")
    code, out, _ = scan(c)
    assert code == 0
    assert "app-mail is too short to search for" in out


def test_values_are_read_through_op_only(c: Canary) -> None:
    scan(c)
    refs = [ch.argv for ch in c.children()]
    assert refs == [
        ["op", "read", "--no-newline", "op://Vault/generic app-mail/credential"],
        ["op", "read", "--no-newline", "op://Vault/cloudflare-token deploy-token/credential"],
    ]


def test_scan_lists_its_paths(c: Canary) -> None:
    (c.home / ".claude").mkdir()
    result = c.run(["scan", "--tmp-root", str(c.tmp), "--paths"])
    assert result.code == 0
    assert "~/.claude" in result.stdout
    assert "~/.zsh_history (not there)" in result.stdout


def test_scan_through_a_real_shell(c: Canary) -> None:
    c.plant(".claude/projects/p/s.jsonl", f"{CANARY}\n")
    result = c.shell(f"keys scan --tmp-root {c.tmp}")
    assert result.code == 1
    assert "~/.claude/projects/p/s.jsonl:1: app-mail (known value)" in result.stdout


# ---------------------------------------------------------------------------- scrub


def test_scrub_replaces_every_form_in_place(c: Canary) -> None:
    text = (
        f"a {CANARY} b\n"
        f"{json.dumps({'k': CANARY})}\n"
        f"{urllib.parse.quote(CANARY, safe='')}\n"
        f"{GH_SHAPED}\nkeep this line\n{OTHER}\n"
    )
    path = c.plant(".claude/projects/p/s.jsonl", text)
    path.chmod(0o600)
    c.unplant(path)  # scrub must change it; the harness checks it like any other file
    result = c.run(["scrub", str(path)])
    assert result.code == 0, result.stderr
    assert "replaced 5" in result.stdout
    after = path.read_text()
    assert "keep this line" in after
    assert after.count("[removed by keys scrub]") == 5
    assert path.stat().st_mode & 0o777 == 0o600
    assert sorted(p.name for p in path.parent.iterdir()) == ["s.jsonl"]


def test_scrub_of_a_clean_file_changes_nothing(c: Canary) -> None:
    path = c.plant(".claude/clean.txt", "nothing here\n")
    before = path.stat().st_mtime_ns
    result = c.run(["scrub", str(path)])
    assert result.code == 0
    assert "replaced 0" in result.stdout
    assert path.stat().st_mtime_ns == before


def test_scrub_of_a_missing_file(c: Canary) -> None:
    result = c.run(["scrub", str(c.home / "nope.txt")])
    assert result.code == 3
    assert "no such file" in result.stderr


def test_scrub_through_a_real_shell(c: Canary) -> None:
    path = c.plant(".claude/x.txt", f"{CANARY}\n")
    c.unplant(path)
    result = c.shell(f"keys scrub {path}")
    assert result.code == 0
    assert CANARY not in Path(path).read_text()


# ---------------------------------------------------------------------------- review fixes

PEM = (
    "-----BEGIN OPENSSH "
    + "PRIVATE KEY-----\n"
    + ("Zx81QwAbCdEf" * 6 + "\n") * 3
    + "-----END OPENSSH "
    + "PRIVATE KEY-----"
)


def test_a_file_named_after_a_value_is_not_printed(c: Canary) -> None:
    c.watch(OTHER)
    c.plant(f".claude/{OTHER}.txt", f"{GH_SHAPED}\n")
    code, out, _ = scan(c)
    assert code == 1
    assert "~/.claude/<name withheld>:1: looks like github-token" in out


def test_a_control_character_in_a_file_name_cannot_forge_a_line(c: Canary) -> None:
    c.plant(".claude/a\nb.txt", f"{CANARY}\n")
    code, out, _ = scan(c)
    assert code == 1
    # A control character makes the name look like a value: it is withheld, so it forges nothing.
    assert "~/.claude/<name withheld>:1: app-mail (known value)" in out
    assert "\nb.txt" not in out


def test_a_symlinked_root_is_followed(c: Canary) -> None:
    real = c.plant("dotfiles/claude/projects/p/s.jsonl", f"{CANARY}\n")
    (c.home / ".claude").symlink_to(real.parent.parent.parent)
    code, out, _ = scan(c)
    assert code == 1
    assert "~/.claude/projects/p/s.jsonl:1: app-mail (known value)" in out


def test_an_unreadable_folder_makes_the_scan_incomplete(c: Canary) -> None:
    locked = c.home / ".claude" / "locked"
    locked.mkdir(parents=True)

    def scan_locked(ctx: Any) -> int:
        locked.chmod(0)
        try:
            from keys import cli

            return cli.main(["scan", "--tmp-root", str(c.tmp)], ctx=ctx)
        finally:
            locked.chmod(0o700)

    result = c.call(scan_locked)
    assert result.code == 2
    assert "1 unreadable" in result.stdout


@pytest.mark.parametrize(
    "text",
    [
        base64.encodebytes(("x" * 40 + CANARY).encode()).decode(),  # wrapped at 76
        json.dumps(json.dumps({"text": CANARY})),  # tool output that was itself JSON
        CANARY.replace(" ", "\\ ").replace('"', '\\"'),  # shell-escaped in history
    ],
)
def test_more_forms_are_found(c: Canary, text: str) -> None:
    c.plant(".claude/x.txt", f"start\n{text}\n")
    code, out, _ = scan(c)
    assert code == 1, out
    assert "app-mail (known value)" in out


def test_a_utf16_copy_is_found(c: Canary) -> None:
    path = c.home / ".claude" / "x.bin"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"\x00\x01" + CANARY.encode("utf-16-le"))
    c.planted[path] = __import__("hashlib").sha256(path.read_bytes()).hexdigest()
    code, out, _ = scan(c)
    assert code == 1
    assert "~/.claude/x.bin:1: app-mail (known value)" in out


def test_a_multi_line_value_is_found(c: Canary) -> None:
    c.op_value("op://Vault/cloudflare-token deploy-token/credential", PEM)
    c.plant(".claude/key.txt", f"one\n{PEM}\n")
    code, out, _ = scan(c)
    assert code == 1
    assert "~/.claude/key.txt:2: deploy-token (known value)" in out


def test_a_value_stored_with_a_trailing_newline_is_found(c: Canary) -> None:
    c.op_value("op://Vault/generic app-mail/credential", CANARY + "\n")
    c.plant(".claude/x.jsonl", json.dumps({"t": CANARY}) + "\n")
    code, out, _ = scan(c)
    assert code == 1
    assert "app-mail (known value)" in out


def test_a_large_file_without_newlines_is_read_in_pieces(c: Canary) -> None:
    c.plant(".claude/big.txt", "x" * 3_000_000 + CANARY + "y" * 10)
    code, out, _ = scan(c)
    assert code == 1
    assert "~/.claude/big.txt:1: app-mail (known value)" in out


@pytest.mark.parametrize(
    "rel",
    [".claude.json", ".claude.json.backup", "Library/Caches/claude-cli-nodejs/mcp/log.txt"],
)
def test_more_places_are_scanned(c: Canary, rel: str) -> None:
    c.plant(rel, f"{CANARY}\n")
    code, _, _ = scan(c)
    assert code == 1


def test_histfile_and_zdotdir_are_scanned(c: Canary) -> None:
    c.plant("elsewhere/hist", f"{CANARY}\n")
    c.plant("zdot/.zsh_history", f"{CANARY}\n")
    env = {"HISTFILE": str(c.home / "elsewhere/hist"), "ZDOTDIR": str(c.home / "zdot")}
    result = c.run(["scan", "--tmp-root", str(c.tmp)], env=env)
    assert "~/elsewhere/hist:1:" in result.stdout
    assert "~/zdot/.zsh_history:1:" in result.stdout


@pytest.mark.parametrize(
    "rel",
    [
        "Library/Application Support/Claude/vm_bundles/disk.img",
        "Library/Application Support/Claude/Cache/x",
        ".cursor/extensions/some-ext/test/fixture.txt",
    ],
)
def test_caches_and_disk_images_are_skipped(c: Canary, rel: str) -> None:
    c.plant(rel, f"{CANARY}\n")
    code, _, _ = scan(c)
    assert code == 0


def test_scrub_removes_a_whole_private_key(c: Canary) -> None:
    c.watch(PEM.splitlines()[1])
    path = c.plant(".claude/k.txt", f"before\n{PEM}\nafter\n")
    c.unplant(path)
    result = c.run(["scrub", str(path)])
    assert result.code == 0, result.stderr
    assert path.read_text() == "before\n[removed by keys scrub]\nafter\n"


def test_scrub_removes_a_whole_base64_run(c: Canary) -> None:
    run = base64.b64encode(b"user:" + CANARY.encode()).decode()
    path = c.plant(".claude/b.txt", f"auth {run} end\n")
    c.unplant(path)
    result = c.run(["scrub", str(path)])
    assert result.code == 0, result.stderr
    assert path.read_text() == "auth [removed by keys scrub] end\n"


def test_scrub_refuses_a_binary_file(c: Canary) -> None:
    path = c.plant(".claude/state.vscdb", "x")
    path.write_bytes(b"SQLite format 3\x00" + CANARY.encode())
    c.planted[path] = __import__("hashlib").sha256(path.read_bytes()).hexdigest()
    result = c.run(["scrub", str(path)])
    assert result.code == 3
    assert "not a text file" in result.stderr


def test_scrub_rewrites_the_same_file(c: Canary) -> None:
    path = c.plant(".claude/s.jsonl", f"{CANARY}\n")
    c.unplant(path)
    inode = path.stat().st_ino
    result = c.run(["scrub", str(path)])
    assert result.code == 0
    assert path.stat().st_ino == inode
    assert "close any session still writing to it" in result.stdout


def test_one_value_inside_another_is_scrubbed_whole(c: Canary) -> None:
    longer = "prefix-" + OTHER + "-suffix"
    c.op_value("op://Vault/generic app-mail/credential", longer)
    path = c.plant(".claude/n.txt", f"{longer}\n")
    c.unplant(path)
    result = c.run(["scrub", str(path)])
    assert result.code == 0
    assert path.read_text() == "[removed by keys scrub]\n"
