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
