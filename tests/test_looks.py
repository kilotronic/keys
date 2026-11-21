"""keys.looks: the one answer to "does this text look like a value?", and the four places that ask.

Every key-shaped string here is made up and built at run time, so no token-shaped literal sits in
the source for a secret scanner to trip on.
"""

from __future__ import annotations

import json

import pytest

from keys import looks
from tests.canary import Canary

MIXED_RUN = "Zx81Qw" + "AbCdEf" * 3  # 24 letters and digits with no space, as keys are
LETTERS_RUN = "Authentication" + "FailedEverywhere"  # long, but a word: no digit
GH_SHAPED = "gh" + "p_" + "Zx81Qw" * 6
UUID = "3f2b9c1e-" + "8a4d-4e6f-9b0c-" + "7d5e1a2b3c4d"
HEXISH = "9f8e7d6c5b4a" + "39281706f5e4d3c2"


# ---------------------------------------------------------------------------- the one rule


@pytest.mark.parametrize(
    "text",
    [
        "the provider has no OIDC sign-in",
        "see https://example.com/org/repo/issues/123 for why",
        "Automation",
        LETTERS_RUN,
        "invalid_client",
        "",
    ],
)
def test_plain_text_does_not_look_like_a_value(text: str) -> None:
    assert not looks.looks_like_value(text)


@pytest.mark.parametrize(
    "text",
    [
        MIXED_RUN,
        f"because {MIXED_RUN}",
        GH_SHAPED,
        f"see {GH_SHAPED} here",
        UUID,
        HEXISH,
        "x\x7fy",
        "tab\tinside",
        "a\ud800b",
        "-----BEGIN RSA " + "PRIVATE KEY-----",
    ],
)
def test_a_value_shape_looks_like_a_value(text: str) -> None:
    assert looks.looks_like_value(text)


def test_a_url_holding_a_key_still_looks_like_one() -> None:
    assert looks.looks_like_value(f"https://example.com/hook?token={GH_SHAPED}")


def test_every_shape_rule_is_in_the_module() -> None:
    assert "github-token" in looks.SHAPES
    from keys import scanning

    assert scanning.PATTERNS is looks.SHAPES


# ---------------------------------------------------------------------------- names (keys new)


@pytest.mark.parametrize("name", ["app-thing", "deploy", "partygame-resend"])
def test_a_short_name_is_fine(name: str) -> None:
    assert not looks.name_looks_like_value(name)


@pytest.mark.parametrize(
    "name", [UUID, HEXISH, "app-" + HEXISH, "app-" + "abcdefghijklmnopq", MIXED_RUN.lower()]
)
def test_a_name_shaped_like_a_value(name: str) -> None:
    assert looks.name_looks_like_value(name)


# ---------------------------------------------------------------------------- file names (scan)


@pytest.mark.parametrize(
    "part",
    [
        f"{UUID}.jsonl",  # a Claude session transcript: named today, still named
        UUID,  # a file-history folder
        "-Users-jason-Code-gh-keys-wt-looks2",  # a Claude project folder
        "-private-tmp-claude-501-Users-jason-Code-gh-auditor",
        "agent-a1b2c3d4e5f6a7b8c.jsonl",
        "snapshot-zsh-1732212345-abc123.sh",
        "history.jsonl",
    ],
)
def test_file_names_keys_names_today_stay_named(part: str) -> None:
    assert not looks.file_name_looks_like_value(part)


@pytest.mark.parametrize(
    "part",
    [f"{GH_SHAPED}.txt", f"{MIXED_RUN}.txt", f"notes-{MIXED_RUN}", "a\x7fb", HEXISH + ".log"],
)
def test_a_file_name_shaped_like_a_value_is_withheld(part: str) -> None:
    assert looks.file_name_looks_like_value(part)


# ---------------------------------------------------------------------------- error codes (check)


@pytest.mark.parametrize(
    "code",
    ["invalid_client", "AuthenticationFailed", "KeyBasedAuthenticationNotPermitted", "a.b:c-d"],
)
def test_a_plain_error_code(code: str) -> None:
    assert looks.plain_code(code)


@pytest.mark.parametrize("code", ["", "has space", MIXED_RUN, GH_SHAPED, UUID, "x" * 61, "a\nb"])
def test_an_error_code_that_could_hold_a_value(code: str) -> None:
    assert not looks.plain_code(code)


# ---------------------------------------------------------------------------- field names (mapping)


@pytest.mark.parametrize("key", ["expire", "kept_becaus", "_x", "a-b"])
def test_a_plain_field_name(key: str) -> None:
    assert looks.plain_key(key)


@pytest.mark.parametrize("key", ["", "1abc", "has space", "a" * 33, MIXED_RUN, UUID, "a.b"])
def test_a_field_name_that_could_be_a_value(key: str) -> None:
    assert not looks.plain_key(key)


# ---------------------------------------------------------------------------- each place asks it


def test_scan_withholds_a_file_name_that_is_a_long_mixed_run(canary: Canary) -> None:
    canary.watch(MIXED_RUN)
    canary.watch(GH_SHAPED)
    canary.plant(f".claude/{MIXED_RUN}.txt", f"{GH_SHAPED}\n")
    canary.plant(f".claude/projects/p/{UUID}.jsonl", f"{GH_SHAPED}\n")
    result = canary.run(["scan", "--patterns-only", "--tmp-root", str(canary.tmp)])
    assert result.code == 1
    assert "~/.claude/<name withheld>:1: looks like github-token" in result.stdout
    assert f"~/.claude/projects/p/{UUID}.jsonl:1: looks like github-token" in result.stdout


def test_check_drops_an_error_code_shaped_like_a_value(canary: Canary) -> None:
    from keys import probes

    other = "Qm7" + "Lr2Xv9Pw4" * 3  # made up, and not the key: only its shape is a value's
    canary.watch(other)
    canary.provider_issued = True  # check prints the console-style hint for provider keys

    def sender(method: str, url: str, headers: dict[str, str], data: bytes | None) -> probes.Answer:
        return probes.Answer(401, json.dumps({"error": {"code": other}}))

    fp = "fp-key-made-up-for-tests-0123456789"
    canary.watch(fp)
    result = canary.run(
        ["check", "openai", "--key", "env:K"],
        env={"K": canary.value, "FPK": fp, "KEYS_FP_KEY": "env:FPK"},
        send=sender,
    )
    assert result.code == 1
    assert "DEAD (HTTP 401 from api.openai.com/v1/models)" in result.stdout


def test_new_refuses_a_uuid_in_the_reason(canary: Canary) -> None:
    canary.watch(UUID)
    result = canary.run(["new", "generic", "a", "--vault", "V", "--kept-because", f"x {UUID}"])
    assert result.code == 3
    assert not canary.children()


def test_new_refuses_a_name_with_a_secret_shape(canary: Canary) -> None:
    result = canary.run(
        ["new", "generic", "a", "--vault", "V", "--kept-because", "x", "--owner", "ab\tc"]
    )
    assert result.code == 3
    assert not canary.children()
