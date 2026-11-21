"""What keys took over from the old key checker: the Key Vault and gitleaks-report key sources,
`keys leaks` (a gitleaks report's leaked values by fingerprint) and `keys fp`.

The planted report holds the canary on purpose, as a real unredacted report holds the leaked
value. The harness allows that while the file is unchanged, and checks that nothing else
(output, children, other files, history) ever holds it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from keys.fingerprint import fingerprint, hint
from keys.secret import Secret
from tests.canary import CANARY, Canary
from tests.test_check import FP_KEY, Recorder

ENV = {"FPK": FP_KEY, "KEYS_FP_KEY": "env:FPK"}
# Made up, built at run time so no scanner mistakes the test for a leak.
OTHER = "kc_" + "Zz9Qw" * 6 + "_other"
AZ_SHOW = ["az", "keyvault", "secret", "show", "--vault-name", "app-kv", "--name", "mail-key"]


def fp(value: str) -> str:
    return fingerprint(Secret(FP_KEY), Secret(value))


@pytest.fixture
def c(canary: Canary) -> Canary:
    # keys check prints the console-style hint of a provider's key; keys fp and leaks only
    # for a mapped provider kind, which those tests say themselves.
    canary.watch(FP_KEY)
    canary.watch(OTHER)
    return canary


def finding(secret: str, **over: str) -> dict[str, Any]:
    row: dict[str, Any] = {
        "RuleID": "generic-api-key",
        "Secret": secret,
        "Match": f"token = {secret}",
        "File": "src/app.py",
        "Commit": "aaaaaaaa1111",
        "Date": "2025-01-02T03:04:05Z",
        "Line": f"token = {secret}",
    }
    row.update(over)
    return row


def report(c: Canary, rows: list[dict[str, Any]], name: str = "report.json") -> Path:
    return c.plant(c.work / name, json.dumps(rows))


# ---------------------------------------------------------------------------- kv://


def test_a_key_from_key_vault(c: Canary) -> None:
    c.provider_issued = True
    c.kv_value("app-kv", "mail-key", CANARY)
    sender = Recorder(200)
    result = c.run(["check", "github", "--key", "kv://app-kv/mail-key"], env=ENV, send=sender)
    assert result.code == 0, result.stderr
    assert sender.calls[0][2]["Authorization"] == f"Bearer {CANARY}"
    assert result.children[0].argv == [*AZ_SHOW, "--query", "value", "--output", "json"]
    assert f"fp:{fp(CANARY)}" in result.stdout


def test_a_key_vault_failure_prints_only_its_exit_code(c: Canary) -> None:
    c.kv_fail("app-kv", "mail-key", code=7)  # az's error text holds the canary
    result = c.run(
        ["check", "github", "--key", "kv://app-kv/mail-key"], env=ENV, send=Recorder(200)
    )
    assert result.code == 3
    assert "az exited 7" in result.stderr


@pytest.mark.parametrize("source", ["kv://app-kv", "kv:///mail-key", "kv://a/b/c", "kv://a b/c"])
def test_a_malformed_key_vault_source_starts_nothing(c: Canary, source: str) -> None:
    result = c.run(["check", "github", "--key", source], env=ENV, send=Recorder(200))
    assert result.code == 3
    assert "kv://<vault>/<secret>" in result.stderr
    assert not result.children


def test_a_key_vault_child_sees_only_basic_variables(c: Canary) -> None:
    c.provider_issued = True
    c.kv_value("app-kv", "mail-key", CANARY)
    # A variable az would read, holding a watched value: az must not be handed it.
    env = {**ENV, "AZURE_CORE_LOG_HTTP": OTHER, "AZURE_CONFIG_DIR": "/cfg"}
    result = c.run(
        ["check", "github", "--key", "kv://app-kv/mail-key"], env=env, send=Recorder(200)
    )
    assert result.code == 0, result.stderr
    # The audit hook checks each child's environment: it would fail the test had OTHER or FPK
    # (the fingerprint key) reached az.


# ---------------------------------------------------------------------------- gitleaks:


def test_a_key_from_a_gitleaks_report(c: Canary) -> None:
    c.provider_issued = True
    report(c, [finding(CANARY), finding(CANARY, File="b.py"), finding(OTHER)])
    sender = Recorder(401)
    result = c.run(
        ["check", "github", "--key", f"gitleaks:report.json#{fp(CANARY)}", "--expect", "dead"],
        env=ENV,
        send=sender,
    )
    assert result.code == 0, result.stderr
    assert sender.calls[0][2]["Authorization"] == f"Bearer {CANARY}"
    assert not result.children


def test_a_short_fingerprint_prefix_is_enough_when_it_is_unique(c: Canary) -> None:
    c.provider_issued = True
    report(c, [finding(CANARY)])
    result = c.run(
        ["check", "github", "--key", f"gitleaks:report.json#{fp(CANARY)[:4]}"],
        env=ENV,
        send=Recorder(200),
    )
    assert result.code == 0, result.stderr


def _two_sharing_a_first_digit() -> tuple[str, str]:
    first = fp(CANARY)[0]
    for i in range(1000):
        other = f"kc_made_up_{i:04d}_" + "Qw" * 8
        if fp(other)[0] == first:
            return CANARY, other
    raise AssertionError("no made-up value shares a first digit")


def test_an_ambiguous_fingerprint_is_refused(c: Canary) -> None:
    a, b = _two_sharing_a_first_digit()
    c.watch(b)
    report(c, [finding(a), finding(b)])
    result = c.run(
        ["check", "github", "--key", f"gitleaks:report.json#{fp(a)[0]}"],
        env=ENV,
        send=Recorder(200),
    )
    assert result.code == 3
    assert "2 leaked values have that fingerprint" in result.stderr


@pytest.mark.parametrize(
    ("rows", "source", "message"),
    [
        ([finding("REDACTED")], "gitleaks:report.json#{fp}", "--redact"),
        ([finding(OTHER)], "gitleaks:report.json#{fp}", "no leaked value has that fingerprint"),
        ([finding(CANARY)], "gitleaks:report.json", "gitleaks:<report.json>#<fingerprint>"),
        ([finding(CANARY)], "gitleaks:report.json#zz", "gitleaks:<report.json>#<fingerprint>"),
        ([finding(CANARY)], "gitleaks:missing.json#{fp}", "cannot read the gitleaks report"),
    ],
)
def test_gitleaks_source_problems(
    c: Canary, rows: list[dict[str, Any]], source: str, message: str
) -> None:
    report(c, rows)
    result = c.run(
        ["check", "github", "--key", source.format(fp=fp(CANARY))], env=ENV, send=Recorder(200)
    )
    assert result.code == 3
    assert message in result.stderr


def test_a_report_that_is_not_gitleaks_json_is_refused(c: Canary) -> None:
    c.plant(c.work / "report.json", f"not json {CANARY}")
    result = c.run(
        ["check", "github", "--key", f"gitleaks:report.json#{fp(CANARY)}"],
        env=ENV,
        send=Recorder(200),
    )
    assert result.code == 3
    assert "not a gitleaks JSON report" in result.stderr


def test_the_fingerprint_key_cannot_come_from_a_report(c: Canary) -> None:
    report(c, [finding(CANARY)])
    result = c.run(
        ["check", "github", "--key", "env:K", "--fp-key", "gitleaks:report.json#00"],
        env={"K": CANARY},
        send=Recorder(200),
    )
    assert result.code == 3
    assert "unknown key source for the fingerprint key" in result.stderr


# ---------------------------------------------------------------------------- keys leaks


def test_leaks_lists_each_value_once_by_fingerprint(c: Canary) -> None:
    report(
        c,
        [
            finding(CANARY, File="a.py", Commit="aaaaaaaa11", Date="2025-01-02T00:00:00Z"),
            finding(CANARY, File="b.py", Commit="bbbbbbbb22", Date="2025-02-03T00:00:00Z"),
            finding(
                OTHER,
                RuleID="openai-api-key",
                File="c.py",
                Commit="cccccccc33",
                Date="2025-03-04T00:00:00Z",
            ),
        ],
    )
    result = c.run(["leaks", "report.json"], env=ENV)
    assert result.code == 1, result.stderr  # something leaked: the nightly-style exit
    lines = result.stdout.splitlines()
    assert lines[0] == (
        f"fp:{fp(CANARY)}  generic-api-key  a.py (+1 more)  2 findings in 2 commits, "
        "first aaaaaaaa, 2025-01-02..2025-02-03"
    )
    assert lines[1] == (
        f"fp:{fp(OTHER)}  openai-api-key  c.py  1 finding in 1 commit, "
        "first cccccccc, 2025-03-04..2025-03-04"
    )
    assert lines[-1] == "keys leaks: 2 leaked values in 3 findings"


def test_leaks_with_an_empty_report_is_clean(c: Canary) -> None:
    report(c, [])
    result = c.run(["leaks", "report.json"], env=ENV)
    assert result.code == 0
    assert "keys leaks: 0 leaked values" in result.stdout


def test_leaks_withholds_a_file_name_that_holds_the_value_or_looks_like_one(c: Canary) -> None:
    shaped = "Zx81Qw" + "AbCdEf" * 3  # made up: a long mixed run, as keys are
    c.watch(shaped)
    report(
        c,
        [
            finding(CANARY, File=f"notes/{CANARY[:12]}.txt"),
            finding(CANARY, File=f"cfg/{shaped}.env"),
        ],
    )
    result = c.run(["leaks", "report.json"], env=ENV)
    assert result.code == 1
    assert f"fp:{fp(CANARY)}  generic-api-key  cfg/<name withheld> (+1 more)  " in result.stdout


def test_leaks_withholds_odd_rule_commit_and_date_fields(c: Canary) -> None:
    report(c, [finding(CANARY, RuleID=CANARY[:20], Commit=CANARY[:12], Date=CANARY[:10])])
    result = c.run(["leaks", "report.json"], env=ENV)
    assert result.code == 1
    assert "<rule withheld>" in result.stdout
    assert "first -" in result.stdout


def test_leaks_refuses_a_redacted_report(c: Canary) -> None:
    report(c, [finding("REDACTED"), finding("REDACTED", File="b.py")])
    result = c.run(["leaks", "report.json"], env=ENV)
    assert result.code == 3
    assert "--redact" in result.stderr


@pytest.mark.parametrize("text", ["[1, 2]", '{"a": 1}', '[{"Secret": 5}]'])
def test_leaks_refuses_what_is_not_a_report(c: Canary, text: str) -> None:
    c.plant(c.work / "report.json", text)
    result = c.run(["leaks", "report.json"], env=ENV)
    assert result.code == 3
    assert "not a gitleaks JSON report" in result.stderr


def test_leaks_needs_the_fingerprint_key(c: Canary) -> None:
    report(c, [finding(CANARY)])
    result = c.run(["leaks", "report.json"])
    assert result.code == 3
    assert "fingerprint key" in result.stderr


def test_leaks_does_not_repeat_the_report_path(c: Canary) -> None:
    result = c.run(["leaks", f"{CANARY}.json"], env=ENV)
    assert result.code == 3
    assert "cannot read the gitleaks report" in result.stderr


def test_leaks_through_a_real_shell(c: Canary) -> None:
    report(c, [finding(CANARY)])
    result = c.shell("keys leaks report.json", env=ENV)
    assert result.code == 1, result.stderr
    assert f"fp:{fp(CANARY)}" in result.stdout


# ---------------------------------------------------------------------------- keys fp

MAPPING = """
[[credential]]
name = "deploy"
kind = "cloudflare-token"
item = "op://Vault/cloudflare-token deploy"
kept_because = "x"
fp = "{fp}"

[[credential]]
name = "signing"
kind = "generic"
item = "op://Vault/generic signing"
kept_because = "x"
"""


def mapping(c: Canary, recorded: str) -> None:
    (c.work / "keys.toml").write_text(MAPPING.format(fp=recorded))


def test_fp_of_a_source_prints_only_the_fingerprint(c: Canary) -> None:
    result = c.run(["fp", "--key", "env:K"], env={**ENV, "K": CANARY})
    assert result.code == 0, result.stderr
    assert result.stdout.strip() == f"fp:{fp(CANARY)}"


def test_fp_of_a_key_vault_source(c: Canary) -> None:
    c.kv_value("app-kv", "mail-key", CANARY)
    result = c.run(["fp", "--key", "kv://app-kv/mail-key"], env=ENV)
    assert result.code == 0, result.stderr
    assert result.stdout.strip() == f"fp:{fp(CANARY)}"


def test_fp_of_a_mapped_provider_key_shows_its_hint_and_agrees(c: Canary) -> None:
    c.provider_issued = True
    mapping(c, fp(CANARY))
    c.op_value("op://Vault/cloudflare-token deploy/credential", CANARY)
    result = c.run(["fp", "deploy"], env=ENV)
    assert result.code == 0, result.stderr
    assert result.stdout.strip() == (
        f"deploy cloudflare-token fp:{fp(CANARY)} {hint(Secret(CANARY))}: matches the mapping file"
    )


def test_fp_of_a_mapped_key_that_differs_from_the_mapping_fails(c: Canary) -> None:
    c.provider_issued = True
    mapping(c, "00000000")
    c.op_value("op://Vault/cloudflare-token deploy/credential", CANARY)
    result = c.run(["fp", "deploy"], env=ENV)
    assert result.code == 1
    assert "differs from the mapping file's fp:00000000" in result.stdout


def test_fp_of_a_generated_secret_shows_no_hint(c: Canary) -> None:
    mapping(c, "00000000")
    c.op_value("op://Vault/generic signing/credential", CANARY)
    result = c.run(["fp", "signing"], env=ENV)
    assert result.code == 0, result.stderr
    assert result.stdout.strip() == f"signing generic fp:{fp(CANARY)}: no fp in the mapping file"


def test_fp_of_a_mapped_key_when_1password_fails(c: Canary) -> None:
    mapping(c, "00000000")
    c.op_fail("op://Vault/generic signing/credential", code=6)
    result = c.run(["fp", "signing"], env=ENV)
    assert result.code == 3
    assert "op exited 6" in result.stderr


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["fp"], "keys fp <name> or keys fp --key <source>"),
        (["fp", "deploy", "--key", "env:K"], "keys fp <name> or keys fp --key <source>"),
        (["fp", "nobody"], "no credential by that name"),
        (["fp", CANARY], "no credential by that name"),
    ],
)
def test_fp_usage(c: Canary, argv: list[str], message: str) -> None:
    mapping(c, "00000000")
    result = c.run(argv, env={**ENV, "K": CANARY})
    assert result.code == 3
    assert message in result.stderr
    assert not result.children


def test_fp_through_a_real_shell(c: Canary) -> None:
    c.op_value("op://Vault/generic signing/credential", CANARY)
    mapping(c, "00000000")
    result = c.shell("keys fp signing", env=ENV)
    assert result.code == 0, result.stderr
    assert f"fp:{fp(CANARY)}" in result.stdout


# ---------------------------------------------------------------------------- review fixes


def test_leaks_withholds_a_file_path_that_holds_a_value_across_folders(c: Canary) -> None:
    slashed = "/".join(["AbCd" + "1234", "EfGh" + "5678", "IjKl" + "9012"])  # made up
    c.watch(slashed)
    report(c, [finding(slashed, File=f"cfg/{slashed}/x.env")])
    result = c.run(["leaks", "report.json"], env=ENV)
    assert result.code == 1
    assert "  <name withheld>  " in result.stdout


def test_leaks_withholds_a_rule_or_commit_that_holds_a_leaked_value(c: Canary) -> None:
    plain = "abcdef0123" + "456789"  # made up, hex: passes the commit and rule shapes
    c.watch(plain)
    report(c, [finding(plain, RuleID=f"rule-{plain}", Commit=plain + "ffff")])
    result = c.run(["leaks", "report.json"], env=ENV)
    assert result.code == 1
    assert "<rule withheld>" in result.stdout
    assert "first -" in result.stdout


@pytest.mark.parametrize("command", ["leaks", "check"])
def test_a_partly_redacted_report_is_refused(c: Canary, command: str) -> None:
    report(c, [finding(CANARY[:10] + "...")])
    argv = (
        ["leaks", "report.json"]
        if command == "leaks"
        else ["check", "github", "--key", f"gitleaks:report.json#{fp(CANARY[:10] + '...')}"]
    )
    result = c.run(argv, env=ENV, send=Recorder(401))
    assert result.code == 3
    assert "--redact" in result.stderr


def test_a_finding_whose_match_lacks_its_secret_is_refused(c: Canary) -> None:
    report(c, [finding(CANARY, Match="token = REDACTED")])
    result = c.run(["leaks", "report.json"], env=ENV)
    assert result.code == 3
    assert "--redact" in result.stderr


def test_a_secret_with_a_trailing_newline_has_one_fingerprint(c: Canary) -> None:
    c.provider_issued = True
    report(c, [finding(CANARY + "\n", Match=f"token = {CANARY}\n")])
    listed = c.run(["leaks", "report.json"], env=ENV)
    assert f"fp:{fp(CANARY)}  " in listed.stdout
    checked = c.run(
        ["check", "github", "--key", f"gitleaks:report.json#{fp(CANARY)}"],
        env=ENV,
        send=Recorder(200),
    )
    assert checked.code == 0, checked.stderr


def test_empty_secrets_are_skipped(c: Canary) -> None:
    report(c, [finding(""), finding(CANARY)])
    result = c.run(["leaks", "report.json"], env=ENV)
    assert result.stdout.splitlines()[-1] == "keys leaks: 1 leaked value in 1 finding"


def test_a_finding_outside_git_says_so(c: Canary) -> None:
    report(c, [finding(CANARY, Commit="", Date="")])
    result = c.run(["leaks", "report.json"], env=ENV)
    assert "1 finding, not in git" in result.stdout


def test_a_gitleaks_fingerprint_field_points_at_the_keys_fingerprint(c: Canary) -> None:
    report(c, [finding(CANARY)])
    result = c.run(
        ["check", "github", "--key", "gitleaks:report.json#abc123:src/app.py:generic-api-key:4"],
        env=ENV,
        send=Recorder(200),
    )
    assert result.code == 3
    assert "the fp: digits keys leaks prints" in result.stderr


def test_fp_of_a_key_can_show_the_hint(c: Canary) -> None:
    c.provider_issued = True
    result = c.run(["fp", "--key", "env:K", "--hint"], env={**ENV, "K": CANARY})
    assert result.code == 0, result.stderr
    assert result.stdout.strip() == f"fp:{fp(CANARY)} {hint(Secret(CANARY))}"


def test_fp_of_a_key_from_a_report(c: Canary) -> None:
    report(c, [finding(CANARY)])
    result = c.run(["fp", "--key", f"gitleaks:report.json#{fp(CANARY)}"], env=ENV)
    assert result.code == 0, result.stderr
    assert result.stdout.strip() == f"fp:{fp(CANARY)}"


def test_fp_refuses_key_and_fingerprint_key_both_on_stdin(c: Canary) -> None:
    result = c.run(["fp", "--key", "stdin"], stdin=CANARY, env={"KEYS_FP_KEY": "stdin"})
    assert result.code == 3
    assert "cannot both come from stdin" in result.stderr


def test_a_key_vault_value_is_kept_exactly(c: Canary) -> None:
    lines = "kc_line_one_" + "Qw" * 6 + "\nkc_line_two_" + "Er" * 6 + "\n"
    c.watch(lines)
    c.kv_value("app-kv", "mail-key", lines)
    result = c.run(["fp", "--key", "kv://app-kv/mail-key"], env=ENV)
    assert result.code == 0, result.stderr
    assert result.stdout.strip() == f"fp:{fp(lines)}"


def test_a_key_vault_secret_with_no_value_is_refused(c: Canary) -> None:
    c.kv_value("app-kv", "mail-key", None)
    result = c.run(["fp", "--key", "kv://app-kv/mail-key"], env=ENV)
    assert result.code == 3
    assert "no value" in result.stderr


@pytest.mark.parametrize(
    ("code", "message"),
    [(1, "not signed in"), (2, "did not understand"), (3, "no such secret")],
)
def test_az_exit_codes_have_fixed_messages(c: Canary, code: int, message: str) -> None:
    c.kv_fail("app-kv", "mail-key", code=code, stdout=True)  # prints the value while failing
    result = c.run(["fp", "--key", "kv://app-kv/mail-key"], env=ENV)
    assert result.code == 3
    assert f"az exited {code}" in result.stderr
    assert message in result.stderr


@pytest.mark.parametrize("error", ["timeout", "missing"])
def test_az_that_hangs_or_is_missing(
    c: Canary, monkeypatch: pytest.MonkeyPatch, error: str
) -> None:
    import subprocess

    from keys import proc

    def fail(argv: list[str], **_: Any) -> None:
        if error == "timeout":
            raise subprocess.TimeoutExpired(argv, 120)
        raise FileNotFoundError(argv[0])

    monkeypatch.setattr(proc.subprocess, "run", fail)
    result = c.run(["fp", "--key", "kv://app-kv/mail-key"], env=ENV)
    assert result.code == 3
    assert ("took longer" if error == "timeout" else "not installed") in result.stderr


def test_az_keeps_the_proxy_settings(c: Canary, monkeypatch: pytest.MonkeyPatch) -> None:
    from keys import proc

    seen: list[dict[str, str]] = []
    real = proc.run

    def record(argv: list[str], environ: dict[str, str], **kw: Any) -> proc.Done:
        seen.append(dict(environ))
        return real(argv, environ, **kw)

    monkeypatch.setattr(proc, "run", record)
    c.kv_value("app-kv", "mail-key", CANARY)
    env = {**ENV, "HTTPS_PROXY": "http://proxy.example:3128", "NO_PROXY": "localhost"}
    result = c.run(["fp", "--key", "kv://app-kv/mail-key"], env=env)
    assert result.code == 0, result.stderr
    assert seen[0]["HTTPS_PROXY"] == "http://proxy.example:3128"
    assert seen[0]["NO_PROXY"] == "localhost"
    assert "FPK" not in seen[0]
