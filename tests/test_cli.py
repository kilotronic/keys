"""The command line itself: help, unknown commands, and the one top-level error handler."""

from __future__ import annotations

import io

from keys import cli


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(argv, ctx=cli.Context(stdout=out, stderr=err))
    return code, out.getvalue(), err.getvalue()


def test_help_names_every_phase_one_command() -> None:
    code, out, _ = run(["--help"])
    assert code == 0
    for command in ("list", "check", "scan", "scrub", "new"):
        assert command in out


def test_no_command_is_a_usage_error() -> None:
    code, _, err = run([])
    assert code == 3
    assert "usage" in err
