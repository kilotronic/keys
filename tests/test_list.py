"""keys list: the nightly check's core. Names, fingerprints, dates and problems; exit 1 on any."""

from __future__ import annotations

import datetime

from tests.canary import CANARY, Canary

TODAY = datetime.date(2026, 11, 21)
Q = f"'{CANARY}'"  # a TOML literal string: the canary holds " and \


def entry(name: str, **fields: object) -> str:
    lines = [
        "[[credential]]",
        f'name = "{name}"',
        'kind = "generic"',
        f'item = "op://Vault/generic {name}"',
    ]
    for k, v in fields.items():
        if isinstance(v, datetime.date):
            lines.append(f"{k} = {v.isoformat()}")
        elif isinstance(v, str) and v.startswith("'"):
            lines.append(f"{k} = {v}")
        else:
            lines.append(f'{k} = "{v}"')
    return "\n".join(lines) + "\n"


def days(n: int) -> datetime.date:
    return TODAY + datetime.timedelta(days=n)


def write(canary: Canary, text: str) -> None:
    canary.plant(canary.work / "keys.toml", text)


def lines_by_name(stdout: str) -> dict[str, str]:
    return {line.split()[0]: line for line in stdout.splitlines() if line.strip()}


def test_a_healthy_credential(canary: Canary) -> None:
    write(
        canary,
        entry(
            "app-mail", kept_because="no OIDC", fp="1a2b3c4d", rotated=days(-10), expires=days(170)
        ),
    )
    result = canary.run(["list"], today=lambda: TODAY)
    assert result.code == 0, result.stderr
    row = lines_by_name(result.stdout)["app-mail"]
    for part in ("generic", "fp:1a2b3c4d", days(170).isoformat(), "170", "180"):
        assert part in row
    assert "1 credential kept, no problems" in result.stdout


def test_each_problem_is_flagged_and_fails(canary: Canary) -> None:
    write(
        canary,
        entry("no-expiry", kept_because="x", rotated=days(-5))
        + entry("too-long", kept_because="x", rotated=days(-1), expires=days(200))
        + entry("expires-far", kept_because="x", expires=days(181))
        + entry("old", kept_because="x", rotated=days(-181), expires=days(-1))
        + entry("no-reason", rotated=days(-1), expires=days(100))
        + entry("blank-reason", kept_because="  ", rotated=days(-1), expires=days(100)),
    )
    result = canary.run(["list"], today=lambda: TODAY)
    assert result.code == 1
    rows = lines_by_name(result.stdout)
    assert "no expiry" in rows["no-expiry"]
    assert "lifetime 201 days, over 180" in rows["too-long"]
    assert "expires in 181 days, over 180" in rows["expires-far"]
    assert "rotated 181 days ago, over 180" in rows["old"]
    assert "expired" in rows["old"]
    assert "no kept_because" in rows["no-reason"]
    assert "no kept_because" in rows["blank-reason"]
    assert "6 with problems" in result.stdout


def test_day_120_is_a_warning_not_a_failure(canary: Canary) -> None:
    write(canary, entry("due", kept_because="x", rotated=days(-120), expires=days(60)))
    result = canary.run(["list"], today=lambda: TODAY)
    assert result.code == 0
    assert "due: rotated 120 days ago" in lines_by_name(result.stdout)["due"]


def test_the_kept_budget(canary: Canary) -> None:
    ok = entry("a", kept_because="x", rotated=days(-1), expires=days(100))
    write(canary, "kept_budget = 1\n" + ok + ok.replace('"a"', '"b"').replace(" a", " b"))
    result = canary.run(["list"], today=lambda: TODAY)
    assert result.code == 1
    assert "2 credentials kept, over the budget of 1" in result.stdout


def test_mapping_path_from_flag_and_environment(canary: Canary) -> None:
    other = canary.work / "elsewhere.toml"
    canary.plant(other, entry("x", kept_because="y", rotated=days(-1), expires=days(9)))
    for argv, env in (
        (["list", "--mapping", str(other)], {}),
        (["list"], {"KEYS_MAPPING": str(other)}),
    ):
        result = canary.run(argv, env=env, today=lambda: TODAY)
        assert result.code == 0, result.stderr
        assert "x" in lines_by_name(result.stdout)


def test_a_bad_mapping_is_a_usage_error_naming_the_field_only(canary: Canary) -> None:
    write(canary, entry("a", expires=Q, owner=Q, kept_because=Q))
    result = canary.run(["list"], today=lambda: TODAY)
    assert result.code == 3
    assert "credential[0] (a).expires: must be a date" in result.stderr


def test_a_missing_mapping(canary: Canary) -> None:
    result = canary.run(["list"])
    assert result.code == 3
    assert "no mapping file at" in result.stderr


def test_a_value_pasted_into_a_text_field_is_never_listed(canary: Canary) -> None:
    write(canary, entry("a", owner=Q, kept_because=Q, rotated=days(-1), expires=days(9)))
    result = canary.run(["list"], today=lambda: TODAY)
    assert result.code == 0


def test_list_through_a_real_shell(canary: Canary) -> None:
    write(canary, entry("a", owner=Q, kept_because=Q, rotated=days(-1), expires=days(9)))
    result = canary.shell("keys list")
    assert "a" in lines_by_name(result.stdout)
