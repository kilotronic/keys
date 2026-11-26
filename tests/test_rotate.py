"""keys rotate: the eight steps, the paste flow, and the rollback, through the canary harness.

The old key is the canary, held in a fake 1Password item; the provider fakes mint fresh random
values that the canary also watches. Each failure test fails one step and then checks the exact
state left in 1Password, at the targets and at the provider.
"""

from __future__ import annotations

import datetime
import tomllib
from typing import Any

import pytest

from keys import kinds
from keys.fingerprint import fingerprint
from keys.secret import Secret
from tests.canary import CANARY, Canary
from tests.fake_providers import CF, Providers, days, made_up

TODAY = datetime.date(2026, 11, 21)
FP_KEY = "fp-key-made-up-for-tests-0123456789"
ENV = {"FPK": FP_KEY, "KEYS_FP_KEY": "env:FPK"}
VAULT = "Automation"
CF_ITEM = "cloudflare-token deploy"
MINTER_ITEM = "cloudflare-token cf-minter"
POLICIES = [
    {
        "id": "policy-1",
        "effect": "allow",
        "resources": {"com.cloudflare.api.account.zone.z1": "*"},
        "permission_groups": [{"id": "pg-1", "name": "Workers Scripts Write"}],
    }
]
CONDITION = {"request.ip": {"in": ["192.0.2.0/24"]}}

GH_ENV = "gh:owner/app:env:production:CLOUDFLARE_API_TOKEN"
KV = "az:app-kv:cf-token"
RW = "railway:proj:app:production:CF_TOKEN"

CF_MAPPING = f"""
[[credential]]
name = "cf-minter"
kind = "cloudflare-token"
item = "op://{VAULT}/{MINTER_ITEM}"
kept_because = "it mints the deploy tokens"

[[credential]]
name = "deploy"
kind = "cloudflare-token"
item = "op://{VAULT}/{CF_ITEM}"
minted_by = "cf-minter"
kept_because = "no OIDC sign-in for Workers deploys"
rotated = 2026-06-01
expires = 2026-11-28

[[credential.target]]
type = "github-actions-env"
repo = "owner/app"
environment = "production"
secret = "CLOUDFLARE_API_TOKEN"

[[credential.target]]
type = "azure-key-vault"
vault = "app-kv"
secret = "cf-token"

[[credential.target]]
type = "railway"
project = "proj"
service = "app"
environment = "production"
variable = "CF_TOKEN"
"""


def fp(value: str) -> str:
    return fingerprint(Secret(FP_KEY), Secret(value))


def entry(c: Canary, name: str) -> dict[str, Any]:
    doc = tomllib.loads((c.work / "keys.toml").read_text())
    return next(e for e in doc["credential"] if e["name"] == name)


@pytest.fixture
def cf(canary: Canary) -> tuple[Canary, Providers]:
    c = canary
    c.watch(FP_KEY)
    minter = made_up("mint")
    c.op_item(VAULT, CF_ITEM, {"credential": CANARY, "token_id": "cf-old", "account_id": ""})
    c.op_item(VAULT, MINTER_ITEM, {"credential": minter, "token_id": "cf-mint", "account_id": ""})
    c.never_written.append(minter)
    c.gh_main_only("owner/app", "production")
    c.target_put(GH_ENV, CANARY)
    c.target_put(KV, CANARY, tags={})
    c.target_put(RW, CANARY)
    (c.work / "keys.toml").write_text(CF_MAPPING)
    p = Providers(c)
    p.add("cloudflare", CANARY, "cf-old", policies=POLICIES, condition=CONDITION, name="deploy")
    p.add("cloudflare", minter, "cf-mint", can_mint=True)
    return c, p


def rotate(c: Canary, p: Providers, *argv: str) -> Any:
    return c.run(["rotate", *argv], env=ENV, send=p, today=lambda: TODAY)


def new_value(p: Providers) -> str:
    assert len(p.minted) == 1
    return p.minted[0]


def untouched(c: Canary, p: Providers) -> None:
    """1Password, the targets and the provider are as they were before the run."""
    fields = c.op_fields(VAULT, CF_ITEM)
    assert fields["credential"] == CANARY
    assert fields["token_id"] == "cf-old"
    assert not fields.get("pending")
    assert not fields.get("previous")
    for key in (GH_ENV, KV, RW):
        assert c.target(key)["value"] == CANARY  # type: ignore[index]
    assert CANARY in p.keys["cloudflare"]
    assert entry(c, "deploy")["rotated"] == datetime.date(2026, 6, 1)


# ---------------------------------------------------------------------------- the whole way


def test_a_cloudflare_token_is_replaced_end_to_end(cf: tuple[Canary, Providers]) -> None:
    c, p = cf
    result = rotate(c, p, "deploy")
    assert result.code == 0, result.stderr
    new = new_value(p)
    # The new token copies the old one's policies and IP condition, expires within 180 days,
    # and is named for the credential and the day.
    minted = p.keys["cloudflare"][new]
    assert minted.policies == [
        {k: v for k, v in POLICIES[0].items() if k != "id"}
        | {"permission_groups": [{"id": "pg-1"}]}
    ]
    assert minted.condition == CONDITION
    assert minted.expires == f"{days(TODAY, 180)}T00:00:00Z"
    assert minted.name == "deploy 2026-11-21"
    # 1Password holds only the new key; the old one is revoked at the provider.
    fields = c.op_fields(VAULT, CF_ITEM)
    assert fields["credential"] == new
    assert fields["token_id"] == minted.ident
    assert not fields["pending"]
    assert not fields["previous"]
    assert not fields["previous_id"]
    assert CANARY not in p.keys["cloudflare"]
    # Every target holds the new key; Key Vault carries its fingerprint; Railway redeployed.
    for key in (GH_ENV, KV, RW):
        assert c.target(key)["value"] == new, key  # type: ignore[index]
    assert c.target(KV)["tags"] == {"keys-fp": fp(new)}  # type: ignore[index]
    assert c.deploys("railway:proj:app:production:")[0]["id"] != "d0"
    # The mapping file records the new fingerprint, today and the expiry.
    e = entry(c, "deploy")
    assert (e["fp"], e["rotated"], e["expires"]) == (
        fp(new),
        TODAY,
        TODAY + datetime.timedelta(180),
    )
    assert f"fp:{fp(new)}" in result.stdout
    assert "commit the mapping file" in result.stdout
    for step in range(1, 9):
        assert f"deploy: {step} " in result.stdout, step


def test_the_mapping_file_keeps_everything_else(cf: tuple[Canary, Providers]) -> None:
    c, p = cf
    before = (c.work / "keys.toml").read_text()
    assert rotate(c, p, "deploy").code == 0
    after = (c.work / "keys.toml").read_text()
    assert after.startswith(before.split("rotated = 2026-06-01")[0])
    assert entry(c, "cf-minter") == tomllib.loads(before)["credential"][0]
    assert len(tomllib.loads(after)["credential"][1]["target"]) == 3


def test_a_resend_key_is_replaced_and_keeps_its_permission(canary: Canary) -> None:
    c = canary
    c.watch(FP_KEY)
    admin = made_up("re_admin")
    item, admin_item = "resend-key app-mail", "resend-key resend-admin"
    c.op_item(
        VAULT,
        item,
        {"credential": CANARY, "key_id": "re-old", "domain_id": "dom-1", "permission": ""},
    )
    c.op_item(VAULT, admin_item, {"credential": admin, "key_id": "re-admin"})
    c.target_put("gh:owner/app:RESEND_API_KEY", CANARY)
    (c.work / "keys.toml").write_text(
        f'[[credential]]\nname = "resend-admin"\nkind = "resend-key"\n'
        f'item = "op://{VAULT}/{admin_item}"\nkept_because = "mints the sending keys"\n\n'
        f'[[credential]]\nname = "app-mail"\nkind = "resend-key"\nitem = "op://{VAULT}/{item}"\n'
        'minted_by = "resend-admin"\nkept_because = "Resend has no OIDC sign-in"\n\n'
        '[[credential.target]]\ntype = "github-actions"\nrepo = "owner/app"\n'
        'secret = "RESEND_API_KEY"\n'
    )
    p = Providers(c)
    p.add("resend", CANARY, "re-old", permission="sending_access")
    p.add("resend", admin, "re-admin", permission="full_access")
    result = rotate(c, p, "app-mail")
    assert result.code == 0, result.stderr
    new = new_value(p)
    assert p.keys["resend"][new].permission == "sending_access"
    assert CANARY not in p.keys["resend"]
    assert c.target("gh:owner/app:RESEND_API_KEY")["value"] == new  # type: ignore[index]
    e = entry(c, "app-mail")
    assert e["fp"] == fp(new)
    assert e["rotated"] == TODAY
    assert "expires" not in e  # Resend keys do not expire; the rotation date counts


def test_resend_mint_sends_the_domain_and_permission(canary: Canary) -> None:
    from keys import rotators

    body = rotators.resend_mint_body("app-mail 2026-11-21", {"domain_id": "dom-1"})
    assert body == {
        "name": "app-mail 2026-11-21",
        "permission": "sending_access",
        "domain_id": "dom-1",
    }
    body = rotators.resend_mint_body("x", {"permission": "full_access", "domain_id": ""})
    assert body == {"name": "x", "permission": "full_access"}


# ---------------------------------------------------------------------------- dry run


def test_a_dry_run_writes_nothing_and_reads_no_value(cf: tuple[Canary, Providers]) -> None:
    c, p = cf
    result = rotate(c, p, "deploy", "--dry-run")
    assert result.code == 0, result.stderr
    untouched(c, p)
    assert p.calls == []
    progs = [ch.argv[:3] for ch in c.children()]
    assert ["op", "item", "edit"] not in progs
    assert not any(ch.argv[:2] == ["op", "read"] for ch in c.children())
    assert not any(ch.argv[:3] == ["op", "item", "get"] for ch in c.children())
    assert not [ch for ch in c.children() if ch.stdin]
    for word in ("mint", "probe", "sync", "revoke", "record"):
        assert word in result.stdout
    assert "nothing was changed" in result.stdout


def test_a_dry_run_through_a_real_shell(cf: tuple[Canary, Providers]) -> None:
    c, _ = cf
    result = c.shell("keys rotate deploy --dry-run", env=ENV)
    assert result.code == 0, result.stderr
    assert "nothing was changed" in result.stdout


# ---------------------------------------------------------------------------- step 1: preflight


def test_an_environment_that_admits_more_than_main_stops_it(cf: tuple[Canary, Providers]) -> None:
    c, p = cf
    c.gh_main_only("owner/app", "production", ["main", "dev"])
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "admits more than main" in result.stderr
    assert p.minted == []
    untouched(c, p)


def test_a_missing_environment_stops_it(cf: tuple[Canary, Providers]) -> None:
    c, p = cf
    c.set_db("gh_api", {})
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert p.minted == []
    untouched(c, p)


def test_an_unreachable_target_stops_it(cf: tuple[Canary, Providers]) -> None:
    c, p = cf
    c.child_fails(["az", "keyvault", "secret", "list"], code=2)
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "az exited 2" in result.stderr
    assert p.minted == []
    untouched(c, p)


def test_an_unreadable_minting_key_stops_it(cf: tuple[Canary, Providers]) -> None:
    c, p = cf
    c.child_fails(["op", "item", "get", MINTER_ITEM], code=6)
    result = rotate(c, p, "deploy")
    assert result.code == 3
    assert "op exited 6" in result.stderr
    assert p.minted == []
    untouched(c, p)


def test_a_mint_kind_without_minted_by_is_refused(cf: tuple[Canary, Providers]) -> None:
    c, p = cf
    text = CF_MAPPING.replace('minted_by = "cf-minter"\n', "")
    (c.work / "keys.toml").write_text(text)
    result = rotate(c, p, "deploy")
    assert result.code == 3
    assert "minted_by" in result.stderr
    assert not c.children()


def test_an_unknown_name_is_not_echoed(cf: tuple[Canary, Providers]) -> None:
    c, p = cf
    result = rotate(c, p, CANARY)
    assert result.code == 3
    assert "no credential by that name" in result.stderr


# ---------------------------------------------------------------------------- step 2: create


def test_a_failed_mint_changes_nothing(cf: tuple[Canary, Providers]) -> None:
    c, p = cf
    p.fail("POST", CF, 500)
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "HTTP 500" in result.stderr
    assert "fake_failure" in result.stderr
    untouched(c, p)


def test_a_mint_whose_pending_write_fails_is_revoked_at_once(
    cf: tuple[Canary, Providers],
) -> None:
    c, p = cf
    c.child_fails(["op", "item", "edit"], code=5)
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "op exited 5" in result.stderr
    new = new_value(p)
    assert new not in p.keys["cloudflare"]  # revoked: it existed nowhere else
    untouched(c, p)


# ---------------------------------------------------------------------------- step 3: probe


def test_a_new_key_that_does_not_work_is_revoked_and_pending_cleared(
    cf: tuple[Canary, Providers],
) -> None:
    c, p = cf
    p.mint_status = "disabled"
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "3 probe" in result.stderr
    new = new_value(p)
    assert new not in p.keys["cloudflare"]
    untouched(c, p)
    assert not c.op_fields(VAULT, CF_ITEM)["pending_id"]


# ---------------------------------------------------------------------------- step 4: store


def test_a_failed_store_leaves_pending_and_a_rerun_finishes(
    cf: tuple[Canary, Providers],
) -> None:
    c, p = cf
    c.child_fails(["op", "item", "edit"], code=5, skip=1)  # the pending write works, the store not
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "4 store" in result.stderr
    new = new_value(p)
    fields = c.op_fields(VAULT, CF_ITEM)
    assert (fields["credential"], fields["pending"]) == (CANARY, new)
    assert c.target(GH_ENV)["value"] == CANARY  # type: ignore[index]
    c.clear_child_fails()
    result = rotate(c, p, "deploy")
    assert result.code == 0, result.stderr
    assert len(p.minted) == 1  # resumed: nothing minted twice
    assert c.op_fields(VAULT, CF_ITEM)["credential"] == new


# ---------------------------------------------------------------------------- steps 5-6: rollback


def test_a_failed_sync_puts_the_old_key_back_everywhere(cf: tuple[Canary, Providers]) -> None:
    c, p = cf
    c.child_fails(["railway", "variable", "set"], code=7)  # after GitHub and Key Vault
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "5 sync" in result.stderr
    assert "rolled back" in result.stderr
    new = new_value(p)
    assert new not in p.keys["cloudflare"]  # the new key is revoked
    untouched(c, p)
    assert c.target(GH_ENV)["writes"] == 2  # type: ignore[index]
    assert c.target(KV)["tags"] == {"keys-fp": fp(CANARY)}  # type: ignore[index]


def test_rotate_reaches_a_github_owner_with_its_own_token(canary: Canary) -> None:
    # The Environment's rules (step 1), the secret (step 5) and the verify run (step 6) all
    # take the owner's KEYS_GH_TOKEN_<OWNER>; GH_TOKEN here belongs to another owner.
    c = canary
    c.watch(FP_KEY)
    minter = made_up("mint")
    c.op_item(VAULT, CF_ITEM, {"credential": CANARY, "token_id": "cf-old", "account_id": ""})
    c.op_item(VAULT, MINTER_ITEM, {"credential": minter, "token_id": "cf-mint", "account_id": ""})
    c.never_written.append(minter)
    c.gh_main_only("owner/app", "production")
    c.target_put(GH_ENV, CANARY)
    c.target_put("gh:owner/app:CF", CANARY)
    (c.work / "keys.toml").write_text(
        CF_MAPPING.split("[[credential.target]]")[0]
        + '[[credential.target]]\ntype = "github-actions-env"\nrepo = "owner/app"\n'
        'environment = "production"\nsecret = "CLOUDFLARE_API_TOKEN"\n\n'
        '[[credential.target]]\ntype = "github-actions"\nrepo = "owner/app"\nsecret = "CF"\n'
        'verify = { workflow = "deploy.yml" }\n'
    )
    p = Providers(c)
    p.add("cloudflare", CANARY, "cf-old", policies=POLICIES, condition=CONDITION, name="deploy")
    p.add("cloudflare", minter, "cf-mint", can_mint=True)
    c.set_db("gh_tokens", {"owner": "owner-token-made-up"})
    env = {**ENV, "GH_TOKEN": "another-owner-token-made-up"}
    env["KEYS_GH_TOKEN_OWNER"] = "owner-token-made-up"
    result = c.run(["rotate", "deploy"], env=env, send=p, today=lambda: TODAY)
    assert result.code == 0, result.stderr
    new = new_value(p)
    assert c.target(GH_ENV)["value"] == new  # type: ignore[index]
    assert c.target("gh:owner/app:CF")["value"] == new  # type: ignore[index]
    gh = [ch for ch in c.children() if ch.prog == "gh"]
    assert [ch for ch in gh if ch.argv[:3] == ["gh", "run", "watch"]]
    assert not [n for ch in gh for n in ch.env if n.startswith("KEYS_GH_TOKEN_")]


def test_a_failed_verify_puts_the_old_key_back(canary: Canary) -> None:
    c = canary
    c.watch(FP_KEY)
    minter = made_up("mint")
    c.op_item(VAULT, CF_ITEM, {"credential": CANARY, "token_id": "cf-old", "account_id": ""})
    c.op_item(VAULT, MINTER_ITEM, {"credential": minter, "token_id": "cf-mint", "account_id": ""})
    c.target_put("gh:owner/app:CF", CANARY)
    (c.work / "keys.toml").write_text(
        CF_MAPPING.split("[[credential.target]]")[0]
        + '[[credential.target]]\ntype = "github-actions"\nrepo = "owner/app"\nsecret = "CF"\n'
        'verify = { workflow = "deploy.yml" }\n'
    )
    p = Providers(c)
    p.add("cloudflare", CANARY, "cf-old", policies=POLICIES)
    p.add("cloudflare", minter, "cf-mint", can_mint=True)
    c.set_db("run_result", 1)
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "6 verify" in result.stderr
    assert c.target("gh:owner/app:CF")["value"] == CANARY  # type: ignore[index]
    assert c.op_fields(VAULT, CF_ITEM)["credential"] == CANARY
    assert new_value(p) not in p.keys["cloudflare"]
    runs = [ch.argv for ch in c.children() if ch.argv[:3] == ["gh", "run", "watch"]]
    assert len(runs) == 1
    assert "--interval" in runs[0]
    assert "--exit-status" in runs[0]


def test_a_passing_workflow_is_dispatched_once_and_watched_once(canary: Canary) -> None:
    c = canary
    c.watch(FP_KEY)
    minter = made_up("mint")
    c.op_item(VAULT, CF_ITEM, {"credential": CANARY, "token_id": "cf-old", "account_id": ""})
    c.op_item(VAULT, MINTER_ITEM, {"credential": minter, "token_id": "cf-mint", "account_id": ""})
    (c.work / "keys.toml").write_text(
        CF_MAPPING.split("[[credential.target]]")[0]
        + '[[credential.target]]\ntype = "github-actions"\nrepo = "owner/app"\nsecret = "CF"\n'
        'verify = { workflow = "deploy.yml" }\n'
    )
    p = Providers(c)
    p.add("cloudflare", CANARY, "cf-old", policies=POLICIES)
    p.add("cloudflare", minter, "cf-mint", can_mint=True)
    result = rotate(c, p, "deploy")
    assert result.code == 0, result.stderr
    dispatched = [ch.argv for ch in c.children() if ch.argv[:3] == ["gh", "workflow", "run"]]
    assert dispatched == [
        ["gh", "workflow", "run", "deploy.yml", "--repo", "owner/app", "--ref", "main"]
    ]
    watched = [ch.argv for ch in c.children() if ch.argv[:3] == ["gh", "run", "watch"]]
    assert watched == [
        ["gh", "run", "watch", "100", "--repo", "owner/app", "--interval", "60", "--exit-status"]
    ]


# ---------------------------------------------------------------------------- step 7: revoke


def test_a_failed_revoke_keeps_previous_and_a_rerun_finishes(
    cf: tuple[Canary, Providers],
) -> None:
    c, p = cf
    p.fail("DELETE", f"{CF}/cf-old", 502)
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "7 revoke" in result.stderr
    new = new_value(p)
    fields = c.op_fields(VAULT, CF_ITEM)
    assert (fields["credential"], fields["previous"]) == (new, CANARY)
    for key in (GH_ENV, KV, RW):
        assert c.target(key)["value"] == new  # type: ignore[index]
    assert entry(c, "deploy")["rotated"] == datetime.date(2026, 6, 1)
    del p.fails[("DELETE", f"{CF}/cf-old")]
    writes_before = c.target(GH_ENV)["writes"]  # type: ignore[index]
    result = rotate(c, p, "deploy")
    assert result.code == 0, result.stderr
    assert c.target(GH_ENV)["writes"] == writes_before  # type: ignore[index]  # no second sync
    assert CANARY not in p.keys["cloudflare"]
    assert not c.op_fields(VAULT, CF_ITEM)["previous"]
    assert entry(c, "deploy")["fp"] == fp(new)


def test_an_old_key_that_still_works_after_revoke_stops_it(
    cf: tuple[Canary, Providers],
) -> None:
    c, p = cf
    p.ignore_revoke = True
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "still works" in result.stderr
    assert c.op_fields(VAULT, CF_ITEM)["previous"] == CANARY


# ---------------------------------------------------------------------------- step 8: record


def test_a_mapping_that_cannot_be_written_is_retried_by_a_rerun(
    cf: tuple[Canary, Providers],
) -> None:
    c, p = cf
    c.work.chmod(0o500)
    try:
        result = rotate(c, p, "deploy")
    finally:
        c.work.chmod(0o700)
    assert result.code == 1
    assert "8 record" in result.stderr
    new = new_value(p)
    assert c.op_fields(VAULT, CF_ITEM)["previous"] == CANARY
    calls = len(p.calls)
    result = rotate(c, p, "deploy")
    assert result.code == 0, result.stderr
    assert entry(c, "deploy")["fp"] == fp(new)
    assert not c.op_fields(VAULT, CF_ITEM)["previous"]
    assert all(m != "POST" and m != "DELETE" for m, _ in p.calls[calls:])


# ---------------------------------------------------------------------------- the paste flow

PAT_ITEM = "github-pat bot"
PAT_MAPPING = f"""
[[credential]]
name = "bot"
kind = "github-pat"
item = "op://{VAULT}/{PAT_ITEM}"
owner = "example-org"
kept_because = "the app cannot reach this API"
permissions = {{ contents = "read", issues = "write" }}
rotated = 2026-06-01
expires = 2026-11-28

[[credential.target]]
type = "github-actions"
repo = "example-org/app"
secret = "BOT_TOKEN"
"""


@pytest.fixture
def pat(canary: Canary) -> tuple[Canary, Providers]:
    c = canary
    c.watch(FP_KEY)
    c.op_item(VAULT, PAT_ITEM, {"credential": CANARY, "owner": "example-org"})
    c.target_put("gh:example-org/app:BOT_TOKEN", CANARY)
    (c.work / "keys.toml").write_text(PAT_MAPPING)
    p = Providers(c)
    p.add("github", CANARY, "pat-old", expires=days(TODAY, 7))
    return c, p


def opened(c: Canary) -> list[str]:
    return [ch.argv[1] for ch in c.children() if ch.prog == "open"]


def test_a_token_is_pasted_then_rotated_end_to_end(pat: tuple[Canary, Providers]) -> None:
    c, p = pat
    first = rotate(c, p, "bot")
    assert first.code == 5, first.stderr
    urls = opened(c)
    assert len(urls) == 2
    new_page = urls[0]
    assert new_page.startswith("https://github.com/settings/personal-access-tokens/new?")
    for part in (
        "name=bot+2026-11-21",
        "target_name=example-org",
        "expires_in=180",
        "contents=read",
        "issues=write",
    ):
        assert part in new_page, part
    assert urls[1].startswith("onepassword://")
    assert "example-org/app" in first.stdout  # the repositories to pick, printed
    assert "paste" in first.stdout
    assert c.op_fields(VAULT, PAT_ITEM)["pending"] == ""

    again = rotate(c, p, "bot")  # nothing pasted yet
    assert again.code == 5

    new = made_up("pat")
    p.add("github", new, "pat-new", expires=days(TODAY, 180))
    c.op_set_field(VAULT, PAT_ITEM, "pending", new)
    resumed = rotate(c, p, "bot")
    assert resumed.code == 5, resumed.stderr  # waiting for the old token's revoke
    assert [ch.stdin for ch in c.children() if ch.prog == "pbcopy"] == [""]
    assert c.target("gh:example-org/app:BOT_TOKEN")["value"] == new  # type: ignore[index]
    assert opened(c) == ["https://github.com/settings/personal-access-tokens"]
    assert c.op_fields(VAULT, PAT_ITEM)["previous"] == CANARY

    del p.keys["github"][CANARY]  # the owner deletes the old token on GitHub
    done = rotate(c, p, "bot")
    assert done.code == 0, done.stderr
    e = entry(c, "bot")
    assert (e["fp"], e["rotated"]) == (fp(new), TODAY)
    assert e["expires"] == TODAY + datetime.timedelta(180)
    assert not c.op_fields(VAULT, PAT_ITEM)["previous"]


def test_a_pasted_token_that_lives_too_long_is_refused(pat: tuple[Canary, Providers]) -> None:
    c, p = pat
    assert rotate(c, p, "bot").code == 5
    new = made_up("pat")
    p.add("github", new, "pat-new", expires=days(TODAY, 366))
    c.op_set_field(VAULT, PAT_ITEM, "pending", new)
    result = rotate(c, p, "bot")
    assert result.code == 1
    assert "over 180" in result.stderr
    fields = c.op_fields(VAULT, PAT_ITEM)
    assert (fields["credential"], fields["pending"]) == (CANARY, "")
    assert c.target("gh:example-org/app:BOT_TOKEN")["value"] == CANARY  # type: ignore[index]
    assert "https://github.com/settings/personal-access-tokens" in opened(c)


def test_a_pasted_token_that_does_not_work_is_cleared(pat: tuple[Canary, Providers]) -> None:
    c, p = pat
    assert rotate(c, p, "bot").code == 5
    c.op_set_field(VAULT, PAT_ITEM, "pending", made_up("dud"))
    result = rotate(c, p, "bot")
    assert result.code == 1
    assert c.op_fields(VAULT, PAT_ITEM)["pending"] == ""
    assert c.op_fields(VAULT, PAT_ITEM)["credential"] == CANARY


# ---------------------------------------------------------------------------- --now


def test_a_single_key_kind_needs_now(
    cf: tuple[Canary, Providers], monkeypatch: pytest.MonkeyPatch
) -> None:
    c, p = cf
    single = kinds.Kind(
        "cloudflare-token",
        "test: one key at a time",
        ("token_id", "account_id"),
        can_expire=True,
        single_key=True,
    )
    monkeypatch.setitem(kinds.KINDS, "cloudflare-token", single)
    result = rotate(c, p, "deploy")
    assert result.code == 3
    assert "--now" in result.stderr
    assert not c.children()
    result = rotate(c, p, "deploy", "--now")
    assert result.code == 0, result.stderr


def test_a_kind_keys_cannot_rotate_is_refused(canary: Canary) -> None:
    c = canary
    (c.work / "keys.toml").write_text(
        '[[credential]]\nname = "x"\nkind = "generic"\nitem = "op://V/generic x"\n'
        'kept_because = "y"\n'
    )
    result = c.run(["rotate", "x"], env=ENV)
    assert result.code == 3
    assert "cannot rotate" in result.stderr


# ---------------------------------------------------------------------------- review: reruns


def test_a_rerun_after_the_old_key_was_deleted_but_not_recorded_finishes(
    cf: tuple[Canary, Providers],
) -> None:
    c, p = cf
    # edits: pending, store, verified; the fourth (revoked) fails after the DELETE went through
    c.child_fails(["op", "item", "edit"], code=5, skip=3)
    first = rotate(c, p, "deploy")
    assert first.code == 1
    assert CANARY not in p.keys["cloudflare"]
    c.clear_child_fails()
    again = rotate(c, p, "deploy")
    assert again.code == 0, again.stderr
    assert entry(c, "deploy")["fp"] == fp(new_value(p))
    assert not c.op_fields(VAULT, CF_ITEM)["previous"]


def test_a_revoke_that_takes_effect_late_is_seen_on_the_rerun(
    cf: tuple[Canary, Providers],
) -> None:
    c, p = cf
    p.ignore_revoke = True
    assert rotate(c, p, "deploy").code == 1
    p.ignore_revoke = False
    del p.keys["cloudflare"][CANARY]  # the provider caught up
    again = rotate(c, p, "deploy")
    assert again.code == 0, again.stderr
    assert entry(c, "deploy")["fp"] == fp(new_value(p))


def test_a_write_that_failed_but_landed_is_rolled_back_too(cf: tuple[Canary, Providers]) -> None:
    c, p = cf
    c.child_fails(["railway", "variable", "set"], code=7, after=True)
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "rolled back" in result.stderr
    untouched(c, p)


def test_an_unclear_probe_of_the_new_key_keeps_it_for_a_rerun(
    cf: tuple[Canary, Providers],
) -> None:
    c, p = cf
    p.fail("GET", f"{CF}/verify", 503)
    first = rotate(c, p, "deploy")
    assert first.code == 1
    assert "rerun" in first.stderr
    new = new_value(p)
    assert new in p.keys["cloudflare"]  # not revoked
    fields = c.op_fields(VAULT, CF_ITEM)
    assert (fields["pending"], fields["keys_step"]) == (new, "pending")
    del p.fails[("GET", f"{CF}/verify")]
    again = rotate(c, p, "deploy")
    assert again.code == 0, again.stderr
    assert p.minted == [new]  # nothing minted twice


def test_a_new_key_whose_revoke_fails_in_rollback_is_revoked_by_the_next_run(
    cf: tuple[Canary, Providers],
) -> None:
    c, p = cf
    c.child_fails(["railway", "variable", "set"], code=7)
    p.fail("DELETE", f"{CF}/cl-new-1", 502)
    first = rotate(c, p, "deploy")
    assert first.code == 1
    new = new_value(p)
    assert new in p.keys["cloudflare"]
    assert c.op_fields(VAULT, CF_ITEM)["unrevoked_id"] == "cl-new-1"
    c.clear_child_fails()
    del p.fails[("DELETE", f"{CF}/cl-new-1")]
    again = rotate(c, p, "deploy")
    assert again.code == 0, again.stderr
    assert new not in p.keys["cloudflare"]  # the stray key went first
    assert not c.op_fields(VAULT, CF_ITEM)["unrevoked_id"]
    assert len(p.minted) == 2


def test_an_item_changed_by_another_run_stops_the_save(cf: tuple[Canary, Providers]) -> None:
    c, p = cf
    # Another run moves the item on between this run's read and its first save.
    c.set_db("item_step_race", {"title": CF_ITEM, "step": "pending"})
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "another keys rotate" in result.stderr
    assert p.minted
    assert p.minted[0] not in p.keys["cloudflare"]  # its own key is revoked


# ---------------------------------------------------------------------------- review: first value


def test_the_first_value_is_minted_into_an_empty_item(canary: Canary) -> None:
    c = canary
    c.watch(FP_KEY)
    admin = made_up("re_admin")
    item, admin_item = "resend-key app-mail", "resend-key resend-admin"
    c.op_item(VAULT, item, {"credential": "", "key_id": "", "domain_id": "", "permission": ""})
    c.op_item(VAULT, admin_item, {"credential": admin, "key_id": "re-admin"})
    (c.work / "keys.toml").write_text(
        f'[[credential]]\nname = "resend-admin"\nkind = "resend-key"\n'
        f'item = "op://{VAULT}/{admin_item}"\nkept_because = "mints the sending keys"\n\n'
        f'[[credential]]\nname = "app-mail"\nkind = "resend-key"\nitem = "op://{VAULT}/{item}"\n'
        'minted_by = "resend-admin"\nkept_because = "Resend has no OIDC sign-in"\n\n'
        '[[credential.target]]\ntype = "github-actions"\nrepo = "owner/app"\n'
        'secret = "RESEND_API_KEY"\n'
    )
    p = Providers(c)
    p.add("resend", admin, "re-admin", permission="full_access")
    result = rotate(c, p, "app-mail")
    assert result.code == 0, result.stderr
    new = new_value(p)
    assert c.target("gh:owner/app:RESEND_API_KEY")["value"] == new  # type: ignore[index]
    assert "no old key to revoke" in result.stdout
    assert c.op_fields(VAULT, item)["key_id"] == p.keys["resend"][new].ident


def test_a_value_without_its_key_id_is_refused_before_anything_is_made(
    cf: tuple[Canary, Providers],
) -> None:
    c, p = cf
    c.op_set_field(VAULT, CF_ITEM, "token_id", "")
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "token_id" in result.stderr
    assert p.minted == []


# ---------------------------------------------------------------------------- review: checks


def test_cloudflare_expiry_is_read_back_from_the_provider(cf: tuple[Canary, Providers]) -> None:
    c, p = cf
    p.cf_expires_on = f"{days(TODAY, 365)}T00:00:00Z"  # Cloudflare ignored the asked expiry
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "over 180" in result.stderr
    assert c.op_fields(VAULT, CF_ITEM)["credential"] == CANARY


def test_the_new_key_is_probed_again_before_the_old_one_goes(
    pat: tuple[Canary, Providers],
) -> None:
    c, p = pat
    assert rotate(c, p, "bot").code == 5
    new = made_up("pat")
    p.add("github", new, "pat-new", expires=days(TODAY, 180))
    c.op_set_field(VAULT, PAT_ITEM, "pending", new)
    assert rotate(c, p, "bot").code == 5  # waiting for the old token's revoke
    del p.keys["github"][new]  # the owner deleted the wrong token
    result = rotate(c, p, "bot")
    assert result.code == 1
    assert "the new key no longer works" in result.stderr


def test_an_unclear_answer_about_the_old_key_is_not_called_still_working(
    cf: tuple[Canary, Providers],
) -> None:
    c, p = cf
    p.ignore_revoke = True
    p.fail_after_delete = ("GET", f"{CF}/verify", 503)
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "cannot tell whether the old key" in result.stderr


def test_a_hand_edited_expiry_field_is_not_printed(cf: tuple[Canary, Providers]) -> None:
    c, p = cf
    c.child_fails(["op", "item", "edit"], code=5, skip=3)
    assert rotate(c, p, "deploy").code == 1
    c.clear_child_fails()
    c.op_set_field(VAULT, CF_ITEM, "keys_expires", CANARY)
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "keys_expires" in result.stderr


def test_permissions_cannot_override_the_token_page_settings(canary: Canary) -> None:
    from keys import mapping, rotators

    c = mapping.Credential(
        "bot",
        "github-pat",
        "V",
        "github-pat bot",
        owner="example-org",
        permissions={"expires_in": "admin", "contents": "read"},
    )
    page = rotators.GitHubPat("github-pat", "github").create_page(c, {}, "bot 2026-11-21")
    assert "expires_in=180" in page
    assert "expires_in=admin" not in page


def test_a_plain_text_pending_field_becomes_concealed() -> None:
    from keys.op import set_fields

    item = {"fields": [{"id": "pending", "label": "pending", "type": "STRING", "value": ""}]}
    set_fields(item, {"pending": "x"}, {"pending"})
    assert item["fields"][0]["type"] == "CONCEALED"


def test_only_a_dispatch_on_main_is_watched(canary: Canary) -> None:
    c = canary
    c.watch(FP_KEY)
    minter = made_up("mint")
    c.op_item(VAULT, CF_ITEM, {"credential": CANARY, "token_id": "cf-old", "account_id": ""})
    c.op_item(VAULT, MINTER_ITEM, {"credential": minter, "token_id": "cf-mint", "account_id": ""})
    (c.work / "keys.toml").write_text(
        CF_MAPPING.split("[[credential.target]]")[0]
        + '[[credential.target]]\ntype = "github-actions"\nrepo = "owner/app"\nsecret = "CF"\n'
        'verify = { workflow = "deploy.yml" }\n'
    )
    p = Providers(c)
    p.add("cloudflare", CANARY, "cf-old", policies=POLICIES)
    p.add("cloudflare", minter, "cf-mint", can_mint=True)
    # Someone else's dispatch on another branch appears first.
    c.set_db(
        "runs_on_dispatch",
        [
            {
                "event": "workflow_dispatch",
                "workflow": "deploy.yml",
                "repo": "owner/app",
                "ref": "dev",
            }
        ],
    )
    result = rotate(c, p, "deploy")
    assert result.code == 0, result.stderr
    watched = [ch.argv[3] for ch in c.children() if ch.argv[:3] == ["gh", "run", "watch"]]
    assert watched == ["100"]


# ---------------------------------------------------------------------------- review: more paths


def test_a_rollback_that_cannot_restore_a_target_keeps_the_new_key(
    cf: tuple[Canary, Providers],
) -> None:
    c, p = cf
    c.child_fails(["railway", "variable", "set"], code=7)
    c.child_fails(["gh", "secret", "set"], code=8, skip=1)  # the rollback write fails
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "could not be put back" in result.stderr
    new = new_value(p)
    assert new in p.keys["cloudflare"]
    fields = c.op_fields(VAULT, CF_ITEM)
    assert (fields["credential"], fields["previous"]) == (new, CANARY)


def test_a_rollback_whose_1password_save_fails_says_where_the_old_key_is(
    cf: tuple[Canary, Providers],
) -> None:
    c, p = cf
    c.child_fails(["railway", "variable", "set"], code=7)
    c.child_fails(["op", "item", "edit"], code=5, skip=2)  # pending, store; then rollback's
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "previous field" in result.stderr
    for key in (GH_ENV, KV, RW):
        assert c.target(key)["value"] == CANARY  # type: ignore[index]


def test_a_failed_redeploy_in_verify_rolls_back(cf: tuple[Canary, Providers]) -> None:
    c, p = cf
    c.child_fails(["railway", "redeploy"], code=9)
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "6 verify" in result.stderr
    for key in (GH_ENV, KV):
        assert c.target(key)["value"] == CANARY  # type: ignore[index]
    assert c.op_fields(VAULT, CF_ITEM)["credential"] == CANARY


def test_a_keys_step_keys_did_not_write_stops_it(cf: tuple[Canary, Providers]) -> None:
    c, p = cf
    c.op_set_field(VAULT, CF_ITEM, "keys_step", "half-done")
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "keys_step" in result.stderr
    assert p.minted == []


def test_a_pending_value_keys_did_not_leave_stops_it(cf: tuple[Canary, Providers]) -> None:
    c, p = cf
    c.op_set_field(VAULT, CF_ITEM, "pending", made_up("stray"))
    result = rotate(c, p, "deploy")
    assert result.code == 1
    assert "did not leave there" in result.stderr
    assert p.minted == []


def test_a_pasted_value_with_a_carriage_return_is_refused(pat: tuple[Canary, Providers]) -> None:
    c, p = pat
    assert rotate(c, p, "bot").code == 5
    new = made_up("pat")
    p.add("github", new, "pat-new", expires=days(TODAY, 180))
    c.op_set_field(VAULT, PAT_ITEM, "pending", new + "\r\n")
    result = rotate(c, p, "bot")
    assert result.code == 3
    assert "carriage return" in result.stderr
    assert c.target("gh:example-org/app:BOT_TOKEN")["value"] == CANARY  # type: ignore[index]


def test_the_harness_refuses_a_minting_key_at_a_target(cf: tuple[Canary, Providers]) -> None:
    c, _ = cf
    minter = c.op_fields(VAULT, MINTER_ITEM)["credential"]
    held = c._held([])  # pyright: ignore[reportPrivateUsage]
    assert c._expected_write(CANARY, held)  # pyright: ignore[reportPrivateUsage]
    assert not c._expected_write(minter, held)  # pyright: ignore[reportPrivateUsage]
