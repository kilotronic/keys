"""keys rotate for Twilio keys, Railway tokens and GitHub App keys, through the canary harness.

Each old key is the canary in a fake 1Password item; the fakes mint fresh random values (and
the App keys are fresh RSA keys made at run time), which the canary also watches.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.canary import CANARY, Canary
from tests.fake_providers import Key, Providers, made_up
from tests.test_appjwt import make_key
from tests.test_rotate import ENV, FP_KEY, TODAY, VAULT, entry, fp, opened

# ---------------------------------------------------------------------------- Twilio

TW_ITEM, TW_MAIN = "twilio-key app-sms", "twilio-key twilio-main"
OLD_SID, MAIN_SID, ACCOUNT = "SKold", "SKmain", "AC0001"
SECRET_AT = "railway:proj:app:production:TWILIO_API_KEY_SECRET"
SID_AT = "railway:proj:app:production:TWILIO_API_KEY_SID"
STAGING_SECRET = "railway:proj:app:staging:TWILIO_API_KEY_SECRET"
STAGING_SID = "railway:proj:app:staging:TWILIO_API_KEY_SID"

TW_MAPPING = f"""
[[credential]]
name = "twilio-main"
kind = "twilio-key"
item = "op://{VAULT}/{TW_MAIN}"
kept_because = "it mints the sending keys"

[[credential]]
name = "app-sms"
kind = "twilio-key"
item = "op://{VAULT}/{TW_ITEM}"
minted_by = "twilio-main"
kept_because = "Twilio has no OIDC sign-in"
rotated = 2026-06-01
""" + "".join(
    f"""
[[credential.target]]
type = "railway"
project = "proj"
service = "app"
environment = "{env}"
variable = "TWILIO_API_KEY_{var}"
{extra}
"""
    for env in ("staging", "production")
    for var, extra in (("SID", 'field = "key_sid"'), ("SECRET", ""))
)


def rotate(c: Canary, p: Providers, *argv: str) -> object:
    return c.run(["rotate", *argv], env=ENV, send=p, today=lambda: TODAY)


@pytest.fixture
def tw(canary: Canary) -> tuple[Canary, Providers]:
    c = canary
    c.watch(FP_KEY)
    main = made_up("main")
    c.op_item(VAULT, TW_ITEM, {"credential": CANARY, "key_sid": OLD_SID, "account_sid": ACCOUNT})
    c.op_item(VAULT, TW_MAIN, {"credential": main, "key_sid": MAIN_SID, "account_sid": ACCOUNT})
    c.never_written.append(main)
    for key in (SECRET_AT, STAGING_SECRET):
        c.target_put(key, CANARY)
    for key in (SID_AT, STAGING_SID):
        c.target_put(key, OLD_SID, secret=False)
    (c.work / "keys.toml").write_text(TW_MAPPING)
    p = Providers(c)
    p.add("twilio", CANARY, OLD_SID)
    p.add("twilio", main, MAIN_SID, can_mint=True)
    return c, p


def test_a_twilio_key_and_its_sid_are_replaced_in_both_environments(
    tw: tuple[Canary, Providers],
) -> None:
    c, p = tw
    result = rotate(c, p, "app-sms")
    assert result.code == 0, result.stderr  # type: ignore[attr-defined]
    assert len(p.minted) == 1
    new = p.minted[0]
    new_sid = p.keys["twilio"][new].ident
    assert p.keys["twilio"][new].name == "app-sms 2026-11-21"
    for key in (SECRET_AT, STAGING_SECRET):
        assert c.target(key)["value"] == new  # type: ignore[index]
    for key in (SID_AT, STAGING_SID):
        assert c.target(key)["value"] == new_sid  # type: ignore[index]
    assert CANARY not in p.keys["twilio"]  # the old key is deleted
    fields = c.op_fields(VAULT, TW_ITEM)
    assert (fields["credential"], fields["key_sid"]) == (new, new_sid)
    assert not fields["previous"]
    # Each environment is redeployed once, though two of its variables changed.
    for env in ("staging", "production"):
        assert len(c.deploys(f"railway:proj:app:{env}:")) == 2, env
    e = entry(c, "app-sms")
    assert (e["fp"], e["rotated"]) == (fp(new), TODAY)
    assert "reads back" in result.stdout  # type: ignore[attr-defined]


def test_a_twilio_rollback_puts_the_old_sid_back_too(tw: tuple[Canary, Providers]) -> None:
    c, p = tw
    c.child_fails(["railway", "redeploy"], code=9)
    result = rotate(c, p, "app-sms")
    assert result.code == 1  # type: ignore[attr-defined]
    assert "rolled back" in result.stderr  # type: ignore[attr-defined]
    for key in (SECRET_AT, STAGING_SECRET):
        assert c.target(key)["value"] == CANARY  # type: ignore[index]
    for key in (SID_AT, STAGING_SID):
        assert c.target(key)["value"] == OLD_SID  # type: ignore[index]
    fields = c.op_fields(VAULT, TW_ITEM)
    assert (fields["credential"], fields["key_sid"]) == (CANARY, OLD_SID)
    assert p.minted[0] not in p.keys["twilio"]  # the new key is deleted


def test_a_variable_that_does_not_read_back_rolls_back(tw: tuple[Canary, Providers]) -> None:
    c, p = tw
    # Railway answers every listing with an other value: the read-back cannot match.
    c.child_prints(["railway", "variable", "list"], '{"TWILIO_API_KEY_SECRET": "other"}')
    result = rotate(c, p, "app-sms")
    assert result.code == 1  # type: ignore[attr-defined]
    assert "does not read back" in result.stderr  # type: ignore[attr-defined]
    assert p.minted[0] not in p.keys["twilio"]


def test_a_field_target_must_name_a_field_of_the_kind(tw: tuple[Canary, Providers]) -> None:
    c, p = tw
    (c.work / "keys.toml").write_text(TW_MAPPING.replace('field = "key_sid"', 'field = "nope"'))
    result = rotate(c, p, "app-sms")
    assert result.code == 3  # type: ignore[attr-defined]
    assert "key_sid, account_sid" in result.stderr  # type: ignore[attr-defined]


def test_keys_sync_delivers_the_sid_field_too(tw: tuple[Canary, Providers]) -> None:
    c, _ = tw
    c.op_value(f"op://{VAULT}/{TW_ITEM}/credential", CANARY)
    c.op_value(f"op://{VAULT}/{TW_ITEM}/key_sid", "SKsame")
    result = c.run(["sync", "app-sms", "--no-deploy"], env=ENV)
    assert result.code == 0, result.stderr
    assert c.target(SID_AT)["value"] == "SKsame"  # type: ignore[index]
    assert c.target(SECRET_AT)["value"] == CANARY  # type: ignore[index]


# ---------------------------------------------------------------------------- Railway

RW_ITEM, RW_WS = "railway-project-token ci-prod", "railway-workspace-token railway-ws"
RW_MAPPING = f"""
[[credential]]
name = "railway-ws"
kind = "railway-workspace-token"
item = "op://{VAULT}/{RW_WS}"
kept_because = "Railway has no OIDC sign-in"
rotated = 2026-06-01

[[credential.target]]
type = "github-actions-env"
repo = "owner/app"
environment = "railway"
secret = "RAILWAY_API_TOKEN"

[[credential]]
name = "ci-prod"
kind = "railway-project-token"
item = "op://{VAULT}/{RW_ITEM}"
minted_by = "railway-ws"
kept_because = "Railway has no OIDC sign-in"
rotated = 2026-06-01

[[credential.target]]
type = "github-actions-env"
repo = "owner/app"
environment = "railway"
secret = "RAILWAY_TOKEN_PRODUCTION"
"""
PROD_AT = "gh:owner/app:env:railway:RAILWAY_TOKEN_PRODUCTION"
WS_AT = "gh:owner/app:env:railway:RAILWAY_API_TOKEN"


@pytest.fixture
def rw(canary: Canary) -> tuple[Canary, Providers, str]:
    c = canary
    c.watch(FP_KEY)
    ws = made_up("ws")
    ids = {"project_id": "proj-1", "environment_id": "env-1", "token_id": "tok-old"}
    c.op_item(VAULT, RW_ITEM, {"credential": CANARY, **ids})
    c.op_item(VAULT, RW_WS, {"credential": ws})
    c.gh_main_only("owner/app", "railway")
    c.target_put(PROD_AT, CANARY)
    c.target_put(WS_AT, ws)
    (c.work / "keys.toml").write_text(RW_MAPPING)
    p = Providers(c)
    p.add("railway", CANARY, "tok-old", name="ci-prod 2026-05-01")
    p.add("railway", ws, "ws-1", can_mint=True)
    return c, p, ws


def test_a_railway_project_token_is_minted_with_the_workspace_token(
    rw: tuple[Canary, Providers, str],
) -> None:
    c, p, _ = rw
    c.never_written.append(c.op_fields(VAULT, RW_WS)["credential"])
    result = rotate(c, p, "ci-prod")
    assert result.code == 0, result.stderr  # type: ignore[attr-defined]
    new = p.minted[0]
    made = p.keys["railway"][new]
    assert made.policies == [
        {"name": "ci-prod 2026-11-21", "projectId": "proj-1", "environmentId": "env-1"}
    ]
    assert c.target(PROD_AT)["value"] == new  # type: ignore[index]
    assert CANARY not in p.keys["railway"]
    assert c.op_fields(VAULT, RW_ITEM)["token_id"] == made.ident
    assert entry(c, "ci-prod")["fp"] == fp(new)


def test_a_railway_token_of_the_same_name_is_not_minted_again(
    rw: tuple[Canary, Providers, str],
) -> None:
    c, p, _ = rw
    p.add("railway", made_up("rw"), "tok-same", name="ci-prod 2026-11-21")
    result = rotate(c, p, "ci-prod")
    assert result.code == 1  # type: ignore[attr-defined]
    assert "is there already" in result.stderr  # type: ignore[attr-defined]
    assert p.minted == []


def test_a_railway_token_whose_id_is_not_listed_still_rotates(
    rw: tuple[Canary, Providers, str],
) -> None:
    c, p, _ = rw
    p.railway_lists_ids = False
    result = rotate(c, p, "ci-prod")
    assert result.code == 0, result.stderr  # type: ignore[attr-defined]
    assert "fill the item's token_id field by hand" in result.stdout  # type: ignore[attr-defined]


def test_a_workspace_token_is_pasted_then_the_old_one_deleted_by_hand(
    rw: tuple[Canary, Providers, str],
) -> None:
    c, p, ws = rw
    first = rotate(c, p, "railway-ws")
    assert first.code == 5, first.stderr  # type: ignore[attr-defined]
    assert opened(c)[0] == "https://railway.com/account/tokens"
    new = made_up("ws")
    p.add("railway", new, "ws-2", can_mint=True)
    c.op_set_field(VAULT, RW_WS, "pending", new)
    again = rotate(c, p, "railway-ws")
    assert again.code == 5, again.stderr  # type: ignore[attr-defined]
    assert c.target(WS_AT)["value"] == new  # type: ignore[index]
    del p.keys["railway"][ws]  # the owner deletes the old token in the dashboard
    done = rotate(c, p, "railway-ws")
    assert done.code == 0, done.stderr  # type: ignore[attr-defined]
    assert entry(c, "railway-ws")["fp"] == fp(new)
    assert "expires" not in entry(c, "railway-ws")


# ---------------------------------------------------------------------------- GitHub App keys

APP_ITEM = "github-app-key settings-app"
APP_AT = "gh:owner/app:env:settings:SETTINGS_APP_KEY"
APP_MAPPING = f"""
[[credential]]
name = "settings-app"
kind = "github-app-key"
item = "op://{VAULT}/{APP_ITEM}"
owner = "example-org"
kept_because = "GitHub has no keyless App sign-in"
rotated = 2026-06-01

[[credential.target]]
type = "github-actions-env"
repo = "owner/app"
environment = "settings"
secret = "SETTINGS_APP_KEY"
"""


@pytest.fixture
def app(canary: Canary) -> tuple[Canary, Providers, str]:
    c = canary
    c.watch(FP_KEY)
    old, _, _ = make_key(1024)
    c.watch(old)
    fields = {"credential": old, "app_id": "123", "client_id": "Iv1.abc", "slug": "the-app"}
    c.op_item(VAULT, APP_ITEM, fields)
    c.gh_main_only("owner/app", "settings")
    c.target_put(APP_AT, old)
    (c.work / "keys.toml").write_text(APP_MAPPING)
    p = Providers(c)
    p.keys["github-app"][old] = Key("old")
    return c, p, old


def _download(c: Canary, pem: str, name: str = "the-app.2026-11-21.private-key.pem") -> Path:
    return c.plant(Path("Downloads") / name, pem)  # a copy the harness allows while unchanged


def test_an_app_key_is_taken_from_the_download_and_the_file_deleted(
    app: tuple[Canary, Providers, str],
) -> None:
    c, p, old = app
    first = rotate(c, p, "settings-app")
    assert first.code == 5, first.stderr  # type: ignore[attr-defined]
    assert opened(c)[0] == "https://github.com/organizations/example-org/settings/apps/the-app"
    assert "Do not open the file" in first.stdout  # type: ignore[attr-defined]
    new, _, _ = make_key(1024)
    c.watch(new)
    p.keys["github-app"][new] = Key("new")
    path = _download(c, new)
    again = rotate(c, p, "settings-app")
    assert again.code == 5, again.stderr  # type: ignore[attr-defined]  # the old key's delete
    assert not path.exists()
    assert c.target(APP_AT)["value"] == new.rstrip("\n")  # type: ignore[index]
    assert c.op_fields(VAULT, APP_ITEM)["previous"] == old
    assert not [ch for ch in c.children() if ch.prog == "pbcopy"]  # nothing was copied
    del p.keys["github-app"][old]  # the owner deletes the old key on the App's page
    done = rotate(c, p, "settings-app")
    assert done.code == 0, done.stderr  # type: ignore[attr-defined]
    assert entry(c, "settings-app")["fp"] == fp(new.rstrip("\n"))
    assert entry(c, "settings-app")["rotated"] == TODAY


def test_two_downloaded_app_keys_are_refused(app: tuple[Canary, Providers, str]) -> None:
    c, p, _ = app
    assert rotate(c, p, "settings-app").code == 5  # type: ignore[attr-defined]
    one, _, _ = make_key(1024)
    two, _, _ = make_key(1024)
    c.watch(one)
    c.watch(two)
    a = _download(c, one)
    b = _download(c, two, "the-app.2026-11-20.private-key.pem")
    result = rotate(c, p, "settings-app")
    assert result.code == 1  # type: ignore[attr-defined]
    assert "2 downloaded keys" in result.stderr  # type: ignore[attr-defined]
    assert a.exists()
    assert b.exists()
    assert c.op_fields(VAULT, APP_ITEM)["pending"] == ""


def test_a_downloaded_file_that_is_not_a_key_is_refused(
    app: tuple[Canary, Providers, str],
) -> None:
    c, p, _ = app
    assert rotate(c, p, "settings-app").code == 5  # type: ignore[attr-defined]
    path = _download(c, "not a key")
    result = rotate(c, p, "settings-app")
    assert result.code == 1  # type: ignore[attr-defined]
    assert "not an RSA private key" in result.stderr  # type: ignore[attr-defined]
    assert path.exists()


def test_an_app_key_that_github_does_not_hold_is_not_kept(
    app: tuple[Canary, Providers, str],
) -> None:
    c, p, old = app
    assert rotate(c, p, "settings-app").code == 5  # type: ignore[attr-defined]
    stray, _, _ = make_key(1024)
    c.watch(stray)
    _download(c, stray)  # a key GitHub never issued (or already deleted)
    result = rotate(c, p, "settings-app")
    assert result.code == 1  # type: ignore[attr-defined]
    assert "does not work" in result.stderr  # type: ignore[attr-defined]
    assert c.op_fields(VAULT, APP_ITEM)["credential"] == old
    assert c.target(APP_AT)["value"] == old  # type: ignore[index]
