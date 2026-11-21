"""keys rotate for secrets kept only at their targets: signing keys (with an overlap), a job's
key held as a digest, and datastore passwords. Ported from the old Railway rotation script's
tests, with generic names, through the canary harness.

keys makes these values itself, so the tests make its random values watched ones.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any
from urllib.parse import quote

import pytest

from keys import runtime
from keys.secret import Secret
from tests.canary import CANARY, Canary
from tests.fake_providers import made_up
from tests.test_rotate import ENV, FP_KEY, TODAY, entry, fp

APP = "railway:proj:app:production:"
PG = "railway:proj:Postgres:production:"
REDIS = "railway:proj:Redis:production:"

SIGNING = """
[[credential]]
name = "jwt-secret"
kind = "generated"
kept_because = "the app signs its sessions with it"
rotated = 2026-06-01

[[credential.target]]
type = "railway"
project = "proj"
service = "app"
environment = "production"
variable = "JWT_SECRET"
previous = "JWT_SECRET_FALLBACK"

[[credential]]
name = "secret-key"
kind = "generated"
kept_because = "the app signs its cookies with it"
rotated = 2026-06-01

[[credential.target]]
type = "railway"
project = "proj"
service = "app"
environment = "production"
variable = "SECRET_KEY"
"""

ERASURE = """
[[credential]]
name = "erasure-key"
kind = "generated"
generate = "urlsafe32"
kept_because = "the scheduled erasure job signs in with it"

[[credential.target]]
type = "railway"
project = "proj"
service = "app"
environment = "production"
variable = "ERASURE_KEY_SHA256"
store = "sha256"

[[credential.target]]
type = "github-actions-env"
repo = "owner/app"
environment = "erasure"
secret = "PRODUCTION_ERASURE_KEY"
"""

DATASTORES = """
[[credential]]
name = "pg"
kind = "postgres-password"
url_variable = "DATABASE_PUBLIC_URL"
redeploy = ["Redis", "app", "Postgres"]
kept_because = "the app signs in to its database with it"

[[credential.target]]
type = "railway"
project = "proj"
service = "Postgres"
environment = "production"
variable = "POSTGRES_PASSWORD"

[[credential]]
name = "redis"
kind = "generated"
generate = "hex24"
redeploy = ["Redis", "app", "Postgres"]
kept_because = "the app signs in to Redis with it"

[[credential.target]]
type = "railway"
project = "proj"
service = "Redis"
environment = "production"
variable = "REDIS_PASSWORD"
"""


@pytest.fixture
def made(canary: Canary, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """keys's new values: fresh, watched, and allowed at the targets (with their digests)."""
    out: list[str] = []
    real = runtime.make_value

    def make(form: str) -> Secret:
        value = real(form).reveal()
        out.append(value)
        canary.watch(value)
        canary.writable += [value, hashlib.sha256(value.encode()).hexdigest()]
        return Secret(value)

    monkeypatch.setattr(runtime, "make_value", make)
    canary.watch(FP_KEY)
    return out


def rotate(c: Canary, *argv: str) -> Any:
    return c.run(["rotate", *argv], env=ENV, today=lambda: TODAY)


def redeploys(c: Canary) -> list[str]:
    out: list[str] = []
    for ch in c.children():
        if ch.argv[:2] == ["railway", "redeploy"]:
            out.append(ch.argv[ch.argv.index("--service") + 1])
    return out


def value(c: Canary, key: str) -> str | None:
    t = c.target(key)
    return None if t is None else str(t["value"])


# ---------------------------------------------------------------------------- signing keys


@pytest.fixture
def signing(canary: Canary, made: list[str]) -> tuple[Canary, list[str], str]:
    c = canary
    old_sk = made_up("sk")
    c.target_put(APP + "JWT_SECRET", CANARY)
    c.target_put(APP + "SECRET_KEY", old_sk)
    (c.work / "keys.toml").write_text(SIGNING)
    return c, made, old_sk


def test_signing_keys_are_replaced_together_with_one_redeploy(
    signing: tuple[Canary, list[str], str],
) -> None:
    c, made, _ = signing
    c.target_put(APP + "JWT_SECRET_FALLBACK", CANARY)  # left from an old overlap
    result = rotate(c, "jwt-secret", "secret-key")
    assert result.code == 0, result.stderr
    jwt, sk = made
    assert (value(c, APP + "JWT_SECRET"), value(c, APP + "SECRET_KEY")) == (jwt, sk)
    assert value(c, APP + "JWT_SECRET_FALLBACK") is None  # a plain rotation ends any overlap
    assert redeploys(c) == ["app"]
    assert (entry(c, "jwt-secret")["fp"], entry(c, "secret-key")["fp"]) == (fp(jwt), fp(sk))
    assert entry(c, "jwt-secret")["rotated"] == TODAY
    assert not [ch for ch in c.children() if ch.prog == "gh"]  # never reaches GitHub
    assert "reads back" in result.stdout


def test_keep_previous_keeps_the_old_key_as_the_fallback(
    signing: tuple[Canary, list[str], str],
) -> None:
    c, made, _ = signing
    result = rotate(c, "jwt-secret", "--keep-previous")
    assert result.code == 0, result.stderr
    assert value(c, APP + "JWT_SECRET_FALLBACK") == CANARY
    assert value(c, APP + "JWT_SECRET") == made[0]
    staged = [ch.argv[3] for ch in c.children() if ch.argv[:3] == ["railway", "variable", "set"]]
    assert staged == ["JWT_SECRET_FALLBACK", "JWT_SECRET"]  # the fallback first
    assert "2026-12-21" in result.stdout
    assert "--end-overlap" in result.stdout


def test_keep_previous_refuses_while_an_overlap_runs(
    signing: tuple[Canary, list[str], str],
) -> None:
    c, made, _ = signing
    other = made_up("fb")
    c.target_put(APP + "JWT_SECRET_FALLBACK", other)
    result = rotate(c, "jwt-secret", "--keep-previous")
    assert result.code == 1
    assert "an overlap is still running" in result.stderr
    assert made == []
    assert value(c, APP + "JWT_SECRET") == CANARY
    assert not redeploys(c)


def test_keep_previous_goes_ahead_after_a_run_that_stopped_before_the_new_key(
    signing: tuple[Canary, list[str], str],
) -> None:
    c, made, _ = signing
    c.target_put(APP + "JWT_SECRET_FALLBACK", CANARY)  # staged, then the run stopped
    result = rotate(c, "jwt-secret", "--keep-previous")
    assert result.code == 0, result.stderr
    assert value(c, APP + "JWT_SECRET") == made[0]


def test_keep_previous_with_no_current_key_changes_nothing(
    signing: tuple[Canary, list[str], str],
) -> None:
    c, made, _ = signing
    c.set_db("targets", {k: v for k, v in c.db["targets"].items() if not k.endswith("JWT_SECRET")})
    result = rotate(c, "jwt-secret", "--keep-previous")
    assert result.code == 1
    assert "no old value to keep" in result.stderr
    assert made == []


def test_a_failed_redeploy_says_what_is_staged_and_to_rerun(
    signing: tuple[Canary, list[str], str],
) -> None:
    c, _, _ = signing
    c.child_fails(["railway", "redeploy"], code=9)
    result = rotate(c, "jwt-secret", "secret-key")
    assert result.code == 1
    assert "may be staged, and may be live: rerun" in result.stderr
    assert str(entry(c, "jwt-secret")["rotated"]) == "2026-06-01"  # not recorded


def test_a_failed_redeploy_after_keep_previous_says_not_to_rerun(
    signing: tuple[Canary, list[str], str],
) -> None:
    c, _, _ = signing
    c.child_fails(["railway", "redeploy"], code=9)
    result = rotate(c, "jwt-secret", "--keep-previous")
    assert result.code == 1
    assert "do not rerun" in result.stderr


def test_end_overlap_deletes_the_fallback_and_redeploys(
    signing: tuple[Canary, list[str], str],
) -> None:
    c, made, _ = signing
    c.target_put(APP + "JWT_SECRET_FALLBACK", made_up("fb"))
    result = rotate(c, "jwt-secret", "--end-overlap")
    assert result.code == 0, result.stderr
    assert value(c, APP + "JWT_SECRET_FALLBACK") is None
    assert redeploys(c) == ["app"]
    assert made == []
    assert value(c, APP + "JWT_SECRET") == CANARY


def test_end_overlap_with_none_set_redeploys_once_and_says_so(
    signing: tuple[Canary, list[str], str],
) -> None:
    c, _, _ = signing
    result = rotate(c, "jwt-secret", "--end-overlap")
    assert result.code == 0, result.stderr
    assert "no overlap to end" in result.stdout
    assert redeploys(c) == ["app"]


def test_end_overlap_that_fails_says_to_rerun(signing: tuple[Canary, list[str], str]) -> None:
    c, _, _ = signing
    c.target_put(APP + "JWT_SECRET_FALLBACK", made_up("fb"))
    c.child_fails(["railway", "redeploy"], code=9)
    result = rotate(c, "jwt-secret", "--end-overlap")
    assert result.code == 1
    assert "the old value may still verify: rerun now" in result.stderr


def test_the_two_overlap_flags_exclude_each_other(signing: tuple[Canary, list[str], str]) -> None:
    c, _, _ = signing
    result = rotate(c, "jwt-secret", "--keep-previous", "--end-overlap")
    assert result.code != 0


def test_a_credential_with_an_item_cannot_rotate_with_a_generated_one(
    signing: tuple[Canary, list[str], str],
) -> None:
    c, _, _ = signing
    (c.work / "keys.toml").write_text(
        SIGNING + '\n[[credential]]\nname = "x"\nkind = "generic"\nitem = "op://V/generic x"\n'
        'kept_because = "y"\n'
    )
    result = rotate(c, "jwt-secret", "x")
    assert result.code == 3
    assert "rotate together" in result.stderr


# ---------------------------------------------------------------------------- a job's key


@pytest.fixture
def erasure(canary: Canary, made: list[str]) -> tuple[Canary, list[str]]:
    c = canary
    c.gh_main_only("owner/app", "erasure")
    c.target_put(APP + "ERASURE_KEY_SHA256", hashlib.sha256(CANARY.encode()).hexdigest())
    c.target_put("gh:owner/app:env:erasure:PRODUCTION_ERASURE_KEY", CANARY)
    (c.work / "keys.toml").write_text(ERASURE)
    return c, made


def test_railway_holds_the_digest_of_exactly_what_github_got(
    erasure: tuple[Canary, list[str]],
) -> None:
    c, made = erasure
    result = rotate(c, "erasure-key")
    assert result.code == 0, result.stderr
    key = made[0]
    assert value(c, APP + "ERASURE_KEY_SHA256") == hashlib.sha256(key.encode()).hexdigest()
    assert value(c, "gh:owner/app:env:erasure:PRODUCTION_ERASURE_KEY") == key
    progs = [ch.argv[:3] for ch in c.children()]
    # The app redeploys before the job's secret changes, so a failure strands the job only.
    assert progs.index(["railway", "redeploy", "--service"]) < progs.index(["gh", "secret", "set"])
    assert entry(c, "erasure-key")["fp"] == fp(key)


def test_an_environment_open_beyond_main_changes_nothing(
    erasure: tuple[Canary, list[str]],
) -> None:
    c, made = erasure
    c.gh_main_only("owner/app", "erasure", ["main", "dev"])
    result = rotate(c, "erasure-key")
    assert result.code == 1
    assert "admits more than main" in result.stderr
    assert made == []
    assert value(c, "gh:owner/app:env:erasure:PRODUCTION_ERASURE_KEY") == CANARY


# ---------------------------------------------------------------------------- datastores


def _url(pw: str) -> str:
    return f"postgresql://postgres:{quote(pw, safe='')}@db.example.test:5432/railway"


@pytest.fixture
def stores(canary: Canary, made: list[str]) -> tuple[Canary, list[str]]:
    c = canary
    c.target_put(PG + "POSTGRES_PASSWORD", CANARY)
    c.target_put(REDIS + "REDIS_PASSWORD", made_up("redis-old"))
    for service in ("app", "Redis", "Postgres"):
        c.target_put(f"railway:proj:{service}:production:PORT", "8080", secret=False)
    c.target(PG + "POSTGRES_PASSWORD")  # loads the fake's state
    # The URL holds the password, which the canary watches; the URL's other parts are plain,
    # so the URL itself is not watched (psql gets it without the password).
    url = {"value": _url(CANARY), "updated_at": "2026-01-01T00:00:00Z", "writes": 0}
    c.set_db("targets", {**c.db["targets"], PG + "DATABASE_PUBLIC_URL": url})
    c.set_db("pg", {"password": CANARY})
    template = "postgresql://postgres:{pw}@db.example.test:5432/railway"
    c.set_db(
        "derived",
        {PG + "POSTGRES_PASSWORD": {"url": PG + "DATABASE_PUBLIC_URL", "template": template}},
    )
    (c.work / "keys.toml").write_text(DATASTORES)
    return c, made


def test_postgres_learns_the_new_password_before_anything_restarts(
    stores: tuple[Canary, list[str]],
) -> None:
    c, made = stores
    result = rotate(c, "pg", "redis")
    assert result.code == 0, result.stderr
    pg_pw, redis_pw = made
    assert value(c, PG + "POSTGRES_PASSWORD") == pg_pw
    assert value(c, REDIS + "REDIS_PASSWORD") == redis_pw
    assert len(redis_pw) == 48  # hex: a value starting with -- would be read as an option
    db = c.db["pg"]
    assert db["altered_by"] == "postgres"
    assert db["verifier"].startswith("SCRAM-SHA-256$4096:")  # never the password itself
    assert redeploys(c) == ["Redis", "app", "Postgres"]
    calls = [ch for ch in c.children() if ch.prog == "psql"]
    assert len(calls) == 2  # the ALTER over the old URL, then select 1 over the new one
    assert all(":" not in ch.argv[1].split("@")[0].removeprefix("postgresql://") for ch in calls)


def test_a_failed_alter_stages_nothing_and_prints_the_recovery(
    stores: tuple[Canary, list[str]],
) -> None:
    c, _ = stores
    c.set_db("pg", {"password": CANARY, "alter_fails": True})
    result = rotate(c, "pg", "redis")
    assert result.code == 1
    assert "railway ssh --service Postgres --environment production" in result.stderr
    assert value(c, PG + "POSTGRES_PASSWORD") == CANARY
    assert not redeploys(c)


def test_a_new_password_that_does_not_connect_restarts_nothing(
    stores: tuple[Canary, list[str]],
) -> None:
    c, _ = stores
    c.set_db("derived", {})  # Railway's URL keeps the old password: the new one cannot sign in
    result = rotate(c, "pg")
    assert result.code == 1
    assert not redeploys(c)


def test_a_failed_deploy_stops_the_chain(stores: tuple[Canary, list[str]]) -> None:
    c, _ = stores
    c.child_fails(["railway", "redeploy"], code=9, skip=1)
    result = rotate(c, "pg", "redis")
    assert result.code == 1
    assert redeploys(c) == ["Redis", "app"]


def test_scram_matches_the_rfc_7677_example() -> None:
    # RFC 7677 section 3: password "pencil", this salt, 4096 rounds; the server key in the
    # verifier must sign the example's AuthMessage into the RFC's ServerSignature.
    salt = base64.b64decode("W22ZaJ0SNY7soEsUEjb6gQ==")
    got = runtime.scram_verifier(Secret("pencil"), salt, 4096)
    assert got.startswith("SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$")
    server_key = base64.b64decode(got.rsplit(":", 1)[1])
    nonce = "rOprNGfwEbeRWgbNEkqO"
    full = nonce + "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
    auth = f"n=user,r={nonce},r={full},s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=biws,r={full}"
    signature = hmac.new(server_key, auth.encode(), "sha256").digest()
    assert base64.b64encode(signature).decode() == "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="


def test_psql_target_moves_the_password_out_of_the_url() -> None:
    bare, user, pw = runtime.psql_target(Secret("postgresql://us%40r:p%2Fw@h:5/db"))
    assert (bare, user, pw.reveal()) == ("postgresql://us%40r@h:5/db", "us@r", "p/w")


# ---------------------------------------------------------------------------- the mapping file


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (
            '[[credential]]\nname = "g"\nkind = "generated"\nitem = "op://V/x"\n'
            'kept_because = "y"\n',
            "lives only at its targets",
        ),
        (
            '[[credential]]\nname = "p"\nkind = "postgres-password"\nkept_because = "y"\n',
            "url_variable: missing",
        ),
        (
            '[[credential]]\nname = "g"\nkind = "generic"\nitem = "op://V/x"\ngenerate = "hex32"\n'
            'kept_because = "y"\n',
            "only for generated",
        ),
    ],
)
def test_the_mapping_file_rules_for_these_kinds(canary: Canary, text: str, message: str) -> None:
    (canary.work / "keys.toml").write_text(text)
    result = canary.run(["list"])
    assert message in result.stderr


def test_keys_sync_refuses_a_secret_kept_only_at_its_targets(
    signing: tuple[Canary, list[str], str],
) -> None:
    c, _, _ = signing
    result = c.run(["sync", "jwt-secret"], env=ENV)
    assert result.code == 3
    assert "lives only at its targets" in result.stderr


def test_keys_new_refuses_a_secret_kept_only_at_its_targets(canary: Canary) -> None:
    result = canary.run(["new", "generated", "x", "--vault", "V", "--kept-because", "y"])
    assert result.code == 3
    assert "no 1Password item" in result.stderr
    assert not canary.children()
