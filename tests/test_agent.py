"""keys install-key, gh and git-credential: the token reaches only gh's environment or git's
pipe, an owner with no installation fails closed, and nothing prints a value."""

from __future__ import annotations

import argparse
import base64
import io
import json
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

import pytest

from keys import agent
from keys.context import Context, UsageError
from keys.probes import Answer

PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIfake\n-----END RSA PRIVATE KEY-----\n"
TOKEN = "ghs_mintedtokenvalue1234567890"
JWT_SIG = b"\x01\x02signature"


class Fakes:
    def __init__(self, installed: Mapping[str, int] | None = None, revoke_status: int = 204):
        self.installed = dict(installed if installed is not None else {"jasonluther": 7})
        self.runs: list[tuple[list[str], bytes | None, dict[int, bytes]]] = []
        self.sends: list[tuple[str, str, dict[str, str]]] = []
        self.revoke_status = revoke_status
        self.keychain: bytes | None = base64.b64encode(PEM.encode())
        self.gh_calls: list[tuple[list[str], dict[str, str]]] = []
        self.gh_code = 0

    def run(
        self, argv: Sequence[str], stdin: bytes | None, fds: Mapping[int, bytes]
    ) -> tuple[int, bytes]:
        argv = list(argv)
        self.runs.append((argv, stdin, dict(fds)))
        if argv[:2] == ["security", "-i"]:
            return 0, b""
        if argv[:2] == ["security", "find-generic-password"]:
            if self.keychain is None:
                return 44, b""
            if "-w" in argv:
                return 0, self.keychain + b"\n"
            return 0, b'keychain: "login"\n    "icmt"<blob>="Iv23clientid"\n'
        if argv[0] == "openssl":
            return 0, JWT_SIG
        if argv[0] == "git":
            return 0, b"git@github.com:jasonluther/demo-app.git\n"
        raise AssertionError(f"unexpected child {argv}")

    def send(self, method: str, url: str, headers: dict[str, str], data: bytes | None) -> Answer:
        self.sends.append((method, url, headers))
        path = url.removeprefix(agent.API)
        if method == "DELETE":
            return Answer(self.revoke_status, "")
        if method == "POST" and path.endswith("/access_tokens"):
            return Answer(201, json.dumps({"token": TOKEN}))
        if method == "GET" and path == "/app":
            return Answer(200, "{}")
        for prefix in ("/repos/", "/users/", "/orgs/"):
            if path.startswith(prefix):
                owner = path[len(prefix) :].split("/")[0]
                if owner in self.installed:
                    return Answer(200, json.dumps({"id": self.installed[owner]}))
                return Answer(404, "{}")
        return Answer(500, "")

    def exec_gh(self, argv: Sequence[str], env: Mapping[str, str]) -> int:
        self.gh_calls.append((list(argv), dict(env)))
        return self.gh_code

    def deps(self) -> agent.Deps:
        return agent.Deps(
            run=self.run,
            send=self.send,
            now=lambda: 1_000_000,
            exec_gh=self.exec_gh,
            platform="darwin",
        )


class TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


def ctx(
    stdin: str = "", environ: Mapping[str, str] | None = None, stdout: io.StringIO | None = None
):
    env = {
        "KEYS_GH_APPS": "jasonluther=kilotronic-agents kilotronic=kilotronic-agents",
        "KEYS_REAL_GH": "/opt/homebrew/bin/gh",
    }
    env.update(environ or {})
    c = Context(
        stdout=stdout or io.StringIO(), stderr=io.StringIO(), stdin=io.StringIO(stdin), environ=env
    )
    return c


def out(c: Context) -> str:
    return cast(io.StringIO, c.stdout).getvalue()


def err(c: Context) -> str:
    return cast(io.StringIO, c.stderr).getvalue()


def printed(c: Context) -> str:
    return out(c) + err(c)


def gh_args(*rest: str, app: str | None = None) -> argparse.Namespace:
    return argparse.Namespace(app=app, gh_args=["--", *rest])


# ── Which owner ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("args", "env", "origin", "want"),
    [
        (["pr", "list", "-R", "kilotronic/keys"], {}, None, ("kilotronic", "keys")),
        (["pr", "list", "--repo=jasonluther/agents"], {}, None, ("jasonluther", "agents")),
        (["pr", "list"], {"GH_REPO": "kilotronic/lint"}, None, ("kilotronic", "lint")),
        (
            ["pr", "view", "https://github.com/kilotronic/keys/pull/7"],
            {},
            None,
            ("kilotronic", "keys"),
        ),
        (["api", "repos/kilotronic/keys/pulls"], {}, None, ("kilotronic", "keys")),
        (["api", "/orgs/kilotronic/members"], {}, None, ("kilotronic", None)),
        (
            ["pr", "list"],
            {},
            "git@github.com:jasonluther/demo-app.git",
            ("jasonluther", "demo-app"),
        ),
        (["pr", "list"], {}, "https://github.com/kilotronic/keys.git", ("kilotronic", "keys")),
        (["auth", "status"], {"KEYS_GH_DEFAULT_OWNER": "jasonluther"}, None, ("jasonluther", None)),
        (["project", "view", "1", "--owner", "example-org"], {}, None, ("example-org", None)),
        (["project", "field-list", "1", "--owner=example-org"], {}, None, ("example-org", None)),
        (
            ["project", "view", "1", "--owner", "example-org"],
            {},
            "git@github.com:jasonluther/demo-app.git",
            ("example-org", None),
        ),
        (
            ["project", "item-edit", "--id", "PVTI_x", "--project-id", "PVT_y"],
            {"KEYS_GH_OWNER": "example-org", "KEYS_GH_DEFAULT_OWNER": "jasonluther"},
            "git@github.com:jasonluther/demo-app.git",
            ("example-org", None),
        ),
        (
            ["pr", "list", "-R", "kilotronic/keys"],
            {"KEYS_GH_OWNER": "example-org"},
            None,
            ("kilotronic", "keys"),
        ),
        (
            ["project", "list", "--owner", "@me"],
            {"KEYS_GH_DEFAULT_OWNER": "jasonluther"},
            None,
            ("jasonluther", None),
        ),
        (
            ["pr", "list"],
            {"KEYS_GH_OWNER": ""},
            "https://github.com/kilotronic/keys.git",
            ("kilotronic", "keys"),
        ),
    ],
)
def test_the_owner_comes_from_the_call_then_the_repo(
    args: list[str], env: dict[str, str], origin: str | None, want: tuple[str, str | None]
) -> None:
    assert agent.target(args, env, origin) == want


def test_an_owner_flag_without_a_name_is_a_usage_error() -> None:
    with pytest.raises(UsageError):
        agent.target(["project", "view", "1", "--owner"], {}, None)
    with pytest.raises(UsageError):
        agent.target(["project", "view", "1", "--owner=not/valid"], {}, None)


def test_no_owner_at_all_is_a_usage_error() -> None:
    with pytest.raises(UsageError):
        agent.target(["pr", "list"], {}, None)


# ── keys gh ──────────────────────────────────────────────────────────────────


def test_gh_gets_the_token_only_in_its_environment_and_it_is_revoked() -> None:
    f = Fakes()
    c = ctx(
        environ={"GITHUB_PERSONAL_ACCESS_TOKEN": "owner-admin", "GITHUB_TOKEN": "x", "HOME": "/h"}
    )
    code = agent.gh(gh_args("pr", "list", "-R", "jasonluther/demo-app"), c, f.deps())
    assert code == 0
    ((argv, env),) = f.gh_calls
    assert argv == ["/opt/homebrew/bin/gh", "pr", "list", "-R", "jasonluther/demo-app"]
    assert env["GH_TOKEN"] == TOKEN
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" not in env
    assert "GITHUB_TOKEN" not in env
    assert env["HOME"] == "/h"
    assert f.sends[-1][0] == "DELETE"
    assert TOKEN not in printed(c)


def test_gh_revokes_even_when_gh_fails_and_passes_its_exit_code() -> None:
    f = Fakes()
    f.gh_code = 5
    assert agent.gh(gh_args("pr", "list", "-R", "jasonluther/demo-app"), ctx(), f.deps()) == 5
    assert f.sends[-1][0] == "DELETE"


def test_a_failed_revoke_warns_without_the_token() -> None:
    f = Fakes(revoke_status=401)
    c = ctx()
    agent.gh(gh_args("pr", "list", "-R", "jasonluther/demo-app"), c, f.deps())
    assert "could not be revoked" in err(c)
    assert TOKEN not in printed(c)


def test_an_owner_with_no_installation_fails_closed_and_never_runs_gh() -> None:
    f = Fakes(installed={"jasonluther": 7})
    c = ctx(environ={"KEYS_GH_APPS": "someone=kilotronic-agents"})
    with pytest.raises(agent.AgentError, match="not installed on someone/repo"):
        agent.gh(gh_args("pr", "list", "-R", "someone/repo"), c, f.deps())
    assert f.gh_calls == []
    assert not any(m == "POST" for m, _, _ in f.sends)


@pytest.mark.parametrize("sub", ["token", "login", "refresh", "switch"])
def test_gh_refuses_the_owners_auth_commands(sub: str) -> None:
    f = Fakes()
    with pytest.raises(UsageError):
        agent.gh(gh_args("auth", sub), ctx(), f.deps())
    assert f.gh_calls == []
    assert f.sends == []


def test_no_app_named_is_a_usage_error() -> None:
    c = ctx()
    c.environ = {"KEYS_REAL_GH": "/x/gh"}
    with pytest.raises(UsageError, match="--app"):
        agent.gh(gh_args("pr", "list", "-R", "jasonluther/demo-app"), c, Fakes().deps())


def test_no_key_in_the_keychain_names_install_key() -> None:
    f = Fakes()
    f.keychain = None
    with pytest.raises(agent.AgentError, match="keys install-key kilotronic-agents"):
        agent.gh(gh_args("pr", "list", "-R", "jasonluther/demo-app"), ctx(), f.deps())


def test_the_real_gh_skips_the_keys_shim(tmp_path: Path) -> None:
    shim, real = tmp_path / "shim", tmp_path / "real"
    shim.mkdir()
    real.mkdir()
    (shim / "gh").write_text('#!/bin/sh\nexec keys gh -- "$@"\n')
    (real / "gh").write_text("#!/bin/sh\necho real\n")
    for p in (shim / "gh", real / "gh"):
        p.chmod(0o755)
    assert agent.real_gh({"PATH": f"{shim}:{real}"}) == str(real / "gh")


# ── keys git-credential ──────────────────────────────────────────────────────

GET = "protocol=https\nhost=github.com\npath=jasonluther/agents.git\n\n"


def test_git_gets_the_token_on_its_pipe_for_the_paths_owner() -> None:
    f = Fakes()
    c = ctx(stdin=GET)
    assert agent.git_credential(argparse.Namespace(app=None, operation="get"), c, f.deps()) == 0
    assert out(c) == f"username=x-access-token\npassword={TOKEN}\n"  # type: ignore[attr-defined]
    assert any(u.endswith("/repos/jasonluther/agents/installation") for _, u, _ in f.sends)


def test_git_credential_refuses_a_terminal() -> None:
    c = ctx(stdin=GET, stdout=TTY())
    with pytest.raises(UsageError, match="pipe"):
        agent.git_credential(argparse.Namespace(app=None, operation="get"), c, Fakes().deps())


def test_git_without_a_path_is_told_to_set_use_http_path() -> None:
    c = ctx(stdin="protocol=https\nhost=github.com\n\n")
    with pytest.raises(UsageError, match="useHttpPath"):
        agent.git_credential(argparse.Namespace(app=None, operation="get"), c, Fakes().deps())


@pytest.mark.parametrize(
    "stdin",
    ["protocol=https\nhost=gitlab.com\npath=a/b\n", "protocol=http\nhost=github.com\npath=a/b\n"],
)
def test_another_host_is_left_to_the_next_helper(stdin: str) -> None:
    f = Fakes()
    c = ctx(stdin=stdin)
    assert agent.git_credential(argparse.Namespace(app=None, operation="get"), c, f.deps()) == 0
    assert out(c) == ""
    assert f.sends == []


@pytest.mark.parametrize("op", ["store", "erase"])
def test_store_and_erase_do_nothing(op: str) -> None:
    f = Fakes()
    c = ctx(stdin=GET)
    assert agent.git_credential(argparse.Namespace(app=None, operation=op), c, f.deps()) == 0
    assert out(c) == ""
    assert f.sends == []


def test_git_for_an_owner_with_no_installation_fails_closed() -> None:
    f = Fakes(installed={})
    c = ctx(stdin=GET)
    with pytest.raises(agent.AgentError, match="not installed on jasonluther/agents"):
        agent.git_credential(argparse.Namespace(app=None, operation="get"), c, f.deps())
    # quit=1: git must not go on to a later helper holding the owner's own login.
    assert out(c) == "quit=1\n"  # type: ignore[attr-defined]


# ── The key and the JWT ──────────────────────────────────────────────────────


def test_the_key_reaches_the_keychain_on_stdin_never_argv() -> None:
    f = Fakes()
    agent.store_key("kilotronic-agents", agent.Secret(PEM), "Iv23clientid", f.deps())
    ((argv, stdin, _),) = f.runs
    assert argv == ["security", "-i"]
    assert PEM not in " ".join(argv)
    assert "MIIfake" not in " ".join(argv)
    assert base64.b64encode(PEM.encode()).decode() in (stdin or b"").decode()


def test_off_a_mac_the_key_goes_to_a_file_only_its_owner_can_read(tmp_path: Path) -> None:
    f = Fakes()
    deps = f.deps()
    deps.platform, deps.key_dir = "linux", tmp_path / "app-keys"
    agent.store_key("kilotronic-agents", agent.Secret(PEM), "Iv23clientid", deps)
    path = tmp_path / "app-keys" / "kilotronic-agents.json"
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert not f.runs  # no `security`, no child at all
    pem, client_id = agent.load_key("kilotronic-agents", deps)
    assert pem == agent.Secret(PEM)
    assert client_id == "Iv23clientid"
    assert [p.name for p in path.parent.iterdir()] == [path.name]  # no temporary file left


def test_a_key_file_others_can_read_is_refused(tmp_path: Path) -> None:
    deps = Fakes().deps()
    deps.platform, deps.key_dir = "linux", tmp_path
    agent.store_key("kilotronic-agents", agent.Secret(PEM), "Iv23clientid", deps)
    (tmp_path / "kilotronic-agents.json").chmod(0o644)
    with pytest.raises(agent.AgentError, match="readable by others") as e:
        agent.load_key("kilotronic-agents", deps)
    assert "MIIfake" not in str(e.value)


def test_a_missing_or_foreign_key_file_names_install_key(tmp_path: Path) -> None:
    deps = Fakes().deps()
    deps.platform, deps.key_dir = "linux", tmp_path
    with pytest.raises(agent.AgentError, match="keys install-key kilotronic-agents"):
        agent.load_key("kilotronic-agents", deps)
    bad = tmp_path / "kilotronic-agents.json"
    bad.write_text('{"pem": "MIIfake"}')
    bad.chmod(0o600)
    with pytest.raises(agent.AgentError, match="not one install-key wrote") as e:
        agent.load_key("kilotronic-agents", deps)
    assert "MIIfake" not in str(e.value)


def test_a_client_id_that_could_break_the_keychain_line_is_refused() -> None:
    with pytest.raises(UsageError):
        agent.store_key("kilotronic-agents", agent.Secret(PEM), 'Iv" -w x', Fakes().deps())


def test_openssl_gets_the_key_on_stdin_and_the_claims_on_a_pipe() -> None:
    f = Fakes()
    jwt = agent.app_jwt(agent.Secret(PEM), "Iv23clientid", f.deps())
    ((argv, stdin, fds),) = f.runs
    assert "MIIfake" not in " ".join(argv)
    assert stdin == PEM.encode()
    claims = json.loads(base64.urlsafe_b64decode(fds[3].split(b".")[1] + b"=="))
    assert claims == {"iat": 1_000_000 - 60, "exp": 1_000_000 + 540, "iss": "Iv23clientid"}
    assert str(jwt) == "<secret>"


def test_a_real_openssl_signs_over_the_pipes(tmp_path: Path) -> None:
    key = tmp_path / "k.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(key), "2048"], check=True, capture_output=True)
    pem = key.read_text()
    jwt = agent.app_jwt(agent.Secret(pem), "Iv23clientid", agent.Deps(now=lambda: 1_000_000))
    head, body, sig = jwt.reveal().split(".")
    pub = tmp_path / "pub.pem"
    subprocess.run(
        ["openssl", "rsa", "-in", str(key), "-pubout", "-out", str(pub)],
        check=True,
        capture_output=True,
    )
    (tmp_path / "data").write_bytes(f"{head}.{body}".encode())
    (tmp_path / "sig").write_bytes(base64.urlsafe_b64decode(sig + "=="))
    v = subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(pub),
            "-signature",
            str(tmp_path / "sig"),
            str(tmp_path / "data"),
        ],
        capture_output=True,
    )
    assert v.returncode == 0


# ── Review fixes ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("args", "origin", "want"),
    [
        (["pr", "list", "-R", "github.com/kilotronic/keys"], None, ("kilotronic", "keys")),
        (["pr", "list", "-Rkilotronic/keys"], None, ("kilotronic", "keys")),
        (
            ["repo", "clone", "kilotronic/keys"],
            "https://github.com/jasonluther/demo-app",
            ("kilotronic", "keys"),
        ),
        (["release", "view", "kilotronic/keys"], None, ("kilotronic", "keys")),
        (
            ["api", "repos/{owner}/{repo}/pulls"],
            "https://github.com/kilotronic/keys.git",
            ("kilotronic", "keys"),
        ),
    ],
)
def test_more_ways_of_naming_the_repo(
    args: list[str], origin: str | None, want: tuple[str, str | None]
) -> None:
    assert agent.target(args, {}, origin) == want


def test_an_unreadable_repo_flag_fails_rather_than_guessing() -> None:
    with pytest.raises(UsageError, match="-R"):
        agent.target(
            ["pr", "list", "-R", "not a repo"], {}, "https://github.com/jasonluther/demo-app"
        )


@pytest.mark.parametrize(
    "rest",
    [
        ["auth", "status", "--show-token"],
        ["auth", "status", "-t"],
        ["auth", "git-credential", "get"],
        ["auth", "setup-git"],
        ["auth", "logout"],
    ],
)
def test_only_plain_auth_status_is_an_agents(rest: list[str]) -> None:
    f = Fakes()
    with pytest.raises(UsageError):
        agent.gh(gh_args(*rest), ctx(), f.deps())
    assert f.gh_calls == []
    assert f.sends == []


def test_a_known_repo_the_app_does_not_cover_never_widens_to_the_owner() -> None:
    f = Fakes(installed={"jasonluther": 7})
    original = f.send

    def send(method: str, url: str, headers: dict[str, str], data: bytes | None) -> Answer:
        if "/repos/jasonluther/secret-repo/installation" in url:
            return Answer(404, "{}")
        return original(method, url, headers, data)

    deps = f.deps()
    deps.send = send
    with pytest.raises(agent.AgentError, match="not installed on jasonluther/secret-repo"):
        agent.gh(gh_args("pr", "list", "-R", "jasonluther/secret-repo"), ctx(), deps)
    assert f.gh_calls == []


def test_the_token_is_limited_to_the_one_repo() -> None:
    f = Fakes()
    bodies: list[bytes | None] = []
    original = f.send

    def send(method: str, url: str, headers: dict[str, str], data: bytes | None) -> Answer:
        if method == "POST":
            bodies.append(data)
        return original(method, url, headers, data)

    deps = f.deps()
    deps.send = send
    agent.gh(gh_args("pr", "list", "-R", "jasonluther/demo-app"), ctx(), deps)
    assert json.loads(bodies[0] or b"{}") == {"repositories": ["demo-app"]}


def test_an_owner_flag_mints_a_token_for_the_whole_installation() -> None:
    # gh project names an account, not a repo: a token for one repo could not see its boards.
    f = Fakes()
    calls: list[tuple[str, str, bytes | None]] = []
    original = f.send

    def send(method: str, url: str, headers: dict[str, str], data: bytes | None) -> Answer:
        calls.append((method, url, data))
        return original(method, url, headers, data)

    deps = f.deps()
    deps.send = send
    agent.gh(gh_args("project", "view", "1", "--owner", "jasonluther"), ctx(), deps)
    posts = [(u, d) for m, u, d in calls if m == "POST"]
    assert json.loads(posts[0][1] or b"{}") == {}
    assert not any("/repos/" in u for _, u, _ in calls)


def test_an_lfs_path_names_its_repo() -> None:
    f = Fakes()
    c = ctx(stdin="protocol=https\nhost=github.com\npath=jasonluther/agents.git/info/lfs\n\n")
    assert agent.git_credential(argparse.Namespace(app=None, operation="get"), c, f.deps()) == 0
    assert "password=" in out(c)


def test_git_without_a_path_also_tells_git_to_stop() -> None:
    c = ctx(stdin="protocol=https\nhost=github.com\n\n")
    with pytest.raises(UsageError):
        agent.git_credential(argparse.Namespace(app=None, operation="get"), c, Fakes().deps())
    assert out(c) == "quit=1\n"  # type: ignore[attr-defined]


def test_keys_gh_reaching_itself_stops() -> None:
    f = Fakes()
    with pytest.raises(agent.AgentError, match="reached itself"):
        agent.gh(
            gh_args("pr", "list", "-R", "jasonluther/demo-app"),
            ctx(environ={"KEYS_GH_ACTIVE": "1"}),
            f.deps(),
        )
    assert f.sends == []


def test_the_child_is_told_it_runs_under_keys_gh() -> None:
    f = Fakes()
    agent.gh(gh_args("pr", "list", "-R", "jasonluther/demo-app"), ctx(), f.deps())
    assert f.gh_calls[0][1]["KEYS_GH_ACTIVE"] == "1"


def test_the_real_sender_reads_a_whole_token_answer() -> None:
    # A repo-limited token's answer carries full repository objects, well past 4 KB.
    send = agent.Deps().send
    assert getattr(send, "keywords", {}).get("limit", 0) >= 1 << 20


# ── Which App, by owner ──────────────────────────────────────────────────────


def _keychain_services(f: Fakes) -> list[str]:
    return [
        argv[argv.index("-s") + 1]
        for argv, _, _ in f.runs
        if argv[:2] == ["security", "find-generic-password"]
    ]


# Each owner maps to its own App, unlike ctx()'s default, so a skipped lookup cannot pass unseen.
APPS = {"KEYS_GH_APPS": "acme-corp=acme-agents, jasonluther=jl-agents kilotronic=k-agents"}


def map_only(environ: Mapping[str, str] | None = None, stdin: str = "") -> Context:
    return ctx(stdin=stdin, environ={**APPS, **(environ or {})})


def test_each_owner_gets_its_own_app() -> None:
    f = Fakes(installed={"acme-corp": 9, "jasonluther": 7})
    agent.gh(gh_args("pr", "list", "-R", "acme-corp/widgets"), map_only(), f.deps())
    first = _keychain_services(f)
    agent.gh(gh_args("pr", "list", "-R", "jasonluther/demo-app"), map_only(), f.deps())
    second = _keychain_services(f)[len(first) :]
    assert first
    assert all("acme-agents" in s for s in first)
    assert second
    assert all("jl-agents" in s for s in second)


def test_owner_case_maps_to_the_same_app() -> None:
    f = Fakes(installed={"Acme-Corp": 9})  # GitHub matches names in any case; the fake doesn't
    agent.gh(gh_args("pr", "list", "-R", "Acme-Corp/widgets"), map_only(), f.deps())
    assert all("acme-agents" in s for s in _keychain_services(f))


def test_the_retired_single_app_setting_alone_is_refused() -> None:
    f = Fakes(installed={"kilotronic": 8})
    c = ctx()
    c.environ = {"KEYS_GH_APP": "kilotronic-agents", "KEYS_REAL_GH": "/opt/homebrew/bin/gh"}
    with pytest.raises(UsageError, match=r"\$KEYS_GH_APPS"):
        agent.gh(gh_args("pr", "list", "-R", "kilotronic/keys"), c, f.deps())
    assert f.sends == []
    assert f.gh_calls == []


def test_a_non_ascii_owner_never_folds_onto_a_mapped_one() -> None:
    f = Fakes(installed={"kilotronic": 8})
    with pytest.raises(UsageError):
        agent.gh(gh_args("api", "https://github.com/\u212ailotronic/x"), map_only(), f.deps())
    assert f.sends == []


def test_two_apps_for_one_owner_is_a_usage_error() -> None:
    c = map_only({"KEYS_GH_APPS": "acme-corp=acme-agents Acme-Corp=k-agents"})
    with pytest.raises(UsageError, match="two Apps"):
        agent.gh(gh_args("pr", "list", "-R", "acme-corp/widgets"), c, Fakes().deps())


def test_a_malformed_app_map_is_a_usage_error() -> None:
    c = map_only({"KEYS_GH_APPS": "acme-corp"})
    with pytest.raises(UsageError, match="KEYS_GH_APPS"):
        agent.gh(gh_args("pr", "list", "-R", "acme-corp/widgets"), c, Fakes().deps())


def test_app_flag_wins_even_over_a_malformed_map() -> None:
    f = Fakes(installed={"acme-corp": 9})
    c = map_only({"KEYS_GH_APPS": "acme-corp"})
    agent.gh(gh_args("pr", "list", "-R", "acme-corp/widgets", app="k-agents"), c, f.deps())
    assert all("k-agents" in s for s in _keychain_services(f))


def test_no_app_source_is_named_before_any_git_call() -> None:
    f = Fakes()
    c = ctx()
    c.environ = {"KEYS_REAL_GH": "/x/gh"}
    with pytest.raises(UsageError, match="--app"):
        agent.gh(gh_args("pr", "list"), c, f.deps())
    assert f.runs == []


GIT_IN = "protocol=https\nhost=github.com\npath={path}\n"


def test_git_credential_picks_the_app_by_the_path_owner() -> None:
    f = Fakes(installed={"acme-corp": 9})
    c = map_only(stdin=GIT_IN.format(path="acme-corp/widgets.git"))
    agent.git_credential(argparse.Namespace(app=None, operation="get"), c, f.deps())
    assert _keychain_services(f)
    assert all("acme-agents" in s for s in _keychain_services(f))


@pytest.mark.parametrize("env", [{}, {"KEYS_GH_APPS": "acme-corp"}])
def test_git_credential_quits_on_an_app_map_refusal(env: dict[str, str]) -> None:
    f = Fakes()
    c = map_only(env, stdin=GIT_IN.format(path="someone-else/repo.git"))
    with pytest.raises(UsageError):
        agent.git_credential(argparse.Namespace(app=None, operation="get"), c, f.deps())
    assert out(c) == "quit=1\n"
    assert f.sends == []


def test_git_credential_ignores_a_leftover_single_app_for_an_unmapped_owner() -> None:
    f = Fakes()
    c = ctx(stdin=GIT_IN.format(path="someone-else/repo.git"), environ=APPS)
    with pytest.raises(UsageError):
        agent.git_credential(argparse.Namespace(app=None, operation="get"), c, f.deps())
    assert out(c) == "quit=1\n"
    assert f.sends == []


def test_git_credential_quits_on_an_unexpected_failure() -> None:
    f = Fakes(installed={"acme-corp": 9})

    def boom(*_: object) -> agent.Answer:
        raise RuntimeError("unexpected")

    deps = f.deps()
    deps = agent.Deps(
        run=deps.run, send=boom, now=deps.now, exec_gh=deps.exec_gh, platform="darwin"
    )
    c = map_only(stdin=GIT_IN.format(path="acme-corp/widgets.git"))
    with pytest.raises(RuntimeError):
        agent.git_credential(argparse.Namespace(app=None, operation="get"), c, deps)
    assert out(c) == "quit=1\n"


@pytest.mark.parametrize("host", ["GitHub.com", "github.com:443"])
def test_git_credential_claims_github_in_any_spelling(host: str) -> None:
    f = Fakes(installed={"acme-corp": 9})
    c = map_only(stdin=f"protocol=https\nhost={host}\npath=acme-corp/widgets.git\n")
    agent.git_credential(argparse.Namespace(app=None, operation="get"), c, f.deps())
    assert "password=" in out(c)
    assert all("acme-agents" in s for s in _keychain_services(f))


def test_a_crafted_owner_is_refused_on_every_app_source() -> None:
    f = Fakes()
    with pytest.raises(UsageError):
        agent.gh(gh_args("api", "https://github.com/..%2Fusers/x", app="k-agents"), ctx(), f.deps())
    assert f.sends == []


def test_has_key_answers_by_exit_code_and_prints_nothing(tmp_path: Path) -> None:
    deps = Fakes().deps()
    deps.platform, deps.key_dir = "linux", tmp_path
    c = map_only()
    ns = argparse.Namespace(name="kilotronic-agents")
    assert agent.has_key(ns, c, deps) == agent.EXIT_FAIL
    agent.store_key("kilotronic-agents", agent.Secret(PEM), "Iv23clientid", deps)
    assert agent.has_key(ns, c, deps) == agent.EXIT_OK
    assert out(c) == ""
    f = Fakes()
    f.keychain = None
    assert agent.has_key(ns, c, f.deps()) == agent.EXIT_FAIL
