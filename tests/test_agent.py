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
            return 0, b"git@github.com:jasonluther/partygame.git\n"
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
        return agent.Deps(run=self.run, send=self.send, now=lambda: 1_000_000, exec_gh=self.exec_gh)


class TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


def ctx(
    stdin: str = "", environ: Mapping[str, str] | None = None, stdout: io.StringIO | None = None
):
    env = {"KEYS_GH_APP": "kilotronic-agents", "KEYS_REAL_GH": "/opt/homebrew/bin/gh"}
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
            "git@github.com:jasonluther/partygame.git",
            ("jasonluther", "partygame"),
        ),
        (["pr", "list"], {}, "https://github.com/kilotronic/keys.git", ("kilotronic", "keys")),
        (["auth", "status"], {"KEYS_GH_DEFAULT_OWNER": "jasonluther"}, None, ("jasonluther", None)),
    ],
)
def test_the_owner_comes_from_the_call_then_the_repo(
    args: list[str], env: dict[str, str], origin: str | None, want: tuple[str, str | None]
) -> None:
    assert agent.target(args, env, origin) == want


def test_no_owner_at_all_is_a_usage_error() -> None:
    with pytest.raises(UsageError):
        agent.target(["pr", "list"], {}, None)


# ── keys gh ──────────────────────────────────────────────────────────────────


def test_gh_gets_the_token_only_in_its_environment_and_it_is_revoked() -> None:
    f = Fakes()
    c = ctx(
        environ={"GITHUB_PERSONAL_ACCESS_TOKEN": "owner-admin", "GITHUB_TOKEN": "x", "HOME": "/h"}
    )
    code = agent.gh(gh_args("pr", "list", "-R", "jasonluther/partygame"), c, f.deps())
    assert code == 0
    ((argv, env),) = f.gh_calls
    assert argv == ["/opt/homebrew/bin/gh", "pr", "list", "-R", "jasonluther/partygame"]
    assert env["GH_TOKEN"] == TOKEN
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" not in env
    assert "GITHUB_TOKEN" not in env
    assert env["HOME"] == "/h"
    assert f.sends[-1][0] == "DELETE"
    assert TOKEN not in printed(c)


def test_gh_revokes_even_when_gh_fails_and_passes_its_exit_code() -> None:
    f = Fakes()
    f.gh_code = 5
    assert agent.gh(gh_args("pr", "list", "-R", "jasonluther/partygame"), ctx(), f.deps()) == 5
    assert f.sends[-1][0] == "DELETE"


def test_a_failed_revoke_warns_without_the_token() -> None:
    f = Fakes(revoke_status=401)
    c = ctx()
    agent.gh(gh_args("pr", "list", "-R", "jasonluther/partygame"), c, f.deps())
    assert "could not be revoked" in err(c)
    assert TOKEN not in printed(c)


def test_an_owner_with_no_installation_fails_closed_and_never_runs_gh() -> None:
    f = Fakes(installed={"jasonluther": 7})
    with pytest.raises(agent.AgentError, match="not installed on someone/repo"):
        agent.gh(gh_args("pr", "list", "-R", "someone/repo"), ctx(), f.deps())
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
        agent.gh(gh_args("pr", "list", "-R", "jasonluther/partygame"), c, Fakes().deps())


def test_no_key_in_the_keychain_names_install_key() -> None:
    f = Fakes()
    f.keychain = None
    with pytest.raises(agent.AgentError, match="keys install-key kilotronic-agents"):
        agent.gh(gh_args("pr", "list", "-R", "jasonluther/partygame"), ctx(), f.deps())


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
            "https://github.com/jasonluther/partygame",
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
            ["pr", "list", "-R", "not a repo"], {}, "https://github.com/jasonluther/partygame"
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
    agent.gh(gh_args("pr", "list", "-R", "jasonluther/partygame"), ctx(), deps)
    assert json.loads(bodies[0] or b"{}") == {"repositories": ["partygame"]}


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
            gh_args("pr", "list", "-R", "jasonluther/partygame"),
            ctx(environ={"KEYS_GH_ACTIVE": "1"}),
            f.deps(),
        )
    assert f.sends == []


def test_the_child_is_told_it_runs_under_keys_gh() -> None:
    f = Fakes()
    agent.gh(gh_args("pr", "list", "-R", "jasonluther/partygame"), ctx(), f.deps())
    assert f.gh_calls[0][1]["KEYS_GH_ACTIVE"] == "1"


def test_the_real_sender_reads_a_whole_token_answer() -> None:
    # A repo-limited token's answer carries full repository objects, well past 4 KB.
    send = agent.Deps().send
    assert getattr(send, "keywords", {}).get("limit", 0) >= 1 << 20
