"""Agents sign in to GitHub as an App: `keys install-key`, `keys gh` and `keys git-credential`.

The App's private key goes from 1Password into one login-keychain item on a Mac (elsewhere, a
file only its owner can read, under ~/.config/keys/app-keys), once, so minting needs no Touch ID.
Each `keys gh` call mints a one-hour installation token for the repo's owner, hands it to the real
gh only in gh's environment, and revokes it when gh ends. `keys git-credential` answers git's
credential protocol on a pipe. An owner with no installation fails with a message naming it;
nothing ever falls back to the owner's own sign-in, and no value is printed, nor written anywhere
but that one keychain item or key file.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import functools
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from keys.context import EXIT_FAIL, EXIT_OK, Context, UsageError
from keys.probes import Answer, send
from keys.secret import Secret

API = "https://api.github.com"
ACCOUNT = "keys"
# Variables gh would prefer over GH_TOKEN, or that carry another sign-in: never passed on.
DROP = ("GITHUB_TOKEN", "GITHUB_PERSONAL_ACCESS_TOKEN", "GH_ENTERPRISE_TOKEN", "GH_HOST")
NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")
OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
CLIENT_ID = re.compile(r"[A-Za-z0-9._-]{4,64}")

# (argv, stdin bytes, extra fds) -> (exit code, stdout bytes). Never stderr: it can echo input.
Runner = Callable[[Sequence[str], bytes | None, Mapping[int, bytes]], tuple[int, bytes]]
Sender = Callable[[str, str, dict[str, str], bytes | None], Answer]


class AgentError(Exception):
    """A step failed. The message names the step and owner, never a value or a reply's text."""


def _run(argv: Sequence[str], stdin: bytes | None, fds: Mapping[int, bytes]) -> tuple[int, bytes]:
    """Run a child with stdin and extra read-only pipes, keeping only its exit code and stdout."""
    pipes: list[tuple[int, int]] = []
    try:
        for _ in fds:
            pipes.append(os.pipe())
        args = list(argv)
        for (placeholder, _data), (r, _w) in zip(fds.items(), pipes, strict=True):
            args = [a.replace(f"/dev/fd/{placeholder}", f"/dev/fd/{r}") for a in args]
        proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            pass_fds=[r for r, _ in pipes],
        )
        writers: list[threading.Thread] = []
        for (_p, data), (r, w) in zip(fds.items(), pipes, strict=True):
            os.close(r)
            writers.append(threading.Thread(target=_write_all, args=(w, data), daemon=True))
        pipes.clear()
        for t in writers:
            t.start()
        try:
            out, _ = proc.communicate(stdin, timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise AgentError(f"{argv[0]} took longer than 60s") from None
        for t in writers:
            t.join(5)
        return proc.returncode, out
    except FileNotFoundError:
        raise AgentError(f"{argv[0]} is not installed") from None
    except (OSError, subprocess.SubprocessError) as e:
        raise AgentError(f"{argv[0]} failed ({type(e).__name__})") from None
    finally:
        for r, w in pipes:
            for fd in (r, w):
                with contextlib.suppress(OSError):
                    os.close(fd)


def _write_all(fd: int, data: bytes) -> None:
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
    except OSError:
        pass
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)


_SEND: Sender = functools.partial(send, limit=1 << 20)


@dataclass
class Deps:
    """What the commands touch outside Python; tests swap in fakes."""

    run: Runner = _run
    # A token answer lists its repositories in full: read past send's 4 KB default.
    send: Sender = _SEND
    now: Callable[[], float] = time.time
    exec_gh: Callable[[Sequence[str], Mapping[str, str]], int] | None = None
    # Where install-key keeps the key: the login keychain on a Mac, else a 0600 file in key_dir.
    platform: str = sys.platform
    key_dir: Path | None = None


def _key_file(name: str, deps: Deps) -> Path:
    if deps.key_dir is not None:
        return deps.key_dir / f"{name}.json"
    # A relative XDG_CONFIG_HOME is ignored (as the spec says): it would put the key inside
    # whatever folder install-key ran in, a repo perhaps.
    config = os.environ.get("XDG_CONFIG_HOME", "")
    base = Path(config) if os.path.isabs(config) else Path.home() / ".config"
    return base / "keys" / "app-keys" / f"{name}.json"


def _store_name(deps: Deps) -> str:
    return "the login keychain" if deps.platform == "darwin" else "its key file"


# ── The keychain ─────────────────────────────────────────────────────────────


def _service(name: str) -> str:
    return f"keys:{name}"


def store_key(name: str, pem: Secret, client_id: str, deps: Deps) -> None:
    """Write the key to the login keychain through `security -i` on stdin, never argv; off a Mac,
    to a file only its owner can read."""
    if not CLIENT_ID.fullmatch(client_id):
        raise UsageError("the item's client_id field does not look like a GitHub App client id")
    if deps.platform != "darwin":
        _store_file(name, pem, client_id, deps)
        return
    blob = base64.b64encode(pem.reveal().encode()).decode()
    line = f'add-generic-password -U -a {ACCOUNT} -s {_service(name)} -j "{client_id}" -w {blob}\n'
    code, _ = deps.run(["security", "-i"], line.encode(), {})
    if code != 0:
        raise AgentError(f"the keychain refused the key for {name} (security exited {code})")


def _store_file(name: str, pem: Secret, client_id: str, deps: Deps) -> None:
    """Write {"client_id", "pem"} to the key file: folder 0700, file 0600, made under a temporary
    name and renamed into place, so no reader sees half a key or a wider mode."""
    path = _key_file(name, deps)
    tmp = path.with_name(f".{path.name}.{os.getpid()}")
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        tmp.unlink(missing_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(json.dumps({"client_id": client_id, "pem": pem.reveal()}).encode())
        os.replace(tmp, path)
    except OSError as e:
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
        raise AgentError(f"could not write the key file for {name} ({type(e).__name__})") from None


def _load_file(name: str, deps: Deps) -> tuple[Secret, str]:
    path = _key_file(name, deps)
    # One open, not following a link; mode and owner are checked on that same open file.
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        raise AgentError(f"no key file for {name}: run `keys install-key {name}`") from None
    except OSError as e:
        raise AgentError(f"could not read the key file for {name} ({type(e).__name__})") from None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if st.st_mode & 0o077 or st.st_uid != os.getuid():
            raise AgentError(
                f"the key file for {name} is readable by others or not yours: rerun install-key"
            )
        raw = f.read()
    try:
        data = json.loads(raw)
        pem, client_id = data["pem"], data["client_id"]
    except (ValueError, KeyError, TypeError):
        raise AgentError(f"the key file for {name} is not one install-key wrote") from None
    if not isinstance(pem, str) or not isinstance(client_id, str) or "PRIVATE KEY" not in pem:
        raise AgentError(f"the key file for {name} is not one install-key wrote")
    if not CLIENT_ID.fullmatch(client_id):
        raise AgentError(f"the key file for {name} has no client id: rerun install-key")
    return Secret(pem), client_id


def load_key(name: str, deps: Deps) -> tuple[Secret, str]:
    """The key and client id from the keychain item (off a Mac, the file) install-key wrote."""
    if deps.platform != "darwin":
        return _load_file(name, deps)
    code, out = deps.run(
        ["security", "find-generic-password", "-a", ACCOUNT, "-s", _service(name), "-w"], None, {}
    )
    if code != 0:
        raise AgentError(f"no key for {name} in the keychain: run `keys install-key {name}`")
    try:
        pem = Secret(base64.b64decode(out.strip(), validate=True).decode())
    except ValueError:
        raise AgentError(f"the keychain item for {name} is not one install-key wrote") from None
    code, attrs = deps.run(
        ["security", "find-generic-password", "-a", ACCOUNT, "-s", _service(name)], None, {}
    )
    m = re.search(rb'"icmt"<blob>="([A-Za-z0-9._-]+)"', attrs) if code == 0 else None
    if not m:
        raise AgentError(f"the keychain item for {name} has no client id: rerun install-key")
    return pem, m.group(1).decode()


# ── Minting ──────────────────────────────────────────────────────────────────


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def app_jwt(pem: Secret, client_id: str, deps: Deps) -> Secret:
    """A ten-minute App JWT, signed by openssl with the key on stdin and the claims on a pipe."""
    now = int(deps.now())
    head = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = {"iat": now - 60, "exp": now + 540, "iss": client_id}
    body = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing = f"{head}.{body}".encode()
    code, sig = deps.run(
        ["openssl", "dgst", "-sha256", "-sign", "/dev/stdin", "/dev/fd/3"],
        pem.reveal().encode(),
        {3: signing},
    )
    if code != 0 or not sig:
        raise AgentError(f"openssl could not sign with the key (exit {code})")
    return Secret(f"{head}.{body}.{_b64url(sig)}")


def _headers(bearer: Secret) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {bearer.reveal()}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def installation_id(app: Secret, owner: str, repo: str | None, deps: Deps) -> int:
    # A known repo's answer is final: never a wider installation for a repo it does not cover.
    paths = (
        [f"/repos/{owner}/{repo}/installation"]
        if repo
        else [f"/users/{owner}/installation", f"/orgs/{owner}/installation"]
    )
    for path in paths:
        a = deps.send("GET", API + path, _headers(app), None)
        if a.status == 200:
            try:
                return int(json.loads(a.body)["id"])
            except (ValueError, KeyError, TypeError):
                raise AgentError("GitHub's installation answer had no id") from None
        if a.status not in (404,):
            raise AgentError(f"GitHub answered {a.status or a.error} looking up {owner}")
    where = f"{owner}/{repo}" if repo else owner
    raise AgentError(f"the App is not installed on {where}: ask the owner to add it")


def mint(name: str, owner: str, repo: str | None, deps: Deps) -> Secret:
    pem, client_id = load_key(name, deps)
    app = app_jwt(pem, client_id, deps)
    iid = installation_id(app, owner, repo, deps)
    body = json.dumps({"repositories": [repo]} if repo else {}).encode()
    a = deps.send("POST", f"{API}/app/installations/{iid}/access_tokens", _headers(app), body)
    if a.status != 201:
        raise AgentError(f"GitHub answered {a.status or a.error} minting a token for {owner}")
    try:
        return Secret(str(json.loads(a.body)["token"]))
    except (ValueError, KeyError, TypeError):
        raise AgentError("GitHub's token answer had no token") from None


def revoke(token: Secret, deps: Deps) -> bool:
    return deps.send("DELETE", f"{API}/installation/token", _headers(token), None).status == 204


# ── Which owner ──────────────────────────────────────────────────────────────

_URL = re.compile(r"^(?:https://|git@|ssh://git@)github\.com[:/]([^/\s]+)(?:/([^/\s?#]+))?")
_API_PATH = re.compile(r"^/?(?:repos|orgs|users)/([^/\s?]+)(?:/([^/\s?]+))?")


def _split(pair: str, *, extra: bool = False) -> tuple[str, str | None] | None:
    """OWNER/REPO (or github.com/OWNER/REPO) as (owner, repo); with extra, later segments
    (an LFS path's `/info/lfs`) are allowed and dropped."""
    parts = pair.strip("/").split("/")
    if parts[:1] == ["github.com"]:
        parts = parts[1:]
    if len(parts) < 2 or (len(parts) > 2 and not extra):
        return None
    owner, repo = parts[0], parts[1].removesuffix(".git")
    if OWNER.match(owner) and REPO.match(repo):
        return owner, repo
    return None


def target(
    args: Sequence[str], environ: Mapping[str, str], origin: str | None
) -> tuple[str, str | None]:
    """The owner (and repo, if known) a gh call acts on."""
    args = list(args)
    for i, a in enumerate(args):
        given = None
        if a in ("-R", "--repo"):
            given = args[i + 1] if i + 1 < len(args) else ""
        elif a.startswith("--repo="):
            given = a.split("=", 1)[1]
        elif a.startswith("-R") and len(a) > 2:
            given = a[2:]
        if given is not None:
            if found := _split(given):
                return found
            raise UsageError("-R must name OWNER/REPO")
    if environ.get("GH_REPO") and (found := _split(environ["GH_REPO"])):
        return found
    api = len(args) >= 1 and args[0] == "api"
    if args[:1] in (["repo"], ["release"]) and len(args) > 2:
        positional = [a for a in args[2:] if not a.startswith("-")]
        if positional and (found := _split(positional[0])):
            return found
    for a in args[1:] if api else args:
        if m := _URL.match(a):
            return m.group(1), (m.group(2) or "").removesuffix(".git") or None
        if api and (m := _API_PATH.match(a)) and OWNER.match(m.group(1)):
            if a.lstrip("/").startswith("repos/") and m.group(2) and REPO.match(m.group(2)):
                return m.group(1), m.group(2)
            if not a.lstrip("/").startswith("repos/"):
                return m.group(1), None
    # `gh project --owner X` names an account, not a repo, so its token is the whole
    # installation's; a call naming nothing (`gh project item-edit`) takes $KEYS_GH_OWNER,
    # which a caller sets once, ahead of the repo it happens to run in.
    for i, a in enumerate(args):
        given = None
        if a == "--owner":
            given = args[i + 1] if i + 1 < len(args) else ""
        elif a.startswith("--owner="):
            given = a.split("=", 1)[1]
        if given == "@me":
            break  # gh's signed-in user: an App has none, so the next source decides
        if given is not None:
            if OWNER.fullmatch(given):
                return given, None
            raise UsageError("--owner must name a GitHub account")
    if named := environ.get("KEYS_GH_OWNER"):
        if OWNER.fullmatch(named):
            return named, None
        raise UsageError("$KEYS_GH_OWNER must name a GitHub account")
    if origin and (m := _URL.match(origin.strip())):
        return m.group(1), (m.group(2) or "").removesuffix(".git") or None
    if default := environ.get("KEYS_GH_DEFAULT_OWNER"):
        return default, None
    raise UsageError("cannot tell which owner this gh call is for: pass -R OWNER/REPO")


def origin_url(cwd: Path, deps: Deps) -> str | None:
    code, out = deps.run(["git", "-C", str(cwd), "remote", "get-url", "origin"], None, {})
    return out.decode(errors="replace").strip() if code == 0 else None


def real_gh(environ: Mapping[str, str]) -> str:
    """The real gh: $KEYS_REAL_GH, else the first gh on PATH that is not the keys shim."""
    if explicit := environ.get("KEYS_REAL_GH"):
        return explicit
    for d in environ.get("PATH", "").split(os.pathsep):
        p = Path(d) / "gh"
        if not (p.is_file() and os.access(p, os.X_OK)):
            continue
        try:
            head = p.read_bytes()[:4096]
        except OSError:
            continue
        if b"keys gh" not in head:
            return str(p)
    raise AgentError("no real gh found on PATH")


def _exec_gh(argv: Sequence[str], env: Mapping[str, str]) -> int:
    try:
        return subprocess.run(list(argv), env=dict(env), check=False).returncode
    except OSError as e:
        raise AgentError(f"gh could not start ({type(e).__name__})") from None


# ── Commands ─────────────────────────────────────────────────────────────────


def configure_install(p: argparse.ArgumentParser) -> None:
    p.add_argument("name", help="the credential's name in the mapping file")
    p.add_argument("--mapping", help="the mapping file (default: $KEYS_MAPPING, else ./keys.toml)")


def configure_has_key(p: argparse.ArgumentParser) -> None:
    p.add_argument("name", help="the App credential's name, as install-key took it")


def configure_gh(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--app",
        help="the App credential's name (default: the owner's in $KEYS_GH_APPS)",
    )
    p.add_argument("gh_args", nargs=argparse.REMAINDER, help="-- then gh's own arguments")


def configure_git(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--app",
        help="the App credential's name (default: the owner's in $KEYS_GH_APPS)",
    )
    p.add_argument("operation", choices=["get", "store", "erase"])


def _fold(owner: str) -> str:
    # ASCII-only: str.lower() folds some non-ASCII letters (U+212A KELVIN SIGN) to ASCII ones.
    return owner.translate(_UPPER)


_UPPER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _apps(environ: Mapping[str, str]) -> dict[str, str]:
    """$KEYS_GH_APPS, `owner=app` pairs split by commas or spaces: each owner's own App."""
    apps: dict[str, str] = {}
    for pair in re.split(r"[\s,]+", environ.get("KEYS_GH_APPS", "").strip()):
        if not pair:
            continue
        owner, _, name = pair.partition("=")
        if not (OWNER.fullmatch(owner) and NAME.match(name)):
            raise UsageError("$KEYS_GH_APPS wants owner=app pairs, split by commas or spaces")
        if apps.get(_fold(owner), name) != name:
            raise UsageError(f"$KEYS_GH_APPS names two Apps for {owner}")
        apps[_fold(owner)] = name
    return apps


def _app(args: argparse.Namespace, ctx: Context, owner: str) -> str:
    """--app (the owner's own override), else the owner's App in $KEYS_GH_APPS. An owner the
    map doesn't name has no App, so fail closed, never guess."""
    if not OWNER.fullmatch(owner):
        raise UsageError("the owner is not a GitHub account name")
    if args.app:
        name = args.app
    else:
        name = _apps(ctx.environ).get(_fold(owner), "")
        if not name:
            raise UsageError(f"no App for {owner}: add {owner}=<app> to $KEYS_GH_APPS")
    if not NAME.match(name):
        raise UsageError("name the App with --app NAME or $KEYS_GH_APPS")
    return name


def _read_app_key(args: argparse.Namespace, ctx: Context) -> tuple[Secret, str]:
    """The App's private key and client id, read in memory from the 1Password item the mapping
    names."""
    from keys.mapping import load
    from keys.op import Op

    if not NAME.fullmatch(args.name):
        raise UsageError("a credential name is lower-case letters, digits and dashes")
    path = Path(args.mapping or ctx.environ.get("KEYS_MAPPING") or "keys.toml")
    entry = next((c for c in load(path).credentials if c.name == args.name), None)
    if entry is None or entry.kind != "github-app-key":
        raise UsageError(f"the mapping file has no github-app-key named {args.name}")
    op = Op(ctx.environ)
    pem = op.read(entry.value_ref)
    client_id = op.read(f"{entry.item}/client_id").reveal().strip()
    if "PRIVATE KEY" not in pem.reveal():
        raise UsageError(f"{args.name}'s credential field holds no private key")
    if not CLIENT_ID.fullmatch(client_id):
        raise UsageError("the item's client_id field does not look like a GitHub App client id")
    return pem, client_id


def install(args: argparse.Namespace, ctx: Context, deps: Deps | None = None) -> int:
    deps = deps or Deps()
    pem, client_id = _read_app_key(args, ctx)
    store_key(args.name, pem, client_id, deps)
    stored, stored_id = load_key(args.name, deps)
    if stored != pem or stored_id != client_id:
        raise AgentError(
            f"{_store_name(deps)} did not keep {args.name}'s key: nothing usable was stored"
        )
    a = deps.send("GET", f"{API}/app", _headers(app_jwt(stored, stored_id, deps)), None)
    if a.status != 200:
        ctx.warn(f"keys: stored, but GitHub answered {a.status or a.error} signing in as the App")
        return EXIT_FAIL
    ctx.say(f"stored {args.name} in {_store_name(deps)}; it signs in as its App")
    return EXIT_OK


# A host as ssh takes it: a name, an ssh_config alias or user@host. Never a leading dash (an
# ssh option) and nothing a shell would read.
HOST = re.compile(r"^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9][A-Za-z0-9._-]*$")


def remote_script(name: str, size: int) -> str:
    """Write stdin to the host's key file the way _store_file does: folder 0700, file 0600, made
    under a temporary name and renamed into place. A relative XDG_CONFIG_HOME is ignored there too.
    The rename happens only when all `size` bytes arrived, so a dropped connection leaves the old
    key in place; any failure removes the temporary file. Runs in sh, bash or zsh."""
    if not NAME.fullmatch(name):
        raise UsageError("a credential name is lower-case letters, digits and dashes")
    return (
        'case "${XDG_CONFIG_HOME:-}" in /*) c=$XDG_CONFIG_HOME ;; *) c=$HOME/.config ;; esac; '
        'd="$c/keys/app-keys"; umask 077; mkdir -p "$d" && chmod 700 "$d" || exit 1; '
        f't="$d/.{name}.json.$$"; '
        f'if cat >"$t" && [ "$(wc -c <"$t" | tr -d " ")" = {size} ] && chmod 600 "$t" '
        f'&& mv -f "$t" "$d/{name}.json"; then exit 0; fi; rm -f "$t"; exit 1'
    )


def send_key_to(name: str, pem: Secret, client_id: str, host: str, deps: Deps) -> None:
    """Send the key to one host over ssh, on stdin: never argv, never a local file."""
    if not HOST.fullmatch(host):
        raise UsageError(f"{host!r} is not a host ssh can take here")
    blob = json.dumps({"client_id": client_id, "pem": pem.reveal()}).encode()
    argv = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=15",
        # No terminal (it would echo stdin back) and no RemoteCommand from ssh_config; and only
        # a host whose key ssh already knows gets the App key.
        "-T",
        "-o",
        "RemoteCommand=none",
        "-o",
        "StrictHostKeyChecking=yes",
        "--",
        host,
        remote_script(name, len(blob)),
    ]
    code, _ = deps.run(argv, blob, {})
    if code != 0:
        raise AgentError(f"could not write {name}'s key on {host} (ssh exited {code})")


def configure_send(p: argparse.ArgumentParser) -> None:
    p.add_argument("name", help="the credential's name in the mapping file")
    p.add_argument("hosts", nargs="+", metavar="host", help="hosts ssh can reach (Linux)")
    p.add_argument("--mapping", help="the mapping file (default: $KEYS_MAPPING, else ./keys.toml)")


def send_key(args: argparse.Namespace, ctx: Context, deps: Deps | None = None) -> int:
    """Read the key from 1Password here, prove it signs in, and write it into each host's key file
    over ssh, for machines with no 1Password of their own."""
    deps = deps or Deps()
    bad = [h for h in args.hosts if not HOST.fullmatch(h)]
    if bad:
        raise UsageError(f"not a host ssh can take here: {', '.join(map(repr, bad))}")
    pem, client_id = _read_app_key(args, ctx)
    a = deps.send("GET", f"{API}/app", _headers(app_jwt(pem, client_id, deps)), None)
    if a.status != 200:
        ctx.warn(f"keys: GitHub answered {a.status or a.error} signing in as the App; nothing sent")
        return EXIT_FAIL
    failed = 0
    for host in args.hosts:
        try:
            send_key_to(args.name, pem, client_id, host, deps)
            ctx.say(f"{host}: {args.name}'s key is in its key file")
        except AgentError as e:
            failed += 1
            ctx.warn(f"keys: {e}")
    return EXIT_FAIL if failed else EXIT_OK


def has_key(args: argparse.Namespace, ctx: Context, deps: Deps | None = None) -> int:
    """Whether install-key's key is here and readable, so a setup script needn't know where."""
    deps = deps or Deps()
    if not NAME.fullmatch(args.name):
        raise UsageError("a credential name is lower-case letters, digits and dashes")
    try:
        load_key(args.name, deps)
    except AgentError:
        return EXIT_FAIL
    return EXIT_OK


def gh(args: argparse.Namespace, ctx: Context, deps: Deps | None = None) -> int:
    deps = deps or Deps()
    rest = list(args.gh_args)
    if rest[:1] == ["--"]:
        rest = rest[1:]
    if rest[:1] == ["auth"] and (
        rest[1:2] != ["status"] or any(a in ("-t", "--show-token") for a in rest[2:])
    ):
        raise UsageError(
            "only `gh auth status` is an agent's; the rest of `gh auth` is the owner's"
        )
    if ctx.environ.get("KEYS_GH_ACTIVE"):
        raise AgentError("keys gh reached itself: $KEYS_REAL_GH or PATH names the shim")
    if not (args.app or ctx.environ.get("KEYS_GH_APPS")):
        raise UsageError("name the App with --app NAME or $KEYS_GH_APPS")
    owner, repo = target(rest, ctx.environ, origin_url(ctx.cwd(), deps))
    if repo is not None and not REPO.fullmatch(repo):
        raise UsageError("the repo is not a GitHub repository name")
    token = mint(_app(args, ctx, owner), owner, repo, deps)
    env = {k: v for k, v in ctx.environ.items() if k not in DROP}
    env["GH_TOKEN"] = token.reveal()
    env["KEYS_GH_ACTIVE"] = "1"
    try:
        code = (deps.exec_gh or _exec_gh)([real_gh(ctx.environ), *rest], env)
    finally:
        if not revoke(token, deps):
            ctx.warn("keys: the token could not be revoked; it expires within the hour")
    return code


def git_credential(args: argparse.Namespace, ctx: Context, deps: Deps | None = None) -> int:
    deps = deps or Deps()
    if args.operation != "get":
        return EXIT_OK
    if ctx.stdout.isatty():
        raise UsageError("keys git-credential answers git on a pipe, never a terminal")
    fields: dict[str, str] = {}
    for line in ctx.stdin.read().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            fields[k] = v
    host = fields.get("host", "").lower().removesuffix(":443")
    if fields.get("protocol", "").lower() != "https" or host != "github.com":
        return EXIT_OK  # not ours: git asks the next helper
    # From here the request is github.com's: on any failure tell git to stop (quit=1), so it
    # never asks a later helper holding the owner's own login.
    try:
        found = _split(fields.get("path", ""), extra=True)
        if not found:
            raise UsageError(
                "git sent no repo path: set credential.useHttpPath true for github.com"
            )
        owner, repo = found
        token = mint(_app(args, ctx, owner), owner, repo, deps)
    except BaseException:
        # Any failure, not only ours: an unexpected one must stop git too.
        ctx.stdout.write("quit=1\n")
        ctx.stdout.flush()
        raise
    ctx.stdout.write(f"username=x-access-token\npassword={token.reveal()}\n")
    ctx.stdout.flush()
    return EXIT_OK


def handle(e: AgentError, ctx: Context) -> int:
    ctx.warn(f"keys: {e}")
    return EXIT_FAIL


if __name__ == "__main__":  # pragma: no cover
    sys.exit("run as `keys`")
