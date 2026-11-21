"""Starting a child: argv with no value in it, the value only on stdin, and only the exit code
and stdout coming back. A child's stderr is never kept, since it can repeat what it was given.
"""

from __future__ import annotations

import subprocess
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass

from keys.secret import Secret

TIMEOUT_S = 120


# A child gets only these from keys's environment, so a value keys was handed in a variable
# (env:NAME) never reaches it.
KEEP = {
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "TMPDIR",
    "XDG_CONFIG_HOME",
    "SSH_AUTH_SOCK",
}


def child_env(
    environ: Mapping[str, str], prefixes: Sequence[str] = (), names: Collection[str] = ()
) -> dict[str, str]:
    """The part of environ a child may see: the basics, names with the given prefixes (OP_ for
    op's own settings), and the given names."""
    return {
        k: v
        for k, v in environ.items()
        if k in KEEP or k in names or any(k.startswith(p) for p in prefixes)
    }


class ChildError(Exception):
    """A child that could not start, timed out or failed. Names the program and exit code only."""


@dataclass(frozen=True)
class Done:
    code: int
    stdout: str


def run(
    argv: Sequence[str],
    environ: Mapping[str, str],
    *,
    stdin: Secret | str | None = None,
    timeout: int = TIMEOUT_S,
) -> Done:
    text = stdin.reveal() if isinstance(stdin, Secret) else stdin
    # Bytes, not text: no newline translation, and UTF-8 whatever the locale says.
    data = text.encode() if text is not None else None
    try:
        r = subprocess.run(
            list(argv),
            input=data,
            stdin=None if data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=dict(environ),
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        raise ChildError(f"{argv[0]} is not installed") from None
    except subprocess.TimeoutExpired:
        raise ChildError(f"{argv[0]} took longer than {timeout}s") from None
    except OSError as e:
        raise ChildError(f"{argv[0]} could not start ({type(e).__name__})") from None
    return Done(r.returncode, r.stdout.decode(errors="replace"))
