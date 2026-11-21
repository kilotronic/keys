"""keys check <service> --key <source>: ask the service whether a key works.

The key comes from op://… (read in process through 1Password), env:NAME, or stdin; never from
the command line. One line comes back: the service, the key's keyed fingerprint, the hint its
console shows, and the verdict with the HTTP status and error code. Exit 0 for WORKS (or the
--expect verdict), 1 for DEAD (or the other one), 2 for UNKNOWN, 3 for a usage error.
"""

from __future__ import annotations

import argparse

from keys import probes
from keys.context import EXIT_FAIL, EXIT_OK, EXIT_UNKNOWN, Context, UsageError
from keys.fingerprint import fingerprint, hint
from keys.op import Op, OpError
from keys.secret import Secret

FP_KEY_MIN = 16
SOURCES = "op://<vault>/<item>/<field>, env:NAME or stdin"


def configure(p: argparse.ArgumentParser) -> None:
    p.add_argument("service", nargs="?", help="a service; --list names them")
    p.add_argument("--list", action="store_true", help="list the services and what each asks")
    p.add_argument("--key", metavar="SOURCE", help=f"where the key comes from: {SOURCES}")
    p.add_argument(
        "--fp-key",
        metavar="SOURCE",
        help="where the fingerprint secret comes from (default: $KEYS_FP_KEY), same forms",
    )
    p.add_argument("--expect", choices=["works", "dead"], help="exit 0 only for this verdict")
    for flag in ("--client-id", "--account", "--scm-host", "--user", "--url", "--query"):
        p.add_argument(flag)
    p.add_argument("--header", action="append", help="'Name: {key}' (http)")
    p.add_argument("--bearer", action="store_true", help="send the key as a bearer token (http)")
    p.add_argument("--method", default="GET")
    p.add_argument("--works-status")
    p.add_argument("--dead-status")


def read_key(source: str, ctx: Context, what: str = "key") -> Secret:
    """The value a source names. Errors never hold the source or the value."""
    if source.startswith("op://"):
        try:
            value = Op(ctx.environ).read(source)
        except OpError as e:
            raise UsageError(f"could not read the {what} from 1Password: {e}") from None
        text = value.reveal()
    elif source.startswith("env:"):
        name = source[4:]
        if not name.replace("_", "").isalnum():
            raise UsageError(f"env: takes the name of an environment variable ({what})")
        text = ctx.environ.get(name, "")
        if not text:
            # The name is not echoed: a value typed after env: by mistake would be printed.
            flag = "--key" if what == "key" else "--fp-key or $KEYS_FP_KEY"
            raise UsageError(f"the environment variable named by {flag} is not set")
    elif source == "stdin":
        text = ctx.stdin.read()
    else:
        # Not echoed: a value typed here by mistake would be printed back.
        raise UsageError(f"unknown key source for the {what}: use {SOURCES}")
    text = text.rstrip("\r\n")
    if not text:
        raise UsageError(f"the {what} is empty")
    return Secret(text)


def run(args: argparse.Namespace, ctx: Context) -> int:
    if args.list:
        for p in probes.PROVIDERS.values():
            ctx.say(f"{p.name:20} {p.about}")
        return EXIT_OK
    service: str | None = args.service
    if not service:
        raise UsageError("keys check <service> --key <source>; `keys check --list` names them")
    provider = probes.PROVIDERS.get(service)
    if provider is None:
        raise UsageError("unknown service; `keys check --list` names them")
    if not args.key:
        raise UsageError(f"--key is required: {SOURCES}")
    fp_source: str | None = args.fp_key or ctx.environ.get("KEYS_FP_KEY")
    if not fp_source:
        raise UsageError(
            "no fingerprint key: give --fp-key or set KEYS_FP_KEY to op://… or env:NAME"
        )
    if args.key == "stdin" and fp_source == "stdin":
        raise UsageError("the key and the fingerprint key cannot both come from stdin")
    fp_key = read_key(fp_source, ctx, "fingerprint key")
    if len(fp_key) < FP_KEY_MIN:
        raise UsageError(f"the fingerprint key must be at least {FP_KEY_MIN} characters")
    key = read_key(args.key, ctx)
    opts = probes.Options(
        client_id=args.client_id,
        account=args.account,
        scm_host=args.scm_host,
        user=args.user,
        url=args.url,
        header=args.header,
        bearer=args.bearer,
        query=args.query,
        method=args.method,
        works_status=args.works_status,
        dead_status=args.dead_status,
    )
    sender = ctx.send or probes.send
    verdict, reason = probes.check(provider, key, opts, sender)
    shown = hint(key) if provider.hint else ""
    ident = f"fp:{fingerprint(fp_key, key)}" + (f" {shown}" if shown else "")
    ctx.say(f"{service} key {ident}: {verdict} ({reason})")
    if verdict == probes.UNKNOWN:
        return EXIT_UNKNOWN
    if args.expect:
        return EXIT_OK if verdict.lower() == args.expect else EXIT_FAIL
    return EXIT_OK if verdict == probes.WORKS else EXIT_FAIL
