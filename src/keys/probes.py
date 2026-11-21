"""Does this key still work? One free, read-only call to the service that issued it.

Ported from the key checker this tool took over. Each provider builds one request (listing
models, reading the account, asking for a token) and reads the verdict from the status and the
error code in the answer:

    WORKS   the service accepted it
    DEAD    the service refused it as unknown, revoked or wrong
    UNKNOWN anything else: no answer, a 5xx, an answer this does not recognise

The reason printed names the host, path, status and the service's machine-readable error code.
Never the service's message (some repeat the key), never a network error's text (only its type),
and an error code holding any piece of the key is dropped.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from email.utils import formatdate
from typing import Any, cast

from keys import forms
from keys.context import UsageError
from keys.secret import Secret

WORKS, DEAD, UNKNOWN = "WORKS", "DEAD", "UNKNOWN"
CODE = re.compile(r"^[A-Za-z0-9_.:-]{1,60}$")


@dataclasses.dataclass
class Answer:
    status: int  # 0 when no answer came back
    body: str
    error: str = ""  # the network error's type, when status is 0


Request = tuple[str, str, dict[str, str], bytes | None]
Sender = Callable[[str, str, dict[str, str], bytes | None], Answer]


@dataclasses.dataclass
class Options:
    """The extra flags some providers need. None of them is secret."""

    client_id: str | None = None
    account: str | None = None
    scm_host: str | None = None
    user: str | None = None
    url: str | None = None
    header: list[str] | None = None
    bearer: bool = False
    query: str | None = None
    method: str = "GET"
    works_status: str | None = None
    dead_status: str | None = None


def send(method: str, url: str, headers: dict[str, str], data: bytes | None = None) -> Answer:
    req = urllib.request.Request(  # noqa: S310 - https, or http to this machine only
        url, data=data, method=method, headers={"User-Agent": "keys-check", **headers}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            return Answer(resp.status, resp.read(4096).decode(errors="replace"))
    except urllib.error.HTTPError as e:
        return Answer(e.code, e.read(4096).decode(errors="replace"))
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return Answer(0, "", type(e).__name__)


def error_code(body: str) -> str:
    """The machine-readable error code in a service's answer, if any. Never the message."""
    try:
        doc: object = json.loads(body)
    except ValueError:
        start = body.find("<Code>")
        return body[start + 6 : body.find("</Code>")] if start >= 0 else ""
    if not isinstance(doc, dict):
        return ""
    d = cast(dict[str, Any], doc)
    err = d.get("error")
    if isinstance(err, dict):
        e = cast(dict[str, Any], err)
        return str(e.get("type") or e.get("code") or "")
    if isinstance(err, str) and len(err) < 40 and " " not in err:
        return err
    errors = d.get("errors")
    if isinstance(errors, list) and errors and isinstance(errors[0], dict):
        first = cast(dict[str, Any], errors[0])
        return str(first.get("code") or "")
    return ""


@dataclasses.dataclass
class Provider:
    name: str
    about: str
    build: Callable[[Secret, Options], Request]
    works: set[int]
    dead: set[int]
    # Error codes that settle the verdict whatever the status (Google answers a good client
    # with an error).
    works_codes: frozenset[str] = frozenset()
    dead_codes: frozenset[str] = frozenset()
    needs: tuple[str, ...] = ()
    shown_url: str = ""  # what the result names; the real URL can hold the key (SerpApi)


def _form(fields: dict[str, str]) -> bytes:
    return urllib.parse.urlencode(fields).encode()


FORM = {"Content-Type": "application/x-www-form-urlencoded"}


def azure_storage_request(key: Secret, opts: Options) -> Request:
    """List containers, signed with the account key (Shared Key). A connection string works too."""
    account = opts.account or ""
    raw = key.reveal()
    if raw.startswith("DefaultEndpointsProtocol=") or "AccountKey=" in raw:
        parts = dict(p.split("=", 1) for p in raw.strip(";").split(";") if "=" in p)
        account = account or parts.get("AccountName", "")
        raw = parts.get("AccountKey", "")
    if not account:
        raise UsageError(
            "azure-storage needs --account <storage account> (or a connection string as the key)"
        )
    date = formatdate(usegmt=True)
    version = "2021-08-06"
    to_sign = azure_string_to_sign(account, date, version)
    try:
        secret = base64.b64decode(raw, validate=True)
    except ValueError:
        raise UsageError("an Azure Storage account key is base64; this key is not") from None
    signature = base64.b64encode(hmac.new(secret, to_sign.encode(), hashlib.sha256).digest())
    headers = {
        "x-ms-date": date,
        "x-ms-version": version,
        "Authorization": f"SharedKey {account}:{signature.decode()}",
    }
    return "GET", f"https://{account}.blob.core.windows.net/?comp=list&maxresults=1", headers, None


def azure_string_to_sign(account: str, date: str, version: str) -> str:
    # VERB, then eleven standard headers (all empty for this GET), then x-ms-* headers, then
    # the resource.
    return (
        "GET\n"
        + "\n" * 11
        + f"x-ms-date:{date}\nx-ms-version:{version}\n"
        + f"/{account}/\ncomp:list\nmaxresults:1"
    )


def _local(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def http_request(key: Secret, opts: Options) -> Request:
    if not opts.url:
        raise UsageError("http needs --url, and --header 'Name: {key}', --bearer or --query <name>")
    parts = urllib.parse.urlsplit(opts.url)
    if parts.scheme != "https" and not (parts.scheme == "http" and _local(parts.hostname or "")):
        raise UsageError("http sends the key only over https (plain http only to this machine)")
    url = opts.url
    headers: dict[str, str] = {}
    if opts.bearer:
        headers["Authorization"] = f"Bearer {key.reveal()}"
    for h in opts.header or []:
        name, _, value = h.partition(":")
        if "{key}" not in value:
            raise UsageError("--header must hold {key} where the key goes, e.g. 'X-API-Key: {key}'")
        headers[name.strip()] = value.strip().replace("{key}", key.reveal())
    if opts.query:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode({opts.query: key.reveal()})
    if not (opts.bearer or opts.header or opts.query):
        raise UsageError("http needs --header 'Name: {key}', --bearer or --query <name>")
    return opts.method, url, headers, None


def _statuses(text: str | None, default: set[int]) -> set[int]:
    if not text:
        return default
    try:
        return {int(s) for s in text.split(",")}
    except ValueError:
        raise UsageError("--works-status and --dead-status take numbers, like 401,403") from None


def _bearer(url: str, extra: dict[str, str] | None = None) -> Callable[[Secret, Options], Request]:
    def build(k: Secret, o: Options) -> Request:
        return "GET", url, {"Authorization": f"Bearer {k.reveal()}", **(extra or {})}, None

    return build


def _api_key(url: str, header: str, extra: dict[str, str]) -> Callable[[Secret, Options], Request]:
    def build(k: Secret, o: Options) -> Request:
        return "GET", url, {header: k.reveal(), **extra}, None

    return build


ANTHROPIC = {"anthropic-version": "2023-06-01"}

PROVIDERS: dict[str, Provider] = {
    p.name: p
    for p in [
        Provider(
            "anthropic",
            "Anthropic API key: lists models",
            _api_key("https://api.anthropic.com/v1/models?limit=1", "x-api-key", ANTHROPIC),
            {200},
            {401},
        ),
        Provider(
            "anthropic-admin",
            "Anthropic Admin API key: lists one organization member",
            _api_key(
                "https://api.anthropic.com/v1/organizations/users?limit=1", "x-api-key", ANTHROPIC
            ),
            {200},
            {401},
        ),
        Provider(
            "openai",
            "OpenAI API key: lists models",
            _bearer("https://api.openai.com/v1/models"),
            {200},
            {401},
        ),
        Provider(
            "openai-admin",
            "OpenAI Admin key: lists one organization member",
            _bearer("https://api.openai.com/v1/organization/users?limit=1"),
            {200},
            {401},
        ),
        Provider(
            "github",
            "GitHub token: reads its rate limit",
            _bearer("https://api.github.com/rate_limit", {"Accept": "application/vnd.github+json"}),
            {200},
            {401},
        ),
        Provider(
            "cloudflare",
            "Cloudflare API token: verifies itself",
            _bearer("https://api.cloudflare.com/client/v4/user/tokens/verify"),
            {200},
            {401},
        ),
        Provider(
            "serpapi",
            "SerpApi key: reads the account (no search is spent)",
            lambda k, o: (
                "GET",
                "https://serpapi.com/account.json?"
                + urllib.parse.urlencode({"api_key": k.reveal()}),
                {},
                None,
            ),
            {200},
            {401},
            shown_url="https://serpapi.com/account.json",
        ),
        Provider(
            "adobe",
            "Adobe PDF Services client secret: asks for an access token; needs --client-id",
            lambda k, o: (
                "POST",
                "https://pdf-services.adobe.io/token",
                FORM,
                _form({"client_id": o.client_id or "", "client_secret": k.reveal()}),
            ),
            {200},
            {400, 401},
            dead_codes=frozenset({"invalid_client"}),
            needs=("client_id",),
        ),
        Provider(
            "google-oauth-client",
            "Google OAuth client secret: tries a made-up refresh token, which a real client is "
            "told is invalid_grant and a revoked one invalid_client; needs --client-id",
            lambda k, o: (
                "POST",
                "https://oauth2.googleapis.com/token",
                FORM,
                _form(
                    {
                        "grant_type": "refresh_token",
                        "refresh_token": "keys-check-not-a-token",
                        "client_id": o.client_id or "",
                        "client_secret": k.reveal(),
                    }
                ),
            ),
            set(),
            {401},
            works_codes=frozenset({"invalid_grant"}),
            dead_codes=frozenset({"invalid_client", "unauthorized_client"}),
            needs=("client_id",),
        ),
        Provider(
            "azure-storage",
            "Azure Storage account key or connection string: lists one container; needs "
            "--account unless the key is a connection string",
            azure_storage_request,
            {200},
            {403},
            dead_codes=frozenset({"AuthenticationFailed", "KeyBasedAuthenticationNotPermitted"}),
        ),
        Provider(
            "azure-publish",
            "Azure App Service publishing password: lists deployments; needs --scm-host, --user",
            lambda k, o: (
                "GET",
                f"https://{o.scm_host}/api/deployments",
                {
                    "Authorization": "Basic "
                    + base64.b64encode(f"{o.user}:{k.reveal()}".encode()).decode()
                },
                None,
            ),
            {200},
            {401, 403},
            needs=("scm_host", "user"),
        ),
        Provider(
            "argilla",
            "Argilla API key: reads its own user; needs --url (the Argilla server)",
            lambda k, o: (
                "GET",
                (o.url or "").rstrip("/") + "/api/v1/me",
                {"X-Argilla-Api-Key": k.reveal()},
                None,
            ),
            {200},
            {401},
            needs=("url",),
        ),
        Provider(
            "unstructured",
            "Unstructured API key: lists jobs",
            _api_key(
                "https://platform.unstructuredapp.io/api/v1/jobs/", "unstructured-api-key", {}
            ),
            {200},
            {401},
        ),
        Provider(
            "http",
            "any HTTPS API: --url, the key in --header 'Name: {key}', --bearer or --query; "
            "--works-status and --dead-status (default 200 and 401,403)",
            http_request,
            {200},
            {401, 403},
        ),
    ]
}


def _shown(text: str, key: Secret) -> str:
    """text, if it holds no form or piece of the key; otherwise nothing."""
    return "" if forms.holds_piece(text, key) else text


def check(provider: Provider, key: Secret, opts: Options, sender: Sender) -> tuple[str, str]:
    """(verdict, reason). The reason names host, path, status and error code; never the key."""
    for need in provider.needs:
        if not getattr(opts, need, None):
            raise UsageError(f"{provider.name} needs --{need.replace('_', '-')}")
    method, url, headers, data = provider.build(key, opts)
    works, dead = provider.works, provider.dead
    if provider.name == "http":
        works = _statuses(opts.works_status, works)
        dead = _statuses(opts.dead_status, dead)
    answer = sender(method, url, headers, data)
    parts = urllib.parse.urlsplit(provider.shown_url or url)
    where = _shown(f"{parts.netloc}{parts.path}", key) or parts.hostname or "the service"
    where = _shown(where, key) or "the service"
    if answer.status == 0:
        kind = answer.error.split(":", 1)[0].strip()
        kind = kind if re.match(r"^[A-Za-z]{1,40}$", kind) else "network error"
        return UNKNOWN, f"no answer from {where} ({kind})"
    raw_code = error_code(answer.body)
    code = _shown(raw_code, key) if CODE.match(raw_code) else ""
    reason = f"HTTP {answer.status} from {where}" + (f" ({code})" if code else "")
    # Adobe answers invalid_client both for a dead secret and for a client ID it doesn't
    # know; only its (fixed, key-free) message tells them apart.
    if provider.name == "adobe" and "invalid client_id" in answer.body:
        return UNKNOWN, reason + ": Adobe does not know this client ID; check --client-id"
    if raw_code in provider.works_codes:
        return WORKS, reason
    if raw_code in provider.dead_codes:
        return DEAD, reason
    if answer.status in works:
        return WORKS, reason
    if answer.status in dead:
        return DEAD, reason
    return UNKNOWN, reason
