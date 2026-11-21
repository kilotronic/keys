"""What each kind needs from its provider to rotate: mint, revoke, probe and its pages.

A rung-3 kind mints the new key by API with another credential's key (`minted_by`) and revokes
the old one the same way. A paste kind (rung 4) has no create API: keys opens the provider's
pre-filled page, and the owner pastes the new value into the 1Password item.

Every request goes through keys's own HTTPS client with the key in a header it builds. An error
names the host, a fixed path (never an id taken from the item), the HTTP status and the
provider's error code, and only when that code holds no piece of a key.
"""

from __future__ import annotations

import datetime
import json
import re
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, cast

from keys import forms, looks, mapping, probes
from keys.secret import Secret

MAX_DAYS = 180
IDENT = re.compile(r"[A-Za-z0-9_-]{1,64}")
OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}")

Send = Callable[[str, str, dict[str, str], bytes | None], probes.Answer]


class RotateError(Exception):
    """A provider call failed. The message names host, path, status and code only."""


@dataclass(frozen=True)
class Minted:
    value: Secret
    ident: str
    expires: datetime.date | None = None


class Api:
    """JSON over HTTPS with a key, for mint and revoke."""

    def __init__(self, send: Send, secrets: list[Secret]) -> None:
        self.send = send
        self.secrets = secrets  # every key in play: an error code holding a piece is dropped

    def call(
        self,
        method: str,
        url: str,
        shown: str,
        token: Secret,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https":
            raise RotateError("keys sends a key only over https")
        headers = {"Authorization": f"Bearer {token.reveal()}", "Accept": "application/json"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        answer = self.send(method, url, headers, data)
        where = f"{parts.hostname}{shown}"
        if answer.status == 0:
            kind = answer.error if re.fullmatch(r"[A-Za-z]{1,40}", answer.error) else "error"
            raise RotateError(f"no answer from {where} ({kind})")
        if not 200 <= answer.status < 300:
            code = probes.error_code(answer.body)
            plain = looks.plain_code(code) and not any(
                forms.holds_piece(code, s) for s in self.secrets
            )
            raise RotateError(
                f"HTTP {answer.status} from {where}" + (f" ({code})" if plain else "")
            )
        try:
            doc: object = json.loads(answer.body or "{}")
        except ValueError:
            raise RotateError(f"{where} answered with something keys cannot read") from None
        return cast(dict[str, Any], doc) if isinstance(doc, dict) else {}


def ident(fields: dict[str, str], name: str, values: list[Secret]) -> str:
    """An id from the item, checked: a plain id, and not a key pasted into the wrong field."""
    value = fields.get(name, "").strip()
    if not value:
        raise RotateError(f"the item's {name} field is empty: fill it with the key's id")
    if not IDENT.fullmatch(value) or any(forms.holds_piece(value, s) for s in values):
        raise RotateError(f"the item's {name} field is not a plain id")
    return value


@dataclass
class Rotator:
    kind: str
    probe: str  # the keys check service that probes it
    id_field: str = ""  # the item field holding the current key's provider id
    mints: bool = False  # rung 3: made by API with the minted_by credential's key
    revoke_page: str = ""  # where the owner revokes it when there is no API
    fields: dict[str, str] = field(default_factory=lambda: dict[str, str]())

    def mint(
        self, api: Api, minter: Secret, fields: dict[str, str], name: str, today: datetime.date
    ) -> Minted:
        raise NotImplementedError

    def revoke(self, api: Api, minter: Secret, key_id: str) -> None:
        raise NotImplementedError

    @property
    def revokes_by_api(self) -> bool:
        return self.mints

    def create_page(self, c: mapping.Credential, fields: dict[str, str], name: str) -> str:
        raise NotImplementedError

    def expiry(self, answer: probes.Answer) -> datetime.date | None:
        """The expiry the provider reports for a key, from its probe's answer."""
        return None


# ---------------------------------------------------------------------------- Cloudflare

CF = "https://api.cloudflare.com/client/v4/user/tokens"


class Cloudflare(Rotator):
    """A user API token. The new one copies the old one's policies and IP condition, and
    expires 180 days from today. Account-owned tokens are not handled yet."""

    def mint(
        self, api: Api, minter: Secret, fields: dict[str, str], name: str, today: datetime.date
    ) -> Minted:
        old_id = ident(fields, "token_id", api.secrets)
        got = api.call("GET", f"{CF}/{old_id}", "/client/v4/user/tokens/<id>", minter)
        old = cast(dict[str, Any], got.get("result") or {})
        policies: list[dict[str, Any]] = []
        for raw in cast(list[Any], old.get("policies") or []):
            if not isinstance(raw, dict):
                continue
            p = cast(dict[str, Any], raw)
            groups = cast(list[Any], p.get("permission_groups") or [])
            policies.append(
                {
                    "effect": p.get("effect"),
                    "resources": p.get("resources"),
                    "permission_groups": [
                        {"id": cast(dict[str, Any], g).get("id")}
                        for g in groups
                        if isinstance(g, dict)
                    ],
                }
            )
        if not policies:
            raise RotateError("the old token has no policies keys can copy")
        expires = today + datetime.timedelta(days=MAX_DAYS)
        body: dict[str, Any] = {
            "name": name,
            "policies": policies,
            "expires_on": f"{expires.isoformat()}T00:00:00Z",
        }
        if old.get("condition"):
            body["condition"] = old["condition"]
        made = api.call("POST", CF, "/client/v4/user/tokens", minter, body)
        result = cast(dict[str, Any], made.get("result") or {})
        value, new_id = result.get("value"), result.get("id")
        if not isinstance(value, str) or not value or not isinstance(new_id, str):
            raise RotateError("Cloudflare's answer had no new token in it")
        return Minted(Secret(value), new_id, expires)

    def revoke(self, api: Api, minter: Secret, key_id: str) -> None:
        api.call("DELETE", f"{CF}/{key_id}", "/client/v4/user/tokens/<id>", minter)


# ---------------------------------------------------------------------------- Resend

RESEND = "https://api.resend.com/api-keys"


def resend_mint_body(name: str, fields: dict[str, str]) -> dict[str, Any]:
    """The new key keeps the item's permission (sending only, unless it says full_access) and
    its one domain."""
    permission = "full_access" if fields.get("permission") == "full_access" else "sending_access"
    body: dict[str, Any] = {"name": name, "permission": permission}
    if fields.get("domain_id"):
        body["domain_id"] = fields["domain_id"]
    return body


class Resend(Rotator):
    def mint(
        self, api: Api, minter: Secret, fields: dict[str, str], name: str, today: datetime.date
    ) -> Minted:
        if fields.get("domain_id"):
            ident(fields, "domain_id", api.secrets)
        made = api.call("POST", RESEND, "/api-keys", minter, resend_mint_body(name, fields))
        value, new_id = made.get("token"), made.get("id")
        if not isinstance(value, str) or not value or not isinstance(new_id, str):
            raise RotateError("Resend's answer had no new key in it")
        return Minted(Secret(value), new_id)

    def revoke(self, api: Api, minter: Secret, key_id: str) -> None:
        api.call("DELETE", f"{RESEND}/{key_id}", "/api-keys/<id>", minter)


# ---------------------------------------------------------------------------- GitHub tokens

PAT_NEW = "https://github.com/settings/personal-access-tokens/new"
PAT_LIST = "https://github.com/settings/personal-access-tokens"


class GitHubPat(Rotator):
    """A fine-grained token: no API makes one, so keys opens GitHub's pre-filled page."""

    def create_page(self, c: mapping.Credential, fields: dict[str, str], name: str) -> str:
        owner = c.owner or fields.get("owner", "")
        if not OWNER.fullmatch(owner) or looks.looks_like_value(owner):
            raise RotateError("github-pat needs owner: the user or org the token is for")
        query = {
            "name": name,
            "description": "Managed by keys",
            "target_name": owner,
            "expires_in": str(MAX_DAYS),
            **c.permissions,
        }
        return f"{PAT_NEW}?{urllib.parse.urlencode(query)}"

    def expiry(self, answer: probes.Answer) -> datetime.date | None:
        text = answer.headers.get("github-authentication-token-expiration", "")
        try:
            return datetime.date.fromisoformat(text[:10])
        except ValueError:
            return None


ROTATORS: dict[str, Rotator] = {
    r.kind: r
    for r in [
        Cloudflare("cloudflare-token", "cloudflare", id_field="token_id", mints=True),
        Resend("resend-key", "resend", id_field="key_id", mints=True),
        GitHubPat("github-pat", "github", revoke_page=PAT_LIST),
    ]
}
