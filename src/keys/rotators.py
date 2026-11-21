"""What each kind needs from its provider to rotate: mint, revoke, probe and its pages.

A rung-3 kind mints the new key by API with another credential's key (`minted_by`) and revokes
the old one the same way. A paste kind (rungs 4 and 5) has no create API: keys opens the
provider's page, and the owner pastes the new value into the 1Password item (a GitHub App key,
which GitHub hands out only as a download, keys moves from the download into the item itself).

Every request goes through keys's own HTTPS client with the key in a header it builds. An error
names the host, a fixed path (never an id taken from the item), the HTTP status and the
provider's error code, and only when that code holds no piece of a key.
"""

from __future__ import annotations

import base64
import datetime
import json
import re
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, cast

from keys import appjwt, forms, looks, mapping, probes
from keys.secret import Secret

MAX_DAYS = 180
IDENT = re.compile(r"[A-Za-z0-9_-]{1,64}")
OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}")

Send = Callable[[str, str, dict[str, str], bytes | None], probes.Answer]


class RotateError(Exception):
    """A provider call failed. The message names host, path, status and code only."""

    def __init__(self, text: str, status: int = 0) -> None:
        super().__init__(text)
        self.status = status  # the HTTP status, when the provider answered


@dataclass(frozen=True)
class Grant:
    """A key that acts for keys (the minting key): its value and its item's other fields."""

    value: Secret
    fields: dict[str, str] = field(default_factory=lambda: dict[str, str]())


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
        *,
        basic: str = "",
        form: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """The call, signed in with token as a bearer, or with `basic` as the user name and
        token as the password (Twilio); a JSON body, or a form."""
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https":
            raise RotateError("keys sends a key only over https")
        if basic:
            pair = base64.b64encode(f"{basic}:{token.reveal()}".encode()).decode()
            auth = f"Basic {pair}"
        else:
            auth = f"Bearer {token.reveal()}"
        headers = {"Authorization": auth, "Accept": "application/json"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        elif form is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            data = urllib.parse.urlencode(form).encode()
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
                f"HTTP {answer.status} from {where}" + (f" ({code})" if plain else ""),
                answer.status,
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
        self, api: Api, minter: Grant, fields: dict[str, str], name: str, today: datetime.date
    ) -> Minted:
        raise NotImplementedError

    def revoke(self, api: Api, minter: Grant, fields: dict[str, str], key_id: str) -> None:
        raise NotImplementedError

    @property
    def revokes_by_api(self) -> bool:
        return self.mints

    def create_page(self, c: mapping.Credential, fields: dict[str, str], name: str) -> str:
        raise NotImplementedError

    def revoke_url(self, c: mapping.Credential, fields: dict[str, str]) -> str:
        """The page where the owner deletes a key, for a kind with no revoke API."""
        return self.revoke_page

    def expiry(self, answer: probes.Answer) -> datetime.date | None:
        """The expiry the provider reports for a key, from its probe's answer."""
        return None

    def probe_options(self, fields: dict[str, str], key_id: str) -> probes.Options:
        """What the probe needs besides the key: the key's own id (`key_id`, the one being
        probed) or a field of the item. Checked: plain ids only."""
        return probes.Options()

    def describe(self, value: Secret) -> str:
        """How the provider's page names a key it lists without a name keys gave it (a GitHub
        App key, by its public fingerprint); empty when keys's name for it shows."""
        return ""

    def download(self, fields: dict[str, str]) -> re.Pattern[str] | None:
        """The name of the file the provider's page downloads the new key as, for a kind
        handed out only as a file; None for a kind the owner pastes."""
        return None


# ---------------------------------------------------------------------------- Cloudflare

CF = "https://api.cloudflare.com/client/v4/user/tokens"


class Cloudflare(Rotator):
    """A user API token. The new one copies the old one's policies and IP condition, and
    expires 180 days from today. Account-owned tokens are not handled yet."""

    def mint(
        self, api: Api, minter: Grant, fields: dict[str, str], name: str, today: datetime.date
    ) -> Minted:
        token = minter.value
        old_id = ident(fields, "token_id", api.secrets)
        got = api.call("GET", f"{CF}/{old_id}", "/client/v4/user/tokens/<id>", token)
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
        made = api.call("POST", CF, "/client/v4/user/tokens", token, body)
        result = cast(dict[str, Any], made.get("result") or {})
        value, new_id = result.get("value"), result.get("id")
        if not isinstance(value, str) or not value or not isinstance(new_id, str):
            raise RotateError("Cloudflare's answer had no new token in it")
        return Minted(Secret(value), new_id, expires)

    def revoke(self, api: Api, minter: Grant, fields: dict[str, str], key_id: str) -> None:
        api.call("DELETE", f"{CF}/{key_id}", "/client/v4/user/tokens/<id>", minter.value)

    def expiry(self, answer: probes.Answer) -> datetime.date | None:
        """The expiry Cloudflare reports in the verify answer, so the 180-day check reads what
        the provider holds, not what keys asked for."""
        try:
            doc = cast(dict[str, Any], json.loads(answer.body))
            text = cast(dict[str, Any], doc.get("result") or {}).get("expires_on")
            return datetime.date.fromisoformat(str(text)[:10]) if text else None
        except (ValueError, AttributeError):
            return None


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
        self, api: Api, minter: Grant, fields: dict[str, str], name: str, today: datetime.date
    ) -> Minted:
        if fields.get("domain_id"):
            ident(fields, "domain_id", api.secrets)
        body = resend_mint_body(name, fields)
        made = api.call("POST", RESEND, "/api-keys", minter.value, body)
        value, new_id = made.get("token"), made.get("id")
        if not isinstance(value, str) or not value or not isinstance(new_id, str):
            raise RotateError("Resend's answer had no new key in it")
        return Minted(Secret(value), new_id)

    def revoke(self, api: Api, minter: Grant, fields: dict[str, str], key_id: str) -> None:
        api.call("DELETE", f"{RESEND}/{key_id}", "/api-keys/<id>", minter.value)


# ---------------------------------------------------------------------------- GitHub tokens

PAT_NEW = "https://github.com/settings/personal-access-tokens/new"
PAT_LIST = "https://github.com/settings/personal-access-tokens"


class GitHubPat(Rotator):
    """A fine-grained token: no API makes one, so keys opens GitHub's pre-filled page."""

    def create_page(self, c: mapping.Credential, fields: dict[str, str], name: str) -> str:
        owner = c.owner or fields.get("owner", "")
        if not OWNER.fullmatch(owner) or looks.looks_like_value(owner):
            raise RotateError("github-pat needs owner: the user or org the token is for")
        query = {  # the permissions first, so none of them can replace the fixed settings
            **c.permissions,
            "name": name,
            "description": "Managed by keys",
            "target_name": owner,
            "expires_in": str(MAX_DAYS),
        }
        return f"{PAT_NEW}?{urllib.parse.urlencode(query)}"

    def expiry(self, answer: probes.Answer) -> datetime.date | None:
        text = answer.headers.get("github-authentication-token-expiration", "")
        try:
            return datetime.date.fromisoformat(text[:10])
        except ValueError:
            return None


# ---------------------------------------------------------------------------- Twilio

TWILIO = "https://api.twilio.com/2010-04-01/Accounts"


class Twilio(Rotator):
    """A standard API key (a restricted one would come back standard, with wider rights, so
    keys does not rotate those), minted and deleted with a Main key (the minted_by
    credential: its own `key_sid` and secret), for the item's `account_sid`. The value is the
    key's secret; its SID is the item's `key_sid` field, delivered by targets that say
    `field = "key_sid"`."""

    def _account(self, api: Api, fields: dict[str, str]) -> str:
        return ident(fields, "account_sid", api.secrets)

    def mint(
        self, api: Api, minter: Grant, fields: dict[str, str], name: str, today: datetime.date
    ) -> Minted:
        account = self._account(api, fields)
        main = ident(minter.fields, "key_sid", api.secrets)
        made = api.call(
            "POST",
            f"{TWILIO}/{account}/Keys.json",
            "/2010-04-01/Accounts/<account>/Keys.json",
            minter.value,
            basic=main,
            form={"FriendlyName": name},
        )
        value, new_id = made.get("secret"), made.get("sid")
        if not isinstance(value, str) or not value or not isinstance(new_id, str):
            raise RotateError("Twilio's answer had no new key in it")
        if not IDENT.fullmatch(new_id):
            raise RotateError("Twilio's answer named the new key with something not an id")
        return Minted(Secret(value), new_id)

    def revoke(self, api: Api, minter: Grant, fields: dict[str, str], key_id: str) -> None:
        account = self._account(api, fields)
        main = ident(minter.fields, "key_sid", api.secrets)
        api.call(
            "DELETE",
            f"{TWILIO}/{account}/Keys/{key_id}.json",
            "/2010-04-01/Accounts/<account>/Keys/<id>.json",
            minter.value,
            basic=main,
        )

    def probe_options(self, fields: dict[str, str], key_id: str) -> probes.Options:
        account = fields.get("account_sid", "")
        if not IDENT.fullmatch(account) or not IDENT.fullmatch(key_id):
            raise RotateError("the item's account_sid or key SID is not a plain id")
        return probes.Options(user=key_id, account=account)


# ---------------------------------------------------------------------------- Railway

RAILWAY = "https://backboard.railway.com/graphql/v2"
RAILWAY_TOKENS = "https://railway.com/account/tokens"
BY_NAME = "byname-"  # a token id keys stands in for by the token's name
TOKENS_QUERY = "query($p: String!) { projectTokens(projectId: $p) { edges { node { id name } } } }"
CREATE = "mutation($i: ProjectTokenCreateInput!) { projectTokenCreate(input: $i) }"
DELETE = "mutation($id: String!) { projectTokenDelete(id: $id) }"


class RailwayProject(Rotator):
    """A project token for one environment, minted and deleted with a workspace token (the
    minted_by credential), for the item's `project_id` and `environment_id`. Railway documents
    neither mutation, so they are read from its public GraphQL schema. Project tokens have no
    expiry, so the rotation date counts."""

    def _gql(self, api: Api, minter: Grant, query: str, variables: dict[str, Any]) -> Any:
        doc = api.call(
            "POST", RAILWAY, "/graphql/v2", minter.value, {"query": query, "variables": variables}
        )
        if doc.get("errors") or not isinstance(doc.get("data"), dict):
            raise RotateError("Railway refused the call (backboard.railway.com/graphql/v2)")
        return doc["data"]

    def _named(self, api: Api, minter: Grant, project: str, name: str) -> list[str]:
        data = self._gql(api, minter, TOKENS_QUERY, {"p": project})
        tokens = cast(dict[str, Any], cast(dict[str, Any], data).get("projectTokens") or {})
        ids: list[str] = []
        for e in cast(list[Any], tokens.get("edges") or []):
            raw = cast(dict[str, Any], e).get("node") if isinstance(e, dict) else None
            node = cast(dict[str, Any], raw) if isinstance(raw, dict) else {}
            if node.get("name") == name and isinstance(node.get("id"), str):
                ids.append(cast(str, node["id"]))
        return ids

    def mint(
        self, api: Api, minter: Grant, fields: dict[str, str], name: str, today: datetime.date
    ) -> Minted:
        project = ident(fields, "project_id", api.secrets)
        environment = ident(fields, "environment_id", api.secrets)
        if self._named(api, minter, project, name):
            raise RotateError(
                f"a project token named {name!r} is there already: delete it in Railway, "
                "or rotate tomorrow"
            )
        variables = {"i": {"name": name, "projectId": project, "environmentId": environment}}
        value = self._gql(api, minter, CREATE, variables).get("projectTokenCreate")
        if not isinstance(value, str) or not value:
            raise RotateError("Railway's answer had no new token in it")
        new = Secret(value)
        try:
            found = self._named(api, minter, project, name)
        except RotateError:
            found = []
        if len(found) == 1 and IDENT.fullmatch(found[0]):
            return Minted(new, found[0])
        # No id listed: the name keys gave it is unique (checked above), so it is found by
        # that name when it is revoked.
        return Minted(new, BY_NAME + name.replace(" ", "_"))

    def revoke(self, api: Api, minter: Grant, fields: dict[str, str], key_id: str) -> None:
        if key_id.startswith(BY_NAME):
            project = ident(fields, "project_id", api.secrets)
            named = self._named(
                api, minter, project, key_id.removeprefix(BY_NAME).replace("_", " ")
            )
            if len(named) != 1:
                raise RotateError("Railway lists no single token by the name keys gave it")
            key_id = named[0]
        if self._gql(api, minter, DELETE, {"id": key_id}).get("projectTokenDelete") is not True:
            raise RotateError("Railway did not confirm the delete")


class RailwayWorkspace(Rotator):
    """A workspace (or account) token: only the dashboard makes and deletes one."""

    def create_page(self, c: mapping.Credential, fields: dict[str, str], name: str) -> str:
        return RAILWAY_TOKENS


# ---------------------------------------------------------------------------- GitHub App keys

APP_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,33}")


class GitHubAppKey(Rotator):
    """An App's private key. GitHub makes one only on the App's page, as a download, and
    deletes one only there; it allows 25 at once, so the new key works before the old one
    goes. keys moves the downloaded file into the item's pending field and deletes it."""

    def _page(self, c: mapping.Credential, fields: dict[str, str]) -> str:
        slug = fields.get("slug", "")
        if not APP_SLUG.fullmatch(slug):
            raise RotateError("github-app-key needs the item's slug field: the App's URL name")
        owner = c.owner
        if owner and (not OWNER.fullmatch(owner) or looks.looks_like_value(owner)):
            raise RotateError("github-app-key: owner must be the org that owns the App")
        if owner:
            return f"https://github.com/organizations/{owner}/settings/apps/{slug}"
        return f"https://github.com/settings/apps/{slug}"

    def create_page(self, c: mapping.Credential, fields: dict[str, str], name: str) -> str:
        return self._page(c, fields)

    def revoke_url(self, c: mapping.Credential, fields: dict[str, str]) -> str:
        return self._page(c, fields)

    def probe_options(self, fields: dict[str, str], key_id: str) -> probes.Options:
        issuer = fields.get("client_id") or fields.get("app_id") or ""
        if not IDENT.fullmatch(issuer.replace(".", "-")):
            raise RotateError("github-app-key needs the item's client_id (or app_id) field")
        return probes.Options(client_id=issuer)

    def describe(self, value: Secret) -> str:
        try:
            return appjwt.github_fingerprint(value)
        except appjwt.KeyFormatError:
            return ""

    def download(self, fields: dict[str, str]) -> re.Pattern[str] | None:
        slug = fields.get("slug", "")
        if not APP_SLUG.fullmatch(slug):
            return None
        return re.compile(
            rf"{re.escape(slug)}\.\d{{4}}-\d{{2}}-\d{{2}}\.private-key( \(\d+\))?\.pem"
        )


ROTATORS: dict[str, Rotator] = {
    r.kind: r
    for r in [
        Cloudflare("cloudflare-token", "cloudflare", id_field="token_id", mints=True),
        Resend("resend-key", "resend", id_field="key_id", mints=True),
        GitHubPat("github-pat", "github", revoke_page=PAT_LIST),
        Twilio("twilio-key", "twilio", id_field="key_sid", mints=True),
        RailwayProject("railway-project-token", "railway-project", id_field="token_id", mints=True),
        RailwayWorkspace("railway-workspace-token", "railway", revoke_page=RAILWAY_TOKENS),
        GitHubAppKey("github-app-key", "github-app"),
    ]
}
