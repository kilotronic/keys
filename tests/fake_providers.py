"""Made-up Cloudflare, Resend, GitHub, Twilio and Railway APIs, answering keys's HTTPS client in
process.

Each fake keeps its keys by value, so a probe with a revoked key gets the provider's own "dead"
answer, and a key it mints is a fresh random value that the canary watches. Nothing here
reaches a real service. A failure planted with `fail` answers with a body that holds the
canary, so a test proves keys never passes a provider's text through.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import secrets
import string
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

from keys import appjwt
from keys.probes import Answer
from keys.secret import Secret
from tests.canary import Canary, LeakError

CF = "/client/v4/user/tokens"


def made_up(prefix: str) -> str:
    """A fresh random value, built at run time (never a literal shaped like a key)."""
    alphabet = string.ascii_letters + string.digits
    return prefix + "".join(secrets.choice(alphabet) for _ in range(40))


@dataclass
class Key:
    ident: str
    status: str = "active"  # active, disabled, expired
    permission: str = "full_access"  # resend
    policies: list[dict[str, Any]] = field(default_factory=lambda: list[dict[str, Any]]())
    condition: dict[str, Any] = field(default_factory=lambda: dict[str, Any]())
    expires: str = ""  # cloudflare expires_on; github expiry date
    name: str = ""
    can_mint: bool = False


class Providers:
    """Callable as keys's sender: (method, url, headers, data) -> Answer."""

    def __init__(self, canary: Canary) -> None:
        self.canary = canary
        self.keys: dict[str, dict[str, Key]] = {
            p: {} for p in ("cloudflare", "resend", "github", "twilio", "railway", "github-app")
        }
        self.railway_list_fails: set[int] = set()  # which projectTokens calls fail (1 first)
        self.railway_lists = 0
        self.twilio_refuse_reads: set[str] = set()  # key SIDs refused a read of the account
        self.calls: list[tuple[str, str]] = []
        self.fails: dict[tuple[str, str], int] = {}
        self.minted: list[str] = []
        self.mint_status = "active"  # the status a newly minted key gets
        self.ignore_revoke = False  # a revoke that answers 200 but leaves the key working
        self.last_body: dict[str, Any] = {}
        self.cf_expires_on = ""  # what Cloudflare reports, when it ignored the asked expiry
        # (method, path, status): a failure that starts once any DELETE has been answered
        self.fail_after_delete: tuple[str, str, int] | None = None

    # ------------------------------------------------------------------ setting the scene

    def add(self, provider: str, value: str, ident: str, **kw: Any) -> None:
        self.keys[provider][value] = Key(ident, **kw)
        self.canary.watch(value)

    def fail(self, method: str, path: str, status: int = 500) -> None:
        self.fails[(method, path)] = status

    def by_id(self, provider: str, ident: str) -> Key | None:
        return next((k for k in self.keys[provider].values() if k.ident == ident), None)

    def value_of(self, provider: str, ident: str) -> str:
        return next(v for v, k in self.keys[provider].items() if k.ident == ident)

    # ------------------------------------------------------------------ answering

    def __call__(
        self, method: str, url: str, headers: dict[str, str], data: bytes | None = None
    ) -> Answer:
        parts = urlsplit(url)
        assert parts.scheme == "https"
        self.calls.append((method, parts.path))
        sent = url.encode() + (data or b"")
        for value in self.canary.secrets():
            found = self.canary._leak(value, sent)  # pyright: ignore[reportPrivateUsage]
            if found:
                raise LeakError(f"a watched value went to a provider in a URL or body ({found})")
        if method == "DELETE" and self.fail_after_delete:
            m, path, code = self.fail_after_delete
            self.fails[(m, path)] = code
        status = self.fails.get((method, parts.path))
        if status is not None:
            body = {"errors": [{"code": "fake_failure", "message": self.canary.value}]}
            return Answer(status, json.dumps(body))
        auth = headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ") if auth.startswith("Bearer ") else ""
        if parts.hostname == "api.twilio.com":
            return self._twilio(method, parts.path, auth, parse_qs((data or b"").decode()))
        body_in: dict[str, Any] = json.loads(data) if data else {}
        self.last_body = body_in
        if parts.hostname == "backboard.railway.com":
            project = headers.get("Project-Access-Token", "")
            return self._railway(token, project, body_in)
        if parts.hostname == "api.github.com" and parts.path == "/app":
            return self._github_app(token)
        if parts.hostname == "api.cloudflare.com":
            return self._cloudflare(method, parts.path, token, body_in)
        if parts.hostname == "api.resend.com":
            return self._resend(method, parts.path, token, body_in)
        if parts.hostname == "api.github.com":
            return self._github(method, parts.path, token)
        return Answer(0, "", "URLError")

    def _mint(self, provider: str, prefix: str, **kw: Any) -> tuple[str, Key]:
        value = made_up(prefix)
        key = Key(f"{provider[:2]}-new-{len(self.minted) + 1}", status=self.mint_status, **kw)
        self.keys[provider][value] = key
        self.minted.append(value)
        self.canary.watch(value)
        return value, key

    def _cloudflare(self, method: str, path: str, token: str, body: dict[str, Any]) -> Answer:
        keys = self.keys["cloudflare"]
        me = keys.get(token)
        if path == f"{CF}/verify":
            if me is None:
                return Answer(401, json.dumps({"success": False, "errors": [{"code": 1000}]}))
            result = {"id": me.ident, "status": me.status, "expires_on": me.expires or None}
            return Answer(200, json.dumps({"result": result}))
        if me is None or not me.can_mint:
            return Answer(403, json.dumps({"success": False, "errors": [{"code": 9109}]}))
        if method == "POST" and path == CF:
            value, key = self._mint(
                "cloudflare",
                "cf",
                policies=body.get("policies", []),
                condition=body.get("condition", {}),
                expires=self.cf_expires_on or body.get("expires_on", ""),
                name=body.get("name", ""),
            )
            result = {"id": key.ident, "value": value, "expires_on": key.expires}
            return Answer(200, json.dumps({"success": True, "result": result}))
        ident = path.removeprefix(f"{CF}/")
        found = self.by_id("cloudflare", ident)
        if found is None:
            return Answer(404, json.dumps({"success": False, "errors": [{"code": 1003}]}))
        if method == "GET":
            result = {
                "id": found.ident,
                "name": found.name,
                "status": found.status,
                "policies": found.policies,
                "condition": found.condition,
            }
            return Answer(200, json.dumps({"success": True, "result": result}))
        if method == "DELETE":
            if not self.ignore_revoke:
                del keys[self.value_of("cloudflare", ident)]
            return Answer(200, json.dumps({"success": True, "result": {"id": ident}}))
        return Answer(405, "{}")

    def _resend(self, method: str, path: str, token: str, body: dict[str, Any]) -> Answer:
        me = self.keys["resend"].get(token)

        def err(status: int, name: str) -> Answer:
            return Answer(status, json.dumps({"statusCode": status, "name": name}))

        if method == "GET" and path == "/domains":
            if me is None:
                return err(400, "validation_error")
            if me.status != "active":
                return err(403, "restricted_api_key")
            if me.permission == "sending_access":
                return err(401, "restricted_api_key")
            return Answer(200, json.dumps({"data": []}))
        if me is None or me.permission != "full_access":
            return err(401, "restricted_api_key")
        if method == "POST" and path == "/api-keys":
            value, key = self._mint(
                "resend",
                "re_",
                permission=body.get("permission", "full_access"),
                name=body.get("name", ""),
            )
            return Answer(201, json.dumps({"id": key.ident, "token": value}))
        if method == "DELETE" and path.startswith("/api-keys/"):
            ident = path.removeprefix("/api-keys/")
            if self.by_id("resend", ident) is None:
                return err(404, "not_found")
            if not self.ignore_revoke:
                del self.keys["resend"][self.value_of("resend", ident)]
            return Answer(200, "{}")
        return err(405, "method_not_allowed")

    def _github(self, method: str, path: str, token: str) -> Answer:
        me = self.keys["github"].get(token)
        if path == "/rate_limit" and method == "GET":
            if me is None:
                return Answer(401, json.dumps({"message": "Bad credentials"}))
            headers = {"github-authentication-token-expiration": f"{me.expires} 08:00:00 UTC"}
            return Answer(200, json.dumps({"resources": {}}), headers=headers)
        return Answer(404, "{}")

    # ------------------------------------------------------------------ Twilio

    def _twilio(self, method: str, path: str, auth: str, form: dict[str, list[str]]) -> Answer:
        keys = self.keys["twilio"]
        try:
            sid, _, secret = base64.b64decode(auth.removeprefix("Basic ")).decode().partition(":")
        except ValueError:
            sid, secret = "", ""
        me = keys.get(secret)
        if me is None or me.ident != sid:
            return Answer(401, json.dumps({"code": 20003, "status": 401}))
        parts = path.split("/")  # /2010-04-01/Accounts/<account>[.json|/Keys...]
        if method == "GET" and len(parts) == 4:
            if me.ident in self.twilio_refuse_reads:
                return Answer(401, json.dumps({"code": 20003, "status": 401}))
            return Answer(200, json.dumps({"sid": parts[3].removesuffix(".json")}))
        if not me.can_mint:
            return Answer(401, json.dumps({"code": 70004, "status": 401}))
        if method == "POST" and path.endswith("/Keys.json"):
            value = made_up("tw")
            key = Key(f"SK{len(self.minted) + 1:032d}", name=form.get("FriendlyName", [""])[0])
            keys[value] = key
            self.minted.append(value)
            self.canary.watch(value)
            return Answer(201, json.dumps({"sid": key.ident, "secret": value}))
        if method == "DELETE" and "/Keys/" in path:
            ident = path.rsplit("/", 1)[1].removesuffix(".json")
            if self.by_id("twilio", ident) is None:
                return Answer(404, json.dumps({"code": 20404, "status": 404}))
            if not self.ignore_revoke:
                del keys[self.value_of("twilio", ident)]
            return Answer(204, "")
        return Answer(405, "{}")

    # ------------------------------------------------------------------ Railway

    def _railway(self, token: str, project: str, body: dict[str, Any]) -> Answer:
        keys = self.keys["railway"]
        query = str(body.get("query", ""))
        variables: dict[str, Any] = body.get("variables") or {}
        denied = json.dumps({"errors": [{"message": "Not Authorized"}], "data": None})
        if project:
            me = keys.get(project)
            if me is None or me.can_mint:  # a workspace token is not a project token
                return Answer(200, denied)
            return Answer(200, json.dumps({"data": {"projectToken": {"projectId": "p"}}}))
        me = keys.get(token)
        if me is None or not me.can_mint:
            return Answer(200, denied)
        if query.startswith("query { projects"):
            return Answer(200, json.dumps({"data": {"projects": {"edges": []}}}))
        if "projectTokens(" in query:
            self.railway_lists += 1
            if self.railway_lists in self.railway_list_fails:
                return Answer(503, "{}")
            edges = [
                {"node": {"id": k.ident, "name": k.name}} for k in keys.values() if not k.can_mint
            ]
            return Answer(200, json.dumps({"data": {"projectTokens": {"edges": edges}}}))
        if "projectTokenCreate" in query:
            value = made_up("rw")
            made: dict[str, Any] = variables["i"]
            key = Key(f"tok-new-{len(self.minted) + 1}", name=str(made["name"]))
            key.policies = [made]
            keys[value] = key
            self.minted.append(value)
            self.canary.watch(value)
            return Answer(200, json.dumps({"data": {"projectTokenCreate": value}}))
        if "projectTokenDelete" in query:
            found = self.by_id("railway", str(variables.get("id", "")))
            if found is None:
                return Answer(200, json.dumps({"errors": [{"message": "Not Found"}]}))
            if not self.ignore_revoke:
                del keys[self.value_of("railway", found.ident)]
            return Answer(200, json.dumps({"data": {"projectTokenDelete": True}}))
        return Answer(400, "{}")

    # ------------------------------------------------------------------ GitHub Apps

    def _github_app(self, token: str) -> Answer:
        """GET /app: 200 when the JWT is signed by a key the App still holds."""
        try:
            head, body, sig = token.split(".")
            raw = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
        except ValueError:
            return Answer(401, json.dumps({"message": "A JSON web token could not be decoded"}))
        digest = hashlib.sha256(f"{head}.{body}".encode()).digest()
        for pem in self.keys["github-app"]:
            n, _ = appjwt._private(Secret(pem))  # pyright: ignore[reportPrivateUsage]
            size = (n.bit_length() + 7) // 8
            em = pow(int.from_bytes(raw, "big"), 65537, n).to_bytes(size, "big")
            if em == appjwt.emsa_pkcs1_v15(digest, size):
                return Answer(200, json.dumps({"slug": "the-app"}))
        return Answer(401, json.dumps({"message": "Integration not found"}))


def days(today: datetime.date, n: int) -> str:
    return (today + datetime.timedelta(days=n)).isoformat()
