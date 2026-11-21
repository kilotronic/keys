"""keys check: each service's request and verdict, and that the key never leaves the process.

Ported from the key checker these probes came from; every case runs through the canary harness,
so stdout, stderr, children, files and (for the shell cases) history are all checked.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import json
import threading
import urllib.parse
from collections.abc import Generator
from typing import Any, ClassVar

import pytest

from keys import probes
from keys.fingerprint import fingerprint, hint
from keys.secret import Secret
from tests.canary import CANARY, Canary

FP_KEY = "fp-key-made-up-for-tests-0123456789"
KEY = CANARY


class Recorder:
    """Stands in for the network: remembers the request, gives a set answer."""

    def __init__(self, status: int, body: str = "", error: str = "") -> None:
        self.status, self.body, self.error = status, body, error
        self.calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def __call__(
        self, method: str, url: str, headers: dict[str, str], data: bytes | None = None
    ) -> probes.Answer:
        self.calls.append((method, url, headers, data))
        return probes.Answer(self.status, self.body, self.error)


@pytest.fixture
def c(canary: Canary) -> Canary:
    canary.provider_issued = True  # check prints the console-style hint for provider keys
    canary.watch(FP_KEY)
    return canary


def check(
    c: Canary, argv: list[str], status: int, body: str = "", *, key: str = KEY, error: str = ""
) -> tuple[int, str, Recorder]:
    if key != c.value:
        c.watch(key)
    sender = Recorder(status, body, error)
    result = c.run(
        ["check", *argv, "--key", "env:K"],
        env={"K": key, "FPK": FP_KEY, "KEYS_FP_KEY": "env:FPK"},
        send=sender,
    )
    return result.code, result.stdout + result.stderr, sender


def test_the_fingerprint_is_keyed_and_short() -> None:
    want = hmac.new(FP_KEY.encode(), KEY.encode(), hashlib.sha256).hexdigest()[:8]
    assert fingerprint(Secret(FP_KEY), Secret(KEY)) == want
    assert want != hashlib.sha256(KEY.encode()).hexdigest()[:8]


def test_hint_only_for_long_keys() -> None:
    assert hint(Secret(KEY)) == KEY[:8] + "…" + KEY[-4:]
    assert hint(Secret("short-password")) == ""


def test_anthropic_works_and_dead(c: Canary) -> None:
    code, out, s = check(c, ["anthropic"], 200)
    assert code == 0
    fp = fingerprint(Secret(FP_KEY), Secret(KEY))
    assert f"anthropic key fp:{fp} {KEY[:8]}…{KEY[-4:]}: WORKS" in out
    method, url, headers, _ = s.calls[0]
    assert (method, headers["x-api-key"]) == ("GET", KEY)
    assert url.startswith("https://api.anthropic.com/v1/models")
    code, out, _ = check(
        c,
        ["anthropic", "--expect", "dead"],
        401,
        '{"type":"error","error":{"type":"authentication_error"}}',
    )
    assert code == 0
    assert "DEAD (HTTP 401 from api.anthropic.com/v1/models (authentication_error))" in out


def test_expect_mismatch_fails(c: Canary) -> None:
    code, out, _ = check(c, ["anthropic", "--expect", "dead"], 200)
    assert code == 1
    assert "WORKS" in out


def test_openai_echoed_key_is_not_printed(c: Canary) -> None:
    body = json.dumps(
        {"error": {"message": f"Incorrect API key provided: {KEY}.", "code": "invalid_api_key"}}
    )
    code, out, s = check(c, ["openai"], 401, body)
    assert code == 1
    assert "DEAD" in out
    assert "invalid_api_key" in out
    assert s.calls[0][2]["Authorization"] == f"Bearer {KEY}"


def test_unknown_on_server_error_and_network(c: Canary) -> None:
    code, out, _ = check(c, ["github"], 503)
    assert code == 2
    assert "UNKNOWN (HTTP 503" in out
    code, out, _ = check(c, ["github"], 0, error=f"URLError: refused for {KEY} at the proxy")
    assert code == 2
    assert "no answer from api.github.com/rate_limit (URLError)" in out


@pytest.mark.parametrize(
    "echo",
    [
        KEY,
        KEY[:30],
        urllib.parse.quote(KEY, safe=""),
        urllib.parse.quote_plus(KEY).lower(),
        base64.b64encode(KEY.encode()).decode(),
        json.dumps(KEY)[1:-1],
    ],
)
def test_an_error_code_echoing_the_key_in_any_form_is_withheld(c: Canary, echo: str) -> None:
    code, out, _ = check(c, ["openai"], 401, json.dumps({"error": {"code": echo}}))
    assert code == 1
    assert "DEAD (HTTP 401 from api.openai.com/v1/models)" in out


def test_a_short_key_in_the_error_code_is_withheld(c: Canary) -> None:
    short = "sk-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"  # made up; fits the code length cap
    code, out, _ = check(c, ["openai"], 401, json.dumps({"error": {"code": short}}), key=short)
    assert code == 1
    assert "DEAD (HTTP 401 from api.openai.com/v1/models)" in out


def test_key_in_the_request_path_is_never_shown(c: Canary) -> None:
    prov = probes.Provider(
        "path",
        "test",
        lambda k, a: ("GET", f"https://api.example.com/bot{k.reveal()}/me", {}, None),
        {200},
        {401},
    )
    for answer in (probes.Answer(401, ""), probes.Answer(0, "", "URLError: refused")):
        sender = Recorder(answer.status, answer.body, answer.error)
        _, reason = probes.check(prov, Secret(KEY), probes.Options(), sender)
        assert KEY[:9] not in reason
        assert "api.example.com" in reason


def test_serpapi_url_holding_key_is_not_shown(c: Canary) -> None:
    code, out, s = check(c, ["serpapi"], 401, '{"error": "Invalid API key."}')
    assert code == 1
    assert "serpapi.com/account.json" in out
    assert "api_key=" in s.calls[0][1]


def test_adobe_needs_client_id_and_reads_invalid_client(c: Canary) -> None:
    code, _, _ = check(c, ["adobe"], 200)
    assert code == 3
    code, out, s = check(
        c,
        ["adobe", "--client-id", "cid"],
        400,
        '{"error":{"code":"invalid_client","message":"invalid client_secret parameter"}}',
    )
    assert code == 1
    assert "DEAD" in out
    data = s.calls[0][3]
    assert data is not None
    assert b"client_secret=" in data


def test_adobe_unknown_client_id_is_not_dead(c: Canary) -> None:
    code, out, _ = check(
        c,
        ["adobe", "--client-id", "wrong", "--expect", "dead"],
        400,
        '{"error":{"code":"invalid_client","message":"invalid client_id parameter"}}',
    )
    assert code == 2
    assert "UNKNOWN" in out
    assert "check --client-id" in out


def test_google_client_good_secret_is_invalid_grant(c: Canary) -> None:
    code, out, _ = check(
        c,
        ["google-oauth-client", "--client-id", "x.apps.googleusercontent.com"],
        400,
        '{"error": "invalid_grant", "error_description": "Bad Request"}',
    )
    assert code == 0
    assert "WORKS" in out
    code, out, _ = check(
        c,
        ["google-oauth-client", "--client-id", "x"],
        401,
        '{"error": "invalid_client", "error_description": "The OAuth client was not found."}',
    )
    assert code == 1
    assert "DEAD" in out


def test_cloudflare_verify(c: Canary) -> None:
    code, out, s = check(c, ["cloudflare"], 200, '{"success":true,"result":{"status":"active"}}')
    assert code == 0
    assert s.calls[0][1] == "https://api.cloudflare.com/client/v4/user/tokens/verify"
    code, out, _ = check(
        c, ["cloudflare"], 401, '{"success":false,"errors":[{"code":1000,"message":"Invalid"}]}'
    )
    assert code == 1
    assert "(1000)" in out


def test_azure_storage_shared_key_is_off(c: Canary) -> None:
    key = base64.b64encode(b"k" * 64).decode()
    body = '﻿<?xml version="1.0"?><Error><Code>KeyBasedAuthenticationNotPermitted</Code></Error>'
    code, out, s = check(c, ["azure-storage", "--account", "acct"], 403, body, key=key)
    assert code == 1
    assert "KeyBasedAuthenticationNotPermitted" in out
    assert s.calls[0][2]["Authorization"].startswith("SharedKey acct:")


def test_azure_storage_connection_string(c: Canary) -> None:
    key = base64.b64encode(b"k" * 64).decode()
    conn = f"DefaultEndpointsProtocol=https;AccountName=acct2;AccountKey={key};EndpointSuffix=x"
    code, _, s = check(c, ["azure-storage"], 200, key=conn)
    assert code == 0
    assert s.calls[0][1].startswith("https://acct2.blob.core.windows.net/")


def test_azure_storage_signature() -> None:
    key = base64.b64encode(b"secret-bytes").decode()
    _, _, headers, _ = probes.azure_storage_request(Secret(key), probes.Options(account="acct"))
    to_sign = probes.azure_string_to_sign("acct", headers["x-ms-date"], headers["x-ms-version"])
    want = base64.b64encode(
        hmac.new(b"secret-bytes", to_sign.encode(), hashlib.sha256).digest()
    ).decode()
    assert headers["Authorization"] == f"SharedKey acct:{want}"
    assert to_sign.count("\n") == 12 + 2 + 2


def test_http_generic(c: Canary) -> None:
    code, _, s = check(
        c,
        [
            "http",
            "--url",
            "https://api.example.com/me",
            "--header",
            "X-API-Key: {key}",
            "--dead-status",
            "401",
        ],
        401,
    )
    assert code == 1
    assert s.calls[0][2]["X-API-Key"] == KEY
    code, _, _ = check(
        c, ["http", "--url", "https://api.example.com/me", "--header", "X-API-Key: oops"], 200
    )
    assert code == 3


def test_http_refuses_plain_http_except_to_this_machine(c: Canary) -> None:
    code, out, _ = check(c, ["http", "--url", "http://api.example.com/me", "--bearer"], 200)
    assert code == 3
    assert "https" in out
    code, _, _ = check(c, ["http", "--url", "http://127.0.0.1:9/me", "--bearer"], 200)
    assert code == 0


def test_every_provider_has_a_check() -> None:
    opts = probes.Options(
        client_id="x", account="x", scm_host="x", user="x", url="https://x", header=["X: {key}"]
    )
    for p in probes.PROVIDERS.values():
        key = base64.b64encode(b"k" * 32).decode() if p.name == "azure-storage" else KEY
        verdict, reason = probes.check(p, Secret(key), opts, Recorder(200))
        assert verdict in (probes.WORKS, probes.UNKNOWN), p.name
        assert key not in reason


def test_list_of_services(c: Canary) -> None:
    result = c.run(["check", "--list"])
    assert result.code == 0
    for name in ("anthropic", "openai", "github", "cloudflare", "http"):
        assert name in result.stdout


# ---------------------------------------------------------------------------- key sources


def test_the_key_from_1password(c: Canary) -> None:
    c.op_value("op://Vault/item/credential", KEY)
    sender = Recorder(200)
    result = c.run(
        ["check", "github", "--key", "op://Vault/item/credential"],
        env={"FPK": FP_KEY, "KEYS_FP_KEY": "env:FPK"},
        send=sender,
    )
    assert result.code == 0, result.stderr
    assert sender.calls[0][2]["Authorization"] == f"Bearer {KEY}"
    assert result.children[0].argv == ["op", "read", "--no-newline", "op://Vault/item/credential"]


def test_a_1password_failure_prints_only_its_exit_code(c: Canary) -> None:
    c.op_fail("op://Vault/item/credential", code=6)  # its error text holds the canary
    result = c.run(
        ["check", "github", "--key", "op://Vault/item/credential"],
        env={"FPK": FP_KEY, "KEYS_FP_KEY": "env:FPK"},
        send=Recorder(200),
    )
    assert result.code == 3
    assert "op exited 6" in result.stderr


def test_the_fingerprint_key_from_1password(c: Canary) -> None:
    c.op_value("op://Vault/keys fingerprint/credential", FP_KEY)
    result = c.run(
        ["check", "github", "--key", "env:K", "--fp-key", "op://Vault/keys fingerprint/credential"],
        env={"K": KEY},
        send=Recorder(200),
    )
    assert result.code == 0, result.stderr
    assert f"fp:{fingerprint(Secret(FP_KEY), Secret(KEY))}" in result.stdout


def test_the_key_on_stdin(c: Canary) -> None:
    sender = Recorder(200)
    result = c.run(
        ["check", "github", "--key", "stdin"],
        stdin=KEY + "\n",
        env={"FPK": FP_KEY, "KEYS_FP_KEY": "env:FPK"},
        send=sender,
    )
    assert result.code == 0
    assert sender.calls[0][2]["Authorization"] == f"Bearer {KEY}"


@pytest.mark.parametrize(
    ("source", "env", "message"),
    [
        (KEY, {}, "unknown key source"),  # the value itself, typed by mistake: not echoed
        ("env:MISSING", {}, "the environment variable named by --key is not set"),
        ("stdin", {}, "the key is empty"),
    ],
)
def test_bad_sources(c: Canary, source: str, env: dict[str, str], message: str) -> None:
    result = c.run(
        ["check", "github", "--key", source],
        env={"FPK": FP_KEY, "KEYS_FP_KEY": "env:FPK", **env},
        send=Recorder(200),
    )
    assert result.code == 3
    assert message in result.stderr


def test_no_fingerprint_key_is_a_usage_error(c: Canary) -> None:
    result = c.run(["check", "github", "--key", "env:K"], env={"K": KEY}, send=Recorder(200))
    assert result.code == 3
    assert "fingerprint key" in result.stderr


def test_an_unknown_service(c: Canary) -> None:
    result = c.run(["check", "nope", "--key", "env:K"], env={"K": KEY}, send=Recorder(200))
    assert result.code == 3
    assert "unknown service" in result.stderr


# ---------------------------------------------------------------------------- a real shell


class _Echo(http.server.BaseHTTPRequestHandler):
    """A service that repeats the key back everywhere it can."""

    def do_GET(self) -> None:
        auth = self.headers.get("Authorization", "")
        body = json.dumps({"error": {"code": auth, "message": f"bad key {auth}"}}).encode()
        self.send_response(401)
        self.send_header("X-Echo", auth)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        pass


@pytest.fixture
def echo_server() -> Generator[str]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/me"
    server.shutdown()


def test_check_through_a_real_shell_against_a_service_that_echoes_the_key(
    c: Canary, echo_server: str
) -> None:
    c.op_value("op://Vault/item/credential", KEY)
    result = c.shell(
        f"KEYS_FP_KEY=env:FPK keys check http --url {echo_server} --bearer "
        "--key op://Vault/item/credential",
        env={"FPK": FP_KEY},
    )
    assert result.code == 1, result.stderr
    assert "DEAD (HTTP 401 from 127.0.0.1" in result.stdout


def test_check_with_the_key_piped_from_op_in_a_real_shell(c: Canary, echo_server: str) -> None:
    c.op_value("op://Vault/item/credential", KEY)
    result = c.shell(
        "op read --no-newline op://Vault/item/credential | "
        f"KEYS_FP_KEY=env:FPK keys check http --url {echo_server} --bearer --key stdin",
        env={"FPK": FP_KEY},
    )
    assert result.code == 1, result.stderr
    assert "DEAD" in result.stdout


def test_a_child_never_sees_keys_own_environment() -> None:
    from keys.proc import child_env

    env = {"PATH": "/bin", "HOME": "/h", "K": KEY, "OP_ACCOUNT": "acct", "GH_TOKEN": "x"}
    assert child_env(env, ("OP_",)) == {"PATH": "/bin", "HOME": "/h", "OP_ACCOUNT": "acct"}


# ---------------------------------------------------------------------------- review fixes


class _Redirect(http.server.BaseHTTPRequestHandler):
    target = ""

    def do_GET(self) -> None:
        self.send_response(302)
        self.send_header("Location", self.target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        pass


class _Count(http.server.BaseHTTPRequestHandler):
    seen: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        _Count.seen.append(self.headers.get("Authorization", ""))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        pass


def _serve(handler: type[http.server.BaseHTTPRequestHandler]) -> http.server.ThreadingHTTPServer:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_a_redirect_is_not_followed_with_the_key(c: Canary) -> None:
    other = _serve(_Count)
    _Redirect.target = f"http://127.0.0.1:{other.server_address[1]}/elsewhere"
    first = _serve(_Redirect)
    _Count.seen.clear()
    try:
        result = c.run(
            [
                "check",
                "http",
                "--url",
                f"http://127.0.0.1:{first.server_address[1]}/me",
                "--bearer",
                "--key",
                "env:K",
            ],
            env={"K": KEY, "FPK": FP_KEY, "KEYS_FP_KEY": "env:FPK"},
        )
    finally:
        first.shutdown()
        other.shutdown()
    assert _Count.seen == []
    assert result.code == 2
    assert "UNKNOWN (HTTP 302" in result.stdout


def test_a_refused_connection_names_the_real_error_type(c: Canary) -> None:
    result = c.run(
        ["check", "http", "--url", "http://127.0.0.1:9/me", "--bearer", "--key", "env:K"],
        env={"K": KEY, "FPK": FP_KEY, "KEYS_FP_KEY": "env:FPK"},
    )
    assert result.code == 2
    assert "(ConnectionRefusedError)" in result.stdout


@pytest.mark.parametrize("key", [KEY[:10] + "\n" + KEY[10:], KEY + "☃"])
def test_a_key_that_cannot_go_in_a_header_is_unknown_not_a_crash(c: Canary, key: str) -> None:
    c.watch(key)
    result = c.run(
        ["check", "http", "--url", "http://127.0.0.1:9/me", "--bearer", "--key", "env:K"],
        env={"K": key, "FPK": FP_KEY, "KEYS_FP_KEY": "env:FPK"},
    )
    assert result.code == 2, result.stderr


def test_an_env_source_named_like_a_token_is_not_echoed(c: Canary) -> None:
    token = "gh" + "p_" + "Zx81Qw" * 6  # made up
    c.watch(token)
    result = c.run(
        ["check", "github", "--key", f"env:{token}"],
        env={"FPK": FP_KEY, "KEYS_FP_KEY": "env:FPK"},
        send=Recorder(200),
    )
    assert result.code == 3
    assert "the environment variable named by --key is not set" in result.stderr


@pytest.mark.parametrize(
    "url", ["http://argilla.example.com", "file:///etc/hosts", "ftp://x.example.com"]
)
def test_argilla_and_every_provider_send_only_over_https(c: Canary, url: str) -> None:
    code, out, s = check(c, ["argilla", "--url", url], 200)
    assert code == 3
    assert "https" in out
    assert s.calls == []


def test_userinfo_in_the_url_is_not_shown(c: Canary) -> None:
    _code, out, _ = check(c, ["http", "--url", "https://someone@api.example.com/me", "--bearer"], 0)
    assert "someone" not in out
    assert "api.example.com/me" in out


def test_a_short_fingerprint_key_is_refused(c: Canary) -> None:
    result = c.run(
        ["check", "github", "--key", "env:K"],
        env={"K": KEY, "FPK": "short", "KEYS_FP_KEY": "env:FPK"},
        send=Recorder(200),
    )
    assert result.code == 3
    assert "at least 16" in result.stderr


def test_no_hint_for_a_key_of_unknown_origin(c: Canary) -> None:
    c.provider_issued = False
    code, out, _ = check(c, ["http", "--url", "https://api.example.com/me", "--bearer"], 200)
    assert code == 0
    assert "…" not in out


@pytest.mark.parametrize(
    ("status", "verdict"), [("active", "WORKS"), ("disabled", "DEAD"), ("expired", "DEAD")]
)
def test_cloudflare_reads_the_token_status(c: Canary, status: str, verdict: str) -> None:
    body = json.dumps({"success": True, "result": {"status": status}})
    code, out, _ = check(c, ["cloudflare"], 200, body)
    assert verdict in out
    assert code == (0 if verdict == "WORKS" else 1)
