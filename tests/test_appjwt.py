"""The GitHub App's JWT, signed RS256 in pure Python from the App's private key.

The keys here are made at run time (two random primes), never a literal, and the signature is
checked both by the RSA equation and, where `openssl` is installed, by openssl itself.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import shutil
import subprocess
from pathlib import Path

import pytest

from keys import appjwt
from keys.secret import Secret

E = 65537


def _probable_prime(bits: int) -> int:
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if all(n % p for p in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)) and _miller_rabin(n):
            return n


def _miller_rabin(n: int, rounds: int = 24) -> bool:
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _int(n: int) -> bytes:
    raw = n.to_bytes(n.bit_length() // 8 + 1, "big")
    return _tlv(0x02, raw)


def _pem(label: str, der: bytes) -> str:
    b64 = base64.b64encode(der).decode()
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def make_key(bits: int = 2048) -> tuple[str, str, int]:
    """(PKCS#1 PEM, PKCS#8 PEM, n) of a fresh RSA key."""
    while True:
        p, q = _probable_prime(bits // 2), _probable_prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and phi % E:
            break
    n, d = p * q, pow(E, -1, phi)
    ints = [0, n, E, d, p, q, d % (p - 1), d % (q - 1), pow(q, -1, p)]
    pkcs1 = _tlv(0x30, b"".join(_int(i) for i in ints))
    rsa_oid = bytes.fromhex("06092a864886f70d0101010500")
    pkcs8 = _tlv(0x30, _int(0) + _tlv(0x30, rsa_oid) + _tlv(0x04, pkcs1))
    return _pem("RSA PRIVATE KEY", pkcs1), _pem("PRIVATE KEY", pkcs8), n


@pytest.fixture(scope="module")
def key() -> tuple[str, str, int]:
    return make_key()


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _check(token: str, n: int) -> dict[str, object]:
    head, body, sig = token.split(".")
    assert json.loads(_b64d(head)) == {"alg": "RS256", "typ": "JWT"}
    s = int.from_bytes(_b64d(sig), "big")
    em = pow(s, E, n).to_bytes((n.bit_length() + 7) // 8, "big")
    digest = hashlib.sha256(f"{head}.{body}".encode()).digest()
    assert em == appjwt.emsa_pkcs1_v15(digest, len(em))
    return json.loads(_b64d(body))


def test_a_pkcs1_key_signs_a_jwt_the_rsa_equation_accepts(key: tuple[str, str, int]) -> None:
    pkcs1, _, n = key
    token = appjwt.app_jwt(Secret(pkcs1), "Iv1.abc123", now=1_800_000_000).reveal()
    claims = _check(token, n)
    # Issued a minute back for clock drift, and alive under ten minutes, as GitHub asks.
    assert claims == {"iat": 1_800_000_000 - 60, "exp": 1_800_000_000 + 540, "iss": "Iv1.abc123"}


def test_a_pkcs8_key_signs_the_same_way(key: tuple[str, str, int]) -> None:
    pkcs1, pkcs8, n = key
    one = appjwt.app_jwt(Secret(pkcs1), "123", now=1_800_000_000).reveal()
    eight = appjwt.app_jwt(Secret(pkcs8), "123", now=1_800_000_000).reveal()
    assert one == eight  # PKCS#1 v1.5 is deterministic
    _check(eight, n)


def test_the_token_is_a_secret() -> None:
    pkcs1, _, _ = make_key(1024)
    token = appjwt.app_jwt(Secret(pkcs1), "1", now=1)
    assert isinstance(token, Secret)
    assert str(token) == "<secret>"


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is not installed")
def test_openssl_verifies_the_signature(key: tuple[str, str, int], tmp_path: Path) -> None:
    pkcs1, _, _ = key
    token = appjwt.app_jwt(Secret(pkcs1), "123", now=1_800_000_000).reveal()
    head, body, sig = token.split(".")
    (tmp_path / "k.pem").write_text(pkcs1)
    pub = subprocess.run(
        ["openssl", "rsa", "-in", str(tmp_path / "k.pem"), "-pubout"],
        capture_output=True,
        check=True,
    ).stdout
    (tmp_path / "pub.pem").write_bytes(pub)
    (tmp_path / "sig").write_bytes(_b64d(sig))
    (tmp_path / "data").write_bytes(f"{head}.{body}".encode())
    done = subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(tmp_path / "pub.pem"),
            "-signature",
            str(tmp_path / "sig"),
            str(tmp_path / "data"),
        ],
        capture_output=True,
    )
    assert done.returncode == 0, done.stdout


@pytest.mark.parametrize(
    "text",
    [
        "",
        "not a key at all",
        _pem("RSA PRIVATE KEY", b"").replace("\n\n", "\n!!!!\n"),  # not base64
        _pem("RSA PRIVATE KEY", b"\x30\x00"),  # an empty sequence
        _pem("EC PRIVATE KEY", b"\x30\x00"),
        _pem("ENCRYPTED PRIVATE KEY", b"\x30\x00"),
    ],
)
def test_text_that_is_not_an_rsa_key_is_refused_without_repeating_it(text: str) -> None:
    with pytest.raises(appjwt.KeyFormatError) as e:
        appjwt.app_jwt(Secret(text), "1", now=1)
    assert str(e.value) == "the value is not an RSA private key in PEM form"
    assert e.value.__cause__ is None
    assert e.value.__context__ is None or e.value.__suppress_context__


def test_a_key_with_its_pem_lines_folded_by_crlf_still_reads(key: tuple[str, str, int]) -> None:
    pkcs1, _, n = key
    token = appjwt.app_jwt(Secret(pkcs1.replace("\n", "\r\n")), "1", now=5).reveal()
    _check(token, n)


def test_looks_like_an_rsa_key() -> None:
    pkcs1, pkcs8, _ = make_key(1024)
    assert appjwt.is_rsa_key(Secret(pkcs1))
    assert appjwt.is_rsa_key(Secret(pkcs8))
    assert not appjwt.is_rsa_key(Secret("plain text"))


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is not installed")
@pytest.mark.parametrize("argv", [["genrsa", "2048"], ["genpkey", "-algorithm", "RSA"]])
def test_keys_openssl_makes_are_read_and_fingerprinted_as_github_shows(
    argv: list[str], tmp_path: Path
) -> None:
    pem = subprocess.run(["openssl", *argv], capture_output=True, check=True, text=True).stdout
    assert appjwt.is_rsa_key(Secret(pem))
    (tmp_path / "k.pem").write_text(pem)
    der = subprocess.run(
        ["openssl", "pkey", "-in", str(tmp_path / "k.pem"), "-pubout", "-outform", "DER"],
        capture_output=True,
        check=True,
    ).stdout
    want = "SHA256:" + base64.b64encode(hashlib.sha256(der).digest()).decode()
    assert appjwt.github_fingerprint(Secret(pem)) == want
