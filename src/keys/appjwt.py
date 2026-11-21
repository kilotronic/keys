"""A GitHub App's JWT, signed RS256 with its private key, in pure Python.

GitHub signs an App in with a JWT the App signs itself (RS256, alive at most ten minutes). keys
needs one to probe an App key, and only that. The design keeps keys to the standard library, and
RS256 signing is small: read the PEM's DER (PKCS#1 `RSA PRIVATE KEY`, as GitHub hands it out, or
PKCS#8 `PRIVATE KEY`), pad the SHA-256 digest as PKCS#1 v1.5 says, and raise it to the private
exponent. Nothing here verifies or encrypts, so the usual traps of hand-written RSA (padding
oracles, signature checks) do not arise; timing is no concern for a probe run on the owner's Mac.

The key and the token are Secrets; an error never says anything about the key's content.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re

from keys.secret import Secret

LIFETIME_S = 540  # GitHub allows ten minutes; a little less, for clock drift
BACKDATE_S = 60
SHA256_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
RSA_OID = bytes.fromhex("2a864886f70d010101")
PEM = re.compile(r"-----BEGIN (RSA PRIVATE KEY|PRIVATE KEY)-----(.*?)-----END \1-----", re.S)


class KeyFormatError(ValueError):
    """The value is not an RSA private key keys can read. Says nothing of the value."""

    def __init__(self) -> None:
        super().__init__("the value is not an RSA private key in PEM form")


def _read(der: bytes, at: int) -> tuple[int, bytes, int]:
    """(tag, body, the offset after it) of the DER element at `at`."""
    if at + 2 > len(der):
        raise KeyFormatError
    tag, n = der[at], der[at + 1]
    at += 2
    if n & 0x80:
        width = n & 0x7F
        if not 1 <= width <= 4 or at + width > len(der):
            raise KeyFormatError
        n = int.from_bytes(der[at : at + width], "big")
        at += width
    if at + n > len(der):
        raise KeyFormatError
    return tag, der[at : at + n], at + n


def _items(body: bytes) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    at = 0
    while at < len(body):
        tag, item, at = _read(body, at)
        out.append((tag, item))
    return out


def _private(pem: Secret) -> tuple[int, int]:
    """(n, d) from the PEM."""
    n, _, d = _numbers(pem)
    return n, d


def _numbers(pem: Secret) -> tuple[int, int, int]:
    """(n, e, d) from the PEM."""
    found = PEM.search(pem.reveal())
    if found is None:
        raise KeyFormatError
    try:
        der = base64.b64decode("".join(found.group(2).split()), validate=True)
    except (binascii.Error, ValueError):
        raise KeyFormatError from None
    tag, body, _ = _read(der, 0)
    if tag != 0x30:
        raise KeyFormatError
    items = _items(body)
    if found.group(1) == "PRIVATE KEY":  # PKCS#8: version, algorithm, the PKCS#1 key
        if len(items) < 3 or items[1][0] != 0x30 or items[2][0] != 0x04:
            raise KeyFormatError
        algorithm = _items(items[1][1])
        if not algorithm or algorithm[0] != (0x06, RSA_OID):
            raise KeyFormatError
        tag, body, _ = _read(items[2][1], 0)
        if tag != 0x30:
            raise KeyFormatError
        items = _items(body)
    if len(items) < 4 or any(t != 0x02 for t, _ in items[:4]):
        raise KeyFormatError
    n = int.from_bytes(items[1][1], "big")
    e = int.from_bytes(items[2][1], "big")
    d = int.from_bytes(items[3][1], "big")
    if n.bit_length() < 1000 or not 1 < d < n:
        raise KeyFormatError
    return n, e, d


def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    size = (
        bytes([n])
        if n < 0x80
        else bytes([0x80 | ((n.bit_length() + 7) // 8)])
        + n.to_bytes((n.bit_length() + 7) // 8, "big")
    )
    return bytes([tag]) + size + body


def _der_int(n: int) -> bytes:
    return _der(0x02, n.to_bytes(n.bit_length() // 8 + 1, "big"))


def github_fingerprint(pem: Secret) -> str:
    """How GitHub's App page names a key: SHA256: and the base64 SHA-256 of its public key
    (SubjectPublicKeyInfo DER). Public, so it may be printed, and it tells two keys apart."""
    n, e, _ = _numbers(pem)
    rsa_key = _der(0x30, _der_int(n) + _der_int(e))
    algorithm = _der(0x30, _der(0x06, RSA_OID) + b"\x05\x00")
    spki = _der(0x30, algorithm + _der(0x03, b"\x00" + rsa_key))
    return "SHA256:" + base64.b64encode(hashlib.sha256(spki).digest()).decode()


def is_rsa_key(pem: Secret) -> bool:
    try:
        _private(pem)
    except KeyFormatError:
        return False
    return True


def emsa_pkcs1_v15(digest: bytes, size: int) -> bytes:
    """The PKCS#1 v1.5 encoding of a SHA-256 digest, `size` bytes long (RFC 8017, 9.2)."""
    t = SHA256_INFO + digest
    if size < len(t) + 11:
        raise KeyFormatError
    return b"\x00\x01" + b"\xff" * (size - len(t) - 3) + b"\x00" + t


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign_rs256(pem: Secret, claims: dict[str, object]) -> Secret:
    n, d = _private(pem)
    head = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64(json.dumps(claims, separators=(",", ":")).encode())
    size = (n.bit_length() + 7) // 8
    em = emsa_pkcs1_v15(hashlib.sha256(f"{head}.{body}".encode()).digest(), size)
    sig = pow(int.from_bytes(em, "big"), d, n).to_bytes(size, "big")
    return Secret(f"{head}.{body}.{_b64(sig)}")


def app_jwt(pem: Secret, issuer: str, now: int) -> Secret:
    """The App's JWT: issued a minute back, alive nine minutes; `issuer` is the App's client id
    (or its numeric id)."""
    return sign_rs256(pem, {"iat": now - BACKDATE_S, "exp": now + LIFETIME_S, "iss": issuer})
