"""The forms a value takes when it leaks: as sent, URL-encoded, JSON-escaped, base64, hex.

Used to search for a known value (keys scan, keys scrub) and to drop a service's error code
that holds a piece of a key (keys check). Neither is the main defence: keys never passes a
child's or a service's text through, only status and error codes it has checked.
"""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import quote, quote_plus

from keys.secret import Secret

PIECE = 9  # a run of this many characters of a value counts as the value (a hint shows 8)


def _lower_escapes(text: str) -> str:
    return re.sub(r"%[0-9A-F]{2}", lambda m: m.group().lower(), text)


def base64_forms(value: Secret) -> list[bytes]:
    """The value's base64 at each alignment, standard and URL-safe, cut to the characters that
    depend only on the value."""
    raw = value.reveal().encode()
    out: list[bytes] = []
    for shift in range(3):
        start = (shift * 8 + 5) // 6
        for enc in (base64.b64encode, base64.urlsafe_b64encode):
            text = enc(b"\0" * shift + raw).rstrip(b"=")
            part = text[start : len(text) - 2]
            if len(part) >= PIECE:
                out.append(part)
    return list(dict.fromkeys(out))


def forms(value: Secret) -> list[bytes]:
    """Every form, longest first, without duplicates."""
    v = value.reveal()
    raw = v.encode()
    out = [
        raw,
        quote(v, safe="").encode(),
        quote(v).encode(),
        quote_plus(v).encode(),
        _lower_escapes(quote(v, safe="")).encode(),
        _lower_escapes(quote(v)).encode(),
        _lower_escapes(quote_plus(v)).encode(),
        json.dumps(v)[1:-1].encode(),
        json.dumps(v, ensure_ascii=False)[1:-1].encode(),
        raw.hex().encode(),
        raw.hex().upper().encode(),
        v.encode("utf-16-le"),  # Chromium and Electron storage
    ]
    for shift in range(3):
        start = (shift * 8 + 5) // 6
        for enc in (base64.b64encode, base64.urlsafe_b64encode):
            text = enc(b"\0" * shift + raw).rstrip(b"=")
            part = text[start : len(text) - 2]
            if len(part) >= PIECE:
                out.append(part)
    unique = list(dict.fromkeys(f for f in out if f))
    return sorted(unique, key=len, reverse=True)


def holds_piece(text: str, value: Secret) -> bool:
    """Whether text holds the value in any form, or any 9-character piece of it."""
    data = text.encode()
    if any(f in data for f in forms(value)):
        return True
    raw = value.reveal().encode()
    return any(raw[i : i + PIECE] in data for i in range(len(raw) - PIECE + 1))
