"""How keys names a value without showing it.

`fp:` is the first 8 hex digits of an HMAC-SHA-256 of the value, keyed by a fingerprint secret
held in 1Password, so even a short password cannot be guessed back from it. The hint is the
start and end of a long provider-issued key, as the provider's own console shows it.
"""

from __future__ import annotations

import hashlib
import hmac

from keys.secret import Secret

HINT_MIN = 24


def fingerprint(fp_key: Secret, value: Secret) -> str:
    mac = hmac.new(fp_key.reveal().encode(), value.reveal().encode(), hashlib.sha256)
    return mac.hexdigest()[:8]


def hint(value: Secret) -> str:
    """The first 8 and last 4 characters of a long key; nothing for a short one."""
    v = value.reveal()
    if len(v) < HINT_MIN:
        return ""
    return f"{v[:8]}…{v[-4:]}"
