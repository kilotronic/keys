"""A credential's value, which never shows itself by accident.

str, repr and format give a placeholder, so a Secret that ends up in an f-string, a log line or
an exception's arguments prints nothing of the value. Code that must send the value asks for it
by name, with `reveal()`, right where it builds the request or the child's stdin.
"""

from __future__ import annotations

from typing import NoReturn

PLACEHOLDER = "<secret>"


class Secret:
    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __str__(self) -> str:
        return PLACEHOLDER

    def __repr__(self) -> str:
        return f"Secret({PLACEHOLDER})"

    def __format__(self, spec: str) -> str:
        return PLACEHOLDER

    def __len__(self) -> int:
        return len(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and other._value == self._value

    def __hash__(self) -> int:
        return hash(("Secret", self._value))

    def __reduce__(self) -> NoReturn:
        raise TypeError("a Secret cannot be pickled")
