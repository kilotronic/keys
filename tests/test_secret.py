"""A Secret never shows its value by accident: not in str, repr, format, an f-string or pickle."""

from __future__ import annotations

import pickle

import pytest

from keys.secret import Secret
from tests.canary import CANARY


def test_a_secret_hides_its_value() -> None:
    s = Secret(CANARY)
    for text in (str(s), repr(s), f"{s}", f"{s!r}", "%s" % (s,), str([s]), str({"k": s})):  # noqa: UP031
        assert CANARY not in text
    assert s.reveal() == CANARY


def test_a_secret_cannot_be_pickled() -> None:
    with pytest.raises(TypeError):
        pickle.dumps(Secret(CANARY))


def test_an_exception_holding_a_secret_shows_no_value() -> None:
    e = ValueError("bad", Secret(CANARY))
    assert CANARY not in str(e) + repr(e)


def test_equality_and_length_without_the_value() -> None:
    assert Secret("a") == Secret("a")
    assert Secret("a") != Secret("b")
    assert len(Secret("abc")) == 3
    assert not Secret("")
