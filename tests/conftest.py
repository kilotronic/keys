from __future__ import annotations

from pathlib import Path

import pytest

from tests.canary import Canary


@pytest.fixture
def canary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Canary:
    return Canary(tmp_path, monkeypatch)
