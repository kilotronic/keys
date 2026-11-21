"""Replacing a file keys owns (the mapping file) whole, so a crash never leaves half of it."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def replace(path: Path, text: str) -> None:
    """path, replaced whole: written beside it under a fresh name, then moved over it, keeping
    its permissions, and the folder synced so the move survives a power cut."""
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".keys-new")
    tmp = Path(name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        folder = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(folder)
        finally:
            os.close(folder)
    finally:
        tmp.unlink(missing_ok=True)
