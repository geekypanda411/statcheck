"""Central cache directory utilities.

Runtime caches (TLD lists, TI responses) must never be written inside the
repository; they live under ``$XDG_CACHE_HOME/statcheck`` (or
``~/.cache/statcheck``). Writes are atomic so concurrent runs cannot corrupt
each other's cache files.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


def cache_dir() -> Path:
    """Return (and create) the statcheck cache directory."""
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    directory = Path(base) / "statcheck"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def write_json(path: str | Path, data) -> Path:
    """Atomically write ``data`` as JSON to ``path``.

    Uses a temp file in the same directory followed by ``os.replace`` so
    readers never observe a half-written file.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp_name, path)
    finally:
        # Only present if the replace above failed.
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
    return path


def read_json(path: str | Path):
    """Read JSON from ``path``; return None when missing or invalid."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
