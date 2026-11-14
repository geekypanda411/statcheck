"""Centralized path resolution.

All statcheck defaults are anchored to the project layout (the directory
containing ``main.py``), never to the caller's CWD. Relative user-supplied
paths are resolved against an explicit base (default: the project root).
"""

from __future__ import annotations

from pathlib import Path

# src/core/paths.py -> src/core -> src -> <project root>
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def resolve_path(value: str | Path, base: Path = PROJECT_ROOT) -> Path:
    """Resolve ``value`` against ``base`` (default project root).

    Absolute paths are returned as-is (after expanduser/resolve); relative
    paths are interpreted relative to ``base``, not the current CWD.
    """
    p = Path(value).expanduser()
    return p.resolve() if p.is_absolute() else (base / p).resolve()
