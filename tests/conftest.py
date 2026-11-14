"""Shared pytest fixtures.

Rules (from the improvement plan):
- No network.
- No writes inside the repo; use ``tmp_path``.
- No real malware; use benign system binaries or synthetic bytes.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure the project root is importable regardless of the CWD pytest is
# invoked from. This deliberately mirrors what `python main.py` does.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture()
def project_root() -> Path:
    """Absolute path to the repository root (import location, not CWD)."""
    return PROJECT_ROOT
