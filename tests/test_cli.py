"""CLI-level tests for statcheck (run in a subprocess, never inside the repo)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

MAIN = Path(__file__).resolve().parents[1] / "main.py"


def _sanitized_env():
    """Strip API keys so no test can ever hit a live TI endpoint."""
    env = dict(os.environ)
    for key in list(env):
        if key.upper().endswith("_API_KEY"):
            del env[key]
    return env


def _run_cli(args, cwd, timeout=120):
    cmd = [sys.executable, str(MAIN), *args]
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                          env=_sanitized_env())


def test_invalid_report_format_fails_fast_with_exit_2(tmp_path):
    """Regression: unknown --report values used to silently produce nothing."""
    result = _run_cli(
        ["/bin/true", "--format", "elf", "--report", "pdf"],
        cwd=tmp_path,
    )
    assert result.returncode == 2, (f"expected exit 2, got {result.returncode}\n"
                                    f"stdout: {result.stdout}\nstderr: {result.stderr}")
    assert "pdf" in result.stdout


def test_missing_file_exits_1(tmp_path):
    result = _run_cli([str(tmp_path / "missing.bin"), "--format", "pe"], cwd=tmp_path)
    assert result.returncode == 1
