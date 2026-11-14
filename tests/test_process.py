"""Tests for the shared subprocess helper (no real malware, no network)."""

from __future__ import annotations

import sys

import pytest

from src.core.process import ToolError, ToolTimeout, run_tool

SLEEP_CMD = [sys.executable, "-c", "import time; time.sleep(5)"]


def test_run_tool_success():
    result = run_tool([sys.executable, "-c", "print('hello')"], timeout=10)
    assert result.returncode == 0
    assert result.stdout.strip() == "hello"


def test_run_tool_nonzero_exit_raises_tool_error():
    with pytest.raises(ToolError) as excinfo:
        run_tool([sys.executable, "-c", "import sys; sys.stderr.write('boom\n'); sys.exit(3)"], timeout=10)
    assert "boom" in str(excinfo.value)
    assert "exit" in str(excinfo.value).lower()


def test_run_tool_timeout_raises_tool_timeout():
    with pytest.raises(ToolTimeout):
        run_tool(SLEEP_CMD, timeout=0.2)


def test_run_tool_check_false_returns_nonzero_process():
    result = run_tool(
        [sys.executable, "-c", "import sys; sys.exit(1)"],
        timeout=10,
        check=False,
    )
    assert result.returncode == 1


def test_stderr_is_truncated_in_tool_error():
    filler = "x" * 5000
    with pytest.raises(ToolError) as excinfo:
        run_tool(
            [sys.executable, "-c", f"import sys; sys.stderr.write({filler!r}); sys.exit(2)"],
            timeout=10,
        )
    # 2000 chars of stderr + command name + exit code framing.
    assert len(str(excinfo.value)) < 2400


def test_missing_binary_raises_oserror_not_silent():
    # FileNotFoundError (an OSError, not a ToolError) must propagate so the
    # orchestrator records the plugin as failed, not silently "done".
    with pytest.raises(OSError):
        run_tool(["/nonexistent/binary-xyz", "--version"], timeout=10)
