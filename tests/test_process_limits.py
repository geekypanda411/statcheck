"""Resource-limit and process-tree tests for run_tool."""

from __future__ import annotations

import os
import sys
import time

import pytest

from src.core.process import ToolError, ToolTimeout, run_tool


def test_excessive_stdout_raises_instead_of_returning_unbounded_text():
    with pytest.raises(ToolError, match="output limit.*stdout"):
        run_tool(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 20000)"],
            timeout=10,
            max_output_bytes=1024,
        )


@pytest.mark.skipif(os.name != "posix", reason="process-group assertions are POSIX-specific")
def test_timeout_kills_descendant_processes(tmp_path):
    marker = tmp_path / "descendant-survived"
    grandchild = (
        f"import pathlib,time; time.sleep(0.4); pathlib.Path({str(marker)!r}).write_text('survived'); time.sleep(20)"
    )
    parent = f"import subprocess,sys,time; subprocess.Popen([sys.executable, '-c', {grandchild!r}]); time.sleep(20)"

    with pytest.raises(ToolTimeout):
        run_tool([sys.executable, "-c", parent], timeout=0.1)

    time.sleep(0.6)
    assert not marker.exists(), "a descendant continued running after ToolTimeout"


@pytest.mark.skipif(os.name != "posix", reason="process-group assertions are POSIX-specific")
def test_parent_exit_cannot_extend_deadline_through_inherited_pipes():
    parent = "import subprocess,sys; subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(5)'])"
    started = time.monotonic()

    with pytest.raises(ToolTimeout):
        run_tool([sys.executable, "-c", parent], timeout=0.15)

    assert time.monotonic() - started < 1.5


@pytest.mark.skipif(os.name != "posix", reason="process-group assertions are POSIX-specific")
def test_successful_parent_does_not_leave_detached_output_descendant(tmp_path):
    marker = tmp_path / "background-write"
    grandchild = (
        f"import pathlib,time; time.sleep(0.3); pathlib.Path({str(marker)!r}).write_text('survived'); time.sleep(5)"
    )
    parent = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}], "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)"
    )

    result = run_tool([sys.executable, "-c", parent], timeout=2)
    assert result.returncode == 0
    time.sleep(0.5)
    assert not marker.exists()
