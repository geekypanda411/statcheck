"""Shared subprocess helper: every external tool call gets a timeout.

Analyzers must never call ``subprocess.run`` directly; ``run_tool`` adds:
- a mandatory timeout (no tool can hang the pipeline indefinitely),
- structured :class:`ToolError` / :class:`ToolTimeout` exceptions,
- captured stdout/stderr and debug logging of the command (basename only).
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


class ToolError(RuntimeError):
    """External tool failed (non-zero exit code)."""


class ToolTimeout(ToolError):
    """External tool exceeded its timeout."""


def run_tool(cmd: list[str], *, timeout: float, cwd=None, env=None,
             check: bool = True) -> subprocess.CompletedProcess:
    """Run an external tool with a hard timeout.

    Raises ToolTimeout when the tool exceeds ``timeout`` seconds and ToolError
    when it exits non-zero (with stderr truncated to 2000 chars).
    """
    tool_name = Path(cmd[0]).name if cmd else "<unknown>"
    logger.debug(f"Running tool: {tool_name} (timeout: {timeout}s)")
    try:
        result = subprocess.run(
            cmd, cwd=cwd, env=env, timeout=timeout,
            text=True, capture_output=True, check=False,
        )
    except subprocess.TimeoutExpired as e:
        logger.warning(f"Tool '{tool_name}' timed out after {timeout}s.")
        raise ToolTimeout(f"'{tool_name}' timed out after {timeout}s") from e

    if check and result.returncode != 0:
        stderr = (result.stderr or "").strip()[:2000]
        raise ToolError(f"'{tool_name}' exited with code {result.returncode}: {stderr}")
    return result
