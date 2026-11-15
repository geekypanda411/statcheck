"""Shared subprocess helper with output limits and process-tree timeouts.

Analyzers must never call ``subprocess.run`` directly. ``run_tool`` provides:
- a mandatory timeout and descendant-process cleanup;
- bounded stdout/stderr capture;
- structured :class:`ToolError` / :class:`ToolTimeout` exceptions;
- debug logging of the command basename only.
"""

from __future__ import annotations

import contextlib
import logging
import math
import os
import signal
import subprocess
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_MAX_OUTPUT_BYTES = 512 * 1024 * 1024


class ToolError(RuntimeError):
    """External tool failed, produced excessive output, or exited non-zero."""


class ToolTimeout(ToolError):
    """External tool exceeded its timeout."""


def _terminate_process_tree(process: subprocess.Popen) -> None:
    """Best-effort termination of the tool and its descendants."""
    # The group leader may already have exited while descendants remain.
    # POSIX killpg still works in that case, so do not gate this on poll().
    try:
        if os.name == "posix":
            # start_new_session=True makes the child the process-group leader.
            os.killpg(process.pid, signal.SIGKILL)
        elif os.name == "nt":
            # CREATE_NEW_PROCESS_GROUP alone does not kill descendants. The
            # Windows taskkill /T option terminates the complete tree.
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:  # pragma: no cover - supported development platforms are POSIX/NT
            process.kill()
    except OSError:  # pragma: no cover - platform/race dependent
        with contextlib.suppress(OSError):
            process.kill()


def _read_bounded(stream, limit: int, destination: dict, key: str) -> None:
    """Drain a pipe while retaining at most ``limit`` bytes in memory."""
    retained = bytearray()
    truncated = False
    try:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            remaining = limit - len(retained)
            if remaining > 0:
                retained.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True
    finally:
        stream.close()
    destination[key] = (bytes(retained), truncated)


def run_tool(
    cmd: list[str],
    *,
    timeout: float,
    cwd=None,
    env=None,
    check: bool = True,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> subprocess.CompletedProcess:
    """Run an external tool with timeout and bounded stream capture.

    Each of stdout and stderr is capped independently at ``max_output_bytes``.
    Excess output is drained (so the child cannot deadlock on a full pipe) but
    discarded. A tool exceeding either cap raises :class:`ToolError`.

    Raises :class:`ToolTimeout` after terminating the process tree when the
    deadline expires, and :class:`ToolError` for excessive output or a non-zero
    exit status when ``check`` is true. ``OSError`` from process creation is
    deliberately preserved so orchestration records an analyzer failure.
    """
    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be greater than zero")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be a finite number greater than zero")

    tool_name = Path(cmd[0]).name if cmd else "<unknown>"
    logger.debug(f"Running tool: {tool_name} (timeout: {timeout}s)")
    start_new_session = os.name == "posix"
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0

    process = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=start_new_session,
        creationflags=creationflags,
    )
    captured: dict[str, tuple[bytes, bool]] = {}
    threads = [
        threading.Thread(
            target=_read_bounded,
            args=(stream, max_output_bytes, captured, name),
            name=f"ToolOutput-{tool_name}-{name}",
            daemon=True,
        )
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))
    ]
    for thread in threads:
        thread.start()

    deadline = time.monotonic() + timeout
    try:
        timed_out = False
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True

        # A direct child can exit while descendants keep stdout/stderr open.
        # Draining pipes is therefore covered by the same wall-clock deadline.
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        if any(thread.is_alive() for thread in threads):
            timed_out = True

        if timed_out:
            logger.warning(f"Tool '{tool_name}' timed out after {timeout}s; terminating its process tree.")
            raise ToolTimeout(f"'{tool_name}' timed out after {timeout}s")

        # Successful direct-child exit must not leave background descendants
        # running with redirected output after the invocation has returned.
        _terminate_process_tree(process)
    except BaseException:
        # Timeout, Ctrl-C, or reader failure must not orphan a running tool.
        _terminate_process_tree(process)
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            process.wait(timeout=1)
        for thread in threads:
            thread.join(timeout=1)
        raise

    stdout_bytes, stdout_truncated = captured.get("stdout", (b"", False))
    stderr_bytes, stderr_truncated = captured.get("stderr", (b"", False))
    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")

    if stdout_truncated or stderr_truncated:
        streams = "+".join(
            name for name, truncated in (("stdout", stdout_truncated), ("stderr", stderr_truncated)) if truncated
        )
        raise ToolError(f"'{tool_name}' exceeded the {max_output_bytes}-byte output limit on {streams}")

    if check and returncode != 0:
        stderr_summary = stderr.strip()[:2000]
        raise ToolError(f"'{tool_name}' exited with code {returncode}: {stderr_summary}")
    return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)
