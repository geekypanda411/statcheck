"""CLI-level tests for statcheck (run in a subprocess, never inside the repo)."""

from __future__ import annotations

import json
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


def _offline_config(tmp_path):
    """Config that disables every external/network-backed plugin."""
    config = tmp_path / "smoke-config.json"
    config.write_text(
        json.dumps(
            {
                "bin_path": "./bin",
                "plugins": {
                    "iocextractor": {"enabled": False},
                    "malwarebazaar": {"enabled": False},
                    "vtlookup": {"enabled": False},
                    "capa": {"enabled": False},
                    "diec": {"enabled": False},
                    "floss": {"enabled": False},
                    "quantumstrand": {"enabled": False},
                    "yara_scanner": {"enabled": False},
                },
            }
        )
    )
    return str(config)


def _run_cli(args, cwd, timeout=120):
    cmd = [sys.executable, str(MAIN), *args]
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=_sanitized_env())


def test_invalid_report_format_fails_fast_with_exit_2(tmp_path):
    """Regression: unknown --report values used to silently produce nothing."""
    result = _run_cli(
        ["/bin/true", "--format", "elf", "--report", "pdf"],
        cwd=tmp_path,
    )
    assert result.returncode == 2, (
        f"expected exit 2, got {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "pdf" in result.stdout


def test_missing_file_exits_1(tmp_path):
    result = _run_cli([str(tmp_path / "missing.bin"), "--format", "pe"], cwd=tmp_path)
    assert result.returncode == 1


def test_missing_file_without_format_still_exits_1(tmp_path):
    # --format now defaults to 'auto'; missing file must still fail cleanly.
    result = _run_cli([str(tmp_path / "missing.bin")], cwd=tmp_path)
    assert result.returncode == 1


def test_version_flag(tmp_path):
    result = _run_cli(["--version"], cwd=tmp_path)
    assert result.returncode == 0
    assert "statcheck" in result.stdout


def test_list_plugins_does_not_need_a_file(tmp_path):
    result = _run_cli(["--list-plugins"], cwd=tmp_path)
    assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"
    assert "fileinfo" in result.stdout
    assert "json_reporter" in result.stdout


def test_no_file_without_list_plugins_is_usage_error(tmp_path):
    result = _run_cli([], cwd=tmp_path)
    assert result.returncode == 2


def test_invalid_config_exits_2(tmp_path):
    bad = tmp_path / "bad-config.json"
    bad.write_text('{"plugins": {"capa": {"enabled": "yes"}}}')
    result = _run_cli(["/bin/true", "--format", "elf", "--config", str(bad)], cwd=tmp_path)
    assert result.returncode == 2, f"stdout: {result.stdout}\nstderr: {result.stderr}"
    assert "Configuration error" in result.stdout


def test_cli_is_cwd_independent(tmp_path):
    """The CLI must find its plugins/configs regardless of the caller's CWD."""
    out_dir = tmp_path / "reports-out"
    result = _run_cli(
        ["/bin/true", "--report", "json", "--config", _offline_config(tmp_path), "--output-dir", str(out_dir)],
        cwd=tmp_path,  # deliberately NOT the project root
    )
    assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"

    run_dirs = sorted(d for d in out_dir.glob("true_*") if d.is_dir())
    assert run_dirs, f"no run directory produced under {out_dir}"
    report = list(run_dirs[-1].glob("true_statcheck_summary_*.json"))
    assert report, "no JSON summary generated"
    # The report must be valid JSON with the expected top-level sections.
    payload = json.loads(report[0].read_text())
    assert "metadata" in payload
    assert "result_summary" in payload


def test_format_auto_detects_elf_for_system_binary(tmp_path):
    out_dir = tmp_path / "reports-out"
    result = _run_cli(
        ["/bin/true", "--report", "json", "--config", _offline_config(tmp_path), "--output-dir", str(out_dir)],
        cwd=tmp_path,
    )
    assert result.returncode == 0
    assert "Auto detected format elf" in result.stdout
