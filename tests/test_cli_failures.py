"""End-to-end CLI failure-status regressions."""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import main as cli

MAIN = Path(__file__).resolve().parents[1] / "main.py"


def test_analyzer_failure_returns_exit_1_and_preserves_status_report(tmp_path):
    # Avoid unrelated unavailable-tool failures: only the deliberately broken
    # resource analyzer is enabled.
    plugins = {
        plugin_id: {"enabled": False}
        for plugin_id in (
            "fileinfo",
            "elfstructure",
            "pe_sections",
            "authenticode",
            "vtlookup",
            "malwarebazaar",
            "diec",
            "capa",
            "yara_scanner",
            "floss",
            "quantumstrand",
            "iocextractor",
        )
    }
    plugins["resource_overlay"] = {"enabled": True, "max_resource_bytes": "invalid"}
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"plugins": plugins}))
    reports = tmp_path / "reports"

    result = subprocess.run(
        [
            sys.executable,
            str(MAIN),
            "/bin/true",
            "--format",
            "elf",
            "--report",
            "json",
            "--config",
            str(config),
            "--output-dir",
            str(reports),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 1, result.stdout
    payload = json.loads(next(reports.glob("**/*.json")).read_text())
    assert payload["metadata"]["plugins"]["resource_overlay"]["status"] == "failed"
    assert "completed with failures" in result.stdout


def test_input_limit_rejects_before_format_detection(tmp_path):
    args = cli.build_parser().parse_args(["/bin/true", "--format", "auto"])
    with (
        patch.object(cli.Orchestrator, "enforce_input_limit", side_effect=ValueError("too large")),
        patch.object(cli, "detect_format") as detect,
    ):
        assert cli._run(args, logging.getLogger(__name__)) == 1
    detect.assert_not_called()


def test_non_finite_timeout_is_usage_error():
    args = cli.build_parser().parse_args(["/bin/true", "--timeout", "inf"])
    assert cli._run(args, logging.getLogger(__name__)) == 2
