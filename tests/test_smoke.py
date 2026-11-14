"""End-to-end smoke test: full pipeline against a benign system binary.

External/network-backed plugins are disabled via a temp config; the output
goes to a temp directory. No network, no repo writes, no malware.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

MAIN = Path(__file__).resolve().parents[1] / "main.py"


def _sanitized_env():
    env = dict(os.environ)
    for key in list(env):
        if key.upper().endswith("_API_KEY"):
            del env[key]
    return env


def _offline_config(tmp_path):
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


def _run(tmp_path, target="/bin/true", fmt="elf", reports=("json",)):
    out_dir = tmp_path / "reports-out"
    cmd = [
        sys.executable,
        str(MAIN),
        target,
        "--format",
        fmt,
        "--report",
        *reports,
        "--config",
        _offline_config(tmp_path),
        "--output-dir",
        str(out_dir),
        "--workers",
        "4",
    ]
    result = subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True, timeout=180, env=_sanitized_env())
    return result, out_dir


def test_smoke_elf_bin_true_full_pipeline(tmp_path):
    result, out_dir = _run(tmp_path)

    assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"

    run_dirs = [d for d in out_dir.glob("true_*") if d.is_dir()]
    assert run_dirs, f"no run directory under {out_dir}"
    run_dir = run_dirs[0]

    reports = list(run_dir.glob("true_statcheck_summary_*.json"))
    assert reports, "no JSON report generated"
    payload = json.loads(reports[0].read_text())

    # Schema and metadata contract.
    assert payload["schema_version"] == "1.0"
    assert "run" in payload["metadata"]
    assert "plugins" in payload["metadata"]
    assert payload["metadata"]["run"]["format"] == "elf"
    assert "python_version" in payload["metadata"]["run"]
    assert "duration_ms" in payload["metadata"]["run"]

    # The pure-python analyzers must have completed successfully.
    plugins = payload["metadata"]["plugins"]
    assert plugins["fileinfo"]["status"] == "completed"
    assert plugins["elfstructure"]["status"] == "completed"
    assert plugins["resource_overlay"]["status"] == "completed"

    # Summaries exist and hashes are sane.
    fileinfo = payload["result_summary"]["fileinfo"]
    sha256 = fileinfo["File_SHA256"]
    assert len(sha256) == 64 and sha256 == sha256.lower()
    assert fileinfo["Size_Bytes"] == Path("/bin/true").stat().st_size
    assert "Entropy" in fileinfo

    # Disabled plugins are visible in the report.
    assert plugins["capa"]["status"] == "skipped_disabled"
    assert plugins["vtlookup"]["status"] == "skipped_disabled"

    # Raw artifact paths are run-dir-relative and exist.
    raw_rel = payload["result_summary"]["fileinfo"].get("raw_output_path")
    if raw_rel is not None:
        assert not raw_rel.startswith("/")
        assert (run_dir / raw_rel).is_file()


def test_smoke_markdown_and_json_together(tmp_path):
    result, out_dir = _run(tmp_path, reports=("json", "markdown"))
    assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"

    run_dir = next(d for d in out_dir.glob("true_*") if d.is_dir())
    assert list(run_dir.glob("true_statcheck_summary_*.json"))
    md = list(run_dir.glob("true_statcheck_summary_*.md"))
    assert md, "no Markdown report generated"
    text = md[0].read_text()
    assert text.startswith("# statcheck report:")
    assert "## fileinfo" in text


def test_smoke_tools_config_untouched(tmp_path):
    """tools_config.json must never be written at runtime."""
    import hashlib

    config = tmp_path / "config.json"
    config.write_text(json.dumps({"bin_path": "./bin", "plugins": {"capa": {"enabled": False}}}))
    before = hashlib.sha256(config.read_bytes()).hexdigest()

    out_dir = tmp_path / "out"
    subprocess.run(
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
            str(out_dir),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=180,
        env=_sanitized_env(),
    )

    after = hashlib.sha256(config.read_bytes()).hexdigest()
    assert before == after, "config file was modified during the run"
