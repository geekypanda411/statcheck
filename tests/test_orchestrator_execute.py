"""Tests for orchestrator execution: statuses, run metadata, DAG behavior."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.analyzers.base_analyzer import BaseAnalyzer
from src.core.orchestrator import Orchestrator
from src.core.process import ToolTimeout


class OkAnalyzer(BaseAnalyzer):
    name = "Ok Analyzer"
    supported_formats = ["all"]
    plugin_id = "stub_ok"
    depends = {"all": [], "any": []}

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        target_file.add_result(self.plugin_id, summary_data={"value": 1})


class CrashingAnalyzer(BaseAnalyzer):
    name = "Crashing Analyzer"
    supported_formats = ["all"]
    plugin_id = "stub_crash"
    depends = {"all": [], "any": []}

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        raise RuntimeError("intentional crash for tests")


class TimingOutAnalyzer(BaseAnalyzer):
    name = "Timing Out Analyzer"
    supported_formats = ["all"]
    plugin_id = "stub_timeout"
    depends = {"all": [], "any": []}

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        raise ToolTimeout("stub timed out")


class DependentAnalyzer(BaseAnalyzer):
    name = "Dependent Analyzer"
    supported_formats = ["all"]
    plugin_id = "stub_dep"
    depends = {"all": ["stub_ok"], "any": []}

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        target_file.add_result(self.plugin_id, summary_data={"ran_after": "stub_ok"})


@pytest.fixture()
def app(tmp_path, project_root):
    app = Orchestrator(str(tmp_path / "x.bin"), "pe", str(tmp_path / "no-config.json"),
                       str(tmp_path / "no-reporter-config.json"))
    app.load_reporters(str(project_root / "src" / "reporters"), desired_reporter=["json"])
    return app


def _run(app, analyzers, tmp_path, config=None):
    app.analyzers = analyzers
    app.config = {"bin_path": "./bin", "plugins": config or {}}
    run_dir = tmp_path / "reports"
    app.execute(str(run_dir))
    return run_dir, app


def test_statuses_recorded_completed_and_failed(app, tmp_path):
    run_dir, app = _run(app, [OkAnalyzer(), CrashingAnalyzer()], tmp_path)

    plugins = app.target_file.results["metadata"]["plugins"]
    assert plugins["stub_ok"]["status"] == "completed"
    assert "duration_ms" in plugins["stub_ok"]
    assert plugins["stub_crash"]["status"] == "failed"
    assert "intentional crash" in plugins["stub_crash"]["error"]


def test_timeout_status_recorded(app, tmp_path):
    run_dir, app = _run(app, [TimingOutAnalyzer()], tmp_path)
    plugins = app.target_file.results["metadata"]["plugins"]
    assert plugins["stub_timeout"]["status"] == "timeout"


def test_skipped_disabled_status(app, tmp_path):
    run_dir, app = _run(
        app, [OkAnalyzer(), CrashingAnalyzer()], tmp_path,
        config={"stub_crash": {"enabled": False}},
    )
    plugins = app.target_file.results["metadata"]["plugins"]
    assert plugins["stub_crash"]["status"] == "skipped_disabled"
    assert "stub_crash" not in app.target_file.results["metadata"]["analyzed_by"]


def test_cascade_skip_records_skipped_dependency(app, tmp_path):
    run_dir, app = _run(
        app, [OkAnalyzer(), DependentAnalyzer()], tmp_path,
        config={"stub_ok": {"enabled": False}},
    )
    plugins = app.target_file.results["metadata"]["plugins"]
    assert plugins["stub_ok"]["status"] == "skipped_disabled"
    assert plugins["stub_dep"]["status"] == "skipped_dependency"
    assert "stub_dep" not in app.target_file.results["metadata"]["analyzed_by"]


def test_run_metadata_populated(app, tmp_path):
    run_dir, app = _run(app, [OkAnalyzer()], tmp_path)
    run_meta = app.target_file.results["metadata"]["run"]
    assert run_meta["started_at"]
    assert run_meta["finished_at"]
    assert run_meta["duration_ms"] >= 0
    assert run_meta["format"] == "pe"
    assert run_meta["target_filename"] == "x.bin"
    assert "python_version" in run_meta


def test_analyzed_by_is_sorted(app, tmp_path):
    run_dir, app = _run(app, [CrashingAnalyzer(), OkAnalyzer(), DependentAnalyzer()], tmp_path)
    analyzed = app.target_file.results["metadata"]["analyzed_by"]
    assert analyzed == sorted(analyzed)
    assert set(analyzed) == {"stub_ok", "stub_crash", "stub_dep"}


def test_runtime_context_reaches_analyzers(app, tmp_path):
    seen = {}

    class ContextAnalyzer(BaseAnalyzer):
        name = "Context Analyzer"
        supported_formats = ["all"]
        plugin_id = "stub_ctx"
        depends = {"all": [], "any": []}

        def analyze(self, target_file, tool_path, plugin_config, run_dir):
            seen["timeout"] = self.runtime.timeout
            seen["run_dir"] = self.runtime.run_dir
            seen["project_root"] = self.runtime.project_root
            target_file.add_result(self.plugin_id, summary_data={"ok": True})

    _run(app, [ContextAnalyzer()], tmp_path)
    assert seen["timeout"] == 300.0
    # run_dir points at the created run directory, not the reports root.
    assert seen["run_dir"].is_dir()
    assert seen["run_dir"].parent == (tmp_path / "reports")
    assert seen["run_dir"].name.startswith("x")  # sanitized target name


def test_json_report_contains_statuses_and_schema(app, tmp_path):
    run_dir, app = _run(app, [OkAnalyzer()], tmp_path)
    # The orchestrator stores the actual run directory (reports/<name>_<ts>/).
    reports = sorted(Path(app.run_dir).glob("*statcheck_summary_*.json"))
    assert reports, "no report generated"
    payload = json.loads(reports[-1].read_text())
    assert payload["schema_version"] == "1.0"
    assert payload["metadata"]["plugins"]["stub_ok"]["status"] == "completed"
