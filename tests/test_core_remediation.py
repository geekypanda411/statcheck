"""Regression tests for review findings in core execution and caching."""

from __future__ import annotations

import itertools
import json
import threading
import time
from pathlib import Path

import pytest

from src.analyzers.base_analyzer import BaseAnalyzer
from src.analyzers.malwarebazaar_analyzer import MalwareBazaarAnalyzer
from src.analyzers.vtcheck_analyzer import VirusTotalAnalyzer
from src.core.http import cached_response, read_json, write_json
from src.core.orchestrator import Orchestrator
from src.core.target_file import TargetFile
from src.reporters.base_reporter import BaseReporter
from src.reporters.json_reporter import JsonReporter


class StubAnalyzer(BaseAnalyzer):
    name = "Review stub"
    supported_formats = ["all"]
    depends = {"all": [], "any": []}

    def __init__(self, plugin_id="review_stub", summary=None, exception=None):
        self._plugin_id = plugin_id
        self.summary = summary
        self.exception = exception

    @property
    def plugin_id(self):
        return self._plugin_id

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        if self.exception is not None:
            raise self.exception
        if self.summary is not None:
            target_file.add_result(self.plugin_id, summary_data=self.summary)


class FailingReporter(BaseReporter):
    name = "Failing reporter"
    format_id = "failing"
    reporter_id = "failing_reporter"

    def generate(self, target_file, output_dir, reporter_config, timestamp):
        raise OSError("intentional reporter failure")


def _app(tmp_path, analyzers=None, reporters=None):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    missing = tmp_path / "missing.json"
    app = Orchestrator(str(sample), "unknown", missing, missing)
    app.analyzers = list(analyzers or [])
    app.reporters = list(reporters or [])
    return app


def test_ti_plugins_are_disabled_when_config_is_missing(tmp_path):
    analyzers = [VirusTotalAnalyzer(), MalwareBazaarAnalyzer()]
    app = _app(tmp_path, analyzers, [JsonReporter()])

    # A regression must fail quickly, never make a real API request.
    for analyzer in analyzers:
        analyzer.analyze = lambda *args, **kwargs: pytest.fail("opt-out TI plugin was executed")

    assert app.execute(str(tmp_path / "reports")) is True
    statuses = app.target_file.results["metadata"]["plugins"]
    assert statuses["vtlookup"]["status"] == "skipped_disabled"
    assert statuses["malwarebazaar"]["status"] == "skipped_disabled"


def test_failed_and_unavailable_analyzers_make_run_unsuccessful(tmp_path):
    app = _app(
        tmp_path,
        [
            StubAnalyzer("good", {"value": 1}),
            StubAnalyzer("bad", exception=RuntimeError("boom")),
            StubAnalyzer("missing", {"status": "unavailable", "reason": "not installed"}),
        ],
        [JsonReporter()],
    )

    assert app.execute(str(tmp_path / "reports")) is False
    metadata = app.target_file.results["metadata"]
    assert metadata["plugins"]["bad"]["status"] == "failed"
    assert metadata["plugins"]["missing"]["status"] == "unavailable"
    assert metadata["analyzed_by"] == ["good"]


def test_reused_orchestrator_does_not_reuse_results_or_failure_status(tmp_path):
    app = _app(tmp_path, [StubAnalyzer("old", {"status": "unavailable", "reason": "old failure"})])
    assert app.execute(str(tmp_path / "reports")) is False

    app.analyzers = []
    assert app.execute(str(tmp_path / "reports")) is True
    assert app.target_file.results["result_summary"] == {}
    assert app.target_file.results["metadata"].get("plugins", {}) == {}


def test_dependency_deadlock_makes_run_unsuccessful(tmp_path):
    first = StubAnalyzer("first")
    second = StubAnalyzer("second")
    first.depends = {"all": ["second"], "any": []}
    second.depends = {"all": ["first"], "any": []}
    app = _app(tmp_path, [first, second], [JsonReporter()])

    assert app.execute(str(tmp_path / "reports")) is False
    statuses = app.target_file.results["metadata"]["plugins"]
    assert statuses["first"]["status"] == "skipped_dependency"
    assert statuses["second"]["status"] == "skipped_dependency"


def test_reporter_failure_makes_run_unsuccessful(tmp_path):
    app = _app(tmp_path, reporters=[FailingReporter()])
    assert app.execute(str(tmp_path / "reports")) is False


def test_all_disabled_analyzers_still_generate_report(tmp_path):
    app = _app(tmp_path, [StubAnalyzer()], [JsonReporter()])
    app.config["plugins"] = {"review_stub": {"enabled": False}}

    assert app.execute(str(tmp_path / "reports")) is True
    reports = list(Path(app.run_dir).glob("*.json"))
    assert len(reports) == 1
    payload = json.loads(reports[0].read_text())
    assert payload["metadata"]["plugins"]["review_stub"]["status"] == "skipped_disabled"
    assert payload["metadata"]["analyzed_by"] == []


def test_run_ids_are_unique_with_frozen_wall_clock(tmp_path, monkeypatch):
    app = _app(tmp_path)
    monkeypatch.setattr("src.core.orchestrator.time.time", lambda: 1_700_000_000.0)

    assert app.execute(str(tmp_path / "reports")) is True
    first = app.run_dir
    assert app.execute(str(tmp_path / "reports")) is True
    second = app.run_dir

    assert first != second
    assert Path(first).name.startswith("sample.bin_1700000000_")
    assert Path(second).name.startswith("sample.bin_1700000000_")


def test_input_size_limit_stops_execution_before_analyzers(tmp_path):
    analyzer = StubAnalyzer()
    app = _app(tmp_path, [analyzer])
    app.config["limits"] = {"max_file_bytes": 1}

    with pytest.raises(ValueError, match="max_file_bytes"):
        app.execute(str(tmp_path / "reports"))
    assert "review_stub" not in app.target_file.results["result_summary"]
    assert not (tmp_path / "reports").exists()


def test_target_file_cache_reads_once_across_threads(tmp_path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"payload")
    target = TargetFile(str(sample))
    original_read_bytes = Path.read_bytes
    calls = 0
    calls_lock = threading.Lock()

    def counted_read(path):
        nonlocal calls
        with calls_lock:
            calls += 1
        time.sleep(0.05)
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", counted_read)
    barrier = threading.Barrier(3)
    results = []

    def reader():
        barrier.wait()
        results.append(target.read_bytes())

    workers = [threading.Thread(target=reader) for _ in range(2)]
    for worker in workers:
        worker.start()
    barrier.wait()
    for worker in workers:
        worker.join()

    assert results == [b"payload", b"payload"]
    assert calls == 1


def test_ti_cache_concurrent_writers_do_not_lose_entries(tmp_path, monkeypatch):
    monkeypatch.setattr("src.core.http.cache_dir", lambda: tmp_path)
    barrier = threading.Barrier(4)

    def insert(key):
        barrier.wait()
        data, from_cache = cached_response("provider", key, lambda: {"key": key})
        assert data == {"key": key}
        assert from_cache is False

    workers = [threading.Thread(target=insert, args=(key,)) for key in ("a", "b", "c")]
    for worker in workers:
        worker.start()
    barrier.wait()
    for worker in workers:
        worker.join()

    index = read_json(tmp_path / "ti" / "provider.json")
    assert set(index) == {"a", "b", "c"}


def test_ti_cache_prunes_on_cache_hit(tmp_path, monkeypatch):
    monkeypatch.setattr("src.core.http.cache_dir", lambda: tmp_path)
    index_path = tmp_path / "ti" / "provider.json"
    write_json(
        index_path,
        {
            "hit": {"fetched_at": 999, "data": {"fresh": True}},
            "expired": {"fetched_at": 0, "data": {"old": True}},
        },
    )
    monkeypatch.setattr("src.core.http.time.time", lambda: 1000)

    data, from_cache = cached_response(
        "provider", "hit", lambda: pytest.fail("cache miss"), ttl_seconds=1000, max_entries=1
    )
    assert data == {"fresh": True}
    assert from_cache is True
    assert set(read_json(index_path)) == {"hit"}


def test_ti_cache_prunes_expired_and_caps_retention(tmp_path, monkeypatch):
    monkeypatch.setattr("src.core.http.cache_dir", lambda: tmp_path)
    index_path = tmp_path / "ti" / "provider.json"
    write_json(index_path, {"expired": {"fetched_at": 0, "data": {"old": True}}})
    clock = itertools.count(1000)
    monkeypatch.setattr("src.core.http.time.time", lambda: next(clock))

    for key in ("first", "second", "third"):
        cached_response("provider", key, lambda key=key: {"key": key}, max_entries=2)

    index = read_json(index_path)
    assert set(index) == {"second", "third"}
    assert len(index_path.read_text()) < 1000
