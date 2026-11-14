"""Tests for the JSON reporter: schema, ordering, metadata, relative paths."""

from __future__ import annotations

import json

import pytest

from src.core.target_file import TargetFile
from src.reporters.json_reporter import JsonReporter, _json_default


@pytest.fixture()
def target(tmp_path):
    t = TargetFile(str(tmp_path / "sample.bin"), "pe")
    t.results["metadata"]["analyzed_by"] = ["zeta", "alpha"]
    t.results["metadata"]["plugins"] = {"alpha": {"status": "completed"}}
    t.results["metadata"]["run"] = {"format": "pe", "target_filename": "sample.bin"}
    t.results["result_summary"] = {
        "fileinfo": {"Filename": "sample.bin", "raw_output_path": "fileinfo/x.json"},
        "zeta_analyzer": {"value": 2},
        "alpha_analyzer": {"value": 1},
        "capa": {"rules": {}, "raw_output_path": "capa/capa_raw_output.json"},
    }
    return t


def _generate(target, tmp_path, config=None):
    run_dir = tmp_path / "run"
    run_dir.mkdir(exist_ok=True)
    reporter = JsonReporter()
    reporter.generate(target, str(run_dir), config or {}, 1794000000)
    report_file = run_dir / "sample.bin_statcheck_summary_1794000000.json"
    assert report_file.is_file()
    return json.loads(report_file.read_text())


def test_schema_version_and_top_level_order(target, tmp_path):
    payload = _generate(target, tmp_path)
    assert payload["schema_version"] == "1.0"
    assert list(payload.keys()) == ["schema_version", "metadata", "result_summary"]


def test_template_order_then_sorted_orphans(target, tmp_path):
    config = {"output_template": ["fileinfo", "capa"]}
    payload = _generate(target, tmp_path, config=config)
    order = list(payload["result_summary"].keys())
    # Template entries come first (in template order)...
    assert order[:2] == ["fileinfo", "capa"]
    # ...then orphans, deterministically sorted.
    assert order[2:] == ["alpha_analyzer", "zeta_analyzer"]


def test_metadata_is_included_unchanged(target, tmp_path):
    payload = _generate(target, tmp_path)
    assert payload["metadata"]["plugins"]["alpha"]["status"] == "completed"
    assert payload["metadata"]["run"]["format"] == "pe"


def test_no_absolute_paths_in_summary(target, tmp_path):
    payload = _generate(target, tmp_path)
    for plugin_id, section in payload["result_summary"].items():
        if isinstance(section, dict) and "raw_output_path" in section:
            path = section["raw_output_path"]
            assert not str(path).startswith("/"), f"{plugin_id} has an absolute raw path"


def test_default_serializer_handles_common_types():
    import datetime
    from pathlib import Path

    assert _json_default(datetime.datetime(2026, 1, 2, 3, 4)) == "2026-01-02T03:04:00"
    assert _json_default(Path("/tmp/x")) == "/tmp/x"
    assert _json_default({"b", "a"}) == ["a", "b"]
    assert _json_default(b"\xde\xad") == "dead"


def test_default_serializer_strict_mode_raises(monkeypatch, tmp_path):
    monkeypatch.setenv("STATCHHECK_STRICT_JSON", "1")

    class Mystery:
        pass

    with pytest.raises(TypeError):
        _json_default(Mystery())


def test_default_serializer_production_falls_back(monkeypatch):
    monkeypatch.delenv("STATCHHECK_STRICT_JSON", raising=False)

    class Mystery:
        def __str__(self):
            return "mystery-str"

    # Ensure DEBUG is not enabled so production fallback applies.
    import logging

    assert _json_default(Mystery()) == "mystery-str"
    assert logging.getLogger(__name__).isEnabledFor(logging.DEBUG) is False
