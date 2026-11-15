"""Regression tests for the QuantumStrand analyzer result contract.

The tool itself is never executed: ``subprocess.run`` is monkeypatched with a
fake JSON payload. No network, no real binary.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from src.analyzers.quantumstrand_analyzer import QuantumStrandAnalyzer
from src.core.target_file import TargetFile


@pytest.fixture()
def analyzer():
    return QuantumStrandAnalyzer()


class Harness:
    """Minimal scaffolding to run the analyzer against a fake tool."""

    def __init__(self, tmp_path, monkeypatch):
        self.tmp_path = tmp_path
        self.target = TargetFile(str(tmp_path / "sample.bin"), "pe")
        self.run_dir = tmp_path / "run"
        self.run_dir.mkdir()
        # Deterministic tool resolution: pretend the fake tool exists.
        from src.analyzers import quantumstrand_analyzer as qs

        monkeypatch.setattr(qs, "resolve_tool_path", lambda p: "/fake/bin/quantumstrand")

    def run(self, analyzer, config=None):
        analyzer.analyze(
            self.target,
            tool_path="/nonexistent/quantumstrand",
            plugin_config=config or {},
            run_dir=str(self.run_dir),
        )
        return self.target.results


@pytest.fixture()
def harness(tmp_path, monkeypatch):
    return Harness(tmp_path, monkeypatch)


def _patch_subprocess(monkeypatch, stdout):
    from src.analyzers import quantumstrand_analyzer as qs

    monkeypatch.setattr(
        qs,
        "run_tool",
        lambda cmd, **kwargs: SimpleNamespace(stdout=stdout, stderr="", returncode=0),
    )


def test_no_strings_path_does_not_raise_and_writes_raw(monkeypatch, analyzer, harness):
    """Regression for the add_result(complete_data=...) TypeError."""
    payload = {"meta": {"version": "beta3"}, "layout": {"strings": [], "children": []}}
    _patch_subprocess(monkeypatch, json.dumps(payload))

    results = harness.run(analyzer)

    summary = results["result_summary"]["quantumstrand"]
    assert summary["strings_found"] == 0
    raw_rel = summary["raw_output_path"]
    assert not raw_rel.startswith("/"), "raw path must be run-dir relative"
    assert (harness.run_dir / raw_rel).is_file()
    assert json.loads((harness.run_dir / raw_rel).read_text()) == payload


def test_success_path_publishes_strings_and_raw(monkeypatch, analyzer, harness):
    payload = {
        "meta": {"version": "beta3", "sample": {"sha256": "ab" * 32}, "min_str_len": 5},
        "layout": {
            "strings": [
                {"string": "CreateFileW", "tags": ["#winapi"]},
                {"string": "http://evil.example", "tags": []},
            ],
            "children": [],
        },
    }
    _patch_subprocess(monkeypatch, json.dumps(payload))

    results = harness.run(analyzer)

    summary = results["result_summary"]["quantumstrand"]
    assert "CreateFileW" in summary["winapi_strings"]
    raw_rel = summary["raw_output_path"]
    assert not raw_rel.startswith("/")
    assert (harness.run_dir / raw_rel).is_file()

    context = results["internal_context"]["quantumstrand"]
    published = {item["string"] for item in context["ioc_extractor_input"]}
    assert published == {"CreateFileW", "http://evil.example"}


def test_string_cap_selects_sorted_strings(monkeypatch, analyzer, harness):
    payload = {
        "meta": {},
        "layout": {
            "strings": [{"string": "z-last", "tags": []}, {"string": "a-first", "tags": []}],
            "children": [{"strings": [{"string": "m-middle", "tags": []}, {"string": "b-second", "tags": []}]}],
        },
    }
    _patch_subprocess(monkeypatch, json.dumps(payload))
    original_get_limit = analyzer.get_limit
    monkeypatch.setattr(
        analyzer,
        "get_limit",
        lambda key, default=None: 2 if key == "max_strings" else original_get_limit(key, default),
    )

    results = harness.run(analyzer)

    strings = results["internal_context"]["quantumstrand"]["ioc_extractor_input"]
    assert [item["string"] for item in strings] == ["a-first", "b-second"]


def test_invalid_json_output_is_handled(monkeypatch, analyzer, harness):
    _patch_subprocess(monkeypatch, "not json at all")

    results = harness.run(analyzer)
    # Must not raise; the failure is visible as an unavailable status.
    summary = results["result_summary"]["quantumstrand"]
    assert summary["status"] == "unavailable"


def test_missing_tool_returns_unavailable(analyzer, harness, monkeypatch):
    from src.analyzers import quantumstrand_analyzer as qs

    monkeypatch.setattr(qs, "resolve_tool_path", lambda p: None)
    analyzer.analyze(
        harness.target,
        tool_path="/nonexistent/quantumstrand",
        plugin_config={},
        run_dir=str(harness.run_dir),
    )
    summary = harness.target.results["result_summary"]["quantumstrand"]
    assert summary["status"] == "unavailable"
    assert "reason" in summary


def test_tool_timeout_propagates(analyzer, harness, monkeypatch):
    from src.analyzers import quantumstrand_analyzer as qs
    from src.core.process import ToolTimeout

    def exploding_run_tool(cmd, **kwargs):
        raise ToolTimeout("quantumstrand timed out")

    monkeypatch.setattr(qs, "run_tool", exploding_run_tool)
    import pytest

    with pytest.raises(ToolTimeout):
        analyzer.analyze(
            harness.target,
            tool_path="/nonexistent/quantumstrand",
            plugin_config={},
            run_dir=str(harness.run_dir),
        )


def test_success_path_accepts_config_override_for_tags(monkeypatch, analyzer, harness):
    payload = {
        "meta": {},
        "layout": {"strings": [{"string": "X" * 5, "tags": ["#decoded"]}], "children": []},
    }
    _patch_subprocess(monkeypatch, json.dumps(payload))

    results = harness.run(analyzer, config={"summary_tags": ["#decoded"]})
    summary = results["result_summary"]["quantumstrand"]
    assert "decoded_strings" in summary
