"""Tests for the YARA scanner: compile cache, namespaces, raw contract.

Uses tiny synthetic rule files in ``tmp_path``. No network.
"""

from __future__ import annotations

import json

import pytest

from src.analyzers import yara_scanner_analyzer as ysa
from src.analyzers.yara_scanner_analyzer import YaraAnalyzer, _compile_rules
from src.core.target_file import TargetFile

RULE = """
rule test_marker_rule {
    meta:
        description = "test marker"
        author = "pytest"
    strings:
        $marker = "statcheck-test-marker"
    condition:
        $marker
}
"""


@pytest.fixture()
def rules_dir(tmp_path):
    d = tmp_path / "yara_rules"
    d.mkdir()
    (d / "marker.yar").write_text(RULE)
    return d


@pytest.fixture()
def analyzer():
    return YaraAnalyzer()


def _target(tmp_path, content=b"statcheck-test-marker inside a benign file"):
    f = tmp_path / "sample.bin"
    f.write_bytes(content)
    return TargetFile(str(f), "pe")


def _run(analyzer, target, rules_dir, tmp_path, config=None):
    run_dir = tmp_path / "run"
    run_dir.mkdir(exist_ok=True)
    analyzer.analyze(
        target,
        tool_path="",
        plugin_config={"rule_path": str(rules_dir), **(config or {})},
        run_dir=str(run_dir),
    )
    return target.results, run_dir


def test_compile_cache_reuses_rules(rules_dir):
    ysa._RULES_CACHE.clear()
    rules_a, from_cache_a = _compile_rules(rules_dir, precompiled=False, recursive=True)
    rules_b, from_cache_b = _compile_rules(rules_dir, precompiled=False, recursive=True)

    assert from_cache_a is False, "first compile must be a cache miss"
    assert from_cache_b is True, "second compile of the same rules must hit the cache"
    assert rules_a is rules_b


def test_compile_cache_invalidates_on_rule_change(rules_dir):
    ysa._RULES_CACHE.clear()
    rules_a, _ = _compile_rules(rules_dir, precompiled=False, recursive=True)
    # Touch the rule file (new mtime/size) -> new key -> recompile.
    (rules_dir / "marker.yar").write_text(RULE + "\n" + RULE.replace("test_marker_rule", "second_rule"))
    rules_b, from_cache_b = _compile_rules(rules_dir, precompiled=False, recursive=True)
    assert from_cache_b is False
    assert rules_a is not rules_b


def test_namespaces_are_relative_to_rule_path(rules_dir, monkeypatch):
    captured = {}
    monkeypatch.setattr(ysa.yara, "compile", lambda filepaths: captured.update(filepaths) or object())
    ysa._RULES_CACHE.clear()
    _compile_rules(rules_dir, precompiled=False, recursive=True)
    assert list(captured.keys()) == ["marker.yar"], f"namespaces must be run-relative, got {list(captured.keys())}"


def test_successful_match_publishes_summary_and_raw(analyzer, rules_dir, tmp_path):
    target = _target(tmp_path)
    results, run_dir = _run(analyzer, target, rules_dir, tmp_path)

    summary = results["result_summary"]["yara_scanner"]
    assert summary["match_count"] == 1
    assert summary["matched_rules"][0]["rule"] == "test_marker_rule"
    raw_rel = summary["raw_output_path"]
    assert not raw_rel.startswith("/")
    raw = json.loads((run_dir / raw_rel).read_text())
    assert raw["yara_matches"][0]["rule"] == "test_marker_rule"


def test_no_match_still_writes_raw_and_summary(analyzer, rules_dir, tmp_path):
    target = _target(tmp_path, content=b"nothing to see here")
    results, run_dir = _run(analyzer, target, rules_dir, tmp_path)

    summary = results["result_summary"]["yara_scanner"]
    assert summary["match_count"] == 0
    raw_rel = summary["raw_output_path"]
    raw = json.loads((run_dir / raw_rel).read_text())
    assert raw["yara_matches"] == []


def test_missing_rules_path_reports_unavailable(analyzer, tmp_path):
    target = _target(tmp_path)
    results, run_dir = _run(analyzer, target, tmp_path / "no-rules", tmp_path)
    summary = results["result_summary"]["yara_scanner"]
    assert summary["status"] == "unavailable"
    assert "reason" in summary


def test_max_matches_cap_is_enforced(analyzer, tmp_path):
    rules_dir = tmp_path / "many_rules"
    rules_dir.mkdir()
    for i in range(5):
        (rules_dir / f"rule{i}.yar").write_text(
            f'rule rule_{i} {{ strings: $m = "statcheck-test-marker" condition: $m }}'
        )
    target = _target(tmp_path)
    results, run_dir = _run(analyzer, target, rules_dir, tmp_path, config={"max_matches": 2})
    summary = results["result_summary"]["yara_scanner"]
    assert summary["match_count"] == 2
