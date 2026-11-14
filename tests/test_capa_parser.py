"""Tests for capa output parsing and tool resolution guards."""

from __future__ import annotations

from src.analyzers.capa_analyzer import CapaAnalyzer
from src.core.target_file import TargetFile

VALID_PAYLOAD = {
    "capa-all": {
        "rules": {
            "rule-001": {
                "meta": {
                    "name": "create file",
                    "description": "Creates a file on disk",
                    "attack": [{"id": "T1105", "tactic": "command-and-control"}],
                },
                "matches": [
                    [
                        {"type": "location"},
                        {
                            "success": True,
                            "node": {"type": "feature", "feature": {"type": "api", "api": "CreateFileW"}},
                            "children": [],
                        },
                    ],
                    # A failed branch must be ignored.
                    [
                        {"type": "location"},
                        {
                            "success": False,
                            "node": {"type": "feature", "feature": {"type": "string", "string": "x"}},
                            "children": [],
                        },
                    ],
                ],
            }
        }
    }
}


def _analyzer():
    return CapaAnalyzer()


def test_parse_valid_payload():
    summary = _analyzer().parse_analyzer_output(VALID_PAYLOAD)
    rule = summary["rule-001"]
    assert rule["name"] == "create file"
    assert rule["rule_attack"] == ["T1105 - command-and-control"]
    assert "api: CreateFileW" in rule["matched_features"]
    assert "string: x" not in rule["matched_features"]


def test_parse_empty_dict():
    assert _analyzer().parse_analyzer_output({}) == {}


def test_parse_missing_capa_all_key():
    """Regression: raw_results_dict['capa-all'] used to raise KeyError."""
    assert _analyzer().parse_analyzer_output({"something-else": {}}) == {}


def test_parse_non_dict_capa_all():
    assert _analyzer().parse_analyzer_output({"capa-all": "garbage"}) == {}
    assert _analyzer().parse_analyzer_output({"capa-all": None}) == {}


def test_parse_non_dict_rules():
    assert _analyzer().parse_analyzer_output({"capa-all": {"rules": "nope"}}) == {}


def test_missing_tool_returns_unavailable_status(tmp_path):
    target = TargetFile(str(tmp_path / "x.bin"), "pe")
    _analyzer().analyze(
        target,
        tool_path="/nonexistent/path/capa-never-installed",
        plugin_config={},
        run_dir=str(tmp_path / "run"),
    )
    summary = target.results["result_summary"]["capa"]
    assert summary["status"] == "unavailable"
    assert "reason" in summary
