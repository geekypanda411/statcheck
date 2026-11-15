"""Focused subprocess timeout and output-limit checks for external tools."""

from __future__ import annotations

import pytest

from src.analyzers import capa_analyzer, diec_analyzer, floss_analyzer, quantumstrand_analyzer
from src.core.process import ToolError, ToolTimeout
from src.core.target_file import TargetFile


@pytest.mark.parametrize(
    ("module", "analyzer_type"),
    [
        (capa_analyzer, capa_analyzer.CapaAnalyzer),
        (diec_analyzer, diec_analyzer.DIEAnalyzer),
        (floss_analyzer, floss_analyzer.FlossAnalyzer),
        (quantumstrand_analyzer, quantumstrand_analyzer.QuantumStrandAnalyzer),
    ],
)
def test_tool_timeout_propagates_with_output_limit(module, analyzer_type, monkeypatch, tmp_path):
    analyzer = analyzer_type()
    target = TargetFile(str(tmp_path / "sample.bin"), "pe")
    calls = []

    monkeypatch.setattr(module, "resolve_tool_path", lambda path: "/fake/tool")

    def timeout_run_tool(command, **kwargs):
        calls.append({"command": command, **kwargs})
        raise ToolTimeout("tool timed out")

    monkeypatch.setattr(module, "run_tool", timeout_run_tool)

    with pytest.raises(ToolTimeout):
        analyzer.analyze(target, tool_path="/fake/tool", plugin_config={}, run_dir=str(tmp_path / "run"))

    # In particular, DiE must not launch its remaining commands after a timeout.
    assert len(calls) == 1
    assert calls[0]["max_output_bytes"] == int(analyzer.get_limit("max_tool_output_mb")) * 1024 * 1024


@pytest.mark.parametrize(
    ("module", "analyzer_type"),
    [(capa_analyzer, capa_analyzer.CapaAnalyzer), (diec_analyzer, diec_analyzer.DIEAnalyzer)],
)
def test_tool_error_is_unavailable_not_successful_no_output(module, analyzer_type, monkeypatch, tmp_path):
    analyzer = analyzer_type()
    target = TargetFile(str(tmp_path / "sample.bin"), "pe")
    monkeypatch.setattr(module, "resolve_tool_path", lambda path: "/fake/tool")
    monkeypatch.setattr(module, "run_tool", lambda *args, **kwargs: (_ for _ in ()).throw(ToolError("output limit")))

    analyzer.analyze(target, tool_path="/fake/tool", plugin_config={}, run_dir=str(tmp_path / "run"))

    summary = target.results["result_summary"][analyzer.plugin_id]
    assert summary["status"] == "unavailable"
    assert "output limit" in summary["reason"]
