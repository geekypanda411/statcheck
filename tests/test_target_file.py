"""Tests for the TargetFile result contract."""

from __future__ import annotations

import pytest

from src.core.target_file import TargetFile


@pytest.fixture()
def target(tmp_path):
    return TargetFile(str(tmp_path / "sample.bin"), "pe")


def test_add_result_stores_summary_and_context(target):
    target.add_result(
        "analyzer_x",
        summary_data={"a": 1},
        internal_context_data={"b": 2},
    )
    assert target.results["result_summary"]["analyzer_x"] == {"a": 1}
    assert target.results["internal_context"]["analyzer_x"] == {"b": 2}


def test_add_result_rejects_unknown_kwargs(target):
    """Regression: QuantumStrand used to call add_result(complete_data=...).

    The contract only accepts ``summary_data`` / ``internal_context_data``;
    anything else must fail loudly instead of being silently dropped.
    """
    with pytest.raises(TypeError):
        target.add_result("analyzer_x", complete_data={"raw": "data"})


def test_add_result_recreates_deleted_sections(target):
    # Simulate a downstream plugin accidentally deleting a section.
    del target.results["result_summary"]
    target.add_result("analyzer_x", summary_data={"a": 1})
    assert target.results["result_summary"]["analyzer_x"] == {"a": 1}


def test_add_result_skips_none_payloads(target):
    target.add_result("analyzer_x", summary_data=None, internal_context_data=None)
    assert "analyzer_x" not in target.results["result_summary"]
    assert "analyzer_x" not in target.results["internal_context"]


def test_format_is_lowercased(tmp_path):
    t = TargetFile(str(tmp_path / "x.bin"), "PE")
    assert t.format == "pe"
