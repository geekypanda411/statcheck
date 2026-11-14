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


def test_read_bytes_is_cached(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"payload-bytes")
    t = TargetFile(str(sample), "pe")

    first = t.read_bytes()
    assert first == b"payload-bytes"

    # Change the file on disk; the cached copy must be returned unchanged.
    sample.write_bytes(b"different-bytes")
    assert t.read_bytes() == b"payload-bytes"

    # Cache is per-TargetFile instance.
    t2 = TargetFile(str(sample), "pe")
    assert t2.read_bytes() == b"different-bytes"


def test_set_plugin_status_shapes(tmp_path):
    t = TargetFile(str(tmp_path / "x.bin"), "pe")
    t.set_plugin_status("p1", "completed", duration_ms=12.34567)
    t.set_plugin_status("p2", "failed", error="boom", tool="diec")

    plugins = t.results["metadata"]["plugins"]
    assert plugins["p1"] == {"status": "completed", "duration_ms": 12.3}
    assert plugins["p2"]["status"] == "failed"
    assert plugins["p2"]["error"] == "boom"
    assert plugins["p2"]["tool"] == "diec"
