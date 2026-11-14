"""Tests for orchestrator plugin loading and DAG scheduling."""

from __future__ import annotations

import pytest

from src.core.orchestrator import Orchestrator


@pytest.fixture()
def app(project_root, tmp_path):
    # Point at a non-existent config so the fallback path is exercised; the
    # real repo config (gitignored) must not influence tests.
    missing_config = tmp_path / "does-not-exist.json"
    return Orchestrator(str(tmp_path / "target.bin"), "elf", str(missing_config), str(missing_config))


def test_load_analyzers_twice_is_idempotent(app, project_root):
    app.load_analyzers(str(project_root / "src" / "analyzers"))
    first = [a.plugin_id for a in app.analyzers]
    assert first, "expected the real analyzer directory to yield plugins"

    app.load_analyzers(str(project_root / "src" / "analyzers"))
    second = [a.plugin_id for a in app.analyzers]

    assert first == second
    assert len(second) == len(set(second)), f"duplicate plugin_ids: {second}"


def test_load_reporters_twice_is_idempotent(app, project_root):
    app.load_reporters(str(project_root / "src" / "reporters"), desired_reporter=["all"])
    first = [r.reporter_id for r in app.reporters]
    assert first

    app.load_reporters(str(project_root / "src" / "reporters"), desired_reporter=["all"])
    second = [r.reporter_id for r in app.reporters]

    assert first == second
    assert len(second) == len(set(second)), f"duplicate reporter_ids: {second}"


def test_reporter_selection_filters_by_format(app, project_root):
    app.load_reporters(str(project_root / "src" / "reporters"), desired_reporter=["json"])
    assert [r.format_id for r in app.reporters] == ["json"]


def test_format_specific_analyzers_are_filtered(app, project_root):
    app.load_analyzers(str(project_root / "src" / "analyzers"))
    ids = {a.plugin_id for a in app.analyzers}
    # 'elf' format must pull in the ELF-specific analyzer but not PE-only ones.
    assert "elfstructure" in ids
    assert "pe_sections" not in ids
    assert "authenticode" not in ids
